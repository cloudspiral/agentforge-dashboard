from __future__ import annotations

import hmac
import uuid
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from agentforge.api.schemas import CampaignCreateRequest
from agentforge.api.services import ApplicationService
from agentforge.dashboard.evaluations import (
    DashboardEvaluationManager,
    DashboardEvaluationSnapshot,
    EvaluationAlreadyRunning,
    EvaluationStartFailed,
)
from agentforge.evaluation import load_seed_cases, load_taxonomy
from agentforge.evidence import (
    EvidenceArtifactError,
    EvidenceArtifactMissing,
    EvidenceArtifactStore,
)
from agentforge.observability.metrics import AgentForgeMetrics
from agentforge.observability.metrics import metrics as default_metrics
from agentforge.persistence.models import AttackAttempt
from agentforge.persistence.repositories import (
    CampaignNotFound,
    CampaignRepository,
    FindingRepository,
    OperationalRepository,
    RegressionRunRepository,
    coverage_summary,
)
from agentforge.security.auth import require_dashboard_auth
from agentforge.security.redaction import redact

PROJECT_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_CAMPAIGN_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})
CATEGORY_ORDER = (
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_role_exploitation",
)


def _app_metrics(application: FastAPI) -> AgentForgeMetrics:
    for attribute in ("metrics", "app_metrics"):
        candidate = getattr(application.state, attribute, None)
        if isinstance(candidate, AgentForgeMetrics):
            return candidate
    return default_metrics


@asynccontextmanager
async def _dashboard_lifespan(application: FastAPI) -> AsyncIterator[None]:
    runtime_metrics = _app_metrics(application)
    database = application.state.database
    runtime_metrics.bind_persistence(
        database,
        stale_after_seconds=int(
            getattr(application.state.settings, "worker_stale_after_seconds", 120)
        ),
    )
    try:
        yield
    finally:
        runtime_metrics.unbind_persistence(database)


router = APIRouter(
    lifespan=_dashboard_lifespan,
    dependencies=[Depends(require_dashboard_auth)],
)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _stale_after_seconds(request: Request) -> int:
    return int(getattr(request.app.state.settings, "worker_stale_after_seconds", 120))


def _pagination(*, offset: int, limit: int, total: int) -> dict[str, Any]:
    return {
        "offset": offset,
        "limit": limit,
        "previous_offset": max(0, offset - limit),
        "next_offset": offset + limit,
        "has_previous": offset > 0,
        "has_next": offset + limit < total,
    }


def _runtime_metrics(request: Request) -> AgentForgeMetrics:
    return _app_metrics(request.app)


def _repository_root(request: Request) -> Path:
    return Path(getattr(request.app.state, "repository_root", PROJECT_ROOT)).resolve()


def _seed_catalog(request: Request) -> list[tuple[Any, Path]]:
    directory = _repository_root(request) / "evals" / "seed-cases"
    paths = sorted(directory.glob("*.yaml"))
    cases = load_seed_cases(directory)
    return list(zip(cases, paths, strict=True))


def _evaluation_manager(request: Request) -> DashboardEvaluationManager | None:
    candidate = getattr(request.app.state, "evaluation_manager", None)
    return candidate if isinstance(candidate, DashboardEvaluationManager) else candidate


def _evaluation_snapshot(request: Request) -> DashboardEvaluationSnapshot:
    manager = _evaluation_manager(request)
    return manager.snapshot() if manager is not None else DashboardEvaluationSnapshot(phase="idle")


def _csrf_token(request: Request) -> str:
    return str(getattr(request.app.state, "dashboard_csrf_token", ""))


def _campaign_form_defaults(request: Request) -> dict[str, str]:
    settings = request.app.state.settings
    return {
        "target_alias": "local",
        "category": "",
        "subcategory": "",
        "max_attempts": "1",
        "max_cost_usd": "0.25",
        "max_duration_seconds": str(
            getattr(settings, "default_campaign_max_duration_seconds", 900)
        ),
        "priority": "0",
        "idempotency_key": f"dashboard-{uuid.uuid4().hex}",
        "confirm_authorized": "",
    }


def _taxonomy_options(request: Request) -> list[dict[str, Any]]:
    taxonomy = getattr(request.app.state, "taxonomy", None)
    if taxonomy is None:
        taxonomy = load_taxonomy(_repository_root(request) / "config" / "attack-taxonomy.yaml")
    return [
        {
            "id": category.id,
            "description": category.description,
            "subcategories": [
                {"id": item.id, "description": item.description} for item in category.subcategories
            ],
        }
        for category in taxonomy.categories
    ]


def _campaign_page_context(
    request: Request,
    *,
    offset: int,
    limit: int,
    launch_values: dict[str, str] | None = None,
    launch_error: str | None = None,
) -> dict[str, Any]:
    with request.app.state.database.session_factory() as session:
        operations = OperationalRepository(session)
        items, total = operations.campaign_rows(offset=offset, limit=limit)
        queue = operations.queue_summary(stale_after_seconds=_stale_after_seconds(request))
    settings = request.app.state.settings
    return {
        "campaigns": items,
        "total": total,
        "queue": queue,
        "taxonomy_options": _taxonomy_options(request),
        "launch_values": launch_values or _campaign_form_defaults(request),
        "launch_error": launch_error,
        "csrf_token": _csrf_token(request),
        "campaign_ceiling_usd": getattr(settings, "default_campaign_max_cost_usd", 2.0),
        "global_ceiling_usd": getattr(settings, "global_max_cost_usd", 10.0),
        **_pagination(offset=offset, limit=limit, total=total),
    }


def _optional_form_value(value: str) -> str | None:
    normalized = value.strip()
    return normalized or None


def _evidence_store(request: Request) -> EvidenceArtifactStore:
    configured = Path(getattr(request.app.state.settings, "artifacts_dir", "artifacts"))
    artifacts = configured if configured.is_absolute() else _repository_root(request) / configured
    return EvidenceArtifactStore(artifacts / "evidence")


def _attempt_result_rows(
    request: Request,
    detail: dict[str, Any],
) -> dict[uuid.UUID, dict[str, Any]]:
    rows: dict[uuid.UUID, dict[str, Any]] = {}
    store = _evidence_store(request)
    for attempt in detail["attempts"]:
        payload = attempt.evidence_payload if isinstance(attempt.evidence_payload, dict) else {}
        transcript = payload.get("transcript", [])
        turns = [
            {
                "turn_index": turn.get("turn_index"),
                "role": str(turn.get("role", "system")),
                "content": redact(str(turn.get("content", ""))),
                "observed_at": turn.get("observed_at"),
            }
            for turn in transcript
            if isinstance(turn, dict)
        ]
        artifact_state = "durable evidence unavailable"
        if payload:
            try:
                store.load_verified(
                    campaign_id=attempt.campaign_id,
                    attempt_id=attempt.id,
                    database_payload=payload,
                )
                artifact_state = "verified export available"
            except EvidenceArtifactMissing:
                artifact_state = "durable evidence unavailable"
            except EvidenceArtifactError:
                artifact_state = "evidence export corrupt"
        rows[attempt.id] = {
            "transcript": turns,
            "http": redact(payload.get("sanitized_http_metadata", [])),
            "tool_calls": redact(payload.get("target_visible_tool_calls", [])),
            "side_effects": redact(payload.get("side_effects", [])),
            "errors": redact(payload.get("errors", [])),
            "evidence_hash": attempt.evidence_hash,
            "artifact_state": artifact_state,
            "download_url": (
                f"/dashboard/campaigns/{attempt.campaign_id}/attempts/{attempt.id}/evidence.json"
                if artifact_state == "verified export available"
                else None
            ),
            "verdict": detail["verdicts"].get(attempt.id),
        }
    return rows


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request) -> Response:
    runtime_metrics = _runtime_metrics(request)
    runtime_metrics.bind_persistence(
        request.app.state.database,
        stale_after_seconds=_stale_after_seconds(request),
    )
    return Response(content=runtime_metrics.render(), media_type=runtime_metrics.content_type)


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def overview(request: Request) -> HTMLResponse:
    seed_catalog = _seed_catalog(request)
    case_ids = [case.id for case, _path in seed_catalog]
    with request.app.state.database.session_factory() as session:
        operations = OperationalRepository(session)
        campaigns = operations.campaign_status_counts()
        queue = operations.queue_summary(stale_after_seconds=_stale_after_seconds(request))
        activity = operations.activity_summary()
        finding_summary = operations.finding_summary()
        regression_summary = operations.regression_summary()
        recent_campaigns, _ = operations.campaign_rows(limit=8)
        recent_events = operations.recent_events(limit=12)
        coverage = coverage_summary(session)
        latest_evaluations = operations.latest_live_evaluations(case_ids)
    seed_groups = []
    for category in CATEGORY_ORDER:
        cases = []
        for case, _path in seed_catalog:
            if case.category != category:
                continue
            cases.append(
                {
                    "id": case.id,
                    "name": case.name,
                    "category": case.category,
                    "subcategory": case.subcategory,
                    "surface": case.surface,
                    "latest": latest_evaluations.get(case.id),
                }
            )
        seed_groups.append(
            {"id": category, "label": category.replace("_", " ").title(), "cases": cases}
        )
    evaluation = _evaluation_snapshot(request)
    return templates.TemplateResponse(
        request=request,
        name="overview.html",
        context={
            "campaigns": campaigns,
            "campaign_total": sum(campaigns.values()),
            "queue": queue,
            "activity": activity,
            "finding_summary": finding_summary,
            "regression_summary": regression_summary,
            "recent_campaigns": recent_campaigns,
            "recent_events": recent_events,
            "coverage": coverage,
            "seed_groups": seed_groups,
            "evaluation": evaluation,
            "csrf_token": _csrf_token(request),
        },
    )


@router.post(
    "/dashboard/evaluations/{case_id}/run",
    response_class=RedirectResponse,
    include_in_schema=False,
)
async def run_seed_evaluation(
    request: Request,
    case_id: str,
    csrf_token: str = Form(...),
) -> RedirectResponse:
    expected_csrf = _csrf_token(request)
    if not expected_csrf or not hmac.compare_digest(csrf_token, expected_csrf):
        raise HTTPException(status_code=403, detail="invalid dashboard action token")
    case_paths = {case.id: path for case, path in _seed_catalog(request)}
    case_path = case_paths.get(case_id)
    if case_path is None:
        raise HTTPException(status_code=404, detail="evaluation case not found")
    manager = _evaluation_manager(request)
    if manager is None:
        raise HTTPException(status_code=503, detail="dashboard evaluation runner unavailable")
    try:
        campaign_id = await manager.start(case_id=case_id, case_path=case_path)
    except EvaluationAlreadyRunning as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except EvaluationStartFailed as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return RedirectResponse(
        url=f"/dashboard/campaigns/{campaign_id}",
        status_code=303,
    )


@router.get("/dashboard/queue", response_class=HTMLResponse, include_in_schema=False)
def queue_status(request: Request) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        operations = OperationalRepository(session)
        queue = operations.queue_summary(stale_after_seconds=_stale_after_seconds(request))
        recent_events = operations.recent_events(limit=25)
    if queue["worker_status"] == "unknown" and not getattr(
        request.app.state.settings, "worker_enabled", True
    ):
        queue["worker_status"] = "disabled"
    return templates.TemplateResponse(
        request=request,
        name="queue.html",
        context={"queue": queue, "recent_events": recent_events},
    )


@router.get("/dashboard/campaigns", response_class=HTMLResponse, include_in_schema=False)
def campaigns(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="campaigns.html",
        context=_campaign_page_context(request, offset=offset, limit=limit),
    )


@router.post(
    "/dashboard/campaigns",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def launch_campaign(
    request: Request,
    csrf_token: str = Form(...),
    idempotency_key: str = Form(...),
    target_alias: str = Form("local"),
    category: str = Form(""),
    subcategory: str = Form(""),
    max_attempts: str = Form("1"),
    max_cost_usd: str = Form("0.25"),
    max_duration_seconds: str = Form(""),
    priority: str = Form("0"),
    confirm_authorized: str = Form(""),
) -> Response:
    expected_csrf = _csrf_token(request)
    if not expected_csrf or not hmac.compare_digest(csrf_token, expected_csrf):
        raise HTTPException(status_code=403, detail="invalid dashboard action token")
    values = {
        "target_alias": target_alias,
        "category": category,
        "subcategory": subcategory,
        "max_attempts": max_attempts,
        "max_cost_usd": max_cost_usd,
        "max_duration_seconds": max_duration_seconds,
        "priority": priority,
        "idempotency_key": idempotency_key,
        "confirm_authorized": confirm_authorized,
    }
    try:
        if target_alias == "deployed" and confirm_authorized != "yes":
            raise ValueError(
                "Deployed campaigns require confirmation that the target is authorized "
                "and contains synthetic data only."
            )
        body = CampaignCreateRequest.model_validate(
            {
                "campaign_type": "discovery",
                "target_alias": target_alias,
                "category": _optional_form_value(category),
                "subcategory": _optional_form_value(subcategory),
                "max_attempts": _optional_form_value(max_attempts),
                "max_cost_usd": _optional_form_value(max_cost_usd),
                "max_duration_seconds": _optional_form_value(max_duration_seconds),
                "priority": _optional_form_value(priority) or "0",
                "idempotency_key": idempotency_key,
            }
        )
        with request.app.state.database.session_factory() as session:
            campaign = ApplicationService(
                session,
                settings=request.app.state.settings,
                target_profile=request.app.state.target_profile,
                taxonomy=request.app.state.taxonomy,
            ).create_campaign(
                body,
                trigger_type="dashboard",
                idempotency_key=idempotency_key,
            )
    except (ValidationError, ValueError) as exc:
        message = str(exc)
        if isinstance(exc, ValidationError) and exc.errors():
            message = str(exc.errors()[0].get("msg", message))
        return templates.TemplateResponse(
            request=request,
            name="campaigns.html",
            context=_campaign_page_context(
                request,
                offset=0,
                limit=50,
                launch_values=values,
                launch_error=message,
            ),
            status_code=400,
        )
    return RedirectResponse(
        url=f"/dashboard/campaigns/{campaign.id}",
        status_code=303,
    )


@router.get(
    "/dashboard/campaigns/{campaign_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def campaign_detail(request: Request, campaign_id: uuid.UUID) -> HTMLResponse:
    try:
        with request.app.state.database.session_factory() as session:
            detail = OperationalRepository(session).campaign_detail(campaign_id)
            safe_error = redact(detail["campaign"].sanitized_error)
            event_rows = [
                {"event": event, "details": redact(event.details_json)}
                for event in detail["events"]
            ]
    except CampaignNotFound as exc:
        raise HTTPException(status_code=404, detail="campaign not found") from exc
    return templates.TemplateResponse(
        request=request,
        name="campaign_detail.html",
        context={
            **detail,
            "event_rows": event_rows,
            "safe_error": safe_error,
            "attempt_results": _attempt_result_rows(request, detail),
            "terminal": detail["campaign"].status in TERMINAL_CAMPAIGN_STATUSES,
        },
    )


@router.get(
    "/dashboard/campaigns/{campaign_id}/attempts/{attempt_id}/evidence.json",
    response_class=Response,
    include_in_schema=False,
)
def download_dashboard_attempt_evidence(
    request: Request,
    campaign_id: uuid.UUID,
    attempt_id: uuid.UUID,
) -> Response:
    with request.app.state.database.session_factory() as session:
        attempt = session.get(AttackAttempt, attempt_id)
        if (
            attempt is None
            or attempt.campaign_id != campaign_id
            or not isinstance(attempt.evidence_payload, dict)
        ):
            raise HTTPException(
                status_code=404,
                detail="durable evidence is unavailable for this campaign attempt",
            )
        try:
            content = _evidence_store(request).load_verified(
                campaign_id=campaign_id,
                attempt_id=attempt_id,
                database_payload=attempt.evidence_payload,
            )
        except EvidenceArtifactMissing as exc:
            raise HTTPException(
                status_code=404,
                detail="database evidence exists but its verified export is unavailable",
            ) from exc
        except EvidenceArtifactError as exc:
            raise HTTPException(
                status_code=409,
                detail="evidence export does not match its PostgreSQL source record",
            ) from exc
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": (f'attachment; filename="{attempt_id}.evidence.json"'),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/dashboard/campaigns/{campaign_id}/status",
    response_class=JSONResponse,
    include_in_schema=False,
)
def campaign_status(request: Request, campaign_id: uuid.UUID) -> JSONResponse:
    try:
        with request.app.state.database.session_factory() as session:
            campaign = CampaignRepository(session).get(campaign_id)
            payload = {
                "campaign_id": str(campaign.id),
                "status": campaign.status,
                "terminal": campaign.status in TERMINAL_CAMPAIGN_STATUSES,
                "updated_at": campaign.updated_at.isoformat(),
            }
    except CampaignNotFound as exc:
        raise HTTPException(status_code=404, detail="campaign not found") from exc
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


@router.get("/dashboard/findings", response_class=HTMLResponse, include_in_schema=False)
def findings(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        items, total = FindingRepository(session).list(
            offset=offset,
            limit=limit,
            include_reports=True,
        )
    return templates.TemplateResponse(
        request=request,
        name="findings.html",
        context={
            "findings": items,
            "total": total,
            **_pagination(offset=offset, limit=limit, total=total),
        },
    )


@router.get(
    "/dashboard/findings/{finding_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def finding_detail(request: Request, finding_id: uuid.UUID) -> HTMLResponse:
    try:
        with request.app.state.database.session_factory() as session:
            finding = FindingRepository(session).get(finding_id, include_reports=True)
            report = max(finding.reports, key=lambda item: item.report_version, default=None)
            safe_report_body = redact(report.markdown_body) if report else None
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    return templates.TemplateResponse(
        request=request,
        name="finding_detail.html",
        context={"finding": finding, "report": report, "safe_report_body": safe_report_body},
    )


@router.get(
    "/dashboard/regression-runs",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def regression_runs(
    request: Request,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> HTMLResponse:
    with request.app.state.database.session_factory() as session:
        items, total = RegressionRunRepository(session).list(offset=offset, limit=limit)
    return templates.TemplateResponse(
        request=request,
        name="regressions.html",
        context={
            "runs": items,
            "total": total,
            **_pagination(offset=offset, limit=limit, total=total),
        },
    )


@router.get(
    "/dashboard/regression-runs/{run_id}",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def regression_run_detail(request: Request, run_id: uuid.UUID) -> HTMLResponse:
    try:
        with request.app.state.database.session_factory() as session:
            run = RegressionRunRepository(session).get(run_id)
            outcomes = Counter(result.outcome for result in run.results)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="regression run not found") from exc
    duration_seconds = (
        max(0.0, (run.completed_at - run.started_at).total_seconds())
        if run.started_at and run.completed_at
        else None
    )
    return templates.TemplateResponse(
        request=request,
        name="regression_detail.html",
        context={"run": run, "outcomes": outcomes, "duration_seconds": duration_seconds},
    )
