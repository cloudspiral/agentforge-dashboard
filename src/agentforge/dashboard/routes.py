from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates

from agentforge.observability.metrics import AgentForgeMetrics
from agentforge.observability.metrics import metrics as default_metrics
from agentforge.persistence.repositories import (
    CampaignNotFound,
    FindingRepository,
    OperationalRepository,
    RegressionRunRepository,
    coverage_summary,
)
from agentforge.security.auth import require_dashboard_auth
from agentforge.security.redaction import redact


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
        },
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
    with request.app.state.database.session_factory() as session:
        items, total = OperationalRepository(session).campaign_rows(offset=offset, limit=limit)
    return templates.TemplateResponse(
        request=request,
        name="campaigns.html",
        context={
            "campaigns": items,
            "total": total,
            **_pagination(offset=offset, limit=limit, total=total),
        },
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
        context={**detail, "event_rows": event_rows, "safe_error": safe_error},
    )


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
