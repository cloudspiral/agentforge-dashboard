from __future__ import annotations

import hmac
import uuid
from collections.abc import Generator

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy.orm import Session

from agentforge.api.schemas import (
    AgentRunPage,
    AgentRunResponse,
    CampaignCreateRequest,
    CampaignDetailResponse,
    CampaignPage,
    CampaignResponse,
    CoverageResponse,
    ErrorResponse,
    FindingPage,
    FindingResponse,
    FindingStatusUpdate,
    RegressionResultResponse,
    RegressionRunCreateRequest,
    RegressionRunPage,
    RegressionRunResponse,
    ReportExportResponse,
    ReportResponse,
    TargetDeploymentHookRequest,
)
from agentforge.api.services import ApplicationService
from agentforge.persistence.models import AgentRun, AttackAttempt, Campaign, Finding, RegressionRun
from agentforge.persistence.repositories import (
    AgentRunRepository,
    CampaignNotFound,
    CampaignRepository,
    FindingRepository,
    RegressionRunRepository,
    ReportRepository,
)

router = APIRouter(prefix="/api/v1")
ERROR_RESPONSES = {
    400: {"model": ErrorResponse},
    401: {"model": ErrorResponse},
    404: {"model": ErrorResponse},
}


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def get_session(request: Request) -> Generator[Session, None, None]:
    with request.app.state.database.session_factory() as session:
        yield session


def get_service(request: Request, session: Session = Depends(get_session)) -> ApplicationService:
    return ApplicationService(
        session,
        settings=request.app.state.settings,
        target_profile=request.app.state.target_profile,
        taxonomy=request.app.state.taxonomy,
    )


def require_api_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    expected = request.app.state.settings.platform_api_token
    candidate = None
    if authorization and authorization.lower().startswith("bearer "):
        candidate = authorization[7:].strip()
    if (
        not expected
        or not candidate
        or not hmac.compare_digest(candidate, expected.get_secret_value())
    ):
        raise ApiError(status.HTTP_401_UNAUTHORIZED, "invalid_token", "invalid bearer token")


def require_webhook_secret(
    request: Request,
    x_agentforge_webhook_secret: str | None = Header(default=None),
) -> None:
    expected = request.app.state.settings.deploy_webhook_secret
    if (
        not expected
        or not x_agentforge_webhook_secret
        or not hmac.compare_digest(
            x_agentforge_webhook_secret,
            expected.get_secret_value(),
        )
    ):
        raise ApiError(status.HTTP_401_UNAUTHORIZED, "invalid_webhook", "invalid webhook secret")


def _campaign(entity: Campaign) -> CampaignResponse:
    return CampaignResponse(
        id=entity.id,
        campaign_type=entity.campaign_type,
        trigger_type=entity.trigger_type,
        status=entity.status,
        target_alias=entity.target_alias,
        target_version=entity.target_version,
        category=entity.category_scope,
        subcategory=entity.subcategory_scope,
        max_cost_usd=entity.max_cost_usd,
        max_attempts=entity.max_attempts,
        max_duration_seconds=entity.max_duration_seconds,
        actual_cost_usd=entity.actual_cost_usd,
        actual_attempts=entity.actual_attempts,
        priority=entity.priority,
        idempotency_key=entity.idempotency_key,
        cancellation_requested=entity.cancellation_requested,
        heartbeat_at=entity.heartbeat_at,
        started_at=entity.started_at,
        completed_at=entity.completed_at,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        sanitized_error=entity.sanitized_error,
    )


def _attempt_summary(entity: AttackAttempt) -> dict[str, object]:
    return {
        "id": str(entity.id),
        "status": entity.status,
        "category": entity.category,
        "subcategory": entity.subcategory,
        "attack_family_id": entity.attack_family_id,
        "mutation_generation": entity.mutation_generation,
        "evidence_hash": entity.evidence_hash,
        "estimated_cost_usd": str(entity.estimated_cost_usd),
        "latency_ms": entity.latency_ms,
        "langfuse_trace_id": entity.langfuse_trace_id,
        "created_at": entity.created_at.isoformat(),
    }


def _finding(entity: Finding) -> FindingResponse:
    return FindingResponse(
        id=entity.id,
        vulnerability_id=entity.vulnerability_id,
        title=entity.title,
        category=entity.category,
        subcategory=entity.subcategory,
        severity=entity.severity,
        status=entity.status,
        description=entity.description,
        clinical_impact=entity.clinical_impact,
        expected_behavior=entity.expected_behavior,
        observed_behavior=entity.observed_behavior,
        first_seen_target_version=entity.first_seen_target_version,
        last_seen_target_version=entity.last_seen_target_version,
        current_regression_case_id=entity.current_regression_case_id,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
    )


def _regression(entity: RegressionRun) -> RegressionRunResponse:
    return RegressionRunResponse(
        id=entity.id,
        target_version=entity.target_version,
        campaign_id=entity.campaign_id,
        trigger=entity.trigger,
        status=entity.status,
        total_cases=entity.total_cases,
        passed_cases=entity.passed_cases,
        reproduced_cases=entity.reproduced_cases,
        inconclusive_cases=entity.inconclusive_cases,
        error_cases=entity.error_cases,
        estimated_cost_usd=entity.estimated_cost_usd,
        created_at=entity.created_at,
        updated_at=entity.updated_at,
        results=[
            RegressionResultResponse(
                id=result.id,
                case_id=result.case_id,
                case_version=result.case_version,
                outcome=result.outcome,
                deterministic_results=result.deterministic_results,
                evidence_references=result.evidence_references,
                estimated_cost_usd=result.estimated_cost_usd,
                latency_ms=result.latency_ms,
                trace_id=result.trace_id,
            )
            for result in entity.results
        ],
    )


def _agent_run(entity: AgentRun) -> AgentRunResponse:
    return AgentRunResponse(
        id=entity.id,
        campaign_id=entity.campaign_id,
        attempt_id=entity.attempt_id,
        finding_id=entity.finding_id,
        role=entity.role,
        prompt_version=entity.prompt_version,
        model=entity.model,
        status=entity.status,
        input_tokens=entity.input_tokens,
        output_tokens=entity.output_tokens,
        estimated_cost_usd=entity.estimated_cost_usd,
        latency_ms=entity.latency_ms,
        langfuse_trace_id=entity.langfuse_trace_id,
        typed_error=entity.typed_error,
        created_at=entity.created_at,
    )


@router.post(
    "/campaigns",
    response_model=CampaignResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_api_token)],
)
def create_campaign(
    body: CampaignCreateRequest,
    service: ApplicationService = Depends(get_service),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> CampaignResponse:
    try:
        return _campaign(service.create_campaign(body, idempotency_key=idempotency_key))
    except ValueError as exc:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_campaign", str(exc)) from exc


@router.get("/campaigns", response_model=CampaignPage)
def list_campaigns(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> CampaignPage:
    items, total = CampaignRepository(session).list(offset=offset, limit=limit)
    return CampaignPage(
        items=[_campaign(item) for item in items], total=total, offset=offset, limit=limit
    )


@router.get(
    "/campaigns/{campaign_id}", response_model=CampaignDetailResponse, responses=ERROR_RESPONSES
)
def get_campaign(
    campaign_id: uuid.UUID, session: Session = Depends(get_session)
) -> CampaignDetailResponse:
    try:
        entity = CampaignRepository(session).get(campaign_id, include_attempts=True)
    except CampaignNotFound as exc:
        raise ApiError(
            status.HTTP_404_NOT_FOUND, "campaign_not_found", "campaign not found"
        ) from exc
    return CampaignDetailResponse(
        **_campaign(entity).model_dump(),
        attempts=[_attempt_summary(attempt) for attempt in entity.attempts],
    )


@router.post(
    "/campaigns/{campaign_id}/cancel",
    response_model=CampaignResponse,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_api_token)],
)
def cancel_campaign(
    campaign_id: uuid.UUID, session: Session = Depends(get_session)
) -> CampaignResponse:
    try:
        return _campaign(CampaignRepository(session).cancel(campaign_id))
    except CampaignNotFound as exc:
        raise ApiError(
            status.HTTP_404_NOT_FOUND, "campaign_not_found", "campaign not found"
        ) from exc


@router.post(
    "/regression-runs",
    response_model=RegressionRunResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_api_token)],
)
def create_regression_run(
    body: RegressionRunCreateRequest,
    service: ApplicationService = Depends(get_service),
) -> RegressionRunResponse:
    try:
        return _regression(service.create_regression_run(body))
    except ValueError as exc:
        raise ApiError(status.HTTP_400_BAD_REQUEST, "invalid_regression", str(exc)) from exc


@router.get("/regression-runs", response_model=RegressionRunPage)
def list_regression_runs(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> RegressionRunPage:
    items, total = RegressionRunRepository(session).list(offset=offset, limit=limit)
    return RegressionRunPage(
        items=[_regression(item) for item in items], total=total, offset=offset, limit=limit
    )


@router.get(
    "/regression-runs/{run_id}", response_model=RegressionRunResponse, responses=ERROR_RESPONSES
)
def get_regression_run(
    run_id: uuid.UUID, session: Session = Depends(get_session)
) -> RegressionRunResponse:
    try:
        return _regression(RegressionRunRepository(session).get(run_id))
    except LookupError as exc:
        raise ApiError(
            status.HTTP_404_NOT_FOUND, "regression_not_found", "regression run not found"
        ) from exc


@router.post(
    "/hooks/target-deployed",
    response_model=CampaignResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_webhook_secret)],
)
def target_deployed(
    body: TargetDeploymentHookRequest,
    service: ApplicationService = Depends(get_service),
) -> CampaignResponse:
    return _campaign(
        service.trigger_deployment_regression(
            deployment_id=body.deployment_id,
            target_version=body.target_version,
        )
    )


@router.get("/findings", response_model=FindingPage)
def list_findings(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> FindingPage:
    items, total = FindingRepository(session).list(offset=offset, limit=limit)
    return FindingPage(
        items=[_finding(item) for item in items], total=total, offset=offset, limit=limit
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse, responses=ERROR_RESPONSES)
def get_finding(finding_id: uuid.UUID, session: Session = Depends(get_session)) -> FindingResponse:
    try:
        return _finding(FindingRepository(session).get(finding_id))
    except LookupError as exc:
        raise ApiError(status.HTTP_404_NOT_FOUND, "finding_not_found", "finding not found") from exc


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingResponse,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_api_token)],
)
def update_finding_status(
    finding_id: uuid.UUID,
    body: FindingStatusUpdate,
    session: Session = Depends(get_session),
) -> FindingResponse:
    try:
        return _finding(FindingRepository(session).set_status(finding_id, body.status))
    except LookupError as exc:
        raise ApiError(status.HTTP_404_NOT_FOUND, "finding_not_found", "finding not found") from exc


@router.get("/reports/{finding_id}", response_model=ReportResponse, responses=ERROR_RESPONSES)
def get_report(finding_id: uuid.UUID, session: Session = Depends(get_session)) -> ReportResponse:
    try:
        report = ReportRepository(session).latest_for_finding(finding_id)
    except LookupError as exc:
        raise ApiError(status.HTTP_404_NOT_FOUND, "report_not_found", "report not found") from exc
    return ReportResponse(
        finding_id=report.finding_id,
        report_version=report.report_version,
        status=report.status,
        structured_report=report.structured_report,
        markdown_body=report.markdown_body,
        markdown_path=report.markdown_path,
        validation_summary=report.validation_summary,
        created_at=report.created_at,
        updated_at=report.updated_at,
    )


@router.post(
    "/reports/{finding_id}/export",
    response_model=ReportExportResponse,
    responses=ERROR_RESPONSES,
    dependencies=[Depends(require_api_token)],
)
def export_report(
    finding_id: uuid.UUID,
    service: ApplicationService = Depends(get_service),
) -> ReportExportResponse:
    try:
        path, version = service.export_report(finding_id)
    except LookupError as exc:
        raise ApiError(status.HTTP_404_NOT_FOUND, "report_not_found", "report not found") from exc
    return ReportExportResponse(finding_id=finding_id, path=path, report_version=version)


@router.get("/coverage", response_model=CoverageResponse)
def get_coverage(service: ApplicationService = Depends(get_service)) -> CoverageResponse:
    return CoverageResponse(rows=service.coverage())


@router.get("/agent-runs", response_model=AgentRunPage)
def list_agent_runs(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    session: Session = Depends(get_session),
) -> AgentRunPage:
    items, total = AgentRunRepository(session).list(offset=offset, limit=limit)
    return AgentRunPage(
        items=[_agent_run(item) for item in items], total=total, offset=offset, limit=limit
    )
