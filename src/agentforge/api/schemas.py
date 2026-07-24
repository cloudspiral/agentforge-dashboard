from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


SafeKey = Annotated[
    str,
    StringConstraints(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.:-]+$"),
]


class ErrorResponse(ApiModel):
    code: str
    message: str
    correlation_id: str | None = None


class CampaignCreateRequest(ApiModel):
    campaign_type: Literal["discovery", "regression"] = "discovery"
    target_alias: Literal["local", "deployed"] = "local"
    category: str | None = Field(default=None, max_length=100)
    subcategory: str | None = Field(default=None, max_length=100)
    max_cost_usd: Decimal | None = Field(default=None, gt=0, decimal_places=6)
    max_attempts: int | None = Field(default=None, ge=1, le=100)
    max_duration_seconds: int | None = Field(default=None, ge=30, le=86_400)
    priority: int = Field(default=0, ge=-100, le=100)
    idempotency_key: SafeKey | None = None


class CampaignResponse(ApiModel):
    id: uuid.UUID
    campaign_type: str
    trigger_type: str
    status: str
    target_alias: str
    target_version: str
    category: str | None
    subcategory: str | None
    max_cost_usd: Decimal
    max_attempts: int
    max_duration_seconds: int
    actual_cost_usd: Decimal
    actual_attempts: int
    priority: int
    idempotency_key: str | None
    cancellation_requested: bool
    heartbeat_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    sanitized_error: dict[str, Any] | None


class CampaignPage(ApiModel):
    items: list[CampaignResponse]
    total: int
    offset: int
    limit: int


class CampaignEventResponse(ApiModel):
    id: uuid.UUID
    event_type: str
    from_status: str | None
    to_status: str
    worker_name: str | None
    details: dict[str, Any]
    created_at: datetime


class CampaignDetailResponse(CampaignResponse):
    attempts: list[dict[str, Any]] = Field(default_factory=list)
    events: list[CampaignEventResponse] = Field(default_factory=list)


class QueueStatusResponse(ApiModel):
    depth: int
    running: int
    oldest_age_seconds: float
    stale_running: int
    worker_name: str | None
    worker_status: str


class OperationalSummaryResponse(ApiModel):
    campaigns: dict[str, int]
    queue: QueueStatusResponse
    activity: dict[str, Any]
    findings: dict[str, Any]
    regressions: dict[str, Any]


class RegressionRunCreateRequest(ApiModel):
    target_alias: Literal["local", "deployed"] = "local"
    target_version: str | None = Field(default=None, max_length=255)
    idempotency_key: SafeKey | None = None


class RegressionResultResponse(ApiModel):
    id: uuid.UUID
    case_id: uuid.UUID
    case_version: int
    outcome: str
    judge_result: dict[str, Any] | None
    evidence_hash: str | None
    estimated_cost_usd: Decimal
    latency_ms: int | None
    trace_id: str | None


class RegressionRunResponse(ApiModel):
    id: uuid.UUID
    target_version: str
    campaign_id: uuid.UUID | None
    trigger: str
    status: str
    total_cases: int
    passed_cases: int
    reproduced_cases: int
    inconclusive_cases: int
    error_cases: int
    estimated_cost_usd: Decimal
    created_at: datetime
    updated_at: datetime
    results: list[RegressionResultResponse] = Field(default_factory=list)


class RegressionRunPage(ApiModel):
    items: list[RegressionRunResponse]
    total: int
    offset: int
    limit: int


class TargetDeploymentHookRequest(ApiModel):
    deployment_id: SafeKey
    target_version: str = Field(min_length=1, max_length=255)
    target_alias: Literal["deployed"] = "deployed"


class FindingResponse(ApiModel):
    id: uuid.UUID
    vulnerability_id: str
    title: str
    category: str
    subcategory: str
    severity: str
    status: str
    description: str
    clinical_impact: str
    expected_behavior: str
    observed_behavior: str
    first_seen_target_version: str
    last_seen_target_version: str
    current_regression_case_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class FindingPage(ApiModel):
    items: list[FindingResponse]
    total: int
    offset: int
    limit: int


class FindingStatusUpdate(ApiModel):
    action: Literal["confirm", "begin_work", "dismiss", "resolve"]
    reason: str | None = Field(default=None, max_length=2_000)
    regression_result_id: uuid.UUID | None = None
    manual_override: bool = False


class ReportResponse(ApiModel):
    finding_id: uuid.UUID
    report_version: int
    status: str
    structured_report: dict[str, Any]
    markdown_body: str
    markdown_path: str | None
    validation_summary: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ReportExportResponse(ApiModel):
    finding_id: uuid.UUID
    path: str
    report_version: int


class CoverageResponse(ApiModel):
    rows: list[dict[str, Any]]


class AgentRunResponse(ApiModel):
    id: uuid.UUID
    campaign_id: uuid.UUID | None
    attempt_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    role: str
    prompt_version: str
    model: str
    status: str
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: Decimal
    latency_ms: int | None
    langfuse_trace_id: str | None
    output_payload: dict[str, Any] | None
    typed_error: dict[str, Any] | None
    created_at: datetime


class AgentRunPage(ApiModel):
    items: list[AgentRunResponse]
    total: int
    offset: int
    limit: int
