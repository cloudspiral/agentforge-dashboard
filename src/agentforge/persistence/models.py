from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from agentforge.persistence.db import Base

JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")
MONEY = Numeric(12, 6)


def utcnow() -> datetime:
    return datetime.now(UTC)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class TargetVersion(TimestampMixin, Base):
    __tablename__ = "target_versions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    environment: Mapped[str] = mapped_column(String(32), nullable=False)
    version_label: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    git_sha: Mapped[str | None] = mapped_column(String(64))
    deployment_id: Mapped[str | None] = mapped_column(String(255))
    base_url_alias: Mapped[str] = mapped_column(String(255), nullable=False)
    target_profile_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)


class Campaign(TimestampMixin, Base):
    __tablename__ = "campaigns"
    __table_args__ = (
        Index("ix_campaigns_status_created_at", "status", "created_at"),
        Index("ix_campaigns_category_subcategory", "category_scope", "subcategory_scope"),
        Index("ix_campaigns_target_version", "target_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    campaign_type: Mapped[str] = mapped_column(String(32), nullable=False, default="discovery")
    trigger_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    target_alias: Mapped[str] = mapped_column(String(64), nullable=False, default="local")
    target_version: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    category_scope: Mapped[str | None] = mapped_column(String(100))
    subcategory_scope: Mapped[str | None] = mapped_column(String(100))
    max_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    max_mutations: Mapped[int] = mapped_column(Integer, nullable=False)
    no_signal_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    actual_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    actual_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    idempotency_key: Mapped[str | None] = mapped_column(String(255), unique=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sanitized_error: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    attempts: Mapped[list[AttackAttempt]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    agent_runs: Mapped[list[AgentRun]] = relationship(back_populates="campaign")
    events: Mapped[list[CampaignEvent]] = relationship(
        back_populates="campaign",
        cascade="all, delete-orphan",
        order_by="CampaignEvent.created_at",
    )


class CampaignEvent(Base):
    __tablename__ = "campaign_events"
    __table_args__ = (Index("ix_campaign_events_campaign_created", "campaign_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(32))
    to_status: Mapped[str] = mapped_column(String(32), nullable=False)
    worker_name: Mapped[str | None] = mapped_column(String(128))
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    campaign: Mapped[Campaign] = relationship(back_populates="events")


class AttackAttempt(TimestampMixin, Base):
    __tablename__ = "attack_attempts"
    __table_args__ = (
        Index("ix_attack_attempts_category_subcategory", "category", "subcategory"),
        Index("ix_attack_attempts_trace_id", "langfuse_trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_family_id: Mapped[str] = mapped_column(String(255), nullable=False)
    lineage_id: Mapped[str | None] = mapped_column(String(255))
    parent_attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("attack_attempts.id", ondelete="SET NULL")
    )
    mutation_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    proposal_source: Mapped[str] = mapped_column(
        String(40), nullable=False, default="legacy_unknown"
    )
    objective_source: Mapped[str] = mapped_column(
        String(40), nullable=False, default="legacy_unknown"
    )
    proposal_fallback_reason: Mapped[str | None] = mapped_column(String(255))
    sequence_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    subcategory: Mapped[str] = mapped_column(String(100), nullable=False)
    owasp_mappings: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False, default=list)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_sequence: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    executed_sequence: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    taxonomy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    evidence_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    evidence_payload: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    evidence_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    langfuse_trace_id: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    campaign: Mapped[Campaign] = relationship(back_populates="attempts")
    verdict: Mapped[JudgeVerdict | None] = relationship(
        back_populates="attempt", uselist=False, cascade="all, delete-orphan"
    )


class JudgeVerdict(TimestampMixin, Base):
    __tablename__ = "judge_verdicts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    attempt_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_attempts.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    verdict: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    exploitability: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(5, 4), nullable=False)
    evidence_references: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False, default=list)
    violated_invariants: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False, default=list)
    next_recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    rubric_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    rubric_version: Mapped[str] = mapped_column(String(64), nullable=False)
    deterministic_override_applied: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    deterministic_override_reason: Mapped[str | None] = mapped_column(Text)

    attempt: Mapped[AttackAttempt] = relationship(back_populates="verdict")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
        Index("ix_findings_severity_status", "severity", "status"),
        Index("ix_findings_category_subcategory", "category", "subcategory"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    source_attempt_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("attack_attempts.id", ondelete="RESTRICT"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    subcategory: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    description: Mapped[str] = mapped_column(Text, nullable=False)
    clinical_impact: Mapped[str] = mapped_column(Text, nullable=False)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    observed_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen_target_version: Mapped[str] = mapped_column(String(255), nullable=False)
    last_seen_target_version: Mapped[str] = mapped_column(String(255), nullable=False)
    current_regression_case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "regression_cases.id",
            name="fk_findings_current_regression_case_id_regression_cases",
            ondelete="SET NULL",
            use_alter=True,
        )
    )

    reports: Mapped[list[VulnerabilityReport]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class VulnerabilityReport(TimestampMixin, Base):
    __tablename__ = "vulnerability_reports"
    __table_args__ = (UniqueConstraint("finding_id", "report_version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    report_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    structured_report: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    markdown_body: Mapped[str] = mapped_column(Text, nullable=False)
    markdown_path: Mapped[str | None] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    validation_summary: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")

    finding: Mapped[Finding] = relationship(back_populates="reports")


class RegressionCase(TimestampMixin, Base):
    __tablename__ = "regression_cases"
    __table_args__ = (
        UniqueConstraint("finding_id", "case_version"),
        Index("ix_regression_cases_category", "category"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    case_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    setup: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    ordered_sequence: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    expected_security_invariants: Mapped[list[str]] = mapped_column(
        JSON_TYPE, nullable=False, default=list
    )
    deterministic_checks: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_TYPE, nullable=False, default=list
    )
    judge_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    judge_rubric_subset: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    subcategory: Mapped[str] = mapped_column(String(100), nullable=False)
    owasp_mappings: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False, default=list)
    target_requirements: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    created_from_evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class RegressionRun(TimestampMixin, Base):
    __tablename__ = "regression_runs"
    __table_args__ = (Index("ix_regression_runs_target_version", "target_version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_version: Mapped[str] = mapped_column(String(255), nullable=False)
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL")
    )
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued")
    total_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reproduced_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inconclusive_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_cases: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    results: Mapped[list[RegressionResult]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class RegressionResult(TimestampMixin, Base):
    __tablename__ = "regression_results"
    __table_args__ = (
        UniqueConstraint("run_id", "case_id", "case_version"),
        Index("ix_regression_results_run_case", "run_id", "case_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("regression_runs.id", ondelete="CASCADE"), nullable=False
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("regression_cases.id", ondelete="RESTRICT"), nullable=False
    )
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    deterministic_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_TYPE, nullable=False, default=list
    )
    judge_result: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    evidence_references: Mapped[list[str]] = mapped_column(JSON_TYPE, nullable=False, default=list)
    estimated_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    trace_id: Mapped[str | None] = mapped_column(String(255), index=True)

    run: Mapped[RegressionRun] = relationship(back_populates="results")


class AgentRun(TimestampMixin, Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        Index("ix_agent_runs_role_created", "role", "created_at"),
        Index("ix_agent_runs_trace_id", "langfuse_trace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), index=True
    )
    attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("attack_attempts.id", ondelete="SET NULL"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), index=True
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[Decimal] = mapped_column(MONEY, nullable=False, default=Decimal("0"))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    langfuse_trace_id: Mapped[str | None] = mapped_column(String(255))
    typed_error: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)

    campaign: Mapped[Campaign | None] = relationship(back_populates="agent_runs")
