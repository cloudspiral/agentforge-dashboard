from __future__ import annotations

import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from agentforge.persistence.models import (
    AgentRun,
    AttackAttempt,
    Campaign,
    CampaignEvent,
    Finding,
    FindingLifecycleEvent,
    FindingObservation,
    JudgeVerdict,
    PlatformEvent,
    RegressionCase,
    RegressionReplay,
    RegressionResult,
    RegressionRun,
    VulnerabilityReport,
)


class DuplicateIdempotencyKey(ValueError):
    pass


class CampaignNotFound(LookupError):
    pass


class CampaignRepository:
    GLOBAL_QUEUE_LOCK = 2_145_117_049
    TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})

    def __init__(self, session: Session) -> None:
        self.session = session

    @staticmethod
    def _event(
        campaign: Campaign,
        *,
        event_type: str,
        from_status: str | None,
        to_status: str,
        worker_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> CampaignEvent:
        event = CampaignEvent(
            event_type=event_type,
            from_status=from_status,
            to_status=to_status,
            worker_name=worker_name,
            details_json=details or {},
        )
        campaign.events.append(event)
        return event

    def create(
        self,
        *,
        campaign_type: str,
        trigger_type: str,
        target_alias: str,
        target_version: str,
        category_scope: str | None,
        subcategory_scope: str | None,
        max_cost_usd: Decimal,
        max_attempts: int,
        max_duration_seconds: int,
        priority: int = 0,
        idempotency_key: str | None = None,
        commit: bool = True,
    ) -> Campaign:
        campaign = Campaign(
            campaign_type=campaign_type,
            trigger_type=trigger_type,
            target_alias=target_alias,
            target_version=target_version,
            category_scope=category_scope,
            subcategory_scope=subcategory_scope,
            max_cost_usd=max_cost_usd,
            max_attempts=max_attempts,
            max_duration_seconds=max_duration_seconds,
            priority=priority,
            idempotency_key=idempotency_key,
        )
        self._event(
            campaign,
            event_type="created",
            from_status=None,
            to_status="queued",
            details={"trigger_type": trigger_type},
        )
        self.session.add(campaign)
        try:
            if commit:
                self.session.commit()
            else:
                self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            if idempotency_key:
                existing = self.get_by_idempotency_key(idempotency_key)
                if existing:
                    return existing
                raise DuplicateIdempotencyKey(idempotency_key) from exc
            raise
        if commit:
            self.session.refresh(campaign)
        return campaign

    def get(self, campaign_id: uuid.UUID, *, include_attempts: bool = False) -> Campaign:
        statement = select(Campaign).where(Campaign.id == campaign_id)
        if include_attempts:
            statement = statement.options(
                selectinload(Campaign.attempts),
                selectinload(Campaign.events),
            )
        campaign = self.session.scalar(statement)
        if not campaign:
            raise CampaignNotFound(str(campaign_id))
        return campaign

    def get_by_idempotency_key(self, key: str) -> Campaign | None:
        return self.session.scalar(select(Campaign).where(Campaign.idempotency_key == key))

    def list(self, *, offset: int = 0, limit: int = 50) -> tuple[list[Campaign], int]:
        total = self.session.scalar(select(func.count()).select_from(Campaign)) or 0
        rows = list(
            self.session.scalars(
                select(Campaign).order_by(Campaign.created_at.desc()).offset(offset).limit(limit)
            )
        )
        return rows, total

    def queue_stats(self) -> tuple[int, float]:
        now = datetime.now(UTC)
        depth = (
            self.session.scalar(
                select(func.count()).select_from(Campaign).where(Campaign.status == "queued")
            )
            or 0
        )
        oldest = self.session.scalar(
            select(func.min(Campaign.created_at)).where(Campaign.status == "queued")
        )
        age = max(0.0, (now - oldest).total_seconds()) if oldest else 0.0
        return depth, age

    def cancel(self, campaign_id: uuid.UUID) -> Campaign:
        campaign = self.session.scalar(
            select(Campaign).where(Campaign.id == campaign_id).with_for_update()
        )
        if not campaign:
            raise CampaignNotFound(str(campaign_id))
        if campaign.status == "queued":
            previous_status = campaign.status
            campaign.status = "cancelled"
            campaign.completed_at = datetime.now(UTC)
            self._event(
                campaign,
                event_type="cancelled",
                from_status=previous_status,
                to_status=campaign.status,
            )
        elif campaign.status == "running":
            if not campaign.cancellation_requested:
                campaign.cancellation_requested = True
                self._event(
                    campaign,
                    event_type="cancellation_requested",
                    from_status=campaign.status,
                    to_status=campaign.status,
                )
        self.session.commit()
        return campaign

    def claim_next(self, *, worker_name: str | None = None) -> Campaign | None:
        if self.session.bind and self.session.bind.dialect.name == "postgresql":
            locked = self.session.scalar(
                text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                {"lock_id": self.GLOBAL_QUEUE_LOCK},
            )
            if not locked:
                self.session.rollback()
                return None
        running = self.session.scalar(
            select(func.count()).select_from(Campaign).where(Campaign.status == "running")
        )
        if running:
            self.session.rollback()
            return None
        campaign = self.session.scalar(
            select(Campaign)
            .where(Campaign.status == "queued")
            .order_by(Campaign.priority.desc(), Campaign.created_at.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if not campaign:
            self.session.rollback()
            return None
        now = datetime.now(UTC)
        campaign.status = "running"
        campaign.started_at = now
        campaign.heartbeat_at = now
        self._event(
            campaign,
            event_type="claimed",
            from_status="queued",
            to_status=campaign.status,
            worker_name=worker_name,
        )
        self.session.commit()
        return campaign

    def heartbeat(self, campaign_id: uuid.UUID) -> None:
        campaign = self.get(campaign_id)
        campaign.heartbeat_at = datetime.now(UTC)
        self.session.commit()

    def finish(
        self,
        campaign_id: uuid.UUID,
        *,
        status: str,
        actual_cost_usd: Decimal | None = None,
        sanitized_error: dict[str, Any] | None = None,
        worker_name: str | None = None,
    ) -> Campaign:
        if status not in self.TERMINAL_STATUSES:
            raise ValueError(f"unsupported terminal campaign status: {status}")
        campaign = self.session.scalar(
            select(Campaign).where(Campaign.id == campaign_id).with_for_update()
        )
        if not campaign:
            raise CampaignNotFound(str(campaign_id))
        if campaign.status != "running":
            self.session.commit()
            return campaign
        effective_status = "cancelled" if campaign.cancellation_requested else status
        campaign.status = effective_status
        campaign.completed_at = datetime.now(UTC)
        campaign.heartbeat_at = campaign.completed_at
        if actual_cost_usd is not None:
            campaign.actual_cost_usd = actual_cost_usd
        if effective_status == "cancelled" and sanitized_error is None:
            sanitized_error = {
                "code": "cancellation_requested",
                "message": "campaign cancellation was requested",
            }
        campaign.sanitized_error = sanitized_error
        details: dict[str, Any] = {"actual_cost_usd": str(campaign.actual_cost_usd)}
        if sanitized_error and sanitized_error.get("code"):
            details["error_code"] = str(sanitized_error["code"])
        self._event(
            campaign,
            event_type="finished",
            from_status="running",
            to_status=effective_status,
            worker_name=worker_name,
            details=details,
        )
        self.session.commit()
        return campaign

    def recover_stale(self, stale_after_seconds: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(seconds=stale_after_seconds)
        stale = list(
            self.session.scalars(
                select(Campaign)
                .where(Campaign.status == "running")
                .where(Campaign.heartbeat_at.is_not(None))
                .where(Campaign.heartbeat_at < cutoff)
                .with_for_update(skip_locked=True)
            )
        )
        for campaign in stale:
            previous_status = campaign.status
            campaign.status = "interrupted"
            campaign.completed_at = datetime.now(UTC)
            campaign.sanitized_error = {
                "code": "worker_heartbeat_stale",
                "message": "worker stopped updating the campaign heartbeat",
            }
            self._event(
                campaign,
                event_type="stale_recovered",
                from_status=previous_status,
                to_status=campaign.status,
                details={"error_code": "worker_heartbeat_stale"},
            )
        self.session.commit()
        return len(stale)


class FindingRepository:
    ALLOWED_STATUSES = {
        "pending_review",
        "open",
        "in_progress",
        "resolved",
        "false_positive",
    }
    ACTION_TARGETS = {
        "confirm": {"pending_review": "open"},
        "begin_work": {"open": "in_progress"},
        "dismiss": {
            "pending_review": "false_positive",
            "open": "false_positive",
            "in_progress": "false_positive",
        },
        "resolve": {"open": "resolved", "in_progress": "resolved"},
    }

    def __init__(self, session: Session) -> None:
        self.session = session

    def list(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        include_reports: bool = False,
    ) -> tuple[list[Finding], int]:
        total = self.session.scalar(select(func.count()).select_from(Finding)) or 0
        statement = select(Finding).order_by(Finding.updated_at.desc()).offset(offset).limit(limit)
        if include_reports:
            statement = statement.options(selectinload(Finding.reports))
        findings = list(self.session.scalars(statement))
        return findings, total

    def get(self, finding_id: uuid.UUID, *, include_reports: bool = False) -> Finding:
        statement = select(Finding).where(Finding.id == finding_id)
        if include_reports:
            statement = statement.options(
                selectinload(Finding.reports),
                selectinload(Finding.lifecycle_events),
                selectinload(Finding.observations),
            )
        finding = self.session.scalar(statement)
        if finding is None:
            raise LookupError(str(finding_id))
        return finding

    def transition(
        self,
        finding_id: uuid.UUID,
        *,
        action: str,
        actor: str,
        reason: str | None = None,
        evidence_reference: str | None = None,
        secure_evidence_on_changed_version: bool = False,
        manual_override: bool = False,
    ) -> Finding:
        finding = self.session.scalar(
            select(Finding).where(Finding.id == finding_id).with_for_update()
        )
        if finding is None:
            raise LookupError(str(finding_id))
        target = self.ACTION_TARGETS.get(action, {}).get(finding.status)
        if target is None:
            raise ValueError(f"action {action!r} is invalid from status {finding.status!r}")
        normalized_reason = reason.strip() if isinstance(reason, str) else None
        if action == "dismiss" and not normalized_reason:
            raise ValueError("dismissing a finding requires a reason")
        if action == "resolve":
            evidence_based = bool(evidence_reference and secure_evidence_on_changed_version)
            if not evidence_based and not (manual_override and normalized_reason):
                raise ValueError(
                    "resolution requires changed-version secure evidence or a reasoned override"
                )
        previous = finding.status
        finding.status = target
        self.session.add(
            FindingLifecycleEvent(
                finding_id=finding.id,
                from_status=previous,
                to_status=target,
                action=("manual_resolution_override" if manual_override else action),
                actor=actor,
                reason=normalized_reason,
                evidence_reference=evidence_reference,
                details_json={
                    "secure_evidence_on_changed_version": secure_evidence_on_changed_version,
                    "manual_override": manual_override,
                },
            )
        )
        PlatformEventRepository(self.session).record(
            event_type="finding_lifecycle_transition",
            actor=actor,
            finding_id=finding.id,
            details={
                "from_status": previous,
                "to_status": target,
                "action": ("manual_resolution_override" if manual_override else action),
                "reason": normalized_reason,
                "evidence_reference": evidence_reference,
            },
        )
        self.session.flush()
        return finding

    def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        return self.session.scalar(
            select(Finding).where(Finding.fingerprint == fingerprint).with_for_update()
        )

    def create_confirmed(
        self,
        *,
        fingerprint: str,
        finding_key: str,
        provenance: str,
        source_attempt_id: uuid.UUID,
        vulnerability_id: str,
        title: str,
        category: str,
        subcategory: str,
        severity: str,
        description: str,
        clinical_impact: str,
        expected_behavior: str,
        observed_behavior: str,
        target_version: str,
    ) -> Finding:
        finding = Finding(
            vulnerability_id=vulnerability_id,
            fingerprint=fingerprint,
            finding_key=finding_key,
            provenance=provenance,
            source_attempt_id=source_attempt_id,
            title=title,
            category=category,
            subcategory=subcategory,
            severity=severity,
            status="pending_review",
            description=description,
            clinical_impact=clinical_impact,
            expected_behavior=expected_behavior,
            observed_behavior=observed_behavior,
            first_seen_target_version=target_version,
            last_seen_target_version=target_version,
        )
        self.session.add(finding)
        self.session.flush()
        self.session.add(
            FindingLifecycleEvent(
                finding_id=finding.id,
                from_status=None,
                to_status="pending_review",
                action="judge_confirmed",
                actor="agentforge:promotion",
                reason=None,
                evidence_reference=str(source_attempt_id),
                details_json={"provenance": provenance},
            )
        )
        PlatformEventRepository(self.session).record(
            event_type="finding_confirmed",
            actor="agentforge:promotion",
            finding_id=finding.id,
            details={
                "status": "pending_review",
                "provenance": provenance,
                "source_attempt_id": str(source_attempt_id),
            },
        )
        return finding

    def record_observation(
        self,
        *,
        finding: Finding,
        attempt_id: uuid.UUID,
        target_version: str,
        provenance: str,
        evidence_hash: str,
        judge_verdict: dict[str, Any],
        observation_kind: str = "confirmation",
    ) -> FindingObservation:
        existing = self.session.scalar(
            select(FindingObservation).where(
                FindingObservation.finding_id == finding.id,
                FindingObservation.attempt_id == attempt_id,
            )
        )
        if existing is not None:
            return existing
        observation = FindingObservation(
            finding_id=finding.id,
            attempt_id=attempt_id,
            target_version=target_version,
            provenance=provenance,
            evidence_hash=evidence_hash,
            judge_verdict=judge_verdict,
            observation_kind=observation_kind,
        )
        self.session.add(observation)
        finding.last_seen_target_version = target_version
        if attempt_id != finding.source_attempt_id:
            finding.rediscovery_count += 1
        self.session.flush()
        return observation

    def reopen_from_regression(
        self,
        finding_id: uuid.UUID,
        *,
        actor: str,
        evidence_reference: str,
    ) -> Finding:
        finding = self.session.scalar(
            select(Finding).where(Finding.id == finding_id).with_for_update()
        )
        if finding is None:
            raise LookupError(str(finding_id))
        previous = finding.status
        if finding.status == "resolved":
            finding.status = "open"
        elif finding.status == "false_positive":
            finding.status = "pending_review"
        else:
            return finding
        self.session.add(
            FindingLifecycleEvent(
                finding_id=finding.id,
                from_status=previous,
                to_status=finding.status,
                action="regression_reproduced",
                actor=actor,
                reason="A Judge-confirmed replay reproduced the saved vulnerability.",
                evidence_reference=evidence_reference,
                details_json={"immutable_reopen_event": True},
            )
        )
        PlatformEventRepository(self.session).record(
            event_type="finding_reopened_by_regression",
            actor=actor,
            finding_id=finding.id,
            details={
                "from_status": previous,
                "to_status": finding.status,
                "evidence_reference": evidence_reference,
            },
        )
        self.session.flush()
        return finding


class ReportRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def latest_for_finding(self, finding_id: uuid.UUID) -> VulnerabilityReport:
        report = self.session.scalar(
            select(VulnerabilityReport)
            .where(VulnerabilityReport.finding_id == finding_id)
            .order_by(VulnerabilityReport.report_version.desc())
            .limit(1)
        )
        if report is None:
            raise LookupError(str(finding_id))
        return report

    def create_versioned(
        self,
        *,
        finding_id: uuid.UUID,
        structured_report: dict[str, Any],
        markdown_body: str,
        validation_summary: dict[str, Any],
        prompt_version: str,
        status: str = "pending_review",
    ) -> VulnerabilityReport:
        version = (
            self.session.scalar(
                select(func.coalesce(func.max(VulnerabilityReport.report_version), 0)).where(
                    VulnerabilityReport.finding_id == finding_id
                )
            )
            or 0
        ) + 1
        report = VulnerabilityReport(
            finding_id=finding_id,
            report_version=version,
            structured_report=structured_report,
            markdown_body=markdown_body,
            markdown_path=None,
            status=status,
            validation_summary=validation_summary,
            prompt_version=prompt_version,
            schema_version="v2",
        )
        self.session.add(report)
        self.session.flush()
        return report


class RegressionCaseRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def active(self) -> list[RegressionCase]:
        return list(
            self.session.scalars(
                select(RegressionCase)
                .where(RegressionCase.active.is_(True))
                .order_by(RegressionCase.created_at, RegressionCase.id)
            )
        )

    def list(self, *, active_only: bool = False) -> list[RegressionCase]:
        statement = select(RegressionCase).order_by(
            RegressionCase.category,
            RegressionCase.subcategory,
            RegressionCase.case_id,
        )
        if active_only:
            statement = statement.where(RegressionCase.active.is_(True))
        return list(self.session.scalars(statement))

    def get(self, case_id: uuid.UUID) -> RegressionCase:
        row = self.session.get(RegressionCase, case_id)
        if row is None:
            raise LookupError(str(case_id))
        return row

    def create_versioned(
        self,
        *,
        finding_id: uuid.UUID,
        case_payload: dict[str, Any],
    ) -> RegressionCase:
        current_version = (
            self.session.scalar(
                select(func.coalesce(func.max(RegressionCase.case_version), 0)).where(
                    RegressionCase.finding_id == finding_id
                )
            )
            or 0
        )
        expected_version = current_version + 1
        if case_payload["case_version"] != expected_version:
            raise ValueError("regression case version is not the next finding version")
        for previous in self.session.scalars(
            select(RegressionCase)
            .where(RegressionCase.finding_id == finding_id)
            .where(RegressionCase.active.is_(True))
            .with_for_update()
        ):
            previous.active = False
        case = RegressionCase(
            case_id=case_payload["case_id"],
            finding_id=finding_id,
            case_version=expected_version,
            schema_version=case_payload.get("schema_version", "v2"),
            active=case_payload["active"],
            setup=case_payload["setup"],
            ordered_sequence=case_payload["exact_ordered_sequence"],
            judge_context=case_payload["judge_context"],
            expected_behavior=case_payload["expected_behavior"],
            category=case_payload["category"],
            subcategory=case_payload["subcategory"],
            owasp_mappings=case_payload["owasp_mappings"],
            target_requirements=case_payload["target_requirements"],
            created_from_evidence_hash=case_payload["created_from_evidence_hash"],
            sequence_hash=case_payload["sequence_hash"],
            fingerprint=case_payload["fingerprint"],
            finding_key=case_payload.get(
                "finding_key",
                case_payload.get("judge_context", {}).get("finding_key")
                or f"legacy-{case_payload['fingerprint'][:16]}",
            ),
            source_target_version=case_payload["target_requirements"]["source_target_version"],
            source_provenance=case_payload.get("source_provenance", "legacy_unknown"),
            required_replays=case_payload.get("required_replays", 2),
            created_at=case_payload["created_at"],
        )
        self.session.add(case)
        self.session.flush()
        return case


class RegressionRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        target_version: str,
        trigger: str,
        campaign_id: uuid.UUID | None = None,
        previous_target_version: str | None = None,
        cohort_hash: str | None = None,
        commit: bool = True,
    ) -> RegressionRun:
        run = RegressionRun(
            target_version=target_version,
            campaign_id=campaign_id,
            previous_target_version=previous_target_version,
            cohort_hash=cohort_hash,
            trigger=trigger,
            status="queued",
        )
        self.session.add(run)
        if commit:
            self.session.commit()
            self.session.refresh(run)
        else:
            self.session.flush()
        return run

    def list(self, *, offset: int = 0, limit: int = 50) -> tuple[list[RegressionRun], int]:
        total = self.session.scalar(select(func.count()).select_from(RegressionRun)) or 0
        runs = list(
            self.session.scalars(
                select(RegressionRun)
                .options(selectinload(RegressionRun.results).selectinload(RegressionResult.replays))
                .order_by(RegressionRun.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
        )
        return runs, total

    def get(self, run_id: uuid.UUID) -> RegressionRun:
        run = self.session.scalar(
            select(RegressionRun)
            .where(RegressionRun.id == run_id)
            .options(selectinload(RegressionRun.results).selectinload(RegressionResult.replays))
        )
        if run is None:
            raise LookupError(str(run_id))
        return run

    def for_campaign(self, campaign_id: uuid.UUID) -> RegressionRun:
        run = self.session.scalar(
            select(RegressionRun).where(RegressionRun.campaign_id == campaign_id).with_for_update()
        )
        if run is None:
            raise LookupError(str(campaign_id))
        return run

    def add_result(
        self,
        *,
        run_id: uuid.UUID,
        case_id: uuid.UUID,
        case_version: int,
        outcome: str,
        judge_result: dict[str, Any] | None,
        evidence_hash: str | None,
        estimated_cost_usd: Decimal,
        latency_ms: int | None,
        trace_id: str | None,
        changed_target_version: bool = False,
        aggregate_reason: str | None = None,
    ) -> RegressionResult:
        result = RegressionResult(
            run_id=run_id,
            case_id=case_id,
            case_version=case_version,
            outcome=outcome,
            judge_result=judge_result,
            evidence_hash=evidence_hash,
            estimated_cost_usd=estimated_cost_usd,
            latency_ms=latency_ms,
            trace_id=trace_id,
            changed_target_version=changed_target_version,
            aggregate_reason=aggregate_reason,
        )
        self.session.add(result)
        self.session.flush()
        return result

    def add_replay(
        self,
        *,
        result_id: uuid.UUID,
        attempt_id: uuid.UUID | None,
        replay_index: int,
        target_version: str,
        valid_replay: bool,
        judge_verdict: dict[str, Any] | None,
        evidence_hash: str | None,
        error: dict[str, Any] | None,
        estimated_cost_usd: Decimal,
        latency_ms: int | None,
        trace_id: str | None,
    ) -> RegressionReplay:
        replay = RegressionReplay(
            result_id=result_id,
            attempt_id=attempt_id,
            replay_index=replay_index,
            target_version=target_version,
            valid_replay=valid_replay,
            judge_verdict=judge_verdict,
            evidence_hash=evidence_hash,
            error=error,
            estimated_cost_usd=estimated_cost_usd,
            latency_ms=latency_ms,
            trace_id=trace_id,
        )
        self.session.add(replay)
        self.session.flush()
        return replay


class PlatformEventRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record(
        self,
        *,
        event_type: str,
        actor: str,
        campaign_id: uuid.UUID | None = None,
        attempt_id: uuid.UUID | None = None,
        finding_id: uuid.UUID | None = None,
        regression_run_id: uuid.UUID | None = None,
        role: str | None = None,
        model: str | None = None,
        prompt_version: str | None = None,
        trace_id: str | None = None,
        latency_ms: int | None = None,
        cost_usd: Decimal = Decimal("0"),
        details: dict[str, Any] | None = None,
    ) -> PlatformEvent:
        event = PlatformEvent(
            campaign_id=campaign_id,
            attempt_id=attempt_id,
            finding_id=finding_id,
            regression_run_id=regression_run_id,
            event_type=event_type,
            actor=actor,
            role=role,
            model=model,
            prompt_version=prompt_version,
            trace_id=trace_id,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            details_json=details or {},
        )
        self.session.add(event)
        self.session.flush()
        return event


class AgentRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(self, *, offset: int = 0, limit: int = 50) -> tuple[list[AgentRun], int]:
        total = self.session.scalar(select(func.count()).select_from(AgentRun)) or 0
        runs = list(
            self.session.scalars(
                select(AgentRun).order_by(AgentRun.created_at.desc()).offset(offset).limit(limit)
            )
        )
        return runs, total


class OperationalRepository:
    """Bounded, read-only queries shared by the local dashboard and metrics view."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def campaign_status_counts(self) -> dict[str, int]:
        return {
            status: count
            for status, count in self.session.execute(
                select(Campaign.status, func.count(Campaign.id)).group_by(Campaign.status)
            )
        }

    def latest_live_evaluations(self, case_hashes: dict[str, str]) -> dict[str, dict[str, Any]]:
        """Return the latest deployed single-case attempt for each requested seed ID."""

        if not case_hashes:
            return {}
        statement = (
            select(AttackAttempt, Campaign, JudgeVerdict)
            .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
            .outerjoin(JudgeVerdict, JudgeVerdict.attempt_id == AttackAttempt.id)
            .where(AttackAttempt.attack_family_id.in_(case_hashes))
            .where(Campaign.trigger_type == "live_deployed")
            .order_by(Campaign.created_at.desc(), AttackAttempt.created_at.desc())
        )
        latest: dict[str, dict[str, Any]] = {}
        for attempt, campaign, verdict in self.session.execute(statement):
            if attempt.seed_case_hash != case_hashes[attempt.attack_family_id]:
                continue
            latest.setdefault(
                attempt.attack_family_id,
                {"attempt": attempt, "campaign": campaign, "verdict": verdict},
            )
        return latest

    def campaign_rows(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[dict[str, Any]], int]:
        bounded_limit = min(max(limit, 1), 200)
        attempt_counts = (
            select(
                AttackAttempt.campaign_id.label("campaign_id"),
                func.count(AttackAttempt.id).label("attempt_count"),
            )
            .group_by(AttackAttempt.campaign_id)
            .subquery()
        )
        latest_worker = (
            select(CampaignEvent.worker_name)
            .where(CampaignEvent.campaign_id == Campaign.id)
            .where(CampaignEvent.worker_name.is_not(None))
            .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
            .limit(1)
            .correlate(Campaign)
            .scalar_subquery()
        )
        statement = (
            select(
                Campaign,
                func.coalesce(attempt_counts.c.attempt_count, 0),
                latest_worker,
            )
            .outerjoin(attempt_counts, attempt_counts.c.campaign_id == Campaign.id)
            .order_by(Campaign.created_at.desc(), Campaign.id.desc())
            .offset(max(offset, 0))
            .limit(bounded_limit)
        )
        total = self.session.scalar(select(func.count()).select_from(Campaign)) or 0
        rows = [
            {"campaign": campaign, "attempt_count": attempt_count, "worker_name": worker_name}
            for campaign, attempt_count, worker_name in self.session.execute(statement)
        ]
        return rows, total

    def recent_events(self, *, limit: int = 12) -> list[dict[str, Any]]:
        statement = (
            select(CampaignEvent, Campaign)
            .join(Campaign, Campaign.id == CampaignEvent.campaign_id)
            .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
            .limit(min(max(limit, 1), 100))
        )
        return [
            {"event": event, "campaign": campaign}
            for event, campaign in self.session.execute(statement)
        ]

    def campaign_detail(self, campaign_id: uuid.UUID) -> dict[str, Any]:
        campaign = CampaignRepository(self.session).get(campaign_id, include_attempts=True)
        attempts = sorted(campaign.attempts, key=lambda item: (item.created_at, str(item.id)))
        events = sorted(campaign.events, key=lambda item: (item.created_at, str(item.id)))
        attempt_ids = [attempt.id for attempt in attempts]
        verdicts = (
            {
                verdict.attempt_id: verdict
                for verdict in self.session.scalars(
                    select(JudgeVerdict).where(JudgeVerdict.attempt_id.in_(attempt_ids))
                )
            }
            if attempt_ids
            else {}
        )
        agent_runs = list(
            self.session.scalars(
                select(AgentRun)
                .where(AgentRun.campaign_id == campaign_id)
                .order_by(AgentRun.created_at, AgentRun.id)
            )
        )
        proposal_sources = Counter(attempt.proposal_source for attempt in attempts)
        objective_sources = Counter(attempt.objective_source for attempt in attempts)
        attempts_by_id = {attempt.id: attempt for attempt in attempts}
        generations: dict[uuid.UUID, int] = {}

        def generation(attempt: AttackAttempt, seen: frozenset[uuid.UUID] = frozenset()) -> int:
            if attempt.id in generations:
                return generations[attempt.id]
            if attempt.id in seen or attempt.parent_attempt_id is None:
                generations[attempt.id] = 0
                return 0
            parent = attempts_by_id.get(attempt.parent_attempt_id)
            value = 0 if parent is None else generation(parent, seen | {attempt.id}) + 1
            generations[attempt.id] = value
            return value

        for attempt in attempts:
            generation(attempt)
        proposal_verdict_counts: dict[str, Counter[str]] = {}
        for attempt in attempts:
            source_counts = proposal_verdict_counts.setdefault(
                attempt.proposal_source,
                Counter(),
            )
            source_counts["attempts"] += 1
            verdict = verdicts.get(attempt.id)
            source_counts[verdict.verdict if verdict is not None else "no_verdict"] += 1
        return {
            "campaign": campaign,
            "attempts": attempts,
            "events": events,
            "verdicts": verdicts,
            "agent_runs": agent_runs,
            "proposal_sources": proposal_sources,
            "objective_sources": objective_sources,
            "generations": generations,
            "proposal_verdict_counts": proposal_verdict_counts,
        }

    def queue_summary(self, *, stale_after_seconds: int) -> dict[str, Any]:
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=max(stale_after_seconds, 0))
        stale_condition = and_(
            Campaign.status == "running",
            or_(Campaign.heartbeat_at.is_(None), Campaign.heartbeat_at < cutoff),
        )
        row = self.session.execute(
            select(
                func.count(Campaign.id).filter(Campaign.status == "queued"),
                func.count(Campaign.id).filter(Campaign.status == "running"),
                func.min(Campaign.created_at).filter(Campaign.status == "queued"),
                func.count(Campaign.id).filter(stale_condition),
            )
        ).one()
        oldest = row[2]
        if oldest is not None and oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=UTC)
        oldest_age = max(0.0, (now - oldest).total_seconds()) if oldest else 0.0
        active_worker = self.session.execute(
            select(CampaignEvent.worker_name, Campaign.heartbeat_at)
            .join(Campaign, Campaign.id == CampaignEvent.campaign_id)
            .where(Campaign.status == "running")
            .where(CampaignEvent.event_type == "claimed")
            .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
            .limit(1)
        ).first()
        latest_worker = (
            active_worker
            or self.session.execute(
                select(CampaignEvent.worker_name, CampaignEvent.created_at)
                .where(CampaignEvent.worker_name.is_not(None))
                .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
                .limit(1)
            ).first()
        )
        worker_name = latest_worker[0] if latest_worker else None
        return {
            "depth": row[0] or 0,
            "running": row[1] or 0,
            "oldest_age_seconds": oldest_age,
            "stale_running": row[3] or 0,
            "worker_name": worker_name,
            "worker_status": "active" if active_worker else ("idle" if worker_name else "unknown"),
        }

    def finding_summary(self) -> dict[str, Any]:
        status_counts = {
            status: count
            for status, count in self.session.execute(
                select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
            )
        }
        report_count = (
            self.session.scalar(select(func.count()).select_from(VulnerabilityReport)) or 0
        )
        return {
            "total": sum(status_counts.values()),
            "active": sum(
                status_counts.get(status, 0) for status in ("pending_review", "open", "in_progress")
            ),
            "reports": report_count,
            "by_status": status_counts,
        }

    def regression_summary(self) -> dict[str, Any]:
        status_counts = {
            status: count
            for status, count in self.session.execute(
                select(RegressionRun.status, func.count(RegressionRun.id)).group_by(
                    RegressionRun.status
                )
            )
        }
        outcome_counts = {
            outcome: count
            for outcome, count in self.session.execute(
                select(RegressionResult.outcome, func.count(RegressionResult.id)).group_by(
                    RegressionResult.outcome
                )
            )
        }
        estimated_cost = self.session.scalar(select(func.sum(RegressionRun.estimated_cost_usd)))
        return {
            "total": sum(status_counts.values()),
            "by_status": status_counts,
            "outcomes": outcome_counts,
            "estimated_cost_usd": estimated_cost or Decimal("0"),
        }

    def activity_summary(self) -> dict[str, Any]:
        total_cost = self.session.scalar(select(func.sum(Campaign.actual_cost_usd))) or Decimal("0")
        average_latency = self.session.scalar(
            select(func.avg(AttackAttempt.latency_ms)).where(AttackAttempt.latency_ms.is_not(None))
        )
        total_attempts = self.session.scalar(select(func.count()).select_from(AttackAttempt)) or 0
        proposal_sources = {
            source: count
            for source, count in self.session.execute(
                select(AttackAttempt.proposal_source, func.count(AttackAttempt.id)).group_by(
                    AttackAttempt.proposal_source
                )
            )
        }
        return {
            "actual_cost_usd": total_cost,
            "average_attempt_latency_ms": float(average_latency or 0),
            "attempts": total_attempts,
            "proposal_sources": proposal_sources,
        }

    def metrics_snapshot(self, *, stale_after_seconds: int) -> dict[str, Any]:
        campaign_counts = [
            {"status": status, "campaign_type": campaign_type, "count": count}
            for status, campaign_type, count in self.session.execute(
                select(Campaign.status, Campaign.campaign_type, func.count(Campaign.id)).group_by(
                    Campaign.status, Campaign.campaign_type
                )
            )
        ]
        if self.session.bind is not None and self.session.bind.dialect.name == "postgresql":
            duration_expression = func.extract("epoch", Campaign.completed_at - Campaign.started_at)
        else:
            duration_expression = (
                func.julianday(Campaign.completed_at) - func.julianday(Campaign.started_at)
            ) * 86_400
        duration_rows = [
            {
                "status": status,
                "count": count,
                "sum": float(total or 0),
                "average": float(average or 0),
                "maximum": float(maximum or 0),
            }
            for status, count, total, average, maximum in self.session.execute(
                select(
                    Campaign.status,
                    func.count(Campaign.id),
                    func.sum(duration_expression),
                    func.avg(duration_expression),
                    func.max(duration_expression),
                )
                .where(Campaign.started_at.is_not(None), Campaign.completed_at.is_not(None))
                .group_by(Campaign.status)
            )
        ]
        attempts_row = self.session.execute(
            select(
                func.avg(Campaign.actual_attempts),
                func.max(Campaign.actual_attempts),
                func.sum(Campaign.actual_attempts),
            )
        ).one()
        event_counts = {
            event_type: count
            for event_type, count in self.session.execute(
                select(CampaignEvent.event_type, func.count(CampaignEvent.id)).group_by(
                    CampaignEvent.event_type
                )
            )
        }
        regression_runs = {
            status: count
            for status, count in self.session.execute(
                select(RegressionRun.status, func.count(RegressionRun.id)).group_by(
                    RegressionRun.status
                )
            )
        }
        regression_results = {
            outcome: count
            for outcome, count in self.session.execute(
                select(RegressionResult.outcome, func.count(RegressionResult.id)).group_by(
                    RegressionResult.outcome
                )
            )
        }
        agent_usage = [
            {
                "role": role,
                "input_tokens": input_tokens or 0,
                "output_tokens": output_tokens or 0,
                "cost_usd": cost_usd or Decimal("0"),
            }
            for role, input_tokens, output_tokens, cost_usd in self.session.execute(
                select(
                    AgentRun.role,
                    func.sum(AgentRun.input_tokens),
                    func.sum(AgentRun.output_tokens),
                    func.sum(AgentRun.estimated_cost_usd),
                ).group_by(AgentRun.role)
            )
        ]
        queue = self.queue_summary(stale_after_seconds=stale_after_seconds)
        return {
            "campaign_counts": campaign_counts,
            "queue": queue,
            "completed": sum(
                row["count"] for row in campaign_counts if row["status"] == "completed"
            ),
            "failed": sum(row["count"] for row in campaign_counts if row["status"] == "failed"),
            "durations": duration_rows,
            "attempts": {
                "average": float(attempts_row[0] or 0),
                "maximum": float(attempts_row[1] or 0),
                "sum": float(attempts_row[2] or 0),
            },
            "worker_claims": event_counts.get("claimed", 0),
            "worker_failures": sum(
                count
                for status, count in self.session.execute(
                    select(CampaignEvent.to_status, func.count(CampaignEvent.id))
                    .where(CampaignEvent.event_type == "finished")
                    .where(CampaignEvent.to_status == "failed")
                    .group_by(CampaignEvent.to_status)
                )
            ),
            "event_counts": event_counts,
            "regression_runs": regression_runs,
            "regression_results": regression_results,
            "agent_usage": agent_usage,
        }


def coverage_summary(session: Session) -> list[dict[str, Any]]:
    statement = (
        select(
            AttackAttempt.category,
            AttackAttempt.subcategory,
            Campaign.target_version,
            func.count(AttackAttempt.id),
            func.count(JudgeVerdict.id).filter(JudgeVerdict.verdict == "exploit_confirmed"),
            func.count(JudgeVerdict.id).filter(JudgeVerdict.verdict == "partial_signal"),
            func.count(JudgeVerdict.id).filter(JudgeVerdict.verdict == "attack_blocked"),
            func.count(JudgeVerdict.id).filter(JudgeVerdict.verdict == "inconclusive"),
        )
        .join(Campaign, Campaign.id == AttackAttempt.campaign_id)
        .outerjoin(JudgeVerdict, JudgeVerdict.attempt_id == AttackAttempt.id)
        .group_by(AttackAttempt.category, AttackAttempt.subcategory, Campaign.target_version)
        .order_by(AttackAttempt.category, AttackAttempt.subcategory, Campaign.target_version)
    )
    return [
        {
            "category": row[0],
            "subcategory": row[1],
            "target_version": row[2],
            "attempts": row[3],
            "exploit_confirmed": row[4],
            "partial_signal": row[5],
            "attack_blocked": row[6],
            "inconclusive": row[7],
            "secure_rate": (row[6] / sum(row[4:8]) if sum(row[4:8]) else 0.0),
            "confirmed_rate": (row[4] / sum(row[4:8]) if sum(row[4:8]) else 0.0),
        }
        for row in session.execute(statement)
    ]
