from __future__ import annotations

import uuid
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
    JudgeVerdict,
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
        max_mutations: int,
        no_signal_limit: int,
        priority: int = 0,
        idempotency_key: str | None = None,
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
            max_mutations=max_mutations,
            no_signal_limit=no_signal_limit,
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
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            if idempotency_key:
                existing = self.get_by_idempotency_key(idempotency_key)
                if existing:
                    return existing
                raise DuplicateIdempotencyKey(idempotency_key) from exc
            raise
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
    ALLOWED_STATUSES = {"open", "in_progress", "resolved", "reopened", "false_positive"}

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
        statement = (
            select(Finding).order_by(Finding.updated_at.desc()).offset(offset).limit(limit)
        )
        if include_reports:
            statement = statement.options(selectinload(Finding.reports))
        findings = list(
            self.session.scalars(statement)
        )
        return findings, total

    def get(self, finding_id: uuid.UUID, *, include_reports: bool = False) -> Finding:
        statement = select(Finding).where(Finding.id == finding_id)
        if include_reports:
            statement = statement.options(selectinload(Finding.reports))
        finding = self.session.scalar(statement)
        if finding is None:
            raise LookupError(str(finding_id))
        return finding

    def set_status(self, finding_id: uuid.UUID, status: str) -> Finding:
        if status not in self.ALLOWED_STATUSES:
            raise ValueError(f"unsupported finding status: {status}")
        finding = self.get(finding_id)
        finding.status = status
        self.session.commit()
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


class RegressionRunRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self,
        *,
        target_version: str,
        trigger: str,
        campaign_id: uuid.UUID | None = None,
    ) -> RegressionRun:
        run = RegressionRun(
            target_version=target_version,
            campaign_id=campaign_id,
            trigger=trigger,
            status="queued",
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def list(self, *, offset: int = 0, limit: int = 50) -> tuple[list[RegressionRun], int]:
        total = self.session.scalar(select(func.count()).select_from(RegressionRun)) or 0
        runs = list(
            self.session.scalars(
                select(RegressionRun)
                .options(selectinload(RegressionRun.results))
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
            .options(selectinload(RegressionRun.results))
        )
        if run is None:
            raise LookupError(str(run_id))
        return run


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
        return {
            "campaign": campaign,
            "attempts": attempts,
            "events": events,
            "verdicts": verdicts,
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
        latest_worker = active_worker or self.session.execute(
            select(CampaignEvent.worker_name, CampaignEvent.created_at)
            .where(CampaignEvent.worker_name.is_not(None))
            .order_by(CampaignEvent.created_at.desc(), CampaignEvent.id.desc())
            .limit(1)
        ).first()
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
        report_count = self.session.scalar(
            select(func.count()).select_from(VulnerabilityReport)
        ) or 0
        return {
            "total": sum(status_counts.values()),
            "active": sum(
                status_counts.get(status, 0) for status in ("open", "in_progress", "reopened")
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
        return {
            "actual_cost_usd": total_cost,
            "average_attempt_latency_ms": float(average_latency or 0),
            "attempts": total_attempts,
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
            duration_expression = func.extract(
                "epoch", Campaign.completed_at - Campaign.started_at
            )
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
        }
        for row in session.execute(statement)
    ]
