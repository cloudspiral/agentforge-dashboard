"""Process-local coordinator for dashboard-triggered live evaluations."""

from __future__ import annotations

import asyncio
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agentforge.evaluation.catalog import TaxonomyV1
from agentforge.evaluation.live_local import LiveLocalEvaluationResultV1, run_live_local_case
from agentforge.observability import LangfuseTelemetry
from agentforge.persistence import Database
from agentforge.persistence.repositories import CampaignRepository
from agentforge.settings import Settings
from agentforge.target.profile import LoadedTargetProfile


class EvaluationAlreadyRunning(RuntimeError):
    """Raised when a second browser evaluation is requested."""


class EvaluationStartFailed(RuntimeError):
    """Raised when an evaluation fails before its campaign is persisted."""


class EvaluationRunner(Protocol):
    async def __call__(self, **kwargs: Any) -> LiveLocalEvaluationResultV1: ...


@dataclass(frozen=True, slots=True)
class DashboardEvaluationSnapshot:
    phase: str
    case_id: str | None = None
    campaign_id: uuid.UUID | None = None
    result_path: str | None = None
    error_message: str | None = None

    @property
    def active(self) -> bool:
        return self.phase in {"starting", "running"}


class DashboardEvaluationManager:
    """Run at most one exact seed case in the single Railway web process."""

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        loaded_profile: LoadedTargetProfile,
        taxonomy: TaxonomyV1,
        telemetry: LangfuseTelemetry,
        repository_root: Path,
        runner: EvaluationRunner = run_live_local_case,
    ) -> None:
        self.settings = settings
        self.database = database
        self.loaded_profile = loaded_profile
        self.taxonomy = taxonomy
        self.telemetry = telemetry
        self.repository_root = repository_root
        self.runner = runner
        self._start_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._snapshot = DashboardEvaluationSnapshot(phase="idle")

    def snapshot(self) -> DashboardEvaluationSnapshot:
        return self._snapshot

    async def start(self, *, case_id: str, case_path: Path) -> uuid.UUID:
        """Start one case and return once its durable campaign row exists."""

        async with self._start_lock:
            if self._task is not None and not self._task.done():
                raise EvaluationAlreadyRunning("another dashboard evaluation is already running")

            loop = asyncio.get_running_loop()
            campaign_ready: asyncio.Future[uuid.UUID] = loop.create_future()
            self._snapshot = DashboardEvaluationSnapshot(phase="starting", case_id=case_id)

            def campaign_persisted(campaign_id: uuid.UUID) -> None:
                if not campaign_ready.done():
                    campaign_ready.set_result(campaign_id)
                self._snapshot = DashboardEvaluationSnapshot(
                    phase="running",
                    case_id=case_id,
                    campaign_id=campaign_id,
                )

            async def execute() -> None:
                try:
                    result = await self.runner(
                        case_path=case_path,
                        settings=self.settings,
                        database=self.database,
                        loaded_profile=self.loaded_profile,
                        taxonomy=self.taxonomy,
                        telemetry=self.telemetry,
                        target_alias="deployed",
                        headed=False,
                        repository_root=self.repository_root,
                        on_campaign_persisted=campaign_persisted,
                    )
                    self._snapshot = DashboardEvaluationSnapshot(
                        phase=result.status,
                        case_id=case_id,
                        campaign_id=uuid.UUID(result.campaign_id),
                        result_path=result.result_path,
                        error_message=result.error_message,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    if not campaign_ready.done():
                        campaign_ready.set_exception(
                            EvaluationStartFailed(
                                "the evaluation failed before its campaign could be created"
                            )
                        )
                    current = self._snapshot
                    self._snapshot = DashboardEvaluationSnapshot(
                        phase="failed",
                        case_id=case_id,
                        campaign_id=current.campaign_id,
                        error_message="the dashboard evaluation did not complete",
                    )
                    if current.campaign_id is not None:
                        self._mark_terminal(
                            current.campaign_id,
                            status="failed",
                            code="dashboard_evaluation_failed",
                            message="the dashboard evaluation did not complete",
                        )

            self._task = asyncio.create_task(execute(), name=f"dashboard-eval-{case_id}")

        try:
            return await asyncio.wait_for(asyncio.shield(campaign_ready), timeout=30)
        except TimeoutError as exc:
            raise EvaluationStartFailed(
                "the evaluation did not create its campaign within 30 seconds"
            ) from exc

    def _mark_terminal(
        self,
        campaign_id: uuid.UUID,
        *,
        status: str,
        code: str,
        message: str,
    ) -> None:
        with self.database.session_factory() as session:
            CampaignRepository(session).finish(
                campaign_id,
                status=status,
                sanitized_error={"code": code, "message": message},
                worker_name="dashboard-evaluation",
            )

    async def shutdown(self) -> None:
        task = self._task
        if task is None or task.done():
            return
        campaign_id = self._snapshot.campaign_id
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if campaign_id is not None:
            self._mark_terminal(
                campaign_id,
                status="interrupted",
                code="dashboard_shutdown",
                message="the dashboard stopped while the evaluation was running",
            )


__all__ = [
    "DashboardEvaluationManager",
    "DashboardEvaluationSnapshot",
    "EvaluationAlreadyRunning",
    "EvaluationStartFailed",
]
