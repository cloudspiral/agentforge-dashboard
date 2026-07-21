from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

from agentforge.observability.metrics import AgentForgeMetrics
from agentforge.persistence import Database
from agentforge.persistence.repositories import CampaignRepository
from agentforge.security.redaction import redact
from agentforge.settings import Settings

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CampaignProcessResult:
    status: str
    actual_cost_usd: Decimal = Decimal("0")
    sanitized_error: dict[str, Any] | None = None


class CampaignProcessor(Protocol):
    async def process(self, campaign_id: uuid.UUID) -> CampaignProcessResult: ...


class CampaignWorker:
    def __init__(
        self,
        *,
        database: Database,
        settings: Settings,
        processor: CampaignProcessor,
        metrics: AgentForgeMetrics,
        worker_name: str = "primary",
    ) -> None:
        self.database = database
        self.settings = settings
        self.processor = processor
        self.metrics = metrics
        self.worker_name = worker_name
        self._stop = asyncio.Event()

    def request_stop(self) -> None:
        self._stop.set()

    async def _db(self, function: Callable[[], Any]) -> Any:
        return await asyncio.to_thread(function)

    def _recover_stale(self) -> int:
        with self.database.session_factory() as session:
            return CampaignRepository(session).recover_stale(
                self.settings.worker_stale_after_seconds
            )

    def _claim(self) -> uuid.UUID | None:
        with self.database.session_factory() as session:
            campaign = CampaignRepository(session).claim_next()
            return campaign.id if campaign else None

    def _heartbeat(self, campaign_id: uuid.UUID) -> None:
        with self.database.session_factory() as session:
            CampaignRepository(session).heartbeat(campaign_id)

    def _finish(self, campaign_id: uuid.UUID, result: CampaignProcessResult) -> None:
        with self.database.session_factory() as session:
            CampaignRepository(session).finish(
                campaign_id,
                status=result.status,
                actual_cost_usd=result.actual_cost_usd,
                sanitized_error=result.sanitized_error,
            )

    def _queue_stats(self) -> tuple[int, float]:
        with self.database.session_factory() as session:
            return CampaignRepository(session).queue_stats()

    async def _heartbeat_loop(self, campaign_id: uuid.UUID, done: asyncio.Event) -> None:
        interval = max(5.0, self.settings.worker_stale_after_seconds / 3)
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), timeout=interval)
            except TimeoutError:
                try:
                    await self._db(lambda: self._heartbeat(campaign_id))
                except Exception:
                    LOGGER.exception(
                        "campaign heartbeat failed", extra={"campaign_id": campaign_id}
                    )

    async def run_once(self) -> bool:
        campaign_id = await self._db(self._claim)
        if campaign_id is None:
            return False

        self.metrics.worker_active.labels(worker=self.worker_name).set(1)
        done = asyncio.Event()
        heartbeat_task = asyncio.create_task(self._heartbeat_loop(campaign_id, done))
        cancelled = False
        try:
            result = await self.processor.process(campaign_id)
        except asyncio.CancelledError:
            cancelled = True
            result = CampaignProcessResult(
                status="interrupted",
                sanitized_error={"code": "worker_cancelled", "message": "worker shutdown"},
            )
        except Exception as exc:
            LOGGER.exception("campaign processing failed", extra={"campaign_id": campaign_id})
            result = CampaignProcessResult(
                status="failed",
                sanitized_error=redact(
                    {
                        "code": "unexpected_internal_error",
                        "type": type(exc).__name__,
                        "message": str(exc)[:500],
                    }
                ),
            )
        finally:
            done.set()
            await heartbeat_task
            self.metrics.worker_active.labels(worker=self.worker_name).set(0)

        await self._db(lambda: self._finish(campaign_id, result))
        self.metrics.campaigns_total.labels(
            status=result.status,
            campaign_type="bounded",
        ).inc()
        if cancelled:
            raise asyncio.CancelledError
        return True

    async def run_forever(self) -> None:
        recovered = await self._db(self._recover_stale)
        if recovered:
            LOGGER.warning("marked stale campaigns interrupted", extra={"count": recovered})
        while not self._stop.is_set():
            try:
                depth, age = await self._db(self._queue_stats)
                self.metrics.queue_depth.labels(queue="campaigns").set(depth)
                self.metrics.queue_oldest_age_seconds.labels(queue="campaigns").set(age)
                processed = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("worker polling iteration failed")
                processed = False
            if not processed:
                with suppress(TimeoutError):
                    await asyncio.wait_for(
                        self._stop.wait(),
                        timeout=self.settings.worker_poll_seconds,
                    )


async def run_worker_until_cancelled(worker: CampaignWorker) -> None:
    try:
        await worker.run_forever()
    finally:
        worker.request_stop()


ProcessorFactory = Callable[[], Awaitable[CampaignProcessor]]
