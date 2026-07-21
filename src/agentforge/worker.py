"""Standalone campaign-worker entrypoint for future split-service deployment."""

from __future__ import annotations

import asyncio
from contextlib import suppress

from agentforge.logging import configure_logging
from agentforge.observability import AgentForgeMetrics, LangfuseTelemetry, metrics
from agentforge.orchestration.worker import (
    CampaignProcessor,
    CampaignWorker,
    run_worker_until_cancelled,
)
from agentforge.persistence import Database
from agentforge.settings import Settings, get_settings


def build_processor(
    *,
    database: Database,
    settings: Settings,
    app_metrics: AgentForgeMetrics,
    telemetry: LangfuseTelemetry,
) -> CampaignProcessor:
    from agentforge.orchestration.controller import build_campaign_controller

    return build_campaign_controller(
        database=database,
        settings=settings,
        metrics=app_metrics,
        telemetry=telemetry,
    )


async def serve_worker(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    telemetry: LangfuseTelemetry | None = None,
    app_metrics: AgentForgeMetrics = metrics,
    processor: CampaignProcessor | None = None,
) -> None:
    """Run one polling worker until cancelled, then close owned runtime resources."""

    configured_settings = settings or get_settings()
    configured_database = database or Database(configured_settings.database_url)
    configured_telemetry = telemetry or LangfuseTelemetry.from_settings(configured_settings)
    configured_processor = processor or build_processor(
        database=configured_database,
        settings=configured_settings,
        app_metrics=app_metrics,
        telemetry=configured_telemetry,
    )
    configure_logging(configured_settings.log_level)
    worker = CampaignWorker(
        database=configured_database,
        settings=configured_settings,
        processor=configured_processor,
        metrics=app_metrics,
    )
    try:
        await run_worker_until_cancelled(worker)
    finally:
        configured_telemetry.flush()
        configured_telemetry.shutdown()
        configured_database.dispose()


def main() -> None:
    with suppress(KeyboardInterrupt):
        asyncio.run(serve_worker())


if __name__ == "__main__":
    main()


__all__ = ["build_processor", "main", "serve_worker"]
