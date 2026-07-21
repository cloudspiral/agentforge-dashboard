"""FastAPI bootstrap for the AgentForge API, dashboard, metrics, and worker."""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import inspect

from agentforge.api import router as api_router
from agentforge.api.routes import ApiError
from agentforge.api.schemas import ErrorResponse
from agentforge.dashboard import router as dashboard_router
from agentforge.evaluation import (
    load_judge_rubric,
    load_seed_cases,
    load_taxonomy,
)
from agentforge.logging import configure_logging, correlation_id
from agentforge.observability import AgentForgeMetrics, LangfuseTelemetry, metrics
from agentforge.orchestration.worker import CampaignProcessor, CampaignWorker
from agentforge.persistence import Database
from agentforge.settings import Settings, get_settings
from agentforge.target import load_target_profile

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATIC_ROOT = Path(__file__).resolve().parent / "dashboard" / "static"
_SAFE_CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

ProcessorFactory = Callable[
    [Database, Settings, AgentForgeMetrics, LangfuseTelemetry],
    CampaignProcessor,
]


def _project_path(path: Path | str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _default_processor_factory(
    database: Database,
    settings: Settings,
    app_metrics: AgentForgeMetrics,
    telemetry: LangfuseTelemetry,
) -> CampaignProcessor:
    # Deferred to keep module import and credentialless health checks independent
    # from construction of agents, target runners, and the campaign controller.
    from agentforge.orchestration.controller import build_campaign_controller

    return build_campaign_controller(
        database=database,
        settings=settings,
        metrics=app_metrics,
        telemetry=telemetry,
    )


async def _stop_worker(worker: CampaignWorker, task: asyncio.Task[None], timeout: float) -> None:
    worker.request_stop()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
    except TimeoutError:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    except asyncio.CancelledError:
        if not task.done():
            task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    except Exception:
        LOGGER.exception("campaign worker terminated during application shutdown")


def create_app(
    *,
    settings: Settings | None = None,
    database: Database | None = None,
    telemetry: LangfuseTelemetry | None = None,
    app_metrics: AgentForgeMetrics = metrics,
    processor_factory: ProcessorFactory | None = None,
) -> FastAPI:
    """Build an application without connecting to the DB, target, or model provider."""

    configured_settings = settings or get_settings()
    configured_database = database or Database(configured_settings.database_url)
    provided_telemetry = telemetry
    build_processor = processor_factory or _default_processor_factory

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        configure_logging(configured_settings.log_level)
        runtime_telemetry = provided_telemetry or LangfuseTelemetry.from_settings(
            configured_settings
        )
        application.state.settings = configured_settings
        application.state.database = configured_database
        application.state.metrics = app_metrics
        application.state.telemetry = runtime_telemetry
        application.state.target_profile = load_target_profile(
            _project_path(configured_settings.target_profile_path)
        )
        application.state.taxonomy = load_taxonomy(
            _project_path(configured_settings.attack_taxonomy_path)
        )
        application.state.judge_rubric = load_judge_rubric(
            _project_path(configured_settings.judge_rubric_path)
        )
        application.state.seed_cases = load_seed_cases(PROJECT_ROOT / "evals" / "seed-cases")
        application.state.worker = None
        application.state.worker_task = None

        worker: CampaignWorker | None = None
        worker_task: asyncio.Task[None] | None = None
        if configured_settings.worker_enabled:
            processor = build_processor(
                configured_database,
                configured_settings,
                app_metrics,
                runtime_telemetry,
            )
            worker = CampaignWorker(
                database=configured_database,
                settings=configured_settings,
                processor=processor,
                metrics=app_metrics,
            )
            worker_task = asyncio.create_task(
                worker.run_forever(),
                name="agentforge-campaign-worker",
            )
            application.state.worker = worker
            application.state.worker_task = worker_task

        try:
            yield
        finally:
            if worker is not None and worker_task is not None:
                await _stop_worker(
                    worker,
                    worker_task,
                    timeout=max(2.0, configured_settings.worker_poll_seconds + 1.0),
                )
            runtime_telemetry.flush()
            runtime_telemetry.shutdown()
            configured_database.dispose()

    application = FastAPI(
        title="AgentForge",
        summary="Authorized synthetic-data security evaluation for the OpenEMR Clinical Co-Pilot",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def correlation_middleware(request: Request, call_next: Callable[..., Any]) -> Response:
        supplied = request.headers.get("x-correlation-id")
        current = (
            supplied
            if supplied is not None and _SAFE_CORRELATION_ID.fullmatch(supplied)
            else str(uuid4())
        )
        token = correlation_id.set(current)
        try:
            response = await call_next(request)
            response.headers["X-Correlation-ID"] = current
            return response
        finally:
            correlation_id.reset(token)

    @application.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
        body = ErrorResponse(
            code=exc.code,
            message=exc.message,
            correlation_id=correlation_id.get(),
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump(mode="json"))

    @application.get("/healthz", tags=["operations"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz", tags=["operations"], response_model=None)
    def readiness(request: Request) -> JSONResponse:
        checks: dict[str, str] = {"configuration": "ready"}
        ready = True
        try:
            request.app.state.database.ping()
            if not inspect(request.app.state.database.engine).has_table("campaigns"):
                raise RuntimeError("database schema is not migrated")
        except Exception:
            checks["database"] = "unavailable"
            ready = False
        else:
            checks["database"] = "ready"

        worker_task = request.app.state.worker_task
        if configured_settings.worker_enabled:
            if worker_task is None or worker_task.done():
                checks["worker"] = "unavailable"
                ready = False
            else:
                checks["worker"] = "ready"
        else:
            checks["worker"] = "disabled"

        return JSONResponse(
            status_code=200 if ready else 503,
            content={"status": "ready" if ready else "not_ready", "checks": checks},
        )

    @application.get("/metrics", tags=["operations"], response_model=None)
    def prometheus_metrics() -> Response:
        return Response(
            content=app_metrics.render(),
            headers={"Content-Type": app_metrics.content_type},
        )

    application.include_router(api_router)
    application.include_router(dashboard_router)
    application.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
    return application


app = create_app()


__all__ = ["app", "create_app"]
