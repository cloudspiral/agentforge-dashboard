"""Thin Typer CLI over AgentForge application services and repositories."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from alembic import command
from alembic.config import Config
from sqlalchemy.exc import SQLAlchemyError

from agentforge.api.schemas import CampaignCreateRequest, RegressionRunCreateRequest
from agentforge.api.services import ApplicationService
from agentforge.evaluation import TaxonomyV1, load_seed_cases, load_taxonomy
from agentforge.persistence import Database
from agentforge.persistence.models import Campaign, RegressionRun
from agentforge.persistence.repositories import CampaignRepository
from agentforge.runners.playwright_runner import UISmokeResult, run_ui_smoke
from agentforge.settings import Settings, get_settings
from agentforge.target import (
    LoadedTargetProfile,
    TargetProbeResult,
    load_target_profile,
    probe_target,
)
from agentforge.worker import serve_worker

PROJECT_ROOT = Path(__file__).resolve().parents[3]
TERMINAL_CAMPAIGN_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})


class SeedSurface(StrEnum):
    API = "api"
    UI = "ui"


class TargetAlias(StrEnum):
    LOCAL = "local"
    DEPLOYED = "deployed"


@dataclass(frozen=True, slots=True)
class CliRuntime:
    settings: Settings
    database: Database
    target_profile: LoadedTargetProfile
    taxonomy: TaxonomyV1


app = typer.Typer(
    name="agentforge",
    help="Operate bounded AgentForge campaigns against allowlisted synthetic targets.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
db_app = typer.Typer(help="Database lifecycle commands.", no_args_is_help=True)
campaign_app = typer.Typer(help="Create and inspect bounded campaigns.", no_args_is_help=True)
regression_app = typer.Typer(help="Trigger saved regression campaigns.", no_args_is_help=True)
eval_app = typer.Typer(help="Queue versioned defensive seed evaluations.", no_args_is_help=True)
reports_app = typer.Typer(help="Export controller-approved finding reports.", no_args_is_help=True)
contracts_app = typer.Typer(help="Export versioned public JSON schemas.", no_args_is_help=True)
worker_app = typer.Typer(help="Run the durable campaign queue worker.", no_args_is_help=True)
target_app = typer.Typer(help="Inspect approved target connectivity.", no_args_is_help=True)

app.add_typer(db_app, name="db")
app.add_typer(campaign_app, name="campaign")
app.add_typer(regression_app, name="regression")
app.add_typer(eval_app, name="eval")
app.add_typer(reports_app, name="reports")
app.add_typer(contracts_app, name="contracts")
app.add_typer(worker_app, name="worker")
app.add_typer(target_app, name="target")


def _project_path(path: Path | str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _emit(value: Any) -> None:
    typer.echo(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str))


def _abort(message: str) -> None:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=1)


def _target_probe_message(result: TargetProbeResult) -> str:
    location = result.sanitized_base_url or "configured host unavailable"
    if not result.reachable:
        return (
            f"Target {result.target_alias} is unavailable at {location}: "
            f"{result.error_code} ({result.error_message})."
        )
    details = [f"HTTP {result.http_status}"]
    if result.target_version:
        details.append(f"version {result.target_version}")
    details.append(f"{result.latency_ms:.1f} ms")
    return f"Target {result.target_alias} is reachable at {location} ({', '.join(details)})."


def _target_ui_smoke_message(result: UISmokeResult) -> str:
    if result.failed_step is not None:
        return (
            f"Local UI smoke failed at {result.failed_step.value}: "
            f"{result.error_code} ({result.error_message})."
        )
    return (
        f"Local UI smoke completed for {result.target_alias}: login succeeded, "
        f"synthetic patient selected, and Clinical Co-Pilot is ready "
        f"({result.total_latency_ms:.1f} ms)."
    )


@contextmanager
def _runtime() -> Iterator[CliRuntime]:
    settings = get_settings()
    database = Database(settings.database_url)
    try:
        yield CliRuntime(
            settings=settings,
            database=database,
            target_profile=load_target_profile(_project_path(settings.target_profile_path)),
            taxonomy=load_taxonomy(_project_path(settings.attack_taxonomy_path)),
        )
    except typer.Exit:
        raise
    except SQLAlchemyError:
        _abort("database operation failed")
    except LookupError:
        _abort("requested record was not found")
    except (OSError, ValueError) as exc:
        _abort(str(exc))
    finally:
        database.dispose()


def _campaign_payload(campaign: Campaign, *, include_attempts: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(campaign.id),
        "campaign_type": campaign.campaign_type,
        "trigger_type": campaign.trigger_type,
        "status": campaign.status,
        "target_alias": campaign.target_alias,
        "target_version": campaign.target_version,
        "category": campaign.category_scope,
        "subcategory": campaign.subcategory_scope,
        "max_cost_usd": str(campaign.max_cost_usd),
        "max_attempts": campaign.max_attempts,
        "max_duration_seconds": campaign.max_duration_seconds,
        "actual_cost_usd": str(campaign.actual_cost_usd),
        "actual_attempts": campaign.actual_attempts,
        "cancellation_requested": campaign.cancellation_requested,
        "created_at": campaign.created_at.isoformat(),
        "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
    }
    if include_attempts:
        payload["attempts"] = [
            {
                "id": str(attempt.id),
                "status": attempt.status,
                "category": attempt.category,
                "subcategory": attempt.subcategory,
                "evidence_hash": attempt.evidence_hash,
            }
            for attempt in sorted(campaign.attempts, key=lambda item: item.created_at)
        ]
        payload["events"] = [
            {
                "id": str(event.id),
                "event_type": event.event_type,
                "from_status": event.from_status,
                "to_status": event.to_status,
                "worker_name": event.worker_name,
                "details": event.details_json,
                "created_at": event.created_at.isoformat(),
            }
            for event in campaign.events
        ]
    return payload


def _regression_payload(run: RegressionRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "campaign_id": str(run.campaign_id) if run.campaign_id else None,
        "target_version": run.target_version,
        "status": run.status,
        "total_cases": run.total_cases,
        "estimated_cost_usd": str(run.estimated_cost_usd),
        "created_at": run.created_at.isoformat(),
    }


def _contract_exporter() -> Any:
    """Load the repository's canonical exporter independently of the current cwd."""

    script_path = PROJECT_ROOT / "scripts" / "export_contracts.py"
    specification = importlib.util.spec_from_file_location(
        "agentforge_checked_in_contract_exporter",
        script_path,
    )
    if specification is None or specification.loader is None:
        raise OSError("contract exporter could not be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module.export_schemas


@target_app.command("probe")
def target_probe(
    target: Annotated[
        str,
        typer.Option("--target", help="Alias from the checked-in target profile."),
    ] = "local",
    timeout_seconds: Annotated[
        float | None,
        typer.Option(
            "--timeout-seconds",
            min=0.1,
            max=30.0,
            help="Override the short target-probe timeout.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the typed result as compact JSON."),
    ] = False,
) -> None:
    """Make one credential-free read-only request to the approved health endpoint."""

    settings = get_settings()
    try:
        profile = load_target_profile(_project_path(settings.target_profile_path))
    except (OSError, ValueError):
        _abort("target profile could not be loaded")
    result = asyncio.run(
        probe_target(
            loaded_profile=profile,
            settings=settings,
            target_alias=target,
            timeout_seconds=timeout_seconds or settings.target_probe_timeout_seconds,
        )
    )
    if json_output:
        _emit(result.model_dump(mode="json"))
    else:
        typer.echo(_target_probe_message(result), err=not result.reachable)
    if not result.reachable:
        raise typer.Exit(code=1)


@target_app.command("ui-smoke")
def target_ui_smoke(
    target: Annotated[
        str,
        typer.Option("--target", help="Local alias from the checked-in target profile."),
    ] = "local",
    headed: Annotated[
        bool,
        typer.Option("--headed", help="Show Chromium for local selector debugging."),
    ] = False,
    timeout_seconds: Annotated[
        float | None,
        typer.Option(
            "--timeout-seconds",
            min=0.1,
            max=120.0,
            help="Override the bounded browser navigation timeout.",
        ),
    ] = None,
    failure_screenshot: Annotated[
        bool,
        typer.Option(
            "--failure-screenshot",
            help="Capture one sanitized artifact only if the smoke flow fails.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the typed result as compact JSON."),
    ] = False,
) -> None:
    """Verify local authenticated UI readiness without chat or upload actions."""

    settings = get_settings()
    try:
        profile = load_target_profile(_project_path(settings.target_profile_path))
    except (OSError, ValueError):
        _abort("target profile could not be loaded")
    result = asyncio.run(
        run_ui_smoke(
            loaded_profile=profile,
            settings=settings,
            target_alias=target,
            repository_root=PROJECT_ROOT,
            artifacts_dir=_project_path(settings.artifacts_dir),
            timeout_seconds=(timeout_seconds or settings.target_ui_smoke_timeout_seconds),
            headless=False if headed else settings.target_ui_smoke_headless,
            screenshot_on_failure=(
                failure_screenshot or settings.target_ui_smoke_screenshot_on_failure
            ),
        )
    )
    if json_output:
        _emit(result.model_dump(mode="json"))
    else:
        typer.echo(_target_ui_smoke_message(result), err=result.failed_step is not None)
    if result.failed_step is not None:
        raise typer.Exit(code=1)


@db_app.command("upgrade")
def db_upgrade() -> None:
    """Apply all checked-in Alembic migrations to the configured database."""

    configuration = Config(str(PROJECT_ROOT / "alembic.ini"))
    configuration.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    try:
        command.upgrade(configuration, "head")
    except Exception:
        _abort("database migration failed")
    typer.echo("Database is at the latest migration.")


@campaign_app.command("create")
def campaign_create(
    category: Annotated[str | None, typer.Option(help="Checked-in taxonomy category.")] = None,
    subcategory: Annotated[
        str | None,
        typer.Option(help="Checked-in taxonomy subcategory."),
    ] = None,
    max_attempts: Annotated[
        int | None,
        typer.Option(min=1, max=100, help="Maximum bounded attack attempts."),
    ] = None,
    max_cost_usd: Annotated[
        float | None,
        typer.Option(min=0.000001, help="Maximum model cost in USD."),
    ] = None,
    max_duration_seconds: Annotated[
        int | None,
        typer.Option(min=30, max=86_400, help="Campaign wall-clock limit."),
    ] = None,
    target: Annotated[
        TargetAlias,
        typer.Option("--target", help="Allowlisted target alias."),
    ] = TargetAlias.LOCAL,
    idempotency_key: Annotated[
        str | None,
        typer.Option(help="Safe key preventing duplicate campaign creation."),
    ] = None,
) -> None:
    """Queue one bounded discovery campaign."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        request = CampaignCreateRequest(
            campaign_type="discovery",
            target_alias=target.value,
            category=category,
            subcategory=subcategory,
            max_attempts=max_attempts,
            max_cost_usd=max_cost_usd,
            max_duration_seconds=max_duration_seconds,
            idempotency_key=idempotency_key,
        )
        campaign = ApplicationService(
            session,
            settings=runtime.settings,
            target_profile=runtime.target_profile,
            taxonomy=runtime.taxonomy,
        ).create_campaign(request, idempotency_key=idempotency_key)
        _emit(_campaign_payload(campaign))


@campaign_app.command("list")
def campaign_list(
    limit: Annotated[int, typer.Option(min=1, max=200)] = 50,
    offset: Annotated[int, typer.Option(min=0)] = 0,
) -> None:
    """List campaigns newest first."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        items, total = CampaignRepository(session).list(offset=offset, limit=limit)
        _emit(
            {
                "items": [_campaign_payload(item) for item in items],
                "limit": limit,
                "offset": offset,
                "total": total,
            }
        )


@campaign_app.command("show")
def campaign_show(campaign_id: uuid.UUID) -> None:
    """Show one campaign with persisted attempt summaries and lifecycle events."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        campaign = CampaignRepository(session).get(campaign_id, include_attempts=True)
        _emit(_campaign_payload(campaign, include_attempts=True))


@campaign_app.command("cancel")
def campaign_cancel(campaign_id: uuid.UUID) -> None:
    """Cancel queued work or request cooperative cancellation of running work."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        campaign = CampaignRepository(session).cancel(campaign_id)
        _emit(_campaign_payload(campaign))


@campaign_app.command("wait")
def campaign_wait(
    campaign_id: uuid.UUID,
    timeout_seconds: Annotated[
        float,
        typer.Option(min=0.1, max=86_400, help="Maximum time to wait."),
    ] = 300.0,
    poll_seconds: Annotated[
        float,
        typer.Option(min=0.1, max=60, help="Database polling interval."),
    ] = 1.0,
) -> None:
    """Wait until a campaign reaches a terminal state."""

    deadline = time.monotonic() + timeout_seconds
    with _runtime() as runtime, runtime.database.session_factory() as session:
        repository = CampaignRepository(session)
        while True:
            session.expire_all()
            campaign = repository.get(campaign_id)
            if campaign.status in TERMINAL_CAMPAIGN_STATUSES:
                _emit(_campaign_payload(campaign))
                return
            if time.monotonic() >= deadline:
                _abort("campaign wait timed out")
            time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))


@regression_app.command("trigger")
def regression_trigger(
    target_version: Annotated[
        str | None,
        typer.Option(help="Exact target build/version label."),
    ] = None,
    target: Annotated[
        TargetAlias,
        typer.Option("--target", help="Allowlisted target alias."),
    ] = TargetAlias.LOCAL,
    idempotency_key: Annotated[
        str | None,
        typer.Option(help="Safe key preventing a duplicate regression trigger."),
    ] = None,
) -> None:
    """Queue a bounded saved-case regression run."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        request = RegressionRunCreateRequest(
            target_alias=target.value,
            target_version=target_version,
            idempotency_key=idempotency_key,
        )
        run = ApplicationService(
            session,
            settings=runtime.settings,
            target_profile=runtime.target_profile,
            taxonomy=runtime.taxonomy,
        ).create_regression_run(request)
        _emit(_regression_payload(run))


@eval_app.command("run-seeds")
def eval_run_seeds(
    surface: Annotated[
        SeedSurface,
        typer.Option(help="Only queue approved seeds for this execution surface."),
    ],
    target: Annotated[
        TargetAlias,
        typer.Option("--target", help="Allowlisted target alias."),
    ] = TargetAlias.LOCAL,
) -> None:
    """Queue one exact category/subcategory campaign per versioned seed case."""

    seeds = [
        seed
        for seed in load_seed_cases(PROJECT_ROOT / "evals" / "seed-cases")
        if seed.surface == surface.value
    ]
    if not seeds:
        _abort(f"no checked-in seed cases use the {surface.value} surface")

    queued: list[dict[str, Any]] = []
    with _runtime() as runtime, runtime.database.session_factory() as session:
        service = ApplicationService(
            session,
            settings=runtime.settings,
            target_profile=runtime.target_profile,
            taxonomy=runtime.taxonomy,
        )
        for seed in seeds:
            idempotency_key = f"seed:{surface.value}:{seed.id}"
            campaign = service.create_campaign(
                CampaignCreateRequest(
                    campaign_type="discovery",
                    target_alias=target.value,
                    category=seed.category,
                    subcategory=seed.subcategory,
                    max_attempts=1,
                    idempotency_key=idempotency_key,
                    priority=10,
                ),
                idempotency_key=idempotency_key,
            )
            queued.append(
                {
                    "campaign_id": str(campaign.id),
                    "seed_id": seed.id,
                    "status": campaign.status,
                }
            )
    _emit({"count": len(queued), "surface": surface.value, "campaigns": queued})


@reports_app.command("export")
def reports_export(finding_id: uuid.UUID) -> None:
    """Write the latest validated report for a finding to the configured directory."""

    with _runtime() as runtime, runtime.database.session_factory() as session:
        path, version = ApplicationService(
            session,
            settings=runtime.settings,
            target_profile=runtime.target_profile,
            taxonomy=runtime.taxonomy,
        ).export_report(finding_id)
        _emit({"finding_id": str(finding_id), "path": path, "report_version": version})


@contracts_app.command("export")
def contracts_export(
    output_dir: Annotated[
        Path | None,
        typer.Option(help="Schema destination (defaults to contracts/v1)."),
    ] = None,
) -> None:
    """Regenerate deterministic JSON Schemas for public v1 contracts."""

    destination = (output_dir or PROJECT_ROOT / "contracts" / "v1").resolve()
    try:
        paths = _contract_exporter()(destination)
    except (AttributeError, OSError):
        _abort("contract schema export failed")
    _emit({"count": len(paths), "paths": [str(path) for path in paths]})


@worker_app.command("run")
def worker_run() -> None:
    """Run the durable queue worker until interrupted."""

    with suppress(KeyboardInterrupt):
        asyncio.run(serve_worker())


if __name__ == "__main__":
    app()


__all__ = ["app"]
