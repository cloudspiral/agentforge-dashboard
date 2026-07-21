from __future__ import annotations

from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

_LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120)
_QUEUE_AGE_BUCKETS = (1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600)


class AgentForgeMetrics:
    """Prometheus instruments with deliberately low-cardinality labels.

    Campaign, attempt, trace, patient, and worker-run identifiers belong in logs
    and PostgreSQL, never in metric labels.
    """

    def __init__(self, registry: CollectorRegistry = REGISTRY) -> None:
        self.registry = registry
        self._persistence_database: Any | None = None
        self._persistence_stale_after_seconds = 120

        self.queue_depth = Gauge(
            "agentforge_queue_depth",
            "Campaigns waiting to be claimed by a worker.",
            ("queue",),
            registry=registry,
        )
        self.queue_oldest_age_seconds = Gauge(
            "agentforge_queue_oldest_age_seconds",
            "Age in seconds of the oldest queued campaign.",
            ("queue",),
            registry=registry,
        )
        self.queue_wait_seconds = Histogram(
            "agentforge_queue_wait_seconds",
            "Time a campaign waits before a worker claims it.",
            ("queue",),
            buckets=_QUEUE_AGE_BUCKETS,
            registry=registry,
        )

        self.campaigns_current = Gauge(
            "agentforge_campaigns_current",
            "Current campaigns grouped by status and trigger type.",
            ("status", "campaign_type"),
            registry=registry,
        )
        self.campaigns_total = Counter(
            "agentforge_campaigns_total",
            "Campaign transitions grouped by terminal status and trigger type.",
            ("status", "campaign_type"),
            registry=registry,
        )
        self.attempts_total = Counter(
            "agentforge_attempts_total",
            "Attack attempts grouped by category and judge verdict.",
            ("category", "verdict"),
            registry=registry,
        )

        self.worker_active = Gauge(
            "agentforge_worker_active",
            "Whether a worker is actively processing campaigns (1 or 0).",
            ("worker",),
            registry=registry,
        )
        self.worker_heartbeat_timestamp_seconds = Gauge(
            "agentforge_worker_heartbeat_timestamp_seconds",
            "Unix timestamp of the latest successful worker heartbeat.",
            ("worker",),
            registry=registry,
        )

        self.agent_latency_seconds = Histogram(
            "agentforge_agent_latency_seconds",
            "OpenAI Agents SDK run latency by role, model, and outcome.",
            ("role", "model", "status"),
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.agent_tokens_total = Counter(
            "agentforge_agent_tokens_total",
            "Agent token usage by role, model, and token type.",
            ("role", "model", "token_type"),
            registry=registry,
        )
        self.agent_estimated_cost_usd_total = Counter(
            "agentforge_agent_estimated_cost_usd_total",
            "Estimated model cost in US dollars by role and model.",
            ("role", "model"),
            registry=registry,
        )

        self.target_latency_seconds = Histogram(
            "agentforge_target_latency_seconds",
            "Authorized target request latency by transport, operation, and status.",
            ("transport", "operation", "status"),
            buckets=_LATENCY_BUCKETS,
            registry=registry,
        )
        self.target_errors_total = Counter(
            "agentforge_target_errors_total",
            "Authorized target errors by transport and normalized error type.",
            ("transport", "error_type"),
            registry=registry,
        )

        self.regression_outcomes_total = Counter(
            "agentforge_regression_outcomes_total",
            "Regression case outcomes grouped by category and result.",
            ("category", "outcome"),
            registry=registry,
        )
        self.report_generation_failures_total = Counter(
            "agentforge_report_generation_failures_total",
            "Report generation failures by normalized error type.",
            ("error_type",),
            registry=registry,
        )

    def bind_persistence(self, database: Any, *, stale_after_seconds: int) -> None:
        self._persistence_database = database
        self._persistence_stale_after_seconds = max(stale_after_seconds, 0)

    def unbind_persistence(self, database: Any) -> None:
        if self._persistence_database is database:
            self._persistence_database = None

    def render(self) -> bytes:
        content = generate_latest(self.registry)
        if self._persistence_database is None:
            return content
        from agentforge.persistence.repositories import OperationalRepository

        with self._persistence_database.session_factory() as session:
            snapshot = OperationalRepository(session).metrics_snapshot(
                stale_after_seconds=self._persistence_stale_after_seconds
            )
        return content + render_persistence_metrics(snapshot)

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST


metrics = AgentForgeMetrics()


def render_persistence_metrics(snapshot: dict[str, Any]) -> bytes:
    """Render a fresh low-cardinality snapshot sourced from persisted application data."""

    registry = CollectorRegistry()
    campaigns = Gauge(
        "agentforge_persisted_campaigns",
        "Persisted campaigns grouped by current status and campaign type.",
        ("status", "campaign_type"),
        registry=registry,
    )
    queue_depth = Gauge(
        "agentforge_persisted_queue_depth",
        "Persisted campaigns waiting to be claimed.",
        registry=registry,
    )
    running = Gauge(
        "agentforge_persisted_running_campaigns",
        "Persisted campaigns currently running.",
        registry=registry,
    )
    oldest_age = Gauge(
        "agentforge_persisted_queue_oldest_age_seconds",
        "Age in seconds of the oldest persisted queued campaign.",
        registry=registry,
    )
    stale_running = Gauge(
        "agentforge_stale_running_campaigns",
        "Persisted running campaigns whose heartbeat is stale or missing.",
        registry=registry,
    )
    completed = Gauge(
        "agentforge_persisted_campaigns_completed_total",
        "Persisted campaigns in the completed state.",
        registry=registry,
    )
    failed = Gauge(
        "agentforge_persisted_campaigns_failed_total",
        "Persisted campaigns in the failed state.",
        registry=registry,
    )
    durations = Gauge(
        "agentforge_persisted_campaign_duration_seconds",
        "Persisted campaign duration grouped by terminal status and statistic.",
        ("status", "statistic"),
        registry=registry,
    )
    attempts = Gauge(
        "agentforge_persisted_attempts_per_campaign",
        "Persisted attempts per campaign by aggregate statistic.",
        ("statistic",),
        registry=registry,
    )
    worker_claims = Gauge(
        "agentforge_persisted_worker_claims_total",
        "Durable campaign claim events.",
        registry=registry,
    )
    worker_failures = Gauge(
        "agentforge_persisted_worker_failures_total",
        "Durable worker completions ending in failure.",
        registry=registry,
    )
    lifecycle_events = Gauge(
        "agentforge_persisted_lifecycle_events_total",
        "Durable campaign lifecycle events grouped by bounded event type.",
        ("event_type",),
        registry=registry,
    )
    regression_runs = Gauge(
        "agentforge_persisted_regression_runs",
        "Persisted regression runs grouped by status.",
        ("status",),
        registry=registry,
    )
    regression_results = Gauge(
        "agentforge_persisted_regression_results",
        "Persisted regression results grouped by outcome.",
        ("outcome",),
        registry=registry,
    )
    agent_tokens = Gauge(
        "agentforge_persisted_llm_tokens_total",
        "Stored LLM tokens grouped by bounded agent role and token type.",
        ("role", "token_type"),
        registry=registry,
    )
    agent_cost = Gauge(
        "agentforge_persisted_llm_cost_usd_total",
        "Stored LLM estimated cost grouped by bounded agent role.",
        ("role",),
        registry=registry,
    )

    for row in snapshot["campaign_counts"]:
        campaigns.labels(status=row["status"], campaign_type=row["campaign_type"]).set(row["count"])
    queue = snapshot["queue"]
    queue_depth.set(queue["depth"])
    running.set(queue["running"])
    oldest_age.set(queue["oldest_age_seconds"])
    stale_running.set(queue["stale_running"])
    completed.set(snapshot["completed"])
    failed.set(snapshot["failed"])
    for row in snapshot["durations"]:
        for statistic in ("count", "sum", "average", "maximum"):
            durations.labels(status=row["status"], statistic=statistic).set(row[statistic])
    for statistic, value in snapshot["attempts"].items():
        attempts.labels(statistic=statistic).set(value)
    worker_claims.set(snapshot["worker_claims"])
    worker_failures.set(snapshot["worker_failures"])
    for event_type, count in snapshot["event_counts"].items():
        lifecycle_events.labels(event_type=event_type).set(count)
    for status, count in snapshot["regression_runs"].items():
        regression_runs.labels(status=status).set(count)
    for outcome, count in snapshot["regression_results"].items():
        regression_results.labels(outcome=outcome).set(count)
    for row in snapshot["agent_usage"]:
        agent_tokens.labels(row["role"], "input").set(row["input_tokens"])
        agent_tokens.labels(row["role"], "output").set(row["output_tokens"])
        agent_cost.labels(role=row["role"]).set(float(row["cost_usd"]))
    return generate_latest(registry)
