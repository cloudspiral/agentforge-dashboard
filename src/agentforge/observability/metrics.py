from __future__ import annotations

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

    def render(self) -> bytes:
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        return CONTENT_TYPE_LATEST


metrics = AgentForgeMetrics()
