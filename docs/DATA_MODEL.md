# AgentForge data model

## Authority and revision

PostgreSQL is the operational source of truth. The feature-branch schema is
represented by SQLAlchemy models and Alembic head `f43a8d7e91b2`. Empty-database
upgrade/current/check and the explicit PostgreSQL integration suite have been
exercised. The current deployment remains on the earlier `c71d9e5a4b20` schema until
this branch is reviewed and separately deployed.

```mermaid
erDiagram
    CAMPAIGNS ||--o{ ATTACK_ATTEMPTS : contains
    CAMPAIGNS ||--o{ AGENT_RUNS : records
    CAMPAIGNS o|--o{ REGRESSION_RUNS : triggers
    ATTACK_ATTEMPTS ||--o| JUDGE_VERDICTS : receives
    ATTACK_ATTEMPTS ||--o{ ATTACK_ATTEMPTS : mutates
    ATTACK_ATTEMPTS ||--o{ FINDINGS : supports
    ATTACK_ATTEMPTS o|--o{ AGENT_RUNS : traces
    FINDINGS ||--o{ VULNERABILITY_REPORTS : versions
    FINDINGS ||--o{ REGRESSION_CASES : creates
    FINDINGS o|--o{ AGENT_RUNS : documents
    REGRESSION_RUNS ||--o{ REGRESSION_RESULTS : contains
    REGRESSION_CASES ||--o{ REGRESSION_RESULTS : replayed_as
```

## Tables

| Table | Purpose and important fields | Integrity/lifecycle |
| --- | --- | --- |
| `target_versions` | Environment, version label, Git SHA, deployment ID, URL alias, profile hash, metadata | Unique version label; records exact evaluated runtime, not assumed checkout HEAD |
| `campaigns` | Type/trigger/status, target alias/version, category scope, budgets, attempts, priority, heartbeat, cancellation, sanitized error | Unique idempotency key; indexed queue/status/category/version; parent for attempts and agent runs |
| `attack_attempts` | Family/lineage/parent/mutation generation, trusted proposal and objective provenance, sanitized fallback reason, sequence hash, objective, proposed/executed sequences, prompt/taxonomy/profile versions, evidence hash, usage/cost/latency/trace | Cascades with campaign; self-parent becomes null; immutable proposal provenance and evidence identity should be treated append-only after creation/completion |
| `judge_verdicts` | Verdict, severity, exploitability, confidence, evidence references, violated invariants, rubric version/hash, deterministic override | Exactly zero or one per attempt; cascades with attempt |
| `findings` | Stable vulnerability ID/fingerprint, source attempt, category/severity/status, clinical impact, expected/observed behavior, first/last target versions | Fingerprint and vulnerability ID unique; source attempt restricted from deletion; current regression pointer optional |
| `vulnerability_reports` | Finding/version, structured report, Markdown, export path, draft status, validation summary, prompt/schema versions | Unique finding/version; cascades with finding; export path is metadata, not evidence authority |
| `regression_cases` | Finding/version, setup, exact ordered sequence, invariants, deterministic checks, rubric subset, target requirements, source evidence hash | Unique finding/version; versioned rather than edited in place |
| `regression_runs` | Target version, optional campaign, trigger/status, outcome counters, cost and timing | Campaign deletion sets null; results cascade |
| `regression_results` | Run/case/version, four-state outcome, deterministic/Judge results, evidence references, cost/latency/trace | Unique run/case/version; case deletion restricted |
| `agent_runs` | Role, prompt version, model, status, tokens, cost, latency, trace ID, typed error, campaign/attempt/finding links | Links set null on parent removal; supports audit and cost measurement |

## State rules

Campaign states should be changed only by repository/controller transitions. Queue
claiming and heartbeat recovery are transactional. A cancelled or stale run becomes
an explicit terminal/interrupted record, not silently retried. Attempts retain
controller-assigned proposal/objective provenance, lineage, proposal, actual
execution, versions, and frozen evidence separately. Historical attempts are
explicitly `legacy_unknown`; provenance is never inferred retrospectively. Findings
are deduplicated by fingerprint and progress through human-controlled status. Reports
and regression cases are new versions, not destructive updates.

Regression outcomes are `secure_pass`, `vulnerability_reproduced`, `inconclusive`, or `error`. A secure pass requires affirmative evidence for every saved invariant; a transport failure or missing Judge result for a Judge-required case cannot pass.

## JSON/JSONB fields

Flexible contracts are stored as JSON with a PostgreSQL JSONB variant. This supports versioned typed payloads but shifts some integrity to Pydantic and application code. Every stored contract should carry `schema_version`, source/prompt/profile/rubric versions where relevant, and hashes for evidence or configuration. Migrations must accompany incompatible shape changes; free-form secrets or raw headers must never be stored.

## Sensitive data and retention

The system is synthetic-only but still handles credentials, session cookies, CSRF values, prompts, target responses, and potentially sensitive implementation details. Credentials and session artifacts belong only in process memory/secret stores and must be redacted before database, logs, Langfuse, screenshots, or reports. Evidence should be bounded to required canaries, target-visible facts, correlations, and hashes.

No retention schedule or automated purge job is implemented. Before production, define retention by record class, legal/security hold, artifact deletion, Langfuse retention, backup encryption, restoration tests, and auditable deletion. PostgreSQL backups and exported Markdown require the same access classification as findings.

## Index and scale notes

Existing indexes cover queue/status time, target version, category/subcategory, evidence/trace IDs, severity/status, and regression run/case lookup. At higher volume, evaluate time partitioning for attempts, agent runs, and regression results; partial indexes for queued/active campaigns; object storage for large artifacts; and separate analytics replicas. Do not place raw screenshots or PDFs directly in JSONB.

## Known gaps

- No schema-level enum/check constraints enforce status vocabularies.
- No row-level access control, tenant boundary, retention job, or encryption policy is implemented.
- Multi-worker kill/recovery and backup/restore exercises remain outstanding.
- The process-local fixed-case dashboard evaluation path persists a valid lifecycle
  but intentionally bypasses controller Finding/Documentation Agent creation. The
  new full-campaign launcher uses the durable queue and normal controller instead.
