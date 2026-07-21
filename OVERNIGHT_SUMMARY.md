# AgentForge overnight implementation summary

## Executive status

AgentForge now has a substantial, testable safety-first foundation: strict v1 contracts and exported schemas, four bounded OpenAI Agents SDK role adapters, versioned prompts/configuration, deterministic budgets/stopping/execution gate, status and ephemeral-browser runners, evidence/Judge reconciliation, regression semantics, PostgreSQL models/migration/repositories, FastAPI/dashboard/CLI/worker shells, Langfuse and Prometheus adapters, report rendering, offline evaluation/load scripts, Docker/Compose/Railway configuration, GitLab CI, and the required security/architecture/evidence documentation.

It is **not an end-to-end working campaign system and is not ready for public deployment**. The concrete `agentforge.orchestration.controller` referenced by the default worker-enabled ASGI lifespan and standalone worker does not exist. The gate emits `ValidatedAttackV1`, but runners accept `ProposedAttackV1`, so gate authorization is not enforced by a type-closed execution boundary. Read APIs and dashboard routes are unauthenticated. No W3 PostgreSQL-backed service, model call, Langfuse trace, target execution, full regression, or Railway deployment was proven.

## What works locally

- Dependency resolution from the frozen lock succeeded with a writable temporary uv cache.
- `agentforge` CLI imports and renders its command tree.
- `agentforge.main:app` imports and reports title `AgentForge`.
- FastAPI health, readiness, metrics, dashboard, static assets, read API, mutation-auth rejection, worker lifecycle, CLI service calls, offline scripts, and deployment-hook fail-closed behavior have unit coverage.
- Seven exported v1 JSON schemas match their Python contracts.
- Six synthetic seed definitions cross-validate against the taxonomy and Judge rubric.
- Docker Compose configuration parses successfully.
- Alembic reports one head: `1b98633917fc`.
- The offline load script validates/evaluates/serializes deterministic fake evidence without model, database, or target I/O.

Useful commands:

```bash
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run agentforge --help
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run pytest
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/export_contracts.py --check
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/export_evals.py --validate-only
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/load_test.py --operations 100 --max-seconds 30
docker compose config --quiet
```

Configured local URLs, once a service is actually started, are `http://127.0.0.1:8080/`, `/healthz`, `/readyz`, `/metrics`, and `/api/v1`. No running W3 URL was verified during this packet.

## Exact validation evidence

The local validation environment was macOS with Python 3.13.5 and pytest 9.1.1; deployment images target Python 3.12, so container execution remains a separate required check.

| Check | Result |
| --- | --- |
| `uv sync --frozen --all-extras --dev` | Initial default-cache attempt failed under filesystem sandbox; repeated with `UV_CACHE_DIR=/private/tmp/agentforge-uv-cache` and succeeded (`Checked 87 packages`) |
| `uv run pytest` | **98 passed in 2.47s**; one Starlette TestClient deprecation warning |
| `uv run pytest tests/contract -q` | **13 passed in 0.08s** |
| Contract export drift | **Passed**, 7 current schema files |
| Synthetic eval validation | **Passed**, 6 seeds; catalog hash `86d5abb87f466a8cacf487df758fc46f2353955765694477150936292b38437f` |
| Offline deterministic load | **Passed**, 100/100; 0.008074 s; p50 0.073354 ms; p95 0.110481 ms; max 0.233542 ms; 48,824 peak allocated bytes; zero external calls/writes/cost |
| `docker compose config --quiet` | **Passed** |
| `uv run alembic heads` | **Passed**, `1b98633917fc (head)` |
| CLI help | **Passed** |
| ASGI import | **Passed** |
| `uv run ruff format --check .` | **Failed**: `src/agentforge/__init__.py`, `runners/playwright_runner.py`, and `tests/unit/test_app_cli.py` would be reformatted |
| `uv run ruff check .` | **Failed**: one `S701` at `reports/renderer.py` for Jinja `autoescape=False` |

The offline load number is only an in-process Python microbenchmark. It excludes API, queue, worker, controller, PostgreSQL, browser, target, model, and network performance.

## Database, CI, and deployment

- Database schema revision: initial/head `1b98633917fc`.
- A PostgreSQL service migration was **not run** in this validation; only migration-head discovery and SQLite-backed application tests ran.
- `.gitlab-ci.yml` defines quality, test, PostgreSQL migration, and container-build jobs, but no live GitLab pipeline result or branch-gate configuration was inspected.
- Dockerfile, `compose.yaml`, and `railway.toml` are present; Compose config parsed. No image build, container startup, readiness check, or W3 Railway deployment was performed.
- Default Docker/Railway startup would reach the missing controller when the worker starts, so configuration presence is not deployment readiness.

## Target evidence and changes

No W1 target file, migration, hook, database row, or deployment was changed for this project. `docs/TARGET_CHANGES.md` records the zero-change decision.

The current target-integration document contains a read-only 2026-07-21 baseline: W1 checkout and deployed build `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d`, older local sidecar runtime `85a25ac14fa20a3d48630f90888e5c089dbe3f60`, and one normal local synthetic Patient A blood-pressure UI response with citation/evidence. That baseline was not refreshed by the W3 validation above and is not a W3 campaign trace.

## Cost status

Validation made zero live model calls and the offline benchmark recorded $0. No measured W3 campaign token/spend dataset exists. `AI_COST_ANALYSIS.md` provides an explicit planning baseline of $0.03522 per evaluated attempt and projections of $3.52 / $35.22 / $352.20 / $3,522.00 at 100 / 1K / 10K / 100K attempts. Those values are assumptions using the checked-in 2026-07-21 price catalog, not actual billing.

## Release blockers

1. Implement the concrete campaign controller/processor and transactionally persist the complete role/gate/runner/evaluation/report lifecycle.
2. Make runners consume only the exact frozen gate-authorized envelope; prove raw proposals cannot execute.
3. Authenticate and authorize every non-health API/dashboard/metrics surface before any public deployment.
4. Resolve format/lint failures and add PostgreSQL-backed, multi-worker, fake end-to-end, live synthetic, and deployment integration evidence.
5. Complete SBOM/SAST/SCA/secrets/container/license scans, retention/backup/restore controls, capacity test, incident exercise, and residual-risk approval.

## Next five actions

1. Build `orchestration/controller.py` around existing contracts and add one deterministic fake full-chain integration test, including cancellation, cost reservation/reconciliation, cleanup failure, and recovery.
2. Replace the runner's `ProposedAttackV1` input with a minimal immutable authorized execution plan emitted by the gate; add bypass and profile-drift tests.
3. Add principal-based protection for dashboard/read/metrics routes and negative deployed-access tests; keep only health/readiness public.
4. Fix the two quality gates, run the real PostgreSQL migration and Compose app with worker disabled, then exercise a fake queued campaign with saved audit evidence.
5. After owner review, perform one serial, bounded, local-only synthetic W1 E2E, capture the first honest cross-agent trace, then evaluate Railway deployment and CI enforcement.

## Git state

The workspace is a Git repository on branch `main`, but it has no commits. Every project file is currently untracked. This documentation work did not stage or commit because multiple workstreams were still changing the shared tree; the first commit should be made only after the final combined review, using a comprehensive message that enumerates architecture, agents, controls, integrations, tests, docs, and known gaps.

## Exact morning demo sequence

The full campaign cannot be honestly demoed until the controller exists. The following single sequence starts the currently available **scaffold demo only**: it creates/migrates local PostgreSQL, queues deterministic seed definitions without running them, and serves the dashboard/API with the missing worker explicitly disabled. It does not call OpenAI or the W1 target.

```bash
docker compose up -d postgres && env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache DATABASE_URL=postgresql+psycopg://agentforge:agentforge@127.0.0.1:5433/agentforge uv run alembic upgrade head && env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache DATABASE_URL=postgresql+psycopg://agentforge:agentforge@127.0.0.1:5433/agentforge WORKER_ENABLED=false uv run agentforge eval run-seeds --surface api && env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache DATABASE_URL=postgresql+psycopg://agentforge:agentforge@127.0.0.1:5433/agentforge WORKER_ENABLED=false uv run uvicorn agentforge.main:app --host 127.0.0.1 --port 8080
```
