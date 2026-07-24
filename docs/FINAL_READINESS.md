# Final readiness

Final architecture and production evidence were verified on 2026-07-24. Status labels
below distinguish implementation/test proof from live target evidence.

| Area | Status | Evidence / boundary |
| --- | --- | --- |
| Exact runtime linkage | `VERIFIED LIVE` | GitLab and GitHub mirror parity was verified at application runtime SHA `e552300912734ae4c491d3db0bca35de948f5b30`; Railway deployment `72f153c1-1f64-448d-8e40-4295c7daa4d5` is `SUCCESS` on that SHA. A later evidence-only Markdown/JSON merge does not change the verified runtime behavior. |
| Health and readiness | `VERIFIED LIVE` | `/healthz` returned `ok`; `/readyz` returned configuration, database, and worker `ready`; authenticated dashboard HTML rendered from production. |
| Neutral Orchestrator authority | `VERIFIED TESTED + LIVE DATA` | All 17 subcategories are supplied in stable neutral order with raw coverage, capability, finding, prior-family, partial-signal, and remaining-limit facts. The live campaign page says `Agent-selected scope` and displays persisted objectives/rationales; queue priority is explicitly labeled an operator scheduling input, not taxonomy ranking. |
| UI/API/document surfaces | `VERIFIED TESTED + LIVE EXECUTIONS` | The catalog supports UI, same-origin API, direct sidecar API, staged document, and hybrid. Live durable attempts include 26 UI, 2 same-origin API, 2 direct sidecar API, and 4 staged-document executions. Hybrid remains supported but has no final-run execution. |
| Fuzzing | `VERIFIED TESTED + LIVE EXECUTIONS` | Versioned corpus and `FuzzPlanV2` generate at most six deterministic variants. Two direct-sidecar fuzz variants executed and are separately visible as `inconclusive`. |
| Current seed suite | `VERIFIED LIVE` | All nine exact current YAML hashes show terminal results in the authenticated production dashboard: 6 blocked and 3 confirmed, with no error or missing verdict. |
| Taxonomy coverage | `VERIFIED LIVE` | Every one of the 17 subcategories has at least one target execution. Coverage retains error, partial, inconclusive, provenance, surface, technique, version, seed, and regression counts. |
| Judge authority | `VERIFIED TESTED + LIVE` | Raw evidence goes to the same Judge verdict contract for seed, discovery, fuzz, API, and regression work. Deterministic code validates and conservatively projects only valid semantic verdicts. |
| Unified Finding promotion | `VERIFIED LIVE` | Seed and agent rediscoveries share semantic deduplication. Production has exactly three distinct Findings; rediscovery appended observations instead of creating duplicate reports. |
| Finding lifecycle and reports | `VERIFIED TESTED + LIVE` | Three Findings are `pending_review`, each with canonical report version 5 and an active regression case. Confirm, begin work, dismiss-with-reason, secure resolve, labeled manual override, audit, and reopen behavior are tested and rendered. |
| Regression harness V2 | `VERIFIED TESTED; LIVE VERDICTS BLOCKED` | Four three-case suites completed and stored 12 target replay records. All Judge calls were provider-rate-limited, so aggregates are 12 honest `error` results—not false passes. Two-replay secure-pass, version validation, reopening, and cross-category transitions pass protected tests. |
| Matched-cohort resilience | `VERIFIED CONSERVATIVE` | Placeholder and same-version runs are excluded. No target version changed during final testing, so production correctly shows no transition rather than a fabricated trend. The final run page labels its retained `local-unknown` history as excluded rather than presenting it as a meaningful baseline. |
| Shared observability | `VERIFIED LIVE` | One typed PostgreSQL service feeds dashboard/API and Orchestrator context: 17 coverage rows, four outcome lanes, capabilities, lifecycle, resilience, cost dimensions, projections, and a 127-event ordered timeline. |
| Cost controls and analysis | `VERIFIED LIVE + GENERATED` | Production AgentRun cost is `$3.820690`, below the `$20` ceiling. The reproducible report merges 83 unique calls at `$3.872759`, preserves `UNMEASURED` channels, and projects complete workload mixes at 100/1K/10K/100K. |
| Database migration | `VERIFIED CI + LIVE` | `d94e7b3a21c8 (head)` upgraded PostgreSQL; protected CI reported no Alembic drift. |
| Protected automated gate | `VERIFIED CI` | Pipeline `16807`, job `57342`: Ruff, 13 contract schemas, 9-seed/4-control catalog, submission/control evidence, full PostgreSQL migrations, Alembic check, and 234 tests passed; only explicit `RUN_LIVE_E2E` browser smoke was skipped. |
| Dashboard demo path | `VERIFIED LIVE` | Authenticated overview, campaigns, Findings, Finding detail, regression list, and terminal regression detail render against production durable data with no console errors. Chrome and the in-app browser block the Railway hostname locally with `ERR_BLOCKED_BY_CLIENT`, so visual verification used a temporary localhost-only GET/HEAD bridge; direct authenticated HTTP checks also passed. |
| OpenEMR webhook | `DEFERRED` | Deployment-trigger integration was intentionally deferred; manual full-suite launch is live. |

## Production evidence snapshot

| Metric | Value |
| --- | ---: |
| Current target build | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Total durable attempts | 45 |
| Target-executed attempts represented by cost snapshot | 42 |
| Current seed attempts / executions | 9 / 9 |
| Discovery attempts / executions | 22 / 19 |
| Fuzz attempts / executions | 2 / 2 |
| Regression attempts / executions | 12 / 12 |
| Findings / current reports / active regression cases | 3 / 3 / 3 |
| Production AgentForge model calls | 80 |
| Production configured model cost | `$3.820690` |
| Ordered timeline events | 127 |
| Live matched-version resilience transitions | 0 |

## Verification commands

```bash
uv run ruff format --check .
uv run ruff check .
uv run python scripts/export_contracts.py --check
uv run python scripts/export_evals.py --validate-only
uv run python scripts/check_submission_results.py
uv run python scripts/check_control_results.py
uv run alembic heads
uv run alembic upgrade head
uv run alembic check
uv run pytest -q
docker compose config --quiet
docker build -t agentforge-final-multi-agent-hardening:latest .
uv run python scripts/generate_cost_analysis.py --help
```

PostgreSQL integration and migration tests must use a database whose name ends in
`_test`. Live work remains restricted to the authorized synthetic Clinical Co-Pilot
hosts and controller-owned credential aliases. The final release neither modifies
OpenEMR nor treats provider/runner failure as a security verdict.
