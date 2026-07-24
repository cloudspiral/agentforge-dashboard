# Final readiness

V2 architecture verification was performed locally on 2026-07-24. Historical
production evidence was captured on 2026-07-22. `VERIFIED LOCALLY` does not mean
deployed, and historical evidence is not presented as a current V2 run.

| Area | Status | Evidence / boundary |
| --- | --- | --- |
| Neutral Orchestrator authority | `VERIFIED LOCALLY` | The Orchestrator receives all 17 subcategories in stable neutral order with raw coverage, capability, finding, partial-signal, prior-family, and remaining-limit facts. Tests prove no deterministic ranking/shortlist remains. |
| UI/API/document surfaces | `VERIFIED LOCALLY` | The gate and runners cover UI, authenticated same-origin API, direct sidecar API, staged document, and true multi-surface hybrid sequences. Secrets, CSRF, numeric patient context, and endpoint URLs remain controller-owned. |
| Fuzzing | `VERIFIED LOCALLY` | A versioned corpus plus `FuzzPlanV2` yields at most six deterministic variants. Confirmed variants may schedule at most three strictly smaller replays; only an independently confirmed smaller payload versions the regression case. |
| Judge authority | `VERIFIED LOCALLY` | Raw evidence goes to the Judge for ordinary, seed, fuzz, API, and regression attempts. New confirmed verdicts require a semantic finding key; deterministic code only validates and conservatively projects it. |
| Unified finding promotion | `VERIFIED LOCALLY` | Seed, scenario, fuzz, API, and minimization confirmations share semantic deduplication. Rediscovery appends evidence rather than creating a duplicate report. |
| Finding lifecycle and reports | `VERIFIED LOCALLY` | CSRF-protected dashboard actions implement pending review, open, in progress, false positive, and resolved with actor/reason/evidence audit. PostgreSQL Markdown is canonical and lifecycle/regression updates create deterministic versions. |
| Regression harness V2 | `VERIFIED LOCALLY` | Exact cases retain original confirmation and evidence. Separate replay rows enforce two consistent blocked changed-version replays for secure pass, same-version uncertainty, version/correlation errors, reopening, and matched-cohort transition flags. |
| Shared observability | `VERIFIED LOCALLY` | One typed PostgreSQL service feeds dashboard/API and Orchestrator facts. It exposes taxonomy/surface coverage, separated lanes, lifecycle, matched resilience, cost dimensions/projections, and ordered agent/controller/runner events. |
| Cost controls and analysis | `VERIFIED LOCALLY` | A $20 global ceiling, 30-attempt/6-hour defaults, and max($3, 125% projected regression cost) discovery reserve are enforced. The reproducible analysis generator uses durable AgentRun/attempt/regression data plus versioned non-model assumptions. |
| Migration | `VERIFIED LOCALLY` | `d94e7b3a21c8 (head)` upgraded the isolated `_test` PostgreSQL database and `alembic check` reported no schema drift. |
| Automated tests | `VERIFIED LOCALLY` | 199 unit/contract/offline tests passed; 24 isolated PostgreSQL integration tests passed; the only skipped integration test is the explicitly opt-in live browser smoke. Ruff format/lint, contracts, the nine-seed/four-control catalog, current result hashes, fake load, Compose, and Alembic drift checks also passed. |
| Container | `VERIFIED LOCALLY` | Production Docker image `agentforge:final-submission-gate` built successfully on 2026-07-24 with packaged Chromium (manifest list `sha256:036abf3e87d3e33677b4554381d6436de63538a325f2afa89ae0f8e5a2e1ddbe`). The recreated local service passed `/readyz` and rendered the seed, taxonomy, surface, cost, timeline, campaign, and regression views without browser console errors. |
| Current nine-seed deployed run | `NOT YET RUN` | Architecture-first sequencing: all current YAML hashes are run only after this V2 build is deployed. |
| V2 live discovery and API/fuzz coverage | `NOT YET RUN` | Begins after deployment within the authorized 60 target-execution, six-hour, and $20 model-cost limits. |
| Full production regression suite | `NOT YET RUN` | Will be launched from the deployed dashboard after current Findings and cases are reconciled. |
| Three distinct confirmed reports | `UNMET PENDING LIVE RUNS` | Existing evidence contains two genuine Findings. A third is sought but will not be fabricated or duplicated. |
| Production deployment/browser demo | `NOT YET RUN` | GitLab MR, mirror SHA, Railway health/readiness, and authenticated browser evidence are still pending. |

## Validation commands

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest -q
uv run python scripts/export_contracts.py --check
uv run python scripts/export_evals.py --validate-only
uv run python scripts/check_submission_results.py
uv run python scripts/check_control_results.py
uv run alembic heads
uv run agentforge artifacts reconcile
docker compose config --quiet
docker build -t agentforge-final-multi-agent-hardening:latest .
```

PostgreSQL integration and migration tests must use a database whose name ends in
`_test`. Production browser verification uses only the explicitly authorized
synthetic Clinical Co-Pilot target and the controller-owned execution boundaries.
