# Final readiness

Production evidence was captured 2026-07-22. Simplified-pipeline branch verification
was performed locally on 2026-07-23. `VERIFIED LOCALLY` does not mean deployed.

| Area | Status | Evidence / boundary |
| --- | --- | --- |
| Simplified controller | `VERIFIED LOCALLY` | Unit/contract tests and isolated PostgreSQL integration cover agent-only discovery, retries, rejection, runner/Judge failure, all verdicts, mutation parent rules, immediate Finding/report/regression, and continued discovery |
| No discovery fallbacks | `VERIFIED LOCALLY` | Invalid Orchestrator or Attack Generator output ends visibly after bounded same-agent retries; no YAML/objective/sequence/Judge fallback exists |
| Judge-only security outcome | `VERIFIED LOCALLY` | Raw runner evidence is passed directly; no deterministic assertion, evaluator, reconciliation, upgrade, or downgrade is in discovery |
| Attempt model | `VERIFIED LOCALLY` | Lifecycle state is `pending/running/completed/failed/cancelled`; structured operational failure is separate from Judge verdict |
| Single-attempt finding | `VERIFIED LOCALLY` | One confirmed attempt creates exactly one new Finding, Documentation Agent report, and regression case; identical confirmed attempts create separate Findings |
| Mutation model | `VERIFIED LOCALLY` | Only a `partial_signal` parent is eligible; only parent ID is stored and generation is derived |
| Migration | `VERIFIED LOCALLY` | `a812e4c97f30 (head)` backfills lifecycle states and removes retired persistence fields against an isolated `_test` PostgreSQL database |
| Dashboard launcher | `VERIFIED LOCALLY` | CSRF, idempotency, taxonomy validation, inline errors, deployed confirmation, redirects, and bearer-token absence are tested |
| Fixed YAML harness | `VERIFIED LOCALLY` | Explicit-only; deterministic assertions stay outside Judge input and cannot create discovery Findings or change verdicts |
| Historical deployed evidence | `VERIFIED` | Four current sanitized exports across three categories remain bound to their exact case bytes and target build |
| Confirmed deployed vulnerability | `VERIFIED` | `AF-TM-001`: irrelevant selected-patient `get_vitals` invocation; medium severity/high exploitability |
| Documentation Agent live proof | `VERIFIED LOCALLY AGAINST DEPLOYED TARGET` | Prompt-injection attempt `40004cce-…` produced Finding `AF-5860F03C4E00`, Documentation Agent report `ed0d115e-…`, and regression case `969e3b3a-…` immediately; discovery continued |
| Live simplified-loop coverage | `VERIFIED` | 24 executed attempts: 16 blocked, 5 inconclusive, 2 partial signal, 1 confirmed; state-corruption demonstrated two generations of agent-generated mutation and identity testing demonstrated Orchestrator stop |
| Three confirmed exploit reports | `UNMET` | Two confirmed reports: historical AF-TM-001 and new Documentation Agent AF-5860F03C4E00; A06 records are exposure/triage only |
| OWASP A06 | `EXPOSURE, NOT EXPLOITABILITY` | Affected installed Composer versions were verified; the Co-Pilot bridge uses native cURL and advisory prerequisites were not exercised |
| OWASP A09 | `PARTIAL` | Correlation mechanism exists in source, but attributable runtime security-log evidence was unavailable |
| Feature branch deployment | `NO` | Branch is intentionally not merged or deployed; Clinical Co-Pilot and infrastructure are untouched |
| Docker build | `VERIFIED LOCALLY` | Packaged Python 3.12/Playwright Chromium image builds and executes deployed-target campaigns; application-source build ID `sha256:fc59cdf3e63976284ea661d98cbadd8063fdff087ac0fa449c0a635c34b3b678` (the only later tree change was this evidence annotation) |
| Browser dashboard smoke | `VERIFIED LOCALLY` | Isolated service returned ready, challenged unauthenticated access, rendered launcher, activated taxonomy subcategories, showed only current advanced limits/deployed confirmation, exposed no bearer field, and emitted no console errors |

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
docker compose config --quiet
docker build -t agentforge-final-multi-agent-hardening:latest .
```

PostgreSQL integration and migration tests must use a database whose name ends in
`_test`. Browser smoke should use the feature-branch service and must not submit an
attack or modify the Clinical Co-Pilot merely to verify dashboard rendering.
