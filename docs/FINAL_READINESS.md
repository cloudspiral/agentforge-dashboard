# Final readiness

Production evidence was captured 2026-07-22. Feature-branch verification was
captured 2026-07-23. `VERIFIED` means directly inspected in the named environment;
`PARTIAL` records an explicit missing channel.

| Area | Status | Evidence / blocker |
| --- | --- | --- |
| GitLab → GitHub mirror | `VERIFIED` | Both `main` refs matched `d798add9e13fe3187ab0be4becf1e90f79952e67` before the final evidence commit |
| GitHub → Railway automatic deploy | `VERIFIED` | Existing service deployment `397e6f47-b04e-408e-8621-f0c31d4d4c16`, source `cloudspiral/agentforge-dashboard`, branch `main`; no duplicate service/action path |
| Feature branch deployed | `NO` | Intentionally not merged or deployed; current Railway evidence describes the earlier `main` baseline |
| Runtime shape | `VERIFIED` | One replica, Uvicorn `--workers 1`, embedded worker ready, sleep disabled, Dockerfile build, `/readyz` health check |
| Dashboard authentication | `VERIFIED` | Unauthenticated `/` returns `401`; authenticated overview, run action, status polling, and detail work |
| Dashboard campaign launcher | `VERIFIED LOCALLY` | CSRF, idempotency, taxonomy validation, inline error preservation, deployed-target confirmation, redirect, and bearer-token absence are tested |
| Multi-agent controller | `VERIFIED LOCALLY` | Orchestrator selection, deterministic fallback, exact Attack Generator proposals, valid partial-signal mutation, rejected proposal accounting, duplicate gate, safe incomplete evidence, Documentation/report path, and regression replay pass PostgreSQL tests |
| Proposal provenance | `VERIFIED LOCALLY` | Trusted `agent_generated`, `agent_generated_mutation`, and `deterministic_seed_fallback` plus objective source, lineage, parent, generation, hash, and sanitized fallback reason are persisted before execution |
| Health/readiness | `VERIFIED` | `/healthz` and `/readyz` return `200`; configuration, database, and worker are ready |
| PostgreSQL durability | `VERIFIED` | Campaign, attempt, 8 assertions, Judge verdict, AgentRun usage/cost/latency/trace, and terminal state inspected through SELECT-only CLI |
| Feature-branch migration | `VERIFIED LOCALLY` | `f43a8d7e91b2 (head)`; Alembic check reports no pending operations; 20 PostgreSQL lifecycle/controller tests pass |
| Langfuse linkage | `VERIFIED` | Trace `e4ac48aa75342ec674ca38ebea64d49b` links matching campaign/attempt metadata and six observations; root input/output fully masked, observation payloads absent, trace private |
| Current eval hashes | `VERIFIED` | Four portable exports validate against exact YAML bytes; catalog validates 9 seeds and 4 controls |
| OWASP coverage | `PARTIAL` | A10 and LLM05 verified; A06 and LLM06 failed; A07/A09 and LLM03 partial; see `evals/OWASP_COVERAGE.md` |
| Confirmed live vulnerabilities | `VERIFIED` | One: AF-TM-001 irrelevant chart-tool invocation; medium severity/high exploitability |
| Three exploit reports | `UNMET` | One confirmed human-authored AF-TM-001 report; two A06 exposure/triage reports explicitly do not count as exploit reports |
| Documentation Agent | `TESTED, NOT LIVE-CONFIRMED` | Controller finding/report/regression workflow passes PostgreSQL tests; no new live confirmed finding justified invoking it |
| Bounded multi-agent trace | `PARTIAL` | One real Orchestrator → Attack Generator → Judge trace persisted with trusted provenance; sandbox browser initialization failed, so verdict was correctly inconclusive and Documentation did not run |
| OpenEMR target unchanged | `VERIFIED` | `openemr-web` deployment `531630f7-da13-4aa3-b365-bbbb15dfdd50`; `agent-service` `9b7d9985-1e57-4735-9fe4-dcc536a91bc7` |
| Optional 100-operation benchmark | `NOT RUN` | Deferred per final-hardening priority |
| Simulated reports | `NOT RUN` | Optional and explicitly not used to inflate live finding count |
| Feature-branch image build | `CI REQUIRED` | Local Docker metadata write was denied by the desktop approval layer; compose validates, but no local build claim is made |

## Verification commands

```bash
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv sync --frozen
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run ruff format --check .
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run ruff check .
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run pytest -q
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/export_contracts.py --check
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/export_evals.py --validate-only
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/check_submission_results.py
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run python scripts/check_control_results.py
docker compose config --quiet
env UV_CACHE_DIR=/private/tmp/agentforge-uv-cache uv run alembic heads
```

For durable production linkage, run locally through the authenticated Railway shell:

```bash
railway ssh --service agentforge-dashboard python scripts/verify_production_linkage.py \
  --campaign-id f7023f5e-17ca-4f8b-81a9-0738b61413a9 --verify-langfuse
```

No public diagnostic endpoint is added.
