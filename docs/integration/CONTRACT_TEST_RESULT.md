# Contract and release test result

## Latest result

On 2026-07-22, final-hardening verification produced:

- `uv sync --frozen`: passed; 87 packages checked.
- `uv run ruff format --check .`: passed; 104 files formatted.
- `uv run ruff check .`: passed.
- `uv run pytest -q`: **179 passed, 16 skipped**; the skips are explicit
  PostgreSQL/live-browser opt-ins, not unexpected omissions.
- Explicit isolated PostgreSQL integration suite: **15 passed**.
- Contract export drift: passed; 7 schemas current.
- Mixed eval catalog: passed; 6 live seed definitions and 4 control definitions.
- Current-result validation: passed; 4 exact-schema exports matched exact YAML bytes.
- Control-result validation: passed; all 4 target-specific OWASP result/evidence
  envelopes validated.
- `docker compose config --quiet`: passed.
- Empty PostgreSQL database upgrade/current/check: passed at
  `c71d9e5a4b20 (head)` with no pending operations.
- Final Docker image build: passed as `agentforge-final-hardening:latest`.

The isolated database was named `agentforge_final_019f88a8_test`, verified absent
before creation, and removed after the checks.

## What these checks establish

- Representative v1 payloads validate and reject forbidden, secret-shaped, and
  extra input.
- Exported JSON schemas match the Python contract definitions.
- Every result labeled current is bound to its exact case definition.
- OWASP controls use the strict per-mapping status vocabulary and carry target,
  build, case-hash, expected/observed, evidence, severity, exploitability, and
  regression metadata.
- The migrations and controller/job lifecycles work on a fresh PostgreSQL database.
- The production Dockerfile assembles with the pinned lock and matching Chromium.

## What these checks do not establish

They do not make individual target findings universally applicable, reconcile model
cost with provider billing, prove backup/restore or multi-worker kill recovery, close
partial authentication/logging/model-provenance evidence, or replace human clinical
and security review. Live target and production-linkage claims are recorded separately
in `evals/OWASP_COVERAGE.md`, `docs/integration/CROSS_AGENT_TRACE.md`, and
`docs/FINAL_READINESS.md`.
