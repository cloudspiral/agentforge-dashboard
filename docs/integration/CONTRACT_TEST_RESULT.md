# Contract and release test result

## Latest result

On 2026-07-23, feature-branch verification produced:

- `ruff format --check .`: passed; 105 files formatted.
- `uv run ruff check .`: passed.
- Full `pytest -q` with the isolated PostgreSQL opt-in: **201 passed, 1 skipped**.
  The only skip is the explicit live-browser smoke opt-in.
- Explicit isolated PostgreSQL lifecycle/controller suite: **20 passed**.
- Contract export drift: passed; 7 schemas current.
- Mixed eval catalog: passed; 9 live seed definitions and 4 control definitions.
- Current-result validation: passed; 4 exact-schema exports matched exact YAML bytes.
- Control-result validation: passed; all 4 target-specific OWASP result/evidence
  envelopes validated.
- `docker compose config --quiet`: passed.
- Isolated PostgreSQL upgrade/current/check: passed at `f43a8d7e91b2 (head)` with
  no pending operations or model/migration drift.
- A new local Docker build could not start because the desktop approval layer denied
  Docker's build-metadata write. Compose validation passed; the branch image build is
  left to GitLab CI and is not claimed locally.

The isolated database was named `agentforge_final_test`; it is distinct from
development/production data. The bounded discovery evidence used a second isolated
database, `agentforge_final_live_test`.

## What these checks establish

- Representative v1 payloads validate and reject forbidden, secret-shaped, and
  extra input.
- Exported JSON schemas match the Python contract definitions.
- Every result labeled current is bound to its exact case definition.
- OWASP controls use the strict per-mapping status vocabulary and carry target,
  build, case-hash, expected/observed, evidence, severity, exploitability, and
  regression metadata.
- The migrations and controller/job lifecycles work on an isolated PostgreSQL
  database.
- The production Dockerfile still requires the CI image-build result for this exact
  branch.

## What these checks do not establish

They do not make individual target findings universally applicable, reconcile model
cost with provider billing, prove backup/restore or multi-worker kill recovery, close
partial authentication/logging/model-provenance evidence, or replace human clinical
and security review. Live target and production-linkage claims are recorded separately
in `evals/OWASP_COVERAGE.md`, `docs/integration/CROSS_AGENT_TRACE.md`, and
`docs/FINAL_READINESS.md`.
