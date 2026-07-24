# Contract and release test result

## Latest result

On 2026-07-23, feature-branch verification produced:

- `ruff format --check .`: passed; 108 files formatted.
- `uv run ruff check .`: passed.
- Full `pytest -q` with the isolated PostgreSQL opt-in: **206 passed, 1 skipped**.
  The only skip is the explicit live-browser smoke opt-in.
- Explicit isolated PostgreSQL lifecycle/controller suite: **22 passed, 1 live-browser skip**.
- Contract export drift: passed; 8 schemas current.
- Mixed eval catalog: passed; 9 live seed definitions and 4 control definitions.
- Current-result validation: passed; 4 exact-schema exports matched exact YAML bytes.
- Control-result validation: passed; all 4 target-specific OWASP result/evidence
  envelopes validated.
- `docker compose config --quiet`: passed.
- Isolated PostgreSQL upgrade/current/check: passed at `a812e4c97f30 (head)` with
  no pending operations or model/migration drift.
- Commit `98cfc6f` built successfully as non-root ARM64 image
  `sha256:cd20c3f07575a1d8d7b9f01e7a8cf9faa18cada06a17e1a09e629f10ceaed136`.
  An ephemeral container launched packaged Chromium 149 and imported AgentForge;
  GitLab CI remains the independent branch build gate.

The isolated database was named `agentforge_evidence_test`; it is distinct from
development/production data.

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
- The source-level dashboard smoke renders exact transcripts and fails closed for
  historical missing artifacts; the current-revision image packages a working
  Chromium runtime and imports the application as its non-root user.

## What these checks do not establish

They do not make individual target findings universally applicable, reconcile model
cost with provider billing, prove backup/restore or multi-worker kill recovery, close
partial authentication/logging/model-provenance evidence, or replace human clinical
and security review. Live target and production-linkage claims are recorded separately
in `evals/OWASP_COVERAGE.md`, `docs/integration/CROSS_AGENT_TRACE.md`, and
`docs/FINAL_READINESS.md`.
