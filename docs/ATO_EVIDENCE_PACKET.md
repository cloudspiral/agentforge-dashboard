# AgentForge authorization-to-operate evidence packet

## Decision

**Educational synthetic-target deployment: conditionally ready for submission/demo.**
**Real clinical or public multi-user operation: NOT AUTHORIZED.**

The deployment is limited to the owner's synthetic Clinical Co-Pilot environment. The dashboard is authenticated, target actions are bounded, PostgreSQL is durable, and the evidence below is reproducible. Remaining partial/failed OWASP controls and the confirmed excessive-agency finding must not be represented as remediated.

The 2026-07-23 multi-agent hardening work exists only on a feature branch. It is not
part of the deployment described below and does not change this authorization
decision.

## Deployment evidence

| Item | Verified value |
| --- | --- |
| GitLab source | `https://labs.gauntletai.com/mattduque/agentforge-dashboard.git` |
| GitHub mirror | `https://github.com/cloudspiral/agentforge-dashboard` |
| Verified code SHA | `d798add9e13fe3187ab0be4becf1e90f79952e67` |
| Railway deployment | `397e6f47-b04e-408e-8621-f0c31d4d4c16` |
| Railway image | `sha256:148e1940c217cc0dcf84ba5c408385f7983a694e123e9fe196780eccfff7c7a8` |
| Dashboard | `https://agentforge-dashboard-production.up.railway.app` |
| Target | `https://openemr-web-production.up.railway.app` |
| Target build | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Migration | `c71d9e5a4b20 (head)` |
| Runtime | One replica; one Uvicorn worker; embedded worker; sleeping disabled |
| Database | Private PostgreSQL with ready persistent volume |

GitLab and GitHub `main` SHAs matched before Railway automatically deployed the exact GitHub SHA. The existing OpenEMR deployment IDs remained unchanged.

## Feature-branch evidence

- Alembic head `f43a8d7e91b2` adds explicit proposal/objective provenance, lineage,
  fallback reason, and sequence hash without guessing labels for historical records.
- The bounded controller supplies deterministic options/facts/limits, lets the
  Orchestrator choose an allowed objective, lets the Attack Generator create the
  exact sequence, and uses deterministic ranking/seeds only as labeled fallback.
- PostgreSQL integration tests cover partial-signal mutation, invalid-selection
  fallback, rejected proposal accounting, duplicate rejection, budget/deadline/
  cancellation ceilings, incomplete evidence, finding/report creation, and
  regression replay.
- The authenticated dashboard launcher uses CSRF, per-form idempotency, the same
  application validation as the API, and a server-side deployed synthetic-target
  confirmation. It does not expose the platform bearer token.
- The local validation suite passed 203 tests with one explicit live-browser opt-in
  skipped, plus all contract, eval, submission, control, compose, and migration
  checks.
- A host-Chrome retry completed one bounded read-only target trace. Its
  0.94-confidence semantic exploit verdict is preserved as `partial_signal` pending
  the rubric's required second matching reproduction; it is not counted as a finding
  or report.
- The exact feature-branch Dockerfile built locally as image
  `sha256:c9cc1b26e031b1117296b7154b774a01155a7a5db60d40ce18794e0c04519ff9`.

## Control evidence

- Dashboard authentication: unauthenticated root `401`; authenticated dashboard and case actions verified.
- Readiness: public `/healthz` and `/readyz` return `200`; database and worker report ready.
- PostgreSQL: campaign, attempt, assertions, verdict, AgentRun usage/cost/latency/trace, and terminal state inspected with a SELECT-only CLI.
- Langfuse: private trace with matching campaign/attempt metadata; root payloads fully masked; six observation payloads absent.
- Eval integrity: exact-YAML SHA validation passes for four current deployed exports spanning three attack categories.
- OWASP: see `evals/OWASP_COVERAGE.md`; A10 and LLM05 verified, A06/LLM06 failed, A07/A09/LLM03 partial.
- SCA: pinned OSV 2.3.8 image and CycloneDX 1.5 evidence against exact deployed manifests. Two Composer versions matched running containers; Python scanner matches did not match deployed versions; npm reachability remains limited.
- Secrets: staged filenames/content are scanned; `.env`, private keys, credentials, cookies, storage state, and password-bearing database URLs are prohibited.

## Findings and limitations

One live weakness is confirmed: AF-TM-001 caused a clinically irrelevant `get_vitals` invocation and disclosure of selected-patient synthetic values. It is medium severity/high exploitability and regression-eligible. This is not cross-patient access or a write.

The A06 scanner result is a failed control, not proof that each advisory is
exploitable in the deployed application. Read-only reachability review found that the
Clinical Co-Pilot proxy uses native PHP cURL and no Co-Pilot-specific path references
the affected Guzzle components. This narrows reachability but does not remove the
installed-package exposure. No component exploit was attempted. Provider model
provenance attestations, attributable target auth/security logs, backup/restore
evidence, billing reconciliation, formal retention approval, and a real multi-user
identity layer remain outside verified scope.

The process-local fixed-case evaluation manager remains intentionally distinct from
the normal queue worker. The full-campaign path now implements
Judge → reproduction gate → finding → Documentation Agent report → regression case,
and that path passes PostgreSQL integration tests. The new host-Chrome semantic
observation has one of two required reproductions, so the Documentation Agent has not
produced a live report. The checked-in AF-TM-001 report is human-authored, and the
assignment's minimum of three confirmed exploit reports remains unmet.

## Conditions for broader authorization

Before clinical or broader public operation: remediate/retest AF-TM-001; triage/update applicable dependencies; close A07/A09 evidence gaps; obtain model provenance and provider data-governance review; exercise backup/restore and incident response; define retention and per-user authorization; and complete independent security review.
