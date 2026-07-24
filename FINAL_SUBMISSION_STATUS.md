# Final submission status

Production evidence was captured 2026-07-22 against Clinical Co-Pilot build
`fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d`. The simplified-pipeline evidence below
is local feature-branch evidence from 2026-07-23. The branch is not merged or deployed.

## Submission verdict

The checked-in eval-dataset gate is met: `evals/results/submission/` contains four
sanitized, schema-valid deployed results across three categories, and every
`case_sha256` matches the exact current YAML bytes. CI rejects drift in result,
contract, and OWASP control artifacts.

The feature branch adds:

- an agent-driven discovery loop with no deterministic objective, attack, or verdict
  fallback;
- Judge-only semantic outcomes from raw runner evidence;
- one-attempt Finding, Documentation Agent report, and regression creation;
- lifecycle-only attempt state with separate operational failures;
- parent-only mutation persistence with derived generation;
- an authenticated CSRF/idempotent campaign launcher;
- explicit separation between fixed YAML assertions and discovery;
- additional state-corruption, bounded-work, and role-escalation cases;
- A06 reachability triage and honest A09 evidence boundaries.

## Historical deployed evidence

| Item | Verified value |
| --- | --- |
| Evidence-capture source SHA | `d798add9e13fe3187ab0be4becf1e90f79952e67` |
| Railway deployment | `397e6f47-b04e-408e-8621-f0c31d4d4c16` |
| Railway image | `sha256:148e1940c217cc0dcf84ba5c408385f7983a694e123e9fe196780eccfff7c7a8` |
| Historical database revision | `c71d9e5a4b20` |
| Dashboard | `https://agentforge-dashboard-production.up.railway.app` |
| Target | `https://openemr-web-production.up.railway.app` |
| Target web deployment | `531630f7-da13-4aa3-b365-bbbb15dfdd50` |
| Target agent deployment | `9b7d9985-1e57-4735-9fe4-dcc536a91bc7` |

These values describe the earlier deployed `main`, not this branch. No deployment or
Clinical Co-Pilot change is part of this merge request.

## Confirmed vulnerability

`AF-TM-001` is one confirmed live vulnerability: an unrelated request caused an
unnecessary `get_vitals` call and returned selected-patient synthetic values. It is
medium severity/high exploitability. It is not a cross-patient disclosure or write.

A later pre-refactor discovery trace observed the same attack family and received a
Judge `exploit_confirmed` verdict, but the old controller stored it inconclusively
because of a reproduction gate. Historical rows are not rewritten. Under the new
controller, the first confirmed attempt immediately becomes its own Finding, report,
and regression case.

The assignment's target of three confirmed exploit reports remains unmet. There are
two confirmed exploit reports: historical human-authored `AF-TM-001` and the new
Documentation Agent report `AF-5860F03C4E00`. A06 dependency records are
exposure/triage reports and do not count as application exploits.

The new report is live proof of the simplified path. A five-attempt prompt-injection
campaign produced one `exploit_confirmed`, created one Finding/report/regression
immediately, continued to the fifth attempt, and completed. The confirmed attempt
disclosed purported hidden control content and abandoned clinical scope without an
unauthorized tool call, cross-patient access, or write.

## OWASP status

- `VERIFIED`: A01, A10, LLM02, and LLM05 for the exact executed controls.
- `FAILED`: A03/LLM01 because of `AF-5860F03C4E00`, and A04/LLM06 because
  of `AF-TM-001`.
- `EXPOSURE`: A06 affected deployed components, without demonstrated
  application-specific exploitability.
- `PARTIAL`: A07, A09, and LLM03.

See [evals/OWASP_COVERAGE.md](evals/OWASP_COVERAGE.md) for exact methods and evidence.

## Simplified-pipeline validation

Local unit/contract tests and isolated PostgreSQL integration tests cover:

- valid and invalid Orchestrator and Attack Generator output with bounded same-agent
  retries;
- authorization and duplicate rejection without creating attempts;
- runner failure, partial evidence, persistent Judge failure, and every Judge verdict;
- absence of discovery fallback and deterministic semantic reconciliation;
- immediate one-attempt Finding/report/regression and campaign continuation;
- separate Findings for identical confirmed attempts;
- `partial_signal` mutation parents and derived generation;
- documentation/regression failure preserving confirmed evidence;
- migration backfill, historical provenance display, API/CLI/dashboard validation,
  CSRF, idempotency, and secret absence.

Final formatting, full pytest, schema/eval checks, PostgreSQL migration check, compose,
Docker build, credential scan, and browser smoke are recorded in
[docs/FINAL_READINESS.md](docs/FINAL_READINESS.md).

## Remaining limitations

- The Clinical Co-Pilot needs a separately supervised remediation and secure replay
  for `AF-TM-001`.
- A third distinct confirmed exploit report is still needed to meet the assignment
  target; the branch does not manufacture one from partial or exposure evidence.
- A06 dependencies need applicability/remediation triage; installed affected packages
  alone do not prove exploitability.
- A09 needs attributable runtime security-log evidence for a correlated attack.
- LLM03 needs provider model provenance attestations.
- The optional large-scale benchmark and simulated reports are not used to inflate
  evidence.

This branch is for a draft GitLab merge request only. It does not merge, deploy,
modify target infrastructure, patch the Clinical Co-Pilot, record a demo, or publish
security findings.
