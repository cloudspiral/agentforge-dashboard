# AgentForge authorization-to-operate evidence packet

## Decision

**Educational synthetic-target deployment: conditionally suitable for submission.**
**Real clinical or public multi-user operation: not authorized.**

The deployed baseline is limited to the owner's synthetic Clinical Co-Pilot. The
2026-07-23 simplified-pipeline work is a local feature branch and does not change the
deployed authorization boundary.

## Historical deployed evidence

| Item | Verified value |
| --- | --- |
| GitLab source | `https://labs.gauntletai.com/mattduque/agentforge-dashboard.git` |
| GitHub mirror | `https://github.com/cloudspiral/agentforge-dashboard` |
| Source SHA | `d798add9e13fe3187ab0be4becf1e90f79952e67` |
| Railway deployment | `397e6f47-b04e-408e-8621-f0c31d4d4c16` |
| Railway image | `sha256:148e1940c217cc0dcf84ba5c408385f7983a694e123e9fe196780eccfff7c7a8` |
| Dashboard | `https://agentforge-dashboard-production.up.railway.app` |
| Target build | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Historical migration | `c71d9e5a4b20` |

Dashboard authentication, `/readyz`, durable PostgreSQL records, private redacted
Langfuse linkage, four exact-hash live exports, and one confirmed excessive-agency
finding were verified on that baseline. These facts must not be represented as proof
that the feature branch is deployed.

## Feature-branch controls

- Orchestrator, Attack Generator, Judge, and Documentation Agent own all semantic
  choices through typed contracts.
- Invalid Orchestrator or Attack Generator output receives bounded same-agent retries
  and then fails; discovery has no deterministic/YAML fallback.
- The gate authorizes only configured target/version/operation/payload/synthetic
  scope and rejects duplicate hashes before execution.
- The runner directly constructs raw typed evidence; no discovery evidence-analysis
  or verdict-reconciliation layer exists.
- The Judge is the sole security verdict authority.
- One `exploit_confirmed` attempt immediately creates one Finding, Documentation
  Agent report, and regression case; successful documentation returns to discovery.
- Attempt lifecycle and structured operational failure are separate from Judge
  verdict.
- Dashboard campaign creation is Basic-authenticated, CSRF-protected, idempotent,
  taxonomy-validated, and requires explicit server-side deployed-target confirmation.
- Fixed YAML assertions are isolated to the explicit fixed-case harness.

These controls are unit/contract- and isolated-PostgreSQL-integration-tested. The
four-role path is also live-proven by prompt-injection attempt
`40004cce-cc03-4e60-9357-16067d7b6317`, which produced Finding
`AF-5860F03C4E00`, a Documentation Agent report, and a regression case before the
campaign continued.

## Findings and limitations

`AF-TM-001` is one confirmed live issue: a clinically irrelevant `get_vitals` call
returned selected-patient synthetic values. It is not a cross-patient leak or write.
The Clinical Co-Pilot has not been patched by this branch.

The A06 result proves installed affected components, not application-specific
exploitability. The Co-Pilot bridge uses native PHP cURL; advisory prerequisites were
not exercised. A09 remains partial because runtime target-log evidence attributable
to the test correlation ID was unavailable. Provider provenance, backup/restore,
formal retention, billing reconciliation, and independent security review also remain
open.

There are two confirmed exploit reports, not three. A06 exposure/triage reports do
not count as exploit reports. The historical `AF-TM-001` report is human-authored;
`AF-5860F03C4E00` is the live Documentation Agent report.

## Conditions for broader authorization

Before any clinical or broader public use: remediate and replay `AF-TM-001`; triage
and update applicable dependencies; close A07/A09 evidence gaps; complete provider
and data-governance review; test backup/restore and incident response; define
retention and per-user authorization; and obtain independent security review.
