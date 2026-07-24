# AgentForge authorization-to-operate evidence packet

## Decision

**Educational synthetic-target deployment: conditionally suitable for submission.**
**Real clinical or public multi-user operation: not authorized.**

The deployed baseline is limited to the owner's synthetic Clinical Co-Pilot. The
final V2 platform and demo-hardening changes are merged and deployed without
expanding the authorized-target boundary.

## Historical deployed evidence

| Item | Verified value |
| --- | --- |
| GitLab source | `https://labs.gauntletai.com/mattduque/agentforge-dashboard.git` |
| GitHub mirror | `https://github.com/cloudspiral/agentforge-dashboard` |
| Application code baseline | `942a461e8b84b1d3759f323b7b6425c9f1ce67c1` |
| Railway code-baseline deployment | `59f482bb-db8c-498f-b849-17386f74e5ff` |
| Railway image | `sha256:021f788f7480605cff600121e2074733b0724d132b62071c80a3d7b08bc9b82b` |
| Dashboard | `https://agentforge-dashboard-production.up.railway.app` |
| Target build | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Historical migration | `c71d9e5a4b20` |

Dashboard authentication, `/readyz`, durable PostgreSQL records, private redacted
Langfuse linkage, nine exact-current-hash seed results, three confirmed Findings,
24 immutable report versions, and a successful three-case regression suite were
verified on that baseline.

## Deployed controls

- Orchestrator, Attack Generator, Judge, and Documentation Agent own all semantic
  choices through typed contracts.
- Invalid Orchestrator or Attack Generator output receives bounded same-agent retries
  and then fails; discovery has no deterministic/YAML fallback.
- The gate authorizes only configured target/version/operation/payload/synthetic
  scope and rejects duplicate hashes before execution.
- The runner directly constructs raw typed evidence; no discovery evidence-analysis
  or verdict-reconciliation layer exists.
- The Judge is the sole security verdict authority.
- Every `exploit_confirmed` attempt immediately enters semantic promotion. A new
  fingerprint creates one Finding, Documentation Agent report, and regression case;
  rediscovery appends evidence to the existing Finding. Successful documentation
  returns to discovery.
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

There are three distinct confirmed Findings and three current canonical reports:
`AF-24F032E46E4A`, `AF-C29D26B2B508`, and `AF-0F2C8E9E19D8`. A06
exposure/triage reports do not count as exploit reports. Earlier report artifacts
are retained under `reports/historical/`; the three current version 8 PostgreSQL
exports are under `reports/submission/`.

## Conditions for broader authorization

Before any clinical or broader public use: remediate and replay all three current
Findings; triage and update applicable dependencies; close A07/A09 evidence gaps;
complete provider and data-governance review; test backup/restore and incident
response; define retention and per-user authorization; and obtain independent
security review.
