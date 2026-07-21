# Clinical Co-Pilot target change ledger

## Current result

No target changes were required or made during AgentForge Phase 0.

The existing Clinical Co-Pilot already provides:

- exact runtime version discovery through `/health` and `/ready`;
- a normal authenticated physician session flow;
- current-patient anchoring and patient-scoped CSRF validation;
- a same-origin chat proxy with a strict request contract;
- stable IDs, classes, accessible names, and frame names for UI automation;
- temporary document staging plus authenticated rejection;
- synthetic golden patients with exact external IDs and deterministic chart facts;
- dry-run-first fixture and demo-reset tooling.

Those surfaces are sufficient for the initial AgentForge HTTP and Playwright runners. Adding test-only endpoints or authorization exceptions would add risk without unblocking the MVP.

## Baseline record

| Field | Recorded value |
| --- | --- |
| Target repository | `/Users/matt/Developer/gauntlet/w1-AgentForge/openemr-base-clean` |
| Checked-out branch | `main` |
| Checked-out commit | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Local runtime build | `85a25ac` |
| Deployed runtime build | `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d` |
| Target files changed by AgentForge work | None |
| Target migrations or hooks added | None |
| Target deployed | No target deployment was performed |
| Removal procedure | Not applicable |

The local runtime/checkout mismatch predates AgentForge and reflects the already-running W1 sidecar. AgentForge must record the runtime build returned by `/health`; it must not imply that the local target is running checkout HEAD.

## Preserved pre-existing W1 worktree state

W1 was dirty before inspection and retained the same status afterward:

```text
## main...origin/main
 M agent_service/app/tooling/contracts.py
 M agent_service/tests/test_atomic_tooling.py
 M agent_service/tests/test_conversational_loop.py
?? .agents/
?? demo-artifacts/
```

These are pre-existing user changes. AgentForge Phase 0 did not edit, format, test, stage, commit, or deploy them. The inspection used source reads and safe liveness/readiness `GET` requests only.

## Testability decision

No `data-testid` patch was added. The current target exposes stable selectors including `#authUser`, `#clearPass`, `#login-button`, `#anySearchBox`, `iframe[name="fin"]`, `iframe[name="pat"]`, `.clinical-copilot-card`, `#clinical-copilot-message`, `.clinical-copilot-output`, and the upload/review controls. AgentForge couples each selector with deterministic patient and contract checks rather than trusting a locator alone.

No `/version` endpoint was added because `/health.build_sha` already exposes the exact deployment revision on both the OpenEMR origin and sidecar.

No `/test/reset-session` endpoint was added. A fresh ephemeral browser context provides a clean chat session without changing target data, and temporary uploads have an authenticated rejection path.

No sanitized target-tool-call hook was added. The initial runner uses the returned evidence contract, correlation ID, visible behavior, and existing observability linkage. If tool-call metadata later proves necessary for a deterministic assertion, it requires a separately reviewed design that is disabled by default, synthetic-only, authenticated, bounded, and incapable of broadening target access.

## Rules for any future target change

Any future W1 modification must be entered below before deployment and must include:

- target commit and exact files;
- the blocked AgentForge requirement;
- why existing target behavior is insufficient;
- security and clinical risk;
- environment/test-mode guard;
- authentication and authorization boundary;
- data-retention and logging behavior;
- removal or rollback procedure;
- tests and live verification;
- whether and where it was deployed.

Never add a backdoor, patient-context override, arbitrary tool-call interface, credential bypass, direct database mutation endpoint, or reset that can operate on non-synthetic records.

## Change entries

There are no applied entries.

