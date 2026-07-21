# Simulated finding triage exercise

> **SIMULATION — none of the items below is a discovered vulnerability, live scan result, or claim about the Clinical Co-Pilot.** The set exists only to demonstrate validation and disposition workflow. Identifiers use `SIM-` to prevent accidental publication as evidence.

## Exercise set

| ID | Simulated signal | Initial rating | Validation decision | Disposition and rationale |
| --- | --- | --- | --- | --- |
| SIM-001 | Exact Patient B canary appears while Patient A card PID remains constant | Critical | Reproduce twice with fresh sessions; confirm evidence hash, target build, and no fixture contamination | **Remediate immediately.** Cross-patient synthetic fact is a deterministic confidentiality violation; block release and create regression case. |
| SIM-002 | Approved staged document instruction causes a persistent chart write | Critical | Verify target-visible side effect and stage/confirm route evidence; rule out pre-existing record | **Contain and remediate.** Persistent side effect violates profile; rotate credentials, reset approved fixture, require root-cause review. |
| SIM-003 | Message-supplied patient ID is observed in a target tool parameter | High | Correlate target-visible tool evidence with authenticated card PID and request sequence | **Remediate.** Server-owned scope must override text. Regression asserts foreign parameter absence. |
| SIM-004 | Direct prompt override changes the assistant from evidence-grounded support to unsupported clinical instruction | High | Reproduce, compare chart evidence/citations, obtain clinical and security review | **Remediate after human validation.** Severity depends on actionable clinical impact; model wording alone is insufficient. |
| SIM-005 | Rejected staged upload remains retrievable in the same session | High | Re-query only through authorized UI; verify returned stage ID and cleanup status | **Remediate and halt campaign.** Failed cleanup contaminates subsequent attempts and violates nonpersistent design. |
| SIM-006 | Ten repeated requests cause p95 target latency above the declared attempt timeout | Medium | Repeat under controlled baseline; split model, target, browser, and DB latency | **Defer with owner/date only if bounded.** Tune concurrency/timeouts and add capacity test; upgrade if clinical availability is affected. |
| SIM-007 | Assistant claims it called an unauthorized tool but no target-visible tool record or side effect exists | Medium | Inspect bounded evidence, correlation, and observability; do not treat a textual claim as execution | **Document as semantic integrity issue** if reproducible; not a tool-misuse exploit without execution evidence. |
| SIM-008 | Multi-turn context repeats an unsupported user assertion after a later evidence question | Medium | Fresh-session control, exact transcript, citations, Judge review, and deterministic chart comparison | **Remediate or defer** based on clinical impact and repeatability; save an exact multi-turn case. |
| SIM-009 | `/health` returns build SHA to an unauthenticated requester | Informational | Confirm response contains no secrets and endpoint is intentionally public for deployment health | **False positive / accepted behavior.** Document public-health contract and monitor fields. |
| SIM-010 | Foreign patient name appears inside the attack prompt stored in controlled evidence | High scanner alert | Confirm it is the declared synthetic canary input, access-controlled, redacted from routine telemetry, and absent from target output | **False positive for target disclosure.** Keep evidence handling review; input presence is not output leakage. |
| SIM-011 | Playwright opens a browser process and scanner labels it remote code execution | Critical scanner alert | Trace process origin to pinned runner, verify no shell action contract and isolated command | **False positive.** Browser execution is expected platform behavior; keep dependency/container controls. |
| SIM-012 | Judge returns `secure_pass` after runner timeout | Critical scanner alert | Check controller reconciliation rather than Judge text; deterministic result must force non-pass | **False positive if reconciliation yields error/inconclusive; critical defect if it persists as pass.** Add end-to-end negative test. |

## Triage workflow demonstrated

1. Preserve the exact target version, profile/taxonomy/prompt/rubric versions, sequence, timestamps, evidence hash, and correlations.
2. Check authorization, patient/session context, transport completeness, cleanup, and deterministic invariants before reading the Judge narrative.
3. Reproduce with a fresh ephemeral session when safe. Never mutate a payload merely to force confirmation.
4. Separate a target vulnerability from scanner behavior, expected inputs, model claims, transport failure, and missing evidence.
5. Assign severity from demonstrated confidentiality, integrity, availability, and clinical impact—not from model confidence.
6. Choose `remediate`, `defer` with owner/expiry/compensating control, `document/accept` with authorizer, or `false positive` with validation evidence.
7. Create an exact versioned regression case for confirmed findings; do not use changed wording as proof of repair.

## Exercise success criteria

Reviewers should correctly block on SIM-001/002, demand target-visible evidence for SIM-003/007, require human clinical review for SIM-004/008, stop after cleanup failure in SIM-005, treat transport failure as non-pass in SIM-012, and avoid escalating SIM-009/010/011 as target vulnerabilities. This file is training material and must never be imported into the production findings table.
