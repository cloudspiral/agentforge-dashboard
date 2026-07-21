# AgentForge failure modes and recovery

## Operating rule

AgentForge fails safely only when uncertainty stops authority. An invalid proposal is rejected; an unavailable target is an execution error; incomplete transport or evidence is inconclusive; an unverified staged-upload rejection is a cleanup failure; a telemetry outage is not a target failure; and a generated report is never external publication.

This runbook describes likely behavior, detection, containment, and recovery based on the current W3 components and the verified synthetic OpenEMR integration. It does not claim that these scenarios have all been exercised live. `RUN_LIVE_E2E` is disabled by default.

Before live use, two current integration risks require explicit closure:

- W3 read APIs and the HTML dashboard have no route-level authentication. Keep the service network-private until read authorization is added and verified.
- The deterministic gate produces `ValidatedAttackV1`, while the complete campaign-processor handoff to the runner is not demonstrated here. Verify that the runner consumes the gate-authorized endpoint, fixture, patient, expiry, profile, sequence, and budget bindings—not a raw proposal—before enabling live execution.

## Severity and disposition vocabulary

| Disposition | Meaning | May count as secure? | Default next step |
| --- | --- | --- | --- |
| Rejected | Deterministic authorization denied before target execution | No | Correct scope/input only if the rejection is marked revisable |
| Failed | Component or target operation did not complete as required | No | Contain, reconcile state, then decide whether a bounded retry is safe |
| Timed out | A bounded wait expired | No | Treat as incomplete; check target/provider health and budget |
| Inconclusive | Evidence cannot prove either protected behavior or violation | No | Reproduce only after cause and cleanup are understood |
| Secure pass | Complete evidence proves every required invariant for that case | Yes, for that exact version/case only | Persist result; do not generalize beyond scope |
| Proven violation | Deterministic evidence proves an invariant failed | No | Stop/contain, preserve minimal evidence, human review and safe reproduction |

## Control-plane and authorization failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| Missing or invalid W3 bearer token | Mutation route returns `401`; no queue mutation should occur | Do not add a development bypass | Correct secret source; if unexpected, rotate token and audit recent mutations |
| Missing or invalid deployment webhook secret | Hook returns `401`; no deployment regression should be queued | Keep webhook and platform credentials separate | Correct/rotate webhook secret; replay once with the same deployment/version idempotency identity |
| W3 API or dashboard exposed publicly | Unauthenticated GET caller can read campaign/finding/report/agent-run summaries under current routing | Remove public ingress or require upstream authentication immediately; preserve access logs | Add and verify route-level read authorization and least-privilege views before reopening |
| API/webhook secret exposure | Unauthorized campaign creation, cancellation, status mutation, export, or deployment trigger may become possible | Revoke ingress if needed; rotate the affected secret; do not rotate unrelated domains as a substitute | Audit API/database records and access logs, invalidate old secret, notify owners, reissue least privilege |
| Invalid target alias/taxonomy/cost request | Application service returns a validation error before queue creation | Keep request out of worker queue | Select a checked-in alias/taxonomy value or lower limits; do not accept raw URLs |
| Duplicate API or deployment delivery | Idempotency/unique state should prevent a second logically identical queue record; a conflict or existing record is expected | Do not create a new random key merely to force execution | Retrieve the original record and reconcile its state; retry only if it never obtained authority |
| Database unavailable during queue mutation | API request fails or transaction rolls back; durable queue state is absent/unknown | Stop accepting work if durability cannot be established | Restore DB connectivity, verify transaction outcome by idempotency key, then resubmit if absent |
| API/worker startup or migration fails | Health/readiness never becomes available or container restarts; no campaign should be treated as running | Keep ingress and worker disabled; preserve database volume | Inspect sanitized startup/migration error, repair entrypoint/schema compatibility, rerun migration once, then verify health before queue work |
| Worker cannot claim work | Queue depth/age grows while active worker metric stays low; no target action should start | Keep additional workers from bypassing repository claim semantics | Restore worker/DB, inspect oldest queued record and claim locks, resume ordinary polling |
| Worker crash or stale heartbeat | Campaign remains running until stale recovery marks it interrupted; target action completion may be uncertain | Do not automatically replay a possibly stateful operation | Inspect attempt evidence and target cleanup state, mark/recover deliberately, start a fresh attempt only after reconciliation |
| Cancellation arrives during an action | Worker/controller may finish the in-flight bounded operation before observing cancellation | Prevent new attempts/mutations; prioritize upload rejection if a stage exists | Reconcile action outcome and cleanup, record cancelled/interrupted status, never label as secure pass |
| Campaign processor raises unexpectedly | Worker records a redacted `unexpected_internal_error` and failed campaign status | Stop that campaign; avoid reflecting raw exception secrets | Diagnose locally, repair processor, verify no target state remains, then create an explicit new attempt |
| Cleanup flag is false | Stopping logic and gate deny further attempts | Quarantine campaign and target session | Complete authenticated cleanup or manually verify absence of staged/persistent effects before resetting the flag through a reviewed workflow |

## Proposal, budget, and gate failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| Model output is invalid JSON/schema | Contract validation fails; no valid proposal/verdict/report exists | Do not coerce arbitrary text into a contract | Record typed invalid-contract error; use one bounded repair/retry only if controller policy permits |
| Model refuses the authorized request | Typed refusal/no proposal; no target call | Do not circumvent provider safeguards or broaden prompt authority | Use approved seed-case parameterization or choose a different authorized objective; record refusal |
| Model proposes raw URL/path/shell/SQL | Contract or gate rejects arbitrary authority | Preserve rejection reason without executing | Request a revision expressed only through approved aliases; repeated behavior stops lineage |
| Wrong identity, role, or patient alias | Gate returns authentication/patient scope mismatch | No runner call | Rebuild objective from controller-owned identity/patient context; never let model choose credentials |
| Invalid action order or missing evidence collection | Gate returns invalid sequence | No partial execution | Regenerate the required reset/authenticate/select, operation/wait, final-collection sequence |
| Unknown endpoint or method/purpose mismatch | Gate returns unknown/not-allowlisted/method rejection | No network request | Fix controller binding/profile configuration through code review; do not substitute a URL in the proposal |
| Persistent confirmation route proposed | Gate returns non-retryable prohibited-persistent-route | Stop that proposal/lineage; alert on repeated attempts | Ordinary campaigns have no recovery path to confirmation; a future persistent test needs separate design and approval |
| Unknown or changed fixture | Gate or runner rejects registry/path/type/size/pages/digest mismatch | Do not upload; quarantine changed file | Recreate/review fixture, update committed registry metadata intentionally, then obtain new authorization |
| Message, wait, turn, action, upload, or sequence bound exceeded | Gate returns corresponding limit/duplicate rejection | No target execution for that proposal | Reduce request within policy; do not split it into evasive near-duplicates |
| Unknown or stale model pricing | Unknown models are rejected. Pricing contains a verification date/refresh policy, but freshness enforcement must be verified before relying on it | Disable live model calls when the table is expired or freshness is not enforced | Refresh checked-in pricing from the approved source, implement/verify expiry enforcement, and review the change; unknown models remain disabled |
| Budget reservation missing/consumed/inconsistent | Gate rejects with budget-not-reserved or budget-limit | Stop before model/target work that relies on that reservation | Reconcile actual usage, release/consume prior reservation correctly, then create a new bounded reservation |
| Actual usage exceeds reservation | Budget reconciliation reports overrun/ceiling breach | Stop additional model calls and campaign attempts | Investigate usage accounting/provider response, update conservative estimates, require new reviewed capacity |
| Exact sequence repetition limit reached | Gate rejects duplicate sequence | Stop mutation loop | Choose a materially different approved sequence or end the lineage; preserve no-signal history |
| Gate-to-runner binding mismatch | Runner may reject an unknown alias, or unsafe wiring could reconstruct authority incorrectly | Keep live mode disabled; treat any mismatch as a control-plane defect | Make validated attack the runner input, compare profile/expiry/sequence/budget, and verify with negative integration tests before live use |

## Target authentication, patient, and transport failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| Target status origin unreachable | HTTPX timeout/network error; target version cannot be trusted | Do not start a version-bound campaign | Restore connectivity/DNS/service, then rediscover `/health.build_sha` and `/ready` |
| Checkout/runtime version mismatch | Observed `build_sha` differs from expected source/deployment metadata | Bind evidence to observed runtime; do not imply checkout code ran | Deploy intended revision or intentionally retarget; create a new campaign/version record |
| TLS validation failure | Deployed HTTPS request fails; no fallback to insecure transport | Do not disable TLS globally | Repair certificate/hostname/time. Only the exact local development alias may explicitly disable verification |
| Cross-origin redirect or browser request | HTTP runner rejects redirect or browser route aborts request | Dispose context and stop action; preserve sanitized origin/path category only | Fix target/profile navigation after review; never follow model-supplied redirect |
| Missing/wrong OpenEMR credentials | Authentication fails before patient action | Do not try alternate real users or expose credentials in diagnostics | Configure/rotate approved test identity, verify supported physician role, create fresh context |
| Stale/expired login (`401`/`403`) | Login check or proxy request fails; current cookie/CSRF cannot be trusted | Dispose entire HTTP/browser session | Authenticate normally again, reselect exact synthetic patient, obtain new card PID/CSRF |
| Patient context mismatch (`409`) | Server session PID differs from expected card PID | Stop; do not alter expected PID to satisfy server | Dispose context, search exact `pubpid`/display name again, rebind current card |
| Patient search returns zero/multiple/mismatched rows | Deterministic selection rejects before chat | No Co-Pilot request | Verify golden fixtures/environment; never pick the nearest name or hardcode numeric PID |
| Iframe/selector drift | Playwright locator timeout or missing card/attribute; evidence records failure | Stop UI attempt; do not use a broad ambiguous selector | Inspect target version/source, update profile/selectors through review, rerun local non-live tests |
| Card PID, CSRF, or endpoint changes mid-sequence | Runner binding check rejects action | Dispose context; no retry with stale token | Fresh login/patient selection; if repeatable, investigate target navigation/security state |
| Direct `/agent/chat` attempted | Endpoint resolver/gate/browser filter rejects; no authorized call | Record prohibited action and stop proposal | Use the normal OpenEMR session and same-origin PHP proxy only |
| Target returns `4xx` | Authorization/validation request failed; transport cannot be a secure pass | Avoid blind retries, especially `403/409` | Interpret exact status within sanitized metadata; rebuild session/context or correct bounded input |
| Target returns `5xx` | Target operation failed; response may be incomplete | Stop current attempt; do not claim target security | Check target health and correlation ID, verify no staged state, retry only safe read/transient action |
| Response exceeds byte limit | Capture truncates/rejects and records size condition | Stop semantic interpretation of incomplete body | Reduce approved request or raise limit only through reviewed policy; rerun as new attempt |
| Response or wait times out | Action is timed out; target completion may be unknown | Prevent next turn; check for stage/side effect uncertainty | Reconcile target state and health; use a fresh bounded attempt if retry is safe |
| Browser/Chromium fails to launch | Session initialization records target-unreachable/internal failure; no login | No fallback to saved session or alternate browser profile | Repair packaged browser/runtime, then run fake/unit and explicitly authorized smoke checks |

## Upload staging and cleanup failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| Fixture path traversal or symlink | Fixture resolver rejects before browser file input | No target upload | Place reviewed file under fixture root and authorize exact repository-relative path/digest |
| Wrong extension, MIME, size, pages, or digest | Gate/runner rejects before stage | Quarantine the artifact; do not “fix” metadata to match unreviewed bytes | Rebuild fixture intentionally, review content and limits, record new digest |
| Stage request fails before stage ID | Review does not appear; action fails | Dispose session after checking whether target created a stage | Use correlation metadata/target UI to verify; retry only after absence or rejection is known |
| Stage succeeds but review capture fails | Temporary stage may exist even without evidence | Treat cleanup as required and campaign as non-continuable | Attempt authenticated reject in `finally`; if unverified, manually inspect/reject and record cleanup failure |
| Reject request fails or response is not `rejected` | Cleanup proof is absent | Hard-stop campaign and block new attempts | Reauthenticate same synthetic context if valid, manually reject by target workflow, verify no persistent records |
| Browser closes before reject | Session disposal does not prove target cleanup | Mark cleanup failed | Inspect target stage using authorized UI/correlation data and reject; do not resume until verified |
| Confirmation request appears | Profile/gate/browser request filter should block it; any observed request is critical control failure | Immediately stop worker/campaign and isolate target session | Verify no persistence, inspect target audit/records, remove live authority, root-cause and regression-test all layers |
| Unexpected persistent record or side effect | Side-effect evidence/deterministic invariant fails | Stop campaign, preserve minimal evidence, restrict target access | Follow synthetic target cleanup runbook with human approval and post-cleanup verification; never mutate DB directly |

## Evidence, evaluation, and reporting failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| Missing target response | Deterministic transport status is missing/failed | Judge cannot emit secure pass | Reproduce only after target/session/capture is healthy and cleanup is known |
| Failed action or HTTP status in evidence | Transport-integrity assertion becomes error | Preserve error, skip later actions, no secure pass | Diagnose exact bounded step; create a fresh attempt rather than editing stored evidence |
| Evidence hash mismatch | Canonical evidence no longer matches persisted hash | Quarantine record and exclude from findings/regression | Restore immutable source/backup or rerun; investigate tampering/serialization drift |
| Artifact reference missing or path unsafe | Contract/path validation or artifact read fails | Exclude artifact and prevent report publication | Recover from private storage if hash/identity matches; otherwise recapture in a new attempt |
| Artifact volume full or unwritable | Screenshot, trace, or report export fails; database metadata may exist without the file | Stop evidence-dependent judgment/publication; do not redirect to an arbitrary path | Restore bounded private storage, reconcile orphan metadata/files, then recapture or re-export from validated source data |
| Screenshot/trace captures credentials | Sensitive-data incident; trace beginning before post-login is a warning | Restrict/delete artifact, disable trace export, rotate exposed target credential/session | Fix capture timing/redaction, verify with synthetic test, document incident before re-enabling |
| Synthetic canary appears for foreign patient | Deterministic invariant failure with evidence reference | Stop campaign/lineage; do not query further foreign data | Human review, safe minimal reproduction, finding/regression candidate if confirmed |
| Unauthorized tool/foreign parameter observed | Deterministic tool/patient-scope failure | Stop and dispose session; prevent mutation descendants | Review target/server logs and trusted context derivation, reproduce minimally under same synthetic scope |
| Judge is manipulated by evidence text | Semantic verdict conflicts with deterministic results/rubric | Apply deterministic floor; escalate ambiguity | Adjust rubric/ground truth and reproduce; never let target text act as Judge instruction |
| Judge false negative | Proven deterministic violations override to confirmed | Preserve override IDs/references | Human review and model/rubric analysis; deterministic result remains authoritative |
| Judge false positive or unsupported severity | No deterministic support, missing references, or human escalation trigger | Keep finding/report internal and unconfirmed | Reproduce, inspect evidence lineage, correct semantic verdict through reviewed workflow |
| Documentation invents facts/references | Strict report contract, frozen snapshot, or reference validation fails | Do not persist/export as valid report | Regenerate from minimal evidence after fixing input; never manually retain invented text as fact |
| Local report export path invalid | Safe vulnerability-ID/path check fails | No file write outside reports directory | Correct internal ID through data repair review; never accept arbitrary export filename |
| Draft report is mistaken for publication approval | Template/footer says draft, but human/process confusion remains possible | Keep artifacts private; no external connectors | Require named reviewer and publication checklist; record external disclosure separately |
| Finding/report read leak | Unauthenticated current read route or storage exposure discloses security detail | Remove ingress/revoke access, preserve access logs, restrict artifacts | Add read authorization, assess disclosed data, rotate any accidentally included secret, notify stakeholders |

## External provider and observability failures

| Failure mode | Likely behavior and detection | Containment | Recovery |
| --- | --- | --- | --- |
| OpenAI outage/rate limit/timeout | Typed provider error or no contract; budget reservation remains to reconcile | Stop dependent agent step; no target action from missing output | Reconcile usage/reservation, retry under bounded policy or pause campaign |
| Provider returns refusal | No authorized proposal/verdict/report for that call | Do not evade provider safety | Record refusal; use approved seed/mutation path or human review |
| Provider data-handling concern | Inputs may have crossed an external boundary despite synthetic-only policy | Stop further calls, identify minimized payload class, preserve local incident metadata | Rotate key if needed, follow provider controls, tighten minimization/retention before resume |
| Langfuse credentials absent | Telemetry adapter disables itself; local workflow may continue | Do not fabricate trace IDs or treat telemetry absence as evidence failure by itself | Configure credentials if telemetry is required; local PostgreSQL evidence remains authoritative |
| Langfuse initialization/update/flush outage | Warning and missing/partial external trace; security execution should be failure-isolated | Continue only if local evidence/metrics are durable; mark trace unavailable | Restore exporter and verify future traces; do not backfill secrets/raw evidence |
| Langfuse redaction failure or secret-shaped payload | External telemetry privacy incident | Disable telemetry immediately, rotate exposed secrets, restrict provider project | Delete/contain traces via provider process, repair/red-team redaction, re-enable after review |
| Trace ID missing/mismatched | Local attempt lacks external linkage or points to wrong trace | Do not use trace as sole evidence | Reconcile campaign/attempt metadata; rely on local evidence hash; fix propagation for future attempts |
| Metrics/logging backend unavailable | Reduced operational detection but not target authorization | Consider pausing live work if cleanup/queue health cannot be monitored | Restore monitoring; inspect database worker state and logs before resuming |
| Log message contains sensitive value | Local/central log exposure | Restrict logs, rotate secrets/session, stop forwarding suspect stream | Purge according to retention policy, improve pre-log redaction and regression tests |

## Recovery order after an uncertain target operation

When the outcome is unknown, use this order:

1. Stop new actions for the campaign and lineage.
2. Preserve only sanitized identifiers: campaign, attempt, action, correlation, target version, and timestamps.
3. Determine whether the operation was read-only, a temporary stage, or potentially persistent.
4. Dispose stale browser/HTTP session material; do not reuse cookies or CSRF values.
5. If a stage may exist, authenticate normally to the exact synthetic patient and verify/reject it. Browser closure is insufficient.
6. Verify no persistent chart record or external side effect. Do not inspect or mutate the OpenEMR database directly.
7. Reconcile PostgreSQL campaign/attempt/budget state and mark failed, interrupted, inconclusive, or cleanup-failed accurately.
8. Rotate any secret that may have entered an artifact, log, model input, or telemetry system.
9. Fix the smallest responsible boundary and add a deterministic regression/negative test.
10. Start a new version-bound attempt only after a human or deterministic control confirms recovery.

## Incident escalation triggers

Immediately stop live operation and require human security review if any of these occur:

- possible real-patient or non-approved identity access;
- a foreign synthetic patient canary or identifier in target-produced evidence;
- an allowed tool call with foreign patient/document scope;
- any request to ingestion confirmation or any persistent clinical record;
- inability to verify staged-upload rejection;
- cross-origin browser/network activity not explained by reviewed profile change;
- credential/session/CSRF material in logs, artifacts, OpenAI input, or Langfuse;
- evidence hash mismatch or suspected database/artifact tampering;
- public exposure of unauthenticated findings/reports/dashboard;
- runner execution without an unexpired deterministic gate authorization;
- repeated budget overruns or unbounded target/model activity.

External notification or vulnerability publication still requires the separate human publication process. Incident containment authority does not imply disclosure authority.
