# AgentForge failure modes and recovery

## Operating rule

Uncertainty stops authority. Operational state and security verdicts are separate:

- rejected model output or gate denial produces no target attempt;
- runner failure produces a failed attempt and no Judge call;
- partial/error evidence returned by the runner is judged unchanged;
- persistent Judge, Documentation, or regression failure ends the campaign visibly;
- no failure is converted into a secure pass or a fallback attack.

## Control plane

| Failure | Containment | Recovery |
| --- | --- | --- |
| Invalid dashboard Basic auth, API bearer token, webhook secret, CSRF token, or deployed-target confirmation | Reject before mutation | Correct/rotate the scoped credential or resubmit an authorized form |
| Duplicate API/form delivery | Return the idempotent campaign | Retrieve the existing campaign; do not force a new random key |
| PostgreSQL unavailable | Roll back; no work may be assumed durable | Restore DB, inspect by idempotency key, then resubmit only if absent |
| Migration/startup/readiness failure | Keep worker and ingress unavailable | Repair schema/configuration and verify `/readyz` |
| Worker crash or stale claim | Stop new actions; target completion may be uncertain | Inspect evidence and cleanup state before creating a new attempt |
| Cancellation during an action | Finish only required cleanup; start no next iteration | Persist cancelled/failed state after reconciling the in-flight action |

## Agent output

| Failure | Containment | Recovery |
| --- | --- | --- |
| Orchestrator invalid schema/choice | Retry the same agent within its bounded contract limit | Persistent failure ends campaign; no deterministic objective |
| Attack Generator invalid schema/sequence | Retry the same agent within its bounded contract limit | Persistent failure ends campaign; no YAML or seed fallback |
| Provider refusal/outage/rate limit | No target execution from a missing proposal; preserve AgentRun failure | Retry only within configured same-agent policy or start a later campaign |
| Judge invalid output/failure | Preserve raw evidence and fail campaign | Diagnose provider/contract; never synthesize a verdict |
| Documentation invalid output/failure | Preserve confirmed Finding and evidence; fail campaign | Retry in a separately controlled workflow after fixing the cause |

## Authorization gate

| Failure | Containment | Recovery |
| --- | --- | --- |
| Raw URL, cross-origin action, shell, SQL, target DB, infrastructure, or persistent clinical operation | Reject without runner call | There is no ordinary campaign recovery; change policy only through review |
| Wrong target, version, role, identity, patient, method, endpoint, or fixture | Reject without runner call | Regenerate within server-owned allowed options |
| Payload/action/turn/upload/time bound exceeded | Reject without runner call | Generate a smaller authorized sequence |
| Duplicate sequence hash | Reject without runner call | Generate a materially different sequence or stop |
| Gate-to-runner binding mismatch | Disable live execution | Repair and negative-test immutable `ValidatedAttackV1` handoff |

Rejected proposals remain auditable through `AgentRun` and do not become
`AttackAttempt` records.

## Target and runner

| Failure | Containment | Recovery |
| --- | --- | --- |
| Target version drift | Do not execute or continue campaign | Deliberately start a campaign against the new observed version |
| Login, patient selection, CSRF, selector, or same-origin binding failure | Dispose the ephemeral session | Repair credentials/profile and begin a fresh attempt |
| Browser launch/crash | Mark operational failure; do not call Judge | Repair packaged runtime and validate with an authorized smoke |
| `4xx`, `5xx`, timeout, truncation, or incomplete response returned as typed evidence | Send that raw evidence unchanged to Judge | Let Judge assess only what was observed; retry later only if safe |
| Runner crashes before typed evidence | Mark attempt failed; no Judge | Reconcile target state, then begin a new attempt |
| Target side effect or cleanup uncertain | Hard-stop campaign | Verify through authorized target UI; never inspect or mutate target DB |

## Evidence and verdict

| Failure | Containment | Recovery |
| --- | --- | --- |
| Evidence hash mismatch | Quarantine record from reports/regressions | Restore immutable source or rerun as a new attempt |
| Evidence exceeds 5 MiB | Persist a typed operational failure; do not write an artifact or call Judge | Reduce the authorized sequence/evidence volume and run a new attempt |
| Evidence export missing or write fails | Preserve canonical PostgreSQL evidence; stop before Judge | Repair storage and regenerate only from the matching database record |
| Evidence export mismatches PostgreSQL | Refuse download/render and classify as corrupt | Preserve for investigation; do not overwrite, import, or trust it |
| Orphan JSON or stale temporary file | Never render or import it | Classify with read-only reconciliation; handle only through reviewed cleanup |
| Secret or real-patient data in evidence/artifact/trace | Stop campaign and external telemetry; restrict artifact | Rotate affected credentials, contain data, fix redaction, investigate |
| Target text attempts to instruct Judge | Treat it as quoted evidence data | Strengthen Judge prompt/contract; no deterministic verdict override |
| Suspected Judge false positive/negative | Preserve the Judge verdict and internal report state | Human reviews evidence/model calibration; code does not rewrite history |
| Fixed-case assertion disagrees with Judge | Store both only in fixed-case result | Investigate case/rubric calibration; neither overwrites the other |

## Findings, reports, and regressions

Every `exploit_confirmed` verdict enters promotion immediately; there is no
reproduction gate. A new semantic fingerprint creates a Finding, report, and
regression case, while rediscovery appends an immutable observation to the existing
Finding.

| Failure | Containment | Recovery |
| --- | --- | --- |
| Finding persistence failure | Roll back that mechanical transaction and fail campaign | Repair storage, then rerun a new authorized attempt |
| Report contract/reference failure | Keep confirmed Finding; do not export invented report | Fix Documentation input/contract and explicitly rerun documentation |
| Generated Markdown export failure | Keep Finding plus PostgreSQL structured report and `markdown_body`; leave `markdown_path` unset and fail campaign | Repair storage and regenerate from the matching report record |
| Regression-case creation failure | Keep Finding and report; fail campaign | Repair case builder and create/link the case through reviewed recovery |
| Regression runner/Judge failure | Store `error` | Diagnose operational cause; never record `secure_pass` |
| Regression returns `partial_signal`/`inconclusive` | Store `inconclusive` | Investigate or rerun; target is not proven secure |

Internal report creation is not publication. External disclosure and target
remediation always require human authorization.

## Incident stop triggers

Immediately stop live work for:

- any possible real-patient or unapproved identity access;
- a foreign patient identifier/canary or foreign-scoped tool call;
- persistent chart writes, ingestion confirmation, or uncertain upload cleanup;
- unexplained cross-origin activity;
- credentials in evidence, logs, model input, or telemetry;
- evidence hash mismatch or unauthenticated report/dashboard exposure;
- target execution without an unexpired validated gate envelope;
- repeated unbounded cost, target activity, or cleanup uncertainty.

Preserve sanitized campaign, attempt, correlation, target-version, action, and
timestamp metadata. Dispose stale sessions and verify target state through the normal
authorized UI. Do not use direct target-database access as recovery.
