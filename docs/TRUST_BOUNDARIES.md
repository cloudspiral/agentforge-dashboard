# AgentForge trust boundaries

## Authority map

| Boundary | Trusted authority | Untrusted input |
| --- | --- | --- |
| Campaign control | Authenticated API/dashboard, persisted limits, operator cancellation | Browser form values until validated |
| Objective selection | Orchestrator semantic choice among controller-supplied options | Model output until typed and membership-checked |
| Attack proposal | Attack Generator's typed sequence | Every model-supplied target, parameter, or payload until authorized |
| Target execution | Deterministic gate and immutable `ValidatedAttackV1` | Raw `ProposedAttackV1` |
| Evidence construction | Runner's typed transport plumbing | Target text and target-returned data |
| Security verdict | Judge Agent | Target text as data, never as Judge instructions |
| Persistence | PostgreSQL transactions and canonical hashing | Client- or model-supplied identifiers |
| Finding/report | Judge-confirmed Finding then Documentation Agent | Unsupported narrative claims |
| Publication/remediation | Human reviewer | Models, dashboard, and internal report artifacts |

## Agent boundary

Agents have no target credentials, browser tools, network tools, filesystem tools,
database handles, or publication connectors. Their structured outputs are
recommendations or interpretations.

The Orchestrator may return only `new_attack`, `mutation`, or `stop`. A mutation must
identify a persisted `partial_signal` parent. Invalid structured output is retried by
the same agent within a bounded limit; persistent failure ends the campaign. No
deterministic selector replaces it.

The Attack Generator creates the exact sequence. Invalid output is likewise retried
and then fails visibly. Discovery never substitutes a YAML seed, deterministic
sequence, or alternate model-produced attack.

The Judge is the only discovery component allowed to assign
`exploit_confirmed`, `partial_signal`, `attack_blocked`, or `inconclusive`.
Deterministic code does not supply semantic conclusions, evidence assertions, or a
minimum verdict and cannot reconcile the result.

## Execution boundary

Only `ValidatedAttackV1` reaches a runner. The authorization gate checks:

- configured target alias and exact target version;
- approved synthetic identity, patient, method, endpoint, and operation;
- message, turn, upload, response, and duration bounds;
- payload types and fixture identity;
- prohibited persistent writes, arbitrary URLs, cross-origin actions, shell, SQL,
  target-database access, and infrastructure operations;
- duplicate sequence hash.

Cost, attempt, duration, and cancellation limits are controller concerns checked
between iterations. They are not evidence about target security.

The target retains its own final authorization controls. The normal OpenEMR session
and same-origin proxy derive user, patient, CSRF, ACL, and tool scope server-side.

## Evidence boundary

The browser/HTTP runner executes an authorized envelope and directly constructs
typed raw evidence: actions, transcript, HTTP metadata, tool calls, side effects,
errors, timestamps, and target version. Schema construction and correlation IDs are
plumbing, not semantic validation.

A runner crash produces an operational failure and no Judge call. Successfully
returned evidence is bounded to 5 MiB, hash-verified, and committed to PostgreSQL
before an artifact is written or the Judge is invoked. Partial or error-bearing
evidence is then sent unchanged to the Judge. Target text is quoted as evidence data
and cannot issue instructions to the Judge.

Evidence JSON and generated Markdown are derived exports. Every download first loads
the corresponding PostgreSQL records and verifies the expected filesystem path,
identifiers, evidence hash, and contents. Files are never imported as runtime state,
and a database reset makes surviving exports untrusted archives.

The fixed YAML harness may compute deterministic assertions for a selected case.
Those assertions stay outside discovery evidence, are not sent to the Judge, cannot
override its verdict, and cannot create a discovery Finding.

## Finding and documentation boundary

One `exploit_confirmed` verdict creates one Finding for that attempt. The controller
does not reproduce, deduplicate, score, or reinterpret the issue. It mechanically
invokes the Documentation Agent and then creates a regression case from the saved
sequence and Judge context.

Documentation output must validate against its typed contract. The controller
mechanically replaces its transcript with the committed source-evidence transcript,
then commits the structured report and rendered Markdown body before exporting a
file. Failure preserves the Finding, evidence, and any committed report, records an
operational campaign failure, and does not fabricate a replacement report.

Canonical reports remain private. Only a human may authorize target changes,
deploy a fix, disclose an issue, publish evidence, or broaden the testing scope;
external disclosure is not a second finding-status workflow.

## Credentials and external services

Dashboard Basic credentials, API bearer credentials, provider credentials, and
synthetic target credentials are separate domains. Models receive none of them.
Browser contexts are fresh and non-persistent. Secrets and clinical content are
redacted from logs, traces, errors, result exports, and report filenames.

PostgreSQL is authoritative. Langfuse and metrics are supplemental and
failure-isolated; an observability outage cannot change a verdict or erase local
evidence. Direct access to the target database or Docker socket is prohibited.

## Recovery rule

If target completion or side effects are uncertain, stop the campaign, preserve
sanitized evidence, dispose the session, verify cleanup through the authorized target
UI, and start a new attempt only when safety is known. Browser closure is not cleanup
proof. An operational failure is never converted to a secure verdict.
