# AgentForge data model

PostgreSQL is the canonical operational and audit store. JSON and Markdown files are
portable exports; they do not replace database records.

## Core records

| Table | Purpose and important fields | Cardinality / rule |
| --- | --- | --- |
| `campaigns` | Target, taxonomy scope, `max_attempts`, maximum cost, duration, priority, state, cancellation, idempotency | One campaign has many attempts and AgentRuns |
| `campaign_events` | Timestamped mechanical lifecycle events | Append-only history |
| `attack_attempts` | Lifecycle `state`, optional structured failure, parent attempt, trusted provenance, sequence hash, objective, proposed/executed sequence, target/profile/prompt/taxonomy versions, raw evidence, evidence hash, usage/cost/latency/trace | Created only after an agent proposal passes authorization |
| `judge_verdicts` | Verdict, confidence, severity, exploitability, violated invariants, observed/expected behavior, rubric version/hash | Zero or one per executed attempt |
| `agent_runs` | Role, model, prompt version, input/output metadata, usage, cost, latency, trace ID, typed failure | Persists successful and rejected/invalid role calls |
| `findings` | One confirmed attempt, attempt/evidence fingerprint, status | Exactly one new Finding per `exploit_confirmed` attempt |
| `vulnerability_reports` | Documentation Agent structured output, controller-anchored exact transcript, and rendered internal draft | Exactly one per successfully documented Finding |
| `regression_cases` | Saved sequence, target requirements, original Judge context, expected secure behavior, taxonomy metadata, source evidence hash | Created mechanically after report persistence |
| `regression_runs` | New target/evidence/verdict and mapped regression outcome | Many runs per regression case |

## Attempt lifecycle and outcome

`AttackAttempt.state` is deliberately lifecycle-only:

```text
pending | running | completed | failed | cancelled
```

`failure`, when present, is:

```json
{
  "stage": "runner",
  "code": "runner_crash",
  "retryable": false
}
```

Security outcomes exist only in `JudgeVerdict.verdict`:

```text
exploit_confirmed | partial_signal | attack_blocked | inconclusive
```

This keeps operational execution state separate from semantic assessment. A runner
crash produces a failed attempt and no Judge row. Successfully returned partial/error
evidence is persisted and judged.

## Provenance and mutation

New discovery attempts permit:

```text
proposal_provenance = agent_generated | agent_generated_mutation
objective_provenance = orchestrator_selected
```

Historical fallback values are retained for read-only compatibility but are rejected
for new discovery writes.

Only `parent_attempt_id` is stored for mutation. It must reference an attempt whose
Judge verdict is `partial_signal`. Lineage and generation are derived by following
parents; they are not separately persisted facts.

## Evidence identity

The runner constructs `AttackEvidenceV1` and computes its canonical content hash. The
controller verifies the hash and 5 MiB serialized ceiling, commits the complete
payload to `AttackAttempt.evidence_payload`, and only then writes a deterministic
JSON export or invokes the Judge. The raw evidence and hash are retained unchanged
for the Judge, report, and regression source.

`artifacts/evidence/<campaign-id>/<attempt-id>.json` is a same-directory,
temporary-file-plus-atomic-rename export derived from the committed payload. Serving
an export requires a matching PostgreSQL attempt and exact agreement on campaign ID,
attempt ID, target version, evidence hash, and serialized bytes. Missing or corrupt
files are unavailable; orphan files are never imported or rendered.

Discovery does not persist deterministic assertion summaries or authorization-result
fields. Fixed-case assertions are stored only with fixed-case evaluation records and
cannot become discovery Findings or change Judge rows.

## Findings and reports

One `exploit_confirmed` verdict creates a new Finding immediately. Its unique
fingerprint is derived from the attempt ID and evidence hash, so even identical attack
sequences in separate attempts create separate Findings. There is no reproduction
counter, semantic deduplication, finding upsert, or target-version reopening rule.

The Documentation Agent runs immediately for that Finding. If report or regression
creation fails, the Finding and evidence remain durable and the campaign ends
visibly.

The controller replaces any model-supplied report transcript with the committed
source-evidence transcript. Structured report data and rendered `markdown_body` are
committed to PostgreSQL before `reports/generated/<vulnerability-id>.md` is exported;
`markdown_path` is recorded only after a verified atomic write. `reports/generated/`
is ignored derived output. `reports/submission/` contains reviewed, Git-tracked
copies that retain source IDs and the evidence hash and may intentionally differ
editorially.

`agentforge artifacts reconcile` classifies valid, missing, corrupt, orphan, and
stale temporary evidence/Markdown files without changing them.
`agentforge artifacts regenerate-evidence` can recreate a missing JSON file from a
matching database payload and refuses to overwrite a corrupt file. The existing
`agentforge reports export` command regenerates Markdown from its PostgreSQL report.
After a database reset, surviving files are archival only.

## Regression mapping

The same runner and Judge evaluate a saved regression sequence:

| Judge / operational result | Stored regression outcome |
| --- | --- |
| `exploit_confirmed` | `vulnerability_reproduced` |
| `attack_blocked` | `secure_pass` |
| `partial_signal` or `inconclusive` | `inconclusive` |
| runner or Judge operational failure | `error` |

## Legacy migration

Migration `a812e4c97f30` maps old attempt status values as follows:

- `proposed` to `pending`;
- active execution/evaluation/documentation states to `running`;
- `cancelled` to `cancelled`;
- rejected, operational-error, and documentation-failure states to `failed`;
- semantic terminal outcomes to `completed`.

It removes stored lineage, mutation generation, fallback reason, and redundant
evidence summaries while preserving historical provenance values for audit display.
