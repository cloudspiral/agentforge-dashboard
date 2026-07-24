# AgentForge data model

PostgreSQL is the canonical operational and audit store. JSON and Markdown files are
portable exports; they do not replace database records.

## Core records

| Table | Purpose and important fields | Cardinality / rule |
| --- | --- | --- |
| `campaigns` | Target, taxonomy scope, `max_attempts`, maximum cost, duration, priority, state, cancellation, idempotency | One campaign has many attempts and AgentRuns |
| `campaign_events` | Timestamped mechanical lifecycle events | Append-only history |
| `attack_attempts` | Lifecycle `state`, optional structured failure, parent attempt, trusted provenance, sequence hash, objective, proposed/executed sequence, target/profile/prompt/taxonomy versions, raw evidence, evidence hash, usage/cost/latency/trace | Many per campaign across seed, discovery, fuzz, and regression lanes; `target_executed` distinguishes target contact |
| `judge_verdicts` | Verdict, confidence, severity, exploitability, violated invariants, observed/expected behavior, rubric version/hash | Zero or one per executed attempt |
| `agent_runs` | Role, model, prompt version, input/output metadata, usage, cost, latency, trace ID, typed failure | Persists successful and rejected/invalid role calls |
| `findings` | Semantic fingerprint, finding key, source attempt, first/last target version, severity, human lifecycle, rediscovery count, current regression case | Exactly one per semantic fingerprint |
| `finding_observations` | Finding/attempt link, target version, provenance, evidence hash, exact Judge verdict, observation kind | One immutable observation per promoted attempt |
| `finding_lifecycle_events` | Actor, transition, reason, evidence reference, timestamp, details | Append-only human and regression audit history |
| `vulnerability_reports` | Versioned structured report, controller-anchored exact transcript, canonical Markdown body, validation summary | Many immutable versions per Finding; unique by Finding and report version |
| `regression_cases` | Versioned saved sequence, target requirements, original Judge context, expected secure behavior, taxonomy metadata, source evidence hash | Versioned per Finding; one current active case is referenced by the Finding |
| `regression_runs` | Cohort, current/previous target version, trigger, state, aggregate outcomes, cost | One run contains many case results |
| `regression_results` / `regression_replays` | Per-case aggregate plus each replay's target version, evidence, Judge verdict/error, cost, latency, and trace | Many results per run; multiple replay records may support one conservative result |

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
cannot themselves create or suppress Findings or change Judge rows. Raw seed evidence
receives an independent Judge verdict, and a Judge-confirmed seed uses the same
promotion service as discovery.

## Findings and reports

Every `exploit_confirmed` verdict enters promotion immediately, without a reproduction
gate. The semantic fingerprint is derived from the Judge finding key, taxonomy scope,
and sorted violated invariants. A new fingerprint creates one pending-review Finding
and its first immutable observation. Rediscovery upserts no new Finding: it appends a
new attempt-bound observation, increments `rediscovery_count`, and updates
`last_seen_target_version`. Regression reproduction can reopen a resolved or
false-positive Finding through an audited lifecycle event.

The Documentation Agent runs for a new Finding, after which the controller creates
its initial regression case. Human lifecycle changes and regression validation create
new deterministic report versions. If initial report or regression creation fails,
the Finding and evidence remain durable and the campaign ends visibly.

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
