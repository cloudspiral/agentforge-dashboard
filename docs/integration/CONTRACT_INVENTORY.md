# Contract inventory

## Exported v1 JSON schemas

| Schema | Producer | Consumer | Execution authority |
| --- | --- | --- | --- |
| `campaign-objective.schema.json` | Orchestrator Agent | Deterministic controller | None; recommendation only |
| `proposed-attack.schema.json` | Attack Generator | Execution gate | None; cannot be sent directly to target |
| `attack-evidence.schema.json` | Runner | Deterministic evaluator, Judge, persistence | Evidence only |
| `judge-verdict.schema.json` | Judge/reconciliation | Controller, finding workflow | No state-change authority by itself |
| `documentation-request.schema.json` | Controller | Documentation Agent | Frozen report input only |
| `vulnerability-report.schema.json` | Documentation Agent | Validator, persistence, renderer | Draft only; no publication authority |
| `agent-error.schema.json` | Any model adapter | Controller/audit store | Typed failure; never coerced to success |

Internal v1 contracts additionally define action discriminators, evidence items, token usage, OWASP mappings, budgets, report sections, errors, and validation outcomes. Strict Pydantic models forbid unknown fields and constrain lengths, enums, IDs, and action-specific fields.

## Deterministic boundary types

The gate consumes `ProposedAttackV1` plus controller-owned `ExecutionAuthorizationV1`, endpoint/fixture bindings, patient context, and limits. It returns `ValidatedAttackV1` or `GateRejectionV1`. `ValidatedAttackV1` embeds the proposal, hashes the authorized sequence and profile, and carries exact resolved authorization data.

Current incompatibility: `AttackRunner.execute` accepts `ProposedAttackV1`, not `ValidatedAttackV1` or a derived immutable authorized envelope. A caller could therefore bypass the gate at the type boundary. No controller currently bridges these types. Live execution must remain disabled until the runner consumes only gate-authorized input and tests prove direct proposals cannot execute.

## Compatibility rules

- `schema_version` is mandatory and currently `v1`.
- Producers and consumers validate independently; model output is never trusted because it is structured.
- Extra fields, arbitrary URLs, secrets, raw credentials, and unknown action variants reject.
- Schema changes update Python contracts, exported JSON, tests, prompts, and this inventory together.
- Backward-incompatible changes require a new schema version and explicit migration/adapter.
- Evidence and reports retain prompt/profile/taxonomy/rubric/target versions and hashes.
- A contract test proves shape, not semantic safety or successful execution.
