# Cross-agent trace

## Evidence status

**No successful end-to-end cross-agent trace exists in this checkout.** The ASGI entrypoint and CLI exist, but the concrete campaign controller/processor is absent and the gate-to-runner type handoff is not closed. Creating plausible IDs, token counts, verdicts, findings, or Langfuse links would fabricate evidence.

## Trace that must be captured

Once the path works, add one redacted trace for a safe synthetic case with this exact responsibility chain:

1. Human queues a bounded campaign against an exact target alias/build.
2. Orchestrator produces a typed objective; controller records model/prompt/usage/cost.
3. Attack Generator produces `ProposedAttackV1` using symbolic endpoints/fixtures only.
4. Gate either rejects or emits a hashed authorized envelope.
5. Runner executes that exact envelope in an ephemeral session and proves Patient A context.
6. Runner returns bounded `AttackEvidenceV1` and cleanup result.
7. Deterministic evaluator records every invariant as pass/fail/unobserved.
8. Judge evaluates the frozen packet; controller reconciles and applies stopping policy.
9. If confirmed and reproduced, Documentation Agent creates a draft; human disposition remains pending.
10. PostgreSQL records link campaign, attempt, agent runs, evidence hash, verdict, finding/report, and trace ID.

## Required evidence fields

| Layer | Fields |
| --- | --- |
| Build/config | W3 revision, DB revision, target build, profile/taxonomy/rubric/pricing/prompt hashes |
| Campaign | ID, type, scope, budgets, timestamps, stop reason |
| Role call | role, model, prompt version, input/output tokens, cost, latency, typed error |
| Authorization | proposal hash, gate decision/reasons, authorized sequence hash, exact alias (not secret URL input) |
| Execution | attempt ID, action statuses, card patient assertion, correlation IDs, artifact hashes, cleanup |
| Evaluation | deterministic checks, evidence references/hash, Judge result, reconciliation |
| Persistence/report | finding fingerprint/version or no-finding reason, regression link, report status |
| Observability | redacted Langfuse trace ID if enabled and Prometheus snapshot |

## Acceptance rule

The trace is acceptable only if it can be independently followed from queued campaign to terminal state without consulting unredacted secrets, and every target action is proven to descend from the gate-authorized envelope. A component-unit demonstration or Langfuse-only screenshot is not a cross-agent trace.
