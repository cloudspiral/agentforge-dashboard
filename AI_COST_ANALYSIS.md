# AI cost analysis

## Evidence status

No measured production or live W3 campaign token record is present in the repository, generated reports, or checked-in artifacts. The application has not been proven end to end, so this document does **not** label projections as actual spend. Once the controller persists successful `agent_runs`, the authoritative measured fields are model, input/output tokens, latency, estimated cost, campaign ID, attempt ID, and trace ID.

The checked-in catalog (`config/pricing.yaml`) was marked verified on 2026-07-21 and prices one million tokens at:

| Model | Input | Cached input | Cache write | Output |
| --- | ---: | ---: | ---: | ---: |
| GPT-5.6 Sol | $5.00 | $0.50 | $6.25 | $30.00 |
| GPT-5.6 Terra | $2.50 | $0.25 | $3.125 | $15.00 |
| GPT-5.6 Luna | $1.00 | $0.10 | $1.25 | $6.00 |

Prices and availability are configuration, not timeless facts; the catalog policy requires refresh after 30 days and rejects unknown model pricing for live calls.

## Baseline projection model

For planning, one **evaluated attempt** means one Attack Generator call and one Judge call. One Orchestrator call is amortized over a ten-attempt campaign, and 10% of attempts produce one Documentation call. This is intentionally explicit and can be replaced with measured percentiles.

| Role | Model | Assumed tokens per call | Cost per call | Calls per evaluated attempt |
| --- | --- | ---: | ---: | ---: |
| Orchestrator | Terra | 2,000 input / 400 output | $0.01100 | 0.10 |
| Attack Generator | Terra | 2,500 input / 700 output | $0.01675 | 1.00 |
| Judge | Terra | 3,500 input / 500 output | $0.01625 | 1.00 |
| Documentation | Luna | 4,000 input / 1,200 output | $0.01120 | 0.10 |

Baseline projected cost is **$0.03522 per evaluated attempt**, excluding cache discounts, Sol escalation, retries, storage, Langfuse, PostgreSQL, Railway, browser CPU, and target infrastructure. It is a capacity assumption, not a quote or measurement.

## Volume projections

| Evaluated attempts | Projected model cost | Architecture implication |
| ---: | ---: | --- |
| 100 | $3.52 | Single worker is adequate; inspect every finding and calibrate token assumptions from stored usage. |
| 1,000 | $35.22 | Batch campaigns, cap concurrency per target, add cost/latency percentiles and prompt-cache analysis. |
| 10,000 | $352.20 | Separate browser and model worker pools, queue backpressure, artifact lifecycle jobs, sampled semantic judging where deterministic checks are decisive, and daily spend alarms. |
| 100,000 | $3,522.00 | Horizontal workers with strict leases, per-tenant quotas, partitioned/archived audit data, dedicated browser capacity, rate-limit coordination, anomaly detection, and formal cost governance. |

Simple multiplication stops being sufficient at scale. Target throughput and authenticated browser capacity will likely constrain the system before raw model inference. Larger volumes also increase false-positive review burden, evidence retention, database indexing, prompt/version comparability, and provider rate-limit risk.

## Budget controls already represented

- Global and per-campaign dollar ceilings.
- Maximum attempts, duration, mutation depth, and no-signal count.
- One-turn role adapters with role-specific output caps.
- Maximum-output reservation before a call.
- Unknown-price rejection.
- Typed usage and estimated-cost records.
- Sol escalation only when deterministic checks are ambiguous and budget is reserved.
- No automatic model retry setting in checked-in routing; the adapter has bounded transport retries.

The missing campaign controller means these pieces are not yet proven as one atomic enforcement path.

## Cost-reduction order

1. Measure real token distributions and retry/escalation rates before changing prompts.
2. Keep deterministic seed selection, canary detection, and regression checks outside the model.
3. Minimize role inputs to hashes, bounded evidence, and required context; never resend whole transcripts unnecessarily.
4. Reuse stable prompt prefixes only after verifying cache billing and privacy behavior.
5. Skip semantic Judge calls when policy explicitly permits a deterministic terminal outcome; never skip them merely to make a suspicious result look secure.
6. Use Luna for documentation, Terra for routine structured roles, and Sol only for controlled escalation.
7. Deduplicate identical target-version/case replays and stop no-signal mutation chains early.

## Measurement plan

After the controller works, report p50/p95 input tokens, output tokens, latency, retries, cost per role, Sol escalation rate, documentation rate, cost per confirmed finding, cost per regression case, and abandoned reservation. Reconcile persisted totals with provider billing and Langfuse only after confirming trace completeness; telemetry must not become the billing authority.
