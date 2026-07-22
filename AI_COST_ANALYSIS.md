# AI cost analysis

## Measured production usage

PostgreSQL `AgentRun` rows are the source for the measured values below. These are AgentForge estimates from the checked-in pricing catalog, not provider-billing reconciliation.

| Purpose / campaign | Role | Model | Calls | Input tokens | Output tokens | Latency | Estimated cost |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Persistence/Langfuse verification — `f7023f5e…` | Judge | `gpt-5.6-terra` | 1 | 3,850 | 334 | 3,938 ms | $0.017039 |
| AF-TM-001 — `7dee7918…` | Judge | `gpt-5.6-terra` | 1 | 4,175 | 390 | 5,604 ms | $0.018895 |
| AF-TM-002 — `9ee3d4bc…` | Judge | `gpt-5.6-terra` | 1 | 4,006 | 347 | 3,733 ms | $0.017722 |
| **Measured final-hardening total** |  |  | **3** | **12,031** | **1,071** | **13,275 ms** | **$0.053656** |

Each campaign has one Judge `AgentRun`, no typed failure, and therefore no bounded Judge-contract retry. The two required current tool evaluations cost $0.036617 total, or $0.018309 average per completed evaluation. The static/browser OWASP controls made no AgentForge Judge or Documentation model call.

The Documentation Agent was **NOT RUN**. The confirmed AF-TM-001 result came through the process-local dashboard evaluation manager, which persists an attempt and Judge verdict but does not enter the controller's finding/report workflow. The checked-in report is human-authored from typed evidence; Documentation Agent tokens, latency, retries, and cost are all zero rather than estimated.

Preserved Stage 3 JSON artifacts do not carry AgentRun token/cost rows, and their original campaign IDs are not present in the current production database. Their historical spend is therefore not added to the measured total.

## Pricing inputs

The checked-in `config/pricing.yaml` catalog was marked verified on 2026-07-21:

| Model | Input / 1M | Cached input / 1M | Cache write / 1M | Output / 1M |
| --- | ---: | ---: | ---: | ---: |
| GPT-5.6 Sol | $5.00 | $0.50 | $6.25 | $30.00 |
| GPT-5.6 Terra | $2.50 | $0.25 | $3.125 | $15.00 |
| GPT-5.6 Luna | $1.00 | $0.10 | $1.25 | $6.00 |

Prices are configuration, not a timeless quote. Unknown models fail pricing validation.

## Planning assumptions and projections

For capacity planning only, assume one evaluated attempt uses the earlier explicit baseline of $0.03522: one Attack Generator call, one Judge call, 0.1 amortized Orchestrator calls, and 0.1 Documentation calls. The current fixed dashboard seeds are cheaper because they do not call the Orchestrator or Attack Generator.

| Evaluated attempts | Assumed model cost | Interpretation |
| ---: | ---: | --- |
| 100 | $3.52 | Single-worker validation scale; calibrate against more persisted role data |
| 1,000 | $35.22 | Add budget percentiles, caching analysis, and target backpressure |
| 10,000 | $352.20 | Separate worker capacity only after measured need |
| 100,000 | $3,522.00 | Requires formal quotas, retention, rate-limit, and review governance |

These projections exclude Railway, PostgreSQL, Langfuse, browser CPU, target infrastructure, taxes, discounts, cache effects, retries, and provider price changes. No provider invoice or billing API was reconciled.
