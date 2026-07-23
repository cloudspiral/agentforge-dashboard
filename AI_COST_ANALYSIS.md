# AI cost analysis

## Measured production usage

PostgreSQL `AgentRun` rows are the source for the measured values below. These are
AgentForge estimates from the checked-in pricing catalog, not provider-billing
reconciliation.

| Purpose / campaign | Role | Model | Calls | Input tokens | Output tokens | Latency | Estimated cost |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Persistence/Langfuse verification - `f7023f5e...` | Judge | `gpt-5.6-terra` | 1 | 3,850 | 334 | 3,938 ms | $0.017039 |
| AF-TM-001 - `7dee7918...` | Judge | `gpt-5.6-terra` | 1 | 4,175 | 390 | 5,604 ms | $0.018895 |
| AF-TM-002 - `9ee3d4bc...` | Judge | `gpt-5.6-terra` | 1 | 4,006 | 347 | 3,733 ms | $0.017722 |
| Browser-bound fallback - `943aab23...` | Judge | `gpt-5.6-terra` | 1 | 3,560 | 317 | 4,355 ms | $0.015878 |
| Multi-agent browser-bound run - `8eb948ce...` | Orchestrator | `gpt-5.6-terra` | 1 | 1,535 | 328 | 3,149 ms | $0.009715 |
| Multi-agent browser-bound run - `8eb948ce...` | Attack Generator | `gpt-5.6-terra` | 1 | 2,710 | 668 | 6,059 ms | $0.018487 |
| Multi-agent browser-bound run - `8eb948ce...` | Judge | `gpt-5.6-terra` | 1 | 3,520 | 337 | 5,988 ms | $0.016053 |
| **Measured total** |  |  | **7** | **23,356** | **2,721** | **32,826 ms** | **$0.113789** |

The three earlier campaigns each have one successful Judge `AgentRun`, no typed
failure, and no bounded Judge-contract retry. The two current tool evaluations cost
$0.036617 total, or $0.018309 average per completed evaluation. The static/browser
OWASP controls made no AgentForge Judge or Documentation model call.

The new full-discovery controller produced one successful, separately metered
Orchestrator → Attack Generator → Judge sequence at `$0.044255`. Its browser could not
initialize in the sandbox, so the Judge correctly returned `inconclusive` and the
Documentation Agent did not run. Ten additional zero-token, zero-cost AgentRun rows
recorded pre-provider schema failures encountered during validation; the adapter was
then fixed and tested. They are retained as operational error evidence but do not
change provider cost totals.

The historical dashboard single-case path did not call the Orchestrator, Attack
Generator, or Documentation Agent. The new measurement is therefore the first
observed three-role discovery cost, not yet a complete four-role confirmed-finding
cost. Documentation usage remains unmeasured in a live run.

Preserved Stage 3 JSON artifacts do not carry AgentRun token/cost rows, and their
original campaign IDs are not present in the current production database. Their
historical spend is not added to the measured total.

## Pricing inputs

The checked-in `config/pricing.yaml` catalog was marked verified on 2026-07-21:

| Model | Input / 1M | Cached input / 1M | Cache write / 1M | Output / 1M |
| --- | ---: | ---: | ---: | ---: |
| GPT-5.6 Sol | $5.00 | $0.50 | $6.25 | $30.00 |
| GPT-5.6 Terra | $2.50 | $0.25 | $3.125 | $15.00 |
| GPT-5.6 Luna | $1.00 | $0.10 | $1.25 | $6.00 |

Prices are versioned configuration, not a timeless quote. Unknown models fail pricing
validation.

## Full-attempt planning model

The planning unit is one evaluated target attempt. The model-cost baseline is now
`$0.050000`: the observed `$0.044255` Orchestrator/Attack Generator/Judge run rounded
up by `$0.005745` for amortized Documentation use and ordinary token variance. This is
a deliberately conservative planning assumption until a successful live
Documentation Agent call is measured. The controller still reserves worst-case role
usage before starting; this expected-cost model is only for capacity planning.

| Cost driver | Expected cost per evaluated attempt | Explicit assumption |
| --- | ---: | --- |
| Model inference | $0.050000 | Observed three-role discovery cost plus an explicit Documentation/variance allowance |
| Bounded model retries | $0.002500 | 5% uplift; production evidence must replace this with measured typed retries |
| Browser and target compute | $0.003000 | 90 seconds of roughly two effective vCPUs at an assumed $0.06/vCPU-hour, including memory overhead |
| PostgreSQL and artifact retention | $0.000150 | Approximately 200 KB retained for 90 days at an assumed $0.25/GB-month; excludes database minimum charge |
| Trace/metrics ingestion | $0.000400 | Four role/runner trace groups at an assumed $0.0001 each |
| Human security triage | $0.600000 | 2% of attempts reviewed for 15 minutes at $120/hour |
| **Expected variable total** | **$0.656050** | Human review dominates; deduplication and confidence routing are economic controls |

A separate $60/month fixed placeholder covers a small application service,
PostgreSQL minimum, backups, and observability minimums. It is an assumption, not a
Railway or Langfuse invoice. Target-system infrastructure, taxes, discounts, support,
egress, incident response, remediation engineering, and provider price changes remain
excluded.

## 100 / 1K / 10K / 100K projection

| Evaluated attempts | Models | Retry reserve | Browser compute | DB/storage | Telemetry | Human triage | Fixed platform | Planning total |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | $5.00 | $0.25 | $0.30 | $0.02 | $0.04 | $60.00 | $60.00 | **$125.61** |
| 1,000 | $50.00 | $2.50 | $3.00 | $0.15 | $0.40 | $600.00 | $60.00 | **$716.05** |
| 10,000 | $500.00 | $25.00 | $30.00 | $1.50 | $4.00 | $6,000.00 | $60.00 | **$6,620.50** |
| 100,000 | $5,000.00 | $250.00 | $300.00 | $15.00 | $40.00 | $60,000.00 | $60.00 | **$65,665.00** |

These totals are deliberately not `token price x runs`. They include retries,
headless-browser work, retained evidence, telemetry, a fixed platform floor, and
human disposition. They also show why simply scaling the current process is
unacceptable: the reviewer queue, not tokens, becomes the dominant cost.

## Architecture changes by scale

- **100 attempts:** one worker is adequate. Measure p50/p95 usage by role, browser
  latency, retry reason, stored bytes, and reviewer minutes before changing the
  architecture.
- **1,000 attempts:** add target-aware backpressure, alerting on budget and queue
  depth, prompt caching analysis, finding fingerprint review, and storage retention
  jobs. Separate fixed-case runs from exploratory discovery in cost reports.
- **10,000 attempts:** split API and worker processes, enforce per-target concurrency,
  batch deterministic checks, tier artifacts to object storage, sample successful
  traces, and route only confirmed/high-confidence or novel findings to humans.
- **100,000 attempts:** require a scheduler with tenant/target quotas, distributed
  workers, provider failover, calibrated smaller-model routing, aggressive semantic
  deduplication, formal retention/deletion policy, and a staffed triage SLO. A 2%
  manual-review rate is still too expensive; regression-safe automation must reduce
  it without allowing uncertain evidence to become a pass.

## Reconciliation gaps

No provider billing API or invoice was reconciled. Browser CPU/memory, database bytes,
telemetry units, and human review time are not yet metered per attempt. Until those
channels are instrumented, the production numbers above must be read as measured
model use plus an explicit planning model, not an audited total cost of ownership.
