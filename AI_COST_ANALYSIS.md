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
| Historical browser-bound fixed run - `943aab23...` | Judge | `gpt-5.6-terra` | 1 | 3,560 | 317 | 4,355 ms | $0.015878 |
| Multi-agent browser-bound run - `8eb948ce...` | Orchestrator | `gpt-5.6-terra` | 1 | 1,535 | 328 | 3,149 ms | $0.009715 |
| Multi-agent browser-bound run - `8eb948ce...` | Attack Generator | `gpt-5.6-terra` | 1 | 2,710 | 668 | 6,059 ms | $0.018487 |
| Multi-agent browser-bound run - `8eb948ce...` | Judge | `gpt-5.6-terra` | 1 | 3,520 | 337 | 5,988 ms | $0.016053 |
| Host-Chrome discovery retry - `71386c97...` | Orchestrator | `gpt-5.6-terra` | 1 | 1,532 | 361 | 5,189 ms | $0.010201 |
| Host-Chrome discovery retry - `71386c97...` | Attack Generator | `gpt-5.6-terra` | 1 | 2,708 | 654 | 6,683 ms | $0.018271 |
| Host-Chrome discovery retry - `71386c97...` | Judge | `gpt-5.6-terra` | 1 | 3,844 | 649 | 7,448 ms | $0.021746 |
| **Measured total** |  |  | **10** | **31,440** | **4,385** | **52,146 ms** | **$0.164007** |

## Measured post-refactor local live usage

The isolated feature-branch PostgreSQL database recorded six campaigns after the
final controller repair. They executed 24 attempts through the deployed synthetic
target: 16 `attack_blocked`, five `inconclusive`, two `partial_signal`, and one
`exploit_confirmed`. These are local controller measurements, not provider-invoice
reconciliation and not evidence that the feature branch was deployed.

| Role | Calls | Input tokens | Output tokens | Estimated cost |
| --- | ---: | ---: | ---: | ---: |
| Orchestrator | 25 | 26,422 | 3,031 | $0.121893 |
| Attack Generator | 24 | 71,814 | 15,676 | $0.362124 |
| Judge | 24 | 73,861 | 5,764 | $0.317231 |
| Documentation Agent | 1 | 4,796 | 1,020 | $0.012114 |
| **Feature-branch total** | **74** | **176,893** | **25,491** | **$0.813362** |

The one complete confirmed-finding iteration cost `$0.051364`: Orchestrator
`$0.007331`, Attack Generator `$0.015271`, Judge `$0.016648`, and Documentation
`$0.012114`. It immediately created the report and regression case, then returned to
discovery. One additional Orchestrator call selected `stop` without an attack, which
is why Orchestrator calls exceed executed attempts.

The three earlier campaigns each have one successful Judge `AgentRun`, no typed
failure, and no bounded Judge-contract retry. The two current tool evaluations cost
$0.036617 total, or $0.018309 average per completed evaluation. The static/browser
OWASP controls made no AgentForge Judge or Documentation model call.

The pre-refactor full-discovery controller produced two successful, separately metered
Orchestrator → Attack Generator → Judge sequences at `$0.044255` and `$0.050217`
campaign cost. The first could not initialize Chrome in the restricted sandbox. The
second used host Chrome, completed login and bounded target execution, and produced
complete read-only evidence. Its Judge returned a 0.94-confidence semantic
`exploit_confirmed` verdict, but the retired controller required reproduction before
finding/report promotion. The Documentation Agent therefore did not run in that
historical trace. The simplified controller now promotes one confirmed attempt
immediately; this behavior is PostgreSQL-integration-tested but has not yet produced a
new live Documentation Agent measurement. Ten
additional zero-token, zero-cost AgentRun rows recorded pre-provider schema failures
encountered during validation; the adapter was then fixed and tested. They are
retained as operational error evidence but do not change provider cost totals.

The historical dashboard single-case path did not call the Orchestrator, Attack
Generator, or Documentation Agent. The post-refactor measurements now include one
complete four-role confirmed-finding cost. More than one Documentation sample is
still needed before treating `$0.012114` as a stable role average.

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

The planning unit is one evaluated target attempt. The model-cost baseline remains
`$0.060000`: it is above the observed `$0.051364` four-role confirmed-finding
iteration and leaves room for ordinary token variance. One report call is not enough
to recalibrate the planning model. The controller enforces the configured campaign
ceiling before continuing; this expected-cost model is only for capacity planning.

| Cost driver | Expected cost per evaluated attempt | Explicit assumption |
| --- | ---: | --- |
| Model inference | $0.060000 | Rounded above the observed four-role confirmed-finding iteration |
| Bounded model retries | $0.003000 | 5% uplift; production evidence must replace this with measured typed retries |
| Browser and target compute | $0.003000 | 90 seconds of roughly two effective vCPUs at an assumed $0.06/vCPU-hour, including memory overhead |
| PostgreSQL and artifact retention | $0.000150 | Approximately 200 KB retained for 90 days at an assumed $0.25/GB-month; excludes database minimum charge |
| Trace/metrics ingestion | $0.000400 | Four role/runner trace groups at an assumed $0.0001 each |
| Human security triage | $0.600000 | 2% of attempts reviewed for 15 minutes at $120/hour |
| **Expected variable total** | **$0.666550** | Human review dominates; triage sampling and aggregate reporting are economic controls |

A separate $60/month fixed placeholder covers a small application service,
PostgreSQL minimum, backups, and observability minimums. It is an assumption, not a
Railway or Langfuse invoice. Target-system infrastructure, taxes, discounts, support,
egress, incident response, remediation engineering, and provider price changes remain
excluded.

## 100 / 1K / 10K / 100K projection

| Evaluated attempts | Models | Retry reserve | Browser compute | DB/storage | Telemetry | Human triage | Fixed platform | Planning total |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | $6.00 | $0.30 | $0.30 | $0.02 | $0.04 | $60.00 | $60.00 | **$126.66** |
| 1,000 | $60.00 | $3.00 | $3.00 | $0.15 | $0.40 | $600.00 | $60.00 | **$726.55** |
| 10,000 | $600.00 | $30.00 | $30.00 | $1.50 | $4.00 | $6,000.00 | $60.00 | **$6,725.50** |
| 100,000 | $6,000.00 | $300.00 | $300.00 | $15.00 | $40.00 | $60,000.00 | $60.00 | **$66,715.00** |

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
  batch fixed-case checks, tier artifacts to object storage, sample successful
  traces, and route only confirmed/high-confidence or novel findings to humans.
- **100,000 attempts:** require a scheduler with tenant/target quotas, distributed
  workers, provider failover, calibrated smaller-model routing, aggregate related
  one-attempt Findings for triage without merging their audit records, formal
  retention/deletion policy, and a staffed triage SLO. A 2%
  manual-review rate is still too expensive; regression-safe automation must reduce
  it without allowing uncertain evidence to become a pass.

## Reconciliation gaps

No provider billing API or invoice was reconciled. Browser CPU/memory, database bytes,
telemetry units, and human review time are not yet metered per attempt. Until those
channels are instrumented, the production numbers above must be read as measured
model use plus an explicit planning model, not an audited total cost of ownership.
