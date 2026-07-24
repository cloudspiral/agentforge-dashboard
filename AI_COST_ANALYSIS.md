# AI Cost Analysis

Generated from durable evidence at `2026-07-24T10:20:42.740410+00:00` using assumptions schema `1.0`. One projected run means: One workload unit is one seed evaluation, ordinary discovery attempt, fuzz variant, or full two-replay regression case according to the scenario mix.

## 1. Actual development and testing spend

| Source | Unique AgentForge calls | Input tokens | Output tokens | Configured cost |
| --- | ---: | ---: | ---: | ---: |
| local-development | 3 | 11,643 | 1,046 | $0.052069 |
| production-final-2026-07-24 | 80 | 920,931 | 67,529 | $3.820690 |
| **Deduplicated total** | **83** | **932,574** | **68,575** | **$3.872759** |

Final overnight campaign spend: `$3.767034` across 17 explicitly selected campaigns.

- Provider billing reconciliation — **UNMEASURED: no project-scoped provider billing export was available.**
- Target OpenEMR model inference — **UNMEASURED: 42 target executions observed without target-provider usage.**
- Railway/Langfuse/infrastructure — **UNMEASURED: Railway, PostgreSQL, and Langfuse invoices were not available.**
- Codex subscription usage — **UNMEASURED: Codex subscription usage is outside AgentRun.**
- Developer labor — **UNMEASURED: developer labor was not time-tracked.**

### Versioned pricing inputs

Verified `2026-07-24` from [the official OpenAI API pricing page](https://developers.openai.com/api/docs/pricing).

| Model | Input / 1M | Cached input / 1M | Cache write / 1M | Output / 1M |
| --- | ---: | ---: | ---: | ---: |
| `gpt-5.6-sol` | $5.0 | $0.5 | $6.25 | $30.0 |
| `gpt-5.6-terra` | $2.5 | $0.25 | $3.125 | $15.0 |
| `gpt-5.6-luna` | $1.0 | $0.1 | $1.25 | $6.0 |

## 2. Observed unit economics

| Unit | Samples | Measured AgentForge model cost | Interpretation |
| --- | ---: | ---: | --- |
| confirmed finding iteration | 3 | $0.027037 | Agent calls linked to a confirmed observation; campaign-level Orchestrator planning remains reported separately. |
| fuzz plan | 6 | $0.020760 | Attack Generator calls in campaigns containing expanded fuzz variants. |
| fuzz variant | 2 | $0.021096 | Mean model cost stored on the completed/gated attempt. |
| ordinary discovery | 22 | $0.030026 | Mean model cost stored on the completed/gated attempt. |
| regression case two replays | 0 | UNMEASURED | Mean aggregate of durable regression results with at least two replays. |
| seed evaluation | 9 | $0.015907 | Mean model cost stored on the completed/gated attempt. |

- Database evidence payload: `596,072` bytes.
- Artifact files: `0` bytes.
- Browser time: `609.37` seconds.
- Mean target latency: `17333.88095238095238095238095` ms.
- Bounded model retry rate: `25.24%`.
- Human-review rate: `0.00%`.

## 3. Production projections at 100 / 1K / 10K / 100K runs

These projections use workload mixes and include attacker models, estimated target inference, retries/escalations, browser/API workers, PostgreSQL, artifact storage, telemetry, fixed platform floors, and human triage. They are not cost-per-token multiplied by run count.

| Scenario | Runs | Attacker models | Target models | Retries | Workers | PostgreSQL | Artifacts | Telemetry | Fixed | Human triage | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| low | 100 | $2.490000 | $0.690000 | $0.095400 | $0.024931 | $0.008382 | $0.001157 | $0.100000 | $60.000000 | $16.000000 | **$79.409869** |
| low | 1,000 | $24.900000 | $6.900000 | $0.954000 | $0.249306 | $0.083819 | $0.011567 | $1.000000 | $120.000000 | $160.000000 | **$314.098692** |
| low | 10,000 | $249.000000 | $69.000000 | $9.540000 | $2.493056 | $0.838190 | $0.115670 | $10.000000 | $650.000000 | $1600.000000 | **$2590.986916** |
| low | 100,000 | $2490.000000 | $690.000000 | $95.400000 | $24.930556 | $8.381903 | $1.156703 | $100.000000 | $4500.000000 | $16000.000000 | **$23909.869161** |
| base | 100 | $3.425000 | $1.852500 | $0.422200 | $0.087111 | $0.013970 | $0.002249 | $0.160000 | $75.000000 | $60.000000 | **$140.963030** |
| base | 1,000 | $34.250000 | $18.525000 | $4.222000 | $0.871111 | $0.139698 | $0.022491 | $1.600000 | $250.000000 | $600.000000 | **$909.630301** |
| base | 10,000 | $342.500000 | $185.250000 | $42.220000 | $8.711111 | $1.396984 | $0.224914 | $16.000000 | $1500.000000 | $6000.000000 | **$8096.303009** |
| base | 100,000 | $3425.000000 | $1852.500000 | $422.200000 | $87.111111 | $13.969839 | $2.249144 | $160.000000 | $9000.000000 | $60000.000000 | **$74963.030094** |
| high | 100 | $6.300000 | $5.932500 | $2.201850 | $0.287500 | $0.024447 | $0.005141 | $0.280000 | $120.000000 | $250.000000 | **$385.031438** |
| high | 1,000 | $63.000000 | $59.325000 | $22.018500 | $2.875000 | $0.244472 | $0.051409 | $2.800000 | $450.000000 | $2500.000000 | **$3100.314381** |
| high | 10,000 | $630.000000 | $593.250000 | $220.185000 | $28.750000 | $2.444722 | $0.514090 | $28.000000 | $3000.000000 | $25000.000000 | **$29503.143812** |
| high | 100,000 | $6300.000000 | $5932.500000 | $2201.850000 | $287.500000 | $24.447218 | $5.140901 | $280.000000 | $18000.000000 | $250000.000000 | **$283031.438118** |

### Sensitivities

- Finding yield changes Documentation calls, regression-case creation, and human triage.
- Replay multiplier changes target/model work non-linearly; a secure pass requires two valid consistent replays.
- Retention changes PostgreSQL and object-storage totals independently.
- Concurrency changes worker floors and target-aware backpressure requirements.
- Target inference is **ESTIMATED** until OpenEMR exposes provider usage and billing.

## 4. Architecture required at each scale

- **100 runs:** one worker, direct measurement, and complete evidence retention.
- **1K runs:** target-aware backpressure, prompt-cache analysis, retention jobs, and finding deduplication.
- **10K runs:** split API/browser/model worker pools, queue quotas, object storage, trace sampling, selective human review, and latency-insensitive Batch/Flex evaluation where semantics permit.
- **100K runs:** distributed scheduling, target/tenant quotas, calibrated smaller-model routing with Judge escalation, provider failover, partitioned audit tables, formal retention, and triage SLOs.

## Reproducibility and limitations

The evidence JSON contains only identifiers, usage counters, latency, and cost; it excludes prompts, outputs, credentials, and patient data. AgentRun UUIDs are deduplicated when local and production snapshots are merged. Pricing and all non-model inputs are versioned configuration. `UNMEASURED` and `ESTIMATED` labels are intentionally retained instead of presenting unsupported precision.
