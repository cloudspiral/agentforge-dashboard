# Load and capacity test record

## Result

An **offline deterministic microbenchmark** ran on 2026-07-21 with:

```bash
uv run python scripts/load_test.py --operations 100 --max-seconds 30
```

It completed 100/100 operations in 0.008074 seconds (12,385.435 operations/second), with latency p50 0.073354 ms, p95 0.110481 ms, maximum 0.233542 ms, and peak Python allocation 48,824 bytes. It made **zero target requests, zero model calls, zero database writes, and cost $0**.

The measured path is only v1 contract validation, deterministic invariant evaluation, and result serialization. It does not measure API, queue, worker, controller, PostgreSQL, HTTP/Playwright, target, or model performance. The concrete controller and an authorized end-to-end campaign path remain unavailable, so this is not a platform load test and must not be extrapolated to production throughput.

## Required full-platform benchmark

Run 100 deterministic fake-platform operations through the real API, queue, worker, controller, persistence, report, and metrics path with model and target adapters replaced by latency-controlled fakes. This measures AgentForge orchestration without spending tokens or touching OpenEMR. Then run a much smaller, separately approved live sample only to characterize target/browser latency.

### Workload mix

- 10 campaign creations with distinct idempotency keys.
- 70 fake evaluated attempts across all six taxonomy categories.
- 10 gate rejections (wrong host, prohibited route, wrong patient, excessive bounds).
- 5 deterministic confirmed findings plus canonical initial reports.
- 5 regression replays covering secure pass, reproduced, inconclusive, and error.
- Concurrent read traffic for overview, campaign detail, findings, coverage, and agent-run audit.

No live-model or target credential should be required. Fixed seeds, fake token usage, known costs, and injected error cases make results reproducible.

## Metrics to record

| Layer | Required measurements |
| --- | --- |
| API/orchestration | throughput, p50/p95/p99 queue-to-start and total latency, error/timeout rate, idempotency conflicts |
| Worker/queue | claim latency, queue depth/oldest age, active workers, heartbeat delay, stale recovery, retries |
| Model adapter | calls/role, fake or real input/output tokens, reservation, cost, latency, retry/escalation rate |
| Target/runner | HTTP versus browser latency, redirect/rejection count, session setup, action count, cleanup failures |
| PostgreSQL | transactions/sec, query p95, lock waits, pool saturation, rows/table, storage growth |
| Host/container | CPU, RSS, file descriptors, network, artifact bytes, browser processes |
| Correctness | lost/duplicate attempts, illegal state transitions, hash drift, evidence/report linkage, budget overshoot |

## Procedure

1. Pin the W3 revision, Python/lockfile, database revision, Compose image digests, fake-adapter seed, and host resources.
2. Start a clean migrated test database and record baseline row counts/storage.
3. Warm the application without counting warm-up.
4. Execute one sequential 100-operation run, then controlled concurrency of 2, 5, and 10.
5. Inject one worker termination, one stale heartbeat, one telemetry outage, and deterministic adapter timeouts.
6. Verify every operation has exactly one terminal state, expected cost, and trace/evidence linkage.
7. Repeat three times; report median and worst run, not only the best.
8. Tear down and verify no target requests or persistent browser states occurred.

## Acceptance thresholds to approve before execution

Thresholds must be selected by the owner from clinical/test needs. A reasonable initial fake-path proposal is zero lost/duplicate operations, zero unauthorized runner calls, zero secure passes after injected failures, no budget overshoot, p95 queue-to-terminal under five seconds at concurrency five, and clean stale-worker recovery within the configured 120-second lease. These are proposals, not measured results.

## Small authorized live characterization

Only after fake-load acceptance, execute at most five status operations and two normal UI conversations against the selected synthetic local alias, serially, with exact target build and owner approval. Do not load-test the shared Railway deployment. Record browser/session setup, Co-Pilot response time, evidence capture, and cleanup separately; stop on version drift, login failure, 429/5xx, unexpected patient state, or cleanup uncertainty.

## Scaling hypotheses

Browser session startup will likely dominate CPU/memory; target inference will likely dominate end-to-end latency; model calls and human triage will dominate variable cost; PostgreSQL queue contention may emerge with many workers; artifacts may dominate storage. These are hypotheses to test, not findings. At 10K+ attempts, separate browser/model worker pools, apply target-specific concurrency limits and queue backpressure, archive evidence, and partition high-growth audit tables.

## Evidence template

Record date/operator, revision/image/database IDs, environment, command, workload seed, resource limits, all metric summaries, raw artifact path/hash, bottleneck, errors, correctness checks, cost, comparison to threshold, and go/no-go decision. Attach graphs only when backed by saved raw measurements.
