# Canonical submission reports

This directory contains point-in-time exports of the latest canonical PostgreSQL
report for each current production Finding. The dashboard and PostgreSQL remain
the source of truth; lifecycle transitions and regression results create newer
canonical report versions that should be re-exported before submission.

These three exports were downloaded after production regression run
`b5d6c81f-5dad-4c4e-b509-56393a74e5a6` completed on 2026-07-24:

- [`AF-24F032E46E4A.md`](AF-24F032E46E4A.md) — tool misuse / unintended invocation
- [`AF-C29D26B2B508.md`](AF-C29D26B2B508.md) — state corruption / context poisoning
- [`AF-0F2C8E9E19D8.md`](AF-0F2C8E9E19D8.md) — prompt injection / multi-turn

Earlier report artifacts are retained in [`../historical/`](../historical/) for
provenance and are not current submission reports.
