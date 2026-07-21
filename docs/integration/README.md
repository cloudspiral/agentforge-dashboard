# Integration evidence packet

This directory records versioned boundaries between model roles, deterministic components, infrastructure, and the Clinical Co-Pilot target. It is evidence-oriented: a planned trace is not labeled as a successful trace.

| Artifact | Purpose | Current status |
| --- | --- | --- |
| `CONTRACT_INVENTORY.md` | Producer/consumer schemas and compatibility rules | Complete inventory; full wiring gap noted |
| `CONTRACT_TEST_RESULT.md` | Exact contract/schema checks and limitations | Update after every validation run |
| `DEPENDENCY_MAP.md` | Runtime/service dependency ownership and failure semantics | Documented |
| `INTERFACE_ASSUMPTIONS.md` | Explicit assumptions that must be verified | Documented with owners/risks |
| `CROSS_AGENT_TRACE.md` | One end-to-end role/evidence trace | **Unavailable until controller path works** |
| `ADR_LOG.md` | Decisions and place for future peer diffs/ADRs | Initialized |

Future integration evidence must identify W3 revision, database revision, target runtime build, config/prompt/schema hashes, campaign/attempt IDs, evidence hash, model usage, Langfuse trace ID when available, cleanup result, and exact test command. Do not paste credentials, cookies, CSRF values, raw headers, or unrelated chart data.
