# Architecture decision and peer-integration log

## Recorded decisions

| ID | Decision | Status | Rationale |
| --- | --- | --- | --- |
| ADR-001 | Agents propose/evaluate/document; deterministic code executes and changes state | Accepted | Prevent stochastic output from becoming authority |
| ADR-002 | Hub-and-spoke controller, no direct agent-to-agent handoffs | Accepted | Minimal inputs, auditable state transitions, consistent budgets |
| ADR-003 | PostgreSQL is authoritative; Langfuse is optional redacted telemetry | Accepted | Evidence survives telemetry loss and remains transactionally linked |
| ADR-004 | HTTP runner is status-only; Playwright handles normal authenticated UI | Accepted | Avoid bypassing OpenEMR session/patient/CSRF boundaries |
| ADR-005 | Persistent ingestion confirmation is prohibited by default | Accepted | Prevent chart mutation and cleanup uncertainty |
| ADR-006 | Plain Python controller before LangGraph adoption | Accepted, review trigger documented | Keep safety state machine explicit until complexity justifies runtime change |

## Required future decisions

- ADR for the authorized gate-to-runner envelope and serialization boundary.
- ADR for authentication/authorization of all read and dashboard routes.
- ADR for artifact storage, encryption, retention, and deletion.
- ADR for worker concurrency, target rate limits, and lease recovery.
- ADR for Railway/private networking versus another deployment platform.
- ADR for importing garak/PyRIT/ZAP/Semgrep evidence without conflating tool output and confirmed findings.

## Peer diff template

For each future peer integration, record contributor/system, branch/revision, files and schemas changed, compatibility impact, security assumptions, migrations, test commands/results, deployment state, rollback, unresolved questions, and reviewer. Attach diffs or links; never paste secrets.
