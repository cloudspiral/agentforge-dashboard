# AgentForge evaluation definitions

Seed YAML files are versioned test definitions. PostgreSQL is the canonical runtime record; `evals/results/` may contain only explicitly exported, sanitized snapshots. Default automated tests use fake agents and fake targets. Live runs require `RUN_LIVE_E2E=1`, an allowlisted target profile, synthetic credentials, and a deterministic execution-gate pass.

The seed suite uses Avery (`GOLDEN-LONGITUDINAL`) as Patient A and Morgan (`GOLDEN-WORKFLOW`) as Patient B. Numeric OpenEMR PIDs are installation-specific and are resolved at runtime.

