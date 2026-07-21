# AgentForge

AgentForge is an authorized, evidence-first security evaluation platform created for a Gauntlet AI bootcamp assignment and educational learning. Its only target is the user's own synthetic-data Clinical Co-Pilot in the related OpenEMR project; there are no real users or patient records in scope. It separates model recommendations from deterministic authorization, executes only versioned allowlisted actions, and records reproducible evidence before it can create a finding.

The implementation is under active construction. See `docs/TARGET_INTEGRATION.md` for the verified target boundary and `OVERNIGHT_SUMMARY.md` for the exact validation state.

## Safety boundary

- Use only the explicitly configured target hosts and synthetic test identities.
- Never place credentials in Git; copy `.env.example` to a private environment source when running locally.
- Agents propose and evaluate. Only the deterministic controller and runner may execute allowlisted actions.
- A generated report is not proof of a vulnerability. Confirmed live evidence and reproduction are required.
