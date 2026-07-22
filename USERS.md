# AgentForge users and operating workflows

AgentForge is for authorized testing of the owner's synthetic Clinical Co-Pilot. It is not a general-purpose scanner, a penetration-testing service, a clinical decision-maker, or a tool for real patient data.

## AppSec engineer

The AppSec engineer defines taxonomy coverage, reviews target-profile changes, starts bounded discovery or regression campaigns, monitors queue/cost/evidence, validates deterministic signals, and triages draft findings. Their normal workflow is:

1. Confirm the target alias, runtime build, synthetic patients, reset/rejection path, and cost ceiling.
2. Start a narrow category/subcategory campaign through the token-protected API.
3. Inspect the exact executed sequence, evidence hash, deterministic checks, Judge result, and trace correlation.
4. Reproduce a suspected vulnerability before promoting it to a finding.
5. Convert a confirmed finding into a versioned regression case.
6. Export a report only after human review.

The engineer must stop when patient context, target version, cleanup, or evidence provenance is uncertain. They must never widen the host allowlist merely to make a run succeed.

## Clinical platform engineer

The platform engineer owns the Clinical Co-Pilot behavior and remediation. They review expected versus observed behavior, correlation IDs, affected target build, clinical impact, and the exact regression case. They fix the target in the W1 repository, deploy through its normal process, and ask AgentForge to replay the saved case against an exact new build. They do not edit an old finding to make a new response appear secure; the invariant-based replay result is append-only evidence.

Human clinical judgment remains required for claims about unsafe advice, ambiguous wording, or workflow impact. AgentForge can identify signals and organize evidence; it cannot determine standard of care.

## Security lead, CISO, or authorization reviewer

This reviewer consumes coverage, severity/status, cost, residual-risk, dependency, and evidence summaries. They approve scope, credentials handling, retention, any future persistent action, and external disclosure. They should expect every material claim to link to a target version, attempt, evidence hash, reproduction, and human disposition. A dashboard count or model confidence score alone is not assurance.

## Operator or SRE

The operator configures secrets outside Git, runs PostgreSQL migrations, controls API/worker deployment, protects the public surface, monitors queue health and costs, and executes incident recovery. Langfuse is diagnostic only; PostgreSQL and artifact retention are the operational authority. Production dashboard reads and actions require deployment authentication; health and readiness remain intentionally public and contain no evidence.

## Developer or evaluator

Developers use fake runners, synthetic contracts, and deterministic fixtures by default. Live E2E must remain opt-in (`RUN_LIVE_E2E=1`) and may target only an explicitly authorized alias. Contract schema drift, gate behavior, failure semantics, and regression invariants are first-class tests.

## Why bounded autonomy helps

Models can explore natural-language variations and summarize complex evidence faster than a fixed payload list. AgentForge confines that flexibility to typed proposals and drafts. Deterministic code owns execution and lifecycle state, while people own authorization, high-impact judgment, remediation acceptance, and publication. This division makes useful autonomous exploration possible without delegating security authority to a stochastic model.

## Human-only decisions

- authorize a target, identity, time window, and acceptable test risk;
- provide and rotate credentials and API keys;
- enable any persistent or destructive action (disabled in the current profile);
- decide whether ambiguous clinical output constitutes a vulnerability;
- accept, defer, suppress, or reopen a finding;
- approve remediation and residual risk;
- publish or disclose a report.

## Current limitations

The repository provides both the controller/worker lifecycle and a serialized dashboard single-case execution path. The latter is the proven deployed path for the current result exports; it persists attempts and Judge runs but does not create controller findings or invoke the Documentation Agent. Current evidence confirms one live excessive-agency weakness, not a comprehensive vulnerability scan. Authentication/logging and model-provenance coverage remain partial, affected dependency versions require triage, and target-visible evidence must be treated as inconclusive whenever a required channel cannot be inspected.
