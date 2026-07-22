# AgentForge trust boundaries

## Purpose and status

This document identifies where data and authority cross between W3 AgentForge, external providers, and the separately operated Clinical Co-Pilot target. It describes the required boundary behavior; it does not assert that a complete live W3 campaign has executed. The checked-in default keeps `RUN_LIVE_E2E=0`.

The target facts are grounded in the read-only 2026-07-21 integration inventory in `TARGET_INTEGRATION.md`. The current target is synthetic-only. Its local running sidecar was observed at a different revision from the W1 checkout, so runtime `build_sha`, profile version, and profile hash must travel with campaign evidence rather than being inferred from source control.

## Trust and data classes

| Class | Examples | Handling rule |
| --- | --- | --- |
| Authority-bearing secret | W3 API token, deployment webhook secret, OpenAI key, Langfuse secret key, OpenEMR test password | Environment/secret store only; never model input, telemetry, report, screenshot, browser storage file, or Git |
| Ephemeral target secret | Session cookies, CSRF value, sidecar shared secret | Keep in process memory and the normal target session only; redact from logs/evidence; never call the sidecar directly |
| Synthetic clinical evidence | Patient A/B chart facts, canaries, assistant text, citations, upload review | Still sensitive; minimize, access-control, retain only when needed to prove an invariant |
| Control metadata | Campaign/attempt ID, target alias/version, taxonomy/profile/prompt versions, sequence/evidence hashes | Persist locally and propagate in bounded telemetry; contains no authority by itself |
| Untrusted content | API text fields, model outputs, chat text, document text, target response text, semantic verdicts | Validate shape and scope; never interpret as identity, endpoint, file, patient, tool, or publication authority |
| Local evidence artifact | Screenshot, Playwright trace, generated Markdown report | Repository-relative bounded path; private storage; draft until human review |

“Synthetic” does not mean “safe to publish.” Synthetic records and test canaries can expose evaluation design, target internals, or unreleased findings.

## Authority chain

Authority narrows as it moves through the system:

1. A human or deployment system authenticates to a specific W3 mutation endpoint.
2. The API validates the request against checked-in aliases, taxonomy, and configured campaign ceilings, then records queued work in PostgreSQL.
3. The worker claims one durable campaign and delegates to a campaign processor. Claiming work does not authorize a model or target action.
4. Model roles receive bounded inputs and return strict contracts. They cannot contact the target or mutate campaign state directly.
5. The deterministic execution gate either returns a typed rejection or a `ValidatedAttackV1` containing exact patient, endpoint, fixture, sequence, profile, expiry, and budget bindings.
6. The controller-to-runner integration must preserve those bindings without substituting raw proposal values. This handoff is a critical boundary that requires end-to-end verification before live mode.
7. The runner resolves aliases, creates an ephemeral session, and performs only the authorized operation.
8. OpenEMR independently authenticates and authorizes every patient-scoped request. AgentForge cannot confer OpenEMR authority.
9. Deterministic evaluation runs before semantic judgment; proven invariant violations cannot be downgraded.
10. Documentation produces an internal draft. Only a human may decide to disclose or publish externally.

## Boundary 1: human or deployment caller to W3 API

### What crosses

- Campaign creation/cancellation, regression trigger, finding status update, or local report export.
- A bearer token for operator mutations, or a distinct webhook secret for target-deployment hooks.
- Non-authoritative target alias, category, limits, deployment ID, and target-version claims.

### Enforcement

- Mutation routes compare secrets in constant time and reject missing configuration or credentials.
- Campaign service accepts only checked-in `local`/`deployed` aliases, known taxonomy scope, and costs no higher than configured global/campaign ceilings.
- Deployment webhook work receives an idempotency key derived from deployment ID and version.
- Request text cannot directly define a URL, credential, patient, endpoint path, fixture path, or runner operation.

### Current exposure

The deployed server-rendered dashboard and protected read/action surfaces require
deployment authentication; an unauthenticated dashboard-root request returned `401`.
Health and readiness are public and contain only bounded status. Local Compose remains
loopback-bound by default. Reports and finding details still contain security-sensitive
synthetic evidence, so authentication does not replace least privilege, retention,
secret rotation, or per-user authorization review.

## Boundary 2: API/worker to PostgreSQL

### What crosses

Queue status, budgets, attempts, executed/evidence summaries, verdicts, findings, regression records, agent-run metadata, and report drafts are persisted. PostgreSQL is the durable system of record; Langfuse is not.

### Enforcement

- Repository operations and database constraints provide IDs, unique fingerprints/idempotency keys, and relationships.
- Worker claims, heartbeats, completion status, and stale-work recovery distinguish queued, running, interrupted, and failed work.
- Evidence hashes bind canonical evidence content, but a hash does not prove that capture was complete or true.
- Database credentials grant storage access only; they must not be reused as target or provider credentials.

The current schema does not by itself define a retention/deletion schedule. Deployment owners must set backup, access, and retention policy for evidence, artifacts, reports, and synthetic canaries before accumulating live results.

### Failure rule

If persistence fails after a target operation, do not blindly replay. First determine whether the operation was read-only or whether a staged upload may still exist. Reconcile cleanup and durable state before allowing another attempt.

## Boundary 3: W3 orchestration to external OpenAI models

### What crosses

Only the minimum role-specific structured input should cross: bounded objective/profile subset for orchestration, approved seed/prior summaries for attack generation, sanitized evidence and fixed rubric for judging, and a frozen confirmed-finding/evidence package for documentation.

### What never crosses

Credentials, cookies, CSRF values, raw authorization headers, browser storage, arbitrary database records, real PHI, unrelated chart content, unrestricted file contents, or authority-bearing URLs.

### Enforcement

- Each role has a versioned strict input/output contract and a prompt that denies direct execution or publication authority.
- Worst-case model usage is reserved against checked-in pricing before a call; an unknown model is a fail-closed condition.
- Invalid schema, refusal, timeout, or provider failure becomes a typed error. It is not repaired by weakening safeguards or granting a different model more target authority.
- Model output remains untrusted even when schema-valid. The execution gate, deterministic evaluator, report validators, and human reviewer make separate decisions.

OpenAI remains an external processor with its own availability and data-handling risk. Environment settings request hidden model/tool payloads in tracing, but minimization must happen before the call rather than relying on exporter flags alone.

## Boundary 4: deterministic gate to target runner

This is the highest-risk W3 internal boundary because untrusted recommendations become possible network/browser actions here.

The gate checks:

- active campaign window, cancellation, cleanup success, exact category/subcategory, and repetition bounds;
- required reset/authenticate/select prefix and one final evidence collection;
- exact synthetic identity, role, patient alias, and current profile;
- origin-relative endpoint bindings whose method, surface, path, and purpose match the profile;
- rejection of arbitrary authority parameters, prohibited persistence routes, and GET bodies;
- repository-relative fixture registry membership, type, extension, MIME, size, page count, and staged-reject capability;
- total messages, waits, uploads, turns, actions, cost, and an active worst-case reservation.

The runner must receive the validated result or an equivalently frozen authorization object—not a raw model proposal with a parallel, reconstructable allowlist. Endpoint and fixture IDs are capabilities only within that validated attempt and expiry. Any mapping mismatch, expired validation, profile-version change, or absent binding fails closed.

## Boundary 5: runner to OpenEMR target

### Browser/session boundary

The runner uses the normal login form with an approved test identity inside one ephemeral Playwright context. It does not write storage state to disk. Login tracing must not capture password entry. Redirects and browser requests leaving the approved OpenEMR UI origin are blocked.

Patient selection requires one result containing the exact approved synthetic `pubpid` and display name. Numeric PID is dynamic and comes from that live result/card. The runner reacquires frames after navigation and verifies the Clinical Co-Pilot card's PID, CSRF binding, and proxy endpoint before and after actions.

### Server-owned authorization boundary

The browser supplies message text, the card token, and the expected card PID, but OpenEMR decides whether they are valid. The server session owns user identity and active patient. The PHP proxy rechecks the scoped CSRF token, current PID, patient/view-event/squad ACL, and derives allowed tools, patient identity, and encounter/document bounds. Message or document text cannot modify those fields. A `403` or `409` is an authorization/context failure, not an invitation to change the requested PID.

### Sidecar boundary

The sidecar `/agent/chat` accepts a private, server-derived context and is explicitly prohibited from the AgentForge runner. Status `/health` and `/ready` may be read from the separate approved status origin. The browser origin does not gain general access to the status origin, and `/metrics` is not an attack surface.

AgentForge has no OpenEMR database, shell, Docker, seeding, or demo-reset authority.

## Boundary 6: approved fixture to temporary target stage

The model/action supplies only a fixture alias and declared media type. The controller-owned registry supplies the repository-relative path, document type, size, pages, and SHA-256. The runner rechecks the on-disk file, rejects symlinks/traversal, and applies the lower of profile and runtime size limits.

The permitted target sequence is stage, observe bounded review, and authenticated reject. A close button or browser-context disposal is not proof of cleanup. The target rejection response must establish `rejected`. `ingestion_confirm.php` is prohibited by the profile, gate, and browser request filter. Ordinary human campaign approval does not silently enable it; adding persistent confirmation would require a separate reviewed design, profile/code change, exact synthetic reset plan, and new threat review.

If staging succeeds but rejection is not verified, set cleanup failure, stop the campaign, preserve non-secret correlation metadata, and resolve the target stage manually through its authenticated workflow before resuming.

## Boundary 7: W3 to Langfuse Cloud

Langfuse is supplemental external telemetry. The adapter redacts secret-shaped fields, authentication headers/values, known provider keys, secret query values, URL credentials, binary bodies, and unknown object representations. Metadata is bounded and role/campaign/attempt linkage is low-cardinality.

Telemetry failures are isolated: initialization, update, flush, trace-ID lookup, or shutdown failure must not change the security verdict or destroy local evidence. Conversely, a successful Langfuse trace does not prove that target evidence is complete. PostgreSQL and validated artifacts remain authoritative.

If a redaction defect is suspected, disable Langfuse, rotate affected credentials, preserve a local incident record without copying the suspect payload, and use provider deletion/incident procedures. Do not keep exporting while investigating.

## Boundary 8: evidence to Judge, Documentation, and human publication

Target output can itself contain instructions aimed at the Judge or Documentation role. It is quoted evidence, never a control message. Deterministic checks establish transport completeness and versioned invariants first. A foreign canary, unauthorized side effect, or allowed foreign-context tool call creates a deterministic floor. Missing response/evidence yields inconclusive or error, never secure pass.

The semantic Judge receives sanitized evidence and a fixed rubric but no target access. The Documentation role receives a frozen finding snapshot and minimal evidence package but cannot patch, change finding status, export, or publish. Contract validation requires references and target versions to agree.

Authenticated report export writes a sanitized local Markdown artifact. It is not external publication. Human review must confirm authorization, evidence sufficiency, clinical interpretation, affected versions, reproduction safety, redaction, and disclosure destination before information leaves the private environment.

## Boundary review checklist

Before enabling a live campaign, verify all of the following:

- the selected target alias resolves to the profile-owned hosts with the expected TLS policy;
- `/health.build_sha` is captured and the profile/config hashes are recorded;
- read APIs/dashboard are private or authenticated;
- provider and target credentials are present only in the runtime secret source;
- worst-case budget is reserved and pricing is current;
- the controller passes gate-authorized endpoint/fixture bindings intact to the runner;
- exact synthetic patient selection and card PID/CSRF checks are enabled;
- upload confirmation is unreachable and rejection cleanup has a tested observation path;
- telemetry redaction/hide settings are active, while local evidence remains authoritative;
- report export is local-only and an identified human owns any publication decision.
