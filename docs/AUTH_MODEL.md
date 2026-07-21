# AgentForge authentication and authorization model

## Principles

AgentForge uses separate authentication domains for the W3 control plane, external providers, and the OpenEMR target. A credential valid in one domain grants no authority in another. Authentication answers who a caller is; deterministic authorization still decides which campaign, patient, endpoint, fixture, model call, state change, and report action is permitted.

The model follows these rules:

1. Deny when a required secret, alias, binding, budget reservation, or cleanup proof is missing.
2. Models never possess credentials or executable authority.
3. Target patient and tool authorization are server-owned and rechecked by OpenEMR.
4. Capability-like IDs are meaningful only inside one validated, unexpired attempt.
5. Read access to stored security evidence is sensitive and must be authenticated before public exposure.
6. Export is local artifact creation; external publication always requires a human decision.

This document describes the current route and component model. It does not claim a completed live end-to-end campaign.

## Principals and roles

| Principal | Authenticates with | Authorized actions | Explicitly not authorized |
| --- | --- | --- | --- |
| Human W3 operator | `PLATFORM_API_TOKEN` bearer credential | Create/cancel campaigns, create regression runs, update finding status, export a stored draft locally | Raw target URLs/files, direct runner calls, target database access, automatic external publication |
| Deployment system | `DEPLOY_WEBHOOK_SECRET` header | Queue one idempotent deployed-target regression for a supplied deployment/version | General API mutations, findings, reports, changing target alias away from `deployed` |
| W3 read user | No route-level identity exists currently | Current code exposes dashboard and read APIs to any network caller | This is a deployment gap, not intended public authorization |
| API service | Database credential and checked-in configuration | Validate request scope and persist queued work | Target execution or model authority merely because a request was accepted |
| Worker | Database credential; process identity | Claim/heartbeat/finish queued campaigns and invoke the configured processor | Inventing campaign scope, bypassing gate, publishing reports |
| Orchestrator/Attack Generator | External model API under W3 service account | Return a strict objective/proposal contract | Credentials, database/network/filesystem access, campaign mutation, target access |
| Deterministic gate | In-process trusted code plus frozen context | Approve exact bounded bindings or reject | Network calls or modifying a proposal to make it pass |
| Runner | One validated attempt plus runtime target credential | Status reads or normal authenticated synthetic UI actions in profile scope | `/agent/chat`, arbitrary hosts/files, real patients, persistence confirmation, OpenEMR DB/shell |
| OpenEMR test user | `TARGET_TEST_USERNAME` and `TARGET_TEST_PASSWORD` through normal login | Actions allowed to the configured physician role and server ACLs | Any authority beyond the actual session role or current patient ACL |
| OpenEMR PHP proxy | Authenticated OpenEMR session and patient-scoped CSRF | Derive trusted patient/tool/document context and call the private sidecar | Trusting client/model-supplied identity, ACL, or tool scope |
| Judge/Documentation model | External model API under W3 service account | Produce strict semantic verdict or draft report data | Target access, deterministic override, finding status, export, publication |
| Human reviewer/publisher | Organizational identity outside this repository | Approve a reviewed artifact for an explicitly chosen external destination | Delegating publication approval back to a model |

## Credential inventory and lifecycle

| Secret | Consumer | Storage and transmission | Rotation/revocation |
| --- | --- | --- | --- |
| `PLATFORM_API_TOKEN` | W3 mutation routes | Runtime secret only; bearer header over protected transport | Rotate after exposure or operator change; invalidate old token and audit mutations |
| `DEPLOY_WEBHOOK_SECRET` | `/api/v1/hooks/target-deployed` | Separate runtime secret; dedicated header | Rotate independently; replay/queue audit by deployment idempotency key |
| `DATABASE_URL` | API and worker | Runtime secret; private database network | Rotate DB user/password, terminate sessions, review database access |
| `OPENAI_API_KEY` | Model adapter | Runtime secret; HTTPS to provider | Revoke/rotate with provider; inspect usage and W3 agent-run records |
| `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Telemetry adapter | Runtime secret; HTTPS to configured Langfuse base URL | Disable exporter, rotate keys, review/delete suspect traces |
| `TARGET_TEST_USERNAME` / `TARGET_TEST_PASSWORD` | Ephemeral HTTP/browser target session | Runtime secret; normal OpenEMR login only | Revoke/rotate in target; dispose sessions; verify role and synthetic scope |
| Target session cookie and CSRF | In-memory target client/context | Ephemeral process memory and same-origin requests | Dispose context; reauthenticate and reselect patient; never persist storage state |
| `TARGET_AGENT_SHARED_SECRET` | OpenEMR PHP-to-sidecar integration, not AgentForge runner | Must not be given to model or direct attack action | Rotate in target pair if exposed; AgentForge continues through PHP proxy |
| `TARGET_RESET_TOKEN` | Reserved future reset integration | Unused by ordinary campaigns; no current reset route is authorized | Keep unset unless a separately reviewed synthetic-only reset exists |

Secrets must not enter Git, PostgreSQL evidence, Langfuse inputs/outputs, logs, screenshots, Playwright traces, Markdown reports, exception messages, or URLs. Secret-shaped fields are redacted, but callers must minimize before serialization rather than treating redaction as permission to pass secrets around.

## W3 API authentication

### Mutation routes

The current API requires the platform bearer token for:

- `POST /api/v1/campaigns`;
- `POST /api/v1/campaigns/{campaign_id}/cancel`;
- `POST /api/v1/regression-runs`;
- `PATCH /api/v1/findings/{finding_id}/status`;
- `POST /api/v1/reports/{finding_id}/export`.

The deployment hook uses the distinct webhook secret for:

- `POST /api/v1/hooks/target-deployed`.

Comparison is constant-time. An unset expected secret fails authentication rather than creating an open development mode. The API token identifies an operator class, not an individual user: current code has no per-user identity, role hierarchy, session, audit actor, expiry, or fine-grained permission. Deployment should therefore restrict token distribution and network access, and future multi-user operation requires a proper identity layer rather than issuing a shared bearer token broadly.

### Read routes and dashboard

Current GET routes for campaigns, regressions, findings, reports, coverage, and agent runs, plus the HTML dashboard, have no route-level authentication. They can expose target versions, findings, costs, trace IDs, report drafts, and synthetic evidence summaries. Local Compose binds port 8080 to `127.0.0.1`, but Railway or another public ingress removes that containment.

Required deployment rule: keep W3 private until read authentication and authorization are implemented and verified. A reverse-proxy login may be an interim network control, but documentation must not describe unauthenticated routes as authorized public reads. At minimum, future read authorization should distinguish general campaign metrics from finding/report/evidence detail and record the reviewing user.

## Campaign-scope authorization

An authenticated API mutation does not directly authorize execution. `ApplicationService` constrains creation to:

- a target alias present in the checked-in profile;
- a category/subcategory in the checked-in taxonomy;
- configured campaign and global cost ceilings;
- bounded attempts, duration, mutations, no-signal threshold, priority, and idempotency key.

The queue record is a request for processing, not a runner capability. The worker's database claim prevents concurrent ordinary processing and uses heartbeats/stale interruption, but a claimed row still must pass budget, stopping, and execution authorization.

## Model-role authorization

All model roles operate by structured recommendation:

- The Orchestrator selects one bounded objective from the supplied taxonomy/profile subset.
- The Attack Generator proposes a sequence from the discriminated action vocabulary.
- The Judge classifies sanitized evidence under a fixed rubric.
- The Documentation role renders a frozen confirmed finding into a strict report contract.

Schema validity is necessary but insufficient. A model cannot create authority by emitting a valid endpoint ID, patient alias, fixture ID, role, or “approved” statement. It cannot contact the target, query arbitrary data, reserve its own budget, change database state, invoke another model without the controller, or publish.

Prompt injection in model input does not alter this authorization model. Target response/document text delivered to the Judge or Documentation role must be treated as quoted evidence.

## Deterministic execution authorization

The execution gate is the sole component that turns a proposal into a bounded authorization decision. It fails closed when any of these checks fail:

- campaign cancelled, expired, over limit, over budget, duplicate-bounded, or cleanup failed;
- target alias absent from the synthetic-only profile;
- proposal taxonomy differs from the controller-selected scope;
- sequence does not begin with fresh reset, approved authentication, and exact synthetic patient selection, or does not end with evidence collection;
- action/wait order, turn count, message bytes, wait time, upload count/bytes, or cost exceeds a bound;
- identity alias, role, or patient alias differs from controller-owned values;
- endpoint ID lacks an exact method/surface/path/purpose binding in both controller context and target profile;
- request parameters contain arbitrary URL/path/shell/SQL authority or foreign patient values;
- fixture alias lacks controller registry metadata or violates root/type/extension/MIME/size/page constraints;
- upload stage/reject endpoints are not both authorized, or any route represents persistent confirmation;
- worst-case budget reservation is absent, consumed, inconsistent, or beyond the current campaign window.

Approval yields a `ValidatedAttackV1` with the exact authorized bindings, selected patient, target profile version, sequence hash, budget reservation, authorization timestamp, and expiry. The controller must pass those values intact to the runner. A raw `ProposedAttackV1` is not an equivalent authorization token. Until this W3 gate-to-runner integration is verified in the complete processor path, live execution must remain disabled.

## Target authentication and patient authorization

### Login and session

The runner uses the normal OpenEMR form with the single approved `physician_test` identity alias. Credentials are resolved from environment settings; a model cannot submit a username/password. The authenticated cookie jar exists only in one in-memory HTTP client or ephemeral Playwright context. Saved browser auth state is prohibited.

A stale or failed login is an authentication failure. Recovery is to discard the context and authenticate normally again. The runner may not use a different account, bypass login, or obtain the private sidecar secret.

### Exact synthetic patient selection

Patient aliases map through the target profile:

- `patient_a` -> `GOLDEN-LONGITUDINAL`, Avery GoldenFixture;
- `patient_b` -> `GOLDEN-WORKFLOW`, Morgan GoldenFixture.

The selected UI row must uniquely contain the exact approved `pubpid` and expected display name. Numeric PIDs are installation-specific and are discovered from the authenticated UI/card, never configured by a model or copied across environments. Selection of any other chart fails before a Co-Pilot action.

### Server-owned ACL and CSRF context

The Clinical Co-Pilot card exposes an expected numeric patient ID, a scoped CSRF token, and the same-origin proxy endpoint. The runner verifies and binds them before each message/upload step. These client checks detect drift but do not replace server authorization.

OpenEMR owns the authoritative decision. The PHP proxy:

- identifies the user from the authenticated session;
- requires the session's active PID to match the expected card PID;
- validates CSRF scope `clinical_copilot:<pid>`;
- rechecks patient/view-event/squad ACLs;
- derives patient name, allowed tools, and bounded encounter, appointment, note, and document scope;
- sends that server-derived trusted context to the sidecar.

Message text, document content, correlation metadata, browser attributes, or a model-proposed parameter cannot elevate role, change patient, or expand tool scope. A `403` or `409` means the relationship is invalid. Discard the session/page, reauthenticate, and reselect the exact patient. Never change expected PID to make the error disappear.

## Endpoint and network authorization

Actions carry endpoint aliases, not URLs. The selected target alias supplies the only approved base/status origins. Endpoint resolution requires an exact profile rule for method, surface, and path and rejects credentials in URLs, traversal, unapproved hosts, and cross-origin redirects.

The authorized target surfaces are normal OpenEMR login/navigation, status `GET /health` and `GET /ready`, same-origin chat proxy, upload stage, and upload reject. The following are prohibited:

- direct `/agent/chat`;
- `/metrics` as an attack action;
- ingestion confirmation;
- arbitrary scheme/host/path, shell, SQL, or target database access.

TLS verification remains enabled for deployed HTTPS. A local development alias may explicitly disable verification only for its profile-owned host; this is not a general certificate bypass.

## Fixture authorization and nonpersistent upload

An upload action supplies only a fixture alias, approved upload-surface alias, and media type. The controller-owned authorization binds that alias to a repository-relative path, document type, size, page count, and SHA-256. The runner rechecks actual bytes and rejects changed files, symlinks, traversal, wrong MIME/extension, or exceeded limits.

Authorization permits stage and reject only. It does not permit confirmation. The target stage is bound to the same authenticated user, patient, session, and CSRF context. Successful stage must be followed by verified rejection; browser closure is not cleanup. Failure to verify rejection revokes further campaign execution through the cleanup-failed stopping condition.

## Evidence, finding, and publication authorization

The runner may record bounded sanitized evidence. It is not authorized to decide severity or publication. Deterministic evaluation first separates complete transport, proven invariant violations, indeterminate evidence, and errors. The semantic Judge cannot downgrade a proven deterministic violation and cannot turn missing evidence into a secure pass.

A finding and report remain internal records. Documentation requires a frozen confirmed-finding snapshot, matching target versions, and existing evidence references. The authenticated export endpoint writes one safe local Markdown filename under the configured report directory. It does not send email, create an issue, upload to a vendor, or disclose externally.

External publication requires a named human reviewer to verify:

- the target and testing authorization;
- that all data are synthetic and correctly redacted;
- complete, reproducible, version-bound evidence;
- clinical-impact wording and severity;
- safe reproduction and remediation guidance;
- the destination, audience, embargo, and disclosure process.

No model, webhook, worker, target response, finding status, or “confirmed” verdict substitutes for this human publication gate.

## Authorization review checklist

- Are W3 read surfaces private or authenticated?
- Are API, webhook, provider, database, and target secrets distinct and current?
- Does the campaign use one checked-in target alias and an observed runtime version?
- Is the budget reservation active and pricing current?
- Did the gate produce exact endpoint/fixture/patient bindings for this unexpired attempt?
- Does the runner consume those bindings without reconstructing authority from model output?
- Does OpenEMR independently validate the current PID, ACL, role, and CSRF scope?
- Is browser state ephemeral and are credentials absent from traces/artifacts?
- Is any staged upload verified rejected, with confirmation still unreachable?
- Is the report still private until a human explicitly approves external publication?
