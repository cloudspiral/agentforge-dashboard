# AgentForge users, workflows, and use cases

AgentForge serves the security and engineering team responsible for an AI-enabled
Clinical Co-Pilot. Its purpose is to help that team find, reproduce, document, and
prevent security failures before they affect real clinical data or workflows.
AgentForge is limited to systems the operator owns or is explicitly authorized to
test, using synthetic identities, synthetic patients, and approved fixtures.

It is not a general-purpose vulnerability scanner, a penetration-testing service, a
clinical decision-maker, or a replacement for human security review.

## Primary user: application security engineer

The primary user is an application security (AppSec) engineer or security evaluator
who needs to test a natural-language, tool-using application. Traditional scanners
can check known HTTP patterns, but they cannot adequately explore failures that
depend on conversation history, model interpretation, patient context, or a sequence
of tool calls.

The engineer's discovery workflow is:

1. Confirm the authorized target alias, target version, synthetic identity and
   patient, allowed execution surfaces, cleanup behavior, attempt limit, duration,
   and cost ceiling.
2. Launch a bounded discovery campaign from `/dashboard/campaigns`, optionally
   narrowing it to an OWASP category or subcategory.
3. Monitor the queue and campaign page while the Orchestrator selects an objective,
   the Attack Generator proposes an exact scenario, and deterministic code authorizes
   and executes it.
4. Review the ordered transcript, actions, tool calls, target version, evidence hash,
   deterministic case checks, Judge verdict, cost, and trace correlation.
5. Investigate a Judge-confirmed exploit in `/dashboard/findings`. Reproduce it when
   additional validation is needed, then accept it as a real finding or mark it as a
   false positive. AgentForge never makes that lifecycle decision.
6. After the target team deploys a fix, launch the saved case from
   `/dashboard/regression-runs` and use changed-version evidence to decide whether the
   finding can be resolved.

Automation is appropriate for this workflow because the adversarial input space is
too large and stateful to cover reliably by hand. AgentForge can generate variations,
repeat multi-step browser or API sequences, preserve the complete evidence trail, and
enforce the same authorization and budget limits on every attempt. The engineer
remains responsible for scope, interpretation, and disposition.

## Collaborating users and their workflows

### Clinical platform engineer

The clinical platform engineer owns the Clinical Co-Pilot and remediates confirmed
issues. They move from a Finding to its exact transcript, evidence, affected target
version, expected behavior, and saved regression case. They change the target in its
own repository and deployment process, then ask AgentForge to replay the case against
the new build.

Automation is the right fit for verification because replaying the exact sequence
removes the wording and timing drift of manual retesting. It also makes it practical
to rerun the entire active regression cohort after a change, which can reveal a fix
in one category that caused a regression in another. Human clinical judgment is
still required for claims about unsafe advice, ambiguous language, or standard of
care.

### Security lead, CISO, or authorization reviewer

This user defines acceptable scope and risk, reviews OWASP coverage and residual
gaps, monitors cost and finding status, and decides whether evidence supports release
or risk acceptance. Their workflow begins with authorizing the target, identities,
time window, and permitted actions. They then use the dashboard and evidence-backed
reports to review what was tested, what was blocked or inconclusive, which findings
remain open, and how the current build compares with the previous build.

Automation is appropriate for evidence aggregation because campaigns produce many
linked records: attempts, transcripts, target versions, evidence hashes, verdicts,
costs, traces, findings, reports, and regression results. Automatically correlating
those records is faster and less error-prone than assembling an assurance packet by
hand. Approval, risk acceptance, and disclosure remain human decisions; a dashboard
count or model confidence score alone is never assurance.

### Operator or site reliability engineer

The operator configures secrets outside Git, runs database migrations, deploys the
API and worker, protects the dashboard, and monitors readiness, queue health, campaign
heartbeats, failures, and spend. If an execution or cleanup boundary becomes
uncertain, they stop the affected work rather than weakening the allowlist or safety
profile.

Automation is appropriate for queue processing, limit enforcement, evidence
persistence, retries, and stale-work recovery because these are repetitive,
time-sensitive mechanical tasks with rules that should be applied identically every
time. PostgreSQL is the operational authority; telemetry such as Langfuse is
diagnostic. Credential rotation, incident response, and any expansion of target scope
remain operator-controlled.

### Developer or evaluator

Developers create typed contracts, synthetic fixtures, deterministic assertions, and
YAML seed cases. They run fake-runner tests by default and opt into live evaluation
only for an explicitly authorized target. A representative workflow is to add a
fixed case for a known security invariant, validate it locally, run it from the
dashboard, and promote it to an ongoing regression when a separate Judge verdict
confirms an exploit.

Automation is appropriate because contract checks, schema drift detection, seed-case
validation, and repeatable regression execution belong in every development and
release cycle. Automating them provides consistent feedback that manual spot checks
cannot. A fixed assertion can report whether its narrow expectation passed, but it
cannot substitute for the Judge verdict or human finding review.

## Specific use cases and why they should be automated

| Use case | Example | Why automation is the right solution | Human responsibility |
| --- | --- | --- | --- |
| Discover cross-context data exposure | Test whether a Patient A session can be induced to reveal a Patient B synthetic canary through direct, indirect, or multi-turn instructions. | The failure may depend on turn order, phrasing, patient binding, and tool behavior. Automated agents can explore bounded variations and preserve the exact transcript and target-visible evidence for each attempt. | Define the authorized synthetic context and determine whether the evidence demonstrates a real disclosure. |
| Detect unintended tool use or excessive agency | Ask an out-of-scope question and observe whether the co-pilot invokes a clinically irrelevant chart tool or accepts a message-supplied patient identifier. | Reliable validation requires capturing the ordered conversation, tool parameters, side effects, and authenticated patient context together. Automated execution and evidence capture make that correlation repeatable. | Decide the allowed product behavior and the security or clinical impact of the observed action. |
| Exercise prompt-injection and instruction-boundary defenses | Apply direct overrides, role-escalation text, uploaded-document instructions, evidence-precedence conflicts, and multi-turn context attacks. | Natural-language attacks have a combinatorial input space that fixed payload lists and occasional manual testing do not cover. Agent-guided exploration can adapt within a typed taxonomy while deterministic gates keep every executable action in scope. | Approve fixtures and actions, review ambiguous model behavior, and halt testing if cleanup or provenance is uncertain. |
| Follow up on partial signals | Mutate an attempt only after the Judge records a `partial_signal`, retaining the parent attempt and lineage. | Adaptive follow-up is valuable when a near miss suggests a productive direction. Automation can create and track bounded mutations without losing provenance or repeatedly retesting unrelated paths. | Decide whether continued exploration is worth the risk and budget; review any eventual finding. |
| Repeat known security checks | Run YAML seed cases for cross-patient access, parameter tampering, unintended tools, direct instruction override, or bounded-work amplification. | Exact setup, actions, assertions, and evidence can be replayed consistently across environments. This removes tester-to-tester variation and makes failures reproducible. | Author meaningful invariants and interpret deterministic results alongside raw evidence and the independent Judge verdict. |
| Verify remediation and detect regressions | Replay a confirmed finding's saved sequence against a changed target version, then run the full active regression suite. | Manual retesting often changes wording or setup and can miss collateral regressions. Version-bound automated replay provides comparable evidence and makes full-suite checks practical after every material release. | Implement the fix, assess changed-version evidence, and approve resolution or residual risk. |
| Build an auditable finding and report | Deduplicate repeated observations, retain immutable evidence, create a draft report, and link a regression case to the confirmed finding. | Correlating IDs, hashes, versions, transcripts, verdicts, and observations is repetitive and error-prone. Automation produces a consistent evidence package and prevents rediscovery from creating duplicate findings. | Validate the finding, choose its lifecycle state, edit or approve the report, and control publication or disclosure. |
| Track coverage, reliability, and cost | Summarize tested and untested taxonomy areas, supported and blocked surfaces, queue state, failures, token usage, and estimated cost. | These facts change throughout a campaign and across releases. Automated aggregation gives the team a current view and supplies the Orchestrator with the same durable facts shown to reviewers. | Set budgets and stopping rules, investigate anomalies, and decide whether coverage is sufficient for the intended release. |

## Why bounded automation, not unsupervised autonomy

The platform combines model-driven exploration with deterministic control. Models are
useful for generating realistic natural-language attacks, selecting productive areas
to explore, interpreting complex evidence, and drafting reports. Deterministic code
owns authorization, target and operation allowlists, execution, lifecycle state,
evidence hashing and persistence, duplicate detection, budgets, and stopping limits.

This division is essential to the user need. A fully manual process does not scale to
stateful conversational attacks or continuous regression testing, while an
unsupervised agent should not be trusted with security scope, clinical impact,
credentials, target changes, or disclosure authority. AgentForge automates the
high-volume and repeatable parts of the work while leaving consequential decisions
with accountable people.

## Decisions that remain human-only

- authorize a target, identity, time window, and acceptable test risk;
- provide and rotate credentials and API keys;
- enable any persistent or destructive action, which the current profile disables;
- determine whether ambiguous clinical output constitutes a vulnerability;
- accept, defer, suppress, reopen, or resolve a finding;
- approve remediation and residual risk; and
- publish or disclose a report.
