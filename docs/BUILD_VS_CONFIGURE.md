# Build versus configure decisions

## Decision

Keep the current combination of the OpenAI Agents SDK for four bounded structured
model roles, plain Python for mechanical orchestration and authorization, HTTPX for
status-only target access, Playwright for the authenticated UI, PostgreSQL for durable
state, and Langfuse/Prometheus for optional telemetry. Build the Clinical
Co-Pilot-specific authorization gate, typed raw-evidence transport, saved-sequence
regression mapping, and report lifecycle. Semantic objective, attack, verdict, and
report decisions remain with the four agents.

## Options evaluated

| Option | Fit | Decision and rationale |
| --- | --- | --- |
| OpenAI Agents SDK | Typed outputs, model settings, usage, tracing, bounded runner | **Use.** The SDK supports structured agents and tracks usage. AgentForge deliberately withholds tools/handoffs and keeps execution in deterministic code. [Official agents docs](https://openai.github.io/openai-agents-python/agents/) |
| Plain Python | Explicit state machine, policy, transactions, tests | **Use.** Safety decisions need inspectable functions and domain contracts more than a general orchestration abstraction. |
| LangGraph | Durable execution, persistence, human interrupts | **Defer.** These capabilities become attractive for many long-lived branches or interactive approvals, but adopting it now would duplicate the existing PostgreSQL worker/state design before the simple controller exists. Re-evaluate after recovery requirements exceed the current queue. [Official overview](https://docs.langchain.com/oss/python/langgraph/overview) |
| garak | Broad LLM probes, detectors, repeated generations, structured logs | **Configure as a complementary corpus adapter later.** It is strong for generic LLM failure discovery, but its changing probe set and non-normalized scores do not replace patient/session/CSRF/tool evidence or AgentForge regression invariants. [Official docs](https://docs.garak.ai/garak) |
| OWASP ZAP | General web DAST with YAML automation | **Configure separately for conventional web/API scanning.** Do not route ZAP through the model campaign or let it crawl the clinical target by default. Its automation framework can cover conventional vulnerabilities under a separately authorized profile. [Official automation docs](https://www.zaproxy.org/docs/automate/automation-framework/) |
| Burp Suite / Burp DAST | Mature authenticated crawl/audit and CI integration | **Optional commercial complement.** Useful for enterprise DAST and manual validation, but it does not supply Clinical Co-Pilot-specific semantic evidence or the synthetic-patient invariant model. Its own documentation warns that scanning can damage targets, reinforcing separate authorization. [Official DAST docs](https://portswigger.net/burp/documentation/dast) |
| Semgrep | SAST, dependency, and secret scanning in CI | **Configure in CI.** It complements runtime AI testing and should scan W3 and W1 source independently; it cannot observe model behavior through an authenticated chart workflow. [Official platform description](https://semgrep.dev/pricing/) |
| HTTPX | Exact async HTTP, timeout and redirect policy | **Use** for `/health` and `/ready` only. Small scope is easier to audit than a general scanner. |
| Playwright | Real browser behavior and isolated contexts | **Use** for normal OpenEMR login, patient selection, Co-Pilot chat, evidence, and staged-upload rejection. Official docs support isolated modern browser automation. [Official Python docs](https://playwright.dev/python/docs/intro) |
| Commercial AI red-team platforms | Managed scale, dashboards, collaboration, probe libraries | **Evaluate after MVP** for fleet governance and independent assurance. Export/import through versioned contracts; never outsource the target's authorization boundary or accept opaque scores as findings. |

PyRIT is another credible build-versus-configure comparator: it provides scanners, multi-turn attacks, Playwright targets, memory, and scoring. It may become a useful attack-corpus source or independent cross-check, but replacing the current code would still require custom patient, session, evidence, and publication controls. [Official PyRIT docs](https://azure.github.io/PyRIT/)

## What AgentForge should build

- The mechanical campaign controller and gate-to-runner authorized envelope.
- Exact Clinical Co-Pilot target profile and synthetic fixture mapping.
- Patient/session/CSRF/current-card invariants and cleanup semantics.
- Versioned raw evidence, one-Finding-per-confirmed-attempt lifecycle, saved-sequence
  regression mapping, and human-controlled external disclosure boundary.
- Explicit separation between fixed-case deterministic assertions and discovery
  Judge verdicts; there is no reconciliation layer.
- Integration contracts and ATO evidence mapping.

## What AgentForge should configure or buy

- Model provider, model routing, output caps, and pricing catalog.
- Langfuse, Prometheus scraping/alerts, PostgreSQL operations, Railway/private networking.
- Semgrep/SCA/secret scanning and dependency update automation.
- ZAP or Burp for conventional DAST under an independent scope.
- garak/PyRIT corpora as input adapters after a safe normalization contract exists.

## Re-evaluation triggers

Adopt a graph runtime only when campaigns require durable human pauses, complex
parallel branches, or replayable node-level recovery that the explicit controller
cannot handle cleanly. Adopt a commercial platform when multi-team tenancy, fleet
scheduling, regulatory workflow, or managed probe maintenance outweighs data-control
and integration costs. Every substitution must preserve typed contracts, exact target
authorization, runner-produced raw evidence, Judge-only semantic authority, and human
publication authority.
