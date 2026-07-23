# AgentForge Adversarial Security Platform

AgentForge is an evidence-first adversarial evaluation platform for testing AI-assisted clinical workflows. It runs bounded, reproducible security cases against an authorized Clinical Co-Pilot target, captures the resulting evidence, evaluates that evidence with deterministic checks and an independent Judge Agent, and persists the complete audit trail for review and regression testing.

The platform is designed around a simple rule: **models may propose or interpret, but deterministic code controls what is allowed to execute.**

> AgentForge is intended only for systems you own or are explicitly authorized to test, using synthetic test users and synthetic patient data.

## What AgentForge does

AgentForge can:

- Run versioned adversarial test cases against a live Clinical Co-Pilot
- Exercise the real authenticated UI through Playwright
- Validate every action through an allowlisted execution gate
- Capture transcripts, target version, timings, evidence, and assertion results
- Evaluate outcomes with deterministic invariants and an independent Judge Agent
- Store campaigns, attempts, evidence, verdicts, findings, and regression results in PostgreSQL
- Generate structured vulnerability reports when a finding is confirmed
- Run autonomous, bounded discovery campaigns in which the Orchestrator selects an
  objective and the Attack Generator creates the exact ordered sequence
- Record controller-assigned proposal and objective provenance for every attempt
- Surface campaign status, coverage, findings, costs, and regression history in a web dashboard
- Replay confirmed findings against future target versions

Checked-in YAML cases remain deterministic seeds and standalone evaluations. Full
discovery campaigns use them only when the Orchestrator or Attack Generator fails to
return a usable typed result; the dashboard identifies those attempts explicitly as
`deterministic_seed_fallback`.

## Architecture

```mermaid
flowchart LR
    U["Operator / Dashboard"] --> API["FastAPI API"]
    API --> DB[("PostgreSQL")]
    DB --> W["Background Worker"]
    W --> O{{"Orchestrator / Controller"}}
    O --> G["Deterministic Execution Gate"]
    G --> R["Playwright or HTTP Runner"]
    R --> T["Clinical Co-Pilot Target"]
    R --> O
    O --> J{{"Judge Agent"}}
    J --> O
    O --> DB
    O --> D{{"Documentation Agent"}}
    D --> DB
    DB --> UI["Dashboard / Reports"]
```

### Agent roles

- **Orchestrator Agent / Controller** — selects and coordinates bounded work, applies budgets and stopping rules, and owns workflow decisions.
- **Attack Generator Agent** — produces the exact typed ordered sequence for the
  controller-approved discovery objective; deterministic YAML sequences are clearly
  labeled fallback only.
- **Judge Agent** — independently evaluates frozen evidence and deterministic assertion results.
- **Documentation Agent** — converts confirmed findings into structured vulnerability reports and Markdown exports.

Specialist agents do not communicate directly with one another. The Orchestrator mediates each handoff through versioned typed contracts.

## Evaluation flow

A fixed-case evaluation selected from the dashboard or CLI follows this path:

1. Loads and validates the current case definition
2. Creates a campaign and attempt record
3. Validates the target, patient, action sequence, and budget
4. Executes the fixed interaction against the target
5. Captures transcript and execution evidence
6. Runs deterministic security assertions
7. Sends the frozen evidence to the Judge Agent
8. Persists the verdict and supporting metadata in PostgreSQL
9. Creates a finding, report, and regression candidate only when warranted

A full discovery campaign repeats a stricter four-agent loop. Deterministic code gives
the Orchestrator the allowed taxonomy shortlist, coverage, prior outcomes, target
constraints, and remaining limits. The Orchestrator chooses a new objective or a
partial-signal lineage to mutate. The Attack Generator produces the exact sequence.
The controller rejects invalid scope, lineage, unsafe actions, and duplicate semantic
sequence hashes before target execution. Only a semantic `partial_signal` can open a
mutation lineage. Confirmed deterministic evidence flows through Judge, finding
deduplication, Documentation Agent reporting, and versioned regression-case creation.

For each attempt the controller stores one trusted proposal source:
`agent_generated`, `agent_generated_mutation`, or
`deterministic_seed_fallback`. It separately stores
`orchestrator_selected` or `deterministic_ranked_fallback` for the objective.
Pre-migration records are displayed as `legacy_unknown (pre-provenance)` and are never
retroactively inferred.

PostgreSQL is the canonical source of truth. JSON files under `evals/results/` are portable exports for review and submission.

## Included evaluation categories

The nine-case seed suite covers all six required threat families:

- Direct prompt injection
- Multi-turn prompt injection
- Cross-patient data exposure
- Trusted-context identifier spoofing
- Evidence-precedence and conversation-state poisoning
- Unintended tool invocation
- Tool-parameter tampering
- Bounded recursive work and cost amplification
- Text-only identity and role escalation

Each case defines its category, exact action sequence, expected safe behavior, exploit signals, deterministic assertions, severity, exploitability, and regression eligibility.

## Project structure

```text
.
├── config/                  # Target profile, taxonomy, rubric, routing, pricing
├── contracts/v1/           # Published JSON Schema contracts
├── evals/
│   ├── seed-cases/          # Version-controlled adversarial cases
│   └── results/             # Portable evaluation result exports
├── migrations/              # Alembic database migrations
├── reports/                 # Generated and simulated vulnerability reports
├── src/agentforge/
│   ├── agents/              # Orchestrator, attacker, Judge, documentation roles
│   ├── api/                 # FastAPI routes and schemas
│   ├── dashboard/           # Jinja/HTMX operational dashboard
│   ├── evaluation/          # Case loading and deterministic evaluation
│   ├── orchestration/       # Controller, budgets, queue worker, execution gate
│   ├── persistence/         # SQLAlchemy models and repositories
│   ├── regression/          # Regression case creation and replay semantics
│   ├── runners/             # HTTP and Playwright target runners
│   └── security/            # Allowlisting, authentication, and redaction
├── tests/                   # Unit, contract, integration, and opt-in live tests
├── compose.yaml
├── Dockerfile
└── pyproject.toml
```

## Local setup

### Prerequisites

- Python 3.12+
- `uv`
- Docker and Docker Compose
- An authorized Clinical Co-Pilot test target
- Synthetic test credentials and patients
- An OpenAI API key for agent-backed evaluation

### Install dependencies

```bash
uv sync
uv run playwright install chromium
```

### Configure the environment

```bash
cp .env.example .env
```

Set the required values in `.env`, including:

```text
OPENAI_API_KEY
DATABASE_URL
TARGET_BASE_URL
TARGET_API_BASE_URL
TARGET_TEST_USERNAME
TARGET_TEST_PASSWORD
PLATFORM_API_TOKEN
```

Do not commit `.env`.

### Start AgentForge

```bash
docker compose up --build
```

The application is available at:

```text
http://localhost:8080
```

Health endpoints:

```text
GET /healthz
GET /readyz
```

## Run an evaluation from the CLI

```bash
uv run --env-file .env agentforge eval run \
  --case evals/seed-cases/de-cross-patient-canary.yaml \
  --target deployed \
  --json
```

Replace the case path with any allowlisted file under `evals/seed-cases/`.

A successful run persists its canonical records in PostgreSQL and writes a portable result to `evals/results/`.

## Launch a full discovery campaign

The authenticated dashboard at `/dashboard/campaigns` has a **Launch campaign**
panel with quick target, taxonomy, attempt, and cost controls plus advanced duration,
mutation, no-signal, and priority limits. Deployed campaigns require an explicit
synthetic/authorized-target confirmation. The form is CSRF-protected and uses a
per-form idempotency key; it never places the platform bearer token in HTML or
JavaScript.

The equivalent CLI command is:

```bash
uv run agentforge campaign create \
  --target deployed \
  --category prompt_injection \
  --max-attempts 1 \
  --max-cost-usd 0.25 \
  --max-mutations 1 \
  --no-signal-limit 2
```

Campaigns are queued for the background worker. The detail page polls the durable
campaign state and shows the ordered Orchestrator, Attack Generator, Judge, and
Documentation Agent timeline together with proposal provenance and lineage.

## Dashboard

The dashboard provides views for:

- Campaign status and lifecycle events
- An authenticated, bounded full-campaign launcher
- Queue and worker state
- Attempts and evidence
- Deterministic assertion outcomes
- Judge verdicts and confidence
- Findings and vulnerability reports
- Regression runs and results
- Cost, latency, and coverage summaries
- Proposal-source utilization and per-source verdict counts
- Target-version resilience rates

Allowlisted seed cases can be launched from the dashboard when run controls are enabled. Campaign execution occurs asynchronously through the background worker, and campaign details are read from PostgreSQL.

## Database and migrations

Apply migrations with:

```bash
uv run alembic upgrade head
```

AgentForge stores:

- Campaigns and lifecycle events
- Attempts and evidence
- Judge verdicts
- Findings and reports
- Regression cases, runs, and results
- Agent usage, cost, and trace references

## Testing

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

PostgreSQL and live-target tests are opt-in and require explicitly configured test environments.

GitLab CI runs a minimal pre-merge verification gate with an ephemeral PostgreSQL test
database. It blocks merging when the latest pipeline fails or remains pending and does
not deploy to Railway. See
[`docs/CI.md`](docs/CI.md) for its exact scope, cleanup behavior, and deployment
boundary.

## Deployment

AgentForge is designed to deploy as:

- One application service containing FastAPI, the dashboard, worker, agents, and Playwright runner
- One isolated PostgreSQL service

The target Clinical Co-Pilot remains a separate deployment. AgentForge reaches it only through configured and allowlisted HTTPS endpoints.

For browser-based deployments, run a single application replica with enough memory for headless Chromium.

## Safety model

- Only configured target aliases and allowlisted hosts may be contacted
- Only synthetic identities and patients are permitted
- Model output cannot directly execute network actions
- The execution gate validates every runnable sequence
- Target credentials remain outside model context
- Browser sessions are ephemeral
- Direct target-database access is prohibited
- Missing evidence or incomplete execution is never treated as a secure pass
- Reports remain internal until reviewed by a human

See [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full security and design rationale.

## Current scope

AgentForge supports both fixed, version-controlled evaluations and bounded autonomous
discovery campaigns. The four-agent loop, trusted provenance, partial-signal mutation,
finding/report/regression path, and PostgreSQL recovery behavior are covered by
deterministic and isolated PostgreSQL tests. The current public deployment still
reflects the previously verified `main` release until this feature branch is reviewed
and deployed; this branch does not deploy itself.
