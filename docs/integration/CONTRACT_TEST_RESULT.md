# Contract test result

## Latest result

On 2026-07-21 in the uncommitted W3 working tree, using macOS, Python 3.13.5, and pytest 9.1.1:

- `uv run pytest tests/contract -q`: **13 passed in 0.08s**.
- `uv run python scripts/export_contracts.py --check`: **current, 7 files**.
- `uv run python scripts/export_evals.py --validate-only`: **6 synthetic seeds validated**, catalog SHA-256 `86d5abb87f466a8cacf487df758fc46f2353955765694477150936292b38437f`.
- `uv run pytest`: **98 passed in 2.47s**, with one Starlette TestClient deprecation warning from the environment.
- `uv run ruff format --check .`: **failed** because three files would be reformatted.
- `uv run ruff check .`: **failed** on one `S701` finding for `autoescape=False` in the Markdown report renderer.

The dependency sync command succeeded only after directing the uv cache to a writable temporary directory. No code was reformatted or changed to hide the quality-gate failures.

## Required checks

```bash
uv run pytest tests/contract
uv run python scripts/export_contracts.py --check
uv run ruff check .
uv run ruff format --check .
```

## What these checks establish

- Representative v1 payloads validate and reject forbidden/secret/extra input.
- Exported JSON schemas match the Python contract definitions.
- Source and tests meet configured static/style rules.

## What they do not establish

They do not prove a PostgreSQL migration against a running database, worker/controller behavior, execution-gate enforcement at the runner boundary, live OpenAI or Langfuse calls, OpenEMR login/patient scope, cleanup, a full four-agent trace, Railway deployment, or a vulnerability finding. CLI help and ASGI import succeeded separately, but the default worker-enabled lifespan depends on the absent controller. Those remaining claims require integration, live E2E, and deployment evidence.
