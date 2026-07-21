.PHONY: install lint format test test-unit test-contract test-integration test-e2e schemas evals load-test compose-check quality ci db-up db-down migrate serve worker

install:
	uv sync --extra dev
	uv run playwright install chromium

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest --cov=agentforge --cov-report=term-missing

test-unit:
	uv run pytest tests/unit

test-contract:
	uv run pytest tests/contract

test-integration:
	uv run pytest -m integration

test-e2e:
	RUN_LIVE_E2E=1 uv run pytest -m e2e

schemas:
	uv run python scripts/export_contracts.py --check

evals:
	uv run python scripts/export_evals.py --validate-only

load-test:
	uv run python scripts/load_test.py --target fake --operations 100 --max-seconds 30 --max-cost-usd 0 --max-target-requests 0

compose-check:
	docker compose config --quiet

quality: lint schemas evals load-test

ci: quality test

db-up:
	docker compose up -d postgres

db-down:
	docker compose down

migrate:
	uv run alembic upgrade head

serve:
	uv run uvicorn agentforge.main:app --reload --host 0.0.0.0 --port 8080

worker:
	uv run agentforge worker run
