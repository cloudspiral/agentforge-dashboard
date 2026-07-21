FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.25 /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

FROM python:3.12-slim
RUN useradd --create-home --uid 10001 agentforge
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN playwright install --with-deps chromium \
    && chmod -R a+rX /ms-playwright \
    && rm -rf /var/lib/apt/lists/*
COPY --chown=agentforge:agentforge . .
RUN mkdir -p reports/generated artifacts/browser-traces artifacts/screenshots \
    && chown -R agentforge:agentforge reports artifacts
USER agentforge
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]
STOPSIGNAL SIGTERM
CMD ["uvicorn", "agentforge.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
