# Dependency inventory and update policy

## Inventory basis

`pyproject.toml` declares supported ranges; `uv.lock` is the resolved reproducibility source. Versions below were read from the lock on 2026-07-21. This is an inventory, not a vulnerability or license attestation.

| Dependency | Locked version | Purpose / trust concern |
| --- | ---: | --- |
| Python runtime | 3.12 image family | Application runtime; Docker base is not digest-pinned |
| OpenAI Agents SDK | 0.18.3 | Structured model invocation, usage, tracing; outbound model data boundary |
| OpenAI Python | 2.46.0 | Provider transport; inherited SDK dependency |
| Langfuse | 4.14.1 | Optional redacted telemetry; third-party data/retention boundary |
| OpenInference Agents instrumentation | 1.6.1 | Bridges Agents SDK traces; process-global instrumentation |
| FastAPI | 0.139.2 | API/dashboard framework; route authentication must be explicit |
| Uvicorn | 0.51.0 | ASGI server / public ingress surface |
| Pydantic | 2.13.4 | Strict versioned contracts and settings validation |
| Pydantic Settings | 2.14.2 | Environment configuration and secrets wrapping |
| SQLAlchemy | 2.0.51 | Persistence and transactional queue access |
| Alembic | 1.18.5 | Schema migrations |
| psycopg / binary | 3.3.4 | PostgreSQL driver; binary distribution supply-chain consideration |
| HTTPX | 0.28.1 | Exact status-only target calls; redirect/timeout policy is security-sensitive |
| Playwright | 1.61.0 | Authenticated browser runner; browser binary must match package version |
| Jinja2 | 3.1.6 | Server-rendered dashboard templates |
| Prometheus client | 0.25.0 | Metrics; labels must avoid sensitive/high-cardinality data |
| PyYAML | 6.0.3 | Versioned taxonomy/profile/rubric/pricing parsing |
| Typer | 0.27.0 | Implemented operational CLI; commands that process campaigns still depend on the missing controller |
| python-multipart | 0.0.32 | API multipart support |
| pytest | 9.1.1 | Test runner |
| pytest-asyncio | 1.4.0 | Async tests |
| pytest-cov | 7.1.0 | Coverage measurement |
| Ruff | 0.15.22 | Lint and formatting checks |

Container/tool dependencies include `ghcr.io/astral-sh/uv:0.11.25`, `python:3.12-slim`, and `postgres:17-alpine`. Only the uv tag is exact; none is pinned by digest, and Python/PostgreSQL tags float within their lines.

## Update policy

1. Renovation/update automation opens one scoped dependency change with lockfile diff and upstream release/security notes.
2. Security-critical runtime patches are triaged immediately; normal updates are reviewed at least monthly.
3. Run format/lint, unit, contract drift, migration, Compose build/start, negative authorization, fake integration, and authorized smoke checks before merge.
4. Reinstall the Playwright browser for every Playwright update and run real packaged browser smoke.
5. Revalidate Langfuse/OpenInference together because instrumentation APIs are coupled.
6. Refresh model-routing and pricing configuration independently of Python dependency updates; live calls reject unknown prices.
7. Pin production images by digest or controlled patch release and record SBOM provenance.
8. Maintain rollback instructions for dependency, schema, and image changes; never downgrade migrations destructively during incident response.

## Required supply-chain evidence

No dependency vulnerability scan, SBOM, container scan, provenance/attestation, license inventory, or secret scan result is checked in. Before release, generate machine-readable SBOMs for the Python environment and image, run SCA and image vulnerability scanning, verify hashes/signatures where supported, review licenses, and record triage with owner and expiration. The project metadata is `UNLICENSED`, so redistribution terms also require explicit legal review.

## Minimize and isolate

Production should install only runtime dependencies from the frozen lock, run as the existing non-root user, keep browser execution in a constrained worker, deny the Docker socket, restrict egress to approved model/telemetry/target hosts, and keep optional telemetry failure-isolated. Dev tools and browser binaries should not be present in the API image unless required.
