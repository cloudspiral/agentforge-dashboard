# GitLab CI verification gate

GitLab CI verifies proposed repository changes. It does **not** deploy AgentForge.
Production deployment follows the independent GitLab-to-GitHub mirror and Railway's
GitHub `main` integration.

## When it runs

The pipeline runs for merge requests and for updates to the default branch. Other
branch pushes, schedules, and manually created pipelines are intentionally excluded.

## What it runs

One `verify` job:

1. installs the exact frozen Python environment once;
2. checks Ruff formatting and lint;
3. validates contract schemas, the mixed eval catalog, current result hashes, and
   OWASP control evidence;
4. starts one temporary PostgreSQL service using a database whose name ends in
   `_test`;
5. upgrades and checks the Alembic schema; and
6. runs the complete pytest suite, including the explicit PostgreSQL integration
   tests and excluding live target execution.

The old automatic fake load benchmark, generated catalog/load artifacts, coverage
artifact, duplicate PostgreSQL jobs, dependency cache, and Docker-in-Docker image
build were removed. Railway already performs the production Dockerfile build.

## Storage and cleanup

The PostgreSQL service, its database, the Python environment, and the job workspace
are disposable and removed after the job. This pipeline declares no persistent
volume, GitLab cache, or artifact. The runner owner may retain generic base-image or
package layers outside the project for efficiency, subject to runner cleanup policy.

Job logs and pipeline metadata remain in GitLab according to the instance retention
policy. No CI-created database or image is pushed to Railway or a container registry.

## Making it an actual gate

An available GitLab runner is required. To prevent unverified Railway deployment,
protect `main`, require merge requests and successful pipelines, and let Railway
observe only the mirrored, accepted `main` commit. A direct push to `main` can trigger
CI, but CI then runs too late to prevent the GitHub mirror and Railway deployment.
