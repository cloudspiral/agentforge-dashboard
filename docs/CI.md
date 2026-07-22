# GitLab CI verification check

GitLab CI verifies the accepted repository state. It does **not** deploy AgentForge.
Production deployment follows the independent GitLab-to-GitHub mirror and Railway's
GitHub `main` integration.

## When it runs

The pipeline runs only for updates to the protected default branch. Merge-request
pipelines, other branch pushes, schedules, and manually created pipelines are
intentionally excluded.

Gauntlet's only available shared runner is administrator-managed and configured as a
protected runner. GitLab therefore prevents it from executing jobs from ordinary,
unprotected merge-request branches. Restricting this project to the protected default
branch avoids hour-long stuck jobs and misleading failure notifications.

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

## Pre-merge gate limitation

This check runs after `main` changes, so it cannot stop that commit from being mirrored
to GitHub or deployed by Railway. A true pre-merge gate requires an online runner that
is permitted to execute unprotected merge-request refs. That capability must be
provided by the GitLab administrator or by an independently hosted project runner.
Once available, merge-request workflow rules and the GitLab "Pipelines must succeed"
merge check can be enabled.
