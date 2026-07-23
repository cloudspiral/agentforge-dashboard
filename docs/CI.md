# GitLab CI pre-merge gate

GitLab CI verifies proposed repository changes before they can merge. It does **not**
deploy AgentForge.
Production deployment follows the independent GitLab-to-GitHub mirror and Railway's
GitHub `main` integration.

## When it runs

The pipeline runs when a merge request is opened or updated. Ordinary branch pushes
without an open merge request, accepted `main` updates, schedules, and manually
created pipelines are intentionally excluded, so the full gate runs once per proposed
revision rather than again after merge.

Gauntlet's only available shared runner is administrator-managed and configured as a
protected runner. Both `main` and the trusted `codex/*` source-branch namespace are
protected for this project, and protected-resource access is enabled for merge-request
pipelines. GitLab can therefore assign these jobs to the runner without exposing it to
untrusted refs. New working branches must use the `codex/*` namespace or receive an
equivalent explicit protected-branch rule before opening a merge request.

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

## Enforcement and deployment boundary

GitLab protects `main` from direct pushes and requires the latest merge-request
pipeline to succeed. A failed or pending job leaves the merge request open but blocks
the merge; a successful job permits a Maintainer to merge it. Skipped pipelines are
not considered successful.

After a successful human-approved merge, GitLab's push mirror updates GitHub `main`.
Railway watches that GitHub branch and performs the production build and deployment.
The GitLab job never writes to Railway, GitHub, production PostgreSQL, or the Clinical
Co-Pilot target.
