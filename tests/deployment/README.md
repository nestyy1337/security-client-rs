# Live deployment tests

`run.py` starts a disposable Elastic Stack, runs the ignored tests in `tests/live.rs` and `tests/deployment.rs` against it, and removes everything afterwards.

```sh
uv run python -u tests/deployment/run.py --profile 9.5.4-basic
uv run python -u tests/deployment/run.py --profile 9.4.7-basic
```

Requirements: Linux x86_64, Docker with Compose v2, a Rust toolchain, uv, OpenSSL and curl. Plan for 8 GiB of free memory and 15 GiB of disk. The runner uses `DOCKER_HOST` or the user's rootless Docker socket.

## What a run does

1. Downloads the profile's pinned integration packages and verifies their checksums.
2. Starts Elasticsearch, Kibana, a local package registry, Fleet Server and two Elastic Agents on an internal network. A gateway exposes them on random loopback ports.
3. Creates per-run credentials, a TLS CA, a restricted space, users and an API key.
4. Runs every scenario and fails if any expected test is missing, ignored or did not run.
5. Deletes the Compose project, its volumes and credentials, and verifies they are gone.

| Scenario | Checks |
| --- | --- |
| Detection rules | CRUD, export and import with partial failures, privileges, alert index, space isolation |
| Cases | CRUD, comments, version conflicts |
| Fleet configuration | Agent and package policies, packages, outputs, agent status |
| Roles and spaces | Global role administration, space privileges, space CRUD |
| Exceptions | List and item CRUD, concurrency conflicts, space isolation, shared lists, pagination, duplicate, import, export, rule associations |
| Enrollment keys | Create with expiry, list, paginate, revoke |
| Agent operations | Bulk tags, dry runs, reassignment across two agents with partial failure, diagnostics download, upgrade rejection |
| TLS and permissions | Untrusted CA rejected, Basic and API key identities, denied writes and cross-space access |
| Pagination | Rules retrieved across pages without loss or duplicates |
| Managed agent | Policy delivery, log ingestion, alert suppression by an exception, reassignment, unenrollment, package removal |

## Profiles

Each file in `profiles/` pins every container image by digest and every package by SHA-256, and uses a Basic license on fresh data. To add a version, create a profile with verified digests and checksums and add it to `.github/workflows/deployments.yml`.

## Results

Each run writes a JSON report, per-scenario logs, service logs and a cleanup log under `$XDG_STATE_HOME/security-client-tests`, or the directory given with `--artifacts`. Credentials are redacted. CI runs both profiles and keeps artifacts for 14 days.

## Limits

Container agents cannot be upgraded through Fleet, so successful upgrades and upgrade cancellation are not covered. Paid features, Elastic Defend, Serverless, Elastic Cloud, 8.x and stack upgrades are not covered.
