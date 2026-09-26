# Disposable deployment tests

Run one checked-in profile from the repository root:

```sh
nix develop -c uv run python -u tests/deployment/run.py --profile 9.5.4-basic
nix develop -c uv run python -u tests/deployment/run.py --profile 9.4.7-basic
```

The initial profiles require Linux x86_64, Docker with Compose v2, at least 8 GiB available RAM and about 15 GiB free disk for images, build output and test data. The Nix shell supplies Rust, uv, OpenSSL and curl. On other Linux installations, supply those tools and run the command without `nix develop -c`. The runner uses `DOCKER_HOST`, or detects the user's rootless Docker socket.

No existing Kibana deployment or credentials are required. Each run owns a random Compose project, temporary credentials and CA, and new Elasticsearch/Agent volumes. The runner deletes its containers, networks, volumes and credentials after success, test failure or SIGINT/SIGTERM. It verifies that the project's resources are gone. SIGKILL, a host crash or a dead Docker daemon can prevent cleanup; the report includes the exact project name for recovery. It never runs a global Docker prune.

Ordinary `cargo test` ignores the ten real-deployment scenarios. This runner verifies the complete test inventory, invokes each named scenario and checks that one test actually passed. Missing environment, zero tests, ignored tests, setup failure and cleanup failure cannot produce a passing deployment result.

## What runs

| Scenario | Assertions |
| --- | --- |
| Detection lifecycle | Rule CRUD, export/import including partial errors, privilege read, alert-index initialization, space isolation |
| Cases | CRUD, comments, version conflicts |
| Fleet configuration | Agent policy CRUD/copy/download, integration catalogue/details/install, package policy CRUD, outputs and agent status |
| Roles and spaces | Global role administration, space privilege round trip, space CRUD |
| Exceptions | List/item CRUD, optimistic concurrency conflicts, space isolation and agnostic sharing, pagination, duplicate/import/export, partial import errors and rule associations |
| Enrollment keys | Create with expiry, get/list/paginate, revoke and verify inactive state |
| Agent operations | Bulk tag changes, dry-run counts, reassignment acknowledgment, mixed success/failure across two real agents, diagnostics download, container upgrade rejection |
| TLS and permissions | Untrusted CA rejected, trusted CA accepted, Basic and API-key identities, bad credentials rejected, read-only rule/exception/Fleet mutations denied, cross-space and role administration denied |
| Pagination | Three owned rules retrieved across two pages without loss or duplicates |
| Managed Agent | Enrollment and identity preserved across restart, integration policy acknowledgment, synthetic log ingestion, exception suppresses an alert after successful rule execution, detaching it permits detection, policy revision acknowledgment, reassignment, bulk unenrollment, package uninstall |

Upgrade scheduling/cancellation wire tests cover request encoding and runtime response envelopes. The deployment profile verifies container upgrade rejection, not successful upgrades or cancellation. Bulk diagnostics currently has a real dry-run check; single-agent diagnostics verifies the full download workflow.

Bootstrap uses direct documented APIs. Assertions exercise the public Rust crate; Elasticsearch searches independently verify ingestion and alert creation. Agent readiness checks require the expected policy ID, exact revision and online status. Polling has deadlines and does not retry uncertain writes.

## Reproducibility

Profiles pin every container by digest and every integration ZIP and signature by SHA-256. Elasticsearch, Kibana, Fleet Server and Agent use the same exact patch. The profiles use a Basic license and fresh data, not a trial or an upgrade from older saved objects.

Before starting the isolated network, the host downloads only the exact locked package URLs. Changed bytes fail checksum validation. Elastic Package Registry serves those signed archives locally with signature verification enabled. The small registry image follows Elastic's [documented local-package mode](https://github.com/elastic/package-registry/blob/v1.40.0/README.md#testing-service-with-local-packages). It avoids the 24.5 GB unpacked `lite-9.5.4` distribution.

Elasticsearch, Kibana, EPR, Fleet Server and Agent attach only to an internal Docker network. A digest-pinned HAProxy gateway exposes fixed TCP destinations on random loopback ports for host tests. It passes TLS through. It is the only container attached to the access network. This follows Docker's [separate frontend/internal network topology](https://docs.docker.com/engine/network/). The fixture cannot fall back to the public package or artifact registries during tests. Image/package acquisition and Cargo compilation still need network access before the deployment is ready.

IDs and credentials are unique per run; the log timestamp is current so scheduled detection can process it. Assertions compare semantic fields and sets, not complete snapshots of generated timestamps, UUIDs or background state.

To add a version, add a profile with verified image digests and compatible signed package checksums, then add it to `.github/workflows/deployments.yml`. Run the full fixture. Never resolve `latest` during a compatibility test.

## Results and limits

Results default to `$XDG_STATE_HOME/security-client-tests`, or `~/.local/state/security-client-tests`. `--artifacts PATH` chooses a different parent. Every run writes a JSON report, scenario logs, service logs and a cleanup log. The report records the source commit and dirty flag, client/test and fixture hashes, API snapshot hash, locked profile, timing, individual outcomes and cleanup result. Known credentials and labelled credentials are redacted. Temporary private keys are not copied into artifacts.

GitHub Actions runs both profiles on pushes to main, pull requests, manual dispatch and weekly. Each profile has an independent job; failures retain artifacts for 14 days. Fast transport tests, fixture-runner tests, formatting, linting and coverage checks run separately. A successful ordinary Cargo job alone is not deployment compatibility evidence.

The disposable GitHub runner removes its unused Android and .NET SDKs before pulling images. Without that step, Agent image extraction pushed the runner below Elasticsearch's default high disk watermark and blocked allocation of Fleet's primary shard. Elasticsearch's disk protection stays enabled. On a local machine, leave enough free space after pulling images to remain below the default 85% low watermark.

These workflows exercise selected contracts on clean self-managed deployments. They do not certify every upstream API field, paid features, Serverless, Cloud Hosted, 8.x, deployment upgrades, mixed-version agents, ARM, Elastic Defend or Fleet-managed binary upgrades. Container Agents cannot perform the latter; that needs a future VM fixture. A release must run the matrix against its exact packaged source and declared Rust minimum before claiming release certification.

The [upstream research](../../research/reproducible-deployments.md#what-the-official-rust-client-actually-does) records which testing patterns came from `elastic/elasticsearch-rs` and why its old YAML generator was not copied.
