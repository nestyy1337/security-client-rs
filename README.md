# kibana-rs

An async Rust client for Kibana security operations and Fleet management. The optional browser workbench demonstrates the crate against a real Kibana instance.

The initial implementation targets traditional Kibana 9.x. It is an independent project, not an Elastic-supported client. It has not been published to crates.io.

## API coverage and compatibility

<!-- BEGIN API COVERAGE -->
Against the pinned traditional **9.5.4** bundle: **49/663 named operations** (7.4% endpoint breadth), **45 recorded exercises** on 9.5.4, and **no release-certified deployment profiles**. Recorded evidence is STALE for the current client/test inputs. Full contract parity remains unaudited.
<!-- END API COVERAGE -->

The [operation report](docs/api-coverage.md) lists every wrapper's official operation ID, contract limitations and recorded test evidence. The [coverage tracker](coverage/README.md) checks the report against a checksum-pinned upstream API bundle and the Rust source. CI does not equate a wrapper with complete parameter or response support.

The [deployment suite](tests/deployment/README.md) runs seven required scenarios against disposable **9.5.4** and **9.4.7** profiles, including a real Fleet Server and managed Agent. Images and signed packages are checksum-locked. GitHub Actions retains per-profile results and logs. These selected workflows are separate from full API contract parity and packaged-release certification. The older operation-level evidence above remains a historical record.

## Try the running workbench

On Szymon's Tailscale network: **http://homebox:8787**. The IP fallback is http://100.115.129.28:8787.

The workbench runs on homebox against a dedicated Elasticsearch/Kibana 9.5.4 stack. It can create and edit query detection rules, enable/disable them, manage security cases and notes, create agent policies, browse/install integrations, and assign integrations to policies. Changes are real, confined to this demonstration deployment. The initial rules and cases are labelled demonstration resources.

The app uses a Kibana user restricted to the `kibana-rs` space. Backend credentials never reach the browser. Network access is controlled by the existing tailnet policy; the demo has no separate browser login. It binds only to the host's Tailscale IP. Elasticsearch and Kibana themselves bind only to loopback on ports 19200 and 15601.

There are no enrolled agents or production events. Fleet Server provisioning, agent enrollment, and actual telemetry collection are outside this demonstration. No dashboard authoring APIs were implemented.

## Library

Use the local package as a dependency until it is published:

```toml
[dependencies]
kibana-rs = { path = "../kibana-rs" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use kibana_rs::{Auth, Client, PageOptions, security::{FindRules, QueryRule}};

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(std::env::var("KIBANA_URL")?)
        .auth(Auth::ApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?
        .space("soc")?;

    let rules = client.security().rules(&FindRules::default()).await?;
    let policies = client.fleet().agent_policies(&PageOptions::default()).await?;

    let request = QueryRule::new(
        "Failed authentication",
        "Review failed authentication events",
        "event.category: authentication and event.outcome: failure",
    );
    let rule = client.security().create_rule(&request).await?;
    assert!(!rule.enabled);
    Ok(())
}
```

The executable [security example](examples/security.rs) only reads rules and policies. Run it with `nix develop -c cargo run --example security`, supplying `KIBANA_URL`, `KIBANA_SPACE`, and either `KIBANA_API_KEY` or `KIBANA_USERNAME`/`KIBANA_PASSWORD`.

### Coverage

See the [generated inventory](docs/api-coverage.md) for current counts and per-operation limitations.

| Module | Included |
| --- | --- |
| `security()` | Query-rule creation, list/get/patch/delete, rule import/export, privilege inspection, alert-index initialization |
| `cases()` | Search/get/create/update/delete, comments, optimistic concurrency through case versions |
| `fleet()` | Agent policy CRUD/copy/download; package policy CRUD; integration catalogue/details/install/uninstall; agent list/get/reassign/unenroll; status and outputs |
| `spaces()` | Global space CRUD/list |
| `roles()` | Global role list/get/put/delete with Kibana privileges |

Stable resource fields have Rust types. Responses retain additional fields where they matter for extensibility. Integration input variables and Elasticsearch privilege definitions remain JSON because their schemas depend on the package or Elasticsearch. Query-rule creation supports KQL and Lucene. Other detection-rule types can be read, patched in common fields, imported/exported, or created through the raw request API; they do not yet have dedicated creation types.

Pagination is explicit. `rules`, `find`, and Fleet collection methods return one page and a total. Do not interpret the first page as the complete collection.

### Request behavior

- API key, Basic, and Bearer authentication; custom root certificates and headers; request/connect timeouts.
- Space selection shares the connection pool. Global routes remain global. URL construction preserves reverse-proxy base paths and encodes each resource identifier separately.
- No automatic redirects or retries. An interrupted mutation can have an unknown outcome and must be reconciled by the caller.
- JSON responses have a configurable 32 MiB default limit. Errors retain HTTP status, headers, and at most 16 KiB of body. Error bodies may contain operational data.
- Rule exports and policy downloads return streaming `reqwest::Response` values. Rule import preserves partial-failure results even on HTTP 200.
- `request(method, scope, segments)` exposes the configured HTTP client. Pass the resulting builder to `execute` for checked streaming responses or `json` for bounded decoding. It also supports endpoints without a named wrapper.

Date-based `elastic-api-version` headers can be supplied through `ClientBuilder::headers` when a particular deployment or endpoint requires one. No blanket Serverless compatibility is claimed.

## Run your own isolated demo

Requirements: Nix with flakes, Docker Compose, and a user systemd manager. Rootless Docker is detected. These scripts create only the `kibana-rs-demo` Compose project and `kibana-rs-demo.service`. Expect several GiB of memory and image storage.

```sh
nix develop -c bash deploy/start-stack.sh
KIBANA_RS_BIND="$(tailscale ip -4):8787" nix develop -c bash deploy/start-demo.sh
```

Omit `KIBANA_RS_BIND` to bind the workbench to `127.0.0.1:8787`. Do not bind this demonstration app to a public interface. The Tailscale deployment relies on the tailnet's existing access rules.

The scripts generate credentials under `~/.local/state/kibana-rs` with restricted file permissions. `KIBANA_RS_STATE_DIR` can override this directory. State is outside the checkout. The dedicated stack uses Basic licensing, keeps Elasticsearch data in a named Docker volume, and restarts its containers automatically. A user systemd service runs a separate copy of the release binary and restarts it after failure. Service installation uses the user's data directory rather than modifying a shared dotfiles checkout.

For the user service to start before login and survive logout, enable lingering with `loginctl enable-linger "$(id -un)"`. This is enabled on homebox. Reboot recovery has not been tested.

Package installation requires access to Elastic's package registry. The browser assignment form uses a package's default inputs. Packages requiring additional variables must be configured through the library or Kibana. Installing a package can install its bundled dashboard assets, even though this client provides no dashboard authoring API.

To stop the app, run `systemctl --user stop kibana-rs-demo`. To stop the dedicated containers without deleting data, use Docker Compose with `deploy/compose.yaml` and the generated `stack.env`. The scripts do not alter Tailscale policy or the existing T3 Serve configuration.

## Verification

Run local checks through the pinned Nix environment:

```sh
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --locked --all-features --all-targets -- -D warnings
nix develop -c cargo test --locked --all-features --all-targets
```

Run the full deployment suite, including provisioning, seeding, assertions and cleanup:

```sh
nix develop -c uv run python -u tests/deployment/run.py --profile 9.5.4-basic
nix develop -c uv run python -u tests/deployment/run.py --profile 9.4.7-basic
```

The runner requires Docker on Linux x86_64 and creates its own deployment. It verifies TLS, Basic/API-key permissions, security/case/Fleet lifecycles, pagination, real policy delivery, log ingestion and detection alerts. Every named test must run; ignored or zero-test results fail. Fresh volumes isolate each run. See the [suite documentation](tests/deployment/README.md) for requirements, profiles and artifact locations. Ordinary Cargo tests intentionally ignore these deployment scenarios.

Browser checks use the real workbench and create/delete their own test resources:

```sh
KIBANA_RS_DEMO_URL=http://homebox:8787 \
CHROME_BIN=/path/to/chrome \
KIBANA_RS_SCREENSHOTS=/tmp/kibana-rs-screenshots \
nix develop -c uv run --with playwright python -u tests/browser.py
```

The [Check workflow](.github/workflows/check.yml) runs formatting, linting, transport and runner tests, and API coverage checks. The [deployment workflow](.github/workflows/deployments.yml) runs both deployment profiles on main pushes, pull requests, manual dispatch and weekly. See [verification evidence](docs/verification.md) for historical demo results; browser checks do not replace crate deployment tests.

## Compatibility limits

The initial deployment matrix covers selected workflows on fresh self-managed 9.5.4 and 9.4.7 installations with Basic licensing. It does not cover 8.x, Serverless, Cloud Hosted, deployment upgrades, paid features, mixed-version agents, ARM or Fleet-managed binary upgrades. A release still needs verification against its packaged source and minimum Rust version. EQL/threshold rule builders, exception-list helpers, response actions, generic alerting, connectors, data views, and saved-object transfer remain outside this first implementation. The raw request API is available for those cases.

The [API investigation](research/api-feasibility.md) and [existing-client survey](research/existing-clients.md) preserve the pre-implementation findings. This code is handwritten; no upstream OpenAPI bundle, server source, or generated binding was copied into the crate. The initial research's future scope is superseded by this security/Fleet-first release.

Code is available under MIT or Apache-2.0. Kibana and Elasticsearch are Elastic trademarks; this project is not affiliated with Elastic.
