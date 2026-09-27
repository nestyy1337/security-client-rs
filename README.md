# kibana-rs

An async Rust client for Kibana security operations and Fleet management. The optional browser workbench demonstrates the crate against a real Kibana instance.

The initial implementation targets traditional Kibana 9.x. It is an independent project, not an Elastic-supported client. It has not been published to crates.io.

## API coverage and compatibility

<!-- BEGIN API COVERAGE -->
Against the pinned traditional **9.5.4** bundle: **78/663 named operations** (11.8% endpoint breadth), **45 recorded exercises** on 9.5.4, and **no release-certified deployment profiles**. Recorded evidence is STALE for the current client/test inputs. Full contract parity remains unaudited.
<!-- END API COVERAGE -->

The [operation report](docs/api-coverage.md) lists every wrapper's official operation ID, contract limitations and recorded test evidence. The [coverage tracker](coverage/README.md) checks the report against a checksum-pinned upstream API bundle and the Rust source. CI does not equate a wrapper with complete parameter or response support.

The [deployment suite](tests/deployment/README.md) runs ten required scenarios against disposable **9.5.4** and **9.4.7** profiles, including a real Fleet Server and two managed Agents. Images and signed packages are checksum-locked. GitHub Actions retains per-profile results and logs. These selected workflows are separate from full API contract parity and packaged-release certification. The older operation-level evidence above remains a historical record.

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
use kibana_rs::{
    Kibana,
    http::{Credentials, TransportBuilder, Url},
    security::{QueryRule, Severity},
};

async fn example() -> Result<(), Box<dyn std::error::Error>> {
    let transport = TransportBuilder::new(Url::parse(&std::env::var("KIBANA_URL")?)?)
        .auth(Credentials::EncodedApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?;
    let client = Kibana::new(transport).space("soc")?;

    let rules = client.security().find_rules().per_page(100).send().await?.json().await?;
    let policies = client.fleet().find_agent_policies().send().await?.json().await?;
    println!("{} rules, {} agent policies", rules.total, policies.total);

    let request = QueryRule::new(
        "Failed authentication",
        "Review failed authentication events",
        "event.category: authentication and event.outcome: failure",
    )
    .severity(Severity::High);
    let rule = client.security().create_rule(&request).send().await?.json().await?;
    assert!(!rule.enabled);
    Ok(())
}
```

The executable [security example](examples/security.rs) only reads rules and policies. Run it with `nix develop -c cargo run --example security`, supplying `KIBANA_URL`, `KIBANA_SPACE`, and either `KIBANA_API_KEY` or `KIBANA_USERNAME`/`KIBANA_PASSWORD`.

### Structure

The layout follows the official [Elasticsearch Rust client](https://github.com/elastic/elasticsearch-rs):

- `http::Transport` owns the connection pool, credentials, default headers, timeouts, TLS roots, proxy and response limit. `TransportBuilder` configures it; `Transport::cloud` resolves the Kibana endpoint from an Elastic Cloud ID. `Transport::send` is the single path every request takes.
- `Kibana` wraps a transport and an optional space. Namespace methods (`security()`, `cases()`, `exceptions()`, `fleet()`, `spaces()`, `roles()`) return endpoint builders.
- Each endpoint is its own builder type. Required path and body parameters are method arguments; optional parameters are setters. Every builder has `header()` and `request_timeout()` for per-request overrides and `send()`, which returns `Response<T>`.
- `Response<T>::json()` decodes into the endpoint's type. `json_as::<U>()`, `text()`, `bytes()` and `bytes_stream()` are always available. Endpoints without a body use `Response<Empty>`; NDJSON exports, YAML policies and diagnostic archives use `Response<Raw>`, which has no `json()`.
- Request bodies such as `QueryRule`, `NewCase`, `NewList` and `NewAgentPolicy` are builders. Create and replace endpoints accept any `Serialize` value, so rule types or fields without a typed builder can be sent as JSON.
- Response structs and the `Error` enum are `#[non_exhaustive]`. Most responses keep unmodeled fields in an `extra` map.
- reqwest is an implementation detail. Public HTTP types come from the `http` and `url` crates.

One deliberate difference from the Elasticsearch client: `send()` turns non-success statuses into `Error::Api` instead of returning them for the caller to check. A forgotten status check there turns a 403 into a confusing decode error.

### Coverage

See the [generated inventory](docs/api-coverage.md) for current counts and per-operation limitations. Every named endpoint has an offline wire-contract test that asserts its method, path, query and body against a recording mock; the coverage checker fails when one is missing.

| Namespace | Included |
| --- | --- |
| `security()` | Query-rule creation, find/get/patch/delete, rule import/export, privilege inspection, alert-index initialization |
| `cases()` | Find/get/create/update/delete, comments, optimistic concurrency through case versions |
| `exceptions()` | List/item CRUD and search; typed conditions; optimistic concurrency; duplicate/import/export and OS summaries |
| `fleet()` | Policies and packages; enrollment keys; individual/bulk agent operations; upgrades, diagnostics, action history and binary downloads; status and output listing |
| `spaces()` | Global space CRUD/list |
| `roles()` | Global role list/get/put/delete with Kibana privileges |

Stable resource fields have Rust types. Integration input variables and Elasticsearch privilege definitions remain JSON because their schemas depend on the package or Elasticsearch. Query-rule creation supports KQL and Lucene. Other detection-rule types can be read, patched through `PatchRule::field`, imported/exported, or created from JSON.

Pagination is explicit. `find_*` methods return one page and a total. Do not interpret the first page as the complete collection.

### Exceptions and agent operations

`client.exceptions()` manages detection exception lists and items. Entries support match, match-any, exists, wildcard, value-list references and nested conditions. `NamespaceType::Single` isolates lists to the selected Kibana space; `Agnostic` shares them across spaces. `update_list` and `update_item` require the opaque `_version` token from the last read, separately from the optional user-defined numeric version.

Attach `list.reference()` through `QueryRule::exceptions_list` or `PatchRule::exceptions_list`. Patching this array replaces all associations, so preserve the references you want to keep. An empty array detaches every list. Exception import preserves per-object errors even on HTTP 200. Export requires both the saved-object ID and `list_id`, provided by `ListReference`. Imports can regenerate saved-object IDs; read back by `list_id`/`item_id` before reusing references. Referenced value-list contents need separate management and are not included in exports. Kibana's OS summary can report zero without OS-labelled items; `find_items().total` is the item count.

Fleet bulk methods accept explicit IDs or a KQL query through `AgentSelection`. `dry_run(true)` returns the selected count. Dry runs do not validate every agent's eligibility. Actual submissions return an action ID; inspect `agent_action_status()` for completion, failure counts and sampled errors, then verify the agent state. Action-history pages start at zero; collection pages start at one. Fleet wraps single resources as `{"item": ...}`, so those endpoints decode into `Item<T>`.

Enrollment keys support policy selection, names, expiry, listing and revocation. Their `Debug` output redacts credentials. Revoking an enrollment key does not unenroll existing agents. Diagnostics requests are asynchronous: correlate the action ID with `list_agent_uploads()`, wait for `READY`, then download with `download_agent_file()`. Diagnostic archives can contain sensitive configuration.

Upgrade and cancellation methods have wire-contract tests, but the container fixture cannot prove a successful binary upgrade. Cancellation applies to upgrades and unenrollment, not arbitrary actions. Scheduled upgrade behavior and successful cancellation need a service-installed Agent and the relevant license profile. See the [contract research](research/fleet-agent-operations.md) and [deployment test limits](tests/deployment/README.md).

### Request behavior

- API key (encoded or ID/secret), Basic and Bearer credentials; additional root certificates; transport-wide and per-request headers and timeouts; explicit or disabled proxies. Proxy environment variables are honored unless `disable_proxy()` is set.
- Space selection shares the connection pool. Global routes remain global. URL construction preserves reverse-proxy base paths and percent-encodes each path segment separately.
- No automatic redirects or retries. An interrupted mutation can have an unknown outcome and must be reconciled by the caller.
- `json()`, `bytes()` and `text()` stop at a configurable 32 MiB limit; `bytes_stream()` is unbounded. Errors retain HTTP status, headers, and at most 16 KiB of body; `Error::message()` extracts Kibana's `message` field. Error bodies may contain operational data and are kept out of `Display`.
- Invalid path segments and body serialization failures are reported by `send()` before any request is made.
- `Kibana::request(method, scope, segments)` builds a request to any route without a named builder. `Transport::send` accepts a pre-encoded path for full control.

Date-based `elastic-api-version` headers can be set on the transport or per request when a deployment or endpoint requires one. No blanket Serverless compatibility is claimed.

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

The initial deployment matrix covers selected workflows on fresh self-managed 9.5.4 and 9.4.7 installations with Basic licensing. It does not cover 8.x, Serverless, Cloud Hosted, deployment upgrades, paid features, mixed-version agents, ARM or Fleet-managed binary upgrades. A release still needs verification against its packaged source and minimum Rust version. EQL/threshold rule builders, value-list storage management, Endpoint artifact-specific validation, response actions, generic alerting, connectors, data views, and saved-object transfer remain outside this implementation. The raw request API is available for those cases.

The [API investigation](research/api-feasibility.md) and [existing-client survey](research/existing-clients.md) preserve the pre-implementation findings. This code is handwritten; no upstream OpenAPI bundle, server source, or generated binding was copied into the crate. The initial research's future scope is superseded by this security/Fleet-first release.

Code is available under MIT or Apache-2.0. Kibana and Elasticsearch are Elastic trademarks; this project is not affiliated with Elastic.
