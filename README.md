# kibana-rs

An async Rust client for the Kibana HTTP API, focused on security operations: detection rules, exception lists, cases, Fleet, spaces and roles.

The project is pre-1.0. It is not affiliated with or supported by Elastic.

## Coverage

<!-- BEGIN API COVERAGE -->
78 of the 663 operations in the Kibana 9.5.4 OpenAPI bundle have named builders. See the [coverage report](docs/api-coverage.md) for each builder's route and known limits.
<!-- END API COVERAGE -->

| Namespace | Endpoints |
| --- | --- |
| `security()` | Detection rules: find, get, create, patch, delete, import, export; privileges; alert index setup |
| `exceptions()` | Exception lists and items: CRUD, search, summary, duplicate, import, export |
| `cases()` | Cases: find, get, create, update, delete; comments |
| `fleet()` | Agent and package policies, packages, enrollment keys, agents, bulk agent actions, diagnostics, action status, outputs |
| `spaces()` | Space CRUD |
| `roles()` | Role CRUD |

Routes without a named builder are reachable through `Kibana::request`.

## Installation

```toml
[dependencies]
kibana-rs = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Usage

```rust
use kibana_rs::{
    Kibana,
    http::{Credentials, TransportBuilder, Url},
    security::{QueryRule, Severity},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let transport = TransportBuilder::new(Url::parse("https://kibana.example:5601")?)
        .auth(Credentials::EncodedApiKey(std::env::var("KIBANA_API_KEY")?))
        .build()?;
    let client = Kibana::new(transport).space("soc")?;

    let rules = client.security().find_rules().per_page(100).send().await?.json().await?;
    println!("{} rules", rules.total);

    let rule = QueryRule::new("Failed logins", "Repeated authentication failures", "event.outcome: failure")
        .severity(Severity::High);
    let created = client.security().create_rule(&rule).send().await?.json().await?;
    println!("created disabled rule {}", created.rule_id);
    Ok(())
}
```

More examples are in [examples/](examples/).

## How the client works

- `http::Transport` holds the connection pool, credentials, default headers, timeouts, trusted roots, proxy and response size limit. `Transport::cloud` connects with an Elastic Cloud ID.
- Namespace methods on `Kibana` return one builder per endpoint. Required parameters are arguments; optional ones are setters. Every builder also has `header()` and `request_timeout()`.
- `send()` returns `Response<T>`, and `json()` decodes into the endpoint's type. `text()`, `bytes()`, `bytes_stream()` and `json_as::<U>()` are always available. Exports and downloads return `Response<Raw>`.
- Create endpoints accept any `Serialize` body, so rule types and fields without a typed builder can be sent as JSON. A body whose extension map repeats a modeled field, such as `id`, is rejected rather than sent with two identities.
- Existing exception lists and items are changed through `list.edit()` and `item.edit()`, which start from the retrieved state and bind its ID, namespace and concurrency token. Comments are append-only: `add_comment` sends only the new comment. Retrieved lists and items can be passed to `get_*`, `delete_*` and `find_items`, which then use their namespace.
- Package policies are edited in Fleet's full format with `policy.edit()`, which keeps the editable inputs and requires a concurrency token, or replaced with a simplified definition through `NewPackagePolicy::replacing`. Creation and simplified replacement responses must be fetched with `get_package_policy` before editing.
- Agent policies use `policy.edit()?` and `fleet.edit_agent_policy(&edit)` to retain their inactivity timeout and change selected settings. `data_output_id(id)` selects an output; `clear_data_output_id()` sends null to restore Fleet's default. Unset optional fields keep their server values. Agent-policy updates have no concurrency check.
- Headers are combined once per request: built-in defaults and credentials, transport headers, the body's `Content-Type`, then per-request headers. Each stage replaces every earlier value of a name it sets.

Case updates accept extra fields through `CasePatch::field`, which rejects `id`
and `version` so the patch keeps its resource identity and concurrency token.
Checked rule patch fields also reserve selectors. Space updates require a body
`id` matching the URL; generic agent-policy updates allow `id` to be omitted,
but reject a conflicting or non-string value before HTTP.
Extension fields must be supported by the target Kibana version.

Every named builder has `into_request()` to preserve its route, scope and settings
while adding options through the raw request interface. Replacing the raw body
with `Request::json` or `Request::body` does not reapply the builder's identity
or concurrency checks. Earlier construction errors still fail at `send`.
`Request::query` appends parameters; avoid adding a second value for an existing
selector or other single-valued option. `unchecked_field` and raw replacements
leave these guarantees to the caller.

## Behavior to know

- Requests are never retried and redirects are never followed.
- `Kibana::space` scopes space-aware routes to `/s/{space}`. Space, role and status routes are always global.
- `find_*` methods return one page and a total. `pages()` and `items()` stream the whole collection, one request per page, and fail with `Error::UnexpectedPage` if Kibana returns a different page than requested. `bounded_pages(n)` and `bounded_items(n)` read at most `n` pages and end with `Error::PageLimit` when more remain. Kibana pages by offset, so concurrent changes can skip or repeat items, and most collections stop at 10,000 results.
- Detection rule schedules use `RuleSchedule`, which derives the lookback (`from`) from the interval so consecutive runs cannot leave gaps. `custom_schedule` sets raw date math.
- Cases and exception lists use optimistic concurrency. Pass the latest `version` or `_version`; stale values fail with HTTP 409.
- Rule and exception imports report typed per-object failures inside an HTTP 200 response. Rule-import `success` covers rules only; check `exceptions_success`, `action_connectors_success` and their error arrays separately.
- Fleet wraps single resources as `{"item": ...}`, so those endpoints decode into `Item<T>`. Fleet collections count pages from 1; action status counts from 0.
- Fleet agent actions are asynchronous. `Fleet::wait_for_action`, `wait_for_upload` and `wait_for_agent_policy` enforce an overall deadline, including requests and body reads, and retain the last observed state on timeout. Zero timeout sends no request. A resource that disappears after being seen ends the wait as `WaitOutcome::Vanished`. Action states Kibana adds later are kept as `Unknown` and end the wait for inspection. A finished action can still report failed agents. Action lookup searches up to 10,000 recent action documents; older actions may remain outside that window.

## Error handling and recovery

Non-success responses become `Error::Api` with the status, headers and up to 16 KiB of body. `Error::message()` returns Kibana's message and `Error::retry_after()` the `Retry-After` delay. When a successful response's body is interrupted or exceeds the limit, `Error::Body` and `Error::ResponseTooLarge` keep its status and headers, available through `Error::status()` and `Error::headers()`.

Bodies may contain operational data and are never printed by `Display` or `Debug`. Neither are response values quoted by decoding errors, query values, or Fleet policy variables; `DecodeError::inner()` returns the full serde error deliberately.

`Error::Decode` reports the JSON error category, line and column through
`DecodeError`, including when logging the error's source chain. The original
Serde message can contain response values and is available explicitly through
`DecodeError::as_serde_error`. Response `Debug` output omits query values.

The client does not retry, because whether a retry is safe depends on the request:

- Reads can be retried on 429, 502, 503 and transport failures, honoring `Retry-After`, with backoff and an overall deadline.
- A mutation interrupted by a timeout or dropped connection, including while its response body is read, may or may not have been applied. Read the resource back by a stable identifier, such as a rule's `rule_id` or a list's `list_id`, before trying again. A successful status on `Error::Body` shows Kibana accepted the request, not what it did.
- On HTTP 409, read the resource again to get its current version and reapply the change.

[examples/recovery.rs](examples/recovery.rs) implements these patterns. [examples/pagination.rs](examples/pagination.rs) and [examples/transfer.rs](examples/transfer.rs) show collection streams and export and import with partial failures.

## Tracing

The optional `tracing` feature emits debug events under the `kibana_rs` target with the endpoint name, method, path, status, duration and any `X-Opaque-Id` header. A request emits one event when successful response headers arrive or when it fails, and reading a successful body with `bytes`, `text` or `json` emits a second event when the body is complete, interrupted or too large. Streamed or unread bodies emit no body event. A response that does not match the expected type is also reported. Query values, bodies, credentials and other headers are never recorded.

```toml
kibana-rs = { version = "0.1", features = ["tracing"] }
```

## Compatibility

The initial supported targets are self-managed Kibana 9.5.4 and 9.4.7 with a Basic
license on Linux x86_64. Each release must pass both pinned deployment profiles.
Other patches within those minor versions are expected to be similar but are
not certified by those runs. 8.x, Serverless, Elastic Cloud, paid features and
stack upgrades are outside the tested scope. The minimum Rust version is 1.88.

The [supported workflow review](docs/supported-contracts.md) records the checked
request and response subsets and their remaining limits. New Kibana versions
enter the support list only after their contracts are reviewed and a deployment
profile passes. Removing a supported minor or raising the Rust minimum requires
a new minor crate version and a changelog entry. Patch releases keep the documented
Rust interface compatible; before 1.0, minor releases may change it.

Use a dedicated service identity for detection-rule automation. Rule creation
and updates capture the caller's privileges for execution, so credential rotation
and privilege changes also need rule-level verification. See
[Elastic's detection API authentication notes](https://www.elastic.co/docs/api/doc/kibana/group/endpoint-security-detections-api).

## Development

```sh
cargo test --workspace --all-targets --all-features
```

Offline tests check every builder's method, path, query and body against a recording mock server. Live tests run against disposable Elastic Stack deployments; see [tests/deployment](tests/deployment/README.md). The [coverage report](docs/api-coverage.md) is generated and checked by `tools/api_coverage.py`; see [coverage](coverage/README.md).

A Nix flake provides the toolchain for those who use it.

[Release steps](docs/releasing.md) cover package verification, version tags and
publication. Before registry publication, use a Git dependency pinned with `rev`
to the reviewed commit.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.

Kibana and Elasticsearch are trademarks of Elasticsearch B.V.
