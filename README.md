# kibana-rs

An async Rust client for the Kibana HTTP API, focused on security operations: detection rules, exception lists, cases, Fleet, spaces and roles.

The project is pre-release and not yet published on crates.io. It is not affiliated with or supported by Elastic.

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
kibana-rs = { git = "https://github.com/nestyy1337/security-client-rs" }
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

A [runnable example](examples/security.rs) reads rules and agent policies.

## How the client works

- `http::Transport` holds the connection pool, credentials, default headers, timeouts, trusted roots, proxy and response size limit. `Transport::cloud` connects with an Elastic Cloud ID.
- Namespace methods on `Kibana` return one builder per endpoint. Required parameters are arguments; optional ones are setters. Every builder also has `header()` and `request_timeout()`.
- `send()` returns `Response<T>`, and `json()` decodes into the endpoint's type. `text()`, `bytes()`, `bytes_stream()` and `json_as::<U>()` are always available. Exports and downloads return `Response<Raw>`.
- Create and replace endpoints accept any `Serialize` body, so rule types and fields without a typed builder can be sent as JSON.
- Non-success statuses become `Error::Api`, which keeps the status, headers and up to 16 KiB of body. `Error::message()` returns Kibana's error message.

## Behavior to know

- Requests are never retried and redirects are never followed. A mutation interrupted by a timeout or connection failure may or may not have been applied.
- `Kibana::space` scopes space-aware routes to `/s/{space}`. Space, role and status routes are always global.
- `find_*` methods return one page and a total. Fleet collections count pages from 1; Fleet action status counts from 0.
- Cases and exception lists use optimistic concurrency. Pass the latest `version` or `_version`; stale values fail with HTTP 409.
- Rule and exception imports report per-object failures inside an HTTP 200 response.
- Fleet wraps single resources as `{"item": ...}`, so those endpoints decode into `Item<T>`.

## Compatibility

Tested against self-managed Kibana 9.5 and 9.4 with a Basic license. 8.x, Serverless, Elastic Cloud and paid features are not tested. The declared minimum Rust version is 1.88.

## Development

```sh
cargo test --workspace --all-targets
```

Offline tests check every builder's method, path, query and body against a recording mock server. Live tests run against disposable Elastic Stack deployments; see [tests/deployment](tests/deployment/README.md). The [coverage report](docs/api-coverage.md) is generated and checked by `tools/api_coverage.py`; see [coverage](coverage/README.md).

A Nix flake provides the toolchain for those who use it.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.

Kibana and Elasticsearch are trademarks of Elasticsearch B.V.
