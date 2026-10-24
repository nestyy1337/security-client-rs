# security-client-rs

An async Rust client for the Kibana HTTP API, focused on security operations: detection rules, exception lists, cases, Fleet, spaces and roles.

The project is pre-1.0. It is not affiliated with or supported by Elastic.

## Coverage

<!-- BEGIN API COVERAGE -->
78 of the 663 operations in the Kibana 9.5.5 OpenAPI bundle have named builders. See the [coverage report](coverage/README.md) for each builder's route and known limits.
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
security-client-rs = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The optional `tracing` feature emits a debug event per request with the endpoint, method, path, status and duration. Bodies, query values and credentials are never recorded.

## Usage

```rust
use security_client_rs::{
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

| Task | Example |
| --- | --- |
| List detection rules and agent policies | [security.rs](examples/security.rs) |
| Read collections across pages | [pagination.rs](examples/pagination.rs) |
| Export and import, including partial failures | [transfer.rs](examples/transfer.rs) |
| Retry reads and reconcile uncertain writes | [recovery.rs](examples/recovery.rs) |

The [API documentation](https://docs.rs/security-client-rs) covers each module's workflows and Kibana's quirks: concurrency tokens, partial import failures, Fleet's asynchronous actions and policy formats.

## Behavior to know

- Requests are never retried and redirects are never followed. See the crate documentation for which errors are safe to retry.
- `Kibana::space` scopes space-aware routes to `/s/{space}`. Space, role and status routes are always global.
- `find_*` methods return one page. `pages()` and `items()` stream the whole collection; Kibana pages by offset, so concurrent changes can skip or repeat items.
- Rule and exception imports report per-object failures inside an HTTP 200 response.
- Cases and exception lists use optimistic concurrency; stale versions fail with HTTP 409. Fleet agent-policy updates have no concurrency check.

## Compatibility

Tested against self-managed Kibana 8.19.23, 9.0.8, 9.1.10, 9.2.8, 9.3.8, 9.4.8 and 9.5.5 with a Basic license on Linux x86_64. Other patches of those minor versions are expected to work but are not tested. Earlier 8.x minors, Serverless, Elastic Cloud and paid features are out of scope. The minimum Rust version is 1.88.

Rule creation and updates capture the caller's privileges for execution, so use a dedicated service identity for detection-rule automation. See [Elastic's detection API authentication notes](https://www.elastic.co/docs/api/doc/kibana/group/endpoint-security-detections-api).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests, the live deployment suite and the coverage tooling.

## License

Copyright (c) 2026 security-client-rs contributors.

Licensed under the [Apache License 2.0](LICENSE-APACHE).

Kibana and Elasticsearch are trademarks of Elasticsearch B.V.
