# kibana-rs

Research and proposal for a Rust client for Kibana's public HTTP APIs.

Status as of 2026-09-26: local Git repository with research only. There is no Rust implementation, Cargo project, generated client, or published package.

## Recommendation

Proceed with a focused, typed automation client. A solid first release is plausible for one maintainer if it has a small compatibility matrix and publishes its omissions. Supporting every Kibana feature would turn this into a much larger project.

I interpret the intended scope as reliable common operations, with specialist features allowed to remain missing. I would not assume Fleet, Security, or reporting are unimportant to everyone. Add those when there is a concrete consumer and someone can test them.

The reason to build is a reusable Rust API for application code, with predictable errors, streaming transfers, and tested version support. HTTP wrappers alone would offer little over existing tools. Technical feasibility is supported by this research; broad market demand is not established.

## Existing alternatives

| Project | What it tells us |
| --- | --- |
| [`kibana-sync`](https://crates.io/crates/kibana-sync), Rust, 0.4.1 | Already solves artifact synchronization and exposes reusable components. Prefer it if the need is moving saved objects or related artifacts. Its ETL model does not cover the proposed general alerting, connector, and data-view client. |
| [`kibana-py`](https://pypi.org/project/kibana-py/), Python, 0.6.0 | A broad community client already exists. Its published testing policy is a useful maintenance model. Rust would need to justify itself through integration and typed behavior, not novelty. |
| [Elastic Terraform provider](https://github.com/elastic/terraform-provider-elasticstack/tree/main/generated/kbapi), Go | Strong evidence that curated generation works, but requires an allowlist and ongoing schema repairs. |
| [`go-kibana-rest`](https://github.com/disaster37/go-kibana-rest), Go | A narrower client, with 25 operations across seven groups in the inspected source and a stated 7.x/8.x target. |

See [the client comparison](research/existing-clients.md) for source-level coverage, activity, test evidence, and limitations. Version numbers above were checked in package registries on the research date.

## Proposed first release

Aim for roughly 45 to 60 deliberately selected operations, not an arbitrary percentage of Kibana. The final count depends on which rule controls and data-view helpers earn a place.

| Area | First release |
| --- | --- |
| Connection | API key, Basic, and caller-supplied Bearer credentials; TLS and custom CA support; timeouts; proxy base paths; global and space-scoped requests |
| Status and spaces | Status, space CRUD, and a small set of object-transfer helpers |
| Data views | CRUD, default data view, and runtime fields |
| Saved objects | Streaming export, multipart import, import-error resolution, and full partial-failure results |
| Alerting | Rule CRUD/list, rule types, enable/disable, selected mute/snooze controls, and API key refresh |
| Connectors | CRUD/list, connector types, and execution; extensible configuration and secret payloads |
| Roles | Core Kibana role administration |
| Unsupported operations | An explicit raw-request API using the same authentication, routing, and error handling |

Dashboard transfer is covered by saved-object export/import. New dashboard authoring is a later, 9.5-specific addition. Generic saved-object CRUD is deprecated, and the main OpenAPI bundle lacks the full dashboard schemas. Neither should form the foundation of a new authoring API. [API investigation](research/api-feasibility.md).

Cases and Security detection rules are sensible next modules if incident automation is the intended consumer. Security detection rules are distinct from generic Kibana alerting rules and need their own models and tests. Fleet can follow as a separate demand-driven addition.

Defer Serverless certification, 8.x support, detailed Lens authoring, reporting, Synthetics, APM, ML, AI/agent features, and private UI endpoints. Elasticsearch search/indexing and OpenSearch Dashboards belong outside this project's initial scope. A CLI and a desired-state reconciliation engine would also be separate work.

## Rust approach

Use an async library with `reqwest` and `serde`, one shared connection pool, and small domain modules. Keep deployment configuration and space selection explicit. Do not introduce a pluggable transport framework or a blocking API until a consumer needs one.

Write the initial public request and response types deliberately. Type stable resource fields and operation results; leave plugin-specific rule parameters and connector configuration extensible through JSON or caller-defined serializable types. Distinguish absent fields from explicit null when update semantics require it. Response decoding must tolerate new fields and unknown extensible values without silently discarding failure details.

Centralize URL encoding, base paths, headers, authentication, cancellation, and error preservation. Treat export as bytes or a stream. A raw request must support non-JSON bodies and responses and make global versus space routing explicit. Do not retry potentially mutating operations automatically after an ambiguous failure.

Use release-pinned OpenAPI files to inventory and review upstream changes. Evaluate generation for selected internal models later. Keep generated names and schema quirks out of the public Rust interface, and do not require downstream users to fetch specifications or run a generator during their build.

Generation is not proven yet. The main 9.5.4 specification contains 663 operations, schema composition, multipart uploads, several response formats, and incomplete dashboard entries. Specification reuse permissions also need resolution before distributing copied or generated material. [Measured findings and sources](research/api-feasibility.md).

## Compatibility and maintenance

Begin with traditional Kibana 9.5, using 9.5.4 as the initial test target. Certify the chosen common operations on 9.4.7 next. Publish the exact versions tested and endpoint availability. Do not turn two successful test targets into a promise that every patch and minor works.

For each upstream release, review specification and release-note differences, run the compatibility matrix, and update the support table. Adding a module also adds its integration tests and maintenance commitment. Experimental APIs should be explicitly opt-in; raw access is not a claim that an unsupported endpoint works.

The meaningful release checks would be:

- Create, read, update, and delete resources in an isolated space against real Elasticsearch and Kibana instances.
- Export and reimport objects with references, conflicts, and partial failures.
- Verify authentication and permissions with ordinary scoped credentials, not only an administrator.
- Exercise reverse-proxy prefixes, global versus space routing, pagination, streaming, malformed/non-JSON errors, and ambiguous request failures.
- Confirm forward-compatible response decoding and run the exact documented server versions before release.

These are proposed checks. None has been run for this repository because implementation has not started.

## Effort estimate

These are planning estimates for one experienced Rust engineer working focused days. They are not measurements from a prototype, and AI assistance is not assumed to eliminate compatibility testing.

| Milestone | Estimate |
| --- | --- |
| Small working slice, transport plus a few real workflows | 3 to 5 engineer-days |
| Useful first release with the selected operations, documentation, and a real compatibility matrix | 20 to 40 engineer-days total, about 4 to 8 focused weeks |
| Broad coverage including several specialist modules | 3 to 6 months total, depending on typing depth and deployment variants |
| Maintain the focused client after stabilization | Budget 1 to 3 days/month, plus 2 to 5 days for a supported minor-version transition |

The maintenance estimates assume a narrow, tested contract. More major versions, Serverless, preview APIs, and exhaustive visualization models can increase them substantially. Adding types is often cheap; reproducing permissions, subscription behavior, and version-specific failures is less predictable.

## Next decision

When implementation is authorized, start with a small slice: connect, create a space and data view, export/import a dashboard, and create a disabled rule with a connector. Use that to test the interface and the compatibility assumptions before expanding coverage. Success means those workflows run on the stated targets with useful failure reporting, and the schema adjustments remain small enough to maintain.

Prefer contributing to `kibana-sync` if the actual need narrows to artifact transfer. For the broader typed automation client proposed here, a separate crate is reasonable. No maintainer contact, external repository creation, or package publication was performed.
