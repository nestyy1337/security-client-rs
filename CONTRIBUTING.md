# Contributing

## Tests

```sh
cargo test --workspace --all-targets --all-features
```

Offline tests check every builder's method, path, query and body against a
recording mock server. Live tests are ignored by default and run against
disposable Elastic Stack deployments; see [tests/deployment](tests/deployment/README.md).
A release needs a passing live run for every profile in `tests/deployment/profiles`.

A Nix flake provides the toolchain. Prefix commands with `nix develop -c` when
using it.

## API coverage

`coverage/` pins the upstream Kibana OpenAPI bundles and maps each builder to
its operation:

- `upstream.json` pins the baseline bundle, and the other supported versions
  under `comparisons`, by URL and SHA-256.
- `operations.json` maps each builder to its operation, with its contract
  status, known limits and optional `live_evidence` (`file.rs:scenario` and a
  reviewed `success` or `rejection` outcome).
- `schema-snapshots.json` fingerprints each operation's parameters, request
  and responses for every pinned version.
- `README.md` is the generated coverage report.

```sh
uv run tools/api_coverage.py --fetch            # regenerate coverage/README.md and the README summary
uv run tools/api_coverage.py --fetch --check    # fail if either is out of date
uv run tools/api_coverage.py --fetch --missing  # list operations without a builder
uv run tools/schema_contracts.py --fetch --check
uv run tools/schema_contracts.py --fetch --update --report drift.md
```

Use `--spec path/to/kibana.yaml` (coverage) or `--spec-dir dir` with
`kibana-VERSION.yaml` files (schemas) instead of `--fetch` to work offline.
Checksums are verified either way.

The coverage check fails when a builder is missing from `operations.json` or
differs from its entry, when the operation is not in the pinned bundle, when a
builder has no offline test, or when the report is stale. Builders are found by
convention: a public namespace method taking `&self` that builds exactly one
`.request(Method::X, Scope::Y, &[...])`. Other public `&self` methods in an
endpoint module must be listed in `NON_ENDPOINTS`.

The schema check compares every named operation's contract across the pinned
versions and validates the fixtures in `tests/fixtures/contracts.json` against
the OpenAPI schemas. [tests/contracts.rs](tests/contracts.rs) runs the same
fixtures through the Rust builders and response types, so add a Rust test with
each new fixture. CI writes the drift report to the job summary.

## Supporting a new Kibana version

1. Add or update the deployment profile in `tests/deployment/profiles`.
2. Update `coverage/upstream.json`, keeping a still-supported old baseline
   under `comparisons`.
3. Run the schema `--update --report` and the coverage commands, and review the
   drift report, fixture version lists and affected Rust models.
4. Run the live deployment suite for every profile.
5. Update the compatibility section of the README and the changelog.

Dropping a supported minor version or raising the minimum Rust version needs a
new minor crate version and a changelog entry.
