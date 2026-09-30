# API coverage tracking

`tools/api_coverage.py` compares the crate's named builders with a pinned Kibana OpenAPI bundle and generates [docs/api-coverage.md](../docs/api-coverage.md) and the summary in the top-level README.

- `upstream.json` pins the baseline and comparison bundles by URL and SHA-256.
- `operations.json` maps each builder to its upstream operation and records known limits.

```sh
uv run tools/api_coverage.py --fetch            # regenerate the report
uv run tools/api_coverage.py --fetch --check    # fail if the report is out of date
uv run tools/api_coverage.py --fetch --missing  # list operations without a builder
```

Use `--spec path/to/kibana.yaml` instead of `--fetch` to work offline. The checksum is verified either way.

The check fails when:

- a builder is missing from `operations.json`, or an entry has no builder;
- a builder's method, path or scope differs from its entry, or the operation is not in the pinned bundle;
- a builder has no offline test in `tests/`;
- the committed report is out of date.

Optional `live_evidence` entries name a `file.rs:scenario` and a reviewed outcome,
`success` or `rejection`. The check verifies that the scenario and a live builder
call still exist; reviewing the assertions is a human task. Unreviewed live calls
remain labeled `called`. These labels do not imply a passing deployment run.
The [supported workflow review](../docs/supported-contracts.md) records the
request/response subsets checked against both supported versions. The inventory
tool checks routes and test references; the schema check below checks contracts.

Builders are found by convention: a public namespace method taking `&self` that builds exactly one `.request(Method::X, Scope::Y, &[...])`. Any other public `&self` method in an endpoint module fails the check unless it is listed in `NON_ENDPOINTS`.

## Schema comparison and fixtures

`tools/schema_contracts.py` compares every named operation's parameters, request
body and documented responses across the pinned versions. It expands local
schema references and retains types, required fields, enums, nullability,
defaults, constraints, headers and media types. Documentation and vendor
annotations are ignored. External references and a changed OpenAPI dialect
fail until the tool is reviewed.

```sh
uv run tools/schema_contracts.py --fetch --check
uv run tools/schema_contracts.py --fetch --update
```

For offline work, replace `--fetch` with `--spec-dir path/to/bundles`, containing
`kibana-VERSION.yaml` for each pin. Both modes verify the upstream checksums.
CI uses `--check`; it never rewrites the committed files.

- `schema-snapshots.json` retains a fingerprint for each operation's parameters,
  request and responses, for every supported deployment version.
- [docs/schema-drift.md](../docs/schema-drift.md) lists field changes between the
  pins. Review the report and fingerprint diff together when updating pins.
- [tests/fixtures/contracts.json](../tests/fixtures/contracts.json) contains
  synthetic request and response examples with explicit applicable versions.
  The check validates each body against its operation's OpenAPI JSON schema.
  [tests/contracts.rs](../tests/contracts.rs) exercises the same fixtures through
  typed Rust builders and response decoding. Add a matching Rust test when
  adding a fixture; unhandled fixture builders fail those tests.

Fixture validation checks read/write constraints, formats and union alternatives.
It checks union branches directly because the bundled rule-source discriminator
has no mapping to its prefixed components. Discriminator metadata still affects
the fingerprints. The role fixture records an upstream `oneOf` ambiguity at
`/kibana/0/base`; only that ambiguity is exempted while multiple valid branches
match. Invalid values, other validation errors and obsolete exceptions fail.
The report records these limits. Responses without an upstream JSON schema are
still fingerprinted, but cannot receive a schema-validated response fixture.

These checks detect changes and regressions in selected workflows. They do not
prove complete client support or replace the deployment tests.

To move to a new Kibana version, update the supported deployment profiles and
`upstream.json`, retaining the old baseline as a comparison pin when it remains
supported. Fetch and verify the new bundle's checksum, then run the inventory
commands and schema `--update`. Review field changes, fixture version lists and
Rust model behavior before committing both generated outputs and running
`--check`. An update validates fixtures before writing either output.
