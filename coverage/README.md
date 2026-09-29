# API coverage tracking

`tools/api_coverage.py` compares the crate's named builders with a pinned Kibana OpenAPI bundle and generates [docs/api-coverage.md](../docs/api-coverage.md) and the summary in the top-level README.

- `upstream.json` pins the bundle by URL and SHA-256.
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
request/response subsets checked against both supported versions. This tool does
not validate complete schemas.

Builders are found by convention: a public namespace method taking `&self` that builds exactly one `.request(Method::X, Scope::Y, &[...])`. Any other public `&self` method in an endpoint module fails the check unless it is listed in `NON_ENDPOINTS`.

To move to a new Kibana version, update `upstream.json`, run `--missing` and `--check`, and review changed operations before regenerating.
