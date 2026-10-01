# Releasing

The first package is `kibana-rs` 0.1.0. It remains unpublished until the publication
step below. No credentials belong in this repository. Cargo needs a crates.io
credential with permission to publish this package; docs.rs builds the published
crate automatically with all features enabled.

## Verify the candidate

Use a clean checkout of the candidate commit. Run tools through `nix develop -c`
when using the repository's Nix environment.

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --doc --all-features
cargo doc --locked --no-deps --all-features
uv run --with PyYAML==6.0.3 --with openapi-schema-validator==0.9.0 --with jsonschema==4.26.0 python -m unittest discover -s tools -p 'test_*.py'
uv run tools/api_coverage.py --fetch --check
uv run tools/schema_contracts.py --fetch --check
uv run python -m unittest discover -s tests/deployment -p 'test_*.py'
uv run python -u tests/deployment/run.py --profile 9.5.4-basic
uv run python -u tests/deployment/run.py --profile 9.4.7-basic
cargo publish --locked --dry-run
```

Also run the workspace tests with Rust 1.88 and the dependency checks configured
in CI. Inspect both deployment reports: all ten scenarios and cleanup must pass.
Retain the reports with the release evidence. A live `success` or `rejection`
label in the API inventory describes the assertions, not the current run result.

## Publish the approved commit

The candidate already includes the 0.1.0 changelog and registry installation
instructions. If publication is delayed, update the release date and verify the
resulting package with the same dry-run command.

Publishing consumes the crate name/version permanently. Obtain the maintainer's
approval of the candidate before this step. Publish that clean commit with
`cargo publish --locked`, then tag it `v0.1.0` and push the commit and tag to the
repository. Verify the crates.io package and docs.rs build before announcing it.

For later releases, update the version and changelog together. The README's
compatibility policy determines whether a change needs a new minor version.
Successful agent upgrades, Cloud/Serverless and unsupported Kibana versions must
not be inferred from the existing test matrix.
