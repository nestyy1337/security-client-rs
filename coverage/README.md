# Maintaining API coverage

The [generated report](../docs/api-coverage.md) distinguishes three things:

1. A named Rust method maps to a published HTTP operation.
2. Its request and response contract is complete, partial or still unaudited.
3. A particular scenario ran on a particular deployment and source revision.

The initial manifest has no full-contract certification. Generic JSON values and the raw request escape hatch do not turn missing typed operations into implemented ones. A recorded happy-path exercise is not proof that every request variant or permission combination works.

## Sources and checks

`upstream.json` pins the traditional 9.5.4 OpenAPI bundle by URL and SHA-256. `operations.json` is our reviewed list of named wrappers, route identities, limitations and evidence references. We keep upstream schemas and descriptions out of the repository. The checker downloads the pinned document into temporary storage and retains only our report.

```sh
nix develop -c uv run tools/api_coverage.py --fetch --check
nix develop -c uv run tools/api_coverage.py --fetch --missing
```

For offline work, download the pinned bundle once outside the checkout, then use `--spec /path/to/kibana.yaml` instead of `--fetch`. Both modes verify the checksum.

After reviewing a manifest change, regenerate and commit the report:

```sh
nix develop -c uv run tools/api_coverage.py --fetch
```

CI rejects stale reports, mismatched upstream hashes, missing or duplicate manifest entries, changed route mappings, missing evidence-test references, and named wrappers without an offline wire test. The parser recognizes the crate's builder convention: a namespace method taking `&self` builds exactly one `.request(Method::X, Scope::Y, &[...])`. Any other public `&self` method in an endpoint module fails the check unless it is listed as a non-endpoint helper, so a new helper or dynamic route shape cannot silently disappear from the count. A wrapper counts as wire-tested when an offline test in `tests/` (excluding the live suites) calls it through its namespace. This is a source inventory check, not a Rust semantic analyzer; the wire tests themselves assert request shape.

The historical evidence stores its original source commit and a fingerprint of the client, dependency lock and test inputs. If those inputs change, the report labels that evidence stale. Do not update that fingerprint to turn the label green without a corresponding run. The record remains historical. Current deployment runs emit separate machine-readable reports tied to the source revision and fixture hashes.

## Upstream changes

Keep each published crate's report attached to its source commit and exact deployment profile. For a baseline update, fetch the candidate tagged bundle separately, review method/path additions and removals plus request/response schema differences, then change the pin and regenerate. A digest mismatch is a failed check, never permission to accept a new source silently.

The current checker does not discover new upstream releases or assess schema compatibility automatically. The next step is a scheduled candidate-version comparison that files reviewable added/removed/changed operations. It must not silently advance the supported version or rewrite successful test evidence.

Avoid a single "API parity" badge. Show named endpoint breadth, known contract gaps, and passing supported-deployment profiles independently. Include skipped and failed profiles in release artifacts. An intentionally deferred feature stays visible as missing rather than disappearing from the denominator.

## Next coverage work

The security-first backlog should prioritize closing existing behavioral gaps before adding more wrappers:

- Keep real agent, exception suppression and package-removal assertions in the deployment matrix. Historical manifest evidence remains separate from current CI artifacts.
- Authentication, TLS, non-default spaces, permission denials and pagination beyond one page on every claimed deployment.
- Field/variant audits for existing rule, case, policy and role methods. Query-rule creation does not represent EQL, threshold, indicator-match, machine-learning or other rule types.
- Value-list storage management; prebuilt rule install/update and bulk rule operations; policy outputs and Fleet Server configuration. Exception-list management and enrollment keys now have named wrappers and deployment scenarios.
- Endpoint response actions and Osquery only with appropriate endpoint fixtures and license profiles.

Dashboard authoring stays deferred. The full bundle count is context, not a target to implement every endpoint.

The [deployment proposal](../research/reproducible-deployments.md) defines the next implementation stages. The implemented deployment suite runs selected scenarios on two exact profiles; successful binary upgrades, cancellation and release certification remain deferred.
