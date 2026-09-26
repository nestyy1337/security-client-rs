# Kibana API feasibility

Research date: 2026-09-26. This is a source and specification review. No client was implemented, generated, or exercised against a running Kibana instance.

## Finding

A useful Rust client is technically feasible. The work is ordinary HTTP, serialization, and version testing. The maintenance cost comes from selecting supported APIs, handling inconsistent schemas, and verifying behavior across releases. Complete Kibana coverage would be a substantially larger commitment.

Elastic publishes separate OpenAPI 3.0.3 bundles for traditional deployments and Serverless. Its documentation pipeline combines route-derived definitions with manually maintained definitions and overlays. That gives us a usable inventory, but not a single authoritative input that can safely produce the whole library unattended. [Tagged bundling documentation](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/README.md), [merge configuration](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/scripts/merge_ess_oas.js).

## What I measured

I downloaded the following upstream YAML files, parsed them with PyYAML, and counted HTTP method entries under `paths`. An operation is a method/path pair, not a Rust method or a distinct user workflow. These totals include deprecated operations, documentation placeholders, and path variants. They are not completeness scores.

| Source | Paths | Operations | Component schemas | Deprecated operations |
| --- | ---: | ---: | ---: | ---: |
| [Kibana v8.19.0](https://raw.githubusercontent.com/elastic/kibana/v8.19.0/oas_docs/output/kibana.yaml) | 245 | 349 | 918 | 49 |
| [Kibana v9.4.7](https://raw.githubusercontent.com/elastic/kibana/v9.4.7/oas_docs/output/kibana.yaml) | 438 | 608 | 1,587 | 34 |
| [Kibana v9.5.4](https://raw.githubusercontent.com/elastic/kibana/v9.5.4/oas_docs/output/kibana.yaml) | 478 | 663 | 1,711 | 40 |
| [Serverless bundle at v9.5.4](https://raw.githubusercontent.com/elastic/kibana/v9.5.4/oas_docs/output/kibana.serverless.yaml) | 413 | 569 | 1,610 | Not counted |
| [Kibana main, fetched on research date](https://raw.githubusercontent.com/elastic/kibana/main/oas_docs/output/kibana.yaml) | 536 | 741 | 1,864 | 35 |

Comparing method/path sets between 9.4.7 and 9.5.4 found 59 additions and four removals. This measures documentation changes, which can include newly documented existing behavior. It does not establish 59 new runtime capabilities or four breaking changes.

The 9.5.4 traditional bundle had no duplicate or missing operation IDs and no unresolved `$ref` pointers in my traversal. It also contains 643 `anyOf`, 229 `oneOf`, and 233 `allOf` keys. These are structural counts across the document, not independent model counts. Parsing and reference resolution are useful checks, but are not full OpenAPI validation or proof of generator compatibility.

For reproducibility, the downloaded files had these SHA-256 hashes:

| File | SHA-256 |
| --- | --- |
| v8.19.0 traditional | `80736e301a8364018585fbca55960e9ac7408d231bfcd08279bcb70702194e82` |
| v9.4.7 traditional | `4746196c160554bc3dac4800d0f19f4848b660ad8a4f1b1be7c0eef55299d660` |
| v9.5.4 traditional | `a5dd0f2a0fa30f2bdcba6b42c712b9bfcd89f22aef29c9bf5285328f014279d9` |
| v9.5.4 Serverless | `dd22c723eaf00b72eb576a40e41d2092dcec40dc46f882ac57ccbac4ea7a9192` |
| main traditional | `1ade1b1ae0ef2f72adc5f7adc82cf99a1b2029b64d27cad88f776ba0dcf134b1` |

The source downloads and temporary analysis environment were kept outside this repository. We retain findings and provenance here, not copies of upstream specifications.

## Constraints that affect the design

### Public does not always mean stable

Elastic's current HTTP API guidelines distinguish experimental, preview, stable, and deprecated APIs. Stable APIs are intended to avoid breaking changes outside major versions. Undocumented and internal APIs carry no such promise. The guidance itself is marked work in progress, and missing lifecycle labels should not be treated as evidence of stability. [HTTP API guidelines](https://www.elastic.co/docs/extend/kibana/contributing/api-design/guidelines-for-http-api-design-in-kibana).

The hosted API reference follows `main` and explicitly includes future work. It also warns about restrictions on internal APIs starting in 9.0. We should pin release tags and document support per operation. A path beginning with `/api/` is not enough to establish a public contract. [API introduction](https://www.elastic.co/docs/api/doc/kibana), [route access classification](https://www.elastic.co/docs/extend/kibana/contributing/api-design/guidelines-for-http-api-design-in-kibana#internal-vs-public-apis).

Proposal: support traditional Kibana 9.5 first, then certify the selected core on 9.4. Do not claim generic 8.x/9.x or Serverless compatibility. Add those only with their own tests and explicit differences. The Serverless YAML stored at a release tag is a specification snapshot, not a version of the continuously deployed service.

### Dashboard schemas need a separate source

The primary bundle replaces Dashboard and Visualization definitions with links because the documentation renderer cannot handle the full schemas. Elastic's README describes a manually regenerated external bundle and warns that it can drift. The expected `oas_docs/output/kibana.external.yaml` URL returned 404 at tag v9.5.4. That is not evidence the full schemas are unavailable elsewhere. [Tagged README](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/README.md), [tracking issue](https://github.com/elastic/kibana/issues/266195).

The separate reference says Dashboard APIs were experimental in 9.4 and generally available in 9.5, with breaking changes at that transition. New dashboard authoring is therefore a separate compatibility commitment from exporting existing dashboards. [Dashboard reference](https://dashboardsapispec.kibana.dev/dashboards).

Proposal: start with export/import for dashboard transfer. Add 9.5 dashboard authoring separately, after pinning the full schemas and testing their behavior. Do not model every Lens visualization in the first release.

### Saved objects are not a universal stable CRUD interface

In the tagged 9.5.4 bundle, generic saved-object create, get, update, delete, find, and bulk operations are marked deprecated. Export, import, and import-error resolution are not. Prefer purpose-specific APIs such as data views and dashboards when authoring objects. [Tagged definitions](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/output/kibana.yaml), [Elastic provider's deprecation tracking](https://github.com/elastic/terraform-provider-elasticstack/issues/637).

Export produces NDJSON that Elastic says to treat as opaque. Imports are multipart uploads and have version-direction constraints. An HTTP 200 import response can contain failures, so the result must preserve object-level errors and success information. These facts make a generic JSON-only transport insufficient. [Export API](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-saved-objects-export), [import API](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-saved-objects-import).

### Routing, authentication, and error handling belong in the core

Non-default spaces use `/s/{space_id}`. Some operations are global, so a scoped client cannot prepend that prefix indiscriminately. Reverse-proxy base paths also need to survive URL construction. [Spaces documentation](https://www.elastic.co/docs/api/doc/kibana/topic/topic-kibana-spaces).

API key and Basic authentication are documented API schemes. Bearer authentication depends on configured HTTP authentication support. Accept existing credentials first; browser login and token acquisition are separate tasks. [API authentication](https://www.elastic.co/docs/api/doc/kibana/authentication), [HTTP authentication configuration](https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/kibana-authentication).

Handle `kbn-xsrf` centrally for mutating operations. Treat `elastic-api-version` as endpoint/deployment metadata, not a Kibana product version. Preserve status, useful headers, and a bounded response body when the response is an error or cannot be decoded. [Import headers](https://www.elastic.co/docs/api/doc/kibana/operation/operation-post-saved-objects-import), [versioned API example](https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-getenvironmentsforservice).

Proposal: never automatically retry a mutating request merely because it received a timeout or 5xx. The server may already have acted. Reporting illustrates why retry behavior can also be endpoint-specific: a download can return 503 while a report is still generating, with a `Retry-After` header. Reporting can wait until later, but the transport should leave room for that policy. [Report automation](https://www.elastic.co/docs/explore-analyze/report-and-share/automating-report-generation).

### Code generation helps only after curation

OpenAPI Generator's Rust feature table lists incomplete support for schema composition. Progenitor supports OpenAPI 3.0.x and async clients, but explicitly warns that some documents fail and identifies Dropshot output as its primary target. Neither is verified against Kibana by this research. [Rust generator](https://openapi-generator.tech/docs/generators/rust/), [Progenitor](https://github.com/oxidecomputer/progenitor).

The existing-client review records a stronger practical example: Elastic's own Terraform provider maintains an operation allowlist and a substantial schema transformation layer. See [existing clients](existing-clients.md).

Proposal: write the first small set of public Rust types and operations deliberately. Use upstream specification differences to flag review work. Later, evaluate selected generated models or internal endpoint plumbing behind the same public interface. Avoid spending the first milestone building a general-purpose generator repair pipeline.

### Specification reuse needs a decision before distribution

The published specifications identify their documentation license as CC BY-NC-ND 4.0. Kibana's source repository also has file-dependent licenses. This review does not determine the legal status of generated bindings. Before distributing copied specifications, copied documentation, or generated code, establish which material and permissions the project will use. This is a concrete unresolved issue for the generation approach, not a finding that an independently implemented client is prohibited. [Specification metadata](https://raw.githubusercontent.com/elastic/kibana/v9.5.4/oas_docs/output/kibana.yaml), [repository license notice](https://github.com/elastic/kibana/blob/v9.5.4/LICENSE.txt).

## What remains unverified

- Live request/response behavior, permissions, subscription-dependent features, and cross-version compatibility.
- Whether a chosen Rust generator handles a curated subset without excessive patches.
- Compilation time, binary size, and ergonomics of generated or handwritten Rust models.
- User demand beyond the owner's intended automation tasks.

The evidence supports proceeding with a bounded client. It does not justify promising complete Kibana coverage or a maintenance-free generated SDK.
