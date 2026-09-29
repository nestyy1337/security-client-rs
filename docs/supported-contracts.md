# Supported workflow contracts

Reviewed on 2026-09-29 against the traditional, self-managed Kibana
[v9.5.4 OpenAPI bundle](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/output/kibana.yaml)
and [v9.4.7 bundle](https://github.com/elastic/kibana/blob/v9.4.7/oas_docs/output/kibana.yaml),
plus the tagged implementations linked below. Deployment fixtures use Basic
licenses and pinned images and packages. This is a review of selected existing
workflows, not certification of every field or endpoint. The generated
[API inventory](api-coverage.md) measures a different thing: named routes and
test references.

The source review and test inspection do not establish a fresh passing deployment
run. The ignored tests need the [deployment runner](../tests/deployment/README.md);
ordinary `cargo test` does not execute them. A release needs passing reports for
both configured profiles.

## Query detection rules

The typed creation subset is `QueryRule`, a KQL or Lucene query rule. Creation,
reads, patching, deletion, pagination and NDJSON export/import are covered. Reads
and deletes accept the saved-object `id` or portable `rule_id`; export selection
uses `rule_id`. Import uploads a multipart `file`. HTTP 200 can include failed
objects. Error entries carry an `error` with `status_code` and `message`, plus
optional object identifiers. These request and error schemas agree between the
two reviewed tags. See the
[rule operations](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/output/kibana.yaml#L15779)
and [import schema](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/output/kibana.yaml#L18347).

Import `success` describes the rules. Exception and connector imports have
separate success flags and error arrays; callers must inspect those too. The
[import handler](https://github.com/elastic/kibana/blob/v9.5.4/x-pack/solutions/security/plugins/security_solution/server/lib/detection_engine/rule_management/api/rules/import_rules/route.ts)
builds these results independently. The
[export contract](https://github.com/elastic/kibana/blob/v9.4.7/oas_docs/output/kibana.yaml)
excludes value-list contents and connector secrets, so a round trip does not prove
that every dependency needed to execute the rule was transferred.

`RuleImportResult` exposes these error groups through `ImportFailure` and their
success flags directly. Counts and connector warnings remain in `extra`.
`DetectionRule.execution_summary` exposes the last execution's status, date and
message, preserving metrics and other fields in `extra`. Execution status stays
a string so unfamiliar values can be read. Upstream describes execution summary
as evolving and `succeeded` as execution health, not proof of generated alerts.
See the [execution schema](https://github.com/elastic/kibana/blob/v9.4.7/oas_docs/output/kibana.yaml).

`detection_rules_crud_export_import_and_space_isolation` in
[live.rs](../tests/live.rs) checks a successful round trip, duplicate import
failure, a mixed import with one successful rule and one conflict, and cross-space
404. The multipart and partial-failure wire checks are in
`exports_stream_ndjson_and_imports_upload_multipart_with_partial_failures` in
[security.rs](../tests/security.rs). The managed-agent deployment scenario also
checks an actual query rule execution and alert suppression through an exception.
Other rule types and connector execution are outside this reviewed subset.

## Cases and exception updates

Cases updates send `{"cases":[...]}`. Each entry needs its `id` and current
opaque `version`; the successful response is an array. The typed subset covers
ordinary case fields and user comments. Extension fields still follow the target
server's schema: for example, `extended_fields` exists in 9.5.4 but not 9.4.7.
See the [case update schema](https://github.com/elastic/kibana/blob/v9.5.4/oas_docs/output/kibana.yaml#L84334).

Exception list/item updates use the opaque `_version`, separate from the list's
numeric `version`. The
[list update implementation](https://github.com/elastic/kibana/blob/v9.5.4/x-pack/solutions/security/plugins/lists/server/services/exception_lists/update_exception_list.ts)
passes `_version` to saved-object concurrency checking. Scope matters: `single`
lists belong to a space; `agnostic` lists are shared. Exception imports also
return per-object failures in a successful HTTP response. See the
[exception contracts](https://github.com/elastic/kibana/blob/v9.4.7/oas_docs/output/kibana.yaml).

`security_cases_comments_and_version_conflicts` and
`exception_lists_items_roundtrip_conflicts_and_spaces` in
[live.rs](../tests/live.rs) check successful updates followed by stale-token 409s.
The exception scenario also covers item pagination, duplication, shared-list
visibility, import conflicts and rule association. It does not establish support
for every Endpoint exception variant, case connector or custom-field configuration.

## Fleet action lookup and policy acknowledgment

The action-status route uses zero-based `page` and camel-case `perPage`, unlike
the ordinary one-based list endpoints. It returns `items` without a total or
cursor and has no action-ID filter. The request schema supplies defaults of
page 0 and 20 items. See the
[route schema](https://github.com/elastic/kibana/blob/v9.5.4/x-pack/platform/plugins/shared/fleet/server/types/rest_spec/agent.ts#L824).

Both tagged
[9.5.4](https://github.com/elastic/kibana/blob/v9.5.4/x-pack/platform/plugins/shared/fleet/server/services/agents/action_status.ts)
and [9.4.7](https://github.com/elastic/kibana/blob/v9.4.7/x-pack/platform/plugins/shared/fleet/server/services/agents/action_status.ts)
implementations fetch limited raw action documents, deduplicate action IDs, merge
policy changes, then slice the result. Consequently, a short or empty page does
not prove that older actions are absent. `wait_for_action` therefore widens page
zero through 100, 1,000 and 10,000 documents during each observation. This is a
bounded lookup, not complete history retrieval. Elasticsearch's default result
window is 10,000 in both
[9.5.4](https://github.com/elastic/elasticsearch/blob/v9.5.4/server/src/main/java/org/elasticsearch/index/IndexSettings.java)
and [9.4.7](https://github.com/elastic/elasticsearch/blob/v9.4.7/server/src/main/java/org/elasticsearch/index/IndexSettings.java).

The waiter stops on `COMPLETE`, `FAILED`, `CANCELLED`, `EXPIRED` or
`ROLLOUT_PASSED`. Stopping does not imply success; inspect failure counts and
errors. The upstream action-status implementation can replace expiry or rollout
status after later acknowledgments. Unknown statuses keep waiting.

Policy acknowledgment requires the requested policy ID, an online agent and
`policy_revision` at least as high as requested. An absent or null revision is
pending. This matches the nullable revision in the
[agent response schema](https://github.com/elastic/kibana/blob/v9.5.4/x-pack/platform/plugins/shared/fleet/server/types/rest_spec/agent.ts#L301).
It does not prove ingestion; the deployment test checks that separately.

`waiting_for_an_action_expands_history_even_when_documents_are_deduplicated` and
`waiting_for_uploads_and_policy_acknowledgment` in
[helpers.rs](../tests/helpers.rs) check lookup and acknowledgment decisions.
`fleet_agent_bulk_actions_and_diagnostics` in [deployment.rs](../tests/deployment.rs)
checks successful tags, reassignment and diagnostics, a reassignment with one
failed agent, and rejected container-agent upgrades.
`agent_policy_delivery_ingestion_reassignment_and_unenrollment` checks delivery,
ingestion and removal. Successful upgrades, upgrade cancellation and production
history volumes remain unverified.

## Scope of compatibility

The named builders and selected models are partial. Additional fields sent through
raw requests or builder extensions remain the caller's responsibility. This review
does not cover 8.x, Cloud, Serverless, paid features or upgrading an existing stack.
Version support should expand only when corresponding deployment profiles and
successful workflow checks exist.

Endpoint `into_request()` retains the route and configuration while allowing
additional request fields or query options. `CasePatch::field` extends case
updates while protecting `id` and `version`. Selected response models retain
unmodeled fields in `extra`; this does not extend the supported server versions.
Fleet's typed agent subset includes nullable policy revision, last check-in and
tags, alongside the policy ID and status used by acknowledgment checks.
