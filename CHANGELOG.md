# Changelog

This project follows [Semantic Versioning](https://semver.org/). Until 1.0, minor versions may contain breaking changes; they are listed under **Changed**.

## Unreleased

Initial release.

### Added

- `http::Transport` with Basic, API key and bearer credentials, custom root certificates, proxies, timeouts, a response size limit and Elastic Cloud ID support.
- `Kibana` client with space scoping and one builder per endpoint for detection rules, exception lists, cases, Fleet, spaces and roles.
- `Kibana::request` for routes without a named builder.
- `pages()` and `items()` streams on paginated builders.
- `Fleet::wait_for_action`, `wait_for_upload` and `wait_for_agent_policy` with deadlines that bound each check's requests, and `WaitOutcome::Vanished` for resources that disappear after being seen.
- `Error::message` and `Error::retry_after` for error responses.
- `Error::Body` and status and headers on `Error::ResponseTooLarge` for failures while reading a successful response body; `Error::status`, `Error::headers` and `Error::transport`.
- `DecodeError`, which keeps response values quoted by serde out of `Display`, `Debug` and the error source chain.
- `ExceptionList::edit` and `ExceptionItem::edit`, resource-derived edits with append-only comments, and namespace-carrying `ListTarget`, `ItemTarget` and `ItemsOf`.
- `PackagePolicy::edit` for full-format package policy edits and `NewPackagePolicy::replacing` for simplified replacement.
- Forward-compatible `ActionStatus` and `UploadStatus`, and a typed `Agent::policy_revision`.
- `RuleSchedule` for detection rules, and `PatchRule::unchecked_field` beside a `field` setter that reserves selectors and validated fields.
- `bounded_pages` and `bounded_items`, with `Error::UnexpectedPage` and `Error::PageLimit`.
- Optional `tracing` feature with debug events for response headers and body completion.
