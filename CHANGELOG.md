# Changelog

This project follows [Semantic Versioning](https://semver.org/). Until 1.0, minor versions may contain breaking changes; they are listed under **Changed**.

## 0.1.0 - 2026-09-29

Initial release.

### Added

- `http::Transport` with Basic, API key and bearer credentials, custom root certificates, proxies, timeouts, a response size limit and Elastic Cloud ID support.
- `Kibana` client with space scoping and one builder per endpoint for detection rules, exception lists, cases, Fleet, spaces and roles.
- `Kibana::request` for routes without a named builder.
- `pages()` and `items()` streams on paginated builders.
- `Fleet::wait_for_action`, `wait_for_upload` and `wait_for_agent_policy` with deadlines.
- `Error::message` and `Error::retry_after` for error responses.
- Optional `tracing` feature with a debug event per request.
- `into_request()` on endpoint builders and `CasePatch::field` for additional server options.
- Typed agent policy revision, tags and last check-in, rule execution summaries, and per-object import failures with separate rule, exception and connector outcomes.
- Reviewed workflow contracts for Kibana 9.5.4 and 9.4.7, with explicit live success and rejection evidence.

### Changed

- Prerelease consumers must read import errors through `ImportFailure` fields instead of JSON indexing. Agent policy revision, tags and last check-in and rule execution summaries now have named fields instead of entries in `extra`.
- `Error::Decode.source` is a `DecodeError`. It retains category and location for logging; the original Serde error is available through `as_serde_error()`.

### Fixed

- Polling enforces deadlines across requests, retains the last observed state and sends no request after the deadline.
- Fleet action waits expand their history lookup beyond the first 100 documents without skipping deduplicated actions, up to 10,000 documents.
- Response and decode-error diagnostics omit query values and response values, including error source chains.
- The recovery example bounds requests and retry backoff with one overall timeout.
