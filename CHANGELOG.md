# Changelog

This project follows [Semantic Versioning](https://semver.org/). Until 1.0, minor versions may contain breaking changes; they are listed under **Changed**.

## Unreleased

Initial release.

### Added

- `http::Transport` with Basic, API key and bearer credentials, custom root certificates, proxies, timeouts, a response size limit and Elastic Cloud ID support.
- `Kibana` client with space scoping and one builder per endpoint for detection rules, exception lists, cases, Fleet, spaces and roles.
- `Kibana::request` for routes without a named builder.
- `pages()` and `items()` streams on paginated builders.
- `Fleet::wait_for_action`, `wait_for_upload` and `wait_for_agent_policy` with deadlines.
- `Error::message` and `Error::retry_after` for error responses.
- Optional `tracing` feature with a debug event per request.
