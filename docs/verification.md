# Verification record

Verified on 2026-09-26 on homebox against a dedicated, Basic-licensed Elasticsearch and Kibana **9.5.4** deployment. The browser workbench uses the `kibana-rs` space and a restricted service account. The live library tests use a separate administrator credential to create and remove temporary spaces and roles.

## Automated checks

| Check | Result |
| --- | --- |
| Rust formatting | Passed |
| Clippy, all features and targets, warnings denied | Passed |
| Compilation, all features and targets | Passed, including the demo and read-only example |
| Transport tests | 5 passed |
| Opt-in live API tests | 4 passed against Kibana 9.5.4 |
| Documentation test command | Passed; there are currently no doctest cases |
| JavaScript syntax check | Passed |
| Chrome browser workflows | Passed at desktop and phone sizes |

The ordinary Cargo test run deliberately ignores the four live tests. They were also run explicitly with `--ignored --test-threads=1`; these results are from that live run, not from an empty test pass.

Transport checks exercise proxy-prefix and space routing, resource-ID encoding, global routes, authentication and XSRF headers, bounded non-JSON API errors, response-size limits, decode errors, redacted credentials, and the absence of redirects and automatic mutation retries.

The four live tests cover:

- Detection-rule initialization and privilege inspection; create/read/list/update/delete; rule-ID lookup; isolation between spaces; streaming NDJSON export; duplicate-import partial errors and successful reimport.
- Security case creation, search, status changes, stale-version HTTP 409, notes, retrieval, and deletion.
- Fleet setup; agent-policy creation, update, copy, retrieval, pagination, download, and deletion; package catalogue and installation; package-policy creation, update, retrieval, listing, and deletion; assigned integration counts; empty agent lists, status, and outputs.
- Global role creation, retrieval, listing, update, and deletion; space creation, retrieval, update, listing, and deletion; roundtrip of space-specific privileges.

## Browser and deployment checks

The browser tests drive the served application in headless Chrome. They create real disposable resources through the Rust backend, then delete them:

- Create, enable, disable, edit, and delete a detection rule.
- Open a case, start an investigation, add a note, close, and delete it.
- Create an agent policy, assign the System integration, remove that assignment, and delete the policy.
- Inspect the empty agent state, actual operation history, and seeded policy's assigned-integration count.
- Verify that asset-only packages cannot be selected for agent-policy assignment.
- Check phone layout for page overflow and open a rule detail drawer.
- Fail on uncaught JavaScript errors.

Auditd Manager 1.21.0 was separately installed through the running workbench API with the restricted demo account. Kibana reported 14 installed assets. System 2.26.0 is assigned to the seeded Linux policy. Installation and assignment do not enroll agents or prove that telemetry is being collected.

From lightbox, a separate tailnet machine, requests to `http://homebox:8787` returned the application's health, Kibana version/status, and screenshot content successfully. Elasticsearch and Kibana remain bound to loopback. The app runs under a user systemd service, and the dedicated containers have restart policies. User lingering is enabled so the service can run without an interactive login. Reboot recovery has not been exercised.

The demo account can access detection rules in `kibana-rs`. Attempts to access rules in the default space or administer Kibana roles returned HTTP 403. Browser mutations require the application's custom request header. There is no separate browser login: access to the app follows the existing tailnet policy. Package assets are deployment-wide even when installed through a space-scoped account.

## Screenshots

Captured from the running app, not mockups:

- [Detection rules, desktop](http://homebox:8787/screenshots/rules-desktop.png)
- [Fleet policies, desktop](http://homebox:8787/screenshots/fleet-desktop.png)
- [Integrations, desktop](http://homebox:8787/screenshots/integrations-desktop.png)
- [Detection rules, phone](http://homebox:8787/screenshots/rules-mobile.png)
- [Rule details, phone](http://homebox:8787/screenshots/rule-detail-mobile.png)

Original PNGs are stored outside the checkout at `~/.local/state/kibana-rs/screenshots` on homebox. The screenshot endpoint serves only these five allowlisted filenames.

## Limits

This verifies an initial client and an isolated demonstration, not production compatibility across Kibana releases. Only traditional Kibana 9.5.4 was tested. No enrolled agents or production events are present. Agent get/reassign/unenroll operations and package uninstallation are implemented but have not been exercised against live agents or packages being removed. No Fleet Server provisioning, agent enrollment, or detection execution on live telemetry was tested. Kibana 8.x, 9.4, and Serverless remain unverified.

The demo exposes a subset of the library. Integration assignment uses package defaults, the assignment picker loads the first 50 agent policies, and a case drawer loads its first 100 comments. Package-specific settings requiring extra variables need library calls or Kibana. Recent operations are an in-memory convenience, cleared on restart, not an audit log.

The GitHub Actions definition was added but has not run remotely. The repository has no remote and the crate has not been published. There has been no sustained-load, dependency-security, or Rust minimum-version compatibility certification.
