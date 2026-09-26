# Reproducible compatibility testing

Research date: 2026-09-26. Proposal only. This research did not deploy services or run mutation tests.

## Starting point

The existing [verification record](../docs/verification.md) records four successful live workflows on traditional Kibana 9.5.4. This is historical evidence, not a release-certified compatibility matrix. The [Compose deployment](../deploy/compose.yaml) has Elasticsearch and Kibana, mutable image tags, persistent demo data and no Fleet Server or enrolled Agent. The [live tests](../tests/live.rs) use administrator credentials and a live package catalogue. They are useful smoke tests, but they cannot yet justify a multi-version release claim.

I recommend a separate disposable test deployment, one explicit compatibility manifest, and operation-level results. Keep the existing demo separate. A green browser demo is not release evidence for the crate's full API coverage.

The [API coverage report](../docs/api-coverage.md) now supplies the operation inventory and identifies the initial evidence gaps. Its historical evidence is curated. The suite proposed here must produce new machine-readable run results, with pass, fail, skipped and not-applicable outcomes kept distinct.

## Upstream facts that constrain the suite

| Fact | Consequence |
| --- | --- |
| Elastic requires Elasticsearch to be at least as new as Fleet Server, and Fleet Server at least as new as Agent, ignoring patch differences. Kibana should match Elasticsearch's minor version. [Compatibility](https://www.elastic.co/docs/reference/fleet/add-fleet-server-mixed) | Start each baseline with the same exact patch on every component. Add supported older-Agent combinations deliberately, not every possible version combination. |
| Docker tags can move; digest references identify the image content. [Docker image pinning](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions) | Record tag, digest and platform for every image, including the registry and fixture services. Update locks through reviewed changes. |
| Elastic provides versioned EPR distributions, including `9.5.4` and `lite-9.5.4`. Floating `production` and `lite` distributions change with package releases. The registry filters packages by Kibana compatibility. [Air-gapped deployments](https://www.elastic.co/docs/reference/fleet/air-gapped) | Pin a versioned distribution by digest and separately lock package versions. Confirm the selected packages exist in that distribution. The current demo's System and Auditd Manager versions are not automatically suitable. |
| `xpack.fleet.registryUrl` selects the package registry, `xpack.fleet.isAirGapped` suppresses unnecessary network requests, and package preconfiguration accepts exact versions. [Fleet configuration](https://www.elastic.co/docs/reference/kibana/configuration-reference/fleet-settings) | Use a local EPR and explicit package versions. Keep signature verification enabled. Do not resolve `latest` during a test. |
| EPR supplies integration packages. Agent components and upgrades can also require the artifact registry; Elastic Defend uses security artifacts. [Component communication](https://www.elastic.co/docs/reference/fleet) | A local EPR alone does not make the whole stack offline. Preload required images/components, block unplanned egress in the deterministic lane, and fail on missing dependencies. |
| The server Agent container includes Fleet Server. Container Agent enrollment uses environment variables; its state must survive restarts to preserve enrollment. [Container deployment](https://www.elastic.co/docs/reference/fleet/elastic-agent-container) | Use separate Fleet Server and ordinary Agent containers with per-run state volumes. Preserve state for restart tests, discard it between runs. |
| Container Agents cannot be upgraded through Fleet. Service installations from Linux tarballs can. [Upgrade restrictions](https://www.elastic.co/docs/reference/fleet/upgrade-elastic-agent) | Enroll, reassign and unenroll fit the container suite. Fleet-managed binary upgrades need a later VM lane. |
| New 9.1+ deployments enable Fleet space awareness by default; upgraded older deployments require migration. Agent policies can span spaces; Kibana integration assets are installed per space. [Fleet spaces](https://www.elastic.co/docs/deploy-manage/manage-spaces-fleet/) | A clean 9.5 fixture does not certify upgraded deployments. Test spaces and privileges explicitly. Do not describe every integration asset as deployment-wide. |

## Proposed fixture and startup contract

Use Elasticsearch, Kibana, local EPR, Fleet Server, one managed Agent, and a mounted synthetic log fixture. Generate an isolated network, temporary CA, credentials, data volumes and run ID. Publish test endpoints only on loopback. Enable TLS and verify the CA through the crate; Elastic documents the Fleet certificate configuration. [Fleet TLS](https://www.elastic.co/docs/reference/fleet/secure-connections).

Commit a small manifest containing exact component versions and image digests, architecture, license, package versions, fixture revision, deployment settings and upstream API snapshot hash. Store credentials outside the checkout. Initial package selection should be Fleet Server, System for policy tests, and a pinned file-input integration for synthetic ingestion.

Use separate bootstrap credentials for provisioning and restricted Basic/API-key identities for client assertions. Bootstrap through direct documented APIs; exercise supported operations through the crate. Verify important outcomes independently through Kibana or Elasticsearch reads so a request/response bug cannot hide behind the same client model.

Elastic's `elastic-package stack` already provisions test stacks and enrolled Agents. It supports profiles, separate Agent versions and custom image references. Its documented defaults include a trial license and public EPR access. It is a useful reference and possible provisioner, but requires explicit configuration for this plan. [Tool and settings](https://github.com/elastic/elastic-package#elastic-package-stack), [upstream testing workflow](https://www.elastic.co/docs/extend/integrations/testing-validation). I would first keep an owned Compose recipe beside our existing deployment scripts, with Rust tests independent of the provisioner.

Readiness must assert state, with bounded polling and a last-observed-state error:

1. Elasticsearch responds with the expected version and license, reaches at least yellow health, and reports no timed-out health wait. Yellow permits the unallocated replicas expected on one node. [Cluster health](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-cluster-health).
2. EPR returns success from `/health?ready=true` and serves every locked package. [EPR readiness](https://www.elastic.co/docs/reference/fleet/air-gapped).
3. Kibana reports the expected version and `status.overall.level=available`. Its status API reports readiness and saved-object migration status. [Kibana status](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-status).
4. Fleet setup and pinned package installation complete. The ordinary Agent is enrolled in the expected policy and reaches the expected policy revision. Policy changes arrive at subsequent check-ins, and the Agent API exposes status, policy ID and revision. [Fleet communication](https://www.elastic.co/docs/reference/fleet), [Agent API](https://www.elastic.co/docs/api/doc/kibana/operation/operation-get-fleet-agents-agentid).
5. A synthetic event with this run's marker becomes searchable. Then test an enabled query rule against controlled events and wait for its expected alert. Rule execution depends on the creating or editing identity's data privileges. [Custom query requirements](https://www.elastic.co/docs/solutions/security/detect-and-alert/custom-query).

Fix event IDs and content, derive timestamps from one run-start time, and assert selected fields or unordered sets. Avoid whole-response snapshots of UUIDs, timestamps or background status. Repeat reads while waiting; do not retry uncertain writes automatically. Package install success, policy save success and acknowledged policy execution need separate assertions.

Always collect redacted logs and final state before deleting only that run's resources. Cleanup must also run after panics, assertion failures and interruption; the current live tests' normal cleanup path is insufficient for every panic. Reuse downloaded images, not mutated Elasticsearch volumes.

## Rollout and release gates

| Stage | Deployment and tests | Gate |
| --- | --- | --- |
| 1. Repeatable current baseline | Exact 9.5.4, Basic license, local EPR. Run existing live workflows, real TLS, Basic/API-key identities, denial cases, space isolation, import partial failures and resource cleanup. | Two fresh-volume runs pass without public package downloads. Record operation IDs tested, not just four workflow names. |
| 2. Fleet behavior | Add Fleet Server and Agent. Install/assign a package, ingest a marked event, change a policy and wait for acknowledgment, reassign, restart with preserved state, unenroll, remove an unused package. Run a query rule through alert generation. | Every advertised Agent operation has successful behavior evidence. Policy writes alone cannot satisfy this gate. |
| 3. Selected compatibility | Certify 9.4.7 as a second exact baseline if still an intended target, then maintain the chosen patches in a support manifest. Add an older compatible Agent and a separate deployment-upgrade path. | Run every required workflow on every claimed target. Mark unsupported features explicitly. A changed response must be reviewed, not accepted by regenerating snapshots. |
| 4. Broader products | Dedicated Cloud Hosted smoke tests, separate Serverless Security tests, paid-capability tests, and VM Agent upgrade/endpoint tests as those capabilities enter scope. | Publish separate results and limits; do not infer these from local Compose. |

Run transport/model checks on every PR, the primary deployment suite on client changes, and all supported targets before release. Browser checks remain optional demo regression tests and do not replace direct crate tests. A schedule can detect upstream drift; release certification must use the release commit and checked-in locks. Do not label a workflow passed when it was ignored, skipped for missing secrets, or only reached setup.

Each report should contain commit, fixture hash, component versions/digests, license, OS/architecture, API snapshot, executed operation/test IDs, outcome, duration and artifact links. Show implementation coverage and live verification separately. A 200 response proves less than a complete mutation/readback workflow. A known failing required operation blocks release unless the support claim is narrowed explicitly.

Expose one runner command that accepts a checked-in profile and owns provisioning, seeding, tests, evidence collection and cleanup. Its exit status covers the entire run, including bootstrap and cleanup failure. Separate the bootstrap module from the client tests: the tests consume endpoint URLs, CA material, restricted credentials and fixture identifiers, and exercise the public crate interface. Compose is the first deployment adapter. An explicitly selected managed-cloud adapter can supply the same inputs later, without making the tests depend on container names or log parsing.

Before publishing, run that command against the packaged crate contents, verify the declared minimum Rust version as well as stable, and require all mandatory profiles to pass for the exact release source. Missing credentials or unavailable test infrastructure must produce a non-passing result, not a green skipped matrix. An independently retried clean deployment can help diagnose an infrastructure failure; it must preserve the first failure and cannot silently erase a flaky test.

## Product boundaries

Basic licenses do not expire. Trials last 30 days and have activation restrictions. Keep Basic as the default release lane; paid features need a separate authorized license fixture and explicit capability checks. Subscription-dependent rule actions, machine learning and endpoint features must not silently turn into skips. [License behavior](https://www.elastic.co/docs/deploy-manage/license/manage-your-license-in-self-managed-cluster), [machine learning requirements](https://www.elastic.co/docs/solutions/security/detect-and-alert/machine-learning), [rule actions](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings).

Cloud Hosted permits user-controlled upgrade timing; Serverless updates automatically. Serverless also has its own API and authentication differences. [Deployment comparison](https://www.elastic.co/docs/deploy-manage/deploy/elastic-cloud/differences-from-other-elasticsearch-offerings). Serverless does not currently support an on-premises Fleet Server and constrains output and Fleet Server URLs. Use its managed Fleet Server and record project type, capability tier and test date. A local version number is not a Serverless certification. [Serverless Fleet restrictions](https://www.elastic.co/docs/reference/fleet/fleet-agent-serverless-restrictions).

No new deployment, image digest, package lock, runtime budget or cross-version result was validated by this note. Those are the deliverables of stages 1 and 2, before widening release claims.
