//! Executed by tests/deployment/run.py against a disposable, digest-locked stack.
use futures_util::TryStreamExt;
use kibana_rs::{
    Error, Kibana, Result,
    exceptions::{Entry, ListSelector, NewItem, NewList, Operator},
    fleet::{
        ActionStatus, AgentActionStatus, AgentSelection, BulkActionResult, NewAgentPolicy,
        NewPackagePolicy, PackageRef, PolicyInput, PolicyStream, UploadStatus,
    },
    http::{Certificate, Credentials, StatusCode, TransportBuilder, Url},
    poll::{PollOptions, WaitOutcome},
    security::{QueryRule, RuleSelector},
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must come from the deployment runner"))
}

fn ca() -> reqwest::Certificate {
    reqwest::Certificate::from_pem(&std::fs::read(env("KIBANA_CA_CERT")).unwrap()).unwrap()
}

fn transport(credentials: Credentials) -> TransportBuilder {
    TransportBuilder::new(Url::parse(&env("KIBANA_URL")).unwrap())
        .auth(credentials)
        .timeout(Duration::from_secs(90))
}

fn client(credentials: Credentials) -> Kibana {
    let ca = Certificate::from_pem(&std::fs::read(env("KIBANA_CA_CERT")).unwrap()).unwrap();
    Kibana::new(transport(credentials).root_certificate(ca).build().unwrap())
}

fn basic(username: &str, variable: &str) -> Credentials {
    Credentials::Basic(username.into(), env(variable))
}

fn admin() -> Kibana {
    client(basic("elastic", "KIBANA_PASSWORD"))
}

fn status<T>(result: Result<T>) -> Option<StatusCode> {
    result.err().and_then(|error| error.status())
}

fn ids(agents: &[&str]) -> AgentSelection {
    AgentSelection::Ids(agents.iter().map(ToString::to_string).collect())
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner"]
async fn tls_authentication_and_space_permissions() {
    let untrusted = Kibana::new(
        transport(basic("elastic", "KIBANA_PASSWORD"))
            .build()
            .unwrap(),
    );
    assert!(
        matches!(untrusted.status().send().await.unwrap_err(), Error::Transport(error) if error.is_connect()),
        "Untrusted CA must fail before HTTP"
    );
    assert_eq!(
        admin().status().send().await.unwrap().json().await.unwrap()["version"]["number"],
        env("KIBANA_TEST_VERSION")
    );

    let writer = client(basic("fixture_writer", "KIBANA_TEST_WRITER_PASSWORD"))
        .space("fixture")
        .unwrap();
    let reader = client(basic("fixture_reader", "KIBANA_TEST_READER_PASSWORD"))
        .space("fixture")
        .unwrap();
    let api_key = client(Credentials::EncodedApiKey(env("KIBANA_TEST_API_KEY")))
        .space("fixture")
        .unwrap();
    for identity in [&writer, &reader, &api_key] {
        identity.security().find_rules().send().await.unwrap();
    }
    let request = QueryRule::new(
        "Permission fixture",
        "Disposable test",
        "event.outcome: failure",
    );
    let rule = api_key
        .security()
        .create_rule(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let exception_request = NewList::detection("Permission exception", "Owned permission fixture");
    let exception_list = api_key
        .exceptions()
        .create_list(&exception_request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        reader
            .exceptions()
            .get_list(ListSelector::Id(&exception_list.id))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .id,
        exception_list.id
    );
    assert_eq!(
        status(
            reader
                .exceptions()
                .create_list(&exception_request)
                .send()
                .await
        ),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        status(
            api_key
                .default_space()
                .exceptions()
                .get_list(ListSelector::Id(&exception_list.id))
                .send()
                .await
        ),
        Some(StatusCode::FORBIDDEN)
    );
    writer
        .exceptions()
        .delete_list(ListSelector::Id(&exception_list.id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        status(
            reader
                .fleet()
                .bulk_update_agent_tags(ids(&["not-an-agent"]))
                .add_tags(["denied"])
                .send()
                .await
        ),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        writer
            .security()
            .get_rule(RuleSelector::Id(&rule.id))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .id,
        rule.id
    );
    assert_eq!(
        status(reader.security().create_rule(&request).send().await),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        status(writer.default_space().security().find_rules().send().await),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        status(api_key.default_space().security().find_rules().send().await),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        status(writer.roles().list().send().await),
        Some(StatusCode::FORBIDDEN)
    );
    let wrong = client(Credentials::Basic(
        "fixture_writer".into(),
        "deliberately-wrong".into(),
    ))
    .space("fixture")
    .unwrap();
    assert_eq!(
        status(wrong.security().find_rules().send().await),
        Some(StatusCode::UNAUTHORIZED)
    );
    writer
        .security()
        .delete_rule(RuleSelector::Id(&rule.id))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner"]
async fn pagination_returns_all_owned_rules() {
    let client = client(basic("fixture_writer", "KIBANA_TEST_WRITER_PASSWORD"))
        .space("fixture")
        .unwrap();
    let mut expected = Vec::new();
    for number in 0..3 {
        let request = QueryRule::new(
            format!("Pagination {number}"),
            "Disposable test",
            "event.outcome: failure",
        );
        expected.push(
            client
                .security()
                .create_rule(&request)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap()
                .id,
        );
    }
    let mut received = Vec::new();
    for page in 1..=2 {
        let response = client
            .security()
            .find_rules()
            .page(page)
            .per_page(2)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response.total, 3);
        assert_eq!(response.data.len(), if page == 1 { 2 } else { 1 });
        received.extend(response.data.into_iter().map(|r| r.id));
    }
    expected.sort();
    received.sort();
    assert_eq!(received, expected);
    let pages: Vec<_> = client
        .security()
        .find_rules()
        .per_page(2)
        .pages()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(pages.len(), 2);
    let mut streamed: Vec<_> = client
        .security()
        .find_rules()
        .per_page(2)
        .items()
        .map_ok(|rule| rule.id)
        .try_collect()
        .await
        .unwrap();
    streamed.sort();
    assert_eq!(streamed, expected);
    for id in expected {
        client
            .security()
            .delete_rule(RuleSelector::Id(&id))
            .send()
            .await
            .unwrap();
    }
}

async fn search(index: &str, query: Value) -> u64 {
    let http = reqwest::Client::builder()
        .add_root_certificate(ca())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let health = http
        .get(format!(
            "{}/_cluster/health/{index}?wait_for_status=yellow&timeout=1s",
            env("ELASTICSEARCH_URL")
        ))
        .basic_auth("elastic", Some(env("KIBANA_PASSWORD")))
        .send()
        .await
        .unwrap();
    let status = health.status();
    let health = health.json::<Value>().await.unwrap();
    assert!(
        status.is_success() || status == StatusCode::REQUEST_TIMEOUT,
        "Index health failed: {status} {health}"
    );
    if health["timed_out"] == true || health["active_primary_shards"].as_u64() == Some(0) {
        return 0;
    }
    assert!(matches!(
        health["status"].as_str(),
        Some("yellow" | "green")
    ));
    let response = http
        .post(format!(
            "{}/{index}/_search?allow_partial_search_results=false",
            env("ELASTICSEARCH_URL")
        ))
        .basic_auth("elastic", Some(env("KIBANA_PASSWORD")))
        .json(&json!({"query": query, "size": 0, "track_total_hits": true}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let response = response.json::<Value>().await.unwrap();
    if missing_search_shards(status, &response) {
        return 0;
    }
    assert!(status.is_success(), "Search failed: {status} {response}");
    assert_eq!(response["_shards"]["failed"], 0);
    assert_eq!(response["timed_out"], false);
    response["hits"]["total"]["value"].as_u64().unwrap()
}

fn missing_search_shards(status: StatusCode, response: &Value) -> bool {
    status == StatusCode::SERVICE_UNAVAILABLE
        && response["error"]["type"] == "search_phase_execution_exception"
        && response["error"]["caused_by"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("Search rejected due to missing shards ["))
}

#[test]
fn only_missing_shards_are_pending_search_results() {
    let missing = json!({"error": {
        "type": "search_phase_execution_exception",
        "caused_by": {"reason": "Search rejected due to missing shards [[fixture][0]]."}
    }});
    assert!(missing_search_shards(
        StatusCode::SERVICE_UNAVAILABLE,
        &missing
    ));
    assert!(!missing_search_shards(StatusCode::UNAUTHORIZED, &missing));
    assert!(!missing_search_shards(StatusCode::OK, &missing));
    for response in [
        json!({"error": {"type": "search_phase_execution_exception", "caused_by": {"reason": "invalid query"}}}),
        json!({"error": {"type": "circuit_breaking_exception"}}),
        json!({"error": {"type": "security_exception"}}),
        json!({"hits": {"total": {"value": 0}}}),
    ] {
        assert!(!missing_search_shards(
            StatusCode::SERVICE_UNAVAILABLE,
            &response
        ));
    }
}

async fn wait_for_policy(client: &Kibana, agent_id: &str, policy: &str, revision: u64) {
    let outcome = client
        .fleet()
        .wait_for_agent_policy(agent_id, policy, revision, PollOptions::default())
        .await
        .unwrap();
    if let WaitOutcome::TimedOut { last } = outcome {
        panic!(
            "Agent did not acknowledge policy {policy} revision {revision}; last state: {last:?}"
        );
    }
}

async fn wait_for_action(client: &Kibana, result: BulkActionResult) -> AgentActionStatus {
    let BulkActionResult::Action { action_id } = result else {
        panic!("expected an action, received dry-run result")
    };
    match client
        .fleet()
        .wait_for_action(&action_id, PollOptions::default())
        .await
        .unwrap()
    {
        WaitOutcome::Finished(action) => action,
        other => panic!("Action {action_id} did not finish: {other:?}"),
    }
}

fn successful_action(action: &AgentActionStatus) {
    assert_eq!(action.status, ActionStatus::Complete, "{action:?}");
    assert_eq!(action.nb_agents_failed, 0, "{action:?}");
}

async fn agent_tags(client: &Kibana, agent_id: &str) -> Vec<String> {
    let agent = client
        .fleet()
        .get_agent(agent_id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    agent.tags.unwrap_or_default()
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner with a real Agent"]
async fn fleet_agent_bulk_actions_and_diagnostics() {
    let client = admin();
    let fleet = client.fleet();
    let agent_id = env("KIBANA_TEST_AGENT_ID");
    let peer_id = env("KIBANA_TEST_PEER_ID");
    let preview = fleet
        .bulk_unenroll_agents(ids(&[&agent_id]))
        .batch_size(1)
        .dry_run(true)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(preview, BulkActionResult::DryRun { count: 1 }));
    assert_eq!(
        fleet
            .get_agent(&agent_id)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .item
            .active,
        Some(true)
    );

    let task = fleet
        .bulk_update_agent_tags(ids(&[&agent_id]))
        .batch_size(1)
        .add_tags(["owned-fixture"])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, task).await);
    assert!(
        agent_tags(&client, &agent_id)
            .await
            .contains(&"owned-fixture".to_owned())
    );

    let target = fleet
        .get_agent_policy("fixture-agent-target")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    let task = fleet
        .bulk_reassign_agents(ids(&[&agent_id, &peer_id]), &target.id)
        .include_inactive(false)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let partial = wait_for_action(&client, task).await;
    assert_eq!(partial.status, ActionStatus::Failed, "{partial:?}");
    assert_eq!(partial.nb_agents_failed, 1, "{partial:?}");
    assert_eq!(partial.nb_agents_ack, 1, "{partial:?}");
    assert!(
        partial
            .latest_errors
            .iter()
            .any(|e| e["agentId"] == peer_id),
        "{partial:?}"
    );
    wait_for_policy(&client, &agent_id, &target.id, target.revision).await;

    let repeated = fleet
        .bulk_reassign_agents(ids(&[&agent_id]), &target.id)
        .send()
        .await
        .unwrap_err();
    assert_eq!(repeated.status(), Some(StatusCode::BAD_REQUEST));
    assert!(repeated.body().unwrap().contains("No agents to reassign"));

    let original = fleet
        .get_agent_policy("fixture-agent")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    let task = fleet
        .bulk_reassign_agents(ids(&[&agent_id]), &original.id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, task).await);
    wait_for_policy(&client, &agent_id, &original.id, original.revision).await;

    assert!(matches!(
        fleet
            .bulk_request_agent_diagnostics(AgentSelection::Query("policy_id:fixture-agent".into()))
            .dry_run(true)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap(),
        BulkActionResult::DryRun { count: 1 }
    ));
    let diagnostics = fleet
        .request_agent_diagnostics(&agent_id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let action = wait_for_action(&client, diagnostics).await;
    successful_action(&action);
    let upload = match fleet
        .wait_for_upload(&agent_id, &action.action_id, PollOptions::default())
        .await
        .unwrap()
    {
        WaitOutcome::Finished(upload) => upload,
        other => panic!("Diagnostics upload did not finish: {other:?}"),
    };
    assert_eq!(upload.status, UploadStatus::Ready, "{upload:?}");
    let bytes = fleet
        .download_agent_file(&upload.id, &upload.name)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert!(
        bytes.starts_with(b"PK"),
        "diagnostics must be a ZIP archive"
    );

    let upgrade = fleet
        .upgrade_agent(&agent_id, &env("KIBANA_TEST_VERSION"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(upgrade.status(), Some(StatusCode::BAD_REQUEST));
    assert!(
        upgrade.body().unwrap().contains("not upgradeable"),
        "{upgrade:?}"
    );

    let task = fleet
        .bulk_update_agent_tags(ids(&[&agent_id]))
        .batch_size(1)
        .remove_tags(["owned-fixture"])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, task).await);
    assert!(
        !agent_tags(&client, &agent_id)
            .await
            .contains(&"owned-fixture".to_owned())
    );
}

async fn alerts_for(rule_id: &str) -> u64 {
    search(
        ".alerts-security.alerts-default",
        json!({"term": {"kibana.alert.rule.rule_id": rule_id}}),
    )
    .await
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner with a real Agent"]
async fn agent_policy_delivery_ingestion_reassignment_and_unenrollment() {
    let client = admin();
    let fleet = client.fleet();
    let agent_id = env("KIBANA_TEST_AGENT_ID");
    let agent = fleet
        .get_agent(&agent_id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(agent.policy_id.as_deref(), Some("fixture-agent"));
    assert!(
        fleet
            .find_agents()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .items
            .iter()
            .any(|a| a.id == agent_id)
    );
    let system = PackageRef::new("system", env("KIBANA_TEST_SYSTEM_VERSION"));
    let package = fleet
        .create_package_policy(
            &NewPackagePolicy::new("fixture-system", "fixture", system)
                .policy_id("fixture-agent")
                .description("Controlled log fixture")
                .input(
                    "system-logfile",
                    PolicyInput::new()
                        .enabled(true)
                        .stream(
                            "system.syslog",
                            PolicyStream::new()
                                .enabled(true)
                                .var("paths", json!(["/fixtures/system.log"])),
                        )
                        .stream("system.auth", PolicyStream::new().enabled(false)),
                )
                .input("system-system/metrics", PolicyInput::new().enabled(false)),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    let policy = fleet
        .get_agent_policy("fixture-agent")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    wait_for_policy(&client, &agent_id, &policy.id, policy.revision).await;
    let marker = env("KIBANA_TEST_MARKER");
    let deadline = Instant::now() + Duration::from_secs(180);
    while search(
        "logs-system.syslog-fixture",
        json!({"match_phrase": {"message": marker}}),
    )
    .await
        == 0
    {
        assert!(
            Instant::now() < deadline,
            "Agent did not ingest the fixture marker"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    client
        .security()
        .create_alerts_index()
        .send()
        .await
        .unwrap();
    let exception_list = client
        .exceptions()
        .create_list(&NewList::detection(
            "Suppress fixture",
            "Verify exceptions affect execution",
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    client
        .exceptions()
        .create_item(&NewItem::new(
            &exception_list,
            "Events containing a message",
            vec![Entry::Exists {
                field: "message".into(),
                operator: Operator::Included,
            }],
        ))
        .send()
        .await
        .unwrap();
    let request = QueryRule::new(
        "Fixture alert",
        "Controlled event detection",
        format!("message: \"{marker}\""),
    )
    .index(["logs-system.syslog-fixture"])
    .enabled(true)
    .custom_schedule("1m", "now-15m")
    .exceptions_list(vec![exception_list.reference()]);
    let rule = client
        .security()
        .create_rule(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let current = client
            .security()
            .get_rule(RuleSelector::Id(&rule.id))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let execution = current
            .execution_summary
            .as_ref()
            .map(|summary| &summary.last_execution);
        if execution.is_some_and(|execution| execution.status == "succeeded") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Rule did not execute with exceptions: {execution:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let refresh = reqwest::Client::builder()
        .add_root_certificate(ca())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
        .post(format!(
            "{}/.alerts-security.alerts-default/_refresh",
            env("ELASTICSEARCH_URL")
        ))
        .basic_auth("elastic", Some(env("KIBANA_PASSWORD")))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(refresh["_shards"]["failed"], 0);
    assert_eq!(alerts_for(&rule.rule_id).await, 0);
    client
        .security()
        .patch_rule(RuleSelector::Id(&rule.id))
        .exceptions_list(vec![])
        .send()
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    while alerts_for(&rule.rule_id).await == 0 {
        assert!(
            Instant::now() < deadline,
            "Enabled rule did not produce an alert for the fixture event"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    client
        .security()
        .patch_rule(RuleSelector::Id(&rule.id))
        .enabled(false)
        .send()
        .await
        .unwrap();
    client
        .security()
        .delete_rule(RuleSelector::Id(&rule.id))
        .send()
        .await
        .unwrap();

    let changed = NewAgentPolicy::new(&policy.name, &policy.namespace)
        .description("Policy revision acknowledgment test")
        .monitoring_enabled(Vec::<String>::new());
    let updated = fleet
        .update_agent_policy(&policy.id, &changed)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert!(updated.revision > policy.revision);
    wait_for_policy(&client, &agent_id, &policy.id, updated.revision).await;
    fleet
        .reassign_agent(&agent_id, "fixture-agent-target")
        .send()
        .await
        .unwrap();
    let target = fleet
        .get_agent_policy("fixture-agent-target")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    wait_for_policy(&client, &agent_id, &target.id, target.revision).await;
    let unenroll = fleet
        .bulk_unenroll_agents(ids(&[&agent_id]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, unenroll).await);
    let deadline = Instant::now() + Duration::from_secs(180);
    while fleet
        .get_agent(&agent_id)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item
        .active
        != Some(false)
    {
        assert!(
            Instant::now() < deadline,
            "Agent did not finish unenrollment"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    fleet
        .delete_package_policy(&package.id)
        .send()
        .await
        .unwrap();
    client
        .exceptions()
        .delete_list(ListSelector::Id(&exception_list.id))
        .send()
        .await
        .unwrap();
    let version = env("KIBANA_TEST_SYSTEM_VERSION");
    fleet
        .uninstall_package("system", &version)
        .send()
        .await
        .unwrap();
    assert_ne!(
        fleet
            .get_package("system", &version)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .item
            .status
            .as_deref(),
        Some("installed")
    );
}
