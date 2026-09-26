//! Executed by tests/deployment/run.py against a disposable, digest-locked stack.
use kibana_rs::exceptions::{Entry, ListSelector, NamespaceType, NewItem, NewList, Operator};
use kibana_rs::fleet::{
    ActionOptions, AgentActionStatus, AgentSelection, BulkActionResult, BulkAgents,
    DiagnosticsOptions, TagUpdate, UnenrollOptions, UpgradeAgent,
};
use kibana_rs::{
    Auth, Client, Error, PageOptions, StatusCode,
    fleet::{AgentPolicyRequest, PackagePolicyRequest, PackageRef, PolicyInput, PolicyStream},
    security::{FindRules, QueryRule, RulePatch, RuleSelector},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must come from the deployment runner"))
}

fn ca() -> reqwest::Certificate {
    reqwest::Certificate::from_pem(&std::fs::read(env("KIBANA_CA_CERT")).unwrap()).unwrap()
}

fn client(auth: Auth) -> Client {
    Client::builder(env("KIBANA_URL"))
        .auth(auth)
        .root_certificate(ca())
        .timeout(Duration::from_secs(90))
        .build()
        .unwrap()
}

fn basic(username: &str, variable: &str) -> Auth {
    Auth::Basic {
        username: username.into(),
        password: env(variable),
    }
}

fn admin() -> Client {
    client(basic("elastic", "KIBANA_PASSWORD"))
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner"]
async fn tls_authentication_and_space_permissions() {
    let untrusted = Client::builder(env("KIBANA_URL"))
        .auth(basic("elastic", "KIBANA_PASSWORD"))
        .build()
        .unwrap();
    assert!(
        matches!(untrusted.status().await.unwrap_err(), Error::Transport(error) if error.is_connect()),
        "Untrusted CA must fail before HTTP"
    );
    assert_eq!(
        admin().status().await.unwrap()["version"]["number"],
        env("KIBANA_TEST_VERSION")
    );

    let writer = client(basic("fixture_writer", "KIBANA_TEST_WRITER_PASSWORD"))
        .space("fixture")
        .unwrap();
    let reader = client(basic("fixture_reader", "KIBANA_TEST_READER_PASSWORD"))
        .space("fixture")
        .unwrap();
    let api_key = client(Auth::ApiKey(env("KIBANA_TEST_API_KEY")))
        .space("fixture")
        .unwrap();
    writer
        .security()
        .rules(&FindRules::default())
        .await
        .unwrap();
    reader
        .security()
        .rules(&FindRules::default())
        .await
        .unwrap();
    api_key
        .security()
        .rules(&FindRules::default())
        .await
        .unwrap();
    let request = QueryRule::new(
        "Permission fixture",
        "Disposable test",
        "event.outcome: failure",
    );
    let rule = api_key.security().create_rule(&request).await.unwrap();
    let exception_request = NewList::detection("Permission exception", "Owned permission fixture");
    let exception_list = api_key
        .exceptions()
        .create_list(&exception_request)
        .await
        .unwrap();
    assert_eq!(
        reader
            .exceptions()
            .list(ListSelector::Id(&exception_list.id), NamespaceType::Single)
            .await
            .unwrap()
            .id,
        exception_list.id
    );
    assert_eq!(
        reader
            .exceptions()
            .create_list(&exception_request)
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        api_key
            .default_space()
            .exceptions()
            .list(ListSelector::Id(&exception_list.id), NamespaceType::Single)
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    writer
        .exceptions()
        .delete_list(ListSelector::Id(&exception_list.id), NamespaceType::Single)
        .await
        .unwrap();
    assert_eq!(
        reader
            .fleet()
            .bulk_update_agent_tags(
                &BulkAgents::new(AgentSelection::Ids(vec!["not-an-agent".into()])),
                &TagUpdate {
                    tags_to_add: vec!["denied".into()],
                    ..Default::default()
                }
            )
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        writer
            .security()
            .rule(RuleSelector::Id(&rule.id))
            .await
            .unwrap()
            .id,
        rule.id
    );
    assert_eq!(
        reader
            .security()
            .create_rule(&request)
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        writer
            .default_space()
            .security()
            .rules(&FindRules::default())
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        api_key
            .default_space()
            .security()
            .rules(&FindRules::default())
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        writer.roles().list().await.unwrap_err().status(),
        Some(StatusCode::FORBIDDEN)
    );
    let wrong = client(Auth::Basic {
        username: "fixture_writer".into(),
        password: "deliberately-wrong".into(),
    })
    .space("fixture")
    .unwrap();
    assert_eq!(
        wrong
            .security()
            .rules(&FindRules::default())
            .await
            .unwrap_err()
            .status(),
        Some(StatusCode::UNAUTHORIZED)
    );
    writer
        .security()
        .delete_rule(RuleSelector::Id(&rule.id))
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
        expected.push(client.security().create_rule(&request).await.unwrap().id);
    }
    let mut received = Vec::new();
    for page in 1..=2 {
        let response = client
            .security()
            .rules(&FindRules {
                page,
                per_page: 2,
                filter: None,
            })
            .await
            .unwrap();
        assert_eq!(response.total, 3);
        assert_eq!(response.data.len(), if page == 1 { 2 } else { 1 });
        received.extend(response.data.into_iter().map(|r| r.id));
    }
    expected.sort();
    received.sort();
    assert_eq!(received, expected);
    for id in expected {
        client
            .security()
            .delete_rule(RuleSelector::Id(&id))
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

async fn wait_for_policy(client: &Client, agent_id: &str, policy: &str, revision: u64) {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let agent = client.fleet().agent(agent_id).await.unwrap();
        if agent.policy_id.as_deref() == Some(policy)
            && agent.extra.get("policy_revision").and_then(Value::as_u64) == Some(revision)
            && agent.status.as_deref() == Some("online")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Agent did not acknowledge policy {policy} revision {revision}; last status={:?}, revision={:?}",
            agent.status,
            agent.extra.get("policy_revision")
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn wait_for_action(client: &Client, result: BulkActionResult) -> AgentActionStatus {
    let BulkActionResult::Action { action_id } = result else {
        panic!("expected an action, received dry-run result")
    };
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let actions = client
            .fleet()
            .agent_actions(&ActionOptions {
                per_page: 100,
                ..Default::default()
            })
            .await
            .unwrap();
        if let Some(action) = actions.items.into_iter().find(|a| a.action_id == action_id)
            && matches!(
                action.status.as_str(),
                "COMPLETE" | "FAILED" | "CANCELLED" | "EXPIRED"
            )
        {
            return action;
        }
        assert!(
            Instant::now() < deadline,
            "Action {action_id} did not finish"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn successful_action(action: &AgentActionStatus) {
    assert_eq!(action.status, "COMPLETE", "{action:?}");
    assert_eq!(action.nb_agents_failed, 0, "{action:?}");
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner with a real Agent"]
async fn fleet_agent_bulk_actions_and_diagnostics() {
    let client = admin();
    let agent_id = env("KIBANA_TEST_AGENT_ID");
    let peer_id = env("KIBANA_TEST_PEER_ID");
    let mut selection = BulkAgents::new(AgentSelection::Ids(vec![agent_id.clone()]));
    selection.batch_size = Some(1);
    selection.dry_run = true;
    let preview = client
        .fleet()
        .bulk_unenroll_agents(&selection, &UnenrollOptions::default())
        .await
        .unwrap();
    assert!(matches!(preview, BulkActionResult::DryRun { count: 1 }));
    assert_eq!(
        client.fleet().agent(&agent_id).await.unwrap().active,
        Some(true)
    );

    selection.dry_run = false;
    let tags = TagUpdate {
        tags_to_add: vec!["owned-fixture".into()],
        ..Default::default()
    };
    let task = client
        .fleet()
        .bulk_update_agent_tags(&selection, &tags)
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, task).await);
    assert!(
        client.fleet().agent(&agent_id).await.unwrap().extra["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("owned-fixture"))
    );

    let target = client
        .fleet()
        .agent_policy("fixture-agent-target")
        .await
        .unwrap();
    let both = BulkAgents::new(AgentSelection::Ids(vec![agent_id.clone(), peer_id.clone()]));
    let task = client
        .fleet()
        .bulk_reassign_agents(&both, &target.id, false)
        .await
        .unwrap();
    let partial = wait_for_action(&client, task).await;
    assert_eq!(partial.status, "FAILED", "{partial:?}");
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

    let repeated = client
        .fleet()
        .bulk_reassign_agents(&selection, &target.id, false)
        .await
        .unwrap_err();
    assert_eq!(repeated.status(), Some(StatusCode::BAD_REQUEST));
    assert!(repeated.body().unwrap().contains("No agents to reassign"));

    let original = client.fleet().agent_policy("fixture-agent").await.unwrap();
    let task = client
        .fleet()
        .bulk_reassign_agents(&selection, &original.id, false)
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, task).await);
    wait_for_policy(&client, &agent_id, &original.id, original.revision).await;

    let by_query = BulkAgents {
        agents: AgentSelection::Query("policy_id:fixture-agent".into()),
        dry_run: true,
        batch_size: None,
    };
    assert!(matches!(
        client
            .fleet()
            .bulk_request_agent_diagnostics(&by_query, &DiagnosticsOptions::default())
            .await
            .unwrap(),
        BulkActionResult::DryRun { count: 1 }
    ));
    let diagnostics = client
        .fleet()
        .request_agent_diagnostics(&agent_id, &DiagnosticsOptions::default())
        .await
        .unwrap();
    let action = wait_for_action(&client, diagnostics).await;
    successful_action(&action);
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let uploads = client.fleet().agent_uploads(&agent_id).await.unwrap();
        if let Some(upload) = uploads
            .items
            .into_iter()
            .find(|u| u.action_id == action.action_id)
        {
            assert_ne!(upload.status, "FAILED", "{upload:?}");
            if upload.status == "READY" {
                let response = client
                    .fleet()
                    .download_agent_file(&upload.id, &upload.name)
                    .await
                    .unwrap();
                let bytes = response.bytes().await.unwrap();
                assert!(
                    bytes.starts_with(b"PK"),
                    "diagnostics must be a ZIP archive"
                );
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "Diagnostics upload did not become READY"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let upgrade = client
        .fleet()
        .upgrade_agent(&agent_id, &UpgradeAgent::new(env("KIBANA_TEST_VERSION")))
        .await
        .unwrap_err();
    assert_eq!(upgrade.status(), Some(StatusCode::BAD_REQUEST));
    assert!(
        upgrade.body().unwrap().contains("not upgradeable"),
        "{upgrade:?}"
    );

    let tags = TagUpdate {
        tags_to_remove: vec!["owned-fixture".into()],
        ..Default::default()
    };
    successful_action(
        &wait_for_action(
            &client,
            client
                .fleet()
                .bulk_update_agent_tags(&selection, &tags)
                .await
                .unwrap(),
        )
        .await,
    );
    assert!(
        !client.fleet().agent(&agent_id).await.unwrap().extra["tags"]
            .as_array()
            .unwrap()
            .contains(&json!("owned-fixture"))
    );
}

#[tokio::test]
#[ignore = "requires the disposable deployment runner with a real Agent"]
async fn agent_policy_delivery_ingestion_reassignment_and_unenrollment() {
    let client = admin();
    let agent_id = env("KIBANA_TEST_AGENT_ID");
    let agent = client.fleet().agent(&agent_id).await.unwrap();
    assert_eq!(agent.policy_id.as_deref(), Some("fixture-agent"));
    assert!(
        client
            .fleet()
            .agents(&PageOptions::default())
            .await
            .unwrap()
            .items
            .iter()
            .any(|a| a.id == agent_id)
    );
    let package = client
        .fleet()
        .create_package_policy(&PackagePolicyRequest {
            name: "fixture-system".into(),
            namespace: "fixture".into(),
            policy_ids: vec!["fixture-agent".into()],
            package: PackageRef {
                name: "system".into(),
                version: env("KIBANA_TEST_SYSTEM_VERSION"),
            },
            inputs: BTreeMap::from([
                (
                    "system-logfile".into(),
                    PolicyInput {
                        enabled: Some(true),
                        vars: BTreeMap::new(),
                        streams: BTreeMap::from([
                            (
                                "system.syslog".into(),
                                PolicyStream {
                                    enabled: Some(true),
                                    vars: BTreeMap::from([(
                                        "paths".into(),
                                        json!(["/fixtures/system.log"]),
                                    )]),
                                },
                            ),
                            (
                                "system.auth".into(),
                                PolicyStream {
                                    enabled: Some(false),
                                    vars: BTreeMap::new(),
                                },
                            ),
                        ]),
                    },
                ),
                (
                    "system-system/metrics".into(),
                    PolicyInput {
                        enabled: Some(false),
                        ..Default::default()
                    },
                ),
            ]),
            description: Some("Controlled log fixture".into()),
        })
        .await
        .unwrap();
    let policy = client.fleet().agent_policy("fixture-agent").await.unwrap();
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

    client.security().initialize().await.unwrap();
    let mut request = QueryRule::new(
        "Fixture alert",
        "Controlled event detection",
        format!("message: \"{marker}\""),
    );
    request.index = vec!["logs-system.syslog-fixture".into()];
    request.enabled = true;
    request.interval = "1m".into();
    request.from = "now-15m".into();
    let exception_list = client
        .exceptions()
        .create_list(&NewList::detection(
            "Suppress fixture",
            "Verify exceptions affect execution",
        ))
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
        .await
        .unwrap();
    request.exceptions_list = vec![exception_list.reference()];
    let rule = client.security().create_rule(&request).await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let current = client
            .security()
            .rule(RuleSelector::Id(&rule.id))
            .await
            .unwrap();
        let execution = current
            .extra
            .get("execution_summary")
            .and_then(|summary| summary.get("last_execution"))
            .unwrap_or(&Value::Null);
        if execution["status"] == "succeeded" {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Rule did not execute with exceptions: {execution}"
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
    assert_eq!(
        search(
            ".alerts-security.alerts-default",
            json!({"term": {"kibana.alert.rule.rule_id": rule.rule_id}})
        )
        .await,
        0
    );
    client
        .security()
        .update_rule(
            RuleSelector::Id(&rule.id),
            &RulePatch {
                exceptions_list: Some(vec![]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    while search(
        ".alerts-security.alerts-default",
        json!({"term": {"kibana.alert.rule.rule_id": rule.rule_id}}),
    )
    .await
        == 0
    {
        assert!(
            Instant::now() < deadline,
            "Enabled rule did not produce an alert for the fixture event"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    client
        .security()
        .update_rule(
            RuleSelector::Id(&rule.id),
            &RulePatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    client
        .security()
        .delete_rule(RuleSelector::Id(&rule.id))
        .await
        .unwrap();

    let mut changed = AgentPolicyRequest::new(policy.name, policy.namespace);
    changed.description = Some("Policy revision acknowledgment test".into());
    changed.monitoring_enabled = Some(vec![]);
    let updated = client
        .fleet()
        .update_agent_policy(&policy.id, &changed)
        .await
        .unwrap();
    assert!(updated.revision > policy.revision);
    wait_for_policy(&client, &agent_id, &policy.id, updated.revision).await;
    client
        .fleet()
        .reassign_agent(&agent_id, "fixture-agent-target")
        .await
        .unwrap();
    let target = client
        .fleet()
        .agent_policy("fixture-agent-target")
        .await
        .unwrap();
    wait_for_policy(&client, &agent_id, &target.id, target.revision).await;
    let selection = BulkAgents::new(AgentSelection::Ids(vec![agent_id.clone()]));
    let unenroll = client
        .fleet()
        .bulk_unenroll_agents(&selection, &UnenrollOptions::default())
        .await
        .unwrap();
    successful_action(&wait_for_action(&client, unenroll).await);
    let deadline = Instant::now() + Duration::from_secs(180);
    while client.fleet().agent(&agent_id).await.unwrap().active != Some(false) {
        assert!(
            Instant::now() < deadline,
            "Agent did not finish unenrollment"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    client
        .fleet()
        .delete_package_policy(&package.id)
        .await
        .unwrap();
    client
        .exceptions()
        .delete_list(ListSelector::Id(&exception_list.id), NamespaceType::Single)
        .await
        .unwrap();
    client
        .fleet()
        .uninstall_integration("system", &env("KIBANA_TEST_SYSTEM_VERSION"))
        .await
        .unwrap();
    assert_ne!(
        client
            .fleet()
            .integration("system", &env("KIBANA_TEST_SYSTEM_VERSION"))
            .await
            .unwrap()
            .status
            .as_deref(),
        Some("installed")
    );
}
