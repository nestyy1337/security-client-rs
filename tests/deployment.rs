//! Executed by tests/deployment/run.py against a disposable, digest-locked stack.
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
    let response = http
        .post(format!(
            "{}/{index}/_search?ignore_unavailable=true",
            env("ELASTICSEARCH_URL")
        ))
        .basic_auth("elastic", Some(env("KIBANA_PASSWORD")))
        .json(&json!({"query": query, "size": 0, "track_total_hits": true}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    response["hits"]["total"]["value"].as_u64().unwrap()
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
    let rule = client.security().create_rule(&request).await.unwrap();
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
    client.fleet().unenroll_agent(&agent_id).await.unwrap();
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
