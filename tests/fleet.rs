mod common;

use common::Mock;
use kibana_rs::{
    Error, SortOrder,
    fleet::{
        AgentPolicy, AgentSelection, BulkActionResult, DiagnosticMetric, NewAgentPolicy,
        NewPackagePolicy, PackagePolicy, PackageRef, PolicyInput, PolicyStream,
    },
};
use serde_json::{Value, json};

fn policy(id: &str) -> Value {
    json!({"id": id, "name": "SOC Linux", "namespace": "default", "revision": 3,
           "status": "active", "agents": 2, "package_policies": [{"id": "pp"}], "is_managed": false})
}

fn package_policy(id: &str) -> Value {
    json!({"id": id, "name": "system-1", "namespace": "default", "enabled": true, "revision": 1,
           "package": {"name": "system", "version": "2.5.0"}, "policy_ids": ["p1"], "inputs": []})
}

fn ids() -> AgentSelection {
    AgentSelection::Ids(vec!["one".into(), "two".into()])
}

#[tokio::test]
async fn setup_and_enrollment_keys() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"isInitialized": true, "nonFatalErrors": []}));
    assert_eq!(
        client
            .fleet()
            .setup()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()["isInitialized"],
        true
    );
    mock.take()
        .route("POST", "/s/soc/api/fleet/setup", &[])
        .no_body();

    let key = json!({"id": "key-id", "api_key_id": "es-key", "api_key": "do-not-log-this-key", "active": true,
                     "policy_id": "p1", "name": "laptops", "expire_at": "2030-01-01T00:00:00Z"});
    mock.json(json!({"items": [key], "page": 2, "perPage": 1, "total": 2}));
    let page = client
        .fleet()
        .find_enrollment_keys()
        .page(2)
        .per_page(1)
        .kuery("policy_id:p1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((page.page, page.per_page, page.total), (2, 1, 2));
    assert!(!format!("{:?}", page.items[0]).contains("do-not-log-this-key"));
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/enrollment_api_keys",
        &[("page", "2"), ("perPage", "1"), ("kuery", "policy_id:p1")],
    );

    mock.json(json!({"item": key}));
    let fetched = client
        .fleet()
        .get_enrollment_key("key-id")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(fetched.api_key, "do-not-log-this-key");
    assert_eq!(fetched.policy_id.as_deref(), Some("p1"));
    mock.take()
        .route("GET", "/s/soc/api/fleet/enrollment_api_keys/key-id", &[]);

    mock.json(json!({"item": key, "action": "created"}));
    client
        .fleet()
        .create_enrollment_key("p1")
        .name("laptops")
        .expiration("24h")
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/enrollment_api_keys", &[])
        .body(json!({"policy_id": "p1", "name": "laptops", "expiration": "24h"}));

    mock.json(json!({"action": "deleted"}));
    client
        .fleet()
        .revoke_enrollment_key("key-id")
        .send()
        .await
        .unwrap();
    mock.take()
        .route("DELETE", "/s/soc/api/fleet/enrollment_api_keys/key-id", &[])
        .no_body();
}

#[tokio::test]
async fn agents_are_listed_read_and_managed_individually() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let agent = json!({"id": "a/1", "policy_id": "p1", "active": true, "status": "online",
                       "local_metadata": {"host": {"hostname": "web-1"}}, "policy_revision": 3, "tags": ["dmz"]});
    mock.json(json!({"items": [agent], "page": 1, "perPage": 20, "total": 1, "statusSummary": {}}));
    let page = client
        .fleet()
        .find_agents()
        .page(1)
        .per_page(20)
        .kuery("tags:dmz")
        .show_inactive(true)
        .sort_field("last_checkin")
        .sort_order(SortOrder::Desc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.items[0].local_metadata["host"]["hostname"], "web-1");
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/agents",
        &[
            ("page", "1"),
            ("perPage", "20"),
            ("kuery", "tags:dmz"),
            ("showInactive", "true"),
            ("sortField", "last_checkin"),
            ("sortOrder", "desc"),
        ],
    );

    mock.json(json!({"item": agent}));
    let fetched = client
        .fleet()
        .get_agent("a/1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(fetched.policy_revision, Some(3));
    assert_eq!(fetched.tags.as_deref(), Some(&["dmz".to_owned()][..]));
    mock.take()
        .route("GET", "/s/soc/api/fleet/agents/a%2F1", &[]);

    mock.json(json!({"results": {"online": 1}}));
    client
        .fleet()
        .agent_status()
        .policy_id("p1")
        .kuery("tags:dmz")
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/agent_status",
        &[("policyId", "p1"), ("kuery", "tags:dmz")],
    );

    mock.json(json!({}));
    client
        .fleet()
        .reassign_agent("one", "p2")
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agents/one/reassign", &[])
        .body(json!({"policy_id": "p2"}));

    mock.json(json!({}));
    client.fleet().unenroll_agent("one").send().await.unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agents/one/unenroll", &[])
        .body(json!({}));
    mock.json(json!({}));
    client
        .fleet()
        .unenroll_agent("one")
        .force(true)
        .revoke(true)
        .send()
        .await
        .unwrap();
    mock.take().body(json!({"force": true, "revoke": true}));

    mock.json(json!({}));
    client
        .fleet()
        .upgrade_agent("one", "9.5.4")
        .force(true)
        .source_uri("https://artifacts.internal/")
        .skip_rate_limit_check(true)
        .send()
        .await
        .unwrap();
    mock.take().route("POST", "/s/soc/api/fleet/agents/one/upgrade", &[]).body(json!({
        "version": "9.5.4", "force": true, "source_uri": "https://artifacts.internal/", "skipRateLimitCheck": true
    }));

    mock.json(json!({"actionId": "diag"}));
    let result = client
        .fleet()
        .request_agent_diagnostics("one")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(result, BulkActionResult::Action { action_id } if action_id == "diag"));
    mock.take()
        .route(
            "POST",
            "/s/soc/api/fleet/agents/one/request_diagnostics",
            &[],
        )
        .body(json!({}));
    mock.json(json!({"actionId": "diag"}));
    client
        .fleet()
        .request_agent_diagnostics("one")
        .additional_metrics(vec![DiagnosticMetric::Cpu])
        .send()
        .await
        .unwrap();
    mock.take().body(json!({"additional_metrics": ["CPU"]}));
}

#[tokio::test]
async fn bulk_actions_send_selection_options_and_decode_dry_runs() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let query = || AgentSelection::Query("tags:owned-fixture".into());

    mock.json(json!({"count": 2}));
    let result = client
        .fleet()
        .bulk_upgrade_agents(query(), "9.5.4")
        .dry_run(true)
        .batch_size(2)
        .include_inactive(false)
        .start_time("2030-01-01T00:00:00Z")
        .rollout_duration_seconds(600)
        .force(false)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(matches!(result, BulkActionResult::DryRun { count: 2 }));
    mock.take().route("POST", "/s/soc/api/fleet/agents/bulk_upgrade", &[]).body(json!({
        "agents": "tags:owned-fixture", "version": "9.5.4", "dryRun": true, "batchSize": 2,
        "includeInactive": false, "start_time": "2030-01-01T00:00:00Z", "rollout_duration_seconds": 600,
        "force": false
    }));

    mock.json(json!({"actionId": "tags"}));
    client
        .fleet()
        .bulk_update_agent_tags(ids())
        .add_tags(["investigate"])
        .remove_tags(["old"])
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "POST",
            "/s/soc/api/fleet/agents/bulk_update_agent_tags",
            &[],
        )
        .body(json!({
            "agents": ["one", "two"], "tagsToAdd": ["investigate"], "tagsToRemove": ["old"]
        }));

    mock.json(json!({"actionId": "reassign"}));
    client
        .fleet()
        .bulk_reassign_agents(ids(), "p2")
        .include_inactive(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agents/bulk_reassign", &[])
        .body(json!({"agents": ["one", "two"], "policy_id": "p2", "includeInactive": true}));

    mock.json(json!({"actionId": "unenroll"}));
    client
        .fleet()
        .bulk_unenroll_agents(query())
        .force(true)
        .revoke(false)
        .batch_size(100)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agents/bulk_unenroll", &[])
        .body(json!({
            "agents": "tags:owned-fixture", "force": true, "revoke": false, "batchSize": 100
        }));

    mock.json(json!({"actionId": "diagnostics"}));
    client
        .fleet()
        .bulk_request_agent_diagnostics(ids())
        .additional_metrics(vec![DiagnosticMetric::Cpu])
        .dry_run(false)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "POST",
            "/s/soc/api/fleet/agents/bulk_request_diagnostics",
            &[],
        )
        .body(json!({
            "agents": ["one", "two"], "additional_metrics": ["CPU"], "dryRun": false
        }));
}

#[tokio::test]
async fn action_history_cancellation_uploads_and_binary_downloads() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.json(json!({"items": [{"actionId": "mixed", "type": "FUTURE_ACTION", "status": "IN_PROGRESS",
        "nbAgentsActionCreated": 3, "nbAgentsAck": 1, "nbAgentsFailed": 1, "nbAgentsActioned": 3,
        "latestErrors": [{"agentId": "failed-agent", "error": "agent unavailable"}], "future_detail": "retained"}]}));
    let actions = client
        .fleet()
        .agent_action_status()
        .page(0)
        .per_page(20)
        .date("2026-09-01T00:00:00Z")
        .latest(3600)
        .error_size(5)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(actions.items[0].nb_agents_failed, 1);
    assert_eq!(actions.items[0].latest_errors[0]["agentId"], "failed-agent");
    assert_eq!(actions.items[0].extra["future_detail"], "retained");
    mock.take().route(
        "GET",
        "/api/fleet/agents/action_status",
        &[
            ("page", "0"),
            ("perPage", "20"),
            ("date", "2026-09-01T00:00:00Z"),
            ("latest", "3600"),
            ("errorSize", "5"),
        ],
    );

    mock.json(json!({"item": {"id": "cancel-id", "type": "CANCEL"}}));
    assert_eq!(
        client
            .fleet()
            .cancel_agent_action("upgrade/id")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()["item"]["id"],
        "cancel-id"
    );
    mock.take()
        .route("POST", "/api/fleet/agents/actions/upgrade%2Fid/cancel", &[])
        .body(json!({}));

    mock.json(
        json!({"items": [{"id": "file-1", "name": "diag.zip", "actionId": "diag", "status": "READY",
                                "createTime": "2026-09-28T00:00:00Z"}]}),
    );
    let uploads = client
        .fleet()
        .list_agent_uploads("one")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (
            uploads.items[0].status.as_str(),
            uploads.items[0].error.as_deref()
        ),
        ("READY", None)
    );
    mock.take()
        .route("GET", "/api/fleet/agents/one/uploads", &[]);

    mock.reply_with(
        200,
        vec![("content-type", "application/octet-stream".into())],
        vec![80, 75, 3, 4, 0, 255],
    );
    let bytes = client
        .fleet()
        .download_agent_file("file/id", "diagnostics file.zip")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(bytes.as_ref(), &[80, 75, 3, 4, 0, 255]);
    mock.take().route(
        "GET",
        "/api/fleet/agents/files/file%2Fid/diagnostics%20file.zip",
        &[],
    );
}

#[tokio::test]
async fn agent_policy_updates_check_optional_body_ids_against_the_path() {
    let mock = Mock::start().await;
    let client = mock.soc();
    for body in [
        json!({"id": "other-policy", "name": "Wrong policy", "namespace": "default"}),
        json!({"id": null}),
        json!({"id": 1}),
        json!({"id": ""}),
        json!([{"id": "p/1"}]),
        json!(null),
    ] {
        let error = client
            .fleet()
            .update_agent_policy("p/1", &body)
            .send()
            .await
            .unwrap_err();
        assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    }
    assert_eq!(mock.request_count(), 0);

    for body in [
        json!({"name": "SOC Linux", "namespace": "default"}),
        json!({"id": "p/1", "name": "SOC Linux", "namespace": "default",
            "future_setting": {"id": "another-id"}}),
    ] {
        mock.json(json!({"item": policy("p/1")}));
        client
            .fleet()
            .update_agent_policy("p/1", &body)
            .send()
            .await
            .unwrap();
        mock.take()
            .route("PUT", "/s/soc/api/fleet/agent_policies/p%2F1", &[])
            .body(body);
    }
}

#[tokio::test]
async fn agent_policy_edits_bind_identity_and_only_send_requested_settings() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let mut original = policy("p/1");
    original["description"] = json!("Keep this description");
    original["inactivity_timeout"] = json!(3600);
    original["monitoring_enabled"] = json!(["logs"]);
    original["data_output_id"] = json!("existing-output");
    original["monitoring_output_id"] = json!("monitoring-output");
    original["updated_at"] = json!("2026-09-30T10:00:00Z");
    original["future_setting"] = json!({"enabled": true});
    mock.json(json!({"item": original}));
    let fetched = client
        .fleet()
        .get_agent_policy("p/1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    mock.take()
        .route("GET", "/s/soc/api/fleet/agent_policies/p%2F1", &[]);

    let edit = fetched.edit().unwrap().name("Renamed");
    mock.json(json!({"item": original}));
    client
        .fleet()
        .edit_agent_policy(&edit)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/fleet/agent_policies/p%2F1", &[])
        .body(json!({"name": "Renamed", "namespace": "default", "inactivity_timeout": 3600}));

    let edit = fetched
        .edit()
        .unwrap()
        .namespace("soc")
        .description("")
        .monitoring_enabled(Vec::<String>::new())
        .inactivity_timeout(0)
        .data_output_id("replacement-output")
        .clear_data_output_id();
    mock.json(json!({"item": original}));
    client
        .fleet()
        .edit_agent_policy(&edit)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/fleet/agent_policies/p%2F1", &[])
        .body(
            json!({"name": "SOC Linux", "namespace": "soc", "inactivity_timeout": 0,
            "description": "", "monitoring_enabled": [], "data_output_id": null}),
        );
}

#[tokio::test]
async fn agent_policy_outputs_can_be_omitted_selected_or_cleared() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let minimal = NewAgentPolicy::new("SOC Linux", "default");
    let base = json!({"name": "SOC Linux", "namespace": "default"});
    let mut selected = base.clone();
    selected["data_output_id"] = json!("output-id");
    let mut cleared = base.clone();
    cleared["data_output_id"] = Value::Null;
    for (definition, expected) in [
        (minimal.clone(), base),
        (
            minimal.clone().data_output_id("output-id"),
            selected.clone(),
        ),
        (
            minimal
                .clone()
                .data_output_id("output-id")
                .clear_data_output_id(),
            cleared,
        ),
        (
            minimal.clear_data_output_id().data_output_id("output-id"),
            selected,
        ),
    ] {
        mock.json(json!({"item": policy("p1")}));
        client
            .fleet()
            .update_agent_policy("p1", &definition)
            .send()
            .await
            .unwrap();
        mock.take()
            .route("PUT", "/s/soc/api/fleet/agent_policies/p1", &[])
            .body(expected);
    }
}

#[test]
fn agent_policy_edits_require_a_retrieved_inactivity_timeout() {
    let mut body = policy("p1");
    let fetched: AgentPolicy = serde_json::from_value(body.clone()).unwrap();
    assert!(matches!(fetched.edit(), Err(Error::InvalidRequest(_))));
    for invalid in [Value::Null, json!("3600"), json!(-1), json!(1.5)] {
        body["inactivity_timeout"] = invalid;
        let fetched: AgentPolicy = serde_json::from_value(body.clone()).unwrap();
        assert!(matches!(fetched.edit(), Err(Error::InvalidRequest(_))));
    }
    body["inactivity_timeout"] = json!(0);
    let fetched: AgentPolicy = serde_json::from_value(body).unwrap();
    assert!(fetched.edit().is_ok());
}

#[tokio::test]
async fn agent_policies_lifecycle() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"items": [policy("p1")], "page": 1, "perPage": 50, "total": 1}));
    let page = client
        .fleet()
        .find_agent_policies()
        .per_page(50)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (page.items[0].agents, page.items[0].package_policies.len()),
        (Some(2), 1)
    );
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/agent_policies",
        &[
            ("full", "true"),
            ("withAgentCount", "true"),
            ("perPage", "50"),
        ],
    );
    mock.json(json!({"items": [], "page": 2, "perPage": 1, "total": 0}));
    client
        .fleet()
        .find_agent_policies()
        .full(false)
        .with_agent_count(false)
        .page(2)
        .kuery("name:SOC*")
        .sort_field("updated_at")
        .sort_order(SortOrder::Asc)
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/agent_policies",
        &[
            ("full", "false"),
            ("withAgentCount", "false"),
            ("page", "2"),
            ("kuery", "name:SOC*"),
            ("sortField", "updated_at"),
            ("sortOrder", "asc"),
        ],
    );

    mock.json(json!({"item": policy("p1")}));
    let fetched = client
        .fleet()
        .get_agent_policy("p1")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(fetched.extra["is_managed"], false);
    mock.take()
        .route("GET", "/s/soc/api/fleet/agent_policies/p1", &[]);

    let definition = NewAgentPolicy::new("SOC Linux", "default")
        .description("Linux servers")
        .monitoring_enabled(["logs", "metrics"])
        .data_output_id("default-output")
        .inactivity_timeout(1_209_600);
    let expected = json!({"name": "SOC Linux", "namespace": "default", "description": "Linux servers",
        "monitoring_enabled": ["logs", "metrics"], "data_output_id": "default-output", "inactivity_timeout": 1_209_600});
    mock.json(json!({"item": policy("p1")}));
    client
        .fleet()
        .create_agent_policy(&definition)
        .sys_monitoring(false)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "POST",
            "/s/soc/api/fleet/agent_policies",
            &[("sys_monitoring", "false")],
        )
        .body(expected.clone());
    mock.json(json!({"item": policy("p2")}));
    client
        .fleet()
        .create_agent_policy(&NewAgentPolicy::new("Minimal", "fixture"))
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agent_policies", &[])
        .body(json!({"name": "Minimal", "namespace": "fixture"}));

    mock.json(json!({"item": policy("p1")}));
    let updated = client
        .fleet()
        .update_agent_policy("p1", &definition)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(updated.revision, 3);
    mock.take()
        .route("PUT", "/s/soc/api/fleet/agent_policies/p1", &[])
        .body(expected);

    mock.json(json!({"item": policy("copy")}));
    client
        .fleet()
        .copy_agent_policy("p1", "Copy")
        .description("Staging")
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agent_policies/p1/copy", &[])
        .body(json!({"name": "Copy", "description": "Staging"}));

    mock.reply_with(
        200,
        vec![("content-type", "application/x-yaml".into())],
        "id: p1\noutputs: {}\n",
    );
    let yaml = client
        .fleet()
        .download_agent_policy("p1")
        .standalone(true)
        .kubernetes(false)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(yaml.starts_with("id: p1"));
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/agent_policies/p1/download",
        &[("standalone", "true"), ("kubernetes", "false")],
    );

    mock.json(json!({"id": "p1", "name": "SOC Linux"}));
    client
        .fleet()
        .delete_agent_policy("p1")
        .force(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/agent_policies/delete", &[])
        .body(json!({"agentPolicyId": "p1", "force": true}));
}

#[tokio::test]
async fn package_policies_use_the_simplified_format() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"items": [package_policy("pp")], "page": 1, "perPage": 10, "total": 1}));
    let page = client
        .fleet()
        .find_package_policies()
        .page(1)
        .per_page(10)
        .kuery("ingest-package-policies.package.name:system")
        .sort_field("name")
        .sort_order(SortOrder::Asc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.items[0].package.version, "2.5.0");
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/package_policies",
        &[
            ("page", "1"),
            ("perPage", "10"),
            ("kuery", "ingest-package-policies.package.name:system"),
            ("sortField", "name"),
            ("sortOrder", "asc"),
        ],
    );

    mock.json(json!({"item": package_policy("pp")}));
    assert_eq!(
        client
            .fleet()
            .get_package_policy("pp")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .item
            .policy_ids,
        ["p1"]
    );
    mock.take()
        .route("GET", "/s/soc/api/fleet/package_policies/pp", &[]);

    let definition =
        NewPackagePolicy::new("system-1", "default", PackageRef::new("system", "2.5.0"))
            .policy_id("p1")
            .policy_id("p2")
            .description("Syslog")
            .input(
                "system-logfile",
                PolicyInput::new()
                    .enabled(true)
                    .var("preserve_original_event", json!(false))
                    .stream(
                        "system.syslog",
                        PolicyStream::new()
                            .enabled(true)
                            .var("paths", json!(["/var/log/syslog"])),
                    )
                    .stream("system.auth", PolicyStream::new().enabled(false)),
            )
            .input("system-system/metrics", PolicyInput::new().enabled(false));
    let expected = json!({
        "name": "system-1", "namespace": "default", "policy_ids": ["p1", "p2"],
        "package": {"name": "system", "version": "2.5.0"}, "description": "Syslog",
        "inputs": {
            "system-logfile": {"enabled": true, "vars": {"preserve_original_event": false}, "streams": {
                "system.auth": {"enabled": false},
                "system.syslog": {"enabled": true, "vars": {"paths": ["/var/log/syslog"]}}
            }},
            "system-system/metrics": {"enabled": false}
        }
    });
    mock.json(json!({"item": package_policy("pp")}));
    client
        .fleet()
        .create_package_policy(&definition)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "POST",
            "/s/soc/api/fleet/package_policies",
            &[("format", "simplified")],
        )
        .body(expected.clone());

    mock.json(json!({"item": package_policy("pp")}));
    client
        .fleet()
        .update_package_policy(definition.replacing("pp"))
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "PUT",
            "/s/soc/api/fleet/package_policies/pp",
            &[("format", "simplified")],
        )
        .body(expected);

    let full_inputs = json!([{"type": "logfile", "policy_template": "system", "enabled": true,
        "streams": [{"id": "logfile-system.syslog", "enabled": true,
                     "data_stream": {"type": "logs", "dataset": "system.syslog"},
                     "vars": {"paths": {"type": "text", "value": ["/var/log/syslog"]}}}]}]);
    let mut stored = package_policy("pp");
    stored["inputs"] = full_inputs.clone();
    stored["inputs"][0]["compiled_input"] = json!({"generated": "response only"});
    stored["vars"] = json!({"api_key": {"type": "password", "value": "vars-secret"}});
    stored["version"] = json!("WzMsMV0=");
    stored["package"]["title"] = json!("System");
    stored["created_at"] = json!("2026-09-30T00:00:00Z");
    mock.json(json!({"item": stored}));
    let retrieved = client
        .fleet()
        .get_package_policy("pp")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    mock.take()
        .route("GET", "/s/soc/api/fleet/package_policies/pp", &[]);
    assert!(!format!("{retrieved:?}").contains("vars-secret"));
    let edit = retrieved
        .edit()
        .name("renamed-system")
        .description("Edited")
        .policy_ids(["p1", "p3"]);
    assert!(
        serde_json::to_value(&edit).unwrap()["inputs"][0]
            .get("compiled_input")
            .is_none()
    );
    let edit = edit.inputs(retrieved.inputs.clone());
    assert!(!format!("{edit:?}").contains("vars-secret"));
    mock.json(json!({"item": package_policy("pp")}));
    client
        .fleet()
        .update_package_policy(&edit)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/fleet/package_policies/pp", &[])
        .body(json!({
            "name": "renamed-system", "namespace": "default", "description": "Edited", "enabled": true,
            "package": {"name": "system", "version": "2.5.0", "title": "System"},
            "policy_ids": ["p1", "p3"], "inputs": full_inputs,
            "vars": {"api_key": {"type": "password", "value": "vars-secret"}},
            "version": "WzMsMV0="
        }));
    assert!(retrieved.inputs[0].get("compiled_input").is_some());
    let debug = format!("{definition:?}");
    assert!(
        debug.contains("paths") && !debug.contains("/var/log/syslog"),
        "{debug}"
    );

    mock.json(json!({"id": "pp"}));
    client
        .fleet()
        .delete_package_policy("pp")
        .force(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "DELETE",
            "/s/soc/api/fleet/package_policies/pp",
            &[("force", "true")],
        )
        .no_body();
}

#[tokio::test]
async fn package_policy_edits_require_full_inputs_and_a_version() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let mut simplified = package_policy("pp");
    simplified["inputs"] = json!({"system-logfile": {
        "enabled": true,
        "vars": {"preserve_original_event": false},
        "streams": {"system.syslog": {"vars": {"paths": ["/var/log/syslog"]}}}
    }});
    simplified["vars"] = json!({"api_key": "vars-secret"});
    simplified["version"] = json!("WzMsMV0=");
    let definition =
        NewPackagePolicy::new("system-1", "default", PackageRef::new("system", "2.5.0"));
    for create in [true, false] {
        mock.json(json!({"item": simplified}));
        let response = if create {
            client
                .fleet()
                .create_package_policy(&definition)
                .send()
                .await
                .unwrap()
        } else {
            client
                .fleet()
                .update_package_policy(definition.replacing("pp"))
                .send()
                .await
                .unwrap()
        };
        let policy = response.json().await.unwrap().item;
        mock.take();
        let error = client
            .fleet()
            .update_package_policy(&policy.edit().name("renamed"))
            .send()
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidRequest(message) if message.contains("get_package_policy")),
            "{error:?}"
        );
        let edit = policy.edit().inputs(json!([]));
        let error = client
            .fleet()
            .update_package_policy(&edit)
            .send()
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidRequest(message) if message.contains("get_package_policy")),
            "{error:?}"
        );
    }
    for version in [Value::Null, json!("")] {
        let mut stored = package_policy("pp");
        stored["version"] = version;
        let policy: PackagePolicy = serde_json::from_value(stored).unwrap();
        let error = client
            .fleet()
            .update_package_policy(&policy.edit())
            .send()
            .await
            .unwrap_err();
        assert!(
            matches!(&error, Error::InvalidRequest(message) if message.contains("version")),
            "{error:?}"
        );
    }
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn packages_and_outputs() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"items": [{"name": "system", "version": "2.5.0", "title": "System", "status": "installed", "categories": ["os_system"]}]}));
    let packages = client
        .fleet()
        .list_packages()
        .category("security")
        .prerelease(false)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(packages.items[0].extra["categories"][0], "os_system");
    mock.take().route(
        "GET",
        "/s/soc/api/fleet/epm/packages",
        &[("category", "security"), ("prerelease", "false")],
    );

    mock.json(json!({"item": {"name": "system", "version": "2.5.0", "status": "not_installed"}, "metadata": {}}));
    let package = client
        .fleet()
        .get_package("system", "2.5.0")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
        .item;
    assert_eq!(package.status.as_deref(), Some("not_installed"));
    mock.take()
        .route("GET", "/s/soc/api/fleet/epm/packages/system/2.5.0", &[]);

    mock.json(json!({"items": [], "_meta": {"install_source": "registry"}}));
    client
        .fleet()
        .install_package("system", "2.5.0")
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/fleet/epm/packages/system/2.5.0", &[])
        .body(json!({}));
    mock.json(json!({"items": []}));
    client
        .fleet()
        .install_package("system", "2.5.0")
        .force(true)
        .ignore_constraints(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .body(json!({"force": true, "ignore_constraints": true}));

    mock.json(json!({"items": []}));
    client
        .fleet()
        .uninstall_package("system", "2.5.0")
        .force(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "DELETE",
            "/s/soc/api/fleet/epm/packages/system/2.5.0",
            &[("force", "true")],
        )
        .no_body();

    mock.json(json!({"items": [{"id": "default-output", "type": "elasticsearch"}], "total": 1}));
    assert_eq!(
        client
            .fleet()
            .list_outputs()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()["total"],
        1
    );
    mock.take().route("GET", "/s/soc/api/fleet/outputs", &[]);
}
