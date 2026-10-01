mod common;

use std::collections::BTreeMap;

use common::Mock;
use security_client_rs::{
    cases::{CasePatch, CaseStatus},
    exceptions::{ExceptionItem, NamespaceType},
    fleet::{ActionStatus, AgentPolicy, PackagePolicy},
    roles::{KibanaPrivilege, RoleDefinition},
    security::{QueryRule, RuleSelector},
    spaces::Space,
};
use serde_json::{Value, json};

fn fixtures() -> BTreeMap<String, Value> {
    serde_json::from_str(include_str!("fixtures/contracts.json")).unwrap()
}

#[tokio::test]
async fn retained_requests_match_typed_builders() {
    let fixtures = fixtures();
    let mock = Mock::start().await;
    let client = mock.soc();
    for (name, fixture) in &fixtures {
        let Some(body) = fixture.get("request") else {
            continue;
        };
        let (request, method, path) = match fixture["wrapper"].as_str().unwrap() {
            "security.create_rule" => (
                client
                    .security()
                    .create_rule(
                        &QueryRule::new(
                            "Failed logins",
                            "Repeated authentication failures",
                            "event.outcome: failure",
                        )
                        .rule_id("fixture-rule"),
                    )
                    .into_request(),
                "POST",
                "/s/soc/api/detection_engine/rules",
            ),
            "security.patch_rule" => (
                client
                    .security()
                    .patch_rule(RuleSelector::Id("11111111-1111-4111-8111-111111111111"))
                    .enabled(true)
                    .into_request(),
                "PATCH",
                "/s/soc/api/detection_engine/rules",
            ),
            "cases.update" => {
                let patch = CasePatch::new("fixture-case", "WzAsMV0=");
                let patch = if name == "case-extended-fields" {
                    patch
                        .field("extended_fields", json!({"priority_as_keyword": "high"}))
                        .unwrap()
                } else {
                    patch
                        .status(CaseStatus::Closed)
                        .description("Resolved")
                        .tags(Vec::<String>::new())
                };
                (
                    client.cases().update([patch]).into_request(),
                    "PATCH",
                    "/s/soc/api/cases",
                )
            }
            "exceptions.update_item" => {
                let item: ExceptionItem =
                    serde_json::from_value(fixture["response"]["body"].clone()).unwrap();
                (
                    client
                        .exceptions()
                        .update_item(&item.edit().name("Updated scanner"))
                        .into_request(),
                    "PUT",
                    "/s/soc/api/exception_lists/items",
                )
            }
            "fleet.update_agent_policy" => {
                let policy: AgentPolicy =
                    serde_json::from_value(fixture["response"]["body"]["item"].clone()).unwrap();
                (
                    client
                        .fleet()
                        .edit_agent_policy(&policy.edit().unwrap().clear_data_output_id())
                        .into_request(),
                    "PUT",
                    "/s/soc/api/fleet/agent_policies/fixture-policy",
                )
            }
            "fleet.update_package_policy" => {
                let policy: PackagePolicy = serde_json::from_value(
                    fixtures["package-policy-full"]["response"]["body"]["item"].clone(),
                )
                .unwrap();
                (
                    client
                        .fleet()
                        .update_package_policy(&policy.edit())
                        .into_request(),
                    "PUT",
                    "/s/soc/api/fleet/package_policies/fixture-package-policy",
                )
            }
            "spaces.update" => {
                let mut space = Space::new("soc", "SOC");
                space.description = Some("Security operations".into());
                space.extra.insert("color".into(), json!("#aabbcc"));
                (
                    client.spaces().update("soc", &space).into_request(),
                    "PUT",
                    "/api/spaces/space/soc",
                )
            }
            "roles.put" => (
                client
                    .roles()
                    .put(
                        "fixture-role",
                        &RoleDefinition::new(
                            json!({"cluster": [], "indices": [], "run_as": []}),
                            vec![KibanaPrivilege::new(
                                vec!["soc".into()],
                                vec!["read".into()],
                            )],
                        ),
                    )
                    .into_request(),
                "PUT",
                "/api/security/role/fixture-role",
            ),
            wrapper => panic!("request fixture {name} has no typed builder test: {wrapper}"),
        };
        mock.json(json!({}));
        request.send().await.unwrap();
        let recorded = mock.take();
        recorded.route(method, path, &[]);
        assert_eq!(recorded.json(), *body, "request fixture {name}");
    }
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn retained_responses_decode_through_named_builders() {
    let fixtures = fixtures();
    let mock = Mock::start().await;
    let client = mock.soc();
    for (name, fixture) in &fixtures {
        let Some(response) = fixture.get("response") else {
            continue;
        };
        assert_eq!(response["status"], 200);
        mock.json(response["body"].clone());
        match fixture["wrapper"].as_str().unwrap() {
            "security.get_rule" => {
                let rule = client
                    .security()
                    .get_rule(RuleSelector::RuleId("fixture-rule"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(rule.rule_id, "fixture-rule");
                assert_eq!(rule.rule_type, "query");
                assert_eq!(rule.extra["version"], 1);
                let execution = rule.execution_summary.unwrap().last_execution;
                assert_eq!(execution.status, "succeeded");
                assert_eq!(execution.extra["metrics"]["total_search_duration_ms"], 3);
            }
            "security.import_rules" => {
                let result = client
                    .security()
                    .import_rules(b"{}\n".to_vec())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert!(result.success);
                assert_eq!(result.success_count, 1);
                assert_eq!(result.exceptions_success, Some(false));
                assert_eq!(result.exceptions_errors[0].error.status_code, 409);
                assert_eq!(result.action_connectors_success, Some(false));
                assert_eq!(result.action_connectors_errors[0].error.status_code, 400);
            }
            "cases.update" => {
                let cases = client
                    .cases()
                    .update([CasePatch::new("fixture-case", "WzAsMV0=")])
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(cases.len(), 1);
                assert_eq!(cases[0].version, "WzEsMV0=");
                assert_eq!(cases[0].status, "closed");
                assert_eq!(cases[0].extra["closed_by"]["email"], Value::Null);
            }
            "exceptions.update_item" => {
                let stored: ExceptionItem =
                    serde_json::from_value(response["body"].clone()).unwrap();
                let item = client
                    .exceptions()
                    .update_item(&stored.edit())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                assert_eq!(item.namespace_type, NamespaceType::Single);
                assert_eq!(item.revision.as_deref(), Some("WzIsMV0="));
                assert_eq!(item.entries[0]["type"], "match");
                assert_eq!(item.extra["created_by"], "fixture-user");
            }
            "fleet.update_agent_policy" => {
                let stored: AgentPolicy =
                    serde_json::from_value(response["body"]["item"].clone()).unwrap();
                let policy = client
                    .fleet()
                    .edit_agent_policy(&stored.edit().unwrap())
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap()
                    .item;
                assert_eq!(policy.revision, 3);
                assert_eq!(policy.extra["inactivity_timeout"], 3600);
                assert_eq!(policy.extra["data_output_id"], Value::Null);
                assert!(policy.edit().is_ok());
            }
            "fleet.get_package_policy" => {
                let policy = client
                    .fleet()
                    .get_package_policy("fixture-package-policy")
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap()
                    .item;
                assert_eq!(policy.version.as_deref(), Some("WzIsMV0="));
                assert_eq!(policy.package.name, "system");
                if name == "package-policy-full" {
                    assert!(policy.inputs.is_array());
                    assert_eq!(policy.inputs[0]["compiled_input"]["type"], "logfile");
                } else {
                    assert!(policy.inputs.is_object());
                    assert_eq!(policy.inputs["logfile"]["enabled"], true);
                }
            }
            "fleet.get_agent" => {
                let agent = client
                    .fleet()
                    .get_agent("fixture-agent")
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap()
                    .item;
                assert_eq!(agent.policy_revision, None);
                assert_eq!(agent.tags, Some(vec!["soc".into()]));
                assert_eq!(agent.last_checkin.as_deref(), Some("2026-09-30T12:01:00Z"));
                assert_eq!(agent.extra["effective_config"], Value::Null);
            }
            "fleet.agent_action_status" => {
                let actions = client
                    .fleet()
                    .agent_action_status()
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap()
                    .items;
                assert_eq!(actions.len(), 1);
                assert_eq!(actions[0].status, ActionStatus::Complete);
                assert!(actions[0].is_finished());
                assert_eq!(actions[0].nb_agents_failed, 1);
            }
            wrapper => panic!("response fixture {name} has no typed builder test: {wrapper}"),
        }
        mock.take();
    }
    assert_eq!(mock.request_count(), 0);
}
