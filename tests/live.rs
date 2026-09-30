//! Run only against a disposable, dedicated Kibana deployment.
use std::time::Duration;

use kibana_rs::{
    Kibana, Result,
    cases::{CaseComment, CasePatch, CaseStatus, NewCase},
    exceptions::{
        Comment, Entry, ItemSelector, ListSelector, NamespaceType, NewItem, NewList, Operator,
        OsType,
    },
    fleet::{NewAgentPolicy, NewPackagePolicy, PackageRef},
    http::{Certificate, Credentials, TransportBuilder, Url},
    roles::{KibanaPrivilege, RoleDefinition},
    security::{QueryRule, RuleSelector},
    spaces::Space,
};

fn client() -> Kibana {
    let url = std::env::var("KIBANA_URL").expect("KIBANA_URL is required");
    let mut builder = TransportBuilder::new(Url::parse(&url).unwrap())
        .auth(Credentials::Basic(
            std::env::var("KIBANA_USERNAME").unwrap_or("elastic".into()),
            std::env::var("KIBANA_PASSWORD").expect("KIBANA_PASSWORD is required"),
        ))
        .timeout(Duration::from_secs(180));
    if let Ok(path) = std::env::var("KIBANA_CA_CERT") {
        builder =
            builder.root_certificate(Certificate::from_pem(&std::fs::read(path).unwrap()).unwrap());
    }
    Kibana::new(builder.build().unwrap())
}

async fn space(root: &Kibana) -> (String, Kibana) {
    let id = format!("krs-test-{}", uuid::Uuid::new_v4());
    let mut space = Space::new(&id, &id);
    space.description = Some("kibana-rs integration test".into());
    root.spaces().create(&space).send().await.unwrap();
    let scoped = root.space(&id).unwrap();
    (id, scoped)
}

fn status<T>(result: Result<T>) -> u16 {
    match result {
        Ok(_) => panic!("expected an HTTP error"),
        Err(error) => error.status().expect("expected an HTTP error").as_u16(),
    }
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn exception_lists_items_roundtrip_conflicts_and_spaces() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let exceptions = client.exceptions();
        let list_id = format!("scanner-{}", uuid::Uuid::new_v4());
        let list = exceptions
            .create_list(
                &NewList::detection("Known scanners", "Owned exception fixture").list_id(&list_id),
            )
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(
            exceptions
                .get_list(ListSelector::ListId(&list.list_id))
                .send()
                .await?
                .json()
                .await?
                .id,
            list.id
        );
        assert_eq!(
            status(
                root.exceptions()
                    .get_list(ListSelector::Id(&list.id))
                    .send()
                    .await
            ),
            404
        );

        let tagged = exceptions
            .update_list(&list.edit().tags(["network"]))
            .send()
            .await?
            .json()
            .await?;
        let renamed = tagged.edit().name("Approved scanners");
        let updated = exceptions
            .update_list(&renamed)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(updated.name, "Approved scanners");
        assert_eq!(updated.tags, ["network"], "edits keep unchanged fields");
        assert_eq!(updated.description, "Owned exception fixture");
        assert_eq!(
            status(exceptions.update_list(&renamed).send().await),
            409,
            "a stale edit conflicts"
        );

        let item_id = format!("scanner-item-{}", uuid::Uuid::new_v4());
        let entries = vec![Entry::Match {
            field: "host.name".into(),
            operator: Operator::Included,
            value: "scanner-1".into(),
        }];
        let item = exceptions
            .create_item(
                &NewItem::new(&list, "Scanner host", entries.clone())
                    .item_id(&item_id)
                    .description("Known scanner")
                    .tags(["network"])
                    .comments(vec![Comment::new("Approved by SOC")])
                    .os_types(vec![OsType::Linux]),
            )
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(
            exceptions
                .get_item(ItemSelector::ItemId(&item.item_id))
                .send()
                .await?
                .json()
                .await?
                .id,
            item.id
        );
        assert_eq!(
            status(
                root.exceptions()
                    .get_item(ItemSelector::Id(&item.id))
                    .send()
                    .await
            ),
            404
        );
        let renamed = item.edit().name("Renamed scanner");
        let updated = exceptions
            .update_item(&renamed)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(updated.name, "Renamed scanner");
        assert_eq!(
            updated.description, "Known scanner",
            "edits keep unchanged fields"
        );
        assert_eq!(updated.tags, ["network"]);
        assert_eq!(updated.os_types, [OsType::Linux]);
        assert_eq!(updated.entries, item.entries);
        assert_eq!(
            updated.comments.len(),
            1,
            "existing comments are not repeated"
        );
        assert_eq!(
            status(exceptions.update_item(&renamed).send().await),
            409,
            "a stale edit conflicts"
        );
        let commented = exceptions
            .update_item(&updated.edit().add_comment("Re-reviewed"))
            .send()
            .await?
            .json()
            .await?;
        let comments: Vec<_> = commented
            .comments
            .iter()
            .map(|c| c.comment.as_str())
            .collect();
        assert_eq!(comments, ["Approved by SOC", "Re-reviewed"]);

        let second = exceptions
            .create_item(&NewItem::new(
                &list,
                "Other scanner",
                vec![Entry::MatchAny {
                    field: "host.name".into(),
                    operator: Operator::Included,
                    value: vec!["scanner-2".into(), "scanner-3".into()],
                }],
            ))
            .send()
            .await?
            .json()
            .await?;
        let first_page = exceptions
            .find_items(&list.list_id)
            .per_page(1)
            .sort_field("name")
            .send()
            .await?
            .json()
            .await?;
        let second_page = exceptions
            .find_items(&list.list_id)
            .page(2)
            .per_page(1)
            .sort_field("name")
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(first_page.total, 2);
        assert_ne!(first_page.data[0].id, second_page.data[0].id);
        assert_eq!(
            exceptions
                .summary(ListSelector::Id(&list.id))
                .send()
                .await?
                .json()
                .await?["total"],
            2
        );

        let duplicate = exceptions
            .duplicate_list(&list.list_id, NamespaceType::Single, true)
            .send()
            .await?
            .json()
            .await?;
        assert_ne!(duplicate.list_id, list.list_id);
        assert_eq!(
            exceptions
                .find_items(&duplicate.list_id)
                .send()
                .await?
                .json()
                .await?
                .total,
            2
        );
        assert_eq!(
            exceptions
                .find_lists()
                .per_page(1)
                .send()
                .await?
                .json()
                .await?
                .total,
            2
        );
        exceptions
            .delete_list(ListSelector::Id(&duplicate.id))
            .send()
            .await?;

        let export = exceptions
            .export_list(&list.reference(), true)
            .send()
            .await?
            .bytes()
            .await?;
        let conflict = exceptions
            .import_lists(export.to_vec())
            .overwrite(false)
            .send()
            .await?
            .json()
            .await?;
        assert!(!conflict.success);
        assert!(!conflict.errors.is_empty());
        let overwrite = exceptions
            .import_lists(export.to_vec())
            .overwrite(true)
            .send()
            .await?
            .json()
            .await?;
        assert!(overwrite.success, "{overwrite:?}");
        let list = exceptions
            .get_list(ListSelector::ListId(&list.list_id))
            .send()
            .await?
            .json()
            .await?;
        let item = exceptions
            .get_item(ItemSelector::ItemId(&item.item_id))
            .send()
            .await?
            .json()
            .await?;

        let rule = QueryRule::new(
            "Rule with shared exceptions",
            "Exception association",
            "host.name: scanner-1",
        )
        .exceptions_list(vec![list.reference()]);
        let rule = client
            .security()
            .create_rule(&rule)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(rule.extra["exceptions_list"][0]["list_id"], list.list_id);
        let detached = client
            .security()
            .patch_rule(RuleSelector::Id(&rule.id))
            .exceptions_list(vec![])
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(detached.extra["exceptions_list"], serde_json::json!([]));
        client
            .security()
            .delete_rule(RuleSelector::Id(&rule.id))
            .send()
            .await?;

        exceptions
            .delete_item(ItemSelector::ItemId(&second.item_id))
            .send()
            .await?;
        exceptions
            .delete_item(ItemSelector::Id(&item.id))
            .send()
            .await?;
        exceptions
            .delete_list(ListSelector::Id(&list.id))
            .send()
            .await?;
        let imported = exceptions
            .import_lists(export.to_vec())
            .send()
            .await?
            .json()
            .await?;
        assert!(imported.success, "{imported:?}");
        assert_eq!(
            exceptions
                .find_items(&list.list_id)
                .send()
                .await?
                .json()
                .await?
                .total,
            2
        );
        exceptions
            .delete_list(ListSelector::ListId(&list.list_id))
            .send()
            .await?;

        let shared = exceptions
            .create_list(
                &NewList::detection("Cross-space exception fixture", "Shared namespace")
                    .namespace_type(NamespaceType::Agnostic),
            )
            .send()
            .await?
            .json()
            .await?;
        let visible = root
            .exceptions()
            .get_list(ListSelector::Id(&shared.id))
            .namespace_type(NamespaceType::Agnostic)
            .send()
            .await;
        let cleanup = exceptions
            .delete_list(ListSelector::Id(&shared.id))
            .namespace_type(NamespaceType::Agnostic)
            .send()
            .await;
        assert_eq!(visible?.json().await?.id, shared.id);
        cleanup?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn fleet_enrollment_key_lifecycle_and_pagination() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let fleet = client.fleet();
        fleet.setup().send().await?;
        let policy = fleet
            .create_agent_policy(&NewAgentPolicy::new("Enrollment fixture", "fixture"))
            .send()
            .await?
            .json()
            .await?
            .item;
        let mut keys = vec![];
        for index in 0..2 {
            let key = fleet
                .create_enrollment_key(&policy.id)
                .name(&format!("krs-test-key-{index}"))
                .expiration("24h")
                .send()
                .await?
                .json()
                .await?
                .item;
            assert!(key.active);
            assert!(!key.api_key.is_empty());
            assert!(key.expire_at.is_some());
            assert!(!format!("{key:?}").contains(&key.api_key));
            let fetched = fleet
                .get_enrollment_key(&key.id)
                .send()
                .await?
                .json()
                .await?
                .item;
            assert_eq!(fetched.policy_id.as_deref(), Some(policy.id.as_str()));
            keys.push(key);
        }
        let kuery = format!("policy_id:\"{}\" AND name:krs-test-key-*", policy.id);
        let first = fleet
            .find_enrollment_keys()
            .per_page(1)
            .kuery(&kuery)
            .send()
            .await?
            .json()
            .await?;
        let second = fleet
            .find_enrollment_keys()
            .page(2)
            .per_page(1)
            .kuery(&kuery)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(first.total, 2);
        assert_ne!(first.items[0].id, second.items[0].id);
        for key in keys {
            fleet.revoke_enrollment_key(&key.id).send().await?;
            assert!(
                !fleet
                    .get_enrollment_key(&key.id)
                    .send()
                    .await?
                    .json()
                    .await?
                    .item
                    .active
            );
        }
        fleet.delete_agent_policy(&policy.id).send().await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn detection_rules_crud_export_import_and_space_isolation() {
    use serde_json::{Value, json};

    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let security = client.security();
        security.create_alerts_index().send().await?;
        security.privileges().send().await?;
        let request = QueryRule::new(
            "Test failed login",
            "Integration test",
            "event.category: authentication and event.outcome: failure",
        )
        .rule_id(format!("krs-test-{}", uuid::Uuid::new_v4()));
        let rule = security.create_rule(&request).send().await?.json().await?;
        assert!(!rule.enabled);
        assert_eq!(
            security
                .get_rule(RuleSelector::RuleId(&rule.rule_id))
                .send()
                .await?
                .json()
                .await?
                .id,
            rule.id
        );
        assert_eq!(
            security
                .find_rules()
                .per_page(1)
                .send()
                .await?
                .json()
                .await?
                .total,
            1
        );
        assert_eq!(
            status(
                root.security()
                    .get_rule(RuleSelector::Id(&rule.id))
                    .send()
                    .await
            ),
            404
        );

        let updated = security
            .patch_rule(RuleSelector::Id(&rule.id))
            .name("Updated rule")
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(updated.name, "Updated rule");
        let bytes = security
            .export_rules()
            .rule_ids([&rule.rule_id])
            .send()
            .await?
            .bytes()
            .await?;
        assert!(String::from_utf8_lossy(&bytes).contains(&rule.rule_id));
        let duplicate = security
            .import_rules(bytes.to_vec())
            .overwrite(false)
            .send()
            .await?
            .json()
            .await?;
        assert!(!duplicate.success);
        assert!(!duplicate.errors.is_empty());

        let fresh_id = format!("krs-import-{}", uuid::Uuid::new_v4());
        let mut fresh: Value = String::from_utf8_lossy(&bytes)
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|value| value["rule_id"] == rule.rule_id)
            .unwrap();
        fresh["rule_id"] = json!(fresh_id);
        fresh.as_object_mut().unwrap().remove("id");
        let mut mixed = format!("{fresh}\n").into_bytes();
        mixed.extend_from_slice(&bytes);
        let partial = security
            .import_rules(mixed)
            .overwrite(false)
            .send()
            .await?
            .json()
            .await?;
        assert!(!partial.success, "{partial:?}");
        assert_eq!(partial.success_count, 1, "{partial:?}");
        assert_eq!(partial.errors.len(), 1, "{partial:?}");
        assert_eq!(
            partial.errors[0].rule_id.as_deref(),
            Some(rule.rule_id.as_str())
        );
        assert_eq!(partial.errors[0].error.status_code, 409);
        assert_eq!(
            security
                .get_rule(RuleSelector::RuleId(&fresh_id))
                .send()
                .await?
                .json()
                .await?
                .rule_id,
            fresh_id
        );
        security
            .delete_rule(RuleSelector::RuleId(&fresh_id))
            .send()
            .await?;

        security
            .delete_rule(RuleSelector::Id(&rule.id))
            .send()
            .await?;
        let imported = security
            .import_rules(bytes.to_vec())
            .send()
            .await?
            .json()
            .await?;
        assert!(imported.success, "{imported:?}");
        assert_eq!(imported.success_count, 1);
        security
            .delete_rule(RuleSelector::RuleId(&rule.rule_id))
            .send()
            .await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn security_cases_comments_and_version_conflicts() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let cases = client.cases();
        let case = cases
            .create(&NewCase::security(
                "Authentication investigation",
                "Synthetic integration test",
            ))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(case.owner, "securitySolution");
        assert_eq!(cases.find().send().await?.json().await?.total, 1);
        let change = || {
            CasePatch::new(&case.id, &case.version)
                .status(CaseStatus::InProgress)
                .field("category", "Authentication")
                .unwrap()
        };
        let changed = cases.update([change()]).send().await?.json().await?;
        assert_eq!(changed[0].status, "in-progress");
        assert_eq!(changed[0].extra["category"], "Authentication");
        assert_eq!(status(cases.update([change()]).send().await), 409);
        let commented = cases
            .add_comment(
                &case.id,
                &CaseComment::user(&case.owner, "Validated with a real Kibana API call."),
            )
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(commented.total_comments, 1);
        let comments = cases
            .find_comments(&case.id)
            .per_page(10)
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(comments.total, 1);
        assert_eq!(
            cases.get(&case.id).send().await?.json().await?.title,
            case.title
        );
        cases.delete([&case.id]).send().await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment and Elastic package registry access"]
async fn fleet_policy_and_integration_lifecycle() {
    use serde_json::{Value, json};

    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let fleet = client.fleet();
        let setup = fleet.setup().send().await?.json().await?;
        assert_eq!(setup["isInitialized"], true);
        let request = NewAgentPolicy::new("Test SOC endpoints", "default")
            .description("Retain policy settings when renamed")
            .inactivity_timeout(3600)
            .monitoring_enabled(["logs"]);
        let policy = fleet
            .create_agent_policy(&request)
            .send()
            .await?
            .json()
            .await?
            .item;
        let fetched = fleet
            .get_agent_policy(&policy.id)
            .send()
            .await?
            .json()
            .await?
            .item;
        assert_eq!(fetched.name, "Test SOC endpoints");
        let renamed = fetched.edit()?.name("Updated SOC endpoints");
        let updated = fleet
            .edit_agent_policy(&renamed)
            .send()
            .await?
            .json()
            .await?
            .item;
        assert_eq!(updated.name, "Updated SOC endpoints");
        assert_eq!(updated.description, fetched.description);
        assert_eq!(updated.extra["inactivity_timeout"], 3600);
        assert_eq!(updated.extra["monitoring_enabled"], json!(["logs"]));
        let outputs = fleet.list_outputs().send().await?.json().await?;
        let default_output = outputs["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|output| output["is_default"] == true)
            .unwrap()["id"]
            .as_str()
            .unwrap();
        let select_output = updated.edit()?.data_output_id(default_output);
        let rejected = fleet
            .edit_agent_policy(&select_output)
            .send()
            .await
            .unwrap_err();
        assert_eq!(rejected.status().unwrap().as_u16(), 400);
        assert!(
            rejected
                .message()
                .is_some_and(|message| message.contains("platinum"))
        );
        let clear_output = updated.edit()?.clear_data_output_id();
        fleet.edit_agent_policy(&clear_output).send().await?;
        let cleared = fleet
            .get_agent_policy(&policy.id)
            .send()
            .await?
            .json()
            .await?
            .item;
        assert_eq!(cleared.extra.get("data_output_id"), Some(&Value::Null));
        assert_eq!(cleared.description, fetched.description);
        assert_eq!(cleared.extra["inactivity_timeout"], 3600);
        assert_eq!(cleared.extra["monitoring_enabled"], json!(["logs"]));
        assert!(
            fleet
                .find_agent_policies()
                .per_page(1)
                .send()
                .await?
                .json()
                .await?
                .total
                >= 1
        );
        let copy = fleet
            .copy_agent_policy(&policy.id, "SOC policy copy")
            .send()
            .await?
            .json()
            .await?
            .item;
        fleet.delete_agent_policy(&copy.id).send().await?;

        let packages = fleet.list_packages().send().await?.json().await?;
        assert!(packages.items.iter().any(|p| p.name == "system"));
        let version = std::env::var("KIBANA_TEST_SYSTEM_VERSION")
            .expect("KIBANA_TEST_SYSTEM_VERSION must pin the package version");
        let package = fleet
            .get_package("system", &version)
            .send()
            .await?
            .json()
            .await?
            .item;
        fleet
            .install_package(&package.name, &package.version)
            .send()
            .await?;
        assert_eq!(
            fleet
                .get_package(&package.name, &package.version)
                .send()
                .await?
                .json()
                .await?
                .item
                .name,
            "system"
        );
        let integration = |description: &str| {
            NewPackagePolicy::new(
                format!("krs-system-{space_id}"),
                "default",
                PackageRef::new(&package.name, &package.version),
            )
            .policy_id(&policy.id)
            .description(description)
        };
        let attached = fleet
            .create_package_policy(&integration("Integration test"))
            .send()
            .await?
            .json()
            .await?
            .item;
        assert_eq!(attached.package.name, "system");
        let populated = fleet.find_agent_policies().send().await?.json().await?;
        let listed = populated.items.iter().find(|p| p.id == policy.id).unwrap();
        assert_eq!(listed.package_policies.len(), 1);
        assert_eq!(listed.agents, Some(0));
        let replaced = integration("Updated integration test");
        fleet
            .update_package_policy(replaced.replacing(&attached.id))
            .send()
            .await?;
        let current = fleet
            .get_package_policy(&attached.id)
            .send()
            .await?
            .json()
            .await?
            .item;
        let renamed = format!("krs-system-edited-{space_id}");
        let edited = fleet
            .update_package_policy(
                &current
                    .edit()
                    .name(&renamed)
                    .description("Edited integration test"),
            )
            .send()
            .await?
            .json()
            .await?
            .item;
        assert_eq!(
            edited.description.as_deref(),
            Some("Edited integration test")
        );
        assert_eq!(edited.name, renamed);
        assert_eq!(
            edited.inputs.as_array().map(Vec::len),
            current.inputs.as_array().map(Vec::len),
            "a full-format edit keeps the inputs"
        );
        assert_eq!(
            fleet
                .get_package_policy(&attached.id)
                .send()
                .await?
                .json()
                .await?
                .item
                .id,
            attached.id
        );
        assert!(
            fleet
                .find_package_policies()
                .send()
                .await?
                .json()
                .await?
                .total
                >= 1
        );
        let download = fleet
            .download_agent_policy(&policy.id)
            .send()
            .await?
            .text()
            .await?;
        assert!(download.contains(&policy.id));
        assert_eq!(fleet.find_agents().send().await?.json().await?.total, 0);
        fleet.agent_status().send().await?;
        fleet.list_outputs().send().await?;
        fleet.delete_package_policy(&attached.id).send().await?;
        fleet.delete_agent_policy(&policy.id).send().await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment with role administration privileges"]
async fn roles_are_global_and_roundtrip_space_privileges() {
    let root = client();
    let (space_id, scoped) = space(&root).await;
    let name = format!("krs-test-{}", uuid::Uuid::new_v4());
    let result: Result<()> = async {
        let mut updated_space = root.spaces().get(&space_id).send().await?.json().await?;
        updated_space.name = "Updated integration-test space".into();
        scoped
            .spaces()
            .update(&space_id, &updated_space)
            .send()
            .await?;
        assert!(
            scoped
                .spaces()
                .list()
                .send()
                .await?
                .json()
                .await?
                .iter()
                .any(|s| s.id == space_id && s.name == updated_space.name)
        );
        let mut definition = RoleDefinition::new(
            serde_json::json!({"cluster": [], "indices": []}),
            vec![KibanaPrivilege::new(
                vec![space_id.clone()],
                vec!["read".into()],
            )],
        );
        scoped.roles().put(&name, &definition).send().await?;
        let role = scoped.roles().get(&name).send().await?.json().await?;
        assert_eq!(role.name, name);
        assert_eq!(role.definition.kibana[0].spaces, vec![space_id.clone()]);
        definition.kibana[0].base = vec!["all".into()];
        scoped.roles().put(&name, &definition).send().await?;
        assert_eq!(
            root.roles()
                .get(&name)
                .send()
                .await?
                .json()
                .await?
                .definition
                .kibana[0]
                .base,
            vec!["all"]
        );
        assert!(
            root.roles()
                .list()
                .send()
                .await?
                .json()
                .await?
                .iter()
                .any(|r| r.name == name)
        );
        Ok(())
    }
    .await;
    let role_cleanup = root.roles().delete(&name).send().await;
    let space_cleanup = root.spaces().delete(&space_id).send().await;
    result.unwrap();
    role_cleanup.unwrap();
    space_cleanup.unwrap();
}
