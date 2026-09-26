//! Run only against a disposable, dedicated Kibana deployment.
use kibana_rs::{
    Auth, Client, PageOptions, Result,
    cases::{CasePatch, CaseStatus, FindCases, NewCase},
    fleet::{AgentPolicyRequest, PackagePolicyRequest, PackageRef},
    security::{FindRules, QueryRule, RulePatch, RuleSelector},
    spaces::Space,
};
use std::{collections::BTreeMap, time::Duration};

fn client() -> Client {
    let mut builder = Client::builder(std::env::var("KIBANA_URL").expect("KIBANA_URL is required"))
        .auth(Auth::Basic {
            username: std::env::var("KIBANA_USERNAME").unwrap_or("elastic".into()),
            password: std::env::var("KIBANA_PASSWORD").expect("KIBANA_PASSWORD is required"),
        })
        .timeout(Duration::from_secs(180));
    if let Ok(path) = std::env::var("KIBANA_CA_CERT") {
        builder = builder.root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(path).unwrap()).unwrap(),
        );
    }
    builder.build().unwrap()
}

async fn space(root: &Client) -> (String, Client) {
    let id = format!("krs-test-{}", uuid::Uuid::new_v4());
    root.spaces()
        .create(&Space {
            id: id.clone(),
            name: id.clone(),
            description: "kibana-rs integration test".into(),
            disabled_features: vec![],
        })
        .await
        .unwrap();
    let scoped = root.space(&id).unwrap();
    (id, scoped)
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn detection_rules_crud_export_import_and_space_isolation() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        client.security().initialize().await?;
        client.security().privileges().await?;
        let mut request = QueryRule::new(
            "Test failed login",
            "Integration test",
            "event.category: authentication and event.outcome: failure",
        );
        request.rule_id = Some(format!("krs-test-{}", uuid::Uuid::new_v4()));
        let rule = client.security().create_rule(&request).await?;
        assert!(!rule.enabled);
        assert_eq!(
            client
                .security()
                .rule(RuleSelector::RuleId(&rule.rule_id))
                .await?
                .id,
            rule.id
        );
        assert_eq!(
            client
                .security()
                .rules(&FindRules {
                    per_page: 1,
                    ..Default::default()
                })
                .await?
                .total,
            1
        );
        let missing = root
            .security()
            .rule(RuleSelector::Id(&rule.id))
            .await
            .unwrap_err();
        assert_eq!(missing.status().unwrap().as_u16(), 404);

        let updated = client
            .security()
            .update_rule(
                RuleSelector::Id(&rule.id),
                &RulePatch {
                    name: Some("Updated rule".into()),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(updated.name, "Updated rule");
        let bytes = client
            .security()
            .export_rules(&[&rule.rule_id])
            .await?
            .bytes()
            .await?;
        assert!(String::from_utf8_lossy(&bytes).contains(&rule.rule_id));
        let duplicate = client
            .security()
            .import_rules(bytes.to_vec(), false)
            .await?;
        assert!(!duplicate.success);
        assert!(!duplicate.errors.is_empty());
        client
            .security()
            .delete_rule(RuleSelector::Id(&rule.id))
            .await?;
        let imported = client
            .security()
            .import_rules(bytes.to_vec(), false)
            .await?;
        assert!(imported.success, "{imported:?}");
        assert_eq!(imported.success_count, 1);
        client
            .security()
            .delete_rule(RuleSelector::RuleId(&rule.rule_id))
            .await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment"]
async fn security_cases_comments_and_version_conflicts() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let case = client
            .cases()
            .create(&NewCase::security(
                "Authentication investigation",
                "Synthetic integration test",
            ))
            .await?;
        assert_eq!(case.owner, "securitySolution");
        assert_eq!(client.cases().find(&FindCases::default()).await?.total, 1);
        let changes = [CasePatch {
            id: &case.id,
            version: &case.version,
            status: Some(CaseStatus::InProgress),
            title: None,
            severity: None,
        }];
        let changed = client.cases().update(&changes).await?;
        assert_eq!(changed[0].status, "in-progress");
        let stale = client.cases().update(&changes).await.unwrap_err();
        assert_eq!(stale.status().unwrap().as_u16(), 409);
        client
            .cases()
            .comment(
                &case.id,
                &case.owner,
                "Validated with a real Kibana API call.",
            )
            .await?;
        let comments = client.cases().comments(&case.id, 1, 10).await?;
        assert_eq!(comments["total"], 1);
        assert_eq!(client.cases().get(&case.id).await?.title, case.title);
        client.cases().delete(&[&case.id]).await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment and Elastic package registry access"]
async fn fleet_policy_and_integration_lifecycle() {
    let root = client();
    let (space_id, client) = space(&root).await;
    let result: Result<()> = async {
        let setup = client.fleet().setup().await?;
        assert_eq!(setup["isInitialized"], true);
        let mut request = AgentPolicyRequest::new("Test SOC endpoints", "default");
        request.monitoring_enabled = Some(vec![]);
        let policy = client.fleet().create_agent_policy(&request).await?;
        assert_eq!(
            client.fleet().agent_policy(&policy.id).await?.name,
            request.name
        );
        request.name = "Updated SOC endpoints".into();
        let updated = client
            .fleet()
            .update_agent_policy(&policy.id, &request)
            .await?;
        assert_eq!(updated.name, request.name);
        let policies = client
            .fleet()
            .agent_policies(&PageOptions {
                per_page: 1,
                ..Default::default()
            })
            .await?;
        assert!(policies.total >= 1);
        let copy = client
            .fleet()
            .copy_agent_policy(&policy.id, "SOC policy copy")
            .await?;
        client.fleet().delete_agent_policy(&copy.id).await?;

        let packages = client.fleet().integrations().await?;
        assert!(packages.items.iter().any(|p| p.name == "system"));
        let version = std::env::var("KIBANA_TEST_SYSTEM_VERSION")
            .expect("KIBANA_TEST_SYSTEM_VERSION must pin the package version");
        let package = client.fleet().integration("system", &version).await?;
        client
            .fleet()
            .install_integration(&package.name, &package.version)
            .await?;
        assert_eq!(
            client
                .fleet()
                .integration(&package.name, &package.version)
                .await?
                .name,
            "system"
        );
        let mut integration = PackagePolicyRequest {
            name: format!("krs-system-{}", uuid::Uuid::new_v4()),
            namespace: "default".into(),
            policy_ids: vec![policy.id.clone()],
            package: PackageRef {
                name: package.name.clone(),
                version: package.version.clone(),
            },
            inputs: BTreeMap::new(),
            description: Some("Integration test".into()),
        };
        let attached = client.fleet().create_package_policy(&integration).await?;
        assert_eq!(attached.package.name, "system");
        let populated = client
            .fleet()
            .agent_policies(&PageOptions::default())
            .await?;
        let listed = populated.items.iter().find(|p| p.id == policy.id).unwrap();
        assert_eq!(listed.package_policies.len(), 1);
        assert_eq!(listed.agents, Some(0));
        integration.description = Some("Updated integration test".into());
        client
            .fleet()
            .update_package_policy(&attached.id, &integration)
            .await?;
        assert_eq!(
            client.fleet().package_policy(&attached.id).await?.id,
            attached.id
        );
        assert!(
            client
                .fleet()
                .package_policies(&PageOptions::default())
                .await?
                .total
                >= 1
        );
        let download = client
            .fleet()
            .download_agent_policy(&policy.id)
            .await?
            .text()
            .await?;
        assert!(download.contains(&policy.id));
        assert_eq!(
            client.fleet().agents(&PageOptions::default()).await?.total,
            0
        );
        client.fleet().agent_status().await?;
        client.fleet().outputs().await?;
        client.fleet().delete_package_policy(&attached.id).await?;
        client.fleet().delete_agent_policy(&policy.id).await?;
        Ok(())
    }
    .await;
    let cleanup = root.spaces().delete(&space_id).await;
    result.unwrap();
    cleanup.unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated live Kibana deployment with role administration privileges"]
async fn roles_are_global_and_roundtrip_space_privileges() {
    use kibana_rs::roles::{KibanaPrivilege, RoleDefinition};
    let root = client();
    let (space_id, scoped) = space(&root).await;
    let name = format!("krs-test-{}", uuid::Uuid::new_v4());
    let result: Result<()> = async {
        let mut updated_space = root.spaces().get(&space_id).await?;
        updated_space.name = "Updated integration-test space".into();
        scoped.spaces().update(&updated_space).await?;
        assert!(
            scoped
                .spaces()
                .list()
                .await?
                .iter()
                .any(|s| s.id == space_id && s.name == updated_space.name)
        );
        let mut definition = RoleDefinition {
            elasticsearch: serde_json::json!({"cluster":[],"indices":[]}),
            kibana: vec![KibanaPrivilege {
                spaces: vec![space_id.clone()],
                base: vec!["read".into()],
                feature: BTreeMap::new(),
            }],
        };
        scoped.roles().put(&name, &definition).await?;
        let role = scoped.roles().get(&name).await?;
        assert_eq!(role.name, name);
        assert_eq!(role.definition.kibana[0].spaces, vec![space_id.clone()]);
        definition.kibana[0].base = vec!["all".into()];
        scoped.roles().put(&name, &definition).await?;
        assert_eq!(
            root.roles().get(&name).await?.definition.kibana[0].base,
            vec!["all"]
        );
        assert!(root.roles().list().await?.iter().any(|r| r.name == name));
        Ok(())
    }
    .await;
    let role_cleanup = root.roles().delete(&name).await;
    let space_cleanup = root.spaces().delete(&space_id).await;
    result.unwrap();
    role_cleanup.unwrap();
    space_cleanup.unwrap();
}
