mod common;

use common::Mock;
use kibana_rs::{
    roles::{KibanaPrivilege, RoleDefinition},
    spaces::Space,
};
use serde_json::{Map, json};

#[tokio::test]
async fn spaces_are_global_even_on_a_scoped_client() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let stored = json!({"id": "soc", "name": "SOC", "description": "Analysts", "disabledFeatures": ["ml"],
                        "color": "#aabbcc", "solution": "security", "_reserved": false});

    mock.json(json!([stored]));
    let spaces = client
        .spaces()
        .list()
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(spaces[0].disabled_features, ["ml"]);
    assert_eq!(spaces[0].extra["solution"], "security");
    mock.take().route("GET", "/api/spaces/space", &[]);

    mock.json(stored.clone());
    let mut space = client
        .spaces()
        .get("soc")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    mock.take().route("GET", "/api/spaces/space/soc", &[]);

    space.name = "Security operations".into();
    let mut expected = stored.clone();
    expected["name"] = json!("Security operations");
    mock.json(expected.clone());
    client
        .spaces()
        .update(&space.id, &space)
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/api/spaces/space/soc", &[])
        .body(expected);

    let mut new = Space::new("ir", "Incident response");
    new.description = Some("Temporary".into());
    mock.json(json!({"id": "ir", "name": "Incident response"}));
    let created = client
        .spaces()
        .create(&new)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.description, None);
    mock.take()
        .route("POST", "/api/spaces/space", &[])
        .body(json!({"id": "ir", "name": "Incident response", "description": "Temporary", "disabledFeatures": []}));

    mock.reply(204, "");
    client.spaces().delete("ir").send().await.unwrap();
    mock.take()
        .route("DELETE", "/api/spaces/space/ir", &[])
        .no_body();
}

#[tokio::test]
async fn roles_roundtrip_kibana_privileges_and_metadata() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let stored = json!({
        "name": "analyst", "description": "Read alerts",
        "elasticsearch": {"cluster": [], "indices": [{"names": [".alerts-*"], "privileges": ["read"]}], "run_as": []},
        "kibana": [{"spaces": ["soc"], "base": [], "feature": {"siemV2": ["all"]}}],
        "metadata": {"team": "soc"}, "transient_metadata": {"enabled": true}
    });

    mock.json(json!([stored]));
    let roles = client
        .roles()
        .list()
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(roles[0].definition.kibana[0].feature["siemV2"], ["all"]);
    assert_eq!(roles[0].extra["transient_metadata"]["enabled"], true);
    mock.take().route("GET", "/api/security/role", &[]);

    mock.json(stored);
    let role = client
        .roles()
        .get("analyst")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(role.definition.description.as_deref(), Some("Read alerts"));
    assert_eq!(role.definition.metadata.as_ref().unwrap()["team"], "soc");
    mock.take().route("GET", "/api/security/role/analyst", &[]);

    let mut privilege = KibanaPrivilege::new(vec!["soc".into()], vec!["read".into()]);
    privilege
        .feature
        .insert("fleetv2".into(), vec!["read".into()]);
    let mut definition = RoleDefinition::new(json!({"cluster": ["monitor"]}), vec![privilege]);
    definition.metadata = Some(Map::from_iter([("owner".into(), json!("krs"))]));
    mock.reply(204, "");
    client
        .roles()
        .put("soc reader", &definition)
        .create_only(true)
        .send()
        .await
        .unwrap();
    mock.take()
        .route(
            "PUT",
            "/api/security/role/soc%20reader",
            &[("createOnly", "true")],
        )
        .body(json!({
            "elasticsearch": {"cluster": ["monitor"]},
            "kibana": [{"spaces": ["soc"], "base": ["read"], "feature": {"fleetv2": ["read"]}}],
            "metadata": {"owner": "krs"}
        }));

    mock.reply(204, "");
    client
        .roles()
        .put("copy", &role.definition)
        .send()
        .await
        .unwrap();
    let body = mock.take().json();
    assert!(
        body.get("transient_metadata").is_none(),
        "read-only fields are not sent back"
    );
    assert_eq!(body["description"], "Read alerts");

    mock.reply(204, "");
    client.roles().delete("analyst").send().await.unwrap();
    mock.take()
        .route("DELETE", "/api/security/role/analyst", &[])
        .no_body();
}
