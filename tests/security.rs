mod common;

use std::time::Duration;

use common::Mock;
use kibana_rs::{
    Error, SortOrder,
    exceptions::{ListReference, NamespaceType},
    security::{QueryLanguage, QueryRule, RiskScore, RuleSchedule, RuleSelector, Severity},
};
use serde_json::{Value, json};

fn rule(id: &str) -> Value {
    json!({
        "id": id, "rule_id": "stable-id", "name": "Failed logins", "description": "d",
        "enabled": false, "severity": "high", "risk_score": 73, "type": "query",
        "query": "event.outcome: failure", "tags": ["soc"], "updated_at": "2026-09-28T00:00:00Z",
        "exceptions_list": [], "execution_summary": {"last_execution": {"status": "succeeded"}}
    })
}

#[tokio::test]
async fn privileges_and_alert_index_initialization() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"has_encryption_key": true}));
    assert_eq!(
        client
            .security()
            .privileges()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()["has_encryption_key"],
        true
    );
    mock.take()
        .route("GET", "/s/soc/api/detection_engine/privileges", &[])
        .no_body();

    mock.json(json!({"acknowledged": true}));
    client
        .security()
        .create_alerts_index()
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/detection_engine/index", &[])
        .no_body();
}

#[tokio::test]
async fn find_rules_sends_only_selected_options_and_decodes_pages() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"data": [rule("a")], "page": 2, "perPage": 1, "total": 3}));
    let page = client
        .security()
        .find_rules()
        .page(2)
        .per_page(1)
        .filter("alert.attributes.enabled: true")
        .sort_field("name")
        .sort_order(SortOrder::Desc)
        .page(3)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((page.page, page.per_page, page.total), (2, 1, 3));
    assert_eq!(page.data[0].severity, "high");
    assert_eq!(
        page.data[0].extra["execution_summary"]["last_execution"]["status"],
        "succeeded"
    );
    mock.take().route(
        "GET",
        "/s/soc/api/detection_engine/rules/_find",
        &[
            ("per_page", "1"),
            ("filter", "alert.attributes.enabled: true"),
            ("sort_field", "name"),
            ("sort_order", "desc"),
            ("page", "3"),
        ],
    );

    mock.json(json!({"data": [], "page": 1, "per_page": 20, "total": 0}));
    assert_eq!(
        client
            .security()
            .find_rules()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .per_page,
        20
    );
    mock.take()
        .route("GET", "/s/soc/api/detection_engine/rules/_find", &[]);
}

#[tokio::test]
async fn rules_are_selected_by_saved_object_or_stable_id() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(rule("saved/id"));
    let found = client
        .security()
        .get_rule(RuleSelector::Id("saved/id"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(found.id, "saved/id");
    mock.take().route(
        "GET",
        "/s/soc/api/detection_engine/rules",
        &[("id", "saved/id")],
    );

    mock.json(rule("x"));
    client
        .security()
        .get_rule(RuleSelector::RuleId("stable id"))
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/detection_engine/rules",
        &[("rule_id", "stable id")],
    );

    mock.json(rule("x"));
    let deleted = client
        .security()
        .delete_rule(RuleSelector::RuleId("stable-id"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(deleted.rule_id, "stable-id");
    mock.take()
        .route(
            "DELETE",
            "/s/soc/api/detection_engine/rules",
            &[("rule_id", "stable-id")],
        )
        .no_body();
}

#[tokio::test]
async fn query_rules_serialize_defaults_and_every_option() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(rule("new"));
    client
        .security()
        .create_rule(&QueryRule::new("Default", "Defaults", "host.name: *"))
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/detection_engine/rules", &[])
        .body(json!({
            "type": "query", "name": "Default", "description": "Defaults", "query": "host.name: *",
            "language": "kuery", "index": ["logs-*"], "severity": "medium", "risk_score": 47,
            "enabled": false, "interval": "5m", "from": "now-6m", "tags": []
        }));

    let list = ListReference::new("so-id", "allowlist", NamespaceType::Agnostic, "detection");
    let request = QueryRule::new("Custom", "All options", "process.name: nc")
        .language(QueryLanguage::Lucene)
        .index(["auditbeat-*", "logs-endpoint.*"])
        .severity(Severity::Critical)
        .risk_score(RiskScore::new(99).unwrap())
        .enabled(true)
        .schedule(RuleSchedule::new(Duration::from_secs(60), Duration::from_secs(60)).unwrap())
        .tags(["soc", "linux"])
        .rule_id("custom-rule")
        .exceptions_list(vec![list]);
    mock.json(rule("new"));
    client
        .security()
        .create_rule(&request)
        .send()
        .await
        .unwrap();
    mock.take().body(json!({
        "type": "query", "name": "Custom", "description": "All options", "query": "process.name: nc",
        "language": "lucene", "index": ["auditbeat-*", "logs-endpoint.*"], "severity": "critical",
        "risk_score": 99, "enabled": true, "interval": "1m", "from": "now-2m", "tags": ["soc", "linux"],
        "rule_id": "custom-rule",
        "exceptions_list": [{"id": "so-id", "list_id": "allowlist", "namespace_type": "agnostic", "type": "detection"}]
    }));

    let eql = json!({"type": "eql", "name": "EQL", "description": "d", "query": "process where true",
                     "language": "eql", "severity": "low", "risk_score": 21});
    mock.json(rule("eql"));
    client.security().create_rule(&eql).send().await.unwrap();
    mock.take().body(eql);
}

#[tokio::test]
async fn patch_rule_sends_the_selector_and_only_changed_fields() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(rule("id-1"));
    let patched = client
        .security()
        .patch_rule(RuleSelector::Id("id-1"))
        .name("Renamed")
        .description("New description")
        .enabled(true)
        .query("event.outcome: success")
        .severity(Severity::Low)
        .risk_score(RiskScore::try_from(10).unwrap())
        .tags(["triaged"])
        .exceptions_list(vec![])
        .field("max_signals", 50)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(patched.id, "id-1");
    mock.take().route("PATCH", "/s/soc/api/detection_engine/rules", &[]).body(json!({
        "id": "id-1", "name": "Renamed", "description": "New description", "enabled": true,
        "query": "event.outcome: success", "severity": "low", "risk_score": 10, "tags": ["triaged"],
        "exceptions_list": [], "max_signals": 50
    }));

    mock.json(rule("x"));
    client
        .security()
        .patch_rule(RuleSelector::RuleId("stable"))
        .enabled(false)
        .send()
        .await
        .unwrap();
    mock.take()
        .body(json!({"rule_id": "stable", "enabled": false}));
}

#[tokio::test]
async fn exports_stream_ndjson_and_imports_upload_multipart_with_partial_failures() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.reply(200, "{\"rule_id\":\"a\"}\n{\"exported_count\":1}\n");
    let exported = client
        .security()
        .export_rules()
        .rule_ids(["a", "b"])
        .exclude_export_details(true)
        .file_name("rules.ndjson")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert!(exported.starts_with(b"{\"rule_id\":\"a\"}"));
    mock.take()
        .route(
            "POST",
            "/s/soc/api/detection_engine/rules/_export",
            &[
                ("exclude_export_details", "true"),
                ("file_name", "rules.ndjson"),
            ],
        )
        .body(json!({"objects": [{"rule_id": "a"}, {"rule_id": "b"}]}));

    mock.reply(200, "");
    client.security().export_rules().send().await.unwrap();
    mock.take()
        .route("POST", "/s/soc/api/detection_engine/rules/_export", &[])
        .no_body();

    mock.json(json!({"success": false, "success_count": 0, "errors": [{"rule_id": "a", "error": {"status_code": 409}}],
                     "rules_count": 1, "exceptions_success": true}));
    let result = client
        .security()
        .import_rules(exported.to_vec())
        .overwrite(false)
        .overwrite_exceptions(true)
        .overwrite_action_connectors(false)
        .as_new_list(true)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!result.success);
    assert_eq!(result.errors[0]["error"]["status_code"], 409);
    assert_eq!(result.extra["rules_count"], 1);
    let request = mock.take();
    request.route(
        "POST",
        "/s/soc/api/detection_engine/rules/_import",
        &[
            ("overwrite", "false"),
            ("overwrite_exceptions", "true"),
            ("overwrite_action_connectors", "false"),
            ("as_new_list", "true"),
        ],
    );
    assert_eq!(
        request
            .multipart_file("rules.ndjson", "application/x-ndjson")
            .as_bytes(),
        exported.as_ref()
    );
}

#[test]
fn risk_scores_above_100_are_rejected() {
    assert_eq!(RiskScore::new(100).unwrap().get(), 100);
    assert!(matches!(
        RiskScore::new(101),
        Err(kibana_rs::Error::InvalidRequest(_))
    ));
    assert!(RiskScore::try_from(255).is_err());
}

#[test]
fn schedules_derive_a_lookback_covering_the_interval() {
    let body = |rule: QueryRule| {
        let value = serde_json::to_value(rule).unwrap();
        (value["interval"].clone(), value["from"].clone())
    };
    let rule = || QueryRule::new("n", "d", "q");
    assert_eq!(body(rule()), (json!("5m"), json!("now-6m")));
    let every = |secs| RuleSchedule::every(Duration::from_secs(secs)).unwrap();
    assert_eq!(
        body(rule().schedule(every(900))),
        (json!("15m"), json!("now-16m"))
    );
    assert_eq!(
        body(rule().schedule(every(3540))),
        (json!("59m"), json!("now-1h"))
    );
    let exact = RuleSchedule::new(Duration::from_secs(90), Duration::ZERO).unwrap();
    assert_eq!(
        body(rule().schedule(exact)),
        (json!("90s"), json!("now-90s"))
    );
    assert_eq!(exact.lookback(), exact.interval());
    assert_eq!(
        body(rule().custom_schedule("1h", "now-2h/h")),
        (json!("1h"), json!("now-2h/h"))
    );
    for invalid in [
        RuleSchedule::every(Duration::ZERO),
        RuleSchedule::every(Duration::from_millis(1500)),
        RuleSchedule::new(Duration::from_secs(60), Duration::from_millis(1)),
    ] {
        assert!(matches!(invalid, Err(Error::InvalidRequest(_))));
    }
}

#[tokio::test]
async fn patches_cannot_silently_change_the_selector_or_bypass_validation() {
    let mock = Mock::start().await;
    let client = mock.soc();
    for (field, value) in [
        ("id", json!("b")),
        ("rule_id", json!("other")),
        ("risk_score", json!(500)),
        ("severity", json!("extreme")),
    ] {
        let error = client
            .security()
            .patch_rule(RuleSelector::Id("a"))
            .field(field, value)
            .send()
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidRequest(_)),
            "{field}: {error:?}"
        );
    }
    for error in [
        client
            .security()
            .patch_rule(RuleSelector::Id(""))
            .enabled(true)
            .send()
            .await
            .unwrap_err(),
        client
            .security()
            .get_rule(RuleSelector::RuleId(""))
            .send()
            .await
            .unwrap_err(),
        client
            .security()
            .delete_rule(RuleSelector::Id(""))
            .send()
            .await
            .unwrap_err(),
    ] {
        assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    }
    assert_eq!(mock.request_count(), 0);

    mock.json(rule("a"));
    client
        .security()
        .patch_rule(RuleSelector::Id("a"))
        .schedule(RuleSchedule::every(Duration::from_secs(600)).unwrap())
        .unchecked_field("rule_id", "deliberate")
        .send()
        .await
        .unwrap();
    mock.take().body(json!({
        "id": "a", "interval": "10m", "from": "now-11m", "rule_id": "deliberate"
    }));
}
