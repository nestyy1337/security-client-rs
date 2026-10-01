mod common;

use common::Mock;
use security_client_rs::{
    SortOrder,
    cases::{CaseComment, CasePatch, CaseStatus, NewCase, SECURITY_OWNER},
    security::Severity,
};
use serde_json::{Value, json};

#[tokio::test]
async fn extra_patch_fields_preserve_case_identity_and_version() {
    let mock = Mock::start().await;
    let patch = CasePatch::new("a", "v1")
        .status(CaseStatus::Closed)
        .field("assignees", json!([{ "uid": "analyst" }]))
        .unwrap()
        .field("customFields", json!([]))
        .unwrap();
    mock.json(json!([]));
    mock.soc().cases().update([patch]).send().await.unwrap();
    mock.take()
        .route("PATCH", "/s/soc/api/cases", &[])
        .body(json!({"cases": [{
            "id": "a", "version": "v1", "status": "closed",
            "assignees": [{"uid": "analyst"}], "customFields": []
        }]}));

    for key in ["id", "version"] {
        assert!(matches!(
            CasePatch::new("a", "v1").field(key, "replacement"),
            Err(security_client_rs::Error::InvalidRequest(_))
        ));
    }
}

fn case(id: &str, status: &str) -> Value {
    json!({
        "id": id, "version": "WzEsMV0=", "title": "Brute force", "description": "d",
        "owner": "securitySolution", "status": status, "severity": "low", "tags": [],
        "created_at": "2026-09-28T00:00:00Z", "updated_at": null, "totalComment": 2,
        "assignees": [], "connector": {"id": "none"}
    })
}

#[tokio::test]
async fn find_cases_supports_filters_repeated_owners_and_tags() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(
        json!({"cases": [case("a", "open")], "page": 1, "per_page": 5, "total": 1,
                     "count_open_cases": 1, "count_in_progress_cases": 0, "count_closed_cases": 0}),
    );
    let page = client
        .cases()
        .find()
        .page(1)
        .per_page(5)
        .owner(SECURITY_OWNER)
        .owner("observability")
        .search("ssh")
        .status(CaseStatus::InProgress)
        .severity(Severity::Critical)
        .tag("linux")
        .tag("auth")
        .sort_field("updatedAt")
        .sort_order(SortOrder::Asc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.cases[0].total_comments, 2);
    assert_eq!(page.extra["count_open_cases"], 1);
    mock.take().route(
        "GET",
        "/s/soc/api/cases/_find",
        &[
            ("page", "1"),
            ("perPage", "5"),
            ("owner", "securitySolution"),
            ("owner", "observability"),
            ("search", "ssh"),
            ("status", "in-progress"),
            ("severity", "critical"),
            ("tags", "linux"),
            ("tags", "auth"),
            ("sortField", "updatedAt"),
            ("sortOrder", "asc"),
        ],
    );
}

#[tokio::test]
async fn create_get_update_and_delete_cases() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(case("new", "open"));
    let created = client
        .cases()
        .create(
            &NewCase::security("Brute force", "SSH failures")
                .severity(Severity::High)
                .tags(["ssh"])
                .sync_alerts(true),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.version, "WzEsMV0=");
    assert_eq!(created.extra["assignees"], json!([]));
    mock.take()
        .route("POST", "/s/soc/api/cases", &[])
        .body(json!({
            "title": "Brute force", "description": "SSH failures", "owner": "securitySolution",
            "severity": "high", "tags": ["ssh"],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
            "settings": {"syncAlerts": true}
        }));

    let connector =
        json!({"id": "jira", "name": "Jira", "type": ".jira", "fields": {"issueType": "10001"}});
    mock.json(case("obs", "open"));
    client
        .cases()
        .create(&NewCase::new("Latency", "p99", "observability").connector(connector.clone()))
        .send()
        .await
        .unwrap();
    let body = mock.take().json();
    assert_eq!(
        (
            body["owner"].clone(),
            body["severity"].clone(),
            body["connector"].clone()
        ),
        (json!("observability"), json!("low"), connector)
    );
    assert_eq!(body["settings"], json!({"syncAlerts": false}));

    mock.json(case("a/b", "open"));
    assert_eq!(
        client
            .cases()
            .get("a/b")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
            .id,
        "a/b"
    );
    mock.take()
        .route("GET", "/s/soc/api/cases/a%2Fb", &[])
        .no_body();

    mock.json(json!([case("a", "closed"), case("b", "open")]));
    let updated = client
        .cases()
        .update([
            CasePatch::new("a", "v1")
                .status(CaseStatus::Closed)
                .title("Closed")
                .description("Resolved")
                .severity(Severity::Medium)
                .tags(["done"]),
            CasePatch::new("b", "v2"),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated[0].status, "closed");
    mock.take().route("PATCH", "/s/soc/api/cases", &[]).body(json!({"cases": [
        {"id": "a", "version": "v1", "status": "closed", "title": "Closed", "description": "Resolved",
         "severity": "medium", "tags": ["done"]},
        {"id": "b", "version": "v2"}
    ]}));

    mock.reply(204, "");
    client.cases().delete(["a", "b/c"]).send().await.unwrap();
    mock.take()
        .route("DELETE", "/s/soc/api/cases", &[("ids", r#"["a","b/c"]"#)])
        .no_body();
}

#[tokio::test]
async fn comments_are_added_and_paged() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(case("a", "open"));
    let updated = client
        .cases()
        .add_comment("a", &CaseComment::user(SECURITY_OWNER, "Checked the host"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated.total_comments, 2);
    mock.take()
        .route("POST", "/s/soc/api/cases/a/comments", &[])
        .body(json!({"type": "user", "owner": "securitySolution", "comment": "Checked the host"}));

    mock.json(json!({"comments": [{"id": "c1", "type": "user", "comment": "x"}], "page": 2, "per_page": 1, "total": 2}));
    let page = client
        .cases()
        .find_comments("a")
        .page(2)
        .per_page(1)
        .sort_order(SortOrder::Desc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((page.page, page.total), (2, 2));
    assert_eq!(page.comments[0]["id"], "c1");
    mock.take().route(
        "GET",
        "/s/soc/api/cases/a/comments/_find",
        &[("page", "2"), ("perPage", "1"), ("sortOrder", "desc")],
    );
}
