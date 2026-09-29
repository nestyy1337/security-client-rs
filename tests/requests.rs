//! Request construction: errors caught before sending, raw bodies and builder reuse.
mod common;

use std::collections::BTreeMap;

use common::Mock;
use kibana_rs::{
    Error, Scope,
    cases::{CasePatch, CaseStatus},
    http::{Body, Method},
    security::{RuleSelector, Severity},
};
use serde_json::json;

/// Maps with non-string keys cannot be represented as JSON objects.
fn unserializable() -> BTreeMap<(u8, u8), u8> {
    BTreeMap::from([((1, 2), 3)])
}

#[tokio::test]
async fn serialization_failures_are_reported_by_send_without_a_request() {
    let mock = Mock::start().await;
    let client = mock.client();
    let failures = [
        client
            .request(Method::GET, Scope::Space, &["api", "x"])
            .query(&json!({"nested": {"objects": "are not query strings"}}))
            .send()
            .await
            .unwrap_err(),
        client
            .request(Method::POST, Scope::Space, &["api", "x"])
            .json(&unserializable())
            .send()
            .await
            .unwrap_err(),
        client
            .security()
            .create_rule(&unserializable())
            .send()
            .await
            .unwrap_err(),
        client
            .security()
            .patch_rule(RuleSelector::Id("r"))
            .field("threat", unserializable())
            .send()
            .await
            .unwrap_err(),
    ];
    for error in failures {
        assert!(matches!(error, Error::Serialize(_)), "{error:?}");
    }
    assert_eq!(mock.request_count(), 0);
    assert!(matches!(
        CasePatch::new("a", "v1").field("customFields", unserializable()),
        Err(Error::Serialize(_))
    ));
}

#[tokio::test]
async fn named_builders_can_extend_a_request_without_rebuilding_it() {
    use kibana_rs::http::headers::{HeaderName, HeaderValue};
    use std::time::Duration;

    let mock = Mock::start_at("/proxy").await;
    let client = mock.soc();
    mock.json(json!({}));
    client
        .security()
        .patch_rule(RuleSelector::RuleId("r"))
        .enabled(true)
        .header(
            HeaderName::from_static("x-opaque-id"),
            HeaderValue::from_static("extended"),
        )
        .into_request()
        .query(&[("refresh", "wait_for")])
        .send()
        .await
        .unwrap();
    let request = mock.take();
    request
        .route(
            "PATCH",
            "/proxy/s/soc/api/detection_engine/rules",
            &[("refresh", "wait_for")],
        )
        .body(json!({"rule_id": "r", "enabled": true}));
    assert_eq!(request.header("x-opaque-id"), Some("extended"));

    mock.reply_after(Duration::from_secs(1));
    let error = client
        .status()
        .request_timeout(Duration::from_millis(20))
        .into_request()
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Transport(e) if e.is_timeout()));
    mock.take().route("GET", "/proxy/api/status", &[]);

    let error = client
        .cases()
        .get("")
        .into_request()
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::InvalidRequest(_)));
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn fields_cannot_be_merged_into_a_non_object_body() {
    let mock = Mock::start().await;
    let error = mock
        .client()
        .exceptions()
        .update_list("id", "WzEsMV0=", &json!(["not", "an", "object"]))
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::InvalidRequest(ref message) if message.contains("\"id\"")),
        "{error:?}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn the_first_construction_error_wins_and_survives_cloning() {
    let mock = Mock::start().await;
    let client = mock.client();
    let error = client
        .request(Method::POST, Scope::Global, &["api", ".."])
        .json(&unserializable())
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::InvalidRequest(_)),
        "the path error comes first: {error:?}"
    );

    let original = client.cases().get("");
    let copy = original.clone();
    for error in [
        original.send().await.unwrap_err(),
        copy.send().await.unwrap_err(),
    ] {
        assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    }
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn raw_requests_send_json_and_file_bodies() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(json!({"ok": true}));
    client
        .request(Method::POST, Scope::Space, &["api", "lists", "items"])
        .body(Body::json(&json!({"value": "10.0.0.1"})).unwrap())
        .send()
        .await
        .unwrap();
    mock.take()
        .route("POST", "/s/soc/api/lists/items", &[])
        .body(json!({"value": "10.0.0.1"}));

    mock.json(json!({"ok": true}));
    let upload = Body::file(
        "file",
        "ips.txt",
        "text/plain",
        b"10.0.0.1\n10.0.0.2\n".to_vec(),
    )
    .unwrap();
    client
        .request(
            Method::POST,
            Scope::Space,
            &["api", "lists", "items", "_import"],
        )
        .query(&[("type", "ip")])
        .body(upload)
        .send()
        .await
        .unwrap();
    let request = mock.take();
    request.route("POST", "/s/soc/api/lists/items/_import", &[("type", "ip")]);
    assert_eq!(
        request.multipart_file("ips.txt", "text/plain"),
        "10.0.0.1\n10.0.0.2\n"
    );

    assert!(matches!(
        Body::file("file", "x", "not a content type", Vec::new()),
        Err(Error::InvalidRequest(_))
    ));
}

#[tokio::test]
async fn enum_filters_use_kibana_wire_values() {
    let mock = Mock::start().await;
    let client = mock.client();
    let cases = [
        (CaseStatus::Open, Severity::Low, "open", "low"),
        (
            CaseStatus::InProgress,
            Severity::Medium,
            "in-progress",
            "medium",
        ),
        (CaseStatus::Closed, Severity::High, "closed", "high"),
        (CaseStatus::Closed, Severity::Critical, "closed", "critical"),
    ];
    for (status, severity, status_value, severity_value) in cases {
        mock.json(json!({"cases": [], "page": 1, "per_page": 20, "total": 0}));
        client
            .cases()
            .find()
            .status(status)
            .severity(severity)
            .send()
            .await
            .unwrap();
        mock.take().route(
            "GET",
            "/api/cases/_find",
            &[("status", status_value), ("severity", severity_value)],
        );
    }
}

#[tokio::test]
async fn errors_without_a_response_have_no_status_body_or_hints() {
    let mock = Mock::start().await;
    let error = mock.client().cases().get("").send().await.unwrap_err();
    assert_eq!(error.status(), None);
    assert_eq!(error.body(), None);
    assert_eq!(error.message(), None);
    assert_eq!(error.retry_after(), None);

    mock.reply_with(
        503,
        vec![("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT".into())],
        "busy",
    );
    let error = mock.client().status().send().await.unwrap_err();
    assert_eq!(error.retry_after(), None, "HTTP-date values are not parsed");
    assert_eq!(
        error.message(),
        None,
        "a non-JSON body has no Kibana message"
    );
}
