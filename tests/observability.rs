//! Trace events from the optional `tracing` feature.
#![cfg(feature = "tracing")]

mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use common::Mock;
use kibana_rs::{
    Kibana,
    http::{
        Credentials, TransportBuilder, Url,
        headers::{HeaderName, HeaderValue},
    },
};
use serde_json::json;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn requests_are_traced_without_secrets() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mock = Mock::start().await;
    let client = Kibana::new(
        TransportBuilder::new(Url::parse(&mock.url).unwrap())
            .auth(Credentials::Basic(
                "elastic".into(),
                "password-secret".into(),
            ))
            .build()
            .unwrap(),
    )
    .space("soc")
    .unwrap();

    mock.json(json!({"data": [], "page": 1, "perPage": 20, "total": 0}));
    client
        .security()
        .find_rules()
        .filter("query-secret")
        .header(
            HeaderName::from_static("x-opaque-id"),
            HeaderValue::from_static("trace-42"),
        )
        .send()
        .await
        .unwrap();
    mock.reply(404, r#"{"message":"body-secret"}"#);
    let _ = client.cases().get("missing").send().await;
    mock.reply(200, "not json");
    let _ = client
        .cases()
        .get("broken")
        .send()
        .await
        .unwrap()
        .json()
        .await;
    mock.json(json!({}));
    client
        .request(
            kibana_rs::http::Method::GET,
            kibana_rs::Scope::Global,
            &["api", "status"],
        )
        .send()
        .await
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let unreachable = Kibana::new(kibana_rs::http::Transport::single_node(&closed).unwrap());
    let _ = unreachable
        .cases()
        .find()
        .search("search-secret")
        .send()
        .await;
    let _ = client.cases().get("..").send().await;

    for path in [
        "api/x?token=rejected-query-secret",
        "api/x#rejected-fragment-secret",
    ] {
        let error = client
            .transport()
            .send::<()>(
                kibana_rs::http::Method::GET,
                path,
                Default::default(),
                None,
                None,
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, kibana_rs::Error::InvalidRequest(_)));
    }

    let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = output.lines().collect();
    let completed = lines
        .iter()
        .find(|l| l.contains("operation=\"FindRules\""))
        .expect(&output);
    for field in [
        "method=GET",
        "path=\"/s/soc/api/detection_engine/rules/_find\"",
        "status=200",
        "opaque_id=\"trace-42\"",
        "elapsed_ms=",
    ] {
        assert!(
            completed.contains(field),
            "{field} missing from {completed}"
        );
    }
    assert!(
        lines
            .iter()
            .any(|l| l.contains("operation=\"GetCase\"") && l.contains("status=404")),
        "{output}"
    );
    assert!(
        lines.iter().any(|l| l.contains("Kibana response body read")
            && l.contains("operation=\"GetCase\"")
            && l.contains("bytes=8")),
        "reading a body is traced separately from the headers: {output}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("did not match the expected type")
                && l.contains("operation=\"GetCase\"")),
        "{output}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("operation=\"request\"") && l.contains("path=\"/api/status\"")),
        "{output}"
    );
    for secret in [
        "query-secret",
        "rejected-query-secret",
        "rejected-fragment-secret",
        "body-secret",
        "password-secret",
        "ZWxhc3RpYzpwYXNzd29yZC1zZWNyZXQ=",
    ] {
        assert!(!output.contains(secret), "{secret} leaked:\n{output}");
    }
}
