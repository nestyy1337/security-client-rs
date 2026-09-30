mod common;

use std::time::Duration;

use common::Mock;
use futures_util::TryStreamExt;
use kibana_rs::{
    Error, Kibana, Scope,
    http::{
        Body, Credentials, Method, StatusCode, Transport, TransportBuilder, Url,
        headers::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue},
    },
    security::Severity,
};
use serde_json::{Value, json};

fn transport(url: &str) -> TransportBuilder {
    TransportBuilder::new(Url::parse(url).unwrap())
}

#[tokio::test]
async fn decode_errors_keep_response_headers_without_logging_their_values() {
    let mock = Mock::start().await;
    mock.reply_with(
        200,
        vec![("x-opaque-id", "decode-header-secret".into())],
        "not json",
    );
    let error = mock
        .client()
        .status()
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::OK));
    assert_eq!(
        error.headers().unwrap()["x-opaque-id"],
        "decode-header-secret"
    );
    assert!(!format!("{error:?}").contains("decode-header-secret"));
}

#[tokio::test]
async fn routing_preserves_proxy_prefix_and_encodes_segments_without_scoping_global_routes() {
    let mock = Mock::start_at("/kibana/proxy/").await;
    let client = Kibana::new(
        transport(&mock.url)
            .auth(Credentials::EncodedApiKey("test-key".into()))
            .build()
            .unwrap(),
    )
    .space("soc")
    .unwrap();

    mock.json(json!({"ok": true}));
    let value = client
        .request(
            Method::GET,
            Scope::Space,
            &["api", "things", "id/with?reserved#chars"],
        )
        .query(&[("filter", "name: a+b & c")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value, json!({"ok": true}));
    let request = mock.take();
    assert_eq!(
        request.path,
        "/kibana/proxy/s/soc/api/things/id%2Fwith%3Freserved%23chars"
    );
    assert_eq!(request.query.as_deref(), Some("filter=name%3A+a%2Bb+%26+c"));
    assert_eq!(request.header("authorization"), Some("ApiKey test-key"));
    assert_eq!(request.header("kbn-xsrf"), Some("kibana-rs"));
    assert!(
        request
            .header("user-agent")
            .unwrap()
            .starts_with("kibana-rs/")
    );
    request.no_body();

    mock.json(json!({"status": {}}));
    client.status().send().await.unwrap();
    mock.take().route("GET", "/kibana/proxy/api/status", &[]);
    mock.json(json!([]));
    client
        .default_space()
        .request(Method::GET, Scope::Space, &["api", "x"])
        .send()
        .await
        .unwrap();
    mock.take().route("GET", "/kibana/proxy/api/x", &[]);
}

#[tokio::test]
async fn basic_credentials_and_transport_headers_are_sent_and_requests_can_override_them() {
    let mock = Mock::start().await;
    let client = Kibana::new(
        transport(&mock.url)
            .auth(Credentials::Basic("elastic".into(), "changeme".into()))
            .header(
                HeaderName::from_static("elastic-api-version"),
                HeaderValue::from_static("2023-10-31"),
            )
            .build()
            .unwrap(),
    );
    mock.json(json!({}));
    client.status().send().await.unwrap();
    let request = mock.take();
    assert_eq!(
        request.header("authorization"),
        Some("Basic ZWxhc3RpYzpjaGFuZ2VtZQ==")
    );
    assert_eq!(request.header("elastic-api-version"), Some("2023-10-31"));

    mock.json(json!({}));
    client
        .status()
        .header(AUTHORIZATION, HeaderValue::from_static("Bearer run-as"))
        .header(
            HeaderName::from_static("kbn-xsrf"),
            HeaderValue::from_static("custom"),
        )
        .send()
        .await
        .unwrap();
    let request = mock.take();
    assert_eq!(request.header("authorization"), Some("Bearer run-as"));
    assert_eq!(request.header("kbn-xsrf"), Some("custom"));
}

#[tokio::test]
async fn errors_keep_status_headers_bounded_body_and_kibana_message() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.reply_with(429, vec![("retry-after", "3".into())], "x".repeat(20_000));
    let error = client.status().send().await.unwrap_err();
    assert_eq!(error.retry_after(), Some(Duration::from_secs(3)));
    match error {
        Error::Api {
            status,
            headers,
            body,
            truncated,
            ..
        } => {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(headers["retry-after"], "3");
            assert_eq!(body.len(), 16384);
            assert!(truncated);
        }
        other => panic!("wrong error: {other}"),
    }

    mock.reply(
        409,
        json!({"statusCode": 409, "error": "Conflict", "message": "version conflict"}).to_string(),
    );
    let error = client.status().send().await.unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::CONFLICT));
    assert_eq!(error.message().as_deref(), Some("version conflict"));
    assert!(error.body().unwrap().contains("Conflict"));
    assert!(
        !error.to_string().contains("version conflict"),
        "bodies stay out of Display"
    );
}

#[tokio::test]
async fn mutations_are_not_retried_and_redirects_are_not_followed() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.reply(503, "uncertain write outcome");
    mock.reply_with(307, vec![("location", "/api/write".into())], "");
    for status in [503, 307] {
        let error = client
            .request(Method::POST, Scope::Space, &["api", "write"])
            .json(&json!({}))
            .send()
            .await
            .unwrap_err();
        assert_eq!(error.status().unwrap().as_u16(), status);
    }
    assert_eq!(mock.request_count(), 2);
}

#[tokio::test]
async fn response_limits_and_decode_errors_are_distinct() {
    let mock = Mock::start().await;
    mock.reply(200, "<html>login required</html>");
    assert!(matches!(
        mock.client()
            .status()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap_err(),
        Error::Decode {
            status: StatusCode::OK,
            ..
        }
    ));

    let limited = Kibana::new(transport(&mock.url).response_limit(8).build().unwrap());
    mock.reply(200, "0123456789");
    assert!(matches!(
        limited
            .status()
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap_err(),
        Error::ResponseTooLarge { limit: 8, .. }
    ));
    mock.reply(200, "0123456789");
    assert!(matches!(
        limited
            .status()
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap_err(),
        Error::ResponseTooLarge { limit: 8, .. }
    ));
    mock.reply(200, "0123456789");
    let chunks: Vec<_> = limited
        .status()
        .send()
        .await
        .unwrap()
        .bytes_stream()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(chunks.concat(), b"0123456789", "streams are not limited");
}

#[tokio::test]
async fn responses_expose_status_headers_and_alternative_decoding() {
    let mock = Mock::start().await;
    mock.reply_with(
        201,
        vec![("x-trace", "abc".into())],
        r#"{"version":{"number":"9.5.4"}}"#,
    );
    let response = mock.client().status().send().await.unwrap();
    assert_eq!(response.status_code(), StatusCode::CREATED);
    assert_eq!(response.headers()["x-trace"], "abc");
    assert_eq!(response.content_length(), Some(30));
    #[derive(serde::Deserialize)]
    struct Version {
        number: String,
    }
    #[derive(serde::Deserialize)]
    struct Status {
        version: Version,
    }
    assert_eq!(
        response.json_as::<Status>().await.unwrap().version.number,
        "9.5.4"
    );
}

#[tokio::test]
async fn invalid_requests_fail_on_send_without_contacting_kibana() {
    let mock = Mock::start().await;
    let client = mock.client();
    for error in [
        client
            .request(Method::GET, Scope::Global, &["api", ".."])
            .send()
            .await
            .unwrap_err(),
        client
            .request(Method::GET, Scope::Global, &[])
            .send()
            .await
            .unwrap_err(),
        client.cases().get("").send().await.unwrap_err(),
        client.spaces().delete(".").send().await.unwrap_err(),
    ] {
        assert!(matches!(error, Error::InvalidRequest(_)), "{error}");
    }
    let raw = client
        .transport()
        .send::<()>(
            Method::GET,
            "/api/x?y=1",
            HeaderMap::new(),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(raw.unwrap_err(), Error::InvalidRequest(_)));
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn invalid_configuration_is_rejected_and_debug_output_hides_credentials() {
    for url in [
        "file:///tmp/test",
        "http://user:secret@localhost",
        "http://localhost?token=secret",
        "http://localhost/#fragment",
    ] {
        assert!(
            matches!(transport(url).build().unwrap_err(), Error::Configuration(_)),
            "{url}"
        );
    }
    assert!(Transport::single_node("not a url").is_err());
    assert!(
        transport("http://localhost")
            .response_limit(0)
            .build()
            .is_err()
    );
    assert!(
        transport("http://localhost")
            .auth(Credentials::Bearer("bad\ntoken".into()))
            .build()
            .is_err()
    );

    let credentials = Credentials::Basic("a".into(), "supersecret".into());
    assert!(!format!("{credentials:?}").contains("supersecret"));
    let builder = transport("http://localhost").auth(credentials);
    assert!(!format!("{builder:?}").contains("supersecret"));
    let client = Kibana::new(builder.build().unwrap());
    assert!(!format!("{client:?}").contains("supersecret"));
    for invalid in ["", ".", "..", "../admin"] {
        assert!(client.space(invalid).is_err(), "{invalid}");
    }
    assert_eq!(client.space("soc").unwrap().space_id(), Some("soc"));

    let cloud = Transport::cloud(
        "prod:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyRlcy11dWlkJGtiLXV1aWQ=",
        Credentials::EncodedApiKey("key".into()),
    )
    .unwrap();
    assert_eq!(
        cloud.url().as_str(),
        "https://kb-uuid.us-east-1.aws.found.io/"
    );
}

#[tokio::test]
async fn transport_and_request_timeouts_are_transport_errors() {
    let mock = Mock::start().await;
    mock.reply_after(Duration::from_secs(5));
    mock.reply_after(Duration::from_secs(5));
    let client = Kibana::new(
        transport(&mock.url)
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap(),
    );
    assert!(matches!(
        client.request(Method::GET, Scope::Global, &["api", "status"]).send().await.unwrap_err(),
        Error::Transport(error) if error.is_timeout()
    ));
    let error = mock
        .client()
        .status()
        .request_timeout(Duration::from_millis(100))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Transport(e) if e.is_timeout()));
}

#[tokio::test]
async fn raw_transport_send_encodes_query_and_json_body() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.json(json!({"accepted": true}));
    let mut headers = HeaderMap::new();
    headers.insert("x-opaque-id", HeaderValue::from_static("trace-1"));
    let value: Value = client
        .transport()
        .send(
            Method::POST,
            "api/lists/items",
            headers,
            Some(&[("list_id", "ip list"), ("refresh", "true")]),
            Some(Body::json(&json!({"value": "10.0.0.1"})).unwrap()),
            None,
        )
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["accepted"], true);
    let request = mock.take();
    request
        .route(
            "POST",
            "/api/lists/items",
            &[("list_id", "ip list"), ("refresh", "true")],
        )
        .body(json!({"value": "10.0.0.1"}));
    assert_eq!(request.header("x-opaque-id"), Some("trace-1"));
}

#[tokio::test]
async fn an_explicit_proxy_receives_requests_for_the_kibana_host() {
    let proxy = Mock::start().await;
    let client = Kibana::new(
        transport("http://kibana.invalid:5601")
            .proxy(Url::parse(&proxy.url).unwrap())
            .build()
            .unwrap(),
    );
    proxy.json(json!({}));
    client.status().send().await.unwrap();
    proxy.take().route("GET", "/api/status", &[]);
}

#[tokio::test]
async fn backslashes_in_identifiers_cannot_change_the_route() {
    let mock = Mock::start().await;
    mock.json(json!({}));
    let _ = mock
        .soc()
        .cases()
        .get(r"..\..\..\api\security\role")
        .send()
        .await;
    mock.take().route(
        "GET",
        "/s/soc/api/cases/..%5C..%5C..%5Capi%5Csecurity%5Crole",
        &[],
    );
    let raw = mock
        .client()
        .transport()
        .send::<()>(
            Method::GET,
            r"/api\..\status",
            HeaderMap::new(),
            None,
            None,
            None,
        )
        .await;
    assert!(matches!(raw.unwrap_err(), Error::InvalidRequest(_)));
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn debug_output_omits_proxy_passwords_query_values_and_bodies() {
    let builder = transport("http://localhost")
        .proxy(Url::parse("http://proxy-user:proxy-secret@proxy.invalid:3128").unwrap())
        .header(
            HeaderName::from_static("x-api-token"),
            HeaderValue::from_static("header-secret"),
        );
    let debug = format!("{builder:?}");
    assert!(
        !debug.contains("proxy-secret")
            && !debug.contains("proxy-user")
            && !debug.contains("header-secret"),
        "{debug}"
    );
    assert!(debug.contains("x-api-token"), "{debug}");

    let mock = Mock::start().await;
    let client = mock.client();
    let request = client
        .request(Method::GET, Scope::Global, &["api", "x"])
        .query(&[("token", "query-secret")]);
    let debug = format!("{request:?}");
    assert!(
        debug.contains("token") && !debug.contains("query-secret"),
        "{debug}"
    );

    mock.reply(403, r#"{"message":"body-secret"}"#);
    let error = client.status().send().await.unwrap_err();
    assert!(!format!("{error:?}").contains("body-secret"));
    assert_eq!(error.message().as_deref(), Some("body-secret"));
}

#[tokio::test]
async fn response_and_decode_error_diagnostics_do_not_expose_values() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.json(json!("body-secret"));
    let response = client
        .request(Method::GET, Scope::Global, &["api", "status"])
        .query(&[("token", "query-secret")])
        .send()
        .await
        .unwrap();
    assert!(response.url().as_str().contains("query-secret"));
    assert!(!format!("{response:?}").contains("query-secret"));

    let error = response.json_as::<u64>().await.unwrap_err();
    assert_eq!(error.body(), Some("\"body-secret\""));
    let mut cause: Option<&dyn std::error::Error> = Some(&error);
    while let Some(error) = cause {
        assert!(!format!("{error}").contains("body-secret"));
        assert!(!format!("{error:?}").contains("body-secret"));
        cause = error.source();
    }
}

#[tokio::test]
async fn an_interrupted_error_body_keeps_status_headers_and_partial_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket
            .write_all(b"HTTP/1.1 429 Too Many Requests\r\nretry-after: 3\r\ncontent-length: 100\r\n\r\npartial")
            .await
            .unwrap();
    });
    let client = Kibana::new(Transport::single_node(&url).unwrap());
    match client.status().send().await.unwrap_err() {
        Error::Api {
            status,
            headers,
            body,
            truncated,
            body_error,
            ..
        } => {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(headers["retry-after"], "3");
            assert_eq!(body, "partial");
            assert!(!truncated);
            assert!(body_error.is_some());
        }
        other => panic!("wrong error: {other:?}"),
    }
    server.await.unwrap();
}

/// A throwaway self-signed CA used only to check certificate parsing.
const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUWvDoZB2tpC0JKr+pfEsfke1uo0YwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRa2liYW5hLXJzIHRlc3QgQ0EwIBcNMjYwOTI4MjMzMzUzWhgP
MjEyNjA5MDQyMzMzNTNaMBwxGjAYBgNVBAMMEWtpYmFuYS1ycyB0ZXN0IENBMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENlfzDO8MU/3qtiElHVLHegUbQXCfw96m
0z+rVeSfENTTPzEDUJj1DLYN9auvsAVhdmH5d3KgL8EG3H64cbSdSqNTMFEwHQYD
VR0OBBYEFGJQMhr6hhaZwVKU5TLD4Sh+xDscMB8GA1UdIwQYMBaAFGJQMhr6hhaZ
wVKU5TLD4Sh+xDscMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIg
WNe2dl/GLMFkOFT/MMkZvM1tSs/clK5OtefTJdd1MGkCIQCdXyI/ESqHQjOyl7+n
85hBYPg9Ll+f9pd1oz9J/OGlWw==
-----END CERTIFICATE-----
";

#[test]
fn certificates_must_contain_a_usable_certificate() {
    use base64::Engine;
    use kibana_rs::http::Certificate;
    let with_root = |certificate: Certificate| {
        transport("https://localhost")
            .root_certificate(certificate)
            .build()
    };

    assert!(with_root(Certificate::from_pem(TEST_CA.as_bytes()).unwrap()).is_ok());
    let bundle = format!("{TEST_CA}{TEST_CA}");
    assert!(
        with_root(Certificate::from_pem(bundle.as_bytes()).unwrap()).is_ok(),
        "bundles are accepted"
    );
    for invalid in [
        &b""[..],
        b"garbage",
        b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    ] {
        assert!(
            matches!(Certificate::from_pem(invalid), Err(Error::Configuration(_))),
            "{}",
            String::from_utf8_lossy(invalid)
        );
    }

    let body: String = TEST_CA
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    assert!(with_root(Certificate::from_der(&der).unwrap()).is_ok());
    let invalid_der = Certificate::from_der(b"not DER").unwrap();
    assert!(matches!(
        with_root(invalid_der),
        Err(Error::Configuration(_))
    ));
}

#[tokio::test]
async fn transport_default_headers_merge_and_later_values_replace_earlier_ones() {
    let mock = Mock::start().await;
    let mut first = HeaderMap::new();
    first.insert("x-team", HeaderValue::from_static("blue"));
    first.insert("x-region", HeaderValue::from_static("eu"));
    let mut second = HeaderMap::new();
    second.insert("x-team", HeaderValue::from_static("red"));
    let client = Kibana::new(
        transport(&mock.url)
            .headers(first)
            .headers(second)
            .build()
            .unwrap(),
    );
    mock.json(json!({}));
    client.status().send().await.unwrap();
    let request = mock.take();
    assert_eq!(request.header("x-team"), Some("red"));
    assert_eq!(request.header("x-region"), Some("eu"));
    assert_eq!(
        request.header("kbn-xsrf"),
        Some("kibana-rs"),
        "built-in defaults stay"
    );
}

#[tokio::test]
async fn transport_errors_do_not_reveal_query_values() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let error = Kibana::new(Transport::single_node(&closed).unwrap())
        .request(Method::GET, Scope::Global, &["api", "x"])
        .query(&[("token", "query-secret")])
        .send()
        .await
        .unwrap_err();
    let Error::Transport(transport_error) = &error else {
        panic!("expected a transport error, got {error:?}");
    };
    assert!(transport_error.is_connect());
    assert!(std::error::Error::source(transport_error).is_some());
    for text in [
        error.to_string(),
        format!("{error:?}"),
        transport_error.to_string(),
    ] {
        assert!(!text.contains("query-secret"), "{text}");
    }
}

#[tokio::test]
async fn headers_are_prepared_once_with_defaults_body_then_request_precedence() {
    let mock = Mock::start().await;
    let mut defaults = HeaderMap::new();
    defaults.insert("content-type", HeaderValue::from_static("text/plain"));
    defaults.append("x-multi", HeaderValue::from_static("one"));
    defaults.append("x-multi", HeaderValue::from_static("two"));
    defaults.insert("x-team", HeaderValue::from_static("blue"));
    let client = Kibana::new(transport(&mock.url).headers(defaults).build().unwrap());

    mock.json(json!({}));
    client
        .request(Method::POST, Scope::Global, &["api", "x"])
        .json(&json!({"a": 1}))
        .send()
        .await
        .unwrap();
    let request = mock.take();
    let values = |name: &str| -> Vec<&str> {
        request
            .headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    };
    assert_eq!(
        values("content-type"),
        ["application/json"],
        "the body's type replaces the default"
    );
    assert_eq!(
        values("x-multi"),
        ["one", "two"],
        "repeated default values are all sent"
    );

    mock.json(json!({}));
    client
        .request(Method::GET, Scope::Global, &["api", "x"])
        .send()
        .await
        .unwrap();
    assert_eq!(
        mock.take().header("content-type"),
        Some("text/plain"),
        "defaults apply without a body"
    );

    mock.json(json!({}));
    client
        .request(Method::POST, Scope::Global, &["api", "x"])
        .body(Body::file("file", "a.ndjson", "application/ndjson", b"{}\n".to_vec()).unwrap())
        .header(
            HeaderName::from_static("x-multi"),
            HeaderValue::from_static("three"),
        )
        .send()
        .await
        .unwrap();
    let request = mock.take();
    let content_types: Vec<_> = request.headers.get_all("content-type").iter().collect();
    assert_eq!(content_types.len(), 1, "{content_types:?}");
    assert_eq!(
        request.multipart_file("a.ndjson", "application/ndjson"),
        "{}\n"
    );
    let multi: Vec<_> = request.headers.get_all("x-multi").iter().collect();
    assert_eq!(
        multi,
        ["three"],
        "a request header replaces every default value"
    );
    assert_eq!(request.header("x-team"), Some("blue"));

    mock.json(json!({}));
    client
        .request(Method::POST, Scope::Global, &["api", "x"])
        .json(&json!({}))
        .header(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/vnd.custom+json"),
        )
        .send()
        .await
        .unwrap();
    let request = mock.take();
    let content_types: Vec<_> = request.headers.get_all("content-type").iter().collect();
    assert_eq!(content_types, ["application/vnd.custom+json"]);
}

#[tokio::test]
async fn raw_paths_cannot_escape_the_base_path() {
    let mock = Mock::start_at("/kibana/proxy/").await;
    let client = Kibana::new(Transport::single_node(&mock.url).unwrap());
    for path in [
        "../../api/security/role",
        "api/../../../api/security/role",
        "%2e%2e/%2E%2e/api/security/role",
        ".%2e/api/security/role",
        "api/%2e/status",
        "api/.\t./status",
        "api/\n",
    ] {
        let error = client
            .transport()
            .send::<()>(Method::GET, path, HeaderMap::new(), None, None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidRequest(_)),
            "{path:?}: {error:?}"
        );
    }
    assert_eq!(mock.request_count(), 0);

    mock.json(json!({}));
    client
        .transport()
        .send::<()>(
            Method::GET,
            "api/%252e%252e/x..y/.hidden",
            HeaderMap::new(),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    mock.take()
        .route("GET", "/kibana/proxy/api/%252e%252e/x..y/.hidden", &[]);
}

/// Answers one request with `head` and then closes the connection.
async fn truncated_server(head: &'static [u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        socket.write_all(head).await.unwrap();
    });
    url
}

#[tokio::test]
async fn interrupted_streams_keep_response_context_and_delivered_byte_counts() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for chunks in [vec![], vec![&b"stream-"[..], &b"body-secret"[..]]] {
        let expected_received: usize = chunks.iter().map(|chunk| chunk.len()).sum();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (proceed, mut delivered) = tokio::sync::mpsc::channel(1);
        let server_chunks = chunks.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 201 Created\r\nx-operation: header-secret\r\ncontent-length: 100\r\n\r\n")
                .await
                .unwrap();
            for chunk in server_chunks {
                socket.write_all(chunk).await.unwrap();
                delivered.recv().await.unwrap();
            }
        });

        let client = Kibana::new(transport(&url).response_limit(1).build().unwrap());
        let response = client
            .request(Method::GET, Scope::Global, &["api", "x"])
            .query(&[("token", "query-secret")])
            .send()
            .await
            .unwrap();
        let mut stream = std::pin::pin!(response.bytes_stream());
        let error = tokio::time::timeout(Duration::from_secs(5), async {
            for expected in chunks {
                let mut bytes = Vec::new();
                while bytes.len() < expected.len() {
                    bytes.extend_from_slice(&stream.try_next().await.unwrap().unwrap());
                }
                assert_eq!(bytes, expected);
                proceed.send(()).await.unwrap();
            }
            stream.try_next().await.unwrap_err()
        })
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(error.status(), Some(StatusCode::CREATED));
        assert_eq!(error.headers().unwrap()["x-operation"], "header-secret");
        assert!(error.transport().is_some());
        assert!(matches!(
            error,
            Error::Body { received, .. } if received == expected_received
        ));
        let mut chain = format!("{error} {error:?}");
        let mut source = std::error::Error::source(&error);
        while let Some(next) = source {
            chain.push_str(&format!(" {next} {next:?}"));
            source = next.source();
        }
        for secret in ["header-secret", "body-secret", "query-secret"] {
            assert!(!chain.contains(secret), "{chain}");
        }
    }
}

#[tokio::test]
async fn an_interrupted_success_body_keeps_status_and_headers() {
    let url = truncated_server(
        b"HTTP/1.1 201 Created\r\nx-operation: op-7\r\ncontent-length: 100\r\n\r\n{\"id\":",
    )
    .await;
    let client = Kibana::new(Transport::single_node(&url).unwrap());
    let error = client
        .request(Method::POST, Scope::Global, &["api", "x"])
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::CREATED));
    assert_eq!(error.headers().unwrap()["x-operation"], "op-7");
    assert!(error.transport().is_some());
    match &error {
        Error::Body { received, .. } => assert_eq!(*received, 6),
        other => panic!("expected a body error, got {other:?}"),
    }

    let mock = Mock::start().await;
    let limited = Kibana::new(transport(&mock.url).response_limit(4).build().unwrap());
    mock.reply_with(200, vec![("x-operation", "op-8".into())], "0123456789");
    let error = limited
        .status()
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap_err();
    assert_eq!(error.status(), Some(StatusCode::OK));
    assert_eq!(error.headers().unwrap()["x-operation"], "op-8");
}

#[tokio::test]
async fn decode_errors_and_response_debug_do_not_reveal_response_or_query_values() {
    let mock = Mock::start().await;
    let client = mock.client();
    mock.reply(200, r#""response-secret""#);
    let error = client
        .request(Method::GET, Scope::Global, &["api", "x"])
        .query(&[("token", "query-secret")])
        .send()
        .await
        .unwrap()
        .json_as::<Severity>()
        .await
        .unwrap_err();
    let mut chain = format!("{error} {error:?}");
    let mut source = std::error::Error::source(&error);
    while let Some(next) = source {
        chain.push_str(&format!(" {next} {next:?}"));
        source = next.source();
    }
    assert!(!chain.contains("response-secret"), "{chain}");
    assert!(chain.contains("line 1"), "{chain}");
    let Error::Decode { source, body, .. } = &error else {
        panic!("expected a decode error, got {error:?}")
    };
    assert!(
        source.inner().to_string().contains("response-secret"),
        "rich detail stays reachable"
    );
    assert!(body.contains("response-secret"));

    mock.json(json!({}));
    let response = client
        .request(Method::GET, Scope::Global, &["api", "x"])
        .query(&[("token", "query-secret")])
        .send()
        .await
        .unwrap();
    let debug = format!("{response:?}");
    assert!(
        debug.contains("/api/x") && !debug.contains("query-secret"),
        "{debug}"
    );
    assert!(
        response.url().as_str().contains("query-secret"),
        "url() is deliberate"
    );

    let builder = transport("http://user:url-secret@localhost/?token=query-secret");
    let debug = format!("{builder:?}");
    assert!(
        !debug.contains("url-secret") && !debug.contains("query-secret"),
        "{debug}"
    );
    assert!(builder.build().is_err());
}
