use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::any,
};
use kibana_rs::{Auth, Client, Error, Method, Scope};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

async fn mock(handler: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, handler).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test]
async fn routing_preserves_proxy_prefix_and_encodes_ids_without_scoping_global_calls() {
    let (url, task) = mock(Router::new().fallback(any(|req: Request| async move {
        axum::Json(
            json!({"uri":req.uri().to_string(), "xsrf":req.headers()["kbn-xsrf"].to_str().unwrap(),
            "auth":req.headers()["authorization"].to_str().unwrap()}),
        )
    })))
    .await;
    let client = Client::builder(format!("{url}/kibana/proxy/"))
        .auth(Auth::ApiKey("test-key".into()))
        .build()
        .unwrap()
        .space("soc")
        .unwrap();
    let result: Value = client
        .json(
            client
                .request(
                    Method::GET,
                    Scope::Space,
                    &["api", "things", "id/with?reserved#chars"],
                )
                .unwrap()
                .query(&[("filter", "name: a+b & c")]),
        )
        .await
        .unwrap();
    assert_eq!(
        result["uri"],
        "/kibana/proxy/s/soc/api/things/id%2Fwith%3Freserved%23chars?filter=name%3A+a%2Bb+%26+c"
    );
    assert_eq!(result["auth"], "ApiKey test-key");
    assert_eq!(result["xsrf"], "kibana-rs");
    let status = client.status().await.unwrap();
    assert_eq!(status["uri"], "/kibana/proxy/api/status");
    task.abort();
}

#[tokio::test]
async fn errors_keep_status_headers_and_bounded_non_json_body() {
    let (url, task) = mock(Router::new().fallback(any(|| async {
        Response::builder()
            .status(429)
            .header("retry-after", "3")
            .body(Body::from("x".repeat(20_000)))
            .unwrap()
    })))
    .await;
    let client = Client::builder(url).build().unwrap();
    let error = client.status().await.unwrap_err();
    match error {
        Error::Api {
            status,
            headers,
            body,
            truncated,
        } => {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(headers["retry-after"], "3");
            assert_eq!(body.len(), 16384);
            assert!(truncated);
        }
        other => panic!("wrong error: {other}"),
    }
    task.abort();
}

#[tokio::test]
async fn ambiguous_mutations_are_not_retried_and_redirects_are_not_followed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (url, task) = mock(
        Router::new()
            .fallback(any(
                |State(count): State<Arc<AtomicUsize>>, req: Request| async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    if req.uri().path() == "/api/redirect" {
                        Response::builder()
                            .status(307)
                            .header("location", "/api/write")
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(503)
                            .body(Body::from("uncertain write outcome"))
                            .unwrap()
                    }
                },
            ))
            .with_state(calls.clone()),
    )
    .await;
    let client = Client::builder(url).build().unwrap();
    for (path, status) in [("write", 503), ("redirect", 307)] {
        let error = client
            .execute(
                client
                    .request(Method::POST, Scope::Space, &["api", path])
                    .unwrap()
                    .json(&json!({})),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status().unwrap().as_u16(), status);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn response_limits_and_decode_errors_are_distinct() {
    let (url, task) =
        mock(Router::new().fallback(any(|| async { "<html>login required</html>" }))).await;
    let client = Client::builder(&url).build().unwrap();
    assert!(matches!(
        client.status().await.unwrap_err(),
        Error::Decode {
            status: StatusCode::OK,
            ..
        }
    ));
    let limited = Client::builder(&url).response_limit(8).build().unwrap();
    assert!(matches!(
        limited.status().await.unwrap_err(),
        Error::ResponseTooLarge { limit: 8 }
    ));
    task.abort();
}

#[test]
fn invalid_configuration_and_debug_do_not_leak_credentials() {
    for url in [
        "file:///tmp/test",
        "http://user:secret@localhost",
        "http://localhost?token=secret",
        "http://localhost/#fragment",
    ] {
        assert!(Client::builder(url).build().is_err());
    }
    let auth = Auth::Basic {
        username: "a".into(),
        password: "supersecret".into(),
    };
    assert!(!format!("{auth:?}").contains("supersecret"));
    let client = Client::builder("http://localhost")
        .auth(auth)
        .build()
        .unwrap();
    assert!(!format!("{client:?}").contains("supersecret"));
    assert!(client.space("../admin").is_err());
    assert!(
        client
            .request(Method::GET, Scope::Global, &["api", ".."])
            .is_err()
    );
}

#[tokio::test]
async fn request_timeout_is_a_transport_error() {
    let (url, task) = mock(Router::new().fallback(any(|| async {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        axum::Json(json!({"status": "late"}))
    })))
    .await;
    let client = Client::builder(url)
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();
    assert!(matches!(
        client.status().await.unwrap_err(),
        Error::Transport(error) if error.is_timeout()
    ));
    task.abort();
}
