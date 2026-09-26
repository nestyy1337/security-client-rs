use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    routing::any,
};
use kibana_rs::exceptions::{
    Entry, ListReference, NamespaceType, NestedEntry, Operator, ValueListReference,
};
use kibana_rs::fleet::{
    ActionOptions, AgentSelection, BulkActionResult, BulkAgents, TagUpdate, UpgradeAgent,
    UpgradeRollout,
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

#[test]
fn exception_entry_variants_match_the_public_wire_contract() {
    let entries = vec![
        Entry::Match {
            field: "host.name".into(),
            operator: Operator::Included,
            value: "scanner".into(),
        },
        Entry::MatchAny {
            field: "host.name".into(),
            operator: Operator::Excluded,
            value: vec!["one".into(), "two".into()],
        },
        Entry::Exists {
            field: "user.name".into(),
            operator: Operator::Included,
        },
        Entry::Wildcard {
            field: "process.executable".into(),
            operator: Operator::Included,
            value: "/opt/scanner/*".into(),
        },
        Entry::List {
            field: "source.ip".into(),
            operator: Operator::Included,
            list: ValueListReference {
                id: "scanner-ips".into(),
                list_type: "ip".into(),
            },
        },
        Entry::Nested {
            field: "process.Ext.code_signature".into(),
            entries: vec![NestedEntry::Match {
                field: "subject_name".into(),
                operator: Operator::Included,
                value: "Vendor".into(),
            }],
        },
    ];
    assert_eq!(
        serde_json::to_value(&entries).unwrap(),
        json!([
            {"type":"match","field":"host.name","operator":"included","value":"scanner"},
            {"type":"match_any","field":"host.name","operator":"excluded","value":["one","two"]},
            {"type":"exists","field":"user.name","operator":"included"},
            {"type":"wildcard","field":"process.executable","operator":"included","value":"/opt/scanner/*"},
            {"type":"list","field":"source.ip","operator":"included","list":{"id":"scanner-ips","type":"ip"}},
            {"type":"nested","field":"process.Ext.code_signature","entries":[{"type":"match","field":"subject_name","operator":"included","value":"Vendor"}]}
        ])
    );
}

#[tokio::test]
async fn exception_exports_encode_selectors_and_imports_preserve_partial_failures() {
    let (url, task) = mock(Router::new().fallback(any(|req: Request| async move {
        assert_eq!(req.method(), "POST");
        assert!(req.headers().contains_key("kbn-xsrf"));
        match req.uri().path() {
            "/proxy/s/soc/api/exception_lists/_export" => {
                let query: std::collections::HashMap<_, _> = url::form_urlencoded::parse(req.uri().query().unwrap().as_bytes()).into_owned().collect();
                assert_eq!(query["list_id"], "allowlist &/?");
                assert_eq!(query["id"], "saved-object-id");
                assert_eq!(query["namespace_type"], "agnostic");
                assert_eq!(query["include_expired_exceptions"], "false");
                Response::new(Body::from("{\"list_id\":\"exported\"}\n"))
            }
            "/proxy/s/soc/api/exception_lists/_import" => {
                assert_eq!(req.uri().query(), Some("overwrite=false&as_new_list=true"));
                assert!(req.headers()["content-type"].to_str().unwrap().starts_with("multipart/form-data; boundary="));
                let bytes = axum::body::to_bytes(req.into_body(), 8192).await.unwrap();
                let body = String::from_utf8(bytes.to_vec()).unwrap();
                assert!(body.contains("name=\"file\"; filename=\"exceptions.ndjson\""));
                assert!(body.contains("{\"list_id\":\"exported\"}\n"));
                Response::new(Body::from(json!({"success":false,"success_count":1,"errors":[{"error":{"status_code":409,"message":"conflict"}}],"success_count_exception_lists":1,"success_count_exception_list_items":0}).to_string()))
            }
            other => panic!("unexpected route {other}"),
        }
    }))).await;
    let client = Client::builder(format!("{url}/proxy"))
        .build()
        .unwrap()
        .space("soc")
        .unwrap();
    let export = client
        .exceptions()
        .export_list(
            &ListReference {
                id: "saved-object-id".into(),
                list_id: "allowlist &/?".into(),
                namespace_type: NamespaceType::Agnostic,
                list_type: "detection".into(),
            },
            false,
        )
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let result = client
        .exceptions()
        .import_lists(export.to_vec(), false, true)
        .await
        .unwrap();
    assert!(!result.success);
    assert_eq!(result.success_count, 1);
    assert_eq!(result.errors[0]["error"]["status_code"], 409);
    assert_eq!(result.extra["success_count_exception_list_items"], 0);
    task.abort();
}

#[tokio::test]
async fn fleet_bulk_requests_preserve_selection_options_and_response_variants() {
    let (url, task) = mock(Router::new().fallback(any(|req: Request| async move {
        assert_eq!(req.method(), "POST");
        let path = req.uri().path().to_owned();
        let bytes = axum::body::to_bytes(req.into_body(), 8192).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let result = match path.as_str() {
            "/s/soc/api/fleet/agents/bulk_upgrade" => {
                assert_eq!(body, json!({"agents":"tags:owned-fixture","dryRun":true,"batchSize":2,"version":"9.5.4","start_time":"2030-01-01T00:00:00Z","rollout_duration_seconds":600}));
                json!({"count":2})
            }
            "/s/soc/api/fleet/agents/bulk_update_agent_tags" => {
                assert_eq!(body, json!({"agents":["one","two"],"dryRun":false,"tagsToAdd":["investigate"],"tagsToRemove":["old"]}));
                json!({"actionId":"accepted-action"})
            }
            "/s/soc/api/fleet/agents/bulk_request_diagnostics" => {
                assert_eq!(body, json!({"agents":["one","two"],"dryRun":false}));
                json!({"actionId":"diagnostics-action"})
            }
            "/s/soc/api/fleet/agents/one/upgrade" => {
                assert_eq!(body, json!({"version":"9.5.4"}));
                json!({})
            }
            "/s/soc/api/fleet/agents/actions/upgrade%2Fid/cancel" => json!({"item":{"id":"cancel-id","type":"CANCEL","created_at":"2026-09-26T00:00:00Z"}}),
            other => panic!("unexpected route {other}"),
        };
        axum::Json(result)
    }))).await;
    let client = Client::builder(url).build().unwrap().space("soc").unwrap();
    let query = BulkAgents {
        agents: AgentSelection::Query("tags:owned-fixture".into()),
        dry_run: true,
        batch_size: Some(2),
    };
    let upgrade = UpgradeAgent::new("9.5.4");
    let result = client
        .fleet()
        .bulk_upgrade_agents(
            &query,
            &upgrade,
            &UpgradeRollout {
                start_time: Some("2030-01-01T00:00:00Z".into()),
                rollout_duration_seconds: Some(600),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(result, BulkActionResult::DryRun { count: 2 }));
    let ids = BulkAgents::new(AgentSelection::Ids(vec!["one".into(), "two".into()]));
    let result = client
        .fleet()
        .bulk_update_agent_tags(
            &ids,
            &TagUpdate {
                tags_to_add: vec!["investigate".into()],
                tags_to_remove: vec!["old".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        matches!(result, BulkActionResult::Action { action_id } if action_id == "accepted-action")
    );
    assert!(
        matches!(client.fleet().bulk_request_agent_diagnostics(&ids, &Default::default()).await.unwrap(), BulkActionResult::Action { action_id } if action_id == "diagnostics-action")
    );
    assert_eq!(
        client.fleet().upgrade_agent("one", &upgrade).await.unwrap(),
        json!({})
    );
    assert_eq!(
        client
            .fleet()
            .cancel_agent_action("upgrade/id")
            .await
            .unwrap()["item"]["id"],
        "cancel-id"
    );
    task.abort();
}

#[tokio::test]
async fn fleet_history_preserves_failures_and_downloads_are_binary() {
    let (url, task) = mock(Router::new().fallback(any(|req: Request| async move {
        assert_eq!(req.method(), "GET");
        match req.uri().path() {
            "/api/fleet/agents/action_status" => {
                assert_eq!(req.uri().query(), Some("page=0&perPage=20&errorSize=5"));
                Response::new(Body::from(json!({"items":[{"actionId":"mixed","type":"FUTURE_ACTION","status":"IN_PROGRESS","nbAgentsActionCreated":3,"nbAgentsAck":1,"nbAgentsFailed":1,"nbAgentsActioned":3,"latestErrors":[{"agentId":"failed-agent","error":"agent unavailable"}],"future_detail":"retained"}]}).to_string()))
            }
            "/api/fleet/enrollment_api_keys/key-id" => Response::new(Body::from(json!({"item":{"id":"key-id","api_key_id":"es-key-id","api_key":"do-not-log-this-key","active":true}}).to_string())),
            "/api/fleet/agents/files/file%2Fid/diagnostics%20file.zip" => Response::builder().header("content-type", "application/octet-stream").body(Body::from(vec![80,75,3,4,0,255])).unwrap(),
            other => panic!("unexpected route {other}"),
        }
    }))).await;
    let client = Client::builder(url).build().unwrap();
    let actions = client
        .fleet()
        .agent_actions(&ActionOptions::default())
        .await
        .unwrap();
    assert_eq!(actions.items[0].nb_agents_failed, 1);
    assert_eq!(actions.items[0].latest_errors[0]["agentId"], "failed-agent");
    assert_eq!(actions.items[0].extra["future_detail"], "retained");
    let key = client.fleet().enrollment_key("key-id").await.unwrap();
    assert_eq!(key.api_key, "do-not-log-this-key");
    assert!(!format!("{key:?}").contains(&key.api_key));
    assert_eq!(
        client
            .fleet()
            .download_agent_file("file/id", "diagnostics file.zip")
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .as_ref(),
        &[80, 75, 3, 4, 0, 255]
    );
    task.abort();
}
