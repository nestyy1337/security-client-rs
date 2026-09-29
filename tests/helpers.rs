mod common;

use std::time::Duration;

use common::Mock;
use futures_util::TryStreamExt;
use kibana_rs::{
    pagination::Page,
    poll::{PollOptions, WaitOutcome},
};
use serde_json::{Value, json};

fn rule(id: usize) -> Value {
    json!({"id": format!("r{id}"), "rule_id": format!("rule-{id}"), "name": "n", "description": "d",
           "enabled": true, "severity": "low", "risk_score": 21, "type": "query"})
}

fn fast() -> PollOptions {
    PollOptions::new(Duration::from_millis(500)).interval(Duration::from_millis(10))
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[tokio::test]
async fn items_follow_pages_until_the_total_is_reached() {
    let mock = Mock::start().await;
    for (page, ids) in [(1, vec![0, 1]), (2, vec![2, 3]), (3, vec![4])] {
        let data: Vec<Value> = ids.into_iter().map(rule).collect();
        mock.json(json!({"data": data, "page": page, "perPage": 2, "total": 5}));
    }
    let client = mock.soc();
    let stream = client
        .security()
        .find_rules()
        .per_page(2)
        .filter("x: y")
        .page(9)
        .items();
    let rules: Vec<_> = assert_send(stream).try_collect().await.unwrap();
    let ids: Vec<_> = rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["r0", "r1", "r2", "r3", "r4"]);
    for page in ["1", "2", "3"] {
        mock.take().route(
            "GET",
            "/s/soc/api/detection_engine/rules/_find",
            &[("per_page", "2"), ("filter", "x: y"), ("page", page)],
        );
    }
    assert_eq!(
        mock.request_count(),
        0,
        "no request after the total is reached"
    );
}

#[tokio::test]
async fn pages_stop_at_an_empty_page_and_propagate_errors() {
    let mock = Mock::start().await;
    mock.json(json!({"items": [{"id": "a"}], "page": 1, "perPage": 1, "total": 9}));
    mock.json(json!({"items": [], "page": 2, "perPage": 1, "total": 9}));
    let pages: Vec<_> = mock
        .client()
        .fleet()
        .find_agents()
        .per_page(1)
        .pages()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].total(), 9);
    assert_eq!(pages[0].items()[0].id, "a");

    mock.json(json!({"cases": [], "page": 1, "per_page": 20, "total": 0}));
    let cases: Vec<_> = mock
        .client()
        .cases()
        .find()
        .items()
        .try_collect()
        .await
        .unwrap();
    assert!(cases.is_empty());

    mock.json(json!({"data": [{"id": "l", "list_id": "l", "name": "n", "description": "d",
                     "namespace_type": "single", "type": "detection"}], "page": 1, "per_page": 1, "total": 2}));
    mock.reply(500, "boom");
    let error = mock
        .client()
        .exceptions()
        .find_lists()
        .per_page(1)
        .items()
        .try_collect::<Vec<_>>()
        .await
        .unwrap_err();
    assert_eq!(error.status().unwrap().as_u16(), 500);
}

#[tokio::test]
async fn waiting_for_an_action_returns_its_final_state_or_the_last_seen_state() {
    let mock = Mock::start().await;
    let action = |status: &str, failed: u64| {
        json!({"actionId": "act", "type": "UPDATE_TAGS", "status": status, "nbAgentsActionCreated": 2,
               "nbAgentsAck": 2 - failed, "nbAgentsFailed": failed, "nbAgentsActioned": 2})
    };
    mock.json(json!({"items": []}));
    mock.json(json!({"items": [action("IN_PROGRESS", 0)]}));
    mock.json(json!({"items": [action("FAILED", 1)]}));
    let fleet = mock.client();
    let outcome = assert_send(fleet.fleet().wait_for_action("act", fast()))
        .await
        .unwrap();
    let WaitOutcome::Finished(done) = outcome else {
        panic!("expected a finished action")
    };
    assert_eq!((done.status.as_str(), done.nb_agents_failed), ("FAILED", 1));
    mock.take().route(
        "GET",
        "/api/fleet/agents/action_status",
        &[("page", "0"), ("perPage", "100")],
    );

    for _ in 0..100 {
        mock.json(json!({"items": [action("IN_PROGRESS", 0)]}));
    }
    let options = PollOptions::new(Duration::from_millis(60)).interval(Duration::from_millis(10));
    match fleet.fleet().wait_for_action("act", options).await.unwrap() {
        WaitOutcome::TimedOut { last: Some(last) } => assert_eq!(last.status, "IN_PROGRESS"),
        other => panic!("expected a timeout with the last state, got {other:?}"),
    }
    let empty = Mock::start().await;
    empty.json(json!({"items": []}));
    let outcome = empty
        .client()
        .fleet()
        .wait_for_action("act", PollOptions::new(Duration::ZERO))
        .await
        .unwrap();
    assert!(
        matches!(outcome, WaitOutcome::TimedOut { last: None }),
        "{outcome:?}"
    );
    assert!(outcome.finished().is_none());
}

#[tokio::test]
async fn waiting_for_uploads_and_policy_acknowledgment() {
    let mock = Mock::start().await;
    let client = mock.soc();
    mock.json(
        json!({"items": [{"id": "f", "name": "d.zip", "actionId": "other", "status": "READY"}]}),
    );
    mock.json(json!({"items": [{"id": "f", "name": "d.zip", "actionId": "diag", "status": "AWAITING_UPLOAD"}]}));
    mock.json(
        json!({"items": [{"id": "f", "name": "d.zip", "actionId": "diag", "status": "READY"}]}),
    );
    let upload = client
        .fleet()
        .wait_for_upload("agent", "diag", fast())
        .await
        .unwrap()
        .finished()
        .unwrap();
    assert_eq!(upload.status, "READY");
    mock.take()
        .route("GET", "/s/soc/api/fleet/agents/agent/uploads", &[]);

    let agent = |policy: &str, revision: u64, status: &str| json!({"item": {"id": "agent", "policy_id": policy, "policy_revision": revision, "status": status}});
    while mock.request_count() > 0 {
        mock.take();
    }
    mock.json(agent("old", 9, "online"));
    mock.json(agent("new", 1, "updating"));
    mock.json(agent("new", 2, "online"));
    let acknowledged = client
        .fleet()
        .wait_for_agent_policy("agent", "new", 2, fast())
        .await
        .unwrap()
        .finished()
        .unwrap();
    assert_eq!(acknowledged.policy_revision, Some(2));
    mock.take()
        .route("GET", "/s/soc/api/fleet/agents/agent", &[]);

    mock.reply(404, r#"{"message":"missing"}"#);
    let error = client
        .fleet()
        .wait_for_agent_policy("gone", "p", 1, fast())
        .await
        .unwrap_err();
    assert_eq!(
        error.status().unwrap().as_u16(),
        404,
        "request errors end the wait"
    );
}

#[tokio::test]
async fn waiting_for_an_action_expands_history_even_when_documents_are_deduplicated() {
    let mock = Mock::start().await;
    let action = |id: String| {
        json!({"actionId": id, "type": "UPDATE_TAGS", "status": "COMPLETE",
               "nbAgentsActionCreated": 1, "nbAgentsAck": 1, "nbAgentsFailed": 0,
               "nbAgentsActioned": 1})
    };
    mock.json(json!({"items": [action("new".into())]}));
    mock.json(json!({"items": [action("new".into())]}));
    mock.json(json!({"items": [action("new".into()), action("old".into())]}));

    let result = mock
        .client()
        .fleet()
        .wait_for_action("old", fast())
        .await
        .unwrap();
    assert_eq!(result.finished().unwrap().action_id, "old");
    for size in ["100", "1000", "10000"] {
        mock.take().route(
            "GET",
            "/api/fleet/agents/action_status",
            &[("page", "0"), ("perPage", size)],
        );
    }
    assert_eq!(mock.request_count(), 0);
}

#[tokio::test]
async fn configured_builders_can_be_reused() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let base = client.cases().find().owner("securitySolution").per_page(5);
    for page in [1, 2] {
        mock.json(json!({"cases": [], "page": page, "per_page": 5, "total": 0}));
        base.clone().page(page).send().await.unwrap();
    }
    for page in ["1", "2"] {
        mock.take().route(
            "GET",
            "/s/soc/api/cases/_find",
            &[
                ("owner", "securitySolution"),
                ("perPage", "5"),
                ("page", page),
            ],
        );
    }
    let import = client
        .security()
        .import_rules(b"{}\n".to_vec())
        .overwrite(true);
    for _ in 0..2 {
        mock.json(json!({"success": true, "success_count": 1, "errors": []}));
        import.clone().send().await.unwrap();
        assert_eq!(
            mock.take()
                .multipart_file("rules.ndjson", "application/x-ndjson"),
            "{}\n"
        );
    }
}

#[tokio::test]
async fn every_page_shape_streams_its_items() {
    let mock = Mock::start().await;
    let client = mock.soc();

    mock.json(
        json!({"comments": [{"id": "c1"}, {"id": "c2"}], "page": 1, "per_page": 2, "total": 3}),
    );
    mock.json(json!({"comments": [{"id": "c3"}], "page": 2, "per_page": 2, "total": 3}));
    let comments: Vec<_> = client
        .cases()
        .find_comments("case")
        .per_page(2)
        .items()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        comments
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["c1", "c2", "c3"]
    );
    for page in ["1", "2"] {
        mock.take().route(
            "GET",
            "/s/soc/api/cases/case/comments/_find",
            &[("perPage", "2"), ("page", page)],
        );
    }

    let policy = |id: &str| {
        json!({"id": id, "name": id, "namespace": "default", "revision": 1,
               "package": {"name": "system", "version": "1.0.0"}})
    };
    mock.json(json!({"items": [policy("p1")], "page": 1, "perPage": 1, "total": 2}));
    mock.json(json!({"items": [policy("p2")], "page": 2, "perPage": 1, "total": 2}));
    let policies: Vec<_> = client
        .fleet()
        .find_package_policies()
        .per_page(1)
        .items()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(
        policies.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        ["p1", "p2"]
    );
    for page in ["1", "2"] {
        mock.take().route(
            "GET",
            "/s/soc/api/fleet/package_policies",
            &[("perPage", "1"), ("page", page)],
        );
    }

    let item = json!({"id": "i1", "item_id": "i1", "list_id": "l", "name": "n", "description": "",
                      "namespace_type": "single", "entries": []});
    mock.json(json!({"data": [item], "page": 1, "per_page": 50, "total": 1}));
    let items: Vec<_> = client
        .exceptions()
        .find_items("l")
        .items()
        .try_collect()
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/items/_find",
        &[("list_id", "l"), ("page", "1")],
    );
    assert_eq!(
        mock.request_count(),
        0,
        "a complete first page ends the stream"
    );
}
