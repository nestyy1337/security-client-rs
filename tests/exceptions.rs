mod common;

use common::Mock;
use kibana_rs::{
    Error, SortOrder,
    exceptions::{
        Comment, Entry, ExceptionItem, ExceptionList, ItemSelector, ItemTarget, ListReference,
        ListSelector, ListTarget, NamespaceType, NestedEntry, NewItem, NewList, Operator, OsType,
        ValueListReference,
    },
};
use serde_json::{Map, Value, json};

fn list_json(id: &str) -> Value {
    json!({"id": id, "list_id": "scanners", "name": "Scanners", "description": "d",
           "namespace_type": "single", "type": "detection", "_version": "WzEsMV0=",
           "tags": [], "version": 1, "immutable": false})
}

fn item_json(id: &str) -> Value {
    json!({"id": id, "item_id": "scanner-1", "list_id": "scanners", "name": "Scanner",
           "description": "", "namespace_type": "single", "_version": "WzIsMV0=",
           "entries": [{"type": "future_type", "field": "x"}], "type": "simple"})
}

#[test]
fn entry_variants_match_the_public_wire_contract() {
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
            list: ValueListReference::new("scanner-ips", "ip"),
        },
        Entry::Nested {
            field: "process.Ext.code_signature".into(),
            entries: vec![
                NestedEntry::Match {
                    field: "subject_name".into(),
                    operator: Operator::Included,
                    value: "Vendor".into(),
                },
                NestedEntry::MatchAny {
                    field: "status".into(),
                    operator: Operator::Included,
                    value: vec!["trusted".into()],
                },
                NestedEntry::Exists {
                    field: "trusted".into(),
                    operator: Operator::Excluded,
                },
            ],
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
            {"type":"nested","field":"process.Ext.code_signature","entries":[
                {"type":"match","field":"subject_name","operator":"included","value":"Vendor"},
                {"type":"match_any","field":"status","operator":"included","value":["trusted"]},
                {"type":"exists","field":"trusted","operator":"excluded"}
            ]}
        ])
    );
}

#[tokio::test]
async fn lists_are_created_read_replaced_deleted_and_paged() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let definition = NewList::detection("Scanners", "Known scanners")
        .namespace_type(NamespaceType::Agnostic)
        .list_id("scanners")
        .tags(["network"])
        .os_types(vec![OsType::Linux, OsType::Windows])
        .version(2)
        .meta(Map::from_iter([("owner".into(), json!("soc"))]));
    let expected = json!({
        "name": "Scanners", "description": "Known scanners", "type": "detection",
        "namespace_type": "agnostic", "list_id": "scanners", "tags": ["network"],
        "os_types": ["linux", "windows"], "version": 2, "meta": {"owner": "soc"}
    });

    mock.json(list_json("so-1"));
    let list = client
        .exceptions()
        .create_list(&definition)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.revision.as_deref(), Some("WzEsMV0="));
    assert_eq!(list.extra["immutable"], false);
    let reference = list.reference();
    assert_eq!(
        (reference.id.as_str(), reference.list_id.as_str()),
        ("so-1", "scanners")
    );
    mock.take()
        .route("POST", "/s/soc/api/exception_lists", &[])
        .body(expected.clone());

    mock.json(json!({"id": "x", "list_id": "y", "name": "n", "description": "d", "namespace_type": "single", "type": "endpoint"}));
    client
        .exceptions()
        .create_list(&NewList::new("Endpoint", "d", "endpoint"))
        .send()
        .await
        .unwrap();
    mock.take().body(json!({"name": "Endpoint", "description": "d", "type": "endpoint", "namespace_type": "single", "tags": []}));

    mock.json(list_json("so-1"));
    client
        .exceptions()
        .get_list(ListSelector::ListId("scanners"))
        .namespace_type(NamespaceType::Agnostic)
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists",
        &[("list_id", "scanners"), ("namespace_type", "agnostic")],
    );

    mock.json(list_json("so-1"));
    client
        .exceptions()
        .update_list(&list.edit().name("Renamed").version(3))
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/exception_lists", &[])
        .body(json!({
            "id": "so-1", "_version": "WzEsMV0=", "namespace_type": "single", "type": "detection",
            "name": "Renamed", "description": "d", "tags": [], "os_types": [], "version": 3
        }));

    mock.json(list_json("so-1"));
    client
        .exceptions()
        .delete_list(ListSelector::Id("so-1"))
        .send()
        .await
        .unwrap();
    mock.take()
        .route("DELETE", "/s/soc/api/exception_lists", &[("id", "so-1")])
        .no_body();

    mock.json(json!({"data": [list_json("so-1")], "page": 1, "per_page": 1, "total": 4}));
    let page = client
        .exceptions()
        .find_lists()
        .namespace_type(NamespaceType::Single)
        .page(1)
        .per_page(1)
        .filter("exception-list.attributes.name: Scanners")
        .sort_field("name")
        .sort_order(SortOrder::Asc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!((page.total, page.data[0].id.as_str()), (4, "so-1"));
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/_find",
        &[
            ("namespace_type", "single"),
            ("page", "1"),
            ("per_page", "1"),
            ("filter", "exception-list.attributes.name: Scanners"),
            ("sort_field", "name"),
            ("sort_order", "asc"),
        ],
    );
}

#[tokio::test]
async fn items_are_created_read_replaced_deleted_searched_and_summarized() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let list: ExceptionList = serde_json::from_value(list_json("so-1")).unwrap();
    let definition = NewItem::new(
        &list,
        "Scanner",
        vec![Entry::Match {
            field: "host.name".into(),
            operator: Operator::Included,
            value: "scanner-1".into(),
        }],
    )
    .description("Known scanner")
    .item_id("scanner-1")
    .tags(["network"])
    .os_types(vec![OsType::Macos])
    .comments(vec![Comment::new("Approved by SOC")])
    .expire_time("2030-01-01T00:00:00Z")
    .meta(Map::new());
    let expected = json!({
        "name": "Scanner", "description": "Known scanner", "list_id": "scanners", "item_id": "scanner-1",
        "type": "simple", "namespace_type": "single",
        "entries": [{"type": "match", "field": "host.name", "operator": "included", "value": "scanner-1"}],
        "tags": ["network"], "os_types": ["macos"],
        "comments": [{"comment": "Approved by SOC"}],
        "expire_time": "2030-01-01T00:00:00Z", "meta": {}
    });

    mock.json(item_json("item-1"));
    let item = client
        .exceptions()
        .create_item(&definition)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(item.entries[0]["type"], "future_type");
    mock.take()
        .route("POST", "/s/soc/api/exception_lists/items", &[])
        .body(expected.clone());

    mock.json(item_json("item-1"));
    client
        .exceptions()
        .get_item(ItemSelector::ItemId("scanner-1"))
        .namespace_type(NamespaceType::Single)
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/items",
        &[("item_id", "scanner-1"), ("namespace_type", "single")],
    );

    mock.json(item_json("item-1"));
    client
        .exceptions()
        .update_item(&item.edit())
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/exception_lists/items", &[])
        .body(json!({
            "id": "item-1", "_version": "WzIsMV0=", "namespace_type": "single", "type": "simple",
            "name": "Scanner", "description": "", "entries": [{"type": "future_type", "field": "x"}],
            "tags": [], "os_types": [], "comments": []
        }));

    mock.json(item_json("item-1"));
    client
        .exceptions()
        .delete_item(ItemSelector::Id("item-1"))
        .namespace_type(NamespaceType::Agnostic)
        .send()
        .await
        .unwrap();
    mock.take().route(
        "DELETE",
        "/s/soc/api/exception_lists/items",
        &[("id", "item-1"), ("namespace_type", "agnostic")],
    );

    mock.json(
        json!({"data": [item_json("item-1")], "page": 2, "per_page": 1, "total": 2, "pit": "x"}),
    );
    let page = client
        .exceptions()
        .find_items("scanners")
        .namespace_type(NamespaceType::Single)
        .search("scanner")
        .filter("exception-list.attributes.name: Scanner")
        .page(2)
        .per_page(1)
        .sort_field("name")
        .sort_order(SortOrder::Desc)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(page.extra["pit"], "x");
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/items/_find",
        &[
            ("list_id", "scanners"),
            ("namespace_type", "single"),
            ("search", "scanner"),
            ("filter", "exception-list.attributes.name: Scanner"),
            ("page", "2"),
            ("per_page", "1"),
            ("sort_field", "name"),
            ("sort_order", "desc"),
        ],
    );

    mock.json(json!({"linux": 0, "macos": 1, "windows": 0, "total": 1}));
    let summary = client
        .exceptions()
        .summary(ListSelector::Id("so-1"))
        .namespace_type(NamespaceType::Single)
        .filter("exception-list.attributes.os_types: macos")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(summary["macos"], 1);
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/summary",
        &[
            ("id", "so-1"),
            ("namespace_type", "single"),
            ("filter", "exception-list.attributes.os_types: macos"),
        ],
    );
}

#[tokio::test]
async fn duplication_export_and_import_encode_required_selectors() {
    let mock = Mock::start_at("/proxy").await;
    let client = mock.soc();
    mock.json(list_json("copy"));
    client
        .exceptions()
        .duplicate_list("scanners", NamespaceType::Agnostic, true)
        .send()
        .await
        .unwrap();
    mock.take().route(
        "POST",
        "/proxy/s/soc/api/exception_lists/_duplicate",
        &[
            ("list_id", "scanners"),
            ("namespace_type", "agnostic"),
            ("include_expired_exceptions", "true"),
        ],
    );

    mock.reply(200, "{\"list_id\":\"exported\"}\n");
    let reference = ListReference::new(
        "saved-object-id",
        "allowlist &/?",
        NamespaceType::Agnostic,
        "detection",
    );
    let export = client
        .exceptions()
        .export_list(&reference, false)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    mock.take().route(
        "POST",
        "/proxy/s/soc/api/exception_lists/_export",
        &[
            ("id", "saved-object-id"),
            ("list_id", "allowlist &/?"),
            ("namespace_type", "agnostic"),
            ("include_expired_exceptions", "false"),
        ],
    );

    mock.json(json!({"success": false, "success_count": 1, "errors": [{"error": {"status_code": 409, "message": "conflict"}}],
                     "success_count_exception_lists": 1, "success_count_exception_list_items": 0}));
    let result = client
        .exceptions()
        .import_lists(export.to_vec())
        .overwrite(false)
        .as_new_list(true)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!result.success);
    assert_eq!(result.success_count, 1);
    assert_eq!(result.errors[0]["error"]["status_code"], 409);
    assert_eq!(result.extra["success_count_exception_list_items"], 0);
    let request = mock.take();
    request.route(
        "POST",
        "/proxy/s/soc/api/exception_lists/_import",
        &[("overwrite", "false"), ("as_new_list", "true")],
    );
    assert_eq!(
        request.multipart_file("exceptions.ndjson", "application/ndjson"),
        "{\"list_id\":\"exported\"}\n"
    );
}

fn populated_item() -> ExceptionItem {
    serde_json::from_value(json!({
        "id": "item-1", "item_id": "scanner-1", "list_id": "scanners", "name": "Scanner",
        "description": "Known scanner", "namespace_type": "agnostic", "_version": "WzUsMV0=",
        "type": "simple", "tags": ["network"], "os_types": ["windows"],
        "entries": [{"type": "future_type", "field": "x"},
                    {"type": "match", "field": "host.name", "operator": "included", "value": "scanner-1"}],
        "comments": [{"id": "c-1", "comment": "Approved by SOC", "created_at": "2026-09-01T00:00:00Z",
                      "created_by": "analyst"}],
        "expire_time": "2030-01-01T00:00:00.000Z", "meta": {"ticket": "SOC-1"},
        "created_at": "2026-09-01T00:00:00Z", "tie_breaker_id": "t"
    }))
    .unwrap()
}

#[tokio::test]
async fn edits_keep_retrieved_state_and_send_only_new_comments() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let item = populated_item();
    assert_eq!(item.comments[0].created_by.as_deref(), Some("analyst"));

    mock.json(item_json("item-1"));
    client
        .exceptions()
        .update_item(
            &item
                .edit()
                .name("Renamed scanner")
                .add_comment("Re-reviewed"),
        )
        .send()
        .await
        .unwrap();
    mock.take()
        .route("PUT", "/s/soc/api/exception_lists/items", &[])
        .body(json!({
            "id": "item-1", "_version": "WzUsMV0=", "namespace_type": "agnostic", "type": "simple",
            "name": "Renamed scanner", "description": "Known scanner", "tags": ["network"],
            "os_types": ["windows"],
            "entries": [{"type": "future_type", "field": "x"},
                        {"type": "match", "field": "host.name", "operator": "included", "value": "scanner-1"}],
            "comments": [{"comment": "Re-reviewed"}],
            "expire_time": "2030-01-01T00:00:00.000Z", "meta": {"ticket": "SOC-1"}
        }));

    let replaced = item
        .edit()
        .description("")
        .tags(Vec::<String>::new())
        .os_types(vec![])
        .entries(vec![Entry::Exists {
            field: "user.name".into(),
            operator: Operator::Included,
        }])
        .expire_time("2031-01-01T00:00:00Z")
        .meta(Map::new());
    mock.json(item_json("item-1"));
    client
        .exceptions()
        .update_item(&replaced)
        .send()
        .await
        .unwrap();
    let body = mock.take().json();
    assert_eq!(
        body["entries"],
        json!([{"type": "exists", "field": "user.name", "operator": "included"}])
    );
    assert_eq!(
        (body["tags"].clone(), body["os_types"].clone()),
        (json!([]), json!([]))
    );
    assert_eq!(
        body["comments"],
        json!([]),
        "existing comments are never resent"
    );
    assert_eq!(body["expire_time"], "2031-01-01T00:00:00Z");

    let list: ExceptionList = serde_json::from_value(json!({
        "id": "so-1", "list_id": "scanners", "name": "Scanners", "description": "d",
        "namespace_type": "agnostic", "type": "endpoint", "_version": "WzEsMV0=",
        "tags": ["network"], "os_types": ["linux"], "meta": {"owner": "soc"}, "version": 4
    }))
    .unwrap();
    mock.json(list_json("so-1"));
    client
        .exceptions()
        .update_list(&list.edit().description("Updated"))
        .send()
        .await
        .unwrap();
    mock.take().body(json!({
        "id": "so-1", "_version": "WzEsMV0=", "namespace_type": "agnostic", "type": "endpoint",
        "name": "Scanners", "description": "Updated", "tags": ["network"], "os_types": ["linux"],
        "meta": {"owner": "soc"}
    }));
}

#[tokio::test]
async fn retrieved_resources_select_their_own_namespace() {
    let mock = Mock::start().await;
    let client = mock.soc();
    let item = populated_item();
    let list: ExceptionList = serde_json::from_value(json!({
        "id": "so-1", "list_id": "scanners", "name": "Scanners", "description": "d",
        "namespace_type": "agnostic", "type": "detection"
    }))
    .unwrap();

    mock.json(item_json("item-1"));
    client.exceptions().get_item(&item).send().await.unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/items",
        &[("id", "item-1"), ("namespace_type", "agnostic")],
    );
    mock.json(item_json("item-1"));
    client
        .exceptions()
        .delete_item(ItemTarget::new(
            ItemSelector::ItemId("scanner-1"),
            NamespaceType::Agnostic,
        ))
        .send()
        .await
        .unwrap();
    mock.take().route(
        "DELETE",
        "/s/soc/api/exception_lists/items",
        &[("item_id", "scanner-1"), ("namespace_type", "agnostic")],
    );

    mock.json(list_json("so-1"));
    client.exceptions().delete_list(&list).send().await.unwrap();
    mock.take().route(
        "DELETE",
        "/s/soc/api/exception_lists",
        &[("id", "so-1"), ("namespace_type", "agnostic")],
    );
    mock.json(json!({"total": 0}));
    client
        .exceptions()
        .summary(&list.reference())
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/summary",
        &[("id", "so-1"), ("namespace_type", "agnostic")],
    );
    mock.json(json!({"total": 0}));
    client
        .exceptions()
        .get_list(ListTarget::new(
            ListSelector::ListId("scanners"),
            NamespaceType::Single,
        ))
        .send()
        .await
        .unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists",
        &[("list_id", "scanners"), ("namespace_type", "single")],
    );
    mock.json(json!({"data": [], "page": 1, "per_page": 20, "total": 0}));
    client.exceptions().find_items(&list).send().await.unwrap();
    mock.take().route(
        "GET",
        "/s/soc/api/exception_lists/items/_find",
        &[("list_id", "scanners"), ("namespace_type", "agnostic")],
    );

    for error in [
        client
            .exceptions()
            .get_list(ListSelector::Id(""))
            .send()
            .await
            .unwrap_err(),
        client
            .exceptions()
            .delete_item(ItemSelector::ItemId(""))
            .send()
            .await
            .unwrap_err(),
        client.exceptions().find_items("").send().await.unwrap_err(),
    ] {
        assert!(matches!(error, Error::InvalidRequest(_)), "{error:?}");
    }
    assert_eq!(mock.request_count(), 0);
}
