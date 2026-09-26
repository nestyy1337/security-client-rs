//! Detection exception lists and items. `Single` is scoped to a Kibana space;
//! `Agnostic` lists are shared across spaces. Referenced value-list contents are
//! managed separately and are not included in exception exports.
use crate::{Client, Result, Scope};
use reqwest::{Method, Response, multipart};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceType {
    #[default]
    Single,
    Agnostic,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OsType {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListReference {
    pub id: String,
    pub list_id: String,
    pub namespace_type: NamespaceType,
    #[serde(rename = "type")]
    pub list_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExceptionList {
    pub id: String,
    pub list_id: String,
    pub name: String,
    pub description: String,
    pub namespace_type: NamespaceType,
    #[serde(rename = "type")]
    pub list_type: String,
    /// Opaque concurrency token, distinct from the user-defined `version`.
    #[serde(rename = "_version", default)]
    pub revision: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ExceptionList {
    pub fn reference(&self) -> ListReference {
        ListReference {
            id: self.id.clone(),
            list_id: self.list_id.clone(),
            namespace_type: self.namespace_type,
            list_type: self.list_type.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NewList {
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub list_type: String,
    pub namespace_type: NamespaceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_id: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub os_types: Vec<OsType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
}

impl NewList {
    pub fn detection(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            list_type: "detection".into(),
            namespace_type: NamespaceType::Single,
            list_id: None,
            tags: vec![],
            os_types: vec![],
            version: None,
            meta: None,
        }
    }
}

/// Replaces the list's editable fields. Supply the last read `_version`.
#[derive(Debug, Serialize)]
pub struct UpdateList<'a> {
    pub id: &'a str,
    #[serde(rename = "_version")]
    pub revision: &'a str,
    #[serde(flatten)]
    pub definition: &'a NewList,
}

#[derive(Clone, Copy, Debug)]
pub enum ListSelector<'a> {
    Id(&'a str),
    ListId(&'a str),
}

impl<'a> ListSelector<'a> {
    fn pair(self) -> (&'static str, &'a str) {
        match self {
            Self::Id(id) => ("id", id),
            Self::ListId(id) => ("list_id", id),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ItemSelector<'a> {
    Id(&'a str),
    ItemId(&'a str),
}

impl<'a> ItemSelector<'a> {
    fn pair(self) -> (&'static str, &'a str) {
        match self {
            Self::Id(id) => ("id", id),
            Self::ItemId(id) => ("item_id", id),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Included,
    Excluded,
}

/// Nested entries support match, match_any and exists, not recursive nesting.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NestedEntry {
    Match {
        field: String,
        operator: Operator,
        value: String,
    },
    MatchAny {
        field: String,
        operator: Operator,
        value: Vec<String>,
    },
    Exists {
        field: String,
        operator: Operator,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValueListReference {
    pub id: String,
    #[serde(rename = "type")]
    pub list_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Entry {
    Match {
        field: String,
        operator: Operator,
        value: String,
    },
    MatchAny {
        field: String,
        operator: Operator,
        value: Vec<String>,
    },
    Exists {
        field: String,
        operator: Operator,
    },
    Wildcard {
        field: String,
        operator: Operator,
        value: String,
    },
    List {
        field: String,
        operator: Operator,
        list: ValueListReference,
    },
    Nested {
        field: String,
        entries: Vec<NestedEntry>,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Comment {
    pub comment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NewItem {
    pub name: String,
    pub description: String,
    pub list_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(rename = "type")]
    item_type: &'static str,
    pub namespace_type: NamespaceType,
    pub entries: Vec<Entry>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub os_types: Vec<OsType>,
    pub comments: Vec<Comment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
}

impl NewItem {
    pub fn new(list: &ExceptionList, name: impl Into<String>, entries: Vec<Entry>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            list_id: list.list_id.clone(),
            item_id: None,
            item_type: "simple",
            namespace_type: list.namespace_type,
            entries,
            tags: vec![],
            os_types: vec![],
            comments: vec![],
            expire_time: None,
            meta: None,
        }
    }
}

/// Replaces the item's editable fields. Omitted fields may be reset by Kibana.
#[derive(Debug, Serialize)]
pub struct UpdateItem<'a> {
    pub id: &'a str,
    #[serde(rename = "_version")]
    pub revision: &'a str,
    #[serde(flatten)]
    pub definition: &'a NewItem,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExceptionItem {
    pub id: String,
    pub item_id: String,
    pub list_id: String,
    pub name: String,
    pub description: String,
    pub namespace_type: NamespaceType,
    #[serde(rename = "_version", default)]
    pub revision: Option<String>,
    /// JSON preserves entry variants added by newer deployments.
    pub entries: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindOptions {
    pub page: u32,
    pub per_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 50,
            filter: None,
            sort_field: None,
            sort_order: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExceptionPage<T> {
    pub data: Vec<T>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// HTTP 200 can contain failed list or item imports; inspect `success` and `errors`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImportResult {
    pub success: bool,
    pub success_count: u64,
    pub errors: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

pub struct Exceptions<'a>(pub(crate) &'a Client);

impl Exceptions<'_> {
    pub async fn create_list(&self, list: &NewList) -> Result<ExceptionList> {
        self.0
            .json(
                self.0
                    .request(Method::POST, Scope::Space, &["api", "exception_lists"])?
                    .json(list),
            )
            .await
    }

    pub async fn list(
        &self,
        selector: ListSelector<'_>,
        namespace: NamespaceType,
    ) -> Result<ExceptionList> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "exception_lists"])?
                    .query(&[selector.pair()])
                    .query(&[("namespace_type", namespace)]),
            )
            .await
    }

    pub async fn update_list(&self, list: &UpdateList<'_>) -> Result<ExceptionList> {
        self.0
            .json(
                self.0
                    .request(Method::PUT, Scope::Space, &["api", "exception_lists"])?
                    .json(list),
            )
            .await
    }

    /// Deletes the list and its items. Detach it from rules first.
    pub async fn delete_list(
        &self,
        selector: ListSelector<'_>,
        namespace: NamespaceType,
    ) -> Result<ExceptionList> {
        self.0
            .json(
                self.0
                    .request(Method::DELETE, Scope::Space, &["api", "exception_lists"])?
                    .query(&[selector.pair()])
                    .query(&[("namespace_type", namespace)]),
            )
            .await
    }

    pub async fn lists(
        &self,
        namespace: NamespaceType,
        options: &FindOptions,
    ) -> Result<ExceptionPage<ExceptionList>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "exception_lists", "_find"],
                    )?
                    .query(&[("namespace_type", namespace)])
                    .query(options),
            )
            .await
    }

    pub async fn create_item(&self, item: &NewItem) -> Result<ExceptionItem> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "exception_lists", "items"],
                    )?
                    .json(item),
            )
            .await
    }

    pub async fn item(
        &self,
        selector: ItemSelector<'_>,
        namespace: NamespaceType,
    ) -> Result<ExceptionItem> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "exception_lists", "items"],
                    )?
                    .query(&[selector.pair()])
                    .query(&[("namespace_type", namespace)]),
            )
            .await
    }

    pub async fn update_item(&self, item: &UpdateItem<'_>) -> Result<ExceptionItem> {
        self.0
            .json(
                self.0
                    .request(
                        Method::PUT,
                        Scope::Space,
                        &["api", "exception_lists", "items"],
                    )?
                    .json(item),
            )
            .await
    }

    pub async fn delete_item(
        &self,
        selector: ItemSelector<'_>,
        namespace: NamespaceType,
    ) -> Result<ExceptionItem> {
        self.0
            .json(
                self.0
                    .request(
                        Method::DELETE,
                        Scope::Space,
                        &["api", "exception_lists", "items"],
                    )?
                    .query(&[selector.pair()])
                    .query(&[("namespace_type", namespace)]),
            )
            .await
    }

    /// Retrieves one page for one list. The upstream multi-list search is not exposed.
    /// Kibana splits scalar list IDs and filters on commas after URL decoding;
    /// literal commas in these values are not supported by this method.
    pub async fn items(
        &self,
        list_id: &str,
        namespace: NamespaceType,
        options: &FindOptions,
    ) -> Result<ExceptionPage<ExceptionItem>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "exception_lists", "items", "_find"],
                    )?
                    .query(&[("list_id", list_id)])
                    .query(&[("namespace_type", namespace)])
                    .query(options),
            )
            .await
    }

    /// OS counts from Kibana. Lists with no OS-tagged items can report total=0;
    /// use `items().total` for the unfiltered item count.
    pub async fn summary(
        &self,
        selector: ListSelector<'_>,
        namespace: NamespaceType,
    ) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "exception_lists", "summary"],
                    )?
                    .query(&[selector.pair()])
                    .query(&[("namespace_type", namespace)]),
            )
            .await
    }

    pub async fn duplicate_list(
        &self,
        list_id: &str,
        namespace: NamespaceType,
        include_expired: bool,
    ) -> Result<ExceptionList> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "exception_lists", "_duplicate"],
                    )?
                    .query(&[("list_id", list_id)])
                    .query(&[("namespace_type", namespace)])
                    .query(&[("include_expired_exceptions", include_expired)]),
            )
            .await
    }

    pub async fn export_list(
        &self,
        list: &ListReference,
        include_expired: bool,
    ) -> Result<Response> {
        self.0
            .execute(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "exception_lists", "_export"],
                    )?
                    .query(&[("id", &list.id), ("list_id", &list.list_id)])
                    .query(&[("namespace_type", list.namespace_type)])
                    .query(&[("include_expired_exceptions", include_expired)]),
            )
            .await
    }

    pub async fn import_lists(
        &self,
        ndjson: Vec<u8>,
        overwrite: bool,
        as_new_list: bool,
    ) -> Result<ImportResult> {
        let file = multipart::Part::bytes(ndjson)
            .file_name("exceptions.ndjson")
            .mime_str("application/ndjson")?;
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "exception_lists", "_import"],
                    )?
                    .query(&[("overwrite", overwrite), ("as_new_list", as_new_list)])
                    .multipart(multipart::Form::new().part("file", file)),
            )
            .await
    }
}
