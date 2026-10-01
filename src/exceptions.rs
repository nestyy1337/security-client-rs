//! Detection exception lists and items. `Single` lists are scoped to a Kibana
//! space; `Agnostic` lists are shared across spaces. Referenced value-list
//! contents are managed separately and are not included in exception exports.
//!
//! Create lists and items from [`NewList`] and [`NewItem`]. Change existing ones
//! through [`ExceptionList::edit`] and [`ExceptionItem::edit`], which start from
//! the retrieved state, so fields that are not changed are sent back as they were.
//! Retrieved resources also carry their namespace: pass them to `get_*`,
//! `delete_*` and `find_items` instead of repeating a selector and namespace.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    Kibana, Request, Scope, SortOrder,
    http::{Method, Raw},
    pagination::paginated,
    request::endpoint,
};

/// Whether an exception list or item belongs to one space or is shared across spaces.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceType {
    #[default]
    Single,
    Agnostic,
}

impl NamespaceType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Agnostic => "agnostic",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OsType {
    Linux,
    Macos,
    Windows,
}

/// Identifies a list for rule associations and exports.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ListReference {
    pub id: String,
    pub list_id: String,
    pub namespace_type: NamespaceType,
    #[serde(rename = "type")]
    pub list_type: String,
}

impl ListReference {
    pub fn new(
        id: impl Into<String>,
        list_id: impl Into<String>,
        namespace_type: NamespaceType,
        list_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            list_id: list_id.into(),
            namespace_type,
            list_type: list_type.into(),
        }
    }
}

/// A retrieved exception list. Use [`Self::edit`] to retain its writable fields on update.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ExceptionList {
    /// Kibana saved-object ID, distinct from the portable [`list_id`](Self::list_id).
    pub id: String,
    /// Stable list identifier used in rule associations and item membership.
    pub list_id: String,
    pub name: String,
    pub description: String,
    pub namespace_type: NamespaceType,
    #[serde(rename = "type")]
    pub list_type: String,
    /// Opaque concurrency token, distinct from the user-defined `version`.
    #[serde(rename = "_version", default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub os_types: Vec<OsType>,
    #[serde(default)]
    pub meta: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ExceptionList {
    pub fn reference(&self) -> ListReference {
        ListReference::new(
            &self.id,
            &self.list_id,
            self.namespace_type,
            &self.list_type,
        )
    }

    /// A replacement for this list that keeps its current editable fields until
    /// changed, bound to its ID, namespace and concurrency token.
    /// Sending the edit fails locally if the retrieved token is missing or empty.
    ///
    /// ```no_run
    /// use kibana_rs::exceptions::ListSelector;
    ///
    /// # async fn rename(client: &kibana_rs::Kibana) -> kibana_rs::Result<()> {
    /// let exceptions = client.exceptions();
    /// let list = exceptions.get_list(ListSelector::Id("list-id")).send().await?.json().await?;
    /// let edit = list.edit().name("Renamed list");
    /// exceptions.update_list(&edit).send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn edit(&self) -> ListEdit {
        ListEdit {
            id: self.id.clone(),
            revision: self.revision.clone(),
            namespace_type: self.namespace_type,
            list_type: self.list_type.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            tags: self.tags.clone(),
            os_types: self.os_types.clone(),
            meta: self.meta.clone(),
            version: None,
        }
    }
}

/// A list definition for [`Exceptions::create_list`]. To change an existing
/// list, use [`ExceptionList::edit`].
#[derive(Clone, Debug, Serialize)]
pub struct NewList {
    name: String,
    description: String,
    #[serde(rename = "type")]
    list_type: String,
    namespace_type: NamespaceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    list_id: Option<String>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    os_types: Vec<OsType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Map<String, Value>>,
}

impl NewList {
    /// `list_type` is `detection`, `rule_default` or an Endpoint artifact type.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        list_type: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            list_type: list_type.into(),
            namespace_type: NamespaceType::Single,
            list_id: None,
            tags: Vec::new(),
            os_types: Vec::new(),
            version: None,
            meta: None,
        }
    }

    /// A shared detection list in the current space.
    pub fn detection(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(name, description, "detection")
    }

    pub fn namespace_type(mut self, namespace: NamespaceType) -> Self {
        self.namespace_type = namespace;
        self
    }

    /// A stable human-readable identifier, generated by Kibana when omitted.
    pub fn list_id(mut self, list_id: impl Into<String>) -> Self {
        self.list_id = Some(list_id.into());
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn os_types(mut self, os_types: Vec<OsType>) -> Self {
        self.os_types = os_types;
        self
    }

    /// A user-defined version number, unrelated to the concurrency token.
    pub fn version(mut self, version: u64) -> Self {
        self.version = Some(version);
        self
    }

    pub fn meta(mut self, meta: Map<String, Value>) -> Self {
        self.meta = Some(meta);
        self
    }
}

/// Changes to an existing list for [`Exceptions::update_list`], created by
/// [`ExceptionList::edit`].
///
/// The edit keeps the retrieved writable fields, so changing the name also
/// retains tags and metadata. A list changed since then fails with HTTP 409;
/// read it again and reapply the change rather than retrying the same edit.
#[derive(Clone, Debug, Serialize)]
pub struct ListEdit {
    id: String,
    #[serde(rename = "_version", skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    namespace_type: NamespaceType,
    #[serde(rename = "type")]
    list_type: String,
    name: String,
    description: String,
    tags: Vec<String>,
    os_types: Vec<OsType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
}

impl ListEdit {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn os_types(mut self, os_types: Vec<OsType>) -> Self {
        self.os_types = os_types;
        self
    }

    pub fn meta(mut self, meta: Map<String, Value>) -> Self {
        self.meta = Some(meta);
        self
    }

    /// A user-defined version number. Kibana increments it when unset.
    pub fn version(mut self, version: u64) -> Self {
        self.version = Some(version);
        self
    }
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

/// A list to read, delete or summarize.
///
/// A bare [`ListSelector`] uses the server's default namespace unless the
/// builder's `namespace_type` is set. A retrieved [`ExceptionList`] or a
/// [`ListReference`] also selects its own namespace.
#[derive(Clone, Copy, Debug)]
pub struct ListTarget<'a> {
    selector: ListSelector<'a>,
    namespace: Option<NamespaceType>,
}

impl<'a> ListTarget<'a> {
    pub fn new(selector: ListSelector<'a>, namespace: NamespaceType) -> Self {
        Self {
            selector,
            namespace: Some(namespace),
        }
    }

    fn apply(self, request: Request<'_>) -> Request<'_> {
        let request = request.selector(self.selector.pair());
        match self.namespace {
            Some(namespace) => request.param("namespace_type", namespace.as_str()),
            None => request,
        }
    }
}

impl<'a> From<ListSelector<'a>> for ListTarget<'a> {
    fn from(selector: ListSelector<'a>) -> Self {
        Self {
            selector,
            namespace: None,
        }
    }
}

impl<'a> From<&'a ExceptionList> for ListTarget<'a> {
    fn from(list: &'a ExceptionList) -> Self {
        Self::new(ListSelector::Id(&list.id), list.namespace_type)
    }
}

impl<'a> From<&'a ListReference> for ListTarget<'a> {
    fn from(list: &'a ListReference) -> Self {
        Self::new(ListSelector::Id(&list.id), list.namespace_type)
    }
}

/// The list whose items [`Exceptions::find_items`] searches: a `list_id`, or a
/// retrieved [`ExceptionList`], which also selects its namespace.
#[derive(Clone, Copy, Debug)]
pub struct ItemsOf<'a> {
    list_id: &'a str,
    namespace: Option<NamespaceType>,
}

impl<'a> From<&'a str> for ItemsOf<'a> {
    fn from(list_id: &'a str) -> Self {
        Self {
            list_id,
            namespace: None,
        }
    }
}

impl<'a> From<&'a String> for ItemsOf<'a> {
    fn from(list_id: &'a String) -> Self {
        list_id.as_str().into()
    }
}

impl<'a> From<&'a ExceptionList> for ItemsOf<'a> {
    fn from(list: &'a ExceptionList) -> Self {
        Self {
            list_id: &list.list_id,
            namespace: Some(list.namespace_type),
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

/// An item to read or delete. See [`ListTarget`] for how the namespace is chosen.
#[derive(Clone, Copy, Debug)]
pub struct ItemTarget<'a> {
    selector: ItemSelector<'a>,
    namespace: Option<NamespaceType>,
}

impl<'a> ItemTarget<'a> {
    pub fn new(selector: ItemSelector<'a>, namespace: NamespaceType) -> Self {
        Self {
            selector,
            namespace: Some(namespace),
        }
    }

    fn apply(self, request: Request<'_>) -> Request<'_> {
        let request = request.selector(self.selector.pair());
        match self.namespace {
            Some(namespace) => request.param("namespace_type", namespace.as_str()),
            None => request,
        }
    }
}

impl<'a> From<ItemSelector<'a>> for ItemTarget<'a> {
    fn from(selector: ItemSelector<'a>) -> Self {
        Self {
            selector,
            namespace: None,
        }
    }
}

impl<'a> From<&'a ExceptionItem> for ItemTarget<'a> {
    fn from(item: &'a ExceptionItem) -> Self {
        Self::new(ItemSelector::Id(&item.id), item.namespace_type)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Included,
    Excluded,
}

/// Conditions inside [`Entry::Nested`]. Nesting is one level deep.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
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

/// A value list referenced by [`Entry::List`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ValueListReference {
    pub id: String,
    /// The value type, such as `ip`, `keyword` or `text`.
    #[serde(rename = "type")]
    pub list_type: String,
}

impl ValueListReference {
    pub fn new(id: impl Into<String>, list_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            list_type: list_type.into(),
        }
    }
}

/// One condition in an exception item. The item's entries are combined with AND.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
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

/// A new comment. Kibana records its author and time.
#[derive(Clone, Debug, Serialize)]
pub struct Comment {
    comment: String,
}

impl Comment {
    pub fn new(comment: impl Into<String>) -> Self {
        Self {
            comment: comment.into(),
        }
    }
}

/// A comment stored on an item.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ItemComment {
    pub id: String,
    pub comment: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An item definition for [`Exceptions::create_item`]. To change an existing
/// item, use [`ExceptionItem::edit`].
#[derive(Clone, Debug, Serialize)]
pub struct NewItem {
    name: String,
    description: String,
    list_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    item_id: Option<String>,
    #[serde(rename = "type")]
    item_type: &'static str,
    namespace_type: NamespaceType,
    entries: Vec<Entry>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    os_types: Vec<OsType>,
    comments: Vec<Comment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Map<String, Value>>,
}

impl NewItem {
    /// An item in `list`. Its entries are combined with AND.
    pub fn new(list: &ExceptionList, name: impl Into<String>, entries: Vec<Entry>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            list_id: list.list_id.clone(),
            item_id: None,
            item_type: "simple",
            namespace_type: list.namespace_type,
            entries,
            tags: Vec::new(),
            os_types: Vec::new(),
            comments: Vec::new(),
            expire_time: None,
            meta: None,
        }
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// A stable human-readable identifier, generated by Kibana when omitted.
    pub fn item_id(mut self, item_id: impl Into<String>) -> Self {
        self.item_id = Some(item_id.into());
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn os_types(mut self, os_types: Vec<OsType>) -> Self {
        self.os_types = os_types;
        self
    }

    pub fn comments(mut self, comments: Vec<Comment>) -> Self {
        self.comments = comments;
        self
    }

    /// An ISO 8601 time after which the item no longer applies.
    pub fn expire_time(mut self, time: impl Into<String>) -> Self {
        self.expire_time = Some(time.into());
        self
    }

    pub fn meta(mut self, meta: Map<String, Value>) -> Self {
        self.meta = Some(meta);
        self
    }
}

/// A retrieved exception item and its current entries and comments.
/// Use [`Self::edit`] to change it without dropping unchanged writable fields.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ExceptionItem {
    /// Kibana saved-object ID, distinct from [`item_id`](Self::item_id).
    pub id: String,
    /// Stable item identifier, retained across exports and imports.
    pub item_id: String,
    pub list_id: String,
    pub name: String,
    pub description: String,
    pub namespace_type: NamespaceType,
    /// Opaque concurrency token, sent by [`ExceptionItem::edit`].
    #[serde(rename = "_version", default)]
    pub revision: Option<String>,
    #[serde(rename = "type", default = "simple")]
    pub item_type: String,
    /// JSON preserves entry variants added by newer deployments.
    pub entries: Vec<Value>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub os_types: Vec<OsType>,
    #[serde(default)]
    pub comments: Vec<ItemComment>,
    #[serde(default)]
    pub expire_time: Option<String>,
    #[serde(default)]
    pub meta: Option<Map<String, Value>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn simple() -> String {
    "simple".into()
}

impl ExceptionItem {
    /// A replacement for this item that keeps its current editable fields,
    /// including entries of types this client does not model, until changed.
    /// It is bound to the item's ID, namespace and concurrency token.
    /// Sending the edit fails locally if the retrieved token is missing or empty.
    /// Existing comments stay on the server; only newly added comments are sent.
    ///
    /// ```
    /// use kibana_rs::exceptions::ExceptionItem;
    /// use serde_json::{from_value, json, to_value};
    ///
    /// let item: ExceptionItem = from_value(json!({
    ///     "id": "item-a", "item_id": "scanner", "list_id": "allowlist",
    ///     "name": "Scanner", "description": "Known host", "namespace_type": "single",
    ///     "_version": "opaque-token", "entries": [], "tags": ["reviewed"],
    ///     "comments": [{"id": "comment-a", "comment": "Already reviewed"}]
    /// }))?;
    /// let body = to_value(item.edit().name("Approved scanner").add_comment("Checked again"))?;
    /// assert_eq!(body["_version"], "opaque-token");
    /// assert_eq!(body["tags"], json!(["reviewed"]));
    /// assert_eq!(body["comments"], json!([{"comment": "Checked again"}]));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn edit(&self) -> ItemEdit {
        ItemEdit {
            id: self.id.clone(),
            revision: self.revision.clone(),
            namespace_type: self.namespace_type,
            item_type: self.item_type.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            entries: self.entries.clone(),
            tags: self.tags.clone(),
            os_types: self.os_types.clone(),
            comments: Vec::new(),
            expire_time: self.expire_time.clone(),
            meta: self.meta.clone(),
        }
    }
}

/// Changes to an existing item for [`Exceptions::update_item`], created by
/// [`ExceptionItem::edit`].
///
/// Kibana overwrites the item, so the edit starts from its writable fields as
/// they were read. Comments are append-only: existing comments are always kept,
/// and only comments added with [`add_comment`](Self::add_comment) are sent. An item
/// changed since it was read fails with HTTP 409; read it again and reapply the
/// change rather than retrying the same edit.
#[derive(Clone, Debug, Serialize)]
pub struct ItemEdit {
    id: String,
    #[serde(rename = "_version", skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    namespace_type: NamespaceType,
    #[serde(rename = "type")]
    item_type: String,
    name: String,
    description: String,
    entries: Vec<Value>,
    tags: Vec<String>,
    os_types: Vec<OsType>,
    comments: Vec<Comment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expire_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Map<String, Value>>,
}

impl ItemEdit {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Replaces every entry. Entries are combined with AND.
    pub fn entries(mut self, entries: impl IntoIterator<Item = Entry>) -> Self {
        self.entries = entries
            .into_iter()
            .map(|entry| serde_json::to_value(&entry).expect("entries serialize as JSON"))
            .collect();
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    pub fn os_types(mut self, os_types: Vec<OsType>) -> Self {
        self.os_types = os_types;
        self
    }

    /// Appends a comment to the item's existing comments.
    pub fn add_comment(mut self, comment: impl Into<String>) -> Self {
        self.comments.push(Comment::new(comment));
        self
    }

    /// An ISO 8601 time after which the item no longer applies.
    pub fn expire_time(mut self, time: impl Into<String>) -> Self {
        self.expire_time = Some(time.into());
        self
    }

    pub fn meta(mut self, meta: Map<String, Value>) -> Self {
        self.meta = Some(meta);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ImportResult {
    pub success: bool,
    pub success_count: u64,
    pub errors: Vec<crate::ImportFailure>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct Exceptions<'a>(pub(crate) &'a Kibana);

impl<'a> Exceptions<'a> {
    /// Creates a list from a [`NewList`] or equivalent JSON.
    pub fn create_list<B: Serialize + ?Sized>(&self, list: &B) -> CreateList<'a> {
        CreateList(
            self.0
                .request(Method::POST, Scope::Space, &["api", "exception_lists"])
                .json(list),
        )
    }

    /// Reads a list by [`ListSelector`] or from a retrieved [`ExceptionList`].
    pub fn get_list<'l>(&self, list: impl Into<ListTarget<'l>>) -> GetList<'a> {
        GetList(
            list.into().apply(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "exception_lists"],
            )),
        )
    }

    /// Replaces the editable fields of the list the edit was created from. A
    /// list changed since it was read fails with HTTP 409. A missing or empty
    /// concurrency token fails locally with [`crate::Error::InvalidRequest`].
    pub fn update_list(&self, list: &ListEdit) -> UpdateList<'a> {
        UpdateList(
            self.0
                .request(Method::PUT, Scope::Space, &["api", "exception_lists"])
                .nonempty("_version", list.revision.as_deref().unwrap_or_default())
                .json(list),
        )
    }

    /// Deletes the list and its items. Detach it from rules first.
    pub fn delete_list<'l>(&self, list: impl Into<ListTarget<'l>>) -> DeleteList<'a> {
        DeleteList(list.into().apply(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "exception_lists"],
        )))
    }

    pub fn find_lists(&self) -> FindLists<'a> {
        FindLists(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "exception_lists", "_find"],
        ))
    }

    /// Creates an item from a [`NewItem`] or equivalent JSON.
    pub fn create_item<B: Serialize + ?Sized>(&self, item: &B) -> CreateItem<'a> {
        CreateItem(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "exception_lists", "items"],
                )
                .json(item),
        )
    }

    /// Reads an item by [`ItemSelector`] or from a retrieved [`ExceptionItem`].
    pub fn get_item<'i>(&self, item: impl Into<ItemTarget<'i>>) -> GetItem<'a> {
        GetItem(item.into().apply(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "exception_lists", "items"],
        )))
    }

    /// Replaces the editable fields of the item the edit was created from and
    /// appends its new comments. An item changed since it was read fails with HTTP 409.
    /// A missing or empty concurrency token fails locally with [`crate::Error::InvalidRequest`].
    pub fn update_item(&self, item: &ItemEdit) -> UpdateItem<'a> {
        UpdateItem(
            self.0
                .request(
                    Method::PUT,
                    Scope::Space,
                    &["api", "exception_lists", "items"],
                )
                .nonempty("_version", item.revision.as_deref().unwrap_or_default())
                .json(item),
        )
    }

    pub fn delete_item<'i>(&self, item: impl Into<ItemTarget<'i>>) -> DeleteItem<'a> {
        DeleteItem(item.into().apply(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "exception_lists", "items"],
        )))
    }

    /// One page of items from one list, given by `list_id` or as a retrieved
    /// [`ExceptionList`], which also selects its namespace.
    ///
    /// Kibana splits list IDs and filters on commas after URL decoding, so
    /// literal commas in these values are not supported.
    pub fn find_items<'l>(&self, list: impl Into<ItemsOf<'l>>) -> FindItems<'a> {
        let list = list.into();
        let request = self
            .0
            .request(
                Method::GET,
                Scope::Space,
                &["api", "exception_lists", "items", "_find"],
            )
            .selector(("list_id", list.list_id));
        FindItems(match list.namespace {
            Some(namespace) => request.param("namespace_type", namespace.as_str()),
            None => request,
        })
    }

    /// Item counts per operating system. Lists without OS-tagged items can report
    /// `total: 0`; use [`find_items`](Self::find_items) for the item count.
    pub fn summary<'l>(&self, list: impl Into<ListTarget<'l>>) -> Summary<'a> {
        Summary(list.into().apply(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "exception_lists", "summary"],
        )))
    }

    pub fn duplicate_list(
        &self,
        list_id: &str,
        namespace: NamespaceType,
        include_expired: bool,
    ) -> DuplicateList<'a> {
        DuplicateList(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "exception_lists", "_duplicate"],
                )
                .selector(("list_id", list_id))
                .param("namespace_type", namespace.as_str())
                .param("include_expired_exceptions", include_expired),
        )
    }

    /// Exports the list and its items as NDJSON.
    pub fn export_list(&self, list: &ListReference, include_expired: bool) -> ExportList<'a> {
        ExportList(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "exception_lists", "_export"],
                )
                .param("id", &list.id)
                .param("list_id", &list.list_id)
                .param("namespace_type", list.namespace_type.as_str())
                .param("include_expired_exceptions", include_expired),
        )
    }

    /// Imports NDJSON lists and items. Partial failures are reported with HTTP 200.
    /// Imports can regenerate saved-object IDs; read back by `list_id` afterwards.
    pub fn import_lists(&self, ndjson: impl Into<Vec<u8>>) -> ImportLists<'a> {
        ImportLists(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "exception_lists", "_import"],
                )
                .file("exceptions.ndjson", "application/ndjson", ndjson.into()),
        )
    }
}

macro_rules! namespace_setter {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// Defaults to [`NamespaceType::Single`] on the server.
            pub fn namespace_type(self, namespace: NamespaceType) -> Self {
                Self(self.0.param("namespace_type", namespace.as_str()))
            }
        }
    )*};
}

macro_rules! find_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// One-based page number.
            pub fn page(self, page: u32) -> Self {
                Self(self.0.positive_param("page", page))
            }

            pub fn per_page(self, per_page: u32) -> Self {
                Self(self.0.positive_param("per_page", per_page))
            }

            /// A KQL filter over list or item attributes.
            pub fn filter(self, filter: &str) -> Self {
                Self(self.0.param("filter", filter))
            }

            pub fn sort_field(self, field: &str) -> Self {
                Self(self.0.param("sort_field", field))
            }

            pub fn sort_order(self, order: SortOrder) -> Self {
                Self(self.0.param("sort_order", order.as_str()))
            }
        }
    )*};
}

endpoint! {
    /// `POST /api/exception_lists`
    CreateList => ExceptionList
}

endpoint! {
    /// `GET /api/exception_lists`
    GetList => ExceptionList
}

endpoint! {
    /// `PUT /api/exception_lists`
    UpdateList => ExceptionList
}

endpoint! {
    /// `DELETE /api/exception_lists`
    DeleteList => ExceptionList
}

endpoint! {
    /// `GET /api/exception_lists/_find`
    FindLists => ExceptionPage<ExceptionList>
}

endpoint! {
    /// `POST /api/exception_lists/items`
    CreateItem => ExceptionItem
}

endpoint! {
    /// `GET /api/exception_lists/items`
    GetItem => ExceptionItem
}

endpoint! {
    /// `PUT /api/exception_lists/items`
    UpdateItem => ExceptionItem
}

endpoint! {
    /// `DELETE /api/exception_lists/items`
    DeleteItem => ExceptionItem
}

endpoint! {
    /// `GET /api/exception_lists/items/_find`
    FindItems => ExceptionPage<ExceptionItem>
}

impl FindItems<'_> {
    /// Free-text search over item fields.
    pub fn search(self, text: &str) -> Self {
        Self(self.0.param("search", text))
    }
}

endpoint! {
    /// `GET /api/exception_lists/summary`
    Summary => Value
}

impl Summary<'_> {
    /// A KQL filter applied before counting.
    pub fn filter(self, filter: &str) -> Self {
        Self(self.0.param("filter", filter))
    }
}

endpoint! {
    /// `POST /api/exception_lists/_duplicate`
    DuplicateList => ExceptionList
}

endpoint! {
    /// `POST /api/exception_lists/_export`
    ExportList => Raw
}

endpoint! {
    /// `POST /api/exception_lists/_import`
    ImportLists => ImportResult
}

impl ImportLists<'_> {
    /// Replaces existing lists and items with the same IDs.
    pub fn overwrite(self, overwrite: bool) -> Self {
        Self(self.0.param("overwrite", overwrite))
    }

    /// Imports under newly generated list IDs.
    pub fn as_new_list(self, enabled: bool) -> Self {
        Self(self.0.param("as_new_list", enabled))
    }
}

namespace_setter!(
    GetList, DeleteList, FindLists, GetItem, DeleteItem, FindItems, Summary
);
find_setters!(FindLists, FindItems);
paginated!(
    FindLists => ExceptionPage<ExceptionList>,
    FindItems => ExceptionPage<ExceptionItem>,
);
