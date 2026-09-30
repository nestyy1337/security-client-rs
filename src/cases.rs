//! Cases and their comments. Updates use optimistic concurrency through case versions.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    Error, Kibana, Result, Scope, SortOrder,
    http::{Empty, Method},
    pagination::paginated,
    request::endpoint,
    security::Severity,
};

/// The case owner used by the Security solution.
pub const SECURITY_OWNER: &str = "securitySolution";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Case {
    pub id: String,
    /// Opaque concurrency token required by [`CasePatch`].
    pub version: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub status: String,
    pub severity: String,
    pub tags: Vec<String>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(rename = "totalComment", default)]
    pub total_comments: u64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatus {
    Open,
    InProgress,
    Closed,
}

impl CaseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in-progress",
            Self::Closed => "closed",
        }
    }
}

/// A case definition for [`Cases::create`]. Cases have no external connector
/// and do not sync alert status unless configured.
#[derive(Clone, Debug, Serialize)]
pub struct NewCase {
    title: String,
    description: String,
    owner: String,
    severity: Severity,
    tags: Vec<String>,
    connector: Value,
    settings: CaseSettings,
}

#[derive(Clone, Debug, Serialize)]
struct CaseSettings {
    #[serde(rename = "syncAlerts")]
    sync_alerts: bool,
}

impl NewCase {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            owner: owner.into(),
            severity: Severity::Low,
            tags: Vec::new(),
            connector: json!({"id": "none", "name": "none", "type": ".none", "fields": null}),
            settings: CaseSettings { sync_alerts: false },
        }
    }

    /// A low-severity case owned by the Security solution.
    pub fn security(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(title, description, SECURITY_OWNER)
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Keeps attached alert statuses in step with the case status.
    pub fn sync_alerts(mut self, enabled: bool) -> Self {
        self.settings.sync_alerts = enabled;
        self
    }

    /// An external incident connector as Kibana's `{id, name, type, fields}` object.
    pub fn connector(mut self, connector: Value) -> Self {
        self.connector = connector;
        self
    }
}

/// Changes to one case. Only the fields set here are sent.
#[derive(Clone, Debug, Serialize)]
pub struct CasePatch {
    id: String,
    version: String,
    #[serde(flatten)]
    changes: Map<String, Value>,
}

impl CasePatch {
    /// `version` must come from the most recent read; stale versions fail with HTTP 409.
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            version: version.into(),
            changes: Map::new(),
        }
    }

    pub fn status(self, status: CaseStatus) -> Self {
        self.set("status", status.as_str().into())
    }

    pub fn title(self, title: impl Into<String>) -> Self {
        self.set("title", Value::String(title.into()))
    }

    pub fn description(self, description: impl Into<String>) -> Self {
        self.set("description", Value::String(description.into()))
    }

    pub fn severity(self, severity: Severity) -> Self {
        self.set("severity", severity.as_str().into())
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(self, tags: I) -> Self {
        self.set(
            "tags",
            tags.into_iter().map(|t| Value::String(t.into())).collect(),
        )
    }

    /// Sets an additional patchable field. The case ID and concurrency version
    /// are reserved; supply them through [`Self::new`].
    pub fn field(self, name: &str, value: impl Serialize) -> Result<Self> {
        if matches!(name, "id" | "version") {
            return Err(Error::InvalidRequest(format!(
                "case patch field {name:?} is reserved"
            )));
        }
        Ok(self.set(name, serde_json::to_value(value).map_err(Error::serialize)?))
    }

    fn set(mut self, key: &str, value: Value) -> Self {
        self.changes.insert(key.into(), value);
        self
    }
}

/// A comment body for [`Cases::add_comment`].
#[derive(Clone, Debug, Serialize)]
pub struct CaseComment {
    #[serde(rename = "type")]
    kind: &'static str,
    owner: String,
    comment: String,
}

impl CaseComment {
    /// A free-text comment. `owner` must match the case owner.
    pub fn user(owner: impl Into<String>, comment: impl Into<String>) -> Self {
        Self {
            kind: "user",
            owner: owner.into(),
            comment: comment.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CasePage {
    pub cases: Vec<Case>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    /// Status counts such as `count_open_cases`.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CommentPage {
    /// User comments, alert attachments and other attachment types.
    pub comments: Vec<Value>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Cases<'a>(pub(crate) &'a Kibana);

impl<'a> Cases<'a> {
    /// One page of cases visible to the user, across owners unless filtered.
    pub fn find(&self) -> FindCases<'a> {
        FindCases(
            self.0
                .request(Method::GET, Scope::Space, &["api", "cases", "_find"]),
        )
    }

    pub fn get(&self, id: &str) -> GetCase<'a> {
        GetCase(
            self.0
                .request(Method::GET, Scope::Space, &["api", "cases", id]),
        )
    }

    /// Creates a case from a [`NewCase`] or equivalent JSON.
    pub fn create<B: Serialize + ?Sized>(&self, case: &B) -> CreateCase<'a> {
        CreateCase(
            self.0
                .request(Method::POST, Scope::Space, &["api", "cases"])
                .json(case),
        )
    }

    /// Applies several versioned patches in one request.
    pub fn update(&self, patches: impl IntoIterator<Item = CasePatch>) -> UpdateCases<'a> {
        let cases: Vec<CasePatch> = patches.into_iter().collect();
        UpdateCases(
            self.0
                .request(Method::PATCH, Scope::Space, &["api", "cases"])
                .field("cases", cases),
        )
    }

    /// Deletes cases and their comments.
    pub fn delete<I: IntoIterator<Item = S>, S: AsRef<str>>(&self, ids: I) -> DeleteCases<'a> {
        let ids: Vec<String> = ids.into_iter().map(|id| id.as_ref().to_owned()).collect();
        DeleteCases(
            self.0
                .request(Method::DELETE, Scope::Space, &["api", "cases"])
                .param("ids", Value::from(ids)),
        )
    }

    /// Adds a [`CaseComment`] or other attachment and returns the updated case.
    pub fn add_comment<B: Serialize + ?Sized>(&self, case_id: &str, comment: &B) -> AddComment<'a> {
        AddComment(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "cases", case_id, "comments"],
                )
                .json(comment),
        )
    }

    pub fn find_comments(&self, case_id: &str) -> FindComments<'a> {
        FindComments(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "cases", case_id, "comments", "_find"],
        ))
    }
}

endpoint! {
    /// `GET /api/cases/_find`
    FindCases => CasePage
}

impl FindCases<'_> {
    /// One-based page number.
    pub fn page(self, page: u32) -> Self {
        Self(self.0.positive_param("page", page))
    }

    pub fn per_page(self, per_page: u32) -> Self {
        Self(self.0.positive_param("perPage", per_page))
    }

    /// Restricts results to an owner such as [`SECURITY_OWNER`]. Repeat for several owners.
    pub fn owner(self, owner: &str) -> Self {
        Self(self.0.append_param("owner", owner))
    }

    pub fn search(self, text: &str) -> Self {
        Self(self.0.param("search", text))
    }

    pub fn status(self, status: CaseStatus) -> Self {
        Self(self.0.param("status", status.as_str()))
    }

    pub fn severity(self, severity: Severity) -> Self {
        Self(self.0.param("severity", severity.as_str()))
    }

    /// Restricts results to cases with this tag. Repeat for several tags.
    pub fn tag(self, tag: &str) -> Self {
        Self(self.0.append_param("tags", tag))
    }

    /// A case field such as `createdAt`, `updatedAt`, `title` or `severity`.
    pub fn sort_field(self, field: &str) -> Self {
        Self(self.0.param("sortField", field))
    }

    pub fn sort_order(self, order: SortOrder) -> Self {
        Self(self.0.param("sortOrder", order.as_str()))
    }
}

endpoint! {
    /// `GET /api/cases/{caseId}`
    GetCase => Case
}

endpoint! {
    /// `POST /api/cases`
    CreateCase => Case
}

endpoint! {
    /// `PATCH /api/cases`
    UpdateCases => Vec<Case>
}

endpoint! {
    /// `DELETE /api/cases`
    DeleteCases => Empty
}

endpoint! {
    /// `POST /api/cases/{caseId}/comments`
    AddComment => Case
}

endpoint! {
    /// `GET /api/cases/{caseId}/comments/_find`
    FindComments => CommentPage
}

impl FindComments<'_> {
    /// One-based page number.
    pub fn page(self, page: u32) -> Self {
        Self(self.0.positive_param("page", page))
    }

    pub fn per_page(self, per_page: u32) -> Self {
        Self(self.0.positive_param("perPage", per_page))
    }

    pub fn sort_order(self, order: SortOrder) -> Self {
        Self(self.0.param("sortOrder", order.as_str()))
    }
}

paginated!(FindCases => CasePage, FindComments => CommentPage);
