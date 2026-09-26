//! Security cases and comments, including optimistic concurrency through versions.
use crate::{Client, Result, Scope, security::Severity};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
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
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NewCase {
    pub title: String,
    pub description: String,
    pub owner: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub connector: Value,
    pub settings: CaseSettings,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseSettings {
    #[serde(rename = "syncAlerts")]
    pub sync_alerts: bool,
}

impl NewCase {
    pub fn security(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: description.into(),
            owner: "securitySolution".into(),
            severity: Severity::Low,
            tags: vec![],
            connector: json!({"id":"none","name":"none","type":".none","fields":null}),
            settings: CaseSettings { sync_alerts: false },
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaseStatus {
    Open,
    InProgress,
    Closed,
}

#[derive(Debug, Serialize)]
pub struct CasePatch<'a> {
    pub id: &'a str,
    pub version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<CaseStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindCases {
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
}
impl Default for FindCases {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 50,
            owner: "securitySolution".into(),
            search: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CasePage {
    pub cases: Vec<Case>,
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
}

pub struct Cases<'a>(pub(crate) &'a Client);
impl Cases<'_> {
    pub async fn find(&self, options: &FindCases) -> Result<CasePage> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "cases", "_find"])?
                    .query(options),
            )
            .await
    }
    pub async fn get(&self, id: &str) -> Result<Case> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "cases", id])?,
            )
            .await
    }
    pub async fn create(&self, case: &NewCase) -> Result<Case> {
        self.0
            .json(
                self.0
                    .request(Method::POST, Scope::Space, &["api", "cases"])?
                    .json(case),
            )
            .await
    }
    pub async fn update(&self, changes: &[CasePatch<'_>]) -> Result<Vec<Case>> {
        self.0
            .json(
                self.0
                    .request(Method::PATCH, Scope::Space, &["api", "cases"])?
                    .json(&json!({"cases":changes})),
            )
            .await
    }
    pub async fn delete(&self, ids: &[&str]) -> Result<()> {
        self.0
            .empty(
                self.0
                    .request(Method::DELETE, Scope::Space, &["api", "cases"])?
                    .query(&[("ids", serde_json::to_string(ids)?)]),
            )
            .await
    }
    pub async fn comment(&self, id: &str, owner: &str, comment: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "cases", id, "comments"],
                    )?
                    .json(&json!({"type":"user","owner":owner,"comment":comment})),
            )
            .await
    }
    pub async fn comments(&self, id: &str, page: u32, per_page: u32) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "cases", id, "comments", "_find"],
                    )?
                    .query(&[("page", page), ("perPage", per_page)]),
            )
            .await
    }
}
