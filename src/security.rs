//! Security detection rules. These are distinct from generic Kibana alerting rules.
use crate::{Client, Result, Scope};
use reqwest::{Method, Response, multipart};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: String,
    pub risk_score: f64,
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Create a KQL or Lucene query rule. Rules start disabled unless explicitly enabled.
#[derive(Clone, Debug, Serialize)]
pub struct QueryRule {
    #[serde(rename = "type")]
    rule_type: &'static str,
    pub name: String,
    pub description: String,
    pub query: String,
    pub language: QueryLanguage,
    pub index: Vec<String>,
    pub severity: Severity,
    pub risk_score: u8,
    pub enabled: bool,
    pub interval: String,
    pub from: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions_list: Vec<crate::exceptions::ListReference>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryLanguage {
    Kuery,
    Lucene,
}

impl QueryRule {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        query: impl Into<String>,
    ) -> Self {
        Self {
            rule_type: "query",
            name: name.into(),
            description: description.into(),
            query: query.into(),
            language: QueryLanguage::Kuery,
            index: vec!["logs-*".into()],
            severity: Severity::Medium,
            risk_score: 47,
            enabled: false,
            interval: "5m".into(),
            from: "now-6m".into(),
            tags: vec![],
            rule_id: None,
            exceptions_list: vec![],
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RulePatch {
    /// Replaces all list associations. Use an empty vector to detach every list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exceptions_list: Option<Vec<crate::exceptions::ListReference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug)]
pub enum RuleSelector<'a> {
    Id(&'a str),
    RuleId(&'a str),
}
impl RuleSelector<'_> {
    fn pair(&self) -> (&str, &str) {
        match self {
            Self::Id(v) => ("id", v),
            Self::RuleId(v) => ("rule_id", v),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FindRules {
    pub page: u32,
    pub per_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}
impl Default for FindRules {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 50,
            filter: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RulePage {
    pub data: Vec<DetectionRule>,
    pub page: u32,
    #[serde(rename = "perPage", alias = "per_page")]
    pub per_page: u32,
    pub total: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleImportResult {
    pub success: bool,
    pub success_count: u64,
    #[serde(default)]
    pub errors: Vec<Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

pub struct Security<'a>(pub(crate) &'a Client);

impl Security<'_> {
    pub async fn privileges(&self) -> Result<Value> {
        self.0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "detection_engine", "privileges"],
            )?)
            .await
    }
    pub async fn initialize(&self) -> Result<Value> {
        self.0
            .json(self.0.request(
                Method::POST,
                Scope::Space,
                &["api", "detection_engine", "index"],
            )?)
            .await
    }
    pub async fn rules(&self, options: &FindRules) -> Result<RulePage> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "detection_engine", "rules", "_find"],
                    )?
                    .query(options),
            )
            .await
    }
    pub async fn rule(&self, selector: RuleSelector<'_>) -> Result<DetectionRule> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "detection_engine", "rules"],
                    )?
                    .query(&[selector.pair()]),
            )
            .await
    }
    pub async fn create_rule(&self, rule: &QueryRule) -> Result<DetectionRule> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "detection_engine", "rules"],
                    )?
                    .json(rule),
            )
            .await
    }
    pub async fn update_rule(
        &self,
        selector: RuleSelector<'_>,
        patch: &RulePatch,
    ) -> Result<DetectionRule> {
        let mut body = serde_json::to_value(patch)?;
        let (key, value) = selector.pair();
        body[key] = json!(value);
        self.0
            .json(
                self.0
                    .request(
                        Method::PATCH,
                        Scope::Space,
                        &["api", "detection_engine", "rules"],
                    )?
                    .json(&body),
            )
            .await
    }
    pub async fn delete_rule(&self, selector: RuleSelector<'_>) -> Result<DetectionRule> {
        self.0
            .json(
                self.0
                    .request(
                        Method::DELETE,
                        Scope::Space,
                        &["api", "detection_engine", "rules"],
                    )?
                    .query(&[selector.pair()]),
            )
            .await
    }
    /// Returns a streaming NDJSON response. IDs here are stable `rule_id` values.
    pub async fn export_rules(&self, rule_ids: &[&str]) -> Result<Response> {
        let objects: Vec<_> = rule_ids.iter().map(|id| json!({"rule_id": id})).collect();
        self.0
            .execute(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "detection_engine", "rules", "_export"],
                    )?
                    .json(&json!({"objects": objects})),
            )
            .await
    }
    /// Imports NDJSON and preserves partial failures even when HTTP status is 200.
    pub async fn import_rules(&self, ndjson: Vec<u8>, overwrite: bool) -> Result<RuleImportResult> {
        let file = multipart::Part::bytes(ndjson)
            .file_name("rules.ndjson")
            .mime_str("application/x-ndjson")?;
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "detection_engine", "rules", "_import"],
                    )?
                    .query(&[("overwrite", overwrite)])
                    .multipart(multipart::Form::new().part("file", file)),
            )
            .await
    }
}
