//! Security detection rules. These are distinct from generic Kibana alerting rules.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    Error, Kibana, Result, Scope, SortOrder,
    exceptions::ListReference,
    http::{Method, Raw},
    pagination::paginated,
    request::endpoint,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// A detection rule's risk score, from 0 to 100.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RiskScore(u8);

impl RiskScore {
    /// Fails with [`Error::InvalidRequest`] above 100.
    pub fn new(score: u8) -> Result<Self> {
        if score > 100 {
            return Err(Error::InvalidRequest(format!(
                "risk score {score} is above 100"
            )));
        }
        Ok(Self(score))
    }

    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for RiskScore {
    type Error = Error;

    fn try_from(score: u8) -> Result<Self> {
        Self::new(score)
    }
}

/// When a rule runs and how far back each run searches.
///
/// Kibana configures these separately: `interval` is how often the rule runs
/// and `from` is the start of each run's search window. A window no longer
/// than the interval leaves gaps between runs whenever a run starts late or
/// events arrive late, so this type derives `from` as the interval plus an
/// additional lookback by which consecutive windows overlap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleSchedule {
    interval: u64,
    additional_lookback: u64,
}

impl RuleSchedule {
    /// Fails with [`Error::InvalidRequest`] unless both durations are whole
    /// seconds and the interval is at least one second.
    pub fn new(interval: Duration, additional_lookback: Duration) -> Result<Self> {
        if interval.subsec_nanos() != 0 || additional_lookback.subsec_nanos() != 0 {
            return Err(Error::InvalidRequest(
                "rule schedules use whole seconds".into(),
            ));
        }
        if interval.is_zero() {
            return Err(Error::InvalidRequest(
                "a rule interval must be at least one second".into(),
            ));
        }
        Ok(Self {
            interval: interval.as_secs(),
            additional_lookback: additional_lookback.as_secs(),
        })
    }

    /// Runs every `interval`, with windows overlapping by one minute.
    pub fn every(interval: Duration) -> Result<Self> {
        Self::new(interval, Duration::from_secs(60))
    }

    pub fn interval(self) -> Duration {
        Duration::from_secs(self.interval)
    }

    /// How far back each run searches: the interval plus the additional lookback.
    pub fn lookback(self) -> Duration {
        Duration::from_secs(self.interval.saturating_add(self.additional_lookback))
    }

    fn interval_value(self) -> String {
        date_math(self.interval)
    }

    fn lookback_value(self) -> String {
        format!("now-{}", date_math(self.lookback().as_secs()))
    }
}

impl Default for RuleSchedule {
    /// Every five minutes, searching the last six.
    fn default() -> Self {
        Self {
            interval: 300,
            additional_lookback: 60,
        }
    }
}

/// Seconds in the largest whole Elastic time unit.
fn date_math(seconds: u64) -> String {
    match seconds {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
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
    /// Type-specific and newer fields, including `exceptions_list` and `execution_summary`.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryLanguage {
    Kuery,
    Lucene,
}

/// A KQL or Lucene query rule. Rules start disabled unless explicitly enabled.
///
/// Other rule types can be created by passing their JSON definition to
/// [`Security::create_rule`].
#[derive(Clone, Debug, Serialize)]
pub struct QueryRule {
    #[serde(rename = "type")]
    rule_type: &'static str,
    name: String,
    description: String,
    query: String,
    language: QueryLanguage,
    index: Vec<String>,
    severity: Severity,
    risk_score: RiskScore,
    enabled: bool,
    interval: String,
    from: String,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exceptions_list: Vec<ListReference>,
}

impl QueryRule {
    /// A disabled KQL rule over `logs-*` with medium severity, on the default
    /// [`RuleSchedule`]: every 5 minutes, searching the last 6.
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
            risk_score: RiskScore(47),
            enabled: false,
            interval: RuleSchedule::default().interval_value(),
            from: RuleSchedule::default().lookback_value(),
            tags: Vec::new(),
            rule_id: None,
            exceptions_list: Vec::new(),
        }
    }

    pub fn language(mut self, language: QueryLanguage) -> Self {
        self.language = language;
        self
    }

    pub fn index<I: IntoIterator<Item = S>, S: Into<String>>(mut self, patterns: I) -> Self {
        self.index = patterns.into_iter().map(Into::into).collect();
        self
    }

    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn risk_score(mut self, score: RiskScore) -> Self {
        self.risk_score = score;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets how often the rule runs and how far back each run searches.
    pub fn schedule(mut self, schedule: RuleSchedule) -> Self {
        self.interval = schedule.interval_value();
        self.from = schedule.lookback_value();
        self
    }

    /// Sets Kibana's `interval`, such as `15m`, and `from`, such as `now-20m`
    /// or other date math, directly. Keep `from` at least one interval back,
    /// or runs leave gaps; prefer [`schedule`](Self::schedule).
    pub fn custom_schedule(mut self, interval: impl Into<String>, from: impl Into<String>) -> Self {
        self.interval = interval.into();
        self.from = from.into();
        self
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tags: I) -> Self {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// A stable identifier, generated by Kibana when omitted.
    pub fn rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn exceptions_list(mut self, lists: Vec<ListReference>) -> Self {
        self.exceptions_list = lists;
        self
    }
}

/// Selects a rule by saved-object `id` or by its stable `rule_id`.
#[derive(Clone, Copy, Debug)]
pub enum RuleSelector<'a> {
    Id(&'a str),
    RuleId(&'a str),
}

impl<'a> RuleSelector<'a> {
    fn pair(self) -> (&'static str, &'a str) {
        match self {
            Self::Id(v) => ("id", v),
            Self::RuleId(v) => ("rule_id", v),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct RulePage {
    pub data: Vec<DetectionRule>,
    pub page: u32,
    #[serde(rename = "perPage", alias = "per_page")]
    pub per_page: u32,
    pub total: u64,
}

/// HTTP 200 can contain failed imports; inspect `success` and `errors`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct RuleImportResult {
    pub success: bool,
    pub success_count: u64,
    #[serde(default)]
    pub errors: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct Security<'a>(pub(crate) &'a Kibana);

impl<'a> Security<'a> {
    /// The current user's detection-engine privileges.
    pub fn privileges(&self) -> GetPrivileges<'a> {
        GetPrivileges(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "detection_engine", "privileges"],
        ))
    }

    /// Creates the space's alert index and mappings if they do not exist.
    pub fn create_alerts_index(&self) -> CreateAlertsIndex<'a> {
        CreateAlertsIndex(self.0.request(
            Method::POST,
            Scope::Space,
            &["api", "detection_engine", "index"],
        ))
    }

    /// One page of rules. Page through `total` to read the whole collection.
    pub fn find_rules(&self) -> FindRules<'a> {
        FindRules(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "detection_engine", "rules", "_find"],
        ))
    }

    pub fn get_rule(&self, rule: RuleSelector<'_>) -> GetRule<'a> {
        GetRule(
            self.0
                .request(
                    Method::GET,
                    Scope::Space,
                    &["api", "detection_engine", "rules"],
                )
                .selector(rule.pair()),
        )
    }

    /// Creates a rule from a [`QueryRule`] or any rule definition serializable as JSON.
    pub fn create_rule<B: Serialize + ?Sized>(&self, rule: &B) -> CreateRule<'a> {
        CreateRule(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "detection_engine", "rules"],
                )
                .json(rule),
        )
    }

    /// Changes only the fields set on the returned builder. The selector is
    /// sent in the body and cannot be changed by later setters.
    pub fn patch_rule(&self, rule: RuleSelector<'_>) -> PatchRule<'a> {
        let (key, value) = rule.pair();
        PatchRule(
            self.0
                .request(
                    Method::PATCH,
                    Scope::Space,
                    &["api", "detection_engine", "rules"],
                )
                .nonempty(key, value)
                .field(key, value),
        )
    }

    pub fn delete_rule(&self, rule: RuleSelector<'_>) -> DeleteRule<'a> {
        DeleteRule(
            self.0
                .request(
                    Method::DELETE,
                    Scope::Space,
                    &["api", "detection_engine", "rules"],
                )
                .selector(rule.pair()),
        )
    }

    /// Exports rules as NDJSON. Without [`ExportRules::rule_ids`], every rule is exported.
    pub fn export_rules(&self) -> ExportRules<'a> {
        ExportRules(self.0.request(
            Method::POST,
            Scope::Space,
            &["api", "detection_engine", "rules", "_export"],
        ))
    }

    /// Imports an NDJSON export. Partial failures are reported with HTTP 200.
    pub fn import_rules(&self, ndjson: impl Into<Vec<u8>>) -> ImportRules<'a> {
        ImportRules(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "detection_engine", "rules", "_import"],
                )
                .file("rules.ndjson", "application/x-ndjson", ndjson.into()),
        )
    }
}

endpoint! {
    /// `GET /api/detection_engine/privileges`
    GetPrivileges => Value
}

endpoint! {
    /// `POST /api/detection_engine/index`
    CreateAlertsIndex => Value
}

endpoint! {
    /// `GET /api/detection_engine/rules/_find`
    FindRules => RulePage
}

impl FindRules<'_> {
    /// One-based page number.
    pub fn page(self, page: u32) -> Self {
        Self(self.0.positive_param("page", page))
    }

    pub fn per_page(self, per_page: u32) -> Self {
        Self(self.0.positive_param("per_page", per_page))
    }

    /// A KQL filter over rule attributes, for example `alert.attributes.enabled: true`.
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

endpoint! {
    /// `GET /api/detection_engine/rules`
    GetRule => DetectionRule
}

endpoint! {
    /// `POST /api/detection_engine/rules`
    CreateRule => DetectionRule
}

endpoint! {
    /// `PATCH /api/detection_engine/rules`
    PatchRule => DetectionRule
}

/// Fields [`PatchRule::field`] refuses: the selectors, and values with validated setters.
const RESERVED_PATCH_FIELDS: &[&str] = &["id", "rule_id", "risk_score", "severity"];

impl PatchRule<'_> {
    pub fn name(self, name: &str) -> Self {
        Self(self.0.field("name", name))
    }

    pub fn description(self, description: &str) -> Self {
        Self(self.0.field("description", description))
    }

    pub fn enabled(self, enabled: bool) -> Self {
        Self(self.0.field("enabled", enabled))
    }

    pub fn query(self, query: &str) -> Self {
        Self(self.0.field("query", query))
    }

    pub fn severity(self, severity: Severity) -> Self {
        Self(self.0.field("severity", severity))
    }

    pub fn risk_score(self, score: RiskScore) -> Self {
        Self(self.0.field("risk_score", score))
    }

    pub fn tags<I: IntoIterator<Item = S>, S: Into<String>>(self, tags: I) -> Self {
        let tags: Vec<String> = tags.into_iter().map(Into::into).collect();
        Self(self.0.field("tags", tags))
    }

    /// Replaces every list association. An empty vector detaches all lists.
    pub fn exceptions_list(self, lists: Vec<ListReference>) -> Self {
        Self(self.0.field("exceptions_list", lists))
    }

    /// Changes how often the rule runs and how far back each run searches.
    pub fn schedule(self, schedule: RuleSchedule) -> Self {
        Self(
            self.0
                .field("interval", schedule.interval_value())
                .field("from", schedule.lookback_value()),
        )
    }

    /// Sets any other patchable rule field. The selectors `id` and `rule_id`,
    /// and `risk_score` and `severity`, which have validated setters, fail
    /// with [`Error::InvalidRequest`]; use [`unchecked_field`](Self::unchecked_field)
    /// to send them anyway.
    pub fn field(self, name: &str, value: impl Serialize) -> Self {
        if RESERVED_PATCH_FIELDS.contains(&name) {
            return Self(self.0.invalid(format!(
                "{name:?} is set by the selector or a typed setter; use unchecked_field to override it"
            )));
        }
        Self(self.0.field(name, value))
    }

    /// Sets any field without checks, including one that replaces the selector
    /// and changes which rule is patched.
    pub fn unchecked_field(self, name: &str, value: impl Serialize) -> Self {
        Self(self.0.field(name, value))
    }
}

endpoint! {
    /// `DELETE /api/detection_engine/rules`
    DeleteRule => DetectionRule
}

endpoint! {
    /// `POST /api/detection_engine/rules/_export`
    ExportRules => Raw
}

impl ExportRules<'_> {
    /// Exports only these stable `rule_id` values.
    pub fn rule_ids<I: IntoIterator<Item = S>, S: AsRef<str>>(self, rule_ids: I) -> Self {
        let objects: Vec<Value> = rule_ids
            .into_iter()
            .map(|id| serde_json::json!({ "rule_id": id.as_ref() }))
            .collect();
        Self(self.0.field("objects", objects))
    }

    /// Omits the trailing export summary line.
    pub fn exclude_export_details(self, exclude: bool) -> Self {
        Self(self.0.param("exclude_export_details", exclude))
    }

    pub fn file_name(self, name: &str) -> Self {
        Self(self.0.param("file_name", name))
    }
}

endpoint! {
    /// `POST /api/detection_engine/rules/_import`
    ImportRules => RuleImportResult
}

impl ImportRules<'_> {
    /// Replaces existing rules with the same `rule_id`.
    pub fn overwrite(self, overwrite: bool) -> Self {
        Self(self.0.param("overwrite", overwrite))
    }

    pub fn overwrite_exceptions(self, overwrite: bool) -> Self {
        Self(self.0.param("overwrite_exceptions", overwrite))
    }

    pub fn overwrite_action_connectors(self, overwrite: bool) -> Self {
        Self(self.0.param("overwrite_action_connectors", overwrite))
    }

    /// Imports referenced exception lists under new list IDs.
    pub fn as_new_list(self, enabled: bool) -> Self {
        Self(self.0.param("as_new_list", enabled))
    }
}

paginated!(FindRules => RulePage);
