//! Agent policies, integration packages, package policies, and enrolled agents.
//! Package installation changes assets; assigning a package policy changes agent
//! configuration. These are separate operations with separate results.
use crate::{Client, PageOptions, Result, Scope};
use reqwest::{Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;

/// Enrollment credentials are deliberately omitted from Debug output.
#[derive(Clone, Deserialize)]
pub struct EnrollmentKey {
    pub id: String,
    pub api_key_id: String,
    pub api_key: String,
    pub active: bool,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub expire_at: Option<String>,
}

impl fmt::Debug for EnrollmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentKey")
            .field("id", &self.id)
            .field("active", &self.active)
            .field("api_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct NewEnrollmentKey {
    pub policy_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Elastic duration, for example `24h`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration: Option<String>,
}

/// An explicit ID set or a Fleet KQL query. A query can select many agents.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum AgentSelection {
    Ids(Vec<String>),
    Query(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkAgents {
    pub agents: AgentSelection,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
}

impl BulkAgents {
    pub fn new(agents: AgentSelection) -> Self {
        Self {
            agents,
            dry_run: false,
            batch_size: None,
        }
    }
}

/// Submission does not prove completion. Follow an action ID through `agent_actions`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BulkActionResult {
    Action {
        #[serde(rename = "actionId")]
        action_id: String,
    },
    DryRun {
        count: u64,
    },
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnenrollOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_inactive: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TagUpdate {
    pub tags_to_add: Vec<String>,
    pub tags_to_remove: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_inactive: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpgradeAgent {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    #[serde(rename = "skipRateLimitCheck", skip_serializing_if = "Option::is_none")]
    pub skip_rate_limit_check: Option<bool>,
}

impl UpgradeAgent {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            force: None,
            source_uri: None,
            skip_rate_limit_check: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct UpgradeRollout {
    #[serde(rename = "includeInactive", skip_serializing_if = "Option::is_none")]
    pub include_inactive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollout_duration_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiagnosticsOptions {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional_metrics: Vec<DiagnosticMetric>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub enum DiagnosticMetric {
    #[serde(rename = "CPU")]
    Cpu,
}

/// Action history uses zero-based pages, unlike Fleet resource listings.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionOptions {
    pub page: u32,
    pub per_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<u32>,
    pub error_size: u32,
}

impl Default for ActionOptions {
    fn default() -> Self {
        Self {
            page: 0,
            per_page: 20,
            date: None,
            latest: None,
            error_size: 5,
        }
    }
}

/// Inspect failure counts and errors, including while the action is IN_PROGRESS.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentActionStatus {
    pub action_id: String,
    pub status: String,
    #[serde(rename = "type")]
    pub action_type: String,
    pub nb_agents_action_created: u64,
    pub nb_agents_ack: u64,
    pub nb_agents_failed: u64,
    pub nb_agents_actioned: u64,
    #[serde(default)]
    pub latest_errors: Vec<Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentUpload {
    pub id: String,
    pub name: String,
    pub action_id: String,
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

fn combined(parts: &[Value]) -> Value {
    let mut body = serde_json::Map::new();
    for part in parts {
        body.extend(
            part.as_object()
                .expect("request structs serialize as objects")
                .clone(),
        );
    }
    Value::Object(body)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Item<T> {
    pub item: T,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Items<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FleetPage<T> {
    pub items: Vec<T>,
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    pub total: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentPolicy {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub revision: u64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub agents: Option<u64>,
    #[serde(default)]
    pub package_policies: Vec<Value>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentPolicyRequest {
    pub name: String,
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitoring_enabled: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_output_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactivity_timeout: Option<u64>,
}

impl AgentPolicyRequest {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            description: None,
            monitoring_enabled: None,
            data_output_id: None,
            inactivity_timeout: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PackagePolicy {
    pub id: String,
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    pub revision: u64,
    pub package: PackageRef,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    #[serde(default)]
    pub inputs: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Simplified input format. Stream names and variables depend on the package.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub streams: BTreeMap<String, PolicyStream>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyStream {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackagePolicyRequest {
    pub name: String,
    pub namespace: String,
    pub policy_ids: Vec<String>,
    pub package: PackageRef,
    pub inputs: BTreeMap<String, PolicyInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Integration {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Agent {
    pub id: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub local_metadata: Value,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

pub struct Fleet<'a>(pub(crate) &'a Client);
impl Fleet<'_> {
    pub async fn enrollment_keys(&self, options: &PageOptions) -> Result<FleetPage<EnrollmentKey>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "fleet", "enrollment_api_keys"],
                    )?
                    .query(options),
            )
            .await
    }

    pub async fn enrollment_key(&self, id: &str) -> Result<EnrollmentKey> {
        let result: Item<EnrollmentKey> = self
            .0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "enrollment_api_keys", id],
            )?)
            .await?;
        Ok(result.item)
    }

    pub async fn create_enrollment_key(&self, request: &NewEnrollmentKey) -> Result<EnrollmentKey> {
        let result: Item<EnrollmentKey> = self
            .0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "enrollment_api_keys"],
                    )?
                    .json(request),
            )
            .await?;
        Ok(result.item)
    }

    /// Revokes future enrollment. Already enrolled agents keep their own credentials.
    pub async fn revoke_enrollment_key(&self, id: &str) -> Result<Value> {
        self.0
            .json(self.0.request(
                Method::DELETE,
                Scope::Space,
                &["api", "fleet", "enrollment_api_keys", id],
            )?)
            .await
    }

    pub async fn bulk_reassign_agents(
        &self,
        agents: &BulkAgents,
        policy_id: &str,
        include_inactive: bool,
    ) -> Result<BulkActionResult> {
        let body = combined(&[
            serde_json::to_value(agents)?,
            json!({"policy_id": policy_id, "includeInactive": include_inactive}),
        ]);
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "bulk_reassign"],
                    )?
                    .json(&body),
            )
            .await
    }

    pub async fn bulk_unenroll_agents(
        &self,
        agents: &BulkAgents,
        options: &UnenrollOptions,
    ) -> Result<BulkActionResult> {
        let body = combined(&[
            serde_json::to_value(agents)?,
            serde_json::to_value(options)?,
        ]);
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "bulk_unenroll"],
                    )?
                    .json(&body),
            )
            .await
    }

    pub async fn bulk_update_agent_tags(
        &self,
        agents: &BulkAgents,
        tags: &TagUpdate,
    ) -> Result<BulkActionResult> {
        let body = combined(&[serde_json::to_value(agents)?, serde_json::to_value(tags)?]);
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "bulk_update_agent_tags"],
                    )?
                    .json(&body),
            )
            .await
    }

    /// Schedules an upgrade; the empty acknowledgment is not proof of completion.
    /// Container agents cannot perform Fleet-managed binary upgrades.
    pub async fn upgrade_agent(&self, id: &str, upgrade: &UpgradeAgent) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", id, "upgrade"],
                    )?
                    .json(upgrade),
            )
            .await
    }

    pub async fn bulk_upgrade_agents(
        &self,
        agents: &BulkAgents,
        upgrade: &UpgradeAgent,
        rollout: &UpgradeRollout,
    ) -> Result<BulkActionResult> {
        let body = combined(&[
            serde_json::to_value(agents)?,
            serde_json::to_value(upgrade)?,
            serde_json::to_value(rollout)?,
        ]);
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "bulk_upgrade"],
                    )?
                    .json(&body),
            )
            .await
    }

    pub async fn request_agent_diagnostics(
        &self,
        id: &str,
        options: &DiagnosticsOptions,
    ) -> Result<BulkActionResult> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", id, "request_diagnostics"],
                    )?
                    .json(options),
            )
            .await
    }

    pub async fn bulk_request_agent_diagnostics(
        &self,
        agents: &BulkAgents,
        options: &DiagnosticsOptions,
    ) -> Result<BulkActionResult> {
        let body = combined(&[
            serde_json::to_value(agents)?,
            serde_json::to_value(options)?,
        ]);
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "bulk_request_diagnostics"],
                    )?
                    .json(&body),
            )
            .await
    }

    pub async fn agent_actions(&self, options: &ActionOptions) -> Result<Items<AgentActionStatus>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "fleet", "agents", "action_status"],
                    )?
                    .query(options),
            )
            .await
    }

    /// Kibana supports cancellation of upgrade and unenrollment actions only.
    pub async fn cancel_agent_action(&self, id: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", "actions", id, "cancel"],
                    )?
                    .json(&json!({})),
            )
            .await
    }

    pub async fn agent_uploads(&self, id: &str) -> Result<Items<AgentUpload>> {
        self.0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "agents", id, "uploads"],
            )?)
            .await
    }

    /// Downloads diagnostic bytes after the corresponding upload reports READY.
    pub async fn download_agent_file(&self, id: &str, name: &str) -> Result<Response> {
        self.0
            .execute(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "agents", "files", id, name],
            )?)
            .await
    }

    pub async fn setup(&self) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(Method::POST, Scope::Space, &["api", "fleet", "setup"])?,
            )
            .await
    }
    pub async fn agent_policies(&self, options: &PageOptions) -> Result<FleetPage<AgentPolicy>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "fleet", "agent_policies"],
                    )?
                    .query(options)
                    .query(&[("full", true), ("withAgentCount", true)]),
            )
            .await
    }
    pub async fn agent_policy(&self, id: &str) -> Result<AgentPolicy> {
        let value: Item<AgentPolicy> = self
            .0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "agent_policies", id],
            )?)
            .await?;
        Ok(value.item)
    }
    pub async fn create_agent_policy(&self, policy: &AgentPolicyRequest) -> Result<AgentPolicy> {
        let value: Item<AgentPolicy> = self
            .0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agent_policies"],
                    )?
                    .query(&[("sys_monitoring", false)])
                    .json(policy),
            )
            .await?;
        Ok(value.item)
    }
    pub async fn update_agent_policy(
        &self,
        id: &str,
        policy: &AgentPolicyRequest,
    ) -> Result<AgentPolicy> {
        let value: Item<AgentPolicy> = self
            .0
            .json(
                self.0
                    .request(
                        Method::PUT,
                        Scope::Space,
                        &["api", "fleet", "agent_policies", id],
                    )?
                    .json(policy),
            )
            .await?;
        Ok(value.item)
    }
    pub async fn delete_agent_policy(&self, id: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agent_policies", "delete"],
                    )?
                    .json(&json!({"agentPolicyId":id})),
            )
            .await
    }
    pub async fn copy_agent_policy(&self, id: &str, name: &str) -> Result<AgentPolicy> {
        let value: Item<AgentPolicy> = self
            .0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agent_policies", id, "copy"],
                    )?
                    .json(&json!({"name":name})),
            )
            .await?;
        Ok(value.item)
    }
    pub async fn download_agent_policy(&self, id: &str) -> Result<Response> {
        self.0
            .execute(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "agent_policies", id, "download"],
            )?)
            .await
    }
    pub async fn package_policies(
        &self,
        options: &PageOptions,
    ) -> Result<FleetPage<PackagePolicy>> {
        self.0
            .json(
                self.0
                    .request(
                        Method::GET,
                        Scope::Space,
                        &["api", "fleet", "package_policies"],
                    )?
                    .query(options),
            )
            .await
    }
    pub async fn package_policy(&self, id: &str) -> Result<PackagePolicy> {
        let value: Item<PackagePolicy> = self
            .0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "package_policies", id],
            )?)
            .await?;
        Ok(value.item)
    }
    pub async fn create_package_policy(
        &self,
        policy: &PackagePolicyRequest,
    ) -> Result<PackagePolicy> {
        let value: Item<PackagePolicy> = self
            .0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "package_policies"],
                    )?
                    .query(&[("format", "simplified")])
                    .json(policy),
            )
            .await?;
        Ok(value.item)
    }
    pub async fn update_package_policy(
        &self,
        id: &str,
        policy: &PackagePolicyRequest,
    ) -> Result<PackagePolicy> {
        let value: Item<PackagePolicy> = self
            .0
            .json(
                self.0
                    .request(
                        Method::PUT,
                        Scope::Space,
                        &["api", "fleet", "package_policies", id],
                    )?
                    .query(&[("format", "simplified")])
                    .json(policy),
            )
            .await?;
        Ok(value.item)
    }
    pub async fn delete_package_policy(&self, id: &str) -> Result<Value> {
        self.0
            .json(self.0.request(
                Method::DELETE,
                Scope::Space,
                &["api", "fleet", "package_policies", id],
            )?)
            .await
    }
    pub async fn integrations(&self) -> Result<Items<Integration>> {
        self.0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "epm", "packages"],
            )?)
            .await
    }
    pub async fn integration(&self, name: &str, version: &str) -> Result<Integration> {
        let value: Item<Integration> = self
            .0
            .json(self.0.request(
                Method::GET,
                Scope::Space,
                &["api", "fleet", "epm", "packages", name, version],
            )?)
            .await?;
        Ok(value.item)
    }
    pub async fn install_integration(&self, name: &str, version: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "epm", "packages", name, version],
                    )?
                    .json(&json!({})),
            )
            .await
    }
    pub async fn uninstall_integration(&self, name: &str, version: &str) -> Result<Value> {
        self.0
            .json(self.0.request(
                Method::DELETE,
                Scope::Space,
                &["api", "fleet", "epm", "packages", name, version],
            )?)
            .await
    }
    pub async fn agents(&self, options: &PageOptions) -> Result<FleetPage<Agent>> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "fleet", "agents"])?
                    .query(options),
            )
            .await
    }
    pub async fn agent(&self, id: &str) -> Result<Agent> {
        let value: Item<Agent> = self
            .0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "fleet", "agents", id])?,
            )
            .await?;
        Ok(value.item)
    }
    pub async fn reassign_agent(&self, id: &str, policy_id: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", id, "reassign"],
                    )?
                    .json(&json!({"policy_id":policy_id})),
            )
            .await
    }
    pub async fn unenroll_agent(&self, id: &str) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(
                        Method::POST,
                        Scope::Space,
                        &["api", "fleet", "agents", id, "unenroll"],
                    )?
                    .json(&json!({})),
            )
            .await
    }
    pub async fn agent_status(&self) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "fleet", "agent_status"])?,
            )
            .await
    }
    pub async fn outputs(&self) -> Result<Value> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Space, &["api", "fleet", "outputs"])?,
            )
            .await
    }
}
