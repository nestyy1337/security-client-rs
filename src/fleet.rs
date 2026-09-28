//! Agent policies, integration packages, package policies, and enrolled agents.
//!
//! Installing a package changes assets; assigning a package policy changes agent
//! configuration. Agent actions are asynchronous: a submitted action ID is not
//! proof of completion, so follow it through [`Fleet::agent_action_status`].
use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{
    Kibana, Result, Scope, SortOrder,
    http::{Method, Raw},
    pagination::paginated,
    poll::{self, PollOptions, WaitOutcome},
    request::endpoint,
};

/// Fleet wraps single resources in `{"item": ...}`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Item<T> {
    pub item: T,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Items<T> {
    pub items: Vec<T>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct FleetPage<T> {
    pub items: Vec<T>,
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    pub total: u64,
}

/// Enrollment credentials are omitted from `Debug` output.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
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

/// An explicit ID set or a Fleet KQL query. A query can select many agents.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum AgentSelection {
    Ids(Vec<String>),
    Query(String),
}

/// Submission does not prove completion. Follow an action ID through
/// [`Fleet::agent_action_status`].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum BulkActionResult {
    Action {
        #[serde(rename = "actionId")]
        action_id: String,
    },
    /// The number of selected agents. Eligibility is not checked for every agent.
    DryRun { count: u64 },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[non_exhaustive]
pub enum DiagnosticMetric {
    #[serde(rename = "CPU")]
    Cpu,
}

/// Inspect failure counts and errors, including while the action is `IN_PROGRESS`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AgentUpload {
    pub id: String,
    pub name: String,
    pub action_id: String,
    /// `READY` once the file can be downloaded.
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct AgentPolicy {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub revision: u64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// Present when listed with agent counts.
    #[serde(default)]
    pub agents: Option<u64>,
    /// Populated when listed with full policies.
    #[serde(default)]
    pub package_policies: Vec<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An agent policy definition for [`Fleet::create_agent_policy`] and
/// [`Fleet::update_agent_policy`].
#[derive(Clone, Debug, Serialize)]
pub struct NewAgentPolicy {
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monitoring_enabled: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_output_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inactivity_timeout: Option<u64>,
}

impl NewAgentPolicy {
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

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Agent self-monitoring to collect: `logs`, `metrics` and `traces`. Empty disables it.
    pub fn monitoring_enabled<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        kinds: I,
    ) -> Self {
        self.monitoring_enabled = Some(kinds.into_iter().map(Into::into).collect());
        self
    }

    pub fn data_output_id(mut self, id: impl Into<String>) -> Self {
        self.data_output_id = Some(id.into());
        self
    }

    /// Seconds without check-in before an agent is considered inactive.
    pub fn inactivity_timeout(mut self, seconds: u64) -> Self {
        self.inactivity_timeout = Some(seconds);
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PackageRef {
    pub name: String,
    pub version: String,
}

impl PackageRef {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
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
    pub extra: Map<String, Value>,
}

/// One input in Fleet's simplified package-policy format. Input, stream and
/// variable names depend on the package.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PolicyInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    streams: BTreeMap<String, PolicyStream>,
}

impl PolicyInput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn var(mut self, name: impl Into<String>, value: Value) -> Self {
        self.vars.insert(name.into(), value);
        self
    }

    pub fn stream(mut self, name: impl Into<String>, stream: PolicyStream) -> Self {
        self.streams.insert(name.into(), stream);
        self
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PolicyStream {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<String, Value>,
}

impl PolicyStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn var(mut self, name: impl Into<String>, value: Value) -> Self {
        self.vars.insert(name.into(), value);
        self
    }
}

/// A package policy in the simplified format, for [`Fleet::create_package_policy`]
/// and [`Fleet::update_package_policy`]. Unset inputs use package defaults.
#[derive(Clone, Debug, Serialize)]
pub struct NewPackagePolicy {
    name: String,
    namespace: String,
    policy_ids: Vec<String>,
    package: PackageRef,
    inputs: BTreeMap<String, PolicyInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl NewPackagePolicy {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, package: PackageRef) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            policy_ids: Vec::new(),
            package,
            inputs: BTreeMap::new(),
            description: None,
        }
    }

    /// Assigns the package policy to an agent policy. Repeat for several policies.
    pub fn policy_id(mut self, id: impl Into<String>) -> Self {
        self.policy_ids.push(id.into());
        self
    }

    /// Configures an input by name, such as `system-logfile`.
    pub fn input(mut self, name: impl Into<String>, input: PolicyInput) -> Self {
        self.inputs.insert(name.into(), input);
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Package {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// For example `installed` or `not_installed`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
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
    /// Fields such as `policy_revision`, `tags` and `last_checkin`.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct Fleet<'a>(pub(crate) &'a Kibana);

impl AgentActionStatus {
    /// Whether the action can no longer progress: `COMPLETE`, `FAILED`,
    /// `CANCELLED`, `EXPIRED` or `ROLLOUT_PASSED`. Check the failure counts too.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status.as_str(),
            "COMPLETE" | "FAILED" | "CANCELLED" | "EXPIRED" | "ROLLOUT_PASSED"
        )
    }
}

impl AgentUpload {
    /// Whether the upload can no longer change: `READY`, `FAILED`, `EXPIRED` or `DELETED`.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status.as_str(),
            "READY" | "FAILED" | "EXPIRED" | "DELETED"
        )
    }
}

impl<'a> Fleet<'a> {
    /// Waits until an agent action finishes. The action is looked up among the
    /// 100 most recent actions, so start waiting soon after submitting it.
    pub async fn wait_for_action(
        &self,
        action_id: &str,
        options: PollOptions,
    ) -> Result<WaitOutcome<AgentActionStatus>> {
        poll::wait(
            options,
            || async {
                let actions = self
                    .agent_action_status()
                    .per_page(100)
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(actions.items.into_iter().find(|a| a.action_id == action_id))
            },
            AgentActionStatus::is_finished,
        )
        .await
    }

    /// Waits until the upload created by a diagnostics action finishes.
    /// Download it with [`download_agent_file`](Self::download_agent_file) once it is `READY`.
    pub async fn wait_for_upload(
        &self,
        agent_id: &str,
        action_id: &str,
        options: PollOptions,
    ) -> Result<WaitOutcome<AgentUpload>> {
        poll::wait(
            options,
            || async {
                let uploads = self
                    .list_agent_uploads(agent_id)
                    .send()
                    .await?
                    .json()
                    .await?;
                Ok(uploads.items.into_iter().find(|u| u.action_id == action_id))
            },
            AgentUpload::is_finished,
        )
        .await
    }

    /// Waits until the agent is online and reports `policy_id` at `revision` or later.
    pub async fn wait_for_agent_policy(
        &self,
        agent_id: &str,
        policy_id: &str,
        revision: u64,
        options: PollOptions,
    ) -> Result<WaitOutcome<Agent>> {
        poll::wait(
            options,
            || async {
                Ok(Some(
                    self.get_agent(agent_id).send().await?.json().await?.item,
                ))
            },
            |agent| {
                agent.policy_id.as_deref() == Some(policy_id)
                    && agent.status.as_deref() == Some("online")
                    && agent
                        .extra
                        .get("policy_revision")
                        .and_then(Value::as_u64)
                        .is_some_and(|current| current >= revision)
            },
        )
        .await
    }

    /// Initializes Fleet in the current space. Safe to repeat.
    pub fn setup(&self) -> Setup<'a> {
        Setup(
            self.0
                .request(Method::POST, Scope::Space, &["api", "fleet", "setup"]),
        )
    }

    pub fn find_enrollment_keys(&self) -> FindEnrollmentKeys<'a> {
        FindEnrollmentKeys(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys"],
        ))
    }

    pub fn get_enrollment_key(&self, id: &str) -> GetEnrollmentKey<'a> {
        GetEnrollmentKey(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys", id],
        ))
    }

    pub fn create_enrollment_key(&self, policy_id: &str) -> CreateEnrollmentKey<'a> {
        CreateEnrollmentKey(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "enrollment_api_keys"],
                )
                .field("policy_id", policy_id),
        )
    }

    /// Revokes future enrollment. Already enrolled agents keep their own credentials.
    pub fn revoke_enrollment_key(&self, id: &str) -> RevokeEnrollmentKey<'a> {
        RevokeEnrollmentKey(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys", id],
        ))
    }

    pub fn find_agents(&self) -> FindAgents<'a> {
        FindAgents(
            self.0
                .request(Method::GET, Scope::Space, &["api", "fleet", "agents"]),
        )
    }

    pub fn get_agent(&self, id: &str) -> GetAgent<'a> {
        GetAgent(
            self.0
                .request(Method::GET, Scope::Space, &["api", "fleet", "agents", id]),
        )
    }

    /// Agent counts by status.
    pub fn agent_status(&self) -> AgentStatus<'a> {
        AgentStatus(
            self.0
                .request(Method::GET, Scope::Space, &["api", "fleet", "agent_status"]),
        )
    }

    pub fn reassign_agent(&self, id: &str, policy_id: &str) -> ReassignAgent<'a> {
        ReassignAgent(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", id, "reassign"],
                )
                .field("policy_id", policy_id),
        )
    }

    pub fn unenroll_agent(&self, id: &str) -> UnenrollAgent<'a> {
        UnenrollAgent(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", id, "unenroll"],
                )
                .json(&json!({})),
        )
    }

    /// Schedules an upgrade; the acknowledgment is not proof of completion.
    /// Container agents cannot perform Fleet-managed binary upgrades.
    pub fn upgrade_agent(&self, id: &str, version: &str) -> UpgradeAgent<'a> {
        UpgradeAgent(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", id, "upgrade"],
                )
                .field("version", version),
        )
    }

    /// Correlate the returned action ID with [`list_agent_uploads`](Self::list_agent_uploads).
    pub fn request_agent_diagnostics(&self, id: &str) -> RequestAgentDiagnostics<'a> {
        RequestAgentDiagnostics(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", id, "request_diagnostics"],
                )
                .json(&json!({})),
        )
    }

    pub fn bulk_reassign_agents(
        &self,
        agents: AgentSelection,
        policy_id: &str,
    ) -> BulkReassignAgents<'a> {
        BulkReassignAgents(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "bulk_reassign"],
                )
                .field("agents", agents)
                .field("policy_id", policy_id),
        )
    }

    pub fn bulk_unenroll_agents(&self, agents: AgentSelection) -> BulkUnenrollAgents<'a> {
        BulkUnenrollAgents(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "bulk_unenroll"],
                )
                .field("agents", agents),
        )
    }

    pub fn bulk_update_agent_tags(&self, agents: AgentSelection) -> BulkUpdateAgentTags<'a> {
        BulkUpdateAgentTags(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "bulk_update_agent_tags"],
                )
                .field("agents", agents),
        )
    }

    pub fn bulk_upgrade_agents(
        &self,
        agents: AgentSelection,
        version: &str,
    ) -> BulkUpgradeAgents<'a> {
        BulkUpgradeAgents(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "bulk_upgrade"],
                )
                .field("agents", agents)
                .field("version", version),
        )
    }

    pub fn bulk_request_agent_diagnostics(
        &self,
        agents: AgentSelection,
    ) -> BulkRequestAgentDiagnostics<'a> {
        BulkRequestAgentDiagnostics(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "bulk_request_diagnostics"],
                )
                .field("agents", agents),
        )
    }

    /// Recent agent actions with completion and failure counts. Pages start at zero.
    pub fn agent_action_status(&self) -> AgentActionStatuses<'a> {
        AgentActionStatuses(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", "action_status"],
        ))
    }

    /// Kibana supports cancellation of upgrade and unenrollment actions only.
    pub fn cancel_agent_action(&self, action_id: &str) -> CancelAgentAction<'a> {
        CancelAgentAction(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agents", "actions", action_id, "cancel"],
                )
                .json(&json!({})),
        )
    }

    pub fn list_agent_uploads(&self, agent_id: &str) -> ListAgentUploads<'a> {
        ListAgentUploads(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", agent_id, "uploads"],
        ))
    }

    /// Downloads an upload after it reports `READY`. Diagnostic archives can
    /// contain sensitive configuration.
    pub fn download_agent_file(&self, file_id: &str, file_name: &str) -> DownloadAgentFile<'a> {
        DownloadAgentFile(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agents", "files", file_id, file_name],
        ))
    }

    /// Requests full policies with agent counts, which populate
    /// [`AgentPolicy::package_policies`] and [`AgentPolicy::agents`].
    pub fn find_agent_policies(&self) -> FindAgentPolicies<'a> {
        FindAgentPolicies(
            self.0
                .request(
                    Method::GET,
                    Scope::Space,
                    &["api", "fleet", "agent_policies"],
                )
                .param("full", true)
                .param("withAgentCount", true),
        )
    }

    pub fn get_agent_policy(&self, id: &str) -> GetAgentPolicy<'a> {
        GetAgentPolicy(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agent_policies", id],
        ))
    }

    /// Creates a policy from a [`NewAgentPolicy`] or equivalent JSON.
    pub fn create_agent_policy<B: Serialize + ?Sized>(&self, policy: &B) -> CreateAgentPolicy<'a> {
        CreateAgentPolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agent_policies"],
                )
                .json(policy),
        )
    }

    /// Replaces the policy definition and increments its revision.
    pub fn update_agent_policy<B: Serialize + ?Sized>(
        &self,
        id: &str,
        policy: &B,
    ) -> UpdateAgentPolicy<'a> {
        UpdateAgentPolicy(
            self.0
                .request(
                    Method::PUT,
                    Scope::Space,
                    &["api", "fleet", "agent_policies", id],
                )
                .json(policy),
        )
    }

    pub fn delete_agent_policy(&self, id: &str) -> DeleteAgentPolicy<'a> {
        DeleteAgentPolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agent_policies", "delete"],
                )
                .field("agentPolicyId", id),
        )
    }

    pub fn copy_agent_policy(&self, id: &str, name: &str) -> CopyAgentPolicy<'a> {
        CopyAgentPolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agent_policies", id, "copy"],
                )
                .field("name", name),
        )
    }

    /// The agent configuration as YAML.
    pub fn download_agent_policy(&self, id: &str) -> DownloadAgentPolicy<'a> {
        DownloadAgentPolicy(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "agent_policies", id, "download"],
        ))
    }

    pub fn find_package_policies(&self) -> FindPackagePolicies<'a> {
        FindPackagePolicies(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "package_policies"],
        ))
    }

    pub fn get_package_policy(&self, id: &str) -> GetPackagePolicy<'a> {
        GetPackagePolicy(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "package_policies", id],
        ))
    }

    /// Creates a package policy from a [`NewPackagePolicy`] or equivalent JSON
    /// in the simplified format.
    pub fn create_package_policy<B: Serialize + ?Sized>(
        &self,
        policy: &B,
    ) -> CreatePackagePolicy<'a> {
        CreatePackagePolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "package_policies"],
                )
                .param("format", "simplified")
                .json(policy),
        )
    }

    /// Replaces a package policy with a definition in the simplified format.
    pub fn update_package_policy<B: Serialize + ?Sized>(
        &self,
        id: &str,
        policy: &B,
    ) -> UpdatePackagePolicy<'a> {
        UpdatePackagePolicy(
            self.0
                .request(
                    Method::PUT,
                    Scope::Space,
                    &["api", "fleet", "package_policies", id],
                )
                .param("format", "simplified")
                .json(policy),
        )
    }

    pub fn delete_package_policy(&self, id: &str) -> DeletePackagePolicy<'a> {
        DeletePackagePolicy(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "fleet", "package_policies", id],
        ))
    }

    /// Packages available from the configured registry, with install status.
    pub fn list_packages(&self) -> ListPackages<'a> {
        ListPackages(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "epm", "packages"],
        ))
    }

    pub fn get_package(&self, name: &str, version: &str) -> GetPackage<'a> {
        GetPackage(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "epm", "packages", name, version],
        ))
    }

    /// Installs package assets such as index templates and dashboards.
    pub fn install_package(&self, name: &str, version: &str) -> InstallPackage<'a> {
        InstallPackage(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "epm", "packages", name, version],
                )
                .json(&json!({})),
        )
    }

    pub fn uninstall_package(&self, name: &str, version: &str) -> UninstallPackage<'a> {
        UninstallPackage(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "fleet", "epm", "packages", name, version],
        ))
    }

    pub fn list_outputs(&self) -> ListOutputs<'a> {
        ListOutputs(
            self.0
                .request(Method::GET, Scope::Space, &["api", "fleet", "outputs"]),
        )
    }
}

/// Pagination and KQL filtering for Fleet collections, whose pages start at one.
macro_rules! page_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// One-based page number.
            pub fn page(self, page: u32) -> Self {
                Self(self.0.param("page", page))
            }

            pub fn per_page(self, per_page: u32) -> Self {
                Self(self.0.param("perPage", per_page))
            }

            /// A KQL filter over the collection's fields.
            pub fn kuery(self, kuery: &str) -> Self {
                Self(self.0.param("kuery", kuery))
            }
        }
    )*};
}

macro_rules! sort_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            pub fn sort_field(self, field: &str) -> Self {
                Self(self.0.param("sortField", field))
            }

            pub fn sort_order(self, order: SortOrder) -> Self {
                Self(self.0.param("sortOrder", order.as_str()))
            }
        }
    )*};
}

macro_rules! bulk_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// Returns the number of selected agents instead of creating an action.
            pub fn dry_run(self, dry_run: bool) -> Self {
                Self(self.0.field("dryRun", dry_run))
            }

            /// How many agents Kibana processes per batch for query selections.
            pub fn batch_size(self, size: u32) -> Self {
                Self(self.0.field("batchSize", size))
            }
        }
    )*};
}

macro_rules! include_inactive_setter {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// Also selects inactive agents matched by a query.
            pub fn include_inactive(self, include: bool) -> Self {
                Self(self.0.field("includeInactive", include))
            }
        }
    )*};
}

macro_rules! upgrade_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// Upgrades even when Fleet considers the agent ineligible.
            pub fn force(self, force: bool) -> Self {
                Self(self.0.field("force", force))
            }

            /// Downloads agent binaries from this URI instead of the default source.
            pub fn source_uri(self, uri: &str) -> Self {
                Self(self.0.field("source_uri", uri))
            }

            pub fn skip_rate_limit_check(self, skip: bool) -> Self {
                Self(self.0.field("skipRateLimitCheck", skip))
            }
        }
    )*};
}

macro_rules! diagnostics_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            pub fn additional_metrics(self, metrics: Vec<DiagnosticMetric>) -> Self {
                Self(self.0.field("additional_metrics", metrics))
            }
        }
    )*};
}

endpoint! {
    /// `POST /api/fleet/setup`
    Setup => Value
}

endpoint! {
    /// `GET /api/fleet/enrollment_api_keys`
    FindEnrollmentKeys => FleetPage<EnrollmentKey>
}

endpoint! {
    /// `GET /api/fleet/enrollment_api_keys/{keyId}`
    GetEnrollmentKey => Item<EnrollmentKey>
}

endpoint! {
    /// `POST /api/fleet/enrollment_api_keys`
    CreateEnrollmentKey => Item<EnrollmentKey>
}

impl CreateEnrollmentKey<'_> {
    pub fn name(self, name: &str) -> Self {
        Self(self.0.field("name", name))
    }

    /// An Elastic duration after which the key expires, for example `24h`.
    pub fn expiration(self, duration: &str) -> Self {
        Self(self.0.field("expiration", duration))
    }
}

endpoint! {
    /// `DELETE /api/fleet/enrollment_api_keys/{keyId}`
    RevokeEnrollmentKey => Value
}

endpoint! {
    /// `GET /api/fleet/agents`
    FindAgents => FleetPage<Agent>
}

impl FindAgents<'_> {
    pub fn show_inactive(self, show: bool) -> Self {
        Self(self.0.param("showInactive", show))
    }
}

endpoint! {
    /// `GET /api/fleet/agents/{agentId}`
    GetAgent => Item<Agent>
}

endpoint! {
    /// `GET /api/fleet/agent_status`
    AgentStatus => Value
}

impl AgentStatus<'_> {
    pub fn policy_id(self, id: &str) -> Self {
        Self(self.0.param("policyId", id))
    }

    pub fn kuery(self, kuery: &str) -> Self {
        Self(self.0.param("kuery", kuery))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/{agentId}/reassign`
    ReassignAgent => Value
}

endpoint! {
    /// `POST /api/fleet/agents/{agentId}/unenroll`
    UnenrollAgent => Value
}

impl UnenrollAgent<'_> {
    /// Removes the agent immediately instead of waiting for it to acknowledge.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.field("force", force))
    }

    /// Revokes the agent's API keys.
    pub fn revoke(self, revoke: bool) -> Self {
        Self(self.0.field("revoke", revoke))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/{agentId}/upgrade`
    UpgradeAgent => Value
}

endpoint! {
    /// `POST /api/fleet/agents/{agentId}/request_diagnostics`
    RequestAgentDiagnostics => BulkActionResult
}

endpoint! {
    /// `POST /api/fleet/agents/bulk_reassign`
    BulkReassignAgents => BulkActionResult
}

endpoint! {
    /// `POST /api/fleet/agents/bulk_unenroll`
    BulkUnenrollAgents => BulkActionResult
}

impl BulkUnenrollAgents<'_> {
    /// Removes agents immediately instead of waiting for them to acknowledge.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.field("force", force))
    }

    /// Revokes the agents' API keys.
    pub fn revoke(self, revoke: bool) -> Self {
        Self(self.0.field("revoke", revoke))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/bulk_update_agent_tags`
    BulkUpdateAgentTags => BulkActionResult
}

impl BulkUpdateAgentTags<'_> {
    pub fn add_tags<I: IntoIterator<Item = S>, S: Into<String>>(self, tags: I) -> Self {
        let tags: Vec<String> = tags.into_iter().map(Into::into).collect();
        Self(self.0.field("tagsToAdd", tags))
    }

    pub fn remove_tags<I: IntoIterator<Item = S>, S: Into<String>>(self, tags: I) -> Self {
        let tags: Vec<String> = tags.into_iter().map(Into::into).collect();
        Self(self.0.field("tagsToRemove", tags))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/bulk_upgrade`
    BulkUpgradeAgents => BulkActionResult
}

impl BulkUpgradeAgents<'_> {
    /// An ISO 8601 time at which the rollout starts.
    pub fn start_time(self, time: &str) -> Self {
        Self(self.0.field("start_time", time))
    }

    /// Spreads upgrades over this many seconds.
    pub fn rollout_duration_seconds(self, seconds: u64) -> Self {
        Self(self.0.field("rollout_duration_seconds", seconds))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/bulk_request_diagnostics`
    BulkRequestAgentDiagnostics => BulkActionResult
}

endpoint! {
    /// `GET /api/fleet/agents/action_status`
    AgentActionStatuses => Items<AgentActionStatus>
}

impl AgentActionStatuses<'_> {
    /// Zero-based page number, unlike Fleet resource collections.
    pub fn page(self, page: u32) -> Self {
        Self(self.0.param("page", page))
    }

    pub fn per_page(self, per_page: u32) -> Self {
        Self(self.0.param("perPage", per_page))
    }

    /// Only actions created after this ISO 8601 time.
    pub fn date(self, date: &str) -> Self {
        Self(self.0.param("date", date))
    }

    /// Only actions from the last `seconds`.
    pub fn latest(self, seconds: u32) -> Self {
        Self(self.0.param("latest", seconds))
    }

    /// How many recent errors to include per action.
    pub fn error_size(self, size: u32) -> Self {
        Self(self.0.param("errorSize", size))
    }
}

endpoint! {
    /// `POST /api/fleet/agents/actions/{actionId}/cancel`
    CancelAgentAction => Value
}

endpoint! {
    /// `GET /api/fleet/agents/{agentId}/uploads`
    ListAgentUploads => Items<AgentUpload>
}

endpoint! {
    /// `GET /api/fleet/agents/files/{fileId}/{fileName}`
    DownloadAgentFile => Raw
}

endpoint! {
    /// `GET /api/fleet/agent_policies`
    FindAgentPolicies => FleetPage<AgentPolicy>
}

impl FindAgentPolicies<'_> {
    /// Populates package policies. Enabled by default.
    pub fn full(self, full: bool) -> Self {
        Self(self.0.param("full", full))
    }

    /// Populates agent counts. Enabled by default.
    pub fn with_agent_count(self, enabled: bool) -> Self {
        Self(self.0.param("withAgentCount", enabled))
    }
}

endpoint! {
    /// `GET /api/fleet/agent_policies/{agentPolicyId}`
    GetAgentPolicy => Item<AgentPolicy>
}

endpoint! {
    /// `POST /api/fleet/agent_policies`
    CreateAgentPolicy => Item<AgentPolicy>
}

impl CreateAgentPolicy<'_> {
    /// Also adds the System integration to the new policy.
    pub fn sys_monitoring(self, enabled: bool) -> Self {
        Self(self.0.param("sys_monitoring", enabled))
    }
}

endpoint! {
    /// `PUT /api/fleet/agent_policies/{agentPolicyId}`
    UpdateAgentPolicy => Item<AgentPolicy>
}

endpoint! {
    /// `POST /api/fleet/agent_policies/delete`
    DeleteAgentPolicy => Value
}

impl DeleteAgentPolicy<'_> {
    pub fn force(self, force: bool) -> Self {
        Self(self.0.field("force", force))
    }
}

endpoint! {
    /// `POST /api/fleet/agent_policies/{agentPolicyId}/copy`
    CopyAgentPolicy => Item<AgentPolicy>
}

impl CopyAgentPolicy<'_> {
    pub fn description(self, description: &str) -> Self {
        Self(self.0.field("description", description))
    }
}

endpoint! {
    /// `GET /api/fleet/agent_policies/{agentPolicyId}/download`
    DownloadAgentPolicy => Raw
}

impl DownloadAgentPolicy<'_> {
    /// Produces a configuration for a standalone, non-Fleet agent.
    pub fn standalone(self, enabled: bool) -> Self {
        Self(self.0.param("standalone", enabled))
    }

    /// Produces a Kubernetes manifest.
    pub fn kubernetes(self, enabled: bool) -> Self {
        Self(self.0.param("kubernetes", enabled))
    }
}

endpoint! {
    /// `GET /api/fleet/package_policies`
    FindPackagePolicies => FleetPage<PackagePolicy>
}

endpoint! {
    /// `GET /api/fleet/package_policies/{packagePolicyId}`
    GetPackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `POST /api/fleet/package_policies`
    CreatePackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `PUT /api/fleet/package_policies/{packagePolicyId}`
    UpdatePackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `DELETE /api/fleet/package_policies/{packagePolicyId}`
    DeletePackagePolicy => Value
}

impl DeletePackagePolicy<'_> {
    /// Deletes even when the package policy is managed.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.param("force", force))
    }
}

endpoint! {
    /// `GET /api/fleet/epm/packages`
    ListPackages => Items<Package>
}

impl ListPackages<'_> {
    pub fn category(self, category: &str) -> Self {
        Self(self.0.param("category", category))
    }

    pub fn prerelease(self, include: bool) -> Self {
        Self(self.0.param("prerelease", include))
    }
}

endpoint! {
    /// `GET /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
    GetPackage => Item<Package>
}

endpoint! {
    /// `POST /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
    InstallPackage => Value
}

impl InstallPackage<'_> {
    /// Reinstalls or installs despite version constraints.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.field("force", force))
    }

    pub fn ignore_constraints(self, ignore: bool) -> Self {
        Self(self.0.field("ignore_constraints", ignore))
    }
}

endpoint! {
    /// `DELETE /api/fleet/epm/packages/{pkgName}/{pkgVersion}`
    UninstallPackage => Value
}

impl UninstallPackage<'_> {
    pub fn force(self, force: bool) -> Self {
        Self(self.0.param("force", force))
    }
}

endpoint! {
    /// `GET /api/fleet/outputs`
    ListOutputs => Value
}

page_setters!(
    FindEnrollmentKeys,
    FindAgents,
    FindAgentPolicies,
    FindPackagePolicies
);
sort_setters!(FindAgents, FindAgentPolicies, FindPackagePolicies);
bulk_setters!(
    BulkReassignAgents,
    BulkUnenrollAgents,
    BulkUpdateAgentTags,
    BulkUpgradeAgents,
    BulkRequestAgentDiagnostics
);
include_inactive_setter!(
    BulkReassignAgents,
    BulkUnenrollAgents,
    BulkUpdateAgentTags,
    BulkUpgradeAgents
);
upgrade_setters!(UpgradeAgent, BulkUpgradeAgents);
diagnostics_setters!(RequestAgentDiagnostics, BulkRequestAgentDiagnostics);
paginated!(
    FindEnrollmentKeys => FleetPage<EnrollmentKey>,
    FindAgents => FleetPage<Agent>,
    FindAgentPolicies => FleetPage<AgentPolicy>,
    FindPackagePolicies => FleetPage<PackagePolicy>,
);
