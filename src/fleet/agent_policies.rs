//! Agent policies, which group the package policies an agent runs.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Fleet, FleetPage, Item};
use crate::{
    Error, Result, Scope,
    http::{Method, Raw},
    pagination::paginated,
    request::endpoint,
};

/// `Debug` output counts package policies instead of printing them, since
/// their variables can hold credentials.
#[derive(Clone, Deserialize, Serialize)]
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

impl AgentPolicy {
    /// Changes to this policy, bound to its ID. Required name and namespace
    /// start from the retrieved values. The inactivity timeout is retained
    /// because Kibana resets it to two weeks when it is omitted from an update.
    /// Other settings are left unchanged unless their setter is called.
    ///
    /// Returns [`Error::InvalidRequest`] if `extra["inactivity_timeout"]` is
    /// missing or is not an unsigned integer. Fetch the policy again rather
    /// than guessing its timeout.
    ///
    /// Fleet agent-policy updates do not enforce optimistic concurrency;
    /// [`revision`](Self::revision) tracks configuration delivery to agents.
    ///
    /// ```no_run
    /// # async fn rename(client: &kibana_rs::Kibana) -> kibana_rs::Result<()> {
    /// let fleet = client.fleet();
    /// let policy = fleet.get_agent_policy("policy-id").send().await?.json().await?.item;
    /// let edit = policy.edit()?.name("SOC endpoints").clear_data_output_id();
    /// fleet.edit_agent_policy(&edit).send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn edit(&self) -> Result<AgentPolicyEdit> {
        let timeout = self
            .extra
            .get("inactivity_timeout")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                Error::InvalidRequest(
                    "agent policy edit requires a retrieved inactivity_timeout".into(),
                )
            })?;
        Ok(AgentPolicyEdit {
            id: self.id.clone(),
            policy: NewAgentPolicy::new(&self.name, &self.namespace).inactivity_timeout(timeout),
        })
    }
}

impl fmt::Debug for AgentPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentPolicy")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("revision", &self.revision)
            .field("status", &self.status)
            .field("agents", &self.agents)
            .field("package_policies", &self.package_policies.len())
            .finish_non_exhaustive()
    }
}

/// An agent policy definition for [`Fleet::create_agent_policy`] and
/// [`Fleet::update_agent_policy`].
/// For changes to a retrieved policy, prefer [`AgentPolicy::edit`] to retain
/// its inactivity timeout instead of accepting the server's default.
#[derive(Clone, Debug, Serialize)]
pub struct NewAgentPolicy {
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monitoring_enabled: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_output_id: Option<Option<String>>,
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

    /// Selects a data output explicitly. Without this setter or
    /// [`clear_data_output_id`](Self::clear_data_output_id), the field is omitted.
    /// Kibana requires a Platinum license to set a per-policy output.
    pub fn data_output_id(mut self, id: impl Into<String>) -> Self {
        self.data_output_id = Some(Some(id.into()));
        self
    }

    /// Sends `data_output_id: null` to use Fleet's default output.
    /// On update, omission keeps the existing selection; null clears it.
    ///
    /// ```
    /// use kibana_rs::fleet::NewAgentPolicy;
    /// use serde_json::{json, to_value};
    ///
    /// let policy = NewAgentPolicy::new("SOC endpoints", "default");
    /// assert!(to_value(&policy)?.get("data_output_id").is_none());
    /// let selected = policy.data_output_id("output-id");
    /// assert_eq!(to_value(&selected)?["data_output_id"], json!("output-id"));
    /// let cleared = selected.clear_data_output_id();
    /// assert_eq!(to_value(&cleared)?["data_output_id"], json!(null));
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    pub fn clear_data_output_id(mut self) -> Self {
        self.data_output_id = Some(None);
        self
    }

    /// Seconds without check-in before an agent is considered inactive.
    pub fn inactivity_timeout(mut self, seconds: u64) -> Self {
        self.inactivity_timeout = Some(seconds);
        self
    }
}

/// Changes to a retrieved agent policy, created by [`AgentPolicy::edit`] and
/// sent with [`Fleet::edit_agent_policy`].
///
/// The request includes name, namespace and the retained inactivity timeout,
/// plus explicitly changed settings. It omits response metadata, package
/// policies and unknown fields. Unset optional fields keep their server values.
/// Fleet merges submitted attributes and does not check the policy's revision
/// for concurrent updates.
#[derive(Clone, Debug, Serialize)]
pub struct AgentPolicyEdit {
    #[serde(skip)]
    id: String,
    #[serde(flatten)]
    policy: NewAgentPolicy,
}

impl AgentPolicyEdit {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.policy.name = name.into();
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.policy.namespace = namespace.into();
        self
    }

    /// Sets the description. An empty string clears its text.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.policy = self.policy.description(description);
        self
    }

    /// Agent self-monitoring to collect: `logs`, `metrics` and `traces`.
    /// Empty disables it; leaving this unset retains the existing selection.
    pub fn monitoring_enabled<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        kinds: I,
    ) -> Self {
        self.policy = self.policy.monitoring_enabled(kinds);
        self
    }

    /// Selects a data output explicitly. Leaving this unset retains the
    /// existing output selection. Kibana requires a Platinum license to set it.
    pub fn data_output_id(mut self, id: impl Into<String>) -> Self {
        self.policy = self.policy.data_output_id(id);
        self
    }

    /// Clears the output selection with JSON null, restoring Fleet's default.
    pub fn clear_data_output_id(mut self) -> Self {
        self.policy = self.policy.clear_data_output_id();
        self
    }

    /// Seconds without check-in before an agent is considered inactive.
    /// Leaving this unset retains the retrieved timeout.
    pub fn inactivity_timeout(mut self, seconds: u64) -> Self {
        self.policy = self.policy.inactivity_timeout(seconds);
        self
    }
}

impl<'a> Fleet<'a> {
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

    /// Updates submitted attributes and increments the policy's revision.
    /// Name and namespace are required. Omitting `inactivity_timeout` resets
    /// it to the server's default; prefer [`edit_agent_policy`](Self::edit_agent_policy)
    /// with a retrieved policy's edit to retain it.
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

    /// Applies changes bound to a retrieved policy's ID, retaining its timeout.
    /// Optional settings are changed only when their setter was called.
    pub fn edit_agent_policy(&self, edit: &AgentPolicyEdit) -> UpdateAgentPolicy<'a> {
        self.update_agent_policy(&edit.id, edit)
    }

    pub fn delete_agent_policy(&self, id: &str) -> DeleteAgentPolicy<'a> {
        DeleteAgentPolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "agent_policies", "delete"],
                )
                .nonempty("agentPolicyId", id)
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

page_setters!(FindAgentPolicies);
sort_setters!(FindAgentPolicies);
paginated!(FindAgentPolicies => FleetPage<AgentPolicy>);
