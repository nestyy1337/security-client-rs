//! Agent policies, which group the package policies an agent runs.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Fleet, FleetPage, Item};
use crate::{
    Scope,
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
