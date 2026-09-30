//! Enrolled agents and the actions submitted to them.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{Fleet, FleetPage, Item};
use crate::{Scope, http::Method, pagination::paginated, request::endpoint};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Agent {
    pub id: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    /// The revision of `policy_id` the agent last acknowledged. Absent until it
    /// reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<u64>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub local_metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checkin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An explicit ID set or a Fleet KQL query. A query can select many agents.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum AgentSelection {
    Ids(Vec<String>),
    Query(String),
}

/// Submission does not prove completion. Follow an action ID through
/// [`Fleet::agent_action_status`] or [`Fleet::wait_for_action`].
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

impl<'a> Fleet<'a> {
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
                .nonempty("policy_id", policy_id)
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
                .nonempty("version", version)
                .field("version", version),
        )
    }

    /// Correlate the returned action ID with [`list_agent_uploads`](Self::list_agent_uploads)
    /// or [`wait_for_upload`](Self::wait_for_upload).
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
                .nonempty("policy_id", policy_id)
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
                .nonempty("version", version)
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

page_setters!(FindAgents);
sort_setters!(FindAgents);
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
paginated!(FindAgents => FleetPage<Agent>);
