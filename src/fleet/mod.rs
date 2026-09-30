//! Agent policies, integration packages, package policies, and enrolled agents.
//!
//! Installing a package changes assets; assigning a package policy changes agent
//! configuration. Agent actions are asynchronous: a submitted action ID is not
//! proof of completion, so follow it through [`Fleet::agent_action_status`] or
//! [`Fleet::wait_for_action`].
//!
//! Package policies have two formats. [`NewPackagePolicy`] builds Fleet's
//! simplified format, keyed by input and stream name. A retrieved
//! [`PackagePolicy`] holds the full format; change it through
//! [`PackagePolicy::edit`] to keep its existing configuration.
//! Agent-policy edits use [`AgentPolicy::edit`] and [`Fleet::edit_agent_policy`]
//! to retain the inactivity timeout. Optional settings are changed only when
//! requested; [`AgentPolicyEdit::clear_data_output_id`] restores the default
//! output with JSON null.
//!
//! Policy variables can hold credentials, so `Debug` output of package policies
//! and their inputs omits variable values.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Kibana, Scope, http::Method, request::endpoint};

/// Pagination and KQL filtering for Fleet collections, whose pages start at one.
macro_rules! page_setters {
    ($($name:ident),*) => {$(
        impl $name<'_> {
            /// One-based page number.
            pub fn page(self, page: u32) -> Self {
                Self(self.0.positive_param("page", page))
            }

            pub fn per_page(self, per_page: u32) -> Self {
                Self(self.0.positive_param("perPage", per_page))
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

            pub fn sort_order(self, order: $crate::SortOrder) -> Self {
                Self(self.0.param("sortOrder", order.as_str()))
            }
        }
    )*};
}

mod actions;
mod agent_policies;
mod agents;
mod enrollment;
mod package_policies;
mod packages;
mod wait;

pub use actions::{
    ActionStatus, AgentActionStatus, AgentActionStatuses, AgentUpload, CancelAgentAction,
    DownloadAgentFile, ListAgentUploads, UploadStatus,
};
pub use agent_policies::{
    AgentPolicy, AgentPolicyEdit, CopyAgentPolicy, CreateAgentPolicy, DeleteAgentPolicy,
    DownloadAgentPolicy, FindAgentPolicies, GetAgentPolicy, NewAgentPolicy, UpdateAgentPolicy,
};
pub use agents::{
    Agent, AgentSelection, AgentStatus, BulkActionResult, BulkReassignAgents,
    BulkRequestAgentDiagnostics, BulkUnenrollAgents, BulkUpdateAgentTags, BulkUpgradeAgents,
    DiagnosticMetric, FindAgents, GetAgent, ReassignAgent, RequestAgentDiagnostics, UnenrollAgent,
    UpgradeAgent,
};
pub use enrollment::{
    CreateEnrollmentKey, EnrollmentKey, FindEnrollmentKeys, GetEnrollmentKey, RevokeEnrollmentKey,
};
pub use package_policies::{
    CreatePackagePolicy, DeletePackagePolicy, FindPackagePolicies, GetPackagePolicy,
    NewPackagePolicy, PackagePolicy, PackagePolicyEdit, PackagePolicyUpdate, PackageRef,
    PolicyInput, PolicyStream, UpdatePackagePolicy,
};
pub use packages::{GetPackage, InstallPackage, ListPackages, Package, UninstallPackage};

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

/// The Fleet API. Endpoints are grouped by resource in private modules and
/// re-exported here.
#[derive(Clone, Copy, Debug)]
pub struct Fleet<'a>(pub(crate) &'a Kibana);

impl<'a> Fleet<'a> {
    /// Initializes Fleet in the current space. Safe to repeat.
    pub fn setup(&self) -> Setup<'a> {
        Setup(
            self.0
                .request(Method::POST, Scope::Space, &["api", "fleet", "setup"]),
        )
    }

    pub fn list_outputs(&self) -> ListOutputs<'a> {
        ListOutputs(
            self.0
                .request(Method::GET, Scope::Space, &["api", "fleet", "outputs"]),
        )
    }
}

endpoint! {
    /// `POST /api/fleet/setup`
    Setup => Value
}

endpoint! {
    /// `GET /api/fleet/outputs`
    ListOutputs => Value
}
