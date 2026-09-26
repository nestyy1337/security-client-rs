//! Agent policies, integration packages, package policies, and enrolled agents.
//! Package installation changes assets; assigning a package policy changes agent
//! configuration. These are separate operations with separate results.
use crate::{Client, PageOptions, Result, Scope};
use reqwest::{Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

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
