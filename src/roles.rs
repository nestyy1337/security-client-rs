//! Kibana role administration. Role routes are global even on a scoped client.
use crate::{Client, Result, Scope};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KibanaPrivilege {
    pub spaces: Vec<String>,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub feature: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// Elasticsearch index/cluster privileges follow the Elasticsearch role API.
    pub elasticsearch: Value,
    pub kibana: Vec<KibanaPrivilege>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    #[serde(flatten)]
    pub definition: RoleDefinition,
}

pub struct Roles<'a>(pub(crate) &'a Client);
impl Roles<'_> {
    pub async fn list(&self) -> Result<Vec<Role>> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Global, &["api", "security", "role"])?,
            )
            .await
    }
    pub async fn get(&self, name: &str) -> Result<Role> {
        self.0
            .json(self.0.request(
                Method::GET,
                Scope::Global,
                &["api", "security", "role", name],
            )?)
            .await
    }
    pub async fn put(&self, name: &str, role: &RoleDefinition) -> Result<()> {
        self.0
            .empty(
                self.0
                    .request(
                        Method::PUT,
                        Scope::Global,
                        &["api", "security", "role", name],
                    )?
                    .json(role),
            )
            .await
    }
    pub async fn delete(&self, name: &str) -> Result<()> {
        self.0
            .empty(self.0.request(
                Method::DELETE,
                Scope::Global,
                &["api", "security", "role", name],
            )?)
            .await
    }
}
