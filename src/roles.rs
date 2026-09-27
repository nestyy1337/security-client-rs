//! Kibana role administration. Role routes are global even on a scoped client.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    Kibana, Scope,
    http::{Empty, Method},
    request::endpoint,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KibanaPrivilege {
    pub spaces: Vec<String>,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub feature: BTreeMap<String, Vec<String>>,
}

impl KibanaPrivilege {
    /// Grants base privileges such as `read` or `all` in the given spaces.
    pub fn new(spaces: Vec<String>, base: Vec<String>) -> Self {
        Self {
            spaces,
            base,
            feature: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RoleDefinition {
    /// Elasticsearch cluster, index and run-as privileges, as in the Elasticsearch role API.
    pub elasticsearch: Value,
    #[serde(default)]
    pub kibana: Vec<KibanaPrivilege>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

impl RoleDefinition {
    pub fn new(elasticsearch: Value, kibana: Vec<KibanaPrivilege>) -> Self {
        Self {
            elasticsearch,
            kibana,
            description: None,
            metadata: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Role {
    pub name: String,
    #[serde(flatten)]
    pub definition: RoleDefinition,
    /// Read-only fields such as `transient_metadata`.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub struct Roles<'a>(pub(crate) &'a Kibana);

impl<'a> Roles<'a> {
    pub fn list(&self) -> ListRoles<'a> {
        ListRoles(
            self.0
                .request(Method::GET, Scope::Global, &["api", "security", "role"]),
        )
    }

    pub fn get(&self, name: &str) -> GetRole<'a> {
        GetRole(self.0.request(
            Method::GET,
            Scope::Global,
            &["api", "security", "role", name],
        ))
    }

    /// Creates or replaces a role from a [`RoleDefinition`] or equivalent JSON.
    pub fn put<B: Serialize + ?Sized>(&self, name: &str, role: &B) -> PutRole<'a> {
        PutRole(
            self.0
                .request(
                    Method::PUT,
                    Scope::Global,
                    &["api", "security", "role", name],
                )
                .json(role),
        )
    }

    pub fn delete(&self, name: &str) -> DeleteRole<'a> {
        DeleteRole(self.0.request(
            Method::DELETE,
            Scope::Global,
            &["api", "security", "role", name],
        ))
    }
}

endpoint! {
    /// `GET /api/security/role`
    ListRoles => Vec<Role>
}

endpoint! {
    /// `GET /api/security/role/{name}`
    GetRole => Role
}

endpoint! {
    /// `PUT /api/security/role/{name}`
    PutRole => Empty
}

impl PutRole<'_> {
    /// Fails with HTTP 409 instead of replacing an existing role.
    pub fn create_only(self, enabled: bool) -> Self {
        Self(self.0.param("createOnly", enabled))
    }
}

endpoint! {
    /// `DELETE /api/security/role/{name}`
    DeleteRole => Empty
}
