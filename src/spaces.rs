//! Kibana space administration. Space routes are global even on a scoped client.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    Kibana, Scope,
    http::{Empty, Method},
    request::endpoint,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Space {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, rename = "disabledFeatures")]
    pub disabled_features: Vec<String>,
    /// Fields such as `color`, `initials` and `solution`, kept for round trips.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Space {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            disabled_features: Vec::new(),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Spaces<'a>(pub(crate) &'a Kibana);

impl<'a> Spaces<'a> {
    pub fn list(&self) -> ListSpaces<'a> {
        ListSpaces(
            self.0
                .request(Method::GET, Scope::Global, &["api", "spaces", "space"]),
        )
    }

    pub fn get(&self, id: &str) -> GetSpace<'a> {
        GetSpace(
            self.0
                .request(Method::GET, Scope::Global, &["api", "spaces", "space", id]),
        )
    }

    /// Creates a space from a [`Space`] or any JSON object with `id` and `name`.
    pub fn create<B: Serialize + ?Sized>(&self, space: &B) -> CreateSpace<'a> {
        CreateSpace(
            self.0
                .request(Method::POST, Scope::Global, &["api", "spaces", "space"])
                .json(space),
        )
    }

    /// Replaces the space's definition. The JSON object body must contain a
    /// string `id` matching the path argument. Missing, non-string or conflicting
    /// IDs fail with [`crate::Error::InvalidRequest`] before HTTP.
    pub fn update<B: Serialize + ?Sized>(&self, id: &str, space: &B) -> UpdateSpace<'a> {
        UpdateSpace(
            self.0
                .request(Method::PUT, Scope::Global, &["api", "spaces", "space", id])
                .json(space)
                .check_body_id(id, true),
        )
    }

    /// Deletes the space and every saved object inside it.
    pub fn delete(&self, id: &str) -> DeleteSpace<'a> {
        DeleteSpace(self.0.request(
            Method::DELETE,
            Scope::Global,
            &["api", "spaces", "space", id],
        ))
    }
}

endpoint! {
    /// `GET /api/spaces/space`
    ListSpaces => Vec<Space>
}

endpoint! {
    /// `GET /api/spaces/space/{id}`
    GetSpace => Space
}

endpoint! {
    /// `POST /api/spaces/space`
    CreateSpace => Space
}

endpoint! {
    /// `PUT /api/spaces/space/{id}`
    UpdateSpace => Space
}

endpoint! {
    /// `DELETE /api/spaces/space/{id}`
    DeleteSpace => Empty
}
