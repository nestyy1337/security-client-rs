use crate::{Client, Result, Scope};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Space {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "disabledFeatures")]
    pub disabled_features: Vec<String>,
}

pub struct Spaces<'a>(pub(crate) &'a Client);

impl Spaces<'_> {
    pub async fn list(&self) -> Result<Vec<Space>> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Global, &["api", "spaces", "space"])?,
            )
            .await
    }
    pub async fn get(&self, id: &str) -> Result<Space> {
        self.0
            .json(
                self.0
                    .request(Method::GET, Scope::Global, &["api", "spaces", "space", id])?,
            )
            .await
    }
    pub async fn create(&self, space: &Space) -> Result<Space> {
        self.0
            .json(
                self.0
                    .request(Method::POST, Scope::Global, &["api", "spaces", "space"])?
                    .json(space),
            )
            .await
    }
    pub async fn update(&self, space: &Space) -> Result<Space> {
        self.0
            .json(
                self.0
                    .request(
                        Method::PUT,
                        Scope::Global,
                        &["api", "spaces", "space", &space.id],
                    )?
                    .json(space),
            )
            .await
    }
    pub async fn delete(&self, id: &str) -> Result<()> {
        self.0
            .empty(self.0.request(
                Method::DELETE,
                Scope::Global,
                &["api", "spaces", "space", id],
            )?)
            .await
    }
}
