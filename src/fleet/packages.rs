//! Integration packages from the package registry.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{Fleet, Item, Items};
use crate::{Scope, http::Method, request::endpoint};

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

impl<'a> Fleet<'a> {
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
    /// Deletes the package even when it has active package policies.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.param("force", force))
    }
}
