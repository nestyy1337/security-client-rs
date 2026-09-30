//! Package policies: an integration's configuration, assigned to agent policies.
use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Fleet, FleetPage, Item};
use crate::{Scope, http::Method, pagination::paginated, request::endpoint};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PackageRef {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl PackageRef {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            title: None,
        }
    }
}

/// A package policy as Kibana returns it. Reads use Fleet's full format;
/// creation and simplified replacement responses use the simplified format.
///
/// `Debug` output omits inputs, variables and other fields, which can hold credentials.
#[derive(Clone, Deserialize, Serialize)]
#[non_exhaustive]
pub struct PackagePolicy {
    pub id: String,
    pub name: String,
    pub namespace: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    pub revision: u64,
    pub package: PackageRef,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    /// Full-format inputs are an array; simplified inputs are an object keyed by input name.
    #[serde(default)]
    pub inputs: Value,
    /// Package-level variables.
    #[serde(default)]
    pub vars: Option<Value>,
    /// Opaque concurrency token, sent back by [`PackagePolicy::edit`].
    #[serde(default)]
    pub version: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PackagePolicy {
    /// A replacement for this policy in the full format. It keeps the current
    /// inputs, variables and assignments until changed, and is bound to the
    /// policy's ID and concurrency token.
    /// Fetch a simplified response with [`Fleet::get_package_policy`] before
    /// editing it. Updating requires full inputs and a nonempty concurrency token.
    pub fn edit(&self) -> PackagePolicyEdit {
        PackagePolicyEdit {
            id: self.id.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            description: self.description.clone(),
            enabled: self.enabled,
            package: self.package.clone(),
            policy_ids: self.policy_ids.clone(),
            inputs: editable_inputs(self.inputs.clone()),
            vars: self.vars.clone(),
            version: self.version.clone(),
            full_format: self.inputs.is_array(),
        }
    }
}

fn editable_inputs(mut inputs: Value) -> Value {
    if let Some(inputs) = inputs.as_array_mut() {
        for input in inputs {
            if let Some(input) = input.as_object_mut() {
                input.remove("compiled_input");
            }
        }
    }
    inputs
}

impl fmt::Debug for PackagePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackagePolicy")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("enabled", &self.enabled)
            .field("revision", &self.revision)
            .field("package", &self.package)
            .field("policy_ids", &self.policy_ids)
            .finish_non_exhaustive()
    }
}

/// Changes to a retrieved package policy, created by [`PackagePolicy::edit`]
/// and sent with [`Fleet::update_package_policy`] in the full format.
///
/// A policy changed since it was read fails with HTTP 409; read it again and
/// reapply the change. `Debug` output omits inputs and variables.
#[derive(Clone, Serialize)]
pub struct PackagePolicyEdit {
    #[serde(skip)]
    id: String,
    name: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    package: PackageRef,
    policy_ids: Vec<String>,
    #[serde(skip_serializing_if = "Value::is_null")]
    inputs: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    vars: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip)]
    full_format: bool,
}

impl PackagePolicyEdit {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    /// Replaces the agent policies the package policy is assigned to.
    pub fn policy_ids<I: IntoIterator<Item = S>, S: Into<String>>(mut self, ids: I) -> Self {
        self.policy_ids = ids.into_iter().map(Into::into).collect();
        self
    }

    /// Replaces the inputs with a full-format array, typically a modified copy
    /// of [`PackagePolicy::inputs`].
    pub fn inputs(mut self, inputs: Value) -> Self {
        self.inputs = editable_inputs(inputs);
        self
    }

    /// Replaces the package-level variables in the full format.
    pub fn vars(mut self, vars: Value) -> Self {
        self.vars = Some(vars);
        self
    }
}

impl fmt::Debug for PackagePolicyEdit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackagePolicyEdit")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("namespace", &self.namespace)
            .field("policy_ids", &self.policy_ids)
            .finish_non_exhaustive()
    }
}

/// A replacement for [`Fleet::update_package_policy`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum PackagePolicyUpdate<'p> {
    /// A retrieved policy with changes, in the full format. Created from a
    /// [`PackagePolicyEdit`].
    Edit(&'p PackagePolicyEdit),
    /// A new simplified definition for policy `id`, from
    /// [`NewPackagePolicy::replacing`]. Inputs it does not configure revert to
    /// package defaults, and it carries no concurrency token.
    Replace {
        id: &'p str,
        policy: &'p NewPackagePolicy,
    },
}

impl<'p> From<&'p PackagePolicyEdit> for PackagePolicyUpdate<'p> {
    fn from(edit: &'p PackagePolicyEdit) -> Self {
        Self::Edit(edit)
    }
}

/// Lists variable names without values, which can be credentials.
struct VarNames<'v>(&'v BTreeMap<String, Value>);

impl fmt::Debug for VarNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

/// One input in Fleet's simplified package-policy format. Input, stream and
/// variable names depend on the package. `Debug` output omits variable values.
#[derive(Clone, Default, Serialize)]
pub struct PolicyInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    streams: BTreeMap<String, PolicyStream>,
}

impl PolicyInput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn var(mut self, name: impl Into<String>, value: Value) -> Self {
        self.vars.insert(name.into(), value);
        self
    }

    pub fn stream(mut self, name: impl Into<String>, stream: PolicyStream) -> Self {
        self.streams.insert(name.into(), stream);
        self
    }
}

impl fmt::Debug for PolicyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyInput")
            .field("enabled", &self.enabled)
            .field("vars", &VarNames(&self.vars))
            .field("streams", &self.streams)
            .finish()
    }
}

/// A stream within a [`PolicyInput`]. `Debug` output omits variable values.
#[derive(Clone, Default, Serialize)]
pub struct PolicyStream {
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    vars: BTreeMap<String, Value>,
}

impl PolicyStream {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = Some(enabled);
        self
    }

    pub fn var(mut self, name: impl Into<String>, value: Value) -> Self {
        self.vars.insert(name.into(), value);
        self
    }
}

impl fmt::Debug for PolicyStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyStream")
            .field("enabled", &self.enabled)
            .field("vars", &VarNames(&self.vars))
            .finish()
    }
}

/// A package policy in the simplified format, for [`Fleet::create_package_policy`]
/// and, through [`replacing`](Self::replacing), [`Fleet::update_package_policy`].
/// Unset inputs use package defaults. `Debug` output omits variable values.
#[derive(Clone, Debug, Serialize)]
pub struct NewPackagePolicy {
    name: String,
    namespace: String,
    policy_ids: Vec<String>,
    package: PackageRef,
    inputs: BTreeMap<String, PolicyInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl NewPackagePolicy {
    pub fn new(name: impl Into<String>, namespace: impl Into<String>, package: PackageRef) -> Self {
        Self {
            name: name.into(),
            namespace: namespace.into(),
            policy_ids: Vec::new(),
            package,
            inputs: BTreeMap::new(),
            description: None,
        }
    }

    /// Assigns the package policy to an agent policy. Repeat for several policies.
    pub fn policy_id(mut self, id: impl Into<String>) -> Self {
        self.policy_ids.push(id.into());
        self
    }

    /// Configures an input by name, such as `system-logfile`.
    pub fn input(mut self, name: impl Into<String>, input: PolicyInput) -> Self {
        self.inputs.insert(name.into(), input);
        self
    }

    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Replaces the whole of package policy `id` with this definition. Existing
    /// configuration this definition does not set reverts to package defaults;
    /// to change a retrieved policy instead, use [`PackagePolicy::edit`].
    pub fn replacing<'p>(&'p self, id: &'p str) -> PackagePolicyUpdate<'p> {
        PackagePolicyUpdate::Replace { id, policy: self }
    }
}

impl<'a> Fleet<'a> {
    pub fn find_package_policies(&self) -> FindPackagePolicies<'a> {
        FindPackagePolicies(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "package_policies"],
        ))
    }

    pub fn get_package_policy(&self, id: &str) -> GetPackagePolicy<'a> {
        GetPackagePolicy(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "package_policies", id],
        ))
    }

    /// Creates a package policy from a [`NewPackagePolicy`] or equivalent JSON
    /// in the simplified format. The response is also simplified; fetch it with
    /// [`get_package_policy`](Self::get_package_policy) before editing it.
    pub fn create_package_policy<B: Serialize + ?Sized>(
        &self,
        policy: &B,
    ) -> CreatePackagePolicy<'a> {
        CreatePackagePolicy(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "package_policies"],
                )
                .param("format", "simplified")
                .json(policy),
        )
    }

    /// Replaces a package policy, either with a [`PackagePolicyEdit`] of a
    /// retrieved policy, sent in the full format with its concurrency token, or
    /// with a simplified definition from [`NewPackagePolicy::replacing`].
    /// Edits with simplified inputs or a missing/empty concurrency token fail
    /// locally with [`crate::Error::InvalidRequest`].
    pub fn update_package_policy<'p>(
        &self,
        update: impl Into<PackagePolicyUpdate<'p>>,
    ) -> UpdatePackagePolicy<'a> {
        let update = update.into();
        let id = match update {
            PackagePolicyUpdate::Edit(edit) => edit.id.as_str(),
            PackagePolicyUpdate::Replace { id, .. } => id,
        };
        let request = self.0.request(
            Method::PUT,
            Scope::Space,
            &["api", "fleet", "package_policies", id],
        );
        UpdatePackagePolicy(match update {
            PackagePolicyUpdate::Edit(edit) => {
                let request = if edit.full_format && edit.inputs.is_array() {
                    request
                } else {
                    request.invalid(
                        "package-policy edits require full inputs; fetch the policy with get_package_policy before editing it".into(),
                    )
                };
                request
                    .nonempty("version", edit.version.as_deref().unwrap_or_default())
                    .json(edit)
            }
            PackagePolicyUpdate::Replace { policy, .. } => {
                request.param("format", "simplified").json(policy)
            }
        })
    }

    pub fn delete_package_policy(&self, id: &str) -> DeletePackagePolicy<'a> {
        DeletePackagePolicy(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "fleet", "package_policies", id],
        ))
    }
}

endpoint! {
    /// `GET /api/fleet/package_policies`
    FindPackagePolicies => FleetPage<PackagePolicy>
}

endpoint! {
    /// `GET /api/fleet/package_policies/{packagePolicyId}`
    GetPackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `POST /api/fleet/package_policies`
    CreatePackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `PUT /api/fleet/package_policies/{packagePolicyId}`
    UpdatePackagePolicy => Item<PackagePolicy>
}

endpoint! {
    /// `DELETE /api/fleet/package_policies/{packagePolicyId}`
    DeletePackagePolicy => Value
}

impl DeletePackagePolicy<'_> {
    /// Deletes even when the package policy is managed.
    pub fn force(self, force: bool) -> Self {
        Self(self.0.param("force", force))
    }
}

page_setters!(FindPackagePolicies);
sort_setters!(FindPackagePolicies);
paginated!(FindPackagePolicies => FleetPage<PackagePolicy>);
