//! Enrollment API keys, which let new agents join a policy.
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use super::{Fleet, FleetPage, Item};
use crate::{Scope, http::Method, pagination::paginated, request::endpoint};

/// Enrollment credentials are omitted from `Debug` output.
#[derive(Clone, Deserialize)]
#[non_exhaustive]
pub struct EnrollmentKey {
    pub id: String,
    pub api_key_id: String,
    pub api_key: String,
    pub active: bool,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub expire_at: Option<String>,
}

impl fmt::Debug for EnrollmentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollmentKey")
            .field("id", &self.id)
            .field("active", &self.active)
            .field("api_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl<'a> Fleet<'a> {
    pub fn find_enrollment_keys(&self) -> FindEnrollmentKeys<'a> {
        FindEnrollmentKeys(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys"],
        ))
    }

    pub fn get_enrollment_key(&self, id: &str) -> GetEnrollmentKey<'a> {
        GetEnrollmentKey(self.0.request(
            Method::GET,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys", id],
        ))
    }

    pub fn create_enrollment_key(&self, policy_id: &str) -> CreateEnrollmentKey<'a> {
        CreateEnrollmentKey(
            self.0
                .request(
                    Method::POST,
                    Scope::Space,
                    &["api", "fleet", "enrollment_api_keys"],
                )
                .nonempty("policy_id", policy_id)
                .field("policy_id", policy_id),
        )
    }

    /// Revokes future enrollment. Already enrolled agents keep their own credentials.
    pub fn revoke_enrollment_key(&self, id: &str) -> RevokeEnrollmentKey<'a> {
        RevokeEnrollmentKey(self.0.request(
            Method::DELETE,
            Scope::Space,
            &["api", "fleet", "enrollment_api_keys", id],
        ))
    }
}

endpoint! {
    /// `GET /api/fleet/enrollment_api_keys`
    FindEnrollmentKeys => FleetPage<EnrollmentKey>
}

endpoint! {
    /// `GET /api/fleet/enrollment_api_keys/{keyId}`
    GetEnrollmentKey => Item<EnrollmentKey>
}

endpoint! {
    /// `POST /api/fleet/enrollment_api_keys`
    CreateEnrollmentKey => Item<EnrollmentKey>
}

impl CreateEnrollmentKey<'_> {
    pub fn name(self, name: &str) -> Self {
        Self(self.0.field("name", name))
    }

    /// An Elastic duration after which the key expires, for example `24h`.
    pub fn expiration(self, duration: &str) -> Self {
        Self(self.0.field("expiration", duration))
    }
}

endpoint! {
    /// `DELETE /api/fleet/enrollment_api_keys/{keyId}`
    RevokeEnrollmentKey => Value
}

page_setters!(FindEnrollmentKeys);
paginated!(FindEnrollmentKeys => FleetPage<EnrollmentKey>);
