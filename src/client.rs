use std::fmt;

use serde_json::Value;

use crate::{
    Error, Request, Result,
    cases::Cases,
    exceptions::Exceptions,
    fleet::Fleet,
    http::{Method, Transport},
    request::endpoint,
    roles::Roles,
    security::Security,
    spaces::Spaces,
};

/// Whether a route is resolved inside the client's selected space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Always `/api/...`, even on a space-scoped client.
    Global,
    /// `/s/{space}/api/...` when a space is selected, otherwise `/api/...`.
    Space,
}

/// Result ordering for search endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortOrder {
    Asc,
    Desc,
}

impl SortOrder {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

/// The Kibana client. API groups are reached through namespace methods such as
/// [`security`](Self::security), each returning request builders.
///
/// Cloning a client or selecting a space shares the transport and its connection pool.
#[derive(Clone)]
pub struct Kibana {
    transport: Transport,
    space: Option<String>,
}

impl Kibana {
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            space: None,
        }
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// A client whose space-scoped routes use `/s/{id}`. Global routes are unchanged.
    /// This selects a space without contacting Kibana or creating the space.
    /// Empty IDs, dot segments and IDs containing `/` return [`Error::Configuration`].
    pub fn space(&self, id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id == "." || id == ".." || id.contains('/') {
            return Err(Error::Configuration("invalid space ID".into()));
        }
        Ok(Self {
            transport: self.transport.clone(),
            space: Some(id),
        })
    }

    pub fn default_space(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            space: None,
        }
    }

    pub fn space_id(&self) -> Option<&str> {
        self.space.as_deref()
    }

    pub fn security(&self) -> Security<'_> {
        Security(self)
    }

    pub fn exceptions(&self) -> Exceptions<'_> {
        Exceptions(self)
    }

    pub fn cases(&self) -> Cases<'_> {
        Cases(self)
    }

    pub fn fleet(&self) -> Fleet<'_> {
        Fleet(self)
    }

    pub fn spaces(&self) -> Spaces<'_> {
        Spaces(self)
    }

    pub fn roles(&self) -> Roles<'_> {
        Roles(self)
    }

    /// `GET /api/status`
    pub fn status(&self) -> Status<'_> {
        Status(self.request(Method::GET, Scope::Global, &["api", "status"]))
    }

    /// A request to a route without a named builder. Each segment is percent-encoded
    /// separately, so identifiers cannot change the route.
    pub fn request(&self, method: Method, scope: Scope, segments: &[&str]) -> Request<'_> {
        Request::new(self, method, scope, segments)
    }
}

impl fmt::Debug for Kibana {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kibana")
            .field("transport", &self.transport)
            .field("space", &self.space)
            .finish()
    }
}

endpoint! {
    /// `GET /api/status`
    Status => Value
}
