//! An async client for Kibana security operations and Fleet management.
//!
//! The layout follows the official Elasticsearch Rust client: a [`Transport`]
//! owns the connection, credentials and limits; [`Kibana`] groups the API into
//! namespaces; every endpoint is a builder that is configured and then `send`s.
//!
//! ```no_run
//! use kibana_rs::{Kibana, http::{Credentials, Transport, TransportBuilder, Url}};
//! use kibana_rs::security::{QueryRule, Severity};
//!
//! # async fn run() -> kibana_rs::Result<()> {
//! let transport = TransportBuilder::new(Url::parse("https://kibana.example:5601").unwrap())
//!     .auth(Credentials::EncodedApiKey("base64-key".into()))
//!     .build()?;
//! let client = Kibana::new(transport).space("soc")?;
//!
//! let page = client.security().find_rules().per_page(100).send().await?.json().await?;
//! println!("{} rules", page.total);
//!
//! let rule = QueryRule::new("Failed logins", "Repeated failures", "event.outcome: failure")
//!     .severity(Severity::High);
//! let created = client.security().create_rule(&rule).send().await?.json().await?;
//! assert!(!created.enabled);
//! # Ok(())
//! # }
//! ```
//!
//! Space-scoped routes use the client's selected space ([`Kibana::space`]);
//! space administration, roles and status are always global. Requests are
//! never retried and redirects are never followed. Non-success statuses become
//! [`Error::Api`]. Routes without a named builder are available through
//! [`Kibana::request`].

pub mod cases;
mod client;
mod error;
pub mod exceptions;
pub mod fleet;
pub mod http;
pub mod pagination;
pub mod poll;
mod request;
pub mod roles;
pub mod security;
pub mod spaces;

pub use client::{Kibana, Scope, SortOrder, Status};
pub use error::{DecodeError, Error, ImportError, ImportFailure, Result, TransportError};
pub use http::Transport;
pub use request::Request;
