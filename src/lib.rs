//! An async client for Kibana security operations and Fleet management.
//!
//! Resources are scoped with [`Client::space`]. Space administration and status
//! always use the global route. Mutating requests are never automatically retried.
//! The client targets traditional Kibana 9.5; see the repository's verification
//! record for the exact workflows and server version exercised.

pub mod cases;
mod client;
mod error;
pub mod exceptions;
pub mod fleet;
pub mod roles;
pub mod security;
pub mod spaces;

pub use client::{Auth, Client, ClientBuilder, PageOptions, Scope};
pub use error::{Error, Result};
pub use reqwest::{Method, StatusCode};
pub use serde_json::Value;
