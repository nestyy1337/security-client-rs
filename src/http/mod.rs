//! The HTTP transport and wire types shared by every endpoint.
//!
//! [`Method`], [`StatusCode`] and the [`headers`] types come from the `http` crate.
mod body;
mod response;
#[cfg(feature = "tracing")]
mod trace;
mod transport;

pub use body::Body;
pub use http::{Method, StatusCode};
pub use response::{Empty, Raw, Response};
pub use transport::{Certificate, Credentials, DEFAULT_ADDRESS, Transport, TransportBuilder};
pub use url::Url;

pub mod headers {
    //! Header names, values and maps, re-exported from the `http` crate.
    pub use http::header::*;
}
