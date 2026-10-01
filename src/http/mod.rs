//! The HTTP transport and wire types shared by every endpoint.
//!
//! [`Method`], [`StatusCode`] and the [`headers`] types come from the `http` crate.
mod body;
mod response;
#[cfg(feature = "tracing")]
mod trace;
mod transport;

pub use body::Body;
pub(crate) use body::to_json;
pub use http::{Method, StatusCode};
pub use response::{Empty, Raw, Response};
pub use transport::{Certificate, Credentials, DEFAULT_ADDRESS, Transport, TransportBuilder};
pub use url::Url;

pub mod headers {
    //! Header names, values and maps, re-exported from the `http` crate.
    pub use http::header::*;
}

/// `url` without credentials, query or fragment, which can carry secrets.
pub(crate) fn redacted(url: &Url) -> String {
    let mut url = url.clone();
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Copies `src` into `dst`. Each name in `src` replaces every earlier value of
/// that name in `dst`, while repeated values of one name in `src` are all kept.
pub(crate) fn merge_headers(dst: &mut headers::HeaderMap, src: headers::HeaderMap) {
    let mut current = None;
    for (name, value) in src {
        match name {
            Some(name) => {
                dst.insert(&name, value);
                current = Some(name);
            }
            // `HeaderMap::into_iter` yields a name before its further values.
            None => {
                if let Some(name) = &current {
                    dst.append(name, value);
                }
            }
        }
    }
}
