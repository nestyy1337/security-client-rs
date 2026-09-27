use std::fmt;

use reqwest::multipart::{Form, Part};
use serde::Serialize;

use crate::{Error, Result};

/// A request body. Endpoint builders create these; use them directly with
/// [`Transport::send`](super::Transport::send) or [`Request::body`](crate::Request::body).
pub struct Body(pub(crate) Content);

pub(crate) enum Content {
    Json(Vec<u8>),
    Multipart(Form),
}

impl Body {
    pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<Self> {
        Ok(Self(Content::Json(
            serde_json::to_vec(value).map_err(Error::serialize)?,
        )))
    }

    /// A `multipart/form-data` body with a single file part, as used by Kibana import APIs.
    pub fn file(
        field: impl Into<String>,
        file_name: impl Into<String>,
        content_type: &str,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let part = Part::bytes(bytes.into())
            .file_name(file_name.into())
            .mime_str(content_type)
            .map_err(|_| Error::InvalidRequest(format!("invalid content type {content_type:?}")))?;
        Ok(Self(Content::Multipart(
            Form::new().part(field.into(), part),
        )))
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Content::Json(bytes) => write!(f, "Body::Json({} bytes)", bytes.len()),
            Content::Multipart(_) => f.write_str("Body::Multipart"),
        }
    }
}
