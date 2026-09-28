use std::fmt;

use reqwest::multipart::{Form, Part};
use serde::Serialize;

use crate::{Error, Result};

/// A request body. Endpoint builders create these; use them directly with
/// [`Transport::send`](super::Transport::send) or [`Request::body`](crate::Request::body).
#[derive(Clone)]
pub struct Body(pub(crate) Content);

#[derive(Clone)]
pub(crate) enum Content {
    Json(Vec<u8>),
    File {
        field: String,
        file_name: String,
        content_type: String,
        bytes: Vec<u8>,
    },
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
        Part::bytes(Vec::new())
            .mime_str(content_type)
            .map_err(|_| Error::InvalidRequest(format!("invalid content type {content_type:?}")))?;
        Ok(Self(Content::File {
            field: field.into(),
            file_name: file_name.into(),
            content_type: content_type.to_owned(),
            bytes: bytes.into(),
        }))
    }
}

impl Content {
    pub(crate) fn form(
        field: String,
        file_name: String,
        content_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Form> {
        let part = Part::bytes(bytes)
            .file_name(file_name)
            .mime_str(content_type)
            .map_err(|_| Error::InvalidRequest(format!("invalid content type {content_type:?}")))?;
        Ok(Form::new().part(field, part))
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Content::Json(bytes) => write!(f, "Body::Json({} bytes)", bytes.len()),
            Content::File {
                file_name, bytes, ..
            } => {
                write!(f, "Body::File({file_name:?}, {} bytes)", bytes.len())
            }
        }
    }
}
