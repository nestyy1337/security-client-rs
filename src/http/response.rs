use std::{fmt, marker::PhantomData};

use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

use crate::{Error, Result};

/// Marker for endpoints that answer without a body.
pub enum Empty {}

/// Marker for endpoints that return non-JSON bytes, such as NDJSON exports,
/// YAML policies and diagnostic archives.
pub enum Raw {}

/// A successful response. `T` is the type [`json`](Self::json) decodes into.
///
/// Non-success statuses never reach this type; [`send`](super::Transport::send)
/// turns them into [`Error::Api`].
pub struct Response<T = Value> {
    inner: reqwest::Response,
    limit: usize,
    operation: &'static str,
    kind: PhantomData<fn() -> T>,
}

impl<T> Response<T> {
    pub(crate) fn new(inner: reqwest::Response, limit: usize) -> Self {
        Self {
            inner,
            limit,
            operation: "request",
            kind: PhantomData,
        }
    }

    pub(crate) fn named(mut self, operation: &'static str) -> Self {
        self.operation = operation;
        self
    }

    pub(crate) fn cast<U>(self) -> Response<U> {
        Response {
            inner: self.inner,
            limit: self.limit,
            operation: self.operation,
            kind: PhantomData,
        }
    }

    pub fn status_code(&self) -> StatusCode {
        self.inner.status()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    pub fn url(&self) -> &Url {
        self.inner.url()
    }

    /// Reads the whole body, failing with [`Error::ResponseTooLarge`] above the transport limit.
    pub async fn bytes(self) -> Result<Bytes> {
        let limit = self.limit;
        let (body, truncated) = read_bounded(self.inner, limit).await?;
        if truncated {
            return Err(Error::ResponseTooLarge { limit });
        }
        Ok(body)
    }

    /// Reads the body as UTF-8, replacing invalid sequences.
    pub async fn text(self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes().await?).into_owned())
    }

    /// Streams the body without the transport's size limit.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes>> + Send {
        self.inner.bytes_stream().map_err(Error::from)
    }

    /// Decodes the body into a type other than the endpoint's default.
    pub async fn json_as<U: DeserializeOwned>(self) -> Result<U> {
        let status = self.status_code();
        #[cfg(feature = "tracing")]
        let operation = self.operation;
        let body = self.bytes().await?;
        serde_json::from_slice(&body).map_err(|source| {
            #[cfg(feature = "tracing")]
            super::trace::decode_failed(operation, status, &source);
            Error::Decode {
                status,
                body: String::from_utf8_lossy(
                    &body[..body.len().min(super::transport::ERROR_LIMIT)],
                )
                .into_owned(),
                source,
            }
        })
    }
}

impl<T: DeserializeOwned> Response<T> {
    pub async fn json(self) -> Result<T> {
        self.json_as().await
    }
}

impl<T> fmt::Debug for Response<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status_code())
            .field("url", self.url())
            .finish_non_exhaustive()
    }
}

pub(crate) async fn read_bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<(Bytes, bool)> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            return Ok((body.into(), true));
        }
    }
    Ok((body.into(), false))
}
