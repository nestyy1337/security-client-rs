use std::{fmt, marker::PhantomData};

use bytes::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt};
use http::{HeaderMap, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;
use url::Url;

use crate::{Error, Result, TransportError, error::DecodeError};

/// Marker for endpoints that answer without a body.
pub enum Empty {}

/// Marker for endpoints that return non-JSON bytes, such as NDJSON exports,
/// YAML policies and diagnostic archives.
pub enum Raw {}

/// A successful response. `T` is the type [`json`](Self::json) decodes into.
///
/// Non-success statuses never reach this type; [`send`](super::Transport::send)
/// turns them into [`Error::Api`]. A failure while reading the body keeps the
/// status and headers: [`Error::Body`] for an interrupted body and
/// [`Error::ResponseTooLarge`] above the transport limit.
pub struct Response<T = Value> {
    inner: reqwest::Response,
    limit: usize,
    operation: &'static str,
    #[cfg(feature = "tracing")]
    trace: Option<super::trace::Request>,
    kind: PhantomData<fn() -> T>,
}

impl<T> Response<T> {
    pub(crate) fn new(inner: reqwest::Response, limit: usize) -> Self {
        Self {
            inner,
            limit,
            operation: "request",
            #[cfg(feature = "tracing")]
            trace: None,
            kind: PhantomData,
        }
    }

    pub(crate) fn named(mut self, operation: &'static str) -> Self {
        self.operation = operation;
        self
    }

    #[cfg(feature = "tracing")]
    pub(crate) fn traced(mut self, trace: super::trace::Request) -> Self {
        self.trace = Some(trace);
        self
    }

    pub(crate) fn cast<U>(self) -> Response<U> {
        Response {
            inner: self.inner,
            limit: self.limit,
            operation: self.operation,
            #[cfg(feature = "tracing")]
            trace: self.trace,
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

    /// The requested URL, including query values. `Debug` omits them.
    pub fn url(&self) -> &Url {
        self.inner.url()
    }

    /// Reads the whole body, failing with [`Error::ResponseTooLarge`] above the transport limit.
    pub async fn bytes(mut self) -> Result<Bytes> {
        let status = self.inner.status();
        let headers = std::mem::take(self.inner.headers_mut());
        let body = read_bounded(self.inner, self.limit).await;
        let result = match body {
            Bounded {
                error: Some(source),
                bytes,
                ..
            } => Err(Error::Body {
                status,
                headers: Box::new(headers),
                received: bytes.len(),
                source,
            }),
            Bounded {
                truncated: true, ..
            } => Err(Error::ResponseTooLarge {
                limit: self.limit,
                status,
                headers: Box::new(headers),
            }),
            Bounded { bytes, .. } => Ok(Bytes::from(bytes)),
        };
        #[cfg(feature = "tracing")]
        if let Some(trace) = &self.trace {
            trace.body_finished(status, &result);
        }
        result
    }

    /// Reads the body as UTF-8, replacing invalid sequences.
    pub async fn text(self) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.bytes().await?).into_owned())
    }

    /// Streams the body without the transport's size limit. Inspect the status
    /// and headers first; stream errors are plain [`Error::Transport`] values,
    /// and no body trace event is emitted.
    pub fn bytes_stream(self) -> impl Stream<Item = Result<Bytes>> + Send {
        self.inner.bytes_stream().map_err(Error::from)
    }

    /// Decodes the body into a type other than the endpoint's default.
    pub async fn json_as<U: DeserializeOwned>(self) -> Result<U> {
        let status = self.status_code();
        let headers = Box::new(self.headers().clone());
        #[cfg(feature = "tracing")]
        let operation = self.operation;
        let body = self.bytes().await?;
        serde_json::from_slice(&body).map_err(|source| {
            #[cfg(feature = "tracing")]
            super::trace::decode_failed(operation, status, &source);
            Error::Decode {
                status,
                headers,
                body: String::from_utf8_lossy(
                    &body[..body.len().min(super::transport::ERROR_LIMIT)],
                )
                .into_owned(),
                source: DecodeError::new(source),
            }
        })
    }
}

impl<T: DeserializeOwned> Response<T> {
    pub async fn json(self) -> Result<T> {
        self.json_as().await
    }
}

/// Omits query values, which can carry filters or tokens.
impl<T> fmt::Debug for Response<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status_code())
            .field("url", &super::redacted(self.url()))
            .finish_non_exhaustive()
    }
}

/// At most `limit` bytes of a body, with how reading it ended.
pub(crate) struct Bounded {
    pub(crate) bytes: Vec<u8>,
    /// The body was longer than `limit`.
    pub(crate) truncated: bool,
    /// Reading failed; `bytes` holds what arrived first.
    pub(crate) error: Option<TransportError>,
}

pub(crate) async fn read_bounded(response: reqwest::Response, limit: usize) -> Bounded {
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                return Bounded {
                    bytes,
                    truncated: false,
                    error: Some(TransportError::from(error)),
                };
            }
        };
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            return Bounded {
                bytes,
                truncated: true,
                error: None,
            };
        }
    }
    Bounded {
        bytes,
        truncated: false,
        error: None,
    }
}
