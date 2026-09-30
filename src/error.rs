use std::{fmt, sync::Arc, time::Duration};

use http::{HeaderMap, StatusCode, header::RETRY_AFTER};
use serde::{Deserialize, Serialize};
use serde_json::error::Category;
use serde_json::{Map, Value};

pub type Result<T> = std::result::Result<T, Error>;

/// One object that failed during an HTTP-successful rule or exception import.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ImportFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    pub error: ImportError,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct ImportError {
    pub status_code: u16,
    pub message: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Responses that fail keep their status and headers. Bodies may contain
/// operational data, so neither `Display` nor `Debug` prints them, nor any
/// response value quoted by a decoding error; read [`Error::body`] or
/// [`DecodeError::inner`] deliberately.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid client configuration: {0}")]
    Configuration(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("HTTP transport failed: {0}")]
    Transport(#[source] TransportError),
    #[error("Kibana returned HTTP {status}")]
    #[non_exhaustive]
    Api {
        status: StatusCode,
        headers: Box<HeaderMap>,
        /// At most 16 KiB of the response body.
        body: String,
        /// The body was longer than the retained part.
        truncated: bool,
        /// Reading the body failed after the status and headers arrived;
        /// `body` holds what was received.
        body_error: Option<TransportError>,
    },
    /// A successful status and headers arrived, but reading the body failed.
    /// For a mutation this is evidence that Kibana accepted the request, not
    /// proof of its outcome; reconcile by reading the resource back.
    #[error("reading the body of a Kibana response with HTTP {status} failed: {source}")]
    #[non_exhaustive]
    Body {
        status: StatusCode,
        headers: Box<HeaderMap>,
        /// Bytes received before the failure.
        received: usize,
        #[source]
        source: TransportError,
    },
    #[error("could not decode Kibana response with HTTP {status}: {source}")]
    #[non_exhaustive]
    Decode {
        status: StatusCode,
        headers: Box<HeaderMap>,
        /// At most 16 KiB of the response body.
        body: String,
        #[source]
        source: DecodeError,
    },
    #[error("response with HTTP {status} exceeded the configured limit of {limit} bytes")]
    #[non_exhaustive]
    ResponseTooLarge {
        limit: usize,
        status: StatusCode,
        headers: Box<HeaderMap>,
    },
    /// A page stream received a different page than it requested.
    #[error("requested page {requested} but Kibana returned page {returned}")]
    UnexpectedPage { requested: u32, returned: u32 },
    /// A bounded page stream read its maximum number of pages while more remained.
    #[error("stopped after {max_pages} pages before the end of the collection")]
    PageLimit { max_pages: u32 },
    #[error("request serialization failed: {0}")]
    Serialize(#[source] Arc<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// The HTTP status of a response that arrived, including successful
    /// responses whose body could not be read or decoded.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. }
            | Self::Body { status, .. }
            | Self::Decode { status, .. }
            | Self::ResponseTooLarge { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The headers of a response that arrived.
    pub fn headers(&self) -> Option<&HeaderMap> {
        match self {
            Self::Api { headers, .. }
            | Self::Body { headers, .. }
            | Self::Decode { headers, .. }
            | Self::ResponseTooLarge { headers, .. } => Some(headers),
            _ => None,
        }
    }

    pub fn body(&self) -> Option<&str> {
        match self {
            Self::Api { body, .. } | Self::Decode { body, .. } => Some(body),
            _ => None,
        }
    }

    /// The connection, timeout or streaming failure behind this error, whether
    /// it happened before a response arrived or while reading its body.
    pub fn transport(&self) -> Option<&TransportError> {
        match self {
            Self::Transport(error) | Self::Body { source: error, .. } => Some(error),
            Self::Api { body_error, .. } => body_error.as_ref(),
            _ => None,
        }
    }

    /// The `message` field of a Kibana JSON error body, when present.
    pub fn message(&self) -> Option<String> {
        let Self::Api { body, .. } = self else {
            return None;
        };
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        value.get("message")?.as_str().map(str::to_owned)
    }

    /// The `Retry-After` delay of an error response, when given in seconds.
    /// HTTP-date values are not parsed.
    pub fn retry_after(&self) -> Option<Duration> {
        let Self::Api { headers, .. } = self else {
            return None;
        };
        let seconds = headers
            .get(RETRY_AFTER)?
            .to_str()
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some(Duration::from_secs(seconds))
    }

    pub(crate) fn serialize(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Serialize(Arc::new(error))
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(TransportError::from(error))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = |headers: &HeaderMap| headers.keys().cloned().collect::<Vec<_>>();
        match self {
            Self::Configuration(message) => f.debug_tuple("Configuration").field(message).finish(),
            Self::InvalidRequest(message) => {
                f.debug_tuple("InvalidRequest").field(message).finish()
            }
            Self::Transport(error) => f.debug_tuple("Transport").field(error).finish(),
            Self::Api {
                status,
                headers,
                body,
                truncated,
                body_error,
            } => f
                .debug_struct("Api")
                .field("status", status)
                .field("headers", &names(headers))
                .field("body_bytes", &body.len())
                .field("truncated", truncated)
                .field("body_error", body_error)
                .finish(),
            Self::Body {
                status,
                headers,
                received,
                source,
            } => f
                .debug_struct("Body")
                .field("status", status)
                .field("headers", &names(headers))
                .field("received", received)
                .field("source", source)
                .finish(),
            Self::Decode {
                status,
                headers,
                body,
                source,
            } => f
                .debug_struct("Decode")
                .field("status", status)
                .field("headers", &names(headers))
                .field("body_bytes", &body.len())
                .field("source", source)
                .finish(),
            Self::ResponseTooLarge {
                limit,
                status,
                headers,
            } => f
                .debug_struct("ResponseTooLarge")
                .field("limit", limit)
                .field("status", status)
                .field("headers", &names(headers))
                .finish(),
            Self::UnexpectedPage {
                requested,
                returned,
            } => f
                .debug_struct("UnexpectedPage")
                .field("requested", requested)
                .field("returned", returned)
                .finish(),
            Self::PageLimit { max_pages } => f
                .debug_struct("PageLimit")
                .field("max_pages", max_pages)
                .finish(),
            Self::Serialize(error) => f.debug_tuple("Serialize").field(error).finish(),
        }
    }
}

/// A response body that did not match the expected type.
///
/// Serde messages can quote response values, such as an unknown enum variant,
/// so `Display` and `Debug` show only the category and position, and the
/// serde error is not exposed as an error source. [`inner`](Self::inner)
/// returns it deliberately.
pub struct DecodeError(serde_json::Error);

impl DecodeError {
    pub(crate) fn new(error: serde_json::Error) -> Self {
        Self(error)
    }

    /// Whether the body was malformed JSON, ended early, or was valid JSON of the wrong shape.
    pub fn category(&self) -> Category {
        self.0.classify()
    }

    pub fn classify(&self) -> Category {
        self.category()
    }

    pub fn line(&self) -> usize {
        self.0.line()
    }

    pub fn column(&self) -> usize {
        self.0.column()
    }

    /// The full serde error, whose message can contain response values.
    pub fn inner(&self) -> &serde_json::Error {
        &self.0
    }

    /// The full serde error, whose message can contain response values.
    pub fn as_serde_error(&self) -> &serde_json::Error {
        self.inner()
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let category = match self.category() {
            Category::Io => "I/O error",
            Category::Syntax => "invalid JSON",
            Category::Data => "unexpected JSON content",
            Category::Eof => "unexpected end of JSON",
        };
        write!(
            f,
            "{category} at line {} column {}",
            self.line(),
            self.column()
        )
    }
}

impl fmt::Debug for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeError")
            .field("category", &self.category())
            .field("line", &self.line())
            .field("column", &self.column())
            .finish()
    }
}

impl std::error::Error for DecodeError {}

/// Query values can carry filters or tokens, so they are dropped from the retained URL.
impl From<reqwest::Error> for TransportError {
    fn from(mut error: reqwest::Error) -> Self {
        if let Some(url) = error.url_mut() {
            url.set_query(None);
        }
        Self(error)
    }
}

/// A connection, TLS, timeout, or body-streaming failure.
pub struct TransportError(reqwest::Error);

impl TransportError {
    pub fn is_timeout(&self) -> bool {
        self.0.is_timeout()
    }

    /// True when the connection failed before a request was sent, including TLS failures.
    pub fn is_connect(&self) -> bool {
        self.0.is_connect()
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// A request construction failure kept until `send`. Clones of a request share
/// it, and every clone reports the same variant and source.
#[derive(Clone)]
pub(crate) enum Deferred {
    InvalidRequest(String),
    Serialize(Arc<dyn std::error::Error + Send + Sync>),
}

impl From<Error> for Deferred {
    fn from(error: Error) -> Self {
        match error {
            Error::Serialize(source) => Self::Serialize(source),
            Error::InvalidRequest(message) => Self::InvalidRequest(message),
            // Construction only produces the two variants above.
            other => Self::InvalidRequest(other.to_string()),
        }
    }
}

impl From<Deferred> for Error {
    fn from(error: Deferred) -> Self {
        match error {
            Deferred::InvalidRequest(message) => Self::InvalidRequest(message),
            Deferred::Serialize(source) => Self::Serialize(source),
        }
    }
}
