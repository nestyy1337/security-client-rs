use std::{fmt, time::Duration};

use http::{HeaderMap, StatusCode, header::RETRY_AFTER};
use serde::{Deserialize, Serialize};
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

/// Error responses retain their status, headers, and a bounded body.
/// Bodies may contain operational data, so neither `Display` nor `Debug`
/// prints them; read [`Error::body`] deliberately.
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
    #[error("could not decode Kibana response with HTTP {status}: {source}")]
    Decode {
        status: StatusCode,
        body: String,
        #[source]
        source: DecodeError,
    },
    #[error("response exceeded the configured limit of {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request serialization failed: {0}")]
    Serialize(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// A JSON decoding failure whose formatting omits response values.
/// The original Serde message is available only through [`Self::as_serde_error`].
pub struct DecodeError(pub(crate) serde_json::Error);

impl DecodeError {
    pub fn line(&self) -> usize {
        self.0.line()
    }

    pub fn column(&self) -> usize {
        self.0.column()
    }

    pub fn classify(&self) -> serde_json::error::Category {
        self.0.classify()
    }

    /// Inspects the original failure. Its message can contain response values.
    pub fn as_serde_error(&self) -> &serde_json::Error {
        &self.0
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON {:?} error at line {} column {}",
            self.classify(),
            self.line(),
            self.column()
        )
    }
}

impl fmt::Debug for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeError")
            .field("category", &self.classify())
            .field("line", &self.line())
            .field("column", &self.column())
            .finish()
    }
}

impl std::error::Error for DecodeError {}

impl Error {
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } | Self::Decode { status, .. } => Some(*status),
            _ => None,
        }
    }

    pub fn body(&self) -> Option<&str> {
        match self {
            Self::Api { body, .. } | Self::Decode { body, .. } => Some(body),
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
        Self::Serialize(Box::new(error))
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(TransportError::from(error))
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
                .field("headers", &headers.keys().collect::<Vec<_>>())
                .field("body_bytes", &body.len())
                .field("truncated", truncated)
                .field("body_error", body_error)
                .finish(),
            Self::Decode {
                status,
                body,
                source,
            } => f
                .debug_struct("Decode")
                .field("status", status)
                .field("body_bytes", &body.len())
                .field("source", source)
                .finish(),
            Self::ResponseTooLarge { limit } => f
                .debug_struct("ResponseTooLarge")
                .field("limit", limit)
                .finish(),
            Self::Serialize(error) => f.debug_tuple("Serialize").field(error).finish(),
        }
    }
}

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
