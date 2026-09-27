use std::fmt;

use http::{HeaderMap, StatusCode};

pub type Result<T> = std::result::Result<T, Error>;

/// Error responses retain their status, headers, and a bounded body.
/// Bodies may contain operational data; do not log them indiscriminately.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid client configuration: {0}")]
    Configuration(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("HTTP transport failed: {0}")]
    Transport(#[source] TransportError),
    #[error("Kibana returned HTTP {status}")]
    Api {
        status: StatusCode,
        headers: Box<HeaderMap>,
        body: String,
        truncated: bool,
    },
    #[error("could not decode Kibana response with HTTP {status}: {source}")]
    Decode {
        status: StatusCode,
        body: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("response exceeded the configured limit of {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("request serialization failed: {0}")]
    Serialize(#[source] Box<dyn std::error::Error + Send + Sync>),
}

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

    pub(crate) fn serialize(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Serialize(Box::new(error))
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(TransportError(error))
    }
}

/// A connection, TLS, timeout, or body-streaming failure. No HTTP status is available.
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
