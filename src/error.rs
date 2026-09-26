use reqwest::{StatusCode, header::HeaderMap};

pub type Result<T> = std::result::Result<T, Error>;

/// Error responses retain their status, headers, and a bounded body.
/// Bodies may contain operational data; do not log them indiscriminately.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid client configuration: {0}")]
    Configuration(String),
    #[error("HTTP transport failed: {0}")]
    Transport(#[from] reqwest::Error),
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
    Serialize(#[from] serde_json::Error),
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
}
