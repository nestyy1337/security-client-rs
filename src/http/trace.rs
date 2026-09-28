//! Trace events for the optional `tracing` feature. Events carry the endpoint,
//! method, path, status, duration and `X-Opaque-Id`, never query values,
//! bodies, credentials or other headers.
use std::time::Instant;

use http::{HeaderMap, Method, StatusCode};

use super::Response;
use crate::{Error, Result};

const TARGET: &str = "kibana_rs";

pub(super) struct Request {
    operation: &'static str,
    method: Method,
    path: String,
    opaque_id: String,
    started: Instant,
}

impl Request {
    pub(super) fn start(
        operation: &'static str,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        defaults: &HeaderMap,
    ) -> Self {
        let opaque_id = headers
            .get("x-opaque-id")
            .or_else(|| defaults.get("x-opaque-id"))
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        Self {
            operation,
            method: method.clone(),
            path: path.to_owned(),
            opaque_id,
            started: Instant::now(),
        }
    }

    pub(super) fn finish(self, result: &Result<Response>) {
        let Self {
            operation,
            method,
            path,
            opaque_id,
            started,
        } = self;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(response) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms,
                status = response.status_code().as_u16(), "Kibana request completed"
            ),
            Err(Error::Api { status, .. }) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms,
                status = status.as_u16(), "Kibana returned an error status"
            ),
            Err(Error::Transport(error)) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms,
                timeout = error.is_timeout(), connect = error.is_connect(), "Kibana request failed"
            ),
            Err(_) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms,
                "Kibana request was not sent"
            ),
        }
    }
}

pub(super) fn decode_failed(
    operation: &'static str,
    status: StatusCode,
    error: &serde_json::Error,
) {
    tracing::debug!(
        target: TARGET, operation, status = status.as_u16(), line = error.line(), column = error.column(),
        "Kibana response did not match the expected type"
    );
}
