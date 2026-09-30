//! Trace events for the optional `tracing` feature. Events carry the endpoint,
//! method, path, status, duration and `X-Opaque-Id`, never query values,
//! bodies, credentials or other headers.
//!
//! A request emits one event when it ends before a successful response
//! (`sent` is false or the status is an error, whose bounded body has been
//! read) or when successful response headers arrive. Reading a successful body
//! through `bytes`, `text` or `json` emits a second event when the body is
//! complete or fails. Streamed and unread bodies emit no body event.
use std::time::Instant;

use http::{HeaderMap, Method, StatusCode};

use super::Response;
use crate::{Error, Result};

const TARGET: &str = "kibana_rs";

#[derive(Clone)]
pub(crate) struct Request {
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

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub(super) fn finish(&self, result: &Result<Response>) {
        let Self {
            operation,
            method,
            path,
            opaque_id,
            ..
        } = self;
        let elapsed_ms = self.elapsed_ms();
        match result {
            Ok(response) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms,
                status = response.status_code().as_u16(), "Kibana response headers received"
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

    /// `elapsed_ms` counts from the start of the request.
    pub(super) fn body_finished(&self, status: StatusCode, result: &Result<bytes::Bytes>) {
        let Self {
            operation,
            method,
            path,
            opaque_id,
            ..
        } = self;
        let elapsed_ms = self.elapsed_ms();
        let status = status.as_u16();
        match result {
            Ok(body) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms, status,
                bytes = body.len(), "Kibana response body read"
            ),
            Err(Error::Body {
                received, source, ..
            }) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms, status,
                bytes = received, timeout = source.is_timeout(), "Kibana response body was interrupted"
            ),
            Err(Error::ResponseTooLarge { limit, .. }) => tracing::debug!(
                target: TARGET, operation, %method, path, opaque_id, elapsed_ms, status,
                limit, "Kibana response body exceeded the limit"
            ),
            Err(_) => {}
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
