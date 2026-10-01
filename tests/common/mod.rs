//! A recording mock Kibana for offline wire-contract tests.
#![allow(dead_code)]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, Response},
    routing::any,
};
use kibana_rs::{Kibana, http::Transport};
use serde_json::Value;

#[derive(Default)]
struct Shared {
    replies: VecDeque<Reply>,
    requests: VecDeque<Recorded>,
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    delay: Duration,
}

/// Answers requests in order from queued replies and records every request.
pub struct Mock {
    pub url: String,
    shared: Arc<Mutex<Shared>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Mock {
    pub async fn start() -> Self {
        Self::start_at("").await
    }

    /// Serves under a base path, as a reverse proxy would.
    pub async fn start_at(prefix: &str) -> Self {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let router = Router::new()
            .fallback(any(record))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}{prefix}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, shared, task }
    }

    pub fn client(&self) -> Kibana {
        Kibana::new(Transport::single_node(&self.url).unwrap())
    }

    /// A client scoped to the `soc` space.
    pub fn soc(&self) -> Kibana {
        self.client().space("soc").unwrap()
    }

    pub fn reply(&self, status: u16, body: impl Into<Vec<u8>>) {
        self.reply_with(status, vec![], body);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn json(&self, body: Value) {
        self.reply_with(
            200,
            vec![("content-type", "application/json".into())],
            body.to_string(),
        );
    }

    pub fn reply_with(
        &self,
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: impl Into<Vec<u8>>,
    ) {
        self.push(Reply {
            status,
            headers,
            body: body.into(),
            delay: Duration::ZERO,
        });
    }

    /// Answers the next request with an empty object after `delay`.
    pub fn reply_after(&self, delay: Duration) {
        self.push(Reply {
            status: 200,
            headers: vec![],
            body: b"{}".to_vec(),
            delay,
        });
    }

    fn push(&self, reply: Reply) {
        self.shared.lock().unwrap().replies.push_back(reply);
    }

    /// The oldest request not yet inspected.
    pub fn take(&self) -> Recorded {
        self.shared
            .lock()
            .unwrap()
            .requests
            .pop_front()
            .expect("no request was recorded")
    }

    pub fn request_count(&self) -> usize {
        self.shared.lock().unwrap().requests.len()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn record(State(shared): State<Arc<Mutex<Shared>>>, request: Request) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.unwrap().to_vec();
    let reply = {
        let mut shared = shared.lock().unwrap();
        shared.requests.push_back(Recorded {
            method: parts.method.to_string(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers: parts.headers,
            body,
        });
        shared.replies.pop_front()
    };
    let Some(reply) = reply else {
        return Response::builder()
            .status(599)
            .body(Body::from("no reply queued"))
            .unwrap();
    };
    tokio::time::sleep(reply.delay).await;
    let mut response = Response::builder().status(reply.status);
    for (name, value) in reply.headers {
        response = response.header(name, value);
    }
    response.body(Body::from(reply.body)).unwrap()
}

impl Recorded {
    /// Asserts the method, the percent-encoded path and the exact query pairs.
    pub fn route(&self, method: &str, path: &str, query: &[(&str, &str)]) -> &Self {
        assert_eq!(self.method, method, "method for {}", self.path);
        assert_eq!(self.path, path);
        let expected: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(self.query_pairs(), expected, "query for {path}");
        self
    }

    pub fn query_pairs(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(self.query.as_deref().unwrap_or("").as_bytes())
            .into_owned()
            .collect()
    }

    pub fn json(&self) -> Value {
        assert_eq!(
            self.header("content-type"),
            Some("application/json"),
            "JSON content type for {}",
            self.path
        );
        serde_json::from_slice(&self.body).unwrap()
    }

    /// Asserts the JSON body.
    #[allow(clippy::needless_pass_by_value)]
    pub fn body(&self, expected: Value) -> &Self {
        assert_eq!(self.json(), expected, "body for {}", self.path);
        self
    }

    pub fn no_body(&self) -> &Self {
        assert!(
            self.body.is_empty(),
            "unexpected body for {}: {}",
            self.path,
            String::from_utf8_lossy(&self.body)
        );
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.to_str().unwrap())
    }

    /// Asserts a multipart upload of one `file` part and returns its contents.
    pub fn multipart_file(&self, file_name: &str, content_type: &str) -> String {
        assert!(
            self.header("content-type")
                .unwrap()
                .starts_with("multipart/form-data; boundary=")
        );
        let body = String::from_utf8(self.body.clone()).unwrap();
        assert!(
            body.contains(&format!("name=\"file\"; filename=\"{file_name}\"")),
            "{body}"
        );
        assert!(
            body.contains(&format!("Content-Type: {content_type}")),
            "{body}"
        );
        let start = body.find("\r\n\r\n").unwrap() + 4;
        let end = body[start..].find("\r\n--").unwrap() + start;
        body[start..end].to_owned()
    }
}
