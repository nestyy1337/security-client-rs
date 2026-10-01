use std::{fmt, sync::Arc, time::Duration};

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    Error, Kibana, Result, Scope,
    error::Deferred,
    http::{
        Body, Method, Response, Transport,
        headers::{HeaderMap, HeaderName, HeaderValue},
    },
};

/// Characters escaped inside one path segment. URL parsing treats `\\` as `/`
/// and resolves dot segments, so `/`, `\\` and `%` must never pass through.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\')
    .add(b'%');

/// A request to any Kibana route, created by [`Kibana::request`].
///
/// Every endpoint builder wraps one of these. Construction never fails;
/// invalid path segments and serialization errors are returned by `send`,
/// with the same variant from every clone. Cloning shares the body, so a
/// configured request can be reused cheaply, for example per page.
#[derive(Clone)]
#[must_use = "requests do nothing until sent"]
pub struct Request<'a> {
    transport: &'a Transport,
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<Payload>,
    timeout: Option<Duration>,
    error: Option<Deferred>,
    operation: &'static str,
}

#[derive(Clone)]
enum Payload {
    Json(Arc<Value>),
    Body(Body),
}

impl<'a> Request<'a> {
    pub(crate) fn new(client: &'a Kibana, method: Method, scope: Scope, segments: &[&str]) -> Self {
        let space = match scope {
            Scope::Global => None,
            Scope::Space => client.space_id(),
        };
        let (path, error) = match path(space, segments) {
            Ok(path) => (path, None),
            Err(error) => (String::new(), Some(error.into())),
        };
        Self {
            transport: client.transport(),
            method,
            path,
            query: Vec::new(),
            headers: HeaderMap::new(),
            body: None,
            timeout: None,
            error,
            operation: "request",
        }
    }

    /// Appends URL-encoded query parameters serialized from `query`.
    /// Avoid adding a second value for an existing selector or other
    /// single-valued parameter; raw query additions do not check for conflicts.
    pub fn query<Q: Serialize + ?Sized>(mut self, query: &Q) -> Self {
        match serde_urlencoded::to_string(query) {
            Ok(encoded) => self
                .query
                .extend(url::form_urlencoded::parse(encoded.as_bytes()).into_owned()),
            Err(error) => self.fail(Error::serialize(error)),
        }
        self
    }

    /// Sends `body` as JSON, replacing any previous body. A body that would
    /// repeat an object key, as when a flattened extension map sets a modeled
    /// field such as `id`, fails with [`Error::InvalidRequest`].
    ///
    /// This is a raw replacement: it does not reapply the named builder's
    /// selector, concurrency or URL/body identity checks. The caller must
    /// retain those fields. An earlier construction error is still returned
    /// by `send`, even if the replacement body would be valid.
    pub fn json<B: Serialize + ?Sized>(mut self, body: &B) -> Self {
        match crate::http::to_json(body) {
            Ok(value) => self.body = Some(Payload::Json(Arc::new(value))),
            Err(error) => self.fail(error),
        }
        self
    }

    /// Replaces the body without reapplying named-builder checks, as with
    /// [`Self::json`]. Earlier construction errors still fail at `send`.
    pub fn body(mut self, body: Body) -> Self {
        self.body = Some(Payload::Body(body));
        self
    }

    /// Checks the top-level JSON ID against the path argument. Some update
    /// contracts require it; others allow it to be omitted.
    pub(crate) fn check_body_id(mut self, id: &str, required: bool) -> Self {
        if self.error.is_some() {
            return self;
        }
        let object = match self.body.as_ref() {
            Some(Payload::Json(body)) => body.as_object(),
            _ => None,
        };
        let error = match object {
            None => Some("request body must be a JSON object"),
            Some(object) => match object.get("id") {
                None if !required => None,
                Some(Value::String(body_id)) if body_id == id => None,
                _ => Some("request body id must be a string matching the path id"),
            },
        };
        if let Some(error) = error {
            self.fail(Error::InvalidRequest(error.into()));
        }
        self
    }

    /// Sets a header on this request only. It replaces every value of the same
    /// name from the transport defaults or the body, including `Content-Type`.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Overrides the transport timeout for this request.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sends the request and checks its HTTP status. A successful response's body
    /// is read separately with [`Response::json`], [`Response::bytes`] or a stream.
    /// Construction errors are returned before HTTP. Requests are never retried.
    pub async fn send(self) -> Result<Response> {
        self.send_as().await
    }

    /// Sets a query parameter, replacing an earlier value with the same key.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn param(mut self, key: &str, value: impl ToString) -> Self {
        self.query.retain(|(k, _)| k != key);
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Sets a count parameter that must be at least one, such as a page size.
    pub(crate) fn positive_param(mut self, key: &str, value: u32) -> Self {
        if value == 0 {
            self.fail(Error::InvalidRequest(format!("{key} must be at least 1")));
        }
        self.param(key, value)
    }

    /// Sets a selector query parameter, which must not be empty.
    pub(crate) fn selector(self, (key, value): (&str, &str)) -> Self {
        self.nonempty(key, value).param(key, value)
    }

    /// Fails the request when a required identifier is empty.
    pub(crate) fn nonempty(mut self, key: &str, value: &str) -> Self {
        if value.is_empty() {
            self.fail(Error::InvalidRequest(format!("{key} must not be empty")));
        }
        self
    }

    /// Fails the request with `message`.
    pub(crate) fn invalid(mut self, message: String) -> Self {
        self.fail(Error::InvalidRequest(message));
        self
    }

    /// Adds a query parameter, keeping earlier values with the same key.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn append_param(mut self, key: &str, value: impl ToString) -> Self {
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Sets one field of a JSON object body, creating the object if needed.
    pub(crate) fn field(mut self, key: &str, value: impl Serialize) -> Self {
        let value = match crate::http::to_json(&value) {
            Ok(value) => value,
            Err(error) => {
                self.fail(error);
                return self;
            }
        };
        let body = self
            .body
            .get_or_insert_with(|| Payload::Json(Arc::new(Value::Object(Map::new()))));
        match body {
            Payload::Json(json) => match Arc::make_mut(json) {
                Value::Object(object) => {
                    object.insert(key.to_owned(), value);
                }
                _ => self.fail(Error::InvalidRequest(format!(
                    "cannot set {key:?} because the request body is not a JSON object"
                ))),
            },
            Payload::Body(_) => self.fail(Error::InvalidRequest(format!(
                "cannot set {key:?} because the request body is not a JSON object"
            ))),
        }
        self
    }

    /// Sends `bytes` as the `file` part of a multipart upload.
    pub(crate) fn file(mut self, file_name: &str, content_type: &str, bytes: Vec<u8>) -> Self {
        match Body::file("file", file_name, content_type, bytes) {
            Ok(body) => self.body = Some(Payload::Body(body)),
            Err(error) => self.fail(error),
        }
        self
    }

    /// Labels the request with its endpoint name for trace events.
    pub(crate) fn named(mut self, operation: &'static str) -> Self {
        self.operation = operation;
        self
    }

    pub(crate) async fn send_as<T>(self) -> Result<Response<T>> {
        if let Some(error) = self.error {
            return Err(error.into());
        }
        let body = match self.body {
            None => None,
            Some(Payload::Json(value)) => Some(Body::json(&*value)?),
            Some(Payload::Body(body)) => Some(body),
        };
        let query = (!self.query.is_empty()).then_some(&self.query);
        let response = self
            .transport
            .send_named(
                self.operation,
                self.method,
                &self.path,
                self.headers,
                query,
                body,
                self.timeout,
            )
            .await?;
        Ok(response.cast())
    }

    fn fail(&mut self, error: Error) {
        self.error.get_or_insert_with(|| error.into());
    }
}

/// Omits query values, header values and the body, which can carry secrets.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let query: Vec<&str> = self.query.iter().map(|(key, _)| key.as_str()).collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query_keys", &query)
            .finish_non_exhaustive()
    }
}

fn path(space: Option<&str>, segments: &[&str]) -> Result<String> {
    if segments.is_empty()
        || segments
            .iter()
            .any(|s| s.is_empty() || *s == "." || *s == "..")
    {
        return Err(Error::InvalidRequest(
            "path segments must be nonempty and cannot be dot segments".into(),
        ));
    }
    let mut path = String::new();
    for segment in space
        .into_iter()
        .flat_map(|id| ["s", id])
        .chain(segments.iter().copied())
    {
        path.push('/');
        path.extend(utf8_percent_encode(segment, SEGMENT));
    }
    Ok(path)
}

/// Declares an endpoint builder around a [`Request`] with the common per-request
/// options and a `send` method returning `Response<$output>`.
macro_rules! endpoint {
    ($(#[$doc:meta])* $name:ident => $output:ty) => {
        $(#[$doc])*
        #[derive(Clone, Debug)]
        #[must_use = "requests do nothing until sent"]
        pub struct $name<'a>($crate::Request<'a>);

        impl<'a> $name<'a> {
            /// Converts this builder to a raw request, preserving its configured
            /// route, scope, parameters, body, headers and timeout.
            /// Replacing the raw body does not reapply this builder's identity,
            /// concurrency or typed-field checks. Existing construction errors
            /// remain errors and cannot be repaired through the raw request.
            pub fn into_request(self) -> $crate::Request<'a> {
                self.0.named(stringify!($name))
            }

            /// Sets a header on this request only. It replaces every value of the
            /// same name from the transport defaults or the body.
            pub fn header(
                self,
                name: $crate::http::headers::HeaderName,
                value: $crate::http::headers::HeaderValue,
            ) -> Self {
                Self(self.0.header(name, value))
            }

            /// Overrides the transport timeout for this request.
            pub fn request_timeout(self, timeout: ::std::time::Duration) -> Self {
                Self(self.0.request_timeout(timeout))
            }

            /// Sends the request and checks its HTTP status. The successful body
            /// remains unread; consume it through [`Response`](crate::http::Response).
            /// Construction errors are returned before HTTP. Requests are never retried.
            pub async fn send(self) -> $crate::Result<$crate::http::Response<$output>> {
                self.into_request().send_as().await
            }
        }
    };
}
pub(crate) use endpoint;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::path;
    use crate::{Error, Kibana, Scope, http::Method, http::Transport};

    #[tokio::test]
    async fn fields_cannot_be_merged_into_a_non_object_body() {
        let client = Kibana::new(Transport::single_node("http://127.0.0.1:9").unwrap());
        let error = client
            .request(Method::PUT, Scope::Global, &["api", "x"])
            .json(&json!(["not", "an", "object"]))
            .field("id", "a")
            .send()
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidRequest(ref message) if message.contains("\"id\"")),
            "{error:?}"
        );
    }

    #[test]
    fn segments_are_encoded_individually_and_scoped_to_the_space() {
        assert_eq!(
            path(Some("soc team"), &["api", "cases", "a/b?c#d%e"]).unwrap(),
            "/s/soc%20team/api/cases/a%2Fb%3Fc%23d%25e"
        );
        assert_eq!(path(None, &["api", "status"]).unwrap(), "/api/status");
        assert_eq!(
            path(Some("soc"), &["api", "cases", r"..\..\api\security\role"]).unwrap(),
            "/s/soc/api/cases/..%5C..%5Capi%5Csecurity%5Crole"
        );
        for invalid in [&[][..], &["api", ""], &["api", "."], &["api", ".."]] {
            assert!(path(None, invalid).is_err());
        }
    }
}
