use std::{fmt, time::Duration};

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    Error, Kibana, Result, Scope,
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
/// invalid path segments and serialization errors are returned by `send`.
#[must_use = "requests do nothing until sent"]
pub struct Request<'a> {
    transport: &'a Transport,
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    headers: HeaderMap,
    body: Option<Payload>,
    timeout: Option<Duration>,
    error: Option<Error>,
}

enum Payload {
    Json(Value),
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
            Err(error) => (String::new(), Some(error)),
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
        }
    }

    /// Appends URL-encoded query parameters serialized from `query`.
    pub fn query<Q: Serialize + ?Sized>(mut self, query: &Q) -> Self {
        match serde_urlencoded::to_string(query) {
            Ok(encoded) => self
                .query
                .extend(url::form_urlencoded::parse(encoded.as_bytes()).into_owned()),
            Err(error) => self.fail(Error::serialize(error)),
        }
        self
    }

    /// Sends `body` as JSON, replacing any previous body.
    pub fn json<B: Serialize + ?Sized>(mut self, body: &B) -> Self {
        match serde_json::to_value(body) {
            Ok(value) => self.body = Some(Payload::Json(value)),
            Err(error) => self.fail(Error::serialize(error)),
        }
        self
    }

    pub fn body(mut self, body: Body) -> Self {
        self.body = Some(Payload::Body(body));
        self
    }

    /// Sets a header on this request only, overriding client defaults.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Overrides the transport timeout for this request.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub async fn send(self) -> Result<Response> {
        self.send_as().await
    }

    /// Sets a query parameter, replacing an earlier value with the same key.
    pub(crate) fn param(mut self, key: &str, value: impl ToString) -> Self {
        self.query.retain(|(k, _)| k != key);
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Adds a query parameter, keeping earlier values with the same key.
    pub(crate) fn append_param(mut self, key: &str, value: impl ToString) -> Self {
        self.query.push((key.to_owned(), value.to_string()));
        self
    }

    /// Sets one field of a JSON object body, creating the object if needed.
    pub(crate) fn field(mut self, key: &str, value: impl Serialize) -> Self {
        let value = match serde_json::to_value(value) {
            Ok(value) => value,
            Err(error) => {
                self.fail(Error::serialize(error));
                return self;
            }
        };
        match &mut self.body {
            None => {
                self.body = Some(Payload::Json(Value::Object(Map::from_iter([(
                    key.to_owned(),
                    value,
                )]))))
            }
            Some(Payload::Json(Value::Object(object))) => {
                object.insert(key.to_owned(), value);
            }
            Some(_) => self.fail(Error::InvalidRequest(format!(
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

    pub(crate) async fn send_as<T>(self) -> Result<Response<T>> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let body = match self.body {
            None => None,
            Some(Payload::Json(value)) => Some(Body::json(&value)?),
            Some(Payload::Body(body)) => Some(body),
        };
        let query = (!self.query.is_empty()).then_some(&self.query);
        let response = self
            .transport
            .send(
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
        self.error.get_or_insert(error);
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
        #[derive(Debug)]
        #[must_use = "requests do nothing until sent"]
        pub struct $name<'a>($crate::Request<'a>);

        impl $name<'_> {
            /// Sets a header on this request only, overriding client defaults.
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

            pub async fn send(self) -> $crate::Result<$crate::http::Response<$output>> {
                self.0.send_as().await
            }
        }
    };
}
pub(crate) use endpoint;

#[cfg(test)]
mod tests {
    use super::path;

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
