use std::{fmt, sync::Arc, time::Duration};

use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::{
    Method, RequestBuilder, Response,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};
use url::Url;

use crate::{
    Error, Result, cases::Cases, exceptions::Exceptions, fleet::Fleet, roles::Roles,
    security::Security, spaces::Spaces,
};

const ERROR_LIMIT: usize = 16 * 1024;

/// Credentials are redacted from `Debug` output.
#[derive(Clone)]
pub enum Auth {
    None,
    Basic { username: String, password: String },
    ApiKey(String),
    Bearer(String),
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "Auth::None",
            Self::Basic { .. } => "Auth::Basic([redacted])",
            Self::ApiKey(_) => "Auth::ApiKey([redacted])",
            Self::Bearer(_) => "Auth::Bearer([redacted])",
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Global,
    Space,
}

#[derive(Clone, Debug, Serialize)]
pub struct PageOptions {
    pub page: u32,
    #[serde(rename = "perPage")]
    pub per_page: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kuery: Option<String>,
}

impl Default for PageOptions {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 50,
            kuery: None,
        }
    }
}

struct Inner {
    http: reqwest::Client,
    base: Url,
    auth: Auth,
    headers: HeaderMap,
    response_limit: usize,
}

/// Cloning a client or selecting a space shares the HTTP connection pool.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
    space: Option<String>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.inner.base)
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

pub struct ClientBuilder {
    base: String,
    auth: Auth,
    timeout: Duration,
    connect_timeout: Duration,
    headers: HeaderMap,
    certificates: Vec<reqwest::Certificate>,
    response_limit: usize,
}

impl ClientBuilder {
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
    pub fn response_limit(mut self, bytes: usize) -> Self {
        self.response_limit = bytes;
        self
    }
    pub fn root_certificate(mut self, cert: reqwest::Certificate) -> Self {
        self.certificates.push(cert);
        self
    }
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn build(self) -> Result<Client> {
        let base = Url::parse(&self.base)
            .map_err(|_| Error::Configuration("expected an absolute HTTP(S) URL".into()))?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(Error::Configuration(
                "base URL must use HTTP(S), without credentials, query, or fragment".into(),
            ));
        }
        if self.response_limit == 0 {
            return Err(Error::Configuration(
                "response limit must be positive".into(),
            ));
        }

        let mut http = reqwest::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .user_agent(concat!("kibana-rs/", env!("CARGO_PKG_VERSION")));
        for cert in self.certificates {
            http = http.add_root_certificate(cert);
        }

        Ok(Client {
            inner: Arc::new(Inner {
                http: http.build()?,
                base,
                auth: self.auth,
                headers: self.headers,
                response_limit: self.response_limit,
            }),
            space: None,
        })
    }
}

impl Client {
    pub fn builder(base: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base: base.into(),
            auth: Auth::None,
            timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            headers: HeaderMap::new(),
            certificates: Vec::new(),
            response_limit: 32 * 1024 * 1024,
        }
    }

    pub fn space(&self, id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id == "." || id == ".." || id.contains('/') {
            return Err(Error::Configuration("invalid space ID".into()));
        }
        Ok(Self {
            inner: self.inner.clone(),
            space: Some(id),
        })
    }

    pub fn default_space(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            space: None,
        }
    }
    pub fn security(&self) -> Security<'_> {
        Security(self)
    }
    pub fn fleet(&self) -> Fleet<'_> {
        Fleet(self)
    }
    pub fn exceptions(&self) -> Exceptions<'_> {
        Exceptions(self)
    }
    pub fn cases(&self) -> Cases<'_> {
        Cases(self)
    }
    pub fn spaces(&self) -> Spaces<'_> {
        Spaces(self)
    }
    pub fn roles(&self) -> Roles<'_> {
        Roles(self)
    }

    pub async fn status(&self) -> Result<serde_json::Value> {
        self.json(self.request(Method::GET, Scope::Global, &["api", "status"])?)
            .await
    }

    /// Build an authenticated request. Each path segment is encoded separately.
    /// Use `execute` to enforce status handling, or `json` for bounded JSON decoding.
    /// No retries or redirects are performed. Caller-supplied headers can override defaults.
    pub fn request(
        &self,
        method: Method,
        scope: Scope,
        segments: &[&str],
    ) -> Result<RequestBuilder> {
        if segments.is_empty()
            || segments
                .iter()
                .any(|s| s.is_empty() || *s == "." || *s == "..")
        {
            return Err(Error::Configuration(
                "path segments must be nonempty and cannot be dot segments".into(),
            ));
        }
        let mut url = self.inner.base.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| Error::Configuration("invalid base path".into()))?;
            path.pop_if_empty();
            if let Scope::Space = scope
                && let Some(id) = &self.space
            {
                path.push("s").push(id);
            }
            for segment in segments {
                path.push(segment);
            }
        }
        let mut req = self
            .inner
            .http
            .request(method, url)
            .header("kbn-xsrf", "kibana-rs")
            .headers(self.inner.headers.clone());
        req = match &self.inner.auth {
            Auth::None => req,
            Auth::Basic { username, password } => req.basic_auth(username, Some(password)),
            Auth::ApiKey(key) => req.header(AUTHORIZATION, secret_header("ApiKey", key)?),
            Auth::Bearer(token) => req.header(AUTHORIZATION, secret_header("Bearer", token)?),
        };
        Ok(req)
    }

    pub async fn execute(&self, request: RequestBuilder) -> Result<Response> {
        let response = request.send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let headers = Box::new(response.headers().clone());
        let (body, truncated) = read_bounded(response, ERROR_LIMIT).await?;
        Err(Error::Api {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
            truncated,
        })
    }

    pub async fn json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = self.execute(request).await?;
        let status = response.status();
        let (body, truncated) = read_bounded(response, self.inner.response_limit).await?;
        if truncated {
            return Err(Error::ResponseTooLarge {
                limit: self.inner.response_limit,
            });
        }

        serde_json::from_slice(&body).map_err(|source| Error::Decode {
            status,
            body: String::from_utf8_lossy(&body[..body.len().min(ERROR_LIMIT)]).into_owned(),
            source,
        })
    }

    pub(crate) async fn empty(&self, request: RequestBuilder) -> Result<()> {
        self.execute(request).await?;
        Ok(())
    }
}

fn secret_header(scheme: &str, value: &str) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(&format!("{scheme} {value}")).map_err(|_| {
        Error::Configuration("credential contains invalid header characters".into())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

async fn read_bounded(response: Response, limit: usize) -> Result<(Bytes, bool)> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining {
            return Ok((body.into(), true));
        }
    }
    Ok((body.into(), false))
}
