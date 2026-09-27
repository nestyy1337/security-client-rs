use std::{fmt, sync::Arc, time::Duration};

use base64::{
    Engine,
    alphabet::STANDARD,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose},
};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method,
    header::{AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
};
use serde::Serialize;
use url::Url;

use super::{Body, Response, body::Content, response::read_bounded};
use crate::{Error, Result};

/// The address used by [`Transport::single_node`] examples and local development stacks.
pub const DEFAULT_ADDRESS: &str = "http://localhost:5601";

pub(crate) const ERROR_LIMIT: usize = 16 * 1024;
const RESPONSE_LIMIT: usize = 32 * 1024 * 1024;

/// Credentials are redacted from `Debug` output.
#[derive(Clone)]
#[non_exhaustive]
pub enum Credentials {
    /// Username and password.
    Basic(String, String),
    /// An OAuth or Elasticsearch token service bearer token.
    Bearer(String),
    /// An API key as its ID and secret.
    ApiKey(String, String),
    /// A Base64-encoded API key, as displayed by Kibana when a key is created.
    EncodedApiKey(String),
}

impl Credentials {
    fn header(&self) -> Result<HeaderValue> {
        let encode =
            |id: &str, secret: &str| general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        let value = match self {
            Self::Basic(username, password) => format!("Basic {}", encode(username, password)),
            Self::Bearer(token) => format!("Bearer {token}"),
            Self::ApiKey(id, key) => format!("ApiKey {}", encode(id, key)),
            Self::EncodedApiKey(key) => format!("ApiKey {key}"),
        };
        let mut header = HeaderValue::from_str(&value).map_err(|_| {
            Error::Configuration("credential contains invalid header characters".into())
        })?;
        header.set_sensitive(true);
        Ok(header)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Basic(..) => "Credentials::Basic([redacted])",
            Self::Bearer(_) => "Credentials::Bearer([redacted])",
            Self::ApiKey(..) => "Credentials::ApiKey([redacted])",
            Self::EncodedApiKey(_) => "Credentials::EncodedApiKey([redacted])",
        })
    }
}

/// A trusted root certificate for the Kibana server.
#[derive(Clone)]
pub struct Certificate(reqwest::Certificate);

impl Certificate {
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        reqwest::Certificate::from_pem(pem)
            .map(Self)
            .map_err(|_| Error::Configuration("invalid PEM certificate".into()))
    }

    pub fn from_der(der: &[u8]) -> Result<Self> {
        reqwest::Certificate::from_der(der)
            .map(Self)
            .map_err(|_| Error::Configuration("invalid DER certificate".into()))
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certificate")
    }
}

#[derive(Debug)]
enum Proxy {
    System,
    Disabled,
    Url(Url),
}

/// Configures a [`Transport`]. Requests have a 60 second timeout, a 10 second
/// connect timeout and a 32 MiB response limit unless changed here.
#[derive(Debug)]
pub struct TransportBuilder {
    url: Url,
    credentials: Option<Credentials>,
    headers: HeaderMap,
    timeout: Duration,
    connect_timeout: Duration,
    certificates: Vec<Certificate>,
    proxy: Proxy,
    response_limit: usize,
}

impl TransportBuilder {
    /// Every request path is appended to `url`, so a reverse-proxy base path is preserved.
    pub fn new(url: Url) -> Self {
        Self {
            url,
            credentials: None,
            headers: HeaderMap::new(),
            timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            certificates: Vec::new(),
            proxy: Proxy::System,
            response_limit: RESPONSE_LIMIT,
        }
    }

    pub fn auth(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Sends a header with every request. Per-request headers take precedence.
    pub fn header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Sends these headers with every request, replacing earlier values for the same names.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        for (name, value) in &headers {
            self.headers.insert(name, value.clone());
        }
        self
    }

    /// The total time allowed for a request, including reading the body.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Trusts an additional root certificate alongside the platform roots.
    pub fn root_certificate(mut self, certificate: Certificate) -> Self {
        self.certificates.push(certificate);
        self
    }

    /// Routes every request through this proxy. Credentials may be embedded in the URL.
    pub fn proxy(mut self, url: Url) -> Self {
        self.proxy = Proxy::Url(url);
        self
    }

    /// Ignores proxy environment variables such as `HTTPS_PROXY`, which are honored by default.
    pub fn disable_proxy(mut self) -> Self {
        self.proxy = Proxy::Disabled;
        self
    }

    /// The largest body `Response::json`, `bytes` and `text` will read.
    pub fn response_limit(mut self, bytes: usize) -> Self {
        self.response_limit = bytes;
        self
    }

    pub fn build(self) -> Result<Transport> {
        let url = self.url;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
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

        let mut headers = HeaderMap::new();
        headers.insert("kbn-xsrf", HeaderValue::from_static("kibana-rs"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("kibana-rs/", env!("CARGO_PKG_VERSION"))),
        );
        if let Some(credentials) = &self.credentials {
            headers.insert(AUTHORIZATION, credentials.header()?);
        }
        for (name, value) in &self.headers {
            headers.insert(name, value.clone());
        }

        let mut client = reqwest::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never());
        for certificate in self.certificates {
            client = client.add_root_certificate(certificate.0);
        }
        client = match self.proxy {
            Proxy::System => client,
            Proxy::Disabled => client.no_proxy(),
            Proxy::Url(url) => client.proxy(
                reqwest::Proxy::all(url)
                    .map_err(|_| Error::Configuration("invalid proxy URL".into()))?,
            ),
        };

        Ok(Transport {
            inner: Arc::new(Inner {
                client: client.build()?,
                url,
                headers,
                response_limit: self.response_limit,
            }),
        })
    }
}

struct Inner {
    client: reqwest::Client,
    url: Url,
    headers: HeaderMap,
    response_limit: usize,
}

/// Sends requests to one Kibana address. Clones share the connection pool.
///
/// Requests are never retried and redirects are never followed. An interrupted
/// mutation can have an unknown outcome and must be reconciled by the caller.
#[derive(Clone)]
pub struct Transport {
    inner: Arc<Inner>,
}

impl Transport {
    pub fn single_node(url: &str) -> Result<Self> {
        let url = Url::parse(url)
            .map_err(|_| Error::Configuration("expected an absolute HTTP(S) URL".into()))?;
        TransportBuilder::new(url).build()
    }

    /// Connects to the Kibana endpoint encoded in an Elastic Cloud ID.
    pub fn cloud(cloud_id: &str, credentials: Credentials) -> Result<Self> {
        TransportBuilder::new(cloud_url(cloud_id)?)
            .auth(credentials)
            .build()
    }

    pub fn url(&self) -> &Url {
        &self.inner.url
    }

    /// Sends one request and checks its status.
    ///
    /// `path` must already be percent-encoded and is appended to the base URL.
    /// Non-success statuses become [`Error::Api`] with at most 16 KiB of body.
    pub async fn send<Q>(
        &self,
        method: Method,
        path: &str,
        headers: HeaderMap,
        query: Option<&Q>,
        body: Option<Body>,
        timeout: Option<Duration>,
    ) -> Result<Response>
    where
        Q: Serialize + ?Sized,
    {
        let mut request = self
            .inner
            .client
            .request(method, self.endpoint(path, query)?)
            .headers(self.inner.headers.clone());
        request = match body.map(|body| body.0) {
            None => request,
            Some(Content::Json(bytes)) => request
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(bytes),
            Some(Content::Multipart(form)) => request.multipart(form),
        };
        request = request.headers(headers);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }

        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let headers = Box::new(response.headers().clone());
            let (body, truncated) = read_bounded(response, ERROR_LIMIT).await?;
            return Err(Error::Api {
                status,
                headers,
                body: String::from_utf8_lossy(&body).into_owned(),
                truncated,
            });
        }
        Ok(Response::new(response, self.inner.response_limit))
    }

    fn endpoint<Q: Serialize + ?Sized>(&self, path: &str, query: Option<&Q>) -> Result<Url> {
        if path.contains(['?', '#']) {
            return Err(Error::InvalidRequest(
                "path must not contain a query or fragment".into(),
            ));
        }
        let mut url = self.inner.url.clone();
        let joined = format!(
            "{}/{}",
            url.path().trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        url.set_path(&joined);
        if let Some(query) = query {
            let query = serde_urlencoded::to_string(query).map_err(Error::serialize)?;
            if !query.is_empty() {
                url.set_query(Some(&query));
            }
        }
        Ok(url)
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("url", &self.inner.url.as_str())
            .finish_non_exhaustive()
    }
}

/// A Cloud ID is `name:base64(host[:port]$elasticsearch-id$kibana-id)`.
fn cloud_url(cloud_id: &str) -> Result<Url> {
    let invalid = || Error::Configuration("invalid Elastic Cloud ID".into());
    let (_, encoded) = cloud_id.rsplit_once(':').ok_or_else(invalid)?;
    let engine = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let decoded =
        String::from_utf8(engine.decode(encoded).map_err(|_| invalid())?).map_err(|_| invalid())?;
    let mut parts = decoded.split('$');
    let host = parts.next().filter(|h| !h.is_empty()).ok_or_else(invalid)?;
    let kibana = parts.nth(1).filter(|k| !k.is_empty()).ok_or_else(|| {
        Error::Configuration("Elastic Cloud ID does not include a Kibana endpoint".into())
    })?;
    let (host, port) = host.split_once(':').unwrap_or((host, "443"));
    Url::parse(&format!("https://{kibana}.{host}:{port}")).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloud_id(decoded: &str) -> String {
        format!("deployment:{}", general_purpose::STANDARD.encode(decoded))
    }

    #[test]
    fn cloud_ids_resolve_the_kibana_endpoint() {
        let url = cloud_url(&cloud_id("eu-west-1.aws.found.io$es-uuid$kb-uuid")).unwrap();
        assert_eq!(url.as_str(), "https://kb-uuid.eu-west-1.aws.found.io/");
        let url = cloud_url(&cloud_id("example.com:9243$es-uuid$kb-uuid")).unwrap();
        assert_eq!(url.as_str(), "https://kb-uuid.example.com:9243/");
        let unpadded = cloud_id("host.io$es$kb").trim_end_matches('=').to_owned();
        assert_eq!(cloud_url(&unpadded).unwrap().host_str(), Some("kb.host.io"));
        for invalid in [
            "no-separator".to_owned(),
            "name:not base64!".to_owned(),
            cloud_id("host.io$es-uuid"),
            cloud_id("host.io$es-uuid$"),
        ] {
            assert!(cloud_url(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn credentials_encode_the_documented_schemes() {
        let header = |c: Credentials| c.header().unwrap().to_str().unwrap().to_owned();
        assert_eq!(
            header(Credentials::Basic("elastic".into(), "changeme".into())),
            "Basic ZWxhc3RpYzpjaGFuZ2VtZQ=="
        );
        assert_eq!(
            header(Credentials::ApiKey("id".into(), "secret".into())),
            "ApiKey aWQ6c2VjcmV0"
        );
        assert_eq!(
            header(Credentials::EncodedApiKey("aWQ6c2VjcmV0".into())),
            "ApiKey aWQ6c2VjcmV0"
        );
        assert_eq!(header(Credentials::Bearer("token".into())), "Bearer token");
        assert!(Credentials::Bearer("line\nbreak".into()).header().is_err());
        assert!(
            Credentials::Basic("a".into(), "b".into())
                .header()
                .unwrap()
                .is_sensitive()
        );
    }
}
