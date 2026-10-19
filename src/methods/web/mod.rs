//! `did:web`: a DID document served over HTTPS by a web origin.
//!
//! The [did:web method] maps a DID to the URL of its document: `did:web:example.com` is served
//! at `https://example.com/.well-known/did.json`, and `did:web:example.com%3A8443:user:alice`
//! at `https://example.com:8443/user/alice/did.json` (a port is percent-encoded as `%3A`, path
//! segments are separated by `:`). [`document_url`] implements that mapping and
//! [`did_from_url`] its inverse. The document is fetched through an [`HttpClient`] the caller
//! injects; [`ReqwestClient`] (feature `reqwest`) is a hardened default that speaks HTTPS only,
//! follows no redirect, refuses non-public addresses and caps the response size.
//!
//! The method is updated by republishing the document and deactivated by removing it; neither
//! has an API, so [`DidWeb`] as a [`DidProducer`] builds the document to publish and nothing
//! more.
//!
//! [did:web method]: https://w3c-ccg.github.io/did-method-web/

use core::fmt;
use std::error::Error;
use std::sync::Arc;

use url::{Host, Url};

use crate::did::{
    Context, Did, DidDocument, MethodType, ResolutionError, ResolutionErrorKind, ResolutionOptions,
    ResolutionResult, VerificationMaterial, VerificationMethod, VerificationRelationship,
};
use crate::jose::Jwk;
use crate::resolver::{DidProducer, DidResolver, Hosting, MethodCapabilities, ProduceError};

use super::check_accept;

#[cfg(feature = "reqwest")]
mod client;

#[cfg(feature = "reqwest")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
pub use client::ReqwestClient;
#[cfg(feature = "reqwest-local-network")]
#[cfg_attr(docsrs, doc(cfg(feature = "reqwest-local-network")))]
pub use client::{LocalNetwork, ReqwestClientBuilder};

/// The method name, `web`.
pub const METHOD: &str = "web";

/// The `@context` of a document [`DidWeb`] produces.
pub const CONTEXT: [&str; 2] = [
    Context::DID_V1,
    "https://w3id.org/security/suites/jws-2020/v1",
];

// ---------------------------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------------------------

/// What [`DidWeb`] needs from HTTP: a `GET` of a URL.
///
/// Implement it over the HTTP client of the application so `did:web` resolution shares its
/// connection pool, proxy and TLS settings. The implementation decides the security policy:
/// [`ReqwestClient`] is the one this crate ships.
///
/// Every URL a client is given comes from untrusted input (a DID, a credential's status list
/// reference), so an implementation must refuse what [`ReqwestClient`] refuses, or weigh the
/// consequence: plain `http`, redirects, hosts that resolve to loopback, private, link-local or
/// other non-public addresses, unbounded bodies and unbounded waits.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Fetches `url`, returning the status and the body of the final response.
    ///
    /// # Errors
    ///
    /// Any failure to get a response: a refused URL, a network or TLS error, a timeout, a body
    /// over the client's limit. An HTTP error status is a response, not an error.
    async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError>;
}

macro_rules! forward_http_client {
    ($($t:ty),* $(,)?) => {$(
        #[async_trait::async_trait]
        impl<T: HttpClient + ?Sized> HttpClient for $t {
            async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
                (**self).get(url).await
            }
        }
    )*};
}

forward_http_client!(&T, Box<T>, Arc<T>);

/// An HTTP response: the status code and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse {
    /// The status code, `200` for a served document.
    pub status: u16,
    /// The body, which a `did:web` resolver parses as JSON.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A response with `status` and `body`.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            body: body.into(),
        }
    }
}

/// Why an [`HttpClient`] could not get a response.
#[derive(Debug)]
pub struct HttpError(Box<dyn Error + Send + Sync + 'static>);

impl HttpError {
    /// Wraps `error`.
    pub fn new<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self(Box::new(error))
    }

    /// An error carrying `message`.
    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self(message.to_string().into())
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn Error + Send + Sync + 'static) {
        self.0.as_ref()
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for HttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<Box<dyn Error + Send + Sync + 'static>> for HttpError {
    fn from(error: Box<dyn Error + Send + Sync + 'static>) -> Self {
        Self(error)
    }
}

// ---------------------------------------------------------------------------------------------
// DID <-> URL
// ---------------------------------------------------------------------------------------------

/// Why a URL has no `did:web`, or a `did:web` no document URL.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WebError {
    /// The URL is not an HTTPS location a `did:web` can name.
    #[error("`{url}` cannot be a did:web: {reason}")]
    InvalidUrl {
        /// The URL.
        url: Url,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The DID is not a well-formed `did:web`.
    #[error("`{did}` is not a valid did:web: {reason}")]
    InvalidDid {
        /// The DID.
        did: Did,
        /// What is wrong with it.
        reason: &'static str,
    },
}

/// The directory of the document of a DID without path segments.
const WELL_KNOWN: &str = ".well-known";

/// The file name of the document.
const DOCUMENT_FILE: &str = "did.json";

/// The `did:web` whose document lives under `url`: `https://example.com` gives
/// `did:web:example.com`, `https://example.com:8443/user/alice` gives
/// `did:web:example.com%3A8443:user:alice`.
///
/// The URL must be `https`, name a domain (not an IP address) and carry no credentials, query
/// or fragment. A trailing slash is ignored, as is the document file name that
/// [`document_url`] appends (`/.well-known/did.json` or `/did.json`), so a document URL maps
/// back to its DID; other path segments become `:`-separated id segments, percent-encoded where
/// the DID syntax requires it.
///
/// # Errors
///
/// [`WebError::InvalidUrl`] when the URL breaks one of those rules.
///
/// # Examples
///
/// ```
/// use identity_kit::methods::web::did_from_url;
/// use url::Url;
///
/// let did = did_from_url(&Url::parse("https://example.com:3000/user/alice/")?)?;
/// assert_eq!(did.as_str(), "did:web:example.com%3A3000:user:alice");
/// let did = did_from_url(&Url::parse("https://example.com/.well-known/did.json")?)?;
/// assert_eq!(did.as_str(), "did:web:example.com");
/// assert!(did_from_url(&Url::parse("https://192.0.2.1/")?).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn did_from_url(url: &Url) -> Result<Did, WebError> {
    let invalid = |reason| WebError::InvalidUrl {
        url: url.clone(),
        reason,
    };
    if url.scheme() != "https" {
        return Err(invalid("the scheme must be `https`"));
    }
    let domain = match url.host() {
        Some(Host::Domain(domain)) => domain,
        Some(_) => return Err(invalid("the host must be a domain name, not an IP address")),
        None => return Err(invalid("the URL has no host")),
    };
    if !domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(invalid("the host has characters a DID cannot carry"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("the URL must not carry credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("the URL must not have a query or a fragment"));
    }
    let mut id = domain.to_owned();
    if let Some(port) = url.port() {
        id.push_str(&format!("%3A{port}"));
    }
    let mut segments: Vec<&str> = url
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default();
    if segments.last() == Some(&"") {
        segments.pop();
    }
    if segments.last() == Some(&DOCUMENT_FILE) {
        segments.pop();
        if segments.as_slice() == [WELL_KNOWN] {
            segments.clear();
        }
    }
    for segment in segments {
        if segment.is_empty() {
            return Err(invalid("the path has an empty segment"));
        }
        id.push(':');
        id.push_str(&encode_segment(segment));
    }
    Did::parse(&format!("did:web:{id}")).map_err(|_| invalid("the URL does not map to a DID"))
}

/// The `did:web` of the origin of `url`: as [`did_from_url`], but the URL must have no path.
///
/// # Errors
///
/// [`WebError::InvalidUrl`] when the URL has a path, or breaks a rule of [`did_from_url`].
pub fn did_from_origin(url: &Url) -> Result<Did, WebError> {
    if !matches!(url.path(), "" | "/") {
        return Err(WebError::InvalidUrl {
            url: url.clone(),
            reason: "an origin has no path",
        });
    }
    did_from_url(url)
}

/// `segment` with every byte outside the DID `idchar` set percent-encoded.
fn encode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_') {
            out.push(char::from(b));
        } else if b == b'%'
            && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            out.push_str(&segment[i..i + 3]);
            i += 3;
            continue;
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
        i += 1;
    }
    out
}

/// The URL of the document of `did` (the Read operation's URL construction):
/// `https://host[:port]/.well-known/did.json` for a bare domain, else
/// `https://host[:port]/<segments>/did.json`.
///
/// # Errors
///
/// [`WebError::InvalidDid`] when `did` is not a `did:web`, names an IP address, has a
/// malformed port, or has an empty, `.` or `..` path segment, percent-encoded or not.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Did;
/// use identity_kit::methods::web::document_url;
///
/// let url = document_url(&Did::parse("did:web:example.com")?)?;
/// assert_eq!(url.as_str(), "https://example.com/.well-known/did.json");
///
/// let url = document_url(&Did::parse("did:web:example.com%3A3000:user:alice")?)?;
/// assert_eq!(url.as_str(), "https://example.com:3000/user/alice/did.json");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn document_url(did: &Did) -> Result<Url, WebError> {
    let invalid = |reason| WebError::InvalidDid {
        did: did.clone(),
        reason,
    };
    if did.method() != METHOD {
        return Err(invalid("the method is not `web`"));
    }
    let mut segments = did.method_specific_id().split(':');
    let authority = percent_decode(segments.next().unwrap_or_default());
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority.as_str(), None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(invalid("the host is not a domain name"));
    }
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid("the port is not a number"));
    }
    let mut path = String::new();
    let mut has_segments = false;
    for segment in segments {
        if is_dot_segment(segment) {
            return Err(invalid("a path segment is empty, `.` or `..`"));
        }
        has_segments = true;
        path.push('/');
        path.push_str(segment);
    }
    if !has_segments {
        path.push('/');
        path.push_str(WELL_KNOWN);
    }
    let port = port.map(|port| format!(":{port}")).unwrap_or_default();
    let url = Url::parse(&format!("https://{host}{port}{path}/{DOCUMENT_FILE}"))
        .map_err(|_| invalid("the DID does not map to a URL"))?;
    match url.host() {
        Some(Host::Domain(_)) => Ok(url),
        _ => Err(invalid("the host is an IP address")),
    }
}

/// Whether `segment` is empty, or is `.` or `..` as the URL parser reads it: a segment of `.` and
/// `%2E` in any combination and case is a dot segment, which the parser collapses into the path
/// before it, so `did:web:example.com:a:%2E%2E:b` would name `https://example.com/b/did.json`.
fn is_dot_segment(segment: &str) -> bool {
    let mut dots = 0;
    let mut i = 0;
    let bytes = segment.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'.' {
            i += 1;
        } else if bytes[i..]
            .get(..3)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"%2e"))
        {
            i += 3;
        } else {
            return false;
        }
        dots += 1;
    }
    dots <= 2
}

/// Decodes the percent-encoded octets of a DID segment, which the DID syntax has checked to be
/// complete; non-UTF-8 octets become replacement characters and fail the host check.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(hi), Some(lo)) if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit() => {
                let hex = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
                out.push(hex(*hi) << 4 | hex(*lo));
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------------------------
// The method
// ---------------------------------------------------------------------------------------------

/// The `did:web` method: a [`DidResolver`] fetching documents through an [`HttpClient`], and a
/// [`DidProducer`] building the document to publish.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Did;
/// use identity_kit::methods::web::{DidWeb, HttpClient, HttpError, HttpResponse};
/// use identity_kit::resolver::Resolver;
/// use url::Url;
///
/// /// Serves one document from memory.
/// struct Static(String);
///
/// #[async_trait::async_trait]
/// impl HttpClient for Static {
///     async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
///         Ok(if url.as_str() == "https://example.com/.well-known/did.json" {
///             HttpResponse::new(200, self.0.as_bytes())
///         } else {
///             HttpResponse::new(404, Vec::new())
///         })
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let document = r#"{"id": "did:web:example.com"}"#.to_owned();
/// let resolver = Resolver::builder().with(DidWeb::new(Static(document))).build();
/// let did = Did::parse("did:web:example.com")?;
/// assert_eq!(resolver.resolve_document(&did).await?.id, did);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct DidWeb<C> {
    client: C,
}

impl<C: HttpClient> DidWeb<C> {
    /// The method fetching documents with `client`.
    pub const fn new(client: C) -> Self {
        Self { client }
    }

    /// The HTTP client.
    pub const fn client(&self) -> &C {
        &self.client
    }
}

#[async_trait::async_trait]
impl<C: HttpClient> DidResolver for DidWeb<C> {
    fn method(&self) -> &'static str {
        METHOD
    }

    /// Fetches the document of `did` from [`document_url`] and checks that its `id` is `did`.
    ///
    /// # Errors
    ///
    /// A [`ResolutionError`] whose kind is:
    ///
    /// - [`InvalidDid`](ResolutionErrorKind::InvalidDid) when `did` has no document URL, caused
    ///   by the [`WebError`].
    /// - [`NotFound`](ResolutionErrorKind::NotFound) on a `404` or `410` response.
    /// - [`InternalError`](ResolutionErrorKind::InternalError) when the client fails, caused by
    ///   its [`HttpError`], or when it returns any other non-success status, which the detail
    ///   names.
    /// - [`InvalidDidDocument`](ResolutionErrorKind::InvalidDidDocument) when the body is not a
    ///   DID document, caused by the [`serde_json::Error`], or is the document of another DID,
    ///   which the detail names.
    /// - [`RepresentationNotSupported`](ResolutionErrorKind::RepresentationNotSupported) for an
    ///   `accept` that is not JSON.
    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        check_accept(options)?;
        let url = document_url(did).map_err(|error| {
            ResolutionError::new(ResolutionErrorKind::InvalidDid).with_source(error)
        })?;
        let response = self.client.get(&url).await.map_err(|error| {
            ResolutionError::new(ResolutionErrorKind::InternalError)
                .with_detail(format!("fetching `{url}` failed"))
                .with_source(error)
        })?;
        let kind = match response.status {
            200..=299 => None,
            404 | 410 => Some(ResolutionErrorKind::NotFound),
            _ => Some(ResolutionErrorKind::InternalError),
        };
        if let Some(kind) = kind {
            return Err(ResolutionError::new(kind).with_detail(format!(
                "`{url}` responded with HTTP status {}",
                response.status
            )));
        }
        let document: DidDocument = serde_json::from_slice(&response.body).map_err(|error| {
            ResolutionError::new(ResolutionErrorKind::InvalidDidDocument)
                .with_detail(format!("the body of `{url}` is not a DID document"))
                .with_source(error)
        })?;
        if document.id != *did {
            return Err(
                ResolutionError::new(ResolutionErrorKind::InvalidDidDocument).with_detail(format!(
                    "`{url}` holds the document of `{}`, not `{did}`",
                    document.id
                )),
            );
        }
        Ok(ResolutionResult::new(document))
    }
}

#[async_trait::async_trait]
impl<C: HttpClient> DidProducer for DidWeb<C> {
    /// The HTTPS URL the document will be served under, as [`did_from_url`] reads it.
    type Params = Url;

    fn method(&self) -> &'static str {
        METHOD
    }

    /// Hosted on the web, any number of keys, updated by republishing; fragments come from the
    /// keys.
    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(Hosting::Web).with_updatable(true)
    }

    /// The document to publish at `url` for `keys`.
    ///
    /// Each key becomes a `JsonWebKey2020` verification method whose fragment is the key's
    /// `kid`, or `key-<index>` when it has none. A key with `use` `enc`, or an X25519 key, is
    /// referenced from `keyAgreement`; every other key from `authentication`,
    /// `assertionMethod`, `capabilityInvocation` and `capabilityDelegation`. The document's
    /// `@context` is [`CONTEXT`].
    ///
    /// # Errors
    ///
    /// - [`ProduceError::NoKeys`] without a key.
    /// - [`ProduceError::InvalidParams`] when `url` has no `did:web` (see [`did_from_url`]).
    /// - [`ProduceError::UnsupportedKey`] for a `kid` that is not a valid fragment.
    /// - [`ProduceError::Document`] for two keys with the same `kid`.
    async fn produce(&self, keys: &[Jwk], url: Url) -> Result<DidDocument, ProduceError> {
        if keys.is_empty() {
            return Err(ProduceError::NoKeys);
        }
        let did =
            did_from_url(&url).map_err(|error| ProduceError::InvalidParams(error.to_string()))?;
        let mut builder = DidDocument::builder(did.clone()).context(Context::uris(CONTEXT));
        for (index, key) in keys.iter().enumerate() {
            let id = match key.kid() {
                Some(kid) => {
                    did.join(&format!("#{kid}"))
                        .map_err(|_| ProduceError::UnsupportedKey {
                            index,
                            reason: format!("`kid` {kid:?} is not a valid DID URL fragment"),
                        })?
                }
                None => did.to_url().with_fragment(&format!("key-{index}")),
            };
            let relationships: &[VerificationRelationship] =
                if key.key_use() == Some("enc") || key.crv() == Some("X25519") {
                    &[VerificationRelationship::KeyAgreement]
                } else {
                    &[
                        VerificationRelationship::Authentication,
                        VerificationRelationship::AssertionMethod,
                        VerificationRelationship::CapabilityInvocation,
                        VerificationRelationship::CapabilityDelegation,
                    ]
                };
            let method = VerificationMethod::new(
                id,
                MethodType::JSON_WEB_KEY_2020,
                did.clone(),
                VerificationMaterial::jwk(key),
            );
            builder = builder.verification_method(method, relationships.iter().copied());
        }
        Ok(builder.build()?)
    }
}
