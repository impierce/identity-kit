//! DID resolution types (DID Core §7.1, W3C DID Resolution): the result of resolving a DID, its
//! two metadata structures, the resolution options and the error vocabulary.

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;
use std::error::Error;
use std::sync::Arc;

use indexmap::IndexMap;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{Did, DidDocument, DidError};

/// Media type of the plain JSON representation of a DID document (DID Core §6.2).
pub const APPLICATION_DID_JSON: &str = "application/did+json";
/// Media type of the JSON-LD representation of a DID document (DID Core §6.3).
pub const APPLICATION_DID_LD_JSON: &str = "application/did+ld+json";

/// The error keywords of DID resolution (DID Core §7.1.2, DID Resolution).
///
/// [`ResolutionError::kind`] returns it; it is what the error serializes as and what callers
/// match on. A keyword this crate does not know is kept in [`Other`](Self::Other).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResolutionErrorKind {
    /// `invalidDid`: the DID does not conform to the DID syntax.
    InvalidDid,
    /// `notFound`: no DID document exists for the DID.
    NotFound,
    /// `methodNotSupported`: the resolver has no implementation of the DID method.
    MethodNotSupported,
    /// `representationNotSupported`: the resolver cannot produce the requested media type.
    RepresentationNotSupported,
    /// `invalidDidDocument`: the method returned a document that is malformed or not the
    /// document of the DID (DID Resolution "Errors").
    InvalidDidDocument,
    /// `internalError`: the resolver failed unexpectedly (DID Resolution "Errors").
    InternalError,
    /// Any other keyword.
    Other(String),
}

impl ResolutionErrorKind {
    /// The registered keyword, for example `notFound`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidDid => "invalidDid",
            Self::NotFound => "notFound",
            Self::MethodNotSupported => "methodNotSupported",
            Self::RepresentationNotSupported => "representationNotSupported",
            Self::InvalidDidDocument => "invalidDidDocument",
            Self::InternalError => "internalError",
            Self::Other(keyword) => keyword,
        }
    }
}

impl fmt::Display for ResolutionErrorKind {
    /// A short English description, for example "DID not found".
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDid => f.write_str("invalid DID"),
            Self::NotFound => f.write_str("DID not found"),
            Self::MethodNotSupported => f.write_str("DID method not supported"),
            Self::RepresentationNotSupported => f.write_str("representation not supported"),
            Self::InvalidDidDocument => f.write_str("invalid DID document"),
            Self::InternalError => f.write_str("internal resolver error"),
            Self::Other(keyword) => write!(f, "resolution error `{keyword}`"),
        }
    }
}

impl FromStr for ResolutionErrorKind {
    type Err = core::convert::Infallible;

    /// Never fails: an unknown keyword becomes [`ResolutionErrorKind::Other`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "invalidDid" => Self::InvalidDid,
            "notFound" => Self::NotFound,
            "methodNotSupported" => Self::MethodNotSupported,
            "representationNotSupported" => Self::RepresentationNotSupported,
            "invalidDidDocument" => Self::InvalidDidDocument,
            "internalError" => Self::InternalError,
            other => Self::Other(other.to_owned()),
        })
    }
}

/// Why a DID could not be resolved: a [`ResolutionErrorKind`] keyword, and optionally a
/// human-readable detail and the underlying error.
///
/// The keyword is the error as DID Core defines it: it is what the error serializes as, what
/// [`ResolutionMetadata::error`] reports, and the only part two errors are compared on. The
/// detail (the HTTP status of a failed `did:web` fetch, the ids of a mismatched document) and
/// the source (the HTTP client's error, the JSON or decoding error)
/// are diagnostics: they appear in [`Display`](fmt::Display) and [`Error::source`], and are
/// lost when the error is serialized.
///
/// # Examples
///
/// ```
/// use std::error::Error as _;
///
/// use identity_kit::did::{ResolutionError, ResolutionErrorKind};
///
/// let cause = std::io::Error::other("connection refused");
/// let error = ResolutionError::new(ResolutionErrorKind::InternalError)
///     .with_detail("fetching `https://example.com/.well-known/did.json` failed")
///     .with_source(cause);
///
/// assert_eq!(error.kind(), &ResolutionErrorKind::InternalError);
/// assert_eq!(error, ResolutionErrorKind::InternalError);
/// assert_eq!(error.as_str(), "internalError");
/// assert_eq!(
///     error.to_string(),
///     "internal resolver error: fetching `https://example.com/.well-known/did.json` failed: \
///      connection refused"
/// );
/// assert!(error.source().unwrap().downcast_ref::<std::io::Error>().is_some());
/// assert_eq!(serde_json::to_string(&error)?, r#""internalError""#);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ResolutionError {
    kind: ResolutionErrorKind,
    detail: Option<String>,
    source: Option<Arc<dyn Error + Send + Sync + 'static>>,
}

impl ResolutionError {
    /// An error reporting `kind`, without detail or source.
    pub const fn new(kind: ResolutionErrorKind) -> Self {
        Self {
            kind,
            detail: None,
            source: None,
        }
    }

    /// This error with a human-readable `detail`, replacing any previous one.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// This error caused by `source`, replacing any previous source.
    #[must_use]
    pub fn with_source<E: Error + Send + Sync + 'static>(mut self, source: E) -> Self {
        self.source = Some(Arc::new(source));
        self
    }

    /// The keyword.
    pub const fn kind(&self) -> &ResolutionErrorKind {
        &self.kind
    }

    /// The registered keyword, for example `notFound`.
    pub fn as_str(&self) -> &str {
        self.kind.as_str()
    }

    /// The human-readable detail, if any.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl fmt::Display for ResolutionError {
    /// The keyword's description, then the detail and the source's message when present, each
    /// after a colon.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for ResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Errors are equal when their keywords are; the detail and the source are not compared, so an
/// error equals its own serialization round trip.
impl PartialEq for ResolutionError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

impl Eq for ResolutionError {}

impl PartialEq<ResolutionErrorKind> for ResolutionError {
    fn eq(&self, other: &ResolutionErrorKind) -> bool {
        self.kind == *other
    }
}

impl Hash for ResolutionError {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
    }
}

impl From<ResolutionErrorKind> for ResolutionError {
    fn from(kind: ResolutionErrorKind) -> Self {
        Self::new(kind)
    }
}

impl FromStr for ResolutionError {
    type Err = core::convert::Infallible;

    /// Never fails: an unknown keyword becomes [`ResolutionErrorKind::Other`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self::new)
    }
}

impl From<DidError> for ResolutionError {
    /// [`ResolutionErrorKind::InvalidDid`], caused by `error`.
    fn from(error: DidError) -> Self {
        Self::new(ResolutionErrorKind::InvalidDid).with_source(error)
    }
}

impl Serialize for ResolutionError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ResolutionError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let keyword = String::deserialize(deserializer)?;
        if keyword.is_empty() || !keyword.is_ascii() {
            return Err(D::Error::custom("error must be an ASCII keyword"));
        }
        keyword.parse().map_err(|never| match never {})
    }
}

/// Options passed to a resolver (DID Core §7.1.1 "DID resolution options").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResolutionOptions {
    /// The media type the caller wants the document in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
    /// Every other option, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl ResolutionOptions {
    /// Options asking for `accept`.
    pub fn accept(media_type: impl Into<String>) -> Self {
        Self {
            accept: Some(media_type.into()),
            properties: IndexMap::new(),
        }
    }
}

/// Metadata about the resolution process (DID Core §7.1.3 "DID resolution metadata").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResolutionMetadata {
    /// The media type of the returned document.
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    /// Why resolution failed. Only the keyword is serialized; the detail and source of the
    /// error are kept in memory, for the caller of the resolver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ResolutionError>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl ResolutionMetadata {
    /// Metadata reporting `error`, a [`ResolutionError`] or a bare [`ResolutionErrorKind`].
    pub fn error(error: impl Into<ResolutionError>) -> Self {
        Self {
            content_type: None,
            error: Some(error.into()),
            properties: IndexMap::new(),
        }
    }

    /// Metadata reporting `content_type`.
    pub fn content_type(media_type: impl Into<String>) -> Self {
        Self {
            content_type: Some(media_type.into()),
            error: None,
            properties: IndexMap::new(),
        }
    }
}

/// Metadata about the DID document (DID Core §7.1.3 "DID document metadata").
///
/// Timestamps are XML Datetime strings in UTC without fractional seconds, as DID Core requires,
/// for example `2020-12-20T19:17:47Z`; this layer carries them as strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DocumentMetadata {
    /// When the DID was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// When the resolved version was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Whether the DID has been deactivated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    /// When the next version was written, if the resolved version is not the latest.
    #[serde(
        rename = "nextUpdate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_update: Option<String>,
    /// The version of the resolved document.
    #[serde(rename = "versionId", default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// The version after the resolved one, if any.
    #[serde(
        rename = "nextVersionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_version_id: Option<String>,
    /// DIDs the method defines as logically equivalent to the resolved one.
    #[serde(
        rename = "equivalentId",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub equivalent_id: Vec<Did>,
    /// The DID the method defines as canonical for the resolved one.
    #[serde(
        rename = "canonicalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub canonical_id: Option<Did>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl DocumentMetadata {
    /// Whether the DID is deactivated.
    pub fn is_deactivated(&self) -> bool {
        self.deactivated == Some(true)
    }
}

/// What a resolver returns: the document when resolution succeeded, and the two metadata
/// structures (DID Core §7.1.1).
///
/// # Examples
///
/// ```
/// use identity_kit::did::{ResolutionErrorKind, ResolutionResult};
///
/// let failed = ResolutionResult::error(ResolutionErrorKind::NotFound);
/// assert_eq!(
///     serde_json::to_string(&failed)?,
///     r#"{"didResolutionMetadata":{"error":"notFound"},"didDocumentMetadata":{}}"#
/// );
/// assert_eq!(failed.into_document().unwrap_err(), ResolutionErrorKind::NotFound);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResolutionResult {
    /// The DID document, absent when resolution failed.
    #[serde(
        rename = "didDocument",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub document: Option<DidDocument>,
    /// Metadata about the resolution process.
    #[serde(rename = "didResolutionMetadata", default)]
    pub resolution_metadata: ResolutionMetadata,
    /// Metadata about the document.
    #[serde(rename = "didDocumentMetadata", default)]
    pub document_metadata: DocumentMetadata,
}

impl ResolutionResult {
    /// A successful result holding `document`.
    pub fn new(document: DidDocument) -> Self {
        Self {
            document: Some(document),
            resolution_metadata: ResolutionMetadata::default(),
            document_metadata: DocumentMetadata::default(),
        }
    }

    /// A failed result reporting `error`, a [`ResolutionError`] or a bare
    /// [`ResolutionErrorKind`].
    pub fn error(error: impl Into<ResolutionError>) -> Self {
        Self {
            document: None,
            resolution_metadata: ResolutionMetadata::error(error),
            document_metadata: DocumentMetadata::default(),
        }
    }

    /// This result with `document_metadata`.
    #[must_use]
    pub fn with_document_metadata(mut self, metadata: DocumentMetadata) -> Self {
        self.document_metadata = metadata;
        self
    }

    /// This result with `resolution_metadata`.
    #[must_use]
    pub fn with_resolution_metadata(mut self, metadata: ResolutionMetadata) -> Self {
        self.resolution_metadata = metadata;
        self
    }

    /// The keyword of the reported error, if any; the error itself, with its detail and source,
    /// is in [`resolution_metadata`](Self::resolution_metadata).
    pub fn error_kind(&self) -> Option<&ResolutionErrorKind> {
        self.resolution_metadata
            .error
            .as_ref()
            .map(ResolutionError::kind)
    }

    /// The document, or the reported error; a result with neither counts as
    /// [`ResolutionErrorKind::NotFound`].
    ///
    /// # Errors
    ///
    /// The [`ResolutionError`] of the resolution metadata.
    pub fn into_document(self) -> Result<DidDocument, ResolutionError> {
        match (self.document, self.resolution_metadata.error) {
            (_, Some(error)) => Err(error),
            (Some(document), None) => Ok(document),
            (None, None) => Err(ResolutionErrorKind::NotFound.into()),
        }
    }
}

impl fmt::Display for ResolutionResult {
    /// The result as compact JSON, or a placeholder naming the reason when it cannot be
    /// serialized (a verification method holding a private JWK).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => f.write_str(&json),
            Err(e) => write!(f, "<unserializable resolution result: {e}>"),
        }
    }
}
