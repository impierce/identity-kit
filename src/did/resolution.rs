//! DID resolution types (DID Core §7.1, W3C DID Resolution): the result of resolving a DID, its
//! two metadata structures, the resolution options and the error vocabulary.

use core::fmt;
use core::str::FromStr;

use indexmap::IndexMap;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{Did, DidDocument, DidError};

/// Media type of the plain JSON representation of a DID document (DID Core §6.2).
pub const APPLICATION_DID_JSON: &str = "application/did+json";
/// Media type of the JSON-LD representation of a DID document (DID Core §6.3).
pub const APPLICATION_DID_LD_JSON: &str = "application/did+ld+json";

/// The error vocabulary of DID resolution (DID Core §7.1.2, DID Resolution).
///
/// Serializes as the registered keyword, for example `notFound`; a keyword this crate does not
/// know is kept in [`Other`](Self::Other).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum ResolutionError {
    /// `invalidDid`: the DID does not conform to the DID syntax.
    #[error("invalid DID")]
    InvalidDid,
    /// `notFound`: no DID document exists for the DID.
    #[error("DID not found")]
    NotFound,
    /// `methodNotSupported`: the resolver has no implementation of the DID method.
    #[error("DID method not supported")]
    MethodNotSupported,
    /// `representationNotSupported`: the resolver cannot produce the requested media type.
    #[error("representation not supported")]
    RepresentationNotSupported,
    /// Any other keyword.
    #[error("resolution error `{0}`")]
    Other(String),
}

impl ResolutionError {
    /// The registered keyword, for example `notFound`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::InvalidDid => "invalidDid",
            Self::NotFound => "notFound",
            Self::MethodNotSupported => "methodNotSupported",
            Self::RepresentationNotSupported => "representationNotSupported",
            Self::Other(keyword) => keyword,
        }
    }
}

impl FromStr for ResolutionError {
    type Err = core::convert::Infallible;

    /// Never fails: an unknown keyword becomes [`ResolutionError::Other`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "invalidDid" => Self::InvalidDid,
            "notFound" => Self::NotFound,
            "methodNotSupported" => Self::MethodNotSupported,
            "representationNotSupported" => Self::RepresentationNotSupported,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl From<DidError> for ResolutionError {
    fn from(_: DidError) -> Self {
        Self::InvalidDid
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
    /// Why resolution failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ResolutionError>,
    /// Every other property, in insertion order.
    #[serde(flatten)]
    pub properties: IndexMap<String, Value>,
}

impl ResolutionMetadata {
    /// Metadata reporting `error`.
    pub fn error(error: ResolutionError) -> Self {
        Self {
            content_type: None,
            error: Some(error),
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
/// use identity_kit::did::{ResolutionError, ResolutionResult};
///
/// let failed = ResolutionResult::error(ResolutionError::NotFound);
/// assert_eq!(
///     serde_json::to_string(&failed)?,
///     r#"{"didResolutionMetadata":{"error":"notFound"},"didDocumentMetadata":{}}"#
/// );
/// assert_eq!(failed.into_document(), Err(ResolutionError::NotFound));
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

    /// A failed result reporting `error`.
    pub fn error(error: ResolutionError) -> Self {
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

    /// The reported error, if any.
    pub fn error_kind(&self) -> Option<&ResolutionError> {
        self.resolution_metadata.error.as_ref()
    }

    /// The document, or the reported error; a result with neither counts as
    /// [`ResolutionError::NotFound`].
    ///
    /// # Errors
    ///
    /// The [`ResolutionError`] of the resolution metadata.
    pub fn into_document(self) -> Result<DidDocument, ResolutionError> {
        match (self.document, self.resolution_metadata.error) {
            (_, Some(error)) => Err(error),
            (Some(document), None) => Ok(document),
            (None, None) => Err(ResolutionError::NotFound),
        }
    }
}

impl fmt::Display for ResolutionResult {
    /// The result as compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).map_err(|_| fmt::Error)?;
        f.write_str(&json)
    }
}
