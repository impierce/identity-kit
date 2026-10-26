//! Validation errors.

use core::fmt;
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::cause::cause;
use crate::did::{OneOrMany, Uri};
use crate::jose::{JwsError, VerificationError};
use crate::resolver::{KeyReference, KeyReferenceError, KeyResolutionError};
use crate::vc::CredentialError;

/// Why a credential or presentation JWT did not validate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The token is not a compact JWS this crate decodes.
    #[error("invalid JWS: {0}")]
    Jws(#[from] JwsError),
    /// The JWS header names no key this crate can look for: no `kid`, a `kid` that is not a
    /// DID URL, a DID URL with a path or DID parameters, a relative `kid` without a DID issuer.
    #[error(transparent)]
    KeyReference(#[from] KeyReferenceError),
    /// The header `typ` is not the one the profile requires.
    #[error("header `typ` is {found:?}, not `{expected}`")]
    UnexpectedTyp {
        /// The `typ` the profile requires.
        expected: &'static str,
        /// The `typ` found.
        found: String,
    },
    /// The payload is not a JSON claims set; the source is the JSON error.
    #[error("the payload is not a JWT claims set: {0}")]
    Payload(#[source] serde_json::Error),
    /// The claims do not map to a credential or presentation.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The payload carries `_sd_alg`, `_sd` or an array element `{"...": "<digest>"}`: it is
    /// the issuer-signed JWT of an SD-JWT, whose claims mean something else until its
    /// disclosures are processed, so it is not read as a plain JWT (RFC 8725 §3.12).
    /// `SdJwtCredentialValidator` of `sd_jwt_vc` validates it.
    #[error("the payload carries `{claim}`, so it is an SD-JWT, not a plain JWT")]
    SdJwtPayload {
        /// The claim found: `_sd_alg`, `_sd` or `...`.
        claim: &'static str,
    },
    /// The key the token names could not be resolved.
    #[error("resolving key {key}: {source}")]
    KeyResolution {
        /// Where the token says its key is.
        key: Box<KeyReference>,
        /// What went wrong.
        #[source]
        source: KeyResolutionError,
    },
    /// The signature does not verify under the resolved key.
    #[error("signature: {0}")]
    Signature(#[from] VerificationError),
    /// The issuer of the credential does not control the key that signed it.
    #[error("issuer `{issuer}` does not control signing key {key}")]
    IssuerMismatch {
        /// The issuer of the credential.
        issuer: Uri,
        /// Where the token says its key is.
        key: Box<KeyReference>,
    },
    /// The issuer is not a DID, so no key of it can be resolved.
    #[error("{role} `{id}` is not a DID")]
    NotDid {
        /// `issuer` or `holder`.
        role: &'static str,
        /// The identifier.
        id: String,
    },
    /// The holder of the presentation does not control the key that signed it.
    #[error("holder `{holder}` does not control signing key {key}")]
    HolderMismatch {
        /// The holder of the presentation.
        holder: Uri,
        /// Where the token says its key is.
        key: Box<KeyReference>,
    },
    /// The token or credential is not valid yet.
    #[error("not valid before {} (now is {})", not_before.to_rfc3339(), now.to_rfc3339())]
    NotYetValid {
        /// When it becomes valid.
        not_before: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
    },
    /// The token or credential has expired.
    #[error("expired at {} (now is {})", expired_at.to_rfc3339(), now.to_rfc3339())]
    Expired {
        /// When it expired.
        expired_at: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
    },
    /// The token claims to have been issued in the future.
    #[error("issued at {}, after now ({})", issued_at.to_rfc3339(), now.to_rfc3339())]
    IssuedInFuture {
        /// The `iat`.
        issued_at: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
    },
    /// The `aud` does not include the expected audience.
    #[error("audience {found:?} does not include {expected:?}")]
    AudienceMismatch {
        /// The audience expected.
        expected: String,
        /// The `aud` found.
        found: Option<OneOrMany<String>>,
    },
    /// The `nonce` is not the expected one.
    #[error("nonce {found:?} is not {expected:?}")]
    NonceMismatch {
        /// The nonce expected.
        expected: String,
        /// The `nonce` found.
        found: Option<String>,
    },
    /// The credential has a `credentialStatus` and the validator has no
    /// [`StatusCheck`](super::StatusCheck) for it.
    #[error("`credentialStatus` of type `{0}` cannot be checked")]
    StatusUnchecked(String),
    /// The status check failed or found the credential revoked or suspended.
    #[error("credential status: {0}")]
    Status(#[from] StatusError),
    /// The subject of a presented credential is not the holder presenting it.
    #[error("credential subject {subject:?} is not the holder `{holder}`")]
    SubjectHolderMismatch {
        /// The `id` of the subject, if any.
        subject: Option<Uri>,
        /// The holder of the presentation.
        holder: Uri,
    },
    /// A credential secured with SD-JWT, enveloped in a presentation, failed a check of its
    /// own: it is not a well-formed SD-JWT credential, or its key binding is missing or wrong.
    /// (A check shared with the JWT validators is reported as that check's own variant.)
    #[cfg(feature = "sd-jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
    #[error(transparent)]
    SdJwt(Box<crate::sd_jwt_vc::SdJwtValidationError>),
}

#[cfg(feature = "sd-jwt")]
impl From<crate::sd_jwt_vc::SdJwtValidationError> for ValidationError {
    /// Unwraps a shared check's error; boxes the SD-JWT-specific ones.
    fn from(error: crate::sd_jwt_vc::SdJwtValidationError) -> Self {
        match error {
            crate::sd_jwt_vc::SdJwtValidationError::Validation(error) => error,
            other => Self::SdJwt(Box::new(other)),
        }
    }
}

/// Why a [`StatusCheck`] did not pass.
///
/// The variants tell apart what a caller may want to handle differently: an
/// [`Unavailable`](Self::Unavailable) list may be fetched on a later attempt, an
/// [`Expired`](Self::Expired) one may be valid once its provider has refreshed it, and an
/// [`UnresolvedKey`](Self::UnresolvedKey) depends on why the resolver failed, which its source
/// says. An [`InvalidList`](Self::InvalidList) or an
/// [`IndexOutOfRange`](Self::IndexOutOfRange) will not pass by trying again.
///
/// Where a variant has a `source`, [`Error::source`](std::error::Error::source) returns it,
/// and the message ends with it.
///
/// [`StatusCheck`]: super::StatusCheck
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StatusError {
    /// The check does not understand the status type.
    #[error("status type `{0}` is not supported")]
    Unsupported(String),
    /// The status list could not be fetched: the request failed, the server answered with an
    /// error status, or the check refused a redirect. The source is the client's error, when
    /// there is one.
    #[error("status list {uri} unavailable: {reason}{}", cause(.source.as_ref()))]
    Unavailable {
        /// The status list URI the credential references.
        uri: String,
        /// What went wrong, naming the URL of a redirect hop where it is not `uri`.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The reference or the status list is not one the check can read or trust: a URI that is
    /// not a URL, a body that is not a status list token, a `sub` other than the URI, a
    /// signature that does not verify, a key that is not the issuer's. The source is the
    /// underlying error, when there is one.
    #[error("status list {uri} is invalid: {reason}{}", cause(.source.as_ref()))]
    InvalidList {
        /// The status list URI the credential references.
        uri: String,
        /// What is wrong.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// The key that signed the status list could not be resolved; the source is the
    /// resolver's error.
    #[error("status list {uri}: cannot resolve key {key}: {source}")]
    UnresolvedKey {
        /// The status list URI the credential references.
        uri: String,
        /// The key reference, as the token's header names it.
        key: String,
        /// The resolver's error.
        source: KeyResolutionError,
    },
    /// The status list has expired.
    #[error(
        "status list {uri} expired at {} (now is {})",
        expired_at.to_rfc3339(),
        now.to_rfc3339()
    )]
    Expired {
        /// The status list URI the credential references.
        uri: String,
        /// Its `exp`.
        expired_at: DateTime<Utc>,
        /// The validation time.
        now: DateTime<Utc>,
    },
    /// The credential's index is beyond the end of the status list.
    #[error("index {idx} is out of range of status list {uri} of {len} entries")]
    IndexOutOfRange {
        /// The status list URI the credential references.
        uri: String,
        /// The credential's index.
        idx: u64,
        /// The number of entries in the list.
        len: usize,
    },
    /// The credential's status makes it unusable: `revoked`, `suspended`, …
    #[error("credential is {0}")]
    Invalid(String),
}

/// Why a presentation did not validate: the presentation itself, or some of its credentials.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub struct PresentationValidationError {
    /// What is wrong with the presentation JWT; when set, no credential was validated.
    pub presentation: Option<Box<ValidationError>>,
    /// What is wrong with each failing credential, by its position in
    /// `verifiableCredential`.
    pub credentials: BTreeMap<usize, ValidationError>,
}

impl PresentationValidationError {
    /// An error of the presentation itself.
    pub fn presentation(error: ValidationError) -> Self {
        Self {
            presentation: Some(Box::new(error)),
            credentials: BTreeMap::new(),
        }
    }

    /// An error of the credentials at the given positions.
    pub fn credentials(errors: BTreeMap<usize, ValidationError>) -> Self {
        Self {
            presentation: None,
            credentials: errors,
        }
    }
}

impl fmt::Display for PresentationValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.presentation {
            return write!(f, "presentation: {error}");
        }
        for (i, (index, error)) in self.credentials.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "credential {index}: {error}")?;
        }
        Ok(())
    }
}
