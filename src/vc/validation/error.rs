//! Validation errors.

use core::fmt;
use std::collections::BTreeMap;
use std::error::Error;

use chrono::{DateTime, Utc};

use crate::did::{DidError, DidUrl, OneOrMany, Uri};
use crate::jose::{JwsError, VerificationError};
use crate::vc::CredentialError;

/// Why a credential or presentation JWT did not validate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The token is not a compact JWS this crate decodes.
    #[error("invalid JWS: {0}")]
    Jws(#[from] JwsError),
    /// The JWS header has no `kid`, so the signing key cannot be found.
    #[error("the JWS header has no `kid`")]
    MissingKid,
    /// The `kid` is not a DID URL naming a verification method.
    #[error("`kid` {kid:?} is not a DID URL: {source}")]
    InvalidKid {
        /// The `kid`.
        kid: String,
        /// Why it did not parse.
        #[source]
        source: DidError,
    },
    /// The `kid` carries a path or DID parameters. `versionId` and `versionTime` could select a
    /// document version that still lists a retired key, so only `did:…#fragment` keys are
    /// accepted.
    #[error("`kid` `{0}` carries a path or DID parameters")]
    KidWithParameters(DidUrl),
    /// The header `typ` is not the one the profile requires.
    #[error("header `typ` is {found:?}, not `{expected}`")]
    UnexpectedTyp {
        /// The `typ` the profile requires.
        expected: &'static str,
        /// The `typ` found.
        found: String,
    },
    /// The payload is not a JSON claims set.
    #[error("the payload is not a JWT claims set: {0}")]
    Payload(String),
    /// The claims do not map to a credential or presentation.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The key `kid` names could not be resolved.
    #[error("resolving key `{kid}`: {source}")]
    KeyResolution {
        /// The `kid`.
        kid: DidUrl,
        /// What went wrong.
        #[source]
        source: KeyResolutionError,
    },
    /// The signature does not verify under the resolved key.
    #[error("signature: {0}")]
    Signature(#[from] VerificationError),
    /// The issuer of the credential does not control the key that signed it.
    #[error("issuer `{issuer}` does not control signing key `{kid}`")]
    IssuerMismatch {
        /// The issuer of the credential.
        issuer: Uri,
        /// The key that signed the JWT.
        kid: DidUrl,
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
    #[error("holder `{holder}` does not control signing key `{kid}`")]
    HolderMismatch {
        /// The holder of the presentation.
        holder: Uri,
        /// The key that signed the JWT.
        kid: DidUrl,
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
/// [`StatusCheck`]: super::StatusCheck
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StatusError {
    /// The check does not understand the status type.
    #[error("status type `{0}` is not supported")]
    Unsupported(String),
    /// The status could not be obtained: the list could not be fetched, say.
    #[error("status unavailable: {0}")]
    Unavailable(String),
    /// The credential's status makes it unusable: `revoked`, `suspended`, …
    #[error("credential is {0}")]
    Invalid(String),
}

/// Why a key could not be resolved for a [`KeyResolver`](super::KeyResolver).
#[derive(Debug)]
pub struct KeyResolutionError(Box<dyn Error + Send + Sync + 'static>);

impl KeyResolutionError {
    /// Wraps `error`.
    pub fn new<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self(Box::new(error))
    }

    /// An error carrying only `message`.
    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self(message.to_string().into())
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn Error + Send + Sync + 'static) {
        &*self.0
    }
}

impl fmt::Display for KeyResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for KeyResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<crate::resolver::DereferenceError> for KeyResolutionError {
    fn from(error: crate::resolver::DereferenceError) -> Self {
        Self::new(error)
    }
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
