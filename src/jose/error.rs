//! Error types of the `jose` module.

use core::fmt;
use std::error::Error;

use super::{JwsAlgorithm, KeyType};

/// Why a [`Jwk`](super::Jwk) cannot be built, or cannot be used the way it was asked to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwkError {
    /// A member the key type requires is absent.
    #[error("missing JWK member `{0}`")]
    MissingMember(&'static str),
    /// A member is not valid base64url without padding.
    #[error("JWK member `{0}` is not valid base64url")]
    InvalidBase64Url(&'static str),
    /// The key has a different type than the operation needs, for example an RSA key where an
    /// Ed25519 key was expected.
    #[error("expected {expected} key, found `kty` {kty:?} with `crv` {crv:?}")]
    UnexpectedKeyType {
        /// The key type the operation needs, such as `Ed25519` or `RSA`.
        expected: &'static str,
        /// The `kty` of the key.
        kty: String,
        /// The `crv` of the key, if any.
        crv: Option<String>,
    },
    /// The key type or curve is not one this crate supports.
    #[error("unsupported key type: `kty` {kty:?} with `crv` {crv:?}")]
    UnsupportedKeyType {
        /// The `kty` of the key.
        kty: String,
        /// The `crv` of the key, if any.
        crv: Option<String>,
    },
    /// The key material does not decode to a valid key: wrong length, not on the curve, even
    /// modulus, and so on.
    #[error("invalid {key} key: {reason}")]
    InvalidKey {
        /// The key type, such as `P-256`.
        key: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// The encoded key is valid but not of the [`KeyType`] that was expected.
    #[error("key is not a {expected:?} key")]
    KeyMismatch {
        /// The key type the caller expected.
        expected: KeyType,
    },
    /// Support for this key type is compiled out; enable the named Cargo feature.
    #[error("support for {key} keys requires the `{feature}` feature")]
    FeatureDisabled {
        /// The key type, such as `secp256k1`.
        key: &'static str,
        /// The Cargo feature that enables it.
        feature: &'static str,
    },
    /// `jsonwebtoken` rejected the key material.
    #[error("cannot build a jsonwebtoken decoding key: {0}")]
    DecodingKey(String),
}

/// Why a JWS signature did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// The verifier has no implementation of this algorithm, possibly because the Cargo feature
    /// that provides it is off.
    #[error("algorithm {0} is not supported by this verifier")]
    UnsupportedAlgorithm(JwsAlgorithm),
    /// The key's `alg` member names a different algorithm than the one being verified.
    #[error("key `alg` {key_alg:?} does not match {alg}")]
    AlgorithmMismatch {
        /// The algorithm being verified.
        alg: JwsAlgorithm,
        /// The `alg` member of the key.
        key_alg: String,
    },
    /// The key's `use` or `key_ops` member excludes signature verification.
    #[error("key is not meant for signature verification: {0}")]
    KeyUse(&'static str),
    /// The key cannot be used with this algorithm.
    #[error(transparent)]
    Key(#[from] JwkError),
    /// The signature does not have the length the algorithm requires.
    #[error("signature is {actual} bytes, expected {expected}")]
    InvalidSignatureLength {
        /// The length the algorithm requires.
        expected: usize,
        /// The length that was given.
        actual: usize,
    },
    /// An ECDSA signature was given in ASN.1 DER instead of the raw `r || s` form JWS requires.
    #[error("ECDSA signature appears to be DER-encoded; JWS requires the raw `r || s` form")]
    DerEncodedSignature,
    /// The signature is well-formed but does not verify under the key.
    #[error("signature verification failed")]
    InvalidSignature,
}

/// Why a compact JWS could not be decoded or produced.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwsError {
    /// The input is not three base64url parts separated by `.`.
    #[error("compact JWS must have exactly three parts separated by `.`, found {parts}")]
    InvalidFormat {
        /// The number of `.`-separated parts found.
        parts: usize,
    },
    /// A part is not valid base64url without padding.
    #[error("JWS {part} is not valid base64url")]
    InvalidBase64Url {
        /// Which part: `header`, `payload` or `signature`.
        part: &'static str,
    },
    /// The protected header is not a JSON object with the expected members.
    #[error("invalid JWS protected header: {0}")]
    InvalidHeader(String),
    /// The header `alg` is missing or not a [`JwsAlgorithm`].
    #[error("unsupported JWS algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// The header has a `crit` member; this crate understands no extensions, so it must reject
    /// every one of them (RFC 7515 §4.1.11).
    #[error("unsupported critical header parameters {0:?}")]
    UnsupportedCritical(Vec<String>),
    /// The header sets `b64` to `false` (RFC 7797); only base64url-encoded payloads are supported.
    #[error("unencoded payloads (`b64: false`) are not supported")]
    UnencodedPayload,
    /// The header `alg` differs from the algorithm of the signer.
    #[error("header `alg` {header} does not match the signer's {signer}")]
    AlgorithmMismatch {
        /// The `alg` in the header.
        header: JwsAlgorithm,
        /// The algorithm of the signer.
        signer: JwsAlgorithm,
    },
    /// The signer failed.
    #[error("signing failed: {0}")]
    Signer(#[source] SignError),
}

/// An error from a [`Signer`](super::Signer).
///
/// Signers live in key stores, HSMs and cloud services with their own error types; this wraps any
/// of them.
#[derive(Debug)]
pub struct SignError(Box<dyn Error + Send + Sync + 'static>);

impl SignError {
    /// Wraps `error`.
    pub fn new<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self(Box::new(error))
    }

    /// Wraps a message.
    pub fn msg<M: fmt::Display>(message: M) -> Self {
        Self(message.to_string().into())
    }

    /// The wrapped error.
    pub fn inner(&self) -> &(dyn Error + Send + Sync + 'static) {
        self.0.as_ref()
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Error for SignError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl From<Box<dyn Error + Send + Sync + 'static>> for SignError {
    fn from(error: Box<dyn Error + Send + Sync + 'static>) -> Self {
        Self(error)
    }
}
