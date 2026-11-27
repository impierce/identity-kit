//! `JwsAlgorithm`: the digital signature algorithms this crate speaks.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// A JWS digital signature algorithm (RFC 7518 §3.1, RFC 8037 §3.1, RFC 8812 §3.2, RFC 9964 §5).
///
/// Only asymmetric algorithms are listed: a DID controller signs with a private key and anyone
/// resolves the public key, so HMAC and `none` have no place here. Conversions to and from
/// [`jsonwebtoken::Algorithm`] are fallible in both directions because `jsonwebtoken` has HMAC
/// variants this type lacks and lacks [`ES256K`](Self::ES256K).
///
/// The `Display` and `FromStr` forms are the IANA "JSON Web Signature and Encryption Algorithms"
/// names, and the type serializes as that string.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JwsAlgorithm;
///
/// let alg: JwsAlgorithm = "ES256".parse()?;
/// assert_eq!(alg, JwsAlgorithm::ES256);
/// assert_eq!(alg.to_string(), "ES256");
/// assert_eq!(serde_json::to_string(&alg)?, "\"ES256\"");
///
/// assert!("HS256".parse::<JwsAlgorithm>().is_err());
/// assert!("none".parse::<JwsAlgorithm>().is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum JwsAlgorithm {
    /// EdDSA with Ed25519 (RFC 8037).
    EdDSA,
    /// ECDSA with P-256 and SHA-256 (RFC 7518 §3.4). Verification accepts `s` and `n - s`
    /// alike, as JOSE allows, so a JWS's bytes do not identify it; see
    /// [`DefaultVerifier`](super::DefaultVerifier).
    ES256,
    /// ECDSA with secp256k1 and SHA-256 (RFC 8812 §3.2). Verification accepts only the lower of
    /// `s` and `n - s`.
    ES256K,
    /// ECDSA with P-384 and SHA-384 (RFC 7518 §3.4).
    ES384,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), with a key of at least 2048 bits.
    RS256,
    /// RSASSA-PSS with SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5), with a key of at least 2048 bits.
    PS256,
    /// ML-DSA-44 (FIPS 204, RFC 9964 §5): pure ML-DSA with an empty context string, an `AKP` key
    /// of 1312 bytes, 2420-byte signatures.
    #[serde(rename = "ML-DSA-44")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, RFC 9964 §5): pure ML-DSA with an empty context string, an `AKP` key
    /// of 1952 bytes, 3309-byte signatures.
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, RFC 9964 §5): pure ML-DSA with an empty context string, an `AKP` key
    /// of 2592 bytes, 4627-byte signatures.
    #[serde(rename = "ML-DSA-87")]
    MlDsa87,
}

impl JwsAlgorithm {
    /// Every algorithm this type knows, in declaration order.
    pub const ALL: &'static [JwsAlgorithm] = &[
        Self::EdDSA,
        Self::ES256,
        Self::ES256K,
        Self::ES384,
        Self::RS256,
        Self::PS256,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// The IANA name, for example `ES256`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
            Self::ES256K => "ES256K",
            Self::ES384 => "ES384",
            Self::RS256 => "RS256",
            Self::PS256 => "PS256",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Whether this is an ECDSA algorithm, whose JWS signature is the raw `r || s` concatenation.
    pub const fn is_ecdsa(self) -> bool {
        matches!(self, Self::ES256 | Self::ES256K | Self::ES384)
    }

    /// The `kty` and `crv` of the keys this algorithm signs with (RFC 7518 §6, RFC 8037 §2,
    /// RFC 8812 §3.1, RFC 9964 §3); `crv` is `None` for `RSA` and `AKP` keys. An `AKP` key also
    /// names its algorithm in `alg`, which must be this one.
    ///
    /// This is the crate's one mapping from algorithm to key type: key specs, signers, key
    /// generation ([`KeyType::for_algorithm`](super::KeyType::for_algorithm)) and the key store
    /// test suite all decide with it.
    pub const fn jwk_type(self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::EdDSA => ("OKP", Some("Ed25519")),
            Self::ES256 => ("EC", Some("P-256")),
            Self::ES256K => ("EC", Some("secp256k1")),
            Self::ES384 => ("EC", Some("P-384")),
            Self::RS256 | Self::PS256 => ("RSA", None),
            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => ("AKP", None),
        }
    }
}

impl fmt::Display for JwsAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An algorithm name that is not a [`JwsAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown or unsupported JWS algorithm `{0}`")]
pub struct UnknownAlgorithm(String);

impl UnknownAlgorithm {
    /// The rejected name.
    pub fn name(&self) -> &str {
        &self.0
    }
}

impl FromStr for JwsAlgorithm {
    type Err = UnknownAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|alg| alg.as_str() == s)
            .ok_or_else(|| UnknownAlgorithm(s.to_owned()))
    }
}

impl TryFrom<jsonwebtoken::Algorithm> for JwsAlgorithm {
    type Error = UnknownAlgorithm;

    /// Fails for the HMAC algorithms and the SHA-384/SHA-512 RSA variants.
    fn try_from(alg: jsonwebtoken::Algorithm) -> Result<Self, Self::Error> {
        use jsonwebtoken::Algorithm as A;
        match alg {
            A::EdDSA => Ok(Self::EdDSA),
            A::ES256 => Ok(Self::ES256),
            A::ES384 => Ok(Self::ES384),
            A::RS256 => Ok(Self::RS256),
            A::PS256 => Ok(Self::PS256),
            other => Err(UnknownAlgorithm(format!("{other:?}"))),
        }
    }
}

impl TryFrom<JwsAlgorithm> for jsonwebtoken::Algorithm {
    type Error = UnknownAlgorithm;

    /// Fails for [`JwsAlgorithm::ES256K`] and the ML-DSA algorithms, which `jsonwebtoken` does not
    /// implement.
    fn try_from(alg: JwsAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            JwsAlgorithm::EdDSA => Ok(Self::EdDSA),
            JwsAlgorithm::ES256 => Ok(Self::ES256),
            JwsAlgorithm::ES384 => Ok(Self::ES384),
            JwsAlgorithm::RS256 => Ok(Self::RS256),
            JwsAlgorithm::PS256 => Ok(Self::PS256),
            other => Err(UnknownAlgorithm(other.as_str().to_owned())),
        }
    }
}
