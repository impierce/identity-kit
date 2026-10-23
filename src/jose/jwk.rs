//! `Jwk`: a JSON Web Key (RFC 7517) with the parameters of RFC 7518 and RFC 8037.

use core::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::JwkError;
use super::base64url;

/// The kind of key behind a [`Jwk`], as a key store or HSM names it.
///
/// Used as the hint for [`Jwk::from_spki_der`], where it selects the parser and is checked against
/// the encoded key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// Ed25519, used with [`EdDSA`](super::JwsAlgorithm::EdDSA).
    Ed25519,
    /// NIST P-256 (secp256r1), used with [`ES256`](super::JwsAlgorithm::ES256).
    P256,
    /// secp256k1, used with [`ES256K`](super::JwsAlgorithm::ES256K).
    Secp256k1,
    /// RSA with a 2048-bit modulus, used with [`RS256`](super::JwsAlgorithm::RS256) and
    /// [`PS256`](super::JwsAlgorithm::PS256).
    Rsa2048,
    /// RSA with a 4096-bit modulus, used with [`RS256`](super::JwsAlgorithm::RS256) and
    /// [`PS256`](super::JwsAlgorithm::PS256).
    Rsa4096,
}

/// A JSON Web Key (RFC 7517).
///
/// A `Jwk` carries the common members (`kty`, `use`, `key_ops`, `alg`, `kid`), the public
/// parameters of RFC 7518 and RFC 8037 (`crv`, `x`, `y`, `n`, `e`), the private parameters (`d`,
/// `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) and any other member in an insertion-ordered map, so a
/// key round-trips through JSON with its extension members intact.
///
/// Private parameters never appear in `Debug` or `Display` output and are zeroized when the key
/// is dropped. [`Jwk::public`] strips them; serde serialization keeps them, because a key store
/// that persists private JWKs needs it to.
///
/// Members are kept as the base64url strings they arrive as. Nothing is validated when a key is
/// parsed; the accessors that decode the material ([`Jwk::ed25519_public_bytes`],
/// [`Jwk::p256_public_bytes`], …) and the operations that need it ([`Jwk::thumbprint_sha256`],
/// [`Jwk::to_decoding_key`], the verifiers) report what is wrong.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::Jwk;
///
/// // The Ed25519 key of RFC 8037 Appendix A.2.
/// let jwk: Jwk = serde_json::from_str(
///     r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
/// )?;
/// assert_eq!(jwk.kty(), "OKP");
/// assert_eq!(jwk.crv(), Some("Ed25519"));
/// assert_eq!(jwk.ed25519_public_bytes()?.len(), 32);
/// assert_eq!(jwk.thumbprint_sha256()?, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    e: Option<String>,
    // Private parameters follow the public ones, as in the examples of RFC 7517 Appendix A.2.
    #[serde(flatten)]
    pub(crate) private: PrivateParams,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    key_use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(flatten)]
    additional: IndexMap<String, Value>,
}

/// The private parameters of RFC 7518 §6.2.2, §6.3.2 and §6.4 and RFC 8037 §2.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PrivateParams {
    /// EC and OKP private key, RSA private exponent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) p: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) q: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) qi: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) oth: Option<Vec<OtherPrime>>,
    /// Symmetric key value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) k: Option<String>,
}

impl PrivateParams {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// One entry of the RSA `oth` member (RFC 7518 §6.3.2.7).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub(crate) struct OtherPrime {
    pub(crate) r: String,
    pub(crate) d: String,
    pub(crate) t: String,
}

/// Decodes the base64url member `name` of `value`.
fn decode_member(name: &'static str, value: Option<&str>) -> Result<Vec<u8>, JwkError> {
    let value = value.ok_or(JwkError::MissingMember(name))?;
    base64url::decode(value).map_err(|_| JwkError::InvalidBase64Url(name))
}

/// The shortest RSA modulus, in bits, a key may have to verify RS256 or PS256 signatures:
/// RFC 7518 §3.3 and §3.5 require "a key of size 2048 bits or larger".
const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Refuses an RSA modulus `n` (big-endian, leading zero octets allowed) shorter than
/// [`MIN_RSA_MODULUS_BITS`].
fn check_rsa_modulus_size(n: &[u8]) -> Result<(), JwkError> {
    let bits = match n.iter().position(|&b| b != 0) {
        Some(first) => (n.len() - first) * 8 - n[first].leading_zeros() as usize,
        None => 0,
    };
    if bits < MIN_RSA_MODULUS_BITS {
        return Err(JwkError::InvalidKey {
            key: "RSA",
            reason: format!(
                "the modulus is {bits} bits; RS256 and PS256 need at least {MIN_RSA_MODULUS_BITS}"
            ),
        });
    }
    Ok(())
}

impl Jwk {
    /// A key with only `kty` set, the starting point of the `from_*` constructors.
    fn with_kty(kty: &str) -> Self {
        Self {
            kty: kty.to_owned(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            key_use: None,
            key_ops: None,
            alg: None,
            kid: None,
            private: PrivateParams::default(),
            additional: IndexMap::new(),
        }
    }

    /// An `OKP` key with `crv` `Ed25519` from the 32-byte public key of RFC 8032.
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKey`] when `public` is not 32 bytes or not a valid point.
    pub fn from_ed25519_public(public: &[u8]) -> Result<Self, JwkError> {
        let bytes: &[u8; 32] = public.try_into().map_err(|_| JwkError::InvalidKey {
            key: "Ed25519",
            reason: format!("expected 32 bytes, found {}", public.len()),
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|e| JwkError::InvalidKey {
            key: "Ed25519",
            reason: e.to_string(),
        })?;
        let mut jwk = Self::with_kty("OKP");
        jwk.crv = Some("Ed25519".to_owned());
        jwk.x = Some(base64url::encode(bytes));
        Ok(jwk)
    }

    /// An `OKP` key with `crv` `X25519` from the 32-byte public key of RFC 7748, for key
    /// agreement (RFC 8037 §3).
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKeyLength`] when `public` is not 32 bytes.
    pub fn from_x25519_public(public: &[u8]) -> Result<Self, JwkError> {
        if public.len() != 32 {
            return Err(JwkError::InvalidKeyLength {
                key: "X25519",
                expected: 32,
                actual: public.len(),
            });
        }
        let mut jwk = Self::with_kty("OKP");
        jwk.crv = Some("X25519".to_owned());
        jwk.x = Some(base64url::encode(public));
        Ok(jwk)
    }

    /// An `EC` key with `crv` `P-256` from a SEC1-encoded point, compressed or uncompressed.
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKey`] when `sec1` is not a valid P-256 point.
    pub fn from_p256_public(sec1: &[u8]) -> Result<Self, JwkError> {
        let key = p256::PublicKey::from_sec1_bytes(sec1).map_err(|e| JwkError::InvalidKey {
            key: "P-256",
            reason: e.to_string(),
        })?;
        Ok(Self::from_p256_key(&key))
    }

    fn from_p256_key(key: &p256::PublicKey) -> Self {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let point = key.to_sec1_point(false);
        let mut jwk = Self::with_kty("EC");
        jwk.crv = Some("P-256".to_owned());
        jwk.x = point.x().map(|x| base64url::encode(x));
        jwk.y = point.y().map(|y| base64url::encode(y));
        jwk
    }

    /// An `EC` key with `crv` `secp256k1` from a SEC1-encoded point, compressed or uncompressed.
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKey`] when `sec1` is not a valid secp256k1 point.
    #[cfg(feature = "secp256k1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
    pub fn from_secp256k1_public(sec1: &[u8]) -> Result<Self, JwkError> {
        let key = k256::PublicKey::from_sec1_bytes(sec1).map_err(|e| JwkError::InvalidKey {
            key: "secp256k1",
            reason: e.to_string(),
        })?;
        Ok(Self::from_secp256k1_key(&key))
    }

    #[cfg(feature = "secp256k1")]
    fn from_secp256k1_key(key: &k256::PublicKey) -> Self {
        use k256::elliptic_curve::sec1::ToSec1Point as _;
        let point = key.to_sec1_point(false);
        let mut jwk = Self::with_kty("EC");
        jwk.crv = Some("secp256k1".to_owned());
        jwk.x = point.x().map(|x| base64url::encode(x));
        jwk.y = point.y().map(|y| base64url::encode(y));
        jwk
    }

    /// An `RSA` key from the big-endian modulus `n` and public exponent `e`.
    ///
    /// Leading zero octets are dropped, as RFC 7518 §6.3.1 requires. The values are not checked
    /// beyond being non-empty, like the other parsers of this crate leave the rules of an
    /// algorithm to verification: [`DefaultVerifier`](super::DefaultVerifier) and
    /// [`Jwk::to_decoding_key`] refuse a modulus shorter than 2048 bits (RFC 7518 §3.3, §3.5),
    /// and the verifier an otherwise unusable modulus or exponent, when the key is used.
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKey`] when `n` or `e` is empty.
    pub fn from_rsa_public(n: &[u8], e: &[u8]) -> Result<Self, JwkError> {
        if n.is_empty() || e.is_empty() {
            return Err(JwkError::InvalidKey {
                key: "RSA",
                reason: "modulus and exponent must not be empty".to_owned(),
            });
        }
        let mut jwk = Self::with_kty("RSA");
        jwk.n = Some(base64url::encode_uint(n));
        jwk.e = Some(base64url::encode_uint(e));
        Ok(jwk)
    }

    /// A key from a DER-encoded X.509 `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7), the form in
    /// which KMS and HSM backends return public keys.
    ///
    /// `hint` is what the caller expects and selects the parser; a key of another type is an
    /// error, as is an RSA modulus of another size than the hint names.
    ///
    /// # Errors
    ///
    /// - [`JwkError::InvalidKey`] when `der` does not decode as a key of the hinted type.
    /// - [`JwkError::KeyMismatch`] when it decodes but has another size than hinted.
    /// - [`JwkError::FeatureDisabled`] when the hinted type is compiled out.
    pub fn from_spki_der(hint: KeyType, der: &[u8]) -> Result<Self, JwkError> {
        match hint {
            KeyType::Ed25519 => {
                use ed25519_dalek::pkcs8::DecodePublicKey as _;
                let key = ed25519_dalek::VerifyingKey::from_public_key_der(der).map_err(|e| {
                    JwkError::InvalidKey {
                        key: "Ed25519",
                        reason: e.to_string(),
                    }
                })?;
                Self::from_ed25519_public(&key.to_bytes())
            }
            KeyType::P256 => {
                use p256::pkcs8::DecodePublicKey as _;
                let key = p256::PublicKey::from_public_key_der(der).map_err(|e| {
                    JwkError::InvalidKey {
                        key: "P-256",
                        reason: e.to_string(),
                    }
                })?;
                Ok(Self::from_p256_key(&key))
            }
            #[cfg(feature = "secp256k1")]
            KeyType::Secp256k1 => {
                use k256::pkcs8::DecodePublicKey as _;
                let key = k256::PublicKey::from_public_key_der(der).map_err(|e| {
                    JwkError::InvalidKey {
                        key: "secp256k1",
                        reason: e.to_string(),
                    }
                })?;
                Ok(Self::from_secp256k1_key(&key))
            }
            #[cfg(not(feature = "secp256k1"))]
            KeyType::Secp256k1 => Err(JwkError::FeatureDisabled {
                key: "secp256k1",
                feature: "secp256k1",
            }),
            #[cfg(feature = "rsa")]
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                use rsa::pkcs8::DecodePublicKey as _;
                use rsa::traits::PublicKeyParts as _;
                let key = rsa::RsaPublicKey::from_public_key_der(der).map_err(|e| {
                    JwkError::InvalidKey {
                        key: "RSA",
                        reason: e.to_string(),
                    }
                })?;
                let expected_bits = match hint {
                    KeyType::Rsa4096 => 4096,
                    _ => 2048,
                };
                if key.n().bits_vartime() != expected_bits {
                    return Err(JwkError::KeyMismatch { expected: hint });
                }
                Self::from_rsa_public(
                    &key.n().to_be_bytes_trimmed_vartime(),
                    &key.e().to_be_bytes_trimmed_vartime(),
                )
            }
            #[cfg(not(feature = "rsa"))]
            KeyType::Rsa2048 | KeyType::Rsa4096 => Err(JwkError::FeatureDisabled {
                key: "RSA",
                feature: "rsa",
            }),
        }
    }

    /// The key type (`kty`): `OKP`, `EC`, `RSA` or `oct`.
    pub fn kty(&self) -> &str {
        &self.kty
    }

    /// The curve (`crv`) of an `EC` or `OKP` key.
    pub fn crv(&self) -> Option<&str> {
        self.crv.as_deref()
    }

    /// The base64url `x` coordinate (`EC`) or public key (`OKP`).
    pub fn x(&self) -> Option<&str> {
        self.x.as_deref()
    }

    /// The base64url `y` coordinate of an `EC` key.
    pub fn y(&self) -> Option<&str> {
        self.y.as_deref()
    }

    /// The base64url RSA modulus `n`.
    pub fn n(&self) -> Option<&str> {
        self.n.as_deref()
    }

    /// The base64url RSA public exponent `e`.
    pub fn e(&self) -> Option<&str> {
        self.e.as_deref()
    }

    /// The public key use (`use`): `sig` or `enc`.
    pub fn key_use(&self) -> Option<&str> {
        self.key_use.as_deref()
    }

    /// The key operations (`key_ops`), such as `sign` and `verify`.
    pub fn key_ops(&self) -> Option<&[String]> {
        self.key_ops.as_deref()
    }

    /// The algorithm (`alg`) the key is intended for.
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// The key id (`kid`).
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Members other than the ones this type models, in the order they were inserted.
    pub fn additional(&self) -> &IndexMap<String, Value> {
        &self.additional
    }

    /// Mutable access to the members other than the ones this type models.
    pub fn additional_mut(&mut self) -> &mut IndexMap<String, Value> {
        &mut self.additional
    }

    /// Whether the key carries private parameters (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or
    /// `k`).
    pub fn is_private(&self) -> bool {
        !self.private.is_empty()
    }

    /// This key with its `kid` set.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// This key with its `alg` set.
    #[must_use]
    pub fn with_alg(mut self, alg: impl Into<String>) -> Self {
        self.alg = Some(alg.into());
        self
    }

    /// This key with its `use` set.
    #[must_use]
    pub fn with_key_use(mut self, key_use: impl Into<String>) -> Self {
        self.key_use = Some(key_use.into());
        self
    }

    /// This key with its `key_ops` set.
    #[must_use]
    pub fn with_key_ops<I, S>(mut self, key_ops: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.key_ops = Some(key_ops.into_iter().map(Into::into).collect());
        self
    }

    /// A copy of this key without private parameters.
    #[must_use]
    pub fn public(&self) -> Self {
        let mut public = self.clone();
        public.private = PrivateParams::default();
        public
    }

    /// The RFC 7638 JWK thumbprint with SHA-256, as base64url.
    ///
    /// The thumbprint hashes the required members of the key type (`crv`, `kty`, `x`, `y` for
    /// `EC`; `crv`, `kty`, `x` for `OKP`; `e`, `kty`, `n` for `RSA`; `k`, `kty` for `oct`) in
    /// lexicographic order with no whitespace, exactly as they appear in the key.
    ///
    /// # Errors
    ///
    /// [`JwkError::MissingMember`] when a required member is absent and
    /// [`JwkError::UnsupportedKeyType`] for any other `kty`.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::jose::Jwk;
    ///
    /// // RFC 7638 §3.1.
    /// let jwk: Jwk = serde_json::from_str(r#"{
    ///   "kty": "RSA",
    ///   "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    ///   "e": "AQAB",
    ///   "alg": "RS256",
    ///   "kid": "2011-04-29"
    /// }"#)?;
    /// assert_eq!(jwk.thumbprint_sha256()?, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn thumbprint_sha256(&self) -> Result<String, JwkError> {
        let canonical = self.thumbprint_input()?;
        Ok(base64url::encode(&Sha256::digest(canonical.as_bytes())))
    }

    /// The canonical JSON that [`Jwk::thumbprint_sha256`] hashes.
    pub(crate) fn thumbprint_input(&self) -> Result<String, JwkError> {
        fn member(name: &'static str, value: Option<&str>) -> Result<String, JwkError> {
            let value = value.ok_or(JwkError::MissingMember(name))?;
            // Serializing a `str` cannot fail.
            Ok(serde_json::to_string(value).unwrap_or_default())
        }
        let kty = serde_json::to_string(&self.kty).unwrap_or_default();
        Ok(match self.kty.as_str() {
            "EC" => format!(
                r#"{{"crv":{},"kty":{kty},"x":{},"y":{}}}"#,
                member("crv", self.crv())?,
                member("x", self.x())?,
                member("y", self.y())?
            ),
            "OKP" => format!(
                r#"{{"crv":{},"kty":{kty},"x":{}}}"#,
                member("crv", self.crv())?,
                member("x", self.x())?
            ),
            "RSA" => format!(
                r#"{{"e":{},"kty":{kty},"n":{}}}"#,
                member("e", self.e())?,
                member("n", self.n())?
            ),
            "oct" => format!(
                r#"{{"k":{},"kty":{kty}}}"#,
                member("k", self.private.k.as_deref())?
            ),
            _ => return Err(self.unsupported()),
        })
    }

    /// The 32-byte Ed25519 public key of an `OKP` key with `crv` `Ed25519`.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnexpectedKeyType`] for any other key, [`JwkError::MissingMember`] or
    /// [`JwkError::InvalidBase64Url`] for a broken `x`, and [`JwkError::InvalidKey`] when `x` is
    /// not a valid point.
    pub fn ed25519_public_bytes(&self) -> Result<[u8; 32], JwkError> {
        Ok(self.ed25519_verifying_key()?.to_bytes())
    }

    pub(crate) fn ed25519_verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, JwkError> {
        self.expect("Ed25519", "OKP", Some("Ed25519"))?;
        let x = decode_member("x", self.x())?;
        let bytes: &[u8; 32] = x.as_slice().try_into().map_err(|_| JwkError::InvalidKey {
            key: "Ed25519",
            reason: format!("expected 32 bytes, found {}", x.len()),
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|e| JwkError::InvalidKey {
            key: "Ed25519",
            reason: e.to_string(),
        })
    }

    /// The 32-byte X25519 public key of an `OKP` key with `crv` `X25519`.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnexpectedKeyType`] for any other key, [`JwkError::MissingMember`] or
    /// [`JwkError::InvalidBase64Url`] for a broken `x`, and [`JwkError::InvalidKeyLength`] when
    /// `x` is not 32 bytes.
    pub fn x25519_public_bytes(&self) -> Result<[u8; 32], JwkError> {
        self.expect("X25519", "OKP", Some("X25519"))?;
        let x = decode_member("x", self.x())?;
        x.as_slice()
            .try_into()
            .map_err(|_| JwkError::InvalidKeyLength {
                key: "X25519",
                expected: 32,
                actual: x.len(),
            })
    }

    /// The uncompressed SEC1 point (`0x04 || x || y`, 65 bytes) of an `EC` key with `crv`
    /// `P-256`.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnexpectedKeyType`] for any other key, [`JwkError::MissingMember`] or
    /// [`JwkError::InvalidBase64Url`] for a broken `x` or `y`, and [`JwkError::InvalidKey`] when
    /// the coordinates are not a point on the curve.
    pub fn p256_public_bytes(&self) -> Result<[u8; 65], JwkError> {
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let point = self.p256_public_key()?.to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .map_err(|_| JwkError::InvalidKey {
                key: "P-256",
                reason: "point is not 65 bytes".to_owned(),
            })
    }

    pub(crate) fn p256_public_key(&self) -> Result<p256::PublicKey, JwkError> {
        self.expect("P-256", "EC", Some("P-256"))?;
        let sec1 = self.ec_uncompressed_point(32, "P-256")?;
        p256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| JwkError::InvalidKey {
            key: "P-256",
            reason: e.to_string(),
        })
    }

    /// The uncompressed SEC1 point (`0x04 || x || y`, 65 bytes) of an `EC` key with `crv`
    /// `secp256k1`.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnexpectedKeyType`] for any other key, [`JwkError::MissingMember`] or
    /// [`JwkError::InvalidBase64Url`] for a broken `x` or `y`, and [`JwkError::InvalidKey`] when
    /// the coordinates are not a point on the curve.
    #[cfg(feature = "secp256k1")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
    pub fn secp256k1_public_bytes(&self) -> Result<[u8; 65], JwkError> {
        use k256::elliptic_curve::sec1::ToSec1Point as _;
        let point = self.secp256k1_public_key()?.to_sec1_point(false);
        point
            .as_bytes()
            .try_into()
            .map_err(|_| JwkError::InvalidKey {
                key: "secp256k1",
                reason: "point is not 65 bytes".to_owned(),
            })
    }

    #[cfg(feature = "secp256k1")]
    pub(crate) fn secp256k1_public_key(&self) -> Result<k256::PublicKey, JwkError> {
        self.expect("secp256k1", "EC", Some("secp256k1"))?;
        let sec1 = self.ec_uncompressed_point(32, "secp256k1")?;
        k256::PublicKey::from_sec1_bytes(&sec1).map_err(|e| JwkError::InvalidKey {
            key: "secp256k1",
            reason: e.to_string(),
        })
    }

    /// `0x04 || x || y` from the `x` and `y` members, each of which must be `len` bytes.
    fn ec_uncompressed_point(&self, len: usize, key: &'static str) -> Result<Vec<u8>, JwkError> {
        let x = decode_member("x", self.x())?;
        let y = decode_member("y", self.y())?;
        if x.len() != len || y.len() != len {
            return Err(JwkError::InvalidKey {
                key,
                reason: format!(
                    "expected {len}-byte coordinates, found {} and {}",
                    x.len(),
                    y.len()
                ),
            });
        }
        let mut sec1 = Vec::with_capacity(1 + 2 * len);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        Ok(sec1)
    }

    /// The big-endian modulus `n` and public exponent `e` of an `RSA` key.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnexpectedKeyType`] for any other key, [`JwkError::MissingMember`] or
    /// [`JwkError::InvalidBase64Url`] for a broken `n` or `e`.
    pub fn rsa_public_components(&self) -> Result<(Vec<u8>, Vec<u8>), JwkError> {
        self.expect("RSA", "RSA", None)?;
        Ok((decode_member("n", self.n())?, decode_member("e", self.e())?))
    }

    #[cfg(feature = "rsa")]
    pub(crate) fn rsa_public_key(&self) -> Result<rsa::RsaPublicKey, JwkError> {
        let (n, e) = self.rsa_public_components()?;
        if n.is_empty() || e.is_empty() {
            return Err(JwkError::InvalidKey {
                key: "RSA",
                reason: "modulus and exponent must not be empty".to_owned(),
            });
        }
        check_rsa_modulus_size(&n)?;
        // `rsa` sizes an integer by its octets, so a leading zero octet (which RFC 7518 §6.3.1
        // forbids but a JWK may carry) would make the modulus one octet longer than its value.
        let trim = |value: &[u8]| {
            let first = value
                .iter()
                .position(|&b| b != 0)
                .unwrap_or(value.len() - 1);
            value[first..].to_vec()
        };
        rsa::RsaPublicKey::new(
            rsa::BoxedUint::from_be_slice_vartime(&trim(&n)),
            rsa::BoxedUint::from_be_slice_vartime(&trim(&e)),
        )
        .map_err(|e| JwkError::InvalidKey {
            key: "RSA",
            reason: e.to_string(),
        })
    }

    /// A [`jsonwebtoken::DecodingKey`] for this key, so a JWT can be verified with `jsonwebtoken`.
    ///
    /// Supports `OKP`/`Ed25519`, `EC`/`P-256`, `EC`/`P-384` and `RSA` keys, the types
    /// `jsonwebtoken` can verify with. Private parameters are not needed and not used.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnsupportedKeyType`] for any other key, [`JwkError::MissingMember`] when a
    /// required member is absent, [`JwkError::InvalidBase64Url`] for an RSA modulus or exponent
    /// that is not base64url, [`JwkError::InvalidKey`] for an RSA modulus shorter than 2048 bits
    /// (RFC 7518 §3.3, §3.5) and [`JwkError::DecodingKey`] when `jsonwebtoken` rejects the
    /// material.
    pub fn to_decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, JwkError> {
        use jsonwebtoken::DecodingKey;
        let result = match (self.kty.as_str(), self.crv()) {
            ("OKP", Some("Ed25519")) => {
                DecodingKey::from_ed_components(self.x().ok_or(JwkError::MissingMember("x"))?)
            }
            ("EC", Some("P-256" | "P-384")) => DecodingKey::from_ec_components(
                self.x().ok_or(JwkError::MissingMember("x"))?,
                self.y().ok_or(JwkError::MissingMember("y"))?,
            ),
            ("RSA", _) => {
                check_rsa_modulus_size(&self.rsa_public_components()?.0)?;
                DecodingKey::from_rsa_components(
                    self.n().ok_or(JwkError::MissingMember("n"))?,
                    self.e().ok_or(JwkError::MissingMember("e"))?,
                )
            }
            _ => return Err(self.unsupported()),
        };
        result.map_err(|e| JwkError::DecodingKey(e.to_string()))
    }

    /// Checks that this is a `kty` key on curve `crv`.
    pub(super) fn expect(
        &self,
        expected: &'static str,
        kty: &str,
        crv: Option<&str>,
    ) -> Result<(), JwkError> {
        if self.kty == kty && (crv.is_none() || self.crv() == crv) {
            Ok(())
        } else {
            Err(JwkError::UnexpectedKeyType {
                expected,
                kty: self.kty.clone(),
                crv: self.crv.clone(),
            })
        }
    }

    pub(super) fn unsupported(&self) -> JwkError {
        JwkError::UnsupportedKeyType {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
        }
    }
}

impl fmt::Debug for Jwk {
    /// Public members only; private parameters are shown as `private: true`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Jwk");
        s.field("kty", &self.kty);
        for (name, value) in [
            ("crv", &self.crv),
            ("x", &self.x),
            ("y", &self.y),
            ("n", &self.n),
            ("e", &self.e),
            ("use", &self.key_use),
            ("alg", &self.alg),
            ("kid", &self.kid),
        ] {
            if let Some(value) = value {
                s.field(name, value);
            }
        }
        if let Some(key_ops) = &self.key_ops {
            s.field("key_ops", key_ops);
        }
        if !self.additional.is_empty() {
            s.field("additional", &self.additional);
        }
        s.field("private", &self.is_private());
        s.finish()
    }
}

impl fmt::Display for Jwk {
    /// The public key as compact JSON, as [`Jwk::public`] serializes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(&self.public()).map_err(|_| fmt::Error)?;
        f.write_str(&json)
    }
}
