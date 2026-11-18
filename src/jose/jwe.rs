//! JSON Web Encryption (RFC 7516) in the compact serialization, with ECDH-ES key agreement on
//! P-256 (RFC 7518 §4.6) and AES-GCM content encryption (RFC 7518 §5.3): what the OpenID4VC
//! High Assurance Interoperability Profile 1.0 (HAIP) §5 requires of an encrypted response
//! (OpenID4VP §8.3), and nothing more (ADR 0009).

use core::fmt;
use core::str::FromStr;
use std::collections::HashSet;
use std::error::Error;

use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{Jwk, JwkError, base64url};
use crate::cause::cause;

/// The length of an AES-GCM Initialization Vector, 96 bits (RFC 7518 §5.3).
const IV_LEN: usize = 12;

/// The length of an AES-GCM Authentication Tag, 128 bits (RFC 7518 §5.3).
const TAG_LEN: usize = 16;

/// The length of a P-256 ECDH shared secret, the `x` coordinate of the shared point.
const P256_SHARED_SECRET_LEN: usize = 32;

/// How much of an unsupported header value an error repeats: enough to name it, not so much
/// that a hostile header fills a log.
const SHOWN_LEN: usize = 64;

/// The header parameters [`JweHeader`] has fields for: a member of `additional` by one of these
/// names would be serialized next to the field, and read back in its place.
const REGISTERED: [&str; 9] = [
    "alg", "enc", "kid", "typ", "cty", "epk", "apu", "apv", "crit",
];

/// A JWE key management algorithm (`alg`, RFC 7518 §4.1) this crate implements.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JweAlgorithm;
///
/// assert_eq!("ECDH-ES".parse::<JweAlgorithm>()?, JweAlgorithm::EcdhEs);
/// assert_eq!(JweAlgorithm::EcdhEs.to_string(), "ECDH-ES");
/// # Ok::<(), identity_kit::jose::JweError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum JweAlgorithm {
    /// ECDH-ES in the Direct Key Agreement mode (RFC 7518 §4.6): the Concat KDF output over
    /// the shared secret is the Content Encryption Key, and the JWE Encrypted Key is empty.
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

impl JweAlgorithm {
    /// The registered name, as in the `alg` header parameter.
    pub const fn name(self) -> &'static str {
        match self {
            Self::EcdhEs => "ECDH-ES",
        }
    }
}

impl fmt::Display for JweAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for JweAlgorithm {
    type Err = JweError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ECDH-ES" => Ok(Self::EcdhEs),
            other => Err(JweError::UnsupportedAlgorithm(shown(other))),
        }
    }
}

/// A JWE content encryption algorithm (`enc`, RFC 7518 §5.1) this crate implements.
///
/// These are the values HAIP §5 requires: a Verifier supports both and lists both in
/// `encrypted_response_enc_values_supported`, a Wallet supports at least one. `A128GCM` is the
/// default of OpenID4VP §8.3 when a Verifier lists none.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JweEncryption;
///
/// assert_eq!("A256GCM".parse::<JweEncryption>()?, JweEncryption::A256Gcm);
/// assert_eq!(serde_json::to_string(&JweEncryption::A128Gcm)?, r#""A128GCM""#);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum JweEncryption {
    /// AES-GCM with a 128-bit key (RFC 7518 §5.3).
    #[serde(rename = "A128GCM")]
    A128Gcm,
    /// AES-GCM with a 256-bit key (RFC 7518 §5.3).
    #[serde(rename = "A256GCM")]
    A256Gcm,
}

impl JweEncryption {
    /// The registered name, as in the `enc` header parameter.
    pub const fn name(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// The length of the Content Encryption Key in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A256Gcm => 32,
        }
    }
}

impl fmt::Display for JweEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for JweEncryption {
    type Err = JweError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A128GCM" => Ok(Self::A128Gcm),
            "A256GCM" => Ok(Self::A256Gcm),
            other => Err(JweError::UnsupportedEncryption(shown(other))),
        }
    }
}

/// The JOSE header of a JWE (RFC 7516 §4), all of it in the JWE Protected Header, as the
/// compact serialization has no other.
///
/// The registered parameters this crate acts on are fields; everything else lives in
/// `additional` in insertion order. `epk` is set by [`CompactJwe::encrypt`].
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{JweAlgorithm, JweEncryption, JweHeader};
///
/// let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A128Gcm).with_kid("ac");
/// assert_eq!(
///     serde_json::to_string(&header)?,
///     r#"{"alg":"ECDH-ES","enc":"A128GCM","kid":"ac"}"#
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JweHeader {
    /// The key management algorithm (`alg`).
    pub alg: JweAlgorithm,
    /// The content encryption algorithm (`enc`).
    pub enc: JweEncryption,
    /// The id of the recipient's key (`kid`). OpenID4VP §8.3 requires the `kid` of the
    /// Verifier's key the response is encrypted to, when that key has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The media type of the whole JWE (`typ`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The media type of the plaintext (`cty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// The sender's ephemeral public key (`epk`, RFC 7518 §4.6.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epk: Option<Jwk>,
    /// Information about the sender (`apu`, RFC 7518 §4.6.1.2), base64url-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,
    /// Information about the recipient (`apv`, RFC 7518 §4.6.1.3), base64url-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,
    /// Extensions a recipient must understand (`crit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Every other header parameter, in insertion order.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl JweHeader {
    /// A header with only `alg` and `enc` set.
    pub fn new(alg: JweAlgorithm, enc: JweEncryption) -> Self {
        Self {
            alg,
            enc,
            kid: None,
            typ: None,
            cty: None,
            epk: None,
            apu: None,
            apv: None,
            crit: None,
            additional: IndexMap::new(),
        }
    }

    /// This header with its `kid` set.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// This header with its `typ` set.
    #[must_use]
    pub fn with_typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// This header with `apu` set to `party_u_info`, base64url-encoded.
    #[must_use]
    pub fn with_apu(mut self, party_u_info: &[u8]) -> Self {
        self.apu = Some(base64url::encode(party_u_info));
        self
    }

    /// This header with `apv` set to `party_v_info`, base64url-encoded.
    #[must_use]
    pub fn with_apv(mut self, party_v_info: &[u8]) -> Self {
        self.apv = Some(base64url::encode(party_v_info));
        self
    }
}

/// A JWE in the compact serialization (RFC 7516 §7.1): `BASE64URL(header) || '.' ||
/// BASE64URL(encrypted key) || '.' || BASE64URL(IV) || '.' || BASE64URL(ciphertext) || '.' ||
/// BASE64URL(tag)`.
///
/// [`decode`](Self::decode) parses one and checks it is a JWE this crate can decrypt;
/// [`decrypt`](Self::decrypt) then needs the recipient's key, which the recipient usually picks
/// by [`kid`](Self::kid). [`encrypt`](Self::encrypt) makes one to a recipient's public key.
///
/// # Examples
///
/// The encrypted response of OpenID4VP §8.3, decrypted with the Verifier's key:
///
/// ```
/// use identity_kit::jose::{CompactJwe, EcdhKey, JweEncryption, Jwk};
///
/// let response = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6ImFjIiwiZXBrIjp7Imt\
///     0eSI6IkVDIiwieCI6Im5ubVZwbTNWM2piaGNhZlFhUkJrU1ZOSGx3Wkh3dC05ck9wSnVmeVlJdWsiLCJ5I\
///     joicjRmakRxd0p5czlxVU9QLV9iM21SNVNaRy0tQ3dPMm1pYzVWU05UWU45ZyIsImNydiI6IlAtMjU2In1\
///     9..uAYcHRUSSn2X0WPX.yVzlGSYG4qbg0bq18JcUiDRw56yVnbKR8E7S7YlEtzT00RqE3Pw5oTpUG3hdLN\
///     4taHZ9gC1kwak8JOnJgQ.1wR024_3-qtAlx1oFIUpQQ";
/// let jwe = CompactJwe::decode(response)?;
/// assert_eq!(jwe.kid(), Some("ac"));
/// assert_eq!(jwe.header().enc, JweEncryption::A128Gcm);
///
/// let key: Jwk = serde_json::from_str(
///     r#"{"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
///         "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
///         "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
///         "d":"Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"}"#,
/// )?;
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let payload = jwe.decrypt(&EcdhKey::from_jwk(&key)?).await?;
/// let payload: serde_json::Value = serde_json::from_slice(&payload)?;
/// assert!(payload.get("vp_token").is_some());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct CompactJwe {
    token: String,
    /// Byte offset of the `.` after the protected header: the Additional Authenticated Data is
    /// the header as received, `token[..header_end]` (RFC 7516 §5.2 step 14).
    header_end: usize,
    header: JweHeader,
    iv: [u8; IV_LEN],
    ciphertext: Vec<u8>,
    tag: [u8; TAG_LEN],
}

impl CompactJwe {
    /// Parses a compact JWE without decrypting it, and checks that it is one this crate can
    /// decrypt.
    ///
    /// # Errors
    ///
    /// A [`JweError`] when the input is not five base64url parts, the header is not a JSON
    /// object with a supported `alg` and `enc` and a P-256 public `epk`, the header has `crit`
    /// or `zip`, the JWE Encrypted Key is not empty as ECDH-ES requires, or the IV or the tag
    /// is not of the AES-GCM length.
    pub fn decode(token: &str) -> Result<Self, JweError> {
        // Five parts read in place: a token of many `.` costs no memory to refuse.
        let mut parts = token.splitn(6, '.');
        let (Some(header_b64), Some(encrypted_key), Some(iv), Some(ciphertext), Some(tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(JweError::InvalidFormat {
                parts: token.split('.').count(),
            });
        };
        let header_json = base64url::decode(header_b64)
            .map_err(|_| JweError::InvalidBase64Url { part: "header" })?;
        let header = parse_header(&header_json)?;
        // ECDH-ES in the Direct Key Agreement mode: "the empty octet sequence is used as the
        // JWE Encrypted Key value" (RFC 7518 §4.6).
        if !encrypted_key.is_empty() {
            return Err(JweError::UnexpectedEncryptedKey);
        }
        let decode = |part: &'static str, value: &str| {
            base64url::decode(value).map_err(|_| JweError::InvalidBase64Url { part })
        };
        let iv = fixed_length("iv", decode("iv", iv)?)?;
        let ciphertext = decode("ciphertext", ciphertext)?;
        let tag = fixed_length("tag", decode("tag", tag)?)?;
        Ok(Self {
            token: token.to_owned(),
            header_end: header_b64.len(),
            header,
            iv,
            ciphertext,
            tag,
        })
    }

    /// Encrypts `plaintext` to `recipient`, an `EC` P-256 public key, under `header`: generates
    /// an ephemeral key pair, puts its public key in `epk`, derives the Content Encryption Key
    /// with ECDH-ES and the Concat KDF (RFC 7518 §4.6) over `apu` and `apv` as the header has
    /// them, and encrypts with a random IV.
    ///
    /// The header's `kid` is the recipient's: taken from `recipient` when the header has none,
    /// as OpenID4VP §8.3 requires, and refused when it names another key or `recipient` has
    /// none.
    ///
    /// # Errors
    ///
    /// [`JweError::InvalidKey`] when `recipient` is not an `EC` P-256 public key, has no `alg`
    /// or another than the header's (OpenID4VP §8.3 requires one), a `use` other than `enc`,
    /// `key_ops` with `sign` or `verify`, or private parameters, [`JweError::InvalidHeader`]
    /// when `header` already has an `epk`, has `zip` or `crit`, a `kid` that is not the
    /// recipient's, malformed `apu` or `apv` or equal non-empty ones, a
    /// field's name among its `additional` parameters, or anything else decoding refuses,
    /// [`JweError::PlaintextTooLong`] past 2^36 − 32 bytes of plaintext, and
    /// [`JweError::Random`] when the operating system has no randomness to give.
    pub fn encrypt(header: JweHeader, plaintext: &[u8], recipient: &Jwk) -> Result<Self, JweError> {
        let ephemeral = random_secret_key()?;
        Self::encrypt_with(header, plaintext, recipient, &ephemeral, random_iv()?)
    }

    /// [`encrypt`](Self::encrypt) with the ephemeral key and the IV given.
    fn encrypt_with(
        mut header: JweHeader,
        plaintext: &[u8],
        recipient: &Jwk,
        ephemeral: &p256::SecretKey,
        iv: [u8; IV_LEN],
    ) -> Result<Self, JweError> {
        let recipient_key = recipient_public_key(recipient, header.alg)?;
        if header.epk.is_some() {
            return Err(JweError::invalid_header(
                "`epk` is the sender's ephemeral key, which encryption generates",
            ));
        }
        if header.additional.contains_key("zip") {
            return Err(JweError::invalid_header("`zip` is not supported"));
        }
        // A header this crate would refuse to decode is not one to encrypt under.
        if header.crit.is_some() {
            return Err(JweError::invalid_header(
                "`crit` names extensions no recipient of this crate understands",
            ));
        }
        if let Some(name) = REGISTERED
            .iter()
            .find(|name| header.additional.contains_key(**name))
        {
            return Err(JweError::invalid_header(&format!(
                "`{name}` is a field of the header, not an additional parameter"
            )));
        }
        match (&header.kid, recipient.kid()) {
            (None, Some(kid)) => header.kid = Some(kid.to_owned()),
            (Some(kid), Some(recipient)) if kid != recipient => {
                return Err(JweError::invalid_header(
                    "`kid` differs from the `kid` of the recipient's key",
                ));
            }
            (Some(_), None) => {
                return Err(JweError::invalid_header(
                    "`kid` names a key, but the recipient's key has no `kid`",
                ));
            }
            _ => {}
        }
        header.epk = Some(Jwk::from_p256_key(&ephemeral.public_key()));

        let shared = ephemeral.diffie_hellman(&recipient_key);
        let cek = derive_cek(shared.raw_secret_bytes(), &header)?;
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| JweError::invalid_header_json("cannot be serialized", e))?;
        // A header decoding refuses (nested past the JSON parser's limit, equal `apu` and
        // `apv`) is not one to encrypt under.
        parse_header(&header_json)?;
        let header_b64 = base64url::encode(&header_json);
        let (ciphertext, tag) = seal(header.enc, &cek, &iv, header_b64.as_bytes(), plaintext)?;
        let token = format!(
            "{header_b64}..{}.{}.{}",
            base64url::encode(&iv),
            base64url::encode(&ciphertext),
            base64url::encode(&tag)
        );
        Ok(Self {
            header_end: header_b64.len(),
            token,
            header,
            iv,
            ciphertext,
            tag,
        })
    }

    /// Decrypts this JWE with the recipient's key and returns the plaintext.
    ///
    /// The Content Encryption Key is derived from the shared secret `recipient` computes with
    /// the sender's `epk`, and the plaintext is returned only when the authentication tag
    /// verifies over the ciphertext and the protected header as received.
    ///
    /// # Errors
    ///
    /// [`JweError::InvalidKey`] when `epk` is not a P-256 public key, an error of `recipient`,
    /// [`JweError::KeyAgreement`] when `recipient` returns a shared secret of other than 32
    /// bytes, and [`JweError::DecryptionFailed`] when the tag does not verify: the JWE was altered, or
    /// was encrypted to another key. The error says no more than that, on purpose.
    pub async fn decrypt<D>(&self, recipient: &D) -> Result<Vec<u8>, JweError>
    where
        D: JweDecrypter + ?Sized,
    {
        let epk = self
            .header
            .epk
            .as_ref()
            .ok_or_else(|| JweError::invalid_header("missing `epk`"))?;
        let shared = recipient.shared_secret(epk).await?;
        // A P-256 shared secret is the 32-byte `x` coordinate of the shared point; anything
        // else is a decrypter that returned the wrong value, not an altered JWE.
        if shared.len() != P256_SHARED_SECRET_LEN {
            return Err(JweError::KeyAgreement(
                format!(
                    "the shared secret is {} bytes, not the {P256_SHARED_SECRET_LEN} of a P-256 \
                     `x` coordinate",
                    shared.len()
                )
                .into(),
            ));
        }
        let cek = derive_cek(&shared, &self.header)?;
        open(
            self.header.enc,
            &cek,
            &self.iv,
            &self.token.as_bytes()[..self.header_end],
            &self.ciphertext,
            &self.tag,
        )
    }

    /// The JOSE header.
    pub fn header(&self) -> &JweHeader {
        &self.header
    }

    /// The `kid` of the recipient's key, if the header names it.
    pub fn kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }

    /// The compact serialization.
    pub fn as_str(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for CompactJwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactJwe")
            .field("header", &self.header)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for CompactJwe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token)
    }
}

impl AsRef<str> for CompactJwe {
    fn as_ref(&self) -> &str {
        &self.token
    }
}

/// The recipient's private key, as [`CompactJwe::decrypt`] needs it: what computes the ECDH
/// shared secret with the sender's ephemeral public key.
///
/// [`EcdhKey`] is a P-256 key held in memory, which is what an OpenID4VP Verifier uses: a fresh
/// key for each Authorization Request (HAIP §5). Implement this trait for a key kept elsewhere,
/// an HSM say; the crate derives the Content Encryption Key from the secret and decrypts.
#[async_trait::async_trait]
pub trait JweDecrypter: Send + Sync {
    /// The ECDH shared secret `Z` of the recipient's private key and `epk`, the `x` coordinate
    /// of the shared point as an octet string (RFC 7518 §4.6.2, NIST SP 800-56A §5.7.1.2).
    ///
    /// # Errors
    ///
    /// [`JweError::InvalidKey`] when `epk` is not a public key on the recipient key's curve, or
    /// [`JweError::KeyAgreement`] when the key's backend fails.
    async fn shared_secret(&self, epk: &Jwk) -> Result<Zeroizing<Vec<u8>>, JweError>;
}

macro_rules! forward_jwe_decrypter {
    ($($ty:ty),*) => {$(
        #[async_trait::async_trait]
        impl<T: JweDecrypter + ?Sized> JweDecrypter for $ty {
            async fn shared_secret(&self, epk: &Jwk) -> Result<Zeroizing<Vec<u8>>, JweError> {
                (**self).shared_secret(epk).await
            }
        }
    )*};
}

forward_jwe_decrypter!(&T, Box<T>, std::sync::Arc<T>);

/// A P-256 key for ECDH-ES, held in memory: a Verifier generates one for each request, puts
/// its [`public_jwk`](Self::public_jwk) in the request's client metadata, keeps it until the
/// response arrives, and decrypts the response with it.
///
/// The private key is zeroized when the value is dropped, and never printed.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{CompactJwe, EcdhKey, JweAlgorithm, JweEncryption, JweHeader};
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let verifier = EcdhKey::generate()?;
/// let public = verifier.public_jwk().with_kid("1");
/// assert_eq!(public.alg(), Some("ECDH-ES"));
/// assert!(!public.is_private());
///
/// // The Wallet encrypts its response to the key it found in the request.
/// let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A256Gcm);
/// let response = CompactJwe::encrypt(header, br#"{"vp_token":{}}"#, &public)?;
/// assert_eq!(response.kid(), Some("1"));
///
/// // The Verifier decrypts it.
/// let response = CompactJwe::decode(response.as_str())?;
/// assert_eq!(response.decrypt(&verifier).await?, br#"{"vp_token":{}}"#);
/// # Ok::<(), identity_kit::jose::JweError>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct EcdhKey {
    secret: p256::SecretKey,
}

impl EcdhKey {
    /// A new key from the operating system's random number generator.
    ///
    /// # Errors
    ///
    /// [`JweError::Random`] when the operating system has no randomness to give.
    pub fn generate() -> Result<Self, JweError> {
        random_secret_key().map(|secret| Self { secret })
    }

    /// The key a private `EC` P-256 JWK holds, such as one [`to_jwk`](Self::to_jwk) wrote.
    ///
    /// # Errors
    ///
    /// [`JweError::InvalidKey`] when `jwk` is not an `EC` P-256 key, has no valid `d`, has a
    /// `d` that does not belong to its `x` and `y`, or has a `use` other than `enc`, an `alg`
    /// other than `ECDH-ES`, or `key_ops` without `deriveKey` or `deriveBits` or with `sign` or
    /// `verify`.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, JweError> {
        // A key published for another purpose is not reused for key agreement.
        if jwk.key_use().is_some_and(|key_use| key_use != "enc") {
            return Err(JweError::invalid_key("the key is not for encryption"));
        }
        if jwk
            .alg()
            .is_some_and(|alg| alg != JweAlgorithm::EcdhEs.name())
        {
            return Err(JweError::invalid_key(
                "the key is for another algorithm than `ECDH-ES`",
            ));
        }
        check_agreement_key_ops(jwk, "the key's", true)?;
        let public = jwk.p256_public_key().map_err(JweError::key)?;
        let d = jwk
            .private
            .d
            .as_deref()
            .ok_or_else(|| JweError::key(JwkError::MissingMember("d")))?;
        let d = Zeroizing::new(
            base64url::decode(d).map_err(|_| JweError::key(JwkError::InvalidBase64Url("d")))?,
        );
        // A `d` of other than 32 bytes is malformed (RFC 7518 §6.2.2.1), even where the curve
        // arithmetic would pad it.
        let secret = <&[u8; 32]>::try_from(d.as_slice())
            .ok()
            .and_then(|d| p256::SecretKey::from_slice(d).ok())
            .ok_or_else(|| JweError::invalid_key("`d` is not a P-256 private key"))?;
        if secret.public_key() != public {
            return Err(JweError::invalid_key("`d` does not belong to `x` and `y`"));
        }
        Ok(Self { secret })
    }

    /// The public key, with `use` `enc` and `alg` `ECDH-ES`: what a Verifier publishes in the
    /// `jwks` of its client metadata, after giving it a `kid` (OpenID4VP §5.1 requires one).
    pub fn public_jwk(&self) -> Jwk {
        Jwk::from_p256_key(&self.secret.public_key())
            .with_key_use("enc")
            .with_alg(JweAlgorithm::EcdhEs.name())
    }

    /// The private key as a JWK, [`public_jwk`](Self::public_jwk) with `d`, to keep the key
    /// between the request and the response. It holds the private key: store it as a secret.
    pub fn to_jwk(&self) -> Jwk {
        let mut jwk = self.public_jwk();
        let d = Zeroizing::new(<[u8; 32]>::from(self.secret.to_bytes()));
        jwk.private.d = Some(base64url::encode(d.as_slice()));
        jwk
    }
}

impl fmt::Debug for EcdhKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdhKey")
            .field("public", &self.public_jwk())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl JweDecrypter for EcdhKey {
    async fn shared_secret(&self, epk: &Jwk) -> Result<Zeroizing<Vec<u8>>, JweError> {
        let epk = ephemeral_public_key(epk)?;
        let shared = self.secret.diffie_hellman(&epk);
        Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
    }
}

/// Why a JWE cannot be decoded, encrypted or decrypted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JweError {
    /// The input is not five parts separated by `.`.
    #[error("compact JWE must have exactly five parts separated by `.`, found {parts}")]
    InvalidFormat {
        /// The number of `.`-separated parts found.
        parts: usize,
    },
    /// A part is not valid base64url without padding.
    #[error("JWE {part} is not valid base64url")]
    InvalidBase64Url {
        /// Which part: `header`, `iv`, `ciphertext` or `tag`.
        part: &'static str,
    },
    /// The IV or the tag does not have the length AES-GCM uses.
    #[error("JWE {part} must be {expected} bytes, found {found}")]
    InvalidLength {
        /// Which part: `iv` or `tag`.
        part: &'static str,
        /// The length AES-GCM uses.
        expected: usize,
        /// The length found.
        found: usize,
    },
    /// The protected header is not a JSON object with the expected members. The source is the
    /// JSON error, when there is one.
    #[error("invalid JWE protected header: {reason}{}", cause(.source.as_ref()))]
    InvalidHeader {
        /// What is wrong with it.
        reason: String,
        /// The JSON error.
        source: Option<serde_json::Error>,
    },
    /// The header `alg` is not a [`JweAlgorithm`]. The value is cut to 64 characters.
    #[error("unsupported JWE algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// The header `enc` is not a [`JweEncryption`]. The value is cut to 64 characters.
    #[error("unsupported JWE content encryption {0:?}")]
    UnsupportedEncryption(String),
    /// The header has a `crit` member; this crate understands no extensions, so it must reject
    /// every one of them (RFC 7516 §4.1.13). The first eight names are kept, each cut to 64
    /// characters.
    #[error("unsupported critical header parameters {0:?}")]
    UnsupportedCritical(Vec<String>),
    /// The header has a `zip` member; compressed plaintext is not supported, and a recipient
    /// must not ignore it (RFC 7516 §4.1.3). The value is cut to 64 characters.
    #[error("unsupported JWE compression {0:?}")]
    UnsupportedCompression(String),
    /// The JWE Encrypted Key is not empty, as ECDH-ES in the Direct Key Agreement mode requires
    /// (RFC 7518 §4.6).
    #[error("JWE Encrypted Key must be empty for `ECDH-ES`")]
    UnexpectedEncryptedKey,
    /// A key cannot be used: the recipient's public key for encryption, the recipient's private
    /// key, or the sender's `epk`. The source is the JWK error, when there is one.
    #[error("invalid JWE key: {reason}{}", cause(.source.as_ref()))]
    InvalidKey {
        /// What is wrong with it.
        reason: String,
        /// The JWK error.
        source: Option<JwkError>,
    },
    /// A [`JweDecrypter`] backend failed to compute the shared secret.
    #[error("key agreement failed: {0}")]
    KeyAgreement(#[source] Box<dyn Error + Send + Sync>),
    /// The plaintext is longer than AES-GCM can encrypt under one IV, 2^36 − 32 bytes.
    #[error("the plaintext is too long for AES-GCM")]
    PlaintextTooLong,
    /// The operating system's random number generator failed.
    #[error("no randomness available: {0}")]
    Random(#[source] Box<dyn Error + Send + Sync>),
    /// The authentication tag does not verify: the JWE was altered, or encrypted to another
    /// key. On purpose, nothing tells which.
    #[error("JWE decryption failed")]
    DecryptionFailed,
}

impl JweError {
    fn invalid_header(reason: &str) -> Self {
        Self::InvalidHeader {
            reason: reason.to_owned(),
            source: None,
        }
    }

    fn invalid_header_json(reason: &str, source: serde_json::Error) -> Self {
        Self::InvalidHeader {
            reason: reason.to_owned(),
            source: Some(source),
        }
    }

    fn invalid_key(reason: &str) -> Self {
        Self::InvalidKey {
            reason: reason.to_owned(),
            source: None,
        }
    }

    fn key(source: JwkError) -> Self {
        Self::InvalidKey {
            reason: "not an `EC` P-256 key".to_owned(),
            source: Some(source),
        }
    }
}

/// Parses the header JSON, naming an unsupported `alg` or `enc` and rejecting `crit`, `zip`,
/// and an `epk` that is missing or not a P-256 public key.
fn parse_header(json: &[u8]) -> Result<JweHeader, JweError> {
    let value: Value =
        serde_json::from_slice(json).map_err(|e| JweError::invalid_header_json("not JSON", e))?;
    let Some(object) = value.as_object() else {
        return Err(JweError::invalid_header("not a JSON object"));
    };
    match object.get("alg") {
        Some(Value::String(alg)) => {
            alg.parse::<JweAlgorithm>()?;
        }
        Some(other) => return Err(JweError::UnsupportedAlgorithm(shown(&other.to_string()))),
        None => return Err(JweError::invalid_header("missing `alg`")),
    }
    match object.get("enc") {
        Some(Value::String(enc)) => {
            enc.parse::<JweEncryption>()?;
        }
        Some(other) => return Err(JweError::UnsupportedEncryption(shown(&other.to_string()))),
        None => return Err(JweError::invalid_header("missing `enc`")),
    }
    if let Some(zip) = object.get("zip") {
        let zip = zip.as_str().map_or_else(|| zip.to_string(), str::to_owned);
        return Err(JweError::UnsupportedCompression(shown(&zip)));
    }
    // Read from the JSON itself: `"crit": null` deserializes as no `crit` at all, and an
    // array is the only form RFC 7516 §4.1.13 allows.
    match object.get("crit") {
        None => {}
        Some(Value::Array(names)) => {
            let names = names
                .iter()
                .take(8)
                .map(|name| {
                    shown(
                        &name
                            .as_str()
                            .map_or_else(|| name.to_string(), str::to_owned),
                    )
                })
                .collect();
            return Err(JweError::UnsupportedCritical(names));
        }
        Some(_) => return Err(JweError::invalid_header("`crit` is not an array")),
    }
    // Read from the JSON itself: `null` deserializes as an absent member, but RFC 7516 §4.1 and
    // RFC 7518 §4.6.1 give these members as strings only.
    for name in ["kid", "typ", "cty", "apu", "apv"] {
        if object.get(name).is_some_and(|value| !value.is_string()) {
            return Err(JweError::invalid_header(&format!(
                "`{name}` is not a string"
            )));
        }
    }
    // `epk` holds only public parameters (RFC 7518 §4.6.1.1): a private one present in any
    // form, `null` included, is refused before it could read as absent.
    match object.get("epk") {
        None | Some(Value::Object(_)) => {}
        Some(_) => return Err(JweError::invalid_header("`epk` is not a JSON object")),
    }
    if let Some(Value::Object(epk)) = object.get("epk")
        && PRIVATE_JWK_MEMBERS
            .iter()
            .any(|name| epk.contains_key(*name))
    {
        return Err(JweError::invalid_key("`epk` has private parameters"));
    }
    // The JSON error is quoted cut short: it can repeat a string from the token.
    let header: JweHeader = serde_json::from_value(value).map_err(|e| {
        JweError::invalid_header(&format!("a member is malformed: {}", shown(&e.to_string())))
    })?;
    let epk = header
        .epk
        .as_ref()
        .ok_or_else(|| JweError::invalid_header("missing `epk`"))?;
    ephemeral_public_key(epk)?;
    let mut party_info = [None, None];
    for (slot, (name, value)) in party_info
        .iter_mut()
        .zip([("apu", &header.apu), ("apv", &header.apv)])
    {
        if let Some(value) = value {
            *slot = Some(base64url::decode(value).map_err(|_| {
                JweError::invalid_header(&format!("`{name}` is not valid base64url"))
            })?);
        }
    }
    // "The "apu" and "apv" values MUST be distinct, when used" (RFC 7518 §4.6.2); an empty
    // value is not used, and gives the KDF the same input as an absent one.
    if let [Some(apu), Some(apv)] = &party_info
        && !apu.is_empty()
        && apu == apv
    {
        return Err(JweError::invalid_header("`apu` and `apv` are equal"));
    }
    Ok(header)
}

/// The members of a JWK that are private parameters (RFC 7518 §6.2.2, §6.3.2 and §6.4).
const PRIVATE_JWK_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// At most the first [`SHOWN_LEN`] characters of `value`, with `…` when there were more.
fn shown(value: &str) -> String {
    match value.char_indices().nth(SHOWN_LEN) {
        Some((end, _)) => format!("{}…", &value[..end]),
        None => value.to_owned(),
    }
}

/// The sender's ephemeral public key: an `EC` P-256 key with only public parameters
/// (RFC 7518 §4.6.1.1), a point on the curve.
fn ephemeral_public_key(epk: &Jwk) -> Result<p256::PublicKey, JweError> {
    if epk.is_private() {
        return Err(JweError::invalid_key("`epk` has private parameters"));
    }
    // Named here, cut short: the JWK error would repeat `kty` and `crv` from the token in full.
    if epk.kty() != "EC" || epk.crv() != Some("P-256") {
        return Err(JweError::invalid_key(&format!(
            "`epk` is not an `EC` P-256 key: `kty` {:?}, `crv` {:?}",
            shown(epk.kty()),
            epk.crv().map(shown)
        )));
    }
    epk.p256_public_key().map_err(JweError::key)
}

/// The recipient's public key for encryption with `alg`: an `EC` P-256 public key whose `alg`
/// is `alg` (OpenID4VP §8.3: "The alg parameter MUST be present in the JWKs"), meant for
/// encryption by its `use` and `key_ops` when it has them.
fn recipient_public_key(recipient: &Jwk, alg: JweAlgorithm) -> Result<p256::PublicKey, JweError> {
    if recipient.is_private() {
        return Err(JweError::invalid_key(
            "the recipient's key has private parameters: it was published by mistake",
        ));
    }
    match recipient.alg() {
        Some(key_alg) if key_alg == alg.name() => {}
        Some(_) => {
            return Err(JweError::invalid_key(&format!(
                "the recipient's key is for another algorithm than `{alg}`"
            )));
        }
        None => {
            return Err(JweError::invalid_key(
                "the recipient's key has no `alg`, which OpenID4VP §8.3 requires",
            ));
        }
    }
    if recipient.key_use().is_some_and(|key_use| key_use != "enc") {
        return Err(JweError::invalid_key(
            "the recipient's key is not for encryption",
        ));
    }
    check_agreement_key_ops(recipient, "the recipient's", false)?;
    recipient.p256_public_key().map_err(JweError::key)
}

/// `key_ops`, when `jwk` has them, allow no signature operation, which would contradict a key
/// meant for encryption, nor any operation twice (RFC 7517 §4.3); a private
/// key's must also allow key agreement (`deriveKey` or `deriveBits`). A public key's need not:
/// in the Web Crypto API the private key holds the agreement usages, and an exported ECDH
/// public key has `"key_ops": []`.
fn check_agreement_key_ops(jwk: &Jwk, whose: &str, private: bool) -> Result<(), JweError> {
    let Some(ops) = jwk.key_ops() else {
        return Ok(());
    };
    // "Duplicate key operation values MUST NOT be present in the array" (RFC 7517 §4.3); one
    // pass, as a recipient key from another party can list any number of operations.
    let mut seen = HashSet::with_capacity(ops.len());
    if !ops.iter().all(|op| seen.insert(op.as_str())) {
        return Err(JweError::invalid_key(&format!(
            "{whose} `key_ops` repeat an operation"
        )));
    }
    if private && !ops.iter().any(|op| op == "deriveKey" || op == "deriveBits") {
        return Err(JweError::invalid_key(&format!(
            "{whose} `key_ops` allow no key agreement"
        )));
    }
    if ops.iter().any(|op| op == "sign" || op == "verify") {
        return Err(JweError::invalid_key(&format!(
            "{whose} `key_ops` make it a signature key too"
        )));
    }
    Ok(())
}

/// The Content Encryption Key for `header` from the shared secret `z`.
fn derive_cek(z: &[u8], header: &JweHeader) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let decode = |name: &str, value: Option<&str>| match value {
        Some(value) => base64url::decode(value)
            .map_err(|_| JweError::invalid_header(&format!("`{name}` is not valid base64url"))),
        None => Ok(Vec::new()),
    };
    let apu = decode("apu", header.apu.as_deref())?;
    let apv = decode("apv", header.apv.as_deref())?;
    // In the Direct Key Agreement mode the `AlgorithmID` is the `enc` value (RFC 7518 §4.6.2).
    concat_kdf(z, header.enc.name(), header.enc.key_len(), &apu, &apv)
}

/// The Concat KDF of NIST SP 800-56A §5.8.1 with SHA-256, as ECDH-ES parameterizes it
/// (RFC 7518 §4.6.2): a key of `key_len` bytes, at most 32 so that one round gives it, with `algorithm_id` as the `AlgorithmID`,
/// `apu` and `apv` as `PartyUInfo` and `PartyVInfo`, the key length in bits as `SuppPubInfo`,
/// and no `SuppPrivInfo`.
fn concat_kdf(
    z: &[u8],
    algorithm_id: &str,
    key_len: usize,
    apu: &[u8],
    apv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JweError> {
    let length = |data: &[u8]| {
        u32::try_from(data.len())
            .map(u32::to_be_bytes)
            .map_err(|_| JweError::invalid_header("`apu` or `apv` is too long"))
    };
    if key_len > 32 {
        return Err(JweError::invalid_header("a key of more than 256 bits"));
    }
    let key_bits =
        u32::try_from(key_len * 8).map_err(|_| JweError::invalid_header("the key is too long"))?;
    let mut other_info = Vec::new();
    for data in [algorithm_id.as_bytes(), apu, apv] {
        other_info.extend_from_slice(&length(data)?);
        other_info.extend_from_slice(data);
    }
    other_info.extend_from_slice(&key_bits.to_be_bytes());

    // Round 1 alone: every key here is at most 256 bits, one SHA-256 output. The digest is
    // wiped once copied; for A256GCM it is the key itself.
    let digest = Zeroizing::new(<[u8; 32]>::from(
        Sha256::new()
            .chain_update(1_u32.to_be_bytes())
            .chain_update(z)
            .chain_update(&other_info)
            .finalize(),
    ));
    Ok(Zeroizing::new(digest[..key_len].to_vec()))
}

/// Whether AES-GCM encrypts a plaintext of `len` bytes under one IV: at most 2^36 − 32
/// (NIST SP 800-38D §5.2.1.1). Checked before the plaintext is copied.
fn fits_aes_gcm(len: usize) -> bool {
    u64::try_from(len).is_ok_and(|len| len <= aes_gcm::P_MAX)
}

/// Encrypts `plaintext` with AES-GCM: the ciphertext and the authentication tag.
fn seal(
    enc: JweEncryption,
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), JweError> {
    fn run<A: AeadInOut + KeyInit>(
        cek: &[u8],
        iv: &[u8; IV_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Option<[u8; TAG_LEN]> {
        let cipher = A::new_from_slice(cek).ok()?;
        let nonce = <&Nonce<A>>::try_from(iv.as_slice()).ok()?;
        let tag = cipher
            .encrypt_inout_detached(nonce, aad, buffer.into())
            .ok()?;
        tag.as_slice().try_into().ok()
    }
    if !fits_aes_gcm(plaintext.len()) {
        return Err(JweError::PlaintextTooLong);
    }
    let mut buffer = plaintext.to_vec();
    let tag = match enc {
        JweEncryption::A128Gcm => run::<Aes128Gcm>(cek, iv, aad, &mut buffer),
        JweEncryption::A256Gcm => run::<Aes256Gcm>(cek, iv, aad, &mut buffer),
    };
    // With a key of the right length, AES-GCM fails only on a plaintext too long.
    let tag = tag.ok_or(JweError::PlaintextTooLong)?;
    Ok((buffer, tag))
}

/// Decrypts `ciphertext` with AES-GCM, if `tag` verifies.
fn open(
    enc: JweEncryption,
    cek: &[u8],
    iv: &[u8; IV_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Vec<u8>, JweError> {
    fn run<A: AeadInOut + KeyInit>(
        cek: &[u8],
        iv: &[u8; IV_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Option<()> {
        let cipher = A::new_from_slice(cek).ok()?;
        let nonce = <&Nonce<A>>::try_from(iv.as_slice()).ok()?;
        let tag = <&Tag<A>>::try_from(tag.as_slice()).ok()?;
        cipher
            .decrypt_inout_detached(nonce, aad, buffer.into(), tag)
            .ok()
    }
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let opened = match enc {
        JweEncryption::A128Gcm => run::<Aes128Gcm>(cek, iv, aad, &mut buffer, tag),
        JweEncryption::A256Gcm => run::<Aes256Gcm>(cek, iv, aad, &mut buffer, tag),
    };
    opened.ok_or(JweError::DecryptionFailed)?;
    Ok(core::mem::take(&mut *buffer))
}

/// `bytes` as an array of `N`, the length AES-GCM uses for `part`.
fn fixed_length<const N: usize>(part: &'static str, bytes: Vec<u8>) -> Result<[u8; N], JweError> {
    let found = bytes.len();
    bytes.try_into().map_err(|_| JweError::InvalidLength {
        part,
        expected: N,
        found,
    })
}

/// Fills `buf` from the operating system's random number generator.
fn fill_random(buf: &mut [u8]) -> Result<(), JweError> {
    getrandom::fill(buf).map_err(|e| JweError::Random(Box::new(e)))
}

/// A random 96-bit IV, drawn as two numbers from the operating system's random number
/// generator.
fn random_iv() -> Result<[u8; IV_LEN], JweError> {
    let failed = |e: getrandom::Error| JweError::Random(Box::new(e));
    let high = getrandom::u64().map_err(failed)?.to_be_bytes();
    let low = getrandom::u32().map_err(failed)?.to_be_bytes();
    Ok(core::array::from_fn(|i| {
        if i < high.len() {
            high[i]
        } else {
            low[i - high.len()]
        }
    }))
}

/// A random P-256 private key.
fn random_secret_key() -> Result<p256::SecretKey, JweError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    loop {
        fill_random(bytes.as_mut())?;
        // A scalar outside `1..n` is rejected; the probability is below 2^-32 per draw.
        if let Ok(secret) = p256::SecretKey::from_slice(bytes.as_ref()) {
            return Ok(secret);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(s: &str) -> Vec<u8> {
        base64url::decode(s).unwrap()
    }

    fn jwk(json: &str) -> Jwk {
        serde_json::from_str(json).unwrap()
    }

    /// RFC 7518 Appendix C: Alice's ephemeral key and Bob's key.
    const ALICE: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
        "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}"#;
    const BOB: &str = r#"{"kty":"EC","crv":"P-256",
        "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#;
    /// RFC 7518 Appendix C: the shared secret `Z`.
    const Z: [u8; 32] = [
        158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110,
        163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
    ];

    /// RFC 7518 Appendix C: the shared secret of both sides, and the A128GCM key the Concat
    /// KDF derives from it with `apu` "Alice" and `apv` "Bob".
    #[tokio::test]
    async fn ecdh_es_derives_the_key_of_rfc7518_appendix_c() {
        let (alice, bob) = (jwk(ALICE), jwk(BOB));
        let alice_key = EcdhKey::from_jwk(&alice).unwrap();
        let bob_key = EcdhKey::from_jwk(&bob).unwrap();
        assert_eq!(*bob_key.shared_secret(&alice.public()).await.unwrap(), Z);
        assert_eq!(*alice_key.shared_secret(&bob.public()).await.unwrap(), Z);

        let key = concat_kdf(&Z, "A128GCM", 16, b"Alice", b"Bob").unwrap();
        assert_eq!(*key, decode("VqqN6vgjbSBcIijNcacQGg"));
        assert_eq!(
            *key,
            [
                86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
            ]
        );
    }

    /// RFC 7520 §5.6: direct encryption with A128GCM.
    #[test]
    fn a128gcm_of_rfc7520_section_5_6() {
        let plaintext = "You can trust us to stick with you through thick and thin\u{2013}to the \
            bitter end. And you can trust us to keep any secret of yours\u{2013}closer than you \
            keep it yourself. But you cannot trust us to let you face trouble alone, and go off \
            without a word. We are your friends, Frodo.";
        let cek = decode("XctOhJAkA-pD9Lh7ZgW_2A");
        let iv: [u8; IV_LEN] = decode("refa467QzzKx6QAB").try_into().unwrap();
        let aad = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2Ei\
                   LCJlbmMiOiJBMTI4R0NNIn0";
        let ciphertext = decode(
            "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcX\
             kZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-\
             Nceb4h3-FtBP-c_BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPb\
             jk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios\
             61EKgyIQ4CWao8PFMj8TTnp",
        );
        let tag: [u8; TAG_LEN] = decode("vbb32Xvllea2OtmHAdccRQ").try_into().unwrap();

        let sealed = seal(
            JweEncryption::A128Gcm,
            &cek,
            &iv,
            aad.as_bytes(),
            plaintext.as_bytes(),
        );
        assert_eq!(sealed.unwrap(), (ciphertext.clone(), tag));
        let opened = open(
            JweEncryption::A128Gcm,
            &cek,
            &iv,
            aad.as_bytes(),
            &ciphertext,
            &tag,
        );
        assert_eq!(opened.unwrap(), plaintext.as_bytes());
    }

    /// RFC 7516 Appendix A.1: content encryption with A256GCM.
    #[test]
    fn a256gcm_of_rfc7516_appendix_a1() {
        let plaintext = b"The true sign of intelligence is not knowledge but imagination.";
        // The CEK, which the appendix gives as octets, base64url-encoded.
        let cek = decode("saH0gFSP4XM_tAP_a5rU9ooHbltwLiJpL4LLLnrqQPw");
        let iv: [u8; IV_LEN] = decode("48V1_ALb6US04U3b").try_into().unwrap();
        let aad = b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        let ciphertext = decode(
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A",
        );
        let tag: [u8; TAG_LEN] = decode("XFBoMYUZodetZdvTiFvSkQ").try_into().unwrap();

        let sealed = seal(JweEncryption::A256Gcm, &cek, &iv, aad, plaintext);
        assert_eq!(sealed.unwrap(), (ciphertext.clone(), tag));
        let opened = open(JweEncryption::A256Gcm, &cek, &iv, aad, &ciphertext, &tag);
        assert_eq!(opened.unwrap(), plaintext);

        let mut altered = tag;
        altered[0] ^= 1;
        assert!(matches!(
            open(
                JweEncryption::A256Gcm,
                &cek,
                &iv,
                aad,
                &ciphertext,
                &altered
            ),
            Err(JweError::DecryptionFailed)
        ));
    }

    /// Encryption with RFC 7518 Appendix C's keys and parameters puts Alice's public key in
    /// `epk` and encrypts with the key of the appendix, which Bob derives again.
    #[tokio::test]
    async fn encryption_uses_the_ephemeral_key_and_party_info() {
        let (alice, bob) = (jwk(ALICE), jwk(BOB));
        let ephemeral =
            p256::SecretKey::from_slice(&decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"))
                .unwrap();
        let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A128Gcm)
            .with_apu(b"Alice")
            .with_apv(b"Bob");
        // RFC 7520 §5.6's IV.
        let iv: [u8; IV_LEN] = decode("refa467QzzKx6QAB").try_into().unwrap();
        let jwe = CompactJwe::encrypt_with(
            header,
            b"plaintext",
            &bob.public().with_alg("ECDH-ES"),
            &ephemeral,
            iv,
        )
        .unwrap();

        assert_eq!(jwe.header().epk.as_ref(), Some(&alice.public()));
        assert_eq!(jwe.header().apu.as_deref(), Some("QWxpY2U"));
        assert_eq!(jwe.header().apv.as_deref(), Some("Qm9i"));
        let cek = decode("VqqN6vgjbSBcIijNcacQGg");
        let aad = &jwe.as_str().as_bytes()[..jwe.header_end];
        assert_eq!(
            open(
                JweEncryption::A128Gcm,
                &cek,
                &iv,
                aad,
                &jwe.ciphertext,
                &jwe.tag
            )
            .unwrap(),
            b"plaintext"
        );

        let decoded = CompactJwe::decode(jwe.as_str()).unwrap();
        let bob_key = EcdhKey::from_jwk(&bob).unwrap();
        assert_eq!(decoded.decrypt(&bob_key).await.unwrap(), b"plaintext");
    }

    /// AES-GCM's plaintext limit, 2^36 − 32 bytes, checked without a plaintext that long.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn plaintext_limit_is_that_of_aes_gcm() {
        let limit = usize::try_from(aes_gcm::P_MAX).unwrap();
        assert_eq!(limit, (1 << 36) - 32);
        assert!(fits_aes_gcm(0));
        assert!(fits_aes_gcm(limit));
        assert!(!fits_aes_gcm(limit + 1));
    }

    /// Every byte of an IV comes from its own random draw: across many IVs, each position
    /// takes more than one value and no two positions always agree.
    #[test]
    fn ivs_are_random_in_every_byte() {
        let ivs: Vec<[u8; IV_LEN]> = (0..64).map(|_| random_iv().unwrap()).collect();
        for position in 0..IV_LEN {
            assert!(
                ivs.iter().any(|iv| iv[position] != ivs[0][position]),
                "{position}"
            );
            for other in position + 1..IV_LEN {
                assert!(
                    ivs.iter().any(|iv| iv[position] != iv[other]),
                    "{position} and {other}"
                );
            }
        }
    }

    /// RFC 7520 §5.5: the static key of Figure 120 and the ephemeral key of Figure 122 agree
    /// on the 256-bit CEK of Figure 123, with no `apu` or `apv`. The `enc` there is
    /// `A128CBC-HS256`, which only names the `AlgorithmID` here.
    #[tokio::test]
    async fn ecdh_es_derives_the_256_bit_key_of_rfc7520_section_5_5() {
        let recipient = jwk(r#"{"kty":"EC","kid":"meriadoc.brandybuck@buckland.example",
            "use":"enc","crv":"P-256",
            "x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
            "y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            "d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"}"#);
        let ephemeral = jwk(r#"{"kty":"EC","crv":"P-256",
            "x":"mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
            "y":"8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs",
            "d":"AtH35vJsQ9SGjYfOsjUxYXQKrPH3FjZHmEtSKoSN8cM"}"#);
        let z = EcdhKey::from_jwk(&recipient)
            .unwrap()
            .shared_secret(&ephemeral.public())
            .await
            .unwrap();
        let key = concat_kdf(&z, "A128CBC-HS256", 32, b"", b"").unwrap();
        assert_eq!(*key, decode("hzHdlfQIAEehb8Hrd_mFRhKsKLEzPfshfXs9l6areCc"));
    }
}
