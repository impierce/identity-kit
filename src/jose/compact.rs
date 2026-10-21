//! Compact JWS serialization (RFC 7515 §7.1): decoding without verification, and encoding with
//! a [`Signer`].

use core::fmt;

use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Jwk, JwsAlgorithm, JwsError, JwsVerifier, SignError, VerificationError, base64url};

/// The JOSE header of a JWS (RFC 7515 §4).
///
/// The registered parameters this crate acts on are fields; everything else, `x5c` and `b64`
/// included, lives in `additional` in insertion order. `jwk` is the public key the signer claims
/// to have used; trusting it is the verifier's decision, never the crate's.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{JwsAlgorithm, JwsHeader};
///
/// let mut header = JwsHeader::new(JwsAlgorithm::ES256).with_kid("did:example:123#key-1");
/// header.typ = Some("JWT".to_owned());
/// assert_eq!(
///     serde_json::to_string(&header)?,
///     r#"{"alg":"ES256","typ":"JWT","kid":"did:example:123#key-1"}"#
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwsHeader {
    /// The signature algorithm (`alg`).
    pub alg: JwsAlgorithm,
    /// The media type of the whole JWS (`typ`), such as `JWT` or `vc+jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The media type of the payload (`cty`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// The key id (`kid`); for a DID controller, usually a DID URL with a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// The public key the signature was made with (`jwk`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Extensions a recipient must understand (`crit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Every other header parameter, in insertion order.
    #[serde(flatten)]
    pub additional: IndexMap<String, Value>,
}

impl JwsHeader {
    /// A header with only `alg` set.
    pub fn new(alg: JwsAlgorithm) -> Self {
        Self {
            alg,
            typ: None,
            cty: None,
            kid: None,
            jwk: None,
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
}

/// A decoded compact JWS: `BASE64URL(header) || '.' || BASE64URL(payload) || '.' ||
/// BASE64URL(signature)`.
///
/// Decoding parses the header and the parts and nothing more: [`CompactJws::verify`] (or any
/// [`JwsVerifier`]) checks the signature once the caller has resolved the key, which usually
/// means dereferencing [`kid`](Self::kid) through a DID resolver.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{CompactJws, JwsAlgorithm};
///
/// // RFC 8037 Appendix A.4.
/// let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
///              hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
/// let jws = CompactJws::decode(token)?;
/// assert_eq!(jws.alg(), JwsAlgorithm::EdDSA);
/// assert_eq!(jws.kid(), None);
/// assert_eq!(jws.payload(), b"Example of Ed25519 signing");
/// assert_eq!(
///     jws.signing_input(),
///     b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
/// );
/// assert_eq!(jws.signature().len(), 64);
/// # Ok::<(), identity_kit::jose::JwsError>(())
/// ```
#[derive(Debug, Clone)]
pub struct CompactJws {
    token: String,
    /// Byte offset of the `.` between payload and signature; the signing input ends there.
    signing_input_end: usize,
    header: JwsHeader,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CompactJws {
    /// Parses a compact JWS without verifying it.
    ///
    /// # Errors
    ///
    /// A [`JwsError`] when the input is not three base64url parts, the header is not a JSON
    /// object with a supported `alg`, or the header has `crit` or `b64: false`.
    pub fn decode(token: &str) -> Result<Self, JwsError> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(JwsError::InvalidFormat {
                parts: token.split('.').count(),
            });
        };
        let header_json = base64url::decode(header_b64)
            .map_err(|_| JwsError::InvalidBase64Url { part: "header" })?;
        let header = parse_header(&header_json)?;
        let payload = base64url::decode(payload_b64)
            .map_err(|_| JwsError::InvalidBase64Url { part: "payload" })?;
        let signature = base64url::decode(signature_b64)
            .map_err(|_| JwsError::InvalidBase64Url { part: "signature" })?;
        Ok(Self {
            token: token.to_owned(),
            signing_input_end: header_b64.len() + 1 + payload_b64.len(),
            header,
            payload,
            signature,
        })
    }

    /// The protected header.
    pub fn header(&self) -> &JwsHeader {
        &self.header
    }

    /// The header `alg`.
    pub fn alg(&self) -> JwsAlgorithm {
        self.header.alg
    }

    /// The header `kid`, if any.
    pub fn kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }

    /// The JWS signing input: `BASE64URL(header) || '.' || BASE64URL(payload)` as ASCII.
    pub fn signing_input(&self) -> &[u8] {
        &self.token.as_bytes()[..self.signing_input_end]
    }

    /// The decoded payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The decoded signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The payload read as JSON into `T`, a [`JwtClaims`](super::JwtClaims) set say, unverified:
    /// nothing about the signature or the claims is checked.
    ///
    /// # Errors
    ///
    /// [`JwsError::InvalidPayload`] when the payload is not JSON of the shape `T` expects.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::jose::{CompactJws, JwtClaims};
    ///
    /// // RFC 7515 Appendix A.3: the RFC 7519 §3.1 claims set, signed with ES256.
    /// let jws = CompactJws::decode(
    ///     "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGF\
    ///      tcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDx\
    ///      w5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
    /// )?;
    /// let claims: JwtClaims = jws.claims()?;
    /// assert_eq!(claims.iss.as_deref(), Some("joe"));
    /// assert_eq!(claims.exp, Some(1300819380));
    /// assert_eq!(claims.additional["http://example.com/is_root"], true);
    /// # Ok::<(), identity_kit::jose::JwsError>(())
    /// ```
    pub fn claims<T: DeserializeOwned>(&self) -> Result<T, JwsError> {
        serde_json::from_slice(&self.payload).map_err(|e| JwsError::InvalidPayload(e.to_string()))
    }

    /// The compact serialization as it was decoded.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Verifies the signature with `verifier` under `key` and the header `alg`.
    ///
    /// # Errors
    ///
    /// Whatever the verifier reports; see [`JwsVerifier::verify`].
    pub fn verify<V: JwsVerifier + ?Sized>(
        &self,
        verifier: &V,
        key: &Jwk,
    ) -> Result<(), VerificationError> {
        verifier.verify(self.alg(), self.signing_input(), &self.signature, key)
    }
}

impl fmt::Display for CompactJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.token)
    }
}

impl AsRef<str> for CompactJws {
    fn as_ref(&self) -> &str {
        &self.token
    }
}

/// Parses the header JSON, naming an unsupported `alg` and rejecting `crit` and `b64: false`.
fn parse_header(json: &[u8]) -> Result<JwsHeader, JwsError> {
    let value: Value =
        serde_json::from_slice(json).map_err(|e| JwsError::InvalidHeader(e.to_string()))?;
    let Some(object) = value.as_object() else {
        return Err(JwsError::InvalidHeader("not a JSON object".to_owned()));
    };
    match object.get("alg") {
        Some(Value::String(alg)) if alg.parse::<JwsAlgorithm>().is_ok() => {}
        Some(Value::String(alg)) => return Err(JwsError::UnsupportedAlgorithm(alg.clone())),
        Some(other) => return Err(JwsError::UnsupportedAlgorithm(other.to_string())),
        None => return Err(JwsError::InvalidHeader("missing `alg`".to_owned())),
    }
    if object
        .get("b64")
        .is_some_and(|b64| b64 != &Value::Bool(true))
    {
        return Err(JwsError::UnencodedPayload);
    }
    let header: JwsHeader =
        serde_json::from_value(value).map_err(|e| JwsError::InvalidHeader(e.to_string()))?;
    if let Some(crit) = &header.crit {
        return Err(JwsError::UnsupportedCritical(crit.clone()));
    }
    Ok(header)
}

/// Produces JWS signatures.
///
/// A signer binds one key and one algorithm. Private keys live behind it, in a key store, an HSM
/// or a cloud service, which is why signing is `async`. The signature is returned in the JWS form
/// of the algorithm: raw `r || s` for ECDSA, never DER.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// The algorithm every signature of this signer uses.
    fn alg(&self) -> JwsAlgorithm;

    /// The key id to put in a header, if the signer has one.
    fn kid(&self) -> Option<&str>;

    /// Signs `signing_input`.
    ///
    /// # Errors
    ///
    /// A [`SignError`] wrapping whatever the backend reports.
    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Encodes `payload` under `header` as a compact JWS signed by `signer`.
///
/// The header is serialized as given: `alg` must equal the signer's algorithm, and `kid` is
/// whatever the caller set (a DID URL, usually), not necessarily [`Signer::kid`].
///
/// # Errors
///
/// [`JwsError::AlgorithmMismatch`] when `header.alg` differs from the signer's algorithm, and
/// [`JwsError::Signer`] when signing fails.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{CompactJws, JwsAlgorithm, JwsHeader, SignError, Signer, encode_compact};
///
/// struct Rejecting;
///
/// #[async_trait::async_trait]
/// impl Signer for Rejecting {
///     fn alg(&self) -> JwsAlgorithm { JwsAlgorithm::ES256 }
///     fn kid(&self) -> Option<&str> { None }
///     async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
///         Err(SignError::msg("key store is offline"))
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// let header = JwsHeader::new(JwsAlgorithm::ES256);
/// let err = encode_compact(&header, b"{}", &Rejecting).await.unwrap_err();
/// assert_eq!(err.to_string(), "signing failed: key store is offline");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub async fn encode_compact(
    header: &JwsHeader,
    payload: &[u8],
    signer: &dyn Signer,
) -> Result<String, JwsError> {
    if header.alg != signer.alg() {
        return Err(JwsError::AlgorithmMismatch {
            header: header.alg,
            signer: signer.alg(),
        });
    }
    // Serializing a header cannot fail: every field is a string, a list, a `Jwk` or a `Value`.
    let header_json =
        serde_json::to_vec(header).map_err(|e| JwsError::InvalidHeader(e.to_string()))?;
    let mut token = base64url::encode(&header_json);
    token.push('.');
    token.push_str(&base64url::encode(payload));
    let signature = signer
        .sign(token.as_bytes())
        .await
        .map_err(JwsError::Signer)?;
    token.push('.');
    token.push_str(&base64url::encode(&signature));
    Ok(token)
}
