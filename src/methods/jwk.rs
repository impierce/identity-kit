//! `did:jwk`: a DID that is a base64url-encoded JSON Web Key.
//!
//! The [did:jwk method] is a deterministic transformation of a public JWK into a DID document:
//! the method-specific id is `base64url(JWK)`, the document has exactly one verification method,
//! `#0`, of type `JsonWebKey2020`, and the verification relationships follow the key's `use`
//! member (all five when it is absent, no `keyAgreement` for `sig`, only `keyAgreement` for
//! `enc`). The method cannot update or deactivate.
//!
//! # Canonical form
//!
//! The method does not fix how the JWK is serialized, so one key has many valid `did:jwk`s. The
//! specification names the JSON Canonicalization Scheme ([RFC 8785]) as helpful when the DID is
//! not stored in its serialized form, and [`DidJwk::did`] uses it: members sorted, no
//! whitespace. The result is the DID every other JCS implementation derives for the same key,
//! including the specification's P-256 example. Resolution accepts any serialization, so a DID
//! created another way still resolves; it is just not the one [`DidJwk::did`] produces. An
//! application holding DIDs created another way, such as this crate's before 0.2, should keep
//! those strings rather than derive them again.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
//!
//! [did:jwk method]: https://github.com/quartzjer/did-jwk/blob/main/spec.md

use crate::did::{
    Context, DEFAULT_MAX_LEN, Did, DidDocument, DidError, DocumentError, MethodType,
    ResolutionError, ResolutionOptions, ResolutionResult, VerificationMaterial, VerificationMethod,
    VerificationRelationship,
};
use crate::jose::Jwk;
use crate::resolver::{DidProducer, DidResolver, Hosting, MethodCapabilities, ProduceError};

use super::check_accept;

/// The `did:jwk` method: a [`DidResolver`] that expands the DID and a [`DidProducer`] that
/// encodes one public key.
///
/// # Examples
///
/// ```
/// use identity_kit::did::{Did, VerificationRelationship};
/// use identity_kit::jose::Jwk;
/// use identity_kit::methods::DidJwk;
///
/// let jwk: Jwk = serde_json::from_str(
///     r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
/// )?;
/// let did = DidJwk::did(&jwk)?;
/// assert!(did.as_str().starts_with("did:jwk:eyJ"));
///
/// let document = DidJwk::document(&did)?;
/// let key = did.join("#0")?;
/// let method = document.resolve_verification_method(&key, Some(VerificationRelationship::Authentication))?;
/// assert_eq!(method.public_key_jwk(), Some(&jwk));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DidJwk;

impl DidJwk {
    /// The method name, `jwk`.
    pub const METHOD: &'static str = "jwk";

    /// The fragment of the one verification method, `0`.
    pub const FRAGMENT: &'static str = "0";

    /// The longest `did:jwk` whose document this method can represent: the verification
    /// method id `did#0` must fit [`DEFAULT_MAX_LEN`] bytes.
    pub const MAX_DID_LEN: usize = DEFAULT_MAX_LEN - 1 - Self::FRAGMENT.len();

    /// The `@context` of every `did:jwk` document.
    pub const CONTEXT: [&'static str; 2] = [
        Context::DID_V1,
        "https://w3id.org/security/suites/jws-2020/v1",
    ];

    /// The `did:jwk` of the public part of `jwk`: `base64url` of its JSON Canonicalization
    /// Scheme form ([RFC 8785]), so members are sorted, and extension members too, recursively.
    /// Private parameters never reach the DID.
    ///
    /// Any other serialization of the same key is another valid DID, which
    /// [`document`](Self::document) resolves but this function never produces; see the
    /// [module documentation](self#canonical-form).
    ///
    /// # Errors
    ///
    /// [`DidError::TooLong`] when the encoded key exceeds [`MAX_DID_LEN`](Self::MAX_DID_LEN)
    /// bytes, as a JWK carrying an `x5c` chain or large extension members may; base64url is
    /// otherwise valid DID syntax.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::jose::Jwk;
    /// use identity_kit::methods::DidJwk;
    ///
    /// // The key of the did:jwk specification's P-256 example, members in any order: its DID
    /// // is the specification's, which is in JCS order.
    /// let jwk: Jwk = serde_json::from_str(
    ///     r#"{
    ///       "kty": "EC",
    ///       "crv": "P-256",
    ///       "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
    ///       "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
    ///     }"#,
    /// )?;
    /// assert_eq!(
    ///     DidJwk::did(&jwk)?.as_str(),
    ///     "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
    pub fn did(jwk: &Jwk) -> Result<Did, DidError> {
        let value = serde_json::to_value(jwk.public()).expect("a JWK serializes");
        let id = crate::jose::base64url::encode(super::jcs::to_string(&value).as_bytes());
        Did::parse_with_max_len(&format!("did:jwk:{id}"), Self::MAX_DID_LEN)
    }

    /// The DID document `did` expands to (the method's Read operation).
    ///
    /// # Errors
    ///
    /// - [`ResolutionError::MethodNotSupported`] when `did` is not a `did:jwk`.
    /// - [`ResolutionError::InvalidDid`] when the method-specific id is not base64url of a
    ///   JSON Web Key, the key carries private parameters, or the DID is longer than
    ///   [`MAX_DID_LEN`](Self::MAX_DID_LEN).
    pub fn document(did: &Did) -> Result<DidDocument, ResolutionError> {
        if did.method() != Self::METHOD {
            return Err(ResolutionError::MethodNotSupported);
        }
        if did.as_str().len() > Self::MAX_DID_LEN {
            return Err(ResolutionError::InvalidDid);
        }
        let json = crate::jose::base64url::decode(did.method_specific_id())
            .map_err(|_| ResolutionError::InvalidDid)?;
        let jwk: Jwk = serde_json::from_slice(&json).map_err(|_| ResolutionError::InvalidDid)?;
        if jwk.is_private() {
            return Err(ResolutionError::InvalidDid);
        }
        build(did, jwk).map_err(|_| ResolutionError::InvalidDid)
    }
}

/// The document of `did` for `jwk`, whose relationships follow `use`.
fn build(did: &Did, jwk: Jwk) -> Result<DidDocument, DocumentError> {
    let relationships: &[VerificationRelationship] = match jwk.key_use() {
        Some("sig") => &[
            VerificationRelationship::Authentication,
            VerificationRelationship::AssertionMethod,
            VerificationRelationship::CapabilityInvocation,
            VerificationRelationship::CapabilityDelegation,
        ],
        Some("enc") => &[VerificationRelationship::KeyAgreement],
        _ => VerificationRelationship::ALL,
    };
    let method = VerificationMethod::new(
        did.to_url().with_fragment(DidJwk::FRAGMENT),
        MethodType::JSON_WEB_KEY_2020,
        did.clone(),
        VerificationMaterial::PublicKeyJwk(Box::new(jwk)),
    );
    DidDocument::builder(did.clone())
        .context(Context::uris(DidJwk::CONTEXT))
        .verification_method(method, relationships.iter().copied())
        .build()
}

#[async_trait::async_trait]
impl DidResolver for DidJwk {
    fn method(&self) -> &'static str {
        Self::METHOD
    }

    /// Expands `did` with [`DidJwk::document`]; `options` may only ask for a JSON
    /// representation.
    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        check_accept(options)?;
        Self::document(did).map(ResolutionResult::new)
    }
}

#[async_trait::async_trait]
impl DidProducer for DidJwk {
    type Params = ();

    fn method(&self) -> &'static str {
        Self::METHOD
    }

    /// Embedded, one key, never updated, verification method `#0`.
    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(Hosting::Embedded)
            .with_single_key(true)
            .with_fixed_fragment(Self::FRAGMENT)
    }

    /// The document [`DidJwk::did`] of the one key in `keys` resolves to, which holds the key in
    /// its canonical form.
    async fn produce(&self, keys: &[Jwk], _: ()) -> Result<DidDocument, ProduceError> {
        let jwk = super::single_key(keys)?;
        let unsupported = |reason: String| ProduceError::UnsupportedKey { index: 0, reason };
        let did = Self::did(jwk).map_err(|error| unsupported(error.to_string()))?;
        // The document of the key as the DID encodes it, so that it is the document the DID
        // resolves to: JCS writes `1.0` as `1`, which reads back as an integer.
        Self::document(&did).map_err(|error| unsupported(error.to_string()))
    }
}
