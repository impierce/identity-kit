//! `did:jwk`: a DID that is a base64url-encoded JSON Web Key.
//!
//! The [did:jwk method] is a deterministic transformation of a public JWK into a DID document:
//! the method-specific id is `base64url(JWK)`, the document has exactly one verification method,
//! `#0`, of type `JsonWebKey2020`, and the verification relationships follow the key's `use`
//! member (all five when it is absent, no `keyAgreement` for `sig`, only `keyAgreement` for
//! `enc`). The method cannot update or deactivate.
//!
//! [did:jwk method]: https://github.com/quartzjer/did-jwk/blob/main/spec.md

use crate::did::{
    Context, Did, DidDocument, DocumentError, MethodType, ResolutionError, ResolutionOptions,
    ResolutionResult, VerificationMaterial, VerificationMethod, VerificationRelationship,
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
/// let did = DidJwk::did(&jwk);
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

    /// The `@context` of every `did:jwk` document.
    pub const CONTEXT: [&'static str; 2] = [
        Context::DID_V1,
        "https://w3id.org/security/suites/jws-2020/v1",
    ];

    /// The `did:jwk` of the public part of `jwk`, serialized as compact JSON in this crate's
    /// member order. Any other serialization of the same key is another, equally valid, DID.
    pub fn did(jwk: &Jwk) -> Did {
        let json = serde_json::to_vec(&jwk.public()).expect("a JWK serializes");
        let id = crate::jose::base64url::encode(&json);
        Did::parse(&format!("did:jwk:{id}")).expect("base64url is valid DID syntax")
    }

    /// The DID document `did` expands to (the method's Read operation).
    ///
    /// # Errors
    ///
    /// - [`ResolutionError::MethodNotSupported`] when `did` is not a `did:jwk`.
    /// - [`ResolutionError::InvalidDid`] when the method-specific id is not base64url of a
    ///   JSON Web Key, or the key carries private parameters.
    pub fn document(did: &Did) -> Result<DidDocument, ResolutionError> {
        if did.method() != Self::METHOD {
            return Err(ResolutionError::MethodNotSupported);
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

    /// The document of [`DidJwk::did`] for the one key in `keys`.
    async fn produce(&self, keys: &[Jwk], _: ()) -> Result<DidDocument, ProduceError> {
        let jwk = super::single_key(keys)?;
        Ok(build(&Self::did(jwk), jwk.public())?)
    }
}
