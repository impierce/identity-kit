//! `did:key`: a DID that is a public key.
//!
//! The [did:key method] (v0.9) expands `did:key:<multibase>` deterministically into a DID
//! document: the method-specific id is the Multikey form of the public key (base58btc multibase
//! of the multicodec header and the raw key, see [`Jwk::from_multikey`]), the document has one
//! verification method whose fragment is that same Multikey string, referenced from
//! `authentication`, `assertionMethod`, `capabilityInvocation` and `capabilityDelegation`, and
//! optionally an X25519 key agreement method derived from an Ed25519 key. The method cannot
//! update or deactivate.
//!
//! Supported key types are those of [`KeyCodec`](crate::jose::KeyCodec): Ed25519, X25519,
//! P-256, secp256k1 (feature `secp256k1`) and RSA. The version segment of
//! `did:key:1:<multibase>` is accepted and must be a positive integer.
//!
//! [did:key method]: https://w3c-ccg.github.io/did-key-spec/

use core::fmt;

use serde_json::Value;

use crate::did::{
    Context, Did, DidDocument, DocumentError, MethodType, ResolutionError, ResolutionOptions,
    ResolutionResult, VerificationMaterial, VerificationMethod, VerificationRelationship,
};
use crate::jose::{Jwk, JwkError};
use crate::resolver::{DidProducer, DidResolver, Hosting, MethodCapabilities, ProduceError};

use super::check_accept;

/// How a verification method of a `did:key` document carries the key (the `publicKeyFormat`
/// option of the method).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyFormat {
    /// Type `Multikey` with `publicKeyMultibase`: the Multikey string of the DID itself. The
    /// default, and what the specification's examples show.
    #[default]
    Multikey,
    /// Type `JsonWebKey` with `publicKeyJwk`.
    JsonWebKey,
}

impl KeyFormat {
    /// The verification method type name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Multikey => "Multikey",
            Self::JsonWebKey => "JsonWebKey",
        }
    }

    const fn method_type(self) -> MethodType {
        match self {
            Self::Multikey => MethodType::MULTIKEY,
            Self::JsonWebKey => MethodType::JSON_WEB_KEY,
        }
    }
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `did:key` method: a [`DidResolver`] that expands the DID and a [`DidProducer`] that
/// encodes one public key.
///
/// The resolver's options are those the specification defines: the [`KeyFormat`]
/// (`publicKeyFormat`) and whether to derive an X25519 key agreement method from an Ed25519
/// key (`enableEncryptionKeyDerivation`). Both are set here as defaults and may be overridden
/// per resolution through [`ResolutionOptions::properties`] under those names, with a string
/// and a boolean respectively.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Did;
/// use identity_kit::jose::Jwk;
/// use identity_kit::methods::DidKey;
/// use identity_kit::methods::key::KeyFormat;
///
/// let jwk: Jwk = serde_json::from_str(
///     r#"{"kty":"OKP","crv":"Ed25519","x":"Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"}"#,
/// )?;
/// let did = DidKey::did(&jwk)?;
/// assert_eq!(did.as_str(), "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
///
/// let document = DidKey::new().with_format(KeyFormat::JsonWebKey).document(&did)?;
/// let method = &document.verification_method[0];
/// assert_eq!(method.id.fragment(), Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"));
/// assert_eq!(method.public_key_jwk(), Some(&jwk));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DidKey {
    format: KeyFormat,
    key_agreement: bool,
}

impl DidKey {
    /// The method name, `key`.
    pub const METHOD: &'static str = "key";

    /// The `@context` of every `did:key` document.
    pub const CONTEXT: [&'static str; 1] = ["https://www.w3.org/ns/did/v1.1"];

    /// The method with [`KeyFormat::Multikey`] and no key agreement derivation.
    pub const fn new() -> Self {
        Self {
            format: KeyFormat::Multikey,
            key_agreement: false,
        }
    }

    /// This method expressing keys as `format`.
    #[must_use]
    pub const fn with_format(mut self, format: KeyFormat) -> Self {
        self.format = format;
        self
    }

    /// This method deriving an X25519 key agreement method from an Ed25519 key when
    /// `derive` is set (`enableEncryptionKeyDerivation`). The derived method is embedded under
    /// `keyAgreement`, as in the specification's examples.
    #[must_use]
    pub const fn with_key_agreement(mut self, derive: bool) -> Self {
        self.key_agreement = derive;
        self
    }

    /// The key format.
    pub const fn format(&self) -> KeyFormat {
        self.format
    }

    /// Whether an X25519 key agreement method is derived from an Ed25519 key.
    pub const fn key_agreement(&self) -> bool {
        self.key_agreement
    }

    /// The `did:key` of the public part of `jwk`.
    ///
    /// # Errors
    ///
    /// The errors of [`Jwk::to_multikey`]: an unsupported key type or undecodable material.
    pub fn did(jwk: &Jwk) -> Result<Did, JwkError> {
        let multikey = jwk.to_multikey()?;
        Ok(Did::parse(&format!("did:key:{multikey}")).expect("base58btc is valid DID syntax"))
    }

    /// The DID document `did` expands to with this method's options (the method's Read
    /// operation).
    ///
    /// # Errors
    ///
    /// - [`ResolutionError::MethodNotSupported`] when `did` is not a `did:key`.
    /// - [`ResolutionError::InvalidDid`] when the method-specific id is not a Multikey string
    ///   (optionally preceded by a positive integer version) with a known multicodec header.
    /// - [`ResolutionError::Other`] with the method's own error names otherwise:
    ///   `unsupportedPublicKeyType` for a key type this crate cannot read,
    ///   `invalidPublicKeyLength` when the raw key has the wrong length, and `invalidPublicKey`
    ///   when it is not a valid key.
    pub fn document(&self, did: &Did) -> Result<DidDocument, ResolutionError> {
        if did.method() != Self::METHOD {
            return Err(ResolutionError::MethodNotSupported);
        }
        let multikey = multikey_of(did).ok_or(ResolutionError::InvalidDid)?;
        let jwk = Jwk::from_multikey(multikey).map_err(|error| match error {
            JwkError::InvalidMultikey(_) => ResolutionError::InvalidDid,
            JwkError::UnsupportedMulticodec(_) | JwkError::FeatureDisabled { .. } => {
                ResolutionError::Other("unsupportedPublicKeyType".to_owned())
            }
            JwkError::InvalidKeyLength { .. } => {
                ResolutionError::Other("invalidPublicKeyLength".to_owned())
            }
            _ => ResolutionError::Other("invalidPublicKey".to_owned()),
        })?;
        self.build(did, multikey, jwk)
            .map_err(|_| ResolutionError::InvalidDidDocument)
    }

    /// The document for `did`, whose Multikey string is `multikey` and decodes to `jwk`.
    fn build(&self, did: &Did, multikey: &str, jwk: Jwk) -> Result<DidDocument, DocumentError> {
        let ed25519 = (self.key_agreement && jwk.crv() == Some("Ed25519"))
            .then(|| jwk.ed25519_verifying_key().ok())
            .flatten();
        let signature = self.verification_method(did, multikey, jwk);
        let mut builder = DidDocument::builder(did.clone())
            .context(Context::uris(Self::CONTEXT))
            .verification_method(
                signature,
                [
                    VerificationRelationship::Authentication,
                    VerificationRelationship::AssertionMethod,
                    VerificationRelationship::CapabilityInvocation,
                    VerificationRelationship::CapabilityDelegation,
                ],
            );
        if let Some(key) = ed25519 {
            // Derive Encryption Key Algorithm: the Montgomery form of the Edwards point.
            let x25519 = Jwk::from_x25519_public(key.to_montgomery().as_bytes())
                .expect("a Montgomery point is 32 bytes");
            let multikey = x25519.to_multikey().expect("an X25519 key has a codec");
            let method = self.verification_method(did, &multikey, x25519);
            builder = builder.embedded_method(VerificationRelationship::KeyAgreement, method);
        }
        builder.build()
    }

    /// The verification method `did#multikey` carrying `jwk` in this method's format.
    fn verification_method(&self, did: &Did, multikey: &str, jwk: Jwk) -> VerificationMethod {
        let material = match self.format {
            KeyFormat::Multikey => VerificationMaterial::multibase(multikey),
            KeyFormat::JsonWebKey => VerificationMaterial::PublicKeyJwk(Box::new(jwk)),
        };
        VerificationMethod::new(
            did.to_url().with_fragment(multikey),
            self.format.method_type(),
            did.clone(),
            material,
        )
    }

    /// This method with the `publicKeyFormat` and `enableEncryptionKeyDerivation` resolution
    /// options applied.
    fn with_options(self, options: &ResolutionOptions) -> Result<Self, ResolutionError> {
        let mut method = self;
        if let Some(format) = options.properties.get("publicKeyFormat") {
            method.format = match format.as_str() {
                Some("Multikey") => KeyFormat::Multikey,
                Some("JsonWebKey") => KeyFormat::JsonWebKey,
                _ => {
                    return Err(ResolutionError::Other(
                        "unsupportedPublicKeyType".to_owned(),
                    ));
                }
            };
        }
        if let Some(derive) = options.properties.get("enableEncryptionKeyDerivation") {
            method.key_agreement = match derive {
                Value::Bool(derive) => *derive,
                _ => return Err(ResolutionError::Other("invalidOptions".to_owned())),
            };
        }
        Ok(method)
    }
}

impl Default for DidKey {
    fn default() -> Self {
        Self::new()
    }
}

/// The Multikey string of a `did:key`, after the optional version segment, which must be a
/// positive integer.
fn multikey_of(did: &Did) -> Option<&str> {
    let id = did.method_specific_id();
    let multikey = match id.split_once(':') {
        None => id,
        Some((version, multikey)) => {
            if version.bytes().all(|b| b.is_ascii_digit()) && version.bytes().any(|b| b != b'0') {
                multikey
            } else {
                return None;
            }
        }
    };
    multikey.starts_with('z').then_some(multikey)
}

#[async_trait::async_trait]
impl DidResolver for DidKey {
    fn method(&self) -> &'static str {
        Self::METHOD
    }

    /// Expands `did` with [`DidKey::document`], with the `publicKeyFormat` and
    /// `enableEncryptionKeyDerivation` options of `options` overriding this method's defaults.
    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        check_accept(options)?;
        self.with_options(options)?
            .document(did)
            .map(ResolutionResult::new)
    }
}

#[async_trait::async_trait]
impl DidProducer for DidKey {
    type Params = ();

    fn method(&self) -> &'static str {
        Self::METHOD
    }

    /// Embedded, one key, never updated; the fragment is the Multikey string of the key.
    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(Hosting::Embedded).with_single_key(true)
    }

    /// The document of [`DidKey::did`] for the one key in `keys`, with this method's options.
    async fn produce(&self, keys: &[Jwk], _: ()) -> Result<DidDocument, ProduceError> {
        let jwk = super::single_key(keys)?;
        let multikey = jwk
            .to_multikey()
            .map_err(|error| ProduceError::UnsupportedKey {
                index: 0,
                reason: error.to_string(),
            })?;
        let did =
            Did::parse(&format!("did:key:{multikey}")).expect("base58btc is valid DID syntax");
        Ok(self.build(&did, &multikey, jwk.public())?)
    }
}
