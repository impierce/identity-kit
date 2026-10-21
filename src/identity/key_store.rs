//! `KeyStoreIdentity`: an [`Identity`] over any `KeyStore` and the `DidProducer`s registered with
//! it.

use core::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use super::{Identifier, Identity, IdentityError, IdentityKind};
use crate::did::{DidMethod, DidUrl};
use crate::jose::{Jwk, JwsAlgorithm, KeyType, SignError, Signer};
use crate::keys::{KeyId, KeySigner, KeySpec, KeyStore, KeyStoreError};
use crate::resolver::DidProducer;

/// An [`Identity`] over the keys of a [`KeyStore`], vendor-agnostic: a KMS or HSM backend that
/// implements [`KeyStore`] works without glue.
///
/// A key of the store is bound to a `(kind, alg)` pair with [`bind`](Self::bind), which derives
/// the identifier: the thumbprint of the key for [`IdentityKind::JwkThumbprint`], and for
/// [`IdentityKind::Did`] the DID of the document that the producer registered for the method
/// (see [`with_producer`](Self::with_producer)) makes for the key, with its first verification
/// method as the `kid`. A DID that no registered producer can make, such as a `did:web` whose
/// producer needs an origin, is bound with [`bind_did_url`](Self::bind_did_url).
///
/// # Key generation is opt-in
///
/// By default an unbound pair is an error, so that a production deployment never mints keys
/// silently. With [`generate_missing(true)`](Self::generate_missing) the identity asks the store
/// for a new key the first time an unbound pair is used, binds it, and reuses it from then on.
/// Bindings live in memory only: an application that generates keys this way stores
/// [`bindings`](Self::bindings) and binds them again on the next start.
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "in-memory", feature = "did-key", feature = "did-jwk"))]
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use std::sync::Arc;
///
/// use identity_kit::did::DidMethod;
/// use identity_kit::identity::{Identity, IdentityKind, KeyStoreIdentity};
/// use identity_kit::jose::JwsAlgorithm;
/// use identity_kit::keys::InMemoryKeyStore;
/// use identity_kit::methods::{DidJwk, DidKey};
///
/// let identity = KeyStoreIdentity::new(Arc::new(InMemoryKeyStore::new()))
///     .with_producer(DidKey::default())
///     .with_producer(DidJwk)
///     .generate_missing(true);
///
/// let kind = IdentityKind::Did(DidMethod::new("jwk")?);
/// let did = identity.identifier(&kind, JwsAlgorithm::ES256).await?;
/// assert!(did.to_string().starts_with("did:jwk:"));
/// // The key was generated once and is reused.
/// assert_eq!(identity.identifier(&kind, JwsAlgorithm::ES256).await?, did);
/// assert_eq!(identity.bindings().len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct KeyStoreIdentity {
    store: Arc<dyn KeyStore>,
    producers: Vec<Arc<dyn DidProducer<Params = ()>>>,
    generate_missing: bool,
    bindings: RwLock<Vec<Binding>>,
}

/// A key bound to a `(kind, alg)` pair, with what was derived from it.
#[derive(Clone)]
struct Binding {
    kind: IdentityKind,
    signer: KeySigner<Arc<dyn KeyStore>>,
    identifier: Identifier,
    kid: Option<String>,
}

impl KeyStoreIdentity {
    /// An identity over `store`, with no producer, no binding and key generation off.
    pub fn new(store: Arc<dyn KeyStore>) -> Self {
        Self {
            store,
            producers: Vec::new(),
            generate_missing: false,
            bindings: RwLock::new(Vec::new()),
        }
    }

    /// This identity with `producer` making the DIDs of its method, replacing a producer
    /// registered for the same method before.
    ///
    /// Only producers that need no parameters (`Params = ()`) are registered: those whose DID
    /// follows from the key, such as `did:key` and `did:jwk`. A DID made with parameters, such as
    /// a `did:web` from its origin, is bound with [`bind_did_url`](Self::bind_did_url).
    #[must_use]
    pub fn with_producer(mut self, producer: impl DidProducer<Params = ()> + 'static) -> Self {
        self.producers
            .retain(|registered| registered.method() != producer.method());
        self.producers.push(Arc::new(producer));
        self
    }

    /// This identity generating a key the first time an unbound pair is used, when `enabled`
    /// and the store can generate keys for the algorithm. Off by default; see the
    /// [type documentation](Self#key-generation-is-opt-in).
    #[must_use]
    pub fn generate_missing(mut self, enabled: bool) -> Self {
        self.generate_missing = enabled;
        self
    }

    /// Binds `key` of the store to `(kind, alg)`, replacing a key bound to the pair before, and
    /// returns the identifier derived from it.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::UnsupportedAlgorithm`] when the store does not sign with `alg`;
    /// - [`IdentityError::KeyStore`] when the key does not exist or is not a key for `alg`;
    /// - [`IdentityError::UnsupportedKind`] when no registered producer makes DIDs of the
    ///   method, or the DID it made is not in the namespace of `kind`;
    /// - [`IdentityError::Produce`] when the producer refuses the key;
    /// - [`IdentityError::NoVerificationMethod`] when its document has no verification method.
    pub async fn bind(
        &self,
        kind: IdentityKind,
        alg: JwsAlgorithm,
        key: KeyId,
    ) -> Result<Identifier, IdentityError> {
        let binding = self.derive(kind, alg, key).await?;
        let identifier = binding.identifier.clone();
        self.insert(binding, true);
        Ok(identifier)
    }

    /// Binds `key` of the store to `(kind, alg)` as the verification method `url`, replacing a
    /// key bound to the pair before, and returns the DID of `url`.
    ///
    /// This is how a DID that no registered producer makes is used: a `did:web`, or a DID of a
    /// registry method that the application created. The caller vouches that the published
    /// document of the DID has `url` as a verification method with the public key of `key`;
    /// the identity cannot tell without resolving it.
    ///
    /// # Errors
    ///
    /// [`IdentityError::UnsupportedKind`] when `kind` is not a DID kind that the DID of `url`
    /// matches, and as [`bind`](Self::bind) for the key.
    pub async fn bind_did_url(
        &self,
        kind: IdentityKind,
        alg: JwsAlgorithm,
        key: KeyId,
        url: DidUrl,
    ) -> Result<Identifier, IdentityError> {
        match &kind {
            IdentityKind::Did(method) if method.matches(url.did()) => {}
            _ => return Err(IdentityError::UnsupportedKind(kind)),
        }
        let signer = self.signer_for(alg, key).await?;
        let identifier = Identifier::Did(url.did().clone());
        self.insert(
            Binding {
                kind,
                signer,
                identifier: identifier.clone(),
                kid: Some(url.to_string()),
            },
            true,
        );
        Ok(identifier)
    }

    /// The bound pairs and their keys, in the order they were bound, for an application to
    /// store and bind again on the next start.
    pub fn bindings(&self) -> Vec<(IdentityKind, JwsAlgorithm, KeyId)> {
        self.read()
            .iter()
            .map(|binding| {
                (
                    binding.kind.clone(),
                    binding.signer.alg(),
                    binding.signer.key_id().clone(),
                )
            })
            .collect()
    }

    /// A signer over `key` for `alg`, which checks that the store signs with `alg` and that
    /// `key` exists and is a key for it.
    async fn signer_for(
        &self,
        alg: JwsAlgorithm,
        key: KeyId,
    ) -> Result<KeySigner<Arc<dyn KeyStore>>, IdentityError> {
        KeySigner::new(Arc::clone(&self.store), key, alg)
            .await
            .map_err(|error| match error {
                KeyStoreError::UnsupportedAlgorithm(alg) => {
                    IdentityError::UnsupportedAlgorithm(alg)
                }
                error => IdentityError::KeyStore(error),
            })
    }

    /// The binding of `key` to `(kind, alg)`, with its identifier and `kid`.
    async fn derive(
        &self,
        kind: IdentityKind,
        alg: JwsAlgorithm,
        key: KeyId,
    ) -> Result<Binding, IdentityError> {
        let producer = match &kind {
            IdentityKind::Did(method) => Some(
                self.producer(method)
                    .ok_or_else(|| IdentityError::UnsupportedKind(kind.clone()))?,
            ),
            IdentityKind::JwkThumbprint => None,
        };
        let signer = self.signer_for(alg, key).await?;
        let public = signer.public_jwk().public();
        let (identifier, kid) = match (&kind, producer) {
            (IdentityKind::Did(method), Some(producer)) => {
                let document = producer.produce(&[public], ()).await?;
                if !method.matches(&document.id) {
                    return Err(IdentityError::UnsupportedKind(kind));
                }
                let kid = document
                    .methods(None)
                    .next()
                    .map(|method| method.id.to_string())
                    .ok_or_else(|| IdentityError::NoVerificationMethod(document.id.clone()))?;
                (Identifier::Did(document.id), Some(kid))
            }
            _ => (Identifier::JwkThumbprint(public.thumbprint_sha256()?), None),
        };
        Ok(Binding {
            kind,
            signer,
            identifier,
            kid,
        })
    }

    /// The registered producer for the method of `method`.
    fn producer(&self, method: &DidMethod) -> Option<&Arc<dyn DidProducer<Params = ()>>> {
        self.producers
            .iter()
            .find(|producer| producer.method() == method.name())
    }

    /// The binding of `(kind, alg)`, generating a key for it when that is enabled.
    async fn binding(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Binding, IdentityError> {
        if let Some(binding) = self.find(kind, alg) {
            return Ok(binding);
        }
        if !self.generate_missing {
            return Err(if self.read().iter().any(|binding| binding.kind == *kind) {
                IdentityError::UnsupportedAlgorithm(alg)
            } else {
                IdentityError::UnsupportedKind(kind.clone())
            });
        }
        if let IdentityKind::Did(method) = kind
            && self.producer(method).is_none()
        {
            return Err(IdentityError::UnsupportedKind(kind.clone()));
        }
        let capabilities = self.store.capabilities();
        let Some(key_type) = key_type_for(alg).filter(|_| capabilities.supports(alg)) else {
            return Err(IdentityError::UnsupportedAlgorithm(alg));
        };
        if !capabilities.can_generate {
            return Err(KeyStoreError::Unsupported("generate").into());
        }
        let key = self.store.generate(KeySpec::new(key_type, alg)).await?;
        let binding = match self.derive(kind.clone(), alg, key.clone()).await {
            Ok(binding) => binding,
            Err(error) => {
                self.discard(&key).await;
                return Err(error);
            }
        };
        let kept = self.insert(binding, false);
        // Another call generated a key for the pair at the same time and won.
        if kept.signer.key_id() != &key {
            self.discard(&key).await;
        }
        Ok(kept)
    }

    /// Deletes a key this identity generated and does not use, when the store can.
    async fn discard(&self, key: &KeyId) {
        if self.store.capabilities().can_delete {
            // Best effort: the key is unused either way.
            let _ = self.store.delete(key).await;
        }
    }

    fn find(&self, kind: &IdentityKind, alg: JwsAlgorithm) -> Option<Binding> {
        self.read()
            .iter()
            .find(|binding| binding.kind == *kind && binding.signer.alg() == alg)
            .cloned()
    }

    /// Stores `binding`. A binding of the same pair is replaced when `replace`, and kept
    /// otherwise; returns the binding the pair has afterwards.
    fn insert(&self, binding: Binding, replace: bool) -> Binding {
        let mut bindings = self
            .bindings
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let existing = bindings
            .iter_mut()
            .find(|bound| bound.kind == binding.kind && bound.signer.alg() == binding.signer.alg());
        match existing {
            Some(bound) if replace => {
                *bound = binding.clone();
                binding
            }
            Some(bound) => bound.clone(),
            None => {
                bindings.push(binding.clone());
                binding
            }
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Binding>> {
        self.bindings.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The key type generated for `alg`: `None` for ES384, which no [`KeyType`] of this crate is,
/// and the 2048-bit key for the RSA algorithms.
fn key_type_for(alg: JwsAlgorithm) -> Option<KeyType> {
    match alg {
        JwsAlgorithm::EdDSA => Some(KeyType::Ed25519),
        JwsAlgorithm::ES256 => Some(KeyType::P256),
        JwsAlgorithm::ES256K => Some(KeyType::Secp256k1),
        JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => Some(KeyType::Rsa2048),
        JwsAlgorithm::ES384 => None,
    }
}

impl fmt::Debug for KeyStoreIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let producers: Vec<&str> = self
            .producers
            .iter()
            .map(|producer| producer.method())
            .collect();
        f.debug_struct("KeyStoreIdentity")
            .field("producers", &producers)
            .field("generate_missing", &self.generate_missing)
            .field("bindings", &self.bindings())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Identity for KeyStoreIdentity {
    /// The bound pairs, then, when key generation is on and the store can generate, every pair
    /// of a registered producer's method or the thumbprint with an algorithm the store
    /// generates keys for. A generated pair can still fail when the producer refuses the key
    /// type.
    fn capabilities(&self) -> Vec<(IdentityKind, JwsAlgorithm)> {
        let mut pairs: Vec<(IdentityKind, JwsAlgorithm)> = self
            .read()
            .iter()
            .map(|binding| (binding.kind.clone(), binding.signer.alg()))
            .collect();
        let capabilities = self.store.capabilities();
        if self.generate_missing && capabilities.can_generate {
            let kinds = self
                .producers
                .iter()
                .filter_map(|producer| DidMethod::new(producer.method()).ok())
                .map(IdentityKind::Did)
                .chain([IdentityKind::JwkThumbprint]);
            for kind in kinds {
                for &alg in &capabilities.algorithms {
                    if key_type_for(alg).is_some() && !pairs.contains(&(kind.clone(), alg)) {
                        pairs.push((kind.clone(), alg));
                    }
                }
            }
        }
        pairs
    }

    async fn identifier(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Identifier, IdentityError> {
        Ok(self.binding(kind, alg).await?.identifier)
    }

    async fn public_jwk(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Jwk, IdentityError> {
        Ok(self.binding(kind, alg).await?.signer.public_jwk().public())
    }

    async fn signer(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Box<dyn Signer + '_>, IdentityError> {
        let binding = self.binding(kind, alg).await?;
        Ok(Box::new(BoundSigner {
            signer: binding.signer,
            kid: binding.kid,
        }))
    }
}

/// A [`KeySigner`] whose [`Signer::kid`] is the verification method of a DID, or `None` for a
/// thumbprint.
struct BoundSigner {
    signer: KeySigner<Arc<dyn KeyStore>>,
    kid: Option<String>,
}

#[async_trait::async_trait]
impl Signer for BoundSigner {
    fn alg(&self) -> JwsAlgorithm {
        self.signer.alg()
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.signer.sign(signing_input).await
    }
}
