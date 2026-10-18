//! `KeySigner`: a key of a `KeyStore` as a `jose::Signer`.

use core::fmt;

use super::{KeyId, KeyStore, KeyStoreError};
use crate::jose::{Jwk, JwsAlgorithm, SignError, Signer};

/// A [`Signer`] over one key of a [`KeyStore`].
///
/// The signer looks the key up once, when it is created, and keeps the public [`Jwk`] so that a
/// caller building a DID document or a JWS header never round-trips to the store for it
/// ([`KeySigner::public_jwk`]). Signing goes to the store on every call.
///
/// [`Signer::kid`] is the key id, unless [`KeySigner::with_kid`] set another value, such as the
/// DID URL of the verification method the key backs.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "in-memory")]
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use identity_kit::jose::{CompactJws, DefaultVerifier, JwsAlgorithm, JwsHeader, KeyType, encode_compact};
/// use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
///
/// let store = InMemoryKeyStore::new();
/// let key = store.generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA)).await?;
/// let signer = KeySigner::new(&store, key, JwsAlgorithm::EdDSA).await?;
///
/// let header = JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(signer.key_id().as_str());
/// let token = encode_compact(&header, b"{}", &signer).await?;
/// let jws = CompactJws::decode(&token)?;
/// jws.verify(&DefaultVerifier, signer.public_jwk())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct KeySigner<'a> {
    store: &'a dyn KeyStore,
    key: KeyId,
    alg: JwsAlgorithm,
    public: Jwk,
    kid: Option<String>,
}

impl<'a> KeySigner<'a> {
    /// A signer over `key` of `store`, signing with `alg`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnsupportedAlgorithm`] when the store does not advertise `alg`,
    /// [`KeyStoreError::NotFound`] when the key does not exist,
    /// [`KeyStoreError::AlgorithmMismatch`] when the key's public JWK names another algorithm,
    /// and whatever else the store reports.
    pub async fn new(
        store: &'a dyn KeyStore,
        key: KeyId,
        alg: JwsAlgorithm,
    ) -> Result<Self, KeyStoreError> {
        if !store.capabilities().supports(alg) {
            return Err(KeyStoreError::UnsupportedAlgorithm(alg));
        }
        let public = store.public_jwk(&key).await?;
        if let Some(key_alg) = public.alg() {
            let key_alg: JwsAlgorithm = key_alg.parse().map_err(|_| KeyStoreError::InvalidKey {
                key: key.clone(),
                reason: format!("unknown algorithm `{key_alg}` in its public JWK"),
            })?;
            if key_alg != alg {
                return Err(KeyStoreError::AlgorithmMismatch {
                    key,
                    key_alg,
                    requested: alg,
                });
            }
        }
        Ok(Self {
            store,
            key,
            alg,
            public,
            kid: None,
        })
    }

    /// This signer with [`Signer::kid`] set to `kid` instead of the key id.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The store the key lives in.
    pub fn store(&self) -> &'a dyn KeyStore {
        self.store
    }

    /// The key this signer signs with.
    pub fn key_id(&self) -> &KeyId {
        &self.key
    }

    /// The public key, as the store reported it when the signer was created.
    pub fn public_jwk(&self) -> &Jwk {
        &self.public
    }
}

impl fmt::Debug for KeySigner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySigner")
            .field("key", &self.key)
            .field("alg", &self.alg)
            .field("public", &self.public)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl Signer for KeySigner<'_> {
    fn alg(&self) -> JwsAlgorithm {
        self.alg
    }

    fn kid(&self) -> Option<&str> {
        Some(self.kid.as_deref().unwrap_or(self.key.as_str()))
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        self.store
            .sign(&self.key, self.alg, signing_input)
            .await
            .map_err(SignError::new)
    }
}
