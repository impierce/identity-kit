//! `KeySigner`: a key of a `KeyStore` as a `jose::Signer`.

use core::fmt;

use super::{KeyId, KeyStore, KeyStoreError};
use crate::jose::{Jwk, JwsAlgorithm, SignError, Signer};

/// A [`Signer`] over one key of a [`KeyStore`].
///
/// `S` is the handle the signer holds the store by: a reference (`&InMemoryKeyStore`,
/// `&dyn KeyStore`) for a signer that lives next to the store, or an `Arc<dyn KeyStore>` for one
/// that outlives the scope it was made in, moved into a spawned task or kept in shared
/// application state. Every such handle implements [`KeyStore`] itself.
///
/// The signer looks the key up once, when it is created, and keeps the public [`Jwk`] so that a
/// caller building a DID document or a JWS header never round-trips to the store for it
/// ([`KeySigner::public_jwk`]). A caller that already has the public key, for instance stored
/// next to the DID document it published, skips that lookup with [`KeySigner::from_public_jwk`].
/// Signing goes to the store on every call.
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
///
/// A signer over an `Arc<dyn KeyStore>` is `'static` and moves into a spawned task:
///
/// ```
/// # #[cfg(feature = "in-memory")]
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use std::sync::Arc;
///
/// use identity_kit::jose::{JwsAlgorithm, JwsHeader, KeyType, encode_compact};
/// use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
///
/// let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());
/// let key = store.generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256)).await?;
/// let signer = KeySigner::new(Arc::clone(&store), key, JwsAlgorithm::ES256).await?;
///
/// let token = tokio::spawn(async move {
///     encode_compact(&JwsHeader::new(JwsAlgorithm::ES256), b"{}", &signer).await
/// })
/// .await??;
/// assert_eq!(token.split('.').count(), 3);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct KeySigner<S> {
    store: S,
    key: KeyId,
    alg: JwsAlgorithm,
    public: Jwk,
    kid: Option<String>,
}

impl<S: KeyStore> KeySigner<S> {
    /// A signer over `key` of `store`, signing with `alg`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnsupportedAlgorithm`] when the store does not advertise `alg`,
    /// [`KeyStoreError::NotFound`] when the key does not exist,
    /// [`KeyStoreError::AlgorithmMismatch`] when the key's public JWK names another algorithm,
    /// and whatever else the store reports.
    pub async fn new(store: S, key: KeyId, alg: JwsAlgorithm) -> Result<Self, KeyStoreError> {
        if !store.capabilities().supports(alg) {
            return Err(KeyStoreError::UnsupportedAlgorithm(alg));
        }
        let public = store.public_jwk(&key).await?;
        check_alg(&key, &public, alg)?;
        Ok(Self {
            store,
            key,
            alg,
            public,
            kid: None,
        })
    }

    /// A signer over `key` of `store`, signing with `alg`, whose public key the caller already
    /// has. The store is not asked for anything until the first signature.
    ///
    /// The caller vouches that `public` is the public key of `key`: the signer cannot tell, and
    /// with a wrong one it makes signatures that verify against no key the caller publishes.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::UnsupportedAlgorithm`] when the store does not advertise `alg`,
    /// [`KeyStoreError::AlgorithmMismatch`] when `public` names another algorithm, and
    /// [`KeyStoreError::InvalidKey`] when `public` carries private parameters or is not a key
    /// for `alg` (its `kty` and `crv`).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "in-memory")]
    /// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
    /// use identity_kit::jose::{JwsAlgorithm, KeyType};
    /// use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
    ///
    /// let store = InMemoryKeyStore::new();
    /// let key = store.generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA)).await?;
    /// // Fetched once and kept, for instance next to the DID document.
    /// let public = store.public_jwk(&key).await?;
    ///
    /// let signer = KeySigner::from_public_jwk(&store, key, JwsAlgorithm::EdDSA, public)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # })?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_public_jwk(
        store: S,
        key: KeyId,
        alg: JwsAlgorithm,
        public: Jwk,
    ) -> Result<Self, KeyStoreError> {
        if !store.capabilities().supports(alg) {
            return Err(KeyStoreError::UnsupportedAlgorithm(alg));
        }
        if public.is_private() {
            return Err(KeyStoreError::InvalidKey {
                key,
                reason: "the given public JWK carries private parameters".to_owned(),
            });
        }
        if !fits(&public, alg) {
            return Err(KeyStoreError::InvalidKey {
                reason: format!(
                    "the given public JWK (`kty` {}, `crv` {}) is not a key for {alg}",
                    public.kty(),
                    public.crv().unwrap_or("absent"),
                ),
                key,
            });
        }
        check_alg(&key, &public, alg)?;
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
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The key this signer signs with.
    pub fn key_id(&self) -> &KeyId {
        &self.key
    }

    /// The public key, as the store reported it when the signer was created, or as given to
    /// [`KeySigner::from_public_jwk`].
    pub fn public_jwk(&self) -> &Jwk {
        &self.public
    }
}

/// [`KeyStoreError::AlgorithmMismatch`] unless `public` names no algorithm or names `alg`.
fn check_alg(key: &KeyId, public: &Jwk, alg: JwsAlgorithm) -> Result<(), KeyStoreError> {
    let Some(key_alg) = public.alg() else {
        return Ok(());
    };
    let key_alg: JwsAlgorithm = key_alg.parse().map_err(|_| KeyStoreError::InvalidKey {
        key: key.clone(),
        reason: format!("unknown algorithm `{key_alg}` in its public JWK"),
    })?;
    if key_alg == alg {
        Ok(())
    } else {
        Err(KeyStoreError::AlgorithmMismatch {
            key: key.clone(),
            key_alg,
            requested: alg,
        })
    }
}

/// Whether `public` is a key `alg` signs with, by its `kty` and `crv` (RFC 7518 §6, RFC 8037 §2,
/// RFC 8812 §3.1).
fn fits(public: &Jwk, alg: JwsAlgorithm) -> bool {
    match alg {
        JwsAlgorithm::EdDSA => public.kty() == "OKP" && public.crv() == Some("Ed25519"),
        JwsAlgorithm::ES256 => public.kty() == "EC" && public.crv() == Some("P-256"),
        JwsAlgorithm::ES256K => public.kty() == "EC" && public.crv() == Some("secp256k1"),
        JwsAlgorithm::ES384 => public.kty() == "EC" && public.crv() == Some("P-384"),
        JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => public.kty() == "RSA",
    }
}

impl<S> fmt::Debug for KeySigner<S> {
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
impl<S: KeyStore> Signer for KeySigner<S> {
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
