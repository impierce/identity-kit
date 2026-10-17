//! `InMemoryKeyStore`: keys in process memory, for tests and development.

use core::fmt;
use std::sync::{Mutex, PoisonError, RwLock};

use indexmap::IndexMap;

use super::local::{self, Entry, SeededRandom};
use super::{KeyId, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError};
use crate::jose::{Jwk, JwsAlgorithm};

/// A [`KeyStore`] holding its keys in memory.
///
/// Signs EdDSA, ES256 and (feature `secp256k1`) ES256K; generates and deletes. Keys are lost
/// when the store is dropped, and zeroized then. Meant for tests, examples and development, not
/// for production keys.
///
/// [`InMemoryKeyStore::with_seed`] makes key generation deterministic, so that a fixture's keys,
/// key ids and (for EdDSA and the RFC 6979 ECDSA signatures) signatures are stable across runs.
/// A seeded store must never hold production keys: anyone with the seed has them.
///
/// The key id of a generated key is the spec's label when set, the RFC 7638 thumbprint of its
/// public key otherwise.
///
/// # Examples
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use identity_kit::jose::{JwsAlgorithm, KeyType};
/// use identity_kit::keys::{InMemoryKeyStore, KeySpec, KeyStore};
///
/// let store = InMemoryKeyStore::with_seed([7; 32]);
/// let key = store.generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA)).await?;
/// let signature = store.sign(&key, JwsAlgorithm::EdDSA, b"payload").await?;
/// assert_eq!(signature.len(), 64);
///
/// // The same seed gives the same key.
/// let again = InMemoryKeyStore::with_seed([7; 32]);
/// assert_eq!(again.generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA)).await?, key);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct InMemoryKeyStore {
    keys: RwLock<IndexMap<KeyId, Entry>>,
    seeded: Option<Mutex<SeededRandom>>,
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKeyStore {
    /// An empty store generating keys from the operating system's randomness.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(IndexMap::new()),
            seeded: None,
        }
    }

    /// An empty store generating keys deterministically from `seed`.
    ///
    /// The n-th key generated from a seed is always the same key. For fixtures only.
    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self {
            keys: RwLock::new(IndexMap::new()),
            seeded: Some(Mutex::new(SeededRandom::new(seed))),
        }
    }

    /// The ids of the keys in the store, in generation order.
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Whether key generation is seeded.
    pub fn is_seeded(&self) -> bool {
        self.seeded.is_some()
    }

    fn random(&self, buf: &mut [u8]) -> Result<(), KeyStoreError> {
        match &self.seeded {
            Some(seeded) => {
                seeded
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .fill(buf);
                Ok(())
            }
            None => local::os_random(buf),
        }
    }
}

impl fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("keys", &self.key_ids())
            .field("seeded", &self.is_seeded())
            .finish()
    }
}

#[async_trait::async_trait]
impl KeyStore for InMemoryKeyStore {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new(local::ALGORITHMS.iter().copied())
            .with_generate()
            .with_delete()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .map(Entry::public_jwk)
            .ok_or_else(|| KeyStoreError::NotFound(key.clone()))
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .ok_or_else(|| KeyStoreError::NotFound(key.clone()))?
            .sign(key, alg, data)
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        Ok(self
            .keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(key))
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        let (id, key) = local::generate(&spec, &mut |buf| self.random(buf))?;
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        if keys.contains_key(&id) {
            return Err(KeyStoreError::AlreadyExists(id));
        }
        keys.insert(id.clone(), Entry::new(&id, key, spec.alg));
        Ok(id)
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .shift_remove(key)
            .map(drop)
            .ok_or_else(|| KeyStoreError::NotFound(key.clone()))
    }
}
