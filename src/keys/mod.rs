//! Key stores: private keys behind an opaque id, with signing as a remote operation.
//!
//! The module is shaped by remote signers, an HSM or a cloud KMS being the design target:
//!
//! - A key is named by an opaque [`KeyId`] (a label, a PKCS#11 object name, a cloud key ARN).
//! - Private material never leaves the backend. [`KeyStore::sign`] is `async`, and callers keep
//!   the public [`Jwk`] they get from [`KeyStore::public_jwk`] rather than asking for it on every
//!   use; [`KeySigner`] does exactly that and implements [`Signer`](crate::jose::Signer).
//! - Every key has one algorithm. A backend declares what it signs with, and whether it can
//!   generate and delete keys, in [`KeyStoreCapabilities`]; the declaration must be truthful and
//!   [`testsuite`] (feature `test-vectors`) checks it.
//! - Signatures are returned in their JWS form: 64 bytes for EdDSA, raw `r || s` for ECDSA.
//!
//! Three backends ship with the crate. [`InMemoryKeyStore`] (feature `in-memory`) and
//! [`SoftwareKeyStore`] (feature `software`), a private JWK set file, are for development and
//! tests: both sign EdDSA, ES256 and, with the `secp256k1` feature, ES256K, and neither signs
//! with RSA, which stays outside the software backends per
//! `docs/adr/0001-rsa-verification-only.md`. [`Pkcs11KeyStore`] (feature `pkcs11`) signs in a
//! PKCS#11 module, an HSM or a software token, with whatever the module offers, RSA included.
//! Vendor-specific backends live in their own crates and implement [`KeyStore`];
//! `docs/key-stores.md` is the contract they follow.
//!
//! # Cargo features
//!
//! - `in-memory`: [`InMemoryKeyStore`].
//! - `software` (default): [`SoftwareKeyStore`].
//! - `pkcs11`: [`Pkcs11KeyStore`].
//! - `test-vectors`: [`testsuite`].

use core::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::jose::{Jwk, JwsAlgorithm};

mod error;
#[cfg(feature = "in-memory")]
mod in_memory;
#[cfg(any(feature = "in-memory", feature = "software"))]
mod local;
#[cfg(feature = "pkcs11")]
mod pkcs11;
mod signer;
#[cfg(feature = "software")]
mod software;
#[cfg(feature = "test-vectors")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-vectors")))]
pub mod testsuite;

pub use crate::jose::KeyType;
pub use error::KeyStoreError;
#[cfg(feature = "in-memory")]
#[cfg_attr(docsrs, doc(cfg(feature = "in-memory")))]
pub use in_memory::InMemoryKeyStore;
#[cfg(feature = "pkcs11")]
#[cfg_attr(docsrs, doc(cfg(feature = "pkcs11")))]
pub use pkcs11::{
    Pkcs11Error, Pkcs11KeyStore, Pkcs11KeyStoreOptions, Pkcs11Token, STAGING_LABEL_PREFIX,
};
pub use signer::KeySigner;
#[cfg(feature = "software")]
#[cfg_attr(docsrs, doc(cfg(feature = "software")))]
pub use software::{SoftwareKeyStore, SoftwareKeyStoreOptions};

/// The opaque id of a key in a [`KeyStore`].
///
/// What the string means is up to the backend: a label, a PKCS#11 object name, a cloud key ARN.
/// The crate never parses it. It serializes as a plain string.
///
/// # Examples
///
/// ```
/// use identity_kit::keys::KeyId;
///
/// let id = KeyId::new("signing-2026");
/// assert_eq!(id.as_str(), "signing-2026");
/// assert_eq!(id.to_string(), "signing-2026");
/// assert_eq!(serde_json::to_string(&id)?, "\"signing-2026\"");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// A key id from any string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for KeyId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for KeyId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

impl From<KeyId> for String {
    fn from(id: KeyId) -> Self {
        id.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What to generate: a key type, the one algorithm the key will sign with, and an optional
/// label.
///
/// The algorithm must fit the key type ([`KeySpec::validate`]); backends reject a spec that
/// does not. How a backend uses the label is its own business; the software backends use it as
/// the key id when set and the RFC 7638 thumbprint of the public key otherwise.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{JwsAlgorithm, KeyType};
/// use identity_kit::keys::{KeySpec, KeyStoreError};
///
/// let spec = KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("issuer");
/// assert!(spec.validate().is_ok());
///
/// let wrong = KeySpec::new(KeyType::P256, JwsAlgorithm::EdDSA);
/// assert!(matches!(wrong.validate(), Err(KeyStoreError::InvalidSpec { .. })));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeySpec {
    /// The kind of key.
    pub key_type: KeyType,
    /// The algorithm the key signs with.
    pub alg: JwsAlgorithm,
    /// A label for the backend: the key id for the software backends, a PKCS#11 label, a
    /// display name.
    pub label: Option<String>,
}

impl KeySpec {
    /// A spec without a label.
    pub fn new(key_type: KeyType, alg: JwsAlgorithm) -> Self {
        Self {
            key_type,
            alg,
            label: None,
        }
    }

    /// This spec with a label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Checks that the algorithm fits the key type.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::InvalidSpec`] when it does not: `EdDSA` needs an Ed25519 key, `ES256` a
    /// P-256 key, `ES256K` a secp256k1 key and `RS256` or `PS256` an RSA key. `ES384` fits no
    /// [`KeyType`] this crate has.
    pub fn validate(&self) -> Result<(), KeyStoreError> {
        if algorithm_fits(self.key_type, self.alg) {
            Ok(())
        } else {
            Err(KeyStoreError::InvalidSpec {
                key_type: self.key_type,
                alg: self.alg,
            })
        }
    }
}

/// Whether `alg` is an algorithm for keys of type `key_type`.
fn algorithm_fits(key_type: KeyType, alg: JwsAlgorithm) -> bool {
    match key_type {
        KeyType::Ed25519 => alg == JwsAlgorithm::EdDSA,
        KeyType::P256 => alg == JwsAlgorithm::ES256,
        KeyType::Secp256k1 => alg == JwsAlgorithm::ES256K,
        KeyType::Rsa2048 | KeyType::Rsa4096 => {
            matches!(alg, JwsAlgorithm::RS256 | JwsAlgorithm::PS256)
        }
    }
}

/// What a [`KeyStore`] can do.
///
/// A backend's declaration must be truthful: every algorithm listed signs, and `generate` and
/// `delete` succeed only when advertised. [`testsuite`] checks both directions.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JwsAlgorithm;
/// use identity_kit::keys::KeyStoreCapabilities;
///
/// let hsm = KeyStoreCapabilities::new([JwsAlgorithm::ES256, JwsAlgorithm::RS256]).remote();
/// assert!(hsm.supports(JwsAlgorithm::ES256));
/// assert!(!hsm.supports(JwsAlgorithm::EdDSA));
/// assert!(!hsm.can_generate && !hsm.can_delete && hsm.remote);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyStoreCapabilities {
    /// Whether [`KeyStore::generate`] is implemented.
    pub can_generate: bool,
    /// Whether [`KeyStore::delete`] is implemented.
    pub can_delete: bool,
    /// Whether signing leaves the process (an HSM, a network service), so that callers should
    /// expect latency and transient failures.
    pub remote: bool,
    /// The algorithms the store signs with, without duplicates.
    pub algorithms: Vec<JwsAlgorithm>,
}

impl KeyStoreCapabilities {
    /// A local store that signs with `algorithms` and can neither generate nor delete.
    pub fn new(algorithms: impl IntoIterator<Item = JwsAlgorithm>) -> Self {
        let mut deduplicated: Vec<JwsAlgorithm> = Vec::new();
        for alg in algorithms {
            if !deduplicated.contains(&alg) {
                deduplicated.push(alg);
            }
        }
        Self {
            can_generate: false,
            can_delete: false,
            remote: false,
            algorithms: deduplicated,
        }
    }

    /// With [`can_generate`](Self::can_generate) set.
    #[must_use]
    pub fn with_generate(mut self) -> Self {
        self.can_generate = true;
        self
    }

    /// With [`can_delete`](Self::can_delete) set.
    #[must_use]
    pub fn with_delete(mut self) -> Self {
        self.can_delete = true;
        self
    }

    /// With [`remote`](Self::remote) set.
    #[must_use]
    pub fn remote(mut self) -> Self {
        self.remote = true;
        self
    }

    /// Whether the store signs with `alg`.
    pub fn supports(&self, alg: JwsAlgorithm) -> bool {
        self.algorithms.contains(&alg)
    }
}

/// A backend holding private keys.
///
/// This is the crate's key extension point: a KMS, an HSM or a software store implements it,
/// and everything that signs takes a `&dyn KeyStore` (usually through [`KeySigner`]). The
/// contract, which [`testsuite`] checks, is:
///
/// - [`capabilities`](Self::capabilities) is truthful: every listed algorithm signs; `generate`
///   and `delete` return [`KeyStoreError::Unsupported`] unless advertised.
/// - [`public_jwk`](Self::public_jwk) returns a key without private parameters, with `alg` set
///   to the key's algorithm when the backend knows it.
/// - [`sign`](Self::sign) takes the raw signing input (the backend hashes) and returns the JWS
///   form of the signature: 64 bytes for EdDSA, raw `r || s` for ECDSA, the modulus-sized octet
///   string for RSA. A key signs only with its own algorithm; any other `alg` is
///   [`KeyStoreError::AlgorithmMismatch`].
/// - An unknown key is [`KeyStoreError::NotFound`] from every operation but
///   [`exists`](Self::exists), which returns `false`.
///
/// `generate` and `delete` have default implementations returning
/// [`KeyStoreError::Unsupported`], for backends whose keys are provisioned out of band.
#[async_trait::async_trait]
pub trait KeyStore: Send + Sync {
    /// What this store can do.
    fn capabilities(&self) -> KeyStoreCapabilities;

    /// The public key of `key`, without private parameters.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::NotFound`] when there is no such key.
    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError>;

    /// Signs `data` with `key` under `alg`, returning the signature in its JWS form.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::NotFound`] when there is no such key and
    /// [`KeyStoreError::AlgorithmMismatch`] when `alg` is not the key's algorithm.
    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError>;

    /// Whether `key` exists.
    ///
    /// # Errors
    ///
    /// Only when the backend cannot answer.
    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError>;

    /// Generates a key as `spec` describes and returns its id.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Unsupported`] when the store does not generate keys (the default),
    /// [`KeyStoreError::InvalidSpec`] when the algorithm does not fit the key type,
    /// [`KeyStoreError::UnsupportedKeyType`] or [`KeyStoreError::UnsupportedAlgorithm`] when the
    /// store cannot make such a key, and [`KeyStoreError::AlreadyExists`] when the label names
    /// an existing key.
    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        let _ = spec;
        Err(KeyStoreError::Unsupported("generate"))
    }

    /// Deletes `key`.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Unsupported`] when the store does not delete keys (the default) and
    /// [`KeyStoreError::NotFound`] when there is no such key.
    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        let _ = key;
        Err(KeyStoreError::Unsupported("delete"))
    }
}

macro_rules! forward_key_store {
    ($($ty:ty),* $(,)?) => {
        $(
            #[async_trait::async_trait]
            impl<T: KeyStore + ?Sized> KeyStore for $ty {
                fn capabilities(&self) -> KeyStoreCapabilities {
                    (**self).capabilities()
                }

                async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
                    (**self).public_jwk(key).await
                }

                async fn sign(
                    &self,
                    key: &KeyId,
                    alg: JwsAlgorithm,
                    data: &[u8],
                ) -> Result<Vec<u8>, KeyStoreError> {
                    (**self).sign(key, alg, data).await
                }

                async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
                    (**self).exists(key).await
                }

                async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
                    (**self).generate(spec).await
                }

                async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
                    (**self).delete(key).await
                }
            }
        )*
    };
}

forward_key_store!(&T, Box<T>, Arc<T>);
