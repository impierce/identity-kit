//! Error type of the `keys` module.

use std::error::Error;
use std::path::PathBuf;

use super::KeyId;
use crate::cause::cause;
use crate::jose::{JwsAlgorithm, KeyType};

/// Why a [`KeyStore`](super::KeyStore) operation failed.
///
/// The first variants are the contract every backend follows (the test suite checks them); the
/// file variants are reported by [`SoftwareKeyStore`](super::SoftwareKeyStore), and
/// [`Backend`](Self::Backend) carries whatever a remote backend reports.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// No key has this id.
    #[error("key `{0}` not found")]
    NotFound(KeyId),
    /// A key with this id exists already, so it cannot be generated or imported.
    #[error("key `{0}` already exists")]
    AlreadyExists(KeyId),
    /// The key signs with another algorithm than the one requested.
    #[error("key `{key}` signs with {key_alg}, not {requested}")]
    AlgorithmMismatch {
        /// The key.
        key: KeyId,
        /// The algorithm the key was created for.
        key_alg: JwsAlgorithm,
        /// The algorithm that was requested.
        requested: JwsAlgorithm,
    },
    /// The backend does not implement this operation (`generate` or `delete`).
    #[error("key store does not support `{0}`")]
    Unsupported(&'static str),
    /// The backend does not sign with this algorithm; see
    /// [`KeyStoreCapabilities::algorithms`](super::KeyStoreCapabilities::algorithms).
    #[error("key store does not support {0}")]
    UnsupportedAlgorithm(JwsAlgorithm),
    /// The backend cannot generate keys of this type.
    #[error("key store does not support {0:?} keys")]
    UnsupportedKeyType(KeyType),
    /// The algorithm of a [`KeySpec`](super::KeySpec) does not fit its key type, for example
    /// `ES256` with an Ed25519 key.
    #[error("{alg} cannot be used with {key_type:?} keys")]
    InvalidSpec {
        /// The requested key type.
        key_type: KeyType,
        /// The requested algorithm.
        alg: JwsAlgorithm,
    },
    /// The key exists but its material cannot be used: it does not decode, the public part does
    /// not match the private part, the type is unknown, and so on. The source is the error that
    /// says why, when there is one: the [`JwkError`](crate::jose::JwkError) of a public key that
    /// does not convert to a JWK, the error of a private scalar out of range.
    #[error("key `{key}` is unusable: {reason}{}", cause(.source.as_ref()))]
    InvalidKey {
        /// The key.
        key: KeyId,
        /// What is wrong with it.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
    /// Reading or writing the key store file failed.
    #[error("key store file `{}`: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The key store file is readable or writable by other users.
    #[error(
        "key store file `{}` has mode {mode:04o}; make it private (0600) or opt in with `allow_insecure_permissions`",
        path.display()
    )]
    InsecurePermissions {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// The key store file is not a usable JWK set. The source is the JSON error, or the error
    /// that makes one of its keys unusable, when there is one.
    #[error(
        "key store file `{}` is not a usable JWK set: {reason}{}",
        path.display(),
        cause(.source.as_ref())
    )]
    InvalidKeySet {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
        /// The underlying error.
        source: Option<Box<dyn Error + Send + Sync + 'static>>,
    },
    /// An error of a remote backend (an HSM, a cloud service).
    #[error("key store backend error: {0}")]
    Backend(#[source] Box<dyn Error + Send + Sync + 'static>),
}

impl KeyStoreError {
    /// [`KeyStoreError::InvalidKey`] for `key`, without an underlying error.
    pub fn invalid_key(key: KeyId, reason: impl Into<String>) -> Self {
        Self::InvalidKey {
            key,
            reason: reason.into(),
            source: None,
        }
    }

    /// Wraps a backend's own error as [`KeyStoreError::Backend`].
    pub fn backend<E: Error + Send + Sync + 'static>(error: E) -> Self {
        Self::Backend(Box::new(error))
    }
}
