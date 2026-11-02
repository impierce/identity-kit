//! `SoftwareKeyStore`: private keys in a JWK set file.

use core::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::local::{self, Entry};
use super::{KeyId, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError};
use crate::jose::{Jwk, JwsAlgorithm};

/// A JWK set (RFC 7517 §5) of private keys, the on-disk format of the store.
#[derive(Serialize, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
    #[serde(flatten)]
    additional: IndexMap<String, Value>,
}

/// How to open a [`SoftwareKeyStore`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SoftwareKeyStoreOptions {
    /// Open a file that other users can read or write.
    ///
    /// By default a key store file with group or world permission bits is refused with
    /// [`KeyStoreError::InsecurePermissions`]. The check runs on Unix only.
    pub allow_insecure_permissions: bool,
    /// Create an empty key store if the file does not exist.
    pub create_if_missing: bool,
}

impl SoftwareKeyStoreOptions {
    /// The defaults: refuse insecure permissions, fail on a missing file.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`allow_insecure_permissions`](Self::allow_insecure_permissions).
    #[must_use]
    pub fn allow_insecure_permissions(mut self, allow: bool) -> Self {
        self.allow_insecure_permissions = allow;
        self
    }

    /// Sets [`create_if_missing`](Self::create_if_missing).
    #[must_use]
    pub fn create_if_missing(mut self, create: bool) -> Self {
        self.create_if_missing = create;
        self
    }
}

/// A [`KeyStore`] over a file holding a JWK set of private keys.
///
/// The file is `{"keys": [...]}` (RFC 7517 §5) where every key is a private JWK with a `kid`,
/// the key id, and an `alg`, the one algorithm it signs with. Signs EdDSA, ES256 and (feature
/// `secp256k1`) ES256K; generates and deletes. RSA keys in the file are refused, since the crate
/// never signs with RSA (`docs/adr/0001-rsa-verification-only.md`).
///
/// The whole file is read when the store is opened and every key is checked then: a key whose
/// public members do not match its private scalar, whose `alg` does not fit, or whose `kid` is
/// taken by another key fails [`SoftwareKeyStore::open`] with [`KeyStoreError::InvalidKeySet`].
/// Private material is zeroized when the store is dropped.
///
/// Writes (`generate`, `delete`, [`import`](Self::import)) replace the file atomically: the new
/// set is written to a temporary file in the same directory, created with mode `0600` on Unix,
/// synced and renamed over the old one. A store opened on a file that other users can read is
/// refused unless [`SoftwareKeyStoreOptions::allow_insecure_permissions`] is set. Nothing locks
/// the file against other processes; one store per file.
///
/// The key id of a generated key is the spec's label when set and the RFC 7638 thumbprint of
/// the public key otherwise. `xtask keys generate` provisions a file from the command line.
///
/// # Examples
///
/// ```
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use identity_kit::jose::{JwsAlgorithm, KeyType};
/// use identity_kit::keys::{KeySpec, KeyStore, SoftwareKeyStore, SoftwareKeyStoreOptions};
///
/// let dir = tempfile::tempdir()?;
/// let path = dir.path().join("keys.json");
/// let store = SoftwareKeyStore::create(&path)?;
/// let key = store
///     .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("issuer"))
///     .await?;
/// assert_eq!(key.as_str(), "issuer");
///
/// // The key is on disk and usable by the next store opened on the file.
/// let reopened = SoftwareKeyStore::open(&path)?;
/// assert!(reopened.exists(&key).await?);
/// assert_eq!(reopened.sign(&key, JwsAlgorithm::ES256, b"payload").await?.len(), 64);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct SoftwareKeyStore {
    path: PathBuf,
    keys: RwLock<IndexMap<KeyId, Entry>>,
    additional: IndexMap<String, Value>,
}

impl SoftwareKeyStore {
    /// Opens the key set file at `path` with the default options.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Io`] when the file cannot be read, [`KeyStoreError::InsecurePermissions`]
    /// when other users can read it and [`KeyStoreError::InvalidKeySet`] when it is not a JWK set
    /// of usable private keys.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        Self::open_with(path, SoftwareKeyStoreOptions::default())
    }

    /// Opens the key set file at `path` as `options` say.
    ///
    /// # Errors
    ///
    /// As [`SoftwareKeyStore::open`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "options are taken by value, as builders take them, so that they can grow"
    )]
    pub fn open_with(
        path: impl Into<PathBuf>,
        options: SoftwareKeyStoreOptions,
    ) -> Result<Self, KeyStoreError> {
        let path = path.into();
        if options.create_if_missing && !path.exists() {
            return Self::create(path);
        }
        let data = fs::read(&path).map_err(|source| KeyStoreError::Io {
            path: path.clone(),
            source,
        })?;
        if !options.allow_insecure_permissions {
            check_permissions(&path)?;
        }
        let set: JwkSet =
            serde_json::from_slice(&data).map_err(|e| KeyStoreError::InvalidKeySet {
                path: path.clone(),
                reason: "not a JWK set".to_owned(),
                source: Some(Box::new(e)),
            })?;
        let mut keys = IndexMap::with_capacity(set.keys.len());
        for jwk in set.keys {
            let (id, entry) =
                Entry::from_jwk(jwk).map_err(|unusable| unusable.for_key_set(path.clone()))?;
            if keys.insert(id.clone(), entry).is_some() {
                return Err(KeyStoreError::InvalidKeySet {
                    path,
                    reason: format!("key `{id}` is defined twice"),
                    source: None,
                });
            }
        }
        Ok(Self {
            path,
            keys: RwLock::new(keys),
            additional: set.additional,
        })
    }

    /// Creates an empty key set file at `path`, with mode `0600` on Unix.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Io`] when the file exists already or cannot be written.
    pub fn create(path: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        let path = path.into();
        if path.exists() {
            return Err(KeyStoreError::Io {
                path,
                source: io::Error::new(io::ErrorKind::AlreadyExists, "file exists"),
            });
        }
        let store = Self {
            path,
            keys: RwLock::new(IndexMap::new()),
            additional: IndexMap::new(),
        };
        store.save(&IndexMap::new())?;
        Ok(store)
    }

    /// The key set file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The ids of the keys in the store, in file order.
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Adds an existing private JWK to the store and writes the file.
    ///
    /// The key id is the `kid` when set and the RFC 7638 thumbprint of the public key otherwise;
    /// `alg` must fit the key when set and defaults to the key type's algorithm.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::InvalidKey`] when the JWK is not a usable private key of a supported
    /// type, [`KeyStoreError::AlreadyExists`] when its id is taken and [`KeyStoreError::Io`] when
    /// the file cannot be written.
    pub fn import(&self, jwk: Jwk) -> Result<KeyId, KeyStoreError> {
        let key = KeyId::new(jwk.kid().unwrap_or_default());
        let (id, entry) = Entry::from_jwk(jwk).map_err(|unusable| unusable.for_key(key))?;
        self.insert(id, entry)
    }

    /// Inserts `entry` under `id` and writes the file, rolling back on failure.
    fn insert(&self, id: KeyId, entry: Entry) -> Result<KeyId, KeyStoreError> {
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        if keys.contains_key(&id) {
            return Err(KeyStoreError::AlreadyExists(id));
        }
        keys.insert(id.clone(), entry);
        if let Err(e) = self.save(&keys) {
            keys.shift_remove(&id);
            return Err(e);
        }
        Ok(id)
    }

    /// Writes `keys` to the file atomically.
    fn save(&self, keys: &IndexMap<KeyId, Entry>) -> Result<(), KeyStoreError> {
        let set = JwkSet {
            keys: keys.values().map(|entry| entry.jwk.clone()).collect(),
            additional: self.additional.clone(),
        };
        // A `Jwk` serializes to a JSON object; this cannot fail.
        let mut json = serde_json::to_vec_pretty(&set).map_err(|e| KeyStoreError::Io {
            path: self.path.clone(),
            source: io::Error::other(e),
        })?;
        json.push(b'\n');
        write_atomically(&self.path, &json).map_err(|source| KeyStoreError::Io {
            path: self.path.clone(),
            source,
        })
    }
}

impl fmt::Debug for SoftwareKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKeyStore")
            .field("path", &self.path)
            .field("keys", &self.key_ids())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl KeyStore for SoftwareKeyStore {
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
        let (id, key) = local::generate(&spec, &mut local::os_random)?;
        let entry = Entry::new(&id, key, spec.alg);
        self.insert(id, entry)
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        let mut keys = self.keys.write().unwrap_or_else(PoisonError::into_inner);
        let (index, id, entry) = keys
            .shift_remove_full(key)
            .ok_or_else(|| KeyStoreError::NotFound(key.clone()))?;
        if let Err(e) = self.save(&keys) {
            keys.shift_insert(index, id, entry);
            return Err(e);
        }
        Ok(())
    }
}

/// Refuses a file with group or world permission bits. Unix only.
#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), KeyStoreError> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = fs::metadata(path)
        .map_err(|source| KeyStoreError::Io {
            path: path.to_owned(),
            source,
        })?
        .permissions()
        .mode()
        & 0o7777;
    if mode & 0o077 != 0 {
        return Err(KeyStoreError::InsecurePermissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), KeyStoreError> {
    Ok(())
}

/// Writes `data` to a private temporary file next to `path`, syncs it and renames it over
/// `path`, so that a reader sees either the old or the new content and never a partial file.
fn write_atomically(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(format!(".{:016x}.tmp", u64::from_be_bytes(nonce)));
    let tmp = dir.join(tmp_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = options.open(&tmp).and_then(|mut file| {
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
