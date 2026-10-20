//! `Pkcs11KeyStore`: keys in a PKCS#11 token, an HSM or a software token such as SoftHSM2.

use core::fmt;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CryptokiError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType as CkKeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sha2::{Digest as _, Sha256};

use super::{KeyId, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError};
use crate::jose::{Jwk, JwsAlgorithm, KeyType};

/// DER `OBJECT IDENTIFIER` 1.2.840.10045.3.1.7 (`prime256v1`), the `CKA_EC_PARAMS` of a P-256 key.
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER `OBJECT IDENTIFIER` 1.3.132.0.10 (`secp256k1`).
const SECP256K1_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a];
/// DER `OBJECT IDENTIFIER` 1.3.101.112 (`id-Ed25519`, RFC 8410), the `CKA_EC_PARAMS` this store
/// writes for an Ed25519 key.
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER `PrintableString "edwards25519"`, the other `CKA_EC_PARAMS` form PKCS #11 v3.1 §2.3.3
/// allows for Ed25519 and the one `pkcs11-tool` writes.
const ED25519_NAME_PARAMS: &[u8] = b"\x13\x0cedwards25519";
/// The RSA public exponent of generated keys, 65537.
const RSA_PUBLIC_EXPONENT: &[u8] = &[0x01, 0x00, 0x01];
/// The DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2, note 1): `CKM_RSA_PKCS` takes the
/// whole `DigestInfo`, so the store builds it around the hash it computes.
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Which token of a PKCS#11 module a [`Pkcs11KeyStore`] uses.
///
/// `&str`, `String` and `u64` convert into it.
///
/// # Examples
///
/// ```
/// use identity_kit::keys::Pkcs11Token;
///
/// assert_eq!(Pkcs11Token::from("issuer"), Pkcs11Token::Label("issuer".to_owned()));
/// assert_eq!(Pkcs11Token::from(2_108_653_770), Pkcs11Token::Slot(2_108_653_770));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Pkcs11Token {
    /// The token whose label (`CK_TOKEN_INFO.label`, as set when the token was initialized)
    /// is this string. Trailing blanks are ignored on both sides.
    Label(String),
    /// The token in the slot with this id. Slot ids are assigned by the module; SoftHSM2
    /// assigns a new one whenever a token is initialized, so a label is usually the better
    /// choice.
    Slot(u64),
}

impl From<&str> for Pkcs11Token {
    fn from(label: &str) -> Self {
        Self::Label(label.to_owned())
    }
}

impl From<String> for Pkcs11Token {
    fn from(label: String) -> Self {
        Self::Label(label)
    }
}

impl From<u64> for Pkcs11Token {
    fn from(slot: u64) -> Self {
        Self::Slot(slot)
    }
}

impl fmt::Display for Pkcs11Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Label(label) => write!(f, "token `{label}`"),
            Self::Slot(slot) => write!(f, "slot {slot}"),
        }
    }
}

/// How a [`Pkcs11KeyStore`] uses its token.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::JwsAlgorithm;
/// use identity_kit::keys::Pkcs11KeyStoreOptions;
///
/// let options = Pkcs11KeyStoreOptions::new()
///     .sessions(2)
///     .rsa_algorithm(JwsAlgorithm::PS256)
///     .algorithms([JwsAlgorithm::ES256, JwsAlgorithm::PS256]);
/// assert_eq!(options.sessions, 2);
/// assert_eq!(options.rsa_algorithm, JwsAlgorithm::PS256);
/// assert_eq!(
///     options.algorithms,
///     Some(vec![JwsAlgorithm::ES256, JwsAlgorithm::PS256])
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pkcs11KeyStoreOptions {
    /// How many sessions the store keeps open at most, `4` by default.
    ///
    /// Sessions are opened as needed, logged in and reused; an operation waits for a session
    /// when all of them are in use. At least `1`.
    pub sessions: usize,
    /// The algorithm RSA keys sign with, `RS256` by default: `RS256` (`CKM_RSA_PKCS`) or
    /// `PS256` (`CKM_RSA_PKCS_PSS`).
    ///
    /// A PKCS#11 RSA key does not record which padding it is for, and a key signs with one
    /// algorithm only, so the store settles it for all RSA keys of the token: the public JWK
    /// of every RSA key carries this `alg`, `sign` accepts only this algorithm for an RSA key
    /// and `generate` makes RSA keys for it.
    pub rsa_algorithm: JwsAlgorithm,
    /// The algorithms the store offers, out of those the module signs with; `None` for all of
    /// them.
    ///
    /// The store derives what it can sign with from the module's mechanism list (see
    /// [`Pkcs11KeyStore`]); this narrows that list, for a module whose `CKM_ECDSA` cannot take
    /// secp256k1 for instance. Algorithms the module does not sign with are left out.
    pub algorithms: Option<Vec<JwsAlgorithm>>,
}

impl Default for Pkcs11KeyStoreOptions {
    fn default() -> Self {
        Self {
            sessions: 4,
            rsa_algorithm: JwsAlgorithm::RS256,
            algorithms: None,
        }
    }
}

impl Pkcs11KeyStoreOptions {
    /// The defaults: four sessions, `RS256` for RSA keys, every algorithm the module signs with.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`sessions`](Self::sessions).
    #[must_use]
    pub fn sessions(mut self, sessions: usize) -> Self {
        self.sessions = sessions;
        self
    }

    /// Sets [`rsa_algorithm`](Self::rsa_algorithm).
    #[must_use]
    pub fn rsa_algorithm(mut self, alg: JwsAlgorithm) -> Self {
        self.rsa_algorithm = alg;
        self
    }

    /// Sets [`algorithms`](Self::algorithms).
    #[must_use]
    pub fn algorithms(mut self, algorithms: impl IntoIterator<Item = JwsAlgorithm>) -> Self {
        self.algorithms = Some(algorithms.into_iter().collect());
        self
    }
}

/// What went wrong with the PKCS#11 module, carried as [`KeyStoreError::Backend`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Pkcs11Error {
    /// The module could not be loaded or initialized.
    #[error("PKCS#11 module `{}`: {source}", module.display())]
    Module {
        /// The module's path.
        module: PathBuf,
        /// What the module reported.
        #[source]
        source: CryptokiError,
    },
    /// No slot of the module holds the requested token.
    #[error("PKCS#11 module has no {0}")]
    TokenNotFound(Pkcs11Token),
    /// An option is not usable.
    #[error("PKCS#11 key store options: {0}")]
    InvalidOptions(String),
    /// A PKCS#11 function failed.
    #[error("PKCS#11 {function} failed: {source}")]
    Call {
        /// The operation, as `C_...` names it.
        function: &'static str,
        /// What the module reported.
        #[source]
        source: CryptokiError,
    },
    /// The module returned a signature of another length than the algorithm's JWS form has.
    #[error("PKCS#11 module returned a {actual}-byte signature for {alg}, expected {expected}")]
    SignatureLength {
        /// The algorithm.
        alg: JwsAlgorithm,
        /// The length the JWS form has.
        expected: usize,
        /// The length the module returned.
        actual: usize,
    },
}

impl Pkcs11Error {
    /// Wraps the error of the PKCS#11 function `function` as [`KeyStoreError::Backend`].
    fn call(function: &'static str) -> impl FnOnce(CryptokiError) -> KeyStoreError {
        move |source| KeyStoreError::backend(Self::Call { function, source })
    }

    /// Whether the session the error came from is unusable from now on.
    fn closes_session(&self) -> bool {
        matches!(
            self,
            Self::Call {
                source: CryptokiError::Pkcs11(
                    RvError::SessionHandleInvalid
                        | RvError::SessionClosed
                        | RvError::DeviceRemoved
                        | RvError::DeviceError
                        | RvError::TokenNotPresent,
                    _
                ),
                ..
            }
        )
    }
}

/// A [`KeyStore`] over a token of a PKCS#11 module: an HSM, a smart card or a software token
/// such as SoftHSM2.
///
/// The key id is the object label (`CKA_LABEL`): a key is the private key object and the
/// public key object that share a label. Keys are referenced by label, so a label must name one
/// key; the store refuses a label that names several.
///
/// Signing happens in the module. The store hashes in-process and signs the hash with
/// `CKM_ECDSA` (ES256, ES256K), `CKM_RSA_PKCS` over a SHA-256 `DigestInfo` (RS256) or
/// `CKM_RSA_PKCS_PSS` with SHA-256, MGF1-SHA-256 and a 32-byte salt (PS256); EdDSA signs the
/// message itself with `CKM_EDDSA`. ECDSA signatures come back as raw `r || s`, the JWS form.
///
/// What the store signs with is read from the module's mechanism list when it is opened:
/// `EdDSA` when the module has `CKM_EDDSA`, `ES256` and (feature `secp256k1`) `ES256K` when it
/// has `CKM_ECDSA`, and [`rsa_algorithm`](Pkcs11KeyStoreOptions::rsa_algorithm) when it has the
/// matching RSA mechanism. [`Pkcs11KeyStoreOptions::algorithms`] narrows the list. The store
/// generates and deletes keys unless the token is write-protected; a generated key is an
/// Ed25519, P-256, secp256k1 or RSA (65537) key pair stored on the token, the private key
/// sensitive and not extractable. The key id of a generated key is the spec's label when set
/// and the RFC 7638 thumbprint of the public key otherwise.
///
/// The module's functions block, so every operation runs on `tokio`'s blocking thread pool;
/// the store needs a `tokio` runtime. It keeps a pool of logged-in sessions
/// ([`Pkcs11KeyStoreOptions::sessions`]) and an operation that finds all of them busy waits
/// for one. A module is loaded and initialized when the first store on it is opened, shared
/// by every later store on the same path, and never finalized or unloaded before the process
/// ends. The PIN is kept in memory for logging in
/// new sessions and zeroized when the store is dropped.
///
/// # Examples
///
/// ```no_run
/// # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
/// use identity_kit::jose::{JwsAlgorithm, KeyType};
/// use identity_kit::keys::{KeySpec, KeyStore, Pkcs11KeyStore};
///
/// let store = Pkcs11KeyStore::open("/usr/lib/softhsm/libsofthsm2.so", "issuer", Some("1234"))?;
/// let key = store
///     .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("issuer-2026"))
///     .await?;
/// let signature = store.sign(&key, JwsAlgorithm::ES256, b"payload").await?;
/// assert_eq!(signature.len(), 64);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # })?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct Pkcs11KeyStore {
    inner: Arc<Inner>,
}

/// The state behind the `Arc`, so that blocking tasks can own a reference to it.
struct Inner {
    module: PathBuf,
    context: Pkcs11,
    slot: Slot,
    token_label: String,
    pin: Option<AuthPin>,
    options: Pkcs11KeyStoreOptions,
    /// The algorithms the store signs with.
    algorithms: Vec<JwsAlgorithm>,
    /// The key pair generation mechanisms the module has.
    key_pair_generation: Vec<MechanismType>,
    write_protected: bool,
    pool: Pool,
    /// Held while this store generates or deletes a key; see [`TOKEN_WRITES`].
    writes: Arc<Mutex<()>>,
}

/// The logged-in sessions.
struct Pool {
    state: Mutex<PoolState>,
    /// Signalled when a session is returned or given up.
    available: Condvar,
    /// The most sessions open at once.
    max: usize,
}

#[derive(Default)]
struct PoolState {
    idle: Vec<Session>,
    /// Sessions open, idle or in use.
    open: usize,
}

impl Pkcs11KeyStore {
    /// Opens `token` of the PKCS#11 module at `module` with the default options.
    ///
    /// Loads the module, initializes it if needed, finds the token, reads its mechanism list and
    /// opens one session, logging in as the user with `pin` when given. A token that needs no
    /// login, or one with a protected authentication path, is opened with `None`. This blocks
    /// while it talks to the module.
    ///
    /// PKCS#11 logs the application in, not the session: when the process is logged in to the
    /// token already (through another store, say), the module reports that instead of checking
    /// `pin`, and a wrong PIN goes unnoticed until the process logs out.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Backend`] carrying a [`Pkcs11Error`]: the module does not load, the token
    /// is not there, the PIN is wrong, or the options are not usable.
    pub fn open(
        module: impl AsRef<Path>,
        token: impl Into<Pkcs11Token>,
        pin: Option<&str>,
    ) -> Result<Self, KeyStoreError> {
        Self::open_with(module, token, pin, Pkcs11KeyStoreOptions::default())
    }

    /// Opens `token` of the PKCS#11 module at `module` as `options` say.
    ///
    /// # Errors
    ///
    /// As [`Pkcs11KeyStore::open`].
    pub fn open_with(
        module: impl AsRef<Path>,
        token: impl Into<Pkcs11Token>,
        pin: Option<&str>,
        options: Pkcs11KeyStoreOptions,
    ) -> Result<Self, KeyStoreError> {
        let module = module.as_ref().to_path_buf();
        let token = token.into();
        if options.sessions == 0 {
            return Err(invalid_options("`sessions` must be at least 1"));
        }
        if !matches!(
            options.rsa_algorithm,
            JwsAlgorithm::RS256 | JwsAlgorithm::PS256
        ) {
            return Err(invalid_options(format!(
                "`rsa_algorithm` must be RS256 or PS256, not {}",
                options.rsa_algorithm
            )));
        }

        let context = load_module(&module)?;

        let (slot, token_label, write_protected) = find_token(&context, &token)?;
        let mechanisms = context
            .get_mechanism_list(slot)
            .map_err(Pkcs11Error::call("C_GetMechanismList"))?;
        let mut algorithms = Vec::new();
        if mechanisms.contains(&MechanismType::EDDSA) {
            algorithms.push(JwsAlgorithm::EdDSA);
        }
        if mechanisms.contains(&MechanismType::ECDSA) {
            algorithms.push(JwsAlgorithm::ES256);
            #[cfg(feature = "secp256k1")]
            algorithms.push(JwsAlgorithm::ES256K);
        }
        let rsa_mechanism = match options.rsa_algorithm {
            JwsAlgorithm::PS256 => MechanismType::RSA_PKCS_PSS,
            _ => MechanismType::RSA_PKCS,
        };
        if mechanisms.contains(&rsa_mechanism) {
            algorithms.push(options.rsa_algorithm);
        }
        if let Some(wanted) = &options.algorithms {
            algorithms.retain(|alg| wanted.contains(alg));
        }
        let key_pair_generation = [
            MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
            MechanismType::ECC_KEY_PAIR_GEN,
            MechanismType::RSA_PKCS_KEY_PAIR_GEN,
        ]
        .into_iter()
        .filter(|mechanism| mechanisms.contains(mechanism))
        .collect();

        let writes = token_writes(&module, slot.id());
        let inner = Inner {
            writes,
            module,
            context,
            slot,
            token_label,
            pin: pin.map(|pin| AuthPin::from(pin.to_owned())),
            pool: Pool {
                state: Mutex::new(PoolState::default()),
                available: Condvar::new(),
                max: options.sessions,
            },
            options,
            algorithms,
            key_pair_generation,
            write_protected,
        };
        // Open and log in one session now, so that a wrong PIN fails here and not on first use.
        let session = inner.open_session()?;
        inner.pool.release(session);
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The module's path.
    pub fn module(&self) -> &Path {
        &self.inner.module
    }

    /// The id of the slot the token is in.
    pub fn slot(&self) -> u64 {
        self.inner.slot.id()
    }

    /// The token's label.
    pub fn token_label(&self) -> &str {
        &self.inner.token_label
    }

    /// The options the store was opened with.
    pub fn options(&self) -> &Pkcs11KeyStoreOptions {
        &self.inner.options
    }

    /// Runs `f` on the blocking pool with a reference to the store's state.
    async fn blocking<T, F>(&self, f: F) -> Result<T, KeyStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Inner) -> Result<T, KeyStoreError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        match tokio::task::spawn_blocking(move || f(&inner)).await {
            Ok(result) => result,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(KeyStoreError::backend(e)),
        }
    }
}

impl fmt::Debug for Pkcs11KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkcs11KeyStore")
            .field("module", &self.inner.module)
            .field("slot", &self.inner.slot.id())
            .field("token_label", &self.inner.token_label)
            .field("algorithms", &self.inner.algorithms)
            .field("options", &self.inner.options)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl KeyStore for Pkcs11KeyStore {
    fn capabilities(&self) -> KeyStoreCapabilities {
        let capabilities =
            KeyStoreCapabilities::new(self.inner.algorithms.iter().copied()).remote();
        if self.inner.write_protected {
            capabilities
        } else {
            capabilities.with_generate().with_delete()
        }
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        let key = key.clone();
        self.blocking(move |inner| inner.with_session(|session| inner.public_jwk(session, &key)))
            .await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let key = key.clone();
        let data = data.to_vec();
        self.blocking(move |inner| {
            inner.with_session(|session| inner.sign(session, &key, alg, &data))
        })
        .await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        let key = key.clone();
        self.blocking(move |inner| {
            inner.with_session(|session| {
                Ok(find_key(session, ObjectClass::PRIVATE_KEY, &key)?.is_some())
            })
        })
        .await
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        if self.inner.write_protected {
            return Err(KeyStoreError::Unsupported("generate"));
        }
        self.blocking(move |inner| {
            let _writing = inner.writes.lock().unwrap_or_else(PoisonError::into_inner);
            inner.with_session(|session| inner.generate(session, &spec))
        })
        .await
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        if self.inner.write_protected {
            return Err(KeyStoreError::Unsupported("delete"));
        }
        let key = key.clone();
        self.blocking(move |inner| {
            let _writing = inner.writes.lock().unwrap_or_else(PoisonError::into_inner);
            inner.with_session(|session| delete(session, &key))
        })
        .await
    }
}

impl Inner {
    /// Opens a session on the token and logs in when the store has a PIN.
    ///
    /// A write-protected token refuses read/write sessions (`CKR_TOKEN_WRITE_PROTECTED`), and
    /// signing needs none, so such a token gets read-only sessions.
    fn open_session(&self) -> Result<Session, KeyStoreError> {
        let session = if self.write_protected {
            self.context.open_ro_session(self.slot)
        } else {
            self.context.open_rw_session(self.slot)
        }
        .map_err(Pkcs11Error::call("C_OpenSession"))?;
        if let Some(pin) = &self.pin {
            match session.login(UserType::User, Some(pin)) {
                // The login state is the application's, not the session's: once one session
                // of this process is logged in, so are the others.
                Ok(()) | Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(source) => return Err(Pkcs11Error::call("C_Login")(source)),
            }
        }
        Ok(session)
    }

    /// Runs `f` with a session from the pool, opening one if none is idle and fewer than the
    /// maximum are open, and waiting otherwise. A session an error made unusable is dropped
    /// instead of returned.
    fn with_session<T>(
        &self,
        f: impl FnOnce(&Session) -> Result<T, KeyStoreError>,
    ) -> Result<T, KeyStoreError> {
        let session = self.pool.acquire(|| self.open_session())?;
        let result = f(&session);
        let dead = matches!(
            &result,
            Err(KeyStoreError::Backend(e))
                if e.downcast_ref::<Pkcs11Error>().is_some_and(Pkcs11Error::closes_session)
        );
        if dead {
            self.pool.discard(session);
        } else {
            self.pool.release(session);
        }
        result
    }

    /// The algorithm a key of `kind` signs with.
    fn algorithm_of(&self, kind: KeyKind) -> JwsAlgorithm {
        match kind {
            KeyKind::Ed25519 => JwsAlgorithm::EdDSA,
            KeyKind::P256 => JwsAlgorithm::ES256,
            KeyKind::Secp256k1 => JwsAlgorithm::ES256K,
            KeyKind::Rsa => self.options.rsa_algorithm,
        }
    }

    /// [`KeyStore::public_jwk`] on `session`.
    fn public_jwk(&self, session: &Session, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        let Some(public) = find_key(session, ObjectClass::PUBLIC_KEY, key)? else {
            return Err(
                if find_key(session, ObjectClass::PRIVATE_KEY, key)?.is_some() {
                    KeyStoreError::InvalidKey {
                        key: key.clone(),
                        reason: "the token has no public key object with this label".to_owned(),
                    }
                } else {
                    KeyStoreError::NotFound(key.clone())
                },
            );
        };
        self.public_jwk_of(session, key, public)
    }

    /// The public JWK of the public key object `public`, with `kid` and `alg` set.
    fn public_jwk_of(
        &self,
        session: &Session,
        key: &KeyId,
        public: ObjectHandle,
    ) -> Result<Jwk, KeyStoreError> {
        let kind = key_kind(session, key, public)?;
        let invalid = |reason: String| KeyStoreError::InvalidKey {
            key: key.clone(),
            reason,
        };
        let jwk = match kind {
            KeyKind::Rsa => {
                let attributes = session
                    .get_attributes(
                        public,
                        &[AttributeType::Modulus, AttributeType::PublicExponent],
                    )
                    .map_err(Pkcs11Error::call("C_GetAttributeValue"))?;
                let mut modulus = None;
                let mut exponent = None;
                for attribute in attributes {
                    match attribute {
                        Attribute::Modulus(n) => modulus = Some(n),
                        Attribute::PublicExponent(e) => exponent = Some(e),
                        _ => {}
                    }
                }
                let (Some(n), Some(e)) = (modulus, exponent) else {
                    return Err(invalid(
                        "the public key object has no modulus or public exponent".to_owned(),
                    ));
                };
                Jwk::from_rsa_public(&n, &e).map_err(|e| invalid(e.to_string()))?
            }
            KeyKind::Ed25519 | KeyKind::P256 | KeyKind::Secp256k1 => {
                let point = ec_point(session, key, public, kind)?;
                match kind {
                    KeyKind::Ed25519 => {
                        Jwk::from_ed25519_public(&point).map_err(|e| invalid(e.to_string()))?
                    }
                    KeyKind::P256 => {
                        Jwk::from_p256_public(&point).map_err(|e| invalid(e.to_string()))?
                    }
                    #[cfg(feature = "secp256k1")]
                    KeyKind::Secp256k1 => {
                        Jwk::from_secp256k1_public(&point).map_err(|e| invalid(e.to_string()))?
                    }
                    #[cfg(not(feature = "secp256k1"))]
                    KeyKind::Secp256k1 => {
                        return Err(invalid(
                            "secp256k1 keys need the `secp256k1` feature".to_owned(),
                        ));
                    }
                    KeyKind::Rsa => unreachable!("matched above"),
                }
            }
        };
        Ok(jwk
            .with_kid(key.as_str())
            .with_alg(self.algorithm_of(kind).as_str()))
    }

    /// [`KeyStore::sign`] on `session`.
    fn sign(
        &self,
        session: &Session,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let private = find_key(session, ObjectClass::PRIVATE_KEY, key)?
            .ok_or_else(|| KeyStoreError::NotFound(key.clone()))?;
        let kind = key_kind(session, key, private)?;
        let key_alg = self.algorithm_of(kind);
        if alg != key_alg {
            return Err(KeyStoreError::AlgorithmMismatch {
                key: key.clone(),
                key_alg,
                requested: alg,
            });
        }
        if !self.algorithms.contains(&alg) {
            return Err(KeyStoreError::UnsupportedAlgorithm(alg));
        }
        let signature = match kind {
            KeyKind::Ed25519 => session
                .sign(
                    &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                    private,
                    data,
                )
                .map_err(Pkcs11Error::call("C_Sign"))?,
            KeyKind::P256 => session
                .sign(&Mechanism::Ecdsa, private, &Sha256::digest(data))
                .map_err(Pkcs11Error::call("C_Sign"))?,
            KeyKind::Secp256k1 => {
                let signature = session
                    .sign(&Mechanism::Ecdsa, private, &Sha256::digest(data))
                    .map_err(Pkcs11Error::call("C_Sign"))?;
                low_s(signature)
            }
            KeyKind::Rsa if alg == JwsAlgorithm::PS256 => {
                let params = PkcsPssParams {
                    hash_alg: MechanismType::SHA256,
                    mgf: PkcsMgfType::MGF1_SHA256,
                    s_len: 32.into(),
                };
                session
                    .sign(
                        &Mechanism::RsaPkcsPss(params),
                        private,
                        &Sha256::digest(data),
                    )
                    .map_err(Pkcs11Error::call("C_Sign"))?
            }
            KeyKind::Rsa => {
                let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
                digest_info.extend_from_slice(&Sha256::digest(data));
                session
                    .sign(&Mechanism::RsaPkcs, private, &digest_info)
                    .map_err(Pkcs11Error::call("C_Sign"))?
            }
        };
        if let Some(expected) = match kind {
            KeyKind::Ed25519 | KeyKind::P256 | KeyKind::Secp256k1 => Some(64),
            KeyKind::Rsa => None,
        } && signature.len() != expected
        {
            return Err(KeyStoreError::backend(Pkcs11Error::SignatureLength {
                alg,
                expected,
                actual: signature.len(),
            }));
        }
        Ok(signature)
    }

    /// [`KeyStore::generate`] on `session`.
    fn generate(&self, session: &Session, spec: &KeySpec) -> Result<KeyId, KeyStoreError> {
        spec.validate()?;
        if !self.algorithms.contains(&spec.alg) {
            return Err(KeyStoreError::UnsupportedAlgorithm(spec.alg));
        }
        let (mechanism, generation, mut public_template) = match spec.key_type {
            KeyType::Ed25519 => (
                Mechanism::EccEdwardsKeyPairGen,
                MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
                vec![
                    Attribute::KeyType(CkKeyType::EC_EDWARDS),
                    Attribute::EcParams(ED25519_PARAMS.to_vec()),
                ],
            ),
            KeyType::P256 => (
                Mechanism::EccKeyPairGen,
                MechanismType::ECC_KEY_PAIR_GEN,
                vec![
                    Attribute::KeyType(CkKeyType::EC),
                    Attribute::EcParams(P256_PARAMS.to_vec()),
                ],
            ),
            KeyType::Secp256k1 => (
                Mechanism::EccKeyPairGen,
                MechanismType::ECC_KEY_PAIR_GEN,
                vec![
                    Attribute::KeyType(CkKeyType::EC),
                    Attribute::EcParams(SECP256K1_PARAMS.to_vec()),
                ],
            ),
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                let bits: cryptoki::types::Ulong = match spec.key_type {
                    KeyType::Rsa4096 => 4096.into(),
                    _ => 2048.into(),
                };
                (
                    Mechanism::RsaPkcsKeyPairGen,
                    MechanismType::RSA_PKCS_KEY_PAIR_GEN,
                    vec![
                        Attribute::KeyType(CkKeyType::RSA),
                        Attribute::ModulusBits(bits),
                        Attribute::PublicExponent(RSA_PUBLIC_EXPONENT.to_vec()),
                    ],
                )
            }
        };
        if !self.key_pair_generation.contains(&generation) {
            return Err(KeyStoreError::UnsupportedKeyType(spec.key_type));
        }
        public_template.extend([
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
        ]);
        let mut private_template = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
        ];
        if let Some(label) = &spec.label {
            let id = KeyId::new(label.as_str());
            if find_key(session, ObjectClass::PRIVATE_KEY, &id)?.is_some()
                || find_key(session, ObjectClass::PUBLIC_KEY, &id)?.is_some()
            {
                return Err(KeyStoreError::AlreadyExists(id));
            }
            public_template.extend(label_attributes(label));
            private_template.extend(label_attributes(label));
        }

        let (public, private) = session
            .generate_key_pair(&mechanism, &public_template, &private_template)
            .map_err(Pkcs11Error::call("C_GenerateKeyPair"))?;
        if let Some(label) = &spec.label {
            return Ok(KeyId::new(label.as_str()));
        }
        // No label: the key id is the thumbprint of the public key, so label both objects with
        // it now that the key exists. A key that cannot be labelled is not kept.
        let labelled = self
            .public_jwk_of(session, &KeyId::new(""), public)
            .and_then(|jwk| {
                jwk.thumbprint_sha256()
                    .map_err(|e| KeyStoreError::InvalidKey {
                        key: KeyId::new(""),
                        reason: e.to_string(),
                    })
            })
            .and_then(|thumbprint| {
                let attributes = label_attributes(&thumbprint);
                session
                    .update_attributes(public, &attributes)
                    .and_then(|()| session.update_attributes(private, &attributes))
                    .map_err(Pkcs11Error::call("C_SetAttributeValue"))?;
                Ok(KeyId::new(thumbprint))
            });
        if labelled.is_err() {
            // Best effort: the error being returned is the one that matters.
            let _ = session.destroy_object(private);
            let _ = session.destroy_object(public);
        }
        labelled
    }
}

impl Pool {
    /// A session from the pool: an idle one, else a new one from `open` while fewer than the
    /// maximum are open, else the next one returned.
    fn acquire(
        &self,
        open: impl FnOnce() -> Result<Session, KeyStoreError>,
    ) -> Result<Session, KeyStoreError> {
        let mut state = self.lock();
        loop {
            if let Some(session) = state.idle.pop() {
                return Ok(session);
            }
            if state.open < self.max {
                state.open += 1;
                drop(state);
                return open().inspect_err(|_| {
                    self.lock().open -= 1;
                    self.available.notify_one();
                });
            }
            state = self
                .available
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Returns a usable session to the pool.
    fn release(&self, session: Session) {
        self.lock().idle.push(session);
        self.available.notify_one();
    }

    /// Drops an unusable session, making room for a new one.
    fn discard(&self, session: Session) {
        drop(session);
        self.lock().open -= 1;
        self.available.notify_one();
    }

    /// The pool's state, poison or not.
    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The modules loaded so far, by canonical path, each initialized once.
///
/// A PKCS#11 library must be initialized once per process, and unloading one that is still
/// initialized is unsafe, so a loaded module stays loaded and initialized until the process
/// ends; a store on a module loaded already shares the context.
static MODULES: Mutex<Vec<(PathBuf, Pkcs11)>> = Mutex::new(Vec::new());

/// One lock per token of the process, held while a key is generated or deleted.
///
/// Generation and deletion are provisioning, not the signing path, and serializing them
/// process-wide costs nothing there; SoftHSM2's file object store fails
/// (`CKR_GENERAL_ERROR`) when objects are created and destroyed from several sessions at
/// once, which would otherwise make it unusable for tests that provision in parallel.
static TOKEN_WRITES: Mutex<Vec<TokenWriteLock>> = Mutex::new(Vec::new());

/// A token, as (canonical module path, slot id), and its write lock.
type TokenWriteLock = ((PathBuf, u64), Arc<Mutex<()>>);

/// The write lock of the token in `slot` of the module at `module` (canonical path).
fn token_writes(module: &Path, slot: u64) -> Arc<Mutex<()>> {
    let key = (
        std::fs::canonicalize(module).unwrap_or_else(|_| module.to_path_buf()),
        slot,
    );
    let mut locks = TOKEN_WRITES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, lock)) = locks.iter().find(|(k, _)| *k == key) {
        return Arc::clone(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.push((key, Arc::clone(&lock)));
    lock
}

/// The initialized context for the module at `module`, loading it on first use.
fn load_module(module: &Path) -> Result<Pkcs11, KeyStoreError> {
    let key = std::fs::canonicalize(module).unwrap_or_else(|_| module.to_path_buf());
    let mut modules = MODULES.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, context)) = modules.iter().find(|(path, _)| *path == key) {
        return Ok(context.clone());
    }
    let failed = |source| {
        KeyStoreError::backend(Pkcs11Error::Module {
            module: module.to_path_buf(),
            source,
        })
    };
    let context = Pkcs11::new(module).map_err(failed)?;
    // The application itself may have initialized the module through another handle.
    match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CryptokiError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(source) => return Err(failed(source)),
    }
    modules.push((key, context.clone()));
    Ok(context)
}

/// The kinds of key the store signs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Ed25519,
    P256,
    Secp256k1,
    Rsa,
}

/// Finds the slot holding `token`, with the token's label and whether it is write-protected.
fn find_token(
    context: &Pkcs11,
    token: &Pkcs11Token,
) -> Result<(Slot, String, bool), KeyStoreError> {
    let not_found = || KeyStoreError::backend(Pkcs11Error::TokenNotFound(token.clone()));
    let slots = context
        .get_slots_with_token()
        .map_err(Pkcs11Error::call("C_GetSlotList"))?;
    for slot in slots {
        let matches = match token {
            Pkcs11Token::Slot(id) => slot.id() == *id,
            Pkcs11Token::Label(_) => true,
        };
        if !matches {
            continue;
        }
        let info = context
            .get_token_info(slot)
            .map_err(Pkcs11Error::call("C_GetTokenInfo"))?;
        let label = info.label().trim_end().to_owned();
        if let Pkcs11Token::Label(wanted) = token
            && label != wanted.trim_end()
        {
            continue;
        }
        return Ok((slot, label, info.write_protected()));
    }
    Err(not_found())
}

/// The one object of `class` labelled `key`, if any.
fn find_key(
    session: &Session,
    class: ObjectClass,
    key: &KeyId,
) -> Result<Option<ObjectHandle>, KeyStoreError> {
    let template = [
        Attribute::Class(class),
        Attribute::Label(key.as_str().as_bytes().to_vec()),
    ];
    let objects = session
        .find_objects(&template)
        .map_err(Pkcs11Error::call("C_FindObjects"))?;
    match objects.as_slice() {
        [] => Ok(None),
        [object] => Ok(Some(*object)),
        several => Err(KeyStoreError::InvalidKey {
            key: key.clone(),
            reason: format!(
                "the label names {} objects of the same class",
                several.len()
            ),
        }),
    }
}

/// Destroys the private and the public key object labelled `key`.
fn delete(session: &Session, key: &KeyId) -> Result<(), KeyStoreError> {
    let private = find_key(session, ObjectClass::PRIVATE_KEY, key)?;
    let public = find_key(session, ObjectClass::PUBLIC_KEY, key)?;
    if private.is_none() && public.is_none() {
        return Err(KeyStoreError::NotFound(key.clone()));
    }
    for object in [private, public].into_iter().flatten() {
        session
            .destroy_object(object)
            .map_err(Pkcs11Error::call("C_DestroyObject"))?;
    }
    Ok(())
}

/// `CKA_LABEL` and `CKA_ID`, both set to `label` so that tools pairing the objects of a key by
/// id (`pkcs11-tool`, for one) see one key.
fn label_attributes(label: &str) -> [Attribute; 2] {
    [
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(label.as_bytes().to_vec()),
    ]
}

/// What kind of key the object `object` is, from `CKA_KEY_TYPE` and `CKA_EC_PARAMS`.
fn key_kind(
    session: &Session,
    key: &KeyId,
    object: ObjectHandle,
) -> Result<KeyKind, KeyStoreError> {
    let attributes = session
        .get_attributes(object, &[AttributeType::KeyType, AttributeType::EcParams])
        .map_err(Pkcs11Error::call("C_GetAttributeValue"))?;
    let mut key_type = None;
    let mut params = None;
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(t) => key_type = Some(t),
            Attribute::EcParams(p) => params = Some(p),
            _ => {}
        }
    }
    let invalid = |reason: &str| KeyStoreError::InvalidKey {
        key: key.clone(),
        reason: reason.to_owned(),
    };
    match key_type {
        Some(CkKeyType::RSA) => Ok(KeyKind::Rsa),
        Some(CkKeyType::EC) => match params.as_deref() {
            Some(P256_PARAMS) => Ok(KeyKind::P256),
            Some(SECP256K1_PARAMS) => Ok(KeyKind::Secp256k1),
            Some(_) => Err(invalid("the curve is not P-256 or secp256k1")),
            None => Err(invalid("the EC key has no CKA_EC_PARAMS")),
        },
        Some(CkKeyType::EC_EDWARDS) => match params.as_deref() {
            Some(ED25519_PARAMS | ED25519_NAME_PARAMS) => Ok(KeyKind::Ed25519),
            Some(_) => Err(invalid("the Edwards curve is not Ed25519")),
            None => Err(invalid("the Edwards key has no CKA_EC_PARAMS")),
        },
        Some(_) => Err(invalid("the key type is not RSA, EC or EC_EDWARDS")),
        None => Err(invalid("the object has no CKA_KEY_TYPE")),
    }
}

/// The public point of the EC public key object `object`, a key of `kind`: the content of its
/// `CKA_EC_POINT`, a DER `OCTET STRING` holding the uncompressed SEC1 point (P-256, secp256k1)
/// or the 32-byte public key (Ed25519), or that content bare, as some modules store it.
fn ec_point(
    session: &Session,
    key: &KeyId,
    object: ObjectHandle,
    kind: KeyKind,
) -> Result<Vec<u8>, KeyStoreError> {
    let attributes = session
        .get_attributes(object, &[AttributeType::EcPoint])
        .map_err(Pkcs11Error::call("C_GetAttributeValue"))?;
    let invalid = |reason: &str| KeyStoreError::InvalidKey {
        key: key.clone(),
        reason: reason.to_owned(),
    };
    let Some(Attribute::EcPoint(encoded)) = attributes.into_iter().next() else {
        return Err(invalid("the public key object has no CKA_EC_POINT"));
    };
    ec_point_bytes(&encoded, kind)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| invalid("CKA_EC_POINT is neither a DER OCTET STRING nor a bare point"))
}

/// The point in a `CKA_EC_POINT` value: the content of the DER `OCTET STRING` the attribute
/// should be, or the value itself when it is not one but is a point of the size `kind` has.
///
/// A DER content of the right size wins, so that a bare value which happens to parse as DER
/// (a 32-byte key starting `04 1e`) is still read correctly whenever its content would not fit.
fn ec_point_bytes(encoded: &[u8], kind: KeyKind) -> Option<&[u8]> {
    let fits = |point: &[u8]| match kind {
        KeyKind::Ed25519 => point.len() == 32,
        KeyKind::P256 | KeyKind::Secp256k1 => point.len() == 65 && point[0] == 0x04,
        KeyKind::Rsa => false,
    };
    match der_octet_string(encoded) {
        Some(content) if fits(content) => Some(content),
        _ if fits(encoded) => Some(encoded),
        other => other,
    }
}

/// The content of a DER `OCTET STRING` that spans exactly `der`.
fn der_octet_string(der: &[u8]) -> Option<&[u8]> {
    let (&0x04, rest) = der.split_first()? else {
        return None;
    };
    let (&first, rest) = rest.split_first()?;
    let (length, content) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let length_bytes = usize::from(first & 0x7f);
        if length_bytes == 0 || length_bytes > 2 || rest.len() < length_bytes {
            return None;
        }
        let (length, content) = rest.split_at(length_bytes);
        let length = length
            .iter()
            .fold(0usize, |n, &b| (n << 8) | usize::from(b));
        // DER uses the shortest form: long form only from 128 up.
        if length < 0x80 {
            return None;
        }
        (length, content)
    };
    (content.len() == length).then_some(content)
}

/// `signature`, a secp256k1 `r || s`, with `s` in the lower half of the group order.
///
/// A module may return either of the two equivalent `s` values; `k256`, like Bitcoin, accepts
/// only the lower one, so the store always returns that one. A signature that is not 64 bytes
/// is returned as is, for the length check that follows.
#[cfg(feature = "secp256k1")]
fn low_s(signature: Vec<u8>) -> Vec<u8> {
    match k256::ecdsa::Signature::from_slice(&signature) {
        Ok(parsed) => parsed.normalize_s().to_bytes().to_vec(),
        Err(_) => signature,
    }
}

/// Without `k256` the store does not offer ES256K, so no secp256k1 signature is made.
#[cfg(not(feature = "secp256k1"))]
fn low_s(signature: Vec<u8>) -> Vec<u8> {
    signature
}

/// [`Pkcs11Error::InvalidOptions`] as a [`KeyStoreError`].
fn invalid_options(reason: impl Into<String>) -> KeyStoreError {
    KeyStoreError::backend(Pkcs11Error::InvalidOptions(reason.into()))
}

// `Pkcs11Error` is what `Backend` carries, so it must be sendable between threads.
const _: () = {
    const fn assert_send_sync<T: Send + Sync + Error + 'static>() {}
    assert_send_sync::<Pkcs11Error>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_octet_strings_decode() {
        // Short form, as every EC point of this crate's curves uses.
        assert_eq!(
            der_octet_string(&[0x04, 0x02, 0xaa, 0xbb]),
            Some(&[0xaa, 0xbb][..])
        );
        assert_eq!(der_octet_string(&[0x04, 0x00]), Some(&[][..]));
        // Long form.
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend(std::iter::repeat_n(7u8, 128));
        assert_eq!(der_octet_string(&long), Some(&long[3..]));
        let mut longer = vec![0x04, 0x82, 0x01, 0x00];
        longer.extend(std::iter::repeat_n(7u8, 256));
        assert_eq!(der_octet_string(&longer), Some(&longer[4..]));

        // Not an OCTET STRING, truncated, trailing bytes, non-minimal length.
        assert_eq!(der_octet_string(&[0x03, 0x01, 0xaa]), None);
        assert_eq!(der_octet_string(&[0x04]), None);
        assert_eq!(der_octet_string(&[0x04, 0x03, 0xaa, 0xbb]), None);
        assert_eq!(der_octet_string(&[0x04, 0x01, 0xaa, 0xbb]), None);
        assert_eq!(der_octet_string(&[0x04, 0x81, 0x01, 0xaa]), None);
        assert_eq!(der_octet_string(&[0x04, 0x80]), None);
        assert_eq!(
            der_octet_string(&[0x04, 0x83, 0x00, 0x00, 0x01, 0xaa]),
            None
        );
        assert_eq!(der_octet_string(&[]), None);
    }

    #[test]
    fn ec_points_are_read_wrapped_or_bare() {
        let ed25519 = [7u8; 32];
        let mut wrapped = vec![0x04, 0x20];
        wrapped.extend_from_slice(&ed25519);
        assert_eq!(
            ec_point_bytes(&wrapped, KeyKind::Ed25519),
            Some(&ed25519[..])
        );
        assert_eq!(
            ec_point_bytes(&ed25519, KeyKind::Ed25519),
            Some(&ed25519[..])
        );
        // A bare key that happens to parse as DER: its DER content is 30 bytes, which does
        // not fit, so the bare reading wins.
        let mut tricky = vec![0x04, 0x1e];
        tricky.extend_from_slice(&[9u8; 30]);
        assert_eq!(ec_point_bytes(&tricky, KeyKind::Ed25519), Some(&tricky[..]));

        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&[1u8; 64]);
        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&sec1);
        for kind in [KeyKind::P256, KeyKind::Secp256k1] {
            assert_eq!(ec_point_bytes(&wrapped, kind), Some(&sec1[..]));
            assert_eq!(ec_point_bytes(&sec1, kind), Some(&sec1[..]));
            // The wrong size for the kind: the DER content is handed on for the key
            // constructor to refuse.
            assert_eq!(ec_point_bytes(&[0x04, 0x01, 0xaa], kind), Some(&[0xaa][..]));
        }
        // A compressed point is not accepted bare, and nothing that is not DER is.
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[1u8; 64]);
        assert_eq!(ec_point_bytes(&compressed, KeyKind::P256), None);
        assert_eq!(ec_point_bytes(&[0x05, 0x01, 0xaa], KeyKind::P256), None);
        assert_eq!(ec_point_bytes(&ed25519, KeyKind::Rsa), None);
    }

    #[test]
    fn the_digest_info_prefix_is_the_one_of_rfc_8017() {
        // RFC 8017 §9.2, note 1: SHA-256's DigestInfo is this prefix followed by the 32-byte hash.
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(&[0u8; 32]);
        assert_eq!(digest_info.len(), 51);
        assert_eq!(digest_info[1], 0x31, "SEQUENCE length covers the rest");
        assert_eq!(
            &digest_info[4..13],
            &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04]
        );
        assert_eq!(&digest_info[13..15], &[0x02, 0x01], "id-sha256");
        assert_eq!(
            &digest_info[17..19],
            &[0x04, 0x20],
            "OCTET STRING of 32 bytes"
        );
    }

    #[test]
    fn tokens_convert_and_display() {
        assert_eq!(Pkcs11Token::from("a"), Pkcs11Token::Label("a".to_owned()));
        assert_eq!(
            Pkcs11Token::from("a".to_owned()),
            Pkcs11Token::Label("a".to_owned())
        );
        assert_eq!(Pkcs11Token::from(7), Pkcs11Token::Slot(7));
        assert_eq!(Pkcs11Token::from("a").to_string(), "token `a`");
        assert_eq!(Pkcs11Token::from(7).to_string(), "slot 7");
    }

    #[test]
    fn options_default_and_build() {
        let options = Pkcs11KeyStoreOptions::new();
        assert_eq!(options, Pkcs11KeyStoreOptions::default());
        assert_eq!(options.sessions, 4);
        assert_eq!(options.rsa_algorithm, JwsAlgorithm::RS256);
        assert_eq!(options.algorithms, None);
        let options = options
            .sessions(1)
            .rsa_algorithm(JwsAlgorithm::PS256)
            .algorithms([JwsAlgorithm::EdDSA]);
        assert_eq!(options.sessions, 1);
        assert_eq!(options.rsa_algorithm, JwsAlgorithm::PS256);
        assert_eq!(options.algorithms, Some(vec![JwsAlgorithm::EdDSA]));
    }

    #[test]
    fn bad_options_are_refused_before_the_module_loads() {
        let no_sessions = Pkcs11KeyStore::open_with(
            "/nonexistent/module.so",
            "token",
            None,
            Pkcs11KeyStoreOptions::new().sessions(0),
        )
        .unwrap_err();
        assert_eq!(
            no_sessions.to_string(),
            "key store backend error: PKCS#11 key store options: `sessions` must be at least 1"
        );
        let wrong_rsa = Pkcs11KeyStore::open_with(
            "/nonexistent/module.so",
            "token",
            None,
            Pkcs11KeyStoreOptions::new().rsa_algorithm(JwsAlgorithm::ES256),
        )
        .unwrap_err();
        assert_eq!(
            wrong_rsa.to_string(),
            "key store backend error: PKCS#11 key store options: `rsa_algorithm` must be RS256 or PS256, not ES256"
        );
    }

    #[test]
    fn a_missing_module_is_reported_with_its_path() {
        let error = Pkcs11KeyStore::open("/nonexistent/module.so", "token", None).unwrap_err();
        let KeyStoreError::Backend(source) = &error else {
            panic!("expected Backend, got {error:?}");
        };
        let pkcs11 = source.downcast_ref::<Pkcs11Error>().expect("a Pkcs11Error");
        assert!(
            matches!(pkcs11, Pkcs11Error::Module { module, .. } if module == Path::new("/nonexistent/module.so"))
        );
        assert!(
            error
                .to_string()
                .starts_with("key store backend error: PKCS#11 module `/nonexistent/module.so`: "),
            "{error}"
        );
        assert!(pkcs11.source().is_some());
    }

    #[test]
    fn errors_that_close_a_session_are_known() {
        let call = |rv| Pkcs11Error::Call {
            function: "C_Sign",
            source: CryptokiError::Pkcs11(rv, cryptoki::context::Function::Sign),
        };
        assert!(call(RvError::SessionHandleInvalid).closes_session());
        assert!(call(RvError::DeviceRemoved).closes_session());
        assert!(!call(RvError::KeyHandleInvalid).closes_session());
        assert!(!Pkcs11Error::TokenNotFound(Pkcs11Token::Slot(1)).closes_session());
        assert_eq!(
            Pkcs11Error::SignatureLength {
                alg: JwsAlgorithm::ES256,
                expected: 64,
                actual: 70
            }
            .to_string(),
            "PKCS#11 module returned a 70-byte signature for ES256, expected 64"
        );
    }
}
