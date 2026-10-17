//! `DidProducer`: creating the DID document of a method from keys.

use core::fmt;
use std::error::Error;

use crate::did::{DidDocument, DocumentError};
use crate::jose::Jwk;

/// Where the documents of a DID method live, which decides what creating one involves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Hosting {
    /// The document is derived from the DID itself (`did:key`, `did:jwk`): nothing is published.
    Embedded,
    /// The document is served over HTTPS by its controller (`did:web`).
    Web,
    /// The document is written to a verifiable data registry (a ledger, a directory).
    Registry,
}

impl Hosting {
    /// The lowercase name: `embedded`, `web` or `registry`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Embedded => "embedded",
            Self::Web => "web",
            Self::Registry => "registry",
        }
    }
}

impl fmt::Display for Hosting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a DID method can do, declared by its [`DidProducer`] so an application can pick a
/// method without knowing it.
///
/// # Examples
///
/// ```
/// use identity_kit::resolver::{Hosting, MethodCapabilities};
///
/// // did:jwk: one key, no updates, the method is always `#0`.
/// let jwk = MethodCapabilities::new(Hosting::Embedded)
///     .with_single_key(true)
///     .with_fixed_fragment("0");
/// assert!(!jwk.updatable);
/// assert_eq!(jwk.fixed_fragment, Some("0"));
///
/// // did:web: any number of keys, updated by republishing the document.
/// let web = MethodCapabilities::new(Hosting::Web).with_updatable(true);
/// assert!(web.updatable && !web.single_key && web.fixed_fragment.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MethodCapabilities {
    /// Whether a document can change after creation. An embedded method never can.
    pub updatable: bool,
    /// Where the documents live.
    pub hosting: Hosting,
    /// Whether a document holds exactly one verification method.
    pub single_key: bool,
    /// The fragment every verification method of the method is named with (`0` for `did:jwk`),
    /// or `None` when the fragment depends on the key or on the caller.
    pub fixed_fragment: Option<&'static str>,
}

impl MethodCapabilities {
    /// Capabilities of a method hosted as `hosting`: not updatable, any number of keys, no fixed
    /// fragment.
    pub const fn new(hosting: Hosting) -> Self {
        Self {
            updatable: false,
            hosting,
            single_key: false,
            fixed_fragment: None,
        }
    }

    /// These capabilities with `updatable` set.
    #[must_use]
    pub const fn with_updatable(mut self, updatable: bool) -> Self {
        self.updatable = updatable;
        self
    }

    /// These capabilities with `single_key` set.
    #[must_use]
    pub const fn with_single_key(mut self, single_key: bool) -> Self {
        self.single_key = single_key;
        self
    }

    /// These capabilities with `fixed_fragment` set.
    #[must_use]
    pub const fn with_fixed_fragment(mut self, fragment: &'static str) -> Self {
        self.fixed_fragment = Some(fragment);
        self
    }
}

/// Why a [`DidProducer`] could not produce a document.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProduceError {
    /// The method needs at least one key and got none.
    #[error("at least one key is required")]
    NoKeys,
    /// More keys than the method can hold in one document.
    #[error("at most {max} key(s) can be used, got {actual}")]
    TooManyKeys {
        /// How many keys the method accepts.
        max: usize,
        /// How many were given.
        actual: usize,
    },
    /// A key the method cannot represent: a private key, an unsupported key type, a malformed
    /// JWK.
    #[error("key {index} cannot be used: {reason}")]
    UnsupportedKey {
        /// The position of the key in the `keys` slice.
        index: usize,
        /// Why.
        reason: String,
    },
    /// The method-specific parameters are invalid.
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// The document could not be assembled.
    #[error(transparent)]
    Document(#[from] DocumentError),
    /// A failure of whatever the method writes to (a registry, a file).
    #[error("backend error: {0}")]
    Backend(#[source] Box<dyn Error + Send + Sync>),
}

impl ProduceError {
    /// [`ProduceError::Backend`] wrapping `error`.
    pub fn backend(error: impl Error + Send + Sync + 'static) -> Self {
        Self::Backend(Box::new(error))
    }
}

/// Produces the DID document of one method from public keys.
///
/// The keys are public JWKs, typically fetched from a [`KeyStore`]: producing a document never
/// touches private material. `Params` carries whatever the method needs beyond the keys: the
/// origin of a `did:web`, nothing (`()`) for an embedded method.
///
/// [`KeyStore`]: https://github.com/impierce/identity-kit/issues/8
#[async_trait::async_trait]
pub trait DidProducer: Send + Sync {
    /// Method-specific parameters.
    type Params: Send;

    /// The method name: `web` for `did:web`.
    fn method(&self) -> &'static str;

    /// What the method can do.
    fn capabilities(&self) -> MethodCapabilities;

    /// Produces the document for `keys`.
    ///
    /// The same keys and parameters produce the same document; for a method whose DID depends
    /// on the keys, the `id` of the document is that DID.
    ///
    /// # Errors
    ///
    /// A [`ProduceError`] when the keys or the parameters do not fit the method, or writing the
    /// document (a registry method) fails.
    async fn produce(
        &self,
        keys: &[Jwk],
        params: Self::Params,
    ) -> Result<DidDocument, ProduceError>;
}
