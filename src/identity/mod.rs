//! The signing party: which identifiers it controls and the keys that sign for them.
//!
//! Every protocol that signs on behalf of a party needs the same three things: an identifier for
//! `iss` or `sub`, a `kid` for the header and a [`Signer`]. Which identifier depends on what the
//! other side accepts, a DID of some method or the RFC 7638 thumbprint of a bare key, and on the
//! algorithm both sides agreed on. The protocol negotiates that pair (SIOPv2 matches
//! `subject_syntax_types_supported` against what the wallet offers, OID4VCI the
//! `proof_signing_alg_values_supported`), using [`Identity::capabilities`] for the identity's
//! side; the identity then answers for the chosen pair:
//!
//! - [`Identity::identifier`]: the `iss`/`sub` value, a [`Did`] or a thumbprint;
//! - [`Identity::public_jwk`]: the public key, for `cnf.jwk`, `sub_jwk` or a `jwk` header;
//! - [`Identity::signer`]: a [`Signer`] whose [`kid`](Signer::kid) is the absolute DID URL of the
//!   verification method for a DID, and `None` for a thumbprint, where the caller puts the
//!   public key in the header instead.
//!
//! All three name the same key for the same pair. A party may hold a key per algorithm for one
//! kind, so the identifier takes the algorithm too: a `did:key`, a `did:jwk` or a thumbprint is
//! derived from the key and differs between them.
//!
//! [`KeyStoreIdentity`] is the implementation the crate ships, over any [`KeyStore`] and the
//! [`DidProducer`]s registered with it. There is no hook for an external signer: a remote or
//! hardware signer is a [`KeyStore`] (ADR 0006).
//!
//! # Examples
//!
//! ```
//! # #[cfg(all(feature = "in-memory", feature = "did-key"))]
//! # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
//! use std::sync::Arc;
//!
//! use identity_kit::did::{DidMethod, VerificationRelationship};
//! use identity_kit::identity::{Identity, IdentityKind, KeyStoreIdentity};
//! use identity_kit::jose::{CompactJws, DefaultVerifier, JwsAlgorithm, JwsHeader, KeyType, encode_compact};
//! use identity_kit::keys::{InMemoryKeyStore, KeySpec, KeyStore};
//! use identity_kit::methods::DidKey;
//! use identity_kit::resolver::Resolver;
//!
//! let store = Arc::new(InMemoryKeyStore::new());
//! let key = store.generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA)).await?;
//! let identity = KeyStoreIdentity::new(store).with_producer(DidKey::default());
//!
//! // The protocol settled on did:key and EdDSA.
//! let kind = IdentityKind::Did(DidMethod::new("key")?);
//! let did = identity.bind(kind.clone(), JwsAlgorithm::EdDSA, key).await?;
//! assert!(did.to_string().starts_with("did:key:z6Mk"));
//!
//! let signer = identity.signer(&kind, JwsAlgorithm::EdDSA).await?;
//! let kid = signer.kid().expect("a DID signer names its verification method");
//! let header = JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(kid);
//! let token = encode_compact(&header, br#"{"iss":"me"}"#, &*signer).await?;
//!
//! // A verifier finds the key through the DID in `kid`.
//! let resolver = Resolver::builder().with(DidKey::default()).build();
//! let url = kid.parse()?;
//! let key = resolver
//!     .resolve_public_key(&url, Some(VerificationRelationship::AssertionMethod))
//!     .await?;
//! CompactJws::decode(&token)?.verify(&DefaultVerifier, &key)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`KeyStore`]: crate::keys::KeyStore
//! [`DidProducer`]: crate::resolver::DidProducer

use core::fmt;
use std::sync::Arc;

use crate::did::{Did, DidMethod};
use crate::jose::{Jwk, JwkError, JwsAlgorithm, Signer};
use crate::keys::KeyStoreError;
use crate::resolver::ProduceError;

mod key_store;

pub use key_store::KeyStoreIdentity;

/// The kind of identifier the other side accepts.
///
/// # Examples
///
/// ```
/// use identity_kit::did::DidMethod;
/// use identity_kit::identity::IdentityKind;
///
/// let kind = IdentityKind::Did(DidMethod::new("key")?);
/// assert_eq!(kind.to_string(), "did:key");
/// assert_eq!(IdentityKind::JwkThumbprint.to_string(), "JWK thumbprint");
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentityKind {
    /// A DID of this method, and of its namespace when the [`DidMethod`] has one.
    Did(DidMethod),
    /// The RFC 7638 SHA-256 thumbprint of the public key, as SIOPv2 self-issued ID tokens and
    /// key binding with `cnf.jwk` use it.
    JwkThumbprint,
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Did(method) => fmt::Display::fmt(method, f),
            Self::JwkThumbprint => f.write_str("JWK thumbprint"),
        }
    }
}

/// The identifier of an [`Identity`] for one kind and algorithm; [`Display`](fmt::Display) gives
/// the `iss` or `sub` value.
///
/// # Examples
///
/// ```
/// use identity_kit::did::Did;
/// use identity_kit::identity::Identifier;
///
/// let did = Identifier::Did(Did::parse("did:example:123")?);
/// assert_eq!(did.to_string(), "did:example:123");
/// assert!(did.as_did().is_some());
///
/// // RFC 7638 §3.1.
/// let thumbprint = Identifier::JwkThumbprint("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".into());
/// assert_eq!(thumbprint.to_string(), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
/// assert!(thumbprint.as_did().is_none());
/// # Ok::<(), identity_kit::did::DidError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Identifier {
    /// A DID.
    Did(Did),
    /// The RFC 7638 SHA-256 thumbprint of the public key, base64url without padding.
    JwkThumbprint(String),
}

impl Identifier {
    /// The DID, if this is one.
    pub fn as_did(&self) -> Option<&Did> {
        match self {
            Self::Did(did) => Some(did),
            Self::JwkThumbprint(_) => None,
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Did(did) => fmt::Display::fmt(did, f),
            Self::JwkThumbprint(thumbprint) => f.write_str(thumbprint),
        }
    }
}

/// Why an [`Identity`] cannot answer for a kind and algorithm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// The identity has no identifier of this kind: no key is bound to it, or nothing can
    /// produce a DID of the method (and namespace).
    #[error("no identifier of kind {0}")]
    UnsupportedKind(IdentityKind),
    /// The identity has an identifier of the kind, but no key for this algorithm, or the key
    /// store cannot sign with it.
    #[error("no key for algorithm {0}")]
    UnsupportedAlgorithm(JwsAlgorithm),
    /// The document a producer made for the key has no verification method to name in `kid`.
    #[error("the document of {0} has no verification method")]
    NoVerificationMethod(Did),
    /// The key store failed, or refused the key for the algorithm.
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),
    /// The DID producer failed.
    #[error(transparent)]
    Produce(#[from] ProduceError),
    /// The thumbprint of the public key could not be computed.
    #[error(transparent)]
    Jwk(#[from] JwkError),
}

/// A party that signs: the identifiers it controls and the keys behind them.
///
/// See the [module documentation](self) for how a protocol uses it. Every method answers for a
/// `(kind, alg)` pair; for one pair, [`identifier`](Identity::identifier),
/// [`public_jwk`](Identity::public_jwk) and [`signer`](Identity::signer) name the same key.
#[async_trait::async_trait]
pub trait Identity: Send + Sync {
    /// The `(kind, alg)` pairs this identity can sign for, for negotiation.
    fn capabilities(&self) -> Vec<(IdentityKind, JwsAlgorithm)>;

    /// The identifier for `(kind, alg)`. A thumbprint, a `did:key` or a `did:jwk` is derived from
    /// the key bound to the pair, so it names the same key as
    /// [`public_jwk`](Identity::public_jwk) and [`signer`](Identity::signer) only for the same
    /// pair.
    ///
    /// # Errors
    ///
    /// [`IdentityError::UnsupportedKind`] or [`IdentityError::UnsupportedAlgorithm`] when the
    /// identity cannot answer for the pair, and whatever producing the identifier reports.
    async fn identifier(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Identifier, IdentityError>;

    /// The public key that [`signer(kind, alg)`](Identity::signer) signs with, for `cnf.jwk`,
    /// `sub_jwk` or a `jwk` header.
    ///
    /// # Errors
    ///
    /// As [`identifier`](Identity::identifier).
    async fn public_jwk(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Jwk, IdentityError>;

    /// A signer for `(kind, alg)`. For [`IdentityKind::Did`], [`Signer::kid`] is the absolute
    /// DID URL of the verification method; for [`IdentityKind::JwkThumbprint`] it is `None` and
    /// the caller puts [`public_jwk`](Identity::public_jwk) in the header.
    ///
    /// # Errors
    ///
    /// As [`identifier`](Identity::identifier).
    async fn signer(
        &self,
        kind: &IdentityKind,
        alg: JwsAlgorithm,
    ) -> Result<Box<dyn Signer + '_>, IdentityError>;
}

// Implements `Identity` for `&T`, `Box<T>` and `Arc<T>` by forwarding every method to `T`.
// A method added to the trait is added here too: one with a default body would still compile
// if left out, and calls through these wrappers would then run the default, not `T`'s
// override. `clippy::missing_trait_methods` turns that omission into an error.
macro_rules! forward_identity {
    ($($ty:ty),* $(,)?) => {
        $(
            #[async_trait::async_trait]
            #[deny(clippy::missing_trait_methods)]
            impl<T: Identity + ?Sized> Identity for $ty {
                fn capabilities(&self) -> Vec<(IdentityKind, JwsAlgorithm)> {
                    (**self).capabilities()
                }

                async fn identifier(
                    &self,
                    kind: &IdentityKind,
                    alg: JwsAlgorithm,
                ) -> Result<Identifier, IdentityError> {
                    (**self).identifier(kind, alg).await
                }

                async fn public_jwk(
                    &self,
                    kind: &IdentityKind,
                    alg: JwsAlgorithm,
                ) -> Result<Jwk, IdentityError> {
                    (**self).public_jwk(kind, alg).await
                }

                async fn signer(
                    &self,
                    kind: &IdentityKind,
                    alg: JwsAlgorithm,
                ) -> Result<Box<dyn Signer + '_>, IdentityError> {
                    (**self).signer(kind, alg).await
                }
            }
        )*
    };
}

forward_identity!(&T, Box<T>, Arc<T>);
