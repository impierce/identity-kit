//! DID resolution and production: the [`DidResolver`] and [`DidProducer`] traits a DID method
//! implements, the [`Resolver`] registry that routes a DID to the resolver of its method, an
//! optional TTL [`DocumentCache`], and DID URL dereferencing. Beside DIDs, finding the key a
//! token was signed with: [`KeyReference`] and [`KeyResolver`].
//!
//! The module ships no DID method. Each method is a type implementing [`DidResolver`] and/or
//! [`DidProducer`], registered with [`ResolverBuilder::with`]; adding one needs no change here.
//!
//! # Resolution
//!
//! [`Resolver::resolve`] implements the DID Resolution algorithm around the method's resolver:
//! it reports [`ResolutionErrorKind::MethodNotSupported`] for a method nobody registered, turns a
//! result whose metadata reports an error into `Err`, refuses a document whose `id` is not the
//! DID being resolved (nor its `canonicalId`), and serves repeated resolutions from the cache
//! when one is configured. [`Resolver::resolve_document`] is the shortcut to the document.
//!
//! # Dereferencing
//!
//! [`Resolver::dereference`] resolves the DID of a DID URL and then selects the resource the URL
//! names: the document itself, or the verification method or service whose `id` is the URL
//! ([`Dereferenced`]). The `versionId` and `versionTime` DID parameters are passed to the
//! method's resolver as resolution options; a path, any other query parameter and the
//! `service`/`relativeRef` parameters are method-specific and reported as
//! [`DereferenceError::MethodSpecific`]. [`Resolver::resolve_public_key`] goes one step further
//! and returns the [`Jwk`](crate::jose::Jwk) of a verification method, optionally checked to be
//! usable for a verification relationship, decoding `publicKeyMultibase` material as a Multikey,
//! which is what a JWS verifier needs.
//!
//! # Key references
//!
//! A JWT names the key that signed it in one of several ways (ADR 0006), and
//! [`KeyReference::from_jws`] reads which, in this order: a `kid` that is a DID URL
//! (`did:…#fragment`, without a path or DID parameters); a `kid` that is a `#fragment`, joined
//! with a DID `iss`; another `kid` with an HTTPS `iss`, naming a key of the issuer's key set; the
//! key itself in a `jwk` header; an `x5c` certificate chain; a `jku` key set URL. A
//! [`KeyResolver`] turns the reference into a key for a [`KeyRole`], the issuer's
//! (`assertionMethod` in a DID document) or the subject's (`authentication`):
//!
//! | Reference | Resolved by |
//! |---|---|
//! | [`KeyReference::DidUrl`] | [`Resolver`], dereferencing the verification method |
//! | [`KeyReference::Jwk`] | [`JwkResolver`], the key itself |
//! | [`KeyReference::Jwks`] | `JwksResolver` (feature `jwks`), the JWT VC issuer metadata of the issuer |
//! | [`KeyReference::X509Chain`], [`KeyReference::Jku`] | nothing in the crate yet; an application's own [`KeyResolver`] |
//!
//! [`CompositeKeyResolver`] tries several in order. Resolving says nothing about trust: after
//! the signature verifies, [`KeyReference::binds_to`] checks that the key belongs to the party
//! the token claims, which the validators of the upper layer do.
//!
//! # Plain JWTs
//!
//! [`JwtValidator`] validates a JWT that is neither a credential nor a presentation, an OAuth
//! 2.0 access token say, as RFC 7519 §7.2 and RFC 8725 describe: an allowed `alg`, the
//! expected `typ`, the signature under the key a [`KeyResolver`] finds, that key bound to
//! `iss` ([`IssuerBinding`]), the expected `iss` and `aud`, `exp`, `nbf` and `iat` within a
//! leeway, and the claims the [`JwtValidationOptions`] require.
//!
//! # Examples
//!
//! A method is a type implementing [`DidResolver`]; here one that serves documents from memory.
//!
//! ```
//! use std::collections::HashMap;
//!
//! use identity_kit::did::{
//!     Did, DidDocument, DidUrl, ResolutionError, ResolutionErrorKind, ResolutionOptions,
//!     ResolutionResult,
//! };
//! use identity_kit::resolver::{Dereferenced, DidResolver, Resolver};
//!
//! struct Static(HashMap<Did, DidDocument>);
//!
//! #[async_trait::async_trait]
//! impl DidResolver for Static {
//!     fn method(&self) -> &'static str {
//!         "example"
//!     }
//!
//!     async fn resolve(
//!         &self,
//!         did: &Did,
//!         _: &ResolutionOptions,
//!     ) -> Result<ResolutionResult, ResolutionError> {
//!         self.0.get(did).cloned().map(ResolutionResult::new).ok_or_else(|| {
//!             ResolutionError::new(ResolutionErrorKind::NotFound)
//!                 .with_detail(format!("no document is stored for `{did}`"))
//!         })
//!     }
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
//! let document: DidDocument = serde_json::from_str(r##"{
//!   "id": "did:example:123",
//!   "verificationMethod": [{
//!     "id": "did:example:123#key-1",
//!     "type": "JsonWebKey2020",
//!     "controller": "did:example:123",
//!     "publicKeyJwk": {
//!       "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
//!     }
//!   }],
//!   "authentication": ["#key-1"]
//! }"##)?;
//! let did = document.id.clone();
//! let resolver = Resolver::builder()
//!     .with(Static(HashMap::from([(did.clone(), document)])))
//!     .cache(std::time::Duration::from_secs(60))
//!     .build();
//!
//! assert_eq!(resolver.resolve_document(&did).await?.id, did);
//!
//! let key = DidUrl::parse("did:example:123#key-1")?;
//! let jwk = resolver.resolve_public_key(&key, None).await?;
//! assert_eq!(jwk.crv(), Some("Ed25519"));
//! assert!(matches!(resolver.dereference(&key).await?, Dereferenced::VerificationMethod(_)));
//!
//! let unknown = Did::parse("did:other:123")?;
//! let error = resolver.resolve(&unknown).await.unwrap_err();
//! assert_eq!(error, ResolutionErrorKind::MethodNotSupported);
//! assert_eq!(error.detail(), Some("no resolver is registered for `did:other`"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::sync::Arc;

#[cfg(doc)]
use crate::did::ResolutionErrorKind;
use crate::did::{Did, ResolutionError, ResolutionOptions, ResolutionResult};

mod cache;
mod dereference;
#[cfg(feature = "jwks")]
mod jwks;
mod jwt;
mod key;
mod producer;
mod registry;

pub use cache::DocumentCache;
pub use dereference::{DereferenceError, Dereferenced};
#[cfg(feature = "jwks")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwks")))]
pub use jwks::{JwksError, JwksResolver};
pub use jwt::{
    IssuerBinding, JwtValidationError, JwtValidationOptions, JwtValidator, ValidatedJwt,
};
pub use key::{
    CompositeKeyResolver, JwkResolver, KeyReference, KeyReferenceError, KeyResolutionError,
    KeyResolver, KeyRole,
};
pub use producer::{DidProducer, Hosting, MethodCapabilities, ProduceError};
pub use registry::{Resolver, ResolverBuilder};

/// Resolves the DIDs of one method (DID Resolution "DID Resolution Algorithm").
///
/// A resolver is registered with a [`Resolver`] under [`method`](Self::method) and receives
/// only DIDs of that method. It is `Send + Sync` and resolution is `async` because most methods
/// fetch the document over the network or from a registry.
///
/// A failed resolution may be reported either as `Err`, or as an `Ok` result whose resolution
/// metadata carries the error, which is the shape a method that builds a full
/// [`ResolutionResult`] (a client of a remote resolver, say) produces anyway. The [`Resolver`]
/// normalizes both to `Err`.
#[async_trait::async_trait]
pub trait DidResolver: Send + Sync {
    /// The method name this resolver handles: `web` for `did:web`.
    fn method(&self) -> &'static str;

    /// Resolves `did`, whose method is [`method`](Self::method), with `options`.
    ///
    /// On success the result holds the document with `id` equal to `did` (or to the
    /// `canonicalId` of the document metadata) and whatever metadata the method knows. A
    /// deactivated DID resolves to a result without a document whose document metadata has
    /// `deactivated: true`.
    ///
    /// # Errors
    ///
    /// A [`ResolutionError`] whose kind is [`NotFound`](ResolutionErrorKind::NotFound) for a DID
    /// that does not exist,
    /// [`RepresentationNotSupported`](ResolutionErrorKind::RepresentationNotSupported) for an
    /// `accept` the method cannot produce, or [`InternalError`](ResolutionErrorKind::InternalError)
    /// for an unexpected failure such as a network error. Attach what caused it with
    /// [`ResolutionError::with_source`] and [`ResolutionError::with_detail`], so callers can tell
    /// one failure from another.
    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError>;
}

// Implements `DidResolver` for `&T`, `Box<T>` and `Arc<T>` by forwarding every method to `T`.
// A method added to the trait is added here too: one with a default body would still compile
// if left out, and calls through these wrappers would then run the default, not `T`'s
// override. `clippy::missing_trait_methods` turns that omission into an error.
macro_rules! forward_did_resolver {
    ($($ty:ty),* $(,)?) => {$(
        #[async_trait::async_trait]
        #[deny(clippy::missing_trait_methods)]
        impl<T: DidResolver + ?Sized> DidResolver for $ty {
            fn method(&self) -> &'static str {
                (**self).method()
            }

            async fn resolve(
                &self,
                did: &Did,
                options: &ResolutionOptions,
            ) -> Result<ResolutionResult, ResolutionError> {
                (**self).resolve(did, options).await
            }
        }
    )*};
}

forward_did_resolver!(&T, Box<T>, Arc<T>);
