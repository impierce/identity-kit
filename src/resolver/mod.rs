//! DID resolution and production: the [`DidResolver`] and [`DidProducer`] traits a DID method
//! implements, the [`Resolver`] registry that routes a DID to the resolver of its method, an
//! optional TTL [`DocumentCache`], and DID URL dereferencing.
//!
//! The module ships no DID method. Each method is a type implementing [`DidResolver`] and/or
//! [`DidProducer`], registered with [`ResolverBuilder::with`]; adding one needs no change here.
//!
//! # Resolution
//!
//! [`Resolver::resolve`] implements the DID Resolution algorithm around the method's resolver:
//! it reports [`ResolutionError::MethodNotSupported`] for a method nobody registered, turns a
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
//! # Examples
//!
//! A method is a type implementing [`DidResolver`]; here one that serves documents from memory.
//!
//! ```
//! use std::collections::HashMap;
//!
//! use identity_kit::did::{
//!     Did, DidDocument, DidUrl, ResolutionError, ResolutionOptions, ResolutionResult,
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
//!         self.0
//!             .get(did)
//!             .cloned()
//!             .map(ResolutionResult::new)
//!             .ok_or(ResolutionError::NotFound)
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
//! assert_eq!(
//!     resolver.resolve(&unknown).await.unwrap_err(),
//!     ResolutionError::MethodNotSupported
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::sync::Arc;

use crate::did::{Did, ResolutionError, ResolutionOptions, ResolutionResult};

mod cache;
mod dereference;
mod producer;
mod registry;

pub use cache::DocumentCache;
pub use dereference::{DereferenceError, Dereferenced};
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
    /// A [`ResolutionError`]: [`NotFound`](ResolutionError::NotFound) for a DID that does not
    /// exist, [`RepresentationNotSupported`](ResolutionError::RepresentationNotSupported) for an
    /// `accept` the method cannot produce, [`InternalError`](ResolutionError::InternalError) for
    /// an unexpected failure such as a network error.
    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError>;
}

macro_rules! forward_did_resolver {
    ($($ty:ty),* $(,)?) => {$(
        #[async_trait::async_trait]
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
