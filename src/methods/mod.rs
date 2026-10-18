//! DID methods: `did:key` ([`key`]), `did:jwk` ([`jwk`]) and `did:web` ([`web`]).
//!
//! Each method is a type implementing [`DidResolver`] and [`DidProducer`], registered with a
//! [`Resolver`] through [`ResolverBuilder::with`]; [`default_methods`] registers all three at
//! once. The methods are behind the `did-key`, `did-jwk` and `did-web` Cargo features, all on
//! by default; `did:web` needs an [`HttpClient`](web::HttpClient), and the `reqwest` feature
//! provides [`ReqwestClient`](web::ReqwestClient), a hardened default.
//!
//! # Examples
//!
//! ```
//! # #[cfg(all(feature = "did-key", feature = "did-jwk", feature = "reqwest"))]
//! # tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
//! use identity_kit::did::DidUrl;
//! use identity_kit::methods::web::ReqwestClient;
//!
//! let resolver = identity_kit::methods::default_methods(ReqwestClient::new()?).build();
//! assert_eq!(resolver.methods(), ["jwk", "key", "web"]);
//!
//! // Embedded methods need no network: the document is derived from the DID.
//! let key = DidUrl::parse(
//!     "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
//! )?;
//! let jwk = resolver.resolve_public_key(&key).await?;
//! assert_eq!(jwk.crv(), Some("Ed25519"));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # })?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#[cfg(feature = "did-jwk")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-jwk")))]
pub mod jwk;
#[cfg(feature = "did-key")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-key")))]
pub mod key;
#[cfg(feature = "did-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-web")))]
pub mod web;

#[cfg(feature = "did-jwk")]
pub use jwk::DidJwk;
#[cfg(feature = "did-key")]
pub use key::DidKey;
#[cfg(feature = "did-web")]
pub use web::DidWeb;

use crate::did::{
    APPLICATION_DID_JSON, APPLICATION_DID_LD_JSON, ResolutionError, ResolutionOptions,
};
#[cfg(any(feature = "did-key", feature = "did-jwk"))]
use crate::jose::Jwk;
#[cfg(any(feature = "did-key", feature = "did-jwk"))]
use crate::resolver::ProduceError;
#[allow(unused_imports)]
use crate::resolver::{DidProducer, DidResolver, Resolver, ResolverBuilder};

/// A [`ResolverBuilder`] with every method this crate ships registered, with their defaults:
/// `did:key` ([`DidKey`]), `did:jwk` ([`DidJwk`]) and `did:web` over `http`.
///
/// Register a configured method afterwards to replace a default, and add a cache with
/// [`ResolverBuilder::cache`] before [`build`](ResolverBuilder::build).
#[cfg(feature = "did-web")]
#[cfg_attr(docsrs, doc(cfg(feature = "did-web")))]
pub fn default_methods(http: impl web::HttpClient + 'static) -> ResolverBuilder {
    let builder = Resolver::builder();
    #[cfg(feature = "did-key")]
    let builder = builder.with(DidKey::default());
    #[cfg(feature = "did-jwk")]
    let builder = builder.with(DidJwk);
    builder.with(DidWeb::new(http))
}

/// The one key an embedded method takes.
#[cfg(any(feature = "did-key", feature = "did-jwk"))]
fn single_key(keys: &[Jwk]) -> Result<&Jwk, ProduceError> {
    match keys {
        [] => Err(ProduceError::NoKeys),
        [key] => Ok(key),
        _ => Err(ProduceError::TooManyKeys {
            max: 1,
            actual: keys.len(),
        }),
    }
}

/// The media types a method of this crate can serve, which are all the JSON ones.
const JSON_MEDIA_TYPES: [&str; 3] = [
    APPLICATION_DID_JSON,
    APPLICATION_DID_LD_JSON,
    "application/json",
];

/// Refuses an `accept` option asking for anything but a JSON representation.
fn check_accept(options: &ResolutionOptions) -> Result<(), ResolutionError> {
    match options.accept.as_deref() {
        None => Ok(()),
        Some(accept) if JSON_MEDIA_TYPES.contains(&accept) => Ok(()),
        Some(_) => Err(ResolutionError::RepresentationNotSupported),
    }
}
