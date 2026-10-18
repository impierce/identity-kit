//! DID, key management and verifiable credential primitives.
//!
//! The crate is organised in two layers. The lower layer holds the DID data model ([`did`]), JOSE
//! keys and signatures ([`jose`]), key stores ([`keys`]), DID resolution and dereferencing
//! ([`resolver`]) and the `did:key`, `did:jwk` and `did:web` methods ([`methods`]). The upper
//! layer builds JWT-based verifiable credentials on top of it and never leaks back into the
//! lower layer.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod did;
pub mod jose;
pub mod keys;
#[cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web")))
)]
pub mod methods;
pub mod resolver;
