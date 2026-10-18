//! DID, key management and verifiable credential primitives.
//!
//! The crate is organised in two layers. The lower layer holds the DID data model ([`did`]), JOSE
//! keys and signatures ([`jose`]), key stores ([`keys`]), DID resolution and dereferencing
//! ([`resolver`]) and the `did:key`, `did:jwk` and `did:web` methods ([`methods`]). The upper
//! layer builds JWT-based verifiable credentials and presentations on top of it ([`vc`]),
//! SD-JWT verifiable credentials ([`sd_jwt_vc`]) and the DIF Well Known DID Configuration
//! ([`domain_linkage`]), and never leaks back into the lower layer.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod did;
#[cfg(feature = "domain-linkage")]
#[cfg_attr(docsrs, doc(cfg(feature = "domain-linkage")))]
pub mod domain_linkage;
pub mod jose;
pub mod keys;
#[cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web")))
)]
pub mod methods;
pub mod resolver;
#[cfg(feature = "sd-jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
pub mod sd_jwt_vc;
#[cfg(feature = "vc")]
#[cfg_attr(docsrs, doc(cfg(feature = "vc")))]
pub mod vc;
