//! DID, key management and verifiable credential primitives.
//!
//! The crate is organised in two layers. The lower layer holds the DID data model ([`did`]), JOSE
//! keys and signatures ([`jose`]), key stores ([`keys`]), the signing party ([`identity`]), DID
//! resolution and dereferencing ([`resolver`]) and the `did:key`, `did:jwk` and `did:web`
//! methods ([`methods`]). The upper layer builds JWT-based verifiable credentials and
//! presentations on top of it ([`vc`]), SD-JWT verifiable credentials ([`sd_jwt_vc`]), the DIF
//! Well Known DID Configuration ([`domain_linkage`]) and DIF Linked Verifiable Presentations
//! ([`linked_vp`]), and never leaks back into the lower layer. [`prelude`] gathers the common
//! types of the lower layer, [`prelude::credentials`] those of the upper layer.
//!
//! # Cargo features
//!
//! All features are additive. The default set enables both layers over software keys and the
//! three DID methods; `--no-default-features` leaves the lower layer with the in-crate
//! parsers and verifiers only. The complete list, with what each feature pulls in, is in the
//! crate's `docs/DESIGN.md`; the ones that add surface rather than enable a module:
//!
//! - `utoipa`: OpenAPI schemas ([`utoipa::ToSchema`]) for [`DidDocument`](did::DidDocument),
//!   [`VerificationMethod`](did::VerificationMethod), [`Service`](did::Service),
//!   [`Jwk`](jose::Jwk), `DomainLinkageConfiguration` and `TypeMetadata`.
//! - `test-vectors`: [`keys::testsuite`], the behavioural suite every key store must pass, and
//!   [`vectors`], the specification vectors the tests of this crate run against.
#![cfg_attr(docsrs, feature(doc_cfg))]

mod cause;
pub mod did;
#[cfg(feature = "domain-linkage")]
#[cfg_attr(docsrs, doc(cfg(feature = "domain-linkage")))]
pub mod domain_linkage;
pub mod identity;
pub mod jose;
pub mod keys;
#[cfg(feature = "linked-vp")]
#[cfg_attr(docsrs, doc(cfg(feature = "linked-vp")))]
pub mod linked_vp;
#[cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "did-key", feature = "did-jwk", feature = "did-web")))
)]
pub mod methods;
#[cfg(feature = "utoipa")]
mod openapi;
pub mod prelude;
pub mod resolver;
#[cfg(feature = "sd-jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "sd-jwt")))]
pub mod sd_jwt_vc;
#[cfg(feature = "vc")]
#[cfg_attr(docsrs, doc(cfg(feature = "vc")))]
pub mod vc;
#[cfg(feature = "test-vectors")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-vectors")))]
pub mod vectors;
