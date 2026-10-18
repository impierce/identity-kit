//! DID, key management and verifiable credential primitives.
//!
//! The crate is organised in two layers. The lower layer holds the DID data model ([`did`]), JOSE
//! keys and signatures ([`jose`]), key stores ([`keys`]), DID resolution and dereferencing
//! ([`resolver`]) and, as they land, DID methods. The upper layer builds JWT-based verifiable
//! credentials on top of it and never leaks back into the lower layer.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod did;
pub mod jose;
pub mod keys;
pub mod resolver;
