//! DID, key management and verifiable credential primitives.
//!
//! The crate is organised in two layers. The lower layer holds the DID data model ([`did`]) and,
//! as they land, JOSE, key stores, resolution and DID methods. The upper layer builds JWT-based
//! verifiable credentials on top of it and never leaks back into the lower layer.

pub mod did;
