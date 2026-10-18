//! JSON Object Signing and Encryption: keys, algorithms, signature verification and the compact
//! JWS serialization.
//!
//! This is the crate's signature layer. Everything above it (DID documents, credentials) carries a
//! [`Jwk`] and a [`JwsAlgorithm`] and hands signing input to a [`JwsVerifier`] or a [`Signer`]:
//!
//! - [`Jwk`] is a JSON Web Key (RFC 7517), kept as the JSON it arrived as, with RFC 7638
//!   thumbprints, raw public key accessors for Ed25519, X25519, P-256 and secp256k1, and
//!   conversion to and from a Multikey string ([`Jwk::from_multikey`], [`Jwk::to_multikey`]).
//! - [`JwsAlgorithm`] names the asymmetric algorithms this crate speaks and converts to and from
//!   [`jsonwebtoken::Algorithm`].
//! - [`JwsVerifier`] verifies a signature over a signing input; [`DefaultVerifier`] does so with
//!   RustCrypto. ECDSA signatures are the raw `r || s` form JWS uses, never DER.
//! - [`CompactJws`] decodes a compact serialization without verifying it; [`encode_compact`]
//!   produces one with any [`Signer`], which is `async` because private keys live in key stores
//!   and HSMs.
//!
//! JWE is out of scope.
//!
//! # Cargo features
//!
//! - `secp256k1` (default): ES256K and secp256k1 keys, via `k256`.
//! - `rsa`: RS256 and PS256, via `rsa`.

mod algorithm;
pub(crate) mod base64url;
mod compact;
mod error;
mod jwk;
mod multikey;
mod verifier;

pub use algorithm::{JwsAlgorithm, UnknownAlgorithm};
pub use compact::{CompactJws, JwsHeader, Signer, encode_compact};
pub use error::{JwkError, JwsError, SignError, VerificationError};
pub use jwk::{Jwk, KeyType};
pub use multikey::KeyCodec;
pub use verifier::{DefaultVerifier, JwsVerifier};
