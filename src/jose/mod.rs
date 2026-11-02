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
//!   RustCrypto. ECDSA signatures are the raw `r || s` form JWS uses, never DER. An ES256
//!   signature verifies with `s` and `n - s` alike, so identify a token by its claims, not its
//!   bytes (see [`DefaultVerifier`]).
//! - [`CompactJws`] decodes a compact serialization without verifying it; [`encode_compact`]
//!   produces one with any [`Signer`], which is `async` because private keys live in key stores
//!   and HSMs.
//! - [`ecdsa_signature_from_der`] and [`normalize_ecdsa_signature`] turn what an HSM or a cloud
//!   KMS returns for an ECDSA key into the JWS form: raw `r || s`, with a secp256k1 `s` in the
//!   lower half of the group order.
//! - [`JwtClaims`] is a JWT claims set (RFC 7519): the registered claims as fields, `aud` as a
//!   [`OneOrMany`], times as `NumericDate` seconds, every other claim kept in order.
//!   [`CompactJws::claims`] reads a payload as one, unverified; `JwtValidator` of
//!   [`resolver`](crate::resolver) validates one, its signer's key resolved by a `KeyResolver`.
//!
//! JWE is out of scope.
//!
//! # Cargo features
//!
//! - `secp256k1` (default): ES256K and secp256k1 keys, via `k256`.
//! - `rsa`: RS256 and PS256, via `rsa`, with keys of at least 2048 bits (RFC 7518 §3.3,
//!   §3.5).

mod algorithm;
pub(crate) mod base64url;
mod claims;
mod compact;
mod ecdsa;
mod error;
mod jwk;
mod multikey;
mod one_or_many;
mod pkcs1;
mod verifier;

pub use algorithm::{JwsAlgorithm, UnknownAlgorithm};
pub use claims::JwtClaims;
#[cfg(feature = "status-list")]
pub(crate) use claims::numeric_date;
pub use compact::{CompactJws, JwsHeader, Signer, encode_compact};
pub use ecdsa::{ecdsa_signature_from_der, normalize_ecdsa_signature};
pub use error::{EcdsaSignatureError, JwkError, JwsError, SignError, VerificationError};
pub use jwk::{Jwk, KeyType};
pub use multikey::KeyCodec;
pub use one_or_many::OneOrMany;
pub use verifier::{DefaultVerifier, JwsVerifier};
