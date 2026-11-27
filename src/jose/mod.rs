//! JSON Object Signing and Encryption: keys, algorithms, signature verification, the compact
//! JWS serialization and, with `jwe`, the compact JWE serialization.
//!
//! This is the crate's signature layer. Everything above it (DID documents, credentials) carries a
//! [`Jwk`] and a [`JwsAlgorithm`] and hands signing input to a [`JwsVerifier`] or a [`Signer`]:
//!
//! - [`Jwk`] is a JSON Web Key (RFC 7517), kept as the JSON it arrived as, with RFC 7638
//!   thumbprints, raw public key accessors for Ed25519, X25519, P-256 and secp256k1, and
//!   conversion to and from a Multikey string ([`Jwk::from_multikey`], [`Jwk::to_multikey`]). An
//!   `AKP` key (RFC 9964) holds an ML-DSA key, its parameter set named by `alg`.
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
//! - [`ml_dsa_external_mu`] computes the 64-byte μ that an HSM or a cloud KMS signs for an
//!   ML-DSA key in place of a JWS signing input too long for it.
//! - [`JwtClaims`] is a JWT claims set (RFC 7519): the registered claims as fields, `aud` as a
//!   [`OneOrMany`], times as `NumericDate` seconds, every other claim kept in order.
//!   [`CompactJws::claims`] reads a payload as one, unverified; `JwtValidator` of
//!   [`resolver`](crate::resolver) validates one, its signer's key resolved by a `KeyResolver`.
//!
//! - With the `jwe` feature, [`CompactJwe`] decodes, encrypts and decrypts a compact JWE with
//!   ECDH-ES on P-256 and AES-GCM, what the OpenID4VC High Assurance Interoperability Profile
//!   requires of an encrypted response, and nothing more (ADR 0009). [`EcdhKey`] is the
//!   Verifier's per-request key; [`JweDecrypter`] lets a key kept elsewhere decrypt.
//!
//! # Cargo features
//!
//! - `secp256k1` (default): ES256K and secp256k1 keys, via `k256`.
//! - `ml-dsa` (default): ML-DSA-44, ML-DSA-65 and ML-DSA-87 (RFC 9964), via `ml-dsa`. Without
//!   it the algorithms and `AKP` keys still parse, print and have thumbprints, but do not verify.
//! - `jwe`: [`CompactJwe`] and its types, via `aes-gcm` and `p256`'s ECDH.
//! - `rsa`: RS256 and PS256, via `rsa`, with keys of at least 2048 bits (RFC 7518 §3.3,
//!   §3.5).

mod algorithm;
pub(crate) mod base64url;
mod claims;
mod compact;
mod ecdsa;
mod error;
#[cfg(feature = "jwe")]
mod jwe;
mod jwk;
pub(crate) mod ml_dsa;
mod multikey;
mod one_or_many;
mod pkcs1;
mod verifier;

pub use algorithm::{JwsAlgorithm, UnknownAlgorithm};
pub use claims::JwtClaims;
#[cfg(feature = "status-list")]
pub(crate) use claims::numeric_date;
pub use compact::{CertifiedSigner, CompactJws, JwsHeader, Signer, encode_compact};
pub use ecdsa::{ecdsa_signature_from_der, normalize_ecdsa_signature};
pub use error::{EcdsaSignatureError, JwkError, JwsError, SignError, VerificationError};
#[cfg(feature = "jwe")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwe")))]
pub use jwe::{
    CompactJwe, EcdhKey, JweAlgorithm, JweDecrypter, JweEncryption, JweError, JweHeader,
};
pub use jwk::{Jwk, KeyType};
pub use ml_dsa::ml_dsa_external_mu;
pub use multikey::KeyCodec;
pub use one_or_many::OneOrMany;
pub use verifier::{DefaultVerifier, JwsVerifier};
