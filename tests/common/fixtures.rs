//! The parties, resolvers and instants the credential tests share: an issuer of the RFC 8037
//! key behind `did:key` and a holder of the RFC 7515 A.3 key behind `did:jwk`.

#[cfg(feature = "vc")]
use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{Did, DidUrl};
use identity_kit::jose::Jwk;
#[cfg(feature = "did-jwk")]
use identity_kit::methods::DidJwk;
#[cfg(feature = "did-key")]
use identity_kit::methods::DidKey;
#[cfg(all(feature = "did-key", feature = "did-jwk"))]
use identity_kit::resolver::Resolver;
use identity_kit::resolver::{KeyReference, KeyResolutionError, KeyResolver, KeyRole};

use super::{Ed25519Signer, Es256Signer};

/// The audience and nonce a verifier asks a holder to bind a presentation to.
pub(crate) const AUDIENCE: &str = "did:example:verifier";
pub(crate) const NONCE: &str = "n-0S6_WzA2Mj";

/// A DID, the verification method its tokens name as `kid`, and the signer of that key.
pub(crate) struct Party<S> {
    pub(crate) did: Did,
    pub(crate) kid: DidUrl,
    pub(crate) signer: S,
}

/// The [`issuer`].
pub(crate) type Issuer = Party<Ed25519Signer>;

/// The [`holder`].
pub(crate) type Holder = Party<Es256Signer>;

/// The issuer: `did:key` of the RFC 8037 key, whose one verification method is named after the
/// key.
#[cfg(feature = "did-key")]
pub(crate) fn issuer() -> Party<Ed25519Signer> {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    Party { did, kid, signer }
}

/// The holder: `did:jwk` of the RFC 7515 A.3 key, whose verification method is `#0`.
#[cfg(feature = "did-jwk")]
pub(crate) fn holder() -> Party<Es256Signer> {
    let signer = Es256Signer::rfc7515_a3();
    let did = DidJwk::did(&signer.public_jwk()).unwrap();
    let kid = did.join("#0").unwrap();
    Party { did, kid, signer }
}

/// Resolves the issuer's and the holder's DIDs.
#[cfg(all(feature = "did-key", feature = "did-jwk"))]
pub(crate) fn resolver() -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build()
}

/// A key resolver that finds no key for `role` and asks `inner` for the others, as for a DID
/// document listing the key under one verification relationship only.
pub(crate) struct RefusingRole<R> {
    pub(crate) inner: R,
    pub(crate) role: KeyRole,
}

#[async_trait::async_trait]
impl<R: KeyResolver> KeyResolver for RefusingRole<R> {
    async fn resolve_key(
        &self,
        key: &KeyReference,
        role: KeyRole,
    ) -> Result<Jwk, KeyResolutionError> {
        if role == self.role {
            return Err(KeyResolutionError::msg(match role {
                KeyRole::Subject => "not under `authentication`",
                _ => "not under `assertionMethod`",
            }));
        }
        self.inner.resolve_key(key, role).await
    }
}

/// A validation time inside [`issued_at`] to [`expires_at`].
#[cfg(feature = "vc")]
pub(crate) fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
}

/// The `iat` of RFC 9901's examples.
#[cfg(feature = "vc")]
pub(crate) fn issued_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_683_000_000, 0).unwrap()
}

/// The `exp` of RFC 9901's examples.
#[cfg(feature = "vc")]
pub(crate) fn expires_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_883_000_000, 0).unwrap()
}
