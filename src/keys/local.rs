//! Keys held in process, shared by the in-memory and the software store: generation from random
//! bytes, loading from a private JWK, signing.

#[cfg(feature = "in-memory")]
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "software")]
use std::error::Error;

use super::{KeyId, KeySpec, KeyStoreError};
#[cfg(feature = "ml-dsa")]
use crate::jose::ml_dsa::{ParameterSet, SigningKey};
use crate::jose::{Jwk, JwsAlgorithm, KeyType, base64url};

/// A private key of one of the types the software backends sign with.
///
/// Every variant zeroizes its secret on drop.
pub(super) enum LocalKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    #[cfg(feature = "secp256k1")]
    Secp256k1(k256::ecdsa::SigningKey),
    #[cfg(feature = "ml-dsa")]
    MlDsa(SigningKey),
}

/// The algorithms the software backends sign with.
pub(super) const ALGORITHMS: &[JwsAlgorithm] = &[
    JwsAlgorithm::EdDSA,
    JwsAlgorithm::ES256,
    #[cfg(feature = "secp256k1")]
    JwsAlgorithm::ES256K,
    #[cfg(feature = "ml-dsa")]
    JwsAlgorithm::MlDsa44,
    #[cfg(feature = "ml-dsa")]
    JwsAlgorithm::MlDsa65,
    #[cfg(feature = "ml-dsa")]
    JwsAlgorithm::MlDsa87,
];

impl LocalKey {
    /// Generates a key as `spec` describes from `random`, which fills a buffer with secret random
    /// bytes. An ML-DSA key is the one its 32-byte seed derives; the spec's algorithm names the
    /// parameter set.
    pub(super) fn generate(
        spec: &KeySpec,
        random: &mut dyn FnMut(&mut [u8]) -> Result<(), KeyStoreError>,
    ) -> Result<Self, KeyStoreError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        match spec.key_type {
            KeyType::Ed25519 => {
                random(secret.as_mut())?;
                Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                    &secret,
                )))
            }
            // A scalar outside `1..n` is rejected by `from_slice`; the probability is below
            // 2^-128 per draw, so the loop runs once in practice.
            KeyType::P256 => loop {
                random(secret.as_mut())?;
                if let Ok(key) = p256::ecdsa::SigningKey::from_slice(secret.as_ref()) {
                    return Ok(Self::P256(key));
                }
            },
            #[cfg(feature = "secp256k1")]
            KeyType::Secp256k1 => loop {
                random(secret.as_mut())?;
                if let Ok(key) = k256::ecdsa::SigningKey::from_slice(secret.as_ref()) {
                    return Ok(Self::Secp256k1(key));
                }
            },
            #[cfg(feature = "ml-dsa")]
            KeyType::Akp => {
                let set = ParameterSet::of(spec.alg).ok_or(KeyStoreError::InvalidSpec {
                    key_type: spec.key_type,
                    alg: spec.alg,
                })?;
                random(secret.as_mut())?;
                Ok(Self::MlDsa(SigningKey::from_seed(set, &secret)))
            }
            other => Err(KeyStoreError::UnsupportedKeyType(other)),
        }
    }

    /// The key behind a private JWK.
    ///
    /// The public members must be present and match the private scalar, so that a corrupted or
    /// hand-edited file is caught when it is loaded rather than when a signature fails to verify.
    #[cfg(feature = "software")]
    pub(super) fn from_jwk(jwk: &Jwk) -> Result<Self, Unusable> {
        if jwk.kty() == "AKP" {
            return Self::from_akp_jwk(jwk);
        }
        let d = jwk
            .private
            .d
            .as_deref()
            .ok_or("missing private member `d`")?;
        let d = Zeroizing::new(base64url::decode(d).map_err(|_| "`d` is not valid base64url")?);
        let key = match (jwk.kty(), jwk.crv()) {
            ("OKP", Some("Ed25519")) => {
                let bytes: &[u8; 32] = d.as_slice().try_into().map_err(|_| {
                    Unusable::new(format!("expected a 32-byte `d`, found {} bytes", d.len()))
                })?;
                Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(bytes))
            }
            ("EC", Some("P-256")) => Self::P256(
                p256::ecdsa::SigningKey::from_slice(&d)
                    .map_err(|e| Unusable::caused("invalid `d`", e))?,
            ),
            #[cfg(feature = "secp256k1")]
            ("EC", Some("secp256k1")) => Self::Secp256k1(
                k256::ecdsa::SigningKey::from_slice(&d)
                    .map_err(|e| Unusable::caused("invalid `d`", e))?,
            ),
            #[cfg(not(feature = "secp256k1"))]
            ("EC", Some("secp256k1")) => {
                return Err("secp256k1 keys need the `secp256k1` feature".into());
            }
            ("RSA", _) => {
                return Err(
                    "RSA keys are not signed with by this crate (verification only, see ADR 0001)"
                        .into(),
                );
            }
            (kty, crv) => {
                return Err(Unusable::new(format!(
                    "unsupported key type: `kty` {kty:?} with `crv` {crv:?}"
                )));
            }
        };
        let expected = key.public_jwk();
        let same_public = jwk.x() == expected.x() && jwk.y() == expected.y();
        if !same_public {
            return Err("public members `x`/`y` do not match the private key".into());
        }
        Ok(key)
    }

    /// The ML-DSA key behind a private `AKP` JWK: `priv` is the 32-byte seed (RFC 9964 §4), and
    /// the public key it derives must be `pub`.
    #[cfg(all(feature = "software", feature = "ml-dsa"))]
    fn from_akp_jwk(jwk: &Jwk) -> Result<Self, Unusable> {
        let (set, public) = jwk
            .ml_dsa_public_key()
            .map_err(|error| Unusable::caused("invalid public key", error))?;
        let seed = jwk
            .private
            .priv_key
            .as_deref()
            .ok_or("missing private member `priv`")?;
        let seed =
            Zeroizing::new(base64url::decode(seed).map_err(|_| "`priv` is not valid base64url")?);
        let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| {
            Unusable::new(format!(
                "expected a 32-byte `priv`, found {} bytes",
                seed.len()
            ))
        })?;
        let key = SigningKey::from_seed(set, seed);
        if key.public_key() != public.as_slice() {
            return Err("public member `pub` does not match the private key".into());
        }
        Ok(Self::MlDsa(key))
    }

    #[cfg(all(feature = "software", not(feature = "ml-dsa")))]
    fn from_akp_jwk(_: &Jwk) -> Result<Self, Unusable> {
        Err("ML-DSA keys need the `ml-dsa` feature".into())
    }

    /// The one algorithm this key signs with.
    #[cfg(feature = "software")]
    pub(super) fn alg(&self) -> JwsAlgorithm {
        match self {
            Self::Ed25519(_) => JwsAlgorithm::EdDSA,
            Self::P256(_) => JwsAlgorithm::ES256,
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(_) => JwsAlgorithm::ES256K,
            #[cfg(feature = "ml-dsa")]
            Self::MlDsa(key) => key.parameter_set().alg(),
        }
    }

    /// The public key as a JWK with only the key-type members set.
    pub(super) fn public_jwk(&self) -> Jwk {
        // Keys derived from valid private scalars are valid public keys, so the constructors
        // cannot fail; the fallbacks are unreachable.
        match self {
            Self::Ed25519(key) => Jwk::from_ed25519_public(&key.verifying_key().to_bytes()),
            Self::P256(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                Jwk::from_p256_public(point.as_bytes())
            }
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                Jwk::from_secp256k1_public(point.as_bytes())
            }
            #[cfg(feature = "ml-dsa")]
            Self::MlDsa(key) => {
                Jwk::from_ml_dsa_public(key.parameter_set().alg(), key.public_key())
            }
        }
        .unwrap_or_else(|_| {
            unreachable!("a generated or loaded private key has a valid public key")
        })
    }

    /// The private JWK: the public members plus `d`, or `priv` for an ML-DSA key.
    pub(super) fn private_jwk(&self) -> Jwk {
        let secret: Zeroizing<Vec<u8>> = match self {
            Self::Ed25519(key) => Zeroizing::new(key.to_bytes().to_vec()),
            Self::P256(key) => Zeroizing::new(key.to_bytes().to_vec()),
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => Zeroizing::new(key.to_bytes().to_vec()),
            #[cfg(feature = "ml-dsa")]
            Self::MlDsa(key) => Zeroizing::new(key.seed().to_vec()),
        };
        let mut jwk = self.public_jwk();
        let encoded = Some(base64url::encode(&secret));
        // RFC 9964 §4 keeps the ML-DSA seed in `priv`; every other type has its key in `d`.
        if jwk.kty() == "AKP" {
            jwk.private.priv_key = encoded;
        } else {
            jwk.private.d = encoded;
        }
        jwk
    }

    /// Signs `data`, returning the JWS form of the signature.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::Backend`] when an ML-DSA signature cannot get its randomness.
    #[cfg_attr(
        not(feature = "ml-dsa"),
        expect(
            clippy::unnecessary_wraps,
            reason = "only ML-DSA signing can fail, and only with the `ml-dsa` feature"
        )
    )]
    pub(super) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Ok(match self {
            Self::Ed25519(key) => {
                use ed25519_dalek::Signer as _;
                key.sign(data).to_bytes().to_vec()
            }
            Self::P256(key) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = key.sign(data);
                signature.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Self::Secp256k1(key) => {
                use k256::ecdsa::signature::Signer as _;
                let signature: k256::ecdsa::Signature = key.sign(data);
                signature.to_bytes().to_vec()
            }
            #[cfg(feature = "ml-dsa")]
            Self::MlDsa(key) => key.sign(data).map_err(KeyStoreError::backend)?,
        })
    }
}

/// One key of a software backend: the private key, its algorithm and the private JWK it was
/// loaded from or generated as, with `kid` and `alg` set.
pub(super) struct Entry {
    pub(super) key: LocalKey,
    pub(super) alg: JwsAlgorithm,
    /// The private JWK, persisted as is by the software store; `public_jwk` hands out its
    /// public projection.
    pub(super) jwk: Jwk,
}

impl Entry {
    /// An entry for a generated `key` under `id`, signing with `alg`.
    pub(super) fn new(id: &KeyId, key: LocalKey, alg: JwsAlgorithm) -> Self {
        let jwk = key
            .private_jwk()
            .with_kid(id.as_str())
            .with_alg(alg.as_str());
        Self { key, alg, jwk }
    }

    /// An entry for an existing private JWK, from a key set file or an import.
    ///
    /// The id is the `kid` when set and the RFC 7638 thumbprint otherwise; the algorithm is the
    /// `alg` member, which must fit the key, or the key type's algorithm when absent. A key whose
    /// `use` is not `sig` or whose `key_ops` lacks `sign` is refused, since it could not be used.
    #[cfg(feature = "software")]
    pub(super) fn from_jwk(jwk: Jwk) -> Result<(KeyId, Self), Unusable> {
        let key = LocalKey::from_jwk(&jwk)?;
        let alg = match jwk.alg() {
            Some(alg) => {
                let alg: JwsAlgorithm = alg
                    .parse()
                    .map_err(|_| Unusable::new(format!("unknown algorithm `{alg}`")))?;
                if alg != key.alg() {
                    return Err(Unusable::new(format!(
                        "`alg` {alg} does not fit a {} key",
                        key.alg()
                    )));
                }
                alg
            }
            None => key.alg(),
        };
        if jwk.key_use().is_some_and(|key_use| key_use != "sig") {
            return Err("`use` is not `sig`".into());
        }
        if jwk
            .key_ops()
            .is_some_and(|ops| !ops.iter().any(|op| op == "sign"))
        {
            return Err("`key_ops` lacks `sign`".into());
        }
        let id = match jwk.kid() {
            Some(kid) => KeyId::new(kid),
            None => KeyId::new(
                key.public_jwk()
                    .thumbprint_sha256()
                    .map_err(|e| Unusable::caused("no RFC 7638 thumbprint", e))?,
            ),
        };
        let jwk = jwk.with_kid(id.as_str()).with_alg(alg.as_str());
        Ok((id, Self { key, alg, jwk }))
    }

    /// The public JWK handed out by `public_jwk`.
    pub(super) fn public_jwk(&self) -> Jwk {
        self.jwk.public()
    }

    /// Signs `data` under `alg`, which must be this key's algorithm.
    pub(super) fn sign(
        &self,
        id: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        if alg != self.alg {
            return Err(KeyStoreError::AlgorithmMismatch {
                key: id.clone(),
                key_alg: self.alg,
                requested: alg,
            });
        }
        self.key.sign(data)
    }
}

/// Checks `spec` against what the software backends can generate and derives the key id.
///
/// The id is the label when given, the RFC 7638 thumbprint of the public key otherwise.
pub(super) fn generate(
    spec: &KeySpec,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), KeyStoreError>,
) -> Result<(KeyId, LocalKey), KeyStoreError> {
    spec.validate()?;
    if !ALGORITHMS.contains(&spec.alg) {
        return Err(KeyStoreError::UnsupportedKeyType(spec.key_type));
    }
    let key = LocalKey::generate(spec, random)?;
    let id = match &spec.label {
        Some(label) => KeyId::new(label.as_str()),
        None => KeyId::new(key.public_jwk().thumbprint_sha256().map_err(|e| {
            KeyStoreError::InvalidKey {
                key: KeyId::new(""),
                reason: "no RFC 7638 thumbprint".to_owned(),
                source: Some(Box::new(e)),
            }
        })?),
    };
    Ok((id, key))
}

/// Why a private JWK is not a usable key: what is wrong with it, and the error that says so,
/// when there is one. [`SoftwareKeyStore`](super::SoftwareKeyStore) reports it as
/// [`KeyStoreError::InvalidKey`] or [`KeyStoreError::InvalidKeySet`].
#[cfg(feature = "software")]
#[derive(Debug)]
pub(super) struct Unusable {
    pub(super) reason: String,
    pub(super) source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

#[cfg(feature = "software")]
impl Unusable {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            source: None,
        }
    }

    fn caused(reason: &str, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            reason: reason.to_owned(),
            source: Some(Box::new(source)),
        }
    }

    /// [`KeyStoreError::InvalidKey`] of `key`.
    pub(super) fn for_key(self, key: KeyId) -> KeyStoreError {
        KeyStoreError::InvalidKey {
            key,
            reason: self.reason,
            source: self.source,
        }
    }

    /// [`KeyStoreError::InvalidKeySet`] of the file at `path`.
    pub(super) fn for_key_set(self, path: std::path::PathBuf) -> KeyStoreError {
        KeyStoreError::InvalidKeySet {
            path,
            reason: self.reason,
            source: self.source,
        }
    }
}

#[cfg(feature = "software")]
impl From<&str> for Unusable {
    fn from(reason: &str) -> Self {
        Self::new(reason)
    }
}

/// Fills `buf` from the operating system's random number generator.
pub(super) fn os_random(buf: &mut [u8]) -> Result<(), KeyStoreError> {
    getrandom::fill(buf).map_err(KeyStoreError::backend)
}

/// A deterministic stream of secret bytes from a seed, for stable fixtures.
///
/// Block `i` is `SHA-256("identity-kit/in-memory" || seed || i)`.
#[cfg(feature = "in-memory")]
pub(super) struct SeededRandom {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
}

#[cfg(feature = "in-memory")]
impl SeededRandom {
    pub(super) fn new(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
            counter: 0,
        }
    }

    pub(super) fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            let block = Sha256::new()
                .chain_update(b"identity-kit/in-memory")
                .chain_update(self.seed.as_ref())
                .chain_update(self.counter.to_be_bytes())
                .finalize();
            self.counter += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}
