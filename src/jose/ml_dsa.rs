//! ML-DSA (FIPS 204) as RFC 9964 brings it to JOSE: the parameter sets, verification, the
//! external μ of remote signers and the signing key of the software key stores. The only module
//! that names the `ml-dsa` crate.

#[cfg(feature = "ml-dsa")]
use super::VerificationError;
use super::{Jwk, JwkError, JwsAlgorithm};

/// One of the ML-DSA parameter sets of FIPS 204 Table 1, named by its JWS algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParameterSet {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl ParameterSet {
    /// The parameter set of `alg`; `None` for the algorithms that are not ML-DSA.
    pub(crate) fn of(alg: JwsAlgorithm) -> Option<Self> {
        match alg {
            JwsAlgorithm::MlDsa44 => Some(Self::MlDsa44),
            JwsAlgorithm::MlDsa65 => Some(Self::MlDsa65),
            JwsAlgorithm::MlDsa87 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub(crate) fn alg(self) -> JwsAlgorithm {
        match self {
            Self::MlDsa44 => JwsAlgorithm::MlDsa44,
            Self::MlDsa65 => JwsAlgorithm::MlDsa65,
            Self::MlDsa87 => JwsAlgorithm::MlDsa87,
        }
    }

    /// The length of an encoded public key (`pkEncode`, FIPS 204 Table 2).
    pub(crate) fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// The length of an encoded signature (`sigEncode`, FIPS 204 Table 2).
    #[cfg(feature = "ml-dsa")]
    fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }
}

/// The external μ of `message` for the ML-DSA public key `key`: the 64-byte digest that FIPS 204
/// signs in place of the message, μ = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ message, 64) with
/// tr = SHAKE256(`pub`, 64).
///
/// The two zero octets are pure ML-DSA's domain separator and the length of the empty context
/// string, which RFC 9964 §5 requires. A remote signer that caps the message size signs μ instead
/// (AWS KMS with `MessageType: EXTERNAL_MU`, an HSM): a key store passes it the μ of the JWS
/// signing input, and the signature it returns verifies as an ordinary ML-DSA JWS of that signing
/// input, with [`DefaultVerifier`](super::DefaultVerifier) or any other verifier.
///
/// # Errors
///
/// - [`JwkError::UnexpectedKeyType`] when `key` is not an `AKP` key;
/// - [`JwkError::MissingMember`] or [`JwkError::InvalidBase64Url`] for a missing or broken `alg`
///   or `pub`;
/// - [`JwkError::InvalidKey`] when its `alg` is not ML-DSA-44, ML-DSA-65 or ML-DSA-87;
/// - [`JwkError::InvalidKeyLength`] when `pub` is not the length of the parameter set;
/// - [`JwkError::FeatureDisabled`] when the `ml-dsa` feature is off.
pub fn ml_dsa_external_mu(key: &Jwk, message: &[u8]) -> Result<[u8; 64], JwkError> {
    let (_, public) = key.ml_dsa_public_key()?;
    #[cfg(feature = "ml-dsa")]
    {
        Ok(external_mu(&public, message))
    }
    #[cfg(not(feature = "ml-dsa"))]
    {
        let _ = (public, message);
        Err(JwkError::FeatureDisabled {
            key: "ML-DSA",
            feature: "ml-dsa",
        })
    }
}

#[cfg(feature = "ml-dsa")]
fn external_mu(public: &[u8], message: &[u8]) -> [u8; 64] {
    use shake::{ExtendableOutput as _, Shake256, Update as _, XofReader as _};
    let mut tr = [0u8; 64];
    let mut hasher = Shake256::default();
    hasher.update(public);
    hasher.finalize_xof().read(&mut tr);

    let mut mu = [0u8; 64];
    let mut hasher = Shake256::default();
    hasher.update(&tr);
    hasher.update(&[0x00, 0x00]);
    hasher.update(message);
    hasher.finalize_xof().read(&mut mu);
    mu
}

/// Verifies `signature` over `message` with the ML-DSA key `key`, pure ML-DSA with the empty
/// context string (FIPS 204 Algorithm 3, RFC 9964 §5). The parameter set is the key's `alg`,
/// which the caller has checked against the JWS `alg`.
#[cfg(feature = "ml-dsa")]
pub(crate) fn verify(message: &[u8], signature: &[u8], key: &Jwk) -> Result<(), VerificationError> {
    let (set, public) = key.ml_dsa_public_key()?;
    if signature.len() != set.signature_len() {
        return Err(VerificationError::InvalidSignatureLength {
            expected: set.signature_len(),
            actual: signature.len(),
        });
    }
    let verified = match set {
        ParameterSet::MlDsa44 => verify_as::<ml_dsa::MlDsa44>(&public, message, signature),
        ParameterSet::MlDsa65 => verify_as::<ml_dsa::MlDsa65>(&public, message, signature),
        ParameterSet::MlDsa87 => verify_as::<ml_dsa::MlDsa87>(&public, message, signature),
    };
    if verified {
        Ok(())
    } else {
        Err(VerificationError::InvalidSignature)
    }
}

/// Whether `signature` verifies; `false` too for a signature that does not decode (`sigDecode`).
/// The lengths are the parameter set's.
#[cfg(feature = "ml-dsa")]
fn verify_as<P: ml_dsa::MlDsaParams>(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(public), Ok(signature)) = (
        ml_dsa::EncodedVerifyingKey::<P>::try_from(public),
        ml_dsa::Signature::<P>::try_from(signature),
    ) else {
        return false;
    };
    ml_dsa::VerifyingKey::<P>::decode(&public).verify_with_context(message, &[], &signature)
}

/// An ML-DSA private key of the software key stores: the 32-byte seed RFC 9964 §4 stores in
/// `priv`, the public key it derives and the expanded key that signs. Zeroized on drop.
#[cfg(all(feature = "ml-dsa", any(feature = "in-memory", feature = "software")))]
pub(crate) struct SigningKey {
    seed: zeroize::Zeroizing<[u8; 32]>,
    public: Vec<u8>,
    expanded: ExpandedKey,
}

/// The expanded key of one parameter set, boxed: an ML-DSA-87 key is tens of kilobytes.
#[cfg(all(feature = "ml-dsa", any(feature = "in-memory", feature = "software")))]
enum ExpandedKey {
    MlDsa44(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa44>>),
    MlDsa65(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa65>>),
    MlDsa87(Box<ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>>),
}

#[cfg(all(feature = "ml-dsa", any(feature = "in-memory", feature = "software")))]
impl SigningKey {
    /// The key of `set` that `seed` derives (`ML-DSA.KeyGen_internal`, FIPS 204 Algorithm 6).
    pub(crate) fn from_seed(set: ParameterSet, seed: &[u8; 32]) -> Self {
        let (expanded, public) = match set {
            ParameterSet::MlDsa44 => {
                let (key, public) = expand::<ml_dsa::MlDsa44>(seed);
                (ExpandedKey::MlDsa44(key), public)
            }
            ParameterSet::MlDsa65 => {
                let (key, public) = expand::<ml_dsa::MlDsa65>(seed);
                (ExpandedKey::MlDsa65(key), public)
            }
            ParameterSet::MlDsa87 => {
                let (key, public) = expand::<ml_dsa::MlDsa87>(seed);
                (ExpandedKey::MlDsa87(key), public)
            }
        };
        Self {
            seed: zeroize::Zeroizing::new(*seed),
            public,
            expanded,
        }
    }

    pub(crate) fn parameter_set(&self) -> ParameterSet {
        match self.expanded {
            ExpandedKey::MlDsa44(_) => ParameterSet::MlDsa44,
            ExpandedKey::MlDsa65(_) => ParameterSet::MlDsa65,
            ExpandedKey::MlDsa87(_) => ParameterSet::MlDsa87,
        }
    }

    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The encoded public key (`pkEncode`).
    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Signs `message` with hedged (randomized) ML-DSA and the empty context string (FIPS 204
    /// Algorithm 2, RFC 9964 §5), with fresh randomness from the operating system.
    ///
    /// # Errors
    ///
    /// When the operating system's random number generator fails.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, ml_dsa::Error> {
        let mut random = getrandom::SysRng;
        Ok(match &self.expanded {
            ExpandedKey::MlDsa44(key) => key
                .sign_randomized(message, &[], &mut random)?
                .encode()
                .to_vec(),
            ExpandedKey::MlDsa65(key) => key
                .sign_randomized(message, &[], &mut random)?
                .encode()
                .to_vec(),
            ExpandedKey::MlDsa87(key) => key
                .sign_randomized(message, &[], &mut random)?
                .encode()
                .to_vec(),
        })
    }
}

/// The expanded key of `seed` and its encoded public key.
#[cfg(all(feature = "ml-dsa", any(feature = "in-memory", feature = "software")))]
fn expand<P: ml_dsa::MlDsaParams>(
    seed: &[u8; 32],
) -> (Box<ml_dsa::ExpandedSigningKey<P>>, Vec<u8>) {
    let key = Box::new(ml_dsa::ExpandedSigningKey::<P>::from_seed(&(*seed).into()));
    let public = key.verifying_key().encode().to_vec();
    (key, public)
}
