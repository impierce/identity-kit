//! `JwsVerifier` and the pure-Rust `DefaultVerifier`.

use super::{Jwk, JwsAlgorithm, VerificationError};

/// Verifies JWS signatures.
///
/// The verifier is the crate's crypto extension point: [`DefaultVerifier`] implements the
/// algorithms with RustCrypto, and an application can substitute an HSM-backed or FIPS-validated
/// one. Implementations take the signature in the JWS form of the algorithm: 64 bytes for EdDSA,
/// raw `r || s` (not DER) for ECDSA, the modulus-sized octet string for RSA.
pub trait JwsVerifier: Send + Sync {
    /// Verifies that `signature` over `signing_input` was made with the private counterpart of
    /// `key` under `alg`.
    ///
    /// # Errors
    ///
    /// A [`VerificationError`] when the key, the signature or the algorithm is unusable, and
    /// [`VerificationError::InvalidSignature`] when everything is well-formed but the signature
    /// does not verify.
    fn verify(
        &self,
        alg: JwsAlgorithm,
        signing_input: &[u8],
        signature: &[u8],
        key: &Jwk,
    ) -> Result<(), VerificationError>;
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for &T {
    fn verify(
        &self,
        alg: JwsAlgorithm,
        signing_input: &[u8],
        signature: &[u8],
        key: &Jwk,
    ) -> Result<(), VerificationError> {
        (**self).verify(alg, signing_input, signature, key)
    }
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for Box<T> {
    fn verify(
        &self,
        alg: JwsAlgorithm,
        signing_input: &[u8],
        signature: &[u8],
        key: &Jwk,
    ) -> Result<(), VerificationError> {
        (**self).verify(alg, signing_input, signature, key)
    }
}

impl<T: JwsVerifier + ?Sized> JwsVerifier for std::sync::Arc<T> {
    fn verify(
        &self,
        alg: JwsAlgorithm,
        signing_input: &[u8],
        signature: &[u8],
        key: &Jwk,
    ) -> Result<(), VerificationError> {
        (**self).verify(alg, signing_input, signature, key)
    }
}

/// A [`JwsVerifier`] over RustCrypto: `ed25519-dalek` for EdDSA, `p256` for ES256, `k256` for
/// ES256K (feature `secp256k1`) and `rsa` for RS256 and PS256 (feature `rsa`).
///
/// ES384 is in the [`JwsAlgorithm`] vocabulary but not implemented here; verifying it returns
/// [`VerificationError::UnsupportedAlgorithm`].
///
/// Before the signature is checked, the key's own restrictions are: a key whose `alg` names
/// another algorithm, whose `use` is not `sig` or whose `key_ops` lacks `verify` is rejected.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsVerifier};
///
/// // RFC 8037 Appendix A.4 and A.5.
/// let key: Jwk = serde_json::from_str(
///     r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
/// )?;
/// let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
///              hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
/// let jws = identity_kit::jose::CompactJws::decode(token)?;
/// DefaultVerifier.verify(JwsAlgorithm::EdDSA, jws.signing_input(), jws.signature(), &key)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefaultVerifier;

impl JwsVerifier for DefaultVerifier {
    fn verify(
        &self,
        alg: JwsAlgorithm,
        signing_input: &[u8],
        signature: &[u8],
        key: &Jwk,
    ) -> Result<(), VerificationError> {
        check_key_restrictions(alg, key)?;
        match alg {
            JwsAlgorithm::EdDSA => {
                let verifying_key = key.ed25519_verifying_key()?;
                let signature = ed25519_dalek::Signature::from_bytes(fixed_size::<64>(signature)?);
                verifying_key
                    .verify_strict(signing_input, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            JwsAlgorithm::ES256 => {
                use p256::ecdsa::signature::Verifier as _;
                let verifying_key = p256::ecdsa::VerifyingKey::from(&key.p256_public_key()?);
                let signature = p256::ecdsa::Signature::from_slice(ecdsa_raw::<64>(signature)?)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                verifying_key
                    .verify(signing_input, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            #[cfg(feature = "secp256k1")]
            JwsAlgorithm::ES256K => {
                use k256::ecdsa::signature::Verifier as _;
                let verifying_key = k256::ecdsa::VerifyingKey::from(&key.secp256k1_public_key()?);
                let signature = k256::ecdsa::Signature::from_slice(ecdsa_raw::<64>(signature)?)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                verifying_key
                    .verify(signing_input, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            #[cfg(feature = "rsa")]
            JwsAlgorithm::RS256 => {
                use rsa::signature::Verifier as _;
                let public_key = key.rsa_public_key()?;
                let signature =
                    rsa::pkcs1v15::Signature::try_from(rsa_sized(&public_key, signature)?)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key)
                    .verify(signing_input, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            #[cfg(feature = "rsa")]
            JwsAlgorithm::PS256 => {
                use rsa::signature::Verifier as _;
                let public_key = key.rsa_public_key()?;
                let signature = rsa::pss::Signature::try_from(rsa_sized(&public_key, signature)?)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key)
                    .verify(signing_input, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            other => Err(VerificationError::UnsupportedAlgorithm(other)),
        }
    }
}

/// Rejects a key whose `alg`, `use` or `key_ops` excludes verifying with `alg`.
fn check_key_restrictions(alg: JwsAlgorithm, key: &Jwk) -> Result<(), VerificationError> {
    match key.alg() {
        Some(key_alg) if key_alg != alg.as_str() => {
            return Err(VerificationError::AlgorithmMismatch {
                alg,
                key_alg: key_alg.to_owned(),
            });
        }
        _ => {}
    }
    if key.key_use().is_some_and(|key_use| key_use != "sig") {
        return Err(VerificationError::KeyUse("`use` is not `sig`"));
    }
    if key
        .key_ops()
        .is_some_and(|key_ops| !key_ops.iter().any(|op| op == "verify"))
    {
        return Err(VerificationError::KeyUse("`key_ops` lacks `verify`"));
    }
    Ok(())
}

/// `signature` as an array of exactly `N` bytes.
fn fixed_size<const N: usize>(signature: &[u8]) -> Result<&[u8; N], VerificationError> {
    signature
        .try_into()
        .map_err(|_| VerificationError::InvalidSignatureLength {
            expected: N,
            actual: signature.len(),
        })
}

/// `signature` as the octet string of exactly the modulus length that RFC 7518 §3.3 and §3.5
/// require. An RSA signature is an integer, so without this check a shorter or longer encoding
/// of the same value (a leading zero byte dropped or added) would verify as well.
#[cfg(feature = "rsa")]
fn rsa_sized<'a>(
    key: &rsa::RsaPublicKey,
    signature: &'a [u8],
) -> Result<&'a [u8], VerificationError> {
    use rsa::traits::PublicKeyParts as _;
    let expected = key.size();
    if signature.len() != expected {
        return Err(VerificationError::InvalidSignatureLength {
            expected,
            actual: signature.len(),
        });
    }
    Ok(signature)
}

/// `signature` as a raw `r || s` ECDSA signature of exactly `N` bytes, with a dedicated error for
/// a DER-encoded one.
fn ecdsa_raw<const N: usize>(signature: &[u8]) -> Result<&[u8; N], VerificationError> {
    // A DER ECDSA-Sig-Value is a SEQUENCE whose length (N + 6 to N + 8 bytes for the curves here)
    // never equals the raw length, so a 0x30 tag on an input of the wrong length is DER.
    if signature.len() != N && signature.first() == Some(&0x30) {
        return Err(VerificationError::DerEncodedSignature);
    }
    fixed_size::<N>(signature)
}
