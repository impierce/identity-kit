//! ECDSA signatures in their JWS form: from DER, and with a secp256k1 `s` in the lower half.

use super::{EcdsaSignatureError, JwsAlgorithm};

/// A DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3) as the JWS signature for `alg` (RFC 7518 §3.4):
/// `r || s`, each left-padded to the curve's size, with `s` normalized to the lower half of the
/// group order for ES256K.
///
/// This is the conversion a key store backend needs when its signer answers in DER, as the AWS
/// KMS `Sign` and Google Cloud KMS `AsymmetricSign` operations do for ECDSA keys.
/// [`KeyStore::sign`](crate::keys::KeyStore::sign) returns the JWS form, and
/// [`DefaultVerifier`](super::DefaultVerifier) refuses DER.
///
/// Only strict DER is accepted: one `SEQUENCE` of two positive `INTEGER`s, with definite, minimal
/// lengths, minimal integer encodings and nothing after the sequence. Each integer must fit the
/// curve's size (32 bytes for ES256 and ES256K, 48 for ES384). The values are not checked against
/// the group order, except for ES256K, whose normalization needs them below it.
///
/// # Errors
///
/// [`EcdsaSignatureError::NotEcdsa`] for EdDSA, RS256 and PS256,
/// [`EcdsaSignatureError::InvalidDer`] when `der` is not a strict DER `ECDSA-Sig-Value`,
/// [`EcdsaSignatureError::ComponentTooLong`] when `r` or `s` does not fit the curve,
/// [`EcdsaSignatureError::OutOfRange`] when an ES256K `r` or `s` is not below the group order,
/// and [`EcdsaSignatureError::Unsupported`] for ES256K without the `secp256k1` feature.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{JwsAlgorithm, ecdsa_signature_from_der};
///
/// // SEQUENCE { INTEGER 1, INTEGER 0x80 }: `s` needs a leading zero byte to stay positive.
/// let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];
/// let jws = ecdsa_signature_from_der(JwsAlgorithm::ES256, &der)?;
/// assert_eq!(jws.len(), 64);
/// assert_eq!((jws[31], jws[63]), (0x01, 0x80));
/// # Ok::<(), identity_kit::jose::EcdsaSignatureError>(())
/// ```
pub fn ecdsa_signature_from_der(
    alg: JwsAlgorithm,
    der: &[u8],
) -> Result<Vec<u8>, EcdsaSignatureError> {
    let size = component_size(alg)?;
    let (r, s) = parse(der)?;
    let mut signature = vec![0; 2 * size];
    for (component, out) in [r, s].into_iter().zip(signature.chunks_exact_mut(size)) {
        if component.len() > size {
            return Err(EcdsaSignatureError::ComponentTooLong {
                alg,
                len: component.len(),
            });
        }
        out[size - component.len()..].copy_from_slice(component);
    }
    normalize(alg, signature)
}

/// A raw `r || s` signature for `alg`, with `s` normalized to the lower half of the group order
/// for ES256K. ES256 and ES384 signatures are returned unchanged once their length is checked:
/// [`DefaultVerifier`](super::DefaultVerifier) accepts either `s` for ES256.
///
/// ECDSA over secp256k1 accepts `s` and `n - s` alike, but
/// [`DefaultVerifier`](super::DefaultVerifier), like most secp256k1 verifiers, accepts only the
/// lower one. A key store backend whose signer may return the upper one (an HSM, a cloud KMS, a
/// software enclave) passes its ES256K signatures through this function.
///
/// # Errors
///
/// [`EcdsaSignatureError::NotEcdsa`] for EdDSA, RS256 and PS256,
/// [`EcdsaSignatureError::InvalidLength`] when `signature` is not twice the curve's size,
/// [`EcdsaSignatureError::OutOfRange`] when an ES256K `r` or `s` is zero or not below the group
/// order, and [`EcdsaSignatureError::Unsupported`] for ES256K without the `secp256k1` feature.
///
/// # Examples
///
/// ```
/// use identity_kit::jose::{EcdsaSignatureError, JwsAlgorithm, normalize_ecdsa_signature};
///
/// let signature = [7; 64];
/// assert_eq!(normalize_ecdsa_signature(JwsAlgorithm::ES256, &signature)?, signature);
/// assert!(matches!(
///     normalize_ecdsa_signature(JwsAlgorithm::ES256, &signature[..63]),
///     Err(EcdsaSignatureError::InvalidLength { expected: 64, actual: 63, .. })
/// ));
/// # Ok::<(), EcdsaSignatureError>(())
/// ```
pub fn normalize_ecdsa_signature(
    alg: JwsAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, EcdsaSignatureError> {
    let size = component_size(alg)?;
    if signature.len() != 2 * size {
        return Err(EcdsaSignatureError::InvalidLength {
            alg,
            expected: 2 * size,
            actual: signature.len(),
        });
    }
    normalize(alg, signature.to_vec())
}

/// The size of `r` and of `s` for `alg`.
fn component_size(alg: JwsAlgorithm) -> Result<usize, EcdsaSignatureError> {
    match alg {
        JwsAlgorithm::ES256 | JwsAlgorithm::ES256K => Ok(32),
        JwsAlgorithm::ES384 => Ok(48),
        JwsAlgorithm::EdDSA | JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => {
            Err(EcdsaSignatureError::NotEcdsa(alg))
        }
    }
}

/// `signature`, of the right length for `alg`, with a secp256k1 `s` in the lower half.
fn normalize(alg: JwsAlgorithm, signature: Vec<u8>) -> Result<Vec<u8>, EcdsaSignatureError> {
    if alg != JwsAlgorithm::ES256K {
        return Ok(signature);
    }
    #[cfg(feature = "secp256k1")]
    {
        let parsed = k256::ecdsa::Signature::from_slice(&signature)
            .map_err(|_| EcdsaSignatureError::OutOfRange(alg))?;
        Ok(parsed.normalize_s().to_bytes().to_vec())
    }
    #[cfg(not(feature = "secp256k1"))]
    {
        let _ = signature;
        Err(EcdsaSignatureError::Unsupported(alg))
    }
}

/// `r` and `s` of a strict DER `ECDSA-Sig-Value`, without sign bytes.
fn parse(der: &[u8]) -> Result<(&[u8], &[u8]), EcdsaSignatureError> {
    let (sequence, rest) = read(der, SEQUENCE)?;
    if !rest.is_empty() {
        return Err(EcdsaSignatureError::InvalidDer(
            "trailing bytes after the sequence",
        ));
    }
    let (r, rest) = integer(sequence)?;
    let (s, rest) = integer(rest)?;
    if !rest.is_empty() {
        return Err(EcdsaSignatureError::InvalidDer(
            "more than two elements in the sequence",
        ));
    }
    Ok((r, s))
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;

/// A positive `INTEGER` at the start of `input`, minimally encoded, as its magnitude, and what
/// follows it.
fn integer(input: &[u8]) -> Result<(&[u8], &[u8]), EcdsaSignatureError> {
    let (content, rest) = read(input, INTEGER)?;
    let magnitude = match content {
        [] => return Err(EcdsaSignatureError::InvalidDer("empty integer")),
        [first, ..] if first & 0x80 != 0 => {
            return Err(EcdsaSignatureError::InvalidDer("negative integer"));
        }
        [0] => return Err(EcdsaSignatureError::InvalidDer("zero integer")),
        [0, second, ..] if second & 0x80 == 0 => {
            return Err(EcdsaSignatureError::InvalidDer(
                "integer with a superfluous leading zero",
            ));
        }
        [0, magnitude @ ..] | magnitude => magnitude,
    };
    Ok((magnitude, rest))
}

/// The content of the element tagged `tag` at the start of `input`, and what follows it.
fn read(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), EcdsaSignatureError> {
    let (&found, input) = input
        .split_first()
        .ok_or(EcdsaSignatureError::InvalidDer("truncated element"))?;
    if found != tag {
        return Err(EcdsaSignatureError::InvalidDer(if tag == SEQUENCE {
            "not a sequence"
        } else {
            "not an integer"
        }));
    }
    let (&first, input) = input
        .split_first()
        .ok_or(EcdsaSignatureError::InvalidDer("truncated length"))?;
    let (len, input) = match first {
        0x00..=0x7f => (usize::from(first), input),
        // One length byte holds up to 255: more than any signature of these curves needs.
        0x81 => match input.split_first() {
            Some((&len, input)) if len >= 0x80 => (usize::from(len), input),
            Some(_) => {
                return Err(EcdsaSignatureError::InvalidDer(
                    "length not minimally encoded",
                ));
            }
            None => return Err(EcdsaSignatureError::InvalidDer("truncated length")),
        },
        0x80 => return Err(EcdsaSignatureError::InvalidDer("indefinite length")),
        _ => {
            return Err(EcdsaSignatureError::InvalidDer(
                "length too long for a signature",
            ));
        }
    };
    if input.len() < len {
        return Err(EcdsaSignatureError::InvalidDer("truncated element"));
    }
    Ok(input.split_at(len))
}
