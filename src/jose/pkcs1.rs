//! PKCS #1 `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 8017
//! Appendix A.1.1) in DER: the form in which some vaults and HSMs return an RSA public key, and
//! the raw key of an `rsa-pub` Multikey.

use super::{Jwk, JwkError};

impl Jwk {
    /// An `RSA` key from a DER-encoded PKCS #1 `RSAPublicKey`
    /// (`SEQUENCE { modulus INTEGER, publicExponent INTEGER }`, RFC 8017 Appendix A.1.1).
    ///
    /// This is for key store backends whose vault returns an RSA public key as PKCS #1 rather
    /// than as a `SubjectPublicKeyInfo` (for that, see [`Jwk::from_spki_der`]). The parser is
    /// strict DER: definite lengths in the fewest octets, non-negative minimally encoded
    /// INTEGERs, nothing after the `SEQUENCE`. It needs no Cargo feature.
    ///
    /// Unlike [`Jwk::from_spki_der`], it takes no [`KeyType`](super::KeyType) and does not check
    /// the modulus size, as [`Jwk::from_rsa_public`] and [`Jwk::from_multikey`] do not: PKCS #1
    /// carries no algorithm identifier for a hint to select a parser by, and
    /// [`DefaultVerifier`](super::DefaultVerifier) rejects an unusable modulus when the key is
    /// used.
    ///
    /// # Errors
    ///
    /// [`JwkError::InvalidKey`] with `key: "RSA"` when `der` is not a DER `RSAPublicKey`.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::jose::Jwk;
    ///
    /// // `SEQUENCE { INTEGER 0x00c5, INTEGER 65537 }`: the leading zero keeps the modulus positive.
    /// let der = [0x30, 0x09, 0x02, 0x02, 0x00, 0xc5, 0x02, 0x03, 0x01, 0x00, 0x01];
    /// let jwk = Jwk::from_pkcs1_der(&der)?;
    /// assert_eq!(jwk.rsa_public_components()?, (vec![0xc5], vec![0x01, 0x00, 0x01]));
    /// assert_eq!(jwk.to_pkcs1_der()?, der);
    /// # Ok::<(), identity_kit::jose::JwkError>(())
    /// ```
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, JwkError> {
        let (n, e) = decode(der)?;
        Self::from_rsa_public(&n, &e)
    }

    /// This `RSA` key's public parameters as a DER-encoded PKCS #1 `RSAPublicKey`
    /// (RFC 8017 Appendix A.1.1), for key store backends whose vault takes that form.
    ///
    /// The encoding is DER, so it is the same for every JWK of the same key.
    ///
    /// # Errors
    ///
    /// The errors of [`Jwk::rsa_public_components`]: [`JwkError::UnexpectedKeyType`] for any
    /// other key, [`JwkError::MissingMember`] or [`JwkError::InvalidBase64Url`] for a broken `n`
    /// or `e`.
    pub fn to_pkcs1_der(&self) -> Result<Vec<u8>, JwkError> {
        let (n, e) = self.rsa_public_components()?;
        Ok(encode(&n, &e))
    }
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;

fn encode(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = integer(n);
    body.extend(integer(e));
    tlv(SEQUENCE, &body)
}

/// The big-endian `n` and `e` of `der`, without leading zero octets.
fn decode(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JwkError> {
    let (body, rest) = read_tlv(der, SEQUENCE)?;
    if !rest.is_empty() {
        return Err(invalid("trailing bytes after RSAPublicKey"));
    }
    let (n, body) = read_tlv(body, INTEGER)?;
    let (e, body) = read_tlv(body, INTEGER)?;
    if !body.is_empty() {
        return Err(invalid("trailing bytes inside RSAPublicKey"));
    }
    Ok((unsigned(n)?.to_vec(), unsigned(e)?.to_vec()))
}

/// A DER INTEGER holding the unsigned big-endian `value`.
fn integer(value: &[u8]) -> Vec<u8> {
    let first = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let trimmed = &value[first..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|&b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(trimmed);
    tlv(INTEGER, &body)
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        out.push(0x80 | (be.len() - first) as u8);
        out.extend_from_slice(&be[first..]);
    }
    out.extend_from_slice(body);
    out
}

/// The body of the TLV at the start of `der`, which must have tag `tag`, and what follows.
fn read_tlv(der: &[u8], tag: u8) -> Result<(&[u8], &[u8]), JwkError> {
    let (&found, rest) = der.split_first().ok_or_else(|| invalid("unexpected end"))?;
    if found != tag {
        return Err(invalid("unexpected ASN.1 tag"));
    }
    let (&first, rest) = rest
        .split_first()
        .ok_or_else(|| invalid("unexpected end"))?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > size_of::<usize>() || rest.len() < count {
            return Err(invalid("invalid length"));
        }
        let (len_bytes, rest) = rest.split_at(count);
        if len_bytes[0] == 0 || (count == 1 && len_bytes[0] < 0x80) {
            return Err(invalid("length is not minimally encoded"));
        }
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, rest)
    };
    if rest.len() < len {
        return Err(invalid("length exceeds input"));
    }
    Ok(rest.split_at(len))
}

/// The magnitude of a non-negative, minimally encoded INTEGER body.
fn unsigned(body: &[u8]) -> Result<&[u8], JwkError> {
    match body {
        [] => Err(invalid("empty INTEGER")),
        [first, ..] if first & 0x80 != 0 => Err(invalid("negative INTEGER")),
        [0, second, ..] if second & 0x80 == 0 => Err(invalid("INTEGER has a leading zero")),
        [0, rest @ ..] => Ok(rest),
        _ => Ok(body),
    }
}

fn invalid(reason: &str) -> JwkError {
    JwkError::InvalidKey {
        key: "RSA",
        reason: format!("malformed RSAPublicKey: {reason}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs1_round_trips_and_is_minimal() {
        // RFC 8017: INTEGERs are two's complement, so a high bit needs a leading zero.
        let n = [0x80, 0x01];
        let e = [0x01, 0x00, 0x01];
        let der = encode(&n, &e);
        assert_eq!(
            der,
            [
                0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01
            ]
        );
        assert_eq!(decode(&der).unwrap(), (n.to_vec(), e.to_vec()));
        // Leading zeros of the input are dropped.
        assert_eq!(encode(&[0, 0, 0x80, 0x01], &[0, 1, 0, 1]), der);
        // Long-form lengths.
        let big = vec![0x7f; 300];
        let der = encode(&big, &e);
        // 1 + 3 + 300 bytes of modulus INTEGER plus 5 of exponent: 309 = 0x135.
        assert_eq!(&der[..4], [0x30, 0x82, 0x01, 0x35]);
        assert_eq!(decode(&der).unwrap().0, big);
        for broken in [
            &[0x30, 0x00][..],
            &[0x30, 0x04, 0x02, 0x01, 0xff, 0x02][..],
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01][..],
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01][..],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00][..],
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01][..],
        ] {
            assert!(decode(broken).is_err(), "{broken:02x?}");
        }
    }
}
