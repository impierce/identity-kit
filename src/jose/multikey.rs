//! Multikey: a public key as a base58btc multibase string with a multicodec header (Controlled
//! Identifiers 1.0 §2.2.2), the `publicKeyMultibase` of a verification method and the
//! method-specific id of `did:key`.

use super::{Jwk, JwkError};

/// The multicodec codes of the public key types this crate reads from and writes to a Multikey.
///
/// The codes are the [multicodec table] entries; each key is the raw form the table names.
///
/// [multicodec table]: https://github.com/multiformats/multicodec/blob/master/table.csv
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyCodec {
    /// `secp256k1-pub` (`0xe7`): a compressed SEC1 point, 33 bytes.
    Secp256k1,
    /// `x25519-pub` (`0xec`): the 32-byte X25519 public key of RFC 7748.
    X25519,
    /// `ed25519-pub` (`0xed`): the 32-byte Ed25519 public key of RFC 8032.
    Ed25519,
    /// `p256-pub` (`0x1200`): a compressed SEC1 point, 33 bytes.
    P256,
    /// `rsa-pub` (`0x1205`): a DER-encoded PKCS #1 `RSAPublicKey` (RFC 8017 Appendix A.1.1).
    Rsa,
}

impl KeyCodec {
    /// The multicodec code.
    pub const fn code(self) -> u64 {
        match self {
            Self::Secp256k1 => 0xe7,
            Self::X25519 => 0xec,
            Self::Ed25519 => 0xed,
            Self::P256 => 0x1200,
            Self::Rsa => 0x1205,
        }
    }

    /// The multicodec name: `ed25519-pub`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Secp256k1 => "secp256k1-pub",
            Self::X25519 => "x25519-pub",
            Self::Ed25519 => "ed25519-pub",
            Self::P256 => "p256-pub",
            Self::Rsa => "rsa-pub",
        }
    }

    /// The codec with multicodec code `code`, if this crate knows it.
    pub const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0xe7 => Self::Secp256k1,
            0xec => Self::X25519,
            0xed => Self::Ed25519,
            0x1200 => Self::P256,
            0x1205 => Self::Rsa,
            _ => return None,
        })
    }

    /// The byte length of the raw key, when the key type has a fixed one.
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Self::Secp256k1 | Self::P256 => Some(33),
            Self::X25519 | Self::Ed25519 => Some(32),
            Self::Rsa => None,
        }
    }

    const fn key_name(self) -> &'static str {
        match self {
            Self::Secp256k1 => "secp256k1",
            Self::X25519 => "X25519",
            Self::Ed25519 => "Ed25519",
            Self::P256 => "P-256",
            Self::Rsa => "RSA",
        }
    }
}

impl Jwk {
    /// The key a Multikey string (`z6Mk…`) encodes.
    ///
    /// The string is the base58btc multibase (`z`) of a multicodec header followed by the raw
    /// key; see [`KeyCodec`] for the key types understood.
    ///
    /// # Errors
    ///
    /// - [`JwkError::InvalidMultikey`] when the string is not `z` followed by base58btc with a
    ///   complete multicodec header.
    /// - [`JwkError::UnsupportedMulticodec`] for a key type this crate does not know, such as
    ///   P-384 or BLS12-381.
    /// - [`JwkError::InvalidKeyLength`] when the raw key has the wrong length for its type.
    /// - [`JwkError::InvalidKey`] when the raw key is not a valid key: a point off the curve, a
    ///   malformed `RSAPublicKey`.
    /// - [`JwkError::FeatureDisabled`] for a secp256k1 key without the `secp256k1` feature.
    ///
    /// # Examples
    ///
    /// ```
    /// use identity_kit::jose::Jwk;
    ///
    /// // The Ed25519 key of the did:key specification's first example.
    /// let jwk = Jwk::from_multikey("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")?;
    /// assert_eq!((jwk.kty(), jwk.crv()), ("OKP", Some("Ed25519")));
    /// assert_eq!(jwk.to_multikey()?, "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    /// # Ok::<(), identity_kit::jose::JwkError>(())
    /// ```
    pub fn from_multikey(multikey: &str) -> Result<Self, JwkError> {
        let (codec, raw) = decode(multikey)?;
        if let Some(expected) = codec.key_len()
            && raw.len() != expected
        {
            return Err(JwkError::InvalidKeyLength {
                key: codec.key_name(),
                expected,
                actual: raw.len(),
            });
        }
        match codec {
            KeyCodec::Ed25519 => Self::from_ed25519_public(&raw),
            KeyCodec::X25519 => Self::from_x25519_public(&raw),
            KeyCodec::P256 => Self::from_p256_public(&raw),
            #[cfg(feature = "secp256k1")]
            KeyCodec::Secp256k1 => Self::from_secp256k1_public(&raw),
            #[cfg(not(feature = "secp256k1"))]
            KeyCodec::Secp256k1 => Err(JwkError::FeatureDisabled {
                key: "secp256k1",
                feature: "secp256k1",
            }),
            KeyCodec::Rsa => {
                let (n, e) = pkcs1::decode(&raw)?;
                Self::from_rsa_public(&n, &e)
            }
        }
    }

    /// This key as a Multikey string: base58btc multibase of the multicodec header and the raw
    /// public key. EC points are compressed; an RSA key is a PKCS #1 `RSAPublicKey`.
    ///
    /// Only the public parameters are encoded.
    ///
    /// # Errors
    ///
    /// [`JwkError::UnsupportedKeyType`] for a key type without a [`KeyCodec`], and the errors
    /// of the raw key accessors ([`Jwk::ed25519_public_bytes`] and friends) when the key does not
    /// decode.
    pub fn to_multikey(&self) -> Result<String, JwkError> {
        let (codec, raw) = match (self.kty(), self.crv()) {
            ("OKP", Some("Ed25519")) => (KeyCodec::Ed25519, self.ed25519_public_bytes()?.to_vec()),
            ("OKP", Some("X25519")) => (KeyCodec::X25519, self.x25519_public_bytes()?.to_vec()),
            ("EC", Some("P-256")) => {
                use p256::elliptic_curve::sec1::ToSec1Point as _;
                let point = self.p256_public_key()?.to_sec1_point(true);
                (KeyCodec::P256, point.as_bytes().to_vec())
            }
            #[cfg(feature = "secp256k1")]
            ("EC", Some("secp256k1")) => {
                use k256::elliptic_curve::sec1::ToSec1Point as _;
                let point = self.secp256k1_public_key()?.to_sec1_point(true);
                (KeyCodec::Secp256k1, point.as_bytes().to_vec())
            }
            ("RSA", _) => {
                let (n, e) = self.rsa_public_components()?;
                (KeyCodec::Rsa, pkcs1::encode(&n, &e))
            }
            _ => return Err(self.unsupported()),
        };
        Ok(encode(codec, &raw))
    }
}

/// The Multikey string for `raw` of type `codec`.
pub(crate) fn encode(codec: KeyCodec, raw: &[u8]) -> String {
    let mut bytes = varint::encode(codec.code());
    bytes.extend_from_slice(raw);
    format!("z{}", bs58::encode(bytes).into_string())
}

/// The codec and raw key of a Multikey string.
pub(crate) fn decode(multikey: &str) -> Result<(KeyCodec, Vec<u8>), JwkError> {
    let Some(base58) = multikey.strip_prefix('z') else {
        return Err(JwkError::InvalidMultikey(
            "expected the base58btc multibase prefix `z`".to_owned(),
        ));
    };
    let bytes = bs58::decode(base58)
        .into_vec()
        .map_err(|e| JwkError::InvalidMultikey(format!("invalid base58btc: {e}")))?;
    let (code, header_len) = varint::decode(&bytes)?;
    let codec = KeyCodec::from_code(code).ok_or(JwkError::UnsupportedMulticodec(code))?;
    Ok((codec, bytes[header_len..].to_vec()))
}

/// Unsigned varints (LEB128), the multicodec header encoding.
mod varint {
    use crate::jose::JwkError;

    /// The longest varint multicodec allows.
    const MAX_LEN: usize = 9;

    pub(super) fn encode(mut value: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(2);
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    /// The value and the number of bytes it took; the encoding must be minimal.
    pub(super) fn decode(bytes: &[u8]) -> Result<(u64, usize), JwkError> {
        let mut value = 0u64;
        for (i, &byte) in bytes.iter().enumerate().take(MAX_LEN) {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && byte == 0 {
                    return Err(JwkError::InvalidMultikey(
                        "multicodec header is not minimally encoded".to_owned(),
                    ));
                }
                return Ok((value, i + 1));
            }
        }
        Err(JwkError::InvalidMultikey(
            "multicodec header is truncated or too long".to_owned(),
        ))
    }
}

/// The DER encoding of PKCS #1 `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }` (RFC 8017 Appendix A.1.1), which `rsa-pub` carries.
mod pkcs1 {
    use crate::jose::JwkError;

    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;

    pub(super) fn encode(n: &[u8], e: &[u8]) -> Vec<u8> {
        let mut body = integer(n);
        body.extend(integer(e));
        tlv(SEQUENCE, &body)
    }

    /// The big-endian `n` and `e` of `der`, without leading zero octets.
    pub(super) fn decode(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), JwkError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trips_multicodec_headers() {
        // Multicodec table: `ed25519-pub` 0xed, `p256-pub` 0x1200, `rsa-pub` 0x1205.
        assert_eq!(varint::encode(0xed), [0xed, 0x01]);
        assert_eq!(varint::encode(0x1200), [0x80, 0x24]);
        assert_eq!(varint::encode(0x1205), [0x85, 0x24]);
        assert_eq!(varint::encode(0x7f), [0x7f]);
        for code in [0u64, 1, 0x7f, 0x80, 0xed, 0x1200, 0x1205, u64::MAX >> 1] {
            let encoded = varint::encode(code);
            assert_eq!(varint::decode(&encoded).unwrap(), (code, encoded.len()));
        }
        assert!(varint::decode(&[0x80]).is_err(), "truncated");
        assert!(varint::decode(&[0xed, 0x80, 0x00]).is_err(), "not minimal");
        assert!(varint::decode(&[0x80; 10]).is_err(), "too long");
    }

    #[test]
    fn pkcs1_round_trips_and_is_minimal() {
        // RFC 8017: INTEGERs are two's complement, so a high bit needs a leading zero.
        let n = [0x80, 0x01];
        let e = [0x01, 0x00, 0x01];
        let der = pkcs1::encode(&n, &e);
        assert_eq!(
            der,
            [
                0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01
            ]
        );
        assert_eq!(pkcs1::decode(&der).unwrap(), (n.to_vec(), e.to_vec()));
        // Leading zeros of the input are dropped.
        assert_eq!(pkcs1::encode(&[0, 0, 0x80, 0x01], &[0, 1, 0, 1]), der);
        // Long-form lengths.
        let big = vec![0x7f; 300];
        let der = pkcs1::encode(&big, &e);
        // 1 + 3 + 300 bytes of modulus INTEGER plus 5 of exponent: 309 = 0x135.
        assert_eq!(&der[..4], [0x30, 0x82, 0x01, 0x35]);
        assert_eq!(pkcs1::decode(&der).unwrap().0, big);
        for broken in [
            &[0x30, 0x00][..],
            &[0x30, 0x04, 0x02, 0x01, 0xff, 0x02][..],
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01][..],
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01][..],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00][..],
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01][..],
        ] {
            assert!(pkcs1::decode(broken).is_err(), "{broken:02x?}");
        }
    }
}
