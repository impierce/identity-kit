//! Base64url without padding (RFC 7515 §2, RFC 4648 §5), the encoding of every JOSE octet string.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Encodes `data` as base64url without padding.
pub(crate) fn encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url without padding, rejecting padding, non-canonical trailing bits and any
/// character outside the base64url alphabet.
pub(crate) fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// Encodes an unsigned big-endian integer as `Base64urlUInt` (RFC 7518 §2): the minimum number of
/// octets, so leading zero octets are dropped and zero is a single `0x00` octet.
pub(crate) fn encode_uint(be: &[u8]) -> String {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let trimmed = &be[first..];
    if trimmed.is_empty() {
        encode(&[0])
    } else {
        encode(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint_encoding_is_minimal() {
        assert_eq!(encode_uint(&[0, 0, 1, 0]), encode(&[1, 0]));
        assert_eq!(encode_uint(&[0, 0]), encode(&[0]));
        assert_eq!(encode_uint(&[]), encode(&[0]));
        assert_eq!(encode_uint(&[1, 0, 1]), "AQAB");
    }

    #[test]
    fn decode_is_strict() {
        assert!(decode("AQAB=").is_err(), "padding");
        assert!(decode("AQA+").is_err(), "standard alphabet");
        assert!(decode("AQAB\n").is_err(), "whitespace");
        assert!(decode("AQ").is_ok());
        assert!(decode("AR").is_err(), "non-canonical trailing bits");
    }
}
