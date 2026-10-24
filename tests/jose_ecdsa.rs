//! Specification vectors for `jose::ecdsa_signature_from_der` and
//! `jose::normalize_ecdsa_signature`: RFC 6979 Appendix A.2.5 and A.2.6, and Project Wycheproof's
//! ECDSA test vectors (`tests/wycheproof/`, Apache-2.0).

use identity_kit::jose::{
    DefaultVerifier, EcdsaSignatureError, Jwk, JwsAlgorithm, JwsVerifier as _,
    ecdsa_signature_from_der, normalize_ecdsa_signature,
};
use serde_json::Value;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `SEQUENCE { INTEGER r, INTEGER s }` in DER, for positive big-endian `r` and `s`.
fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
    fn integer(value: &[u8]) -> Vec<u8> {
        let start = value
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(value.len() - 1);
        let mut content = value[start..].to_vec();
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        let mut out = vec![0x02, u8::try_from(content.len()).unwrap()];
        out.extend(content);
        out
    }
    let content = [integer(r), integer(s)].concat();
    let mut out = vec![0x30, u8::try_from(content.len()).unwrap()];
    out.extend(content);
    out
}

// ---------------------------------------------------------------------------------------------
// RFC 6979
// ---------------------------------------------------------------------------------------------

/// RFC 6979 Appendix A.2.5: the P-256 key and the SHA-256 signatures of "sample" and "test".
const RFC6979_P256_UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const RFC6979_P256_UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
const RFC6979_P256: [(&[u8], &str, &str); 2] = [
    (
        b"sample",
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
    ),
    (
        b"test",
        "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
        "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083",
    ),
];

/// RFC 6979 Appendix A.2.6: the SHA-384 signatures of "sample" and "test" with the P-384 key.
const RFC6979_P384: [(&str, &str); 2] = [
    (
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
    ),
    (
        "8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
        "DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5",
    ),
];

#[test]
fn rfc6979_p256_signatures_convert_from_der_and_verify() {
    let public = Jwk::from_p256_public(
        &[&[0x04][..], &hex(RFC6979_P256_UX), &hex(RFC6979_P256_UY)].concat(),
    )
    .unwrap();
    for (message, r, s) in RFC6979_P256 {
        let raw = [hex(r), hex(s)].concat();
        let der = der(&hex(r), &hex(s));
        // `r` of "sample" and both components of "test" have their high bit set or a leading
        // zero, so the DER carries a sign byte or a short integer.
        assert_eq!(
            ecdsa_signature_from_der(JwsAlgorithm::ES256, &der).unwrap(),
            raw
        );
        assert_eq!(
            normalize_ecdsa_signature(JwsAlgorithm::ES256, &raw).unwrap(),
            raw
        );
        DefaultVerifier
            .verify(JwsAlgorithm::ES256, message, &raw, &public)
            .unwrap();
    }
}

#[test]
fn rfc6979_p384_signatures_convert_from_der() {
    for (r, s) in RFC6979_P384 {
        let raw = [hex(r), hex(s)].concat();
        assert_eq!(raw.len(), 96);
        assert_eq!(
            ecdsa_signature_from_der(JwsAlgorithm::ES384, &der(&hex(r), &hex(s))).unwrap(),
            raw
        );
        assert_eq!(
            normalize_ecdsa_signature(JwsAlgorithm::ES384, &raw).unwrap(),
            raw
        );
        // A P-384 signature is too long for P-256.
        assert!(matches!(
            ecdsa_signature_from_der(JwsAlgorithm::ES256, &der(&hex(r), &hex(s))),
            Err(EcdsaSignatureError::ComponentTooLong {
                alg: JwsAlgorithm::ES256,
                len: 48
            })
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// Wycheproof
// ---------------------------------------------------------------------------------------------

/// Flags of test cases whose signature is not a strict DER `ECDSA-Sig-Value`.
const ENCODING_FLAGS: &[&str] = &[
    "BerEncodedSignature",
    "InvalidEncoding",
    "InvalidTypesInSignature",
    "MissingZero",
];

#[derive(Debug, Default)]
struct Tally {
    valid: usize,
    normalized: usize,
    refused_encoding: usize,
    refused_other: usize,
    not_verified: usize,
}

impl Tally {
    /// Every kind of case occurs in the file.
    fn assert_complete(&self) {
        assert!(
            self.valid > 0
                && self.refused_encoding > 0
                && self.refused_other > 0
                && self.not_verified > 0,
            "{self:?}"
        );
    }
}

/// Runs every test case of a Wycheproof ECDSA file over `alg`:
///
/// - a valid case converts, and the converted signature verifies;
/// - a case flagged for its encoding is refused by the conversion;
/// - any other invalid case is refused by the conversion or fails to verify, except, when
///   `high_s_is_invalid`, one whose only fault is a high `s`: the conversion normalizes it, so it
///   verifies.
fn run_wycheproof(json: &str, alg: JwsAlgorithm, high_s_is_invalid: bool) -> Tally {
    let file: Value = serde_json::from_str(json).unwrap();
    let mut tally = Tally::default();
    for group in file["testGroups"].as_array().unwrap() {
        let point = hex(group["publicKey"]["uncompressed"].as_str().unwrap());
        let public = match alg {
            JwsAlgorithm::ES256 => Jwk::from_p256_public(&point).unwrap(),
            #[cfg(feature = "secp256k1")]
            JwsAlgorithm::ES256K => Jwk::from_secp256k1_public(&point).unwrap(),
            other => unreachable!("{other}"),
        };
        for case in group["tests"].as_array().unwrap() {
            let id = case["tcId"].as_u64().unwrap();
            let comment = case["comment"].as_str().unwrap();
            let flags: Vec<&str> = case["flags"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap())
                .collect();
            let message = hex(case["msg"].as_str().unwrap());
            let signature = hex(case["sig"].as_str().unwrap());
            let converted = ecdsa_signature_from_der(alg, &signature);
            let verified = converted
                .as_ref()
                .map(|raw| DefaultVerifier.verify(alg, &message, raw, &public).is_ok());
            if case["result"] == "valid" {
                assert_eq!(
                    verified,
                    Ok(true),
                    "tcId {id} ({comment}, {flags:?}) must convert and verify"
                );
                tally.valid += 1;
            } else if flags.iter().any(|f| ENCODING_FLAGS.contains(f)) {
                assert!(
                    converted.is_err(),
                    "tcId {id} ({comment}, {flags:?}) is not strict DER and must be refused"
                );
                tally.refused_encoding += 1;
            } else {
                // The signature as DER carries it, without normalization: P-256 has the same size.
                let as_given = ecdsa_signature_from_der(JwsAlgorithm::ES256, &signature);
                match verified {
                    Ok(true) if high_s_is_invalid && as_given.as_ref() != converted.as_ref() => {
                        tally.normalized += 1;
                    }
                    Ok(true) => panic!("tcId {id} ({comment}, {flags:?}) must not verify"),
                    Ok(false) => tally.not_verified += 1,
                    Err(_) => tally.refused_other += 1,
                }
            }
        }
    }
    tally
}

#[test]
fn wycheproof_p256_signatures() {
    let tally = run_wycheproof(
        include_str!("wycheproof/ecdsa_secp256r1_sha256_test.json"),
        JwsAlgorithm::ES256,
        false,
    );
    tally.assert_complete();
}

#[cfg(feature = "secp256k1")]
#[test]
fn wycheproof_secp256k1_signatures() {
    // Wycheproof's plain secp256k1 file counts a high `s` as valid, as ECDSA does; converted, it
    // is normalized, so the signature verifies under the low-`s` rule of `DefaultVerifier`.
    let tally = run_wycheproof(
        include_str!("wycheproof/ecdsa_secp256k1_sha256_test.json"),
        JwsAlgorithm::ES256K,
        false,
    );
    tally.assert_complete();
}

#[cfg(feature = "secp256k1")]
#[test]
fn wycheproof_secp256k1_bitcoin_signatures_verify_once_normalized() {
    // The Bitcoin variant refuses a high `s` (`SignatureMalleabilityBitcoin` and some edge
    // cases), as `DefaultVerifier` does. The conversion normalizes it, so it verifies: that is
    // the point.
    let tally = run_wycheproof(
        include_str!("wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json"),
        JwsAlgorithm::ES256K,
        true,
    );
    tally.assert_complete();
    assert!(tally.normalized > 0, "{tally:?}");

    // The same signature, raw and unnormalized, does not verify.
    let file: Value = serde_json::from_str(include_str!(
        "wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json"
    ))
    .unwrap();
    let mut high_s_cases = 0;
    for group in file["testGroups"].as_array().unwrap() {
        let public =
            Jwk::from_secp256k1_public(&hex(group["publicKey"]["uncompressed"].as_str().unwrap()))
                .unwrap();
        for case in group["tests"].as_array().unwrap() {
            if !case["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == "SignatureMalleabilityBitcoin")
            {
                continue;
            }
            let message = hex(case["msg"].as_str().unwrap());
            let normalized =
                ecdsa_signature_from_der(JwsAlgorithm::ES256K, &hex(case["sig"].as_str().unwrap()))
                    .unwrap();
            // `n - s` of the normalized signature is the original high `s`.
            let mut high = normalized.clone();
            negate_s(&mut high);
            assert!(
                DefaultVerifier
                    .verify(JwsAlgorithm::ES256K, &message, &high, &public)
                    .is_err()
            );
            assert_eq!(
                normalize_ecdsa_signature(JwsAlgorithm::ES256K, &high).unwrap(),
                normalized
            );
            high_s_cases += 1;
        }
    }
    assert!(high_s_cases > 0);
}

#[cfg(feature = "secp256k1")]
#[test]
fn es256k_refuses_the_upper_s() {
    // Unlike ES256, ES256K verification accepts only the lower of `s` and `n - s`, as `k256`
    // and most secp256k1 verifiers do. Wycheproof's first valid secp256k1 case: the conversion
    // gives the lower `s`, which verifies; its counterpart does not, until normalized.
    let file: Value =
        serde_json::from_str(include_str!("wycheproof/ecdsa_secp256k1_sha256_test.json")).unwrap();
    let group = &file["testGroups"][0];
    let case = &group["tests"][0];
    assert_eq!(
        (case["tcId"].as_u64(), case["result"].as_str()),
        (Some(1), Some("valid"))
    );
    let public =
        Jwk::from_secp256k1_public(&hex(group["publicKey"]["uncompressed"].as_str().unwrap()))
            .unwrap();
    let message = hex(case["msg"].as_str().unwrap());
    let lower = ecdsa_signature_from_der(JwsAlgorithm::ES256K, &hex(case["sig"].as_str().unwrap()))
        .unwrap();
    DefaultVerifier
        .verify(JwsAlgorithm::ES256K, &message, &lower, &public)
        .unwrap();

    let mut upper = lower.clone();
    negate_s(&mut upper);
    assert_ne!(upper, lower);
    assert_eq!(
        DefaultVerifier.verify(JwsAlgorithm::ES256K, &message, &upper, &public),
        Err(identity_kit::jose::VerificationError::InvalidSignature)
    );
    assert_eq!(
        normalize_ecdsa_signature(JwsAlgorithm::ES256K, &upper).unwrap(),
        lower
    );
}

/// `s := n - s` for a secp256k1 `r || s` (SEC 2 §2.4.1).
#[cfg(feature = "secp256k1")]
fn negate_s(signature: &mut [u8]) {
    let n = hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(n[i]) - i16::from(signature[32 + i]) - borrow;
        borrow = i16::from(digit < 0);
        digit += 256 * borrow;
        signature[32 + i] = u8::try_from(digit).unwrap();
    }
}

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[test]
fn malformed_input_is_refused_with_a_reason() {
    let one = [1u8];
    let ok = der(&one, &one);
    assert_eq!(ok, [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    let mut expected = vec![0; 64];
    expected[31] = 1;
    expected[63] = 1;
    assert_eq!(
        ecdsa_signature_from_der(JwsAlgorithm::ES256, &ok).unwrap(),
        expected
    );

    for (input, reason) in [
        (&[][..], "truncated element"),
        (&[0x31, 0x00], "not a sequence"),
        (&[0x30], "truncated length"),
        (
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00],
            "indefinite length",
        ),
        (
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "length not minimally encoded",
        ),
        // `0x81 0x80` is the minimal form of 128, longer than the input that follows.
        (&[0x30, 0x81, 0x80, 0x02, 0x01, 0x01], "truncated element"),
        (
            &[0x30, 0x82, 0x00, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "length too long for a signature",
        ),
        (
            &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            "truncated element",
        ),
        (
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            "trailing bytes after the sequence",
        ),
        (&[0x30, 0x03, 0x02, 0x01, 0x01], "truncated element"),
        (
            &[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
            ],
            "more than two elements in the sequence",
        ),
        (
            &[0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01],
            "not an integer",
        ),
        (&[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01], "empty integer"),
        (
            &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],
            "negative integer",
        ),
        (
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
            "zero integer",
        ),
        (
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            "integer with a superfluous leading zero",
        ),
    ] {
        assert_eq!(
            ecdsa_signature_from_der(JwsAlgorithm::ES256, input),
            Err(EcdsaSignatureError::InvalidDer(reason)),
            "{input:02x?}"
        );
    }

    // 33 bytes of magnitude do not fit P-256.
    let long = der(&[0x01; 33], &one);
    let err = ecdsa_signature_from_der(JwsAlgorithm::ES256, &long).unwrap_err();
    assert_eq!(
        err,
        EcdsaSignatureError::ComponentTooLong {
            alg: JwsAlgorithm::ES256,
            len: 33
        }
    );
    assert_eq!(
        err.to_string(),
        "ECDSA signature component of 33 bytes is too long for ES256"
    );
}

#[test]
fn only_ecdsa_algorithms_are_converted() {
    let ok = der(&[1], &[1]);
    for alg in [
        JwsAlgorithm::EdDSA,
        JwsAlgorithm::RS256,
        JwsAlgorithm::PS256,
    ] {
        assert_eq!(
            ecdsa_signature_from_der(alg, &ok),
            Err(EcdsaSignatureError::NotEcdsa(alg))
        );
        assert_eq!(
            normalize_ecdsa_signature(alg, &[0; 64]),
            Err(EcdsaSignatureError::NotEcdsa(alg))
        );
    }
    assert_eq!(
        EcdsaSignatureError::NotEcdsa(JwsAlgorithm::EdDSA).to_string(),
        "EdDSA is not an ECDSA algorithm"
    );

    for (alg, expected) in [
        (JwsAlgorithm::ES256, 64),
        (JwsAlgorithm::ES256K, 64),
        (JwsAlgorithm::ES384, 96),
    ] {
        let err = normalize_ecdsa_signature(alg, &[1; 63]).unwrap_err();
        assert_eq!(
            err,
            EcdsaSignatureError::InvalidLength {
                alg,
                expected,
                actual: 63
            }
        );
    }
    assert_eq!(
        normalize_ecdsa_signature(JwsAlgorithm::ES256, &[1; 63])
            .unwrap_err()
            .to_string(),
        "ES256 signature must be 64 bytes, got 63"
    );
}

#[cfg(feature = "secp256k1")]
#[test]
fn es256k_components_must_be_below_the_group_order() {
    // r = 0 cannot be normalized, nor can s = n.
    let mut zero_r = [1u8; 64];
    zero_r[..32].fill(0);
    let mut s_is_n = [1u8; 64];
    s_is_n[32..].copy_from_slice(&hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    ));
    for signature in [zero_r, s_is_n] {
        assert_eq!(
            normalize_ecdsa_signature(JwsAlgorithm::ES256K, &signature),
            Err(EcdsaSignatureError::OutOfRange(JwsAlgorithm::ES256K))
        );
    }
    // A low `s` is returned unchanged.
    let low = [1u8; 64];
    assert_eq!(
        normalize_ecdsa_signature(JwsAlgorithm::ES256K, &low).unwrap(),
        low
    );
}

#[cfg(not(feature = "secp256k1"))]
#[test]
fn es256k_needs_the_secp256k1_feature() {
    assert_eq!(
        normalize_ecdsa_signature(JwsAlgorithm::ES256K, &[1; 64]),
        Err(EcdsaSignatureError::Unsupported(JwsAlgorithm::ES256K))
    );
    assert_eq!(
        ecdsa_signature_from_der(JwsAlgorithm::ES256K, &der(&[1], &[1])),
        Err(EcdsaSignatureError::Unsupported(JwsAlgorithm::ES256K))
    );
}
