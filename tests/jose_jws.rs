//! Specification vectors for JWS: RFC 7515 Appendix A, RFC 8037 Appendix A, RFC 8812 (ES256K,
//! cross-checked with `k256`), and the compact serialization grammar.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::jose::{
    CompactJws, DefaultVerifier, Jwk, JwkError, JwsAlgorithm, JwsError, JwsHeader, JwsVerifier,
    SignError, Signer, VerificationError, encode_compact, normalize_ecdsa_signature,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------------------------

/// RFC 7515 Appendix A.1, the payload shared by A.2 and A.3 (with CRLF and a leading space).
const RFC7515_PAYLOAD: &[u8] =
    b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

/// RFC 7515 Appendix A.2.
const RFC7515_A2_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
const RFC7515_A2_SIGNATURE: &[u8] = &[
    112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6, 174, 27, 129,
    255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10, 253, 60, 150, 238, 221, 115,
    162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110, 1, 135, 237, 16, 115, 249, 69, 229, 130,
    173, 252, 239, 22, 216, 90, 121, 142, 232, 198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2,
    190, 237, 213, 217, 217, 112, 7, 16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184,
    31, 190, 127, 249, 217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4,
    10, 203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202, 208,
    102, 171, 101, 25, 129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175, 221, 59, 239, 177,
    139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202, 173, 21, 145, 18, 115, 160, 95,
    35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41, 239, 90, 30, 136, 121, 130, 54, 195, 212,
    14, 96, 69, 34, 165, 68, 200, 242, 122, 122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222,
    64, 92, 178, 33, 90, 69, 178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42,
    70, 149, 67, 208, 25, 238, 251, 71,
];

/// RFC 7515 Appendix A.3.
const RFC7515_A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const RFC7515_A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
const RFC7515_A3_SIGNATURE: &[u8] = &[
    14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249,
    124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60, 112, 229, 216, 241,
    45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154, 143, 63, 127, 138, 131, 163,
    84, 213,
];

/// RFC 8037 Appendix A.1 to A.5.
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const RFC8037_PAYLOAD: &[u8] = b"Example of Ed25519 signing";
const RFC8037_JWS: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn compact(header: &str, payload: &[u8], signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        b64(header.as_bytes()),
        b64(payload),
        b64(signature)
    )
}

fn rfc7515_a2_key() -> Jwk {
    serde_json::from_value(json!({ "kty": "RSA", "n": RFC7515_A2_N, "e": "AQAB" })).unwrap()
}

fn rfc7515_a2_jws() -> String {
    compact(r#"{"alg":"RS256"}"#, RFC7515_PAYLOAD, RFC7515_A2_SIGNATURE)
}

fn rfc7515_a3_key() -> Jwk {
    serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap()
}

fn rfc7515_a3_jws() -> String {
    compact(r#"{"alg":"ES256"}"#, RFC7515_PAYLOAD, RFC7515_A3_SIGNATURE)
}

fn rfc8037_key() -> Jwk {
    serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X })).unwrap()
}

/// Verifies with `jsonwebtoken` through `Jwk::to_decoding_key`, for the algorithms it has.
fn jsonwebtoken_verifies(jws: &CompactJws, key: &Jwk) -> bool {
    let signature = jws.as_str().rsplit('.').next().unwrap();
    jsonwebtoken::crypto::verify(
        signature,
        jws.signing_input(),
        &key.to_decoding_key().unwrap(),
        jws.alg().try_into().unwrap(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------------
// RFC vectors through `DefaultVerifier`
// ---------------------------------------------------------------------------------------------

#[test]
fn rfc8037_a4_eddsa_verifies() {
    let jws = CompactJws::decode(RFC8037_JWS).unwrap();
    assert_eq!(jws.alg(), JwsAlgorithm::EdDSA);
    assert_eq!(jws.header(), &JwsHeader::new(JwsAlgorithm::EdDSA));
    assert_eq!(jws.payload(), RFC8037_PAYLOAD);
    assert_eq!(
        jws.signing_input(),
        &RFC8037_JWS.as_bytes()[..RFC8037_JWS.rfind('.').unwrap()]
    );
    assert_eq!(jws.as_str(), RFC8037_JWS);
    assert_eq!(jws.to_string(), RFC8037_JWS);

    jws.verify(&DefaultVerifier, &rfc8037_key()).unwrap();
    assert!(jsonwebtoken_verifies(&jws, &rfc8037_key()));
}

#[test]
fn rfc7515_a3_es256_verifies() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    assert_eq!(jws.alg(), JwsAlgorithm::ES256);
    assert_eq!(jws.payload(), RFC7515_PAYLOAD);
    assert_eq!(jws.signature(), RFC7515_A3_SIGNATURE);
    assert_eq!(
        jws.signing_input(),
        b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    );

    jws.verify(&DefaultVerifier, &rfc7515_a3_key()).unwrap();
    DefaultVerifier
        .verify(
            JwsAlgorithm::ES256,
            jws.signing_input(),
            jws.signature(),
            &rfc7515_a3_key(),
        )
        .unwrap();
    assert!(jsonwebtoken_verifies(&jws, &rfc7515_a3_key()));
}

/// The order `n` of the P-256 group (SEC 2 §2.4.2), big-endian.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// `n - s` for a P-256 `s` below `n`, big-endian.
fn p256_order_minus(s: &[u8]) -> Vec<u8> {
    let mut out = vec![0; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(P256_ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(digit < 0);
        digit += 256 * borrow;
        out[i] = u8::try_from(digit).unwrap();
    }
    out
}

#[test]
fn es256_verifies_s_and_n_minus_s_alike() {
    // ECDSA signatures are malleable: when `(r, s)` verifies, so does `(r, n - s)`. RFC 7518 §3.4
    // asks for no canonical `s`, and `DefaultVerifier` accepts both for ES256. RFC 7515 A.3's
    // own signature carries the upper `s` of the two.
    let (r, s) = RFC7515_A3_SIGNATURE.split_at(32);
    let lower_s = p256_order_minus(s);
    assert!(s > lower_s.as_slice());
    let other = [r, &lower_s].concat();

    let original = rfc7515_a3_jws();
    let reencoded = compact(r#"{"alg":"ES256"}"#, RFC7515_PAYLOAD, &other);
    assert_ne!(original, reencoded);
    for token in [&original, &reencoded] {
        let jws = CompactJws::decode(token).unwrap();
        jws.verify(&DefaultVerifier, &rfc7515_a3_key()).unwrap();
        assert_eq!(jws.payload(), RFC7515_PAYLOAD);
    }

    // `normalize_ecdsa_signature` leaves an ES256 signature as it is, whichever `s` it has.
    for signature in [RFC7515_A3_SIGNATURE, &other] {
        assert_eq!(
            normalize_ecdsa_signature(JwsAlgorithm::ES256, signature).unwrap(),
            signature
        );
    }
}

#[test]
fn rfc7515_a2_rs256_verifies_or_is_feature_gated() {
    let jws = CompactJws::decode(&rfc7515_a2_jws()).unwrap();
    assert_eq!(jws.alg(), JwsAlgorithm::RS256);
    assert_eq!(jws.signature().len(), 256);
    let result = jws.verify(&DefaultVerifier, &rfc7515_a2_key());
    #[cfg(feature = "rsa")]
    {
        result.unwrap();
        // A PKCS#1 v1.5 signature is not a PSS signature.
        assert_eq!(
            DefaultVerifier.verify(
                JwsAlgorithm::PS256,
                jws.signing_input(),
                jws.signature(),
                &rfc7515_a2_key()
            ),
            Err(VerificationError::InvalidSignature)
        );
    }
    #[cfg(not(feature = "rsa"))]
    assert_eq!(
        result,
        Err(VerificationError::UnsupportedAlgorithm(JwsAlgorithm::RS256))
    );
    assert!(jsonwebtoken_verifies(&jws, &rfc7515_a2_key()));
}

/// RFC 7515 Appendix A.2 private key components, in the order of PKCS#1 `RSAPrivateKey`.
#[cfg(feature = "rsa")]
const RFC7515_A2_PRIVATE: [&str; 8] = [
    RFC7515_A2_N,
    "AQAB",
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
];

/// PKCS#1 `RSAPrivateKey` (RFC 8017 Appendix A.1.2) for the RFC 7515 Appendix A.2 key.
#[cfg(feature = "rsa")]
fn rfc7515_a2_pkcs1_der() -> Vec<u8> {
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = vec![tag];
        match len {
            0..=0x7f => out.push(len as u8),
            0x80..=0xff => out.extend([0x81, len as u8]),
            _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }
    fn integer(be: &[u8]) -> Vec<u8> {
        let mut content = Vec::with_capacity(be.len() + 1);
        if be[0] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(be);
        tlv(0x02, &content)
    }
    let mut body = integer(&[0]);
    for member in RFC7515_A2_PRIVATE {
        body.extend(integer(&URL_SAFE_NO_PAD.decode(member).unwrap()));
    }
    tlv(0x30, &body)
}

/// RS256 is deterministic, so signing the RFC 7515 Appendix A.2 payload with its key through
/// `jsonwebtoken` must reproduce the signature of the RFC; PS256 is randomized, so the signature
/// `jsonwebtoken` makes is checked by `DefaultVerifier`.
#[cfg(feature = "rsa")]
#[test]
fn rsa_signatures_cross_check_with_jsonwebtoken() {
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(&rfc7515_a2_pkcs1_der());
    let jws = CompactJws::decode(&rfc7515_a2_jws()).unwrap();

    let rs256 = jsonwebtoken::crypto::sign(
        jws.signing_input(),
        &encoding_key,
        jsonwebtoken::Algorithm::RS256,
    )
    .unwrap();
    assert_eq!(rs256, b64(RFC7515_A2_SIGNATURE));

    let ps256 = jsonwebtoken::crypto::sign(
        jws.signing_input(),
        &encoding_key,
        jsonwebtoken::Algorithm::PS256,
    )
    .unwrap();
    let ps256 = URL_SAFE_NO_PAD.decode(ps256).unwrap();
    DefaultVerifier
        .verify(
            JwsAlgorithm::PS256,
            jws.signing_input(),
            &ps256,
            &rfc7515_a2_key(),
        )
        .unwrap();
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::RS256,
            jws.signing_input(),
            &ps256,
            &rfc7515_a2_key()
        ),
        Err(VerificationError::InvalidSignature)
    );
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::PS256,
            b"other input",
            &ps256,
            &rfc7515_a2_key()
        ),
        Err(VerificationError::InvalidSignature)
    );
    // The signature must be exactly as long as the modulus (RFC 7518 §3.5): the `rsa` crate
    // reads it as an integer, so a leading zero byte dropped (one PS256 signature in 256 has
    // one) or added would otherwise still verify.
    for (alg, signature) in [
        (JwsAlgorithm::PS256, ps256[1..].to_vec()),
        (JwsAlgorithm::PS256, [&[0u8][..], &ps256].concat()),
        (JwsAlgorithm::RS256, RFC7515_A2_SIGNATURE[1..].to_vec()),
        (
            JwsAlgorithm::RS256,
            [&[0u8][..], RFC7515_A2_SIGNATURE].concat(),
        ),
    ] {
        assert_eq!(
            DefaultVerifier.verify(alg, jws.signing_input(), &signature, &rfc7515_a2_key()),
            Err(VerificationError::InvalidSignatureLength {
                expected: 256,
                actual: signature.len(),
            }),
            "{alg}"
        );
    }

    // An even modulus is not an RSA key, however long.
    let (mut n, e) = rfc7515_a2_key().rsa_public_components().unwrap();
    *n.last_mut().unwrap() &= 0xfe;
    let even = Jwk::from_rsa_public(&n, &e).unwrap();
    assert!(matches!(
        DefaultVerifier.verify(JwsAlgorithm::RS256, jws.signing_input(), &ps256, &even),
        Err(VerificationError::Key(JwkError::InvalidKey {
            key: "RSA",
            reason,
        })) if !reason.starts_with("the modulus is")
    ));
}

/// RFC 7518 §3.3 and §3.5: RS256 and PS256 need "a key of size 2048 bits or larger". The size
/// is checked before the signature, so a short key is refused whatever the signature, and
/// [`Jwk::to_decoding_key`] refuses it too.
#[test]
fn rsa_keys_shorter_than_2048_bits_are_refused() {
    let rsa = |n: &[u8]| -> Jwk {
        serde_json::from_value(json!({ "kty": "RSA", "n": b64(n), "e": "AQAB" })).unwrap()
    };
    #[cfg(feature = "rsa")]
    let jws = CompactJws::decode(&rfc7515_a2_jws()).unwrap();
    // The RFC 7515 Appendix A.2 modulus is 2048 bits: 256 octets, the first with its top bit set.
    let n = URL_SAFE_NO_PAD.decode(RFC7515_A2_N).unwrap();
    assert_eq!((n.len(), n[0] >> 7), (256, 1));

    // Leading zero octets, which RFC 7518 §6.3.1 forbids but a JWK may carry, add no bits and
    // do not change the key.
    let padded: Jwk = serde_json::from_value(json!({
        "kty": "RSA",
        "n": b64(&[&[0u8][..], &n].concat()),
        "e": b64(&[0, 1, 0, 1]),
    }))
    .unwrap();
    assert!(padded.to_decoding_key().is_ok());
    #[cfg(feature = "rsa")]
    jws.verify(&DefaultVerifier, &padded).unwrap();

    // 1024 bits: the first 128 octets of the modulus, made odd. 2047 bits: the modulus with a
    // first octet of 0x7f, with and without leading zero octets.
    let mut half = n[..128].to_vec();
    *half.last_mut().unwrap() |= 1;
    let mut short = n.clone();
    short[0] = 0x7f;
    for (key, bits) in [
        (rsa(&half), 1024),
        (rsa(&short), 2047),
        (rsa(&[&[0, 0][..], &short].concat()), 2047),
    ] {
        let refused = JwkError::InvalidKey {
            key: "RSA",
            reason: format!("the modulus is {bits} bits; RS256 and PS256 need at least 2048"),
        };
        assert_eq!(key.to_decoding_key().err(), Some(refused.clone()));
        #[cfg(feature = "rsa")]
        for alg in [JwsAlgorithm::RS256, JwsAlgorithm::PS256] {
            for signature in [&[][..], RFC7515_A2_SIGNATURE] {
                assert_eq!(
                    DefaultVerifier.verify(alg, jws.signing_input(), signature, &key),
                    Err(VerificationError::Key(refused.clone())),
                    "{alg} {bits}"
                );
            }
        }
    }
}

#[cfg(feature = "secp256k1")]
#[test]
fn es256k_cross_checks_with_k256() {
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::signature::Verifier as _;

    // A fixed secret scalar, so the (RFC 6979 deterministic) signature is reproducible.
    let secret = [0x11u8; 32];
    let signing_key = k256::ecdsa::SigningKey::from_slice(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();
    let key = Jwk::from_secp256k1_public(&verifying_key.to_sec1_bytes()).unwrap();
    assert_eq!(key.crv(), Some("secp256k1"));

    let signing_input = b"eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJqb2UifQ";
    let signature: k256::ecdsa::Signature = signing_key.sign(signing_input);
    let raw = signature.to_bytes();
    assert_eq!(raw.len(), 64);
    verifying_key.verify(signing_input, &signature).unwrap();

    DefaultVerifier
        .verify(JwsAlgorithm::ES256K, signing_input, &raw, &key)
        .unwrap();
    let mut tampered = raw;
    tampered[10] ^= 1;
    assert_eq!(
        DefaultVerifier.verify(JwsAlgorithm::ES256K, signing_input, &tampered, &key),
        Err(VerificationError::InvalidSignature)
    );
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::ES256K,
            signing_input,
            signature.to_der().as_bytes(),
            &key
        ),
        Err(VerificationError::DerEncodedSignature)
    );
    // A secp256k1 key is not a P-256 key.
    assert!(matches!(
        DefaultVerifier.verify(JwsAlgorithm::ES256, signing_input, &raw, &key),
        Err(VerificationError::Key(JwkError::UnexpectedKeyType {
            expected: "P-256",
            ..
        }))
    ));
    // The algorithm is not one `jsonwebtoken` has.
    assert_eq!(
        jsonwebtoken::Algorithm::try_from(JwsAlgorithm::ES256K)
            .unwrap_err()
            .name(),
        "ES256K"
    );
}

// ---------------------------------------------------------------------------------------------
// Negative verification
// ---------------------------------------------------------------------------------------------

#[test]
fn tampering_is_detected() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    let mut payload = RFC7515_PAYLOAD.to_vec();
    payload[8] = b'J';
    let forged = CompactJws::decode(&compact(
        r#"{"alg":"ES256"}"#,
        &payload,
        RFC7515_A3_SIGNATURE,
    ))
    .unwrap();
    assert_eq!(
        forged.verify(&DefaultVerifier, &rfc7515_a3_key()),
        Err(VerificationError::InvalidSignature)
    );
    let mut signature = RFC7515_A3_SIGNATURE.to_vec();
    signature[0] ^= 0x80;
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::ES256,
            jws.signing_input(),
            &signature,
            &rfc7515_a3_key()
        ),
        Err(VerificationError::InvalidSignature)
    );

    let jws = CompactJws::decode(RFC8037_JWS).unwrap();
    let mut signature = jws.signature().to_vec();
    signature[63] ^= 1;
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::EdDSA,
            jws.signing_input(),
            &signature,
            &rfc8037_key()
        ),
        Err(VerificationError::InvalidSignature)
    );
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::EdDSA,
            b"other input",
            jws.signature(),
            &rfc8037_key()
        ),
        Err(VerificationError::InvalidSignature)
    );
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_keys_need_a_modulus_and_an_exponent() {
    let jws = CompactJws::decode(&rfc7515_a2_jws()).unwrap();
    for (n, e) in [(RFC7515_A2_N, ""), ("", "AQAB")] {
        let key: Jwk = serde_json::from_value(json!({ "kty": "RSA", "n": n, "e": e })).unwrap();
        assert_eq!(
            jws.verify(&DefaultVerifier, &key),
            Err(VerificationError::Key(JwkError::InvalidKey {
                key: "RSA",
                reason: "modulus and exponent must not be empty".to_owned(),
            }))
        );
    }
}

#[test]
fn boxed_and_shared_verifiers_delegate() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    let mut signature = RFC7515_A3_SIGNATURE.to_vec();
    signature[0] ^= 0x80;
    let boxed: Box<dyn JwsVerifier> = Box::new(DefaultVerifier);
    let shared: std::sync::Arc<dyn JwsVerifier> = std::sync::Arc::new(DefaultVerifier);
    for verifier in [&boxed as &dyn JwsVerifier, &shared] {
        jws.verify(verifier, &rfc7515_a3_key()).unwrap();
        assert_eq!(
            verifier.verify(
                JwsAlgorithm::ES256,
                jws.signing_input(),
                &signature,
                &rfc7515_a3_key()
            ),
            Err(VerificationError::InvalidSignature)
        );
    }
}

#[test]
fn wrong_key_type_is_rejected() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    assert!(matches!(
        jws.verify(&DefaultVerifier, &rfc8037_key()),
        Err(VerificationError::Key(JwkError::UnexpectedKeyType {
            expected: "P-256",
            ..
        }))
    ));
    assert!(matches!(
        jws.verify(&DefaultVerifier, &rfc7515_a2_key()),
        Err(VerificationError::Key(JwkError::UnexpectedKeyType {
            expected: "P-256",
            ..
        }))
    ));
    let jws = CompactJws::decode(RFC8037_JWS).unwrap();
    assert!(matches!(
        jws.verify(&DefaultVerifier, &rfc7515_a3_key()),
        Err(VerificationError::Key(JwkError::UnexpectedKeyType {
            expected: "Ed25519",
            ..
        }))
    ));
    #[cfg(feature = "rsa")]
    {
        let jws = CompactJws::decode(&rfc7515_a2_jws()).unwrap();
        assert!(matches!(
            jws.verify(&DefaultVerifier, &rfc8037_key()),
            Err(VerificationError::Key(JwkError::UnexpectedKeyType {
                expected: "RSA",
                ..
            }))
        ));
    }
}

#[test]
fn wrong_signature_length_is_rejected() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    for len in [0, 63, 65, 96] {
        let signature = vec![1u8; len];
        assert_eq!(
            DefaultVerifier.verify(
                JwsAlgorithm::ES256,
                jws.signing_input(),
                &signature,
                &rfc7515_a3_key()
            ),
            Err(VerificationError::InvalidSignatureLength {
                expected: 64,
                actual: len
            }),
            "{len}"
        );
        assert_eq!(
            DefaultVerifier.verify(
                JwsAlgorithm::EdDSA,
                jws.signing_input(),
                &signature,
                &rfc8037_key()
            ),
            Err(VerificationError::InvalidSignatureLength {
                expected: 64,
                actual: len
            }),
            "{len}"
        );
    }
    // An all-zero `r || s` has the right length but is not a valid signature.
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::ES256,
            jws.signing_input(),
            &[0; 64],
            &rfc7515_a3_key()
        ),
        Err(VerificationError::InvalidSignature)
    );
}

#[test]
fn der_encoded_ecdsa_signatures_are_rejected() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    let raw = p256::ecdsa::Signature::from_slice(RFC7515_A3_SIGNATURE).unwrap();
    let der = raw.to_der();
    assert_eq!(der.as_bytes()[0], 0x30);
    assert_ne!(der.as_bytes().len(), 64);
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::ES256,
            jws.signing_input(),
            der.as_bytes(),
            &rfc7515_a3_key()
        ),
        Err(VerificationError::DerEncodedSignature)
    );
}

#[test]
fn key_restrictions_are_honoured() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    let key = rfc7515_a3_key();

    jws.verify(&DefaultVerifier, &key.clone().with_alg("ES256"))
        .unwrap();
    assert_eq!(
        jws.verify(&DefaultVerifier, &key.clone().with_alg("ES384")),
        Err(VerificationError::AlgorithmMismatch {
            alg: JwsAlgorithm::ES256,
            key_alg: "ES384".to_owned()
        })
    );

    jws.verify(&DefaultVerifier, &key.clone().with_key_use("sig"))
        .unwrap();
    assert_eq!(
        jws.verify(&DefaultVerifier, &key.clone().with_key_use("enc")),
        Err(VerificationError::KeyUse("`use` is not `sig`"))
    );

    jws.verify(
        &DefaultVerifier,
        &key.clone().with_key_ops(["sign", "verify"]),
    )
    .unwrap();
    assert_eq!(
        jws.verify(&DefaultVerifier, &key.clone().with_key_ops(["sign"])),
        Err(VerificationError::KeyUse("`key_ops` lacks `verify`"))
    );
}

#[test]
fn es384_is_known_but_not_implemented() {
    let jws = CompactJws::decode(&rfc7515_a3_jws()).unwrap();
    assert_eq!(
        DefaultVerifier.verify(
            JwsAlgorithm::ES384,
            jws.signing_input(),
            jws.signature(),
            &rfc7515_a3_key()
        ),
        Err(VerificationError::UnsupportedAlgorithm(JwsAlgorithm::ES384))
    );
}

#[cfg(not(feature = "secp256k1"))]
#[test]
fn es256k_is_feature_gated() {
    let key: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "secp256k1", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap();
    assert_eq!(
        DefaultVerifier.verify(JwsAlgorithm::ES256K, b"input", &[0; 64], &key),
        Err(VerificationError::UnsupportedAlgorithm(
            JwsAlgorithm::ES256K
        ))
    );
}

#[test]
fn verifier_works_through_references_and_boxes() {
    let jws = CompactJws::decode(RFC8037_JWS).unwrap();
    let boxed: Box<dyn JwsVerifier> = Box::new(DefaultVerifier);
    jws.verify(&boxed, &rfc8037_key()).unwrap();
    jws.verify(boxed.as_ref(), &rfc8037_key()).unwrap();
    let shared = std::sync::Arc::new(DefaultVerifier);
    jws.verify(&shared, &rfc8037_key()).unwrap();
    let by_ref = &DefaultVerifier;
    jws.verify(&by_ref, &rfc8037_key()).unwrap();
}

// ---------------------------------------------------------------------------------------------
// Compact serialization grammar
// ---------------------------------------------------------------------------------------------

#[test]
fn header_parameters_are_exposed_and_preserved() {
    let header = r#"{"typ":"JWT","alg":"ES256","kid":"did:example:123#key-1","cty":"json","x5u":"https://example.com/c","b64":true}"#;
    let jws = CompactJws::decode(&compact(header, b"{}", &[0; 64])).unwrap();
    assert_eq!(jws.kid(), Some("did:example:123#key-1"));
    assert_eq!(jws.header().typ.as_deref(), Some("JWT"));
    assert_eq!(jws.header().cty.as_deref(), Some("json"));
    assert_eq!(jws.header().jwk, None);
    assert_eq!(
        jws.header().additional.get("x5u"),
        Some(&json!("https://example.com/c"))
    );
    assert_eq!(jws.header().additional.get("b64"), Some(&json!(true)));
    assert_eq!(jws.payload(), b"{}");

    let with_jwk = format!(
        r#"{{"alg":"EdDSA","jwk":{}}}"#,
        serde_json::to_string(&rfc8037_key()).unwrap()
    );
    let jws = CompactJws::decode(&compact(&with_jwk, b"{}", &[0; 64])).unwrap();
    assert_eq!(jws.header().jwk.as_ref(), Some(&rfc8037_key()));
}

#[test]
fn malformed_tokens_are_rejected() {
    let good = rfc7515_a3_jws();
    let (h, rest) = good.split_once('.').unwrap();
    let (p, s) = rest.split_once('.').unwrap();

    assert!(matches!(
        CompactJws::decode("").unwrap_err(),
        JwsError::InvalidFormat { parts: 1 }
    ));
    assert!(matches!(
        CompactJws::decode(&format!("{h}.{p}")).unwrap_err(),
        JwsError::InvalidFormat { parts: 2 }
    ));
    assert!(matches!(
        CompactJws::decode(&format!("{good}.extra")).unwrap_err(),
        JwsError::InvalidFormat { parts: 4 }
    ));
    assert!(matches!(
        CompactJws::decode(&format!("{h}=.{p}.{s}")).unwrap_err(),
        JwsError::InvalidBase64Url { part: "header" }
    ));
    assert!(matches!(
        CompactJws::decode(&format!("{h}.{p}+.{s}")).unwrap_err(),
        JwsError::InvalidBase64Url { part: "payload" }
    ));
    assert!(matches!(
        CompactJws::decode(&format!("{h}.{p}.{s}/")).unwrap_err(),
        JwsError::InvalidBase64Url { part: "signature" }
    ));
    // Empty payload and signature parts are syntactically fine.
    let jws = CompactJws::decode(&format!("{h}..")).unwrap();
    assert_eq!(jws.payload(), b"");
    assert_eq!(jws.signature(), b"");
    assert_eq!(jws.signing_input(), format!("{h}.").as_bytes());
}

#[test]
fn bad_headers_are_rejected() {
    fn decode(header: &str) -> JwsError {
        CompactJws::decode(&compact(header, b"{}", &[0; 64])).unwrap_err()
    }
    assert!(matches!(decode("not json"), JwsError::InvalidHeader(_)));
    assert!(matches!(decode("[]"), JwsError::InvalidHeader(_)));
    assert!(matches!(decode(r#"{"typ":"JWT"}"#), JwsError::InvalidHeader(m) if m.contains("alg")));
    assert!(
        matches!(decode(r#"{"alg":"none"}"#), JwsError::UnsupportedAlgorithm(a) if a == "none")
    );
    assert!(
        matches!(decode(r#"{"alg":"HS256"}"#), JwsError::UnsupportedAlgorithm(a) if a == "HS256")
    );
    assert!(
        matches!(decode(r#"{"alg":"es256"}"#), JwsError::UnsupportedAlgorithm(a) if a == "es256")
    );
    assert!(matches!(decode(r#"{"alg":256}"#), JwsError::UnsupportedAlgorithm(a) if a == "256"));
    assert!(matches!(
        decode(r#"{"alg":"ES256","kid":5}"#),
        JwsError::InvalidHeader(_)
    ));
    assert!(matches!(
        decode(r#"{"alg":"ES256","crit":["exp"],"exp":1}"#),
        JwsError::UnsupportedCritical(c) if c == ["exp"]
    ));
    assert!(
        matches!(decode(r#"{"alg":"ES256","crit":[]}"#), JwsError::UnsupportedCritical(c) if c.is_empty())
    );
    assert!(matches!(
        decode(r#"{"alg":"ES256","b64":false}"#),
        JwsError::UnencodedPayload
    ));
}

// ---------------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------------

struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
    kid: Option<String>,
}

impl Ed25519Signer {
    fn rfc8037() -> Self {
        let d: [u8; 32] = URL_SAFE_NO_PAD
            .decode(RFC8037_D)
            .unwrap()
            .try_into()
            .unwrap();
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&d),
            kid: None,
        }
    }
}

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::EdDSA
    }

    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(signing_input).to_bytes().to_vec())
    }
}

struct Es256Signer(p256::ecdsa::SigningKey);

#[async_trait::async_trait]
impl Signer for Es256Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::ES256
    }

    fn kid(&self) -> Option<&str> {
        Some("rfc7515-a3")
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.0.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

struct Failing;

#[async_trait::async_trait]
impl Signer for Failing {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::EdDSA
    }

    fn kid(&self) -> Option<&str> {
        None
    }

    async fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::new(std::io::Error::other("HSM unreachable")))
    }
}

#[tokio::test]
async fn rfc8037_a4_is_reproduced_by_encode_compact() {
    let signer = Ed25519Signer::rfc8037();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA);
    let token = encode_compact(&header, RFC8037_PAYLOAD, &signer)
        .await
        .unwrap();
    assert_eq!(token, RFC8037_JWS);
    assert_eq!(signer.kid(), None);
}

#[tokio::test]
async fn encoded_es256_tokens_verify_here_and_in_jsonwebtoken() {
    let d = URL_SAFE_NO_PAD.decode(RFC7515_A3_D).unwrap();
    let signer = Es256Signer(p256::ecdsa::SigningKey::from_slice(&d).unwrap());
    let header = JwsHeader::new(JwsAlgorithm::ES256)
        .with_kid("did:example:123#key-1")
        .with_typ("JWT");
    let token = encode_compact(&header, RFC7515_PAYLOAD, &signer)
        .await
        .unwrap();

    let jws = CompactJws::decode(&token).unwrap();
    assert_eq!(jws.header(), &header);
    assert_eq!(jws.kid(), Some("did:example:123#key-1"));
    assert_eq!(jws.payload(), RFC7515_PAYLOAD);
    assert_eq!(jws.signature().len(), 64);
    assert!(token.starts_with(&format!(
        "{}.",
        b64(br#"{"alg":"ES256","typ":"JWT","kid":"did:example:123#key-1"}"#)
    )));
    jws.verify(&DefaultVerifier, &rfc7515_a3_key()).unwrap();
    assert!(jsonwebtoken_verifies(&jws, &rfc7515_a3_key()));

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded = jsonwebtoken::decode::<Value>(
        &token,
        &rfc7515_a3_key().to_decoding_key().unwrap(),
        &validation,
    )
    .unwrap();
    assert_eq!(decoded.claims["iss"], "joe");
    assert_eq!(decoded.header.kid.as_deref(), Some("did:example:123#key-1"));
}

#[tokio::test]
async fn encode_compact_checks_the_algorithm_and_reports_signer_errors() {
    let signer = Ed25519Signer::rfc8037();
    let err = encode_compact(&JwsHeader::new(JwsAlgorithm::ES256), b"{}", &signer)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        JwsError::AlgorithmMismatch {
            header: JwsAlgorithm::ES256,
            signer: JwsAlgorithm::EdDSA
        }
    ));

    let err = encode_compact(&JwsHeader::new(JwsAlgorithm::EdDSA), b"{}", &Failing)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "signing failed: HSM unreachable");
    let JwsError::Signer(sign_error) = err else {
        panic!("{err:?}");
    };
    assert!(
        sign_error
            .inner()
            .downcast_ref::<std::io::Error>()
            .is_some()
    );
}

/// An error with a cause, as a key store backend might return.
#[derive(Debug)]
struct Unreachable(std::io::Error);

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HSM unreachable")
    }
}

impl std::error::Error for Unreachable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

#[test]
fn sign_error_is_transparent_to_the_wrapped_error() {
    use std::error::Error as _;

    let error = SignError::new(Unreachable(std::io::Error::other("connection reset")));
    assert_eq!(error.to_string(), "HSM unreachable");
    // The wrapped error's cause comes next in the chain, not the wrapped error a second time.
    let source = error.source().expect("the cause of the wrapped error");
    assert!(source.is::<std::io::Error>());
    assert_eq!(source.to_string(), "connection reset");
    assert!(SignError::msg("no cause").source().is_none());
}

#[tokio::test]
async fn encode_compact_keeps_the_header_as_given() {
    let mut header = JwsHeader::new(JwsAlgorithm::EdDSA);
    header.jwk = Some(rfc8037_key());
    header.additional.insert("zip".to_owned(), json!("DEF"));
    header.additional.insert("alpha".to_owned(), json!(1));
    let token = encode_compact(&header, b"", &Ed25519Signer::rfc8037())
        .await
        .unwrap();
    let header_json = URL_SAFE_NO_PAD
        .decode(token.split('.').next().unwrap())
        .unwrap();
    assert_eq!(
        String::from_utf8(header_json).unwrap(),
        format!(
            r#"{{"alg":"EdDSA","jwk":{},"zip":"DEF","alpha":1}}"#,
            serde_json::to_string(&rfc8037_key()).unwrap()
        )
    );
    let jws = CompactJws::decode(&token).unwrap();
    assert_eq!(jws.header(), &header);
    jws.verify(&DefaultVerifier, jws.header().jwk.as_ref().unwrap())
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------------------------

#[test]
fn algorithm_names_round_trip() {
    for &alg in JwsAlgorithm::ALL {
        let name = alg.to_string();
        assert_eq!(name.parse::<JwsAlgorithm>().unwrap(), alg);
        assert_eq!(alg.as_str(), name);
        assert_eq!(serde_json::to_string(&alg).unwrap(), format!("\"{name}\""));
        assert_eq!(
            serde_json::from_str::<JwsAlgorithm>(&format!("\"{name}\"")).unwrap(),
            alg
        );
    }
    assert_eq!(
        JwsAlgorithm::ALL
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>(),
        ["EdDSA", "ES256", "ES256K", "ES384", "RS256", "PS256"]
    );
    for bad in ["HS256", "none", "es256", "EDDSA", "", "RS384"] {
        let err = bad.parse::<JwsAlgorithm>().unwrap_err();
        assert_eq!(err.name(), bad);
        assert_eq!(
            err.to_string(),
            format!("unknown or unsupported JWS algorithm `{bad}`")
        );
        assert!(serde_json::from_str::<JwsAlgorithm>(&format!("\"{bad}\"")).is_err());
    }
    assert!(JwsAlgorithm::ES256.is_ecdsa());
    assert!(JwsAlgorithm::ES256K.is_ecdsa());
    assert!(JwsAlgorithm::ES384.is_ecdsa());
    assert!(!JwsAlgorithm::EdDSA.is_ecdsa());
    assert!(!JwsAlgorithm::RS256.is_ecdsa());
}

#[test]
fn algorithms_convert_to_and_from_jsonwebtoken() {
    use jsonwebtoken::Algorithm as A;
    for (ours, theirs) in [
        (JwsAlgorithm::EdDSA, A::EdDSA),
        (JwsAlgorithm::ES256, A::ES256),
        (JwsAlgorithm::ES384, A::ES384),
        (JwsAlgorithm::RS256, A::RS256),
        (JwsAlgorithm::PS256, A::PS256),
    ] {
        assert_eq!(JwsAlgorithm::try_from(theirs).unwrap(), ours);
        assert_eq!(A::try_from(ours).unwrap(), theirs);
    }
    for theirs in [
        A::HS256,
        A::HS384,
        A::HS512,
        A::RS384,
        A::RS512,
        A::PS384,
        A::PS512,
    ] {
        let err = JwsAlgorithm::try_from(theirs).unwrap_err();
        assert_eq!(err.name(), format!("{theirs:?}"));
    }
    assert_eq!(
        A::try_from(JwsAlgorithm::ES256K).unwrap_err().name(),
        "ES256K"
    );
}
