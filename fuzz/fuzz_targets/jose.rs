//! JOSE (RFC 7515, RFC 7517, RFC 7638, Multikey, PKCS #1): compact JWS decoding, JWK
//! deserialization, the key encodings and signature verification with any key never panic.
//!
//! The input is a compact JWS on the first line, followed by a JWK as JSON; either part may be
//! absent. The bytes after the first line are also tried as a DER `SubjectPublicKeyInfo` and a
//! DER PKCS #1 `RSAPublicKey`.
#![no_main]

use std::str::FromStr as _;
use std::sync::LazyLock;

use identity_kit::jose::{CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, KeyType};
use libfuzzer_sys::fuzz_target;

/// The Ed25519 key of RFC 8037 Appendix A.1 and the P-256 key of RFC 7515 Appendix A.3.
static KEYS: LazyLock<[Jwk; 2]> = LazyLock::new(|| {
    [
        serde_json::from_str(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .expect("a valid JWK"),
        serde_json::from_str(
            r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#,
        )
        .expect("a valid JWK"),
    ]
});

fn exercise_jws(token: &str, keys: &[&Jwk]) {
    let Ok(jws) = CompactJws::decode(token) else {
        return;
    };
    assert_eq!(jws.as_str(), token);
    assert!(token.as_bytes().starts_with(jws.signing_input()));
    assert_eq!(jws.header().alg, jws.alg());
    assert_eq!(jws.header().kid.as_deref(), jws.kid());
    let _ = jws.payload();
    let _ = jws.signature();
    for key in keys {
        // Verification never panics; it succeeds only for a genuine signature, which the input
        // may carry when it is a specification vector next to its key.
        let _ = jws.verify(&DefaultVerifier, key);
    }
}

fn exercise_jwk(jwk: &Jwk) {
    let json = serde_json::to_string(jwk).expect("a JWK serializes");
    let again: Jwk = serde_json::from_str(&json).expect("a serialized JWK parses");
    assert_eq!(&again, jwk);

    let public = jwk.public();
    assert!(!public.is_private());
    assert_eq!(public.public(), public);
    // A symmetric key's thumbprint is built from `k`, its secret, which `public` strips.
    if jwk.kty() != "oct" {
        assert_eq!(
            public.thumbprint_sha256().is_ok(),
            jwk.thumbprint_sha256().is_ok()
        );
        assert_eq!(
            jwk.thumbprint_sha256().ok(),
            public.thumbprint_sha256().ok()
        );
    }

    let _ = jwk.ed25519_public_bytes();
    let _ = jwk.x25519_public_bytes();
    let _ = jwk.p256_public_bytes();
    let _ = jwk.secp256k1_public_bytes();
    if let Ok(multikey) = jwk.to_multikey() {
        let back = Jwk::from_multikey(&multikey).expect("an encoded Multikey decodes");
        assert_eq!(back.to_multikey().as_deref(), Ok(multikey.as_str()));
        assert_eq!(back.public(), back);
        assert_eq!((back.kty(), back.crv()), (jwk.kty(), jwk.crv()));
    }
}

fuzz_target!(|data: &[u8]| {
    let (token, rest) = match data.iter().position(|&b| b == b'\n') {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &[][..]),
    };
    let parsed: Option<Jwk> = serde_json::from_slice(rest).ok();
    if let Some(jwk) = &parsed {
        exercise_jwk(jwk);
    }
    let keys: Vec<&Jwk> = KEYS.iter().chain(parsed.iter()).collect();

    if let Ok(token) = std::str::from_utf8(token) {
        exercise_jws(token, &keys);
        let _ = JwsAlgorithm::from_str(token);
        if let Ok(jwk) = Jwk::from_multikey(token) {
            assert_eq!(jwk.to_multikey().as_deref(), Ok(token));
            exercise_jwk(&jwk);
        }
    }
    for key_type in [
        KeyType::Ed25519,
        KeyType::P256,
        KeyType::Secp256k1,
        KeyType::Rsa2048,
    ] {
        if let Ok(jwk) = Jwk::from_spki_der(key_type, rest) {
            exercise_jwk(&jwk);
        }
    }
    if let Ok(jwk) = Jwk::from_pkcs1_der(rest) {
        // DER has one encoding per key, so whatever parses is re-encoded byte for byte.
        assert_eq!(jwk.to_pkcs1_der().as_deref(), Ok(rest));
        exercise_jwk(&jwk);
    }
});
