//! JWE (feature `jwe`): the encrypted response of OpenID4VP §8.3 decrypted with the Verifier's
//! key, encryption to a Verifier's key with both content encryption algorithms HAIP §5
//! requires, and the checks a recipient makes before and while decrypting.
#![cfg(feature = "jwe")]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::jose::{
    CompactJwe, EcdhKey, JweAlgorithm, JweDecrypter, JweEncryption, JweError, JweHeader, Jwk,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// OpenID4VP §8.3: the response encrypted to the Verifier's key `ac`.
const RESPONSE: &str = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6ImFjIiwiZXBrIjp7Imt\
    0eSI6IkVDIiwieCI6Im5ubVZwbTNWM2piaGNhZlFhUkJrU1ZOSGx3Wkh3dC05ck9wSnVmeVlJdWsiLCJ5I\
    joicjRmakRxd0p5czlxVU9QLV9iM21SNVNaRy0tQ3dPMm1pYzVWU05UWU45ZyIsImNydiI6IlAtMjU2In1\
    9..uAYcHRUSSn2X0WPX.yVzlGSYG4qbg0bq18JcUiDRw56yVnbKR8E7S7YlEtzT00RqE3Pw5oTpUG3hdLN\
    4taHZ9gC1kwak8JOnJgQ.1wR024_3-qtAlx1oFIUpQQ";

/// OpenID4VP §8.3: the Verifier's key, with `d`.
fn verifier_jwk() -> Jwk {
    serde_json::from_value(json!({
        "kty": "EC", "kid": "ac", "use": "enc", "crv": "P-256", "alg": "ECDH-ES",
        "x": "YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
        "y": "Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
        "d": "Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"
    }))
    .unwrap()
}

fn verifier() -> EcdhKey {
    EcdhKey::from_jwk(&verifier_jwk()).unwrap()
}

/// RFC 7518 Appendix C: Bob's key, another P-256 key.
fn other_jwk() -> Jwk {
    serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
    }))
    .unwrap()
}

/// `token` with part `index` replaced by `part`.
fn with_part(token: &str, index: usize, part: &str) -> String {
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[index] = part;
    parts.join(".")
}

/// The OpenID4VP response with its protected header changed by `change`.
fn with_header(change: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let header = RESPONSE.split('.').next().unwrap();
    let mut value: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
    change(value.as_object_mut().unwrap());
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    with_part(RESPONSE, 0, &header)
}

fn decode_err(token: &str) -> JweError {
    CompactJwe::decode(token).unwrap_err()
}

#[tokio::test]
async fn openid4vp_response_decrypts_with_the_verifier_key() {
    let jwe = CompactJwe::decode(RESPONSE).unwrap();
    let header = jwe.header();
    assert_eq!(header.alg, JweAlgorithm::EcdhEs);
    assert_eq!(header.enc, JweEncryption::A128Gcm);
    assert_eq!(jwe.kid(), Some("ac"));
    let epk = header.epk.as_ref().unwrap();
    assert_eq!(epk.crv(), Some("P-256"));
    assert_eq!(epk.x(), Some("nnmVpm3V3jbhcafQaRBkSVNHlwZHwt-9rOpJufyYIuk"));
    assert_eq!(jwe.as_str(), RESPONSE);
    assert_eq!(jwe.to_string(), RESPONSE);

    let payload = jwe.decrypt(&verifier()).await.unwrap();
    let payload: Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(
        payload,
        json!({"vp_token": {"example_credential_id": ["eyJhb...YMetA"]}})
    );
}

/// HAIP §5: a Verifier decrypts both A128GCM and A256GCM; a Wallet encrypts with either.
#[tokio::test]
async fn round_trip_with_both_content_encryption_algorithms() {
    let verifier = EcdhKey::generate().unwrap();
    let public = verifier.public_jwk().with_kid("request-1");
    assert_eq!(public.key_use(), Some("enc"));
    assert_eq!(public.alg(), Some("ECDH-ES"));
    assert!(!public.is_private());

    for enc in [JweEncryption::A128Gcm, JweEncryption::A256Gcm] {
        let payload = br#"{"vp_token":{"pid":["eyJ..."]},"state":"s"}"#;
        let header = JweHeader::new(JweAlgorithm::EcdhEs, enc);
        let jwe = CompactJwe::encrypt(header, payload, &public).unwrap();
        // The `kid` of the Verifier's key, as OpenID4VP §8.3 requires, and a fresh `epk`.
        assert_eq!(jwe.kid(), Some("request-1"));
        assert_eq!(jwe.header().enc, enc);
        assert!(jwe.as_str().split('.').nth(1).unwrap().is_empty());

        let received = CompactJwe::decode(jwe.as_str()).unwrap();
        assert_eq!(received.decrypt(&verifier).await.unwrap(), payload);
    }

    // Two encryptions of the same payload share neither the ephemeral key nor the IV.
    let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A128Gcm);
    let first = CompactJwe::encrypt(header.clone(), b"same", &public).unwrap();
    let second = CompactJwe::encrypt(header, b"same", &public).unwrap();
    assert_ne!(first.header().epk, second.header().epk);
    assert_ne!(
        first.as_str().split('.').nth(2),
        second.as_str().split('.').nth(2)
    );
}

#[tokio::test]
async fn party_info_and_header_members_are_kept() {
    let verifier = verifier();
    let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A256Gcm)
        .with_typ("oauth-authz-resp+jwt")
        .with_apu(b"wallet nonce")
        .with_apv(b"verifier nonce");
    let jwe = CompactJwe::encrypt(header, b"{}", &verifier.public_jwk()).unwrap();
    let received = CompactJwe::decode(jwe.as_str()).unwrap();
    assert_eq!(
        received.header().typ.as_deref(),
        Some("oauth-authz-resp+jwt")
    );
    assert_eq!(received.header().apu.as_deref(), Some("d2FsbGV0IG5vbmNl"));
    // The public key carries no `kid`, so neither does the JWE.
    assert_eq!(received.kid(), None);
    assert_eq!(received.decrypt(&verifier).await.unwrap(), b"{}");
}

/// A Verifier keeps its key between the request and the response as a private JWK.
#[tokio::test]
async fn a_key_survives_as_a_private_jwk() {
    let key = EcdhKey::generate().unwrap();
    let stored = serde_json::to_string(&key.to_jwk()).unwrap();
    assert!(stored.contains(r#""d":"#));
    let debug = format!("{key:?}");
    let d = serde_json::from_str::<Value>(&stored).unwrap()["d"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!debug.contains(&d), "{debug}");

    let header = JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A128Gcm);
    let jwe = CompactJwe::encrypt(header, b"payload", &key.public_jwk()).unwrap();
    let restored = EcdhKey::from_jwk(&serde_json::from_str(&stored).unwrap()).unwrap();
    assert_eq!(jwe.decrypt(&restored).await.unwrap(), b"payload");
}

#[tokio::test]
async fn altered_parts_and_other_keys_fail_alike() {
    let verifier = verifier();
    let jwe = CompactJwe::decode(RESPONSE).unwrap();
    let wrong_key = EcdhKey::from_jwk(&other_jwk()).unwrap();
    assert!(matches!(
        jwe.decrypt(&wrong_key).await,
        Err(JweError::DecryptionFailed)
    ));

    let parts: Vec<&str> = RESPONSE.split('.').collect();
    let flip = |part: &str| {
        let mut bytes = URL_SAFE_NO_PAD.decode(part).unwrap();
        bytes[0] ^= 1;
        URL_SAFE_NO_PAD.encode(bytes)
    };
    for (index, altered) in [
        (2, flip(parts[2])),
        (3, flip(parts[3])),
        (4, flip(parts[4])),
    ] {
        let token = with_part(RESPONSE, index, &altered);
        let error = CompactJwe::decode(&token)
            .unwrap()
            .decrypt(&verifier)
            .await
            .unwrap_err();
        assert!(matches!(error, JweError::DecryptionFailed), "part {index}");
    }
    // The protected header is authenticated as received: a member added to it, or the same
    // header encoded otherwise, fails the tag.
    let with_typ = with_header(|header| {
        header.insert("typ".to_owned(), json!("JWT"));
    });
    let reordered = with_header(|header| {
        let enc = header.shift_remove("enc").unwrap();
        header.insert("enc".to_owned(), enc);
    });
    for token in [with_typ, reordered] {
        let error = CompactJwe::decode(&token)
            .unwrap()
            .decrypt(&verifier)
            .await
            .unwrap_err();
        assert!(matches!(error, JweError::DecryptionFailed));
    }
}

#[test]
fn malformed_serializations_are_refused() {
    assert!(matches!(
        decode_err("a.b.c"),
        JweError::InvalidFormat { parts: 3 }
    ));
    assert!(matches!(
        decode_err(&format!("{RESPONSE}.x")),
        JweError::InvalidFormat { parts: 6 }
    ));
    assert!(matches!(
        decode_err(&with_part(RESPONSE, 0, "e30=")),
        JweError::InvalidBase64Url { part: "header" }
    ));
    for (index, part) in [(2, "iv"), (3, "ciphertext"), (4, "tag")] {
        assert!(
            matches!(
                decode_err(&with_part(RESPONSE, index, "!")),
                JweError::InvalidBase64Url { part: found } if found == part
            ),
            "{part}"
        );
    }
    // ECDH-ES in the Direct Key Agreement mode has an empty JWE Encrypted Key.
    assert!(matches!(
        decode_err(&with_part(RESPONSE, 1, "AAAA")),
        JweError::UnexpectedEncryptedKey
    ));
    // AES-GCM has a 96-bit IV and a 128-bit tag.
    assert!(matches!(
        decode_err(&with_part(RESPONSE, 2, "AAAAAAAAAAAAAAAAAAAA")),
        JweError::InvalidLength {
            part: "iv",
            expected: 12,
            found: 15
        }
    ));
    assert!(matches!(
        decode_err(&with_part(RESPONSE, 4, "AAAAAAAAAAAA")),
        JweError::InvalidLength {
            part: "tag",
            expected: 16,
            found: 9
        }
    ));
}

#[test]
fn headers_this_crate_cannot_honour_are_refused() {
    let unsupported_alg = with_header(|header| {
        header.insert("alg".to_owned(), json!("RSA-OAEP"));
    });
    assert!(
        matches!(decode_err(&unsupported_alg), JweError::UnsupportedAlgorithm(alg) if alg == "RSA-OAEP")
    );
    let key_wrap = with_header(|header| {
        header.insert("alg".to_owned(), json!("ECDH-ES+A128KW"));
    });
    assert!(matches!(
        decode_err(&key_wrap),
        JweError::UnsupportedAlgorithm(_)
    ));
    let cbc = with_header(|header| {
        header.insert("enc".to_owned(), json!("A128CBC-HS256"));
    });
    assert!(
        matches!(decode_err(&cbc), JweError::UnsupportedEncryption(enc) if enc == "A128CBC-HS256")
    );
    let no_enc = with_header(|header| {
        header.remove("enc");
    });
    assert!(matches!(
        decode_err(&no_enc),
        JweError::InvalidHeader { .. }
    ));
    let no_alg = with_header(|header| {
        header.remove("alg");
    });
    assert!(matches!(
        decode_err(&no_alg),
        JweError::InvalidHeader { .. }
    ));
    let numeric_alg = with_header(|header| {
        header.insert("alg".to_owned(), json!(1));
    });
    assert!(matches!(
        decode_err(&numeric_alg),
        JweError::UnsupportedAlgorithm(_)
    ));
    let crit = with_header(|header| {
        header.insert("crit".to_owned(), json!(["exp"]));
        header.insert("exp".to_owned(), json!(1));
    });
    assert!(matches!(decode_err(&crit), JweError::UnsupportedCritical(names) if names == ["exp"]));
    let zip = with_header(|header| {
        header.insert("zip".to_owned(), json!("DEF"));
    });
    assert!(matches!(decode_err(&zip), JweError::UnsupportedCompression(zip) if zip == "DEF"));
    let not_an_object = with_part(RESPONSE, 0, &URL_SAFE_NO_PAD.encode("[]"));
    assert!(matches!(
        decode_err(&not_an_object),
        JweError::InvalidHeader { .. }
    ));
    let bad_apu = with_header(|header| {
        header.insert("apu".to_owned(), json!("not base64url!"));
    });
    assert!(matches!(
        decode_err(&bad_apu),
        JweError::InvalidHeader { .. }
    ));
}

/// RFC 7518 §4.6.1.1: `epk` is present, public and, for a P-256 recipient, a P-256 point.
#[test]
fn the_ephemeral_key_is_checked() {
    let missing = with_header(|header| {
        header.remove("epk");
    });
    assert!(matches!(
        decode_err(&missing),
        JweError::InvalidHeader { .. }
    ));

    let private = with_header(|header| {
        header["epk"]["d"] = json!("Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww");
    });
    assert!(matches!(decode_err(&private), JweError::InvalidKey { .. }));

    // A point off the curve, the start of an invalid-curve attack.
    let off_curve = with_header(|header| {
        header["epk"]["y"] = json!("Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okg");
    });
    assert!(matches!(
        decode_err(&off_curve),
        JweError::InvalidKey { .. }
    ));

    // OpenID4VP §8.3's P-384 key.
    let other_curve = with_header(|header| {
        header["epk"] = json!({
            "kty": "EC", "crv": "P-384",
            "x": "iHytgLNtXjEyYMAIGwfgjINZRmLfObYbmjPhkaPD8OiTkJtRHjegTNdH31Mxg4nV",
            "y": "MizXWSqNB7sSt_SNjg3spvaJnmjB-LpxsPpLUaea33rvINL3Mq-gEaANErRQpbLx"
        });
    });
    assert!(matches!(
        decode_err(&other_curve),
        JweError::InvalidKey { .. }
    ));
}

/// OpenID4VP §8.3: the Wallet encrypts with the `alg` of the Verifier's key, to a key meant
/// for encryption, under its `kid`.
#[test]
fn encryption_refuses_keys_and_headers_that_do_not_fit() {
    let header = || JweHeader::new(JweAlgorithm::EcdhEs, JweEncryption::A128Gcm);
    let public = verifier_jwk().public();
    let refused = |recipient: &Jwk| {
        matches!(
            CompactJwe::encrypt(header(), b"{}", recipient),
            Err(JweError::InvalidKey { .. })
        )
    };
    assert!(refused(&public.clone().with_key_use("sig")));
    assert!(refused(&public.clone().with_alg("ECDH-ES+A128KW")));
    let x25519: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "kid": "jc", "use": "enc", "crv": "X25519", "alg": "ECDH-ES",
        "x": "WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"
    }))
    .unwrap();
    assert!(refused(&x25519));

    let invalid_header = |header: JweHeader| {
        matches!(
            CompactJwe::encrypt(header, b"{}", &public),
            Err(JweError::InvalidHeader { .. })
        )
    };
    assert!(invalid_header(header().with_kid("another key")));
    let mut with_epk = header();
    with_epk.epk = Some(public.clone());
    assert!(invalid_header(with_epk));
    let mut with_zip = header();
    with_zip.additional.insert("zip".to_owned(), json!("DEF"));
    assert!(invalid_header(with_zip));
    // What decoding refuses, encryption does not produce: `crit`, even empty, and a field
    // shadowed by an additional parameter of its name.
    let mut with_crit = header();
    with_crit.crit = Some(Vec::new());
    assert!(invalid_header(with_crit));
    for name in ["alg", "enc", "kid", "epk", "apu", "crit"] {
        let mut shadowed = header();
        shadowed
            .additional
            .insert(name.to_owned(), json!("A256GCM"));
        assert!(invalid_header(shadowed), "{name}");
    }
    // Other additional parameters are kept.
    let mut extended = header();
    extended
        .additional
        .insert("x-request".to_owned(), json!("r1"));
    let jwe = CompactJwe::encrypt(extended, b"{}", &public).unwrap();
    assert_eq!(
        CompactJwe::decode(jwe.as_str())
            .unwrap()
            .header()
            .additional["x-request"],
        "r1"
    );

    // The same `kid` is no conflict.
    let jwe = CompactJwe::encrypt(header().with_kid("ac"), b"{}", &public).unwrap();
    assert_eq!(jwe.kid(), Some("ac"));
}

#[test]
fn private_keys_must_be_whole_and_consistent() {
    let invalid = |jwk: &Jwk| matches!(EcdhKey::from_jwk(jwk), Err(JweError::InvalidKey { .. }));
    assert!(invalid(&verifier_jwk().public()));
    let mut mixed = serde_json::to_value(verifier_jwk()).unwrap();
    mixed["d"] = serde_json::to_value(other_jwk()).unwrap()["d"].clone();
    assert!(invalid(&serde_json::from_value(mixed).unwrap()));
    let mut short = serde_json::to_value(verifier_jwk()).unwrap();
    short["d"] = json!("AQ");
    assert!(invalid(&serde_json::from_value(short).unwrap()));
    let x25519: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "X25519", "x": "WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc",
        "d": "Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"
    }))
    .unwrap();
    assert!(invalid(&x25519));
}

/// A key kept elsewhere, an HSM say, is a `JweDecrypter` of its own; its failure reaches the
/// caller, and the crate does the rest of the decryption.
#[tokio::test]
async fn decrypters_behind_pointers_and_of_other_backends() {
    struct Hsm(EcdhKey);

    #[async_trait::async_trait]
    impl JweDecrypter for Hsm {
        async fn shared_secret(&self, epk: &Jwk) -> Result<Zeroizing<Vec<u8>>, JweError> {
            self.0.shared_secret(epk).await
        }
    }

    struct Offline;

    #[async_trait::async_trait]
    impl JweDecrypter for Offline {
        async fn shared_secret(&self, _: &Jwk) -> Result<Zeroizing<Vec<u8>>, JweError> {
            Err(JweError::KeyAgreement("the HSM is offline".into()))
        }
    }

    let jwe = CompactJwe::decode(RESPONSE).unwrap();
    let boxed: Box<dyn JweDecrypter> = Box::new(Hsm(verifier()));
    assert!(jwe.decrypt(&boxed).await.is_ok());
    assert!(jwe.decrypt(&Arc::new(verifier())).await.is_ok());
    assert!(jwe.decrypt(&&verifier()).await.is_ok());
    let error = jwe.decrypt(&Offline).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "key agreement failed: the HSM is offline"
    );
}

#[test]
fn names_and_errors() {
    assert_eq!(
        "A128GCM".parse::<JweEncryption>().unwrap(),
        JweEncryption::A128Gcm
    );
    assert_eq!(JweEncryption::A256Gcm.to_string(), "A256GCM");
    assert_eq!(JweEncryption::A128Gcm.key_len(), 16);
    assert_eq!(JweEncryption::A256Gcm.key_len(), 32);
    assert!(matches!(
        "dir".parse::<JweAlgorithm>(),
        Err(JweError::UnsupportedAlgorithm(alg)) if alg == "dir"
    ));
    assert_eq!(
        JweError::DecryptionFailed.to_string(),
        "JWE decryption failed"
    );
    assert_eq!(
        decode_err(&with_part(RESPONSE, 1, "AAAA")).to_string(),
        "JWE Encrypted Key must be empty for `ECDH-ES`"
    );
    let debug = format!("{:?}", CompactJwe::decode(RESPONSE).unwrap());
    assert!(
        debug.contains("A128Gcm") && !debug.contains("yVzlGSYG"),
        "{debug}"
    );
}
