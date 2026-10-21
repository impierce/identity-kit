//! Specification vectors for Multikey (`publicKeyMultibase`) conversion: the DIDs of the
//! did:key specification's test vectors, whose method-specific id is the Multikey of the key,
//! and the multicodec table.

use identity_kit::jose::{Jwk, JwkError, KeyCodec};
use serde_json::json;

/// did:key test vectors, "Ed25519 with X25519": the Ed25519 key and the X25519 key the
/// specification derives from it.
const ED25519: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const X25519: &str = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";

fn jwk(value: serde_json::Value) -> Jwk {
    serde_json::from_value(value).unwrap()
}

#[test]
fn ed25519_and_x25519_vectors() {
    let ed25519 = Jwk::from_multikey(ED25519).unwrap();
    assert_eq!(
        serde_json::to_value(&ed25519).unwrap(),
        json!({"kty": "OKP", "crv": "Ed25519", "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"})
    );
    assert_eq!(ed25519.to_multikey().unwrap(), ED25519);

    let x25519 = Jwk::from_multikey(X25519).unwrap();
    assert_eq!(
        serde_json::to_value(&x25519).unwrap(),
        json!({"kty": "OKP", "crv": "X25519", "x": "bl_3kgKpz9jgsg350CNuHa_kQL3B60Gi-98WmdQW2h8"})
    );
    assert_eq!(x25519.to_multikey().unwrap(), X25519);
    assert_eq!(x25519.x25519_public_bytes().unwrap().len(), 32);

    // The second Ed25519 vector.
    let other = Jwk::from_multikey("z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP").unwrap();
    assert_eq!(other.crv(), Some("Ed25519"));
    assert_eq!(
        other.to_multikey().unwrap(),
        "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
    );
}

#[test]
fn p256_vector_is_a_compressed_point() {
    let multikey = "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
    let jwk = Jwk::from_multikey(multikey).unwrap();
    assert_eq!((jwk.kty(), jwk.crv()), ("EC", Some("P-256")));
    // Decompressing the point gives both coordinates.
    assert_eq!(jwk.p256_public_bytes().unwrap()[0], 0x04);
    assert_eq!(jwk.x(), Some("igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns"));
    assert_eq!(jwk.to_multikey().unwrap(), multikey);
}

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_vectors_start_with_zq3s() {
    for multikey in [
        "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
        "zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
    ] {
        let jwk = Jwk::from_multikey(multikey).unwrap();
        assert_eq!((jwk.kty(), jwk.crv()), ("EC", Some("secp256k1")));
        assert_eq!(jwk.secp256k1_public_bytes().unwrap()[0], 0x04);
        assert_eq!(jwk.to_multikey().unwrap(), multikey);
        assert!(multikey.starts_with("zQ3s"));
    }
}

#[cfg(not(feature = "secp256k1"))]
#[test]
fn secp256k1_needs_its_feature() {
    assert_eq!(
        Jwk::from_multikey("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"),
        Err(JwkError::FeatureDisabled {
            key: "secp256k1",
            feature: "secp256k1",
        })
    );
}

#[test]
fn rsa_vector_is_a_pkcs1_public_key() {
    // did:key test vectors (RSA 2048), whose JWK the specification lists.
    let multikey = "z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i";
    let jwk = Jwk::from_multikey(multikey).unwrap();
    assert_eq!(
        serde_json::to_value(&jwk).unwrap(),
        json!({
            "kty": "RSA",
            "n": "sbX82NTV6IylxCh7MfV4hlyvaniCajuP97GyOqSvTmoEdBOflFvZ06kR_9D6ctt45Fk6hskfnag2GG69NALVH2o4RCR6tQiLRpKcMRtDYE_thEmfBvDzm_VVkOIYfxu-Ipuo9J_S5XDNDjczx2v-3oDh5-CIHkU46hvFeCvpUS-L8TJSbgX0kjVk_m4eIb9wh63rtmD6Uz_KBtCo5mmR4TEtcLZKYdqMp3wCjN-TlgHiz_4oVXWbHUefCEe8rFnX1iQnpDHU49_SaXQoud1jCaexFn25n-Aa8f8bc5Vm-5SeRwidHa6ErvEhTvf1dz6GoNPp2iRvm-wJ1gxwWJEYPQ",
            "e": "AQAB"
        })
    );
    assert_eq!(jwk.rsa_public_components().unwrap().0.len(), 256);
    assert_eq!(jwk.to_multikey().unwrap(), multikey);

    // The `rsa-pub` payload after the multicodec header (`0x1205`) is the PKCS #1 key itself.
    let bytes = bs58::decode(&multikey[1..]).into_vec().unwrap();
    assert_eq!(bytes[..2], [0x85, 0x24]);
    let payload = &bytes[2..];
    assert_eq!(Jwk::from_pkcs1_der(payload).unwrap(), jwk);
    assert_eq!(jwk.to_pkcs1_der().unwrap(), payload);
}

#[test]
fn unknown_codecs_are_reported() {
    // P-384 (`p384-pub`, 0x1201) and BLS12-381 G2 (0xeb) vectors of the specification.
    assert_eq!(
        Jwk::from_multikey(
            "z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54"
        ),
        Err(JwkError::UnsupportedMulticodec(0x1201))
    );
    assert_eq!(
        Jwk::from_multikey(
            "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb"
        ),
        Err(JwkError::UnsupportedMulticodec(0xeb))
    );
}

#[test]
fn malformed_multikeys_are_rejected() {
    let base58 = |bytes: &[u8]| format!("z{}", bs58::encode(bytes).into_string());
    for (multikey, message) in [
        ("6MkhaXg", "expected the base58btc multibase prefix `z`"),
        ("u7QEA", "expected the base58btc multibase prefix `z`"),
        ("z0OIl", "invalid base58btc"),
        (
            &base58(&[0x80]),
            "multicodec header is truncated or too long",
        ),
        (
            &base58(&[0xed, 0x80, 0x00, 1, 2]),
            "multicodec header is not minimally encoded",
        ),
        ("z", "multicodec header is truncated or too long"),
    ] {
        match Jwk::from_multikey(multikey) {
            Err(JwkError::InvalidMultikey(reason)) => {
                assert!(reason.contains(message), "{multikey}: {reason}");
            }
            other => panic!("{multikey}: {other:?}"),
        }
    }
    // Wrong key length, and an invalid key of the right length.
    assert_eq!(
        Jwk::from_multikey(&base58(&[&[0xed, 0x01][..], &[7; 31]].concat())),
        Err(JwkError::InvalidKeyLength {
            key: "Ed25519",
            expected: 32,
            actual: 31,
        })
    );
    assert_eq!(
        Jwk::from_multikey(&base58(&[&[0x80, 0x24][..], &[0x04; 33]].concat()))
            .unwrap_err()
            .to_string()
            .split(':')
            .next(),
        Some("invalid P-256 key")
    );
    assert!(matches!(
        Jwk::from_multikey(&base58(&[&[0x85, 0x24][..], &[0x30, 0x00]].concat())),
        Err(JwkError::InvalidKey { key: "RSA", .. })
    ));
}

#[test]
fn keys_without_a_codec_cannot_be_encoded() {
    let oct = jwk(json!({"kty": "oct", "k": "AQAB"}));
    assert_eq!(
        oct.to_multikey(),
        Err(JwkError::UnsupportedKeyType {
            kty: "oct".to_owned(),
            crv: None,
        })
    );
    let p384 = jwk(json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}));
    assert!(matches!(
        p384.to_multikey(),
        Err(JwkError::UnsupportedKeyType { .. })
    ));
    // Only the public part is encoded.
    let private = jwk(json!({
        "kty": "OKP", "crv": "Ed25519",
        "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }));
    assert_eq!(private.to_multikey().unwrap(), ED25519);
}

#[test]
fn x25519_jwk_constructors() {
    let x25519 = Jwk::from_multikey(X25519).unwrap();
    let bytes = x25519.x25519_public_bytes().unwrap();
    assert_eq!(Jwk::from_x25519_public(&bytes).unwrap(), x25519);
    assert_eq!(
        Jwk::from_x25519_public(&bytes[..31]),
        Err(JwkError::InvalidKeyLength {
            key: "X25519",
            expected: 32,
            actual: 31,
        })
    );
    let ed25519 = Jwk::from_multikey(ED25519).unwrap();
    assert_eq!(
        ed25519.x25519_public_bytes(),
        Err(JwkError::UnexpectedKeyType {
            expected: "X25519",
            kty: "OKP".to_owned(),
            crv: Some("Ed25519".to_owned()),
        })
    );
    assert_eq!(
        x25519.thumbprint_sha256().unwrap().len(),
        43,
        "an OKP thumbprint covers crv, kty and x"
    );
}

#[test]
fn codec_table() {
    // multicodec table.csv: name, code, raw key length.
    for (codec, name, code, len) in [
        (KeyCodec::Secp256k1, "secp256k1-pub", 0xe7, Some(33)),
        (KeyCodec::X25519, "x25519-pub", 0xec, Some(32)),
        (KeyCodec::Ed25519, "ed25519-pub", 0xed, Some(32)),
        (KeyCodec::P256, "p256-pub", 0x1200, Some(33)),
        (KeyCodec::Rsa, "rsa-pub", 0x1205, None),
    ] {
        assert_eq!(codec.name(), name);
        assert_eq!(codec.code(), code);
        assert_eq!(codec.key_len(), len);
        assert_eq!(KeyCodec::from_code(code), Some(codec));
    }
    assert_eq!(KeyCodec::from_code(0x1201), None);
}
