//! Specification vectors for `Jwk` (RFC 7517, RFC 7518, RFC 7638, RFC 8037, RFC 8410, RFC 5480).
#![expect(
    clippy::cast_possible_truncation,
    reason = "DER lengths here are below 0x10000, and the test modulus bytes wrap on purpose"
)]

use std::error::Error as _;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use identity_kit::jose::{Jwk, JwkError, KeyType};
use proptest::prelude::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------------------------

/// RFC 7517 Appendix A.1, first key.
const RFC7517_A1_EC: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}"#;

/// RFC 7517 Appendix A.2, first key.
const RFC7517_A2_EC_PRIVATE: &str = r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#;

/// RFC 7638 §3.1 (also RFC 7517 Appendix A.1, second key).
const RFC7638_RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// RFC 8037 Appendix A.1 (private) and A.2 (public).
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
/// RFC 8037 Appendix A.3.
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

/// RFC 7515 Appendix A.3.
const RFC7515_A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

/// RFC 8410 §10.1: an Ed25519 `SubjectPublicKeyInfo`, PEM body.
const RFC8410_ED25519_SPKI: &str = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

fn rfc7638_rsa() -> Jwk {
    serde_json::from_value(json!({
        "kty": "RSA",
        "n": RFC7638_RSA_N,
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29"
    }))
    .unwrap()
}

fn rfc8037_public() -> Jwk {
    serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X })).unwrap()
}

fn rfc8037_private() -> Jwk {
    serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "d": RFC8037_D, "x": RFC8037_X
    }))
    .unwrap()
}

fn rfc7515_a3_public() -> Jwk {
    serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Parsing and serialization
// ---------------------------------------------------------------------------------------------

#[test]
fn rfc7517_a1_public_key_parses_and_round_trips() {
    let jwk: Jwk = serde_json::from_str(RFC7517_A1_EC).unwrap();
    assert_eq!(jwk.kty(), "EC");
    assert_eq!(jwk.crv(), Some("P-256"));
    assert_eq!(jwk.x(), Some("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"));
    assert_eq!(jwk.y(), Some("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"));
    assert_eq!(jwk.key_use(), Some("enc"));
    assert_eq!(jwk.kid(), Some("1"));
    assert_eq!(jwk.alg(), None);
    assert!(!jwk.is_private());
    assert_eq!(serde_json::to_string(&jwk).unwrap(), RFC7517_A1_EC);
}

#[test]
fn rfc7517_a2_private_key_keeps_d_in_json_but_not_in_debug_or_display() {
    let jwk: Jwk = serde_json::from_str(RFC7517_A2_EC_PRIVATE).unwrap();
    assert!(jwk.is_private());
    assert_eq!(serde_json::to_string(&jwk).unwrap(), RFC7517_A2_EC_PRIVATE);

    let debug = format!("{jwk:?}");
    assert!(
        !debug.contains("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"),
        "{debug}"
    );
    assert!(debug.contains("private: true"), "{debug}");
    assert!(
        debug.contains("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
        "{debug}"
    );
    assert!(!debug.contains("additional"), "{debug}");
    let mut extended = jwk.public();
    extended
        .additional_mut()
        .insert("ext".to_owned(), json!(true));
    let debug = format!("{extended:?}");
    assert!(debug.contains("additional"), "{debug}");

    let display = jwk.to_string();
    assert!(
        !display.contains("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"),
        "{display}"
    );
    assert_eq!(display, serde_json::to_string(&jwk.public()).unwrap());

    let public = jwk.public();
    assert!(!public.is_private());
    assert_eq!(serde_json::to_string(&public).unwrap(), RFC7517_A1_EC);
    assert_eq!(public, serde_json::from_str::<Jwk>(RFC7517_A1_EC).unwrap());
    assert_ne!(public, jwk);
}

#[test]
fn rsa_private_parameters_are_recognised() {
    const SECRET: &str = "c2VjcmV0";
    for member in ["d", "p", "q", "dp", "dq", "qi"] {
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA", "n": RFC7638_RSA_N, "e": "AQAB", member: SECRET
        }))
        .unwrap();
        assert!(jwk.is_private(), "{member}");
        assert!(!format!("{jwk:?}").contains(SECRET), "{member}");
        assert!(!jwk.to_string().contains(SECRET), "{member}");
        assert!(
            serde_json::to_string(&jwk).unwrap().contains(SECRET),
            "{member}"
        );
        assert!(!jwk.public().is_private(), "{member}");
    }
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "RSA", "n": RFC7638_RSA_N, "e": "AQAB",
        "oth": [{"r": SECRET, "d": SECRET, "t": SECRET}]
    }))
    .unwrap();
    assert!(jwk.is_private());
    assert!(!jwk.public().is_private());
    assert!(!format!("{jwk:?}").contains(SECRET));
    let json: Value = serde_json::to_value(&jwk).unwrap();
    assert_eq!(json["oth"][0]["t"], SECRET);

    let symmetric: Jwk = serde_json::from_value(json!({ "kty": "oct", "k": SECRET })).unwrap();
    assert!(symmetric.is_private());
    assert!(!symmetric.to_string().contains(SECRET));
    assert!(!format!("{symmetric:?}").contains(SECRET));
}

/// RFC 7517 Appendix A.2, second key, in the member order of the RFC.
const RFC7517_A2_RSA_PRIVATE: &str = r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk","dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk","qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU","alg":"RS256","kid":"2011-04-29"}"#;

#[test]
fn rfc7517_a2_rsa_private_key_round_trips_byte_identically() {
    let jwk: Jwk = serde_json::from_str(RFC7517_A2_RSA_PRIVATE).unwrap();
    assert!(jwk.is_private());
    assert_eq!(serde_json::to_string(&jwk).unwrap(), RFC7517_A2_RSA_PRIVATE);
    assert_eq!(jwk.public(), rfc7638_rsa());
    assert_eq!(jwk.thumbprint_sha256().unwrap(), RFC7638_THUMBPRINT);
}

#[test]
fn extension_members_are_kept_in_order() {
    let input = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","x5c":["MIIB"],"zebra":1,"apple":{"nested":true},"key_ops":["verify"]}"#;
    let jwk: Jwk = serde_json::from_str(input).unwrap();
    assert_eq!(jwk.key_ops(), Some(&["verify".to_owned()][..]));
    assert_eq!(
        jwk.additional().keys().collect::<Vec<_>>(),
        ["x5c", "zebra", "apple"]
    );
    // Modelled members come first in a fixed order, extension members follow in input order.
    assert_eq!(
        serde_json::to_string(&jwk).unwrap(),
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","key_ops":["verify"],"x5c":["MIIB"],"zebra":1,"apple":{"nested":true}}"#
    );
}

#[test]
fn kty_is_required() {
    assert!(serde_json::from_str::<Jwk>(r#"{"crv":"Ed25519"}"#).is_err());
    assert!(serde_json::from_str::<Jwk>(r#"{"kty":5}"#).is_err());
    assert!(serde_json::from_str::<Jwk>("[]").is_err());
}

#[test]
fn builders_set_common_members() {
    let jwk = rfc8037_public()
        .with_kid("did:example:123#key-1")
        .with_alg("EdDSA")
        .with_key_use("sig")
        .with_key_ops(["verify"]);
    assert_eq!(jwk.kid(), Some("did:example:123#key-1"));
    assert_eq!(jwk.alg(), Some("EdDSA"));
    assert_eq!(jwk.key_use(), Some("sig"));
    assert_eq!(jwk.key_ops(), Some(&["verify".to_owned()][..]));
    let mut jwk = jwk;
    jwk.additional_mut()
        .insert("x5u".to_owned(), json!("https://example.com/cert"));
    assert_eq!(
        serde_json::to_string(&jwk).unwrap(),
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","use":"sig","key_ops":["verify"],"alg":"EdDSA","kid":"did:example:123#key-1","x5u":"https://example.com/cert"}"#
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 7638 thumbprints
// ---------------------------------------------------------------------------------------------

#[test]
fn rfc7638_rsa_thumbprint() {
    let jwk = rfc7638_rsa();
    assert_eq!(jwk.thumbprint_sha256().unwrap(), RFC7638_THUMBPRINT);
    // `alg` and `kid` do not take part.
    assert_eq!(
        Jwk::from_rsa_public(&b64(RFC7638_RSA_N), &[1, 0, 1])
            .unwrap()
            .thumbprint_sha256()
            .unwrap(),
        RFC7638_THUMBPRINT
    );
}

#[test]
fn rfc8037_ed25519_thumbprint() {
    assert_eq!(
        rfc8037_public().thumbprint_sha256().unwrap(),
        RFC8037_THUMBPRINT
    );
    // Private parameters do not take part.
    assert_eq!(
        rfc8037_private().thumbprint_sha256().unwrap(),
        RFC8037_THUMBPRINT
    );
}

#[test]
fn ec_thumbprint_is_stable_and_ignores_optional_members() {
    let with_extras: Jwk = serde_json::from_str(RFC7517_A2_EC_PRIVATE).unwrap();
    let bare: Jwk = serde_json::from_value(json!({
        "kty": "EC",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "crv": "P-256",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
    }))
    .unwrap();
    assert_eq!(
        with_extras.thumbprint_sha256().unwrap(),
        bare.thumbprint_sha256().unwrap()
    );
}

#[test]
fn oct_thumbprint_hashes_k_and_kty() {
    use sha2::Digest as _;

    // RFC 7517 Appendix A.3, first key. RFC 7638 §3.2: the required members of an `oct` key are
    // `k` and `kty`, in lexicographic order.
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg"
    }))
    .unwrap();
    let input = r#"{"k":"GawgguFyGrWKav7AX4VKUg","kty":"oct"}"#;
    assert_eq!(
        jwk.thumbprint_sha256().unwrap(),
        URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(input))
    );
}

#[test]
fn thumbprint_needs_the_required_members() {
    let no_y: Jwk =
        serde_json::from_value(json!({ "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X })).unwrap();
    assert_eq!(no_y.thumbprint_sha256(), Err(JwkError::MissingMember("y")));
    let no_e: Jwk = serde_json::from_value(json!({ "kty": "RSA", "n": RFC7638_RSA_N })).unwrap();
    assert_eq!(no_e.thumbprint_sha256(), Err(JwkError::MissingMember("e")));
    let unknown: Jwk = serde_json::from_value(json!({ "kty": "PQC", "crv": "ML-DSA" })).unwrap();
    assert_eq!(
        unknown.thumbprint_sha256(),
        Err(JwkError::UnsupportedKeyType {
            kty: "PQC".to_owned(),
            crv: Some("ML-DSA".to_owned())
        })
    );
}

// ---------------------------------------------------------------------------------------------
// Constructors and raw accessors
// ---------------------------------------------------------------------------------------------

#[test]
fn ed25519_round_trips_through_raw_bytes() {
    let jwk = rfc8037_public();
    let raw = jwk.ed25519_public_bytes().unwrap();
    assert_eq!(raw.to_vec(), b64(RFC8037_X));
    assert_eq!(Jwk::from_ed25519_public(&raw).unwrap(), jwk);
    assert_eq!(rfc8037_private().ed25519_public_bytes().unwrap(), raw);
}

#[test]
fn p256_round_trips_through_sec1() {
    let jwk = rfc7515_a3_public();
    let sec1 = jwk.p256_public_bytes().unwrap();
    assert_eq!(sec1[0], 0x04);
    assert_eq!(sec1[1..33].to_vec(), b64(RFC7515_A3_X));
    assert_eq!(sec1[33..].to_vec(), b64(RFC7515_A3_Y));
    assert_eq!(Jwk::from_p256_public(&sec1).unwrap(), jwk);
    // A compressed point yields the same key.
    let mut compressed = vec![0x02 | (sec1[64] & 1)];
    compressed.extend_from_slice(&sec1[1..33]);
    assert_eq!(Jwk::from_p256_public(&compressed).unwrap(), jwk);
}

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_round_trips_through_sec1() {
    // The secp256k1 generator point G (SEC 2 §2.4.1).
    let gx = hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&gx);
    sec1.extend_from_slice(&gy);
    let jwk = Jwk::from_secp256k1_public(&sec1).unwrap();
    assert_eq!(jwk.kty(), "EC");
    assert_eq!(jwk.crv(), Some("secp256k1"));
    assert_eq!(jwk.x(), Some(URL_SAFE_NO_PAD.encode(&gx).as_str()));
    assert_eq!(jwk.y(), Some(URL_SAFE_NO_PAD.encode(&gy).as_str()));
    assert_eq!(jwk.secp256k1_public_bytes().unwrap().to_vec(), sec1);
    assert!(matches!(
        jwk.p256_public_bytes(),
        Err(JwkError::UnexpectedKeyType {
            expected: "P-256",
            ..
        })
    ));
}

#[test]
fn rsa_components_round_trip_and_drop_leading_zeros() {
    let jwk = rfc7638_rsa();
    let (n, e) = jwk.rsa_public_components().unwrap();
    assert_eq!(e, [1, 0, 1]);
    assert_eq!(n.len(), 256);
    let rebuilt = Jwk::from_rsa_public(&n, &e).unwrap();
    assert_eq!(rebuilt.n(), jwk.n());
    assert_eq!(rebuilt.e(), jwk.e());

    let mut padded_n = vec![0, 0];
    padded_n.extend_from_slice(&n);
    let padded = Jwk::from_rsa_public(&padded_n, &[0, 1, 0, 1]).unwrap();
    assert_eq!(padded.n(), jwk.n());
    assert_eq!(padded.e(), Some("AQAB"));

    assert!(matches!(
        Jwk::from_rsa_public(&[], &[1, 0, 1]),
        Err(JwkError::InvalidKey { key: "RSA", .. })
    ));
}

#[test]
fn accessors_reject_the_wrong_key_type() {
    let ed = rfc8037_public();
    let ec = rfc7515_a3_public();
    let rsa = rfc7638_rsa();

    assert!(matches!(
        ec.ed25519_public_bytes(),
        Err(JwkError::UnexpectedKeyType {
            expected: "Ed25519",
            ..
        })
    ));
    assert!(matches!(
        rsa.p256_public_bytes(),
        Err(JwkError::UnexpectedKeyType {
            expected: "P-256",
            ..
        })
    ));
    assert!(matches!(
        ed.rsa_public_components(),
        Err(JwkError::UnexpectedKeyType {
            expected: "RSA",
            ..
        })
    ));
    let p384: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-384", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap();
    assert_eq!(
        p384.p256_public_bytes(),
        Err(JwkError::UnexpectedKeyType {
            expected: "P-256",
            kty: "EC".to_owned(),
            crv: Some("P-384".to_owned())
        })
    );
}

#[test]
fn accessors_reject_broken_material() {
    let missing: Jwk =
        serde_json::from_value(json!({ "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X })).unwrap();
    assert_eq!(
        missing.p256_public_bytes(),
        Err(JwkError::MissingMember("y"))
    );

    let padded: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": format!("{RFC8037_X}=")
    }))
    .unwrap();
    assert_eq!(
        padded.ed25519_public_bytes(),
        Err(JwkError::InvalidBase64Url("x"))
    );

    let short: Jwk =
        serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519", "x": "AQAB" })).unwrap();
    assert!(matches!(
        short.ed25519_public_bytes(),
        Err(JwkError::InvalidKey { key: "Ed25519", .. })
    ));

    // Either coordinate of the wrong length is enough.
    let short_y = URL_SAFE_NO_PAD.encode(&b64(RFC7515_A3_Y)[1..]);
    for (x, y, lengths) in [
        (RFC7515_A3_X, short_y.as_str(), "32 and 31"),
        (short_y.as_str(), RFC7515_A3_Y, "31 and 32"),
    ] {
        let jwk: Jwk =
            serde_json::from_value(json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })).unwrap();
        assert_eq!(
            jwk.p256_public_bytes(),
            Err(JwkError::InvalidKey {
                key: "P-256",
                reason: format!("expected 32-byte coordinates, found {lengths}"),
            })
        );
    }

    // x and y of the right length that are not a point on P-256.
    let off_curve: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_X
    }))
    .unwrap();
    assert!(matches!(
        off_curve.p256_public_bytes(),
        Err(JwkError::InvalidKey { key: "P-256", .. })
    ));

    assert!(matches!(
        Jwk::from_ed25519_public(&[0; 31]),
        Err(JwkError::InvalidKey { key: "Ed25519", .. })
    ));
    assert!(matches!(
        Jwk::from_p256_public(&[0x04; 65]),
        Err(JwkError::InvalidKey { key: "P-256", .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// SubjectPublicKeyInfo
// ---------------------------------------------------------------------------------------------

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `SubjectPublicKeyInfo` for an `id-ecPublicKey` key (RFC 5480 §2): the fixed
/// `AlgorithmIdentifier` prefix followed by the uncompressed point in a BIT STRING.
fn ec_spki(curve_oid_prefix: &str, point: &[u8]) -> Vec<u8> {
    let mut der = hex(curve_oid_prefix);
    der.extend_from_slice(point);
    der
}

/// A DER TLV with a definite length in the fewest octets (X.690 §10.1), for contents up to
/// 64 KiB.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = vec![tag];
    match n {
        0..=0x7f => out.push(n as u8),
        0x80..=0xff => out.extend([0x81, n as u8]),
        _ => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 8017 A.1.1) for
/// unsigned big-endian `n` and `e` without leading zeros.
fn rsa_pkcs1(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn integer(be: &[u8]) -> Vec<u8> {
        let mut content = Vec::with_capacity(be.len() + 1);
        if be[0] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(be);
        der_tlv(0x02, &content)
    }
    der_tlv(0x30, &[integer(n), integer(e)].concat())
}

/// `SEQUENCE { SEQUENCE { rsaEncryption, NULL }, BIT STRING { RSAPublicKey } }` (RFC 8017 A.1.1).
fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let algorithm = hex("300d06092a864886f70d0101010500");
    let mut bit_string_content = vec![0];
    bit_string_content.extend(rsa_pkcs1(n, e));
    der_tlv(
        0x30,
        &[algorithm, der_tlv(0x03, &bit_string_content)].concat(),
    )
}

#[test]
fn rfc8410_ed25519_spki_parses() {
    let der = STANDARD.decode(RFC8410_ED25519_SPKI).unwrap();
    let jwk = Jwk::from_spki_der(KeyType::Ed25519, &der).unwrap();
    assert_eq!(jwk.kty(), "OKP");
    assert_eq!(jwk.crv(), Some("Ed25519"));
    // The last 32 bytes of the SPKI are the raw key.
    assert_eq!(jwk.ed25519_public_bytes().unwrap(), der[der.len() - 32..]);
    assert_eq!(
        jwk.x(),
        Some(URL_SAFE_NO_PAD.encode(&der[der.len() - 32..]).as_str())
    );

    assert!(matches!(
        Jwk::from_spki_der(KeyType::P256, &der),
        Err(JwkError::InvalidKey { key: "P-256", .. })
    ));
}

#[test]
fn p256_spki_parses() {
    let point = rfc7515_a3_public().p256_public_bytes().unwrap();
    let der = ec_spki(
        "3059301306072a8648ce3d020106082a8648ce3d030107034200",
        &point,
    );
    assert_eq!(
        Jwk::from_spki_der(KeyType::P256, &der).unwrap(),
        rfc7515_a3_public()
    );
    assert!(matches!(
        Jwk::from_spki_der(KeyType::Ed25519, &der),
        Err(JwkError::InvalidKey { key: "Ed25519", .. })
    ));
    assert!(matches!(
        Jwk::from_spki_der(KeyType::P256, &der[..der.len() - 1]),
        Err(JwkError::InvalidKey { key: "P-256", .. })
    ));
}

#[test]
fn secp256k1_spki_parses_or_is_feature_gated() {
    let gx = hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    let point = [vec![0x04], gx, gy].concat();
    let der = ec_spki("3056301006072a8648ce3d020106052b8104000a034200", &point);
    let result = Jwk::from_spki_der(KeyType::Secp256k1, &der);
    #[cfg(feature = "secp256k1")]
    {
        let jwk = result.unwrap();
        assert_eq!(jwk.crv(), Some("secp256k1"));
        assert_eq!(jwk.secp256k1_public_bytes().unwrap().to_vec(), point);
        // A P-256 OID with a secp256k1 point is not a secp256k1 key.
        let wrong_curve = ec_spki(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200",
            &point,
        );
        assert!(matches!(
            Jwk::from_spki_der(KeyType::Secp256k1, &wrong_curve),
            Err(JwkError::InvalidKey {
                key: "secp256k1",
                ..
            })
        ));
    }
    #[cfg(not(feature = "secp256k1"))]
    assert_eq!(
        result,
        Err(JwkError::FeatureDisabled {
            key: "secp256k1",
            feature: "secp256k1"
        })
    );
}

#[test]
fn rsa_spki_parses_or_is_feature_gated() {
    let (n, e) = rfc7638_rsa().rsa_public_components().unwrap();
    let der = rsa_spki(&n, &e);
    let result = Jwk::from_spki_der(KeyType::Rsa2048, &der);
    #[cfg(feature = "rsa")]
    {
        let jwk = result.unwrap();
        assert_eq!(jwk.n(), Some(RFC7638_RSA_N));
        assert_eq!(jwk.e(), Some("AQAB"));
        assert_eq!(jwk.thumbprint_sha256().unwrap(), RFC7638_THUMBPRINT);
        assert_eq!(
            Jwk::from_spki_der(KeyType::Rsa4096, &der),
            Err(JwkError::KeyMismatch {
                expected: KeyType::Rsa4096
            })
        );
        assert!(matches!(
            Jwk::from_spki_der(KeyType::Rsa2048, &der[1..]),
            Err(JwkError::InvalidKey { key: "RSA", .. })
        ));
    }
    #[cfg(not(feature = "rsa"))]
    assert_eq!(
        result,
        Err(JwkError::FeatureDisabled {
            key: "RSA",
            feature: "rsa"
        })
    );
}

// ---------------------------------------------------------------------------------------------
// PKCS #1 `RSAPublicKey`
// ---------------------------------------------------------------------------------------------

/// A 4096-bit modulus: no published 4096-bit key is among the vectors, and PKCS #1 and SPKI
/// parsing need only the size and the encoding, not a product of two primes. The top bit is set
/// so that the modulus is 4096 bits long and its INTEGER needs a leading zero.
fn modulus_4096() -> Vec<u8> {
    let mut n: Vec<u8> = (0..512u32).map(|i| (i * 37 + 11) as u8).collect();
    n[0] = 0xc5;
    n[511] |= 1;
    n
}

#[test]
fn pkcs1_round_trips_2048_and_4096_bit_keys() {
    let (n_2048, e) = rfc7638_rsa().rsa_public_components().unwrap();
    for (n, header) in [
        // 4 + 257 bytes of modulus INTEGER (with its leading zero) plus 5 of exponent: 266 = 0x10a.
        (n_2048, [0x30, 0x82, 0x01, 0x0a]),
        // 4 + 513 plus 5: 522 = 0x20a.
        (modulus_4096(), [0x30, 0x82, 0x02, 0x0a]),
    ] {
        let der = rsa_pkcs1(&n, &e);
        assert_eq!(der[..4], header);
        let jwk = Jwk::from_pkcs1_der(&der).unwrap();
        assert_eq!(jwk.rsa_public_components().unwrap(), (n.clone(), e.clone()));
        assert_eq!(jwk, Jwk::from_rsa_public(&n, &e).unwrap());
        assert_eq!(jwk.to_pkcs1_der().unwrap(), der);

        // The same key as a `SubjectPublicKeyInfo` gives the same JWK.
        #[cfg(feature = "rsa")]
        {
            let hint = if n.len() == 512 {
                KeyType::Rsa4096
            } else {
                KeyType::Rsa2048
            };
            assert_eq!(Jwk::from_spki_der(hint, &rsa_spki(&n, &e)).unwrap(), jwk);
        }
    }
    assert_eq!(
        rfc7638_rsa().to_pkcs1_der().unwrap(),
        rsa_pkcs1(&b64(RFC7638_RSA_N), &[1, 0, 1])
    );
}

#[test]
fn pkcs1_rejects_what_is_not_a_der_rsa_public_key() {
    // `SEQUENCE { INTEGER 0x00c5, INTEGER 65537 }`.
    let valid = hex("3009020200c50203010001");
    assert_eq!(
        Jwk::from_pkcs1_der(&valid)
            .unwrap()
            .rsa_public_components()
            .unwrap(),
        (vec![0xc5], vec![1, 0, 1])
    );
    let (n, e) = rfc7638_rsa().rsa_public_components().unwrap();
    for (name, der) in [
        (
            "trailing bytes after the SEQUENCE",
            "3009020200c502030100010000",
        ),
        (
            "trailing bytes inside the SEQUENCE",
            "300a020200c5020301000100",
        ),
        ("non-minimal length", "30820009020200c50203010001"),
        ("long form of a short length", "308109020200c50203010001"),
        ("negative INTEGER", "30080201c50203010001"),
        ("leading zero octet", "300a02030000c50203010001"),
        ("leading zero octet in e", "3009020200c50203000101"),
        ("empty INTEGER", "300702000203010001"),
        ("wrong outer tag", "3109020200c50203010001"),
        ("BER indefinite length", "3080020200c502030100010000"),
        ("empty input", ""),
    ]
    .map(|(name, der)| (name, hex(der)))
    .into_iter()
    .chain([("a SubjectPublicKeyInfo", rsa_spki(&n, &e))])
    {
        assert!(
            matches!(
                Jwk::from_pkcs1_der(&der),
                Err(JwkError::InvalidKey { key: "RSA", .. })
            ),
            "{name}: {der:02x?}"
        );
    }

    // Truncated at every byte offset.
    let der = rsa_pkcs1(&n, &e);
    for len in 0..der.len() {
        assert!(
            matches!(
                Jwk::from_pkcs1_der(&der[..len]),
                Err(JwkError::InvalidKey { key: "RSA", .. })
            ),
            "truncated to {len} bytes"
        );
    }
}

#[test]
fn pkcs1_needs_an_rsa_key() {
    assert!(matches!(
        rfc8037_public().to_pkcs1_der(),
        Err(JwkError::UnexpectedKeyType {
            expected: "RSA",
            ..
        })
    ));
    let no_e: Jwk = serde_json::from_value(json!({ "kty": "RSA", "n": RFC7638_RSA_N })).unwrap();
    assert_eq!(no_e.to_pkcs1_der(), Err(JwkError::MissingMember("e")));

    // An empty or zero `n` or `e` would encode as `INTEGER 0`, which `from_pkcs1_der` refuses.
    for (n, e) in [
        ("", "AQAB"),
        ("AA", "AQAB"),
        (RFC7638_RSA_N, ""),
        (RFC7638_RSA_N, "AAA"),
    ] {
        let jwk: Jwk = serde_json::from_value(json!({ "kty": "RSA", "n": n, "e": e })).unwrap();
        let zero = Err(JwkError::InvalidKey {
            key: "RSA",
            reason: "modulus and exponent must not be zero".to_owned(),
        });
        assert_eq!(jwk.to_pkcs1_der(), zero, "n {n:?}, e {e:?}");
        assert_eq!(jwk.to_multikey(), zero.map(|_: Vec<u8>| String::new()));
    }
}

// ---------------------------------------------------------------------------------------------
// jsonwebtoken
// ---------------------------------------------------------------------------------------------

#[test]
fn decoding_keys_are_built_for_supported_types() {
    rfc8037_public().to_decoding_key().unwrap();
    rfc7515_a3_public().to_decoding_key().unwrap();
    rfc7638_rsa().to_decoding_key().unwrap();

    let secp: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "secp256k1", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap();
    assert!(matches!(
        secp.to_decoding_key(),
        Err(JwkError::UnsupportedKeyType { .. })
    ));
    let no_x: Jwk = serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519" })).unwrap();
    assert_eq!(
        no_x.to_decoding_key().unwrap_err(),
        JwkError::MissingMember("x")
    );
    let bad: Jwk =
        serde_json::from_value(json!({ "kty": "OKP", "crv": "Ed25519", "x": "not base64!" }))
            .unwrap();
    let error = bad.to_decoding_key().unwrap_err();
    assert!(matches!(error, JwkError::DecodingKey(_)));
    // The source is `jsonwebtoken`'s error, and the message still ends with it.
    let source = error.source().unwrap();
    assert!(source.is::<jsonwebtoken::errors::Error>());
    assert!(error.to_string().ends_with(&source.to_string()));
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

proptest! {
    /// Any key survives a JSON round trip with its members, extension members included, and a
    /// key without private parameters is its own public form.
    #[test]
    fn json_round_trip_preserves_everything(
        kid in "[a-zA-Z0-9:#._-]{0,40}",
        extra in prop::collection::vec(("[a-z_][a-z0-9_]{0,8}", any::<i64>()), 0..4),
    ) {
        let mut jwk = rfc8037_public().with_kid(kid);
        for (name, value) in &extra {
            // Members this type models are not extension members.
            prop_assume!(!matches!(
                name.as_str(),
                "kty" | "crv" | "x" | "y" | "n" | "e" | "use" | "key_ops" | "alg" | "kid"
                    | "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k"
            ));
            jwk.additional_mut().insert(name.clone(), json!(value));
        }
        let json = serde_json::to_string(&jwk).unwrap();
        let back: Jwk = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&back, &jwk);
        prop_assert_eq!(serde_json::to_string(&back).unwrap(), json);
        prop_assert_eq!(jwk.public(), jwk.clone());
        prop_assert_eq!(jwk.thumbprint_sha256().unwrap(), RFC8037_THUMBPRINT);
    }
}
