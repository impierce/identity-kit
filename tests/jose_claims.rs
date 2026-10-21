//! Specification vectors for `JwtClaims`: the RFC 7519 §3.1 claims set as RFC 7515 Appendix A.3
//! signs it, `aud` (RFC 7519 §4.1.3) and `NumericDate` (RFC 7519 §2).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::jose::{CompactJws, DefaultVerifier, Jwk, JwsError, JwtClaims, OneOrMany};
use serde_json::{Value, json};

/// RFC 7519 §3.1, the encoded claims set (also the payload of RFC 7515 Appendix A.1 to A.3).
const RFC7519_CLAIMS_B64: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

/// RFC 7519 §3.1, the claims set as the example writes it (with CRLF and a leading space).
const RFC7519_CLAIMS: &[u8] =
    b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

/// RFC 7515 Appendix A.3: the claims set signed with ES256, and the P-256 key.
const RFC7515_A3_JWS: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
const RFC7515_A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

/// RFC 8037 Appendix A.4: a payload that is not JSON.
const RFC8037_JWS: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

fn rfc7519_claims() -> JwtClaims {
    let mut claims = JwtClaims::new()
        .with_iss("joe")
        .with_claim("http://example.com/is_root", true);
    // Set directly: the `chrono` setters come with the `vc` feature.
    claims.exp = Some(1300819380);
    claims
}

#[test]
fn rfc7519_claims_set_round_trips() {
    let bytes = URL_SAFE_NO_PAD.decode(RFC7519_CLAIMS_B64).unwrap();
    assert_eq!(bytes, RFC7519_CLAIMS);

    let claims: JwtClaims = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(claims.iss.as_deref(), Some("joe"));
    assert_eq!(claims.exp, Some(1300819380));
    assert_eq!(
        claims.additional.get("http://example.com/is_root"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        (
            &claims.sub,
            &claims.aud,
            claims.nbf,
            claims.iat,
            &claims.jti
        ),
        (&None, &None, None, None, &None)
    );
    assert_eq!(claims, rfc7519_claims());

    let compact = serde_json::to_string(&claims).unwrap();
    assert_eq!(
        compact,
        r#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#
    );
    assert_eq!(serde_json::from_str::<JwtClaims>(&compact).unwrap(), claims);
}

#[test]
fn a_signed_payload_reads_as_claims() {
    let jws = CompactJws::decode(RFC7515_A3_JWS).unwrap();
    let key: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap();
    jws.verify(&DefaultVerifier, &key).unwrap();

    assert_eq!(jws.claims::<JwtClaims>().unwrap(), rfc7519_claims());
    assert_eq!(
        jws.claims::<Value>().unwrap(),
        json!({ "iss": "joe", "exp": 1300819380, "http://example.com/is_root": true })
    );

    // Not JSON, or not the JSON asked for.
    let not_json = CompactJws::decode(RFC8037_JWS).unwrap();
    assert!(matches!(
        not_json.claims::<JwtClaims>(),
        Err(JwsError::InvalidPayload(_))
    ));
    assert!(matches!(
        jws.claims::<Vec<String>>(),
        Err(JwsError::InvalidPayload(_))
    ));
}

/// RFC 7519 §4.1.3: `aud` is an array of strings or, with one audience, may be a single string.
#[test]
fn aud_is_a_string_or_an_array() {
    let one: JwtClaims = serde_json::from_value(json!({ "aud": "did:example:verifier" })).unwrap();
    assert_eq!(
        one.aud,
        Some(OneOrMany::One("did:example:verifier".to_owned()))
    );
    assert_eq!(
        one.audiences().collect::<Vec<_>>(),
        ["did:example:verifier"]
    );
    assert_eq!(
        serde_json::to_value(&one).unwrap(),
        json!({ "aud": "did:example:verifier" })
    );

    let many: JwtClaims = serde_json::from_value(json!({ "aud": ["a", "b"] })).unwrap();
    assert_eq!(many.audiences().collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(
        serde_json::to_value(&many).unwrap(),
        json!({ "aud": ["a", "b"] })
    );

    // A list of one stays a list.
    let single: JwtClaims = serde_json::from_value(json!({ "aud": ["a"] })).unwrap();
    assert_eq!(single.aud, Some(OneOrMany::Many(vec!["a".to_owned()])));
    assert_eq!(
        serde_json::to_value(&single).unwrap(),
        json!({ "aud": ["a"] })
    );

    assert_eq!(JwtClaims::new().audiences().count(), 0);
    assert!(serde_json::from_value::<JwtClaims>(json!({ "aud": 1 })).is_err());
    assert!(serde_json::from_value::<JwtClaims>(json!({ "aud": [1] })).is_err());
}

/// RFC 7519 §2: a `NumericDate` is a JSON number of seconds, possibly with a fraction, which the
/// claims drop.
#[test]
fn numeric_dates_are_integer_or_float_seconds() {
    let claims: JwtClaims = serde_json::from_value(
        json!({ "nbf": 1300819380, "iat": 1541493724.5, "exp": 1573029723.999 }),
    )
    .unwrap();
    assert_eq!(
        (claims.nbf, claims.iat, claims.exp),
        (Some(1300819380), Some(1541493724), Some(1573029723))
    );
    let absent: JwtClaims = serde_json::from_value(json!({ "exp": null })).unwrap();
    assert_eq!(absent.exp, None);

    for exp in [json!("1300819380"), json!(true), json!({}), json!(1e300)] {
        assert!(
            serde_json::from_value::<JwtClaims>(json!({ "exp": exp })).is_err(),
            "{exp} is not a NumericDate"
        );
    }
    for claim in ["nbf", "iat"] {
        let claims = format!(r#"{{"{claim}":"soon"}}"#);
        assert!(
            serde_json::from_str::<JwtClaims>(&claims).is_err(),
            "{claims}"
        );
    }
}

#[test]
fn setters_fill_the_registered_claims_in_order() {
    let claims = JwtClaims::new()
        .with_claim("nonce", "n-0S6_WzA2Mj")
        .with_jti("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")
        .with_aud("did:example:verifier")
        .with_sub("did:example:holder")
        .with_iss("did:example:issuer");
    assert_eq!(
        serde_json::to_string(&claims).unwrap(),
        r#"{"iss":"did:example:issuer","sub":"did:example:holder","aud":"did:example:verifier","jti":"urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5","nonce":"n-0S6_WzA2Mj"}"#
    );
    assert_eq!(
        JwtClaims::REGISTERED,
        ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]
    );
}

/// The types moved from `vc` and `did`; the old paths name the same types.
#[test]
fn the_old_paths_still_name_the_types() {
    let _: OneOrMany<String> = identity_kit::did::OneOrMany::One(String::new());
    #[cfg(feature = "vc")]
    {
        let _: JwtClaims = identity_kit::vc::JwtClaims::new();
        let _: JwtClaims = identity_kit::prelude::credentials::JwtClaims::new();
    }
}
