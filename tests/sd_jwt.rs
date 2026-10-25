//! RFC 9901 (SD-JWT) vectors: the disclosure examples of §4.2, the simple SD-JWT of §5 with
//! its presentation and key binding JWT, the nested structures of §6, the decoy example of
//! Appendix A.1, the complex and credential examples of A.2 to A.4, all verified against the
//! issuer key of Appendix A.5 and the holder key in `cnf`.
#![cfg(feature = "sd-jwt")]

mod common;

use std::collections::BTreeSet;
use std::error::Error as _;

use chrono::{TimeZone as _, Utc};
use identity_kit::claim_path;
use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader};
use identity_kit::sd_jwt_vc::{
    ClaimPath, Disclosure, HashAlgorithm, KB_JWT_TYP, KeyBinding, SdJwt, SdJwtBuilder, SdJwtError,
};
use identity_kit::vc::{Jwt, JwtClaims};
use serde_json::{Map, Value, json};

use common::{Es256Signer, unsigned_jwt};

/// RFC 9901 Appendix A.5: the issuer's key.
fn issuer_key() -> Jwk {
    serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
        "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
    }))
    .unwrap()
}

fn object(text: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(text)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

/// The `<hash> <disclosure>` lines of a `disclosures.txt`.
fn disclosures(text: &str) -> Vec<(String, Disclosure)> {
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (hash, disclosure) = line.split_once(' ').unwrap();
            (hash.to_owned(), Disclosure::parse(disclosure).unwrap())
        })
        .collect()
}

/// An SD-JWT over `payload` (unsigned) with every disclosure of `text`.
fn sd_jwt_of(payload: &str, text: &str) -> SdJwt {
    let header = json!({"alg": "ES256"});
    let jwt = Jwt::new(unsigned_jwt(
        &header,
        &serde_json::from_str(payload).unwrap(),
    ))
    .unwrap();
    SdJwt::new(jwt, disclosures(text).into_iter().map(|(_, d)| d).collect())
}

/// Verifies the issuer signature of `sd_jwt` with the A.5 key.
fn verify_issuer(sd_jwt: &SdJwt) {
    sd_jwt
        .jwt()
        .decode()
        .unwrap()
        .verify(&DefaultVerifier, &issuer_key())
        .unwrap();
}

/// Verifies the key binding JWT of `sd_jwt` with the key in `cnf` and returns its claims.
fn verify_key_binding(sd_jwt: &SdJwt) -> JwtClaims {
    let payload = sd_jwt.payload().unwrap();
    let holder_key: Jwk = serde_json::from_value(payload["cnf"]["jwk"].clone()).unwrap();
    let kb = sd_jwt
        .key_binding_jwt()
        .expect("an SD-JWT+KB")
        .decode()
        .unwrap();
    assert_eq!(kb.header().typ.as_deref(), Some(KB_JWT_TYP));
    kb.verify(&DefaultVerifier, &holder_key).unwrap();
    let claims: JwtClaims = serde_json::from_slice(kb.payload()).unwrap();
    let alg = sd_jwt.hash_algorithm().unwrap();
    assert_eq!(claims.additional["sd_hash"], sd_jwt.sd_hash(alg));
    claims
}

macro_rules! vector {
    ($example:literal, $file:literal) => {
        include_str!(concat!("vectors/sd_jwt/", $example, "/", $file)).trim()
    };
}

// ---------------------------------------------------------------------------------------------
// §4.2: disclosures and digests
// ---------------------------------------------------------------------------------------------

#[test]
fn disclosure_for_an_object_property() {
    // §4.2.1: the array, four encodings of it, one digest each (§4.2.3).
    let canonical = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    let variants = [
        canonical,
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNXHUwMGY2Yml1cyJd",
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
        "WwoiXzI2YmM0TFQtYWM2cTJLSTZjQlc1ZXMiLAoiZmFtaWx5X25hbWUiLAoiTcO2Yml1cyIKXQ",
    ];
    for variant in variants {
        let disclosure = Disclosure::parse(variant).unwrap();
        assert_eq!(disclosure.salt(), "_26bc4LT-ac6q2KI6cBW5es");
        assert_eq!(disclosure.name(), Some("family_name"));
        assert_eq!(disclosure.value(), &json!("Möbius"));
        assert!(!disclosure.is_element());
        assert_eq!(disclosure.as_str(), variant);
        assert_eq!(disclosure.to_string(), variant);
    }
    assert_eq!(
        Disclosure::parse(canonical)
            .unwrap()
            .digest(HashAlgorithm::Sha256),
        "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
    );
    // This crate encodes without whitespace: the third variant.
    let built = Disclosure::property("_26bc4LT-ac6q2KI6cBW5es", "family_name", json!("Möbius"));
    assert_eq!(built.as_str(), variants[2]);
    assert_eq!(built, Disclosure::parse(variants[2]).unwrap());
}

#[test]
fn disclosure_for_an_array_element() {
    // §4.2.2 and §4.2.4.2.
    let disclosure = Disclosure::parse("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0").unwrap();
    assert_eq!(disclosure.salt(), "lklxF5jMYlGTPUovMNIvCA");
    assert_eq!(disclosure.name(), None);
    assert!(disclosure.is_element());
    assert_eq!(disclosure.value(), &json!("FR"));
    assert_eq!(
        disclosure.digest(HashAlgorithm::Sha256),
        "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"
    );
    let built = Disclosure::element("lklxF5jMYlGTPUovMNIvCA", json!("FR"));
    assert_eq!(built.as_str(), "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwiRlIiXQ");

    // §4.2.4.2: the array with the digest in place, with and without the disclosure.
    let payload = json!({
        "nationalities": ["DE", {"...": "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"}, "US"]
    });
    let jwt = Jwt::new(unsigned_jwt(&json!({"alg": "ES256"}), &payload)).unwrap();
    let without = SdJwt::new(jwt.clone(), Vec::new()).process().unwrap();
    assert_eq!(without.payload["nationalities"], json!(["DE", "US"]));
    assert_eq!(without.undisclosed, vec![claim_path!["nationalities", 1]]);
    let with = SdJwt::new(jwt, vec![disclosure]).process().unwrap();
    assert_eq!(with.payload["nationalities"], json!(["DE", "FR", "US"]));
    assert!(with.is_disclosed(&claim_path!["nationalities", 1]));
    assert!(with.undisclosed.is_empty());
}

#[test]
fn malformed_disclosures_are_rejected() {
    for (bad, why) in [
        ("not base64url!", "not base64url"),
        (&common::encode(b"\"a string\""), "not a JSON array"),
        (
            &common::encode(b"[\"salt\"]"),
            "not an array of two or three elements",
        ),
        (
            &common::encode(b"[1, \"name\", 2]"),
            "the salt is not a string",
        ),
        (
            &common::encode(b"[\"salt\", 1, 2]"),
            "the claim name is not a string",
        ),
        (
            &common::encode(b"[\"salt\", \"name\", 2, 3]"),
            "not an array of two or three elements",
        ),
    ] {
        assert!(
            matches!(
                Disclosure::parse(bad),
                Err(SdJwtError::InvalidDisclosure { ref reason, .. }) if reason == why
            ),
            "{bad}"
        );
    }
}

#[test]
fn every_example_digest_matches_its_disclosure() {
    let examples = [
        vector!("simple", "disclosures.txt"),
        vector!("flat", "disclosures.txt"),
        vector!("structured", "disclosures.txt"),
        vector!("recursive", "disclosures.txt"),
        vector!("simple_structured", "disclosures.txt"),
        vector!("complex_ekyc", "disclosures.txt"),
        vector!("sd_jwt_vc", "disclosures.txt"),
        vector!("w3c_vcdm", "disclosures.txt"),
    ];
    for text in examples {
        for (hash, disclosure) in disclosures(text) {
            assert_eq!(disclosure.digest(HashAlgorithm::Sha256), hash);
            // Serialization round trip keeps the string.
            let json = serde_json::to_string(&disclosure).unwrap();
            assert_eq!(
                serde_json::from_str::<Disclosure>(&json).unwrap(),
                disclosure
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// §5: the simple example
// ---------------------------------------------------------------------------------------------

#[test]
fn simple_example_issuance() {
    let sd_jwt = SdJwt::parse(vector!("simple", "issuance.txt")).unwrap();
    assert_eq!(sd_jwt.jwt().as_str(), vector!("simple", "jws.txt"));
    assert!(sd_jwt.key_binding_jwt().is_none());
    assert_eq!(sd_jwt.to_string(), vector!("simple", "issuance.txt"));

    let expected = disclosures(vector!("simple", "disclosures.txt"));
    assert_eq!(sd_jwt.disclosures().len(), expected.len());
    for (actual, (_, expected)) in sd_jwt.disclosures().iter().zip(&expected) {
        assert_eq!(actual, expected);
    }

    assert_eq!(
        sd_jwt.payload().unwrap(),
        object(vector!("simple", "payload.json"))
    );
    assert_eq!(sd_jwt.hash_algorithm().unwrap(), HashAlgorithm::Sha256);
    verify_issuer(&sd_jwt);

    // Everything disclosed: the user claims plus the issuer's own.
    let processed = sd_jwt.process().unwrap();
    let mut expected = object(vector!("simple", "user_claims.json"));
    let payload = sd_jwt.payload().unwrap();
    for claim in ["iss", "iat", "exp", "cnf"] {
        expected.insert(claim.to_owned(), payload[claim].clone());
    }
    assert_eq!(processed.payload, expected);
    assert!(processed.undisclosed.is_empty());
    let disclosed: BTreeSet<String> = processed
        .disclosed_paths()
        .map(ToString::to_string)
        .collect();
    let expected_paths: BTreeSet<String> = [
        claim_path!["given_name"],
        claim_path!["family_name"],
        claim_path!["email"],
        claim_path!["phone_number"],
        claim_path!["phone_number_verified"],
        claim_path!["address"],
        claim_path!["birthdate"],
        claim_path!["updated_at"],
        claim_path!["nationalities", 0],
        claim_path!["nationalities", 1],
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(disclosed, expected_paths);
    assert!(processed.is_disclosed(&claim_path!["address"]));
    assert!(!processed.is_disclosed(&claim_path!["address", "locality"]));
}

#[test]
fn simple_example_presentation() {
    let presentation = SdJwt::parse(vector!("simple", "presentation.txt")).unwrap();
    assert_eq!(presentation.disclosures().len(), 4);
    assert_eq!(
        presentation.to_string(),
        vector!("simple", "presentation.txt")
    );
    verify_issuer(&presentation);

    let processed = presentation.process().unwrap();
    assert_eq!(
        processed.payload,
        object(vector!("simple", "verified.json"))
    );
    assert_eq!(processed.undisclosed, vec![claim_path!["nationalities", 1]]);
    let issued = processed.as_issued();
    assert_eq!(issued["nationalities"][0], "US");
    assert_eq!(
        issued["nationalities"][1],
        json!({"...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"})
    );

    let kb = verify_key_binding(&presentation);
    assert_eq!(
        serde_json::to_value(&kb).unwrap(),
        serde_json::from_str::<Value>(vector!("simple", "kb_payload.json")).unwrap()
    );
    assert_eq!(
        kb.additional["sd_hash"],
        "fMV05vuMARs3uG0Dg0BYd_7mQR9EGBkRof0cTZyuqXE"
    );

    // The holder makes the same presentation from the issuance.
    let issuance = SdJwt::parse(vector!("simple", "issuance.txt")).unwrap();
    let selected = issuance
        .disclose(&[
            claim_path!["given_name"],
            claim_path!["family_name"],
            claim_path!["address"],
            claim_path!["nationalities", 0],
        ])
        .unwrap();
    assert!(selected.key_binding_jwt().is_none());
    let chosen: BTreeSet<&str> = selected
        .disclosures()
        .iter()
        .map(Disclosure::as_str)
        .collect();
    let presented: BTreeSet<&str> = presentation
        .disclosures()
        .iter()
        .map(Disclosure::as_str)
        .collect();
    assert_eq!(chosen, presented);
    assert_eq!(selected.process().unwrap().payload, processed.payload);

    let by_name = issuance
        .select(|d| {
            matches!(d.name(), Some("given_name" | "family_name" | "address")) || d.value() == "US"
        })
        .unwrap();
    assert_eq!(by_name, selected);
    assert!(matches!(
        issuance.disclose(&[claim_path!["no_such_claim"]]),
        Err(SdJwtError::NoSuchClaim(_))
    ));
}

#[test]
fn key_binding_jwt_can_be_made_and_checked() {
    let issuance = SdJwt::parse(vector!("simple", "issuance.txt")).unwrap();
    let selected = issuance.disclose(&[claim_path!["given_name"]]).unwrap();
    let holder = Es256Signer::rfc7515_a3();
    let binding = KeyBinding::new(
        "https://verifier.example.org",
        "1234567890",
        Utc.timestamp_opt(1748536865, 0).unwrap(),
    );
    let bound = selected
        .clone()
        .sign_key_binding(&binding, &holder)
        .await_blocking()
        .unwrap();
    let kb = bound.key_binding_jwt().unwrap().decode().unwrap();
    assert_eq!(kb.header().alg, JwsAlgorithm::ES256);
    assert_eq!(kb.header().typ.as_deref(), Some("kb+jwt"));
    kb.verify(&DefaultVerifier, &holder.public_jwk()).unwrap();
    let claims: JwtClaims = serde_json::from_slice(kb.payload()).unwrap();
    assert_eq!(claims.iat, Some(1748536865));
    assert_eq!(
        claims.audiences().collect::<Vec<_>>(),
        ["https://verifier.example.org"]
    );
    assert_eq!(claims.additional["nonce"], "1234567890");
    assert_eq!(
        claims.additional["sd_hash"],
        selected.sd_hash(HashAlgorithm::Sha256)
    );
    assert_eq!(bound.to_string_without_key_binding(), selected.to_string());
    assert_eq!(SdJwt::parse(&bound.to_string()).unwrap(), bound);
    assert_eq!(bound.without_key_binding(), selected);
}

// ---------------------------------------------------------------------------------------------
// §6: nested data
// ---------------------------------------------------------------------------------------------

fn address_claims() -> Map<String, Value> {
    object(
        r#"{
          "iss": "https://issuer.example.com",
          "iat": 1683000000,
          "exp": 1883000000,
          "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
          "address": {
            "street_address": "Schulstr. 12",
            "locality": "Schulpforta",
            "region": "Sachsen-Anhalt",
            "country": "DE"
          }
        }"#,
    )
}

#[test]
fn flat_structured_and_recursive_examples_process_to_the_same_claims() {
    let flat = sd_jwt_of(
        vector!("flat", "payload.json"),
        vector!("flat", "disclosures.txt"),
    );
    let processed = flat.process().unwrap();
    assert_eq!(processed.payload, address_claims());
    assert_eq!(
        processed.disclosed_paths().collect::<Vec<_>>(),
        [&claim_path!["address"]]
    );

    let structured = sd_jwt_of(
        vector!("structured", "payload.json"),
        vector!("structured", "disclosures.txt"),
    );
    let processed = structured.process().unwrap();
    assert_eq!(processed.payload, address_claims());
    assert!(processed.is_disclosed(&claim_path!["address", "region"]));
    assert!(!processed.is_disclosed(&claim_path!["address"]));

    // One member permanently disclosed: `country` has no disclosure.
    let one_open = {
        let text = vector!("structured", "disclosures.txt");
        let kept: Vec<String> = text
            .lines()
            .filter(|line| {
                !line.contains("WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImNvdW50cnkiLCAiREUiXQ")
            })
            .map(str::to_owned)
            .collect();
        sd_jwt_of(
            vector!("structured", "payload_one_open.json"),
            &kept.join("\n"),
        )
    };
    assert_eq!(one_open.process().unwrap().payload, address_claims());

    let recursive = sd_jwt_of(
        vector!("recursive", "payload.json"),
        vector!("recursive", "disclosures.txt"),
    );
    let processed = recursive.process().unwrap();
    assert_eq!(processed.payload, address_claims());
    assert!(processed.is_disclosed(&claim_path!["address"]));
    assert!(processed.is_disclosed(&claim_path!["address", "country"]));

    // A nested disclosure needs the one it is nested in.
    let region = recursive
        .disclose(&[claim_path!["address", "region"]])
        .unwrap();
    assert_eq!(region.disclosures().len(), 2);
    assert_eq!(
        region.process().unwrap().payload["address"],
        json!({"region": "Sachsen-Anhalt"})
    );
    assert!(matches!(
        recursive.select(|d| d.name() == Some("region")),
        Err(SdJwtError::MissingParentDisclosure { .. })
    ));
    let only_address = recursive.disclose(&[claim_path!["address"]]).unwrap();
    assert_eq!(
        only_address.disclosures().len(),
        5,
        "a path keeps what is beneath it"
    );
    let whole = recursive.select(|d| d.name() == Some("address")).unwrap();
    assert_eq!(whole.disclosures().len(), 1);
    assert_eq!(whole.process().unwrap().payload["address"], json!({}));
}

// ---------------------------------------------------------------------------------------------
// Appendices A.1 to A.4
// ---------------------------------------------------------------------------------------------

#[test]
fn simple_structured_example_with_decoys() {
    let issuance = sd_jwt_of(
        vector!("simple_structured", "payload.json"),
        vector!("simple_structured", "disclosures.txt"),
    );
    let processed = issuance.process().unwrap();
    let mut expected = object(vector!("simple_structured", "user_claims.json"));
    let payload = issuance.payload().unwrap();
    for claim in ["iss", "iat", "exp"] {
        expected.insert(claim.to_owned(), payload[claim].clone());
    }
    assert_eq!(processed.payload, expected);
    // Decoys match no disclosure and are not reported: they hide in `_sd` arrays.
    assert!(processed.undisclosed.is_empty());
    let digests = disclosures(vector!("simple_structured", "disclosures.txt"));
    for decoy in vector!("simple_structured", "decoys.txt").lines() {
        assert!(
            Value::Object(payload.clone()).to_string().contains(decoy),
            "decoy {decoy} is in the payload"
        );
        assert!(digests.iter().all(|(hash, _)| hash != decoy));
    }

    let presentation = SdJwt::parse(vector!("simple_structured", "presentation.txt")).unwrap();
    verify_issuer(&presentation);
    assert_eq!(
        presentation.process().unwrap().payload,
        object(vector!("simple_structured", "verified.json"))
    );
}

#[test]
fn complex_structured_example() {
    let presentation = SdJwt::parse(vector!("complex_ekyc", "presentation.txt")).unwrap();
    verify_issuer(&presentation);
    assert_eq!(
        presentation.process().unwrap().payload,
        object(vector!("complex_ekyc", "verified.json"))
    );
    let issuance = sd_jwt_of(
        vector!("complex_ekyc", "payload.json"),
        vector!("complex_ekyc", "disclosures.txt"),
    );
    let mut expected = object(vector!("complex_ekyc", "user_claims.json"));
    let payload = issuance.payload().unwrap();
    for claim in ["iss", "iat", "exp"] {
        expected.insert(claim.to_owned(), payload[claim].clone());
    }
    assert_eq!(issuance.process().unwrap().payload, expected);
}

#[test]
fn sd_jwt_vc_example_of_appendix_a3() {
    let issuance = SdJwt::parse(vector!("sd_jwt_vc", "issuance.txt")).unwrap();
    verify_issuer(&issuance);
    assert_eq!(
        issuance.jwt().decode().unwrap().header().typ.as_deref(),
        Some("dc+sd-jwt")
    );
    assert_eq!(
        issuance.payload().unwrap(),
        object(vector!("sd_jwt_vc", "payload.json"))
    );
    let processed = issuance.process().unwrap();
    let mut expected = object(vector!("sd_jwt_vc", "user_claims.json"));
    let payload = issuance.payload().unwrap();
    for claim in ["iat", "exp", "cnf"] {
        expected.insert(claim.to_owned(), payload[claim].clone());
    }
    assert_eq!(processed.payload, expected);

    let presentation = SdJwt::parse(vector!("sd_jwt_vc", "presentation.txt")).unwrap();
    verify_issuer(&presentation);
    assert_eq!(
        presentation.process().unwrap().payload,
        object(vector!("sd_jwt_vc", "verified.json"))
    );
    let kb = verify_key_binding(&presentation);
    assert_eq!(
        serde_json::to_value(&kb).unwrap(),
        serde_json::from_str::<Value>(vector!("sd_jwt_vc", "kb_payload.json")).unwrap()
    );
}

#[test]
fn w3c_vcdm_example_of_appendix_a4() {
    let issuance = SdJwt::parse(vector!("w3c_vcdm", "issuance.txt")).unwrap();
    verify_issuer(&issuance);
    assert_eq!(
        issuance.payload().unwrap(),
        object(vector!("w3c_vcdm", "payload.json"))
    );
    let processed = issuance.process().unwrap();
    let mut expected = object(vector!("w3c_vcdm", "user_claims.json"));
    let payload = issuance.payload().unwrap();
    for claim in ["iss", "iat", "exp", "cnf"] {
        if let Some(value) = payload.get(claim) {
            expected.insert(claim.to_owned(), value.clone());
        }
    }
    assert_eq!(processed.payload, expected);

    let presentation = SdJwt::parse(vector!("w3c_vcdm", "presentation.txt")).unwrap();
    verify_issuer(&presentation);
    assert_eq!(
        presentation.process().unwrap().payload,
        object(vector!("w3c_vcdm", "verified.json"))
    );
    verify_key_binding(&presentation);
}

// ---------------------------------------------------------------------------------------------
// §7.1: rejections
// ---------------------------------------------------------------------------------------------

#[test]
fn format_errors() {
    let issuance = vector!("simple", "issuance.txt");
    let jws = vector!("simple", "jws.txt");
    assert!(matches!(SdJwt::parse(jws), Err(SdJwtError::Format(_))));
    assert!(matches!(
        SdJwt::parse(&format!("{jws}~~")),
        Err(SdJwtError::Format(_))
    ));
    assert!(matches!(
        SdJwt::parse("not.a~jwt~"),
        Err(SdJwtError::Jws(_))
    ));
    let first = issuance.split('~').nth(1).unwrap();
    assert!(matches!(
        SdJwt::parse(&format!("{jws}~{first}~{first}~")),
        Err(SdJwtError::DuplicateDisclosure(_))
    ));
    assert!(matches!(
        SdJwt::parse(&format!("{jws}~{first}~not-a-disclosure~")),
        Err(SdJwtError::InvalidDisclosure { .. })
    ));
    // Serde goes through the same parser.
    assert!(serde_json::from_value::<SdJwt>(json!(jws)).is_err());
    let parsed: SdJwt = serde_json::from_value(json!(issuance)).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), json!(issuance));
}

#[test]
fn processing_rejections() {
    let header = json!({"alg": "ES256"});
    let given_name = Disclosure::property("2GLC42sKQveCfGfryNRN9w", "given_name", json!("John"));
    let digest = given_name.digest(HashAlgorithm::Sha256);
    let sd_jwt = |payload: Value, disclosures: Vec<Disclosure>| {
        SdJwt::new(
            Jwt::new(unsigned_jwt(&header, &payload)).unwrap(),
            disclosures,
        )
    };

    // A disclosure no digest references.
    let unused = sd_jwt(json!({"_sd": []}), vec![given_name.clone()]);
    assert!(matches!(
        unused.process(),
        Err(SdJwtError::UnusedDisclosure(_))
    ));

    // The same digest twice.
    let duplicate = sd_jwt(json!({"_sd": [digest, digest]}), vec![given_name.clone()]);
    assert!(matches!(
        duplicate.process(),
        Err(SdJwtError::DuplicateDigest(_))
    ));
    let nested = sd_jwt(
        json!({"_sd": [digest], "more": {"_sd": [digest]}}),
        vec![given_name.clone()],
    );
    assert!(matches!(
        nested.process(),
        Err(SdJwtError::DuplicateDigest(_))
    ));

    // A disclosed claim that already exists.
    let existing = sd_jwt(
        json!({"given_name": "Jane", "_sd": [digest]}),
        vec![given_name.clone()],
    );
    assert!(matches!(
        existing.process(),
        Err(SdJwtError::DuplicateClaim { name, .. }) if name == "given_name"
    ));

    // Reserved claim names.
    for reserved in ["_sd", "..."] {
        let disclosure = Disclosure::property("salt", reserved, json!(1));
        let payload = json!({"_sd": [disclosure.digest(HashAlgorithm::Sha256)]});
        assert!(matches!(
            sd_jwt(payload, vec![disclosure]).process(),
            Err(SdJwtError::ReservedClaimName(name)) if name == reserved
        ));
    }

    // The wrong kind of disclosure for the place.
    let element = Disclosure::element("salt", json!("US"));
    let in_object = sd_jwt(
        json!({"_sd": [element.digest(HashAlgorithm::Sha256)]}),
        vec![element.clone()],
    );
    assert!(matches!(
        in_object.process(),
        Err(SdJwtError::WrongDisclosureKind { .. })
    ));
    let in_array = sd_jwt(json!({"list": [{"...": digest}]}), vec![given_name.clone()]);
    assert!(matches!(
        in_array.process(),
        Err(SdJwtError::WrongDisclosureKind { .. })
    ));

    // Malformed digest containers and `_sd_alg`.
    assert!(matches!(
        sd_jwt(json!({"_sd": "x"}), vec![]).process(),
        Err(SdJwtError::Payload { source: None, .. })
    ));
    assert!(matches!(
        sd_jwt(json!({"_sd": [1]}), vec![]).process(),
        Err(SdJwtError::Payload { source: None, .. })
    ));
    assert!(matches!(
        sd_jwt(json!({"_sd_alg": "md5"}), vec![]).process(),
        Err(SdJwtError::UnsupportedHashAlgorithm(name)) if name == "md5"
    ));
    assert!(matches!(
        sd_jwt(json!({"_sd_alg": 5}), vec![]).process(),
        Err(SdJwtError::Payload { .. })
    ));
    // A payload that is not a JSON object: the source is the JSON error.
    let error = SdJwt::new(Jwt::new(unsigned_jwt(&header, &json!([]))).unwrap(), vec![])
        .process()
        .unwrap_err();
    assert!(matches!(error, SdJwtError::Payload { .. }));
    assert!(error.source().unwrap().is::<serde_json::Error>());

    // Other hash algorithms are honoured.
    let digest_512 = given_name.digest(HashAlgorithm::Sha512);
    let sha512 = sd_jwt(
        json!({"_sd": [digest_512], "_sd_alg": "sha-512"}),
        vec![given_name.clone()],
    );
    assert_eq!(sha512.hash_algorithm().unwrap(), HashAlgorithm::Sha512);
    assert_eq!(
        sha512.process().unwrap().payload,
        object(r#"{"given_name": "John"}"#)
    );
    assert!(matches!(
        sd_jwt(
            json!({"_sd": [digest], "_sd_alg": "sha-512"}),
            vec![given_name]
        )
        .process(),
        Err(SdJwtError::UnusedDisclosure(_))
    ));

    // An array element object with `...` and more keys, or a non-string, is plain data.
    let plain = sd_jwt(json!({"list": [{"...": 1}, {"...": "x", "y": 2}]}), vec![]);
    assert_eq!(
        plain.process().unwrap().payload["list"],
        json!([{"...": 1}, {"...": "x", "y": 2}])
    );
}

// ---------------------------------------------------------------------------------------------
// Issuing with the builder
// ---------------------------------------------------------------------------------------------

/// A salt generator replaying the salts of a `disclosures.txt`, in order.
fn spec_salts(text: &'static str) -> impl FnMut() -> String + Send + 'static {
    let mut salts = disclosures(text)
        .into_iter()
        .map(|(_, d)| d.salt().to_owned())
        .collect::<Vec<_>>()
        .into_iter();
    move || salts.next().expect("a salt per disclosure")
}

#[test]
fn claims_nested_beyond_the_limit_are_refused() {
    // `depth` objects around a scalar, each with the member `a`; the claims set adds one.
    let chain = |depth: usize| (0..depth).fold(json!(1), |inner, _| json!({ "a": inner }));
    let claims = |depth: usize| {
        let mut claims = Map::new();
        claims.insert("c".to_owned(), chain(depth));
        claims
    };
    let deepest = claims(SdJwtBuilder::MAX_DEPTH - 1);
    let too_deep = claims(SdJwtBuilder::MAX_DEPTH);
    assert!(matches!(
        SdJwtBuilder::new(too_deep).encode(),
        Err(SdJwtError::TooDeep { max }) if max == SdJwtBuilder::MAX_DEPTH
    ));
    // An array at the bottom counts as a container too.
    let with_leaf = |leaf: Value| {
        let mut claims = claims(SdJwtBuilder::MAX_DEPTH - 2);
        let mut bottom = &mut claims["c"];
        for _ in 0..SdJwtBuilder::MAX_DEPTH - 2 {
            bottom = &mut bottom["a"];
        }
        *bottom = leaf;
        claims
    };
    assert!(SdJwtBuilder::new(with_leaf(json!([1]))).encode().is_ok());
    assert!(matches!(
        SdJwtBuilder::new(with_leaf(json!([[1]]))).encode(),
        Err(SdJwtError::TooDeep { .. })
    ));

    // At the limit, every way of concealing still processes back to the claims.
    let bottom: Vec<&str> = std::iter::once("c")
        .chain(std::iter::repeat_n("a", SdJwtBuilder::MAX_DEPTH - 2))
        .collect();
    let every_level: Vec<ClaimPath> = (1..=bottom.len())
        .map(|len| ClaimPath::new(bottom[..len].iter().copied()))
        .collect();
    for conceal in [
        Vec::new(),
        vec![ClaimPath::new(["c"])],
        vec![ClaimPath::new(bottom.iter().copied())],
        every_level,
    ] {
        let mut builder = SdJwtBuilder::new(deepest.clone()).with_decoys(2);
        for path in &conceal {
            builder = builder.conceal(path.clone());
        }
        let encoded = builder.encode().unwrap();
        assert_eq!(encoded.disclosures.len(), conceal.len());
        let jwt: Jwt = unsigned_jwt(&json!({ "alg": "ES256" }), &Value::Object(encoded.payload))
            .parse()
            .unwrap();
        let sd_jwt = SdJwt::new(jwt, encoded.disclosures);
        let again = SdJwt::parse(&sd_jwt.to_string()).unwrap();
        assert_eq!(again.process().unwrap().as_issued(), &deepest);
    }
}

/// How [`disclosure_chain`] nests the next disclosure in a value.
#[derive(Clone, Copy)]
enum Link {
    /// As an object property, through `_sd`.
    Property,
    /// As an array element, through `...`.
    Element,
}

/// A payload and disclosures nesting one another along `links`, outermost first: each
/// disclosure's value holds the digest of the next, and the innermost holds a scalar.
fn disclosure_chain(links: &[Link]) -> (Value, Vec<Disclosure>) {
    let mut disclosures = Vec::with_capacity(links.len());
    let mut value = json!(1);
    for (i, link) in links.iter().enumerate().rev() {
        let salt = format!("salt-{i}");
        let (disclosure, container) = match link {
            Link::Property => {
                let disclosure = Disclosure::property(salt, "c", value);
                let digest = disclosure.digest(HashAlgorithm::Sha256);
                (disclosure, json!({ "_sd": [digest] }))
            }
            Link::Element => {
                let disclosure = Disclosure::element(salt, value);
                let digest = disclosure.digest(HashAlgorithm::Sha256);
                (disclosure, json!([{ "...": digest }]))
            }
        };
        disclosures.push(disclosure);
        value = container;
    }
    let payload = if value.is_object() {
        value
    } else {
        json!({ "c": value })
    };
    (payload, disclosures)
}

fn chained(links: &[Link]) -> SdJwt {
    let (payload, disclosures) = disclosure_chain(links);
    let jwt = Jwt::new(unsigned_jwt(&json!({ "alg": "ES256" }), &payload)).unwrap();
    SdJwt::new(jwt, disclosures)
}

#[test]
fn disclosures_nested_beyond_the_limit_are_refused() {
    fn too_deep<T>(result: Result<T, SdJwtError>) -> bool {
        matches!(result, Err(SdJwtError::TooDeep { max }) if max == SdJwtBuilder::MAX_DEPTH)
    }

    // `n` property links nest the claims `n` containers deep, counting the payload.
    let deepest = chained(&[Link::Property; SdJwtBuilder::MAX_DEPTH]);
    let processed = deepest.process().unwrap();
    assert_eq!(processed.disclosed_paths().count(), SdJwtBuilder::MAX_DEPTH);
    assert!(too_deep(
        chained(&[Link::Property; SdJwtBuilder::MAX_DEPTH + 1]).process()
    ));

    // Long chains are refused at the limit, not followed: through properties, array elements
    // or both, whatever the order of the disclosures.
    let alternating: Vec<Link> = (0..1000)
        .map(|i| {
            if i % 2 == 0 {
                Link::Property
            } else {
                Link::Element
            }
        })
        .collect();
    for links in [
        vec![Link::Property; 1000],
        vec![Link::Element; 1000],
        alternating,
    ] {
        let sd_jwt = chained(&links);
        assert!(too_deep(sd_jwt.process()));
        let reversed = SdJwt::new(
            sd_jwt.jwt().clone(),
            sd_jwt.disclosures().iter().rev().cloned().collect(),
        );
        assert!(too_deep(reversed.process()));
        assert!(too_deep(
            SdJwt::parse(&sd_jwt.to_string()).unwrap().process()
        ));
        assert!(too_deep(sd_jwt.select(|_| true)));
    }

    // Plain claims count too: a chain of 8 links (8 containers) under `wraps` plain objects
    // nests `wraps + 8` deep.
    let wrapped = |wraps: usize| {
        let (inner, disclosures) = disclosure_chain(&[Link::Property; 8]);
        let payload = (0..wraps).fold(inner, |inner, _| json!({ "a": inner }));
        let jwt = Jwt::new(unsigned_jwt(&json!({ "alg": "ES256" }), &payload)).unwrap();
        SdJwt::new(jwt, disclosures).process()
    };
    assert!(wrapped(SdJwtBuilder::MAX_DEPTH - 8).is_ok());
    assert!(too_deep(wrapped(SdJwtBuilder::MAX_DEPTH - 7)));
    // Plain arrays count towards the depth too.
    let in_arrays = |wraps: usize| {
        let (inner, disclosures) = disclosure_chain(&[Link::Property; 8]);
        let payload = json!({ "a": (0..wraps).fold(inner, |inner, _| json!([inner])) });
        let jwt = Jwt::new(unsigned_jwt(&json!({ "alg": "ES256" }), &payload)).unwrap();
        SdJwt::new(jwt, disclosures).process()
    };
    assert!(in_arrays(SdJwtBuilder::MAX_DEPTH - 9).is_ok());
    assert!(too_deep(in_arrays(SdJwtBuilder::MAX_DEPTH - 8)));
}

#[test]
fn builder_reproduces_the_simple_example() {
    let mut claims = object(vector!("simple", "user_claims.json"));
    let spec_payload = object(vector!("simple", "payload.json"));
    for claim in ["iss", "iat", "exp", "cnf"] {
        claims.insert(claim.to_owned(), spec_payload[claim].clone());
    }
    let builder = SdJwtBuilder::new(claims.clone())
        .conceal(["given_name"])
        .conceal(["family_name"])
        .conceal(["email"])
        .conceal(["phone_number"])
        .conceal(["phone_number_verified"])
        .conceal(["address"])
        .conceal(["birthdate"])
        .conceal(["updated_at"])
        .conceal(claim_path!["nationalities", ()])
        .with_salt_generator(spec_salts(vector!("simple", "disclosures.txt")));
    assert_eq!(builder.claims(), &claims);
    assert_eq!(builder.concealed().len(), 9);
    assert_eq!(builder.concealed()[0], claim_path!["given_name"]);
    let encoded = builder.encode().unwrap();

    // The disclosures have the specification's contents, in its order; only the JSON
    // whitespace differs, so the digests do too.
    let expected = disclosures(vector!("simple", "disclosures.txt"));
    assert_eq!(encoded.disclosures.len(), expected.len());
    for (ours, (_, theirs)) in encoded.disclosures.iter().zip(&expected) {
        assert_eq!(
            (ours.salt(), ours.name(), ours.value()),
            (theirs.salt(), theirs.name(), theirs.value())
        );
    }
    assert_eq!(encoded.payload["_sd"].as_array().unwrap().len(), 8);
    assert_eq!(encoded.payload["_sd_alg"], "sha-256");
    assert_eq!(
        encoded.payload["nationalities"].as_array().unwrap().len(),
        2
    );
    assert!(encoded.payload["nationalities"][0].get("...").is_some());
    for claim in ["iss", "iat", "exp", "sub", "cnf"] {
        assert_eq!(encoded.payload[claim], spec_payload[claim]);
    }
    // `_sd` is sorted, as the specification recommends.
    let sd: Vec<&str> = encoded.payload["_sd"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut sorted = sd.clone();
    sorted.sort_unstable();
    assert_eq!(sd, sorted);

    // Signed, the SD-JWT processes back to the claims.
    let signer = Es256Signer::rfc7515_a3();
    let header = JwsHeader::new(JwsAlgorithm::ES256).with_typ("example+sd-jwt");
    let sd_jwt = SdJwtBuilder::new(claims.clone())
        .conceal(["given_name"])
        .conceal(["address"])
        .conceal(claim_path!["nationalities", ()])
        .sign(&header, &signer)
        .await_blocking()
        .unwrap();
    sd_jwt
        .jwt()
        .decode()
        .unwrap()
        .verify(&DefaultVerifier, &signer.public_jwk())
        .unwrap();
    assert_eq!(sd_jwt.disclosures().len(), 4);
    assert_eq!(sd_jwt.process().unwrap().payload, claims);
    let reparsed = SdJwt::parse(&sd_jwt.to_string()).unwrap();
    assert_eq!(reparsed, sd_jwt);
}

#[test]
fn builder_makes_recursive_disclosures_and_decoys() {
    let claims = address_claims();
    let encoded = SdJwtBuilder::new(claims.clone())
        .conceal(["address", "street_address"])
        .conceal(["address", "locality"])
        .conceal(["address", "region"])
        .conceal(["address", "country"])
        .conceal(["address"])
        .with_salt_generator(spec_salts(vector!("recursive", "disclosures.txt")))
        .encode()
        .unwrap();
    let expected = disclosures(vector!("recursive", "disclosures.txt"));
    for (ours, (_, theirs)) in encoded.disclosures.iter().zip(&expected) {
        assert_eq!((ours.salt(), ours.name()), (theirs.salt(), theirs.name()));
    }
    let address = encoded.disclosures.last().unwrap();
    assert_eq!(address.name(), Some("address"));
    assert_eq!(address.value()["_sd"].as_array().unwrap().len(), 4);
    assert_eq!(encoded.payload["_sd"].as_array().unwrap().len(), 1);
    assert!(!encoded.payload.contains_key("address"));

    let jwt = Jwt::new(unsigned_jwt(
        &json!({"alg": "ES256"}),
        &Value::Object(encoded.payload),
    ))
    .unwrap();
    let sd_jwt = SdJwt::new(jwt, encoded.disclosures);
    assert_eq!(sd_jwt.process().unwrap().payload, claims);

    // Decoys pad every `_sd` array.
    let decoyed = SdJwtBuilder::new(claims.clone())
        .conceal(["address", "region"])
        .conceal(["address"])
        .with_decoys(3)
        .encode()
        .unwrap();
    assert_eq!(decoyed.payload["_sd"].as_array().unwrap().len(), 4);
    let address = decoyed
        .disclosures
        .iter()
        .find(|d| d.name() == Some("address"))
        .unwrap();
    assert_eq!(address.value()["_sd"].as_array().unwrap().len(), 4);
    let jwt = Jwt::new(unsigned_jwt(
        &json!({"alg": "ES256"}),
        &Value::Object(decoyed.payload),
    ))
    .unwrap();
    assert_eq!(
        SdJwt::new(jwt, decoyed.disclosures)
            .process()
            .unwrap()
            .payload,
        claims
    );

    // Nothing concealed: no `_sd_alg`.
    let plain = SdJwtBuilder::new(claims.clone()).encode().unwrap();
    assert_eq!(plain.payload, claims);
    assert!(plain.disclosures.is_empty());

    // Other hash algorithms, random salts of 128 bits.
    let sha384 = SdJwtBuilder::new(claims.clone())
        .conceal(["sub"])
        .with_hash_algorithm(HashAlgorithm::Sha384)
        .encode()
        .unwrap();
    assert_eq!(sha384.payload["_sd_alg"], "sha-384");
    assert_eq!(common::decode(sha384.disclosures[0].salt()).len(), 16);
    let jwt = Jwt::new(unsigned_jwt(
        &json!({"alg": "ES256"}),
        &Value::Object(sha384.payload),
    ))
    .unwrap();
    assert_eq!(
        SdJwt::new(jwt, sha384.disclosures)
            .process()
            .unwrap()
            .payload,
        claims
    );
}

#[test]
fn builder_rejects_bad_paths() {
    let claims = address_claims();
    assert!(matches!(
        SdJwtBuilder::new(claims.clone())
            .conceal(["no_such"])
            .encode(),
        Err(SdJwtError::NoSuchClaim(_))
    ));
    assert!(matches!(
        SdJwtBuilder::new(claims.clone())
            .conceal(["address", "no_such"])
            .encode(),
        Err(SdJwtError::NoSuchClaim(_))
    ));
    let mut reserved = claims.clone();
    reserved.insert("_sd".to_owned(), json!([]));
    assert!(matches!(
        SdJwtBuilder::new(reserved).conceal(["sub"]).encode(),
        Err(SdJwtError::Payload { .. })
    ));
    let mut alg = claims.clone();
    alg.insert("_sd_alg".to_owned(), json!("sha-256"));
    assert!(matches!(
        SdJwtBuilder::new(alg).encode(),
        Err(SdJwtError::Payload { .. })
    ));
    let mut dots = claims;
    dots.insert("...".to_owned(), json!("x"));
    assert!(matches!(
        SdJwtBuilder::new(dots).conceal(["..."]).encode(),
        Err(SdJwtError::NotConcealable { .. })
    ));
}

#[test]
fn claim_paths() {
    let path = claim_path!["degrees", (), "type"];
    assert_eq!(path.to_string(), r#"["degrees", null, "type"]"#);
    assert_eq!(
        serde_json::to_value(&path).unwrap(),
        json!(["degrees", null, "type"])
    );
    assert_eq!(
        serde_json::from_value::<ClaimPath>(json!(["degrees", null, "type"])).unwrap(),
        path
    );
    assert!(!path.is_concrete());
    assert!(path.matches(&claim_path!["degrees", 2, "type"]));
    assert!(!path.matches(&claim_path!["degrees", "x", "type"]));
    assert!(path.is_prefix_of(&claim_path!["degrees", 0, "type", "name"]));
    assert!(!claim_path!["degrees", 0].is_prefix_of(&claim_path!["degrees"]));
    assert_eq!(ClaimPath::new(["a", "b"]).join(1), claim_path!["a", "b", 1]);
    assert!(ClaimPath::root().is_empty());
}

/// Runs a future to completion on a small runtime.
trait AwaitBlocking: Future + Sized {
    fn await_blocking(self) -> Self::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(self)
    }
}

impl<F: Future> AwaitBlocking for F {}

#[test]
fn hash_algorithm_names() {
    // RFC 9901 §4.1.1: `_sd_alg` names the algorithm by its IANA name.
    for (algorithm, name) in [
        (HashAlgorithm::Sha256, "sha-256"),
        (HashAlgorithm::Sha384, "sha-384"),
        (HashAlgorithm::Sha512, "sha-512"),
    ] {
        assert_eq!(algorithm.to_string(), name);
        assert_eq!(serde_json::to_value(algorithm).unwrap(), json!(name));
        assert_eq!(
            serde_json::from_value::<HashAlgorithm>(json!(name)).unwrap(),
            algorithm
        );
    }
    assert!(serde_json::from_value::<HashAlgorithm>(json!("md5")).is_err());
}
