//! SD-JWT VC vectors: the identity credential of §2.3 (issuance, presentation with and
//! without key binding) and the PID credential of Appendix A.1; the Token Status List
//! examples of §4, §5, §6 and Appendix C; the type metadata of §5.1, §5.6 and Appendix A.2.
#![cfg(feature = "sd-jwt")]

mod common;

use chrono::{TimeZone as _, Utc};
use identity_kit::claim_path;
use identity_kit::jose::{DefaultVerifier, Jwk};
use identity_kit::sd_jwt_vc::{
    ClaimMetadata, ClaimPath, Integrity, IntegrityAlgorithm, IntegrityError, LEGACY_TYP,
    NON_DISCLOSABLE_CLAIMS, SdJwt, SdJwtError, SdJwtVc, SdJwtVcClaims, SdJwtVcError, SdPolicy,
    Status, StatusList, StatusListError, StatusListRef, StatusListToken, StatusMechanism,
    StatusType, TYP, TypeMetadata, TypeMetadataError,
};
use identity_kit::vc::{Jwt, JwtClaims};
use serde_json::{Map, Value, json};

use common::unsigned_jwt;

macro_rules! vector {
    ($dir:literal, $file:literal) => {
        include_str!(concat!("vectors/", $dir, "/", $file)).trim()
    };
}

fn object(text: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(text)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

/// An SD-JWT VC over `payload` (unsigned) with `typ`, carrying `disclosures`.
fn credential_of(
    typ: Option<&str>,
    payload: Value,
    disclosures: Vec<&str>,
) -> Result<SdJwtVc, SdJwtVcError> {
    let mut header = json!({"alg": "ES256"});
    if let Some(typ) = typ {
        header["typ"] = json!(typ);
    }
    let mut compact = format!("{}~", unsigned_jwt(&header, &payload));
    for disclosure in disclosures {
        compact.push_str(disclosure);
        compact.push('~');
    }
    SdJwtVc::parse(&compact)
}

// ---------------------------------------------------------------------------------------------
// SD-JWT VC §2.3 and Appendix A.1
// ---------------------------------------------------------------------------------------------

#[test]
fn identity_credential_issuance() {
    let credential =
        SdJwtVc::parse(vector!("sd_jwt_vc/identity_credential", "issuance.txt")).unwrap();
    assert_eq!(credential.header().typ.as_deref(), Some(TYP));
    assert_eq!(
        credential.header().kid.as_deref(),
        Some("doc-signer-05-25-2022")
    );
    assert!(!credential.has_legacy_typ());
    let claims = credential.claims();
    assert_eq!(
        claims.vct,
        "https://credentials.example.com/identity_credential"
    );
    assert_eq!(claims.iss.as_deref(), Some("https://example.com/issuer"));
    assert_eq!(claims.iat, Some(1683000000));
    assert_eq!(claims.exp, Some(1883000000));
    assert_eq!(claims.sub, None);
    assert_eq!(credential.holder_key().map(Jwk::crv), Some(Some("P-256")));

    let mut expected = object(vector!("sd_jwt_vc/identity_credential", "user_claims.json"));
    let payload = object(vector!("sd_jwt_vc/identity_credential", "payload.json"));
    for claim in ["iss", "iat", "exp", "cnf"] {
        expected.insert(claim.to_owned(), payload[claim].clone());
    }
    assert_eq!(credential.payload(), &expected);
    assert_eq!(credential.sd_jwt().payload().unwrap(), payload);
    assert_eq!(credential.sd_jwt().disclosures().len(), 9);
    assert_eq!(
        credential.to_string(),
        vector!("sd_jwt_vc/identity_credential", "issuance.txt")
    );

    // The holder's presentation of §2.3.2 from the issuance.
    let presented = credential
        .disclose(&[claim_path!["is_over_65"], claim_path!["address"]])
        .unwrap();
    assert_eq!(presented.sd_jwt().disclosures().len(), 2);
    assert_eq!(
        presented.payload(),
        &object(vector!("sd_jwt_vc/identity_credential", "verified.json"))
    );
}

#[test]
fn identity_credential_presentations() {
    let with_kb =
        SdJwtVc::parse(vector!("sd_jwt_vc/identity_credential", "presentation.txt")).unwrap();
    assert_eq!(
        with_kb.payload(),
        &object(vector!("sd_jwt_vc/identity_credential", "verified.json"))
    );
    let kb = with_kb
        .sd_jwt()
        .key_binding_jwt()
        .unwrap()
        .decode()
        .unwrap();
    kb.verify(&DefaultVerifier, with_kb.holder_key().unwrap())
        .unwrap();
    let kb_claims: JwtClaims = serde_json::from_slice(kb.payload()).unwrap();
    assert_eq!(kb_claims.additional["nonce"], "1234567890");
    assert_eq!(
        kb_claims.audiences().collect::<Vec<_>>(),
        ["https://example.com/verifier"]
    );
    assert_eq!(
        kb_claims.additional["sd_hash"],
        with_kb
            .sd_jwt()
            .sd_hash(with_kb.sd_jwt().hash_algorithm().unwrap())
    );
    assert!(with_kb.processed().is_disclosed(&claim_path!["is_over_65"]));
    assert!(!with_kb.processed().is_disclosed(&claim_path!["given_name"]));

    let without_kb = SdJwtVc::parse(vector!(
        "sd_jwt_vc/identity_credential",
        "presentation_no_kb.txt"
    ))
    .unwrap();
    assert!(without_kb.sd_jwt().key_binding_jwt().is_none());
    assert_eq!(
        without_kb.payload(),
        &object(vector!(
            "sd_jwt_vc/identity_credential",
            "verified_no_kb.json"
        ))
    );
    assert_eq!(without_kb.claims().cnf, None);
    let roundtrip: SdJwtVc = serde_json::from_value(json!(without_kb.to_string())).unwrap();
    assert_eq!(roundtrip, without_kb);
}

#[test]
fn pid_credential() {
    let issuance = SdJwtVc::parse(vector!("sd_jwt_vc/pid", "issuance.txt")).unwrap();
    assert_eq!(issuance.claims().vct, "urn:example:eudi:pid:aendgard:1");
    assert_eq!(
        issuance.claims().iss.as_deref(),
        Some("https://pid-issuer.aendgard.example")
    );
    assert_eq!(
        issuance.sd_jwt().payload().unwrap(),
        object(vector!("sd_jwt_vc/pid", "payload.json"))
    );
    assert_eq!(issuance.payload()["given_name"], "Astrid");
    assert_eq!(issuance.payload()["address"]["locality"], "Viken");
    assert_eq!(issuance.payload()["nationalities"], json!(["Ændgard"]));
    assert!(
        issuance.payload()["portrait"]
            .as_str()
            .unwrap()
            .starts_with("data:image/png;base64,")
    );

    let presentation = SdJwtVc::parse(vector!("sd_jwt_vc/pid", "presentation.txt")).unwrap();
    assert_eq!(
        presentation.payload(),
        &object(vector!("sd_jwt_vc/pid", "verified.json"))
    );
    let kb = presentation
        .sd_jwt()
        .key_binding_jwt()
        .unwrap()
        .decode()
        .unwrap();
    kb.verify(&DefaultVerifier, presentation.holder_key().unwrap())
        .unwrap();
    let kb_claims: Value = serde_json::from_slice(kb.payload()).unwrap();
    assert_eq!(kb_claims, json(vector!("sd_jwt_vc/pid", "kb_payload.json")));
    assert_eq!(
        kb_claims["sd_hash"],
        presentation
            .sd_jwt()
            .sd_hash(presentation.sd_jwt().hash_algorithm().unwrap())
    );
    // The same presentation from the issuance.
    let again = issuance
        .disclose(&[
            claim_path!["age_equal_or_over", "18"],
            claim_path!["nationalities"],
        ])
        .unwrap();
    assert_eq!(again.payload(), presentation.payload());
}

#[test]
fn typ_and_registered_claims_are_enforced() {
    let payload = json!({
        "vct": "https://credentials.example.com/identity_credential",
        "iss": "https://example.com/issuer",
        "exp": 1883000000
    });
    assert!(matches!(
        credential_of(None, payload.clone(), vec![]),
        Err(SdJwtVcError::MissingTyp)
    ));
    assert!(matches!(
        credential_of(Some("JWT"), payload.clone(), vec![]),
        Err(SdJwtVcError::UnexpectedTyp(typ)) if typ == "JWT"
    ));
    let legacy = credential_of(Some(LEGACY_TYP), payload.clone(), vec![]).unwrap();
    assert!(legacy.has_legacy_typ());
    let current = credential_of(Some(TYP), payload.clone(), vec![]).unwrap();
    assert!(!current.has_legacy_typ());
    assert!(current.sd_jwt().disclosures().is_empty());

    // No `vct`.
    assert!(matches!(
        credential_of(Some(TYP), json!({"iss": "x"}), vec![]),
        Err(SdJwtVcError::Claims(_))
    ));
    // `aka_vcts` rules.
    assert!(matches!(
        credential_of(Some(TYP), json!({"vct": "a", "aka_vcts": []}), vec![]),
        Err(SdJwtVcError::InvalidClaim {
            claim: "aka_vcts",
            ..
        })
    ));
    assert!(matches!(
        credential_of(Some(TYP), json!({"vct": "a", "aka_vcts": ["a"]}), vec![]),
        Err(SdJwtVcError::InvalidClaim {
            claim: "aka_vcts",
            ..
        })
    ));
    let aka = credential_of(
        Some(TYP),
        json!({"vct": "urn:example:eudi:pid:aendgard:1", "aka_vcts": ["urn:example:eudi:pid"]}),
        vec![],
    )
    .unwrap();
    assert_eq!(
        aka.claims().aka_vcts.as_deref(),
        Some(&["urn:example:eudi:pid".to_owned()][..])
    );

    // The registered claims that must stay in the clear.
    for claim in NON_DISCLOSABLE_CLAIMS {
        let disclosure = identity_kit::sd_jwt_vc::Disclosure::property(
            "salt",
            claim,
            json!("https://example.com/issuer"),
        );
        let mut payload = json!({"vct": "a"});
        payload["_sd"] = json!([disclosure.digest(Default::default())]);
        if claim == "vct" {
            payload.as_object_mut().unwrap().remove("vct");
        }
        let result = credential_of(Some(TYP), payload, vec![disclosure.as_str()]);
        assert!(
            matches!(&result, Err(SdJwtVcError::DisclosedRegisteredClaim(name)) if name == claim),
            "{claim}: {result:?}"
        );
    }
    // A sub-claim of one either.
    let disclosure = identity_kit::sd_jwt_vc::Disclosure::property("salt", "jwk", json!({}));
    let payload = json!({"vct": "a", "cnf": {"_sd": [disclosure.digest(Default::default())]}});
    assert!(matches!(
        credential_of(Some(TYP), payload, vec![disclosure.as_str()]),
        Err(SdJwtVcError::DisclosedRegisteredClaim(name)) if name == "cnf"
    ));
    // `sub` and `iat` may be disclosed.
    let sub = identity_kit::sd_jwt_vc::Disclosure::property("salt", "sub", json!("user_42"));
    let payload = json!({"vct": "a", "_sd": [sub.digest(Default::default())]});
    let credential = credential_of(Some(TYP), payload, vec![sub.as_str()]).unwrap();
    assert_eq!(credential.claims().sub.as_deref(), Some("user_42"));

    // Processing errors surface as SD-JWT errors.
    let payload = json!({"vct": "a", "_sd": []});
    assert!(matches!(
        credential_of(Some(TYP), payload, vec![sub.as_str()]),
        Err(SdJwtVcError::SdJwt(SdJwtError::UnusedDisclosure(_)))
    ));
}

#[test]
fn claims_setters_and_serialization() {
    let claims = SdJwtVcClaims::new("https://credentials.example.com/identity_credential")
        .with_issuer("https://example.com/issuer")
        .with_subject("user_42")
        .with_jti("urn:uuid:9f4e9c2f-5d0d-4f0a-8d8e-2a9b7a3f5c11")
        .with_issued_at(Utc.timestamp_opt(1683000000, 0).unwrap())
        .with_not_before(Utc.timestamp_opt(1683000000, 0).unwrap())
        .with_expires_at(Utc.timestamp_opt(1883000000, 0).unwrap())
        .with_type_integrity("sha256-5qAmRHgxiSHIPqS+mLzrVKVWliOBm955Oj86pMrc5g4=")
        .with_aka_vct("https://credentials.example.com/credential")
        .with_status(Status::status_list(StatusListRef::new(
            "https://example.com/statuslists/1",
            0,
        )))
        .with_claim("given_name", "John");
    let value = serde_json::to_value(&claims).unwrap();
    assert_eq!(
        value,
        json!({
            "vct": "https://credentials.example.com/identity_credential",
            "vct#integrity": "sha256-5qAmRHgxiSHIPqS+mLzrVKVWliOBm955Oj86pMrc5g4=",
            "aka_vcts": ["https://credentials.example.com/credential"],
            "iss": "https://example.com/issuer",
            "sub": "user_42",
            "jti": "urn:uuid:9f4e9c2f-5d0d-4f0a-8d8e-2a9b7a3f5c11",
            "iat": 1683000000,
            "nbf": 1683000000,
            "exp": 1883000000,
            "status": {"status_list": {"idx": 0, "uri": "https://example.com/statuslists/1"}},
            "given_name": "John"
        })
    );
    assert_eq!(
        serde_json::from_value::<SdJwtVcClaims>(value).unwrap(),
        claims
    );
    assert_eq!(claims.to_map()["given_name"], "John");
    assert!(claims.check().is_ok());
}

// ---------------------------------------------------------------------------------------------
// Token Status List
// ---------------------------------------------------------------------------------------------

#[test]
fn status_claim_of_a_referenced_token() {
    // §6.2: the claim, and the SD-JWT carrying it.
    let payload = json(vector!("status_list", "referenced_payload.json"));
    let status: Status = serde_json::from_value(payload["status"].clone()).unwrap();
    assert_eq!(
        status,
        Status::status_list(StatusListRef::new("https://example.com/statuslists/1", 0))
    );
    assert_eq!(serde_json::to_value(&status).unwrap(), payload["status"]);
    let mechanisms: Vec<_> = status.mechanisms().collect();
    assert_eq!(mechanisms.len(), 1);
    assert!(matches!(mechanisms[0], StatusMechanism::StatusList(r) if r.idx == 0));

    let other = Status::new().with_mechanism("example_mechanism", json!({"id": 7}));
    assert!(other.status_list.is_none());
    assert!(matches!(
        other.mechanisms().next(),
        Some(StatusMechanism::Other {
            name: "example_mechanism",
            ..
        })
    ));
    assert!(Status::new().is_empty());

    let sd_jwt = SdJwt::parse(vector!("status_list", "referenced_sd_jwt.txt")).unwrap();
    assert_eq!(
        sd_jwt.payload().unwrap(),
        object(vector!("status_list", "referenced_processed.json"))
    );
    let processed = sd_jwt.process().unwrap();
    let status: Status = serde_json::from_value(processed.payload["status"].clone()).unwrap();
    assert_eq!(
        status.status_list.unwrap().uri,
        "https://example.com/statuslists/1"
    );
    assert_eq!(processed.payload["address"]["locality"], "Schulpforta");
}

#[test]
fn status_list_encoding_of_section_4() {
    // §4.1 and §4.2: 16 statuses of 1 bit, 12 statuses of 2 bits.
    let one_bit: StatusList =
        serde_json::from_str(vector!("status_list", "list_1bit.json")).unwrap();
    assert_eq!(one_bit.bits(), 1);
    assert_eq!(one_bit.as_bytes(), &[0xb9, 0xa3]);
    assert_eq!(one_bit.len(), 16);
    let expected = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
    for (index, status) in expected.iter().enumerate() {
        assert_eq!(
            one_bit.get(index as u64),
            Some(StatusType(*status)),
            "status[{index}]"
        );
    }
    assert_eq!(one_bit.get(16), None);

    let two_bit: StatusList =
        serde_json::from_str(vector!("status_list", "list_2bit.json")).unwrap();
    assert_eq!(two_bit.bits(), 2);
    assert_eq!(two_bit.as_bytes(), &[0xc9, 0x44, 0xf9]);
    assert_eq!(two_bit.len(), 12);
    let expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
    for (index, status) in expected.iter().enumerate() {
        assert_eq!(
            two_bit.get(index as u64),
            Some(StatusType(*status)),
            "status[{index}]"
        );
    }
    assert_eq!(two_bit.get(5), Some(StatusType::INVALID));
    assert_eq!(two_bit.get(1), Some(StatusType::SUSPENDED));

    // Rebuilt from the statuses, the byte arrays are the same; the compressed form decodes
    // back to them.
    let mut rebuilt = StatusList::new(2, 12).unwrap();
    for (index, status) in expected.iter().enumerate() {
        rebuilt.set(index as u64, StatusType(*status)).unwrap();
    }
    assert_eq!(rebuilt.as_bytes(), two_bit.as_bytes());
    let lst = rebuilt.to_lst();
    let decoded = StatusList::from_lst(2, &lst, StatusList::MAX_BYTES).unwrap();
    assert_eq!(decoded, rebuilt);
    let value = serde_json::to_value(&rebuilt).unwrap();
    assert_eq!(value["bits"], 2);
    assert_eq!(
        serde_json::from_value::<StatusList>(value).unwrap(),
        rebuilt
    );

    // Errors.
    assert!(matches!(
        StatusList::new(3, 1),
        Err(StatusListError::InvalidBits(3))
    ));
    assert!(matches!(
        rebuilt.set(12, StatusType::VALID),
        Err(StatusListError::IndexOutOfRange { idx: 12, len: 12 })
    ));
    assert!(matches!(
        rebuilt.set(0, StatusType(4)),
        Err(StatusListError::InvalidStatusValue { value: 4, bits: 2 })
    ));
    assert!(matches!(
        StatusList::from_lst(1, "not-zlib", StatusList::MAX_BYTES),
        Err(StatusListError::Compression(_))
    ));
    assert!(matches!(
        StatusList::from_lst(1, "eNrbuRgAAhcBXQ", 1),
        Err(StatusListError::TooLarge { limit: 1 })
    ));
    let mut aggregated = StatusList::new(8, 4)
        .unwrap()
        .with_aggregation_uri("https://example.com/aggregation");
    aggregated.set(3, StatusType(255)).unwrap();
    let value = serde_json::to_value(&aggregated).unwrap();
    assert_eq!(value["aggregation_uri"], "https://example.com/aggregation");
    let decoded: StatusList = serde_json::from_value(value).unwrap();
    assert_eq!(
        decoded.aggregation_uri(),
        Some("https://example.com/aggregation")
    );
    assert_eq!(decoded.get(3), Some(StatusType(255)));
}

#[test]
fn status_list_test_vectors_of_appendix_c() {
    let vectors = [
        (
            vector!("status_list", "c1_1bit.json"),
            vector!("status_list", "c1_1bit_statuses.json"),
            1,
        ),
        (
            vector!("status_list", "c2_2bit.json"),
            vector!("status_list", "c2_2bit_statuses.json"),
            2,
        ),
        (
            vector!("status_list", "c3_4bit.json"),
            vector!("status_list", "c3_4bit_statuses.json"),
            4,
        ),
        (
            vector!("status_list", "c4_8bit.json"),
            vector!("status_list", "c4_8bit_statuses.json"),
            8,
        ),
    ];
    for (list, statuses, bits) in vectors {
        let list: StatusList = serde_json::from_str(list).unwrap();
        assert_eq!(list.bits(), bits);
        assert_eq!(list.len(), 1 << 20, "initialized with 2^20 entries");
        let statuses: Vec<(u64, u8)> = serde_json::from_str(statuses).unwrap();
        let mut rebuilt = StatusList::new(bits, 1 << 20).unwrap();
        for (index, status) in &statuses {
            assert_eq!(
                list.get(*index),
                Some(StatusType(*status)),
                "{bits} bits, status[{index}]"
            );
            rebuilt.set(*index, StatusType(*status)).unwrap();
        }
        // Everything else is VALID.
        let set: std::collections::HashSet<u64> = statuses.iter().map(|(i, _)| *i).collect();
        for index in [1u64, 2, 1000, 1992, 1994, 524287, (1 << 20) - 1] {
            if !set.contains(&index) {
                assert_eq!(list.get(index), Some(StatusType::VALID));
            }
        }
        assert_eq!(rebuilt.as_bytes(), list.as_bytes());
    }
}

#[test]
fn status_list_token_of_section_5_and_8() {
    let jwt: Jwt = vector!("status_list", "token.txt").parse().unwrap();
    let (header, token) = StatusListToken::decode(&jwt).unwrap();
    assert_eq!(
        serde_json::to_value(&header).unwrap(),
        json(vector!("status_list", "token_header.json"))
    );
    let payload = json(vector!("status_list", "token_payload.json"));
    assert_eq!(token.sub, payload["sub"]);
    assert_eq!(token.iat, payload["iat"]);
    assert_eq!(json!(token.exp), payload["exp"]);
    assert_eq!(json!(token.ttl), payload["ttl"]);
    assert_eq!(token.additional["iss"], "https://example.com");
    assert_eq!(
        serde_json::to_value(&token.status_list).unwrap(),
        payload["status_list"]
    );

    let now = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
    let uri = "https://example.com/statuslists/1";
    assert_eq!(
        token.status_of(&StatusListRef::new(uri, 0), now).unwrap(),
        StatusType::INVALID
    );
    assert_eq!(
        token.status_of(&StatusListRef::new(uri, 1), now).unwrap(),
        StatusType::VALID
    );
    assert_eq!(
        token.status_of(&StatusListRef::new(uri, 15), now).unwrap(),
        StatusType::INVALID
    );
    assert!(matches!(
        token.status_of(&StatusListRef::new(uri, 16), now),
        Err(StatusListError::IndexOutOfRange { idx: 16, len: 16 })
    ));
    assert!(matches!(
        token.status_of(
            &StatusListRef::new("https://example.com/statuslists/2", 0),
            now
        ),
        Err(StatusListError::SubjectMismatch { .. })
    ));
    let later = Utc.timestamp_opt(2291720170, 0).unwrap();
    assert!(matches!(
        token.status_of(&StatusListRef::new(uri, 0), later),
        Err(StatusListError::Expired { .. })
    ));
    assert_eq!(StatusType::INVALID.to_string(), "INVALID (0x01)");
    assert_eq!(StatusType(0x0c).to_string(), "0x0c");
    assert!(StatusType::VALID.is_valid());

    // `typ` is required.
    let plain: Jwt = unsigned_jwt(&json!({"alg": "ES256"}), &payload)
        .parse()
        .unwrap();
    assert!(matches!(
        StatusListToken::decode(&plain),
        Err(StatusListError::UnexpectedTyp(None))
    ));
    let typed: Jwt = unsigned_jwt(&json!({"alg": "ES256", "typ": "statuslist+jwt"}), &payload)
        .parse()
        .unwrap();
    let mut without_iss = token.clone();
    without_iss.additional.clear();
    assert_eq!(StatusListToken::decode(&typed).unwrap().1, without_iss);

    // Built and serialized, the claims come out as the example's.
    let built = StatusListToken::new(
        uri,
        Utc.timestamp_opt(1686920170, 0).unwrap(),
        token.status_list.clone(),
    )
    .with_expires_at(Utc.timestamp_opt(2291720170, 0).unwrap())
    .with_ttl(43200)
    .with_claim("iss", "https://example.com");
    assert_eq!(built, token);
}

// ---------------------------------------------------------------------------------------------
// Type metadata
// ---------------------------------------------------------------------------------------------

#[test]
fn type_metadata_documents() {
    // §5.1, Figure 17.
    let v42 =
        TypeMetadata::parse(vector!("type_metadata", "education_credential_v42.json").as_bytes())
            .unwrap();
    assert_eq!(
        v42.vct,
        "https://betelgeuse.example.com/education_credential/v42"
    );
    assert_eq!(
        v42.name.as_deref(),
        Some("Betelgeuse Education Credential - Version 42")
    );
    assert_eq!(
        v42.extends.as_deref(),
        Some("https://galaxy.example.com/galactic-education-credential/v2")
    );
    assert_eq!(
        v42.extends_integrity.as_deref(),
        Some("sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=")
    );
    assert!(v42.display.is_empty() && v42.claims.is_empty());

    // Appendix A.2, Figure 30.
    let text = vector!("type_metadata", "education_credential.json");
    let metadata = TypeMetadata::parse(text.as_bytes()).unwrap();
    assert_eq!(metadata.display.len(), 2);
    assert_eq!(metadata.display[0].locale, "en-US");
    assert_eq!(metadata.display[0].name, "Betelgeuse Education Credential");
    assert_eq!(metadata.display[1].locale, "de-DE");
    assert_eq!(
        metadata.display[0].rendering.as_ref().unwrap()["simple"]["logo"]["uri"],
        "https://betelgeuse.example.com/public/education-logo.png"
    );
    let paths: Vec<String> = metadata.claims.iter().map(|c| c.path.to_string()).collect();
    assert_eq!(
        paths,
        [
            r#"["name"]"#,
            r#"["address"]"#,
            r#"["address", "street_address"]"#,
            r#"["degrees"]"#,
            r#"["degrees", null]"#,
            r#"["degrees", null, "field_of_study"]"#,
            r#"["degrees", null, "date_awarded"]"#,
        ]
    );
    let street = metadata
        .claim(&claim_path!["address", "street_address"])
        .unwrap();
    assert_eq!(street.sd_policy(), SdPolicy::Always);
    assert_eq!(street.svg_id.as_deref(), Some("address_street_address"));
    assert_eq!(street.display[0].locale, "de-DE");
    assert_eq!(street.display[1].label, "Street Address");
    assert!(!street.is_mandatory());
    assert_eq!(
        metadata.claim(&claim_path!["degrees"]).unwrap().sd_policy(),
        SdPolicy::Never
    );
    assert!(metadata.claim(&claim_path!["nope"]).is_none());
    // Round trip keeps every property.
    assert_eq!(serde_json::to_value(&metadata).unwrap(), json(text));

    // Structural rules.
    assert!(matches!(
        TypeMetadata::new("a")
            .with_claim(ClaimMetadata::new(ClaimPath::root()))
            .check(),
        Err(TypeMetadataError::InvalidClaimMetadata { .. })
    ));
    assert!(matches!(
        TypeMetadata::new("a")
            .with_claim(ClaimMetadata::new(["x"]).with_svg_id("1x"))
            .check(),
        Err(TypeMetadataError::InvalidClaimMetadata { .. })
    ));
    assert!(matches!(
        TypeMetadata::new("a")
            .with_claim(ClaimMetadata::new(claim_path!["x", ()]).with_svg_id("x"))
            .check(),
        Err(TypeMetadataError::InvalidClaimMetadata { .. })
    ));
    assert!(matches!(
        TypeMetadata::new("a")
            .with_claim(ClaimMetadata::new(["x"]).with_svg_id("same"))
            .with_claim(ClaimMetadata::new(["y"]).with_svg_id("same"))
            .check(),
        Err(TypeMetadataError::DuplicateSvgId(id)) if id == "same"
    ));
    assert!(matches!(
        TypeMetadata::parse(b"[]"),
        Err(TypeMetadataError::Json(_))
    ));
}

#[test]
fn claim_path_examples_of_section_5_6_1() {
    let credential = json!({
      "vct": "https://betelgeuse.example.com/education_credential/v42",
      "name": "Arthur Dent",
      "address": {
        "street_address": "42 Market Street",
        "city": "Milliways",
        "postal_code": "12345"
      },
      "degrees": [
        { "type": "Bachelor of Science", "university": "University of Betelgeuse" },
        { "type": "Master of Science", "university": "University of Betelgeuse" }
      ],
      "nationalities": ["British", "Betelgeusian"]
    });
    assert_eq!(
        claim_path!["name"].select(&credential).unwrap(),
        vec![&json!("Arthur Dent")]
    );
    assert_eq!(
        claim_path!["address"].select(&credential).unwrap(),
        vec![&credential["address"]]
    );
    assert_eq!(
        claim_path!["address", "street_address"]
            .select(&credential)
            .unwrap(),
        vec![&json!("42 Market Street")]
    );
    assert_eq!(
        claim_path!["degrees", (), "type"]
            .select(&credential)
            .unwrap(),
        vec![&json!("Bachelor of Science"), &json!("Master of Science")]
    );
    assert_eq!(
        claim_path!["nationalities", 1].select(&credential).unwrap(),
        vec![&json!("Betelgeusian")]
    );
    // Missing names and indexes select nothing; wrong kinds are errors.
    assert!(
        claim_path!["missing"]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(
        claim_path!["nationalities", 2]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(
        claim_path!["degrees", (), "missing"]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(claim_path!["name", "first"].select(&credential).is_err());
    assert!(claim_path!["address", ()].select(&credential).is_err());
    assert!(claim_path!["address", 0].select(&credential).is_err());
    assert!(claim_path!["degrees", "type"].select(&credential).is_err());
    assert_eq!(
        claim_path!["degrees", (), "type"]
            .resolve(&credential)
            .unwrap(),
        vec![
            claim_path!["degrees", 0, "type"],
            claim_path!["degrees", 1, "type"]
        ]
    );
}

#[test]
fn extending_type_metadata() {
    // §5.6.5.2, Figures 20 to 22, is in the module documentation; the rules around it here.
    let base = TypeMetadata::new("https://example.com/base")
        .with_display(identity_kit::sd_jwt_vc::DisplayMetadata::new("en", "Base"))
        .with_claim(
            ClaimMetadata::new(["name"])
                .with_sd(SdPolicy::Always)
                .with_mandatory(true),
        )
        .with_claim(ClaimMetadata::new(["age"]))
        .with_claim(ClaimMetadata::new(["email"]).with_sd(SdPolicy::Never));
    let child = TypeMetadata::new("https://example.com/child")
        .with_extends("https://example.com/base", None)
        .with_claim(
            ClaimMetadata::new(["age"])
                .with_sd(SdPolicy::Never)
                .with_mandatory(true),
        )
        .with_claim(ClaimMetadata::new(["name"]).with_svg_id("name"))
        .with_claim(ClaimMetadata::new(["extra"]));
    let effective = child.clone().extend(&base).unwrap();
    assert_eq!(
        effective.display, base.display,
        "display inherited when the child has none"
    );
    assert_eq!(effective.extends, None);
    let paths: Vec<String> = effective
        .claims
        .iter()
        .map(|c| c.path.to_string())
        .collect();
    assert_eq!(
        paths,
        [r#"["name"]"#, r#"["age"]"#, r#"["email"]"#, r#"["extra"]"#]
    );
    let name = effective.claim(&claim_path!["name"]).unwrap();
    assert_eq!(
        (
            name.sd_policy(),
            name.is_mandatory(),
            name.svg_id.as_deref()
        ),
        (SdPolicy::Always, true, Some("name"))
    );
    let age = effective.claim(&claim_path!["age"]).unwrap();
    assert_eq!(
        (age.sd_policy(), age.is_mandatory()),
        (SdPolicy::Never, true)
    );

    // Wrong parent.
    assert!(matches!(
        child
            .clone()
            .extend(&TypeMetadata::new("https://example.com/other")),
        Err(TypeMetadataError::WrongParent { .. })
    ));
    // `always`/`never` and `mandatory: true` cannot be undone.
    let relaxing = TypeMetadata::new("https://example.com/child")
        .with_extends("https://example.com/base", None)
        .with_claim(ClaimMetadata::new(["email"]).with_sd(SdPolicy::Allowed));
    assert!(matches!(
        relaxing.extend(&base),
        Err(TypeMetadataError::IllegalOverride { property: "sd", .. })
    ));
    let optional = TypeMetadata::new("https://example.com/child")
        .with_extends("https://example.com/base", None)
        .with_claim(ClaimMetadata::new(["name"]).with_mandatory(false));
    assert!(matches!(
        optional.extend(&base),
        Err(TypeMetadataError::IllegalOverride {
            property: "mandatory",
            ..
        })
    ));
    // The child's own display replaces the parent's.
    let own = TypeMetadata::new("https://example.com/child")
        .with_extends("https://example.com/base", None)
        .with_display(identity_kit::sd_jwt_vc::DisplayMetadata::new("de", "Kind"));
    assert_eq!(own.extend(&base).unwrap().display[0].name, "Kind");
}

#[test]
fn claim_metadata_validation_of_a_presentation() {
    // The §2.3.2 presentation: `address` and `is_over_65` disclosed, the rest withheld.
    let presentation = SdJwtVc::parse(vector!(
        "sd_jwt_vc/identity_credential",
        "presentation_no_kb.txt"
    ))
    .unwrap();
    let processed = presentation.processed();
    let fine = TypeMetadata::new(&presentation.claims().vct)
        .with_claim(ClaimMetadata::new(["address"]).with_sd(SdPolicy::Always))
        .with_claim(ClaimMetadata::new(["address", "locality"]).with_sd(SdPolicy::Never))
        .with_claim(
            ClaimMetadata::new(["iss"])
                .with_sd(SdPolicy::Never)
                .with_mandatory(true),
        )
        .with_claim(
            ClaimMetadata::new(["given_name"])
                .with_sd(SdPolicy::Always)
                .with_mandatory(true),
        );
    assert!(fine.check_claims(processed, false).is_ok());
    // With every disclosure at hand, `given_name` would have to be there.
    assert!(matches!(
        fine.check_claims(processed, true),
        Err(TypeMetadataError::MissingMandatoryClaim(path)) if path == claim_path!["given_name"]
    ));
    let issuance =
        SdJwtVc::parse(vector!("sd_jwt_vc/identity_credential", "issuance.txt")).unwrap();
    assert!(fine.check_claims(issuance.processed(), true).is_ok());

    let never =
        TypeMetadata::new("x").with_claim(ClaimMetadata::new(["address"]).with_sd(SdPolicy::Never));
    assert!(matches!(
        never.check_claims(processed, false),
        Err(TypeMetadataError::SdViolation {
            policy: SdPolicy::Never,
            disclosable: true,
            ..
        })
    ));
    let always =
        TypeMetadata::new("x").with_claim(ClaimMetadata::new(["iss"]).with_sd(SdPolicy::Always));
    assert!(matches!(
        always.check_claims(processed, false),
        Err(TypeMetadataError::SdViolation {
            policy: SdPolicy::Always,
            disclosable: false,
            ..
        })
    ));
    let wrong_kind = TypeMetadata::new("x").with_claim(ClaimMetadata::new(["iss", "x"]));
    assert!(matches!(
        wrong_kind.check_claims(processed, false),
        Err(TypeMetadataError::Path(_))
    ));

    // Undisclosed array elements count as present and disclosable, with nothing beneath.
    let simple =
        SdJwt::parse(include_str!("vectors/sd_jwt/simple/presentation.txt").trim()).unwrap();
    let processed = simple.process().unwrap();
    let elements = TypeMetadata::new("x")
        .with_claim(
            ClaimMetadata::new(claim_path!["nationalities", ()])
                .with_sd(SdPolicy::Always)
                .with_mandatory(true),
        )
        .with_claim(ClaimMetadata::new(claim_path!["nationalities", 1, "x"]).with_mandatory(true));
    assert!(
        elements.check_claims(&processed, true).is_ok(),
        "unknown contents are not missing"
    );
    let never = TypeMetadata::new("x")
        .with_claim(ClaimMetadata::new(claim_path!["nationalities", 1]).with_sd(SdPolicy::Never));
    assert!(matches!(
        never.check_claims(&processed, false),
        Err(TypeMetadataError::SdViolation { .. })
    ));
}

#[test]
fn integrity_metadata() {
    // §5.1, Figure 17 and §6.
    let integrity = Integrity::parse("sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=");
    assert_eq!(integrity.algorithms(), [IntegrityAlgorithm::Sha256]);
    assert!(matches!(
        integrity.verify(b"{}"),
        Err(IntegrityError::Mismatch {
            algorithm: IntegrityAlgorithm::Sha256
        })
    ));

    let document = vector!("type_metadata", "education_credential_v42.json").as_bytes();
    for algorithm in [
        IntegrityAlgorithm::Sha256,
        IntegrityAlgorithm::Sha384,
        IntegrityAlgorithm::Sha512,
    ] {
        let computed = Integrity::compute(algorithm, document);
        assert!(
            computed
                .as_str()
                .starts_with(&format!("{}-", algorithm.prefix()))
        );
        assert!(Integrity::parse(computed.as_str()).verify(document).is_ok());
        assert!(
            Integrity::parse(computed.as_str())
                .verify(b"other")
                .is_err()
        );
    }
    // Several expressions: the strongest supported algorithm decides; options are ignored.
    let weak = Integrity::compute(IntegrityAlgorithm::Sha256, b"other");
    let strong = Integrity::compute(IntegrityAlgorithm::Sha512, document);
    let both = Integrity::parse(&format!("{weak} {strong}?opt=1"));
    assert_eq!(
        both.algorithms(),
        [IntegrityAlgorithm::Sha256, IntegrityAlgorithm::Sha512]
    );
    assert!(both.verify(document).is_ok());
    assert!(matches!(
        Integrity::parse("md5-AAAA").verify(document),
        Err(IntegrityError::NoSupportedAlgorithm(_))
    ));
    assert_eq!(
        Integrity::parse("sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=").to_string(),
        "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU="
    );
}
