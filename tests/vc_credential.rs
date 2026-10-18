//! Specification vectors for `Credential`: the examples of the Verifiable Credentials Data
//! Model 1.1 and its JWT profile (§6.3.1).
#![cfg(feature = "vc")]

use chrono::{TimeZone as _, Utc};
use identity_kit::did::{OneOrMany, Uri};
use identity_kit::vc::validation::{ValidationError, decode_credential};
use identity_kit::vc::{Credential, CredentialError, Jwt, JwtClaims, Party, Subject, TypedObject};
use serde_json::{Value, json};

/// VCDM 1.1 Example 1, without the comments and with the `proof` as the example shows it.
const EXAMPLE_1: &str = r#"{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "issuer": "https://example.edu/issuers/565049",
  "issuanceDate": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": [{
        "value": "Example University",
        "lang": "en"
      }, {
        "value": "Exemple d'Université",
        "lang": "fr"
      }]
    }
  },
  "proof": {
    "type": "RsaSignature2018",
    "created": "2017-06-18T21:19:10Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "https://example.edu/issuers/565049#key-1",
    "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV-TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq-pQy7UJiN5mgRxD-WUcX16dUEMGlv50aqzpqh4Qktb3rk-BuQy72IFLOqV0G_zS245-kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
  }
}"#;

/// VCDM 1.1 Example 31: the JWT claims of a credential, before signing.
const EXAMPLE_31_CLAIMS: &str = r#"{
  "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
  "jti": "http://example.edu/credentials/3732",
  "iss": "https://example.com/keys/foo.jwk",
  "nbf": 1541493724,
  "iat": 1541493724,
  "exp": 1573029723,
  "nonce": "660!6345FSer",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    "type": ["VerifiableCredential", "UniversityDegreeCredential"],
    "credentialSubject": {
      "degree": {
        "type": "BachelorDegree",
        "name": "Bachelor of Science and Arts"
      }
    }
  }
}"#;

/// VCDM 1.1 Example 31: the same claims as a JWT (its RS256 signature is the example's; the
/// key is not published, so only the decoding is a vector).
const EXAMPLE_31: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmFiZmUxM2Y3MTIxMjA0MzFjMjc2ZTEyZWNhYiNr\
    ZXlzLTEifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJqdGkiOiJodHRwOi8vZXhhb\
    XBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20va2V5cy9mb28uandrIiwibmJmIjoxN\
    TQxNDkzNzI0LCJpYXQiOjE1NDE0OTM3MjQsImV4cCI6MTU3MzAyOTcyMywibm9uY2UiOiI2NjAhNjM0NUZTZXIiLCJ2YyI6eyJAY\
    29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L\
    2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJVbml2ZXJzaXR5RGVncmVlQ\
    3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6I\
    jxzcGFuIGxhbmc9J2ZyLUNBJz5CYWNjYWxhdXLDqWF0IGVuIG11c2lxdWVzIG51bcOpcmlxdWVzPC9zcGFuPiJ9fX19.KLJo5GAy\
    BND3LDTn9H7FQokEsUEi8jKwXhGvoN3JtRa51xrNDgXDb0cq1UTYB-rK4Ft9YVmR1NI_ZOF8oGc_7wAp8PHbF2HaWodQIoOBxxT-\
    4WNqAxft7ET6lkH-4S6Ux3rSGAmczMohEEf8eCeN-jC8WekdPl6zKZQj0YPB1rx6X0-xlFBs7cl6Wt8rfBP_tZ9YgVWrQmUWypSi\
    oc0MUyiphmyEbLZagTyPlUyflGlEdqrZAv6eSe6RtxJy6M1-lD7a5HTzanYTWBPAUHDZGyGKXdJw-W_x0IWChBzI8t3kpG253fg6\
    V3tPgHeKXE94fz_QpYfg--7kLsyBAfQGbg";

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

fn value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn example_1_round_trips_as_data() {
    let credential: Credential = serde_json::from_str(EXAMPLE_1).unwrap();
    assert_eq!(
        credential.id,
        Some(uri("http://example.edu/credentials/1872"))
    );
    assert!(credential.has_type("AlumniCredential"));
    assert_eq!(
        credential.issuer,
        Party::Uri(uri("https://example.edu/issuers/565049"))
    );
    assert_eq!(
        credential.issuance_date,
        Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap()
    );
    let subject = credential.subject().unwrap();
    assert_eq!(
        subject.id,
        Some(uri("did:example:ebfeb1f712ebc6f1c276e12ec21"))
    );
    assert_eq!(
        subject.properties["alumniOf"]["name"][1]["value"],
        "Exemple d'Université"
    );
    // `proof` is data this crate carries, not processes.
    assert_eq!(credential.properties["proof"]["type"], "RsaSignature2018");

    // Re-serialization reproduces the example, property for property and in order.
    let expected: Value = serde_json::from_str(EXAMPLE_1).unwrap();
    assert_eq!(value(&credential), expected);
    assert_eq!(
        serde_json::to_string(&credential).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );
}

#[test]
fn example_1_is_built_from_parts() {
    let credential = Credential::new(
        uri("https://example.edu/issuers/565049"),
        Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap(),
        Subject::new(uri("did:example:ebfeb1f712ebc6f1c276e12ec21")).with_property(
            "alumniOf",
            json!({
                "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
                "name": [
                    { "value": "Example University", "lang": "en" },
                    { "value": "Exemple d'Université", "lang": "fr" }
                ]
            }),
        ),
    )
    .with_context("https://www.w3.org/2018/credentials/examples/v1")
    .with_id(uri("http://example.edu/credentials/1872"))
    .with_type("AlumniCredential");

    let mut expected: Value = serde_json::from_str(EXAMPLE_1).unwrap();
    expected.as_object_mut().unwrap().remove("proof");
    assert_eq!(value(&credential), expected);
    assert_eq!(
        credential.types,
        OneOrMany::Many(vec![
            "VerifiableCredential".to_owned(),
            "AlumniCredential".to_owned()
        ])
    );
}

#[test]
fn expiration_status_evidence_and_terms_of_use_examples() {
    // VCDM 1.1 §4.7 (expiration) and §4.9 (credentialStatus) examples.
    let credential: Credential = serde_json::from_value(json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
        "issuer": "https://example.edu/issuers/14",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "expirationDate": "2020-01-01T19:23:24Z",
        "credentialSubject": {
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "degree": { "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }
        },
        "credentialStatus": {
            "id": "https://example.edu/status/24",
            "type": "CredentialStatusList2017"
        },
        "evidence": [{
            "id": "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
            "type": ["DocumentVerification"],
            "verifier": "https://example.edu/issuers/14",
            "evidenceDocument": "DriversLicense",
            "subjectPresence": "Physical",
            "documentPresence": "Physical",
            "licenseNumber": "123AB4567"
        }],
        "termsOfUse": [{
            "type": "IssuerPolicy",
            "id": "http://example.com/policies/credential/4",
            "profile": "http://example.com/profiles/credential",
            "prohibition": [{
                "assigner": "https://example.edu/issuers/14",
                "assignee": "AllVerifiers",
                "target": "http://example.edu/credentials/3732",
                "action": ["Archival"]
            }]
        }]
    }))
    .unwrap();
    assert_eq!(
        credential.expiration_date,
        Some(Utc.with_ymd_and_hms(2020, 1, 1, 19, 23, 24).unwrap())
    );
    let status = credential.credential_status.as_ref().unwrap();
    assert_eq!(status.id, Some(uri("https://example.edu/status/24")));
    assert_eq!(status.object_type(), "CredentialStatusList2017");
    let evidence = credential.evidence.as_ref().unwrap();
    assert_eq!(evidence.len(), 1);
    assert!(evidence.first().unwrap().has_type("DocumentVerification"));
    assert_eq!(
        evidence.first().unwrap().properties["licenseNumber"],
        "123AB4567"
    );
    let terms = credential.terms_of_use.as_ref().unwrap().first().unwrap();
    assert_eq!(terms.object_type(), "IssuerPolicy");
    assert_eq!(
        terms.properties["prohibition"][0]["assignee"],
        "AllVerifiers"
    );
    // Everything comes back out as it went in.
    assert_eq!(
        value(&credential)["termsOfUse"][0]["prohibition"][0]["action"],
        json!(["Archival"])
    );
}

#[test]
fn example_31_claims_decode_to_the_credential_and_back() {
    let claims: JwtClaims = serde_json::from_str(EXAMPLE_31_CLAIMS).unwrap();
    let credential = Credential::from_jwt_claims(&claims).unwrap();

    // §6.3.1 "JWT Decoding": jti → id, iss → issuer, nbf → issuanceDate, exp → expirationDate,
    // sub → credentialSubject.id.
    assert_eq!(
        credential.id,
        Some(uri("http://example.edu/credentials/3732"))
    );
    assert_eq!(
        credential.issuer,
        Party::Uri(uri("https://example.com/keys/foo.jwk"))
    );
    assert_eq!(
        credential.issuance_date,
        Utc.with_ymd_and_hms(2018, 11, 6, 8, 42, 4).unwrap()
    );
    assert_eq!(
        credential.expiration_date,
        Some(Utc.with_ymd_and_hms(2019, 11, 6, 8, 42, 3).unwrap())
    );
    let subject = credential.subject().unwrap();
    assert_eq!(
        subject.id,
        Some(uri("did:example:ebfeb1f712ebc6f1c276e12ec21"))
    );
    assert_eq!(subject.properties["degree"]["type"], "BachelorDegree");
    assert_eq!(
        value(&credential),
        json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.edu/credentials/3732",
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "issuer": "https://example.com/keys/foo.jwk",
            "issuanceDate": "2018-11-06T08:42:04Z",
            "expirationDate": "2019-11-06T08:42:03Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": { "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }
            }
        })
    );

    // §6.3.1 "JWT Encoding" reproduces the example's claims; `iat` and `nonce` are the
    // issuer's to add.
    let encoded = credential.to_jwt_claims().unwrap();
    let mut expected = claims.clone();
    expected.iat = None;
    expected.additional.shift_remove("nonce");
    assert_eq!(encoded, expected);
    assert_eq!(
        encoded
            .with_iat(credential.issuance_date)
            .with_claim("nonce", "660!6345FSer"),
        claims
    );
}

#[test]
fn example_31_token_decodes() {
    let jwt: Jwt = EXAMPLE_31.parse().unwrap();
    let decoded = decode_credential(&jwt).unwrap();
    assert_eq!(decoded.header.typ.as_deref(), Some("JWT"));
    assert_eq!(
        decoded.header.kid.as_deref(),
        Some("did:example:abfe13f712120431c276e12ecab#keys-1")
    );
    assert_eq!(decoded.claims.additional["nonce"], "660!6345FSer");
    assert_eq!(decoded.claims.iat, Some(1541493724));
    assert_eq!(
        decoded.credential.id,
        Some(uri("http://example.edu/credentials/3732"))
    );
    assert_eq!(
        decoded.credential.subject().unwrap().properties["degree"]["name"],
        "<span lang='fr-CA'>Baccalauréat en musiques numériques</span>"
    );
}

#[test]
fn object_issuer_stays_in_the_vc_claim() {
    // VCDM 1.1 §4.5: the issuer may be an object with an `id`.
    let credential: Credential = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": { "id": "did:example:76e12ec712ebc6f1c221ebfeb1f", "name": "Example University" },
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": { "id": "did:example:ebfeb1f712ebc6f1c276e12ec21" }
    }))
    .unwrap();
    let claims = credential.to_jwt_claims().unwrap();
    assert_eq!(
        claims.iss.as_deref(),
        Some("did:example:76e12ec712ebc6f1c221ebfeb1f")
    );
    assert_eq!(
        claims.additional["vc"]["issuer"],
        json!({ "id": "did:example:76e12ec712ebc6f1c221ebfeb1f", "name": "Example University" })
    );
    assert_eq!(claims.additional["vc"]["credentialSubject"], json!({}));
    assert_eq!(Credential::from_jwt_claims(&claims).unwrap(), credential);
}

#[test]
fn claims_and_properties_must_agree() {
    let claims: JwtClaims = serde_json::from_str(EXAMPLE_31_CLAIMS).unwrap();
    let with = |name: &str, value: Value| {
        let mut claims = claims.clone();
        claims.additional["vc"][name] = value;
        claims
    };
    let mismatch = |claim, property| CredentialError::ClaimMismatch { claim, property };

    // A duplicated property must agree with its claim; an object issuer agrees through its
    // `id`, a timestamp through the instant it names.
    assert_eq!(
        Credential::from_jwt_claims(&with("id", json!("http://example.edu/credentials/1"))),
        Err(mismatch("jti", "id"))
    );
    assert_eq!(
        Credential::from_jwt_claims(&with("issuer", json!("did:example:other"))),
        Err(mismatch("iss", "issuer"))
    );
    assert!(
        Credential::from_jwt_claims(&with(
            "issuer",
            json!({ "id": "https://example.com/keys/foo.jwk", "name": "Example" })
        ))
        .is_ok()
    );
    assert_eq!(
        Credential::from_jwt_claims(&with("issuanceDate", json!("2018-11-06T08:42:05Z"))),
        Err(mismatch("nbf", "issuanceDate"))
    );
    assert!(
        Credential::from_jwt_claims(&with("issuanceDate", json!("2018-11-06T09:42:04+01:00")))
            .is_ok()
    );
    assert_eq!(
        Credential::from_jwt_claims(&with("expirationDate", json!("2019-11-06T08:42:04Z"))),
        Err(mismatch("exp", "expirationDate"))
    );
    assert_eq!(
        Credential::from_jwt_claims(&with(
            "credentialSubject",
            json!({ "id": "did:example:other" })
        )),
        Err(mismatch("sub", "credentialSubject.id"))
    );
    assert_eq!(
        Credential::from_jwt_claims(&with(
            "credentialSubject",
            json!([{ "id": "did:example:a" }, { "id": "did:example:b" }])
        )),
        Err(CredentialError::InvalidClaim {
            claim: "sub",
            reason: "the credential has 2 subjects".to_owned()
        })
    );

    // Without `vc` there is no credential; a `vc` that is not an object is invalid.
    let mut without = claims.clone();
    without.additional.shift_remove("vc");
    assert_eq!(
        Credential::from_jwt_claims(&without),
        Err(CredentialError::MissingClaim("vc"))
    );
    assert_eq!(
        Credential::from_jwt_claims(&without.with_claim("vc", "not an object")),
        Err(CredentialError::InvalidClaim {
            claim: "vc",
            reason: "not a JSON object".to_owned()
        })
    );
    // A `vc` with a `type` the data model forbids is reported through the credential check.
    assert_eq!(
        Credential::from_jwt_claims(&with("type", json!(["UniversityDegreeCredential"]))),
        Err(CredentialError::InvalidClaim {
            claim: "vc",
            reason: "`type` must include `VerifiableCredential`".to_owned()
        })
    );
}

#[test]
fn structural_requirements() {
    let base = json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:issuer",
        "issuanceDate": "2010-01-01T19:23:24Z",
        "credentialSubject": { "id": "did:example:subject" }
    });
    let with = |name: &str, value: Value| {
        let mut credential = base.clone();
        credential[name] = value;
        serde_json::from_value::<Credential>(credential)
    };
    assert!(with("id", json!("urn:uuid:1")).is_ok());

    // VCDM 1.1 §4.1: the first @context is the base context; §4.3: type includes
    // VerifiableCredential; §4.4: a subject; §4.6: a timestamp with a time zone.
    let error = |result: Result<Credential, serde_json::Error>| result.unwrap_err().to_string();
    assert_eq!(
        error(with(
            "@context",
            json!(["https://www.w3.org/2018/credentials/examples/v1"])
        )),
        "the first `@context` must be `https://www.w3.org/2018/credentials/v1`"
    );
    assert_eq!(
        error(with(
            "@context",
            json!("https://www.w3.org/ns/credentials/v2")
        )),
        "the first `@context` must be `https://www.w3.org/2018/credentials/v1`"
    );
    assert_eq!(
        error(with("type", json!("AlumniCredential"))),
        "`type` must include `VerifiableCredential`"
    );
    assert_eq!(
        error(with("credentialSubject", json!([]))),
        "`credentialSubject` is empty"
    );
    assert_eq!(
        error(with("expirationDate", json!("2009-01-01T00:00:00Z"))),
        "`expirationDate` precedes `issuanceDate`"
    );
    assert!(error(with("issuanceDate", json!("2010-01-01T19:23:24"))).contains("premature end"));
    assert!(error(with("issuer", json!({ "name": "no id" }))).contains("untagged"));

    // `type` may be a single string, and is kept as one.
    let single = with("type", json!("VerifiableCredential")).unwrap();
    assert_eq!(value(&single)["type"], "VerifiableCredential");
    assert_eq!(
        serde_json::to_string(&single.with_type("AlumniCredential")).unwrap(),
        serde_json::to_string(
            &with("type", json!(["VerifiableCredential", "AlumniCredential"])).unwrap()
        )
        .unwrap()
    );
}

#[test]
fn multiple_subjects_have_no_jwt_form() {
    // VCDM 1.1 §4.4 example with two subjects; §6.3.1 says a JWT cannot encode it.
    let credential: Credential = serde_json::from_value(json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        "id": "http://example.edu/credentials/3732",
        "type": ["VerifiableCredential", "RelationshipCredential"],
        "issuer": "https://example.com/issuer/123",
        "issuanceDate": "2010-01-01T00:00:00Z",
        "credentialSubject": [{
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "name": "Jayden Doe",
            "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
        }, {
            "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
            "name": "Morgan Doe",
            "spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21"
        }]
    }))
    .unwrap();
    assert_eq!(credential.credential_subject.len(), 2);
    assert_eq!(credential.subject(), None);
    assert_eq!(
        credential.to_jwt_claims(),
        Err(CredentialError::MultipleSubjects(2))
    );

    // A bearer credential has no `sub`.
    let bearer = Credential::new(
        uri("did:example:issuer"),
        Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
        Subject::default().with_property("favoriteCheese", "Gouda"),
    );
    let claims = bearer.to_jwt_claims().unwrap();
    assert_eq!(claims.sub, None);
    assert_eq!(claims.jti, None);
    assert_eq!(claims.exp, None);
    assert_eq!(claims.nbf, Some(1262304000));
    assert_eq!(
        claims.additional["vc"],
        json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "credentialSubject": { "favoriteCheese": "Gouda" }
        })
    );
    assert_eq!(Credential::from_jwt_claims(&claims).unwrap(), bearer);
}

#[test]
fn typed_objects_and_builders() {
    let status = TypedObject::new("StatusList2021Entry")
        .with_id(uri("https://example.edu/status/24#94567"))
        .with_property("statusListIndex", "94567");
    let credential = Credential::new(
        uri("did:example:issuer"),
        Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
        Subject::new(uri("did:example:subject")),
    )
    .with_expiration_date(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap())
    .with_status(status.clone())
    .with_schema(TypedObject::new("JsonSchema").with_id(uri("https://example.org/degree.json")))
    .with_schema(TypedObject::new("JsonSchema").with_id(uri("https://example.org/alumni.json")))
    .with_terms_of_use(TypedObject::new("IssuerPolicy"))
    .with_evidence(TypedObject::new("DocumentVerification"))
    .with_subject(Subject::new(uri("did:example:other")))
    .with_property("nonTransferable", true);
    assert_eq!(credential.credential_status, Some(status));
    assert_eq!(credential.credential_schema.as_ref().unwrap().len(), 2);
    assert_eq!(credential.credential_subject.len(), 2);
    assert_eq!(credential.properties["nonTransferable"], true);
    let json = value(&credential);
    assert_eq!(json["credentialSchema"].as_array().unwrap().len(), 2);
    assert_eq!(json["termsOfUse"], json!({ "type": "IssuerPolicy" }));
    assert_eq!(
        serde_json::from_value::<Credential>(json).unwrap(),
        credential
    );

    // Building a credential whose expiration precedes its issuance is caught at encoding.
    let backwards = Credential::new(
        uri("did:example:issuer"),
        Utc.with_ymd_and_hms(2010, 1, 1, 0, 0, 0).unwrap(),
        Subject::new(uri("did:example:subject")),
    )
    .with_expiration_date(Utc.with_ymd_and_hms(2009, 1, 1, 0, 0, 0).unwrap());
    assert_eq!(
        backwards.to_jwt_claims(),
        Err(CredentialError::InvalidValidity {
            from: "issuanceDate",
            until: "expirationDate"
        })
    );
}

#[test]
fn jwt_type_and_claims_helpers() {
    assert!(matches!(
        Jwt::new("not.a.jwt"),
        Err(identity_kit::jose::JwsError::InvalidBase64Url { part: "header" })
    ));
    assert!(matches!(
        Jwt::new("eyJhbGciOiJub25lIn0.e30."),
        Err(identity_kit::jose::JwsError::UnsupportedAlgorithm(alg)) if alg == "none"
    ));
    let jwt: Jwt = EXAMPLE_31.parse().unwrap();
    assert_eq!(jwt.as_str(), EXAMPLE_31);
    assert_eq!(
        serde_json::to_value(&jwt).unwrap(),
        Value::String(EXAMPLE_31.to_owned())
    );
    assert_eq!(
        serde_json::from_value::<Jwt>(json!(EXAMPLE_31)).unwrap(),
        jwt
    );
    assert!(serde_json::from_value::<Jwt>(json!("x.y")).is_err());

    let time = Utc.with_ymd_and_hms(2019, 11, 6, 8, 42, 3).unwrap();
    assert_eq!(JwtClaims::numeric_date(time), 1573029723);
    assert_eq!(JwtClaims::timestamp(1573029723), Some(time));
    assert_eq!(JwtClaims::timestamp(i64::MAX), None);
    let claims = JwtClaims::new()
        .with_exp(time)
        .with_nbf(time)
        .with_iat(time)
        .with_aud("did:example:verifier")
        .with_claim("nonce", "n-0S6_WzA2Mj");
    assert_eq!(
        serde_json::to_string(&claims).unwrap(),
        r#"{"aud":"did:example:verifier","exp":1573029723,"nbf":1573029723,"iat":1573029723,"nonce":"n-0S6_WzA2Mj"}"#
    );
    assert_eq!(
        claims.audiences().collect::<Vec<_>>(),
        ["did:example:verifier"]
    );
    let many: JwtClaims = serde_json::from_value(json!({ "aud": ["a", "b"] })).unwrap();
    assert_eq!(many.audiences().collect::<Vec<_>>(), ["a", "b"]);
    assert_eq!(JwtClaims::new().audiences().count(), 0);

    // A 1.1 token must have `typ: JWT` when it has a `typ` at all.
    let header = r#"{"alg":"EdDSA","typ":"vc+jwt"}"#;
    let token = format!(
        "{}.{}.{}",
        base64url(header.as_bytes()),
        base64url(EXAMPLE_31_CLAIMS.as_bytes()),
        base64url(&[0; 64])
    );
    assert!(matches!(
        decode_credential(&token.parse().unwrap()),
        Err(ValidationError::UnexpectedTyp { expected: "JWT", found }) if found == "vc+jwt"
    ));
}

fn base64url(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
