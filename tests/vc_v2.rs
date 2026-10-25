//! Specification vectors for VCDM 2.0 credentials and presentations secured with VC-JOSE-COSE:
//! the examples of "Securing JSON-LD Verifiable Credentials/Presentations with JOSE", the
//! enveloped credential and presentation objects of VCDM 2.0 §4.12, and the validity period.
#![cfg(feature = "vc")]
#![expect(
    clippy::unreadable_literal,
    reason = "numbers are written as the specifications' examples write them"
)]

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{OneOrMany, Uri};
use identity_kit::jose::JwsAlgorithm;
use identity_kit::vc::validation::{decode_credential_v2, extract_issuer};
use identity_kit::vc::{
    CredentialError, CredentialV2, EnvelopedVc, EnvelopedVp, Jwt, JwtClaims, Party, PresentationV2,
    Subject, TypedObject,
};
use serde_json::{Value, json};

/// VC-JOSE-COSE "Securing JSON-LD Verifiable Credentials with JOSE": the credential.
const CREDENTIAL: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/3732",
  "type": ["VerifiableCredential", "ExampleDegreeCredential", "ExamplePersonCredential"],
  "issuer": "https://university.example/issuers/14",
  "validFrom": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "ExampleBachelorDegree",
      "name": "Bachelor of Science and Arts"
    },
    "alumniOf": {
      "name": "Example University"
    }
  },
  "credentialSchema": [{
    "id": "https://example.org/examples/degree.json",
    "type": "JsonSchema"
  },
  {
    "id": "https://example.org/examples/alumni.json",
    "type": "JsonSchema"
  }]
}"#;

/// VC-JOSE-COSE "Securing JSON-LD Verifiable Presentations with JOSE": the enveloped
/// credential inside the example presentation, an ES384 `vc+jwt`. (The published example
/// repeats the `data:` URL twice, joined by `;`; this is the first copy.)
const CREDENTIAL_JWT: &str = "eyJraWQiOiJFeEhrQk1XOWZtYmt2VjI2Nm1ScHVQMnNVWV9OX0VXSU4xbGFwVXpPOHJvIiwiYWxnIjoiRVMzODQifQ.\
    eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMv\
    Y3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaWQiOiJodHRwOi8vdW5pdmVyc2l0eS5leGFtcGxlL2NyZWRlbnRpYWxzLzE4NzIi\
    LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRXhhbXBsZUFsdW1uaUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6\
    Ly91bml2ZXJzaXR5LmV4YW1wbGUvaXNzdWVycy81NjUwNDkiLCJ2YWxpZEZyb20iOiIyMDEwLTAxLTAxVDE5OjIzOjI0WiIsImNy\
    ZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2V4YW1wbGUub3JnL2V4YW1wbGVzL2RlZ3JlZS5qc29uIiwidHlwZSI6Ikpz\
    b25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJkZWdyZWUiOnsidHlwZSI6IkJh\
    Y2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19.\
    d2k4O3FytQJf83kLh-HsXuPvh6yeOlhJELVo5TF71gu7elslQyOf2ZItAXrtbXF4Kz9WivNdztOayz4VUQ0Mwa8yCDZkP9B2pH-9\
    S_tcAFxeoeJ6Z4XnFuL_DOfkR1fP";

/// The presentation of the same example, as its JWT payload shows it (with the duplicated
/// `data:` URL reduced to one, as above).
fn presentation_payload() -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "type": "VerifiablePresentation",
        "verifiableCredential": [{
            "@context": "https://www.w3.org/ns/credentials/v2",
            "id": format!("data:application/vc+jwt,{CREDENTIAL_JWT}"),
            "type": "EnvelopedVerifiableCredential"
        }]
    })
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

fn time(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
}

#[test]
fn jose_credential_example_round_trips() {
    let credential: CredentialV2 = serde_json::from_str(CREDENTIAL).unwrap();
    assert_eq!(
        credential.id,
        Some(uri("http://university.example/credentials/3732"))
    );
    assert!(credential.has_type("ExamplePersonCredential"));
    assert_eq!(
        credential.issuer,
        Party::Uri(uri("https://university.example/issuers/14"))
    );
    assert_eq!(credential.valid_from, Some(time("2010-01-01T19:23:24Z")));
    assert_eq!(credential.valid_until, None);
    assert_eq!(
        credential.subject().unwrap().properties["alumniOf"]["name"],
        "Example University"
    );
    let schemas = credential.credential_schema.as_ref().unwrap();
    assert_eq!(schemas.len(), 2);
    assert!(schemas.iter().all(|schema| schema.has_type("JsonSchema")));
    assert_eq!(credential.statuses().count(), 0);

    let expected: Value = serde_json::from_str(CREDENTIAL).unwrap();
    assert_eq!(serde_json::to_value(&credential).unwrap(), expected);
    assert_eq!(
        serde_json::to_string(&credential).unwrap(),
        serde_json::to_string(&expected).unwrap()
    );

    // VC-JOSE-COSE §3.1.1: the credential is the JWT payload.
    let claims = credential.to_jwt_claims();
    assert_eq!(serde_json::to_value(&claims).unwrap(), expected);
    assert_eq!(CredentialV2::from_jwt_claims(&claims).unwrap(), credential);
}

#[test]
fn jose_credential_jwt_decodes() {
    let jwt: Jwt = CREDENTIAL_JWT.parse().unwrap();
    let decoded = decode_credential_v2(&jwt).unwrap();
    assert_eq!(decoded.header.alg, JwsAlgorithm::ES384);
    assert_eq!(
        decoded.header.kid.as_deref(),
        Some("ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro")
    );
    // No registered claims in the example: the payload is the credential alone.
    assert_eq!(decoded.claims.iss, None);
    assert_eq!(decoded.claims.jti, None);
    let credential = decoded.credential;
    assert_eq!(
        credential.id,
        Some(uri("http://university.example/credentials/1872"))
    );
    assert_eq!(
        credential.issuer.id(),
        &uri("https://university.example/issuers/565049")
    );
    assert_eq!(credential.valid_from, Some(time("2010-01-01T19:23:24Z")));
    assert_eq!(
        credential.subject().unwrap().id,
        Some(uri("did:example:123"))
    );
    assert_eq!(
        credential.credential_schema,
        Some(OneOrMany::One(
            TypedObject::new("JsonSchema").with_id(uri("https://example.org/examples/degree.json"))
        ))
    );
    assert!(matches!(
        extract_issuer(&jwt),
        Err(identity_kit::vc::validation::ValidationError::NotDid { role: "issuer", .. })
    ));
}

#[test]
fn jose_presentation_example_with_enveloped_credential() {
    let presentation: PresentationV2 = serde_json::from_value(presentation_payload()).unwrap();
    assert_eq!(
        presentation.types,
        OneOrMany::One("VerifiablePresentation".to_owned())
    );
    assert_eq!(presentation.holder, None);
    assert_eq!(presentation.verifiable_credential.len(), 1);
    let enveloped = &presentation.verifiable_credential[0];
    assert_eq!(enveloped.media_type(), "application/vc+jwt");
    assert_eq!(enveloped.data(), CREDENTIAL_JWT);
    let jwt = enveloped.to_jwt().unwrap();
    assert_eq!(jwt.as_str(), CREDENTIAL_JWT);
    assert_eq!(
        serde_json::to_value(&presentation).unwrap(),
        presentation_payload()
    );

    // The same presentation, built.
    let built = PresentationV2::new()
        .with_context("https://www.w3.org/ns/credentials/examples/v2")
        .with_credential(EnvelopedVc::from_jwt(&jwt));
    assert_eq!(built, presentation);
    let claims = built.to_jwt_claims();
    assert_eq!(
        serde_json::to_value(&claims).unwrap(),
        presentation_payload()
    );
    assert_eq!(PresentationV2::from_jwt_claims(&claims).unwrap(), built);

    let named = built
        .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap())
        .with_type("ExamplePresentation");
    assert_eq!(
        named.id.as_ref().map(Uri::as_str),
        Some("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")
    );
    assert!(named.has_type("VerifiablePresentation"));
    assert!(named.has_type("ExamplePresentation"));
    assert!(!named.has_type("ExampleDegreeCredential"));
}

#[test]
fn enveloped_objects() {
    // VCDM 2.0 §4.12.2: an enveloped presentation.
    let vp: EnvelopedVp = serde_json::from_value(json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "data:application/vp+jwt,eyJraWQiO...zhwGfQ",
        "type": "EnvelopedVerifiablePresentation"
    }))
    .unwrap();
    assert_eq!(vp.media_type(), "application/vp+jwt");
    assert_eq!(vp.data(), "eyJraWQiO...zhwGfQ");
    assert!(matches!(
        vp.to_jwt(),
        Err(CredentialError::InvalidClaim { claim: "id", .. })
    ));

    // VCDM 2.0 §4.12.1: an SD-JWT envelope is carried, not read here.
    let sd_jwt: EnvelopedVc = serde_json::from_value(json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "id": "data:application/vc+sd-jwt,QzVjV...RMjU",
        "type": "EnvelopedVerifiableCredential"
    }))
    .unwrap();
    assert_eq!(sd_jwt.media_type(), "application/vc+sd-jwt");
    assert_eq!(
        sd_jwt.to_jwt(),
        Err(CredentialError::UnsupportedMediaType {
            kind: "credential",
            media_type: "application/vc+sd-jwt".to_owned(),
            expected: "application/vc+jwt"
        })
    );
    let cose = EnvelopedVc::new("application/vc+cose;base64", "0oREo...+Q==").unwrap();
    assert_eq!(cose.media_type(), "application/vc+cose");
    // A `data:` URL is a URI: a space in the data is refused, not panicked on.
    assert!(matches!(
        EnvelopedVc::new("application/vc+jwt", "not a jwt"),
        Err(CredentialError::InvalidClaim { claim: "id", .. })
    ));
    assert_eq!(
        cose.to_jwt(),
        Err(CredentialError::UnsupportedMediaType {
            kind: "credential",
            media_type: "application/vc+cose;base64".to_owned(),
            expected: "application/vc+jwt"
        })
    );

    let error = |value: Value| {
        serde_json::from_value::<EnvelopedVc>(value)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        error(json!({
            "@context": "https://www.w3.org/ns/credentials/v2",
            "id": "https://example.org/credentials/1",
            "type": "EnvelopedVerifiableCredential"
        })),
        "`https://example.org/credentials/1` is not a `data:` URL"
    );
    assert_eq!(
        error(json!({
            "@context": "https://www.w3.org/ns/credentials/v2",
            "id": "data:application/vc+jwt,eyJ",
            "type": "VerifiableCredential"
        })),
        "`type` must include `EnvelopedVerifiableCredential`"
    );
    assert!(
        error(
            json!({ "id": "data:application/vc+jwt,eyJ", "type": "EnvelopedVerifiableCredential" })
        )
        .contains("@context")
    );
}

#[test]
fn validity_period_examples() {
    // VCDM 2.0 §4.6.
    let credential: CredentialV2 = serde_json::from_value(json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "http://university.example/credentials/3732",
        "type": ["VerifiableCredential", "ExampleDegreeCredential"],
        "issuer": "https://university.example/issuers/14",
        "validFrom": "2010-01-01T19:23:24Z",
        "validUntil": "2020-01-01T19:23:24Z",
        "credentialSubject": {
            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "degree": { "type": "ExampleBachelorDegree", "name": "Bachelor of Science and Arts" }
        }
    }))
    .unwrap();
    assert_eq!(credential.valid_until, Some(time("2020-01-01T19:23:24Z")));

    // VCDM 2.0 §5.3 refresh service example: fractional seconds, `name`, no subject id.
    let age: CredentialV2 = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/age/v1"],
        "type": ["VerifiableCredential", "AgeVerificationCredential"],
        "issuer": "did:key:z6MksFxi8wnHkNq4zgEskSZF45SuWQ4HndWSAVYRRGe9qDks",
        "validFrom": "2024-04-03T00:00:00.000Z",
        "validUntil": "2024-12-15T00:00:00.000Z",
        "name": "Age Verification Credential",
        "credentialSubject": { "overAge": 21 },
        "refreshService": {
            "type": "VerifiableCredentialRefreshService2021",
            "url": "https://registration.provider.example/flows/reissue-age-token",
            "refreshToken": "z2BJYfNtmWRiouWhDrbDQmC2zicUPBxsPg"
        }
    }))
    .unwrap();
    assert_eq!(age.valid_from, Some(time("2024-04-03T00:00:00Z")));
    assert_eq!(age.name, Some(json!("Age Verification Credential")));
    assert_eq!(age.subject().unwrap().id, None);
    assert_eq!(
        age.properties["refreshService"]["type"],
        "VerifiableCredentialRefreshService2021"
    );
    let json = serde_json::to_value(&age).unwrap();
    assert_eq!(json["validFrom"], "2024-04-03T00:00:00Z");
    assert_eq!(json["name"], "Age Verification Credential");
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "@context",
            "type",
            "name",
            "issuer",
            "validFrom",
            "validUntil",
            "credentialSubject",
            "refreshService"
        ]
    );

    // VC-JOSE-COSE example with milliseconds, which survive the round trip.
    let kyc: CredentialV2 = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
        "id": "https://contoso.example/credentials/35327255",
        "type": ["VerifiableCredential", "KYCExample"],
        "issuer": "did:web:contoso.example",
        "validFrom": "2019-05-25T03:10:16.992Z",
        "validUntil": "2027-05-25T03:10:16.992Z",
        "credentialSchema": { "id": "https://contoso.example/bafybeigdyr...lqabf3oclgtqy55fbzdi", "type": "JsonSchema" },
        "credentialSubject": { "id": "did:example:1231588", "type": "Person" }
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_value(&kyc).unwrap()["validFrom"],
        "2019-05-25T03:10:16.992Z"
    );

    // validUntil before validFrom is not a credential.
    let error = serde_json::from_value::<CredentialV2>(json!({
        "@context": "https://www.w3.org/ns/credentials/v2",
        "type": "VerifiableCredential",
        "issuer": "did:example:issuer",
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2010-01-01T00:00:00Z",
        "credentialSubject": { "id": "did:example:subject" }
    }))
    .unwrap_err();
    assert_eq!(error.to_string(), "`validUntil` precedes `validFrom`");
}

#[test]
fn registered_claims_must_agree_with_the_credential() {
    let credential: CredentialV2 = serde_json::from_str(CREDENTIAL).unwrap();
    let claims = credential.to_jwt_claims();
    let with = |f: fn(&mut JwtClaims)| {
        let mut claims = claims.clone();
        f(&mut claims);
        CredentialV2::from_jwt_claims(&claims)
    };
    // Agreeing claims are fine (VC-JOSE-COSE §3.3.1: `iss` MUST match `issuer`).
    assert!(
        with(|c| {
            c.iss = Some("https://university.example/issuers/14".to_owned());
            c.jti = Some("http://university.example/credentials/3732".to_owned());
            c.sub = Some("did:example:ebfeb1f712ebc6f1c276e12ec21".to_owned());
            c.iat = Some(1262373804);
        })
        .is_ok()
    );
    assert_eq!(
        with(|c| c.iss = Some("https://university.example/issuers/565049".to_owned())),
        Err(CredentialError::ClaimMismatch {
            claim: "iss",
            property: "issuer"
        })
    );
    assert_eq!(
        with(|c| c.jti = Some("urn:uuid:1".to_owned())),
        Err(CredentialError::ClaimMismatch {
            claim: "jti",
            property: "id"
        })
    );
    assert_eq!(
        with(|c| c.sub = Some("did:example:other".to_owned())),
        Err(CredentialError::ClaimMismatch {
            claim: "sub",
            property: "credentialSubject.id"
        })
    );
    // VC-JOSE-COSE §3.3: the `vc` and `vp` claims MUST NOT be present.
    assert_eq!(
        with(|c| {
            c.additional.insert("vc".to_owned(), json!({}));
        }),
        Err(CredentialError::InvalidClaim {
            claim: "vc",
            reason: "must not be present in a VC-JOSE-COSE payload".to_owned()
        })
    );
    // A payload that is not a credential at all.
    let claims: JwtClaims = serde_json::from_value(json!({ "iss": "did:example:123" })).unwrap();
    assert!(matches!(
        CredentialV2::from_jwt_claims(&claims),
        Err(CredentialError::InvalidClaim {
            claim: "@context",
            ..
        })
    ));
    let claims: JwtClaims = serde_json::from_value(json!({ "vp": {} })).unwrap();
    assert!(matches!(
        PresentationV2::from_jwt_claims(&claims),
        Err(CredentialError::InvalidClaim { claim: "vp", .. })
    ));
}

#[test]
fn builder_reproduces_the_jose_example() {
    let credential = CredentialV2::new(
        uri("https://university.example/issuers/14"),
        Subject::new(uri("did:example:ebfeb1f712ebc6f1c276e12ec21"))
            .with_property(
                "degree",
                json!({ "type": "ExampleBachelorDegree", "name": "Bachelor of Science and Arts" }),
            )
            .with_property("alumniOf", json!({ "name": "Example University" })),
    )
    .with_context("https://www.w3.org/ns/credentials/examples/v2")
    .with_id(uri("http://university.example/credentials/3732"))
    .with_type("ExampleDegreeCredential")
    .with_type("ExamplePersonCredential")
    .with_valid_from(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap())
    .with_schema(
        TypedObject::new("JsonSchema").with_id(uri("https://example.org/examples/degree.json")),
    )
    .with_schema(
        TypedObject::new("JsonSchema").with_id(uri("https://example.org/examples/alumni.json")),
    );
    let expected: Value = serde_json::from_str(CREDENTIAL).unwrap();
    assert_eq!(serde_json::to_value(&credential).unwrap(), expected);

    let with_status = credential
        .clone()
        .with_status(
            TypedObject::new("BitstringStatusListEntry")
                .with_property("statusPurpose", "revocation"),
        )
        .with_status(
            TypedObject::new("BitstringStatusListEntry")
                .with_property("statusPurpose", "suspension"),
        )
        .with_valid_until(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap())
        .with_name("Degree")
        .with_description(json!([{ "@value": "A degree", "@language": "en" }]))
        .with_subject(Subject::default())
        .with_property("relatedResource", json!([]));
    assert_eq!(with_status.statuses().count(), 2);
    assert_eq!(with_status.credential_subject.len(), 2);
    assert_eq!(with_status.subject(), None);
    let roundtrip: CredentialV2 =
        serde_json::from_value(serde_json::to_value(&with_status).unwrap()).unwrap();
    assert_eq!(roundtrip, with_status);
}

#[test]
fn validity_period_may_be_a_single_instant() {
    // VCDM 2.0, Validity Period: `validUntil` may equal `validFrom`.
    let credential: CredentialV2 = serde_json::from_str(CREDENTIAL).unwrap();
    assert!(credential.has_type("ExampleDegreeCredential"));
    assert!(!credential.has_type("ExamplePresentation"));
    let entry = TypedObject::new("BitstringStatusListEntry");
    assert!(entry.has_type("BitstringStatusListEntry"));
    assert!(!entry.has_type("StatusList2021Entry"));
    let from = Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap();
    credential.clone().with_valid_until(from).check().unwrap();
    assert_eq!(
        credential
            .with_valid_until(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 23).unwrap())
            .check(),
        Err(CredentialError::InvalidValidity {
            from: "validFrom",
            until: "validUntil"
        })
    );
}
