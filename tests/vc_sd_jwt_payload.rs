//! The JWT credential and presentation validators refuse the issuer-signed JWT of an SD-JWT
//! (RFC 9901), whose payload carries `_sd_alg`, `_sd` or `{"...": "<digest>"}` array elements:
//! read as a plain JWT, its concealed claims would look absent and its digests would be
//! ordinary properties (RFC 8725 §3.12). A `did:key` issuer (the Ed25519 key of RFC 8037
//! Appendix A.1) signs the credentials; a `did:jwk` holder (the P-256 key of RFC 7515
//! Appendix A.3) presents them.
#![cfg(all(feature = "vc", feature = "did-key", feature = "did-jwk"))]

mod common;

use chrono::{TimeZone as _, Utc};
use identity_kit::did::{DidUrl, Uri};
use identity_kit::jose::{DefaultVerifier, JwsHeader, Signer};
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{
    CredentialValidationOptions, JwtCredentialValidator, JwtPresentationValidator,
    PresentationValidationError, PresentationValidationOptions, TimeOptions, ValidationError,
    decode_credential, decode_credential_v2, decode_presentation, decode_presentation_v2,
};
use identity_kit::vc::{
    Credential, CredentialV2, EnvelopedVc, Jwt, JwtClaims, Presentation, PresentationV2, Subject,
};
use serde_json::{Map, Value, json};

use common::fixtures::{AUDIENCE, NONCE, holder, issuer, now, resolver};

/// RFC 9901 Appendix A.4: an SD-JWT of a VCDM credential, its issuer-signed JWT first.
const RFC9901_A4_ISSUANCE: &str = include_str!("vectors/sd_jwt/w3c_vcdm/issuance.txt");
/// The payload of that issuer-signed JWT.
const RFC9901_A4_PAYLOAD: &str = include_str!("vectors/sd_jwt/w3c_vcdm/payload.json");
/// RFC 9901 §5.1: the payload of the issuer-signed JWT, whose `nationalities` has its two
/// elements concealed.
const RFC9901_SIMPLE_PAYLOAD: &str = include_str!("vectors/sd_jwt/simple/payload.json");

fn credential_validator() -> JwtCredentialValidator<Resolver> {
    JwtCredentialValidator::new(resolver(), DefaultVerifier)
}

fn presentation_validator() -> JwtPresentationValidator<Resolver> {
    JwtPresentationValidator::new(resolver(), DefaultVerifier)
}

fn options() -> CredentialValidationOptions {
    CredentialValidationOptions::new().with_time(TimeOptions::at(now()))
}

fn presentation_options() -> PresentationValidationOptions {
    PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_audience(AUDIENCE)
        .with_nonce(NONCE)
        .with_credentials(options())
}

/// `claims` signed by `signer` under `kid`, with `typ` when given.
async fn sign(claims: &JwtClaims, typ: Option<&str>, kid: &DidUrl, signer: &dyn Signer) -> Jwt {
    let mut header = JwsHeader::new(signer.alg()).with_kid(kid.as_str());
    if let Some(typ) = typ {
        header = header.with_typ(typ);
    }
    Jwt::sign(&header, claims, signer).await.unwrap()
}

/// `claims` signed by the issuer.
async fn issue(claims: &JwtClaims, typ: Option<&str>) -> Jwt {
    let issuer = issuer();
    sign(claims, typ, &issuer.kid, &issuer.signer).await
}

/// A VCDM 2.0 credential about the holder, valid from 2024 to 2026, with `properties` on its
/// subject.
fn credential_v2(properties: Value) -> CredentialV2 {
    let issuer = issuer();
    let holder = holder();
    let Value::Object(properties) = properties else {
        unreachable!()
    };
    let subject = properties
        .into_iter()
        .fold(Subject::new(&holder.did), |subject, (name, value)| {
            subject.with_property(name, value)
        });
    CredentialV2::new(&issuer.did, subject)
        .with_context("https://www.w3.org/ns/credentials/examples/v2")
        .with_type("ExampleDegreeCredential")
        .with_valid_from(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_valid_until(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
}

/// A VCDM 1.1 credential about the holder, issued in 2024.
fn credential(properties: Value) -> Credential {
    let issuer = issuer();
    let holder = holder();
    let Value::Object(properties) = properties else {
        unreachable!()
    };
    let subject = properties
        .into_iter()
        .fold(Subject::new(&holder.did), |subject, (name, value)| {
            subject.with_property(name, value)
        });
    Credential::new(
        &issuer.did,
        Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        subject,
    )
    .with_type("UniversityDegreeCredential")
}

fn degree() -> Value {
    json!({ "degree": { "type": "ExampleBachelorDegree", "name": "Bachelor of Science and Arts" } })
}

/// The digests of `degree` concealed: its subject as an SD-JWT issuer would write it.
fn concealed_degree() -> Value {
    json!({ "_sd": ["1V_K-8lDQ8iFXBFXbZY9ehqR4HabWCi5T0ybIzZPeww"] })
}

/// `claims` with `name` set to `value` at the top level.
fn with(claims: JwtClaims, name: &str, value: Value) -> JwtClaims {
    claims.with_claim(name, value)
}

/// The presentation claims of the holder, for the verifier's audience and nonce.
fn presentation_claims(claims: JwtClaims) -> JwtClaims {
    claims
        .with_aud(AUDIENCE)
        .with_claim("nonce", NONCE)
        .with_iat(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_exp(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
}

/// `claims` signed by the holder.
async fn present(claims: &JwtClaims, typ: Option<&str>) -> Jwt {
    let holder = holder();
    sign(claims, typ, &holder.kid, &holder.signer).await
}

fn sd_jwt_claim(error: &ValidationError) -> Option<&'static str> {
    match error {
        ValidationError::SdJwtPayload { claim } => Some(claim),
        _ => None,
    }
}

fn presentation_error(error: PresentationValidationError) -> ValidationError {
    assert!(error.credentials.is_empty(), "{error:?}");
    *error.presentation.expect("an error of the presentation")
}

fn credential_error(error: PresentationValidationError) -> ValidationError {
    assert!(error.presentation.is_none(), "{error:?}");
    let mut credentials = error.credentials.into_iter();
    let (0, error) = credentials.next().expect("an error of the credential") else {
        panic!("the first credential");
    };
    assert!(credentials.next().is_none());
    error
}

// Credentials

#[tokio::test]
async fn sd_jwt_payload_is_refused_by_validate_v2_typed_or_not() {
    let plain = credential_v2(degree()).to_jwt_claims();
    for typ in [None, Some(CredentialV2::JWT_TYP)] {
        // The control: the same credential without the SD-JWT claims validates.
        credential_validator()
            .validate_v2(&issue(&plain, typ).await, &options())
            .await
            .unwrap();

        // The probe of the issue: `_sd` and `_sd_alg` at the top of a VCDM 2.0 payload.
        let sd_jwt = with(
            with(
                plain.clone(),
                "_sd",
                json!(["X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"]),
            ),
            "_sd_alg",
            json!("sha-256"),
        );
        let jwt = issue(&sd_jwt, typ).await;
        let error = credential_validator()
            .validate_v2(&jwt, &options())
            .await
            .unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");
        let error = decode_credential_v2(&jwt).unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");

        // `_sd_alg` alone, which names the hash of the digests.
        let jwt = issue(&with(plain.clone(), "_sd_alg", json!("sha-256")), typ).await;
        let error = credential_validator()
            .validate_v2(&jwt, &options())
            .await
            .unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd_alg"), "{typ:?}: {error:?}");
    }
}

#[tokio::test]
async fn concealed_claims_below_the_top_level_are_refused() {
    // `_sd_alg` is optional, and an issuer may conceal only the claims of the subject: the
    // digests in `credentialSubject` are what gives it away.
    let jwt = issue(&credential_v2(concealed_degree()).to_jwt_claims(), None).await;
    let error = credential_validator()
        .validate_v2(&jwt, &options())
        .await
        .unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");

    // A concealed array element, as RFC 9901 §5.1 writes `nationalities`.
    let payload: Value = serde_json::from_str(RFC9901_SIMPLE_PAYLOAD).unwrap();
    let nationalities = payload["nationalities"].clone();
    let jwt = issue(
        &credential_v2(json!({ "nationalities": nationalities })).to_jwt_claims(),
        None,
    )
    .await;
    let error = credential_validator()
        .validate_v2(&jwt, &options())
        .await
        .unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("..."), "{error:?}");

    // Deeper still: an element of an array in an object in an array.
    let jwt = issue(
        &credential_v2(json!({ "family": [{ "names": ["Erika", { "...": "digest" }] }] }))
            .to_jwt_claims(),
        None,
    )
    .await;
    let error = decode_credential_v2(&jwt).unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("..."), "{error:?}");
}

#[tokio::test]
async fn sd_jwt_payload_is_refused_by_validate() {
    // A VCDM 1.1 SD-JWT conceals the claims in its `vc` claim.
    let claims = credential(concealed_degree()).to_jwt_claims().unwrap();
    for typ in [None, Some("JWT")] {
        let jwt = issue(&claims, typ).await;
        let error = credential_validator()
            .validate(&jwt, &options())
            .await
            .unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");
        let error = decode_credential(&jwt).unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");
    }
    let jwt = issue(
        &with(
            credential(degree()).to_jwt_claims().unwrap(),
            "_sd_alg",
            json!("sha-256"),
        ),
        None,
    )
    .await;
    let error = credential_validator()
        .validate(&jwt, &options())
        .await
        .unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd_alg"), "{error:?}");
}

#[tokio::test]
async fn rfc9901_a4_issuer_jwt_is_refused() {
    // As published, its `typ` already tells it apart.
    let published: Jwt = RFC9901_A4_ISSUANCE
        .trim()
        .split('~')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let error = credential_validator()
        .validate(&published, &options())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ValidationError::UnexpectedTyp { ref found, .. } if found == "example+sd-jwt"),
        "{error:?}"
    );
    let error = credential_validator()
        .validate_v2(&published, &options())
        .await
        .unwrap_err();
    assert!(
        matches!(error, ValidationError::UnexpectedTyp { .. }),
        "{error:?}"
    );

    // Untyped, under the issuer's DID, its payload is still refused, before its shape or its
    // issuer is looked at.
    let payload: Map<String, Value> = serde_json::from_str(RFC9901_A4_PAYLOAD).unwrap();
    let mut claims = JwtClaims::new();
    claims.additional.extend(payload.clone());
    let jwt = issue(&claims, None).await;
    for error in [
        credential_validator()
            .validate(&jwt, &options())
            .await
            .unwrap_err(),
        credential_validator()
            .validate_v2(&jwt, &options())
            .await
            .unwrap_err(),
        decode_credential(&jwt).unwrap_err(),
        decode_credential_v2(&jwt).unwrap_err(),
    ] {
        // `credentialSubject`, with its `_sd`, comes before `_sd_alg`.
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
    }

    // In the `vc` claim of a VCDM 1.1 JWT, under the issuer's DID.
    let issuer = issuer();
    let mut vc = payload;
    vc.insert("issuer".to_owned(), json!(issuer.did.as_str()));
    let jwt = issue(
        &JwtClaims::new()
            .with_iss(issuer.did.as_str())
            .with_claim("vc", vc),
        Some("JWT"),
    )
    .await;
    let error = credential_validator()
        .validate(&jwt, &options())
        .await
        .unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
}

#[tokio::test]
async fn sd_jwt_names_as_values_or_in_other_shapes_are_not_refused() {
    // The names as strings, a `...` member that is not an array element, a `...` element with
    // another member or a value that is not a digest, and names that merely start alike.
    let properties = json!({
        "note": "_sd",
        "tags": ["_sd", "_sd_alg", "..."],
        "ellipsis": { "...": "not an array element" },
        "elements": [
            { "...": "digest", "name": "two members" },
            { "...": 7 },
            [{ "...": ["not", "a", "string"] }],
        ],
        "_sdx": true,
        "sd": { "_sd_algorithm": "sha-256", "__sd": [] },
    });
    let v2 = credential_v2(properties.clone()).to_jwt_claims();
    for typ in [None, Some(CredentialV2::JWT_TYP)] {
        credential_validator()
            .validate_v2(&issue(&v2, typ).await, &options())
            .await
            .unwrap();
    }
    let v1 = credential(properties).to_jwt_claims().unwrap();
    credential_validator()
        .validate(&issue(&v1, None).await, &options())
        .await
        .unwrap();
}

// Presentations

#[tokio::test]
async fn vp_jwt_payload_with_sd_is_refused() {
    let holder = holder();
    let enveloped =
        EnvelopedVc::from_jwt(&issue(&credential_v2(degree()).to_jwt_claims(), None).await);
    let presentation = PresentationV2::new()
        .with_holder(&holder.did)
        .with_credential(enveloped);
    let plain = presentation_claims(presentation.to_jwt_claims());

    // The control.
    presentation_validator()
        .validate_v2(
            &present(&plain, Some(PresentationV2::JWT_TYP)).await,
            &presentation_options(),
        )
        .await
        .unwrap();

    let sd_jwt = with(
        plain,
        "_sd",
        json!(["X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"]),
    );
    for typ in [None, Some(PresentationV2::JWT_TYP)] {
        let jwt = present(&sd_jwt, typ).await;
        let error = presentation_validator()
            .validate_v2(&jwt, &presentation_options())
            .await
            .unwrap_err();
        let error = presentation_error(error);
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");
        let error = decode_presentation_v2(&jwt).unwrap_err();
        assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{typ:?}: {error:?}");
    }
}

#[tokio::test]
async fn enveloped_vc_jwt_with_sd_is_refused() {
    // A `vc+jwt` envelope holding the issuer-signed JWT of an SD-JWT: it claims to be a plain
    // JWT, so it fails as one.
    let holder = holder();
    let enveloped = EnvelopedVc::from_jwt(
        &issue(
            &credential_v2(concealed_degree()).to_jwt_claims(),
            Some(CredentialV2::JWT_TYP),
        )
        .await,
    );
    let presentation = PresentationV2::new()
        .with_holder(&holder.did)
        .with_credential(enveloped);
    let jwt = present(
        &presentation_claims(presentation.to_jwt_claims()),
        Some(PresentationV2::JWT_TYP),
    )
    .await;
    let error = presentation_validator()
        .validate_v2(&jwt, &presentation_options())
        .await
        .unwrap_err();
    let error = credential_error(error);
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
    let error = decode_presentation_v2(&jwt).unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
}

#[tokio::test]
async fn vcdm_1_1_presentation_and_its_credentials_with_sd_are_refused() {
    let holder = holder();
    let plain_credential = issue(&credential(degree()).to_jwt_claims().unwrap(), None).await;
    let presentation = |credentials: Vec<Jwt>| {
        let mut presentation = Presentation::new()
            .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap())
            .with_holder(&holder.did);
        presentation.verifiable_credential = credentials;
        presentation_claims(presentation.to_jwt_claims().unwrap())
    };

    // The control.
    let claims = presentation(vec![plain_credential.clone()]);
    presentation_validator()
        .validate(
            &present(&claims, Some("JWT")).await,
            &presentation_options(),
        )
        .await
        .unwrap();

    // The presentation JWT carries `_sd_alg`.
    let jwt = present(&with(claims, "_sd_alg", json!("sha-256")), None).await;
    let error = presentation_validator()
        .validate(&jwt, &presentation_options())
        .await
        .unwrap_err();
    let error = presentation_error(error);
    assert_eq!(sd_jwt_claim(&error), Some("_sd_alg"), "{error:?}");
    let error = decode_presentation(&jwt).unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd_alg"), "{error:?}");

    // A credential it carries is the issuer-signed JWT of an SD-JWT.
    let sd_jwt_credential = issue(
        &credential(concealed_degree()).to_jwt_claims().unwrap(),
        None,
    )
    .await;
    let jwt = present(&presentation(vec![sd_jwt_credential]), Some("JWT")).await;
    let error = presentation_validator()
        .validate(&jwt, &presentation_options())
        .await
        .unwrap_err();
    let error = credential_error(error);
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
    let error = decode_presentation(&jwt).unwrap_err();
    assert_eq!(sd_jwt_claim(&error), Some("_sd"), "{error:?}");
}
