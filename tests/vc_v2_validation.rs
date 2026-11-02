//! VCDM 2.0 presentations secured with VC-JOSE-COSE (`vp+jwt`): the specification's enveloped
//! presentation example and the JOSE presentation inputs of the W3C VC-JOSE-COSE test suite,
//! then presentations validated end to end. A `did:key` issuer (the Ed25519 key of RFC 8037
//! Appendix A.1) signs `vc+jwt` credentials for a `did:jwk` holder (the P-256 key of RFC 7515
//! Appendix A.3), who envelopes them in a `vp+jwt` presentation.
#![cfg(all(feature = "vc", feature = "did-key", feature = "did-jwk"))]

mod common;

use std::error::Error as _;

use chrono::{TimeZone as _, Utc};
use identity_kit::did::{Did, DidUrl, Uri};
use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader};
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{
    CredentialValidationOptions, DecodedPresentationV2, FailFast, JwtPresentationValidator,
    KeyReference, KeyReferenceError, KeyResolutionError, KeyRole, PresentationValidationError,
    PresentationValidationOptions, SubjectHolderRelationship, TimeOptions, ValidationError,
    decode_credential_v2, decode_presentation, decode_presentation_v2,
};
use identity_kit::vc::{
    CredentialError, CredentialV2, EnvelopedVc, EnvelopedVp, Jwt, JwtClaims, Presentation,
    PresentationV2, Subject,
};
use serde_json::{Value, json};

use common::fixtures::{AUDIENCE, Issuer, NONCE, RefusingRole, holder, issuer, now, resolver};

fn vector(name: &str) -> &'static str {
    match name {
        "enveloped" => include_str!("vectors/vc_jose_cose/enveloped_presentation_jwt.txt"),
        "multiple" => include_str!("vectors/vc_jose_cose/suite-presentation-jose-multiple.txt"),
        "bad_media_type" => {
            include_str!("vectors/vc_jose_cose/suite-presentation-jose-bad-media-type.txt")
        }
        "bad_credential" => {
            include_str!("vectors/vc_jose_cose/suite-presentation-jose-bad-credential.txt")
        }
        "vm_p256" => include_str!("vectors/vc_jose_cose/suite-vm-p256.json"),
        "vm_p384" => include_str!("vectors/vc_jose_cose/suite-vm-p384.json"),
        "vm_ed25519" => include_str!("vectors/vc_jose_cose/suite-vm-ed25519.json"),
        _ => unreachable!(),
    }
}

fn jwt(name: &str) -> Jwt {
    vector(name).trim().parse().unwrap()
}

fn suite_key(name: &str) -> Jwk {
    let method: Value = serde_json::from_str(vector(name)).unwrap();
    serde_json::from_value(method["publicKeyJwk"].clone()).unwrap()
}

fn payload(jwt: &Jwt) -> JwtClaims {
    serde_json::from_slice(jwt.decode().unwrap().payload()).unwrap()
}

fn presentation_error(error: PresentationValidationError) -> ValidationError {
    match error {
        PresentationValidationError {
            presentation: Some(error),
            ..
        } => *error,
        other => panic!("expected an error of the presentation, got {other:?}"),
    }
}

fn credential_errors(error: PresentationValidationError) -> Vec<(usize, ValidationError)> {
    assert!(error.presentation.is_none(), "{error:?}");
    error.credentials.into_iter().collect()
}

// The specification's example and the W3C test suite's inputs.

#[tokio::test]
async fn enveloped_presentation_example() {
    // VC-JOSE-COSE "A simple example of a verifiable presentation secured with JOSE with the
    // EnvelopedVerifiablePresentation type": the `vp+jwt` its `data:` URL holds.
    let jwt = jwt("enveloped");
    let enveloped = EnvelopedVp::from_jwt(&jwt);
    assert_eq!(enveloped.media_type(), PresentationV2::JWT_MEDIA_TYPE);
    assert_eq!(enveloped.to_jwt().unwrap(), jwt);

    let jws = jwt.decode().unwrap();
    assert_eq!(jws.header().alg, JwsAlgorithm::ES256);
    assert_eq!(jws.header().typ, None);
    let presentation = PresentationV2::from_jwt_claims(&payload(&jwt)).unwrap();
    assert_eq!(presentation.holder, None);
    let [credential] = presentation.verifiable_credential.as_slice() else {
        panic!("one enveloped credential");
    };
    assert_eq!(credential.media_type(), CredentialV2::JWT_MEDIA_TYPE);
    // The published `data:` URL holds the credential twice, joined by `;`, which is not one
    // JWT; its first copy is the ES384 `vc+jwt` of the credential example.
    let (first, second) = credential
        .data()
        .split_once(";data:application/vc+jwt,")
        .unwrap();
    assert_eq!(first, second);
    let first: Jwt = first.parse().unwrap();
    assert_eq!(
        decode_credential_v2(&first)
            .unwrap()
            .credential
            .subject()
            .unwrap()
            .id,
        Some(Uri::parse("did:example:123").unwrap())
    );
    assert!(matches!(
        decode_presentation_v2(&jwt),
        Err(ValidationError::Credential(CredentialError::InvalidClaim {
            claim: "id",
            ..
        }))
    ));

    // Its `kid` is not a DID URL, so no key of a DID can verify it (ADR 0004).
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::KeyReference(KeyReferenceError::InvalidKid { kid, .. }) if kid == "ExHkBMW9fmbkvV266mRpuP2sUY_N_EWIN1lapUzO8ro"
    ));
}

/// The envelopes of the suite's complex presentation, as written.
fn suite_envelopes() -> Vec<Value> {
    let raw: Value = serde_json::from_slice(jwt("multiple").decode().unwrap().payload()).unwrap();
    raw["verifiableCredential"].as_array().unwrap().clone()
}

#[tokio::test]
async fn suite_presentation_with_three_credentials() {
    // W3C VC-JOSE-COSE test suite, test 7 "JWT Complex Presentation Verification": a `vp+jwt`
    // signed with ES384, enveloping a `vc+jwt`, an SD-JWT and a COSE credential.
    let jwt = jwt("multiple");
    let jws = jwt.decode().unwrap();
    assert_eq!(jws.header().alg, JwsAlgorithm::ES384);
    assert_eq!(jws.header().typ.as_deref(), Some(PresentationV2::JWT_TYP));
    assert_eq!(jws.header().cty.as_deref(), Some("vp"));
    let claims = payload(&jwt);
    assert_eq!(
        claims.iss.as_deref(),
        Some("https://example.issuer/vc-jose-cose")
    );
    let ids: Vec<String> = suite_envelopes()
        .iter()
        .map(|envelope| envelope["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids[0].starts_with("data:application/vc+jwt,"));
    assert!(ids[1].starts_with("data:application/vc+sd-jwt,"));
    assert!(ids[2].starts_with("data:application/vc+cose;base64,"));

    // The COSE envelope's `data:` URL ends in a line feed, which RFC 3986 does not allow in a
    // URI, so the presentation does not decode, and validation stops there, before any key is
    // looked up.
    assert!(ids[2].ends_with('\n'));
    assert!(matches!(
        PresentationV2::from_jwt_claims(&claims),
        Err(CredentialError::InvalidClaim { reason, .. }) if reason.contains("'\\n'")
    ));
    assert!(matches!(
        decode_presentation_v2(&jwt),
        Err(ValidationError::Credential(
            CredentialError::InvalidClaim { .. }
        ))
    ));
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Credential(CredentialError::InvalidClaim { .. })
    ));

    // Each envelope on its own: the `vc+jwt` verifies under the suite's P-256 key, and the
    // SD-JWT and COSE envelopes are not JWTs this crate unwraps.
    let mut envelopes = suite_envelopes();
    envelopes[2]["id"] = Value::String(ids[2].trim_end().to_owned());
    let envelopes: Vec<EnvelopedVc> = serde_json::from_value(Value::Array(envelopes)).unwrap();
    let credential = envelopes[0].to_jwt().unwrap();
    credential
        .decode()
        .unwrap()
        .verify(&DefaultVerifier, &suite_key("vm_p256"))
        .unwrap();
    for enveloped in &envelopes[1..] {
        assert!(matches!(
            enveloped.to_jwt(),
            Err(CredentialError::UnsupportedMediaType { .. })
        ));
    }
    // That `vc+jwt` writes `iat` as an RFC 3339 string, where RFC 7519 requires a
    // NumericDate, so it does not decode as a claims set.
    let raw: Value = serde_json::from_slice(credential.decode().unwrap().payload()).unwrap();
    assert_eq!(raw["iat"], "2010-01-01T19:23:24Z");
    let error = decode_credential_v2(&credential).unwrap_err();
    assert!(matches!(error, ValidationError::Payload(_)));
    assert!(error.source().unwrap().is::<serde_json::Error>());
}

#[tokio::test]
async fn suite_presentation_with_bad_media_type() {
    // Test 14 "JWT Presentation with an Invalid Media Type": `typ` is `bad+typ`.
    let jwt = jwt("bad_media_type");
    jwt.decode()
        .unwrap()
        .verify(&DefaultVerifier, &suite_key("vm_ed25519"))
        .unwrap();
    assert!(matches!(
        decode_presentation_v2(&jwt),
        Err(ValidationError::UnexpectedTyp { expected: "vp+jwt", found }) if found == "bad+typ"
    ));
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::UnexpectedTyp { found, .. } if found == "bad+typ"
    ));
    // Accepting its `typ` gets as far as the key: the holder is an HTTPS URL and `kid` a
    // thumbprint, so the key is in the holder's key set (ADR 0006), which a DID resolver does
    // not look in.
    let error = validator()
        .validate_v2(&jwt, &options().with_additional_typ("bad+typ"))
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::KeyResolution {
            key,
            source: KeyResolutionError::Unsupported(_),
        } if matches!(&*key, KeyReference::Jwks { issuer, kid }
            if issuer.as_str() == "https://example.issuer/vc-jose-cose"
                && kid == "2aOHaQxsWVT4mLsUkdtlCnUV-au0BBR-5yPYaPaCc5k")
    ));
}

#[tokio::test]
async fn suite_presentation_with_bad_credential() {
    // Test 16 "JWT Presentation with an Invalid Credential": the envelope's `id` is not a
    // `data:` URL, so the presentation itself does not decode.
    let jwt = jwt("bad_credential");
    jwt.decode()
        .unwrap()
        .verify(&DefaultVerifier, &suite_key("vm_ed25519"))
        .unwrap();
    assert!(matches!(
        decode_presentation_v2(&jwt),
        Err(ValidationError::Credential(_))
    ));
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::Credential(_)
    ));
}

// Presentations validated end to end, at the shared `now`, inside the validity of every
// credential and presentation built here.

fn validator() -> JwtPresentationValidator<Resolver> {
    JwtPresentationValidator::new(resolver(), DefaultVerifier)
}

fn options() -> PresentationValidationOptions {
    PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_audience(AUDIENCE)
        .with_nonce(NONCE)
        .with_credentials(CredentialValidationOptions::new().with_time(TimeOptions::at(now())))
}

/// The VC-JOSE-COSE credential example's shape, issued about `subject`.
fn credential(issuer: &Issuer, subject: &Did) -> CredentialV2 {
    CredentialV2::new(
        &issuer.did,
        Subject::new(subject).with_property(
            "degree",
            json!({ "type": "ExampleBachelorDegree", "name": "Bachelor of Science and Arts" }),
        ),
    )
    .with_context("https://www.w3.org/ns/credentials/examples/v2")
    .with_id(Uri::parse("http://university.example/credentials/3732").unwrap())
    .with_type("ExampleDegreeCredential")
    .with_valid_from(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap())
    .with_valid_until(Utc.with_ymd_and_hms(2030, 1, 1, 19, 23, 24).unwrap())
}

/// `credential` signed by the issuer under `typ`.
async fn issue(credential: &CredentialV2, typ: &str) -> Jwt {
    let issuer = issuer();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(typ)
        .with_kid(issuer.kid.as_str());
    Jwt::sign(&header, &credential.to_jwt_claims(), &issuer.signer)
        .await
        .unwrap()
}

/// A presentation by the holder of `credentials`, its claims for the verifier's audience and
/// nonce, valid in 2024 and 2025.
fn presentation(credentials: impl IntoIterator<Item = EnvelopedVc>) -> PresentationV2 {
    let holder = holder();
    credentials.into_iter().fold(
        PresentationV2::new()
            .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap())
            .with_holder(&holder.did),
        PresentationV2::with_credential,
    )
}

fn claims(presentation: &PresentationV2) -> JwtClaims {
    presentation
        .to_jwt_claims()
        .with_aud(AUDIENCE)
        .with_claim("nonce", NONCE)
        .with_iat(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap())
        .with_exp(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
}

/// `claims` signed by the holder, under `typ` when given, naming `kid` (the holder's own by
/// default).
async fn present(claims: &JwtClaims, typ: Option<&str>, kid: Option<&DidUrl>) -> Jwt {
    let holder = holder();
    let mut header =
        JwsHeader::new(JwsAlgorithm::ES256).with_kid(kid.unwrap_or(&holder.kid).as_str());
    if let Some(typ) = typ {
        header = header.with_typ(typ);
    }
    Jwt::sign(&header, claims, &holder.signer).await.unwrap()
}

async fn valid_presentation() -> (PresentationV2, CredentialV2, Jwt) {
    let issuer = issuer();
    let holder = holder();
    let credential = credential(&issuer, &holder.did);
    let enveloped = EnvelopedVc::from_jwt(&issue(&credential, CredentialV2::JWT_TYP).await);
    let presentation = presentation([enveloped]);
    let jwt = present(&claims(&presentation), Some(PresentationV2::JWT_TYP), None).await;
    (presentation, credential, jwt)
}

#[tokio::test]
async fn presentation_validates() {
    let (presentation, credential, jwt) = valid_presentation().await;
    let holder = holder();
    let decoded: DecodedPresentationV2 = validator().validate_v2(&jwt, &options()).await.unwrap();
    // The payload is the presentation, so the `nonce` claim reads back as one of its
    // properties.
    assert_eq!(
        decoded.presentation,
        presentation.clone().with_property("nonce", NONCE)
    );
    assert_eq!(decoded.header.typ.as_deref(), Some("vp+jwt"));
    assert_eq!(decoded.holder(), Some(&Uri::from(holder.did.clone())));
    assert_eq!(
        decoded
            .claims
            .aud
            .as_ref()
            .map(identity_kit::did::OneOrMany::len),
        Some(1)
    );
    let [validated] = decoded.credentials.as_slice() else {
        panic!("one credential");
    };
    assert_eq!(*validated.credential(), credential);
    assert_eq!(validated.header().typ.as_deref(), Some("vc+jwt"));

    // Decoding without validating gives the same.
    let unverified = decode_presentation_v2(&jwt).unwrap();
    assert_eq!(unverified.presentation, decoded.presentation);
    assert_eq!(*unverified.credentials[0].credential(), credential);

    // The VCDM 1.1 decoder and validator refuse the 2.0 profile by its `typ`.
    assert!(matches!(
        decode_presentation(&jwt),
        Err(ValidationError::UnexpectedTyp { expected: "JWT", found }) if found == "vp+jwt"
    ));
    let error = validator().validate(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::UnexpectedTyp {
            expected: "JWT",
            ..
        }
    ));
}

#[tokio::test]
async fn holder_from_iss_and_untyped() {
    let (_, credential, _) = valid_presentation().await;
    let holder = holder();
    let enveloped = EnvelopedVc::from_jwt(&issue(&credential, CredentialV2::JWT_TYP).await);
    let mut presentation = presentation([enveloped]);
    presentation.holder = None;
    let mut claims = claims(&presentation);
    claims.iss = Some(holder.did.to_string());
    // No `typ` at all is accepted too.
    let jwt = present(&claims, None, None).await;
    let decoded = validator().validate_v2(&jwt, &options()).await.unwrap();
    assert_eq!(decoded.holder(), Some(&Uri::from(holder.did)));
}

#[tokio::test]
async fn presentation_typ_selects_the_profile() {
    let (presentation, _, _) = valid_presentation().await;
    let error = validator()
        .validate_v2(
            &present(&claims(&presentation), Some("JWT"), None).await,
            &options(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::UnexpectedTyp { expected: "vp+jwt", found } if found == "JWT"
    ));
    // Accepted when the caller adds it.
    let lenient = options().with_additional_typ("JWT");
    validator()
        .validate_v2(
            &present(&claims(&presentation), Some("JWT"), None).await,
            &lenient,
        )
        .await
        .unwrap();

    // A VCDM 1.1 presentation typed `vp+jwt` is refused by the 1.1 validator, and one typed
    // `JWT` by the 2.0 validator.
    let holder = holder();
    let v1 = Presentation::new()
        .with_holder(&holder.did)
        .to_jwt_claims()
        .unwrap()
        .with_aud(AUDIENCE)
        .with_claim("nonce", NONCE);
    let error = validator()
        .validate(&present(&v1, Some("vp+jwt"), None).await, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::UnexpectedTyp {
            expected: "JWT",
            ..
        }
    ));
    let error = validator()
        .validate_v2(&present(&v1, Some("JWT"), None).await, &options())
        .await
        .unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::UnexpectedTyp { .. }
    ));
}

#[tokio::test]
async fn presentation_errors() {
    let (presentation, _, _) = valid_presentation().await;
    let typ = Some(PresentationV2::JWT_TYP);
    let check = |jwt: Jwt, options: PresentationValidationOptions| async move {
        presentation_error(validator().validate_v2(&jwt, &options).await.unwrap_err())
    };

    // A `vp` claim marks the VCDM 1.1 profile and is refused in a 2.0 payload.
    let mut with_vp = claims(&presentation);
    with_vp.additional.insert("vp".to_owned(), json!({}));
    assert!(matches!(
        check(present(&with_vp, typ, None).await, options()).await,
        ValidationError::Credential(CredentialError::InvalidClaim { claim: "vp", .. })
    ));

    // `iss` must agree with `holder`.
    let mut other_iss = claims(&presentation);
    other_iss.iss = Some("did:example:other".to_owned());
    assert!(matches!(
        check(present(&other_iss, typ, None).await, options()).await,
        ValidationError::Credential(_)
    ));

    // The first `@context` must be the VCDM 2.0 base context, and `type` must include
    // `VerifiablePresentation`.
    let mut v1_context = claims(&presentation);
    v1_context.additional.insert(
        "@context".to_owned(),
        json!(["https://www.w3.org/2018/credentials/v1"]),
    );
    let mut other_type = claims(&presentation);
    other_type
        .additional
        .insert("type".to_owned(), json!(["VerifiableCredential"]));
    for payload in [v1_context, other_type] {
        assert!(matches!(
            check(present(&payload, typ, None).await, options()).await,
            ValidationError::Credential(CredentialError::InvalidClaim {
                claim: "@context",
                ..
            })
        ));
        assert!(decode_presentation_v2(&present(&payload, typ, None).await).is_err());
    }

    // A holder is required.
    let mut anonymous = presentation.clone();
    anonymous.holder = None;
    assert!(matches!(
        check(present(&claims(&anonymous), typ, None).await, options()).await,
        ValidationError::Credential(CredentialError::MissingClaim("holder"))
    ));

    // The holder must be the DID of `kid`: here the issuer's key names the presentation.
    let issuer = issuer();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("vp+jwt")
        .with_kid(issuer.kid.as_str());
    let signed_by_issuer = Jwt::sign(&header, &claims(&presentation), &issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        check(signed_by_issuer, options()).await,
        ValidationError::HolderMismatch { key, .. } if *key == KeyReference::DidUrl(issuer.kid.clone())
    ));

    // Expired, and the audience and nonce of another exchange.
    let late = options().with_time(TimeOptions::at(
        Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap(),
    ));
    let jwt = present(&claims(&presentation), typ, None).await;
    assert!(matches!(
        check(jwt.clone(), late).await,
        ValidationError::Expired { .. }
    ));
    let mut other_audience = options();
    other_audience.audience = Some("did:example:someone-else".to_owned());
    assert!(matches!(
        check(jwt.clone(), other_audience).await,
        ValidationError::AudienceMismatch { .. }
    ));
    let mut other_nonce = options();
    other_nonce.nonce = Some("another".to_owned());
    assert!(matches!(
        check(jwt, other_nonce).await,
        ValidationError::NonceMismatch { found: Some(found), .. } if found == NONCE
    ));
}

#[tokio::test]
async fn holder_key_must_be_under_authentication() {
    let (_, _, jwt) = valid_presentation().await;
    let assertion_method_only = RefusingRole {
        inner: resolver(),
        role: KeyRole::Subject,
    };
    let validator = JwtPresentationValidator::new(assertion_method_only, DefaultVerifier);
    let error = validator.validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        presentation_error(error),
        ValidationError::KeyResolution { .. }
    ));
}

#[tokio::test]
async fn credential_errors_are_reported_by_index() {
    let issuer = issuer();
    let holder = holder();
    let stranger = Did::parse("did:example:stranger").unwrap();
    let good = EnvelopedVc::from_jwt(&issue(&credential(&issuer, &holder.did), "vc+jwt").await);
    // (An SD-JWT envelope is unwrapped with the `sd-jwt` feature; `tests/sd_jwt_v2.rs` covers
    // it. A COSE one is never.)
    let cose = EnvelopedVc::new("application/vc+cose;base64", "0oRDoQEmoQRYIA").unwrap();
    let v1_typed = EnvelopedVc::from_jwt(&issue(&credential(&issuer, &holder.did), "JWT").await);
    let not_holders =
        EnvelopedVc::from_jwt(&issue(&credential(&issuer, &stranger), "vc+jwt").await);
    let presentation = presentation([good, cose, v1_typed, not_holders]);
    let jwt = present(&claims(&presentation), Some("vp+jwt"), None).await;

    // The first failure stops validation by default.
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        credential_errors(error).as_slice(),
        [(1, ValidationError::Credential(CredentialError::UnsupportedMediaType { media_type, .. }))]
            if media_type == "application/vc+cose;base64"
    ));

    let all = options().with_fail_fast(FailFast::AllErrors);
    let errors = credential_errors(validator().validate_v2(&jwt, &all).await.unwrap_err());
    assert_eq!(errors.len(), 3);
    assert!(matches!(
        &errors[1],
        (2, ValidationError::UnexpectedTyp { expected: "vc+jwt", found }) if found == "JWT"
    ));
    assert!(matches!(
        &errors[2],
        (3, ValidationError::SubjectHolderMismatch { holder: found, .. })
            if *found == Uri::from(holder.did.clone())
    ));

    // `Any` drops the subject check; the other two still fail.
    let any = all
        .clone()
        .with_subject_holder(SubjectHolderRelationship::Any);
    let indices: Vec<usize> =
        credential_errors(validator().validate_v2(&jwt, &any).await.unwrap_err())
            .into_iter()
            .map(|(index, _)| index)
            .collect();
    assert_eq!(indices, [1, 2]);
}

#[tokio::test]
async fn non_transferable_credentials_must_name_the_holder() {
    let issuer = issuer();
    let stranger = Did::parse("did:example:stranger").unwrap();
    let transferable = credential(&issuer, &stranger);
    let non_transferable = transferable.clone().with_property("nonTransferable", true);
    let options = options()
        .with_subject_holder(SubjectHolderRelationship::SubjectOnNonTransferable)
        .with_fail_fast(FailFast::AllErrors);

    let jwt = present(
        &claims(&presentation([
            EnvelopedVc::from_jwt(&issue(&transferable, "vc+jwt").await),
            EnvelopedVc::from_jwt(&issue(&non_transferable, "vc+jwt").await),
        ])),
        Some("vp+jwt"),
        None,
    )
    .await;
    let errors = credential_errors(validator().validate_v2(&jwt, &options).await.unwrap_err());
    assert!(matches!(
        errors.as_slice(),
        [(1, ValidationError::SubjectHolderMismatch { .. })]
    ));
}

#[tokio::test]
async fn tampered_credential_fails_alone() {
    let (presentation, _, _) = valid_presentation().await;
    let enveloped = &presentation.verifiable_credential[0];
    let credential = enveloped.to_jwt().unwrap();
    let mut parts: Vec<&str> = credential.as_str().split('.').collect();
    let forged = common::encode(b"forged signature, 64 bytes long, which no key ever produced!!!");
    parts[2] = &forged;
    let tampered = EnvelopedVc::from_jwt(&parts.join(".").parse().unwrap());
    let mut forged_presentation = presentation.clone();
    forged_presentation.verifiable_credential = vec![tampered];
    let jwt = present(&claims(&forged_presentation), Some("vp+jwt"), None).await;
    let error = validator().validate_v2(&jwt, &options()).await.unwrap_err();
    assert!(matches!(
        credential_errors(error).as_slice(),
        [(0, ValidationError::Signature(_))]
    ));
}
