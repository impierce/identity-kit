//! The validators over real DID methods: a `did:key` issuer (the Ed25519 key of RFC 8037
//! Appendix A.1) signs credentials shaped like VCDM 1.1 Example 31 for a `did:jwk` holder (the
//! P-256 key of RFC 7515 Appendix A.3), who presents them. Every negative case the issue
//! lists: expired, not yet valid, wrong audience, wrong holder, unresolvable `kid`, and more.
#![cfg(all(feature = "vc", feature = "did-key", feature = "did-jwk"))]

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{Did, DidUrl, Uri, VerificationRelationship};
use identity_kit::jose::{
    DefaultVerifier, Jwk, JwsAlgorithm, JwsError, JwsHeader, SignError, Signer, VerificationError,
};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{
    CredentialValidationOptions, FailFast, JwtCredentialValidator, JwtPresentationValidator,
    KeyResolutionError, KeyResolver, PresentationValidationError, PresentationValidationOptions,
    StatusCheck, StatusError, StatusPolicy, SubjectHolderRelationship, TimeOptions,
    ValidationError, extract_holder, extract_issuer,
};
use identity_kit::vc::{
    Credential, CredentialError, CredentialV2, Jwt, JwtClaims, Presentation, Subject, TypedObject,
};
use serde_json::json;

// ---------------------------------------------------------------------------------------------
// Keys and signers
// ---------------------------------------------------------------------------------------------

/// RFC 8037 Appendix A.1: the issuer's Ed25519 key.
const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8037_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

/// RFC 7515 Appendix A.3: the holder's P-256 key.
const RFC7515_A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const RFC7515_A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
const RFC7515_A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

/// VCDM 1.1 Example 31's `nbf` and `exp`, and a validation time in between.
const NBF: i64 = 1541493724;
const EXP: i64 = 1573029723;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2019, 1, 1, 0, 0, 0).unwrap()
}

fn at(now: DateTime<Utc>) -> CredentialValidationOptions {
    CredentialValidationOptions::new().with_time(TimeOptions::at(now))
}

fn decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

struct Ed25519Signer(ed25519_dalek::SigningKey);

#[async_trait::async_trait]
impl Signer for Ed25519Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::EdDSA
    }

    fn kid(&self) -> Option<&str> {
        None
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(signing_input).to_bytes().to_vec())
    }
}

struct Es256Signer(p256::ecdsa::SigningKey);

#[async_trait::async_trait]
impl Signer for Es256Signer {
    fn alg(&self) -> JwsAlgorithm {
        JwsAlgorithm::ES256
    }

    fn kid(&self) -> Option<&str> {
        None
    }

    async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.0.sign(signing_input);
        Ok(signature.to_bytes().to_vec())
    }
}

/// The issuer: `did:key` of the RFC 8037 key, with its one verification method.
struct Issuer {
    did: Did,
    kid: DidUrl,
    signer: Ed25519Signer,
}

fn issuer() -> Issuer {
    let d: [u8; 32] = decode(RFC8037_D).try_into().unwrap();
    let signer = Ed25519Signer(ed25519_dalek::SigningKey::from_bytes(&d));
    let jwk = Jwk::from_ed25519_public(&decode(RFC8037_X)).unwrap();
    assert_eq!(signer.0.verifying_key().as_bytes(), &decode(RFC8037_X)[..]);
    let did = DidKey::did(&jwk).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    Issuer { did, kid, signer }
}

/// The holder: `did:jwk` of the RFC 7515 A.3 key, whose verification method is `#0`.
struct Holder {
    did: Did,
    kid: DidUrl,
    signer: Es256Signer,
}

fn holder() -> Holder {
    let signer = Es256Signer(p256::ecdsa::SigningKey::from_slice(&decode(RFC7515_A3_D)).unwrap());
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256", "x": RFC7515_A3_X, "y": RFC7515_A3_Y
    }))
    .unwrap();
    let did = DidJwk::did(&jwk).unwrap();
    let kid = did.join("#0").unwrap();
    Holder { did, kid, signer }
}

fn resolver() -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build()
}

fn credential_validator() -> JwtCredentialValidator<Resolver> {
    JwtCredentialValidator::new(resolver(), DefaultVerifier)
}

fn presentation_validator() -> JwtPresentationValidator<Resolver> {
    JwtPresentationValidator::new(resolver(), DefaultVerifier)
}

/// VCDM 1.1 Example 31's credential, issued by `issuer` to `subject`.
fn credential(issuer: &Did, subject: &Did) -> Credential {
    Credential::new(
        issuer,
        JwtClaims::timestamp(NBF).unwrap(),
        Subject::new(subject).with_property(
            "degree",
            json!({ "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }),
        ),
    )
    .with_context("https://www.w3.org/2018/credentials/examples/v1")
    .with_id(Uri::parse("http://example.edu/credentials/3732").unwrap())
    .with_type("UniversityDegreeCredential")
    .with_expiration_date(JwtClaims::timestamp(EXP).unwrap())
}

/// `jwt` with a claim added to its payload and its signature left as it was.
fn tamper(jwt: &Jwt) -> Jwt {
    let jws = jwt.decode().unwrap();
    let mut claims: JwtClaims = serde_json::from_slice(jws.payload()).unwrap();
    claims
        .additional
        .insert("nonce".to_owned(), json!("tampered"));
    let mut parts = jwt.as_str().split('.');
    let header = parts.next().unwrap();
    let signature = parts.nth(1).unwrap();
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    Jwt::new(format!("{header}.{payload}.{signature}")).unwrap()
}

fn header(alg: JwsAlgorithm, kid: &DidUrl) -> JwsHeader {
    JwsHeader::new(alg).with_typ("JWT").with_kid(kid.as_str())
}

/// `credential` signed by `issuer`, with `edit` applied to the claims first.
async fn issue(issuer: &Issuer, credential: &Credential, edit: impl FnOnce(&mut JwtClaims)) -> Jwt {
    let mut claims = credential.to_jwt_claims().unwrap();
    edit(&mut claims);
    Jwt::sign(
        &header(JwsAlgorithm::EdDSA, &issuer.kid),
        &claims,
        &issuer.signer,
    )
    .await
    .unwrap()
}

/// A presentation of `credentials` signed by `holder` for the audience of VCDM 1.1 Example 33.
async fn present(holder: &Holder, credentials: Vec<Jwt>, edit: impl FnOnce(&mut JwtClaims)) -> Jwt {
    let mut presentation = Presentation::new()
        .with_id(Uri::parse("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5").unwrap())
        .with_holder(&holder.did);
    presentation.verifiable_credential = credentials;
    let mut claims = presentation
        .to_jwt_claims()
        .unwrap()
        .with_aud("did:example:4a57546973436f6f6c4a4a57573")
        .with_nbf(JwtClaims::timestamp(NBF).unwrap())
        .with_exp(JwtClaims::timestamp(EXP).unwrap())
        .with_claim("nonce", "343s$FSFDa-");
    edit(&mut claims);
    Jwt::sign(
        &header(JwsAlgorithm::ES256, &holder.kid),
        &claims,
        &holder.signer,
    )
    .await
    .unwrap()
}

fn presentation_options() -> PresentationValidationOptions {
    PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_audience("did:example:4a57546973436f6f6c4a4a57573")
        .with_nonce("343s$FSFDa-")
        .with_credentials(at(now()))
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn credential_validates() {
    let (issuer, holder) = (issuer(), holder());
    let credential = credential(&issuer.did, &holder.did);
    let jwt = issue(&issuer, &credential, |claims| {
        claims
            .additional
            .insert("nonce".to_owned(), json!("660!6345FSer"));
    })
    .await;

    let validator = credential_validator();
    let decoded = validator.validate(&jwt, &at(now())).await.unwrap();
    assert_eq!(decoded.credential, credential);
    assert_eq!(decoded.header.kid.as_deref(), Some(issuer.kid.as_str()));
    assert_eq!(decoded.claims.additional["nonce"], "660!6345FSer");
    assert_eq!(decoded.claims.iss.as_deref(), Some(issuer.did.as_str()));
    assert_eq!(decoded.claims.sub.as_deref(), Some(holder.did.as_str()));
    assert_eq!(decoded.claims.nbf, Some(NBF));
    assert_eq!(decoded.claims.exp, Some(EXP));
    assert_eq!(extract_issuer(&jwt).unwrap(), issuer.did);

    assert!(!validator.has_status_check());
    assert!(validator.resolver().supports("key"));
    assert_eq!(validator.verifier(), &DefaultVerifier);
    assert!(format!("{validator:?}").starts_with("JwtCredentialValidator"));
}

#[tokio::test]
async fn validity_period_and_leeway() {
    let (issuer, holder) = (issuer(), holder());
    let credential = credential(&issuer.did, &holder.did);
    let jwt = issue(&issuer, &credential, |_| {}).await;
    let validator = credential_validator();
    let exp = JwtClaims::timestamp(EXP).unwrap();
    let nbf = JwtClaims::timestamp(NBF).unwrap();

    // At `exp` the credential has expired; a second earlier it has not.
    assert!(matches!(
        validator.validate(&jwt, &at(exp)).await,
        Err(ValidationError::Expired { expired_at, now }) if expired_at == exp && now == exp
    ));
    assert!(
        validator
            .validate(&jwt, &at(exp - Duration::from_secs(1)))
            .await
            .is_ok()
    );
    // Before `nbf` it is not valid yet; at `nbf` it is.
    let early = nbf - Duration::from_secs(1);
    assert!(matches!(
        validator.validate(&jwt, &at(early)).await,
        Err(ValidationError::NotYetValid { not_before, now }) if not_before == nbf && now == early
    ));
    assert!(validator.validate(&jwt, &at(nbf)).await.is_ok());
    // Leeway covers clock skew in both directions.
    let leeway = |now: DateTime<Utc>| {
        at(now).with_time(TimeOptions::at(now).with_leeway(Duration::from_secs(60)))
    };
    assert!(validator.validate(&jwt, &leeway(early)).await.is_ok());
    // A leeway past the range `chrono` represents saturates instead of overflowing.
    let unbounded = at(early).with_time(TimeOptions::at(early).with_leeway(Duration::MAX));
    assert!(validator.validate(&jwt, &unbounded).await.is_ok());
    assert!(
        validator
            .validate(&jwt, &leeway(exp + Duration::from_secs(59)))
            .await
            .is_ok()
    );
    assert!(matches!(
        validator
            .validate(&jwt, &leeway(exp + Duration::from_secs(60)))
            .await,
        Err(ValidationError::Expired { .. })
    ));

    // `iat` in the future is rejected, within the leeway accepted.
    let future = issue(&issuer, &credential, |claims| {
        claims.iat = Some(JwtClaims::numeric_date(now() + Duration::from_secs(30)));
    })
    .await;
    assert!(matches!(
        validator.validate(&future, &at(now())).await,
        Err(ValidationError::IssuedInFuture { .. })
    ));
    assert!(validator.validate(&future, &leeway(now())).await.is_ok());

    // Without `nbf` and `exp`, the credential's own dates are checked.
    let dates_in_vc = issue(&issuer, &credential, |claims| {
        claims.nbf = None;
        claims.exp = None;
        claims.additional["vc"]["issuanceDate"] = json!("2018-11-06T08:42:04Z");
        claims.additional["vc"]["expirationDate"] = json!("2019-11-06T08:42:03Z");
    })
    .await;
    assert!(validator.validate(&dates_in_vc, &at(now())).await.is_ok());
    assert!(matches!(
        validator.validate(&dates_in_vc, &at(early)).await,
        Err(ValidationError::NotYetValid { .. })
    ));
    assert!(matches!(
        validator.validate(&dates_in_vc, &at(exp)).await,
        Err(ValidationError::Expired { .. })
    ));

    // The default options validate now.
    assert!(matches!(
        validator
            .validate(&jwt, &CredentialValidationOptions::default())
            .await,
        Err(ValidationError::Expired { .. })
    ));
}

#[tokio::test]
async fn signature_and_key_errors() {
    let (issuer, holder) = (issuer(), holder());
    let credential = credential(&issuer.did, &holder.did);
    let claims = credential.to_jwt_claims().unwrap();
    let validator = credential_validator();
    let sign = |header: JwsHeader| {
        let claims = claims.clone();
        let signer = &issuer.signer;
        async move { Jwt::sign(&header, &claims, signer).await.unwrap() }
    };

    // A payload changed after signing does not verify.
    let tampered = tamper(&sign(header(JwsAlgorithm::EdDSA, &issuer.kid)).await);
    assert!(matches!(
        validator.validate(&tampered, &at(now())).await,
        Err(ValidationError::Signature(
            VerificationError::InvalidSignature
        ))
    ));
    // Signed by the wrong key: the holder's P-256 key under the issuer's Ed25519 `kid`.
    let forged = Jwt::sign(
        &JwsHeader::new(JwsAlgorithm::ES256).with_kid(issuer.kid.as_str()),
        &claims,
        &holder.signer,
    )
    .await
    .unwrap();
    let error = validator.validate(&forged, &at(now())).await.unwrap_err();
    assert!(matches!(
        &error,
        ValidationError::Signature(VerificationError::Key(_))
    ));
    assert!(
        error
            .to_string()
            .starts_with("signature: expected P-256 key")
    );

    // No `kid`, a `kid` that is not a DID URL, and a `kid` that does not resolve.
    assert!(matches!(
        validator
            .validate(&sign(JwsHeader::new(JwsAlgorithm::EdDSA)).await, &at(now()))
            .await,
        Err(ValidationError::MissingKid)
    ));
    let error = validator
        .validate(
            &sign(JwsHeader::new(JwsAlgorithm::EdDSA).with_kid("https://example.edu/keys/1")).await,
            &at(now()),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&error, ValidationError::InvalidKid { kid, .. } if kid == "https://example.edu/keys/1")
    );
    assert!(
        error
            .to_string()
            .starts_with("`kid` \"https://example.edu/keys/1\" is not a DID URL")
    );

    let unresolvable = sign(
        JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_kid("did:example:abfe13f712120431c276e12ecab#keys-1"),
    )
    .await;
    let error = validator
        .validate(&unresolvable, &at(now()))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "resolving key `did:example:abfe13f712120431c276e12ecab#keys-1`: resolving `did:example:abfe13f712120431c276e12ecab`: DID method not supported: no resolver is registered for `did:example`"
    );
    let missing_method = sign(
        JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(issuer.did.join("#keys-1").unwrap().as_str()),
    )
    .await;
    assert!(matches!(
        validator.validate(&missing_method, &at(now())).await,
        Err(ValidationError::KeyResolution { kid, .. }) if kid.fragment() == Some("keys-1")
    ));

    // A `kid` with DID parameters could select an old document version that still lists a
    // retired key; only `did:…#fragment` keys are accepted (a path is refused the same way).
    let versioned = DidUrl::parse(&format!(
        "{}?versionId=1#{}",
        issuer.did,
        issuer.kid.fragment().unwrap()
    ))
    .unwrap();
    assert!(matches!(
        validator
            .validate(&sign(header(JwsAlgorithm::EdDSA, &versioned)).await, &at(now()))
            .await,
        Err(ValidationError::KidWithParameters(kid)) if kid == versioned
    ));

    // A registered claim under `additional` would put the member in the payload twice.
    assert!(matches!(
        Jwt::sign(
            &header(JwsAlgorithm::EdDSA, &issuer.kid),
            &claims.clone().with_claim("exp", EXP),
            &issuer.signer,
        )
        .await,
        Err(JwsError::InvalidPayload(reason)) if reason.contains("`exp`")
    ));

    // A token that is not a credential at all.
    let not_vc = Jwt::sign(
        &header(JwsAlgorithm::EdDSA, &issuer.kid),
        &JwtClaims::new().with_sub("x"),
        &issuer.signer,
    )
    .await
    .unwrap();
    assert_eq!(
        validator
            .validate(&not_vc, &at(now()))
            .await
            .unwrap_err()
            .to_string(),
        "JWT claim `vc` is missing"
    );
}

#[tokio::test]
async fn issuer_must_control_the_signing_key() {
    let (issuer, holder) = (issuer(), holder());
    let validator = credential_validator();

    // The holder claims to be the issuer, but the issuer's key signed.
    let claimed = credential(&holder.did, &holder.did);
    let jwt = issue(&issuer, &claimed, |_| {}).await;
    assert!(matches!(
        validator.validate(&jwt, &at(now())).await,
        Err(ValidationError::IssuerMismatch { issuer: id, kid })
            if id.as_str() == holder.did.as_str() && kid == issuer.kid
    ));

    // An issuer that is not a DID has no resolvable key.
    let https = credential(&issuer.did, &holder.did);
    let jwt = issue(&issuer, &https, |claims| {
        claims.iss = Some("https://example.edu/issuers/565049".to_owned());
    })
    .await;
    let error = validator.validate(&jwt, &at(now())).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "issuer `https://example.edu/issuers/565049` is not a DID"
    );
    assert!(matches!(
        extract_issuer(&jwt),
        Err(ValidationError::NotDid { role: "issuer", .. })
    ));
}

#[tokio::test]
async fn key_must_be_usable_for_the_relationship() {
    // A `did:jwk` whose key has `use: enc` lists it under `keyAgreement` only, so it cannot
    // have signed a credential (`assertionMethod`) or a presentation (`authentication`).
    let issuer = issuer();
    let enc: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "use": "enc"
    }))
    .unwrap();
    let did = DidJwk::did(&enc).unwrap();
    let kid = did.join("#0").unwrap();
    let credential = credential(&did, &holder().did);
    let jwt = Jwt::sign(
        &header(JwsAlgorithm::EdDSA, &kid),
        &credential.to_jwt_claims().unwrap(),
        &issuer.signer,
    )
    .await
    .unwrap();
    let error = credential_validator()
        .validate(&jwt, &at(now()))
        .await
        .unwrap_err();
    assert!(matches!(&error, ValidationError::KeyResolution { kid: k, .. } if *k == kid));
    assert!(
        error
            .to_string()
            .ends_with("is not listed under `assertionMethod`")
    );

    // The resolver's `KeyResolver` implementation is `resolve_public_key` with the relationship.
    let resolver = resolver();
    assert!(
        resolver
            .resolve_key(&kid, VerificationRelationship::KeyAgreement)
            .await
            .is_ok()
    );
    assert!(
        resolver
            .resolve_key(&kid, VerificationRelationship::Authentication)
            .await
            .is_err()
    );
}

/// A status check that knows one status type.
struct Checker;

#[async_trait::async_trait]
impl StatusCheck for Checker {
    async fn check(&self, status: &TypedObject) -> Result<(), StatusError> {
        match status.object_type() {
            "CredentialStatusList2017" => match status.properties.get("revoked") {
                Some(serde_json::Value::Bool(true)) => {
                    Err(StatusError::Invalid("revoked".to_owned()))
                }
                _ => Ok(()),
            },
            "Unavailable" => Err(StatusError::Unavailable(
                "list could not be fetched".to_owned(),
            )),
            other => Err(StatusError::Unsupported(other.to_owned())),
        }
    }
}

#[tokio::test]
async fn status_policies() {
    let (issuer, holder) = (issuer(), holder());
    let with_status =
        |status: TypedObject| credential(&issuer.did, &holder.did).with_status(status);
    let list = TypedObject::new("CredentialStatusList2017")
        .with_id(Uri::parse("https://example.edu/status/24").unwrap());
    let revoked = list.clone().with_property("revoked", true);
    let unknown = TypedObject::new("BitstringStatusListEntry");
    let unavailable = TypedObject::new("Unavailable");
    let good = issue(&issuer, &with_status(list), |_| {}).await;
    let revoked = issue(&issuer, &with_status(revoked), |_| {}).await;
    let unknown = issue(&issuer, &with_status(unknown), |_| {}).await;
    let unavailable = issue(&issuer, &with_status(unavailable), |_| {}).await;
    let options = |policy| at(now()).with_status(policy);

    // Without a check, a status can only be skipped.
    let validator = credential_validator();
    assert!(matches!(
        validator.validate(&good, &options(StatusPolicy::Strict)).await,
        Err(ValidationError::StatusUnchecked(status_type)) if status_type == "CredentialStatusList2017"
    ));
    assert!(
        validator
            .validate(&good, &options(StatusPolicy::SkipUnsupported))
            .await
            .is_ok()
    );
    assert!(
        validator
            .validate(&revoked, &options(StatusPolicy::SkipAll))
            .await
            .is_ok()
    );

    // With one, its verdict counts; unsupported types follow the policy; a failure to check
    // is never skipped.
    let validator = credential_validator().with_status_check(Checker);
    assert!(validator.has_status_check());
    assert!(
        validator
            .validate(&good, &options(StatusPolicy::Strict))
            .await
            .is_ok()
    );
    let error = validator
        .validate(&revoked, &options(StatusPolicy::Strict))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, ValidationError::Status(StatusError::Invalid(reason)) if reason == "revoked")
    );
    assert_eq!(
        error.to_string(),
        "credential status: credential is revoked"
    );
    assert!(matches!(
        validator
            .validate(&revoked, &options(StatusPolicy::SkipUnsupported))
            .await,
        Err(ValidationError::Status(StatusError::Invalid(_)))
    ));
    assert!(
        validator
            .validate(&revoked, &options(StatusPolicy::SkipAll))
            .await
            .is_ok()
    );
    assert!(matches!(
        validator.validate(&unknown, &options(StatusPolicy::Strict)).await,
        Err(ValidationError::StatusUnchecked(status_type)) if status_type == "BitstringStatusListEntry"
    ));
    assert!(
        validator
            .validate(&unknown, &options(StatusPolicy::SkipUnsupported))
            .await
            .is_ok()
    );
    assert!(matches!(
        validator
            .validate(&unavailable, &options(StatusPolicy::SkipUnsupported))
            .await,
        Err(ValidationError::Status(StatusError::Unavailable(_)))
    ));
}

#[tokio::test]
async fn v2_credential_validates() {
    let (issuer, holder) = (issuer(), holder());
    let credential = CredentialV2::new(
        &issuer.did,
        Subject::new(&holder.did)
            .with_property("degree", json!({ "type": "ExampleBachelorDegree" })),
    )
    .with_context("https://www.w3.org/ns/credentials/examples/v2")
    .with_id(Uri::parse("http://university.example/credentials/3732").unwrap())
    .with_type("ExampleDegreeCredential")
    .with_valid_from(Utc.with_ymd_and_hms(2010, 1, 1, 19, 23, 24).unwrap())
    .with_valid_until(Utc.with_ymd_and_hms(2020, 1, 1, 19, 23, 24).unwrap());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(CredentialV2::JWT_TYP)
        .with_kid(issuer.kid.as_str());
    let sign = |claims: JwtClaims| {
        let header = header.clone();
        let signer = &issuer.signer;
        async move { Jwt::sign(&header, &claims, signer).await.unwrap() }
    };
    let validator = credential_validator();

    // VC-JOSE-COSE: the payload is the credential; `iss` and `iat` may accompany it.
    let jwt = sign(credential.to_jwt_claims().with_iat(now())).await;
    let decoded = validator.validate_v2(&jwt, &at(now())).await.unwrap();
    assert_eq!(decoded.credential, credential);
    assert_eq!(decoded.header.typ.as_deref(), Some("vc+jwt"));
    assert_eq!(decoded.claims.iat, Some(JwtClaims::numeric_date(now())));
    assert_eq!(extract_issuer(&jwt).unwrap(), issuer.did);
    let mut claims = credential.to_jwt_claims();
    claims.iss = Some(issuer.did.to_string());
    let with_iss = sign(claims).await;
    assert!(validator.validate_v2(&with_iss, &at(now())).await.is_ok());

    // The validity period of the credential, and the registered claims, are checked.
    assert!(matches!(
        validator.validate_v2(&jwt, &at(Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap())).await,
        Err(ValidationError::Expired { expired_at, .. })
            if expired_at == Utc.with_ymd_and_hms(2020, 1, 1, 19, 23, 24).unwrap()
    ));
    assert!(matches!(
        validator
            .validate_v2(
                &with_iss,
                &at(Utc.with_ymd_and_hms(2009, 1, 1, 0, 0, 0).unwrap())
            )
            .await,
        Err(ValidationError::NotYetValid { .. })
    ));
    // The registered claims come first: `iat` after the validation time is reported before
    // `validFrom`.
    assert!(matches!(
        validator
            .validate_v2(
                &jwt,
                &at(Utc.with_ymd_and_hms(2009, 1, 1, 0, 0, 0).unwrap())
            )
            .await,
        Err(ValidationError::IssuedInFuture { .. })
    ));
    let expired_signature = sign(
        credential
            .to_jwt_claims()
            .with_exp(now() - Duration::from_secs(1)),
    )
    .await;
    assert!(matches!(
        validator.validate_v2(&expired_signature, &at(now())).await,
        Err(ValidationError::Expired { .. })
    ));

    // `iss` must agree with `issuer`, and the issuer must control the key.
    let mut claims = credential.to_jwt_claims();
    claims.iss = Some(holder.did.to_string());
    let other_iss = sign(claims).await;
    assert!(matches!(
        validator.validate_v2(&other_iss, &at(now())).await,
        Err(ValidationError::Credential(
            CredentialError::ClaimMismatch {
                claim: "iss",
                property: "issuer"
            }
        ))
    ));
    let other_issuer =
        sign(CredentialV2::new(&holder.did, Subject::new(&holder.did)).to_jwt_claims()).await;
    assert!(matches!(
        validator.validate_v2(&other_issuer, &at(now())).await,
        Err(ValidationError::IssuerMismatch { .. })
    ));

    // `typ` names the profile when present: a 1.1 token (`JWT`), a presentation (`vp+jwt`) or
    // a key binding JWT is never read as a 2.0 credential, and a 2.0 credential is not a 1.1
    // token. Without `typ`, the payload decides.
    let v1 = issue(&issuer, &self::credential(&issuer.did, &holder.did), |_| {}).await;
    assert!(matches!(
        validator.validate_v2(&v1, &at(now())).await,
        Err(ValidationError::UnexpectedTyp { expected: "vc+jwt", found }) if found == "JWT"
    ));
    for typ in ["vp+jwt", "kb+jwt", "VC+JWT"] {
        let typed = Jwt::sign(
            &header.clone().with_typ(typ),
            &credential.to_jwt_claims().with_iat(now()),
            &issuer.signer,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                validator.validate_v2(&typed, &at(now())).await,
                Err(ValidationError::UnexpectedTyp { expected: "vc+jwt", found }) if found == typ
            ),
            "{typ}"
        );
    }
    let untyped = Jwt::sign(
        &JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(issuer.kid.as_str()),
        &credential.to_jwt_claims().with_iat(now()),
        &issuer.signer,
    )
    .await
    .unwrap();
    assert!(validator.validate_v2(&untyped, &at(now())).await.is_ok());
    assert!(matches!(
        validator.validate(&jwt, &at(now())).await,
        Err(ValidationError::UnexpectedTyp { expected: "JWT", found }) if found == "vc+jwt"
    ));
}

// ---------------------------------------------------------------------------------------------
// Presentations
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn presentation_validates() {
    let (issuer, holder) = (issuer(), holder());
    let credential = credential(&issuer.did, &holder.did);
    let jwt = issue(&issuer, &credential, |_| {}).await;
    let vp = present(&holder, vec![jwt.clone()], |_| {}).await;
    assert_eq!(extract_holder(&vp).unwrap(), holder.did);

    let validator = presentation_validator();
    let decoded = validator
        .validate(&vp, &presentation_options())
        .await
        .unwrap();
    assert_eq!(decoded.holder(), Some(&Uri::from(&holder.did)));
    assert_eq!(decoded.presentation.verifiable_credential, [jwt]);
    assert_eq!(decoded.credentials.len(), 1);
    assert_eq!(decoded.credentials[0].credential, credential);
    assert_eq!(decoded.claims.additional["nonce"], "343s$FSFDa-");
    assert_eq!(
        decoded.presentation.id.as_ref().map(Uri::as_str),
        Some("urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")
    );

    // Audience and nonce are only checked when required.
    let lax = PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_credentials(at(now()));
    assert!(validator.validate(&vp, &lax).await.is_ok());
    let no_aud = present(&holder, vec![], |claims| {
        claims.aud = None;
        claims.additional.shift_remove("nonce");
    })
    .await;
    assert!(
        validator
            .validate(&no_aud, &lax)
            .await
            .unwrap()
            .credentials
            .is_empty()
    );
    assert!(format!("{validator:?}").starts_with("JwtPresentationValidator"));
    assert!(!validator.credential_validator().has_status_check());
}

#[tokio::test]
async fn presentation_errors() {
    let (issuer, holder) = (issuer(), holder());
    let jwt = issue(&issuer, &credential(&issuer.did, &holder.did), |_| {}).await;
    let validator = presentation_validator();
    let options = presentation_options();
    let presentation_error = |error: PresentationValidationError| {
        assert!(error.credentials.is_empty());
        *error.presentation.unwrap()
    };

    let wrong_audience = present(&holder, vec![jwt.clone()], |claims| {
        claims.aud = Some(
            vec![
                "did:example:other".to_owned(),
                "did:example:another".to_owned(),
            ]
            .into(),
        );
    })
    .await;
    let error = presentation_error(
        validator
            .validate(&wrong_audience, &options)
            .await
            .unwrap_err(),
    );
    assert!(
        matches!(&error, ValidationError::AudienceMismatch { expected, found: Some(found) }
        if expected == "did:example:4a57546973436f6f6c4a4a57573" && found.len() == 2)
    );
    let no_audience = present(&holder, vec![jwt.clone()], |claims| claims.aud = None).await;
    assert!(matches!(
        presentation_error(
            validator
                .validate(&no_audience, &options)
                .await
                .unwrap_err()
        ),
        ValidationError::AudienceMismatch { found: None, .. }
    ));

    let wrong_nonce = present(&holder, vec![jwt.clone()], |claims| {
        claims.additional["nonce"] = json!("other");
    })
    .await;
    let error = presentation_error(
        validator
            .validate(&wrong_nonce, &options)
            .await
            .unwrap_err(),
    );
    assert_eq!(
        error.to_string(),
        r#"nonce Some("other") is not "343s$FSFDa-""#
    );
    let no_nonce = present(&holder, vec![jwt.clone()], |claims| {
        claims.additional.shift_remove("nonce");
    })
    .await;
    assert!(matches!(
        presentation_error(validator.validate(&no_nonce, &options).await.unwrap_err()),
        ValidationError::NonceMismatch { found: None, .. }
    ));

    // The holder must control the signing key: here the issuer's DID claims the presentation
    // the holder's key signed.
    let wrong_holder = present(&holder, vec![jwt.clone()], |claims| {
        claims.iss = Some(issuer.did.to_string());
    })
    .await;
    let error = presentation_error(
        validator
            .validate(&wrong_holder, &options)
            .await
            .unwrap_err(),
    );
    assert!(
        matches!(&error, ValidationError::HolderMismatch { holder: h, kid }
        if h.as_str() == issuer.did.as_str() && *kid == holder.kid)
    );
    assert!(error.to_string().starts_with("holder `did:key:"));

    // Expired presentation; a presentation without `iss`; a credential-shaped token.
    let expired = present(&holder, vec![jwt.clone()], |claims| {
        claims.exp = Some(JwtClaims::numeric_date(now() - Duration::from_secs(1)));
    })
    .await;
    assert!(matches!(
        presentation_error(validator.validate(&expired, &options).await.unwrap_err()),
        ValidationError::Expired { .. }
    ));
    let anonymous = present(&holder, vec![], |claims| claims.iss = None).await;
    assert!(matches!(
        presentation_error(validator.validate(&anonymous, &options).await.unwrap_err()),
        ValidationError::Credential(CredentialError::MissingClaim("iss"))
    ));
    let error = presentation_error(validator.validate(&jwt, &options).await.unwrap_err());
    assert_eq!(error.to_string(), "JWT claim `vp` is missing");
    // `extract_holder` reads `iss`, whatever the token is.
    assert_eq!(extract_holder(&jwt).unwrap(), issuer.did);
}

#[tokio::test]
async fn subject_holder_relationship() {
    let (issuer, holder) = (issuer(), holder());
    let validator = presentation_validator();
    let other = Did::parse("did:example:c276e12ec21ebfeb1f712ebc6f1").unwrap();
    let about_other = issue(&issuer, &credential(&issuer.did, &other), |_| {}).await;
    let non_transferable = issue(
        &issuer,
        &credential(&issuer.did, &other).with_property("nonTransferable", true),
        |_| {},
    )
    .await;
    let bearer = issue(
        &issuer,
        &Credential::new(
            &issuer.did,
            JwtClaims::timestamp(NBF).unwrap(),
            Subject::default(),
        ),
        |_| {},
    )
    .await;
    let options = |relationship| presentation_options().with_subject_holder(relationship);
    let credential_error = |error: PresentationValidationError, index: usize| {
        assert!(error.presentation.is_none());
        assert_eq!(
            error.credentials.keys().copied().collect::<Vec<_>>(),
            [index]
        );
        error.credentials.into_values().next().unwrap()
    };

    // AlwaysSubject: the holder must be the subject of every credential.
    let vp = present(&holder, vec![about_other.clone()], |_| {}).await;
    let error = credential_error(
        validator
            .validate(&vp, &options(SubjectHolderRelationship::AlwaysSubject))
            .await
            .unwrap_err(),
        0,
    );
    assert!(
        matches!(&error, ValidationError::SubjectHolderMismatch { subject: Some(subject), holder: h }
        if subject.as_str() == other.as_str() && h.as_str() == holder.did.as_str())
    );
    let vp = present(&holder, vec![bearer.clone()], |_| {}).await;
    assert!(matches!(
        credential_error(
            validator
                .validate(&vp, &options(SubjectHolderRelationship::AlwaysSubject))
                .await
                .unwrap_err(),
            0
        ),
        ValidationError::SubjectHolderMismatch { subject: None, .. }
    ));

    // SubjectOnNonTransferable: only credentials marked `nonTransferable` are bound.
    let vp = present(&holder, vec![about_other.clone(), bearer.clone()], |_| {}).await;
    assert!(
        validator
            .validate(
                &vp,
                &options(SubjectHolderRelationship::SubjectOnNonTransferable)
            )
            .await
            .is_ok()
    );
    let vp = present(
        &holder,
        vec![about_other.clone(), non_transferable.clone()],
        |_| {},
    )
    .await;
    assert!(matches!(
        credential_error(
            validator
                .validate(
                    &vp,
                    &options(SubjectHolderRelationship::SubjectOnNonTransferable)
                )
                .await
                .unwrap_err(),
            1
        ),
        ValidationError::SubjectHolderMismatch { .. }
    ));

    // Any: not checked.
    let vp = present(&holder, vec![about_other, non_transferable, bearer], |_| {}).await;
    let decoded = validator
        .validate(&vp, &options(SubjectHolderRelationship::Any))
        .await
        .unwrap();
    assert_eq!(decoded.credentials.len(), 3);
}

#[tokio::test]
async fn fail_fast_collects_or_stops() {
    let (issuer, holder) = (issuer(), holder());
    let validator = presentation_validator();
    let valid = issue(&issuer, &credential(&issuer.did, &holder.did), |_| {}).await;
    let expired = issue(&issuer, &credential(&issuer.did, &holder.did), |claims| {
        claims.exp = Some(JwtClaims::numeric_date(now() - Duration::from_secs(1)));
    })
    .await;
    let forged = tamper(&valid);
    let vp = present(&holder, vec![expired, valid, forged], |_| {}).await;

    let first = validator
        .validate(
            &vp,
            &presentation_options().with_fail_fast(FailFast::FirstError),
        )
        .await
        .unwrap_err();
    assert!(first.presentation.is_none());
    assert_eq!(first.credentials.keys().copied().collect::<Vec<_>>(), [0]);
    assert!(
        first
            .to_string()
            .starts_with("credential 0: expired at 2018-12-31T23:59:59+00:00")
    );

    let all = validator
        .validate(
            &vp,
            &presentation_options().with_fail_fast(FailFast::AllErrors),
        )
        .await
        .unwrap_err();
    assert_eq!(all.credentials.keys().copied().collect::<Vec<_>>(), [0, 2]);
    assert!(matches!(
        all.credentials[&2],
        ValidationError::Signature(VerificationError::InvalidSignature)
    ));
    assert_eq!(
        all.to_string(),
        "credential 0: expired at 2018-12-31T23:59:59+00:00 (now is 2019-01-01T00:00:00+00:00); credential 2: signature: signature verification failed"
    );
    assert_eq!(
        PresentationValidationError::presentation(ValidationError::MissingKid).to_string(),
        "presentation: the JWS header has no `kid`"
    );
}

// ---------------------------------------------------------------------------------------------
// Custom key resolver
// ---------------------------------------------------------------------------------------------

/// Trusted keys by `kid`, with no DID resolution at all.
struct Trusted(HashMap<DidUrl, Jwk>);

#[async_trait::async_trait]
impl KeyResolver for Trusted {
    async fn resolve_key(
        &self,
        url: &DidUrl,
        _: VerificationRelationship,
    ) -> Result<Jwk, KeyResolutionError> {
        self.0
            .get(url)
            .cloned()
            .ok_or_else(|| KeyResolutionError::msg(format!("`{url}` is not a trusted key")))
    }
}

#[tokio::test]
async fn custom_key_resolver() {
    let (issuer, holder) = (issuer(), holder());
    let jwt = issue(&issuer, &credential(&issuer.did, &holder.did), |_| {}).await;
    let issuer_jwk = Jwk::from_ed25519_public(&decode(RFC8037_X)).unwrap();

    let trusted = Trusted(HashMap::from([(issuer.kid.clone(), issuer_jwk)]));
    let validator = JwtCredentialValidator::new(&trusted, DefaultVerifier);
    assert!(validator.validate(&jwt, &at(now())).await.is_ok());

    let validator = JwtCredentialValidator::new(Trusted(HashMap::new()), DefaultVerifier);
    let error = validator.validate(&jwt, &at(now())).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "resolving key `{}`: `{}` is not a trusted key",
            issuer.kid, issuer.kid
        )
    );
    let source = KeyResolutionError::new(std::io::Error::other("offline"));
    assert_eq!(source.to_string(), "offline");
    assert!(source.inner().is::<std::io::Error>());
}
