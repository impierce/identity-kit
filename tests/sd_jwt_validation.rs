//! `SdJwtCredentialValidator` over real DID methods: a `did:key` issuer (the Ed25519 key of
//! RFC 8037 Appendix A.1) issues an SD-JWT VC bound to a holder key (the P-256 key of RFC 7515
//! Appendix A.3), the holder presents with key binding, and every check of RFC 9901 §7 and
//! SD-JWT VC §2.4 is exercised, the Token Status List included.
#![cfg(all(feature = "sd-jwt", feature = "did-key"))]

mod common;

use std::time::Duration;

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::claim_path;
use identity_kit::did::{Did, DidUrl};
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, JwsHeader};
use identity_kit::methods::DidKey;
use identity_kit::resolver::{KeyReference, KeyReferenceError, Resolver};
use identity_kit::sd_jwt_vc::validation::{KeyBindingOptions, SdJwtValidationOptions};
use identity_kit::sd_jwt_vc::{
    Disclosure, HashAlgorithm, KeyBinding, LEGACY_TYP, SdJwt, SdJwtBuilder, SdJwtCredentialV2Error,
    SdJwtCredentialValidator, SdJwtError, SdJwtValidationError, SdJwtVc, SdJwtVcBuilder,
    SdJwtVcError, Status, StatusList, StatusListRef, StatusListToken, StatusType,
};
use identity_kit::vc::validation::{
    CredentialStatus, StatusCheck, StatusError, StatusPolicy, TimeOptions, ValidationError,
};
use identity_kit::vc::{CredentialError, Jwt, JwtClaims};
use serde_json::json;

use common::{Ed25519Signer, Es256Signer, unsigned_jwt};

const VCT: &str = "https://credentials.example.com/identity_credential";
const AUDIENCE: &str = "https://verifier.example.org";
const NONCE: &str = "1234567890";

fn issued_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1683000000, 0).unwrap()
}

fn expires_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1883000000, 0).unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap()
}

/// The issuer: `did:key` of the RFC 8037 key.
struct Issuer {
    did: Did,
    kid: DidUrl,
    signer: Ed25519Signer,
}

fn issuer() -> Issuer {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    Issuer { did, kid, signer }
}

fn holder() -> Es256Signer {
    Es256Signer::rfc7515_a3()
}

fn builder(issuer: &Issuer) -> SdJwtVcBuilder {
    SdJwtVcBuilder::new(VCT)
        .with_issuer(issuer.did.as_str())
        .with_kid(issuer.kid.as_str())
        .with_issued_at(issued_at())
        .with_expires_at(expires_at())
        .with_holder_key(&holder().public_jwk())
        .with_claim("given_name", "John")
        .with_claim("family_name", "Doe")
        .with_claim(
            "address",
            json!({"street_address": "123 Main St", "country": "US"}),
        )
        .with_claim("nationalities", json!(["US", "DE"]))
        .conceal(["given_name"])
        .conceal(["family_name"])
        .conceal(["address"])
        .conceal(["address", "street_address"])
        .conceal(claim_path!["nationalities", ()])
}

async fn issue(issuer: &Issuer) -> SdJwtVc {
    builder(issuer).sign(&issuer.signer).await.unwrap()
}

/// The holder presents `given_name`, `address` and the first nationality with key binding.
async fn present(credential: &SdJwtVc) -> SdJwtVc {
    credential
        .disclose(&[
            claim_path!["given_name"],
            claim_path!["address"],
            claim_path!["nationalities", 0],
        ])
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), &holder())
        .await
        .unwrap()
}

fn validator() -> SdJwtCredentialValidator<Resolver> {
    let resolver = Resolver::builder().with(DidKey::default()).build();
    SdJwtCredentialValidator::new(resolver, DefaultVerifier)
}

fn options() -> SdJwtValidationOptions {
    SdJwtValidationOptions::new().with_time(TimeOptions::at(now()))
}

fn with_key_binding() -> SdJwtValidationOptions {
    options()
        .with_key_binding(KeyBindingOptions::new(AUDIENCE, NONCE).with_time(TimeOptions::at(now())))
}

#[tokio::test]
async fn issued_credential_validates() {
    let issuer = issuer();
    let credential = issue(&issuer).await;
    assert_eq!(credential.header().typ.as_deref(), Some("dc+sd-jwt"));
    assert_eq!(
        credential.header().kid.as_deref(),
        Some(issuer.kid.as_str())
    );
    assert_eq!(credential.sd_jwt().disclosures().len(), 6);
    assert_eq!(
        credential.claims().iss.as_deref(),
        Some(issuer.did.as_str())
    );

    let validated = validator()
        .validate(credential.sd_jwt(), &options())
        .await
        .unwrap();
    assert_eq!(
        validated.issuer_key,
        KeyReference::DidUrl(issuer.kid.clone())
    );
    assert_eq!(validated.key_binding, None);
    assert_eq!(validated.holder_key, None);
    assert_eq!(validated.credential.payload()["given_name"], "John");
    assert_eq!(
        validated.credential.payload()["nationalities"],
        json!(["US", "DE"])
    );

    // Reparsed from the wire, the same.
    let reparsed = SdJwt::parse(&credential.to_string()).unwrap();
    assert_eq!(
        validator()
            .validate(&reparsed, &options())
            .await
            .unwrap()
            .credential,
        credential
    );
}

#[tokio::test]
async fn presentation_with_key_binding_validates() {
    let issuer = issuer();
    let presentation = present(&issue(&issuer).await).await;
    assert!(presentation.sd_jwt().key_binding_jwt().is_some());
    // `address` brings the `street_address` nested in it along.
    assert_eq!(presentation.sd_jwt().disclosures().len(), 4);

    let validated = validator()
        .validate(presentation.sd_jwt(), &with_key_binding())
        .await
        .unwrap();
    let kb = validated.key_binding.unwrap();
    assert_eq!(kb.additional["nonce"], NONCE);
    assert_eq!(
        kb.additional["sd_hash"],
        presentation.sd_jwt().sd_hash(Default::default())
    );
    assert_eq!(validated.credential.payload()["given_name"], "John");
    assert_eq!(
        validated.credential.payload()["nationalities"],
        json!(["US"])
    );
    assert!(!validated.credential.payload().contains_key("family_name"));
    assert_eq!(
        validated.credential.payload()["address"],
        json!({"street_address": "123 Main St", "country": "US"})
    );

    // Without requiring key binding, the key binding JWT is left alone.
    let validated = validator()
        .validate(presentation.sd_jwt(), &options())
        .await
        .unwrap();
    assert_eq!(validated.key_binding, None);

    // A bounded age, and leeway on `iat`.
    let bounded = options().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, NONCE)
            .with_time(TimeOptions::at(now() + chrono::TimeDelta::minutes(5)))
            .with_max_age(Duration::from_secs(600)),
    );
    assert!(
        validator()
            .validate(presentation.sd_jwt(), &bounded)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn key_binding_errors() {
    let issuer = issuer();
    let credential = issue(&issuer).await;
    let presentation = present(&credential).await;
    let validator = validator();

    // No key binding JWT.
    let unbound = credential.disclose(&[claim_path!["given_name"]]).unwrap();
    assert!(matches!(
        validator
            .validate(unbound.sd_jwt(), &with_key_binding())
            .await,
        Err(SdJwtValidationError::KeyBindingRequired)
    ));

    // No holder key.
    let keyless = SdJwtVcBuilder::new(VCT)
        .with_issuer(issuer.did.as_str())
        .with_kid(issuer.kid.as_str())
        .sign(&issuer.signer)
        .await
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), &holder())
        .await
        .unwrap();
    assert!(matches!(
        validator
            .validate(keyless.sd_jwt(), &with_key_binding())
            .await,
        Err(SdJwtValidationError::NoHolderKey(
            KeyReferenceError::Missing
        ))
    ));

    // Wrong audience and nonce.
    let wrong_aud = options().with_key_binding(
        KeyBindingOptions::new("https://other.example", NONCE).with_time(TimeOptions::at(now())),
    );
    assert!(matches!(
        validator.validate(presentation.sd_jwt(), &wrong_aud).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::AudienceMismatch { .. }
        ))
    ));
    let wrong_nonce = options().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, "other").with_time(TimeOptions::at(now())),
    );
    assert!(matches!(
        validator
            .validate(presentation.sd_jwt(), &wrong_nonce)
            .await,
        Err(SdJwtValidationError::Validation(
            ValidationError::NonceMismatch { .. }
        ))
    ));

    // `iat` in the future, or too old.
    let earlier = options().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, NONCE)
            .with_time(TimeOptions::at(now() - chrono::TimeDelta::hours(1))),
    );
    assert!(matches!(
        validator.validate(presentation.sd_jwt(), &earlier).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::IssuedInFuture { .. }
        ))
    ));
    let stale = options().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, NONCE)
            .with_time(TimeOptions::at(now() + chrono::TimeDelta::hours(1)))
            .with_max_age(Duration::from_secs(60)),
    );
    assert!(matches!(
        validator.validate(presentation.sd_jwt(), &stale).await,
        Err(SdJwtValidationError::KeyBindingTooOld { .. })
    ));
    let oldest = options().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, NONCE)
            .with_time(TimeOptions::at(now() + chrono::TimeDelta::seconds(60)))
            .with_max_age(Duration::from_secs(60)),
    );
    assert!(
        validator
            .validate(presentation.sd_jwt(), &oldest)
            .await
            .is_ok()
    );
    // A `max_age` beyond what the clock represents bounds nothing, and never panics.
    let unbounded = with_key_binding().with_key_binding(
        KeyBindingOptions::new(AUDIENCE, NONCE)
            .with_time(TimeOptions::at(now()))
            .with_max_age(Duration::from_secs(u64::MAX)),
    );
    assert!(
        validator
            .validate(presentation.sd_jwt(), &unbounded)
            .await
            .is_ok()
    );

    // The key binding JWT belongs to another set of disclosures.
    let kb = presentation.sd_jwt().key_binding_jwt().unwrap().clone();
    let swapped = credential
        .disclose(&[claim_path!["family_name"]])
        .unwrap()
        .into_sd_jwt()
        .with_key_binding(kb.clone());
    assert!(matches!(
        validator.validate(&swapped, &with_key_binding()).await,
        Err(SdJwtValidationError::SdHashMismatch { .. })
    ));

    // Signed by the wrong key, or with the wrong `typ`.
    let header = JwsHeader::new(JwsAlgorithm::EdDSA).with_typ("kb+jwt");
    let claims = KeyBinding::new(AUDIENCE, NONCE, now())
        .claims(presentation.sd_jwt().sd_hash(Default::default()));
    let forged = Jwt::sign(&header, &claims, &issuer.signer).await.unwrap();
    let forged = presentation.sd_jwt().clone().with_key_binding(forged);
    assert!(matches!(
        validator.validate(&forged, &with_key_binding()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Signature(_)
        ))
    ));
    let header = JwsHeader::new(JwsAlgorithm::ES256).with_typ("JWT");
    let untyped = Jwt::sign(&header, &claims, &holder()).await.unwrap();
    let untyped = presentation.sd_jwt().clone().with_key_binding(untyped);
    assert!(matches!(
        validator.validate(&untyped, &with_key_binding()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::UnexpectedTyp {
                expected: "kb+jwt",
                ..
            }
        ))
    ));
    let header = JwsHeader::new(JwsAlgorithm::ES256).with_typ("kb+jwt");
    let mut no_iat = claims.clone();
    no_iat.iat = None;
    let no_iat = Jwt::sign(&header, &no_iat, &holder()).await.unwrap();
    let no_iat = presentation.sd_jwt().clone().with_key_binding(no_iat);
    assert!(matches!(
        validator.validate(&no_iat, &with_key_binding()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Credential(CredentialError::MissingClaim("iat"))
        ))
    ));
}

#[tokio::test]
async fn issuer_signature_and_binding_errors() {
    let issuer = issuer();
    let credential = issue(&issuer).await;
    let validator = validator();

    // A tampered disclosure.
    let tampered = {
        let mut disclosures = credential.sd_jwt().disclosures().to_vec();
        disclosures[0] = Disclosure::property(disclosures[0].salt(), "given_name", json!("Jane"));
        SdJwt::new(credential.sd_jwt().jwt().clone(), disclosures)
    };
    assert!(matches!(
        validator.validate(&tampered, &options()).await,
        Err(SdJwtValidationError::Credential(SdJwtVcError::SdJwt(
            SdJwtError::UnusedDisclosure(_)
        )))
    ));

    // A tampered payload (re-signed by nobody).
    let jws = credential.sd_jwt().jwt().as_str();
    let mut parts: Vec<&str> = jws.split('.').collect();
    let payload = common::encode(br#"{"vct":"x","iss":"did:example:123"}"#);
    parts[1] = &payload;
    let forged = SdJwt::new(Jwt::new(parts.join(".")).unwrap(), Vec::new());
    assert!(matches!(
        validator.validate(&forged, &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Signature(_)
        ))
    ));

    // `iss` is not the DID of `kid`, or not a DID, or missing.
    let other = builder(&issuer)
        .with_issuer("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(other.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::IssuerMismatch { .. }
        ))
    ));
    let https = builder(&issuer)
        .with_issuer("https://example.com/issuer")
        .sign(&issuer.signer)
        .await
        .unwrap();
    // An HTTPS issuer does not control the key of a DID, whatever the DID URL in `kid`.
    assert!(matches!(
        validator.validate(https.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(ValidationError::IssuerMismatch {
            issuer: id,
            key,
        })) if id.as_str() == "https://example.com/issuer"
            && *key == KeyReference::DidUrl(issuer.kid.clone())
    ));
    let anonymous = SdJwtVcBuilder::new(VCT)
        .with_kid(issuer.kid.as_str())
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(anonymous.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Credential(CredentialError::MissingClaim("iss"))
        ))
    ));

    // No `kid`, a `kid` that is not a DID URL, one with DID parameters, one that does not
    // resolve.
    let no_kid = SdJwtVcBuilder::new(VCT)
        .with_issuer(issuer.did.as_str())
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(no_kid.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::KeyReference(KeyReferenceError::Missing)
        ))
    ));
    let bad_kid = builder(&issuer)
        .with_kid("doc-signer-05-25-2022")
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(bad_kid.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::KeyReference(KeyReferenceError::InvalidKid { .. })
        ))
    ));
    let versioned = builder(&issuer)
        .with_kid(format!(
            "{}?versionId=1#{}",
            issuer.did,
            issuer.kid.fragment().unwrap()
        ))
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(versioned.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::KeyReference(KeyReferenceError::KidWithParameters(_))
        ))
    ));
    let unknown = builder(&issuer)
        .with_kid("did:example:123#key-1")
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(unknown.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::KeyResolution { .. }
        ))
    ));

    // Not an SD-JWT VC at all.
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(issuer.kid.as_str());
    let plain = Jwt::sign(&header, &JwtClaims::new(), &issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator
            .validate(&SdJwt::new(plain, Vec::new()), &options())
            .await,
        Err(SdJwtValidationError::Credential(
            SdJwtVcError::UnexpectedTyp(_)
        ))
    ));
}

#[tokio::test]
async fn validity_period() {
    let issuer = issuer();
    let credential = issue(&issuer).await;
    let validator = validator();
    let at = |time: DateTime<Utc>| options().with_time(TimeOptions::at(time));
    assert!(matches!(
        validator
            .validate(
                credential.sd_jwt(),
                &at(issued_at() - chrono::TimeDelta::seconds(1))
            )
            .await,
        Err(SdJwtValidationError::Validation(
            ValidationError::IssuedInFuture { .. }
        ))
    ));
    assert!(matches!(
        validator
            .validate(credential.sd_jwt(), &at(expires_at()))
            .await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Expired { .. }
        ))
    ));
    let leeway =
        options().with_time(TimeOptions::at(expires_at()).with_leeway(Duration::from_secs(5)));
    assert!(
        validator
            .validate(credential.sd_jwt(), &leeway)
            .await
            .is_ok()
    );

    let later = builder(&issuer)
        .with_not_before(now() + chrono::TimeDelta::days(1))
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(later.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::NotYetValid { .. }
        ))
    ));

    // The pre-standard `typ`.
    let legacy = {
        let claims = builder(&issuer).claims().clone();
        let header = JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ(LEGACY_TYP)
            .with_kid(issuer.kid.as_str());
        let sd_jwt = identity_kit::sd_jwt_vc::SdJwtBuilder::new(claims.to_map())
            .sign(&header, &issuer.signer)
            .await
            .unwrap();
        SdJwtVc::from_sd_jwt(sd_jwt).unwrap()
    };
    assert!(legacy.has_legacy_typ());
    assert!(
        validator
            .validate(legacy.sd_jwt(), &options())
            .await
            .is_ok()
    );
    assert!(matches!(
        validator
            .validate(legacy.sd_jwt(), &options().rejecting_legacy_typ())
            .await,
        Err(SdJwtValidationError::LegacyTyp)
    ));
}

/// A status check answering from a fixed status list.
struct FixedStatus(StatusList);

#[async_trait::async_trait]
impl StatusCheck for FixedStatus {
    async fn check(
        &self,
        status: CredentialStatus<'_>,
        _: DateTime<Utc>,
    ) -> Result<(), StatusError> {
        let CredentialStatus::SdJwt(Status {
            status_list: Some(reference),
            ..
        }) = status
        else {
            return Err(StatusError::Unsupported(status.mechanism()));
        };
        match self.0.get(reference.idx) {
            Some(status) if status.is_valid() => Ok(()),
            Some(status) => Err(StatusError::Invalid(status.to_string())),
            None => Err(StatusError::IndexOutOfRange {
                uri: reference.uri.clone(),
                idx: reference.idx,
                len: self.0.len(),
            }),
        }
    }
}

#[tokio::test]
async fn status_policies() {
    let issuer = issuer();
    let mut list = StatusList::new(1, 8).unwrap();
    list.set(3, StatusType::INVALID).unwrap();
    let with_status = |idx: u64| {
        builder(&issuer).with_status(Status::status_list(StatusListRef::new(
            "https://example.com/statuslists/1",
            idx,
        )))
    };
    let valid = with_status(2).sign(&issuer.signer).await.unwrap();
    let revoked = with_status(3).sign(&issuer.signer).await.unwrap();
    let other = builder(&issuer)
        .with_status(Status::new().with_mechanism("other", json!({})))
        .sign(&issuer.signer)
        .await
        .unwrap();

    // Strict, without a check: nothing with a status passes.
    let bare = validator();
    assert!(matches!(
        bare.validate(valid.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(ValidationError::StatusUnchecked(mechanism))) if mechanism == "status_list"
    ));
    assert!(
        bare.validate(
            valid.sd_jwt(),
            &options().with_status(StatusPolicy::SkipUnsupported)
        )
        .await
        .is_ok()
    );
    assert!(
        bare.validate(
            revoked.sd_jwt(),
            &options().with_status(StatusPolicy::SkipAll)
        )
        .await
        .is_ok()
    );

    assert!(!validator().has_status_check());
    let checked = validator().with_status_check(FixedStatus(list));
    assert!(checked.has_status_check());
    assert!(checked.validate(valid.sd_jwt(), &options()).await.is_ok());
    assert!(matches!(
        checked.validate(revoked.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(ValidationError::Status(
            StatusError::Invalid(_)
        )))
    ));
    assert!(matches!(
        checked.validate(other.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::StatusUnchecked(_)
        ))
    ));
    assert!(
        checked
            .validate(
                other.sd_jwt(),
                &options().with_status(StatusPolicy::SkipUnsupported)
            )
            .await
            .is_ok()
    );
    assert!(
        checked
            .validate(
                revoked.sd_jwt(),
                &options().with_status(StatusPolicy::SkipAll)
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn disclosures_nested_beyond_the_limit_are_refused_before_any_key_is_resolved() {
    // 1,000 disclosures, each concealing the next as a property; the innermost holds a scalar.
    let mut disclosures = Vec::new();
    let mut value = json!(1);
    for i in 0..1000 {
        let disclosure = Disclosure::property(format!("salt-{i}"), "c", value);
        value = json!({ "_sd": [disclosure.digest(HashAlgorithm::Sha256)] });
        disclosures.push(disclosure);
    }
    // The key is of a DID no method resolves: resolving it would fail differently.
    let sd_jwt = |typ: &str| {
        let header = json!({ "alg": "EdDSA", "typ": typ, "kid": "did:example:123#key-1" });
        SdJwt::new(
            Jwt::new(unsigned_jwt(&header, &value)).unwrap(),
            disclosures.clone(),
        )
    };
    let validator = SdJwtCredentialValidator::new(Resolver::builder().build(), DefaultVerifier);
    let options = SdJwtValidationOptions::new();
    fn too_deep(error: &SdJwtError) -> bool {
        matches!(error, SdJwtError::TooDeep { max } if *max == SdJwtBuilder::MAX_DEPTH)
    }

    let result = validator.validate(&sd_jwt("dc+sd-jwt"), &options).await;
    assert!(
        matches!(&result, Err(SdJwtValidationError::Credential(SdJwtVcError::SdJwt(e))) if too_deep(e)),
        "{result:?}"
    );
    let result = validator.validate_v2(&sd_jwt("vc+sd-jwt"), &options).await;
    assert!(
        matches!(
            &result,
            Err(SdJwtValidationError::CredentialV2(SdJwtCredentialV2Error::SdJwt(e))) if too_deep(e)
        ),
        "{result:?}"
    );
}

#[cfg(feature = "did-web")]
mod status_list_check {
    use std::collections::HashMap;
    use std::error::Error as _;
    use std::sync::Mutex;

    use identity_kit::jose::{JwsError, VerificationError};
    use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
    use identity_kit::resolver::{CompositeKeyResolver, JwkResolver, KeyResolutionError};
    use identity_kit::sd_jwt_vc::StatusListError;
    use identity_kit::sd_jwt_vc::validation::StatusListCheck;
    use identity_kit::vc::TypedObject;
    use url::Url;

    use super::*;

    /// A client serving fixed bodies.
    struct Served(HashMap<String, (u16, String)>);

    #[async_trait::async_trait]
    impl HttpClient for Served {
        async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
            match self.0.get(url.as_str()) {
                Some((status, body)) => Ok(HttpResponse::new(*status, body.as_bytes())),
                None => Err(HttpError::msg("connection refused")),
            }
        }
    }

    const LIST_URI: &str = "https://example.com/statuslists/1";

    #[tokio::test]
    async fn fetches_verifies_and_reads_the_status_list_token() {
        let issuer = issuer();
        let mut list = StatusList::new(2, 16).unwrap();
        list.set(1, StatusType::INVALID).unwrap();
        list.set(2, StatusType::SUSPENDED).unwrap();
        let token = StatusListToken::new(LIST_URI, issued_at(), list)
            .with_expires_at(expires_at())
            .sign(&Ed25519Signer::rfc8037().with_kid(issuer.kid.as_str()))
            .await
            .unwrap();
        let expired = StatusListToken::new(
            "https://example.com/statuslists/3",
            issued_at(),
            StatusList::new(1, 8).unwrap(),
        )
        .with_expires_at(issued_at())
        .sign(&Ed25519Signer::rfc8037().with_kid(issuer.kid.as_str()))
        .await
        .unwrap();
        let versioned = StatusListToken::new(LIST_URI, issued_at(), StatusList::new(1, 8).unwrap())
            .with_expires_at(expires_at())
            .sign(&Ed25519Signer::rfc8037().with_kid(format!(
                "{}?versionId=1#{}",
                issuer.did,
                issuer.kid.fragment().unwrap()
            )))
            .await
            .unwrap();
        // A relative `kid` joined with the token's `iss`.
        let token_of = |n: u8, iss: &str| {
            let mut list = StatusList::new(1, 8).unwrap();
            list.set(1, StatusType::INVALID).unwrap();
            StatusListToken::new(
                format!("https://example.com/statuslists/{n}"),
                issued_at(),
                list,
            )
            .with_expires_at(expires_at())
            .with_claim("iss", iss)
        };
        let relative = token_of(6, issuer.did.as_str())
            .sign(
                &Ed25519Signer::rfc8037().with_kid(format!("#{}", issuer.kid.fragment().unwrap())),
            )
            .await
            .unwrap();
        // The key in a `jwk` header: anybody's without an `iss` it belongs to.
        let with_jwk = |token: StatusListToken| async move {
            let signer = Ed25519Signer::rfc8037();
            let mut header = JwsHeader::new(JwsAlgorithm::EdDSA).with_typ(StatusListToken::TYP);
            header.jwk = Some(signer.public_jwk());
            let payload = serde_json::to_vec(&token).unwrap();
            identity_kit::jose::encode_compact(&header, &payload, &signer)
                .await
                .unwrap()
        };
        let thumbprint = Ed25519Signer::rfc8037()
            .public_jwk()
            .thumbprint_sha256()
            .unwrap();
        let by_thumbprint = with_jwk(token_of(7, &thumbprint)).await;
        let anonymous = with_jwk(
            StatusListToken::new(
                "https://example.com/statuslists/8",
                issued_at(),
                StatusList::new(1, 8).unwrap(),
            )
            .with_expires_at(expires_at()),
        )
        .await;
        // A DID URL of the issuer under another `iss`.
        let other_iss = token_of(9, "did:example:other")
            .sign(&Ed25519Signer::rfc8037().with_kid(issuer.kid.as_str()))
            .await
            .unwrap();
        // A DID URL of a method the resolver does not know.
        let unresolvable = StatusListToken::new(
            "https://example.com/statuslists/10",
            issued_at(),
            StatusList::new(1, 8).unwrap(),
        )
        .with_expires_at(expires_at())
        .sign(&Ed25519Signer::rfc8037().with_kid("did:web:status.example.com#key-1"))
        .await
        .unwrap();
        let forged = {
            let mut parts: Vec<String> = token.as_str().split('.').map(str::to_owned).collect();
            parts[2] = common::encode(&[1u8; 64]);
            parts.join(".")
        };
        let mut served = HashMap::new();
        served.insert(LIST_URI.to_owned(), (200, token.as_str().to_owned()));
        served.insert(
            "https://example.com/statuslists/2".to_owned(),
            (404, String::new()),
        );
        served.insert(
            "https://example.com/statuslists/3".to_owned(),
            (200, expired.as_str().to_owned()),
        );
        served.insert(
            "https://example.com/statuslists/4".to_owned(),
            (200, forged),
        );
        served.insert(
            "https://example.com/statuslists/5".to_owned(),
            (200, versioned.as_str().to_owned()),
        );
        for (n, token) in [
            (6, relative.as_str().to_owned()),
            (7, by_thumbprint),
            (8, anonymous),
            (9, other_iss.as_str().to_owned()),
            (10, unresolvable.as_str().to_owned()),
            (11, "not a token".to_owned()),
            // The list at `LIST_URI`, served under another URI.
            (12, token.as_str().to_owned()),
        ] {
            served.insert(format!("https://example.com/statuslists/{n}"), (200, token));
        }
        let check = StatusListCheck::new(
            Served(served),
            CompositeKeyResolver::new()
                .with(Resolver::builder().with(DidKey::default()).build())
                .with(JwkResolver),
            DefaultVerifier,
        );
        let validator = validator().with_status_check(check);
        let credential = |uri: &str, idx: u64| {
            builder(&issuer).with_status(Status::status_list(StatusListRef::new(uri, idx)))
        };

        let valid = credential(LIST_URI, 0).sign(&issuer.signer).await.unwrap();
        assert!(validator.validate(valid.sd_jwt(), &options()).await.is_ok());
        for uri in [
            "https://example.com/statuslists/6",
            "https://example.com/statuslists/7",
        ] {
            let valid = credential(uri, 0).sign(&issuer.signer).await.unwrap();
            let result = validator.validate(valid.sd_jwt(), &options()).await;
            assert!(result.is_ok(), "{uri}: {result:?}");
            let revoked = credential(uri, 1).sign(&issuer.signer).await.unwrap();
            assert!(matches!(
                validator.validate(revoked.sd_jwt(), &options()).await,
                Err(SdJwtValidationError::Validation(ValidationError::Status(
                    StatusError::Invalid(_)
                )))
            ));
        }
        for (idx, expected) in [(1, "INVALID (0x01)"), (2, "SUSPENDED (0x02)")] {
            let bad = credential(LIST_URI, idx)
                .sign(&issuer.signer)
                .await
                .unwrap();
            assert!(matches!(
                validator.validate(bad.sd_jwt(), &options()).await,
                Err(SdJwtValidationError::Validation(ValidationError::Status(StatusError::Invalid(status)))) if status == expected
            ));
        }
        // Each failure is reported as what it is, with its cause as the source.
        let status_error = async |uri: &str, idx: u64| {
            let bad = credential(uri, idx).sign(&issuer.signer).await.unwrap();
            match validator.validate(bad.sd_jwt(), &options()).await {
                Err(SdJwtValidationError::Validation(ValidationError::Status(error))) => error,
                other => panic!("{uri}#{idx}: {other:?}"),
            }
        };
        let error = status_error(LIST_URI, 16).await;
        assert!(
            matches!(&error, StatusError::IndexOutOfRange { uri, idx: 16, len: 16 } if uri == LIST_URI),
            "{error:?}"
        );
        let error = status_error("https://example.com/statuslists/2", 0).await;
        assert!(
            matches!(&error, StatusError::Unavailable { reason, source: None, .. } if reason == "HTTP 404"),
            "{error:?}"
        );
        let error = status_error("https://example.com/nowhere", 0).await;
        let StatusError::Unavailable {
            source: Some(source),
            ..
        } = &error
        else {
            panic!("{error:?}");
        };
        assert!(source.downcast_ref::<HttpError>().is_some(), "{error:?}");
        assert!(error.to_string().ends_with("connection refused"), "{error}");
        let error = status_error("https://example.com/statuslists/3", 0).await;
        assert!(
            matches!(&error, StatusError::Expired { expired_at, .. } if *expired_at == issued_at()),
            "{error:?}"
        );
        let error = status_error("https://example.com/statuslists/4", 0).await;
        let StatusError::InvalidList { reason, .. } = &error else {
            panic!("{error:?}");
        };
        assert_eq!(reason, "the signature does not verify");
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<VerificationError>()
                .is_some(),
            "{error:?}"
        );
        // A `kid` with DID parameters names no key this crate looks up.
        let error = status_error("https://example.com/statuslists/5", 0).await;
        assert!(
            matches!(&error, StatusError::InvalidList { reason, .. } if reason == "no key to verify it with"),
            "{error:?}"
        );
        assert!(
            matches!(
                error.source().unwrap().downcast_ref::<KeyReferenceError>(),
                Some(KeyReferenceError::KidWithParameters(_))
            ),
            "{error:?}"
        );
        // A body that is not a status list token, a token of another list, and a URI that is not
        // a URL are invalid references or lists, each with its cause.
        let error = status_error("https://example.com/statuslists/11", 0).await;
        assert!(
            matches!(&error, StatusError::InvalidList { reason, .. } if reason == "not a status list token"),
            "{error:?}"
        );
        assert!(error.source().unwrap().is::<JwsError>(), "{error:?}");
        let error = status_error("https://example.com/statuslists/12", 0).await;
        assert!(
            matches!(
                error
                    .source()
                    .and_then(|e| e.downcast_ref::<StatusListError>()),
                Some(StatusListError::SubjectMismatch { .. })
            ),
            "{error:?}"
        );
        let error = status_error("not a url", 0).await;
        assert!(
            matches!(&error, StatusError::InvalidList { reason, .. } if reason == "the URI is not a URL"),
            "{error:?}"
        );
        assert!(error.source().unwrap().is::<url::ParseError>(), "{error:?}");
        let error = status_error("https://example.com/statuslists/10", 0).await;
        assert!(
            matches!(&error, StatusError::UnresolvedKey { key, .. } if key == "did:web:status.example.com#key-1"),
            "{error:?}"
        );
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<KeyResolutionError>()
                .is_some(),
            "{error:?}"
        );
        // A key by value without an `iss`, and a key of a DID other than the `iss`, are not the
        // status issuer's.
        for uri in [
            "https://example.com/statuslists/8",
            "https://example.com/statuslists/9",
        ] {
            let bad = credential(uri, 0).sign(&issuer.signer).await.unwrap();
            let result = validator.validate(bad.sd_jwt(), &options()).await;
            assert!(
                matches!(
                    &result,
                    Err(SdJwtValidationError::Validation(ValidationError::Status(
                        StatusError::InvalidList { reason, source: None, .. }
                    ))) if reason.contains("does not belong to the issuer")
                ),
                "{uri}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn knows_the_token_status_list_only() {
        let check = StatusListCheck::new(
            Served(HashMap::new()),
            Resolver::builder().with(DidKey::default()).build(),
            DefaultVerifier,
        );
        let now = issued_at();
        // A `credentialStatus` entry is another check's business, without a request.
        let entry = TypedObject::new("BitstringStatusListEntry");
        assert!(matches!(
            check.check(CredentialStatus::Vcdm(&entry), now).await,
            Err(StatusError::Unsupported(kind)) if kind == "BitstringStatusListEntry"
        ));
        // So is a `status` claim without a status list reference.
        let other = Status::new().with_mechanism("other", json!({}));
        assert!(matches!(
            check.check(CredentialStatus::SdJwt(&other), now).await,
            Err(StatusError::Unsupported(kind)) if kind == "other"
        ));
        // A reference is fetched: here, from nowhere.
        let listed = Status::status_list(StatusListRef::new(LIST_URI, 0));
        assert_eq!(CredentialStatus::SdJwt(&listed).mechanism(), "status_list");
        assert!(matches!(
            check.check(CredentialStatus::SdJwt(&listed), now).await,
            Err(StatusError::Unavailable { .. })
        ));
    }

    /// A client serving fixed responses and recording each request with the media type it
    /// asked for.
    #[derive(Default)]
    struct Routed {
        routes: HashMap<String, HttpResponse>,
        requests: Mutex<Vec<(String, Option<String>)>>,
    }

    impl Routed {
        fn with(mut self, url: &str, response: HttpResponse) -> Self {
            self.routes.insert(url.to_owned(), response);
            self
        }

        fn redirect(self, url: &str, status: u16, location: &str) -> Self {
            self.with(
                url,
                HttpResponse::new(status, Vec::new()).with_location(location),
            )
        }

        fn respond(&self, url: &Url, accept: Option<&str>) -> Result<HttpResponse, HttpError> {
            self.requests
                .lock()
                .unwrap()
                .push((url.to_string(), accept.map(str::to_owned)));
            self.routes
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| HttpError::msg("connection refused"))
        }

        /// The URLs requested so far, forgotten after.
        fn take(&self) -> Vec<String> {
            let requests = std::mem::take(&mut *self.requests.lock().unwrap());
            for (url, accept) in &requests {
                assert_eq!(
                    accept.as_deref(),
                    Some(StatusListToken::MEDIA_TYPE),
                    "{url}"
                );
            }
            requests.into_iter().map(|(url, _)| url).collect()
        }
    }

    #[async_trait::async_trait]
    impl HttpClient for Routed {
        async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError> {
            self.respond(url, None)
        }

        async fn get_accepting(
            &self,
            url: &Url,
            media_type: &str,
        ) -> Result<HttpResponse, HttpError> {
            self.respond(url, Some(media_type))
        }
    }

    /// A signed status list token for the reference `uri`, all statuses valid.
    async fn token_for(issuer: &Issuer, uri: &str) -> HttpResponse {
        let token = StatusListToken::new(uri, issued_at(), StatusList::new(1, 8).unwrap())
            .with_expires_at(expires_at())
            .sign(&Ed25519Signer::rfc8037().with_kid(issuer.kid.as_str()))
            .await
            .unwrap();
        HttpResponse::new(200, token.as_str())
    }

    #[cfg(feature = "local-network")]
    #[tokio::test]
    async fn reads_gzip_encoded_and_redirected_tokens_through_reqwest() {
        use identity_kit::methods::web::ReqwestClient;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let gzip = |data: &[u8]| {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).unwrap();
            encoder.finish().unwrap()
        };
        let issuer = issuer();
        let server = MockServer::start().await;
        let base = format!("https://127.0.0.1:{}", server.address().port());
        let serve = |route: &'static str, response: ResponseTemplate| {
            Mock::given(method("GET"))
                .and(path(route))
                .and(header("accept", StatusListToken::MEDIA_TYPE))
                .respond_with(response)
        };
        let token = |n: u8| {
            let (issuer, uri) = (&issuer, format!("{base}/statuslists/{n}"));
            async move { token_for(issuer, &uri).await }
        };
        let gzipped = |body: Vec<u8>| {
            ResponseTemplate::new(200)
                .insert_header("content-type", StatusListToken::MEDIA_TYPE)
                .insert_header("content-encoding", "gzip")
                .set_body_bytes(gzip(&body))
        };
        // Compressed; uncompressed; redirected to a compressed one.
        serve("/statuslists/1", gzipped(token(1).await.body))
            .mount(&server)
            .await;
        serve(
            "/statuslists/2",
            ResponseTemplate::new(200).set_body_bytes(token(2).await.body),
        )
        .mount(&server)
        .await;
        serve(
            "/statuslists/3",
            ResponseTemplate::new(302).insert_header("location", "/served/3"),
        )
        .mount(&server)
        .await;
        serve("/served/3", gzipped(token(3).await.body))
            .mount(&server)
            .await;

        let check = StatusListCheck::new(
            ReqwestClient::builder()
                .dangerous_allow_loopback()
                .build()
                .unwrap(),
            Resolver::builder().with(DidKey::default()).build(),
            DefaultVerifier,
        );
        for n in 1..=3 {
            let status =
                Status::status_list(StatusListRef::new(format!("{base}/statuslists/{n}"), 0));
            let result = check
                .check(CredentialStatus::SdJwt(&status), issued_at())
                .await;
            assert!(result.is_ok(), "{n}: {result:?}");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn follows_redirects_through_the_client() {
        let issuer = issuer();
        let at = |path: &str| format!("https://example.com/{path}");
        let mut client = Routed::default()
            // One redirect to an absolute URL, and one to a relative one.
            .redirect(&at("a"), 302, "https://example.com/served/a")
            .with(&at("served/a"), token_for(&issuer, &at("a")).await)
            .redirect(&at("lists/b"), 301, "../served/b")
            .with(&at("served/b"), token_for(&issuer, &at("lists/b")).await)
            // Three redirects, the most followed, and four.
            .redirect(&at("c"), 303, "/c1")
            .redirect(&at("c1"), 307, "/c2")
            .redirect(&at("c2"), 308, "/served/c")
            .with(&at("served/c"), token_for(&issuer, &at("c")).await)
            .redirect(&at("d"), 302, "/d1")
            .redirect(&at("d1"), 302, "/d2")
            .redirect(&at("d2"), 302, "/d3")
            .redirect(&at("d3"), 302, "/served/d")
            .with(&at("served/d"), token_for(&issuer, &at("d")).await)
            // A loop, plain `http`, and a redirect that names no target.
            .redirect(&at("loop"), 302, "/loop2")
            .redirect(&at("loop2"), 302, "/loop")
            .redirect(&at("plain"), 302, "http://example.com/served/plain")
            .with(&at("nowhere"), HttpResponse::new(302, Vec::new()))
            // A target that is no URL, and one the client cannot reach.
            .redirect(&at("malformed"), 302, "https://[::1")
            .redirect(&at("gone"), 302, "/unreachable");
        // 304 and 300 are not redirects to follow: an error status like any other.
        for (path, status) in [("not-modified", 304), ("choices", 300)] {
            client = client.redirect(&at(path), status, "/served/a");
        }
        // Shared, so the requests stay readable; `Arc` forwards `get_accepting`.
        let client = std::sync::Arc::new(client);
        let check = StatusListCheck::new(
            std::sync::Arc::clone(&client),
            Resolver::builder().with(DidKey::default()).build(),
            DefaultVerifier,
        );
        let run = |uri: String| {
            let check = &check;
            async move {
                let status = Status::status_list(StatusListRef::new(uri, 0));
                check
                    .check(CredentialStatus::SdJwt(&status), issued_at())
                    .await
            }
        };

        for (start, hops) in [
            ("a", vec!["a", "served/a"]),
            ("lists/b", vec!["lists/b", "served/b"]),
            ("c", vec!["c", "c1", "c2", "served/c"]),
        ] {
            let result = run(at(start)).await;
            assert!(result.is_ok(), "{start}: {result:?}");
            let requested: Vec<String> = hops.into_iter().map(at).collect();
            assert_eq!(client.take(), requested, "{start}");
        }
        for (start, reason, last) in [
            ("d", "more than 3 redirects", "d3"),
            ("loop", "redirect loop at https://example.com/loop", "loop2"),
            ("plain", "which is not HTTPS", "plain"),
            ("nowhere", "HTTP 302 without a `Location`", "nowhere"),
            ("malformed", r#"to "https://[::1""#, "malformed"),
            (
                "gone",
                "fetching https://example.com/unreachable: connection refused",
                "unreachable",
            ),
            ("not-modified", "HTTP 304", "not-modified"),
            ("choices", "HTTP 300", "choices"),
        ] {
            let result = run(at(start)).await;
            assert!(
                matches!(&result, Err(error @ StatusError::Unavailable { .. }) if error.to_string().contains(reason)),
                "{start}: {result:?}"
            );
            // Nothing past the refused hop was requested.
            assert_eq!(client.take().last(), Some(&at(last)), "{start}");
        }
    }
}
