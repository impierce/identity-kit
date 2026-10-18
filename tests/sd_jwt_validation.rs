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
use identity_kit::resolver::Resolver;
use identity_kit::sd_jwt_vc::validation::{
    KeyBindingOptions, SdJwtStatusCheck, SdJwtValidationOptions,
};
use identity_kit::sd_jwt_vc::{
    Disclosure, KeyBinding, LEGACY_TYP, SdJwt, SdJwtCredentialValidator, SdJwtError,
    SdJwtValidationError, SdJwtVc, SdJwtVcBuilder, SdJwtVcError, Status, StatusList, StatusListRef,
    StatusListToken, StatusType,
};
use identity_kit::vc::validation::{StatusError, StatusPolicy, TimeOptions, ValidationError};
use identity_kit::vc::{CredentialError, Jwt, JwtClaims};
use serde_json::json;

use common::{Ed25519Signer, Es256Signer};

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
    assert_eq!(validated.kid, issuer.kid);
    assert_eq!(validated.key_binding, None);
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
        Err(SdJwtValidationError::NoHolderKey)
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
    assert!(matches!(
        validator.validate(https.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(ValidationError::NotDid {
            role: "issuer",
            ..
        }))
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

    // No `kid`, a `kid` that is not a DID URL, a `kid` that does not resolve.
    let no_kid = SdJwtVcBuilder::new(VCT)
        .with_issuer(issuer.did.as_str())
        .sign(&issuer.signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate(no_kid.sd_jwt(), &options()).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::MissingKid
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
            ValidationError::InvalidKid { .. }
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
impl SdJwtStatusCheck for FixedStatus {
    async fn check(&self, status: &Status, _: DateTime<Utc>) -> Result<(), StatusError> {
        let Some(reference) = &status.status_list else {
            return Err(StatusError::Unsupported("other".into()));
        };
        match self.0.get(reference.idx) {
            Some(status) if status.is_valid() => Ok(()),
            Some(status) => Err(StatusError::Invalid(status.to_string())),
            None => Err(StatusError::Unavailable("index out of range".into())),
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

#[cfg(feature = "did-web")]
mod status_list_check {
    use std::collections::HashMap;

    use identity_kit::methods::web::{HttpClient, HttpError, HttpResponse};
    use identity_kit::sd_jwt_vc::validation::StatusListCheck;
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
        let expired = StatusListToken::new(LIST_URI, issued_at(), StatusList::new(1, 8).unwrap())
            .with_expires_at(issued_at())
            .sign(&Ed25519Signer::rfc8037().with_kid(issuer.kid.as_str()))
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
        let check = StatusListCheck::new(
            Served(served),
            Resolver::builder().with(DidKey::default()).build(),
            DefaultVerifier,
        );
        let validator = validator().with_status_check(check);
        let credential = |uri: &str, idx: u64| {
            builder(&issuer).with_status(Status::status_list(StatusListRef::new(uri, idx)))
        };

        let valid = credential(LIST_URI, 0).sign(&issuer.signer).await.unwrap();
        assert!(validator.validate(valid.sd_jwt(), &options()).await.is_ok());
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
        for (uri, idx) in [
            (LIST_URI, 16),
            ("https://example.com/statuslists/2", 0),
            ("https://example.com/statuslists/3", 0),
            ("https://example.com/statuslists/4", 0),
            ("https://example.com/nowhere", 0),
        ] {
            let bad = credential(uri, idx).sign(&issuer.signer).await.unwrap();
            let result = validator.validate(bad.sd_jwt(), &options()).await;
            assert!(
                matches!(
                    result,
                    Err(SdJwtValidationError::Validation(ValidationError::Status(
                        StatusError::Unavailable(_)
                    )))
                ),
                "{uri}#{idx}: {result:?}"
            );
        }
    }
}
