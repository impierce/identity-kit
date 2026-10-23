//! The validators over `KeyReference` (ADR 0006): a credential and a presentation signed with
//! a relative `kid`, a credential whose key is in a `jwk` header behind a `did:jwk` issuer, and
//! SD-JWT key binding with the holder key from `cnf.kid`. Signatures are made with the RFC 8037
//! Appendix A.1 and RFC 7515 Appendix A.3 keys, as in ADR 0004.
#![cfg(all(feature = "sd-jwt", feature = "did-key", feature = "did-jwk"))]

mod common;

use chrono::{DateTime, TimeZone as _, Utc};
use identity_kit::did::{Did, DidUrl, Uri};
use identity_kit::jose::{DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, VerificationError};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::{
    CompositeKeyResolver, JwkResolver, KeyReference, KeyReferenceError, KeyResolutionError,
    KeyResolver, KeyRole, Resolver,
};
use identity_kit::sd_jwt_vc::{
    Confirmation, KeyBinding, KeyBindingOptions, SdJwtCredentialValidator, SdJwtValidationError,
    SdJwtValidationOptions, SdJwtVc, SdJwtVcBuilder,
};
use identity_kit::vc::validation::{
    CredentialValidationOptions, JwtCredentialValidator, JwtPresentationValidator,
    PresentationValidationOptions, SubjectHolderRelationship, TimeOptions, ValidationError,
};
use identity_kit::vc::{Credential, CredentialV2, Jwt, JwtClaims, Presentation, Subject};
use serde_json::json;

use common::{Ed25519Signer, Es256Signer};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 6, 1, 12, 0, 0).unwrap()
}

fn issued_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
}

fn resolver() -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build()
}

/// `did:key` of the RFC 8037 key and the fragment of its verification method.
fn ed25519_did() -> (Did, String) {
    let did = DidKey::did(&Ed25519Signer::rfc8037().public_jwk()).unwrap();
    let fragment = format!("#{}", did.method_specific_id());
    (did, fragment)
}

/// `did:jwk` of the RFC 7515 A.3 key.
fn p256_did() -> Did {
    DidJwk::did(&Es256Signer::rfc7515_a3().public_jwk()).unwrap()
}

fn subject() -> Subject {
    Subject::new(Uri::parse("did:example:ebfeb1f712ebc6f1c276e12ec21").unwrap())
}

fn at() -> CredentialValidationOptions {
    CredentialValidationOptions::new().with_time(TimeOptions::at(now()))
}

// ---------------------------------------------------------------------------------------------
// Relative `kid`
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn credential_signed_with_a_relative_kid() {
    let (did, fragment) = ed25519_did();
    let signer = Ed25519Signer::rfc8037();
    let validator = JwtCredentialValidator::new(resolver(), DefaultVerifier);

    // VCDM 1.1: the `kid` is joined with the issuer.
    let credential = Credential::new(&did, issued_at(), subject());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(&fragment);
    let jwt = Jwt::sign(&header, &credential.to_jwt_claims().unwrap(), &signer)
        .await
        .unwrap();
    let decoded = validator.validate(&jwt, &at()).await.unwrap();
    assert_eq!(decoded.credential, credential);
    assert_eq!(decoded.header.kid.as_deref(), Some(fragment.as_str()));

    // VCDM 2.0 the same.
    let credential = CredentialV2::new(&did, subject()).with_valid_from(issued_at());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(CredentialV2::JWT_TYP)
        .with_kid(&fragment);
    let jwt = Jwt::sign(&header, &credential.to_jwt_claims(), &signer)
        .await
        .unwrap();
    assert!(validator.validate_v2(&jwt, &at()).await.is_ok());

    // An HTTPS issuer has no DID document to look a fragment up in.
    let credential = CredentialV2::new(Uri::parse("https://issuer.example").unwrap(), subject());
    let jwt = Jwt::sign(&header, &credential.to_jwt_claims(), &signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate_v2(&jwt, &at()).await,
        Err(ValidationError::KeyReference(
            KeyReferenceError::RelativeKidWithoutIssuer(kid)
        )) if kid == fragment
    ));

    // The fragment of another DID's key, joined with this issuer, is not a key of it.
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ(CredentialV2::JWT_TYP)
        .with_kid("#0");
    let credential = CredentialV2::new(&did, subject());
    let jwt = Jwt::sign(&header, &credential.to_jwt_claims(), &signer)
        .await
        .unwrap();
    assert!(matches!(
        validator.validate_v2(&jwt, &at()).await,
        Err(ValidationError::KeyResolution { key, .. })
            if *key == KeyReference::DidUrl(did.join("#0").unwrap())
    ));
}

#[tokio::test]
async fn presentation_signed_with_a_relative_kid() {
    let (issuer, issuer_fragment) = ed25519_did();
    let holder = p256_did();
    let credential = Credential::new(&issuer, issued_at(), Subject::new(&holder));
    let credential = Jwt::sign(
        &JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ("JWT")
            .with_kid(&issuer_fragment),
        &credential.to_jwt_claims().unwrap(),
        &Ed25519Signer::rfc8037(),
    )
    .await
    .unwrap();
    let mut presentation = Presentation::new().with_holder(&holder);
    presentation.verifiable_credential = vec![credential];
    let claims = presentation
        .to_jwt_claims()
        .unwrap()
        .with_aud("https://verifier.example")
        .with_claim("nonce", "n-0S6_WzA2Mj");
    let jwt = Jwt::sign(
        &JwsHeader::new(JwsAlgorithm::ES256)
            .with_typ("JWT")
            .with_kid("#0"),
        &claims,
        &Es256Signer::rfc7515_a3(),
    )
    .await
    .unwrap();

    let options = PresentationValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_audience("https://verifier.example")
        .with_nonce("n-0S6_WzA2Mj")
        .with_subject_holder(SubjectHolderRelationship::AlwaysSubject)
        .with_credentials(at());
    let decoded = JwtPresentationValidator::new(resolver(), DefaultVerifier)
        .validate(&jwt, &options)
        .await
        .unwrap();
    assert_eq!(decoded.holder().map(Uri::as_str), Some(holder.as_str()));
    assert_eq!(decoded.credentials.len(), 1);
}

// ---------------------------------------------------------------------------------------------
// `jwk` header
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn credential_with_its_key_in_a_jwk_header() {
    let signer = Es256Signer::rfc7515_a3();
    let key = signer.public_jwk();
    let mut header = JwsHeader::new(JwsAlgorithm::ES256).with_typ("JWT");
    header.jwk = Some(key.clone());
    let sign = |issuer: Did| {
        let header = header.clone();
        async move {
            let credential = Credential::new(&issuer, issued_at(), subject());
            Jwt::sign(
                &header,
                &credential.to_jwt_claims().unwrap(),
                &Es256Signer::rfc7515_a3(),
            )
            .await
            .unwrap()
        }
    };
    let jwt = sign(p256_did()).await;

    // A DID resolver alone does not take a key by value.
    let error = JwtCredentialValidator::new(resolver(), DefaultVerifier)
        .validate(&jwt, &at())
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        ValidationError::KeyResolution { key: k, source: KeyResolutionError::Unsupported(_) }
            if **k == KeyReference::Jwk(Box::new(key.clone()))
    ));

    // With `JwkResolver` the key verifies, and it is the issuer's: the issuer is its did:jwk.
    let composite = CompositeKeyResolver::new()
        .with(resolver())
        .with(JwkResolver);
    let validator = JwtCredentialValidator::new(composite, DefaultVerifier);
    assert!(validator.validate(&jwt, &at()).await.is_ok());

    // Anybody can sign with a key of their own: an issuer that is not that key is refused.
    let (other, _) = ed25519_did();
    let jwt = sign(other.clone()).await;
    let error = validator.validate(&jwt, &at()).await.unwrap_err();
    assert!(matches!(
        &error,
        ValidationError::IssuerMismatch { issuer, key: k }
            if issuer.as_str() == other.as_str() && **k == KeyReference::Jwk(Box::new(key.clone()))
    ));
    assert_eq!(
        error.to_string(),
        format!(
            "issuer `{other}` does not control signing key JWK {}",
            key.thumbprint_sha256().unwrap()
        )
    );
}

// ---------------------------------------------------------------------------------------------
// Key binding with `cnf.kid`
// ---------------------------------------------------------------------------------------------

const VCT: &str = "https://credentials.example.com/identity_credential";
const AUDIENCE: &str = "https://verifier.example.org";
const NONCE: &str = "1234567890";

/// An SD-JWT VC from the RFC 8037 `did:key` issuer to a holder confirmed by `cnf`, presented
/// with a key binding JWT signed by `holder`.
async fn present(cnf: Confirmation, holder: &dyn identity_kit::jose::Signer) -> SdJwtVc {
    let (issuer, fragment) = ed25519_did();
    SdJwtVcBuilder::new(VCT)
        .with_issuer(issuer.as_str())
        .with_kid(issuer.join(&fragment).unwrap().as_str())
        .with_issued_at(issued_at())
        .with_confirmation(cnf)
        .with_claim("given_name", "John")
        .conceal(["given_name"])
        .sign(&Ed25519Signer::rfc8037())
        .await
        .unwrap()
        .sign_key_binding(&KeyBinding::new(AUDIENCE, NONCE, now()), holder)
        .await
        .unwrap()
}

fn with_key_binding() -> SdJwtValidationOptions {
    SdJwtValidationOptions::new()
        .with_time(TimeOptions::at(now()))
        .with_key_binding(KeyBindingOptions::new(AUDIENCE, NONCE).with_time(TimeOptions::at(now())))
}

async fn validate<R: KeyResolver>(
    resolver: R,
    credential: &SdJwtVc,
) -> Result<identity_kit::sd_jwt_vc::ValidatedSdJwtVc, SdJwtValidationError> {
    SdJwtCredentialValidator::new(resolver, DefaultVerifier)
        .validate(credential.sd_jwt(), &with_key_binding())
        .await
}

/// The verification method of the `did:jwk` holder.
fn holder_kid() -> DidUrl {
    p256_did().join("#0").unwrap()
}

#[tokio::test]
async fn key_binding_with_the_holder_key_from_cnf_kid() {
    let holder = Es256Signer::rfc7515_a3();
    let credential = present(Confirmation::kid(holder_kid().as_str()), &holder).await;
    assert_eq!(credential.holder_key(), None);
    let validated = validate(resolver(), &credential).await.unwrap();
    assert!(validated.key_binding.is_some());
    assert_eq!(
        validated.holder_key,
        Some((KeyReference::DidUrl(holder_kid()), holder.public_jwk()))
    );
    // The holder's DID, for comparing with a presentation's holder or the credential subject.
    let Some((KeyReference::DidUrl(url), _)) = &validated.holder_key else {
        unreachable!()
    };
    assert_eq!(url.did(), &p256_did());
}

#[tokio::test]
async fn key_binding_with_cnf_jwk_is_unchanged() {
    let holder = Es256Signer::rfc7515_a3();
    let credential = present(Confirmation::jwk(&holder.public_jwk()), &holder).await;
    let validated = validate(resolver(), &credential).await.unwrap();
    assert_eq!(
        validated.holder_key,
        Some((
            KeyReference::Jwk(Box::new(holder.public_jwk())),
            holder.public_jwk()
        ))
    );

    // `jwk` wins over `kid`: an unresolvable `kid` beside it is not looked at.
    let mut cnf = Confirmation::jwk(&holder.public_jwk());
    cnf.kid = Some("did:example:unresolvable#key-1".to_owned());
    let credential = present(cnf, &holder).await;
    let validated = validate(resolver(), &credential).await.unwrap();
    assert!(matches!(
        validated.holder_key,
        Some((KeyReference::Jwk(_), _))
    ));
}

#[tokio::test]
async fn cnf_kid_must_be_an_absolute_did_url_without_parameters() {
    let holder = Es256Signer::rfc7515_a3();
    for (kid, expected) in [
        (format!("{}?versionId=1#0", p256_did()), "parameters"),
        (format!("{}/path#0", p256_did()), "parameters"),
        ("#0".to_owned(), "not a DID URL"),
        ("key-1".to_owned(), "not a DID URL"),
    ] {
        let credential = present(Confirmation::kid(&kid), &holder).await;
        let error = validate(resolver(), &credential).await.unwrap_err();
        match expected {
            "parameters" => assert!(
                matches!(
                    &error,
                    SdJwtValidationError::NoHolderKey(KeyReferenceError::KidWithParameters(_))
                ),
                "{kid}: {error:?}"
            ),
            _ => assert!(
                matches!(
                    &error,
                    SdJwtValidationError::NoHolderKey(KeyReferenceError::InvalidKid { kid: k, .. }) if *k == kid
                ),
                "{kid}: {error:?}"
            ),
        }
        assert!(
            error
                .to_string()
                .starts_with("key binding is required, but `cnf` carries no usable key reference")
        );
    }
}

#[tokio::test]
async fn cnf_without_a_usable_key() {
    let holder = Es256Signer::rfc7515_a3();

    // Neither member.
    let credential = present(Confirmation::default(), &holder).await;
    assert!(matches!(
        validate(resolver(), &credential).await,
        Err(SdJwtValidationError::NoHolderKey(
            KeyReferenceError::Missing
        ))
    ));

    // Only a confirmation method the crate does not resolve.
    let mut cnf = Confirmation::default();
    cnf.additional.insert(
        "x5t#S256".to_owned(),
        json!("bDlkZGM4MDMwNWQ5YWE5MmVmZjk3ZDg4OWRjZWJkNTM"),
    );
    let credential = present(cnf, &holder).await;
    assert!(matches!(
        validate(resolver(), &credential).await,
        Err(SdJwtValidationError::NoHolderKey(KeyReferenceError::UnsupportedConfirmation(method)))
            if method == "x5t#S256"
    ));

    // `jku` is a reference, but nothing in the crate fetches it.
    let mut cnf = Confirmation::default();
    cnf.kid = Some("key-1".to_owned());
    cnf.additional
        .insert("jku".to_owned(), json!("https://holder.example/jwks"));
    let credential = present(cnf, &holder).await;
    assert!(matches!(
        validate(resolver(), &credential).await,
        Err(SdJwtValidationError::Validation(ValidationError::KeyResolution {
            key,
            source: KeyResolutionError::Unsupported(_),
        })) if matches!(&*key, KeyReference::Jku { kid: Some(kid), .. } if kid == "key-1")
    ));
}

#[tokio::test]
async fn cnf_kid_that_does_not_resolve_for_authentication() {
    let holder = Es256Signer::rfc7515_a3();

    // A DID nobody resolves.
    let unknown = DidUrl::parse("did:example:holder#key-1").unwrap();
    let credential = present(Confirmation::kid(unknown.as_str()), &holder).await;
    assert!(matches!(
        validate(resolver(), &credential).await,
        Err(SdJwtValidationError::Validation(ValidationError::KeyResolution {
            key,
            ..
        })) if *key == KeyReference::DidUrl(unknown.clone())
    ));

    // A key listed under `assertionMethod` only.
    struct IssuerOnly(Resolver);

    #[async_trait::async_trait]
    impl KeyResolver for IssuerOnly {
        async fn resolve_key(
            &self,
            key: &KeyReference,
            role: KeyRole,
        ) -> Result<Jwk, KeyResolutionError> {
            if role == KeyRole::Subject {
                return Err(KeyResolutionError::msg("not under `authentication`"));
            }
            self.0.resolve_key(key, role).await
        }
    }
    let credential = present(Confirmation::kid(holder_kid().as_str()), &holder).await;
    let error = validate(IssuerOnly(resolver()), &credential)
        .await
        .unwrap_err();
    assert!(matches!(
        &error,
        SdJwtValidationError::Validation(ValidationError::KeyResolution {
            key,
            ..
        }) if **key == KeyReference::DidUrl(holder_kid())
    ));
    assert_eq!(
        error.to_string(),
        format!("resolving key {}: not under `authentication`", holder_kid())
    );

    // A key binding JWT signed by a key other than the one `cnf.kid` names.
    let other = Es256Signer {
        key: p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap(),
        kid: None,
    };
    let credential = present(Confirmation::kid(holder_kid().as_str()), &other).await;
    assert!(matches!(
        validate(resolver(), &credential).await,
        Err(SdJwtValidationError::Validation(
            ValidationError::Signature(VerificationError::InvalidSignature)
        ))
    ));
}

#[test]
fn from_confirmation_precedence() {
    let key = Es256Signer::rfc7515_a3().public_jwk();
    let mut both = Confirmation::jwk(&key);
    both.kid = Some(holder_kid().to_string());
    assert_eq!(
        KeyReference::from_confirmation(&both).unwrap(),
        KeyReference::Jwk(Box::new(key.clone()))
    );
    assert_eq!(
        KeyReference::from_confirmation(&Confirmation::kid(holder_kid().as_str())).unwrap(),
        KeyReference::DidUrl(holder_kid())
    );
    // A DID URL `kid` wins over `jku`.
    let mut kid_and_jku = Confirmation::kid(holder_kid().as_str());
    kid_and_jku
        .additional
        .insert("jku".to_owned(), json!("https://holder.example/jwks"));
    assert_eq!(
        KeyReference::from_confirmation(&kid_and_jku).unwrap(),
        KeyReference::DidUrl(holder_kid())
    );
    let mut bad_jku = Confirmation::default();
    bad_jku.additional.insert("jku".to_owned(), json!("jwks"));
    assert!(matches!(
        KeyReference::from_confirmation(&bad_jku),
        Err(KeyReferenceError::InvalidUrl {
            parameter: "jku",
            ..
        })
    ));
    let private: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": common::RFC7515_A3_X, "y": common::RFC7515_A3_Y, "d": common::RFC7515_A3_D
    }))
    .unwrap();
    let mut leaked = Confirmation::default();
    leaked.jwk = Some(private);
    assert!(matches!(
        KeyReference::from_confirmation(&leaked),
        Err(KeyReferenceError::InvalidJwk(_))
    ));
}

#[tokio::test]
async fn key_binding_jwt_claims_are_returned() {
    let holder = Es256Signer::rfc7515_a3();
    let credential = present(Confirmation::kid(holder_kid().as_str()), &holder).await;
    let validated = validate(resolver(), &credential).await.unwrap();
    let claims: &JwtClaims = validated.key_binding.as_ref().unwrap();
    assert_eq!(claims.additional["nonce"], NONCE);
}
