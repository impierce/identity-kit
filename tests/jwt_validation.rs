//! `JwtValidator` on plain JWTs: the access token of RFC 9068 §2.2 and a token from a DID
//! issuer, then one failure per check. Signatures are made with the RFC 8037 Appendix A.1 and
//! RFC 7515 Appendix A.3 keys; the RS256 key of RFC 9068's example is not published.
#![cfg(feature = "did-key")]

mod common;

use core::time::Duration;
use std::error::Error as _;

use identity_kit::jose::{
    DefaultVerifier, Jwk, JwsAlgorithm, JwsError, JwsHeader, JwtClaims, OneOrMany, Signer,
    VerificationError, encode_compact,
};
use identity_kit::methods::DidKey;
use identity_kit::resolver::{
    IssuerBinding, JwkResolver, JwtValidationError, JwtValidationOptions, JwtValidator,
    KeyReference, KeyReferenceError, KeyResolutionError, KeyResolver, KeyRole, Resolver,
};
use serde_json::{Value, json};

use common::fixtures::RefusingRole;
use common::{Ed25519Signer, Es256Signer};

/// The `kid` of the RFC 9068 §2.2 example header.
const KID: &str = "RjEwOwOA";
/// The `iss` of the RFC 9068 §2.2 example.
const ISSUER: &str = "https://authorization-server.example.com/";
/// The `aud` of the RFC 9068 §2.2 example.
const AUDIENCE: &str = "https://rs.example.com/";
/// Between the `iat` and the `exp` of the RFC 9068 §2.2 example.
const NOW: i64 = 1_620_000_000;

/// The claims of the access token of RFC 9068 §2.2.
fn access_token_claims() -> Value {
    json!({
        "iss": ISSUER,
        "sub": "5ba552d67",
        "aud": AUDIENCE,
        "exp": 1_639_528_912,
        "iat": 1_618_354_090,
        "jti": "dbe39bf3a3ba4238a513f51d6e1691c4",
        "client_id": "s6BhdRkqt3",
        "scope": "openid profile reademail"
    })
}

/// The header of RFC 9068 §2.2, with the algorithm of `signer`.
fn access_token_header(signer: &dyn Signer) -> JwsHeader {
    JwsHeader::new(signer.alg())
        .with_typ("at+JWT")
        .with_kid(KID)
}

async fn sign(header: &JwsHeader, claims: &Value, signer: &dyn Signer) -> String {
    encode_compact(header, &serde_json::to_vec(claims).unwrap(), signer)
        .await
        .unwrap()
}

/// The access token of RFC 9068 §2.2, signed with the RFC 8037 key.
async fn access_token() -> String {
    let signer = Ed25519Signer::rfc8037();
    sign(
        &access_token_header(&signer),
        &access_token_claims(),
        &signer,
    )
    .await
}

/// The key set of the authorization server: the RFC 8037 key under `KID`, the way an
/// application would resolve a `kid` against the key set of an issuer it trusts.
struct AuthorizationServer;

#[async_trait::async_trait]
impl KeyResolver for AuthorizationServer {
    async fn resolve_key(&self, key: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
        match key {
            KeyReference::Jwks { issuer, kid } if issuer.as_str() == ISSUER && kid == KID => {
                Ok(Ed25519Signer::rfc8037().public_jwk())
            }
            KeyReference::Jwks { kid, .. } => {
                Err(KeyResolutionError::msg(format!("no key `{kid}`")))
            }
            other => Err(KeyResolutionError::unsupported(other)),
        }
    }
}

fn validator() -> JwtValidator<AuthorizationServer> {
    JwtValidator::new(AuthorizationServer, DefaultVerifier)
}

/// What a resource server requires of an access token (RFC 9068 §4).
fn access_token_options() -> JwtValidationOptions {
    JwtValidationOptions::new()
        .with_typ("application/at+jwt")
        .with_algorithm(JwsAlgorithm::EdDSA)
        .with_algorithm(JwsAlgorithm::ES256)
        .with_issuer(ISSUER)
        .with_audience(AUDIENCE)
        .with_required_claims(["exp", "iat", "jti", "sub", "client_id"])
        .at(NOW)
}

#[tokio::test]
async fn access_token_validates() {
    let validated = validator()
        .validate(&access_token().await, &access_token_options())
        .await
        .unwrap();
    assert_eq!(validated.header.typ.as_deref(), Some("at+JWT"));
    assert_eq!(validated.claims.sub.as_deref(), Some("5ba552d67"));
    assert_eq!(validated.claims.additional["client_id"], "s6BhdRkqt3");
    assert_eq!(validated.key, Ed25519Signer::rfc8037().public_jwk());
    assert!(matches!(
        validated.key_reference,
        KeyReference::Jwks { ref kid, .. } if kid == KID
    ));
}

/// The claims of an access token a resource server reads.
#[derive(serde::Deserialize)]
struct AccessToken {
    client_id: String,
    scope: String,
    exp: i64,
}

/// A `client_id` the example's string does not fit.
#[derive(Debug, serde::Deserialize)]
struct Mistyped {
    #[expect(dead_code, reason = "read only to fail")]
    client_id: u64,
}

#[tokio::test]
async fn access_token_reads_into_a_type() {
    let validated = validator()
        .validate_as::<AccessToken>(&access_token().await, &access_token_options())
        .await
        .unwrap();
    assert_eq!(validated.claims.client_id, "s6BhdRkqt3");
    assert_eq!(validated.claims.scope, "openid profile reademail");
    assert_eq!(validated.claims.exp, 1_639_528_912);

    let error = validator()
        .validate_as::<Mistyped>(&access_token().await, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::Claims(_)));
    assert!(error.source().unwrap().is::<serde_json::Error>());
}

/// A `#fragment` `kid` joined with a `did:key` `iss`, resolved through the DID document: the key
/// belongs to the issuer.
#[tokio::test]
async fn did_issuer_with_relative_kid() {
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(format!("#{}", did.method_specific_id()));
    let token = sign(
        &header,
        &json!({ "iss": did.as_str(), "iat": NOW }),
        &signer,
    )
    .await;

    let validator = JwtValidator::new(
        Resolver::builder().with(DidKey::default()).build(),
        DefaultVerifier,
    );
    let validated = validator
        .validate(&token, &JwtValidationOptions::new().with_typ("JWT").at(NOW))
        .await
        .unwrap();
    assert_eq!(validated.claims.iss.as_deref(), Some(did.as_str()));

    // The same key under `authentication`, for a token proving possession. Behind a resolver
    // that finds no key under `assertionMethod`, only that role resolves it.
    let validator = JwtValidator::new(
        RefusingRole {
            inner: Resolver::builder().with(DidKey::default()).build(),
            role: KeyRole::Issuer,
        },
        DefaultVerifier,
    );
    let subject = JwtValidationOptions::new()
        .with_role(KeyRole::Subject)
        .at(NOW);
    assert_eq!(subject.role, KeyRole::Subject);
    validator.validate(&token, &subject).await.unwrap();
    assert!(matches!(
        validator
            .validate(&token, &JwtValidationOptions::new().at(NOW))
            .await,
        Err(JwtValidationError::KeyResolution { .. })
    ));
}

#[tokio::test]
async fn key_of_another_party() {
    // The key is the `did:key` of the RFC 8037 key, named by an absolute DID URL, while `iss`
    // is another DID.
    let signer = Ed25519Signer::rfc8037();
    let did = DidKey::did(&signer.public_jwk()).unwrap();
    let kid = format!("{did}#{}", did.method_specific_id());
    let header = JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(&kid);
    let token = sign(&header, &json!({ "iss": "did:example:123" }), &signer).await;

    let validator = JwtValidator::new(
        Resolver::builder().with(DidKey::default()).build(),
        DefaultVerifier,
    );
    let options = JwtValidationOptions::new().at(NOW);
    let error = validator.validate(&token, &options).await.unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::KeyNotIssuers { issuer: Some(ref issuer), ref key }
            if issuer == "did:example:123" && key.to_string() == kid
    ));

    // A resolver of trusted keys may waive the binding.
    validator
        .validate(&token, &options.with_issuer_binding(IssuerBinding::Any))
        .await
        .unwrap();
}

#[tokio::test]
async fn key_by_value() {
    // A `jwk` header binds to a token without `iss` or with its thumbprint as `iss` (RFC 8037
    // Appendix A.3), and to nothing else.
    let signer = Es256Signer::rfc7515_a3();
    let key = signer.public_jwk();
    let mut header = JwsHeader::new(JwsAlgorithm::ES256);
    header.jwk = Some(key.clone());
    let validator = JwtValidator::new(JwkResolver, DefaultVerifier);
    let options = JwtValidationOptions::new().at(NOW);

    let token = sign(&header, &json!({ "nonce": "n-0S6_WzA2Mj" }), &signer).await;
    assert_eq!(validator.validate(&token, &options).await.unwrap().key, key);

    let thumbprint = key.thumbprint_sha256().unwrap();
    let token = sign(&header, &json!({ "iss": thumbprint }), &signer).await;
    validator.validate(&token, &options).await.unwrap();

    let token = sign(&header, &json!({ "iss": ISSUER }), &signer).await;
    let error = validator.validate(&token, &options).await.unwrap_err();
    assert!(matches!(error, JwtValidationError::KeyNotIssuers { .. }));
}

// ---------------------------------------------------------------------------------------------
// One failure per check
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn not_a_jws() {
    let error = validator()
        .validate("not.a.jws.at.all", &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::Jws(JwsError::InvalidFormat { parts: 5 })
    ));
}

#[tokio::test]
async fn algorithm_not_allowed() {
    let options = JwtValidationOptions::new()
        .with_algorithm(JwsAlgorithm::ES256)
        .at(NOW);
    let error = validator()
        .validate(&access_token().await, &options)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::DisallowedAlgorithm(JwsAlgorithm::EdDSA)
    ));
    assert_eq!(error.to_string(), "algorithm `EdDSA` is not accepted");
}

#[tokio::test]
async fn typ() {
    let token = access_token().await;
    let validator = validator();
    // RFC 7515 §4.1.9: case-insensitive, `application/` optional on either side.
    for typ in [
        "at+jwt",
        "AT+JWT",
        "application/at+jwt",
        "Application/AT+JWT",
    ] {
        validator
            .validate(&token, &access_token_options().with_typ(typ))
            .await
            .unwrap();
    }

    let error = validator
        .validate(&token, &access_token_options().with_typ("JWT"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::UnexpectedTyp { ref expected, found: Some(ref found) }
            if expected == "JWT" && found == "at+JWT"
    ));
    // Only `application/` is optional: another 12-character prefix is part of the type.
    let error = validator
        .validate(
            &token,
            &access_token_options().with_typ("vnd.example/at+jwt"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::UnexpectedTyp { .. }));

    // A required `typ` must be there.
    let signer = Ed25519Signer::rfc8037();
    let untyped = sign(
        &JwsHeader::new(JwsAlgorithm::EdDSA).with_kid(KID),
        &access_token_claims(),
        &signer,
    )
    .await;
    let error = validator
        .validate(&untyped, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::UnexpectedTyp { found: None, .. }
    ));
}

#[tokio::test]
async fn payload_not_a_claims_set() {
    let signer = Ed25519Signer::rfc8037();
    let token = encode_compact(&access_token_header(&signer), b"[1, 2]", &signer)
        .await
        .unwrap();
    let error = validator()
        .validate(&token, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::Payload(_)));
    assert!(error.source().unwrap().is::<serde_json::Error>());
}

#[tokio::test]
async fn no_key_named() {
    // RFC 7515 Appendix A.3: the RFC 7519 §3.1 claims set, signed with ES256, without `kid`.
    let token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9\
                 leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFC\
                 gfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    let error = validator()
        .validate(token, &JwtValidationOptions::new().at(1_300_000_000))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::KeyReference(KeyReferenceError::Missing)
    ));
}

#[tokio::test]
async fn key_not_resolved() {
    let signer = Ed25519Signer::rfc8037();
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("at+jwt")
        .with_kid("unknown");
    let token = sign(&header, &access_token_claims(), &signer).await;
    let error = validator()
        .validate(&token, &access_token_options())
        .await
        .unwrap_err();
    let JwtValidationError::KeyResolution { ref source, .. } = error else {
        panic!("{error:?}");
    };
    assert_eq!(source.to_string(), "no key `unknown`");
    assert!(error.source().unwrap().is::<KeyResolutionError>());
}

#[tokio::test]
async fn signature_does_not_verify() {
    // Signed with the RFC 7515 A.3 key under the `kid` of the RFC 8037 one.
    let signer = Es256Signer::rfc7515_a3();
    let token = sign(
        &access_token_header(&signer),
        &access_token_claims(),
        &signer,
    )
    .await;
    let error = validator()
        .validate(&token, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::Signature(_)));
    assert!(error.source().unwrap().is::<VerificationError>());

    // A payload changed after signing.
    let token = access_token().await;
    let mut parts: Vec<&str> = token.split('.').collect();
    let tampered = common::encode(
        serde_json::to_string(&json!({ "iss": ISSUER, "sub": "admin" }))
            .unwrap()
            .as_bytes(),
    );
    parts[1] = &tampered;
    let error = validator()
        .validate(&parts.join("."), &JwtValidationOptions::new().at(NOW))
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::Signature(_)));
}

#[tokio::test]
async fn issuer_not_expected() {
    let options = access_token_options().with_issuer("https://other.example.com/");
    let error = validator()
        .validate(&access_token().await, &options)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::IssuerMismatch { ref expected, found: Some(ref found) }
            if expected == "https://other.example.com/" && found == ISSUER
    ));
}

#[tokio::test]
async fn audience() {
    let signer = Ed25519Signer::rfc8037();
    let mut claims = access_token_claims();
    claims["aud"] = json!(["https://other.example.com/", AUDIENCE]);
    let token = sign(&access_token_header(&signer), &claims, &signer).await;
    validator()
        .validate(&token, &access_token_options())
        .await
        .unwrap();

    let options = access_token_options().with_audience("https://third.example.com/");
    let error = validator().validate(&token, &options).await.unwrap_err();
    let JwtValidationError::AudienceMismatch {
        ref expected,
        ref found,
    } = error
    else {
        panic!("{error:?}");
    };
    assert_eq!(expected, "https://third.example.com/");
    assert_eq!(
        found.as_ref().map(OneOrMany::len),
        Some(2),
        "the `aud` found is reported"
    );

    // No `aud` at all.
    claims.as_object_mut().unwrap().remove("aud");
    let token = sign(&access_token_header(&signer), &claims, &signer).await;
    let error = validator()
        .validate(&token, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::AudienceMismatch { found: None, .. }
    ));
}

#[tokio::test]
async fn validity_period() {
    let token = access_token().await;
    let validator = validator();

    // `exp` 1639528912 has passed a second later, and not with a leeway.
    let error = validator
        .validate(&token, &access_token_options().at(1_639_528_913))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::Expired {
            expired_at: 1_639_528_912,
            now: 1_639_528_913
        }
    ));
    assert_eq!(
        error.to_string(),
        "expired at 1639528912 (now is 1639528913)"
    );
    // At `exp` itself the token has expired (RFC 7519 §4.1.4: before, not at).
    assert!(matches!(
        validator
            .validate(&token, &access_token_options().at(1_639_528_912))
            .await,
        Err(JwtValidationError::Expired { .. })
    ));
    validator
        .validate(
            &token,
            &access_token_options()
                .at(1_639_528_913)
                .with_leeway(Duration::from_secs(60)),
        )
        .await
        .unwrap();

    // `iat` 1618354090 is in the future a second earlier.
    let error = validator
        .validate(&token, &access_token_options().at(1_618_354_089))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::IssuedInFuture {
            issued_at: 1_618_354_090,
            now: 1_618_354_089
        }
    ));
    validator
        .validate(
            &token,
            &access_token_options()
                .at(1_618_354_089)
                .with_leeway(Duration::from_secs(1)),
        )
        .await
        .unwrap();

    // `nbf`.
    let signer = Ed25519Signer::rfc8037();
    let mut claims = access_token_claims();
    claims["nbf"] = json!(NOW + 10);
    let token = sign(&access_token_header(&signer), &claims, &signer).await;
    let error = validator
        .validate(&token, &access_token_options())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        JwtValidationError::NotYetValid { not_before, now: NOW } if not_before == NOW + 10
    ));
    validator
        .validate(
            &token,
            &access_token_options().with_leeway(Duration::from_secs(10)),
        )
        .await
        .unwrap();

    // A leeway past what `i64` holds saturates.
    validator
        .validate(
            &token,
            &access_token_options().with_leeway(Duration::from_secs(u64::MAX)),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn required_claims() {
    let signer = Ed25519Signer::rfc8037();
    for missing in ["exp", "iat", "jti", "sub", "client_id"] {
        let mut claims = access_token_claims();
        claims.as_object_mut().unwrap().remove(missing);
        let token = sign(&access_token_header(&signer), &claims, &signer).await;
        let error = validator()
            .validate(&token, &access_token_options())
            .await
            .unwrap_err();
        assert!(
            matches!(error, JwtValidationError::MissingClaim(ref claim) if claim == missing),
            "{missing}: {error:?}"
        );
    }

    // Every registered claim is looked up in its field.
    let options = access_token_options().with_required_claims(JwtClaims::REGISTERED);
    let error = validator()
        .validate(&access_token().await, &options)
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::MissingClaim(ref claim) if claim == "nbf"));
}

#[tokio::test]
async fn default_options() {
    // Any algorithm, any `typ`, no issuer, audience or claim required, the current time: the
    // RFC 9068 example has expired since 2021.
    let error = validator()
        .validate(&access_token().await, &JwtValidationOptions::new())
        .await
        .unwrap_err();
    assert!(matches!(error, JwtValidationError::Expired { .. }));
    assert!(JwtValidationOptions::new().now() > 1_639_528_912);

    // Without `exp`, it passes.
    let signer = Ed25519Signer::rfc8037();
    let mut claims = access_token_claims();
    claims.as_object_mut().unwrap().remove("exp");
    let token = sign(&access_token_header(&signer), &claims, &signer).await;
    validator()
        .validate(&token, &JwtValidationOptions::new())
        .await
        .unwrap();
}
