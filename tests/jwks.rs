//! `JwksResolver` (feature `jwks`): JWT VC issuer metadata (SD-JWT VC §3.5) served by a mock
//! `HttpClient`, with `jwks` and `jwks_uri`, the path form of the well-known URL, the issuer and
//! key checks, caching, and the identity credential of SD-JWT VC §2.3 validated with its issuer
//! key found through the metadata of its HTTPS `iss`.
#![cfg(feature = "jwks")]
#![expect(
    clippy::unreadable_literal,
    reason = "numbers are written as the specifications' examples write them"
)]

mod common;

use std::time::Duration;

use identity_kit::jose::Jwk;
use identity_kit::resolver::{
    JwksError, JwksResolver, KeyReference, KeyResolutionError, KeyResolver, KeyRole,
};
use serde_json::{Value, json};
use url::Url;

use common::http::Web;

/// RFC 9901 Appendix A.5: the issuer key of the SD-JWT and SD-JWT VC examples.
fn issuer_key() -> Value {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
        "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
    })
}

/// `issuer_key` with `kid`.
fn with_kid(kid: &str) -> Value {
    let mut key = issuer_key();
    key["kid"] = json!(kid);
    key
}

/// RFC 8037 Appendix A.2, with `kid`.
fn ed25519(kid: &str) -> Value {
    json!({
        "kid": kid, "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    })
}

fn reference(issuer: &str, kid: &str) -> KeyReference {
    KeyReference::Jwks {
        issuer: Url::parse(issuer).unwrap(),
        kid: kid.to_owned(),
    }
}

async fn resolve(resolver: &JwksResolver<Web>, issuer: &str, kid: &str) -> Result<Jwk, JwksError> {
    resolver
        .resolve_key(&reference(issuer, kid), KeyRole::Issuer)
        .await
        .map_err(|error| match error {
            KeyResolutionError::Failed(inner) => *inner.downcast::<JwksError>().unwrap(),
            other => panic!("unexpected {other:?}"),
        })
}

const ISSUER: &str = "https://example.com";
const WELL_KNOWN: &str = "https://example.com/.well-known/jwt-vc-issuer";

#[tokio::test]
async fn inline_jwks() {
    // The shape of the first example of SD-JWT VC §3.5, with the A.5 key.
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks": {"keys": [with_kid("doc-signer-05-25-2022"), ed25519("other")]}}),
    );
    let resolver = JwksResolver::new(web);
    let key = resolve(&resolver, ISSUER, "doc-signer-05-25-2022")
        .await
        .unwrap();
    assert_eq!(
        key.thumbprint_sha256().unwrap(),
        serde_json::from_value::<Jwk>(issuer_key())
            .unwrap()
            .thumbprint_sha256()
            .unwrap()
    );
    assert_eq!(resolver.client().fetched(), [WELL_KNOWN]);

    // The role does not matter for a key set.
    assert!(
        resolver
            .resolve_key(&reference(ISSUER, "other"), KeyRole::Subject)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn jwks_uri() {
    // The shape of the second example of SD-JWT VC §3.5.
    let jwks_uri = "https://jwt-vc-issuer.example.org/my_public_keys.jwks";
    let web = Web::default()
        .serve_json(WELL_KNOWN, json!({"issuer": ISSUER, "jwks_uri": jwks_uri}))
        .serve_json(
            jwks_uri,
            json!({"keys": [with_kid("doc-signer-05-25-2022")]}),
        );
    let resolver = JwksResolver::new(web);
    assert!(
        resolve(&resolver, ISSUER, "doc-signer-05-25-2022")
            .await
            .is_ok()
    );
    assert_eq!(resolver.client().fetched(), [WELL_KNOWN, jwks_uri]);

    // `jwks_uri` over plain HTTP is not fetched.
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks_uri": "http://jwt-vc-issuer.example.org/keys"}),
    );
    let resolver = JwksResolver::new(web);
    assert!(matches!(
        resolve(&resolver, ISSUER, "key").await,
        Err(JwksError::NotHttps(url)) if url.scheme() == "http"
    ));
    assert_eq!(resolver.client().fetched(), [WELL_KNOWN]);
}

#[tokio::test]
async fn well_known_url_inserts_before_the_path() {
    // SD-JWT VC §3.5: between the host and the path; a trailing `/` is dropped; the port stays.
    for (issuer, well_known) in [
        (
            "https://example.com/tenant/1234",
            "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
        ),
        (
            "https://example.com/tenant/1234/",
            "https://example.com/.well-known/jwt-vc-issuer/tenant/1234",
        ),
        (
            "https://example.com:8443/issuer",
            "https://example.com:8443/.well-known/jwt-vc-issuer/issuer",
        ),
        ("https://example.com/", WELL_KNOWN),
    ] {
        let web = Web::default().serve_json(
            well_known,
            json!({"issuer": issuer, "jwks": {"keys": [ed25519("key-1")]}}),
        );
        let resolver = JwksResolver::new(web);
        resolve(&resolver, issuer, "key-1").await.unwrap();
        assert_eq!(resolver.client().fetched(), [well_known], "{issuer}");
    }
}

#[tokio::test]
async fn issuer_must_be_https_without_query_or_fragment() {
    let resolver = JwksResolver::new(Web::default());
    assert!(matches!(
        resolve(&resolver, "http://example.com", "key-1").await,
        Err(JwksError::NotHttps(_))
    ));
    for issuer in [
        "https://example.com/?tenant=1",
        "https://example.com/#tenant",
        "https://user:secret@example.com",
        "https://user@example.com",
    ] {
        assert!(matches!(
            resolve(&resolver, issuer, "key-1").await,
            Err(JwksError::InvalidIssuer(_))
        ));
    }
    assert!(resolver.client().fetched().is_empty());
}

#[tokio::test]
async fn metadata_must_name_the_issuer() {
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": "https://attacker.example", "jwks": {"keys": [ed25519("key-1")]}}),
    );
    let error = resolve(&JwksResolver::new(web), ISSUER, "key-1")
        .await
        .unwrap_err();
    assert!(
        matches!(&error, JwksError::IssuerMismatch { found, .. } if found == "https://attacker.example")
    );
    assert_eq!(
        error.to_string(),
        "the metadata of `https://example.com/` names the issuer \"https://attacker.example\""
    );
}

#[tokio::test]
async fn kid_must_name_exactly_one_key() {
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks": {"keys": [
            ed25519("twice"), with_kid("twice"), ed25519("once"),
            {"kty": 7, "kid": "exotic"}
        ]}}),
    );
    let resolver = JwksResolver::new(web);
    assert!(matches!(
        resolve(&resolver, ISSUER, "missing").await,
        Err(JwksError::UnknownKid { kid, .. }) if kid == "missing"
    ));
    assert!(matches!(
        resolve(&resolver, ISSUER, "twice").await,
        Err(JwksError::DuplicateKid { kid, .. }) if kid == "twice"
    ));
    // A key the crate does not read spoils only itself.
    assert!(resolve(&resolver, ISSUER, "once").await.is_ok());
    assert!(matches!(
        resolve(&resolver, ISSUER, "exotic").await,
        Err(JwksError::InvalidKey { kid, .. }) if kid == "exotic"
    ));
}

#[tokio::test]
async fn private_keys_are_refused() {
    let mut private = ed25519("leaked");
    private["d"] = json!("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks": {"keys": [private]}}),
    );
    assert!(matches!(
        resolve(&JwksResolver::new(web), ISSUER, "leaked").await,
        Err(JwksError::InvalidKey { .. })
    ));
}

#[tokio::test]
async fn malformed_metadata() {
    for body in [
        json!({"issuer": ISSUER}),
        json!({"issuer": ISSUER, "jwks": {"keys": []}, "jwks_uri": "https://example.com/keys"}),
        json!({"jwks": {"keys": []}}),
        json!({"issuer": ISSUER, "jwks": {"no_keys": []}}),
        json!(["not", "an", "object"]),
    ] {
        let web = Web::default().serve_json(WELL_KNOWN, body.clone());
        assert!(
            matches!(
                resolve(&JwksResolver::new(web), ISSUER, "key-1").await,
                Err(JwksError::InvalidMetadata { .. })
            ),
            "{body}"
        );
    }
    let web = Web::default().serving(WELL_KNOWN, 404, "");
    assert!(matches!(
        resolve(&JwksResolver::new(web), ISSUER, "key-1").await,
        Err(JwksError::HttpStatus { status: 404, .. })
    ));
    assert!(matches!(
        resolve(&JwksResolver::new(Web::default()), ISSUER, "key-1").await,
        Err(JwksError::Http { .. })
    ));
}

#[tokio::test]
async fn key_sets_are_cached_per_issuer() {
    let other = "https://other.example";
    let web = Web::default()
        .serve_json(
            WELL_KNOWN,
            json!({"issuer": ISSUER, "jwks": {"keys": [ed25519("key-1"), ed25519("key-2")]}}),
        )
        .serve_json(
            "https://other.example/.well-known/jwt-vc-issuer",
            json!({"issuer": other, "jwks": {"keys": [ed25519("key-1")]}}),
        );
    let resolver = JwksResolver::new(web);
    assert_eq!(resolver.ttl(), JwksResolver::<Web>::DEFAULT_TTL);
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    resolve(&resolver, ISSUER, "key-2").await.unwrap();
    // An unknown `kid` is answered from the cache too, until the entry expires.
    assert!(resolve(&resolver, ISSUER, "key-3").await.is_err());
    resolve(&resolver, other, "key-1").await.unwrap();
    assert_eq!(resolver.client().fetched().len(), 2);

    // With a capacity of one, the other issuer's set pushes the first one out.
    let web = Web::default()
        .serve_json(
            WELL_KNOWN,
            json!({"issuer": ISSUER, "jwks": {"keys": [ed25519("key-1")]}}),
        )
        .serve_json(
            "https://other.example/.well-known/jwt-vc-issuer",
            json!({"issuer": other, "jwks": {"keys": [ed25519("key-1")]}}),
        );
    let resolver = JwksResolver::new(web).with_capacity(1);
    for issuer in [ISSUER, other, ISSUER] {
        resolve(&resolver, issuer, "key-1").await.unwrap();
    }
    assert_eq!(resolver.client().fetched().len(), 3);

    // A zero time to live keeps nothing.
    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks": {"keys": [ed25519("key-1")]}}),
    );
    let resolver = JwksResolver::new(web).with_ttl(Duration::ZERO);
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    assert_eq!(resolver.client().fetched().len(), 2);

    let web = Web::default().serve_json(
        WELL_KNOWN,
        json!({"issuer": ISSUER, "jwks": {"keys": [ed25519("key-1")]}}),
    );
    let resolver = JwksResolver::new(web).with_ttl(Duration::from_millis(20));
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    assert_eq!(resolver.client().fetched().len(), 1);
    tokio::time::sleep(Duration::from_millis(50)).await;
    resolve(&resolver, ISSUER, "key-1").await.unwrap();
    assert_eq!(resolver.client().fetched().len(), 2);
    assert!(format!("{resolver:?}").starts_with("JwksResolver {"));
}

#[tokio::test]
async fn other_references_are_unsupported() {
    let resolver = JwksResolver::new(Web::default());
    let did_url = identity_kit::did::DidUrl::parse("did:example:123#key-1").unwrap();
    for reference in [
        KeyReference::DidUrl(did_url),
        KeyReference::Jwk(Box::new(serde_json::from_value(ed25519("key-1")).unwrap())),
        KeyReference::X509Chain(vec![b"leaf".to_vec()]),
        KeyReference::Jku {
            url: Url::parse("https://example.com/keys").unwrap(),
            kid: None,
        },
    ] {
        assert!(
            resolver
                .resolve_key(&reference, KeyRole::Issuer)
                .await
                .unwrap_err()
                .is_unsupported()
        );
    }
    assert!(resolver.client().fetched().is_empty());
}

#[tokio::test]
async fn a_failed_fetch_keeps_its_cause() {
    let web = Web::default().failing(WELL_KNOWN, &format!("no route to {WELL_KNOWN}"));
    let error = JwksResolver::new(web)
        .resolve_key(&reference(ISSUER, "key-1"), KeyRole::Issuer)
        .await
        .unwrap_err();
    let cause = std::error::Error::source(&error).expect("the HTTP error");
    assert_eq!(cause.to_string(), format!("no route to {WELL_KNOWN}"));
}

/// The identity credential of SD-JWT VC §2.3, presented with key binding, its issuer key found
/// through the metadata of its HTTPS `iss`.
#[cfg(feature = "sd-jwt")]
#[tokio::test]
async fn sd_jwt_vc_issued_by_an_https_issuer() {
    use chrono::{TimeZone as _, Utc};
    use identity_kit::jose::DefaultVerifier;
    use identity_kit::resolver::{CompositeKeyResolver, Resolver};
    use identity_kit::sd_jwt_vc::{
        KeyBindingOptions, SdJwtCredentialValidator, SdJwtValidationError, SdJwtValidationOptions,
        SdJwtVc,
    };
    use identity_kit::vc::validation::{TimeOptions, ValidationError};

    let presentation = SdJwtVc::parse(
        include_str!("vectors/sd_jwt_vc/identity_credential/presentation.txt").trim(),
    )
    .unwrap();
    assert_eq!(
        presentation.claims().iss.as_deref(),
        Some("https://example.com/issuer")
    );
    let web = Web::default().serve_json(
        "https://example.com/.well-known/jwt-vc-issuer/issuer",
        json!({
            "issuer": "https://example.com/issuer",
            "jwks": {"keys": [with_kid("doc-signer-05-25-2022")]}
        }),
    );
    // The key binding JWT was issued at 1792011060.
    let now = TimeOptions::at(Utc.timestamp_opt(1792011060, 0).unwrap());
    let options = SdJwtValidationOptions::new()
        .with_time(now)
        .with_key_binding(
            KeyBindingOptions::new("https://example.com/verifier", "1234567890").with_time(now),
        );
    let resolver = CompositeKeyResolver::new()
        .with(Resolver::builder().build())
        .with(JwksResolver::new(web));
    let validated = SdJwtCredentialValidator::new(resolver, DefaultVerifier)
        .validate(presentation.sd_jwt(), &options)
        .await
        .unwrap();
    assert_eq!(
        validated.issuer_key,
        reference("https://example.com/issuer", "doc-signer-05-25-2022")
    );
    assert!(validated.key_binding.is_some());
    assert!(matches!(
        &validated.holder_key,
        Some((KeyReference::Jwk(_), _))
    ));

    // Without the key set the issuer is unknown, and a DID resolver alone does not look.
    let error = SdJwtCredentialValidator::new(Resolver::builder().build(), DefaultVerifier)
        .validate(presentation.sd_jwt(), &options)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::KeyResolution {
            key,
            source: KeyResolutionError::Unsupported(_),
        }) if matches!(*key, KeyReference::Jwks { .. })
    ));

    // Another issuer's metadata naming the same key does not make it this issuer's: the
    // metadata must name the issuer.
    let web = Web::default().serve_json(
        "https://example.com/.well-known/jwt-vc-issuer/issuer",
        json!({
            "issuer": "https://example.com/other",
            "jwks": {"keys": [with_kid("doc-signer-05-25-2022")]}
        }),
    );
    let error = SdJwtCredentialValidator::new(JwksResolver::new(web), DefaultVerifier)
        .validate(presentation.sd_jwt(), &options)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        SdJwtValidationError::Validation(ValidationError::KeyResolution { .. })
    ));
}
