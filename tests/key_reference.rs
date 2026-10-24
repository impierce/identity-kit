//! `KeyReference`, `KeyRole` and the key resolvers of the lower layer (ADR 0006): the
//! precedence of `KeyReference::from_jws` over hand-built headers, RFC 7515 Appendix A.3 signed
//! with its key in a `jwk` header, the binding rule table, `Resolver`, `JwkResolver` and
//! `CompositeKeyResolver`.
#![cfg(all(feature = "did-key", feature = "did-jwk"))]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use identity_kit::did::{DidUrl, VerificationRelationship};
use identity_kit::jose::{
    CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, encode_compact,
};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::{
    CompositeKeyResolver, JwkResolver, KeyReference, KeyReferenceError, KeyResolutionError,
    KeyResolver, KeyRole, Resolver,
};
use serde_json::{Value, json};
use url::Url;

use common::{Ed25519Signer, Es256Signer, RFC8037_X, unsigned_jwt};

/// RFC 8037 Appendix A.3: the thumbprint of the A.2 public key.
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

/// A JWS with `header`, an empty claims set and a placeholder signature.
fn jws(header: Value) -> CompactJws {
    CompactJws::decode(&unsigned_jwt(&header, &json!({}))).unwrap()
}

fn from_jws(header: Value, iss: Option<&str>) -> Result<KeyReference, KeyReferenceError> {
    KeyReference::from_jws(&jws(header), iss)
}

/// RFC 8037 Appendix A.2.
fn ed25519() -> Jwk {
    serde_json::from_value(json!({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X})).unwrap()
}

fn did_url(s: &str) -> DidUrl {
    DidUrl::parse(s).unwrap()
}

fn resolver() -> Resolver {
    Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build()
}

// ---------------------------------------------------------------------------------------------
// `from_jws`
// ---------------------------------------------------------------------------------------------

#[test]
fn absolute_kid_is_a_did_url() {
    let kid = "did:example:123#key-1";
    for iss in [
        None,
        Some("did:example:other"),
        Some("https://issuer.example"),
    ] {
        assert_eq!(
            from_jws(json!({"alg": "EdDSA", "kid": kid}), iss).unwrap(),
            KeyReference::DidUrl(did_url(kid))
        );
    }
    // A DID URL in `kid` wins over a `jwk` header.
    assert_eq!(
        from_jws(json!({"alg": "EdDSA", "kid": kid, "jwk": ed25519()}), None).unwrap(),
        KeyReference::DidUrl(did_url(kid))
    );
}

#[test]
fn did_url_with_path_or_parameters_is_refused() {
    for kid in [
        "did:example:123?versionId=1#key-1",
        "did:example:123?versionTime=2021-05-10T17:00:00Z#key-1",
        "did:example:123/path#key-1",
    ] {
        assert!(matches!(
            from_jws(json!({"alg": "EdDSA", "kid": kid, "jwk": ed25519()}), None),
            Err(KeyReferenceError::KidWithParameters(url)) if url.as_str() == kid
        ));
    }
}

#[test]
fn relative_kid_is_joined_with_a_did_iss() {
    assert_eq!(
        from_jws(
            json!({"alg": "EdDSA", "kid": "#key-1"}),
            Some("did:example:123")
        )
        .unwrap(),
        KeyReference::DidUrl(did_url("did:example:123#key-1"))
    );
    // `did:key`, as a holder signing an ID token or a proof does.
    let did = DidKey::did(&ed25519()).unwrap();
    let fragment = format!("#{}", did.method_specific_id());
    assert_eq!(
        from_jws(json!({"alg": "EdDSA", "kid": fragment}), Some(did.as_str())).unwrap(),
        KeyReference::DidUrl(did.join(&fragment).unwrap())
    );
}

#[test]
fn relative_kid_needs_a_did_iss() {
    // No `iss` (absent, or not a string, which the caller passes as `None`), an `iss` that is
    // not a DID, and an HTTPS `iss`: a `#fragment` is never looked up in a key set.
    for iss in [None, Some("joe"), Some("https://issuer.example")] {
        let error = from_jws(
            json!({"alg": "EdDSA", "kid": "#key-1", "jwk": ed25519()}),
            iss,
        )
        .unwrap_err();
        assert!(
            matches!(&error, KeyReferenceError::RelativeKidWithoutIssuer(kid) if kid == "#key-1")
        );
        assert_eq!(
            error.to_string(),
            "`kid` \"#key-1\" is relative and `iss` is not a DID"
        );
    }
}

#[test]
fn kid_with_an_https_iss_is_a_jwks_key() {
    for (iss, normalized) in [
        ("https://issuer.example", "https://issuer.example/"),
        (
            "https://issuer.example/tenant/1",
            "https://issuer.example/tenant/1",
        ),
        ("HTTPS://Issuer.Example:443/a", "https://issuer.example/a"),
    ] {
        let reference = from_jws(json!({"alg": "ES256", "kid": "key-1"}), Some(iss)).unwrap();
        assert_eq!(
            reference,
            KeyReference::Jwks {
                issuer: Url::parse(normalized).unwrap(),
                kid: "key-1".to_owned()
            }
        );
    }
    // Not over plain HTTP: the `kid` is then refused, unless something else names the key.
    assert!(matches!(
        from_jws(json!({"alg": "ES256", "kid": "key-1"}), Some("http://issuer.example")),
        Err(KeyReferenceError::InvalidKid { kid, .. }) if kid == "key-1"
    ));
    assert_eq!(
        from_jws(
            json!({"alg": "EdDSA", "kid": "key-1", "jwk": ed25519()}),
            Some("http://issuer.example")
        )
        .unwrap(),
        KeyReference::Jwk(Box::new(ed25519()))
    );
}

#[test]
fn jwk_header_is_a_key_by_value() {
    assert_eq!(
        from_jws(json!({"alg": "EdDSA", "jwk": ed25519()}), None).unwrap(),
        KeyReference::Jwk(Box::new(ed25519()))
    );
    // A `kid` that names nothing by itself (a thumbprint, say) leaves the key to `jwk`.
    assert_eq!(
        from_jws(
            json!({"alg": "EdDSA", "kid": RFC8037_THUMBPRINT, "jwk": ed25519()}),
            Some("did:example:123")
        )
        .unwrap(),
        KeyReference::Jwk(Box::new(ed25519()))
    );
    // A private key in a header is a leak, not a reference.
    let private = json!({
        "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X,
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    });
    assert!(matches!(
        from_jws(json!({"alg": "EdDSA", "jwk": private}), None),
        Err(KeyReferenceError::InvalidJwk(_))
    ));
}

#[test]
fn x5c_header_is_a_certificate_chain() {
    let leaf = b"leaf certificate".to_vec();
    let root = b"root certificate".to_vec();
    let x5c = json!([STANDARD.encode(&leaf), STANDARD.encode(&root)]);
    let reference = from_jws(json!({"alg": "ES256", "x5c": x5c}), None).unwrap();
    assert_eq!(reference, KeyReference::X509Chain(vec![leaf, root]));
    assert_eq!(reference.to_string(), "`x5c` chain of 2 certificates");
    // `jwk` comes first.
    assert_eq!(
        from_jws(json!({"alg": "EdDSA", "jwk": ed25519(), "x5c": x5c}), None).unwrap(),
        KeyReference::Jwk(Box::new(ed25519()))
    );
    for x5c in [
        json!("MIIB"),
        json!([]),
        json!([42]),
        json!(["not base64!"]),
        // RFC 7515 §4.1.6: standard base64, not base64url.
        json!(["-_-_"]),
    ] {
        assert!(matches!(
            from_jws(json!({"alg": "ES256", "x5c": x5c}), None),
            Err(KeyReferenceError::InvalidX5c(_))
        ));
    }
}

#[test]
fn jku_header_is_a_key_set_url() {
    let url = Url::parse("https://issuer.example/jwks.json").unwrap();
    assert_eq!(
        from_jws(json!({"alg": "ES256", "jku": url.as_str()}), None).unwrap(),
        KeyReference::Jku {
            url: url.clone(),
            kid: None
        }
    );
    // With a `kid` that names nothing by itself.
    let reference = from_jws(
        json!({"alg": "ES256", "jku": url.as_str(), "kid": "key-1"}),
        Some("joe"),
    )
    .unwrap();
    assert_eq!(
        reference,
        KeyReference::Jku {
            url,
            kid: Some("key-1".to_owned())
        }
    );
    assert_eq!(
        reference.to_string(),
        "`key-1` of `https://issuer.example/jwks.json`"
    );
    // `x5c` comes first.
    assert!(matches!(
        from_jws(
            json!({"alg": "ES256", "jku": "https://a.example", "x5c": [STANDARD.encode(b"c")]}),
            None
        ),
        Ok(KeyReference::X509Chain(_))
    ));
    for jku in [json!("/relative/jwks.json"), json!(7)] {
        assert!(matches!(
            from_jws(json!({"alg": "ES256", "jku": jku}), None),
            Err(KeyReferenceError::InvalidUrl {
                parameter: "jku",
                ..
            })
        ));
    }
}

#[test]
fn header_without_a_key_is_missing() {
    let error = from_jws(json!({"alg": "EdDSA"}), Some("did:example:123")).unwrap_err();
    assert!(matches!(error, KeyReferenceError::Missing));
    assert_eq!(
        error.to_string(),
        "the token names no key: no `kid`, `jwk`, `x5c` or `jku`"
    );
    // A `kid` that names nothing, with nothing else, is reported as such.
    let error = from_jws(
        json!({"alg": "EdDSA", "kid": "key-1"}),
        Some("did:example:123"),
    )
    .unwrap_err();
    assert!(matches!(&error, KeyReferenceError::InvalidKid { kid, .. } if kid == "key-1"));
    assert!(
        error
            .to_string()
            .starts_with("`kid` \"key-1\" is not a DID URL")
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 7515 Appendix A.3 with its key in the header
// ---------------------------------------------------------------------------------------------

/// The payload of RFC 7515 Appendix A.3.
const RFC7515_PAYLOAD: &[u8] =
    b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

#[tokio::test]
async fn rfc7515_a3_with_a_jwk_header_resolves_and_binds() {
    let signer = Es256Signer::rfc7515_a3();
    let key = signer.public_jwk();
    let mut header = JwsHeader::new(JwsAlgorithm::ES256);
    header.jwk = Some(key.clone());
    let token = encode_compact(&header, RFC7515_PAYLOAD, &signer)
        .await
        .unwrap();
    let jws = CompactJws::decode(&token).unwrap();

    // `iss` is `joe`, which names no key, so the `jwk` header does.
    let reference = KeyReference::from_jws(&jws, Some("joe")).unwrap();
    assert_eq!(reference, KeyReference::Jwk(Box::new(key.clone())));
    let resolved = JwkResolver
        .resolve_key(&reference, KeyRole::Issuer)
        .await
        .unwrap();
    jws.verify(&DefaultVerifier, &resolved).unwrap();

    // `joe` is not the key's, but its did:jwk and its thumbprint are.
    assert!(!reference.binds_to(Some("joe"), &resolved));
    let did = DidJwk::did(&key).unwrap();
    assert!(reference.binds_to(Some(did.as_str()), &resolved));
    assert!(reference.binds_to(Some(&key.thumbprint_sha256().unwrap()), &resolved));
    assert!(reference.binds_to(None, &resolved));

    // The same with the A.1 Ed25519 key of RFC 8037.
    let signer = Ed25519Signer::rfc8037();
    let mut header = JwsHeader::new(JwsAlgorithm::EdDSA);
    header.jwk = Some(signer.public_jwk());
    let token = encode_compact(&header, RFC7515_PAYLOAD, &signer)
        .await
        .unwrap();
    let jws = CompactJws::decode(&token).unwrap();
    let reference = KeyReference::from_jws(&jws, None).unwrap();
    let resolved = JwkResolver
        .resolve_key(&reference, KeyRole::Subject)
        .await
        .unwrap();
    jws.verify(&DefaultVerifier, &resolved).unwrap();
    assert!(reference.binds_to(Some(RFC8037_THUMBPRINT), &resolved));
}

// ---------------------------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------------------------

#[test]
fn binding_rule_table() {
    let key = ed25519();
    let other = Es256Signer::rfc7515_a3().public_jwk();

    // DID URL: the party is its DID.
    let by_url = KeyReference::DidUrl(did_url("did:example:123#key-1"));
    assert!(by_url.binds_to(Some("did:example:123"), &key));
    assert!(!by_url.binds_to(Some("did:example:1234"), &key));
    assert!(!by_url.binds_to(Some("did:example:123#key-1"), &key));
    assert!(!by_url.binds_to(Some("https://issuer.example"), &key));
    assert!(!by_url.binds_to(None, &key));

    // Key by value: its did:jwk (whatever the member order), its thumbprint, or no party.
    let by_value = KeyReference::Jwk(Box::new(key.clone()));
    let did = DidJwk::did(&key).unwrap();
    assert!(by_value.binds_to(Some(did.as_str()), &key));
    let reordered = format!(
        "did:jwk:{}",
        common::encode(format!(r#"{{"x":"{RFC8037_X}","crv":"Ed25519","kty":"OKP"}}"#).as_bytes())
    );
    assert!(by_value.binds_to(Some(&reordered), &key));
    assert!(by_value.binds_to(Some(RFC8037_THUMBPRINT), &key));
    assert!(by_value.binds_to(None, &key));
    assert!(!by_value.binds_to(Some(DidJwk::did(&other).unwrap().as_str()), &key));
    assert!(!by_value.binds_to(Some(&other.thumbprint_sha256().unwrap()), &key));
    assert!(!by_value.binds_to(Some(DidKey::did(&key).unwrap().as_str()), &key));
    assert!(!by_value.binds_to(Some("did:jwk:not-base64!"), &key));
    // The key that verified decides, not the one in the reference.
    assert!(!by_value.binds_to(Some(RFC8037_THUMBPRINT), &other));

    // Key set: the party is the issuer, compared as URLs.
    let by_set = KeyReference::Jwks {
        issuer: Url::parse("https://issuer.example/tenant").unwrap(),
        kid: "key-1".to_owned(),
    };
    assert!(by_set.binds_to(Some("https://issuer.example/tenant"), &key));
    assert!(by_set.binds_to(Some("HTTPS://ISSUER.example:443/tenant"), &key));
    assert!(!by_set.binds_to(Some("https://issuer.example/other"), &key));
    assert!(!by_set.binds_to(Some("did:example:123"), &key));
    assert!(!by_set.binds_to(None, &key));

    // Not resolved by the crate yet, so never bound.
    let chain = KeyReference::X509Chain(vec![b"leaf".to_vec()]);
    let jku = KeyReference::Jku {
        url: Url::parse("https://issuer.example/jwks").unwrap(),
        kid: None,
    };
    for reference in [chain, jku] {
        assert!(!reference.binds_to(Some("https://issuer.example"), &key));
        assert!(!reference.binds_to(None, &key));
    }
}

// ---------------------------------------------------------------------------------------------
// Resolvers
// ---------------------------------------------------------------------------------------------

#[test]
fn roles_map_to_relationships() {
    assert_eq!(
        KeyRole::Issuer.relationship(),
        VerificationRelationship::AssertionMethod
    );
    assert_eq!(
        KeyRole::Subject.relationship(),
        VerificationRelationship::Authentication
    );
}

/// Every kind of reference, for the `Unsupported` checks.
fn every_reference() -> Vec<KeyReference> {
    vec![
        KeyReference::DidUrl(did_url("did:example:123#key-1")),
        KeyReference::Jwk(Box::new(ed25519())),
        KeyReference::X509Chain(vec![b"leaf".to_vec()]),
        KeyReference::Jwks {
            issuer: Url::parse("https://issuer.example").unwrap(),
            kid: "key-1".to_owned(),
        },
        KeyReference::Jku {
            url: Url::parse("https://issuer.example/jwks").unwrap(),
            kid: Some("key-1".to_owned()),
        },
    ]
}

#[tokio::test]
async fn resolver_resolves_did_urls_for_the_role() {
    let resolver = resolver();
    let did = DidKey::did(&ed25519()).unwrap();
    let url = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    for role in [KeyRole::Issuer, KeyRole::Subject] {
        assert_eq!(
            resolver
                .resolve_key(&KeyReference::DidUrl(url.clone()), role)
                .await
                .unwrap(),
            ed25519()
        );
    }

    // A did:jwk whose key has `use: enc` lists it under `keyAgreement` only.
    let enc: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X, "use": "enc"
    }))
    .unwrap();
    let url = DidJwk::did(&enc).unwrap().join("#0").unwrap();
    for role in [KeyRole::Issuer, KeyRole::Subject] {
        let error = resolver
            .resolve_key(&KeyReference::DidUrl(url.clone()), role)
            .await
            .unwrap_err();
        assert!(!error.is_unsupported());
        assert!(error.inner().is_some());
    }

    for reference in every_reference().into_iter().skip(1) {
        let error = resolver
            .resolve_key(&reference, KeyRole::Issuer)
            .await
            .unwrap_err();
        assert!(matches!(&error, KeyResolutionError::Unsupported(r) if **r == reference));
        assert!(error.inner().is_none());
        assert_eq!(
            error.to_string(),
            format!("no resolver handles {reference}")
        );
    }
}

#[tokio::test]
async fn jwk_resolver_returns_the_public_key() {
    let private: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": RFC8037_X,
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    for role in [KeyRole::Issuer, KeyRole::Subject] {
        let key = JwkResolver
            .resolve_key(&KeyReference::Jwk(Box::new(private.clone())), role)
            .await
            .unwrap();
        assert_eq!(key, ed25519());
        assert!(!key.is_private());
    }
    for reference in every_reference() {
        if matches!(reference, KeyReference::Jwk(_)) {
            continue;
        }
        assert!(
            JwkResolver
                .resolve_key(&reference, KeyRole::Issuer)
                .await
                .unwrap_err()
                .is_unsupported()
        );
    }
}

/// Answers every reference with `answer`, counting the calls.
struct Fixed {
    answer: fn() -> Result<Jwk, KeyResolutionError>,
    calls: AtomicUsize,
}

impl Fixed {
    fn new(answer: fn() -> Result<Jwk, KeyResolutionError>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl KeyResolver for Fixed {
    async fn resolve_key(&self, _: &KeyReference, _: KeyRole) -> Result<Jwk, KeyResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.answer)()
    }
}

#[tokio::test]
async fn composite_tries_resolvers_in_order() {
    let reference = KeyReference::Jwk(Box::new(ed25519()));

    // Nothing to try.
    let empty = CompositeKeyResolver::new();
    assert!(empty.is_empty());
    assert!(matches!(
        empty.resolve_key(&reference, KeyRole::Issuer).await,
        Err(KeyResolutionError::Unsupported(r)) if *r == reference
    ));

    // `Unsupported` falls through to the next; the first other answer is the answer.
    let unsupported = Fixed::new(|| {
        Err(KeyResolutionError::unsupported(&KeyReference::X509Chain(
            Vec::new(),
        )))
    });
    let found = Fixed::new(|| Ok(ed25519()));
    let never = Fixed::new(|| Ok(Es256Signer::rfc7515_a3().public_jwk()));
    let composite = CompositeKeyResolver::new()
        .with_shared(unsupported.clone())
        .with_shared(found.clone())
        .with_shared(never.clone());
    assert_eq!(composite.len(), 3);
    assert!(!composite.is_empty());
    assert_eq!(
        composite
            .resolve_key(&reference, KeyRole::Issuer)
            .await
            .unwrap(),
        ed25519()
    );
    assert_eq!(
        (unsupported.calls(), found.calls(), never.calls()),
        (1, 1, 0)
    );

    // An error stops the search: a reference the resolver handles but cannot find is not
    // looked up elsewhere.
    let failing = Fixed::new(|| Err(KeyResolutionError::msg("not found")));
    let composite = CompositeKeyResolver::new()
        .with_shared(failing.clone())
        .with_shared(found.clone());
    let error = composite
        .resolve_key(&reference, KeyRole::Issuer)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "not found");
    assert_eq!((failing.calls(), found.calls()), (1, 1));

    // When every resolver declines, the reference is unsupported.
    let composite = CompositeKeyResolver::new()
        .with_shared(unsupported.clone())
        .with(JwkResolver);
    assert!(matches!(
        composite
            .resolve_key(
                &KeyReference::X509Chain(vec![b"leaf".to_vec()]),
                KeyRole::Issuer
            )
            .await,
        Err(KeyResolutionError::Unsupported(r)) if matches!(*r, KeyReference::X509Chain(_))
    ));
    assert_eq!(
        format!("{composite:?}"),
        "CompositeKeyResolver { resolvers: 2 }"
    );
}

#[tokio::test]
async fn composite_of_the_crate_resolvers() {
    let composite = CompositeKeyResolver::new()
        .with(resolver())
        .with(JwkResolver);
    let did = DidKey::did(&ed25519()).unwrap();
    let url = did.join(&format!("#{}", did.method_specific_id())).unwrap();
    assert_eq!(
        composite
            .resolve_key(&KeyReference::DidUrl(url), KeyRole::Issuer)
            .await
            .unwrap(),
        ed25519()
    );
    assert_eq!(
        composite
            .resolve_key(&KeyReference::Jwk(Box::new(ed25519())), KeyRole::Subject)
            .await
            .unwrap(),
        ed25519()
    );
    // `x5c` and `jku` are unsupported everywhere in the crate.
    for reference in every_reference().into_iter().skip(2) {
        assert!(
            composite
                .resolve_key(&reference, KeyRole::Issuer)
                .await
                .unwrap_err()
                .is_unsupported()
        );
    }

    // Shared behind `Arc`, `Box` and `&`.
    let shared: Arc<dyn KeyResolver> = Arc::new(composite);
    let boxed: Box<dyn KeyResolver> = Box::new(JwkResolver);
    let reference = KeyReference::Jwk(Box::new(ed25519()));
    assert!(
        shared
            .resolve_key(&reference, KeyRole::Issuer)
            .await
            .is_ok()
    );
    assert!(boxed.resolve_key(&reference, KeyRole::Issuer).await.is_ok());
    async fn resolves(resolver: impl KeyResolver, reference: &KeyReference) -> bool {
        resolver
            .resolve_key(reference, KeyRole::Issuer)
            .await
            .is_ok()
    }
    assert!(resolves(&*shared, &reference).await);
    assert!(resolves(boxed, &reference).await);
}

#[test]
fn display_of_references_and_errors() {
    assert_eq!(
        KeyReference::Jwk(Box::new(ed25519())).to_string(),
        format!("JWK {RFC8037_THUMBPRINT}")
    );
    assert_eq!(
        KeyReference::Jwks {
            issuer: Url::parse("https://issuer.example").unwrap(),
            kid: "key-1".to_owned()
        }
        .to_string(),
        "`key-1` of issuer `https://issuer.example/`"
    );
    assert_eq!(
        KeyReference::Jku {
            url: Url::parse("https://issuer.example/jwks").unwrap(),
            kid: None
        }
        .to_string(),
        "the key of `https://issuer.example/jwks`"
    );
    let error = KeyResolutionError::new(std::io::Error::other("offline"));
    assert_eq!(error.to_string(), "offline");
    assert!(error.inner().unwrap().is::<std::io::Error>());
    assert!(
        KeyReferenceError::UnsupportedConfirmation("x5t#S256".to_owned())
            .to_string()
            .contains("`x5t#S256`")
    );
}
