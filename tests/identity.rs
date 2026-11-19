//! Behaviour of the `identity` module: `KeyStoreIdentity` over the in-memory and software key
//! stores with the `did:key` and `did:jwk` producers. Vectors are RFC 7638 §3.1 and RFC 8037
//! Appendix A.
#![cfg(all(
    feature = "in-memory",
    feature = "software",
    feature = "did-key",
    feature = "did-jwk"
))]
#![expect(
    clippy::similar_names,
    reason = "the names are the API's terms: `kid` and `kind`"
)]

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use identity_kit::did::{Did, DidDocument, DidMethod, DidUrl, VerificationRelationship};
use identity_kit::identity::{Identifier, Identity, IdentityError, IdentityKind, KeyStoreIdentity};
use identity_kit::jose::{
    CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, KeyType, encode_compact,
};
use identity_kit::keys::{
    InMemoryKeyStore, KeyId, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError,
    SoftwareKeyStore,
};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::{DidProducer, MethodCapabilities, ProduceError};
use serde_json::json;

use common::fixtures::resolver;

/// RFC 8037 Appendix A.1, the private key.
const RFC8037_A1: &str = r#"{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
/// RFC 8037 Appendix A.3.
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
/// RFC 8037 Appendix A.4 and A.5: the signing input and the signature of the JWS.
const RFC8037_SIGNING_INPUT: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
const RFC8037_SIGNATURE: &str =
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// RFC 7638 §3.1: the public key and its thumbprint.
const RFC7638_RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

fn did_kind(method: &str) -> IdentityKind {
    IdentityKind::Did(DidMethod::parse(method).unwrap())
}

fn spec(key_type: KeyType, alg: JwsAlgorithm) -> KeySpec {
    KeySpec::new(key_type, alg)
}

/// An identity over a fresh in-memory store with both producers, and that store.
fn identity() -> (KeyStoreIdentity, Arc<InMemoryKeyStore>) {
    let store = Arc::new(InMemoryKeyStore::new());
    let identity = KeyStoreIdentity::new(Arc::clone(&store) as Arc<dyn KeyStore>)
        .with_producer(DidKey::default())
        .with_producer(DidJwk);
    (identity, store)
}

/// Signs a token with the identity's signer for `(kind, alg)`, with its `kid` in the header,
/// and checks that it verifies under the key the DID in `kid` resolves to for `relationship`.
async fn sign_and_resolve(
    identity: &dyn Identity,
    kind: &IdentityKind,
    alg: JwsAlgorithm,
    relationship: VerificationRelationship,
) -> DidUrl {
    let signer = identity.signer(kind, alg).await.unwrap();
    let kid = DidUrl::parse(signer.kid().expect("a DID signer has a kid")).unwrap();
    let header = JwsHeader::new(alg).with_kid(kid.as_str());
    let token = encode_compact(&header, br#"{"iss":"me"}"#, &*signer)
        .await
        .unwrap();

    let identifier = identity.identifier(kind, alg).await.unwrap();
    assert_eq!(identifier.as_did(), Some(kid.did()));
    let resolved = resolver()
        .resolve_public_key(&kid, Some(relationship))
        .await
        .unwrap();
    // The same key; the resolved one carries no `kid` or `alg`.
    let public = identity.public_jwk(kind, alg).await.unwrap();
    assert_eq!(
        resolved.thumbprint_sha256().unwrap(),
        public.thumbprint_sha256().unwrap()
    );
    CompactJws::decode(&token)
        .unwrap()
        .verify(&DefaultVerifier, &resolved)
        .unwrap();
    kid
}

// ---------------------------------------------------------------------------------------------
// Binding and signing
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn bound_did_key_signs_for_assertion_and_authentication() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let kind = did_kind("did:key");
    let did = identity
        .bind(kind.clone(), JwsAlgorithm::EdDSA, key.clone())
        .await
        .unwrap();

    // did:key: the DID is the Multikey of the key, the fragment repeats it.
    let public = store.public_jwk(&key).await.unwrap();
    assert_eq!(did, Identifier::Did(DidKey::did(&public).unwrap()));
    let multikey = public.to_multikey().unwrap();
    assert_eq!(did.to_string(), format!("did:key:{multikey}"));

    for relationship in [
        VerificationRelationship::AssertionMethod,
        VerificationRelationship::Authentication,
    ] {
        let kid = sign_and_resolve(&identity, &kind, JwsAlgorithm::EdDSA, relationship).await;
        assert_eq!(kid.to_string(), format!("did:key:{multikey}#{multikey}"));
    }
}

#[tokio::test]
async fn bound_did_jwk_signs_with_fragment_zero() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    let kind = did_kind("did:jwk");
    let did = identity
        .bind(kind.clone(), JwsAlgorithm::ES256, key.clone())
        .await
        .unwrap();
    let public = store.public_jwk(&key).await.unwrap();
    assert_eq!(did, Identifier::Did(DidJwk::did(&public).unwrap()));

    let kid = sign_and_resolve(
        &identity,
        &kind,
        JwsAlgorithm::ES256,
        VerificationRelationship::AssertionMethod,
    )
    .await;
    assert_eq!(kid.fragment(), Some("0"));
}

#[tokio::test]
async fn rfc8037_key_as_thumbprint_reproduces_the_appendix_a_jws() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    write_key_set(&path, &format!(r#"{{"keys":[{RFC8037_A1}]}}"#));
    let store: Arc<dyn KeyStore> = Arc::new(SoftwareKeyStore::open(&path).unwrap());
    let identity = KeyStoreIdentity::new(store);

    let kind = IdentityKind::JwkThumbprint;
    let id = identity
        .bind(
            kind.clone(),
            JwsAlgorithm::EdDSA,
            KeyId::new(RFC8037_THUMBPRINT),
        )
        .await
        .unwrap();
    // RFC 8037 Appendix A.3.
    assert_eq!(id, Identifier::JwkThumbprint(RFC8037_THUMBPRINT.to_owned()));
    assert_eq!(id.to_string(), RFC8037_THUMBPRINT);
    assert!(id.as_did().is_none());

    let public = identity
        .public_jwk(&kind, JwsAlgorithm::EdDSA)
        .await
        .unwrap();
    assert!(!public.is_private());
    assert_eq!(public.thumbprint_sha256().unwrap(), RFC8037_THUMBPRINT);

    // No `kid`: the header is A.4's `{"alg":"EdDSA"}`, so the JWS is A.5 byte for byte.
    let signer = identity.signer(&kind, JwsAlgorithm::EdDSA).await.unwrap();
    assert_eq!(signer.kid(), None);
    let token = encode_compact(
        &JwsHeader::new(JwsAlgorithm::EdDSA),
        b"Example of Ed25519 signing",
        &*signer,
    )
    .await
    .unwrap();
    assert_eq!(
        token,
        format!("{RFC8037_SIGNING_INPUT}.{RFC8037_SIGNATURE}")
    );
    CompactJws::decode(&token)
        .unwrap()
        .verify(&DefaultVerifier, &public)
        .unwrap();
}

/// The `did:jwk` of the RFC 8037 Appendix A key with `"alg": "EdDSA"` and its thumbprint as
/// `kid`: the base64url of `{"alg":"EdDSA","crv":"Ed25519","kid":"kPrK_…","kty":"OKP","x":"11qY…"}`.
const RFC8037_DID_JWK: &str = "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJrUHJLX3FteFZXYVlWQTl3d0JGNkl1bzN2Vnp6N1R4SENUd1hCeWdyUzRrIiwia3R5IjoiT0tQIiwieCI6IjExcVlBWUt4Q3JmVlNfN1R5V1FIT2c3aGN2UGFwaU1scndJYWFQY0hVUm8ifQ";

/// A store's key id stays out of what the identity publishes: the `did:jwk` and the public key
/// carry the thumbprint as `kid`, so the key has one `did:jwk` whatever store holds it.
#[tokio::test]
async fn a_store_label_stays_out_of_the_did_jwk() {
    const LABEL: &str = "arn:aws:kms:eu-central-1:111122223333:key/example";
    let dir = tempfile::tempdir().unwrap();
    let key = |kid: Option<&str>| {
        let mut jwk: serde_json::Value = serde_json::from_str(RFC8037_A1).unwrap();
        jwk["alg"] = json!("EdDSA");
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
        }
        jwk
    };
    let mut identifiers = Vec::new();
    for (name, kid, id) in [
        ("labelled.json", Some(LABEL), LABEL),
        ("unlabelled.json", None, RFC8037_THUMBPRINT),
    ] {
        let path = dir.path().join(name);
        write_key_set(&path, &json!({ "keys": [key(kid)] }).to_string());
        let store: Arc<dyn KeyStore> = Arc::new(SoftwareKeyStore::open(&path).unwrap());
        // The store's own public key keeps its key id: the contract is unchanged.
        let stored = store.public_jwk(&KeyId::new(id)).await.unwrap();
        assert_eq!(stored.kid(), Some(id));
        let identity = KeyStoreIdentity::new(store)
            .with_producer(DidKey::default())
            .with_producer(DidJwk);
        let kind = did_kind("did:jwk");
        let did = identity
            .bind(kind.clone(), JwsAlgorithm::EdDSA, KeyId::new(id))
            .await
            .unwrap();
        assert_eq!(did.to_string(), RFC8037_DID_JWK, "{name}");
        let public = identity
            .public_jwk(&kind, JwsAlgorithm::EdDSA)
            .await
            .unwrap();
        assert_eq!(public.kid(), Some(RFC8037_THUMBPRINT));
        assert_eq!(public.alg(), Some("EdDSA"));
        assert!(!serde_json::to_string(&public).unwrap().contains("arn:"));
        sign_and_resolve(
            &identity,
            &kind,
            JwsAlgorithm::EdDSA,
            VerificationRelationship::AssertionMethod,
        )
        .await;
        identifiers.push(did);
    }
    assert_eq!(identifiers[0], identifiers[1]);
}

/// The `did:jwk` of the RFC 7638 §3.1 key with its thumbprint as `kid` and no `alg`: the
/// base64url of `{"e":"AQAB","kid":"NzbL…","kty":"RSA","n":"0vx7…"}`.
const RFC7638_DID_JWK: &str = "did:jwk:eyJlIjoiQVFBQiIsImtpZCI6Ik56YkxzWGg4dURDY2QtNk1Od1hGNFdfN25vV1hGWkFmSGt4WnNSR0M5WHMiLCJrdHkiOiJSU0EiLCJuIjoiMHZ4N2Fnb2ViR2NRU3V1UGlMSlhacHROOW5uZHJRbWJYRXBzMmFpQUZiV2hNNzhMaFd4NGNiYmZBQXRWVDg2end1MVJLN2FQRkZ4dWhEUjFMNnRTb2NfQkpFQ1BlYldLUlhqQlpDaUZWNG4zb2tuamhNc3RuNjR0Wl8yVy01SnNHWTRIYzVuOXlCWEFyd2w5M2xxdDdfUk41dzZDZjBoNFF5UTV2LTY1WUdqUVIwX0ZEVzJRdnpxWTM2OFFRTWljQXRhU3F6czhLSlpnblliOWM3ZDB6Z2RBWkh6dTZxTVF2Ukw1aGFqcm4xbjkxQ2JPcGJJU0QwOHFOTHlyZGt0LWJGVFdoQUk0dk1RRmg2V2VadTBmTTRsRmQyTmNSd3IzWFBrc0lOSGFRLUdfeEJuaUlxYncwTHMxakY0NC1jc0ZDdXIta0VnVThhd2FwSnpLbnFES2d3In0";

/// What a store adds beyond the key and its `alg` is not published: a store's `kid`, `use`,
/// `key_ops` or other member, and no `alg` when the store gives none.
#[tokio::test]
async fn only_the_key_its_alg_and_its_thumbprint_are_published() {
    let store = Fixed(json!({
        "kty": "RSA", "n": RFC7638_RSA_N, "e": "AQAB",
        "kid": "arn:aws:kms:eu-central-1:111122223333:key/example",
        "use": "sig", "key_ops": ["verify"], "x5t#S256": "AQ"
    }));
    let identity = KeyStoreIdentity::new(Arc::new(store)).with_producer(DidJwk);
    let kind = did_kind("did:jwk");
    let did = identity
        .bind(kind.clone(), JwsAlgorithm::RS256, KeyId::new("key"))
        .await
        .unwrap();
    assert_eq!(did.to_string(), RFC7638_DID_JWK);
    let public = identity
        .public_jwk(&kind, JwsAlgorithm::RS256)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&public).unwrap(),
        json!({ "kty": "RSA", "n": RFC7638_RSA_N, "e": "AQAB", "kid": RFC7638_THUMBPRINT })
    );

    // A key bound as the verification method of a DID the caller names is published the same
    // way.
    let url = DidUrl::parse("did:web:example.com#key-1").unwrap();
    identity
        .bind_did_url(
            did_kind("did:web"),
            JwsAlgorithm::RS256,
            KeyId::new("key"),
            url,
        )
        .await
        .unwrap();
    assert_eq!(
        identity
            .public_jwk(&did_kind("did:web"), JwsAlgorithm::RS256)
            .await
            .unwrap(),
        public
    );
}

/// A key without the members its thumbprint covers cannot be published, whatever it is bound
/// as.
#[tokio::test]
async fn a_key_without_its_required_members_is_refused() {
    let store = Fixed(json!({ "kty": "RSA", "e": "AQAB", "alg": "RS256" }));
    let identity = KeyStoreIdentity::new(Arc::new(store)).with_producer(DidJwk);
    let key = || KeyId::new("key");
    let url = DidUrl::parse("did:web:example.com#key-1").unwrap();
    for result in [
        identity
            .bind(did_kind("did:jwk"), JwsAlgorithm::RS256, key())
            .await,
        identity
            .bind(IdentityKind::JwkThumbprint, JwsAlgorithm::RS256, key())
            .await,
        identity
            .bind_did_url(did_kind("did:web"), JwsAlgorithm::RS256, key(), url)
            .await,
    ] {
        assert!(matches!(result, Err(IdentityError::Jwk(_))), "{result:?}");
    }
    assert!(identity.bindings().is_empty());
}

#[tokio::test]
async fn rfc7638_key_gives_the_section_3_1_thumbprint() {
    let identity = KeyStoreIdentity::new(Arc::new(PublicOnly));
    let id = identity
        .bind(
            IdentityKind::JwkThumbprint,
            JwsAlgorithm::RS256,
            KeyId::new("2011-04-29"),
        )
        .await
        .unwrap();
    assert_eq!(id, Identifier::JwkThumbprint(RFC7638_THUMBPRINT.to_owned()));
}

#[tokio::test]
async fn one_kind_under_two_algorithms_has_two_identifiers() {
    let (identity, store) = identity();
    let kind = did_kind("did:key");
    let ed = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let p256 = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    identity
        .bind(kind.clone(), JwsAlgorithm::EdDSA, ed)
        .await
        .unwrap();
    identity
        .bind(kind.clone(), JwsAlgorithm::ES256, p256)
        .await
        .unwrap();

    let mut identifiers = Vec::new();
    for alg in [JwsAlgorithm::EdDSA, JwsAlgorithm::ES256] {
        let identifier = identity.identifier(&kind, alg).await.unwrap();
        let public = identity.public_jwk(&kind, alg).await.unwrap();
        // Each identifier names its own key.
        assert_eq!(identifier, Identifier::Did(DidKey::did(&public).unwrap()));
        sign_and_resolve(
            &identity,
            &kind,
            alg,
            VerificationRelationship::AssertionMethod,
        )
        .await;
        identifiers.push(identifier);
    }
    assert_ne!(identifiers[0], identifiers[1]);
}

#[tokio::test]
async fn one_key_under_two_kinds() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    let public = store.public_jwk(&key).await.unwrap();
    for kind in [
        did_kind("did:key"),
        did_kind("did:jwk"),
        IdentityKind::JwkThumbprint,
    ] {
        identity
            .bind(kind, JwsAlgorithm::ES256, key.clone())
            .await
            .unwrap();
    }
    let expected = [
        Identifier::Did(DidKey::did(&public).unwrap()),
        Identifier::Did(DidJwk::did(&public).unwrap()),
        Identifier::JwkThumbprint(public.thumbprint_sha256().unwrap()),
    ];
    for ((kind, alg, bound), expected) in identity.bindings().into_iter().zip(expected) {
        assert_eq!(bound, key);
        assert_eq!(identity.identifier(&kind, alg).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn binding_again_replaces_the_key() {
    let (identity, store) = identity();
    let kind = IdentityKind::JwkThumbprint;
    let first = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let second = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let old = identity
        .bind(kind.clone(), JwsAlgorithm::EdDSA, first)
        .await
        .unwrap();
    let new = identity
        .bind(kind.clone(), JwsAlgorithm::EdDSA, second.clone())
        .await
        .unwrap();
    assert_ne!(old, new);
    assert_eq!(
        identity
            .identifier(&kind, JwsAlgorithm::EdDSA)
            .await
            .unwrap(),
        new
    );
    assert_eq!(identity.bindings(), [(kind, JwsAlgorithm::EdDSA, second)]);
}

#[tokio::test]
async fn bind_did_url_takes_the_callers_verification_method() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let url = DidUrl::parse("did:web:example.com:alice#key-1").unwrap();
    let kind = did_kind("did:web");
    let did = identity
        .bind_did_url(kind.clone(), JwsAlgorithm::EdDSA, key.clone(), url.clone())
        .await
        .unwrap();
    assert_eq!(
        did,
        Identifier::Did(Did::parse("did:web:example.com:alice").unwrap())
    );
    let signer = identity.signer(&kind, JwsAlgorithm::EdDSA).await.unwrap();
    assert_eq!(signer.kid(), Some("did:web:example.com:alice#key-1"));
    assert_eq!(
        identity
            .public_jwk(&kind, JwsAlgorithm::EdDSA)
            .await
            .unwrap(),
        store.public_jwk(&key).await.unwrap().public()
    );

    // The DID must be of the kind, namespace included.
    for kind in [
        did_kind("did:key"),
        did_kind("did:web:other.example"),
        IdentityKind::JwkThumbprint,
    ] {
        let err = identity
            .bind_did_url(kind.clone(), JwsAlgorithm::EdDSA, key.clone(), url.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::UnsupportedKind(k) if k == kind),
            "{kind}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn unbound_pairs_are_refused_without_generation() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    identity
        .bind(did_kind("did:key"), JwsAlgorithm::EdDSA, key)
        .await
        .unwrap();

    // A kind with no binding at all.
    let err = identity
        .identifier(&did_kind("did:jwk"), JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::UnsupportedKind(k) if k == did_kind("did:jwk")));
    // A bound kind, another algorithm.
    let err = identity
        .signer(&did_kind("did:key"), JwsAlgorithm::ES256)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        err,
        IdentityError::UnsupportedAlgorithm(JwsAlgorithm::ES256)
    ));
    let err = identity
        .public_jwk(&IdentityKind::JwkThumbprint, JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        IdentityError::UnsupportedKind(IdentityKind::JwkThumbprint)
    ));
    // Nothing was generated.
    assert_eq!(store.key_ids().len(), 1);
}

#[tokio::test]
async fn bind_refuses_what_does_not_fit() {
    let (identity, store) = identity();
    let ed = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();

    // No producer for the method.
    let err = identity
        .bind(did_kind("did:web"), JwsAlgorithm::EdDSA, ed.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::UnsupportedKind(_)));
    // did:key has no namespace, so it cannot produce one.
    let err = identity
        .bind(did_kind("did:key:test"), JwsAlgorithm::EdDSA, ed.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::UnsupportedKind(k) if k == did_kind("did:key:test")));
    // An algorithm the store does not sign with.
    let err = identity
        .bind(IdentityKind::JwkThumbprint, JwsAlgorithm::ES384, ed.clone())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        IdentityError::UnsupportedAlgorithm(JwsAlgorithm::ES384)
    ));
    // A key of another algorithm.
    let err = identity
        .bind(IdentityKind::JwkThumbprint, JwsAlgorithm::ES256, ed)
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::KeyStore(_)), "{err:?}");
    // A key that does not exist.
    let err = identity
        .bind(
            IdentityKind::JwkThumbprint,
            JwsAlgorithm::EdDSA,
            KeyId::new("missing"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::KeyStore(KeyStoreError::NotFound(_))),
        "{err:?}"
    );
    assert!(identity.bindings().is_empty());
}

#[tokio::test]
async fn a_document_without_verification_method_is_refused() {
    let store = Arc::new(InMemoryKeyStore::new());
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let identity = KeyStoreIdentity::new(store).with_producer(Empty);
    let err = identity
        .bind(did_kind("did:example"), JwsAlgorithm::EdDSA, key)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, IdentityError::NoVerificationMethod(did) if did.as_str() == "did:example:empty"),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn generate_missing_generates_once_and_reuses() {
    let (identity, store) = identity();
    let identity = identity.generate_missing(true);
    let kind = did_kind("did:key");

    let did = identity
        .identifier(&kind, JwsAlgorithm::ES256)
        .await
        .unwrap();
    assert_eq!(store.key_ids().len(), 1);
    assert_eq!(
        identity
            .identifier(&kind, JwsAlgorithm::ES256)
            .await
            .unwrap(),
        did
    );
    let kid = sign_and_resolve(
        &identity,
        &kind,
        JwsAlgorithm::ES256,
        VerificationRelationship::AssertionMethod,
    )
    .await;
    assert_eq!(Identifier::Did(kid.did().clone()), did);
    // Still the one key, bound to the pair.
    assert_eq!(
        identity.bindings(),
        [(kind, JwsAlgorithm::ES256, store.key_ids()[0].clone())]
    );

    // A thumbprint gets a key of its own.
    let signer = identity
        .signer(&IdentityKind::JwkThumbprint, JwsAlgorithm::EdDSA)
        .await
        .unwrap();
    assert_eq!(signer.kid(), None);
    assert_eq!(store.key_ids().len(), 2);
}

/// A store that lets other tasks run while it generates a key.
struct Yielding(Arc<InMemoryKeyStore>);

#[async_trait::async_trait]
impl KeyStore for Yielding {
    fn capabilities(&self) -> KeyStoreCapabilities {
        self.0.capabilities()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.0.sign(key, alg, data).await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        tokio::task::yield_now().await;
        self.0.generate(spec).await
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        self.0.delete(key).await
    }
}

#[tokio::test]
async fn concurrent_generation_keeps_the_first_key() {
    // Both calls generate a key; the first one bound stays and the other is deleted.
    let store = Arc::new(InMemoryKeyStore::new());
    let identity = KeyStoreIdentity::new(Arc::new(Yielding(Arc::clone(&store))))
        .with_producer(DidKey::default())
        .generate_missing(true);
    let kind = did_kind("did:key");
    let (first, second) = tokio::join!(
        identity.identifier(&kind, JwsAlgorithm::EdDSA),
        identity.identifier(&kind, JwsAlgorithm::EdDSA),
    );
    assert_eq!(first.unwrap(), second.unwrap());
    let keys = store.key_ids();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        identity.bindings(),
        [(kind, JwsAlgorithm::EdDSA, keys[0].clone())]
    );
}

#[tokio::test]
async fn generate_missing_refuses_what_it_cannot_generate() {
    let (identity, store) = identity();
    let identity = identity.generate_missing(true);
    // No producer for the method.
    let err = identity
        .identifier(&did_kind("did:web"), JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::UnsupportedKind(_)));
    // No key type of the crate is ES384.
    let err = identity
        .identifier(&IdentityKind::JwkThumbprint, JwsAlgorithm::ES384)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        IdentityError::UnsupportedAlgorithm(JwsAlgorithm::ES384)
    ));
    // A namespace the producer cannot make: the key it generated is deleted again.
    let err = identity
        .identifier(&did_kind("did:key:test"), JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(matches!(err, IdentityError::UnsupportedKind(_)));
    assert!(store.key_ids().is_empty());
    assert!(identity.bindings().is_empty());
}

#[tokio::test]
async fn a_store_that_cannot_generate_reports_it() {
    let store = Arc::new(InMemoryKeyStore::new());
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let identity = KeyStoreIdentity::new(Arc::new(NoGenerate(store)))
        .with_producer(DidKey::default())
        .generate_missing(true);
    let err = identity
        .identifier(&did_kind("did:key"), JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            IdentityError::KeyStore(KeyStoreError::Unsupported("generate"))
        ),
        "{err:?}"
    );
    // Nothing to generate with, so nothing to offer beyond the bindings.
    assert!(identity.capabilities().is_empty());
    identity
        .bind(did_kind("did:key"), JwsAlgorithm::EdDSA, key)
        .await
        .unwrap();
    assert_eq!(
        identity.capabilities(),
        [(did_kind("did:key"), JwsAlgorithm::EdDSA)]
    );
}

#[tokio::test]
async fn seeded_stores_give_the_same_identifiers() {
    let mut identifiers = Vec::new();
    for _ in 0..2 {
        let identity = KeyStoreIdentity::new(Arc::new(InMemoryKeyStore::with_seed([7; 32])))
            .with_producer(DidKey::default())
            .generate_missing(true);
        let mut these = Vec::new();
        for (kind, alg) in [
            (did_kind("did:key"), JwsAlgorithm::EdDSA),
            (did_kind("did:key"), JwsAlgorithm::ES256),
            (IdentityKind::JwkThumbprint, JwsAlgorithm::EdDSA),
        ] {
            these.push(identity.identifier(&kind, alg).await.unwrap());
        }
        identifiers.push(these);
    }
    assert_eq!(identifiers[0], identifiers[1]);
}

// ---------------------------------------------------------------------------------------------
// Capabilities, producers, object safety
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn capabilities_reflect_bindings_and_generation() {
    let (identity, store) = identity();
    assert!(identity.capabilities().is_empty());
    let key = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    identity
        .bind(did_kind("did:jwk"), JwsAlgorithm::ES256, key)
        .await
        .unwrap();
    assert_eq!(
        identity.capabilities(),
        [(did_kind("did:jwk"), JwsAlgorithm::ES256)]
    );

    // With generation on: the binding first, then every producer method and the thumbprint
    // with every algorithm the store generates.
    let identity = identity.generate_missing(true);
    let capabilities = identity.capabilities();
    assert_eq!(capabilities[0], (did_kind("did:jwk"), JwsAlgorithm::ES256));
    let algorithms = store.capabilities().algorithms;
    for kind in [
        did_kind("did:key"),
        did_kind("did:jwk"),
        IdentityKind::JwkThumbprint,
    ] {
        for &alg in &algorithms {
            let count = capabilities
                .iter()
                .filter(|pair| **pair == (kind.clone(), alg))
                .count();
            assert_eq!(count, 1, "{kind} {alg}");
        }
    }
    assert_eq!(capabilities.len(), 3 * algorithms.len());
}

#[tokio::test]
async fn a_later_producer_replaces_one_for_the_same_method() {
    let store = Arc::new(InMemoryKeyStore::new());
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let identity = KeyStoreIdentity::new(store)
        .with_producer(DidKey::default())
        .with_producer(Empty)
        .with_producer(Example);
    let debug = format!("{identity:?}");
    assert!(
        debug.contains(r#"producers: ["key", "example"]"#),
        "{debug}"
    );
    let did = identity
        .bind(did_kind("did:example"), JwsAlgorithm::EdDSA, key)
        .await
        .unwrap();
    assert_eq!(did.to_string(), "did:example:123");
}

#[tokio::test]
async fn identities_are_object_safe_and_forward() {
    let (identity, store) = identity();
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let kind = did_kind("did:jwk");
    let did = identity
        .bind(kind.clone(), JwsAlgorithm::EdDSA, key)
        .await
        .unwrap();

    let shared: Arc<dyn Identity> = Arc::new(identity);
    let boxed: Box<dyn Identity> = Box::new(Arc::clone(&shared));
    for forwarded in [&shared as &dyn Identity, &boxed, &&*shared] {
        assert_eq!(
            forwarded.capabilities(),
            [(kind.clone(), JwsAlgorithm::EdDSA)]
        );
        assert_eq!(
            forwarded
                .identifier(&kind, JwsAlgorithm::EdDSA)
                .await
                .unwrap(),
            did
        );
        sign_and_resolve(
            forwarded,
            &kind,
            JwsAlgorithm::EdDSA,
            VerificationRelationship::AssertionMethod,
        )
        .await;
    }
}

#[test]
fn kinds_and_identifiers_display() {
    assert_eq!(did_kind("did:key").to_string(), "did:key");
    assert_eq!(did_kind("did:web:example").to_string(), "did:web:example");
    assert_eq!(IdentityKind::JwkThumbprint.to_string(), "JWK thumbprint");
    assert_eq!(
        IdentityError::UnsupportedKind(did_kind("did:key")).to_string(),
        "no identifier of kind did:key"
    );
    assert_eq!(
        IdentityError::UnsupportedAlgorithm(JwsAlgorithm::ES256).to_string(),
        "no key for algorithm ES256"
    );
}

// ---------------------------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------------------------

/// Writes `json` as a private key set file, readable by its owner only.
fn write_key_set(path: &Path, json: &str) {
    fs::write(path, json).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// A store holding the RFC 7638 §3.1 public key only, as a remote store that verifies RS256
/// keys would; it never signs.
struct PublicOnly;

#[async_trait::async_trait]
impl KeyStore for PublicOnly {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new([JwsAlgorithm::RS256])
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        if key.as_str() != "2011-04-29" {
            return Err(KeyStoreError::NotFound(key.clone()));
        }
        Ok(serde_json::from_value(json!({
            "kty": "RSA",
            "n": RFC7638_RSA_N,
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }))
        .unwrap())
    }

    async fn sign(&self, _: &KeyId, _: JwsAlgorithm, _: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::Unsupported("sign"))
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        Ok(key.as_str() == "2011-04-29")
    }
}

/// A store holding one RS256 key, `"key"`, whose public JWK is `jwk` as the store gives it.
struct Fixed(serde_json::Value);

#[async_trait::async_trait]
impl KeyStore for Fixed {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new([JwsAlgorithm::RS256])
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        if key.as_str() != "key" {
            return Err(KeyStoreError::NotFound(key.clone()));
        }
        Ok(serde_json::from_value(self.0.clone()).unwrap())
    }

    async fn sign(&self, _: &KeyId, _: JwsAlgorithm, _: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        Err(KeyStoreError::Unsupported("sign"))
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        Ok(key.as_str() == "key")
    }
}

/// A store that signs with the keys of another but cannot generate.
struct NoGenerate(Arc<InMemoryKeyStore>);

#[async_trait::async_trait]
impl KeyStore for NoGenerate {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new(self.0.capabilities().algorithms)
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.0.sign(key, alg, data).await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }
}

/// A `did:example` producer whose document has no verification method.
struct Empty;

#[async_trait::async_trait]
impl DidProducer for Empty {
    type Params = ();

    fn method(&self) -> &'static str {
        "example"
    }

    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(identity_kit::resolver::Hosting::Registry)
    }

    async fn produce(&self, _: &[Jwk], _: ()) -> Result<DidDocument, ProduceError> {
        Ok(DidDocument::new(Did::parse("did:example:empty").unwrap()))
    }
}

/// A `did:example` producer that names the key `#key-1` of `did:example:123`.
struct Example;

#[async_trait::async_trait]
impl DidProducer for Example {
    type Params = ();

    fn method(&self) -> &'static str {
        "example"
    }

    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(identity_kit::resolver::Hosting::Registry)
    }

    async fn produce(&self, keys: &[Jwk], _: ()) -> Result<DidDocument, ProduceError> {
        let did = Did::parse("did:example:123").unwrap();
        let mut document = DidDocument::new(did.clone());
        document
            .verification_method
            .push(identity_kit::did::VerificationMethod::new(
                did.to_url().with_fragment("key-1"),
                identity_kit::did::MethodType::JSON_WEB_KEY_2020,
                did,
                identity_kit::did::VerificationMaterial::jwk(&keys[0]),
            ));
        Ok(document)
    }
}
