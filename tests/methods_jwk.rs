//! Specification vectors for `did:jwk`: the P-256 and X25519 examples of the did:jwk method
//! specification and its Create and Read operations.
#![cfg(feature = "did-jwk")]

use identity_kit::did::{
    DEFAULT_MAX_LEN, Did, DidDocument, DidError, DidUrl, ResolutionError, ResolutionOptions,
};
use identity_kit::jose::Jwk;
use identity_kit::methods::DidJwk;
use identity_kit::resolver::{
    DereferenceError, DidProducer, DidResolver, Hosting, ProduceError, Resolver,
};
use serde_json::{Value, json};

/// did:jwk specification, "P-256" example. (The specification's `authentication` entry has a
/// stray `$` in the DID, a typo of the template substitution, corrected here.)
const P256_DID: &str = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
const P256_DOCUMENT: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
  "verificationMethod": [
    {
      "id": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0",
      "type": "JsonWebKey2020",
      "controller": "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
      }
    }
  ],
  "assertionMethod": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "authentication": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "capabilityInvocation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "capabilityDelegation": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"],
  "keyAgreement": ["did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#0"]
}"#;

/// did:jwk specification, "X25519" example: a key with `use` `enc`.
const X25519_DID: &str = "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9";
const X25519_DOCUMENT: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
  "verificationMethod": [
    {
      "id": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0",
      "type": "JsonWebKey2020",
      "controller": "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9",
      "publicKeyJwk": {
        "kty":"OKP",
        "crv":"X25519",
        "use":"enc",
        "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"
      }
    }
  ],
  "keyAgreement": ["did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9#0"]
}"#;

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn value(document: &DidDocument) -> Value {
    serde_json::to_value(document).unwrap()
}

fn resolver() -> Resolver {
    Resolver::builder().with(DidJwk).build()
}

#[tokio::test]
async fn p256_example() {
    let document = DidJwk::document(&did(P256_DID)).unwrap();
    let expected: Value = serde_json::from_str(P256_DOCUMENT).unwrap();
    assert_eq!(value(&document), expected);
    assert_eq!(
        document,
        serde_json::from_str::<DidDocument>(P256_DOCUMENT).unwrap()
    );

    let resolver = resolver();
    let key = DidUrl::parse(&format!("{P256_DID}#0")).unwrap();
    let jwk = resolver.resolve_public_key(&key, None).await.unwrap();
    assert_eq!(jwk.x(), Some("acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0"));
    assert!(jwk.p256_public_bytes().is_ok());
    let missing = DidUrl::parse(&format!("{P256_DID}#1")).unwrap();
    assert_eq!(
        resolver.resolve_public_key(&missing, None).await,
        Err(DereferenceError::NotFound(missing))
    );
}

#[test]
fn x25519_example_has_key_agreement_only() {
    let document = DidJwk::document(&did(X25519_DID)).unwrap();
    let expected: Value = serde_json::from_str(X25519_DOCUMENT).unwrap();
    assert_eq!(value(&document), expected);
    assert!(document.authentication.is_empty() && document.assertion_method.is_empty());
    assert!(document.capability_invocation.is_empty() && document.capability_delegation.is_empty());
}

#[test]
fn signing_keys_have_no_key_agreement() {
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "use": "sig",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }))
    .unwrap();
    let signing = DidJwk::did(&jwk).unwrap();
    let document = DidJwk::document(&signing).unwrap();
    assert!(document.key_agreement.is_empty());
    assert_eq!(document.authentication.len(), 1);
    assert_eq!(document.assertion_method.len(), 1);
    assert_eq!(document.capability_invocation.len(), 1);
    assert_eq!(document.capability_delegation.len(), 1);
    assert_eq!(document.verification_method[0].public_key_jwk(), Some(&jwk));
}

#[tokio::test]
async fn create_operation() {
    assert_eq!(DidResolver::method(&DidJwk), "jwk");
    assert_eq!(DidProducer::method(&DidJwk), "jwk");
    let capabilities = DidJwk.capabilities();
    assert_eq!(capabilities.hosting, Hosting::Embedded);
    assert!(capabilities.single_key && !capabilities.updatable);
    assert_eq!(capabilities.fixed_fragment, Some("0"));

    // Create: serialize the JWK, base64url-encode it, prefix `did:jwk:`. The specification's
    // example serializes `crv` first; this crate serializes `kty` first, which is another valid
    // DID for the same key (the method defines no canonical form).
    let jwk: Jwk = serde_json::from_value(json!({
        "crv": "P-256", "kty": "EC",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
    }))
    .unwrap();
    let created = DidJwk::did(&jwk).unwrap();
    assert_eq!(
        created.as_str(),
        "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
    );
    let produced = DidJwk
        .produce(std::slice::from_ref(&jwk), ())
        .await
        .unwrap();
    assert_eq!(produced.id, created);
    assert_eq!(produced, DidJwk::document(&created).unwrap());
    // Both DIDs expand to the same key.
    let spec = DidJwk::document(&did(P256_DID)).unwrap();
    assert_eq!(
        spec.verification_method[0].public_key_jwk(),
        produced.verification_method[0].public_key_jwk()
    );

    // Private parameters never reach the DID.
    let private: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    assert_eq!(
        DidJwk::did(&private).unwrap(),
        DidJwk::did(&private.public()).unwrap()
    );

    // A key too large for a DID (an `x5c` chain, say) is an error, not a panic.
    let mut huge = private.public();
    huge.additional_mut()
        .insert("x5c".to_owned(), json!(["A".repeat(DEFAULT_MAX_LEN)]));
    assert_eq!(
        DidJwk::did(&huge),
        Err(DidError::TooLong {
            max: DidJwk::MAX_DID_LEN
        })
    );
    assert_eq!(DidJwk::MAX_DID_LEN, DEFAULT_MAX_LEN - 2);
    // A DID that fits the DID limit but whose method id `did#0` would not resolves to nothing.
    let mut padding = 0;
    let too_long = loop {
        let mut jwk = private.public();
        jwk.additional_mut()
            .insert("pad".to_owned(), json!("A".repeat(padding)));
        let json = serde_json::to_vec(&jwk).unwrap();
        let did_str = format!(
            "did:jwk:{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json)
        );
        if did_str.len() > DidJwk::MAX_DID_LEN {
            break did_str;
        }
        padding += 1;
    };
    assert!(too_long.len() <= DEFAULT_MAX_LEN);
    assert_eq!(
        DidJwk::document(&did(&too_long)),
        Err(ResolutionError::InvalidDid)
    );
    assert!(matches!(
        DidJwk.produce(std::slice::from_ref(&huge), ()).await,
        Err(ProduceError::UnsupportedKey { index: 0, .. })
    ));
    let document = DidJwk
        .produce(std::slice::from_ref(&private), ())
        .await
        .unwrap();
    assert_eq!(
        document.verification_method[0].public_key_jwk(),
        Some(&private.public())
    );

    assert!(matches!(
        DidJwk.produce(&[], ()).await,
        Err(ProduceError::NoKeys)
    ));
    assert!(matches!(
        DidJwk.produce(&[jwk.clone(), jwk], ()).await,
        Err(ProduceError::TooManyKeys { max: 1, actual: 2 })
    ));
}

#[tokio::test]
async fn read_operation_errors() {
    let encode = |json: &str| {
        format!(
            "did:jwk:{}",
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, json)
        )
    };
    for (did_str, error) in [
        (
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            ResolutionError::MethodNotSupported,
        ),
        // Not base64url: `.` and `%` are DID characters but not base64url ones (`=` padding is
        // not even DID syntax).
        ("did:jwk:abc.def", ResolutionError::InvalidDid),
        ("did:jwk:ab%20", ResolutionError::InvalidDid),
        // Not a JWK.
        (&encode("not json"), ResolutionError::InvalidDid),
        (&encode("{}"), ResolutionError::InvalidDid),
        // A private key must be rejected.
        (
            &encode(
                r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
            ),
            ResolutionError::InvalidDid,
        ),
    ] {
        assert_eq!(DidJwk::document(&did(did_str)), Err(error), "{did_str}");
    }
    // `{"kty":"OKP"}` is a JWK as far as the method goes: whether the key is usable is for the
    // consumer of the document to decide.
    let bare = DidJwk::document(&did(&encode(r#"{"kty":"OKP"}"#))).unwrap();
    assert_eq!(
        bare.verification_method[0].public_key_jwk().map(Jwk::kty),
        Some("OKP")
    );

    let resolver = resolver();
    assert_eq!(
        resolver
            .resolve_with(&did(P256_DID), &ResolutionOptions::accept("text/html"))
            .await,
        Err(ResolutionError::RepresentationNotSupported)
    );
    assert!(
        resolver
            .resolve_with(
                &did(P256_DID),
                &ResolutionOptions::accept("application/did+json")
            )
            .await
            .is_ok()
    );
}
