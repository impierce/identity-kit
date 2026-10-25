//! Specification vectors for the `resolver` module (W3C DID Resolution: the DID Resolution and
//! DID URL Dereferencing algorithms; DID Core 1.0 example documents), exercised through a
//! `did:example` resolver that lives entirely in this file: registering a method needs nothing
//! from the module.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use identity_kit::did::{
    Did, DidDocument, DidUrl, DocumentMetadata, MethodType, ResolutionError, ResolutionErrorKind,
    ResolutionMetadata, ResolutionOptions, ResolutionResult, Service, VerificationMaterial,
    VerificationMethod, VerificationRelationship,
};
use identity_kit::jose::{Jwk, JwkError};
use identity_kit::resolver::{
    DereferenceError, Dereferenced, DidProducer, DidResolver, DocumentCache, Hosting,
    MethodCapabilities, ProduceError, Resolver, ResolverBuilder,
};
use serde_json::json;

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// DID Resolution, "Example: Dereferencing to verification method": the resolved DID document.
const RESOLUTION_EXAMPLE: &str = r#"{
  "@context":[
    "https://www.w3.org/ns/did/v1.1",
    "https://didcomm.org/messaging/contexts/v2",
    "https://identity.foundation/linked-vp/contexts/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Multikey",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
  }],
  "service": [{
    "id": "did:example:123456789abcdefghi#messages",
    "type": "DIDCommMessaging",
    "serviceEndpoint": "https://example.com/messages/8377464"
  }, {
    "id": "did:example:123456789abcdefghi#linkedvp",
    "type": "LinkedVerifiablePresentation",
    "serviceEndpoint": "https://example.com/verifiable-presentation.jsonld"
  }]
}"#;

/// DID Resolution, "Example: Dereferencing to verification method": the output resource (its
/// `@context` is the JSON-LD framing of the example, not part of the verification method).
const RESOLUTION_EXAMPLE_OUTPUT: &str = r#"{
  "id": "did:example:123456789abcdefghi#keys-1",
  "type": "Multikey",
  "controller": "did:example:123456789abcdefghi",
  "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
}"#;

/// DID Core §5.3, Examples 7 to 11: every relationship with one referenced and one embedded
/// method.
const DID_CORE_EXAMPLES_7_TO_11: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }],
  "authentication": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "assertionMethod": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "keyAgreement": [
    "did:example:123456789abcdefghi#keys-1",
    {
      "id": "did:example:123#zC9ByQ8aJs8vrNXyDhPHHNNMSHPcaSgNpjjsBYpMMjsTdS",
      "type": "X25519KeyAgreementKey2019",
      "controller": "did:example:123",
      "publicKeyMultibase": "z9hFgmPVfmBZwRvFEyniQDBkz9LmV7gDEqytWyGZLmDXE"
    }
  ],
  "capabilityInvocation": [
    "did:example:123456789abcdefghi#keys-1",
    {
    "id": "did:example:123456789abcdefghi#keys-2",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "capabilityDelegation": [
    "did:example:123456789abcdefghi#keys-1",
    {
    "id": "did:example:123456789abcdefghi#keys-2",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ]
}"#;

/// DID Core §A.2, Example 20: many key types as `publicKeyJwk` (the `id` of the prose added).
const DID_CORE_EXAMPLE_20: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:example:123",
  "verificationMethod": [
    {
      "id": "did:example:123#key-0",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ"
      }
    },
    {
      "id": "did:example:123#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "pE_mG098rdQjY3MKK2D5SUQ6ZOEW3a6Z6T7Z4SgnzCE"
      }
    },
    {
      "id": "did:example:123#key-2",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8",
        "y": "i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"
      }
    },
    {
      "id": "did:example:123#key-4",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "Ums5WVgwRkRTVVFnU3k5c2xvZllMbEcwM3NPRW91ZzN",
        "y": "nDQW6XZ7b_u2Sy9slofYLlG03sOEoug3I0aAPQ0exs4"
      }
    },
    {
      "id": "did:example:123#key-7",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "RSA",
        "e": "AQAB",
        "n": "UkhWaGJGOUZRMTlFVWtKSElBdENGV2hlU1F2djFNRXh1NVJMQ01UNGpWazlraEpLdjhKZU1YV2UzYldIYXRqUHNrZGYyZGxhR2tXNVFqdE9uVUtMNzQybXZyNHRDbGRLUzNVTElhVDFoSkluTUhIeGoyZ2N1Yk82ZUVlZ0FDUTRRU3U5TE8wSC1MTV9MM0RzUkFCQjdRamE4SGVjcHl1c3BXMVR1X0RicXhjU253ZW5kYW13TDUyVjE3ZUtobE80dVh3djJIRmx4dWZGSE0wS21DSnVqSUt5QXhqRF9tM3FfX0lpSFVWSEQxdERJRXZMUGhHOUF6c24zajk1ZC1zYU"
      }
    }
  ]
}"#;

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn url(s: &str) -> DidUrl {
    DidUrl::parse(s).unwrap()
}

fn document(json: &str) -> DidDocument {
    serde_json::from_str(json).unwrap()
}

// ---------------------------------------------------------------------------------------------
// A `did:example` method, implemented here and only here
// ---------------------------------------------------------------------------------------------

/// Resolves `did:example` DIDs from memory: one response per DID, plus documents by
/// `versionId`. Counts calls and keeps the last options it was given.
#[derive(Default)]
struct ExampleResolver {
    responses: HashMap<Did, Result<ResolutionResult, ResolutionError>>,
    versions: HashMap<(Did, String), DidDocument>,
    calls: AtomicUsize,
    last_options: Mutex<Option<ResolutionOptions>>,
}

impl ExampleResolver {
    fn new() -> Self {
        Self::default()
    }

    fn serving(json: &str) -> Self {
        Self::new().with_document(document(json))
    }

    fn with_document(mut self, document: DidDocument) -> Self {
        self.responses
            .insert(document.id.clone(), Ok(ResolutionResult::new(document)));
        self
    }

    fn with_response(
        mut self,
        did: &str,
        response: Result<ResolutionResult, ResolutionError>,
    ) -> Self {
        self.responses.insert(Did::parse(did).unwrap(), response);
        self
    }

    fn with_version(mut self, version: &str, document: DidDocument) -> Self {
        self.versions
            .insert((document.id.clone(), version.to_owned()), document);
        self
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_options(&self) -> Option<ResolutionOptions> {
        self.last_options.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl DidResolver for ExampleResolver {
    fn method(&self) -> &'static str {
        "example"
    }

    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_options.lock().unwrap() = Some(options.clone());
        if let Some(version) = options.properties.get("versionId") {
            let version = version.as_str().ok_or(ResolutionErrorKind::InternalError)?;
            return self
                .versions
                .get(&(did.clone(), version.to_owned()))
                .cloned()
                .map(|document| {
                    let mut metadata = DocumentMetadata::default();
                    metadata.version_id = Some(version.to_owned());
                    ResolutionResult::new(document).with_document_metadata(metadata)
                })
                .ok_or(ResolutionErrorKind::NotFound.into());
        }
        self.responses
            .get(did)
            .cloned()
            .unwrap_or(Err(ResolutionErrorKind::NotFound.into()))
    }
}

/// Produces `did:example` documents: the method-specific id is the parameter, every key becomes
/// a `JsonWebKey2020` method `#key-<n>` usable for authentication and assertions.
struct ExampleProducer;

#[async_trait::async_trait]
impl DidProducer for ExampleProducer {
    type Params = String;

    fn method(&self) -> &'static str {
        "example"
    }

    fn capabilities(&self) -> MethodCapabilities {
        MethodCapabilities::new(Hosting::Registry).with_updatable(true)
    }

    async fn produce(&self, keys: &[Jwk], params: String) -> Result<DidDocument, ProduceError> {
        if keys.is_empty() {
            return Err(ProduceError::NoKeys);
        }
        let did = Did::parse(&format!("did:example:{params}"))
            .map_err(|e| ProduceError::InvalidParams(e.to_string()))?;
        let mut builder = DidDocument::builder(did.clone());
        for (index, key) in keys.iter().enumerate() {
            if key.is_private() {
                return Err(ProduceError::UnsupportedKey {
                    index,
                    reason: "private key".to_owned(),
                });
            }
            let method = VerificationMethod::new(
                did.join(&format!("#key-{index}")).unwrap(),
                MethodType::JSON_WEB_KEY_2020,
                did.clone(),
                VerificationMaterial::jwk(key),
            );
            builder = builder.verification_method(
                method,
                [
                    VerificationRelationship::Authentication,
                    VerificationRelationship::AssertionMethod,
                ],
            );
        }
        Ok(builder.build()?)
    }
}

fn resolver_for(resolver: ExampleResolver) -> (Arc<ExampleResolver>, Resolver) {
    let resolver = Arc::new(resolver);
    let registry = Resolver::builder().with(Arc::clone(&resolver)).build();
    (resolver, registry)
}

// ---------------------------------------------------------------------------------------------
// Dereferencing (DID Resolution "DID URL Dereferencing Algorithm")
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn did_resolution_example_dereferences_to_verification_method() {
    let (_, resolver) = resolver_for(ExampleResolver::serving(RESOLUTION_EXAMPLE));

    let input = url("did:example:123456789abcdefghi#keys-1");
    let expected: VerificationMethod = serde_json::from_str(RESOLUTION_EXAMPLE_OUTPUT).unwrap();
    let output = resolver.dereference(&input).await.unwrap();
    assert_eq!(output.as_verification_method(), Some(&expected));
    assert_eq!(
        output,
        Dereferenced::VerificationMethod(Box::new(expected.clone()))
    );
    assert!(output.as_document().is_none() && output.as_service().is_none());

    assert_eq!(
        resolver.resolve_verification_method(&input, None).await,
        Ok(expected.clone())
    );
    // The method is not referenced by any relationship.
    assert_eq!(
        resolver
            .resolve_verification_method(&input, Some(VerificationRelationship::Authentication))
            .await,
        Err(DereferenceError::NotInRelationship {
            id: input.clone(),
            relationship: VerificationRelationship::Authentication,
        })
    );

    // The services of the same document.
    let messages = resolver
        .dereference(&url("did:example:123456789abcdefghi#messages"))
        .await
        .unwrap();
    let service = messages.as_service().unwrap();
    assert!(service.has_type("DIDCommMessaging"));
    assert_eq!(
        service.service_endpoint.uris().next().unwrap().as_str(),
        "https://example.com/messages/8377464"
    );
    assert!(matches!(
        resolver
            .dereference(&url("did:example:123456789abcdefghi#linkedvp"))
            .await,
        Ok(Dereferenced::Service(_))
    ));

    // No fragment: the document itself, as resolved.
    let bare = resolver
        .dereference(&url("did:example:123456789abcdefghi"))
        .await
        .unwrap();
    assert_eq!(bare.as_document(), Some(&document(RESOLUTION_EXAMPLE)));

    // A fragment nothing carries.
    assert_eq!(
        resolver
            .dereference(&url("did:example:123456789abcdefghi#keys-2"))
            .await,
        Err(DereferenceError::NotFound(url(
            "did:example:123456789abcdefghi#keys-2"
        )))
    );
    // The fragment is matched against the `id` of the resource, so a query does not get in
    // the way of a fragment and the reported id is `did#fragment`.
    assert_eq!(
        resolver
            .dereference(&url("did:example:123456789abcdefghi?versionId=1#keys-2"))
            .await,
        Err(DereferenceError::Resolution {
            did: did("did:example:123456789abcdefghi"),
            error: ResolutionErrorKind::NotFound.into(),
        })
    );
}

#[tokio::test]
async fn did_resolution_service_endpoint_example_is_method_specific() {
    // DID Resolution, "Example: Dereferencing to service endpoint URL". Service endpoint
    // construction is not implemented: the `service` and `relativeRef` parameters are reported
    // as method-specific rather than silently ignored.
    let (_, resolver) = resolver_for(ExampleResolver::serving(RESOLUTION_EXAMPLE));
    let input = url(
        "did:example:123456789abcdefghi?service=messages&relativeRef=%2Fsome%2Fpath%3Fquery#frag",
    );
    assert_eq!(
        resolver.dereference(&input).await,
        Err(DereferenceError::MethodSpecific(input.clone()))
    );
    assert_eq!(
        resolver.resolve_public_key(&input, None).await,
        Err(DereferenceError::MethodSpecific(input))
    );
}

#[tokio::test]
async fn did_core_example_20_public_keys() {
    let doc = document(DID_CORE_EXAMPLE_20);
    let (_, resolver) = resolver_for(ExampleResolver::new().with_document(doc.clone()));

    for method in &doc.verification_method {
        let jwk = resolver.resolve_public_key(&method.id, None).await.unwrap();
        assert_eq!(&jwk, method.public_key_jwk().unwrap());
        assert!(!jwk.is_private());
    }
    let ed25519 = resolver
        .resolve_public_key(&url("did:example:123#key-0"), None)
        .await
        .unwrap();
    assert_eq!((ed25519.kty(), ed25519.crv()), ("OKP", Some("Ed25519")));
    let rsa = resolver
        .resolve_public_key(&url("did:example:123#key-7"), None)
        .await
        .unwrap();
    assert_eq!((rsa.kty(), rsa.e()), ("RSA", Some("AQAB")));

    assert_eq!(
        resolver
            .resolve_public_key(&url("did:example:123"), None)
            .await,
        Err(DereferenceError::NotVerificationMethod(url(
            "did:example:123"
        )))
    );
    assert_eq!(
        resolver
            .resolve_public_key(&url("did:example:123#key-3"), None)
            .await,
        Err(DereferenceError::NotFound(url("did:example:123#key-3")))
    );
}

#[tokio::test]
async fn multibase_material_decodes_as_multikey() {
    let (_, resolver) = resolver_for(ExampleResolver::serving(RESOLUTION_EXAMPLE));
    let id = url("did:example:123456789abcdefghi#keys-1");
    // The example's `z6MkmM42…` is the Multikey of an Ed25519 key.
    let jwk = resolver.resolve_public_key(&id, None).await.unwrap();
    assert_eq!((jwk.kty(), jwk.crv()), ("OKP", Some("Ed25519")));
    assert_eq!(
        jwk.to_multikey().unwrap(),
        "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
    );

    // A Multikey of a type this crate cannot read (BLS12-381 G2, multicodec 0xeb) is an error.
    let bls = RESOLUTION_EXAMPLE.replace(
        "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu",
        "zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb",
    );
    let (_, resolver) = resolver_for(ExampleResolver::serving(&bls));
    assert_eq!(
        resolver.resolve_public_key(&id, None).await,
        Err(DereferenceError::NoJwk {
            id: id.clone(),
            method_type: MethodType::MULTIKEY,
            source: Box::new(JwkError::UnsupportedMulticodec(0xeb)),
        })
    );
    let service = url("did:example:123456789abcdefghi#messages");
    assert_eq!(
        resolver.resolve_public_key(&service, None).await,
        Err(DereferenceError::NotVerificationMethod(service.clone()))
    );
    assert_eq!(
        resolver.resolve_verification_method(&service, None).await,
        Err(DereferenceError::NotVerificationMethod(service))
    );
}

#[tokio::test]
async fn did_core_examples_7_to_11_relationships() {
    let (_, resolver) = resolver_for(ExampleResolver::serving(DID_CORE_EXAMPLES_7_TO_11));
    let keys_1 = url("did:example:123456789abcdefghi#keys-1");
    let keys_2 = url("did:example:123456789abcdefghi#keys-2");

    // `keys-1` is listed and referenced from every relationship.
    for relationship in VerificationRelationship::ALL {
        let method = resolver
            .resolve_verification_method(&keys_1, Some(*relationship))
            .await
            .unwrap();
        assert_eq!(method.id, keys_1);
    }
    // `keys-2` is embedded in four relationships but not `keyAgreement`.
    let embedded = resolver
        .resolve_verification_method(&keys_2, Some(VerificationRelationship::AssertionMethod))
        .await
        .unwrap();
    assert_eq!(embedded.id, keys_2);
    assert_eq!(
        resolver
            .resolve_verification_method(&keys_2, Some(VerificationRelationship::KeyAgreement))
            .await,
        Err(DereferenceError::NotInRelationship {
            id: keys_2.clone(),
            relationship: VerificationRelationship::KeyAgreement,
        })
    );
    // Dereferencing finds embedded methods too.
    assert!(matches!(
        resolver.dereference(&keys_2).await,
        Ok(Dereferenced::VerificationMethod(method)) if method.id == keys_2
    ));
    // The X25519 key is embedded under another DID's document, which does not exist.
    let foreign = url("did:example:123#zC9ByQ8aJs8vrNXyDhPHHNNMSHPcaSgNpjjsBYpMMjsTdS");
    assert_eq!(
        resolver.dereference(&foreign).await,
        Err(DereferenceError::Resolution {
            did: did("did:example:123"),
            error: ResolutionErrorKind::NotFound.into(),
        })
    );
}

#[tokio::test]
async fn did_parameters_select_the_version() {
    let mut v1 = document(DID_CORE_EXAMPLE_20);
    v1.verification_method.truncate(1);
    let v2 = document(DID_CORE_EXAMPLE_20);
    let (example, resolver) = resolver_for(
        ExampleResolver::new()
            .with_document(v2.clone())
            .with_version("1", v1.clone())
            .with_version("2", v2.clone()),
    );

    let versioned = resolver
        .dereference(&url("did:example:123?versionId=1"))
        .await
        .unwrap();
    assert_eq!(versioned.as_document(), Some(&v1));
    let mut expected = ResolutionOptions::default();
    expected
        .properties
        .insert("versionId".to_owned(), json!("1"));
    assert_eq!(example.last_options(), Some(expected));

    // Only version 2 has `key-4`; the fragment is looked up in the selected version.
    assert_eq!(
        resolver
            .dereference(&url("did:example:123?versionId=1#key-4"))
            .await,
        Err(DereferenceError::NotFound(url("did:example:123#key-4")))
    );
    assert!(
        resolver
            .resolve_public_key(&url("did:example:123?versionId=2#key-4"), None)
            .await
            .is_ok()
    );

    // Values are percent-decoded; a parameter without `=` has an empty value; empty pairs are
    // skipped.
    let _ = resolver
        .dereference(&url(
            "did:example:123?versionTime=2021-05-10T17%3A00%3A00Z&&versionId",
        ))
        .await;
    let options = example.last_options().unwrap();
    assert_eq!(
        options.properties.get("versionTime"),
        Some(&json!("2021-05-10T17:00:00Z"))
    );
    assert_eq!(options.properties.get("versionId"), Some(&json!("")));
    assert_eq!(options.properties.len(), 2);

    // A scalar parameter given twice is ambiguous (DID Resolution "Duplicate Parameter
    // Handling").
    let twice = url("did:example:123?versionId=1&versionId=2");
    assert_eq!(
        resolver.dereference(&twice).await,
        Err(DereferenceError::InvalidDidUrl {
            url: twice.clone(),
            reason: "DID parameter `versionId` is given twice".to_owned(),
        })
    );

    // Paths and other parameters belong to the method.
    for input in [
        "did:example:123/path",
        "did:example:123/path#key-0",
        "did:example:123?foo=bar",
        "did:example:123?versionId=1&transformKeys=jwks",
        "did:example:123?service=files&relativeRef=%2Fresume.pdf",
        "did:example:123?hl=zQmWvQxTqbG2Z9HPJgG57jjwR154cKhbtJenbyYTWkjgF3e",
    ] {
        let input = url(input);
        assert_eq!(
            resolver.dereference(&input).await,
            Err(DereferenceError::MethodSpecific(input.clone())),
            "{input}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Resolution (DID Resolution "DID Resolution Algorithm")
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn resolution_results_are_normalized() {
    let doc = document(DID_CORE_EXAMPLE_20);
    let other = Did::parse("did:example:other").unwrap();
    let (_, resolver) = resolver_for(
        ExampleResolver::new()
            .with_document(doc.clone())
            .with_response(
                "did:example:err",
                Err(ResolutionError::new(ResolutionErrorKind::InternalError)
                    .with_source(std::io::Error::other("ledger unreachable"))),
            )
            .with_response(
                "did:example:meta",
                Ok(ResolutionResult::error(
                    ResolutionError::new(ResolutionErrorKind::RepresentationNotSupported)
                        .with_detail("only CBOR is served"),
                )),
            )
            .with_response("did:example:empty", Ok(ResolutionResult::default()))
            .with_response("did:example:wrong", Ok(ResolutionResult::new(doc.clone())))
            .with_response("did:example:canonical", {
                let mut metadata = DocumentMetadata::default();
                metadata.canonical_id = Some(doc.id.clone());
                metadata.equivalent_id = vec![Did::parse("did:example:canonical").unwrap()];
                Ok(ResolutionResult::new(doc.clone()).with_document_metadata(metadata))
            })
            .with_response(
                "did:example:other",
                Ok(ResolutionResult::new(DidDocument::new(other.clone()))
                    .with_resolution_metadata(ResolutionMetadata::content_type(
                        "application/did+json",
                    ))),
            ),
    );

    let result = resolver.resolve(&doc.id).await.unwrap();
    assert_eq!(result.document.as_ref(), Some(&doc));
    assert_eq!(resolver.resolve_document(&doc.id).await.unwrap(), doc);

    // Metadata comes through.
    let result = resolver.resolve(&other).await.unwrap();
    assert_eq!(
        result.resolution_metadata.content_type.as_deref(),
        Some("application/did+json")
    );

    // A method without a resolver.
    assert_eq!(
        resolver.resolve(&did("did:web:example.com")).await,
        Err(ResolutionErrorKind::MethodNotSupported.into())
    );
    assert_eq!(
        resolver
            .resolve_document(&did(
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ))
            .await,
        Err(ResolutionErrorKind::MethodNotSupported.into())
    );
    // Both error forms become `Err`.
    assert_eq!(
        resolver.resolve(&did("did:example:missing")).await,
        Err(ResolutionErrorKind::NotFound.into())
    );
    // The method's detail and source come through either way.
    let error = resolver.resolve(&did("did:example:err")).await.unwrap_err();
    assert_eq!(error, ResolutionErrorKind::InternalError);
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("ledger unreachable".to_owned())
    );
    let error = resolver
        .resolve(&did("did:example:meta"))
        .await
        .unwrap_err();
    assert_eq!(error, ResolutionErrorKind::RepresentationNotSupported);
    assert_eq!(error.detail(), Some("only CBOR is served"));
    let error = resolver
        .resolve(&did("did:example:empty"))
        .await
        .unwrap_err();
    assert_eq!(error, ResolutionErrorKind::NotFound);
    assert_eq!(
        error.detail(),
        Some("the resolver returned neither a document nor an error")
    );
    // A document for another DID is refused, unless the DID is an equivalent of the canonical
    // one the document is for.
    let error = resolver
        .resolve(&did("did:example:wrong"))
        .await
        .unwrap_err();
    assert_eq!(error, ResolutionErrorKind::InvalidDidDocument);
    assert_eq!(
        error.detail(),
        Some("the resolver returned the document of `did:example:123` for `did:example:wrong`")
    );
    let canonical = resolver
        .resolve(&did("did:example:canonical"))
        .await
        .unwrap();
    assert_eq!(canonical.document.as_ref().map(|d| &d.id), Some(&doc.id));
    // A fragment of the equivalent DID is looked up under the canonical id of the document.
    let method = doc.verification_method.first().unwrap();
    let fragment = method.id.fragment().unwrap();
    let via_equivalent = url(&format!("did:example:canonical#{fragment}"));
    assert_eq!(
        resolver
            .dereference(&via_equivalent)
            .await
            .unwrap()
            .as_verification_method(),
        Some(method)
    );
    assert_eq!(
        resolver
            .resolve_verification_method(&via_equivalent, None)
            .await
            .unwrap(),
        *method
    );
    assert_eq!(
        resolver
            .dereference(&url("did:example:canonical#nope"))
            .await,
        Err(DereferenceError::NotFound(
            doc.id.to_url().with_fragment("nope")
        ))
    );

    // Dereferencing wraps resolution errors with the DID.
    let error = resolver
        .dereference(&url("did:example:missing#key-0"))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        DereferenceError::Resolution {
            did: did("did:example:missing"),
            error: ResolutionErrorKind::NotFound.into(),
        }
    );
    assert_eq!(
        error.to_string(),
        "resolving `did:example:missing`: DID not found"
    );
    assert_eq!(
        resolver.dereference(&url("did:web:example.com")).await,
        Err(DereferenceError::Resolution {
            did: did("did:web:example.com"),
            error: ResolutionErrorKind::MethodNotSupported.into(),
        })
    );
}

#[tokio::test]
async fn deactivated_dids_resolve_but_do_not_dereference() {
    let doc = document(DID_CORE_EXAMPLE_20);
    let mut deactivated = DocumentMetadata::default();
    deactivated.deactivated = Some(true);
    let (_, resolver) = resolver_for(
        ExampleResolver::new()
            .with_response(
                "did:example:gone",
                Ok(ResolutionResult::default().with_document_metadata(deactivated.clone())),
            )
            .with_response(
                "did:example:123",
                Ok(ResolutionResult::new(doc).with_document_metadata(deactivated)),
            ),
    );

    // The DID Resolution shape of a deactivated DID: no document, `deactivated: true`.
    let gone = did("did:example:gone");
    let result = resolver.resolve(&gone).await.unwrap();
    assert!(result.document.is_none() && result.document_metadata.is_deactivated());
    assert_eq!(
        resolver.resolve_document(&gone).await,
        Err(ResolutionErrorKind::NotFound.into())
    );
    assert_eq!(
        resolver.dereference(&gone.to_url()).await,
        Err(DereferenceError::Deactivated(gone.clone()))
    );

    // A method that still returns the last document of a deactivated DID: `resolve` shows it
    // with its metadata, the shortcuts refuse it.
    let key = url("did:example:123#key-0");
    let result = resolver.resolve(key.did()).await.unwrap();
    assert!(result.document.is_some() && result.document_metadata.is_deactivated());
    assert_eq!(
        resolver.resolve_document(key.did()).await,
        Err(ResolutionErrorKind::NotFound.into())
    );
    assert_eq!(
        resolver.resolve_public_key(&key, None).await,
        Err(DereferenceError::Deactivated(key.did().clone()))
    );
    assert_eq!(
        resolver.dereference(&key).await,
        Err(DereferenceError::Deactivated(key.did().clone()))
    );
}

// ---------------------------------------------------------------------------------------------
// Registry and builder
// ---------------------------------------------------------------------------------------------

struct Other;

#[async_trait::async_trait]
impl DidResolver for Other {
    fn method(&self) -> &'static str {
        "other"
    }

    async fn resolve(
        &self,
        did: &Did,
        _: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        Ok(ResolutionResult::new(DidDocument::new(did.clone())))
    }
}

#[tokio::test]
async fn builder_registers_by_method_and_later_registrations_win() {
    let first = Arc::new(ExampleResolver::serving(DID_CORE_EXAMPLE_20));
    let second = Arc::new(ExampleResolver::serving(RESOLUTION_EXAMPLE));
    let resolver = Resolver::builder()
        .with(Other)
        .with(Arc::clone(&first))
        .with_arc(Arc::clone(&second) as Arc<dyn DidResolver>)
        .build();

    assert_eq!(resolver.methods(), ["example", "other"]);
    assert!(resolver.supports("example") && resolver.supports("other"));
    assert!(!resolver.supports("web") && !resolver.supports("did:example"));
    assert_eq!(
        resolver.resolver("example").map(|r| r.method()),
        Some("example")
    );
    assert!(resolver.resolver("web").is_none());
    assert!(resolver.cache().is_none());

    assert!(
        resolver
            .resolve(&did("did:example:123456789abcdefghi"))
            .await
            .is_ok()
    );
    assert_eq!(
        resolver.resolve(&did("did:example:123")).await,
        Err(ResolutionErrorKind::NotFound.into())
    );
    assert_eq!((first.calls(), second.calls()), (0, 2));
    assert_eq!(
        resolver
            .resolve_document(&did("did:other:x"))
            .await
            .unwrap()
            .id,
        did("did:other:x")
    );

    assert_eq!(
        format!("{resolver:?}"),
        r#"Resolver { methods: ["example", "other"], cache: None }"#
    );
    assert_eq!(
        format!("{:?}", ResolverBuilder::new()),
        "ResolverBuilder { methods: [], cache: None }"
    );
    assert_eq!(
        format!("{:?}", ResolverBuilder::default().with(Other)),
        r#"ResolverBuilder { methods: ["other"], cache: None }"#
    );
    let empty = Resolver::builder().build();
    assert!(empty.methods().is_empty());
    assert_eq!(
        empty.resolve(&did("did:example:123")).await,
        Err(ResolutionErrorKind::MethodNotSupported.into())
    );
}

#[tokio::test]
async fn resolvers_forward_through_references_boxes_and_arcs() {
    let example = ExampleResolver::serving(DID_CORE_EXAMPLE_20);
    let example_did = did("did:example:123");
    let options = ResolutionOptions::default();

    let by_ref: &dyn DidResolver = &&example;
    assert_eq!(by_ref.method(), "example");
    assert!(by_ref.resolve(&example_did, &options).await.is_ok());

    let boxed: Box<dyn DidResolver> = Box::new(Other);
    assert_eq!(boxed.method(), "other");
    let resolver = Resolver::builder().with(boxed).build();
    assert!(resolver.resolve(&did("did:other:1")).await.is_ok());

    let shared = Arc::new(example);
    let resolver = Resolver::builder().with(Arc::clone(&shared)).build();
    assert!(resolver.resolve(&example_did).await.is_ok());
    assert_eq!(shared.calls(), 2);
}

// ---------------------------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn cache_serves_repeated_resolutions_without_options() {
    let example = Arc::new(ExampleResolver::serving(DID_CORE_EXAMPLE_20).with_response(
        "did:example:gone",
        Ok(ResolutionResult::default().with_document_metadata({
            let mut metadata = DocumentMetadata::default();
            metadata.deactivated = Some(true);
            metadata
        })),
    ));
    let resolver = Resolver::builder()
        .with(Arc::clone(&example))
        .cache(Duration::from_secs(60))
        .build();
    let did = did("did:example:123");
    let cache = resolver.cache().unwrap();
    assert_eq!(cache.ttl(), Duration::from_secs(60));
    assert_eq!(cache.capacity(), DocumentCache::DEFAULT_CAPACITY);

    let first = resolver.resolve(&did).await.unwrap();
    let second = resolver.resolve(&did).await.unwrap();
    assert_eq!(first, second);
    assert!(
        resolver
            .resolve_public_key(&url("did:example:123#key-0"), None)
            .await
            .is_ok()
    );
    assert_eq!(example.calls(), 1);
    assert_eq!(cache.len(), 1);
    assert!(cache.get(&did).is_some());

    // Options bypass the cache in both directions.
    let versioned = ResolutionOptions::accept("application/did+json");
    assert!(resolver.resolve_with(&did, &versioned).await.is_ok());
    assert!(resolver.resolve_with(&did, &versioned).await.is_ok());
    assert_eq!(example.calls(), 3);
    assert!(
        resolver
            .dereference(&url("did:example:123?versionId=1"))
            .await
            .is_err()
    );
    assert_eq!(example.calls(), 4);
    assert_eq!(cache.len(), 1);

    // Failures are not cached.
    let missing = Did::parse("did:example:missing").unwrap();
    assert!(resolver.resolve(&missing).await.is_err());
    assert!(resolver.resolve(&missing).await.is_err());
    assert_eq!(example.calls(), 6);

    // Deactivation is.
    let gone = Did::parse("did:example:gone").unwrap();
    assert!(resolver.resolve(&gone).await.is_ok());
    assert!(resolver.resolve(&gone).await.is_ok());
    assert_eq!(example.calls(), 7);
    assert_eq!(cache.len(), 2);
    assert!(!cache.is_empty());

    // Invalidation.
    assert_eq!(cache.remove(&did), Some(first));
    assert_eq!(cache.remove(&did), None);
    assert!(resolver.resolve(&did).await.is_ok());
    assert_eq!(example.calls(), 8);
    cache.clear();
    assert!(cache.is_empty());
    assert!(resolver.resolve(&did).await.is_ok());
    assert_eq!(example.calls(), 9);

    assert_eq!(
        format!("{resolver:?}"),
        r#"Resolver { methods: ["example"], cache: Some(DocumentCache { ttl: 60s, capacity: 1024, len: 1 }) }"#
    );
}

#[tokio::test]
async fn cache_entries_expire() {
    let example = Arc::new(ExampleResolver::serving(DID_CORE_EXAMPLE_20));
    let resolver = Resolver::builder()
        .with(Arc::clone(&example))
        .with_cache(DocumentCache::with_capacity(Duration::from_millis(500), 8))
        .build();
    let did = did("did:example:123");

    assert!(resolver.resolve(&did).await.is_ok());
    assert!(resolver.resolve(&did).await.is_ok());
    assert_eq!(example.calls(), 1);
    std::thread::sleep(Duration::from_millis(1000));
    assert!(resolver.cache().unwrap().is_empty());
    assert!(resolver.resolve(&did).await.is_ok());
    assert_eq!(example.calls(), 2);
    assert_eq!(resolver.cache().unwrap().len(), 1);
}

#[test]
fn cache_is_bounded() {
    let cache = DocumentCache::with_capacity(Duration::from_millis(500), 2);
    assert_eq!(cache.capacity(), 2);
    assert_eq!(
        DocumentCache::with_capacity(Duration::ZERO, 0).capacity(),
        1
    );
    let entry = |n: usize| {
        let did = Did::parse(&format!("did:example:{n}")).unwrap();
        (did.clone(), ResolutionResult::new(DidDocument::new(did)))
    };
    let (a, a_result) = entry(1);
    let (b, b_result) = entry(2);
    let (c, c_result) = entry(3);

    cache.insert(a.clone(), a_result.clone());
    std::thread::sleep(Duration::from_millis(2));
    cache.insert(b.clone(), b_result.clone());
    std::thread::sleep(Duration::from_millis(2));
    // Replacing an entry needs no room.
    cache.insert(a.clone(), a_result.clone());
    assert_eq!(cache.len(), 2);
    // A third entry evicts the one that expires soonest, which is `b` now.
    cache.insert(c.clone(), c_result.clone());
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.get(&a), Some(a_result));
    assert_eq!(cache.get(&b), None);
    assert_eq!(cache.get(&c), Some(c_result.clone()));
    assert_eq!(cache.purge_expired(), 0);

    // Expired entries make room first, and are gone from every accessor.
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(cache.get(&c), None);
    assert_eq!(cache.len(), 0);
    assert!(cache.is_empty());
    assert_eq!(cache.remove(&c), None);
    cache.insert(b.clone(), b_result.clone());
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.get(&b), Some(b_result));
    assert_eq!(cache.purge_expired(), 1);
    assert_eq!(
        format!("{cache:?}"),
        "DocumentCache { ttl: 500ms, capacity: 2, len: 1 }"
    );

    // An entry that can never expire.
    let forever = DocumentCache::new(Duration::MAX);
    forever.insert(a.clone(), c_result);
    assert!(forever.get(&a).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_resolutions_share_one_resolver() {
    let example = Arc::new(ExampleResolver::serving(DID_CORE_EXAMPLE_20));
    let resolver = Arc::new(
        Resolver::builder()
            .with(Arc::clone(&example))
            .cache(Duration::from_secs(60))
            .build(),
    );
    const TASKS: usize = 64;

    let tasks: Vec<_> = (0..TASKS)
        .map(|i| {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move {
                let did = did("did:example:123");
                let key = url("did:example:123#key-0");
                let document = resolver.resolve_document(&did).await.unwrap();
                assert_eq!(document.id, did);
                let jwk = resolver.resolve_public_key(&key, None).await.unwrap();
                assert_eq!(jwk.crv(), Some("Ed25519"));
                assert!(matches!(
                    resolver.dereference(&key).await,
                    Ok(Dereferenced::VerificationMethod(_))
                ));
                i
            })
        })
        .collect();
    let mut done = Vec::new();
    for task in tasks {
        done.push(task.await.unwrap());
    }
    done.sort_unstable();
    assert_eq!(done, (0..TASKS).collect::<Vec<_>>());

    // Every task found the method; concurrent misses may each reach it, repeats never do.
    let calls = example.calls();
    assert!((1..=TASKS).contains(&calls), "{calls} calls");
    assert!(resolver.resolve(&did("did:example:123")).await.is_ok());
    assert_eq!(example.calls(), calls);
}

// ---------------------------------------------------------------------------------------------
// Production
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn producer_makes_documents_the_resolver_serves() {
    let producer = ExampleProducer;
    assert_eq!(producer.method(), "example");
    assert_eq!(
        producer.capabilities(),
        MethodCapabilities::new(Hosting::Registry).with_updatable(true)
    );

    let ed25519: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }))
    .unwrap();
    let p256: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }))
    .unwrap();
    let keys = [ed25519.clone(), p256];

    let document = producer.produce(&keys, "123".to_owned()).await.unwrap();
    assert_eq!(document.id, did("did:example:123"));
    assert_eq!(document.verification_method.len(), 2);
    assert_eq!(document.authentication.len(), 2);
    assert_eq!(document.assertion_method.len(), 2);
    // Determinism.
    assert_eq!(
        producer.produce(&keys, "123".to_owned()).await.unwrap(),
        document
    );

    // A produced document resolves through the registry like any other.
    let (_, resolver) = resolver_for(ExampleResolver::new().with_document(document));
    let key = url("did:example:123#key-0");
    assert_eq!(
        resolver.resolve_public_key(&key, None).await.unwrap(),
        ed25519
    );
    assert!(
        resolver
            .resolve_verification_method(&key, Some(VerificationRelationship::AssertionMethod))
            .await
            .is_ok()
    );
    assert_eq!(
        resolver
            .resolve_verification_method(&key, Some(VerificationRelationship::KeyAgreement))
            .await,
        Err(DereferenceError::NotInRelationship {
            id: key,
            relationship: VerificationRelationship::KeyAgreement,
        })
    );

    // Errors.
    assert!(matches!(
        producer.produce(&[], "123".to_owned()).await,
        Err(ProduceError::NoKeys)
    ));
    let private: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    let error = producer
        .produce(&[ed25519, private], "123".to_owned())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "key 1 cannot be used: private key");
    assert!(matches!(
        error,
        ProduceError::UnsupportedKey { index: 1, .. }
    ));
    let error = producer
        .produce(&keys, "not valid".to_owned())
        .await
        .unwrap_err();
    assert!(matches!(error, ProduceError::InvalidParams(_)));
    assert!(error.to_string().starts_with("invalid parameters: "));
}

#[test]
fn capabilities_and_error_messages() {
    let jwk = MethodCapabilities::new(Hosting::Embedded)
        .with_single_key(true)
        .with_fixed_fragment("0");
    assert!(!jwk.updatable && jwk.single_key);
    assert_eq!(jwk.fixed_fragment, Some("0"));
    let web = MethodCapabilities::new(Hosting::Web).with_updatable(true);
    assert!(web.updatable && !web.single_key && web.fixed_fragment.is_none());
    assert_ne!(jwk, web);
    for (hosting, name) in [
        (Hosting::Embedded, "embedded"),
        (Hosting::Web, "web"),
        (Hosting::Registry, "registry"),
    ] {
        assert_eq!(hosting.as_str(), name);
        assert_eq!(hosting.to_string(), name);
    }

    assert_eq!(
        ProduceError::NoKeys.to_string(),
        "at least one key is required"
    );
    assert_eq!(
        ProduceError::TooManyKeys { max: 1, actual: 2 }.to_string(),
        "at most 1 key(s) can be used, got 2"
    );
    assert_eq!(
        ProduceError::InvalidParams("no origin".to_owned()).to_string(),
        "invalid parameters: no origin"
    );
    let backend = ProduceError::backend(std::io::Error::other("ledger down"));
    assert_eq!(backend.to_string(), "backend error: ledger down");
    assert!(std::error::Error::source(&backend).is_some());
    let document = ProduceError::from(
        DidDocument::builder(did("did:example:1"))
            .service(Service::new(
                url("did:example:1#s"),
                "A",
                identity_kit::did::Uri::parse("https://example.com").unwrap(),
            ))
            .service(Service::new(
                url("did:example:1#s"),
                "B",
                identity_kit::did::Uri::parse("https://example.com").unwrap(),
            ))
            .build()
            .unwrap_err(),
    );
    assert_eq!(
        document.to_string(),
        "service `did:example:1#s` already exists"
    );

    let id = url("did:example:123#key-1");
    for (error, message) in [
        (
            DereferenceError::InvalidDidUrl {
                url: id.clone(),
                reason: "DID parameter `versionId` is given twice".to_owned(),
            },
            "`did:example:123#key-1`: DID parameter `versionId` is given twice",
        ),
        (
            DereferenceError::MethodSpecific(id.clone()),
            "`did:example:123#key-1` has a path or query that only its DID method can dereference",
        ),
        (
            DereferenceError::Deactivated(did("did:example:123")),
            "`did:example:123` is deactivated",
        ),
        (
            DereferenceError::NotFound(id.clone()),
            "`did:example:123#key-1` names no verification method or service of the DID document",
        ),
        (
            DereferenceError::NotVerificationMethod(id.clone()),
            "`did:example:123#key-1` is not a verification method",
        ),
        (
            DereferenceError::NotInRelationship {
                id: id.clone(),
                relationship: VerificationRelationship::AssertionMethod,
            },
            "verification method `did:example:123#key-1` is not listed under `assertionMethod`",
        ),
        (
            DereferenceError::NoJwk {
                id: id.clone(),
                method_type: MethodType::MULTIKEY,
                source: Box::new(JwkError::UnsupportedMulticodec(0xeb)),
            },
            "verification method `did:example:123#key-1` of type `Multikey` has no usable JWK: unsupported multicodec 0xeb",
        ),
    ] {
        assert_eq!(error.to_string(), message);
    }
    let resolution = DereferenceError::Resolution {
        did: did("did:example:123"),
        error: ResolutionErrorKind::MethodNotSupported.into(),
    };
    assert_eq!(
        std::error::Error::source(&resolution).map(ToString::to_string),
        Some("DID method not supported".to_owned())
    );
}
