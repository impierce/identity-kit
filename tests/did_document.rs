//! Specification vectors for the DID document data model (W3C DID Core 1.0 §5 and §6.2).
//!
//! The JSON fixtures are the examples of the DID Core 1.0 Recommendation with their editorial
//! defects removed: comments, `...` placeholders, a missing comma after `@context` (Examples 1
//! and 2) and a trailing comma (Example 4). Where an example is a fragment without `id`, the
//! `id` the surrounding prose names is added. "Byte-identical" means that parsing an example and
//! serializing it again gives the same compact JSON, member for member, as the example itself.

use identity_kit::did::{
    Context, DEFAULT_MAX_LEN, Did, DidDocument, DidError, DidUrl, DidUrlReference, DocumentError,
    MethodRef, MethodType, OneOrMany, Service, ServiceEndpoint, Uri, VerificationMaterial,
    VerificationMethod, VerificationRelationship,
};
use identity_kit::jose::Jwk;
use indexmap::IndexMap;
use proptest::prelude::*;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// DID Core §1.3, Example 1 (also §6.2, Example 13 with its JSON-LD context).
const EXAMPLE_1: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "authentication": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}"#;

/// DID Core §3.2.2, Example 2: a relative DID URL.
const EXAMPLE_2: &str = r##"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:example:123456789abcdefghi",
  "verificationMethod": [{
    "id": "did:example:123456789abcdefghi#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }],
  "authentication": [
    "#key-1"
  ]
}"##;

/// DID Core §5.1.1, Example 3: the minimal document.
const EXAMPLE_3: &str = r#"{
  "id": "did:example:123456789abcdefghijk"
}"#;

/// DID Core §5.1.2, Example 4: a controller.
const EXAMPLE_4: &str = r#"{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:123456789abcdefghi",
  "controller": "did:example:bcehfew7h32f32h7af3"
}"#;

/// DID Core §5.3, Examples 7 to 11: every relationship with one referenced and one embedded
/// method, plus the method they reference.
const EXAMPLES_7_TO_11: &str = r#"{
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

/// DID Core §5.4, Example 12 (the `id` of the prose added).
const EXAMPLE_12: &str = r#"{
  "id": "did:example:123",
  "service": [{
    "id":"did:example:123#linked-domain",
    "type": "LinkedDomains",
    "serviceEndpoint": "https://bar.example.com"
  }]
}"#;

/// DID Core §6.2.1, Example 13: `publicKeyBase58` material, which DID Core does not define.
const EXAMPLE_13: &str = r#"{
  "id": "did:example:123456789abcdefghi",
  "authentication": [{
    "id": "did:example:123456789abcdefghi#keys-1",
    "type": "Ed25519VerificationKey2018",
    "controller": "did:example:123456789abcdefghi",
    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
  }]
}"#;

/// DID Core §A.1, Example 19: one verification method type, embedded per relationship.
const EXAMPLE_19: &str = r#"{
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:example:123",
    "authentication": [
      {
        "id": "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf"
      }
    ],
    "capabilityInvocation": [
      {
        "id": "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
      }
    ],
    "capabilityDelegation": [
      {
        "id": "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL"
      }
    ],
    "assertionMethod": [
      {
        "id": "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
        "type": "Ed25519VerificationKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA"
      }
    ]
}"#;

/// DID Core §A.2, Example 20: many key types as `publicKeyJwk` (the `id` of the prose added).
const EXAMPLE_20: &str = r#"{
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
      "id": "did:example:123#key-3",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "U1V4TVZVMUpUa0ZVU1NBcU9CRm5IbmFaaEpGNkxkdWx",
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
      "id": "did:example:123#key-5",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-384",
        "x": "VUZKSlUwMGdpSXplekRwODhzX2N4U1BYdHVYWUZsaXVDR25kZ1U0UXA4bDkxeHpE",
        "y": "jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP"
      }
    },
    {
      "id": "did:example:123#key-6",
      "type": "JsonWebKey2020",
      "controller": "did:example:123",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-521",
        "x": "VTI5c1lYSmZWMmx1WkhNZ0dQTXhaYkhtSnBEU3UtSXZwdUtpZ0VOMnB6Z1d0U28tLVJ3ZC1uNzhuclduWnplRGMx",
        "y": "UW5WNVgwSnBkR052YVc0Z1VqY1B6LVpoZWNaRnliT3FMSUpqVk9sTEVUSDd1UGx5RzBnRW9NV25JWlhoUVZ5cFB5"
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

/// Compact JSON of `json`, members in the order written.
fn canonical(json: &str) -> String {
    serde_json::to_string(&serde_json::from_str::<Value>(json).unwrap()).unwrap()
}

fn parse(json: &str) -> DidDocument {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}\n{json}"))
}

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn url(s: &str) -> DidUrl {
    DidUrl::parse(s).unwrap()
}

fn multikey(id: &str, controller: &str, key: &str) -> VerificationMethod {
    VerificationMethod::new(
        url(id),
        MethodType::MULTIKEY,
        did(controller),
        VerificationMaterial::multibase(key),
    )
}

// ---------------------------------------------------------------------------------------------
// W3C examples round-trip
// ---------------------------------------------------------------------------------------------

#[test]
fn did_core_examples_round_trip_byte_identically() {
    for (name, example) in [
        ("1", EXAMPLE_1),
        ("2", EXAMPLE_2),
        ("3", EXAMPLE_3),
        ("4", EXAMPLE_4),
        ("7-11", EXAMPLES_7_TO_11),
        ("12", EXAMPLE_12),
    ] {
        let document = parse(example);
        let serialized = serde_json::to_string(&document).unwrap();
        assert_eq!(serialized, canonical(example), "example {name}");
        let again: DidDocument = serde_json::from_str(&serialized).unwrap();
        assert_eq!(again, document, "example {name}");
        assert_eq!(
            serde_json::to_string_pretty(&document).unwrap(),
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(example).unwrap()).unwrap(),
            "example {name}"
        );
    }
}

/// Example 19 lists its relationships as authentication, capabilityInvocation,
/// capabilityDelegation, assertionMethod, and the RSA key of Example 20 writes `e` before `n`.
/// The crate always writes core members in the order the specifications define them, so these
/// two round-trip member for member but not byte for byte: the members and values are the same,
/// the order is the canonical one.
#[test]
fn examples_19_and_20_round_trip_in_canonical_order() {
    let document = parse(EXAMPLE_19);
    let serialized = serde_json::to_string(&document).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&serialized).unwrap(),
        serde_json::from_str::<Value>(EXAMPLE_19).unwrap()
    );
    let members: IndexMap<String, Value> = serde_json::from_str(&serialized).unwrap();
    assert_eq!(
        members.keys().collect::<Vec<_>>(),
        [
            "@context",
            "id",
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation"
        ]
    );
    assert_eq!(
        serde_json::from_str::<DidDocument>(&serialized).unwrap(),
        document
    );

    let document = parse(EXAMPLE_20);
    let serialized = serde_json::to_string(&document).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&serialized).unwrap(),
        serde_json::from_str::<Value>(EXAMPLE_20).unwrap()
    );
    assert!(serialized.contains(r#""kty":"RSA","n":"#));
    assert_eq!(
        serde_json::from_str::<DidDocument>(&serialized).unwrap(),
        document
    );
}

#[test]
fn example_1_embeds_an_authentication_method() {
    let document = parse(EXAMPLE_1);
    assert_eq!(document.id, did("did:example:123456789abcdefghi"));
    let context = document.context.as_ref().unwrap();
    assert!(context.contains(Context::DID_V1));
    assert!(context.contains("https://w3id.org/security/suites/ed25519-2020/v1"));
    assert!(document.verification_method.is_empty());
    assert_eq!(document.authentication.len(), 1);

    let key = url("did:example:123456789abcdefghi#keys-1");
    let method = document.authentication[0].as_embedded().unwrap();
    assert_eq!(method.id, key);
    assert_eq!(
        method.method_type,
        MethodType::ED25519_VERIFICATION_KEY_2020
    );
    assert_eq!(method.controller, document.id);
    assert_eq!(
        method.public_key_multibase(),
        Some("zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV")
    );
    assert_eq!(method.public_key_jwk(), None);

    assert_eq!(document.verification_method(&key), Some(method));
    assert_eq!(
        document.resolve_verification_method(&key, None).unwrap(),
        method
    );
    assert_eq!(
        document
            .resolve_verification_method(&key, Some(VerificationRelationship::Authentication))
            .unwrap(),
        method
    );
    for other in VerificationRelationship::ALL
        .iter()
        .filter(|r| **r != VerificationRelationship::Authentication)
    {
        assert_eq!(
            document.resolve_verification_method(&key, Some(*other)),
            Err(DocumentError::NotInRelationship {
                id: key.clone(),
                relationship: *other
            })
        );
    }
    assert_eq!(document.methods(None).count(), 1);
    assert_eq!(
        document
            .methods(Some(VerificationRelationship::AssertionMethod))
            .count(),
        0
    );
}

#[test]
fn example_2_resolves_a_relative_reference() {
    let document = parse(EXAMPLE_2);
    let reference = document.authentication[0].as_reference().unwrap();
    assert_eq!(reference, &DidUrlReference::Relative("#key-1".to_owned()));
    assert!(reference.is_relative());
    let key = url("did:example:123456789abcdefghi#key-1");
    assert_eq!(reference.resolve(&document.id).unwrap(), key);
    assert!(reference.refers_to(&key, &document.id));

    let method = document
        .resolve_verification_method(&key, Some(VerificationRelationship::Authentication))
        .unwrap();
    assert_eq!(method.id, key);
    assert_eq!(
        document
            .resolve_method_reference(reference, Some(VerificationRelationship::Authentication))
            .unwrap(),
        method
    );
    assert_eq!(
        document
            .methods(Some(VerificationRelationship::Authentication))
            .collect::<Vec<_>>(),
        [method]
    );
    assert_eq!(
        document.resolve_verification_method(&key, Some(VerificationRelationship::KeyAgreement)),
        Err(DocumentError::NotInRelationship {
            id: key,
            relationship: VerificationRelationship::KeyAgreement
        })
    );
}

#[test]
fn example_4_has_a_single_controller() {
    let document = parse(EXAMPLE_4);
    assert_eq!(
        document.context,
        Some(Context::uri("https://www.w3.org/ns/did/v1"))
    );
    assert_eq!(
        document.controller,
        Some(OneOrMany::One(did("did:example:bcehfew7h32f32h7af3")))
    );
}

#[test]
fn examples_7_to_11_mix_references_and_embedded_methods() {
    let document = parse(EXAMPLES_7_TO_11);
    let keys_1 = url("did:example:123456789abcdefghi#keys-1");
    let keys_2 = url("did:example:123456789abcdefghi#keys-2");
    for relationship in VerificationRelationship::ALL {
        let entries = document.relationship(*relationship);
        assert_eq!(entries.len(), 2, "{relationship}");
        assert_eq!(
            entries[0],
            MethodRef::reference(keys_1.clone()),
            "{relationship}"
        );
        assert!(entries[1].as_embedded().is_some(), "{relationship}");
        assert_eq!(
            document
                .resolve_verification_method(&keys_1, Some(*relationship))
                .unwrap()
                .id,
            keys_1,
            "{relationship}"
        );
        let embedded = document.methods(Some(*relationship)).nth(1).unwrap();
        assert_eq!(embedded, entries[1].as_embedded().unwrap());
    }
    // keys-2 is embedded under four relationships; the same id in each, as the spec writes it.
    assert_eq!(
        document
            .resolve_verification_method(&keys_2, Some(VerificationRelationship::Authentication))
            .unwrap()
            .controller,
        document.id
    );
    // The key agreement method of another DID cannot be resolved from this document.
    let foreign = url("did:example:123#zC9ByQ8aJs8vrNXyDhPHHNNMSHPcaSgNpjjsBYpMMjsTdS");
    assert_eq!(
        document
            .resolve_verification_method(&foreign, Some(VerificationRelationship::KeyAgreement)),
        Err(DocumentError::ForeignDid {
            url: foreign.clone(),
            document: document.id.clone()
        })
    );
    assert!(document.verification_method(&foreign).is_some());
    // All methods: one listed, five embedded.
    assert_eq!(document.methods(None).count(), 6);
}

#[test]
fn example_12_has_a_uri_service_endpoint() {
    let document = parse(EXAMPLE_12);
    let id = url("did:example:123#linked-domain");
    let service = document.service(&id).unwrap();
    assert_eq!(
        service.service_type,
        OneOrMany::One("LinkedDomains".to_owned())
    );
    assert!(service.has_type("LinkedDomains"));
    assert!(!service.has_type("DIDCommMessaging"));
    assert_eq!(
        service.service_endpoint,
        ServiceEndpoint::Uri(Uri::parse("https://bar.example.com").unwrap())
    );
    assert_eq!(
        service
            .service_endpoint
            .uris()
            .map(Uri::as_str)
            .collect::<Vec<_>>(),
        ["https://bar.example.com"]
    );
}

#[test]
fn example_19_embeds_one_method_per_relationship() {
    let document = parse(EXAMPLE_19);
    for relationship in [
        VerificationRelationship::Authentication,
        VerificationRelationship::CapabilityInvocation,
        VerificationRelationship::CapabilityDelegation,
        VerificationRelationship::AssertionMethod,
    ] {
        assert_eq!(document.relationship(relationship).len(), 1);
        assert_eq!(document.methods(Some(relationship)).count(), 1);
    }
    assert!(document.key_agreement.is_empty());
    assert_eq!(document.methods(None).count(), 4);
}

#[test]
fn example_20_carries_every_jwk_as_is() {
    let document = parse(EXAMPLE_20);
    assert_eq!(document.verification_method.len(), 8);
    let curves: Vec<_> = document
        .verification_method
        .iter()
        .map(|m| {
            let jwk = m.public_key_jwk().unwrap();
            (jwk.kty().to_owned(), jwk.crv().map(str::to_owned))
        })
        .collect();
    assert_eq!(
        curves,
        [
            ("OKP", Some("Ed25519")),
            ("OKP", Some("X25519")),
            ("EC", Some("secp256k1")),
            ("EC", Some("secp256k1")),
            ("EC", Some("P-256")),
            ("EC", Some("P-384")),
            ("EC", Some("P-521")),
            ("RSA", None),
        ]
        .map(|(k, c)| (k.to_owned(), c.map(str::to_owned)))
    );
    for method in &document.verification_method {
        assert_eq!(method.method_type, MethodType::JSON_WEB_KEY_2020);
        assert!(!method.public_key_jwk().unwrap().is_private());
    }
    let ed25519 = document.verification_method[0].public_key_jwk().unwrap();
    assert_eq!(ed25519.ed25519_public_bytes().unwrap().len(), 32);
}

#[test]
fn examples_with_public_key_base58_are_rejected() {
    // DID Core 1.0 only defines `publicKeyJwk` and `publicKeyMultibase`; Example 13 (and A.3,
    // Example 21) use the `publicKeyBase58` of the 2018 suites, which this crate does not model.
    let err = serde_json::from_str::<DidDocument>(EXAMPLE_13).unwrap_err();
    assert!(
        err.to_string()
            .contains("neither `publicKeyJwk` nor `publicKeyMultibase`"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------------------------
// Serialization rules
// ---------------------------------------------------------------------------------------------

#[test]
fn context_is_first_and_empties_are_omitted() {
    let json = r#"{"service":[],"id":"did:example:1","controller":[],"foo":1,"verificationMethod":[],"@context":"https://www.w3.org/ns/did/v1","authentication":[]}"#;
    let document = parse(json);
    assert_eq!(document.controller, None);
    assert_eq!(
        serde_json::to_string(&document).unwrap(),
        r#"{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:1","foo":1}"#
    );
    assert_eq!(
        serde_json::to_string(&DidDocument::new(did("did:example:1"))).unwrap(),
        r#"{"id":"did:example:1"}"#
    );
}

/// Extension properties come back as written, numbers of every precision included: a document
/// is byte-identical after a round trip, not merely close.
#[test]
fn extension_numbers_round_trip_exactly() {
    let json = r#"{"id":"did:example:1","weight":2.2222222222222227e107,"count":9007199254740993}"#;
    let document = parse(json);
    let again = parse(&serde_json::to_string(&document).unwrap());
    assert_eq!(again, document);
    assert_eq!(
        serde_json::to_string(&again).unwrap(),
        serde_json::to_string(&document).unwrap()
    );
}

#[test]
fn core_properties_serialize_in_spec_order_and_extensions_in_input_order() {
    let json = r##"{
      "zzz": "last extension",
      "service": [{"id": "did:example:1#s", "type": ["A", "B"], "serviceEndpoint": {"uri": "https://x.example", "n": 1}}],
      "capabilityDelegation": ["did:example:1#k"],
      "capabilityInvocation": ["#k"],
      "keyAgreement": ["#k"],
      "assertionMethod": ["#k"],
      "authentication": ["#k"],
      "verificationMethod": [{"id": "did:example:1#k", "type": "Multikey", "controller": "did:example:1", "publicKeyMultibase": "z6Mk", "revoked": "2024-01-01T00:00:00Z"}],
      "controller": ["did:example:2", "did:example:3"],
      "alsoKnownAs": ["https://alias.example/me", "did:web:alias.example"],
      "id": "did:example:1",
      "@context": ["https://www.w3.org/ns/did/v1", {"@vocab": "https://example.com/#"}],
      "aaa": "first extension"
    }"##;
    let document = parse(json);
    assert_eq!(
        serde_json::to_string(&document).unwrap(),
        concat!(
            r#"{"@context":["https://www.w3.org/ns/did/v1",{"@vocab":"https://example.com/#"}],"#,
            r#""id":"did:example:1","#,
            r#""alsoKnownAs":["https://alias.example/me","did:web:alias.example"],"#,
            r#""controller":["did:example:2","did:example:3"],"#,
            r#""verificationMethod":[{"id":"did:example:1#k","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z6Mk","revoked":"2024-01-01T00:00:00Z"}],"#,
            r##""authentication":["#k"],"assertionMethod":["#k"],"keyAgreement":["#k"],"capabilityInvocation":["#k"],"capabilityDelegation":["did:example:1#k"],"##,
            r#""service":[{"id":"did:example:1#s","type":["A","B"],"serviceEndpoint":{"uri":"https://x.example","n":1}}],"#,
            r#""zzz":"last extension","aaa":"first extension"}"#
        )
    );
    assert_eq!(
        document.properties.keys().collect::<Vec<_>>(),
        ["zzz", "aaa"]
    );
    assert_eq!(
        document.verification_method[0].properties["revoked"],
        json!("2024-01-01T00:00:00Z")
    );
    assert_eq!(
        document.controller,
        Some(OneOrMany::Many(vec![
            did("did:example:2"),
            did("did:example:3")
        ]))
    );
    assert_eq!(document.also_known_as.len(), 2);
    assert!(document.also_known_as[1].is_did_url());
    let ServiceEndpoint::Map(map) = &document.service[0].service_endpoint else {
        panic!("map endpoint");
    };
    assert_eq!(map.keys().collect::<Vec<_>>(), ["uri", "n"]);
    assert_eq!(document.service[0].service_endpoint.uris().count(), 0);
}

#[test]
fn service_endpoint_forms() {
    let set: Service = serde_json::from_str(
        r#"{"id":"did:example:1#s","type":"T","serviceEndpoint":["https://a.example","https://b.example","https://a.example"]}"#,
    )
    .unwrap();
    let ServiceEndpoint::Set(uris) = &set.service_endpoint else {
        panic!("set endpoint");
    };
    assert_eq!(
        uris.iter().map(Uri::as_str).collect::<Vec<_>>(),
        ["https://a.example", "https://b.example"]
    );
    assert_eq!(
        serde_json::to_string(&set).unwrap(),
        r#"{"id":"did:example:1#s","type":"T","serviceEndpoint":["https://a.example","https://b.example"]}"#
    );

    let err = serde_json::from_str::<Service>(
        r#"{"id":"did:example:1#s","type":"T","serviceEndpoint":[]}"#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("at least one URI"), "{err}");
    for bad in [
        r#"42"#,
        r#"true"#,
        r#"null"#,
        r#""not a uri""#,
        r#"["https://a.example", 1]"#,
    ] {
        let json = format!(r#"{{"id":"did:example:1#s","type":"T","serviceEndpoint":{bad}}}"#);
        assert!(serde_json::from_str::<Service>(&json).is_err(), "{bad}");
    }
    let service = Service::new(
        url("did:example:1#s"),
        "T",
        Uri::parse("https://a.example").unwrap(),
    );
    assert_eq!(
        serde_json::to_string(&service).unwrap(),
        r#"{"id":"did:example:1#s","type":"T","serviceEndpoint":"https://a.example"}"#
    );
}

#[test]
fn verification_material_is_exactly_one_member() {
    let base = r#""id":"did:example:1#k","type":"JsonWebKey2020","controller":"did:example:1""#;
    let jwk = r#""publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let multibase = r#""publicKeyMultibase":"z6Mk""#;

    let err = serde_json::from_str::<VerificationMethod>(&format!("{{{base}}}")).unwrap_err();
    assert!(err.to_string().contains("neither"), "{err}");
    let err = serde_json::from_str::<VerificationMethod>(&format!("{{{base},{jwk},{multibase}}}"))
        .unwrap_err();
    assert!(err.to_string().contains("both"), "{err}");

    let with_jwk: VerificationMethod = serde_json::from_str(&format!("{{{base},{jwk}}}")).unwrap();
    assert_eq!(with_jwk.public_key_jwk().unwrap().crv(), Some("Ed25519"));
    assert!(with_jwk.properties.is_empty());
    assert_eq!(
        serde_json::to_string(&with_jwk).unwrap(),
        format!("{{{base},{jwk}}}")
    );

    let with_multibase: VerificationMethod =
        serde_json::from_str(&format!("{{{base},{multibase}}}")).unwrap();
    assert_eq!(with_multibase.public_key_multibase(), Some("z6Mk"));
    assert_eq!(with_multibase.material.as_jwk(), None);

    // A private JWK is refused both ways.
    let private = r#""publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#;
    let err =
        serde_json::from_str::<VerificationMethod>(&format!("{{{base},{private}}}")).unwrap_err();
    assert!(err.to_string().contains("private"), "{err}");
    let private_jwk: Jwk = serde_json::from_str(
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
    )
    .unwrap();
    let mut method = with_jwk.clone();
    method.material = VerificationMaterial::PublicKeyJwk(Box::new(private_jwk.clone()));
    let err = serde_json::to_string(&method).unwrap_err();
    assert!(err.to_string().contains("private"), "{err}");
    // The constructor strips the private part.
    assert_eq!(
        VerificationMaterial::jwk(&private_jwk),
        VerificationMaterial::PublicKeyJwk(Box::new(private_jwk.public()))
    );
}

#[test]
fn method_refs_are_strings_or_objects() {
    let refs: Vec<MethodRef> = serde_json::from_str(
        r##"["did:example:1#a", "#b", "?versionId=2#c", {"id":"did:example:1#d","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z6Mk"}]"##,
    )
    .unwrap();
    assert_eq!(refs[0], MethodRef::reference(url("did:example:1#a")));
    assert_eq!(
        refs[1],
        MethodRef::Reference(DidUrlReference::parse("#b").unwrap())
    );
    assert_eq!(
        refs[2]
            .as_reference()
            .unwrap()
            .resolve(&did("did:example:1"))
            .unwrap()
            .as_str(),
        "did:example:1?versionId=2#c"
    );
    assert_eq!(refs[3].as_embedded().unwrap().id, url("did:example:1#d"));
    assert_eq!(
        serde_json::to_string(&refs).unwrap(),
        r##"["did:example:1#a","#b","?versionId=2#c",{"id":"did:example:1#d","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z6Mk"}]"##
    );
    for bad in [
        r#"42"#,
        r#""not a did url""#,
        r#""key-1""#,
        r#"{"id":"did:example:1#d"}"#,
        r#"["did:example:1#a"]"#,
    ] {
        let err = serde_json::from_str::<MethodRef>(bad).unwrap_err();
        assert!(!err.to_string().is_empty(), "{bad}");
    }
}

#[test]
fn invalid_identifiers_are_rejected_on_read() {
    for (json, what) in [
        (r##"{"id":"example:1"}"##, "id"),
        (
            r##"{"id":"did:example:1","controller":"DID:example:2"}"##,
            "controller",
        ),
        (
            r##"{"id":"did:example:1","alsoKnownAs":["no scheme"]}"##,
            "alsoKnownAs",
        ),
        (r##"{"id":"did:example:1","@context":[]}"##, "@context"),
        (r##"{"id":"did:example:1","@context":5}"##, "@context"),
        (
            r##"{"id":"did:example:1","authentication":"did:example:1#k"}"##,
            "authentication",
        ),
        (
            r##"{"id":"did:example:1","service":[{"id":"#s","type":"T","serviceEndpoint":"https://a.example"}]}"##,
            "service id",
        ),
        (
            r##"{"id":"did:example:1","verificationMethod":[{"id":"#k","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z"}]}"##,
            "method id",
        ),
        (
            r##"{"@context":"https://www.w3.org/ns/did/v1"}"##,
            "missing id",
        ),
    ] {
        assert!(serde_json::from_str::<DidDocument>(json).is_err(), "{what}");
    }
}

#[test]
fn context_forms() {
    assert_eq!(
        serde_json::to_string(&Context::did_v1()).unwrap(),
        r#""https://www.w3.org/ns/did/v1""#
    );
    let object = Context::new(json!({"@vocab": "https://example.com/#"})).unwrap();
    assert!(!object.contains("https://example.com/#"));
    assert_eq!(object.as_value()["@vocab"], "https://example.com/#");
    assert_eq!(Context::new(json!([])), Err(DocumentError::InvalidContext));
    assert_eq!(
        Context::new(json!(null)),
        Err(DocumentError::InvalidContext)
    );
    assert_eq!(Context::new(json!(1)), Err(DocumentError::InvalidContext));
    let mixed: Context =
        serde_json::from_str(r#"["https://www.w3.org/ns/did/v1",{"a":"b"}]"#).unwrap();
    assert!(mixed.contains(Context::DID_V1));
    assert_eq!(mixed.into_value().as_array().unwrap().len(), 2);
}

#[test]
fn relationship_and_method_type_names() {
    for relationship in VerificationRelationship::ALL {
        assert_eq!(
            relationship
                .to_string()
                .parse::<VerificationRelationship>()
                .unwrap(),
            *relationship
        );
        assert_eq!(
            serde_json::to_string(relationship).unwrap(),
            format!("\"{relationship}\"")
        );
    }
    assert_eq!(
        VerificationRelationship::ALL
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>(),
        [
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation"
        ]
    );
    assert_eq!(
        "Authentication".parse::<VerificationRelationship>(),
        Err(DocumentError::UnknownRelationship(
            "Authentication".to_owned()
        ))
    );

    assert_eq!(MethodType::JSON_WEB_KEY_2020, "JsonWebKey2020");
    assert_eq!(MethodType::JSON_WEB_KEY, "JsonWebKey");
    assert_eq!(MethodType::MULTIKEY, "Multikey");
    assert_eq!(
        MethodType::ED25519_VERIFICATION_KEY_2020,
        "Ed25519VerificationKey2020"
    );
    let custom = MethodType::new("EcdsaSecp256k1VerificationKey2019");
    assert_eq!(
        format!("{custom:?}"),
        "\"EcdsaSecp256k1VerificationKey2019\""
    );
    assert_eq!(custom.to_string(), "EcdsaSecp256k1VerificationKey2019");
    assert_eq!(
        serde_json::from_str::<MethodType>("\"Multikey\"").unwrap(),
        MethodType::MULTIKEY
    );
}

// ---------------------------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------------------------

fn sample() -> DidDocument {
    parse(EXAMPLES_7_TO_11)
}

#[test]
fn insert_attach_detach_and_remove_methods() {
    let mut document = DidDocument::new(did("did:example:1"));
    let k1 = url("did:example:1#k1");
    let k2 = url("did:example:1#k2");

    document
        .insert_verification_method(
            multikey("did:example:1#k1", "did:example:1", "z1"),
            [
                VerificationRelationship::Authentication,
                VerificationRelationship::AssertionMethod,
            ],
        )
        .unwrap();
    assert_eq!(document.verification_method.len(), 1);
    assert_eq!(document.authentication, [MethodRef::reference(k1.clone())]);
    assert_eq!(
        document.assertion_method,
        [MethodRef::reference(k1.clone())]
    );
    assert!(document.key_agreement.is_empty());

    assert_eq!(
        document
            .insert_verification_method(multikey("did:example:1#k1", "did:example:1", "z9"), []),
        Err(DocumentError::DuplicateVerificationMethod(k1.clone()))
    );
    assert_eq!(
        document.verification_method[0].public_key_multibase(),
        Some("z1")
    );

    // Attaching is idempotent and needs a listed method.
    assert_eq!(
        document.attach_relationship(&k1, VerificationRelationship::Authentication),
        Ok(false)
    );
    assert_eq!(
        document.attach_relationship(&k1, VerificationRelationship::KeyAgreement),
        Ok(true)
    );
    assert_eq!(
        document.attach_relationship(&k2, VerificationRelationship::KeyAgreement),
        Err(DocumentError::VerificationMethodNotFound(k2.clone()))
    );
    assert!(document.detach_relationship(&k1, VerificationRelationship::KeyAgreement));
    assert!(!document.detach_relationship(&k1, VerificationRelationship::KeyAgreement));
    assert!(document.key_agreement.is_empty());

    // An embedded method counts as existing but cannot be referenced.
    document
        .capability_invocation
        .push(MethodRef::embedded(multikey(
            "did:example:1#k2",
            "did:example:1",
            "z2",
        )));
    assert_eq!(
        document
            .insert_verification_method(multikey("did:example:1#k2", "did:example:1", "z2"), []),
        Err(DocumentError::DuplicateVerificationMethod(k2.clone()))
    );
    assert_eq!(
        document.attach_relationship(&k2, VerificationRelationship::Authentication),
        Err(DocumentError::VerificationMethodNotFound(k2.clone()))
    );
    assert_eq!(
        document
            .resolve_verification_method(&k2, Some(VerificationRelationship::CapabilityInvocation))
            .unwrap()
            .id,
        k2
    );

    // Removing takes the method and every entry for it.
    let removed = document.remove_verification_method(&k1).unwrap();
    assert_eq!(removed.public_key_multibase(), Some("z1"));
    assert!(document.verification_method.is_empty());
    assert!(document.authentication.is_empty());
    assert!(document.assertion_method.is_empty());
    assert_eq!(document.remove_verification_method(&k1), None);
    let removed = document.remove_verification_method(&k2).unwrap();
    assert_eq!(removed.public_key_multibase(), Some("z2"));
    assert!(document.capability_invocation.is_empty());
    assert_eq!(
        serde_json::to_string(&document).unwrap(),
        r#"{"id":"did:example:1"}"#
    );
}

#[test]
fn removing_a_method_drops_relative_references_too() {
    let mut document = parse(EXAMPLE_2);
    let key = url("did:example:123456789abcdefghi#key-1");
    assert!(document.remove_verification_method(&key).is_some());
    assert!(document.authentication.is_empty());
    assert!(document.verification_method.is_empty());
}

#[test]
fn resolve_reports_the_most_specific_error() {
    let document = sample();
    let missing = url("did:example:123456789abcdefghi#nope");
    assert_eq!(
        document.resolve_verification_method(&missing, None),
        Err(DocumentError::VerificationMethodNotFound(missing.clone()))
    );
    assert_eq!(
        document
            .resolve_verification_method(&missing, Some(VerificationRelationship::Authentication)),
        Err(DocumentError::VerificationMethodNotFound(missing))
    );
    let foreign = url("did:example:other#keys-1");
    assert_eq!(
        document.resolve_verification_method(&foreign, None),
        Err(DocumentError::ForeignDid {
            url: foreign.clone(),
            document: document.id.clone()
        })
    );
    assert_eq!(
        document
            .resolve_method_reference(&foreign.into(), None)
            .unwrap_err()
            .to_string(),
        "`did:example:other#keys-1` does not belong to document `did:example:123456789abcdefghi`"
    );

    // A reference to a method that is not listed resolves to nothing.
    let mut dangling = DidDocument::new(did("did:example:1"));
    dangling
        .authentication
        .push(MethodRef::reference(url("did:example:1#gone")));
    let gone = url("did:example:1#gone");
    assert_eq!(
        dangling.resolve_verification_method(&gone, Some(VerificationRelationship::Authentication)),
        Err(DocumentError::VerificationMethodNotFound(gone))
    );
    assert_eq!(
        dangling
            .methods(Some(VerificationRelationship::Authentication))
            .count(),
        0
    );
}

#[test]
fn services_are_unique_by_id() {
    let mut document = DidDocument::new(did("did:example:1"));
    let id = url("did:example:1#s");
    let service = Service::new(id.clone(), "T", Uri::parse("https://a.example").unwrap());
    document.insert_service(service.clone()).unwrap();
    assert_eq!(
        document.insert_service(service),
        Err(DocumentError::DuplicateService(id.clone()))
    );
    assert_eq!(document.service(&id).unwrap().id, id);
    assert!(document.remove_service(&id).is_some());
    assert!(document.remove_service(&id).is_none());
    assert!(document.service(&id).is_none());
    // DID Core §5.4: a consumer MUST produce an error on multiple service entries with one id.
    let err = serde_json::from_str::<DidDocument>(
        r#"{"id":"did:example:1","service":[{"id":"did:example:1#s","type":"T","serviceEndpoint":"https://a.example"},{"id":"did:example:1#s","type":"T","serviceEndpoint":"https://b.example"}]}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        DocumentError::DuplicateService(id.clone()).to_string()
    );
}

#[test]
fn duplicate_method_ids_are_rejected_on_read_and_cleared_on_removal() {
    let listed = |key: &str| {
        format!(
            r##"{{"id":"did:example:1#k","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"{key}"}}"##
        )
    };
    let (a, b) = (listed("z6MkA"), listed("z6MkB"));
    // Two listed methods, a listed and an embedded one, and two embedded ones: every pair of
    // differing definitions for one id is rejected, so no lookup path can pick different material.
    for (json, what) in [
        (
            format!(r#"{{"id":"did:example:1","verificationMethod":[{a},{b}]}}"#),
            "listed twice",
        ),
        (
            format!(
                r#"{{"id":"did:example:1","verificationMethod":[{a}],"authentication":[{b}]}}"#
            ),
            "listed and embedded",
        ),
        (
            format!(r#"{{"id":"did:example:1","authentication":[{a}],"assertionMethod":[{b}]}}"#),
            "embedded twice",
        ),
    ] {
        let err = serde_json::from_str::<DidDocument>(&json).unwrap_err();
        assert_eq!(
            err.to_string(),
            DocumentError::DuplicateVerificationMethod(url("did:example:1#k")).to_string(),
            "{what}"
        );
    }
    // A reference to a listed method is not a second definition, and neither is the same method
    // embedded under several relationships (DID Core Examples 7 to 11 do that).
    let document = parse(&format!(
        r##"{{"id":"did:example:1","verificationMethod":[{a}],"authentication":["#k"],"assertionMethod":["did:example:1#k"]}}"##
    ));
    assert_eq!(document.check_unique_ids(), Ok(()));
    let twice = parse(&format!(
        r#"{{"id":"did:example:1","authentication":[{a}],"assertionMethod":[{a}]}}"#
    ));
    assert_eq!(twice.check_unique_ids(), Ok(()));

    // Plain field mutation can still define an id twice; removal then clears every definition.
    let mut document = document;
    let mut other = document.verification_method[0].clone();
    other.material = VerificationMaterial::multibase("z6MkB");
    document.verification_method.push(other.clone());
    document.authentication.push(MethodRef::embedded(other));
    assert_eq!(
        document.check_unique_ids(),
        Err(DocumentError::DuplicateVerificationMethod(url(
            "did:example:1#k"
        )))
    );
    let removed = document.remove_verification_method(&url("did:example:1#k"));
    assert_eq!(
        removed.map(|m| m.public_key_multibase().map(str::to_owned)),
        Some(Some("z6MkA".to_owned()))
    );
    assert!(document.verification_method.is_empty());
    assert!(document.authentication.is_empty());
    assert!(document.assertion_method.is_empty());
    assert_eq!(document.check_unique_ids(), Ok(()));
}

#[test]
fn builder_builds_or_reports_the_first_error() {
    let id = did("did:example:1");
    let document = DidDocument::builder(id.clone())
        .context(Context::did_v1())
        .also_known_as(Uri::parse("https://alias.example/me").unwrap())
        .controller(did("did:example:c1"))
        .controller(did("did:example:c2"))
        .verification_method(
            multikey("did:example:1#k1", "did:example:1", "z1"),
            [VerificationRelationship::Authentication],
        )
        .embedded_method(
            VerificationRelationship::KeyAgreement,
            multikey("did:example:1#k2", "did:example:1", "z2"),
        )
        .service(Service::new(
            url("did:example:1#s"),
            vec!["A".to_owned(), "B".to_owned()],
            Uri::parse("https://a.example").unwrap(),
        ))
        .property("deactivated", false)
        .build()
        .unwrap();
    assert_eq!(
        serde_json::to_string(&document).unwrap(),
        concat!(
            r#"{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:1","#,
            r#""alsoKnownAs":["https://alias.example/me"],"controller":["did:example:c1","did:example:c2"],"#,
            r#""verificationMethod":[{"id":"did:example:1#k1","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z1"}],"#,
            r#""authentication":["did:example:1#k1"],"#,
            r#""keyAgreement":[{"id":"did:example:1#k2","type":"Multikey","controller":"did:example:1","publicKeyMultibase":"z2"}],"#,
            r#""service":[{"id":"did:example:1#s","type":["A","B"],"serviceEndpoint":"https://a.example"}],"#,
            r#""deactivated":false}"#
        )
    );
    assert_eq!(
        serde_json::to_string(
            &DidDocument::builder(id.clone())
                .controller(did("did:example:c1"))
                .build()
                .unwrap()
        )
        .unwrap(),
        r#"{"id":"did:example:1","controller":"did:example:c1"}"#
    );

    assert_eq!(
        DidDocument::builder(id.clone())
            .property("service", json!([]))
            .build(),
        Err(DocumentError::ReservedProperty("service".to_owned()))
    );
    assert!(DidDocument::CORE_PROPERTIES.contains(&"@context"));

    let err = DidDocument::builder(id.clone())
        .verification_method(multikey("did:example:1#k", "did:example:1", "z"), [])
        .embedded_method(
            VerificationRelationship::Authentication,
            multikey("did:example:1#k", "did:example:1", "z"),
        )
        .service(Service::new(
            url("did:example:1#s"),
            "T",
            Uri::parse("https://a.example").unwrap(),
        ))
        .service(Service::new(
            url("did:example:1#s"),
            "T",
            Uri::parse("https://a.example").unwrap(),
        ))
        .build()
        .unwrap_err();
    assert_eq!(
        err,
        DocumentError::DuplicateVerificationMethod(url("did:example:1#k"))
    );
}

// ---------------------------------------------------------------------------------------------
// map_dids
// ---------------------------------------------------------------------------------------------

#[test]
fn map_dids_rewrites_every_did_but_relative_references() {
    let mut document = sample();
    document.controller = Some(OneOrMany::Many(vec![
        did("did:example:123456789abcdefghi"),
        did("did:example:controller"),
    ]));
    document
        .insert_service(Service::new(
            url("did:example:123456789abcdefghi#svc"),
            "T",
            Uri::parse("https://a.example").unwrap(),
        ))
        .unwrap();
    document
        .also_known_as
        .push(Uri::from(did("did:example:123456789abcdefghi")));
    document.authentication.push(MethodRef::Reference(
        DidUrlReference::parse("#keys-1").unwrap(),
    ));
    document.properties.insert(
        "note".to_owned(),
        json!("did:example:123456789abcdefghi stays in extension properties"),
    );

    let old = did("did:example:123456789abcdefghi");
    let new = did("did:web:example.com:user");
    let mut calls = 0;
    document.map_dids(|d| {
        calls += 1;
        if d == old { new.clone() } else { d }
    });
    // id, 2 controllers, 1 listed method (id + controller), 5 references, 5 embedded
    // (id + controller each), 1 service.
    assert_eq!(calls, 1 + 2 + 2 + 5 + 10 + 1);

    assert_eq!(document.id, new);
    assert_eq!(
        document.controller,
        Some(OneOrMany::Many(vec![
            new.clone(),
            did("did:example:controller")
        ]))
    );
    assert_eq!(
        document.verification_method[0].id.as_str(),
        "did:web:example.com:user#keys-1"
    );
    assert_eq!(document.verification_method[0].controller, new);
    for relationship in VerificationRelationship::ALL {
        let entries = document.relationship(*relationship);
        assert_eq!(
            entries[0],
            MethodRef::reference(url("did:web:example.com:user#keys-1")),
            "{relationship}"
        );
        let embedded = entries[1].as_embedded().unwrap();
        if *relationship == VerificationRelationship::KeyAgreement {
            // The foreign DID of the X25519 example is not `old`, so it is left alone.
            assert_eq!(embedded.controller.as_str(), "did:example:123");
        } else {
            assert_eq!(embedded.id.as_str(), "did:web:example.com:user#keys-2");
            assert_eq!(embedded.controller, new);
        }
    }
    assert_eq!(
        document.authentication[2],
        MethodRef::Reference(DidUrlReference::Relative("#keys-1".to_owned()))
    );
    assert_eq!(
        document.service[0].id.as_str(),
        "did:web:example.com:user#svc"
    );
    assert_eq!(
        document.also_known_as[0].as_str(),
        "did:example:123456789abcdefghi"
    );
    assert!(
        document.properties["note"]
            .as_str()
            .unwrap()
            .contains("did:example:123456789abcdefghi")
    );

    // Everything still resolves under the new DID, relative reference included.
    let key = new.join("#keys-1").unwrap();
    assert!(
        document
            .resolve_verification_method(&key, Some(VerificationRelationship::Authentication))
            .is_ok()
    );
    assert_eq!(
        document
            .methods(Some(VerificationRelationship::Authentication))
            .count(),
        3
    );
}

#[test]
fn map_dids_with_identity_changes_nothing() {
    let before = sample();
    let mut after = before.clone();
    after.map_dids(|d| d);
    assert_eq!(after, before);
    assert_eq!(
        serde_json::to_string(&after).unwrap(),
        serde_json::to_string(&before).unwrap()
    );
}

// ---------------------------------------------------------------------------------------------
// Uri and DidUrlReference
// ---------------------------------------------------------------------------------------------

#[test]
fn uris_are_checked_and_kept_verbatim() {
    for valid in [
        "https://bar.example.com",
        "https://example.com/path/to?x=1&y=%20#frag",
        "did:example:123",
        "did:web:example.com%3A8443#key-1",
        "urn:uuid:c499e122-3ba9-4e95-8d4d-c0ebfcf8c51a",
        "mailto:alice@example.com",
        "a+b-c.d:anything/at/all",
        "x:",
    ] {
        let uri = Uri::parse(valid).unwrap_or_else(|e| panic!("{valid}: {e}"));
        assert_eq!(uri.as_str(), valid);
        assert_eq!(uri.to_string(), valid);
        assert_eq!(uri, valid);
        assert_eq!(serde_json::to_string(&uri).unwrap(), format!("\"{valid}\""));
        assert_eq!(
            serde_json::from_str::<Uri>(&format!("\"{valid}\"")).unwrap(),
            uri
        );
        assert_eq!(valid.parse::<Uri>().unwrap(), uri);
        assert_eq!(Uri::try_from(valid.to_owned()).unwrap(), uri);
    }
    assert_eq!(
        Uri::parse("https://example.com/").unwrap().scheme(),
        "https"
    );
    assert!(Uri::parse("did:example:123").unwrap().is_did_url());
    assert!(!Uri::parse("https://example.com").unwrap().is_did_url());
    for (invalid, expected) in [
        (
            "",
            DidError::InvalidChar {
                position: 0,
                ch: ':',
            },
        ),
        (
            "no-scheme",
            DidError::InvalidChar {
                position: 9,
                ch: ':',
            },
        ),
        (
            ":missing",
            DidError::InvalidChar {
                position: 0,
                ch: ':',
            },
        ),
        (
            "1abc:x",
            DidError::InvalidChar {
                position: 0,
                ch: '1',
            },
        ),
        (
            "ab_c:x",
            DidError::InvalidChar {
                position: 2,
                ch: '_',
            },
        ),
        (
            "http://exa mple.com",
            DidError::InvalidChar {
                position: 10,
                ch: ' ',
            },
        ),
        (
            "http://a#b#c",
            DidError::InvalidChar {
                position: 10,
                ch: '#',
            },
        ),
        (
            "http://%zz",
            DidError::InvalidPercentEncoding { position: 7 },
        ),
        (
            "http://%2",
            DidError::InvalidPercentEncoding { position: 7 },
        ),
        (
            "http://ü.example",
            DidError::InvalidChar {
                position: 7,
                ch: 'ü',
            },
        ),
        (
            "http://a\"b",
            DidError::InvalidChar {
                position: 8,
                ch: '"',
            },
        ),
        (
            "http://a<b>",
            DidError::InvalidChar {
                position: 8,
                ch: '<',
            },
        ),
        (
            "http://a\\b",
            DidError::InvalidChar {
                position: 8,
                ch: '\\',
            },
        ),
        (
            "http://a{b}",
            DidError::InvalidChar {
                position: 8,
                ch: '{',
            },
        ),
        (
            "http://a|b",
            DidError::InvalidChar {
                position: 8,
                ch: '|',
            },
        ),
        (
            "http://a\x7f",
            DidError::InvalidChar {
                position: 8,
                ch: '\x7f',
            },
        ),
        (
            "/relative/path",
            DidError::InvalidChar {
                position: 14,
                ch: ':',
            },
        ),
        (
            "#fragment",
            DidError::InvalidChar {
                position: 9,
                ch: ':',
            },
        ),
    ] {
        assert_eq!(Uri::parse(invalid), Err(expected), "{invalid:?}");
        assert!(
            serde_json::from_str::<Uri>(&serde_json::to_string(invalid).unwrap()).is_err(),
            "{invalid:?}"
        );
    }
    assert_eq!(Uri::from(did("did:example:1")).as_str(), "did:example:1");
    assert_eq!(
        Uri::from(&url("did:example:1#k")).as_str(),
        "did:example:1#k"
    );
}

#[test]
fn did_url_references_parse_resolve_and_round_trip() {
    let base = did("did:example:123");
    for (input, resolved) in [
        ("#key-1", "did:example:123#key-1"),
        ("#", "did:example:123#"),
        ("?versionId=1", "did:example:123?versionId=1"),
        (
            "/path?versionId=1#key-1",
            "did:example:123/path?versionId=1#key-1",
        ),
        ("did:example:123#key-1", "did:example:123#key-1"),
        ("did:example:456/x", "did:example:456/x"),
    ] {
        let reference = DidUrlReference::parse(input).unwrap_or_else(|e| panic!("{input}: {e}"));
        assert_eq!(reference.as_str(), input);
        assert_eq!(reference.to_string(), input);
        assert_eq!(reference.is_relative(), !input.starts_with("did:"));
        assert_eq!(reference.resolve(&base).unwrap().as_str(), resolved);
        assert!(reference.refers_to(&url(resolved), &base));
        assert!(!reference.refers_to(&url("did:example:999#key-1"), &base));
        assert_eq!(
            serde_json::to_string(&reference).unwrap(),
            format!("\"{input}\"")
        );
        assert_eq!(
            serde_json::from_str::<DidUrlReference>(&format!("\"{input}\"")).unwrap(),
            reference
        );
        assert_eq!(input.parse::<DidUrlReference>().unwrap(), reference);
    }
    // Positions are byte offsets into the input, for relative references too.
    for (invalid, expected) in [
        ("", DidError::MissingScheme),
        ("key-1", DidError::MissingScheme),
        ("https://example.com#k", DidError::MissingScheme),
        (
            "did:Example:1#k",
            DidError::InvalidMethodName { position: 4 },
        ),
        ("#a#b", DidError::InvalidFragment),
        ("?a b", DidError::InvalidQuery),
        ("/p#a#b", DidError::InvalidFragment),
        ("/p q", DidError::InvalidPath),
        ("#a%zz", DidError::InvalidPercentEncoding { position: 2 }),
        ("/p?q=%4", DidError::InvalidPercentEncoding { position: 5 }),
    ] {
        assert_eq!(
            DidUrlReference::parse(invalid),
            Err(expected),
            "{invalid:?}"
        );
    }
    // The length limit applies to relative references as it does to DID URLs.
    let longest = format!("#{}", "k".repeat(DEFAULT_MAX_LEN - 1));
    assert!(DidUrlReference::parse(&longest).is_ok());
    assert_eq!(
        DidUrlReference::parse(&format!("{longest}k")),
        Err(DidError::TooLong {
            max: DEFAULT_MAX_LEN
        })
    );
    assert_eq!(
        DidUrlReference::from(url("did:example:1#k")),
        DidUrlReference::Absolute(url("did:example:1#k"))
    );
}

#[test]
fn one_or_many() {
    let one: OneOrMany<u8> = 1.into();
    let many: OneOrMany<u8> = vec![1, 2].into();
    let empty: OneOrMany<u8> = Vec::new().into();
    assert_eq!(one.len(), 1);
    assert_eq!(many.len(), 2);
    assert!(empty.is_empty());
    assert!(!one.is_empty());
    assert_eq!(one.first(), Some(&1));
    assert_eq!(empty.first(), None);
    assert!(many.contains(&2));
    assert!(!one.contains(&2));
    assert_eq!(many.iter().copied().collect::<Vec<_>>(), [1, 2]);
    assert_eq!(one.clone().into_vec(), [1]);
    assert_eq!(serde_json::to_string(&one).unwrap(), "1");
    assert_eq!(serde_json::to_string(&many).unwrap(), "[1,2]");
    assert_eq!(
        serde_json::from_str::<OneOrMany<u8>>("[1]").unwrap(),
        OneOrMany::Many(vec![1])
    );
    assert_eq!(serde_json::from_str::<OneOrMany<u8>>("1").unwrap(), one);
}

// ---------------------------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------------------------

fn did_strategy() -> impl Strategy<Value = Did> {
    "did:[a-z0-9]{1,6}:[A-Za-z0-9._-]{1,12}".prop_map(|s| Did::parse(&s).unwrap())
}

fn fragment_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._-]{1,8}"
}

fn material_strategy() -> impl Strategy<Value = VerificationMaterial> {
    prop_oneof![
        "z[1-9A-HJ-NP-Za-km-z]{8,44}".prop_map(VerificationMaterial::multibase),
        Just(VerificationMaterial::jwk(
            &serde_json::from_str::<Jwk>(
                r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
            )
            .unwrap()
        )),
    ]
}

fn relationships_strategy() -> impl Strategy<Value = Vec<VerificationRelationship>> {
    proptest::sample::subsequence(VerificationRelationship::ALL.to_vec(), 0..=5)
}

fn endpoint_strategy() -> impl Strategy<Value = ServiceEndpoint> {
    let uri = "https://[a-z]{1,8}\\.example(/[a-z0-9]{0,5})?".prop_map(|s| Uri::parse(&s).unwrap());
    prop_oneof![
        uri.clone().prop_map(ServiceEndpoint::Uri),
        prop::collection::vec(uri, 1..3)
            .prop_map(|uris| ServiceEndpoint::Set(uris.into_iter().collect())),
        prop::collection::vec(("[a-z]{1,5}", any::<i32>()), 0..3).prop_map(|entries| {
            ServiceEndpoint::Map(entries.into_iter().map(|(k, v)| (k, json!(v))).collect())
        }),
    ]
}

/// Every DID the document mentions outside `alsoKnownAs` and extension properties.
fn dids_in(document: &DidDocument) -> Vec<Did> {
    let mut dids = vec![document.id.clone()];
    dids.extend(document.controller.iter().flat_map(|c| c.iter().cloned()));
    for method in document.methods(None) {
        dids.push(method.id.did().clone());
        dids.push(method.controller.clone());
    }
    for relationship in VerificationRelationship::ALL {
        for entry in document.relationship(*relationship) {
            if let Some(DidUrlReference::Absolute(url)) = entry.as_reference() {
                dids.push(url.did().clone());
            }
        }
    }
    dids.extend(document.service.iter().map(|s| s.id.did().clone()));
    dids
}

fn document_strategy() -> impl Strategy<Value = DidDocument> {
    (
        did_strategy(),
        prop::collection::btree_set(fragment_strategy(), 0..4),
        prop::collection::vec((material_strategy(), relationships_strategy()), 4),
        prop::collection::btree_set(fragment_strategy(), 0..3),
        prop::collection::vec(endpoint_strategy(), 3),
        prop::collection::vec(("x-[a-z]{1,6}", any::<i64>()), 0..3),
        prop::option::of(did_strategy()),
    )
        .prop_map(
            |(id, fragments, materials, services, endpoints, properties, controller)| {
                let mut builder = DidDocument::builder(id.clone()).context(Context::did_v1());
                if let Some(controller) = controller {
                    builder = builder.controller(controller);
                }
                for (i, fragment) in fragments.into_iter().enumerate() {
                    let (material, relationships) = &materials[i];
                    let method = VerificationMethod::new(
                        id.join(&format!("#{fragment}")).unwrap(),
                        MethodType::MULTIKEY,
                        id.clone(),
                        material.clone(),
                    );
                    builder = if i % 2 == 0 {
                        builder.verification_method(method, relationships.iter().copied())
                    } else {
                        builder.embedded_method(
                            relationships
                                .first()
                                .copied()
                                .unwrap_or(VerificationRelationship::Authentication),
                            method,
                        )
                    };
                }
                for (i, fragment) in services.into_iter().enumerate() {
                    builder = builder.service(Service::new(
                        id.join(&format!("#svc-{fragment}")).unwrap(),
                        "Service",
                        endpoints[i].clone(),
                    ));
                }
                for (name, value) in properties {
                    builder = builder.property(name, value);
                }
                builder.build().unwrap()
            },
        )
}

proptest! {
    /// The same document always serializes to the same bytes, and the bytes read back as the
    /// same document, which serializes to the same bytes again.
    #[test]
    fn serialization_is_deterministic(document in document_strategy()) {
        let first = serde_json::to_string(&document).unwrap();
        let second = serde_json::to_string(&document.clone()).unwrap();
        prop_assert_eq!(&first, &second);
        let parsed: DidDocument = serde_json::from_str(&first).unwrap();
        prop_assert_eq!(&parsed, &document);
        prop_assert_eq!(serde_json::to_string(&parsed).unwrap(), first.clone());
        let starts_with_context = first.starts_with(r#"{"@context":"https://www.w3.org/ns/did/v1","id":""#);
        prop_assert!(starts_with_context);
        prop_assert!(!first.contains("[]"), "{}", first);
        // Every property name appears once at the top level, in the order DID Core lists them.
        let value: IndexMap<String, Value> = serde_json::from_str(&first).unwrap();
        let core = ["@context", "id", "controller", "verificationMethod", "authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation", "service"];
        let positions: Vec<usize> = core.iter().filter_map(|name| value.get_index_of(*name)).collect();
        prop_assert!(positions.windows(2).all(|w| w[0] < w[1]), "{:?}", positions);
    }

    /// Rewriting the DID moves every method, reference and service with it.
    #[test]
    fn map_dids_moves_the_whole_document(document in document_strategy(), new_id in did_strategy()) {
        let old_id = document.id.clone();
        let mut moved = document.clone();
        moved.map_dids(|d| if d == old_id { new_id.clone() } else { d });
        prop_assert_eq!(&moved.id, &new_id);
        if old_id != new_id {
            prop_assert!(dids_in(&moved).iter().all(|d| *d != old_id), "{:?}", dids_in(&moved));
        }
        for method in document.methods(None) {
            let new_url = method.id.with_did(new_id.clone());
            prop_assert!(moved.verification_method(&new_url).is_some());
        }
        for relationship in VerificationRelationship::ALL {
            prop_assert_eq!(moved.methods(Some(*relationship)).count(), document.methods(Some(*relationship)).count());
        }
        for service in &document.service {
            prop_assert!(moved.service(&service.id.with_did(new_id.clone())).is_some());
        }
        let mut back = moved.clone();
        back.map_dids(|d| if d == new_id { old_id.clone() } else { d });
        if document.controller.iter().flat_map(|c| c.iter()).all(|c| *c != new_id) {
            prop_assert_eq!(back, document);
        }
    }
}
