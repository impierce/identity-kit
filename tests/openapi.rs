//! The OpenAPI schemas of the `utoipa` feature accept the specifications' own examples (DID
//! Core documents, RFC 7517 keys, the DIF DID configuration resource, SD-JWT VC type
//! metadata) and the documents this crate produces, and reject what the types reject.
#![cfg(feature = "utoipa")]

use boon::{Compiler, Draft, SchemaIndex, Schemas};
use identity_kit::did::{DidDocument, MethodRef, Service, VerificationMethod};
use identity_kit::jose::Jwk;
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use utoipa::openapi::{RefOr, Schema};

/// Where the OpenAPI document lives, for `$ref` resolution.
const OPENAPI_URL: &str = "https://example.com/openapi.json";

/// Adds `T` and the schemas it names in `ToSchema::schemas`.
fn add<T: ToSchema>(schemas: &mut Vec<(String, RefOr<Schema>)>) {
    schemas.push((T::name().into_owned(), T::schema()));
    T::schemas(schemas);
}

/// An OpenAPI document whose components are every schema of the crate.
fn openapi() -> Value {
    let mut schemas = Vec::new();
    add::<DidDocument>(&mut schemas);
    add::<Jwk>(&mut schemas);
    #[cfg(feature = "domain-linkage")]
    add::<identity_kit::domain_linkage::DomainLinkageConfiguration>(&mut schemas);
    #[cfg(feature = "vc")]
    add::<identity_kit::vc::ClaimPath>(&mut schemas);
    #[cfg(feature = "sd-jwt")]
    add::<identity_kit::sd_jwt_vc::TypeMetadata>(&mut schemas);
    #[cfg(feature = "sd-jwt")]
    add::<identity_kit::sd_jwt_vc::StatusType>(&mut schemas);
    document(schemas)
}

/// An OpenAPI document whose components are `schemas`.
fn document(schemas: Vec<(String, RefOr<Schema>)>) -> Value {
    // A name reached twice always names the same schema.
    let mut components = Map::new();
    for (name, schema) in schemas {
        let schema = serde_json::to_value(schema).unwrap();
        match components.get(&name) {
            Some(present) => assert_eq!(present, &schema, "{name}"),
            None => {
                components.insert(name, schema);
            }
        }
    }
    json!({
        "openapi": "3.1.0",
        "info": { "title": "identity-kit", "version": "0" },
        "components": { "schemas": components },
    })
}

struct Validator {
    schemas: Schemas,
    index: SchemaIndex,
}

impl Validator {
    /// The component schema `name`, compiled with every `$ref` resolved.
    fn of(name: &str) -> Self {
        Self::of_in(openapi(), name)
    }

    /// The component schema `name` of `document`, compiled with every `$ref` resolved.
    fn of_in(document: Value, name: &str) -> Self {
        let mut compiler = Compiler::new();
        compiler.set_default_draft(Draft::V2020_12);
        compiler.add_resource(OPENAPI_URL, document).unwrap();
        let mut schemas = Schemas::new();
        let index = compiler
            .compile(
                &format!("{OPENAPI_URL}#/components/schemas/{name}"),
                &mut schemas,
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        Self { schemas, index }
    }

    fn accepts(&self, text: &str) {
        let value: Value = serde_json::from_str(text).unwrap();
        if let Err(error) = self.schemas.validate(&value, self.index) {
            panic!("{text}\n{error}");
        }
    }

    fn rejects(&self, value: &Value) {
        assert!(
            self.schemas.validate(value, self.index).is_err(),
            "accepted {value}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// DID documents
// ---------------------------------------------------------------------------------------------

/// DID Core §1.3, Example 1.
const DID_CORE_EXAMPLE_1: &str = r#"{
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
const DID_CORE_EXAMPLE_2: &str = r##"{
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
const DID_CORE_EXAMPLE_3: &str = r#"{
  "id": "did:example:123456789abcdefghijk"
}"#;

/// DID Core §5.1.2, Example 4: a controller.
const DID_CORE_EXAMPLE_4: &str = r#"{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:example:123456789abcdefghi",
  "controller": "did:example:bcehfew7h32f32h7af3"
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

/// DID Core §5.4, Example 12 (the `id` of the prose added).
const DID_CORE_EXAMPLE_12: &str = r#"{
  "id": "did:example:123",
  "service": [{
    "id":"did:example:123#linked-domain",
    "type": "LinkedDomains",
    "serviceEndpoint": "https://bar.example.com"
  }]
}"#;

/// DID Core §A.2, Example 20 (abridged to three keys): `publicKeyJwk` material.
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

#[test]
fn every_schema_compiles_with_its_references_resolved() {
    let document = openapi();
    let components = document["components"]["schemas"].as_object().unwrap();
    for name in [
        "DidDocument",
        "VerificationMethod",
        "MethodRef",
        "Service",
        "Jwk",
    ] {
        assert!(components.contains_key(name), "{name}");
    }
    #[cfg(feature = "domain-linkage")]
    assert!(components.contains_key("DomainLinkageConfiguration"));
    #[cfg(feature = "vc")]
    assert!(components.contains_key("ClaimPath"));
    #[cfg(feature = "sd-jwt")]
    for name in [
        "TypeMetadata",
        "DisplayMetadata",
        "ClaimMetadata",
        "ClaimDisplay",
        "StatusType",
    ] {
        assert!(components.contains_key(name), "{name}");
    }
    for name in components.keys() {
        Validator::of(name);
    }
    // The schemas of DID Core types describe the core properties and stay open.
    let did_document = &components["DidDocument"];
    assert_eq!(did_document["required"], json!(["id"]));
    assert_eq!(did_document["additionalProperties"], json!(true));
    let properties = did_document["properties"].as_object().unwrap();
    for property in [
        "@context",
        "id",
        "alsoKnownAs",
        "controller",
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
        "service",
    ] {
        assert!(properties.contains_key(property), "{property}");
    }
    assert_eq!(
        properties["verificationMethod"]["items"]["$ref"],
        json!("#/components/schemas/VerificationMethod")
    );
}

/// Each type's `ToSchema::schemas` names every schema its `$ref`s point to.
#[test]
fn every_schema_names_the_schemas_it_refers_to() {
    fn alone<T: ToSchema>() {
        let mut schemas = Vec::new();
        add::<T>(&mut schemas);
        Validator::of_in(document(schemas), &T::name());
    }
    alone::<DidDocument>();
    alone::<VerificationMethod>();
    alone::<MethodRef>();
    alone::<Service>();
    alone::<Jwk>();
    #[cfg(feature = "domain-linkage")]
    alone::<identity_kit::domain_linkage::DomainLinkageConfiguration>();
    #[cfg(feature = "vc")]
    alone::<identity_kit::vc::ClaimPath>();
    #[cfg(feature = "sd-jwt")]
    alone::<identity_kit::sd_jwt_vc::TypeMetadata>();
    #[cfg(feature = "sd-jwt")]
    alone::<identity_kit::sd_jwt_vc::StatusType>();
}

#[test]
fn did_core_examples_validate() {
    let validator = Validator::of("DidDocument");
    for example in [
        DID_CORE_EXAMPLE_1,
        DID_CORE_EXAMPLE_2,
        DID_CORE_EXAMPLE_3,
        DID_CORE_EXAMPLE_4,
        DID_CORE_EXAMPLES_7_TO_11,
        DID_CORE_EXAMPLE_12,
        DID_CORE_EXAMPLE_20,
    ] {
        validator.accepts(example);
        // What the type writes validates too.
        let document: DidDocument = serde_json::from_str(example).unwrap();
        validator.accepts(&serde_json::to_string(&document).unwrap());
    }
}

#[cfg(feature = "did-key")]
#[test]
fn produced_did_key_documents_validate() {
    use identity_kit::methods::DidKey;
    use identity_kit::methods::key::KeyFormat;

    let validator = Validator::of("DidDocument");
    // RFC 8037 Appendix A.1.
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }))
    .unwrap();
    let did = DidKey::did(&jwk).unwrap();
    for method in [
        DidKey::new(),
        DidKey::new().with_format(KeyFormat::JsonWebKey),
        DidKey::new().with_key_agreement(true),
    ] {
        let document = method.document(&did).unwrap();
        validator.accepts(&serde_json::to_string(&document).unwrap());
    }
}

#[cfg(feature = "did-jwk")]
#[test]
fn produced_did_jwk_documents_validate() {
    use identity_kit::methods::DidJwk;

    let validator = Validator::of("DidDocument");
    // RFC 7515 Appendix A.3.
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "EC", "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }))
    .unwrap();
    let document = DidJwk::document(&DidJwk::did(&jwk).unwrap()).unwrap();
    validator.accepts(&serde_json::to_string(&document).unwrap());
}

#[test]
fn documents_the_type_rejects_are_rejected() {
    let validator = Validator::of("DidDocument");
    let method = json!({
        "id": "did:example:123#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:example:123",
        "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    });
    for invalid in [
        // No `id`.
        json!({ "@context": "https://www.w3.org/ns/did/v1" }),
        // Not a DID: uppercase method, empty method-specific id, trailing colon.
        json!({ "id": "DID:example:123" }),
        json!({ "id": "did:example:" }),
        json!({ "id": "did:example:123:" }),
        json!({ "id": "https://example.com" }),
        // Controllers that are not DIDs.
        json!({ "id": "did:example:123", "controller": "https://example.com" }),
        json!({ "id": "did:example:123", "controller": ["did:example:1", 2] }),
        // A verification method without its required members.
        json!({ "id": "did:example:123", "verificationMethod": [{ "id": "did:example:123#k" }] }),
        json!({ "id": "did:example:123", "authentication": [{ "type": "JsonWebKey2020" }] }),
        json!({ "id": "did:example:123", "verificationMethod": [{
            "id": "did:example:123#key-1", "type": "JsonWebKey2020",
            "controller": "did:example:123", "publicKeyJwk": { "crv": "P-256" }
        }] }),
        // A relationship entry that is neither a reference nor a method.
        json!({ "id": "did:example:123", "assertionMethod": [1] }),
        // A service without an endpoint, and one with an empty endpoint set.
        json!({ "id": "did:example:123", "service": [{ "id": "did:example:123#s", "type": "S" }] }),
        json!({ "id": "did:example:123", "service": [{
            "id": "did:example:123#s", "type": "S", "serviceEndpoint": []
        }] }),
        // An empty context.
        json!({ "id": "did:example:123", "@context": [] }),
    ] {
        validator.rejects(&invalid);
        assert!(
            serde_json::from_value::<DidDocument>(invalid.clone()).is_err(),
            "the type accepted {invalid}"
        );
    }
    // Extension properties are allowed, as DID Core §4.1 requires, and an empty controller
    // set reads as none, as the type does.
    let mut extended = json!({
        "id": "did:example:123", "controller": [], "verificationMethod": [method]
    });
    extended["foo"] = json!({ "bar": 1 });
    extended["verificationMethod"][0]["revoked"] = json!("2026-01-01T00:00:00Z");
    validator.accepts(&extended.to_string());
    serde_json::from_value::<DidDocument>(extended).unwrap();
}

// ---------------------------------------------------------------------------------------------
// JOSE
// ---------------------------------------------------------------------------------------------

#[test]
fn rfc_7517_keys_validate() {
    let validator = Validator::of("Jwk");
    for example in [
        // RFC 7517 Appendix A.1, first key.
        r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"}"#,
        // RFC 7517 Appendix A.2, first key.
        r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE","use":"enc","kid":"1"}"#,
        // RFC 7517 Appendix A.2, second key.
        r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q","p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs","q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk","dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0","dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk","qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU","alg":"RS256","kid":"2011-04-29"}"#,
        // RFC 8037 Appendix A.1.
        r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    ] {
        validator.accepts(example);
        let jwk: Jwk = serde_json::from_str(example).unwrap();
        validator.accepts(&serde_json::to_string(&jwk).unwrap());
        validator.accepts(&serde_json::to_string(&jwk.public()).unwrap());
    }
    for invalid in [
        json!({ "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" }),
        json!({ "kty": 1 }),
        json!({ "kty": "RSA", "oth": [{ "r": "AQAB" }] }),
        json!({ "kty": "OKP", "key_ops": "sign" }),
    ] {
        validator.rejects(&invalid);
        assert!(serde_json::from_value::<Jwk>(invalid).is_err());
    }
}

// ---------------------------------------------------------------------------------------------
// DIF Well Known DID Configuration
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "domain-linkage")]
#[test]
fn did_configuration_resource_validates() {
    use identity_kit::domain_linkage::{CONTEXT, DomainLinkageConfiguration};

    let validator = Validator::of("DomainLinkageConfiguration");
    let resource = include_str!("vectors/did_configuration/resource.json");
    validator.accepts(resource);
    let configuration: DomainLinkageConfiguration = serde_json::from_str(resource).unwrap();
    validator.accepts(&serde_json::to_string(&configuration).unwrap());
    validator.accepts(&serde_json::to_string(&DomainLinkageConfiguration::new()).unwrap());

    for invalid in [
        json!({ "linked_dids": [] }),
        json!({ "@context": "https://example.com/other", "linked_dids": [] }),
        json!({ "@context": CONTEXT }),
        json!({ "@context": CONTEXT, "linked_dids": [1] }),
        json!({ "@context": CONTEXT, "linked_dids": [], "extra": true }),
    ] {
        validator.rejects(&invalid);
        assert!(serde_json::from_value::<DomainLinkageConfiguration>(invalid).is_err());
    }
}

/// The map branches of `@context` and `serviceEndpoint` are open objects with a description.
#[test]
fn map_branches_are_described_open_objects() {
    use utoipa::PartialSchema;

    for (schema, pointer, description) in [
        (
            DidDocument::schema(),
            "/properties/@context/oneOf/2",
            "A context object.",
        ),
        (
            Service::schema(),
            "/properties/serviceEndpoint/oneOf/2",
            "An endpoint map.",
        ),
    ] {
        let schema = serde_json::to_value(schema).unwrap();
        assert_eq!(
            schema.pointer(pointer),
            Some(&json!({
                "type": "object",
                "description": description,
                "additionalProperties": true,
            })),
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Claim paths
// ---------------------------------------------------------------------------------------------

/// The `ClaimPath` schema: a non-empty array of names, non-negative indexes and `null`, as
/// SD-JWT VC §5.6.1 and OID4VP §7 define it.
#[cfg(feature = "vc")]
#[test]
fn claim_path_schema() {
    use identity_kit::claim_path;
    use identity_kit::vc::ClaimPath;

    assert_eq!(
        serde_json::to_value(<ClaimPath as utoipa::PartialSchema>::schema()).unwrap(),
        json!({
            "type": "array",
            "description": "A claim path (SD-JWT VC §5.6.1), the claims path pointer of OID4VP §7: where a claim sits in a JSON credential.",
            "items": {
                "description": "A path component.",
                "oneOf": [
                    { "type": "string", "description": "An object key." },
                    { "type": "integer", "minimum": 0, "description": "An array index." },
                    { "type": "null", "description": "Every element of an array." }
                ]
            },
            "minItems": 1
        })
    );

    let validator = Validator::of("ClaimPath");
    // The paths of SD-JWT VC §5.6.1.1 and OID4VP §7.
    for path in [
        json!(["name"]),
        json!(["address"]),
        json!(["address", "street_address"]),
        json!(["degrees", null, "type"]),
        json!(["nationalities", 1]),
    ] {
        validator.accepts(&path.to_string());
        let parsed: ClaimPath = serde_json::from_value(path.clone()).unwrap();
        validator.accepts(&serde_json::to_string(&parsed).unwrap());
    }
    validator.accepts(&serde_json::to_string(&claim_path!["degrees", (), "type"]).unwrap());
    for invalid in [
        json!([]),
        json!(["a", -1]),
        json!(["a", 1.5]),
        json!(["a", true]),
        json!("a"),
    ] {
        validator.rejects(&invalid);
    }
}

// ---------------------------------------------------------------------------------------------
// SD-JWT VC type metadata
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "sd-jwt")]
#[test]
fn type_metadata_examples_validate() {
    use identity_kit::sd_jwt_vc::{
        ClaimDisplay, ClaimMetadata, ClaimPath, PathComponent, SdPolicy, TypeMetadata,
    };

    let validator = Validator::of("TypeMetadata");
    for example in [
        include_str!("vectors/type_metadata/education_credential_v42.json"),
        include_str!("vectors/type_metadata/education_credential.json"),
    ] {
        validator.accepts(example);
        let metadata = TypeMetadata::parse(example.as_bytes()).unwrap();
        validator.accepts(&serde_json::to_string(&metadata).unwrap());
    }
    // What the builder writes, with every kind of path component.
    let built = TypeMetadata::new("https://example.com/credential").with_claim(
        ClaimMetadata::new(ClaimPath::new([
            PathComponent::from("degrees"),
            PathComponent::from(()),
            PathComponent::from("type"),
        ]))
        .with_display(ClaimDisplay::new("en-US", "Degree type"))
        .with_sd(SdPolicy::Always)
        .with_mandatory(false),
    );
    validator.accepts(&serde_json::to_string(&built).unwrap());
    // `vct` is a collision-resistant name, which need not be a URI.
    validator.accepts(r#"{ "vct": "com.example.IdentityCredential" }"#);

    for invalid in [
        json!({ "name": "no vct" }),
        json!({ "vct": "https://example.com/c", "claims": [{ "display": [] }] }),
        json!({ "vct": "https://example.com/c", "claims": [{ "path": ["a", -1] }] }),
        json!({ "vct": "https://example.com/c", "claims": [{ "path": ["a"], "sd": "maybe" }] }),
        json!({ "vct": "https://example.com/c", "claims": [{ "path": ["a"], "display": [{ "locale": "en" }] }] }),
        json!({ "vct": "https://example.com/c", "display": [{ "locale": "en" }] }),
    ] {
        validator.rejects(&invalid);
        assert!(TypeMetadata::parse(invalid.to_string().as_bytes()).is_err());
    }
}

#[cfg(feature = "sd-jwt")]
#[test]
fn status_type_schema() {
    use identity_kit::sd_jwt_vc::StatusType;

    // The schema takes what `StatusType` serializes to: a name of its own, or a number.
    let validator = Validator::of("StatusType");
    for status in [0, 1, 2, 3, 0x0C, 255].map(StatusType) {
        validator.accepts(&serde_json::to_string(&status).unwrap());
    }
    for rejected in [
        json!("APPLICATION_SPECIFIC"),
        json!("valid"),
        json!(256),
        json!(-1),
        json!(1.5),
    ] {
        validator.rejects(&rejected);
    }
}
