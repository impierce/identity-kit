//! Specification vectors for `did:key` (did:key method v0.9): the test vectors appendix, the
//! Document Creation Algorithm and its options.
#![cfg(feature = "did-key")]

use identity_kit::did::{
    Did, DidDocument, DidUrl, MethodType, ResolutionError, ResolutionOptions,
    VerificationRelationship,
};
use identity_kit::jose::Jwk;
use identity_kit::methods::DidKey;
use identity_kit::methods::key::KeyFormat;
use identity_kit::resolver::{DidProducer, DidResolver, Hosting, ProduceError, Resolver};
use serde_json::{Value, json};

/// did:key test vectors, "Ed25519 with X25519": the document of the Ed25519 DID with
/// encryption key derivation enabled.
const ED25519_WITH_X25519: &str = r#"{
"@context": [
  "https://www.w3.org/ns/did/v1.1"
],
"id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
"verificationMethod": [{
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "type": "Multikey",
  "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
}],
"authentication": [
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
],
"assertionMethod": [
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
],
"capabilityDelegation": [
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
],
"capabilityInvocation": [
  "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
],
"keyAgreement": [{
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
  "type": "Multikey",
  "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "publicKeyMultibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
}]
}"#;

const ED25519_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const ED25519_MULTIKEY: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn value(document: &DidDocument) -> Value {
    serde_json::to_value(document).unwrap()
}

fn resolver(method: DidKey) -> Resolver {
    Resolver::builder().with(method).build()
}

#[tokio::test]
async fn ed25519_with_x25519_vector() {
    let method = DidKey::new().with_key_agreement(true);
    let document = method.document(&did(ED25519_DID)).unwrap();
    let expected: Value = serde_json::from_str(ED25519_WITH_X25519).unwrap();
    assert_eq!(value(&document), expected);
    // Re-reading the expected document gives the same structure.
    assert_eq!(
        document,
        serde_json::from_str::<DidDocument>(ED25519_WITH_X25519).unwrap()
    );

    let resolver = resolver(method);
    let key_agreement = DidUrl::parse(
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
    )
    .unwrap();
    let x25519 = resolver
        .resolve_verification_method(&key_agreement, Some(VerificationRelationship::KeyAgreement))
        .await
        .unwrap();
    assert_eq!(x25519.method_type, MethodType::MULTIKEY);
    assert_eq!(
        resolver
            .resolve_public_key(&key_agreement)
            .await
            .unwrap()
            .crv(),
        Some("X25519")
    );
}

#[tokio::test]
async fn default_document_has_no_key_agreement() {
    let document = DidKey::default().document(&did(ED25519_DID)).unwrap();
    let mut expected: Value = serde_json::from_str(ED25519_WITH_X25519).unwrap();
    expected.as_object_mut().unwrap().remove("keyAgreement");
    assert_eq!(value(&document), expected);
    assert!(document.key_agreement.is_empty());
    assert_eq!(document.verification_method.len(), 1);
}

#[tokio::test]
async fn json_web_key_format() {
    let method = DidKey::new()
        .with_format(KeyFormat::JsonWebKey)
        .with_key_agreement(true);
    assert_eq!(method.format(), KeyFormat::JsonWebKey);
    assert!(method.key_agreement());
    let document = method.document(&did(ED25519_DID)).unwrap();
    let id = format!("{ED25519_DID}#{ED25519_MULTIKEY}");
    assert_eq!(
        value(&document)["verificationMethod"][0],
        json!({
            "id": id,
            "type": "JsonWebKey",
            "controller": ED25519_DID,
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"}
        })
    );
    assert_eq!(
        value(&document)["keyAgreement"][0],
        json!({
            "id": format!("{ED25519_DID}#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"),
            "type": "JsonWebKey",
            "controller": ED25519_DID,
            "publicKeyJwk": {"kty": "OKP", "crv": "X25519", "x": "bl_3kgKpz9jgsg350CNuHa_kQL3B60Gi-98WmdQW2h8"}
        })
    );
    assert_eq!(KeyFormat::JsonWebKey.to_string(), "JsonWebKey");
    assert_eq!(KeyFormat::default(), KeyFormat::Multikey);
}

#[tokio::test]
async fn every_key_type_of_the_test_vectors() {
    let resolver = resolver(DidKey::new());
    let vectors: &[(&str, &str, Option<&str>)] = &[
        (
            "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
            "OKP",
            Some("Ed25519"),
        ),
        (
            "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
            "OKP",
            Some("X25519"),
        ),
        (
            "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
            "EC",
            Some("P-256"),
        ),
        #[cfg(feature = "secp256k1")]
        (
            "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            "EC",
            Some("secp256k1"),
        ),
        #[cfg(feature = "secp256k1")]
        (
            "zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2",
            "EC",
            Some("secp256k1"),
        ),
        #[cfg(feature = "secp256k1")]
        (
            "zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N",
            "EC",
            Some("secp256k1"),
        ),
        (
            "z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",
            "RSA",
            None,
        ),
    ];
    for (multikey, kty, crv) in vectors {
        let did = did(&format!("did:key:{multikey}"));
        let document = resolver.resolve_document(&did).await.unwrap();
        assert_eq!(document.id, did);
        let method = &document.verification_method[0];
        assert_eq!(method.id.fragment(), Some(*multikey));
        assert_eq!(method.public_key_multibase(), Some(*multikey));
        for relationship in [
            VerificationRelationship::Authentication,
            VerificationRelationship::AssertionMethod,
            VerificationRelationship::CapabilityInvocation,
            VerificationRelationship::CapabilityDelegation,
        ] {
            assert!(
                document
                    .resolve_verification_method(&method.id, Some(relationship))
                    .is_ok(),
                "{multikey} {relationship}"
            );
        }
        assert!(document.key_agreement.is_empty());
        let jwk = resolver.resolve_public_key(&method.id).await.unwrap();
        assert_eq!((jwk.kty(), jwk.crv()), (*kty, *crv), "{multikey}");
        assert_eq!(DidKey::did(&jwk).unwrap(), did);
    }
}

#[test]
fn version_segment() {
    let method = DidKey::new();
    let versioned = did(&format!("did:key:1:{ED25519_MULTIKEY}"));
    let document = method.document(&versioned).unwrap();
    assert_eq!(document.id, versioned);
    assert_eq!(
        document.verification_method[0].id.as_str(),
        format!("did:key:1:{ED25519_MULTIKEY}#{ED25519_MULTIKEY}")
    );
    for invalid in ["0", "x", "", "1.0", "-1"] {
        let did = did(&format!("did:key:{invalid}:{ED25519_MULTIKEY}"));
        assert_eq!(
            method.document(&did),
            Err(ResolutionError::InvalidDid),
            "{did}"
        );
    }
}

#[test]
fn errors_of_the_document_creation_algorithm() {
    let method = DidKey::new();
    let base58 = |bytes: &[u8]| format!("did:key:z{}", bs58::encode(bytes).into_string());
    let other = |name: &str| ResolutionError::Other(name.to_owned());
    for (did_str, error) in [
        // Not a `did:key`.
        ("did:web:example.com", ResolutionError::MethodNotSupported),
        // No `z` multibase prefix (the base64url form is not supported).
        ("did:key:u7QEA", ResolutionError::InvalidDid),
        ("did:key:6MkhaXg", ResolutionError::InvalidDid),
        // Not base58btc.
        ("did:key:z0OIl", ResolutionError::InvalidDid),
        // A multicodec this crate does not know: P-384, BLS12-381.
        (
            "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
            other("unsupportedPublicKeyType"),
        ),
        (
            "did:key:zUC7EK3ZakmukHhuncwkbySmomv3FmrkmS36E4Ks5rsb6VQSRpoCrx6Hb8e2Nk6UvJFSdyw9NK1scFXJp21gNNYFjVWNgaqyGnkyhtagagCpQb5B7tagJu3HDbjQ8h5ypoHjwBb",
            other("unsupportedPublicKeyType"),
        ),
        // Wrong key length, invalid key.
        (
            &base58(&[&[0xed, 0x01][..], &[7; 31]].concat()),
            other("invalidPublicKeyLength"),
        ),
        (
            &base58(&[&[0x80, 0x24][..], &[0x04; 33]].concat()),
            other("invalidPublicKey"),
        ),
    ] {
        assert_eq!(method.document(&did(did_str)), Err(error), "{did_str}");
    }
}

#[tokio::test]
async fn resolution_options() {
    let resolver = resolver(DidKey::new());
    let did = did(ED25519_DID);
    let options = |properties: Value| {
        let mut options = ResolutionOptions::default();
        for (name, value) in properties.as_object().unwrap() {
            options.properties.insert(name.clone(), value.clone());
        }
        options
    };

    let result = resolver
        .resolve_with(&did, &options(json!({"publicKeyFormat": "JsonWebKey"})))
        .await
        .unwrap();
    let document = result.document.unwrap();
    assert_eq!(
        document.verification_method[0].method_type,
        MethodType::JSON_WEB_KEY
    );
    assert!(document.verification_method[0].public_key_jwk().is_some());

    let result = resolver
        .resolve_with(
            &did,
            &options(json!({"publicKeyFormat": "Multikey", "enableEncryptionKeyDerivation": true})),
        )
        .await
        .unwrap();
    let expected: Value = serde_json::from_str(ED25519_WITH_X25519).unwrap();
    assert_eq!(value(&result.document.unwrap()), expected);

    for (properties, error) in [
        (
            json!({"publicKeyFormat": "Ed25519VerificationKey2018"}),
            ResolutionError::Other("unsupportedPublicKeyType".to_owned()),
        ),
        (
            json!({"publicKeyFormat": 1}),
            ResolutionError::Other("unsupportedPublicKeyType".to_owned()),
        ),
        (
            json!({"enableEncryptionKeyDerivation": "yes"}),
            ResolutionError::Other("invalidOptions".to_owned()),
        ),
    ] {
        assert_eq!(
            resolver.resolve_with(&did, &options(properties)).await,
            Err(error)
        );
    }

    // `accept` may only ask for JSON.
    for accept in [
        "application/did+json",
        "application/did+ld+json",
        "application/json",
    ] {
        assert!(
            resolver
                .resolve_with(&did, &ResolutionOptions::accept(accept))
                .await
                .is_ok()
        );
    }
    assert_eq!(
        resolver
            .resolve_with(&did, &ResolutionOptions::accept("application/did+cbor"))
            .await,
        Err(ResolutionError::RepresentationNotSupported)
    );
}

#[tokio::test]
async fn producer_round_trip() {
    let method = DidKey::new().with_format(KeyFormat::JsonWebKey);
    assert_eq!(DidResolver::method(&method), "key");
    assert_eq!(DidProducer::method(&method), "key");
    let capabilities = method.capabilities();
    assert_eq!(capabilities.hosting, Hosting::Embedded);
    assert!(capabilities.single_key && !capabilities.updatable);
    assert_eq!(capabilities.fixed_fragment, None);

    // A private key produces the document of its public part.
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    let document = method
        .produce(std::slice::from_ref(&jwk), ())
        .await
        .unwrap();
    assert_eq!(document.id, did(ED25519_DID));
    assert_eq!(document, method.document(&did(ED25519_DID)).unwrap());
    assert_eq!(
        document.verification_method[0].public_key_jwk(),
        Some(&jwk.public())
    );
    assert_eq!(DidKey::did(&jwk).unwrap(), did(ED25519_DID));

    assert!(matches!(
        method.produce(&[], ()).await,
        Err(ProduceError::NoKeys)
    ));
    assert!(matches!(
        method.produce(&[jwk.clone(), jwk.clone()], ()).await,
        Err(ProduceError::TooManyKeys { max: 1, actual: 2 })
    ));
    let oct: Jwk = serde_json::from_value(json!({"kty": "oct", "k": "AQAB"})).unwrap();
    assert!(matches!(
        method.produce(&[oct], ()).await,
        Err(ProduceError::UnsupportedKey { index: 0, .. })
    ));
}
