//! Specification vectors for `did:key` (did:key method v0.9): the test vectors appendix, the
//! Document Creation Algorithm and its options.
#![cfg(feature = "did-key")]

use std::error::Error as _;

use identity_kit::did::{
    DEFAULT_MAX_LEN, Did, DidDocument, DidUrl, MethodType, ResolutionErrorKind, ResolutionOptions,
    VerificationRelationship,
};
#[cfg(feature = "rsa")]
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, JwsVerifier as _, VerificationError};
use identity_kit::jose::{Jwk, JwkError};
use identity_kit::methods::DidKey;
use identity_kit::methods::key::{DidKeyError, KeyFormat};
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
            .resolve_public_key(&key_agreement, None)
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
    assert!(!DidKey::default().key_agreement());
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
        let jwk = resolver.resolve_public_key(&method.id, None).await.unwrap();
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
            Err(ResolutionErrorKind::InvalidDid.into()),
            "{did}"
        );
    }
    // A version so long that `did#multikey` would not fit a DID URL.
    let prefix = format!(
        "did:key:{}:",
        "1".repeat(DEFAULT_MAX_LEN - 2 * ED25519_MULTIKEY.len())
    );
    let long = did(&format!("{prefix}{ED25519_MULTIKEY}"));
    assert!(long.as_str().len() <= DEFAULT_MAX_LEN);
    assert_eq!(
        method.document(&long),
        Err(ResolutionErrorKind::InvalidDid.into())
    );
    let fits = did(&format!(
        "did:key:{}:{ED25519_MULTIKEY}",
        "1".repeat(DEFAULT_MAX_LEN - 2 * ED25519_MULTIKEY.len() - 10)
    ));
    assert!(method.document(&fits).is_ok());
}

#[test]
fn errors_of_the_document_creation_algorithm() {
    let method = DidKey::new();
    let base58 = |bytes: &[u8]| format!("did:key:z{}", bs58::encode(bytes).into_string());
    let other = |name: &str| ResolutionErrorKind::Other(name.to_owned());
    for (did_str, error) in [
        // Not a `did:key`.
        (
            "did:web:example.com",
            ResolutionErrorKind::MethodNotSupported,
        ),
        // No `z` multibase prefix (the base64url form is not supported).
        ("did:key:u7QEA", ResolutionErrorKind::InvalidDid),
        ("did:key:6MkhaXg", ResolutionErrorKind::InvalidDid),
        // Not base58btc.
        ("did:key:z0OIl", ResolutionErrorKind::InvalidDid),
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
        assert_eq!(
            method.document(&did(did_str)).unwrap_err(),
            error,
            "{did_str}"
        );
    }
    // A Multikey string that does not decode has the decoding error as its source.
    for did_str in [
        "did:key:z0OIl",
        &base58(&[&[0xed, 0x01][..], &[7; 31]].concat()),
    ] {
        let error = method.document(&did(did_str)).unwrap_err();
        assert!(error.source().unwrap().is::<JwkError>(), "{error}");
    }
    let error = method.document(&did("did:key:u7QEA")).unwrap_err();
    assert_eq!(
        error.detail(),
        Some("the method-specific id is not a Multikey string after an optional version")
    );
}

#[tokio::test]
async fn rsa_key_too_long_for_a_did() {
    use base64::Engine as _;
    let method = DidKey::new();
    let rsa = |modulus_bytes: usize| -> Jwk {
        serde_json::from_value(json!({
            "kty": "RSA",
            "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0xff; modulus_bytes]),
            "e": "AQAB",
        }))
        .unwrap()
    };
    // `did#multikey` repeats the Multikey string, so the DID gets about half the DID URL limit.
    assert_eq!(DidKey::MAX_DID_LEN, 8 + (DEFAULT_MAX_LEN - 9) / 2);

    // The largest modulus that fits, found by growing one until its DID is too long.
    let mut bytes = 700;
    let (fits, too_long) = loop {
        let next = rsa(bytes + 1);
        if DidKey::did(&next).is_err() {
            break (rsa(bytes), next);
        }
        bytes += 1;
    };
    let longest = DidKey::did(&fits).unwrap();
    assert!(longest.as_str().len() <= DidKey::MAX_DID_LEN);
    let document = method.document(&longest).unwrap();
    let id = &document.verification_method[0].id;
    assert!(id.as_str().len() <= DEFAULT_MAX_LEN);
    assert_eq!(DidUrl::parse(id.as_str()).as_ref(), Ok(id));
    assert_eq!(
        method
            .produce(std::slice::from_ref(&fits), ())
            .await
            .unwrap(),
        document
    );

    // One byte more is an error, not a panic, from both construction paths.
    assert_eq!(
        DidKey::did(&too_long),
        Err(DidKeyError::TooLong {
            max: DidKey::MAX_DID_LEN
        })
    );
    assert!(matches!(
        method.produce(std::slice::from_ref(&too_long), ()).await,
        Err(ProduceError::UnsupportedKey { index: 0, .. })
    ));
    // The bare DID still parses, but its document would not fit a DID URL.
    let bare = did(&format!("did:key:{}", too_long.to_multikey().unwrap()));
    assert_eq!(
        method.document(&bare),
        Err(ResolutionErrorKind::InvalidDid.into())
    );
    // An unsupported key type is the other error.
    let p384: Jwk =
        serde_json::from_value(json!({"kty": "EC", "crv": "P-384", "x": "", "y": ""})).unwrap();
    assert!(matches!(DidKey::did(&p384), Err(DidKeyError::Key(_))));
}

/// An `rsa-pub` Multikey is a PKCS #1 key of any size, so the did:key of a 1024-bit key
/// resolves. RS256 and PS256 need 2048 bits (RFC 7518 §3.3, §3.5), so no signature under it
/// verifies.
#[tokio::test]
async fn rsa_key_shorter_than_2048_bits_resolves_but_does_not_verify() {
    use base64::Engine as _;
    let jwk: Jwk = serde_json::from_value(json!({
        "kty": "RSA",
        "n": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xff; 128]),
        "e": "AQAB",
    }))
    .unwrap();
    let did = DidKey::did(&jwk).unwrap();
    let resolver = resolver(DidKey::new());
    let document = resolver.resolve_document(&did).await.unwrap();
    let id = &document.verification_method[0].id;
    let key = resolver
        .resolve_public_key(id, Some(VerificationRelationship::AssertionMethod))
        .await
        .unwrap();
    assert_eq!(key, jwk);
    #[cfg(feature = "rsa")]
    for alg in [JwsAlgorithm::RS256, JwsAlgorithm::PS256] {
        assert_eq!(
            DefaultVerifier.verify(alg, b"payload", &[0; 128], &key),
            Err(VerificationError::Key(JwkError::InvalidKey {
                key: "RSA",
                reason: "the modulus is 1024 bits; RS256 and PS256 need at least 2048".to_owned(),
            })),
            "{alg}"
        );
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
            ResolutionErrorKind::Other("unsupportedPublicKeyType".to_owned()),
        ),
        (
            json!({"publicKeyFormat": 1}),
            ResolutionErrorKind::Other("unsupportedPublicKeyType".to_owned()),
        ),
        (
            json!({"enableEncryptionKeyDerivation": "yes"}),
            ResolutionErrorKind::Other("invalidOptions".to_owned()),
        ),
    ] {
        let failure = resolver
            .resolve_with(&did, &options(properties))
            .await
            .unwrap_err();
        assert_eq!(failure, error);
        assert!(failure.detail().is_some(), "{failure}");
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
        Err(ResolutionErrorKind::RepresentationNotSupported.into())
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
