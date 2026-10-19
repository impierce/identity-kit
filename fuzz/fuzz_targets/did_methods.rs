//! The `did:key`, `did:jwk` and `did:web` methods: an arbitrary DID expands to a document or an
//! error, never a panic, and a DID produced from a key resolves back to that key.
//!
//! The input is a DID or an HTTPS URL on the first line, followed by a JWK as JSON; either part
//! may be absent.
#![no_main]

use identity_kit::did::{Did, DidDocument, VerificationRelationship};
use identity_kit::jose::Jwk;
use identity_kit::methods::{DidJwk, DidKey, web};
use libfuzzer_sys::fuzz_target;
use url::Url;

/// The one key the method expands a DID to.
fn key_of(document: &DidDocument, did: &Did) -> Jwk {
    assert_eq!(&document.id, did);
    let method = document
        .methods(Some(VerificationRelationship::AssertionMethod))
        .next()
        .expect("an assertion method");
    assert_eq!(method.id.did(), did);
    assert!(
        document
            .resolve_verification_method(&method.id, None)
            .is_ok()
    );
    let json = serde_json::to_string(document).expect("a document serializes");
    let again: DidDocument = serde_json::from_str(&json).expect("a serialized document parses");
    assert_eq!(&again, document);
    method
        .public_key_jwk()
        .cloned()
        .or_else(|| {
            method
                .public_key_multibase()
                .map(|multikey| Jwk::from_multikey(multikey).expect("a Multikey the method wrote"))
        })
        .expect("key material")
}

fuzz_target!(|data: &[u8]| {
    let (first, rest) = match data.iter().position(|&b| b == b'\n') {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &[][..]),
    };

    if let Ok(input) = std::str::from_utf8(first) {
        if let Ok(did) = Did::parse(input) {
            if let Ok(document) = DidKey::default().document(&did) {
                let key = key_of(&document, &did);
                assert_eq!(DidKey::did(&key).as_ref(), Ok(&did));
            }
            if let Ok(document) = DidJwk::document(&did) {
                let key = key_of(&document, &did);
                assert!(!key.is_private());
                // The DID carries the JWK as serialized by its producer, which need not be the
                // canonical (JCS) form this crate creates, so only the key must agree.
                let produced = DidJwk::did(&key).expect("a key read from a did:jwk fits one");
                let again = DidJwk::document(&produced).expect("a produced did:jwk resolves");
                assert_eq!(key_of(&again, &produced), key);
            }
            if let Ok(url) = web::document_url(&did) {
                let back = web::did_from_url(&url).expect("a document URL maps back");
                assert_eq!(web::document_url(&back).as_ref(), Ok(&url));
            }
        }
        if let Ok(url) = Url::parse(input) {
            if let Ok(did) = web::did_from_url(&url) {
                assert_eq!(did.method(), "web");
                web::document_url(&did).expect("a DID from a URL maps to a document URL");
            }
            let _ = web::did_from_origin(&url);
        }
    }

    if let Ok(jwk) = serde_json::from_slice::<Jwk>(rest) {
        if let Ok(did) = DidKey::did(&jwk) {
            let document = DidKey::default()
                .document(&did)
                .expect("a produced did:key resolves");
            let key = key_of(&document, &did);
            assert_eq!(key.to_multikey().ok(), jwk.to_multikey().ok());
        }
        if let Ok(did) = DidJwk::did(&jwk) {
            let document = DidJwk::document(&did).expect("a produced did:jwk resolves");
            let key = key_of(&document, &did);
            assert_eq!(key, jwk.public());
            // The canonical form survives a round trip through the document.
            assert_eq!(DidJwk::did(&key).as_ref(), Ok(&did));
        }
    }
});
