//! DID documents (DID Core §4 and §5): arbitrary JSON deserializes without panicking, and a
//! document that deserializes serializes back to one that deserializes to the same value, with
//! every verification method and reference resolvable the same way on both.
#![no_main]

use identity_kit::did::{DidDocument, VerificationRelationship};
use libfuzzer_sys::fuzz_target;

fn exercise(document: &DidDocument) {
    let _ = document.check_unique_ids();
    for method in document.methods(None) {
        let _ = method.public_key_jwk();
        let _ = method.public_key_multibase();
        let _ = document.verification_method(&method.id);
        let _ = document.resolve_verification_method(&method.id, None);
    }
    for &relationship in VerificationRelationship::ALL {
        for method in document.relationship(relationship) {
            if let Some(reference) = method.as_reference() {
                let _ = document.resolve_method_reference(reference, Some(relationship));
            }
            if let Some(embedded) = method.as_embedded() {
                let _ = document.resolve_verification_method(&embedded.id, Some(relationship));
            }
        }
        let _ = document.methods(Some(relationship)).count();
    }
    for service in &document.service {
        let _ = document.service(&service.id);
        let _ = service.service_endpoint.uris().count();
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(document) = serde_json::from_slice::<DidDocument>(data) else {
        return;
    };
    exercise(&document);
    let json = serde_json::to_string(&document).expect("a document serializes");
    let again: DidDocument = serde_json::from_str(&json).expect("a serialized document parses");
    assert_eq!(again, document);
    exercise(&again);
});
