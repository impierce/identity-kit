//! Specification vectors for the DID resolution types (W3C DID Core 1.0 §7.1).

use identity_kit::did::{
    APPLICATION_DID_JSON, APPLICATION_DID_LD_JSON, Did, DidDocument, DidError, DocumentMetadata,
    ResolutionError, ResolutionMetadata, ResolutionOptions, ResolutionResult, VerificationMaterial,
};
use identity_kit::jose::Jwk;
use serde_json::{Value, json};

fn canonical(json: &str) -> String {
    serde_json::to_string(&serde_json::from_str::<Value>(json).unwrap()).unwrap()
}

/// DID Core §7.1, Example 16: resolution options.
const EXAMPLE_16: &str = r#"{
  "accept": "application/did+ld+json"
}"#;

/// DID Core §7.1, Example 17: resolution metadata.
const EXAMPLE_17: &str = r#"{
  "error": "notFound"
}"#;

/// DID Core §7.1, Example 18: document metadata.
const EXAMPLE_18: &str = r#"{
  "created": "2019-03-23T06:35:22Z",
  "updated": "2023-08-10T13:40:06Z"
}"#;

#[test]
fn did_core_metadata_examples_round_trip() {
    let options: ResolutionOptions = serde_json::from_str(EXAMPLE_16).unwrap();
    assert_eq!(options.accept.as_deref(), Some(APPLICATION_DID_LD_JSON));
    assert_eq!(options, ResolutionOptions::accept(APPLICATION_DID_LD_JSON));
    assert_eq!(
        serde_json::to_string(&options).unwrap(),
        canonical(EXAMPLE_16)
    );

    let metadata: ResolutionMetadata = serde_json::from_str(EXAMPLE_17).unwrap();
    assert_eq!(metadata.error, Some(ResolutionError::NotFound));
    assert_eq!(
        metadata,
        ResolutionMetadata::error(ResolutionError::NotFound)
    );
    assert_eq!(
        serde_json::to_string(&metadata).unwrap(),
        canonical(EXAMPLE_17)
    );

    let metadata: DocumentMetadata = serde_json::from_str(EXAMPLE_18).unwrap();
    assert_eq!(metadata.created.as_deref(), Some("2019-03-23T06:35:22Z"));
    assert_eq!(metadata.updated.as_deref(), Some("2023-08-10T13:40:06Z"));
    assert!(!metadata.is_deactivated());
    assert_eq!(
        serde_json::to_string(&metadata).unwrap(),
        canonical(EXAMPLE_18)
    );
}

#[test]
fn document_metadata_carries_every_registered_property() {
    let json = r#"{"created":"2019-03-23T06:35:22Z","updated":"2023-08-10T13:40:06Z","deactivated":true,"nextUpdate":"2024-01-01T00:00:00Z","versionId":"4","nextVersionId":"5","equivalentId":["did:example:abc","did:example:ABC"],"canonicalId":"did:example:ABC","method":{"txn":12}}"#;
    let metadata: DocumentMetadata = serde_json::from_str(json).unwrap();
    assert!(metadata.is_deactivated());
    assert_eq!(metadata.version_id.as_deref(), Some("4"));
    assert_eq!(metadata.next_version_id.as_deref(), Some("5"));
    assert_eq!(
        metadata.next_update.as_deref(),
        Some("2024-01-01T00:00:00Z")
    );
    assert_eq!(metadata.equivalent_id.len(), 2);
    assert_eq!(
        metadata.canonical_id,
        Some(Did::parse("did:example:ABC").unwrap())
    );
    assert_eq!(metadata.properties["method"], json!({"txn": 12}));
    assert_eq!(serde_json::to_string(&metadata).unwrap(), json);
    assert_eq!(
        serde_json::to_string(&DocumentMetadata::default()).unwrap(),
        "{}"
    );
    assert!(serde_json::from_str::<DocumentMetadata>(r#"{"equivalentId":["nope"]}"#).is_err());
}

#[test]
fn resolution_metadata_keeps_unknown_properties() {
    let json = r#"{"contentType":"application/did+json","retrieved":"2024-06-01T19:13:24Z","pattern":"^(did:example:.+)$"}"#;
    let metadata: ResolutionMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(metadata.content_type.as_deref(), Some(APPLICATION_DID_JSON));
    assert_eq!(metadata.error, None);
    assert_eq!(
        metadata.properties.keys().collect::<Vec<_>>(),
        ["retrieved", "pattern"]
    );
    assert_eq!(serde_json::to_string(&metadata).unwrap(), json);
    assert_eq!(
        ResolutionMetadata::content_type(APPLICATION_DID_JSON).content_type,
        metadata.content_type
    );
}

#[test]
fn error_vocabulary() {
    for (error, keyword) in [
        (ResolutionError::InvalidDid, "invalidDid"),
        (ResolutionError::NotFound, "notFound"),
        (ResolutionError::MethodNotSupported, "methodNotSupported"),
        (
            ResolutionError::RepresentationNotSupported,
            "representationNotSupported",
        ),
        (
            ResolutionError::Other("internalError".to_owned()),
            "internalError",
        ),
    ] {
        assert_eq!(error.as_str(), keyword);
        assert_eq!(keyword.parse::<ResolutionError>().unwrap(), error);
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            format!("\"{keyword}\"")
        );
        assert_eq!(
            serde_json::from_str::<ResolutionError>(&format!("\"{keyword}\"")).unwrap(),
            error
        );
        assert!(!error.to_string().is_empty());
    }
    assert_eq!(ResolutionError::NotFound.to_string(), "DID not found");
    assert_eq!(
        ResolutionError::Other("x".to_owned()).to_string(),
        "resolution error `x`"
    );
    assert!(serde_json::from_str::<ResolutionError>("\"\"").is_err());
    assert!(serde_json::from_str::<ResolutionError>("\"nötFound\"").is_err());
    assert!(serde_json::from_str::<ResolutionError>("{}").is_err());
    assert_eq!(
        ResolutionError::from(DidError::MissingScheme),
        ResolutionError::InvalidDid
    );
}

#[test]
fn resolution_results() {
    let document: DidDocument = serde_json::from_str(
        r#"{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:123"}"#,
    )
    .unwrap();
    let result = ResolutionResult::new(document.clone())
        .with_resolution_metadata(ResolutionMetadata::content_type(APPLICATION_DID_LD_JSON))
        .with_document_metadata({
            let mut metadata = DocumentMetadata::default();
            metadata.created = Some("2019-03-23T06:35:22Z".to_owned());
            metadata
        });
    assert_eq!(
        serde_json::to_string(&result).unwrap(),
        concat!(
            r#"{"didDocument":{"@context":"https://www.w3.org/ns/did/v1","id":"did:example:123"},"#,
            r#""didResolutionMetadata":{"contentType":"application/did+ld+json"},"#,
            r#""didDocumentMetadata":{"created":"2019-03-23T06:35:22Z"}}"#
        )
    );
    assert_eq!(result.to_string(), serde_json::to_string(&result).unwrap());
    let parsed: ResolutionResult = serde_json::from_str(&result.to_string()).unwrap();
    assert_eq!(parsed, result);
    assert_eq!(parsed.error_kind(), None);
    assert_eq!(parsed.into_document(), Ok(document.clone()));

    let failed = ResolutionResult::error(ResolutionError::MethodNotSupported);
    assert_eq!(failed.document, None);
    assert_eq!(
        failed.error_kind(),
        Some(&ResolutionError::MethodNotSupported)
    );
    assert_eq!(
        failed.clone().into_document(),
        Err(ResolutionError::MethodNotSupported)
    );
    assert_eq!(
        serde_json::to_string(&failed).unwrap(),
        r#"{"didResolutionMetadata":{"error":"methodNotSupported"},"didDocumentMetadata":{}}"#
    );

    // A result with neither document nor error is "not found"; one with both reports the error.
    assert_eq!(
        ResolutionResult::default().into_document(),
        Err(ResolutionError::NotFound)
    );
    let inconsistent: ResolutionResult = serde_json::from_str(
        r#"{"didDocument":{"id":"did:example:123"},"didResolutionMetadata":{"error":"invalidDid"}}"#,
    )
    .unwrap();
    assert_eq!(
        inconsistent.into_document(),
        Err(ResolutionError::InvalidDid)
    );
    // Metadata objects default when absent.
    let minimal: ResolutionResult =
        serde_json::from_str(r#"{"didDocument":{"id":"did:example:123"}}"#).unwrap();
    assert_eq!(minimal.into_document().unwrap().id, document.id);
}

#[test]
fn display_names_the_reason_when_the_result_cannot_be_serialized() {
    let mut document: DidDocument = serde_json::from_value(json!({
        "id": "did:example:123",
        "verificationMethod": [{
            "id": "did:example:123#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
        }]
    }))
    .unwrap();
    // A private JWK cannot be written into a document, so the result has no JSON form.
    let private: Jwk = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    }))
    .unwrap();
    document.verification_method[0].material =
        VerificationMaterial::PublicKeyJwk(Box::new(private));
    let result = ResolutionResult::new(document);
    assert!(serde_json::to_string(&result).is_err());
    let shown = result.to_string();
    assert!(
        shown.starts_with("<unserializable resolution result: "),
        "{shown}"
    );
    assert!(shown.contains("private"), "{shown}");
}
