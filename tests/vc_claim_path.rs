//! Claim path vectors: the examples of SD-JWT VC §5.6.1.1 and OID4VP §7 (the claims path
//! pointer), which share one credential and its paths.
#![cfg(feature = "vc")]

use identity_kit::claim_path;
use identity_kit::vc::{ClaimPath, ClaimPathError, PathComponent};
use serde_json::json;

/// SD-JWT VC §5.6.1.1 and OID4VP §7 use the same credential; one copy serves both.
#[test]
fn claim_path_examples_of_sd_jwt_vc_and_oid4vp() {
    let credential = json!({
      "vct": "https://betelgeuse.example.com/education_credential/v42",
      "name": "Arthur Dent",
      "address": {
        "street_address": "42 Market Street",
        "city": "Milliways",
        "postal_code": "12345"
      },
      "degrees": [
        { "type": "Bachelor of Science", "university": "University of Betelgeuse" },
        { "type": "Master of Science", "university": "University of Betelgeuse" }
      ],
      "nationalities": ["British", "Betelgeusian"]
    });
    assert_eq!(
        claim_path!["name"].select(&credential).unwrap(),
        vec![&json!("Arthur Dent")]
    );
    assert_eq!(
        claim_path!["address"].select(&credential).unwrap(),
        vec![&credential["address"]]
    );
    assert_eq!(
        claim_path!["address", "street_address"]
            .select(&credential)
            .unwrap(),
        vec![&json!("42 Market Street")]
    );
    assert_eq!(
        claim_path!["degrees", (), "type"]
            .select(&credential)
            .unwrap(),
        vec![&json!("Bachelor of Science"), &json!("Master of Science")]
    );
    assert_eq!(
        claim_path!["nationalities", 1].select(&credential).unwrap(),
        vec![&json!("Betelgeusian")]
    );
    // Missing names and indexes select nothing; wrong kinds are errors.
    assert!(
        claim_path!["missing"]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(
        claim_path!["nationalities", 2]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(
        claim_path!["degrees", (), "missing"]
            .select(&credential)
            .unwrap()
            .is_empty()
    );
    assert!(claim_path!["name", "first"].select(&credential).is_err());
    assert!(claim_path!["address", ()].select(&credential).is_err());
    assert!(claim_path!["address", 0].select(&credential).is_err());
    assert!(claim_path!["degrees", "type"].select(&credential).is_err());
    assert_eq!(
        claim_path!["degrees", (), "type"]
            .resolve(&credential)
            .unwrap(),
        vec![
            claim_path!["degrees", 0, "type"],
            claim_path!["degrees", 1, "type"]
        ]
    );
}

#[test]
fn paths_are_json_arrays_of_names_indexes_and_null() {
    let path: ClaimPath = serde_json::from_value(json!(["degrees", null, "type"])).unwrap();
    assert_eq!(path, claim_path!["degrees", (), "type"]);
    assert_eq!(
        path.components(),
        [
            PathComponent::Key("degrees".to_owned()),
            PathComponent::All,
            PathComponent::Key("type".to_owned())
        ]
    );
    assert_eq!(
        serde_json::to_value(claim_path!["nationalities", 1]).unwrap(),
        json!(["nationalities", 1])
    );
    assert_eq!(path.to_string(), r#"["degrees", null, "type"]"#);
    assert!(!path.is_concrete());
    assert!(path.matches(&claim_path!["degrees", 1, "type"]));
    assert!(path.is_prefix_of(&claim_path!["degrees", 0, "type", "x"]));
    for invalid in [
        json!(["a", -1]),
        json!(["a", 1.5]),
        json!(["a", true]),
        json!("a"),
    ] {
        assert!(
            serde_json::from_value::<ClaimPath>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }

    // The error names the path and the component that failed.
    let credential = json!({ "name": "Arthur Dent" });
    assert_eq!(
        claim_path!["name", "first"].select(&credential),
        Err(ClaimPathError {
            path: claim_path!["name", "first"],
            depth: 1,
            expected: "an object"
        })
    );
}

/// The old `sd_jwt_vc` paths name the same types.
#[cfg(feature = "sd-jwt")]
#[test]
fn the_sd_jwt_vc_paths_still_name_the_types() {
    let _: ClaimPath = identity_kit::sd_jwt_vc::ClaimPath::root();
    let _: PathComponent = identity_kit::sd_jwt_vc::PathComponent::All;
    let _: Option<ClaimPathError> = None::<identity_kit::sd_jwt_vc::ClaimPathError>;
}
