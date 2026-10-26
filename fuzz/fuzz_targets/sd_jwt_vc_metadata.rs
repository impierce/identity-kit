//! The documents around an SD-JWT VC: type metadata and integrity metadata (SD-JWT VC §6 and
//! §8), Token Status Lists (§4 to §8 of the Token Status List), claim paths (§5.6.1), and the
//! DIF DID configuration resource. Arbitrary input never panics, and what parses round-trips.
#![no_main]

use std::str::FromStr as _;

use identity_kit::domain_linkage::DomainLinkageConfiguration;
use identity_kit::sd_jwt_vc::{Integrity, IntegrityAlgorithm, TypeMetadata};
use identity_kit::status_list::{StatusList, StatusListToken};
use identity_kit::vc::{ClaimPath, Jwt, PathComponent};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

/// The decompression limit for a list read straight from the input; a deserialized list may
/// be as large as `StatusList::MAX_BYTES`.
const MAX_LIST_BYTES: usize = 1 << 16;

fn exercise_list(list: &StatusList) {
    let json = serde_json::to_value(list).expect("a status list serializes");
    let bits = u8::try_from(json["bits"].as_u64().expect("`bits` is a number")).expect("1 to 8");
    let again: StatusList = serde_json::from_value(json).expect("a serialized list parses");
    assert_eq!(&again, list);
    let again = StatusList::from_lst(bits, &list.to_lst(), StatusList::MAX_BYTES)
        .expect("a compressed list decompresses");
    assert_eq!(&again, list);
    for index in 0..u64::try_from(list.len()).unwrap_or(u64::MAX).min(1024) {
        assert!(list.get(index).is_some());
    }
    assert!(list.get(list.len() as u64).is_none());
}

fn claim_path(value: &Value) -> Option<ClaimPath> {
    let object = value.as_object()?;
    let components = object.get("path")?.as_array()?;
    components
        .iter()
        .map(|component| match component {
            Value::String(name) => Some(PathComponent::from(name.as_str())),
            Value::Number(index) => index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok().map(PathComponent::from)),
            Value::Null => Some(PathComponent::from(())),
            _ => None,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(metadata) = TypeMetadata::parse(data) {
        let _ = metadata.check();
        let json = serde_json::to_vec(&metadata).expect("type metadata serializes");
        let again = TypeMetadata::parse(&json).expect("serialized type metadata parses");
        assert_eq!(again, metadata);
    }
    if let Ok(list) = serde_json::from_slice::<StatusList>(data) {
        exercise_list(&list);
    }
    if let Ok(configuration) = serde_json::from_slice::<DomainLinkageConfiguration>(data) {
        let _ = configuration.check();
        let _ = configuration.jwts().count();
        let json = serde_json::to_string(&configuration).expect("a configuration serializes");
        let again: DomainLinkageConfiguration =
            serde_json::from_str(&json).expect("a serialized configuration parses");
        assert_eq!(again, configuration);
    }
    if let Ok(value) = serde_json::from_slice::<Value>(data)
        && let (Some(path), Some(root)) = (claim_path(&value), value.get("value"))
    {
        if let Ok(selected) = path.select(root) {
            let resolved = path.resolve(root).expect("a selectable path resolves");
            assert_eq!(resolved.len(), selected.len());
            for concrete in &resolved {
                assert!(concrete.is_concrete());
                assert!(path.matches(concrete));
                assert_eq!(concrete.select(root).map(|found| found.len()), Ok(1));
            }
        }
        let _ = path.to_string();
        let _ = path.is_concrete();
        let _ = path.is_prefix_of(&path);
        assert!(path.matches(&path) || !path.is_concrete());
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let integrity = Integrity::parse(input);
    assert_eq!(integrity.as_str(), input);
    assert_eq!(Integrity::from_str(input).as_ref(), Ok(&integrity));
    let _ = integrity.algorithms();
    let _ = integrity.verify(data);
    for algorithm in [
        IntegrityAlgorithm::Sha256,
        IntegrityAlgorithm::Sha384,
        IntegrityAlgorithm::Sha512,
    ] {
        let computed = Integrity::compute(algorithm, data);
        assert!(computed.verify(data).is_ok());
        assert_eq!(Integrity::parse(computed.as_str()), computed);
    }
    for bits in [1, 2, 4, 8] {
        if let Ok(list) = StatusList::from_lst(bits, input, MAX_LIST_BYTES) {
            exercise_list(&list);
        }
    }
    if let Ok(jwt) = Jwt::new(input)
        && let Ok((header, token)) = StatusListToken::decode(&jwt)
    {
        let _ = header.kid;
        exercise_list(&token.status_list);
    }
});
