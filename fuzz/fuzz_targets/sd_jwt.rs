//! SD-JWT, SD-JWT VC and `vc+sd-jwt` credential parsing (RFC 9901 §4 and §7.1, SD-JWT VC §3,
//! VC-JOSE-COSE §3.2.1): arbitrary serializations and disclosures never panic, parse exactly
//! what they print, and a token that processes also processes the same after selecting all or
//! none of its disclosures.
#![no_main]

use identity_kit::sd_jwt_vc::{Disclosure, HashAlgorithm, SdJwt, SdJwtCredentialV2, SdJwtVc};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fn exercise(sd_jwt: &SdJwt) {
    let text = sd_jwt.to_string();
    assert_eq!(SdJwt::parse(&text).ok().as_ref(), Some(sd_jwt));
    let bare = sd_jwt.to_string_without_key_binding();
    assert!(text.starts_with(&bare));
    assert!(SdJwt::parse(&bare).is_ok_and(|parsed| parsed.key_binding_jwt().is_none()));
    let _ = sd_jwt.payload();
    let _ = sd_jwt.hash_algorithm();
    let _ = sd_jwt.sd_hash(HashAlgorithm::Sha256);
    let _ = sd_jwt.clone().without_key_binding();

    let Ok(processed) = sd_jwt.process() else {
        return;
    };
    let root = Value::Object(processed.as_issued().clone());
    for path in processed.disclosed_paths() {
        assert!(processed.is_disclosed(path));
        assert!(path.is_concrete());
        assert_eq!(path.select(&root).map(|found| found.len()), Ok(1));
    }
    let all = sd_jwt
        .select(|_| true)
        .expect("selecting everything processes");
    assert_eq!(all.process().ok().as_ref(), Some(&processed));
    let none = sd_jwt
        .select(|_| false)
        .expect("selecting nothing processes");
    let hidden = none
        .process()
        .expect("a token without disclosures processes");
    assert_eq!(hidden.disclosed_paths().count(), 0);
    assert!(none.disclosures().is_empty());
    let paths: Vec<_> = processed.disclosed_paths().cloned().collect();
    let disclosed = sd_jwt.disclose(&paths).expect("disclosing every path");
    assert_eq!(disclosed.process().ok().as_ref(), Some(&processed));
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(disclosure) = Disclosure::parse(input) {
        assert_eq!(disclosure.as_str(), input);
        assert_eq!(
            Disclosure::parse(disclosure.as_str()).ok().as_ref(),
            Some(&disclosure)
        );
        assert_eq!(disclosure.is_element(), disclosure.name().is_none());
        let _ = disclosure.salt();
        let _ = disclosure.value();
        let _ = disclosure.digest(HashAlgorithm::Sha256);
    }
    let _ = HashAlgorithm::parse(input);
    if let Ok(sd_jwt) = SdJwt::parse(input) {
        assert_eq!(sd_jwt.to_string(), input);
        exercise(&sd_jwt);
        if let Ok(credential) = SdJwtVc::from_sd_jwt(sd_jwt.clone()) {
            assert_eq!(credential.sd_jwt(), &sd_jwt);
            assert_eq!(credential.to_string(), input);
            assert!(credential.claims().check().is_ok());
            let _ = credential.header();
            let _ = credential.processed();
            let all = credential.select(|_| true).expect("selecting everything");
            assert_eq!(all.processed(), credential.processed());
            let _ = credential.select(|_| false).expect("selecting nothing");
        }
    }
    if let Ok(credential) = SdJwtVc::parse(input) {
        assert_eq!(credential.to_string(), input);
    }
    if let Ok(credential) = SdJwtCredentialV2::parse(input) {
        assert_eq!(credential.to_string(), input);
        assert!(credential.credential().check().is_ok());
        let _ = credential.header();
        let _ = credential.claims();
        let _ = credential.confirmation();
        let _ = credential.status();
        let _ = credential.holder_key();
        let all = credential.select(|_| true).expect("selecting everything");
        assert_eq!(all.processed(), credential.processed());
        assert_eq!(all.credential(), credential.credential());
        // Withholding every disclosure may hide a property the credential needs.
        let _ = credential.select(|_| false);
    }
});
