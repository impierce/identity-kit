//! ECDSA signatures in their JWS form: `ecdsa_signature_from_der` and `normalize_ecdsa_signature`
//! never panic, a converted signature has twice the curve's size, and normalizing it again
//! changes nothing.
//!
//! The input is a DER `ECDSA-Sig-Value`, and the same bytes are tried as a raw `r || s`.
#![no_main]

use identity_kit::jose::{JwsAlgorithm, ecdsa_signature_from_der, normalize_ecdsa_signature};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for (alg, size) in [
        (JwsAlgorithm::ES256, 32),
        (JwsAlgorithm::ES256K, 32),
        (JwsAlgorithm::ES384, 48),
    ] {
        if let Ok(raw) = ecdsa_signature_from_der(alg, data) {
            assert_eq!(raw.len(), 2 * size);
            assert_eq!(normalize_ecdsa_signature(alg, &raw).as_ref(), Ok(&raw));
        }
        if let Ok(normalized) = normalize_ecdsa_signature(alg, data) {
            assert_eq!(normalized.len(), data.len());
            assert_eq!(normalize_ecdsa_signature(alg, &normalized).as_ref(), Ok(&normalized));
        }
    }
    for alg in [JwsAlgorithm::EdDSA, JwsAlgorithm::RS256, JwsAlgorithm::PS256] {
        assert!(ecdsa_signature_from_der(alg, data).is_err());
    }
});
