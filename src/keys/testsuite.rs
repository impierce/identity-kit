//! The behavioural suite every [`KeyStore`] must pass.
//!
//! The suite checks the contract of [`KeyStore`] against a live backend: that
//! [`capabilities`](KeyStore::capabilities) is truthful, that every advertised algorithm signs
//! and the signature verifies, that signatures are in their JWS form, and that the error
//! vocabulary (`NotFound`, `AlgorithmMismatch`, `Unsupported`, `AlreadyExists`, `InvalidSpec`)
//! is used as documented. It panics with a message naming the violated requirement.
//!
//! A backend that generates keys runs [`run`]; one whose keys are provisioned out of band (an
//! HSM, a KMS) runs [`run_with_keys`] with one key per advertised algorithm. Every run also
//! covers [`KeySigner`] and [`encode_compact`].
//!
//! Signatures are verified with [`DefaultVerifier`]; an algorithm it cannot verify in this build
//! (ES384, or ES256K and the RSA algorithms without their features) is only format-checked.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "in-memory")]
//! # tokio::runtime::Builder::new_current_thread().build()?.block_on(async {
//! use identity_kit::keys::{InMemoryKeyStore, testsuite};
//!
//! testsuite::run(&InMemoryKeyStore::new()).await;
//! # });
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use super::{KeyId, KeySigner, KeySpec, KeyStore, KeyStoreError};
use crate::jose::{
    CompactJws, DefaultVerifier, JwsAlgorithm, JwsHeader, JwsVerifier as _, KeyType, Signer as _,
    VerificationError, encode_compact,
};

/// Runs the suite against a store that generates keys.
///
/// One key per advertised algorithm is generated, checked as [`run_with_keys`] does, and deleted
/// when the store can delete. The generate and delete contract is checked too: specs whose
/// algorithm does not fit, labels, duplicate labels, unsupported key types.
///
/// # Panics
///
/// When the store does not advertise generation, or on the first violated requirement.
pub async fn run(store: &dyn KeyStore) {
    let capabilities = store.capabilities();
    assert!(
        capabilities.can_generate,
        "testsuite::run needs a store that generates keys; use run_with_keys for provisioned keys"
    );
    check_capabilities(store);

    let mut keys = Vec::new();
    for &alg in &capabilities.algorithms {
        let key_type = key_type_for(alg).unwrap_or_else(|| {
            panic!("{alg} is advertised but no KeyType of this crate generates it")
        });
        let spec = KeySpec::new(key_type, alg);
        match store.generate(spec).await {
            Ok(id) => keys.push((id, alg)),
            Err(e) => panic!("generate for advertised algorithm {alg} failed: {e}"),
        }
    }

    // A label becomes the key id, and a taken label is `AlreadyExists`.
    let (first_id, first_alg) = keys[0].clone();
    let label = format!(
        "identity-kit-testsuite-{}",
        first_alg.as_str().to_lowercase()
    );
    let labelled = store
        .generate(
            KeySpec::new(key_type_for(first_alg).expect("checked above"), first_alg)
                .with_label(&label),
        )
        .await
        .expect("generate with a label");
    assert_eq!(
        labelled.as_str(),
        label,
        "the key id of a labelled key is the label"
    );
    let duplicate = store
        .generate(
            KeySpec::new(key_type_for(first_alg).expect("checked above"), first_alg)
                .with_label(&label),
        )
        .await;
    assert!(
        matches!(duplicate, Err(KeyStoreError::AlreadyExists(ref id)) if id.as_str() == label),
        "generating a taken label must be AlreadyExists, got {duplicate:?}"
    );
    keys.push((labelled, first_alg));

    // A spec whose algorithm does not fit its key type is `InvalidSpec`.
    let wrong_type = match key_type_for(first_alg).expect("checked above") {
        KeyType::Ed25519 => KeyType::P256,
        _ => KeyType::Ed25519,
    };
    let invalid = store.generate(KeySpec::new(wrong_type, first_alg)).await;
    assert!(
        matches!(invalid, Err(KeyStoreError::InvalidSpec { .. })),
        "generating {first_alg} with a {wrong_type:?} key must be InvalidSpec, got {invalid:?}"
    );

    // An algorithm that is not advertised is refused.
    if let Some(alg) = JwsAlgorithm::ALL
        .iter()
        .copied()
        .find(|alg| !capabilities.supports(*alg) && key_type_for(*alg).is_some())
    {
        let key_type = key_type_for(alg).expect("filtered above");
        let refused = store.generate(KeySpec::new(key_type, alg)).await;
        assert!(
            matches!(
                refused,
                Err(KeyStoreError::UnsupportedAlgorithm(_) | KeyStoreError::UnsupportedKeyType(_))
            ),
            "generating unadvertised {alg} must be UnsupportedAlgorithm or UnsupportedKeyType, got {refused:?}"
        );
    }

    run_with_keys(store, &keys).await;

    if capabilities.can_delete {
        for (id, _) in &keys {
            store
                .delete(id)
                .await
                .unwrap_or_else(|e| panic!("delete of `{id}` failed: {e}"));
            assert!(
                !store.exists(id).await.expect("exists after delete"),
                "`{id}` still exists after delete"
            );
            let again = store.delete(id).await;
            assert!(
                matches!(again, Err(KeyStoreError::NotFound(ref missing)) if missing == id),
                "deleting `{id}` twice must be NotFound, got {again:?}"
            );
            let gone = store.public_jwk(id).await;
            assert!(
                matches!(gone, Err(KeyStoreError::NotFound(ref missing)) if missing == id),
                "public_jwk of deleted `{id}` must be NotFound, got {gone:?}"
            );
        }
    }
    let _ = first_id;
}

/// Runs the suite against provisioned keys: `keys` names one key per advertised algorithm.
///
/// Checks, for every key: `exists`, `public_jwk` (public only, `alg` consistent, key type
/// consistent with the algorithm), `sign` (JWS signature form, verifies with
/// [`DefaultVerifier`], `AlgorithmMismatch` for any other algorithm), and the JWS round trip
/// through [`KeySigner`]. Checks `NotFound` for an unknown id, and that `generate` and `delete`
/// are `Unsupported` when not advertised.
///
/// # Panics
///
/// When an advertised algorithm has no key in `keys`, or on the first violated requirement.
pub async fn run_with_keys(store: &dyn KeyStore, keys: &[(KeyId, JwsAlgorithm)]) {
    let capabilities = check_capabilities(store);
    for &alg in &capabilities.algorithms {
        assert!(
            keys.iter().any(|(_, key_alg)| *key_alg == alg),
            "no key for advertised algorithm {alg}"
        );
    }

    for (id, alg) in keys {
        assert!(
            capabilities.supports(*alg),
            "key `{id}` signs with {alg}, which the store does not advertise"
        );
        check_key(store, id, *alg).await;
    }

    check_unknown_key(store).await;

    if !capabilities.can_generate {
        let refused = store
            .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
            .await;
        assert!(
            matches!(refused, Err(KeyStoreError::Unsupported("generate"))),
            "a store that does not advertise generation must return Unsupported(\"generate\"), got {refused:?}"
        );
    }
    if !capabilities.can_delete {
        let (id, _) = &keys[0];
        let refused = store.delete(id).await;
        assert!(
            matches!(refused, Err(KeyStoreError::Unsupported("delete"))),
            "a store that does not advertise deletion must return Unsupported(\"delete\"), got {refused:?}"
        );
        assert!(
            store.exists(id).await.expect("exists"),
            "`{id}` vanished after a refused delete"
        );
    }
}

fn check_capabilities(store: &dyn KeyStore) -> super::KeyStoreCapabilities {
    let capabilities = store.capabilities();
    assert!(
        !capabilities.algorithms.is_empty(),
        "a key store must advertise at least one algorithm"
    );
    for (i, alg) in capabilities.algorithms.iter().enumerate() {
        assert!(
            !capabilities.algorithms[..i].contains(alg),
            "{alg} is advertised twice"
        );
    }
    assert_eq!(
        store.capabilities(),
        capabilities,
        "capabilities must be stable between calls"
    );
    capabilities
}

async fn check_key(store: &dyn KeyStore, id: &KeyId, alg: JwsAlgorithm) {
    assert!(
        store
            .exists(id)
            .await
            .unwrap_or_else(|e| panic!("exists for `{id}` failed: {e}")),
        "`{id}` was provisioned or generated but exists is false"
    );

    let public = store
        .public_jwk(id)
        .await
        .unwrap_or_else(|e| panic!("public_jwk for `{id}` failed: {e}"));
    assert!(
        !public.is_private(),
        "public_jwk for `{id}` carries private parameters"
    );
    if let Some(key_alg) = public.alg() {
        assert_eq!(
            key_alg,
            alg.as_str(),
            "public_jwk for `{id}` names `alg` {key_alg}, but the key signs with {alg}"
        );
    }
    let (kty, crv) = expected_key_type(alg);
    assert_eq!(
        (public.kty(), public.crv()),
        (kty, crv),
        "public_jwk for `{id}` ({alg}) has the wrong key type"
    );
    assert!(
        public.thumbprint_sha256().is_ok(),
        "public_jwk for `{id}` lacks the members its key type requires"
    );

    let data = b"identity-kit key store test suite";
    let signature = store
        .sign(id, alg, data)
        .await
        .unwrap_or_else(|e| panic!("sign with `{id}` ({alg}) failed: {e}"));
    check_signature_form(alg, &signature, &public, id);
    // Before verifying, so that a high `s` is reported as such rather than as a bad signature.
    #[cfg(feature = "secp256k1")]
    if alg == JwsAlgorithm::ES256K {
        check_low_s(store, id).await;
    }
    verify(alg, data, &signature, &public, id);

    // Signing twice must give two valid signatures (equal or not; RFC 6979 and random nonces
    // are both fine).
    let second = store
        .sign(id, alg, data)
        .await
        .unwrap_or_else(|e| panic!("second sign with `{id}` failed: {e}"));
    verify(alg, data, &second, &public, id);

    // Any other algorithm is a mismatch, whether or not the store supports it.
    for &other in JwsAlgorithm::ALL {
        if other == alg {
            continue;
        }
        let refused = store.sign(id, other, data).await;
        assert!(
            matches!(
                refused,
                Err(KeyStoreError::AlgorithmMismatch { ref key, key_alg, requested })
                    if key == id && key_alg == alg && requested == other
            ),
            "signing with `{id}` ({alg}) under {other} must be AlgorithmMismatch, got {refused:?}"
        );
    }

    // The JWS round trip through `KeySigner`.
    let signer = KeySigner::new(store, id.clone(), alg)
        .await
        .unwrap_or_else(|e| panic!("KeySigner::new for `{id}` failed: {e}"));
    assert_eq!(signer.kid(), Some(id.as_str()));
    assert_eq!(signer.public_jwk(), &public);
    let header = JwsHeader::new(alg).with_kid(id.as_str());
    let token = encode_compact(&header, b"{\"iss\":\"did:example:123\"}", &signer)
        .await
        .unwrap_or_else(|e| panic!("encode_compact with `{id}` failed: {e}"));
    let jws = CompactJws::decode(&token).expect("the encoded JWS decodes");
    assert_eq!(jws.kid(), Some(id.as_str()));
    check_signature_form(alg, jws.signature(), &public, id);
    verify(alg, jws.signing_input(), jws.signature(), &public, id);

    for &other in JwsAlgorithm::ALL {
        if other == alg {
            continue;
        }
        let mismatch = KeySigner::new(store, id.clone(), other).await;
        assert!(
            matches!(
                mismatch,
                Err(KeyStoreError::AlgorithmMismatch { .. }
                    | KeyStoreError::UnsupportedAlgorithm(_))
            ),
            "KeySigner::new for `{id}` ({alg}) under {other} must fail, got {mismatch:?}"
        );
    }
}

/// Every ES256K signature has `s` in the lower half of the group order, the only one
/// [`DefaultVerifier`] accepts. A store that passes its signer's `s` through gets it right half
/// the time, so the check signs 32 inputs: such a store passes with a chance of 2^-32.
#[cfg(feature = "secp256k1")]
async fn check_low_s(store: &dyn KeyStore, id: &KeyId) {
    for i in 0..32u8 {
        let signature = store
            .sign(id, JwsAlgorithm::ES256K, &[i])
            .await
            .unwrap_or_else(|e| panic!("signing with `{id}` (ES256K) failed: {e}"));
        let normalized = crate::jose::normalize_ecdsa_signature(JwsAlgorithm::ES256K, &signature)
            .unwrap_or_else(|e| panic!("ES256K signature of `{id}` is not `r || s`: {e}"));
        assert!(
            signature == normalized,
            "ES256K signature of `{id}` has `s` in the upper half of the group order, which \
             verifiers refuse; normalize it with `jose::normalize_ecdsa_signature`"
        );
    }
}

async fn check_unknown_key(store: &dyn KeyStore) {
    let unknown = KeyId::new("identity-kit-testsuite-no-such-key");
    assert!(
        !store
            .exists(&unknown)
            .await
            .expect("exists for an unknown key is Ok(false), not an error"),
        "exists reports an unknown key as present"
    );
    let public = store.public_jwk(&unknown).await;
    assert!(
        matches!(public, Err(KeyStoreError::NotFound(ref id)) if *id == unknown),
        "public_jwk of an unknown key must be NotFound, got {public:?}"
    );
    let alg = store.capabilities().algorithms[0];
    let signature = store.sign(&unknown, alg, b"data").await;
    assert!(
        matches!(signature, Err(KeyStoreError::NotFound(ref id)) if *id == unknown),
        "sign with an unknown key must be NotFound, got {signature:?}"
    );
    let signer = KeySigner::new(store, unknown.clone(), alg).await;
    assert!(
        matches!(signer, Err(KeyStoreError::NotFound(ref id)) if *id == unknown),
        "KeySigner::new for an unknown key must be NotFound, got {signer:?}"
    );
    if store.capabilities().can_delete {
        let deleted = store.delete(&unknown).await;
        assert!(
            matches!(deleted, Err(KeyStoreError::NotFound(ref id)) if *id == unknown),
            "delete of an unknown key must be NotFound, got {deleted:?}"
        );
    }
}

/// The JWS form of a signature under `alg`: 64 bytes for EdDSA, raw `r || s` of twice the
/// field size for ECDSA, the modulus size for RSA.
fn check_signature_form(
    alg: JwsAlgorithm,
    signature: &[u8],
    public: &crate::jose::Jwk,
    id: &KeyId,
) {
    let expected = match alg {
        JwsAlgorithm::EdDSA | JwsAlgorithm::ES256 | JwsAlgorithm::ES256K => Some(64),
        JwsAlgorithm::ES384 => Some(96),
        JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => {
            public.rsa_public_components().ok().map(|(n, _)| n.len())
        }
    };
    if let Some(expected) = expected {
        assert_eq!(
            signature.len(),
            expected,
            "signature of `{id}` ({alg}) must be {expected} bytes (the JWS form, not DER or PEM)"
        );
    }
    if alg.is_ecdsa() {
        assert!(
            !(signature.first() == Some(&0x30) && signature.len() != 64 && signature.len() != 96),
            "signature of `{id}` ({alg}) looks DER-encoded; ECDSA signatures must be raw `r || s`"
        );
    }
}

fn verify(alg: JwsAlgorithm, data: &[u8], signature: &[u8], public: &crate::jose::Jwk, id: &KeyId) {
    match DefaultVerifier.verify(alg, data, signature, public) {
        Ok(()) | Err(VerificationError::UnsupportedAlgorithm(_)) => {}
        Err(e) => panic!("signature of `{id}` ({alg}) does not verify with its public JWK: {e}"),
    }
}

/// The key type that signs with `alg`, for generation; `None` for ES384, which no [`KeyType`]
/// of this crate produces, and for the RSA algorithms, where the 2048-bit key stands in.
fn key_type_for(alg: JwsAlgorithm) -> Option<KeyType> {
    match alg {
        JwsAlgorithm::EdDSA => Some(KeyType::Ed25519),
        JwsAlgorithm::ES256 => Some(KeyType::P256),
        JwsAlgorithm::ES256K => Some(KeyType::Secp256k1),
        JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => Some(KeyType::Rsa2048),
        JwsAlgorithm::ES384 => None,
    }
}

/// The `kty` and `crv` of a public JWK for `alg`.
fn expected_key_type(alg: JwsAlgorithm) -> (&'static str, Option<&'static str>) {
    match alg {
        JwsAlgorithm::EdDSA => ("OKP", Some("Ed25519")),
        JwsAlgorithm::ES256 => ("EC", Some("P-256")),
        JwsAlgorithm::ES256K => ("EC", Some("secp256k1")),
        JwsAlgorithm::ES384 => ("EC", Some("P-384")),
        JwsAlgorithm::RS256 | JwsAlgorithm::PS256 => ("RSA", None),
    }
}
