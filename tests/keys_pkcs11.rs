//! `Pkcs11KeyStore` against a live PKCS#11 module, SoftHSM2 in CI.
//!
//! The module, token and PIN come from `PKCS11_MODULE`, `PKCS11_TOKEN_LABEL` and `PKCS11_PIN`;
//! without `PKCS11_MODULE` every test here passes without doing anything. The tests share one
//! token and run in parallel, so each uses labels of its own. The wrong-PIN check is in
//! `keys_pkcs11_login.rs`, a process of its own, because a PKCS#11 login is the application's.

#![cfg(all(feature = "pkcs11", feature = "test-vectors"))]
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use identity_kit::jose::{
    CompactJws, DefaultVerifier, JwsAlgorithm, JwsHeader, JwsVerifier as _, KeyType, encode_compact,
};
use identity_kit::keys::{
    KeyId, KeySigner, KeySpec, KeyStore, KeyStoreError, Pkcs11Error, Pkcs11KeyStore,
    Pkcs11KeyStoreOptions, Pkcs11Token, testsuite,
};

struct Token {
    module: PathBuf,
    label: String,
    pin: String,
}

/// The token to test against, or `None` (after a note on stderr) when `PKCS11_MODULE` is unset.
///
/// A set `PKCS11_MODULE` without the label or the PIN is a misconfiguration, not a skip.
fn token() -> Option<Token> {
    let Ok(module) = std::env::var("PKCS11_MODULE") else {
        eprintln!("PKCS11_MODULE is not set; skipping the PKCS#11 tests");
        return None;
    };
    Some(Token {
        module: PathBuf::from(module),
        label: std::env::var("PKCS11_TOKEN_LABEL").expect("PKCS11_TOKEN_LABEL is set"),
        pin: std::env::var("PKCS11_PIN").expect("PKCS11_PIN is set"),
    })
}

macro_rules! token {
    () => {
        match token() {
            Some(token) => token,
            None => return,
        }
    };
}

fn open(token: &Token) -> Pkcs11KeyStore {
    open_with(token, Pkcs11KeyStoreOptions::new())
}

fn open_with(token: &Token, options: Pkcs11KeyStoreOptions) -> Pkcs11KeyStore {
    Pkcs11KeyStore::open_with(
        &token.module,
        token.label.as_str(),
        Some(&token.pin),
        options,
    )
    .expect("the token opens")
}

/// The test suite uses fixed labels, so two runs of it must not overlap on one token.
static SUITE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The token, shared by the tests that go through the store and taken exclusively by those
/// that run `pkcs11-tool` on it: the store serializes its own key generation and deletion,
/// but SoftHSM2's file object store fails just as readily when another process writes to the
/// token at the same time.
static TOKEN: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

/// Deletes the keys `labels` name, if an earlier, interrupted run left them on the token.
async fn remove(store: &Pkcs11KeyStore, labels: &[&str]) {
    for label in labels {
        match store.delete(&KeyId::new(*label)).await {
            Ok(()) | Err(KeyStoreError::NotFound(_)) => {}
            Err(e) => panic!("removing `{label}` failed: {e}"),
        }
    }
}

fn backend_error(error: &KeyStoreError) -> &Pkcs11Error {
    let KeyStoreError::Backend(source) = error else {
        panic!("expected a backend error, got {error:?}");
    };
    source
        .downcast_ref::<Pkcs11Error>()
        .expect("the backend error is a Pkcs11Error")
}

// ---------------------------------------------------------------------------------------------
// The behavioural suite
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_suite_passes_against_the_token() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let _suite = SUITE.lock().await;
    let store = open(&token);
    remove(&store, &["identity-kit-testsuite-eddsa"]).await;
    let capabilities = store.capabilities();
    assert!(capabilities.remote, "signing leaves the process");
    assert!(capabilities.can_generate && capabilities.can_delete);
    // SoftHSM2 signs with everything the store knows; another module may not.
    for alg in [
        JwsAlgorithm::EdDSA,
        JwsAlgorithm::ES256,
        JwsAlgorithm::RS256,
    ] {
        assert!(capabilities.supports(alg), "{alg} is advertised");
    }
    #[cfg(feature = "secp256k1")]
    assert!(capabilities.supports(JwsAlgorithm::ES256K));
    assert!(
        !capabilities.supports(JwsAlgorithm::PS256),
        "RS256 is the RSA algorithm"
    );

    testsuite::run(&store).await;

    // Through the forwarding impls, and shared between tasks.
    let shared: Arc<dyn KeyStore> = Arc::new(store.clone());
    testsuite::run(&shared).await;
}

#[tokio::test]
async fn ps256_is_the_other_rsa_algorithm() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let _suite = SUITE.lock().await;
    let store = open_with(
        &token,
        Pkcs11KeyStoreOptions::new()
            .rsa_algorithm(JwsAlgorithm::PS256)
            .algorithms([JwsAlgorithm::PS256]),
    );
    remove(
        &store,
        &["identity-kit-testsuite-ps256", "ps256-only", "ps256-4096"],
    )
    .await;
    assert_eq!(store.options().rsa_algorithm, JwsAlgorithm::PS256);
    let capabilities = store.capabilities();
    assert_eq!(capabilities.algorithms, [JwsAlgorithm::PS256]);
    testsuite::run(&store).await;

    // An RSA key made for PS256 says so and signs PS256 only.
    let key = store
        .generate(KeySpec::new(KeyType::Rsa2048, JwsAlgorithm::PS256).with_label("ps256-only"))
        .await
        .unwrap();
    let jwk = store.public_jwk(&key).await.unwrap();
    assert_eq!(jwk.alg(), Some("PS256"));
    assert_eq!(jwk.kid(), Some("ps256-only"));
    assert!(matches!(
        store.sign(&key, JwsAlgorithm::RS256, b"x").await,
        Err(KeyStoreError::AlgorithmMismatch {
            key_alg: JwsAlgorithm::PS256,
            requested: JwsAlgorithm::RS256,
            ..
        })
    ));
    // The other modulus size.
    let big = store
        .generate(KeySpec::new(KeyType::Rsa4096, JwsAlgorithm::PS256).with_label("ps256-4096"))
        .await
        .unwrap();
    let big_jwk = store.public_jwk(&big).await.unwrap();
    assert_eq!(big_jwk.rsa_public_components().unwrap().0.len(), 512);
    let signature = store.sign(&big, JwsAlgorithm::PS256, b"x").await.unwrap();
    assert_eq!(signature.len(), 512);
    #[cfg(feature = "rsa")]
    DefaultVerifier
        .verify(JwsAlgorithm::PS256, b"x", &signature, &big_jwk)
        .unwrap();
    store.delete(&big).await.unwrap();

    // RSA keys are not generated for an algorithm the store does not offer.
    assert!(matches!(
        store
            .generate(KeySpec::new(KeyType::Rsa2048, JwsAlgorithm::RS256))
            .await,
        Err(KeyStoreError::UnsupportedAlgorithm(JwsAlgorithm::RS256))
    ));
    store.delete(&key).await.unwrap();
}

// ---------------------------------------------------------------------------------------------
// Keys on the token
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn keys_outlive_the_store_and_are_found_by_slot() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let label = "keys-outlive-the-store";
    let first = open(&token);
    remove(&first, &[label]).await;
    let key = first
        .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label(label))
        .await
        .unwrap();
    assert_eq!(key.as_str(), label);
    let jwk = first.public_jwk(&key).await.unwrap();
    assert_eq!(jwk.kid(), Some(label));
    assert_eq!(jwk.alg(), Some("ES256"));
    assert!(!jwk.is_private());
    let slot = first.slot();
    assert_eq!(first.token_label(), token.label);
    assert_eq!(first.module(), token.module);
    drop(first);

    // The same token through its slot id, from a second store in the same process.
    let second =
        Pkcs11KeyStore::open(&token.module, Pkcs11Token::Slot(slot), Some(&token.pin)).unwrap();
    assert_eq!(second.slot(), slot);
    assert_eq!(second.token_label(), token.label);
    assert!(second.exists(&key).await.unwrap());
    assert_eq!(second.public_jwk(&key).await.unwrap(), jwk);
    let signature = second
        .sign(&key, JwsAlgorithm::ES256, b"payload")
        .await
        .unwrap();
    assert_eq!(signature.len(), 64);
    DefaultVerifier
        .verify(JwsAlgorithm::ES256, b"payload", &signature, &jwk)
        .expect("the signature verifies with the public JWK");
    second.delete(&key).await.unwrap();
    assert!(!second.exists(&key).await.unwrap());
}

#[tokio::test]
async fn an_unlabelled_key_is_named_by_its_thumbprint() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open(&token);
    let key = store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    let jwk = store.public_jwk(&key).await.unwrap();
    assert_eq!(jwk.thumbprint_sha256().unwrap(), key.as_str());
    assert_eq!(jwk.kid(), Some(key.as_str()));
    assert_eq!(jwk.crv(), Some("Ed25519"));
    store.delete(&key).await.unwrap();
}

#[tokio::test]
async fn a_key_signer_signs_a_jws() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open(&token);
    remove(&store, &["key-signer"]).await;
    let key = store
        .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("key-signer"))
        .await
        .unwrap();
    let signer = KeySigner::new(&store, key.clone(), JwsAlgorithm::ES256)
        .await
        .unwrap();
    assert_eq!(signer.public_jwk().kid(), Some("key-signer"));
    let jws = encode_compact(
        &JwsHeader::new(JwsAlgorithm::ES256),
        br#"{"hello":"world"}"#,
        &signer,
    )
    .await
    .unwrap();
    let decoded = CompactJws::decode(&jws).unwrap();
    assert_eq!(decoded.header().alg, JwsAlgorithm::ES256);
    decoded
        .verify(&DefaultVerifier, signer.public_jwk())
        .expect("the JWS verifies");
    store.delete(&key).await.unwrap();
}

/// Keys generated while other sessions search the token. SoftHSM2's file object store creates
/// a new key's object file empty, and a search in between marks the object invalid, failing the
/// generation with `CKR_GENERAL_ERROR`, unless the store keeps searches apart from generation.
#[tokio::test]
async fn keys_are_generated_while_other_sessions_search() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open(&token);
    let searching = open_with(&token, Pkcs11KeyStoreOptions::new().sessions(4));
    let label = "generated-while-searched";
    remove(&store, &[label]).await;

    let done = Arc::new(AtomicBool::new(false));
    let searches: Vec<_> = (0..4)
        .map(|_| {
            let store = searching.clone();
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                let missing = KeyId::new("never-generated");
                while !done.load(Ordering::Relaxed) {
                    assert!(!store.exists(&missing).await.unwrap());
                }
            })
        })
        .collect();
    let mut generated = Vec::new();
    for _ in 0..20 {
        let key = store
            .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label(label))
            .await;
        if let Ok(key) = &key {
            store.delete(key).await.unwrap();
        }
        generated.push(key);
    }
    done.store(true, Ordering::Relaxed);
    for search in searches {
        search.await.unwrap();
    }
    for key in generated {
        key.unwrap();
    }
}

#[tokio::test]
async fn sessions_are_shared_between_concurrent_signers() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open_with(&token, Pkcs11KeyStoreOptions::new().sessions(2));
    remove(&store, &["concurrent"]).await;
    let key = store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("concurrent"))
        .await
        .unwrap();
    let jwk = store.public_jwk(&key).await.unwrap();
    let tasks: Vec<_> = (0..16u8)
        .map(|i| {
            let store = store.clone();
            let key = key.clone();
            tokio::spawn(async move {
                let data = vec![i; 16];
                let signature = store.sign(&key, JwsAlgorithm::EdDSA, &data).await.unwrap();
                (data, signature)
            })
        })
        .collect();
    for task in tasks {
        let (data, signature) = task.await.unwrap();
        DefaultVerifier
            .verify(JwsAlgorithm::EdDSA, &data, &signature, &jwk)
            .unwrap();
    }
    store.delete(&key).await.unwrap();
}

/// Runs `pkcs11-tool` against the token, or returns `None` when it is not installed.
fn pkcs11_tool(token: &Token, args: &[&str]) -> Option<std::process::Output> {
    let output = std::process::Command::new("pkcs11-tool")
        .arg("--module")
        .arg(&token.module)
        .args([
            "--login",
            "--pin",
            &token.pin,
            "--token-label",
            &token.label,
        ])
        .args(args)
        .output();
    let Ok(output) = output else {
        eprintln!("pkcs11-tool is not installed; skipping");
        return None;
    };
    assert!(
        output.status.success(),
        "pkcs11-tool {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output)
}

/// A key `pkcs11-tool` makes carries `CKA_EC_PARAMS` as `PrintableString "edwards25519"`, the
/// other spelling PKCS #11 allows; the store reads both.
#[tokio::test]
async fn a_key_made_by_pkcs11_tool_is_usable() {
    let token = token!();
    let _exclusive = TOKEN.write().await;
    let label = "made-by-pkcs11-tool";
    let store = open(&token);
    remove(&store, &[label]).await;
    if pkcs11_tool(
        &token,
        &[
            "--keypairgen",
            "--key-type",
            "EC:edwards25519",
            "--label",
            label,
        ],
    )
    .is_none()
    {
        return;
    }
    let key = KeyId::new(label);
    let jwk = store.public_jwk(&key).await.unwrap();
    assert_eq!(jwk.crv(), Some("Ed25519"));
    assert_eq!(jwk.alg(), Some("EdDSA"));
    let signature = store.sign(&key, JwsAlgorithm::EdDSA, b"msg").await.unwrap();
    DefaultVerifier
        .verify(JwsAlgorithm::EdDSA, b"msg", &signature, &jwk)
        .unwrap();
    store.delete(&key).await.unwrap();
}

/// Objects on the token the store cannot use are `InvalidKey`, with the reason, never a panic
/// or a signature with the wrong key.
#[tokio::test]
async fn unusable_objects_are_invalid_keys() {
    let token = token!();
    let _exclusive = TOKEN.write().await;
    let store = open(&token);
    remove(&store, &["odd-curve", "twice", "half-a-key"]).await;

    // A curve the store does not know.
    if pkcs11_tool(
        &token,
        &[
            "--keypairgen",
            "--key-type",
            "EC:secp384r1",
            "--label",
            "odd-curve",
        ],
    )
    .is_none()
    {
        return;
    }
    let odd = KeyId::new("odd-curve");
    assert!(store.exists(&odd).await.unwrap());
    let error = store.public_jwk(&odd).await.unwrap_err();
    assert!(
        matches!(&error, KeyStoreError::InvalidKey { key, reason, source: None } if *key == odd && reason == "the curve is not P-256 or secp256k1"),
        "{error:?}"
    );
    assert!(matches!(
        store.sign(&odd, JwsAlgorithm::ES256, b"x").await,
        Err(KeyStoreError::InvalidKey { .. })
    ));
    store.delete(&odd).await.unwrap();

    // Two keys under one label: the label no longer names a key.
    for _ in 0..2 {
        pkcs11_tool(
            &token,
            &[
                "--keypairgen",
                "--key-type",
                "EC:prime256v1",
                "--label",
                "twice",
            ],
        );
    }
    let twice = KeyId::new("twice");
    let error = store
        .sign(&twice, JwsAlgorithm::ES256, b"x")
        .await
        .unwrap_err();
    assert!(
        matches!(&error, KeyStoreError::InvalidKey { reason, .. } if reason == "the label names 2 objects of the same class"),
        "{error:?}"
    );
    assert!(matches!(
        store.exists(&twice).await,
        Err(KeyStoreError::InvalidKey { .. })
    ));
    // Clean up object by object, which the store refuses to do by label.
    for class in ["privkey", "pubkey"] {
        for _ in 0..2 {
            pkcs11_tool(
                &token,
                &["--delete-object", "--type", class, "--label", "twice"],
            );
        }
    }
    assert!(!store.exists(&twice).await.unwrap());

    // A private key whose public key object is gone still exists, but has no public JWK.
    let half = store
        .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("half-a-key"))
        .await
        .unwrap();
    pkcs11_tool(
        &token,
        &[
            "--delete-object",
            "--type",
            "pubkey",
            "--label",
            "half-a-key",
        ],
    );
    assert!(store.exists(&half).await.unwrap());
    let error = store.public_jwk(&half).await.unwrap_err();
    assert!(
        matches!(&error, KeyStoreError::InvalidKey { reason, .. } if reason == "the token has no public key object with this label"),
        "{error:?}"
    );
    // Signing needs the private key only.
    assert_eq!(
        store
            .sign(&half, JwsAlgorithm::ES256, b"x")
            .await
            .unwrap()
            .len(),
        64
    );
    store.delete(&half).await.unwrap();
    assert!(!store.exists(&half).await.unwrap());
}

// ---------------------------------------------------------------------------------------------
// Options and errors
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn algorithms_can_be_narrowed() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open_with(
        &token,
        Pkcs11KeyStoreOptions::new().algorithms([JwsAlgorithm::ES256, JwsAlgorithm::ES384]),
    );
    // ES384 is nothing the module signs with, so narrowing to it adds nothing.
    assert_eq!(store.capabilities().algorithms, [JwsAlgorithm::ES256]);
    assert!(matches!(
        store
            .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
            .await,
        Err(KeyStoreError::UnsupportedAlgorithm(JwsAlgorithm::EdDSA))
    ));

    // A key of a type the store was narrowed away from still has its public JWK, but does not
    // sign.
    let wide = open(&token);
    remove(&wide, &["narrowed-out"]).await;
    let key = wide
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("narrowed-out"))
        .await
        .unwrap();
    assert_eq!(store.public_jwk(&key).await.unwrap().alg(), Some("EdDSA"));
    assert!(matches!(
        store.sign(&key, JwsAlgorithm::EdDSA, b"x").await,
        Err(KeyStoreError::UnsupportedAlgorithm(JwsAlgorithm::EdDSA))
    ));
    assert!(matches!(
        store.sign(&key, JwsAlgorithm::ES256, b"x").await,
        Err(KeyStoreError::AlgorithmMismatch {
            key_alg: JwsAlgorithm::EdDSA,
            requested: JwsAlgorithm::ES256,
            ..
        })
    ));
    wide.delete(&key).await.unwrap();
}

#[tokio::test]
async fn a_missing_token_is_refused() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let error = Pkcs11KeyStore::open(&token.module, "no-such-token", Some(&token.pin)).unwrap_err();
    assert!(matches!(
        backend_error(&error),
        Pkcs11Error::TokenNotFound(Pkcs11Token::Label(label)) if label == "no-such-token"
    ));
    assert_eq!(
        error.to_string(),
        "key store backend error: PKCS#11 module has no token `no-such-token`"
    );

    let error = Pkcs11KeyStore::open(&token.module, u64::MAX, Some(&token.pin)).unwrap_err();
    assert!(matches!(
        backend_error(&error),
        Pkcs11Error::TokenNotFound(Pkcs11Token::Slot(u64::MAX))
    ));
}

#[tokio::test]
async fn an_unknown_key_is_not_found() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open(&token);
    let missing = KeyId::new("nothing-here");
    assert!(!store.exists(&missing).await.unwrap());
    assert!(
        matches!(store.public_jwk(&missing).await, Err(KeyStoreError::NotFound(k)) if k == missing)
    );
    assert!(matches!(
        store.sign(&missing, JwsAlgorithm::ES256, b"x").await,
        Err(KeyStoreError::NotFound(k)) if k == missing
    ));
    assert!(
        matches!(store.delete(&missing).await, Err(KeyStoreError::NotFound(k)) if k == missing)
    );
}

#[tokio::test]
async fn the_store_describes_itself() {
    let token = token!();
    let _shared = TOKEN.read().await;
    let store = open(&token);
    let debug = format!("{store:?}");
    assert!(debug.starts_with("Pkcs11KeyStore {"), "{debug}");
    assert!(
        debug.contains(&format!("token_label: {:?}", token.label)),
        "{debug}"
    );
    assert!(
        !debug.contains(&token.pin),
        "the PIN is not printed: {debug}"
    );
    assert_eq!(store.options(), &Pkcs11KeyStoreOptions::new());
}
