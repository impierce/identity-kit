//! `SoftwareKeyStore` writes its temporary file next to the key file, never in the working
//! directory. A test binary of its own: it changes the working directory of the process.
#![cfg(all(unix, feature = "software"))]

use identity_kit::jose::{JwsAlgorithm, KeyType};
use identity_kit::keys::{KeySpec, KeyStore, SoftwareKeyStore};

#[tokio::test]
async fn saves_in_the_directory_of_the_key_file() {
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("keys.json");

    // A deleted working directory: nothing can be created in `.`, not even by root.
    let gone = tempfile::tempdir().unwrap().keep();
    std::env::set_current_dir(&gone).unwrap();
    std::fs::remove_dir(&gone).unwrap();

    let store = SoftwareKeyStore::create(&path).unwrap();
    let id = store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    store.delete(&id).await.unwrap();
    let kept = store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    assert!(
        SoftwareKeyStore::open(&path)
            .unwrap()
            .exists(&kept)
            .await
            .unwrap()
    );
}
