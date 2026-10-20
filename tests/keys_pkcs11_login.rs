//! The one `Pkcs11KeyStore` check that needs a process nobody has logged in to the token from:
//! a wrong PIN is refused by `open`. See `keys_pkcs11.rs` for the environment variables.

#![cfg(feature = "pkcs11")]
#![allow(clippy::print_stderr)]

use identity_kit::keys::{KeyStoreError, Pkcs11Error, Pkcs11KeyStore};

#[test]
fn a_wrong_pin_fails_open_not_the_first_signature() {
    let Ok(module) = std::env::var("PKCS11_MODULE") else {
        eprintln!("PKCS11_MODULE is not set; skipping the PKCS#11 tests");
        return;
    };
    let label = std::env::var("PKCS11_TOKEN_LABEL").expect("PKCS11_TOKEN_LABEL is set");
    let pin = std::env::var("PKCS11_PIN").expect("PKCS11_PIN is set");
    assert_ne!(pin, "not-the-pin");

    let error = Pkcs11KeyStore::open(&module, label.as_str(), Some("not-the-pin")).unwrap_err();
    let KeyStoreError::Backend(source) = &error else {
        panic!("expected a backend error, got {error:?}");
    };
    let pkcs11 = source
        .downcast_ref::<Pkcs11Error>()
        .expect("the backend error is a Pkcs11Error");
    assert!(
        matches!(
            pkcs11,
            Pkcs11Error::Call {
                function: "C_Login",
                ..
            }
        ),
        "{error:?}"
    );
    assert!(error.to_string().contains("C_Login failed"), "{error}");

    // The right PIN opens the same token afterwards.
    let store = Pkcs11KeyStore::open(&module, label.as_str(), Some(&pin)).unwrap();
    assert_eq!(store.token_label(), label);
}
