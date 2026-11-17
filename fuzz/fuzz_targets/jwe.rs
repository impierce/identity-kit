//! JWE (RFC 7516, feature `jwe`): decoding a compact JWE, decrypting it with a P-256 key, and
//! reading a private JWK as that key never panic, and a decrypted JWE encrypts back to one that
//! decrypts to the same plaintext.
//!
//! The input is a compact JWE on the first line, followed by a JWK as JSON; either part may be
//! absent. The JWE is decrypted with the Verifier key of OpenID4VP §8.3, whose response is a
//! seed, and with the input's JWK when it is a private P-256 key.
#![no_main]

use std::pin::pin;
use std::sync::LazyLock;
use std::task::{Context, Poll, Waker};

use identity_kit::jose::{CompactJwe, EcdhKey, JweAlgorithm, JweHeader, Jwk};
use libfuzzer_sys::fuzz_target;

/// The Verifier key of OpenID4VP §8.3.
static VERIFIER: LazyLock<EcdhKey> = LazyLock::new(|| {
    let jwk: Jwk = serde_json::from_str(
        r#"{"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
            "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
            "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk",
            "d":"Et-3ce0omz8_TuZ96Df9lp0GAaaDoUnDe6X-CRO7Aww"}"#,
    )
    .expect("a valid JWK");
    EcdhKey::from_jwk(&jwk).expect("a P-256 private key")
});

/// Runs `future`, which never waits: `EcdhKey` computes its shared secret in place.
fn ready<T>(future: impl Future<Output = T>) -> T {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("an `EcdhKey` never waits"),
    }
}

fn exercise(jwe: &CompactJwe, key: &EcdhKey) {
    let Ok(plaintext) = ready(jwe.decrypt(key)) else {
        return;
    };
    let header = JweHeader::new(JweAlgorithm::EcdhEs, jwe.header().enc);
    let again = CompactJwe::encrypt(header, &plaintext, &key.public_jwk())
        .expect("a decrypting key's public key encrypts");
    let again = CompactJwe::decode(again.as_str()).expect("an encrypted JWE decodes");
    assert_eq!(ready(again.decrypt(key)).expect("it decrypts"), plaintext);
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let (token, rest) = input.split_once('\n').unwrap_or((input, ""));
    let key = serde_json::from_str::<Jwk>(rest)
        .ok()
        .and_then(|jwk| EcdhKey::from_jwk(&jwk).ok());
    let Ok(jwe) = CompactJwe::decode(token) else {
        return;
    };
    assert_eq!(jwe.as_str(), token);
    assert_eq!(jwe.header().kid.as_deref(), jwe.kid());
    assert!(jwe.header().epk.as_ref().is_some_and(|epk| !epk.is_private()));
    exercise(&jwe, &VERIFIER);
    if let Some(key) = &key {
        exercise(&jwe, key);
    }
});
