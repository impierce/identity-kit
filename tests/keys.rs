//! Specification vectors and behaviour of the `keys` module: the in-memory and software key
//! stores, `KeySigner`, and the test suite itself. Vectors are RFC 7517 Appendix A.2, RFC 7515
//! Appendix A.3 and RFC 8037 Appendix A.
#![cfg(all(feature = "in-memory", feature = "software", feature = "test-vectors"))]

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use identity_kit::jose::{
    CompactJws, DefaultVerifier, Jwk, JwsAlgorithm, JwsHeader, JwsVerifier, KeyType, Signer,
    encode_compact,
};
use identity_kit::keys::{
    InMemoryKeyStore, KeyId, KeySigner, KeySpec, KeyStore, KeyStoreCapabilities, KeyStoreError,
    SoftwareKeyStore, SoftwareKeyStoreOptions, testsuite,
};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------------------------

/// RFC 8037 Appendix A.1, the private key; A.2 is the same key without `d`.
const RFC8037_A1: &str = r#"{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
/// RFC 8037 Appendix A.3.
const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
/// RFC 8037 Appendix A.4 and A.5: the signing input and the signature of the JWS.
const RFC8037_SIGNING_INPUT: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
const RFC8037_SIGNATURE: &str =
    "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

/// RFC 7515 Appendix A.3, the P-256 key and the signing input.
const RFC7515_A3_KEY: &str = r#"{"kty":"EC","crv":"P-256",
   "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
   "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
   "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}"#;
const RFC7515_A3_SIGNING_INPUT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

/// RFC 7517 Appendix A.2: a JWK set of two private keys, one EC (`use` `enc`) and one RSA.
const RFC7517_A2: &str = r#"{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
          "use":"enc",
          "kid":"1"},

         {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }"#;

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn jwk(json: &str) -> Jwk {
    serde_json::from_str(json).unwrap()
}

/// Writes `json` as a private key set file, readable by its owner only.
fn write_key_set(path: &Path, json: &str) {
    fs::write(path, json).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn file_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn spec(key_type: KeyType, alg: JwsAlgorithm) -> KeySpec {
    KeySpec::new(key_type, alg)
}

// ---------------------------------------------------------------------------------------------
// Software store: specification vectors
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn rfc8037_key_file_reproduces_the_appendix_a_jws() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    // Without `kid` and `alg`: the id is the RFC 7638 thumbprint of A.3, the algorithm EdDSA.
    write_key_set(&path, &format!(r#"{{"keys":[{RFC8037_A1}]}}"#));
    let store = SoftwareKeyStore::open(&path).unwrap();
    let id = KeyId::new(RFC8037_THUMBPRINT);
    assert_eq!(store.key_ids(), std::slice::from_ref(&id));

    let public = store.public_jwk(&id).await.unwrap();
    assert!(!public.is_private());
    assert_eq!(public.x(), jwk(RFC8037_A1).x());
    assert_eq!(public.kid(), Some(RFC8037_THUMBPRINT));
    assert_eq!(public.alg(), Some("EdDSA"));
    assert_eq!(public.thumbprint_sha256().unwrap(), RFC8037_THUMBPRINT);

    // A.4: Ed25519 signatures are deterministic, so the store reproduces the RFC's bytes.
    let signature = store
        .sign(&id, JwsAlgorithm::EdDSA, RFC8037_SIGNING_INPUT.as_bytes())
        .await
        .unwrap();
    assert_eq!(b64(&signature), RFC8037_SIGNATURE);

    // The same through `KeySigner` and `encode_compact`: the whole A.5 JWS, byte for byte.
    let signer = KeySigner::new(&store, id.clone(), JwsAlgorithm::EdDSA)
        .await
        .unwrap();
    assert_eq!(signer.kid(), Some(RFC8037_THUMBPRINT));
    let token = encode_compact(
        &JwsHeader::new(JwsAlgorithm::EdDSA),
        b"Example of Ed25519 signing",
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(
        token,
        format!("{RFC8037_SIGNING_INPUT}.{RFC8037_SIGNATURE}")
    );
    CompactJws::decode(&token)
        .unwrap()
        .verify(&DefaultVerifier, &public)
        .unwrap();
}

#[tokio::test]
async fn rfc7515_a3_key_signs_es256_in_raw_form() {
    let dir = tempfile::tempdir().unwrap();
    let store = SoftwareKeyStore::create(dir.path().join("keys.json")).unwrap();
    let id = store
        .import(jwk(RFC7515_A3_KEY).with_kid("rfc7515-a3"))
        .unwrap();
    assert_eq!(id.as_str(), "rfc7515-a3");

    let public = store.public_jwk(&id).await.unwrap();
    assert_eq!(
        public.p256_public_bytes().unwrap(),
        jwk(RFC7515_A3_KEY).p256_public_bytes().unwrap()
    );
    assert_eq!(public.alg(), Some("ES256"));

    // ECDSA nonces are random in the RFC's example, so the bytes differ; the signature is 64
    // bytes of raw `r || s` and verifies with the A.3 public key.
    let data = RFC7515_A3_SIGNING_INPUT.as_bytes();
    let signature = store.sign(&id, JwsAlgorithm::ES256, data).await.unwrap();
    assert_eq!(signature.len(), 64);
    assert_ne!(signature[0], 0x30, "not DER");
    DefaultVerifier
        .verify(JwsAlgorithm::ES256, data, &signature, &public)
        .unwrap();
    // RFC 6979 deterministic nonces: signing twice gives the same signature.
    assert_eq!(
        store.sign(&id, JwsAlgorithm::ES256, data).await.unwrap(),
        signature
    );

    let err = store
        .sign(&id, JwsAlgorithm::EdDSA, data)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "key `rfc7515-a3` signs with ES256, not EdDSA"
    );
}

#[tokio::test]
async fn rfc7517_a2_key_set_is_checked_key_by_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");

    // The EC key is marked `use` `enc`, so it cannot sign.
    write_key_set(&path, RFC7517_A2);
    let err = SoftwareKeyStore::open(&path).unwrap_err();
    assert!(
        matches!(&err, KeyStoreError::InvalidKeySet { path: p, reason } if p == &path && reason == "`use` is not `sig`"),
        "{err}"
    );

    let set: Value = serde_json::from_str(RFC7517_A2).unwrap();
    let mut ec = set["keys"][0].clone();
    ec.as_object_mut().unwrap().remove("use");
    let rsa = set["keys"][1].clone();

    // The RSA key is refused: the crate never signs with RSA (ADR 0001).
    write_key_set(&path, &json!({"keys": [rsa]}).to_string());
    let err = SoftwareKeyStore::open(&path).unwrap_err();
    assert!(
        matches!(&err, KeyStoreError::InvalidKeySet { reason, .. } if reason.contains("RSA keys")),
        "{err}"
    );

    // The EC key without `use` is a usable ES256 key with id `1`.
    write_key_set(&path, &json!({"keys": [ec.clone()]}).to_string());
    let store = SoftwareKeyStore::open(&path).unwrap();
    let id = KeyId::new("1");
    assert_eq!(store.key_ids(), std::slice::from_ref(&id));
    let public = store.public_jwk(&id).await.unwrap();
    assert_eq!(public.x(), ec["x"].as_str());
    assert_eq!(public.y(), ec["y"].as_str());
    assert!(!public.is_private());
    let signature = store.sign(&id, JwsAlgorithm::ES256, b"data").await.unwrap();
    DefaultVerifier
        .verify(JwsAlgorithm::ES256, b"data", &signature, &public)
        .unwrap();

    // `use` `sig` and `key_ops` with `sign` are fine and kept in the file; an `alg` that does
    // not fit the key, an unknown `alg`, a `key_ops` without `sign` and a `use` that is not
    // `sig` are refused.
    let mut sig = ec.clone();
    sig["use"] = json!("sig");
    sig["key_ops"] = json!(["sign", "verify"]);
    write_key_set(&path, &json!({"keys": [sig]}).to_string());
    let store = SoftwareKeyStore::open(&path).unwrap();
    let public = store.public_jwk(&id).await.unwrap();
    assert_eq!(public.key_use(), Some("sig"));
    assert_eq!(
        public.key_ops(),
        Some(&["sign".to_owned(), "verify".to_owned()][..])
    );
    for (member, value, reason) in [
        (
            "alg",
            json!("EdDSA"),
            "`alg` EdDSA does not fit a ES256 key",
        ),
        ("alg", json!("HS256"), "unknown algorithm `HS256`"),
        ("key_ops", json!(["verify"]), "`key_ops` lacks `sign`"),
        ("use", json!("enc"), "`use` is not `sig`"),
    ] {
        let mut key = ec.clone();
        key[member] = value;
        write_key_set(&path, &json!({"keys": [key]}).to_string());
        let err = SoftwareKeyStore::open(&path).unwrap_err();
        assert!(
            matches!(&err, KeyStoreError::InvalidKeySet { reason: r, .. } if r == reason),
            "{member}: {err}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Software store: file handling
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn generated_keys_are_persisted_as_a_private_jwk_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let store = SoftwareKeyStore::create(&path).unwrap();
    assert_eq!(store.path(), path);
    assert_eq!(file_json(&path), json!({"keys": []}));

    let ed = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("ed"))
        .await
        .unwrap();
    let p256 = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    assert_eq!(ed.as_str(), "ed");
    let p256_public = store.public_jwk(&p256).await.unwrap();
    assert_eq!(p256.as_str(), p256_public.thumbprint_sha256().unwrap());
    assert_eq!(store.key_ids(), [ed.clone(), p256.clone()]);

    // The file is an RFC 7517 JWK set of private keys with `kid` and `alg`.
    let file = file_json(&path);
    let keys = file["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["kid"], "ed");
    assert_eq!(keys[0]["alg"], "EdDSA");
    assert!(keys[0]["d"].is_string() && keys[0]["x"].is_string());
    assert_eq!(keys[1]["kty"], "EC");
    assert_eq!(keys[1]["crv"], "P-256");
    assert_eq!(keys[1]["kid"], p256.as_str());
    assert_eq!(keys[1]["alg"], "ES256");
    assert!(keys[1]["d"].is_string() && keys[1]["x"].is_string() && keys[1]["y"].is_string());
    assert!(
        fs::read_to_string(&path).unwrap().ends_with("}\n"),
        "pretty-printed, newline-terminated"
    );

    // No temporary file is left behind.
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, ["keys.json"]);

    // Reopening gives the same keys and public JWKs; signatures cross-verify.
    let reopened = SoftwareKeyStore::open(&path).unwrap();
    assert_eq!(reopened.key_ids(), [ed.clone(), p256.clone()]);
    assert_eq!(reopened.public_jwk(&p256).await.unwrap(), p256_public);
    let signature = reopened.sign(&ed, JwsAlgorithm::EdDSA, b"x").await.unwrap();
    DefaultVerifier
        .verify(
            JwsAlgorithm::EdDSA,
            b"x",
            &signature,
            &store.public_jwk(&ed).await.unwrap(),
        )
        .unwrap();

    // Delete removes the key from the file.
    store.delete(&ed).await.unwrap();
    assert!(!store.exists(&ed).await.unwrap());
    assert_eq!(file_json(&path)["keys"].as_array().unwrap().len(), 1);
    assert_eq!(
        SoftwareKeyStore::open(&path).unwrap().key_ids(),
        std::slice::from_ref(&p256)
    );
    assert!(matches!(
        store.delete(&ed).await,
        Err(KeyStoreError::NotFound(id)) if id == ed
    ));

    // A label that is taken is refused, and the file is untouched.
    let err = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label(p256.as_str()))
        .await
        .unwrap_err();
    assert!(matches!(err, KeyStoreError::AlreadyExists(id) if id == p256));
    assert_eq!(file_json(&path)["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn other_members_of_the_set_and_of_the_keys_survive_a_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let mut key: Value = serde_json::from_str(RFC8037_A1).unwrap();
    key["kid"] = json!("ed");
    key["x5t"] = json!("not-really");
    write_key_set(
        &path,
        &json!({"keys": [key], "comment": "fixture"}).to_string(),
    );
    let store = SoftwareKeyStore::open(&path).unwrap();
    store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256).with_label("p256"))
        .await
        .unwrap();
    let file = file_json(&path);
    assert_eq!(file["comment"], "fixture");
    assert_eq!(file["keys"][0]["x5t"], "not-really");
    assert_eq!(file["keys"][0]["d"], key["d"]);
    assert_eq!(
        file["keys"][0]["alg"], "EdDSA",
        "the derived algorithm is written out"
    );
    assert_eq!(file["keys"][1]["kid"], "p256");
}

#[test]
fn opening_handles_missing_and_broken_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");

    let err = SoftwareKeyStore::open(&path).unwrap_err();
    assert!(
        matches!(&err, KeyStoreError::Io { path: p, source } if p == &path && source.kind() == std::io::ErrorKind::NotFound),
        "{err}"
    );
    assert!(
        err.to_string()
            .starts_with(&format!("key store file `{}`: ", path.display()))
    );

    // `create_if_missing` makes an empty store; `create` on an existing file fails.
    let store = SoftwareKeyStore::open_with(
        &path,
        SoftwareKeyStoreOptions::new().create_if_missing(true),
    )
    .unwrap();
    assert!(store.key_ids().is_empty());
    assert_eq!(file_json(&path), json!({"keys": []}));
    let err = SoftwareKeyStore::create(&path).unwrap_err();
    assert!(
        matches!(&err, KeyStoreError::Io { source, .. } if source.kind() == std::io::ErrorKind::AlreadyExists)
    );

    for (content, reason) in [
        ("not json", "expected"),
        (r#"{"kty":"OKP"}"#, "missing field `keys`"),
        (
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#,
            "missing private member `d`",
        ),
        (
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}"#,
            "public members `x`/`y` do not match the private key",
        ),
        (
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kid":"a"},{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","kid":"a"}]}"#,
            "key `a` is defined twice",
        ),
        (
            r#"{"keys":[{"kty":"oct","k":"AQAB"}]}"#,
            "missing private member `d`",
        ),
        (
            r#"{"keys":[{"kty":"EC","crv":"P-384","x":"AA","y":"AA","d":"AA"}]}"#,
            "unsupported key type: `kty` \"EC\" with `crv` Some(\"P-384\")",
        ),
        (
            r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"!!"}]}"#,
            "`d` is not valid base64url",
        ),
    ] {
        write_key_set(&path, content);
        let err = SoftwareKeyStore::open(&path).unwrap_err();
        assert!(
            matches!(&err, KeyStoreError::InvalidKeySet { path: p, reason: r } if p == &path && r.contains(reason)),
            "{content}: {err}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn files_readable_by_others_are_refused_unless_allowed() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let store = SoftwareKeyStore::create(&path).unwrap();
    assert_eq!(mode(&path), 0o600, "created private");
    store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await
        .unwrap();
    assert_eq!(mode(&path), 0o600, "rewritten private");

    for insecure in [0o640, 0o604, 0o644, 0o660, 0o666] {
        fs::set_permissions(&path, fs::Permissions::from_mode(insecure)).unwrap();
        let err = SoftwareKeyStore::open(&path).unwrap_err();
        assert!(
            matches!(&err, KeyStoreError::InsecurePermissions { path: p, mode } if p == &path && *mode == insecure),
            "{insecure:o}: {err}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "key store file `{}` has mode {insecure:04o}; make it private (0600) or opt in with `allow_insecure_permissions`",
                path.display()
            )
        );
        SoftwareKeyStore::open_with(
            &path,
            SoftwareKeyStoreOptions::new().allow_insecure_permissions(true),
        )
        .unwrap();
    }
    for secure in [0o600, 0o400, 0o700] {
        fs::set_permissions(&path, fs::Permissions::from_mode(secure)).unwrap();
        SoftwareKeyStore::open(&path).unwrap();
    }
}

#[tokio::test]
async fn a_failed_write_leaves_the_store_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    let store = SoftwareKeyStore::create(&path).unwrap();
    let key = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("k"))
        .await
        .unwrap();
    // Make the directory unwritable (as root, which CI containers may be, this is a no-op, so
    // the test only asserts consistency between memory and file in either case).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    }
    let generated = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256).with_label("p"))
        .await;
    let deleted = store.delete(&key).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let on_disk: Vec<String> = file_json(&path)["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap().to_owned())
        .collect();
    let in_memory: Vec<String> = store.key_ids().iter().map(ToString::to_string).collect();
    assert_eq!(
        on_disk, in_memory,
        "memory and file agree after {generated:?} / {deleted:?}"
    );
    if generated.is_err() {
        assert!(matches!(generated, Err(KeyStoreError::Io { .. })));
        assert!(matches!(deleted, Err(KeyStoreError::Io { .. })));
        assert_eq!(in_memory, ["k"]);
    }
}

// ---------------------------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn seeded_in_memory_stores_generate_the_same_keys() {
    let specs = [
        spec(KeyType::Ed25519, JwsAlgorithm::EdDSA),
        spec(KeyType::P256, JwsAlgorithm::ES256),
        #[cfg(feature = "secp256k1")]
        spec(KeyType::Secp256k1, JwsAlgorithm::ES256K),
    ];
    let mut runs = Vec::new();
    for seed in [[1u8; 32], [1u8; 32], [2u8; 32]] {
        let store = InMemoryKeyStore::with_seed(seed);
        assert!(store.is_seeded());
        let mut keys = Vec::new();
        for spec in &specs {
            let id = store.generate(spec.clone()).await.unwrap();
            let public = store.public_jwk(&id).await.unwrap();
            assert_eq!(id.as_str(), public.thumbprint_sha256().unwrap());
            let signature = store.sign(&id, spec.alg, b"fixture").await.unwrap();
            keys.push((id, public, signature));
        }
        assert_eq!(
            store.key_ids(),
            keys.iter().map(|(id, ..)| id.clone()).collect::<Vec<_>>()
        );
        runs.push(keys);
    }
    assert_eq!(runs[0], runs[1], "same seed, same keys and signatures");
    for (i, (same, other)) in runs[0].iter().zip(&runs[2]).enumerate() {
        assert_ne!(same.0, other.0, "different seed, different key {i}");
    }

    let unseeded = InMemoryKeyStore::new();
    assert!(!unseeded.is_seeded());
    let a = unseeded.generate(specs[0].clone()).await.unwrap();
    let b = unseeded.generate(specs[0].clone()).await.unwrap();
    assert_ne!(a, b);
    assert_ne!(a, runs[0][0].0);

    // Debug shows ids, never material.
    let debug = format!("{unseeded:?}");
    assert!(
        debug.contains(a.as_str()) && !debug.contains("\"d\""),
        "{debug}"
    );
}

#[tokio::test]
async fn in_memory_store_labels_rejects_and_deletes() {
    let store = InMemoryKeyStore::default();
    let id = store
        .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("issuer"))
        .await
        .unwrap();
    assert_eq!(id.as_str(), "issuer");
    assert!(matches!(
        store.generate(spec(KeyType::P256, JwsAlgorithm::ES256).with_label("issuer")).await,
        Err(KeyStoreError::AlreadyExists(taken)) if taken == id
    ));
    assert!(matches!(
        store
            .generate(spec(KeyType::Ed25519, JwsAlgorithm::ES256))
            .await,
        Err(KeyStoreError::InvalidSpec {
            key_type: KeyType::Ed25519,
            alg: JwsAlgorithm::ES256
        })
    ));
    assert!(matches!(
        store
            .generate(spec(KeyType::Rsa2048, JwsAlgorithm::RS256))
            .await,
        Err(KeyStoreError::UnsupportedKeyType(KeyType::Rsa2048))
    ));
    #[cfg(not(feature = "secp256k1"))]
    assert!(matches!(
        store
            .generate(spec(KeyType::Secp256k1, JwsAlgorithm::ES256K))
            .await,
        Err(KeyStoreError::UnsupportedKeyType(KeyType::Secp256k1))
    ));
    assert_eq!(
        store.capabilities(),
        KeyStoreCapabilities::new([
            JwsAlgorithm::EdDSA,
            JwsAlgorithm::ES256,
            #[cfg(feature = "secp256k1")]
            JwsAlgorithm::ES256K,
        ])
        .with_generate()
        .with_delete()
    );

    store.delete(&id).await.unwrap();
    assert!(store.key_ids().is_empty());
    let err = store.public_jwk(&id).await.unwrap_err();
    assert_eq!(err.to_string(), "key `issuer` not found");
}

// ---------------------------------------------------------------------------------------------
// KeySigner
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn key_signer_checks_the_algorithm_and_can_override_the_kid() {
    let store = InMemoryKeyStore::with_seed([3; 32]);
    let id = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256).with_label("k"))
        .await
        .unwrap();

    let err = KeySigner::new(&store, id.clone(), JwsAlgorithm::EdDSA)
        .await
        .unwrap_err();
    assert!(
        matches!(err, KeyStoreError::AlgorithmMismatch { ref key, key_alg: JwsAlgorithm::ES256, requested: JwsAlgorithm::EdDSA } if *key == id),
        "{err}"
    );
    let err = KeySigner::new(&store, id.clone(), JwsAlgorithm::RS256)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        KeyStoreError::UnsupportedAlgorithm(JwsAlgorithm::RS256)
    ));
    assert_eq!(err.to_string(), "key store does not support RS256");

    let signer = KeySigner::new(&store, id.clone(), JwsAlgorithm::ES256)
        .await
        .unwrap()
        .with_kid("did:example:123#k");
    assert_eq!(signer.alg(), JwsAlgorithm::ES256);
    assert_eq!(signer.kid(), Some("did:example:123#k"));
    assert_eq!(signer.key_id(), &id);
    assert_eq!(signer.public_jwk(), &store.public_jwk(&id).await.unwrap());
    assert!(signer.store().exists(&id).await.unwrap());
    let debug = format!("{signer:?}");
    assert!(
        debug.contains("did:example:123#k") && !debug.contains("\"d\""),
        "{debug}"
    );

    let header = JwsHeader::new(JwsAlgorithm::ES256).with_kid("did:example:123#k");
    let token = encode_compact(&header, b"{}", &signer).await.unwrap();
    let jws = CompactJws::decode(&token).unwrap();
    assert_eq!(jws.kid(), Some("did:example:123#k"));
    jws.verify(&DefaultVerifier, signer.public_jwk()).unwrap();

    // A signer over a deleted key reports the store's error through `SignError`.
    store.delete(&id).await.unwrap();
    let err = signer.sign(b"x").await.unwrap_err();
    assert_eq!(err.to_string(), "key `k` not found");
    assert!(err.inner().downcast_ref::<KeyStoreError>().is_some());
}

/// A store that counts the `public_jwk` and `sign` calls it forwards.
struct Counting<S> {
    inner: S,
    public_jwk: AtomicUsize,
    sign: AtomicUsize,
}

impl<S> Counting<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            public_jwk: AtomicUsize::new(0),
            sign: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> (usize, usize) {
        (
            self.public_jwk.load(Ordering::SeqCst),
            self.sign.load(Ordering::SeqCst),
        )
    }
}

#[async_trait::async_trait]
impl<S: KeyStore> KeyStore for Counting<S> {
    fn capabilities(&self) -> KeyStoreCapabilities {
        self.inner.capabilities()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.public_jwk.fetch_add(1, Ordering::SeqCst);
        self.inner.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.sign.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(key, alg, data).await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.inner.exists(key).await
    }
}

#[tokio::test]
async fn key_signer_over_an_arc_moves_into_a_spawned_task() {
    let store: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::with_seed([4; 32]));
    let id = store
        .generate(spec(KeyType::P256, JwsAlgorithm::ES256))
        .await
        .unwrap();
    let signer = KeySigner::new(Arc::clone(&store), id, JwsAlgorithm::ES256)
        .await
        .unwrap();
    let public = signer.public_jwk().clone();

    let token = tokio::spawn(async move {
        encode_compact(&JwsHeader::new(JwsAlgorithm::ES256), b"{}", &signer).await
    })
    .await
    .unwrap()
    .unwrap();
    CompactJws::decode(&token)
        .unwrap()
        .verify(&DefaultVerifier, &public)
        .unwrap();
}

#[tokio::test]
async fn key_signer_from_a_known_public_jwk_skips_the_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.json");
    write_key_set(&path, &format!(r#"{{"keys":[{RFC8037_A1}]}}"#));
    let store = Arc::new(Counting::new(SoftwareKeyStore::open(&path).unwrap()));
    let id = KeyId::new(RFC8037_THUMBPRINT);

    // RFC 8037 A.2, the public key of A.1.
    let public = jwk(RFC8037_A1).public();
    let signer = KeySigner::from_public_jwk(
        Arc::clone(&store),
        id.clone(),
        JwsAlgorithm::EdDSA,
        public.clone(),
    )
    .unwrap();
    assert_eq!(store.calls(), (0, 0));
    assert_eq!(signer.public_jwk(), &public);
    assert_eq!(signer.kid(), Some(RFC8037_THUMBPRINT));

    // RFC 8037 A.5, byte for byte, with one call to the store: the signature.
    let token = encode_compact(
        &JwsHeader::new(JwsAlgorithm::EdDSA),
        b"Example of Ed25519 signing",
        &signer,
    )
    .await
    .unwrap();
    assert_eq!(
        token,
        format!("{RFC8037_SIGNING_INPUT}.{RFC8037_SIGNATURE}")
    );
    CompactJws::decode(&token)
        .unwrap()
        .verify(&DefaultVerifier, &public)
        .unwrap();
    assert_eq!(store.calls(), (0, 1));

    // A clone signs through the same store.
    let clone = signer.clone().with_kid("did:example:123#k");
    assert_eq!(clone.kid(), Some("did:example:123#k"));
    clone.sign(b"x").await.unwrap();
    assert_eq!(store.calls(), (0, 2));
    assert!(Arc::ptr_eq(signer.store(), clone.store()));

    // `new` asks the store for the public key; the result is the same signer.
    let fetched = KeySigner::new(&*store, id, JwsAlgorithm::EdDSA)
        .await
        .unwrap();
    assert_eq!(store.calls(), (1, 2));
    assert_eq!(fetched.public_jwk().x(), public.x());
}

#[tokio::test]
async fn key_signer_from_a_known_public_jwk_checks_the_key() {
    let store = InMemoryKeyStore::with_seed([5; 32]);
    let id = KeyId::new("k");
    let ed25519 = jwk(RFC8037_A1).public();

    // The store does not sign with the algorithm.
    let err = KeySigner::from_public_jwk(&store, id.clone(), JwsAlgorithm::RS256, ed25519.clone())
        .unwrap_err();
    assert!(
        matches!(
            err,
            KeyStoreError::UnsupportedAlgorithm(JwsAlgorithm::RS256)
        ),
        "{err}"
    );

    // The JWK names another algorithm.
    let err = KeySigner::from_public_jwk(
        &store,
        id.clone(),
        JwsAlgorithm::EdDSA,
        ed25519.clone().with_alg("ES256"),
    )
    .unwrap_err();
    assert!(
        matches!(err, KeyStoreError::AlgorithmMismatch { ref key, key_alg: JwsAlgorithm::ES256, requested: JwsAlgorithm::EdDSA } if *key == id),
        "{err}"
    );

    // The JWK carries the private key (RFC 8037 A.1).
    let err = KeySigner::from_public_jwk(&store, id.clone(), JwsAlgorithm::EdDSA, jwk(RFC8037_A1))
        .unwrap_err();
    assert!(matches!(err, KeyStoreError::InvalidKey { .. }), "{err}");
    assert_eq!(
        err.to_string(),
        "key `k` is unusable: the given public JWK carries private parameters"
    );

    // The JWK is not a key for the algorithm: P-256 (RFC 7515 A.3) for EdDSA, Ed25519 for ES256.
    let p256 = jwk(RFC7515_A3_KEY).public();
    let err = KeySigner::from_public_jwk(&store, id.clone(), JwsAlgorithm::EdDSA, p256.clone())
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "key `k` is unusable: the given public JWK (`kty` EC, `crv` P-256) is not a key for EdDSA"
    );
    let err =
        KeySigner::from_public_jwk(&store, id.clone(), JwsAlgorithm::ES256, ed25519).unwrap_err();
    assert!(matches!(err, KeyStoreError::InvalidKey { .. }), "{err}");

    // A fitting key is accepted, with or without `alg`.
    KeySigner::from_public_jwk(&store, id.clone(), JwsAlgorithm::ES256, p256.clone()).unwrap();
    KeySigner::from_public_jwk(&store, id, JwsAlgorithm::ES256, p256.with_alg("ES256")).unwrap();
}

/// A store that claims every algorithm and is asked nothing else: `from_public_jwk` consults
/// only its capabilities, so the key-type check is reached for every algorithm.
struct EveryAlgorithm;

#[async_trait::async_trait]
impl KeyStore for EveryAlgorithm {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new([
            JwsAlgorithm::EdDSA,
            JwsAlgorithm::ES256,
            JwsAlgorithm::ES256K,
            JwsAlgorithm::ES384,
            JwsAlgorithm::RS256,
            JwsAlgorithm::PS256,
        ])
    }

    async fn public_jwk(&self, _: &KeyId) -> Result<Jwk, KeyStoreError> {
        unreachable!("from_public_jwk does not ask for the public key")
    }

    async fn sign(&self, _: &KeyId, _: JwsAlgorithm, _: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        unreachable!("from_public_jwk does not sign")
    }

    async fn exists(&self, _: &KeyId) -> Result<bool, KeyStoreError> {
        unreachable!("from_public_jwk does not look the key up")
    }
}

#[test]
fn key_signer_from_a_known_public_jwk_needs_both_kty_and_crv() {
    // DID Core §A.2, Example 20: secp256k1, P-384 and P-521 keys.
    let secp256k1 = jwk(r#"{"kty":"EC","crv":"secp256k1",
        "x":"Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8",
        "y":"i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk"}"#);
    let p384 = jwk(r#"{"kty":"EC","crv":"P-384",
        "x":"VUZKSlUwMGdpSXplekRwODhzX2N4U1BYdHVYWUZsaXVDR25kZ1U0UXA4bDkxeHpE",
        "y":"jq4QoAHKiIzezDp88s_cxSPXtuXYFliuCGndgU4Qp8l91xzD1spCmFIzQgVjqvcP"}"#);
    let p521 = jwk(r#"{"kty":"EC","crv":"P-521",
        "x":"VTI5c1lYSmZWMmx1WkhNZ0dQTXhaYkhtSnBEU3UtSXZwdUtpZ0VOMnB6Z1d0U28tLVJ3ZC1uNzhuclduWnplRGMx",
        "y":"UW5WNVgwSnBkR052YVc0Z1VqY1B6LVpoZWNaRnliT3FMSUpqVk9sTEVUSDd1UGx5RzBnRW9NV25JWlhoUVZ5cFB5"}"#);
    // The did:jwk specification's X25519 example: an OKP key that is not Ed25519.
    let x25519 =
        jwk(r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#);
    let ed25519 = jwk(RFC8037_A1).public();
    let p256 = jwk(RFC7515_A3_KEY).public();
    // The RSA key of RFC 7517 A.2 without its `alg`, which names RS256.
    let keys: Value = serde_json::from_str(RFC7517_A2).unwrap();
    let rsa: Jwk = serde_json::from_value(
        json!({ "kty": "RSA", "n": keys["keys"][1]["n"], "e": keys["keys"][1]["e"] }),
    )
    .unwrap();

    let fits = |alg, public: &Jwk| {
        KeySigner::from_public_jwk(EveryAlgorithm, KeyId::new("k"), alg, public.clone()).is_ok()
    };
    for (alg, fitting, others) in [
        (JwsAlgorithm::EdDSA, &ed25519, [&x25519, &p256, &rsa]),
        (JwsAlgorithm::ES256, &p256, [&p521, &secp256k1, &ed25519]),
        (JwsAlgorithm::ES256K, &secp256k1, [&p256, &p384, &ed25519]),
        (JwsAlgorithm::ES384, &p384, [&p521, &p256, &x25519]),
        (JwsAlgorithm::RS256, &rsa, [&p256, &ed25519, &x25519]),
        (JwsAlgorithm::PS256, &rsa, [&p384, &secp256k1, &x25519]),
    ] {
        assert!(fits(alg, fitting), "{alg} with a {}", fitting.kty());
        for other in others {
            // Same `kty` and another curve, or another `kty` altogether.
            assert!(
                !fits(alg, other),
                "{alg} with `kty` {} and `crv` {:?}",
                other.kty(),
                other.crv()
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_suite_passes_for_the_shipped_backends() {
    testsuite::run(&InMemoryKeyStore::new()).await;
    testsuite::run(&InMemoryKeyStore::with_seed([9; 32])).await;
    let dir = tempfile::tempdir().unwrap();
    let software = SoftwareKeyStore::create(dir.path().join("keys.json")).unwrap();
    testsuite::run(&software).await;
    assert!(
        software.key_ids().is_empty(),
        "the suite deletes what it generated"
    );

    // Through the forwarding impls.
    let boxed: Box<dyn KeyStore> = Box::new(InMemoryKeyStore::new());
    testsuite::run(&boxed).await;
    let shared = Arc::new(InMemoryKeyStore::new());
    testsuite::run(&shared).await;
    testsuite::run(&&*shared).await;
}

/// A store with keys provisioned out of band, as an HSM or a KMS: signs, but neither generates
/// nor deletes, and says so.
struct Provisioned(InMemoryKeyStore);

#[async_trait::async_trait]
impl KeyStore for Provisioned {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new(self.0.capabilities().algorithms).remote()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.0.sign(key, alg, data).await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }
}

async fn provisioned() -> (Provisioned, Vec<(KeyId, JwsAlgorithm)>) {
    let inner = InMemoryKeyStore::with_seed([4; 32]);
    let mut keys = Vec::new();
    for alg in inner.capabilities().algorithms {
        let key_type = match alg {
            JwsAlgorithm::EdDSA => KeyType::Ed25519,
            JwsAlgorithm::ES256 => KeyType::P256,
            _ => KeyType::Secp256k1,
        };
        keys.push((inner.generate(spec(key_type, alg)).await.unwrap(), alg));
    }
    (Provisioned(inner), keys)
}

#[tokio::test]
async fn the_suite_runs_against_provisioned_keys() {
    let (store, keys) = provisioned().await;
    let unknown = KeyId::new("nope");
    assert!(matches!(
        store
            .generate(spec(KeyType::Ed25519, JwsAlgorithm::EdDSA))
            .await,
        Err(KeyStoreError::Unsupported("generate"))
    ));
    assert!(matches!(
        store.delete(&unknown).await,
        Err(KeyStoreError::Unsupported("delete"))
    ));
    assert_eq!(
        store.delete(&unknown).await.unwrap_err().to_string(),
        "key store does not support `delete`"
    );
    testsuite::run_with_keys(&store, &keys).await;
}

#[tokio::test]
#[should_panic(expected = "needs a store that generates keys")]
async fn the_suite_refuses_run_for_a_store_that_cannot_generate() {
    let (store, _) = provisioned().await;
    testsuite::run(&store).await;
}

#[tokio::test]
#[should_panic(expected = "no key for advertised algorithm ES256")]
async fn the_suite_wants_a_key_per_advertised_algorithm() {
    let (store, keys) = provisioned().await;
    testsuite::run_with_keys(&store, &keys[..1]).await;
}

/// A store whose capabilities lie: it deletes although it says it does not.
struct Liar(InMemoryKeyStore);

#[async_trait::async_trait]
impl KeyStore for Liar {
    fn capabilities(&self) -> KeyStoreCapabilities {
        KeyStoreCapabilities::new(self.0.capabilities().algorithms).with_generate()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        self.0.sign(key, alg, data).await
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        self.0.generate(spec).await
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        self.0.delete(key).await
    }
}

#[tokio::test]
#[should_panic(expected = "must return Unsupported(\"delete\")")]
async fn the_suite_catches_untruthful_capabilities() {
    testsuite::run(&Liar(InMemoryKeyStore::new())).await;
}

/// A store that advertises an algorithm it signs wrongly: EdDSA signatures come back truncated.
struct Truncating(InMemoryKeyStore);

#[async_trait::async_trait]
impl KeyStore for Truncating {
    fn capabilities(&self) -> KeyStoreCapabilities {
        self.0.capabilities()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let mut signature = self.0.sign(key, alg, data).await?;
        signature.truncate(63);
        Ok(signature)
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        self.0.generate(spec).await
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        self.0.delete(key).await
    }
}

#[tokio::test]
#[should_panic(expected = "must be 64 bytes")]
async fn the_suite_checks_the_signature_form() {
    testsuite::run(&Truncating(InMemoryKeyStore::new())).await;
}

/// A store whose ES256K signatures carry `n - s`, the upper of the two valid `s` values.
#[cfg(feature = "secp256k1")]
struct HighS(InMemoryKeyStore);

/// The order of the secp256k1 group (SEC 2 §2.4.1).
#[cfg(feature = "secp256k1")]
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

#[cfg(feature = "secp256k1")]
#[async_trait::async_trait]
impl KeyStore for HighS {
    fn capabilities(&self) -> KeyStoreCapabilities {
        self.0.capabilities()
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> {
        self.0.public_jwk(key).await
    }

    async fn sign(
        &self,
        key: &KeyId,
        alg: JwsAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, KeyStoreError> {
        let mut signature = self.0.sign(key, alg, data).await?;
        if alg == JwsAlgorithm::ES256K {
            // s := n - s, big-endian with borrow.
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let mut digit = i16::from(SECP256K1_N[i]) - i16::from(signature[32 + i]) - borrow;
                borrow = i16::from(digit < 0);
                digit += 256 * borrow;
                signature[32 + i] = u8::try_from(digit).unwrap();
            }
        }
        Ok(signature)
    }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> {
        self.0.exists(key).await
    }

    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> {
        self.0.generate(spec).await
    }

    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> {
        self.0.delete(key).await
    }
}

#[cfg(feature = "secp256k1")]
#[tokio::test]
#[should_panic(expected = "has `s` in the upper half of the group order")]
async fn the_suite_checks_that_es256k_signatures_have_a_low_s() {
    testsuite::run(&HighS(InMemoryKeyStore::new())).await;
}

// ---------------------------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------------------------

#[test]
fn key_id_spec_and_capabilities_basics() {
    let id: KeyId = "a".into();
    assert_eq!(id, KeyId::from("a".to_owned()));
    assert_eq!(String::from(id.clone()), "a");
    assert_eq!(id.as_ref(), "a");
    assert_eq!(format!("{id:?}"), "\"a\"");
    assert_eq!(
        serde_json::from_str::<KeyId>("\"b\"").unwrap().as_str(),
        "b"
    );

    for (key_type, alg, ok) in [
        (KeyType::Ed25519, JwsAlgorithm::EdDSA, true),
        (KeyType::Ed25519, JwsAlgorithm::ES256, false),
        (KeyType::P256, JwsAlgorithm::ES256, true),
        (KeyType::P256, JwsAlgorithm::ES384, false),
        (KeyType::Secp256k1, JwsAlgorithm::ES256K, true),
        (KeyType::Secp256k1, JwsAlgorithm::ES256, false),
        (KeyType::Rsa2048, JwsAlgorithm::RS256, true),
        (KeyType::Rsa4096, JwsAlgorithm::PS256, true),
        (KeyType::Rsa4096, JwsAlgorithm::EdDSA, false),
    ] {
        let result = KeySpec::new(key_type, alg).validate();
        assert_eq!(result.is_ok(), ok, "{key_type:?} {alg}: {result:?}");
        if !ok {
            assert_eq!(
                result.unwrap_err().to_string(),
                format!("{alg} cannot be used with {key_type:?} keys")
            );
        }
    }
    let spec = KeySpec::new(KeyType::P256, JwsAlgorithm::ES256).with_label("x");
    assert_eq!(spec.label.as_deref(), Some("x"));

    let caps = KeyStoreCapabilities::new([
        JwsAlgorithm::ES256,
        JwsAlgorithm::ES256,
        JwsAlgorithm::EdDSA,
    ]);
    assert_eq!(caps.algorithms, [JwsAlgorithm::ES256, JwsAlgorithm::EdDSA]);
    assert!(!caps.can_generate && !caps.can_delete && !caps.remote);
    let caps = caps.with_generate().with_delete().remote();
    assert!(caps.can_generate && caps.can_delete && caps.remote);

    let err = KeyStoreError::backend(std::io::Error::other("hsm offline"));
    assert_eq!(err.to_string(), "key store backend error: hsm offline");
    assert!(std::error::Error::source(&err).is_some());
}
