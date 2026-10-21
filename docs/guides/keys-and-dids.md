# Keys and DIDs

Create a key in a key store, derive a DID for it, and resolve that DID back to its document and
public key. Every other guide starts here.

## What you need

```sh
cargo add identity-kit --features in-memory
cargo add tokio --features macros,rt-multi-thread
```

`in-memory` enables `InMemoryKeyStore`, which keeps keys in process memory and is meant for tests
and development. `did-key` and `did-jwk` are on by default.

## Steps

1. **Create a key store and generate a key.** A key store holds private keys behind an opaque
   `KeyId`; the private material never leaves it. Every key has exactly one algorithm.
2. **Read the public key.** `public_jwk` returns the public half as a JWK; this is what goes
   into a DID.
3. **Derive a DID.** `did:key` and `did:jwk` encode the public key in the DID itself, so they
   need no registry or hosting. `did:key` names its one verification method after the
   method-specific id; `did:jwk` names it `#0`.
4. **Resolve.** A `Resolver` dispatches on the DID method to whatever method resolvers were
   registered. `resolve_public_key` dereferences a verification method URL to its JWK and checks
   that the method is listed under the given verification relationship.

```rust
use identity_kit::did::VerificationRelationship;
use identity_kit::jose::{JwsAlgorithm, KeyType};
use identity_kit::keys::{InMemoryKeyStore, KeySpec, KeyStore};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::Resolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A key store with one Ed25519 key, labelled so it can be found again.
    let store = InMemoryKeyStore::new();
    let key = store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA).with_label("issuer"))
        .await?;
    assert_eq!(key.as_str(), "issuer");

    // 2. Its public key, as a JWK. Private parameters never come out of the store.
    let public = store.public_jwk(&key).await?;
    assert!(!public.is_private());

    // 3. Two DIDs for the same key, and the URL of each one's verification method.
    let did_key = DidKey::did(&public)?;
    let did_key_vm = did_key.join(&format!("#{}", did_key.method_specific_id()))?;
    let did_jwk = DidJwk::did(&public)?;
    let did_jwk_vm = did_jwk.join("#0")?;
    assert!(did_key.as_str().starts_with("did:key:z6Mk"));
    assert!(did_jwk.as_str().starts_with("did:jwk:"));

    // 4. Resolve both DIDs through one resolver.
    let resolver = Resolver::builder()
        .with(DidKey::default())
        .with(DidJwk)
        .build();

    let document = resolver.resolve_document(&did_key).await?;
    assert_eq!(document.id, did_key);

    for vm in [&did_key_vm, &did_jwk_vm] {
        let resolved = resolver
            .resolve_public_key(vm, Some(VerificationRelationship::AssertionMethod))
            .await?;
        assert_eq!(resolved.thumbprint_sha256()?, public.thumbprint_sha256()?);
    }
    Ok(())
}
```

## Variations

- **Keys on disk.** `SoftwareKeyStore` (feature `software`, on by default) keeps private keys in
  a JWK set file that it permission-checks and rewrites atomically:
  `SoftwareKeyStore::create(path)?` for a new file, `SoftwareKeyStore::open(path)?` for an
  existing one. The calls on it are the same as above.
- **An HSM or a cloud KMS.** `Pkcs11KeyStore` (feature `pkcs11`) signs in a PKCS#11 module. A
  cloud KMS backend implements the `KeyStore` trait in its own crate; see
  [`key-stores.md`](../key-stores.md) for the contract.
- **Other algorithms.** `KeyType::P256` with `JwsAlgorithm::ES256`, or `KeyType::Secp256k1` with
  `JwsAlgorithm::ES256K` (feature `secp256k1`, on by default). `store.capabilities()` lists what
  a store signs with.
- **`did:web`.** The document lives on a web server, so the DID does not change when keys
  rotate. Register `DidWeb` with the resolver; it fetches over HTTPS with a hardened client
  (feature `reqwest`).

Next: [sign and verify a JWS](sign-and-verify.md).
