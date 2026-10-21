# Sign and verify a JWS

Sign a payload with a key from a key store under a DID, then verify it the way a relying party
does: find the key through the `kid` in the header, resolve it, and check the signature.

## What you need

```sh
cargo add identity-kit --features in-memory
cargo add tokio --features macros,rt-multi-thread
cargo add serde_json
```

## Steps

1. **Set up the signer's key and DID**, as in [Keys and DIDs](keys-and-dids.md).
2. **Wrap the key in a `KeySigner`.** It implements `jose::Signer`: it fetches the public key
   once, signs through the store, and returns signatures in their JWS form. Its `kid` is the DID
   URL of the verification method, so a verifier knows where to find the key.
3. **Sign.** `encode_compact` builds the compact JWS `header.payload.signature`. The header's
   `alg` must match the signer's.
4. **Verify.** Decode the token without trusting it, resolve the `kid` to a public key under the
   relationship that fits the use (`assertionMethod` for statements an issuer makes,
   `authentication` for proving control), and verify the signature with `DefaultVerifier`.

```rust
use identity_kit::did::{DidUrl, VerificationRelationship};
use identity_kit::jose::{
    CompactJws, DefaultVerifier, JwsAlgorithm, JwsHeader, KeyType, Signer, encode_compact,
};
use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
use identity_kit::methods::DidKey;
use identity_kit::resolver::Resolver;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. A P-256 key and its did:key.
    let store = InMemoryKeyStore::new();
    let key = store
        .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256))
        .await?;
    let did = DidKey::did(&store.public_jwk(&key).await?)?;
    let kid = did.join(&format!("#{}", did.method_specific_id()))?;

    // 2. A signer over the store, announcing the verification method as its `kid`.
    let signer = KeySigner::new(&store, key, JwsAlgorithm::ES256)
        .await?
        .with_kid(kid.as_str());
    assert_eq!(signer.kid(), Some(kid.as_str()));

    // 3. Sign a JSON payload.
    let header = JwsHeader::new(JwsAlgorithm::ES256)
        .with_typ("JWT")
        .with_kid(kid.as_str());
    let payload = json!({ "iss": did.as_str(), "msg": "hello" });
    let token = encode_compact(&header, &serde_json::to_vec(&payload)?, &signer).await?;

    // 4. The verifier: decode, find the key through the `kid`, verify.
    let jws = CompactJws::decode(&token)?;
    let kid = DidUrl::parse(jws.kid().ok_or("no kid")?)?;
    let resolver = Resolver::builder().with(DidKey::default()).build();
    let key = resolver
        .resolve_public_key(&kid, Some(VerificationRelationship::AssertionMethod))
        .await?;
    jws.verify(&DefaultVerifier, &key)?;

    // Only now is the payload trusted.
    let verified: serde_json::Value = serde_json::from_slice(jws.payload())?;
    assert_eq!(verified["msg"], "hello");

    // A tampered payload fails verification.
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[1] = "eyJtc2ciOiJnb29kYnllIn0"; // {"msg":"goodbye"}
    let tampered = CompactJws::decode(&parts.join("."))?;
    assert!(tampered.verify(&DefaultVerifier, &key).is_err());
    Ok(())
}
```

## Things to know

- **Decoding is not verifying.** `CompactJws::decode` checks the format and that `alg` is one
  this crate supports, nothing more. Read the payload only after `verify` succeeds.
- **Bind the key to the claimed party.** A valid signature proves the token was signed by the
  key the `kid` names. When the payload names an issuer (`iss`), also check that it is the DID
  of the `kid`; the credential validators in the next guides do this for you.
- **ECDSA signatures are raw `r || s`,** never DER. A backend whose signer returns DER (as cloud
  KMS services do) converts it before handing it back.
- **Algorithms.** `DefaultVerifier` verifies EdDSA, ES256, ES256K (feature `secp256k1`) and,
  with the `rsa` feature, RS256 and PS256.

Next: [issue and verify a JWT credential](jwt-credentials.md).
