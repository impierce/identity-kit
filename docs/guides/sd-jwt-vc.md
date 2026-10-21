# Selective disclosure with SD-JWT VC

An SD-JWT VC lets the holder reveal only some claims of a credential to a verifier. The issuer
replaces each selectively disclosable claim by a digest and hands its value to the holder as a
separate *disclosure*; the holder presents the issuer-signed JWT with the disclosures they choose,
plus a *key binding JWT* that proves they hold the key the credential is bound to.

## What you need

```sh
cargo add identity-kit --features in-memory
cargo add tokio --features macros,rt-multi-thread
cargo add serde_json chrono
```

`sd-jwt` and `did-key` are on by default.

## Steps

1. **Keys.** The issuer signs under a DID. The holder only needs a key; its public JWK goes
   into the credential's `cnf` claim.
2. **Issue.** `SdJwtVcBuilder` takes the credential type (`vct`), the registered claims and the
   credential's own claims. `conceal` marks a claim, or an element of an array, as selectively
   disclosable; everything else is always visible. `sign` produces the SD-JWT VC with all
   disclosures, which the issuer sends to the holder.
3. **Choose what to disclose.** `disclose` keeps the disclosures for the given claim paths and
   drops the rest. Disclosing an object brings the disclosures nested in it along.
4. **Bind to this verifier.** `sign_key_binding` adds a key binding JWT over the verifier's
   audience and nonce, signed with the holder key. The result serializes to the `~`-separated
   compact form that goes over the wire.
5. **Validate.** The verifier parses the presentation and runs `SdJwtCredentialValidator`: the
   issuer's signature and its binding to the DID in `kid`, the disclosures against their
   digests, the validity period, and the key binding JWT against the `cnf` key, audience and
   nonce. The validated payload holds the disclosed claims only.

```rust
use chrono::{Duration, Utc};
use identity_kit::claim_path;
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, KeyType};
use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
use identity_kit::methods::DidKey;
use identity_kit::resolver::Resolver;
use identity_kit::sd_jwt_vc::validation::{KeyBindingOptions, SdJwtValidationOptions};
use identity_kit::sd_jwt_vc::{KeyBinding, SdJwt, SdJwtCredentialValidator, SdJwtVcBuilder};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. The issuer signs under a did:key; the holder has a P-256 key.
    let issuer_store = InMemoryKeyStore::new();
    let issuer_key = issuer_store
        .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
        .await?;
    let issuer_did = DidKey::did(&issuer_store.public_jwk(&issuer_key).await?)?;
    let issuer_kid = issuer_did.join(&format!("#{}", issuer_did.method_specific_id()))?;
    let issuer = KeySigner::new(&issuer_store, issuer_key, JwsAlgorithm::EdDSA).await?;

    let holder_store = InMemoryKeyStore::new();
    let holder_key = holder_store
        .generate(KeySpec::new(KeyType::P256, JwsAlgorithm::ES256))
        .await?;
    let holder = KeySigner::new(&holder_store, holder_key, JwsAlgorithm::ES256).await?;

    // 2. An identity credential whose personal claims are selectively disclosable.
    let now = Utc::now();
    let credential = SdJwtVcBuilder::new("https://credentials.example.com/identity_credential")
        .with_issuer(issuer_did.as_str())
        .with_kid(issuer_kid.as_str())
        .with_issued_at(now)
        .with_expires_at(now + Duration::days(365))
        .with_holder_key(holder.public_jwk())
        .with_claim("given_name", "Erika")
        .with_claim("family_name", "Mustermann")
        .with_claim("birthdate", "1963-08-12")
        .with_claim("address", json!({ "locality": "Berlin", "country": "DE" }))
        .with_claim("nationalities", json!(["DE", "FR"]))
        .conceal(["given_name"])
        .conceal(["family_name"])
        .conceal(["birthdate"])
        .conceal(["address"])
        .conceal(["address", "locality"])
        .conceal(claim_path!["nationalities", ()])
        .sign(&issuer)
        .await?;
    // One disclosure per concealed claim and array element.
    assert_eq!(credential.sd_jwt().disclosures().len(), 7);

    // 3. and 4. The holder discloses the given name and the address to a verifier, and binds
    // the presentation to the verifier's audience and nonce.
    let (audience, nonce) = ("https://verifier.example.com", "n-0S6_WzA2Mj");
    let presentation = credential
        .disclose(&[claim_path!["given_name"], claim_path!["address"]])?
        .sign_key_binding(&KeyBinding::new(audience, nonce, Utc::now()), &holder)
        .await?;
    let wire = presentation.to_string(); // `<issuer-signed JWT>~<disclosure>~…~<KB-JWT>`

    // 5. The verifier parses and validates it.
    let sd_jwt = SdJwt::parse(&wire)?;
    let validator = SdJwtCredentialValidator::new(
        Resolver::builder().with(DidKey::default()).build(),
        DefaultVerifier,
    );
    let options = SdJwtValidationOptions::new()
        .with_key_binding(KeyBindingOptions::new(audience, nonce));
    let validated = validator.validate(&sd_jwt, &options).await?;

    let claims = validated.credential.payload();
    assert_eq!(claims["given_name"], "Erika");
    assert_eq!(claims["address"], json!({ "locality": "Berlin", "country": "DE" }));
    assert!(!claims.contains_key("family_name"));
    assert!(!claims.contains_key("birthdate"));
    assert_eq!(claims["nationalities"], json!([])); // the array, with no element disclosed

    // The same presentation sent to another verifier fails the key binding check.
    let elsewhere = SdJwtValidationOptions::new()
        .with_key_binding(KeyBindingOptions::new("https://other.example.com", nonce));
    assert!(validator.validate(&sd_jwt, &elsewhere).await.is_err());
    Ok(())
}
```

## Things to know

- **What stays visible.** The registered claims that SD-JWT VC forbids concealing (`iss`, `vct`,
  `cnf`, `iat`, `nbf`, `exp`, `status`, …) are always in the clear; the builder refuses to
  conceal them.
- **Decoys.** `with_decoys(n)` adds digests that match no disclosure, so the number of
  concealed claims does not leak.
- **Key binding is the verifier's choice.** Without `with_key_binding`, the validator accepts
  the presentation and ignores any key binding JWT. Require it whenever the credential should
  only be usable by its holder.
- **Status and type metadata.** A credential can point to a Token Status List
  (`with_status`) that the validator checks through an `SdJwtStatusCheck`, and `TypeMetadata`
  describes a `vct`: its display, its claims and which of them may be concealed.
- **VCDM 2.0 with SD-JWT.** `SdJwtCredentialV2Builder` secures a `CredentialV2` with SD-JWT
  (`typ: vc+sd-jwt`); `SdJwtCredentialValidator::validate_v2` validates it.

Back to the [guide index](README.md).
