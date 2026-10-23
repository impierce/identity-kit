# Issue and verify a JWT credential

The issuer signs a verifiable credential as a JWT, the holder presents it to a verifier inside a
signed presentation, and the verifier validates both. This guide uses the VCDM 1.1 JWT profile,
the most widely deployed form; the VCDM 2.0 form is a variation at the end.

## What you need

```sh
cargo add identity-kit --features in-memory
cargo add tokio --features macros,rt-multi-thread
cargo add serde_json chrono
```

`vc`, `did-key` and `did-jwk` are on by default.

## Steps

1. **Issuer and holder keys.** Each party has its own key and DID; here the issuer uses
   `did:key` and the holder `did:jwk`, as in [Keys and DIDs](keys-and-dids.md).
2. **Build the credential.** `Credential::new` takes the issuer, the issuance date and the
   subject; `with_*` setters add types, an id, an expiration date and more. The subject is the
   holder's DID, which is what lets the verifier tie the credential to the presenter.
3. **Issue.** `to_jwt_claims` maps the credential onto the registered JWT claims (`iss`, `sub`,
   `nbf`, `exp`, `jti`) with the credential itself under `vc`; `Jwt::sign` signs them.
4. **Present.** The holder wraps the credential JWT in a `Presentation`, adds the verifier's
   audience and nonce, and signs it with their own key.
5. **Validate.** `JwtPresentationValidator` checks the presentation's signature, that its
   signer is the holder, the audience, the nonce and the validity period. It then validates
   every credential inside with the rules `JwtCredentialValidator` applies on its own
   (signature, issuer binding, validity period), and checks that each credential's subject is
   the holder; `SubjectHolderRelationship` in the options relaxes that check.

```rust
use chrono::{Duration, Utc};
use identity_kit::jose::{DefaultVerifier, JwsAlgorithm, JwsHeader, KeyType};
use identity_kit::keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore};
use identity_kit::methods::{DidJwk, DidKey};
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{
    CredentialValidationOptions, JwtCredentialValidator, JwtPresentationValidator,
    PresentationValidationOptions,
};
use identity_kit::vc::{Credential, Jwt, Presentation, Subject};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. The issuer (Ed25519, did:key) and the holder (P-256, did:jwk).
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
    let holder_did = DidJwk::did(&holder_store.public_jwk(&holder_key).await?)?;
    let holder_kid = holder_did.join("#0")?;
    let holder = KeySigner::new(&holder_store, holder_key, JwsAlgorithm::ES256).await?;

    // 2. A university degree for the holder, valid for a year.
    let now = Utc::now();
    let credential = Credential::new(
        &issuer_did,
        now,
        Subject::new(&holder_did).with_property(
            "degree",
            json!({ "type": "BachelorDegree", "name": "Bachelor of Science and Arts" }),
        ),
    )
    .with_type("UniversityDegreeCredential")
    .with_expiration_date(now + Duration::days(365));

    // 3. The issuer signs it as a JWT. `typ` is `JWT` in the VCDM 1.1 JWT profile.
    let header = JwsHeader::new(JwsAlgorithm::EdDSA)
        .with_typ("JWT")
        .with_kid(issuer_kid.as_str());
    let credential_jwt = Jwt::sign(&header, &credential.to_jwt_claims()?, &issuer).await?;

    // Anyone can validate the credential on its own. Resolving both methods covers the
    // issuer (did:key) and the holder (did:jwk).
    let resolver = || {
        Resolver::builder()
            .with(DidKey::default())
            .with(DidJwk)
            .build()
    };
    let decoded = JwtCredentialValidator::new(resolver(), DefaultVerifier)
        .validate(&credential_jwt, &CredentialValidationOptions::new())
        .await?;
    assert_eq!(decoded.claims.iss.as_deref(), Some(issuer_did.as_str()));

    // 4. The holder presents it to a verifier that sent this audience and nonce.
    let (audience, nonce) = ("https://verifier.example.com", "n-0S6_WzA2Mj");
    let mut presentation = Presentation::new().with_holder(&holder_did);
    presentation.verifiable_credential = vec![credential_jwt];
    let claims = presentation
        .to_jwt_claims()?
        .with_aud(audience)
        .with_claim("nonce", nonce);
    let header = JwsHeader::new(JwsAlgorithm::ES256)
        .with_typ("JWT")
        .with_kid(holder_kid.as_str());
    let presentation_jwt = Jwt::sign(&header, &claims, &holder).await?;

    // 5. The verifier validates the presentation and the credential inside.
    let options = PresentationValidationOptions::new()
        .with_audience(audience)
        .with_nonce(nonce)
        .with_credentials(CredentialValidationOptions::new());
    let validator = JwtPresentationValidator::new(resolver(), DefaultVerifier);
    let validated = validator.validate(&presentation_jwt, &options).await?;
    assert_eq!(validated.holder().map(|h| h.as_str()), Some(holder_did.as_str()));
    let degree = &validated.credentials[0].credential;
    assert_eq!(
        degree.subject().and_then(|s| s.properties.get("degree")).map(|d| &d["type"]),
        Some(&json!("BachelorDegree"))
    );

    // Replayed later, the same presentation fails: the verifier now expects a fresh nonce.
    let replayed = PresentationValidationOptions::new()
        .with_audience(audience)
        .with_nonce("another-nonce")
        .with_credentials(CredentialValidationOptions::new());
    assert!(validator.validate(&presentation_jwt, &replayed).await.is_err());
    Ok(())
}
```

## Things to know

- **Time.** The validators use the current time unless `with_time(TimeOptions::at(..))` says
  otherwise; `TimeOptions::with_leeway` allows for clock skew between parties.
- **Status.** A credential with `credentialStatus` is checked through a `StatusCheck` you attach
  with `JwtCredentialValidator::with_status_check`; `StatusPolicy` decides what happens to a
  credential whose status cannot be determined.
- **Finding the keys.** The validators take any `KeyResolver`, not only a DID `Resolver`:
  `JwksResolver` (feature `jwks`) for issuers with an HTTPS identifier, `JwkResolver` for a key
  in a `jwk` header, or several in a `CompositeKeyResolver`. Whatever finds the key, the
  validator checks that it belongs to the issuer (`iss`) or holder.
- **Not for SD-JWT.** A payload with `_sd`, `_sd_alg` or `...` digests is an SD-JWT, whose
  concealed claims would look absent here; the validators refuse it with
  `ValidationError::SdJwtPayload`. Validate it with `SdJwtCredentialValidator`
  ([next guide](sd-jwt-vc.md)).
- **Errors are typed.** Validation fails with a `ValidationError` (or
  `PresentationValidationError`) that names the check: `Expired`, `IssuerMismatch`,
  `AudienceMismatch`, `NonceMismatch` and so on. With `FailFast::AllErrors` a presentation
  validation reports every failing credential instead of stopping at the first.
- **VCDM 2.0.** `CredentialV2` and `PresentationV2` are themselves the JWT payload
  (`typ: vc+jwt` and `vp+jwt`), and a presentation carries each credential as an `EnvelopedVc`.
  The validators' `validate_v2` methods check them; pick `validate` or `validate_v2` from the
  token's `typ`.

Next: [selective disclosure with SD-JWT VC](sd-jwt-vc.md).
