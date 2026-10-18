# ADR 0004: `vc` keeps VCDM 1.1 and 2.0 apart, resolves keys through one `KeyResolver` method, and builds its types without builder structs

- Status: accepted
- Date: 2026-10-18

## Context

`docs/DESIGN.md` and issue #11 describe the `vc` module in the vocabulary of the libraries it
replaces: `Credential`/`Presentation` "with builders", a `VerificationMaterialResolver` trait
with `resolve_did_document` and `resolve_public_key`, `JwtCredentialValidator`,
`JwtPresentationValidator` and `SdJwtCredentialValidator`, `FailFast`, a `StatusCheck` hook, and
`chrono` timestamps. The consumers (`openid4vc`, `ssi-agent`) can be migrated, so the shape is
free to follow this crate's own conventions: traits for extension points, `#[non_exhaustive]`
data with open properties, specification vectors as tests.

Two profiles exist: the VCDM 1.1 JWT profile (§6.3.1), where the data model object sits in a
`vc` or `vp` claim next to registered claims that duplicate some of its properties, and
VC-JOSE-COSE for VCDM 2.0, where the data model object *is* the JWT payload and `vc`/`vp` must
not appear. The data model specifications publish no signing keys for their JWT examples, and the
one ES256 example of VC-JOSE-COSE carries a `kid` whose key the specification does not list.

## Decision

1. **Separate types per data model version.** `Credential`/`Presentation` (1.1,
   `issuanceDate`/`expirationDate`, JWT strings under `verifiableCredential`) and
   `CredentialV2`/`PresentationV2` (2.0, `validFrom`/`validUntil`, `EnvelopedVc` objects under
   `verifiableCredential`) are distinct structs sharing `Party`, `Subject` and `TypedObject`.
   `to_jwt_claims`/`from_jwt_claims` implement the respective profile; a registered claim and the
   property it duplicates must agree, else `CredentialError::ClaimMismatch`, and an object-valued
   `issuer` or `holder` stays in the data model object because `iss` carries only its `id`.
   Deserialization runs `check()`: base context first, required type, a subject, an ordered
   validity period.
2. **No builder structs.** Each type has `new(..)` with the required members and chainable
   `with_*` setters; `#[non_exhaustive]` keeps the fields public yet extensible. A credential
   built out of order is caught by `check()` when it is encoded.
3. **`KeyResolver` with one method.** `resolve_key(&DidUrl, VerificationRelationship) -> Jwk`
   replaces the two-method trait; `Resolver` implements it, and `Resolver::resolve_public_key`
   gained the optional relationship so that the key of a credential is looked up under
   `assertionMethod` and the key of a presentation under `authentication`. Resolving the whole
   document is not something a validator needs.
4. **Validators.** `JwtCredentialValidator` validates both profiles (`validate`,
   `validate_v2`); `JwtPresentationValidator` wraps one. Issuer and holder binding is "the party
   is the DID of `kid`". `FailFast` applies to the credentials of a presentation only; a
   credential reports its first failure. `StatusCheck` is a trait the application implements,
   `StatusPolicy` says what to do without one or for an unsupported type. `TimeOptions` takes an
   explicit `now` so validation is reproducible. `ValidationError` holds `JwsError` and the
   opaque `KeyResolutionError`, so it is neither `Clone` nor `PartialEq`.
5. **`SdJwtCredentialValidator` waits for `sd_jwt_vc`.** It needs the SD-JWT parser, which
   issue #12 brings; it lands there.
6. **`chrono` with `now`, `serde` and `std` only.** No `clock` (no `iana-time-zone`), no
   `wasmbind`; the crate only ever needs UTC.
7. **Tests.** The data model examples (VCDM 1.1 Examples 1 and 31 to 33, the VC-JOSE-COSE
   JOSE examples, VCDM 2.0 §4.6 and §4.12) are vectors for the data types, the claim mapping and
   unverified decoding. Signatures are made in the tests with the RFC 8037 Ed25519 key behind a
   `did:key` issuer and the RFC 7515 A.3 P-256 key behind a `did:jwk` holder, so validation runs
   over real DID methods without any other library's output.

## Consequences

- `docs/DESIGN.md` names `KeyResolver` instead of `VerificationMaterialResolver`, and lists the
  SD-JWT validator under `sd_jwt_vc`.
- `Resolver::resolve_public_key(url, relationship)` is a signature change against the
  unreleased resolver of #22.
- Consumers port their builders to `Credential::new(..).with_*(..)` and their validation options
  to `CredentialValidationOptions`/`PresentationValidationOptions`.
