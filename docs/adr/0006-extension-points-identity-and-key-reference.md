# ADR 0006: Extension points are defined in this crate; `Identity` for the signing party, `KeyReference` for finding a verification key

- Status: accepted
- Date: 2026-10-20

## Context

`impierce/openid4vc` is being moved from the `identity_*` crates onto this one. Its `oid4vc-core`
crate carries, next to the OpenID protocol types, a layer of generic signing and verification
abstractions that every consumer of the protocol crates has to implement: `Subject: Sign +
Verify` (an identifier, a `kid` and a signature for a given subject syntax type and algorithm,
with an `ExternalSign` escape hatch), `VerificationMaterialResolver`, `SignatureVerifier`, typed
JWT `encode`/`decode` helpers, `RFC7519Claims`, `ClaimPathPointer`, `CredentialStatusVerifier`
and a `kid` normaliser that joins a relative `#fragment` with the `iss` claim. UniCore
(`ssi-agent`) and UniMe (`identity-wallet`) implement those traits over Stronghold and
`did-manager`; `openid4vc` also carries `did:key`-only test subjects.

Most of that layer is already covered here (`DefaultVerifier`, `Resolver`, `KeyResolver`,
`CompactJws`/`encode_compact`, `ClaimPath`, `StatusCheck`, `InMemoryKeyStore` + `DidKey`). Three
things are not: a signing-party abstraction, a way to find a verification key that is not an
absolute DID URL in `kid` (the migration analysis lists `cnf.kid` and relative `kid` as gaps 3
and 4, and issuers identified by an HTTPS `iss` are not reachable at all), and a DID method type.
Two more are in the wrong place: `JwtClaims` and `ClaimPath` sit behind the `vc` and `sd-jwt`
features although id_tokens, proof JWTs and DCQL queries need them without those.

This crate has consumers beyond Impierce in mind, so the shapes are chosen for them, not for
compatibility with what `openid4vc`, UniCore or UniMe do today; all three can change.

## Decision

1. **Boundary rule.** A data type lives in the crate whose specification defines it: DID Core,
   JOSE, VC and SD-JWT types here; OpenID types (`SubjectSyntaxType`, scopes, authorization
   requests, client metadata, DCQL) in `openid4vc`. An extension point (a trait a consumer
   implements) is always defined here, even when the need comes from an OpenID flow:
   `openid4vc` consumes traits, it never defines one. A consumer therefore implements
   identity-kit traits only.
2. **`identity` module** (lower layer, imports `did`, `jose`, `keys`, `resolver`), the signing
   party:
   - `IdentityKind::{Did(DidMethod), JwkThumbprint}` is what the other side accepts;
     `Identifier::{Did(Did), JwkThumbprint(String)}` with `Display` is the `iss`/`sub` value.
   - `trait Identity { capabilities() -> Vec<(IdentityKind, JwsAlgorithm)>; identifier(kind);
     public_jwk(kind, alg); signer(kind, alg) -> Box<dyn Signer> }`. Negotiation (which kind,
     which algorithm) stays with the protocol; the identity answers for a chosen pair. For a DID
     the signer's `kid()` is the absolute verification-method URL; for a thumbprint it is `None`
     and the caller puts `public_jwk` in the header. No external-signer hook: a remote or
     hardware signer is a `KeyStore` (principle 4 of `DESIGN.md`).
   - One shipped implementation, `KeyStoreIdentity`, over any `KeyStore` and the registered
     `DidProducer`s, vendor-agnostic so that a KMS crate implementing `KeyStore` works without
     glue. It binds existing keys; generating a key on first use is opt-in, so no production
     deployment mints keys silently. Whether that default is the right balance between usability
     and safety is an open point to revisit when the first KMS backend lands.
   - Name: `identity`/`Identity` over `subject` (collides with `credentialSubject` and the
     DID-Core "DID subject", which is the thing identified, not the thing that signs),
     `controller` (precise for DIDs, forced for a bare JWK, unfamiliar outside the DID world),
     `holder`/`issuer` (roles; the same party plays several) and `entity`/`principal` (say
     nothing about keys). Veramo's `IIdentifier` and IOTA Identity are the precedents.
3. **`did::DidMethod`**: method name per the DID Core ABNF plus an optional namespace
   (`did:iota:smr`), parsed, displayed and serialized as a string. `Identity` is keyed on it;
   `Did::method()` stays a `&str`.
4. **`resolver::KeyReference`** describes where a token says its key is, and
   **`resolver::KeyResolver`** takes it:
   - `KeyReference::{DidUrl, Jwk, X509Chain, Jwks { issuer, kid }, Jku}`, `#[non_exhaustive]`,
     built by `KeyReference::from_jws(&CompactJws, iss)` with a documented precedence (a `kid`
     that is a DID URL; a `#fragment` joined with a DID `iss`; a `kid` with an HTTPS `iss`;
     the `jwk` header; `x5c`; `jku`) and by `KeyReference::from_confirmation(&cnf)` for the
     subject side (`jwk`, then `kid`, then `jku`).
   - `KeyRole::{Issuer, Subject}` replaces `VerificationRelationship` at the trait boundary
     (`assertionMethod`/`authentication` for a DID; meaningless for a JWKS).
   - `resolve_key(&KeyReference, KeyRole) -> Jwk`, with `KeyResolutionError::Unsupported` for a
     reference a resolver does not handle, and `CompositeKeyResolver` chaining resolvers. The
     trait moves from `vc::validation` to the lower layer so id_tokens and proofs use it.
   - Shipped: `Resolver` for `DidUrl`; `JwkResolver` for a key by value; `JwksResolver` over an
     `HttpClient` for `Jwks` (SD-JWT VC §3.5 JWT VC issuer metadata, `jwks` or `jwks_uri`).
     `X509Chain` and `Jku` exist in the enum and resolve to `Unsupported` until an issue adds
     them.
   - Resolving says nothing about trust. After the signature verifies, the validators check
     that the key belongs to the claimed party: the DID of the URL; `did:jwk` or the RFC 7638
     thumbprint of a key by value (or no party at all, SIOPv2 self-issued); the issuer URL of a
     JWKS. This generalises "the party is the DID of `kid`" from ADR 0004 §4.
   - ADR 0004 §3 (one-method `KeyResolver` over `DidUrl`) and §5 (`kid` is an absolute DID URL)
     are amended: the one method now takes a `KeyReference`; a relative `kid` is accepted when
     `iss` is a DID; a path or DID parameters in a DID URL stay refused.
5. **`jose::JwtClaims`** and `OneOrMany` move down from `vc` (re-exported there). RFC 7519 is
   JOSE-layer, and the richer type (`aud` one-or-many, `NumericDate`) replaces `openid4vc`'s
   `RFC7519Claims`.
6. **One `StatusCheck`** over `CredentialStatus::{Vcdm(&TypedObject), SdJwt(&Status)}` replaces
   `StatusCheck` and `SdJwtStatusCheck`, so a consumer implements status checking once and the
   `StatusPolicy` handling stays typed. Two typed traits and one trait over a raw `Value` were
   rejected: the first doubles the implementation point, the second pushes parsing into every
   implementor.
7. **`vc::ClaimPath`** leaves the `sd-jwt` gate (re-exported from `sd_jwt_vc`): SD-JWT VC §5.6.1
   and OID4VP §7 define the same construct and DCQL applies it to every JSON-based format. It
   gains a `utoipa` schema.
8. **Deleted on the `openid4vc` side with no replacement** once the above exists:
   `Subject`, `Sign`, `Verify`, `ExternalSign`, `Validator`, `SignatureVerifier`,
   `VerificationMaterialResolver`, `jwt::{encode, decode, extract_header}`,
   `utils::{jwt, did}`, `RFC7519Claims`, `ClaimPathPointer`, `CredentialStatusVerifier`,
   `test_utils`, `oid4vc-manager::KeySubject`. `SubjectSyntaxType` stays and maps its `Did`
   variant onto `IdentityKind::Did`.

## Alternatives considered

- **No signing-party trait; compose `Did` + `Signer` pairs on the consumer side.** Smaller
  surface, but every application repeats the pairing, keys must exist eagerly for every
  (method, algorithm) a protocol may negotiate, and the trait would end up defined in
  `openid4vc`, against decision 1.
- **`IdentityKind` over DID methods only.** Nothing selects the JWK-thumbprint syntax today, but a
  key-only holder is what SD-JWT key binding with `cnf.jwk` already is; the neutral enum costs
  one variant.
- **Keep the `DidUrl` resolver and put a "key locator" in front of it.** Non-breaking, but two
  extension points for one job, and `x5c` or JWKS resolvers have nowhere to plug in.
- **A `KidPolicy` option on the validators for the relative `kid` only.** Solves gap 4 and
  nothing else; a JWT names its key in more ways than `kid`.

## Consequences

- A new lower-layer module; the layer-boundary list in `CONTRIBUTING.md`, `DESIGN.md` and CI
  grows by `identity`.
- `KeyResolver`, `StatusCheck` and the validators' `kid` errors change shape: a breaking release
  (0.3.0). `JwtClaims` and `ClaimPath` moves are additive through re-exports.
- Issues #51 (`DidMethod`), #52 (`identity`), #53 (`KeyReference`), #54 (`JwtClaims`), #55
  (`StatusCheck`), #56 (`ClaimPath`); #52 depends on #51; #50 is subsumed by #53.
- `docs/DESIGN.md` describes the `identity` module, the lower-layer `KeyResolver`, `JwtClaims`
  under `jose` and `ClaimPath` under `vc`.
- `openid4vc` drops `oid4vc-core`'s signing and verification layer and depends on this crate's
  traits; UniCore and UniMe implement `Identity` (or use `KeyStoreIdentity` over their key
  store) and `StatusCheck`, nothing from `openid4vc`.
