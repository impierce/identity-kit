# IdentityKit: Design

`identity-kit` is a Rust library for decentralized identifiers (DIDs), key management behind a
pluggable key store, and JWT-based verifiable credentials. It is published as **one crate** with
Cargo features. Consumers today are `impierce/openid4vc` and `impierce/ssi-agent` (UniCore); it
replaces their use of the `identity_*` crates, Stronghold, spruceid `ssi-*`/`did-*` and `did-key`.

This document describes the target architecture. Parts of it are planned rather than
implemented; [`FEATURES.md`](FEATURES.md) tracks the status of each feature and its issue.

## Principles

1. **One crate, two layers, hard boundary.** Lower layer: `did`, `jose`, `keys`, `identity`,
   `resolver`, `methods`. Upper layer: `vc`, `sd_jwt_vc`, `domain_linkage`, `linked_vp`. Lower modules
   never import upper ones. The upper modules are feature-gated so CI can prove the boundary
   (see Conformance).
2. **Traits, not enums, for extension points.** A DID method implements `DidResolver` and/or
   `DidProducer` and declares `MethodCapabilities`. A key backend implements `KeyStore` and declares
   `KeyStoreCapabilities`. Adding either is a new module behind a feature plus registration; no
   `match` over a closed enum anywhere in the library.
3. **JWT/JWS and SD-JWT only.** No JSON-LD processing, no Data Integrity proofs. `@context` is
   carried as data.
4. **The key store is shaped by remote signers.** Opaque key ids, one algorithm per key, optional
   key generation, declared algorithm support, JWS-ready signatures. A KMS or HSM is the design
   target; in-memory and file-based software keys are the development backends. The crate ships
   vendor-neutral backends only; vendor-specific ones (cloud KMS services) live in their own crates
   and implement `KeyStore`.
5. **Specification conformance is the test oracle.** W3C and method test vectors, RFC JOSE vectors,
   one behavioural suite every key backend must pass, determinism tests. No fixtures of any other
   library's output.
6. **Publishable from day one.** No git or path dependencies. `cargo publish --dry-run` runs on
   every PR. Small, maintained building blocks only: RustCrypto (`ed25519-dalek`, `p256`, `k256`,
   `rsa`, `sha2`), `jsonwebtoken`, `multibase`, `unsigned-varint`, `url`, `serde_json`, `indexmap`,
   `miniz_oxide`, `getrandom`, `cryptoki`. SD-JWT itself is implemented in this crate (ADR 0005).
7. **Developer experience.** A `prelude` per layer (`prelude` for the lower layer,
   `prelude::credentials` for the upper); docs.rs built with `all-features` and `doc_cfg`;
   `#![forbid(unsafe_code)]`; a rolling six-month MSRV; one `CHANGELOG.md`; `release-plz`.
8. **Extension points are defined here.** A data type lives with the specification that defines
   it (DID Core, JOSE, VC, SD-JWT here; OpenID types in `openid4vc`), but a trait a consumer
   implements is always defined in this crate, even when the need comes from an OpenID flow.
   Protocol crates consume `Identity`, `KeyResolver` and `StatusCheck`; they never define an
   extension point of their own (ADR 0006).

## Layout

```
identity-kit/
├── Cargo.toml                 # workspace
├── identity-kit/              # the published crate; lib name `identity_kit`
│   └── src/
│       ├── did/               # Did, DidUrl, DidMethod, DidDocument, VerificationMethod, Service, resolution metadata
│       ├── jose/              # Jwk, JwsAlgorithm, JwsVerifier, compact JWS encode/decode, JwtClaims
│       ├── keys/              # KeyStore, KeySigner, KeyId, KeySpec; backends in_memory, software, pkcs11
│       ├── identity/          # Identity, IdentityKind, Identifier, KeyStoreIdentity
│       ├── resolver/          # DidResolver, DidProducer, MethodCapabilities, Resolver, DocumentCache, dereferencing, KeyReference, KeyResolver
│       ├── methods/           # key, jwk, web
│       ├── vc/                # [vc] Jwt, Credential, Presentation, CredentialV2, EnvelopedVc, ClaimPath, validation
│       ├── sd_jwt_vc/         # [sd-jwt] SD-JWT (RFC 9901), SD-JWT VC, status list, type metadata, validator
│       ├── domain_linkage/    # [domain-linkage] DID configuration resource builder and validator
│       └── linked_vp/         # [linked-vp] linked presentation services, builder, fetcher and validator
├── xtask/                     # publish = false: release checks, vector regeneration, key CLI
└── examples/                  # publish = false
```

## Features

All additive. CI runs `cargo hack --each-feature` and the no-default-features build.

| Feature              | Default | Pulls in                                                      |
| -------------------- | ------- | ------------------------------------------------------------- |
| `did-key`, `did-jwk` | on      | nothing: `bs58` and the multicodec header are always compiled in `jose` (ADR 0003) |
| `did-web`            | on      | `url`; the method works over any injected `HttpClient`        |
| `reqwest`            | on      | `reqwest` with `rustls` and `ring`: the hardened default `HttpClient` for `did:web` (implies `did-web`) |
| `local-network` | off  | Development and tests only: `ReqwestClient::builder` opt-ins for loopback and private addresses (implies `reqwest`) |
| `secp256k1`          | on      | `k256`                                                        |
| `rsa`                | off     | `rsa`                                                         |
| `in-memory`          | off     | test and development key store                                |
| `software`           | on      | `zeroize`; JWK-file key store                                 |
| `pkcs11`             | off     | `cryptoki`; `tokio` (`rt`) for the blocking pool; PKCS#11 key store |
| `vc`                 | on      | `chrono` (`now`, `serde`, `std` only); W3C VC/VP JWT profile and validators |
| `sd-jwt`             | on      | `getrandom` (salts) and `miniz_oxide` (status lists); implies `vc` |
| `domain-linkage`     | on      | implies `vc` and `did-web` (for `url`)                        |
| `linked-vp`          | on      | implies `vc` and `did-web` (for `url` and `HttpClient`)       |
| `jwks`               | off     | implies `did-web` (for `HttpClient`); `JwksResolver` over JWT VC issuer metadata |
| `utoipa`             | off     | `utoipa`; OpenAPI schemas for `DidDocument`, `VerificationMethod`, `Service`, `Jwk`, `DomainLinkageConfiguration`, `ClaimPath` and `TypeMetadata` |
| `test-vectors`       | off     | nothing; `keys::testsuite` and `vectors`, the specification vectors the tests run against |

## `did` module

Pure data: no I/O, no async, no crypto. Typed core properties plus open extension properties
(`properties: IndexMap<String, Value>`, insertion-ordered so output is deterministic).

```rust
pub struct Did(String);                       // validated on construction; serde as string
impl Did {
    pub fn parse(s: &str) -> Result<Self, DidError>;
    pub fn method(&self) -> &str;             // "web"
    pub fn method_specific_id(&self) -> &str; // "example.org%3A8443"
    pub fn to_url(&self) -> DidUrl;
    pub fn join(&self, fragment_or_path: &str) -> Result<DidUrl, DidError>;
}
pub struct DidUrl { did: Did, path: Option<String>, query: Option<String>, fragment: Option<String> }
pub struct DidMethod { name: String, namespace: Option<String> }  // did:demo, did:demo:dev; `matches(&Did)`; serde as string

pub struct DidDocument {
    pub context: Option<Context>,             // "@context", carried verbatim
    pub id: Did,
    pub also_known_as: Vec<Url>,
    pub controller: Option<OneOrMany<Did>>,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<MethodRef>,
    pub assertion_method: Vec<MethodRef>,
    pub key_agreement: Vec<MethodRef>,
    pub capability_invocation: Vec<MethodRef>,
    pub capability_delegation: Vec<MethodRef>,
    pub service: Vec<Service>,
    pub properties: IndexMap<String, Value>,  // flattened extension properties
}
pub enum MethodRef { Reference(DidUrl), Embedded(Box<VerificationMethod>) }
pub struct VerificationMethod { id: DidUrl, controller: Did, r#type: MethodType, material: VerificationMaterial, properties }
pub enum VerificationMaterial { PublicKeyJwk(Jwk), PublicKeyMultibase(String) }
pub struct MethodType(String);               // constants JSON_WEB_KEY_2020, JSON_WEB_KEY, MULTIKEY
pub struct Service { id: DidUrl, r#type: OneOrMany<String>, service_endpoint: ServiceEndpoint, properties }
pub enum ServiceEndpoint { Uri(Url), Set(IndexSet<Url>), Map(IndexMap<String, Value>) }
pub enum VerificationRelationship { Authentication, AssertionMethod, KeyAgreement, CapabilityInvocation, CapabilityDelegation }
```

Operations on `DidDocument`: `builder()`, `insert_verification_method(method, relationships)`,
`remove_verification_method`, `attach_relationship`, `detach_relationship`, `insert_service`,
`remove_service`, `service`, `resolve_verification_method(&DidUrl, Option<VerificationRelationship>)`
(fragment-only references resolve against `id`), `map_dids(FnMut(Did) -> Did)`.

Resolution types follow the W3C DID Resolution specification: `ResolutionResult { document,
document_metadata, resolution_metadata }`, `DocumentMetadata`, `ResolutionMetadata`, and
`ResolutionError`. The error is a `ResolutionErrorKind` keyword (`invalidDid`, `notFound`,
`methodNotSupported`, `representationNotSupported`, `invalidDidDocument`, `internalError`, or any
other) plus an optional human-readable detail and an optional `source()`, the way
`std::io::Error` pairs an `ErrorKind` with a cause. Only the keyword is serialized and compared;
the detail and source tell a refused URL, a timeout, an HTTP `500` and a malformed body apart in
logs. RFC 9457 problem details, which the DID Resolution draft now prefers, map onto the same
three parts.

Serialization: empty arrays and `None` are omitted; `Did`, `DidUrl` serialize as strings;
`Service.type` is a string when single; `@context` is emitted first.

## `jose` module

```rust
pub struct Jwk { .. }                          // RFC 7517; private params never in Debug/Display
impl Jwk {
    pub fn thumbprint_sha256(&self) -> String;   // RFC 7638
    pub fn public(&self) -> Jwk;
    pub fn to_decoding_key(&self) -> Result<jsonwebtoken::DecodingKey>;
    pub fn from_spki_der(hint: KeyType, der: &[u8]) -> Result<Jwk>;   // what KMS/HSM backends return
}
pub enum JwsAlgorithm { EdDSA, ES256, ES256K, ES384, RS256, PS256 }  // From/TryFrom jsonwebtoken::Algorithm
pub trait JwsVerifier: Send + Sync {
    fn verify(&self, alg: JwsAlgorithm, signing_input: &[u8], signature: &[u8], key: &Jwk) -> Result<(), VerificationError>;
}
pub struct DefaultVerifier;                    // ed25519-dalek, p256, k256 (secp256k1), rsa (rsa)
pub struct CompactJws { .. }                   // decode(token); header(), kid(), alg(), signing_input(), payload(), signature()
pub async fn encode_compact(header: &Header, payload: &[u8], signer: &dyn Signer) -> Result<String>;
#[async_trait] pub trait Signer: Send + Sync { fn alg(&self) -> JwsAlgorithm; fn kid(&self) -> Option<&str>; async fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>>; }
pub struct JwtClaims { iss, sub, aud: Option<OneOrMany<String>>, exp, nbf, iat, jti, additional }  // RFC 7519 registered claims; re-exported from `vc` (ADR 0006)
```

`jsonwebtoken` has no ES256K; sign and verify it with `k256` directly. ECDSA signatures are always
the JWS raw `r || s` form at the trait boundary.

## `keys` module

Designed for remote signers first:

- Keys are referenced by an opaque `KeyId` (a name, a PKCS#11 label, a cloud KMS key ARN).
- Private keys never leave the backend; `sign` is remote and async.
- Generation is optional: a KMS or HSM is usually provisioned out of band.
- One algorithm per key. Backends declare which algorithms they support (PKCS#11: Ed25519, ECDSA,
  RSA depending on the module).
- Backends convert their native signature encoding (such as DER-encoded ECDSA) to raw `r || s`.
- Callers cache public keys; a round trip per `kid` lookup is unacceptable.

```rust
pub struct KeyId(String);
pub enum KeyType { Ed25519, P256, Secp256k1, Rsa2048, Rsa4096 }
pub struct KeySpec { key_type: KeyType, alg: JwsAlgorithm, label: Option<String> }
pub struct KeyStoreCapabilities { can_generate: bool, can_delete: bool, remote: bool, algorithms: Vec<JwsAlgorithm> }

#[async_trait]
pub trait KeyStore: Send + Sync {
    fn capabilities(&self) -> KeyStoreCapabilities;
    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError>;
    async fn sign(&self, key: &KeyId, alg: JwsAlgorithm, data: &[u8]) -> Result<Vec<u8>, KeyStoreError>;
    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError>;
    async fn generate(&self, spec: KeySpec) -> Result<KeyId, KeyStoreError> { Err(KeyStoreError::Unsupported("generate")) }
    async fn delete(&self, key: &KeyId) -> Result<(), KeyStoreError> { Err(KeyStoreError::Unsupported("delete")) }
}
pub struct KeySigner<'a> { store: &'a dyn KeyStore, key: KeyId, alg: JwsAlgorithm, public: Jwk }  // implements jose::Signer
```

Backends: `InMemoryKeyStore` (`in-memory`; optional deterministic seed for fixtures),
`SoftwareKeyStore` (`software`; private JWK set file, permission check, `zeroize`, atomic write on
generate), `Pkcs11KeyStore` (`pkcs11`). `keys::testsuite`
(`test-vectors`) runs one behavioural suite against every backend.

## `identity` module

The signing party: which identifiers it controls and the keys that sign for them. Protocols
negotiate the kind of identifier and the algorithm; the identity answers for the chosen pair.

```rust
pub enum IdentityKind { Did(DidMethod), JwkThumbprint }       // what the other side accepts
pub enum Identifier { Did(Did), JwkThumbprint(String) }      // Display: the `iss`/`sub` value
#[async_trait]
pub trait Identity: Send + Sync {
    fn capabilities(&self) -> Vec<(IdentityKind, JwsAlgorithm)>;
    async fn identifier(&self, kind: &IdentityKind, alg: JwsAlgorithm) -> Result<Identifier, IdentityError>;
    async fn public_jwk(&self, kind: &IdentityKind, alg: JwsAlgorithm) -> Result<Jwk, IdentityError>;
    async fn signer(&self, kind: &IdentityKind, alg: JwsAlgorithm) -> Result<Box<dyn Signer + '_>, IdentityError>;
}
pub struct KeyStoreIdentity { .. }   // over any KeyStore + DidProducers; bind(kind, alg, key); generate_missing(bool), off by default
```

- For a DID the signer's `kid()` is the absolute verification-method URL; for a thumbprint it is
  `None` and the caller puts `public_jwk` in the header or `cnf`.
- No external-signer hook: a remote or hardware signer is a `KeyStore`.
- `KeyStoreIdentity` is vendor-agnostic; a KMS crate that implements `KeyStore` needs no glue.
  It binds existing keys and generates on first use only when asked (ADR 0006).

## `resolver` and `methods`

```rust
#[async_trait]
pub trait DidResolver: Send + Sync {
    fn method(&self) -> &'static str;
    async fn resolve(&self, did: &Did, options: &ResolutionOptions) -> Result<ResolutionResult, ResolutionError>;
}
#[async_trait]
pub trait DidProducer: Send + Sync {
    type Params: Send;
    fn method(&self) -> &'static str;
    fn capabilities(&self) -> MethodCapabilities;  // updatable, hosting: Embedded | Web | Registry, single_key, fixed_fragment
    async fn produce(&self, keys: &[Jwk], params: Self::Params) -> Result<DidDocument, ProduceError>;
}
pub struct Resolver { .. }   // ResolverBuilder: .with(resolver) .cache(ttl); resolve, resolve_document, dereference, resolve_public_key

#[non_exhaustive]
pub enum KeyReference { DidUrl(DidUrl), Jwk(Jwk), X509Chain(Vec<Vec<u8>>), Jwks { issuer: Url, kid: String }, Jku { url: Url, kid: Option<String> } }
impl KeyReference { pub fn from_jws(jws: &CompactJws, iss: Option<&str>) -> Result<Self, KeyReferenceError>; }   // `kid` DID URL; `#frag` + DID `iss`; `kid` + HTTPS `iss`; `jwk`; `x5c`; `jku`
pub enum KeyRole { Issuer, Subject }                    // assertionMethod / authentication for a DID
#[async_trait]
pub trait KeyResolver: Send + Sync {
    async fn resolve_key(&self, key: &KeyReference, role: KeyRole) -> Result<Jwk, KeyResolutionError>;   // Unsupported(reference) when it cannot
}
pub struct CompositeKeyResolver(..);   // first resolver that does not answer Unsupported
// in the crate: Resolver (DidUrl), JwkResolver (Jwk by value), JwksResolver<C: HttpClient> (Jwks, feature `jwks`)
```

- `jose::multikey`: the multicodec table (`ed25519-pub 0xed`, `p256-pub 0x1200`, `secp256k1-pub
  0xe7`, `rsa-pub 0x1205`, `x25519-pub 0xec`) and base58btc multibase (`z`) as
  `Jwk::from_multikey`/`Jwk::to_multikey`, so `publicKeyMultibase` material dereferences to a JWK
  for any method.
- `methods::key`: did:key v0.9 Document Creation Algorithm; one `Multikey` method (default) or
  `JsonWebKey` method, fragment equal to the method-specific id, optional X25519 key agreement
  derived from Ed25519; the `publicKeyFormat` and `enableEncryptionKeyDerivation` resolution
  options (ADR 0003).
- `methods::jwk`: `base64url(JWK)` as method-specific id; fragment `#0`; relationships follow `use`.
- `methods::web`: `did_from_url(&Url)`/`did_from_origin(&Url)` (reject IP hosts, credentials,
  queries and fragments; encode a non-default port as `%3A<port>`), DID to document URL mapping
  (`https://host[:port]/.well-known/did.json` when no path segments, else
  `https://host[:port]/<segments>/did.json`), resolver over an injected `HttpClient` trait
  (`ReqwestClient` default: HTTPS only, no redirects, 1 MiB limit, public addresses only),
  producer taking the document URL and setting `@context` to `["https://www.w3.org/ns/did/v1",
  "https://w3id.org/security/suites/jws-2020/v1"]`. For development and tests only, the
  `local-network` feature adds `ReqwestClient::builder` with
  `dangerous_allow_loopback` and `dangerous_allow_private_network`: the host is resolved first,
  plain `http` is used only when every address is in an allowed range, the connection is pinned
  to the checked addresses, and link-local and the other non-public ranges stay refused.
- Key references (ADR 0006): a token names its key in one of several ways and `KeyReference`
  captures which; `from_jws` applies a fixed precedence, `sd_jwt_vc` builds one from `cnf`
  (`jwk`, `kid` as an absolute DID URL, `jku`). Resolving a reference says nothing about
  trust: after the signature verifies, a validator checks that the key belongs to the claimed
  party (the DID of a DID URL; `did:jwk` or the RFC 7638 thumbprint of a key by value; the
  issuer URL of a JWKS). `X509Chain` and `Jku` are in the enum and resolve to `Unsupported`
  until implemented.

## Upper layer

- `vc` (`vc`): `Jwt` newtype and `JwtClaims` (RFC 7519 registered claims plus the rest);
  `Credential`/`Presentation` for the VCDM 1.1 JWT profile, built with `new` and `with_*`
  setters, checked on deserialization, with `to_jwt_claims`/`from_jwt_claims`
  (`iss`/`sub`/`jti`/`nbf`/`exp` mapping, a claim and its property must agree);
  `CredentialV2`/`PresentationV2` as VC-JOSE-COSE JWT payloads (`typ: vc+jwt`/`vp+jwt`) and
  `EnvelopedVc`/`EnvelopedVp` over `data:` URLs; `chrono::DateTime<Utc>` timestamps serialized
  RFC 3339; `vc::validation` with `JwtCredentialValidator` and `JwtPresentationValidator`
  (each with `validate` for 1.1 and `validate_v2` for 2.0, picked by the caller from `typ`)
  over `JwsVerifier` + `resolver::KeyResolver` (the key the token's `KeyReference` names, under
  `assertionMethod` or `authentication`), `TimeOptions` (explicit `now`, leeway), issuer and
  holder binding to the party the `KeyReference` names, audience and nonce, accepted `typ` beyond the profile's,
  `SubjectHolderRelationship`, `FailFast`, one format-agnostic `StatusCheck` trait over
  `CredentialStatus::Vcdm` (and `CredentialStatus::SdJwt` with `sd-jwt`) with a `StatusPolicy`,
  `extract_issuer`/`extract_holder` (ADR 0004, ADR 0006); `ClaimPath` (SD-JWT VC §5.6.1, OID4VP §7 claims path pointer),
  re-exported from `sd_jwt_vc`.
- `sd_jwt_vc` (`sd-jwt`): RFC 9901 implemented in the crate (ADR 0005): `Disclosure`,
  `SdJwt` (parse, `process` per §7.1, `disclose`/`select` for presentation, `sign_key_binding`),
  `SdJwtBuilder` concealing claims at `ClaimPath`s (recursive disclosures, decoys, pluggable
  salts); `SdJwtVc` with `typ: dc+sd-jwt` (`vc+sd-jwt` accepted when the payload has `vct`),
  `SdJwtVcClaims` with the registered claims first-class and the non-disclosable ones
  enforced, `SdJwtVcBuilder`; `SdJwtCredentialV2` for a VCDM 2.0 credential secured with
  SD-JWT (VC-JOSE-COSE §3.2.1: `typ: vc+sd-jwt`, the `CredentialV2` as the payload, `cnf` and
  `status` beside it), `SdJwtCredentialV2Builder`, and `EnvelopedVc::to_sd_jwt` for the
  `application/vc+sd-jwt` envelope of a VCDM 2.0 presentation; `Status`/`StatusListRef`/
  `StatusMechanism`, `StatusList` (ZLIB bit array) and `StatusListToken` for the Token Status
  List; `TypeMetadata` with claim paths, `extends` folding, claim validation and `Integrity`
  metadata; `SdJwtCredentialValidator` over `KeyResolver` + `JwsVerifier` (`validate` an SD-JWT
  VC, `validate_v2` a VCDM 2.0 credential: issuer key from the token's `KeyReference` under
  `assertionMethod`, `iss` or `issuer` bound to the party it names, time claims and validity
  period, key binding with `KeyBindingOptions` and the holder key from `cnf` (`jwk` or `kid`)
  under `authentication`, the `vc` `StatusCheck` with a `StatusPolicy` for `status` and
  `credentialStatus`, `StatusListCheck` over an `HttpClient`).
  `JwtPresentationValidator::validate_v2` unwraps `vc+sd-jwt` envelopes next to `vc+jwt` ones
  (`PresentedCredentialV2`), with key binding required per `PresentationValidationOptions`.
- `domain_linkage` (`domain-linkage`): `DomainLinkageConfiguration` (JWT entries typed, Linked
  Data Proof entries carried as data), `DomainLinkageCredentialBuilder`, `DomainLinkageValidator`
  implementing the DIF Well Known DID Configuration checks (`iss == sub ==
  credentialSubject.id`, one `origin` matching the requested one after normalization, `exp`
  present, no `id`, no extra header parameters or claims, signature under `assertionMethod`);
  validation of a configuration is at-least-one, reporting the rest as errors, and validates at
  most `max_credentials` (32 by default) entries of one configuration.
  `fetch_configuration` gets the resource over the injected `methods::web::HttpClient` (HTTPS
  only; `404`/`410` is `NotPublished`, a state rather than a failure), `service`/`services`
  build and read `LinkedDomains` entries, and `DomainLinkageClient` fetches and validates per
  origin, per DID at an origin, or for every origin of a DID document or resolved DID, fetching
  at most `max_origins` (32 by default) origins per document.
- `linked_vp` (`linked-vp`): DIF Linked Verifiable Presentation v1.0.0. `service`/`services`
  for `LinkedVerifiablePresentation` entries (a map endpoint or a non-URL is an error, never
  skipped), `LinkedPresentationBuilder` (VCDM 1.1 JWT, `iss == sub == holder`, optional `exp`,
  no `aud`/`nonce`), `LinkedVpValidator` over `JwtPresentationValidator` (holder and the DID of
  `kid` checked against the linking DID before any key is resolved, key under
  `authentication`, `AlwaysSubject` by default, the specification's `vp+ld+jwt`/`vc+ld+jwt`
  `typ` values accepted through `additional_typ`), `LinkedVpClient` fetching over an
  `HttpClient` (HTTPS only) with one report per URL, fetching at most `max_urls` (32 by
  default) URLs per document. JSON-LD presentations are reported as
  unsupported; hashlinks are passed through unverified.

## Conformance and CI

- DID documents: W3C DID Core JSON representation; did:key, did:jwk, did:web vectors.
- JOSE: RFC 7515/7517/7638 vectors; cross-verification against `jsonwebtoken` where it supports the
  algorithm and against `k256` for ES256K.
- Key stores: `keys::testsuite` against every backend; PKCS#11 against SoftHSM2 in CI.
- Credentials: DIF DID configuration and Linked Verifiable Presentation examples; SD-JWT VC draft examples; the `openid4vc` test suite
  once ported.
- Determinism: same inputs produce byte-identical documents and configuration resources.
- Layer boundary: `cargo build --no-default-features --features did-key,software` must succeed and
  `cargo tree` in that configuration must not list `chrono`, `miniz_oxide` or `sd-jwt-payload`.
- `cargo hack --each-feature`, `cargo publish --dry-run`, `cargo deny`, clippy pedantic as warnings
  with `-D warnings` on the default lint set.
- Fuzzing: `cargo-fuzz` targets in `fuzz/` over every parser (DID syntax and documents, the DID
  methods, JOSE, VC JWTs, SD-JWT and its builder, SD-JWT VC metadata, linked presentations),
  seeded from the specification vectors (`fuzz/seeds/`, one named file per example; the
  generated corpus is cached in CI, not committed), asserting no panics and serialization round
  trips; a minute per target on pull requests, ten minutes nightly. `fuzz/README.md` is the
  guide.

## References

- W3C DID Core 1.0: https://www.w3.org/TR/did-core/ (DID syntax ABNF in §3.1, DID URL syntax in §3.2)
- W3C DID Resolution: https://www.w3.org/TR/did-resolution/
- W3C Controlled Identifiers (verification material types): https://www.w3.org/TR/cid-1.0/
- did:key: https://w3c-ccg.github.io/did-key-spec/
- did:jwk: https://github.com/quartzjer/did-jwk/blob/main/spec.md
- did:web: https://w3c-ccg.github.io/did-method-web/
- DIF Well Known DID Configuration: https://identity.foundation/.well-known/resources/did-configuration/
- DIF Linked Verifiable Presentation v1.0.0: https://identity.foundation/linked-vp/spec/v1.0.0/
- RFC 3986 (URI, percent-encoding), RFC 7515 (JWS), RFC 7517 (JWK), RFC 7638 (JWK thumbprint)
