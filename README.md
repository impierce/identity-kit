![banner](https://github.com/impierce/identity-kit/raw/HEAD/.github/banner.png)

[![QA](https://github.com/impierce/identity-kit/actions/workflows/qa.yml/badge.svg)](https://github.com/impierce/identity-kit/actions/workflows/qa.yml)
[![Coverage](https://codecov.io/gh/impierce/identity-kit/graph/badge.svg)](https://codecov.io/gh/impierce/identity-kit)
[![crates.io](https://img.shields.io/crates/v/identity-kit.svg)](https://crates.io/crates/identity-kit)
[![docs.rs](https://img.shields.io/docsrs/identity-kit)](https://docs.rs/identity-kit)
[![License](https://img.shields.io/crates/l/identity-kit.svg)](https://github.com/impierce/identity-kit/blob/HEAD/LICENSE)

Collection of primitives for SSI libraries and applications: decentralized identifiers (DIDs), key management behind a pluggable key store, and JWT-based verifiable credentials.

---

## Features

- ✅ `Did` and `DidUrl` parsing and validation per [W3C DID Core](https://www.w3.org/TR/did-core/)
- ✅ `DidDocument` data model and [DID Resolution](https://www.w3.org/TR/did-resolution/) types
- ✅ JWK and compact JWS ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) with EdDSA, ECDSA and RSA verification
- ✅ `KeyStore` trait designed for remote signers, with in-memory and file-based backends
- 📋 PKCS#11 key store backend
- ✅ `DidResolver` and `DidProducer` traits with a `Resolver` registry, document cache and DID URL dereferencing
- ✅ `did:key`, `did:jwk` and `did:web` methods, with a hardened HTTPS client for `did:web`
- ✅ Verifiable credentials and presentations as JWTs: the [VCDM 1.1](https://www.w3.org/TR/vc-data-model/) JWT profile, [VCDM 2.0](https://www.w3.org/TR/vc-data-model-2.0/) with [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) envelopes, and validators over any DID method
- ✅ SD-JWT (RFC 9901) and SD-JWT VC: issuing with selective disclosure, presenting with key binding, validating over any DID method, the Token Status List and type metadata
- ✅ DIF Well Known DID Configuration: the DID configuration resource, its domain linkage credentials and their validation against an origin
- ✅ DIF Linked Verifiable Presentation: `LinkedVerifiablePresentation` services, presentations signed for publishing, and fetching and validating what a DID document links

✅ implemented, 📋 planned. The full checklist, with Cargo features, tracking issues and links to every specification, is in [`docs/FEATURES.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/FEATURES.md).
The architecture is described in [`docs/DESIGN.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/DESIGN.md).

## Cargo features

All features are additive; the lower layer (`did`, `jose`, `keys`, `resolver`) is always compiled.

| Feature          | Default | Enables                                                                                  |
| ---------------- | :-----: | ---------------------------------------------------------------------------------------- |
| `did-key`        |   ✅    | The `did:key` method (`methods::key`)                                                    |
| `did-jwk`        |   ✅    | The `did:jwk` method (`methods::jwk`)                                                    |
| `did-web`        |   ✅    | The `did:web` method (`methods::web`) over any `HttpClient`; pulls in `url`              |
| `reqwest`        |   ✅    | The hardened default `HttpClient` for `did:web` (`reqwest` with `rustls`); implies `did-web` |
| `reqwest-local-network` |  | Development and tests only: `ReqwestClient::builder` with opt-ins to reach loopback and private addresses over `http`; implies `reqwest` |
| `secp256k1`      |   ✅    | ES256K signatures and `secp256k1` keys, via `k256`                                       |
| `rsa`            |         | RS256 and PS256 signature verification, via `rsa`                                        |
| `software`       |   ✅    | `SoftwareKeyStore`: private keys in a JWK set file                                       |
| `in-memory`      |         | `InMemoryKeyStore`: keys in memory, optionally derived from a seed                       |
| `vc`             |   ✅    | Verifiable credentials and presentations as JWTs (`vc`); pulls in `chrono`               |
| `sd-jwt`         |   ✅    | SD-JWT and SD-JWT VC (`sd_jwt_vc`); implies `vc`, pulls in `miniz_oxide`                 |
| `domain-linkage` |   ✅    | DIF Well Known DID Configuration (`domain_linkage`); implies `vc` and `did-web`          |
| `linked-vp`      |   ✅    | DIF Linked Verifiable Presentation (`linked_vp`); implies `vc` and `did-web`             |
| `utoipa`         |         | OpenAPI schemas (`utoipa::ToSchema`) for `DidDocument`, `VerificationMethod`, `Service`, `Jwk`, `DomainLinkageConfiguration` and `TypeMetadata` |
| `test-vectors`   |         | `keys::testsuite`, the behavioural suite every key store must pass, and `vectors`, the specification vectors |

`identity_kit::prelude` gathers the common types of the lower layer and `identity_kit::prelude::credentials` those of the upper layer, for glob import.

## Key stores

Private keys live behind the `KeyStore` trait: opaque key ids, one algorithm per key, signing as an async operation that may leave the process.
The crate ships vendor-neutral backends; a cloud KMS or HSM backend implements the trait from its own crate.

| Backend            | Feature     | Keys live in                           | Generates | Deletes | Signs with                              |
| ------------------ | ----------- | -------------------------------------- | :-------: | :-----: | --------------------------------------- |
| `InMemoryKeyStore` | `in-memory` | Process memory, zeroized on drop       |    ✅     |   ✅    | EdDSA, ES256, ES256K (`secp256k1`)      |
| `SoftwareKeyStore` | `software`  | A private JWK set file, permission-checked, atomically rewritten |    ✅     |   ✅    | EdDSA, ES256, ES256K (`secp256k1`)      |
| `Pkcs11KeyStore`   | `pkcs11`    | An HSM or software token               |  planned  | planned | Module dependent ([#13](https://github.com/impierce/identity-kit/issues/13)) |

Neither software backend signs with RSA: see [ADR 0001](https://github.com/impierce/identity-kit/blob/HEAD/docs/adr/0001-rsa-verification-only.md).
The full contract, with the error vocabulary and the algorithm matrix, is in [`docs/key-stores.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/key-stores.md).

## Extending

### Adding a DID method

A method is a type that implements `DidResolver` (the Read operation) and, when it can create documents from keys, `DidProducer`.
No enum lists the methods: a `Resolver` dispatches on the DID's method name to whatever was registered.

```rust
use identity_kit::prelude::*;

struct DidExample;

#[async_trait::async_trait]
impl DidResolver for DidExample {
    fn method(&self) -> &'static str {
        "example"
    }

    async fn resolve(
        &self,
        did: &Did,
        options: &ResolutionOptions,
    ) -> Result<ResolutionResult, ResolutionError> {
        // Fetch or derive the document, then wrap it with its metadata.
        todo!()
    }
}

let resolver = Resolver::builder().with(DidExample).build();
```

`DidProducer` adds `capabilities()` (whether documents can be updated, where they are hosted, how many keys fit) and `produce(keys, params)`, which builds a document for a set of public keys.
Keep the method in a module of its own behind a Cargo feature, test it against its specification's vectors, and add a row to [`docs/FEATURES.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/FEATURES.md).

### Adding a key store backend

A backend implements `KeyStore`: `capabilities`, `public_jwk`, `sign` and `exists`, plus `generate` and `delete` when the backend supports them.
Signatures come back in their JWS form (64 bytes for EdDSA, raw `r || s` for ECDSA), and the capabilities must be truthful: every algorithm listed signs, and `generate` succeeds only when advertised.

```rust
use identity_kit::prelude::*;

struct MyKms { /* client, credentials */ }

#[async_trait::async_trait]
impl KeyStore for MyKms {
    fn capabilities(&self) -> KeyStoreCapabilities {
        let mut capabilities = KeyStoreCapabilities::new([JwsAlgorithm::ES256]);
        capabilities.remote = true; // signing leaves the process
        capabilities
    }

    async fn public_jwk(&self, key: &KeyId) -> Result<Jwk, KeyStoreError> { todo!() }

    async fn sign(&self, key: &KeyId, alg: JwsAlgorithm, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> { todo!() }

    async fn exists(&self, key: &KeyId) -> Result<bool, KeyStoreError> { todo!() }
}
```

The behavioural suite checks the contract against a live backend; run it in the backend's own tests with the `test-vectors` feature enabled:

```rust
identity_kit::keys::testsuite::run(&store).await;                                   // a backend that generates keys
identity_kit::keys::testsuite::run_with_keys(&store, &[(key_id, JwsAlgorithm::ES256)]).await; // provisioned keys
```

## Development

See [CONTRIBUTING.md](https://github.com/impierce/identity-kit/blob/HEAD/CONTRIBUTING.md) for how to set up, test and submit changes.
The parsers are fuzzed continuously with `cargo-fuzz`; [`fuzz/README.md`](https://github.com/impierce/identity-kit/blob/HEAD/fuzz/README.md) explains the targets, their seeds and how to run them.
To report a vulnerability, see [SECURITY.md](https://github.com/impierce/identity-kit/blob/HEAD/SECURITY.md).

## Release

Releases are automated with [release-plz](https://release-plz.dev/) and follow [Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html).
Every push to `main` updates a release pull request with the next version and changelog, derived from the [Conventional Commits](https://www.conventionalcommits.org/) since the last release.
Merging it publishes to [crates.io](https://crates.io/crates/identity-kit) and creates the tag and GitHub release.
Versions and `CHANGELOG.md` are never edited by hand.
See [`docs/RELEASE.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/RELEASE.md) for the versioning rules, changelog filtering and the credential setup.
