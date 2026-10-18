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
- 📋 `did:key`, `did:jwk` and `did:web` methods
- 📋 W3C Verifiable Credentials (JWT profile), SD-JWT VC and DIF Well Known DID Configuration

✅ implemented, 📋 planned. The full checklist, with Cargo features, tracking issues and links to every specification, is in [`docs/FEATURES.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/FEATURES.md).
The architecture is described in [`docs/DESIGN.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/DESIGN.md).

## Development

See [CONTRIBUTING.md](https://github.com/impierce/identity-kit/blob/HEAD/CONTRIBUTING.md) for how to set up, test and submit changes.
To report a vulnerability, see [SECURITY.md](https://github.com/impierce/identity-kit/blob/HEAD/SECURITY.md).

## Release

Releases are automated with [release-plz](https://release-plz.dev/) and follow [Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html).
Every push to `main` updates a release pull request with the next version and changelog, derived from the [Conventional Commits](https://www.conventionalcommits.org/) since the last release.
Merging it publishes to [crates.io](https://crates.io/crates/identity-kit) and creates the tag and GitHub release.
Versions and `CHANGELOG.md` are never edited by hand.
See [`docs/RELEASE.md`](https://github.com/impierce/identity-kit/blob/HEAD/docs/RELEASE.md) for the versioning rules, changelog filtering and the credential setup.
