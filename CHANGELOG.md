# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.3](https://github.com/impierce/identity-kit/compare/v0.0.2...v0.0.3) - 2026-10-18

### Added

- add OpenAPI schemas, preludes and test vectors ([#29](https://github.com/impierce/identity-kit/pull/29))
- *(sd-jwt)* add `sd_jwt_vc` and `domain_linkage` modules ([#26](https://github.com/impierce/identity-kit/pull/26))
- *(vc)* add VCDM 1.1 JWT profile, VCDM 2.0 envelopes and validators ([#25](https://github.com/impierce/identity-kit/pull/25))
- *(methods)* add `did:key`, `did:jwk` and `did:web` methods ([#24](https://github.com/impierce/identity-kit/pull/24))
- *(keys)* add `KeyStore` trait, `KeySigner`, in-memory and software backends ([#21](https://github.com/impierce/identity-kit/pull/21))
- *(resolver)* add `DidResolver`, `DidProducer`, `Resolver` registry, cache and dereferencing ([#22](https://github.com/impierce/identity-kit/pull/22))
- *(did)* add `DidDocument`, `VerificationMethod`, `Service` and resolution types ([#20](https://github.com/impierce/identity-kit/pull/20))
- *(jose)* add `Jwk`, `JwsAlgorithm`, `JwsVerifier` and compact JWS ([#19](https://github.com/impierce/identity-kit/pull/19))
- *(did)* add `Did` and `DidUrl` types ([#4](https://github.com/impierce/identity-kit/pull/4))

### Documentation

- add feature checklist and move release process to `docs/RELEASE.md` ([#18](https://github.com/impierce/identity-kit/pull/18))

### Fixed

- [**breaking**] add cargo-fuzz targets and fix detected flaws ([#27](https://github.com/impierce/identity-kit/pull/27))
- *(jose)* reject RSA signatures that are not modulus-sized ([#23](https://github.com/impierce/identity-kit/pull/23))

## [0.0.2](https://github.com/impierce/identity-kit/compare/v0.0.1...v0.0.2) - 2026-10-17

### Changed

- `identity-kit` is now a library crate; 0.0.1 was a placeholder binary

### Documentation

- describe release process in README ([#3](https://github.com/impierce/identity-kit/pull/3))
- add security policy, contributing guide and code owners
