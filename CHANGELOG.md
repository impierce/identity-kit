# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/impierce/identity-kit/compare/v0.2.1...v0.2.2) - 2026-10-25

### Added

- *(sd-jwt)* serialize `StatusType` ([#103](https://github.com/impierce/identity-kit/pull/103))

## [0.2.1](https://github.com/impierce/identity-kit/compare/v0.2.0...v0.2.1) - 2026-10-24

### Added

- *(vc)* check `status` claim of JWT credentials ([#94](https://github.com/impierce/identity-kit/pull/94))

### Documentation

- state vulnerability response time, test policy and bug reporting ([#91](https://github.com/impierce/identity-kit/pull/91))

## [0.2.0](https://github.com/impierce/identity-kit/compare/v0.1.0...v0.2.0) - 2026-10-23

### Added

- *(resolver)* [**breaking**] add `KeyReference`, `KeyRole` and generic `KeyResolver` ([#74](https://github.com/impierce/identity-kit/pull/74))
- *(vc)* [**breaking**] replace `SdJwtStatusCheck` with one `StatusCheck` over `CredentialStatus` ([#73](https://github.com/impierce/identity-kit/pull/73))
- *(identity)* add `Identity` trait, `IdentityKind`, `Identifier` and `KeyStoreIdentity` ([#71](https://github.com/impierce/identity-kit/pull/71))
- *(jose)* add `ecdsa_signature_from_der` and `normalize_ecdsa_signature` ([#64](https://github.com/impierce/identity-kit/pull/64))
- *(jose)* add `Jwk::from_pkcs1_der` and `to_pkcs1_der` ([#70](https://github.com/impierce/identity-kit/pull/70))
- *(keys)* [**breaking**] make `KeySigner` generic over store handle, add `from_public_jwk` ([#63](https://github.com/impierce/identity-kit/pull/63))
- *(vc)* move `ClaimPath` out of `sd-jwt` feature, add `utoipa` schema ([#66](https://github.com/impierce/identity-kit/pull/66))
- *(jose)* move `JwtClaims` and `OneOrMany` to `jose`, add `CompactJws::claims` ([#65](https://github.com/impierce/identity-kit/pull/65))
- *(keys)* add `Pkcs11KeyStore` over `cryptoki`, tested against SoftHSM2 ([#48](https://github.com/impierce/identity-kit/pull/48))
- *(did)* add `DidMethod` (method name with optional namespace) ([#59](https://github.com/impierce/identity-kit/pull/59))
- *(methods)* add `local-network` opt-in for `ReqwestClient` ([#47](https://github.com/impierce/identity-kit/pull/47))
- *(sd-jwt)* [**breaking**] add VCDM 2.0 credentials secured with SD-JWT (`vc+sd-jwt`) ([#58](https://github.com/impierce/identity-kit/pull/58))
- *(linked-vp, domain-linkage)* cap URLs fetched and credentials validated per document ([#46](https://github.com/impierce/identity-kit/pull/46))
- *(domain-linkage)* fetch DID configurations through `HttpClient` ([#44](https://github.com/impierce/identity-kit/pull/44))
- *(vc)* validate VCDM 2.0 presentations (`vp+jwt`) ([#43](https://github.com/impierce/identity-kit/pull/43))
- *(linked-vp)* add DIF Linked Verifiable Presentation ([#42](https://github.com/impierce/identity-kit/pull/42))
- *(methods)* [**breaking**] create `did:jwk` in JCS canonical form (RFC 8785) ([#40](https://github.com/impierce/identity-kit/pull/40))
- *(did)* [**breaking**] include cause of failed resolution in `ResolutionError` ([#39](https://github.com/impierce/identity-kit/pull/39))

### Dependencies

- *(deps)* [**breaking**] bump jsonwebtoken to 11, bump base64 to 0.23 ([#33](https://github.com/impierce/identity-kit/pull/33))

### Documentation

- *(jose)* ES256 verification accepts high-S signatures ([#87](https://github.com/impierce/identity-kit/pull/87))

### Fixed

- *(vc)* refuse SD-JWT payloads in JWT validators ([#85](https://github.com/impierce/identity-kit/pull/85))
- *(methods)* `ReqwestClient::new` uses no proxy ([#84](https://github.com/impierce/identity-kit/pull/84))
- *(jose)* reject RSA keys shorter than 2048 bits ([#83](https://github.com/impierce/identity-kit/pull/83))
- *(sd-jwt)* limit nesting depth in `SdJwt::process` ([#82](https://github.com/impierce/identity-kit/pull/82))
- *(keys)* destroy both PKCS#11 objects when `delete` fails on one ([#60](https://github.com/impierce/identity-kit/pull/60))

## [0.1.0](https://github.com/impierce/identity-kit/compare/v0.0.2...v0.1.0) - 2026-10-18

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

### Other

- [**breaking**] raise MSRV to 1.95 under a six-month policy ([#31](https://github.com/impierce/identity-kit/pull/31))

## [0.0.2](https://github.com/impierce/identity-kit/compare/v0.0.1...v0.0.2) - 2026-10-17

### Changed

- `identity-kit` is now a library crate; 0.0.1 was a placeholder binary

### Documentation

- describe release process in README ([#3](https://github.com/impierce/identity-kit/pull/3))
- add security policy, contributing guide and code owners
