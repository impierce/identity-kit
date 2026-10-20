# Features

Everything `identity-kit` implements or plans to implement, grouped by module. The architecture
behind the list is in [`DESIGN.md`](DESIGN.md); each planned row links to the GitHub issue that
tracks it. Tick a row off in the pull request that implements it.

| Status | Meaning                                      |
| ------ | -------------------------------------------- |
| ✅     | Implemented on `main`, covered by spec tests |
| 🚧     | In progress                                  |
| 📋     | Planned, issue open                          |

The _Cargo feature_ column is empty where the functionality is always compiled in. All features are
additive; see [`DESIGN.md`](DESIGN.md#features) for what each one pulls in.

## Lower layer

### `did`: DID data model

| Feature                                                                                                      | Status | Cargo feature | Specification                                                                                     | Issue                                                   |
| ------------------------------------------------------------------------------------------------------------ | :----: | ------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `Did` and `DidUrl`: parsing, validation, `join`, serde as strings                                            |   ✅   |               | [DID Core §3.1, §3.2](https://www.w3.org/TR/did-core/#identifier), [RFC 3986][rfc3986]           | [#5](https://github.com/impierce/identity-kit/issues/5) |
| `DidMethod`: method name with optional namespace (`did:demo`, `did:demo:dev`), `matches` a `Did`, serde as string |   ✅   |               | [DID Core §3.1](https://www.w3.org/TR/did-core/#did-syntax)                                      | [#51](https://github.com/impierce/identity-kit/issues/51) |
| `DidDocument`, `VerificationMethod`, `Service`, verification relationships, open extension properties        |   ✅   |               | [DID Core][did-core], [Controlled Identifiers 1.0][cid]                                           | [#6](https://github.com/impierce/identity-kit/issues/6) |
| Document operations: builder, insert/remove methods and services, relationship management, method resolution |   ✅   |               | [DID Core][did-core]                                                                              | [#6](https://github.com/impierce/identity-kit/issues/6) |
| `ResolutionResult`, document and resolution metadata, error vocabulary                                       |   ✅   |               | [DID Resolution][did-resolution]                                                                  | [#6](https://github.com/impierce/identity-kit/issues/6) |
| Deterministic JSON representation (`@context` first, empties omitted, insertion order kept)                  |   ✅   |               | [DID Core §6.2](https://www.w3.org/TR/did-core/#json)                                             | [#6](https://github.com/impierce/identity-kit/issues/6) |

### `jose`: JWK and JWS

| Feature                                                                | Status | Cargo feature | Specification                                                         | Issue                                                   |
| ---------------------------------------------------------------------- | :----: | ------------- | --------------------------------------------------------------------- | ------------------------------------------------------- |
| `Jwk` with private parameters redacted from `Debug`, `public()` view   |   ✅   |               | [RFC 7517][rfc7517]                                                   | [#7](https://github.com/impierce/identity-kit/issues/7) |
| SHA-256 JWK thumbprint                                                 |   ✅   |               | [RFC 7638][rfc7638]                                                   | [#7](https://github.com/impierce/identity-kit/issues/7) |
| `Jwk::from_spki_der` for keys returned by KMS and HSM backends         |   ✅   |               | [RFC 5280 §4.1.2.7](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7) | [#7](https://github.com/impierce/identity-kit/issues/7) |
| Compact JWS decode, `Signer` and `JwsVerifier` traits, async `encode_compact` |   ✅   |               | [RFC 7515][rfc7515]                                                   | [#7](https://github.com/impierce/identity-kit/issues/7) |
| `DefaultVerifier`: EdDSA, ES256 (ES384 is in `JwsAlgorithm` but not verified) |   ✅   |               | [RFC 7518][rfc7518], [RFC 8037][rfc8037]                              | [#7](https://github.com/impierce/identity-kit/issues/7) |
| ES256K verification via `k256`                                         |   ✅   | `secp256k1`   | [RFC 8812][rfc8812]                                                   | [#7](https://github.com/impierce/identity-kit/issues/7) |
| RSA algorithms (RS256, PS256), verification only ([ADR 0001](adr/0001-rsa-verification-only.md)) |   ✅   | `rsa`         | [RFC 7518 §3.3, §3.5](https://www.rfc-editor.org/rfc/rfc7518#section-3.3) | [#7](https://github.com/impierce/identity-kit/issues/7) |

### `keys`: key stores

| Feature                                                                                  | Status | Cargo feature  | Specification                                   | Issue                                                     |
| ---------------------------------------------------------------------------------------- | :----: | -------------- | ----------------------------------------------- | --------------------------------------------------------- |
| `KeyStore` trait: opaque `KeyId`, one algorithm per key, declared capabilities, async `sign` |   ✅   |                |                                                 | [#8](https://github.com/impierce/identity-kit/issues/8)   |
| `KeySigner` adapter implementing `jose::Signer` over any `KeyStore`                       |   ✅   |                | [RFC 7515][rfc7515]                             | [#8](https://github.com/impierce/identity-kit/issues/8)   |
| `InMemoryKeyStore` with optional deterministic seed                                       |   ✅   | `in-memory`    |                                                 | [#8](https://github.com/impierce/identity-kit/issues/8)   |
| `SoftwareKeyStore`: private JWK set file, permission check, `zeroize`, atomic writes       |   ✅   | `software`     | [RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517#section-5) | [#8](https://github.com/impierce/identity-kit/issues/8)   |
| `keys::testsuite`: one behavioural suite every backend must pass                           |   ✅   | `test-vectors` |                                                 | [#8](https://github.com/impierce/identity-kit/issues/8)   |
| `Pkcs11KeyStore`, tested against SoftHSM2 in CI                                           |   ✅   | `pkcs11`       | [PKCS #11 v3.1][pkcs11]                         | [#13](https://github.com/impierce/identity-kit/issues/13) |

### `resolver`: resolution and production

| Feature                                                                             | Status | Cargo feature | Specification                    | Issue                                                   |
| ----------------------------------------------------------------------------------- | :----: | ------------- | -------------------------------- | ------------------------------------------------------- |
| `DidResolver` and `DidProducer` traits, `MethodCapabilities`                        |   ✅   |               | [DID Resolution][did-resolution] | [#9](https://github.com/impierce/identity-kit/issues/9) |
| `Resolver` registry with builder, `DocumentCache` with TTL                          |   ✅   |               | [DID Resolution][did-resolution] | [#9](https://github.com/impierce/identity-kit/issues/9) |
| DID URL dereferencing and `resolve_public_key`                                      |   ✅   |               | [DID Resolution §4][did-resolution] | [#9](https://github.com/impierce/identity-kit/issues/9) |

### `methods`: DID methods

| Feature                                                                                                | Status | Cargo feature | Specification                                                      | Issue                                                     |
| ------------------------------------------------------------------------------------------------------ | :----: | ------------- | ------------------------------------------------------------------ | --------------------------------------------------------- |
| `did:key`: Ed25519, P-256, secp256k1, RSA and X25519 multicodec keys, base58btc multibase              |   ✅   | `did-key`     | [did:key][did-key], [multicodec][multicodec], [multibase][multibase] | [#10](https://github.com/impierce/identity-kit/issues/10) |
| `did:jwk`: base64url JWK as method-specific id, created in JCS canonical form                          |   ✅   | `did-jwk`     | [did:jwk][did-jwk], [RFC 8785][rfc8785]                            | [#10](https://github.com/impierce/identity-kit/issues/10), [#30](https://github.com/impierce/identity-kit/issues/30) |
| `did:web`: origin mapping, resolver over an injected `HttpClient`, hardened default client, producer   |   ✅   | `did-web`, `reqwest` | [did:web][did-web]                                                 | [#10](https://github.com/impierce/identity-kit/issues/10) |
| `ReqwestClient::builder` for development and tests: `dangerous_allow_loopback`, `dangerous_allow_private_network`; plain `http` only when every address is local, link-local always refused | ✅ | `local-network` | [did:web][did-web] | [#37](https://github.com/impierce/identity-kit/issues/37) |

## Upper layer

### `vc`: verifiable credentials

| Feature                                                                                                     | Status | Cargo feature | Specification                                  | Issue                                                     |
| ----------------------------------------------------------------------------------------------------------- | :----: | ------------- | ---------------------------------------------- | --------------------------------------------------------- |
| `Credential` and `Presentation` builders for the VCDM 1.1 JWT profile, `to_jwt_claims` mapping              |   ✅   | `vc`          | [VCDM 1.1 §6.3.1][vcdm11-jwt]                  | [#11](https://github.com/impierce/identity-kit/issues/11) |
| `CredentialV2` and `EnvelopedVc` for VCDM 2.0 enveloped credentials                                         |   ✅   | `vc`          | [VCDM 2.0][vcdm20], [VC-JOSE-COSE][vc-jose-cose] | [#11](https://github.com/impierce/identity-kit/issues/11) |
| `JwtCredentialValidator`, `JwtPresentationValidator`: issuer and holder binding, clock-skew leeway, `FailFast`, `StatusCheck` hook |   ✅   | `vc`          | [VCDM 1.1][vcdm11], [VCDM 2.0][vcdm20]         | [#11](https://github.com/impierce/identity-kit/issues/11) |
| `JwtPresentationValidator::validate_v2`, `decode_presentation_v2`: VCDM 2.0 `vp+jwt` presentations of enveloped `vc+jwt` credentials |   ✅   | `vc`          | [VCDM 2.0][vcdm20], [VC-JOSE-COSE][vc-jose-cose] | [#36](https://github.com/impierce/identity-kit/issues/36) |
| Additional accepted header `typ` values per validation (`additional_typ`)                                   |   ✅   | `vc`          | [VCDM 1.1][vcdm11], [VC-JOSE-COSE][vc-jose-cose] | [#34](https://github.com/impierce/identity-kit/issues/34) |

### `sd_jwt_vc`: SD-JWT verifiable credentials

| Feature                                                              | Status | Cargo feature | Specification                                  | Issue                                                     |
| -------------------------------------------------------------------- | :----: | ------------- | ---------------------------------------------- | --------------------------------------------------------- |
| Builder with first-class `jti`, parser, `SdJwtCredentialValidator`   |   ✅   | `sd-jwt`      | [RFC 9901][rfc9901], [SD-JWT VC][sd-jwt-vc]    | [#12](https://github.com/impierce/identity-kit/issues/12) |
| `Status`, `StatusListRef`, `StatusMechanism`                         |   ✅   | `sd-jwt`      | [Token Status List][status-list]               | [#12](https://github.com/impierce/identity-kit/issues/12) |
| Type metadata                                                        |   ✅   | `sd-jwt`      | [SD-JWT VC §6][sd-jwt-vc]                      | [#12](https://github.com/impierce/identity-kit/issues/12) |
| `SdJwtCredentialV2`: a VCDM 2.0 credential secured with SD-JWT (`vc+sd-jwt`, `application/vc+sd-jwt`), told apart from an SD-JWT VC by `typ` and payload | ✅ | `sd-jwt` | [VC-JOSE-COSE §3.2.1][vc-jose-cose] | [#49](https://github.com/impierce/identity-kit/issues/49) |
| `SdJwtCredentialV2Builder`: conceal credential properties, decoys, `cnf`, `status`, `iat`/`exp` beside `validFrom`/`validUntil` | ✅ | `sd-jwt` | [VC-JOSE-COSE §3.2.1][vc-jose-cose], [RFC 9901][rfc9901] | [#49](https://github.com/impierce/identity-kit/issues/49) |
| `SdJwtCredentialValidator::validate_v2`: issuer binding, validity period, key binding, `credentialStatus` and `status` | ✅ | `sd-jwt` | [VC-JOSE-COSE §3.2.1][vc-jose-cose], [RFC 9901 §7][rfc9901] | [#49](https://github.com/impierce/identity-kit/issues/49) |
| `JwtPresentationValidator::validate_v2` and `decode_presentation_v2` unwrap `application/vc+sd-jwt` envelopes (`EnvelopedVc::to_sd_jwt`, `PresentedCredentialV2`), key binding required per `PresentationValidationOptions::key_binding` | ✅ | `sd-jwt` | [VC-JOSE-COSE §3.2.2][vc-jose-cose] | [#49](https://github.com/impierce/identity-kit/issues/49) |

### `domain_linkage`: DID configuration

| Feature                                                                              | Status | Cargo feature    | Specification                              | Issue                                                     |
| ------------------------------------------------------------------------------------ | :----: | ---------------- | ------------------------------------------ | --------------------------------------------------------- |
| `DomainLinkageConfiguration` and credential builder                                  |   ✅   | `domain-linkage` | [Well Known DID Configuration][did-config] | [#12](https://github.com/impierce/identity-kit/issues/12) |
| Validator: `iss == sub`, single `origin`, `exp` present, subject matches, at-least-one across DIDs |   ✅   | `domain-linkage` | [Well Known DID Configuration][did-config] | [#12](https://github.com/impierce/identity-kit/issues/12) |
| `LinkedDomains` service entries: `service` builds one, `services` reads the origin string, `{"origins": [...]}` and array forms from a document, invalid entries reported | ✅ | `domain-linkage` | [Well Known DID Configuration][did-config] | [#38](https://github.com/impierce/identity-kit/issues/38) |
| `fetch_configuration` over an `HttpClient` (HTTPS only): "not published" (`404`/`410`) told apart from failures, which keep their cause | ✅ | `domain-linkage` | [Well Known DID Configuration][did-config] | [#38](https://github.com/impierce/identity-kit/issues/38) |
| `DomainLinkageClient`: fetches and validates an origin, one DID at an origin, or every origin of a DID document or resolved DID (at most `max_origins`, 32 by default, fetched), reporting per origin | ✅ | `domain-linkage` | [Well Known DID Configuration][did-config] | [#38](https://github.com/impierce/identity-kit/issues/38) |
| `DomainLinkageValidator` validates at most `max_credentials` (32 by default) entries of a configuration; the rest report `TooManyCredentials` without resolving their issuer | ✅ | `domain-linkage` | [Well Known DID Configuration][did-config] | [#45](https://github.com/impierce/identity-kit/issues/45) |

### `linked_vp`: linked presentations

| Feature                                                                                                   | Status | Cargo feature | Specification                    | Issue                                                     |
| --------------------------------------------------------------------------------------------------------- | :----: | ------------- | -------------------------------- | --------------------------------------------------------- |
| `LinkedVerifiablePresentation` service entries: `service` builds one, `services` reads them from a document, invalid entries reported | ✅ | `linked-vp` | [Linked VP][linked-vp] | [#34](https://github.com/impierce/identity-kit/issues/34) |
| `LinkedPresentationBuilder`: a VCDM 1.1 presentation JWT signed by the holder, `iss == sub == holder`, optional `exp`, no `aud` or `nonce` | ✅ | `linked-vp` | [Linked VP][linked-vp] | [#34](https://github.com/impierce/identity-kit/issues/34) |
| `LinkedVpValidator`: holder and `iss` are the linking DID, key under `authentication`, credentials' subject is the holder, the specification's `typ` values accepted | ✅ | `linked-vp` | [Linked VP][linked-vp] | [#34](https://github.com/impierce/identity-kit/issues/34) |
| `LinkedVpClient`: fetches over an `HttpClient` (HTTPS only), reports per URL; JSON-LD presentations, IPFS and hashlink verification unsupported | ✅ | `linked-vp` | [Linked VP][linked-vp] | [#34](https://github.com/impierce/identity-kit/issues/34) |
| `LinkedVpClient` fetches at most `max_urls` (32 by default) URLs of a document; the rest report `TooManyUrls` without being fetched | ✅ | `linked-vp` | [Linked VP][linked-vp] | [#45](https://github.com/impierce/identity-kit/issues/45) |

## Tooling and integration

| Feature                                                                        | Status | Cargo feature | Specification                                | Issue                                                     |
| ------------------------------------------------------------------------------ | :----: | ------------- | -------------------------------------------- | --------------------------------------------------------- |
| OpenAPI schemas for the public types                                           |   ✅   | `utoipa`      | [OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.0) | [#14](https://github.com/impierce/identity-kit/issues/14) |
| Re-exported conformance vectors (`vectors`)                                    |   ✅   | `test-vectors` |                                             | [#14](https://github.com/impierce/identity-kit/issues/14) |
| CI proof of the layer boundary (`--no-default-features --features did-key,software` builds) |   ✅   |               |                                              | [#14](https://github.com/impierce/identity-kit/issues/14) |
| `cargo hack --each-feature` and `cargo publish --dry-run` in CI; `cargo-semver-checks` through release-plz | ✅ | |                                        | [#14](https://github.com/impierce/identity-kit/issues/14) |
| A `prelude` per layer                                                          |   ✅   |               |                                              | [#14](https://github.com/impierce/identity-kit/issues/14) |

## Out of scope

Decided in [`DESIGN.md`](DESIGN.md#principles); each would need an ADR to revisit.

- JSON-LD processing and Data Integrity proofs. `@context` is carried as opaque data.
- Vendor-specific key backends (cloud KMS services). They implement `KeyStore` from their own crates.
- A closed enum of DID methods or key backends.

## Standards and specifications

| Specification                                | Body        | Used by                                   |
| -------------------------------------------- | ----------- | ----------------------------------------- |
| [DID Core 1.0][did-core]                     | W3C         | `did`, `methods`                          |
| [DID Resolution][did-resolution]             | W3C         | `did`, `resolver`                         |
| [Controlled Identifiers 1.0][cid]            | W3C         | `did` (verification material types)       |
| [VC Data Model 1.1][vcdm11]                  | W3C         | `vc`, `linked_vp`                         |
| [VC Data Model 2.0][vcdm20]                  | W3C         | `vc`                                      |
| [Securing VCs using JOSE and COSE][vc-jose-cose] | W3C     | `vc` (enveloped credentials), `sd_jwt_vc` (`vc+sd-jwt`) |
| [did:key][did-key]                           | W3C CCG     | `methods::key`                            |
| [did:web][did-web]                           | W3C CCG     | `methods::web`, `domain_linkage`, `linked_vp` |
| [did:jwk][did-jwk]                           | Community   | `methods::jwk`                            |
| [Well Known DID Configuration][did-config]   | DIF         | `domain_linkage`                          |
| [Linked Verifiable Presentation][linked-vp]  | DIF         | `linked_vp`                               |
| [RFC 3986: URI generic syntax][rfc3986]      | IETF        | `did`                                     |
| [RFC 7515: JWS][rfc7515]                     | IETF        | `jose`, `keys`                            |
| [RFC 7517: JWK][rfc7517]                     | IETF        | `jose`, `keys::software`                  |
| [RFC 7518: JWA][rfc7518]                     | IETF        | `jose`                                    |
| [RFC 7638: JWK thumbprint][rfc7638]          | IETF        | `jose`                                    |
| [RFC 8037: EdDSA in JOSE][rfc8037]           | IETF        | `jose`                                    |
| [RFC 8785: JSON Canonicalization Scheme][rfc8785] | IETF   | `methods::jwk`                            |
| [RFC 8812: secp256k1 in JOSE][rfc8812]       | IETF        | `jose` (`secp256k1`)                      |
| [RFC 9901: SD-JWT][rfc9901]                  | IETF        | `sd_jwt_vc`                               |
| [SD-JWT VC][sd-jwt-vc]                       | IETF draft  | `sd_jwt_vc`                               |
| [Token Status List][status-list]             | IETF draft  | `sd_jwt_vc`                               |
| [PKCS #11 v3.1][pkcs11]                      | OASIS       | `keys::pkcs11`                            |
| [multicodec][multicodec], [multibase][multibase] | Multiformats | `methods::key`                        |

[did-core]: https://www.w3.org/TR/did-core/
[did-resolution]: https://www.w3.org/TR/did-resolution/
[cid]: https://www.w3.org/TR/cid-1.0/
[vcdm11]: https://www.w3.org/TR/vc-data-model/
[vcdm11-jwt]: https://www.w3.org/TR/vc-data-model/#json-web-token
[vcdm20]: https://www.w3.org/TR/vc-data-model-2.0/
[vc-jose-cose]: https://www.w3.org/TR/vc-jose-cose/
[did-key]: https://w3c-ccg.github.io/did-key-spec/
[did-web]: https://w3c-ccg.github.io/did-method-web/
[did-jwk]: https://github.com/quartzjer/did-jwk/blob/main/spec.md
[did-config]: https://identity.foundation/.well-known/resources/did-configuration/
[linked-vp]: https://identity.foundation/linked-vp/spec/v1.0.0/
[rfc3986]: https://www.rfc-editor.org/rfc/rfc3986
[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[rfc8785]: https://www.rfc-editor.org/rfc/rfc8785
[rfc8812]: https://www.rfc-editor.org/rfc/rfc8812
[rfc9901]: https://www.rfc-editor.org/rfc/rfc9901
[sd-jwt-vc]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
[status-list]: https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/
[pkcs11]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.html
[multicodec]: https://github.com/multiformats/multicodec
[multibase]: https://github.com/multiformats/multibase
