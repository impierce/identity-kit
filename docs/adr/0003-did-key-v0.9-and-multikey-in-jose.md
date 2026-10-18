# ADR 0003: `did:key` follows v0.9 with Multikey by default, and the Multikey codec lives in `jose`

- Status: accepted
- Date: 2026-10-18

## Context

`docs/DESIGN.md` describes `methods::key` as producing "one `JsonWebKey2020` method with
`publicKeyJwk`" and lists `multibase` and `unsigned-varint` as the building blocks behind the
`did-key` and `did-jwk` features, with `reqwest` behind `did-web`.

The current did:key specification (v0.9) defines the verification method types `Multikey` and
`JsonWebKey` (the Controlled Identifiers 1.0 types), shows `Multikey` with `publicKeyMultibase`
in every example and test vector, and names `JsonWebKey2020` only among the experimental legacy
types. It also defines the `publicKeyFormat` and `enableEncryptionKeyDerivation` resolution
options, and derives an X25519 key agreement method from an Ed25519 key.

The codec behind did:key (a multicodec header plus the raw key, base58btc multibase encoded) is
the same thing as the `publicKeyMultibase` material of a `Multikey` verification method in any
DID document, which `Resolver::resolve_public_key` must turn into a JWK to verify a JWS.
`multibase` 0.9 pulls `base-x`, `data-encoding` and a proc-macro crate for the one alphabet this
crate uses; the multicodec header is a two-byte unsigned varint.

`reqwest` 0.13 selects `aws-lc-rs` through its `rustls` feature, which compiles C and assembly
(NASM on Windows) and carries the OpenSSL license, which `deny.toml` does not allow.

## Decision

1. `methods::key` implements did:key v0.9 as written: `Multikey` with `publicKeyMultibase` is the
   default `KeyFormat`, `JsonWebKey` with `publicKeyJwk` the alternative; the fragment is the
   method-specific id; the two resolution options are honoured per resolution; the derived X25519
   method is embedded under `keyAgreement` as the specification's examples and test vectors show.
   The `@context` is the `https://www.w3.org/ns/did/v1.1` of those examples.
2. The Multikey codec is `Jwk::from_multikey`/`Jwk::to_multikey` in `jose`, always compiled, over
   `bs58` and an in-crate varint and PKCS #1 `RSAPublicKey` encoder, so `did-key` and `did-jwk`
   pull no dependency. `Resolver::resolve_public_key` decodes `publicKeyMultibase` material with
   it, whatever the DID method.
3. `did-web` pulls only `url` and works over any `HttpClient`; the hardened default client is
   behind its own `reqwest` feature (on by default), built on `rustls-no-provider` with the
   `ring` provider and the platform's root certificates. `webpki-root-certs`
   (CDLA-Permissive-2.0) is allowed in `deny.toml` as the Mozilla root store data it is.
4. `did:web` resolution is tested through an in-file `HttpClient`, not `wiremock`: the hardened
   client only speaks HTTPS to public addresses, which a local mock server cannot provide, and the
   resolver's own logic is independent of the transport.

## Consequences

- The did:key test vectors of the specification pass byte for byte; a consumer that needs JWK
  material gets it either from `KeyFormat::JsonWebKey` or from `resolve_public_key`.
- `Multikey` documents from any method, not only did:key, dereference to JWKs.
- `ReqwestClient::new` installs `ring` as the process-wide rustls provider when none is
  installed yet; an application that installed another provider first keeps it.
