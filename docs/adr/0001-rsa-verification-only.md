# ADR 0001: RSA is verification-only, and RUSTSEC-2023-0071 is accepted

- Status: accepted
- Date: 2026-10-17

## Context

`docs/DESIGN.md` lists `rsa` among the building blocks for RS256 and PS256, behind the `rsa`
feature. Every published version of the `rsa` crate (0.9.x and the 0.10 release candidates) is
affected by [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071): private-key
operations are not constant-time (the Marvin attack), so a remote attacker observing timing may
recover the private key. No fixed version exists, and `cargo deny check advisories` fails on it.

`jsonwebtoken` has the same dependency through its `rust_crypto` feature, which this crate enables
only as a dev-dependency to cross-check signatures against `jsonwebtoken` in tests.

## Decision

1. The library uses `rsa` for public-key operations only: `DefaultVerifier` verifies RS256 and
   PS256 signatures and `Jwk::from_spki_der` decodes RSA public keys. No code path in the crate
   performs an RSA private-key operation, so the timing side channel of the advisory is not
   reachable through this crate.
2. RUSTSEC-2023-0071 is ignored in `deny.toml` with that reason. The ignore is revisited whenever
   `rsa` publishes a fix, and whenever any module (a software key store in particular) would sign
   with RSA, which this decision does not cover: RSA signing with the `rsa` crate stays out of the
   crate until the advisory is resolved or an HSM/KMS does the signing.
3. The `rsa` feature depends on the 0.10 release candidate rather than 0.9: it is the line that
   shares `sha2`, `digest`, `signature` and `pkcs8` with `p256`, `k256` and `ed25519-dalek`, so
   the dependency graph carries one version of each.

## Consequences

- `cargo deny check advisories` stays green with one documented ignore.
- Consumers who sign with RSA must do so in a backend outside this crate (PKCS#11, cloud KMS).
- Depending on a release candidate means `cargo update` may need a manual bump of the `rsa`
  requirement when the stable 0.10 is released.
