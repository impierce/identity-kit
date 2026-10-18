# ADR 0005: SD-JWT is implemented in the crate, not taken from `sd-jwt-payload`

- Status: accepted
- Date: 2026-10-18

## Context

`docs/DESIGN.md` and issue #12 put the `sd_jwt_vc` module "on `sd-jwt-payload`", with the
proviso that the dependency must be a crates.io release and, if a fork were needed, be published
under our name first. The crate ground rules exclude dependencies on the SSI libraries this crate
replaces, and `sd-jwt-payload` is one of them: it is maintained alongside those libraries and
pulls their cryptography crate for hashing, where this crate already has `sha2`, base64url and
`serde_json`.

What RFC 9901 asks of an implementation is small and precise: a disclosure is a base64url JSON
array, a digest is a hash over that string, `_sd` arrays and `{"...": digest}` elements are
replaced by the matching disclosures recursively, duplicate digests and unreferenced disclosures
are rejected, and the key binding JWT hashes the serialized SD-JWT. The specification publishes
complete vectors for every step, including the issuer's public key, so an implementation can be
tested against the specification directly, as the crate's test policy requires.

SD-JWT VC adds the Token Status List, whose bit array is ZLIB-compressed, and type metadata.

## Decision

1. **RFC 9901 is implemented in `sd_jwt_vc`**: `Disclosure`, `SdJwt` (parsing, §7.1
   processing, `disclose`/`select` for presentation, key binding), `SdJwtBuilder` (concealment
   by `ClaimPath`, recursive disclosures by concealing a claim and claims inside it, decoys,
   sorted `_sd` arrays, a pluggable salt source so tests can replay the specification's salts).
   `sd-jwt-payload` is not a dependency. The design document's dependency list and feature table
   are updated accordingly, and the layer-boundary check of #14 names `chrono` and
   `miniz_oxide` instead of `sd-jwt-payload` (`getrandom` is already in the lower layer through
   the elliptic-curve crates).
2. **Two small dependencies under the `sd-jwt` feature**: `getrandom` for salts and decoys, and
   `miniz_oxide` (pure Rust) for status list compression, with a decompression limit
   (`StatusList::MAX_BYTES`) so a hostile list cannot exhaust memory.
3. **Processing keeps an "as issued" view.** `Processed` carries the processed payload and a
   second view in which undisclosed array elements remain as their `{"...": digest}` placeholder,
   because type metadata claim paths are evaluated in the coordinates of the issued credential
   (SD-JWT VC §5.6), where undisclosed elements still count. Disclosed claim paths and
   undisclosed element paths are recorded for the same reason.
4. **Presentation by path includes descendants and ancestors.** `SdJwt::disclose(paths)` keeps
   every disclosure at or beneath each path, plus the disclosures each is nested in, which is
   what a holder means by "disclose my address"; `SdJwt::select` takes a predicate and only
   checks that parents are kept.
5. **The SD-JWT VC validator resolves DID-keyed issuers only.** `kid` must be a DID URL and
   `iss` the DID it belongs to, as for the JWT validators. JWT VC issuer metadata (`iss` an
   HTTPS URL) and `x5c` chains are left to a later change; a `KeyResolver` implementation can
   cover an HTTPS issuer meanwhile.
6. **`StatusListCheck` trusts the key `kid` resolves to.** Whether that key may speak for a
   list is policy the application enforces around the resolver.
7. **Type metadata is checked on request**, through `TypeMetadata::check_claims`, not inside
   the validator: the specification makes processing it a matter of policy, and retrieval is the
   application's (the `vct` URL, a registry, a cache).
8. **Domain linkage origins are normalized** to `scheme://host[:port]`, `https` assumed when
   no scheme is given, before comparison: the DIF specification's own JWT example writes
   `identity.foundation` while its Linked Data example writes `https://identity.foundation`.
   The builder stores the normalized form. The format rules are applied strictly: no `typ`, no
   header parameter beyond `alg` and `kid`, no claim beyond `iss`, `sub`, `nbf`, `exp` and `vc`,
   no `id`. Linked Data Proof entries of a configuration are carried as data and never validated.

## Consequences

- No dependency on the libraries this crate replaces; the crate controls its own SD-JWT
  behaviour and error types, and the RFC 9901 vectors are the tests.
- The `sd_jwt_vc` module is larger than a wrapper would have been (the RFC 9901 core is about
  as large as the SD-JWT VC layer over it), and interoperability bugs are ours to fix.
- An SD-JWT VC from an issuer identified by an HTTPS `iss` does not validate with the shipped
  `KeyResolver`; support needs a resolver over JWT VC issuer metadata.
- The CI boundary check of #14 should assert the absence of `chrono` and `miniz_oxide` from the
  lower-layer build.
