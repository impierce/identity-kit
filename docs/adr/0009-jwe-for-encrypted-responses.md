# ADR 0009: JWE for encrypted responses: ECDH-ES on P-256 with AES-GCM, in the compact serialization

- Status: accepted
- Date: 2026-11-17

## Context

Principle 3 of `DESIGN.md` limited the crate to JWT/JWS and SD-JWT, and `jose` said "JWE is out
of scope". The OpenID4VC High Assurance Interoperability Profile 1.0 (HAIP) §5 makes encryption
part of every presentation:

- "Response encryption MUST be performed as specified in Section 8.3 of [OIDF.OID4VP]. The JWE
  alg (algorithm) header parameter ... value ECDH-ES ..., with key agreement utilizing keys on
  the P-256 curve ... MUST be supported."
- "The JWE enc (encryption algorithm) header parameter ... values A128GCM and A256GCM ... MUST
  be supported by Verifiers. Wallets MUST support A128GCM or A256GCM, or both."
- "Verifiers MUST supply ephemeral encryption public keys specific to each Authorization Request
  passed via client metadata."

OpenID4VP §8.3 adds what a Wallet does with the Verifier's keys: the `alg` of the chosen JWK is
the JWE `alg`, the JWE carries that key's `kid`, and the payload is a JSON object of the
Authorization Response parameters. Without JWE here, a Wallet or Verifier on this crate takes a
second JOSE implementation, with its own key types, for one operation in each direction.

## Decision

1. **A `jwe` feature in `jose`, off by default.** `CompactJwe` decodes, encrypts and decrypts;
   `JweHeader`, `JweAlgorithm` and `JweEncryption` name what it supports. It is in the lower
   layer: nothing in it is about credentials.

2. **Only what HAIP requires.** `alg` `ECDH-ES` in the Direct Key Agreement mode (RFC 7518 §4.6)
   on P-256, `enc` `A128GCM` and `A256GCM` (RFC 7518 §5.3), the compact serialization. Left out
   until something requires them: key wrapping (`ECDH-ES+A*KW`, `A*KW`, `RSA-OAEP`), `dir`,
   AES-CBC-HMAC, X25519 and other curves, the JSON serialization, several recipients, `zip`
   and HPKE. The enums are `#[non_exhaustive]`, so each is a compatible addition.

3. **RustCrypto for the primitives, the Concat KDF in the crate.** `aes-gcm` is of the family
   `p256` and `sha2` come from, and `p256` gains its `ecdh` feature. The Concat KDF of NIST
   SP 800-56A §5.8.1 is a loop over SHA-256 that RFC 7518 Appendix C pins down. `ring` was not
   taken: its ECDH keys cannot outlive one agreement, and a Verifier keeps its key from the
   request to the response.

4. **The recipient's key behind a trait.** `JweDecrypter::shared_secret` computes the ECDH shared
   secret `Z` with the sender's `epk`; the crate derives the Content Encryption Key and
   decrypts. `EcdhKey` is a P-256 key in memory: generated per request, published with
   `use: enc` and `alg: ECDH-ES`, and written to and read from a private JWK between the request
   and the response; a JWK whose `use` or `alg` says it is for something else is not read. `KeyStore` gains no key agreement: HAIP's encryption keys live for one
   request, and an operation on that trait is one every backend has to answer. A key kept in an
   HSM implements `JweDecrypter` instead.

5. **Strict decoding.** An unsupported `alg` or `enc` is named, cut short so a hostile header
   cannot fill a log; `crit` in any form and `zip` are refused, as a recipient must not ignore
   them; the JWE Encrypted Key must be empty; `epk` must be a public
   P-256 point on the curve, which rules out invalid-curve attacks; the IV is 96 bits and the tag
   128. The protected header is authenticated as received. A shared secret of other than 32
   bytes from a `JweDecrypter` is a key agreement error, so a faulty backend is not mistaken
   for an altered JWE. A tag that does not verify gives one error, which says nothing about
   why.

6. **Encryption follows OpenID4VP §8.3.** The recipient key must have an `alg`, the header's
   ("The alg parameter MUST be present in the JWKs"); a key with a `use` other than `enc`,
   `key_ops` that allow no key agreement, or private parameters is refused. The JWE takes the
   key's `kid` when the header has none, and refuses a `kid` that is not the key's, a key
   without one included. A header decoding would refuse (`crit`, `zip`, an additional
   parameter named like a field) is refused too.

## Consequences

- Principle 3 of `DESIGN.md` and the ground rule in `AGENTS.md` admit JWE for encrypted
  responses, as this ADR bounds it.
- With `jwe` on, the build adds `aes-gcm` and the crates under it (`aes`, `ctr`, `ghash`,
  `polyval`, `aead`, `cipher`, `universal-hash`). The default build does not change.
- The payload is bytes. Reading it as an Authorization Response, choosing the Verifier key from
  client metadata, and listing `encrypted_response_enc_values_supported` are the protocol
  library's.
- No published vector covers ECDH-ES with A256GCM end to end. The tests cover the parts: RFC 7518
  Appendix C (ECDH-ES and the Concat KDF for a 128-bit key), RFC 7520 §5.5 (the same for a
  256-bit key), RFC 7520 §5.6 (A128GCM), RFC 7516 Appendix A.1 (A256GCM), and the encrypted
  response of OpenID4VP §8.3 (ECDH-ES with A128GCM, whole). The
  OpenID Foundation's conformance suite runs outside this repository.
