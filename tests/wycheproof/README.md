# Project Wycheproof ECDSA test vectors

Copied unchanged from [C2SP/wycheproof](https://github.com/C2SP/wycheproof) `testvectors_v1/` at
commit `7a325932231bd7a724c791c8b0d65ea4d6d2f435`, under the Apache License 2.0 (`LICENSE`).
`tests/jose_ecdsa.rs` runs them against `jose::ecdsa_signature_from_der`.

- `ecdsa_secp256r1_sha256_test.json`: P-256 with SHA-256 (ES256).
- `ecdsa_secp256k1_sha256_test.json`: secp256k1 with SHA-256 (ES256K), a high `s` valid.
- `ecdsa_secp256k1_sha256_bitcoin_test.json`: the same with a high `s` invalid, as Bitcoin has it.

They are not part of the published crate (`include` in `Cargo.toml` lists `tests/vectors` only).
