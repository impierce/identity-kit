# NIST ACVP ML-DSA test vectors

Test cases extracted from [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server)
`gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json` at commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, a work of the US government. Each file holds one test
case with its test group's properties; the fields are unchanged, only the ones the tests use are
kept. `tests/jose_ml_dsa.rs` runs them.

All three are deterministic signatures of the pure (`external`) interface with an empty context
string, the only kind RFC 9964 §5 allows:

- `ml_dsa_44_sig_gen_tc5.json`: ML-DSA-44, tcId 5, with the expanded private key `sk`: its
  signature pins the external μ.
- `ml_dsa_65_sig_gen_tc44.json`: ML-DSA-65, tcId 44.
- `ml_dsa_87_sig_gen_tc70.json`: ML-DSA-87, tcId 70.

They are not part of the published crate (`include` in `Cargo.toml` lists `tests/vectors` only).
