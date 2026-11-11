# x509-limbo test vectors

X.509 path validation testcases from [C2SP/x509-limbo](https://github.com/C2SP/x509-limbo), under
the Apache License 2.0 (`LICENSE`), taken from `limbo.json` at commit
`519f4bcf6a31d20e1b7011a0586e233dbbd3e732` (SHA-256 of that file
`56799cefd65fc9e0bdb9cb0f97fce6734533b45df3de4fc17fdc7b7b79654fca`). `tests/x509.rs` runs them
against `resolver::X509Resolver`.

- `limbo.json`: the 182 testcases whose id starts with `rfc5280::`, `pathlen::`, `webpki::`,
  `cve::` or `invalid::`, in the suite's own format. Each testcase is unchanged but for its
  `peer_certificate_key`, the private key of the leaf, which is removed. Left out are
  `bettertls::` (9572 testcases on host names and name constraints, 37 MiB), `crl::` (revocation,
  which the resolver does not check), `online::`, `pathological::` and `rfc9881::` (ML-DSA).
- `signer.json`: the chain of the testcase `pathlen::ee-with-intermediate-pathlen-0` as an `x5c`
  array (leaf and intermediate, base64 DER), its root as `trust_anchor`, and the leaf's private
  key converted from the suite's SEC 1 PEM to a JWK. The tests sign tokens with it.

The suite expects what a validator of TLS server certificates does. Where the resolver's verdict
differs, `tests/x509.rs` lists the testcase with the reason (`KNOWN_DIFFERENCES`) and fails when
that list goes stale. To run the whole suite and print every difference:

```sh
X509_LIMBO=/path/to/limbo.json cargo test --features x509 --test x509 -- --ignored --nocapture
```

At the commit above, 6874 of its 9807 testcases agree. Of the rest, 2829 are `bettertls::`
testcases the suite refuses for the host name it validates for, which a token has none of.

The vectors are not part of the published crate (`include` in `Cargo.toml` lists `tests/vectors`
only).
