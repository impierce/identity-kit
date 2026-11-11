# ADR 0008: `x5c` certificate chains are validated by `rustls-webpki` against the application's trust anchors, and the verifier's resolvers choose the mechanism

- Status: accepted
- Date: 2026-11-11

## Context

`KeyReference::from_jws` has read an `x5c` header into `KeyReference::X509Chain` since ADR 0006,
and nothing resolved it. The OpenID4VC High Assurance Interoperability Profile 1.0 (HAIP), which
the EUDI Wallet ecosystem builds on, makes X.509 the mandatory way to find a key:

- §6.1.1: an SD-JWT VC MUST carry the issuer's signing certificate and its chain in `x5c`, and
  Issuer, Wallet and Verifier MUST support validating the issuer signature that way.
- §6.1: the key of a Status List Token MUST be in its `x5c`.
- §4.1, §4.4.1, §4.5.1, §5: signed issuer metadata, Wallet Attestations, key attestations and
  signed presentation requests use `x5c` too.
- Everywhere: "The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE
  header", and the signing certificate "MUST NOT be self-signed".
- §7: ES256 MUST be supported.

SD-JWT VC §3.5 (in draft 13, which HAIP cites) defines the mechanism, *Inline X.509
Certificates*. The current editor's draft, which answers the IESG review, says more: the
recipient validates the chain "according to RFC 7515 §4.1.6 and RFC 5280 against a trust anchor permitted
for the Issuer according to policy (a certificate in the `x5c` header parameter is not a trust
anchor merely because it is included there)". It adds three things that shape this design:

- "the Issuer of the Verifiable Digital Credential is the subject of the end-entity
  certificate", and `iss` is optional.
- "An `iss` claim, if present, is not authenticated by this mechanism": a recipient "MUST NOT
  treat inputs of other mechanisms as identifying the Issuer unless its policy binds them to
  that identity, for example an `iss` value to the end-entity certificate through a Subject
  Alternative Name".
- "The recipient's policy determines which mechanism applies to an Issuer; the SD-JWT VC does
  not."

## Decision

1. **A `KeyResolver`, behind the `x509` feature, in the lower layer.** `resolver::X509Resolver`
   resolves `KeyReference::X509Chain` to the key of the first certificate. The application
   supplies the trust anchors; the crate ships none.

2. **Path validation is `rustls-webpki`'s, certificate inspection `x509-cert`'s.**
   `rustls-webpki` is already in the dependency tree under `reqwest`, is audited, and builds
   and checks paths per RFC 5280 §6: signatures, validity, `basicConstraints`, path length,
   name constraints, unknown critical extensions, with a budget against expensive chains. Its
   `ExtendedKeyUsageValidator` lets the resolver accept any extended key usage, since the
   specifications define none for credential issuers. It verifies with `ring`, as `rustls`
   does here. The alternative, path validation of our own over a certificate parser, would be
   security-critical code to maintain for no gain.
   `rustls-webpki` reads only what path validation needs, so `x509-cert` (RustCrypto, the
   family `p256` and `der` come from) reads the rest: the subject as a string, Subject
   Alternative Names, key identifiers, `keyUsage`.

3. **Checks added around it.** The x509-limbo suite showed what `rustls-webpki` leaves to its
   caller; the resolver adds:
   - HAIP's two rules: the first certificate is not self-signed, and no certificate of the
     chain is one of the trust anchors. They hold for every chain, not as an option: X.509 is
     here for HAIP, and relaxing a rule later is compatible where tightening one is not.
   - a trust anchor is a CA certificate (`basicConstraints` with `cA`), checked when the
     resolver is built, and is within its own validity period at the validation time, which
     `rustls-webpki` does not look at;
   - a leaf with `keyUsage` asserts `digitalSignature` and not `keyCertSign`;
   - an RSA leaf key has at least 2048 bits;
   - a chain has at most 10 certificates.

   Not checked: revocation (CRLs, OCSP), and certificate policies. SHA-1, P-521 and Brainpool
   signatures are refused, as `ring` has none of them.

4. **The validation time reaches the resolver through a provided trait method.**
   `KeyResolver::resolve_key_at(key, role, now)` defaults to `resolve_key`, so existing
   implementations compile unchanged and a resolver whose answer depends on time overrides it.
   The validators call it with the time they validate at; `&T`, `Box<T>`, `Arc<T>` and
   `CompositeKeyResolver` forward it. Adding a parameter to `resolve_key` would have broken
   every implementation of an extension point (ADR 0006); a clock inside the resolver would
   have validated a token at one time and its certificates at another.

5. **The issuer is the certificate's subject; `iss` binds only through a Subject Alternative
   Name.** `KeyReference::binds_to` for a chain accepts no party, or a party the first
   certificate names: a `uniformResourceIdentifier` equal to it, or, for an `https` URL, a
   `dNSName` equal to its host. Anything else is an `IssuerMismatch`, since any holder of a
   certificate under a trusted anchor could otherwise claim any `iss`. The SD-JWT VC validator
   accepts a credential without `iss` only when a chain resolved its key: a key by value
   binds to no party either, and must not stand in for an issuer. `X509Certificate` reads the
   subject for the application's own policy, which the crate does not have: which subject may
   issue which credential.

6. **The verifier's resolvers choose the mechanism.** `KeyReference::candidates` lists every
   reference a header makes, and a validator takes the first its resolver handles
   (`KeyResolutionError::Unsupported` moves on, any other error ends the search). A verifier
   configured with `X509Resolver` alone is a HAIP verifier; one with `JwksResolver` alone
   ignores chains. `from_jws` stays the first candidate.

7. **A chain is tried before the issuer's key set and before a key by value.** The order
   becomes: DID URL `kid`, `x5c`, `kid` with an HTTPS `iss`, `jwk`, `jku`. HAIP credentials
   often carry an HTTPS `iss` and a `kid` beside the chain, and their issuers need not publish
   JWT VC Issuer Metadata, so a verifier with both resolvers must reach the chain first. A
   chain is also in the token, so it costs no request, and it is validated, where a `jwk`
   header only asserts itself.

8. **Issuing.** `Signer::x5c` (provided, `None`) lets a signer carry its chain, `CertifiedSigner`
   gives any signer one, and `JwsHeader::for_signer`, which the SD-JWT VC and Status List Token
   builders use, writes `x5c` instead of the signer's `kid`.

## Consequences

- `from_jws` returns `X509Chain` where it returned `Jwks` or `Jwk` for a token that carries
  `x5c` beside them. The crate's validators fall through to the other reference when their
  resolver does not handle chains, so they accept what they accepted; code that calls
  `from_jws` itself and resolves only that reference should use `candidates`.
- A verifier with both `X509Resolver` and `JwksResolver` rejects a token whose chain does not
  validate even when its key set would have verified it.
- A credential with a chain and an `iss` the certificate does not name is rejected. Ecosystems
  built on earlier HAIP drafts required `iss` to match a `dNSName`, so theirs pass.
- `x509` adds `rustls-webpki`, `rustls-pki-types` and `x509-cert`, and `ring` where `reqwest`
  did not already bring it. It is not a default feature.
- The `aki` trusted authorities query of OID4VP §6.1.1.1, which HAIP §5 requires, and the
  `x509_hash` client identifier are protocol matters outside this crate; `X509Certificate`
  gives them the Authority Key Identifier and the SHA-256 thumbprint to compare.
- The tests run 182 x509-limbo testcases (`tests/x509-limbo`), with every difference from the
  suite's verdict listed and explained, and sign tokens with one of its chains.
