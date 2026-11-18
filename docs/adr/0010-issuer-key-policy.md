# ADR 0010: The verifier holds each Issuer to the key resolution mechanisms and trust anchors its policy allows, through a resolver that is told the Issuer

- Status: proposed
- Date: 2026-11-18

## Context

ADR 0008 made the verifier's resolvers the policy that picks a key resolution mechanism:
`KeyReference::candidates` lists every reference a token makes (a DID URL `kid`, an `x5c` chain,
a `kid` in the key set of an HTTPS `iss`, a `jwk`, a `jku`), and a validator takes the first one
its resolver handles. That choice is per verifier, not per Issuer. With both `JwksResolver` and
`X509Resolver` configured, a token with `iss: https://bank.example` is accepted when either holds:

- it is signed by a key in the key set `bank.example` publishes, or
- it carries a chain under any configured trust anchor whose leaf has the DNS name
  `bank.example`.

An Issuer that publishes only a key set can therefore be impersonated by whoever obtains a
certificate for its host name from any trust anchor the verifier configured, and the token
picks the route by carrying `x5c` or not. SD-JWT VC forbids this (Security Considerations): "A
Verifier MUST ensure that for any given Issuer, an attacker cannot influence the type of
verification process used." §3.5 also validates a chain "against a trust anchor permitted for
the Issuer according to policy", which `X509Resolver` cannot express: every anchor speaks for
every Issuer.

Today the documentation of `X509Resolver` and ADR 0008 tell such a verifier to validate with one
resolver per mechanism, which leaves the application to route tokens before it has validated
them (#175).

Two facts about the code shape the design:

- Every validator that resolves a key from a token goes through one function,
  `resolver::resolve_jws_key(resolver, jws, iss, role, now)`: `JwtValidator`, the JWT and
  SD-JWT credential validators (and so the presentation validators that use them), and
  `StatusListCheck`. It is the one place that sees the Issuer and every candidate together.
- `KeyResolver::resolve_key_at(key, role, now)` sees the reference, the role and the time, but
  not the Issuer. A `KeyReference::Jwks` carries its Issuer; an `X509Chain` or a `Jwk` does not.

## Decision

1. **The resolver is told the Issuer, through a provided trait method.** `KeyResolver` gains

   ```rust
   async fn resolve_issuer_key_at(
       &self,
       issuer: Option<&str>,
       key: &KeyReference,
       role: KeyRole,
       now: i64,
   ) -> Result<Jwk, KeyResolutionError> {
       let _ = issuer;
       self.resolve_key_at(key, role, now).await
   }
   ```

   `resolve_jws_key` calls it with the `iss` of the token, or `None` when the token has none.
   Existing resolvers compile and behave unchanged, as with `resolve_key_at` (ADR 0008,
   decision 4). `&T`, `Box<T>`, `Arc<T>` (the `forward_key_resolver!` macro, whose
   `clippy::missing_trait_methods` makes the omission an error) and `CompositeKeyResolver`
   forward it, the composite to each resolver it tries, with the Issuer.

2. **The policy is a trait that picks a resolver per Issuer and reference.**

   ```rust
   pub trait IssuerKeyPolicy: Send + Sync {
       /// The resolver for `key` in a token whose Issuer is `issuer`, or why the policy
       /// refuses it.
       fn resolver_for<'a>(
           &'a self,
           issuer: Option<&str>,
           key: &KeyReference,
           role: KeyRole,
       ) -> Result<&'a dyn KeyResolver, PolicyRefusal>;
   }

   pub struct PolicyKeyResolver<P: IssuerKeyPolicy> { .. }   // new(policy); implements KeyResolver
   ```

   `PolicyKeyResolver` implements `resolve_issuer_key_at` by asking the policy and handing the
   reference to the resolver it returns. A refusal becomes a new
   `KeyResolutionError::Refused { key, reason }`. `resolve_jws_key` moves on from it to the next
   candidate, as from a mechanism the verifier lacks, and reports it in preference to a plain
   `Unsupported` when no candidate resolves. A token from an
   Issuer held to its key set that carries only `x5c` is then rejected with "the policy does
   not permit an `x5c` chain for `https://bank.example`", and one that carries `x5c` beside a
   `kid` validates through the key set, as SD-JWT VC requires.

   The Issuer is the `iss` as the token writes it, matched by exact comparison, after an
   `https` `iss` that is not written canonically is refused. `binds_to` reads Issuers two ways:
   a key set binds an `iss` compared as a parsed URL, so `https://Bank.example/` binds the key
   set of `https://bank.example`, while a chain binds only the canonical form (ADR 0008,
   decision 5). Matching by exact string alone would let `https://Bank.example/` miss the entry
   that holds `https://bank.example` to its key set and fall to the fallback, while its key set
   still bound it. So `IssuerPolicy` refuses an `https` `iss` that a URL parser would rewrite
   (case, a default port, an empty path, percent-encoding), as a chain binding does, and stores
   its entries in the canonical form, refusing at construction one that is not. A DID `iss` is
   compared as written; DID syntax has one form.

   Its `resolve_key_at` and `resolve_key`, which carry no Issuer, consult the policy with
   `None`. A wrapper that does not forward `resolve_issuer_key_at` (a cache written before this
   ADR) therefore reaches the policy without an Issuer: the policy decides what that may
   resolve, and a policy written per Issuer refuses it. The policy fails closed.

   The policy is a trait, like the other extension points (ADR 0006): an application writes
   its rules over its own configuration. The crate ships a table-driven implementation,
   `IssuerPolicy`, built per Issuer (`with_key_set(issuer, resolver)`,
   `with_chain(issuer, x509_resolver)`, `with_did(issuer, resolver)`) and with a fallback for
   Issuers it does not list (refuse, by default, or a resolver), so a verifier states the
   common rules without implementing the trait.

3. **Trust anchors per Issuer are a resolver per Issuer.** The policy restricts trust anchors
   by returning, for an Issuer's chains, an `X509Resolver` built with the anchors permitted
   for that Issuer. `X509Resolver` is unchanged and keeps validating against all its anchors;
   anchors shared by several Issuers are shared by putting one resolver behind an `Arc` in
   each of their entries. The alternative, anchors scoped to Issuers inside `X509Resolver`,
   would put the policy in one mechanism's resolver when the same question (which key set,
   which DID method, which anchors) arises for every mechanism.

4. **A token without `iss` is decided on what the token carries.** An SD-JWT VC or a Status
   List Token signed under a chain may have no `iss`; its Issuer is the subject of the leaf
   certificate (ADR 0008, decision 5). The policy then receives `None` and the chain, and
   decides by the certificate: `IssuerPolicy` matches a chain without `iss` against its
   Issuers by the `dNSName` entries of the leaf (`X509Certificate::binds`, as an `iss` would
   bind). It uses an entry only when exactly one entry binds the leaf and that entry permits
   chains; a leaf whose names bind two or more entries is refused as ambiguous, since their
   anchors and mechanisms may differ and no rule picks one without letting the certificate
   choose. A chain no entry binds is an unlisted Issuer. Matching selects anchors and nothing
   else: the resolver it selects still validates the chain against that entry's anchors, the
   credential's Issuer is still the subject of the leaf (ADR 0008, decision 5), not the entry,
   and `binds_to` still checks the `iss` of a token that has one.

5. **Holder keys are not Issuer keys.** The policy also receives the `KeyRole`, so a policy
   applies to `KeyRole::Issuer` and leaves `KeyRole::Subject` (a presentation's holder, a key
   binding JWT whose `cnf` names a `kid`) to a resolver it chooses. `IssuerPolicy` takes a
   resolver for subject keys, the verifier's plain one by default.

6. **No policy, no change.** A verifier that does not wrap its resolver in a
   `PolicyKeyResolver` resolves keys exactly as today: the default `resolve_issuer_key_at`
   drops the Issuer. The documentation that tells a verifier to configure one resolver per
   mechanism is replaced by an example of `IssuerPolicy`.

## Alternatives

- **The policy as a parameter of each validator** (`with_key_policy(policy)` on
  `JwtValidator`, the credential, presentation and SD-JWT validators and `StatusListCheck`),
  consulted by `resolve_jws_key` for each candidate before resolving it. It needs no trait
  method, but every validator gains a builder method and a field, and a policy configured on
  one and forgotten on another leaves that path open. With the policy in the resolver, the one
  object a verifier already hands every validator carries it.
- **A resolver that wraps others and is told the Issuer through the reference**, adding the
  Issuer to `KeyReference::X509Chain` and `Jwk`. It changes a public enum that ADR 0006 made
  part of the extension point, and the reference would then claim an Issuer that nothing has
  checked yet.
- **Anchors scoped to Issuers in `X509Resolver`**: decision 3.

## Consequences

- `KeyResolver` gains a provided method; implementations compile unchanged. A wrapper resolver
  outside the crate that forwards `resolve_key_at` should forward `resolve_issuer_key_at` too,
  or a policy behind it sees no Issuer; the trait documentation says so, as it does for
  `resolve_key_at`.
- `KeyResolutionError` gains a variant, behind `#[non_exhaustive]`.
- `CompositeKeyResolver` forwards the Issuer. A composite inside a `PolicyKeyResolver` resolves
  only what the policy hands it; a `PolicyKeyResolver` inside a composite applies its policy to
  its share. The documentation recommends the policy outermost.
- `linked_vp`'s check that a presentation's key belongs to the DID it is linked from reads the
  candidates itself and is not affected.
- The acceptance criteria of #175 become tests over `PolicyKeyResolver` with `JwksResolver` and
  `X509Resolver`: an Issuer held to its key set rejects a valid chain for its host name and
  accepts its key set; the reverse; an Issuer restricted to one anchor rejects a chain under
  another; a non-canonical spelling of a listed `iss` is refused rather than falling to the
  fallback; a chain without `iss` whose leaf binds two entries is refused; no policy accepts
  what is accepted today; and each validator that calls `resolve_jws_key` is covered.
- `DESIGN.md`, `FEATURES.md`, the `X509Resolver` documentation and ADR 0008, decision 6, point
  here.
