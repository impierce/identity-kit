# ADR 0007: The VCDM 1.1 JWT profile is deprecated outside domain linkage, through deprecated aliases

- Status: accepted
- Date: 2026-11-11

## Context

`vc` implements two JWT profiles (ADR 0004): VCDM 1.1 §6.3.1, with the data model object in a
`vc` or `vp` claim, and VCDM 2.0 secured with VC-JOSE-COSE, whose payload is the object itself.
VCDM 2.0 replaced VCDM 1.1, VC-JOSE-COSE forbids the `vc` and `vp` claims, and SD-JWT VC covers
selective disclosure. The VCDM 1.1 profile stays required in one place: the DIF Well Known DID
Configuration, whose domain linkage credential is a VCDM 1.1 credential as a JWT. The DIF Linked
Verifiable Presentation specification prescribes no data model version; `linked_vp` reads and
builds both forms.

`#[deprecated]` on a struct also deprecates its fields: every read of a field of a value warns,
even where the type is never named. Deprecating `Credential` and `DecodedCredential` themselves
would therefore make every reader of a domain linkage result warn. A `#[deprecated]` on a
`pub use` has no effect.

## Decision

1. The types of the VCDM 1.1 profile live in crate-private modules, undeprecated. Their public
   paths in `vc` become deprecated type aliases: `vc::Credential`, `vc::Presentation`,
   `vc::validation::DecodedCredential`, `vc::validation::DecodedPresentation`. Naming a type
   through an alias warns; using a value of the type does not.
2. `domain_linkage` re-exports the two types it exposes, `Credential` and `DecodedCredential`,
   without the deprecation. A domain linkage user names `domain_linkage::Credential` and sees
   no warning.
3. The entry points of the profile are deprecated functions and methods:
   `decode_credential`, `decode_presentation`, `JwtCredentialValidator::validate`,
   `JwtPresentationValidator::validate`. `domain_linkage` and `linked_vp` call crate-private,
   undeprecated equivalents.
4. In `linked_vp`, what produces or reads only the VCDM 1.1 form is deprecated:
   `LinkedPresentationBuilder`, `LinkedVpValidator::validate`, `decode`,
   `DecodedLinkedPresentation`. `validate_any`, `LinkedVpClient` and
   `LinkedPresentation::Vcdm11` stay: a verifier still reads presentations already published
   in that form.
5. `to_jwt_claims` and `from_jwt_claims` are not deprecated themselves: they are methods of the
   undeprecated types, which domain linkage uses, and reaching them outside domain linkage
   means naming a deprecated alias.
6. The deprecated items are removed in a later breaking release. `domain_linkage` then keeps
   its own copy of what it needs.

## Consequences

- No public path disappears and no type changes, so the change is not breaking;
  `cargo-semver-checks` accepts a struct replaced by a type alias of the same type.
- Code that names the deprecated paths warns, prelude imports included. Tests and fuzz targets
  that cover the profile expect the lint.
- Without the `domain-linkage` feature, the VCDM 1.1 types are reachable only through the
  deprecated aliases, so clippy no longer treats `Credential` as exported; its field-name
  exception applies in that configuration only.
- `LinkedPresentation::Vcdm11` carries a `DecodedPresentation` that can be named only through
  the deprecated alias; matching on the variant does not warn.
