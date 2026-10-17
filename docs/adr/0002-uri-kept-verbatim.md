# ADR 0002: URIs in DID documents are kept verbatim, not parsed with `url`

- Status: accepted
- Date: 2026-10-17

## Context

`docs/DESIGN.md` types `alsoKnownAs` and `serviceEndpoint` with `url::Url` and lists `url`
among the building blocks. `url::Url` implements the WHATWG URL Standard: parsing normalizes
(`https://bar.example.com` becomes `https://bar.example.com/`, hosts are lower-cased and
IDNA-encoded, paths are dot-segment-resolved, non-ASCII is percent-encoded) and rejects
relative references and some RFC 3986 URIs.

DID Core §5.4 requires `serviceEndpoint` strings to be "valid URIs conforming to RFC 3986" and
a conforming consumer to carry them on; DID Core §6.2 requires the JSON representation to be
preserved. Issue #6 asks for the W3C examples to re-serialize byte-identically, and the
determinism principle of the design asks for the same input to give the same output. The service
example of DID Core, `https://bar.example.com`, cannot round-trip through `url::Url`.

## Decision

1. The `did` module defines `Uri`, an RFC 3986 URI stored exactly as written. It checks the
   generic syntax (a scheme, the RFC 3986 character sets, complete percent-encoding, at most one
   `#`) and nothing more. Equality is string equality, as DID Core defines no normalization.
2. `alsoKnownAs` is `Vec<Uri>` and `ServiceEndpoint` holds `Uri`s. `url` is not a dependency of
   the `did` module. `methods::web` may still use `url` for its own origin handling, where
   WHATWG parsing is what a browser-facing method needs.
3. Relative DID URLs (DID Core §3.2.2, `#key-1`) in verification relationships are kept as
   written in `DidUrlReference` and resolved against the document `id` on lookup.

## Consequences

- W3C DID Core examples round-trip member for member; documents from the wild are not rewritten.
- A consumer that needs a parsed URL converts with `url::Url::parse(uri.as_str())` at the point of
  use, where normalization is wanted.
- `Uri` accepts any syntactically valid URI, so scheme-specific rules (`https` only for a
  service) are the caller's to check.
