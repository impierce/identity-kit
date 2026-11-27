# ADR 0012: `did:key` and `did:jwk` refuse ML-DSA keys; `did:web` carries them

- Status: accepted
- Date: 2026-11-27

## Context

RFC 9964 puts ML-DSA keys in JOSE as `AKP` JWKs. Their public keys are 1312 (ML-DSA-44), 1952
(ML-DSA-65) and 2592 (ML-DSA-87) bytes. An issuer moving to post-quantum signatures publishes such
a key next to its classic one and signs with whichever algorithm the wallet or verifier supports.

The crate bounds a DID by the length of the DID URLs built from it (`DEFAULT_MAX_LEN`, 2048
bytes), so that resolvers, logs and URLs never meet a DID they cannot handle:

- `did:key` repeats the Multikey string as the fragment of its verification method, so a DID
  gets about half: `DidKey::MAX_DID_LEN` is 1027 bytes. ML-DSA-44's public key alone is 1312
  bytes, and base58btc makes it about 1790 characters. Nor does ML-DSA have a multicodec for
  `did:key` to use.
- `did:jwk` gets `DidJwk::MAX_DID_LEN`, 2046 bytes. An ML-DSA-44 `AKP` JWK is about 1800
  characters of JSON, and base64url of it about 2400.

Raising the limits would make every DID of these methods several kilobytes long. That breaks
the length assumptions of resolvers, HTTP servers and logs that carry DIDs in URLs and headers.

## Decision

1. `DidKey::did` and `DidJwk::did` refuse an `AKP` key with their existing too-long errors
   (`DidKeyError::TooLong`, `DidError::TooLong`). `did:key` checks the key type first, since no
   Multikey form exists for it. `did:jwk` needs no check of its own: the encoded key is too long.
2. `did:web` is the supported way to publish an ML-DSA key. Its document carries the `AKP` JWK as
   a `JsonWebKey` verification method like any other key, and the DID stays short.
3. The limits stay as they are.

## Consequences

- An identity that must be resolvable without a web server (`did:key`, `did:jwk`) stays on
  classic keys; an issuer that wants ML-DSA uses `did:web`.
- `KeyStoreIdentity` with a `did:key` or `did:jwk` producer refuses to bind an ML-DSA key, with
  `ProduceError::UnsupportedKey` and the too-long error as its source.
- Revisit this when a method specification defines a short form for large keys (a hash of the
  key, say), or when the DID length limits are raised for another reason.
