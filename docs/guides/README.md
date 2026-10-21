# Guides

Step-by-step guides to the most common things done with IdentityKit. Each one walks through a
complete program that compiles and runs as a test of the crate (see below), so the code in them
is always current.

| Guide | Use it to | Main types |
| ----- | --------- | ---------- |
| [Keys and DIDs](keys-and-dids.md) | Generate a key in a key store, derive a `did:key` or `did:jwk` for it, and resolve the DID to its document and public key | `InMemoryKeyStore`, `KeyStore`, `DidKey`, `DidJwk`, `Resolver` |
| [Sign and verify a JWS](sign-and-verify.md) | Sign a payload with a key store key under a DID, and verify a compact JWS by resolving its `kid` | `KeySigner`, `JwsHeader`, `encode_compact`, `CompactJws`, `DefaultVerifier` |
| [Issue and verify a JWT credential](jwt-credentials.md) | Issue a verifiable credential as a JWT, present it in a holder-signed presentation, and validate both | `Credential`, `Presentation`, `Jwt`, `JwtCredentialValidator`, `JwtPresentationValidator` |
| [Selective disclosure with SD-JWT VC](sd-jwt-vc.md) | Issue an SD-JWT VC with concealed claims, present a subset with key binding, and validate it | `SdJwtVcBuilder`, `SdJwtVc`, `KeyBinding`, `SdJwtCredentialValidator` |

The guides build on each other in this order. For extending the crate (a new DID method, a key
store backend for a KMS) see the [README](../../README.md#extending); for the architecture,
[`DESIGN.md`](../DESIGN.md); for what is implemented, [`FEATURES.md`](../FEATURES.md).

## How the code is tested

`src/lib.rs` includes every guide as documentation of an item that exists only when rustdoc
collects doctests, so each `rust` code block is compiled and run by `cargo test`. A guide is
gated on the Cargo features its code needs; `cargo test --all-features` runs them all, as CI
does. Code blocks in other languages (`sh`, `toml`, `text`) are not run.

When you add a guide:

- Write each example as a complete program with `fn main` (or `#[tokio::main] async fn main`),
  so that it reads the same on GitHub as it runs in the test; avoid rustdoc's hidden `#` lines,
  which GitHub would show.
- Use `assert!`/`assert_eq!` to show results; they are checked.
- Include the file in `src/lib.rs` next to the others, gated on its features, and add a row to
  the table above.
