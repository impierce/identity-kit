# Key stores

How a `keys::KeyStore` backend behaves, what the shipped backends do, and how to provision them.
The API reference is the rustdoc of the `keys` module; this page is the contract behind it.

## The contract

A key store holds private keys behind opaque ids and signs on request. The trait is shaped by
remote signers (an HSM, a cloud KMS), and a software backend follows the same rules.

| Operation      | Contract                                                                                                                                               |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `capabilities` | Truthful and stable. Every algorithm listed signs; `generate` and `delete` succeed only when `can_generate` / `can_delete` is set. No duplicate algorithms. |
| `public_jwk`   | The public key, never private parameters. `alg` is set to the key's algorithm when the backend knows it; `kid` is the key id for the shipped backends.   |
| `sign`         | Takes the raw signing input (the backend hashes) and returns the JWS form of the signature: 64 bytes for EdDSA, raw `r \|\| s` for ECDSA (never DER), the modulus-sized octet string for RSA. |
| `exists`       | `Ok(false)` for an unknown key, never an error.                                                                                                        |
| `generate`     | Rejects a spec whose algorithm does not fit the key type (`InvalidSpec`), a key type or algorithm the backend cannot make (`UnsupportedKeyType`, `UnsupportedAlgorithm`) and a taken label (`AlreadyExists`). Default: `Unsupported("generate")`. |
| `delete`       | `NotFound` for an unknown key. Default: `Unsupported("delete")`.                                                                                        |

One key, one algorithm: a key created for `ES256` signs `ES256` and nothing else. Signing with
any other algorithm, supported by the store or not, is `AlgorithmMismatch`. An unknown key is
`NotFound` from `public_jwk`, `sign` and `delete`.

Callers cache the public key. `KeySigner` fetches it once, on construction, checks that the
key's `alg` (if the public JWK carries one) is the algorithm asked for, and then implements
`jose::Signer`; `encode_compact` never asks the store for anything but signatures.

### Errors

`KeyStoreError` is the vocabulary above plus `InvalidKey` (the material exists but cannot be
used), the file errors of the software store (`Io`, `InsecurePermissions`, `InvalidKeySet`), and
`Backend`, which wraps whatever a remote backend reports. `KeyStoreError::backend(e)` builds the
latter.

### The test suite

`keys::testsuite` (feature `test-vectors`) checks the contract against a live backend and panics
on the first violated requirement:

```rust
// A backend that generates keys:
identity_kit::keys::testsuite::run(&store).await;

// A backend whose keys are provisioned out of band, one per advertised algorithm:
identity_kit::keys::testsuite::run_with_keys(&store, &[(key_id, JwsAlgorithm::ES256)]).await;
```

The suite signs with every advertised algorithm and verifies with `DefaultVerifier` (algorithms
it cannot verify in the current build are format-checked only), checks signature lengths and
that ECDSA signatures are not DER, exercises `exists`, `NotFound`, `AlgorithmMismatch`,
`AlreadyExists`, `InvalidSpec`, the `Unsupported` defaults, and the JWS round trip through
`KeySigner`. Every backend in this crate runs it in CI; a backend in another crate should too.

## Algorithm matrix

| Algorithm | Key type              | `InMemoryKeyStore` | `SoftwareKeyStore` | `Pkcs11KeyStore` (planned, #13) |
| --------- | --------------------- | :----------------: | :----------------: | :-----------------------------: |
| `EdDSA`   | `Ed25519`             |         ✅         |         ✅         |        module dependent         |
| `ES256`   | `P256`                |         ✅         |         ✅         |        module dependent         |
| `ES256K`  | `Secp256k1`           |  ✅ (`secp256k1`)  |  ✅ (`secp256k1`)  |        module dependent         |
| `ES384`   | none in this crate    |         ❌         |         ❌         |               ❌                |
| `RS256`   | `Rsa2048`, `Rsa4096`  |         ❌         |         ❌         |        module dependent         |
| `PS256`   | `Rsa2048`, `Rsa4096`  |         ❌         |         ❌         |        module dependent         |

The software backends never sign with RSA: the `rsa` crate's private-key operations are affected
by RUSTSEC-2023-0071 and [ADR 0001](adr/0001-rsa-verification-only.md) keeps them out of the
crate. RSA signing belongs to an HSM or a cloud KMS backend. Generating an RSA key in a software
backend is `UnsupportedKeyType`, and an RSA key in a software key set file is refused when the
file is opened.

ECDSA signatures of the software backends use RFC 6979 deterministic nonces, so the same key and
input give the same signature. Backends are free to use random nonces.

## `InMemoryKeyStore` (feature `in-memory`)

Keys in process memory, zeroized on drop; generates and deletes. For tests, examples and
development. `InMemoryKeyStore::with_seed(seed)` derives keys deterministically from the seed
(block `i` of secret bytes is `SHA-256("identity-kit/in-memory" || seed || i)`), so the n-th key
generated from a seed is always the same key and fixtures stay stable. A seeded store must never
hold production keys.

The key id of a generated key is the spec's label when set and the RFC 7638 SHA-256 thumbprint
of the public key otherwise.

## `SoftwareKeyStore` (feature `software`, default)

A JWK set file (RFC 7517 §5) of private keys:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      "kid": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
      "alg": "EdDSA"
    }
  ]
}
```

- `kid` is the key id; it must be unique in the file. A key without `kid` gets its RFC 7638
  thumbprint and the file is rewritten with it on the next change.
- `alg` is the one algorithm the key signs with and must fit the key; it defaults to the key
  type's algorithm (`EdDSA`, `ES256`, `ES256K`).
- The public members (`x`, `y`) must be present and match `d`; a mismatch fails `open`, so a
  corrupted file is caught before a signature fails to verify.
- A key with `use` other than `sig`, or `key_ops` without `sign`, is refused: it could not be
  used for signing. RSA and unknown key types are refused.
- Other members of the set and of each key are kept and written back unchanged.

The file is read once, when the store is opened, and rewritten as a whole on `generate`,
`delete` and `import`: the new set goes to a temporary file in the same directory (created with
mode `0600` on Unix), is synced and renamed over the old file, so a reader sees the old or the
new content and never a partial file. Private material is zeroized when the store is dropped.
Nothing locks the file against other processes; run one store per file.

On Unix, `open` refuses a file with group or world permission bits (`InsecurePermissions`)
unless `SoftwareKeyStoreOptions::allow_insecure_permissions(true)` is passed; `create` makes the
file `0600`. Other platforms do not check.

### Provisioning

```sh
cargo xtask keys generate --store keys.json --alg ES256 --kid issuer
```

creates `keys.json` if needed, generates a key and prints its public JWK. `--alg` is `EdDSA`,
`ES256` or `ES256K`; without `--kid` the key id is the thumbprint. In code,
`SoftwareKeyStore::create(path)` then `generate`, or `import(jwk)` for a key made elsewhere.
