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

A backend whose signer answers in DER, as AWS KMS and Google Cloud KMS do for ECDSA keys,
converts with `jose::ecdsa_signature_from_der`. A secp256k1 signature must have `s` in the lower
half of the group order, the only one `DefaultVerifier` (like Bitcoin and most secp256k1
verifiers) accepts; `ecdsa_signature_from_der` normalizes it, and a backend that already has
`r || s` passes it through `jose::normalize_ecdsa_signature`. The test suite checks both.

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
that ECDSA signatures are not DER, that ES256K signatures have a low `s`, exercises `exists`, `NotFound`, `AlgorithmMismatch`,
`AlreadyExists`, `InvalidSpec`, the `Unsupported` defaults, and the JWS round trip through
`KeySigner`. Every backend in this crate runs it in CI; a backend in another crate should too.

## Algorithm matrix

| Algorithm | Key type              | `InMemoryKeyStore` | `SoftwareKeyStore` | `Pkcs11KeyStore`                          |
| --------- | --------------------- | :----------------: | :----------------: | :---------------------------------------: |
| `EdDSA`   | `Ed25519`             |         ✅         |         ✅         | ✅ with `CKM_EDDSA`                       |
| `ES256`   | `P256`                |         ✅         |         ✅         | ✅ with `CKM_ECDSA`                       |
| `ES256K`  | `Secp256k1`           |  ✅ (`secp256k1`)  |  ✅ (`secp256k1`)  | ✅ with `CKM_ECDSA` (`secp256k1`)         |
| `ES384`   | none in this crate    |         ❌         |         ❌         |                    ❌                     |
| `RS256`   | `Rsa2048`, `Rsa4096`  |         ❌         |         ❌         | ✅ with `CKM_RSA_PKCS` (`rsa_algorithm`)  |
| `PS256`   | `Rsa2048`, `Rsa4096`  |         ❌         |         ❌         | ✅ with `CKM_RSA_PKCS_PSS` (`rsa_algorithm`) |

The software backends never sign with RSA: the `rsa` crate's private-key operations are affected
by RUSTSEC-2023-0071 and [ADR 0001](adr/0001-rsa-verification-only.md) keeps them out of the
crate. RSA signing belongs to an HSM or a cloud KMS backend; `Pkcs11KeyStore` signs RSA in the
module, with one of `RS256` and `PS256` per store (`rsa_algorithm`). Generating an RSA key in a
software backend is `UnsupportedKeyType`, and an RSA key in a software key set file is refused
when the file is opened.

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

## `Pkcs11KeyStore` (feature `pkcs11`)

A token of a PKCS#11 module, an HSM, a smart card or a software token such as SoftHSM2, through
[`cryptoki`](https://crates.io/crates/cryptoki). The key id is the object label (`CKA_LABEL`):
a key is the private key object and the public key object sharing a label, and a label must
name one key; one that names several is `InvalidKey`. Keys an administrator provisions with
`pkcs11-tool` or the vendor's tools are used as they are; keys the store generates are stored
on the token with the label as both `CKA_LABEL` and `CKA_ID`, the private key sensitive and not
extractable.

```rust
use identity_kit::jose::JwsAlgorithm;
use identity_kit::keys::{Pkcs11KeyStore, Pkcs11KeyStoreOptions, Pkcs11Token};

// By token label, with the defaults.
let store = Pkcs11KeyStore::open("/usr/lib/softhsm/libsofthsm2.so", "issuer", Some("1234"))?;

// By slot id, tuned.
let store = Pkcs11KeyStore::open_with(
    "/usr/lib/softhsm/libsofthsm2.so",
    Pkcs11Token::Slot(2_108_653_770),
    Some("1234"),
    Pkcs11KeyStoreOptions::new()
        .sessions(2)                                        // logged-in sessions kept open
        .rsa_algorithm(JwsAlgorithm::PS256)                 // what RSA keys sign with
        .algorithms([JwsAlgorithm::ES256, JwsAlgorithm::PS256]), // narrow the offer
)?;
```

- **Module.** The path of the PKCS#11 library. It is loaded and initialized (`C_Initialize`
  with `CKF_OS_LOCKING_OK`) when the first store on it is opened, shared by later stores on the
  same path and never finalized before the process ends.
- **Token.** `Pkcs11Token::Label` (the label given at `--init-token`; preferred, slot ids are
  not stable across SoftHSM2 token initializations) or `Pkcs11Token::Slot`.
- **PIN.** The user PIN, or `None` for a token without login or with a protected
  authentication path. `open` logs one session in, so a wrong PIN fails there; the PIN is kept
  for later sessions and zeroized when the store is dropped. PKCS#11 logs in the application,
  not the session: when the process is logged in to the token already, the module does not
  check the PIN again.
- **Sessions.** A pool of logged-in sessions, `4` by default; an operation waits when all are
  in use. Every operation runs on `tokio`'s blocking thread pool, since the module blocks, so
  the store needs a `tokio` runtime.
- **Algorithms.** Read from the module's mechanism list at `open`: `EdDSA` for `CKM_EDDSA`,
  `ES256` and (feature `secp256k1`) `ES256K` for `CKM_ECDSA`, `rsa_algorithm` for its RSA
  mechanism. `algorithms(..)` narrows the list, for a module whose `CKM_ECDSA` has no
  secp256k1, say. The store hashes in-process (SHA-256) and signs the hash: `CKM_ECDSA`,
  `CKM_RSA_PKCS` over the SHA-256 `DigestInfo`, `CKM_RSA_PKCS_PSS` with SHA-256, MGF1-SHA-256
  and a 32-byte salt; EdDSA signs the message with `CKM_EDDSA`. ECDSA signatures are the raw
  `r || s` PKCS#11 returns; a secp256k1 `s` is normalized to the lower half of the order with
  `jose::normalize_ecdsa_signature`, as `k256` and Bitcoin require.
- **RSA.** A PKCS#11 RSA key does not say whether it is for PKCS#1 v1.5 or PSS, so one
  algorithm per store, `RS256` by default: every RSA key's public JWK carries it, `sign`
  accepts only it for an RSA key and `generate` makes RSA keys (65537, 2048 or 4096 bits) for
  it.
- **Generate and delete.** Available unless the token is write-protected; `generate` needs the
  key type's key pair generation mechanism (`UnsupportedKeyType` otherwise). The key id of a
  generated key is the spec's label when set and the RFC 7638 thumbprint of the public key
  otherwise, written to both objects once the key exists; until then the objects carry a label
  starting with `identity-kit-staging-` (`STAGING_LABEL_PREFIX`), so a generation interrupted
  in between leaves a recognizable key to remove with the module's tools. `delete` destroys
  both objects even when destroying the first fails, then returns the first error; what is
  left keeps its label, so calling `delete` again removes it. Generation and
  deletion are serialized per token within the process; SoftHSM2's file object store fails
  when objects are created and destroyed from several sessions at once. The uniqueness of a
  label is checked, not enforced by the module: two processes provisioning the same label at
  once can both succeed, after which the store refuses the label as ambiguous until one key is
  removed with the module's tools. Give a shared token one provisioning owner.
- **Errors.** Module, token, option and call failures are `KeyStoreError::Backend` carrying a
  `Pkcs11Error`, which names the PKCS#11 function and the return value.

### Testing against SoftHSM2

CI runs `keys::testsuite` against SoftHSM2 on Linux. The same setup works locally:

```sh
sudo apt-get install softhsm2 opensc          # or: brew install softhsm opensc
export SOFTHSM2_CONF=$PWD/target/softhsm2.conf  # a token directory of your own
mkdir -p target/tokens && printf 'directories.tokendir = %s/target/tokens\nobjectstore.backend = file\n' "$PWD" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label identity-kit --so-pin 0102 --pin 1234
export PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so PKCS11_TOKEN_LABEL=identity-kit PKCS11_PIN=1234
cargo test --all-features --test keys_pkcs11 --test keys_pkcs11_login
```

Without `PKCS11_MODULE` the PKCS#11 tests pass without doing anything.
