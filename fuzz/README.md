# Fuzzing

The parsers of `identity-kit` are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), the Cargo front end for LLVM's [libFuzzer](https://llvm.org/docs/LibFuzzer.html).
Each target in this directory feeds arbitrary bytes to one surface of the crate and asserts a property that must hold for every input: nothing panics, and whatever parses survives a round trip through its serialization.
libFuzzer mutates the inputs, keeps every input that reaches code the previous ones did not, and stops at the first panic, crash or timeout.
It runs on nightly, with AddressSanitizer, which is why this directory is a Cargo workspace of its own and `exclude`d from the library's.

## Targets

One file per target in [`fuzz_targets/`](fuzz_targets/); the doc comment at the top of each states the property it asserts.

| Target               | Surface                                                                                                   | Input                                                        |
| -------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `did_syntax`         | `Did`, `DidUrl`, `DidUrlReference`, `Uri`: parse, print, `join`, `with_fragment`, `with_did`, `resolve`   | a DID, DID URL, relative reference or URI                    |
| `did_document`       | `DidDocument` JSON: parse, serialize, re-parse equal; every method and reference resolved                 | a JSON document                                              |
| `did_methods`        | `did:key`, `did:jwk`, `did:web`: the Read operations, a DID produced from a key resolves back to that key | a DID or HTTPS URL on the first line, then a JWK as JSON     |
| `jose`               | `CompactJws::decode`, JWK JSON, Multikey and SPKI decoding, verification with any key                     | a compact JWS on the first line, then a JWK as JSON          |
| `vc_jwt`             | `Jwt`, `JwtClaims`, VCDM 1.1 and 2.0 credentials and presentations, `data:` envelopes                     | a JWT, a claims set or a credential as JSON                  |
| `linked_vp`          | `LinkedVerifiablePresentation` services of a document, fetched bodies, linked presentation decoding and validation, `LinkedPresentationBuilder` claims round trip | a DID document, a response body, or builder input derived with `arbitrary` |
| `sd_jwt`             | `Disclosure`, `SdJwt`, `SdJwtVc` parsing, `select` and `disclose`                                         | an SD-JWT, a disclosure or a digest                          |
| `sd_jwt_roundtrip`   | `SdJwtBuilder`: arbitrary claims concealed along arbitrary paths process back to the same claims          | structured, derived from the bytes with `arbitrary`          |
| `sd_jwt_vc_metadata` | type metadata, integrity metadata, status lists, claim paths, DID configuration resources                 | a JSON document, a status list token or an integrity string  |

## Layout

```
fuzz/
├── Cargo.toml          # one [[bin]] per target; the Fuzz workflow discovers the targets here
├── fuzz_targets/       # the targets
├── seeds/<target>/     # committed starting inputs, one file per specification example
├── corpus/<target>/    # what the fuzzer discovers; generated, not committed
├── artifacts/<target>/ # the input of a failing run; generated, not committed
└── run.sh              # runs one target over its corpus and seeds
```

### Seeds

libFuzzer starts from whatever inputs it is given and mutates from there, so a seed that already parses puts it deep into the code from the first run instead of leaving it to guess the shape of a DID or an SD-JWT byte by byte.
The seeds in `seeds/<target>/` are the specification examples the integration tests run against (`tests/vectors/` and the inline vectors of `tests/`), plus a few hand-made edge cases.
Every file is named after what it holds, so it can be read and reviewed: `rfc9901-simple-issuance.txt` is the issued SD-JWT of RFC 9901 §5, `did-core-example-20.json` is example 20 of DID Core, `empty-arrays-and-extension.json` is a hand-made document with every array empty and an extension property.
The names are for people; libFuzzer reads only the bytes.

A target whose input is structured (`sd_jwt_roundtrip`, which derives a claims set and concealment paths from the bytes with `arbitrary`) has no seeds: no hand-written file means anything there, and the fuzzer builds its corpus from scratch within seconds.

### Corpus and artifacts

`corpus/<target>/` is where libFuzzer writes every input that reached new coverage.
Files there are named by the SHA-1 of their content, the libFuzzer convention, and they are mutated bytes nobody needs to read; the directory is in `.gitignore`.
In CI the corpus is cached per target between runs ([`actions/cache`](../.github/workflows/fuzz.yml)), so each run continues from the coverage of the previous one; locally it accumulates in your checkout.
Deleting it costs nothing but the time to rediscover it.

`artifacts/<target>/` holds the input of a failing run as `crash-<sha1>`, `timeout-<sha1>` or `oom-<sha1>`; the file is also what the workflow uploads when a job fails.

## Running locally

```sh
cargo install --locked cargo-fuzz
rustup toolchain install nightly

cargo +nightly fuzz list                    # the targets
fuzz/run.sh sd_jwt 600                      # one target, ten minutes, over its corpus and seeds
cargo +nightly fuzz run sd_jwt fuzz/artifacts/sd_jwt/crash-…   # replay a failing input
cargo +nightly fuzz tmin sd_jwt fuzz/artifacts/sd_jwt/crash-…  # shrink it to the smallest failing input
cargo +nightly fuzz coverage sd_jwt fuzz/corpus/sd_jwt fuzz/seeds/sd_jwt   # coverage of the corpus
```

`run.sh` passes the corpus directory first and the seeds second, which is how libFuzzer tells where to write (the first) from what to read (the rest); run `cargo fuzz run` by hand the same way, or the seeds are left out.

## In CI

The [Fuzz workflow](../.github/workflows/fuzz.yml) reads the targets from `Cargo.toml` and runs each one in its own job, for a minute on pull requests that touch `src/` or `fuzz/` and for ten minutes nightly, restoring and saving the corpus cache around the run.
A failing job uploads `artifacts/<target>/` for replay.

## When a target finds something

A crash is a bug in the library, or a property the target states too strongly; the input decides which.

- A bug: fix it in `src/`, add the input's behaviour as a regular test from the specification it violates, keep the target's assertion.
- A wrong assumption in the target (a specification vector next to its key legitimately verifies, a leap-second date legitimately has no `NumericDate`): narrow the assertion and say why in a comment.

## Adding a target or a seed

A target is a file in `fuzz_targets/` and a `[[bin]]` entry in `Cargo.toml` with `test`, `doc` and `bench` off; the workflow picks it up from the manifest.
State the property in the doc comment, and seed it from the specification's examples under `seeds/<target>/`, one example per file, named after its source.
