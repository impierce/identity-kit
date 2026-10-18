# Contributing

Thanks for your interest in contributing to `identity-kit`!

## Prerequisites

- A stable Rust toolchain, installed via [rustup](https://rustup.rs/).
- The minimum supported Rust version (MSRV) is set by `rust-version` in [`Cargo.toml`](Cargo.toml) and checked in CI.
  Don't use language or standard library features newer than the MSRV without raising it.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) to run the dependency checks locally: `cargo install --locked cargo-deny`.

## Checks

CI runs the following checks on every pull request. Run them locally before opening one:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo deny check
```

CI also measures test coverage and reports it on the pull request via [Codecov](https://codecov.io/gh/impierce/identity-kit).
To see it locally, install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and run `cargo llvm-cov --all-features --open`.

### Fuzzing

The parsers are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) from the [`fuzz/`](fuzz/) crate, a workspace of its own that builds on nightly.
Each target in `fuzz/fuzz_targets/` feeds arbitrary input to one surface (DID syntax, DID documents, the DID methods, JOSE, VC JWTs, SD-JWT, the SD-JWT builder, SD-JWT VC metadata) and asserts that nothing panics and that whatever parses round-trips through its serialization.
CI runs every target for a minute on pull requests that touch `src/` and for ten minutes nightly, carrying the corpus over between runs; `fuzz/corpus/<target>/` holds the committed seeds, taken from the specification vectors.

```sh
cargo install --locked cargo-fuzz
cargo +nightly fuzz list                                   # the targets
cargo +nightly fuzz run sd_jwt -- -max_total_time=600      # one target, ten minutes
cargo +nightly fuzz run sd_jwt fuzz/artifacts/sd_jwt/crash-…   # replay a crash
```

A crash is a bug: fix it in `src/`, add the input's behaviour as a regular test from the specification it violates, and keep the target's assertion.

## Pull requests

Pull requests are squash-merged, so the **pull request title** becomes the commit message on `main`.
It must follow [Conventional Commits](https://www.conventionalcommits.org/), which CI checks:

- `` feat: add `did:key` resolution ``
- `fix(jwk): reject keys with missing curve parameters`
- `feat!: rename credential builder` (breaking change)

The title also determines the next version number and the changelog entry, so describe the change from a user's point of view.
Write it in terse commit style: drop articles (_the_, _a_, _an_) and wrap code literals in backticks, as in `` feat(did): add `Did` and `DidUrl` types ``.
Write `feat: add description to file`, not `feat: add a description to the file`.

## Releases

Releases are automated with [release-plz](https://release-plz.dev/): it keeps a release pull request open with the next version and changelog, and publishes to crates.io once that pull request is merged.
Don't bump the version or edit `CHANGELOG.md` by hand.
[`docs/RELEASE.md`](docs/RELEASE.md) describes the full process.

## Feature checklist

[`docs/FEATURES.md`](docs/FEATURES.md) lists every implemented and planned feature with its tracking issue.
When a pull request implements a feature, change its status to ✅ in the same pull request.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), and not in public issues or pull requests.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as described in section 5 of the license.
