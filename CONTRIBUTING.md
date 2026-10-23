# Contributing

Thanks for your interest in contributing to `identity-kit`!

## Prerequisites

- A stable Rust toolchain, installed via [rustup](https://rustup.rs/).
- The minimum supported Rust version (MSRV) is set by `rust-version` in [`Cargo.toml`](Cargo.toml) and checked in CI.
  Don't use language or standard library features newer than the MSRV without raising it.
  The policy is a rolling six months: the MSRV may be raised to any stable release that is at least six months old.
  Raise it in its own pull request, together with the dependency updates it unlocks, and mark the pull request as a breaking change (`build!:`), since a crate built on an older toolchain stops compiling.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) to run the dependency checks locally: `cargo install --locked cargo-deny`.
- [`cargo-hack`](https://github.com/taiki-e/cargo-hack) to check every feature on its own: `cargo install --locked cargo-hack`.

## Checks

CI runs the following checks on every pull request. Run them locally before opening one:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
cargo hack clippy --each-feature --locked -- -D warnings
cargo build --no-default-features --features did-key,software --locked
cargo publish --dry-run --locked
cargo deny check
```

The lower layer (`did`, `jose`, `keys`, `identity`, `resolver`, `methods`) never imports the upper layer (`vc`, `sd_jwt_vc`, `domain_linkage`, `linked_vp`).
CI proves it by building with `--no-default-features --features did-key,software`, which leaves the upper modules out, and by checking that `cargo tree` in that configuration lists neither `chrono` nor `miniz_oxide`, the upper layer's own dependencies, nor `sd-jwt-payload`, an SD-JWT library the lower layer must never grow.

CI also measures test coverage and reports it on the pull request via [Codecov](https://codecov.io/gh/impierce/identity-kit).
To see it locally, install [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) and run `cargo llvm-cov --all-features --open`.

[CodeQL](https://codeql.github.com/) scans the Rust code and the workflows on every pull request, with the `security-extended` queries; its alerts appear in the repository's code scanning view.
`tests/` and `fuzz/` are left out ([`.github/codeql/codeql-config.yml`](.github/codeql/codeql-config.yml)): their specification vectors hold fixed keys and nonces on purpose.
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/impierce/identity-kit) grades the repository's security practices on every push to `main` and weekly.
Its Vulnerabilities check reads [`osv-scanner.toml`](osv-scanner.toml), which must ignore the same advisories as `deny.toml`, each with its reason.

### Fuzzing

The parsers are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) from the [`fuzz/`](fuzz/) crate, a workspace of its own that builds on nightly.
Each target feeds arbitrary input to one surface and asserts that nothing panics and that whatever parses round-trips; CI runs every target for a minute on pull requests that touch `src/` or `fuzz/` and for ten minutes nightly.
[`fuzz/README.md`](fuzz/README.md) describes the targets, the committed seeds, the generated corpus and how to run, replay and extend them.

```sh
cargo install --locked cargo-fuzz
fuzz/run.sh sd_jwt 600      # one target, ten minutes
```

### Mutation testing

[`cargo-mutants`](https://mutants.rs) checks the tests themselves: it changes the code (a return value, a comparison, a match arm) and reports each change that no test catches, code the tests run but do not check.
Testing every mutant takes hours, so the `Mutants` workflow runs weekly and when started by hand from the Actions tab, optionally limited to a glob such as `src/jose/**`, not on pull requests.
It splits the crate across twelve jobs, and tests `src/keys/pkcs11.rs` in a job of its own against a SoftHSM2 token.
Each job lists its missed mutants in the run summary; they are findings to triage, and the run does not fail on them.
[`.cargo/mutants.toml`](.cargo/mutants.toml) holds the configuration.

To check the mutants of your own change before opening a pull request:

```sh
cargo install --locked cargo-mutants
cargo mutants -f 'src/jose/**' -j 2         # one module
git diff main... > pr.diff && cargo mutants --in-diff pr.diff -j 2   # the lines a branch changes
```

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
