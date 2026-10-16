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

## Pull requests

Pull requests are squash-merged, so the **pull request title** becomes the commit message on `main`.
It must follow [Conventional Commits](https://www.conventionalcommits.org/), which CI checks:

- `feat: add did:key resolution`
- `fix(jwk): reject keys with missing curve parameters`
- `feat!: rename the credential builder` (breaking change)

The title also determines the next version number and the changelog entry, so describe the change from a user's point of view.

## Releases

Releases are automated with [release-plz](https://release-plz.dev/): it keeps a release pull request open with the next version and changelog, and publishes to crates.io once that pull request is merged.
Don't bump the version or edit `CHANGELOG.md` by hand.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), and not in public issues or pull requests.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), as described in section 5 of the license.
