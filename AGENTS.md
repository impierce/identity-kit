# AGENTS.md

## Project

`identity-kit` is a single-crate Rust library for DIDs, pluggable key storage and JWT-based verifiable credentials.

- `docs/DESIGN.md` is the architecture. Follow it unless there is a concrete reason not to, and record any deviation as an ADR in `docs/adr/`.
- The work breakdown is tracked as GitHub Issues labelled `ready-for-agent`, linked by native issue dependencies. Pick the lowest-numbered open issue with no open blockers, one pull request per issue, each with its tests.
- `CONTRIBUTING.md` lists the checks CI runs and the pull request conventions. Read it before writing a pull request title.
- `docs/FEATURES.md` is the feature checklist. When a pull request implements a row, flip its status to ✅ in that pull request.
- `docs/guides/` holds task-oriented usage guides (keys and DIDs, JWS, JWT credentials, SD-JWT VC). Start there to learn how the crate is used. Their `rust` code blocks are doctests (included from `src/lib.rs`), so an API change that breaks a guide fails `cargo test --all-features`; update the guide in the same pull request.

## Ground rules

- One crate, two layers. `did`, `jose`, `keys`, `resolver` and `methods` never import `vc`, `sd_jwt_vc`, `domain_linkage` or `linked_vp`. CI enforces it; keep it green.
- Extension points are traits (`DidResolver`, `DidProducer`, `KeyStore`). Never add a closed enum of methods or backends to the library.
- JWT/JWS and SD-JWT only. No JSON-LD processing.
- Tests are specification vectors (W3C, RFCs, DIF, method specs), never another library's output.
- No git or path dependencies; `cargo publish --dry-run` must pass on every pull request.
- `#![forbid(unsafe_code)]`, clippy clean, `cargo hack --each-feature` clean.

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `impierce/identity-kit` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
