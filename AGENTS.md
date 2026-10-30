# AGENTS.md

## Project

`identity-kit` is a single-crate Rust library for DIDs, pluggable key storage and JWT-based verifiable credentials.

- `docs/DESIGN.md` is the architecture. Follow it unless there is a concrete reason not to, and record any deviation as an ADR in `docs/adr/`.
- The work breakdown is tracked as GitHub Issues labelled `ready-for-agent`, linked by native issue dependencies. Pick the lowest-numbered open issue with no open blockers, one pull request per issue, each with its tests.
- `CONTRIBUTING.md` lists the checks CI runs and the pull request conventions. Read it before writing a pull request title.
- `docs/FEATURES.md` is the feature checklist. When a pull request implements a row, flip its status to ✅ in that pull request.
- `GLOSSARY.md` is the domain language, in the specifications' terms. Use its terms in code, tests, issues and pull requests.
- The agent skills from [mattpocock/skills](https://github.com/mattpocock/skills) live in `.agents/skills/`, with a link per skill in `.claude/skills/`, installed by the [`skills`](https://github.com/vercel-labs/skills) CLI and tracked in `skills-lock.json`. They are upstream files: don't edit them. A scheduled workflow opens a pull request when upstream changes them (`CONTRIBUTING.md`).

## Ground rules

- One crate, two layers. `did`, `jose`, `keys`, `identity`, `resolver` and `methods` never import `vc`, `sd_jwt_vc`, `status_list`, `domain_linkage` or `linked_vp`. CI enforces it; keep it green.
- Extension points are traits (`DidResolver`, `DidProducer`, `KeyStore`). Never add a closed enum of methods or backends to the library.
- JWT/JWS and SD-JWT only. No JSON-LD processing.
- Tests are specification vectors (W3C, RFCs, DIF, method specs), never another library's output.
- No git or path dependencies; `cargo publish --dry-run` must pass on every pull request.
- `unsafe_code = "forbid"` in `[lints.rust]`, clippy clean with `clippy::pedantic` (each exception an `#[expect]` with a reason), `cargo hack --each-feature` clean.

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `impierce/identity-kit` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary, except the `wontfix` role, which uses the existing `Wontfix` label. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
