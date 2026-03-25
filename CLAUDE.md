# Claude Code Instructions

## Absolute Rules

1. **User stories are mandatory.** Every feature must have a user story
   in the format "As a ..., I want ..., so that ..." created and
   maintained with human interaction before implementation begins.
   User stories live in `docs/user-stories/` as individual markdown files.

2. **Remediation commands are domain-expert knowledge.** Never synthesize
   or compose operational commands (sss_debuglevel, dsconf, smbcontrol,
   pki-server, systemctl sequences, etc.) from general patterns. They must
   come from: the user, documentation that was read, or a curated table in
   the codebase. When unsure, ask.

3. **Trace the call path before suggesting debug steps.** When reasoning
   about where logs go or how to enable debugging, mentally trace the actual
   execution: which process runs, what calls what, where output lands.

## Git Identity

- Always use: `git commit --signoff`
- Author: Francois Cami <contribs@fcami.net>
- Set via env vars on every commit (never modify git config):
  ```
  GIT_AUTHOR_NAME="Francois Cami" GIT_AUTHOR_EMAIL="contribs@fcami.net" \
  GIT_COMMITTER_NAME="Francois Cami" GIT_COMMITTER_EMAIL="contribs@fcami.net" \
  git commit --signoff
  ```
- Co-author line: `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

## Language & Toolchain

- **Language:** Rust
- **Minimum target:** RHEL 8 (`rust-toolset` provides Rust 1.71)
- **Edition:** 2021
- Never use features requiring Rust > 1.71

## Quality Gates

- **Linting:** `cargo clippy -- -D warnings` is mandatory before every commit
- **Static analysis:** Clippy pedantic where applicable
- **Test coverage:** Good test coverage is mandatory — unit tests for all
  parsers and logic, integration tests for end-to-end scenarios
- **All tests must pass before committing**
- Never commit with `#[allow(clippy::...)]` at module level — only on
  specific items with a justification comment
- Never `unwrap()` outside tests

## Architecture

- **Separation of concerns is mandatory.** Keep parsing, analysis, and
  presentation in distinct modules. Parsers return data structs, never
  formatted output. Display logic is separate from data logic.

## Build Targets

The project provides 4 build modes:

| Target | Command | Description |
|--------|---------|-------------|
| Local | `just build` | Build with local Rust toolchain |
| RHEL 8 | `just release-rhel8` | Build in UBI8 container |
| RHEL 9 | `just release-rhel9` | Build in UBI9 container |
| RHEL 10 | `just release-rhel10` | Build in UBI10 container |

Container builds use `scripts/ensure-builder-image.py` (shared pattern
from sos-report-analyzer). Each UBI target uses the corresponding
`registry.access.redhat.com/ubi{8,9,10}/ubi:latest` base image with
`rust cargo gcc make` installed. Images are tagged with `YYYYMMDD` and
rebuilt automatically when older than 90 days.

## Code Conventions

- Parsers go in `src/parsers/`, return data structs
- Never crash on missing or corrupted cache files — return meaningful errors
- Use `thiserror` for error types
