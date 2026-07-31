# AGENTS.md

Rules for agents (human or otherwise) working in this repository.

## Non-negotiables

- **Changelog in the same change.** Update `CHANGELOG.md` (see the repo root)
  with every code, docs, test, config, or schema change. Work is not complete
  until the entry exists.
- **Conventional commits.** `feat:`, `fix:`, `refactor:`, `test:`, `chore:`,
  `ci:`, `docs:`. Breaking changes carry `!` and a migration note in the body.
- **No AI-tool attribution** anywhere in git history - no Co-Authored-By
  trailers, no tool names in messages.
- **CI is the gate.** Run the same commands locally that
  `.github/workflows/ci.yml` runs before pushing: fmt, clippy, tests.
- **No placeholders.** No TODOs, no stub implementations presented as
  finished, no "temporary" shortcuts. Production-grade or not at all.
- **Fail closed.** Verification, authorization, and anchor checks error on
  the side of refusal.

## Repo-specific invariants

See CONTRIBUTING.md - it carries the build commands and the lessons-learned
rules that are specific to this repository. Read it before your first change.
