# Contributing to the ACT crate

`agent-capability-token` is the canonical implementation of the Agent
Capability Token wire format, specified normatively by `SPECIFICATION.md`.
This crate exists because three previous implementations of the same format
diverged while each documenting itself as matching the others. The rule
flows from that history:

**The specification changes first, or the implementation does not change.**
A format change with no spec section is a divergence in waiting.

## Build and verify

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
cargo test --workspace
```

All three run in CI (`.github/workflows/ci.yml`). The test suite includes the
conformance suite; the `sign` feature is enabled for test targets only, so
verifier builds never link the signing half.

## Rules

- **Update `CHANGELOG.md` in the same change.**
- **Conventional commits**, breaking changes marked `!` with migration notes.
  No AI-tool attribution.
- **Strict SemVer against the envelope.** The `v` field exists for format
  evolution; a verifier must report an unimplemented version distinctly from
  a signature failure. Do not make the two indistinguishable.
- **Verification order is normative**: signature before claims. A change that
  lets claim checks leak unauthenticated content (into errors, logs, or
  behavior) is a security regression, not a refactor.
- **No placeholders.** Production-grade or not at all.

## License

Apache-2.0 OR MIT. By contributing you agree your contributions are licensed
under both.
