# Changelog

All notable changes to the Agent Capability Token format and its reference
implementation are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- npm scope renamed from `@openagent/*` to `@openagentid/*` (the `@openagent`
  scope is held by an unaffiliated third party). This affects the TypeScript
  package names referenced in docs and the conformance vector descriptions
  (e.g. `@openagentid/crypto-wasm`); the ACT wire format itself is unchanged.
  Breaking for consumers only once packages are published to npm.

### Added

- `examples/gen_conformance_vectors.rs` exports the conformance suite as 13
  JSON vectors (`openagent-sdk/conformance/vectors/arsenal/act-verify.json`):
  valid tokens, wildcard coverage, scope refusal, expiry, not-yet-valid,
  leeway, audience and issuer refusal, foreign key, tampering, unsupported
  version (normative version-first ordering), oversized payloads, and
  multi-audience. Envelopes are minted deterministically (fixed seed, pinned
  claims); runners in both languages verify through the canonical
  implementation - the Rust runner through this crate, the TypeScript runner
  through `@openagent/crypto-wasm` - never a handwritten re-implementation,
  which is the drift rule. Both runners pass 212/212 with drift: 0.
- Community health files: CONTRIBUTING, SECURITY, CODEOWNERS, AGENTS.md, and
  issue/PR templates. The license files (`LICENSE-APACHE`, `LICENSE-MIT`)
  were committed with the initial workspace.
- First-party CI (`.github/workflows/ci.yml`): fmt, clippy, and the
  conformance suite on every change, plus a CODEOWNERS resolution check.
- `SPECIFICATION.md`, the first normative definition of the ACT byte format.
  ANVIL section 5 requires every compliant agent to operate under a scoped ACT
  but never defined its encoding, and the absence of that document is what
  allowed three mutually unreadable implementations to be written, each
  documenting itself as matching the others.
- `agent-capability-token`, the reference implementation: envelope encoding,
  Ed25519 signing and verification, the claim set, and the
  `service:resource:action` scope grammar with wildcard matching.
- A versioned envelope carrying `v` and `alg`. Neither superseded format carried
  either, which left no way to roll out a format change or migrate off Ed25519.
  A verifier reports an unimplemented version distinctly from a signature
  failure, since a newer issuer and a forgery call for opposite responses.
- Typed `cnf` and `delegation` claims, so a verifier cannot silently fail to
  enforce the proof-of-possession binding and delegation subsetting that ANVIL
  section 5.2 requires. CBOR decoders drop unknown members by default, so a
  verifier built on a reduced claim schema would accept a token while
  disregarding the constraints its issuer attached.
- An `ext` claim map for issuer-defined policy - rate limits, budgets, device and
  network bindings, audit trace - carried inside the signature but with its
  schema left to the components that own it. Restating those schemas in every
  verifier is precisely what produced the divergence this format replaces.
- Detached signing (`claims_to_signing_payload` plus `envelope_from_parts`) for
  issuers holding keys in an HSM, asserted to produce bytes identical to
  in-process signing so that moving a key into an HSM cannot silently change wire
  output.
- Conformance suite of 19 integration tests alongside 13 unit tests, covering
  tamper detection, foreign-key rejection, verification ordering, temporal
  boundaries with leeway, scope matching including the non-widening rule, version
  and algorithm rejection, oversized input, and malformed signatures.

### Fixed

- The conformance suite did not compile under a plain `cargo test`. It has to
  mint tokens in order to check that they verify, and signing sits behind the
  non-default `sign` feature. A dev-dependency on this crate with that feature
  enables it for the test targets only, so verifiers - the dependency-sensitive
  side - still get a build without the signing half.

### Notes on specific decisions

- Signatures cover the `claims` byte string as it appears on the wire, not a
  re-serialization of the decoded claims. Formats that sign a canonicalized
  structure force every implementation to agree on canonicalization, and
  disagreements surface as signature failures that are very hard to diagnose. The
  consequence is that relaying a token means forwarding the original bytes.
- Verification order is normative: the signature is checked before any claim. A
  verifier that checks `exp` first reports a forged token as expired and emits its
  unauthenticated `sub` and `iss` into logs as though established.
- A verifier constructed with an empty trusted key set fails at construction
  rather than rejecting every token at runtime, so a misconfiguration does not
  present as a stream of signature failures.
- `kid` is treated as a hint for audit and rotation, never as authoritative for
  key selection, since honouring it would let a sender steer verification away
  from the key that would have validated the token.
- Scope wildcards expand in a grant and are literal in a request, so a holder
  cannot widen its own authority by requesting `*`.
