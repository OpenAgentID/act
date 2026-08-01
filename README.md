# Agent Capability Token (ACT)

Canonical wire format for the Agent Capability Token required by the ANVIL
Capability Contract, with a reference implementation in Rust. The normative
format is defined in [SPECIFICATION.md](SPECIFICATION.md).

## Why this exists

ANVIL requires every compliant agent to operate under a scoped ACT, but no
document defined the token's byte encoding. Three implementations filled that gap
independently, and none could read another's output:

- The issuer encoded temporal claims as RFC 3339 text and identifiers as UUID
  byte strings.
- Two verifiers expected integer epoch seconds and text identifiers - agreeing
  with each other, and with nothing that was actually minted.

A real token failed to decode at its very first field. Each of the three
documented itself as matching the others.

Neither superseded format carried a version or an algorithm identifier, so
neither could be changed safely, and each verifier restated the issuer's entire
claim schema - including structures it never evaluated, each restatement a fresh
chance to drift.

This crate is the single normative definition. It is vendor-neutral and depends
on no product crate, so an issuer and a verifier share one format without either
depending on the other's implementation.

## Format at a glance

```
{
  "v":      1,          ; format version
  "alg":    "Ed25519",  ; signature algorithm
  "claims": bstr,       ; CBOR claim set - the signed bytes
  "sig":    bstr,       ; 64-byte raw Ed25519 signature over "claims"
  "kid":    tstr,       ; optional key identifier
}
```

Encoding follows CWT ([RFC 8392][cwt]) conventions where they apply: integer
epoch seconds, a flat scope array, text identifiers. It is **not** an RFC 8392
implementation and is not wire-compatible with one - claim keys are text rather
than the registered integer keys, and signing is raw Ed25519 rather than
COSE_Sign1.

[cwt]: https://www.rfc-editor.org/rfc/rfc8392

The signature covers the `claims` byte string exactly as it appears, so a
verifier never has to reproduce the issuer's encoding decisions byte for byte.
The corollary: to relay a token, forward the original bytes rather than
re-encoding them.

See [SPECIFICATION.md](SPECIFICATION.md) for the normative description.

## Verifying

```rust
use agent_capability_token::{verify, ActError, Verifier};

let verifier = Verifier::new(
    trusted_keys,                 // loaded from the issuer's key endpoint
    "arsenal:broker:prod-1",
    "my-service",
)?
.requiring_scopes(["tools:calendar:invoke".parse()?])
.with_leeway_seconds(30);

match verify(token_bytes, &verifier) {
    Ok(claims) => { /* authorized: claims.sub */ }
    Err(ActError::Expired { .. }) => { /* ask for a refresh */ }
    Err(other) => { /* reject, and alarm on SignatureInvalid */ }
}
```

Error variants are deliberately specific. A deployment that collapses them into
one "invalid token" outcome loses the ability to alarm on forgery while staying
quiet about ordinary expiry.

## Signing

Signing sits behind the `sign` feature, because most deployments verify in far
more places than they mint and a verifier has no reason to link signing code.

```toml
agent-capability-token = { version = "0.1", features = ["sign"] }
```

For an issuer whose key lives in an HSM, `claims_to_signing_payload` produces the
bytes to sign and `envelope_from_parts` assembles the result. This yields output
identical to in-process signing, which the test suite asserts.

## What it does not do

It carries claims and checks integrity, temporal validity, issuer, audience and
scope. It does not evaluate issuer policy. Rate limits, spend budgets, device and
network bindings and audit trace travel in the `ext` claim map as opaque signed
CBOR, and the components that own their meaning interpret them.

That boundary is the point. Restating those schemas in every verifier is what
produced the divergence above.

## Scopes

Three non-empty colon-separated segments, per ANVIL section 5.3:

```
service:resource:action
```

`*` is a wildcard in a **grant**. It is matched literally in a **request**, so a
holder of `tools:calendar:invoke` cannot escalate by asking for
`tools:calendar:*`.

Two-segment forms such as `tools:invoke` are invalid, and were a further point of
disagreement among the superseded implementations.

## Development

```bash
cargo test --all-features     # 19 conformance + 13 unit + 3 doc tests
cargo clippy --all-features --all-targets
cargo fmt --all -- --check
```

## License

Copyright © 2026 [L1fe Labs, Inc.](https://l1fe.ai)

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
