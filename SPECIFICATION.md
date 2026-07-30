# Agent Capability Token (ACT) Wire Format

**Version:** 1
**Status:** Draft
**Requires:** ANVIL Specification section 5 (Capability Contract)

## 1. Introduction

### 1.1 Purpose

ANVIL section 5 requires that every compliant agent operate under a scoped Agent
Capability Token, and defines what a token must express: a scope grant, a
proof-of-possession binding to the agent's OAS DID, and constraints ensuring
delegated capabilities are a strict subset of their parent's. It does not define
how a token is encoded.

This document supplies that definition. It is the normative description of the
ACT byte format, so that an issuer and a verifier written independently
interoperate.

### 1.2 Motivation

Three implementations previously filled this gap independently, and none could
read another's output. The issuer encoded temporal claims as RFC 3339 text and
identifiers as UUID byte strings; two verifiers expected integer epoch seconds
and text identifiers, agreeing with each other and with nothing that was minted.
A token failed to decode at its first field. Each implementation documented
itself as matching the others.

Two properties of that failure inform this specification. Neither format carried
a version or an algorithm identifier, so neither could be changed safely. And
each verifier restated the issuer's full claim schema, so every schema change
invited fresh divergence. Section 4.3 addresses the second directly.

### 1.3 Scope

This specification defines:

- The ACT envelope structure and its CBOR encoding
- The claim set, and which claims a verifier is required to enforce
- The signing and verification procedure
- The capability scope grammar and its matching rules

This specification does NOT define:

- Token issuance policy, or who may request a token
- Credential storage, brokering, or proxying
- Revocation distribution mechanisms
- Rate limiting, budget, or binding semantics (see section 4.3)

### 1.4 Relationship to CWT

Encoding choices follow CWT (RFC 8392) conventions where they apply: integer
epoch seconds for temporal claims, a flat array for scopes, and text for
identifiers.

This format is **not** an RFC 8392 implementation, and is not wire-compatible
with one. Claim keys are text rather than the registered CWT integer keys, and
signing is raw Ed25519 over the claims byte string rather than COSE_Sign1. The
conventions are borrowed because they are well-reasoned; conformance is not
claimed.

### 1.5 Requirements Language

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described
in RFC 2119.

## 2. Envelope

An ACT is a CBOR map with the following members.

```cddl
act-envelope = {
  "v":       uint,        ; format version
  "alg":     tstr,        ; signature algorithm identifier
  "claims":  bstr,        ; CBOR-encoded claim set
  "sig":     bstr,        ; signature over the "claims" byte string
  ? "kid":   tstr,        ; key identifier
}
```

| Member | Type | Required | Description |
|--------|------|----------|-------------|
| `v` | uint | Yes | Format version. MUST be `1` for this specification. |
| `alg` | tstr | Yes | Signature algorithm. MUST be `"Ed25519"` for this version. |
| `claims` | bstr | Yes | The CBOR-encoded claim set of section 3. |
| `sig` | bstr | Yes | Exactly 64 bytes: a raw Ed25519 signature over the `claims` byte string. |
| `kid` | tstr | No | Identifies the signing key, to support rotation and audit. |

A verifier MUST reject an envelope whose `v` it does not implement, and MUST
distinguish that rejection from a signature failure. A token from a newer issuer
and a forgery are operationally opposite situations, and a verifier that reports
both identically leaves an operator unable to tell a rollout from an attack.

A verifier MUST reject an envelope whose `alg` it does not implement.

Unknown envelope members MUST be ignored.

### 2.1 The signature covers the claims byte string

`sig` is computed over the bytes of `claims` exactly as they appear in the
envelope, not over a re-serialization of the decoded claim set.

This is a deliberate constraint. A verifier never needs to reproduce the
issuer's encoding decisions - map ordering, integer width, string
representation - in order to check a signature. Formats that sign a
canonicalized structure instead require every implementation to agree on
canonicalization, and disagreements surface as signature failures that are
extremely difficult to diagnose.

A consequence is that a verifier MUST NOT re-encode claims and expect the
signature to hold. To relay a token, forward the original bytes.

### 2.2 Size limit

An encoded ACT MUST NOT exceed 16384 bytes (16 KiB).

A verifier MUST enforce this ceiling before parsing, so that an oversized
payload cannot drive allocation ahead of any validation.

## 3. Claim set

The `claims` member decodes to a CBOR map with text keys.

```cddl
act-claims = {
  "jti":          tstr,
  "sub":          tstr,
  "iss":          tstr,
  "aud":          tstr / [+ tstr],
  "iat":          int,
  ? "nbf":        int,
  "exp":          int,
  "tenant_id":    tstr,
  "scope":        [* scope],
  ? "cnf":        confirmation,
  ? "delegation": delegation,
  ? "ext":        { * tstr => any },
}
```

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `jti` | tstr | Yes | Token identifier, unique per issuance. A UUID MUST be carried in canonical hyphenated text form, not as bytes. |
| `sub` | tstr | Yes | The OAS DID of the agent the token was issued to. |
| `iss` | tstr | Yes | Identifier of the issuing broker instance. |
| `aud` | tstr or array | Yes | Intended audiences. A single audience MAY be written as a bare string. |
| `iat` | int | Yes | Issuance time, in seconds since the Unix epoch. |
| `nbf` | int | No | Not-before time, in seconds since the Unix epoch. Defaults to `0`. |
| `exp` | int | Yes | Expiry time, in seconds since the Unix epoch. |
| `tenant_id` | tstr | Yes | Tenant the token is scoped to. |
| `scope` | array | Yes | Granted scopes, as a flat array of strings per section 5. |
| `cnf` | map | No | Proof-of-possession binding, section 3.1. |
| `delegation` | map | No | Onward delegation constraints, section 3.2. |
| `ext` | map | No | Issuer-defined claims, section 4.3. |

Timestamps are integer epoch seconds. An implementation MUST NOT encode them as
text.

Unknown top-level claims MUST be ignored, so that an issuer can introduce a
typed claim without breaking deployed verifiers. Issuer-specific claims belong
in `ext` rather than at the top level.

### 3.1 `cnf` - proof-of-possession

```cddl
confirmation = {
  "key_fingerprint": tstr,
  "alg":             tstr,
}
```

ANVIL section 5.2 requires an ACT to be bound to the agent's OAS DID by
proof-of-possession. `cnf` names the key the holder must demonstrate control of.

A verifier that enforces proof-of-possession MUST treat a missing `cnf` as a
failure rather than as an absence of constraint. Ignoring this claim makes a
captured token usable by whoever holds it, which is the property
proof-of-possession exists to prevent.

Demonstrating possession is out of scope here; it is a property of the calling
protocol, not of the token.

### 3.2 `delegation` - onward delegation constraints

```cddl
delegation = {
  "allow_delegation":            bool,
  "max_depth":                   uint,
  ? "delegatable_scopes":        [* scope],
  "allow_any_delegate":          bool,
  ? "allowed_delegates":         [* tstr],
  ? "min_ttl_reduction_seconds": int,
}
```

ANVIL section 5.2 requires that an agent not delegate capabilities it does not
hold, and that child capabilities be a strict subset of the parent's.

An issuer minting a delegated token MUST ensure that:

- the parent's `allow_delegation` is true;
- the parent's `max_depth` is greater than zero, and the child's `max_depth` is
  less than the parent's;
- the child's `scope` is a subset of the parent's `delegatable_scopes` when
  present, and of the parent's `scope` otherwise;
- the child's `exp` is at least `min_ttl_reduction_seconds` earlier than the
  parent's;
- the child's `sub` appears in `allowed_delegates`, unless
  `allow_any_delegate` is true.

An omitted `delegatable_scopes` means the parent's full scope set is
delegatable, subject to `allow_delegation`. It does not mean no scope is
delegatable.

## 4. Verification

### 4.1 Procedure

A verifier MUST perform these steps in order.

1. Reject the input if it exceeds the section 2.2 size limit.
2. Decode the envelope. Reject an unimplemented `v` or `alg`.
3. Reject an absent signature, or one that is not exactly 64 bytes.
4. Verify the signature over the `claims` byte string against the trusted key
   set. Reject if no key validates.
5. Decode the claim set, and reject a structurally invalid one: a blank required
   claim, or an `nbf` that is not before `exp`.
6. Reject if `exp` is at or before the current time, or `nbf` is after it,
   allowing for configured leeway.
7. Reject if `iss` does not match the expected issuer.
8. Reject if `aud` does not contain the expected audience.
9. Reject if any required scope is not covered by `scope`, per section 5.2.

### 4.2 Order is normative

Signature verification MUST precede every claim check.

Until step 4 completes, the claim set is attacker-controlled. A verifier that
checks `exp` first will report a forged token as expired, and will emit its
unauthenticated `sub` and `iss` into logs and metrics as though they were
established facts. Reversing these steps does not weaken the cryptography, but it
does mean an operator cannot distinguish forgery attempts from ordinary expiry.

A verifier configured with an empty trusted key set MUST fail at construction
rather than at first use. Such a verifier rejects every token, and doing so as a
stream of signature failures rather than a startup error disguises a
misconfiguration as an attack.

### 4.3 `ext` - claims this specification deliberately does not define

Issuers carry policy that verifiers do not evaluate: rate limits, spend budgets,
device and session bindings, network restrictions, audit trace. These belong in
`ext`.

`ext` is inside `claims`, so its contents are covered by the signature and can
be neither stripped nor altered in transit. This specification does not define
their schema; the components that own their meaning do.

This boundary is the direct lesson of the divergence described in section 1.2.
Each verifier had restated the issuer's full claim schema, including structures
it never evaluated, and each restatement was a fresh opportunity to drift. A
verifier now types what it enforces and passes through what it does not.

A verifier that does not understand a member of `ext` MUST preserve it when
relaying, so that a downstream component which does understand it still receives
an intact, signed value.

## 5. Scopes

### 5.1 Grammar

A scope is a text string of exactly three non-empty, colon-separated segments:

```
scope = service ":" resource ":" action
```

This matches ANVIL section 5.3, which specifies `tools:<tool-id>:invoke` for
external tools and `runtime:platform:*` for runtime-granted platform
capabilities.

A verifier MUST reject a scope that does not have exactly three non-empty
segments. Two-segment forms such as `tools:invoke` are invalid.

Scopes are encoded as a flat array of strings. An implementation MUST NOT encode
the scope set as a nested structure.

### 5.2 Matching

The segment `*` is a wildcard. A granted scope covers a requested scope when
each of the granted segments either equals the corresponding requested segment
or is `*`.

Matching is directional. A wildcard in a **requested** scope is matched
literally and MUST NOT expand. Otherwise a holder of `tools:calendar:invoke`
could request `tools:calendar:*` and be authorized for actions it was never
granted.

Given a grant of `runtime:platform:*`:

| Requested | Result |
|-----------|--------|
| `runtime:platform:spawn` | Authorized |
| `runtime:platform:*` | Authorized - the grant is itself a wildcard |
| `runtime:network:spawn` | Denied |

Given a grant of `tools:calendar:invoke`:

| Requested | Result |
|-----------|--------|
| `tools:calendar:invoke` | Authorized |
| `tools:calendar:*` | Denied - a request must not widen a grant |
| `tools:*:invoke` | Denied |

## 6. Cryptography

Signatures are Ed25519 (RFC 8032), computed over the `claims` byte string. A
signature is exactly 64 bytes, carried raw rather than base64-encoded: the
envelope is already a binary format, and encoding bytes as text inside it adds
a third of their length for nothing.

Algorithm agility is provided by the `alg` member. A future version adding an
algorithm MUST register its identifier and its signature length, and MUST NOT
reuse `"Ed25519"`.

Nothing in this format requires a signer to surrender private key material. An
issuer holding its key in an HSM produces the `claims` byte string, signs it
externally, and assembles the envelope from the parts. This MUST yield bytes
identical to in-process signing.

## 7. Versioning

`v` is the format version. This document defines version 1.

An incompatible change MUST increment `v`. A compatible change - adding an
optional claim, or a member of `ext` - MUST NOT.

A verifier encountering a higher `v` MUST reject the token with a distinct
error, per section 2.

## 8. Security considerations

**Verification order.** See section 4.2. Checking claims before the signature
lets unauthenticated content into decisions and logs.

**Proof-of-possession.** A verifier that ignores `cnf` cannot distinguish a
legitimate holder from an attacker replaying a captured token. See section 3.1.

**Delegation.** A verifier that ignores `delegation` cannot detect a token
claiming authority beyond its parent's. See section 3.2.

**Silent claim loss.** CBOR decoders ignore unknown members by default. A
verifier built on a reduced claim schema will therefore accept a token while
disregarding constraints the issuer attached to it - and will do so silently.
This is why `cnf` and `delegation` are typed in this specification rather than
left to `ext`: a verifier that must enforce them cannot fail to see them.

**Size limits.** The section 2.2 ceiling MUST be enforced before parsing.

**Clock skew.** Leeway on temporal checks trades a window of accepted expired
tokens for resilience to unsynchronized clocks. It SHOULD be small - tens of
seconds - and MUST NOT be unbounded.

**Key rotation.** `kid` is a sender-supplied hint. A verifier MUST NOT treat it
as authoritative when selecting a key, since doing so would let a sender steer
verification away from the key that would have validated the token.

## 9. Test vectors

The reference implementation's conformance suite
(`agent-capability-token/tests/conformance.rs`) exercises the required
behaviours: round-tripping a full claim set, extension preservation, tamper
detection, foreign-key rejection, verification ordering, temporal boundaries
including leeway, issuer and audience mismatch, scope matching including the
non-widening rule, version and algorithm rejection, oversized input, malformed
signatures, and equivalence of detached and in-process signing.

## 10. References

- ANVIL Specification, section 5 (Capability Contract)
- RFC 2119 - Key words for use in RFCs
- RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 8392 - CBOR Web Token (CWT), for encoding conventions only; see section 1.4
- RFC 8949 - Concise Binary Object Representation (CBOR)
- W3C DID Core - referenced by OAS for the `sub` claim
