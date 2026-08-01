# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through **GitHub Security
Advisories** for this repository (Security tab -> "Report a vulnerability").
Do not open a public issue for an unpatched vulnerability.

We aim to acknowledge reports within 3 business days and to provide a
remediation plan or a reasoned rejection within 14.

## Scope

This repository defines and implements the ACT capability-token wire format.
The following are always in scope and treated as high severity:

- Forgery or bypass of token signatures or verification steps
- Errors that let a verifier accept a malformed, expired, wrong-issuer,
  wrong-audience, or insufficiently scoped token
- Disclosure of private key material, seeds, or credentials
- Vulnerabilities in dependencies with a reachable exploit path

## Cryptographic notice

ACT envelopes use Ed25519 signatures over the exact CBOR-encoded claim bytes.
If you believe you have found a weakness in that composition, please include a
proof-of-concept against the conformance suite where possible - it shortens
triage considerably.
