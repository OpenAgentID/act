# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately. Do not open a public issue for an
unpatched vulnerability.

- **GitHub:** this repository's **Security** tab -> **Report a vulnerability**
  opens a private advisory visible only to you and the maintainers.
- **Email:** <security@openagent.id>.

We aim to acknowledge reports within 3 business days and to provide a
remediation plan or a reasoned rejection within 14.

## Supported versions

Security fixes ship in the latest release of `agent-capability-token` and on
`main`. Upgrade to the latest release to receive them.

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
