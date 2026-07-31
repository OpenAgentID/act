# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through **GitHub Security
Advisories** for this repository (Security tab -> "Report a vulnerability").
Do not open a public issue for an unpatched vulnerability.

We aim to acknowledge reports within 3 business days and to provide a
remediation plan or a reasoned rejection within 14.

## Scope

This repository builds identity and credential infrastructure. The following
are always in scope and treated as high severity:

- Forgery or bypass of token signatures, lineage proofs, or verification steps
- Errors that let a verifier accept a malformed, expired, or wrong-audience token
- Disclosure of private key material, seeds, or credentials
- Vulnerabilities in dependencies with a reachable exploit path

## Cryptographic notice

Signing and verification use Ed25519; hashing uses BLAKE3; CBOR is used for
wire encoding. If you believe you have found a weakness in how these are
composed, please include a proof-of-concept against the conformance vectors
where possible - it shortens triage considerably.
