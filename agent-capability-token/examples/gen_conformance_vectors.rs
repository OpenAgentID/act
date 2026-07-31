//! Generate the ACT conformance vectors for the OpenAgent SDK conformance
//! suite (`openagent-sdk/conformance/vectors/arsenal/act-verify.json`).
//!
//! Deterministic: fixed signing seed, pinned claims. Regenerate after any
//! format change and review the diff — a changed byte here is a changed wire
//! format, which is exactly what the suite exists to catch.
//!
//! Usage: cargo run --example gen_conformance_vectors -- <output-path>

use agent_capability_token::{sign, ActClaims, Scope};
use ed25519_dalek::SigningKey;

const SIGNER_SEED: [u8; 32] = [7u8; 32];
const FOREIGN_SEED: [u8; 32] = [9u8; 32];

const IAT: i64 = 1_800_000_000;
const EXP: i64 = 1_800_000_600;

fn base_claims(aud: Vec<String>) -> ActClaims {
    ActClaims {
        jti: "vector-act-1".to_string(),
        sub: "did:oas:l1fe:agent:vector".to_string(),
        iss: "arsenal:broker:test-1".to_string(),
        aud,
        iat: IAT,
        nbf: IAT,
        exp: EXP,
        tenant_id: "tenant-a".to_string(),
        scope: vec![
            Scope::parse("tools:calendar:invoke").expect("scope"),
            Scope::parse("tools:*:send").expect("wildcard"),
        ],
        cnf: None,
        delegation: None,
        ext: Default::default(),
    }
}

fn input(
    envelope_hex: &str,
    trusted_key_hex: &str,
    issuer: &str,
    audience: &str,
    scopes: Vec<&str>,
    leeway: i64,
    now: i64,
) -> serde_json::Value {
    serde_json::json!({
        "operation": "verify",
        "envelope_hex": envelope_hex,
        "trusted_key_hex": trusted_key_hex,
        "issuer": issuer,
        "audience": audience,
        "scopes": scopes,
        "leeway_seconds": leeway,
        "now_unix_seconds": now,
    })
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "act-verify.json".to_string());

    let signing_key = SigningKey::from_bytes(&SIGNER_SEED);
    let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let foreign_hex = hex::encode(SigningKey::from_bytes(&FOREIGN_SEED).verifying_key().to_bytes());

    let envelope = sign(&base_claims(vec!["omerta".to_string()]), &signing_key, None)
        .expect("signs");
    let envelope_hex = hex::encode(&envelope);

    let multi_envelope = sign(
        &base_claims(vec!["omerta".to_string(), "other-service".to_string()]),
        &signing_key,
        None,
    )
    .expect("signs multi");
    let multi_hex = hex::encode(&multi_envelope);

    // Tampered envelope: flip one byte inside the claims byte string.
    let mut tampered = envelope.clone();
    let claims_offset = 10; // comfortably inside the claims bytes for this fixture
    tampered[claims_offset] ^= 0x01;
    let tampered_hex = hex::encode(&tampered);

    // Unsupported version: re-encode the envelope with v = 99. The signature
    // covers only the claims bytes, so this envelope's signature is valid -
    // and the version check must still fire first.
    let decoded = agent_capability_token::ActEnvelope::decode(&envelope).expect("decode");
    let v99_value = ciborium::Value::Map(vec![
        (ciborium::Value::Text("v".into()), ciborium::Value::Integer(99.into())),
        (
            ciborium::Value::Text("alg".into()),
            ciborium::Value::Text(decoded.alg.clone()),
        ),
        (
            ciborium::Value::Text("claims".into()),
            ciborium::Value::Bytes(decoded.claims.clone().into_vec()),
        ),
        (
            ciborium::Value::Text("sig".into()),
            ciborium::Value::Bytes(decoded.sig.clone().into_vec()),
        ),
    ]);
    let mut v99_bytes = Vec::new();
    ciborium::into_writer(&v99_value, &mut v99_bytes).expect("encode v99");
    let v99_hex = hex::encode(&v99_bytes);

    // Oversized: 20 KiB of zeros (over the 16 KiB cap).
    let oversized_hex = hex::encode(vec![0u8; 20 * 1024]);

    let iss = "arsenal:broker:test-1";
    let aud = "omerta";
    let valid_now = IAT + 300;

    let vectors = serde_json::json!({
        "category": "arsenal",
        "name": "act-verify",
        "description": "Canonical ACT verification vectors (act/SPECIFICATION.md). Envelopes are minted by the reference implementation with a fixed seed; each vector asserts the verifier's verdict and, on acceptance, key claims. Runners MUST verify through the canonical implementation (Rust: agent-capability-token; TS: @openagent/crypto-wasm act_verify) - never a handwritten re-implementation, which is the drift this suite exists to prevent.",
        "spec": "act/SPECIFICATION.md",
        "vectors": [
            {
                "name": "valid-exact-scope",
                "description": "Valid token with an exact scope requirement",
                "tags": ["accept", "scope"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec!["tools:calendar:invoke"], 0, valid_now),
                "expected_output": { "verdict": "accept", "sub": "did:oas:l1fe:agent:vector", "jti": "vector-act-1", "tenant_id": "tenant-a" }
            },
            {
                "name": "valid-wildcard-coverage",
                "description": "Grant tools:*:send covers the requested tools:email:send",
                "tags": ["accept", "wildcard"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec!["tools:email:send"], 0, valid_now),
                "expected_output": { "verdict": "accept", "sub": "did:oas:l1fe:agent:vector" }
            },
            {
                "name": "scope-not-covered",
                "description": "A scope the grant does not cover is refused",
                "tags": ["reject", "scope"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec!["billing:invoices:write"], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "scope" }
            },
            {
                "name": "expired",
                "description": "Token evaluated one second past expiry",
                "tags": ["reject", "temporal"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec![], 0, EXP + 1),
                "expected_output": { "verdict": "reject", "reason_class": "expired" }
            },
            {
                "name": "not-yet-valid",
                "description": "Token evaluated before its not-before",
                "tags": ["reject", "temporal"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec![], 0, IAT - 61),
                "expected_output": { "verdict": "reject", "reason_class": "not valid until" }
            },
            {
                "name": "leeway-accepts-early",
                "description": "Same early evaluation passes with 60s leeway",
                "tags": ["accept", "temporal", "leeway"],
                "input": input(&envelope_hex, &public_hex, iss, aud, vec![], 60, IAT - 30),
                "expected_output": { "verdict": "accept", "sub": "did:oas:l1fe:agent:vector" }
            },
            {
                "name": "wrong-audience",
                "description": "Verifier bound to a different audience refuses",
                "tags": ["reject", "audience"],
                "input": input(&envelope_hex, &public_hex, iss, "someone-else", vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "audience" }
            },
            {
                "name": "wrong-issuer",
                "description": "Verifier naming a different issuer refuses",
                "tags": ["reject", "issuer"],
                "input": input(&envelope_hex, &public_hex, "arsenal:broker:evil", aud, vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "issuer" }
            },
            {
                "name": "foreign-key",
                "description": "Signature against a key not in the trusted set",
                "tags": ["reject", "signature"],
                "input": input(&envelope_hex, &foreign_hex, iss, aud, vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "signature" }
            },
            {
                "name": "tampered-envelope",
                "description": "One claims byte flipped; signature must fail",
                "tags": ["reject", "tamper"],
                "input": input(&tampered_hex, &public_hex, iss, aud, vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "" }
            },
            {
                "name": "unsupported-version",
                "description": "v=99 envelope with an otherwise-valid signature: the version check is normative-first",
                "tags": ["reject", "version"],
                "input": input(&v99_hex, &public_hex, iss, aud, vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "version" }
            },
            {
                "name": "oversized-payload",
                "description": "20 KiB of zeros exceeds the 16 KiB cap",
                "tags": ["reject", "size"],
                "input": input(&oversized_hex, &public_hex, iss, aud, vec![], 0, valid_now),
                "expected_output": { "verdict": "reject", "reason_class": "exceeding" }
            },
            {
                "name": "multi-audience",
                "description": "Token valid for either of two audiences",
                "tags": ["accept", "audience"],
                "input": input(&multi_hex, &public_hex, iss, "other-service", vec![], 0, valid_now),
                "expected_output": { "verdict": "accept", "sub": "did:oas:l1fe:agent:vector" }
            }
        ]
    });

    let rendered = serde_json::to_string_pretty(&vectors).expect("render");
    std::fs::write(&out_path, rendered + "\n").expect("write");
    eprintln!("wrote {out_path}");
}
