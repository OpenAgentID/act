//! Round-trip and rejection tests for the canonical ACT format.
//!
//! Signing keys are built from fixed seeds rather than generated, so a failure
//! reproduces exactly instead of depending on which key the run happened to draw.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use agent_capability_token::{
    claims_to_signing_payload, envelope_from_parts, sign, verify, ActClaims, ActEnvelope, ActError,
    Confirmation, Delegation, Scope, Verifier, FORMAT_VERSION, MAX_ACT_BYTES,
};
use ed25519_dalek::SigningKey;

const ISSUER: &str = "arsenal:broker:test-1";
const AUDIENCE: &str = "omerta";
const NOW: i64 = 1_800_000_000;

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn foreign_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn scope(s: &str) -> Scope {
    s.parse().expect("valid scope")
}

fn claims() -> ActClaims {
    ActClaims {
        jti: "018f4c1e-0000-7000-8000-00000000abcd".to_string(),
        sub: "did:oas:l1fe:agent:alpha".to_string(),
        iss: ISSUER.to_string(),
        aud: vec![AUDIENCE.to_string()],
        iat: NOW,
        nbf: NOW,
        exp: NOW + 300,
        tenant_id: "acme".to_string(),
        scope: vec![scope("tools:calendar:invoke"), scope("runtime:platform:*")],
        cnf: Some(Confirmation {
            key_fingerprint: "z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP".to_string(),
            alg: "Ed25519".to_string(),
        }),
        delegation: Some(Delegation {
            allow_delegation: true,
            max_depth: 2,
            delegatable_scopes: Some(vec![scope("tools:calendar:invoke")]),
            allow_any_delegate: false,
            allowed_delegates: vec!["did:oas:l1fe:agent:beta".to_string()],
            min_ttl_reduction_seconds: 60,
        }),
        ext: BTreeMap::new(),
    }
}

fn verifier() -> Verifier {
    Verifier::new(
        vec![issuer_key().verifying_key().to_bytes()],
        ISSUER,
        AUDIENCE,
    )
    .expect("verifier builds")
    .with_clock(NOW + 10)
}

fn mint(claims: &ActClaims) -> Vec<u8> {
    sign(claims, &issuer_key(), Some("test-1".to_string())).expect("token signs")
}

#[test]
fn round_trips_a_full_claim_set() {
    let original = claims();
    let token = mint(&original);

    let decoded = verify(&token, &verifier()).expect("token verifies");

    assert_eq!(
        decoded, original,
        "claims must survive the round trip intact"
    );
}

#[test]
fn preserves_issuer_defined_extension_claims() {
    // The extension map is how issuer-owned policy travels without this crate
    // restating its schema. It must survive verification byte-for-byte, or a
    // downstream component that does understand it receives a mangled value.
    let mut original = claims();
    original.ext.insert(
        "limits".to_string(),
        ciborium::Value::Map(vec![(
            ciborium::Value::Text("requests_per_second".into()),
            ciborium::Value::from(50),
        )]),
    );
    original
        .ext
        .insert("budget_micro".to_string(), ciborium::Value::from(250_000));

    let decoded = verify(&mint(&original), &verifier()).expect("token verifies");

    assert_eq!(decoded.ext, original.ext);
}

#[test]
fn rejects_a_tampered_claims_payload() {
    let token = mint(&claims());
    let mut envelope = ActEnvelope::decode(&token).expect("envelope decodes");

    // Re-encode the claims with an extended expiry, leaving the signature as is.
    let mut escalated = claims();
    escalated.exp = NOW + 86_400;
    envelope.claims =
        serde_bytes::ByteBuf::from(claims_to_signing_payload(&escalated).expect("claims encode"));
    let forged = envelope.encode().expect("envelope encodes");

    let error = verify(&forged, &verifier()).expect_err("tampered claims must be rejected");
    assert!(
        matches!(error, ActError::SignatureInvalid { .. }),
        "expected a signature failure, got {error}"
    );
}

#[test]
fn rejects_a_signature_from_an_untrusted_key() {
    let claims = claims();
    let token = sign(&claims, &foreign_key(), None).expect("token signs");

    let error = verify(&token, &verifier()).expect_err("foreign signature must be rejected");
    assert!(matches!(error, ActError::SignatureInvalid { tried: 1 }));
}

#[test]
fn signature_is_checked_before_any_claim() {
    // Ordering matters: a forged token must be rejected as forged, not as
    // expired, so that unauthenticated content never reaches a decision or a
    // log line as though it were trusted.
    let mut stale = claims();
    stale.exp = NOW - 1;
    stale.nbf = NOW - 600;
    stale.iat = NOW - 600;
    let token = sign(&stale, &foreign_key(), None).expect("token signs");

    let error = verify(&token, &verifier()).expect_err("must be rejected");
    assert!(
        matches!(error, ActError::SignatureInvalid { .. }),
        "expected the signature check to run first, got {error}"
    );
}

#[test]
fn rejects_an_expired_token() {
    let token = mint(&claims());
    let late = verifier().with_clock(NOW + 3_600);

    let error = verify(&token, &late).expect_err("expired token must be rejected");
    assert!(matches!(error, ActError::Expired { .. }), "got {error}");
}

#[test]
fn rejects_a_token_presented_before_its_nbf() {
    let token = mint(&claims());
    let early = verifier().with_clock(NOW - 60);

    let error = verify(&token, &early).expect_err("premature token must be rejected");
    assert!(matches!(error, ActError::NotYetValid { .. }), "got {error}");
}

#[test]
fn leeway_absorbs_clock_skew_at_both_edges() {
    let token = mint(&claims());

    // A verifier whose clock trails the issuer's would otherwise reject a token
    // minted moments ago.
    let trailing = verifier().with_clock(NOW - 20).with_leeway_seconds(30);
    assert!(
        verify(&token, &trailing).is_ok(),
        "nbf edge must be tolerated"
    );

    let leading = verifier().with_clock(NOW + 310).with_leeway_seconds(30);
    assert!(
        verify(&token, &leading).is_ok(),
        "exp edge must be tolerated"
    );

    // Beyond the allowance it must still fail.
    let far = verifier().with_clock(NOW + 400).with_leeway_seconds(30);
    assert!(matches!(
        verify(&token, &far),
        Err(ActError::Expired { .. })
    ));
}

#[test]
fn rejects_an_issuer_or_audience_mismatch() {
    let token = mint(&claims());

    let wrong_issuer = Verifier::new(
        vec![issuer_key().verifying_key().to_bytes()],
        "arsenal:broker:other",
        AUDIENCE,
    )
    .expect("verifier builds")
    .with_clock(NOW + 10);
    assert!(matches!(
        verify(&token, &wrong_issuer),
        Err(ActError::IssuerMismatch { .. })
    ));

    let wrong_audience = Verifier::new(
        vec![issuer_key().verifying_key().to_bytes()],
        ISSUER,
        "someone-else",
    )
    .expect("verifier builds")
    .with_clock(NOW + 10);
    assert!(matches!(
        verify(&token, &wrong_audience),
        Err(ActError::AudienceMismatch { .. })
    ));
}

#[test]
fn enforces_required_scopes_with_wildcard_expansion() {
    let token = mint(&claims());

    // Granted directly.
    let direct = verifier().requiring_scopes([scope("tools:calendar:invoke")]);
    assert!(verify(&token, &direct).is_ok());

    // Covered by the granted `runtime:platform:*`.
    let wildcarded = verifier().requiring_scopes([scope("runtime:platform:spawn")]);
    assert!(verify(&token, &wildcarded).is_ok());

    // Not granted at all.
    let absent = verifier().requiring_scopes([scope("secrets:vault:read")]);
    let error = verify(&token, &absent).expect_err("ungranted scope must be rejected");
    assert!(matches!(error, ActError::MissingScope(_)), "got {error}");
}

#[test]
fn a_holder_cannot_widen_scope_by_requesting_a_wildcard() {
    let mut narrow = claims();
    narrow.scope = vec![scope("tools:calendar:invoke")];
    let token = mint(&narrow);

    let escalating = verifier().requiring_scopes([scope("tools:calendar:*")]);
    assert!(matches!(
        verify(&token, &escalating),
        Err(ActError::MissingScope(_))
    ));
}

#[test]
fn rejects_an_unsupported_format_version() {
    let token = mint(&claims());
    let mut envelope = ActEnvelope::decode(&token).expect("envelope decodes");
    envelope.v = FORMAT_VERSION + 1;
    let future = envelope.encode().expect("envelope encodes");

    let error = ActEnvelope::decode(&future).expect_err("unknown version must be rejected");
    assert!(
        matches!(error, ActError::UnsupportedVersion { .. }),
        "a version bump must be distinguishable from a forgery, got {error}"
    );
}

#[test]
fn rejects_an_unsupported_algorithm() {
    let token = mint(&claims());
    let mut envelope = ActEnvelope::decode(&token).expect("envelope decodes");
    envelope.alg = "RSA-PSS".to_string();
    let swapped = envelope.encode().expect("envelope encodes");

    assert!(matches!(
        ActEnvelope::decode(&swapped),
        Err(ActError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn rejects_an_oversized_payload_before_parsing() {
    let oversized = vec![0u8; MAX_ACT_BYTES + 1];
    let error = verify(&oversized, &verifier()).expect_err("oversized input must be rejected");
    assert!(matches!(error, ActError::TooLarge { .. }), "got {error}");
}

#[test]
fn rejects_a_missing_or_malformed_signature() {
    let claims_bytes = claims_to_signing_payload(&claims()).expect("claims encode");

    let short = envelope_from_parts(claims_bytes.clone(), &[0u8; 32], None);
    assert!(matches!(short, Err(ActError::MalformedSignature(32))));

    // An all-zero signature of the right length is well-formed but invalid.
    let zeroed = envelope_from_parts(claims_bytes, &[0u8; 64], None).expect("envelope assembles");
    assert!(matches!(
        verify(&zeroed, &verifier()),
        Err(ActError::SignatureInvalid { .. })
    ));
}

#[test]
fn rejects_non_cbor_and_empty_input() {
    for input in [b"not-cbor".as_slice(), b"".as_slice()] {
        let error = verify(input, &verifier()).expect_err("must be rejected");
        assert!(
            matches!(error, ActError::EnvelopeDecode(_)),
            "got {error} for {input:?}"
        );
    }
}

#[test]
fn a_verifier_without_trusted_keys_is_refused_at_construction() {
    // Failing here rather than at first use turns a silent
    // reject-everything deployment into a startup error.
    assert!(matches!(
        Verifier::new(vec![], ISSUER, AUDIENCE),
        Err(ActError::NoTrustedKeys)
    ));
}

#[test]
fn detached_signing_matches_in_process_signing() {
    // The HSM path and the in-process path must produce identical bytes,
    // otherwise a deployment that moves its key into an HSM silently changes
    // its wire output.
    use ed25519_dalek::Signer;

    let claims = claims();
    let claims_bytes = claims_to_signing_payload(&claims).expect("claims encode");
    let signature = issuer_key().sign(&claims_bytes);
    let detached = envelope_from_parts(
        claims_bytes,
        &signature.to_bytes(),
        Some("test-1".to_string()),
    )
    .expect("envelope assembles");

    assert_eq!(detached, mint(&claims));
    assert!(verify(&detached, &verifier()).is_ok());
}

#[test]
fn refuses_to_sign_a_structurally_invalid_claim_set() {
    // Catching this at mint time avoids shipping a token that every verifier
    // will reject.
    let mut invalid = claims();
    invalid.nbf = invalid.exp;
    assert!(matches!(
        sign(&invalid, &issuer_key(), None),
        Err(ActError::EmptyValidityWindow { .. })
    ));
}
