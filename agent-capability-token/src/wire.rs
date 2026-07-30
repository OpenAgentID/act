//! The ACT envelope: encoding, signing and verification.
//!
//! An ACT is a CBOR map with four keys:
//!
//! ```text
//! {
//!   "v":      uint,   ; format version, currently 1
//!   "alg":    tstr,   ; signature algorithm, currently "Ed25519"
//!   "claims": bstr,   ; CBOR-encoded ActClaims - the signed bytes
//!   "sig":    bstr,   ; 64-byte raw Ed25519 signature over "claims"
//!   "kid":    tstr,   ; optional key identifier, for rotation
//! }
//! ```
//!
//! The signature covers the `claims` byte string exactly as it appears, not a
//! re-serialization of the decoded claims. A verifier therefore never needs to
//! reproduce the issuer's encoding decisions byte for byte, which is the usual
//! source of signature failures in formats that sign a canonicalized structure.
//!
//! `v` and `alg` exist because neither superseded format carried either. Without
//! a version there is no way to roll a format change out, and without an
//! algorithm identifier there is no way to migrate off Ed25519.

// The dalek `Verifier` trait is imported anonymously: only its `verify` method
// is needed, and the name is taken by this module's own `Verifier` type.
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::claims::ActClaims;
use crate::error::{ActError, ActResult};
use crate::scope::Scope;

/// Current ACT format version.
pub const FORMAT_VERSION: u64 = 1;

/// The only signature algorithm this version defines.
pub const ALGORITHM_ED25519: &str = "Ed25519";

/// Maximum accepted size of an encoded ACT, in bytes.
///
/// Enforced before parsing so an oversized payload cannot drive allocation.
pub const MAX_ACT_BYTES: usize = 16 * 1024;

/// Length of a raw Ed25519 signature.
const SIGNATURE_BYTES: usize = 64;

/// A raw Ed25519 public key.
///
/// Kept as a plain array so this crate does not impose a key-handle type on
/// callers, who typically hold a rotating set loaded from their issuer's key
/// endpoint.
pub type PublicKeyBytes = [u8; 32];

/// The outer envelope, as it appears on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActEnvelope {
    /// Format version.
    pub v: u64,
    /// Signature algorithm identifier.
    pub alg: String,
    /// CBOR-encoded claims. These exact bytes are what the signature covers.
    pub claims: serde_bytes::ByteBuf,
    /// Raw signature over `claims`.
    pub sig: serde_bytes::ByteBuf,
    /// Optional key identifier, so a verifier can select a key during rotation
    /// instead of trying every trusted key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl ActEnvelope {
    /// Decodes an envelope without verifying its signature.
    ///
    /// Useful for reading `kid` in order to select a verification key. The
    /// claims inside are unauthenticated until [`verify`] succeeds, and must not
    /// be used for any authorization decision.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::TooLarge`] above [`MAX_ACT_BYTES`],
    /// [`ActError::EnvelopeDecode`] for malformed CBOR,
    /// [`ActError::UnsupportedVersion`] or [`ActError::UnsupportedAlgorithm`]
    /// for a format this build does not implement.
    pub fn decode(bytes: &[u8]) -> ActResult<Self> {
        if bytes.len() > MAX_ACT_BYTES {
            return Err(ActError::TooLarge {
                actual: bytes.len(),
                limit: MAX_ACT_BYTES,
            });
        }

        let envelope: Self =
            ciborium::from_reader(bytes).map_err(|e| ActError::EnvelopeDecode(e.to_string()))?;

        if envelope.v != FORMAT_VERSION {
            return Err(ActError::UnsupportedVersion {
                found: envelope.v,
                supported: FORMAT_VERSION,
            });
        }
        if envelope.alg != ALGORITHM_ED25519 {
            return Err(ActError::UnsupportedAlgorithm(envelope.alg));
        }

        Ok(envelope)
    }

    /// Serializes this envelope to CBOR.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::Encode`] if serialization fails.
    pub fn encode(&self) -> ActResult<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).map_err(|e| ActError::Encode(e.to_string()))?;
        Ok(buffer)
    }
}

/// What a verifier requires of a token.
#[derive(Debug, Clone)]
pub struct Verifier {
    trusted_keys: Vec<PublicKeyBytes>,
    expected_issuer: String,
    expected_audience: String,
    required_scopes: Vec<Scope>,
    clock: Option<i64>,
    leeway_seconds: i64,
}

impl Verifier {
    /// Builds a verifier.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::NoTrustedKeys`] if `trusted_keys` is empty, since no
    /// token could then ever verify and the misconfiguration should surface at
    /// construction rather than as a stream of signature failures.
    pub fn new(
        trusted_keys: Vec<PublicKeyBytes>,
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
    ) -> ActResult<Self> {
        if trusted_keys.is_empty() {
            return Err(ActError::NoTrustedKeys);
        }
        Ok(Self {
            trusted_keys,
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            required_scopes: Vec::new(),
            clock: None,
            leeway_seconds: 0,
        })
    }

    /// Requires that the token grant every scope in `scopes`.
    #[must_use]
    pub fn requiring_scopes(mut self, scopes: impl IntoIterator<Item = Scope>) -> Self {
        self.required_scopes.extend(scopes);
        self
    }

    /// Allows `seconds` of clock skew on the `nbf` and `exp` checks.
    ///
    /// Applied symmetrically. Callers running across hosts without tightly
    /// synchronized clocks need a small allowance here; leaving it at zero makes
    /// a token minted moments ago fail at a verifier whose clock trails the
    /// issuer's.
    #[must_use]
    pub fn with_leeway_seconds(mut self, seconds: i64) -> Self {
        self.leeway_seconds = seconds.abs();
        self
    }

    /// Pins the time used for temporal checks, in seconds since the Unix epoch.
    ///
    /// Intended for tests and for replaying a decision at a known instant.
    #[must_use]
    pub fn with_clock(mut self, now_unix_seconds: i64) -> Self {
        self.clock = Some(now_unix_seconds);
        self
    }

    /// The time this verifier will compare against.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::Encode`] if no clock was pinned and the system clock
    /// is before the Unix epoch.
    fn now(&self) -> ActResult<i64> {
        match self.clock {
            Some(pinned) => Ok(pinned),
            // Read from the system clock without taking a chrono dependency, so
            // that a sidecar embedding this crate stays dependency-light.
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| {
                    let secs = d.as_secs();
                    i64::try_from(secs).unwrap_or(i64::MAX)
                })
                .map_err(|_| ActError::Encode("system clock is before the Unix epoch".to_string())),
        }
    }
}

/// Verifies an encoded ACT and returns its claims.
///
/// The order matters. Signature verification precedes every claim check, so a
/// forged token is rejected before any of its unauthenticated content is used to
/// make a decision or shape a log line.
///
/// 1. Enforce the size ceiling and decode the envelope.
/// 2. Verify the Ed25519 signature over the raw `claims` bytes.
/// 3. Decode the claims and check they are structurally sound.
/// 4. Check the temporal window, issuer, audience, and required scopes.
///
/// # Errors
///
/// Returns the [`ActError`] variant describing the first failed step.
///
/// # Examples
///
/// ```
/// use agent_capability_token::{verify, ActError, Verifier};
///
/// let verifier = Verifier::new(vec![[0u8; 32]], "arsenal:broker:prod-1", "omerta")?;
/// // An empty payload is not a valid envelope.
/// assert!(matches!(verify(&[], &verifier), Err(ActError::EnvelopeDecode(_))));
/// # Ok::<(), ActError>(())
/// ```
pub fn verify(token_bytes: &[u8], verifier: &Verifier) -> ActResult<ActClaims> {
    let envelope = ActEnvelope::decode(token_bytes)?;

    if envelope.sig.is_empty() {
        return Err(ActError::MissingSignature);
    }
    if envelope.sig.len() != SIGNATURE_BYTES {
        return Err(ActError::MalformedSignature(envelope.sig.len()));
    }
    let signature_array: [u8; SIGNATURE_BYTES] =
        <[u8; SIGNATURE_BYTES]>::try_from(envelope.sig.as_ref())
            .map_err(|_| ActError::MalformedSignature(envelope.sig.len()))?;
    let signature = Signature::from_bytes(&signature_array);

    let candidate_keys = decode_trusted_keys(verifier)?;
    let verified = candidate_keys
        .iter()
        .any(|key| key.verify(envelope.claims.as_ref(), &signature).is_ok());
    if !verified {
        return Err(ActError::SignatureInvalid {
            tried: candidate_keys.len(),
        });
    }

    let claims_bytes: &[u8] = envelope.claims.as_ref();
    let claims: ActClaims =
        ciborium::from_reader(claims_bytes).map_err(|e| ActError::ClaimsDecode(e.to_string()))?;
    claims.validate_structure()?;

    check_policy(&claims, verifier)?;

    Ok(claims)
}

/// Decodes every trusted key up front.
///
/// A misconfigured key surfaces as [`ActError::MalformedTrustedKey`] before any
/// verification is attempted, so it is not mistaken for a bad signature.
///
/// Verification tries each key in turn. The envelope's `kid` is carried for the
/// issuer's benefit and for audit, and is deliberately not used to choose a key
/// here: the trusted set is supplied as bare key bytes with no identifiers to
/// match against, and treating a sender-supplied hint as authoritative would let
/// that sender steer a verifier away from the key that would have validated. A
/// keyed trusted set is the natural extension when rotation makes the linear
/// scan costly.
fn decode_trusted_keys(verifier: &Verifier) -> ActResult<Vec<VerifyingKey>> {
    verifier
        .trusted_keys
        .iter()
        .enumerate()
        .map(|(index, raw)| {
            VerifyingKey::from_bytes(raw).map_err(|e| ActError::MalformedTrustedKey {
                index,
                reason: e.to_string(),
            })
        })
        .collect()
}

/// Applies the temporal, issuer, audience and scope checks.
fn check_policy(claims: &ActClaims, verifier: &Verifier) -> ActResult<()> {
    let now = verifier.now()?;

    if claims.exp <= now.saturating_sub(verifier.leeway_seconds) {
        return Err(ActError::Expired {
            expired_at: claims.exp,
            now,
        });
    }
    if claims.nbf > now.saturating_add(verifier.leeway_seconds) {
        return Err(ActError::NotYetValid {
            valid_from: claims.nbf,
            now,
        });
    }

    if claims.iss != verifier.expected_issuer {
        return Err(ActError::IssuerMismatch {
            expected: verifier.expected_issuer.clone(),
            found: claims.iss.clone(),
        });
    }

    if !claims.has_audience(&verifier.expected_audience) {
        return Err(ActError::AudienceMismatch {
            expected: verifier.expected_audience.clone(),
            found: claims.aud.clone(),
        });
    }

    for required in &verifier.required_scopes {
        if !claims.authorizes(required) {
            return Err(ActError::MissingScope(required.to_string()));
        }
    }

    Ok(())
}

/// Encodes claims into the exact byte string the signature must cover.
///
/// Exposed so an issuer holding its key in an HSM, or any other signer that
/// cannot hand over private key material, can produce the payload here and sign
/// it elsewhere.
///
/// # Errors
///
/// Returns [`ActError::Encode`] if serialization fails.
pub fn claims_to_signing_payload(claims: &ActClaims) -> ActResult<Vec<u8>> {
    claims.validate_structure()?;
    let mut buffer = Vec::new();
    ciborium::into_writer(claims, &mut buffer).map_err(|e| ActError::Encode(e.to_string()))?;
    Ok(buffer)
}

/// Assembles an envelope from claims bytes and a detached signature.
///
/// Pairs with [`claims_to_signing_payload`] for signers that hold their key
/// outside the process.
///
/// # Errors
///
/// Returns [`ActError::MalformedSignature`] unless `signature` is 64 bytes, and
/// [`ActError::TooLarge`] if the assembled token exceeds [`MAX_ACT_BYTES`].
pub fn envelope_from_parts(
    claims_bytes: Vec<u8>,
    signature: &[u8],
    kid: Option<String>,
) -> ActResult<Vec<u8>> {
    if signature.len() != SIGNATURE_BYTES {
        return Err(ActError::MalformedSignature(signature.len()));
    }

    let envelope = ActEnvelope {
        v: FORMAT_VERSION,
        alg: ALGORITHM_ED25519.to_string(),
        claims: serde_bytes::ByteBuf::from(claims_bytes),
        sig: serde_bytes::ByteBuf::from(signature.to_vec()),
        kid,
    };

    let encoded = envelope.encode()?;
    if encoded.len() > MAX_ACT_BYTES {
        return Err(ActError::TooLarge {
            actual: encoded.len(),
            limit: MAX_ACT_BYTES,
        });
    }
    Ok(encoded)
}

/// Signs claims with an in-process key and returns an encoded ACT.
///
/// Behind the `sign` feature: a verifier has no reason to link signing code, and
/// most deployments verify in far more places than they mint.
///
/// # Errors
///
/// Returns [`ActError::Encode`] if serialization fails, or [`ActError::TooLarge`]
/// if the assembled token exceeds [`MAX_ACT_BYTES`].
#[cfg(feature = "sign")]
pub fn sign(
    claims: &ActClaims,
    signing_key: &ed25519_dalek::SigningKey,
    kid: Option<String>,
) -> ActResult<Vec<u8>> {
    use ed25519_dalek::Signer;

    let claims_bytes = claims_to_signing_payload(claims)?;
    let signature = signing_key.sign(&claims_bytes);
    envelope_from_parts(claims_bytes, &signature.to_bytes(), kid)
}
