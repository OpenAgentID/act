//! Error types for ACT encoding, decoding and verification.

/// Failures encountered while decoding or verifying an ACT.
///
/// Variants are deliberately specific so callers can distinguish an expired
/// token from a forged one in logs and metrics. A verifier that collapses these
/// into a single "invalid token" outcome loses the ability to alarm on forgery
/// while staying quiet about ordinary expiry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActError {
    /// The encoded token exceeded [`crate::MAX_ACT_BYTES`].
    ///
    /// Checked before any parsing, so a hostile payload cannot force
    /// unbounded allocation.
    #[error("token is {actual} bytes, exceeding the {limit}-byte maximum")]
    TooLarge {
        /// Size of the rejected input.
        actual: usize,
        /// The configured ceiling.
        limit: usize,
    },

    /// The outer envelope was not well-formed CBOR, or did not match the
    /// envelope schema.
    #[error("envelope decode failed: {0}")]
    EnvelopeDecode(String),

    /// The claims payload inside the envelope was not well-formed CBOR, or did
    /// not match the claims schema.
    #[error("claims decode failed: {0}")]
    ClaimsDecode(String),

    /// The envelope declared a format version this build does not implement.
    ///
    /// Carried explicitly so a rollout can distinguish "forged" from "newer
    /// than me", which are operationally opposite situations.
    #[error("unsupported ACT format version {found}, this build supports {supported}")]
    UnsupportedVersion {
        /// Version declared by the envelope.
        found: u64,
        /// Version this build implements.
        supported: u64,
    },

    /// The envelope declared a signature algorithm this build does not
    /// implement.
    #[error("unsupported signature algorithm {0:?}, this build implements Ed25519")]
    UnsupportedAlgorithm(String),

    /// The signature field was absent.
    #[error("envelope carries no signature")]
    MissingSignature,

    /// The signature was present but not 64 bytes.
    #[error("signature is {0} bytes, expected exactly 64")]
    MalformedSignature(usize),

    /// A configured trusted key was not a valid Ed25519 public key.
    ///
    /// Distinguished from a verification failure because it is a
    /// misconfiguration on the verifier's side, not a problem with the token.
    #[error("trusted key at index {index} is not a valid Ed25519 key: {reason}")]
    MalformedTrustedKey {
        /// Position in the supplied key set.
        index: usize,
        /// Underlying reason.
        reason: String,
    },

    /// No trusted keys were supplied, so no token could ever verify.
    #[error("at least one trusted issuer key is required")]
    NoTrustedKeys,

    /// The signature did not validate against any trusted key.
    #[error("signature did not validate against any of {tried} trusted keys")]
    SignatureInvalid {
        /// Number of keys attempted.
        tried: usize,
    },

    /// `exp` is at or before the current time.
    #[error("token expired at {expired_at} (now {now})")]
    Expired {
        /// The `exp` claim.
        expired_at: i64,
        /// Time used for the comparison.
        now: i64,
    },

    /// `nbf` is after the current time.
    #[error("token not valid until {valid_from} (now {now})")]
    NotYetValid {
        /// The `nbf` claim.
        valid_from: i64,
        /// Time used for the comparison.
        now: i64,
    },

    /// `iss` did not match the expected issuer.
    #[error("issuer mismatch: expected {expected:?}, found {found:?}")]
    IssuerMismatch {
        /// Issuer the verifier requires.
        expected: String,
        /// Issuer the token carries.
        found: String,
    },

    /// `aud` did not include the expected audience.
    #[error("audience mismatch: expected {expected:?}, found {found:?}")]
    AudienceMismatch {
        /// Audience the verifier requires.
        expected: String,
        /// Audiences the token carries.
        found: Vec<String>,
    },

    /// A required scope was absent from `scope`.
    #[error("missing required scope {0:?}")]
    MissingScope(String),

    /// A scope did not match the `service:resource:action` grammar.
    #[error("scope {value:?} is malformed: {reason}")]
    MalformedScope {
        /// The offending scope string.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// A structurally required claim was empty.
    #[error("claim {0} must not be empty")]
    EmptyClaim(&'static str),

    /// `exp` was not after `nbf`, so the token has no valid window.
    #[error("token validity window is empty: nbf {nbf} is not before exp {exp}")]
    EmptyValidityWindow {
        /// The `nbf` claim.
        nbf: i64,
        /// The `exp` claim.
        exp: i64,
    },

    /// Serializing claims or an envelope failed.
    #[error("encode failed: {0}")]
    Encode(String),
}

/// Result alias for ACT operations.
pub type ActResult<T> = Result<T, ActError>;
