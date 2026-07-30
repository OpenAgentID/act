//! Canonical wire format for the Agent Capability Token (ACT).
//!
//! ANVIL section 5 requires every compliant agent to operate under a scoped
//! ACT, but no document defined the token's byte encoding. Three
//! implementations filled that gap independently and disagreed: an issuer whose
//! tokens no verifier could read, and two verifiers that agreed with each other
//! and with nothing that was actually minted. Each declared in its own
//! documentation that it matched the others.
//!
//! This crate is the single normative definition. It is vendor-neutral and
//! depends on no product crate, so an issuer and a verifier can share one
//! format without either depending on the other's implementation.
//!
//! # Format
//!
//! See [`wire`] for the envelope, and [`SPECIFICATION.md`] for the normative
//! description.
//!
//! [`SPECIFICATION.md`]: https://github.com/OpenAgentID/act/blob/main/SPECIFICATION.md
//!
//! Encoding choices follow CWT (RFC 8392) conventions where they apply -
//! integer epoch seconds for the temporal claims, a flat array for scopes, text
//! for identifiers. This is **not** an RFC 8392 implementation: claim keys are
//! text rather than the registered integer keys, and signing is raw Ed25519
//! over the claims byte string rather than COSE_Sign1. Callers needing wire
//! compatibility with a CWT library will not find it here.
//!
//! # Verifying
//!
//! ```
//! use agent_capability_token::{verify, ActError, Verifier};
//!
//! # fn main() -> Result<(), ActError> {
//! let verifier = Verifier::new(
//!     vec![[0u8; 32]], // in production, loaded from the issuer's key endpoint
//!     "arsenal:broker:prod-1",
//!     "omerta",
//! )?
//! .requiring_scopes(["tools:calendar:invoke".parse()?])
//! .with_leeway_seconds(30);
//!
//! let token: &[u8] = &[]; // received from the gateway
//! match verify(token, &verifier) {
//!     Ok(claims) => println!("authorized {}", claims.sub),
//!     Err(ActError::Expired { .. }) => println!("token expired"),
//!     Err(other) => println!("rejected: {other}"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # What this crate does not do
//!
//! It carries claims and checks a token's integrity, temporal window, issuer,
//! audience and scope grant. It does not evaluate issuer policy. Rate limits,
//! spend budgets, device and network bindings and audit trace travel in
//! [`ActClaims::ext`] as opaque signed CBOR, and the components that own their
//! meaning interpret them. Restating those schemas here is exactly what caused
//! the divergence this format replaces.

#![forbid(unsafe_code)]

pub mod claims;
pub mod error;
pub mod scope;
pub mod wire;

pub use claims::{ActClaims, Confirmation, Delegation};
pub use error::{ActError, ActResult};
pub use scope::{Scope, SCOPE_SEGMENTS, WILDCARD};
pub use wire::{
    claims_to_signing_payload, envelope_from_parts, verify, ActEnvelope, PublicKeyBytes, Verifier,
    ALGORITHM_ED25519, FORMAT_VERSION, MAX_ACT_BYTES,
};

#[cfg(feature = "sign")]
pub use wire::sign;
