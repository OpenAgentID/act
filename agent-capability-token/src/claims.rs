//! The ACT claim set.
//!
//! Claims divide into two groups, and the split is deliberate.
//!
//! Claims a *verifier* must enforce are typed: the temporal window, issuer and
//! audience, the scope grant, the proof-of-possession binding required by ANVIL
//! section 5.2, and the delegation constraints that make child capabilities a
//! strict subset of their parent's.
//!
//! Claims only the *issuer* interprets - rate limits, spend budgets, device and
//! network bindings, audit trace - are carried in [`ActClaims::ext`] as opaque
//! CBOR. They travel inside the signature, so they cannot be stripped or
//! altered in transit, but this crate does not restate their schema. That
//! restatement is what produced the divergence this format replaces: three
//! copies of the claim structure, each drifting from the issuer.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{ActError, ActResult};
use crate::scope::Scope;

/// Proof-of-possession binding.
///
/// ANVIL section 5.2 requires that an ACT be bound to the agent's OAS DID by
/// proof-of-possession. A verifier that ignores this claim cannot tell a
/// legitimate holder from someone replaying a captured token, which is why it
/// is typed here rather than left to the extension map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confirmation {
    /// Fingerprint of the key the holder must demonstrate control of.
    pub key_fingerprint: String,
    /// Algorithm the fingerprint and possession proof use, for example
    /// `"Ed25519"`.
    pub alg: String,
}

/// Constraints governing whether and how this token may be delegated onward.
///
/// ANVIL section 5.2 requires that an agent not delegate capabilities it does
/// not hold, and that child capabilities be a strict subset of the parent's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Whether onward delegation is permitted at all.
    pub allow_delegation: bool,
    /// Remaining delegation depth. Zero forbids further delegation.
    pub max_depth: u8,
    /// Subset of scopes that may be delegated. `None` means the holder's full
    /// scope set is delegatable, subject to `allow_delegation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegatable_scopes: Option<Vec<Scope>>,
    /// Whether any recipient may receive a delegation.
    pub allow_any_delegate: bool,
    /// DIDs permitted to receive a delegation when `allow_any_delegate` is
    /// false.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_delegates: Vec<String>,
    /// Minimum reduction in lifetime, in seconds, that a delegated token must
    /// apply relative to this one.
    #[serde(default)]
    pub min_ttl_reduction_seconds: i64,
}

/// The claim set carried inside an ACT envelope.
///
/// Field names are the wire keys. Unknown top-level keys are ignored on decode
/// so that a newer issuer can add typed claims without breaking existing
/// verifiers; issuer-specific claims belong in [`ActClaims::ext`] instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActClaims {
    /// Token identifier, unique per issuance. Text, not bytes - a UUID here is
    /// carried in its canonical hyphenated form.
    pub jti: String,

    /// Subject: the OAS DID of the agent this token was issued to.
    pub sub: String,

    /// Issuer: the broker instance that minted this token.
    pub iss: String,

    /// Audiences this token is valid for.
    ///
    /// Decodes from either a single string or an array of strings, since a
    /// single-audience token is the common case and writing it as a bare string
    /// is the conventional CBOR/JWT shorthand.
    #[serde(deserialize_with = "audience_from_string_or_array")]
    pub aud: Vec<String>,

    /// Issued-at time, in seconds since the Unix epoch.
    pub iat: i64,

    /// Not-before time, in seconds since the Unix epoch.
    #[serde(default)]
    pub nbf: i64,

    /// Expiry time, in seconds since the Unix epoch.
    pub exp: i64,

    /// Tenant this token is scoped to.
    pub tenant_id: String,

    /// Granted capability scopes, as a flat array.
    pub scope: Vec<Scope>,

    /// Proof-of-possession binding. See [`Confirmation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Confirmation>,

    /// Onward delegation constraints. See [`Delegation`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,

    /// Issuer-defined claims, carried inside the signature and passed through
    /// unaltered.
    ///
    /// This is where rate limits, budgets, device and network bindings, and
    /// audit trace belong. A verifier that does not understand a key here must
    /// preserve it rather than drop it, so that a downstream component which
    /// does understand it still receives an intact, signed value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ext: BTreeMap<String, ciborium::Value>,
}

/// Accepts `aud` as either a single string or an array of strings.
fn audience_from_string_or_array<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(single) => Ok(vec![single]),
        OneOrMany::Many(many) => Ok(many),
    }
}

impl ActClaims {
    /// Checks the claim set is structurally sound, independent of signature or
    /// clock.
    ///
    /// Called during verification before any policy check. Kept public so an
    /// issuer can reject a malformed claim set at mint time rather than
    /// discovering it at the verifier.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::EmptyClaim`] for a required claim that is blank, and
    /// [`ActError::EmptyValidityWindow`] if `nbf` is not before `exp`.
    pub fn validate_structure(&self) -> ActResult<()> {
        for (name, value) in [
            ("jti", &self.jti),
            ("sub", &self.sub),
            ("iss", &self.iss),
            ("tenant_id", &self.tenant_id),
        ] {
            if value.trim().is_empty() {
                return Err(ActError::EmptyClaim(name));
            }
        }

        if self.aud.is_empty() || self.aud.iter().any(|a| a.trim().is_empty()) {
            return Err(ActError::EmptyClaim("aud"));
        }

        if self.nbf >= self.exp {
            return Err(ActError::EmptyValidityWindow {
                nbf: self.nbf,
                exp: self.exp,
            });
        }

        Ok(())
    }

    /// Whether the granted scopes authorize `requested`.
    ///
    /// Wildcards in the grant expand; wildcards in the request do not. See
    /// [`Scope::covers`].
    #[must_use]
    pub fn authorizes(&self, requested: &Scope) -> bool {
        self.scope.iter().any(|granted| granted.covers(requested))
    }

    /// Whether this token lists `audience` among its audiences.
    #[must_use]
    pub fn has_audience(&self, audience: &str) -> bool {
        self.aud.iter().any(|a| a == audience)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> ActClaims {
        ActClaims {
            jti: "018f4c1e-0000-7000-8000-000000000000".to_string(),
            sub: "did:oas:l1fe:agent:alpha".to_string(),
            iss: "arsenal:broker:test-1".to_string(),
            aud: vec!["omerta".to_string()],
            iat: 1_000,
            nbf: 1_000,
            exp: 2_000,
            tenant_id: "acme".to_string(),
            scope: vec![],
            cnf: None,
            delegation: None,
            ext: BTreeMap::new(),
        }
    }

    #[test]
    fn rejects_blank_required_claims() {
        for mutate in [
            (|c: &mut ActClaims| c.jti.clear()) as fn(&mut ActClaims),
            |c: &mut ActClaims| c.sub.clear(),
            |c: &mut ActClaims| c.iss.clear(),
            |c: &mut ActClaims| c.tenant_id.clear(),
            |c: &mut ActClaims| c.aud.clear(),
        ] {
            let mut subject = claims();
            mutate(&mut subject);
            assert!(subject.validate_structure().is_err());
        }
    }

    #[test]
    fn rejects_whitespace_only_claims() {
        // A blank check that only tests `is_empty` lets " " through, which then
        // compares unequal to every real issuer.
        let mut subject = claims();
        subject.iss = "   ".to_string();
        assert!(matches!(
            subject.validate_structure(),
            Err(ActError::EmptyClaim("iss"))
        ));
    }

    #[test]
    fn rejects_empty_validity_window() {
        let mut subject = claims();
        subject.nbf = subject.exp;
        assert!(matches!(
            subject.validate_structure(),
            Err(ActError::EmptyValidityWindow { .. })
        ));
    }

    #[test]
    fn accepts_audience_as_bare_string_or_array() -> ActResult<()> {
        #[derive(Serialize)]
        struct BareAud {
            aud: &'static str,
        }
        #[derive(Deserialize)]
        struct Probe {
            #[serde(deserialize_with = "audience_from_string_or_array")]
            aud: Vec<String>,
        }

        let mut buf = Vec::new();
        ciborium::into_writer(&BareAud { aud: "omerta" }, &mut buf)
            .map_err(|e| ActError::Encode(e.to_string()))?;
        let probe: Probe = ciborium::from_reader(buf.as_slice())
            .map_err(|e| ActError::ClaimsDecode(e.to_string()))?;
        assert_eq!(probe.aud, vec!["omerta".to_string()]);

        let mut buf = Vec::new();
        ciborium::into_writer(&BareAud { aud: "omerta" }, &mut buf)
            .map_err(|e| ActError::Encode(e.to_string()))?;
        assert!(!buf.is_empty());
        Ok(())
    }

    #[test]
    fn timestamps_encode_as_integers() -> ActResult<()> {
        // The mismatch that made the superseded formats mutually unreadable.
        #[derive(Deserialize)]
        struct Probe {
            iat: ciborium::Value,
            exp: ciborium::Value,
        }

        let mut buf = Vec::new();
        ciborium::into_writer(&claims(), &mut buf).map_err(|e| ActError::Encode(e.to_string()))?;
        let probe: Probe = ciborium::from_reader(buf.as_slice())
            .map_err(|e| ActError::ClaimsDecode(e.to_string()))?;

        assert!(probe.iat.is_integer(), "iat must be an integer");
        assert!(probe.exp.is_integer(), "exp must be an integer");
        Ok(())
    }

    #[test]
    fn identifiers_encode_as_text() -> ActResult<()> {
        #[derive(Deserialize)]
        struct Probe {
            jti: ciborium::Value,
            sub: ciborium::Value,
        }

        let mut buf = Vec::new();
        ciborium::into_writer(&claims(), &mut buf).map_err(|e| ActError::Encode(e.to_string()))?;
        let probe: Probe = ciborium::from_reader(buf.as_slice())
            .map_err(|e| ActError::ClaimsDecode(e.to_string()))?;

        assert!(probe.jti.is_text(), "jti must be text, not UUID bytes");
        assert!(probe.sub.is_text(), "sub must be text");
        Ok(())
    }

    #[test]
    fn unknown_top_level_keys_are_ignored() -> ActResult<()> {
        // Forward compatibility: a newer issuer adding a typed claim must not
        // break an older verifier.
        let mut map = vec![
            (
                ciborium::Value::Text("jti".into()),
                ciborium::Value::Text("id".into()),
            ),
            (
                ciborium::Value::Text("sub".into()),
                ciborium::Value::Text("did:oas:l1fe:agent:alpha".into()),
            ),
            (
                ciborium::Value::Text("iss".into()),
                ciborium::Value::Text("issuer".into()),
            ),
            (
                ciborium::Value::Text("aud".into()),
                ciborium::Value::Text("omerta".into()),
            ),
            (
                ciborium::Value::Text("iat".into()),
                ciborium::Value::from(1),
            ),
            (
                ciborium::Value::Text("nbf".into()),
                ciborium::Value::from(1),
            ),
            (
                ciborium::Value::Text("exp".into()),
                ciborium::Value::from(2),
            ),
            (
                ciborium::Value::Text("tenant_id".into()),
                ciborium::Value::Text("acme".into()),
            ),
            (
                ciborium::Value::Text("scope".into()),
                ciborium::Value::Array(vec![]),
            ),
        ];
        map.push((
            ciborium::Value::Text("claim_from_the_future".into()),
            ciborium::Value::from(42),
        ));

        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Map(map), &mut buf)
            .map_err(|e| ActError::Encode(e.to_string()))?;

        let decoded: ActClaims = ciborium::from_reader(buf.as_slice())
            .map_err(|e| ActError::ClaimsDecode(e.to_string()))?;
        assert_eq!(decoded.tenant_id, "acme");
        Ok(())
    }
}
