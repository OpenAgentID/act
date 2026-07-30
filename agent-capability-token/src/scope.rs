//! Capability scopes.
//!
//! ANVIL section 5.3 binds tool tiers to scope patterns of the form
//! `service:resource:action` - `tools:<tool-id>:invoke` for external tools and
//! `runtime:platform:*` for runtime-granted platform capabilities. This module
//! makes that grammar a parse step rather than a convention, so a malformed
//! scope is rejected at the boundary instead of silently failing to match.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{ActError, ActResult};

/// The wildcard segment, which matches any value in its position.
pub const WILDCARD: &str = "*";

/// Number of colon-separated segments in a well-formed scope.
pub const SCOPE_SEGMENTS: usize = 3;

/// A validated capability scope in `service:resource:action` form.
///
/// Serializes as a plain string, so the wire representation is a flat array of
/// strings rather than a nested structure.
///
/// # Examples
///
/// ```
/// use agent_capability_token::Scope;
///
/// let scope: Scope = "tools:calendar:invoke".parse()?;
/// assert_eq!(scope.service(), "tools");
/// assert_eq!(scope.action(), "invoke");
///
/// // A granted wildcard covers a specific request.
/// let granted: Scope = "runtime:platform:*".parse()?;
/// let requested: Scope = "runtime:platform:spawn".parse()?;
/// assert!(granted.covers(&requested));
/// # Ok::<(), agent_capability_token::ActError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope {
    raw: String,
    // Byte offsets of the two separators, so segment access does not re-scan.
    first_colon: usize,
    second_colon: usize,
}

impl Scope {
    /// Parses and validates a scope string.
    ///
    /// # Errors
    ///
    /// Returns [`ActError::MalformedScope`] unless the input has exactly three
    /// non-empty colon-separated segments.
    pub fn parse(value: impl Into<String>) -> ActResult<Self> {
        let raw = value.into();

        let mut colons = raw.match_indices(':').map(|(i, _)| i);
        let (Some(first_colon), Some(second_colon)) = (colons.next(), colons.next()) else {
            return Err(ActError::MalformedScope {
                value: raw,
                reason: "expected three segments in service:resource:action form",
            });
        };
        if colons.next().is_some() {
            return Err(ActError::MalformedScope {
                value: raw,
                reason: "expected exactly three segments, found more",
            });
        }

        let candidate = Self {
            first_colon,
            second_colon,
            raw,
        };
        if candidate.service().is_empty()
            || candidate.resource().is_empty()
            || candidate.action().is_empty()
        {
            return Err(ActError::MalformedScope {
                value: candidate.raw,
                reason: "no segment may be empty",
            });
        }

        Ok(candidate)
    }

    /// The service segment.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.raw[..self.first_colon]
    }

    /// The resource segment.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.raw[self.first_colon + 1..self.second_colon]
    }

    /// The action segment.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.raw[self.second_colon + 1..]
    }

    /// The scope as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Whether this scope, treated as a grant, authorizes `requested`.
    ///
    /// A [`WILDCARD`] segment in the grant matches any value in the same
    /// position. The comparison is directional: a wildcard in `requested` is
    /// matched literally, so a caller cannot widen its own authority by asking
    /// for `*`.
    #[must_use]
    pub fn covers(&self, requested: &Self) -> bool {
        fn segment_covers(granted: &str, requested: &str) -> bool {
            granted == WILDCARD || granted == requested
        }

        segment_covers(self.service(), requested.service())
            && segment_covers(self.resource(), requested.resource())
            && segment_covers(self.action(), requested.action())
    }
}

impl std::str::FromStr for Scope {
    type Err = ActError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Serialize for Scope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_segments() -> ActResult<()> {
        let scope = Scope::parse("tools:calendar:invoke")?;
        assert_eq!(scope.service(), "tools");
        assert_eq!(scope.resource(), "calendar");
        assert_eq!(scope.action(), "invoke");
        assert_eq!(scope.as_str(), "tools:calendar:invoke");
        Ok(())
    }

    #[test]
    fn rejects_two_segment_scopes() {
        // The form both superseded verifiers documented.
        let error = Scope::parse("tools:invoke").expect_err("two segments must be rejected");
        assert!(matches!(error, ActError::MalformedScope { .. }));
    }

    #[test]
    fn rejects_four_segments_and_empty_segments() {
        assert!(Scope::parse("a:b:c:d").is_err());
        assert!(Scope::parse("a::c").is_err());
        assert!(Scope::parse(":b:c").is_err());
        assert!(Scope::parse("a:b:").is_err());
    }

    #[test]
    fn wildcard_grant_covers_specific_request() -> ActResult<()> {
        let granted = Scope::parse("runtime:platform:*")?;
        assert!(granted.covers(&Scope::parse("runtime:platform:spawn")?));
        assert!(!granted.covers(&Scope::parse("runtime:network:spawn")?));
        Ok(())
    }

    #[test]
    fn requested_wildcard_does_not_widen_authority() -> ActResult<()> {
        // A specific grant must not be satisfied by a wildcard request,
        // otherwise any holder could escalate by asking for "*".
        let granted = Scope::parse("tools:calendar:invoke")?;
        assert!(!granted.covers(&Scope::parse("tools:calendar:*")?));
        assert!(!granted.covers(&Scope::parse("tools:*:invoke")?));
        Ok(())
    }

    #[test]
    fn serializes_as_a_plain_string() -> ActResult<()> {
        let scope = Scope::parse("tools:calendar:invoke")?;
        let mut buf = Vec::new();
        ciborium::into_writer(&scope, &mut buf).map_err(|e| ActError::Encode(e.to_string()))?;

        let value: ciborium::Value = ciborium::from_reader(buf.as_slice())
            .map_err(|e| ActError::ClaimsDecode(e.to_string()))?;
        assert!(value.is_text(), "scope must encode as text, got {value:?}");
        Ok(())
    }
}
