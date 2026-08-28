//! WorkScope-relative path contract.
//!
//! Local architecture anchor `A3` (`WorkScope` and changing world) describes
//! `WorkScope` as a changing boundary containing identity, resources, truth
//! surfaces, and privacy/authority boundaries. Local implementation anchors
//! `I3.11` (`WorkScope` Profile), `I4.1` (`WorkScope` identity), and `I4.3.1`
//! (authenticated `WorkScope` proposal and scan boundary) distinguish available
//! policy from adapter health or claim truth, bind identity to roots and
//! resources rather than display name, and treat an explicit path as evidence
//! requiring authenticated root/resource identities.
//!
//! This module performs lexical normalization only. An adapter must reparse and
//! prove containment. This module owns no filesystem effect or authority.

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{PortError, validate_text};

/// A validated lexical path relative to the authenticated `WorkScope` root.
///
/// The original spelling is retained for display while equality, ordering and
/// hashing use the canonical separator-normalized identity.
#[derive(Clone, Debug, JsonSchema)]
#[schemars(with = "String")]
pub struct WorkScopePath {
    display: String,
    normalized_identity: String,
}

/// Typed input that makes the adapter's reparse-point containment obligation explicit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterPathInput {
    pub display: String,
    pub normalized_identity: String,
    pub containment: AdapterContainment,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdapterContainment {
    ReparseAndProveWithinWorkScope,
}

impl WorkScopePath {
    pub fn new(value: impl Into<String>) -> Result<Self, PortError> {
        let value = value.into();
        validate_text(&value, "path")?;
        let rooted = value.starts_with('/')
            || value.starts_with('\\')
            || (value.len() >= 2 && value.as_bytes()[1] == b':')
            || value.starts_with("//")
            || value.starts_with("\\\\");
        if rooted {
            return Err(PortError::InvalidPath);
        }
        let mut components = Vec::new();
        for component in value.split(['/', '\\']) {
            match component {
                "" | "." => {}
                ".." => return Err(PortError::InvalidPath),
                component => components.push(component.to_owned()),
            }
        }
        if components.is_empty() {
            return Err(PortError::InvalidPath);
        }
        Ok(Self {
            display: value,
            normalized_identity: components.join("/"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.display
    }

    pub fn normalized_identity(&self) -> &str {
        &self.normalized_identity
    }

    pub fn adapter_input(&self) -> AdapterPathInput {
        AdapterPathInput {
            display: self.display.clone(),
            normalized_identity: self.normalized_identity.clone(),
            containment: AdapterContainment::ReparseAndProveWithinWorkScope,
        }
    }
}

impl PartialEq for WorkScopePath {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_identity == other.normalized_identity
    }
}
impl Eq for WorkScopePath {}
impl PartialOrd for WorkScopePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for WorkScopePath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized_identity.cmp(&other.normalized_identity)
    }
}
impl Hash for WorkScopePath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.normalized_identity.hash(state);
    }
}
impl Serialize for WorkScopePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.display)
    }
}
impl<'de> Deserialize<'de> for WorkScopePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let display = String::deserialize(deserializer)?;
        Self::new(display).map_err(serde::de::Error::custom)
    }
}
