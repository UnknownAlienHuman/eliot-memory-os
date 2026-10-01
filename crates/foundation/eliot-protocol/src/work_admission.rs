//! Neutral semantic revision identity shared by canonical admission owners.
//!
//! This shape is transport only. It does not issue a revision or prove that
//! an owner performed the matching compare-and-swap; the canonical owner
//! retains and validates that evidence.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Semantic revision of the canonical work-admission owner snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkAdmissionSemanticRevision {
    /// Exact canonical owner key. Current work admission uses
    /// `owner/canonical`.
    pub key: String,
    /// Canonical decimal revision proposed by the owner.
    pub revision: String,
}

impl WorkAdmissionSemanticRevision {
    /// Checks the exact canonical owner key and next revision against the
    /// predecessor retained by the original owner compare-and-swap.
    pub fn validate_owner_canonical(&self, predecessor_revision: u64) -> Result<(), ProtocolError> {
        let expected = predecessor_revision.checked_add(1).ok_or(ProtocolError::InvalidField {
            field: "work_admission_semantic_revision.predecessor_revision",
            reason: "cannot advance beyond the maximum revision",
        })?;
        if self.key != "owner/canonical" || self.revision != expected.to_string() {
            return Err(ProtocolError::InvalidField {
                field: "work_admission_semantic_revision",
                reason: "must be the next owner/canonical revision from its retained predecessor",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_owner_revision_accepts_exact_successor() {
        WorkAdmissionSemanticRevision {
            key: "owner/canonical".to_owned(),
            revision: "8".to_owned(),
        }
        .validate_owner_canonical(7)
        .expect("owner-issued next revision shape");
    }

    #[test]
    fn canonical_owner_revision_refuses_a_different_predecessor() {
        let revision = WorkAdmissionSemanticRevision {
            key: "owner/canonical".to_owned(),
            revision: "8".to_owned(),
        };
        assert!(
            revision.validate_owner_canonical(8).is_err(),
            "same revision cannot be replayed against a different predecessor"
        );
    }
}
