//! Owner-neutral screen references for Dreamer dispatch gating.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! A screen reference is an opaque pointer to a screening outcome owned
//! elsewhere (for example cells `A-19c`/`A-20`): it carries digests and a
//! fence so dispatch can confirm that a screen ran, but it carries no
//! screening logic, no curation kind, and no admission or effect authority.
//! Generic screens contain no [`CurationKind`][crate::curation::CurationKind]:
//! kind-specific interpretation belongs to typed handlers, never to this hub.

use eliot_contracts::{ReceiptId, RequestId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};

const MAX_TEXT: usize = 256;

/// Closed screen outcome state.
///
/// Only [`ScreenState::Eligible`] can enable dispatch, and only together
/// with well-formed digests. Every other state is fail-closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScreenState {
    /// The screen passed and dispatch may proceed.
    Eligible,
    /// The item is protected; dispatch must not proceed.
    Protected,
    /// Protection status could not be determined; dispatch must not proceed.
    ProtectionUnknown,
    /// The screen reference itself is malformed.
    Malformed,
    /// The screen outcome is stale relative to its fence.
    Stale,
    /// The screen outcome is unavailable.
    Unavailable,
    /// The screen outcome is partial and cannot support dispatch.
    Partial,
    /// The screen outcome was truncated and cannot support dispatch.
    Truncated,
    /// The screen has not been processed yet.
    Unprocessed,
}

impl ScreenState {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Protected => "protected",
            Self::ProtectionUnknown => "protection_unknown",
            Self::Malformed => "malformed",
            Self::Stale => "stale",
            Self::Unavailable => "unavailable",
            Self::Partial => "partial",
            Self::Truncated => "truncated",
            Self::Unprocessed => "unprocessed",
        }
    }

    /// Parses a wire spelling into a [`ScreenState`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::UnknownVariant`] for any unknown spelling.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        match value {
            "eligible" => Ok(Self::Eligible),
            "protected" => Ok(Self::Protected),
            "protection_unknown" => Ok(Self::ProtectionUnknown),
            "malformed" => Ok(Self::Malformed),
            "stale" => Ok(Self::Stale),
            "unavailable" => Ok(Self::Unavailable),
            "partial" => Ok(Self::Partial),
            "truncated" => Ok(Self::Truncated),
            "unprocessed" => Ok(Self::Unprocessed),
            other => Err(ContractViolation::UnknownVariant {
                field: "screen_state",
                value: other.to_owned(),
            }),
        }
    }

    /// Returns true only for [`ScreenState::Eligible`].
    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Eligible)
    }

    /// Exact fail-closed reason for every state; only `Eligible` enables dispatch.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Protected => "screen state is protected",
            Self::ProtectionUnknown => "screen protection is unknown",
            Self::Malformed => "screen state is malformed",
            Self::Stale => "screen state is stale",
            Self::Unavailable => "screen state is unavailable",
            Self::Partial => "screen state is partial",
            Self::Truncated => "screen state is truncated",
            Self::Unprocessed => "screen state is unprocessed",
        }
    }
}

/// Dispatch eligibility derived from a [`ScreenReference`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScreenEligibility {
    /// Dispatch may proceed.
    Eligible,
    /// Dispatch must not proceed, with the exact reason.
    Ineligible {
        /// Exact machine-readable reason.
        reason: String,
    },
}

impl ScreenEligibility {
    /// Returns true only for [`ScreenEligibility::Eligible`].
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible)
    }
}

/// Opaque, owner-neutral pointer to a screening outcome: digests and a fence
/// confirm a screen ran; no curation kind is carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenReference {
    /// Screen identity.
    pub screen_id: String,
    /// A-19c screen request identity.
    pub request_id: RequestId,
    /// Screen result/receipt identity.
    pub receipt_id: ReceiptId,
    /// Screened target identity (non-blank).
    pub target_id: String,
    /// Digest of the screen result (64 lowercase hex chars).
    pub result_digest: String,
    /// Digest of the screened item (64 lowercase hex chars).
    pub item_digest: String,
    /// Screening profile name (non-blank).
    pub profile: String,
    /// Source snapshot the screen ran against (non-blank).
    pub source_snapshot: String,
    /// Source snapshot revision (non-blank).
    pub source_revision: String,
    /// Population denominator the screen ran against (non-blank).
    pub denominator: String,
    /// Owning task identity (non-blank).
    pub task_id: String,
    /// Decision scope identity (non-blank).
    pub scope_id: String,
    /// Fence the screen outcome is bound to.
    pub state_fence: StateFence,
    /// Screen outcome state.
    pub state: ScreenState,
}

impl ScreenReference {
    /// Derives dispatch eligibility: `Eligible` only for an eligible state
    /// with well-formed digests, else `Ineligible` with the exact reason.
    #[must_use]
    pub fn eligibility(&self) -> ScreenEligibility {
        if self.state != ScreenState::Eligible {
            return ScreenEligibility::Ineligible {
                reason: self.state.reason().to_owned(),
            };
        }
        for (label, digest) in [("result", &self.result_digest), ("item", &self.item_digest)] {
            if !is_hex64_lower(digest) {
                return ScreenEligibility::Ineligible {
                    reason: std::format!("screen {label} digest is not 64 lowercase hex"),
                };
            }
        }
        ScreenEligibility::Eligible
    }

    /// Validates identity, digest, and binding shape (not state gating).
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.screen_id, "screen_id", MAX_TEXT)?;
        check_text(&self.target_id, "target_id", MAX_TEXT)?;
        check_text(&self.profile, "profile", MAX_TEXT)?;
        check_text(&self.source_snapshot, "source_snapshot", MAX_TEXT)?;
        check_text(&self.source_revision, "source_revision", MAX_TEXT)?;
        check_text(&self.denominator, "denominator", MAX_TEXT)?;
        check_text(&self.task_id, "task_id", MAX_TEXT)?;
        check_text(&self.scope_id, "scope_id", MAX_TEXT)?;
        require_digest("result_digest", &self.result_digest)?;
        require_digest("item_digest", &self.item_digest)?;
        check_fence(&self.state_fence)?;
        Ok(())
    }
}

/// Owner-neutral A-19c screen handle for the A-31 seam.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenBinding {
    pub request_id: RequestId,
    pub receipt_id: ReceiptId,
    pub screened_targets: Vec<String>,
    pub source_snapshot: String,
    pub source_revision: String,
    pub profile: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub state: ScreenState,
    pub result_digest: String,
    pub item_digest: String,
}

impl ScreenBinding {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.state != ScreenState::Eligible
            || !is_hex64_lower(&self.result_digest)
            || !is_hex64_lower(&self.item_digest)
        {
            return Err(ContractViolation::ScreenIneligible(
                "screen binding is not eligible".to_owned(),
            ));
        }
        check_text(&self.source_snapshot, "source_snapshot", MAX_TEXT)?;
        check_text(&self.source_revision, "source_revision", MAX_TEXT)?;
        check_text(&self.profile, "profile", MAX_TEXT)?;
        check_text(&self.task_id, "task_id", MAX_TEXT)?;
        check_text(&self.scope_id, "scope_id", MAX_TEXT)?;
        if self.request_id.as_str() == self.receipt_id.as_str() {
            return Err(ContractViolation::ScreenIneligible(
                "request and receipt identities must differ".to_owned(),
            ));
        }
        if self.screened_targets.is_empty() {
            return Err(ContractViolation::MissingField("screened_targets"));
        }
        check_vec_bound(self.screened_targets.len(), 1024, "screened_targets")?;
        let aggregate: usize = self.screened_targets.iter().map(String::len).sum();
        check_vec_bound(aggregate, 1_048_576, "screened_targets")?;
        let mut ordered = self.screened_targets.clone();
        ordered.sort();
        for target in &ordered {
            check_text(target, "screened_targets", MAX_TEXT)?;
        }
        ordered.dedup();
        if ordered.len() != self.screened_targets.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "screened_targets",
                reason: "duplicate screened target".to_owned(),
            });
        }
        check_fence(&self.state_fence)?;
        Ok(())
    }
}

fn require_digest(field: &'static str, value: &str) -> Result<(), ContractViolation> {
    if !is_hex64_lower(value) {
        return Err(ContractViolation::Malformed {
            field,
            reason: "expected 64 lowercase hex chars".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn valid_reference() -> ScreenReference {
        ScreenReference {
            screen_id: "screen-36".to_owned(),
            request_id: RequestId::new("req-36").expect("id"),
            receipt_id: ReceiptId::new("rcpt-36").expect("id"),
            target_id: "target-36".to_owned(),
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
            profile: "default".to_owned(),
            source_snapshot: "snapshot-1".to_owned(),
            source_revision: "rev-7".to_owned(),
            denominator: "population".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: fence(),
            state: ScreenState::Eligible,
        }
    }

    // WORK_UNIT_CASE: 578/36
    #[test]
    fn marker_36_exact_eligible_screen_reference() {
        let reference = valid_reference();
        assert!(reference.validate().is_ok());
        assert_eq!(reference.eligibility(), ScreenEligibility::Eligible);
        let bytes = serde_json::to_vec(&reference).expect("reference serializes");
        let decoded: ScreenReference =
            serde_json::from_slice(&bytes).expect("reference roundtrips");
        assert_eq!(decoded, reference);
        assert_eq!(decoded.request_id.as_str(), "req-36");
        assert_eq!(decoded.receipt_id.as_str(), "rcpt-36");
        assert_eq!(decoded.target_id, "target-36");
        assert_eq!(decoded.source_revision, "rev-7");
        assert_eq!(decoded.eligibility(), ScreenEligibility::Eligible);
        let mut oversize = valid_reference();
        oversize.screen_id = "x".repeat(257);
        assert!(oversize.validate().is_err());
        let mut control = valid_reference();
        control.profile = "a\u{7}b".to_owned();
        assert!(control.validate().is_err());
    }

    // WORK_UNIT_CASE: 578/37
    #[test]
    fn marker_37_non_eligible_states_cannot_enable_dispatch() {
        let states = [
            ScreenState::Protected,
            ScreenState::ProtectionUnknown,
            ScreenState::Malformed,
            ScreenState::Stale,
            ScreenState::Unavailable,
            ScreenState::Partial,
            ScreenState::Truncated,
            ScreenState::Unprocessed,
        ];
        assert_eq!(states.len(), 8);
        for state in states {
            let mut reference = valid_reference();
            reference.state = state;
            let eligibility = reference.eligibility();
            assert!(!eligibility.is_eligible());
            assert!(matches!(eligibility, ScreenEligibility::Ineligible { .. }));
        }
    }
}
