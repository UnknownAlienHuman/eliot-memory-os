//! Owner-neutral screen references for Dreamer dispatch gating.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! A screen reference is an opaque pointer to a screening outcome owned
//! elsewhere (for example cells `A-19c`/`A-20`): it carries digests and a
//! fence so dispatch can confirm that a screen ran, but it carries no
//! screening logic, no curation kind, and no admission or effect authority.
//! Generic screens contain no [`CurationKind`][crate::curation::CurationKind]:
//! kind-specific interpretation belongs to typed handlers, never to this hub.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;

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

/// Opaque, owner-neutral pointer to a screening outcome.
///
/// Carries digests and a fence so dispatch can confirm that a screen ran.
/// Carries no curation kind: generic screens contain no kind, and
/// kind-specific interpretation belongs to typed handlers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenReference {
    /// Screen identity (non-blank).
    pub screen_id: String,
    /// Digest of the screen result (64 lowercase hex chars).
    pub result_digest: String,
    /// Digest of the screened item (64 lowercase hex chars).
    pub item_digest: String,
    /// Screening profile name (non-blank).
    pub profile: String,
    /// Source snapshot the screen ran against (non-blank).
    pub source_snapshot: String,
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
    /// Derives dispatch eligibility.
    ///
    /// Returns [`ScreenEligibility::Eligible`] only when the state is
    /// [`ScreenState::Eligible`] and both digests are well-formed. Every
    /// other state maps to [`ScreenEligibility::Ineligible`] with an exact
    /// reason, so no non-eligible state can enable dispatch.
    #[must_use]
    pub fn eligibility(&self) -> ScreenEligibility {
        match self.state {
            ScreenState::Eligible => {
                if !is_digest(&self.result_digest) {
                    return ScreenEligibility::Ineligible {
                        reason: "screen result digest is not 64 lowercase hex".to_owned(),
                    };
                }
                if !is_digest(&self.item_digest) {
                    return ScreenEligibility::Ineligible {
                        reason: "screen item digest is not 64 lowercase hex".to_owned(),
                    };
                }
                ScreenEligibility::Eligible
            }
            ScreenState::Protected => ScreenEligibility::Ineligible {
                reason: "screen state is protected".to_owned(),
            },
            ScreenState::ProtectionUnknown => ScreenEligibility::Ineligible {
                reason: "screen protection is unknown".to_owned(),
            },
            ScreenState::Malformed => ScreenEligibility::Ineligible {
                reason: "screen state is malformed".to_owned(),
            },
            ScreenState::Stale => ScreenEligibility::Ineligible {
                reason: "screen state is stale".to_owned(),
            },
            ScreenState::Unavailable => ScreenEligibility::Ineligible {
                reason: "screen state is unavailable".to_owned(),
            },
            ScreenState::Partial => ScreenEligibility::Ineligible {
                reason: "screen state is partial".to_owned(),
            },
            ScreenState::Truncated => ScreenEligibility::Ineligible {
                reason: "screen state is truncated".to_owned(),
            },
            ScreenState::Unprocessed => ScreenEligibility::Ineligible {
                reason: "screen state is unprocessed".to_owned(),
            },
        }
    }

    /// Validates identity, digest, and binding shape.
    ///
    /// Checks digest formats and non-blank fields plus the state fence.
    /// State gating itself belongs to [`ScreenReference::eligibility`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any field is blank, any digest is
    /// not 64 lowercase hex chars, or the fence is empty.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require_non_blank("screen_id", &self.screen_id)?;
        require_non_blank("profile", &self.profile)?;
        require_non_blank("source_snapshot", &self.source_snapshot)?;
        require_non_blank("denominator", &self.denominator)?;
        require_non_blank("task_id", &self.task_id)?;
        require_non_blank("scope_id", &self.scope_id)?;
        require_digest("result_digest", &self.result_digest)?;
        require_digest("item_digest", &self.item_digest)?;
        self.state_fence
            .validate()
            .map_err(|_| ContractViolation::BindingMismatch {
                field: "state_fence",
                reason: "screen state fence is empty".to_owned(),
            })?;
        Ok(())
    }
}

/// Returns true when `value` is 64 lowercase hex chars.
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn require_non_blank(field: &'static str, value: &str) -> Result<(), ContractViolation> {
    if value.trim().is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    Ok(())
}

fn require_digest(field: &'static str, value: &str) -> Result<(), ContractViolation> {
    if !is_digest(value) {
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
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
            profile: "default".to_owned(),
            source_snapshot: "snapshot-1".to_owned(),
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
        assert_eq!(decoded.eligibility(), ScreenEligibility::Eligible);
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
            assert!(
                !eligibility.is_eligible(),
                "state {} must not enable dispatch",
                state.as_str()
            );
            assert!(
                matches!(eligibility, ScreenEligibility::Ineligible { .. }),
                "state {} must report Ineligible",
                state.as_str()
            );
        }
    }
}
