//! Frozen v2 row identity for derived binding candidates.
//!
//! A candidate is a proposal, not membership: this module computes the same
//! frozen identity the snapshot boundary will close on, so a candidate that
//! cannot join a snapshot row is visible here rather than invented downstream.

use eliot_cue_contracts::{CueBindingCandidate, MatchMode};

use crate::CueBindingError;

/// Computes the frozen v2 row identity for one candidate under one explicit
/// comparison key.
///
/// Binds the caller-supplied scope, the candidate's canonical kind and target,
/// the caller-supplied mode and normalized value, and the identity-contract
/// revision through [`eliot_cue_contracts::cue_row_id`]. Same text in different
/// kinds or modes therefore yields distinct identities.
pub fn binding_row_id(
    candidate: &CueBindingCandidate,
    scope: &str,
    mode: MatchMode,
    normalized_value: &str,
) -> Result<String, CueBindingError> {
    candidate
        .validate()
        .map_err(|_| CueBindingError::Contract {
            field: "binding.candidate",
        })?;
    eliot_cue_contracts::cue_row_id(
        scope,
        candidate.canonical.kind,
        mode,
        normalized_value,
        &candidate.target,
    )
    .map_err(|_| CueBindingError::Contract {
        field: "binding.row_identity",
    })
}
