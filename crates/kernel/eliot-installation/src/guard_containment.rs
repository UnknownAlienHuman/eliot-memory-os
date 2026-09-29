//! Installation-side durable retention of one composite guard-revert outcome.
//!
//! Architecture: A13.2 (failure-domain owners), ARCH-OBS-01, ARCH-SEC-01.
//! Implementation: I2.6 (an error preserves operation identity, effect status
//! and a raw evidence handle), I5.19 (one receipt envelope, never a second
//! journal), I7.20 (typed disposition plus a required recovery action), I14.24
//! (containment).
//!
//! This module owns no provider execution and no terminal write. The composite
//! itself is owned by the provider-neutral P-01 contract
//! (`eliot_platform::GuardRevertOutcome`); the bounded terminal record and its
//! readback are owned by `eliot_platform_windows::terminal_containment`. This
//! module only retains the composite in the installation transaction's existing
//! durable record and records whether an independent owner has reconciled the
//! exact retained terminal record against this exact operation.
//!
//! Nothing here re-encodes, re-digests, or re-interprets the composite. The
//! composite is validated through its own `validate()`, the terminal record is
//! validated through the terminal owner's own readback validator, and the
//! retained record is compared with this operation by content, never by name.

use eliot_platform::{GuardRevertOutcome, RequiredNextAction};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallationError, PlatformHandle, sha256_handle};

/// The exact composite a guard owner returned, plus the owner reconciliation
/// that releases the block on the affected object.
///
/// The composite is retained verbatim for the life of the transaction. It is
/// never replaced, compacted, or deleted to simplify a `Result`: a second,
/// different composite for the same transaction is an identity conflict, not a
/// replacement.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedGuardRevert {
    /// The closed composite exactly as the guard owner returned it, including
    /// the primary failure slot and every explicit and emergency restoration
    /// attempt.
    pub outcome: GuardRevertOutcome,
    /// Content digest of the exact retained terminal record that an
    /// independent owner read back and bound to this operation.
    ///
    /// `None` keeps the affected object blocked. It is never a synthesized
    /// receipt, and it is never inferred from a write return, a reserved slot,
    /// or a nonzero exit.
    #[serde(default)]
    pub reconciliation: Option<PlatformHandle>,
}

impl RetainedGuardRevert {
    /// Whether the affected object stays blocked.
    ///
    /// A composite whose own required next action is a normal return is not
    /// blocked: the guard owner established continuation-safe OS state. Every
    /// other composite stays blocked until an exact owner reconciliation is
    /// retained, and an unresolved retained terminal record never clears it.
    #[must_use]
    pub fn blocks_adoption(&self) -> bool {
        self.reconciliation.is_none()
            && self.outcome.next_action != RequiredNextAction::ContinueNormally
    }

    /// The evidence reference naming the retained bounded terminal record.
    #[must_use]
    pub fn evidence_ref(&self) -> &PlatformHandle {
        &self.outcome.evidence_ref
    }

    /// Validates the retained composite through its own `validate()` and the
    /// retained reconciliation reference through the transaction's existing
    /// evidence rules.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::InvalidField`] when the composite fails its
    /// own validation, when the reconciliation reference is not a valid
    /// evidence reference, or when a reconciliation is retained for a
    /// composite that never required one.
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
        self.outcome
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "guard_revert".to_owned(),
                reason: error.to_string(),
            })?;
        match &self.reconciliation {
            Some(reference) => {
                if self.outcome.next_action == RequiredNextAction::ContinueNormally {
                    return Err(InstallationError::IncompleteObservation(
                        "a continuation-safe guard outcome cannot retain an owner reconciliation"
                            .to_owned(),
                    ));
                }
                sha256_handle(reference, "guard_revert.reconciliation")?;
            }
            None => {}
        }
        Ok(())
    }
}
