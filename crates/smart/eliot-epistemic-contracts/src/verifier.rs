//! Verifier competence and disclosure: who may vouch, and how widely a
//! position may travel.
//!
//! A [`RequiredVerifier`] names the exact evaluation contract and revision
//! required to vouch for a position, the [`EvidenceFreshness`] of the run it
//! vouched for, and its standing. Only a [`VerifierStanding::Competent`]
//! verifier over a current freshness
//! ([`EvidenceFreshness::ExactCandidate`],
//! [`EvidenceFreshness::ExactCommit`], or
//! [`EvidenceFreshness::ExactQuiescedWorktree`]) licenses the strongest
//! renderings; anything else quarantines the position instead of promoting it.
//! Freshness vocabulary is reused from `eliot-evidence` and never redefined.
//!
//! [`DisclosureClass`] bounds how widely a position may travel: open material
//! renders under its ceilings, restricted material never rises above qualified
//! inference, and quarantined material renders only as quarantined unknown.
//! Disclosure is a ceiling, never evidence: it can only lower assertability.

use eliot_contracts::ContractId;
use eliot_evidence::EvidenceFreshness;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, shape_digest, validate_bounded_text, validate_digest,
};

/// Standing of a required verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerifierStanding {
    /// The verifier ran competently over a current freshness.
    Competent,
    /// Competence cannot be established; the position stays qualified at best.
    Unknown,
    /// The verifier is isolated pending a release condition.
    Quarantined,
}

impl VerifierStanding {
    /// Returns the exact frozen wire name of this standing.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Competent => "COMPETENT",
            Self::Unknown => "UNKNOWN",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// How widely a position may travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisclosureClass {
    /// Open material; renders under its evidence ceilings.
    Open,
    /// Restricted material; never rises above qualified inference.
    Restricted,
    /// Quarantined material; renders only as quarantined unknown.
    Quarantined,
}

impl DisclosureClass {
    /// Returns the exact frozen wire name of this disclosure class.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Restricted => "RESTRICTED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// The exact verifier required to vouch for a position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequiredVerifier {
    /// Evaluation contract identity required to vouch.
    pub contract: ContractId,
    /// Revision of the evaluation contract that vouched.
    pub revision: String,
    /// Freshness of the run that vouched, reused from `eliot-evidence`.
    pub freshness: EvidenceFreshness,
    /// Standing of the verifier.
    pub standing: VerifierStanding,
    /// Bounded quarantine reason; required exactly when quarantined.
    pub quarantine_reason: Option<String>,
    /// Canonical digest of the verifier shape, excluding this field.
    pub digest: String,
}

impl RequiredVerifier {
    /// Constructs a required verifier and freezes its canonical digest.
    pub fn new(
        contract: ContractId,
        revision: impl Into<String>,
        freshness: EvidenceFreshness,
        standing: VerifierStanding,
        quarantine_reason: Option<String>,
    ) -> Result<Self, ContractError> {
        let mut verifier = Self {
            contract,
            revision: revision.into(),
            freshness,
            standing,
            quarantine_reason,
            digest: String::new(),
        };
        verifier.validate_shape()?;
        verifier.digest = verifier.compute_digest()?;
        Ok(verifier)
    }

    /// Recomputes the canonical digest of the verifier shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.contract,
            &self.revision,
            &self.freshness,
            &self.standing,
            &self.quarantine_reason,
        ))
    }

    /// Returns whether the vouched run is current.
    ///
    /// Only the exact candidate, the exact commit, or a quiesced exact
    /// worktree counts as current; older snapshots, stale runs, and unknown
    /// freshness never do.
    pub const fn is_current(&self) -> bool {
        matches!(
            self.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        )
    }

    /// Returns whether this verifier licenses the strongest renderings.
    pub const fn is_competent(&self) -> bool {
        matches!(self.standing, VerifierStanding::Competent) && self.is_current()
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.revision, "verifier.revision", MAX_SHORT_TEXT)?;
        match (&self.standing, &self.quarantine_reason) {
            (VerifierStanding::Quarantined, Some(reason)) => {
                validate_bounded_text(
                    reason.as_str(),
                    "verifier.quarantine_reason",
                    MAX_SHORT_TEXT,
                )?;
            }
            (VerifierStanding::Quarantined, None) => {
                return Err(ContractError::EmptyCollection {
                    field: "verifier.quarantine_reason",
                });
            }
            (_, Some(_)) => {
                return Err(ContractError::ImpossibleCombination {
                    field: "verifier.quarantine_reason",
                });
            }
            (_, None) => {}
        }
        Ok(())
    }

    /// Validates the verifier shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "verifier.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "verifier.digest",
            });
        }
        Ok(())
    }
}
