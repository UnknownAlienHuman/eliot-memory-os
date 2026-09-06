//! Verifier competence and disclosure: who may vouch, and how widely a position may travel.
//!
//! A [`RequiredVerifier`] names the evaluation contract, revision, run freshness, and standing required to
//! vouch. Only a competent verifier over a current freshness licenses the strongest renderings.
//! [`DisclosureClass`] bounds travel (open, restricted, quarantined) as a ceiling, never evidence. Freshness
//! vocabulary is reused from `eliot-evidence`.
use eliot_contracts::{ContractId, SourceId};
use eliot_evidence::{EvidenceFreshness, VerificationBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::SourceRevisionId;

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

/// Independent privacy handling of a position: what survived redaction.
/// Purged caps at hypothesis candidate no matter the disclosure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyHandling {
    /// No load-bearing material was redacted.
    Unrestricted,
    /// Some material is need-to-know; the position renders qualified at best.
    RestrictedHandling,
    /// A load-bearing handle was purged; the position holds as candidate only.
    Purged,
}

/// Source assurance binding one proof digest to its actual source, with a
/// derived (never asserted) integrity digest.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SourceAssurance {
    /// Source that produced the proof payload.
    pub source: SourceId,
    /// Source revision the proof was captured under.
    pub revision: String,
    /// Digest of the proof payload this assurance covers.
    pub proof_digest: String,
    /// Derived integrity digest over source, revision, and proof digest.
    pub integrity_digest: String,
}
impl SourceAssurance {
    pub fn new(
        source: SourceId,
        revision: SourceRevisionId,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut assurance = Self {
            source,
            revision: revision.into_string(),
            proof_digest: proof_digest.into(),
            integrity_digest: String::new(),
        };
        validate_digest(&assurance.proof_digest, "assurance.proof_digest")?;
        validate_bounded_text(&assurance.revision, "assurance.revision", MAX_SHORT_TEXT)?;
        assurance.integrity_digest = assurance.compute_integrity()?;
        Ok(assurance)
    }
    pub fn compute_integrity(&self) -> Result<String, ContractError> {
        shape_digest(&(&self.source, &self.revision, &self.proof_digest))
    }
    /// Validates the binding: the integrity digest must cover exactly this
    /// source, revision, and proof digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_digest(&self.proof_digest, "assurance.proof_digest")?;
        validate_bounded_text(&self.revision, "assurance.revision", MAX_SHORT_TEXT)?;
        validate_digest(&self.integrity_digest, "assurance.integrity_digest")?;
        if self.integrity_digest != self.compute_integrity()? {
            return Err(ContractError::DigestMismatch {
                field: "assurance.integrity_digest",
            });
        }
        Ok(())
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
    /// Current run binding reused from `eliot-evidence`: the contract run
    /// that vouched, with its revision. Standing alone never proves a run.
    pub verification: VerificationBinding,
    /// Digest of the exact candidate or receipt the run verified. Results
    /// bind to this digest; a run over another digest vouches nothing here.
    pub verified_digest: String,
    /// Canonical digest of the verifier shape, excluding this field.
    pub digest: String,
}
impl RequiredVerifier {
    pub fn new(
        contract: ContractId,
        revision: impl Into<String>,
        freshness: EvidenceFreshness,
        standing: VerifierStanding,
        quarantine_reason: Option<String>,
        verification: VerificationBinding,
        verified_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut verifier = Self {
            contract,
            revision: revision.into(),
            freshness,
            standing,
            quarantine_reason,
            verification,
            verified_digest: verified_digest.into(),
            digest: String::new(),
        };
        verifier.validate_shape()?;
        verifier.digest = verifier.compute_digest()?;
        Ok(verifier)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.contract,
            &self.revision,
            &self.freshness,
            &self.standing,
            &self.quarantine_reason,
            &self.verification,
            &self.verified_digest,
        ))
    }
    /// Returns whether the vouched run is current (exact candidate, commit,
    /// or quiesced worktree only).
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
        self.verification
            .validate()
            .map_err(|_| ContractError::ImpossibleCombination {
                field: "verifier.verification",
            })?;
        validate_digest(&self.verified_digest, "verifier.verified_digest")?;
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
    /// Validates that this verifier vouched for the given candidate or receipt digest.
    pub fn validate_for(&self, verified_digest: &str) -> Result<(), ContractError> {
        self.validate()?;
        if self.verified_digest != verified_digest {
            return Err(ContractError::DigestMismatch {
                field: "verifier.verified_digest",
            });
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "verifier.digest")
    }
}
