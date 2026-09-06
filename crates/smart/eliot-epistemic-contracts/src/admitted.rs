//! Admitted view: a read of an external admission, proving nothing itself.
//!
//! A [`CurrentEpistemicPosition`] carries the exact position identity and
//! revision, the external admission receipt it was read from, the owning
//! source with currentness and supersession links, the claim with its scope
//! and fence, and evidence, coverage, conflict, and proof references. The
//! view is a read: it proves nothing beyond the receipt it cites, and it
//! carries a distinct marker so a candidate document can never decode as an
//! admitted view nor the reverse.
//!
//! The canonical admitted read-view type is named exactly
//! [`CurrentEpistemicPosition`], satisfying the cognitive edge-map contract
//! `eliot-epistemic-contracts::CurrentEpistemicPosition`.
//! [`CurrentEpistemicPositionView`] is a documented alias of the same type —
//! same definition, same serde, same wire bytes — kept only so existing
//! readers keep compiling while they migrate to the canonical name.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ReceiptId, SourceId, StateFence, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::{ClaimId, PropositionId};

/// Marker proving a document is an admitted view and never a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AdmittedKind {
    /// The single admitted spelling of an admitted position view.
    #[serde(rename = "CURRENT_EPISTEMIC_POSITION")]
    #[schemars(rename = "CURRENT_EPISTEMIC_POSITION")]
    CurrentEpistemicPosition,
}

/// Owner-neutral rendering of the donor position algebra, for record
/// compatibility.
///
/// Donor disposition (`crates/smart/eliot-epistemic/src/lib.rs`, donor scope
/// `PositionState`): the six donor states are preserved exactly, including
/// `Assumed`, which stays a position state rather than a promotion of the
/// underlying evidence vocabulary. An admitted view itself carries
/// [`Currentness`] plus its external receipt instead of a resolver state; this
/// enum exists so donor records and migrated fixtures keep a shared,
/// owner-neutral spelling. The donor `resolve` transition into these states is
/// explicitly not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PositionState {
    /// Directly captured observation, not yet support for a claim.
    Observed,
    /// Currently supported within its declared scope.
    Supported,
    /// Held under an explicit assumption; never decoded as support.
    Assumed,
    /// Competing positions remain unresolved.
    Conflicted,
    /// Once useful material whose freshness boundary has passed.
    Stale,
    /// The available material cannot establish a position.
    Unknown,
}

impl PositionState {
    /// Returns the exact frozen wire name of this position state.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Supported => "SUPPORTED",
            Self::Assumed => "ASSUMED",
            Self::Conflicted => "CONFLICTED",
            Self::Stale => "STALE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Currentness of the admitted position under its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Currentness {
    /// The owner holds this position as current.
    Current,
    /// The owner superseded this position; links say by what.
    Superseded,
}

impl Currentness {
    /// Returns the exact frozen wire name of this currentness.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Current => "CURRENT",
            Self::Superseded => "SUPERSEDED",
        }
    }
}

/// A read view of an externally admitted epistemic position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentEpistemicPosition {
    /// Marker binding this document to the admitted-view decoding.
    pub view_kind: AdmittedKind,
    /// Exact position identity admitted elsewhere.
    pub position: PropositionId,
    /// Exact revision admitted elsewhere.
    pub revision: TaskRevision,
    /// External admission receipt this view was read from.
    pub admission_receipt: ReceiptId,
    /// Digest of the external admission receipt payload.
    pub admission_digest: String,
    /// Source owning the admitted position.
    pub owner: SourceId,
    /// Currentness of the position under its owner.
    pub currentness: Currentness,
    /// Supersession links; required exactly when superseded.
    pub supersession: BTreeSet<ArtifactId>,
    /// Governed claim identity of the admitted position.
    pub claim: ClaimId,
    /// Scope of the admitted position.
    pub scope: String,
    /// Fence the admitted position was read under.
    pub fence: StateFence,
    /// Canonical digest of the evidence set behind the position.
    pub evidence_digest: String,
    /// Canonical digest of the coverage denominator behind the position.
    pub coverage_digest: String,
    /// Canonical digest of the conflict material behind the position.
    pub conflict_digest: String,
    /// Digest of the bounded proof payload behind the position.
    pub proof_digest: String,
    /// Canonical digest of the view shape, excluding this field.
    pub digest: String,
}

/// Previous name of [`CurrentEpistemicPosition`]: the same type, the same
/// serde, the same wire bytes. New code uses the canonical name; this alias
/// exists only so existing readers keep compiling while they migrate.
pub type CurrentEpistemicPositionView = CurrentEpistemicPosition;

impl CurrentEpistemicPosition {
    /// Constructs an admitted view and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        position: PropositionId,
        revision: TaskRevision,
        admission_receipt: ReceiptId,
        admission_digest: impl Into<String>,
        owner: SourceId,
        currentness: Currentness,
        supersession: BTreeSet<ArtifactId>,
        claim: ClaimId,
        scope: impl Into<String>,
        fence: StateFence,
        evidence_digest: impl Into<String>,
        coverage_digest: impl Into<String>,
        conflict_digest: impl Into<String>,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut view = Self {
            view_kind: AdmittedKind::CurrentEpistemicPosition,
            position,
            revision,
            admission_receipt,
            admission_digest: admission_digest.into(),
            owner,
            currentness,
            supersession,
            claim,
            scope: scope.into(),
            fence,
            evidence_digest: evidence_digest.into(),
            coverage_digest: coverage_digest.into(),
            conflict_digest: conflict_digest.into(),
            proof_digest: proof_digest.into(),
            digest: String::new(),
        };
        view.validate_shape()?;
        view.digest = view.compute_digest()?;
        Ok(view)
    }

    /// Recomputes the canonical digest of the view shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.view_kind,
            &self.position,
            &self.revision,
            &self.admission_receipt,
            &self.admission_digest,
            &self.owner,
            &self.currentness,
            &self.supersession,
            &self.claim,
            &self.scope,
            &self.fence,
            &self.evidence_digest,
            &self.coverage_digest,
            &self.conflict_digest,
            &self.proof_digest,
        ))
    }

    /// Returns the admission receipt identity and digest this view proves.
    ///
    /// A read view proves nothing beyond this receipt.
    pub fn receipt_identity(&self) -> (&ReceiptId, &str) {
        (&self.admission_receipt, self.admission_digest.as_str())
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.view_kind != AdmittedKind::CurrentEpistemicPosition {
            return Err(ContractError::ImpossibleCombination {
                field: "admitted.view_kind",
            });
        }
        validate_digest(&self.admission_digest, "admitted.admission_digest")?;
        validate_bounded_text(&self.scope, "admitted.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "admitted.fence",
            })?;
        if self.supersession.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "admitted.supersession",
            });
        }
        match (self.currentness, self.supersession.is_empty()) {
            (Currentness::Current, true) | (Currentness::Superseded, false) => {}
            _ => {
                return Err(ContractError::ImpossibleCombination {
                    field: "admitted.currentness",
                });
            }
        }
        validate_digest(&self.evidence_digest, "admitted.evidence_digest")?;
        validate_digest(&self.coverage_digest, "admitted.coverage_digest")?;
        validate_digest(&self.conflict_digest, "admitted.conflict_digest")?;
        validate_digest(&self.proof_digest, "admitted.proof_digest")?;
        Ok(())
    }

    /// Validates the view shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "admitted.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "admitted.digest",
            });
        }
        Ok(())
    }
}
