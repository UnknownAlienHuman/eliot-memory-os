//! Admitted view: a read of an external admission, proving nothing itself.
//!
//! A [`CurrentEpistemicPosition`] carries the exact position identity and revision plus the typed
//! [`AdmittedReceipt`] envelope it was read from, bound by value; a distinct marker keeps candidates
//! and views undecodable as each other.
//! [`CurrentEpistemicPositionView`] is a documented alias of the same type, kept only for migrating readers.
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use eliot_contracts::{ArtifactId, ReceiptId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::ClaimId;

/// Marker proving a document is an admitted view and never a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum AdmittedKind {
    /// The single admitted spelling of an admitted position view.
    #[serde(rename = "CURRENT_EPISTEMIC_POSITION")]
    #[schemars(rename = "CURRENT_EPISTEMIC_POSITION")]
    CurrentEpistemicPosition,
}
crate::position_id!(
    /// Dedicated identity of one admitted epistemic position: the proposition
    /// names what the position bears on, while the position id names the
    /// admitted position itself (never interchangeable).
    PositionId,
    "position_id"
);

/// Dedicated revision of one admitted epistemic position: a task revision names the plan state the inquiry
/// ran under, while the position revision names the admitted position's own revision (never interchangeable).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct PositionRevision(u64);
impl PositionRevision {
    /// Creates a position revision, rejecting zero as the absent value.
    pub const fn new(value: u64) -> Result<Self, ContractError> {
        if value == 0 {
            return Err(ContractError::OutOfRange {
                field: "position_revision",
            });
        }
        Ok(Self(value))
    }
    /// Creates the genesis position revision for an explicit initial state.
    pub const fn genesis() -> Self {
        Self(1)
    }
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Typed envelope summarizing one externally admitted payload: payload digest, owner, revision, scope, fence,
/// evidence/coverage/conflict/proof digests, and the exact position identity admitted. It performs no admission
/// itself; this crate only reads the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedReceipt {
    /// Canonical external receipt identity, reused from `eliot-contracts`: a payload digest alone never
    /// validates, and every envelope binds this receipt id plus its owner at minimum.
    pub receipt_id: ReceiptId,
    /// Digest of the externally admitted payload.
    pub payload_digest: String,
    /// Source owning the admitted position.
    pub owner: SourceId,
    /// Source revision admitted.
    pub revision: String,
    /// Scope admitted.
    pub scope: String,
    /// Fence the payload was admitted under.
    pub fence: StateFence,
    /// Canonical digest of the evidence set behind the position.
    pub evidence_digest: String,
    /// Canonical digest of the coverage denominator behind the position.
    pub coverage_digest: String,
    /// Canonical digest of the conflict material behind the position.
    pub conflict_digest: String,
    /// Digest of the bounded proof payload behind the position.
    pub proof_digest: String,
    /// Exact position identity admitted.
    pub position: PositionId,
    /// Exact position revision admitted.
    pub position_revision: PositionRevision,
    /// Canonical digest of the envelope shape, excluding this field.
    pub digest: String,
}
/// Missing-invariant role (no canonical owner covers invariant prose).
pub struct ChallengeInvariant(pub String);
/// Named constructor arguments for [`AdmittedReceipt::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct AdmittedReceiptParams {
    pub receipt_id: ReceiptId,
    pub payload_digest: String,
    pub owner: SourceId,
    pub revision: String,
    pub scope: String,
    pub fence: StateFence,
    pub evidence_digest: String,
    pub coverage_digest: String,
    pub conflict_digest: String,
    pub proof_digest: String,
    pub position: PositionId,
    pub position_revision: PositionRevision,
}
impl AdmittedReceipt {
    pub fn new(params: AdmittedReceiptParams) -> Result<Self, ContractError> {
        let mut receipt = Self {
            receipt_id: params.receipt_id,
            payload_digest: params.payload_digest,
            owner: params.owner,
            revision: params.revision,
            scope: params.scope,
            fence: params.fence,
            evidence_digest: params.evidence_digest,
            coverage_digest: params.coverage_digest,
            conflict_digest: params.conflict_digest,
            proof_digest: params.proof_digest,
            position: params.position,
            position_revision: params.position_revision,
            digest: String::new(),
        };
        receipt.validate_shape()?;
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.receipt_id,
            &self.payload_digest,
            &self.owner,
            &self.revision,
            &self.scope,
            &self.fence,
            &self.evidence_digest,
            &self.coverage_digest,
            &self.conflict_digest,
            &self.proof_digest,
            &self.position,
            &self.position_revision,
        ))
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_digest(&self.payload_digest, "admitted.payload_digest")?;
        validate_bounded_text(&self.revision, "admitted.revision", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "admitted.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "admitted.fence",
            })?;
        validate_digest(&self.evidence_digest, "admitted.evidence_digest")?;
        validate_digest(&self.coverage_digest, "admitted.coverage_digest")?;
        validate_digest(&self.conflict_digest, "admitted.conflict_digest")?;
        validate_digest(&self.proof_digest, "admitted.proof_digest")?;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "admitted.digest")
    }
    /// Returns the exact challenge for external existence; the store read belongs to a future work unit.
    pub fn existence_challenge(&self) -> Result<ContractChallenge, ContractError> {
        ContractChallenge::new(
            "admitted.existence",
            self.owner.clone(),
            "admission-store receipt read (no I/O in this crate)",
            ChallengeInvariant("external receipt existence".to_owned()),
            "future admission-owner PR",
        )
    }
}

/// Challenge for a sub-item needing outside-owner I/O; existence is challenged, never claimed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContractChallenge {
    /// Sub-item whose closure is challenged.
    pub sub_item: String,
    /// Owner that must attest the sub-item.
    pub missing_owner: String,
    /// Read API that would prove the sub-item; none is invoked here.
    pub missing_api: String,
    /// Invariant no local check can establish.
    pub missing_invariant: String,
    /// Future work unit or PR that will close the sub-item.
    pub future_work: String,
}
impl ContractChallenge {
    pub fn new(
        sub_item: impl Into<String>,
        missing_owner: SourceId,
        missing_api: impl Into<String>,
        missing_invariant: ChallengeInvariant,
        future_work: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let challenge = Self {
            sub_item: sub_item.into(),
            missing_owner: missing_owner.into_string(),
            missing_api: missing_api.into(),
            missing_invariant: missing_invariant.0,
            future_work: future_work.into(),
        };
        challenge.validate()?;
        Ok(challenge)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.sub_item, "challenge.sub_item", MAX_SHORT_TEXT)?;
        let field = "challenge.missing_owner";
        validate_bounded_text(&self.missing_owner, field, MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.missing_api, "challenge.missing_api", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            &self.missing_invariant,
            "challenge.missing_invariant",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.future_work, "challenge.future_work", MAX_SHORT_TEXT)
    }
}

/// Owner-neutral rendering of the donor position algebra, for record
/// compatibility: the six donor states are preserved exactly (donor
/// `resolve` into them is not carried).
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

/// Currentness of the admitted position under its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Currentness {
    /// The owner holds this position as current.
    Current,
    /// The owner superseded this position; links say by what.
    Superseded,
}

/// A read view of an externally admitted epistemic position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "CurrentEpistemicPositionWire")]
pub struct CurrentEpistemicPosition {
    /// Marker binding this document to the admitted-view decoding.
    pub view_kind: AdmittedKind,
    /// Typed envelope this view was read from, bound by value: the view
    /// digest covers the envelope digest, so an arbitrary receipt id or
    /// digest never substitutes for the envelope.
    pub admission: AdmittedReceipt,
    /// Currentness of the position under its owner.
    pub currentness: Currentness,
    /// Supersession links; required exactly when superseded.
    pub supersession: BTreeSet<ArtifactId>,
    /// Governed claim identity of the admitted position.
    pub claim: ClaimId,
    /// Canonical digest of the view shape, excluding this field.
    pub digest: String,
}

/// Previous name of [`CurrentEpistemicPosition`]: the same type, the same
/// serde, the same wire bytes. New code uses the canonical name; this alias
/// exists only so existing readers keep compiling while they migrate.
pub type CurrentEpistemicPositionView = CurrentEpistemicPosition;
/// Checked wire mirror of [`CurrentEpistemicPosition`]: deserialization validates via `new`.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct CurrentEpistemicPositionWire {
    view_kind: AdmittedKind,
    admission: AdmittedReceipt,
    currentness: Currentness,
    supersession: BTreeSet<ArtifactId>,
    claim: ClaimId,
    digest: String,
}
impl TryFrom<CurrentEpistemicPositionWire> for CurrentEpistemicPosition {
    type Error = ContractError;
    fn try_from(w: CurrentEpistemicPositionWire) -> Result<Self, ContractError> {
        if w.view_kind != AdmittedKind::CurrentEpistemicPosition {
            return Err(ContractError::ImpossibleCombination {
                field: "admitted.view_kind",
            });
        }
        let view = Self::new(w.admission, w.currentness, w.supersession, w.claim)?;
        check_frozen(&w.digest, &view.digest, "admitted.digest")?;
        Ok(view)
    }
}
impl CurrentEpistemicPosition {
    pub fn new(
        admission: AdmittedReceipt,
        currentness: Currentness,
        supersession: BTreeSet<ArtifactId>,
        claim: ClaimId,
    ) -> Result<Self, ContractError> {
        let mut view = Self {
            view_kind: AdmittedKind::CurrentEpistemicPosition,
            admission,
            currentness,
            supersession,
            claim,
            digest: String::new(),
        };
        view.validate_shape()?;
        view.digest = view.compute_digest()?;
        Ok(view)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.view_kind,
            &self.admission,
            &self.currentness,
            &self.supersession,
            &self.claim,
        ))
    }
    /// Returns the exact position identity and revision this view reads.
    pub fn position_identity(&self) -> (&PositionId, PositionRevision) {
        (&self.admission.position, self.admission.position_revision)
    }
    /// Returns the admission envelope digest this view proves; nothing beyond it.
    pub fn receipt_identity(&self) -> &str {
        self.admission.digest.as_str()
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.view_kind != AdmittedKind::CurrentEpistemicPosition {
            return Err(ContractError::ImpossibleCombination {
                field: "admitted.view_kind",
            });
        }
        self.admission.validate()?;
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
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "admitted.digest")
    }
}
