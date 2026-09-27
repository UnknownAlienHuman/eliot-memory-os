//! Governor-owned promotion-boundary evaluation for one committed learning
//! record (CC-007, #45).
//!
//! The learning-closure edge ([`crate::learning_closure`]) commits a durable
//! candidate record and reports whether it may influence a subsequent attempt.
//! That judgement is a *promotion* judgement, and the closure is the production
//! seam where the candidate-only promotion boundary belongs: the Governor reads
//! the owner-published [`PromotionBoundaryCandidate`] together with the
//! attribution and experiment lineage whose digests it consumed, validates the
//! whole boundary in one fence, and records a typed outcome beside the delivery
//! verdict.
//!
//! Nothing here promotes anything. The Governor is the decision owner, so it
//! evaluates and withholds; the behavioural effect still requires the existing
//! [`AdmissionReceipt`] delivery gate. The promotion gate therefore adds an
//! independent evaluation beside the existing one: a record whose boundary does
//! not validate is withheld with the exact contract cause, and an absent
//! boundary is an honest [`PromotionRefusal::MissingBoundary`] rather than a
//! pass.
//!
//! # What the gate proves
//!
//! The two proofs below are what [`evaluate_promotion`] enforces when an owner
//! publishes a boundary ([`PromotionBoundaryInput::Published`]). The production
//! closure seam currently publishes none and therefore records
//! [`PromotionRefusal::MissingBoundary`]; these are the invariants that
//! evaluation enforces, not a claim that a boundary is published today.
//!
//! - **Dimensioned evaluation, never one scalar** (A2). [`evaluate_promotion`]
//!   runs
//!   [`PromotionBoundaryCandidate::validate_against_attribution_and_experiment`].
//!   Its promotion half is [`PromotionBoundaryCandidate::validate`] → the
//!   dimension check: the boundary must carry at least two independent
//!   [`DimensionAssessment`] values, the delayed-harm dimension
//!   (`AssessmentDimension::Harm`, retained independently of benefit) must be
//!   present, every dimension must keep its own evidence, owner receipt and
//!   declared denominator, and the claimed `CausalCeiling` may not exceed the
//!   weakest dimension's. A single scalar score cannot satisfy any of that, so a
//!   scalar boundary is refused with
//!   [`LearningContractError::IncompleteCoverage`]. The same call re-validates
//!   the attribution's confounder accounting and the experiment's harm plus
//!   baseline-control dimensions in the same fence, so the counterfactual and
//!   confounder side of A2 is enforced here too and not only on the boundary's
//!   own dimension list.
//! - **Rollback preserves evidence and history** (A3). A rollback is
//!   [`rollback_promotion`], which delegates to
//!   [`PromotionBoundaryCandidate::invalidate`]: the invalidation identity is
//!   *appended* to the retained `invalidates` history and the record is resealed
//!   under its new canonical digest. Nothing is removed, so the evaluation
//!   dimensions, their evidence and owner receipts, the rollout boundary, the
//!   canary requirement and the invalidation conditions all survive the rollback
//!   and stay auditable. `HistoryRetention::DeleteOnRollback` is already
//!   rejected by `validate`, so a boundary that would delete history never
//!   reaches this gate.
//!
//! # Boundary
//!
//! Every input is a value its owner already published; this module constructs
//! no identity, digest, dimension or receipt of its own. It performs no clock
//! read, no I/O and no live query, and it holds no authority beyond the verdict
//! it returns. The durable record participates only because a promotion
//! boundary adjudicates a committed record; it is validated with its own
//! [`StoredLearningDelta::validate`] and contributes no identity the boundary is
//! compared against, because the contracts family and the durable-delta family
//! compute different digests over different records.

use eliot_contracts::ArtifactId;
use eliot_learning_contracts::{
    DimensionAssessment, HistoryRetention, ImprovementExperimentCandidate, LearningContractError,
    PromotionBoundaryCandidate, UseAttributionCandidate,
};
use eliot_learning_delta::{
    AdmissionReceipt, DeliveryRefusal, LearningDeltaError, StoredLearningDelta,
};
use thiserror::Error;

use crate::learning_delta_integration::delta_delivery_refusal;

/// Exact owner evidence presented to one promotion-boundary evaluation.
///
/// Every value is published by its owner and passed through unchanged. The
/// Governor composes them; it never fills one in.
pub struct PromotionEvaluationInput<'a> {
    /// Durable record the learning-closure edge committed for this attempt.
    pub stored: &'a StoredLearningDelta,
    /// Attributed use lineage the experiment consumed.
    pub attribution: &'a UseAttributionCandidate,
    /// Governed experiment the boundary was derived from.
    pub experiment: &'a ImprovementExperimentCandidate,
    /// Candidate-only promotion boundary under review.
    pub promotion: &'a PromotionBoundaryCandidate,
    /// External Governor receipt presented for delivery of `stored`, if any.
    ///
    /// The delivery gate itself is unchanged and still decides delivery; the
    /// promotion evaluation records the receipt it was evaluated alongside so a
    /// consumer sees both verdicts without a second gate being implied.
    pub admission: Option<&'a AdmissionReceipt>,
    /// Invalidation identities the owner recorded for this boundary.
    ///
    /// The Governor applies each one to a sealed copy of the boundary through
    /// [`PromotionBoundaryCandidate::invalidate`], which appends the identity to
    /// the retained history and reseals the record. This is the A3 rollback
    /// path in production: an invalidation never deletes the evaluation
    /// dimensions, their evidence, or the rollout boundary, and the re-validation
    /// afterwards refuses a boundary that would have become unvalidatable.
    pub invalidations: &'a [ArtifactId],
}

/// The owner-published promotion boundary presented to one closure.
///
/// The presented parts are one unit: a `PromotionBoundaryCandidate` is only
/// meaningful together with the attribution and experiment whose canonical
/// digests it consumed, and
/// [`PromotionBoundaryCandidate::validate_against_attribution_and_experiment`]
/// refuses a boundary separated from its lineage. Presenting them as a single
/// value makes an incomplete presentation unrepresentable rather than
/// something the closure has to check for.
#[derive(Clone, Copy, Debug)]
pub enum PromotionBoundaryInput<'a> {
    /// The owner published a boundary and its lineage.
    Published {
        /// Candidate-only promotion boundary under review.
        promotion: &'a PromotionBoundaryCandidate,
        /// Attributed use lineage the boundary's digests were computed from.
        attribution: &'a UseAttributionCandidate,
        /// Governed experiment the boundary was derived from.
        experiment: &'a ImprovementExperimentCandidate,
        /// Invalidation identities the owner recorded for this boundary.
        ///
        /// Each is applied to a sealed copy through
        /// [`PromotionBoundaryCandidate::invalidate`], which appends to the
        /// retained history and reseals the record instead of removing anything.
        invalidations: &'a [ArtifactId],
    },
    /// No owner publishes a boundary at this seam yet.
    Absent,
}

impl PromotionBoundaryInput<'_> {
    /// The no-boundary presentation, for a seam where no owner publishes one.
    #[must_use]
    pub const fn absent() -> Self {
        Self::Absent
    }

    /// Evaluate this presentation against the record the closure committed.
    ///
    /// A withheld boundary is a verdict, not a failure of the durable edge, so
    /// this returns an outcome for every input: an absent boundary and a refused
    /// boundary both yield [`LearningPromotionOutcome::Withheld`] carrying their
    /// exact typed reason, and the committed record stays candidate-only. The
    /// [`Result`]-returning [`evaluate_promotion`] is available to a caller that
    /// needs to treat a refusal as a hard failure instead.
    pub fn evaluate(
        self,
        stored: &StoredLearningDelta,
        admission: Option<&AdmissionReceipt>,
    ) -> LearningPromotionOutcome {
        match self {
            Self::Published {
                promotion,
                attribution,
                experiment,
                invalidations,
            } => match evaluate_promotion(&PromotionEvaluationInput {
                stored,
                attribution,
                experiment,
                promotion,
                admission,
                invalidations,
            }) {
                Ok(outcome) => outcome,
                Err(error) => LearningPromotionOutcome::Withheld {
                    reason: error.into_reason(),
                },
            },
            Self::Absent => match stored.validate() {
                Ok(()) => LearningPromotionOutcome::Withheld {
                    reason: PromotionRefusal::MissingBoundary,
                },
                Err(error) => LearningPromotionOutcome::Withheld {
                    reason: PromotionRefusal::Record(error),
                },
            },
        }
    }
}

/// Typed refusals of the promotion boundary; every variant names one cause.
///
/// The variants keep the two existing refusal vocabularies this gate composes
/// distinct, so a consumer that records the outcome never has to collapse
/// "invalid boundary" and "the durable record did not validate" into one
/// indistinguishable answer.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PromotionRefusal {
    /// The owner published no promotion boundary for this record, so the
    /// candidate is withheld rather than promoted by default.
    #[error("no promotion boundary was published for this record")]
    MissingBoundary,
    /// The boundary, its attribution, or its experiment failed contract
    /// validation. The contract error travels as the typed source so the exact
    /// field-level cause is never lost.
    #[error("promotion boundary refused: {0}")]
    Boundary(#[source] LearningContractError),
    /// The durable record the boundary adjudicates failed its own validation, so
    /// there is no committed record for the boundary to stand on.
    #[error("committed learning record refused: {0}")]
    Record(#[source] LearningDeltaError),
}

/// Fail-closed errors of the promotion-boundary evaluation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LearningPromotionError {
    /// The boundary was refused; see [`PromotionRefusal`] for the exact cause.
    #[error(transparent)]
    Refused(#[from] PromotionRefusal),
}

impl LearningPromotionError {
    /// The typed refusal behind this error, for a caller that records a verdict
    /// instead of propagating a failure.
    #[must_use]
    pub const fn into_reason(self) -> PromotionRefusal {
        match self {
            Self::Refused(reason) => reason,
        }
    }
}

/// One admitted promotion-boundary evaluation and the receipt it produced.
///
/// The receipt records the exact evidence that was evaluated. It is a
/// Governor-issued *evaluation* record, not a promotion: the boundary stays
/// candidate-only and `active_generation_evaluated` is always `false`, because
/// `PromotionMutationTarget::ActiveGeneration` is rejected by
/// [`PromotionBoundaryCandidate::validate`] and a boundary that reached the
/// gate can therefore only ever have been `CandidateOnly`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionAdmissionReceipt {
    /// Promotion-boundary identity that was evaluated.
    pub promotion_id: ArtifactId,
    /// Canonical digest of the evaluated boundary.
    pub promotion_digest: String,
    /// Durable record this evaluation was performed over.
    pub delta_artifact: ArtifactId,
    /// Canonical digest of that durable record.
    pub delta_digest: String,
    /// Delivery-gate verdict the boundary was evaluated alongside, when a
    /// receipt was presented. `None` records that no receipt was presented,
    /// which is the normal case at the closure seam.
    pub delivery: Option<Option<DeliveryRefusal>>,
    /// Invalidation identities already retained in the boundary's history.
    pub retained_invalidations: Vec<ArtifactId>,
    /// The dimensioned evaluation that survived the rollback unchanged.
    ///
    /// Recorded rather than asserted: an invalidation appends to the history and
    /// reseals, so this list is the same evidence the boundary carried before
    /// the rollback and a consumer can compare the two directly.
    pub retained_dimensions: Vec<DimensionAssessment>,
    /// The history-retention disposition that survived the rollback.
    ///
    /// Always `RetainAlways` on an admitted receipt, because
    /// `HistoryRetention::DeleteOnRollback` is rejected by the boundary's own
    /// validation. Naming it on the receipt is what proves a rollback could not
    /// have deleted evidence or history.
    pub retained_history_retention: HistoryRetention,
    /// Always `false`: an active generation can never be evaluated here.
    pub active_generation_evaluated: bool,
}

/// Typed outcome of one promotion-boundary evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LearningPromotionOutcome {
    /// The boundary validated in one fence. The record remains candidate-only
    /// and whether it may influence a subsequent attempt is still the existing
    /// delivery gate's separate decision.
    Admitted(Box<PromotionAdmissionReceipt>),
    /// The boundary was refused. The typed cause is retained so an absent
    /// boundary, an invalid one and a failed record stay distinct.
    Withheld {
        /// The exact reason the boundary was not admitted.
        reason: PromotionRefusal,
    },
}

/// Evaluate the promotion boundary presented for one committed learning record.
///
/// This is the production promotion gate on the learning-closure seam. It is a
/// pure function of the owner evidence in [`PromotionEvaluationInput`]: no
/// clock, no I/O, no live query, and no authority beyond the verdict it
/// returns. The evaluation order is fixed and fail-closed:
///
/// 1. the durable record must validate, so a boundary is never adjudicated
///    against a record that is not committed;
/// 2. the boundary, attribution and experiment must validate together in one
///    fence through
///    [`PromotionBoundaryCandidate::validate_against_attribution_and_experiment`]
///    — the dimensioned validation of A2, where the boundary's own delayed-harm
///    dimension requirement and the lineage's confounder, counterfactual and
///    baseline-control accounting are re-validated in the same fence;
/// 3. the presented delivery receipt is checked with the existing
///    [`DeliveryRefusal`] vocabulary and recorded on the receipt, so the two
///    verdicts stay visible side by side. A refused delivery does *not* fail the
///    boundary evaluation: the boundary is a promotion property, and whether the
///    record is delivered is the delivery gate's separate decision.
#[must_use = "the promotion verdict must be recorded, not discarded"]
pub fn evaluate_promotion(
    input: &PromotionEvaluationInput<'_>,
) -> Result<LearningPromotionOutcome, LearningPromotionError> {
    input.stored.validate().map_err(PromotionRefusal::Record)?;
    input
        .promotion
        .validate_against_attribution_and_experiment(input.attribution, input.experiment)
        .map_err(PromotionRefusal::Boundary)?;
    // The A3 rollback path runs here on every evaluation that carries
    // invalidation identities. `invalidate` appends to the retained history and
    // reseals, so the evidence and the rollout boundary survive; the
    // re-validation afterwards refuses a boundary whose history would not hold.
    let mut rolled_back = input.promotion.clone();
    for invalidation_id in input.invalidations {
        rollback_promotion(&mut rolled_back, invalidation_id)?;
    }
    Ok(LearningPromotionOutcome::Admitted(Box::new(
        PromotionAdmissionReceipt {
            promotion_id: rolled_back.promotion_id.clone(),
            promotion_digest: rolled_back.canonical_digest.clone(),
            delta_artifact: input.stored.delta_artifact.clone(),
            delta_digest: input.stored.delta_digest.clone(),
            delivery: input
                .admission
                .map(|receipt| delta_delivery_refusal(Some(receipt), input.stored)),
            retained_invalidations: rolled_back.invalidates.clone(),
            // The dimensions and rollout boundary survive every invalidation
            // above; the receipt records them so a consumer sees that the
            // rollback preserved the evidence rather than being told so.
            retained_dimensions: rolled_back.evaluation_dimensions.clone(),
            retained_history_retention: rolled_back.history_retention,
            // `PromotionMutationTarget::ActiveGeneration` is rejected by
            // `validate`, so a boundary that reached this point is candidate-only.
            active_generation_evaluated: false,
        },
    )))
}

/// Roll one promotion boundary back without deleting evidence or history.
///
/// A rollback is neither a deletion nor a rewrite: it appends the invalidation
/// identity to the boundary's retained `invalidates` history and reseals the
/// record, so the evaluation dimensions, their evidence and owner receipts, the
/// rollout boundary, its canary requirement and its invalidation conditions all
/// survive and stay auditable under the new canonical digest. The boundary is
/// re-validated before this returns, so a rollback that would leave the record
/// unvalidatable is refused instead of returned — which is what makes the
/// preserved history a proof rather than a claim about it.
pub fn rollback_promotion(
    promotion: &mut PromotionBoundaryCandidate,
    invalidation_id: &ArtifactId,
) -> Result<(), LearningPromotionError> {
    promotion
        .invalidate(invalidation_id)
        .map_err(PromotionRefusal::Boundary)?;
    promotion.validate().map_err(PromotionRefusal::Boundary)?;
    Ok(())
}
