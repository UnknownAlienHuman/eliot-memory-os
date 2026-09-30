//! Governor-owned durable learning-delta store and the non-blocking
//! learning-closure edge for one consequential attempt (issue #1863,
//! `docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`).
//!
//! Durable commit: [`CanonicalLearningDeltaStore`] follows the existing
//! [`crate::CanonicalSwarmPlanAttachmentStore`] precedent exactly — one
//! mutex-guarded canonical owner image plus a monotonic commit version behind
//! conditional commit. `load`/`compare_and_swap` implement the same
//! conditional-commit contract, a replacement is revalidated before it is
//! stored, lock poisoning fails closed, and a contended commit is reported as
//! [`CasOutcome::Contended`] rather than silently overwriting. The store
//! performs no I/O itself, and it is NOT the durable record: it is this
//! process's image of it.
//!
//! Durability is the daemon composing the version-to-head mapping
//! ([`CanonicalLearningDeltaStore::revision_expectations`],
//! [`CanonicalLearningDeltaStore::ordering_expectations`]) into a real
//! `CanonicalWriteEnvelope`, and a violated head surfaces from the canonical
//! store as a store error that
//! [`CanonicalLearningDeltaStore::classify_store_error`] reports as
//! [`CasOutcome::Contended`]. There is no second writer, no raw SQL, and no
//! remote-database fallback.
//!
//! That image was previously the ONLY place a committed closure existed, so a
//! restart silently emptied it and every consumer of it — including a
//! repeated-verifier-failure marker, which is rare and therefore unrecoverable
//! once lost — could only ever answer for one process lifetime. Both halves of
//! the durable pair now exist: the daemon publishes each committed record through
//! [`crate::commit_learning_record`] at the closed
//! [`LearningRecordKind::Delta`] kind with the heads this store's own receipt
//! carries ([`crate::learning_delta_record_key`] names the record), and
//! [`observed_closure_from_durable_rows`] /
//! [`repeated_verifier_failure_from_durable_rows`] read the served rows back,
//! re-proving each one against its own bytes and the record's own `validate()`.
//!
//!
//! Boundary derivation: [`GovernorComposition::close_attempt_learning`] never
//! trusts a caller-named boundary. It reads the canonical verifier-execution
//! owner fact and the durable terminal job row, names the lifecycle activities
//! those owners actually recorded, and derives the boundary set through
//! [`eliot_learning_delta::derive_boundaries`], which applies the ordinary-read
//! exclusion to the recorded activity name. A row that crossed no consequential
//! boundary commits no record at all.
//!
//! Honest dispositions: the closure never manufactures a behavioral delta to
//! satisfy schema presence. A missing or failed canonical evidence binding
//! closes as `INVALID_EVIDENCE` and a non-conclusive observed outcome closes as
//! `INCONCLUSIVE`, and each of those is a durable disposition, because silence
//! is not a disposition (I12.24 line 291).
//!
//! Repeated verifier failure (issue #1867 W2/A1): a repeat is the one thing a
//! stored record could not previously express. `derive_boundaries` sees it — a
//! failed, physically repeated attempt derives
//! `LifecycleActivity::RepeatedFailureSignature` — but the record keeps only
//! `boundaries[0]`, so it was stamped `VerifierOutcome` and read back exactly
//! like a single run. This seam now also compares the durable terminal job row's
//! own attempt count, settled state and execution projection against the
//! canonical run's finished execution and `Fail` outcome, and records the
//! verifier that repeated as `repeated-verifier-failure:<verifier>` among the
//! record's own evidence references — built by
//! `eliot_learning_delta::repeated_verifier_failure_ref`, which sits beside the
//! reader on the record type, so this seam neither spells the vocabulary nor
//! reaches for the prefix. That handle is the I12.24 evaluator-verdict trigger
//! the daemon improvement intake reads through
//! `eliot_improvement::sourced_evidence_from_repeated_verifier_failure`. Both
//! sides of that comparison are records this seam did not author together, and
//! a repeat that cannot be proven records nothing.
//!
//! Non-blocking: this edge runs after the finish decision has committed, is
//! purely in-process against retained owner images, performs no transport, and
//! never gates or fails the finish ceremony (I12.24 line 293).
//!
//! Delivery gate: the closure consults
//! [`eliot_learning_delta::check_delivery_typed`] before it records whether
//! the stored record may influence a subsequent attempt, and the typed
//! [`DeliveryRefusal`] is what it records, so a stale or mismatched admission
//! receipt is refused and stays distinguishable from an absent one. The same
//! gate decides delivery in the *incoming* direction: the next materially
//! related attempt of the campaign is closed by the next
//! [`LearningClosureService::close_attempt`] call, and the prior record this
//! campaign committed is the one proposed behavioural change that could reach
//! it. [`prior_lineage_delivery`] runs that verdict before any retry relation
//! is built, so a prior proposal the Governor has not admitted is not
//! delivered to the subsequent attempt, while an honest close record — which
//! proposes no behaviour — stays referable as retry lineage.
//!
//! Promotion boundary: the closure also evaluates the candidate-only promotion
//! boundary through [`crate::learning_promotion`] on every committed record, so
//! the promotion verdict is produced by this production path rather than by
//! tests alone. The two verdicts are independent and both stay visible on the
//! receipt: neither gate decides for the other, and neither promotes anything.
//!
//! The current owner at this seam publishes no boundary, so the live caller
//! presents [`PromotionBoundaryInput::Absent`] and the committed record carries
//! [`PromotionRefusal::MissingBoundary`](crate::learning_promotion::PromotionRefusal::MissingBoundary).
//! That is the fail-closed outcome, and it is what the receipt states: the
//! promotion *verdict* runs on every committed record here, while the
//! boundary-content validation behind [`PromotionBoundaryInput::Published`] has
//! no production caller until an owner publishes a boundary.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard};

use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_coordination::CasOutcome;
use eliot_finish::FinishDecisionReceipt;
use eliot_instrument_api::{ExecutionStatus, VerificationOutcome};
use eliot_learning_contracts::{AgentAttemptId, CampaignId, OverlayId};
use eliot_learning_delta::{
    AdmissionReceipt, AttemptCloseDisposition, ConsequentialBoundary, DeliveryRefusal,
    LearningDeltaError, LifecycleActivity, RetryEquivalence, RetryEquivalenceBasis, RetryReason,
    StoredLearningDelta, StoredRetryRelation, derive_boundaries,
};
use eliot_store_api::{
    LearningRecordKind, OrderingHeadExpectation, OrderingScopeId, RevisionHeadExpectation,
    RevisionKey, StoreError,
};
use eliot_testd_core::{JobState as TestdJobState, TestdJob, TestdTerminalCompletionEvidence};
use serde_json::Value;
use thiserror::Error;

use crate::composition::{
    CanonicalVerifierExecutionFact, GovernorComposition, KernelGenerationPort,
};
use crate::learning_delta_integration::{StoredDeltaIdentity, delta_delivery_refusal};
use crate::learning_promotion::{LearningPromotionOutcome, PromotionBoundaryInput};

/// Revision dependency key addressing the canonical learning-delta image.
///
/// The daemon places this key in the envelope's `expected_revision_heads` with
/// the loaded version as the expected revision.
pub const LEARNING_DELTA_REVISION_KEY: &str = "governor.learning-delta.v1";

/// Ordering scope serializing canonical learning-delta commits.
///
/// The daemon places this scope in the envelope's `expected_ordering_heads`
/// with the loaded version as the expected sequence.
pub const LEARNING_DELTA_ORDERING_SCOPE: &str = "governor.learning-delta.v1";

/// Fail-closed errors from the Governor canonical learning-delta store.
///
/// The image is validated before any commit: a corrupt replacement is refused
/// rather than persisted. Lock poisoning fails closed for the same reason.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanonicalLearningDeltaStoreError {
    /// The store mutex is poisoned; no decision is granted on unknown state.
    #[error("learning delta store lock is poisoned")]
    Poisoned,
    /// The replacement image failed revalidation and was not stored.
    #[error("learning delta replacement image is invalid")]
    InvalidImage,
}

/// Typed failures of the learning-closure edge.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LearningClosureError {
    /// The canonical store refused the commit.
    #[error(transparent)]
    Store(#[from] CanonicalLearningDeltaStoreError),
    /// Another writer committed the learning image first, so this commit was
    /// not stored and the caller must reload.
    #[error("learning delta commit was contended")]
    Contended,
    /// A canonical owner value was absent, stale, or unusable.
    #[error("canonical learning owner is unavailable: {0}")]
    Canonical(String),
    /// The durable record failed shape validation.
    #[error(transparent)]
    Delta(#[from] LearningDeltaError),
}

/// Governor-owned production store for canonical learning-delta records.
///
/// This is one mutex-guarded canonical owner image plus a monotonic commit
/// version. It performs no I/O; the canonical-write binding is the
/// version-to-head mapping ([`Self::revision_expectations`],
/// [`Self::ordering_expectations`]) the daemon composes into a
/// `CanonicalWriteEnvelope`, with head violations classified by
/// [`Self::classify_store_error`].
#[derive(Debug, Default)]
pub struct CanonicalLearningDeltaStore {
    state: Mutex<LearningDeltaImage>,
}

#[derive(Clone, Debug, Default)]
struct LearningDeltaImage {
    records: Vec<StoredLearningDelta>,
    version: u64,
}

impl CanonicalLearningDeltaStore {
    /// Creates an empty Governor learning-delta store at the initial version.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of committed records in the canonical image.
    pub fn len(&self) -> Result<usize, CanonicalLearningDeltaStoreError> {
        Ok(self.lock()?.records.len())
    }

    /// Returns whether the committed image records nothing.
    pub fn is_empty(&self) -> Result<bool, CanonicalLearningDeltaStoreError> {
        Ok(self.len()? == 0)
    }

    /// Loads the committed image and its monotonic version.
    pub fn load(
        &self,
    ) -> Result<(Vec<StoredLearningDelta>, u64), CanonicalLearningDeltaStoreError> {
        let state = self.lock()?;
        Ok((state.records.clone(), state.version))
    }

    /// The most recently committed record of one campaign, if any.
    ///
    /// Campaign identity is the durable unit a closure commits under, so the
    /// record this returns is the prior attempt of the same campaign and never
    /// a lookup by an unrelated key.
    pub fn prior_in_campaign(
        &self,
        campaign: &CampaignId,
    ) -> Result<Option<StoredLearningDelta>, CanonicalLearningDeltaStoreError> {
        let state = self.lock()?;
        Ok(state
            .records
            .iter()
            .rev()
            .find(|record| record.campaign_id == *campaign)
            .cloned())
    }

    /// Commits one validated replacement image if the version still matches.
    ///
    /// The replacement is revalidated before any stored state is touched, so a
    /// corrupt image is refused rather than persisted. A version that moved
    /// yields [`CasOutcome::Contended`] and the caller reloads; nothing is
    /// reported as committed before the image actually replaced the old one.
    pub fn compare_and_swap(
        &self,
        expected: u64,
        replacement: &[StoredLearningDelta],
    ) -> Result<CasOutcome, CanonicalLearningDeltaStoreError> {
        for record in replacement {
            record
                .validate()
                .map_err(|_| CanonicalLearningDeltaStoreError::InvalidImage)?;
        }
        let mut state = self.lock()?;
        if expected != state.version {
            return Ok(CasOutcome::Contended);
        }
        state.records = replacement.to_vec();
        state.version = state.version.saturating_add(1);
        Ok(CasOutcome::Committed)
    }

    /// Maps one loaded version onto the envelope's expected revision head.
    ///
    /// The returned expectation is suitable only for an existing committed
    /// learning-delta image; genesis must instead be represented by a canonical
    /// create-if-absent expectation in the durable canonical-write path.
    pub fn revision_expectations(
        version: u64,
        fence: &StateFence,
    ) -> Result<Vec<RevisionHeadExpectation>, StoreError> {
        if version == 0 {
            return Ok(Vec::new());
        }
        Ok(vec![RevisionHeadExpectation {
            key: RevisionKey::new(LEARNING_DELTA_REVISION_KEY)?,
            expected_revision: version,
            state_fence: fence.clone(),
        }])
    }

    /// Maps one loaded version onto the envelope's expected ordering head.
    ///
    /// The returned expectation is suitable only for an existing committed
    /// learning-delta image; genesis must instead be represented by a canonical
    /// create-if-absent expectation in the durable canonical-write path.
    pub fn ordering_expectations(
        version: u64,
        fence: &StateFence,
    ) -> Result<Vec<OrderingHeadExpectation>, StoreError> {
        if version == 0 {
            return Ok(Vec::new());
        }
        Ok(vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(LEARNING_DELTA_ORDERING_SCOPE)?,
            expected_sequence: version,
            state_fence: fence.clone(),
        }])
    }

    /// Classifies a canonical-write failure at the learning-delta head
    /// boundary.
    ///
    /// A violated revision-head or ordering-head expectation means another
    /// writer committed first, so the durable loop must reload and retry:
    /// [`CasOutcome::Contended`]. Any other store failure is not contention and
    /// the caller propagates it instead.
    #[must_use]
    pub const fn classify_store_error(error: &StoreError) -> Option<CasOutcome> {
        match error {
            StoreError::RevisionConflict | StoreError::OrderingConflict => {
                Some(CasOutcome::Contended)
            }
            _ => None,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, LearningDeltaImage>, CanonicalLearningDeltaStoreError> {
        self.state
            .lock()
            .map_err(|_| CanonicalLearningDeltaStoreError::Poisoned)
    }
}

/// Commit the closure record through the single canonical store.
///
/// Split out of [`LearningClosureService::close_attempt`] so the durable commit
/// is one named, testable step: a new record is validated and pushed onto the
/// image the store last committed, and the conditional commit re-checks the
/// version it was derived from. A version that moved returns
/// [`LearningClosureError::Contended`] with nothing stored, so no second writer
/// can silently interleave a half-built image.
fn commit_closure(
    store: &CanonicalLearningDeltaStore,
    record: StoredLearningDelta,
) -> Result<u64, LearningClosureError> {
    let (mut records, version) = store.load()?;
    records.push(record);
    match store.compare_and_swap(version, &records)? {
        CasOutcome::Contended => Err(LearningClosureError::Contended),
        CasOutcome::Committed => Ok(version.saturating_add(1)),
    }
}

/// One durable learning-closure commit and its delivery verdict.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningClosureReceipt {
    /// Durable canonical record this closure committed.
    pub record: StoredLearningDelta,
    /// Monotonic store version after the commit.
    pub version: u64,
    /// Boundaries derived from the recorded owner activities.
    pub boundaries: Vec<ConsequentialBoundary>,
    /// Whether the record may influence a subsequent attempt. `false` unless
    /// the delivery gate accepted an admission receipt bound to this exact
    /// artifact identity and digest.
    pub delivered: bool,
    /// The typed gate refusal, retained so an absent, malformed, and mismatched
    /// receipt stay distinguishable.
    pub delivery_refusal: Option<DeliveryRefusal>,
    /// Delivery verdict for the prior attempt's proposed next-behaviour
    /// change, as the current attempt saw it.
    ///
    /// `Some(reason)` records that the prior attempt of this campaign proposed
    /// a behavioural change the Governor has not admitted, so the record this
    /// closure committed carries no retry relation to it: the proposal was not
    /// delivered to this attempt. `None` means either that no prior record
    /// exists, that it proposed no behavioural change, or that the Governor
    /// admitted it.
    pub prior_delivery: Option<DeliveryRefusal>,
    /// Compare-and-swap heads the daemon composes into the canonical envelope
    /// that carries this commit across process restarts.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Ordering head expectation for the same commit.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    /// Promotion-boundary evaluation for the record this closure committed.
    ///
    /// The closure is the production seam where a candidate is judged, so the
    /// candidate-only promotion boundary is evaluated here beside the delivery
    /// verdict, and both verdicts stay separately visible. `Withheld` with
    /// [`PromotionRefusal::MissingBoundary`](crate::learning_promotion::PromotionRefusal::MissingBoundary)
    /// is the honest current outcome: no owner publishes a promotion boundary
    /// at this seam yet, and an absent boundary is recorded as absent rather
    /// than treated as admissible.
    pub promotion: LearningPromotionOutcome,
}

/// Typed outcome of one learning-closure attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LearningClosureOutcome {
    /// A durable record was committed for a derived consequential boundary.
    Committed(Box<LearningClosureReceipt>),
    /// The attempt crossed no consequential boundary, so no record exists.
    /// This is a recorded observation, never a silent loss.
    NonConsequential {
        /// The typed reason the boundary was refused.
        reason: LearningDeltaError,
    },
}

/// Owner-supplied identity fields the closure binds into a stored record.
///
/// Every field is an owner value read at the finish ceremony; none is
/// synthesized. Campaign identity is the canonical task identity, which is the
/// durable work unit the finish owner itself commits under, and the overlay
/// identity is the canonical plan's task-local work scope — the only
/// campaign-local executable state binding the finish owner actually holds. No
/// separate campaign or overlay artifact owner exists at this seam, and none is
/// invented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureIdentityInput {
    /// Canonical task identity; the durable campaign key for this closure.
    pub task_id: String,
    /// Durable job identity the boundary was observed on.
    pub job_id: String,
    /// Physical execution attempt ordinal the durable job recorded.
    pub attempts: u32,
    /// Actor identity that executed the attempt.
    pub actor_id: String,
    /// Route identity that selected the work.
    pub route_id: String,
    /// Campaign-local executable state binding the canonical plan carries.
    pub overlay_id: OverlayId,
    /// Canonical fingerprint of the strategy the attempt applied.
    pub strategy_fingerprint: String,
    /// State fence the attempt executed under.
    pub state_fence: StateFence,
    /// Raw trace, artifact, and evaluator references observed for the attempt.
    pub evidence_refs: Vec<ArtifactId>,
}

impl ClosureIdentityInput {
    /// Bind one derived boundary into a full stored-delta identity.
    fn into_identity(
        self,
        boundary: ConsequentialBoundary,
    ) -> Result<StoredDeltaIdentity, LearningClosureError> {
        let campaign_id =
            CampaignId::from_artifact(artifact_id(&self.task_id, "campaign task id")?);
        let attempt_id = AgentAttemptId::new(format!("{}:attempt:{}", self.job_id, self.attempts))
            .map_err(|error| {
                LearningClosureError::Canonical(format!("attempt identity is invalid: {error}"))
            })?;
        Ok(StoredDeltaIdentity {
            campaign_id,
            attempt_id,
            state_fence: self.state_fence,
            actor_id: self.actor_id,
            route_id: self.route_id,
            overlay_id: self.overlay_id,
            consequential_boundary: boundary,
            strategy_fingerprint: self.strategy_fingerprint,
            evidence_refs: self.evidence_refs,
        })
    }
}

/// The Governor-owned learning-closure owner.
///
/// It owns the single [`CanonicalLearningDeltaStore`] through which every
/// consequential attempt commits exactly one durable record, and it never
/// derives a behavioral effect of its own.
#[derive(Debug, Default)]
pub struct LearningClosureService {
    store: CanonicalLearningDeltaStore,
}

impl LearningClosureService {
    /// Creates an empty learning-closure owner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the single canonical learning-delta store.
    #[must_use]
    pub const fn store(&self) -> &CanonicalLearningDeltaStore {
        &self.store
    }

    /// Commits one durable learning record for one consequential attempt.
    ///
    /// `activity_name` is the activity/tool identity the durable owner row
    /// recorded and `observed` are the lifecycle activities the same row plus
    /// the canonical verifier-execution fact actually recorded; the boundary set
    /// is derived from those two, never asserted. `receipt` is the admission
    /// receipt presented for this exact record: there is no admission-receipt
    /// owner at the finish seam, so the live caller presents `None` and the
    /// gate refuses with [`DeliveryRefusal::MissingReceipt`], which is exactly
    /// the required "unadmitted means undelivered" outcome.
    ///
    /// `admissions` are the admission receipts the owner holds for this
    /// campaign's already-committed records. The prior record of the campaign
    /// is read from the committed image and passed through
    /// [`prior_lineage_delivery`] before any relation is built, so the
    /// current attempt inherits the prior proposal only when the Governor
    /// admitted it.
    ///
    /// Promotion boundary: the owner-published candidate-only promotion boundary
    /// for this record and its attribution/experiment lineage. The verdict is
    /// produced on every committed record here. A caller that holds no boundary
    /// presents [`PromotionBoundaryInput::absent`] and the evaluation records
    /// [`PromotionRefusal::MissingBoundary`](crate::learning_promotion::PromotionRefusal::MissingBoundary)
    /// instead of passing; the boundary-content validation behind
    /// [`PromotionBoundaryInput::Published`] runs only once an owner publishes a
    /// boundary.
    #[allow(
        clippy::too_many_arguments,
        reason = "one validated owner slot per closure input plus the typed outcome"
    )]
    pub fn close_attempt(
        &self,
        identity_input: ClosureIdentityInput,
        activity_name: &str,
        observed: &[LifecycleActivity],
        close: AttemptCloseDisposition,
        declared_retry_reason: Option<RetryReason>,
        evidence_refs: Vec<ArtifactId>,
        receipt: Option<&AdmissionReceipt>,
        admissions: &[AdmissionReceipt],
        promotion: PromotionBoundaryInput<'_>,
    ) -> Result<LearningClosureOutcome, LearningClosureError> {
        let boundaries = match derive_boundaries(activity_name, observed) {
            Ok(boundaries) if !boundaries.is_empty() => boundaries,
            Ok(_) => {
                return Ok(LearningClosureOutcome::NonConsequential {
                    reason: LearningDeltaError::NonConsequential,
                });
            }
            Err(reason) => return Ok(LearningClosureOutcome::NonConsequential { reason }),
        };
        // The first derived boundary in the closed nine-value order names the
        // record; the full set stays on the receipt so a closure that crossed
        // several boundaries keeps every one of them visible.
        let boundary = boundaries[0];
        let identity = identity_input.into_identity(boundary)?;
        // The prior attempt of this campaign is read from the committed image,
        // so the delivery gate judges the record the store actually holds
        // rather than a caller-supplied copy of it.
        let prior = self.store.prior_in_campaign(&identity.campaign_id)?;
        let prior_delivery = prior_lineage_delivery(prior.as_ref(), admissions);
        let retry_relation = if prior_delivery.is_some() {
            None
        } else {
            retry_relation_from_prior(
                prior.as_ref(),
                &identity.strategy_fingerprint,
                declared_retry_reason,
            )
        };
        let record = crate::learning_delta_integration::store_attempt_close(
            &identity,
            close,
            retry_relation,
            evidence_refs,
        )?;
        let delivery_refusal = delta_delivery_refusal(receipt, &record);
        let promotion_outcome = promotion.evaluate(&record, receipt);
        let version = commit_closure(&self.store, record.clone())?;
        Ok(LearningClosureOutcome::Committed(Box::new(
            LearningClosureReceipt {
                record,
                version,
                boundaries,
                delivered: delivery_refusal.is_none(),
                delivery_refusal,
                prior_delivery,
                // The heads a daemon canonical-write envelope binds to are the
                // version this commit moved *from*, because that is the head
                // the store image still carried when the record was derived.
                expected_revision_heads: CanonicalLearningDeltaStore::revision_expectations(
                    version.saturating_sub(1),
                    &identity.state_fence,
                )
                .map_err(|error| {
                    LearningClosureError::Canonical(format!("revision head: {error}"))
                })?,
                expected_ordering_heads: CanonicalLearningDeltaStore::ordering_expectations(
                    version.saturating_sub(1),
                    &identity.state_fence,
                )
                .map_err(|error| {
                    LearningClosureError::Canonical(format!("ordering head: {error}"))
                })?,
                promotion: promotion_outcome,
            },
        )))
    }
}

/// Builds a foundation artifact identity or fails closed with the field name.
fn artifact_id(value: &str, field: &str) -> Result<ArtifactId, LearningClosureError> {
    ArtifactId::new(value.to_owned())
        .map_err(|error| LearningClosureError::Canonical(format!("{field} is invalid: {error}")))
}

/// Lifecycle activities actually recorded for one terminal attempt.
///
/// Every arm reads a real owner value: the durable job row's lifecycle state
/// and physical-attempt ordinal, and the canonical verifier-execution fact's
/// finished run and completion certification. No arm is inferred from absence
/// and no arm is asserted by the caller.
fn observed_activities(
    job_state: TestdJobState,
    attempts: u32,
    verifier_finished: bool,
    certifies_completion: bool,
) -> Vec<LifecycleActivity> {
    let mut observed = Vec::new();
    if matches!(
        job_state,
        TestdJobState::Succeeded | TestdJobState::Failed | TestdJobState::Cancelled
    ) {
        observed.push(LifecycleActivity::AttemptSettled);
    }
    if verifier_finished {
        observed.push(LifecycleActivity::VerifierOutcome);
    }
    if certifies_completion {
        observed.push(LifecycleActivity::AcceptedArtifactOutcome);
    }
    if attempts > 1 {
        match job_state {
            TestdJobState::Failed => observed.push(LifecycleActivity::RepeatedFailureSignature),
            TestdJobState::Succeeded => observed.push(LifecycleActivity::SubstantialRecovery),
            _ => {}
        }
    }
    observed
}

/// Honest close disposition for one observed attempt.
///
/// The verdict is derived from the canonical evidence, never chosen to satisfy
/// schema presence:
///
/// - an absent canonical evidence binding (`fact` is `None`) is
///   `INVALID_EVIDENCE`;
/// - a verifier outcome that is not `Pass`/`Fail`, an execution that did not
///   settle, or an unfinished run is `INCONCLUSIVE`, because the evidence is
///   valid but does not determine an outcome;
/// - a conclusive run with `derived == false` is `INVALID_EVIDENCE`, because the
///   semantic derivation bundle is absent and a behavioral candidate may not be
///   manufactured from an absent binding;
/// - a conclusive run with `derived == true` is `NO_JUSTIFIED_CHANGE`, the
///   affirmative "the evidence justifies no behavioural change" close.
#[must_use]
pub fn close_disposition_for(
    fact: Option<&CanonicalVerifierExecutionFact>,
    derived: bool,
) -> AttemptCloseDisposition {
    let Some(fact) = fact else {
        return AttemptCloseDisposition::InvalidEvidence;
    };
    let run = &fact.verification_run;
    let execution_settled = matches!(
        run.execution,
        ExecutionStatus::Succeeded | ExecutionStatus::Failed
    );
    if run.finished_at.is_none()
        || !execution_settled
        || !matches!(
            run.outcome,
            VerificationOutcome::Pass | VerificationOutcome::Fail
        )
    {
        return AttemptCloseDisposition::Inconclusive;
    }
    if !derived {
        return AttemptCloseDisposition::InvalidEvidence;
    }
    AttemptCloseDisposition::NoJustifiedChange
}

/// Canonical strategy fingerprint of the strategy the attempt applied.
///
/// Derived from the canonical plan identity and the admitted invocation the
/// durable job row and the canonical verifier fact agree on. Two attempts with
/// equal fingerprints applied materially the same strategy; two attempts with
/// different fingerprints did not, and no prose or normalized plan is compared.
fn strategy_fingerprint(
    fact: &CanonicalVerifierExecutionFact,
) -> Result<String, LearningClosureError> {
    let binding = (
        fact.plan.plan_id.as_str(),
        fact.plan.plan_revision.as_str(),
        fact.plan.work_scope_id.as_str(),
        fact.invocation.instrument.as_str(),
        fact.invocation.profile.as_str(),
        fact.invocation.target.as_str(),
        fact.invocation.declared_scope.as_str(),
        fact.invocation.arguments.as_slice(),
        fact.input_artifact_bindings.as_slice(),
    );
    let bytes = canonical_json_bytes(&binding).map_err(|error| {
        LearningClosureError::Canonical(format!("strategy fingerprint encoding failed: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// The verifier identity of a REPEATED verifier failure, when the recorded
/// closure projections agree that one happened.
///
/// # Why this comparison and not an assertion
///
/// I12.24's second acceptance trigger is a "real repeated verifier failure", and
/// this seam is where a verifier actually runs and fails. Before this, the fact
/// that the failure REPEATED was derivable only inside
/// [`observed_activities`] and was then dropped: `close_attempt` keeps
/// `boundaries[0]`, and a repeated failure derives
/// `[VerifierOutcome, RepeatedFailureSignature, …]`, so the stored record was
/// stamped `VerifierOutcome` and read back exactly like a single passing run.
/// Nothing downstream could tell the two apart — not the disposition (a failed
/// run closes `INVALID_EVIDENCE` here, exactly as a passed one does, because
/// `derived` is false at this seam) and not the evidence refs.
///
/// # What the comparison IS, and what it is NOT
///
/// It was previously documented here as a comparison "between two records this
/// process did not author together" — the durable terminal job row and the
/// canonical verifier-execution fact — reading as corroboration between two
/// independent owners. **That was false and is withdrawn.** Both values descend
/// from ONE owner record:
///
/// - `CanonicalVerifierExecutionFact::from_testd(.., job, receipt, run)` embeds
///   that very `job`, and `run` is not an independent observation of it either:
///   `composition::evaluate_testd_verification_current(job, receipt, plan)`
///   DERIVES the run from `job.invocation` and the raw artifacts retained on
///   `job`'s own `VerificationReceipt`
///   (`crates/governor/eliot-governor/src/composition.rs:4874-4899`);
/// - `job.execution` is itself a copy: the terminal transition assigns
///   `job.execution = Some(execution)` from the same receipt it retains
///   (`crates/instrument/eliot-testd-core/src/lib.rs:4767`, and `receipt.validate(job)`
///   refuses a disagreement at `:4756-4758`).
///
/// So this is a CONSISTENCY CHECK across two projections of one owner record —
/// the row's recorded execution status against the execution status the
/// evaluator derives from the report bytes that same row carries
/// (`run.execution` is `report.execution_status()`,
/// `crates/instrument/eliot-verifier/src/lib.rs:830`) — and NOT corroboration
/// between two owners, and NOT two independent sources. It can catch a row whose
/// recorded status disagrees with the report its own retained bytes contain; it
/// cannot and does not attest that two independent authorities saw the failure.
///
/// `attempts` and `state` are weaker still: `CanonicalVerifierExecutionFact` has
/// no attempt-ordinal field at all, so "physically repeated" rests on the job row
/// alone and the verifier half of the check says only "this run failed".
///
/// A marker is minted only when the job row says the attempt was physically
/// repeated and failed, the row's own execution projection agrees that it
/// failed, and the canonical run finished with a failed execution and a failed
/// semantic outcome. `None` is the ordinary answer for a first-attempt failure,
/// a repeated PASS (`SubstantialRecovery`), an unsettled, blocked or cancelled
/// run, and any row whose execution disagrees with the run — a repeat nobody can
/// show from one owner's record, and `None` never becomes an invented marker.
///
/// The caller still cross-checks `fact.job_id` against the row and the finish
/// decision against the fact before calling this, so the two projections compared
/// here are already bound to the same attempt.
///
/// The verifier identity is returned OWNED rather than borrowed out of `fact`.
/// That matches this file's convention — `strategy_fingerprint` returns
/// `Result<String, _>` and `observed_evidence_refs` returns
/// `Result<Vec<ArtifactId>, _>`, both owned values derived from the same `fact`
/// — and it is what a durable stored marker should be: the result is formatted
/// into a retained evidence reference that outlives this function and is
/// committed to the canonical image, so it must not hold a borrow into a record
/// the caller only holds for the length of this closure.
fn repeated_verifier_failure_verifier(
    job: &TestdJob,
    fact: &CanonicalVerifierExecutionFact,
) -> Option<String> {
    if job.state != TestdJobState::Failed || job.attempts <= 1 {
        return None;
    }
    if job.execution != Some(ExecutionStatus::Failed) {
        return None;
    }
    let run = &fact.verification_run;
    if run.finished_at.is_none()
        || run.execution != ExecutionStatus::Failed
        || run.outcome != VerificationOutcome::Fail
    {
        return None;
    }
    Some(run.verifier.as_str().to_owned())
}

/// One committed closure record re-proved from the DURABLE learning-delta scope,
/// projected to the values a brief reads.
///
/// Owned, not borrowed: the caller of this crate's selectors is a binary that has
/// no `eliot-learning-delta` edge and therefore cannot name
/// [`StoredLearningDelta`]. The projection is what crosses that boundary, and
/// every field on it is the record's own committed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableObservedClosure {
    /// `actor_id` the record committed — the principal the safe boundary names.
    pub actor_id: String,
    /// `consequential_boundary` the record committed, in its own spelling.
    pub boundary_ref: String,
    /// Durable delta artifact handle the record committed.
    pub lineage_artifact: String,
    /// Canonical digest of exactly the bytes that handle names.
    pub lineage_digest: String,
    /// Attempt identity the record was derived from.
    pub attempt_id: String,
    /// Campaign that attempt belonged to.
    pub campaign_id: String,
    /// Route the closed attempt ran.
    pub route_id: String,
    /// How many evidence refs the record itself retained.
    pub evidence_ref_count: usize,
    /// The record's own predicate on whether it proposed a behaviour change.
    pub carries_behavioural_proposal: bool,
    /// Whether the record names a prior-attempt lineage to retry against.
    pub has_retry_lineage: bool,
}

/// One committed repeated verifier failure re-proved from the DURABLE
/// learning-delta scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableRepeatedVerifierFailure {
    /// Verifier identity the marker retained, read whole so an identity
    /// containing `:` survives intact.
    pub verifier_ref: String,
    /// Attempt whose durable record carries the marker.
    pub attempt_id: String,
    /// Campaign that attempt belonged to.
    pub campaign_id: String,
    /// Durable delta artifact identity of that same record.
    pub lineage_artifact: String,
    /// Canonical digest of exactly the bytes that handle names.
    pub lineage_digest: String,
    /// The raw trace, artifact and evaluator references that record retained.
    pub trace_refs: Vec<String>,
}

/// Re-proves every served learning-delta row and decodes it, in store order.
///
/// # Why this exists at all: the in-process image is not durable
///
/// [`CanonicalLearningDeltaStore`] is a `Mutex<LearningDeltaImage>` inside this
/// process. A daemon restart empties it, so every consumer that read the newest
/// closure — and every repeated-failure marker on it — was answering only for
/// this process's lifetime. The durable owner write that publishes these records
/// is [`crate::commit_learning_record`] at the closed
/// [`LearningRecordKind::Delta`] kind; this is the read side of that same pair,
/// and it is the reason the intake can still see a repeat after a restart.
///
/// # Completeness and integrity are the caller's, and neither is inferred here
///
/// The caller MUST hand an EXHAUSTIVE page set read at one fence; a partial set
/// is indistinguishable from an absent record, which is exactly the
/// "looks empty" failure this replaces. This function therefore re-proves each
/// row on its own content and refuses the whole set on any row it cannot prove:
///
/// 1. the `record_kind` is the closed `Delta` spelling;
/// 2. the presented `record_digest` is the SHA-256 of the exact `record_json`
///    bytes the store served under it — the digest IS the immutable revision
///    identity the store keys rows by;
/// 3. the document decodes to [`StoredLearningDelta`] and passes the record's
///    OWN `validate()`, which is what makes
///    [`StoredLearningDelta::repeated_verifier_failure_verifier`] total here: a
///    restored payload carrying the bare marker prefix is refused rather than
///    read back as a proven repeat;
/// 4. the row's `handle` is the `delta_artifact` the decoded record itself
///    carries, so a row cannot present one document under another's handle.
///
/// No row is skipped and none is defaulted past, so a set this function accepts
/// contains only records an owner committed.
fn restored_learning_deltas(rows: &[Value]) -> Result<Vec<StoredLearningDelta>, LearningClosureError> {
    let mut restored = Vec::with_capacity(rows.len());
    for row in rows {
        let handle = row.get("handle").and_then(Value::as_str).unwrap_or_default();
        let refused = |detail: String| {
            LearningClosureError::Canonical(format!(
                "durable learning-delta row {handle}: {detail}"
            ))
        };
        let record_kind = row
            .get("record_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("names no record kind".to_owned()))?;
        if record_kind != LearningRecordKind::Delta.as_str() {
            return Err(refused("is not a closed learning-delta record".to_owned()));
        }
        let record_json = row
            .get("record_json")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("names no record document".to_owned()))?;
        let record_digest = row
            .get("record_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| refused("names no record digest".to_owned()))?;
        if sha256_hex(record_json.as_bytes()) != record_digest {
            return Err(refused(
                "presented digest does not cover the served record bytes".to_owned(),
            ));
        }
        let record: StoredLearningDelta = serde_json::from_str(record_json)
            .map_err(|error| refused(format!("record document does not decode: {error}")))?;
        record
            .validate()
            .map_err(|error| refused(format!("record does not validate: {error}")))?;
        if record.delta_artifact.as_str() != handle {
            return Err(refused(
                "presents a handle its own record does not carry".to_owned(),
            ));
        }
        restored.push(record);
    }
    Ok(restored)
}

/// The observed closure the DURABLE learning-delta scope yields for this pass.
///
/// # Which record this selects, and why it is not called "the newest"
///
/// The learning owner keys rows by `(record_kind, handle, record_digest)` and
/// publishes no per-row commit sequence, so a range read carries a total order
/// that is NOT chronological. This returns the LAST row of that enumeration and
/// does not claim it is the most recent closure: no owner record on this path
/// records a commit time, and inventing one by parsing `attempt_id` would be a
/// second spelling of an identity the attempt owner issued. Every committed
/// closure is a real owner-observed consequential boundary, so any of them
/// discharges the brief's safe-boundary requirement; the choice is deterministic
/// and stated rather than presented as recency.
///
/// An empty scope is a refusal, never a synthesized record: no consequential
/// closure has ever been committed durably, and a brief must not reach an owner
/// as though a boundary had been observed when none was.
pub fn observed_closure_from_durable_rows(
    rows: &[Value],
) -> Result<DurableObservedClosure, LearningClosureError> {
    let restored = restored_learning_deltas(rows)?;
    let record = restored.last().ok_or_else(|| {
        LearningClosureError::Canonical(
            "the durable learning-delta scope holds no committed closure record".to_owned(),
        )
    })?;
    let (lineage_artifact, lineage_digest) = record.lineage_ref();
    Ok(DurableObservedClosure {
        actor_id: record.actor_id.clone(),
        boundary_ref: record.consequential_boundary.as_str().to_owned(),
        lineage_artifact: lineage_artifact.to_string(),
        lineage_digest: lineage_digest.to_owned(),
        attempt_id: record.attempt_id.as_str().to_owned(),
        campaign_id: record.campaign_id.as_str().to_owned(),
        route_id: record.route_id.clone(),
        evidence_ref_count: record.evidence_refs.len(),
        carries_behavioural_proposal: record.carries_behavioural_proposal(),
        has_retry_lineage: record.lineage_for_retry().is_some(),
    })
}

/// The repeated verifier failure the DURABLE learning-delta scope proves, when
/// one of its records proves one.
///
/// Scans the enumeration backwards and returns the LAST record that carries a
/// `repeated-verifier-failure:` marker, for the same reason
/// [`observed_closure_from_durable_rows`] does not claim recency: the store
/// publishes `(record_kind, handle, record_digest)` order, not commit order.
/// `None` is the ordinary answer — no committed record retains a marker, which
/// is a fact about the durable scope and not a substituted value. Every row was
/// re-proved first, so a marker read here names a verifier, came from a record
/// that passed its own validation, and rests on the consistency check documented
/// on [`repeated_verifier_failure_verifier`] — which is a check across two
/// projections of ONE owner record, not corroboration between two owners.
pub fn repeated_verifier_failure_from_durable_rows(
    rows: &[Value],
) -> Result<Option<DurableRepeatedVerifierFailure>, LearningClosureError> {
    let restored = restored_learning_deltas(rows)?;
    Ok(restored.iter().rev().find_map(|record| {
        let verifier_ref = record.repeated_verifier_failure_verifier()?;
        let (lineage_artifact, lineage_digest) = record.lineage_ref();
        Some(DurableRepeatedVerifierFailure {
            verifier_ref: verifier_ref.to_owned(),
            attempt_id: record.attempt_id.as_str().to_owned(),
            campaign_id: record.campaign_id.as_str().to_owned(),
            lineage_artifact: lineage_artifact.to_string(),
            lineage_digest: lineage_digest.to_owned(),
            trace_refs: record
                .evidence_refs
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        })
    }))
}

/// Exact raw trace, artifact, and evaluator references the canonical fact
/// observed for this attempt.
fn observed_evidence_refs(
    fact: &CanonicalVerifierExecutionFact,
) -> Result<Vec<ArtifactId>, LearningClosureError> {
    let mut refs: BTreeSet<ArtifactId> = fact.input_artifact_bindings.iter().cloned().collect();
    refs.extend(fact.verification_run.raw_evidence.iter().cloned());
    for raw in &fact.raw_artifact_bindings {
        refs.insert(artifact_id(&raw.handle, "verifier raw artifact handle")?);
    }
    refs.insert(artifact_id(
        &fact.verification_run.run_id.to_string(),
        "verifier run identity",
    )?);
    Ok(refs.into_iter().collect())
}

/// Builds the explicit retry relation to the prior attempt of the same campaign.
///
/// `prior` is the prior attempt's own committed record, so every field of the
/// relation is owner-derived. The equivalence verdict comes from comparing the
/// two canonical strategy fingerprints: equal fingerprints are an observed
/// equivalence, and a declared allowed unchanged-retry reason is required before
/// that observation may be recorded as `Equivalent`. Without a declared reason
/// the verdict is `Unknown`, so a materially equivalent retry is never recorded
/// as a controlled repeat by omission. Differing fingerprints are an explicit
/// `Distinct` relation carrying the prior fingerprint, the prior observable
/// references, and the prior evidence.
#[must_use]
pub fn retry_relation_from_prior(
    prior: Option<&StoredLearningDelta>,
    current_fingerprint: &str,
    declared_reason: Option<RetryReason>,
) -> Option<StoredRetryRelation> {
    let prior = prior?;
    let basis = if prior.strategy_fingerprint == current_fingerprint {
        RetryEquivalenceBasis::PriorFingerprintMatches
    } else {
        RetryEquivalenceBasis::PriorFingerprintDiffers
    };
    let (equivalence, unchanged_retry_reason) = match basis {
        RetryEquivalenceBasis::PriorFingerprintDiffers => (RetryEquivalence::Distinct, None),
        _ => match declared_reason {
            Some(reason) => (RetryEquivalence::Equivalent, Some(reason)),
            None => (RetryEquivalence::Unknown, None),
        },
    };
    Some(StoredRetryRelation {
        prior_attempt_id: prior.attempt_id.clone(),
        prior_delta_artifact: prior.delta_artifact.clone(),
        prior_delta_digest: prior.delta_digest.clone(),
        prior_fingerprint: prior.strategy_fingerprint.clone(),
        prior_observable_refs: prior.evidence_refs.clone(),
        prior_evidence: prior.retry_canonical_evidence(),
        basis,
        equivalence,
        unchanged_retry_reason,
    })
}

/// Delivery verdict for the prior attempt's proposal to the current attempt.
///
/// This is the W6/A4 decision on the one inheritance path the attempt
/// lifecycle actually has: the next materially related attempt of the same
/// campaign is closed by the next [`LearningClosureService::close_attempt`]
/// call, and the prior record this campaign committed is the only proposed
/// behavioural change that could reach it. The verdict is the existing
/// [`delta_delivery_refusal`] verdict — the crate's own
/// [`check_delivery_typed`](eliot_learning_delta::check_delivery_typed) gate —
/// applied to the exact prior artifact identity and digest, so a stale,
/// malformed or foreign receipt stays distinguishable from an absent one.
///
/// Only a record that carries a proposed next-behaviour change is gated
/// ([`StoredLearningDelta::carries_behavioural_proposal`]). An honest close
/// record (`NO_JUSTIFIED_CHANGE`, `INCONCLUSIVE`, `INVALID_EVIDENCE`) proposes
/// no behaviour, so it stays referable as retry lineage without admission —
/// the durable attempt record must not disappear just because no admission
/// receipt exists for it. A gated record that is refused yields `Some(refusal)`
/// and the current attempt then inherits no relation to it: an unadmitted
/// proposed behavioural change is not delivered to the subsequent attempt.
#[must_use]
pub fn prior_lineage_delivery(
    prior: Option<&StoredLearningDelta>,
    admissions: &[AdmissionReceipt],
) -> Option<DeliveryRefusal> {
    let record = prior?;
    if !record.carries_behavioural_proposal() {
        return None;
    }
    // Only a receipt issued for this exact delta identity is presented to the
    // gate; anything else is left for the gate to name as the refusal it is.
    let presented = admissions
        .iter()
        .find(|receipt| receipt.delta_id == record.delta_artifact);
    delta_delivery_refusal(presented, record)
}

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Runs the non-blocking learning-closure edge for one consequential
    /// attempt at the live finish ceremony.
    ///
    /// Every input is a real owner record: the durable terminal `TestD` row,
    /// the admitted request identity, the committed [`FinishDecisionReceipt`],
    /// and the canonical verifier-execution owner fact that the finish evidence
    /// leg itself published. Nothing is invented to fill a shape, the edge
    /// performs no transport, and its result is returned to the caller rather
    /// than propagated into the finish decision, so closure never blocks or
    /// fails the finish ceremony.
    ///
    /// `activity_name` is the activity/tool identity the durable job row
    /// recorded for the observed step. `receipt` is the admission receipt
    /// presented for the stored record: no admission-receipt owner issues one at
    /// this seam, so the live caller presents `None` and the durable receipt
    /// records the gate refusal, which is exactly the required "unadmitted means
    /// undelivered" outcome. `admissions` are the receipts the owner holds for
    /// this campaign's already-committed records; the prior proposal is delivered
    /// to this attempt only when one of them is admitted for it.
    ///
    /// `promotion` is the owner-published candidate-only promotion boundary for
    /// this attempt together with the attribution and experiment lineage whose
    /// digests it consumed. The promotion verdict is produced on every committed
    /// record here. A caller that holds no boundary presents
    /// [`PromotionBoundaryInput::absent`], and the committed receipt records the
    /// withheld verdict with its exact reason.
    #[allow(
        clippy::too_many_arguments,
        reason = "one validated owner slot per closure input plus the typed outcome"
    )]
    pub fn close_attempt_learning(
        &self,
        service: &LearningClosureService,
        evidence: &TestdTerminalCompletionEvidence,
        decision: &FinishDecisionReceipt,
        activity_name: &str,
        declared_retry_reason: Option<RetryReason>,
        receipt: Option<&AdmissionReceipt>,
        admissions: &[AdmissionReceipt],
        promotion: PromotionBoundaryInput<'_>,
    ) -> Result<LearningClosureOutcome, LearningClosureError> {
        let job = &evidence.job;
        let fence = evidence
            .request_identity
            .request
            .metadata
            .state_fence
            .clone();
        let fact = self
            .owners()
            .canonical
            .read_verifier_execution_fact(&fence)
            .map_err(|error| LearningClosureError::Canonical(error.to_string()))?;
        let admitted_task = evidence
            .request_identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(eliot_contracts::TaskId::as_str)
            .unwrap_or_default();
        if fact.job_id != job.job_id || fact.task_id != admitted_task || fact.state_fence != fence {
            return Err(LearningClosureError::Canonical(
                "canonical verifier fact does not bind the terminal owner row".to_owned(),
            ));
        }
        if decision.task_id != fact.task_id
            || decision.state_fence != fence
            || decision.attempt_id != *evidence.request_identity.idempotency_key
            || job.job_id != fact.receipt.job_id
        {
            return Err(LearningClosureError::Canonical(
                "finish decision does not bind the terminal owner row".to_owned(),
            ));
        }
        let fingerprint = strategy_fingerprint(&fact)?;
        // The raw trace/artifact/evaluator references the canonical fact
        // observed, plus the repeated-verifier-failure marker when the durable
        // job row and that fact together prove one (issue #1867 W2/A1). The
        // marker joins the same `BTreeSet` rather than being appended, so the
        // committed reference list stays canonically ordered and duplicate-free
        // exactly as `observed_evidence_refs` leaves it.
        let mut observed_refs: BTreeSet<ArtifactId> =
            observed_evidence_refs(&fact)?.into_iter().collect();
        if let Some(verifier) = repeated_verifier_failure_verifier(job, &fact) {
            observed_refs.insert(
                eliot_learning_delta::repeated_verifier_failure_ref(&verifier).map_err(
                    |error| {
                        LearningClosureError::Canonical(format!(
                            "repeated verifier failure marker is not a valid handle: {error}"
                        ))
                    },
                )?,
            );
        }
        let evidence_refs: Vec<ArtifactId> = observed_refs.into_iter().collect();
        let identity = ClosureIdentityInput {
            task_id: fact.task_id.clone(),
            job_id: job.job_id.clone(),
            attempts: job.attempts,
            // The durable process identity the Kernel bound to this attempt is
            // the actor that executed it, and the canonical plan identity is
            // the route that selected the work. Both are owner values, never
            // synthesized handles.
            actor_id: job.process.process_tree_id.clone(),
            route_id: format!("{}@{}", fact.plan.plan_id, fact.plan.plan_revision),
            overlay_id: OverlayId::from_artifact(artifact_id(
                &fact.plan.work_scope_id,
                "overlay work scope id",
            )?),
            strategy_fingerprint: fingerprint.clone(),
            state_fence: fence.clone(),
            evidence_refs: evidence_refs.clone(),
        };
        let observed = observed_activities(
            job.state,
            job.attempts,
            fact.verification_run.finished_at.is_some(),
            fact.certifies_completion(),
        );
        // `derived` is false here: no owner publishes the
        // `CampaignLearningStateView` / `AttemptEvidence` bundle the semantic
        // derivation needs at this seam, so the closure states that fact as
        // `INVALID_EVIDENCE` rather than inventing evidence to reach a
        // behavioural delta. A caller that does hold a complete bundle passes
        // `derived = true` and the same verdict ladder applies.
        let derived = false;
        service.close_attempt(
            identity,
            activity_name,
            &observed,
            close_disposition_for(Some(&fact), derived),
            declared_retry_reason,
            evidence_refs,
            receipt,
            admissions,
            promotion,
        )
    }
}
