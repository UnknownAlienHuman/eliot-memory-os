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
//! performs no I/O itself: cross-process durability comes from the daemon
//! wiring [`CanonicalLearningDeltaStore::revision_expectations`] and
//! [`CanonicalLearningDeltaStore::ordering_expectations`] into a real
//! `CanonicalWriteEnvelope`, and a violated head surfaces from the canonical
//! store as a store error that
//! [`CanonicalLearningDeltaStore::classify_store_error`] reports as
//! [`CasOutcome::Contended`]. There is no second writer, no raw SQL, and no
//! remote-database fallback.
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
//! Non-blocking: this edge runs after the finish decision has committed, is
//! purely in-process against retained owner images, performs no transport, and
//! never gates or fails the finish ceremony (I12.24 line 293).
//!
//! Delivery gate: the closure consults
//! [`eliot_learning_delta::check_delivery_typed`] before it records whether
//! the stored record may influence a subsequent attempt, and the typed
//! [`DeliveryRefusal`] is what it records, so a stale or mismatched admission
//! receipt is refused and stays distinguishable from an absent one.

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
    OrderingHeadExpectation, OrderingScopeId, RevisionHeadExpectation, RevisionKey, StoreError,
};
use eliot_testd_core::{JobState as TestdJobState, TestdTerminalCompletionEvidence};
use thiserror::Error;

use crate::composition::{
    CanonicalVerifierExecutionFact, GovernorComposition, KernelGenerationPort,
};
use crate::learning_delta_integration::{StoredDeltaIdentity, delta_delivery_refusal};

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
    /// Compare-and-swap heads the daemon composes into the canonical envelope
    /// that carries this commit across process restarts.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Ordering head expectation for the same commit.
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
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
        retry_relation: Option<StoredRetryRelation>,
        evidence_refs: Vec<ArtifactId>,
        receipt: Option<&AdmissionReceipt>,
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
        let record = crate::learning_delta_integration::store_attempt_close(
            &identity,
            close,
            retry_relation,
            evidence_refs,
        )?;
        let delivery_refusal = delta_delivery_refusal(receipt, &record);
        let version = commit_closure(&self.store, record.clone())?;
        Ok(LearningClosureOutcome::Committed(Box::new(
            LearningClosureReceipt {
                record,
                version,
                boundaries,
                delivered: delivery_refusal.is_none(),
                delivery_refusal,
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
    /// undelivered" outcome.
    pub fn close_attempt_learning(
        &self,
        service: &LearningClosureService,
        evidence: &TestdTerminalCompletionEvidence,
        decision: &FinishDecisionReceipt,
        activity_name: &str,
        declared_retry_reason: Option<RetryReason>,
        receipt: Option<&AdmissionReceipt>,
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
        let evidence_refs = observed_evidence_refs(&fact)?;
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
        let campaign =
            CampaignId::from_artifact(artifact_id(&identity.task_id, "campaign task id")?);
        let prior = service.store().prior_in_campaign(&campaign)?;
        let retry_relation =
            retry_relation_from_prior(prior.as_ref(), &fingerprint, declared_retry_reason);
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
            retry_relation,
            evidence_refs,
            receipt,
        )
    }
}
