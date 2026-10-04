//! Versioned end-of-activity maintenance assessment contract.
//!
//! This module describes evidence, an assessment outcome, and the deterministic
//! decision core. It does not read persistence owners, schedule a wake, or
//! perform shutdown.

use eliot_contracts::{
    ContractIdentity, ContractVersion, DecisionId, Receipt, RequestId, StateFence,
    contract_identity,
};
use eliot_runtime_contracts::{RuntimeLease, WakeIntent};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::MaintenanceFamily;

/// Stable identity of the end-of-activity assessment contract.
pub const END_OF_ACTIVITY_ASSESSMENT_CONTRACT_NAME: &str =
    "eliot.governor.maintenance.end_of_activity_assessment";

/// Current version of the end-of-activity assessment request and outcome.
pub const END_OF_ACTIVITY_ASSESSMENT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Returns the canonical contract identity for request/outcome versioning.
pub fn end_of_activity_assessment_contract_identity()
-> Result<ContractIdentity, EndOfActivityMaintenanceAssessmentValidationError> {
    contract_identity(
        END_OF_ACTIVITY_ASSESSMENT_CONTRACT_NAME,
        END_OF_ACTIVITY_ASSESSMENT_VERSION,
        &serde_json::json!({
            "request": "EndOfActivityMaintenanceAssessmentRequest",
            "outcome": "EndOfActivityMaintenanceAssessmentOutcome",
            "missing_source_data": "unknown",
        }),
    )
    .map_err(|_| EndOfActivityMaintenanceAssessmentValidationError::ContractIdentityInvalid)
}

/// A source gap retained with the scope and reason that could not be read.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSourceGap {
    /// Scope reference affected by the gap, when the source identified one.
    pub scope_ref: Option<String>,
    /// Source-provided reason that coverage is incomplete or unavailable.
    pub reason: String,
}

impl AssessmentSourceGap {
    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        if let Some(scope_ref) = &self.scope_ref {
            validate_text(scope_ref, "source_gap.scope_ref")?;
        }
        validate_text(&self.reason, "source_gap.reason")
    }
}

/// Whether a source set is complete, partially covered, or unknown.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentSourceCoverage {
    /// The source revision covers the declared scopes, including an explicit empty set.
    Complete,
    /// Some declared scopes are covered and every known gap is listed.
    Partial,
    /// The source data is unavailable; it is not interpreted as an empty set.
    Unknown,
}

/// Stable reference to one record included in a source snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentRecordReference {
    /// Existing owner-assigned record identity.
    pub reference: String,
}

/// Record shape used by a typed source snapshot.
pub trait AssessmentSourceRecord {
    /// Returns the existing owner-assigned record identity.
    fn reference(&self) -> &str;

    /// Validates the record identity and its typed fields.
    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError>;
}

impl AssessmentSourceRecord for AssessmentRecordReference {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.reference, "record.reference")
    }
}

/// Exact revision, fence, coverage and records returned by one persistence owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentSourceSnapshot<T> {
    /// Name of the persistence owner that supplied this source.
    pub persistence_owner: String,
    /// Exact source revision, absent only when the owner could not provide one.
    pub source_revision: Option<String>,
    /// Fence at which this source snapshot was read.
    pub state_fence: StateFence,
    /// Explicit coverage state; an empty record list alone never means complete.
    pub coverage: AssessmentSourceCoverage,
    /// Exact scope references covered by this source revision.
    pub covered_scope_refs: Vec<String>,
    /// Records returned from the declared coverage.
    pub records: Vec<T>,
    /// Unavailable or uncovered data, with explicit reasons.
    pub gaps: Vec<AssessmentSourceGap>,
}

impl<T: AssessmentSourceRecord> AssessmentSourceSnapshot<T> {
    /// Returns this source's coverage and retained-gap count for the decision
    /// relation. Read only after [`Self::validate`] has passed.
    fn fact(&self, field: &'static str) -> SourceCoverageFact {
        SourceCoverageFact {
            field,
            coverage: self.coverage,
            gaps: self.gaps.len(),
        }
    }

    /// Validates exact source identity, coverage and record references.
    pub fn validate(
        &self,
        expected_fence: &StateFence,
    ) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.persistence_owner, "source.persistence_owner")?;
        if let Some(revision) = &self.source_revision {
            validate_text(revision, "source.source_revision").map_err(|_| {
                EndOfActivityMaintenanceAssessmentValidationError::InvalidSourceRevision
            })?;
        }
        self.state_fence
            .validate()
            .map_err(|_| EndOfActivityMaintenanceAssessmentValidationError::InvalidFence)?;
        if &self.state_fence != expected_fence {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::FenceMismatch);
        }
        validate_unique_text(&self.covered_scope_refs, "source.covered_scope_refs")?;
        // "Complete" has to be complete over something. A `Complete` source
        // that declares no scope at all is coverage of nothing, which would
        // otherwise let a `no_action` decision rest on an empty read while
        // still claiming an adequate known coverage of due work.
        if self.coverage == AssessmentSourceCoverage::Complete && self.covered_scope_refs.is_empty()
        {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage);
        }

        let mut record_refs = Vec::with_capacity(self.records.len());
        for record in &self.records {
            record.validate()?;
            record_refs.push(record.reference().to_owned());
        }
        validate_unique_text(&record_refs, "source.records")?;
        for gap in &self.gaps {
            gap.validate()?;
        }

        match self.coverage {
            AssessmentSourceCoverage::Complete => {
                if self.source_revision.is_none() || !self.gaps.is_empty() {
                    return Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage);
                }
            }
            AssessmentSourceCoverage::Partial => {
                if self.source_revision.is_none() || self.gaps.is_empty() {
                    return Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage);
                }
            }
            AssessmentSourceCoverage::Unknown => {
                if !self.records.is_empty()
                    || !self.covered_scope_refs.is_empty()
                    || self.gaps.is_empty()
                {
                    return Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage);
                }
            }
        }
        Ok(())
    }
}

/// Activation and scope recorded for an observable-use interval.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationScopeReference {
    /// Existing activation identity from `HostStateJournal`.
    pub activation_ref: String,
    /// Exact governed scopes associated with that activation.
    pub scope_refs: Vec<String>,
}

impl AssessmentSourceRecord for ActivationScopeReference {
    fn reference(&self) -> &str {
        &self.activation_ref
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.activation_ref, "activation_scope.activation_ref")?;
        validate_unique_text(&self.scope_refs, "activation_scope.scope_refs")
    }
}

/// Closed session, attempt, job, or effect identity from its named owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedActivityReference {
    /// Existing owner-assigned identity of the closed activity.
    pub reference: String,
}

impl AssessmentSourceRecord for ClosedActivityReference {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.reference, "closed_activity.reference")
    }
}

/// Maintenance debt identity included in the assessment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceDebtReference {
    /// Existing debt record identity.
    pub reference: String,
    /// Maintenance family associated with the debt.
    pub family: MaintenanceFamily,
}

impl AssessmentSourceRecord for MaintenanceDebtReference {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.reference, "maintenance_debt.reference")
    }
}

/// Existing maintenance policy identity and its due family.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceDuePolicyReference {
    /// Existing owner-assigned policy identity.
    pub reference: String,
    /// Maintenance family governed by the policy.
    pub family: MaintenanceFamily,
}

impl AssessmentSourceRecord for MaintenanceDuePolicyReference {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.reference, "maintenance_due_policy.reference")
    }
}

/// Service-safe route and its existing admitted budget reference.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleServiceSafeRoute {
    /// Existing route identity.
    pub route_ref: String,
    /// Existing budget identity; the amount or quota remains owned elsewhere.
    pub budget_ref: String,
}

impl AssessmentSourceRecord for EligibleServiceSafeRoute {
    fn reference(&self) -> &str {
        &self.route_ref
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.route_ref, "eligible_route.route_ref")?;
        validate_text(&self.budget_ref, "eligible_route.budget_ref")
    }
}

/// Work reference that cannot run without an authenticated user session.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSessionRequiredWorkReference {
    /// Existing owner-assigned work identity.
    pub reference: String,
    /// Maintenance family associated with the work.
    pub family: MaintenanceFamily,
}

impl AssessmentSourceRecord for UserSessionRequiredWorkReference {
    fn reference(&self) -> &str {
        &self.reference
    }

    fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        validate_text(&self.reference, "user_session_required_work.reference")
    }
}

/// Versioned evidence request made before releasing the final observable-use lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndOfActivityMaintenanceAssessmentRequest {
    /// Content-addressed versioned contract identity.
    pub contract_identity: ContractIdentity,
    /// Existing request identity from the shared contract vocabulary.
    pub request_id: RequestId,
    /// Time the request's source observations were assembled, in Unix milliseconds.
    pub observed_at_ms: i64,
    /// Shared state fence for all assessment sources.
    pub source_fence: StateFence,
    /// Activation and exact scope set from `HostStateJournal`.
    pub activation_scope_set: AssessmentSourceSnapshot<ActivationScopeReference>,
    /// Closed session identities from their named persistence owner.
    pub closed_sessions: AssessmentSourceSnapshot<ClosedActivityReference>,
    /// Closed attempt identities from their named persistence owner.
    pub closed_attempts: AssessmentSourceSnapshot<ClosedActivityReference>,
    /// Closed durable job identities from their named persistence owner.
    pub closed_jobs: AssessmentSourceSnapshot<ClosedActivityReference>,
    /// Closed effect identities from their named persistence owner.
    pub closed_effects: AssessmentSourceSnapshot<ClosedActivityReference>,
    /// Pending observation identities from their named persistence owner.
    pub pending_observations: AssessmentSourceSnapshot<AssessmentRecordReference>,
    /// Pending feedback identities from their named persistence owner.
    pub pending_feedback: AssessmentSourceSnapshot<AssessmentRecordReference>,
    /// Pending projection identities from their named persistence owner.
    pub pending_projections: AssessmentSourceSnapshot<AssessmentRecordReference>,
    /// Pending receipt identities from their named persistence owner.
    pub pending_receipts: AssessmentSourceSnapshot<AssessmentRecordReference>,
    /// Maintenance debt by existing debt identity and family.
    pub maintenance_debt: AssessmentSourceSnapshot<MaintenanceDebtReference>,
    /// Due policy by existing policy identity and family.
    pub due_policies: AssessmentSourceSnapshot<MaintenanceDuePolicyReference>,
    /// Eligible service-safe route and existing budget references.
    pub eligible_service_safe_routes: AssessmentSourceSnapshot<EligibleServiceSafeRoute>,
    /// Work that requires an authenticated user session.
    pub user_session_required_work: AssessmentSourceSnapshot<UserSessionRequiredWorkReference>,
}

impl EndOfActivityMaintenanceAssessmentRequest {
    /// Validates request identity and every source's revision, fence and coverage.
    pub fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        self.contract_identity.validate().map_err(|_| {
            EndOfActivityMaintenanceAssessmentValidationError::ContractIdentityInvalid
        })?;
        if self.contract_identity != end_of_activity_assessment_contract_identity()? {
            return Err(
                EndOfActivityMaintenanceAssessmentValidationError::ContractIdentityMismatch,
            );
        }
        self.source_fence
            .validate()
            .map_err(|_| EndOfActivityMaintenanceAssessmentValidationError::InvalidFence)?;

        self.activation_scope_set.validate(&self.source_fence)?;
        self.closed_sessions.validate(&self.source_fence)?;
        self.closed_attempts.validate(&self.source_fence)?;
        self.closed_jobs.validate(&self.source_fence)?;
        self.closed_effects.validate(&self.source_fence)?;
        self.pending_observations.validate(&self.source_fence)?;
        self.pending_feedback.validate(&self.source_fence)?;
        self.pending_projections.validate(&self.source_fence)?;
        self.pending_receipts.validate(&self.source_fence)?;
        self.maintenance_debt.validate(&self.source_fence)?;
        self.due_policies.validate(&self.source_fence)?;
        self.eligible_service_safe_routes
            .validate(&self.source_fence)?;
        self.user_session_required_work.validate(&self.source_fence)
    }

    /// Returns every declared source's coverage and retained-gap count.
    ///
    /// The decision relation is checked against what the request actually
    /// read, never against a caller's claim about it. A source that is
    /// `Partial` or `Unknown`, or that carries any retained gap, is a real
    /// limiting condition and is never treated as a known-empty set.
    fn coverage_facts(&self) -> Vec<SourceCoverageFact> {
        vec![
            self.activation_scope_set.fact("activation_scope_set"),
            self.closed_sessions.fact("closed_sessions"),
            self.closed_attempts.fact("closed_attempts"),
            self.closed_jobs.fact("closed_jobs"),
            self.closed_effects.fact("closed_effects"),
            self.pending_observations.fact("pending_observations"),
            self.pending_feedback.fact("pending_feedback"),
            self.pending_projections.fact("pending_projections"),
            self.pending_receipts.fact("pending_receipts"),
            self.maintenance_debt.fact("maintenance_debt"),
            self.due_policies.fact("due_policies"),
            self.eligible_service_safe_routes
                .fact("eligible_service_safe_routes"),
            self.user_session_required_work
                .fact("user_session_required_work"),
        ]
    }

    /// Returns the first source that is not adequately covered, or `None`
    /// when every declared source is `Complete` with no retained gap.
    ///
    /// "Adequate known coverage of due work" means exactly this: each named
    /// persistence owner answered for its declared scopes. An empty record
    /// list under `Complete` is a known-empty set; the same empty list under
    /// `Partial`, `Unknown` or with a retained gap is not.
    fn first_inadequately_covered_source(&self) -> Option<&'static str> {
        self.coverage_facts()
            .into_iter()
            .find(|fact| fact.coverage != AssessmentSourceCoverage::Complete || fact.gaps != 0)
            .map(|fact| fact.field)
    }

    /// True when the request carries work a decision actually has to address.
    ///
    /// Only the sources that can hold outstanding work are consulted. Closed
    /// activity and the activation/scope set describe what already ended, so
    /// their record count says nothing about whether deferral is justified.
    fn has_outstanding_work(&self) -> bool {
        self.pending_observations.records.len()
            + self.pending_feedback.records.len()
            + self.pending_projections.records.len()
            + self.pending_receipts.records.len()
            + self.maintenance_debt.records.len()
            + self.user_session_required_work.records.len()
            > 0
    }

    /// True when at least one source is incomplete or retains an explicit gap.
    fn has_limiting_condition(&self) -> bool {
        self.first_inadequately_covered_source().is_some()
    }
}

/// One source's coverage and retained-gap count.
struct SourceCoverageFact {
    /// Request field the fact was read from.
    field: &'static str,
    /// Explicit coverage the source owner declared.
    coverage: AssessmentSourceCoverage,
    /// Number of retained, explained gaps.
    gaps: usize,
}

/// Deterministic end-of-activity action vocabulary from I14.22.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndOfActivityAssessmentDecision {
    /// No maintenance action is admitted.
    NoAction,
    /// One bounded maintenance job is admitted.
    StartBoundedJob,
    /// An admitted wake is required for later work.
    ScheduleWake,
    /// Preserve one recommendation for the user.
    SuggestOnce,
    /// Preserve the work for a later eligible opportunity.
    Defer,
}

/// Versioned assessment result and shutdown disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndOfActivityMaintenanceAssessmentOutcome {
    /// Content-addressed versioned contract identity.
    pub contract_identity: ContractIdentity,
    /// Request identity this outcome answers.
    pub request_id: RequestId,
    /// Existing decision identity from the shared contract vocabulary.
    pub decision_id: DecisionId,
    /// Exact fence under which the outcome was formed.
    pub state_fence: StateFence,
    /// I14.22 deterministic decision.
    pub decision: EndOfActivityAssessmentDecision,
    /// Existing runtime lease reference, when a bounded job or repair owns one.
    pub runtime_lease: Option<RuntimeLease>,
    /// Existing `HostStateJournal` wake reference, when work is scheduled.
    pub wake_intent: Option<WakeIntent>,
    /// Whether shutdown may continue after this assessment.
    pub shutdown_may_proceed: bool,
    /// Explicit reason for the shutdown disposition.
    pub shutdown_reason: String,
    /// Time this outcome was formed, in Unix milliseconds.
    pub assessed_at_ms: i64,
    /// Outcome expiry, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Durable decision/outcome receipt from the named persistence owner.
    pub outcome_receipt: Receipt,
}

impl EndOfActivityMaintenanceAssessmentOutcome {
    /// Validates request binding, fencing, expiry and existing runtime receipts.
    pub fn validate_for(
        &self,
        request: &EndOfActivityMaintenanceAssessmentRequest,
    ) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        self.contract_identity.validate().map_err(|_| {
            EndOfActivityMaintenanceAssessmentValidationError::ContractIdentityInvalid
        })?;
        if self.contract_identity != request.contract_identity {
            return Err(
                EndOfActivityMaintenanceAssessmentValidationError::ContractIdentityMismatch,
            );
        }
        if self.request_id != request.request_id {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::RequestMismatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| EndOfActivityMaintenanceAssessmentValidationError::InvalidFence)?;
        if self.state_fence != request.source_fence {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::FenceMismatch);
        }
        if self.expires_at_ms <= self.assessed_at_ms {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::Expired);
        }
        validate_text(&self.shutdown_reason, "shutdown_reason")?;

        if let Some(lease) = &self.runtime_lease {
            lease.validate().map_err(|_| {
                EndOfActivityMaintenanceAssessmentValidationError::RuntimeLeaseInvalid
            })?;
            if lease.state_fence != self.state_fence {
                return Err(EndOfActivityMaintenanceAssessmentValidationError::FenceMismatch);
            }
        }
        if let Some(wake) = &self.wake_intent {
            wake.validate().map_err(|_| {
                EndOfActivityMaintenanceAssessmentValidationError::WakeIntentInvalid
            })?;
            if wake.state_fence != self.state_fence {
                return Err(EndOfActivityMaintenanceAssessmentValidationError::FenceMismatch);
            }
        }
        self.outcome_receipt.validate().map_err(|_| {
            EndOfActivityMaintenanceAssessmentValidationError::OutcomeReceiptInvalid
        })?;
        if self.outcome_receipt.state_fence != self.state_fence
            || self.outcome_receipt.decision_id != self.decision_id
        {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::OutcomeReceiptMismatch);
        }
        self.validate_decision_relation(request)
    }

    /// Validates the complete requested-to-observed action relation.
    ///
    /// The decision, the runtime/wake references it carries and the shutdown
    /// disposition must agree with each other and with what the request
    /// actually read. Without this, a caller could claim `NO_ACTION` from
    /// sources that never answered, claim `SCHEDULE_WAKE` with no admitted
    /// `WakeIntent`, or claim a replacement runtime lease while also letting
    /// shutdown continue, and the record would still validate.
    fn validate_decision_relation(
        &self,
        request: &EndOfActivityMaintenanceAssessmentRequest,
    ) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        let invalid = || EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid;
        match self.decision {
            // `no_action` is the strongest claim in the vocabulary: it says
            // there is nothing to do. That is only admissible on adequate
            // known coverage of due work, so it must not rest on a source that
            // is partial, unknown or gap-carrying.
            EndOfActivityAssessmentDecision::NoAction => {
                if let Some(source) = request.first_inadequately_covered_source() {
                    return Err(
                        EndOfActivityMaintenanceAssessmentValidationError::InsufficientCoverage(
                            source,
                        ),
                    );
                }
                // Nothing is admitted and nothing is scheduled, so drain stays
                // eligible and no replacement ownership appears.
                if self.runtime_lease.is_some() || self.wake_intent.is_some() {
                    return Err(invalid());
                }
                if !self.shutdown_may_proceed {
                    return Err(invalid());
                }
            }
            // A bounded job is the only decision that may hold drain back, and
            // only by naming the current runtime ownership that replaces the
            // released lease. A job reference inside a historical record is
            // not proof that a lease is live.
            EndOfActivityAssessmentDecision::StartBoundedJob => {
                if self.runtime_lease.is_none() {
                    return Err(invalid());
                }
                if self.wake_intent.is_some() {
                    return Err(invalid());
                }
                if self.shutdown_may_proceed {
                    return Err(invalid());
                }
                // This is the only effect-capable decision in the vocabulary,
                // so it is the only one whose outcome receipt must name the
                // operation that admitted the bounded job. Without that
                // identity the held drain has no replay handle and the same
                // boundary could be admitted twice.
                if self.outcome_receipt.operation_id.is_none() {
                    return Err(invalid());
                }
            }
            // `schedule_wake` must name an actual admitted Host `WakeIntent`
            // rather than a locally fabricated scheduler record.
            EndOfActivityAssessmentDecision::ScheduleWake => {
                if self.wake_intent.is_none() || self.runtime_lease.is_some() {
                    return Err(invalid());
                }
                // A pending wake is not admitted runtime ownership, so it must
                // not withhold drain.
                if !self.shutdown_may_proceed {
                    return Err(invalid());
                }
            }
            // A single preserved recommendation renews nothing: it keeps no
            // lease and schedules nothing.
            EndOfActivityAssessmentDecision::SuggestOnce => {
                if self.runtime_lease.is_some() || self.wake_intent.is_some() {
                    return Err(invalid());
                }
                if !self.shutdown_may_proceed {
                    return Err(invalid());
                }
            }
            // `defer` must record a real limiting condition or preserve real
            // outstanding work. It is not the answer to a fully covered request
            // that holds nothing, which would otherwise read as an assessment
            // that decided nothing while looking complete.
            EndOfActivityAssessmentDecision::Defer => {
                if !request.has_limiting_condition() && !request.has_outstanding_work() {
                    return Err(invalid());
                }
                if self.runtime_lease.is_some() || self.wake_intent.is_some() {
                    return Err(invalid());
                }
                if !self.shutdown_may_proceed {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

/// Complete request and outcome representation for an end-of-activity assessment.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndOfActivityMaintenanceAssessment {
    /// Versioned evidence request.
    pub request: EndOfActivityMaintenanceAssessmentRequest,
    /// Decision, shutdown disposition and outcome evidence.
    pub outcome: EndOfActivityMaintenanceAssessmentOutcome,
}

impl EndOfActivityMaintenanceAssessment {
    /// Validates the complete request/outcome binding without evaluating policy.
    pub fn validate(&self) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        self.request.validate()?;
        self.outcome.validate_for(&self.request)
    }
}

/// Deterministic decision core of one end-of-activity assessment: the I14.22
/// decision, the shutdown disposition, and its explicit reason. The owning
/// evaluator attaches this core to the outcome receipts the persistence
/// owners issue; the core itself performs no I/O and acquires no lease.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndOfActivityAssessment {
    /// I14.22 deterministic decision.
    pub decision: EndOfActivityAssessmentDecision,
    /// Whether shutdown may continue after this assessment.
    pub shutdown_may_proceed: bool,
    /// Explicit reason for the shutdown disposition.
    pub shutdown_reason: String,
}

/// Deterministic end-of-activity maintenance assessment (I14.22, MAINT-1..3).
///
/// Runs before drain admission when the final observable-use obligation is
/// about to release its lease. The assessment does not keep ELIOT alive
/// merely because data exists: only an admitted bounded job or active repair
/// acquires a new `RuntimeLease`; otherwise work is scheduled, suggested
/// once or deferred and drain continues. User-session-required maintenance
/// without an authenticated session defers instead of retaining desktop
/// credentials or faking execution.
///
/// Decision precedence, first match wins:
///
/// 1. an admitted bounded job or active repair is running: `START_BOUNDED_JOB`
///    and shutdown waits for its release;
/// 2. user-session-required work exists but no authenticated session is
///    available: `DEFER` with shutdown proceeding and no credential
///    retention;
/// 3. user-session-required work exists with a session available but no
///    admitted job: `SUGGEST_ONCE`, preserving one recommendation while
///    shutdown proceeds (admission itself stays with the trigger path);
/// 4. any source has unknown coverage: `DEFER` with shutdown proceeding —
///    the assessment alone never blocks drain on suspicion, and the lease
///    census remains the drain gate;
/// 5. any pending observation, feedback, projection, receipt, debt or due
///    policy record exists without an admitted job: `DEFER` with shutdown
///    proceeding;
/// 6. otherwise no work is admitted: `NO_ACTION` with shutdown proceeding.
///
/// Closed sessions, attempts, jobs and effects are completed-activity
/// evidence, not work, and never change the decision. Eligible service-safe
/// routes alone are capacity, not work.
///
/// # Errors
///
/// Returns the request validation error when the evidence request is
/// malformed. A malformed request assesses nothing.
pub fn assess_end_of_activity(
    request: &EndOfActivityMaintenanceAssessmentRequest,
    user_session_available: bool,
    bounded_job_admitted: bool,
) -> Result<EndOfActivityAssessment, EndOfActivityMaintenanceAssessmentValidationError> {
    request.validate()?;
    if bounded_job_admitted {
        return Ok(EndOfActivityAssessment {
            decision: EndOfActivityAssessmentDecision::StartBoundedJob,
            shutdown_may_proceed: false,
            shutdown_reason:
                "admitted bounded job holds a runtime lease; drain waits for its release".to_owned(),
        });
    }
    if !request.user_session_required_work.records.is_empty() {
        if user_session_available {
            return Ok(EndOfActivityAssessment {
                decision: EndOfActivityAssessmentDecision::SuggestOnce,
                shutdown_may_proceed: true,
                shutdown_reason:
                    "user-session-required maintenance suggested once; drain continues".to_owned(),
            });
        }
        return Ok(EndOfActivityAssessment {
            decision: EndOfActivityAssessmentDecision::Defer,
            shutdown_may_proceed: true,
            shutdown_reason: "user-session-required maintenance deferred without retaining credentials; drain continues"
                .to_owned(),
        });
    }
    if request.first_inadequately_covered_source().is_some() {
        return Ok(EndOfActivityAssessment {
            decision: EndOfActivityAssessmentDecision::Defer,
            shutdown_may_proceed: true,
            shutdown_reason:
                "incomplete source coverage preserved for a later eligible opportunity; drain continues"
                    .to_owned(),
        });
    }
    if !request.pending_observations.records.is_empty()
        || !request.pending_feedback.records.is_empty()
        || !request.pending_projections.records.is_empty()
        || !request.pending_receipts.records.is_empty()
        || !request.maintenance_debt.records.is_empty()
        || !request.due_policies.records.is_empty()
    {
        return Ok(EndOfActivityAssessment {
            decision: EndOfActivityAssessmentDecision::Defer,
            shutdown_may_proceed: true,
            shutdown_reason:
                "unadmitted work preserved for a later eligible opportunity; drain continues"
                    .to_owned(),
        });
    }
    Ok(EndOfActivityAssessment {
        decision: EndOfActivityAssessmentDecision::NoAction,
        shutdown_may_proceed: true,
        shutdown_reason: "no admitted work; drain continues".to_owned(),
    })
}

/// Fail-closed structural validation failures for the assessment contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EndOfActivityMaintenanceAssessmentValidationError {
    /// A required textual identity or reason is malformed.
    #[error("invalid end-of-activity assessment field: {0}")]
    InvalidField(&'static str),
    /// A source coverage declaration does not match its revision and gap data.
    #[error("invalid end-of-activity source coverage")]
    InvalidCoverage,
    /// A required source revision is missing or malformed.
    #[error("invalid end-of-activity source revision")]
    InvalidSourceRevision,
    /// A record or scope identity appears more than once.
    #[error("duplicate end-of-activity source identity")]
    DuplicateIdentity,
    /// The state fence is malformed.
    #[error("invalid end-of-activity state fence")]
    InvalidFence,
    /// Source or outcome state fences do not match the request fence.
    #[error("end-of-activity state fence mismatch")]
    FenceMismatch,
    /// Contract identity is malformed.
    #[error("end-of-activity contract identity is invalid")]
    ContractIdentityInvalid,
    /// Contract identity does not name this request/outcome version.
    #[error("end-of-activity contract identity mismatch")]
    ContractIdentityMismatch,
    /// Outcome request identity differs from its request.
    #[error("end-of-activity request identity mismatch")]
    RequestMismatch,
    /// Assessment expiry is not after assessment time.
    #[error("end-of-activity assessment is expired")]
    Expired,
    /// Referenced runtime lease failed its existing contract validation.
    #[error("end-of-activity runtime lease is invalid")]
    RuntimeLeaseInvalid,
    /// Referenced wake intent failed its existing contract validation.
    #[error("end-of-activity wake intent is invalid")]
    WakeIntentInvalid,
    /// Existing outcome receipt failed its existing contract validation.
    #[error("end-of-activity outcome receipt is invalid")]
    OutcomeReceiptInvalid,
    /// Existing outcome receipt does not bind this fence and decision.
    #[error("end-of-activity outcome receipt mismatch")]
    OutcomeReceiptMismatch,
    /// `no_action` claimed adequate known coverage of due work that the
    /// request's own sources do not provide. The payload names the first
    /// source that is partial, unknown or carries a retained gap.
    #[error("end-of-activity decision requires coverage {0} does not provide")]
    InsufficientCoverage(&'static str),
    /// The decision, the runtime/wake references it carries and the shutdown
    /// disposition do not form the requested-to-observed action relation.
    #[error("end-of-activity decision records no admissible action relation")]
    DecisionRelationInvalid,
}

fn validate_text(
    value: &str,
    field: &'static str,
) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn validate_unique_text(
    values: &[String],
    field: &'static str,
) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
    for (index, value) in values.iter().enumerate() {
        validate_text(value, field)?;
        if values[..index].contains(value) {
            return Err(EndOfActivityMaintenanceAssessmentValidationError::DuplicateIdentity);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{ClockReading, DecisionId, OperationId, ReceiptId};
    use serde_json::json;

    const FENCE_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn must<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("valid fixture")
    }

    /// The one fence every fixture binds to, in its wire shape.
    fn fence_value() -> serde_json::Value {
        json!({
            "authority_epoch": { "lineage_id": FENCE_LINEAGE, "sequence": 1 },
            "resource_generation": 1,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null
        })
    }

    fn fence() -> StateFence {
        must(fence_value())
    }

    fn request_id() -> RequestId {
        RequestId::new("eoa-request-1").expect("request id")
    }

    fn decision_id() -> DecisionId {
        DecisionId::new("eoa-decision-1").expect("decision id")
    }

    /// A source that answered completely for one declared scope and holds no
    /// records: the known-empty case the coverage rules must accept.
    fn complete_source<T: AssessmentSourceRecord>() -> AssessmentSourceSnapshot<T> {
        AssessmentSourceSnapshot {
            persistence_owner: "owner-1".to_owned(),
            source_revision: Some("rev-1".to_owned()),
            state_fence: fence(),
            coverage: AssessmentSourceCoverage::Complete,
            covered_scope_refs: vec!["scope-1".to_owned()],
            records: Vec::new(),
            gaps: Vec::new(),
        }
    }

    fn record_reference(reference: &str) -> AssessmentRecordReference {
        AssessmentRecordReference {
            reference: reference.to_owned(),
        }
    }

    fn debt_reference(reference: &str) -> MaintenanceDebtReference {
        MaintenanceDebtReference {
            reference: reference.to_owned(),
            family: MaintenanceFamily::OutboxReceiptReconciliation,
        }
    }

    /// A request whose every named owner answered completely for `scope-1`
    /// and reported nothing outstanding.
    fn covered_empty_request() -> EndOfActivityMaintenanceAssessmentRequest {
        EndOfActivityMaintenanceAssessmentRequest {
            contract_identity: end_of_activity_assessment_contract_identity()
                .expect("contract identity"),
            request_id: request_id(),
            observed_at_ms: 1_700_000_000_000,
            source_fence: fence(),
            activation_scope_set: must(json!({
                "persistence_owner": "host-state-journal",
                "source_revision": "rev-activation",
                "state_fence": fence_value(),
                "coverage": "COMPLETE",
                "covered_scope_refs": ["scope-1"],
                "records": [{"activation_ref": "activation-1", "scope_refs": ["scope-1"]}],
                "gaps": []
            })),
            closed_sessions: complete_source(),
            closed_attempts: complete_source(),
            closed_jobs: complete_source(),
            closed_effects: complete_source(),
            pending_observations: complete_source(),
            pending_feedback: complete_source(),
            pending_projections: complete_source(),
            pending_receipts: complete_source(),
            maintenance_debt: complete_source(),
            due_policies: complete_source(),
            eligible_service_safe_routes: complete_source(),
            user_session_required_work: complete_source(),
        }
    }

    fn runtime_lease() -> RuntimeLease {
        must(json!({
            "lease_id": "lease-1",
            "scope_ref": "scope-1",
            "authority_epoch": { "lineage_id": FENCE_LINEAGE, "sequence": 1 },
            "state_fence": fence_value(),
            "state": "ACTIVE",
            "expires_at_ms": 4_000_000_000_000u64
        }))
    }

    fn wake_intent() -> WakeIntent {
        must(json!({
            "wake_id": "wake-1",
            "reason": "later eligible maintenance opportunity",
            "state_fence": fence_value(),
            "state": "PENDING"
        }))
    }

    fn outcome_receipt(operation_id: Option<&str>) -> Receipt {
        Receipt {
            receipt_id: ReceiptId::new("receipt-1").expect("receipt id"),
            operation_id: operation_id.map(|value| OperationId::new(value).expect("operation id")),
            decision_id: decision_id(),
            status: must(json!("SUCCEEDED")),
            state_fence: fence(),
            clock: ClockReading::default(),
        }
    }

    fn outcome(
        decision: EndOfActivityAssessmentDecision,
        runtime_lease: Option<RuntimeLease>,
        wake_intent: Option<WakeIntent>,
        shutdown_may_proceed: bool,
        operation_id: Option<&str>,
    ) -> EndOfActivityMaintenanceAssessmentOutcome {
        EndOfActivityMaintenanceAssessmentOutcome {
            contract_identity: end_of_activity_assessment_contract_identity()
                .expect("contract identity"),
            request_id: request_id(),
            decision_id: decision_id(),
            state_fence: fence(),
            decision,
            runtime_lease,
            wake_intent,
            shutdown_may_proceed,
            shutdown_reason: "drain disposition for one closing boundary".to_owned(),
            assessed_at_ms: 1_700_000_001_000,
            expires_at_ms: 1_700_000_601_000,
            outcome_receipt: outcome_receipt(operation_id),
        }
    }

    fn validate(
        request: &EndOfActivityMaintenanceAssessmentRequest,
        outcome: EndOfActivityMaintenanceAssessmentOutcome,
    ) -> Result<(), EndOfActivityMaintenanceAssessmentValidationError> {
        EndOfActivityMaintenanceAssessment {
            request: request.clone(),
            outcome,
        }
        .validate()
    }

    #[test]
    fn no_action_is_admitted_only_on_complete_coverage() {
        let request = covered_empty_request();
        request.validate().expect("covered request");
        // Known-empty under complete coverage: the strongest admissible case.
        let admitted = outcome(
            EndOfActivityAssessmentDecision::NoAction,
            None,
            None,
            true,
            None,
        );
        validate(&request, admitted).expect("no_action on complete coverage");

        // The same decision off a partially answered owner is not admissible:
        // `no_action` claims there is nothing to do, which needs adequate
        // known coverage of due work.
        let mut partial = covered_empty_request();
        partial.maintenance_debt.coverage = AssessmentSourceCoverage::Partial;
        partial.maintenance_debt.gaps.push(AssessmentSourceGap {
            scope_ref: Some("scope-1".to_owned()),
            reason: "debt owner page not fully read".to_owned(),
        });
        partial
            .validate()
            .expect("partial coverage is a valid request");
        let refused = validate(
            &partial,
            outcome(
                EndOfActivityAssessmentDecision::NoAction,
                None,
                None,
                true,
                None,
            ),
        );
        assert_eq!(
            refused,
            Err(
                EndOfActivityMaintenanceAssessmentValidationError::InsufficientCoverage(
                    "maintenance_debt"
                )
            ),
            "no_action was admitted off a source that only partially answered"
        );

        // Unknown coverage is equally insufficient, and names the same field.
        let mut unknown = covered_empty_request();
        unknown.due_policies.coverage = AssessmentSourceCoverage::Unknown;
        unknown.due_policies.source_revision = None;
        unknown.due_policies.covered_scope_refs.clear();
        unknown.due_policies.gaps.push(AssessmentSourceGap {
            scope_ref: None,
            reason: "policy owner unavailable".to_owned(),
        });
        assert_eq!(
            validate(
                &unknown,
                outcome(
                    EndOfActivityAssessmentDecision::NoAction,
                    None,
                    None,
                    true,
                    None,
                ),
            ),
            Err(
                EndOfActivityMaintenanceAssessmentValidationError::InsufficientCoverage(
                    "due_policies"
                )
            )
        );
    }

    #[test]
    fn complete_coverage_over_no_declared_scope_is_not_coverage() {
        // `Complete` with no declared scope is complete over nothing, so it
        // cannot be the adequate known coverage a `no_action` rests on.
        let mut request = covered_empty_request();
        request.pending_receipts.covered_scope_refs.clear();
        assert_eq!(
            request.validate(),
            Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage)
        );
        assert_eq!(
            validate(
                &request,
                outcome(
                    EndOfActivityAssessmentDecision::NoAction,
                    None,
                    None,
                    true,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::InvalidCoverage)
        );
    }

    #[test]
    fn defer_must_record_a_real_limiting_condition_or_real_work() {
        let mut deferred_by_coverage = covered_empty_request();
        deferred_by_coverage.pending_projections.coverage = AssessmentSourceCoverage::Partial;
        deferred_by_coverage
            .pending_projections
            .gaps
            .push(AssessmentSourceGap {
                scope_ref: Some("scope-1".to_owned()),
                reason: "projection owner page not fully read".to_owned(),
            });
        deferred_by_coverage
            .validate()
            .expect("partial coverage request");
        validate(
            &deferred_by_coverage,
            outcome(
                EndOfActivityAssessmentDecision::Defer,
                None,
                None,
                true,
                None,
            ),
        )
        .expect("defer records an explicit limiting condition");

        // Fully covered and holding nothing: `defer` would decide nothing
        // while looking like a complete assessment.
        assert_eq!(
            validate(
                &covered_empty_request(),
                outcome(
                    EndOfActivityAssessmentDecision::Defer,
                    None,
                    None,
                    true,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );

        // Fully covered but with real outstanding debt, deferral is justified.
        let mut deferred_by_debt = covered_empty_request();
        deferred_by_debt
            .maintenance_debt
            .records
            .push(debt_reference("debt-1"));
        deferred_by_debt.validate().expect("debt request");
        validate(
            &deferred_by_debt,
            outcome(
                EndOfActivityAssessmentDecision::Defer,
                None,
                None,
                true,
                None,
            ),
        )
        .expect("defer preserves real outstanding work");
    }

    #[test]
    fn only_start_bounded_job_may_withhold_drain_and_only_with_live_ownership() {
        let request = covered_empty_request();
        let mut job_request = request.clone();
        job_request
            .maintenance_debt
            .records
            .push(debt_reference("debt-1"));
        job_request.validate().expect("debt request");

        // The admitted relation: a bounded job names the current runtime
        // ownership that replaces the released lease and holds drain.
        let admitted = validate(
            &job_request,
            outcome(
                EndOfActivityAssessmentDecision::StartBoundedJob,
                Some(runtime_lease()),
                None,
                false,
                Some("op-eoa-job-1"),
            ),
        );
        admitted.expect("bounded job with live ownership and an operation id");

        // No named runtime ownership: a job reference or a claimed decision is
        // not proof that a lease is live.
        assert_eq!(
            validate(
                &job_request,
                outcome(
                    EndOfActivityAssessmentDecision::StartBoundedJob,
                    None,
                    None,
                    false,
                    Some("op-eoa-job-1"),
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );
        // Drain proceeds while the bounded job supposedly owns work.
        assert_eq!(
            validate(
                &job_request,
                outcome(
                    EndOfActivityAssessmentDecision::StartBoundedJob,
                    Some(runtime_lease()),
                    None,
                    true,
                    Some("op-eoa-job-1"),
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );
        // The one effect-capable decision must name the admitted operation, so
        // the held drain keeps a replay handle.
        assert_eq!(
            validate(
                &job_request,
                outcome(
                    EndOfActivityAssessmentDecision::StartBoundedJob,
                    Some(runtime_lease()),
                    None,
                    false,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );

        // A decision that renews nothing may not carry replacement ownership,
        // and it must leave drain eligible.
        for decision in [
            EndOfActivityAssessmentDecision::NoAction,
            EndOfActivityAssessmentDecision::ScheduleWake,
            EndOfActivityAssessmentDecision::SuggestOnce,
            EndOfActivityAssessmentDecision::Defer,
        ] {
            assert_eq!(
                validate(
                    &job_request,
                    outcome(decision, Some(runtime_lease()), None, true, None),
                ),
                Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid),
                "{decision:?} carried replacement runtime ownership"
            );
            assert_eq!(
                validate(&job_request, outcome(decision, None, None, false, None)),
                Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid),
                "{decision:?} withheld drain without admitted ownership"
            );
        }
    }

    #[test]
    fn schedule_wake_requires_an_admitted_wake_intent_and_defers_no_drain() {
        let mut request = covered_empty_request();
        request
            .maintenance_debt
            .records
            .push(debt_reference("debt-1"));
        request.validate().expect("debt request");

        // A locally fabricated scheduler record is not an admitted wake.
        assert_eq!(
            validate(
                &request,
                outcome(
                    EndOfActivityAssessmentDecision::ScheduleWake,
                    None,
                    None,
                    true,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );
        // A pending wake is not admitted runtime ownership, so it must not
        // withhold drain.
        assert_eq!(
            validate(
                &request,
                outcome(
                    EndOfActivityAssessmentDecision::ScheduleWake,
                    None,
                    Some(wake_intent()),
                    false,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );
        validate(
            &request,
            outcome(
                EndOfActivityAssessmentDecision::ScheduleWake,
                None,
                Some(wake_intent()),
                true,
                None,
            ),
        )
        .expect("admitted wake lets drain continue");

        // A suggestion keeps no lease and schedules nothing.
        validate(
            &request,
            outcome(
                EndOfActivityAssessmentDecision::SuggestOnce,
                None,
                None,
                true,
                None,
            ),
        )
        .expect("suggestion drains continue");
        assert_eq!(
            validate(
                &request,
                outcome(
                    EndOfActivityAssessmentDecision::SuggestOnce,
                    None,
                    Some(wake_intent()),
                    true,
                    None,
                ),
            ),
            Err(EndOfActivityMaintenanceAssessmentValidationError::DecisionRelationInvalid)
        );
    }

    #[test]
    fn the_evaluator_never_claims_no_action_off_incomplete_coverage() {
        let mut partial = covered_empty_request();
        partial.pending_observations.coverage = AssessmentSourceCoverage::Partial;
        partial.pending_observations.gaps.push(AssessmentSourceGap {
            scope_ref: Some("scope-1".to_owned()),
            reason: "observation owner page not fully read".to_owned(),
        });
        let deferred = assess_end_of_activity(&partial, true, false).expect("assessment");
        assert_eq!(deferred.decision, EndOfActivityAssessmentDecision::Defer);
        assert!(deferred.shutdown_may_proceed);

        // A fully covered known-empty request still admits `no_action`.
        let idle =
            assess_end_of_activity(&covered_empty_request(), true, false).expect("assessment");
        assert_eq!(idle.decision, EndOfActivityAssessmentDecision::NoAction);
        assert!(idle.shutdown_may_proceed);

        // Pending observations keep the decision off `no_action` too.
        let mut pending = covered_empty_request();
        pending
            .pending_observations
            .records
            .push(record_reference("observation-1"));
        assert_eq!(
            assess_end_of_activity(&pending, true, false)
                .expect("assessment")
                .decision,
            EndOfActivityAssessmentDecision::Defer
        );
    }
}
