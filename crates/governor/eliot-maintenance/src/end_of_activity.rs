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
    if [
        &request.activation_scope_set.coverage,
        &request.closed_sessions.coverage,
        &request.closed_attempts.coverage,
        &request.closed_jobs.coverage,
        &request.closed_effects.coverage,
        &request.pending_observations.coverage,
        &request.pending_feedback.coverage,
        &request.pending_projections.coverage,
        &request.pending_receipts.coverage,
        &request.maintenance_debt.coverage,
        &request.due_policies.coverage,
        &request.eligible_service_safe_routes.coverage,
        &request.user_session_required_work.coverage,
    ]
    .contains(&&AssessmentSourceCoverage::Unknown)
    {
        return Ok(EndOfActivityAssessment {
            decision: EndOfActivityAssessmentDecision::Defer,
            shutdown_may_proceed: true,
            shutdown_reason:
                "unknown source coverage preserved for a later eligible opportunity; drain continues"
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
