//! Governor-owned observation admission and rebuildable journal projection.
//!
//! The foundation crates own the shape of observation, coverage and evidence
//! records.  This crate owns the semantic boundary around those records:
//! operation identity, State Fence and plan binding, task-selection safety,
//! capture fallback, idempotent admission and the append-only journal view.
//! It never starts sensors, reads a host, promotes a claim, or treats a
//! transport receipt as epistemic proof.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

pub use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, ObservationRecord,
};
pub use eliot_observation_contracts::{
    ActiveObservationPlan, BlindInterval, CaptureMode, CaptureRoute, CoverageAssessment,
    CoverageDisposition, CoverageEvidence, CoverageGap, CoverageInterval, DenominatorSpec,
    Durability, EliotSystemObservationEvent, GapDisposition, GapPolicy, ObservationEventCore,
    ObservationEventIdentity, ObservationKind, ObservationObligationProfile, ObservationRecordKind,
    ObservationRecordEnvelope, ObservationScope, ProducerGenerationRef, ProducerTrace,
    SamplingPolicy, SystemObservationJournalRecord,
};

use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, StateFence, canonical_json_bytes,
    contract_identity as foundation_contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this Governor observation contract.
pub const CONTRACT_NAME: &str = "eliot.governor.observation";
/// Current wire revision of this contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Failures at the Governor observation boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GovernorObservationError {
    /// A shared foundation primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// The observation-shape contract rejected a record or plan.
    #[error("observation contract: {0}")]
    Observation(eliot_observation_contracts::ObservationError),
    /// A semantic evidence envelope rejected its status or provenance.
    #[error("evidence contract: {0}")]
    Evidence(eliot_evidence::EvidenceError),
    /// A required field is blank or malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required field collection has no members.
    #[error("empty field {field}")]
    Empty {
        /// Stable field path.
        field: &'static str,
    },
    /// A collection contains duplicate identities.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Stable field path.
        field: &'static str,
    },
    /// Reusing an identity with different canonical bytes is forbidden.
    #[error("observation identity conflict")]
    IdentityConflict,
    /// A task-bound observation did not include exact selection evidence.
    #[error("task selection evidence is required")]
    TaskSelectionRequired,
    /// Selection evidence names a different task or WorkScope.
    #[error("task selection is incompatible with observation scope")]
    TaskScopeIncompatible,
    /// A supplied plan or evidence envelope uses another State Fence.
    #[error("observation State Fence mismatch")]
    FenceMismatch,
    /// The capture route cannot provide the declared durability.
    #[error("capture route cannot provide declared durability")]
    InsufficientDurability,
    /// A canonical request could not be hashed.
    #[error("cannot canonicalize observation request")]
    Serialization,
}

impl From<ContractError> for GovernorObservationError {
    fn from(error: ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<eliot_observation_contracts::ObservationError> for GovernorObservationError {
    fn from(error: eliot_observation_contracts::ObservationError) -> Self {
        Self::Observation(error)
    }
}

impl From<eliot_evidence::EvidenceError> for GovernorObservationError {
    fn from(error: eliot_evidence::EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), GovernorObservationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(GovernorObservationError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), GovernorObservationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(GovernorObservationError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn unique<T: Ord>(values: impl IntoIterator<Item = T>, field: &'static str) -> Result<(), GovernorObservationError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(GovernorObservationError::Duplicate { field });
    }
    Ok(())
}

fn route_supports(route: CaptureRoute, durability: Durability) -> bool {
    match durability {
        Durability::Volatile => true,
        Durability::BoundedOutbox => !matches!(route, CaptureRoute::OperationalLog),
        Durability::Durable => matches!(
            route,
            CaptureRoute::CanonicalJournal | CaptureRoute::WatchdogSpool | CaptureRoute::OrsOutbox
        ),
        Durability::Protected => matches!(
            route,
            CaptureRoute::CanonicalJournal | CaptureRoute::WatchdogSpool | CaptureRoute::OrsOutbox
        ),
    }
}

/// Exact binding of an observation to a compiled plan revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPlanBinding {
    /// Plan identity selected by the Governor.
    pub plan_id: String,
    /// Exact plan revision selected by the Governor.
    pub plan_revision: String,
    /// Fence under which the plan was compiled.
    pub state_fence: StateFence,
}

impl ObservationPlanBinding {
    /// Validates the plan identity and fence.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.plan_id, "plan_binding.plan_id")?;
        text(&self.plan_revision, "plan_binding.plan_revision")?;
        self.state_fence.validate()?;
        Ok(())
    }
}

/// Task selection evidence required before a reusable task-bound observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSelectionEvidence {
    /// Exact task identity selected by the owner.
    pub task_ref: String,
    /// Current task-contract revision.
    pub task_revision: u64,
    /// Acceptance digest bound by the selection.
    pub acceptance_digest: String,
    /// WorkScope identity used by the selection.
    pub work_scope_ref: String,
    /// Source/route that established the selection.
    pub selection_source_ref: String,
    /// Exact evidence supporting the selection.
    pub evidence_ref: String,
    /// Explicit contamination flags preserved from the selection route.
    #[serde(default)]
    pub contamination_flags: Vec<String>,
}

impl TaskSelectionEvidence {
    /// Validates a task selection without issuing task authority.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.task_ref, "task_selection.task_ref")?;
        if self.task_revision == 0 {
            return Err(GovernorObservationError::InvalidField {
                field: "task_selection.task_revision",
                reason: "must be non-zero",
            });
        }
        digest(&self.acceptance_digest, "task_selection.acceptance_digest")?;
        text(&self.work_scope_ref, "task_selection.work_scope_ref")?;
        text(&self.selection_source_ref, "task_selection.selection_source_ref")?;
        text(&self.evidence_ref, "task_selection.evidence_ref")?;
        unique(&self.contamination_flags, "task_selection.contamination_flags")?;
        for flag in &self.contamination_flags {
            text(flag, "task_selection.contamination_flag")?;
        }
        Ok(())
    }

    /// Whether the selection carries a known crossover/contamination marker.
    pub const fn is_contaminated(&self) -> bool {
        !self.contamination_flags.is_empty()
    }
}

/// Safe capture disposition for an observation that is not yet reusable memory.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateDisposition {
    /// No task binding was selected; capture remains cold.
    Cold,
    /// Exact task and scope selection evidence is present.
    TaskBound,
    /// Selection exists but contamination blocks reusable influence.
    Quarantined,
}

/// A bounded candidate fallback that preserves a safe observation without
/// silently promoting it into task memory or a claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCandidate {
    /// Stable candidate identity derived from the normalized record.
    pub candidate_id: String,
    /// Normalized operational observation.
    pub record: ObservationRecordEnvelope,
    /// Optional semantic evidence envelope; absence remains explicit unknown.
    pub evidence: Option<EvidenceEnvelope>,
    /// Fence under which the candidate was captured.
    pub state_fence: StateFence,
    /// Why the candidate cannot or can be reused yet.
    pub disposition: CandidateDisposition,
    /// Stable bounded reason for the disposition.
    pub reason_ref: String,
}

impl ObservationCandidate {
    /// Validates the candidate without promoting its semantic status.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.candidate_id, "candidate.candidate_id")?;
        self.record.validate()?;
        self.state_fence.validate()?;
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
            if evidence.state_fence != self.state_fence {
                return Err(GovernorObservationError::FenceMismatch);
            }
        }
        text(&self.reason_ref, "candidate.reason_ref")
    }
}

/// Strict observation submission before journal admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSubmission {
    /// Globally unique operation identity.
    pub operation_id: String,
    /// Retry identity for the same canonical request bytes.
    pub idempotency_key: String,
    /// Current fence captured by the producer.
    pub state_fence: StateFence,
    /// Normalized journal record.
    pub record: ObservationRecordEnvelope,
    /// Route through which the observation was captured.
    pub capture_route: CaptureRoute,
    /// Durability claimed by this submission.
    pub durability: Durability,
    /// Optional active observation plan binding.
    pub plan: Option<ObservationPlanBinding>,
    /// Optional exact task-selection evidence.
    pub task_selection: Option<TaskSelectionEvidence>,
    /// Optional semantic evidence envelope; this never bypasses observation capture.
    pub evidence: Option<EvidenceEnvelope>,
}

impl ObservationSubmission {
    /// Validates the complete pre-admission submission.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.operation_id, "submission.operation_id")?;
        text(&self.idempotency_key, "submission.idempotency_key")?;
        self.state_fence.validate()?;
        self.record.validate()?;
        if !route_supports(self.capture_route, self.durability) {
            return Err(GovernorObservationError::InsufficientDurability);
        }
        if let Some(plan) = &self.plan {
            plan.validate()?;
            if plan.state_fence != self.state_fence {
                return Err(GovernorObservationError::FenceMismatch);
            }
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
            if evidence.state_fence != self.state_fence {
                return Err(GovernorObservationError::FenceMismatch);
            }
        }
        if let Some(gap) = &self.record.coverage_gap {
            if gap.protected
                && (self.durability != Durability::Protected
                    || !route_supports(self.capture_route, Durability::Protected))
            {
                return Err(GovernorObservationError::InsufficientDurability);
            }
        }
        let task_ref = self
            .record
            .event
            .as_ref()
            .and_then(|event| event.affected_scope.task_ref.as_deref());
        match (task_ref, &self.task_selection) {
            (Some(task_ref), Some(selection)) => {
                selection.validate()?;
                if selection.task_ref != task_ref
                    || selection.work_scope_ref
                        != self
                            .record
                            .event
                            .as_ref()
                            .map(|event| event.affected_scope.work_scope.as_str())
                            .unwrap_or_default()
                {
                    return Err(GovernorObservationError::TaskScopeIncompatible);
                }
            }
            (Some(_), None) => return Err(GovernorObservationError::TaskSelectionRequired),
            (None, Some(_)) => return Err(GovernorObservationError::TaskScopeIncompatible),
            (None, None) => {}
        }
        Ok(())
    }

    /// Computes the canonical request hash used for idempotent admission.
    pub fn request_digest(&self) -> Result<String, GovernorObservationError> {
        let bytes = canonical_json_bytes(self).map_err(|_| GovernorObservationError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }

    fn candidate_fallback(&self) -> Option<ObservationCandidate> {
        if self.record.validate().is_err() {
            return None;
        }
        let (disposition, reason_ref) = match &self.task_selection {
            Some(selection) if selection.is_contaminated() => {
                (CandidateDisposition::Quarantined, "task-selection-contaminated")
            }
            Some(_) => (CandidateDisposition::TaskBound, "task-selection-bound"),
            None => (CandidateDisposition::Cold, "unbound-capture"),
        };
        let candidate = ObservationCandidate {
            candidate_id: format!("candidate:{}", self.record.record_id),
            record: self.record.clone(),
            evidence: self.evidence.clone(),
            state_fence: self.state_fence.clone(),
            disposition,
            reason_ref: reason_ref.to_owned(),
        };
        candidate.validate().ok()
    }

    fn candidate_disposition(&self) -> CandidateDisposition {
        match &self.task_selection {
            Some(selection) if selection.is_contaminated() => CandidateDisposition::Quarantined,
            Some(_) => CandidateDisposition::TaskBound,
            None => CandidateDisposition::Cold,
        }
    }

    fn record_id(&self) -> &str {
        &self.record.record_id
    }
}

/// Immutable result of a normalized observation admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAdmissionReceipt {
    /// Operation identity assigned by the caller.
    pub operation_id: String,
    /// Retry identity used by the journal.
    pub idempotency_key: String,
    /// Normalized record identity.
    pub record_id: String,
    /// Exact request hash.
    pub request_digest: String,
    /// Fence under which the record was admitted.
    pub state_fence: StateFence,
    /// Immutable normalized observation retained by the journal.
    pub record: ObservationRecordEnvelope,
    /// Optional semantic evidence retained by exact handle/binding.
    pub evidence: Option<EvidenceEnvelope>,
    /// Capture route and durability recorded as observation metadata.
    pub capture_route: CaptureRoute,
    pub durability: Durability,
    /// Safe-capture/reuse ceiling derived from task selection.
    pub candidate_disposition: CandidateDisposition,
    /// Exact observation-plan binding, when one was active.
    pub plan: Option<ObservationPlanBinding>,
    /// Exact selection evidence, when the observation was task-bound.
    pub task_selection: Option<TaskSelectionEvidence>,
    /// Exact semantic evidence hash, when an envelope was supplied.
    pub evidence_digest: Option<String>,
}

impl ObservationAdmissionReceipt {
    /// Validates a receipt loaded into a rebuilt journal projection.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.operation_id, "admission.operation_id")?;
        text(&self.idempotency_key, "admission.idempotency_key")?;
        text(&self.record_id, "admission.record_id")?;
        digest(&self.request_digest, "admission.request_digest")?;
        self.state_fence.validate()?;
        self.record.validate()?;
        if self.record.record_id != self.record_id {
            return Err(GovernorObservationError::IdentityConflict);
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
            if evidence.state_fence != self.state_fence {
                return Err(GovernorObservationError::FenceMismatch);
            }
        }
        if !route_supports(self.capture_route, self.durability) {
            return Err(GovernorObservationError::InsufficientDurability);
        }
        let request = ObservationSubmission {
            operation_id: self.operation_id.clone(),
            idempotency_key: self.idempotency_key.clone(),
            state_fence: self.state_fence.clone(),
            record: self.record.clone(),
            capture_route: self.capture_route,
            durability: self.durability,
            plan: self.plan.clone(),
            task_selection: self.task_selection.clone(),
            evidence: self.evidence.clone(),
        };
        request.validate()?;
        if request.request_digest()? != self.request_digest {
            return Err(GovernorObservationError::IdentityConflict);
        }
        if let Some(plan) = &self.plan {
            plan.validate()?;
            if plan.state_fence != self.state_fence {
                return Err(GovernorObservationError::FenceMismatch);
            }
        }
        if let Some(selection) = &self.task_selection {
            selection.validate()?;
        }
        if let Some(value) = &self.evidence_digest {
            digest(value, "admission.evidence_digest")?;
            let evidence = self.evidence.as_ref().ok_or(
                GovernorObservationError::InvalidField {
                    field: "admission.evidence_digest",
                    reason: "requires retained evidence",
                },
            )?;
            let bytes = canonical_json_bytes(evidence)
                .map_err(|_| GovernorObservationError::Serialization)?;
            if value != &sha256_hex(&bytes) {
                return Err(GovernorObservationError::IdentityConflict);
            }
        } else if self.evidence.is_some() {
            return Err(GovernorObservationError::InvalidField {
                field: "admission.evidence_digest",
                reason: "retained evidence requires its digest",
            });
        }
        Ok(())
    }
}

/// Why a submission was not staged into the journal.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionDisposition {
    NotAccepted,
    Conflict,
}

/// Typed pre-stage rejection preserving a safe observation fallback.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationAdmissionRejection {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_digest: String,
    pub disposition: RejectionDisposition,
    pub all_contract_errors: Vec<String>,
    pub safe_capture_fallback: Option<ObservationCandidate>,
    pub corrected_retry_identity_rule: String,
    pub next_allowed_action: String,
}

impl ObservationAdmissionRejection {
    /// Validates a rejection loaded into a rebuilt journal projection.
    pub fn validate(&self) -> Result<(), GovernorObservationError> {
        text(&self.operation_id, "rejection.operation_id")?;
        text(&self.idempotency_key, "rejection.idempotency_key")?;
        digest(&self.request_digest, "rejection.request_digest")?;
        if self.all_contract_errors.is_empty() {
            return Err(GovernorObservationError::Empty {
                field: "rejection.all_contract_errors",
            });
        }
        for error in &self.all_contract_errors {
            text(error, "rejection.contract_error")?;
        }
        if let Some(candidate) = &self.safe_capture_fallback {
            candidate.validate()?;
        }
        text(
            &self.corrected_retry_identity_rule,
            "rejection.corrected_retry_identity_rule",
        )?;
        text(&self.next_allowed_action, "rejection.next_allowed_action")
    }
}

/// Stable result of one admission attempt.  Replays return the original
/// receipt/rejection rather than a second journal transition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum ObservationAdmissionResult {
    Accepted { receipt: ObservationAdmissionReceipt },
    Replayed { receipt: ObservationAdmissionReceipt },
    Rejected { rejection: ObservationAdmissionRejection },
}

/// One deterministic journal entry used to rebuild the Governor projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationJournalEntry {
    pub idempotency_key: String,
    pub request_digest: String,
    pub result: ObservationAdmissionResult,
}

/// Rebuildable Governor-owned observation journal projection.
#[derive(Clone, Debug, Default)]
pub struct ObservationJournal {
    entries: BTreeMap<String, ObservationJournalEntry>,
    record_keys: BTreeMap<String, String>,
    operation_keys: BTreeMap<String, String>,
}

impl ObservationJournal {
    /// Rebuilds a projection from immutable accepted/rejected entries.
    pub fn from_entries(
        entries: impl IntoIterator<Item = ObservationJournalEntry>,
    ) -> Result<Self, GovernorObservationError> {
        let mut journal = Self::default();
        for entry in entries {
            text(&entry.idempotency_key, "journal_entry.idempotency_key")?;
            digest(&entry.request_digest, "journal_entry.request_digest")?;
            match &entry.result {
                ObservationAdmissionResult::Accepted { receipt }
                | ObservationAdmissionResult::Replayed { receipt } => {
                    receipt.validate()?;
                    if receipt.idempotency_key != entry.idempotency_key
                        || receipt.request_digest != entry.request_digest
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                    if journal.record_keys.insert(
                        receipt.record_id.clone(),
                        entry.idempotency_key.clone(),
                    ).is_some()
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                    if journal.operation_keys.insert(
                        receipt.operation_id.clone(),
                        entry.idempotency_key.clone(),
                    ).is_some()
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                }
                ObservationAdmissionResult::Rejected { rejection } => {
                    if rejection.idempotency_key != entry.idempotency_key
                        || rejection.request_digest != entry.request_digest
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                    rejection.validate()?;
                }
            }
            if journal
                .entries
                .insert(entry.idempotency_key.clone(), entry)
                .is_some()
            {
                return Err(GovernorObservationError::IdentityConflict);
            }
        }
        Ok(journal)
    }

    /// Admits one observation, preserving exact rejection/replay identity.
    pub fn admit(
        &mut self,
        submission: ObservationSubmission,
    ) -> Result<ObservationAdmissionResult, GovernorObservationError> {
        let request_digest = submission.request_digest()?;
        if let Some(existing) = self.entries.get(&submission.idempotency_key) {
            if existing.request_digest == request_digest {
                return Ok(match &existing.result {
                    ObservationAdmissionResult::Accepted { receipt } => {
                        ObservationAdmissionResult::Replayed {
                            receipt: receipt.clone(),
                        }
                    }
                    ObservationAdmissionResult::Replayed { receipt } => {
                        ObservationAdmissionResult::Replayed {
                            receipt: receipt.clone(),
                        }
                    }
                    ObservationAdmissionResult::Rejected { rejection } => {
                        ObservationAdmissionResult::Rejected {
                            rejection: rejection.clone(),
                        }
                    }
                });
            }
            return Ok(self.rejection_result(
                &submission,
                request_digest,
                RejectionDisposition::Conflict,
                vec!["IDENTITY_CONFLICT".to_owned()],
                None,
            ));
        }
        if let Some(existing_key) = self.record_keys.get(submission.record_id()) {
            if existing_key != &submission.idempotency_key {
                return Ok(self.store_rejection(
                    &submission,
                    request_digest,
                    RejectionDisposition::Conflict,
                    vec!["IDENTITY_CONFLICT".to_owned()],
                    submission.candidate_fallback(),
                ));
            }
        }
        if let Some(existing_key) = self.operation_keys.get(&submission.operation_id) {
            if existing_key != &submission.idempotency_key {
                return Ok(self.rejection_result(
                    &submission,
                    request_digest,
                    RejectionDisposition::Conflict,
                    vec!["IDENTITY_CONFLICT".to_owned()],
                    submission.candidate_fallback(),
                ));
            }
        }
        if let Err(error) = submission.validate() {
            return Ok(self.store_rejection(
                &submission,
                request_digest,
                RejectionDisposition::NotAccepted,
                vec![error.to_string()],
                submission.candidate_fallback(),
            ));
        }
        let evidence_digest = submission
            .evidence
            .as_ref()
            .map(|evidence| canonical_json_bytes(evidence).map(|bytes| sha256_hex(&bytes)))
            .transpose()
            .map_err(|_| GovernorObservationError::Serialization)?;
        let receipt = ObservationAdmissionReceipt {
            operation_id: submission.operation_id.clone(),
            idempotency_key: submission.idempotency_key.clone(),
            record_id: submission.record_id().to_owned(),
            request_digest: request_digest.clone(),
            state_fence: submission.state_fence.clone(),
            record: submission.record.clone(),
            evidence: submission.evidence.clone(),
            capture_route: submission.capture_route,
            durability: submission.durability,
            candidate_disposition: submission.candidate_disposition(),
            plan: submission.plan.clone(),
            task_selection: submission.task_selection.clone(),
            evidence_digest,
        };
        let result = ObservationAdmissionResult::Accepted {
            receipt: receipt.clone(),
        };
        self.record_keys.insert(
            receipt.record_id.clone(),
            submission.idempotency_key.clone(),
        );
        self.operation_keys.insert(
            receipt.operation_id.clone(),
            submission.idempotency_key.clone(),
        );
        self.entries.insert(
            submission.idempotency_key.clone(),
            ObservationJournalEntry {
                idempotency_key: submission.idempotency_key,
                request_digest,
                result: result.clone(),
            },
        );
        Ok(result)
    }

    fn store_rejection(
        &mut self,
        submission: &ObservationSubmission,
        request_digest: String,
        disposition: RejectionDisposition,
        errors: Vec<String>,
        safe_capture_fallback: Option<ObservationCandidate>,
    ) -> ObservationAdmissionResult {
        let result = self.rejection_result(
            submission,
            request_digest.clone(),
            disposition,
            errors,
            safe_capture_fallback,
        );
        self.entries.insert(
            submission.idempotency_key.clone(),
            ObservationJournalEntry {
                idempotency_key: submission.idempotency_key.clone(),
                request_digest,
                result: result.clone(),
            },
        );
        result
    }

    fn rejection_result(
        &self,
        submission: &ObservationSubmission,
        request_digest: String,
        disposition: RejectionDisposition,
        errors: Vec<String>,
        safe_capture_fallback: Option<ObservationCandidate>,
    ) -> ObservationAdmissionResult {
        let rejection = ObservationAdmissionRejection {
            operation_id: submission.operation_id.clone(),
            idempotency_key: submission.idempotency_key.clone(),
            request_digest: request_digest.clone(),
            disposition,
            all_contract_errors: errors,
            safe_capture_fallback,
            corrected_retry_identity_rule:
                "corrected payload requires a new operation and idempotency identity".to_owned(),
            next_allowed_action: "preserve the candidate or correct the bounded contract errors".to_owned(),
        };
        ObservationAdmissionResult::Rejected { rejection }
    }

    /// Returns deterministic journal entries for checkpoint/rebuild.
    pub fn snapshot(&self) -> Vec<ObservationJournalEntry> {
        self.entries.values().cloned().collect()
    }

    /// Looks up the original admission by retry identity.
    pub fn get(&self, idempotency_key: &str) -> Option<&ObservationJournalEntry> {
        self.entries.get(idempotency_key)
    }
}

/// Compiles the Governor-owned plan projection from admitted obligation
/// profiles.  Producers cannot self-certify a plan by merely reporting events.
pub fn compile_plan(
    plan_id: impl Into<String>,
    plan_revision: impl Into<String>,
    state_fence: StateFence,
    activation_and_governance_profile: impl Into<String>,
    profiles: &[ObservationObligationProfile],
    observable_sources: Vec<String>,
    unobservable_sources: Vec<String>,
    cursor_ranges: Vec<CoverageInterval>,
    known_blind_intervals: Vec<BlindInterval>,
    expiry_and_recompile_triggers: Vec<String>,
) -> Result<ActiveObservationPlan, GovernorObservationError> {
    if profiles.is_empty() {
        return Err(GovernorObservationError::Empty {
            field: "obligation_profiles",
        });
    }
    let mut profile_refs = Vec::with_capacity(profiles.len());
    let mut expected_denominators = Vec::with_capacity(profiles.len());
    let mut protected_event_classes = BTreeMap::new();
    for profile in profiles {
        profile.validate()?;
        profile_refs.push(profile.profile_id.clone());
        expected_denominators.push(profile.denominator.clone());
        if profile.minimum_durability == Durability::Protected {
            for event_kind in &profile.expected_event_classes {
                protected_event_classes
                    .entry(format!("{event_kind:?}"))
                    .or_insert(*event_kind);
            }
        }
    }
    unique(profile_refs.iter(), "obligation_profiles")?;
    let plan = ActiveObservationPlan {
        plan_id: plan_id.into(),
        plan_revision: plan_revision.into(),
        state_fence,
        activation_and_governance_profile: activation_and_governance_profile.into(),
        admitted_obligation_profile_refs: profile_refs,
        observable_sources,
        unobservable_sources,
        expected_denominators,
        cursor_ranges,
        protected_event_classes: protected_event_classes.into_values().collect(),
        known_blind_intervals,
        expiry_and_recompile_triggers,
    };
    plan.validate()?;
    Ok(plan)
}

/// Returns the content-addressed identity of this Governor contract.
pub fn contract_identity() -> Result<ContractIdentity, GovernorObservationError> {
    foundation_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "plan_binding": schemars::schema_for!(ObservationPlanBinding),
            "task_selection": schemars::schema_for!(TaskSelectionEvidence),
            "candidate": schemars::schema_for!(ObservationCandidate),
            "submission": schemars::schema_for!(ObservationSubmission),
            "admission": schemars::schema_for!(ObservationAdmissionReceipt),
            "rejection": schemars::schema_for!(ObservationAdmissionRejection),
            "journal_entry": schemars::schema_for!(ObservationJournalEntry),
        }),
    )
    .map_err(GovernorObservationError::Foundation)
}
