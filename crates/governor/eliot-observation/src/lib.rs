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
    ActiveObservationPlan, AmbiguousOrdinaryRecordV2, BlindInterval, CaptureMode, CaptureRoute,
    CoverageAssessment, CoverageDisposition, CoverageEvidence, CoverageGap, CoverageInterval,
    DenominatorSpec, Durability, EliotSystemObservationEvent, GapDisposition, GapPolicy,
    ObservationEventCore, ObservationEventIdentity, ObservationKind, ObservationObligationProfile,
    ObservationRecordEnvelope, ObservationRecordEnvelopeV2, ObservationRecordKind,
    ObservationScope, PrivacyRetentionDisclosure, ProducerGenerationRef, ProducerTrace,
    RecordFamilyClassification, RecordFamilyContractError, RecordFamilyPayloadV2, SamplingPolicy,
    SystemObservationJournalRecord,
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
    /// The v2 record-family contract rejected a family payload or migration.
    #[error("record-family contract: {0}")]
    RecordFamily(RecordFamilyContractError),
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
    /// A replay marker is a transient result and cannot be persisted as input.
    #[error("persisted replay result is not canonical journal input")]
    PersistedReplay,
    /// A non-exact v2 family record is retained cold rather than accepted.
    #[error("non-exact v2 record-family material remains cold: {disposition:?}")]
    RecordFamilyNotAccepted {
        /// Classification retained for the cold fallback.
        disposition: RecordFamilyClassification,
    },
    /// A task-bound observation did not include exact selection evidence.
    #[error("task selection evidence is required")]
    TaskSelectionRequired,
    /// Selection evidence names a different task or `WorkScope`.
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

impl From<RecordFamilyContractError> for GovernorObservationError {
    fn from(error: RecordFamilyContractError) -> Self {
        Self::RecordFamily(error)
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

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), GovernorObservationError> {
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
    /// `WorkScope` identity used by the selection.
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
        text(
            &self.selection_source_ref,
            "task_selection.selection_source_ref",
        )?;
        text(&self.evidence_ref, "task_selection.evidence_ref")?;
        unique(
            &self.contamination_flags,
            "task_selection.contamination_flags",
        )?;
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

/// Governor's bounded consumer decision for a v2 family payload.
///
/// Only field-complete v2 payloads can enter the accepted path. Generic
/// ordinary material remains cold, even when it carries a compatible caller
/// hint; later classifier work may preserve it but cannot promote it here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum RecordFamilyAdmission {
    /// Exact family evidence is eligible for the normal Governor path.
    AcceptedExact {
        /// Mechanically established family.
        family: ObservationRecordKind,
    },
    /// The record is preserved as cold material and is not accepted.
    Cold {
        /// Non-exact classification retained for a later bounded decision.
        classification: RecordFamilyClassification,
    },
}

/// Validates the v2 record at the real Governor consumer boundary.
pub fn admit_record_family_v2(
    record: &ObservationRecordEnvelopeV2,
) -> Result<RecordFamilyAdmission, GovernorObservationError> {
    match record.classification()? {
        RecordFamilyClassification::Exact { family } => {
            Ok(RecordFamilyAdmission::AcceptedExact { family })
        }
        classification => Ok(RecordFamilyAdmission::Cold { classification }),
    }
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
    /// Optional family-complete v2 record for the additive admission edge.
    #[serde(default)]
    pub record_v2: Option<ObservationRecordEnvelopeV2>,
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
        if let Some(record_v2) = &self.record_v2 {
            eliot_observation_contracts::check_v1_v2_coherence(&self.record, record_v2)?;
            if let RecordFamilyAdmission::Cold { classification } =
                admit_record_family_v2(record_v2)?
            {
                return Err(GovernorObservationError::RecordFamilyNotAccepted {
                    disposition: classification,
                });
            }
        }
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
        if let Some(gap) = &self.record.coverage_gap
            && gap.protected
            && (self.durability != Durability::Protected
                || !route_supports(self.capture_route, Durability::Protected))
        {
            return Err(GovernorObservationError::InsufficientDurability);
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
        let bytes =
            canonical_json_bytes(self).map_err(|_| GovernorObservationError::Serialization)?;
        Ok(sha256_hex(&bytes))
    }

    fn candidate_fallback(&self) -> Option<ObservationCandidate> {
        if self.record.validate().is_err() {
            return None;
        }
        let valid_selection = self.task_selection.as_ref().filter(|selection| {
            if selection.validate().is_err() {
                return false;
            }
            let Some(event) = &self.record.event else {
                return false;
            };
            let Some(task_ref) = &event.affected_scope.task_ref else {
                return false;
            };
            selection.task_ref == *task_ref
                && selection.work_scope_ref == event.affected_scope.work_scope.as_str()
        });
        let (disposition, reason_ref) = match valid_selection {
            Some(selection) if selection.is_contaminated() => (
                CandidateDisposition::Quarantined,
                "task-selection-contaminated",
            ),
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
        candidate.validate().ok().map(|()| candidate)
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
    /// Optional family-complete v2 record retained by the additive path.
    #[serde(default)]
    pub record_v2: Option<ObservationRecordEnvelopeV2>,
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
        if let Some(record_v2) = &self.record_v2 {
            eliot_observation_contracts::check_v1_v2_coherence(&self.record, record_v2)?;
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
            record_v2: self.record_v2.clone(),
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
        if self.candidate_disposition != request.candidate_disposition() {
            return Err(GovernorObservationError::InvalidField {
                field: "admission.candidate_disposition",
                reason: "must equal the disposition derived from the submission",
            });
        }
        if let Some(value) = &self.evidence_digest {
            digest(value, "admission.evidence_digest")?;
            let evidence =
                self.evidence
                    .as_ref()
                    .ok_or(GovernorObservationError::InvalidField {
                        field: "admission.evidence_digest",
                        reason: "requires retained evidence",
                    })?;
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
    Accepted {
        receipt: ObservationAdmissionReceipt,
    },
    Replayed {
        receipt: ObservationAdmissionReceipt,
    },
    Rejected {
        rejection: ObservationAdmissionRejection,
    },
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
                ObservationAdmissionResult::Accepted { receipt } => {
                    receipt.validate()?;
                    if receipt.idempotency_key != entry.idempotency_key
                        || receipt.request_digest != entry.request_digest
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                    if journal
                        .record_keys
                        .insert(receipt.record_id.clone(), entry.idempotency_key.clone())
                        .is_some()
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                    if journal
                        .operation_keys
                        .insert(receipt.operation_id.clone(), entry.idempotency_key.clone())
                        .is_some()
                    {
                        return Err(GovernorObservationError::IdentityConflict);
                    }
                }
                ObservationAdmissionResult::Replayed { .. } => {
                    return Err(GovernorObservationError::PersistedReplay);
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
    #[allow(
        clippy::too_many_lines,
        reason = "admission policy checks remain in explicit priority order"
    )]
    pub fn admit(
        &mut self,
        submission: ObservationSubmission,
    ) -> Result<ObservationAdmissionResult, GovernorObservationError> {
        let request_digest = submission.request_digest()?;
        if let Some(existing) = self.entries.get(&submission.idempotency_key) {
            if existing.request_digest == request_digest {
                return Ok(match &existing.result {
                    ObservationAdmissionResult::Accepted { receipt }
                    | ObservationAdmissionResult::Replayed { receipt } => {
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
            return Ok(Self::rejection_result(
                &submission,
                &request_digest,
                RejectionDisposition::Conflict,
                vec!["IDENTITY_CONFLICT".to_owned()],
                None,
            ));
        }
        if let Some(existing_key) = self.record_keys.get(submission.record_id())
            && existing_key != &submission.idempotency_key
        {
            return Ok(self.store_rejection(
                &submission,
                request_digest,
                RejectionDisposition::Conflict,
                vec!["IDENTITY_CONFLICT".to_owned()],
                submission.candidate_fallback(),
            ));
        }
        if let Some(existing_key) = self.operation_keys.get(&submission.operation_id)
            && existing_key != &submission.idempotency_key
        {
            return Ok(Self::rejection_result(
                &submission,
                &request_digest,
                RejectionDisposition::Conflict,
                vec!["IDENTITY_CONFLICT".to_owned()],
                submission.candidate_fallback(),
            ));
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
            record_v2: submission.record_v2.clone(),
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
        let result = Self::rejection_result(
            submission,
            &request_digest,
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
        submission: &ObservationSubmission,
        request_digest: &str,
        disposition: RejectionDisposition,
        errors: Vec<String>,
        safe_capture_fallback: Option<ObservationCandidate>,
    ) -> ObservationAdmissionResult {
        let rejection = ObservationAdmissionRejection {
            operation_id: submission.operation_id.clone(),
            idempotency_key: submission.idempotency_key.clone(),
            request_digest: request_digest.to_owned(),
            disposition,
            all_contract_errors: errors,
            safe_capture_fallback,
            corrected_retry_identity_rule:
                "corrected payload requires a new operation and idempotency identity".to_owned(),
            next_allowed_action: "preserve the candidate or correct the bounded contract errors"
                .to_owned(),
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
#[allow(
    clippy::too_many_arguments,
    reason = "the public API keeps plan dimensions explicit for stable callers"
)]
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
            "record_family_admission": schemars::schema_for!(RecordFamilyAdmission),
            "submission": schemars::schema_for!(ObservationSubmission),
            "admission": schemars::schema_for!(ObservationAdmissionReceipt),
            "rejection": schemars::schema_for!(ObservationAdmissionRejection),
            "journal_entry": schemars::schema_for!(ObservationJournalEntry),
        }),
    )
    .map_err(GovernorObservationError::Foundation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ClockReading, ResourceGeneration};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn event() -> ObservationEventCore {
        let Ok(work_scope) = "scope:test".parse() else {
            unreachable!("fixture work scope is valid")
        };
        let Ok(interval) = CoverageInterval::new(1, 1) else {
            unreachable!("fixture interval is valid")
        };
        ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: "event:test".to_owned(),
                clock: ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "producer:test".to_owned(),
                generation: "generation:test".to_owned(),
                trace_ref: None,
            },
            kind: ObservationKind::QueueResource,
            affected_scope: ObservationScope {
                work_scope,
                task_ref: None,
                attempt_ref: None,
                module_or_route_ref: None,
            },
            observed_delta: "queue observed".to_owned(),
            expected_baseline: None,
            evidence_and_raw_handles: vec!["raw:test".to_owned()],
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: "denominator:test".to_owned(),
                interval: Some(interval),
                blind_intervals: Vec::new(),
                observed_count: 1,
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "privacy:test".to_owned(),
                retention_policy_ref: "retention:test".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: "dedup:test".to_owned(),
        }
    }

    fn v1_submission() -> ObservationSubmission {
        ObservationSubmission {
            operation_id: "operation:test".to_owned(),
            idempotency_key: "idempotency:test".to_owned(),
            state_fence: fence(),
            record: ObservationRecordEnvelope {
                record_id: "record:test".to_owned(),
                kind: ObservationRecordKind::Telemetry,
                event: Some(event()),
                coverage_gap: None,
                journal_control_event: false,
                parent_record_id: None,
            },
            capture_route: CaptureRoute::OperationalLog,
            durability: Durability::Volatile,
            plan: None,
            task_selection: None,
            evidence: None,
            record_v2: None,
        }
    }

    #[test]
    fn v2_compatible_hint_is_cold_at_governor_boundary() {
        let record = ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                record_id: "record:ambiguous".to_owned(),
                event: event(),
                source_contract_ref: "source:generic".to_owned(),
                ambiguity_reason_ref: "family-fields-unavailable".to_owned(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        };
        assert_eq!(
            admit_record_family_v2(&record)
                .unwrap_or_else(|error| { panic!("valid v2 record rejected: {error}") }),
            RecordFamilyAdmission::Cold {
                classification: RecordFamilyClassification::CompatibleHint {
                    hinted_family: ObservationRecordKind::Telemetry,
                },
            }
        );
    }

    #[test]
    fn v2_exact_family_reaches_the_bounded_governor_edge() {
        let record = ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:audit".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        };
        assert_eq!(
            admit_record_family_v2(&record)
                .unwrap_or_else(|error| { panic!("valid v2 record rejected: {error}") }),
            RecordFamilyAdmission::AcceptedExact {
                family: ObservationRecordKind::Audit,
            }
        );
    }

    #[test]
    fn journal_admission_rejects_v2_compatible_material_as_cold() {
        let mut submission = v1_submission();
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                record_id: "record:test".to_owned(),
                event: event(),
                source_contract_ref: "source:generic".to_owned(),
                ambiguity_reason_ref: "family-fields-unavailable".to_owned(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|error| panic!("admission failed: {error}"));
        let ObservationAdmissionResult::Rejected { rejection } = result else {
            panic!("compatible material must not be accepted");
        };
        assert!(
            rejection
                .all_contract_errors
                .iter()
                .any(|error| error.contains("non-exact v2 record-family"))
        );
        assert_eq!(
            rejection
                .safe_capture_fallback
                .map(|candidate| candidate.disposition),
            Some(CandidateDisposition::Cold)
        );
    }

    #[test]
    fn journal_admission_retains_an_exact_v2_receipt() {
        let mut submission = v1_submission();
        submission.record.kind = ObservationRecordKind::Audit;
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|error| panic!("admission failed: {error}"));
        let ObservationAdmissionResult::Accepted { receipt } = result else {
            panic!("exact v2 material should be accepted");
        };
        assert!(receipt.record_v2.is_some());
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn receipt_candidate_disposition_is_derived_not_caller_selected() {
        let submission = v1_submission();
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|error| panic!("admission failed: {error}"));
        let ObservationAdmissionResult::Accepted { mut receipt } = result else {
            panic!("expected accepted receipt");
        };
        receipt.candidate_disposition = CandidateDisposition::TaskBound;
        assert!(matches!(
            receipt.validate(),
            Err(GovernorObservationError::InvalidField {
                field: "admission.candidate_disposition",
                ..
            })
        ));
    }

    #[test]
    fn persisted_replayed_entry_is_rejected_during_rebuild() {
        let submission = v1_submission();
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|error| panic!("admission failed: {error}"));
        let ObservationAdmissionResult::Accepted { receipt } = result else {
            panic!("expected accepted receipt");
        };
        let entry = ObservationJournalEntry {
            idempotency_key: receipt.idempotency_key.clone(),
            request_digest: receipt.request_digest.clone(),
            result: ObservationAdmissionResult::Replayed { receipt },
        };
        assert!(matches!(
            ObservationJournal::from_entries([entry]),
            Err(GovernorObservationError::PersistedReplay)
        ));
    }
    #[test]
    fn coherence_rejects_telemetry_v1_with_audit_v2() {
        let mut submission = v1_submission();
        // v1 is Telemetry, v2 is Audit with same record_id => family mismatch
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|error| panic!("admission failed: {error}"));
        let ObservationAdmissionResult::Rejected { rejection } = result else {
            panic!("telemetry/audit mismatch must be rejected");
        };
        assert!(
            rejection
                .all_contract_errors
                .iter()
                .any(|e| e.contains("family mismatch") || e.contains("ShapeConflict"))
        );
    }

    #[test]
    fn coherence_journal_control_audit_mapping() {
        // Wrong non-Audit family should reject
        let mut wrong = v1_submission();
        wrong.record.kind = ObservationRecordKind::Audit;
        wrong.record.journal_control_event = true;
        wrong.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Telemetry(
                eliot_observation_contracts::TelemetryRecord {
                    record_id: "record:test".to_owned(),
                    core: event(),
                    capture_mode: CaptureMode::Sampled,
                    sample_count: 1,
                    raw_evidence_handle: Some("blob:1".to_owned()),
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(wrong)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        assert!(
            matches!(result, ObservationAdmissionResult::Rejected { .. }),
            "journal-control with wrong family must reject"
        );

        // Correct JournalControlAudit mapping must accept
        let mut correct = v1_submission();
        correct.record.kind = ObservationRecordKind::Audit;
        correct.record.journal_control_event = true;
        correct.record.record_id = "record:control".to_owned();
        correct.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::JournalControlAudit(
                eliot_observation_contracts::JournalControlAuditRecordV2 {
                    record_id: "record:control".to_owned(),
                    event: event(),
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        // v1 also needs event for Audit? journal_control true already has event
        let mut journal2 = ObservationJournal::default();
        let result2 = journal2
            .admit(correct)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        let ObservationAdmissionResult::Accepted { receipt } = result2 else {
            panic!("correct journal-control audit mapping must be accepted");
        };
        assert!(receipt.validate().is_ok());
        assert!(receipt.record.journal_control_event);
    }

    #[test]
    fn coherence_coverage_mismatch_rejected() {
        let mut submission = v1_submission();
        // v1 is CoverageGap but v2 is Telemetry => mismatch
        submission.record.kind = ObservationRecordKind::CoverageGap;
        submission.record.event = None;
        submission.record.coverage_gap = Some(eliot_observation_contracts::CoverageGap {
            gap_id: "gap:1".to_owned(),
            obligation_profile_ref: "profile:1".to_owned(),
            reason_ref: "reason:1".to_owned(),
            affected_interval: None,
            disposition: GapDisposition::DegradeDependentGuarantees,
            protected: false,
            evidence_refs: vec!["evidence:1".to_owned()],
        });
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Telemetry(
                eliot_observation_contracts::TelemetryRecord {
                    record_id: "record:test".to_owned(),
                    core: event(),
                    capture_mode: CaptureMode::Sampled,
                    sample_count: 1,
                    raw_evidence_handle: Some("blob:1".to_owned()),
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        assert!(
            matches!(result, ObservationAdmissionResult::Rejected { .. }),
            "coverage mismatch must reject"
        );
    }

    #[test]
    fn coherence_parent_mismatch_rejected() {
        let mut submission = v1_submission();
        submission.record.kind = ObservationRecordKind::Audit;
        submission.record.parent_record_id = Some("parent:1".to_owned());
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: Some("parent:2".to_owned()),
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        assert!(
            matches!(result, ObservationAdmissionResult::Rejected { .. }),
            "parent mismatch must reject"
        );

        // presence contradiction: v1 has parent, v2 None
        let mut submission2 = v1_submission();
        submission2.record.kind = ObservationRecordKind::Audit;
        submission2.record.parent_record_id = Some("parent:1".to_owned());
        submission2.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        let mut journal2 = ObservationJournal::default();
        let result2 = journal2
            .admit(submission2)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        assert!(
            matches!(result2, ObservationAdmissionResult::Rejected { .. }),
            "parent presence contradiction must reject"
        );
    }

    #[test]
    fn coherence_caller_hint_conflict_remains_fail_closed() {
        // v2 payload Audit with hint Telemetry => FamilyHintConflict
        let mut submission = v1_submission();
        submission.record.kind = ObservationRecordKind::Audit;
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        let ObservationAdmissionResult::Rejected { rejection } = result else {
            panic!("hint conflict must be rejected");
        };
        assert!(
            rejection
                .all_contract_errors
                .iter()
                .any(|e| e.contains("hint")
                    || e.contains("FamilyHintConflict")
                    || e.contains("family"))
        );
    }

    #[test]
    fn coherence_persisted_contradictory_receipt_rejected_on_rebuild() {
        // Build a valid accepted receipt then tamper v2 to be contradictory
        let mut submission = v1_submission();
        submission.record.kind = ObservationRecordKind::Audit;
        submission.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        let mut journal = ObservationJournal::default();
        let result = journal
            .admit(submission)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        let ObservationAdmissionResult::Accepted { mut receipt } = result else {
            panic!("expected accepted");
        };
        // tamper receipt to have contradictory family: change v2 to Telemetry but keep v1 Audit
        receipt.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Telemetry(
                eliot_observation_contracts::TelemetryRecord {
                    record_id: "record:test".to_owned(),
                    core: event(),
                    capture_mode: CaptureMode::Sampled,
                    sample_count: 1,
                    raw_evidence_handle: Some("blob:1".to_owned()),
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        // receipt.validate should now fail closed
        assert!(
            receipt.validate().is_err(),
            "contradictory persisted receipt must fail validation"
        );
        // rebuild must also fail
        let entry = ObservationJournalEntry {
            idempotency_key: receipt.idempotency_key.clone(),
            request_digest: receipt.request_digest.clone(),
            result: ObservationAdmissionResult::Accepted { receipt },
        };
        assert!(
            ObservationJournal::from_entries([entry]).is_err(),
            "rebuild with contradictory receipt must reject"
        );
        // also test parent contradiction in persisted receipt
        let mut submission2 = v1_submission();
        submission2.record.kind = ObservationRecordKind::Audit;
        submission2.record.parent_record_id = None;
        submission2.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(eliot_observation_contracts::AuditRecord {
                record_id: "record:test2".to_owned(),
                core: event(),
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        });
        submission2.operation_id = "operation:test2".to_owned();
        submission2.idempotency_key = "idempotency:test2".to_owned();
        submission2.record.record_id = "record:test2".to_owned();
        let mut journal2 = ObservationJournal::default();
        let result2 = journal2
            .admit(submission2)
            .unwrap_or_else(|e| panic!("admission failed: {e}"));
        let ObservationAdmissionResult::Accepted {
            receipt: mut receipt2,
        } = result2
        else {
            panic!("expected accepted2");
        };
        // tamper parent to mismatch
        receipt2.record.parent_record_id = Some("parent:tampered".to_owned());
        // v2 still has None, so coherence fails
        assert!(
            receipt2.validate().is_err(),
            "parent contradictory persisted receipt must fail"
        );
        assert!(
            ObservationJournal::from_entries([ObservationJournalEntry {
                idempotency_key: receipt2.idempotency_key.clone(),
                request_digest: receipt2.request_digest.clone(),
                result: ObservationAdmissionResult::Accepted { receipt: receipt2 },
            }])
            .is_err()
        );
    }

    #[test]
    fn positive_aligned_exact_family_deterministic_and_byte_stable() {
        // Telemetry aligned
        let mut sub = v1_submission();
        sub.operation_id = "op:pos1".to_owned();
        sub.idempotency_key = "idem:pos1".to_owned();
        sub.record.record_id = "record:pos1".to_owned();
        sub.record.kind = ObservationRecordKind::Telemetry;
        sub.record_v2 = Some(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Telemetry(
                eliot_observation_contracts::TelemetryRecord {
                    record_id: "record:pos1".to_owned(),
                    core: event(),
                    capture_mode: CaptureMode::Sampled,
                    sample_count: 2,
                    raw_evidence_handle: Some("blob:pos1".to_owned()),
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        });
        let mut j1 = ObservationJournal::default();
        let r1 = j1
            .admit(sub.clone())
            .unwrap_or_else(|e| panic!("admit failed: {e}"));
        let mut j2 = ObservationJournal::default();
        let r2 = j2
            .admit(sub.clone())
            .unwrap_or_else(|e| panic!("admit failed: {e}"));
        assert_eq!(r1, r2, "aligned submission must be deterministic");
        if let ObservationAdmissionResult::Accepted { receipt } = r1 {
            let bytes1 =
                serde_json::to_vec(&receipt).unwrap_or_else(|e| panic!("serde failed: {e}"));
            let bytes2 =
                serde_json::to_vec(&receipt).unwrap_or_else(|e| panic!("serde failed: {e}"));
            assert_eq!(bytes1, bytes2);
            // rebuild from persisted entry must succeed and preserve receipt
            let entry = ObservationJournalEntry {
                idempotency_key: receipt.idempotency_key.clone(),
                request_digest: receipt.request_digest.clone(),
                result: ObservationAdmissionResult::Accepted {
                    receipt: receipt.clone(),
                },
            };
            let rebuilt = ObservationJournal::from_entries([entry])
                .unwrap_or_else(|e| panic!("rebuild failed: {e}"));
            let snap = rebuilt.snapshot();
            assert_eq!(snap.len(), 1);
            // cold semantics: ambiguous remains cold
            let mut cold_sub = v1_submission();
            cold_sub.operation_id = "op:cold".to_owned();
            cold_sub.idempotency_key = "idem:cold".to_owned();
            cold_sub.record.record_id = "record:cold".to_owned();
            cold_sub.record.kind = ObservationRecordKind::Telemetry;
            cold_sub.record_v2 = Some(ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                    record_id: "record:cold".to_owned(),
                    event: event(),
                    source_contract_ref: "source:generic".to_owned(),
                    ambiguity_reason_ref: "family-fields-unavailable".to_owned(),
                }),
                caller_family_hint: Some(ObservationRecordKind::Telemetry),
                parent_record_id: None,
            });
            let mut jc = ObservationJournal::default();
            let cr = jc
                .admit(cold_sub)
                .unwrap_or_else(|e| panic!("admit failed: {e}"));
            assert!(
                matches!(cr, ObservationAdmissionResult::Rejected { .. }),
                "ambiguous must remain cold"
            );
        } else {
            panic!("positive aligned must be accepted");
        }
    }
}
