#![forbid(unsafe_code)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

pub const CONTRACT_NAME: &str = "eliot.meta.doctor";
pub const CONTRACT_VERSION: &str = "1.0.0";
pub const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
pub const RECIPE_DIGEST_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairClass {
    AutomaticSafe,
    Guarded,
    DiagnoseOnly,
}

impl RepairClass {
    pub fn can_execute(self) -> bool {
        !matches!(self, Self::DiagnoseOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Requested,
    Admitted,
    Diagnosing,
    ReadyForRepair,
    Running,
    Verifying,
    Succeeded,
    Failed,
    Partial,
    Cancelled,
    Quarantined,
    Escalated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceHandle {
    pub reference: String,
    pub digest: String,
}

impl EvidenceHandle {
    pub fn new(
        reference: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, DoctorError> {
        let value = Self {
            reference: reference.into(),
            digest: digest.into(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        text(&self.reference, "evidence reference")?;
        hex_digest(&self.digest, "evidence digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateFence {
    pub authority_epoch: u64,
    pub generation: u64,
    pub digest: String,
}

impl StateFence {
    pub fn new(
        authority_epoch: u64,
        generation: u64,
        digest: impl Into<String>,
    ) -> Result<Self, DoctorError> {
        let fence = Self {
            authority_epoch,
            generation,
            digest: digest.into(),
        };
        fence.validate()?;
        Ok(fence)
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        if self.authority_epoch == 0 {
            return Err(DoctorError::InvalidFence);
        }
        if self.generation == 0 {
            return Err(DoctorError::InvalidFence);
        }
        hex_digest(&self.digest, "state fence digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryLease {
    pub lease_id: String,
    pub owner: String,
    pub expires_at: OffsetDateTime,
    pub allowed_effects: BTreeSet<String>,
}

impl RecoveryLease {
    pub fn validate_at(&self, now: OffsetDateTime) -> Result<(), DoctorError> {
        text(&self.lease_id, "lease id")?;
        text(&self.owner, "lease owner")?;
        if self.expires_at <= now {
            return Err(DoctorError::LeaseExpired);
        }
        if self.allowed_effects.iter().any(|e| e.trim().is_empty()) {
            return Err(DoctorError::MissingField("allowed_effects"));
        }
        Ok(())
    }
    pub fn permits(&self, effect: &str) -> bool {
        self.allowed_effects.contains(effect)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticBrief {
    pub problem_id: String,
    pub component: String,
    pub failure_class: String,
    pub symptom: String,
    pub impact: String,
    pub evidence: Vec<EvidenceHandle>,
    pub unknowns: Vec<String>,
}

impl DiagnosticBrief {
    pub fn validate(&self) -> Result<(), DoctorError> {
        for (value, name) in [
            (&self.problem_id, "problem id"),
            (&self.component, "component"),
            (&self.failure_class, "failure class"),
            (&self.symptom, "symptom"),
            (&self.impact, "impact"),
        ] {
            text(value, name)?;
        }
        if self.evidence.is_empty() {
            return Err(DoctorError::MissingField("evidence"));
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        if self.unknowns.iter().any(|item| item.trim().is_empty()) {
            return Err(DoctorError::InvalidText("unknown"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepairRecipe {
    pub recipe_id: String,
    pub revision: u64,
    pub problem_classes: BTreeSet<String>,
    pub components: BTreeSet<String>,
    pub repair_class: RepairClass,
    pub prerequisites: Vec<String>,
    pub required_authority: String,
    pub allowed_effects: BTreeSet<String>,
    pub operations: Vec<String>,
    pub expected_observables: Vec<String>,
    pub verification_contract: Vec<String>,
    pub rollback_or_compensation: Vec<String>,
    pub attempt_budget: u32,
    pub cooldown: Duration,
    pub stop_conditions: Vec<String>,
}

impl RepairRecipe {
    pub fn validate(&self) -> Result<(), DoctorError> {
        text(&self.recipe_id, "recipe id")?;
        if self.revision == 0 || self.attempt_budget == 0 {
            return Err(DoctorError::InvalidBudget);
        }
        if self.problem_classes.is_empty() || self.components.is_empty() {
            return Err(DoctorError::MissingField("recipe scope"));
        }
        if !matches!(self.repair_class, RepairClass::DiagnoseOnly)
            && self.allowed_effects.is_empty()
        {
            return Err(DoctorError::MissingField("allowed effects"));
        }
        text(&self.required_authority, "required authority")?;
        if (!matches!(self.repair_class, RepairClass::DiagnoseOnly) && self.operations.is_empty())
            || self.expected_observables.is_empty()
            || self.verification_contract.is_empty()
        {
            return Err(DoctorError::MissingField("recipe contract"));
        }
        if self.cooldown.is_negative() {
            return Err(DoctorError::InvalidBudget);
        }
        if matches!(self.repair_class, RepairClass::DiagnoseOnly)
            && (!self.allowed_effects.is_empty() || !self.operations.is_empty())
        {
            return Err(DoctorError::DiagnoseEffects);
        }
        Ok(())
    }

    /// Digest of the exact recipe contract. It is compared with the digest
    /// issued by Kernel; Doctor never substitutes a local recipe.
    pub fn digest(&self) -> String {
        let mut hasher = Hasher::new();
        hash_field(&mut hasher, b"version", &[RECIPE_DIGEST_VERSION]);
        hash_field(&mut hasher, b"recipe_id", self.recipe_id.as_bytes());
        hash_field(&mut hasher, b"revision", &self.revision.to_le_bytes());
        hash_field(
            &mut hasher,
            b"repair_class",
            &[match self.repair_class {
                RepairClass::AutomaticSafe => 0,
                RepairClass::Guarded => 1,
                RepairClass::DiagnoseOnly => 2,
            }],
        );
        hash_field(
            &mut hasher,
            b"required_authority",
            self.required_authority.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"attempt_budget",
            &self.attempt_budget.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"cooldown_nanoseconds",
            &self.cooldown.whole_nanoseconds().to_le_bytes(),
        );
        hash_set(&mut hasher, b"problem_classes", &self.problem_classes);
        hash_set(&mut hasher, b"components", &self.components);
        hash_set(&mut hasher, b"allowed_effects", &self.allowed_effects);
        hash_list(&mut hasher, b"prerequisites", &self.prerequisites);
        hash_list(&mut hasher, b"operations", &self.operations);
        hash_list(
            &mut hasher,
            b"expected_observables",
            &self.expected_observables,
        );
        hash_list(
            &mut hasher,
            b"verification_contract",
            &self.verification_contract,
        );
        hash_list(
            &mut hasher,
            b"rollback_or_compensation",
            &self.rollback_or_compensation,
        );
        hash_list(&mut hasher, b"stop_conditions", &self.stop_conditions);
        hasher.finalize().to_hex().to_string()
    }
    pub fn applies_to(&self, brief: &DiagnosticBrief) -> bool {
        self.problem_classes.contains(&brief.failure_class)
            && self.components.contains(&brief.component)
    }
}

fn hash_field(hasher: &mut Hasher, name: &[u8], value: &[u8]) {
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(name);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_set(hasher: &mut Hasher, name: &[u8], values: &BTreeSet<String>) {
    hash_field(hasher, name, &(values.len() as u64).to_le_bytes());
    for value in values {
        hash_field(hasher, b"value", value.as_bytes());
    }
}

fn hash_list(hasher: &mut Hasher, name: &[u8], values: &[String]) {
    hash_field(hasher, name, &(values.len() as u64).to_le_bytes());
    for value in values {
        hash_field(hasher, b"value", value.as_bytes());
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepairRequest {
    pub request_id: String,
    pub brief: DiagnosticBrief,
    pub recipe: RepairRecipe,
    pub fence: StateFence,
    pub lease: RecoveryLease,
    pub last_known_good: Option<EvidenceHandle>,
    pub cancellation: bool,
    pub escalation_target: String,
    pub approval: Option<String>,
}

impl RepairRequest {
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), DoctorError> {
        text(&self.request_id, "request id")?;
        text(&self.escalation_target, "escalation target")?;
        self.brief.validate()?;
        self.recipe.validate()?;
        self.fence.validate()?;
        self.lease.validate_at(now)?;
        if !self.recipe.applies_to(&self.brief) {
            return Err(DoctorError::RecipeNotApplicable);
        }
        if let Some(value) = &self.last_known_good {
            value.validate()?;
        }
        if matches!(self.recipe.repair_class, RepairClass::Guarded)
            && self.approval.as_deref().is_none_or(str::is_empty)
        {
            return Err(DoctorError::ApprovalRequired);
        }
        Ok(())
    }
}

/// The complete, authenticated admission issued by Kernel for one invocation.
/// All identity-bearing values are opaque to Doctor and must be echoed back.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelAdmission {
    pub operation: String,
    pub job_id: String,
    pub attempt_id: String,
    pub fence: StateFence,
    pub lease: RecoveryLease,
    pub recipe_id: String,
    pub recipe_revision: u64,
    pub recipe_digest: String,
    pub allowed_effects: BTreeSet<String>,
    pub deadline: OffsetDateTime,
    pub budget_units: u64,
    pub approval: Option<String>,
}

impl KernelAdmission {
    pub fn validate_for(
        &self,
        request: &RepairRequest,
        now: OffsetDateTime,
    ) -> Result<(), DoctorError> {
        text(&self.operation, "operation")?;
        if self.operation != CONTRACT_NAME {
            return Err(DoctorError::OperationNotAdmitted);
        }
        text(&self.job_id, "job id")?;
        text(&self.attempt_id, "attempt id")?;
        self.fence.validate()?;
        self.lease.validate_at(now)?;
        if self.deadline <= now || self.budget_units == 0 {
            return Err(DoctorError::DeadlineOrBudget);
        }
        if self.job_id != request.request_id
            || self.fence != request.fence
            || self.recipe_id != request.recipe.recipe_id
            || self.recipe_revision != request.recipe.revision
            || self.recipe_digest != request.recipe.digest()
        {
            return Err(DoctorError::AdmissionMismatch);
        }
        if self.allowed_effects != request.recipe.allowed_effects
            || self
                .allowed_effects
                .iter()
                .any(|effect| !self.lease.permits(effect))
        {
            return Err(DoctorError::EffectAuthorizationMismatch);
        }
        if matches!(request.recipe.repair_class, RepairClass::Guarded)
            && self.approval.as_deref() != request.approval.as_deref()
        {
            return Err(DoctorError::ApprovalMismatch);
        }
        if matches!(request.recipe.repair_class, RepairClass::DiagnoseOnly)
            && !self.allowed_effects.is_empty()
        {
            return Err(DoctorError::DiagnoseEffects);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectIntent {
    pub job_id: String,
    pub attempt_id: String,
    pub recipe_digest: String,
    pub effect_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EffectOutcome {
    Receipt(AttemptReceipt),
    Unknown { reconciliation_key: String },
}

/// Provider-neutral Kernel contour. Implementations perform authenticated IPC;
/// Doctor has no fallback authority when the operation is not advertised.
pub trait KernelDoctorClient {
    type Error;

    fn advertise_doctor(&mut self) -> Result<bool, Self::Error>;
    fn admit(&mut self, request: &RepairRequest) -> Result<KernelAdmission, Self::Error>;
    fn record_intent(&mut self, intent: &EffectIntent) -> Result<(), Self::Error>;
    fn execute(&mut self, intent: &EffectIntent) -> Result<EffectOutcome, Self::Error>;
    fn reconcile(&mut self, job_id: &str, attempt_id: &str) -> Result<EffectOutcome, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvocationOutcome {
    Diagnosed(DoctorJob),
    Completed(DoctorJob),
    ReconciliationRequired {
        job: DoctorJob,
        reconciliation_key: String,
    },
}

#[derive(Debug, Error)]
pub enum InvocationError<E> {
    #[error("Kernel does not advertise the Doctor operation")]
    KernelAdmissionRequired,
    #[error("Kernel client error: {0}")]
    Kernel(E),
    #[error("Doctor contract error: {0}")]
    Contract(#[from] DoctorError),
}

/// Executes exactly one admitted contour. A provider owns durable status,
/// replay protection, effect execution, and reconciliation.
pub fn invoke_once<C>(
    client: &mut C,
    request: RepairRequest,
    now: OffsetDateTime,
) -> Result<InvocationOutcome, InvocationError<C::Error>>
where
    C: KernelDoctorClient,
{
    if !client.advertise_doctor().map_err(InvocationError::Kernel)? {
        return Err(InvocationError::KernelAdmissionRequired);
    }
    let admission = client.admit(&request).map_err(InvocationError::Kernel)?;
    admission.validate_for(&request, now)?;
    let mut job = DoctorJob::admit(request, now)?;
    if job.state == JobState::Cancelled {
        return Ok(InvocationOutcome::Diagnosed(job));
    }
    job.transition(JobState::Diagnosing, now)?;
    if job.plan.diagnosis_only {
        job.transition(JobState::Escalated, now)?;
        return Ok(InvocationOutcome::Diagnosed(job));
    }
    job.transition(JobState::ReadyForRepair, now)?;
    job.transition(JobState::Running, now)?;
    let intent = EffectIntent {
        job_id: admission.job_id.clone(),
        attempt_id: admission.attempt_id.clone(),
        recipe_digest: admission.recipe_digest,
        effect_digest: job.plan.effect_digest.clone(),
    };
    client
        .record_intent(&intent)
        .map_err(InvocationError::Kernel)?;
    match client.execute(&intent).map_err(InvocationError::Kernel)? {
        EffectOutcome::Unknown { reconciliation_key } => {
            return Ok(InvocationOutcome::ReconciliationRequired {
                job,
                reconciliation_key,
            });
        }
        EffectOutcome::Receipt(receipt) => {
            if receipt.attempt_id != admission.attempt_id {
                return Err(InvocationError::Contract(DoctorError::ReceiptMismatch));
            }
            job.transition(JobState::Verifying, now)?;
            job.record_attempt(receipt, now)?;
        }
    }
    Ok(InvocationOutcome::Completed(job))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepairPlan {
    pub plan_id: String,
    pub request_id: String,
    pub recipe_id: String,
    pub repair_class: RepairClass,
    pub operations: Vec<String>,
    pub verification_contract: Vec<String>,
    pub effect_digest: String,
    pub requires_governor_transition: bool,
    pub diagnosis_only: bool,
}

impl RepairPlan {
    pub fn build(request: &RepairRequest, now: OffsetDateTime) -> Result<Self, DoctorError> {
        request.validate(now)?;
        let diagnosis_only = matches!(request.recipe.repair_class, RepairClass::DiagnoseOnly);
        let requires_governor_transition =
            matches!(request.recipe.repair_class, RepairClass::Guarded);
        let mut hasher = Hasher::new();
        for part in [
            &request.recipe.recipe_id,
            &request.recipe.revision.to_string(),
            &request.brief.problem_id,
            &request.fence.digest,
        ] {
            hasher.update(part.as_bytes());
        }
        for operation in &request.recipe.operations {
            if !request.lease.permits(operation) && !diagnosis_only {
                return Err(DoctorError::EffectNotLeased(operation.clone()));
            }
            hasher.update(operation.as_bytes());
        }
        let effect_digest = hasher.finalize().to_hex().to_string();
        Ok(Self {
            plan_id: format!("{}:{effect_digest}", request.request_id),
            request_id: request.request_id.clone(),
            recipe_id: request.recipe.recipe_id.clone(),
            repair_class: request.recipe.repair_class,
            operations: request.recipe.operations.clone(),
            verification_contract: request.recipe.verification_contract.clone(),
            effect_digest,
            requires_governor_transition,
            diagnosis_only,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttemptReceipt {
    pub attempt_id: String,
    pub plan_id: String,
    pub effect_receipt: EvidenceHandle,
    pub verification: Vec<EvidenceHandle>,
    pub verified: bool,
    pub observed_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoctorJob {
    pub job_id: String,
    pub request: RepairRequest,
    pub plan: RepairPlan,
    pub state: JobState,
    pub attempts: Vec<AttemptReceipt>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl DoctorJob {
    pub fn admit(request: RepairRequest, now: OffsetDateTime) -> Result<Self, DoctorError> {
        request.validate(now)?;
        let plan = RepairPlan::build(&request, now)?;
        let state = if request.cancellation {
            JobState::Cancelled
        } else {
            JobState::Admitted
        };
        Ok(Self {
            job_id: request.request_id.clone(),
            request,
            plan,
            state,
            attempts: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }
    pub fn transition(&mut self, next: JobState, now: OffsetDateTime) -> Result<(), DoctorError> {
        if !valid_transition(self.state, next) {
            return Err(DoctorError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.updated_at = now;
        Ok(())
    }
    pub fn record_attempt(
        &mut self,
        receipt: AttemptReceipt,
        now: OffsetDateTime,
    ) -> Result<(), DoctorError> {
        if self.state != JobState::Verifying {
            return Err(DoctorError::InvalidTransition {
                from: self.state,
                to: JobState::Verifying,
            });
        }
        if receipt.plan_id != self.plan.plan_id {
            return Err(DoctorError::ReceiptMismatch);
        }
        if self.attempts.len() >= self.request.recipe.attempt_budget as usize {
            self.state = JobState::Quarantined;
            self.updated_at = now;
            return Err(DoctorError::BudgetExhausted);
        }
        if receipt.verification.is_empty() || !receipt.verified {
            self.attempts.push(receipt);
            self.state = JobState::Failed;
        } else {
            self.attempts.push(receipt);
            self.state = JobState::Succeeded;
        }
        self.updated_at = now;
        Ok(())
    }
    pub fn attempts_remaining(&self) -> u32 {
        self.request
            .recipe
            .attempt_budget
            .saturating_sub(self.attempts.len() as u32)
    }
    pub fn outcome_digest(&self) -> String {
        let mut h = Hasher::new();
        h.update(self.job_id.as_bytes());
        for attempt in &self.attempts {
            h.update(attempt.attempt_id.as_bytes());
            h.update(attempt.effect_receipt.digest.as_bytes());
        }
        h.finalize().to_hex().to_string()
    }
}

fn valid_transition(from: JobState, to: JobState) -> bool {
    matches!(
        (from, to),
        (
            JobState::Admitted,
            JobState::Diagnosing | JobState::Cancelled
        ) | (
            JobState::Diagnosing,
            JobState::ReadyForRepair | JobState::Escalated | JobState::Cancelled,
        ) | (
            JobState::ReadyForRepair,
            JobState::Running | JobState::Escalated | JobState::Cancelled,
        ) | (
            JobState::Running,
            JobState::Verifying | JobState::Failed | JobState::Cancelled
        ) | (
            JobState::Verifying,
            JobState::Succeeded | JobState::Failed | JobState::Partial | JobState::Quarantined,
        ) | (
            JobState::Failed,
            JobState::Diagnosing | JobState::Quarantined | JobState::Escalated
        ) | (
            JobState::Partial,
            JobState::Diagnosing | JobState::Escalated
        )
    )
}

fn text(value: &str, field: &'static str) -> Result<(), DoctorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(DoctorError::InvalidText(field))
    } else {
        Ok(())
    }
}
fn hex_digest(value: &str, field: &'static str) -> Result<(), DoctorError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Err(DoctorError::InvalidDigest(field))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DoctorError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("invalid text in {0}")]
    InvalidText(&'static str),
    #[error("invalid digest in {0}")]
    InvalidDigest(&'static str),
    #[error("invalid state fence")]
    InvalidFence,
    #[error("recovery lease has expired")]
    LeaseExpired,
    #[error("invalid repair budget")]
    InvalidBudget,
    #[error("recipe does not apply to diagnostic brief")]
    RecipeNotApplicable,
    #[error("effect is not authorized by recovery lease: {0}")]
    EffectNotLeased(String),
    #[error("invalid job transition from {from:?} to {to:?}")]
    InvalidTransition { from: JobState, to: JobState },
    #[error("attempt receipt belongs to another plan")]
    ReceiptMismatch,
    #[error("repair attempt budget exhausted; component must be quarantined")]
    BudgetExhausted,
    #[error("Kernel has not admitted the Doctor operation")]
    OperationNotAdmitted,
    #[error("Kernel admission does not match the requested recipe or fence")]
    AdmissionMismatch,
    #[error("Kernel effect authorization does not match the recipe")]
    EffectAuthorizationMismatch,
    #[error("guarded repair approval does not match Kernel admission")]
    ApprovalMismatch,
    #[error("Kernel admission deadline or budget is invalid")]
    DeadlineOrBudget,
    #[error("guarded repair requires exact approval")]
    ApprovalRequired,
    #[error("diagnose-only recipes cannot declare effects")]
    DiagnoseEffects,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(100)
    }

    fn request(class: RepairClass, effects: &[&str]) -> RepairRequest {
        let operations = if class == RepairClass::DiagnoseOnly {
            Vec::new()
        } else {
            effects.iter().map(|value| (*value).to_owned()).collect()
        };
        let recipe = RepairRecipe {
            recipe_id: "recipe".into(),
            revision: 3,
            problem_classes: ["failure".into()].into_iter().collect(),
            components: ["component".into()].into_iter().collect(),
            repair_class: class,
            prerequisites: vec!["precondition".into()],
            required_authority: "kernel.recovery".into(),
            allowed_effects: effects.iter().map(|value| (*value).to_owned()).collect(),
            operations,
            expected_observables: vec!["healthy".into()],
            verification_contract: vec!["verify".into()],
            rollback_or_compensation: vec!["rollback".into()],
            attempt_budget: 1,
            cooldown: Duration::ZERO,
            stop_conditions: vec!["stop".into()],
        };
        RepairRequest {
            request_id: "job-1".into(),
            brief: DiagnosticBrief {
                problem_id: "problem".into(),
                component: "component".into(),
                failure_class: "failure".into(),
                symptom: "symptom".into(),
                impact: "impact".into(),
                evidence: vec![EvidenceHandle::new("evidence", "a".repeat(64)).unwrap()],
                unknowns: Vec::new(),
            },
            recipe,
            fence: StateFence::new(1, 1, "b".repeat(64)).unwrap(),
            lease: RecoveryLease {
                lease_id: "lease".into(),
                owner: "kernel".into(),
                expires_at: now() + Duration::seconds(30),
                allowed_effects: effects.iter().map(|value| (*value).to_owned()).collect(),
            },
            last_known_good: None,
            cancellation: false,
            escalation_target: "operator".into(),
            approval: (class == RepairClass::Guarded).then(|| "approval".into()),
        }
    }

    fn admission(request: &RepairRequest) -> KernelAdmission {
        KernelAdmission {
            operation: CONTRACT_NAME.into(),
            job_id: request.request_id.clone(),
            attempt_id: "attempt-from-kernel".into(),
            fence: request.fence.clone(),
            lease: request.lease.clone(),
            recipe_id: request.recipe.recipe_id.clone(),
            recipe_revision: request.recipe.revision,
            recipe_digest: request.recipe.digest(),
            allowed_effects: request.recipe.allowed_effects.clone(),
            deadline: now() + Duration::seconds(10),
            budget_units: 1,
            approval: request.approval.clone(),
        }
    }

    #[test]
    fn admission_rejects_stale_fence_or_expired_lease() {
        let request = request(RepairClass::AutomaticSafe, &["restart"]);
        let mut admitted = admission(&request);
        admitted.fence.generation = 2;
        assert_eq!(
            admitted.validate_for(&request, now()),
            Err(DoctorError::AdmissionMismatch)
        );
        let mut admitted = admission(&request);
        admitted.lease.expires_at = now();
        assert_eq!(
            admitted.validate_for(&request, now()),
            Err(DoctorError::LeaseExpired)
        );
    }

    #[test]
    fn admission_rejects_recipe_digest_or_effect_mismatch() {
        let request = request(RepairClass::AutomaticSafe, &["restart"]);
        let mut admitted = admission(&request);
        admitted.recipe_digest = "c".repeat(64);
        assert_eq!(
            admitted.validate_for(&request, now()),
            Err(DoctorError::AdmissionMismatch)
        );
        let mut admitted = admission(&request);
        admitted.allowed_effects.insert("write".into());
        assert_eq!(
            admitted.validate_for(&request, now()),
            Err(DoctorError::EffectAuthorizationMismatch)
        );
    }

    #[test]
    fn recipe_digest_is_versioned_and_binds_each_contract_field() {
        let recipe = request(RepairClass::AutomaticSafe, &["restart"]).recipe;
        let baseline = recipe.digest();
        assert_eq!(
            baseline,
            "d29350b431ed108d5b7606ae6009b77711e3da50bb229d419b389bbbbe999cbd"
        );

        let mut changed = recipe.clone();
        changed.repair_class = RepairClass::Guarded;
        assert_ne!(changed.digest(), baseline);

        let mut changed = recipe.clone();
        changed.operations.push("reconnect".into());
        assert_ne!(changed.digest(), baseline);

        let mut changed = recipe;
        changed.components.insert("other-component".into());
        assert_ne!(changed.digest(), baseline);
    }

    #[test]
    fn guarded_requires_exact_approval_and_diagnosis_has_zero_effects() {
        let mut guarded = request(RepairClass::Guarded, &["restart"]);
        guarded.approval = Some("wrong".into());
        let mut guarded_admission = admission(&guarded);
        guarded_admission.approval = Some("approval".into());
        assert_eq!(
            guarded_admission.validate_for(&guarded, now()),
            Err(DoctorError::ApprovalMismatch)
        );
        let diagnosis = request(RepairClass::DiagnoseOnly, &[]);
        assert_eq!(diagnosis.validate(now()), Ok(()));
        assert!(diagnosis.recipe.allowed_effects.is_empty());
    }

    #[test]
    fn cancellation_is_terminal_and_budget_does_not_loop() {
        let mut request = request(RepairClass::AutomaticSafe, &["restart"]);
        request.cancellation = true;
        let job = DoctorJob::admit(request, now()).unwrap();
        assert_eq!(job.state, JobState::Cancelled);
        assert_eq!(job.attempts_remaining(), 1);
    }
}
