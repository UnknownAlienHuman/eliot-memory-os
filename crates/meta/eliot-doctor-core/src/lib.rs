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
    #[error("repair manifest is invalid")]
    InvalidManifest,
    #[error("operation reference is not bound to the supplied manifest")]
    ManifestMismatch,
    #[error("presented identity does not match the recomputed binding")]
    IdentityMismatch,
    #[error("verification evidence is not independently verified")]
    NotIndependentlyVerified,
    #[error("invalid disposition transition from {from} to {to}")]
    InvalidDispositionTransition {
        from: &'static str,
        to: &'static str,
    },
}

// ============================================================================
// Wave A closed contract: immutable identities, registered operations,
// separated verifier axes, and closed terminal dispositions.
//
// Everything below this marker is additive. The legacy open contract above
// (`RepairRequest`, `KernelAdmission`, `invoke_once`, `AttemptReceipt` with
// its `verified: bool`, `InvocationOutcome::Completed`) is preserved
// untouched so the existing proofs keep compiling and passing.
// ============================================================================

/// Domain separator binding `RepairRecipeIdentity` digests to one meaning.
pub const RECIPE_IDENTITY_DOMAIN: &str = "eliot.doctor.recipe.v1";
/// Domain separator binding `RepairAttemptIdentity` digests to one meaning.
pub const ATTEMPT_IDENTITY_DOMAIN: &str = "eliot.doctor.attempt.v1";
/// Domain separator binding `RepairEffectIdentity` digests to one meaning.
pub const EFFECT_IDENTITY_DOMAIN: &str = "eliot.doctor.effect.v1";
/// Domain separator binding `RepairRecipeManifest` digests to one meaning.
pub const MANIFEST_IDENTITY_DOMAIN: &str = "eliot.doctor.manifest.v1";

/// Canonical encoding version for `RepairRecipeIdentity`.
pub const RECIPE_IDENTITY_VERSION: u8 = 1;
/// Canonical encoding version for `RepairAttemptIdentity`.
pub const ATTEMPT_IDENTITY_VERSION: u8 = 1;
/// Canonical encoding version for `RepairEffectIdentity`.
pub const EFFECT_IDENTITY_VERSION: u8 = 1;
/// Canonical encoding version for `RepairOperationRef` and its manifest.
pub const OPERATION_REF_VERSION: u8 = 1;

/// Immutable identity of one exact registered recipe revision.
///
/// The digest binds every load-bearing recipe field under an explicit
/// domain separator and version, so it is deterministic across
/// serialization and process restart, and changes whenever any
/// load-bearing field changes. It carries no authority material:
/// `Display`/`Debug` expose only the version and digest.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepairRecipeIdentity {
    version: u8,
    digest: String,
}

impl RepairRecipeIdentity {
    /// Binds the exact recipe contract. Fails closed on an invalid recipe.
    pub fn bind(recipe: &RepairRecipe) -> Result<Self, DoctorError> {
        recipe.validate()?;
        let mut hasher = Hasher::new();
        hash_field(&mut hasher, b"domain", RECIPE_IDENTITY_DOMAIN.as_bytes());
        hash_field(&mut hasher, b"version", &[RECIPE_IDENTITY_VERSION]);
        hash_recipe_body(&mut hasher, recipe);
        Ok(Self {
            version: RECIPE_IDENTITY_VERSION,
            digest: hasher.finalize().to_hex().to_string(),
        })
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        if self.version != RECIPE_IDENTITY_VERSION {
            return Err(DoctorError::IdentityMismatch);
        }
        hex_digest(&self.digest, "recipe identity digest")
    }
}

impl std::fmt::Display for RepairRecipeIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "recipe.v{}:{}", self.version, self.digest)
    }
}

/// Immutable identity of one exact admitted repair attempt.
///
/// Binds target (problem/component), recipe identity, closed operation,
/// fence echo, approval, budget, and deadline. A changed load-bearing
/// field yields a different identity, so replay under one identity with
/// changed terms fails the binding check instead of executing.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepairAttemptIdentity {
    version: u8,
    digest: String,
}

/// Borrowed load-bearing fields bound into one `RepairAttemptIdentity`.
///
/// The local `StateFence` is echoed by value (epoch, generation, digest);
/// Doctor never mints fence authority, it only binds the exact fence the
/// Kernel admission carried. The canonical lineaged fence owner stays in
/// `eliot-contracts`; this digest echo is a reference, not a second owner.
#[derive(Clone, Copy, Debug)]
pub struct AttemptIdentityBinding<'a> {
    pub attempt_id: &'a str,
    pub brief: &'a DiagnosticBrief,
    pub recipe: &'a RepairRecipeIdentity,
    pub operation: &'a RepairOperationRef,
    pub fence: &'a StateFence,
    pub approval: Option<&'a str>,
    pub budget_units: u64,
    pub deadline: OffsetDateTime,
}

impl RepairAttemptIdentity {
    /// Binds every load-bearing attempt field. Fails closed on invalid input.
    pub fn bind(binding: &AttemptIdentityBinding<'_>) -> Result<Self, DoctorError> {
        text(binding.attempt_id, "attempt id")?;
        binding.brief.validate()?;
        binding.recipe.validate()?;
        binding.operation.validate()?;
        binding.fence.validate()?;
        if let Some(approval) = binding.approval {
            text(approval, "approval")?;
        }
        let mut hasher = Hasher::new();
        hash_field(&mut hasher, b"domain", ATTEMPT_IDENTITY_DOMAIN.as_bytes());
        hash_field(&mut hasher, b"version", &[ATTEMPT_IDENTITY_VERSION]);
        hash_field(&mut hasher, b"attempt_id", binding.attempt_id.as_bytes());
        hash_field(
            &mut hasher,
            b"problem_id",
            binding.brief.problem_id.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"component",
            binding.brief.component.as_bytes(),
        );
        hash_field(
            &mut hasher,
            b"recipe_digest",
            binding.recipe.digest.as_bytes(),
        );
        hash_operation_ref(&mut hasher, binding.operation);
        hash_field(
            &mut hasher,
            b"authority_epoch",
            &binding.fence.authority_epoch.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"generation",
            &binding.fence.generation.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"fence_digest",
            binding.fence.digest.as_bytes(),
        );
        match binding.approval {
            Some(approval) => {
                hash_field(&mut hasher, b"approval_present", &[1]);
                hash_field(&mut hasher, b"approval", approval.as_bytes());
            }
            None => hash_field(&mut hasher, b"approval_present", &[0]),
        }
        hash_field(
            &mut hasher,
            b"budget_units",
            &binding.budget_units.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"deadline_nanos",
            &binding.deadline.unix_timestamp_nanos().to_le_bytes(),
        );
        Ok(Self {
            version: ATTEMPT_IDENTITY_VERSION,
            digest: hasher.finalize().to_hex().to_string(),
        })
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        if self.version != ATTEMPT_IDENTITY_VERSION {
            return Err(DoctorError::IdentityMismatch);
        }
        hex_digest(&self.digest, "attempt identity digest")
    }
}

impl std::fmt::Display for RepairAttemptIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "attempt.v{}:{}", self.version, self.digest)
    }
}

/// Immutable identity of one exact effect inside one exact attempt.
///
/// `effect_seq` distinguishes several effects of a single attempt; every
/// other load-bearing field arrives through the bound attempt identity
/// and the closed operation reference.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepairEffectIdentity {
    version: u8,
    digest: String,
}

impl RepairEffectIdentity {
    /// Binds attempt identity, closed operation, and effect sequence.
    pub fn bind(
        attempt: &RepairAttemptIdentity,
        operation: &RepairOperationRef,
        effect_seq: u32,
    ) -> Result<Self, DoctorError> {
        attempt.validate()?;
        operation.validate()?;
        let mut hasher = Hasher::new();
        hash_field(&mut hasher, b"domain", EFFECT_IDENTITY_DOMAIN.as_bytes());
        hash_field(&mut hasher, b"version", &[EFFECT_IDENTITY_VERSION]);
        hash_field(&mut hasher, b"attempt_digest", attempt.digest.as_bytes());
        hash_operation_ref(&mut hasher, operation);
        hash_field(&mut hasher, b"effect_seq", &effect_seq.to_le_bytes());
        Ok(Self {
            version: EFFECT_IDENTITY_VERSION,
            digest: hasher.finalize().to_hex().to_string(),
        })
    }
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        if self.version != EFFECT_IDENTITY_VERSION {
            return Err(DoctorError::IdentityMismatch);
        }
        hex_digest(&self.digest, "effect identity digest")
    }
}

impl std::fmt::Display for RepairEffectIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "effect.v{}:{}", self.version, self.digest)
    }
}

fn hash_recipe_body(hasher: &mut Hasher, recipe: &RepairRecipe) {
    hash_field(hasher, b"recipe_id", recipe.recipe_id.as_bytes());
    hash_field(hasher, b"revision", &recipe.revision.to_le_bytes());
    hash_field(
        hasher,
        b"repair_class",
        &[repair_class_tag(recipe.repair_class)],
    );
    hash_field(
        hasher,
        b"required_authority",
        recipe.required_authority.as_bytes(),
    );
    hash_field(
        hasher,
        b"attempt_budget",
        &recipe.attempt_budget.to_le_bytes(),
    );
    hash_field(
        hasher,
        b"cooldown_nanoseconds",
        &recipe.cooldown.whole_nanoseconds().to_le_bytes(),
    );
    hash_set(hasher, b"problem_classes", &recipe.problem_classes);
    hash_set(hasher, b"components", &recipe.components);
    hash_set(hasher, b"allowed_effects", &recipe.allowed_effects);
    hash_list(hasher, b"prerequisites", &recipe.prerequisites);
    hash_list(hasher, b"operations", &recipe.operations);
    hash_list(
        hasher,
        b"expected_observables",
        &recipe.expected_observables,
    );
    hash_list(
        hasher,
        b"verification_contract",
        &recipe.verification_contract,
    );
    hash_list(
        hasher,
        b"rollback_or_compensation",
        &recipe.rollback_or_compensation,
    );
    hash_list(hasher, b"stop_conditions", &recipe.stop_conditions);
}

fn repair_class_tag(class: RepairClass) -> u8 {
    match class {
        RepairClass::AutomaticSafe => 0,
        RepairClass::Guarded => 1,
        RepairClass::DiagnoseOnly => 2,
    }
}

fn hash_operation_ref(hasher: &mut Hasher, operation: &RepairOperationRef) {
    hash_field(hasher, b"operation_ref_version", &[operation.version]);
    hash_field(hasher, b"operation_id", operation.operation_id.as_bytes());
    hash_field(hasher, b"adapter_id", operation.adapter_id.as_bytes());
    hash_field(
        hasher,
        b"definition_digest",
        operation.definition_digest.as_bytes(),
    );
    hash_field(
        hasher,
        b"manifest_digest",
        operation.manifest_digest.as_bytes(),
    );
}

/// Closed reference to one registered named effect operation.
///
/// Values are produced only by `RepairRecipeManifest::resolve` against an
/// immutable Kernel/Governor-supplied manifest. There is no public
/// constructor from free-form text, so an unregistered operation cannot be
/// named here: resolution fails with `OperationNotAdmitted`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RepairOperationRef {
    version: u8,
    operation_id: String,
    adapter_id: String,
    definition_digest: String,
    manifest_digest: String,
}

impl RepairOperationRef {
    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }
    pub fn definition_digest(&self) -> &str {
        &self.definition_digest
    }
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        if self.version != OPERATION_REF_VERSION {
            return Err(DoctorError::ManifestMismatch);
        }
        text(&self.operation_id, "operation id")?;
        text(&self.adapter_id, "adapter id")?;
        hex_digest(&self.definition_digest, "operation definition digest")?;
        hex_digest(&self.manifest_digest, "operation manifest digest")
    }
}

/// One registered named operation inside a Kernel/Governor manifest.
///
/// `description` is human-readable and intentionally non-executable: it is
/// never consulted for resolution, admission, or identity, and it is
/// excluded from the manifest digest so editorial text changes cannot
/// alter authority. Only `definition_digest` binds the executable meaning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisteredOperation {
    pub operation_id: String,
    pub adapter_id: String,
    pub description: String,
    pub definition_digest: String,
}

impl RegisteredOperation {
    pub fn validate(&self) -> Result<(), DoctorError> {
        text(&self.operation_id, "operation id")?;
        text(&self.adapter_id, "adapter id")?;
        text(&self.description, "operation description")?;
        hex_digest(&self.definition_digest, "operation definition digest")
    }
}

/// Immutable registry of named effect operations supplied by
/// Kernel/Governor. Doctor resolves closed references against exactly one
/// admitted manifest revision; caller-supplied operations are rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepairRecipeManifest {
    pub manifest_id: String,
    pub manifest_revision: u64,
    pub operations: Vec<RegisteredOperation>,
}

impl RepairRecipeManifest {
    pub fn validate(&self) -> Result<(), DoctorError> {
        text(&self.manifest_id, "manifest id")?;
        if self.manifest_revision == 0 || self.operations.is_empty() {
            return Err(DoctorError::InvalidManifest);
        }
        let mut seen = BTreeSet::new();
        for operation in &self.operations {
            operation.validate()?;
            if !seen.insert(operation.operation_id.clone()) {
                return Err(DoctorError::InvalidManifest);
            }
        }
        Ok(())
    }
    /// Digest of the load-bearing manifest content: identity, revision,
    /// and every registered operation except its non-executable
    /// description. Deterministic across serialization and restart.
    pub fn digest(&self) -> String {
        let mut hasher = Hasher::new();
        hash_field(&mut hasher, b"domain", MANIFEST_IDENTITY_DOMAIN.as_bytes());
        hash_field(&mut hasher, b"version", &[OPERATION_REF_VERSION]);
        hash_field(&mut hasher, b"manifest_id", self.manifest_id.as_bytes());
        hash_field(
            &mut hasher,
            b"manifest_revision",
            &self.manifest_revision.to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            b"operation_count",
            &(self.operations.len() as u64).to_le_bytes(),
        );
        for operation in &self.operations {
            hash_field(
                &mut hasher,
                b"operation_id",
                operation.operation_id.as_bytes(),
            );
            hash_field(&mut hasher, b"adapter_id", operation.adapter_id.as_bytes());
            hash_field(
                &mut hasher,
                b"definition_digest",
                operation.definition_digest.as_bytes(),
            );
        }
        hasher.finalize().to_hex().to_string()
    }
    /// Resolves one registered name to a closed reference. An unregistered
    /// name fails with `OperationNotAdmitted`; it can never execute.
    pub fn resolve(&self, operation_id: &str) -> Result<RepairOperationRef, DoctorError> {
        self.validate()?;
        text(operation_id, "operation id")?;
        let manifest_digest = self.digest();
        self.operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
            .map(|operation| RepairOperationRef {
                version: OPERATION_REF_VERSION,
                operation_id: operation.operation_id.clone(),
                adapter_id: operation.adapter_id.clone(),
                definition_digest: operation.definition_digest.clone(),
                manifest_digest: manifest_digest.clone(),
            })
            .ok_or(DoctorError::OperationNotAdmitted)
    }
    /// Proves a reference is still admitted by exactly this manifest
    /// revision: the name must resolve here and the bound definition and
    /// manifest digests must match. A reference carried over from a changed
    /// manifest fails with `ManifestMismatch`.
    pub fn check_admitted(&self, operation: &RepairOperationRef) -> Result<(), DoctorError> {
        operation.validate()?;
        let expected = self.resolve(&operation.operation_id)?;
        if expected == *operation {
            Ok(())
        } else {
            Err(DoctorError::ManifestMismatch)
        }
    }
}

/// Owned construction parameters for a `ClosedRepairRequest`.
///
/// `Debug` redacts the approval value (presence only): approval is
/// authority material and must not leak into logs through derived output.
#[derive(Clone)]
pub struct ClosedRequestParams {
    pub request_id: String,
    pub brief: DiagnosticBrief,
    pub recipe: RepairRecipe,
    pub operations: Vec<RepairOperationRef>,
    pub fence: StateFence,
    pub lease: RecoveryLease,
    pub approval: Option<String>,
    pub budget_units: u64,
    pub deadline: OffsetDateTime,
    pub cancellation: bool,
    pub escalation_target: String,
}

impl std::fmt::Debug for ClosedRequestParams {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedRequestParams")
            .field("request_id", &self.request_id)
            .field("brief", &self.brief)
            .field("recipe", &self.recipe)
            .field("operations", &self.operations)
            .field("fence", &self.fence)
            .field("lease", &self.lease)
            .field("approval", &self.approval.as_deref().map(|_| "<redacted>"))
            .field("budget_units", &self.budget_units)
            .field("deadline", &self.deadline)
            .field("cancellation", &self.cancellation)
            .field("escalation_target", &self.escalation_target)
            .finish()
    }
}

/// Repair request over closed operation references.
///
/// The legacy free-form `RepairRequest.operations: Vec<String>` stays for
/// compatibility; this type carries only manifest-resolved
/// `RepairOperationRef` values and a bound `RepairRecipeIdentity`, and its
/// admission entry point is `validate_closed`. `Debug` redacts approval.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClosedRepairRequest {
    pub request_id: String,
    pub brief: DiagnosticBrief,
    pub recipe: RepairRecipe,
    pub recipe_identity: RepairRecipeIdentity,
    pub operations: Vec<RepairOperationRef>,
    pub fence: StateFence,
    pub lease: RecoveryLease,
    pub approval: Option<String>,
    pub budget_units: u64,
    pub deadline: OffsetDateTime,
    pub cancellation: bool,
    pub escalation_target: String,
}

impl std::fmt::Debug for ClosedRepairRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClosedRepairRequest")
            .field("request_id", &self.request_id)
            .field("brief", &self.brief)
            .field("recipe", &self.recipe)
            .field("recipe_identity", &self.recipe_identity)
            .field("operations", &self.operations)
            .field("fence", &self.fence)
            .field("lease", &self.lease)
            .field("approval", &self.approval.as_deref().map(|_| "<redacted>"))
            .field("budget_units", &self.budget_units)
            .field("deadline", &self.deadline)
            .field("cancellation", &self.cancellation)
            .field("escalation_target", &self.escalation_target)
            .finish()
    }
}

impl ClosedRepairRequest {
    fn assemble(params: ClosedRequestParams, for_effect: bool) -> Result<Self, DoctorError> {
        let recipe_identity = RepairRecipeIdentity::bind(&params.recipe)?;
        if for_effect {
            // A diagnose-only recipe cannot open an effect path, by
            // construction: there is no effect constructor for it.
            if matches!(params.recipe.repair_class, RepairClass::DiagnoseOnly) {
                return Err(DoctorError::DiagnoseEffects);
            }
            if params.operations.is_empty() {
                return Err(DoctorError::MissingField("operations"));
            }
        } else if !params.operations.is_empty() {
            return Err(DoctorError::DiagnoseEffects);
        }
        Ok(Self {
            request_id: params.request_id,
            brief: params.brief,
            recipe: params.recipe,
            recipe_identity,
            operations: params.operations,
            fence: params.fence,
            lease: params.lease,
            approval: params.approval,
            budget_units: params.budget_units,
            deadline: params.deadline,
            cancellation: params.cancellation,
            escalation_target: params.escalation_target,
        })
    }
    /// Builds a diagnose-only request. Carrying any operation fails here,
    /// before admission.
    pub fn diagnose(params: ClosedRequestParams) -> Result<Self, DoctorError> {
        Self::assemble(params, false)
    }
    /// Builds an effect-carrying request. A diagnose-only recipe fails
    /// here: it cannot construct the effect path in this type.
    pub fn for_effect(params: ClosedRequestParams) -> Result<Self, DoctorError> {
        Self::assemble(params, true)
    }
    /// Closed admission check against one admitted manifest revision.
    ///
    /// Mirrors the legacy `RepairRequest::validate` shape checks, then
    /// additionally proves: the stored recipe identity matches the recipe,
    /// every operation is still admitted by this exact manifest, every
    /// operation is covered by the recipe allow-list and the live lease,
    /// and guarded approval is present. Identity binding of that approval
    /// to one attempt is proven separately by `check_attempt_binding`.
    pub fn validate_closed(
        &self,
        manifest: &RepairRecipeManifest,
        now: OffsetDateTime,
    ) -> Result<(), DoctorError> {
        text(&self.request_id, "request id")?;
        text(&self.escalation_target, "escalation target")?;
        self.brief.validate()?;
        self.recipe.validate()?;
        self.fence.validate()?;
        self.lease.validate_at(now)?;
        manifest.validate()?;
        if RepairRecipeIdentity::bind(&self.recipe)? != self.recipe_identity {
            return Err(DoctorError::IdentityMismatch);
        }
        if !self.recipe.applies_to(&self.brief) {
            return Err(DoctorError::RecipeNotApplicable);
        }
        if self.deadline <= now || self.budget_units == 0 {
            return Err(DoctorError::DeadlineOrBudget);
        }
        let diagnosis_only = matches!(self.recipe.repair_class, RepairClass::DiagnoseOnly);
        if diagnosis_only && !self.operations.is_empty() {
            return Err(DoctorError::DiagnoseEffects);
        }
        if !diagnosis_only && self.operations.is_empty() {
            return Err(DoctorError::MissingField("operations"));
        }
        for operation in &self.operations {
            manifest.check_admitted(operation)?;
            if !self
                .recipe
                .allowed_effects
                .contains(operation.operation_id())
            {
                return Err(DoctorError::EffectAuthorizationMismatch);
            }
            if !self.lease.permits(operation.operation_id()) {
                return Err(DoctorError::EffectNotLeased(
                    operation.operation_id().to_owned(),
                ));
            }
        }
        if matches!(self.recipe.repair_class, RepairClass::Guarded)
            && self.approval.as_deref().is_none_or(str::is_empty)
        {
            return Err(DoctorError::ApprovalRequired);
        }
        Ok(())
    }
    /// Binds one attempt identity over this admitted request. The operation
    /// must be one of the admitted closed operations; anything else,
    /// including a free-form name, fails with `OperationNotAdmitted`.
    pub fn bind_attempt(
        &self,
        manifest: &RepairRecipeManifest,
        attempt_id: &str,
        operation: &RepairOperationRef,
        now: OffsetDateTime,
    ) -> Result<RepairAttemptIdentity, DoctorError> {
        self.validate_closed(manifest, now)?;
        if !self.operations.contains(operation) {
            return Err(DoctorError::OperationNotAdmitted);
        }
        RepairAttemptIdentity::bind(&AttemptIdentityBinding {
            attempt_id,
            brief: &self.brief,
            recipe: &self.recipe_identity,
            operation,
            fence: &self.fence,
            approval: self.approval.as_deref(),
            budget_units: self.budget_units,
            deadline: self.deadline,
        })
    }
    /// Proves a presented attempt identity binds exactly this request, this
    /// operation, and this approval. A guarded approval bound to any other
    /// attempt or effect fails with `ApprovalMismatch`; any other binding
    /// drift fails with `IdentityMismatch`.
    pub fn check_attempt_binding(
        &self,
        manifest: &RepairRecipeManifest,
        attempt_id: &str,
        operation: &RepairOperationRef,
        presented: &RepairAttemptIdentity,
        now: OffsetDateTime,
    ) -> Result<(), DoctorError> {
        let recomputed = self.bind_attempt(manifest, attempt_id, operation, now)?;
        if recomputed == *presented {
            Ok(())
        } else if matches!(self.recipe.repair_class, RepairClass::Guarded) {
            Err(DoctorError::ApprovalMismatch)
        } else {
            Err(DoctorError::IdentityMismatch)
        }
    }
    /// Binds one effect identity inside an admitted attempt. The operation
    /// must be admitted on this request; unregistered names cannot execute.
    pub fn bind_effect(
        &self,
        attempt: &RepairAttemptIdentity,
        operation: &RepairOperationRef,
        effect_seq: u32,
    ) -> Result<RepairEffectIdentity, DoctorError> {
        attempt.validate()?;
        if !self.operations.contains(operation) {
            return Err(DoctorError::OperationNotAdmitted);
        }
        RepairEffectIdentity::bind(attempt, operation, effect_seq)
    }
}

/// Effect execution and disposition axis: whether the effect ran and how it
/// ended. `UnknownOutcome` is terminal for blind retry: only reconciliation
/// by exact effect identity may disposition it further.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectDisposition {
    NotExecuted,
    Succeeded,
    Failed,
    Partial,
    UnknownOutcome,
}

/// Process/adapter receipt axis: the receipt the executing adapter or
/// process contour returned. Distinct from whether the effect worked and
/// from whether anyone verified it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterReceiptStatus {
    Absent,
    Received(EvidenceHandle),
    Refused,
}

impl AdapterReceiptStatus {
    pub fn validate(&self) -> Result<(), DoctorError> {
        if let Self::Received(handle) = self {
            handle.validate()?;
        }
        Ok(())
    }
}

/// Verification execution axis: whether the verification contract ran.
/// `Simulated` explicitly never verifies; only `Executed` can endorse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationExecution {
    NotExecuted,
    Simulated,
    Executed,
    UnknownOutcome,
}

/// Evaluation outcome axis: what the executed verification concluded.
/// Parser or exit success is not evaluation; only `Pass` can endorse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Unassessed,
    Pass,
    Fail,
    Inconclusive,
    Stale,
}

/// Artifact/target binding axis: which exact target the verification
/// evidence is bound to. Endorsement requires `BoundExact` naming the
/// verified effect identity digest; anything weaker cannot verify.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactBinding {
    Unbound,
    BoundPartial { target_digest: String },
    BoundExact { target_digest: String },
}

impl ArtifactBinding {
    pub fn validate(&self) -> Result<(), DoctorError> {
        match self {
            Self::Unbound => Ok(()),
            Self::BoundPartial { target_digest } | Self::BoundExact { target_digest } => {
                hex_digest(target_digest, "artifact binding digest")
            }
        }
    }
    pub fn bound_exact_digest(&self) -> Option<&str> {
        if let Self::BoundExact { target_digest } = self {
            Some(target_digest)
        } else {
            None
        }
    }
}

/// Scope/fence/freshness axis: the fence the evidence was observed under
/// and whether that fence is still current. The fence digest is an echo of
/// Kernel-owned authority, never Doctor-minted state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeAttestation {
    pub fence_digest: String,
    pub observed_at: OffsetDateTime,
    pub fence_current: bool,
}

impl ScopeAttestation {
    pub fn validate(&self) -> Result<(), DoctorError> {
        hex_digest(&self.fence_digest, "scope fence digest")
    }
}

/// Independence failure-domain classes, mirroring the evidence-axis
/// vocabulary: independence names what actually changed between effect
/// path and verifier path. A different prompt on the same route, a
/// self-report, or a different model over the same evidence never
/// satisfies the independent-owner requirement on its own.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndependenceClass {
    SelfReported,
    SamePath,
    SameRouteNewPrompt,
    DistinctModelSameEvidence,
    DistinctObservationRoute,
    DistinctImplementationOrToolchain,
    DistinctFailureDomain,
    DistinctAnalystOrTeam,
    HumanObservation,
    IndependentFormalChecker,
}

/// Independence profile axis: the non-ordinal set of failure-domain
/// separations between the effect path and the verifier. Multiple labels
/// may apply; strength is not a ladder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndependenceProfile {
    classes: BTreeSet<IndependenceClass>,
}

impl IndependenceProfile {
    pub fn new(classes: BTreeSet<IndependenceClass>) -> Result<Self, DoctorError> {
        if classes.is_empty() {
            return Err(DoctorError::MissingField("independence classes"));
        }
        Ok(Self { classes })
    }
    pub fn classes(&self) -> &BTreeSet<IndependenceClass> {
        &self.classes
    }
    /// True only when the verifier ran through a genuinely separate
    /// failure domain: a distinct observation route, implementation or
    /// toolchain, failure domain, analyst or team, human observation, or
    /// an independent formal checker.
    pub fn is_independent_owner(&self) -> bool {
        self.classes.iter().any(|class| {
            matches!(
                class,
                IndependenceClass::DistinctObservationRoute
                    | IndependenceClass::DistinctImplementationOrToolchain
                    | IndependenceClass::DistinctFailureDomain
                    | IndependenceClass::DistinctAnalystOrTeam
                    | IndependenceClass::HumanObservation
                    | IndependenceClass::IndependentFormalChecker
            )
        })
    }
}

/// Cleanup/rollback disposition axis: whether compensation ran. Rollback is
/// another registered effect with its own identity, tracked here only as
/// disposition, never as an unchecked callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupDisposition {
    NotRequired,
    Pending,
    Complete,
    Failed,
}

/// Separated verifier evidence for one verification run.
///
/// This replaces the collapsed `AttemptReceipt.verified: bool` (which is
/// preserved untouched for compatibility) with the orthogonal axes:
/// verification execution, evaluation, artifact binding, scope/fence/
/// freshness, independence, and raw evidence handles. A value of this type
/// is evidence, not proof: only `VerificationReport::endorse` can promote
/// it to `IndependentVerification`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierEvidence {
    pub verification_execution: VerificationExecution,
    pub evaluation: EvaluationOutcome,
    pub artifact_binding: ArtifactBinding,
    pub scope: ScopeAttestation,
    pub independence: IndependenceProfile,
    pub evidence: Vec<EvidenceHandle>,
}

impl VerifierEvidence {
    pub fn validate(&self) -> Result<(), DoctorError> {
        self.artifact_binding.validate()?;
        self.scope.validate()?;
        if self.evidence.is_empty() {
            return Err(DoctorError::MissingField("verification evidence"));
        }
        for handle in &self.evidence {
            handle.validate()?;
        }
        Ok(())
    }
}

/// Verification report binding verifier evidence to one exact attempt and
/// effect. The binding is structural here; endorsement checks it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub attempt: RepairAttemptIdentity,
    pub effect: RepairEffectIdentity,
    pub evidence: VerifierEvidence,
    pub reported_at: OffsetDateTime,
}

impl VerificationReport {
    pub fn validate(&self) -> Result<(), DoctorError> {
        self.attempt.validate()?;
        self.effect.validate()?;
        self.evidence.validate()?;
        Ok(())
    }
    /// Endorses this report as independently verified evidence bound to the
    /// live fence. Every axis must hold at once: executed (never
    /// simulated) verification, passing evaluation, exact binding to this
    /// effect identity, a current scope under the expected fence digest, an
    /// independent owner, and non-empty evidence handles. Any weaker
    /// combination fails with `NotIndependentlyVerified` and stays visible
    /// instead of becoming a verified repair.
    pub fn endorse(&self, fence: &StateFence) -> Result<IndependentVerification, DoctorError> {
        self.validate()?;
        fence.validate()?;
        let evidence = &self.evidence;
        if !matches!(
            evidence.verification_execution,
            VerificationExecution::Executed
        ) {
            return Err(DoctorError::NotIndependentlyVerified);
        }
        if !matches!(evidence.evaluation, EvaluationOutcome::Pass) {
            return Err(DoctorError::NotIndependentlyVerified);
        }
        match evidence.artifact_binding.bound_exact_digest() {
            Some(digest) if digest == self.effect.digest() => {}
            _ => return Err(DoctorError::NotIndependentlyVerified),
        }
        if !evidence.scope.fence_current || evidence.scope.fence_digest != fence.digest {
            return Err(DoctorError::NotIndependentlyVerified);
        }
        if !evidence.independence.is_independent_owner() {
            return Err(DoctorError::NotIndependentlyVerified);
        }
        Ok(IndependentVerification {
            report: self.clone(),
        })
    }
}

/// Independently verified repair evidence, bound to one exact attempt and
/// effect under a current fence.
///
/// The only way to obtain a value is `VerificationReport::endorse`, which
/// enforces every verifier axis including failure-domain independence.
/// Doctor's effect executor cannot produce one: the legacy `invoke_once`
/// and any closed executor return pending dispositions only, and the only
/// constructor of the verified terminal disposition takes this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndependentVerification {
    report: VerificationReport,
}

impl IndependentVerification {
    pub fn report(&self) -> &VerificationReport {
        &self.report
    }
    pub fn attempt(&self) -> &RepairAttemptIdentity {
        &self.report.attempt
    }
    pub fn effect(&self) -> &RepairEffectIdentity {
        &self.report.effect
    }
}

/// Closed attempt receipt carrying the separated axes.
///
/// Unlike the legacy `AttemptReceipt` (preserved untouched), this receipt
/// never collapses verification to a boolean: effect disposition, adapter
/// receipt, full verification report, and cleanup disposition travel
/// separately so each can be checked, and only an endorsed report can
/// yield the verified terminal disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifiedAttempt {
    pub attempt: RepairAttemptIdentity,
    pub effect: RepairEffectIdentity,
    pub effect_disposition: EffectDisposition,
    pub adapter_receipt: AdapterReceiptStatus,
    pub verification: VerificationReport,
    pub cleanup: CleanupDisposition,
    pub observed_at: OffsetDateTime,
}

impl VerifiedAttempt {
    pub fn validate(&self) -> Result<(), DoctorError> {
        self.attempt.validate()?;
        self.effect.validate()?;
        self.adapter_receipt.validate()?;
        self.verification.validate()?;
        if self.verification.attempt != self.attempt || self.verification.effect != self.effect {
            return Err(DoctorError::IdentityMismatch);
        }
        Ok(())
    }
    pub fn endorse_verification(
        &self,
        fence: &StateFence,
    ) -> Result<IndependentVerification, DoctorError> {
        self.validate()?;
        self.verification.endorse(fence)
    }
}

/// Why a component or attempt was quarantined. Quarantine is terminal for
/// the attempt; only a new admission with a new identity may retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineCause {
    BudgetExhausted,
    CooldownActive,
    RepeatedFailure,
    UnknownOutcomeUnresolved,
}

/// Closed terminal dispositions for one Doctor attempt.
///
/// This replaces the ambiguous outer `Completed`, which could wrap a
/// failed job, with one precise value per outcome. `RepairedVerified` is
/// impossible inside the effect executor by construction: the only
/// constructor is `repaired_verified`, which requires
/// `IndependentVerification`, which requires an endorsed independent
/// verifier report. The executor returns pending dispositions only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorDisposition {
    Diagnosed {
        request_id: String,
    },
    RepairedPendingVerification {
        attempt: RepairAttemptIdentity,
        effect: RepairEffectIdentity,
    },
    RepairedVerified {
        proof: IndependentVerification,
    },
    RepairFailed {
        attempt: RepairAttemptIdentity,
        effect: Option<RepairEffectIdentity>,
    },
    Partial {
        attempt: RepairAttemptIdentity,
    },
    UnknownEffectOutcome {
        attempt: RepairAttemptIdentity,
        reconciliation_key: String,
    },
    Reconciling {
        attempt: RepairAttemptIdentity,
        effect: RepairEffectIdentity,
    },
    Cancelled {
        request_id: String,
    },
    Quarantined {
        attempt: Option<RepairAttemptIdentity>,
        cause: QuarantineCause,
    },
    Escalated {
        request_id: String,
        target: String,
    },
}

impl DoctorDisposition {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Diagnosed { .. } => "diagnosed",
            Self::RepairedPendingVerification { .. } => "repaired_pending_verification",
            Self::RepairedVerified { .. } => "repaired_verified",
            Self::RepairFailed { .. } => "repair_failed",
            Self::Partial { .. } => "partial",
            Self::UnknownEffectOutcome { .. } => "unknown_effect_outcome",
            Self::Reconciling { .. } => "reconciling",
            Self::Cancelled { .. } => "cancelled",
            Self::Quarantined { .. } => "quarantined",
            Self::Escalated { .. } => "escalated",
        }
    }
    /// Terminal dispositions admit no outgoing transition.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::RepairedVerified { .. }
                | Self::Cancelled { .. }
                | Self::Quarantined { .. }
                | Self::Escalated { .. }
        )
    }
    pub fn validate(&self) -> Result<(), DoctorError> {
        match self {
            Self::Diagnosed { request_id } | Self::Cancelled { request_id } => {
                text(request_id, "request id")
            }
            Self::Escalated { request_id, target } => {
                text(request_id, "request id")?;
                text(target, "escalation target")
            }
            Self::RepairedPendingVerification { attempt, effect }
            | Self::Reconciling { attempt, effect } => {
                attempt.validate()?;
                effect.validate()
            }
            Self::RepairedVerified { proof } => proof.report().validate(),
            Self::RepairFailed { attempt, effect } => {
                attempt.validate()?;
                if let Some(effect) = effect {
                    effect.validate()?;
                }
                Ok(())
            }
            Self::Partial { attempt } => attempt.validate(),
            Self::UnknownEffectOutcome {
                attempt,
                reconciliation_key,
            } => {
                attempt.validate()?;
                text(reconciliation_key, "reconciliation key")
            }
            Self::Quarantined { attempt, .. } => {
                if let Some(attempt) = attempt {
                    attempt.validate()?;
                }
                Ok(())
            }
        }
    }
    /// The only constructor for the verified terminal disposition.
    /// Independence was already proven to obtain `proof`; this call only
    /// wraps it. Executor paths never call this: they return pending
    /// dispositions only.
    pub fn repaired_verified(proof: IndependentVerification) -> Self {
        Self::RepairedVerified { proof }
    }
    /// Advances one closed disposition to the next along the governed
    /// lifecycle. Terminal dispositions have no outgoing transition;
    /// anything outside the lifecycle fails instead of inventing a state.
    pub fn advance(self, next: Self) -> Result<Self, DoctorError> {
        if valid_disposition_transition(&self, &next) {
            Ok(next)
        } else {
            Err(DoctorError::InvalidDispositionTransition {
                from: self.name(),
                to: next.name(),
            })
        }
    }
    /// Maps a legacy `InvocationOutcome` to a closed disposition without
    /// altering the legacy flow: `Completed` holding a succeeded job maps
    /// to pending verification, never to verified, because the legacy
    /// receipt carries no independent verifier evidence. A legacy
    /// `Quarantined` job maps to budget exhaustion, which is the only path
    /// in `record_attempt` that produces it. A legacy `Diagnosed` job that
    /// already escalated maps to the escalation target it carries.
    pub fn from_legacy_outcome(
        outcome: &InvocationOutcome,
        attempt: &RepairAttemptIdentity,
        effect: &RepairEffectIdentity,
    ) -> Result<Self, DoctorError> {
        attempt.validate()?;
        effect.validate()?;
        match outcome {
            InvocationOutcome::Diagnosed(job) => {
                text(&job.job_id, "request id")?;
                text(&job.request.escalation_target, "escalation target")?;
                match job.state {
                    JobState::Cancelled => Ok(Self::Cancelled {
                        request_id: job.job_id.clone(),
                    }),
                    JobState::Escalated => Ok(Self::Escalated {
                        request_id: job.job_id.clone(),
                        target: job.request.escalation_target.clone(),
                    }),
                    _ => Ok(Self::Diagnosed {
                        request_id: job.job_id.clone(),
                    }),
                }
            }
            InvocationOutcome::Completed(job) => {
                text(&job.job_id, "request id")?;
                match job.state {
                    JobState::Succeeded => Ok(Self::RepairedPendingVerification {
                        attempt: attempt.clone(),
                        effect: effect.clone(),
                    }),
                    JobState::Failed => Ok(Self::RepairFailed {
                        attempt: attempt.clone(),
                        effect: Some(effect.clone()),
                    }),
                    JobState::Partial => Ok(Self::Partial {
                        attempt: attempt.clone(),
                    }),
                    JobState::Quarantined => Ok(Self::Quarantined {
                        attempt: Some(attempt.clone()),
                        cause: QuarantineCause::BudgetExhausted,
                    }),
                    other => Err(DoctorError::InvalidDispositionTransition {
                        from: "completed",
                        to: job_state_name(other),
                    }),
                }
            }
            InvocationOutcome::ReconciliationRequired {
                job,
                reconciliation_key,
            } => {
                text(&job.job_id, "request id")?;
                text(reconciliation_key, "reconciliation key")?;
                Ok(Self::UnknownEffectOutcome {
                    attempt: attempt.clone(),
                    reconciliation_key: reconciliation_key.clone(),
                })
            }
        }
    }
}

fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Requested => "requested",
        JobState::Admitted => "admitted",
        JobState::Diagnosing => "diagnosing",
        JobState::ReadyForRepair => "ready_for_repair",
        JobState::Running => "running",
        JobState::Verifying => "verifying",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
        JobState::Partial => "partial",
        JobState::Cancelled => "cancelled",
        JobState::Quarantined => "quarantined",
        JobState::Escalated => "escalated",
    }
}

fn valid_disposition_transition(from: &DoctorDisposition, to: &DoctorDisposition) -> bool {
    matches!(
        (from, to),
        (
            DoctorDisposition::Diagnosed { .. },
            DoctorDisposition::Cancelled { .. } | DoctorDisposition::Escalated { .. },
        ) | (
            DoctorDisposition::RepairedPendingVerification { .. },
            DoctorDisposition::RepairedVerified { .. }
                | DoctorDisposition::RepairFailed { .. }
                | DoctorDisposition::Partial { .. }
                | DoctorDisposition::UnknownEffectOutcome { .. }
                | DoctorDisposition::Cancelled { .. },
        ) | (
            DoctorDisposition::UnknownEffectOutcome { .. },
            DoctorDisposition::Reconciling { .. }
                | DoctorDisposition::Quarantined { .. }
                | DoctorDisposition::Escalated { .. },
        ) | (
            DoctorDisposition::Reconciling { .. },
            DoctorDisposition::RepairedPendingVerification { .. }
                | DoctorDisposition::RepairFailed { .. }
                | DoctorDisposition::Partial { .. }
                | DoctorDisposition::Quarantined { .. }
                | DoctorDisposition::Escalated { .. },
        ) | (
            DoctorDisposition::RepairFailed { .. },
            DoctorDisposition::Quarantined { .. }
                | DoctorDisposition::Escalated { .. }
                | DoctorDisposition::Cancelled { .. },
        ) | (
            DoctorDisposition::Partial { .. },
            DoctorDisposition::Quarantined { .. } | DoctorDisposition::Escalated { .. },
        )
    )
}

/// Computes the closed terminal disposition for one closed attempt receipt.
///
/// A successfully executed effect becomes `REPAIRED_VERIFIED` only when
/// the attached verification report endorses under the live fence; weaker
/// evidence stays `REPAIRED_PENDING_VERIFICATION` and remains visible
/// instead of becoming a false verified repair. Unknown effect outcome
/// carries the exact effect digest as its reconciliation key, so a later
/// reconciliation must name the same effect and can never blind-retry a
/// fresh one.
pub fn disposition_for_verified_attempt(
    receipt: &VerifiedAttempt,
    fence: &StateFence,
) -> Result<DoctorDisposition, DoctorError> {
    receipt.validate()?;
    fence.validate()?;
    match receipt.effect_disposition {
        EffectDisposition::Succeeded => match receipt.endorse_verification(fence) {
            Ok(proof) => Ok(DoctorDisposition::repaired_verified(proof)),
            Err(DoctorError::NotIndependentlyVerified) => {
                Ok(DoctorDisposition::RepairedPendingVerification {
                    attempt: receipt.attempt.clone(),
                    effect: receipt.effect.clone(),
                })
            }
            Err(other) => Err(other),
        },
        EffectDisposition::Failed | EffectDisposition::NotExecuted => {
            Ok(DoctorDisposition::RepairFailed {
                attempt: receipt.attempt.clone(),
                effect: Some(receipt.effect.clone()),
            })
        }
        EffectDisposition::Partial => Ok(DoctorDisposition::Partial {
            attempt: receipt.attempt.clone(),
        }),
        EffectDisposition::UnknownOutcome => Ok(DoctorDisposition::UnknownEffectOutcome {
            attempt: receipt.attempt.clone(),
            reconciliation_key: receipt.effect.digest().to_owned(),
        }),
    }
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
