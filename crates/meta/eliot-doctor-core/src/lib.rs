#![forbid(unsafe_code)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const CONTRACT_NAME: &str = "eliot.meta.doctor";
pub const CONTRACT_VERSION: &str = "1.0.0";

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
        if self.allowed_effects.is_empty()
            || self.allowed_effects.iter().any(|e| e.trim().is_empty())
        {
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
        if self.problem_classes.is_empty()
            || self.components.is_empty()
            || self.allowed_effects.is_empty()
        {
            return Err(DoctorError::MissingField("recipe scope"));
        }
        text(&self.required_authority, "required authority")?;
        if self.operations.is_empty()
            || self.expected_observables.is_empty()
            || self.verification_contract.is_empty()
        {
            return Err(DoctorError::MissingField("recipe contract"));
        }
        if self.cooldown.is_negative() {
            return Err(DoctorError::InvalidBudget);
        }
        Ok(())
    }
    pub fn applies_to(&self, brief: &DiagnosticBrief) -> bool {
        self.problem_classes.contains(&brief.failure_class)
            && self.components.contains(&brief.component)
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
        Ok(())
    }
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
        Ok(Self {
            plan_id: Uuid::now_v7().to_string(),
            request_id: request.request_id.clone(),
            recipe_id: request.recipe.recipe_id.clone(),
            repair_class: request.recipe.repair_class,
            operations: request.recipe.operations.clone(),
            verification_contract: request.recipe.verification_contract.clone(),
            effect_digest: hasher.finalize().to_hex().to_string(),
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
            job_id: Uuid::now_v7().to_string(),
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
}
