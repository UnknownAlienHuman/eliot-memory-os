#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const SERVICE_NAME: &str = "eliot-doctor";
pub const PROTOCOL_VERSION: &str = "eliot.doctor.v1";
const MAX_TEXT: usize = 16_384;
const MAX_ITEMS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairClass {
    AutomaticSafe,
    Guarded,
    DiagnoseOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
#[serde(deny_unknown_fields)]
pub struct RecoveryFence {
    pub state_fence: String,
    pub authority_epoch: u64,
    pub recovery_lease: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairRecipe {
    pub recipe_id: String,
    pub version: String,
    pub repair_class: RepairClass,
    pub problem_classes: Vec<String>,
    pub component: String,
    pub allowed_effects: Vec<String>,
    pub expected_observables: Vec<String>,
    pub verification_contract: String,
    pub rollback_or_compensation: String,
    pub stop_conditions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorJob {
    pub job_id: String,
    pub problem_id: String,
    pub incident_id: Option<String>,
    pub diagnostic_brief: String,
    pub evidence_handles: Vec<String>,
    pub recipe: RepairRecipe,
    pub fence: RecoveryFence,
    pub last_known_good: Vec<String>,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub cancellation_token: String,
    pub escalation_target: String,
    pub approval: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorReport {
    pub job_id: String,
    pub attempt_id: String,
    pub state: JobState,
    pub repair_class: RepairClass,
    pub component: String,
    pub evidence_handles: Vec<String>,
    pub observations: Vec<String>,
    pub side_effects: Vec<String>,
    pub verification: String,
    pub escalation_target: String,
    pub reconciliation_intent: String,
}

#[derive(Debug, Error)]
pub enum DoctorError {
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("input limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("duplicate value in {field}: {value}")]
    Duplicate { field: &'static str, value: String },
    #[error("recovery lease is required for a repair job")]
    MissingLease,
    #[error("guarded repair requires exact approval")]
    ApprovalRequired,
    #[error("diagnose-only recipes cannot declare effects")]
    DiagnoseEffects,
    #[error("job already exists: {0}")]
    DuplicateJob(String),
    #[error("unknown job: {0}")]
    UnknownJob(String),
    #[error("job is not cancellable: {0}")]
    NotCancellable(String),
}

fn text(value: &str, field: &'static str) -> Result<(), DoctorError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DoctorError::InvalidField(field));
    }
    if value.len() > MAX_TEXT {
        return Err(DoctorError::LimitExceeded(field));
    }
    Ok(())
}

fn list(values: &[String], field: &'static str, required: bool) -> Result<(), DoctorError> {
    if required && values.is_empty() {
        return Err(DoctorError::InvalidField(field));
    }
    if values.len() > MAX_ITEMS {
        return Err(DoctorError::LimitExceeded(field));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(DoctorError::Duplicate {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

impl DoctorJob {
    pub fn validate(&self) -> Result<(), DoctorError> {
        for (value, field) in [
            (&self.job_id, "job_id"),
            (&self.problem_id, "problem_id"),
            (&self.diagnostic_brief, "diagnostic_brief"),
            (&self.fence.state_fence, "state_fence"),
            (&self.fence.recovery_lease, "recovery_lease"),
            (&self.fence.authority_epoch.to_string(), "authority_epoch"),
            (&self.cancellation_token, "cancellation_token"),
            (&self.escalation_target, "escalation_target"),
            (&self.recipe.recipe_id, "recipe_id"),
            (&self.recipe.version, "recipe_version"),
            (&self.recipe.component, "component"),
            (&self.recipe.verification_contract, "verification_contract"),
            (
                &self.recipe.rollback_or_compensation,
                "rollback_or_compensation",
            ),
        ] {
            text(value, field)?;
        }
        if self.fence.recovery_lease == "none" {
            return Err(DoctorError::MissingLease);
        }
        if self.budget_units == 0 || self.deadline_ms <= 0 {
            return Err(DoctorError::InvalidField("budget_or_deadline"));
        }
        list(&self.evidence_handles, "evidence_handles", true)?;
        list(&self.last_known_good, "last_known_good", false)?;
        list(&self.recipe.problem_classes, "problem_classes", true)?;
        list(&self.recipe.allowed_effects, "allowed_effects", false)?;
        list(
            &self.recipe.expected_observables,
            "expected_observables",
            true,
        )?;
        list(&self.recipe.stop_conditions, "stop_conditions", true)?;
        if self.recipe.repair_class == RepairClass::DiagnoseOnly
            && !self.recipe.allowed_effects.is_empty()
        {
            return Err(DoctorError::DiagnoseEffects);
        }
        if self.recipe.repair_class == RepairClass::Guarded
            && self.approval.as_deref().is_none_or(str::is_empty)
        {
            return Err(DoctorError::ApprovalRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct StoredJob {
    request: DoctorJob,
    report: DoctorReport,
}

/// Composition root for one bounded Doctor process. It owns only in-memory
/// attempt state; canonical transitions and infrastructure effects remain with
/// the authenticated Kernel recovery gateway.
pub struct DoctorComposition {
    jobs: std::collections::BTreeMap<String, StoredJob>,
    max_jobs: usize,
}

impl Default for DoctorComposition {
    fn default() -> Self {
        Self::new(32)
    }
}

impl DoctorComposition {
    #[must_use]
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: std::collections::BTreeMap::new(),
            max_jobs: max_jobs.max(1),
        }
    }

    pub fn run(&mut self, request: DoctorJob) -> Result<DoctorReport, DoctorError> {
        request.validate()?;
        if self.jobs.contains_key(&request.job_id) {
            return Err(DoctorError::DuplicateJob(request.job_id));
        }
        if self.jobs.len() >= self.max_jobs {
            return Err(DoctorError::LimitExceeded("active_jobs"));
        }
        let report = diagnose(&request);
        self.jobs.insert(
            request.job_id.clone(),
            StoredJob {
                request,
                report: report.clone(),
            },
        );
        Ok(report)
    }

    pub fn status(&self, job_id: &str) -> Result<DoctorReport, DoctorError> {
        self.jobs
            .get(job_id)
            .map(|job| job.report.clone())
            .ok_or_else(|| DoctorError::UnknownJob(job_id.to_owned()))
    }

    pub fn cancel(&mut self, job_id: &str) -> Result<DoctorReport, DoctorError> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| DoctorError::UnknownJob(job_id.to_owned()))?;
        if matches!(
            job.report.state,
            JobState::Succeeded
                | JobState::Failed
                | JobState::Cancelled
                | JobState::Quarantined
                | JobState::Escalated
        ) {
            return Err(DoctorError::NotCancellable(job_id.to_owned()));
        }
        job.report.state = JobState::Cancelled;
        "cancelled before governed effect or canonical transition"
            .clone_into(&mut job.report.verification);
        job.report.reconciliation_intent = format!(
            "cancelled:{}:{}",
            job.request.problem_id, job.request.fence.state_fence
        );
        Ok(job.report.clone())
    }
}

fn diagnose(request: &DoctorJob) -> DoctorReport {
    let class = request.recipe.repair_class;
    let (state, verification, intent) = match class {
        RepairClass::DiagnoseOnly => (
            JobState::Escalated,
            "diagnosis complete; no repair effect admitted".to_owned(),
            format!(
                "escalate:{}:{}",
                request.problem_id, request.fence.state_fence
            ),
        ),
        RepairClass::AutomaticSafe | RepairClass::Guarded => (
            JobState::ReadyForRepair,
            "diagnosis complete; Kernel gateway must execute and verify recipe".to_owned(),
            format!(
                "repair-requested:{}:{}",
                request.problem_id, request.fence.recovery_lease
            ),
        ),
    };
    DoctorReport {
        job_id: request.job_id.clone(),
        attempt_id: Uuid::new_v4().to_string(),
        state,
        repair_class: class,
        component: request.recipe.component.clone(),
        evidence_handles: request.evidence_handles.clone(),
        observations: vec![
            format!(
                "recipe={}@{}",
                request.recipe.recipe_id, request.recipe.version
            ),
            format!(
                "fence={} authority_epoch={}",
                request.fence.state_fence, request.fence.authority_epoch
            ),
            format!(
                "observables={}",
                request.recipe.expected_observables.join(",")
            ),
        ],
        side_effects: Vec::new(),
        verification,
        escalation_target: request.escalation_target.clone(),
        reconciliation_intent: intent,
    }
}
