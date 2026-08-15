//! Deterministic verification planning and result authority.
//!
//! This crate decides what an admitted verification request covers and turns
//! observations from an injected executor into a durable verdict.  It does not
//! discover tests, choose a process, or perform filesystem/network effects.

#![forbid(unsafe_code)]

use eliot_types::verification::{
    SkippedTest, SkippedTestReason, TestCostClass, TestInventory, TestMetadata, TestStatefulness,
    TestSuiteProfile, VerificationCommandResult, VerificationCommandStatus, VerificationDecision,
    VerificationPlan, VerificationRun, VerificationRunStatus, VerificationVerdict,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use time::OffsetDateTime;

pub const CONTRACT_NAME: &str = "eliot.instrument.verifier";
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VerifierError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("inventory contains duplicate test id {0}")]
    DuplicateTest(String),
    #[error("profile {0} is not present in the inventory")]
    ProfileNotFound(String),
    #[error("plan has no selected checks and no required command")]
    EmptyPlan,
    #[error("executor rejected command {command}: {reason}")]
    ExecutionRejected { command: String, reason: String },
    #[error("run does not belong to plan {0}")]
    PlanMismatch(String),
    #[error("run contains duplicate command {0}")]
    DuplicateCommand(String),
    #[error("command result is not valid: {0}")]
    InvalidResult(String),
}

fn text(value: &str, field: &'static str) -> Result<(), VerifierError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(VerifierError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn id(prefix: &str, value: impl Serialize) -> String {
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{prefix}-{:x}", digest.finalize())
}

/// A command selected for one verifier plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlannedCommand {
    pub command_id: String,
    pub command: String,
    pub test_ids: Vec<String>,
    pub required: bool,
    pub serial: bool,
}

impl PlannedCommand {
    fn validate(&self) -> Result<(), VerifierError> {
        text(&self.command_id, "command_id")?;
        text(&self.command, "command")?;
        if self.test_ids.is_empty() && !self.required {
            return Err(VerifierError::InvalidText { field: "test_ids" });
        }
        Ok(())
    }
}

/// Complete deterministic input to execution, including the exact command set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierPlan {
    pub plan: VerificationPlan,
    pub commands: Vec<PlannedCommand>,
    pub inventory_id: String,
    pub inventory_generated_at: OffsetDateTime,
}

impl VerifierPlan {
    pub fn validate(&self) -> Result<(), VerifierError> {
        text(&self.plan.plan_id, "plan_id")?;
        text(&self.plan.profile_id, "profile_id")?;
        text(&self.inventory_id, "inventory_id")?;
        let mut ids = BTreeSet::new();
        for command in &self.commands {
            command.validate()?;
            if !ids.insert(command.command_id.clone()) {
                return Err(VerifierError::DuplicateCommand(command.command_id.clone()));
            }
        }
        if self.commands.is_empty() {
            return Err(VerifierError::EmptyPlan);
        }
        Ok(())
    }
}

/// Builds a plan from an immutable inventory and a profile selected by policy.
pub fn plan(
    inventory: &TestInventory,
    profile: &TestSuiteProfile,
    changed_refs: &[String],
    created_at: OffsetDateTime,
) -> Result<VerifierPlan, VerifierError> {
    text(&inventory.inventory_id, "inventory_id")?;
    text(&profile.profile_id, "profile_id")?;
    let mut seen = BTreeSet::new();
    for test in &inventory.tests {
        if !seen.insert(test.test_id.clone()) {
            return Err(VerifierError::DuplicateTest(test.test_id.clone()));
        }
    }
    let changed: BTreeSet<&str> = changed_refs.iter().map(String::as_str).collect();
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    let mut by_command: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for test in &inventory.tests {
        let reason = skip_reason(test, profile);
        if let Some(reason) = reason {
            skipped.push(SkippedTest {
                test_id: test.test_id.clone(),
                reason,
            });
            continue;
        }
        let relevant = changed.is_empty()
            || test
                .component_refs
                .iter()
                .any(|item| changed.contains(item.as_str()))
            || test
                .risk_refs
                .iter()
                .any(|item| changed.contains(item.as_str()));
        if relevant {
            selected.push(test.test_id.clone());
            by_command
                .entry(command_for(test))
                .or_default()
                .push(test.test_id.clone());
        } else {
            skipped.push(SkippedTest {
                test_id: test.test_id.clone(),
                reason: SkippedTestReason::OutOfScopeForProfile,
            });
        }
    }
    let mut commands = Vec::new();
    for command in &profile.required_commands {
        text(command, "required_command")?;
        commands.push(PlannedCommand {
            command_id: id("command", command),
            command: command.clone(),
            test_ids: by_command.remove(command).unwrap_or_default(),
            required: true,
            serial: profile.requires_serial,
        });
    }
    for (command, mut test_ids) in by_command {
        test_ids.sort();
        commands.push(PlannedCommand {
            command_id: id("command", &command),
            command,
            test_ids,
            required: false,
            serial: profile.requires_serial,
        });
    }
    if commands.is_empty() {
        return Err(VerifierError::EmptyPlan);
    }
    selected.sort();
    skipped.sort_by(|a, b| a.test_id.cmp(&b.test_id));
    let runtime = if commands.iter().any(|c| c.serial) {
        eliot_types::verification::VerificationRuntimeClass::Deep
    } else if commands.len() > 3 {
        eliot_types::verification::VerificationRuntimeClass::Full
    } else {
        eliot_types::verification::VerificationRuntimeClass::Fast
    };
    let profile_id = profile.profile_id.clone();
    let base = VerificationPlan {
        plan_id: id("plan", (&inventory.inventory_id, &profile_id, changed_refs)),
        profile_id,
        changed_refs: changed_refs.to_vec(),
        selected_tests: selected,
        required_commands: profile.required_commands.clone(),
        skipped_tests: skipped,
        estimated_runtime_class: runtime,
        created_at,
    };
    let result = VerifierPlan {
        plan: base,
        commands,
        inventory_id: inventory.inventory_id.clone(),
        inventory_generated_at: inventory.generated_at,
    };
    result.validate()?;
    Ok(result)
}

fn skip_reason(test: &TestMetadata, profile: &TestSuiteProfile) -> Option<SkippedTestReason> {
    if !profile.included_intents.is_empty() && !profile.included_intents.contains(&test.intent) {
        return Some(SkippedTestReason::OutOfScopeForProfile);
    }
    if profile.excluded_statefulness.contains(&test.statefulness) {
        return Some(match test.statefulness {
            TestStatefulness::ServiceProcess | TestStatefulness::WindowsServiceDryRun => {
                SkippedTestReason::RequiresManualServiceInstall
            }
            _ => SkippedTestReason::OutOfScopeForProfile,
        });
    }
    if let Some(max) = profile.max_cost_class {
        if test.estimated_cost > max {
            return Some(SkippedTestReason::DeepOnly);
        }
    }
    None
}

fn command_for(test: &TestMetadata) -> String {
    test.required_profiles
        .first()
        .cloned()
        .unwrap_or_else(|| test.crate_name.clone())
}

/// Executor-owned observation. The executor may run a process, remote job, or
/// service call, but it must return only this normalized command observation.
pub trait VerifierExecutionPort {
    fn execute(&self, command: &PlannedCommand)
        -> Result<VerificationCommandResult, VerifierError>;
}

/// Executes every planned command in order, stopping after a required failure.
pub fn execute(
    plan: &VerifierPlan,
    port: &dyn VerifierExecutionPort,
    run_id: impl Into<String>,
    started_at: OffsetDateTime,
) -> Result<VerificationRun, VerifierError> {
    plan.validate()?;
    let run_id = run_id.into();
    text(&run_id, "run_id")?;
    let mut results = Vec::new();
    for command in &plan.commands {
        let result = port.execute(command)?;
        if result.command != command.command {
            return Err(VerifierError::ExecutionRejected {
                command: command.command.clone(),
                reason: "executor changed the planned command".to_owned(),
            });
        }
        results.push(result);
        if command.required
            && matches!(
                results.last().map(|r| r.status),
                Some(VerificationCommandStatus::Failed | VerificationCommandStatus::TimedOut)
            )
        {
            break;
        }
    }
    let status = run_status(&results, plan.commands.len());
    Ok(VerificationRun {
        run_id,
        plan_id: plan.plan.plan_id.clone(),
        profile_id: plan.plan.profile_id.clone(),
        started_at,
        finished_at: Some(OffsetDateTime::now_utc()),
        command_results: results,
        status,
    })
}

fn run_status(results: &[VerificationCommandResult], expected: usize) -> VerificationRunStatus {
    if results.iter().any(|r| {
        matches!(
            r.status,
            VerificationCommandStatus::Failed | VerificationCommandStatus::TimedOut
        )
    }) {
        VerificationRunStatus::Failed
    } else if results.len() < expected
        || results
            .iter()
            .any(|r| matches!(r.status, VerificationCommandStatus::NotSupported))
    {
        VerificationRunStatus::Partial
    } else if results.iter().all(|r| {
        matches!(
            r.status,
            VerificationCommandStatus::Passed | VerificationCommandStatus::Skipped
        )
    }) {
        VerificationRunStatus::Passed
    } else {
        VerificationRunStatus::Blocked
    }
}

/// Converts a completed run into the only decision consumed by finish gates.
pub fn verdict(
    plan: &VerifierPlan,
    run: &VerificationRun,
    created_at: OffsetDateTime,
) -> Result<VerificationVerdict, VerifierError> {
    if run.plan_id != plan.plan.plan_id {
        return Err(VerifierError::PlanMismatch(plan.plan.plan_id.clone()));
    }
    let mut seen = BTreeSet::new();
    for result in &run.command_results {
        if !seen.insert(result.command.clone()) {
            return Err(VerifierError::DuplicateCommand(result.command.clone()));
        }
        if result.command.trim().is_empty() {
            return Err(VerifierError::InvalidResult("blank command".to_owned()));
        }
    }
    let blocking_failures = run
        .command_results
        .iter()
        .filter_map(|result| match result.status {
            VerificationCommandStatus::Failed | VerificationCommandStatus::TimedOut => {
                Some(result.command.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let warnings = run
        .command_results
        .iter()
        .flat_map(|r| r.warnings.clone())
        .collect::<Vec<_>>();
    let decision = match run.status {
        VerificationRunStatus::Passed if warnings.is_empty() => VerificationDecision::Allow,
        VerificationRunStatus::Passed => VerificationDecision::AllowWithWarnings,
        VerificationRunStatus::Partial => VerificationDecision::RequireFullVerify,
        VerificationRunStatus::Blocked => VerificationDecision::Block,
        VerificationRunStatus::Failed => VerificationDecision::Block,
    };
    Ok(VerificationVerdict {
        verdict_id: id("verdict", (&run.run_id, &run.plan_id, &decision)),
        run_id: run.run_id.clone(),
        profile_id: plan.plan.profile_id.clone(),
        decision,
        blocking_failures,
        warnings,
        required_followups: if matches!(decision, VerificationDecision::Allow) {
            Vec::new()
        } else {
            vec!["obtain complete evidence for every planned command".to_owned()]
        },
        created_at,
    })
}
