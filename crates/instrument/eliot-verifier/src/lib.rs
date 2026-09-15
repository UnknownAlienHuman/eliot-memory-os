//! Deterministic verification planning and result authority.
//!
//! This crate decides what an admitted verification request covers and turns
//! observations from an injected executor into a durable verdict.  It does not
//! discover tests, choose a process, or perform filesystem/network effects.

#![forbid(unsafe_code)]

use eliot_contracts::{ClockReading, ContractId, RequestId, sha256_hex};
use eliot_instrument_api::{
    EvidenceCoverage, EvidenceFreshness, InstrumentContractError, InstrumentKind, RawEvidence,
    VerificationOutcome, VerificationRun as CurrentVerificationRun,
};
use eliot_instrument_nextest::{NEXTEST_INSTRUMENT, parse_jsonl};
use eliot_types::verification::{
    SkippedTest, SkippedTestReason, TestInventory, TestMetadata, TestStatefulness,
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
    #[error("current verification requires a non-empty required test set from the admitted plan")]
    EmptyRequiredTests,
    #[error("current verification requires non-empty digest-bound raw evidence")]
    EmptyRawEvidence,
    #[error("raw evidence {artifact} is truncated; incomplete capture cannot pass")]
    TruncatedRawEvidence { artifact: String },
    #[error("raw evidence {artifact} does not belong to this invocation")]
    ForeignRawEvidence { artifact: String },
    #[error("raw evidence {artifact} is not valid: {reason}")]
    InvalidRawEvidence {
        artifact: String,
        reason: &'static str,
    },
    #[error(
        "wrong instrument {instrument}: current verification requires eliot.instrument.nextest"
    )]
    WrongInstrument { instrument: String },
    #[error("unsupported instrument kind {kind:?}: current verification requires TEST")]
    UnsupportedKind { kind: InstrumentKind },
    #[error("nextest output could not be parsed: {reason}")]
    UnparsableReport { reason: String },
    #[error("clock interval is not ordered at {field}")]
    UnorderedClock { field: &'static str },
    #[error("current verification binding is invalid: {detail}")]
    InvalidBinding { detail: String },
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
    if let Some(max) = profile.max_cost_class
        && test.estimated_cost > max
    {
        return Some(SkippedTestReason::DeepOnly);
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
        // Legacy promotion removed (T7-S2): an all-skipped run executed
        // nothing, so it is incomplete rather than passed. A genuine pass
        // still requires at least one passed command; an empty result set
        // can never pass either.
        if results
            .iter()
            .any(|r| matches!(r.status, VerificationCommandStatus::Passed))
        {
            VerificationRunStatus::Passed
        } else {
            VerificationRunStatus::Partial
        }
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
    // Anti-promotion guard (T7-S2): a run marked passed without a single
    // passed command carries no proof, so it stays incomplete and can never
    // become Allow or AllowWithWarnings.
    let has_passed_command = run
        .command_results
        .iter()
        .any(|r| matches!(r.status, VerificationCommandStatus::Passed));
    let decision = match run.status {
        VerificationRunStatus::Passed if warnings.is_empty() && has_passed_command => {
            VerificationDecision::Allow
        }
        VerificationRunStatus::Passed if has_passed_command => {
            VerificationDecision::AllowWithWarnings
        }
        VerificationRunStatus::Passed | VerificationRunStatus::Partial => {
            VerificationDecision::RequireFullVerify
        }
        VerificationRunStatus::Blocked | VerificationRunStatus::Failed => {
            VerificationDecision::Block
        }
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

/// Evaluates one current verification run from already-captured evidence.
///
/// This is the T7-S2 current evaluator. It launches no process, resolves no
/// registry, and promotes no legacy record: the caller supplies the admitted
/// [`InstrumentInvocation`], the digest-bound [`RawEvidence`] captured for
/// exactly that invocation, and the `required_test_ids` taken from the
/// admitted plan only. Raw bytes are checked by digest, parsed with the
/// registered nextest `parse_jsonl` projection, and the passed test names are
/// intersected with the required set. `NextestReport::outcome` alone never
/// decides: an all-skipped report passes its counters while proving nothing,
/// so a pass additionally requires every required id to appear among the
/// passed names. A full failed run is `Fail`; incomplete coverage is
/// `Partial` when at least one required test completed and `Unknown`
/// otherwise. Truncated, foreign, digest-broken, or unparsable input fails
/// closed with a typed error instead of any outcome.
///
/// The returned run is bound to the invocation's declared scope and admitted
/// state fence. Normalized evidence is intentionally empty: normalization
/// belongs to the registered `eliot.instrument.diagnostic` owner, and this
/// evaluator attaches no projection it did not compute.
#[allow(clippy::too_many_lines)]
pub fn evaluate_current(
    invocation: &eliot_instrument_api::InstrumentInvocation,
    raw: &[eliot_instrument_api::RawEvidence],
    required_test_ids: &std::collections::BTreeSet<String>,
    started_at: eliot_contracts::ClockReading,
    finished_at: eliot_contracts::ClockReading,
) -> Result<eliot_instrument_api::VerificationRun, VerifierError> {
    invocation
        .validate()
        .map_err(|error| VerifierError::InvalidBinding {
            detail: format!("invocation rejected: {error}"),
        })?;
    if invocation.kind != InstrumentKind::Test {
        return Err(VerifierError::UnsupportedKind {
            kind: invocation.kind,
        });
    }
    if invocation.instrument.as_str() != NEXTEST_INSTRUMENT {
        return Err(VerifierError::WrongInstrument {
            instrument: invocation.instrument.to_string(),
        });
    }
    if required_test_ids.is_empty() {
        return Err(VerifierError::EmptyRequiredTests);
    }
    if raw.is_empty() {
        return Err(VerifierError::EmptyRawEvidence);
    }
    started_at
        .validate()
        .map_err(|error| VerifierError::InvalidBinding {
            detail: format!("started_at rejected: {error}"),
        })?;
    finished_at
        .validate()
        .map_err(|error| VerifierError::InvalidBinding {
            detail: format!("finished_at rejected: {error}"),
        })?;
    if let (Some(start), Some(end)) = (started_at.known_time_ms, finished_at.known_time_ms)
        && end < start
    {
        return Err(VerifierError::UnorderedClock {
            field: "finished_at",
        });
    }
    let mut stream = Vec::new();
    for item in raw {
        item.validate().map_err(|error| {
            let reason = match error {
                InstrumentContractError::InvalidDigest { .. } => "digest mismatch",
                InstrumentContractError::InvalidText { .. } => "invalid content type",
                InstrumentContractError::InvalidInterval { .. } => "invalid capture clock",
                _ => "invalid raw evidence",
            };
            VerifierError::InvalidRawEvidence {
                artifact: item.artifact_id.to_string(),
                reason,
            }
        })?;
        if item.truncated {
            return Err(VerifierError::TruncatedRawEvidence {
                artifact: item.artifact_id.to_string(),
            });
        }
        if item.invocation_id != invocation.request.request_id {
            return Err(VerifierError::ForeignRawEvidence {
                artifact: item.artifact_id.to_string(),
            });
        }
        stream.extend_from_slice(&item.bytes);
    }
    let report = parse_jsonl(&stream).map_err(|error| VerifierError::UnparsableReport {
        reason: error.to_string(),
    })?;
    let (passed_names, completed_names) = completed_test_names(&stream);
    let has_missing = required_test_ids.difference(&passed_names).next().is_some();
    let observed_required = required_test_ids
        .intersection(&completed_names)
        .next()
        .is_some();
    let (outcome, coverage) = match report.outcome() {
        VerificationOutcome::Pass if !has_missing => (
            VerificationOutcome::Pass,
            EvidenceCoverage::CompleteForScope,
        ),
        VerificationOutcome::Pass | VerificationOutcome::Unknown => {
            // Covers the all-skipped quirk: the counters pass while no
            // required test actually passed.
            if observed_required {
                (
                    VerificationOutcome::Partial,
                    EvidenceCoverage::PartialForScope,
                )
            } else {
                (VerificationOutcome::Unknown, EvidenceCoverage::Unknown)
            }
        }
        VerificationOutcome::Fail => {
            let coverage = if report.started > 0 && report.completed == report.started {
                EvidenceCoverage::CompleteForScope
            } else {
                EvidenceCoverage::PartialForScope
            };
            (VerificationOutcome::Fail, coverage)
        }
        VerificationOutcome::Cancelled => {
            (VerificationOutcome::Cancelled, EvidenceCoverage::Unknown)
        }
        VerificationOutcome::Partial | VerificationOutcome::Blocked => {
            if observed_required {
                (
                    VerificationOutcome::Partial,
                    EvidenceCoverage::PartialForScope,
                )
            } else {
                (VerificationOutcome::Unknown, EvidenceCoverage::Unknown)
            }
        }
    };
    let freshness = if captured_within_window(&started_at, &finished_at, raw) {
        EvidenceFreshness::ExactCandidate
    } else {
        EvidenceFreshness::Unknown
    };
    let digest_input = raw.iter().fold(
        invocation.request.request_id.as_str().as_bytes().to_vec(),
        |mut acc, item| {
            acc.extend_from_slice(item.sha256.as_bytes());
            acc
        },
    );
    let run_id =
        RequestId::new(format!("current-{}", sha256_hex(&digest_input))).map_err(|error| {
            VerifierError::InvalidBinding {
                detail: format!("run identity rejected: {error}"),
            }
        })?;
    let verifier =
        ContractId::new(CONTRACT_NAME).map_err(|error| VerifierError::InvalidBinding {
            detail: format!("verifier identity rejected: {error}"),
        })?;
    let run = CurrentVerificationRun {
        run_id,
        verifier,
        invocation_id: invocation.request.request_id.clone(),
        property: format!(
            "nextest profile '{}' proves the admitted required tests",
            invocation.profile
        ),
        scope: invocation.declared_scope.clone(),
        execution: report.execution_status(),
        outcome,
        freshness,
        coverage,
        evidence: Vec::new(),
        raw_evidence: raw.iter().map(|item| item.artifact_id.clone()).collect(),
        state_fence: invocation.request.state_fence.clone(),
        started_at,
        finished_at: Some(finished_at),
    };
    run.validate()
        .map_err(|error| VerifierError::InvalidBinding {
            detail: format!("constructed run rejected: {error}"),
        })?;
    Ok(run)
}

/// Projects completed and passed test names from one canonical nextest JSONL
/// stream.
///
/// This follows the registered adapter event shape (`type == "test"` with
/// `started`/`completed` events and `PASS`/`pass` completion status) without
/// replacing the authoritative [`parse_jsonl`] counters: callers must parse
/// first, so malformed, duplicate, or unsupported events already failed
/// closed before names are read here.
fn completed_test_names(bytes: &[u8]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut passed = BTreeSet::new();
    let mut completed = BTreeSet::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let is_test = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind == "test");
        if !is_test {
            continue;
        }
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let event = value
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let Some(name) = name else { continue };
        if !matches!(event, "completed" | "COMPLETED") {
            continue;
        }
        completed.insert(name.clone());
        let status = value
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if matches!(status, "PASS" | "pass") {
            passed.insert(name);
        }
    }
    (passed, completed)
}

/// Bounds freshness to capture clocks inside the admitted run window.
///
/// Returns true only when the window is fully known and every raw capture
/// clock falls inside it. Anything less stays [`EvidenceFreshness::Unknown`];
/// the evaluator never upgrades uncertain lineage to exact-candidate proof.
fn captured_within_window(
    started_at: &ClockReading,
    finished_at: &ClockReading,
    raw: &[RawEvidence],
) -> bool {
    let (Some(start), Some(end)) = (started_at.known_time_ms, finished_at.known_time_ms) else {
        return false;
    };
    raw.iter().all(|item| {
        item.captured_at
            .known_time_ms
            .is_some_and(|known| known >= start && known <= end)
    })
}

#[cfg(test)]
mod current_tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_instrument_api::InstrumentInvocation;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const PROBE_ID: &str = "t13s2-current-probe";

    /// Minimal genuine test program. It really executes a check (a checksum
    /// comparison over real arithmetic) and reports canonical nextest-schema
    /// events reflecting its genuine outcome: `PASS` is printed only when
    /// the check actually holds, `FAIL` when it genuinely fails, and `SKIP`
    /// when the mode asks to skip without executing the check. Nothing is
    /// asserted about literal output text; the outer tests assert only on
    /// the evaluator verdict over real process bytes.
    const PROBE_SOURCE: &str = r#"
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("pass");
    let name = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("t13s2-current-probe");
    println!("{{\"type\":\"test\",\"event\":\"started\",\"name\":\"{name}\"}}");
    if mode == "skip" {
        println!("{{\"type\":\"test\",\"event\":\"completed\",\"name\":\"{name}\",\"status\":\"SKIP\"}}");
        return;
    }
    let total: u64 = (1..=1000).sum();
    let expected: u64 = if mode == "pass" { 500_500 } else { 0 };
    let status = if total == expected { "PASS" } else { "FAIL" };
    println!("{{\"type\":\"test\",\"event\":\"completed\",\"name\":\"{name}\",\"status\":\"{status}\"}}");
    if status != "PASS" {
        std::process::exit(1);
    }
}
"#;

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(message.into()))
    }

    fn scratch_dir(tag: &str) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let dir =
            std::env::temp_dir().join(format!("eliot-t13s2-verifier-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn compile_probe(dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let source = dir.join("current_probe.rs");
        std::fs::write(&source, PROBE_SOURCE)?;
        let exe = dir.join(if cfg!(windows) {
            "current_probe.exe"
        } else {
            "current_probe"
        });
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
        let output = std::process::Command::new(rustc)
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .output()?;
        if !output.status.success() {
            return Err(test_error(format!(
                "probe rustc failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(exe)
    }

    fn run_probe(
        exe: &Path,
        mode: &str,
        name: &str,
    ) -> Result<std::process::Output, Box<dyn std::error::Error + Send + Sync>> {
        Ok(std::process::Command::new(exe)
            .arg(mode)
            .arg(name)
            .output()?)
    }

    fn fence() -> Result<StateFence, Box<dyn std::error::Error + Send + Sync>> {
        let lineage = EpochLineageId::new(TEST_LINEAGE)?;
        let Some(sequence) = NonZeroU64::new(7) else {
            return Err(test_error("sequence must be non-zero"));
        };
        let epoch = EpochId::new(lineage, sequence)?;
        Ok(StateFence::new(epoch, ResourceGeneration::genesis()))
    }

    fn clock(known_ms: i64) -> ClockReading {
        ClockReading {
            valid_time_ms: Some(known_ms - 1),
            known_time_ms: Some(known_ms),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        }
    }

    fn invocation() -> Result<InstrumentInvocation, Box<dyn std::error::Error + Send + Sync>> {
        let fence = fence()?;
        let request = RequestMetadata {
            request_id: RequestId::new("current-request-1")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1")?,
            source_id: SourceId::new("source-1")?,
            state_fence: fence,
            clock: clock(100),
        };
        Ok(InstrumentInvocation {
            request,
            instrument: eliot_contracts::ContractId::new("eliot.instrument.nextest")?,
            kind: InstrumentKind::Test,
            profile: "default".to_owned(),
            target: "probe-worktree".to_owned(),
            arguments: vec!["-E".to_owned(), "test(probe)".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "probe-scope".to_owned(),
            requested_at: clock(100),
        })
    }

    fn raw_for(
        invocation: &InstrumentInvocation,
        bytes: Vec<u8>,
        captured_known_ms: i64,
    ) -> Result<RawEvidence, Box<dyn std::error::Error + Send + Sync>> {
        Ok(RawEvidence {
            artifact_id: ArtifactId::new("raw-probe-output")?,
            invocation_id: invocation.request.request_id.clone(),
            source: eliot_instrument_api::RawEvidenceSource::Process,
            content_type: "application/json".to_owned(),
            sha256: sha256_hex(&bytes),
            bytes,
            captured_at: clock(captured_known_ms),
            truncated: false,
        })
    }

    fn required(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| (*id).to_owned()).collect()
    }

    #[test]
    fn real_probe_pass_evaluates_to_pass() -> TestResult {
        let dir = scratch_dir("pass")?;
        let exe = compile_probe(&dir)?;
        let invocation = invocation()?;
        let output = run_probe(&exe, "pass", PROBE_ID)?;
        assert!(
            output.status.success(),
            "real probe process must exit successfully"
        );
        let raw = raw_for(&invocation, output.stdout, 101)?;
        let run = evaluate_current(
            &invocation,
            std::slice::from_ref(&raw),
            &required(&[PROBE_ID]),
            clock(100),
            clock(102),
        )?;
        assert_eq!(run.outcome, VerificationOutcome::Pass);
        assert_eq!(
            run.execution,
            eliot_instrument_api::ExecutionStatus::Succeeded
        );
        assert_eq!(run.coverage, EvidenceCoverage::CompleteForScope);
        assert_eq!(run.scope, "probe-scope");
        assert_eq!(run.invocation_id, invocation.request.request_id);
        assert_eq!(run.state_fence, invocation.request.state_fence);
        assert_eq!(run.raw_evidence, vec![raw.artifact_id.clone()]);
        assert!(run.validate().is_ok());
        Ok(())
    }

    #[test]
    fn real_probe_skip_and_incomplete_set_never_pass() -> TestResult {
        let dir = scratch_dir("skip")?;
        let exe = compile_probe(&dir)?;
        let invocation = invocation()?;
        // All-skipped stream: the nextest counters alone report Pass, but no
        // required test actually passed, so the evaluator must not pass it.
        let skipped = run_probe(&exe, "skip", PROBE_ID)?;
        assert!(
            skipped.status.success(),
            "a skipped probe still exits successfully"
        );
        let skipped_report = eliot_instrument_nextest::parse_jsonl(&skipped.stdout)?;
        assert_eq!(
            skipped_report.outcome(),
            VerificationOutcome::Pass,
            "precondition: all-skipped counters alone report Pass"
        );
        let raw = raw_for(&invocation, skipped.stdout, 101)?;
        let run = evaluate_current(
            &invocation,
            std::slice::from_ref(&raw),
            &required(&[PROBE_ID]),
            clock(100),
            clock(102),
        )?;
        assert_ne!(run.outcome, VerificationOutcome::Pass);
        assert_eq!(run.outcome, VerificationOutcome::Partial);
        assert_ne!(run.coverage, EvidenceCoverage::CompleteForScope);

        // Incomplete required set: one real pass plus one required id that
        // never ran must not pass either.
        let passed = run_probe(&exe, "pass", PROBE_ID)?;
        let raw = raw_for(&invocation, passed.stdout, 101)?;
        let run = evaluate_current(
            &invocation,
            std::slice::from_ref(&raw),
            &required(&[PROBE_ID, "never-executed-required-test"]),
            clock(100),
            clock(102),
        )?;
        assert_ne!(run.outcome, VerificationOutcome::Pass);
        assert_eq!(run.outcome, VerificationOutcome::Partial);
        Ok(())
    }

    #[test]
    fn real_probe_fail_and_tampered_bytes_do_not_pass() -> TestResult {
        let dir = scratch_dir("fail")?;
        let exe = compile_probe(&dir)?;
        let invocation = invocation()?;
        // A genuinely failing check reports FAIL through the real process.
        let failed = run_probe(&exe, "fail", PROBE_ID)?;
        assert!(
            !failed.status.success(),
            "a failing probe must exit non-zero"
        );
        let raw = raw_for(&invocation, failed.stdout, 101)?;
        let run = evaluate_current(
            &invocation,
            std::slice::from_ref(&raw),
            &required(&[PROBE_ID]),
            clock(100),
            clock(102),
        )?;
        assert_eq!(run.outcome, VerificationOutcome::Fail);

        // Tampered bytes break the digest binding and fail closed.
        let passed = run_probe(&exe, "pass", PROBE_ID)?;
        let mut tampered = passed.stdout.clone();
        tampered.extend_from_slice(b" ");
        let raw = RawEvidence {
            artifact_id: ArtifactId::new("raw-tampered")?,
            invocation_id: invocation.request.request_id.clone(),
            source: eliot_instrument_api::RawEvidenceSource::Process,
            content_type: "application/json".to_owned(),
            sha256: sha256_hex(&passed.stdout),
            bytes: tampered,
            captured_at: clock(101),
            truncated: false,
        };
        assert!(
            evaluate_current(
                &invocation,
                std::slice::from_ref(&raw),
                &required(&[PROBE_ID]),
                clock(100),
                clock(102),
            )
            .is_err()
        );

        // Truncated capture and empty inputs fail closed as well.
        let mut truncated = raw_for(&invocation, passed.stdout, 101)?;
        truncated.truncated = true;
        assert!(
            evaluate_current(
                &invocation,
                std::slice::from_ref(&truncated),
                &required(&[PROBE_ID]),
                clock(100),
                clock(102),
            )
            .is_err()
        );
        assert!(
            evaluate_current(
                &invocation,
                &[],
                &required(&[PROBE_ID]),
                clock(100),
                clock(102)
            )
            .is_err()
        );
        assert!(
            evaluate_current(
                &invocation,
                std::slice::from_ref(&raw_for(&invocation, b"\n".to_vec(), 101)?),
                &BTreeSet::new(),
                clock(100),
                clock(102),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_all_skipped_plan_no_longer_passes() -> TestResult {
        let plan = VerifierPlan {
            plan: VerificationPlan {
                plan_id: "plan-legacy".to_owned(),
                profile_id: "nextest".to_owned(),
                changed_refs: Vec::new(),
                selected_tests: Vec::new(),
                required_commands: Vec::new(),
                skipped_tests: Vec::new(),
                estimated_runtime_class: eliot_types::verification::VerificationRuntimeClass::Fast,
                created_at: OffsetDateTime::now_utc(),
            },
            commands: vec![PlannedCommand {
                command_id: "command-1".to_owned(),
                command: "cargo nextest run".to_owned(),
                test_ids: Vec::new(),
                required: false,
                serial: false,
            }],
            inventory_id: "inventory-1".to_owned(),
            inventory_generated_at: OffsetDateTime::now_utc(),
        };
        let run = VerificationRun {
            run_id: "run-legacy".to_owned(),
            plan_id: "plan-legacy".to_owned(),
            profile_id: "nextest".to_owned(),
            started_at: OffsetDateTime::now_utc(),
            finished_at: Some(OffsetDateTime::now_utc()),
            command_results: vec![VerificationCommandResult {
                command: "cargo nextest run".to_owned(),
                status: VerificationCommandStatus::Skipped,
                duration_ms: 1,
                stdout_ref: None,
                stderr_ref: None,
                parsed_test_count: None,
                warnings: Vec::new(),
            }],
            status: VerificationRunStatus::Passed,
        };
        assert_eq!(
            run_status(&run.command_results, 1),
            VerificationRunStatus::Partial
        );
        let verdict = verdict(&plan, &run, OffsetDateTime::now_utc())
            .map_err(|error| test_error(error.to_string()))?;
        assert_eq!(verdict.decision, VerificationDecision::RequireFullVerify);
        Ok(())
    }
}
