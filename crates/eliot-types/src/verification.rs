use crate::ProjectId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestInventory {
    pub inventory_id: String,
    pub project_id: ProjectId,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub test_count: u64,
    pub tests: Vec<TestMetadata>,
    pub suites: Vec<TestSuiteProfile>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestMetadata {
    pub test_id: String,
    pub crate_name: String,
    pub module_path: String,
    pub test_name: String,
    pub test_kind: TestKind,
    pub intent: TestIntent,
    pub phase_owner: Option<String>,
    pub component_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub estimated_cost: TestCostClass,
    pub statefulness: TestStatefulness,
    pub required_profiles: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestKind {
    Unit,
    Integration,
    Doc,
    CliSmoke,
    McpBoundary,
    EvalCase,
    Closeout,
    DependencyPolicy,
    Audit,
    Deny,
    Machete,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestIntent {
    TypeContract,
    BoundarySecurity,
    Regression,
    /// Tests that prove a unit of work is actually finished. Named after the
    /// development milestones it used to close out; records written under that
    /// spelling still load.
    #[serde(alias = "phase_closeout")]
    CompletionProof,
    BehaviorEval,
    StatefulDbSafety,
    RuntimeServiceSafety,
    ExternalProviderSafety,
    PerformanceCost,
    FlakeDetection,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestCostClass {
    Tiny,
    Small,
    Medium,
    Large,
    VeryLarge,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatefulness {
    Pure,
    TempFs,
    LocalDbIsolated,
    LocalDbSharedSerial,
    NetworkForbidden,
    ServiceProcess,
    WindowsServiceDryRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestSuiteProfile {
    pub profile_id: String,
    pub name: String,
    pub description: String,
    pub included_intents: Vec<TestIntent>,
    pub excluded_statefulness: Vec<TestStatefulness>,
    pub max_cost_class: Option<TestCostClass>,
    pub requires_serial: bool,
    pub required_commands: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationPlan {
    pub plan_id: String,
    pub profile_id: String,
    pub changed_refs: Vec<String>,
    pub selected_tests: Vec<String>,
    pub required_commands: Vec<String>,
    pub skipped_tests: Vec<SkippedTest>,
    pub estimated_runtime_class: VerificationRuntimeClass,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRuntimeClass {
    Fast,
    Medium,
    Full,
    Deep,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkippedTest {
    pub test_id: String,
    pub reason: SkippedTestReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkippedTestReason {
    OutOfScopeForProfile,
    CoveredByRequiredGate,
    PlatformNotSupported,
    RequiresManualServiceInstall,
    DeepOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationRun {
    pub run_id: String,
    pub plan_id: String,
    pub profile_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub started_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub finished_at: Option<OffsetDateTime>,
    pub command_results: Vec<VerificationCommandResult>,
    pub status: VerificationRunStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationCommandResult {
    pub command: String,
    pub status: VerificationCommandStatus,
    pub duration_ms: u64,
    pub stdout_ref: Option<String>,
    pub stderr_ref: Option<String>,
    pub parsed_test_count: Option<u64>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCommandStatus {
    Passed,
    Failed,
    Skipped,
    TimedOut,
    NotSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationRunStatus {
    Passed,
    Failed,
    Partial,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationVerdict {
    pub verdict_id: String,
    pub run_id: String,
    pub profile_id: String,
    pub decision: VerificationDecision,
    pub blocking_failures: Vec<String>,
    pub warnings: Vec<String>,
    pub required_followups: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationDecision {
    Allow,
    AllowWithWarnings,
    Block,
    RequireFullVerify,
    RequireSerialDbVerify,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestCostReport {
    pub report_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub total_tests: u64,
    pub by_kind: Vec<TestCountByKind>,
    pub by_intent: Vec<TestCountByIntent>,
    pub by_cost: Vec<TestCountByCost>,
    pub slowest_commands: Vec<VerificationCommandResult>,
    pub recommendations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestCountByKind {
    pub key: TestKind,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestCountByIntent {
    pub key: TestIntent,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TestCountByCost {
    pub key: TestCostClass,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlakeReport {
    pub report_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub repeated_profile: String,
    pub repeated_runs: u64,
    pub stable_tests: Vec<String>,
    pub flaky_tests: Vec<String>,
    pub blocked_tests: Vec<String>,
    pub skipped_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatefulDbIsolationReport {
    pub report_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub serial_required: bool,
    pub isolated_fixture_roots: Vec<String>,
    pub shared_db_tests: Vec<String>,
    pub stale_locks_before: Vec<String>,
    pub stale_locks_after: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerificationDoctorStatus {
    pub last_profile: Option<String>,
    pub last_run_status: Option<VerificationRunStatus>,
    pub last_full_verify: Option<String>,
    #[serde(alias = "required_profile")]
    pub required_profile: String,
    pub test_inventory_count: u64,
    pub slow_high_cost_commands: Vec<String>,
    pub flake_status: String,
    pub stateful_db_isolation_status: String,
    pub missing_metadata: Vec<String>,
}
