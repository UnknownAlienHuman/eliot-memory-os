#![forbid(unsafe_code)]

mod action_plan;
mod calibration_runtime;
mod cognitive_runner;
mod commands;
mod config;
mod delegation_runtime;
mod dogfood;
mod host_runtime;
mod mcp_stdio;
mod named_pipe_ipc;
mod provider_budget_runtime;
mod runtime_bootstrap;
mod runtime_instance;
mod security_scan;
mod windows_service;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "eliot-governor")]
#[command(about = "Eliot Memory OS Governor")]
struct Cli {
    #[arg(long, env = "ELIOT_GOVERNOR_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Dogfood {
        #[command(subcommand)]
        command: DogfoodCommand,
    },
    Doctor {
        #[command(subcommand)]
        command: DoctorCommand,
    },
    DataRoot {
        #[command(subcommand)]
        command: DataRootCommand,
    },
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
    Export {
        #[command(subcommand)]
        command: ExportCommand,
    },
    Import {
        #[command(subcommand)]
        command: ImportCommand,
    },
    Blob {
        #[command(subcommand)]
        command: BlobCommand,
    },
    Cutover {
        #[command(subcommand)]
        command: CutoverCommand,
    },
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    Incident {
        #[command(subcommand)]
        command: IncidentCommand,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    Ipc {
        #[command(subcommand)]
        command: IpcCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
    Security {
        #[command(subcommand)]
        command: SecurityCommand,
    },
    Readiness {
        #[command(subcommand)]
        command: ReadinessCommand,
    },
    StartupRecovery {
        #[command(subcommand)]
        command: StartupRecoveryCommand,
    },
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    Writer {
        #[command(subcommand)]
        command: WriterCommand,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    MemoryLifecycle {
        #[command(subcommand)]
        command: MemoryLifecycleCommand,
    },
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    SkillCurator {
        #[command(subcommand)]
        command: SkillCuratorCommand,
    },
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },
    Ul {
        #[command(subcommand)]
        command: commands::UlCommand,
    },
    Codecortex {
        #[command(subcommand)]
        command: CodeCortexCommand,
    },
    ExternalReview {
        #[command(subcommand)]
        command: ExternalReviewCommand,
    },
    Delegate {
        #[command(subcommand)]
        command: DelegateCommand,
    },
    DelegationCalibration {
        #[command(subcommand)]
        command: DelegationCalibrationCommand,
    },
    Antigravity {
        #[command(subcommand)]
        command: AntigravityCommand,
    },
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    Verify {
        #[command(subcommand)]
        command: VerifyCommand,
    },
    Metrics {
        #[command(subcommand)]
        command: MetricsCommand,
    },
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    Replay {
        #[command(subcommand)]
        command: ReplayCommand,
    },
    Sleep {
        #[command(subcommand)]
        command: SleepCommand,
    },
    Dream {
        #[command(subcommand)]
        command: DreamCommand,
    },
    Action {
        #[command(subcommand)]
        command: ActionCommand,
    },
    Patch {
        #[command(subcommand)]
        command: PatchCommand,
    },
    Work {
        #[command(subcommand)]
        command: WorkCommand,
    },
    Worktree {
        #[command(subcommand)]
        command: WorktreeCommand,
    },
    Blackboard {
        #[command(subcommand)]
        command: BlackboardCommand,
    },
    Mailbox {
        #[command(subcommand)]
        command: MailboxCommand,
    },
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    Collective {
        #[command(subcommand)]
        command: CollectiveCommand,
    },
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    Module {
        #[command(subcommand)]
        command: ModuleCommand,
    },
    Logs {
        #[command(subcommand)]
        command: LogsCommand,
    },
    Adapter {
        #[command(subcommand)]
        command: AdapterCommand,
    },
    Verifier {
        #[command(subcommand)]
        command: VerifierCommand,
    },
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DoctorCommand {
    Run {
        #[arg(long)]
        offline: bool,
    },
    Report,
    Operations,
}

#[derive(Debug, Subcommand)]
enum DataRootCommand {
    Validate {
        #[arg(long, default_value = "dev")]
        profile: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    Plan {
        #[arg(long, default_value = "logical")]
        kind: String,
    },
    Run {
        #[arg(long, default_value = "logical")]
        kind: String,
        #[arg(long)]
        dry_run: bool,
    },
    Verify {
        #[arg(long, default_value = "latest")]
        backup: String,
    },
    List,
    Status {
        #[arg(long, default_value = "latest")]
        backup: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum RestoreCommand {
    Plan {
        #[arg(long, default_value = "latest")]
        backup: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        target_config: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "latest")]
        backup: String,
    },
    Run {
        #[arg(long, default_value = "latest")]
        backup: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        target_config: PathBuf,
        #[arg(long)]
        maintenance_mode: bool,
        #[arg(long)]
        approval_hash: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    Rollback {
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        maintenance_mode: bool,
        #[arg(long)]
        approval_hash: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum ExportCommand {
    Plan {
        #[arg(long, default_value = "reports-only")]
        kind: String,
    },
    Run {
        #[arg(long, default_value = "reports-only")]
        kind: String,
    },
}

#[derive(Debug, Subcommand)]
enum ImportCommand {
    Validate {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        maintenance_mode: bool,
    },
    Preview {
        #[arg(long)]
        path: PathBuf,
    },
    Execute {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        approval_hash: String,
        #[arg(long)]
        maintenance_mode: bool,
    },
    Report,
}

#[derive(Clone, Debug, Subcommand)]
enum BlobCommand {
    Manifest,
    GcPlan,
    GcRun {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        approval_hash: Option<String>,
        #[arg(long)]
        under_load: bool,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum CutoverCommand {
    Plan {
        #[arg(long)]
        proposed_data_root: PathBuf,
        #[arg(long)]
        executable: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum MaintenanceCommand {
    Run {
        #[arg(long)]
        job: String,
        #[arg(long)]
        dry_run: bool,
    },
    Status,
    Report,
}

#[derive(Debug, Subcommand)]
enum IncidentCommand {
    List,
    Open {
        #[arg(long)]
        kind: String,
        #[arg(long)]
        severity: String,
        #[arg(long)]
        summary: String,
    },
    Acknowledge {
        #[arg(long)]
        incident: String,
    },
    Close {
        #[arg(long)]
        incident: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    InitDefault {
        #[arg(long)]
        source_config: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Run {
        #[arg(long)]
        instance: Option<String>,
    },
    Status {
        #[arg(long)]
        instance: Option<String>,
    },
    Health {
        #[arg(long)]
        instance: Option<String>,
    },
    Doctor {
        #[arg(long)]
        instance: Option<String>,
    },
    Stop {
        #[arg(long)]
        instance: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum DogfoodCommand {
    Init {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        project: PathBuf,
    },
    Start {
        #[arg(long)]
        root: PathBuf,
    },
    Doctor {
        #[arg(long)]
        root: PathBuf,
    },
    Status {
        #[arg(long)]
        root: PathBuf,
    },
    PrepareWorktree {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        commit: String,
    },
    RunCodex {
        #[arg(long)]
        root: PathBuf,
    },
    Stop {
        #[arg(long)]
        root: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Run,
    Validate,
    Install {
        #[arg(long)]
        dry_run: bool,
    },
    Uninstall {
        #[arg(long)]
        dry_run: bool,
    },
    Status,
    Start,
    Stop,
    Restart,
    Report,
}

#[derive(Debug, Subcommand)]
enum IpcCommand {
    Smoke,
    Handshake,
    Status,
    Report,
}

#[derive(Debug, Subcommand)]
enum CredentialsCommand {
    Validate,
    Report,
}

#[derive(Debug, Subcommand)]
enum SecurityCommand {
    ScanCanonical,
    RotateLegacyCredential,
    RotateOperatorCursorCredential {
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        remove_legacy_file: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReadinessCommand {
    Probe,
    Report,
}

#[derive(Debug, Subcommand)]
enum StartupRecoveryCommand {
    Scan,
    Report,
}

#[derive(Debug, Subcommand)]
enum DbCommand {
    Start,
    Stop,
    Status,
    Smoke,
    Migrate,
}

#[derive(Debug, Subcommand)]
enum WriterCommand {
    Status,
    Smoke,
    Drain,
}

#[derive(Debug, Subcommand)]
enum MemoryCommand {
    CurrentState {
        #[arg(long)]
        project: String,
    },
    RecallL0 {
        #[arg(long)]
        project: String,
        #[arg(long)]
        query: String,
    },
    FetchL2 {
        #[arg(long)]
        project: String,
        #[arg(long)]
        handles: String,
    },
}

#[derive(Debug, Subcommand)]
enum GraphCommand {
    Health,
}

#[derive(Debug, Subcommand)]
enum CodeCortexCommand {
    Health,
    Scan {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        goal: String,
    },
    Report {
        #[arg(long)]
        latest: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ExternalReviewCommand {
    Providers,
    Provider {
        #[command(subcommand)]
        command: ExternalReviewProviderCommand,
    },
    Request {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        provider: String,
        #[arg(long, default_value = "auditor")]
        role: String,
        #[arg(long)]
        question: String,
    },
    Job {
        #[command(subcommand)]
        command: ExternalReviewJobCommand,
    },
    RunMock {
        #[arg(long)]
        request: String,
    },
    Result {
        #[command(subcommand)]
        command: ExternalReviewResultCommand,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum DelegateCommand {
    Policy,
    Health,
    Explain {
        #[arg(long)]
        origin: String,
        #[arg(long = "kind")]
        review_kind: String,
        #[arg(long)]
        question: String,
    },
    Request {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        origin: String,
        #[arg(long = "kind")]
        review_kind: String,
        #[arg(long = "work-lease")]
        work_lease: String,
        #[arg(long)]
        question: String,
        #[arg(long = "evidence")]
        evidence_refs: Vec<String>,
        #[arg(long, default_value = "auto")]
        preferred_provider: String,
        #[arg(long, default_value_t = false)]
        wait: bool,
    },
    ExecuteProvider {
        #[arg(long)]
        campaign: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        origin: String,
        #[arg(long = "kind")]
        review_kind: String,
        #[arg(long = "work-lease")]
        work_lease: String,
        #[arg(long)]
        question: String,
        #[arg(long = "evidence")]
        evidence_refs: Vec<String>,
        #[arg(long = "idempotency-key")]
        idempotency_key: String,
        #[arg(long, default_value = "antigravity")]
        preferred_provider: String,
        #[arg(long, default_value_t = false)]
        require_budget_slot: bool,
        #[arg(long, default_value_t = false)]
        confirm_operator_intent: bool,
        #[arg(long, default_value_t = false)]
        wait: bool,
    },
    Status {
        #[arg(long)]
        delegation: String,
    },
    Result {
        #[arg(long)]
        delegation: String,
    },
    Outcome {
        #[arg(long)]
        delegation: String,
    },
    Budgets,
    ShadowReport,
    Report,
}

#[derive(Debug, Subcommand)]
enum DelegationCalibrationCommand {
    Ingest,
    Status,
    Samples,
    ShadowRun,
    FamilyReport,
    PolicyCandidate,
    PromotionGate,
    Report,
    CampaignPreview {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        family: String,
        #[arg(long = "selection-rule")]
        selection_rule: String,
        #[arg(long = "provider-route", default_value = "antigravity")]
        provider_route: String,
        #[arg(long = "policy-snapshot")]
        policy_snapshot: String,
        #[arg(long = "max-provider-calls", default_value_t = 1)]
        max_provider_calls: u32,
        #[arg(long = "max-cost")]
        max_cost: Option<f64>,
        #[arg(long = "max-wall-time", default_value_t = 900)]
        max_wall_time: u64,
        #[arg(long = "frozen-input")]
        frozen_inputs: Vec<String>,
    },
    CampaignBindReview {
        #[arg(long)]
        campaign: String,
        #[arg(long)]
        delegation: String,
    },
    EvidenceAttach {
        #[arg(long)]
        path: PathBuf,
    },
    CampaignCloseout {
        #[arg(long, default_value = "latest")]
        campaign: String,
    },
    CampaignStatus {
        #[arg(long, default_value = "latest")]
        campaign: String,
    },
    IntegrityReconcile {
        #[arg(long, default_value = "latest")]
        campaign: String,
    },
}

#[derive(Debug, Subcommand)]
enum ExternalReviewProviderCommand {
    Inspect {
        #[arg(long)]
        provider: String,
    },
}

#[derive(Debug, Subcommand)]
enum ExternalReviewJobCommand {
    Status {
        #[arg(long)]
        job: String,
    },
}

#[derive(Debug, Subcommand)]
enum ExternalReviewResultCommand {
    Inspect {
        #[arg(long)]
        result: String,
    },
}

#[derive(Debug, Subcommand)]
enum AntigravityCommand {
    WindowsDiscover,
    VersionCheck,
    InstallReceipt,
    Resolve,
    Detect,
    Status,
    Doctor,
    CommandContract,
    AuthCheck,
    Enable {
        #[arg(long)]
        scope: String,
        #[arg(long)]
        admin_confirm: bool,
    },
    Disable {
        #[arg(long)]
        reason: String,
    },
    LiveSmoke {
        #[arg(long)]
        mode: String,
    },
    Rollback,
    RealReport,
    Request {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "audit-plan")]
        mode: String,
        #[arg(long)]
        question: String,
    },
    Run {
        #[arg(long)]
        request: String,
        #[arg(long)]
        dry_run: bool,
    },
    JobStatus {
        #[arg(long)]
        run: String,
    },
    Result {
        #[arg(long)]
        run: String,
    },
    Plugin {
        #[command(subcommand)]
        command: AntigravityPluginCommand,
    },
    Mcp {
        #[command(subcommand)]
        command: AntigravityMcpCommand,
    },
    Visibility,
    Report,
}

#[derive(Debug, Subcommand)]
enum AntigravityPluginCommand {
    Schema,
    InstallOfficial {
        #[arg(long)]
        admin_confirm: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AntigravityMcpCommand {
    ConfigStatus,
    Register {
        #[arg(long)]
        admin_confirm: bool,
    },
    BackupList,
    InvocationProof,
}

#[derive(Debug, Subcommand)]
enum EvalCommand {
    Case {
        #[command(subcommand)]
        command: EvalCaseCommand,
    },
    Suite {
        #[command(subcommand)]
        command: EvalSuiteCommand,
    },
    Manifest {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
    Run {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
        #[arg(long, default_value = "deterministic-no-mutation")]
        profile: String,
    },
    Verdict {
        #[arg(long, default_value = "latest")]
        run: String,
    },
    Failures {
        #[arg(long, default_value = "latest")]
        run: String,
    },
    Coverage {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
    Baseline {
        #[command(subcommand)]
        command: EvalBaselineCommand,
    },
    Compare {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
        #[arg(long, default_value = "latest")]
        baseline: String,
        #[arg(long, default_value = "latest")]
        candidate_run: String,
    },
    Gate {
        #[arg(long, default_value = "fast-deterministic")]
        profile: String,
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
    Profiles,
    Trend {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
    Stability {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
        #[arg(long, default_value_t = 2)]
        repeat: u8,
    },
    IntegrationSmoke,
    Report,
    Smoke {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
}

#[derive(Debug, Subcommand)]
enum EvalCaseCommand {
    Create {
        #[arg(long)]
        family: String,
        #[arg(long)]
        name: String,
    },
    List {
        #[arg(long)]
        family: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EvalSuiteCommand {
    Create {
        #[arg(long)]
        name: String,
    },
    Add {
        #[arg(long)]
        suite: String,
        #[arg(long)]
        case: String,
    },
    Freeze {
        #[arg(long)]
        suite: String,
    },
}

#[derive(Debug, Subcommand)]
enum EvalBaselineCommand {
    Create {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
        #[arg(long, default_value = "latest")]
        run: String,
    },
    List {
        #[arg(long, default_value = "core-smoke")]
        suite: String,
    },
}

#[derive(Debug, Subcommand)]
enum VerifyCommand {
    Inventory,
    Profiles,
    Plan {
        #[arg(long, default_value = "dev-fast")]
        profile: String,
    },
    Run {
        #[arg(long, default_value = "dev-fast")]
        profile: String,
    },
    Verdict {
        #[arg(long, default_value = "latest")]
        run: String,
    },
    CostReport,
    Flake {
        #[arg(long, default_value = "change-gate")]
        profile: String,
        #[arg(long, default_value_t = 2)]
        repeat: u64,
    },
    DbIsolation,
    Report,
    DevFast,
    ChangeGate,
    ProviderGate,
    Full,
}

#[derive(Debug, Subcommand)]
enum MetricsCommand {
    Registry,
    RecordSmoke,
    Rollup {
        #[arg(long, default_value = "one-run")]
        window: String,
    },
    Slo,
    Latency,
    Cost,
    Quality,
    Dashboard,
    Report,
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    Completeness {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum ReplayCommand {
    Case {
        #[command(subcommand)]
        command: ReplayCaseCommand,
    },
    Set {
        #[command(subcommand)]
        command: ReplaySetCommand,
    },
    Run {
        #[arg(long, default_value = "latest")]
        set: String,
    },
    Verdict {
        #[arg(long, default_value = "latest")]
        run: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum ReplayCaseCommand {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "regression")]
        kind: String,
    },
}

#[derive(Debug, Subcommand)]
enum ReplaySetCommand {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long, default_value = "replay-smoke")]
        name: String,
        #[arg(long)]
        fixed: bool,
        #[arg(long)]
        holdout: bool,
    },
    Add {
        #[arg(long, default_value = "latest")]
        case: String,
    },
}

#[derive(Debug, Subcommand)]
enum SleepCommand {
    Run {
        #[arg(long, default_value = "eliot-governor")]
        project: String,
        #[arg(long, default_value = "manual")]
        trigger: String,
        #[arg(long)]
        dry_run: bool,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum DreamCommand {
    Candidate {
        #[command(subcommand)]
        command: DreamCandidateCommand,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum DreamCandidateCommand {
    Create {
        #[arg(long, default_value = "eliot-governor")]
        project: String,
        #[arg(long, default_value = "hypothesis")]
        kind: String,
        #[arg(long, default_value = "trace:latest")]
        source_trace: String,
    },
}

#[derive(Debug, Subcommand)]
enum ActionCommand {
    Plan {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        goal: String,
    },
    ValidatePlan {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    LeaseStatus {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
}

#[derive(Debug, Subcommand)]
enum PatchCommand {
    Preflight {
        #[arg(long)]
        lease: String,
        #[arg(long)]
        diff: PathBuf,
    },
    Apply {
        #[arg(long)]
        lease: String,
        #[arg(long)]
        diff: PathBuf,
    },
    Status {
        #[arg(long = "patch-run")]
        patch_run: String,
    },
}

#[derive(Debug, Subcommand)]
enum WorkCommand {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        goal: String,
        #[arg(long = "read")]
        read: Vec<String>,
        #[arg(long = "write")]
        write: Vec<String>,
    },
    Claim {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "implementer")]
        role: String,
    },
    Status {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Renew {
        #[arg(long)]
        lease: String,
    },
    Release {
        #[arg(long)]
        lease: String,
    },
    Revoke {
        #[arg(long)]
        lease: String,
    },
    Conflicts {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
}

#[derive(Debug, Subcommand)]
enum WorktreeCommand {
    Create {
        #[arg(long = "work-lease")]
        work_lease: String,
    },
    Status {
        #[arg(long = "worktree-lease")]
        worktree_lease: String,
    },
    CaptureDiff {
        #[arg(long = "worktree-lease")]
        worktree_lease: String,
    },
    Review {
        #[arg(long = "candidate-diff")]
        candidate_diff: String,
        #[arg(long, default_value = "accept")]
        decision: String,
    },
    Cleanup {
        #[arg(long = "worktree-lease")]
        worktree_lease: String,
    },
}

#[derive(Debug, Subcommand)]
enum BlackboardCommand {
    Add {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "finding")]
        kind: String,
        #[arg(long = "payload-ref")]
        payload_ref: String,
        #[arg(long = "evidence")]
        evidence: Vec<String>,
        #[arg(long)]
        confidence: Option<String>,
    },
    List {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Ack {
        #[arg(long)]
        item: String,
        #[arg(long)]
        session: Option<String>,
    },
    Resolve {
        #[arg(long)]
        item: String,
    },
    Reject {
        #[arg(long)]
        item: String,
    },
}

#[derive(Debug, Subcommand)]
enum MailboxCommand {
    Send {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "ack-required")]
        kind: String,
        #[arg(long = "payload-ref")]
        payload_ref: String,
        #[arg(long, default_value = "controller")]
        recipient: String,
        #[arg(long = "message-id")]
        message_id: Option<String>,
    },
    Inbox {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Ack {
        #[arg(long)]
        message: String,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    Scan {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Report {
        #[arg(long)]
        latest: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CollectiveCommand {
    Trace {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Report {
        #[arg(long)]
        latest: bool,
    },
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum RuntimeCommand {
    Status,
    Health,
    Report,
}

#[derive(Debug, Subcommand)]
enum ModuleCommand {
    List,
    Inspect {
        #[arg(long)]
        module: String,
    },
    Health,
    ValidateManifest {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum LogsCommand {
    Tail {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    Inspect {
        #[arg(long)]
        trace: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum AdapterCommand {
    List,
    Inspect {
        #[arg(long)]
        adapter: String,
    },
    Health,
    ExecuteTest {
        #[arg(long)]
        adapter: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum VerifierCommand {
    Run {
        #[arg(long)]
        plan: String,
    },
    Status {
        #[arg(long)]
        task: String,
    },
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum HookCommand {
    SessionStart,
    UserPromptSubmit,
    SubagentStart,
    PreToolUse,
    PermissionRequest,
    PostToolUse,
    PreCompact,
    PostCompact,
    SubagentStop,
    Stop,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Stdio {
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        instance: Option<String>,
    },
    /// Print the tools and prompts a host surface sees, without starting a
    /// server. Package manifests are generated from this, never transcribed.
    Catalog {
        #[arg(long, default_value = "claude")]
        host: String,
        /// `code` or `desktop` for the Claude host family.
        #[arg(long, default_value = "desktop")]
        surface: String,
    },
}

#[derive(Debug, Subcommand)]
enum HostCommand {
    CognitiveSeal {
        /// Exact immutable cognitive contract JSON.
        #[arg(long)]
        request: PathBuf,
        #[arg(long, default_value = "default")]
        instance: String,
    },
    CognitiveRun {
        /// Sealed JSON request consumed by the unified provider runner.
        #[arg(long)]
        request: PathBuf,
        #[arg(long, default_value = "default")]
        instance: String,
    },
    CognitiveStatus {
        #[arg(long)]
        run: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
        #[arg(long, default_value = "default")]
        instance: String,
    },
    Inspect {
        #[arg(long)]
        host: String,
    },
    Doctor {
        #[arg(long)]
        host: String,
    },
    Render {
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "interactive")]
        mode: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        agent_session: Option<String>,
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        work_item: Option<String>,
        #[arg(long)]
        role_lease: Option<String>,
        #[arg(long)]
        work_lease: Option<String>,
        #[arg(long)]
        worktree_lease: Option<String>,
        #[arg(long)]
        planned_verifier_ref: Option<String>,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        write_path: Vec<String>,
    },
    Launch {
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "interactive")]
        mode: String,
        #[arg(long)]
        cwd: Option<PathBuf>,
        #[arg(long)]
        model: Option<String>,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        agent_session: Option<String>,
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        work_item: Option<String>,
        #[arg(long)]
        role_lease: Option<String>,
        #[arg(long)]
        work_lease: Option<String>,
        #[arg(long)]
        worktree_lease: Option<String>,
        #[arg(long)]
        planned_verifier_ref: Option<String>,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        write_path: Vec<String>,
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long)]
        idempotency_key: Option<String>,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(long)]
        dry_run: bool,
    },
    InvocationStatus {
        #[arg(long)]
        idempotency_key: String,
    },
    Install {
        #[arg(long)]
        host: String,
        #[arg(long)]
        dry_run: bool,
        /// Maximum time to wait for a host-owned interactive installer to finish.
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    /// Select which packaged surface of a host family is the active one.
    ///
    /// Claude ships as a Code plugin and a Desktop MCPB. Both active at once
    /// exposes the tool set twice to a Claude Code session hosted in Desktop,
    /// so exactly one is selected and the other is stood down.
    Activate {
        #[arg(long)]
        host: String,
        /// `code` or `desktop` for the Claude host family.
        #[arg(long)]
        surface: String,
        #[arg(long)]
        dry_run: bool,
    },
    Uninstall {
        #[arg(long)]
        host: String,
        #[arg(long)]
        dry_run: bool,
        /// Maximum time to wait for a host-owned interactive uninstaller to finish.
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    Event {
        #[arg(long)]
        host: String,
        #[arg(long)]
        event: String,
    },
    SessionRegister {
        #[arg(long)]
        host: String,
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        client_instance: Option<String>,
    },
    RoleGrant {
        #[arg(long)]
        task: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        role: String,
        #[arg(long, value_delimiter = ',')]
        capability: Vec<String>,
        #[arg(long, default_value_t = 30)]
        ttl_minutes: i64,
    },
    BrokerStatus,
    SkillLint,
    /// Rewrite every derived host skill package from the canonical bodies.
    SkillSync,
}

#[derive(Debug, Subcommand)]
enum MemoryLifecycleCommand {
    Status {
        #[arg(long)]
        project: String,
        #[arg(long = "ref")]
        memory_ref: String,
    },
    Propose {
        #[arg(long)]
        project: String,
        #[arg(long = "ref")]
        memory_ref: String,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        reason: String,
    },
    Apply {
        #[arg(long)]
        policy: String,
    },
    Vitality {
        #[arg(long)]
        project: String,
    },
    Gravity {
        #[arg(long)]
        project: String,
    },
    Influence {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum SkillCommand {
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        name: String,
    },
    List {
        #[arg(long)]
        project: String,
    },
    Inspect {
        #[arg(long)]
        skill: String,
    },
    Activate {
        #[arg(long)]
        skill: String,
    },
    Archive {
        #[arg(long)]
        skill: String,
        #[arg(long)]
        reason: String,
    },
    Quarantine {
        #[arg(long)]
        skill: String,
        #[arg(long)]
        reason: String,
    },
    Estimate {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Filter {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    ExecutionProof {
        #[arg(long)]
        skill: String,
        #[arg(long)]
        task: String,
    },
    Influence {
        #[arg(long)]
        project: String,
        #[arg(long)]
        task: String,
    },
    Report,
}

#[derive(Debug, Subcommand)]
enum SkillCuratorCommand {
    Run {
        #[arg(long)]
        project: String,
        #[arg(long)]
        dry_run: bool,
    },
    Inspect {
        #[arg(long)]
        run: String,
    },
    Proposals {
        #[arg(long)]
        project: String,
    },
    Gate {
        #[arg(long)]
        proposal: String,
    },
    Apply {
        #[arg(long)]
        proposal: String,
    },
    RollbackPlan {
        #[arg(long)]
        proposal: String,
    },
    Report,
}

fn main() -> Result<()> {
    let handle = std::thread::Builder::new()
        .name("eliot-governor-main".to_owned())
        // Clap and `dispatch_command` are deliberately broad state machines. Parse and run
        // both on the reserved stack so the small Windows process-entry stack is never the
        // limiting factor as governed commands and MCP contracts grow.
        .stack_size(32 * 1024 * 1024)
        .spawn(move || -> Result<()> {
            init_tracing();
            let cli = Cli::parse();
            let (config, implicit_instance) = match cli.config {
                Some(config) => (config, None),
                None => (
                    runtime_instance::default_config_path()?,
                    Some(runtime_instance::DEFAULT_INSTANCE_NAME.to_owned()),
                ),
            };
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(Box::pin(dispatch_command(
                &config,
                cli.command,
                implicit_instance.as_deref(),
            )))
        })?;
    handle
        .join()
        .map_err(|_| anyhow::anyhow!("eliot-governor main thread panicked"))?
}

#[allow(clippy::too_many_lines)]
async fn dispatch_command(
    config: &Path,
    command: Command,
    implicit_instance: Option<&str>,
) -> Result<()> {
    match command {
        Command::Dogfood { command } => match command {
            DogfoodCommand::Init { root, project } => dogfood::init(&root, &project),
            DogfoodCommand::Start { root } => dogfood::start(&root).await,
            DogfoodCommand::Doctor { root } => dogfood::doctor(&root).await,
            DogfoodCommand::Status { root } => dogfood::status(&root).await,
            DogfoodCommand::PrepareWorktree {
                root,
                destination,
                branch,
                commit,
            } => dogfood::prepare_worktree(&root, &destination, &branch, &commit),
            DogfoodCommand::RunCodex { root } => dogfood::run_codex(&root).await,
            DogfoodCommand::Stop { root } => dogfood::stop(&root).await,
        },
        Command::Doctor { command } => dispatch_doctor_command(config, command).await,
        Command::DataRoot { command } => dispatch_data_root_command(config, command),
        Command::Backup { command } => dispatch_backup_command(config, command),
        Command::Restore { command } => dispatch_restore_command(config, command),
        Command::Export { command } => dispatch_export_command(config, command),
        Command::Import { command } => dispatch_import_command(config, command).await,
        Command::Blob { command } => dispatch_blob_command(config, command).await,
        Command::Cutover { command } => dispatch_cutover_command(config, command),
        Command::Maintenance { command } => dispatch_maintenance_command(config, command).await,
        Command::Incident { command } => dispatch_incident_command(config, command),
        Command::Daemon { command } => match command {
            DaemonCommand::InitDefault {
                source_config,
                force,
            } => commands::run_daemon_init_default(config, &source_config, force),
            DaemonCommand::Run { instance } => {
                commands::run_daemon(
                    config,
                    selected_instance(instance, implicit_instance).as_deref(),
                )
                .await
            }
            DaemonCommand::Status { instance } => commands::run_daemon_status(
                config,
                selected_instance(instance, implicit_instance).as_deref(),
            ),
            DaemonCommand::Health { instance } => commands::run_daemon_health(
                config,
                selected_instance(instance, implicit_instance).as_deref(),
            ),
            DaemonCommand::Doctor { instance } => commands::run_daemon_doctor(
                config,
                selected_instance(instance, implicit_instance).as_deref(),
            ),
            DaemonCommand::Stop { instance } => commands::run_daemon_stop(
                config,
                selected_instance(instance, implicit_instance).as_deref(),
            ),
        },
        Command::Service { command } => match command {
            ServiceCommand::Run => windows_service::run_dispatcher().map_err(Into::into),
            ServiceCommand::Validate => commands::run_service_validate(config),
            ServiceCommand::Install { dry_run } => commands::run_service_install(config, dry_run),
            ServiceCommand::Uninstall { dry_run } => {
                commands::run_service_uninstall(config, dry_run)
            }
            ServiceCommand::Status => commands::run_service_status(config),
            ServiceCommand::Start => commands::run_service_start(config),
            ServiceCommand::Stop => commands::run_service_stop(config),
            ServiceCommand::Restart => commands::run_service_restart(config),
            ServiceCommand::Report => commands::run_service_report(config),
        },
        Command::Ipc { command } => match command {
            IpcCommand::Smoke => commands::run_ipc_smoke(config),
            IpcCommand::Handshake => commands::run_ipc_handshake(config),
            IpcCommand::Status => commands::run_ipc_status(config),
            IpcCommand::Report => commands::run_ipc_report(config),
        },
        Command::Credentials { command } => match command {
            CredentialsCommand::Validate => commands::run_credentials_validate(config),
            CredentialsCommand::Report => commands::run_credentials_report(config),
        },
        Command::Security { command } => match command {
            SecurityCommand::ScanCanonical => security_scan::run_canonical(config).await,
            SecurityCommand::RotateLegacyCredential => {
                security_scan::rotate_legacy_credential(config).await
            }
            SecurityCommand::RotateOperatorCursorCredential {
                instance,
                remove_legacy_file,
            } => security_scan::rotate_operator_cursor_credential(
                config,
                instance.as_deref(),
                remove_legacy_file,
            ),
        },
        Command::Readiness { command } => match command {
            ReadinessCommand::Probe => commands::run_readiness_probe(config),
            ReadinessCommand::Report => commands::run_readiness_report(config),
        },
        Command::StartupRecovery { command } => match command {
            StartupRecoveryCommand::Scan => commands::run_startup_recovery_scan(config),
            StartupRecoveryCommand::Report => commands::run_startup_recovery_report(config),
        },
        Command::Db { command } => match command {
            DbCommand::Start => commands::run_db_start(config).await,
            DbCommand::Stop => commands::run_db_stop(config).await,
            DbCommand::Status => commands::run_db_status(config).await,
            DbCommand::Smoke => commands::run_db_smoke(config).await,
            DbCommand::Migrate => commands::run_db_migrate(config).await,
        },
        Command::Writer { command } => match command {
            WriterCommand::Status => commands::run_writer_status(config).await,
            WriterCommand::Smoke => commands::run_writer_smoke(config).await,
            WriterCommand::Drain => commands::run_writer_drain(config),
        },
        Command::Memory { command } => match command {
            MemoryCommand::CurrentState { project } => {
                commands::run_memory_current_state(config, &project).await
            }
            MemoryCommand::RecallL0 { project, query } => {
                commands::run_memory_recall_l0(config, &project, &query).await
            }
            MemoryCommand::FetchL2 { project, handles } => {
                commands::run_memory_fetch_l2(config, &project, &handles).await
            }
        },
        Command::MemoryLifecycle { command } => match command {
            MemoryLifecycleCommand::Status {
                project,
                memory_ref,
            } => commands::run_memory_lifecycle_status(config, &project, &memory_ref),
            MemoryLifecycleCommand::Propose {
                project,
                memory_ref,
                operator,
                reason,
            } => commands::run_memory_lifecycle_propose(
                config,
                &project,
                &memory_ref,
                &operator,
                &reason,
            ),
            MemoryLifecycleCommand::Apply { policy } => {
                commands::run_memory_lifecycle_apply(config, &policy).await
            }
            MemoryLifecycleCommand::Vitality { project } => {
                commands::run_memory_lifecycle_vitality(config, &project)
            }
            MemoryLifecycleCommand::Gravity { project } => {
                commands::run_memory_lifecycle_gravity(config, &project)
            }
            MemoryLifecycleCommand::Influence { project, task } => {
                commands::run_memory_lifecycle_influence(config, &project, &task).await
            }
            MemoryLifecycleCommand::Report => commands::run_memory_lifecycle_report(config),
        },
        Command::Skill { command } => dispatch_skill_command(config, command).await,
        Command::SkillCurator { command } => dispatch_skill_curator_command(config, command).await,
        Command::Graph {
            command: GraphCommand::Health,
        } => commands::run_graph_health(config).await,
        Command::Ul { command } => match command {
            commands::UlCommand::MineGit { project, root } => {
                commands::run_ul_mine_git(config, project, &root).await
            }
            commands::UlCommand::Onboard { project, root } => {
                commands::run_ul_onboard(config, project, &root).await
            }
            commands::UlCommand::Report { project } => {
                commands::run_ul_report(config, project).await
            }
            commands::UlCommand::Maintain {
                project,
                root,
                limit,
            } => commands::run_ul_maintain(config, project, &root, limit).await,
            commands::UlCommand::DirtyReport { project } => {
                commands::run_ul_dirty_report(config, project).await
            }
        },
        Command::Codecortex { command } => match command {
            CodeCortexCommand::Health => commands::run_codecortex_health(config),
            CodeCortexCommand::Scan {
                project,
                task,
                goal,
            } => commands::run_codecortex_scan(config, &project, &task, &goal).await,
            CodeCortexCommand::Report { latest } => commands::run_codecortex_report(config, latest),
        },
        Command::ExternalReview { command } => {
            dispatch_external_review_command(config, command).await
        }
        Command::Delegate { command } => dispatch_delegate_command(config, command).await,
        Command::DelegationCalibration { command } => {
            dispatch_delegation_calibration_command(config, command)
        }
        Command::Antigravity { command } => dispatch_antigravity_command(config, command).await,
        Command::Eval { command } => dispatch_eval_command(config, command),
        Command::Verify { command } => dispatch_verify_command(config, command),
        Command::Metrics { command } => dispatch_metrics_command(config, command),
        Command::Trace { command } => match command {
            TraceCommand::Completeness { project, task } => {
                commands::run_trace_completeness(config, &project, &task)
            }
            TraceCommand::Report => commands::run_trace_report(config),
        },
        Command::Replay { command } => match command {
            ReplayCommand::Case { command } => match command {
                ReplayCaseCommand::Create {
                    project,
                    task,
                    kind,
                } => commands::run_replay_case_create(config, &project, &task, &kind),
            },
            ReplayCommand::Set { command } => match command {
                ReplaySetCommand::Create {
                    project,
                    name,
                    fixed,
                    holdout,
                } => commands::run_replay_set_create(config, &project, &name, fixed, holdout),
                ReplaySetCommand::Add { case } => commands::run_replay_set_add(config, &case),
            },
            ReplayCommand::Run { set } => commands::run_replay_run(config, &set),
            ReplayCommand::Verdict { run } => commands::run_replay_verdict(config, &run),
            ReplayCommand::Report => commands::run_replay_report(config),
        },
        Command::Sleep { command } => match command {
            SleepCommand::Run {
                project,
                trigger,
                dry_run,
            } => commands::run_sleep_run(config, &project, &trigger, dry_run),
            SleepCommand::Report => commands::run_sleep_report(config),
        },
        Command::Dream { command } => match command {
            DreamCommand::Candidate { command } => match command {
                DreamCandidateCommand::Create {
                    project,
                    kind,
                    source_trace,
                } => commands::run_dream_candidate_create(config, &project, &kind, &source_trace),
            },
            DreamCommand::Report => commands::run_dream_report(config),
        },
        Command::Action { command } => match command {
            ActionCommand::Plan {
                project,
                task,
                goal,
            } => commands::run_action_plan(config, &project, &task, &goal).await,
            ActionCommand::ValidatePlan { project, task } => {
                commands::run_action_validate_plan(config, &project, &task).await
            }
            ActionCommand::LeaseStatus { project, task } => {
                commands::run_action_lease_status(config, &project, &task)
            }
        },
        Command::Patch { command } => dispatch_patch_command(config, command).await,
        Command::Work { command } => dispatch_work_command(config, command).await,
        Command::Worktree { command } => dispatch_worktree_command(config, command).await,
        Command::Blackboard { command } => dispatch_blackboard_command(config, command).await,
        Command::Mailbox { command } => dispatch_mailbox_command(config, command).await,
        Command::Recovery { command } => dispatch_recovery_command(config, command).await,
        Command::Collective { command } => dispatch_collective_command(config, command).await,
        Command::Runtime { command } => dispatch_runtime_command(config, command),
        Command::Module { command } => dispatch_module_command(config, command),
        Command::Logs { command } => dispatch_logs_command(config, command),
        Command::Adapter { command } => dispatch_adapter_command(config, command).await,
        Command::Verifier { command } => dispatch_verifier_command(config, command).await,
        Command::Hook { command } => dispatch_hook_command(config, command),
        Command::Mcp {
            command:
                McpCommand::Stdio {
                    profile,
                    host,
                    instance,
                },
        } => {
            mcp_stdio::run(
                config,
                &profile,
                host.as_deref(),
                selected_instance(instance, implicit_instance).as_deref(),
            )
            .await
        }
        Command::Mcp {
            command: McpCommand::Catalog { host, surface },
        } => {
            anyhow::ensure!(
                host.trim().eq_ignore_ascii_case("claude"),
                "only the Claude host family exposes surface catalogs"
            );
            let surface = eliot_types::ClaudeSurface::parse(&surface).ok_or_else(|| {
                anyhow::anyhow!("unknown Claude surface {surface}; expected `code` or `desktop`")
            })?;
            let catalog = mcp_stdio::claude_surface_catalog(surface);
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &catalog)?;
            writeln!(stdout)?;
            Ok(())
        }
        Command::Host { command } => Box::pin(host_runtime::dispatch(config, command)).await,
    }
}

async fn dispatch_external_review_command(
    config: &Path,
    command: ExternalReviewCommand,
) -> Result<()> {
    match command {
        ExternalReviewCommand::Providers => commands::run_external_review_providers(config),
        ExternalReviewCommand::Provider { command } => match command {
            ExternalReviewProviderCommand::Inspect { provider } => {
                commands::run_external_review_provider_inspect(config, &provider)
            }
        },
        ExternalReviewCommand::Request {
            project,
            task,
            provider,
            role,
            question,
        } => commands::run_external_review_request(
            config, &project, &task, &provider, &role, &question,
        ),
        ExternalReviewCommand::Job { command } => match command {
            ExternalReviewJobCommand::Status { job } => {
                commands::run_external_review_job_status(config, &job)
            }
        },
        ExternalReviewCommand::RunMock { request } => {
            commands::run_external_review_run_mock(config, &request).await
        }
        ExternalReviewCommand::Result { command } => match command {
            ExternalReviewResultCommand::Inspect { result } => {
                commands::run_external_review_result_inspect(config, &result)
            }
        },
        ExternalReviewCommand::Report => commands::run_external_review_report(config),
    }
}

#[allow(clippy::print_stdout, clippy::too_many_lines)]
async fn dispatch_delegate_command(config: &Path, command: DelegateCommand) -> Result<()> {
    use eliot_types::DelegationProviderPreference;
    let root = delegation_runtime::root_from_config(config);
    let value = match command {
        DelegateCommand::Policy => delegation_runtime::policy_report(),
        DelegateCommand::Health => serde_json::to_value(delegation_runtime::health(&root)?)?,
        DelegateCommand::Explain {
            origin,
            review_kind,
            question,
        } => delegation_runtime::explain(
            parse_delegation_origin(&origin)?,
            parse_delegation_kind(&review_kind)?,
            &question,
        ),
        DelegateCommand::Request {
            project,
            task,
            origin,
            review_kind,
            work_lease,
            question,
            evidence_refs,
            preferred_provider,
            wait,
        } => {
            let preferred_provider = match preferred_provider.as_str() {
                "auto" => DelegationProviderPreference::Auto,
                "antigravity" => DelegationProviderPreference::Antigravity,
                other => anyhow::bail!("unsupported delegation provider preference: {other}"),
            };
            delegation_runtime::review(
                &root,
                delegation_runtime::DelegationReviewInput {
                    project_id: project,
                    task_id: task,
                    origin: parse_delegation_origin(&origin)?,
                    review_kind: parse_delegation_kind(&review_kind)?,
                    question,
                    work_lease_id: work_lease,
                    evidence_refs,
                    preferred_provider,
                    wait,
                    origin_chain: None,
                    campaign_id: None,
                    idempotency_key: None,
                    require_budget_slot: false,
                    explicit_operator_intent: false,
                    preregistration_id: None,
                    execution_token: None,
                },
            )
            .await?
        }
        DelegateCommand::ExecuteProvider {
            campaign,
            project,
            task,
            origin,
            review_kind,
            work_lease,
            question,
            evidence_refs,
            idempotency_key,
            preferred_provider,
            require_budget_slot,
            confirm_operator_intent,
            wait,
        } => {
            let preferred_provider = match preferred_provider.as_str() {
                "auto" => DelegationProviderPreference::Auto,
                "antigravity" => DelegationProviderPreference::Antigravity,
                other => anyhow::bail!("unsupported delegation provider preference: {other}"),
            };
            delegation_runtime::review(
                &root,
                delegation_runtime::DelegationReviewInput {
                    project_id: project,
                    task_id: task,
                    origin: parse_delegation_origin(&origin)?,
                    review_kind: parse_delegation_kind(&review_kind)?,
                    question,
                    work_lease_id: work_lease,
                    evidence_refs,
                    preferred_provider,
                    wait,
                    origin_chain: None,
                    campaign_id: Some(campaign),
                    idempotency_key: Some(idempotency_key),
                    require_budget_slot,
                    explicit_operator_intent: confirm_operator_intent,
                    preregistration_id: None,
                    execution_token: None,
                },
            )
            .await?
        }
        DelegateCommand::Status { delegation } => delegation_runtime::status(&root, &delegation)?,
        DelegateCommand::Result { delegation } => delegation_runtime::result(&root, &delegation)?,
        DelegateCommand::Outcome { delegation } => delegation_runtime::outcome(&root, &delegation)?,
        DelegateCommand::Budgets => delegation_runtime::budgets(&root)?,
        DelegateCommand::ShadowReport => delegation_runtime::shadow_report(&root)?,
        DelegateCommand::Report => delegation_runtime::report(&root)?,
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[allow(clippy::print_stdout)]
fn dispatch_delegation_calibration_command(
    config_path: &Path,
    command: DelegationCalibrationCommand,
) -> Result<()> {
    let root = delegation_runtime::root_from_config(config_path);
    let loaded = config::load_config(config_path)?;
    let value = match command {
        DelegationCalibrationCommand::Ingest => calibration_runtime::ingest(&root)?,
        DelegationCalibrationCommand::Status => calibration_runtime::status(&root)?,
        DelegationCalibrationCommand::Samples => calibration_runtime::samples(&root)?,
        DelegationCalibrationCommand::ShadowRun => calibration_runtime::shadow_run(&root)?,
        DelegationCalibrationCommand::FamilyReport => {
            calibration_runtime::family_report(&root, &loaded.delegation_calibration)?
        }
        DelegationCalibrationCommand::PolicyCandidate => {
            calibration_runtime::policy_candidate(&root)?
        }
        DelegationCalibrationCommand::PromotionGate => {
            calibration_runtime::promotion_gate(&root, &loaded.delegation_calibration)?
        }
        DelegationCalibrationCommand::Report => calibration_runtime::report(&root)?,
        DelegationCalibrationCommand::CampaignPreview {
            project,
            task,
            family,
            selection_rule,
            provider_route,
            policy_snapshot,
            max_provider_calls,
            max_cost,
            max_wall_time,
            frozen_inputs,
        } => calibration_runtime::campaign_preview(
            &root,
            &loaded.delegation_calibration,
            calibration_runtime::CampaignPreviewInput {
                project_id: project.parse()?,
                task_id: task.parse()?,
                task_family: parse_calibration_family(&family)?,
                selection_rule,
                provider_route,
                policy_snapshot_id: policy_snapshot,
                max_provider_calls,
                max_cost_if_known: max_cost,
                max_wall_time_seconds: max_wall_time,
                frozen_input_refs: frozen_inputs,
            },
        )?,
        DelegationCalibrationCommand::CampaignBindReview {
            campaign,
            delegation,
        } => calibration_runtime::campaign_bind_review(&root, &campaign, &delegation)?,
        DelegationCalibrationCommand::EvidenceAttach { path } => {
            calibration_runtime::attach_independent_evidence(&root, &path)?
        }
        DelegationCalibrationCommand::CampaignCloseout { campaign } => {
            calibration_runtime::campaign_closeout(
                &root,
                &loaded.delegation_calibration,
                &campaign,
            )?
        }
        DelegationCalibrationCommand::CampaignStatus { campaign } => {
            calibration_runtime::campaign_status(&root, &campaign)?
        }
        DelegationCalibrationCommand::IntegrityReconcile { campaign } => {
            calibration_runtime::integrity_reconcile(
                &root,
                &loaded.delegation_calibration,
                &campaign,
            )?
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn parse_delegation_origin(value: &str) -> Result<eliot_types::DelegationOrigin> {
    use eliot_types::DelegationOrigin;
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "user-directed" => Ok(DelegationOrigin::UserDirected),
        "codex-requested" => Ok(DelegationOrigin::CodexRequested),
        "policy-shadow" => Ok(DelegationOrigin::PolicyShadow),
        other => anyhow::bail!("unsupported delegation origin: {other}"),
    }
}

fn parse_delegation_kind(value: &str) -> Result<eliot_types::DelegationReviewKind> {
    use eliot_types::DelegationReviewKind;
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "architecture-audit" => Ok(DelegationReviewKind::ArchitectureAudit),
        "risk-review" => Ok(DelegationReviewKind::RiskReview),
        "diff-audit" => Ok(DelegationReviewKind::DiffAudit),
        "verifier-advice" => Ok(DelegationReviewKind::VerifierAdvice),
        other => anyhow::bail!("unsupported delegation review kind: {other}"),
    }
}

fn parse_calibration_family(value: &str) -> Result<eliot_types::DelegationCalibrationTaskFamily> {
    use eliot_types::DelegationCalibrationTaskFamily;
    match value.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "security-boundary" => Ok(DelegationCalibrationTaskFamily::SecurityBoundary),
        "external-integration" => Ok(DelegationCalibrationTaskFamily::ExternalIntegration),
        "architecture-design" => Ok(DelegationCalibrationTaskFamily::ArchitectureDesign),
        "broad-diff-review" => Ok(DelegationCalibrationTaskFamily::BroadDiffReview),
        "verifier-design" => Ok(DelegationCalibrationTaskFamily::VerifierDesign),
        "repeated-failure-diagnosis" => {
            Ok(DelegationCalibrationTaskFamily::RepeatedFailureDiagnosis)
        }
        "evidence-gap-review" => Ok(DelegationCalibrationTaskFamily::EvidenceGapReview),
        "trivial-deterministic-task" => {
            Ok(DelegationCalibrationTaskFamily::TrivialDeterministicTask)
        }
        "other" => Ok(DelegationCalibrationTaskFamily::Other),
        other => anyhow::bail!("unsupported delegation calibration family: {other}"),
    }
}

async fn dispatch_antigravity_command(config: &Path, command: AntigravityCommand) -> Result<()> {
    match command {
        AntigravityCommand::WindowsDiscover => commands::run_antigravity_windows_discover(config),
        AntigravityCommand::VersionCheck => commands::run_antigravity_version_check(config),
        AntigravityCommand::InstallReceipt => commands::run_antigravity_install_receipt(config),
        AntigravityCommand::Resolve => commands::run_antigravity_resolve(config),
        AntigravityCommand::Detect => commands::run_antigravity_detect(config),
        AntigravityCommand::Status => commands::run_antigravity_status(config),
        AntigravityCommand::Doctor => commands::run_antigravity_doctor(config),
        AntigravityCommand::CommandContract => commands::run_antigravity_command_contract(config),
        AntigravityCommand::AuthCheck => commands::run_antigravity_auth_check(config),
        AntigravityCommand::Enable {
            scope,
            admin_confirm,
        } => commands::run_antigravity_enable(config, &scope, admin_confirm),
        AntigravityCommand::Disable { reason } => {
            commands::run_antigravity_disable(config, &reason)
        }
        AntigravityCommand::LiveSmoke { mode } => {
            commands::run_antigravity_live_smoke(config, &mode).await
        }
        AntigravityCommand::Rollback => commands::run_antigravity_rollback(config),
        AntigravityCommand::RealReport => commands::run_antigravity_real_report(config),
        AntigravityCommand::Request {
            project,
            task,
            mode,
            question,
        } => commands::run_antigravity_request(config, &project, &task, &mode, &question),
        AntigravityCommand::Run { request, dry_run } => {
            commands::run_antigravity_run(config, &request, dry_run)
        }
        AntigravityCommand::JobStatus { run } => commands::run_antigravity_job_status(config, &run),
        AntigravityCommand::Result { run } => commands::run_antigravity_result(config, &run),
        AntigravityCommand::Plugin { command } => match command {
            AntigravityPluginCommand::Schema => commands::run_antigravity_plugin_schema(config),
            AntigravityPluginCommand::InstallOfficial { admin_confirm } => {
                commands::run_antigravity_plugin_install_official(config, admin_confirm)
            }
        },
        AntigravityCommand::Mcp { command } => match command {
            AntigravityMcpCommand::ConfigStatus => {
                commands::run_antigravity_mcp_config_status(config)
            }
            AntigravityMcpCommand::Register { admin_confirm } => {
                commands::run_antigravity_mcp_register(config, admin_confirm)
            }
            AntigravityMcpCommand::BackupList => commands::run_antigravity_mcp_backup_list(config),
            AntigravityMcpCommand::InvocationProof => {
                commands::run_antigravity_mcp_invocation_proof(config)
            }
        },
        AntigravityCommand::Visibility => commands::run_antigravity_visibility(config),
        AntigravityCommand::Report => commands::run_antigravity_report(config),
    }
}

fn dispatch_eval_command(config: &Path, command: EvalCommand) -> Result<()> {
    match command {
        EvalCommand::Case { command } => match command {
            EvalCaseCommand::Create { family, name } => {
                commands::run_eval_case_create(config, &family, &name)
            }
            EvalCaseCommand::List { family } => {
                commands::run_eval_case_list(config, family.as_deref())
            }
        },
        EvalCommand::Suite { command } => match command {
            EvalSuiteCommand::Create { name } => commands::run_eval_suite_create(config, &name),
            EvalSuiteCommand::Add { suite, case } => {
                commands::run_eval_suite_add(config, &suite, &case)
            }
            EvalSuiteCommand::Freeze { suite } => commands::run_eval_suite_freeze(config, &suite),
        },
        EvalCommand::Manifest { suite } => commands::run_eval_manifest(config, &suite),
        EvalCommand::Run { suite, profile } => commands::run_eval_run(config, &suite, &profile),
        EvalCommand::Verdict { run } => commands::run_eval_verdict(config, &run),
        EvalCommand::Failures { run } => commands::run_eval_failures(config, &run),
        EvalCommand::Coverage { suite } => commands::run_eval_coverage(config, &suite),
        EvalCommand::Baseline { command } => match command {
            EvalBaselineCommand::Create { suite, run } => {
                commands::run_eval_baseline_create(config, &suite, &run)
            }
            EvalBaselineCommand::List { suite } => commands::run_eval_baseline_list(config, &suite),
        },
        EvalCommand::Compare {
            suite,
            baseline,
            candidate_run,
        } => commands::run_eval_compare(config, &suite, &baseline, &candidate_run),
        EvalCommand::Gate { profile, suite } => commands::run_eval_gate(config, &profile, &suite),
        EvalCommand::Profiles => commands::run_eval_profiles(config),
        EvalCommand::Trend { suite } => commands::run_eval_trend(config, &suite),
        EvalCommand::Stability { suite, repeat } => {
            commands::run_eval_stability(config, &suite, repeat)
        }
        EvalCommand::IntegrationSmoke => commands::run_eval_integration_smoke(config),
        EvalCommand::Report => commands::run_eval_report(config),
        EvalCommand::Smoke { suite } => commands::run_eval_smoke(config, &suite),
    }
}

fn dispatch_verify_command(config: &Path, command: VerifyCommand) -> Result<()> {
    match command {
        VerifyCommand::Inventory => commands::run_verify_inventory(config),
        VerifyCommand::Profiles => commands::run_verify_profiles(config),
        VerifyCommand::Plan { profile } => commands::run_verify_plan(config, &profile),
        VerifyCommand::Run { profile } => commands::run_verify_run(config, &profile),
        VerifyCommand::Verdict { run } => commands::run_verify_verdict(config, &run),
        VerifyCommand::CostReport => commands::run_verify_cost_report(config),
        VerifyCommand::Flake { profile, repeat } => {
            commands::run_verify_flake(config, &profile, repeat)
        }
        VerifyCommand::DbIsolation => commands::run_verify_db_isolation(config),
        VerifyCommand::Report => commands::run_verify_report(config),
        VerifyCommand::DevFast => commands::run_verify_run(config, "dev-fast"),
        VerifyCommand::ChangeGate => commands::run_verify_run(config, "change-gate"),
        VerifyCommand::ProviderGate => commands::run_verify_run(config, "provider-gate"),
        VerifyCommand::Full => commands::run_verify_run(config, "full"),
    }
}

fn dispatch_metrics_command(config: &Path, command: MetricsCommand) -> Result<()> {
    match command {
        MetricsCommand::Registry => commands::run_metrics_registry(config),
        MetricsCommand::RecordSmoke => commands::run_metrics_record_smoke(config),
        MetricsCommand::Rollup { window } => commands::run_metrics_rollup(config, &window),
        MetricsCommand::Slo => commands::run_metrics_slo(config),
        MetricsCommand::Latency => commands::run_metrics_latency(config),
        MetricsCommand::Cost => commands::run_metrics_cost(config),
        MetricsCommand::Quality => commands::run_metrics_quality(config),
        MetricsCommand::Dashboard => commands::run_metrics_dashboard(config),
        MetricsCommand::Report => commands::run_metrics_report(config),
    }
}

async fn dispatch_skill_command(config: &Path, command: SkillCommand) -> Result<()> {
    match command {
        SkillCommand::Create { project, name } => {
            commands::run_skill_create(config, &project, &name).await
        }
        SkillCommand::List { project } => commands::run_skill_list(config, &project),
        SkillCommand::Inspect { skill } => commands::run_skill_inspect(config, &skill),
        SkillCommand::Activate { skill } => commands::run_skill_activate(config, &skill),
        SkillCommand::Archive { skill, reason } => {
            commands::run_skill_archive(config, &skill, &reason)
        }
        SkillCommand::Quarantine { skill, reason } => {
            commands::run_skill_quarantine(config, &skill, &reason)
        }
        SkillCommand::Estimate { project, task } => {
            commands::run_skill_estimate(config, &project, &task)
        }
        SkillCommand::Filter { project, task } => {
            commands::run_skill_filter(config, &project, &task)
        }
        SkillCommand::ExecutionProof { skill, task } => {
            commands::run_skill_execution_proof(config, &skill, &task).await
        }
        SkillCommand::Influence { project, task } => {
            commands::run_skill_influence(config, &project, &task).await
        }
        SkillCommand::Report => commands::run_skill_report(config),
    }
}

async fn dispatch_skill_curator_command(config: &Path, command: SkillCuratorCommand) -> Result<()> {
    match command {
        SkillCuratorCommand::Run { project, dry_run } => {
            commands::run_skill_curator_run(config, &project, dry_run).await
        }
        SkillCuratorCommand::Inspect { run } => commands::run_skill_curator_inspect(config, &run),
        SkillCuratorCommand::Proposals { project } => {
            commands::run_skill_curator_proposals(config, &project).await
        }
        SkillCuratorCommand::Gate { proposal } => {
            commands::run_skill_curator_gate(config, &proposal)
        }
        SkillCuratorCommand::Apply { proposal } => {
            commands::run_skill_curator_apply(config, &proposal).await
        }
        SkillCuratorCommand::RollbackPlan { proposal } => {
            commands::run_skill_curator_rollback_plan(config, &proposal)
        }
        SkillCuratorCommand::Report => commands::run_skill_curator_report(config),
    }
}

async fn dispatch_doctor_command(config: &Path, command: DoctorCommand) -> Result<()> {
    match command {
        DoctorCommand::Run { offline } => commands::run_doctor_command(config, offline).await,
        DoctorCommand::Report => commands::run_doctor_report(config),
        DoctorCommand::Operations => commands::run_operations_doctor(config),
    }
}

fn dispatch_data_root_command(config: &Path, command: DataRootCommand) -> Result<()> {
    match command {
        DataRootCommand::Validate { profile } => commands::run_data_root_validate(config, &profile),
        DataRootCommand::Report => commands::run_data_root_report(config),
    }
}

fn dispatch_backup_command(config: &Path, command: BackupCommand) -> Result<()> {
    match command {
        BackupCommand::Plan { kind } => commands::run_backup_plan(config, &kind),
        BackupCommand::Run { kind, dry_run } => commands::run_backup_run(config, &kind, dry_run),
        BackupCommand::Verify { backup } => commands::run_backup_verify(config, &backup),
        BackupCommand::List => commands::run_backup_list(config),
        BackupCommand::Status { backup } => commands::run_backup_status(config, &backup),
        BackupCommand::Report => commands::run_backup_report(config),
    }
}

fn dispatch_restore_command(config: &Path, command: RestoreCommand) -> Result<()> {
    match command {
        RestoreCommand::Plan {
            backup,
            target,
            target_config,
        } => commands::run_restore_plan(config, &backup, &target, &target_config),
        RestoreCommand::Verify { backup } => commands::run_restore_verify(config, &backup),
        RestoreCommand::Run {
            backup,
            target,
            target_config,
            maintenance_mode,
            approval_hash,
            dry_run,
        } => commands::run_restore_run(
            config,
            &backup,
            &target,
            &target_config,
            maintenance_mode,
            approval_hash.as_deref().unwrap_or_default(),
            dry_run,
        ),
        RestoreCommand::Rollback {
            target,
            maintenance_mode,
            approval_hash,
            dry_run,
        } => commands::run_restore_rollback(
            config,
            &target,
            maintenance_mode,
            approval_hash.as_deref().unwrap_or_default(),
            dry_run,
        ),
        RestoreCommand::Report => commands::run_restore_report(config),
    }
}

fn dispatch_export_command(config: &Path, command: ExportCommand) -> Result<()> {
    match command {
        ExportCommand::Plan { kind } => commands::run_export_plan(config, &kind),
        ExportCommand::Run { kind } => commands::run_export_run(config, &kind),
    }
}

async fn dispatch_import_command(config: &Path, command: ImportCommand) -> Result<()> {
    match command {
        ImportCommand::Validate {
            path,
            maintenance_mode,
        } => commands::run_import_validate(config, &path, maintenance_mode),
        ImportCommand::Preview { path } => commands::run_import_preview(config, &path),
        ImportCommand::Execute {
            path,
            approval_hash,
            maintenance_mode,
        } => commands::run_import_execute(config, &path, &approval_hash, maintenance_mode).await,
        ImportCommand::Report => commands::run_import_report(config),
    }
}

async fn dispatch_blob_command(config: &Path, command: BlobCommand) -> Result<()> {
    match command {
        BlobCommand::Manifest => commands::run_blob_manifest(config),
        BlobCommand::GcPlan => commands::run_blob_gc_plan(config).await,
        BlobCommand::GcRun {
            dry_run,
            approval_hash,
            under_load,
        } => commands::run_blob_gc_run(config, dry_run, approval_hash.as_deref(), under_load).await,
        BlobCommand::Report => commands::run_blob_report(config),
    }
}

fn dispatch_cutover_command(config: &Path, command: CutoverCommand) -> Result<()> {
    match command {
        CutoverCommand::Plan {
            proposed_data_root,
            executable,
        } => commands::run_cutover_plan(config, &proposed_data_root, &executable),
    }
}

async fn dispatch_maintenance_command(config: &Path, command: MaintenanceCommand) -> Result<()> {
    match command {
        MaintenanceCommand::Run { job, dry_run } => {
            commands::run_maintenance_run(config, &job, dry_run).await
        }
        MaintenanceCommand::Status => commands::run_maintenance_status(config),
        MaintenanceCommand::Report => commands::run_maintenance_report(config),
    }
}

fn dispatch_incident_command(config: &Path, command: IncidentCommand) -> Result<()> {
    match command {
        IncidentCommand::List => commands::run_incident_list(config),
        IncidentCommand::Open {
            kind,
            severity,
            summary,
        } => commands::run_incident_open(config, &kind, &severity, &summary),
        IncidentCommand::Acknowledge { incident } => {
            commands::run_incident_acknowledge(config, &incident)
        }
        IncidentCommand::Close { incident } => commands::run_incident_close(config, &incident),
        IncidentCommand::Report => commands::run_incident_report(config),
    }
}

async fn dispatch_patch_command(config: &Path, command: PatchCommand) -> Result<()> {
    match command {
        PatchCommand::Preflight { lease, diff } => {
            commands::run_patch_preflight(config, &lease, &diff).await
        }
        PatchCommand::Apply { lease, diff } => {
            commands::run_patch_apply(config, &lease, &diff).await
        }
        PatchCommand::Status { patch_run } => commands::run_patch_status(config, &patch_run),
    }
}

async fn dispatch_work_command(config: &Path, command: WorkCommand) -> Result<()> {
    match command {
        WorkCommand::Create {
            project,
            task,
            goal,
            read,
            write,
        } => commands::run_work_create(config, &project, &task, &goal, &read, &write).await,
        WorkCommand::Claim {
            project,
            task,
            role,
        } => commands::run_work_claim(config, &project, &task, &role).await,
        WorkCommand::Status { project, task } => commands::run_work_status(config, &project, &task),
        WorkCommand::Renew { lease } => commands::run_work_renew(config, &lease).await,
        WorkCommand::Release { lease } => commands::run_work_release(config, &lease).await,
        WorkCommand::Revoke { lease } => commands::run_work_revoke(config, &lease).await,
        WorkCommand::Conflicts { project, task } => {
            commands::run_work_conflicts(config, &project, &task)
        }
    }
}

async fn dispatch_worktree_command(config: &Path, command: WorktreeCommand) -> Result<()> {
    match command {
        WorktreeCommand::Create { work_lease } => {
            commands::run_worktree_create(config, &work_lease).await
        }
        WorktreeCommand::Status { worktree_lease } => {
            commands::run_worktree_status(config, &worktree_lease)
        }
        WorktreeCommand::CaptureDiff { worktree_lease } => {
            commands::run_worktree_capture_diff(config, &worktree_lease).await
        }
        WorktreeCommand::Review {
            candidate_diff,
            decision,
        } => commands::run_worktree_review(config, &candidate_diff, &decision).await,
        WorktreeCommand::Cleanup { worktree_lease } => {
            commands::run_worktree_cleanup(config, &worktree_lease).await
        }
    }
}

async fn dispatch_blackboard_command(config: &Path, command: BlackboardCommand) -> Result<()> {
    match command {
        BlackboardCommand::Add {
            project,
            task,
            kind,
            payload_ref,
            evidence,
            confidence,
        } => {
            commands::run_blackboard_add(
                config,
                &project,
                &task,
                &kind,
                &payload_ref,
                &evidence,
                confidence.as_deref(),
            )
            .await
        }
        BlackboardCommand::List { project, task } => {
            commands::run_blackboard_list(config, &project, &task)
        }
        BlackboardCommand::Ack { item, session } => {
            commands::run_blackboard_ack(config, &item, session.as_deref()).await
        }
        BlackboardCommand::Resolve { item } => {
            commands::run_blackboard_resolve(config, &item).await
        }
        BlackboardCommand::Reject { item } => commands::run_blackboard_reject(config, &item).await,
    }
}

async fn dispatch_mailbox_command(config: &Path, command: MailboxCommand) -> Result<()> {
    match command {
        MailboxCommand::Send {
            project,
            task,
            kind,
            payload_ref,
            recipient,
            message_id,
        } => {
            commands::run_mailbox_send(
                config,
                &project,
                &task,
                &kind,
                &payload_ref,
                &recipient,
                message_id.as_deref(),
            )
            .await
        }
        MailboxCommand::Inbox { project, task } => {
            commands::run_mailbox_inbox(config, &project, &task)
        }
        MailboxCommand::Ack { message } => commands::run_mailbox_ack(config, &message).await,
    }
}

async fn dispatch_recovery_command(config: &Path, command: RecoveryCommand) -> Result<()> {
    match command {
        RecoveryCommand::Scan { project, task } => {
            commands::run_recovery_scan(config, &project, &task).await
        }
        RecoveryCommand::Report { latest } => commands::run_recovery_report(config, latest),
    }
}

async fn dispatch_collective_command(config: &Path, command: CollectiveCommand) -> Result<()> {
    match command {
        CollectiveCommand::Trace { project, task } => {
            commands::run_collective_trace(config, &project, &task).await
        }
        CollectiveCommand::Report { latest } => commands::run_collective_report(config, latest),
    }
}

fn dispatch_runtime_command(config: &Path, command: RuntimeCommand) -> Result<()> {
    match command {
        RuntimeCommand::Status => commands::run_runtime_status(config),
        RuntimeCommand::Health => commands::run_runtime_health(config),
        RuntimeCommand::Report => commands::run_runtime_report(config),
    }
}

fn dispatch_module_command(config: &Path, command: ModuleCommand) -> Result<()> {
    match command {
        ModuleCommand::List => commands::run_module_list(config),
        ModuleCommand::Inspect { module } => commands::run_module_inspect(config, &module),
        ModuleCommand::Health => commands::run_module_health(config),
        ModuleCommand::ValidateManifest { path } => commands::run_module_validate_manifest(&path),
    }
}

fn dispatch_logs_command(config: &Path, command: LogsCommand) -> Result<()> {
    match command {
        LogsCommand::Tail { limit } => commands::run_logs_tail(config, limit),
        LogsCommand::Inspect { trace } => commands::run_logs_inspect(config, &trace),
        LogsCommand::Report => commands::run_logs_report(config),
    }
}

async fn dispatch_adapter_command(config: &Path, command: AdapterCommand) -> Result<()> {
    match command {
        AdapterCommand::List => commands::run_adapter_list(config).await,
        AdapterCommand::Inspect { adapter } => commands::run_adapter_inspect(config, &adapter),
        AdapterCommand::Health => commands::run_adapter_health(config).await,
        AdapterCommand::ExecuteTest { adapter } => {
            commands::run_adapter_execute_test(config, &adapter).await
        }
        AdapterCommand::Report => commands::run_adapter_report(config).await,
    }
}

async fn dispatch_verifier_command(config: &Path, command: VerifierCommand) -> Result<()> {
    match command {
        VerifierCommand::Run { plan } => commands::run_verifier_run(config, &plan).await,
        VerifierCommand::Status { task } => commands::run_verifier_status(config, &task),
    }
}

fn dispatch_hook_command(config: &Path, command: HookCommand) -> Result<()> {
    let kind = match command {
        HookCommand::SessionStart => eliot_types::HookEventKind::SessionStart,
        HookCommand::UserPromptSubmit => eliot_types::HookEventKind::UserPromptSubmit,
        HookCommand::SubagentStart => eliot_types::HookEventKind::SubagentStart,
        HookCommand::PreToolUse => eliot_types::HookEventKind::PreToolUse,
        HookCommand::PermissionRequest => eliot_types::HookEventKind::PermissionRequest,
        HookCommand::PostToolUse => eliot_types::HookEventKind::PostToolUse,
        HookCommand::PreCompact => eliot_types::HookEventKind::PreCompact,
        HookCommand::PostCompact => eliot_types::HookEventKind::PostCompact,
        HookCommand::SubagentStop => eliot_types::HookEventKind::SubagentStop,
        HookCommand::Stop => eliot_types::HookEventKind::Stop,
    };
    commands::run_hook(config, kind)
}

fn selected_instance(explicit: Option<String>, implicit: Option<&str>) -> Option<String> {
    explicit.or_else(|| implicit.map(str::to_owned))
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}
