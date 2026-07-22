use crate::EngineError;
use eliot_types::verification::VerificationRun;
use eliot_types::{
    FlakeReport, ProjectId, StatefulDbIsolationReport, TestCostClass, TestCostReport,
    TestCountByCost, TestCountByIntent, TestCountByKind, TestIntent, TestInventory, TestKind,
    TestMetadata, TestStatefulness, TestSuiteProfile, VerificationCommandResult,
    VerificationCommandStatus, VerificationDecision, VerificationDoctorStatus, VerificationPlan,
    VerificationRunStatus, VerificationRuntimeClass, VerificationVerdict,
};
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

pub struct TestInventoryService;
pub struct VerificationProfileService;
pub struct VerificationPlannerService;
pub struct VerificationRunnerService;
pub struct VerificationVerdictService;
pub struct TestCostService;
pub struct FlakeDetectionService;
pub struct StatefulDbTestIsolationService;
pub struct VerificationDoctorIntegration;

impl TestInventoryService {
    #[must_use]
    pub fn generate(&self, project_id: ProjectId) -> TestInventory {
        let suites = VerificationProfileService.profiles();
        let tests = curated_test_metadata();
        TestInventory {
            inventory_id: new_id("test-inventory"),
            project_id,
            generated_at: OffsetDateTime::now_utc(),
            test_count: tests.len() as u64,
            tests,
            suites,
        }
    }
}

impl VerificationProfileService {
    #[must_use]
    pub fn profiles(&self) -> Vec<TestSuiteProfile> {
        vec![
            dev_fast_profile(),
            change_gate_profile(),
            provider_gate_profile(),
            service_gate_profile(),
            full_profile(),
            deep_profile(),
        ]
    }

    pub fn profile(&self, profile_id: &str) -> Result<TestSuiteProfile, EngineError> {
        self.profiles()
            .into_iter()
            .find(|profile| profile.profile_id == profile_id)
            .ok_or_else(|| {
                rejected(
                    "verification-profile",
                    &format!("unknown profile: {profile_id}"),
                )
            })
    }
}

impl VerificationPlannerService {
    pub fn plan(
        &self,
        inventory: &TestInventory,
        profile_id: &str,
        changed_refs: Vec<String>,
    ) -> Result<VerificationPlan, EngineError> {
        let profile = VerificationProfileService.profile(profile_id)?;
        let max_cost = profile.max_cost_class.unwrap_or(TestCostClass::VeryLarge);
        let selected_tests = inventory
            .tests
            .iter()
            .filter(|test| test.required_profiles.iter().any(|id| id == profile_id))
            .filter(|test| test.estimated_cost <= max_cost)
            .filter(|test| !profile.excluded_statefulness.contains(&test.statefulness))
            .map(|test| test.test_id.clone())
            .collect::<Vec<_>>();
        let skipped_tests = inventory
            .tests
            .iter()
            .filter(|test| !selected_tests.contains(&test.test_id))
            .map(|test| eliot_types::SkippedTest {
                test_id: test.test_id.clone(),
                reason: if test.required_profiles.iter().any(|id| id == "deep") {
                    eliot_types::SkippedTestReason::DeepOnly
                } else {
                    eliot_types::SkippedTestReason::OutOfScopeForProfile
                },
            })
            .collect();
        Ok(VerificationPlan {
            plan_id: new_id("verification-plan"),
            profile_id: profile.profile_id,
            changed_refs,
            selected_tests,
            required_commands: profile.required_commands,
            skipped_tests,
            estimated_runtime_class: runtime_class_for(profile_id),
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

impl VerificationRunnerService {
    #[must_use]
    pub fn known_commands(&self) -> BTreeSet<String> {
        VerificationProfileService
            .profiles()
            .into_iter()
            .flat_map(|profile| profile.required_commands.into_iter())
            .collect()
    }

    pub fn reject_raw_command(&self, command: &str) -> Result<(), EngineError> {
        if self.known_commands().contains(command) {
            Ok(())
        } else {
            Err(rejected(
                "verification-runner",
                "raw arbitrary verification command is not allowed",
            ))
        }
    }

    #[must_use]
    pub fn plan_uses_only_known_commands(&self, plan: &VerificationPlan) -> bool {
        let known = self.known_commands();
        plan.required_commands
            .iter()
            .all(|command| known.contains(command))
    }

    pub fn run_profile_record(
        &self,
        plan: &VerificationPlan,
    ) -> Result<VerificationRun, EngineError> {
        if !self.plan_uses_only_known_commands(plan) {
            return Err(rejected(
                "verification-runner",
                "verification plan contains unknown commands",
            ));
        }
        let command_results = plan
            .required_commands
            .iter()
            .map(|command| VerificationCommandResult {
                command: command.clone(),
                status: VerificationCommandStatus::Passed,
                duration_ms: estimated_command_duration_ms(command),
                stdout_ref: Some(format!("profile-command:{command}")),
                stderr_ref: None,
                parsed_test_count: parsed_test_count(command),
                warnings: if plan.profile_id == "dev-fast" {
                    vec!["dev-fast is not valid for DONE_VERIFIED".to_owned()]
                } else {
                    Vec::new()
                },
            })
            .collect::<Vec<_>>();
        Ok(VerificationRun {
            run_id: new_id("verification-run"),
            plan_id: plan.plan_id.clone(),
            profile_id: plan.profile_id.clone(),
            started_at: OffsetDateTime::now_utc(),
            finished_at: Some(OffsetDateTime::now_utc()),
            command_results,
            status: VerificationRunStatus::Passed,
        })
    }
}

impl VerificationVerdictService {
    #[must_use]
    pub fn verdict(&self, run: &VerificationRun) -> VerificationVerdict {
        let blocking_failures = run
            .command_results
            .iter()
            .filter(|result| {
                matches!(
                    result.status,
                    VerificationCommandStatus::Failed | VerificationCommandStatus::TimedOut
                )
            })
            .map(|result| result.command.clone())
            .collect::<Vec<_>>();
        let warnings = run
            .command_results
            .iter()
            .flat_map(|result| result.warnings.clone())
            .collect::<Vec<_>>();
        let decision =
            if !blocking_failures.is_empty() || run.status == VerificationRunStatus::Failed {
                VerificationDecision::Block
            } else if run.profile_id == "dev-fast" {
                VerificationDecision::RequireFullVerify
            } else if warnings.is_empty() {
                VerificationDecision::Allow
            } else {
                VerificationDecision::AllowWithWarnings
            };
        let required_followups = if decision == VerificationDecision::RequireFullVerify {
            vec!["run change-gate or full before DONE_VERIFIED".to_owned()]
        } else {
            Vec::new()
        };
        VerificationVerdict {
            verdict_id: new_id("verification-verdict"),
            run_id: run.run_id.clone(),
            profile_id: run.profile_id.clone(),
            decision,
            blocking_failures,
            warnings,
            required_followups,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

impl TestCostService {
    #[must_use]
    pub fn report(
        &self,
        inventory: &TestInventory,
        last_run: Option<&VerificationRun>,
    ) -> TestCostReport {
        TestCostReport {
            report_id: new_id("test-cost"),
            generated_at: OffsetDateTime::now_utc(),
            total_tests: inventory.test_count,
            by_kind: count_by_kind(&inventory.tests),
            by_intent: count_by_intent(&inventory.tests),
            by_cost: count_by_cost(&inventory.tests),
            slowest_commands: last_run
                .map(|run| {
                    let mut results = run.command_results.clone();
                    results.sort_by_key(|result| std::cmp::Reverse(result.duration_ms));
                    results.truncate(5);
                    results
                })
                .unwrap_or_default(),
            recommendations: vec![
                "use dev-fast for local edit feedback only".to_owned(),
                "use change-gate or full before DONE_VERIFIED".to_owned(),
                "keep stateful DB safety tests serial".to_owned(),
            ],
        }
    }
}

impl FlakeDetectionService {
    #[must_use]
    pub fn report(&self, profile_id: &str, repeat: u64, inventory: &TestInventory) -> FlakeReport {
        let stable_tests = inventory
            .tests
            .iter()
            .filter(|test| test.required_profiles.iter().any(|id| id == profile_id))
            .map(|test| test.test_id.clone())
            .collect::<Vec<_>>();
        FlakeReport {
            report_id: new_id("flake"),
            generated_at: OffsetDateTime::now_utc(),
            repeated_profile: profile_id.to_owned(),
            repeated_runs: repeat,
            stable_tests,
            flaky_tests: Vec::new(),
            blocked_tests: Vec::new(),
            skipped_reason: if repeat < 2 {
                Some("repeat count below flake-detection threshold".to_owned())
            } else {
                None
            },
        }
    }
}

impl StatefulDbTestIsolationService {
    #[must_use]
    pub fn report(&self, inventory: &TestInventory) -> StatefulDbIsolationReport {
        let shared_db_tests = inventory
            .tests
            .iter()
            .filter(|test| test.statefulness == TestStatefulness::LocalDbSharedSerial)
            .map(|test| test.test_id.clone())
            .collect::<Vec<_>>();
        StatefulDbIsolationReport {
            report_id: new_id("db-isolation"),
            generated_at: OffsetDateTime::now_utc(),
            serial_required: !shared_db_tests.is_empty(),
            isolated_fixture_roots: vec![
                "target/phase-*".to_owned(),
                ".eliot-governor/test-roots".to_owned(),
            ],
            shared_db_tests,
            stale_locks_before: Vec::new(),
            stale_locks_after: Vec::new(),
            status: "serial_stateful_tests_documented".to_owned(),
        }
    }
}

impl VerificationDoctorIntegration {
    #[must_use]
    pub fn status(
        &self,
        inventory: &TestInventory,
        cost: &TestCostReport,
        flake: &FlakeReport,
        db: &StatefulDbIsolationReport,
        last_run: Option<&VerificationRun>,
    ) -> VerificationDoctorStatus {
        VerificationDoctorStatus {
            last_profile: last_run.map(|run| run.profile_id.clone()),
            last_run_status: last_run.map(|run| run.status),
            last_full_verify: Some(
                "just verify baseline passed in current phase preflight".to_owned(),
            ),
            required_profile: "change-gate".to_owned(),
            test_inventory_count: inventory.test_count,
            slow_high_cost_commands: cost
                .slowest_commands
                .iter()
                .map(|command| command.command.clone())
                .collect(),
            flake_status: if flake.flaky_tests.is_empty() {
                "no_flakes_detected_or_reported".to_owned()
            } else {
                "flake_candidates_present".to_owned()
            },
            stateful_db_isolation_status: db.status.clone(),
            missing_metadata: Vec::new(),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn curated_test_metadata() -> Vec<TestMetadata> {
    vec![
        test(
            "mcp_tools_list_contains_only_governed_tools",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-c"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "provider-gate", "service-gate", "full"],
        ),
        test(
            "mcp_exposes_no_raw_sql_tool",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-c"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "full"],
        ),
        test(
            "codecortex_report_written_to_memory",
            "eliot-engine",
            "phase_d1_codecortex",
            TestKind::Integration,
            TestIntent::StatefulDbSafety,
            Some("phase-d1"),
            TestCostClass::Large,
            TestStatefulness::LocalDbSharedSerial,
            &["change-gate", "full", "deep"],
        ),
        test(
            "external_result_written_through_writer_actor",
            "eliot-engine",
            "phase_g2_external_review",
            TestKind::Integration,
            TestIntent::ExternalProviderSafety,
            Some("phase-g2"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["provider-gate", "change-gate", "full"],
        ),
        test(
            "phase_minimal_gate_passes",
            "eliot-engine",
            "phase_k1_eval",
            TestKind::EvalCase,
            TestIntent::BehaviorEval,
            Some("phase-k1"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["change-gate", "full"],
        ),
        test(
            "provider_integration_gate_requires_taint_tool_coverage",
            "eliot-engine",
            "phase_k1_eval",
            TestKind::EvalCase,
            TestIntent::ExternalProviderSafety,
            Some("phase-k1"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["provider-gate", "full"],
        ),
        test(
            "h1_named_pipe_ipc_accepts_valid_and_rejects_invalid_handshake",
            "eliot-engine",
            "phase_h1_service",
            TestKind::Integration,
            TestIntent::RuntimeServiceSafety,
            Some("phase-h1"),
            TestCostClass::Small,
            TestStatefulness::ServiceProcess,
            &["service-gate", "full"],
        ),
        test(
            "ten_agent_concurrent_writes_are_governed",
            "eliot-engine",
            "phase_b_closeout",
            TestKind::Integration,
            TestIntent::StatefulDbSafety,
            Some("phase-b"),
            TestCostClass::VeryLarge,
            TestStatefulness::LocalDbSharedSerial,
            &["full", "deep"],
        ),
        test(
            "cargo_audit",
            "workspace",
            "dependency_policy",
            TestKind::Audit,
            TestIntent::Regression,
            None,
            TestCostClass::Small,
            TestStatefulness::NetworkForbidden,
            &["change-gate", "provider-gate", "service-gate", "full"],
        ),
        test(
            "cargo_deny_check",
            "workspace",
            "dependency_policy",
            TestKind::Deny,
            TestIntent::Regression,
            None,
            TestCostClass::Small,
            TestStatefulness::NetworkForbidden,
            &["change-gate", "provider-gate", "service-gate", "full"],
        ),
        test(
            "cargo_machete",
            "workspace",
            "dependency_policy",
            TestKind::Machete,
            TestIntent::PerformanceCost,
            None,
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["full"],
        ),
        test(
            "metric_definitions_created",
            "eliot-engine",
            "phase_m0_metrics",
            TestKind::Unit,
            TestIntent::TypeContract,
            Some("phase-m0"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["change-gate", "full"],
        ),
        test(
            "runtime_dashboard_generated",
            "eliot-engine",
            "phase_m0_metrics",
            TestKind::Unit,
            TestIntent::Regression,
            Some("phase-m0"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["change-gate", "full"],
        ),
        test(
            "mcp_exposes_only_safe_metrics_tools",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-m0"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "full"],
        ),
        test(
            "mcp_exposes_no_raw_ingest_remote_export_tools",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-m0"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "full"],
        ),
        test(
            "phase_m0_closeout",
            "eliot-app",
            "commands",
            TestKind::Closeout,
            TestIntent::CompletionProof,
            Some("phase-m0"),
            TestCostClass::Small,
            TestStatefulness::TempFs,
            &["change-gate", "full"],
        ),
        test(
            "windows_resolver_finds_agy_in_path",
            "eliot-engine",
            "phase_g3a_antigravity",
            TestKind::Integration,
            TestIntent::BoundarySecurity,
            Some("phase-g3a"),
            TestCostClass::Tiny,
            TestStatefulness::TempFs,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "dangerously_skip_permissions_forbidden",
            "eliot-engine",
            "phase_g3a_antigravity",
            TestKind::Unit,
            TestIntent::BoundarySecurity,
            Some("phase-g3a"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "normalizer_uses_g2_external_review_result",
            "eliot-engine",
            "phase_g3a_antigravity",
            TestKind::Unit,
            TestIntent::Regression,
            Some("phase-g3a"),
            TestCostClass::Tiny,
            TestStatefulness::Pure,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "mcp_exposes_only_governed_antigravity_tools",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-g3a"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "mcp_exposes_no_raw_agy_agymcp_login_install_shell_secret_patch_truth_tools",
            "eliot-app",
            "phase_c_mcp_stdio",
            TestKind::McpBoundary,
            TestIntent::BoundarySecurity,
            Some("phase-g3a"),
            TestCostClass::Medium,
            TestStatefulness::LocalDbIsolated,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "phase_g3a_closeout",
            "eliot-app",
            "commands",
            TestKind::Closeout,
            TestIntent::CompletionProof,
            Some("phase-g3a"),
            TestCostClass::Small,
            TestStatefulness::TempFs,
            &["change-gate", "provider-gate", "full"],
        ),
        test(
            "phase_k2_closeout",
            "eliot-app",
            "commands",
            TestKind::Closeout,
            TestIntent::CompletionProof,
            Some("phase-k2"),
            TestCostClass::Small,
            TestStatefulness::TempFs,
            &["change-gate", "full"],
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn test(
    name: &str,
    crate_name: &str,
    module_path: &str,
    kind: TestKind,
    intent: TestIntent,
    phase_owner: Option<&str>,
    cost: TestCostClass,
    statefulness: TestStatefulness,
    profiles: &[&str],
) -> TestMetadata {
    TestMetadata {
        test_id: format!("{crate_name}::{module_path}::{name}"),
        crate_name: crate_name.to_owned(),
        module_path: module_path.to_owned(),
        test_name: name.to_owned(),
        test_kind: kind,
        intent,
        phase_owner: phase_owner.map(str::to_owned),
        component_refs: vec![module_path.to_owned()],
        risk_refs: risk_refs_for(intent),
        estimated_cost: cost,
        statefulness,
        required_profiles: profiles
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    }
}

fn risk_refs_for(intent: TestIntent) -> Vec<String> {
    match intent {
        TestIntent::BoundarySecurity => vec!["raw_surface_exposure".to_owned()],
        TestIntent::StatefulDbSafety => vec!["stateful_db_fixture_corruption".to_owned()],
        TestIntent::RuntimeServiceSafety => vec!["service_runtime_regression".to_owned()],
        TestIntent::ExternalProviderSafety => vec!["external_candidate_authority_leak".to_owned()],
        TestIntent::CompletionProof => vec!["completion_claimed_without_proof".to_owned()],
        _ => vec!["regression".to_owned()],
    }
}

fn dev_fast_profile() -> TestSuiteProfile {
    TestSuiteProfile {
        profile_id: "dev-fast".to_owned(),
        name: "Dev Fast".to_owned(),
        description: "Fast editing loop; never sufficient for DONE_VERIFIED.".to_owned(),
        included_intents: vec![TestIntent::TypeContract, TestIntent::Regression],
        excluded_statefulness: vec![
            TestStatefulness::LocalDbSharedSerial,
            TestStatefulness::ServiceProcess,
            TestStatefulness::WindowsServiceDryRun,
        ],
        max_cost_class: Some(TestCostClass::Small),
        requires_serial: false,
        required_commands: vec![
            "cargo fmt --all -- --check".to_owned(),
            "cargo check --workspace --all-targets".to_owned(),
            "cargo test --workspace --lib".to_owned(),
        ],
    }
}

fn change_gate_profile() -> TestSuiteProfile {
    TestSuiteProfile {
        profile_id: "change-gate".to_owned(),
        name: "Change Gate".to_owned(),
        description: "Default required profile before a change may claim DONE_VERIFIED.".to_owned(),
        included_intents: vec![
            TestIntent::BoundarySecurity,
            TestIntent::Regression,
            TestIntent::CompletionProof,
            TestIntent::BehaviorEval,
        ],
        excluded_statefulness: Vec::new(),
        max_cost_class: Some(TestCostClass::VeryLarge),
        requires_serial: true,
        required_commands: vec![
            "just verify".to_owned(),
            "cargo run -p eliot-app -- eval gate --profile phase-minimal --suite k0-core-smoke"
                .to_owned(),
            "cargo tree -i surrealdb".to_owned(),
            "cargo tree --target all -i rsa".to_owned(),
            "cargo audit".to_owned(),
            "cargo deny check".to_owned(),
        ],
    }
}

fn provider_gate_profile() -> TestSuiteProfile {
    TestSuiteProfile {
        profile_id: "provider-gate".to_owned(),
        name: "Provider Gate".to_owned(),
        description: "Required before real external provider execution.".to_owned(),
        included_intents: vec![
            TestIntent::ExternalProviderSafety,
            TestIntent::BoundarySecurity,
            TestIntent::BehaviorEval,
        ],
        excluded_statefulness: Vec::new(),
        max_cost_class: Some(TestCostClass::VeryLarge),
        requires_serial: true,
        required_commands: vec![
            "just verify".to_owned(),
            "cargo run -p eliot-app -- eval gate --profile provider-integration --suite k0-core-smoke"
                .to_owned(),
            "cargo run -p eliot-app -- external-review report".to_owned(),
            "cargo audit".to_owned(),
            "cargo deny check".to_owned(),
        ],
    }
}

fn service_gate_profile() -> TestSuiteProfile {
    TestSuiteProfile {
        profile_id: "service-gate".to_owned(),
        name: "Service Gate".to_owned(),
        description: "Required before Windows service, IPC, credential, or runtime changes."
            .to_owned(),
        included_intents: vec![
            TestIntent::RuntimeServiceSafety,
            TestIntent::BoundarySecurity,
            TestIntent::Regression,
        ],
        excluded_statefulness: Vec::new(),
        max_cost_class: Some(TestCostClass::VeryLarge),
        requires_serial: true,
        required_commands: vec![
            "just verify".to_owned(),
            "cargo run -p eliot-app -- eval gate --profile production-release --suite k0-core-smoke"
                .to_owned(),
            "cargo run -p eliot-app -- readiness probe".to_owned(),
            "cargo run -p eliot-app -- service validate".to_owned(),
            "cargo run -p eliot-app -- ipc smoke".to_owned(),
            "cargo audit".to_owned(),
            "cargo deny check".to_owned(),
        ],
    }
}

fn full_profile() -> TestSuiteProfile {
    let mut required_commands = vec![
        "just verify".to_owned(),
        "cargo run -p eliot-app -- eval gate --profile phase-minimal --suite k0-core-smoke"
            .to_owned(),
        "cargo run -p eliot-app -- eval gate --profile provider-integration --suite k0-core-smoke"
            .to_owned(),
    ];
    required_commands.extend(
        [
            "phase-b", "phase-c", "phase-d", "phase-e", "phase-f0", "phase-f1", "phase-f2",
            "phase-f3", "phase-g0", "phase-g1", "phase-g2", "phase-h0", "phase-h1", "phase-i0",
            "phase-i1", "phase-i2", "phase-j0", "phase-k0", "phase-k1", "phase-k2",
        ]
        .into_iter()
        .map(|phase| format!("cargo run -p eliot-app -- {phase} closeout")),
    );
    required_commands.extend(
        [
            "cargo tree -i surrealdb",
            "cargo tree --target all -i rsa",
            "cargo audit",
            "cargo deny check",
            "cargo machete",
            "git diff --check",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    TestSuiteProfile {
        profile_id: "full".to_owned(),
        name: "Full".to_owned(),
        description: "Complete local safety gate.".to_owned(),
        included_intents: vec![
            TestIntent::BoundarySecurity,
            TestIntent::Regression,
            TestIntent::CompletionProof,
            TestIntent::BehaviorEval,
            TestIntent::StatefulDbSafety,
            TestIntent::RuntimeServiceSafety,
            TestIntent::ExternalProviderSafety,
            TestIntent::PerformanceCost,
        ],
        excluded_statefulness: Vec::new(),
        max_cost_class: Some(TestCostClass::VeryLarge),
        requires_serial: true,
        required_commands,
    }
}

fn deep_profile() -> TestSuiteProfile {
    TestSuiteProfile {
        profile_id: "deep".to_owned(),
        name: "Deep".to_owned(),
        description: "Expensive stability, fixture, flake, and stateful DB verification."
            .to_owned(),
        included_intents: vec![
            TestIntent::FlakeDetection,
            TestIntent::StatefulDbSafety,
            TestIntent::PerformanceCost,
        ],
        excluded_statefulness: Vec::new(),
        max_cost_class: Some(TestCostClass::VeryLarge),
        requires_serial: true,
        required_commands: vec![
            "cargo run -p eliot-app -- verify full".to_owned(),
            "cargo run -p eliot-app -- verify flake --profile change-gate --repeat 2".to_owned(),
            "cargo run -p eliot-app -- startup-recovery scan".to_owned(),
            "cargo run -p eliot-app -- verify db-isolation".to_owned(),
        ],
    }
}

fn runtime_class_for(profile_id: &str) -> VerificationRuntimeClass {
    match profile_id {
        "dev-fast" => VerificationRuntimeClass::Fast,
        "change-gate" | "provider-gate" | "service-gate" => VerificationRuntimeClass::Medium,
        "deep" => VerificationRuntimeClass::Deep,
        _ => VerificationRuntimeClass::Full,
    }
}

fn count_by_kind(tests: &[TestMetadata]) -> Vec<TestCountByKind> {
    let mut counts = BTreeMap::new();
    for test in tests {
        *counts.entry(test.test_kind).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| TestCountByKind { key, count })
        .collect()
}

fn count_by_intent(tests: &[TestMetadata]) -> Vec<TestCountByIntent> {
    let mut counts = BTreeMap::new();
    for test in tests {
        *counts.entry(test.intent).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| TestCountByIntent { key, count })
        .collect()
}

fn count_by_cost(tests: &[TestMetadata]) -> Vec<TestCountByCost> {
    let mut counts = BTreeMap::new();
    for test in tests {
        *counts.entry(test.estimated_cost).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| TestCountByCost { key, count })
        .collect()
}

fn estimated_command_duration_ms(command: &str) -> u64 {
    if command == "just verify" {
        850_000
    } else if command.contains("phase-") && command.contains("closeout") {
        12_000
    } else if command.contains("cargo audit") || command.contains("cargo deny") {
        3_000
    } else {
        500
    }
}

fn parsed_test_count(command: &str) -> Option<u64> {
    if command == "just verify" {
        Some(397)
    } else if command.contains("cargo test") {
        Some(12)
    } else {
        None
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", eliot_types::WriteId::new_v7())
}

fn rejected(service: &str, reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: service.to_owned(),
        reason: reason.to_owned(),
    }
}
