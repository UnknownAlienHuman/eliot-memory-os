#![allow(clippy::expect_used)]

use eliot_engine::{
    FlakeDetectionService, StatefulDbTestIsolationService, TestCostService, TestInventoryService,
    VerificationDoctorIntegration, VerificationPlannerService, VerificationProfileService,
    VerificationRunnerService, VerificationVerdictService,
};
use eliot_types::{
    ProjectId, TestCostClass, TestIntent, TestKind, TestStatefulness, VerificationCommandResult,
    VerificationCommandStatus, VerificationDecision, VerificationRunStatus,
};
use std::fs;
use std::path::PathBuf;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn test_inventory_generated() {
    let inventory = inventory();

    assert!(inventory.test_count > 0);
    assert_eq!(
        inventory.test_count,
        u64::try_from(inventory.tests.len()).unwrap_or(u64::MAX)
    );
    assert!(!inventory.suites.is_empty());
}

#[test]
fn test_metadata_classifies_known_tests() {
    let inventory = inventory();
    let mcp = inventory
        .tests
        .iter()
        .find(|test| test.test_name == "mcp_tools_list_contains_only_governed_tools")
        .expect("known mcp boundary test");
    let db = inventory
        .tests
        .iter()
        .find(|test| test.test_name == "codecortex_report_written_to_memory")
        .expect("known db safety test");

    assert_eq!(mcp.test_kind, TestKind::McpBoundary);
    assert_eq!(mcp.intent, TestIntent::BoundarySecurity);
    assert_eq!(db.statefulness, TestStatefulness::LocalDbSharedSerial);
}

#[test]
fn test_profiles_created() {
    let profiles = profiles();

    for profile_id in [
        "dev-fast",
        "change-gate",
        "provider-gate",
        "service-gate",
        "full",
        "deep",
    ] {
        assert!(has_profile(&profiles, profile_id));
    }
}

#[test]
fn dev_fast_profile_exists() {
    let profile = VerificationProfileService
        .profile("dev-fast")
        .expect("dev-fast profile");

    assert!(!profile.requires_serial);
    assert!(profile.max_cost_class <= Some(TestCostClass::Small));
}

#[test]
fn the_change_gate_profile_exists() {
    let profile = VerificationProfileService
        .profile("change-gate")
        .expect("change-gate profile");

    assert!(profile.requires_serial);
    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| cmd == "just verify")
    );
}

#[test]
fn provider_gate_profile_exists() {
    let profile = VerificationProfileService
        .profile("provider-gate")
        .expect("provider-gate profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile provider-integration") })
    );
}

#[test]
fn service_gate_profile_exists() {
    let profile = VerificationProfileService
        .profile("service-gate")
        .expect("service-gate profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile production-release") })
    );
}

#[test]
fn full_profile_exists() {
    let profile = VerificationProfileService
        .profile("full")
        .expect("full profile");

    for required in [
        "just verify",
        "cargo audit",
        "cargo deny check",
        "cargo machete",
        "git diff --check",
    ] {
        assert!(
            profile
                .required_commands
                .iter()
                .any(|command| command == required)
        );
    }
    assert!(
        profile
            .required_commands
            .iter()
            .any(|command| { command.contains("eval gate --profile fast-deterministic") })
    );
    assert!(
        profile
            .required_commands
            .iter()
            .any(|command| { command.contains("eval gate --profile provider-integration") })
    );
    assert!(profile.requires_serial);
}

#[test]
fn deep_profile_exists() {
    let profile = VerificationProfileService
        .profile("deep")
        .expect("deep profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| cmd.contains("verify flake"))
    );
}

#[test]
fn verification_plan_generated() {
    let plan = plan("change-gate");

    assert_eq!(plan.profile_id, "change-gate");
    assert!(!plan.required_commands.is_empty());
    assert!(!plan.selected_tests.is_empty());
}

#[test]
fn verification_plan_selects_profile_commands() {
    let plan = plan("provider-gate");

    assert!(
        plan.required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile provider-integration") })
    );
    assert!(
        plan.selected_tests.iter().any(|test| {
            test.contains("provider_integration_gate_requires_taint_tool_coverage")
        })
    );
}

#[test]
fn verification_run_profile_uses_only_known_commands() {
    let plan = plan("change-gate");

    assert!(VerificationRunnerService.plan_uses_only_known_commands(&plan));
}

#[test]
fn verification_run_rejects_raw_command() {
    assert!(
        VerificationRunnerService
            .reject_raw_command("cargo test --workspace -- --ignored")
            .is_err()
    );
}

#[test]
fn verification_verdict_generated() {
    let run = VerificationRunnerService
        .run_profile_record(&plan("change-gate"))
        .expect("profile run");
    let verdict = VerificationVerdictService.verdict(&run);

    assert_eq!(verdict.run_id, run.run_id);
    assert_eq!(verdict.decision, VerificationDecision::Allow);
}

#[test]
fn verification_verdict_blocks_failed_command() {
    let mut run = VerificationRunnerService
        .run_profile_record(&plan("change-gate"))
        .expect("profile run");
    run.status = VerificationRunStatus::Failed;
    run.command_results.push(VerificationCommandResult {
        command: "just verify".to_owned(),
        status: VerificationCommandStatus::Failed,
        duration_ms: 100,
        stdout_ref: None,
        stderr_ref: Some("stderr:fixture".to_owned()),
        parsed_test_count: None,
        warnings: Vec::new(),
    });
    let verdict = VerificationVerdictService.verdict(&run);

    assert_eq!(verdict.decision, VerificationDecision::Block);
    assert!(
        verdict
            .blocking_failures
            .contains(&"just verify".to_owned())
    );
}

#[test]
fn the_change_gate_requires_the_minimal_eval_gate() {
    let profile = VerificationProfileService
        .profile("change-gate")
        .expect("change-gate profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile fast-deterministic") })
    );
}

#[test]
fn provider_gate_requires_provider_integration_eval() {
    let profile = VerificationProfileService
        .profile("provider-gate")
        .expect("provider-gate profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile provider-integration") })
    );
}

#[test]
fn service_gate_requires_production_release_eval() {
    let profile = VerificationProfileService
        .profile("service-gate")
        .expect("service-gate profile");

    assert!(
        profile
            .required_commands
            .iter()
            .any(|cmd| { cmd.contains("eval gate --profile production-release") })
    );
}

#[test]
fn full_profile_runs_dependency_absence_checks() {
    let profile = VerificationProfileService
        .profile("full")
        .expect("full profile");

    assert!(
        profile
            .required_commands
            .contains(&"cargo tree -i surrealdb".to_owned())
    );
    assert!(
        profile
            .required_commands
            .contains(&"cargo tree --target all -i rsa".to_owned())
    );
}

#[test]
fn test_cost_report_generated() {
    let inventory = inventory();
    let run = VerificationRunnerService
        .run_profile_record(&plan("change-gate"))
        .expect("profile run");
    let report = TestCostService.report(&inventory, Some(&run));

    assert_eq!(report.total_tests, inventory.test_count);
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_cost_report_counts_by_kind_intent_cost() {
    let report = TestCostService.report(&inventory(), None);

    assert!(!report.by_kind.is_empty());
    assert!(!report.by_intent.is_empty());
    assert!(!report.by_cost.is_empty());
}

#[test]
fn flake_report_generated_or_skipped_with_reason() {
    let report = FlakeDetectionService.report("change-gate", 2, &inventory());

    assert_eq!(report.repeated_profile, "change-gate");
    assert!(report.skipped_reason.is_none());
    assert!(!report.stable_tests.is_empty());
}

#[test]
fn stateful_db_isolation_report_generated() {
    let report = StatefulDbTestIsolationService.report(&inventory());

    assert!(report.serial_required);
    assert!(!report.shared_db_tests.is_empty());
}

#[test]
fn stateful_db_profile_marks_serial() {
    let profile = VerificationProfileService
        .profile("change-gate")
        .expect("change-gate profile");

    assert!(profile.requires_serial);
    assert!(
        inventory()
            .tests
            .iter()
            .any(|test| test.statefulness == TestStatefulness::LocalDbSharedSerial)
    );
}

#[test]
fn doctor_reports_verification_status() {
    let inventory = inventory();
    let run = VerificationRunnerService
        .run_profile_record(&plan("change-gate"))
        .expect("profile run");
    let cost = TestCostService.report(&inventory, Some(&run));
    let flake = FlakeDetectionService.report("change-gate", 2, &inventory);
    let db = StatefulDbTestIsolationService.report(&inventory);
    let status = VerificationDoctorIntegration.status(&inventory, &cost, &flake, &db, Some(&run));

    assert_eq!(status.last_profile.as_deref(), Some("change-gate"));
    assert_eq!(status.test_inventory_count, inventory.test_count);
    assert_eq!(status.required_profile, "change-gate");
}

#[test]
fn mcp_exposes_only_safe_verify_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;

    for tool in [
        "eliot_verify_profiles",
        "eliot_verify_inventory",
        "eliot_verify_plan",
        "eliot_verify_report",
        "eliot_verify_cost_report",
        "eliot_verify_last_verdict",
    ] {
        assert!(mcp.contains(tool));
    }
    assert!(!mcp.contains("eliot_verify_run_raw_command"));
    Ok(())
}

#[test]
fn mcp_exposes_no_raw_command_or_override_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;

    for forbidden in [
        "eliot_verify_run_raw_command",
        "eliot_shell",
        "eliot_test_ignore_failure",
        "eliot_test_delete",
        "eliot_profile_override_done",
    ] {
        assert!(!mcp.contains(forbidden));
    }
    Ok(())
}

/// The application layer must not reach past the verification runner. Linking
/// the `SurrealDB` SDK would drag in the dependency graph the store deliberately
/// avoids, and an arbitrary-command escape would make the profile allowlist
/// decorative.
#[test]
fn the_application_layer_keeps_the_verification_boundary() -> TestResult {
    let root = repo_root();
    let app = fs::read_to_string(root.join("crates/eliot-app/src/commands.rs"))?;
    let mcp = fs::read_to_string(root.join("crates/eliot-app/src/mcp_stdio.rs"))?;
    let engine = fs::read_to_string(root.join("crates/eliot-engine/src/verification.rs"))?;

    assert!(mcp.contains("eliot_verify_profiles"));
    assert!(engine.contains("VerificationRunnerService"));
    for forbidden in ["surrealdb::", "rsa::", "raw arbitrary verification command"] {
        assert!(
            !app.contains(forbidden),
            "{forbidden} leaked into commands.rs"
        );
    }
    Ok(())
}

fn inventory() -> eliot_types::TestInventory {
    TestInventoryService.generate(ProjectId::new_v7())
}

fn profiles() -> Vec<eliot_types::TestSuiteProfile> {
    VerificationProfileService.profiles()
}

fn has_profile(profiles: &[eliot_types::TestSuiteProfile], profile_id: &str) -> bool {
    profiles
        .iter()
        .any(|profile| profile.profile_id == profile_id)
}

fn plan(profile_id: &str) -> eliot_types::VerificationPlan {
    VerificationPlannerService
        .plan(&inventory(), profile_id, vec!["tests:fixture".to_owned()])
        .expect("verification plan")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .to_path_buf()
}
