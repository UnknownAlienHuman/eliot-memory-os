use anyhow::{Context, Result};
use eliot_types::{
    ProjectId, UL_CROSS_AGENT_CONFIRMATION_TOKEN, UL_CROSS_AGENT_EXACT_CALLS,
    UlCrossAgentDirection, UlCrossAgentDirectionEvidence, UlCrossAgentDispatchDecision,
    UlCrossAgentInvocationState, UlCrossAgentReport, UlCrossAgentRole, UlCrossAgentSuite,
    scan_ul_cross_agent_reader_inputs, ul_cross_agent_dispatch_decision,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolve workspace root")
}

fn suite() -> Result<UlCrossAgentSuite> {
    let path = workspace_root()?
        .join("tests")
        .join("cognitive")
        .join("ul-cross-agent")
        .join("suite.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn passing_evidence(direction: UlCrossAgentDirection) -> UlCrossAgentDirectionEvidence {
    UlCrossAgentDirectionEvidence {
        direction,
        prewrite_control_marker_absent: true,
        writer_canonical_write_succeeded: true,
        writer_memory_has_exact_cue: true,
        treatment_recovered_exact_marker: true,
        treatment_named_exact_handle: true,
        treatment_used_allowed_delivery_surface: true,
        treatment_applicability_exact: true,
        treatment_first_action_exact: true,
        treatment_has_valid_influence_receipt: true,
        memory_free_control_marker_absent: true,
        no_input_contamination: true,
        no_cross_scope_leakage: true,
        truth_revision_changed_only_for_candidate: true,
        candidate_stayed_candidate_only: true,
    }
}

#[test]
fn contract_schemas_are_exact_and_fail_closed() -> Result<()> {
    let suite = suite()?;
    suite.validate().map_err(anyhow::Error::msg)?;
    assert_eq!(suite.confirmation_token, UL_CROSS_AGENT_CONFIRMATION_TOKEN);
    assert_eq!(suite.cases.len(), UL_CROSS_AGENT_EXACT_CALLS);

    let output_path = workspace_root()?.join("tests/cognitive/ul-cross-agent/output-contract.json");
    let output: Value = serde_json::from_slice(&std::fs::read(output_path)?)?;
    assert_eq!(output["type"], "object");
    assert_eq!(output["additionalProperties"], false);
    let required = output["required"]
        .as_array()
        .context("reader output required list")?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        required,
        BTreeSet::from([
            "applicability",
            "delivery_surface",
            "first_action",
            "influence_receipt",
            "marker",
            "memory_handle",
        ])
    );
    assert_eq!(
        output["properties"]
            .as_object()
            .context("reader output properties")?
            .len(),
        6
    );
    Ok(())
}

#[test]
fn marker_contamination_scanner_covers_every_allowed_reader_input() -> Result<()> {
    let marker = "ULX-0123456789abcdef0123456789abcdef";
    let clean = scan_ul_cross_agent_reader_inputs(
        marker,
        [
            ("prompt", b"inspect src/relay_alpha.rs".as_slice()),
            ("schema", br#"{"type":"object"}"#.as_slice()),
            ("fixture", b"FROST-17".as_slice()),
        ],
    );
    assert!(clean.passed);
    assert_eq!(clean.scanned_inputs.len(), 3);
    assert!(clean.contaminated_refs.is_empty());
    assert!(!serde_json::to_string(&clean)?.contains(marker));

    let contaminated = scan_ul_cross_agent_reader_inputs(
        marker,
        [("environment", format!("TOKEN={marker}").as_bytes())],
    );
    assert!(!contaminated.passed);
    assert_eq!(contaminated.contaminated_refs, ["environment"]);
    Ok(())
}

#[test]
fn eight_call_planner_uses_fresh_sessions_and_exact_scopes() -> Result<()> {
    let suite = suite()?;
    let project_id = ProjectId::new_v7();
    let plan = suite
        .plan("ulx-contract-plan", project_id)
        .map_err(anyhow::Error::msg)?;
    assert_eq!(plan.project_id, project_id);
    assert_eq!(plan.calls.len(), UL_CROSS_AGENT_EXACT_CALLS);
    assert_eq!(
        plan.calls
            .iter()
            .map(|call| call.session_id)
            .collect::<BTreeSet<_>>()
            .len(),
        UL_CROSS_AGENT_EXACT_CALLS
    );
    assert_eq!(
        plan.calls
            .iter()
            .map(|call| call.task_id)
            .collect::<BTreeSet<_>>()
            .len(),
        UL_CROSS_AGENT_EXACT_CALLS
    );
    assert!(
        plan.calls
            .iter()
            .filter(|call| call.marker_visible_to_provider)
            .all(|call| call.role == UlCrossAgentRole::Writer)
    );
    assert_eq!(
        plan.calls
            .iter()
            .filter(|call| call.marker_visible_to_provider)
            .count(),
        2
    );
    Ok(())
}

#[test]
fn control_treatment_scope_and_fixture_are_marker_free() -> Result<()> {
    let suite = suite()?;
    for direction in [UlCrossAgentDirection::A, UlCrossAgentDirection::B] {
        let direction_cases = suite
            .cases
            .iter()
            .filter(|case| case.direction == direction)
            .collect::<Vec<_>>();
        assert_eq!(direction_cases.len(), 4);
        assert_eq!(direction_cases[0].role, UlCrossAgentRole::PrewriteControl);
        assert_eq!(direction_cases[1].role, UlCrossAgentRole::Writer);
        assert_eq!(direction_cases[2].role, UlCrossAgentRole::Treatment);
        assert_eq!(direction_cases[3].role, UlCrossAgentRole::MemoryFreeControl);
        assert_eq!(direction_cases[0].file_cue, direction_cases[2].file_cue);
        assert_eq!(direction_cases[0].file_cue, direction_cases[3].file_cue);
    }

    let fixture = workspace_root()?.join("tests/cognitive/ul-cross-agent/fixture-template");
    for relative in ["src/relay_alpha.rs", "src/relay_beta.rs", "README.md"] {
        let bytes = std::fs::read(fixture.join(relative))?;
        assert!(!bytes.windows(4).any(|window| window == b"ULX-"));
        assert!(!String::from_utf8_lossy(&bytes).contains("Certification marker:"));
    }
    Ok(())
}

#[test]
fn report_requires_both_complete_directions_and_eight_calls() {
    let project_id = ProjectId::new_v7();
    let a = passing_evidence(UlCrossAgentDirection::A);
    let b = passing_evidence(UlCrossAgentDirection::B);
    let pass = UlCrossAgentReport::from_evidence("pass", project_id, 8, &a, &b, Vec::new());
    assert!(pass.passed);

    let seven_calls = UlCrossAgentReport::from_evidence("short", project_id, 7, &a, &b, Vec::new());
    assert!(!seven_calls.passed);
    let mut failed_b = b;
    failed_b.treatment_has_valid_influence_receipt = false;
    let partial =
        UlCrossAgentReport::from_evidence("partial", project_id, 8, &a, &failed_b, Vec::new());
    assert!(!partial.passed);
    let unknown = UlCrossAgentReport::from_evidence(
        "unknown",
        project_id,
        8,
        &a,
        &passing_evidence(UlCrossAgentDirection::B),
        vec!["B2".to_owned()],
    );
    assert!(!unknown.passed);
}

#[test]
fn unknown_outcome_never_redispatches() {
    assert_eq!(
        ul_cross_agent_dispatch_decision(UlCrossAgentInvocationState::NeverDispatched, 0),
        UlCrossAgentDispatchDecision::DispatchFirstAttempt
    );
    assert_eq!(
        ul_cross_agent_dispatch_decision(UlCrossAgentInvocationState::NeverDispatched, 1),
        UlCrossAgentDispatchDecision::RetryProvenUndispatched
    );
    for state in [
        UlCrossAgentInvocationState::Attempting,
        UlCrossAgentInvocationState::Succeeded,
        UlCrossAgentInvocationState::Failed,
        UlCrossAgentInvocationState::UnknownOutcome,
    ] {
        assert_eq!(
            ul_cross_agent_dispatch_decision(state, 0),
            UlCrossAgentDispatchDecision::RefuseRedispatch
        );
    }
}

#[test]
fn reference_client_supports_windows_powershell_51_argument_marshalling() -> Result<()> {
    let script =
        std::fs::read_to_string(workspace_root()?.join("scripts/eliot-mcp-reference-client.ps1"))?;

    assert!(script.contains("function ConvertTo-NativeCommandLineArgument"));
    assert!(script.contains("function ConvertFrom-JsonCompatible"));
    assert!(script.contains("if ($null -ne $startInfo.ArgumentList)"));
    assert!(script.contains("$startInfo.Arguments ="));
    let initialize = script
        .find("method = 'initialize'")
        .context("reference client initialize request")?;
    let initialized = script
        .find("method = 'notifications/initialized'")
        .context("reference client initialized notification")?;
    let tools_list = script
        .find("method = 'tools/list'")
        .context("reference client tools/list request")?;
    assert!(initialize < tools_list);
    assert!(initialized > tools_list);
    assert!(script.contains("if ($request.id -eq 1)"));
    assert!(script.contains("ELIOT_GOVERNOR_CONFIG"));
    assert!(script.contains("ELIOT_AGENT_SESSION_ID"));
    assert!(script.contains("ELIOT_PROJECT_ID"));
    assert!(script.contains("ELIOT_TASK_ID"));
    assert!(script.contains("ELIOT_ROLE_LEASE_ID"));
    Ok(())
}

#[test]
fn cli_exposes_separate_cross_agent_group() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["ul", "cross-agent", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for command in ["doctor", "run", "report"] {
        assert!(
            help.contains(command),
            "missing cross-agent command {command}"
        );
    }
    Ok(())
}
