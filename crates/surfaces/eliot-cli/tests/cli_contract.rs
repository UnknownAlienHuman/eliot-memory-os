use eliot_cli::{
    CommandArguments, CommandCatalogue, CommandId, CommandRequest, CommandResult,
    UnavailableReason, validate_catalogue,
};
use eliot_receipts::{EffectClass, ProofCeiling};
use serde_json::{Value, json};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("fixture construction failed: {error:?}"),
    }
}

fn request_json(command: &str) -> Value {
    let arguments = match command {
        "ui" => json!({"kind": "ui"}),
        "dashboard" => json!({"kind": "dashboard"}),
        "bootstrap-brief" => json!({
            "kind": "bootstrap_brief",
            "work_unit": "C:\\Development\\Rust\\projects\\eliot-memory-os\\work-unit.json",
            "repo_root": "C:\\Development\\Rust\\projects\\eliot-memory-os"
        }),
        "doctor-integration" => json!({"kind": "doctor_integration", "profile": "default"}),
        _ => json!({
            "kind": "system_snapshot",
            "repo_root": "C:\\Development\\Rust\\projects\\eliot-memory-os",
            "output_path": "C:\\Temp\\eliot-current-system.json"
        }),
    };
    json!({
        "request": {
            "request": {
                "metadata": {
                    "request_id": "request-1",
                    "session_id": null,
                    "task_id": null,
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": {
                        "authority_epoch": {
                            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                            "sequence": 1
                        },
                        "resource_generation": 1,
                        "task_revision": null,
                        "policy_revision": null,
                        "integration_revision": null
                    },
                    "clock": {
                        "valid_time_ms": null,
                        "known_time_ms": null,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1
                    },
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                }
            },
            "idempotency_key": "idempotency-1",
            "deadline_unix_ms": 1,
            "cancellation_id": "cancel-1"
        },
        "command": command,
        "arguments": arguments
    })
}

fn request(command: &str) -> CommandRequest {
    must(serde_json::from_value(request_json(command)))
}

#[test]
fn help_and_schema_are_deterministic_projections_of_one_catalogue() {
    let catalogue = CommandCatalogue::current();
    must(catalogue.validate());
    assert_eq!(catalogue.commands().len(), 25);
    assert_eq!(
        catalogue.commands().first().map(|spec| spec.usage),
        Some("eliot system snapshot --repo-root <ABSOLUTE> --output <ABSOLUTE>")
    );
    assert_eq!(
        catalogue.commands().last().map(|spec| spec.usage),
        Some("eliot maintenance run")
    );
    assert!(
        catalogue
            .commands()
            .iter()
            .all(|spec| spec.usage != "eliot help" && spec.usage != "eliot schema")
    );
    let help = must(catalogue.help_text());
    let schema = must(catalogue.schema_json());
    assert_eq!(help, must(catalogue.help_text()));
    assert_eq!(schema, must(catalogue.schema_json()));
    let schema_value: Value = must(serde_json::from_str(&schema));
    assert!(schema_value.get("input_schema").is_some());
    assert!(schema_value.get("output_schema").is_some());
    let commands = schema_value.get("commands").and_then(Value::as_array);
    assert!(commands.is_some());
    let input_branches = must(
        schema_value
            .get("input_schema")
            .and_then(|schema| schema.get("oneOf"))
            .and_then(Value::as_array)
            .ok_or("executable input schema branches"),
    );
    assert_eq!(input_branches.len(), catalogue.commands().len());
    for spec in catalogue.commands() {
        assert!(help.contains(spec.usage));
        assert!(commands.is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(spec.id.as_str()))
        }));
        let branch = must(
            input_branches
                .iter()
                .find(|branch| {
                    branch
                        .pointer("/properties/command/const")
                        .and_then(Value::as_str)
                        == Some(spec.id.as_str())
                })
                .ok_or("command branch"),
        );
        assert_eq!(
            branch
                .pointer("/properties/arguments/properties/kind/const")
                .and_then(Value::as_str),
            Some(spec.id.as_str().replace('-', "_").as_str())
        );
    }
    let doctor_branch = must(
        input_branches
            .iter()
            .find(|branch| {
                branch
                    .pointer("/properties/command/const")
                    .and_then(Value::as_str)
                    == Some("doctor-integration")
            })
            .ok_or("doctor integration branch"),
    );
    let doctor_arguments = must(
        doctor_branch
            .pointer("/properties/arguments")
            .ok_or("doctor integration arguments"),
    );
    assert!(doctor_arguments.pointer("/properties/profile").is_some());
    assert!(doctor_arguments.pointer("/properties/scope").is_none());
}

#[test]
fn bootstrap_brief_is_admitted_with_candidate_ceiling_and_explicit_roots() {
    let spec = must(
        CommandCatalogue::current()
            .commands()
            .iter()
            .find(|spec| spec.id == CommandId::BootstrapBrief)
            .ok_or("bootstrap brief command"),
    );
    assert_eq!(spec.effect, EffectClass::Candidate);
    assert_eq!(spec.proof_ceiling, ProofCeiling::CandidateArtifact);
    assert!(matches!(
        spec.availability,
        eliot_cli::CommandAvailability::Admitted
    ));
    let request = request("bootstrap-brief");
    assert!(request.validate().is_ok());
    assert!(matches!(
        request.arguments,
        CommandArguments::BootstrapBrief { .. }
    ));
}

#[test]
fn unknown_and_duplicate_commands_fail_closed() {
    let unknown = serde_json::from_value::<CommandRequest>(request_json("future-command"));
    assert!(unknown.is_err());

    let mut commands = CommandCatalogue::current().commands().to_vec();
    let duplicate = commands[0];
    commands.push(duplicate);
    let providers = must(CommandCatalogue::current().providers());
    assert!(validate_catalogue(&commands, &providers).is_err());

    let mut extra = request_json("system-snapshot");
    if let Some(object) = extra.as_object_mut() {
        object.insert("unexpected".to_owned(), Value::Bool(true));
    } else {
        panic!("request fixture must be an object");
    }
    assert!(serde_json::from_value::<CommandRequest>(extra).is_err());

    let duplicate = must(serde_json::to_string(&request_json("system-snapshot"))).replace(
        "\"kind\":\"system_snapshot\"",
        "\"kind\":\"system_snapshot\",\"kind\":\"system_snapshot\"",
    );
    assert!(serde_json::from_str::<CommandRequest>(&duplicate).is_err());
}

#[test]
fn missing_a06_and_a08_operations_are_typed_unavailable() {
    let catalogue = CommandCatalogue::current();
    let plan_gap = must(catalogue.execute(&request("ui")));
    assert!(matches!(
        &plan_gap.result,
        CommandResult::Unavailable {
            reason: UnavailableReason::PlanGap { .. }
        }
    ));
    must(plan_gap.validate_for(catalogue, &request("ui")));

    let snapshot = must(catalogue.forwarded_snapshot_response(
        &request("system-snapshot"),
        json!({"snapshot_sha256": "a".repeat(64), "receipt_sha256": "b".repeat(64)}),
    ));
    assert!(matches!(snapshot.result, CommandResult::Forwarded { .. }));

    let ui = must(catalogue.execute(&request("ui")));
    match &ui.result {
        CommandResult::Unavailable {
            reason:
                UnavailableReason::PlanGap {
                    missing_work_id,
                    dependency,
                },
        } => {
            assert_eq!(missing_work_id, "A-08");
            assert_eq!(
                dependency,
                "no admitted Kernel/Governor provider is injected"
            );
        }
        result => panic!("unexpected UI result: {result:?}"),
    }
    must(ui.validate_for(catalogue, &request("ui")));

    let dashboard = must(catalogue.execute(&request("dashboard")));
    match &dashboard.result {
        CommandResult::Unavailable {
            reason:
                UnavailableReason::PlanGap {
                    missing_work_id,
                    dependency,
                },
        } => {
            assert_eq!(missing_work_id, "A-08");
            assert_eq!(
                dependency,
                "no admitted Kernel/Governor provider is injected"
            );
        }
        result => panic!("unexpected dashboard result: {result:?}"),
    }
    must(dashboard.validate_for(catalogue, &request("dashboard")));
}

#[test]
fn unimplemented_wire_kind_is_distinct_from_unavailable() {
    let result = CommandResult::Unimplemented {
        architecture_anchor: "A0.8".to_owned(),
        work_item_id: "W0-01".to_owned(),
        detail: "implementation is intentionally bounded to a later work item".to_owned(),
    };
    let wire = must(serde_json::to_value(&result));
    assert_eq!(
        wire.get("kind").and_then(Value::as_str),
        Some("UNIMPLEMENTED")
    );
    assert_eq!(
        wire.get("architecture_anchor").and_then(Value::as_str),
        Some("A0.8")
    );
    assert_eq!(
        wire.get("work_item_id").and_then(Value::as_str),
        Some("W0-01")
    );
    assert_eq!(
        wire.get("detail").and_then(Value::as_str),
        Some("implementation is intentionally bounded to a later work item")
    );
    assert!(matches!(
        must(serde_json::from_value::<CommandResult>(wire.clone())),
        CommandResult::Unimplemented { .. }
    ));

    let unavailable = must(serde_json::to_value(CommandResult::Unavailable {
        reason: UnavailableReason::PlanGap {
            missing_work_id: "W0-01".to_owned(),
            dependency: "eliot-cli".to_owned(),
        },
    }));
    assert_eq!(
        unavailable.get("kind").and_then(Value::as_str),
        Some("UNAVAILABLE")
    );
    assert_ne!(
        unavailable.get("kind").and_then(Value::as_str),
        wire.get("kind").and_then(Value::as_str)
    );
}

#[test]
fn admitted_snapshot_result_preserves_effect_and_exact_correlation() {
    let catalogue = CommandCatalogue::current();
    let request = request("system-snapshot");
    let response = must(catalogue.forwarded_snapshot_response(
        &request,
        json!({"snapshot_sha256": "a".repeat(64), "receipt_sha256": "b".repeat(64)}),
    ));
    assert!(matches!(&response.result, CommandResult::Forwarded { .. }));
    assert_eq!(response.effect, eliot_receipts::EffectClass::Read);
    assert_eq!(
        response.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    must(response.validate_for(catalogue, &request));

    let mut forged = response.clone();
    forged.command = CommandId::RecoveryStatus;
    assert!(forged.validate_for(catalogue, &request).is_err());

    let mut mismatched = response;
    mismatched.command = CommandId::RecoveryStatus;
    assert!(mismatched.validate_for(catalogue, &request).is_err());
}

#[test]
fn typed_arguments_enforce_bijection_and_nonblank_fields() {
    let mut typed = request("bootstrap-brief");
    assert!(typed.validate().is_ok());
    typed.command = CommandId::SystemSnapshot;
    assert!(matches!(
        typed.validate(),
        Err(eliot_cli::CliError::ArgumentCommandMismatch)
    ));

    let mut blank = request("bootstrap-brief");
    if let CommandArguments::BootstrapBrief { work_unit, .. } = &mut blank.arguments {
        work_unit.clear();
    }
    assert!(matches!(
        blank.validate(),
        Err(eliot_cli::CliError::InvalidArgument { field: "work_unit" })
    ));

    let mut control = request("bootstrap-brief");
    if let CommandArguments::BootstrapBrief { work_unit, .. } = &mut control.arguments {
        work_unit.push('\n');
    }
    assert!(control.validate().is_err());

    let mut extra = request_json("bootstrap-brief");
    if let Some(arguments) = extra.get_mut("arguments").and_then(Value::as_object_mut) {
        arguments.insert("unexpected".to_owned(), Value::String("x".to_owned()));
    } else {
        panic!("typed argument fixture must be an object");
    }
    assert!(serde_json::from_value::<CommandRequest>(extra).is_err());

    let mut doctor = request_json("doctor-integration");
    if let Some(arguments) = doctor.get_mut("arguments").and_then(Value::as_object_mut) {
        arguments.insert("scope".to_owned(), Value::String("wrong".to_owned()));
    } else {
        panic!("doctor argument fixture must be an object");
    }
    assert!(serde_json::from_value::<CommandRequest>(doctor).is_err());
}

#[test]
fn public_wire_envelopes_reject_unknown_fields() {
    let reason = json!({
        "code": "PLAN_GAP",
        "missing_work_id": "A-08",
        "dependency": "no admitted Kernel/Governor provider is injected",
        "unexpected": true
    });
    assert!(serde_json::from_value::<UnavailableReason>(reason).is_err());

    let result = json!({
        "kind": "UNAVAILABLE",
        "reason": {
            "code": "PLAN_GAP",
            "missing_work_id": "A-08",
            "dependency": "no admitted Kernel/Governor provider is injected"
        },
        "unexpected": true
    });
    assert!(serde_json::from_value::<CommandResult>(result).is_err());
}

#[test]
fn full_request_identity_and_intended_effect_survive_unavailable_results() {
    let catalogue = CommandCatalogue::current();
    let request = request("ui");
    let response = must(catalogue.execute(&request));
    assert_eq!(response.effect, eliot_receipts::EffectClass::ExternalEffect);

    let mut forged = response.clone();
    forged.request.idempotency_key.push_str("-forged");
    assert!(matches!(
        forged.validate_for(catalogue, &request),
        Err(eliot_cli::CliError::CorrelationMismatch)
    ));

    assert_eq!(
        catalogue
            .commands()
            .iter()
            .find(|spec| spec.id == CommandId::ModulePromote)
            .map(|spec| spec.effect),
        Some(eliot_receipts::EffectClass::ExternalEffect)
    );
}

use eliot_cli::antigravity_terminal::{
    AntigravityTerminalInputs, CanonicalDispositionInput, ErrorEventInput, ProjectedAttemptState,
    ProjectedDisposition, TerminalView, ViewOrigin, project,
};

fn terminal_view(
    origin: ViewOrigin,
    sequence: u64,
    cursor: &str,
    attempt_state: ProjectedAttemptState,
) -> TerminalView {
    TerminalView {
        origin,
        session_id: "session-9b-terminal-1".to_owned(),
        attempt_id: "attempt-9b-terminal-1".to_owned(),
        task_id: "task-9b-terminal-1".to_owned(),
        route_id: eliot_cli::antigravity_terminal::PRIMARY_ROUTE_ID.to_owned(),
        sequence,
        cursor: cursor.to_owned(),
        attempt_state,
        disposition: ProjectedDisposition::UnknownOutcome,
    }
}

fn terminal_inputs() -> AntigravityTerminalInputs {
    AntigravityTerminalInputs {
        supervisor: terminal_view(
            ViewOrigin::Supervisor,
            9,
            "cursor-9b-9",
            ProjectedAttemptState::Reconciling,
        ),
        api: terminal_view(ViewOrigin::Api, 9, "cursor-9b-9", ProjectedAttemptState::Reconciling),
        cli: terminal_view(ViewOrigin::Cli, 9, "cursor-9b-9", ProjectedAttemptState::Reconciling),
        stale_cli: terminal_view(
            ViewOrigin::Cli,
            4,
            "cursor-9b-4",
            ProjectedAttemptState::Running,
        ),
        error_event: ErrorEventInput {
            attempt_id: "attempt-9b-terminal-1".to_owned(),
            event_id: "event-9b-error-5".to_owned(),
            sequence: 5,
            cursor: "cursor-9b-5".to_owned(),
            error_code: "PROVIDER_TIMEOUT".to_owned(),
        },
        canonical: CanonicalDispositionInput {
            session_id: "session-9b-terminal-1".to_owned(),
            attempt_id: "attempt-9b-terminal-1".to_owned(),
            task_id: "task-9b-terminal-1".to_owned(),
            route_id: eliot_cli::antigravity_terminal::PRIMARY_ROUTE_ID.to_owned(),
            disposition: ProjectedDisposition::UnknownOutcome,
            terminal_ref: "terminal-9b-9".to_owned(),
            sequence: 9,
            cursor: "cursor-9b-9".to_owned(),
        },
    }
}

#[test]
fn antigravity_terminal_projection_keeps_stale_error_and_canonical_independent() {
    let inputs = terminal_inputs();
    must(inputs.validate());
    let receipt = must(project(&inputs));
    assert!(receipt.same_identity);
    assert!(receipt.same_disposition);
    assert!(receipt.stale_independent);
    assert!(receipt.error_independent);
    assert!(!receipt.reduces_to_terminal);
    assert_eq!(receipt.coverage, "documented_not_observed");
    assert_eq!(receipt.reducer_handoff, "MGR02");
    assert_ne!(inputs.stale_cli.sequence, inputs.canonical.sequence);
    assert_ne!(inputs.error_event.sequence, inputs.canonical.sequence);
    assert_ne!(
        inputs.error_event.event_id,
        inputs.canonical.terminal_ref
    );
    assert_eq!(inputs.supervisor.attempt_id, inputs.canonical.attempt_id);
    assert_eq!(inputs.api.attempt_id, inputs.canonical.attempt_id);
    assert_eq!(inputs.cli.attempt_id, inputs.canonical.attempt_id);
}

#[test]
fn antigravity_terminal_projection_fails_closed_on_identity_or_disposition_drift() {
    let mut drifted_cli = terminal_inputs();
    drifted_cli.cli.attempt_id = "attempt-9b-terminal-2".to_owned();
    assert!(matches!(
        project(&drifted_cli),
        Err(eliot_cli::antigravity_terminal::TerminalProjectionError::IdentityMismatch)
    ));

    let mut drifted_disposition = terminal_inputs();
    drifted_disposition.cli.disposition = ProjectedDisposition::CandidateSucceeded;
    assert!(matches!(
        project(&drifted_disposition),
        Err(eliot_cli::antigravity_terminal::TerminalProjectionError::DispositionMismatch)
    ));

    let mut blank = terminal_inputs();
    blank.cli.cursor.clear();
    assert!(matches!(
        project(&blank),
        Err(eliot_cli::antigravity_terminal::TerminalProjectionError::BlankField { .. })
    ));

    let mut zero = terminal_inputs();
    zero.error_event.sequence = 0;
    assert!(matches!(
        project(&zero),
        Err(eliot_cli::antigravity_terminal::TerminalProjectionError::ZeroSequence)
    ));
}

#[test]
fn severed_plan_gap_literal_stays_wire_stable() {
    assert_eq!(eliot_cli::CONTROLBOARD_PLAN_GAP, "PLAN_GAP");
    assert!(must(CommandCatalogue::current().help_text()).contains("[PLAN_GAP]"));
    let schema = must(CommandCatalogue::current().schema_json());
    assert!(schema.contains("\"code\":\"PLAN_GAP\""));
}
