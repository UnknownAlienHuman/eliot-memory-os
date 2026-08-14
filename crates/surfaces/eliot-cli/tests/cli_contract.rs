use eliot_cli::{
    CommandArguments, CommandCatalogue, CommandId, CommandRequest, CommandResult,
    UnavailableReason, validate_catalogue,
};
use serde_json::{Value, json};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("fixture construction failed: {error:?}"),
    }
}

fn request_json(command: &str) -> Value {
    let arguments = match command {
        "system-snapshot" => json!({"kind": "system_snapshot"}),
        "ui" => json!({"kind": "ui"}),
        "dashboard" => json!({"kind": "dashboard"}),
        "bootstrap-brief" => json!({"kind": "bootstrap_brief", "work_unit": "work-unit-1"}),
        "doctor-integration" => json!({"kind": "doctor_integration", "profile": "default"}),
        _ => json!({"kind": "system_snapshot"}),
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
                        "authority_epoch": 1,
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
                    "authority_epoch": 1,
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
        Some("eliot system snapshot")
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
    let input_branches = schema_value
        .get("input_schema")
        .and_then(|schema| schema.get("oneOf"))
        .and_then(Value::as_array)
        .expect("executable input schema branches");
    assert_eq!(input_branches.len(), catalogue.commands().len());
    for spec in catalogue.commands() {
        assert!(help.contains(spec.usage));
        assert!(commands.is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(spec.id.as_str()))
        }));
        let branch = input_branches
            .iter()
            .find(|branch| {
                branch
                    .pointer("/properties/command/const")
                    .and_then(Value::as_str)
                    == Some(spec.id.as_str())
            })
            .expect("command branch");
        assert_eq!(
            branch
                .pointer("/properties/arguments/properties/kind/const")
                .and_then(Value::as_str),
            Some(spec.id.as_str().replace('-', "_").as_str())
        );
    }
    let doctor_branch = input_branches
        .iter()
        .find(|branch| {
            branch
                .pointer("/properties/command/const")
                .and_then(Value::as_str)
                == Some("doctor-integration")
        })
        .expect("doctor integration branch");
    let doctor_arguments = doctor_branch
        .pointer("/properties/arguments")
        .expect("doctor integration arguments");
    assert!(doctor_arguments.pointer("/properties/profile").is_some());
    assert!(doctor_arguments.pointer("/properties/scope").is_none());
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
    let plan_gap = must(catalogue.execute(&request("system-snapshot")));
    assert!(matches!(
        &plan_gap.result,
        CommandResult::Unavailable {
            reason: UnavailableReason::PlanGap { .. }
        }
    ));
    must(plan_gap.validate_for(catalogue, &request("system-snapshot")));

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
            assert_eq!(dependency, "eliot-controlboard");
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
            assert_eq!(dependency, "eliot-controlboard");
        }
        result => panic!("unexpected dashboard result: {result:?}"),
    }
    must(dashboard.validate_for(catalogue, &request("dashboard")));
}

#[test]
fn unavailable_result_preserves_effect_and_exact_correlation() {
    let catalogue = CommandCatalogue::current();
    let request = request("system-snapshot");
    let response = must(catalogue.execute(&request));
    assert!(matches!(
        &response.result,
        CommandResult::Unavailable {
            reason: UnavailableReason::PlanGap { .. }
        }
    ));
    assert_eq!(response.effect, eliot_receipts::EffectClass::Read);
    assert_eq!(
        response.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    must(response.validate_for(catalogue, &request));

    let mut forged = response.clone();
    if let CommandResult::Unavailable {
        reason: UnavailableReason::PlanGap { dependency, .. },
    } = &mut forged.result
    {
        dependency.push_str("-forged");
    }
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
    if let CommandArguments::BootstrapBrief { work_unit } = &mut blank.arguments {
        work_unit.clear();
    }
    assert!(matches!(
        blank.validate(),
        Err(eliot_cli::CliError::InvalidArgument { field: "work_unit" })
    ));

    let mut control = request("bootstrap-brief");
    if let CommandArguments::BootstrapBrief { work_unit } = &mut control.arguments {
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
        "dependency": "eliot-controlboard",
        "unexpected": true
    });
    assert!(serde_json::from_value::<UnavailableReason>(reason).is_err());

    let result = json!({
        "kind": "UNAVAILABLE",
        "reason": {
            "code": "PLAN_GAP",
            "missing_work_id": "A-08",
            "dependency": "eliot-controlboard"
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
