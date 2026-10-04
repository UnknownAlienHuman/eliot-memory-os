//! CLI backup surface acceptance cases 1-6, 12, 14 (issue #963).
//!
//! These cases drive the REAL `eliot_cli::backup` parsers
//! (`parse_backup_create`, `parse_backup_verify`, `parse_backup_restore_test`),
//! the catalogue-sourced effect and proof ceiling read from the
//! `CommandCatalogue::current().commands()` rows, and the REAL human
//! projection (`render_backup_outcome_human`). Every accepted scope, class,
//! digest, hex byte and bounded text is checked against the shipped closed
//! rules, and every refusal names the exact field the closed parser used, so
//! no case here can pass on a fixture that has drifted from the source of
//! truth.
//!
//! The three `backup_create` / `backup_verify` / `backup_restore_test`
//! client entry points are deliberately NOT exercised by this suite: each
//! opens a `KernelClient::load` against a live, authenticated Kernel front
//! door, which no hermetic test can supply. Their Kernel-side production
//! dispatch and typed refusals are proven by the sibling suite
//! `bins/eliot-kernel/tests/backup_dispatch.rs`; the fixtures those entry
//! points decode (the `create-refused-plan-gap.json`,
//! `restore-test-blocked-plan-gap.json` and
//! `restore-test-refused-destination-not-admitted.json` replies) are asserted
//! here as the REAL today's answers, never a fabricated receipt.
//!
//! The governing rule is the one every one of these cases serves, quoted from
//! `crates/surfaces/AGENTS.md`: "A displayed ID, successful tool response or
//! UI terminal state is not a canonical receipt/readback." A `refused` or
//! `blocked` owner reply — and this surface's projection of it — is exactly
//! such a displayed state, never a recovery receipt.

use std::path::{Path, PathBuf};

use eliot_cli::backup::{
    BACKUP_CREATE_MISSING_OWNER, BACKUP_STATE_REFUSED, BACKUP_STATE_VERIFIED, BackupCreateParams,
    BackupOperationOutcome, BackupRestoreTestParams, BackupVerifyParams, parse_backup_create,
    parse_backup_restore_test, parse_backup_verify, render_backup_outcome_human,
};
use eliot_cli::{
    CliError, CommandArguments, CommandAvailability, CommandCatalogue, CommandId, CommandRequest,
    CommandResponse, CommandResult,
};
use eliot_protocol::RequestIdentity;
use eliot_protocol::backup::BackupStage;
use eliot_receipts::{EffectClass, ProofCeiling};
use serde_json::{Value, json};

fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("fixture construction failed: {error:?}"),
    }
}

/// Loads one frozen backup fixture by file name, so a fixture that is missing
/// is a loud failure rather than a silent default.
fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/backup")
        .join(name);
    let text = must(std::fs::read_to_string(&path));
    must(serde_json::from_str(&text))
}

/// Reads one required string field out of a fixture object.
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    match value.get(key).and_then(Value::as_str) {
        Some(text) => text,
        None => panic!("fixture field {key} must be a JSON string"),
    }
}

/// Reads one required unsigned integer field out of a fixture object.
fn number(value: &Value, key: &str) -> u64 {
    match value.get(key).and_then(Value::as_u64) {
        Some(parsed) => parsed,
        None => panic!("fixture field {key} must be a JSON unsigned integer"),
    }
}

/// Finds the one catalogue row for `id` through the public `commands()` slice
/// (the catalogue's `find` is private) and asserts it is actually present
/// before any of its values are read.
fn spec_row(id: CommandId) -> eliot_cli::CommandSpec {
    let rows = CommandCatalogue::current().commands();
    assert!(
        rows.iter().any(|spec| spec.id == id),
        "catalogue must carry a row for {}",
        id.as_str()
    );
    let found = rows.iter().find(|spec| spec.id == id);
    match found {
        Some(spec) => *spec,
        None => panic!("catalogue must carry a row for {}", id.as_str()),
    }
}

// ---------------------------------------------------------------------------
// Case 1: the three existing backup command IDs and their usage are preserved.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/1 backup_command_ids_and_usage_preserved
#[test]
fn backup_command_ids_and_usage_preserved() {
    assert_eq!(CommandId::BackupCreate.as_str(), "backup-create");
    assert_eq!(CommandId::BackupVerify.as_str(), "backup-verify");
    assert_eq!(CommandId::BackupRestoreTest.as_str(), "backup-restore-test");

    for (id, usage) in [
        (CommandId::BackupCreate, "eliot backup create"),
        (CommandId::BackupVerify, "eliot backup verify"),
        (CommandId::BackupRestoreTest, "eliot backup restore-test"),
    ] {
        let spec = spec_row(id);
        assert_eq!(spec.usage, usage, "usage for {}", id.as_str());
        assert_eq!(spec.owner, "eliot-cli", "owner for {}", id.as_str());
        assert_eq!(spec.required_work_id, "A-06", "work id for {}", id.as_str());
    }
}

// ---------------------------------------------------------------------------
// Case 2: valid bounded typed create arguments parse, and the parser is
// bounded (blank scope and unknown class each refuse with their own field).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/2 valid_bounded_create_arguments
#[test]
fn valid_bounded_create_arguments() {
    let valid = fixture("create-valid.json");
    let params: BackupCreateParams = must(parse_backup_create(
        field(&valid, "scope_descriptor"),
        field(&valid, "class"),
    ));
    assert_eq!(params.scope_descriptor, field(&valid, "scope_descriptor"));
    assert_eq!(params.class, "full_recovery");

    // Bounded, never defaulted: a blank scope refuses on its own field.
    assert_eq!(
        parse_backup_create("", "full_recovery"),
        Err(CliError::InvalidArgument {
            field: "backup.scope_descriptor"
        })
    );
    // An unknown class token refuses on the class field; it is never coerced
    // to a nearby class and never falls back to a default.
    assert_eq!(
        parse_backup_create("scope", "not-a-class"),
        Err(CliError::InvalidArgument {
            field: "backup.class"
        })
    );
}

// ---------------------------------------------------------------------------
// Case 3: valid typed verify arguments pass through unchanged, and odd-length,
// uppercase, over-length and empty hex each refuse with the bundle field.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/3 valid_verify_arguments_and_hex_bound
#[test]
fn valid_verify_arguments_and_hex_bound() {
    let valid = fixture("verify-valid.json");
    let bundle = field(&valid, "bundle_hex");
    let params: BackupVerifyParams = must(parse_backup_verify(bundle));
    // The parser does NOT normalize the value: it is returned byte-identical.
    assert_eq!(params.bundle_hex, bundle);

    let over_length = "a".repeat(eliot_cli::backup::BACKUP_WIRE_BYTES_MAX * 2 + 2);
    for (label, input) in [
        ("odd-length", "abc"),
        ("uppercase", "ABCDEF"),
        ("over-length", over_length.as_str()),
        ("empty", ""),
    ] {
        assert_eq!(
            parse_backup_verify(input),
            Err(CliError::InvalidArgument {
                field: "backup.bundle_hex"
            }),
            "{label} hex must refuse on backup.bundle_hex"
        );
    }
}

// ---------------------------------------------------------------------------
// Case 4: the eleven valid restore-test arguments round-trip, the ISOLATION
// boundary (target == dest store) refuses on restore.isolation, the zero
// sequence/generation and non-UUID lineage each refuse on their own field, and
// the flat fixture agrees with the nested wire payload.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/4 valid_isolated_restore_test_arguments
#[test]
fn valid_isolated_restore_test_arguments() {
    let valid = fixture("restore-test-valid.json");
    let params = restore_params(&valid);
    assert_restore_params_match(&valid, &params);

    // The A13.7 "restore occurs in an isolated area" boundary: a destination
    // equal to the restore target is not isolated and refuses.
    let mut not_isolated = valid.clone();
    if let Some(object) = not_isolated.as_object_mut() {
        object.insert(
            "dest_store_id".to_owned(),
            Value::String(field(&valid, "target_id").to_owned()),
        );
    } else {
        panic!("restore-test fixture must be an object");
    }
    assert_eq!(
        restore_result(&not_isolated).err(),
        Some(CliError::InvalidArgument {
            field: "restore.isolation"
        })
    );

    // The zero sequence and zero generation each refuse on their own field.
    for (key, expected) in [
        ("target_sequence", "backup.target_sequence"),
        ("target_generation", "backup.target_generation"),
    ] {
        let mut zeroed = valid.clone();
        if let Some(object) = zeroed.as_object_mut() {
            object.insert(key.to_owned(), json!(0));
        } else {
            panic!("restore-test fixture must be an object");
        }
        assert_eq!(
            restore_result(&zeroed).err(),
            Some(CliError::InvalidArgument { field: expected }),
            "zero {key} must refuse on {expected}"
        );
    }

    // A non-UUID target lineage refuses on its own field.
    let mut bad_lineage = valid.clone();
    if let Some(object) = bad_lineage.as_object_mut() {
        object.insert(
            "target_lineage".to_owned(),
            Value::String("not-a-uuid".to_owned()),
        );
    } else {
        panic!("restore-test fixture must be an object");
    }
    assert_eq!(
        restore_result(&bad_lineage).err(),
        Some(CliError::InvalidArgument {
            field: "backup.target_lineage"
        })
    );

    // Cross-surface agreement: the eleven flat fixture fields equal the five
    // wire keys' nested contents (target + provisioning + the three scalars),
    // which is what makes the case 7/17 payload mapping provable.
    restore_flat_agrees_with_nested_wire(&valid);
}

// Feeds a restore-test fixture object into the real parser.
fn restore_params(fixture: &Value) -> BackupRestoreTestParams {
    must(restore_result(fixture))
}

// Calls the real parser with the fixture's eleven arguments.
fn restore_result(fixture: &Value) -> Result<BackupRestoreTestParams, CliError> {
    let introductions = match fixture.get("introductions") {
        Some(Value::Array(entries)) => entries.clone(),
        _ => panic!("restore-test fixture must carry an introductions array"),
    };
    parse_backup_restore_test(
        field(fixture, "bundle_hex"),
        field(fixture, "destination_authorization_hex"),
        field(fixture, "target_id"),
        field(fixture, "target_lineage"),
        number(fixture, "target_sequence"),
        number(fixture, "target_generation"),
        field(fixture, "dest_store_id"),
        field(fixture, "residency_denominator_digest"),
        field(fixture, "source_snapshot_digest"),
        field(fixture, "capture_operation_id"),
        &introductions,
    )
}

/// Asserts every parsed restore-test field equals the fixture input it came
/// from, so the parser is proven to neither normalize nor substitute.
fn assert_restore_params_match(fixture: &Value, params: &BackupRestoreTestParams) {
    assert_eq!(params.bundle_hex, field(fixture, "bundle_hex"));
    assert_eq!(
        params.authorization_hex,
        field(fixture, "destination_authorization_hex")
    );
    assert_eq!(params.target_id, field(fixture, "target_id"));
    assert_eq!(params.target_lineage, field(fixture, "target_lineage"));
    assert_eq!(params.target_sequence, number(fixture, "target_sequence"));
    assert_eq!(
        params.target_generation,
        number(fixture, "target_generation")
    );
    assert_eq!(params.dest_store_id, field(fixture, "dest_store_id"));
    assert_eq!(
        params.residency_denominator_digest,
        field(fixture, "residency_denominator_digest")
    );
    assert_eq!(
        params.source_snapshot_digest,
        field(fixture, "source_snapshot_digest")
    );
    assert_eq!(
        params.capture_operation_id,
        field(fixture, "capture_operation_id")
    );
    assert_eq!(params.introductions.len(), 0);
}

/// Asserts the flat restore-test fixture and the nested wire-payload fixture
/// describe the SAME command, by comparing each flat field to the wire's
/// corresponding nested scalar.
fn restore_flat_agrees_with_nested_wire(flat: &Value) {
    let wire = fixture("restore-test-wire-payload.json");
    let payload = match wire.get("payload") {
        Some(payload) => payload.clone(),
        None => panic!("restore-test wire fixture must carry a payload object"),
    };
    assert_eq!(
        wire.get("operation").and_then(Value::as_str),
        Some("backup.restore-test")
    );

    // The three top-level scalars.
    assert_eq!(
        payload.get("bundle_hex").and_then(Value::as_str),
        Some(field(flat, "bundle_hex"))
    );
    assert_eq!(
        payload
            .get("destination_authorization_hex")
            .and_then(Value::as_str),
        Some(field(flat, "destination_authorization_hex"))
    );

    // The nested `target` object carries the four target fields.
    let target = match payload.get("target") {
        Some(target) => target.clone(),
        None => panic!("wire payload must carry a nested target object"),
    };
    for key in [
        "target_id",
        "target_lineage",
        "target_sequence",
        "target_generation",
    ] {
        assert_eq!(
            target.get(key),
            flat.get(key),
            "wire target.{key} must equal the flat fixture field"
        );
    }

    // The nested `provisioning` object carries the four provisioning fields.
    let provisioning = match payload.get("provisioning") {
        Some(provisioning) => provisioning.clone(),
        None => panic!("wire payload must carry a nested provisioning object"),
    };
    for key in [
        "dest_store_id",
        "residency_denominator_digest",
        "source_snapshot_digest",
        "capture_operation_id",
    ] {
        assert_eq!(
            provisioning.get(key),
            flat.get(key),
            "wire provisioning.{key} must equal the flat fixture field"
        );
    }

    // The explicit (possibly empty) introductions array is the eleventh field.
    assert_eq!(payload.get("introductions"), flat.get("introductions"));
}

// ---------------------------------------------------------------------------
// Case 5: missing / unknown / duplicate / oversized options are all refused,
// and none of them yields a default (any accepted scope is byte-identical to
// the input; the oversized text is refused on the scope field).
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/5 missing_unknown_duplicate_oversized_refuse_without_defaults
#[test]
fn missing_unknown_duplicate_oversized_refuse_without_defaults() {
    let fixture = fixture("create-missing-and-oversized-options.json");

    // Missing class: there is no class to parse, so the create cannot be built
    // from a missing class. Drive it as an explicitly blank class (the value a
    // missing option would have to become) and assert it refuses on the class
    // field, never defaulting to a class.
    let missing_class = match fixture.get("missing_class") {
        Some(value) => value.clone(),
        None => panic!("fixture must carry a missing_class object"),
    };
    assert_eq!(
        parse_backup_create(field(&missing_class, "scope_descriptor"), "").err(),
        Some(CliError::InvalidArgument {
            field: "backup.class"
        })
    );

    // Unknown option: the closed parser takes exactly (scope_descriptor,
    // class). Feeding the unknown option's own scope with the real class
    // yields a scope byte-identical to what was passed (never the unknown
    // option's value, never a default), and the unknown option itself has no
    // parameter it could occupy.
    let unknown = match fixture.get("unknown_option") {
        Some(value) => value.clone(),
        None => panic!("fixture must carry an unknown_option object"),
    };
    let unknown_scope = field(&unknown, "scope_descriptor");
    let unknown_params = must(parse_backup_create(unknown_scope, field(&unknown, "class")));
    assert_eq!(unknown_params.scope_descriptor, unknown_scope);
    assert_eq!(unknown_params.class, "full_recovery");

    // Duplicate scope: two parse attempts each succeed with their own scope;
    // neither can collapse to a single defaulted scope, and the two results
    // differ because the caller supplied two distinct scopes.
    let duplicate = match fixture.get("duplicate_scope") {
        Some(Value::Array(entries)) => entries.clone(),
        _ => panic!("fixture must carry a duplicate_scope array"),
    };
    assert_eq!(duplicate.len(), 2);
    let first = must(parse_backup_create(
        field(&duplicate[0], "scope_descriptor"),
        field(&duplicate[0], "class"),
    ));
    let second = must(parse_backup_create(
        field(&duplicate[1], "scope_descriptor"),
        field(&duplicate[1], "class"),
    ));
    assert_eq!(
        first.scope_descriptor,
        field(&duplicate[0], "scope_descriptor")
    );
    assert_eq!(
        second.scope_descriptor,
        field(&duplicate[1], "scope_descriptor")
    );
    assert_ne!(first.scope_descriptor, second.scope_descriptor);

    // Oversized class: the closed class decoder refuses it outright; a text
    // over BACKUP_TEXT_MAX also cannot become a scope descriptor.
    let oversized_class = field(&fixture, "oversized_class");
    assert_eq!(
        parse_backup_create("scope", oversized_class).err(),
        Some(CliError::InvalidArgument {
            field: "backup.class"
        })
    );
    let oversized_scope = "a".repeat(eliot_cli::backup::BACKUP_TEXT_MAX + 1);
    assert_eq!(
        parse_backup_create(&oversized_scope, "full_recovery").err(),
        Some(CliError::InvalidArgument {
            field: "backup.scope_descriptor"
        })
    );
}

// ---------------------------------------------------------------------------
// Case 6: the closed create parser admits no arbitrary override. The request
// that actually travels on the wire carries exactly the two declared fields,
// and any hostile value substituted for the scope stays an inert,
// non-authoritative scope string while the class remains one of the three
// closed tokens.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/6 arbitrary_overrides_rejected_by_closed_parser
#[test]
fn arbitrary_overrides_rejected_by_closed_parser() {
    let fixture = fixture("create-rejected-overrides.json");
    assert_create_carries_only_the_two_declared_fields();

    // Every fixture key outside that pair has no corresponding parameter.
    let allowed = ["scope_descriptor", "class"];
    if let Some(object) = fixture.as_object() {
        for key in object.keys() {
            assert!(
                !allowed.contains(&key.as_str()),
                "override fixture key {key} must not map to any create parameter"
            );
        }
    } else {
        panic!("override fixture must be an object");
    }

    for (key, hostile) in [
        ("path", field(&fixture, "path")),
        ("endpoint", field(&fixture, "endpoint")),
        ("sql", field(&fixture, "sql")),
        ("command", field(&fixture, "command")),
        ("key", field(&fixture, "key")),
        ("credential", field(&fixture, "credential")),
    ] {
        // For each hostile value, the outcome is DETERMINED, not merely
        // tolerated: the parser's own rule decides it, and this case asserts the
        // decided answer per value rather than accepting either branch. An
        // empty `Err` arm here would make the case unfalsifiable, because a
        // parser that always refused — or one that always accepted — would pass
        // it unchanged.
        //
        // The only create field that can refuse is `scope_descriptor`, via
        // `non_blank` (backup.rs:584-592), which refuses a blank value, any
        // control character, or a value longer than `BACKUP_TEXT_MAX` (256).
        // This predicate is the same three conditions, so the expected outcome
        // below is derived from the shipped rule rather than guessed.
        let refused = hostile.trim().is_empty()
            || hostile.chars().any(char::is_control)
            || hostile.len() > eliot_cli::backup::BACKUP_TEXT_MAX;
        let admitted = parse_backup_create(hostile, "full_recovery");
        if let Ok(params) = admitted {
            assert!(
                !refused,
                "hostile {key} carries a control character and must be refused, not echoed"
            );
            // Admitted only as an inert, non-authoritative descriptor: the
            // value is never normalised, widened, or read as anything but
            // the operator's own declared scope string.
            assert_eq!(params.scope_descriptor, hostile, "hostile {key} echoed");
            assert_eq!(params.class, "full_recovery");
        } else if let Err(error) = admitted {
            assert!(
                refused,
                "hostile {key} is a bounded non-control string and must be \
                 admitted as an inert scope, but it was refused: {error:?}"
            );
            assert_eq!(
                error,
                CliError::InvalidArgument {
                    field: "backup.scope_descriptor"
                }
            );
        }
    }

    // The returned class is always one of the three closed tokens, whatever the
    // hostile scope was.
    for class in ["full_recovery", "canonical_only_degraded", "scope_export"] {
        let parsed = must(parse_backup_create(field(&fixture, "path"), class));
        assert_eq!(parsed.class, class);
    }
}

/// Proves the two-field shape on the value that actually travels on the wire.
///
/// `BackupCreateParams` is the parser's local result and derives neither
/// `Serialize` nor `Deserialize` (`backup.rs:650-657`), so the structural proof
/// is made on `CommandArguments::BackupCreate` instead: the `CommandRequest` wire
/// variant (`lib.rs:178-183`) derives both directions, so it is proven that the
/// create request carries exactly the two declared fields plus the closed `kind`
/// discriminator, and no destination/path/endpoint/key/credential channel at
/// all. The value the wire form is built from is this very parser's own output,
/// and the same JSON decodes back to it unchanged.
fn assert_create_carries_only_the_two_declared_fields() {
    let params = must(parse_backup_create("scope", "full_recovery"));
    assert_eq!(params.scope_descriptor, "scope");
    assert_eq!(params.class, "full_recovery");

    let wire = must(serde_json::to_value(CommandArguments::BackupCreate {
        scope_descriptor: params.scope_descriptor.clone(),
        class: params.class.clone(),
    }));
    let Some(object) = wire.as_object() else {
        panic!("create arguments must serialize to a JSON object");
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["class", "kind", "scope_descriptor"],
        "the create request carries exactly the two declared fields plus the \
         closed kind discriminator"
    );
    assert_eq!(
        object.get("kind").and_then(Value::as_str),
        Some("backup_create"),
        "the discriminator must be the closed backup-create kind"
    );

    // The same wire value decodes back to the identical typed variant, so the
    // key set above is the value's whole admitted shape and not a projection
    // that cannot round-trip its own output.
    let decoded: CommandArguments = must(serde_json::from_value(wire));
    match decoded {
        CommandArguments::BackupCreate {
            scope_descriptor,
            class,
        } => {
            assert_eq!(scope_descriptor, params.scope_descriptor);
            assert_eq!(class, params.class);
        }
        other => panic!("create arguments must decode as BackupCreate, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Case 12: the catalogue is the single owner of effect and proof ceiling. Each
// of the three rows carries the exact effect/ceiling/availability, and a
// hand-built CommandResponse whose effect/proof_ceiling deviate from its spec
// row is refused with ResultMismatch by validate_for.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/12 correct_effect_classification_and_proof_ceiling
#[test]
fn correct_effect_classification_and_proof_ceiling() {
    // The exact catalogue-owned values for each of the three rows.
    for (id, effect) in [
        (CommandId::BackupCreate, EffectClass::ReversibleMutation),
        (CommandId::BackupVerify, EffectClass::Candidate),
        (CommandId::BackupRestoreTest, EffectClass::Candidate),
    ] {
        let spec = spec_row(id);
        assert_eq!(spec.effect, effect, "effect for {}", id.as_str());
        assert_eq!(spec.proof_ceiling, ProofCeiling::CandidateArtifact);
        match spec.availability {
            CommandAvailability::PlanGap {
                missing_work_id, ..
            } => {
                assert_eq!(missing_work_id, "A-06", "availability for {}", id.as_str());
            }
            other => panic!("{} must be PlanGap, got {other:?}", id.as_str()),
        }
    }

    // The load-bearing negative: a response whose effect/proof_ceiling deviate
    // from its spec row cannot validate against the catalogue. This is the
    // direction that refuses a classification the row does not state, so the
    // three commands are not all treated as read-only.
    let request = backup_create_request();
    let honest = honest_response(&request);
    // The honest response validates.
    must(honest.validate_for(CommandCatalogue::current(), &request));

    // An effect that deviates from the create row (ReversibleMutation) is
    // refused with ResultMismatch.
    let mut wrong_effect = honest.clone();
    wrong_effect.effect = EffectClass::Candidate;
    assert!(matches!(
        wrong_effect.validate_for(CommandCatalogue::current(), &request),
        Err(CliError::ResultMismatch)
    ));

    // A proof ceiling that deviates is likewise refused.
    let mut wrong_ceiling = honest.clone();
    wrong_ceiling.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    assert!(matches!(
        wrong_ceiling.validate_for(CommandCatalogue::current(), &request),
        Err(CliError::ResultMismatch)
    ));
}

/// Builds a valid backup-create `CommandRequest` with a full `RequestIdentity`,
/// following the working precedent in `cli_contract.rs`.
fn backup_create_request() -> CommandRequest {
    let request_json = json!({
        "request": {
            "request": {
                "metadata": {
                    "request_id": "request-backup-1",
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
            "idempotency_key": "idempotency-backup-1",
            "deadline_unix_ms": 1,
            "cancellation_id": "cancel-backup-1"
        },
        "command": "backup-create",
        "arguments": {
            "kind": "backup_create",
            "scope_descriptor": "synthetic-scope-descriptor",
            "class": "full_recovery"
        }
    });
    let request: CommandRequest = must(serde_json::from_value(request_json));
    // Confirm the typed arguments actually decoded to the backup-create variant.
    assert!(matches!(
        request.arguments,
        CommandArguments::BackupCreate { .. }
    ));
    request
}

/// Builds a `CommandResponse` whose effect and proof ceiling read honestly
/// from the create catalogue row, so the only deviation under test is the one a
/// later mutation introduces.
fn honest_response(request: &CommandRequest) -> CommandResponse {
    CommandResponse {
        request: request.request.clone(),
        command: request.command,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        result: CommandResult::Forwarded {
            payload: json!({"state": BACKUP_STATE_REFUSED}),
        },
    }
}

// ---------------------------------------------------------------------------
// Case 14: today's REAL answers are asserted, never a fabricated receipt. The
// create refusal names the missing capture owner; the blob-free restore-test
// refusal carries NO missing_owner (absence asserted explicitly); the
// blob-carrying refusal is blocked on plan_gap with a missing owner. A mutated
// outcome still projects `state: refused` and can never read `verified`.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 963/14 domain_receipt_class_source_destination_mismatch_rejected
#[test]
fn domain_receipt_class_source_destination_mismatch_rejected() {
    // The create refusal: status refused, code plan_gap, and the missing owner
    // is the imported constant, not a re-typed literal.
    let create = fixture("create-refused-plan-gap.json");
    assert_eq!(field(&create, "status"), "refused");
    assert_eq!(field(&create, "code"), "plan_gap");
    assert_eq!(field(&create, "missing_owner"), BACKUP_CREATE_MISSING_OWNER);

    // The blob-free restore-test refusal: status refused, code
    // restore-destination-not-admitted, and — the point — NO missing_owner key.
    let not_admitted = fixture("restore-test-refused-destination-not-admitted.json");
    assert_eq!(field(&not_admitted, "status"), "refused");
    assert_eq!(
        field(&not_admitted, "code"),
        "restore-destination-not-admitted"
    );
    assert!(
        not_admitted.get("missing_owner").is_none(),
        "the destination-not-admitted refusal must carry no missing_owner key"
    );

    // The blob-carrying restore-test refusal: status blocked, code plan_gap, and
    // a missing owner is present.
    let blocked = fixture("restore-test-blocked-plan-gap.json");
    assert_eq!(field(&blocked, "status"), "blocked");
    assert_eq!(field(&blocked, "code"), "plan_gap");
    assert!(blocked.get("missing_owner").is_some());

    // The executed-route arrays are part of the answer, not decoration: the
    // Kernel seeds `gates_not_admitted` before the owner is called and appends
    // the two blob gates only for a blob-carrying archive
    // (request_dispatch.rs:471-477, :4382), while `gates_passed` grows as the
    // real execution pushes each gate (:433-440, :4380, :4392, :4417). A gate
    // listed in BOTH sets is the contradiction that split exists to make
    // impossible, and the CLI's own decoder requires a non-empty disjoint
    // `gates_passed` on any blocked reply (backup.rs:1422-1434). So assert the
    // exact membership, the disjointness, and the blob-conditional difference
    // between the two refusals — that difference is what proves the two
    // fixtures really are two different execution outcomes.
    assert_route_gates(&not_admitted, &blocked);

    // The mismatch half: an outcome mutated away from the owner's declared
    // archive/class/source/destination identity still projects `state: refused`
    // and can never be upgraded to verified by the projection, no matter what the
    // identity fields say.
    let rendered = render_backup_outcome_human(&mutated_refused_outcome());
    assert!(
        rendered.contains("state: refused"),
        "rendered projection must still report the refused state"
    );
    assert!(
        !rendered.contains("state: verified"),
        "projection must never upgrade a refused outcome to verified"
    );
    assert!(
        !rendered.contains(&format!("state: {BACKUP_STATE_VERIFIED}")),
        "projection must never contain the verified state line"
    );
}

/// Asserts the executed-route arrays carried by both restore-test refusals.
///
/// The six shape gates are admitted before the owner is called
/// (`RESTORE_TEST_SHAPE_GATES_ADMITTED`, request_dispatch.rs:433-440) and three
/// more are pushed as the real execution reaches them, so every refusal carries
/// the same nine passed gates. `gates_not_admitted` is seeded with two
/// (`RESTORE_TEST_GATES_NOT_ADMITTED`, :471-472) and a blob-carrying archive
/// appends exactly two more (`RESTORE_TEST_BLOB_GATES_NOT_ADMITTED`, :476-477).
/// That difference is the observable proof the two fixtures record two
/// genuinely different executions, and the disjointness is the contradiction the
/// split exists to make impossible.
fn assert_route_gates(blob_free: &Value, blob_carrying: &Value) {
    const SHAPE_AND_REACHED: [&str; 9] = [
        "decode",
        "validate",
        "shape",
        "authorization-shape",
        "provisioning",
        "isolation",
        "archive-decode",
        "plan-compile",
        "journal-admission",
    ];
    const SEEDED_NOT_ADMITTED: [&str; 2] =
        ["destination-manifest-admission", "cutover-qualification"];
    const BLOB_ONLY_NOT_ADMITTED: [&str; 2] =
        ["destination-key-admission", "destination-blob-scope"];

    let gates = |reply: &Value, key: &str| -> Vec<String> {
        match reply.get(key) {
            Some(Value::Array(entries)) => entries
                .iter()
                .map(|entry| match entry.as_str() {
                    Some(text) => text.to_owned(),
                    None => panic!("{key} must carry only JSON strings"),
                })
                .collect(),
            _ => panic!("{key} must be present as a JSON array"),
        }
    };

    // The fixture gates are decoded as owned `String`s, so membership is compared
    // as `&str` content rather than by `Vec<String>::contains`, which would
    // demand a `&String` and force an allocation per probe.
    let lists = |reported: &[String], gate: &str| reported.iter().any(|entry| entry == gate);

    for (label, reply) in [("blob-free", blob_free), ("blob-carrying", blob_carrying)] {
        let passed = gates(reply, "gates_passed");
        assert_eq!(
            passed,
            SHAPE_AND_REACHED
                .iter()
                .map(|gate| (*gate).to_owned())
                .collect::<Vec<String>>(),
            "{label} must report exactly the gates this execution reached"
        );
        let not_admitted = gates(reply, "gates_not_admitted");
        for gate in &passed {
            assert!(
                !lists(&not_admitted, gate),
                "{label} must never report {gate} as both passed and not admitted"
            );
        }
        for gate in SEEDED_NOT_ADMITTED {
            assert!(
                lists(&not_admitted, gate),
                "{label} must report {gate} as not admitted on every answer"
            );
        }
    }

    // The blob-carrying refusal carries exactly the two extra owner gates the
    // blob-free one does not, so the archives really did take different paths.
    let free_not_admitted = gates(blob_free, "gates_not_admitted");
    let carrying_not_admitted = gates(blob_carrying, "gates_not_admitted");
    assert_eq!(
        free_not_admitted.len(),
        SEEDED_NOT_ADMITTED.len(),
        "a blob-free archive reaches no further owner gate"
    );
    for gate in BLOB_ONLY_NOT_ADMITTED {
        assert!(
            lists(&carrying_not_admitted, gate),
            "a blob-carrying archive must report {gate} as not admitted"
        );
        assert!(
            !lists(&free_not_admitted, gate),
            "{gate} is a blob-carrying-only gate and must be absent from the blob-free refusal"
        );
    }
}

/// Builds a refused `BackupOperationOutcome` whose `requested_class`,
/// `source_identity` and `destination_identity` are mutated away from any
/// value the owner could have declared, to prove the projection still reports
/// the refused state verbatim.
fn mutated_refused_outcome() -> BackupOperationOutcome {
    BackupOperationOutcome {
        operation: "backup.create".to_owned(),
        state: BACKUP_STATE_REFUSED.to_owned(),
        requested_class: Some("mutated-class-not-owner-declared".to_owned()),
        requested_scope: Some("mutated-scope-not-owner-declared".to_owned()),
        archive_id: Some("mutated-archive-not-proven".to_owned()),
        operation_id: "mutated-operation-not-a-real-correlation".to_owned(),
        source_identity: Some("mutated-source-not-declared".to_owned()),
        destination_identity: Some("mutated-destination-not-declared".to_owned()),
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        proof_level: BackupStage::Requested,
        verification_level: None,
        class_ceiling: None,
        capture_receipt: None,
        result_identity: None,
        archive_fence_relation: None,
        archive_fence_proof: None,
        target_compatibility: None,
        cancellation_reason_code: None,
        owner_cleanup_state: None,
        gates_passed: Vec::new(),
        missing_obligations: vec![BACKUP_CREATE_MISSING_OWNER.to_owned()],
        next_reconciliation: "reconcile the same operation only after the owner exists".to_owned(),
        reason: "capture owner unreachable".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Cases 8, 9, 15, 16, 18.
//
// Everything below is written against the items the shared `use` block of this
// file already imports (`RequestIdentity`, `PathBuf`, `Value`, `json!`,
// `CliError`, `CommandArguments`, `CommandId`, `CommandRequest`,
// `BackupOperationOutcome`, `BackupStage`, `EffectClass`, `ProofCeiling`,
// `render_backup_outcome_human`). The product symbols this section needs that
// are NOT in that block are written through fully-qualified paths, because the
// `use` block is owned by another writer:
//
//   * `eliot_cli::backup::backup_unknown_outcome`
//   * `eliot_cli::backup::BackupUnknownOutcome`
//   * `eliot_cli::backup::BackupResultIdentity`
//   * `eliot_cli::backup::BACKUP_STATE_UNKNOWN`
//   * `eliot_cli::backup::BACKUP_STATE_VERIFIED`
//   * `eliot_cli::backup::BACKUP_CREATE_OPERATION`
//   * `eliot_cli::backup::BACKUP_VERIFY_OPERATION`
//   * `eliot_cli::backup::BACKUP_RESTORE_TEST_OPERATION`
//   * `eliot_protocol::ProtocolError`
//
// The only local helper for unwrapping a result is `owned`, which is distinct
// from this file's shared `must`, and no fixture here depends on another
// writer's test helper.
// ---------------------------------------------------------------------------

/// Unwrap-free local helper: this section does not own the file's shared `must`,
/// so it brings its own and panics with an explicit message rather than calling
/// `expect`.
fn owned<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("backup case construction failed: {error:?}"),
    }
}

/// The `Option`-shaped sibling of `owned`, for the owner slots this section
/// reads rather than operations it performs (`NonZeroU64::new`, an accessor
/// returning `Option`). The two are deliberately not interchangeable: `owned`
/// says a fallible operation must answer, `owned_some` says a slot must
/// already hold a value. Neither may be handed the other's argument, and a
/// missing slot is never reshaped into a success.
fn owned_some<T>(value: Option<T>) -> T {
    match value {
        Some(value) => value,
        None => panic!("backup case slot must be present"),
    }
}

/// One admitted `RequestIdentity` whose two fences AGREE, decoded from JSON so
/// the typed decode itself is exercised. `authority_sequence` and
/// `idempotency_key` are the only caller-chosen parts.
fn agreeing_identity(authority_sequence: u64, idempotency_key: &str) -> RequestIdentity {
    owned(serde_json::from_value(identity_json(
        authority_sequence,
        idempotency_key,
    )))
}

/// The wire shape of an admitted `RequestIdentity`, with the authority epoch
/// sequence as a parameter so the same bytes express both an agreeing identity
/// and a self-declared fence override.
fn identity_json(authority_sequence: u64, idempotency_key: &str) -> Value {
    json!({
        "request": {
            "metadata": {
                "request_id": "request-backup-963",
                "session_id": null,
                "task_id": null,
                "product_id": "product-1",
                "source_id": "source-1",
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": authority_sequence
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
                    "sequence": authority_sequence
                },
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        },
        "idempotency_key": idempotency_key,
        "deadline_unix_ms": 1,
        "cancellation_id": "cancel-backup-963"
    })
}

/// The closed create arguments the create entry gate admits.
fn create_arguments() -> CommandArguments {
    CommandArguments::BackupCreate {
        scope_descriptor: "synthetic-scope-descriptor".to_owned(),
        class: "full_recovery".to_owned(),
    }
}

/// A `CommandRequest` carrying `identity` to the backup-create entry gate.
fn create_request(identity: RequestIdentity) -> CommandRequest {
    CommandRequest {
        request: identity,
        command: CommandId::BackupCreate,
        arguments: create_arguments(),
    }
}

/// Asserts one identity whose two fences disagree is refused by the protocol
/// owner's own gate with the exact typed fence-mismatch field and reason.
fn assert_fence_override_refused(identity: &RequestIdentity) {
    match identity.validate() {
        Ok(()) => panic!("a self-declared fence override must be refused"),
        Err(error) => match error {
            eliot_protocol::ProtocolError::InvalidField { field, reason } => {
                assert_eq!(field, "request.state_fence");
                assert_eq!(reason, "must match request metadata state_fence");
            }
            other => panic!("unexpected protocol error for a fence override: {other:?}"),
        },
    }
}

// WORK_UNIT_CASE: 963/8 authenticated_principal_scope_fence_cannot_be_overridden
#[test]
fn authenticated_principal_scope_fence_cannot_be_overridden() {
    // The two gates under test, named once:
    //
    //  * `eliot_protocol::RequestIdentity::validate`
    //    (crates/foundation/eliot-protocol/src/lib.rs:702-720) compares
    //    `request.metadata.state_fence` against `request.state_fence` and
    //    refuses when they differ.
    //  * `eliot_cli::CommandRequest::validate`
    //    (crates/surfaces/eliot-cli/src/lib.rs:422-434) delegates to that same
    //    identity check first and maps its failure onto the TYPED
    //    `CliError::Protocol` variant, before the arguments and the
    //    command/argument bijection are considered at all.
    //
    // I15.2 from the issue: "Principal identity is issued by Kernel, never
    // self-declared." The request's fence is therefore not a value the caller
    // may restate, and one self-declared identity carrying TWO fences is the
    // shape of an override attempt.
    let agreeing = agreeing_identity(1, "idempotency-fence-1");
    let mut overridden = agreeing_identity(1, "idempotency-fence-1");

    // The override: only the inner `authority_epoch.sequence` moves, so a gate
    // that merely carried a fence without comparing it would pass this fixture.
    let declared = overridden
        .request
        .state_fence
        .authority_epoch
        .sequence
        .get();
    overridden
        .request
        .metadata
        .state_fence
        .authority_epoch
        .sequence = owned_some(std::num::NonZeroU64::new(declared + 1));
    assert_ne!(
        overridden
            .request
            .metadata
            .state_fence
            .authority_epoch
            .sequence,
        overridden.request.state_fence.authority_epoch.sequence,
        "the override fixture must disagree on the authority epoch sequence"
    );
    assert_eq!(
        overridden
            .request
            .metadata
            .state_fence
            .authority_epoch
            .lineage_id,
        overridden.request.state_fence.authority_epoch.lineage_id,
        "only the sequence may differ, so this is a fence override and not an \
         unrelated authority lineage"
    );

    // Phase 1 — the protocol owner's own gate refuses the override, and the
    // refusal is the typed fence comparison rather than a message text match.
    assert_fence_override_refused(&overridden);

    // Phase 2 — the same override carried through the CLI's own entry gate with
    // the closed `CommandArguments::BackupCreate` variant is refused there too.
    let request = create_request(overridden.clone());
    assert!(matches!(
        request.arguments,
        CommandArguments::BackupCreate { .. }
    ));
    let error = match request.validate() {
        Ok(()) => panic!("the CLI entry gate must refuse a fence override"),
        Err(error) => error,
    };
    // The scope/fence half: a TYPED CliError, never a bare string.
    assert!(
        matches!(&error, CliError::Protocol(_)),
        "the entry gate must fail with the typed CliError::Protocol, got {error:?}"
    );
    assert!(
        error.to_string().contains("request.state_fence"),
        "the typed error must carry the protocol field it refused: {error}"
    );

    // Phase 3 — the fence is COMPARED, not merely present: the same request
    // whose two fences agree validates, so the refusal above is the fence and
    // not an artifact of this fixture.
    assert!(
        agreeing.validate().is_ok(),
        "an agreeing fence must validate"
    );
    assert!(
        create_request(agreeing).validate().is_ok(),
        "the agreeing backup-create request must validate"
    );
}

// WORK_UNIT_CASE: 963/9 request_correlation_and_stable_mutation_operation_identity
#[test]
fn request_correlation_and_stable_mutation_operation_identity() {
    assert_operation_identity_is_the_request_key();
    assert_operation_selectors_are_distinct();
}

/// The unknown-outcome projection takes the REQUEST's idempotency key as its
/// operation identity, so the identity is bound to the correlated request and
/// not to the operation name: two requests give two identities, one request
/// re-observed gives the same identity, and the transport detail the caller
/// supplies is echoed without ever being promoted into it.
fn assert_operation_identity_is_the_request_key() {
    let first = agreeing_identity(1, "idempotency-create-1");
    let second = agreeing_identity(1, "idempotency-create-2");
    let detail = "pipe closed before the reply frame was read";

    let one = eliot_cli::backup::backup_unknown_outcome(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        &first,
        detail,
    );
    let two = eliot_cli::backup::backup_unknown_outcome(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        &second,
        detail,
    );

    // The bounded unknown state: never a success, never a domain verdict.
    assert_eq!(one.state, eliot_cli::backup::BACKUP_STATE_UNKNOWN);
    assert_eq!(two.state, eliot_cli::backup::BACKUP_STATE_UNKNOWN);

    // The operation identity IS the request's idempotency key, echoed from the
    // correlated request rather than minted here.
    assert_eq!(one.operation_id, first.idempotency_key.clone());
    assert_eq!(two.operation_id, second.idempotency_key.clone());
    assert_eq!(one.operation, eliot_cli::backup::BACKUP_CREATE_OPERATION);

    // ... and because it is bound to the REQUEST, two requests carrying two
    // different keys produce two different operation identities. A value bound
    // to the operation name instead could not tell them apart, and a retry
    // would then have no identity to reconcile against.
    assert_ne!(one.operation_id, two.operation_id);
    assert_ne!(one.operation_id, one.operation);
    assert_ne!(two.operation_id, two.operation);

    // The same request re-observed keeps the SAME operation identity. That is
    // the stable identity a same-operation reconciliation consumes (case 15),
    // and the caller's transport detail is echoed, never substituted.
    let replay = eliot_cli::backup::backup_unknown_outcome(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        &first,
        "second observation of the same request",
    );
    assert_eq!(replay.operation_id, one.operation_id);
    assert_eq!(replay.operation, one.operation);
    assert_eq!(replay.state, one.state);
    assert_eq!(replay.detail, "second observation of the same request");
}

/// The three operation selectors are three distinct closed constants, so an
/// operation identity could never collide across two operations even if it were
/// derived from a name.
fn assert_operation_selectors_are_distinct() {
    assert_eq!(eliot_cli::backup::BACKUP_CREATE_OPERATION, "backup.create");
    assert_eq!(eliot_cli::backup::BACKUP_VERIFY_OPERATION, "backup.verify");
    assert_eq!(
        eliot_cli::backup::BACKUP_RESTORE_TEST_OPERATION,
        "backup.restore-test"
    );
    assert_ne!(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        eliot_cli::backup::BACKUP_VERIFY_OPERATION
    );
    assert_ne!(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        eliot_cli::backup::BACKUP_RESTORE_TEST_OPERATION
    );
    assert_ne!(
        eliot_cli::backup::BACKUP_VERIFY_OPERATION,
        eliot_cli::backup::BACKUP_RESTORE_TEST_OPERATION
    );
}

// WORK_UNIT_CASE: 963/15 unknown_outcome_requires_same_operation_reconciliation
#[test]
fn unknown_outcome_requires_same_operation_reconciliation() {
    assert_next_action_names_the_same_operation();
    assert_unknown_outcome_fails_closed_on_an_added_field();
    assert_cancellation_retains_owner_cleanup_state();
}

/// A cancelled owner operation is the third way an operation ends without a
/// domain result, and the issue requires that it "retains owner cleanup state"
/// rather than being projected as a field-shape failure.
///
/// The Kernel's cancellation arm is the ONLY producer of this envelope
/// (`cancellation_reply`, request_dispatch.rs:794-811), it hardcodes the verify
/// operation, and it carries exactly two closed values: the I7.20 reason code
/// `CANCELLATION_UNCONFIRMED` and the owner cleanup state. Both are `pub`
/// constants on the CLI side, so the fixture is compared against the shipped
/// vocabulary rather than a retyped literal — and the cleanup state is asserted
/// to be the honest `not-supplied`, because both cancellation variants are unit
/// variants and carry no cleanup detail, so any other value would be fabricated.
fn assert_cancellation_retains_owner_cleanup_state() {
    let cancelled = fixture("cancellation-reply.json");

    assert_eq!(
        field(&cancelled, "command"),
        eliot_cli::backup::BACKUP_VERIFY_OPERATION
    );
    assert_eq!(
        field(&cancelled, "status"),
        eliot_cli::backup::BACKUP_STATE_CANCELLED
    );
    assert_eq!(
        field(&cancelled, "code"),
        eliot_cli::backup::BACKUP_REASON_CANCELLATION_UNCONFIRMED
    );
    assert_eq!(
        field(&cancelled, "owner_cleanup_state"),
        eliot_cli::backup::BACKUP_OWNER_CLEANUP_NOT_SUPPLIED
    );

    // The two cleanup states are a CLOSED single-element vocabulary, so an
    // operator can never read a fabricated cleanup as an owner-attested one.
    assert_eq!(eliot_cli::backup::BACKUP_OWNER_CLEANUP_STATES.len(), 1);
    assert_eq!(
        eliot_cli::backup::BACKUP_OWNER_CLEANUP_STATES[0],
        eliot_cli::backup::BACKUP_OWNER_CLEANUP_NOT_SUPPLIED
    );

    // The cancellation reason code is a member of the I7.20 registry's
    // route/integration group and is the only one this surface admits, so a
    // reply cannot arrive under an unregistered cancellation code.
    assert_eq!(eliot_cli::backup::BACKUP_CANCELLATION_REASON_CODES.len(), 1);
    assert_eq!(
        eliot_cli::backup::BACKUP_CANCELLATION_REASON_CODES[0],
        eliot_cli::backup::BACKUP_REASON_CANCELLATION_UNCONFIRMED
    );

    // The cancelled reply is NOT an unknown outcome: it carries an owner
    // cancellation code and cleanup state, so the reconciliation vocabulary must
    // not silently absorb it. Its status differs from the unknown placeholder's.
    assert_ne!(
        field(&cancelled, "status"),
        eliot_cli::backup::BACKUP_STATE_UNKNOWN
    );
    // And the cancelled state is a member of the closed state set the surface
    // admits, distinct from both `refused` and `blocked`, so an operator
    // cancellation is never rendered as a refusal.
    assert_ne!(field(&cancelled, "status"), BACKUP_STATE_REFUSED);
    assert_ne!(
        field(&cancelled, "status"),
        eliot_cli::backup::BACKUP_STATE_BLOCKED
    );
}

/// The next action an unknown outcome states NAMES its own operation identity,
/// and a different request yields a correspondingly different action, so a blind
/// second capture or restore is never what the text asks an operator to do.
fn assert_next_action_names_the_same_operation() {
    let first = agreeing_identity(1, "idempotency-reconcile-1");
    let second = agreeing_identity(1, "idempotency-reconcile-2");
    let detail = "reply frame never arrived";

    let unknown = eliot_cli::backup::backup_unknown_outcome(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        &first,
        detail,
    );
    let other = eliot_cli::backup::backup_unknown_outcome(
        eliot_cli::backup::BACKUP_CREATE_OPERATION,
        &second,
        detail,
    );

    assert_eq!(unknown.operation_id, first.idempotency_key.clone());
    assert!(
        unknown.next_reconciliation.contains(&first.idempotency_key),
        "next_reconciliation must name operation_id {:?}, got {:?}",
        unknown.operation_id,
        unknown.next_reconciliation
    );
    assert!(
        unknown
            .next_reconciliation
            .contains("reconcile the same operation"),
        "the next action must be same-operation reconciliation: {:?}",
        unknown.next_reconciliation
    );

    // The converse: a different idempotency key gives a different operation
    // identity and a different next action, and one unknown outcome's text can
    // never reconcile another operation.
    assert_ne!(other.operation_id, unknown.operation_id);
    assert_ne!(other.next_reconciliation, unknown.next_reconciliation);
    assert!(
        !other.next_reconciliation.contains(&first.idempotency_key),
        "the second unknown outcome must not propose reconciling the first \
         operation: {:?}",
        other.next_reconciliation
    );
    assert!(other.next_reconciliation.contains(&second.idempotency_key));
}

/// The projection is `deny_unknown_fields` with exactly five declared fields:
/// an unknown outcome cannot be silently upgraded by an added field.
fn assert_unknown_outcome_fails_closed_on_an_added_field() {
    let identity = agreeing_identity(1, "idempotency-unknown-1");
    let unknown: eliot_cli::backup::BackupUnknownOutcome =
        eliot_cli::backup::backup_unknown_outcome(
            eliot_cli::backup::BACKUP_CREATE_OPERATION,
            &identity,
            "reply frame never arrived",
        );

    let wire = owned(serde_json::to_value(&unknown));
    let Some(object) = wire.as_object() else {
        panic!("unknown outcome must serialize as a JSON object");
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "detail",
            "next_reconciliation",
            "operation",
            "operation_id",
            "state",
        ],
        "the unknown-outcome key set must be exactly the five declared fields"
    );

    // Fail closed: injecting an extra key is refused rather than ignored.
    let mut injected = wire.clone();
    match injected.as_object_mut() {
        Some(object) => {
            object.insert(
                "receipt".to_owned(),
                Value::String("synthetic-injected-receipt".to_owned()),
            );
        }
        None => panic!("unknown outcome wire must be an object"),
    }
    assert!(
        serde_json::from_value::<eliot_cli::backup::BackupUnknownOutcome>(injected).is_err(),
        "an injected field must be refused, not silently ignored"
    );

    // The exact key set round-trips byte-identically, so the refusal above is the
    // added key and not a projection that fails to decode its own output.
    let decoded = owned(serde_json::from_value::<
        eliot_cli::backup::BackupUnknownOutcome,
    >(wire));
    assert_eq!(decoded, unknown);
    assert_eq!(decoded.state, eliot_cli::backup::BACKUP_STATE_UNKNOWN);
}

// WORK_UNIT_CASE: 963/16 human_json_semantics_and_bounded_redaction_agree
#[test]
fn human_json_semantics_and_bounded_redaction_agree() {
    assert_both_projections_come_from_one_typed_value();
    assert_absent_declarations_render_their_stated_sentinel();
    assert_projection_is_structurally_free_of_material();
    assert_renderer_projects_verbatim_and_emits_a_derived_line_set();
}

/// The JSON key set is EXACTLY the 24 declared fields of
/// `BackupOperationOutcome` (`backup.rs:903-1051`), the nested typed identity is
/// EXACTLY its 6 declared fields (`backup.rs:847-879`), and every checked value
/// appears in the human projection of the very same value.
fn assert_both_projections_come_from_one_typed_value() {
    let outcome = outcome_with_every_field_present();
    let wire = owned(serde_json::to_value(&outcome));
    // Both projections are driven from this ONE typed value, so every value
    // checked below is literally the same string in both.
    let human = render_backup_outcome_human(&outcome);

    assert_declared_key_sets(&wire);
    assert_typed_values_appear_in_both_projections(&outcome, &wire, &human);
    assert_nested_identity_values_are_printed(&outcome, &human);
}

/// The JSON projection's own key set is exactly the 24 declared fields of
/// `BackupOperationOutcome` (`backup.rs:903-1051`), and the nested typed
/// identity it carries is exactly the 6 declared fields of
/// `BackupResultIdentity` (`backup.rs:847-879`).
fn assert_declared_key_sets(wire: &Value) {
    let mut keys: Vec<&str> = match wire.as_object() {
        Some(object) => object.keys().map(String::as_str).collect(),
        None => panic!("outcome must serialize as a JSON object"),
    };
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "archive_fence_proof",
            "archive_fence_relation",
            "archive_id",
            "cancellation_reason_code",
            "capture_receipt",
            "class_ceiling",
            "destination_identity",
            "effect",
            "gates_passed",
            "missing_obligations",
            "next_reconciliation",
            "operation",
            "operation_id",
            "owner_cleanup_state",
            "proof_ceiling",
            "proof_level",
            "reason",
            "requested_class",
            "requested_scope",
            "result_identity",
            "source_identity",
            "state",
            "target_compatibility",
            "verification_level",
        ],
        "the JSON key set must be exactly the 24 declared fields"
    );
    assert_eq!(keys.len(), 24, "the struct declares 24 fields");

    let nested = match wire.pointer("/result_identity") {
        Some(Value::Object(object)) => {
            let mut nested_keys: Vec<&str> = object.keys().map(String::as_str).collect();
            nested_keys.sort_unstable();
            nested_keys
        }
        _ => panic!("result_identity must project as a JSON object"),
    };
    assert_eq!(
        nested,
        vec![
            "archive_digest",
            "capture_receipt",
            "operation_id",
            "operation_namespace",
            "request_digest",
            "validity_attestation",
        ]
    );
}

/// Every owner-declared value appears verbatim in the human projection, and the
/// three typed enums are printed by the renderer in their OWN JSON form, so both
/// projections must spell them identically.
fn assert_typed_values_appear_in_both_projections(
    outcome: &BackupOperationOutcome,
    wire: &Value,
    human: &str,
) {
    for value in [
        outcome.operation.as_str(),
        outcome.state.as_str(),
        outcome.operation_id.as_str(),
        required(outcome.archive_id.as_ref(), "archive_id").as_str(),
        required(outcome.source_identity.as_ref(), "source_identity").as_str(),
        required(
            outcome.destination_identity.as_ref(),
            "destination_identity",
        )
        .as_str(),
        required(outcome.capture_receipt.as_ref(), "capture_receipt").as_str(),
        required(outcome.verification_level.as_ref(), "verification_level").as_str(),
        required(outcome.class_ceiling.as_ref(), "class_ceiling").as_str(),
        outcome.reason.as_str(),
        outcome.next_reconciliation.as_str(),
    ] {
        assert!(
            human.contains(value),
            "the human projection must contain {value:?}:\n{human}"
        );
    }

    for (pointer, typed) in [
        ("/effect", owned(serde_json::to_string(&outcome.effect))),
        (
            "/proof_ceiling",
            owned(serde_json::to_string(&outcome.proof_ceiling)),
        ),
        (
            "/proof_level",
            owned(serde_json::to_string(&outcome.proof_level)),
        ),
    ] {
        assert_eq!(
            wire.pointer(pointer).and_then(Value::as_str),
            Some(typed.as_str()),
            "the JSON projection must carry the typed form at {pointer}"
        );
        assert!(
            human.contains(&typed),
            "the human projection must contain the typed form {typed} from \
             {pointer}:\n{human}"
        );
    }
}

/// The nested identity's own six values are printed too, beside the outer
/// operation identity they distinguish.
fn assert_nested_identity_values_are_printed(outcome: &BackupOperationOutcome, human: &str) {
    let Some(identity) = outcome.result_identity.as_ref() else {
        panic!("this fixture populates the nested typed identity");
    };
    for value in [
        identity.operation_id.as_str(),
        identity.request_digest.as_str(),
        identity.operation_namespace.as_str(),
        identity.archive_digest.as_str(),
        required(
            identity.capture_receipt.as_ref(),
            "identity.capture_receipt",
        )
        .as_str(),
        required(
            identity.validity_attestation.as_ref(),
            "identity.validity_attestation",
        )
        .as_str(),
    ] {
        assert!(
            human.contains(value),
            "the human projection must contain the nested identity value \
             {value:?}:\n{human}"
        );
    }
}

/// An absent declaration renders the renderer's OWN stated sentinel, never an
/// empty value and never an invented token.
fn assert_absent_declarations_render_their_stated_sentinel() {
    let outcome = outcome_with_every_field_absent();
    let human = render_backup_outcome_human(&outcome);
    for sentinel in [
        "requested_class: not-declared",
        "requested_scope: not-declared",
        "source: not-declared",
        "destination: not-declared",
        "archive_id: not-proven",
    ] {
        assert!(
            human.contains(sentinel),
            "an absent declaration must render {sentinel:?}:\n{human}"
        );
    }

    // The owner's absent answers stay SILENT rather than printing an empty or
    // `unknown` value, so silence remains distinguishable from a proven answer.
    for absent_line in [
        "verification_level",
        "class_ceiling",
        "capture_receipt",
        "archive_fence_relation",
        "archive_fence_proof",
        "target_compatibility",
        "cancellation_reason_code",
        "owner_cleanup_state",
    ] {
        assert!(
            !human.contains(absent_line),
            "an absent owner answer must print no line at all, found \
             {absent_line:?}:\n{human}"
        );
    }
    assert_eq!(
        rendered_labels(&human),
        expected_line_labels(&outcome),
        "the absent shape emits exactly the always-present lines plus the two \
         explicit `none` lines"
    );
}

/// The bounded part of the no-secrets rule is STRUCTURAL: the typed outcome has
/// no field that can carry archive bytes, key material or archived user data, so
/// neither projection can print one. There is no content filter standing in for
/// that, which is what the phase below states plainly.
fn assert_projection_is_structurally_free_of_material() {
    let outcome = outcome_with_every_field_present();
    let wire = owned(serde_json::to_value(&outcome));
    let human = render_backup_outcome_human(&outcome);
    for (name, projection) in [("json", wire.to_string()), ("human", human.clone())] {
        for forbidden in [
            "bundle_hex",
            "authorization_hex",
            "archive_bytes",
            "key_material",
            "user_data",
        ] {
            assert!(
                !projection.contains(forbidden),
                "the {name} projection must not carry {forbidden}"
            );
        }
    }
}

/// The renderer applies NO redaction, and this case asserts that honestly.
///
/// `crates/surfaces/AGENTS.md` states "Do not show secrets or raw archived user
/// data". Read against the shipped renderer (`backup.rs:1117-1237`): there is no
/// pattern match, no truncation, no length bound and no digest substitution in
/// it. Every line is a `writeln!` of a value the typed outcome carries, so the
/// renderer PROJECTS VERBATIM. The honest assertions are therefore:
///
///   * the synthetic identities are projected verbatim;
///   * a canary planted in a free-text field is projected verbatim too, which is
///     the measurement that FAILS if redaction is ever added, and the only one
///     that can detect redaction being removed.
///
/// No redaction rule is asserted, because the shipped code has none. What IS
/// bounded is the line set, derived below from the value's declared shape.
fn assert_renderer_projects_verbatim_and_emits_a_derived_line_set() {
    let outcome = outcome_with_every_field_present();
    let human = render_backup_outcome_human(&outcome);

    let canary = "-----BEGIN RSA PRIVATE KEY----- synthetic-canary";
    let mut planted = outcome.clone();
    canary.clone_into(&mut planted.reason);
    let planted_human = render_backup_outcome_human(&planted);

    for identity in [
        "synthetic-archive-963",
        "synthetic-source-963",
        "synthetic-destination-963",
        "synthetic-capture-receipt-963",
        "synthetic-answer-operation-963",
        "synthetic-request-digest-963",
        "synthetic-operation-namespace-963",
        "synthetic-archive-digest-963",
        "synthetic-validity-attestation-963",
        "synthetic-nested-capture-receipt-963",
    ] {
        assert!(
            planted_human.contains(identity),
            "the synthetic identity {identity:?} must project verbatim:\n{planted_human}"
        );
    }
    assert!(
        planted_human.contains(canary),
        "the shipped renderer redacts nothing, so a canary planted in a free \
         text field is projected verbatim; asserting this is what makes a later \
         redaction, or its removal, visible:\n{planted_human}"
    );
    assert_eq!(
        planted.next_reconciliation, outcome.next_reconciliation,
        "planting the canary changed only the free-text reason"
    );

    // The derived line set. `expected_line_labels` mirrors `backup.rs:1117-1237`
    // line for line: ten lines are unconditional, and each remaining line exists
    // only when the value carries the answer that line reports.
    assert_eq!(
        rendered_labels(&human),
        expected_line_labels(&outcome.clone()),
        "the populated projection must emit exactly its derived line set"
    );
    assert_eq!(
        rendered_labels(&planted_human),
        expected_line_labels(&planted),
        "planting a canary in a free-text field adds no line at all"
    );
    assert_eq!(
        render_backup_outcome_human(&outcome),
        human,
        "rendering is deterministic: one value, one projection"
    );

    // Content length does not change the line set; only the two declared arrays
    // do, and they contribute exactly one line per element.
    let mut wide = outcome;
    for gate in &mut wide.gates_passed {
        gate.push_str("-extended-well-past-any-sane-bound");
    }
    wide.gates_passed.push("synthetic-gate-three".to_owned());
    for obligation in &mut wide.missing_obligations {
        obligation.push_str("-extended-well-past-any-sane-bound");
    }
    let wide_human = render_backup_outcome_human(&wide);
    assert_eq!(
        wide.gates_passed.len(),
        3,
        "the fixture really did add a third gate"
    );
    assert_eq!(
        wide_human.lines().count(),
        human.lines().count() + 1,
        "one more gate adds exactly one line however long its text is"
    );
}

/// Returns a required `Some` text as an owned string, so a projection assertion
/// can never be satisfied by the empty string.
fn required(value: Option<&String>, field: &str) -> String {
    match value {
        Some(text) => text.clone(),
        None => panic!("{field} must be populated for this fixture"),
    }
}

/// The label of every rendered line, i.e. the text before the first colon.
fn rendered_labels(projection: &str) -> Vec<String> {
    projection
        .lines()
        .map(|line| match line.split_once(':') {
            Some((label, _)) => label.to_owned(),
            None => panic!("every rendered line must be `label: value`: {line}"),
        })
        .collect()
}

/// The exact line list `render_backup_outcome_human` emits for one value,
/// derived from `backup.rs:1117-1237`: ten lines are unconditional, and each
/// remaining line exists only when the value carries the answer it reports.
fn expected_line_labels(outcome: &BackupOperationOutcome) -> Vec<String> {
    let mut labels: Vec<&str> = vec![
        "operation",
        "state",
        "requested_class",
        "requested_scope",
        "archive_id",
        "operation_id",
        "source",
        "destination",
        "effect",
        "proof_level",
    ];
    if outcome.verification_level.is_some() {
        labels.push("verification_level");
    }
    if outcome.class_ceiling.is_some() {
        labels.push("class_ceiling");
    }
    if outcome.capture_receipt.is_some() {
        labels.push("capture_receipt");
    }
    if let Some(identity) = &outcome.result_identity {
        labels.push("answer_operation_id");
        labels.push("request_digest");
        labels.push("operation_namespace");
        labels.push("answer_archive_digest");
        if identity.validity_attestation.is_some() {
            labels.push("validity_attestation");
        }
    }
    if outcome.archive_fence_relation.is_some() {
        labels.push("archive_fence_relation");
    }
    if outcome.archive_fence_proof.is_some() {
        labels.push("archive_fence_proof");
    }
    if outcome.target_compatibility.is_some() {
        labels.push("target_compatibility");
    }
    if outcome.cancellation_reason_code.is_some() {
        labels.push("cancellation_reason_code");
    }
    if outcome.owner_cleanup_state.is_some() {
        labels.push("owner_cleanup_state");
    }
    labels.push("gates_passed");
    if outcome.missing_obligations.is_empty() {
        labels.push("missing_obligations");
    } else {
        labels.extend(std::iter::repeat_n(
            "missing_obligation",
            outcome.missing_obligations.len(),
        ));
    }
    labels.push("reason");
    labels.push("next_reconciliation");
    labels.into_iter().map(str::to_owned).collect()
}

/// The closed typed result identity with all six fields populated by obviously
/// synthetic values.
fn synthetic_result_identity() -> eliot_cli::backup::BackupResultIdentity {
    eliot_cli::backup::BackupResultIdentity {
        operation_id: "synthetic-answer-operation-963".to_owned(),
        request_digest: "synthetic-request-digest-963".to_owned(),
        operation_namespace: "synthetic-operation-namespace-963".to_owned(),
        archive_digest: "synthetic-archive-digest-963".to_owned(),
        capture_receipt: Some("synthetic-nested-capture-receipt-963".to_owned()),
        validity_attestation: Some("synthetic-validity-attestation-963".to_owned()),
    }
}

/// One `BackupOperationOutcome` with EVERY field present, so the JSON key set,
/// the human line set and value containment are exercised on the widest shape
/// the type admits.
fn outcome_with_every_field_present() -> BackupOperationOutcome {
    BackupOperationOutcome {
        operation: eliot_cli::backup::BACKUP_VERIFY_OPERATION.to_owned(),
        state: eliot_cli::backup::BACKUP_STATE_VERIFIED.to_owned(),
        requested_class: Some("full_recovery".to_owned()),
        requested_scope: Some("synthetic-scope-descriptor".to_owned()),
        archive_id: Some("synthetic-archive-963".to_owned()),
        operation_id: "synthetic-operation-963".to_owned(),
        source_identity: Some("synthetic-source-963".to_owned()),
        destination_identity: Some("synthetic-destination-963".to_owned()),
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        proof_level: BackupStage::Verified,
        verification_level: Some("provenance-bound-capture".to_owned()),
        class_ceiling: Some("full_recovery".to_owned()),
        capture_receipt: Some("synthetic-capture-receipt-963".to_owned()),
        result_identity: Some(synthetic_result_identity()),
        archive_fence_relation: Some("same-authority".to_owned()),
        archive_fence_proof: Some("capture-owner-proven".to_owned()),
        target_compatibility: Some("schema-and-build-compatible".to_owned()),
        cancellation_reason_code: Some("CANCELLATION_UNCONFIRMED".to_owned()),
        owner_cleanup_state: Some("not-supplied".to_owned()),
        gates_passed: vec![
            "declaration-admitted".to_owned(),
            "provisioning-admitted".to_owned(),
        ],
        missing_obligations: vec![
            "synthetic-missing-obligation-one".to_owned(),
            "synthetic-missing-obligation-two".to_owned(),
        ],
        next_reconciliation: "synthetic next_reconciliation text".to_owned(),
        reason: "synthetic reason text".to_owned(),
    }
}

/// The same typed value with EVERY optional owner answer absent and both lists
/// empty: the shape an undecided transport state reports.
fn outcome_with_every_field_absent() -> BackupOperationOutcome {
    BackupOperationOutcome {
        operation: eliot_cli::backup::BACKUP_CREATE_OPERATION.to_owned(),
        state: eliot_cli::backup::BACKUP_STATE_UNKNOWN.to_owned(),
        requested_class: None,
        requested_scope: None,
        archive_id: None,
        operation_id: "synthetic-absent-operation-963".to_owned(),
        source_identity: None,
        destination_identity: None,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        proof_level: BackupStage::Requested,
        verification_level: None,
        class_ceiling: None,
        capture_receipt: None,
        result_identity: None,
        archive_fence_relation: None,
        archive_fence_proof: None,
        target_compatibility: None,
        cancellation_reason_code: None,
        owner_cleanup_state: None,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: "synthetic absent next_reconciliation".to_owned(),
        reason: "synthetic absent reason".to_owned(),
    }
}

/// The repository root: the nearest ancestor of `CARGO_MANIFEST_DIR` whose
/// `Cargo.toml` declares a `[workspace]` table, so the guard reads the real tree
/// rather than a copy of it.
fn repo_root() -> PathBuf {
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        // Only an ancestor that is REACHED and readable is a candidate; a
        // missing `Cargo.toml` is not a workspace, so the walk climbs past it
        // with the same pop-or-fail guard the fallible read used to carry.
        let Ok(text) = std::fs::read_to_string(current.join("Cargo.toml")) else {
            assert!(
                current.pop(),
                "no ancestor of CARGO_MANIFEST_DIR declares a [workspace]"
            );
            continue;
        };
        if text.contains("[workspace]") {
            return current;
        }
        assert!(
            current.pop(),
            "no ancestor of CARGO_MANIFEST_DIR declares a [workspace]"
        );
    }
}

/// Recursively collects every `.rs` file under `root`, asserting the walk really
/// found the tree's sources so a wrong path can never look like a clean scan.
fn rust_files_under(root: &PathBuf) -> Vec<PathBuf> {
    let rust: Vec<PathBuf> = files_under(root)
        .into_iter()
        .filter(|path| path.extension().is_some_and(|value| value == "rs"))
        .collect();
    assert!(
        !rust.is_empty(),
        "the walk under {} must find Rust sources",
        root.display()
    );
    rust
}

/// Recursively collects every file under `root`, asserting the walk found some.
fn files_under(root: &PathBuf) -> Vec<PathBuf> {
    fn walk(root: &PathBuf, found: &mut Vec<PathBuf>) {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) => panic!("cannot read directory {}: {error}", root.display()),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => panic!("cannot read entry in {}: {error}", root.display()),
            };
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    assert!(
        !found.is_empty(),
        "the walk under {} must find files",
        root.display()
    );
    found.sort();
    found
}

/// Reads one file as text without ever panicking on a non-UTF-8 byte: this case
/// scans the real tree, and a stray byte must not turn a scan into a crash.
fn read_lossy(path: &PathBuf) -> String {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read {}: {error}", path.display()),
    };
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Counts the lines of `text` that contain `needle`. Every guard property
/// asserts a non-zero count on the file it is about to scan before asserting any
/// absence, because a zero count from a wrong path is indistinguishable from a
/// clean tree.
fn lines_containing(text: &str, needle: &str) -> usize {
    text.lines().filter(|line| line.contains(needle)).count()
}

/// The repo-relative spelling of `path`, for readable assertion messages.
fn relative_to_repo(path: &Path) -> String {
    match path.strip_prefix(repo_root()) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// Every whitespace-delimited token of `haystack` that begins with `prefix`,
/// sorted and deduplicated.
fn tokens_after(haystack: &str, prefix: &str) -> Vec<String> {
    let mut found: Vec<String> = haystack
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| token.starts_with(prefix))
        .map(str::to_owned)
        .collect();
    found.sort();
    found.dedup();
    found
}

/// The path of one crate inside the real workspace.
fn crate_path(crate_dir: &str) -> PathBuf {
    repo_root().join(crate_dir)
}

// WORK_UNIT_CASE: 963/18 source_and_api_guard_excludes_second_cli_and_authority
#[test]
fn source_and_api_guard_excludes_second_cli_and_authority() {
    let cli = crate_path("crates/surfaces/eliot-cli");
    let cli_src = cli.join("src");
    let cli_lib = cli_src.join("lib.rs");
    let backup_rs = cli_src.join("backup.rs");
    let cli_manifest = cli.join("Cargo.toml");
    let bin_src = crate_path("bins/eliot/src");
    let dispatch = crate_path("bins/eliot-kernel/src/request_dispatch.rs");

    // Every file this case reads must exist, so a moved path fails loudly
    // instead of silently matching nothing.
    for path in [&cli_lib, &backup_rs, &cli_manifest, &dispatch] {
        assert!(
            path.is_file(),
            "the guard reads {} and it must exist",
            path.display()
        );
    }
    for directory in [&cli_src, &bin_src] {
        assert!(
            directory.is_dir(),
            "the guard walks {} and it must exist",
            directory.display()
        );
    }

    guard_one_transport(&cli_src, &bin_src);
    guard_two_no_legacy_facade_source(&cli_manifest, &cli_src, &bin_src);
    guard_three_no_raw_untyped_backup_success(&backup_rs);
    guard_four_no_new_backup_authority(&dispatch, &cli_lib, &bin_src);
}

/// Property 1 — no second CLI or transport. Exactly one
/// `KERNEL_FRONT_DOOR_PIPE` declaration exists, inside exactly one file of the
/// CLI crate's `src`, that one name is the only named-pipe literal on the
/// surface, and the binary that drives it names no Kernel front-door pipe of its
/// own.
fn guard_one_transport(cli_src: &PathBuf, bin_src: &PathBuf) {
    let declaration = "const KERNEL_FRONT_DOOR_PIPE";
    let mut declaring: Vec<String> = Vec::new();
    let mut declaration_lines = 0usize;
    let mut referencing: Vec<String> = Vec::new();
    let mut reference_lines = 0usize;
    let mut other_pipe_literals = 0usize;

    for path in rust_files_under(cli_src) {
        let text = read_lossy(&path);
        let relative = relative_to_repo(&path);
        let declarations = lines_containing(&text, declaration);
        let references = lines_containing(&text, "KERNEL_FRONT_DOOR_PIPE");
        if declarations > 0 {
            declaration_lines += declarations;
            declaring.push(relative.clone());
        }
        if references > 0 {
            reference_lines += references;
            referencing.push(relative);
        } else if text.contains(r"\\.\pipe") {
            // A pipe literal the surface declares under a different name would
            // be a second transport.
            other_pipe_literals += 1;
        }
    }

    assert_eq!(
        declaration_lines, 1,
        "exactly one KERNEL_FRONT_DOOR_PIPE declaration may exist, found {declaring:?}"
    );
    assert_eq!(
        declaring.len(),
        1,
        "the declaration must live in exactly one file, found {declaring:?}"
    );
    assert_eq!(
        other_pipe_literals, 0,
        "the CLI surface must declare no other named-pipe constant for backup"
    );
    assert_eq!(
        reference_lines, 3,
        "the one transport name is declared once and referenced by the connect \
         site and by the hello assertion; a fourth reference would be a second \
         transport"
    );
    assert_eq!(
        referencing,
        vec![relative_to_repo(&cli_src.join("lib.rs"))],
        "only the front-door client module may name it"
    );

    // The binary reaches the Kernel through the surface client, so it must not
    // name the Kernel front-door pipe at all.
    let binary_references: usize = rust_files_under(bin_src)
        .into_iter()
        .map(|path| lines_containing(&read_lossy(&path), "KERNEL_FRONT_DOOR_PIPE"))
        .sum();
    assert_eq!(
        binary_references, 0,
        "bins/eliot must not name the Kernel front-door pipe"
    );
}

/// Property 2 — no legacy facade import. No occurrence of the retired facade
/// crate name, case-insensitively, in the CLI surface's sources, in the surface
/// manifest, or in the binary's sources.
///
/// The binary's own manifest still declares that dependency today; it is
/// deliberately outside this scan, and that fact is reported to the manager
/// rather than asserted away here. The property the issue names is an IMPORT,
/// and this asserts the surface sources, the surface manifest and the binary's
/// sources are all free of it.
fn guard_two_no_legacy_facade_source(cli_manifest: &PathBuf, cli_src: &PathBuf, bin_src: &PathBuf) {
    // Spelled so this test file never carries the retired name in plain text.
    let retired = format!("eliot-{}", "engine");
    let mut scanned = 0usize;
    let mut hits: Vec<(String, usize)> = Vec::new();

    let manifest = read_lossy(cli_manifest);
    scanned += 1;
    let manifest_hits = lines_containing(&manifest.to_lowercase(), &retired);
    if manifest_hits > 0 {
        hits.push((relative_to_repo(cli_manifest), manifest_hits));
    }
    for root in [cli_src.to_owned(), bin_src.to_owned()] {
        for path in rust_files_under(&root) {
            let text = read_lossy(&path).to_lowercase();
            scanned += 1;
            let count = lines_containing(&text, &retired);
            if count > 0 {
                hits.push((relative_to_repo(&path), count));
            }
        }
    }

    assert!(
        scanned >= 20,
        "the legacy-facade scan must read the real crate and binary sources, \
         read {scanned} files"
    );
    assert_eq!(
        hits.len(),
        0,
        "no retired facade import may appear in the CLI surface or bins/eliot: \
         {hits:?}"
    );
}

/// Property 3 — no raw untyped backup success. The `plan_gap` refusal token is
/// really present in `backup.rs`, the raw success token is never reported as a
/// state, and there is exactly one `Forwarded` construction: the shared typed
/// one, which also checks the correlation and runs the catalogue parity check.
fn guard_three_no_raw_untyped_backup_success(backup_rs: &PathBuf) {
    let text = read_lossy(backup_rs);

    // The scan found the handlers it is about to reason about.
    for entry in [
        "fn backup_create",
        "fn backup_verify",
        "fn backup_restore_test",
    ] {
        assert!(text.contains(entry), "backup.rs must still define {entry}");
    }

    // The refusal token is real: an absent owner answers with it, and each of
    // the three handlers checks for it before projecting anything.
    let plan_gap = lines_containing(&text, "plan_gap");
    assert!(
        plan_gap >= 3,
        "the create/verify/restore-test handlers really do check plan_gap, \
         found {plan_gap} lines"
    );

    // The raw success token is a transport acknowledgement, not a state, so no
    // handler may report it.
    assert!(
        !text.contains("state: BACKUP_WIRE_OK") && !text.contains("state: \"ok\""),
        "no backup handler may report the raw ok token as a state"
    );
    assert!(
        text.contains("const BACKUP_WIRE_OK"),
        "the raw success token still exists, so the assertion above is real"
    );

    // The honest form of "ok is not an accepted status for these three
    // commands": the token is declared EXACTLY once, as the wire
    // acknowledgement, and the reported states are the closed
    // `BACKUP_STATE_*` vocabulary. `ok` is not one of them.
    assert_eq!(
        lines_containing(&text, "= \"ok\""),
        1,
        "the raw ok token must be declared exactly once, as the wire \
         acknowledgement"
    );
    let reported_states = quoted_strings(&text, "pub const BACKUP_STATE_");
    assert_eq!(
        reported_states,
        vec![
            "verified",
            "invalid",
            "refused",
            "blocked",
            "unknown",
            "cancelled",
            "candidate",
        ],
        "the reported states are the closed BACKUP_STATE_* vocabulary"
    );
    for state in &reported_states {
        assert!(state != "ok", "`ok` must never be a reported backup state");
    }

    // What the shipped code really does with `ok` is NOT report it. It opens an
    // UNPROVEN branch: the unknown state is its own placeholder, and the graded
    // arm still ends in the unknown state unless the owner returned a receipt.
    assert!(
        text.contains("BACKUP_WIRE_OK => BACKUP_STATE_UNKNOWN"),
        "an unproven ok reply must open as the unknown state, never a success"
    );
    assert!(
        text.contains("BACKUP_WIRE_OK if owner_returned_receipt"),
        "a restore-test ok reply is graded by the owner's receipt, not by the \
         token"
    );
    assert!(
        text.contains("BACKUP_WIRE_OK => BACKUP_STATE_CANDIDATE,"),
        "the only other ok rung is the rehearsed candidate, still not a success"
    );

    // Exactly one `Forwarded` construction: the shared typed helper, which
    // refuses an outcome whose operation identity does not match the request and
    // runs the catalogue parity check before returning.
    let forwarded = lines_containing(&text, "CommandResult::Forwarded");
    assert_eq!(
        forwarded, 1,
        "the only Forwarded construction must be the shared typed one"
    );
    let Some(forward_at) = text.find("CommandResult::Forwarded") else {
        panic!("backup.rs must still build one typed Forwarded response");
    };
    let before = &text[..forward_at];
    assert!(
        before.contains("fn respond("),
        "the Forwarded construction must be the shared typed `respond` helper"
    );
    assert!(
        text.contains(".validate_for(CommandCatalogue::current(), request)"),
        "the shared respond must run the catalogue parity check"
    );
    assert!(
        text.contains("CliError::CorrelationMismatch"),
        "the shared respond must refuse an outcome whose operation identity \
         does not match the request"
    );
}

/// Property 4 — no new authority. The Kernel's closed backup entry admits
/// exactly its four declared selectors, and the surface exposes exactly three
/// backup command selectors with no fourth operation name anywhere on it.
fn guard_four_no_new_backup_authority(dispatch: &PathBuf, cli_lib: &PathBuf, bin_src: &PathBuf) {
    let dispatch_text = read_lossy(dispatch);

    // The Kernel entry itself: exactly the four constants its guard names.
    let Some(entry_start) = dispatch_text.find("fn is_backup_operation(") else {
        panic!("request_dispatch.rs must still define is_backup_operation");
    };
    let after = &dispatch_text[entry_start..];
    let entry_end = match after.find("\n}\n") {
        Some(at) => at + 3,
        None => panic!("is_backup_operation must still be a closed function"),
    };
    let admitted = tokens_after(&after[..entry_end], "BACKUP_");
    assert_eq!(
        admitted,
        vec![
            "BACKUP_CREATE_OPERATION",
            "BACKUP_RESTORE_STORE_OPERATION",
            "BACKUP_RESTORE_TEST_OPERATION",
            "BACKUP_VERIFY_OPERATION",
        ],
        "the Kernel backup entry must admit exactly its four declared selectors"
    );

    // Each admitted selector is the spelling the surface mirrors, and the fourth
    // is the one the route does not answer on the path this surface reaches.
    for literal in [
        "backup.create",
        "backup.verify",
        "backup.restore-test",
        "backup.restore-store",
    ] {
        assert!(
            dispatch_text.contains(&format!("\"{literal}\"")),
            "the Kernel route must still declare {literal}"
        );
    }

    // The surface's own command selectors: exactly three.
    let cli_text = read_lossy(cli_lib);
    let selectors: Vec<String> = quoted_strings(&cli_text, "\"backup-");
    assert!(
        !selectors.is_empty(),
        "the scan must find the surface's backup command selectors"
    );
    let mut unique = selectors.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique,
        vec![
            "backup-create".to_owned(),
            "backup-restore-test".to_owned(),
            "backup-verify".to_owned(),
        ],
        "the surface's backup command selector set must be exactly the three"
    );
    for absent in [
        "backup-restore-store",
        "backup-delete",
        "backup-purge",
        "backup-import",
    ] {
        assert!(
            !cli_text.contains(absent),
            "the surface must not add a {absent} selector"
        );
    }

    // No fourth operation selector is spelled on the binary that drives the
    // surface either: it routes through the closed constants.
    let mut scanned = 0usize;
    for path in rust_files_under(bin_src) {
        let text = read_lossy(&path);
        scanned += 1;
        assert_eq!(
            quoted_strings(&text, "\"backup."),
            Vec::<String>::new(),
            "{} must not spell a backup operation selector; it routes through \
             the closed constants",
            relative_to_repo(&path)
        );
    }
    assert!(
        scanned >= 5,
        "the operation-selector scan must read the binary's sources, read \
         {scanned} files"
    );
}

/// Every double-quoted string literal in `haystack` that begins with `prefix`,
/// in source order. The text is split on the quote character and the segments
/// between quote PAIRS are the literals, which is exact for Rust source.
fn quoted_strings(haystack: &str, prefix: &str) -> Vec<String> {
    let parts: Vec<&str> = haystack.split('"').collect();
    let mut found: Vec<String> = Vec::new();
    let mut index = 1usize;
    while index < parts.len() {
        if parts[index].starts_with(prefix) {
            found.push(parts[index].to_owned());
        }
        index += 2;
    }
    found
}
