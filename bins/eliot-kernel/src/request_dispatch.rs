//! Kernel front-door backup method route (issue #963).
//!
//! Architecture: A12.3 One Governed Write Path (no direct canonical
//! writes here — verify performs bounded reads/validation only, create
//! and restore-test refuse before effects); A13.7 Backups, Restore, and
//! Migration (isolated restore verifies before any effect; rehearsal
//! never activates, retires, or cuts over); I1.8 Exact Ownership and
//! Call Paths (typed frames in, typed receipts out; the operation string
//! only selects this closed entry); I7.5 Named pipes (existing Kernel
//! front door, no new transport).
//!
//! This file owns exactly the backup method entry: the closed operation
//! allowlist plus per-command decode/validate/gate handlers. It performs
//! no capture (owner #959, open), no journal mutation, no store import,
//! and no cutover: create refuses with the exact missing capture owner,
//! verify executes bounded bundle validation with no owners needed, and
//! restore-test runs every gate it can prove (decode, plan, destination
//! authorization, fence currency, provisioning) before refusing execution
//! with the exact missing journal-admission owner. Missing owners refuse
//! as typed `plan_gap`, never as fake success and never silently.
//!
//! Wire contract mirror: the operator CLI surface
//! (`crates/surfaces/eliot-cli/src/backup.rs`) carries these exact
//! operation strings and payload shapes; a mismatch on either side
//! refuses before effects. Frame correlation, peer authentication, and
//! session/fence joins mirror the sibling native-worker route. The
//! dispatch-matrix arm lives in `frame_dispatch` (manager-serialized
//! shared registration); this file holds only the route.
//!
//! Capability cell: Kernel front-door backup dispatch (bounded backup
//! method entry). Forbidden authority: no capture orchestration, no
//! journal admission minting, no store import, no activation/retirement/
//! cutover, no second dispatch vocabulary.

use std::{num::NonZeroU64, path::Path};

use eliot_backup::{BackupBundle, BackupClass, BackupError, RestoreContext, RestorePlan};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_ipc::{Session, TransportError};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use serde_json::{Map, Value};

use super::backup_owner_clients::{AuthorizationExpectation, verify_destination_authorization};
use super::backup_restore_admission::RestoreProvisioningProof;
use super::backup_restore_ports::check_kernel_effect_fence;
use super::{KernelFrameAction, status_frame};

/// Closed backup create operation selector (mirrored by the operator CLI
/// surface; the string only selects this entry, never authority).
pub(crate) const BACKUP_CREATE_OPERATION: &str = "backup.create";
/// Closed backup verify operation selector (mirrored by the operator CLI
/// surface).
pub(crate) const BACKUP_VERIFY_OPERATION: &str = "backup.verify";
/// Closed isolated restore-test operation selector (mirrored by the
/// operator CLI surface; rehearsal only, never cutover).
pub(crate) const BACKUP_RESTORE_TEST_OPERATION: &str = "backup.restore-test";

/// Maximum inline bundle bytes admitted on one backup frame payload.
///
/// Derived from the 4 MiB frame ceiling (`MAX_FRAME_BYTES`): JSON hex
/// inflation doubles input bytes on the wire, so 1 MiB of archive bytes
/// stays within budget with envelope headroom. Larger archives refuse
/// with an exact bound instead of truncating or splitting across frames.
pub(crate) const BACKUP_WIRE_BYTES_MAX: usize = 1_048_576;
/// Maximum inline destination-authorization bytes: mirrors the
/// destination verifier's 16 KiB cap so oversized input refuses here
/// with the same bound instead of reaching the verifier.
pub(crate) const BACKUP_AUTH_BYTES_MAX: usize = 16_384;
/// Maximum operator text field length (scope descriptors, identities).
pub(crate) const BACKUP_TEXT_MAX: usize = 256;

fn non_blank(value: &str, field: &'static str) -> Result<(), BackupError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    if value.len() > BACKUP_TEXT_MAX {
        return Err(BackupError::InvalidField {
            field,
            reason: "exceeds the bounded operator text length",
        });
    }
    Ok(())
}

fn hex_bytes(value: &str, field: &'static str, max_bytes: usize) -> Result<Vec<u8>, BackupError> {
    if value.len() > max_bytes.saturating_mul(2) {
        return Err(BackupError::InvalidField {
            field,
            reason: "exceeds the bounded inline byte length",
        });
    }
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(BackupError::InvalidField {
            field,
            reason: "must be even-length lowercase hex",
        });
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let pair =
            std::str::from_utf8(&raw[index..index + 2]).map_err(|_| BackupError::InvalidField {
                field,
                reason: "must be even-length lowercase hex",
            })?;
        let byte = u8::from_str_radix(pair, 16).map_err(|_| BackupError::InvalidField {
            field,
            reason: "must be even-length lowercase hex",
        })?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}

fn get_str<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, BackupError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BackupError::InvalidField {
            field,
            reason: "required string field is missing",
        })
}

fn get_u64(object: &Map<String, Value>, field: &'static str) -> Result<u64, BackupError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BackupError::InvalidField {
            field,
            reason: "required unsigned integer field is missing",
        })
}

fn get_object<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>, BackupError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(BackupError::InvalidField {
            field,
            reason: "required object field is missing",
        })
}

fn require_exact_keys(
    object: &Map<String, Value>,
    keys: &[&str],
    field: &'static str,
) -> Result<(), BackupError> {
    for key in object.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(BackupError::InvalidField {
                field,
                reason: "unexpected payload field",
            });
        }
    }
    for key in keys {
        if !object.contains_key(*key) {
            return Err(BackupError::InvalidField {
                field,
                reason: "required payload field is missing",
            });
        }
    }
    Ok(())
}

/// Returns whether the operation string selects the closed backup route.
///
/// The operation string only selects this entry; every call still proves
/// its exact payload shape, session joins, and fence below. Unknown
/// operations never reach the handlers.
pub(crate) fn is_backup_operation(operation: &str) -> bool {
    matches!(
        operation,
        BACKUP_CREATE_OPERATION | BACKUP_VERIFY_OPERATION | BACKUP_RESTORE_TEST_OPERATION
    )
}

fn backup_error_code(error: &BackupError) -> &'static str {
    match error {
        BackupError::InvalidField { .. }
        | BackupError::Serialization(_)
        | BackupError::UnsupportedFormat(_) => "invalid",
        BackupError::FenceMismatch { .. } | BackupError::StaleRestoreLineage => "stale",
        BackupError::RestoreCapabilityUnsupported { .. }
        | BackupError::RestoreCapabilityNotAttempted { .. }
        | BackupError::MissingRecoveryComponent(_) => "plan_gap",
        _ => "mismatch",
    }
}

fn backup_status(code: &str) -> &'static str {
    if code == "plan_gap" {
        "refused"
    } else {
        "invalid"
    }
}

fn backup_reply(
    command: &str,
    status: &str,
    idempotency_key: &str,
    fields: Vec<(&str, Value)>,
) -> Value {
    let mut object = Map::with_capacity(fields.len() + 3);
    object.insert("command".to_owned(), Value::String(command.to_owned()));
    object.insert("status".to_owned(), Value::String(status.to_owned()));
    object.insert(
        "idempotency_key".to_owned(),
        Value::String(idempotency_key.to_owned()),
    );
    for (key, value) in fields {
        object.insert(key.to_owned(), value);
    }
    Value::Object(object)
}

fn refused_reply(
    command: &str,
    idempotency_key: &str,
    code: &str,
    missing_owner: &str,
    reason: &str,
) -> Value {
    backup_reply(
        command,
        "refused",
        idempotency_key,
        vec![
            ("code", Value::String(code.to_owned())),
            ("missing_owner", Value::String(missing_owner.to_owned())),
            ("reason", Value::String(reason.to_owned())),
        ],
    )
}

fn backup_class_name(class: &BackupClass) -> &'static str {
    match class {
        BackupClass::FullRecovery => "full_recovery",
        BackupClass::CanonicalOnlyDegraded => "canonical_only_degraded",
        BackupClass::ScopeExport => "scope_export",
    }
}

/// Handles one backup create frame: validates the bounded capture
/// descriptors, then refuses with the exact missing capture owner.
///
/// Capture orchestration belongs to the #959 owner (open everywhere):
/// admitting capture here would invent authority, so the only honest
/// outcome is a typed `plan_gap` naming that owner. Shape failures
/// refuse as `invalid` before any owner is named.
fn handle_backup_create(payload: &Value, idempotency_key: &str) -> Result<Value, BackupError> {
    let object = payload.as_object().ok_or(BackupError::InvalidField {
        field: "backup.create",
        reason: "payload must be a JSON object",
    })?;
    require_exact_keys(object, &["scope_descriptor", "class"], "backup.create")?;
    let scope = get_str(object, "scope_descriptor")?;
    non_blank(scope, "backup.scope_descriptor")?;
    match get_str(object, "class")? {
        "full_recovery" | "canonical_only_degraded" | "scope_export" => Ok(()),
        _ => Err(BackupError::InvalidField {
            field: "backup.class",
            reason: "must be full_recovery, canonical_only_degraded, or scope_export",
        }),
    }?;
    Ok(refused_reply(
        BACKUP_CREATE_OPERATION,
        idempotency_key,
        "plan_gap",
        "backup-capture-owner (#959)",
        "admitted capture is not implemented; rehearsal-only paths cannot invent it",
    ))
}

/// Handles one backup verify frame: bounded bundle validation with no
/// owners needed, reporting the verified identities.
///
/// Fully real: decode, structural validation, and class/denominator
/// reporting run here through the accepted backup owner library. No
/// journal, store, Host, or Watchdog state is touched.
fn handle_backup_verify(payload: &Value, idempotency_key: &str) -> Result<Value, BackupError> {
    let object = payload.as_object().ok_or(BackupError::InvalidField {
        field: "backup.verify",
        reason: "payload must be a JSON object",
    })?;
    require_exact_keys(object, &["bundle_hex"], "backup.verify")?;
    let raw = hex_bytes(
        get_str(object, "bundle_hex")?,
        "backup.bundle_hex",
        BACKUP_WIRE_BYTES_MAX,
    )?;
    let bundle = BackupBundle::decode(&raw).map_err(|error| {
        BackupError::Serialization(format!("archive bytes do not decode: {error}"))
    })?;
    bundle.validate()?;
    let blob_count = u64::try_from(bundle.blobs.len()).unwrap_or(u64::MAX);
    let event_count = u64::try_from(bundle.canonical_events.len()).unwrap_or(u64::MAX);
    let receipt_count = u64::try_from(bundle.receipts.len()).unwrap_or(u64::MAX);
    Ok(backup_reply(
        BACKUP_VERIFY_OPERATION,
        "ok",
        idempotency_key,
        vec![
            (
                "bundle_id",
                Value::String(bundle.manifest.backup_id.clone()),
            ),
            (
                "class",
                Value::String(backup_class_name(&bundle.manifest.class).to_owned()),
            ),
            (
                "integrity_sha256",
                Value::String(bundle.manifest.integrity_sha256.clone()),
            ),
            ("blob_count", Value::from(blob_count)),
            ("event_count", Value::from(event_count)),
            ("receipt_count", Value::from(receipt_count)),
        ],
    ))
}

fn restore_target_context(target: &Map<String, Value>) -> Result<RestoreContext, BackupError> {
    require_exact_keys(
        target,
        &[
            "target_id",
            "target_lineage",
            "target_sequence",
            "target_generation",
        ],
        "backup.target",
    )?;
    let target_id = get_str(target, "target_id")?;
    non_blank(target_id, "restore.target_id")?;
    let lineage_id = EpochLineageId::new(get_str(target, "target_lineage")?).map_err(|_| {
        BackupError::InvalidField {
            field: "restore.target_lineage",
            reason: "target lineage is not a canonical UUID",
        }
    })?;
    let sequence =
        NonZeroU64::new(get_u64(target, "target_sequence")?).ok_or(BackupError::InvalidField {
            field: "restore.target_sequence",
            reason: "target sequence must be nonzero",
        })?;
    let authority_epoch =
        EpochId::new(lineage_id, sequence).map_err(|_| BackupError::InvalidField {
            field: "restore.target_sequence",
            reason: "target authority epoch is not admissible",
        })?;
    let resource_generation = ResourceGeneration::new(get_u64(target, "target_generation")?)
        .map_err(|_| BackupError::InvalidField {
            field: "restore.target_generation",
            reason: "target resource generation must be nonzero",
        })?;
    let context = RestoreContext {
        target_id: target_id.to_owned(),
        target_authority_epoch: authority_epoch,
        target_resource_generation: resource_generation,
    };
    context.validate()?;
    Ok(context)
}

fn restore_provisioning(
    payload: &Map<String, Value>,
) -> Result<RestoreProvisioningProof, BackupError> {
    let provisioning = get_object(payload, "provisioning")?;
    require_exact_keys(
        provisioning,
        &[
            "dest_store_id",
            "residency_denominator_digest",
            "source_snapshot_digest",
            "capture_operation_id",
        ],
        "backup.provisioning",
    )?;
    let proof = RestoreProvisioningProof {
        dest_store_id: get_str(provisioning, "dest_store_id")?.to_owned(),
        residency_denominator_digest: get_str(provisioning, "residency_denominator_digest")?
            .to_owned(),
        source_snapshot_digest: get_str(provisioning, "source_snapshot_digest")?.to_owned(),
        capture_operation_id: get_str(provisioning, "capture_operation_id")?.to_owned(),
    };
    proof.validate()?;
    Ok(proof)
}

/// Handles one isolated restore-test frame: every gate provable without
/// owners, then a typed execution refusal naming the exact missing owner.
/// Decode, structural validation, governed plan compilation (lineage
/// advance proven inside), destination authorization verification
/// against the plan/bundle-bound expectation, live fence currency,
/// effect-fence gating, provisioning shape checks, and
/// source-isolation binding all run here for real. The restore effect
/// itself refuses with `plan_gap` naming the journal-admission minter:
/// minting durability admission from nothing would fabricate authority,
/// and rehearsal never activates, retires, or cuts over. The reply
/// names every passed gate so the operator sees the safe next action.
fn handle_backup_restore_test(
    payload: &Value,
    live_fence: &StateFence,
    work_root: &Path,
    idempotency_key: &str,
) -> Result<Value, BackupError> {
    let object = payload.as_object().ok_or(BackupError::InvalidField {
        field: "backup.restore-test",
        reason: "payload must be a JSON object",
    })?;
    require_exact_keys(
        object,
        &[
            "bundle_hex",
            "destination_authorization_hex",
            "target",
            "provisioning",
        ],
        "backup.restore-test",
    )?;
    let raw = hex_bytes(
        get_str(object, "bundle_hex")?,
        "backup.bundle_hex",
        BACKUP_WIRE_BYTES_MAX,
    )?;
    let bundle = BackupBundle::decode(&raw).map_err(|error| {
        BackupError::Serialization(format!("archive bytes do not decode: {error}"))
    })?;
    bundle.validate()?;
    let context = restore_target_context(get_object(object, "target")?)?;
    let plan = RestorePlan::compile(&bundle, context)?;
    let transaction = plan.transaction()?;
    let config_digest = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == "config")
        .map(|artifact| artifact.sha256.as_str());
    let auth_raw = hex_bytes(
        get_str(object, "destination_authorization_hex")?,
        "backup.destination_authorization_hex",
        BACKUP_AUTH_BYTES_MAX,
    )?;
    let expectation = AuthorizationExpectation {
        target_id: plan.target.target_id.as_str(),
        transaction_id: transaction.transaction_id.as_str(),
        expected_manifest_digest: config_digest,
        kernel_work_root: work_root,
    };
    let verified = verify_destination_authorization(&auth_raw, &expectation)?;
    if verified.fence_authority_generation() != live_fence.resource_generation.value() {
        return Err(BackupError::FenceMismatch {
            subject: "destination authority generation is not current".to_owned(),
        });
    }
    check_kernel_effect_fence(live_fence, &bundle)?;
    let _provisioning = restore_provisioning(object)?;
    if plan.target.target_id == verified.source_installation_id() {
        return Err(BackupError::FenceMismatch {
            subject: "restore destination is not isolated from the source installation".to_owned(),
        });
    }
    Ok(backup_reply(
        BACKUP_RESTORE_TEST_OPERATION,
        "blocked",
        idempotency_key,
        vec![
            ("code", Value::String("plan_gap".to_owned())),
            (
                "missing_owner",
                Value::String("restore-journal-admission-minter".to_owned()),
            ),
            (
                "reason",
                Value::String(
                    "gates proven; restore effects need production journal admission that no owner mints yet"
                        .to_owned(),
                ),
            ),
            (
                "gates_passed",
                Value::Array(
                    [
                        "decode",
                        "validate",
                        "plan",
                        "authorization",
                        "currency",
                        "effect-fence",
                        "provisioning",
                        "isolation",
                    ]
                    .iter()
                    .map(|gate| Value::String((*gate).to_owned()))
                    .collect(),
                ),
            ),
        ],
    ))
}

/// Dispatches one backup frame from an admitted session.
///
/// Mirrors the sibling route entry shape: request identity presence,
/// session fence join, connection join, JSON payload, and exact
/// operation allowlist are all re-checked here so direct callers cannot
/// bypass them. The adapter work root scopes destination containment.
/// Domain outcomes return as typed reply frames; only authentication,
/// session, and shape failures fence.
///
/// Uncalled until the `frame_dispatch` backup arm lands (manager-
/// serialized shared registration): the allow below documents exactly
/// that pending wiring instead of pretending otherwise.
#[allow(
    dead_code,
    reason = "no frame_dispatch backup arm calls into the route yet; remove when the shared arm lands"
)]
pub(crate) fn dispatch_backup_frame(
    session: &Session,
    frame: &Frame,
    work_root: &Path,
) -> Result<KernelFrameAction, TransportError> {
    let request_id = frame
        .request_id
        .clone()
        .ok_or(TransportError::SessionFenced)?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or(TransportError::SessionFenced)?;
    if !session
        .module_generation
        .state_fence
        .is_compatible_with(&identity.request.state_fence)
    {
        return Err(TransportError::SessionFenced);
    }
    if frame.connection_id != session.connection_id {
        return Err(TransportError::SessionFenced);
    }
    let payload = match &frame.payload {
        ProtocolPayload::Json(payload) => payload.clone(),
        _ => return Err(TransportError::SessionFenced),
    };
    let operation = payload
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if !is_backup_operation(operation) {
        return Err(TransportError::SessionFenced);
    }
    let live_fence = &session.module_generation.state_fence;
    let idempotency_key = identity.idempotency_key.as_str();
    if idempotency_key.trim().is_empty() {
        return Err(TransportError::SessionFenced);
    }
    let body = match operation {
        BACKUP_CREATE_OPERATION => handle_backup_create(&payload, idempotency_key),
        BACKUP_VERIFY_OPERATION => handle_backup_verify(&payload, idempotency_key),
        BACKUP_RESTORE_TEST_OPERATION => {
            handle_backup_restore_test(&payload, live_fence, work_root, idempotency_key)
        }
        _ => return Err(TransportError::SessionFenced),
    };
    let reply = match body {
        Ok(value) => value,
        Err(error) => {
            let code = backup_error_code(&error);
            let (field, reason) = match error {
                BackupError::InvalidField { field, reason } => (field, reason.to_owned()),
                _ => ("backup.request", error.to_string()),
            };
            backup_reply(
                operation,
                backup_status(code),
                idempotency_key,
                vec![
                    ("code", Value::String(code.to_owned())),
                    ("field", Value::String(field.to_owned())),
                    ("reason", Value::String(reason)),
                ],
            )
        }
    };
    let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, reply)?;
    frame.request_id = Some(request_id);
    Ok(KernelFrameAction::Reply(frame))
}
