//! Typed backup command surface (issue #963).
//!
//! Thin client adapters for the three backup catalogue commands: parse
//! bounded operator fields, build the closed kernel payload, delegate
//! through the correlated [`KernelClient`] front door, and decode the
//! typed reply into a [`CommandResponse`]. This crate never opens
//! transports beyond the client, never mints authority, and never
//! interprets a payload as canonical state: every cross-boundary fact is
//! re-checked here (command echo, idempotency echo, status, and exact
//! result shape) before it becomes a response.
//!
//! Wire contract mirror: the Kernel backup route
//! (`bins/eliot-kernel/src/request_dispatch.rs`) carries the exact
//! operation selectors and payload shapes used here; a mismatch on
//! either side refuses before effects. `CommandArguments` stays with its
//! unit variants (bijection enforced per call below); the typed fields
//! travel in the operation payload, mirroring
//! `user_automation_route_payload`.
//!
//! Empty payloads never select scope or destination silently: create
//! requires an explicit scope descriptor and closed class, verify and
//! restore-test require explicit bundle bytes, restore-test additionally
//! requires explicit target descriptors, authorization bytes,
//! provisioning attestations, and an explicit introductions array.
//! Unknown outcomes stay unknown with their operation identity for
//! same-operation reconciliation — never success, never blind retry.

use eliot_contracts::EpochLineageId;
use eliot_protocol::RequestIdentity;
use eliot_receipts::{EffectClass, ProofCeiling};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use super::{
    CliError, CommandArguments, CommandId, CommandRequest, CommandResponse, CommandResult,
    kernel_client::{KernelClient, KernelClientError},
};

/// Closed backup create operation selector (mirrored by the Kernel
/// backup route; the string only selects the entry, never authority).
pub const BACKUP_CREATE_OPERATION: &str = "backup.create";
/// Closed backup verify operation selector (mirrored by the Kernel
/// backup route).
pub const BACKUP_VERIFY_OPERATION: &str = "backup.verify";
/// Closed isolated restore-test operation selector (mirrored by the
/// Kernel backup route; rehearsal only, never cutover).
pub const BACKUP_RESTORE_TEST_OPERATION: &str = "backup.restore-test";

/// Maximum inline bundle bytes admitted in one backup payload.
///
/// Derived from the 4 MiB frame ceiling: JSON hex inflation doubles
/// input bytes on the wire, so 1 MiB of archive bytes stays within
/// budget with envelope headroom. Mirrors the Kernel bound byte-exact;
/// larger archives refuse on both sides instead of truncating.
pub const BACKUP_WIRE_BYTES_MAX: usize = 1_048_576;
/// Maximum inline destination-authorization bytes: mirrors the Kernel
/// destination verifier's 16 KiB cap.
pub const BACKUP_AUTH_BYTES_MAX: usize = 16_384;
/// Maximum operator text field length (scope descriptors, identities).
pub const BACKUP_TEXT_MAX: usize = 256;
/// Maximum console-presented capability introductions admitted in one
/// restore-test payload.
///
/// Mirrors `eliot_ors::MAX_RECOVERY_PAGE` (256) byte-exact with the
/// Kernel bound; the Kernel exact-set check stays authoritative and
/// refuses anything the live owner page cannot verify.
pub const BACKUP_INTRODUCTIONS_MAX: usize = 256;

/// Failure of one thin backup delegation: transport problems stay
/// transport errors (with their operation identity for same-operation
/// reconciliation); client-side problems reuse the catalogue [`CliError`].
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BackupClientError {
    /// Authenticated transport failed or returned an unknown outcome.
    #[error("backup transport failure: {0}")]
    Transport(KernelClientError),
    /// Catalogue client validation failed.
    #[error("backup client failure: {0}")]
    Client(CliError),
}

fn non_blank(value: &str, field: &'static str) -> Result<(), CliError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::InvalidArgument { field });
    }
    if value.len() > BACKUP_TEXT_MAX {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

fn hex_bytes(value: &str, field: &'static str, max_bytes: usize) -> Result<(), CliError> {
    if value.len() > max_bytes.saturating_mul(2) {
        return Err(CliError::InvalidArgument { field });
    }
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

fn hex64(value: &str, field: &'static str) -> Result<(), CliError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CliError::InvalidArgument { field });
    }
    Ok(())
}

/// Typed backup create arguments: explicit scope descriptor plus the
/// closed class vocabulary (mirrors `BackupClass` variant names; no
/// eliot-backup dependency is introduced for spelling).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCreateParams {
    /// Capture scope descriptor (required, bounded, never defaulted).
    pub scope_descriptor: String,
    /// Archive class: `full_recovery`, `canonical_only_degraded`, or
    /// `scope_export`.
    pub class: String,
}

/// Typed backup verify arguments: explicit archive bytes (bounded hex).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupVerifyParams {
    /// Archive bytes as lowercase hex (bounded by [`BACKUP_WIRE_BYTES_MAX`]).
    pub bundle_hex: String,
}

/// Typed isolated restore-test arguments: explicit archive, explicit
/// authorization, explicit target, explicit provisioning attestations,
/// explicit console-presented introductions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRestoreTestParams {
    /// Archive bytes as lowercase hex (bounded by [`BACKUP_WIRE_BYTES_MAX`]).
    pub bundle_hex: String,
    /// Host-issued destination authorization bytes as lowercase hex
    /// (bounded by [`BACKUP_AUTH_BYTES_MAX`]).
    pub authorization_hex: String,
    /// Isolated-restore target identity (required, never defaulted).
    pub target_id: String,
    /// Target authority lineage UUID text.
    pub target_lineage: String,
    /// Target authority sequence, nonzero.
    pub target_sequence: u64,
    /// Target resource generation, nonzero.
    pub target_generation: u64,
    /// Provisioned isolated destination store identity.
    pub dest_store_id: String,
    /// Capture residency denominator digest.
    pub residency_denominator_digest: String,
    /// Source snapshot digest the restore replays.
    pub source_snapshot_digest: String,
    /// Capture operation that produced the source snapshot.
    pub capture_operation_id: String,
    /// Console-presented capability introductions as owner-shaped JSON
    /// objects (explicit array, may be explicitly empty; typed decode and
    /// exact-set verification run Kernel-side against live owner readback).
    pub introductions: Vec<Value>,
}

/// Parses bounded backup create arguments. No defaults: a missing scope
/// or class refuses instead of selecting production scope silently.
pub fn parse_backup_create(
    scope_descriptor: &str,
    class: &str,
) -> Result<BackupCreateParams, CliError> {
    non_blank(scope_descriptor, "backup.scope_descriptor")?;
    match class {
        "full_recovery" | "canonical_only_degraded" | "scope_export" => Ok(()),
        _ => Err(CliError::InvalidArgument {
            field: "backup.class",
        }),
    }?;
    Ok(BackupCreateParams {
        scope_descriptor: scope_descriptor.to_owned(),
        class: class.to_owned(),
    })
}

/// Parses bounded backup verify arguments.
pub fn parse_backup_verify(bundle_hex: &str) -> Result<BackupVerifyParams, CliError> {
    hex_bytes(bundle_hex, "backup.bundle_hex", BACKUP_WIRE_BYTES_MAX)?;
    if bundle_hex.is_empty() {
        return Err(CliError::InvalidArgument {
            field: "backup.bundle_hex",
        });
    }
    Ok(BackupVerifyParams {
        bundle_hex: bundle_hex.to_owned(),
    })
}

/// Parses bounded restore-test arguments. Every binding is explicit:
/// empty archive, authorization, target, or provisioning refuses, and
/// the console-presented introductions arrive as an explicit JSON array
/// (explicitly empty allowed — never absent, never defaulted).
#[allow(
    clippy::too_many_arguments,
    reason = "restore-test carries eleven independently validated bindings; grouping them would hide which exact field refused"
)]
pub fn parse_backup_restore_test(
    bundle_hex: &str,
    authorization_hex: &str,
    target_id: &str,
    target_lineage: &str,
    target_sequence: u64,
    target_generation: u64,
    dest_store_id: &str,
    residency_denominator_digest: &str,
    source_snapshot_digest: &str,
    capture_operation_id: &str,
    introductions_json: &str,
) -> Result<BackupRestoreTestParams, CliError> {
    parse_backup_verify(bundle_hex)?;
    hex_bytes(
        authorization_hex,
        "backup.destination_authorization_hex",
        BACKUP_AUTH_BYTES_MAX,
    )?;
    if authorization_hex.is_empty() {
        return Err(CliError::InvalidArgument {
            field: "backup.destination_authorization_hex",
        });
    }
    non_blank(target_id, "backup.target_id")?;
    EpochLineageId::new(target_lineage).map_err(|_| CliError::InvalidArgument {
        field: "backup.target_lineage",
    })?;
    if target_sequence == 0 {
        return Err(CliError::InvalidArgument {
            field: "backup.target_sequence",
        });
    }
    if target_generation == 0 {
        return Err(CliError::InvalidArgument {
            field: "backup.target_generation",
        });
    }
    non_blank(dest_store_id, "backup.dest_store_id")?;
    hex64(
        residency_denominator_digest,
        "backup.residency_denominator_digest",
    )?;
    hex64(source_snapshot_digest, "backup.source_snapshot_digest")?;
    non_blank(capture_operation_id, "backup.capture_operation_id")?;
    let introductions_value: Value =
        serde_json::from_str(introductions_json).map_err(|_| CliError::InvalidArgument {
            field: "backup.introductions",
        })?;
    let introductions_array = introductions_value
        .as_array()
        .ok_or(CliError::InvalidArgument {
            field: "backup.introductions",
        })?;
    if introductions_array.len() > BACKUP_INTRODUCTIONS_MAX {
        return Err(CliError::InvalidArgument {
            field: "backup.introductions",
        });
    }
    for introduction in introductions_array {
        if !introduction.is_object() {
            return Err(CliError::InvalidArgument {
                field: "backup.introductions",
            });
        }
    }
    Ok(BackupRestoreTestParams {
        bundle_hex: bundle_hex.to_owned(),
        authorization_hex: authorization_hex.to_owned(),
        target_id: target_id.to_owned(),
        target_lineage: target_lineage.to_owned(),
        target_sequence,
        target_generation,
        dest_store_id: dest_store_id.to_owned(),
        residency_denominator_digest: residency_denominator_digest.to_owned(),
        source_snapshot_digest: source_snapshot_digest.to_owned(),
        capture_operation_id: capture_operation_id.to_owned(),
        introductions: introductions_array.clone(),
    })
}

/// Typed backup create result: always a refusal today (capture owner
/// open), carrying the exact missing owner for the safe next action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupCreateResult {
    /// Owner that must implement admitted capture.
    pub missing_owner: String,
    /// Exact reason the command refused.
    pub reason: String,
}

/// Typed backup verify result: the verified archive identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupVerifyResult {
    /// Verified archive identity.
    pub bundle_id: String,
    /// Verified archive class.
    pub class: String,
    /// Verified integrity digest.
    pub integrity_sha256: String,
    /// Verified blob population.
    pub blob_count: u64,
    /// Verified canonical event population.
    pub event_count: u64,
    /// Verified receipt population.
    pub receipt_count: u64,
}

/// Typed restore-test result: rehearsal gates proven, the minted
/// identity bound, plus the exact missing Governor inputs blocking
/// execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreTestResult {
    /// Owner inputs that must arrive Governor-built.
    pub missing_owner: String,
    /// Exact reason execution is blocked.
    pub reason: String,
    /// Gates the Kernel proved, in order.
    pub gates_passed: Vec<String>,
    /// Minted restore operation identity the Governor lane correlates.
    pub restore_operation_id: String,
    /// Coordination decision digest built from the minted admission.
    pub decision_digest: String,
    /// Admitted plan identity.
    pub plan_id: String,
    /// Admitted archive digest.
    pub bundle_sha256: String,
}

fn require_command(
    request: &CommandRequest,
    expected: CommandId,
    unit: &CommandArguments,
) -> Result<(), CliError> {
    if request.command != expected || &request.arguments != unit {
        return Err(CliError::ArgumentCommandMismatch);
    }
    Ok(())
}

fn envelope_command(response: &Value, expected_operation: &str) -> Result<(), BackupClientError> {
    let command = response
        .get("command")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    if command != expected_operation {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(())
}

fn envelope_idempotency(
    response: &Value,
    identity: &RequestIdentity,
) -> Result<(), BackupClientError> {
    let key = response
        .get("idempotency_key")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::CorrelationMismatch))?;
    if key != identity.idempotency_key.as_str() {
        return Err(BackupClientError::Client(CliError::CorrelationMismatch));
    }
    Ok(())
}

fn envelope_status(response: &Value) -> Result<&str, BackupClientError> {
    response
        .get("status")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

fn envelope_text<'a>(
    response: &'a Value,
    field: &'static str,
) -> Result<&'a str, BackupClientError> {
    response
        .get(field)
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

fn envelope_count(response: &Value, field: &'static str) -> Result<u64, BackupClientError> {
    response
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))
}

fn respond(
    request: &CommandRequest,
    command: CommandId,
    effect: EffectClass,
    proof_ceiling: ProofCeiling,
    result: Value,
) -> CommandResponse {
    CommandResponse {
        request: request.request.clone(),
        command,
        effect,
        proof_ceiling,
        result: CommandResult::Forwarded { payload: result },
    }
}

/// Delegates one backup create command through the correlated Kernel
/// front door: the only honest outcome today is the typed capture-owner
/// refusal, decoded strictly (never a fake success).
pub fn backup_create(
    client: &mut KernelClient,
    request: &CommandRequest,
    params: &BackupCreateParams,
) -> Result<CommandResponse, BackupClientError> {
    require_command(
        request,
        CommandId::BackupCreate,
        &CommandArguments::BackupCreate,
    )
    .map_err(BackupClientError::Client)?;
    client.set_request_identity(request.request.clone());
    let payload = json!({
        "operation": BACKUP_CREATE_OPERATION,
        "scope_descriptor": params.scope_descriptor.as_str(),
        "class": params.class.as_str(),
    });
    let response = client
        .transact_json(BACKUP_CREATE_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_CREATE_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    if envelope_status(&response)? != "refused" {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    if envelope_text(&response, "code")? != "plan_gap" {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let result = BackupCreateResult {
        missing_owner: envelope_text(&response, "missing_owner")?.to_owned(),
        reason: envelope_text(&response, "reason")?.to_owned(),
    };
    // Refusal performed bounded validation reads only: nothing admitted,
    // nothing proven beyond observation.
    Ok(respond(
        request,
        CommandId::BackupCreate,
        EffectClass::Read,
        ProofCeiling::Observation,
        serde_json::to_value(&result)
            .map_err(|_| BackupClientError::Client(CliError::ResultMismatch))?,
    ))
}

/// Delegates one backup verify command: bounded bundle validation with
/// receipt-grade reporting. Transport ack is never verification proof:
/// only a fully decoded `ok` envelope with exact identities counts.
pub fn backup_verify(
    client: &mut KernelClient,
    request: &CommandRequest,
    params: &BackupVerifyParams,
) -> Result<CommandResponse, BackupClientError> {
    require_command(
        request,
        CommandId::BackupVerify,
        &CommandArguments::BackupVerify,
    )
    .map_err(BackupClientError::Client)?;
    client.set_request_identity(request.request.clone());
    let payload = json!({
        "operation": BACKUP_VERIFY_OPERATION,
        "bundle_hex": params.bundle_hex.as_str(),
    });
    let response = client
        .transact_json(BACKUP_VERIFY_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_VERIFY_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    match envelope_status(&response)? {
        "ok" => {
            let result = BackupVerifyResult {
                bundle_id: envelope_text(&response, "bundle_id")?.to_owned(),
                class: envelope_text(&response, "class")?.to_owned(),
                integrity_sha256: envelope_text(&response, "integrity_sha256")?.to_owned(),
                blob_count: envelope_count(&response, "blob_count")?,
                event_count: envelope_count(&response, "event_count")?,
                receipt_count: envelope_count(&response, "receipt_count")?,
            };
            if result.class != "full_recovery"
                && result.class != "canonical_only_degraded"
                && result.class != "scope_export"
            {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            hex64(&result.integrity_sha256, "backup.integrity_sha256")
                .map_err(BackupClientError::Client)?;
            // Bounded verification proven: candidate output under a
            // verification proof ceiling.
            Ok(respond(
                request,
                CommandId::BackupVerify,
                EffectClass::Candidate,
                ProofCeiling::ScopedVerification,
                serde_json::to_value(&result)
                    .map_err(|_| BackupClientError::Client(CliError::ResultMismatch))?,
            ))
        }
        "invalid" => {
            let reason = envelope_text(&response, "reason")?.to_owned();
            let _ = envelope_text(&response, "field")?;
            // Invalid archive: reads attempted, nothing validated.
            Ok(respond(
                request,
                CommandId::BackupVerify,
                EffectClass::Read,
                ProofCeiling::Observation,
                json!({"status": "invalid", "reason": reason}),
            ))
        }
        _ => Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
}

/// Delegates one isolated restore-test command: gates plus a typed
/// execution block. Rehearsal can never select cutover: the Kernel
/// method has no cutover path, and this surface never asks for one.
pub fn backup_restore_test(
    client: &mut KernelClient,
    request: &CommandRequest,
    params: &BackupRestoreTestParams,
) -> Result<CommandResponse, BackupClientError> {
    require_command(
        request,
        CommandId::BackupRestoreTest,
        &CommandArguments::BackupRestoreTest,
    )
    .map_err(BackupClientError::Client)?;
    client.set_request_identity(request.request.clone());
    let payload = json!({
        "operation": BACKUP_RESTORE_TEST_OPERATION,
        "bundle_hex": params.bundle_hex.as_str(),
        "destination_authorization_hex": params.authorization_hex.as_str(),
        "target": {
            "target_id": params.target_id.as_str(),
            "target_lineage": params.target_lineage.as_str(),
            "target_sequence": params.target_sequence,
            "target_generation": params.target_generation,
        },
        "provisioning": {
            "dest_store_id": params.dest_store_id.as_str(),
            "residency_denominator_digest": params.residency_denominator_digest.as_str(),
            "source_snapshot_digest": params.source_snapshot_digest.as_str(),
            "capture_operation_id": params.capture_operation_id.as_str(),
        },
        "introductions": Value::Array(params.introductions.clone()),
    });
    let response = client
        .transact_json(BACKUP_RESTORE_TEST_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_RESTORE_TEST_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    match envelope_status(&response)? {
        "blocked" => {
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            let gates = response
                .get("gates_passed")
                .and_then(Value::as_array)
                .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
            let mut gates_passed = Vec::with_capacity(gates.len());
            for gate in gates {
                gates_passed.push(
                    gate.as_str()
                        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?
                        .to_owned(),
                );
            }
            if gates_passed.is_empty() {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            let result = BackupRestoreTestResult {
                missing_owner: envelope_text(&response, "missing_owner")?.to_owned(),
                reason: envelope_text(&response, "reason")?.to_owned(),
                gates_passed,
                restore_operation_id: envelope_text(&response, "restore_operation_id")?.to_owned(),
                decision_digest: envelope_text(&response, "decision_digest")?.to_owned(),
                plan_id: envelope_text(&response, "plan_id")?.to_owned(),
                bundle_sha256: envelope_text(&response, "bundle_sha256")?.to_owned(),
            };
            if result.restore_operation_id.trim().is_empty()
                || result.decision_digest.trim().is_empty()
                || result.plan_id.trim().is_empty()
                || result.bundle_sha256.trim().is_empty()
            {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            // Gates proven, execution blocked: candidate evidence under a
            // candidate-artifact ceiling (partial proof, never readiness).
            Ok(respond(
                request,
                CommandId::BackupRestoreTest,
                EffectClass::Candidate,
                ProofCeiling::CandidateArtifact,
                serde_json::to_value(&result)
                    .map_err(|_| BackupClientError::Client(CliError::ResultMismatch))?,
            ))
        }
        "invalid" | "refused" => {
            let reason = envelope_text(&response, "reason")?.to_owned();
            let _ = envelope_text(&response, "code")?;
            // Gate failure: reads attempted, nothing proven.
            Ok(respond(
                request,
                CommandId::BackupRestoreTest,
                EffectClass::Read,
                ProofCeiling::Observation,
                json!({"status": envelope_status(&response)?, "reason": reason}),
            ))
        }
        _ => Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
}
