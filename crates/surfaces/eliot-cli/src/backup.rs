//! Typed backup command surface (issue #963).
//!
//! Thin client adapters for the three backup catalogue commands: parse
//! bounded operator fields, build the closed kernel payload, delegate
//! through the correlated [`KernelClient`] front door, and decode the
//! typed reply into a closed [`BackupOperationOutcome`]. This crate never
//! opens transports beyond the client, never mints authority, and never
//! interprets a payload as canonical state: every cross-boundary fact is
//! re-checked here (command echo, idempotency echo, status, and exact
//! result shape) before it becomes a response.
//!
//! Wire contract mirror: the Kernel backup route
//! (`bins/eliot-kernel/src/request_dispatch.rs`) carries the exact
//! operation selectors and payload shapes used here; a mismatch on
//! either side refuses before effects. The typed fields travel in the
//! typed `CommandArguments` variants and in the operation payload, so an
//! empty payload can never select scope or destination silently: the
//! payload only exists after the closed parser admitted every field.
//!
//! Empty payloads never select scope or destination silently: create
//! requires an explicit scope descriptor and closed class, verify and
//! restore-test require explicit bundle bytes, restore-test additionally
//! requires explicit target descriptors, authorization bytes,
//! provisioning attestations, and an explicit introductions array.
//! Unknown outcomes stay unknown with their operation identity for
//! same-operation reconciliation — never success, never blind retry.
//!
//! The closed archive class and the proven backup lifecycle level come
//! from the protocol owner (`eliot_protocol::backup::BackupClassWire` and
//! `eliot_protocol::backup::BackupStage`), never from a second local
//! vocabulary. I5.13 fixes the operator class tokens in lower snake case
//! while the protocol enum's serde spelling is `SCREAMING_SNAKE_CASE`, so
//! [`backup_class`] is the one documented spelling decoder for both
//! spellings; the Kernel route carries the mirrored decoder for the same
//! reason, because a binary crate cannot import a surface crate.

use std::fmt::Write as _;

use eliot_contracts::EpochLineageId;
use eliot_protocol::RequestIdentity;
use eliot_protocol::backup::{BackupClassWire, BackupStage};
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

/// Bounded outcome state of a typed backup result: the archive was
/// verified and its identities were proved.
pub const BACKUP_STATE_VERIFIED: &str = "verified";
/// Bounded outcome state: the request shape failed its closed validation
/// and no owner was named.
pub const BACKUP_STATE_INVALID: &str = "invalid";
/// Bounded outcome state: a closed owner refused the admitted request
/// and named the exact missing owner.
pub const BACKUP_STATE_REFUSED: &str = "refused";
/// Bounded outcome state: the rehearsal proved its gates and execution
/// is blocked on a named owner input.
pub const BACKUP_STATE_BLOCKED: &str = "blocked";
/// Bounded outcome state of an unproven transport outcome: the request
/// may already have reached the Kernel, so the only safe next action is
/// same-operation reconciliation.
pub const BACKUP_STATE_UNKNOWN: &str = "unknown";

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

/// Requires a lowercase 64-character hex digest.
///
/// The predicate is exactly the private `lowercase_sha256` predicate of
/// `crates/foundation/eliot-protocol/src/backup.rs:220`; `eliot_protocol`
/// exposes no public digest validator, so the identical expression is
/// reused instead of inventing a second digest rule here.
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

/// Decodes the operator class token into the closed protocol class
/// vocabulary.
///
/// [`BackupClassWire`] is the only class set this surface admits; an
/// unknown token decodes to `None` and refuses instead of falling back to
/// a default class. I5.13 fixes the operator/wire tokens as
/// `full_recovery`, `canonical_only_degraded`, and `scope_export` while the
/// protocol enum's serde spelling is `SCREAMING_SNAKE_CASE`, so the two
/// spellings are bound in this one decoder and nowhere else.
///
/// [`BackupClassWire::validate_transition`] is deliberately not applied to
/// the requested class: a request carries a declared class only, and the
/// evidenced class belongs to the owning capture or verification receipt.
/// Binding an evidenced value to a request would fabricate a receipt.
fn backup_class(token: &str) -> Option<BackupClassWire> {
    match token {
        "full_recovery" => Some(BackupClassWire::FullRecovery),
        "canonical_only_degraded" => Some(BackupClassWire::CanonicalOnlyDegraded),
        "scope_export" => Some(BackupClassWire::ScopeExport),
        _ => None,
    }
}

/// Typed backup create arguments: explicit scope descriptor plus the
/// closed class vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCreateParams {
    /// Capture scope descriptor (required, bounded, never defaulted).
    pub scope_descriptor: String,
    /// Archive class exactly as the operator typed it; already admitted
    /// against the closed protocol class vocabulary.
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
    if backup_class(class).is_none() {
        return Err(CliError::InvalidArgument {
            field: "backup.class",
        });
    }
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
/// (explicitly empty allowed — never absent, never defaulted). The
/// destination must also be provably distinct from the restore target at
/// shape level; a destination equal to the target is not isolated.
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
    introductions: &[Value],
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
    if introductions.len() > BACKUP_INTRODUCTIONS_MAX {
        return Err(CliError::InvalidArgument {
            field: "backup.introductions",
        });
    }
    for entry in introductions {
        if !entry.is_object() {
            return Err(CliError::InvalidArgument {
                field: "backup.introductions",
            });
        }
    }
    if target_id == dest_store_id {
        return Err(CliError::InvalidArgument {
            field: "restore.isolation",
        });
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
        introductions: introductions.to_vec(),
    })
}

/// Closed typed result of one backup operation, and the single source of
/// both projections this surface renders.
///
/// Every field is bounded and owner-named: the routed operation, the
/// bounded outcome state, the requested class and the declared
/// source/destination identities exactly as the request carried them, the
/// stable operation identity, the effect class and proof ceiling actually
/// achieved, the proven backup lifecycle level, the gates the Kernel
/// proved, the missing or failed obligations, and the one safe next
/// reconciliation action. Archive bytes, key material, secrets, and
/// archived user data are structurally absent: a successful transport or
/// exit is not capture or restore proof, so a refused, blocked, invalid,
/// or unproven outcome never reports a proven level.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupOperationOutcome {
    /// Closed operation selector that was routed.
    pub operation: String,
    /// Bounded outcome state: one of [`BACKUP_STATE_VERIFIED`],
    /// [`BACKUP_STATE_INVALID`], [`BACKUP_STATE_REFUSED`], or
    /// [`BACKUP_STATE_BLOCKED`].
    pub state: String,
    /// Requested archive class exactly as the operator typed it, or
    /// `null` when the routed command declares no class. Never a
    /// defaulted class.
    pub requested_class: Option<String>,
    /// Capture scope descriptor the request declared, or `null` when the
    /// routed command declares none. Never a guessed or defaulted
    /// production scope.
    pub requested_scope: Option<String>,
    /// Archive identity the outcome actually proved, or `null` while no
    /// owner has attested one. Never a fabricated archive identity.
    pub archive_id: Option<String>,
    /// Stable operation identity for same-operation reconciliation: the
    /// correlated request's idempotency key, echoed from the request and
    /// never taken from the reply body.
    pub operation_id: String,
    /// Source identity the request declared, or `null` when the routed
    /// command declares none. Never a guessed production source
    /// installation.
    pub source_identity: Option<String>,
    /// Destination identity the request declared, or `null` when the
    /// routed command declares none. Never a default production
    /// destination.
    pub destination_identity: Option<String>,
    /// Effect class the routed operation actually achieved.
    pub effect: EffectClass,
    /// Proof ceiling the routed operation is bound to.
    pub proof_ceiling: ProofCeiling,
    /// Bounded backup lifecycle level actually proven. Backup existence
    /// is not recovery proof (I5.13), so a refused, blocked, or invalid
    /// outcome never advances past [`BackupStage::Requested`].
    pub proof_level: BackupStage,
    /// Gates the Kernel proved, in pass order; empty when the command
    /// proves no rehearsal gate.
    pub gates_passed: Vec<String>,
    /// Bounded missing or failed obligations, each naming the exact owner
    /// or field the outcome is waiting on.
    pub missing_obligations: Vec<String>,
    /// The single safe next reconciliation action for this outcome. It
    /// always names the same operation identity and never proposes a
    /// second capture or a second restore.
    pub next_reconciliation: String,
    /// Bounded reason text. Never a secret and never archived user data.
    pub reason: String,
}

/// Bounded projection of an operation whose transport outcome is unproven.
///
/// This is deliberately a different closed type from
/// [`BackupOperationOutcome`]: an unknown transport outcome carries no
/// domain result at all, so it must not be able to borrow a domain
/// verdict. The only safe next action is to reconcile the same operation
/// identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupUnknownOutcome {
    /// Closed operation selector whose outcome is unproven.
    pub operation: String,
    /// Bounded state: always [`BACKUP_STATE_UNKNOWN`].
    pub state: String,
    /// Stable operation identity to reconcile; the correlated request's
    /// idempotency key, never a freshly minted one.
    pub operation_id: String,
    /// Bounded transport detail. Never a secret.
    pub detail: String,
    /// The single safe next action: reconcile this exact operation.
    pub next_reconciliation: String,
}

/// Builds the same-operation reconciliation projection for an unproven
/// transport outcome.
///
/// A request whose reply never arrived may already have been admitted by
/// the Kernel, so the only safe next action is to reconcile the *same*
/// operation identity. This projection never proposes a second capture or
/// a second restore, and it never reports success.
pub fn backup_unknown_outcome(
    operation: &str,
    request: &RequestIdentity,
    transport_detail: &str,
) -> BackupUnknownOutcome {
    BackupUnknownOutcome {
        operation: operation.to_owned(),
        state: BACKUP_STATE_UNKNOWN.to_owned(),
        operation_id: request.idempotency_key.clone(),
        detail: transport_detail.to_owned(),
        next_reconciliation: format!(
            "reconcile the same operation {}; a second {} is never a safe next action",
            request.idempotency_key.as_str(),
            operation
        ),
    }
}

/// Renders the bounded human projection of one typed backup outcome.
///
/// Every line is derived from the same [`BackupOperationOutcome`] value the
/// JSON projection serializes, so the two projections cannot disagree. The
/// renderer is bounded by construction: it prints only the operation, the
/// outcome state, the requested class and scope, the declared
/// source/destination identities, the archive identity, the operation
/// identity, the effect class and proof ceiling, the proven lifecycle
/// level, the gates, the missing obligations, the reason, and the one next
/// reconciliation action. It never prints archive bytes, key material,
/// secrets, or archived user data.
pub fn render_backup_outcome_human(outcome: &BackupOperationOutcome) -> String {
    let mut lines = String::with_capacity(512);
    let _ = writeln!(lines, "operation: {}", outcome.operation);
    let _ = writeln!(lines, "state: {}", outcome.state);
    let _ = writeln!(
        lines,
        "requested_class: {}",
        outcome.requested_class.as_deref().unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "requested_scope: {}",
        outcome.requested_scope.as_deref().unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "archive_id: {}",
        outcome.archive_id.as_deref().unwrap_or("not-proven")
    );
    let _ = writeln!(lines, "operation_id: {}", outcome.operation_id);
    let _ = writeln!(
        lines,
        "source: {}",
        outcome.source_identity.as_deref().unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "destination: {}",
        outcome
            .destination_identity
            .as_deref()
            .unwrap_or("not-declared")
    );
    let _ = writeln!(
        lines,
        "effect: {} proof_ceiling: {}",
        serde_json::to_string(&outcome.effect).unwrap_or_else(|_| "unknown".to_owned()),
        serde_json::to_string(&outcome.proof_ceiling).unwrap_or_else(|_| "unknown".to_owned())
    );
    let _ = writeln!(
        lines,
        "proof_level: {}",
        serde_json::to_string(&outcome.proof_level).unwrap_or_else(|_| "UNKNOWN".to_owned())
    );
    if outcome.gates_passed.is_empty() {
        let _ = writeln!(lines, "gates_passed: none");
    } else {
        let _ = writeln!(lines, "gates_passed: {}", outcome.gates_passed.join(", "));
    }
    if outcome.missing_obligations.is_empty() {
        let _ = writeln!(lines, "missing_obligations: none");
    } else {
        for obligation in &outcome.missing_obligations {
            let _ = writeln!(lines, "missing_obligation: {obligation}");
        }
    }
    let _ = writeln!(lines, "reason: {}", outcome.reason);
    let _ = writeln!(
        lines,
        "next_reconciliation: {}",
        outcome.next_reconciliation
    );
    lines
}

/// Renders the bounded human projection of one unproven transport
/// outcome, from the same [`BackupUnknownOutcome`] value the JSON
/// projection serializes.
pub fn render_backup_unknown_human(outcome: &BackupUnknownOutcome) -> String {
    let mut lines = String::with_capacity(256);
    let _ = writeln!(lines, "operation: {}", outcome.operation);
    let _ = writeln!(lines, "state: {}", outcome.state);
    let _ = writeln!(lines, "operation_id: {}", outcome.operation_id);
    let _ = writeln!(lines, "reason: {}", outcome.detail);
    let _ = writeln!(
        lines,
        "next_reconciliation: {}",
        outcome.next_reconciliation
    );
    lines
}

fn require_command(request: &CommandRequest, expected: CommandId) -> Result<(), CliError> {
    if request.command != expected {
        return Err(CliError::ArgumentCommandMismatch);
    }
    request.arguments.validate()
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

/// Closed wire status vocabulary a backup reply may carry.
///
/// `ok` is the owner's success spelling; this surface never turns it into a
/// verified outcome on its own — the exact archive identity, class, and
/// integrity digest must also decode before [`BACKUP_STATE_VERIFIED`] is
/// reported. Any other status is a typed result mismatch, never success.
const BACKUP_WIRE_OK: &str = "ok";

fn envelope_status(response: &Value) -> Result<&str, BackupClientError> {
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    if !matches!(
        status,
        BACKUP_WIRE_OK | BACKUP_STATE_INVALID | BACKUP_STATE_REFUSED | BACKUP_STATE_BLOCKED
    ) {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    Ok(status)
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

fn envelope_gates(response: &Value) -> Result<Vec<String>, BackupClientError> {
    let gates = response
        .get("gates_passed")
        .and_then(Value::as_array)
        .ok_or(BackupClientError::Client(CliError::ResultMismatch))?;
    if gates.is_empty() {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    gates
        .iter()
        .map(|gate| {
            gate.as_str()
                .map(str::to_owned)
                .ok_or(BackupClientError::Client(CliError::ResultMismatch))
        })
        .collect()
}

fn respond(
    request: &CommandRequest,
    command: CommandId,
    outcome: &BackupOperationOutcome,
) -> Result<CommandResponse, BackupClientError> {
    if outcome.operation_id != request.request.idempotency_key.as_str() {
        return Err(BackupClientError::Client(CliError::CorrelationMismatch));
    }
    Ok(CommandResponse {
        request: request.request.clone(),
        command,
        effect: outcome.effect,
        proof_ceiling: outcome.proof_ceiling,
        result: CommandResult::Forwarded {
            payload: serde_json::to_value(outcome)
                .map_err(|_| BackupClientError::Client(CliError::ResultMismatch))?,
        },
    })
}

fn next_action(state: &str, operation: &str, operation_id: &str) -> String {
    match state {
        BACKUP_STATE_INVALID => format!(
            "correct the refused field and resubmit operation {operation_id} once; no {operation} was started"
        ),
        BACKUP_STATE_VERIFIED => format!(
            "operation {operation_id} verified; backup existence is not recovery proof, so rehearse the isolated restore before treating it as a recovery point"
        ),
        _ => format!(
            "reconcile the same operation {operation_id} after the named owner lands; a second {operation} is never a safe next action"
        ),
    }
}

/// Extracts the closed typed create arguments from the routed request.
fn create_params(request: &CommandRequest) -> Result<BackupCreateParams, BackupClientError> {
    let CommandArguments::BackupCreate {
        scope_descriptor,
        class,
    } = &request.arguments
    else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_create(scope_descriptor, class).map_err(BackupClientError::Client)
}

/// Extracts the closed typed verify arguments from the routed request.
fn verify_params(request: &CommandRequest) -> Result<BackupVerifyParams, BackupClientError> {
    let CommandArguments::BackupVerify { bundle_hex } = &request.arguments else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_verify(bundle_hex).map_err(BackupClientError::Client)
}

/// Extracts the closed typed restore-test arguments from the routed request.
fn restore_test_params(
    request: &CommandRequest,
) -> Result<BackupRestoreTestParams, BackupClientError> {
    let CommandArguments::BackupRestoreTest {
        bundle_hex,
        destination_authorization_hex,
        target_id,
        target_lineage,
        target_sequence,
        target_generation,
        dest_store_id,
        residency_denominator_digest,
        source_snapshot_digest,
        capture_operation_id,
        introductions,
    } = &request.arguments
    else {
        return Err(BackupClientError::Client(CliError::ArgumentCommandMismatch));
    };
    parse_backup_restore_test(
        bundle_hex,
        destination_authorization_hex,
        target_id,
        target_lineage,
        *target_sequence,
        *target_generation,
        dest_store_id,
        residency_denominator_digest,
        source_snapshot_digest,
        capture_operation_id,
        introductions,
    )
    .map_err(BackupClientError::Client)
}

/// Routes one backup create command through the correlated Kernel front
/// door.
///
/// Create requests an archive capture, so its effect class is the
/// catalogue's reversible-mutation request bound at the candidate-artifact
/// ceiling — never a read. The only honest outcome today is the typed
/// capture-owner refusal, decoded strictly: a reply that claims a capture
/// happened, or that names a different command, correlation, or status, is
/// a typed result mismatch rather than a success.
pub fn backup_create(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupCreate).map_err(BackupClientError::Client)?;
    let params = create_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    client.set_request_identity(request.request.clone());
    // `transact_json` already sets `operation` as the envelope's routing
    // selector, so the body carries command fields only. Repeating the
    // selector inside the body would be a second routing selector the route
    // would then have to reconcile.
    let payload = json!({
        "scope_descriptor": params.scope_descriptor.as_str(),
        "class": params.class.as_str(),
    });
    let response = client
        .transact_json(BACKUP_CREATE_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_CREATE_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    if envelope_status(&response)? != BACKUP_STATE_REFUSED {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    if envelope_text(&response, "code")? != "plan_gap" {
        return Err(BackupClientError::Client(CliError::ResultMismatch));
    }
    let missing_owner = envelope_text(&response, "missing_owner")?.to_owned();
    let reason = envelope_text(&response, "reason")?.to_owned();
    // Admitted capture is not implemented: the request proved its shape and
    // nothing else, so the proven level never leaves `Requested` and the
    // effect/proof pair reports the requested mutation, not a read.
    let state = BACKUP_STATE_REFUSED;
    let outcome = BackupOperationOutcome {
        operation: BACKUP_CREATE_OPERATION.to_owned(),
        state: state.to_owned(),
        requested_class: Some(params.class.clone()),
        requested_scope: Some(params.scope_descriptor.clone()),
        archive_id: None,
        operation_id: operation_id.clone(),
        // The create payload carries no source or destination installation
        // identity, and the surface never guesses one: only the declared
        // scope above is reported.
        source_identity: None,
        destination_identity: None,
        effect: EffectClass::ReversibleMutation,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        proof_level: BackupStage::Requested,
        gates_passed: Vec::new(),
        missing_obligations: vec![missing_owner],
        next_reconciliation: next_action(state, BACKUP_CREATE_OPERATION, &operation_id),
        reason,
    };
    respond(request, CommandId::BackupCreate, &outcome)
}

/// Routes one backup verify command through the correlated Kernel front
/// door.
///
/// Verify performs bounded verification only: it can never restore, change
/// an installation, or select a cutover. A transport acknowledgement is
/// never verification proof, so only a fully decoded `ok` envelope whose
/// archive identity, class, and integrity digest all pass the closed
/// checks reports [`BACKUP_STATE_VERIFIED`]; a `plan_gap` refusal keeps the
/// outcome incomplete instead of being promoted to a verified archive.
pub fn backup_verify(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupVerify).map_err(BackupClientError::Client)?;
    let params = verify_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    client.set_request_identity(request.request.clone());
    let payload = json!({
        "bundle_hex": params.bundle_hex.as_str(),
    });
    let response = client
        .transact_json(BACKUP_VERIFY_OPERATION, payload)
        .map_err(BackupClientError::Transport)?;
    envelope_command(&response, BACKUP_VERIFY_OPERATION)?;
    envelope_idempotency(&response, &request.request)?;
    let wire_status = envelope_status(&response)?;
    // The owner's `ok` spelling is a transport-level acknowledgement. It
    // becomes a verified outcome only after the exact archive identity,
    // class, and integrity digest decode below.
    let state = match wire_status {
        BACKUP_WIRE_OK => BACKUP_STATE_VERIFIED,
        other => other,
    };
    let mut outcome = BackupOperationOutcome {
        operation: BACKUP_VERIFY_OPERATION.to_owned(),
        state: state.to_owned(),
        // Verify declares no class and no scope: the evidenced class belongs
        // to the verification owner receipt, so nothing is requested here.
        requested_class: None,
        requested_scope: None,
        archive_id: None,
        operation_id: operation_id.clone(),
        // The verify reply contract declares no source or destination
        // installation identity, and the surface never invents one.
        source_identity: None,
        destination_identity: None,
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        proof_level: BackupStage::Requested,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: next_action(state, BACKUP_VERIFY_OPERATION, &operation_id),
        reason: String::new(),
    };
    match wire_status {
        BACKUP_WIRE_OK => {
            // A transport acknowledgement is not verification proof: the
            // exact archive identity, the closed class, and the integrity
            // digest must all decode before any verified level is reported.
            let bundle_id = envelope_text(&response, "bundle_id")?.to_owned();
            non_blank(&bundle_id, "backup.bundle_id").map_err(BackupClientError::Client)?;
            let class = envelope_text(&response, "class")?;
            if backup_class(class).is_none() {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            let integrity_sha256 = envelope_text(&response, "integrity_sha256")?.to_owned();
            hex64(&integrity_sha256, "backup.integrity_sha256")
                .map_err(BackupClientError::Client)?;
            for (field, count) in [
                ("blob_count", envelope_count(&response, "blob_count")?),
                ("event_count", envelope_count(&response, "event_count")?),
                ("receipt_count", envelope_count(&response, "receipt_count")?),
            ] {
                outcome.gates_passed.push(format!("{field}={count}"));
            }
            BACKUP_STATE_VERIFIED.clone_into(&mut outcome.state);
            outcome.archive_id = Some(bundle_id);
            outcome.requested_class = Some(class.to_owned());
            outcome.proof_level = BackupStage::Verified;
            "bounded archive verification reported by the verifier owner"
                .clone_into(&mut outcome.reason);
            outcome.next_reconciliation = next_action(
                BACKUP_STATE_VERIFIED,
                BACKUP_VERIFY_OPERATION,
                &operation_id,
            );
        }
        BACKUP_STATE_INVALID => {
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            let _ = envelope_text(&response, "field")?;
            outcome.missing_obligations = vec![format!("invalid field: {}", outcome.reason)];
        }
        BACKUP_STATE_REFUSED => {
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            outcome.missing_obligations =
                vec![envelope_text(&response, "missing_owner")?.to_owned()];
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
        }
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
    respond(request, CommandId::BackupVerify, &outcome)
}

/// Routes one isolated restore-test command through the correlated Kernel
/// front door.
///
/// The rehearsal runs in full isolation and can never cut over, retire the
/// source, or select an installation change: this surface never asks for
/// one and the Kernel method has no cutover path. Execution is blocked on a
/// named owner input, so the proven level stays [`BackupStage::Requested`]
/// and the stable operation identity — the correlated idempotency key, never
/// a value read back from the reply body — is what the owner lane
/// reconciles.
pub fn backup_restore_test(
    client: &mut KernelClient,
    request: &CommandRequest,
) -> Result<CommandResponse, BackupClientError> {
    require_command(request, CommandId::BackupRestoreTest).map_err(BackupClientError::Client)?;
    let params = restore_test_params(request)?;
    let operation_id = request.request.idempotency_key.clone();
    client.set_request_identity(request.request.clone());
    let payload = json!({
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
    let state = envelope_status(&response)?;
    let mut outcome = BackupOperationOutcome {
        operation: BACKUP_RESTORE_TEST_OPERATION.to_owned(),
        state: state.to_owned(),
        requested_class: None,
        requested_scope: None,
        archive_id: None,
        operation_id: operation_id.clone(),
        // Exactly the identities the request declared: the capture
        // operation that produced the source snapshot, and the provisioned
        // isolated destination store. Neither is defaulted.
        source_identity: Some(params.capture_operation_id.clone()),
        destination_identity: Some(params.dest_store_id.clone()),
        effect: EffectClass::Candidate,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        // Gates proven, execution blocked: a rehearsal is never a
        // completed rehearsal, and never a cutover.
        proof_level: BackupStage::Requested,
        gates_passed: Vec::new(),
        missing_obligations: Vec::new(),
        next_reconciliation: next_action(state, BACKUP_RESTORE_TEST_OPERATION, &operation_id),
        reason: String::new(),
    };
    match state {
        BACKUP_STATE_BLOCKED => {
            if envelope_text(&response, "code")? != "plan_gap" {
                return Err(BackupClientError::Client(CliError::ResultMismatch));
            }
            outcome.gates_passed = envelope_gates(&response)?;
            outcome.missing_obligations =
                vec![envelope_text(&response, "missing_owner")?.to_owned()];
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
        }
        BACKUP_STATE_INVALID | BACKUP_STATE_REFUSED => {
            envelope_text(&response, "reason")?.clone_into(&mut outcome.reason);
            let code = envelope_text(&response, "code")?.to_owned();
            outcome.missing_obligations = vec![format!("{state}: {code}")];
        }
        _ => return Err(BackupClientError::Client(CliError::ResultMismatch)),
    }
    respond(request, CommandId::BackupRestoreTest, &outcome)
}
