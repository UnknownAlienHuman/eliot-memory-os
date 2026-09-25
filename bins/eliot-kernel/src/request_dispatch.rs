//! Kernel front-door backup method route (issue #963).
//!
//! Closed backup entry: exactly three operations (`backup.create`,
//! `backup.verify`, `backup.restore-test`) selected by the operation string,
//! each validated to its exact payload shape before any owner is named.
//! Rehearsal only: this route performs no capture, no coordination commit,
//! no store import, and no activation/retirement/cutover. Missing owners
//! refuse as typed replies (`refused`/`blocked` with `code = plan_gap`),
//! never as fake success and never silently.
//!
//! Why each refusal is honest rather than a validation gap:
//! - `backup.create` admits bounded capture descriptors, then refuses naming
//!   the capture owner (`backup-capture-owner (#959)`, open): admitting
//!   capture here would invent authority.
//! - `backup.verify` admits the bounded inline bundle bytes (hex shape only),
//!   then refuses naming the decode owner (`backup-verify-owner`;
//!   eliot-backup decode edge, owning lane #960 follow-up): archive decode
//!   goes real when the Cargo edge lands. No new Cargo dependency is added
//!   here.
//! - `backup.restore-test` rehearses the shape path reachable without
//!   owner-held state (bounded decode, exact shapes, digest shapes, lineage
//!   admissibility, provisioning shape, store-level isolation inequality),
//!   then returns `blocked` naming the Governor-built transitions
//!   (`governor-restore-transitions`: `CoordinationCommit` plus restore-class
//!   imports; owning lane Governor/eliotd). Owner-backed gates are marked
//!   `-deferred` in `gates_passed` and never claimed as proven.
//!
//! The dispatch-matrix arm is [`crate::frame_dispatch`]'s closed `backup`
//! operation gate; this file holds only the route. The arm fences the frame
//! before this route reads a payload field, and this route re-proves the
//! request identity, session fence join, connection join, JSON payload, and
//! exact operation allowlist for every direct caller.
//!
//! Capability cell: Kernel front-door backup dispatch (bounded backup method
//! entry). Forbidden authority: no capture orchestration, no coordination
//! commit, no store import, no activation/retirement/cutover, no second
//! dispatch vocabulary.

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
use eliot_ipc::{Session, TransportError};
use eliot_protocol::backup::BackupClassWire;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use serde_json::{Map, Value};

use super::{KernelFrameAction, status_frame};

/// Closed backup create operation selector (mirrored by the operator CLI
/// surface; the string only selects this entry, never authority).
pub(crate) const BACKUP_CREATE_OPERATION: &str = "backup.create";
/// Closed backup verify operation selector (mirrored by the operator CLI
/// surface).
pub(crate) const BACKUP_VERIFY_OPERATION: &str = "backup.verify";
/// Closed isolated restore-test operation selector (mirrored by the operator
/// CLI surface; rehearsal only, never cutover).
pub(crate) const BACKUP_RESTORE_TEST_OPERATION: &str = "backup.restore-test";

/// Maximum inline bundle bytes admitted on one backup frame payload.
///
/// Byte-exact with the CLI surface: JSON hex inflation doubles input bytes on
/// the wire, so 1 MiB of archive bytes stays within the frame budget with
/// envelope headroom. Larger archives refuse with this exact bound instead of
/// truncating or splitting across frames.
pub(crate) const BACKUP_WIRE_BYTES_MAX: usize = 1_048_576;
/// Maximum inline destination-authorization bytes, byte-exact with the CLI
/// surface: oversized input refuses here with the same bound instead of
/// reaching the (owner-held) verifier.
pub(crate) const BACKUP_AUTH_BYTES_MAX: usize = 16_384;
/// Maximum operator text field length (scope descriptors, identities),
/// byte-exact with the CLI surface.
pub(crate) const BACKUP_TEXT_MAX: usize = 256;
/// Maximum console-presented capability introductions admitted in one
/// restore-test payload, byte-exact with the CLI surface: a larger presented
/// set refuses early instead of reaching owner-held verification.
pub(crate) const BACKUP_INTRODUCTIONS_MAX: usize = 256;

/// Gates reported by the restore-test rehearsal, in pass order.
///
/// Gates without a `-deferred` suffix ran here for real against the frame
/// bytes; gates with the suffix need owner-held state and are named as
/// deferred, never claimed as proven. See [`handle_backup_restore_test`].
const RESTORE_TEST_GATES: [&str; 8] = [
    "decode",
    "validate",
    "shape",
    "authorization-shape",
    "currency-deferred",
    "provisioning",
    "isolation",
    "admission-deferred",
];

/// Field-bound shape failure, rendered as an `invalid` reply by the handlers.
struct InvalidShape {
    field: &'static str,
    reason: String,
}

fn non_blank(value: &str, field: &'static str) -> Result<(), String> {
    debug_assert!(
        !field.is_empty(),
        "non_blank requires a field name so the caller can bind the invalid reply"
    );
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err("must be non-blank with no control characters".to_owned());
    }
    if value.len() > BACKUP_TEXT_MAX {
        return Err("exceeds the bounded operator text length".to_owned());
    }
    Ok(())
}

fn hex_bytes(value: &str, field: &'static str, max_bytes: usize) -> Result<Vec<u8>, String> {
    debug_assert!(
        !field.is_empty(),
        "hex_bytes requires a field name so the caller can bind the invalid reply"
    );
    if value.len() > max_bytes.saturating_mul(2) {
        return Err("exceeds the bounded inline byte length".to_owned());
    }
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("must be even-length lowercase hex".to_owned());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let pair = std::str::from_utf8(&raw[index..index + 2])
            .map_err(|_| "must be even-length lowercase hex".to_owned())?;
        let byte = u8::from_str_radix(pair, 16)
            .map_err(|_| "must be even-length lowercase hex".to_owned())?;
        bytes.push(byte);
        index += 2;
    }
    Ok(bytes)
}

/// Requires a 64-character lowercase hex SHA-256 digest shape (length and
/// alphabet only; digest binding itself is owner-held).
///
/// The rule is the shared protocol rule, not a second one: the predicate is
/// exactly the private `lowercase_sha256` predicate of
/// `crates/foundation/eliot-protocol/src/backup.rs:220` (64 characters, and
/// every byte an ASCII hex digit that is not an ASCII uppercase letter).
/// `eliot_protocol` exposes no public digest validator — `lowercase_sha256`
/// is a private `fn` and is not re-exported from `crates/foundation/
/// eliot-protocol/src/lib.rs` — so the identical expression is kept here
/// rather than importing a second digest rule or widening the foundation
/// owner from this route.
fn sha256_digest_shape(value: &str, field: &'static str) -> Result<(), InvalidShape> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(InvalidShape {
            field,
            reason: "must be 64-character lowercase hex (SHA-256 digest shape)".to_owned(),
        });
    }
    Ok(())
}

/// Decodes the operator class token into the closed protocol class vocabulary.
///
/// [`BackupClassWire`] is the single class owner and the only closed class
/// set this route admits; an unknown token decodes to `None` and refuses. The
/// function is a spelling decoder only, never a second class set: I5.13 fixes
/// the operator/wire tokens as `full_recovery`, `canonical_only_degraded`,
/// and `scope_export`, while the protocol enum's serde spelling is
/// `SCREAMING_SNAKE_CASE`, so the two spellings must be bound in one place.
///
/// [`BackupClassWire::validate_transition`] has no applicable site on this
/// entry: a request carries a declared class only, and the evidenced class
/// belongs to the capture owner's receipt (`backup-capture-owner (#959)`,
/// open). Binding an evidenced value here would fabricate a receipt, so the
/// transition check is left to the owner that can actually attest one.
fn backup_class(token: &str) -> Option<BackupClassWire> {
    match token {
        "full_recovery" => Some(BackupClassWire::FullRecovery),
        "canonical_only_degraded" => Some(BackupClassWire::CanonicalOnlyDegraded),
        "scope_export" => Some(BackupClassWire::ScopeExport),
        _ => None,
    }
}

fn get_str<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("required string field '{key}' is missing"))
}

fn get_u64(object: &Map<String, Value>, key: &str) -> Result<u64, String> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("required unsigned integer field '{key}' is missing"))
}

fn get_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, String> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("required object field '{key}' is missing"))
}

fn require_exact_keys(object: &Map<String, Value>, keys: &[&str]) -> Result<(), String> {
    for key in object.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(format!("unexpected payload field '{key}'"));
        }
    }
    for key in keys {
        if !object.contains_key(*key) {
            return Err(format!("required payload field '{key}' is missing"));
        }
    }
    Ok(())
}

/// Returns whether the operation string selects the closed backup route.
///
/// The operation string only selects this entry; every call still proves its
/// exact payload shape, session joins, and fence below. Unknown operations
/// never reach the handlers.
///
/// The three selectors stay literals because the protocol's own operation
/// vocabulary is a different, non-interchangeable one:
/// `eliot_protocol::backup::BackupOperationKind` names backup *control*
/// operations (`REQUEST_CAPTURE`, `VERIFY_ARCHIVE`,
/// `PREPARE_ISOLATED_RESTORE`, `RESTORE_STEP`, `COMPLETE_REHEARSAL`, …) at
/// `crates/foundation/eliot-protocol/src/backup.rs:257`, while these strings
/// name the front-door *method selectors* the operator surface and
/// `frame_dispatch` route on. Deriving one from the other would assert an
/// identity the protocol does not state, and `backup.restore-test` has no
/// single protocol kind at all: the isolated rehearsal spans destination
/// preparation, restore steps, and rehearsal completion.
pub(crate) fn is_backup_operation(operation: &str) -> bool {
    matches!(
        operation,
        BACKUP_CREATE_OPERATION | BACKUP_VERIFY_OPERATION | BACKUP_RESTORE_TEST_OPERATION
    )
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

fn invalid_reply(command: &str, idempotency_key: &str, field: &str, reason: &str) -> Value {
    backup_reply(
        command,
        "invalid",
        idempotency_key,
        vec![
            ("code", Value::String("invalid".to_owned())),
            ("field", Value::String(field.to_owned())),
            ("reason", Value::String(reason.to_owned())),
        ],
    )
}

/// Handles one backup create frame: validates the bounded capture
/// descriptors, then refuses with the exact missing capture owner.
///
/// Capture orchestration belongs to the #959 owner (open everywhere):
/// admitting capture here would invent authority, so the only honest outcome
/// is a typed `plan_gap` naming that owner. Shape failures refuse as
/// `invalid` before any owner is named.
fn handle_backup_create(payload: &Value, idempotency_key: &str) -> Value {
    let Some(object) = payload.as_object() else {
        return invalid_reply(
            BACKUP_CREATE_OPERATION,
            idempotency_key,
            "backup.create",
            "payload must be a JSON object",
        );
    };
    if let Err(reason) = require_exact_keys(object, &["scope_descriptor", "class"]) {
        return invalid_reply(
            BACKUP_CREATE_OPERATION,
            idempotency_key,
            "backup.create",
            &reason,
        );
    }
    let scope = match get_str(object, "scope_descriptor") {
        Ok(scope) => scope,
        Err(reason) => {
            return invalid_reply(
                BACKUP_CREATE_OPERATION,
                idempotency_key,
                "backup.scope_descriptor",
                &reason,
            );
        }
    };
    if let Err(reason) = non_blank(scope, "backup.scope_descriptor") {
        return invalid_reply(
            BACKUP_CREATE_OPERATION,
            idempotency_key,
            "backup.scope_descriptor",
            &reason,
        );
    }
    let class = match get_str(object, "class") {
        Ok(class) => class,
        Err(reason) => {
            return invalid_reply(
                BACKUP_CREATE_OPERATION,
                idempotency_key,
                "backup.class",
                &reason,
            );
        }
    };
    if backup_class(class).is_none() {
        return invalid_reply(
            BACKUP_CREATE_OPERATION,
            idempotency_key,
            "backup.class",
            "must be full_recovery, canonical_only_degraded, or scope_export",
        );
    }
    refused_reply(
        BACKUP_CREATE_OPERATION,
        idempotency_key,
        "plan_gap",
        "backup-capture-owner (#959)",
        "admitted capture is not implemented; rehearsal-only paths cannot invent it",
    )
}

/// Handles one backup verify frame: admits the bounded inline bundle bytes by
/// hex shape, then refuses with the exact missing decode owner.
///
/// Archive decode belongs to the eliot-backup edge (owning lane #960
/// follow-up, open): decoding without it would invent the owner library, so
/// the only honest outcome after shape admission is a typed `plan_gap`
/// naming that edge. Shape failures refuse as `invalid` before any owner is
/// named. Decode goes real when the Cargo edge lands; no new Cargo
/// dependency is added here.
fn handle_backup_verify(payload: &Value, idempotency_key: &str) -> Value {
    let Some(object) = payload.as_object() else {
        return invalid_reply(
            BACKUP_VERIFY_OPERATION,
            idempotency_key,
            "backup.verify",
            "payload must be a JSON object",
        );
    };
    if let Err(reason) = require_exact_keys(object, &["bundle_hex"]) {
        return invalid_reply(
            BACKUP_VERIFY_OPERATION,
            idempotency_key,
            "backup.verify",
            &reason,
        );
    }
    let bundle_hex = match get_str(object, "bundle_hex") {
        Ok(bundle_hex) => bundle_hex,
        Err(reason) => {
            return invalid_reply(
                BACKUP_VERIFY_OPERATION,
                idempotency_key,
                "backup.bundle_hex",
                &reason,
            );
        }
    };
    let bundle_raw = match hex_bytes(bundle_hex, "backup.bundle_hex", BACKUP_WIRE_BYTES_MAX) {
        Ok(bundle_raw) => bundle_raw,
        Err(reason) => {
            return invalid_reply(
                BACKUP_VERIFY_OPERATION,
                idempotency_key,
                "backup.bundle_hex",
                &reason,
            );
        }
    };
    if bundle_raw.is_empty() {
        return invalid_reply(
            BACKUP_VERIFY_OPERATION,
            idempotency_key,
            "backup.bundle_hex",
            "bundle bytes must be non-empty",
        );
    }
    refused_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "plan_gap",
        "backup-verify-owner (eliot-backup decode edge; owning lane: #960 follow-up)",
        "inline bundle bytes admit bounded hex shape here; archive decode goes real when the Cargo edge lands",
    )
}

/// Validates the restore target shape and binds the exact authority tuple,
/// returning the admitted target identity.
///
/// `EpochLineageId::new` proves canonical lineage spelling, `NonZeroU64`
/// plus `EpochId::new` bind the exact `(lineage_id, sequence)` authority
/// tuple, and `ResourceGeneration::new` proves a nonzero generation; all
/// three contract imports compile directly against current main.
fn restore_target_shape(target: &Map<String, Value>) -> Result<String, InvalidShape> {
    require_exact_keys(
        target,
        &[
            "target_id",
            "target_lineage",
            "target_sequence",
            "target_generation",
        ],
    )
    .map_err(|reason| InvalidShape {
        field: "backup.target",
        reason,
    })?;
    let target_id = get_str(target, "target_id")
        .map_err(|reason| InvalidShape {
            field: "restore.target_id",
            reason,
        })?
        .to_owned();
    non_blank(&target_id, "restore.target_id").map_err(|reason| InvalidShape {
        field: "restore.target_id",
        reason,
    })?;
    let lineage_id =
        EpochLineageId::new(
            get_str(target, "target_lineage").map_err(|reason| InvalidShape {
                field: "restore.target_lineage",
                reason,
            })?,
        )
        .map_err(|_| InvalidShape {
            field: "restore.target_lineage",
            reason: "target lineage is not a canonical UUID".to_owned(),
        })?;
    let sequence =
        NonZeroU64::new(
            get_u64(target, "target_sequence").map_err(|reason| InvalidShape {
                field: "restore.target_sequence",
                reason,
            })?,
        )
        .ok_or(InvalidShape {
            field: "restore.target_sequence",
            reason: "target sequence must be nonzero".to_owned(),
        })?;
    // Binds the exact authority tuple; the constructor is infallible on main
    // but the binding itself is the proof the rehearsal carries.
    let _authority_epoch = EpochId::new(lineage_id, sequence).map_err(|_| InvalidShape {
        field: "restore.target_sequence",
        reason: "target authority epoch is not admissible".to_owned(),
    })?;
    let _resource_generation =
        ResourceGeneration::new(get_u64(target, "target_generation").map_err(|reason| {
            InvalidShape {
                field: "restore.target_generation",
                reason,
            }
        })?)
        .map_err(|_| InvalidShape {
            field: "restore.target_generation",
            reason: "target resource generation must be nonzero".to_owned(),
        })?;
    Ok(target_id)
}

/// Validates the restore provisioning shape, returning the admitted
/// destination store identity for the isolation check.
fn restore_provisioning_shape(provisioning: &Map<String, Value>) -> Result<String, InvalidShape> {
    require_exact_keys(
        provisioning,
        &[
            "dest_store_id",
            "residency_denominator_digest",
            "source_snapshot_digest",
            "capture_operation_id",
        ],
    )
    .map_err(|reason| InvalidShape {
        field: "backup.provisioning",
        reason,
    })?;
    let dest_store_id = get_str(provisioning, "dest_store_id")
        .map_err(|reason| InvalidShape {
            field: "restore.dest_store_id",
            reason,
        })?
        .to_owned();
    non_blank(&dest_store_id, "restore.dest_store_id").map_err(|reason| InvalidShape {
        field: "restore.dest_store_id",
        reason,
    })?;
    sha256_digest_shape(
        get_str(provisioning, "residency_denominator_digest").map_err(|reason| InvalidShape {
            field: "restore.residency_denominator_digest",
            reason,
        })?,
        "restore.residency_denominator_digest",
    )?;
    sha256_digest_shape(
        get_str(provisioning, "source_snapshot_digest").map_err(|reason| InvalidShape {
            field: "restore.source_snapshot_digest",
            reason,
        })?,
        "restore.source_snapshot_digest",
    )?;
    let capture_operation_id =
        get_str(provisioning, "capture_operation_id").map_err(|reason| InvalidShape {
            field: "restore.capture_operation_id",
            reason,
        })?;
    non_blank(capture_operation_id, "restore.capture_operation_id").map_err(|reason| {
        InvalidShape {
            field: "restore.capture_operation_id",
            reason,
        }
    })?;
    Ok(dest_store_id)
}

/// Handles one isolated restore-test frame: rehearses the shape path reachable
/// without owner-held state, then returns `blocked` naming the exact missing
/// Governor inputs.
///
/// Gates that run here for real: `decode` (both inline hex bodies admit
/// bounded even-length lowercase hex and decode non-empty), `validate`
/// (bounded lengths, non-blank texts, digest shapes, lineage/sequence/
/// generation admissibility), `shape` (exact-key payload/target/provisioning
/// shapes plus an explicit introductions array of JSON objects),
/// `authorization-shape` (destination authorization present, bounded, and
/// hex-shaped only — never cryptographic verification), `provisioning`
/// (provisioning exact shape plus digest shapes), and `isolation`
/// (target identity differs from the destination store identity at shape
/// level only). Gates marked `-deferred` need owner-held state:
/// `currency-deferred` (live fence currency needs the owner-held fence) and
/// `admission-deferred` (journal production admission, introduction exact-set
/// verification against live owner readback, and the admission mint need the
/// owner-held journal). Typed projection decode of introductions likewise
/// waits for the owner edge; each entry must already be a JSON object so
/// malformed rows refuse before any owner readback.
///
/// Execution itself refuses with `plan_gap` naming the Governor-built
/// coordination commit plus restore-class imports (owning lane
/// Governor/eliotd, open): committing or importing without them would
/// fabricate Governor authority, and rehearsal never activates, retires, or
/// cuts over.
#[allow(
    clippy::too_many_lines,
    reason = "one linear shape-validation sequence per rehearsal gate; splitting it would hide the exact admission order the blocked reply reports"
)]
fn handle_backup_restore_test(payload: &Value, idempotency_key: &str) -> Value {
    let Some(object) = payload.as_object() else {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.restore-test",
            "payload must be a JSON object",
        );
    };
    if let Err(reason) = require_exact_keys(
        object,
        &[
            "bundle_hex",
            "destination_authorization_hex",
            "target",
            "provisioning",
            "introductions",
        ],
    ) {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.restore-test",
            &reason,
        );
    }
    let bundle_hex = match get_str(object, "bundle_hex") {
        Ok(bundle_hex) => bundle_hex,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.bundle_hex",
                &reason,
            );
        }
    };
    let bundle_raw = match hex_bytes(bundle_hex, "backup.bundle_hex", BACKUP_WIRE_BYTES_MAX) {
        Ok(bundle_raw) => bundle_raw,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.bundle_hex",
                &reason,
            );
        }
    };
    if bundle_raw.is_empty() {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.bundle_hex",
            "bundle bytes must be non-empty",
        );
    }
    let authorization_hex = match get_str(object, "destination_authorization_hex") {
        Ok(authorization_hex) => authorization_hex,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.destination_authorization_hex",
                &reason,
            );
        }
    };
    let authorization_raw = match hex_bytes(
        authorization_hex,
        "backup.destination_authorization_hex",
        BACKUP_AUTH_BYTES_MAX,
    ) {
        Ok(authorization_raw) => authorization_raw,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.destination_authorization_hex",
                &reason,
            );
        }
    };
    if authorization_raw.is_empty() {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.destination_authorization_hex",
            "destination authorization bytes must be non-empty",
        );
    }
    let target = match get_object(object, "target") {
        Ok(target) => target,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.target",
                &reason,
            );
        }
    };
    let target_id = match restore_target_shape(target) {
        Ok(target_id) => target_id,
        Err(fault) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                fault.field,
                &fault.reason,
            );
        }
    };
    let provisioning = match get_object(object, "provisioning") {
        Ok(provisioning) => provisioning,
        Err(reason) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.provisioning",
                &reason,
            );
        }
    };
    let dest_store_id = match restore_provisioning_shape(provisioning) {
        Ok(dest_store_id) => dest_store_id,
        Err(fault) => {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                fault.field,
                &fault.reason,
            );
        }
    };
    // Console-presented introductions must be an explicit JSON array of
    // objects, never defaulted. An explicitly empty array is admitted (a
    // restore with no capability introductions has nothing to compare);
    // full source-installation isolation and exact-set verification stay
    // owner-held.
    let Some(introductions) = object.get("introductions").and_then(Value::as_array) else {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.introductions",
            "console-presented introductions must be an explicit JSON array",
        );
    };
    if introductions.len() > BACKUP_INTRODUCTIONS_MAX {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "backup.introductions",
            "exceeds the bounded console-presented introduction count",
        );
    }
    for (index, entry) in introductions.iter().enumerate() {
        if !entry.is_object() {
            return invalid_reply(
                BACKUP_RESTORE_TEST_OPERATION,
                idempotency_key,
                "backup.introductions",
                &format!("introduction {index} must be a JSON object"),
            );
        }
    }
    if target_id == dest_store_id {
        return invalid_reply(
            BACKUP_RESTORE_TEST_OPERATION,
            idempotency_key,
            "restore.isolation",
            "restore destination is not isolated from the source store at shape level",
        );
    }
    backup_reply(
        BACKUP_RESTORE_TEST_OPERATION,
        "blocked",
        idempotency_key,
        vec![
            ("code", Value::String("plan_gap".to_owned())),
            (
                "missing_owner",
                Value::String(
                    "governor-restore-transitions (CoordinationCommit plus restore-class imports; owning lane Governor/eliotd)"
                        .to_owned(),
                ),
            ),
            (
                "reason",
                Value::String(
                    "gates proven through the rehearsal shape path; execution needs the Governor-built coordination commit plus restore-class imports, which no owner supplies yet"
                        .to_owned(),
                ),
            ),
            (
                "gates_passed",
                Value::Array(
                    RESTORE_TEST_GATES
                        .iter()
                        .map(|gate| Value::String((*gate).to_owned()))
                        .collect(),
                ),
            ),
        ],
    )
}

/// Dispatches one backup frame from an admitted session.
///
/// Mirrors the sibling native-worker route entry shape: request identity
/// presence, session fence join, connection join, JSON payload, and exact
/// operation allowlist are all re-checked here so direct callers cannot
/// bypass them. The `operation` routing selector is stripped before the
/// params object reaches the handlers so their exact-key shape checks see
/// only command fields. Domain outcomes return as typed reply frames; only
/// authentication, session, fence, and routing failures fence.
///
/// Service-readiness and peer-authentication gates stay with the
/// `frame_dispatch` backup arm, which owns the exact pre-dispatch binding
/// this free function must not duplicate.
pub(crate) fn dispatch_backup_frame(
    session: &Session,
    frame: &Frame,
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
        .and_then(Value::as_str)
        .ok_or(TransportError::SessionFenced)?
        .to_owned();
    if !is_backup_operation(&operation) {
        return Err(TransportError::SessionFenced);
    }
    let idempotency_key = identity.idempotency_key.as_str();
    if idempotency_key.trim().is_empty() {
        return Err(TransportError::SessionFenced);
    }
    let params = match payload {
        Value::Object(mut map) => {
            map.remove("operation");
            // The one canonical EBP envelope is `{operation, payload}`: the
            // authenticated `KernelClient` sets `operation` as the routing
            // selector and carries the command fields inside `payload`.
            // Descend exactly one level and no deeper, so the handlers'
            // exact-key checks still see only command fields and no caller can
            // smuggle extra top-level keys past them. A frame with no
            // `payload` member keeps the flat shape, and a non-object
            // `payload` is handed on so the handlers refuse it on shape.
            match map.remove("payload") {
                Some(Value::Object(fields)) => Value::Object(fields),
                Some(other) => other,
                None => Value::Object(map),
            }
        }
        other => other,
    };
    let reply = match operation.as_str() {
        BACKUP_CREATE_OPERATION => handle_backup_create(&params, idempotency_key),
        BACKUP_VERIFY_OPERATION => handle_backup_verify(&params, idempotency_key),
        BACKUP_RESTORE_TEST_OPERATION => handle_backup_restore_test(&params, idempotency_key),
        _ => return Err(TransportError::SessionFenced),
    };
    let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, reply)?;
    frame.request_id = Some(request_id);
    frame
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(KernelFrameAction::Reply(frame))
}
