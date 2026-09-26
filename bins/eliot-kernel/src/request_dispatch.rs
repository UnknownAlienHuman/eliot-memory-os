//! Kernel front-door backup method route (issue #963).
//!
//! Closed backup entry: exactly three operations (`backup.create`,
//! `backup.verify`, `backup.restore-test`) selected by the operation string,
//! each validated to its exact payload shape before any owner is named.
//! `backup.verify` reaches the real capture owner and answers from it; the
//! other two remain rehearsal-only and perform no capture, no coordination
//! commit, no store import, and no activation/retirement/cutover. Missing
//! owners refuse as typed replies (`refused`/`blocked` with
//! `code = plan_gap`), never as fake success and never silently.
//!
//! Why each refusal is honest rather than a validation gap:
//! - `backup.create` admits bounded capture descriptors, then refuses naming
//!   the capture owner (`backup-capture-owner (#959)`, open): admitting
//!   capture here would invent authority.
//! - `backup.verify` admits the bounded inline bundle bytes, then decodes and
//!   validates them through the real capture owner
//!   ([`KernelBackupCapture::verify_only`], bound on the composition by #959
//!   and reachable through [`KernelComposition::backup_capture`]). The
//!   manifest, every member disposition, the evidenced class, the exact class
//!   ceiling and the archived-fence relation are the owner's answers: a hex
//!   shape and a self-reported checksum are never verification. What this
//!   proves is STRUCTURAL validity plus the archived fence's own validation -
//!   recomputed checksums, the class's own requirements, and a `StateFence`
//!   that is either the live session fence or this installation's own earlier
//!   authority epoch. Exact equality with the live generation is deliberately
//!   not required: it made a genuine earlier-generation archive unverifiable
//!   after the restart or epoch rotation at which verification matters most,
//!   and current-target compatibility plus epoch monotonicity belong to the
//!   isolated restore/cutover owners (A13.7 "Cutover requires separate
//!   authority"). It is NOT provenance: nothing in the path is signed,
//!   `StateFence` is publicly observable through `ServerHello`, and no member
//!   denominator is checked on the verify path, so the owner answers at the
//!   structurally-valid-candidate level with no capture receipt. A valid
//!   degraded or scope class is a real archive with a lower ceiling (I5.13:
//!   `canonical_only_degraded` "preserves semantic data only and is never
//!   advertised as operational recovery"; `scope_export` is "not an
//!   installation backup"), never `invalid`. The `eliot-backup` edge this route
//!   needs is already declared in `bins/eliot-kernel/Cargo.toml`, so no
//!   dependency is added here. The archive itself is published nowhere and no
//!   installation state is mutated, but the decided answer is recorded as one
//!   durable readback row in the Kernel's existing ORS (issue #2802): keyed by
//!   the request's own idempotency identity, committed before the reply, and
//!   read back so an exact replay after a Kernel restart or an Authority Epoch
//!   rotation returns the same owner-proved answer with its historical fence,
//!   while a changed archive under the same identity is an `IDENTITY_CONFLICT`
//!   that performs no transition (I5.27, I14.21). A store outage fails closed
//!   instead of downgrading to a non-persisted answer, because that would be a
//!   false proof claim under A0.3.
//! - `backup.restore-test` rehearses the shape path reachable without
//!   owner-held state (bounded decode, exact shapes, digest shapes, lineage
//!   admissibility, provisioning shape, store-level isolation inequality),
//!   then returns `blocked` naming the three real owners rather than a
//!   Governor transition type: the Kernel restore coordinator and the
//!   production call to it (#960), the owner-issued restore evidence - a
//!   `RestoreJournalAdmission` plus a `DestinationManifestEvidence` - (#962),
//!   and the front-door connection (#2569), all open. Measured on this tree,
//!   none of those three exists yet: there is no `restore_transitions` symbol
//!   and no `CoordinationCommit` type anywhere, and the composition's
//!   isolated-restore entry has no production caller. Owner-backed gates are
//!   marked `-deferred` in `gates_passed` and never claimed as proven.
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

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, canonical_json_bytes, sha256_hex,
};
use eliot_ipc::{PeerIdentity, Session, TransportError};
use eliot_ors::{
    BACKUP_VERIFICATION_RESULT_RECORD_TYPE, BackupVerificationDisposition,
    BackupVerificationResultRecord, CONTRACT_VERSION as ORS_CONTRACT_VERSION, OrsError,
};
use eliot_protocol::backup::BackupClassWire;
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use serde_json::{Map, Value};

use super::backup_capture::{
    MEMBER_DOMAIN_BLOB, MEMBER_DOMAIN_CANONICAL, MEMBER_DOMAIN_RECEIPT, class_name,
    member_domain_count,
};
use super::composition_bootstrap::DAEMON_FRONT_DOOR_CAPABILITY;
use super::{
    CaptureCallerAuth, CaptureReport, CaptureState, KernelCaptureError, KernelComposition,
    KernelFrameAction, status_frame,
};

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

/// Domain separator of the `backup.verify` canonical request digest (I5.27).
///
/// I5.27 binds idempotency to canonical bytes rather than to caller spelling, so
/// the digest needs a named domain that cannot collide with another operation's
/// digest over the same archive bytes.
const BACKUP_VERIFY_REQUEST_DOMAIN: &str = "eliot.kernel.backup-verify.request";
/// Canonical encoding version of the `backup.verify` request digest.
///
/// This is I5.27's `canonical_encoding_version`: a move of the number is a new
/// digest contract, never a silent reinterpretation of a retained one, and no
/// field that affects authority, scope, ordering, privacy or effect is omitted
/// or defaulted around it.
const BACKUP_VERIFY_REQUEST_ENCODING_VERSION: u16 = 1;

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

/// Projects this transport's own admission into the capture owner's
/// caller-admission shape, or fences the session.
///
/// The capture owner takes [`CaptureCallerAuth`] as owner-supplied admission
/// evidence and refuses an unadmitted caller before it touches a protected
/// owner source or publishes anything. Nothing here is taken from the payload,
/// the archive or the caller:
///
/// - the peer identity was proved by the platform adapter's SID/ACL/
///   impersonation proof ([`PeerIdentity::Authenticated`]);
/// - the session must carry exactly one capability, and it must be
///   [`DAEMON_FRONT_DOOR_CAPABILITY`] - this Kernel's own server-allowed
///   capability for the daemon/operator front-door class, read from the policy
///   declaration itself. The Host `UserAutomation` capability is the policy's
///   only other entry and its binder asserts an exact single value, and the
///   Doctor, `TestD` and native-worker binders overwrite the field with their own
///   server-minted wire ids. So an exact `daemon` match excludes every
///   specialised owner session instead of admitting "any session that happens
///   to carry one capability".
///
/// A session that fails either check is **fenced**, not answered: an
/// authorisation refusal is not a malformed request, and replying `invalid`
/// would tell the operator to correct a field they do not control. This mirrors
/// [`crate::dreamer_job_dispatch`]'s exact module-and-capability admission and
/// the `daemon_request_dispatch` module gate.
fn admit_backup_caller(session: &Session) -> Result<CaptureCallerAuth, TransportError> {
    let PeerIdentity::Authenticated {
        user_identity,
        session_identity,
        ..
    } = &session.peer
    else {
        return Err(TransportError::SessionFenced);
    };
    if session.capabilities.len() != 1 || session.capabilities[0] != DAEMON_FRONT_DOOR_CAPABILITY {
        return Err(TransportError::SessionFenced);
    }
    Ok(CaptureCallerAuth {
        principal: format!("{user_identity}@{session_identity}"),
        capability: session.capabilities[0].clone(),
        admitted: true,
    })
}

/// Bounds one owner-supplied reason before it reaches the operator wire.
///
/// Owner error text can embed archive-controlled identifiers, and the operator
/// surface documents `reason` as bounded and prints it verbatim, so a reason is
/// truncated at the route's own operator text bound instead of being relayed
/// unbounded. Truncation is on a char boundary and never splits a UTF-8
/// sequence.
fn bounded_reason(reason: &str) -> String {
    if reason.len() <= BACKUP_TEXT_MAX {
        return reason.to_owned();
    }
    let mut end = BACKUP_TEXT_MAX;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

/// Maps one typed capture-owner refusal onto the route's closed reply set.
///
/// The operator surface admits exactly three verify statuses: `ok`, `invalid`,
/// and a `plan_gap` refusal, and it treats any other `code` on a `refused`
/// reply as a result mismatch. Verify has no missing owner left to name, so
/// every owner refusal - an unadmitted caller, an incoherent archive relation,
/// an unsupported class, a budget or publication failure - is reported as a
/// typed `invalid` naming the causal class. The reason is the OWNER's own
/// `Display` text, bounded: this route never invents a second reason vocabulary
/// next to the owner's, and never renders an owner state as a Rust `Debug`
/// name on the operator wire.
fn capture_error_reply(idempotency_key: &str, error: &KernelCaptureError) -> Value {
    let field = match error {
        KernelCaptureError::NotAdmitted => "backup.caller",
        KernelCaptureError::InvalidInput { field, .. }
        | KernelCaptureError::BudgetExceeded { field } => field,
        KernelCaptureError::ClassCapabilityUnsupported { .. } => "backup.class",
        KernelCaptureError::RelationIncoherent(_)
        | KernelCaptureError::DenominatorIncomplete(_)
        | KernelCaptureError::OwnerEvidenceInvalid(_)
        | KernelCaptureError::ArchiveInvalid(_)
        | KernelCaptureError::PublicationUnknown(_) => "backup.archive",
        KernelCaptureError::Cancelled | KernelCaptureError::Unsupported { .. } => "backup.verify",
    };
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        field,
        &bounded_reason(&error.to_string()),
    )
}

/// Every owner-proved value one successful `backup.verify` answer projects.
///
/// The live owner report and the durable ORS record are both projected into
/// this one shape, so [`verified_reply`] stays the single wire projection and a
/// replayed answer cannot drift from a freshly computed one. Every field is an
/// owner answer: none is derived from the caller's `bundle_hex` spelling, none
/// is defaulted, and none is inferred from a sibling field.
struct VerifiedProjection {
    /// Archive identity the owner proved.
    backup_id: String,
    /// Evidenced archive class in the owner's own class-name spelling.
    class: String,
    /// The owner's digest of the complete encoded archive.
    archive_sha256: String,
    /// The owner's own class-ceiling spelling.
    class_ceiling: String,
    /// The evidence level the owner proved.
    verification_level: String,
    /// The archived fence's current/historical relation to this target.
    target_compatibility: String,
    /// Canonical-member denominator in the owner's own dispositions.
    event_count: u64,
    /// Receipt-obligation member denominator in the owner's own dispositions.
    receipt_count: u64,
    /// Sealed-blob obligation member denominator in the owner's own
    /// dispositions. Equal bytes under different obligations stay distinct
    /// counts instead of being coalesced into one.
    blob_count: u64,
    /// Owner-issued publication receipt, explicitly absent when the owner
    /// issued none.
    capture_receipt: Option<String>,
    /// Digest of the canonical request bytes this operation was admitted with.
    request_digest: String,
}

/// Projects one verification result into the route's `ok` envelope.
///
/// Every field is an owner answer read from `projection`: the archive identity
/// (bounded to the same operator text limit the surface applies, so a
/// structurally valid archive with an over-long identity cannot make the surface
/// return a result mismatch), the evidenced class under the owner's single
/// class-name spelling, the archive digest, the request's stable operation
/// identity, the evidence level the owner proved, the exact class ceiling and
/// archived-fence relation in the owner's own spellings, the capture receipt
/// (explicitly null when the owner has none), the per-domain member counts read
/// from the owner's own dispositions, and the canonical request digest this
/// operation was admitted under.
///
/// `operation_id` is the request's stable operation identity the route already
/// bound (`idempotency_key`), never a minted `verify-only-{backup_id}`: I5.27
/// defines idempotency over canonical bytes, "not over caller spelling or an
/// unversioned hash", and the owner only ever reports back the identity its
/// caller bound.
///
/// `request_digest` is additive. It binds this exact answer to the canonical
/// request bytes that produced it, so a later replay under the same operation
/// identity can return this same body and can tell a changed archive apart from
/// it; no existing field is removed, renamed or re-spelled.
fn verified_reply(projection: &VerifiedProjection, idempotency_key: &str) -> Value {
    // The operator surface applies its own bounded-text check to `bundle_id`
    // and would answer a result mismatch for an over-long identity, so the
    // route refuses with the owner's own class reason instead of emitting an
    // `ok` the surface cannot project.
    if projection.backup_id.len() > BACKUP_TEXT_MAX {
        return invalid_reply(
            BACKUP_VERIFY_OPERATION,
            idempotency_key,
            "backup.archive",
            "archive identity exceeds the bounded operator text length",
        );
    }
    // Explicitly null, never omitted: no retained-artifact owner issues a
    // capture receipt on this path. The missing symbol is a production
    // `impl PublicationPort`; the only implementation is `MemPublisher` inside
    // `bins/eliot-kernel/tests/backup_capture.rs`.
    let capture_receipt = projection
        .capture_receipt
        .clone()
        .map_or(Value::Null, Value::String);
    backup_reply(
        BACKUP_VERIFY_OPERATION,
        "ok",
        idempotency_key,
        vec![
            ("bundle_id", Value::String(projection.backup_id.clone())),
            ("class", Value::String(projection.class.clone())),
            (
                "integrity_sha256",
                Value::String(projection.archive_sha256.clone()),
            ),
            ("operation_id", Value::String(idempotency_key.to_owned())),
            (
                "verification_level",
                Value::String(projection.verification_level.clone()),
            ),
            (
                "class_ceiling",
                Value::String(projection.class_ceiling.clone()),
            ),
            (
                "target_compatibility",
                Value::String(projection.target_compatibility.clone()),
            ),
            ("capture_receipt", capture_receipt),
            ("event_count", Value::from(projection.event_count)),
            ("receipt_count", Value::from(projection.receipt_count)),
            ("blob_count", Value::from(projection.blob_count)),
            (
                "request_digest",
                Value::String(projection.request_digest.clone()),
            ),
        ],
    )
}

/// Projects the live owner report into the shared successful-answer shape.
///
/// The class ceiling is the owner's own class-evidence value, so its exact
/// spelling is read through that closed type's serialization instead of a second
/// hand-written vocabulary here; a ceiling that does not serialize to a JSON
/// string is a change in that type, and the route refuses rather than projecting
/// a value the operator surface cannot bound.
fn projection_from_report(
    report: &CaptureReport,
    request_digest: String,
) -> Result<VerifiedProjection, String> {
    let Ok(Value::String(class_ceiling)) = serde_json::to_value(report.class_ceiling) else {
        return Err("class evidence ceiling is not serializable".to_owned());
    };
    Ok(VerifiedProjection {
        backup_id: report.backup_id.clone(),
        class: class_name(report.class).to_owned(),
        archive_sha256: report.archive_sha256.clone(),
        class_ceiling,
        verification_level: report.evidence_level.as_wire_name().to_owned(),
        target_compatibility: report.archived_fence_relation.as_wire_name().to_owned(),
        event_count: member_domain_count(report, MEMBER_DOMAIN_CANONICAL),
        receipt_count: member_domain_count(report, MEMBER_DOMAIN_RECEIPT),
        blob_count: member_domain_count(report, MEMBER_DOMAIN_BLOB),
        capture_receipt: report.receipt_identity.clone(),
        request_digest,
    })
}

/// Projects the durable ORS record into the shared successful-answer shape.
///
/// The stored owner answers win over anything recomputed on this call: the
/// persisted archived-fence relation is the historical one, and re-deriving it
/// against whatever generation happens to be live now is exactly the drift this
/// durable row exists to prevent.
fn projection_from_record(record: &BackupVerificationResultRecord) -> VerifiedProjection {
    VerifiedProjection {
        backup_id: record.backup_id.clone(),
        class: record.class.clone(),
        archive_sha256: record.archive_sha256.clone(),
        class_ceiling: record.class_ceiling.clone(),
        verification_level: record.verification_level.clone(),
        target_compatibility: record.target_compatibility.clone(),
        event_count: record.event_count,
        receipt_count: record.receipt_count,
        blob_count: record.blob_count,
        capture_receipt: record.capture_receipt.clone(),
        request_digest: record.request_digest.clone(),
    }
}

/// Binds one fresh owner-proved answer to its operation identity and to the
/// digest of the exact reply body it projects.
///
/// `contract_version` is ORS's own wire/storage version, so a row written under
/// a different record contract fails its read closed instead of being read back
/// as the same answer.
fn record_from_projection(
    idempotency_key: &str,
    projection: &VerifiedProjection,
    reply_digest: String,
) -> BackupVerificationResultRecord {
    BackupVerificationResultRecord {
        contract_version: ORS_CONTRACT_VERSION,
        idempotency_key: idempotency_key.to_owned(),
        request_digest: projection.request_digest.clone(),
        archive_sha256: projection.archive_sha256.clone(),
        backup_id: projection.backup_id.clone(),
        class: projection.class.clone(),
        class_ceiling: projection.class_ceiling.clone(),
        verification_level: projection.verification_level.clone(),
        target_compatibility: projection.target_compatibility.clone(),
        event_count: projection.event_count,
        receipt_count: projection.receipt_count,
        blob_count: projection.blob_count,
        capture_receipt: projection.capture_receipt.clone(),
        reply_digest,
    }
}

/// Computes the canonical request digest of one `backup.verify` operation.
///
/// Only owner-proved values enter the preimage: the fixed operation kind, its
/// canonical encoding version, this operation's domain, and the verification
/// owner's own digest of the complete encoded archive. The caller's `bundle_hex`
/// spelling is deliberately excluded - the same bytes re-spelled in another case
/// must resolve to the same operation, and a caller-authored checksum is not the
/// owner's answer (see the module docs). I5.27 forbids omitting or defaulting a
/// field that affects authority, scope, ordering, privacy or effect, so the
/// preimage names the operation kind and its version instead of a bare archive
/// digest.
fn backup_verify_request_digest(archive_sha256: &str) -> Result<String, String> {
    let preimage = serde_json::json!({
        "archive_sha256": archive_sha256,
        "canonical_encoding_version": BACKUP_VERIFY_REQUEST_ENCODING_VERSION,
        "domain_separator": BACKUP_VERIFY_REQUEST_DOMAIN,
        "semantic_command_kind": BACKUP_VERIFY_OPERATION,
    });
    let bytes = canonical_json_bytes(&preimage).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// Digest over the exact reply body one verification projects.
///
/// A replay recomputes this against the stored value, so a row that cannot
/// rebuild the body it claims to hold fails closed instead of projecting a body
/// it never produced.
fn reply_body_digest(body: &Value) -> Result<String, String> {
    let bytes = canonical_json_bytes(body).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// Projects the I5.27 identity conflict for a reused operation identity.
///
/// Reusing an idempotency key with a different canonical request hash returns
/// `IDENTITY_CONFLICT` and performs no transition, so the refusal names the two
/// bounded digests and nothing else: no archive bytes, no caller text, and no
/// stored answer is projected into a refusal. `bound_request_digest` is
/// optional because a conflict observed at stage time can be answered before the
/// bound row could be read back.
fn identity_conflict_reply(
    idempotency_key: &str,
    bound_request_digest: Option<&str>,
    presented_request_digest: &str,
) -> Value {
    let reason = bound_request_digest.map_or_else(
        || {
            format!(
                "IDENTITY_CONFLICT: idempotency key is already bound to a different canonical request than {presented_request_digest}; no transition"
            )
        },
        |bound| {
            format!(
                "IDENTITY_CONFLICT: idempotency key already bound to request digest {bound}; presented request digest {presented_request_digest}; no transition"
            )
        },
    );
    backup_reply(
        BACKUP_VERIFY_OPERATION,
        "invalid",
        idempotency_key,
        vec![
            ("code", Value::String("identity_conflict".to_owned())),
            ("field", Value::String("backup.verify".to_owned())),
            ("reason", Value::String(bounded_reason(&reason))),
        ],
    )
}

/// Fail-closed reply used when no durable row backs this operation identity.
///
/// A store outage must never silently downgrade to a non-persisted answer: a
/// verification that claims `ok` with nothing recorded behind it is a false
/// proof claim under A0.3. The route refuses instead of answering from a
/// recompute it could not bind to an operation identity. The store's own error
/// text is deliberately not relayed here, because the operator surface prints
/// `reason` verbatim and a durable-store error can name local paths.
fn verification_not_recorded_reply(idempotency_key: &str) -> Value {
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.verify",
        "the durable verification result store did not record this operation, so no verification result is answered; this is not a verification answer",
    )
}

/// Returns whether one durable-store failure is the I5.27 identity conflict
/// rather than an outage.
///
/// The store reports a binding conflict through the same typed integrity error
/// it uses for every record family, distinguished by the record type, so the
/// route reads the published record-type constant instead of matching error
/// prose or inventing a second error type.
fn is_backup_verification_conflict(error: &OrsError) -> bool {
    matches!(
        error,
        OrsError::IntegrityProblem { record_type, .. }
            if *record_type == BACKUP_VERIFICATION_RESULT_RECORD_TYPE
    )
}

/// Returns the refusal for an owner state that is not a decided verification.
///
/// `Complete` and `Incomplete` both answer `ok`: a structurally valid archive
/// of a degraded class is a real archive with a lower ceiling, not a corrupt
/// one. I5.13 gives each class its own explicit wording -
/// `canonical_only_degraded` "preserves semantic data only and is never
/// advertised as operational recovery" and `scope_export` is "not an
/// installation backup" - and the owner's `class_ceiling` and `evidence_level`
/// carry that lower bound explicitly, so reporting it as `invalid` would
/// misstate a good archive. Only an undecided or refused owner state (`Unknown`,
/// `Cancelled`, `Unsupported`) keeps the stable-prose refusal, and no other
/// check is weakened.
fn undecided_report_reply(report: &CaptureReport, idempotency_key: &str) -> Option<Value> {
    if matches!(
        report.state,
        CaptureState::Complete | CaptureState::Incomplete { .. }
    ) {
        return None;
    }
    let reason = match &report.state {
        CaptureState::Unknown { reason } | CaptureState::Unsupported { reason } => reason.clone(),
        // Every remaining terminal state is reported with stable prose rather
        // than a Rust `Debug` name, so no owner state leaks an internal enum
        // spelling onto the operator wire.
        CaptureState::Cancelled => "capture owner cancelled the verification".to_owned(),
        CaptureState::Complete | CaptureState::Incomplete { .. } => {
            "capture owner reported a decided state after a decided-state refusal".to_owned()
        }
    };
    Some(invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.class",
        &bounded_reason(&reason),
    ))
}

/// What the durable store already holds for one verification operation.
///
/// `Absent` is a positive fact about the store, not an unknown answer: it means
/// this operation identity was never recorded, so the caller may verify and
/// stage exactly once. It is never produced from a store failure, because a
/// failure that degraded to `Absent` would answer `ok` for a result nothing
/// recorded. The bound record is boxed so this two-variant shape stays small
/// next to `Absent`.
enum PriorVerification {
    /// No durable row owns this operation identity yet.
    Absent,
    /// A durable owner-backed result already owns this operation identity.
    Bound(Box<BackupVerificationResultRecord>),
}

/// Admits the bounded inline bundle bytes one verify frame presents.
///
/// Every refusal here is a shape failure decided before any owner is named: a
/// non-object payload, an unexpected or missing key, a non-string or non-hex
/// `bundle_hex`, and empty bytes. The returned field and reason are the route's
/// own shape vocabulary; the owner's refusal vocabulary is never used for a
/// shape the owner never saw.
fn admit_verify_bundle(payload: &Value) -> Result<Vec<u8>, (&'static str, String)> {
    let Some(object) = payload.as_object() else {
        return Err(("backup.verify", "payload must be a JSON object".to_owned()));
    };
    if let Err(reason) = require_exact_keys(object, &["bundle_hex"]) {
        return Err(("backup.verify", reason));
    }
    let bundle_hex = match get_str(object, "bundle_hex") {
        Ok(bundle_hex) => bundle_hex,
        Err(reason) => return Err(("backup.bundle_hex", reason)),
    };
    let bundle_raw = match hex_bytes(bundle_hex, "backup.bundle_hex", BACKUP_WIRE_BYTES_MAX) {
        Ok(bundle_raw) => bundle_raw,
        Err(reason) => return Err(("backup.bundle_hex", reason)),
    };
    if bundle_raw.is_empty() {
        return Err((
            "backup.bundle_hex",
            "bundle bytes must be non-empty".to_owned(),
        ));
    }
    Ok(bundle_raw)
}

/// Answers from the durable owner-backed result that owns this operation.
///
/// A different canonical request hash under the same key is the I5.27 identity
/// conflict: the request performs no transition, and the stored answers are not
/// projected into a refusal. An equal hash replays the persisted result, whose
/// stored answers win over anything recomputed on this call, so an exact replay
/// after a Kernel restart or an Authority Epoch rotation reports the historical
/// archived-fence relation and the exact receipt proved then. The stored reply
/// digest is recomputed and must match; a row that cannot rebuild the body it
/// claims to hold fails closed instead of projecting one it never produced.
fn answer_bound_verification(
    record: &BackupVerificationResultRecord,
    fresh: &VerifiedProjection,
    idempotency_key: &str,
) -> Value {
    if record.request_digest != fresh.request_digest {
        return identity_conflict_reply(
            idempotency_key,
            Some(record.request_digest.as_str()),
            fresh.request_digest.as_str(),
        );
    }
    let body = verified_reply(&projection_from_record(record), idempotency_key);
    match reply_body_digest(&body) {
        Ok(digest) if digest == record.reply_digest => body,
        _ => verification_not_recorded_reply(idempotency_key),
    }
}

impl KernelComposition {
    /// Handles one backup verify frame: admits the bounded inline bundle bytes,
    /// then decodes and validates them through the real capture owner and binds
    /// the decided answer to this operation's durable identity.
    ///
    /// The owner is [`super::backup_capture::KernelBackupCapture`], already bound
    /// on the composition by #959; this route supplies only what a front door
    /// legitimately holds: the presented bytes, the session's own admission
    /// projection, the Kernel's live state fence, and the request's stable
    /// operation identity. Manifest, member integrity, the closed class rules
    /// and the archived-fence relation are the owner's answers, so a corrupted
    /// archive refuses as a typed `invalid` carrying the owner's own reason
    /// instead of a shape check passing. Shape failures refuse as `invalid`
    /// before the owner is called at all.
    ///
    /// The durable readback is consulted before the expensive recompute, and a
    /// store outage fails closed there: an answer must never be returned for a
    /// result that could not be bound to this operation's identity. A decided
    /// answer is recorded under the request's own idempotency key before it is
    /// returned, so an exact replay after a Kernel restart or an Authority Epoch
    /// rotation reads the same owner-backed result back - retaining its
    /// historical fence and its exact member denominators - while a changed
    /// archive under the same identity is an `IDENTITY_CONFLICT` that performs
    /// no transition (I5.27, I14.21).
    ///
    /// The command stays read-only in every other respect: no restore, no
    /// activation, no cutover, no key availability, no Product readiness and no
    /// installation mutation. The added effect is one durable readback row.
    fn handle_backup_verify(
        &self,
        session: &Session,
        payload: &Value,
        idempotency_key: &str,
    ) -> Result<Value, TransportError> {
        let bundle_raw = match admit_verify_bundle(payload) {
            Ok(bundle_raw) => bundle_raw,
            Err((field, reason)) => {
                return Ok(invalid_reply(
                    BACKUP_VERIFY_OPERATION,
                    idempotency_key,
                    field,
                    &reason,
                ));
            }
        };
        let caller = admit_backup_caller(session)?;
        let Ok(prior) = self.load_prior_verification(idempotency_key) else {
            return Ok(verification_not_recorded_reply(idempotency_key));
        };
        let report = match self.backup_capture().verify_only(
            &bundle_raw,
            &caller,
            &session.module_generation.state_fence,
            idempotency_key,
        ) {
            Ok(report) => report,
            Err(error) => return Ok(capture_error_reply(idempotency_key, &error)),
        };
        if let Some(refusal) = undecided_report_reply(&report, idempotency_key) {
            return Ok(refusal);
        }
        let Ok(request_digest) = backup_verify_request_digest(&report.archive_sha256) else {
            return Ok(verification_not_recorded_reply(idempotency_key));
        };
        let fresh = match projection_from_report(&report, request_digest) {
            Ok(fresh) => fresh,
            Err(reason) => {
                return Ok(invalid_reply(
                    BACKUP_VERIFY_OPERATION,
                    idempotency_key,
                    "backup.class_ceiling",
                    &bounded_reason(&reason),
                ));
            }
        };
        Ok(self.answer_backup_verify(prior, &fresh, idempotency_key))
    }

    /// Reads the durable verification result already bound to this operation.
    ///
    /// A store failure is returned, never flattened into "absent": a store
    /// outage that silently downgraded to a non-persisted answer would let this
    /// route answer `ok` for a verification with no durable result behind it,
    /// which A0.3 classifies as a false proof claim. The caller fails closed.
    fn load_prior_verification(
        &self,
        idempotency_key: &str,
    ) -> Result<PriorVerification, OrsError> {
        match self
            .p07_ors
            .load_backup_verification_result(idempotency_key)?
        {
            Some(record) => Ok(PriorVerification::Bound(Box::new(record))),
            None => Ok(PriorVerification::Absent),
        }
    }

    /// Answers one decided verification from the owner report and the store.
    ///
    /// Every branch either replays the persisted owner-backed result or records
    /// the fresh one first, so an `ok` reply never precedes its durable row.
    fn answer_backup_verify(
        &self,
        prior: PriorVerification,
        fresh: &VerifiedProjection,
        idempotency_key: &str,
    ) -> Value {
        match prior {
            PriorVerification::Bound(record) => {
                answer_bound_verification(&record, fresh, idempotency_key)
            }
            PriorVerification::Absent => self.stage_backup_verification(fresh, idempotency_key),
        }
    }

    /// Records the fresh owner-proved answer and returns the body to send.
    ///
    /// Persist-before-answer: the durable row is committed before the body is
    /// returned, so a lost response reconciles to this same persisted result
    /// (I14.21) rather than re-deriving a differently-fenced one. A concurrent
    /// stage that already bound this key is answered from the durable winner.
    fn stage_backup_verification(
        &self,
        fresh: &VerifiedProjection,
        idempotency_key: &str,
    ) -> Value {
        let body = verified_reply(fresh, idempotency_key);
        let Ok(reply_digest) = reply_body_digest(&body) else {
            return verification_not_recorded_reply(idempotency_key);
        };
        let record = record_from_projection(idempotency_key, fresh, reply_digest);
        match self.p07_ors.stage_backup_verification_result(&record) {
            Ok(BackupVerificationDisposition::Stored) => body,
            Ok(BackupVerificationDisposition::AlreadyBound(bound)) => {
                answer_bound_verification(&bound, fresh, idempotency_key)
            }
            Err(error) => self.answer_failed_stage(&fresh.request_digest, idempotency_key, &error),
        }
    }

    /// Answers after the durable stage did not succeed.
    ///
    /// The I5.27 identity conflict is the one stage failure that is an answer
    /// rather than an outage, so the bound digest is read back to make the
    /// refusal concrete. Every other failure is an outage: the effect was not
    /// recorded, and this route must not answer `ok` for it.
    fn answer_failed_stage(
        &self,
        presented_request_digest: &str,
        idempotency_key: &str,
        error: &OrsError,
    ) -> Value {
        if !is_backup_verification_conflict(error) {
            return verification_not_recorded_reply(idempotency_key);
        }
        let bound = match self
            .p07_ors
            .load_backup_verification_result(idempotency_key)
        {
            Ok(Some(record)) => Some(record.request_digest),
            Ok(None) | Err(_) => None,
        };
        identity_conflict_reply(idempotency_key, bound.as_deref(), presented_request_digest)
    }
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
/// Execution itself refuses with `plan_gap` naming the real owners rather
/// than a Governor transition type: the Kernel restore coordinator and the
/// production call to it (#960), the owner-issued `RestoreJournalAdmission`
/// and `DestinationManifestEvidence` (#962), and the front-door connection
/// (#2569), all open. Provisioning the isolated destination, admitting the
/// durable ORS restore journal and importing restore-class bytes without that
/// owner evidence would fabricate owner authority, and rehearsal never
/// activates, retires, or cuts over.
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
                    "backup-restore-owners (#960 Kernel restore coordinator and its production call; #962 owner-issued RestoreJournalAdmission and DestinationManifestEvidence; #2569 front-door connection)"
                        .to_owned(),
                ),
            ),
            (
                "reason",
                Value::String(
                    "the six rehearsal shape gates ran for real; the isolated destination, the durable ORS journal admission and the restore-class import are owner evidence no production owner supplies, and the composition's isolated-restore entry has no production caller"
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

impl KernelComposition {
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
    /// The receiver is the composition, exactly like the sibling `TestD` and
    /// Dreamer route entries: `backup.verify` reaches the real capture owner held at
    /// [`KernelComposition::backup_capture`], and no second dispatch entry is
    /// introduced. `backup.create` and `backup.restore-test` still refuse naming
    /// their missing owners, so binding the receiver changes no other behaviour.
    ///
    /// Service-readiness and peer-authentication gates stay with the
    /// `frame_dispatch` backup arm, which owns the exact pre-dispatch binding
    /// this method must not duplicate.
    pub(crate) fn dispatch_backup_frame(
        &self,
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
            BACKUP_VERIFY_OPERATION => {
                self.handle_backup_verify(session, &params, idempotency_key)?
            }
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
}
