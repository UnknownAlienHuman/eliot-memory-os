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
//!   the accepted request identity's namespace digest, committed before the
//!   reply, and read back so an exact replay after a Kernel restart or an
//!   Authority Epoch rotation returns the same owner-proved answer with its
//!   historical fence, while a changed archive, source, class, scope, fence or
//!   admission under the same identity is an `IDENTITY_CONFLICT` that performs
//!   no transition (I5.27, I14.21). A store outage fails closed
//!   instead of downgrading to a non-persisted answer, because that would be a
//!   false proof claim under A0.3.
//!
//!   Since #2883 that durable key is the 64-hex namespace digest of the accepted
//!   [`BackupVerifyRequestIdentity`] — a versioned read-only verify profile of the
//!   protocol's `BackupRequestIdentity` — and never the caller's own idempotency
//!   text. That is the difference between "two callers who happen to pick the same
//!   string" and "two operations": the key is principal, authority lineage,
//!   operation id and the four profile constants, so one principal can never read,
//!   conflict with, or inherit another principal's verification result (I5.27,
//!   I15.2, A12.2). "Within one installation" is structural, not an in-band field:
//!   a row is only ever read out of the ORS file that owns it. Its exact preimage
//!   is enumerated in exactly ONE place,
//!   `eliot_ors::BackupVerifyRequestIdentity::namespace_digest`; nothing in this file
//!   restates it, so a change to the key cannot leave a stale copy of the list
//!   behind here.
//!
//!   The durable operation identity is the PRINCIPAL and its `WorkScope`, not the
//!   session. A reconnect, or any new session, by the same principal in the same
//!   scope with the same `operation_id` and the same archive is the SAME operation
//!   and replays the stored answer, with no reconciliation evidence at all — that is
//!   what acceptance clause 2 and I14.21's reconcile-by-key require, and it is why
//!   `session_id` is ambient. Issue #2883's clause 1 says "principals OR SESSIONS",
//!   which is genuinely ambiguous; this implementation reads it as per-PRINCIPAL and
//!   discloses the reading on `BackupVerifyRequestIdentity` for the owner to settle.
//!
//!   Three consequences are load-bearing and are each a typed answer rather than a
//!   silent one: a cross-principal or cross-scope hit on one key is refused with a
//!   bounded typed refusal that projects nothing; a row written under the pre-#2883
//!   raw text key is quarantined as unscoped legacy evidence and is never certified,
//!   re-keyed or projected, while bytes under that key that decode as NEITHER shape
//!   fail closed instead of being read as absent; and a caller that is NOT the
//!   principal owning an operation may read that operation's stored answer only by
//!   presenting the caller-presented evidence pair that names it exactly — the
//!   predecessor's durable namespace digest plus its canonical request hash — and
//!   only after the route has proved the caller is admitted for the front door in the
//!   same `WorkScope` and on the same authority LINEAGE, the named predecessor is the
//!   same principal's, and the presented archive is the predecessor's archive. That
//!   is the ONLY case `successor_of` exists for: the key cannot otherwise separate a
//!   non-owner from the operation it wants to read. The verify payload is therefore
//!   `{bundle_hex}` or `{bundle_hex, successor_of}`.
//!
//!   The succession evidence is CALLER-PRESENTED, not owner-issued, and the route
//!   does not pretend otherwise. It is scope-guarded, the authorization checks
//!   answer with ONE static sentence that names no class, the integrity/no-row arms
//!   answer with the fail-closed `verification_not_recorded_reply`, and the original
//!   operation identity is preserved on the answer. What it cannot prove is
//!   that the owner would authorise THIS caller to reconcile THAT operation, because
//!   no owner issues a backup-verify succession or reconciliation receipt on this
//!   product; that owner is `backup-capture-owner (#959)`, OPEN. Nothing here invents
//!   a capability, a receipt type, or an owner value to paper over that.
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
    BACKUP_VERIFICATION_RESULT_RECORD_TYPE, BACKUP_VERIFY_PROFILE_ID,
    BACKUP_VERIFY_PROFILE_VERSION, BACKUP_VERIFY_RETENTION_WINDOW, BackupVerificationDisposition,
    BackupVerificationResultRecord, BackupVerifyRequestIdentity,
    CONTRACT_VERSION as ORS_CONTRACT_VERSION, LegacyUnscopedBackupVerificationClass, OrsError,
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
/// digest over the same archive bytes. It is now one field of the accepted
/// [`BackupVerifyRequestIdentity`] rather than a preimage key, so a second
/// operation that reused the same archive bytes could not produce the same
/// durable key either.
const BACKUP_VERIFY_REQUEST_DOMAIN: &str = "eliot.kernel.backup-verify.request";
/// Canonical encoding version of the `backup.verify` request digest.
///
/// This is I5.27's `canonical_encoding_version`: a move of the number is a new
/// digest contract, never a silent reinterpretation of a retained one, and no
/// field that affects authority, scope, ordering, privacy or effect is omitted
/// or defaulted around it. It is one field of the accepted
/// [`BackupVerifyRequestIdentity`], whose own `profile_version` is the second
/// version a change to that field set must move.
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

/// Wire status of an owner cancellation: the capture owner reported that it
/// cancelled, and this route answers that as its own outcome state.
///
/// This is deliberately NOT the `invalid` status. A cancellation is not a
/// malformed request field, and MAPPING it as one was wrong on the wire:
/// `undecided_report_reply` named `backup.class` and `capture_error_reply`
/// named `backup.verify` for the very same owner answer, so a cancellation was
/// indistinguishable from a caller who typed a bad class token, and the owner's
/// cleanup state was dropped on the floor in both cases. Issue #963 requires
/// that "Cancellation retains owner cleanup state", so the cancellation gets a
/// status of its own, which the operator surface decodes as
/// `BACKUP_STATE_CANCELLED` (the constant lives in `eliot_cli::backup`; it is
/// named here in plain text because this crate does not depend on that crate)
/// rather than as a field-shape failure.
///
/// State the limit honestly, because it decides how much this constant is
/// worth: NO production owner can currently EMIT a cancellation.
/// `KernelBackupCapture::verify_only` returns only `CaptureState::Complete` or
/// `CaptureState::Incomplete`, and `KernelCaptureError::Cancelled` and
/// `KernelCaptureError::Unsupported` are constructed nowhere in the tree. So
/// this is a correct and exhaustive mapping of the owner's PUBLISHED state
/// vocabulary, not a demonstrated runtime event: no operator has yet seen a
/// cancellation misreported, and this route does not pretend otherwise. What
/// it removes is the wrong answer, so that the first owner able to cancel is
/// answered as a cancellation with its cleanup state retained.
const BACKUP_STATUS_CANCELLED: &str = "cancelled";

/// Exact I7.20 reason code for a cancellation whose cleanup this owner never
/// confirmed.
///
/// Taken from the ADDITIVE, already-documented reason-code registry in
/// `docs/architecture/I07-20-agent-facing-error-contract.md` (route/integration
/// group); this route invents no new reason code and never renames this one.
/// `CANCELLATION_UNCONFIRMED` is the honest cause rather than
/// `PROCESS_TREE_CLEANUP_FAILED` because no cleanup failure was observed: the
/// owner reported a cancellation and supplied no cleanup evidence at all, so
/// the correct claim is that cleanup is UNCONFIRMED, not that cleanup failed.
/// An operator must therefore not treat the target as clean.
const BACKUP_REASON_CANCELLATION_UNCONFIRMED: &str = "CANCELLATION_UNCONFIRMED";

/// The owner cleanup state this route reports for a cancellation.
///
/// Both cancellation carriers are UNIT variants - `CaptureState::Cancelled`
/// (`backup_capture.rs`) and `KernelCaptureError::Cancelled`
/// (`backup_capture_ports.rs`) - so the owner supplies NO cleanup evidence:
/// there is no residue report, no teardown receipt and no handle list to relay.
/// The only value this route may state is that truth, and stating it as an
/// explicit field is what keeps the owner cleanup state RETAINED instead of
/// dropped. Inventing a `clean` or `residual` value here would be a fabricated
/// cleanup fact, so the vocabulary has exactly this one member until an owner
/// actually supplies cleanup evidence; a second member is a change to the
/// owner, not to this reply.
const BACKUP_OWNER_CLEANUP_NOT_SUPPLIED: &str = "not-supplied";

/// Builds the one typed reply for a capture owner that cancelled.
///
/// Four properties are load-bearing, and each is why this is not
/// [`invalid_reply`]:
///
/// - **Same operation identity.** `idempotency_key` is the correlated request
///   identity the admitted request carried, carried through `backup_reply`
///   exactly as every other reply on this route does. This route never mints a
///   fresh identity for a cancellation, so a retry of an uncertain mutation
///   reconciles the SAME operation instead of silently starting a second
///   capture.
/// - **A named cause, not a named field.** `code` is the I7.20 reason code
///   above, so the operator gets the exact machine-readable cause rather than a
///   field they must go and fix.
/// - **The owner's own bounded reason.** `reason` is the OWNER's text passed
///   through the existing [`bounded_reason`] bound; this route does not
///   synthesise a second reason vocabulary beside the owner's, and never
///   renders an owner state as a Rust `Debug` name.
/// - **The owner cleanup state, retained.** `owner_cleanup_state` is the
///   constant above, so the operator projection keeps the fact that cleanup was
///   never confirmed instead of dropping it. It is bounded, owned text: no
///   secret, no key material, and no archived user data crosses here.
///
/// One I7.20 requirement is knowingly NOT met here, and it is recorded rather
/// than hidden: I7.20 says every non-success response includes a `disposition`,
/// an exact `reason_code`, the applicable directive and the operation identity.
/// This reply supplies the reason code, the owner's reason and the operation
/// identity, but no `disposition` key. That gap is ROUTE-WIDE and pre-existing -
/// `invalid_reply` and `refused_reply` on this same route carry no disposition
/// either - so adding one only here would leave the route speaking two
/// vocabularies, and adding it to the whole route is a wider contract change
/// than this issue may make on its own. The open point is the route owner:
/// give every backup reply one `disposition` vocabulary.
fn cancellation_reply(idempotency_key: &str, owner_reason: &str) -> Value {
    backup_reply(
        BACKUP_VERIFY_OPERATION,
        BACKUP_STATUS_CANCELLED,
        idempotency_key,
        vec![
            (
                "code",
                Value::String(BACKUP_REASON_CANCELLATION_UNCONFIRMED.to_owned()),
            ),
            (
                "owner_cleanup_state",
                Value::String(BACKUP_OWNER_CLEANUP_NOT_SUPPLIED.to_owned()),
            ),
            ("reason", Value::String(bounded_reason(owner_reason))),
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

/// Returns the authenticated `(user_identity, session_identity)` pair of one
/// session, or fences the session when the peer identity was never proved.
///
/// I15.2 binds principal identity to a launch nonce, pipe ACL/user/service SID,
/// capability token and Authority Epoch, and A12.2 states identity "is not a
/// model's self-declared string"; both values here come from
/// [`PeerIdentity::Authenticated`], which the platform adapter produced from its
/// SID/ACL/impersonation proof. Nothing is read from the payload, the archive or
/// the caller, so no frame can declare its own principal.
///
/// This is the single reader of that pair, and both
/// [`admit_backup_caller`] and [`backup_verify_identity`] call it. Be precise about
/// what that guarantees, because the two consumers are STRUCTURALLY DIFFERENT
/// values and the difference is load-bearing: `admit_backup_caller` hands the
/// capture owner a COMPOSITE `CaptureCallerAuth::principal` of
/// `format!("{user_identity}@{session_identity}")`, while the durable request
/// identity binds the BARE `user_identity` as its `principal` and keeps
/// `session_id` as a separate AMBIENT field. So they share one source and cannot
/// disagree about who the peer is, and they deliberately do NOT produce the same
/// string — and if they did, the durable key would have been per-session composite
/// and every I14.21 reconnect would have re-keyed a committed operation.
fn authenticated_backup_principal(session: &Session) -> Result<(&str, &str), TransportError> {
    let PeerIdentity::Authenticated {
        user_identity,
        session_identity,
        ..
    } = &session.peer
    else {
        return Err(TransportError::SessionFenced);
    };
    Ok((user_identity.as_str(), session_identity.as_str()))
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
///   impersonation proof ([`PeerIdentity::Authenticated`]), read through the one
///   shared [`authenticated_backup_principal`] reader;
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
    let (user_identity, session_identity) = authenticated_backup_principal(session)?;
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
/// The operator surface admits exactly four verify statuses: `ok`, `invalid`,
/// a `plan_gap` refusal, and `cancelled`. It treats any other `code` on a
/// `refused` or `cancelled` reply as a result mismatch. Verify has no missing
/// owner left to name, so every other owner refusal - an unadmitted caller, an
/// incoherent archive relation, an unsupported class, a budget or publication
/// failure - is reported as a typed `invalid` naming the causal class. The
/// reason is the OWNER's own `Display` text, bounded: this route never invents
/// a second reason vocabulary next to the owner's, and never renders an owner
/// state as a Rust `Debug` name on the operator wire.
///
/// [`KernelCaptureError::Cancelled`] is the one refusal that is NOT a
/// field-shape failure, so it is answered by [`cancellation_reply`] from its
/// own match arm and names no `field` at all. It previously shared the
/// `backup.verify` field with [`KernelCaptureError::Unsupported`], which mapped
/// a cancellation onto the wire as though a request field were malformed and
/// dropped the owner's unconfirmed cleanup state. That is a mapping defect
/// fixed, not an observed operator incident: nothing in the tree constructs
/// `Cancelled` today (see [`BACKUP_STATUS_CANCELLED`]).
fn capture_error_reply(idempotency_key: &str, error: &KernelCaptureError) -> Value {
    let field = match error {
        KernelCaptureError::Cancelled => {
            return cancellation_reply(idempotency_key, &error.to_string());
        }
        KernelCaptureError::NotAdmitted => "backup.caller",
        KernelCaptureError::InvalidInput { field, .. }
        | KernelCaptureError::BudgetExceeded { field } => field,
        KernelCaptureError::ClassCapabilityUnsupported { .. } => "backup.class",
        KernelCaptureError::RelationIncoherent(_)
        | KernelCaptureError::DenominatorIncomplete(_)
        | KernelCaptureError::OwnerEvidenceInvalid(_)
        | KernelCaptureError::ArchiveInvalid(_)
        | KernelCaptureError::PublicationUnknown(_) => "backup.archive",
        KernelCaptureError::Unsupported { .. } => "backup.verify",
    };
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        field,
        &bounded_reason(&error.to_string()),
    )
}

/// Every value one successful `backup.verify` answer projects.
///
/// The live owner report and the durable ORS record are both projected into this
/// one shape, so [`verified_reply`] stays the single wire projection and a
/// replayed answer cannot drift from a freshly computed one. `backup_id`, `class`,
/// `archive_sha256`, `class_ceiling`, `verification_level`, `target_compatibility`,
/// the three member counts and `capture_receipt` are answers the capture owner
/// returned, read from the decoded archive.
///
/// Be precise about "the owner proved" for those, because it is not one uniform
/// claim, and the surface's own evidence level is what keeps the difference
/// visible. `verification_level`, `class_ceiling`, `target_compatibility` and the
/// three member counts come from the owner's own TYPED values
/// (`CaptureEvidenceLevel`, `BackupClass::evidence_level`, `ArchivedFenceRelation`,
/// the per-domain dispositions), so their spellings really are the owner's.
/// `backup_id` and `class` are text the archive declares about itself and the
/// owner re-validates for internal consistency, and `archive_sha256` is computed by
/// the archive format itself (`BackupBundle::bundle_sha256`) — none of the three is
/// proved against a capture owner, because no production `impl PublicationPort`
/// exists on this path and `verify_only` therefore always answers
/// `StructurallyValidCandidate`. That is exactly why the surface reports a
/// structurally valid archive as a `candidate` and never as `verified`.
///
/// The other three fields are DERIVED from the accepted request identity, not owner
/// answers, and are called out as such in their own field docs: `request_digest` is
/// that identity's canonical request hash, `operation_namespace` is the durable row
/// key derived from it, and both are a function of the request rather than a claim
/// about it. No field is derived from the caller's `bundle_hex` spelling, none is
/// defaulted, and none is inferred from a sibling field.
struct VerifiedProjection {
    /// Archive identity, DECLARED by the archive and re-validated by the owner for
    /// internal consistency. Not proved against a capture owner - see the type doc.
    backup_id: String,
    /// Evidenced archive class in the ROUTE's closed wire spelling
    /// (`full_recovery` / `canonical_only_degraded` / `scope_export`), read from
    /// `identity.evidenced_class` — i.e. through the route's own `class_name`
    /// mapping from the owner's typed class, not in the protocol enum's own serde
    /// spelling. Read the class from the accepted identity rather than recomputing
    /// it from the report, so the answer, the durable row and the request hash
    /// cannot disagree about which class was presented.
    class: String,
    /// Digest of the complete encoded archive, COMPUTED by the archive format
    /// itself (`BackupBundle::bundle_sha256`) and reported by the owner. Content
    /// integrity, not a proved capture identity - see the type doc.
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
    /// Derived, not an owner answer: the canonical request hash of the accepted
    /// request identity, which since #2883 is a hash over the whole accepted
    /// request and not over one archive field.
    request_digest: String,
    /// Derived, not an owner answer: the 64-hex namespace digest of the request
    /// identity that produced this answer, i.e. the exact durable row key it lives
    /// under. Additive, so a frame-level consumer can correlate the answer to its
    /// row without being able to name another caller's.
    operation_namespace: String,
}

/// Projects one verification result into the route's `ok` envelope.
///
/// `envelope_idempotency_key` and `answer_operation_id` are deliberately TWO
/// parameters because they are two different facts, and the reply carries both:
///
/// - `envelope_idempotency_key` is ALWAYS the calling request's own
///   `idempotency_key`. It is the transport correlation this frame must answer
///   on, and the operator surface checks exactly that: it compares the envelope
///   `idempotency_key` against the caller's own request identity and answers a
///   `CorrelationMismatch` on any other value. No other route path may ever put a
///   different value in the envelope.
/// - `answer_operation_id` is the operation that PRODUCED the answer, i.e. the
///   wire `operation_id` field. On every non-reconciliation path it is the same
///   value as the envelope key, and both call sites pass it twice; it is never a
///   minted `verify-only-{backup_id}`, because I5.27 defines idempotency over
///   canonical bytes, "not over caller spelling or an unversioned hash", and the
///   owner only ever reports back the identity its caller bound.
///
/// A reconciliation is the ONE route where the two differ, and it must: the
/// reconciling session answers its own frame, but the stored answer it reads back
/// was produced by the predecessor operation, so `operation_id` preserves the
/// predecessor's identity rather than re-spelling it as the reconciling caller's.
/// Collapsing the two would either break the correlation or lose the original
/// operation identity, and the acceptance requires both.
///
/// `request_digest` is additive. It binds this exact answer to the canonical
/// request bytes that produced it, so a later replay under the same operation
/// identity can return this same body and can tell a changed archive apart from
/// it; no existing field is removed, renamed or re-spelled.
///
/// `operation_namespace` is likewise additive (#2883) and carries the 64-hex
/// namespace digest of the request identity that PRODUCED the answer, i.e. the
/// exact durable row key that answer lives under. It is one field rather than a
/// second "original namespace" field because on a reconciliation the producing
/// row and the answer are the same row: the reconciling session reads the
/// predecessor's answers and therefore the predecessor's namespace is the honest
/// value, and adding a separate field would have to invent a namespace for an
/// operation that is never stored.
///
/// It exists so a raw IPC consumer can correlate the answer to its durable row.
/// Be precise about who reads it: NO operator surface reads it —
/// `crates/surfaces/eliot-cli/src/backup.rs::verify_evidence` reads neither
/// `operation_namespace`, nor `request_digest`, nor the wire `operation_id` — so
/// it is available to a frame-level consumer and not to the current CLI. It is
/// added because the durable key stopped being caller text: without it a
/// frame-level consumer cannot tell two principals' rows apart when they share a
/// human key. It is derived from values the caller already supplied or the archive
/// already declares, so it discloses nothing a caller does not already know.
/// Nothing else is added and nothing is removed, renamed or re-spelled.
fn verified_reply(
    projection: &VerifiedProjection,
    envelope_idempotency_key: &str,
    answer_operation_id: &str,
) -> Value {
    // The operator surface applies its own bounded-text check to `bundle_id`
    // and would answer a result mismatch for an over-long identity, so the
    // route refuses with the owner's own class reason instead of emitting an
    // `ok` the surface cannot project.
    if projection.backup_id.len() > BACKUP_TEXT_MAX {
        return invalid_reply(
            BACKUP_VERIFY_OPERATION,
            envelope_idempotency_key,
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
        envelope_idempotency_key,
        vec![
            ("bundle_id", Value::String(projection.backup_id.clone())),
            ("class", Value::String(projection.class.clone())),
            (
                "integrity_sha256",
                Value::String(projection.archive_sha256.clone()),
            ),
            (
                "operation_id",
                Value::String(answer_operation_id.to_owned()),
            ),
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
            (
                "operation_namespace",
                Value::String(projection.operation_namespace.clone()),
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
///
/// The evidenced class is read from the *accepted request identity* rather than
/// recomputed from the report, and the namespace digest is the `operation_namespace`
/// PARAMETER — the caller already computed it as `identity.namespace_digest()` —
/// so the answer, the durable key and the stored identity are one value read once.
fn projection_from_report(
    report: &CaptureReport,
    identity: &BackupVerifyRequestIdentity,
    request_digest: String,
    operation_namespace: String,
) -> Result<VerifiedProjection, String> {
    let Ok(Value::String(class_ceiling)) = serde_json::to_value(report.class_ceiling) else {
        return Err("class evidence ceiling is not serializable".to_owned());
    };
    Ok(VerifiedProjection {
        backup_id: report.backup_id.clone(),
        class: identity.evidenced_class.clone(),
        archive_sha256: report.archive_sha256.clone(),
        class_ceiling,
        verification_level: report.evidence_level.as_wire_name().to_owned(),
        target_compatibility: report.archived_fence_relation.as_wire_name().to_owned(),
        event_count: member_domain_count(report, MEMBER_DOMAIN_CANONICAL),
        receipt_count: member_domain_count(report, MEMBER_DOMAIN_RECEIPT),
        blob_count: member_domain_count(report, MEMBER_DOMAIN_BLOB),
        capture_receipt: report.receipt_identity.clone(),
        request_digest,
        operation_namespace,
    })
}

/// Projects the durable ORS record into the shared successful-answer shape.
///
/// The stored owner answers win over anything recomputed on this call: the
/// persisted archived-fence relation is the historical one, and re-deriving it
/// against whatever generation happens to be live now is exactly the drift this
/// durable row exists to prevent. The same holds for the operation identity and
/// the namespace digest: a replay answers from the *stored* identity, so the
/// original operation identity is preserved rather than re-spelled as the
/// caller's, and a reconciliation answers with exactly these values because the
/// row it reads IS the operation that produced the answer. That is why
/// `operation_namespace` needs no separate "original namespace" field on a
/// reconciliation: the producing row and the answer are the same row.
fn projection_from_record(
    record: &BackupVerificationResultRecord,
) -> Result<VerifiedProjection, String> {
    let operation_namespace = record.record_key().map_err(|error| error.to_string())?;
    Ok(VerifiedProjection {
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
        operation_namespace,
    })
}

/// Binds one fresh owner-proved answer to its accepted request identity and to
/// the digest of the exact reply body it projects.
///
/// The identity is stored nested and is never flattened into a second copy that is
/// not cross-checked. Four fields ARE retained both flat and nested — the request
/// digest, the archive digest, the class and the capture receipt — because they are
/// what a reader indexes on; `BackupVerificationResultRecord::validate` re-derives
/// and compares all four on every load, so the durable key, the request digest and
/// the recorded identity cannot disagree about which request a stored answer belongs
/// to (#2883). `contract_version` is ORS's own wire/storage version, so a row written
/// under a different record contract fails its read closed instead of being read back
/// as the same answer.
fn record_from_projection(
    identity: &BackupVerifyRequestIdentity,
    projection: &VerifiedProjection,
    reply_digest: String,
) -> BackupVerificationResultRecord {
    BackupVerificationResultRecord {
        contract_version: ORS_CONTRACT_VERSION,
        identity: identity.clone(),
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

/// Constructs the accepted request identity of one read-only `backup.verify`
/// operation from owner and authenticated sources only (#2883 instructions 1
/// and 2).
///
/// Every value below has exactly one owner, and nothing here is read from the
/// caller's spelling of anything:
///
/// - `principal` and `session_id` come from
///   [`authenticated_backup_principal`], i.e. the authenticated peer's
///   `user_identity` and `session_identity`. The full `BackupRequestIdentity`
///   spells these as one `BackupAuthenticatedPrincipal` carrying a role and an
///   epoch. No `BackupRole` is available on this frame at all — no owner issues
///   one for a read-only verify — so nothing here constructs or compares a role,
///   and the admitted single front-door capability is the only role evidence this
///   route holds. The epoch is bound separately as `authority_epoch`.
/// - `capability` is the one capability [`admit_backup_caller`] admitted, so the
///   durable identity records the same capability the owner was called under.
/// - `scope_id` and `resource_generation` are the admitted `WorkScope` owner value
///   and generation of the session's module generation; `authority_epoch` is that
///   generation's current State Fence epoch. `scope_id` is operation identity;
///   the generation and the epoch's sequence are ambient observation context (see
///   `BackupVerifyRequestIdentity`'s ambient note).
/// - `archive_source_installation`, `archive_owner_contract`,
///   `archive_export_fence_digest`, `archive_sha256`, `evidenced_class` and
///   `capture_receipt` are read from the DECODED archive by the capture owner.
///   They are not caller spelling — the caller contributes only bytes, and the
///   owner decides what those bytes declare — but they are also not proved
///   against a capture owner, because none exists on this path; the one value the
///   archive format genuinely re-derives is `archive_export_fence_digest`, which
///   `BackupBundle::validate` recomputes and re-checks on every decode.
///   `archive_sha256` alone is content integrity, not the source/capture operation
///   identity (I5.27), which is why the archive's own source installation, owner
///   contract and export-fence digest travel with it.
/// - `operation_id` is the caller-provided idempotency text. It is the only
///   caller-authored value in the identity, and it is namespaced: it can never be
///   a durable key on its own.
/// - `profile_id`, `profile_version`, `idempotency_namespace`,
///   `domain_separator`, `canonical_encoding_version`, `semantic_command_kind`
///   and `retention_and_collision_window` are the versioned profile's own fixed
///   constants. This is a list of the STRUCT's constant members, deliberately not
///   a list of the durable KEY preimage: only four of them reach the key, and that
///   preimage is enumerated in exactly one place,
///   `eliot_ors::BackupVerifyRequestIdentity::namespace_digest`. The idempotency
///   namespace is derived from the profile id and version, never from the caller,
///   so it is the single place a profile change has to be declared.
///
/// The transport `launch_nonce` is deliberately NOT recorded here at all. The
/// protocol calls it "correlation-only connection data … deliberately absent from
/// this declaration and therefore cannot change its digest or act as an
/// authority-bearing identity"
/// (`crates/foundation/eliot-protocol/src/lib.rs`); putting it in a durable
/// identity would let a per-connection value re-key a committed operation on
/// every reconnect, which is instruction 4 inverted. Fresh transport correlation
/// stays on the frame's own reply, where the operator surface checks it.
///
/// `installation_id` is deliberately NOT a field here, and that is a decision
/// rather than a gap in coverage: the value this route used to bind was
/// `report.source_installation`, which is the archive's own declared
/// `export_fence.export_id` — free text inside the caller-presented `bundle_hex`,
/// checked only for non-blank shape. A caller-movable KEY component is a
/// caller-movable durable namespace, so two archives declaring different
/// `export_id`s under one human key would land on two rows and both would be
/// answered `ok` with no identity conflict. The archive's declared source is
/// therefore an ANSWER and lives in `archive_source_installation`, bound in the
/// canonical request hash, where a change is the identity conflict acceptance
/// clause 4's `source` term requires. Cross-installation separation is structural
/// instead: a durable row is only read out of the ORS file that owns it, so another
/// installation's rows are not in this table and no digest pair can name them. The
/// first real platform-independent verifying-installation identifier is where an
/// in-band field check would belong; inventing one now would mean inventing an
/// owner value.
fn backup_verify_identity(
    session: &Session,
    caller: &CaptureCallerAuth,
    report: &CaptureReport,
    idempotency_key: &str,
) -> Result<BackupVerifyRequestIdentity, String> {
    let (principal, session_id) =
        authenticated_backup_principal(session).map_err(|_| "unauthenticated peer".to_owned())?;
    let identity = BackupVerifyRequestIdentity {
        profile_id: BACKUP_VERIFY_PROFILE_ID.to_owned(),
        profile_version: BACKUP_VERIFY_PROFILE_VERSION,
        domain_separator: BACKUP_VERIFY_REQUEST_DOMAIN.to_owned(),
        idempotency_namespace: format!(
            "{BACKUP_VERIFY_PROFILE_ID}/v{BACKUP_VERIFY_PROFILE_VERSION}"
        ),
        canonical_encoding_version: BACKUP_VERIFY_REQUEST_ENCODING_VERSION,
        semantic_command_kind: BACKUP_VERIFY_OPERATION.to_owned(),
        principal: principal.to_owned(),
        session_id: session_id.to_owned(),
        capability: caller.capability.clone(),
        scope_id: session.module_generation.module_id.as_str().to_owned(),
        resource_generation: session.module_generation.generation,
        authority_epoch: session
            .module_generation
            .state_fence
            .authority_epoch
            .clone(),
        operation_id: idempotency_key.to_owned(),
        archive_sha256: report.archive_sha256.clone(),
        archive_owner_contract: report.owner_contract.clone(),
        archive_source_installation: report.source_installation.clone(),
        archive_export_fence_digest: report.export_fence_digest.clone(),
        evidenced_class: class_name(report.class).to_owned(),
        capture_receipt: report.receipt_identity.clone(),
        retention_and_collision_window: BACKUP_VERIFY_RETENTION_WINDOW.to_owned(),
        identity_digest: String::new(),
    };
    identity
        .with_computed_digest()
        .map_err(|error| error.to_string())
}

/// Computes the canonical request digest of one `backup.verify` operation.
///
/// Since #2883 the preimage is the WHOLE accepted request identity minus the three
/// ambient observation fields, and `eliot_ors::BackupVerifyIdentityPreimage` is the
/// authoritative field list — this function does not restate it, deliberately, so a
/// field added there cannot leave a stale copy of the list behind here. I5.27
/// requires exactly this: canonical encoding is versioned and a field affecting
/// authority, scope, ordering, privacy or effect cannot be omitted or defaulted
/// silently, so nothing that could decide *who may read this result* or *what the
/// result is about* is left out of the preimage, and nothing in it is given a
/// default.
///
/// Three things are NOT in the preimage, each for a stated reason, and the list is
/// exhaustive:
/// - `session_id`, `resource_generation` and `authority_epoch` — ambient
///   observation context, because binding them would make every I14.21
///   reconcile-by-key and every post-rotation replay a second stored row;
/// - `identity_digest` itself, so the digest is a function of the request and never
///   of itself;
/// - the caller's `bundle_hex` SPELLING. The same bytes re-spelled in another case
///   must resolve to the same operation, and a caller-authored checksum is not the
///   archive's answer. The archive's own `archive_sha256` IS in the preimage, so a
///   re-spelling that decodes to different bytes is still a different operation.
fn backup_verify_request_digest(identity: &BackupVerifyRequestIdentity) -> Result<String, String> {
    Ok(identity
        .clone()
        .with_computed_digest()
        .map_err(|error| error.to_string())?
        .identity_digest)
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
/// `IDENTITY_CONFLICT` and performs no transition. The refusal names the
/// PRESENTED digest and nothing else: no archive bytes, no caller text, no stored
/// answer, and — deliberately — no stored digest.
///
/// The stored digest used to be an `Option<&str>` argument here. It is gone, and
/// that is a real change in what this function can say. Rendering a stored digest
/// is only safe when the caller already owns the row it names, and after #2883
/// there is exactly one producer left: the fresh-verify path, where
/// `answer_bound_verification` and `answer_failed_stage` answer about the caller's
/// OWN key and the digest is its own freshly computed one. The reconciliation
/// path is the caller-supplied-digest case, and there a stored digest must never be
/// echoed: `stored.identity.identity_digest` is the second half of a
/// successor-evidence pair, so naming it would let a caller that failed the scope
/// or archive check assemble a valid pair for a row it is not authorised to read.
/// That path answers with [`successor_not_observed_reply`], which is digest-free.
///
/// So the single parameter is always the caller's own presented digest, and this
/// function is unreachable from any path where the presented digest is a guess.
fn identity_conflict_reply(idempotency_key: &str, presented_request_digest: &str) -> Value {
    let reason = format!(
        "IDENTITY_CONFLICT: idempotency key is already bound to a different canonical request than {presented_request_digest}; no transition"
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

/// Returns whether the live, already-admitted session may observe the one stored
/// predecessor row it named (#2883 instruction 5 "or permitted successor" and
/// instruction 7 "the new caller must still be authorized to observe/reconcile
/// that exact operation").
///
/// This is a JOIN over facts the live `Session` already holds against facts the
/// stored [`BackupVerifyRequestIdentity`] holds, and it is deliberately a JOIN and
/// nothing more. It is not a second front-door admission gate —
/// [`admit_backup_caller`] already proved the peer identity and the exact single
/// front-door capability, and `verify_only` already refused an unadmitted caller
/// through `require_capture_admitted`, both before this runs.
///
/// Only two terms survive, because only two can FAIL and a comparison that cannot
/// fail is not evidence. Each is a real cross-boundary comparison between a live
/// session value and a stored row value:
///
/// - `scope_id` against the live `session.module_generation.module_id`, the
///   admitted `WorkScope` owner value. A successor outside the predecessor's scope
///   is refused, and this cannot be a constant comparison: the two sides come from
///   different sources.
/// - authority LINEAGE: `stored.identity.authority_epoch.lineage_id` against
///   `session.module_generation.state_fence.authority_epoch.lineage_id`, compared
///   as the lineage alone. The sequence is deliberately excluded because it is
///   ambient (an Authority Epoch rotation is the same authority lineage observed
///   later), and instruction 7 says replaying a historical result after such a
///   rotation may be valid. A different lineage is a different authority and is
///   refused. `EpochId::is_same_authority` is deliberately NOT used: it is an exact
///   `(lineage_id, sequence)` compare — "true only when `lineage_id` and `sequence`
///   are both equal" (`crates/foundation/eliot-contracts/src/epoch_identity.rs`) —
///   and would refuse the very rotation this must permit.
///
/// Three comparisons that were here before are GONE because they cannot fail:
/// `capability` against `caller.capability` is constant against a value
/// `admit_backup_caller` already forced; `semantic_command_kind` against the
/// route's own operation constant is constant against constant, and the row's
/// `validate()` already pins the PROFILE ID and VERSION — not the command kind,
/// which it does not compare against anything; `retention_and_collision_window`
/// against the route's own window constant is constant against constant.
/// `resource_generation` is also gone, and that is a narrowing rather than a
/// tautology: it is ambient by the same argument as the epoch sequence, so
/// requiring it equal would forbid the post-restart, post-re-registration
/// reconciliation that the ambient rule exists to enable.
///
/// Deliberately NOT compared here, and why: `principal` and `session_id`. The
/// `principal` cross-check IS made, but in `answer_successor_verification`, because
/// it compares against the live authenticated peer rather than against a session
/// value and belongs with the rest of the reconciliation decision. `session_id` is
/// not compared anywhere, and the reason is the one that matters most on this path:
/// a new session inheriting a prior session's operation is the ENTIRE POINT of a
/// succession, so requiring session equality would make every reconciliation
/// impossible. Note what the presented `predecessor_identity_digest` does and does
/// not do: the canonical request hash covers the predecessor's principal, so the
/// evidence names WHICH principal's operation it is, but it provably does NOT cover
/// the predecessor's session — `BackupVerifyIdentityPreimage` omits `session_id` as
/// ambient, and the type doc says so. So the successor is bound to that exact
/// PRINCIPAL-and-operation, not to a session.
///
/// There is deliberately no installation field comparison here, and that is a
/// decision rather than a gap. There is no platform-independent
/// verifying-installation identifier on this frame to join against:
/// `KernelStartupBinding::installation_id` is `#[cfg(windows)]` and is not held on
/// `KernelComposition`, and the composition's `kernel_artifact_sha256` is an
/// `Option` that is `None` whenever no Host launch injected one. Binding the
/// predecessor row's own `archive_source_installation` would be a
/// self-comparison that proves nothing about the caller while looking exactly like
/// isolation, so it is not written — and that value is caller-presented archive
/// text besides. The installation scope IS enforced on this path, but
/// STRUCTURALLY: the predecessor row was read out of *this* composition's own ORS
/// file, and a row belonging to a different installation is not in this table at
/// all, so no digest pair can name it. The first real platform-independent
/// verifying-installation identifier is where a field check would belong;
/// inventing one now would mean inventing an owner value.
fn successor_may_observe(session: &Session, stored: &BackupVerificationResultRecord) -> bool {
    stored.identity.scope_id == session.module_generation.module_id.as_str()
        && stored.identity.authority_epoch.lineage_id
            == session
                .module_generation
                .state_fence
                .authority_epoch
                .lineage_id
}

/// Returns the authenticated principal of the reconciling session.
///
/// It reads the same single authenticated source as
/// [`authenticated_backup_principal`], so the principal the capture owner admitted
/// and the principal compared against the stored predecessor cannot drift apart.
/// `None` is unreachable here — [`admit_backup_caller`] already fenced the frame
/// on an unauthenticated peer — so the route treats it as a fenced transport error
/// rather than as a scope decision.
fn successor_caller_principal(session: &Session) -> Result<&str, TransportError> {
    authenticated_backup_principal(session).map(|(principal, _)| principal)
}

/// Projects the ONE refusal the failed AUTHORIZATION checks on the reconciliation
/// path answer with (instructions 4, 5, 7 and 8 on that path).
///
/// This function's sibling refusal call sites do NOT use this sentence. The load
/// miss, the row that cannot be rebuilt, and the `reply_digest` that does not
/// re-derive all answer with the fail-closed `verification_not_recorded_reply`,
/// which is the same refusal the caller's own replay path returns for an
/// untrustworthy row. So a caller can tell "no row at that key" from "a row you may
/// not read" — that residue is deliberate, and the full accounting, including the
/// count of arms on each side, is on [`answer_successor_verification`].
///
/// It is deliberately a SINGLE sentence for all of them, and that is a security
/// property, not brevity. A caller that learns a namespace digest can probe for
/// rows; when the scope, principal, digest and archive checks each answered with
/// their own class, those replies told it whether a row exists there and whether it
/// belongs to another principal or another scope — an existence and ownership oracle
/// built out of our own refusals. One sentence removes that. The stored
/// `identity_digest` is the second half of a successor-evidence pair and
/// `operation_namespace` is on the wire, so an echo anywhere on this path would hand
/// a caller the exact value that completes the pair for any row it can name.
///
/// What this DOES guarantee: no stored VALUE is extractable on this path. No
/// principal, session, scope, lineage, digest, archive identity, count, store error
/// or path ever leaves the store here. What it does NOT conceal: whether a row
/// exists at the probed key at all. A refusal is never proof of absence, and
/// separating "no such row" from "a row you may not read" would require the typed
/// classes this path used to have — which were themselves the oracle. That trade is
/// deliberate. It is also not observable by the shipped product today, because the
/// operator surface cannot send `successor_of` at all (see
/// `answer_successor_verification`).
///
/// It is routed through the same bounded reason the other refusals use, so it is
/// truncated at the route's own operator text bound and can never relay an
/// unbounded value. It is deliberately NOT a fence: a caller may be perfectly well
/// admitted and still not entitled to this operation, and fencing the session would
/// hide an ordinary scope answer behind an authorisation failure.
fn successor_not_observed_reply(idempotency_key: &str) -> Value {
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.verify",
        &bounded_reason(
            "the presented succession evidence does not name a stored verification operation this caller may observe; no stored result is projected",
        ),
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

/// Projects the typed refusal for a verification operation that belongs to a
/// DIFFERENT authenticated principal (#2883 instruction 8).
///
/// The reason names the CLASS of the refusal and nothing else: no bound
/// principal, no session id, no stored identity digest, no stored archive
/// identity, counts or capture receipt, and no store error string or path. The
/// store's own disposition is a unit variant for exactly this reason — it has no
/// field a foreign row's metadata could travel through — so this function has
/// nothing to leak even if it wanted to.
///
/// It has exactly ONE producer, the STORE's
/// [`BackupVerificationDisposition::ForeignOperation`], which compares the stored
/// row's `principal` OR its `scope_id` against the candidate. Both classes are named
/// in the reason because both are real and both are reachable:
///
/// - a different `scope_id` at the same key is an ORDINARY, uncorrupted case.
///   `scope_id` is deliberately not a key component, so two sessions of one
///   principal, on one lineage, with one `operation_id` and one archive but
///   different `WorkScope`s share one key, and a load-then-stage race between them
///   lands the second writer on the first's row here;
/// - a different `principal` at the same key is a SHA-256 collision over the key
///   preimage and is not reachable through the route; it is here for a hand-edited
///   row.
///
/// So the reason names both rather than only the reachable one: naming only the
/// collision case would misdescribe the case that actually happens, and splitting it
/// into two typed reasons would give the caller a distinguishability it has no need
/// for. The reconciliation path's own authorization refusals are a different
/// mechanism entirely — the four authorization checks there are all
/// [`successor_not_observed_reply`], one static sentence, so a caller
/// cannot use them to probe for rows it may not read.
fn foreign_operation_reply(idempotency_key: &str) -> Value {
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.verify",
        "this operation identity is bound to a different authenticated principal or work scope; no stored result is projected",
    )
}

/// Projects the typed refusal for a pre-#2883 unscoped durable row
/// (#2883 instruction 9).
///
/// A new durable key is a 64-hex namespace digest — its preimage is enumerated in
/// exactly one place, `eliot_ors::BackupVerifyRequestIdentity::namespace_digest`,
/// and is deliberately not restated here — so a legacy row's raw caller-text key
/// cannot collide with a new key and the two are told apart by shape alone. That is
/// what makes the extra probe sound: a scoped lookup returning absent is NOT proof
/// that nothing is stored under the caller's own text, because a pre-#2883 row may
/// be. The probe therefore exists precisely so a legacy row is neither silently
/// ignored NOR silently adopted: it is quarantined as unscoped evidence, never
/// certified to, re-keyed for, or projected to this caller, and the caller is told
/// to re-run under a fresh key.
///
/// The third probe outcome, bytes under that key that decode as neither shape, is
/// answered differently and more strictly: it fails closed as
/// `verification_not_recorded_reply` rather than reaching this function, because
/// staging over an unreadable row would destroy evidence and answer `ok`.
///
/// The reason deliberately echoes no stored field: not the legacy key's contents,
/// not its request digest, not its archive identity or counts. It is a class
/// statement about evidence this route refuses to rely on, and it is bounded like
/// every other reason on this route.
fn legacy_unscoped_evidence_reply(idempotency_key: &str) -> Value {
    invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.verify",
        "a pre-scoped durable result exists under the unscoped raw idempotency key; it carries no principal, session, scope or fence ownership, so it is quarantined as legacy evidence and is neither certified to, re-keyed for, nor projected here; re-run this operation under a fresh key",
    )
}

/// Returns whether one durable-store failure is the I5.27 identity conflict
/// rather than an outage.
///
/// Read the honest version of what this predicate does and does not distinguish. It
/// matches ONE variant, [`OrsError::IntegrityProblem`], filtered by the published
/// record type — so the route reads the contract constant instead of matching error
/// prose or inventing a second error type. But #2883 introduced a SECOND
/// `IntegrityProblem` for this record type, raised when a row at the staged key
/// cannot be decoded as a current-contract row at all: a corrupted row, a partial
/// write, or a shape from a future contract.
///
/// That means this predicate CONFLATES the two, and the consequence is stated
/// rather than hidden: a corrupt row at the staged key is answered to the operator
/// as `IDENTITY_CONFLICT` instead of as an outage. That is a real loss of precision,
/// and it is deliberate for now because both outcomes are fail-closed — neither
/// writes a row and neither answers `ok` — and because giving the corruption class
/// its own signal would mean either a new public `OrsError` variant or a new field
/// on the disposition, and both are a wider store contract change than this route
/// may make on its own. The open point is the ORS store owner: split the two
/// `IntegrityProblem` causes there, and this predicate becomes exact without any
/// route change.
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
/// `Cancelled`, `Unsupported`) keeps a non-`ok` answer, and no other check is
/// weakened.
///
/// `Cancelled` gets its OWN answer through [`cancellation_reply`] rather than
/// the `invalid` field-shape envelope the other two undecided states share. It
/// used to fall into that envelope as `backup.class`, which mapped a
/// cancellation onto the wire as a malformed class token and dropped the
/// owner's cleanup state entirely - so a cancellation was indistinguishable
/// from a bad class string and issue #963's "Cancellation retains owner cleanup
/// state" could not be honoured by the operator projection. `Unsupported`
/// deliberately stays on the `invalid` path: an explicitly unsupported
/// capability IS a statement about the requested class, so the `backup.class`
/// field is the truthful one for it and is not weakened here.
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
    if matches!(report.state, CaptureState::Cancelled) {
        return Some(cancellation_reply(idempotency_key, &reason));
    }
    Some(invalid_reply(
        BACKUP_VERIFY_OPERATION,
        idempotency_key,
        "backup.class",
        &bounded_reason(&reason),
    ))
}

/// What the durable store already holds for one scoped verification identity.
///
/// Be precise about who checks what, because the split matters. The STORE's
/// `validate()` supplies SHAPE, SELF-CONSISTENCY and DIGEST INCLUSION: the profile
/// id and version, the per-field text and digest shapes, the four
/// flat-versus-nested drift checks, and `identity_digest == compute_digest()`. It
/// compares NOTHING against the live caller — it cannot, it holds no session. The
/// LIVE-CALLER JOINS are this route's: the namespace key itself is scoped to
/// `(principal, authority lineage, operation id)`, and on the reconciliation path
/// `successor_may_observe` plus the principal comparison in
/// `answer_successor_verification` are what join a caller to a stored row. So
/// `Bound` means "the store proved this row is well-formed and names the operation
/// the caller addressed", NOT "the store authorised this caller".
///
/// `Absent` is a positive fact about the store, not an unknown answer: nothing is
/// stored under this identity's namespace digest AND nothing is stored under the
/// caller's raw text in any of the three probe classes. It is never produced from a
/// store failure, because a failure that degraded to `Absent` would answer `ok` for
/// a result nothing recorded. `LegacyUnscoped` is the quarantined pre-#2883 class,
/// neither replayable nor stageable, and `Unreadable` is the fail-closed arm for
/// bytes that decode as neither shape. The bound record is boxed so this shape stays
/// small next to the three unit answers.
enum PriorVerification {
    /// No durable row owns this scoped verification identity, and no pre-#2883
    /// row owns the caller's raw text either.
    Absent,
    /// A pre-#2883 unscoped row owns the caller's raw text. It is quarantined
    /// legacy evidence: never certified to, re-keyed for, or projected.
    LegacyUnscoped,
    /// Bytes are stored under the caller's raw text and decode as NEITHER the
    /// current contract nor the pre-#2883 shape. The durable row is unreadable, so
    /// the route fails closed and answers no verification result at all. This arm
    /// exists because collapsing "not a legacy row" into "absent" is fail-OPEN: it
    /// would stage a new scoped row over evidence that is still on disk and answer
    /// `ok`, which is the outcome instruction 9 and acceptance clause 6 exist to
    /// prevent.
    Unreadable,
    /// A durable owner-backed result already owns this scoped verification
    /// identity, validated under the same accepted request identity.
    Bound(Box<BackupVerificationResultRecord>),
}

/// Optional caller-presented succession evidence for a reconciliation verify
/// (#2883 instruction 4).
///
/// A fresh session may read a prior operation's stored answer ONLY by naming it
/// exactly. The two digests are that naming: the predecessor's durable namespace
/// key and the predecessor's canonical request hash. This is the same
/// predecessor-pair shape the ORS activation lifecycle already uses for
/// `successor_of` (`eliot_ors::ActivationSuccessorBinding`), reused rather than
/// a second succession family: a predecessor identity is named by a durable key
/// plus the request hash under that key.
///
/// The pair alone is deliberately not sufficient, and the checks are ordered so
/// that a wrong guess is worthless:
///
/// 1. [`successor_may_observe`] joins the live, already-admitted session against
///    the named row's `WorkScope` and authority LINEAGE. This runs FIRST, before any
///    digest comparison and before the row is used for anything observable.
/// 2. the named predecessor must belong to the SAME authenticated principal, so a
///    caller cannot read another principal's operation at all.
/// 3. the presented request hash must equal the stored one AND the presented archive
///    must be the stored archive. The stored request hash covers the predecessor's
///    own PRINCIPAL, `WorkScope`, operation id and archive provenance, so guessing the
///    namespace key alone — which is on the wire as `operation_namespace` — yields
///    nothing. It provably does NOT cover the predecessor's session, because
///    `session_id` is ambient; that is deliberate and is justified in
///    `answer_successor_verification`, not by any claim that the hash names it.
/// 4. the row must still rebuild the exact reply body it claims to hold before
///    anything is projected, which is what makes a stored row safe to project at
///    all.
///
/// Presenting a WRONG predecessor digest yields NO STORED VALUE AT ALL: the
/// mismatch answers with [`successor_not_observed_reply`], whose reason is a
/// single static string, and the scope and principal checks have already refused a
/// caller that was never allowed to ask. The pair therefore cannot be used to
/// EXTRACT a value: a caller cannot learn a row's request hash or any of its answers
/// by guessing, and the one value it could start from — the namespace digest on the
/// wire — is useless without the hash, which is what check 3 requires.
///
/// Be precise about the half that is NOT a guarantee, because an earlier draft of
/// this doc claimed it and was wrong: existence and ownership CLASS are NOT
/// concealed. A caller that knows or guesses a namespace digest learns whether a row
/// exists there — the load-miss arm answers the fail-closed
/// `verification_not_recorded_reply`, which is distinguishable from the refusal —
/// and it gets a refusal either way. Collapsing the four authorization failures onto
/// one sentence removes the per-class oracle; it does not make the probe blind, and
/// it does not make the load-miss indistinguishable. See
/// `answer_successor_verification` and `successor_not_observed_reply` for why that
/// trade is taken deliberately, and for the fact that the successor path has no
/// operator surface today.
///
/// What the pair is NOT is an owner-issued capability: nothing here proves the
/// owner would have authorised THIS caller to reconcile THAT operation, because
/// no owner issues a backup-verify succession or reconciliation receipt on this
/// product. That owner is `backup-capture-owner (#959)`, which is OPEN.
struct VerifySuccessorEvidence {
    /// The predecessor operation's durable namespace key.
    predecessor_namespace_digest: String,
    /// The predecessor operation's full accepted-identity digest.
    predecessor_identity_digest: String,
}

/// The verify shape this route admits: the decoded inline bundle bytes and the
/// optional succession evidence naming a predecessor operation.
type AdmittedVerifyBundle = (Vec<u8>, Option<VerifySuccessorEvidence>);

/// Admits the bounded inline bundle bytes one verify frame presents, and its
/// optional succession evidence.
///
/// Every refusal here is a shape failure decided before any owner is named: a
/// non-object payload, an unexpected or missing key, a non-string or non-hex
/// `bundle_hex`, empty bytes, and a `successor_of` that is not an object of
/// exactly two 64-hex digests. The returned field and reason are the route's own
/// shape vocabulary; the owner's refusal vocabulary is never used for a shape the
/// owner never saw.
///
/// `successor_of` is admitted only when present, so the payload is `{bundle_hex}`
/// or `{bundle_hex, successor_of}` and nothing else. The presence of the key
/// SELECTS which of the two route bodies runs — a fresh verification or a
/// reconciliation read of a named predecessor — and no accepted request identity is
/// constructed at all on the reconciliation path, so it is not accurate to say the
/// evidence "changes the accepted request identity". What it does change is which
/// durable row is read and what the answer means, and the two are distinguishable
/// on the wire: a reconciliation's `operation_id` and `operation_namespace` carry
/// the PREDECESSOR's values while the envelope correlation stays the caller's own
/// key.
///
/// Admitting the shape here proves nothing about the caller. The two digests are
/// only checked for 64-hex shape. Every check that decides whether the named
/// operation may be observed happens AFTER the real store read, and not all of it
/// is in one function: the `WorkScope` and authority-lineage joins are in
/// [`successor_may_observe`], while the principal comparison and the
/// digest-and-archive equality are in [`answer_successor_verification`].
fn admit_verify_bundle(payload: &Value) -> Result<AdmittedVerifyBundle, (&'static str, String)> {
    let Some(object) = payload.as_object() else {
        return Err(("backup.verify", "payload must be a JSON object".to_owned()));
    };
    let admitted_keys: &[&str] = if object.contains_key("successor_of") {
        &["bundle_hex", "successor_of"]
    } else {
        &["bundle_hex"]
    };
    if let Err(reason) = require_exact_keys(object, admitted_keys) {
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
    if !object.contains_key("successor_of") {
        return Ok((bundle_raw, None));
    }
    let successor = match get_object(object, "successor_of") {
        Ok(successor) => successor,
        Err(reason) => return Err(("backup.successor_of", reason)),
    };
    if let Err(reason) = require_exact_keys(
        successor,
        &[
            "predecessor_identity_digest",
            "predecessor_namespace_digest",
        ],
    ) {
        return Err(("backup.successor_of", reason));
    }
    let mut digests = [String::new(), String::new()];
    for (index, key) in [
        "predecessor_identity_digest",
        "predecessor_namespace_digest",
    ]
    .into_iter()
    .enumerate()
    {
        let value = match get_str(successor, key) {
            Ok(value) => value.to_owned(),
            Err(reason) => return Err(("backup.successor_of", reason)),
        };
        if let Err(shape) = sha256_digest_shape(&value, "backup.successor_of") {
            return Err(("backup.successor_of", shape.reason));
        }
        digests[index] = value;
    }
    Ok((
        bundle_raw,
        Some(VerifySuccessorEvidence {
            predecessor_namespace_digest: digests[1].clone(),
            predecessor_identity_digest: digests[0].clone(),
        }),
    ))
}

/// Answers from the durable owner-backed result that owns this operation.
///
/// A different canonical request hash under the same key is the I5.27 identity
/// conflict: the request performs no transition, and the stored answers are not
/// projected into a refusal. Since #2883 that hash covers the whole accepted
/// request identity MINUS the three ambient observation fields (`session_id`,
/// `resource_generation`, `authority_epoch`) — that is the authoritative field
/// list, `eliot_ors::BackupVerifyIdentityPreimage`, and it is not restated here.
/// So a changed archive, declared source, class, `WorkScope` or admitted
/// capability under one bound key conflicts instead of reading as a replay, and
/// nothing is stored.
///
/// A changed authority LINEAGE is NOT one of those, and cannot be: the lineage is
/// a key component, so a lineage change MOVES the key and stages a new row
/// rather than conflicting on the old one. That is deliberate and disclosed at
/// `eliot_ors::BackupVerifyRequestIdentity::namespace_digest`; cross-authority
/// separation is worth more than cross-lineage conflict detection.
///
/// An equal hash replays the persisted result, whose stored answers win over
/// anything recomputed on this call, so an exact replay after a Kernel restart or
/// an Authority Epoch rotation reports the historical archived-fence relation and
/// the exact receipt proved then. That replay is possible at all because neither
/// the restart nor the rotation is in the hash or in the key: they are recorded as
/// ambient observation context, so the same operation retried later addresses the
/// same row instead of staging a second one (I14.21). The stored reply digest is
/// recomputed and must match; a row that cannot rebuild the body it claims to hold
/// fails closed instead of projecting one it never produced.
///
/// This is a REPLAY of the CALLER'S PRINCIPAL's own operation, not a
/// reconciliation of somebody else's, so the envelope correlation and the
/// `operation_id` field are the same value and are both the caller's own key. The
/// row is the row of the CALLER'S PRINCIPAL at the PRINCIPAL's namespace key — not
/// "the caller's own row at the caller's own key" in any per-session sense: a NEW
/// SESSION of that same principal, in the same scope, replaying it here with no
/// reconciliation evidence at all, is the INTENDED I14.21 behaviour, not a
/// reconciliation. That is what acceptance clause 2 and I14.21 require, and it is
/// why `session_id` is ambient. A caller that is NOT that principal cannot reach
/// this function at all: the key is namespaced by principal, and the
/// reconciliation path exists for the non-owner case and answers from
/// `answer_successor_verification`.
///
/// It is one of exactly TWO producers of [`identity_conflict_reply`], the other
/// being [`answer_failed_stage`]. Both are safe for the same reason: each is about
/// the CALLER'S PRINCIPAL's own key, and the digest each names is either its own
/// freshly computed one or a row at its own key. [`answer_failed_stage`] is
/// genuinely reachable, not merely defensive: two different archives that share a
/// declared `export_id` produce the same key with the same principal and the same
/// scope but different canonical request hashes, so the store reports a conflict and
/// that branch answers.
fn answer_bound_verification(
    record: &BackupVerificationResultRecord,
    fresh: &VerifiedProjection,
    idempotency_key: &str,
) -> Value {
    if record.request_digest != fresh.request_digest {
        return identity_conflict_reply(idempotency_key, fresh.request_digest.as_str());
    }
    let Ok(stored) = projection_from_record(record) else {
        return verification_not_recorded_reply(idempotency_key);
    };
    let body = verified_reply(&stored, idempotency_key, idempotency_key);
    match reply_body_digest(&body) {
        Ok(digest) if digest == record.reply_digest => body,
        _ => verification_not_recorded_reply(idempotency_key),
    }
}

impl KernelComposition {
    /// Handles one backup verify frame: admits the bounded inline bundle bytes,
    /// then decodes and validates them through the real capture owner and binds
    /// the decided answer to the exact authenticated request identity.
    ///
    /// The owner is [`super::backup_capture::KernelBackupCapture`], already bound
    /// on the composition by #959; this route supplies only what a front door
    /// legitimately holds: the presented bytes, the session's own admission
    /// projection, the Kernel's live state fence, and the request's stable
    /// operation identity. Manifest, member integrity, the closed class rules,
    /// the archive's own source/provenance commitments and the archived-fence
    /// relation are the owner's answers, so a corrupted archive refuses as a
    /// typed `invalid` carrying the owner's own reason instead of a shape check
    /// passing. Shape failures refuse as `invalid` before the owner is called at
    /// all.
    ///
    /// Order since #2883: shape-admit, then [`admit_backup_caller`], then the
    /// real capture owner, then the accepted request identity, then the durable
    /// readback, then the decision, then the record. The owner must run BEFORE
    /// the readback now, because the request identity is built from the owner's
    /// own archive provenance: the owner answer, not the caller text, decides
    /// which durable row this operation is. The front-door checks in
    /// [`dispatch_backup_frame`] and in `admit_backup_caller` are unchanged and
    /// still run before any of this.
    ///
    /// The durable readback is keyed by the accepted identity's namespace digest —
    /// principal, authority lineage, operation id and the four profile constants,
    /// enumerated in exactly one place,
    /// `eliot_ors::BackupVerifyRequestIdentity::namespace_digest` — and never by the
    /// caller's idempotency text, so two principals that pick the same human key
    /// land on different rows and can neither read nor conflict with each other.
    /// There is no in-band installation component: "within one installation" is
    /// structural, because a row is only ever read out of the ORS file that owns
    /// it. A store outage still fails closed: an answer is never returned for a
    /// result that could not be bound to this identity. A decided answer is recorded
    /// under that namespace key before it is returned, so an exact replay by the
    /// owning PRINCIPAL after a Kernel restart or an Authority Epoch rotation reads
    /// the same owner-backed result back - retaining its historical fence and its
    /// exact member denominators - because neither the restart nor the rotation is in
    /// the key or in the request hash. A new SESSION of that same principal
    /// replaying it here, with no `successor_of` at all, is the intended I14.21
    /// behaviour and not a reconciliation. A changed archive, declared source,
    /// class, `WorkScope` or admitted capability under one bound key is an
    /// `IDENTITY_CONFLICT` that performs no transition and stores nothing (I5.27,
    /// I14.21); a changed authority LINEAGE is not one of those, because it is a key
    /// component, so it moves the key and stages a new row instead.
    ///
    /// `successor_of` is therefore for exactly one case: a caller that is NOT the
    /// principal owning the operation, which the namespace key cannot otherwise
    /// separate from it. Such a reconciliation answers from the NAMED predecessor's
    /// own row, not from a recompute of the presented bytes, so the presented bundle
    /// must be that predecessor's archive: the freshly decoded
    /// `report.archive_sha256` is compared against the stored
    /// `identity.archive_sha256` before anything is projected. The bundle is still
    /// decoded and validated first either way, so a reconciliation never skips the
    /// capture owner's admission gate.
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
        let (bundle_raw, successor) = match admit_verify_bundle(payload) {
            Ok(admitted) => admitted,
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
        // A permitted successor reconciles a prior operation by naming it
        // exactly, and that answer comes from the predecessor's own row. It is
        // answered before the fresh identity is even built, because a
        // reconciliation is a read of another operation, not a new one. The live
        // session, the admitted caller and the freshly decoded owner report are
        // all handed in: a reconciliation must additionally prove that THIS caller
        // may observe THAT operation, and that the archive just decoded from the
        // presented bytes is the predecessor's archive.
        if let Some(successor) = successor {
            return Ok(self.answer_successor_verification(
                session,
                &report,
                &successor,
                idempotency_key,
            ));
        }
        let identity = match backup_verify_identity(session, &caller, &report, idempotency_key) {
            Ok(identity) => identity,
            Err(reason) => {
                return Ok(invalid_reply(
                    BACKUP_VERIFY_OPERATION,
                    idempotency_key,
                    "backup.verify",
                    &bounded_reason(&reason),
                ));
            }
        };
        let Ok(request_digest) = backup_verify_request_digest(&identity) else {
            return Ok(verification_not_recorded_reply(idempotency_key));
        };
        let Ok(record_key) = identity.namespace_digest() else {
            return Ok(verification_not_recorded_reply(idempotency_key));
        };
        let fresh =
            match projection_from_report(&report, &identity, request_digest, record_key.clone()) {
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
        let Ok(prior) = self.load_prior_verification(record_key.as_str(), idempotency_key) else {
            return Ok(verification_not_recorded_reply(idempotency_key));
        };
        Ok(self.answer_backup_verify(prior, &identity, &fresh, idempotency_key))
    }

    /// Reads the durable verification result already bound to this scoped
    /// identity, and quarantines a pre-#2883 row on the caller's raw text.
    ///
    /// `record_key` is the accepted identity's 64-hex namespace digest, not caller
    /// text. A scoped lookup that finds nothing is NOT proof that nothing is stored
    /// under the caller's own text, so the raw key is probed as well and its class
    /// is carried through rather than collapsed into "absent":
    /// [`LegacyUnscopedBackupVerificationClass::Absent`] is the only arm that lets a
    /// fresh row be staged, `Legacy` is quarantined, and `Unreadable` fails closed.
    /// Both probes return store failures rather than degrading, because a store
    /// outage that silently downgraded to a non-persisted answer would let this route
    /// answer `ok` for a verification with no durable result behind it, which A0.3
    /// classifies as a false proof claim.
    fn load_prior_verification(
        &self,
        record_key: &str,
        idempotency_key: &str,
    ) -> Result<PriorVerification, OrsError> {
        match self.p07_ors.load_backup_verification_result(record_key)? {
            Some(record) => Ok(PriorVerification::Bound(Box::new(record))),
            None => Ok(
                match self
                    .p07_ors
                    .legacy_unscoped_backup_verification_class(idempotency_key)?
                {
                    LegacyUnscopedBackupVerificationClass::Absent => PriorVerification::Absent,
                    LegacyUnscopedBackupVerificationClass::Legacy => {
                        PriorVerification::LegacyUnscoped
                    }
                    LegacyUnscopedBackupVerificationClass::Unreadable => {
                        PriorVerification::Unreadable
                    }
                },
            ),
        }
    }

    /// Answers one reconciliation from the predecessor row the caller named.
    ///
    /// Three independent things are proved before anything is projected.
    ///
    /// (1) The caller is admitted for this front door in the SAME scope as the
    /// predecessor. The reconciling session is already authenticated and admitted
    /// by the time this runs — [`admit_backup_caller`] proved the peer identity
    /// and the single front-door capability, and `verify_only` →
    /// `require_capture_admitted` refused an unadmitted caller before this point —
    /// so these are additional joins on facts the live `Session` already holds,
    /// not a new admission gate and not a re-implementation of one. The joins are
    /// enumerated, with what is deliberately excluded and why, in
    /// [`successor_may_observe`]. The authority term is lineaged rather than
    /// exact, so a legitimate epoch rotation on this installation's own lineage
    /// is still a permitted reconciliation, which is exactly what instruction 7
    /// allows, while a foreign authority lineage is refused.
    ///
    /// The PRINCIPAL compare is a FOURTH check and a separate call site, not part
    /// of [`successor_may_observe`] — see that function's own note on what it
    /// deliberately does not compare. It is the one check a same-scope caller on the
    /// same lineage would otherwise slip past, and the one that makes `successor_of`
    /// a non-owner case at all. Like the other three it answers with
    /// [`successor_not_observed_reply`], so the four are indistinguishable to a
    /// caller that fails one.
    ///
    /// (2) The named predecessor is a real stored `backup.verify` row in that
    /// scope, and it is exactly the row the caller named: the presented
    /// `predecessor_identity_digest` must equal the stored row's canonical
    /// request hash, which covers the row's principal, `WorkScope`, operation id and
    /// archive provenance. A namespace key alone is therefore not a succession
    /// claim.
    ///
    /// (3) The presented archive IS that predecessor's archive: the freshly
    /// decoded `report.archive_sha256` must equal the stored
    /// `identity.archive_sha256`. Without this the caller could present a valid
    /// but different archive and be answered with the predecessor's identity,
    /// class, counts and fence relation, which would be a projection about bytes
    /// the caller did not present.
    ///
    /// The answer then keeps BOTH facts the transport needs. The envelope
    /// correlation is always the reconciling caller's own `idempotency_key`,
    /// because that is what the operator surface correlates against and a
    /// different value is a `CorrelationMismatch`; the `operation_id` field and
    /// the `operation_namespace` field carry the PREDECESSOR's, because that is
    /// the operation that produced the answer and the original operation identity
    /// must not be re-spelled as the reconciling caller's.
    ///
    /// The `reply_digest` check is preserved, not dropped, and it is checked
    /// against the body the PREDECESSOR would have projected: the stored digest
    /// was computed over the predecessor's own reply, so it is recomputed from
    /// `verified_reply(projection, stored.identity.operation_id,
    /// stored.identity.operation_id)` before the answer is re-projected with the
    /// caller's correlation. That is the only thing that makes a stored row safe
    /// to project at all — it proves the row can still rebuild the exact body it
    /// claims to hold — so a row that cannot is `verification_not_recorded_reply`
    /// rather than a re-projected answer nobody can check. The two bodies differ
    /// in exactly one field, the envelope `idempotency_key`, and the `ok`
    /// projection is a pure function of the row plus that correlation.
    ///
    /// NO CALLER-SUPPLIED-DIGEST PATH CAN RENDER A STORED VALUE, AND NONE OF THEM
    /// NAMES A CLASS EITHER, BUT THE ONE-SENTENCE CLAIM IS ABOUT THE AUTHORIZATION
    /// ARMS ONLY, NOT ALL SIX ARMS OF THIS FUNCTION. This function has six refusal
    /// call sites, and they answer with TWO different sentences:
    /// - the three AUTHORIZATION call sites — the scope/lineage join, the separate
    ///   principal compare, and the presented-digest + presented-archive compare —
    ///   all answer with the ONE [`successor_not_observed_reply`], whose reason is a
    ///   single static sentence naming no principal, no session, no scope, no
    ///   lineage, no digest, no archive identity, no count and no store error;
    /// - the three INTEGRITY/NO-ROW call sites — the load miss, the row that cannot
    ///   be rebuilt, and the `reply_digest` that does not re-derive — all answer
    ///   with the fail-closed [`verification_not_recorded_reply`], the same refusal
    ///   the caller's OWN replay path returns for a key holding nothing
    ///   trustworthy. So a caller CAN distinguish "there is no row at that key" (and
    ///   "a row whose body does not verify") from "there is a row you may not read".
    ///
    /// That residue is deliberate and it is the non-concealment paragraph below
    /// stated in the other direction: it is an OUTAGE signal, not an authorization
    /// oracle, because every one of those three arms is equally reachable by the
    /// caller for its own key. Collapsing them onto the authorization sentence would
    /// only hide a store fault behind an authorization refusal.
    ///
    /// Be precise about what the collapse does and does not buy, because the two are
    /// different and only one is a guarantee:
    /// - It DOES guarantee that no stored VALUE is extractable. Every field of the
    ///   predecessor's row, and every digest computed from it, stays inside the
    ///   store unless all checks pass.
    /// - It does NOT conceal existence or ownership CLASS. A caller that knows or
    ///   guesses a namespace digest can still learn whether a row exists there, and
    ///   it always gets a refusal either way, so a refusal is not proof of absence.
    ///   Distinguishing "no such row" from "a row you may not read" would require
    ///   the typed classes this path used to have, and those classes were themselves
    ///   the oracle. That trade is deliberate. It is also not currently observable
    ///   by the shipped product: the successor path has NO operator surface, because
    ///   `crates/surfaces/eliot-cli/src/backup.rs` builds the verify payload from
    ///   `CommandArguments::BackupVerify { bundle_hex }` only and cannot send
    ///   `successor_of` at all. A frame-level consumer could observe it; the CLI
    ///   cannot.
    ///
    /// RESIDUAL, stated rather than softened. What this route proves is: (a) the
    /// caller is admitted for the front door, by [`admit_backup_caller`] and by
    /// `verify_only`'s own `require_capture_admitted`, before this function runs;
    /// (b) the caller is in the same `WorkScope` and on the same authority LINEAGE as
    /// the named predecessor; and (c) the named predecessor is a real stored
    /// `backup.verify` row in this ORS file, whose canonical request hash — which
    /// covers its PRINCIPAL, `WorkScope`, operation id and archive provenance, and
    /// provably NOT its session — is exactly the one presented, and whose archive is
    /// exactly the one presented. The predecessor's own SESSION is deliberately not
    /// required to match and is deliberately not covered by the hash, and the
    /// justification is not a claim that the hash names it: a new session inheriting
    /// a prior session's operation is the ENTIRE POINT of a succession, so requiring
    /// session equality would make every reconciliation impossible.
    ///
    /// What it does NOT prove is that the owner would authorise THIS caller to
    /// reconcile THAT operation, because no owner issues a backup-verify succession
    /// or reconciliation receipt on this product. That owner is
    /// `backup-capture-owner (#959)`, which is OPEN. Instruction 4's
    /// "owner-authorized" half is therefore NOT met on this product, and it cannot
    /// be met here without inventing a capability, a receipt type, or an owner value
    /// that does not exist.
    ///
    /// # OPEN POINT FOR THE OWNER — the issue's clause-1 phrase. Clause 1 says "two
    /// authenticated principals OR SESSIONS" may use the same human idempotency text
    /// without reading or conflicting with each other's verification operation. Read
    /// per-SESSION, that would require `session_id` in the durable key. This
    /// implementation reads it per-PRINCIPAL, because acceptance clause 2 ("exact
    /// replay by the OWNING IDENTITY returns the same durable result after restart")
    /// and I14.21 (a retry after a lost response necessarily arrives on a NEW session
    /// and must reconcile to the committed result) cannot both hold if the key moves
    /// with the session. Note also that in this codebase
    /// `CaptureCallerAuth::principal` is `format!("{user_identity}@{session_identity}")`,
    /// so "principal/session" is already one composite string at the capture owner.
    /// The reading is DISCLOSED here for the owner to settle and is deliberately NOT
    /// resolved in code; no change here could resolve it without breaking clause 2.
    fn answer_successor_verification(
        &self,
        session: &Session,
        report: &CaptureReport,
        successor: &VerifySuccessorEvidence,
        idempotency_key: &str,
    ) -> Value {
        let Ok(Some(stored)) = self
            .p07_ors
            .load_backup_verification_result(successor.predecessor_namespace_digest.as_str())
        else {
            return verification_not_recorded_reply(idempotency_key);
        };
        // (1) FIRST, before any digest is compared and before the row is used for
        // anything observable. (2) and (3) follow. All three checks still run, in
        // this order, before any projection — only the ANSWER they produce is
        // shared, so a refusal cannot be used to tell the cases apart.
        if !successor_may_observe(session, &stored) {
            return successor_not_observed_reply(idempotency_key);
        }
        let Ok(caller_principal) = successor_caller_principal(session) else {
            return successor_not_observed_reply(idempotency_key);
        };
        if stored.identity.principal != caller_principal {
            return successor_not_observed_reply(idempotency_key);
        }
        if stored.identity.identity_digest != successor.predecessor_identity_digest
            || stored.identity.archive_sha256 != report.archive_sha256
        {
            return successor_not_observed_reply(idempotency_key);
        }
        let Ok(projection) = projection_from_record(&stored) else {
            return verification_not_recorded_reply(idempotency_key);
        };
        // Verify the row can still rebuild the exact body it claims to hold,
        // using the predecessor's OWN correlation, because that is the body the
        // stored digest was computed over.
        let predecessor_body = verified_reply(
            &projection,
            stored.identity.operation_id.as_str(),
            stored.identity.operation_id.as_str(),
        );
        match reply_body_digest(&predecessor_body) {
            Ok(digest) if digest == stored.reply_digest => verified_reply(
                &projection,
                idempotency_key,
                stored.identity.operation_id.as_str(),
            ),
            _ => verification_not_recorded_reply(idempotency_key),
        }
    }

    /// Answers one decided verification from the owner report and the store.
    ///
    /// Every branch either replays the persisted owner-backed result, refuses a
    /// class the store named, or records the fresh one first, so an `ok` reply
    /// never precedes its durable row and a refusal never carries a stored
    /// projection.
    fn answer_backup_verify(
        &self,
        prior: PriorVerification,
        identity: &BackupVerifyRequestIdentity,
        fresh: &VerifiedProjection,
        idempotency_key: &str,
    ) -> Value {
        match prior {
            PriorVerification::Bound(record) => {
                answer_bound_verification(&record, fresh, idempotency_key)
            }
            PriorVerification::LegacyUnscoped => legacy_unscoped_evidence_reply(idempotency_key),
            // Fail closed: bytes are stored under this caller's text and decode as
            // neither shape. Staging over them would destroy evidence and answer
            // `ok` for a verification whose prior answer is still on disk, so the
            // only honest answer is no verification result at all.
            PriorVerification::Unreadable => verification_not_recorded_reply(idempotency_key),
            PriorVerification::Absent => {
                self.stage_backup_verification(identity, fresh, idempotency_key)
            }
        }
    }

    /// Records the fresh owner-proved answer and returns the body to send.
    ///
    /// Persist-before-answer: the durable row is committed before the body is
    /// returned, so a lost response reconciles to this same persisted result
    /// (I14.21) rather than re-deriving a differently-fenced one — and it
    /// reconciles to it because the durable key does not move with the session,
    /// the resource generation or the Authority Epoch, so the retry addresses this
    /// row. A concurrent stage that already bound this key is answered from the
    /// durable winner. A fresh verify is not a reconciliation, so the envelope
    /// correlation and the `operation_id` field are the same value and are both
    /// the caller's own key.
    fn stage_backup_verification(
        &self,
        identity: &BackupVerifyRequestIdentity,
        fresh: &VerifiedProjection,
        idempotency_key: &str,
    ) -> Value {
        let body = verified_reply(fresh, idempotency_key, idempotency_key);
        let Ok(reply_digest) = reply_body_digest(&body) else {
            return verification_not_recorded_reply(idempotency_key);
        };
        let record = record_from_projection(identity, fresh, reply_digest);
        match self.p07_ors.stage_backup_verification_result(&record) {
            Ok(BackupVerificationDisposition::Stored) => body,
            // `AlreadyBound` means the full canonical request hash already matched,
            // so the stored principal and session are necessarily the candidate's
            // own and re-checking them here could never fail. It is answered
            // directly; the store's own cross-identity branch is below.
            Ok(BackupVerificationDisposition::AlreadyBound(bound)) => {
                answer_bound_verification(&bound, fresh, idempotency_key)
            }
            // Store-side refusal on a row that already occupies this key but whose
            // stored owner-bearing identity contradicts the candidate. It is
            // REACHABLE on an ordinary, uncorrupted row, and this is the branch a
            // reviewer reads first, so say why honestly: `scope_id` is deliberately
            // NOT a key component, so two sessions of the SAME principal, on the
            // same lineage, with the same `operation_id` and the same archive but
            // DIFFERENT `WorkScope`s produce the SAME key. The load and the stage
            // are two separate redb transactions, so between them a second writer
            // reads the first's row here: `same_binding` is false because `scope_id`
            // is in the request hash, and `foreign_to` is true because it is not.
            // See `BackupVerificationResultRecord::foreign_to` for exactly which
            // fields it compares. A different PRINCIPAL at the same key would be a
            // SHA-256 collision and is not reachable through this route; that
            // narrower case is a hand-edited row, and the same class answers it.
            // Either way the stored row is never read back, so the typed class is
            // the whole of what leaves the store.
            Ok(BackupVerificationDisposition::ForeignOperation) => {
                foreign_operation_reply(idempotency_key)
            }
            Err(error) => answer_failed_stage(&fresh.request_digest, idempotency_key, &error),
        }
    }
}

/// Answers after the durable stage did not succeed.
///
/// The I5.27 identity conflict is the one stage failure that is an answer rather
/// than an outage, and it needs no readback: the refusal names only the caller's
/// own presented digest, so there is nothing to make concrete by reading the
/// bound row back, and that readback was the only reason this decision needed the
/// namespace key or the composition. Every other failure is an outage: the effect
/// was not recorded, and this route must not answer `ok` for it.
fn answer_failed_stage(
    presented_request_digest: &str,
    idempotency_key: &str,
    error: &OrsError,
) -> Value {
    if !is_backup_verification_conflict(error) {
        return verification_not_recorded_reply(idempotency_key);
    }
    identity_conflict_reply(idempotency_key, presented_request_digest)
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
