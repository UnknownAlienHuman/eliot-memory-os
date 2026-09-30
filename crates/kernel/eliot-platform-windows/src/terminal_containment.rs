//! Bounded terminal containment evidence for the Windows guard fail-stop path.
//!
//! Architecture: A0.3 (a hidden expansion of authority fails closed),
//! ARCH-OBS-01, A13.2 (independent failure domains). Implementation: I1.6
//! (Windows isolation boundary), I2.6 (exact operation identity, effect
//! status, and a raw evidence handle), I7.20 (typed failure disposition),
//! I14.23 (safe shutdown never resumes unsafe state), I14.24 (containment),
//! I15.4 (no secret value in diagnostics).
//!
//! This module owns three things and nothing else: the bounded evidence
//! resource acquired **before** a guarded mutation, the fixed record encoding
//! written **on** the fail-stop path, and the readback validator an
//! independent owner uses afterwards. It is the replacement backing mechanism
//! for the previous `std::io::stderr().lock()` emergency emitter. It is not a
//! logging service: there is no level, no formatting, no rotation, no
//! destination configuration, and no arbitrary path, command, or termination
//! interface.
//!
//! # Record layout
//!
//! One record is exactly [`TERMINAL_CONTAINMENT_RECORD_BYTES`] bytes:
//!
//! ```text
//! 0..8    magic              b"ELIOTTC1"
//! 8..12   record_version     u32 little-endian
//! 12..16  record_bytes       u32 little-endian, the exact fixed length
//! 16..20  os_code            u32 little-endian, the exact OS error
//! 20      operation_binding  0 = not bound, 1 = bound to a prepared operation
//! 21      site_len           u8, bounded by TERMINAL_CONTAINMENT_SITE_MAX_BYTES
//! 22      detail_len         u8, bounded by TERMINAL_CONTAINMENT_DETAIL_MAX_BYTES
//! 23      reserved           0
//! 24..64  site               fixed-width, NUL padded, bounded non-secret ID
//! 64..96  detail             fixed-width, NUL padded, bounded non-secret ID
//! 96..128 operation_digest   32 bytes, all zero exactly when not bound
//! ```
//!
//! NUL padding is load-bearing, not cosmetic: every byte inside `site_len` and
//! `detail_len` is non-zero and every padding byte to the fixed field end is
//! zero. The readback validator enforces this completion rule, so a torn or
//! partially overwritten record that keeps a valid magic, version and length
//! still stays unresolved rather than validating as a completed cleanup.
//!
//! Only bounded non-secret identities and the exact `u32` OS error are
//! present. No path, token, ACL, principal value, or secret value is
//! representable.
//!
//! # Submission bound
//!
//! The terminal path uses one fixed stack record, one bounded copy of each
//! static identity, one `WriteFile` on the process standard-error OS handle,
//! and one `GetLastError` taken immediately after the failed call. It never
//! allocates, never builds a `String` or `Vec`, never formats, never takes a
//! stdio lock, never calls an arbitrary callback, never panics, never unwinds,
//! and never attempts recursive error reporting. The reentry guard is a
//! compare-exchange, so a second entry cannot wait on itself.
//!
//! `WriteFile` is a synchronous OS call. This module proves a bounded record
//! length, a bounded call count, and immediate error capture; it does **not**
//! claim a wall-clock completion bound, and it never claims that a successful
//! write is durable restoration proof.

use std::sync::OnceLock;

use eliot_contracts::RequestMetadata;
use eliot_platform::PlatformHandle;
use sha2::{Digest, Sha256};

/// Current fixed terminal-containment record version.
pub const TERMINAL_CONTAINMENT_RECORD_VERSION: u32 = 1;

/// Exact fixed record length in bytes.
pub const TERMINAL_CONTAINMENT_RECORD_BYTES: usize = 128;

/// Maximum encoded length of the bounded non-secret site identity.
pub const TERMINAL_CONTAINMENT_SITE_MAX_BYTES: usize = 40;

/// Maximum encoded length of the bounded non-secret detail identity.
pub const TERMINAL_CONTAINMENT_DETAIL_MAX_BYTES: usize = 32;

/// Length of the bounded non-secret operation identity.
pub const TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES: usize = 32;

const RECORD_MAGIC: [u8; 8] = *b"ELIOTTC1";
const OPERATION_BINDING_BOUND: u8 = 1;
const OPERATION_BINDING_NOT_BOUND: u8 = 0;

const OFFSET_MAGIC: usize = 0;
const OFFSET_VERSION: usize = 8;
const OFFSET_RECORD_BYTES: usize = 12;
const OFFSET_OS_CODE: usize = 16;
const OFFSET_OPERATION_BINDING: usize = 20;
const OFFSET_SITE_LEN: usize = 21;
const OFFSET_DETAIL_LEN: usize = 22;
const OFFSET_RESERVED: usize = 23;
const OFFSET_SITE: usize = 24;
const OFFSET_DETAIL: usize = 64;
const OFFSET_OPERATION_DIGEST: usize = 96;

/// The closed set of approved terminal-containment sinks.
///
/// The process standard-error OS handle is OS-owned process state that exists
/// before any ELIOT code runs. It does not depend on the protected object or
/// token, on any logger being repaired, on the heap, or on a `String`. The
/// previous emitter used the same destination but reached it through
/// `std::io::stderr().lock()` and several ignored `write_all` results; this
/// owner reaches the raw OS handle with no stdio lock and captures one exact
/// result instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalContainmentSink {
    /// The process standard-error OS handle.
    StandardError,
}

/// Typed failure of the pre-mutation acquisition.
///
/// Every variant refuses the guarded mutation. A preparation failure must
/// never be followed by impersonation or elevation, because the evidence
/// resource that bounds the fail-stop path would then be missing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalContainmentError {
    /// The supplied operation context did not validate.
    InvalidOperationContext,
    /// The site identity cannot be represented as a bounded non-secret ID.
    SiteIdentityNotRepresentable,
    /// The detail identity cannot be represented as a bounded non-secret ID.
    DetailIdentityNotRepresentable,
    /// The bounded operation identity could not be encoded.
    OperationIdentityUnavailable,
    /// One process-wide sink is already prepared. Two prepared sinks could not
    /// be reconciled into one terminal record, so the second acquisition is
    /// refused rather than silently replacing the first.
    SinkAlreadyPrepared,
    /// This terminal mechanism is unavailable off Windows.
    UnsupportedPlatform,
}

impl std::fmt::Display for TerminalContainmentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOperationContext => {
                formatter.write_str("terminal containment operation context is invalid")
            }
            Self::SiteIdentityNotRepresentable => {
                formatter.write_str("terminal containment site identity is not representable")
            }
            Self::DetailIdentityNotRepresentable => {
                formatter.write_str("terminal containment detail identity is not representable")
            }
            Self::OperationIdentityUnavailable => {
                formatter.write_str("terminal containment operation identity is unavailable")
            }
            Self::SinkAlreadyPrepared => formatter
                .write_str("a terminal containment sink is already prepared for this process"),
            Self::UnsupportedPlatform => {
                formatter.write_str("terminal containment requires Windows")
            }
        }
    }
}

impl std::error::Error for TerminalContainmentError {}

/// The exact bounded result of one terminal submission attempt.
///
/// A submission attempt is not durable evidence. No variant here — not even
/// [`TerminalSubmission::Recorded`] — is a restoration receipt, and this module
/// mints none: a successful write is OS acceptance of 128 bytes, never proof
/// that restoration happened. Only the independent supervisor's readback
/// decision ([`TerminalContainmentReadback`], [`TerminalRestartGate`])
/// establishes evidence, and only the guard owner establishes that
/// continuation-safe OS state was reached. If submission fails in any way, the
/// fail-stop fallback still runs and the supervisor retains
/// non-success/unknown state; no receipt is synthesized and ordinary work is
/// never resumed under unsafe security state.
///
/// Exactly one bounded write is attempted per call. There is no retry loop on
/// the emergency path: a second attempt would need a second bounded resource
/// it does not own, and unbounded retry could delay the fail-stop the unsafe
/// state requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalSubmission {
    /// The complete fixed record was accepted by the approved sink.
    Recorded { bytes: u32 },
    /// The OS accepted a short write, so no complete record exists.
    ShortWrite { bytes: u32 },
    /// A bounded static identity does not fit its fixed record field, so
    /// nothing was submitted.
    IdentityNotRepresentable,
    /// A second terminal entry could not re-enter the writer. The reentry guard
    /// is a compare-exchange, so the second entry never waits on itself.
    ReentryRefused,
    /// The OS refused the bounded write. `code` is the exact error captured
    /// immediately after the failed call.
    WriteFailed { code: u32 },
    /// This terminal mechanism is unavailable off Windows.
    UnsupportedPlatform,
}

/// Why one retained record is not a complete current terminal-containment
/// record. An unresolved record is never a completed cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalContainmentUnresolved {
    /// No retained bytes were supplied.
    Missing,
    /// The retained bytes are shorter than the exact fixed record.
    ShortRecord,
    /// The retained bytes are not one exact fixed record.
    ForeignRecord,
    /// The retained record version is not the current fixed version.
    UnsupportedVersion,
    /// A length, binding, or reserved field does not match the fixed encoding.
    MalformedField,
    /// The record is a valid current fixed record, but it is not bound to the
    /// exact operation whose evidence was requested. An unbound record and a
    /// record bound to a different operation are both this case; neither is a
    /// completed cleanup.
    OperationGenerationMismatch,
}

/// One validated current fixed terminal-containment record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalContainmentRecord {
    /// The exact OS error captured immediately after the failed call.
    pub os_code: u32,
    /// The bounded non-secret operation identity precomputed by
    /// [`prepare_terminal_containment`], or `None` when this process holds no
    /// prepared evidence resource. Absence is explicit; it is never an invented
    /// zero digest.
    pub operation_digest: Option<[u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES]>,
    /// Encoded length of the bounded non-secret site identity.
    pub site_len: u8,
    /// Encoded length of the bounded non-secret detail identity.
    pub detail_len: u8,
}

/// Readback classification of one retained record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalContainmentReadback {
    /// The retained bytes are one complete, current, fixed record.
    Complete(TerminalContainmentRecord),
    /// The retained bytes stay unresolved.
    Unresolved(TerminalContainmentUnresolved),
}

/// Restart decision for one retained terminal-containment record.
///
/// The restart owner reads retained composite/terminal evidence before
/// adopting or overwriting the affected object and keeps it blocked until
/// exact owner reconciliation. A [`TerminalRestartGate::Blocked`] decision
/// names the exact unresolved reason; it is never a completed cleanup and it
/// never authorizes adoption or overwrite. A
/// [`TerminalRestartGate::Reconciled`] decision carries the validated record
/// bound to the exact expected operation generation; the owner still performs
/// the reconciliation itself — this value only reports that the retained
/// evidence is complete, current, and exactly bound, so the owner has
/// something unambiguous to reconcile against.
///
/// The gate creates no journal, no receipt, and no second derivation: the
/// expected identity is computed by [`terminal_containment_operation_digest`],
/// the one rule the writer used. Unknown, missing, short, torn, foreign, or
/// differently-bound records stay blocked; restart never adopts ambiguous
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalRestartGate {
    /// The affected object stays blocked. `reason` is the exact unresolved
    /// cause; the owner must reconcile before any adoption or overwrite.
    Blocked {
        reason: TerminalContainmentUnresolved,
    },
    /// The retained record is complete, current, and bound to the exact
    /// expected operation generation. The owner may now reconcile; this value
    /// alone adopts nothing.
    Reconciled { record: TerminalContainmentRecord },
}

/// The installed bounded evidence resource.
///
/// Exactly one preparation is admitted per process. The value is owned here for
/// the life of the process and is never replaced, dropped, or re-armed, so the
/// terminal path can never run a destructor, a lock, or a flush.
struct InstalledEvidenceResource {
    operation_digest: [u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES],
}

static INSTALLED_EVIDENCE_RESOURCE: OnceLock<InstalledEvidenceResource> = OnceLock::new();

/// Nonblocking terminal reentry guard.
///
/// `compare_exchange` never blocks, so a second terminal entry cannot wait on
/// the writer it is re-entering, and a thread that fails to re-enter cannot
/// deadlock the process it is trying to contain.
static TERMINAL_REENTRY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// #860 handoff — the one accepted interface, for both guard families.
//
// Both `ScopedRestorePrivilege` (token privilege) and `ImpersonationGuard`
// (thread impersonation) use exactly these three entry points and no other
// terminal mechanism. There is no second logger, no second journal, and no
// per-guard emitter.
//
// 1. Before the guarded mutation, in the operation that owns the failure
//    evidence, call [`prepare_terminal_containment`] once with the same
//    validated `RequestMetadata` the composite's `parent_operation` carries.
//    A returned error refuses the mutation; impersonation or elevation must not
//    proceed. Preparation is per process, so a second call is
//    [`TerminalContainmentError::SinkAlreadyPrepared`] rather than a silent
//    replacement.
//
// 2. When the OS state is not proven continuation-safe, and only then, call
//    [`fail_stop_with_terminal_containment`] with a `&'static str` site, a
//    `&'static str` detail, and the exact `u32` captured immediately after the
//    failed call. This never returns.
//
// 3. On the normal path, where the guard owner established continuation-safe OS
//    state, do not call the terminal path at all. Return the
//    `eliot_platform::GuardRevertOutcome` composite to the installation caller,
//    which persists it through
//    `InstallationCoordinator::record_guard_revert` and reads it back on
//    restart through
//    `InstallationCoordinator::reconcile_retained_guard_evidence`.
//
// The composite retains the primary failure, the explicit restore failure and
// the emergency restore failure as separate slots; a successful emergency
// restoration must not erase the explicit failure that preceded it. Both
// attempts stay separately recorded.
//
// #860 per-guard wiring — same three entry points, no second mechanism.
//
// `ScopedRestorePrivilege` (token privilege, `installer_root.rs`) and
// `ImpersonationGuard` (thread impersonation, `named_pipe_peer_auth.rs`) each
// wire identically:
//
// 1. `enter`/`begin`: call [`prepare_terminal_containment`] once with the same
//    validated `RequestMetadata` the composite's `parent_operation` carries,
//    before any impersonation or elevation. A returned error refuses the
//    mutation; the guard must not arm.
// 2. Fail-stop sites keep their exact `site`/`detail`/`code` triple and route
//    it to [`fail_stop_with_terminal_containment`]:
//    `installer-root/scoped-restore-drop`, `installer-root/dual-failure`, and
//    `peer-auth/impersonation-drop`, each with its stage-name detail and the
//    exact `u32` captured immediately after the failed call. The in-crate
//    forwarder `installer_root::emit_abort_boundary_evidence` already delegates
//    to that owner and stays the only forwarder; #860 adds no other emitter,
//    logger, journal, or per-guard writer.
// 3. Restart/startup reads each retained record through
//    [`gate_terminal_restart_for`] with the expected digest from
//    [`terminal_containment_operation_digest`]. `Blocked` keeps the affected
//    object fenced until exact owner reconciliation; `Reconciled` is what the
//    owner reconciles against.
//
// Ownership, lifetime, and error rules for every guard body:
//
// - Ownership: the prepared resource, the record encoding, the sink, and the
//   reentry guard are owned here for the process life. Guards own only their
//   `site`/`detail` identities and their immediately-captured `code`; they
//   never own the sink, a handle, or a receipt.
// - Lifetime: `site` and `detail` are `&'static str` — static call-site names
//   and stage names only. No borrowed runtime string may cross into the
//   terminal path, which cannot validate or retain heap state; in particular
//   Drop-time calls must not borrow guard fields that may be mid-unwind.
// - Errors: every terminal entry reports through [`TerminalSubmission`] or
//   diverges via fail-stop; a terminal failure never becomes a `Result` the
//   guard could match on and continue from. Every readback entry reports
//   through [`TerminalContainmentReadback`] or [`TerminalRestartGate`]; an
//   unresolved record never becomes success.

/// Acquires the bounded terminal-containment evidence resource **before** a
/// guarded mutation, and fixes every terminal-path decision while normal
/// allocation is still safe.
///
/// Preparation validates the caller's operation context, bounds both static
/// identities into non-secret reference widths, precomputes the variable-length
/// operation identity into one fixed 32-byte reference, fixes the record
/// version, record size, field encoding, approved sink identity, ownership
/// rule, and completion/readback rule, and installs the result as this
/// process's single sink. The prepared resource does not depend on the
/// protected object or token and does not depend on any logger.
///
/// A returned error refuses the guarded mutation: the caller must not proceed
/// to impersonation or elevation, because the fail-stop path would then have no
/// bounded evidence resource.
pub fn prepare_terminal_containment(
    context: &RequestMetadata,
    site: &'static str,
    detail: &'static str,
) -> Result<(), TerminalContainmentError> {
    context
        .validate()
        .map_err(|_| TerminalContainmentError::InvalidOperationContext)?;
    if !is_bounded_identity(site, TERMINAL_CONTAINMENT_SITE_MAX_BYTES) {
        return Err(TerminalContainmentError::SiteIdentityNotRepresentable);
    }
    if !is_bounded_identity(detail, TERMINAL_CONTAINMENT_DETAIL_MAX_BYTES) {
        return Err(TerminalContainmentError::DetailIdentityNotRepresentable);
    }
    let operation_digest = terminal_containment_operation_digest(context)?;

    #[cfg(not(windows))]
    {
        let _ = (site, detail, operation_digest);
        Err(TerminalContainmentError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        INSTALLED_EVIDENCE_RESOURCE
            .set(InstalledEvidenceResource { operation_digest })
            .map_err(|_| TerminalContainmentError::SinkAlreadyPrepared)
    }
}

/// Derives the exact bounded operation identity one prepared record is bound
/// to.
///
/// This is the single derivation used both by
/// [`prepare_terminal_containment`] and by the normal recovery owner, so the
/// expected identity is computed from the same rule the writer used rather
/// than supplied by a second caller-supplied list.
///
/// # Errors
///
/// Returns [`TerminalContainmentError::InvalidOperationContext`] for an
/// unvalidated operation context and
/// [`TerminalContainmentError::OperationIdentityUnavailable`] when the
/// context cannot be canonicalized.
pub fn terminal_containment_operation_digest(
    context: &RequestMetadata,
) -> Result<[u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES], TerminalContainmentError> {
    context
        .validate()
        .map_err(|_| TerminalContainmentError::InvalidOperationContext)?;
    let encoded = serde_json::to_vec(context)
        .map_err(|_| TerminalContainmentError::OperationIdentityUnavailable)?;
    Ok(Sha256::digest(&encoded).into())
}

/// Submits one bounded terminal-containment record and never returns to
/// ordinary code.
///
/// The submission is exactly one fixed stack record, one `WriteFile` on the
/// approved sink, and one immediately captured `GetLastError`. If the record
/// was not recorded in full, this performs the documented fail-stop fallback
/// instead of returning: a caller can never observe a submission failure and
/// continue under unsafe OS state. `std::process::abort()` runs no destructors
/// and flushes no Rust IO buffer, so the fallback is independent of every
/// ordinary persistence, logging, and callback path.
pub fn fail_stop_with_terminal_containment(
    site: &'static str,
    detail: &'static str,
    code: u32,
) -> ! {
    let _submission = submit_terminal_containment(site, detail, code);
    std::process::abort();
}

/// Submits one bounded fixed record to the approved terminal sink.
///
/// This is the minimal terminal path. It allocates nothing, builds no `String`
/// or `Vec`, formats nothing, takes no stdio lock, accepts no arbitrary
/// callback, cannot panic, never unwinds, and never attempts recursive error
/// reporting. The reentry guard is a compare-exchange, so a second entry is
/// refused immediately rather than waiting on itself.
pub fn submit_terminal_containment(
    site: &'static str,
    detail: &'static str,
    code: u32,
) -> TerminalSubmission {
    use std::sync::atomic::Ordering;

    if TERMINAL_REENTRY
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return TerminalSubmission::ReentryRefused;
    }
    match encode_terminal_record(site, detail, code) {
        Some(record) => submit_record(&record),
        None => TerminalSubmission::IdentityNotRepresentable,
    }
}

/// Validates one retained record against the exact fixed encoding.
///
/// A missing, short, foreign, stale-version, or malformed record stays
/// [`TerminalContainmentUnresolved`] and is never a completed cleanup. When the
/// record validates, its operation identity is bound to the exact preparation
/// that produced it; an unbound record is reported explicitly.
///
/// Beyond version, length, and binding, the validator enforces the field-image
/// completion rule: every identity byte inside the declared length is non-zero
/// and every NUL-padding byte to the fixed field end is zero. A torn or
/// partially overwritten record can keep a valid header while carrying a
/// corrupted identity image; such a record is malformed, not evidence.
pub fn validate_terminal_containment_readback(bytes: &[u8]) -> TerminalContainmentReadback {
    use TerminalContainmentUnresolved::{
        ForeignRecord, MalformedField, Missing, ShortRecord, UnsupportedVersion,
    };

    if bytes.is_empty() {
        return TerminalContainmentReadback::Unresolved(Missing);
    }
    if bytes.len() < TERMINAL_CONTAINMENT_RECORD_BYTES {
        return TerminalContainmentReadback::Unresolved(ShortRecord);
    }
    if bytes.len() != TERMINAL_CONTAINMENT_RECORD_BYTES
        || bytes[OFFSET_MAGIC..OFFSET_VERSION] != RECORD_MAGIC
    {
        return TerminalContainmentReadback::Unresolved(ForeignRecord);
    }
    if read_u32(bytes, OFFSET_VERSION) != TERMINAL_CONTAINMENT_RECORD_VERSION {
        return TerminalContainmentReadback::Unresolved(UnsupportedVersion);
    }
    if read_u32(bytes, OFFSET_RECORD_BYTES) != fixed_record_length_field() {
        return TerminalContainmentReadback::Unresolved(MalformedField);
    }
    let site_len = bytes[OFFSET_SITE_LEN];
    let detail_len = bytes[OFFSET_DETAIL_LEN];
    if bytes[OFFSET_RESERVED] != 0
        || usize::from(site_len) > TERMINAL_CONTAINMENT_SITE_MAX_BYTES
        || usize::from(detail_len) > TERMINAL_CONTAINMENT_DETAIL_MAX_BYTES
    {
        return TerminalContainmentReadback::Unresolved(MalformedField);
    }
    if !field_image_is_intact(bytes, OFFSET_SITE, site_len, OFFSET_DETAIL)
        || !field_image_is_intact(bytes, OFFSET_DETAIL, detail_len, OFFSET_OPERATION_DIGEST)
    {
        return TerminalContainmentReadback::Unresolved(MalformedField);
    }
    // `bytes.len() == TERMINAL_CONTAINMENT_RECORD_BYTES` is already proven
    // above, so this slice is exactly the fixed digest width.
    let digest_bytes = &bytes[OFFSET_OPERATION_DIGEST
        ..OFFSET_OPERATION_DIGEST + TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES];
    let all_zero = digest_bytes.iter().all(|byte| *byte == 0);
    let operation_digest = match bytes[OFFSET_OPERATION_BINDING] {
        OPERATION_BINDING_BOUND if !all_zero => {
            let mut digest = [0_u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES];
            digest.copy_from_slice(digest_bytes);
            Some(digest)
        }
        OPERATION_BINDING_NOT_BOUND if all_zero => None,
        _ => return TerminalContainmentReadback::Unresolved(MalformedField),
    };
    TerminalContainmentReadback::Complete(TerminalContainmentRecord {
        os_code: read_u32(bytes, OFFSET_OS_CODE),
        operation_digest,
        site_len,
        detail_len,
    })
}

/// Validates one retained record against the exact fixed encoding **and**
/// against the exact operation generation whose evidence was requested.
///
/// This is the normal recovery owner's entry point. It first runs the same
/// fixed-encoding validator the terminal path uses, then compares the record's
/// bound operation identity with the expected one by content. A valid record
/// that is unbound, or that is bound to a different operation, stays
/// [`TerminalContainmentUnresolved::OperationGenerationMismatch`]: an
/// unsupported, stale, or foreign record is never a completed cleanup.
pub fn validate_terminal_containment_readback_for(
    bytes: &[u8],
    expected_operation_digest: [u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES],
) -> TerminalContainmentReadback {
    match validate_terminal_containment_readback(bytes) {
        TerminalContainmentReadback::Unresolved(unresolved) => {
            TerminalContainmentReadback::Unresolved(unresolved)
        }
        TerminalContainmentReadback::Complete(record) => {
            if record.operation_digest != Some(expected_operation_digest) {
                return TerminalContainmentReadback::Unresolved(
                    TerminalContainmentUnresolved::OperationGenerationMismatch,
                );
            }
            TerminalContainmentReadback::Complete(record)
        }
    }
}

/// Gates restart of the affected object on one retained record and the exact
/// expected operation generation.
///
/// This is the restart owner's entry point. It runs the same fixed-encoding
/// validator the terminal path uses, bound to the expected identity by
/// content, and projects the outcome onto the one restart decision: anything
/// unresolved — missing, short, torn, foreign, stale-version, malformed, or
/// bound to another operation — stays [`TerminalRestartGate::Blocked`], and
/// the affected object must not be adopted or overwritten until the exact
/// owner reconciles it. Only a complete, current record bound to the exact
/// expected generation becomes [`TerminalRestartGate::Reconciled`].
///
/// Ownership: the caller owns `bytes` and the expected digest; this function
/// borrows both, copies out at most one fixed record, and retains nothing.
/// Lifetime: no state escapes except the returned `Copy` decision. Errors:
/// there is no failure return — every non-evidence input is a `Blocked`
/// reason, never success and never a synthesized receipt.
///
/// The expected digest must come from [`terminal_containment_operation_digest`]
/// over the same validated operation context the writer prepared with. A
/// caller-supplied second derivation is a second journal by another name and
/// is not accepted here.
pub fn gate_terminal_restart_for(
    bytes: &[u8],
    expected_operation_digest: [u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES],
) -> TerminalRestartGate {
    match validate_terminal_containment_readback_for(bytes, expected_operation_digest) {
        TerminalContainmentReadback::Unresolved(reason) => {
            TerminalRestartGate::Blocked { reason }
        }
        TerminalContainmentReadback::Complete(record) => {
            TerminalRestartGate::Reconciled { record }
        }
    }
}

fn is_bounded_identity(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && PlatformHandle::new(value).is_ok()
}

/// Checks one fixed-width identity field image: every byte inside the declared
/// length is non-zero and every padding byte to the fixed field end is zero.
///
/// All indices derive from the fixed layout and the already range-checked
/// length, so no slice access can panic. This runs on the normal/restart path,
/// never on the terminal path; it still allocates nothing, formats nothing,
/// and cannot panic.
fn field_image_is_intact(bytes: &[u8], field_start: usize, len: u8, field_end: usize) -> bool {
    let len = usize::from(len);
    let width = field_end.saturating_sub(field_start);
    if len > width || bytes.len() < field_end {
        return false;
    }
    let mut index = 0;
    while index < width {
        let byte = bytes[field_start + index];
        if index < len {
            if byte == 0 {
                return false;
            }
        } else if byte != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn fixed_record_length_field() -> u32 {
    u32::try_from(TERMINAL_CONTAINMENT_RECORD_BYTES).unwrap_or(u32::MAX)
}

/// Encodes one complete fixed record into stack storage.
///
/// Every slice copy below is preceded by the exact bound check that makes it
/// total, so no copy can panic.
fn encode_terminal_record(
    site: &str,
    detail: &str,
    code: u32,
) -> Option<[u8; TERMINAL_CONTAINMENT_RECORD_BYTES]> {
    if site.len() > TERMINAL_CONTAINMENT_SITE_MAX_BYTES
        || detail.len() > TERMINAL_CONTAINMENT_DETAIL_MAX_BYTES
    {
        return None;
    }
    let site_len = u8::try_from(site.len()).unwrap_or(u8::MAX);
    let detail_len = u8::try_from(detail.len()).unwrap_or(u8::MAX);
    let mut record = [0_u8; TERMINAL_CONTAINMENT_RECORD_BYTES];
    record[OFFSET_MAGIC..OFFSET_VERSION].copy_from_slice(&RECORD_MAGIC);
    record[OFFSET_VERSION..OFFSET_RECORD_BYTES]
        .copy_from_slice(&TERMINAL_CONTAINMENT_RECORD_VERSION.to_le_bytes());
    record[OFFSET_RECORD_BYTES..OFFSET_OS_CODE]
        .copy_from_slice(&fixed_record_length_field().to_le_bytes());
    record[OFFSET_OS_CODE..OFFSET_OPERATION_BINDING].copy_from_slice(&code.to_le_bytes());
    record[OFFSET_OPERATION_BINDING] = match INSTALLED_EVIDENCE_RESOURCE.get() {
        Some(_) => OPERATION_BINDING_BOUND,
        None => OPERATION_BINDING_NOT_BOUND,
    };
    record[OFFSET_SITE_LEN] = site_len;
    record[OFFSET_DETAIL_LEN] = detail_len;
    let site_end = OFFSET_SITE + site.len();
    record[OFFSET_SITE..site_end].copy_from_slice(site.as_bytes());
    let detail_end = OFFSET_DETAIL + detail.len();
    record[OFFSET_DETAIL..detail_end].copy_from_slice(detail.as_bytes());
    if let Some(prepared) = INSTALLED_EVIDENCE_RESOURCE.get() {
        record[OFFSET_OPERATION_DIGEST..].copy_from_slice(&prepared.operation_digest);
    }
    Some(record)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let raw = &bytes[offset..offset + 4];
    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]])
}

#[cfg(windows)]
fn submit_record(record: &[u8; TERMINAL_CONTAINMENT_RECORD_BYTES]) -> TerminalSubmission {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    let expected = fixed_record_length_field();
    let mut written: u32 = 0;
    let accepted = unsafe {
        // SAFETY: `std::io::stderr().as_raw_handle()` returns the process
        // standard-error OS handle, which stays valid for the process life and
        // is never closed here; `record` is a live stack array of exactly
        // `expected` bytes; `written` is a live exclusive local; a null
        // OVERLAPPED requests the synchronous call, so no event, iocp, or
        // completion path is used.
        WriteFile(
            std::io::stderr().as_raw_handle(),
            record.as_ptr(),
            expected,
            &raw mut written,
            std::ptr::null_mut(),
        )
    };
    if accepted == 0 {
        // Captured immediately after the failed call, before any other Win32
        // call on this thread can overwrite the last-error value.
        let code = unsafe {
            // SAFETY: `GetLastError` takes no pointers, owns no resources, and
            // is called on the same thread immediately after the failed
            // `WriteFile`.
            GetLastError()
        };
        return TerminalSubmission::WriteFailed { code };
    }
    if written == expected {
        TerminalSubmission::Recorded { bytes: written }
    } else {
        TerminalSubmission::ShortWrite { bytes: written }
    }
}

#[cfg(not(windows))]
fn submit_record(_record: &[u8; TERMINAL_CONTAINMENT_RECORD_BYTES]) -> TerminalSubmission {
    TerminalSubmission::UnsupportedPlatform
}
