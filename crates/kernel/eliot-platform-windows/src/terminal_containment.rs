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
    let encoded = serde_json::to_vec(context)
        .map_err(|_| TerminalContainmentError::OperationIdentityUnavailable)?;
    let operation_digest: [u8; TERMINAL_CONTAINMENT_OPERATION_DIGEST_BYTES] =
        Sha256::digest(&encoded).into();

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

fn is_bounded_identity(value: &str, max_bytes: usize) -> bool {
    value.len() <= max_bytes && PlatformHandle::new(value).is_ok()
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
