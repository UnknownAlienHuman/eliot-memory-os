//! NTFS change-journal (USN) read position and bounded page reads.
//!
//! Architecture (verified):
//! - `I8.2` (`docs/architecture/I08-02-independent-observation-routes.md:12,33`)
//!   (filesystem change journal with persisted USN cursor replay on wake for
//!   registered Windows scopes; the cursor lives outside canonical memory,
//!   replay is bounded and records wrap/gaps).
//!
//! This module owns the OS journal surface only: opening the volume,
//! querying journal state, and reading one bounded page through a caller-held
//! cursor. It stores no cursor, admits no scope, and interprets no record:
//! the Watchdog spool owns the persisted cursor and the observation adapter
//! owns the replay reading. All `unsafe` is encapsulated here behind safe
//! signatures (the Watchdog crate forbids `unsafe_code`).
//!
//! Reason mask, timeout and wait are fixed, not parameters: coverage needs
//! every change class (`0xFFFF_FFFF`), and a sensor tick never blocks
//! (`Timeout = 0`, `BytesToWaitFor = 0`), so a page is whatever the journal
//! holds at the call instant. Page bytes are capped at
//! [`MAX_USN_PAGE_BYTES`]: the journal is unbounded but one read is not.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Existing hard upper bound for one USN journal page read.
const MAX_USN_PAGE_BYTES: u32 = 256 * 1024;

/// `FSCTL_QUERY_USN_JOURNAL` (`CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, ...)`).
#[cfg(windows)]
const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00F4;
/// `FSCTL_READ_USN_JOURNAL` (`CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46, ...)`).
#[cfg(windows)]
const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00B8;

/// Maps the last OS error of a journal call to a typed refusal.
#[cfg(windows)]
fn os_journal_error() -> UsnJournalError {
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_JOURNAL_NOT_ACTIVE};
    let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    match code {
        ERROR_ACCESS_DENIED => UsnJournalError::AccessDenied,
        ERROR_JOURNAL_NOT_ACTIVE => UsnJournalError::JournalNotActive,
        _ => UsnJournalError::ProviderFailed,
    }
}

/// One persisted journal read position, owned by the caller (the Watchdog
/// spool), never by this module.
///
/// The journal identity pins the page to one journal lifetime: a recreated
/// journal reuses USN values, so a cursor without its journal identity would
/// replay a different journal's history as continuity.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct UsnCursor {
    /// `UsnJournalID` the cursor was taken from.
    pub journal_id: u64,
    /// USN to resume after (the last USN the caller already consumed).
    pub next_usn: u64,
}

/// Live state of one volume's change journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UsnJournalState {
    /// Current `UsnJournalID` (zero when no journal is active).
    pub journal_id: u64,
    /// First USN the journal can produce.
    pub first_usn: u64,
    /// USN the next journal write will use.
    pub next_usn: u64,
    /// Lowest USN still readable (records below it wrapped away).
    pub lowest_valid_usn: u64,
}

/// One parsed change record: identity and cause only, never file contents.
///
/// Names are hints for counting and correlation, never principal identity
/// (norm I8.2: file changes alone cannot establish attribution).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsnRecordView {
    /// Record USN.
    pub usn: u64,
    /// `USN_REASON_*` bitmask.
    pub reason: u32,
    /// File name in UTF-16 lossy form (see [`read_usn_journal_page`]).
    pub file_name: String,
}

/// One bounded journal page read through a cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsnJournalPage {
    /// Journal the page was read from (equals the cursor's identity).
    pub journal_id: u64,
    /// USN to resume after (last consumed record, or the cursor when the
    /// page holds no record).
    pub next_usn: u64,
    /// Parsed records in journal order.
    pub records: Vec<UsnRecordView>,
}

/// Failure to query or read the NTFS change journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsnJournalError {
    /// The watched path is not an absolute drive-rooted Windows path.
    InvalidVolume,
    /// The volume device could not be opened (non-denied failure).
    VolumeOpenFailed,
    /// Windows denied the volume or journal observation.
    AccessDenied,
    /// No journal is active on the volume.
    JournalNotActive,
    /// The journal was recreated under the cursor: resuming would replay a
    /// different journal's history as continuity.
    StaleCursor {
        /// Journal identity the cursor names.
        expected_journal_id: u64,
        /// Journal identity the volume holds now.
        observed_journal_id: u64,
    },
    /// The cursor fell below the lowest valid USN: the journal wrapped.
    /// The adapter resets to `lowest_valid_usn` and records the gap.
    JournalWrapped {
        /// Lowest USN still readable.
        lowest_valid_usn: u64,
    },
    /// A record is shorter than its own header or runs past the buffer.
    TruncatedRecord,
    /// A record names an unsupported major version (only 2 and 3 parse).
    UnsupportedRecordVersion {
        /// `MajorVersion` the record carries.
        version: u16,
    },
    /// Another OS failure prevented a trustworthy classification.
    ProviderFailed,
    /// Journal observation is unavailable on this platform.
    UnsupportedPlatform,
}

impl std::fmt::Display for UsnJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidVolume => formatter.write_str("USN volume path is not observable"),
            Self::VolumeOpenFailed => formatter.write_str("USN volume could not be opened"),
            Self::AccessDenied => formatter.write_str("USN journal observation was denied"),
            Self::JournalNotActive => formatter.write_str("no USN journal is active"),
            Self::StaleCursor {
                expected_journal_id,
                observed_journal_id,
            } => write!(
                formatter,
                "USN cursor names journal {expected_journal_id:#x}, volume holds {observed_journal_id:#x}"
            ),
            Self::JournalWrapped { lowest_valid_usn } => write!(
                formatter,
                "USN journal wrapped under the cursor; lowest valid USN is {lowest_valid_usn:#x}"
            ),
            Self::TruncatedRecord => formatter.write_str("USN record is truncated"),
            Self::UnsupportedRecordVersion { version } => {
                write!(formatter, "USN record version {version} is unsupported")
            }
            Self::ProviderFailed => formatter.write_str("USN journal observation failed"),
            Self::UnsupportedPlatform => {
                formatter.write_str("USN journal observation is unsupported")
            }
        }
    }
}

impl std::error::Error for UsnJournalError {}

/// Live state of the change journal on the volume holding `watched_root`.
///
/// `watched_root` is any absolute drive-rooted path on the volume (a
/// registered-scope root); only its drive selects the `\\.\X:` device. A
/// zero journal identity is [`UsnJournalError::JournalNotActive`], never a
/// state: there is no position in a journal that does not exist.
///
/// # Errors
///
/// Returns a typed fail-closed [`UsnJournalError`] for bad paths, denied or
/// failed volume opens, inactive journals, and non-Windows platforms.
#[cfg(windows)]
pub fn query_usn_journal_state(watched_root: &Path) -> Result<UsnJournalState, UsnJournalError> {
    let device = volume_device_path(watched_root)?;
    let volume = open_volume(&device)?;
    let mut output = [0_u8; 56];
    let mut returned = 0_u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            volume.handle(),
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            u32::try_from(output.len()).map_err(|_| UsnJournalError::ProviderFailed)?,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(os_journal_error());
    }
    let state = UsnJournalState {
        journal_id: u64::from_le_bytes(
            output[0..8]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        first_usn: u64::from_le_bytes(
            output[8..16]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        next_usn: u64::from_le_bytes(
            output[16..24]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        lowest_valid_usn: u64::from_le_bytes(
            output[24..32]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
    };
    if state.journal_id == 0 {
        return Err(UsnJournalError::JournalNotActive);
    }
    Ok(state)
}

/// Off-Windows builds retain the typed API but never observe a journal.
#[cfg(not(windows))]
pub fn query_usn_journal_state(_watched_root: &Path) -> Result<UsnJournalState, UsnJournalError> {
    Err(UsnJournalError::UnsupportedPlatform)
}

/// Reads one bounded journal page through `cursor` on the volume holding
/// `watched_root`.
///
/// The page starts after `cursor.next_usn` and holds at most `max_bytes`
/// (capped at [`MAX_USN_PAGE_BYTES`]) of records. An empty page is a live
/// empty result carrying the cursor forward, never absence: the returned
/// `next_usn` is the resume position either way. File names parse lossy:
/// names count and correlate records but never establish identity, so one
/// malformed name must not refuse the whole page.
///
/// # Errors
///
/// Returns [`UsnJournalError::StaleCursor`] when the journal was recreated
/// under the cursor, [`UsnJournalError::JournalWrapped`] when the cursor
/// fell below the lowest valid USN, and the query errors otherwise.
#[cfg(windows)]
pub fn read_usn_journal_page(
    watched_root: &Path,
    cursor: &UsnCursor,
    max_bytes: u32,
) -> Result<UsnJournalPage, UsnJournalError> {
    let device = volume_device_path(watched_root)?;
    let volume = open_volume(&device)?;
    let state = query_volume_state(&volume)?;
    if state.journal_id != cursor.journal_id {
        return Err(UsnJournalError::StaleCursor {
            expected_journal_id: cursor.journal_id,
            observed_journal_id: state.journal_id,
        });
    }
    let capped = max_bytes.clamp(8, MAX_USN_PAGE_BYTES);
    let capacity = usize::try_from(capped).map_err(|_| UsnJournalError::ProviderFailed)? + 8;
    let mut output = vec![0_u8; capacity];
    let mut input = [0_u8; 40];
    input[0..8].copy_from_slice(&cursor.next_usn.to_le_bytes());
    input[8..12].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    input[32..40].copy_from_slice(&cursor.journal_id.to_le_bytes());
    let mut returned = 0_u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            volume.handle(),
            FSCTL_READ_USN_JOURNAL,
            input.as_ptr().cast(),
            u32::try_from(input.len()).map_err(|_| UsnJournalError::ProviderFailed)?,
            output.as_mut_ptr().cast(),
            capped,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(classify_read_failure(&device, cursor));
    }
    let returned = usize::try_from(returned).map_err(|_| UsnJournalError::ProviderFailed)?;
    if returned < 8 || returned > output.len() {
        return Err(UsnJournalError::ProviderFailed);
    }
    let next_usn = u64::from_le_bytes(
        output[0..8]
            .try_into()
            .map_err(|_| UsnJournalError::ProviderFailed)?,
    );
    let records = parse_usn_record_page(&output[8..returned])?;
    Ok(UsnJournalPage {
        journal_id: cursor.journal_id,
        next_usn: records
            .last()
            .map_or(cursor.next_usn.max(next_usn), |record| {
                record.usn.max(cursor.next_usn)
            }),
        records,
    })
}

/// Off-Windows builds retain the typed API but never read a journal.
#[cfg(not(windows))]
pub fn read_usn_journal_page(
    _watched_root: &Path,
    _cursor: &UsnCursor,
    _max_bytes: u32,
) -> Result<UsnJournalPage, UsnJournalError> {
    Err(UsnJournalError::UnsupportedPlatform)
}

/// Queries journal state through an open volume handle.
#[cfg(windows)]
fn query_volume_state(volume: &VolumeHandle) -> Result<UsnJournalState, UsnJournalError> {
    let mut output = [0_u8; 56];
    let mut returned = 0_u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            volume.handle(),
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            u32::try_from(output.len()).map_err(|_| UsnJournalError::ProviderFailed)?,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(os_journal_error());
    }
    let state = UsnJournalState {
        journal_id: u64::from_le_bytes(
            output[0..8]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        first_usn: u64::from_le_bytes(
            output[8..16]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        next_usn: u64::from_le_bytes(
            output[16..24]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
        lowest_valid_usn: u64::from_le_bytes(
            output[24..32]
                .try_into()
                .map_err(|_| UsnJournalError::ProviderFailed)?,
        ),
    };
    if state.journal_id == 0 {
        return Err(UsnJournalError::JournalNotActive);
    }
    Ok(state)
}

/// Classifies a failed page read with one state re-query: a changed journal
/// identity is [`UsnJournalError::StaleCursor`], a cursor below the lowest
/// valid USN is [`UsnJournalError::JournalWrapped`], anything else keeps the
/// original OS classification.
#[cfg(windows)]
fn classify_read_failure(device: &[u16], cursor: &UsnCursor) -> UsnJournalError {
    let probe = os_journal_error();
    let Ok(volume) = open_volume(device) else {
        return probe;
    };
    let Ok(state) = query_volume_state(&volume) else {
        return UsnJournalError::JournalNotActive;
    };
    if state.journal_id != cursor.journal_id {
        return UsnJournalError::StaleCursor {
            expected_journal_id: cursor.journal_id,
            observed_journal_id: state.journal_id,
        };
    }
    if cursor.next_usn < state.lowest_valid_usn {
        return UsnJournalError::JournalWrapped {
            lowest_valid_usn: state.lowest_valid_usn,
        };
    }
    probe
}

/// One open volume handle. The handle closes on drop: callers never retain
/// it past one query or page read.
#[cfg(windows)]
struct VolumeHandle {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl VolumeHandle {
    /// Returns the raw handle for one `DeviceIoControl` call.
    fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for VolumeHandle {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

/// Opens the `\\.\X:` volume device for journal reads.
///
/// The handle carries `FILE_GENERIC_READ`: the journal `FSCTL`s are rejected
/// with `ERROR_INVALID_FUNCTION` on a no-access handle (probed), so an
/// attributes-only open cannot serve them. Opening a volume for read still
/// needs elevation; without it the open fails closed with `AccessDenied`.
#[cfg(windows)]
fn open_volume(device: &[u16]) -> Result<VolumeHandle, UsnJournalError> {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    let handle = unsafe {
        CreateFileW(
            device.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(match os_journal_error() {
            UsnJournalError::AccessDenied => UsnJournalError::AccessDenied,
            _ => UsnJournalError::VolumeOpenFailed,
        });
    }
    Ok(VolumeHandle { handle })
}

/// Builds the `\\.\X:` device path for the drive holding `watched_root`.
pub(crate) fn volume_device_path(watched_root: &Path) -> Result<Vec<u16>, UsnJournalError> {
    let text = watched_root
        .as_os_str()
        .to_str()
        .ok_or(UsnJournalError::InvalidVolume)?;
    let bytes = text.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || (bytes[2] != b'\\' && bytes[2] != b'/')
    {
        return Err(UsnJournalError::InvalidVolume);
    }
    let device = format!(r"\\.\{}:", bytes[0].to_ascii_uppercase() as char);
    Ok(device.encode_utf16().chain([0]).collect())
}

/// Parses one `FSCTL_READ_USN_JOURNAL` record area (after the leading
/// `NextUsn`) into record views in journal order.
///
/// Versions 2 and 3 parse; anything else is
/// [`UsnJournalError::UnsupportedRecordVersion`]. A zero or overrunning
/// record length is [`UsnJournalError::TruncatedRecord`]: lengths come from
/// the journal, never trusted blindly.
pub(crate) fn parse_usn_record_page(buffer: &[u8]) -> Result<Vec<UsnRecordView>, UsnJournalError> {
    let mut records = Vec::new();
    let mut offset = 0_usize;
    while offset < buffer.len() {
        let rest = &buffer[offset..];
        if rest.len() < 8 {
            return Err(UsnJournalError::TruncatedRecord);
        }
        let length = u32::from_le_bytes(
            rest[0..4]
                .try_into()
                .map_err(|_| UsnJournalError::TruncatedRecord)?,
        );
        let version = u16::from_le_bytes(
            rest[4..6]
                .try_into()
                .map_err(|_| UsnJournalError::TruncatedRecord)?,
        );
        let length = usize::try_from(length).map_err(|_| UsnJournalError::TruncatedRecord)?;
        if length < 8 || length > rest.len() {
            return Err(UsnJournalError::TruncatedRecord);
        }
        let record = &rest[..length];
        let (usn, reason, name_length, name_offset) = match version {
            2 => (
                u64::from_le_bytes(
                    record[24..32]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u32::from_le_bytes(
                    record[40..44]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u16::from_le_bytes(
                    record[56..58]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u16::from_le_bytes(
                    record[58..60]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
            ),
            3 => (
                u64::from_le_bytes(
                    record[40..48]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u32::from_le_bytes(
                    record[48..52]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u16::from_le_bytes(
                    record[64..66]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
                u16::from_le_bytes(
                    record[66..68]
                        .try_into()
                        .map_err(|_| UsnJournalError::TruncatedRecord)?,
                ),
            ),
            other => {
                return Err(UsnJournalError::UnsupportedRecordVersion { version: other });
            }
        };
        let name_length = usize::from(name_length);
        let name_offset = usize::from(name_offset);
        let name_end = name_offset
            .checked_add(name_length)
            .ok_or(UsnJournalError::TruncatedRecord)?;
        if name_end > record.len() || name_length % 2 != 0 {
            return Err(UsnJournalError::TruncatedRecord);
        }
        let units = record[name_offset..name_end]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        records.push(UsnRecordView {
            usn,
            reason,
            file_name: String::from_utf16_lossy(&units),
        });
        offset += length;
    }
    Ok(records)
}
