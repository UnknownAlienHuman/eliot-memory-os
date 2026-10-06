//! Journal-replay adapter over one volume's NTFS change journal (#1755 W3).
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose).
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes),
//! I8.6 (docs/architecture/I08-06-bypass-detection.md#i86-bypass-detection).
//!
//! One call reads one bounded journal page through the spool-retained cursor
//! for one volume and reports at most one exact dense window. The window is
//! claimed only over consecutively numbered USNs the page actually returned:
//! a hole is never papered over, the cursor still advances past it (the
//! operating system positions the next read there), and the advance is
//! reported as [`JournalReplayOutcome::AdvancedPastHole`], never as
//! coverage. A first observation seeds the position at the live journal head
//! without backfill: history the Watchdog never observed cannot become
//! replayed coverage for this interval. A recreated journal reseeds rather
//! than resuming: old USNs name a different journal's history.
//!
//! The cursor is retained BEFORE the window is claimed: a page that cannot
//! be retained is reported [`JournalReplayOutcome::Unavailable`], never
//! half-claimed, so the next call retries the same window instead of
//! double-counting it. Every refusal names its bound; nothing here invents
//! a position, a window, or a scope.
//!
//! The tick does not call this yet: it holds no registered-scope roots to
//! pass (see [`RegisteredScope`](crate::observation_attribution::RegisteredScope)),
//! so no window is ever recorded and file-change coverage stays blind. The
//! adapter, the platform surface and the spool cursor are proved by unit
//! tests; the production caller waits on the scope-registry source.

use std::path::Path;

use eliot_evaluation_contracts::JournalReplayEvidence;
use eliot_platform_windows::{
    UsnCursor, UsnJournalError, UsnJournalPage, UsnRecordView, query_usn_journal_state,
    read_usn_journal_page,
};

use crate::watchdog_spool::WatchdogSpool;

/// The spool could not supply or retain the cursor.
const SPOOL_UNAVAILABLE: &str = "JOURNAL_SPOOL_UNAVAILABLE";
/// The journal state query was denied.
const QUERY_DENIED: &str = "JOURNAL_QUERY_DENIED";
/// The journal state query failed without classification.
const QUERY_FAILED: &str = "JOURNAL_QUERY_FAILED";
/// No journal is active on the volume.
const NOT_ACTIVE: &str = "JOURNAL_NOT_ACTIVE";
/// The page read was denied.
const READ_DENIED: &str = "JOURNAL_READ_DENIED";
/// The page read failed without classification.
const READ_FAILED: &str = "JOURNAL_READ_FAILED";
/// The advanced cursor could not be retained.
const RETAIN_FAILED: &str = "JOURNAL_RETAIN_FAILED";

/// One journal-replay adapter step over one volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JournalReplayOutcome {
    /// The first position was established at the live journal head; no
    /// window is claimed for this call.
    Seeded,
    /// The journal was recreated under the retained cursor: the old history
    /// is lost and the position was re-established at the new head.
    ReseededAfterRecreate {
        /// Journal identity the volume holds now.
        observed_journal_id: u64,
    },
    /// One exact dense window was claimed and its cursor retained.
    Replayed {
        /// Claimed window over consecutively numbered USNs.
        evidence: JournalReplayEvidence,
        /// Records the window holds (equals the window length exactly).
        records: usize,
    },
    /// The page held no new record; the position was retained.
    Idle,
    /// The page held a USN hole: nothing is claimed and the cursor advanced
    /// past it, so the next read does not stall on it.
    AdvancedPastHole {
        /// Resume USN the cursor now names.
        resume_usn: u64,
    },
    /// The journal is unreadable now; the retained cursor stands untouched.
    Unavailable(&'static str),
}

/// Observes one journal page for `volume` through its spool-retained cursor.
///
/// `volume` is the spool key (the `\\.\X:` device label); `watched_root` is
/// any absolute path on that volume selecting the device for the platform
/// call. At most one page (`max_bytes`, platform-capped) is read and at most
/// one window claimed per call: the tick calls once per volume per interval,
/// matching the one-window-per-channel-per-interval record bound.
pub(crate) fn observe_journal_replay(
    spool: &WatchdogSpool,
    volume: &str,
    watched_root: &Path,
    max_bytes: u32,
) -> JournalReplayOutcome {
    let retained = match spool.read_journal_cursor(volume) {
        Ok(cursor) => cursor,
        Err(_) => return JournalReplayOutcome::Unavailable(SPOOL_UNAVAILABLE),
    };
    match retained {
        None => seed_position(spool, volume, watched_root),
        Some(cursor) => replay_from_cursor(spool, volume, watched_root, &cursor, max_bytes),
    }
}

/// Establishes the first read position at the live journal head.
fn seed_position(spool: &WatchdogSpool, volume: &str, watched_root: &Path) -> JournalReplayOutcome {
    let state = match query_usn_journal_state(watched_root) {
        Ok(state) => state,
        Err(error) => return JournalReplayOutcome::Unavailable(map_query_error(&error)),
    };
    let cursor = UsnCursor {
        journal_id: state.journal_id,
        next_usn: state.next_usn,
    };
    match spool.retain_journal_cursor(volume, &cursor) {
        Ok(()) => JournalReplayOutcome::Seeded,
        Err(_) => JournalReplayOutcome::Unavailable(SPOOL_UNAVAILABLE),
    }
}

/// Replays one page from a retained cursor, resetting across journal
/// recreation and wrap instead of resuming a foreign history.
fn replay_from_cursor(
    spool: &WatchdogSpool,
    volume: &str,
    watched_root: &Path,
    cursor: &UsnCursor,
    max_bytes: u32,
) -> JournalReplayOutcome {
    match read_usn_journal_page(watched_root, cursor, max_bytes) {
        Ok(page) => claim_page(spool, volume, cursor.journal_id, &page),
        Err(UsnJournalError::StaleCursor {
            observed_journal_id,
            ..
        }) => reseed_after_recreate(spool, volume, watched_root, observed_journal_id),
        Err(UsnJournalError::JournalWrapped { lowest_valid_usn }) => {
            let reset = UsnCursor {
                journal_id: cursor.journal_id,
                next_usn: lowest_valid_usn,
            };
            match read_usn_journal_page(watched_root, &reset, max_bytes) {
                Ok(page) => claim_page(spool, volume, cursor.journal_id, &page),
                Err(error) => JournalReplayOutcome::Unavailable(map_read_error(&error)),
            }
        }
        Err(error) => JournalReplayOutcome::Unavailable(map_read_error(&error)),
    }
}

/// Re-establishes the position at a recreated journal's head.
fn reseed_after_recreate(
    spool: &WatchdogSpool,
    volume: &str,
    watched_root: &Path,
    observed_journal_id: u64,
) -> JournalReplayOutcome {
    let state = match query_usn_journal_state(watched_root) {
        Ok(state) => state,
        Err(error) => return JournalReplayOutcome::Unavailable(map_query_error(&error)),
    };
    if state.journal_id != observed_journal_id {
        return JournalReplayOutcome::Unavailable(READ_FAILED);
    }
    let cursor = UsnCursor {
        journal_id: state.journal_id,
        next_usn: state.next_usn,
    };
    match spool.retain_journal_cursor(volume, &cursor) {
        Ok(()) => JournalReplayOutcome::ReseededAfterRecreate {
            observed_journal_id,
        },
        Err(_) => JournalReplayOutcome::Unavailable(SPOOL_UNAVAILABLE),
    }
}

/// Claims at most one exact dense window from a read page.
///
/// The cursor is retained before anything is claimed: a page whose advance
/// cannot be retained reports [`JournalReplayOutcome::Unavailable`] and the
/// next call retries the same window instead of double-counting it.
fn claim_page(
    spool: &WatchdogSpool,
    volume: &str,
    journal_id: u64,
    page: &UsnJournalPage,
) -> JournalReplayOutcome {
    if page.records.is_empty() {
        return match retain_cursor(spool, volume, journal_id, page.next_usn) {
            Ok(()) => JournalReplayOutcome::Idle,
            Err(reason) => JournalReplayOutcome::Unavailable(reason),
        };
    }
    let Some((first, last)) = dense_window(&page.records) else {
        tracing::warn!(
            event = "watchdog.journal_replay_hole",
            observation = "unclaimed",
            resume_usn = page.next_usn,
            "journal page holds a USN hole; nothing is claimed and the cursor advances past it",
        );
        return match retain_cursor(spool, volume, journal_id, page.next_usn) {
            Ok(()) => JournalReplayOutcome::AdvancedPastHole {
                resume_usn: page.next_usn,
            },
            Err(reason) => JournalReplayOutcome::Unavailable(reason),
        };
    };
    match retain_cursor(spool, volume, journal_id, page.next_usn) {
        Ok(()) => JournalReplayOutcome::Replayed {
            evidence: JournalReplayEvidence {
                journal_id: format!("filesystem-usn-journal:{journal_id:016x}"),
                first_cursor: first,
                last_cursor: last,
            },
            records: page.records.len(),
        },
        Err(reason) => JournalReplayOutcome::Unavailable(reason),
    }
}

/// Retains one advanced read position for a volume.
fn retain_cursor(
    spool: &WatchdogSpool,
    volume: &str,
    journal_id: u64,
    next_usn: u64,
) -> Result<(), &'static str> {
    spool
        .retain_journal_cursor(
            volume,
            &UsnCursor {
                journal_id,
                next_usn,
            },
        )
        .map_err(|_| RETAIN_FAILED)
}

/// Returns the exact dense USN span the records cover, or `None`.
///
/// A window is claimable only when every record continues its predecessor:
/// the claimed count then equals the window length exactly, which is what
/// the channel record requires.
fn dense_window(records: &[UsnRecordView]) -> Option<(u64, u64)> {
    let first = records.first()?;
    let mut previous = first.usn;
    for record in &records[1..] {
        if record.usn != previous.checked_add(1).unwrap_or(0) {
            return None;
        }
        previous = record.usn;
    }
    Some((first.usn, previous))
}

/// Maps a journal state query failure to a stable refusal code.
fn map_query_error(error: &UsnJournalError) -> &'static str {
    match error {
        UsnJournalError::AccessDenied => QUERY_DENIED,
        UsnJournalError::JournalNotActive => NOT_ACTIVE,
        _ => QUERY_FAILED,
    }
}

/// Maps a journal page read failure to a stable refusal code.
fn map_read_error(error: &UsnJournalError) -> &'static str {
    match error {
        UsnJournalError::AccessDenied => READ_DENIED,
        UsnJournalError::JournalNotActive => NOT_ACTIVE,
        _ => READ_FAILED,
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the replay tests unwrap the owner's own spool and journal calls; a fixture that cannot bind is a test failure"
)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_spool(name: &str) -> Result<WatchdogSpool, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "eliot-watchdog-replay-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Ok(WatchdogSpool::open_test(&path)?)
    }

    fn system_volume() -> (String, std::path::PathBuf) {
        let drive = std::env::var("SystemDrive").expect("system drive present");
        let label = format!("\\\\.\\{}:", drive.chars().next().expect("drive letter"));
        (label, std::path::PathBuf::from(format!("{drive}\\")))
    }

    fn record(usn: u64) -> UsnRecordView {
        UsnRecordView {
            usn,
            reason: 0x100,
            file_name: "t.txt".to_owned(),
        }
    }

    /// An unusable volume is unavailable and retains nothing: refusal
    /// repairs nothing and invents no position.
    #[test]
    fn invalid_volume_is_unavailable_and_retains_nothing() -> TestResult {
        let spool = test_spool("invalid-volume")?;
        assert_eq!(
            observe_journal_replay(
                &spool,
                "\\\\.\\C:",
                std::path::Path::new("relative"),
                65_536
            ),
            JournalReplayOutcome::Unavailable(QUERY_FAILED)
        );
        assert_eq!(spool.read_journal_cursor("\\\\.\\C:")?, None);
        Ok(())
    }

    /// A fresh spool either seeds at the live head (elevated) or reports
    /// the exact query refusal (otherwise): in both cases the retained row
    /// matches the outcome, never a half-position.
    #[test]
    fn fresh_spool_seed_or_refusal_is_consistent() -> TestResult {
        let spool = test_spool("seed-consistent")?;
        let (volume, root) = system_volume();
        match observe_journal_replay(&spool, &volume, &root, 65_536) {
            JournalReplayOutcome::Seeded => {
                assert!(spool.read_journal_cursor(&volume)?.is_some());
            }
            JournalReplayOutcome::Unavailable(reason) => {
                assert!(
                    matches!(reason, QUERY_DENIED | NOT_ACTIVE),
                    "unexpected refusal {reason}"
                );
                assert_eq!(spool.read_journal_cursor(&volume)?, None);
            }
            other => panic!("fresh spool must seed or refuse, got {other:?}"),
        }
        Ok(())
    }

    /// A query failure leaves a previously retained cursor untouched: the
    /// next readable call resumes where the journal left off, not where
    /// the failed call stopped.
    #[test]
    fn query_failure_leaves_retained_cursor_untouched() -> TestResult {
        let spool = test_spool("query-untouched")?;
        let cursor = UsnCursor {
            journal_id: 0x01dc_2182_7839_5a3f,
            next_usn: 41,
        };
        spool.retain_journal_cursor("\\\\.\\C:", &cursor)?;
        assert_eq!(
            observe_journal_replay(
                &spool,
                "\\\\.\\C:",
                std::path::Path::new("relative"),
                65_536
            ),
            JournalReplayOutcome::Unavailable(READ_FAILED)
        );
        assert_eq!(spool.read_journal_cursor("\\\\.\\C:")?, Some(cursor));
        Ok(())
    }

    /// Only consecutively numbered USNs form a claimable window: a hole, an
    /// empty page, or a single record behave exactly.
    #[test]
    fn dense_window_accepts_consecutive_usns_only() {
        assert_eq!(
            dense_window(&[record(5), record(6), record(7)]),
            Some((5, 7))
        );
        assert_eq!(dense_window(&[record(5), record(7)]), None);
        assert_eq!(dense_window(&[]), None);
        assert_eq!(dense_window(&[record(9)]), Some((9, 9)));
    }
}
