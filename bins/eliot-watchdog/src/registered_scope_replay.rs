//! Registered-scope journal replay step of one supervision tick (#1755 W3/C6, W4).
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose).
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes).
//!
//! One call replays one bounded journal page per candidate scope through the
//! spool-retained cursor and records at most one exact dense window on the
//! `FilesystemJournal` channel. A candidate contributes coverage only while it
//! is a current member of the admitted set: a superseded (`HistoricalOnly`) or
//! foreign (`OutsideRegistered`) root is skipped with a trace and never
//! recorded. Every replayed scope is bound to its membership through
//! [`FileChangeEvidence`](crate::observation_attribution::FileChangeEvidence)
//! with [`EventOrigin::unknown`](crate::observation_attribution::EventOrigin):
//! journal records name no writer, so no authenticated correlation exists and
//! task attribution is refused at this call site, never guessed (I8.2:
//! "Independent observation proves event existence, not principal
//! attribution").
//!
//! The step takes no daemon handle: it reads the owner spool and the platform
//! journal only, so with `eliotd` down it still runs and still refuses to
//! invent coverage. Cursor durability is save-before-ack: the adapter retains
//! the advanced cursor BEFORE the window is claimed, so a crash between the
//! save and the interval close replays the same window on the next tick (no
//! loss) while the unclosed interval publishes `INTERVAL_NOT_CLOSED` (no false
//! claim) and the next interval starts from a fresh publisher (no duplicate).
//!
//! No production registrar issues scopes, so the supervision tick passes an
//! empty admitted set and this step is a measured no-op there; the admitted
//! disposable scopes that prove it are owner-issued test-side (see the tests
//! below). Nothing here invents a scope, a position, or a window.

use std::path::{Component, Path, Prefix};

use crate::journal_replay_observation::{JournalReplayOutcome, observe_journal_replay};
use crate::observation_attribution::{
    FileChangeEvidence, RegisteredScope, ScopeMembership, resolve_scope_membership,
};
use crate::observation_coverage::{IntervalCoverageCell, ObservationChannel, RecordOutcome};
use crate::watchdog_spool::WatchdogSpool;

/// One bounded journal page read per scope per tick, in bytes.
pub(crate) const JOURNAL_REPLAY_PAGE_BYTES: u32 = 65_536;

/// Per-tick account of one
/// [`replay_registered_scopes`] call: every candidate scope lands in exactly
/// one counter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RegisteredScopeReplaySummary {
    /// Candidate scopes this call examined.
    pub(crate) seen: usize,
    /// Scopes whose page yielded a claimed replay window.
    pub(crate) replayed: usize,
    /// Scopes whose page held a USN hole: nothing claimed, cursor advanced.
    pub(crate) advanced_past_hole: usize,
    /// Scopes that seeded, reseeded, or idled: position stands, no claim.
    pub(crate) settled: usize,
    /// Scopes whose journal or volume is unreadable now.
    pub(crate) unavailable: usize,
    /// Candidates that are not current members of the admitted set.
    pub(crate) skipped_unregistered: usize,
}

/// Replays one bounded journal page per candidate scope for this tick.
///
/// `candidates` are the volumes the tick wants to replay;
/// `current`/`historical` are the admitted scope sets the membership of each
/// candidate is resolved against. Only a
/// [`ScopeMembership::CurrentMember`] candidate reaches the journal; every
/// other candidate is skipped without touching a cursor or a record. At most
/// one claimed window lands on the `FilesystemJournal` channel per interval
/// (the publisher refuses a second), but every scope's cursor still advances,
/// so no volume stalls behind the claimed one.
#[must_use]
pub(crate) fn replay_registered_scopes(
    spool: &WatchdogSpool,
    coverage: &IntervalCoverageCell,
    candidates: &[RegisteredScope],
    current: &[RegisteredScope],
    historical: &[RegisteredScope],
    max_bytes: u32,
) -> RegisteredScopeReplaySummary {
    let mut summary = RegisteredScopeReplaySummary::default();
    for scope in candidates {
        summary.seen += 1;
        match replay_one_scope(spool, coverage, scope, current, historical, max_bytes) {
            ScopeReplayEffect::Replayed => summary.replayed += 1,
            ScopeReplayEffect::AdvancedPastHole => summary.advanced_past_hole += 1,
            ScopeReplayEffect::Settled => summary.settled += 1,
            ScopeReplayEffect::Unavailable => summary.unavailable += 1,
            ScopeReplayEffect::SkippedUnregistered => summary.skipped_unregistered += 1,
        }
    }
    summary
}

/// One candidate scope's replay effect on this tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScopeReplayEffect {
    /// A replay window was claimed (or refused by the one-window bound).
    Replayed,
    /// A USN hole: nothing claimed, cursor advanced past it.
    AdvancedPastHole,
    /// Seeded, reseeded, or idle: position stands, no claim.
    Settled,
    /// Journal or volume unreadable; cursors and records untouched.
    Unavailable,
    /// Not a current member of the admitted set; ignored entirely.
    SkippedUnregistered,
}

/// Replays one candidate scope and records its window, if any.
fn replay_one_scope(
    spool: &WatchdogSpool,
    coverage: &IntervalCoverageCell,
    scope: &RegisteredScope,
    current: &[RegisteredScope],
    historical: &[RegisteredScope],
    max_bytes: u32,
) -> ScopeReplayEffect {
    let membership = resolve_scope_membership(scope.root(), current, historical);
    if membership != ScopeMembership::CurrentMember {
        tracing::debug!(
            event = "watchdog.registered_scope_replay_skipped",
            observation = "skipped",
            membership = membership.as_str(),
            root = scope.root().display().to_string(),
            "candidate scope is not currently registered; contributes no replay coverage",
        );
        return ScopeReplayEffect::SkippedUnregistered;
    }
    let Some(volume) = volume_label_for_root(scope.root()) else {
        tracing::debug!(
            event = "watchdog.registered_scope_replay_no_volume",
            observation = "unavailable",
            root = scope.root().display().to_string(),
            "registered scope names no drive volume; no journal to replay",
        );
        return ScopeReplayEffect::Unavailable;
    };
    match observe_journal_replay(spool, &volume, scope.root(), max_bytes) {
        JournalReplayOutcome::Replayed { evidence, records } => {
            bind_replayed_scope(scope, membership);
            match coverage.record_replayed(ObservationChannel::FilesystemJournal, evidence) {
                RecordOutcome::Recorded => {
                    tracing::debug!(
                        event = "watchdog.registered_scope_replayed",
                        observation = "replayed",
                        records = records,
                        "journal window claimed for the admitted scope",
                    );
                }
                outcome => {
                    tracing::debug!(
                        event = "watchdog.registered_scope_replay_not_kept",
                        observation = outcome.as_str(),
                        "replayed window was not kept as evidence for this interval",
                    );
                }
            }
            ScopeReplayEffect::Replayed
        }
        JournalReplayOutcome::AdvancedPastHole { resume_usn } => {
            tracing::debug!(
                event = "watchdog.registered_scope_replay_hole",
                observation = "unclaimed",
                resume_usn = resume_usn,
                "journal page held a USN hole; cursor advanced, nothing claimed",
            );
            ScopeReplayEffect::AdvancedPastHole
        }
        JournalReplayOutcome::Seeded
        | JournalReplayOutcome::ReseededAfterRecreate { .. }
        | JournalReplayOutcome::Idle => ScopeReplayEffect::Settled,
        JournalReplayOutcome::Unavailable(reason) => {
            tracing::debug!(
                event = "watchdog.registered_scope_replay_unavailable",
                observation = "unavailable",
                reason = reason,
                "registered scope journal unreadable now; cursors and records untouched",
            );
            ScopeReplayEffect::Unavailable
        }
    }
}

/// Binds one replayed scope root to its membership with unknown origin.
///
/// The enforcement point W4 requires: the event exists (the adapter replayed
/// its window) and its scope membership is established, but no authenticated
/// correlation supplies the writer, so
/// [`attribute_to_task`](crate::observation_attribution::FileChangeEvidence::attribute_to_task)
/// refuses and the refusal is the verdict — task attribution without a
/// correlated process never happens here.
fn bind_replayed_scope(scope: &RegisteredScope, membership: ScopeMembership) {
    let event = FileChangeEvidence::observed(scope.root().to_path_buf(), membership);
    match event.attribute_to_task() {
        Ok(_) => {
            tracing::warn!(
                event = "watchdog.registered_scope_attribution_unexpected",
                observation = "unexpected",
                "file-change event attributed without an authenticated correlation",
            );
        }
        Err(_) => {
            tracing::debug!(
                event = "watchdog.registered_scope_attribution_refused",
                observation = "refused",
                "replayed file-change event keeps unknown origin; no task attribution",
            );
        }
    }
}

/// Returns the `\\.\X:` volume label holding an absolute drive `root`.
fn volume_label_for_root(root: &Path) -> Option<String> {
    let Component::Prefix(prefix) = root.components().next()? else {
        return None;
    };
    if !matches!(prefix.kind(), Prefix::Disk(_)) {
        return None;
    }
    let drive = prefix.as_os_str().to_str()?;
    let bytes = drive.as_bytes();
    if bytes.len() != 2 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
        return None;
    }
    Some(format!("\\\\.\\{drive}"))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "the replay-step tests unwrap the owner's own spool and scope fixtures; a fixture that cannot bind is a test failure"
)]
mod tests {
    use super::*;
    use crate::observation_coverage::{
        CoverageDisposition, IntervalCoverageReport, ObservationClass,
    };
    use eliot_evaluation_contracts::JournalReplayEvidence;
    use eliot_platform_windows::ProcessIdentity;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_spool(name: &str) -> Result<WatchdogSpool, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "eliot-watchdog-scope-replay-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        Ok(WatchdogSpool::open_test(&path)?)
    }

    fn disposable_scope(name: &str) -> Result<RegisteredScope, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("eliot-o5-1755-{name}-scope"));
        Ok(RegisteredScope::new(root, "disposable-gen-1")?)
    }

    fn window(first: u64, last: u64) -> JournalReplayEvidence {
        JournalReplayEvidence {
            journal_id: "filesystem-usn-journal:scope-replay".to_owned(),
            first_cursor: first,
            last_cursor: last,
        }
    }

    fn close_report(cell: &IntervalCoverageCell) -> IntervalCoverageReport {
        cell.close_interval(2000)
            .expect("open interval closes")
            .report()
            .clone()
    }

    fn journal_record(report: &IntervalCoverageReport) -> CoverageDisposition {
        report
            .records()
            .iter()
            .find(|record| record.channel() == ObservationChannel::FilesystemJournal)
            .expect("journal record present")
            .disposition()
    }

    /// C6 gap: an empty admitted set replays nothing and records nothing — the
    /// wired channel names its omission instead of inventing coverage. No
    /// daemon, lease, or Kernel handle exists anywhere in this proof.
    #[test]
    fn empty_scope_set_records_nothing_and_names_the_gap() -> TestResult {
        let spool = test_spool("empty-set")?;
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        let summary = replay_registered_scopes(&spool, &cell, &[], &[], &[], 65_536);
        assert_eq!(summary, RegisteredScopeReplaySummary::default());
        let report = close_report(&cell);
        assert!(report.valid());
        assert_eq!(journal_record(&report), CoverageDisposition::Unknown);
        let record = report
            .records()
            .iter()
            .find(|record| record.channel() == ObservationChannel::FilesystemJournal)
            .expect("journal record present");
        assert!(record.replayed_evidence().is_none());
        assert_eq!(record.observed_replayed_observations(), 0);
        assert!(
            record
                .gaps()
                .iter()
                .any(|gap| gap.reason == "NO_ESTABLISHABLE_SAMPLE")
        );
        assert!(!report.full_coverage_claimed());
        Ok(())
    }

    /// W4 gate: a superseded scope and a foreign scope contribute no coverage,
    /// and an unreadable current scope claims none either — all deterministically,
    /// with no live journal anywhere.
    #[test]
    fn stale_and_outside_scopes_contribute_no_coverage() -> TestResult {
        let spool = test_spool("gate")?;
        let fresh = disposable_scope("fresh")?;
        let stale = disposable_scope("stale")?;
        let outsider = disposable_scope("outsider")?;
        let candidates = [fresh.clone(), stale.clone(), outsider.clone()];
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        let summary = replay_registered_scopes(
            &spool,
            &cell,
            &candidates,
            std::slice::from_ref(&fresh),
            std::slice::from_ref(&stale),
            65_536,
        );
        assert_eq!(summary.seen, 3);
        assert_eq!(summary.skipped_unregistered, 2);
        assert_eq!(summary.unavailable, 1);
        assert_eq!(summary.replayed, 0);
        let report = close_report(&cell);
        assert!(report.valid());
        assert_eq!(journal_record(&report), CoverageDisposition::Unknown);
        Ok(())
    }

    /// W4 origin: a well-formed current-member event with unknown origin is
    /// refused task attribution; the positive control proves the refusal is
    /// about the missing correlation, not the membership.
    #[test]
    fn unknown_origin_file_event_refuses_task_attribution() -> TestResult {
        let scope = disposable_scope("attribution")?;
        let path = scope.root().join("changed.txt");
        let event = FileChangeEvidence::observed(path, ScopeMembership::CurrentMember);
        assert_eq!(
            event.attribute_to_task(),
            Err(crate::observation_attribution::AttributionError::RefusedTaskAttribution)
        );
        let process = ProcessIdentity {
            process_id: 4,
            start_time_100ns: 9,
            image_path: "C:\\Windows\\System32\\store.exe".to_owned(),
        };
        let mut correlated = FileChangeEvidence::observed(
            scope.root().join("written.txt"),
            ScopeMembership::CurrentMember,
        );
        correlated.correlate_origin(&process, "attempt-7")?;
        let attribution = correlated.attribute_to_task()?;
        assert_eq!(attribution.process_key(), process.stable_key());
        assert_eq!(attribution.attempt(), "attempt-7");
        Ok(())
    }

    /// Volume derivation is pure path math: drive roots map to their device
    /// label, anything else (relative, UNC, verbatim) names no volume.
    #[test]
    fn volume_label_names_drive_volumes_only() {
        assert_eq!(
            volume_label_for_root(std::path::Path::new("C:\\scope")),
            Some("\\\\.\\C:".to_owned())
        );
        assert_eq!(
            volume_label_for_root(std::path::Path::new("relative")),
            None
        );
        assert_eq!(
            volume_label_for_root(std::path::Path::new("\\\\server\\share")),
            None
        );
        assert_eq!(
            volume_label_for_root(std::path::Path::new("\\\\?\\C:\\scope")),
            None
        );
    }

    /// A1 cursor: the retained cursor survives a spool reopen (the restart),
    /// and the next tick resumes from it — a failed read leaves it untouched,
    /// so no record is lost or skipped across the stop.
    #[test]
    fn cursor_survives_spool_reopen_and_step_resumes_from_it() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "eliot-watchdog-scope-replay-restart-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let retained = eliot_platform_windows::UsnCursor {
            journal_id: 0x0A11_CE5C_09,
            next_usn: 4242,
        };
        let scope = disposable_scope("restart")?;
        let volume = volume_label_for_root(scope.root()).expect("temp root has a drive volume");
        {
            let spool = WatchdogSpool::open_test(&path)?;
            spool.retain_journal_cursor(&volume, &retained)?;
        }
        let spool = WatchdogSpool::open_test(&path)?;
        assert_eq!(spool.read_journal_cursor(&volume)?, Some(retained));
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        let summary = replay_registered_scopes(
            &spool,
            &cell,
            std::slice::from_ref(&scope),
            std::slice::from_ref(&scope),
            &[],
            65_536,
        );
        assert_eq!(summary.seen, 1);
        assert_eq!(summary.unavailable, 1);
        assert_eq!(spool.read_journal_cursor(&volume)?, Some(retained));
        let _ = close_report(&cell);
        Ok(())
    }

    /// A3 crash: a window saved (cursor retained, window recorded) but never
    /// closed (no tick reached its close) publishes a named omission, never a
    /// coverage claim — and the next interval starts clean, never duplicating
    /// the un-acked window.
    #[test]
    fn crash_between_save_and_ack_is_a_named_omission() -> TestResult {
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        assert_eq!(
            cell.record_replayed(ObservationChannel::FilesystemJournal, window(50, 59)),
            RecordOutcome::Recorded
        );
        let abandoned = cell
            .begin_interval(2000)
            .expect("abandoned interval is published");
        let report = abandoned.report().clone();
        assert!(report.valid());
        let record = report
            .records()
            .iter()
            .find(|record| record.channel() == ObservationChannel::FilesystemJournal)
            .expect("journal record present");
        assert_eq!(record.disposition(), CoverageDisposition::Unknown);
        assert_eq!(
            record
                .gaps()
                .iter()
                .map(|gap| gap.reason)
                .collect::<Vec<_>>(),
            vec!["INTERVAL_NOT_CLOSED"]
        );
        assert_eq!(record.observed_replayed_observations(), 10);
        let report = close_report(&cell);
        assert!(report.valid());
        let record = report
            .records()
            .iter()
            .find(|record| record.channel() == ObservationChannel::FilesystemJournal)
            .expect("journal record present");
        assert_eq!(record.disposition(), CoverageDisposition::Unknown);
        assert_eq!(record.observed_replayed_observations(), 0);
        assert!(record.replayed_evidence().is_none());
        Ok(())
    }

    /// A5 daemon-down: the replay step runs with no daemon, lease, or Kernel
    /// handle anywhere in scope — only the owner spool and platform reads —
    /// and an unreadable journal still refuses healthy-by-absence.
    #[test]
    fn replay_step_runs_with_no_daemon_in_scope() -> TestResult {
        let spool = test_spool("daemon-down")?;
        let scope = disposable_scope("daemon-down")?;
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        let summary = replay_registered_scopes(
            &spool,
            &cell,
            std::slice::from_ref(&scope),
            std::slice::from_ref(&scope),
            &[],
            65_536,
        );
        assert_eq!(summary.seen, 1);
        assert_eq!(summary.unavailable, 1);
        let report = close_report(&cell);
        assert!(report.valid());
        assert_ne!(journal_record(&report), CoverageDisposition::Continuous);
        assert!(!report.full_coverage_claimed());
        Ok(())
    }

    /// A8 completeness: one interval driven through every producer the tick
    /// owns accounts every channel — live samples, the replayed window, the
    /// measured partials, and exactly the four measured-missing adapters.
    #[test]
    fn full_interval_accounts_every_producer() -> TestResult {
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        for (channel, class) in [
            (
                ObservationChannel::ScmServiceState,
                ObservationClass::ServiceState,
            ),
            (
                ObservationChannel::ProcessExitIdentity,
                ObservationClass::ProcessIdentity,
            ),
            (
                ObservationChannel::ArtifactConfigIdentity,
                ObservationClass::ArtifactDigest,
            ),
            (
                ObservationChannel::StoreProcessHealth,
                ObservationClass::ReadOnlyProbe,
            ),
            (
                ObservationChannel::ListenerInventory,
                ObservationClass::ListenerBinding,
            ),
            (
                ObservationChannel::KernelHeartbeat,
                ObservationClass::Liveness,
            ),
        ] {
            assert_eq!(cell.record(channel, class), RecordOutcome::Recorded);
        }
        assert_eq!(
            cell.record_replayed(ObservationChannel::FilesystemJournal, window(1, 4)),
            RecordOutcome::Recorded
        );
        let report = close_report(&cell);
        assert!(report.valid());
        assert!(!report.full_coverage_claimed());
        assert_eq!(
            report.blocking_channels(),
            vec![
                ObservationChannel::JobResourceCounters,
                ObservationChannel::NamedPipeHandshake,
                ObservationChannel::ArtifactConfigIdentity,
                ObservationChannel::HookEventCadence,
                ObservationChannel::SecurityAudit,
            ]
        );
        let journal = report
            .records()
            .iter()
            .find(|record| record.channel() == ObservationChannel::FilesystemJournal)
            .expect("journal record present");
        assert_eq!(journal.disposition(), CoverageDisposition::JournalReplayed);
        assert_eq!(journal.observed_replayed_observations(), 4);
        assert_eq!(journal.replayed_evidence(), Some(&window(1, 4)));
        for channel in [
            ObservationChannel::ScmServiceState,
            ObservationChannel::ProcessExitIdentity,
            ObservationChannel::StoreProcessHealth,
            ObservationChannel::ListenerInventory,
            ObservationChannel::KernelHeartbeat,
        ] {
            let record = report
                .records()
                .iter()
                .find(|record| record.channel() == channel)
                .expect("live record present");
            assert_eq!(record.disposition(), CoverageDisposition::Continuous);
        }
        Ok(())
    }

    /// Disposable-scope acceptance, live or refused: on the system volume the
    /// owner-issued scope either settles a position (elevated) or reports the
    /// exact query refusal — in both cases the retained row matches the
    /// outcome, never a half-position.
    #[test]
    fn disposable_scope_step_is_consistent_live_or_refused() -> TestResult {
        let drive = std::env::var("SystemDrive").expect("system drive present");
        let root = std::path::PathBuf::from(format!("{drive}\\"));
        let scope = RegisteredScope::new(root.clone(), "disposable-gen-1")?;
        let volume = volume_label_for_root(&root).expect("system root has a drive volume");
        let spool = test_spool("disposable-live")?;
        let cell = IntervalCoverageCell::new(1000);
        assert_eq!(cell.begin_interval(1000), None);
        let summary = replay_registered_scopes(
            &spool,
            &cell,
            std::slice::from_ref(&scope),
            std::slice::from_ref(&scope),
            &[],
            65_536,
        );
        assert_eq!(summary.seen, 1);
        assert_eq!(summary.replayed, 0);
        assert_eq!(summary.skipped_unregistered, 0);
        assert_eq!(
            summary.settled + summary.unavailable + summary.advanced_past_hole,
            1
        );
        if summary.unavailable == 1 {
            assert_eq!(spool.read_journal_cursor(&volume)?, None);
        } else {
            assert!(spool.read_journal_cursor(&volume)?.is_some());
        }
        let report = close_report(&cell);
        assert!(report.valid());
        Ok(())
    }
}
