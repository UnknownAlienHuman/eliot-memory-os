//! Import of the bounded Watchdog spool fence as suspended forensic evidence.
//!
//! Architecture: ARCH-RES-03 (A13.7), I05.13.
//! Implementation: I5.13 (bounded `WatchdogSpoolFence` in a `full_recovery`
//! receipt), issue #960.
//!
//! A `full_recovery` archive REFUSES to build without a `watchdog_spool`
//! member (`BackupBundle::validate_class_requirements`), so the member is
//! mandatory. Before this module the restore dropped it after the bundle
//! digest passed: no phase read it, and the `watchdog_signals` obligation was
//! one constant regardless of whether the fence named zero unreconciled
//! critical signals or a thousand. I5.13 requires the receipt to carry "any
//! unreconciled critical Watchdog signals/intents under a
//! `WatchdogSpoolFence`", so the member is evidence that requires READING it.
//!
//! This module is that read, and it is deliberately the ONLY thing it does.
//!
//! ## What it reads, and what it does not claim
//!
//! It reads the archive's own [`WatchdogSpoolFence`] and returns one suspended
//! [`RestoreHistoricalAuthority`] of kind
//! [`RestoreHistoricalKind::WatchdogSignal`] per declared unresolved signal
//! digest. That is the same shape, over the same mechanism, as
//! [`suspended_recovery_entries`](super::suspended_recovery_entries) already
//! uses for the ORS snapshot's pending operations — the restore preserves the
//! source's declared unresolved work as evidence and stops there.
//!
//! What it explicitly does NOT claim:
//!
//! - It does not assert that the signals were RECONCILED. Reconciliation is the
//!   #955 Watchdog owner's decision and the restore performs none of it, so the
//!   `watchdog_signals` obligation stays an unsatisfied owner slot.
//! - It does not assert completeness against an independent denominator. The
//!   expected set here is the ARCHIVE's own declared list, because the archive
//!   is the only thing that carries the fence. A caller cannot widen it (the
//!   fence's digests are unique and digest-shaped, checked by the fence's own
//!   `validate`) and cannot narrow it (every declared digest is emitted).
//! - It does not reactivate supervision. I5.13 is explicit that Watchdog
//!   operational snapshots restore "only as forensic/suspended evidence and
//!   never as active supervision or authority", so every entry is
//!   `suspended: true`, and [`RestoreHistoricalAuthority::validate`] refuses any
//!   entry that is not.
//! - It performs no I/O, opens no `watchdog.redb`, holds no cursor and reads no
//!   live spool. A live Watchdog owner read is that owner's channel, not this
//!   crate's.
//!
//! ## Why this lives here and not in the composition binary
//!
//! The mapping from an archive member to restore evidence is archive/backup
//! semantics (`bins/AGENTS.md`), and the crate already owns the identical
//! mapping for the ORS fence. This is that one function again over the other
//! mandatory member, not a second scheme.
//!
//! ## Error mapping
//!
//! Only [`BackupError`] is used. An absent fence is not an error here: the
//! caller decides applicability, exactly as it does for the ORS snapshot. A
//! malformed fence — unbounded, a blank fence id, a malformed or duplicated
//! signal digest — is [`BackupError::UnboundedWatchdogSpool`] or
//! [`BackupError::InvalidField`] from the fence's own `validate`, never an
//! empty evidence list.
//!
//! The declared digests are emitted in sorted order so the same fence always
//! produces byte-identical evidence; an order that depended on the archive's
//! serialization order would make a resume's evidence differ from the original
//! run's.

use super::{BackupError, RestoreHistoricalAuthority, RestoreHistoricalKind, WatchdogSpoolFence};

/// Imports the unresolved critical Watchdog signals under `fence` as suspended
/// forensic evidence.
///
/// One [`RestoreHistoricalAuthority`] of kind
/// [`RestoreHistoricalKind::WatchdogSignal`] is returned per entry in
/// [`WatchdogSpoolFence::unresolved_signal_digests`], each `suspended: true`
/// and each carrying that exact digest as its `historical_ref`. A fence that
/// declares no unresolved signal yields no entries — which is a fact about the
/// archive's declaration, not a claim that the destination spool is empty.
///
/// The fence is validated first through its own accepted `validate`, so an
/// unbounded fence, a blank fence id, or a malformed/duplicated signal digest
/// refuses here rather than producing partial evidence. Nothing in this
/// function activates, resumes, or reconciles anything: the entries are
/// historical evidence, and the caller may not mark them otherwise.
///
/// # Errors
///
/// Returns the typed refusal from [`WatchdogSpoolFence::validate`] when the
/// fence is not a coherent bounded fence, and the typed refusal from
/// [`RestoreHistoricalAuthority::validate`] if a produced entry is not
/// suspended (which the `suspended: true` this function always sets cannot
/// trigger, so a failure here is a defect rather than an input class).
pub fn suspended_watchdog_signal_entries(
    fence: &WatchdogSpoolFence,
) -> Result<Vec<RestoreHistoricalAuthority>, BackupError> {
    fence.validate()?;
    // Sorted, so the same fence always yields the same evidence bytes and a
    // resumed run reconstructs the identical list. `validate` already proved
    // uniqueness, so the sort cannot merge two entries.
    let mut signal_digests = fence.unresolved_signal_digests.clone();
    signal_digests.sort();
    let mut entries = Vec::with_capacity(signal_digests.len());
    for historical_ref in signal_digests {
        let entry = RestoreHistoricalAuthority {
            kind: RestoreHistoricalKind::WatchdogSignal,
            historical_ref,
            suspended: true,
        };
        entry.validate()?;
        entries.push(entry);
    }
    Ok(entries)
}
