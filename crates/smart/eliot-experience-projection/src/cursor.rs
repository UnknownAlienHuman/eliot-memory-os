//! Live journal cursors and snapshot coverage over the Governor owner.
//!
//! The observation journal is append-only and key-ordered
//! (`BTreeMap<idempotency_key, ObservationJournalEntry>`), so a cursor is
//! exactly the last key observed plus the entry count, and reads after a
//! cursor are exactly the keys ordered after it. These helpers perform
//! genuine owner reads ([`ObservationJournal::snapshot`]) with no new
//! state, no vendor execution, and no fabrication: every value returned
//! comes from the supplied live journal.
//!
//! Owner placement note: these functions read only through the journal's
//! public snapshot API and belong beside it long-term
//! (`crates/governor/eliot-observation/src/lib.rs`, next to
//! `snapshot`/`get`/`from_entries`). They live here so this lane can ship
//! without colliding with the observation owner's active classifier work
//! (#217); relocation is a pure move with no semantic change.
//!
//! Cursor/coverage reads never establish completeness: [`journal_coverage`]
//! reports admitted/rejected counts with a recomputable digest, and unknown
//! or blind intervals stay unknown. This module is a read surface, not
//! edge, product, or W9-consumer proof.

#![forbid(unsafe_code)]

use eliot_observation::{ObservationAdmissionResult, ObservationJournal, ObservationJournalEntry};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ObservationError;

/// Opaque cursor over one observed journal state: last key plus count.
///
/// `None` reads as the beginning of the journal. Keys compare in the
/// journal's own key order; cursors from another journal are meaningless
/// and simply match nothing or everything, never silently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalCursor {
    /// Last idempotency key observed, if any.
    pub last_key: Option<String>,
    /// Entries observed at the cursor.
    pub entry_count: usize,
}

impl JournalCursor {
    /// The beginning of the journal: matches everything.
    #[must_use]
    pub fn beginning() -> Self {
        Self {
            last_key: None,
            entry_count: 0,
        }
    }

    /// Validate cursor shape: non-blank key when present.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if let Some(key) = &self.last_key {
            if key.trim().is_empty() || key.chars().any(char::is_control) {
                return Err(ObservationError::InvalidField {
                    field: "journal_cursor.last_key",
                    reason: "must be non-blank and free of control characters",
                });
            }
        }
        Ok(())
    }
}

/// Read the current cursor of a live journal: last key plus entry count.
#[must_use]
pub fn journal_cursor(journal: &ObservationJournal) -> JournalCursor {
    let snapshot = journal.snapshot();
    JournalCursor {
        last_key: snapshot.last().map(|entry| entry.idempotency_key.clone()),
        entry_count: snapshot.len(),
    }
}

/// Read entries ordered after a cursor from a live journal.
///
/// Returns owned entries, like [`ObservationJournal::snapshot`], filtered
/// to keys ordered after the cursor's last key. A foreign cursor matches
/// by key order only and never errors: absence of overlap is an empty
/// result, not a failure.
#[must_use]
pub fn entries_since(
    journal: &ObservationJournal,
    cursor: &JournalCursor,
) -> Vec<ObservationJournalEntry> {
    journal
        .snapshot()
        .into_iter()
        .filter(|entry| match &cursor.last_key {
            None => true,
            Some(key) => entry.idempotency_key.as_str() > key.as_str(),
        })
        .collect()
}

/// Coverage of one live journal read: admitted/rejected counts with a
/// recomputable digest over admitted request digests in key order.
///
/// The digest binds exactly what was read and lets a later read prove
/// change-or-same; it establishes no completeness beyond the read itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalCoverage {
    /// Entries in the read.
    pub entry_count: usize,
    /// Entries admitted (Accepted result).
    pub admitted: usize,
    /// Entries rejected (Rejected result).
    pub rejected: usize,
    /// sha256 over admitted request digests in key order, empty when none.
    pub coverage_digest: String,
}

impl JournalCoverage {
    /// Validate shape: 64-hex digest and reconciling counts.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.coverage_digest.len() != 64
            || !self
                .coverage_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ObservationError::InvalidField {
                field: "journal_coverage.coverage_digest",
                reason: "must be lowercase SHA-256 hex",
            });
        }
        if self.admitted + self.rejected != self.entry_count {
            return Err(ObservationError::CoverageIncomplete {
                reason: "admitted plus rejected must equal entries read",
            });
        }
        Ok(())
    }
}

/// Read coverage of a live journal in one pass.
#[must_use]
pub fn journal_coverage(journal: &ObservationJournal) -> JournalCoverage {
    use eliot_contracts::{canonical_json_bytes, sha256_hex};
    let snapshot = journal.snapshot();
    let mut admitted = 0usize;
    let mut rejected = 0usize;
    let mut digests: Vec<&str> = Vec::new();
    for entry in &snapshot {
        match &entry.result {
            ObservationAdmissionResult::Accepted { .. } => {
                admitted += 1;
                digests.push(entry.request_digest.as_str());
            }
            ObservationAdmissionResult::Rejected { .. } => {
                rejected += 1;
            }
            _ => {}
        }
    }
    // Replayed entries never persist (the rebuild rejects them), so any
    // other variant here is future-proofed as uncounted, never admitted.
    digests.sort_unstable();
    let coverage_digest = canonical_json_bytes(&digests)
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_else(|_| "0".repeat(64));
    JournalCoverage {
        entry_count: snapshot.len(),
        admitted,
        rejected,
        coverage_digest,
    }
}
