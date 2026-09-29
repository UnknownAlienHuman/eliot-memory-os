//! P-06 purge-ledger ownership and the one authoritative ledger revision.
//!
//! `I5.13:44` requires a `full_recovery` backup receipt to bind the
//! purge-ledger revision, and `A13.7` requires a restore to verify privacy
//! purge and revocation closure before any effect. That revision is evidence
//! only when the owner that applied the purges issues it. A value copied out
//! of the archive under check compares the caller with itself, and a value
//! recomputed over an entry list the caller handed over measures that list,
//! not the ledger.
//!
//! ORS is that owner. It stores the [`PurgeLedgerEntry`] values the existing
//! ledger contract already defines — no second entry type, no second ledger,
//! no parallel store — and publishes the ledger-wide revision it allocated
//! when each purge was applied. The revision is allocated inside the same
//! exclusive write transaction that makes the entry durable, so exactly one
//! revision is consumed per applied purge: replaying a purge the ledger
//! already holds consumes none, and a revision can never advance without the
//! purge that named it.

use eliot_security_contracts::PurgeLedgerEntry;
use serde::{Deserialize, Serialize};

use crate::OrsError;

/// Stable ORS record-type name of one durable purge-ledger record.
///
/// Published rather than spelled as a literal at a call site so a refusal can
/// name this contract instead of a second copy of the same string.
pub const PURGE_LEDGER_RECORD_TYPE: &str = "purge_ledger";

/// One durable purge-ledger record: the accepted ledger entry together with
/// the ledger-wide revision the owner allocated when it applied that purge.
///
/// The row carries no purged content, exactly like the ledger entry it holds:
/// `A12.08` requires the purge ledger to preserve a non-revealing record and
/// deletion scope without reconstructing the content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeLedgerRecord {
    /// ORS wire/storage contract version of this row. A row written under
    /// another version fails its read closed instead of being reinterpreted as
    /// the same applied purge.
    pub contract_version: u16,
    /// Ledger-wide revision the owner allocated for this purge.
    ///
    /// It is the position of this purge in the owner's own applied sequence:
    /// never a value the caller proposed, and never a count recomputed over the
    /// rows a reader happens to hold. `entry.revision` is a different thing —
    /// the per-entry revision the purge owner itself wrote — and the two are
    /// deliberately not conflated.
    pub applied_revision: u64,
    /// The accepted purge-ledger entry, stored verbatim as applied.
    pub entry: PurgeLedgerEntry,
}

impl PurgeLedgerRecord {
    /// Validates the stored row against the current ORS contract and the
    /// existing ledger-entry contract.
    ///
    /// The entry is checked with the ledger contract's own `validate()` rather
    /// than a second local rule set, so a row can never be durable in a shape
    /// the ledger itself refuses.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if self.applied_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "purge_ledger_applied_revision",
                reason: "an applied purge always consumes a non-zero ledger revision",
            });
        }
        self.entry
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }

    /// Returns whether two records carry the exact same applied purge.
    ///
    /// The applied revision is excluded because it is owner-allocated
    /// progression, not caller binding: an exact replay of the same entry
    /// under the same `purge_id` is one applied purge and must not consume a
    /// second revision, while a different entry under that `purge_id` is a
    /// conflict rather than a second answer.
    #[must_use]
    pub fn same_applied_purge(&self, other: &Self) -> bool {
        self.entry == other.entry
    }
}
