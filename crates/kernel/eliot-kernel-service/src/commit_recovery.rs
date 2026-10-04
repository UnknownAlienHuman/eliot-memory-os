//! Unknown-commit recovery for canonical Store mutations (I14.21, issue #1690).
//!
//! Architecture traceability: `I14.21` requires that on a connection failure
//! during commit the Kernel queries the `WriteReceipt` by idempotency key and
//! then reconciles (committed), retries under the same identity (known
//! rollback), or pauses the Ordering Scope, preserves the operation, and
//! opens Problem State (unknown). `I14.24` requires that ORS
//! unavailability closes the recovery path fail-closed and that no pending
//! acceptance is ever synthesized.
//!
//! ## Division of responsibility (read before extending)
//!
//! Duplicate-safety is NOT owned here. The Store enforces idempotency keys
//! and the transport client (`EbpCanonicalStoreClient`) reconciles every
//! uncertain send through an exact receipt lookup before returning, so a
//! same-identity resend can never double-apply. This module adds the three
//! things those layers do not: (1) the same-identity retry on a
//! terminal-not-committed receipt (known rollback); (2) the durable
//! unknown-commit record plus Ordering Scope pause plus visible Problem
//! State on a still-unknown outcome; (3) disposition-first handling of a
//! resubmitted key (fresh receipt evidence decides, never a blind send).
//!
//! ## Flow
//!
//! ```text
//! recover_commit: disposition-first (open record? query evidence first)
//!   -> pause gate (paused scope? refuse)
//!   -> send once
//!   -> Committed => resolve + return (exactly one mutation)
//!   -> KnownRollback => one same-identity retry, then resolve + return
//!   -> NeedsNewIdentity => resolve + return (caller mints a new identity)
//!   -> Missing/Unavailable => stage open record + pause scopes + typed error
//!   -> other error => deterministic refusal, returned unchanged
//! ```
//!
//! A resolved record never reopens; a resubmitted terminal key re-queries
//! fresh receipt evidence and returns it without a new send. Scope pause is
//! held both in memory (fast path) and durably (open ORS records), so a
//! restart rehydrates the same paused set from the database.
//!
//! ## Checked pause observation (issue #2763)
//!
//! The in-memory index is a *mirror*, never an authority. Every admission
//! decision reads [`CheckedPauseObservation`], whose three states are
//! complete-empty, complete-with-records, and unavailable/incomplete. An
//! absent ORS handle, a decode or storage failure, a poisoned required
//! lock, and a bounded query that ran out of coverage all produce
//! `Unavailable`; none of them can produce complete-empty. That distinction
//! is the whole point: an unreadable pause ledger is not an empty pause
//! ledger, and treating it as one turned durable uncertainty into permission
//! for a dependent mutation. I14.24 requires exactly this, and I14.21's
//! "pause the Ordering Scope until an evidence-backed disposition" is only
//! meaningful while the pause set itself is honest about its coverage.
//!
//! ## Retained binding and the contract-version clause (issue #2764 item 1)
//!
//! [`verify_retained_binding`] compares the four fields the persisted
//! `UnknownCommitRecord` actually carries — operation id, idempotency key,
//! canonical request hash, and the original scope/owner binding
//! (`ordering_scopes`) — and names every disagreeing field in one
//! [`CommitRecoveryError::RetainedRecordConflict`]. The fifth field the item
//! names, "applicable contract version", is NOT compared, and this module
//! does not pretend otherwise: `UnknownCommitRecord` is a
//! `#[serde(deny_unknown_fields)]` persisted row with no version field, so
//! there is no stored version to compare and inventing one would fabricate a
//! value the durable state never held. I5.22 requires "core schema is
//! explicit and versioned" and "migration IDs/checksums are immutable after
//! release" — adding the field is a real schema change, and a comparable
//! contract version is only truthful once rows written by a *different*
//! contract can be told apart from rows written by this one. This issue owns
//! no migration, so the clause is void here, not silently satisfied. The
//! record type's own schema evolution is the owning question, recorded here
//! rather than papered over in code.
//!
//! I5.27 does require that idempotency be defined over canonical bytes rather
//! than caller spelling, and on the Dreamer recovery leg the admitted request
//! hash is presented by the caller. That is why
//! [`verify_dreamer_canonical_request_hash`] exists here: it recomputes the
//! hash through the owning Dreamer protocol contract
//! ([`DurableRequestIdentity::digest_for`]) so the retained-state comparison
//! runs on a contract-derived binding, not on a spelled string.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use eliot_ors::{
    MAX_RECOVERY_PAGE, RedbRecoveryStore, UnknownCommitOutcome, UnknownCommitRecord,
    UnknownCommitRecoveryCursor,
};
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableRequestIdentity};
use eliot_store_api::{
    OperationIdentity, Resubmission, StoreError, WriteReceipt, WriteReceiptStatus,
};
use sha2::{Digest as _, Sha256};

/// Terminal classification of a Store receipt observed after a commit
/// attempt whose outcome was uncertain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitRecoveryClass {
    /// The mutation committed: reconcile and return, never resend.
    Committed,
    /// The mutation terminally did not commit and the Store allows the same
    /// identity again: retry exactly once under the identical identity.
    KnownRollback,
    /// The receipt forbids same-identity resubmission (dead-lettered, or a
    /// new identity is required after a condition): resolve and return the
    /// receipt so the caller mints a new identity. Never retry here.
    NeedsNewIdentity(UnknownCommitOutcome),
}

/// Classifies one observed receipt for unknown-commit recovery.
///
/// Only [`WriteReceiptStatus::Committed`] reconciles as committed. Every
/// other terminal status is a known non-commit; whether the same identity
/// may be retried is decided solely by the receipt's [`Resubmission`]
/// disposition, never by the status name.
#[must_use]
pub fn classify_commit_receipt(receipt: &WriteReceipt) -> CommitRecoveryClass {
    match receipt.status {
        WriteReceiptStatus::Committed => CommitRecoveryClass::Committed,
        WriteReceiptStatus::DeadLetter => {
            CommitRecoveryClass::NeedsNewIdentity(UnknownCommitOutcome::DeadLetter)
        }
        WriteReceiptStatus::Rejected | WriteReceiptStatus::Cancelled => {
            match receipt.resubmission {
                Resubmission::None => CommitRecoveryClass::KnownRollback,
                Resubmission::NewIdentityAfterCondition => {
                    CommitRecoveryClass::NeedsNewIdentity(UnknownCommitOutcome::NewIdentityRequired)
                }
            }
        }
    }
}

/// Typed unknown-commit recovery failure.
///
/// Every variant refuses or reports without synthesizing acceptance: an
/// unknown outcome is never reported as committed, terminal, unavailable,
/// or safe-to-retry, and no blind duplicate send ever follows.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommitRecoveryError {
    /// The commit outcome is still unknown after receipt lookup. The
    /// operation is preserved in the durable record (`preserved`) and its
    /// scopes are paused while open. No dependent mutation in those scopes
    /// is admitted until an evidence-backed disposition resolves it.
    #[error(
        "canonical commit outcome unknown for idempotency key {idempotency_key}: problem state open (preserved: {preserved}, paused scopes: {paused_scopes:?})"
    )]
    UnknownCommitOpen {
        /// Admitted idempotency key whose outcome is unknown.
        idempotency_key: String,
        /// Ordering scopes paused while the record is open.
        paused_scopes: Vec<String>,
        /// Whether the attempt is preserved in the durable ORS record.
        preserved: bool,
    },
    /// A mutation was submitted for an ordering scope paused by another
    /// key's open unknown-commit record. The operation was not sent.
    #[error(
        "ordering scope {scope} is paused by unknown commit {paused_by_key}: dependent mutation refused"
    )]
    ScopePaused {
        /// Refused ordering scope.
        scope: String,
        /// Idempotency key whose open record pauses the scope.
        paused_by_key: String,
    },
    /// The same idempotency key is already terminally resolved, but the
    /// fresh receipt evidence does not bind it: the Store answer cannot be
    /// adopted. No send occurred.
    #[error(
        "resubmitted idempotency key {idempotency_key} receipt evidence does not bind the admitted identity"
    )]
    ReceiptIdentityConflict {
        /// Resubmitted idempotency key.
        idempotency_key: String,
    },
    /// The receipt lookup itself failed deterministically. The commit
    /// outcome stays exactly as unknown as before: no retry, no adoption.
    #[error("unknown-commit receipt lookup failed for idempotency key {idempotency_key}: {detail}")]
    ReceiptQueryFailed {
        /// Admitted idempotency key under disposition.
        idempotency_key: String,
        /// Owner error text from the failed lookup.
        detail: String,
    },
    /// The ORS recovery record is unavailable (absent handle or storage
    /// failure). Durable mutation admission through this path is closed
    /// (I14.24): the outcome is reported, never synthesized.
    #[error("unknown-commit ORS recovery unavailable: {detail}")]
    OrsUnavailable {
        /// What is missing or failed.
        detail: String,
    },
    /// A mutating operation proved the Ordering Scope of the ledger record it
    /// writes but not the enclosing level an open record may be indexed at, so
    /// its coverage by the open unknown-commit set cannot be shown. This is
    /// the precise missing-link limitation, never a bypass: an unproven link
    /// is not evidence that a mutation is unpaused, so durable admission stays
    /// closed while any other open record could be covering it.
    #[error(
        "mutating operation {operation} proves no Ordering Scope above the ledger record it \
         writes, so its unknown-commit pause coverage cannot be proven: {detail}"
    )]
    OrderingScopeUnresolved {
        /// Closed operation kind whose enclosing Ordering Scope is not derivable.
        operation: String,
        /// Why no enclosing scope is available for this operation.
        detail: String,
    },
    /// A retained record exists under the presented idempotency key but does
    /// not bind the presented operation, or later evidence contradicts the
    /// terminal disposition already bound. The old history is preserved and
    /// the adoption is rejected: a different operation reusing one key, or a
    /// changed terminal digest, is a conflict and never a replacement.
    #[error(
        "retained unknown-commit record for idempotency key {idempotency_key} conflicts with the presented operation: {detail}"
    )]
    RetainedRecordConflict {
        /// Idempotency key whose retained record is in conflict.
        idempotency_key: String,
        /// Exact conflict: which field disagreed and with what.
        detail: String,
    },
    /// The commit attempt was deterministically refused (pre-effect Store
    /// validation or client contract failure). Returned unchanged: no
    /// recovery semantics apply and nothing was staged.
    #[error("canonical commit refused: {detail}")]
    CommitRefused {
        /// Owner refusal text.
        detail: String,
    },
}

/// Computes the stable evidence digest bound when an unknown-commit record
/// resolves: SHA-256 over the exact observed receipt bytes.
#[must_use]
pub fn receipt_evidence_digest(receipt: &WriteReceipt) -> String {
    let bytes = serde_json::to_vec(receipt).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

/// Builds the open unknown-commit record staged when a commit outcome stays
/// unknown after receipt lookup.
///
/// # Errors
///
/// Returns [`CommitRecoveryError::CommitRefused`] when the admitted
/// operation identity is not a well-formed label; nothing is staged.
pub fn open_record_for(
    identity: &OperationIdentity,
    ordering_scopes: &[String],
) -> Result<UnknownCommitRecord, CommitRecoveryError> {
    let operation_id =
        eliot_ors::OperationIdentity::new(identity.operation_id.as_str()).map_err(|error| {
            CommitRecoveryError::CommitRefused {
                detail: format!("admitted operation identity is not a label: {error}"),
            }
        })?;
    Ok(UnknownCommitRecord {
        idempotency_key: identity.idempotency_key.clone(),
        operation_id,
        canonical_request_hash: identity.canonical_request_hash.clone(),
        ordering_scopes: ordering_scopes.to_owned(),
        outcome: None,
        evidence_receipt_digest: None,
    })
}

/// Checks that an observed receipt binds the exact admitted identity.
/// A receipt for another operation, key, or request digest is never
/// adopted, however it was observed.
///
/// This is the one full operation/key/hash verifier for this module, and
/// every recovery adoption runs it: the disposition path, the send path, the
/// same-identity retry, and the Dreamer read-first path in
/// `store_gateway` all call exactly this function rather than comparing a
/// subset of fields. Issue #2764 requires the whole binding at every
/// adoption, including the already-terminal shortcuts, so this stays
/// `pub(crate)` instead of being re-implemented per caller.
pub(crate) fn verify_receipt_binding(
    receipt: &WriteReceipt,
    identity: &OperationIdentity,
) -> Result<(), CommitRecoveryError> {
    if receipt.operation_id != identity.operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != identity.canonical_request_hash
    {
        return Err(CommitRecoveryError::ReceiptIdentityConflict {
            idempotency_key: identity.idempotency_key.clone(),
        });
    }
    Ok(())
}

fn ors_error(detail: impl std::fmt::Display) -> CommitRecoveryError {
    CommitRecoveryError::OrsUnavailable {
        detail: detail.to_string(),
    }
}

/// Bounded coverage of one checked pause observation.
///
/// The owner query is bounded so a per-mutation admission check can never
/// become an unbounded full-store scan. Exhausting the bound yields
/// [`CheckedPauseObservation::Unavailable`], never an empty page: a bounded
/// answer that stopped early has not proven anything about the records it did
/// not reach, so it closes admission rather than admitting on a partial read.
pub const MAX_OBSERVED_OPEN_COMMITS: usize = 4096;

/// The owner-issued durable revision one checked pause observation was read
/// under.
///
/// `revision` is the unknown-commit family's own monotone counter, read out of
/// the owner in the same read transaction that served the page. It is therefore
/// a fact about the durable family rather than about this process: it advances
/// in the same ORS write transaction as every stage and every resolution, so a
/// pause published by any writer — this process, another gateway instance, or
/// another process entirely — moves it.
///
/// That is what lets admission and release order against it. A clearance decided
/// under revision R is stale the moment the family reaches R+1, and a mirror
/// entry stamped with a revision the owner has since passed describes a pause
/// that is provably newer than the scan that decided the answer. `None` means no
/// revision could be read at all, which is an unavailable answer and never a
/// cleared one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PauseLedgerBinding {
    /// Owner-issued family revision, or `None` when none could be read.
    pub revision: Option<u64>,
}

impl PauseLedgerBinding {
    /// Returns the durable revision, or the typed absence of one.
    #[must_use]
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }
}

/// One checked observation of the durable unknown-commit pause ledger.
///
/// This is the admission input. It is deliberately not a `Vec`: a `Vec`
/// cannot say whether it is the whole truth, which is precisely the defect
/// this type removes. A caller cannot accidentally treat `Unavailable` as
/// "no pauses" because the empty set only exists in
/// [`Self::CompleteEmpty`], which requires a successful bounded read of a
/// present owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckedPauseObservation {
    /// The owner answered completely and no open record exists anywhere.
    CompleteEmpty {
        /// Owner and revision that answered.
        binding: PauseLedgerBinding,
    },
    /// The owner answered completely and these are every open record.
    CompleteWithRecords {
        /// Owner and revision that answered.
        binding: PauseLedgerBinding,
        /// Every open record, with its own operation and scope binding.
        records: Vec<UnknownCommitRecord>,
    },
    /// The pause set is NOT known: absent handle, decode or storage failure,
    /// poisoned required state, or a bounded query that lost coverage.
    Unavailable {
        /// Owner and revision of the failed attempt.
        binding: PauseLedgerBinding,
        /// Exactly what could not be observed.
        detail: String,
    },
}

impl CheckedPauseObservation {
    /// Returns the owner/revision binding this observation was made under.
    #[must_use]
    pub const fn binding(&self) -> &PauseLedgerBinding {
        match self {
            Self::CompleteEmpty { binding }
            | Self::CompleteWithRecords { binding, .. }
            | Self::Unavailable { binding, .. } => binding,
        }
    }

    /// Returns whether this observation proved the complete applicable
    /// open-record set.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }

    /// Returns every open record of a complete observation; empty for a
    /// complete-empty answer and for an unavailable one, which callers must
    /// test with [`Self::is_complete`] or [`Self::unavailable_error`]
    /// before treating empty as "nothing is paused".
    #[must_use]
    pub fn records(&self) -> &[UnknownCommitRecord] {
        match self {
            Self::CompleteWithRecords { records, .. } => records,
            Self::CompleteEmpty { .. } | Self::Unavailable { .. } => &[],
        }
    }

    /// Returns the typed fail-closed refusal when durable recovery state is
    /// not available, and `None` when the observation is complete.
    ///
    /// This is the "require available durable recovery state" gate: mutating
    /// work consults it even when its own scope vector is empty, so an
    /// unreadable ledger closes dependent durable mutation admission (I14.24)
    /// instead of silently permitting it.
    #[must_use]
    pub fn unavailable_error(&self) -> Option<CommitRecoveryError> {
        match self {
            Self::Unavailable { binding, detail } => Some(CommitRecoveryError::OrsUnavailable {
                detail: format!(
                    "durable unknown-commit pause state is unavailable at owner-issued family revision {}: {detail}; dependent durable mutation admission is closed and a permitted read of an exact receipt stays available",
                    binding
                        .revision
                        .map_or_else(|| "unreadable".to_owned(), |revision| revision.to_string()),
                ),
            }),
            Self::CompleteEmpty { .. } | Self::CompleteWithRecords { .. } => None,
        }
    }

    /// Returns the other-key open record pausing `scope`, if any.
    ///
    /// `except_key` is the admitted key of the mutation being gated: a key
    /// never pauses itself, because the disposition path leaves its own
    /// record open across its own single retry.
    #[must_use]
    pub fn pausing_key_for(&self, scope: &str, except_key: &str) -> Option<&str> {
        self.records().iter().find_map(|record| {
            (record.idempotency_key != except_key
                && record
                    .ordering_scopes
                    .iter()
                    .any(|open_scope| open_scope == scope))
            .then_some(record.idempotency_key.as_str())
        })
    }

    /// Returns whether any open record other than `except_key` exists.
    ///
    /// Used by the missing-scope gate: a mutating operation that proves no
    /// Ordering Scope cannot be shown unaffected by a record it cannot
    /// locate, so any other open record blocks it.
    #[must_use]
    pub fn any_open_except(&self, except_key: &str) -> bool {
        self.records()
            .iter()
            .any(|record| record.idempotency_key != except_key)
    }
}

/// One retained mirror entry: the scope, the key that paused it, and the
/// observation revision that proved it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PausedScopeEntry {
    /// Ordering Scope this entry holds paused.
    pub scope: String,
    /// Idempotency key of the open record that paused it, when durably known.
    pub paused_by_key: String,
    /// Observation revision that last proved the pause.
    pub observed_revision: u64,
}

/// State of the in-process pause mirror.
///
/// Coverage is stored, never inferred: `owner: None` is the constructor's
/// uninitialized state and is explicitly *not* an observed clear ledger, so
/// no negative answer can be taken from it.
#[derive(Default)]
struct PausedScopeMirrorState {
    entries: BTreeMap<String, PausedScopeEntry>,
    observed_revision: Option<u64>,
    coverage: PauseCoverage,
    last_refresh_limitation: Option<String>,
}

/// Whether the mirror currently holds proven-complete evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PauseCoverage {
    /// The mirror has never been answered by an owner: uninitialized
    /// evidence, never an observed clear ledger (issue #2763 item 3).
    #[default]
    Uninitialized,
    /// The last observation was complete.
    Complete,
    /// The last observation failed: entries are last-known positives and
    /// their coverage is unavailable.
    Unavailable,
}

/// In-process mirror of the Ordering Scopes paused by open unknown-commit
/// records, with per-entry provenance and explicit coverage.
///
/// The durable open set in ORS is authoritative; this exists so admission can
/// report and retain the last-known positive pauses without a database round
/// trip, and so a failed refresh is visible rather than silent. It is one
/// object shared by reference with the gateway — there is no second pause
/// index anywhere.
pub struct PausedScopeMirror {
    state: Mutex<PausedScopeMirrorState>,
}

impl PausedScopeMirror {
    /// Creates an uninitialized mirror.
    ///
    /// The empty entry set here is uninitialized evidence, not an observed
    /// clear ledger: coverage starts `Uninitialized` and the first
    /// authoritative answer comes from [`Self::observe`]. No negative
    /// admission answer is ever taken from this constructor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(PausedScopeMirrorState::default()),
        }
    }

    /// Observes the durable pause ledger through the owner and reconciles
    /// this mirror.
    ///
    /// The owner is read with no lock held, so neither the gateway/service
    /// mutex nor this mirror's own mutex is ever held across a read or an
    /// `await`. A complete answer replaces the mirrored set and records each
    /// entry's source, which is how an obsolete entry is healed: it is
    /// removed only because a complete observation from a present owner no
    /// longer covers it, i.e. its original record is resolved or otherwise
    /// authoritatively dispositioned. A later empty query alone can never
    /// erase a possibly issued effect, because a failed query is `Unavailable`
    /// and keeps every last-known positive entry with its source.
    pub fn observe(&self, ors: Option<&RedbRecoveryStore>) -> CheckedPauseObservation {
        let Some(store) = ors else {
            return self.record_unavailable(
                PauseLedgerBinding { revision: None },
                "no durable recovery owner is bound to this gateway, so the pause ledger was \
                 never read"
                    .to_owned(),
            );
        };
        // The owner-issued family revision is read first and frozen for the whole
        // answer. Every page is then served under it, so a pause staged while
        // this read is in flight moves the revision and the next page refuses
        // rather than answering from a torn set.
        let revision = match store.unknown_commit_recovery_revision() {
            Ok(revision) => revision,
            Err(error) => {
                return self.record_unavailable(
                    PauseLedgerBinding { revision: None },
                    format!(
                        "the durable pause ledger revision could not be read: {error}; the open \
                         set was not enumerated at all"
                    ),
                );
            }
        };
        let binding = PauseLedgerBinding {
            revision: Some(revision),
        };
        let mut records: Vec<UnknownCommitRecord> = Vec::new();
        // The per-page ceiling is the owner's `MAX_RECOVERY_PAGE`, not the
        // coverage bound: the coverage bound caps how much this answer may
        // accumulate, while the page ceiling caps how much any single read does.
        // The two are different limits and conflating them would either reject
        // every observation or restore an unbounded read.
        let mut cursor = match UnknownCommitRecoveryCursor::start(revision, MAX_RECOVERY_PAGE) {
            Ok(cursor) => cursor,
            Err(error) => {
                return self.record_unavailable(
                    binding,
                    format!("the bounded pause cursor is unusable: {error}"),
                );
            }
        };
        loop {
            let page = match store.scan_unknown_commit_recovery_page(&cursor) {
                Ok(page) => page,
                Err(error) => {
                    return self.record_unavailable(
                        binding,
                        format!(
                            "the bounded owner query could not be continued under revision \
                             {revision}: {error}; the open set is not completely known"
                        ),
                    );
                }
            };
            records.extend(page.records);
            // The bound is applied to what has actually been accumulated, so an
            // over-large family is refused rather than materialised. A page that
            // stopped at its ceiling proves nothing about the records it did not
            // reach, so exhaustion is incomplete, never empty.
            if records.len() > MAX_OBSERVED_OPEN_COMMITS {
                return self.record_unavailable(
                    binding,
                    format!(
                        "the bounded owner query returned more than \
                         {MAX_OBSERVED_OPEN_COMMITS} open records under revision {revision}; the \
                         answer is incomplete, not empty"
                    ),
                );
            }
            if page.complete {
                break;
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => {
                    return self.record_unavailable(
                        binding,
                        format!(
                            "the bounded owner query reported an incomplete page with no \
                             continuation under revision {revision}; the open set is not \
                             completely known"
                        ),
                    );
                }
            }
        }
        let observation = if records.is_empty() {
            CheckedPauseObservation::CompleteEmpty { binding }
        } else {
            CheckedPauseObservation::CompleteWithRecords {
                binding,
                records: records.clone(),
            }
        };
        self.apply_complete(revision, &records);
        observation
    }

    /// Reconciles the mirror from a complete observation.
    ///
    /// An entry stamped by a strictly newer revision than this observation
    /// was proved by a pause staged after the read that decided this answer,
    /// so it survives: an older observation cannot erase a concurrent new
    /// pause. Everything else is replaced, and an entry this observation no
    /// longer covers is healed because its original record is resolved or
    /// otherwise authoritatively dispositioned.
    fn apply_complete(&self, revision: u64, records: &[UnknownCommitRecord]) {
        let mut entries: BTreeMap<String, PausedScopeEntry> = BTreeMap::new();
        for record in records {
            for scope in &record.ordering_scopes {
                entries
                    .entry(scope.clone())
                    .or_insert_with(|| PausedScopeEntry {
                        scope: scope.clone(),
                        paused_by_key: record.idempotency_key.clone(),
                        observed_revision: revision,
                    });
            }
        }
        let Ok(mut state) = self.state.lock() else {
            // A poisoned mirror lock must never look like a clear ledger. The
            // observation already answered; the mirror simply keeps its
            // previous state and stays Unavailable, and every admission
            // consults the observation rather than this cache.
            return;
        };
        state.entries.retain(|scope, entry| {
            if entry.observed_revision > revision {
                // Concurrently staged after this observation was read.
                return true;
            }
            !entries.contains_key(scope)
        });
        state.entries.extend(entries);
        state.observed_revision = Some(revision);
        state.coverage = PauseCoverage::Complete;
        state.last_refresh_limitation = None;
    }

    /// Records a failed observation: entries and their source are kept as
    /// last-known positives and coverage is marked unavailable.
    fn record_unavailable(
        &self,
        binding: PauseLedgerBinding,
        detail: String,
    ) -> CheckedPauseObservation {
        if let Ok(mut state) = self.state.lock() {
            state.coverage = PauseCoverage::Unavailable;
            state.observed_revision = binding.revision;
            state.last_refresh_limitation = Some(detail.clone());
        }
        CheckedPauseObservation::Unavailable { binding, detail }
    }

    /// Records a pause proved by a successful durable stage.
    ///
    /// Called only after ORS accepted the record, so the mirror never names a
    /// pause that no durable record backs. The entry is stamped with the
    /// owner-issued family revision the stage advanced to, so it is strictly
    /// newer than any observation read before that stage: a release or refresh
    /// already in flight cannot erase this pause with the older revision it
    /// decided on. The revision is the durable one, so a pause published by any
    /// writer orders the same way as one published here.
    pub fn record_paused(&self, revision: u64, scopes: &[String], key: &str) {
        if scopes.is_empty() {
            return;
        }
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        for scope in scopes {
            state
                .entries
                .entry(scope.clone())
                .or_insert_with(|| PausedScopeEntry {
                    scope: scope.clone(),
                    paused_by_key: key.to_owned(),
                    observed_revision: revision,
                });
        }
    }

    /// Returns the mirrored scopes with their source, or the typed reason
    /// the mirror could not be read.
    ///
    /// A poisoned required lock is explicit, never zero: it returns
    /// `OrsUnavailable` instead of an empty list.
    pub fn mirrored_entries(&self) -> Result<Vec<PausedScopeEntry>, CommitRecoveryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CommitRecoveryError::OrsUnavailable {
                detail: "the in-process unknown-commit pause mirror is poisoned, so the paused \
                         Ordering Scope set cannot be read"
                    .to_owned(),
            })?;
        Ok(state.entries.values().cloned().collect())
    }

    /// Returns the coverage the mirror entries were last observed under.
    ///
    /// `Uninitialized` is the constructor's state and is deliberately not an
    /// observed clear ledger.
    #[must_use]
    pub fn coverage(&self) -> PauseCoverage {
        self.state
            .lock()
            .map_or(PauseCoverage::Unavailable, |state| state.coverage)
    }

    /// Returns the owner-issued durable family revision the mirror is currently
    /// bound to, or `None` while it has never been answered.
    #[must_use]
    pub fn observed_revision(&self) -> Option<u64> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.observed_revision)
    }

    /// Returns the retained limitation from the last failed refresh, if any.
    ///
    /// A successful terminal ORS write followed by a failed mirror refresh
    /// keeps its recorded disposition and retains the limitation here, so it
    /// is reported on the next observation and closes the next mutating
    /// admission instead of being silently forgotten.
    #[must_use]
    pub fn last_refresh_limitation(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.last_refresh_limitation.clone())
    }

    /// Releases the named scopes that a fresh complete observation shows are
    /// covered by no remaining open record.
    ///
    /// This is the unified release path for both helpers. It re-observes
    /// rather than reusing the pre-resolution scan, so an older scan cannot
    /// erase a concurrent new pause: the removal decision is made against
    /// current entries and revisions, immediately before the mirror is
    /// mutated, under the caller's existing admission/order serialization. A
    /// scope still covered by another open record keeps its pause, so two
    /// records over one scope need both to resolve.
    pub fn release_resolved(
        &self,
        ors: Option<&RedbRecoveryStore>,
        scopes: &[String],
        resolved_key: &str,
    ) -> PauseReleaseOutcome {
        if scopes.is_empty() {
            return PauseReleaseOutcome::NothingToRelease;
        }
        let observation = self.observe(ors);
        if let Some(error) = observation.unavailable_error() {
            // A successful terminal ORS write followed by a failed mirror
            // refresh is a recorded disposition plus a refresh limitation.
            // Nothing is released and the commit is not reported as failed;
            // the limitation is retained on the mirror, so the next
            // observation reports it and the next mutating admission refuses.
            let detail = error.to_string();
            return PauseReleaseOutcome::RefreshUnavailable {
                scopes: scopes.to_owned(),
                detail,
            };
        }
        // A complete observation always carries the owner-issued revision it was
        // read under. A revision-less complete answer is not one this mirror can
        // have produced, so it releases nothing rather than guessing an order.
        let Some(revision) = observation.binding().revision else {
            return PauseReleaseOutcome::RefreshUnavailable {
                scopes: scopes.to_owned(),
                detail: "the refresh proved no owner-issued unknown-commit family revision, so \
                         no scope could be released"
                    .to_owned(),
            };
        };
        let retained: Vec<String> = scopes
            .iter()
            .filter(|scope| {
                observation.records().iter().any(|record| {
                    record.idempotency_key != resolved_key
                        && record.ordering_scopes.iter().any(|open| open == *scope)
                })
            })
            .cloned()
            .collect();
        let released: Vec<String> = scopes
            .iter()
            .filter(|scope| !retained.contains(scope))
            .cloned()
            .collect();
        let Ok(mut state) = self.state.lock() else {
            return PauseReleaseOutcome::RefreshUnavailable {
                scopes: released,
                detail: "the in-process unknown-commit pause mirror is poisoned, so no released \
                         scope could be recorded"
                    .to_owned(),
            };
        };
        if state.coverage != PauseCoverage::Complete {
            return PauseReleaseOutcome::RefreshUnavailable {
                scopes: released,
                detail: "the in-process unknown-commit pause mirror has no complete evidence, so \
                         no released scope could be recorded"
                    .to_owned(),
            };
        }
        // A concurrent stage that landed after the deciding observation is
        // stamped with a strictly newer revision, so this older scan cannot
        // erase that new pause.
        let mut removed: Vec<String> = Vec::new();
        let mut superseded: Vec<String> = Vec::new();
        for scope in &released {
            let concurrent = state
                .entries
                .get(scope)
                .is_some_and(|entry| entry.observed_revision > revision);
            if concurrent {
                superseded.push(scope.clone());
            } else if state.entries.remove(scope).is_some() {
                removed.push(scope.clone());
            }
        }
        state.last_refresh_limitation = None;
        state.observed_revision = observation.binding().revision;
        PauseReleaseOutcome::Released {
            scopes: removed,
            retained,
            superseded,
            binding: *observation.binding(),
        }
    }
}

impl Default for PausedScopeMirror {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of one release attempt, including the refresh limitation a
/// successful disposition may still carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PauseReleaseOutcome {
    /// Every named scope was covered by no remaining open record and was
    /// released at this observation revision.
    Released {
        /// Scopes whose mirror entry was removed.
        scopes: Vec<String>,
        /// Scopes still covered by another open record, kept paused.
        retained: Vec<String>,
        /// Scopes left paused because a pause was staged concurrently, after
        /// the observation this release decided on was read.
        superseded: Vec<String>,
        /// Owner-issued revision the release decision was made under.
        binding: PauseLedgerBinding,
    },
    /// Nothing was released because the refresh could not be proven
    /// complete. The recorded terminal disposition stands.
    RefreshUnavailable {
        /// Scopes that would have been released had the scan been complete.
        scopes: Vec<String>,
        /// Exactly why nothing was released.
        detail: String,
    },
    /// The disposition named no Ordering Scope, so there is nothing to
    /// release and nothing was observed.
    NothingToRelease,
}

/// Disposition-first handling for an already-open unknown-commit record.
///
/// Fresh receipt evidence decides: committed resolves and returns the
/// receipt with no new send; a rollback-needing-new-identity resolves and
/// returns the receipt; a known rollback lets the caller proceed to its
/// single send WITHOUT resolving first, so the record stays open across
/// the retry and resolves exactly once when the retry outcome lands (a
/// crash between still dispositions correctly on restart). A still-unknown
/// outcome refuses with the open Problem State. Returns `Ok(None)` when
/// the caller must proceed to send.
async fn dispose_open_record<QueryFut>(
    ors: &RedbRecoveryStore,
    paused: &PausedScopeMirror,
    open: &UnknownCommitRecord,
    identity: &OperationIdentity,
    query: impl Fn() -> QueryFut,
) -> Result<Option<WriteReceipt>, CommitRecoveryError>
where
    QueryFut: Future<Output = Result<WriteReceipt, StoreError>>,
{
    let key = open.idempotency_key.clone();
    let receipt = match query().await {
        Ok(receipt) => receipt,
        Err(
            StoreError::MissingReceiptEnvelope
            | StoreError::UnknownOutcome { .. }
            | StoreError::Unavailable,
        ) => {
            return Err(CommitRecoveryError::UnknownCommitOpen {
                idempotency_key: key,
                paused_scopes: open.ordering_scopes.clone(),
                preserved: true,
            });
        }
        Err(error) => {
            return Err(CommitRecoveryError::ReceiptQueryFailed {
                idempotency_key: key,
                detail: error.to_string(),
            });
        }
    };
    verify_receipt_binding(&receipt, identity)?;
    match classify_commit_receipt(&receipt) {
        CommitRecoveryClass::Committed => {
            resolve_staged(ors, paused, &key, UnknownCommitOutcome::Committed, &receipt)?;
            Ok(Some(receipt))
        }
        CommitRecoveryClass::KnownRollback => Ok(None),
        CommitRecoveryClass::NeedsNewIdentity(outcome) => {
            resolve_staged(ors, paused, &key, outcome, &receipt)?;
            Ok(Some(receipt))
        }
    }
}

/// Resolves one open record with its receipt evidence and releases the
/// scopes no longer paused by any open record.
///
/// The durable resolve is the commit point: it happens first and is the only
/// step whose failure is an error. Release follows and its outcome is
/// returned rather than raised, because a mirror refresh that fails after a
/// proven commit must not turn that commit into a reported failure. The
/// [`PauseReleaseOutcome::RefreshUnavailable`] arm is how a caller with a
/// typed carrier (the Dreamer gateway) still exposes the limitation.
fn resolve_staged(
    ors: &RedbRecoveryStore,
    paused: &PausedScopeMirror,
    key: &str,
    outcome: UnknownCommitOutcome,
    receipt: &WriteReceipt,
) -> Result<PauseReleaseOutcome, CommitRecoveryError> {
    let digest = receipt_evidence_digest(receipt);
    let open = ors
        .load_unknown_commit(key)
        .map_err(ors_error)?
        .ok_or_else(|| CommitRecoveryError::ReceiptQueryFailed {
            idempotency_key: key.to_owned(),
            detail: "staged unknown-commit record vanished before resolution".to_owned(),
        })?;
    resolve_open_record(ors, key, outcome, &digest)?;
    Ok(paused.release_resolved(Some(ors), &open.ordering_scopes, key))
}

/// Resolves an open record under exact expected identity, outcome and
/// receipt commitment (issue #2764 item 5).
///
/// `resolve_unknown_commit` only resolves an open record and never replaces
/// a bound digest, so a second resolution fails. That failure is not an
/// error to retry blindly: the record is reloaded, and a concurrent
/// reconciliation that already reached the same outcome and digest is
/// *reused*, while a different outcome or a changed digest is a conflict.
/// Concurrent reconciliation therefore cannot replace a committed result
/// with a different receipt, and a lost response replays the same terminal
/// result.
pub(crate) fn resolve_open_record(
    ors: &RedbRecoveryStore,
    key: &str,
    outcome: UnknownCommitOutcome,
    evidence_receipt_digest: &str,
) -> Result<ResolutionOutcome, CommitRecoveryError> {
    match ors.resolve_unknown_commit(key, outcome, evidence_receipt_digest) {
        Ok(Some(record)) => Ok(ResolutionOutcome::Resolved { record }),
        Ok(None) => Err(CommitRecoveryError::ReceiptQueryFailed {
            idempotency_key: key.to_owned(),
            detail: "no unknown-commit record exists to resolve".to_owned(),
        }),
        Err(error) => {
            let current = ors.load_unknown_commit(key).map_err(ors_error)?;
            match current {
                Some(record) => match (record.outcome, record.evidence_receipt_digest.as_deref()) {
                    (Some(recorded), Some(digest))
                        if recorded == outcome && digest == evidence_receipt_digest =>
                    {
                        Ok(ResolutionOutcome::AlreadyResolved { record })
                    }
                    // The record is reloaded and still open, so the resolve
                    // itself failed and no concurrent reconciliation reached a
                    // terminal state. That is the owner failure below, not a
                    // contradiction of recorded evidence: this arm must precede
                    // the catch-all below, or a still-open record would be
                    // reported as a conflict against a terminal state it does
                    // not hold.
                    (None, _) => Err(ors_error(error)),
                    (recorded, digest) => Err(CommitRecoveryError::RetainedRecordConflict {
                        idempotency_key: key.to_owned(),
                        detail: format!(
                            "the record already holds terminal outcome {recorded:?} with evidence \
                             digest {digest:?}, which contradicts the presented outcome \
                             {outcome:?} with evidence digest {evidence_receipt_digest:?}; the \
                             recorded history is preserved and later evidence never replaces it"
                        ),
                    }),
                },
                None => Err(ors_error(error)),
            }
        }
    }
}

/// How one durable resolution ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolutionOutcome {
    /// This call performed the resolution and bound the receipt evidence.
    Resolved {
        /// The terminal record as durably written.
        record: UnknownCommitRecord,
    },
    /// A concurrent reconciliation already recorded the identical terminal
    /// outcome and evidence digest; the same result is reused.
    AlreadyResolved {
        /// The terminal record already durably recorded.
        record: UnknownCommitRecord,
    },
}

impl ResolutionOutcome {
    /// Returns the terminal record either way.
    #[must_use]
    pub(crate) const fn record(&self) -> &UnknownCommitRecord {
        match self {
            Self::Resolved { record } | Self::AlreadyResolved { record } => record,
        }
    }
}

/// Runs one canonical commit through unknown-commit recovery (I14.21).
///
/// `identity` is the admitted write-attempt identity keyed by idempotency
/// key; `ordering_scopes` are paused while the outcome is unknown. `send`
/// performs exactly one commit attempt per call (called at most twice: the
/// initial attempt plus one same-identity retry after a known rollback);
/// `query` looks the receipt up by the admitted identity without sending.
///
/// `ors` is the durable recovery owner. When `None`, staging, pause, and
/// disposition are unavailable and every unknown outcome fails closed with
/// [`CommitRecoveryError::OrsUnavailable`]. That `None` branch is stated
/// honestly: it skips the disposition check, the pause gate, and the
/// durable scan entirely, so this legacy/reference seam is NOT evidence of
/// production readiness. A production durable path must supply the owner; the
/// Dreamer gateway refuses a mutating operation with no owner outright
/// (issue #2763) rather than reaching here with a skipped gate.
///
/// `paused` is the in-process pause mirror, always updated alongside the
/// durable record so admission gating never depends on a database round trip
/// alone, and never trusted as the admission input on its own: the gate below
/// reads the authoritative checked observation.
pub async fn recover_commit<SendFut, QueryFut>(
    ors: Option<&RedbRecoveryStore>,
    paused: &PausedScopeMirror,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
    mut send: impl FnMut() -> SendFut,
    query: impl Fn() -> QueryFut,
) -> Result<WriteReceipt, CommitRecoveryError>
where
    SendFut: Future<Output = Result<WriteReceipt, StoreError>>,
    QueryFut: Future<Output = Result<WriteReceipt, StoreError>>,
{
    let key = identity.idempotency_key.clone();
    // Whether an unknown-commit record is open for this key and must
    // resolve exactly once when the send journey below ends. Staging is
    // lazy (only on unknown outcomes), so a fresh key starts unstaged.
    let mut staged = false;
    if let Some(ors) = ors {
        // 1. Disposition-first: an already-open record means a previous attempt
        //    under this key ended unknown. Fresh evidence decides; never a
        //    blind send.
        if let Some(open) = ors.load_unknown_commit(&key).map_err(ors_error)? {
            if open.outcome.is_some() {
                // Terminally resolved earlier: re-query fresh evidence and
                // return it. No new send under any circumstance. The full
                // operation/key/hash verifier runs here too, so a terminal
                // record never adopts a different operation's receipt.
                let receipt = query().await.map_err(|error| match error {
                    StoreError::MissingReceiptEnvelope
                    | StoreError::UnknownOutcome { .. }
                    | StoreError::Unavailable => CommitRecoveryError::ReceiptQueryFailed {
                        idempotency_key: key.clone(),
                        detail: "resolving receipt evidence vanished after terminal disposition"
                            .to_owned(),
                    },
                    error => CommitRecoveryError::ReceiptQueryFailed {
                        idempotency_key: key.clone(),
                        detail: error.to_string(),
                    },
                })?;
                verify_receipt_binding(&receipt, identity)?;
                return Ok(receipt);
            }
            if let Some(receipt) = dispose_open_record(ors, paused, &open, identity, &query).await?
            {
                return Ok(receipt);
            }
            // The record stays open across the send below and resolves
            // exactly once when that journey ends.
            staged = true;
        }
        // 2. Pause gate. This is the checked observation (#2763): the owner
        //    is read here, immediately before the send below, so a pause
        //    published after admission cannot be missed by a clearance
        //    computed at construction. A key never pauses itself: the
        //    disposition path above leaves this key's record open across its
        //    own retry, so self-covering records are excluded.
        let observed = paused.observe(Some(ors));
        if let Some(error) = observed.unavailable_error() {
            return Err(error);
        }
        if let Some(paused_scope) = ordering_scopes
            .iter()
            .find_map(|scope| Some((scope.clone(), observed.pausing_key_for(scope, &key)?)))
        {
            return Err(CommitRecoveryError::ScopePaused {
                scope: paused_scope.0,
                paused_by_key: paused_scope.1.to_owned(),
            });
        }
    }
    // 3. Send once. The transport client reconciles uncertain sends through
    //    its own exact receipt lookup; what returns here is either a bound
    //    receipt or a typed failure. The send future is boxed: the admitted
    //    transition it carries would otherwise bloat every poller of this
    //    future past the large-future threshold.
    let attempt = Box::pin(send()).await;
    handle_send_outcome(
        ors,
        paused,
        identity,
        ordering_scopes,
        staged,
        attempt,
        &mut send,
    )
    .await
}

/// Handles one send outcome: branch, retry once on known rollback, or open
/// Problem State on a still-unknown outcome.
///
/// `staged` tells whether an unknown-commit record is already open for this
/// key (from the disposition path): only then is there anything to resolve
/// when the journey ends. A fresh key stages nothing on healthy outcomes.
async fn handle_send_outcome<SendFut>(
    ors: Option<&RedbRecoveryStore>,
    paused: &PausedScopeMirror,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
    staged: bool,
    attempt: Result<WriteReceipt, StoreError>,
    send: impl FnMut() -> SendFut,
) -> Result<WriteReceipt, CommitRecoveryError>
where
    SendFut: Future<Output = Result<WriteReceipt, StoreError>>,
{
    match attempt {
        Ok(receipt) => {
            verify_receipt_binding(&receipt, identity)?;
            match classify_commit_receipt(&receipt) {
                CommitRecoveryClass::Committed => {
                    // Exactly one reconciled canonical operation: the send
                    // above is the only mutation. A record staged by the
                    // disposition path reconciles now.
                    if staged {
                        let Some(ors) = ors else {
                            return Err(CommitRecoveryError::OrsUnavailable {
                                detail: "staged unknown-commit record lost its ORS owner"
                                    .to_owned(),
                            });
                        };
                        resolve_staged(
                            ors,
                            paused,
                            &identity.idempotency_key,
                            UnknownCommitOutcome::Committed,
                            &receipt,
                        )?;
                    }
                    Ok(receipt)
                }
                CommitRecoveryClass::KnownRollback => {
                    // Known rollback under the identical identity: one
                    // same-identity retry, never more.
                    retry_same_identity(ors, paused, identity, ordering_scopes, staged, send).await
                }
                CommitRecoveryClass::NeedsNewIdentity(outcome) => {
                    if staged {
                        let Some(ors) = ors else {
                            return Err(CommitRecoveryError::OrsUnavailable {
                                detail: "staged unknown-commit record lost its ORS owner"
                                    .to_owned(),
                            });
                        };
                        resolve_staged(ors, paused, &identity.idempotency_key, outcome, &receipt)?;
                    }
                    Ok(receipt)
                }
            }
        }
        Err(
            StoreError::MissingReceiptEnvelope
            | StoreError::UnknownOutcome { .. }
            | StoreError::Unavailable,
        ) => open_problem_state(ors, paused, identity, ordering_scopes),
        Err(error) => {
            // Deterministic refusal: the staged record (if any, from the
            // disposition path) stays open, because the earlier attempt it
            // tracks is still unresolved. The refusal itself is returned
            // unchanged; nothing is staged for it and nothing resolves.
            Err(CommitRecoveryError::CommitRefused {
                detail: error.to_string(),
            })
        }
    }
}

/// Performs the single same-identity retry after a known rollback.
async fn retry_same_identity<SendFut>(
    ors: Option<&RedbRecoveryStore>,
    paused: &PausedScopeMirror,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
    staged: bool,
    mut send: impl FnMut() -> SendFut,
) -> Result<WriteReceipt, CommitRecoveryError>
where
    SendFut: Future<Output = Result<WriteReceipt, StoreError>>,
{
    // The retry future is boxed like the initial send: same admitted
    // transition, same large-future threshold. A pure read or a receipt
    // lookup is not an attempt; only this send is, and it is the last one
    // under this identity.
    match Box::pin(send()).await {
        Ok(receipt) => {
            verify_receipt_binding(&receipt, identity)?;
            let outcome = match classify_commit_receipt(&receipt) {
                CommitRecoveryClass::Committed => UnknownCommitOutcome::Committed,
                CommitRecoveryClass::KnownRollback => UnknownCommitOutcome::RolledBack,
                CommitRecoveryClass::NeedsNewIdentity(outcome) => outcome,
            };
            if staged {
                let Some(ors) = ors else {
                    return Err(CommitRecoveryError::OrsUnavailable {
                        detail: "staged unknown-commit record lost its ORS owner".to_owned(),
                    });
                };
                resolve_staged(ors, paused, &identity.idempotency_key, outcome, &receipt)?;
            }
            Ok(receipt)
        }
        Err(
            StoreError::MissingReceiptEnvelope
            | StoreError::UnknownOutcome { .. }
            | StoreError::Unavailable,
        ) => open_problem_state(ors, paused, identity, ordering_scopes),
        Err(error) => Err(CommitRecoveryError::CommitRefused {
            detail: error.to_string(),
        }),
    }
}

/// Stages the open unknown-commit record and pauses its scopes: the
/// visible Problem State for Doctor/Human disposition.
///
/// The ORS handle is resolved BEFORE the mirror is touched. Indexing first
/// and bailing after would mark every affected Ordering Scope paused with no
/// durable record behind it: the scope would be quarantined forever, nothing
/// would ever resolve it, and the caller would be told the outcome is
/// unpreserved — a silent permanent lockout rather than a recoverable
/// Problem State, and a contradiction of this function's own contract that a
/// scope is paused *because* a preserved record says so.
fn open_problem_state(
    ors: Option<&RedbRecoveryStore>,
    paused: &PausedScopeMirror,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
) -> Result<WriteReceipt, CommitRecoveryError> {
    let Some(ors) = ors else {
        return Err(CommitRecoveryError::OrsUnavailable {
            detail: format!(
                "ORS recovery unavailable for unknown commit {}: outcome unpreserved, no blind retry",
                identity.idempotency_key
            ),
        });
    };
    let record = open_record_for(identity, ordering_scopes)?;
    ors.stage_unknown_commit(&record).map_err(ors_error)?;
    // Only a durably staged record may mark a scope paused, and the mirror
    // keeps that source with the entry. The stamp is the owner-issued family
    // revision the stage advanced to, read back from ORS rather than minted
    // here, so a pause published by any writer orders identically.
    let staged_revision = ors.unknown_commit_recovery_revision().map_err(ors_error)?;
    paused.record_paused(
        staged_revision,
        ordering_scopes,
        identity.idempotency_key.as_str(),
    );
    Err(CommitRecoveryError::UnknownCommitOpen {
        idempotency_key: identity.idempotency_key.clone(),
        paused_scopes: ordering_scopes.to_owned(),
        preserved: true,
    })
}

/// Classified retained unknown-commit state for one exact key (issue
/// #2764 item 1).
///
/// `Absent` means the owner answered completely and holds no record for this
/// key. An unreadable owner is never `Absent`: it is the typed error from
/// [`classify_retained_commit`], so a failed load cannot be read as "no
/// retained state" and let a blind send through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetainedCommitState {
    /// No record exists for this key.
    Absent,
    /// A record exists, binds the presented operation, and is still open.
    Open {
        /// The retained open record.
        record: UnknownCommitRecord,
    },
    /// A record exists, binds the presented operation, and is already
    /// terminal with its evidence bound.
    Terminal {
        /// The retained terminal record.
        record: UnknownCommitRecord,
    },
}

/// Verifies that a retained record binds the exact presented operation
/// (issue #2764 items 1 and 3).
///
/// The comparison covers operation id, idempotency key, canonical request
/// hash, and the original scope/owner binding. The scope/owner binding is
/// compared as CONTENT, never merely as proof that a record exists: two
/// records differing only in their `ordering_scopes` are a conflict and not
/// the same admitted operation. `presented_ordering_scopes` is the scope set
/// the caller already proved for this operation from its owning contract (the
/// same set that opened the record), so nothing about scope is inferred here.
///
/// Every disagreement is collected by field name into ONE
/// [`CommitRecoveryError::RetainedRecordConflict`], which preserves the
/// retained history and rejects the adoption. A scope-only divergence is
/// named as `ordering_scopes` in that same detail, so it stays
/// distinguishable without a second error type.
///
/// The canonical request hash compared here is the value the admitted
/// identity carries. Recomputing that hash through its owning contract is
/// [`verify_dreamer_canonical_request_hash`], deliberately a separate step: a
/// caller-spelled hash is not a contract-verified one, and the two are never
/// conflated into a single claim.
///
/// Historical operation/fence data in the record is never rewritten to
/// today's epoch: a mismatch rejects the presentation and leaves the record
/// exactly as retained.
pub(crate) fn verify_retained_binding(
    record: &UnknownCommitRecord,
    identity: &OperationIdentity,
    presented_ordering_scopes: &[String],
) -> Result<(), CommitRecoveryError> {
    let mut mismatches: Vec<&str> = Vec::new();
    if record.idempotency_key != identity.idempotency_key {
        mismatches.push("idempotency_key");
    }
    if record.operation_id.as_str() != identity.operation_id.as_str() {
        mismatches.push("operation_id");
    }
    if record.canonical_request_hash != identity.canonical_request_hash {
        mismatches.push("canonical_request_hash");
    }
    if !same_ordering_scopes(&record.ordering_scopes, presented_ordering_scopes) {
        mismatches.push("ordering_scopes");
    }
    if mismatches.is_empty() {
        return Ok(());
    }
    Err(CommitRecoveryError::RetainedRecordConflict {
        idempotency_key: identity.idempotency_key.clone(),
        detail: format!(
            "the retained record binds {} for idempotency key {}, which the presented operation \
             does not match; the retained history is preserved and this adoption is rejected",
            mismatches.join(", "),
            record.idempotency_key
        ),
    })
}

/// Compares the retained Ordering Scope set with the presented one as sets.
///
/// The retained set was declared once by the owner that opened the record;
/// the presented set is this same operation's proven set. Reordering the same
/// scopes is the same binding, so the comparison is set equality after
/// canonical ordering, and a repeated entry names one scope rather than two.
/// An empty set equals only an empty set: a scoped operation and a scopeless
/// genesis commit are different bindings, exactly as `ordering_scopes`' own
/// field contract says.
fn same_ordering_scopes(retained: &[String], presented: &[String]) -> bool {
    let mut left = retained.to_vec();
    left.sort();
    left.dedup();
    let mut right = presented.to_vec();
    right.sort();
    right.dedup();
    left == right
}

/// Recomputes one Dreamer request's canonical request hash through the owning
/// protocol contract and rejects a caller-spelled divergence (issue #2764
/// item 1, I5.27).
///
/// This is the seam that lets "recompute/verify canonical request binding
/// through the existing contract, not caller spelling" be satisfied on the
/// retained-recovery leg. I5.27 defines idempotency over canonical bytes, not
/// over an unversioned hash, so a `DurableJobRequest` whose
/// `request_identity.canonical_request_hash` was spelled rather than derived
/// must be refused before that identity loads retained state, queries a
/// receipt, or authorizes a send. The recomputation is the owner's own
/// versioned derivation, [`DurableRequestIdentity::digest_for`], over the same
/// stable fields the contract hashes, so this introduces no second hash owner
/// and keeps the fresh transport correlation excluded exactly as the contract
/// excludes it.
///
/// The refusal is [`CommitRecoveryError::CommitRefused`] and nothing is
/// staged, queried or sent: a determinate pre-effect refusal belongs before
/// the recovery classification. The retained record keeps its own history
/// either way; this check rewrites no operation or fence data to today's
/// epoch.
///
/// `Reconcile` is exempt, and that exemption is the contract's own, not a
/// local relaxation. [`DurableJobRequest::validate`] applies exactly the
/// same two arms: for a `Reconcile` it requires the mutation's operation and
/// canonical request hash to equal the identity's, and for every other kind
/// it recomputes the digest. A reconciler legitimately presents the ORIGINAL
/// operation's contract digest, not a digest of its own envelope, so
/// recomputing over the reconcile payload would refuse every valid
/// reconciliation and accuse it of caller spelling when it is carrying the
/// owning contract's own value. This function mirrors the contract's arms
/// rather than introducing a second rule, so a request the protocol accepts
/// is never refused here for the hash alone. For a non-`Reconcile` request
/// the returned value is the contract-recomputed digest; for `Reconcile` it
/// is the identity's own hash, which the contract has already proven equals
/// the mutation's.
///
/// # Errors
///
/// Returns [`CommitRecoveryError::CommitRefused`] when the request's own
/// contract recomputation fails, or when the recomputed digest differs from
/// the digest the caller spelled.
pub(crate) fn verify_dreamer_canonical_request_hash(
    request: &DurableJobRequest,
) -> Result<String, CommitRecoveryError> {
    let identity = &request.request_identity;
    if let eliot_protocol::dreamer_job::JobOperation::Reconcile { mutation } = &request.operation {
        // The reconciler carries the original operation's digest by contract.
        // `DurableJobRequest::validate` has already proven it equals the
        // mutation's own hash, so it is a contract-derived value, not caller
        // spelling, and it is exactly the value a retained record for the
        // original operation is bound to.
        return Ok(mutation.canonical_request_hash.clone());
    }
    let recomputed = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &request.operation,
        request.role,
    )
    .map_err(|error| CommitRecoveryError::CommitRefused {
        detail: format!(
            "the canonical request hash of Dreamer operation {} cannot be recomputed through the \
             owning protocol contract: {error}",
            identity.operation.operation_id
        ),
    })?;
    if recomputed != identity.canonical_request_hash {
        return Err(CommitRecoveryError::CommitRefused {
            detail: format!(
                "Dreamer operation {} spells a canonical request hash its own admitted bytes do \
                 not produce; that identity is not this contract's binding, so no retained state \
                 is classified, no receipt is queried and no send is authorized under it",
                identity.operation.operation_id
            ),
        });
    }
    Ok(recomputed)
}

/// Loads and classifies the retained unknown-commit state for one exact key.
///
/// An absent ORS owner and an unreadable record are both errors, never
/// `Absent`: I14.24 closes durable admission when the recovery state cannot
/// be read, and I14.21's "keep the scope paused until an exact
/// evidence-backed disposition" is only meaningful while the record is
/// honestly classified.
///
/// `ordering_scopes` is this operation's proven scope set and is compared as
/// binding content against the loaded record before the state is reported as
/// `Open` or `Terminal`, so a record that paused a different scope set is a
/// conflict at classification time rather than a mismatch discovered later.
/// It is the same set the record itself was staged with.
pub(crate) fn classify_retained_commit(
    ors: Option<&RedbRecoveryStore>,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
) -> Result<RetainedCommitState, CommitRecoveryError> {
    let Some(ors) = ors else {
        return Err(CommitRecoveryError::OrsUnavailable {
            detail: format!(
                "no durable recovery owner is bound, so the retained unknown-commit state for \
                 idempotency key {} cannot be classified and no recovery path may proceed",
                identity.idempotency_key
            ),
        });
    };
    let Some(record) = ors
        .load_unknown_commit(&identity.idempotency_key)
        .map_err(ors_error)?
    else {
        return Ok(RetainedCommitState::Absent);
    };
    verify_retained_binding(&record, identity, ordering_scopes)?;
    match record.outcome {
        None => Ok(RetainedCommitState::Open { record }),
        Some(_) => Ok(RetainedCommitState::Terminal { record }),
    }
}

/// Compares later receipt evidence against a retained terminal disposition
/// (issue #2764 item 3).
///
/// Contradictory later evidence is a conflict, never a replacement: a
/// receipt whose classified outcome differs from the recorded one, or whose
/// digest differs from the bound evidence, is rejected and the recorded
/// history stands.
pub(crate) fn verify_terminal_evidence(
    record: &UnknownCommitRecord,
    outcome: UnknownCommitOutcome,
    evidence_receipt_digest: &str,
) -> Result<(), CommitRecoveryError> {
    let (Some(recorded), Some(bound)) = (record.outcome, record.evidence_receipt_digest.as_deref())
    else {
        return Err(CommitRecoveryError::ReceiptQueryFailed {
            idempotency_key: record.idempotency_key.clone(),
            detail: "a terminal unknown-commit record binds no receipt evidence, so no later \
                     evidence can be compared against it"
                .to_owned(),
        });
    };
    if recorded != outcome || bound != evidence_receipt_digest {
        return Err(CommitRecoveryError::RetainedRecordConflict {
            idempotency_key: record.idempotency_key.clone(),
            detail: format!(
                "the retained terminal disposition is {recorded:?} with evidence digest {bound:?}, \
                 which contradicts later evidence {outcome:?} with evidence digest \
                 {evidence_receipt_digest:?}; a wrong receipt or a changed terminal digest cannot \
                 resolve the record and never replaces it"
            ),
        });
    }
    Ok(())
}

/// Returns the mirrored paused scopes together with the checked coverage
/// they were last observed under (I14.21 visible Problem State).
///
/// This is a projection, never an admission input: the admission input is
/// [`CheckedPauseObservation`] from the owner. A poisoned required lock is
/// explicit, never zero, and an unavailability report can never render as
/// "no paused scopes" — the typed error travels beside the last-known
/// positives instead of replacing them with an empty list.
#[must_use]
pub fn paused_scopes_snapshot(
    paused: &PausedScopeMirror,
    ors: Option<&RedbRecoveryStore>,
) -> PausedScopeSnapshot {
    let observation = paused.observe(ors);
    let limitation = observation
        .unavailable_error()
        .map(|error| error.to_string())
        .or_else(|| {
            // A limitation retained by an earlier failed refresh is still
            // part of the current answer, so the projection never reports a
            // clean ledger after a release it could not prove.
            paused.last_refresh_limitation()
        });
    let mut scopes: Vec<String> = observation
        .records()
        .iter()
        .flat_map(|record| record.ordering_scopes.iter().cloned())
        .collect();
    // A failed observation keeps the last-known positive pauses rather than
    // dropping them: an unreadable ledger must not silently shrink the
    // visible Problem State.
    if limitation.is_some()
        && let Ok(entries) = paused.mirrored_entries()
    {
        for entry in entries {
            if !scopes.contains(&entry.scope) {
                scopes.push(entry.scope);
            }
        }
    }
    scopes.sort();
    scopes.dedup();
    PausedScopeSnapshot {
        scopes,
        observation,
        coverage: paused.coverage(),
        observed_revision: paused.observed_revision(),
        limitation,
    }
}

/// One visible Problem State projection: the applicable paused scopes, the
/// checked observation they came from, and any coverage limitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PausedScopeSnapshot {
    /// Known paused Ordering Scopes. With a complete observation this is
    /// every paused scope; with an unavailable one it is a bounded known
    /// subset and [`Self::limitation`] is set.
    pub scopes: Vec<String>,
    /// The checked observation the projection was built from.
    pub observation: CheckedPauseObservation,
    /// Coverage the mirror entries were last observed under.
    pub coverage: PauseCoverage,
    /// Owner-issued durable family revision the mirror is currently bound
    /// to, or `None` while it has never been answered by one.
    pub observed_revision: Option<u64>,
    /// `Some` exactly when durable recovery state was unavailable, carrying
    /// the typed reason. Consumers label the scope list unavailable; they
    /// never report it as zero.
    pub limitation: Option<String>,
}

/// Lists the paused ordering scopes with the idempotency key pausing each:
/// the visible Problem State surface for Doctor/Human disposition.
///
/// The authoritative answer is the checked observation, so a failed or absent
/// owner is reported as unavailable rather than projected as "nothing is
/// paused". Every open record covering a scope is preserved: the projection
/// is a display shape, never the admission input, so it keeps one entry per
/// (scope, pausing key) pair instead of collapsing several pausing operations
/// onto one key.
#[must_use]
pub fn paused_ordering_scope_view(
    paused: &PausedScopeMirror,
    ors: Option<&RedbRecoveryStore>,
) -> PauseScopeView {
    let observation = paused.observe(ors);
    let limitation = observation
        .unavailable_error()
        .map(|error| error.to_string())
        .or_else(|| paused.last_refresh_limitation());
    let mut view: Vec<(String, String)> = Vec::new();
    for record in observation.records() {
        for scope in &record.ordering_scopes {
            let entry = (scope.clone(), record.idempotency_key.clone());
            if !view.contains(&entry) {
                view.push(entry);
            }
        }
    }
    if limitation.is_some()
        && let Ok(entries) = paused.mirrored_entries()
    {
        for entry in entries {
            let projected = (entry.scope.clone(), entry.paused_by_key.clone());
            if !view.contains(&projected) {
                view.push(projected);
            }
        }
    }
    view.sort();
    PauseScopeView {
        scopes: view,
        observation,
        coverage: paused.coverage(),
        observed_revision: paused.observed_revision(),
        limitation,
    }
}

/// One paused-scope view with the coverage that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseScopeView {
    /// Bounded known (scope, pausing key) pairs. Every open record covering a
    /// scope is kept; this is a projection, not the admission input.
    pub scopes: Vec<(String, String)>,
    /// The checked observation the projection was built from.
    pub observation: CheckedPauseObservation,
    /// Coverage the mirror entries were last observed under.
    pub coverage: PauseCoverage,
    /// Owner-issued durable family revision the mirror is currently bound
    /// to, or `None` while it has never been answered by one.
    pub observed_revision: Option<u64>,
    /// `Some` exactly when durable recovery state was unavailable. A
    /// diagnostic consumer reports the scope list as a bounded known subset
    /// with this label and never as "zero paused".
    pub limitation: Option<String>,
}
