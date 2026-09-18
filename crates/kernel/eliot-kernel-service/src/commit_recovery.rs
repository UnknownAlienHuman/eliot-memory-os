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

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;

use eliot_ors::{RedbRecoveryStore, UnknownCommitOutcome, UnknownCommitRecord};
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
fn verify_receipt_binding(
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
    paused: &Mutex<BTreeSet<String>>,
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
        Err(StoreError::MissingReceiptEnvelope | StoreError::Unavailable) => {
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
fn resolve_staged(
    ors: &RedbRecoveryStore,
    paused: &Mutex<BTreeSet<String>>,
    key: &str,
    outcome: UnknownCommitOutcome,
    receipt: &WriteReceipt,
) -> Result<(), CommitRecoveryError> {
    let digest = receipt_evidence_digest(receipt);
    let open = ors
        .load_unknown_commit(key)
        .map_err(ors_error)?
        .ok_or_else(|| CommitRecoveryError::ReceiptQueryFailed {
            idempotency_key: key.to_owned(),
            detail: "staged unknown-commit record vanished before resolution".to_owned(),
        })?;
    ors.resolve_unknown_commit(key, outcome, &digest)
        .map_err(ors_error)?;
    release_scopes(ors, paused, &open.ordering_scopes);
    Ok(())
}

/// Releases paused scopes no longer covered by any open unknown-commit
/// record. Called after every resolution so disposition lifts exactly the
/// scopes it paused; scopes still paused by other keys stay paused.
fn release_scopes(ors: &RedbRecoveryStore, paused: &Mutex<BTreeSet<String>>, scopes: &[String]) {
    let still_open: BTreeSet<String> = ors
        .list_open_unknown_commits()
        .map(|records| {
            records
                .into_iter()
                .flat_map(|record| record.ordering_scopes)
                .collect()
        })
        .unwrap_or_default();
    if let Ok(mut index) = paused.lock() {
        for scope in scopes {
            if !still_open.contains(scope) {
                index.remove(scope);
            }
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
/// [`CommitRecoveryError::OrsUnavailable`]. `paused` is the in-process
/// pause index, always updated alongside the durable record so admission
/// gating never depends on a database round trip alone.
pub async fn recover_commit<SendFut, QueryFut>(
    ors: Option<&RedbRecoveryStore>,
    paused: &Mutex<BTreeSet<String>>,
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
    // 1. Disposition-first: an already-open record means a previous attempt
    //    under this key ended unknown. Fresh evidence decides; never a
    //    blind send.
    if let Some(ors) = ors {
        if let Some(open) = ors.load_unknown_commit(&key).map_err(ors_error)? {
            if open.outcome.is_some() {
                // Terminally resolved earlier: re-query fresh evidence and
                // return it. No new send under any circumstance.
                let receipt = query().await.map_err(|error| match error {
                    StoreError::MissingReceiptEnvelope | StoreError::Unavailable => {
                        CommitRecoveryError::ReceiptQueryFailed {
                            idempotency_key: key.clone(),
                            detail:
                                "resolving receipt evidence vanished after terminal disposition"
                                    .to_owned(),
                        }
                    }
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
        // 2. Pause gate: no dependent mutation in a scope paused by ANOTHER
        //    key's open record is admitted. A key never pauses itself: the
        //    disposition path above leaves this key's record open across its
        //    own retry, so self-covering records are skipped in both checks.
        let paused_here: Vec<String> = ordering_scopes
            .iter()
            .filter(|scope| {
                paused
                    .lock()
                    .is_ok_and(|index| index.contains(scope.as_str()))
            })
            .cloned()
            .collect();
        if let Some(scope) = paused_here.into_iter().next() {
            let pausing_key = ors
                .list_open_unknown_commits()
                .map_err(ors_error)?
                .into_iter()
                .filter(|candidate| candidate.idempotency_key != key)
                .find(|candidate| {
                    candidate
                        .ordering_scopes
                        .iter()
                        .any(|open_scope| open_scope == &scope)
                })
                .map(|candidate| candidate.idempotency_key.clone());
            if let Some(pausing_key) = pausing_key {
                return Err(CommitRecoveryError::ScopePaused {
                    scope,
                    paused_by_key: pausing_key,
                });
            }
            // Memory hit with no other key covering the scope durably: the
            // entry is stale (only this key's own open record, or a
            // resolution that already released it). Heal the index and
            // admit; the durable set stays authoritative.
            if let Ok(mut index) = paused.lock() {
                index.remove(&scope);
            }
        }
        let durable_paused = ors.list_open_unknown_commits().map_err(ors_error)?;
        for record in &durable_paused {
            if record.idempotency_key == key {
                continue;
            }
            if let Some(scope) = ordering_scopes.iter().find(|scope| {
                record
                    .ordering_scopes
                    .iter()
                    .any(|open_scope| open_scope == *scope)
            }) {
                if let Ok(mut index) = paused.lock() {
                    index.insert((*scope).clone());
                }
                return Err(CommitRecoveryError::ScopePaused {
                    scope: (*scope).clone(),
                    paused_by_key: record.idempotency_key.clone(),
                });
            }
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
    paused: &Mutex<BTreeSet<String>>,
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
        Err(StoreError::MissingReceiptEnvelope | StoreError::Unavailable) => {
            open_problem_state(ors, paused, identity, ordering_scopes)
        }
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
    paused: &Mutex<BTreeSet<String>>,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
    staged: bool,
    mut send: impl FnMut() -> SendFut,
) -> Result<WriteReceipt, CommitRecoveryError>
where
    SendFut: Future<Output = Result<WriteReceipt, StoreError>>,
{
    // The retry future is boxed like the initial send: same admitted
    // transition, same large-future threshold.
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
        Err(StoreError::MissingReceiptEnvelope | StoreError::Unavailable) => {
            open_problem_state(ors, paused, identity, ordering_scopes)
        }
        Err(error) => Err(CommitRecoveryError::CommitRefused {
            detail: error.to_string(),
        }),
    }
}

/// Stages the open unknown-commit record and pauses its scopes: the
/// visible Problem State for Doctor/Human disposition.
fn open_problem_state(
    ors: Option<&RedbRecoveryStore>,
    paused: &Mutex<BTreeSet<String>>,
    identity: &OperationIdentity,
    ordering_scopes: &[String],
) -> Result<WriteReceipt, CommitRecoveryError> {
    if let Ok(mut index) = paused.lock() {
        index.extend(ordering_scopes.iter().cloned());
    }
    let Some(ors) = ors else {
        return Err(CommitRecoveryError::OrsUnavailable {
            detail: format!(
                "ORS recovery unavailable for unknown commit {}: outcome unpreserved, no blind retry",
                identity.idempotency_key
            ),
        });
    };
    let record = open_record_for(identity, ordering_scopes)?;
    match ors.stage_unknown_commit(&record) {
        Ok(_) => Err(CommitRecoveryError::UnknownCommitOpen {
            idempotency_key: identity.idempotency_key.clone(),
            paused_scopes: ordering_scopes.to_owned(),
            preserved: true,
        }),
        Err(error) => Err(ors_error(error)),
    }
}

/// Returns the currently paused ordering scopes: the in-process Problem
/// State surface. The durable open set in ORS is authoritative; this index
/// mirrors it for admission gating without a database round trip.
#[must_use]
pub fn paused_scopes_snapshot(paused: &Mutex<BTreeSet<String>>) -> Vec<String> {
    let mut scopes: Vec<String> = paused
        .lock()
        .map(|index| index.iter().cloned().collect())
        .unwrap_or_default();
    scopes.sort();
    scopes
}

/// Lists the paused ordering scopes with the idempotency key pausing each:
/// the visible Problem State surface for Doctor/Human disposition. Scopes
/// known only in memory pair with an empty key; the durable open set in
/// ORS is authoritative and always carries its key.
#[must_use]
pub fn paused_ordering_scope_view(
    paused: &Mutex<BTreeSet<String>>,
    ors: Option<&RedbRecoveryStore>,
) -> Vec<(String, String)> {
    // Durable first so the pausing key is always named when durably known;
    // memory-only entries (staged while ORS was unreachable) pair with an
    // empty key.
    let mut paused_view: Vec<(String, String)> = Vec::new();
    let open: Vec<UnknownCommitRecord> = ors
        .map(|ors| ors.list_open_unknown_commits().unwrap_or_default())
        .unwrap_or_default();
    for record in open {
        for scope in &record.ordering_scopes {
            if !paused_view.iter().any(|(known, _)| known == scope) {
                paused_view.push((scope.clone(), record.idempotency_key.clone()));
            }
        }
    }
    if let Ok(index) = paused.lock() {
        for scope in index.iter() {
            if !paused_view.iter().any(|(known, _)| known == scope) {
                paused_view.push((scope.clone(), String::new()));
            }
        }
    }
    paused_view.sort();
    paused_view
}
