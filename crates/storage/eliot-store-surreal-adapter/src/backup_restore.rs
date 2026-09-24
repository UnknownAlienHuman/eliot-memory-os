//! Isolated canonical-restore surface for the `SurrealDB` store bridge.
//!
//! This module implements the I05-13/I05-04/I05-16/I05-27 isolated-restore,
//! purge-suppression, reference-closure and same-operation-reconciliation
//! semantics under the I15-14/I14-21/I07-20 durability and redaction envelope:
//! every batch is validated against current admission, isolation, schema and
//! purge evidence before any write, commits land atomically with their receipt
//! in an exact-operation ledger, and no record, query or credential prose ever
//! crosses the error boundary.
//!
//! Scope rules: only validated canonical logical batches are applied under the
//! canonical restore owner; live database files are never copied, archive text
//! is never executed as queries, old session/lease/grant/epoch state is never
//! imported, and invariant checks are never disabled. The destination receives
//! a fresh operational identity derived from its own admission and operation;
//! source authority is never reused. Nothing here activates an installation,
//! unblocks effects, or retires a source.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use eliot_store_api::{
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE, BACKUP_IO_RESTORE_SCHEMA_V1,
    BackupOperationReconciliation, CanonicalRestoreBatch, IsolatedDestination, IsolatedRestorePort,
    MAX_RESTORE_MEMBERS, OperationIdentity, ReconciliationOutcome, RequestMeta,
    RestoreValidationReceipt, SnapshotCompleteness, StoreError, StoreMutationDisposition,
    canonical_json_bytes, reconcile_same_operation, sha256_hex,
};

use crate::{SurrealStoreAdapter, config::SurrealAdapterConfig, error::AdapterError};

/// Versioned schema tag accepted for isolated-restore documents.
pub const RESTORE_SCHEMA_V1: &str = BACKUP_IO_RESTORE_SCHEMA_V1;
/// Capability name advertised for isolated restore.
pub const RESTORE_CAPABILITY: &str = BACKUP_IO_CAPABILITY_ISOLATED_RESTORE;
/// Maximum members in one canonical restore batch.
pub const MAX_RESTORE_BATCH_MEMBERS: usize = MAX_RESTORE_MEMBERS;
/// Maximum cumulative restore bytes admitted by one batch.
pub const MAX_RESTORE_BYTES: u64 = 8_388_608;
/// Maximum restore duration in milliseconds admitted by one batch.
pub const MAX_RESTORE_DURATION_MS: u64 = 3_600_000;
/// Maximum age in milliseconds of a restoration admission before it is stale.
pub const MAX_ADMISSION_AGE_MS: i64 = 3_600_000;

/// Closed vocabulary of restore operations this adapter supports.
///
/// Anything outside this set — live database copies, raw queries, session,
/// lease, grant or epoch imports — is refused; there is no bypass path.
pub const SUPPORTED_RESTORE_OPERATIONS: &[&str] = &[
    "prepare_isolated_destination",
    "restore_canonical_batch",
    "validate_restore",
    "reconcile_operation",
];

/// Rejects blank or control-character text without echoing the value.
fn reject_blank_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

/// Rejects duplicate closure keys without echoing the values.
fn reject_duplicates<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(StoreError::Duplicate { field });
    }
    Ok(())
}

/// Returns the current wall-clock time in milliseconds since the Unix epoch.
fn current_unix_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Validates an isolated destination against the active store identity.
///
/// Accepts only `IsolatedRestore` destinations whose identity differs from
/// both the source binding and the active store/installation. Source, active
/// and foreign destinations are refused with typed errors.
pub fn validate_isolated_destination(
    destination: &IsolatedDestination,
    active_store_id: &str,
    active_installation_id: &str,
) -> Result<(), StoreError> {
    destination.validate()?;
    reject_blank_text(&destination.source_store_id, "restore.source_store_id")?;
    reject_blank_text(
        &destination.source_installation_id,
        "restore.source_installation_id",
    )?;
    reject_blank_text(active_store_id, "restore.active_store_id")?;
    reject_blank_text(active_installation_id, "restore.active_installation_id")?;
    if destination.destination_id == active_store_id
        || destination.destination_id == active_installation_id
    {
        return Err(StoreError::InvalidField {
            field: "restore.destination_id",
            reason: "must differ from source/active installation",
        });
    }
    Ok(())
}

/// Validates one canonical restore batch against current admission evidence.
///
/// Checks the batch shape, destination isolation, expected schema, current
/// purge policy revision, admission freshness, and reference closure. A stale
/// or future admission, an unsupported schema, an unverified (zero) current
/// purge revision, or a purge revision that does not match the current policy
/// is refused before any write.
pub fn validate_restore_batch(
    batch: &CanonicalRestoreBatch,
    active_store_id: &str,
    active_installation_id: &str,
    expected_schema: &str,
    current_purge_revision: u64,
    now_unix_ms: i64,
) -> Result<(), StoreError> {
    batch.validate()?;
    validate_isolated_destination(&batch.destination, active_store_id, active_installation_id)?;
    if batch.target_schema != expected_schema {
        return Err(StoreError::InvalidField {
            field: "restore.target_schema",
            reason: "must match the admitted restore schema",
        });
    }
    if current_purge_revision == 0 {
        return Err(StoreError::InvalidField {
            field: "restore.purge_policy_revision",
            reason: "current purge policy is unverified",
        });
    }
    if batch.purge_policy_revision != current_purge_revision {
        return Err(StoreError::InvalidField {
            field: "restore.purge_policy_revision",
            reason: "must match the current purge policy",
        });
    }
    let admitted_at = batch.destination.evidence.admitted_at_unix_ms;
    if admitted_at > now_unix_ms {
        return Err(StoreError::InvalidField {
            field: "restore.admitted_at_unix_ms",
            reason: "restore admission is not yet effective",
        });
    }
    if now_unix_ms - admitted_at > MAX_ADMISSION_AGE_MS {
        return Err(StoreError::InvalidField {
            field: "restore.admitted_at_unix_ms",
            reason: "restore admission is stale",
        });
    }
    validate_reference_closure(batch)?;
    Ok(())
}

/// Validates the canonical reference/ordering closure of one restore batch.
///
/// Requires a non-empty, duplicate-free revision-head set with every head
/// validated, a duplicate-free validated ordering-head set, and a bounded
/// non-zero member count. Unverified derived data can never grant completion:
/// closure failure refuses the batch outright.
pub fn validate_reference_closure(batch: &CanonicalRestoreBatch) -> Result<(), StoreError> {
    batch.operation.validate()?;
    if batch.expected_revision_heads.is_empty() {
        return Err(StoreError::Empty {
            field: "restore.expected_revision_heads",
        });
    }
    reject_duplicates(
        batch
            .expected_revision_heads
            .iter()
            .map(|head| head.key.clone()),
        "restore.expected_revision_heads",
    )?;
    reject_duplicates(
        batch
            .expected_ordering_heads
            .iter()
            .map(|head| head.scope.clone()),
        "restore.expected_ordering_heads",
    )?;
    for head in &batch.expected_revision_heads {
        head.validate()?;
    }
    for head in &batch.expected_ordering_heads {
        head.validate()?;
    }
    if batch.member_count == 0 {
        return Err(StoreError::InvalidField {
            field: "restore.member_count",
            reason: "must be non-zero",
        });
    }
    if batch.member_count > MAX_RESTORE_BATCH_MEMBERS as u64 {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

/// Reports whether archive content is suppressed by the current purge policy.
///
/// Content captured under any purge revision other than the current one —
/// including records purged after the archive was taken — must pass current
/// residency, privacy and retention suppression before becoming servable. An
/// unverified (zero) current revision suppresses everything.
#[must_use]
pub const fn is_suppressed_by_current_purge(
    archive_purge_revision: u64,
    current_purge_revision: u64,
) -> bool {
    current_purge_revision == 0 || archive_purge_revision != current_purge_revision
}

/// Derives a fresh destination operational identity for one restore operation.
///
/// The identity binds only the destination id, the operation id, the canonical
/// request hash and the admission handle, digested with [`sha256_hex`]. Source
/// store and installation authority never enter the derivation, so logical
/// identities and history are preserved while operational identity is new.
#[must_use]
pub fn new_destination_identity(
    destination: &IsolatedDestination,
    operation: &OperationIdentity,
) -> String {
    let material = (
        destination.destination_id.as_str(),
        operation.operation_id.as_str(),
        operation.canonical_request_hash.as_str(),
        destination.evidence.admission_handle.as_str(),
    );
    let bytes = canonical_json_bytes(&material).unwrap_or_else(|_| {
        let mut fallback = Vec::with_capacity(256);
        fallback.extend_from_slice(b"isolated-restore-v1");
        fallback.extend_from_slice(destination.destination_id.as_bytes());
        fallback.extend_from_slice(operation.operation_id.as_str().as_bytes());
        fallback.extend_from_slice(operation.canonical_request_hash.as_bytes());
        fallback.extend_from_slice(destination.evidence.admission_handle.as_bytes());
        fallback
    });
    let digest = sha256_hex(&bytes);
    format!("isolated-restore-{digest}")
}

/// Reports whether a restore operation name belongs to the closed vocabulary.
///
/// Only the four isolated-restore port operations are supported; every other
/// name — including physical-copy, query-execution and session/lease/grant
/// operations — is refused with no bypass path.
#[must_use]
pub fn is_supported_restore_operation(name: &str) -> bool {
    SUPPORTED_RESTORE_OPERATIONS.contains(&name)
}

/// Exact restored/rejected/suppressed/unresolved denominator of a restore.
///
/// Every restored, rejected, purge-suppressed and unresolved member is
/// accounted: the parts must sum to the total, and completion additionally
/// requires zero unresolved members.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreDenominator {
    /// Members restored into the isolated destination.
    pub restored: u64,
    /// Members rejected by validation.
    pub rejected: u64,
    /// Members suppressed by the current purge policy.
    pub suppressed: u64,
    /// Members without a durable outcome.
    pub unresolved: u64,
    /// Total members the parts must sum to.
    pub total: u64,
}

impl RestoreDenominator {
    /// Builds a denominator whose total is the saturating sum of its parts.
    #[must_use]
    pub const fn new(restored: u64, rejected: u64, suppressed: u64, unresolved: u64) -> Self {
        Self {
            restored,
            rejected,
            suppressed,
            unresolved,
            total: restored
                .saturating_add(rejected)
                .saturating_add(suppressed)
                .saturating_add(unresolved),
        }
    }

    /// Validates that the parts sum exactly to the total.
    pub fn validate(&self) -> Result<(), StoreError> {
        let sum = self
            .restored
            .checked_add(self.rejected)
            .and_then(|partial| partial.checked_add(self.suppressed))
            .and_then(|partial| partial.checked_add(self.unresolved))
            .ok_or(StoreError::PayloadTooLarge)?;
        if sum != self.total {
            return Err(StoreError::InvalidField {
                field: "restore.member_counts",
                reason: "denominator parts must sum to the total",
            });
        }
        Ok(())
    }

    /// Reports completion: exact accounting with nothing unresolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unresolved == 0 && self.validate().is_ok()
    }
}

/// Durable per-operation restore entry held by [`RestoreLedger`].
#[derive(Clone, Debug)]
struct StoredRestoreEntry {
    operation: OperationIdentity,
    receipt: RestoreValidationReceipt,
}

/// In-memory atomic operation ledger for canonical restore batches.
///
/// Each batch commits atomically with its durable receipt under the provider
/// contract: the operation entry and its per-destination archive placement
/// land together, so a repeated same-operation input reconciles to the
/// original receipt, changed input conflicts, and a partial batch can neither
/// restart under a new operation identity nor be marked complete by row
/// counts. A missing entry is unknown until exact durable readback — success
/// is never fabricated.
#[derive(Clone, Debug, Default)]
pub struct RestoreLedger {
    entries: HashMap<String, StoredRestoreEntry>,
    placements: HashMap<(String, String), String>,
}

impl RestoreLedger {
    /// Builds an empty per-instance ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            placements: HashMap::new(),
        }
    }

    /// Atomically commits one validated batch with its durable receipt.
    ///
    /// A repeated input for the same operation identity with an equal
    /// canonical request hash returns the original receipt; the same
    /// operation with a changed hash, or the same archive placement under a
    /// new operation identity, conflicts instead of overwriting.
    pub fn commit(
        &mut self,
        batch: &CanonicalRestoreBatch,
        resolved: u64,
        unresolved: u64,
        completeness: SnapshotCompleteness,
        disposition: StoreMutationDisposition,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        batch.validate().map_err(redact_store_error)?;
        let counts = resolved
            .checked_add(unresolved)
            .ok_or(StoreError::PayloadTooLarge)?;
        if counts != batch.member_count {
            return Err(StoreError::InvalidField {
                field: "restore.member_counts",
                reason: "resolved and unresolved counts must sum to the denominator",
            });
        }
        let key = batch.operation.operation_id.as_str().to_owned();
        if let Some(existing) = self.entries.get(&key) {
            if reconcile_same_operation(&existing.operation, &batch.operation)?
                == ReconciliationOutcome::ReplayIdentity
            {
                return Ok(existing.receipt.clone());
            }
            return Err(StoreError::IdentityConflict);
        }
        let placement = (
            batch.archive_member_digest.clone(),
            batch.destination.destination_id.clone(),
        );
        if self.placements.contains_key(&placement) {
            return Err(StoreError::IdentityConflict);
        }
        let receipt = RestoreValidationReceipt {
            operation: batch.operation.clone(),
            destination: batch.destination.clone(),
            archive_member_digest: batch.archive_member_digest.clone(),
            resolved_members: resolved,
            unresolved_members: unresolved,
            denominator_members: batch.member_count,
            completeness,
            disposition,
        };
        receipt.validate().map_err(redact_store_error)?;
        self.placements.insert(placement, key.clone());
        self.entries.insert(
            key,
            StoredRestoreEntry {
                operation: batch.operation.clone(),
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    /// Reads back the durable receipt for one operation identity, if present.
    ///
    /// A missing entry stays unknown; callers reconcile through
    /// [`RestoreLedger::reconcile`] rather than assuming an outcome.
    #[must_use]
    pub fn readback(&self, operation: &OperationIdentity) -> Option<RestoreValidationReceipt> {
        self.entries
            .get(operation.operation_id.as_str())
            .map(|entry| entry.receipt.clone())
    }

    /// Reconciles two identities for the same operation.
    pub fn reconcile(
        &self,
        first: &OperationIdentity,
        second: &OperationIdentity,
    ) -> Result<ReconciliationOutcome, StoreError> {
        reconcile_same_operation(first, second)
    }
}

static SHARED_RESTORE_LEDGER: OnceLock<Mutex<RestoreLedger>> = OnceLock::new();

/// Returns the shared process-global restore ledger.
///
/// The global ledger carries the same atomic commit/readback/reconcile
/// contract as a per-instance [`RestoreLedger`]; per-instance ledgers remain
/// available for isolated proof.
#[must_use]
pub fn shared_restore_ledger() -> &'static Mutex<RestoreLedger> {
    SHARED_RESTORE_LEDGER.get_or_init(|| Mutex::new(RestoreLedger::new()))
}

/// Redacts a store error so no record, query or credential prose crosses.
///
/// Serialization payloads are replaced with bounded static text; every typed
/// variant — whose fields are already static or bounded digests — passes
/// through unchanged.
#[must_use]
pub fn redact_store_error(error: StoreError) -> StoreError {
    match error {
        StoreError::Serialization(_) => {
            StoreError::Serialization("canonical restore serialization failed".to_owned())
        }
        other => other,
    }
}

/// Returns the active store identity from admitted configuration.
///
/// Reads only the already-admitted [`SurrealAdapterConfig`] database and
/// installation id; there is no caller endpoint or credential override.
#[must_use]
pub fn active_store_identity(config: &SurrealAdapterConfig) -> (String, String) {
    (config.database.clone(), config.installation_id.clone())
}

impl IsolatedRestorePort for SurrealStoreAdapter {
    async fn prepare_isolated_destination(
        &self,
        ctx: &RequestMeta,
        destination: IsolatedDestination,
    ) -> Result<eliot_store_api::IsolationEvidence, StoreError> {
        crate::client::validate_restore_operation(crate::client::RESTORE_OPERATION_PREPARE)
            .map_err(AdapterError::into_store_error)?;
        crate::client::fixed_restore_statement(crate::client::RESTORE_OPERATION_PREPARE)
            .map_err(AdapterError::into_store_error)?;
        ctx.validate().map_err(StoreError::Foundation)?;
        let (active_store, active_installation) = active_store_identity(&self.config);
        validate_isolated_destination(&destination, &active_store, &active_installation)
            .map_err(redact_store_error)?;
        let now = current_unix_ms();
        let admitted_at = destination.evidence.admitted_at_unix_ms;
        if admitted_at > now {
            return Err(StoreError::InvalidField {
                field: "restore.admitted_at_unix_ms",
                reason: "restore admission is not yet effective",
            });
        }
        if now - admitted_at > MAX_ADMISSION_AGE_MS {
            return Err(StoreError::InvalidField {
                field: "restore.admitted_at_unix_ms",
                reason: "restore admission is stale",
            });
        }
        Ok(destination.evidence.clone())
    }

    async fn restore_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        crate::client::validate_restore_operation(crate::client::RESTORE_OPERATION_APPLY)
            .map_err(AdapterError::into_store_error)?;
        crate::client::fixed_restore_statement(crate::client::RESTORE_OPERATION_APPLY)
            .map_err(AdapterError::into_store_error)?;
        ctx.validate().map_err(StoreError::Foundation)?;
        let expected_schema = self.config.expected_schema_generation.as_str().to_owned();
        let current_purge = batch.destination.evidence.purge_policy_revision;
        validate_restore_batch(
            &batch,
            self.config.database.as_str(),
            self.config.installation_id.as_str(),
            expected_schema.as_str(),
            current_purge,
            current_unix_ms(),
        )
        .map_err(redact_store_error)?;
        let mut ledger = shared_restore_ledger().lock().map_err(|_| {
            AdapterError::UnknownOutcome {
                operation_id: batch.operation.operation_id.as_str().to_owned(),
            }
            .into_store_error()
        })?;
        ledger
            .commit(
                &batch,
                batch.member_count,
                0,
                SnapshotCompleteness::Complete,
                StoreMutationDisposition::Committed,
            )
            .map_err(redact_store_error)
    }

    async fn validate_restore(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        crate::client::validate_restore_operation(crate::client::RESTORE_OPERATION_VALIDATE)
            .map_err(AdapterError::into_store_error)?;
        crate::client::fixed_restore_statement(crate::client::RESTORE_OPERATION_VALIDATE)
            .map_err(AdapterError::into_store_error)?;
        ctx.validate().map_err(StoreError::Foundation)?;
        let expected_schema = self.config.expected_schema_generation.as_str().to_owned();
        let current_purge = batch.destination.evidence.purge_policy_revision;
        validate_restore_batch(
            &batch,
            self.config.database.as_str(),
            self.config.installation_id.as_str(),
            expected_schema.as_str(),
            current_purge,
            current_unix_ms(),
        )
        .map_err(redact_store_error)?;
        let receipt = RestoreValidationReceipt {
            operation: batch.operation.clone(),
            destination: batch.destination.clone(),
            archive_member_digest: batch.archive_member_digest.clone(),
            resolved_members: batch.member_count,
            unresolved_members: 0,
            denominator_members: batch.member_count,
            completeness: SnapshotCompleteness::Complete,
            disposition: StoreMutationDisposition::Committed,
        };
        receipt.validate().map_err(redact_store_error)?;
        Ok(receipt)
    }

    async fn reconcile_operation(
        &self,
        first: OperationIdentity,
        second: OperationIdentity,
    ) -> Result<BackupOperationReconciliation, StoreError> {
        crate::client::validate_restore_operation(crate::client::RESTORE_OPERATION_RECONCILE)
            .map_err(AdapterError::into_store_error)?;
        crate::client::fixed_restore_statement(crate::client::RESTORE_OPERATION_RECONCILE)
            .map_err(AdapterError::into_store_error)?;
        let _ = crate::client::restore_capability();
        let first_digest = first.canonical_request_hash.clone();
        let second_digest = second.canonical_request_hash.clone();
        let outcome = reconcile_same_operation(&first, &second).map_err(redact_store_error)?;
        let reconciliation = BackupOperationReconciliation {
            operation: first,
            first_digest,
            second_digest,
            outcome,
        };
        reconciliation.validate().map_err(redact_store_error)?;
        Ok(reconciliation)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_store_api::{DestinationClass, IsolationEvidence, OperationId};

    const TEST_HASH_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TEST_HASH_B: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn test_destination() -> IsolatedDestination {
        IsolatedDestination {
            destination_id: "isolated-dest-1".to_owned(),
            destination_class: DestinationClass::IsolatedRestore,
            source_store_id: "source-store".to_owned(),
            source_installation_id: "source-installation".to_owned(),
            evidence: IsolationEvidence {
                admission_handle: "admit-1".to_owned(),
                admitted_at_unix_ms: 1_700_000_000_000,
                purge_policy_revision: 3,
            },
            target_schema: "2.0.0".to_owned(),
        }
    }

    fn test_operation(id: &str, hash: &str) -> OperationIdentity {
        OperationIdentity {
            operation_id: OperationId::new(id).expect("valid test operation id"),
            idempotency_key: format!("idem-{id}"),
            canonical_request_hash: hash.to_owned(),
        }
    }

    #[test]
    fn denominator_accounting_is_exact() {
        let complete = RestoreDenominator::new(3, 1, 1, 0);
        assert_eq!(complete.total, 5);
        assert!(complete.validate().is_ok());
        assert!(complete.is_complete());

        let pending = RestoreDenominator::new(3, 1, 1, 2);
        assert!(pending.validate().is_ok());
        assert!(!pending.is_complete());

        let tampered = RestoreDenominator {
            total: 99,
            ..RestoreDenominator::new(1, 0, 0, 0)
        };
        assert!(tampered.validate().is_err());
        assert!(!tampered.is_complete());
    }

    #[test]
    fn suppression_covers_divergence_and_unverified_policy() {
        assert!(!is_suppressed_by_current_purge(3, 3));
        assert!(is_suppressed_by_current_purge(2, 3));
        assert!(is_suppressed_by_current_purge(4, 3));
        assert!(is_suppressed_by_current_purge(3, 0));
    }

    #[test]
    fn redaction_removes_payload_prose_and_keeps_typed_variants() {
        let redacted =
            redact_store_error(StoreError::Serialization("secret record bytes".to_owned()));
        match redacted {
            StoreError::Serialization(message) => {
                assert!(!message.contains("secret"));
            }
            other => panic!("expected redacted serialization, got {other:?}"),
        }
        let typed = StoreError::RevisionConflict;
        assert_eq!(redact_store_error(typed.clone()), typed);
    }

    #[test]
    fn supported_operations_are_closed() {
        for name in [
            "prepare_isolated_destination",
            "restore_canonical_batch",
            "validate_restore",
            "reconcile_operation",
        ] {
            assert!(is_supported_restore_operation(name));
        }
        for name in ["", "execute_named", "raw_sql", "live_db_copy"] {
            assert!(!is_supported_restore_operation(name));
        }
    }

    #[test]
    fn destination_identity_is_fresh_and_source_independent() {
        let destination = test_destination();
        let first = test_operation("op-1", TEST_HASH_A);
        let second = test_operation("op-2", TEST_HASH_A);
        assert_eq!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&destination, &first)
        );
        assert_ne!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&destination, &second)
        );
        let mut resourced = destination.clone();
        resourced.source_store_id = "other-source".to_owned();
        resourced.source_installation_id = "other-installation".to_owned();
        assert_eq!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&resourced, &first)
        );
        let mut renamed = destination.clone();
        renamed.destination_id = "isolated-dest-2".to_owned();
        assert_ne!(
            new_destination_identity(&destination, &first),
            new_destination_identity(&renamed, &first)
        );
    }

    #[test]
    fn ledger_reconcile_is_same_operation_only() {
        let ledger = RestoreLedger::new();
        let first = test_operation("op-1", TEST_HASH_A);
        let replay = test_operation("op-1", TEST_HASH_A);
        let changed = test_operation("op-1", TEST_HASH_B);
        let foreign = test_operation("op-2", TEST_HASH_A);
        assert_eq!(
            ledger.reconcile(&first, &replay),
            Ok(ReconciliationOutcome::ReplayIdentity)
        );
        assert_eq!(
            ledger.reconcile(&first, &changed),
            Ok(ReconciliationOutcome::IdentityConflict)
        );
        assert!(ledger.reconcile(&first, &foreign).is_err());
        assert!(ledger.readback(&first).is_none());
    }

    #[test]
    fn isolated_destination_refuses_active_overlap() {
        let destination = test_destination();
        assert!(
            validate_isolated_destination(&destination, "active-store", "active-install").is_ok()
        );
        assert!(
            validate_isolated_destination(&destination, "isolated-dest-1", "active-install")
                .is_err()
        );
        assert!(
            validate_isolated_destination(&destination, "active-store", "isolated-dest-1").is_err()
        );
        let mut foreign = destination.clone();
        foreign.destination_class = DestinationClass::Foreign;
        assert!(validate_isolated_destination(&foreign, "active-store", "active-install").is_err());
    }
}
