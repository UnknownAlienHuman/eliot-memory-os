//! Narrow, explicit test-only ORS controls plus the Kernel-route store fixture.
//!
//! The [`KernelRouteStoreFixture`] below is the single public test-usable
//! Kernel ORS store: one temp redb database opened with the structural
//! [`KernelRouteEvidence`] provider, so Kernel-route tests share one evidence
//! binding instead of vendoring their own. Production composition keeps
//! binding its own provider through
//! [`RedbRecoveryStore::open_with_evidence`]; this module never mints
//! authority, only a test-owned store handle with automatic cleanup.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::{
    CanonicalEvidenceProvider, CanonicalReconciliation, EpochIdentity, EpochLineage, OpaqueLabel,
    OperationIdentity, OrsError, RecoveryInboxItem, RedbRecoveryStore, ScopeReservationRequest,
};

/// Typed metadata substitution used only by authority snapshot integrity tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritySnapshotMetadataSubstitution {
    /// Replacement snapshot record identity.
    pub record_id: OperationIdentity,
    /// Replacement creation timestamp.
    pub created_at_ms: i64,
    /// Replacement cleanup timestamp.
    pub cleanup_after_ms: Option<i64>,
}

/// One-shot simulation of an error returned after a consume commit attempt.
#[derive(Debug, Default)]
pub struct AuthorityHandoffPersistenceFailpoint {
    fail_after_consume_commit: AtomicBool,
}

impl AuthorityHandoffPersistenceFailpoint {
    /// Arms the next RESERVED-to-CONSUMED commit to report an uncertain error
    /// after its durable effect has been committed.
    pub fn fail_next_consume_commit_after_durable_effect(&self) {
        self.fail_after_consume_commit.store(true, Ordering::SeqCst);
    }

    pub(crate) fn take_consume_commit_failure(&self) -> bool {
        self.fail_after_consume_commit.swap(false, Ordering::SeqCst)
    }
}

/// Composition-shaped verifier bound into every Kernel-route test store.
///
/// It authenticates structure, never identity by fiat: empty scope sets,
/// blank scopes, malformed head digests, misbound reconciliations, and invalid
/// envelopes all fail closed. Recovery-inbox items are never authenticated on
/// the Kernel route. Mirrors the structural checks production composition
/// providers apply without granting any authority.
#[derive(Debug, Default)]
pub struct KernelRouteEvidence;

impl CanonicalEvidenceProvider for KernelRouteEvidence {
    fn verify_ordering_heads(&self, scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        if scopes.is_empty() {
            return Err(OrsError::CanonicalEvidence(
                "kernel-route evidence rejects an empty scope set".to_owned(),
            ));
        }
        for scope in scopes {
            if scope.scope.as_str().trim().is_empty() {
                return Err(OrsError::CanonicalEvidence(
                    "kernel-route evidence rejects a blank ordering scope".to_owned(),
                ));
            }
            if scope.expected_head.head_sha256.len() != 64
                || scope
                    .expected_head
                    .head_sha256
                    .bytes()
                    .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(OrsError::CanonicalEvidence(
                    "kernel-route evidence rejects a malformed ordering head".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        token: &crate::WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        if reconciliation.reservation_id != token.reservation_id
            || reconciliation.reservation_order != token.reservation_order
            || reconciliation.scopes.len() != token.scopes.len()
        {
            return Err(OrsError::CanonicalEvidence(
                "kernel-route evidence rejects a misbound reconciliation".to_owned(),
            ));
        }
        self.verify_receipt(&reconciliation.receipt)
    }

    fn verify_receipt(&self, receipt: &eliot_receipts::ReceiptEnvelope) -> Result<(), OrsError> {
        receipt.validate().map_err(|error| {
            OrsError::CanonicalEvidence(format!("kernel-route bad envelope: {error}"))
        })
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "kernel-route evidence never authenticates inbox items".to_owned(),
        ))
    }
}

/// Test-owned Kernel-route ORS store: one temp redb database opened with the
/// [`KernelRouteEvidence`] provider.
///
/// `open` creates a unique temp directory, opens `ors.redb` inside it through
/// [`RedbRecoveryStore::open_kernel_route_for_test`], and hands out the store
/// handle. Dropping the fixture removes the temp directory best-effort; the
/// database files stay durable until then, so crash/restart shapes can reopen
/// the same path through [`KernelRouteStoreFixture::reopen`] while the fixture
/// is alive.
pub struct KernelRouteStoreFixture {
    store: Arc<RedbRecoveryStore>,
    dir: PathBuf,
}

impl KernelRouteStoreFixture {
    /// Opens one isolated Kernel-route test store tagged for diagnosis.
    ///
    /// The tag names the temp directory only; it grants nothing and is never
    /// stored. A blank tag or one containing control characters fails before
    /// any filesystem or database work.
    pub fn open(tag: &str) -> Result<Self, OrsError> {
        let dir = kernel_fixture_dir(tag)?;
        let store = RedbRecoveryStore::open_kernel_route_for_test(dir.join("ors.redb"))?;
        Ok(Self {
            store: Arc::new(store),
            dir,
        })
    }

    /// Returns the test-owned store handle.
    pub fn store(&self) -> &Arc<RedbRecoveryStore> {
        &self.store
    }

    /// Returns the fixture temp directory holding `ors.redb`.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Reopens the same database path with fresh Kernel-route evidence.
    ///
    /// The caller must have released every prior handle to this path first:
    /// redb takes an exclusive file lock, so a second live handle fails with
    /// a storage error instead of forking the database.
    pub fn reopen(&self) -> Result<RedbRecoveryStore, OrsError> {
        RedbRecoveryStore::open_kernel_route_for_test(self.dir.join("ors.redb"))
    }
}

impl Drop for KernelRouteStoreFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Builds the writer epoch for the exact live fence tuple in tests.
///
/// The lineage label and sequence come from the test's trusted fence, never
/// from caller text; the predecessor edge stays empty because succession
/// edges are owned by the epoch authority, not by this binding. The epoch is
/// validated before return, so a zero sequence fails here rather than at the
/// first lifecycle call.
pub fn kernel_route_writer_epoch(lineage_id: &str, epoch: u64) -> Result<EpochLineage, OrsError> {
    let lineage = EpochLineage {
        current: EpochIdentity {
            lineage_id: OpaqueLabel::new(lineage_id)?,
            epoch,
        },
        predecessor: None,
    };
    lineage.validate()?;
    Ok(lineage)
}

/// Creates one unique temp-root directory for a Kernel ORS fixture.
///
/// Shared by every fixture constructor in this module so directory naming,
/// label validation, and sanitization stay identical: the label names the
/// directory only, grants nothing, and is never stored. A blank label or one
/// containing control characters fails before any filesystem work; all other
/// non-filename characters are flattened to `-`.
pub fn kernel_fixture_dir(label: &str) -> Result<PathBuf, OrsError> {
    if label.trim().is_empty() || label.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field: "fixture_label",
            reason: "must be non-blank text without control characters",
        });
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let safe_label: String = label
        .chars()
        .map(|cell| {
            if cell.is_alphanumeric() || cell == '-' || cell == '_' {
                cell
            } else {
                '-'
            }
        })
        .collect();
    let dir = std::env::temp_dir().join(format!(
        "eliot-kernel-ors-{safe_label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|error| {
        OrsError::Storage(format!("kernel fixture temp root is not writable: {error}"))
    })?;
    Ok(dir)
}

/// Fixture evidence that accepts every canonical check (issue #2031).
///
/// Test-only shortcut for open/empty-state proofs that never exercise
/// lifecycle authority: coordinator and store open paths, empty recovery
/// scans, and isolation checks. Lifecycle proofs that stage, execute, or
/// reconcile reservations must use [`KernelRouteEvidence`], which
/// authenticates structure instead of accepting by fiat.
#[derive(Debug, Default)]
pub struct AcceptAllCanonicalEvidence;

impl CanonicalEvidenceProvider for AcceptAllCanonicalEvidence {
    fn verify_ordering_heads(&self, _scopes: &[ScopeReservationRequest]) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_reconciliation(
        &self,
        _token: &crate::WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_receipt(&self, _receipt: &eliot_receipts::ReceiptEnvelope) -> Result<(), OrsError> {
        Ok(())
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Ok(())
    }
}

/// Store-level Kernel ORS fixture: one temp redb database opened with the
/// [`AcceptAllCanonicalEvidence`] provider (issue #2031).
///
/// The store-level equivalent of
/// [`OrsCoordinator::open_kernel_fixture`][crate::OrsCoordinator]: minimal
/// open/empty-state proofs share this handle instead of vendoring their own
/// temp-root setup. Lifecycle proofs that need structural authentication use
/// [`KernelRouteStoreFixture`]. Dropping the fixture removes the temp
/// directory best-effort.
pub struct KernelOrsFixture {
    store: Arc<RedbRecoveryStore>,
    dir: PathBuf,
}

impl KernelOrsFixture {
    /// Opens one isolated store fixture tagged for diagnosis.
    pub fn open(label: &str) -> Result<Self, OrsError> {
        let dir = kernel_fixture_dir(label)?;
        let store = RedbRecoveryStore::open_with_evidence(
            dir.join("ors.redb"),
            Arc::new(AcceptAllCanonicalEvidence),
        )?;
        Ok(Self {
            store: Arc::new(store),
            dir,
        })
    }

    /// Returns the test-owned store handle.
    pub fn store(&self) -> &Arc<RedbRecoveryStore> {
        &self.store
    }

    /// Returns the fixture temp directory holding `ors.redb`.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for KernelOrsFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Installs one typed handoff persistence failpoint on a test-owned store.
pub fn install_authority_handoff_failpoint(
    store: &RedbRecoveryStore,
    failpoint: Arc<AuthorityHandoffPersistenceFailpoint>,
) {
    store.install_authority_handoff_failpoint(failpoint);
}

/// Substitutes only the typed authority snapshot metadata used by integrity
/// tests; no general raw operational-state mutation is exposed.
pub fn substitute_authority_snapshot_metadata(
    store: &RedbRecoveryStore,
    substitution: AuthoritySnapshotMetadataSubstitution,
) -> Result<(), OrsError> {
    store.substitute_authority_snapshot_metadata_for_test(substitution)
}

#[cfg(test)]
mod kernel_ors_fixture_tests {
    use super::{AcceptAllCanonicalEvidence, KernelOrsFixture};
    use crate::{CanonicalEvidenceProvider as _, OperationIdentity, UnknownCommitRecord};

    fn unknown_record(operation: &str) -> UnknownCommitRecord {
        let operation_id = match OperationIdentity::new(operation) {
            Ok(identity) => identity,
            Err(error) => panic!("2031 fixture operation identity must build: {error}"),
        };
        UnknownCommitRecord {
            idempotency_key: "key-2031".to_owned(),
            operation_id,
            canonical_request_hash: "a".repeat(64),
            ordering_scopes: vec!["scope-2031".to_owned()],
            outcome: None,
            evidence_receipt_digest: None,
        }
    }

    #[test]
    fn fixture_vends_usable_isolated_store() {
        let evidence = AcceptAllCanonicalEvidence;
        assert!(evidence.verify_ordering_heads(&[]).is_ok());
        let home = match KernelOrsFixture::open("2031-home") {
            Ok(fixture) => fixture,
            Err(error) => panic!("2031 home fixture must open: {error}"),
        };
        assert!(home.path().exists());
        match home.store().list_open_unknown_commits() {
            Ok(open) => assert!(open.is_empty()),
            Err(error) => panic!("2031 fresh fixture must list empty: {error}"),
        }
        let record = unknown_record("op-2031-1");
        match home.store().stage_unknown_commit(&record) {
            Ok(staged) => assert!(staged.is_none()),
            Err(error) => panic!("2031 fixture must stage: {error}"),
        }
        match home.store().list_open_unknown_commits() {
            Ok(open) => assert_eq!(open.len(), 1),
            Err(error) => panic!("2031 fixture must list staged: {error}"),
        }
        let away = match KernelOrsFixture::open("2031-away") {
            Ok(fixture) => fixture,
            Err(error) => panic!("2031 away fixture must open: {error}"),
        };
        assert_ne!(away.path(), home.path());
        match away.store().list_open_unknown_commits() {
            Ok(open) => assert!(open.is_empty()),
            Err(error) => panic!("2031 away fixture stays isolated: {error}"),
        }
    }
}
