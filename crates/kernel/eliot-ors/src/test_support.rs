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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
/// database files stay durable until then. There is no reopen seam: redb takes
/// an exclusive file lock, so a second handle cannot open while the fixture's
/// store is alive, and dropping the fixture removes the path. Restart shapes
/// reopen through [`RedbRecoveryStore::open`] on a persisted (non-fixture)
/// path instead.
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
/// non-filename characters are flattened to `-`. Uniqueness is monotonic, not
/// clock-derived: a process-wide counter disambiguates two same-label fixtures
/// even when the wall clock repeats.
pub fn kernel_fixture_dir(label: &str) -> Result<PathBuf, OrsError> {
    static NEXT_KERNEL_FIXTURE: AtomicU64 = AtomicU64::new(1);
    if label.trim().is_empty() || label.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field: "fixture_label",
            reason: "must be non-blank text without control characters",
        });
    }
    let serial = NEXT_KERNEL_FIXTURE.fetch_add(1, Ordering::Relaxed);
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
        "eliot-kernel-ors-{safe_label}-{}-{serial}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|error| {
        OrsError::Storage(format!("kernel fixture temp root is not writable: {error}"))
    })?;
    Ok(dir)
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
