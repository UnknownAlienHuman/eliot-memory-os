//! Narrow, explicit test-only ORS controls.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{OperationIdentity, OrsError, RedbRecoveryStore};

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
