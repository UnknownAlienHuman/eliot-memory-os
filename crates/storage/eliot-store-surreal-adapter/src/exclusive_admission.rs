//! Store-level admission gate between ordinary canonical writes and the
//! store's exclusive operations (issue #67, R3/A6).
//!
//! Architecture: A12.3 (one governed canonical write path), I5.7 (ordering
//! and parallelism).
//!
//! # Why this gate exists
//!
//! The process-global `SurrealStoreAdapter::write_lock` is acquired only by
//! the exclusive entrypoints (`apply_migration_direct`, the admitted erasure
//! leg, `initialize_genesis_direct`). Ordinary canonical applies stopped
//! acquiring it when the normal-write guard was removed, so after that
//! removal the mutex excluded the exclusive operations from *each other* and
//! from nothing else: a migration and an ordinary canonical apply could run
//! concurrently against the same provider generation.
//!
//! When a write-execution generation is installed, the migration drain gate
//! closes admission and drives the scheduler to quiescence before an
//! exclusive operation runs. Without an installed generation that drain has
//! no queue to drive, and the leftover mutex is the only guard — one no
//! ordinary write participates in. This gate closes the difference:
//!
//! - an ordinary canonical apply holds a **shared** permit for its whole
//!   provider transaction, and
//! - an exclusive operation holds the **exclusive** permit, so it observes
//!   every ordinary apply that already started and no ordinary apply starts
//!   until it finishes.
//!
//! # What this gate is not
//!
//! - It is **not** a full-duration application-global gate on ordinary
//!   writes: shared permits do not exclude each other, so concurrent
//!   ordinary applies still overlap. Only an exclusive operation waits.
//! - It is **not** a substitute for the scheduler drain. A concurrent
//!   generation additionally drains reserved writes through
//!   `WriteExecution::drain_for_migration`; this gate never queues, cancels,
//!   or reconciles any scheduler work itself.
//! - It is **not** taken by the admitted erasure leg
//!   (`apply_surreal_erasure`). That leg runs *inside* an ordinary apply and
//!   already holds the shared permit its caller holds; requesting the
//!   exclusive permit from the same task would self-deadlock on a
//!   non-reentrant lock.
//! - It is **not** taken by the reserved-write lane
//!   (`apply_reserved_write` / `apply_reserved_attempt`). A migration holds
//!   the exclusive permit and *then* calls the scheduler drain, which drives
//!   exactly those attempts on the same task; a shared permit requested from
//!   there would deadlock against the exclusive permit the migrating task
//!   already holds. Reserved writes are excluded by that drain instead.
//! - It says nothing about the Dreamer job lanes, backup/restore, or any
//!   other operation that documents its own provider-side arbitration.

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Admission gate between ordinary canonical writes and exclusive store
/// operations.
///
/// The underlying lock is deliberately write-preferring: once an exclusive
/// operation is waiting, later ordinary applies queue behind it instead of
/// starving it, which is what "closes admission" means here.
#[derive(Debug)]
pub(crate) struct ExclusiveAdmission {
    permits: RwLock<()>,
}

impl ExclusiveAdmission {
    /// Builds an open gate. No state is shared with any other adapter
    /// instance, so exclusivity is exactly this adapter's own writes.
    pub(crate) fn new() -> Self {
        Self {
            permits: RwLock::new(()),
        }
    }

    /// Shared permit for one ordinary canonical apply.
    ///
    /// Held across that apply's whole provider transaction so an exclusive
    /// operation can never observe a partially applied canonical write.
    /// Concurrent ordinary applies hold concurrent permits and never wait
    /// for each other.
    pub(crate) async fn ordinary_write(&self) -> RwLockReadGuard<'_, ()> {
        self.permits.read().await
    }

    /// Exclusive permit for one store-level exclusive operation.
    ///
    /// Acquiring it waits for every ordinary apply already in flight and
    /// stops new ones from starting, so the caller observes a quiescent
    /// ordinary-write path for the whole operation.
    pub(crate) async fn exclusive_operation(&self) -> RwLockWriteGuard<'_, ()> {
        self.permits.write().await
    }
}
