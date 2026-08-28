//! `DbClientSet` metrics / reader-observation cell.
//!
//! Source-backed observability seam extracted mechanically from
//! `crates/eliot-store/src/db_client_set.rs:19-36,119-133,140-143,566-612`.
//! Owns only the aggregated snapshot `DbClientSetMetrics` and the
//! in-generation reader accounting (`MetricCounters` + `ReadActivity`/
//! `active_readers`/`peak_readers` + query/shutdown counters).
//!
//! Architecture handles: `A13.2` Kernel failure domains – this cell is a
//! failure-domain-local observation bridge (counts/snapshots only) and carries
//! no supervisor authority, health guarantee, or cancellation/recovery fence.
//! Implementation handles: `I16.1` Four surfaces – Metrics (bounded aggregated
//! performance/health) – this module is the store-client Metrics surface;
//! `I2.23` Capability-family topology – store metrics isolated as its own
//! micro-module seam under the store capability family (mechanical split, no
//! new crate), preserving `DbClientSet::metrics()` facade in the parent.
//!
//! Explicit non-scope (no behavior change): `SurrealServerSupervisor` /
//! `ReadySurrealServer` lifecycle, startup/adoption/shutdown, process/auth/
//! security, transport/handshake/reconnect, query execution, migration/
//! provider-port, frozen/Luna/Dreamer, and canonical authority. No new
//! dependencies, no semantic redesign – see parent `DbClientSet::metrics`
//! facade (`db_client_set.rs:226-230`).

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use uuid::Uuid;

/// A stable observation of the persistent database sessions and bounded read
/// concurrency owned by one [`crate::db_client_set::DbClientSet`] generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DbClientSetMetrics {
    pub generation_id: Uuid,
    pub read_pool_size: usize,
    pub sessions_opened: u64,
    pub reconnect_attempts: u64,
    pub reconnect_successes: u64,
    pub transport_invalidations: u64,
    pub read_queries: u64,
    pub write_queries: u64,
    pub admin_queries: u64,
    pub active_readers: usize,
    pub peak_readers: usize,
    pub rejected_after_shutdown: u64,
    pub shutdown_completed: bool,
}

#[derive(Debug)]
pub(crate) struct MetricCounters {
    pub(crate) sessions_opened: AtomicU64,
    pub(crate) reconnect_attempts: AtomicU64,
    pub(crate) reconnect_successes: AtomicU64,
    pub(crate) transport_invalidations: AtomicU64,
    pub(crate) read_queries: AtomicU64,
    pub(crate) write_queries: AtomicU64,
    pub(crate) admin_queries: AtomicU64,
    pub(crate) active_readers: AtomicUsize,
    pub(crate) peak_readers: AtomicUsize,
    pub(crate) rejected_after_shutdown: AtomicU64,
    pub(crate) shutdown_completed: AtomicBool,
}

pub(crate) struct ReadActivity<'a> {
    metrics: &'a MetricCounters,
}

impl MetricCounters {
    pub(crate) const fn new(sessions_opened: u64) -> Self {
        Self {
            sessions_opened: AtomicU64::new(sessions_opened),
            reconnect_attempts: AtomicU64::new(0),
            reconnect_successes: AtomicU64::new(0),
            transport_invalidations: AtomicU64::new(0),
            read_queries: AtomicU64::new(0),
            write_queries: AtomicU64::new(0),
            admin_queries: AtomicU64::new(0),
            active_readers: AtomicUsize::new(0),
            peak_readers: AtomicUsize::new(0),
            rejected_after_shutdown: AtomicU64::new(0),
            shutdown_completed: AtomicBool::new(false),
        }
    }

    pub(crate) fn begin_read(&self) -> ReadActivity<'_> {
        let active = self.active_readers.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak_readers.fetch_max(active, Ordering::AcqRel);
        ReadActivity { metrics: self }
    }

    pub(crate) fn snapshot(
        &self,
        generation_id: Uuid,
        read_pool_size: usize,
    ) -> DbClientSetMetrics {
        DbClientSetMetrics {
            generation_id,
            read_pool_size,
            sessions_opened: self.sessions_opened.load(Ordering::Relaxed),
            reconnect_attempts: self.reconnect_attempts.load(Ordering::Relaxed),
            reconnect_successes: self.reconnect_successes.load(Ordering::Relaxed),
            transport_invalidations: self.transport_invalidations.load(Ordering::Relaxed),
            read_queries: self.read_queries.load(Ordering::Relaxed),
            write_queries: self.write_queries.load(Ordering::Relaxed),
            admin_queries: self.admin_queries.load(Ordering::Relaxed),
            active_readers: self.active_readers.load(Ordering::Acquire),
            peak_readers: self.peak_readers.load(Ordering::Acquire),
            rejected_after_shutdown: self.rejected_after_shutdown.load(Ordering::Relaxed),
            shutdown_completed: self.shutdown_completed.load(Ordering::Acquire),
        }
    }
}

impl Drop for ReadActivity<'_> {
    fn drop(&mut self) {
        self.metrics.active_readers.fetch_sub(1, Ordering::AcqRel);
    }
}
