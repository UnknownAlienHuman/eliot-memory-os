//! Process-scoped retention of validated owner projection sets (#1942 lane D).
//!
//! Retention is the existing restore path's in-memory projection of
//! owner-served snapshots: the bridge restore round-trip (Store/Kernel,
//! `GetReactiveInjectionState` + `GetResourceSnapshot` semantics) serves
//! ledger bytes and resource snapshots for exactly one live (session, fence)
//! binding, and the bridge ledger plus resource registry retain them for
//! that binding. This module retains the same class of state for the six
//! reactive projections: validated [`OwnerProjectionSet`] values keyed by
//! the exact (session, fence) they were served under.
//!
//! Ingestion discipline (type-enforced):
//!
//! ```text
//! owner-served snapshot bytes (restore shaped: reply session echo +
//!   six projection slots)
//! → read_owner_projection_set (decode + intrinsic validation + fence
//!   and cross-projection joins; the ONLY constructor —
//!   OwnerProjectionSet fields are private)
//! → ReactiveOwnerRetention::ingest (keyed by the set's own
//!   session/binding identity)
//! → feed drivers read via ReactiveOwnerRetention::read under the live
//!   (session, fence); stale or foreign reads fail closed.
//! ```
//!
//! The retention holds no bytes and runs no decoders: decoders live only in
//! the ingestion edge (`owner_supply`), and the read path serves retained
//! validated sets. Durable source of truth remains the Store/Kernel restore
//! path (unchanged, unowned here); this retention is process-scoped and
//! bounded. Session end or fence rotation invalidates explicitly via
//! [`ReactiveOwnerRetention::invalidate_session`]; a rotated fence is never
//! served from a stale entry.
//!
//! Authority boundaries (no new authority, no second ledger):
//!
//! ```text
//! retention owns: exact-key storage and fail-closed reads of validated
//!                 sets; it validates nothing itself beyond key equality.
//! supply owns:    decode + intrinsic validation + coherence joins.
//! bridge owns:    live session/fence binding, ledger mutation, receipts.
//! store/kernel:   durable snapshots and their serving reads (unchanged).
//! ```

use eliot_contracts::{SessionId, StateFence};

use crate::owner_supply::{
    OwnerProjectionBytes, OwnerProjectionSet, OwnerSupplyError, read_owner_projection_set,
};

/// Maximum validated projection sets retained in one process.
///
/// One entry per live session; same-session ingest replaces (fence
/// rotation), so the bound only ever binds pathological session fan-out, at
/// which point ingest fails closed instead of growing without bound.
pub const MAX_RETAINED_PROJECTION_SETS: usize = 8;

/// One retained entry: the validated set plus the exact key it was served under.
#[derive(Clone, Debug)]
struct RetainedEntry {
    /// Live session the set was served for.
    session_id: SessionId,
    /// Live fence the set was served under.
    fence: StateFence,
    /// Owner revision observed on the serving restore leg, when known.
    revision: Option<u64>,
    /// Validated coherent set.
    set: OwnerProjectionSet,
}

/// Process-scoped retention of validated owner projection sets.
///
/// Holds no bytes and runs no decoders; populated only through
/// [`ingest_restored_projection_set`] (restore-shaped ingestion) and read
/// only through [`ReactiveOwnerRetention::read`] under an exact
/// (session, fence) key.
#[derive(Clone, Debug, Default)]
pub struct ReactiveOwnerRetention {
    entries: Vec<RetainedEntry>,
}

/// Owner-served snapshot legs for one restore-shaped ingestion.
///
/// The bytes are the six projection slots served for the restore reply's
/// session; slot order is fixed by [`OwnerProjectionBytes`]. Which snapshot
/// URI each slot was served under is the serving path's mapping (the
/// reported publication-contract blocker); retention never invents URIs.
#[derive(Clone, Copy, Debug)]
pub struct RestoredOwnerSnapshots<'a> {
    /// Session identity echoed by the serving restore reply.
    pub reply_session: &'a str,
    /// Owner revision observed on the serving restore leg, when known.
    pub reply_revision: Option<u64>,
    /// Six served projection slots, in [`OwnerProjectionBytes`] order.
    pub projections: OwnerProjectionBytes<'a>,
}

impl ReactiveOwnerRetention {
    /// Create an empty retention.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of retained sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no set is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Ingest one validated set, keyed by its own session/binding identity.
    ///
    /// Same-session ingest replaces (fence rotation supersedes); an
    /// unknown session pushes while bounded, else [`OwnerSupplyError::RetentionFull`].
    /// Only [`ingest_restored_projection_set`] calls this with
    /// restore-shaped inputs — the set type itself is constructible only
    /// via the validated supply read.
    fn ingest(&mut self, set: OwnerProjectionSet, revision: Option<u64>) -> Result<(), OwnerSupplyError> {
        let session_id = set.session().session_id.clone();
        let fence = set.view().view.binding.state_fence.clone();
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.session_id == session_id)
        {
            entry.fence = fence;
            entry.revision = revision;
            entry.set = set;
            return Ok(());
        }
        if self.entries.len() >= MAX_RETAINED_PROJECTION_SETS {
            return Err(OwnerSupplyError::RetentionFull);
        }
        self.entries.push(RetainedEntry {
            session_id,
            fence,
            revision,
            set,
        });
        Ok(())
    }

    /// Read the retained set for exactly the live (session, fence) key.
    ///
    /// Unknown sessions withhold ([`OwnerSupplyError::Empty`]); a retained
    /// session under a rotated fence withholds
    /// ([`OwnerSupplyError::FenceMismatch`]) — a stale entry is never
    /// served. Returns a borrow: the set stays retained for later reads.
    pub fn read(
        &self,
        session_id: &SessionId,
        fence: &StateFence,
    ) -> Result<&OwnerProjectionSet, OwnerSupplyError> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| &entry.session_id == session_id)
        else {
            return Err(OwnerSupplyError::Empty {
                projection: "retention",
            });
        };
        if entry.fence != *fence {
            return Err(OwnerSupplyError::FenceMismatch {
                projection: "retention",
            });
        }
        Ok(&entry.set)
    }

    /// Drop every entry for a session (session end or explicit rotation).
    ///
    /// Returns the number of entries removed. Critical stickiness and the
    /// bridge ledger are unaffected: this drops retained planning inputs,
    /// never delivery records.
    pub fn invalidate_session(&mut self, session_id: &SessionId) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| &entry.session_id != session_id);
        before - self.entries.len()
    }
}

/// Ingest one restore-shaped owner snapshot delivery into retention.
///
/// Requires the serving reply's session echo to equal the live session and
/// the set's own session identity to agree with it; the supply read binds
/// every projection fence to the live fence. Any absent, oversize,
/// undecodable, invalid, foreign-session, or fence-mismatched leg withholds
/// the whole ingestion: partial sets never land in retention.
pub fn ingest_restored_projection_set(
    retention: &mut ReactiveOwnerRetention,
    live_session: &str,
    live_fence: &StateFence,
    restored: &RestoredOwnerSnapshots<'_>,
) -> Result<(), OwnerSupplyError> {
    if restored.reply_session != live_session {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "retention",
            field: "restore.reply_session",
        });
    }
    let set = read_owner_projection_set(live_fence, &restored.projections)?;
    if set.session().session_id.as_str() != live_session {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "session",
            field: "session.session_id",
        });
    }
    retention.ingest(set, restored.reply_revision)
}
