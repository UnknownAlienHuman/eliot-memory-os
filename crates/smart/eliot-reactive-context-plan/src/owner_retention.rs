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
//! Canonical slot contract (published here for the serving side):
//!
//! ```text
//! slot view            context-assembly owner snapshot;
//! slot cue_activation  cue-activation owner snapshot (A10 pair + bindings);
//! slot session         session/delivery owner snapshot;
//! slot attention       attention owner snapshot;
//! slot coverage        host/coverage owner snapshot;
//! slot policy          policy owner record.
//! ```
//!
//! The serving side (Store/Kernel restore + central export) fills one
//! [`ServedSnapshotDelivery`] per (session, fence) binding: the reply
//! session echo, the observed owner revision, and exactly one
//! [`ServedSnapshotLeg`] per [`ProjectionSnapshotSlot`] — matched by slot,
//! never by position. Each leg carries its claimed content digest and owner
//! revision; retention re-hashes content (presented digests are never
//! trusted), enforces the byte ceiling and identity shape, binds
//! session/attention/coverage revisions to the decoded projections, and only
//! then runs the validated supply read. No snapshot URIs are invented here:
//! the I07-18 identities under which legs are served are the serving side's
//! mapping; retention checks slot completeness, never URI text.
//!
//! Ingestion discipline (type-enforced):
//!
//! ```text
//! ServedSnapshotDelivery (slot-complete, reply echo)
//! → per-leg identity/digest/ceiling checks + revision binds
//! → read_owner_projection_set (decode + intrinsic validation + fence
//!   and cross-projection joins; the ONLY constructor —
//!   OwnerProjectionSet fields are private)
//! → ReactiveOwnerRetention::ingest (keyed by the set's own
//!   session/binding identity)
//! → feed drivers read via ReactiveOwnerRetention::read under the live
//!   (session, fence); stale or foreign reads fail closed.
//! ```
//!
//! The retention holds no undecodable bytes and runs no planners: decoders
//! live only in the ingestion edge (`owner_supply`), and the read path
//! serves retained validated sets. Durable source of truth remains the
//! Store/Kernel restore path (unchanged, unowned here); this retention is
//! process-scoped and bounded. Session end or fence rotation invalidates
//! explicitly via [`ReactiveOwnerRetention::invalidate_session`]; a rotated
//! fence is never served from a stale entry.
//!
//! Authority boundaries (no new authority, no second ledger):
//!
//! ```text
//! retention owns: exact-key storage and fail-closed reads of validated
//!                 sets; it validates nothing itself beyond key equality.
//! supply owns:    leg checks, decode, intrinsic validation, coherence.
//! bridge owns:    live session/fence binding, ledger mutation, receipts.
//! store/kernel:   durable snapshots and their serving reads (unchanged).
//! ```

use eliot_contracts::{SessionId, StateFence, sha256_hex};

use crate::owner_supply::{
    MAX_OWNER_SNAPSHOT_BYTES, OwnerProjectionBytes, OwnerProjectionSet, OwnerSupplyError,
    read_owner_projection_set,
};

/// Maximum validated projection sets retained in one process.
///
/// One entry per live session; same-session ingest replaces (fence
/// rotation supersedes), so the bound only ever binds pathological session
/// fan-out, at which point ingest fails closed instead of growing without
/// bound.
pub const MAX_RETAINED_PROJECTION_SETS: usize = 8;

/// Maximum bytes for one snapshot-leg identity field (owner, revision).
pub const MAX_SNAPSHOT_IDENTITY_BYTES: usize = 256;

/// Canonical snapshot slot for one of the six projections.
///
/// Fixed slot vocabulary for the serving contract: legs are matched by slot,
/// never by position, so serving order is irrelevant and a missing or
/// duplicated slot fails closed by name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionSnapshotSlot {
    /// Context-assembly owner snapshot.
    View,
    /// Cue-activation owner snapshot (A10 pair + target-to-atom bindings).
    CueActivation,
    /// Session/delivery owner snapshot.
    Session,
    /// Attention owner snapshot.
    Attention,
    /// Host/coverage owner snapshot.
    Coverage,
    /// Policy owner record.
    Policy,
}

impl ProjectionSnapshotSlot {
    /// Stable slot name used in diagnostics and revision binds.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::View => "view",
            Self::CueActivation => "cue_activation",
            Self::Session => "session",
            Self::Attention => "attention",
            Self::Coverage => "coverage",
            Self::Policy => "policy",
        }
    }

    /// All six slots in supply (dependency) order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::View,
            Self::CueActivation,
            Self::Session,
            Self::Attention,
            Self::Coverage,
            Self::Policy,
        ]
    }
}

/// One served snapshot leg: content plus its claimed identity.
///
/// Filled by the serving side per slot. `content_digest` is the claimed
/// lowercase SHA-256 hex of `content`; retention re-hashes and enforces
/// equality (never trusted as presented). `owner_id` and `source_revision`
/// are bounded provenance text; session/attention/coverage revisions are
/// additionally bound to the decoded projections at ingest.
#[derive(Clone, Copy, Debug)]
pub struct ServedSnapshotLeg<'a> {
    /// Slot this leg serves.
    pub slot: ProjectionSnapshotSlot,
    /// Served canonical snapshot bytes.
    pub content: &'a [u8],
    /// Claimed lowercase SHA-256 hex of `content`.
    pub content_digest: &'a str,
    /// Owner revision of the served snapshot.
    pub source_revision: &'a str,
    /// Owner identity that issued the snapshot.
    pub owner_id: &'a str,
}

/// The exact fillable delivery the serving side must produce per binding.
///
/// One delivery per live (session, fence) binding: the serving reply's
/// session echo, the observed owner revision, and exactly one leg per slot.
/// Slot completeness (exactly one leg per slot) is enforced at ingest.
#[derive(Clone, Copy, Debug)]
pub struct ServedSnapshotDelivery<'a> {
    /// Session identity echoed by the serving restore reply.
    pub reply_session: &'a str,
    /// Owner revision observed on the serving restore leg, when known.
    pub reply_revision: Option<u64>,
    /// Six served legs, matched by slot (any order, no duplicates).
    pub legs: [ServedSnapshotLeg<'a>; 6],
}

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
/// Holds no undecodable bytes and runs no decoders beyond the ingestion
/// edge; populated only through [`ingest_served_snapshot_delivery`]
/// (slot-complete served deliveries) and read only through
/// [`ReactiveOwnerRetention::read`] under an exact (session, fence) key.
#[derive(Clone, Debug, Default)]
pub struct ReactiveOwnerRetention {
    entries: Vec<RetainedEntry>,
}

fn valid_identity(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.chars().any(char::is_control)
        && value.len() <= MAX_SNAPSHOT_IDENTITY_BYTES
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn leg_for<'a>(
    legs: &'a [ServedSnapshotLeg<'a>],
    slot: ProjectionSnapshotSlot,
) -> Result<&'a ServedSnapshotLeg<'a>, OwnerSupplyError> {
    let mut found = None;
    for leg in legs {
        if leg.slot == slot {
            if found.is_some() {
                return Err(OwnerSupplyError::Invalid {
                    projection: slot.name(),
                    detail: "duplicate snapshot leg".to_string(),
                });
            }
            found = Some(leg);
        }
    }
    found.ok_or(OwnerSupplyError::Empty {
        projection: slot.name(),
    })
}

fn verified_leg_content<'a>(
    leg: &'a ServedSnapshotLeg<'a>,
) -> Result<&'a [u8], OwnerSupplyError> {
    let slot = leg.slot.name();
    if leg.content.is_empty() {
        return Err(OwnerSupplyError::Empty { projection: slot });
    }
    if leg.content.len() > MAX_OWNER_SNAPSHOT_BYTES {
        return Err(OwnerSupplyError::Oversize { projection: slot });
    }
    if !valid_identity(leg.owner_id) || !valid_identity(leg.source_revision) {
        return Err(OwnerSupplyError::Invalid {
            projection: slot,
            detail: "snapshot leg identity is invalid".to_string(),
        });
    }
    if !valid_digest(leg.content_digest) {
        return Err(OwnerSupplyError::Invalid {
            projection: slot,
            detail: "snapshot leg digest is invalid".to_string(),
        });
    }
    if sha256_hex(leg.content) != leg.content_digest {
        return Err(OwnerSupplyError::DigestMismatch { projection: slot });
    }
    Ok(leg.content)
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
    /// Only [`ingest_served_snapshot_delivery`] calls this with
    /// slot-complete served inputs — the set type itself is constructible
    /// only via the validated supply read.
    fn ingest(
        &mut self,
        set: OwnerProjectionSet,
        revision: Option<u64>,
    ) -> Result<(), OwnerSupplyError> {
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

/// Ingest one slot-complete served delivery into retention.
///
/// Requires the serving reply's session echo to equal the live session;
/// requires exactly one leg per slot; re-hashes every leg against its
/// claimed digest; binds session/attention/coverage leg revisions to the
/// decoded projections; then runs the validated supply read binding every
/// projection fence to the live fence, and requires the set's own session
/// identity to agree with the live session. Any absent, duplicated,
/// oversize, undecodable, digest-mismatched, revision-diverged, invalid,
/// foreign-session, or fence-mismatched leg withholds the whole ingestion:
/// partial sets never land in retention.
pub fn ingest_served_snapshot_delivery(
    retention: &mut ReactiveOwnerRetention,
    live_session: &str,
    live_fence: &StateFence,
    served: &ServedSnapshotDelivery<'_>,
) -> Result<(), OwnerSupplyError> {
    if served.reply_session != live_session {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "retention",
            field: "restore.reply_session",
        });
    }
    let mut legs = [None; 6];
    for (index, slot) in ProjectionSnapshotSlot::all().into_iter().enumerate() {
        let leg = leg_for(&served.legs, slot)?;
        legs[index] = Some(verified_leg_content(leg)?);
    }
    let [view, cue_activation, session, attention, coverage, policy] =
        legs.map(|leg| leg.expect("slot-complete legs"));
    let session_leg = leg_for(&served.legs, ProjectionSnapshotSlot::Session)?;
    let attention_leg = leg_for(&served.legs, ProjectionSnapshotSlot::Attention)?;
    let coverage_leg = leg_for(&served.legs, ProjectionSnapshotSlot::Coverage)?;
    let bytes = OwnerProjectionBytes {
        view,
        cue_activation,
        session,
        attention,
        coverage,
        policy,
    };
    let set = read_owner_projection_set(live_fence, &bytes)?;
    if set.session().source_revision != session_leg.source_revision {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "session",
            field: "session.source_revision",
        });
    }
    if set.attention().source_revision != attention_leg.source_revision {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "attention",
            field: "attention.source_revision",
        });
    }
    if set.coverage().profile_revision != coverage_leg.source_revision {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "coverage",
            field: "coverage.profile_revision",
        });
    }
    if set.session().session_id.as_str() != live_session {
        return Err(OwnerSupplyError::BindingMismatch {
            projection: "session",
            field: "session.session_id",
        });
    }
    retention.ingest(set, served.reply_revision)
}
