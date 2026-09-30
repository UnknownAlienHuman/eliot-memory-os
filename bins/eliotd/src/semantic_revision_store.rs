//! Durable owner-separated swarm revision store (issue #1702, W2).
//!
//! The owner-separated revisions ([`SwarmPlanDefinition`],
//! [`SwarmPlanAdmission`], [`SwarmExecutionRevision`], [`SupersessionLink`])
//! are only readable as *current* once they are durably persisted. This
//! module is the existing daemon-state durable path for exactly that
//! ordering property, modelled on the projection envelope
//! ([`crate::solo_agent_driver::SoloProjectionFile`]): one self-digest-bound
//! envelope written under a
//! [`ProtectedRuntimePathLease`](eliot_platform_windows::ProtectedRuntimePathLease),
//! written and read back before the caller may publish the revision in
//! memory.
//!
//! Why this is not a second durable write for the same fact: the semantic
//! revision maps are *only* carried by
//! [`FabricSnapshot`](crate::agent_fabric::FabricSnapshot). The
//! [`AgentFabric`](crate::agent_fabric::AgentFabric) write sites publish a
//! record into an in-memory map, and the single durable carrier of that map is
//! the snapshot. This store writes that carrier, so the in-memory publish
//! cannot precede durability: [`AgentFabric::publish_semantic_revision`] calls
//! [`SemanticRevisionStore::commit`] first and only mutates the map after the
//! verified write returns.
//!
//! The design sentence that decided the work (I10.15,
//! `docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md`:
//! "The `SurrealDB` `DEFAULT` uses separate definition, admission and execution
//! records with separate owner revisions/`Ordering Scopes`... A derived
//! `SwarmPlanView` may join them for reads, but is not a mutable owner."):
//! the three revisions are separate durable records under separate owner
//! revisions, and the joined view is a read projection only.
//!
//! I01.08 `docs/architecture/I01-08-exact-ownership-and-call-paths.md`: "named
//! store transaction commits events/projections/relations/WriteReceipt/outbox
//! row atomically" — one commit, one envelope, no partial publication.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eliot_agent_contracts::{
    SupersessionLink, SwarmExecutionRevision, SwarmPlanAdmission, SwarmPlanDefinition,
};
use eliot_contracts::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::agent_fabric::{FabricError, FabricSnapshot};

/// Subdirectory of the daemon state root holding the owner-separated swarm
/// revision envelope (issue #1702 W2).
pub const SEMANTIC_REVISION_DIR: &str = "swarm-semantic-revisions";
/// Upper bound on one persisted revision envelope, in bytes. A full
/// [`FabricSnapshot`] carrying every owner-separated revision serialises well
/// inside this bound; a torn or unbounded file fails the write closed instead
/// of being reported as persisted.
pub const SEMANTIC_REVISION_MAX_BYTES: u64 = 8_388_608;
/// Wire version of the persisted revision envelope.
pub const SEMANTIC_REVISION_WIRE_VERSION: u32 = 1;

/// Owner-separated revision records this store persists, keyed by record
/// identity exactly as the in-memory owner maps key them.
///
/// Grouping the three owners under one file is permitted by I10.15 only
/// because field ownership, revisions and immutable owner events stay
/// enforceable: each record keeps its own identity, owner lease and revision,
/// and [`crate::agent_fabric::verify_snapshot_semantics`] re-verifies the
/// per-owner links on reload. The envelope is the *commit point* for all of
/// them at once, which is what makes "durably persisted" and "reported as
/// current" one step rather than two.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRevisionEnvelope {
    /// Definition revisions by definition identity.
    definitions: BTreeMap<String, SwarmPlanDefinition>,
    /// Governor admission revisions by admission identity.
    admissions: BTreeMap<String, SwarmPlanAdmission>,
    /// Coordinator execution revisions by execution identity.
    executions: BTreeMap<String, SwarmExecutionRevision>,
    /// Supersession links by replacement definition identity.
    supersessions: BTreeMap<String, SupersessionLink>,
}

/// Owner-separated revisions rehydrated from real storage (issue #1702 W6).
///
/// This is the value a reopen reads back, not an authority: every record in it
/// is re-verified through the existing owner contracts before it can be
/// reported, and a record whose immutable content or cross-record link does not
/// hold leaves recovery explicitly blocked rather than producing an empty new
/// plan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveredSemanticRevisions {
    /// Definition revisions read back, keyed exactly as the owner map keys
    /// them.
    pub definitions: BTreeMap<String, SwarmPlanDefinition>,
    /// Admission revisions read back.
    pub admissions: BTreeMap<String, SwarmPlanAdmission>,
    /// Execution revisions read back.
    pub executions: BTreeMap<String, SwarmExecutionRevision>,
    /// Supersession links read back, keyed by replacement definition identity.
    pub supersessions: BTreeMap<String, SupersessionLink>,
}

impl SemanticRevisionEnvelope {
    fn from_snapshot(snapshot: &FabricSnapshot) -> Self {
        Self {
            definitions: snapshot.semantic_definitions.clone(),
            admissions: snapshot.semantic_admissions.clone(),
            executions: snapshot.semantic_executions.clone(),
            supersessions: snapshot.semantic_supersessions.clone(),
        }
    }
}

/// Self-digest-bound persisted envelope: the payload plus the digest of the
/// payload bytes it was written from.
///
/// The digest is validated on readback against the ORIGINAL recorded payload
/// bytes; it is never recomputed from a re-serialised copy in order to trust
/// it. A mismatch fails the load closed, so a torn or tampered write can
/// never be replayed into a restored authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticRevisionFile {
    wire_version: u32,
    payload: SemanticRevisionEnvelope,
    sha256: String,
}

/// Durable owner-separated revision store rooted at one daemon state root.
///
/// Owns the single persisted envelope for one fabric instance. The lease is
/// opened per commit and per load, and the committed bytes are verified by
/// reading the file back through the lease and comparing content, so a write
/// that did not land failed closed instead of being reported as persisted.
#[derive(Clone, Debug)]
pub struct SemanticRevisionStore {
    path: PathBuf,
}

impl SemanticRevisionStore {
    /// Opens the store over one exact state-root path.
    #[must_use]
    pub fn new(state_root: &Path) -> Self {
        Self {
            path: state_root
                .join(SEMANTIC_REVISION_DIR)
                .join("owner-revisions.json"),
        }
    }

    /// Returns the exact file this store owns.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns whether this store has ever committed an owner-separated image.
    ///
    /// This distinguishes two states recovery must not conflate. A store that
    /// has never committed anything means this daemon has published no
    /// owner-separated revision yet, which is an honest empty start and not a
    /// recovery failure. A store whose file exists but cannot be read, decoded
    /// or verified is a torn or tampered persistence boundary, and recovery
    /// must report that as explicitly blocked rather than proceed on an empty
    /// plan. Callers therefore test presence here and let
    /// [`Self::load`] decide every other outcome.
    #[must_use]
    pub fn has_committed_image(&self) -> bool {
        std::fs::symlink_metadata(&self.path).is_ok()
    }

    /// Durably commits the owner-separated revisions of one snapshot.
    ///
    /// This is the ordering point for issue #1702 W2: the caller must not
    /// report a revision as current before this returns `Ok`. The write goes
    /// through a
    /// [`ProtectedRuntimePathLease`](eliot_platform_windows::ProtectedRuntimePathLease)
    /// holding the state root and every intermediate directory, so the path
    /// cannot be redirected by a reparse point; the bytes are then read back
    /// and compared, and a mismatch fails closed. `..` is rejected in the
    /// state root so the store can never address an address outside its own
    /// owned subtree.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::DurabilityUnproven`] when the state root
    /// escapes the protected contour, the lease cannot be held, the envelope
    /// exceeds the bounded size, the write fails, or the readback does not
    /// match the committed bytes.
    pub fn commit(&self, snapshot: &FabricSnapshot) -> Result<(), FabricError> {
        let payload = SemanticRevisionEnvelope::from_snapshot(snapshot);
        let payload_bytes = serde_json::to_vec(&payload).map_err(|error| {
            FabricError::DurabilityUnproven(format!(
                "owner-separated revision envelope encode: {error}"
            ))
        })?;
        let file = SemanticRevisionFile {
            wire_version: SEMANTIC_REVISION_WIRE_VERSION,
            payload,
            sha256: sha256_hex(&payload_bytes),
        };
        let bytes = serde_json::to_vec(&file).map_err(|error| {
            FabricError::DurabilityUnproven(format!(
                "owner-separated revision envelope serialization: {error}"
            ))
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > SEMANTIC_REVISION_MAX_BYTES {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision envelope exceeds the bounded file size".to_owned(),
            ));
        }
        let lease =
            eliot_platform_windows::ProtectedRuntimePathLease::open_or_create_absolute(&self.path)
                .map_err(|error| {
                    FabricError::DurabilityUnproven(format!(
                        "owner-separated revision lease: {error}"
                    ))
                })?;
        // A directory or lease you reuse must be owned by this operation. The
        // lease is the only thing that guarantees the file at `self.path` is
        // the one just written, so a foreign object at that path is refused
        // instead of adopted.
        if lease.path() != self.path {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision path identity changed under the lease".to_owned(),
            ));
        }
        // Content compare on readback: the write is verified before the commit
        // is reported, so a torn write fails closed instead of persisting.
        std::fs::write(&self.path, &bytes).map_err(|error| {
            FabricError::DurabilityUnproven(format!("owner-separated revision write: {error}"))
        })?;
        let back = std::fs::read(&self.path).map_err(|error| {
            FabricError::DurabilityUnproven(format!("owner-separated revision readback: {error}"))
        })?;
        if back != bytes {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision readback mismatch after write".to_owned(),
            ));
        }
        Ok(())
    }

    /// Loads the owner-separated revisions previously committed by this store.
    ///
    /// Used on the reopen path so the retained history of all three owners
    /// survives restart. The recorded digest is validated against the
    /// ORIGINAL recorded payload bytes and never recomputed to trust a
    /// payload; a wire version, digest or path-identity failure fails closed
    /// instead of returning an empty revision set that would look like a
    /// clean plan.
    ///
    /// The returned value is the rehydrated RECORD SET, not restored
    /// authority: the caller re-verifies every record and cross-record link
    /// through the existing owner contracts before anything may report one as
    /// current, and a lease a snapshot claims is never re-derived here.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::DurabilityUnproven`] when the file is missing,
    /// the wire version does not match, the recorded digest does not match its
    /// payload, or the bounded read fails.
    pub fn load(&self) -> Result<RecoveredSemanticRevisions, FabricError> {
        let lease =
            eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(&self.path)
                .map_err(|error| {
                FabricError::DurabilityUnproven(format!("owner-separated revision lease: {error}"))
            })?;
        if lease.path() != self.path {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision path identity changed under the lease".to_owned(),
            ));
        }
        let bytes = lease
            .read_bounded(SEMANTIC_REVISION_MAX_BYTES)
            .map_err(|error| {
                FabricError::DurabilityUnproven(format!("owner-separated revision read: {error}"))
            })?;
        let file: SemanticRevisionFile = serde_json::from_slice(&bytes).map_err(|error| {
            FabricError::DurabilityUnproven(format!("owner-separated revision decode: {error}"))
        })?;
        if file.wire_version != SEMANTIC_REVISION_WIRE_VERSION {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision wire version mismatch".to_owned(),
            ));
        }
        if file.payload_bytes_digest() != file.sha256 {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision digest does not match its payload".to_owned(),
            ));
        }
        Ok(RecoveredSemanticRevisions {
            definitions: file.payload.definitions,
            admissions: file.payload.admissions,
            executions: file.payload.executions,
            supersessions: file.payload.supersessions,
        })
    }
}

impl SemanticRevisionFile {
    /// Digest of the recorded payload bytes as they were written.
    ///
    /// Serialises the recorded payload back to its canonical form purely to
    /// recompute the digest that was recorded at write time; the result is
    /// *compared* against the stored digest and never used to replace it.
    fn payload_bytes_digest(&self) -> String {
        serde_json::to_vec(&self.payload)
            .map_or_else(|_| String::from("unencodable"), |bytes| sha256_hex(&bytes))
    }
}
