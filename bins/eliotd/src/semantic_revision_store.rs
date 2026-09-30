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
//!
//! The post-commit/pre-ack window (issue #1702, A4): [`Self::commit`] makes
//! the whole image durable and only then does the caller get acknowledged, so a
//! process that dies between the two leaves a committed revision that no
//! acknowledgement refers to.
//! [`SemanticRevisionStore::resume_committed_publish`] is the one step that
//! decides what such an interrupted publish means, and
//! [`SemanticRevisionStore::resume_committed_execution_launch`] is the launch
//! dedupe the committed keyed execution revisions already imply. Both are
//! reads over the committed image; neither writes, mints or overwrites.
//!
//! BLOCKED-BY scope `bins/eliotd/src/agent_fabric.rs::AgentFabric` (and
//! `bins/eliotd/src/solo_agent_driver.rs` for the acknowledged production
//! caller): no production operation reaches these resumes. The four semantic
//! writers call `publish_semantic_revision` and then either return or roll the
//! map back, so on the current base nothing re-enters the fabric between a
//! commit and its acknowledgement, and
//! `recover_semantic_revisions(store, &snapshot)` verifies the committed image
//! on reopen without discarding the caller's own in-memory maps. Only the
//! store's owner is implemented here; the caller that would re-drive an
//! interrupted publish belongs to the fabric's owner, not to this one.

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

/// What the committed image already says about one publish operation identity
/// the caller intended (issue #1702, A4).
///
/// These three outcomes are the whole of the post-commit/pre-ack window and
/// are deliberately distinguishable: a caller resuming an interrupted publish
/// must be able to tell "my revision is already current, report the committed
/// bytes" from "someone committed different bytes under my identity, refuse"
/// without reading either file or image itself.
///
/// [`SemanticRevisionStore::resume_committed_publish`] and
/// [`SemanticRevisionStore::resume_committed_execution_launch`] return this
/// type, and the `Replayed` variant carries the committed record set taken
/// from the store's own verified image, never one handed back in by the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticPublishOutcome {
    /// This store has never committed an image, so the publish cannot have
    /// reached durability. The caller owes the first commit; this is the
    /// honest empty start, and it is NOT the same as a failed read of an
    /// existing image, which returns [`FabricError::DurabilityUnproven`].
    NotCommitted,
    /// The committed image carries exactly the intended content for this
    /// identity, so the operation already committed and the caller may be
    /// acknowledged with the returned records. Nothing is rewritten and no
    /// second revision is minted.
    Replayed {
        /// The owner-separated records read back from the committed image,
        /// exactly as committed.
        recovered: RecoveredSemanticRevisions,
    },
    /// The committed image carries different content under this identity. A
    /// committed revision is never silently overwritten: the caller is
    /// refused and the committed bytes stay current.
    Conflict,
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

    /// Resumes one publish after a crash between its commit and its
    /// acknowledgement (issue #1702, A4).
    ///
    /// [`Self::commit`] writes the whole owner-separated image before the
    /// caller is acknowledged, so a process that dies between those two points
    /// leaves a committed revision that no acknowledgement refers to. This is
    /// the one step that decides what that interrupted publish means, and it is
    /// a READ: it never writes, never mints a second revision, and never
    /// rewrites a committed one. The caller presents the intended content under
    /// the identity it intended and gets the committed result instead.
    ///
    /// Nothing is re-decided here. The committed image is the only evidence, it
    /// is verified through [`Self::load`] exactly as a reopen verifies it —
    /// wire version, path identity, bounded read and the recorded digest against
    /// the ORIGINAL recorded payload bytes — and an already-committed record is
    /// returned exactly as it was committed. The two replay verdicts are
    /// decided by that image and stay distinguishable:
    ///
    /// * [`SemanticPublishOutcome::Replayed`] — the committed image already
    ///   carries this exact revision (and, for a replacement definition, its
    ///   exact supersession link), so the interrupted publish already
    ///   committed and the caller may be acknowledged with the returned
    ///   records.
    /// * [`SemanticPublishOutcome::Conflict`] — the committed image holds
    ///   different content under this identity, so it is refused: a committed
    ///   revision is never silently overwritten by a same-identity replay with
    ///   changed bytes. The key's mere presence is not authority.
    /// * [`SemanticPublishOutcome::NotCommitted`] — this store has never
    ///   committed an image, so there is nothing to resume and the caller owes
    ///   the first [`Self::commit`].
    ///
    /// The committed image does not carry the Store owner revision its commit was
    /// made under, and this store persists records and nothing else, so no
    /// resume here can check a caller against that owner revision: a replay
    /// with a stale `SwarmOwnerRevision` is stopped by its own live writer,
    /// which re-runs `require_durable_owner_revision`, not by this read. This
    /// is therefore a READ that re-decides nothing about authority — it answers
    /// only what is already current.
    ///
    /// The launch side needs no third verdict: an execution revision committed
    /// here is keyed by its own execution identity, which the launch path
    /// already carries as `attempt_id/execution_id`, so resuming through
    /// [`Self::resume_committed_execution_launch`] cannot launch a second
    /// wave for a committed identity.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::DurabilityUnproven`] when the presence probe
    /// reports a committed image that cannot be leased, read, decoded or
    /// verified. A readable, verified image that merely differs from the
    /// intended content is not an error: it is [`SemanticPublishOutcome::Conflict`].
    pub fn resume_committed_publish(
        &self,
        revision: &SemanticRevision,
    ) -> Result<SemanticPublishOutcome, FabricError> {
        // The presence probe is the same one recovery uses, so an honest empty
        // start stays distinguishable from an unreadable committed image.
        if !self.has_committed_image() {
            return Ok(SemanticPublishOutcome::NotCommitted);
        }
        // The committed image is the only evidence, verified exactly as a
        // reopen verifies it: one lease, one bounded read, one digest over the
        // ORIGINAL recorded payload bytes. Nothing is recomputed or trusted
        // from a copy the caller carried in.
        let committed = self.load()?;
        if revision.already_committed(&committed) {
            return Ok(SemanticPublishOutcome::Replayed { recovered: committed });
        }
        // An identity the committed image does not carry cannot have been
        // interrupted here, so it is an honest first publish rather than a
        // conflict with something already current.
        if revision.is_absent_from(&committed) {
            return Ok(SemanticPublishOutcome::NotCommitted);
        }
        // Same identity, different bytes: the committed revision stays current
        // and the caller is refused. This is the one case a resume must never
        // answer by writing, because writing would silently overwrite.
        Ok(SemanticPublishOutcome::Conflict)
    }

    /// Resumes one execution launch after a crash between its commit and its
    /// acknowledgement (issue #1702, A4).
    ///
    /// This is the launch-side dedupe the existing commit/load pair already
    /// implies, derived from the store's own data and nothing else: a launch
    /// may run only under an execution revision this store has committed. So
    /// a coordinator that crashed after committing a revision and before
    /// acknowledging it, and then re-launches, is refused a second launch for
    /// the committed execution identity instead of running a duplicate wave,
    /// and the committed bytes are handed back to resume from rather than
    /// rewritten. There is no dedupe table, journal or attempt log here: the
    /// keyed execution revisions of the committed image ARE the record of what
    /// was launched.
    ///
    /// `attempt_id` is the launch path's own `attempt_id/execution_id` pair;
    /// the caller passes the execution identity itself. It is checked only
    /// against the committed image, and only so the caller can tell a committed
    /// identity from an identity this store never committed; it is not
    /// authority over whether the attempt may launch. As in
    /// [`Self::resume_committed_publish`], a committed image that cannot be
    /// verified fails closed rather than reporting an unlaunchable execution.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::DurabilityUnproven`] when this store has
    /// committed an image that cannot be leased, read, decoded or verified.
    /// An execution identity this store never committed is
    /// [`SemanticPublishOutcome::NotCommitted`], not an error.
    pub fn resume_committed_execution_launch(
        &self,
        attempt_id: &str,
    ) -> Result<SemanticPublishOutcome, FabricError> {
        if !self.has_committed_image() {
            return Ok(SemanticPublishOutcome::NotCommitted);
        }
        let committed = self.load()?;
        match committed.executions.get(attempt_id) {
            None => Ok(SemanticPublishOutcome::NotCommitted),
            Some(_) => Ok(SemanticPublishOutcome::Replayed { recovered: committed }),
        }
    }
}

/// One publish operation identity a caller can interrupt between its commit and
/// its acknowledgement (issue #1702, A4).
///
/// The identity is the record's OWN identity — definition, admission or
/// execution — exactly the key its committed owner map holds it under. This is
/// the same identity the in-memory replay arms key off, so a resume is the same
/// question the live replay asks, asked of the committed image instead of the
/// volatile map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticRevision {
    /// A Task-Controller-owned plan definition revision, as the registering and
    /// superseding writers present it.
    Definition(SwarmPlanDefinition),
    /// A Governor-owned admission revision, as the binding and disposition
    /// writers present it.
    Admission(SwarmPlanAdmission),
    /// A coordinator-owned execution revision, as the recording writer presents
    /// it. Its identity is the launch-side dedupe key.
    Execution(SwarmExecutionRevision),
}

impl SemanticRevision {
    /// Whether the verified committed image already carries exactly this
    /// publish, and therefore whether resuming it must return the committed
    /// result instead of minting a second revision.
    ///
    /// This is the one comparison a replay turn makes, and it is content
    /// equality — the same equality the in-memory replay arms use, never the
    /// presence of a key. A replacement definition carries its supersession
    /// link with it, because the superseding writer publishes the two as one
    /// image: a replacement whose definition bytes are unchanged but whose link
    /// differs is a conflict here exactly as it is there.
    fn already_committed(&self, committed: &RecoveredSemanticRevisions) -> bool {
        match self {
            Self::Definition(definition) => {
                committed.definitions.get(definition.definition_id.as_str())
                    == Some(definition)
                    && definition
                        .supersedes
                        .as_ref()
                        .is_none_or(|link| {
                            committed.supersessions.get(definition.definition_id.as_str())
                                == Some(link)
                        })
            }
            Self::Admission(admission) => {
                committed.admissions.get(admission.admission_id.as_str()) == Some(admission)
            }
            Self::Execution(execution) => {
                committed.executions.get(execution.execution_id.as_str()) == Some(execution)
            }
        }
    }

    /// Whether the verified committed image does not carry this identity at
    /// all, so this publish is a first publish rather than a replay.
    ///
    /// This is the honest empty start INSIDE an existing image: the store has
    /// committed other revisions, but not this one. It is distinct from
    /// [`SemanticRevisionStore::resume_committed_publish`] returning
    /// [`SemanticPublishOutcome::NotCommitted`] for no committed image at all.
    fn is_absent_from(&self, committed: &RecoveredSemanticRevisions) -> bool {
        match self {
            Self::Definition(definition) => !committed
                .definitions
                .contains_key(definition.definition_id.as_str()),
            Self::Admission(admission) => !committed
                .admissions
                .contains_key(admission.admission_id.as_str()),
            Self::Execution(execution) => !committed
                .executions
                .contains_key(execution.execution_id.as_str()),
        }
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
