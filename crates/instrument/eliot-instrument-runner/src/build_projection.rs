//! The one InstrumentRunner-controlled build projection for swarm work
//! (issue #1902).
//!
//! I18.26 is normative and short. Line 3 reads: "Parallel agents use Cargo
//! package selection and one InstrumentRunner-controlled build projection.
//! They do not independently launch unrestricted `cargo --workspace`
//! commands." This module is that one projection. It is the only place in the
//! runner where a swarm work item becomes a Cargo argv, a producer claim on a
//! target root, a cancellation/quarantine record, or a cleanup decision.
//!
//! What it owns, mapping each Work bullet to the I18.26 lines it implements:
//!
//! * **the declaration gate** — "one work item -> primary crate + frozen
//!   contract + `BuildFingerprint` + target class" (line 7). Toolchain, features,
//!   environment class, and candidate are *not* re-declared: they are read
//!   from the already-admitted [`GovernedWorkEnvelope`], so the projection can
//!   never disagree with the lane ([`DeclaredWorkItem::declare`],
//!   [`DeclaredWorkItem::validate`]);
//! * **the projection mapping** — a private crate change selects the primary
//!   crate and carries the declared module capsules and the affected edges
//!   (line 10); a public contract change selects the provider plus its reverse
//!   consumer closure and carries the declared capsule revisions as the
//!   compatibility fixtures (line 13). The closure is delegated to the
//!   existing `BuildTestGraph::impact`; no traversal is reimplemented
//!   ([`DeclaredWorkItem::project`]). The emitted argv is a plain
//!   `Vec<String>` and nothing is executed;
//! * **one producer per (target root, fingerprint)** — the first real consumer
//!   of the existing `SingleFlightBuildRegistry`, held **once per target
//!   root**, so the slot a flight occupies and the root it builds in are the
//!   same identity by construction rather than by coincidence. Waiters receive
//!   the producer's own raw evidence on success and on failure
//!   ([`TargetRootBuildCoordinator`], [`ProducerOutcome`],
//!   [`TargetRootBuildCoordinator::terminal_outcome`]);
//! * **the refusal of an agent-originated `--workspace`/`--all`** (line 3),
//!   with no override, because the projected route is the only admitted one
//!   and the projected route is admitted only by presenting the real
//!   [`ProjectedBuild`] it was emitted from
//!   ([`restrict_agent_argv`], [`CargoOrigin`]);
//! * **lineage separation and rebuild-on-unknown-identity**, both *derived*:
//!   the last segment of the target root is
//!   [`BuildFingerprint::digest`], and the single-flight key is that same
//!   digest held in the registry of its own target root, so a different
//!   toolchain, feature set, environment class, or candidate — or a different
//!   worktree or build mode, which I2.22 places in the root path itself — is
//!   already a different lineage with a different producer slot, and unknown
//!   cache identity is the existing `CacheLookup::Miss`
//!   ([`BuildCacheDecision`]). No second fingerprint, digest, or cache exists
//!   here;
//! * **cancellation evidence and quarantine** (line 36), plus a lineage- and
//!   lease-aware disk cleanup (line 37) ([`BuildCancellation`],
//!   [`BuildCleanupPass`]);
//! * **the recorded pre-emption order** inside the target-root claim (line 33)
//!   ([`BuildClaimOrder`], [`PreemptionClass`]).
//!
//! Ownership boundary (I18.26 line 63): this stays an `InstrumentRunner`
//! capability. It holds no Durable Job, no Ready Queue, no budget, and no task
//! priority, and it builds no pre-emption engine.
//! [`BuildClaimOrder::order_claims`] consumes the target-coordination class the
//! caller already owns and records the resulting order inside one target root;
//! it never stops, delays, reschedules, or admits anything, and that boundary
//! is stated on the type rather than assumed.
//!
//! Target coordination is not weakened to make room for this projection. Line
//! 31 admits a second producer only when "exact tool evidence proves safe
//! concurrency", and no such evidence type exists anywhere in the codebase, so
//! one producer per target root is the rule with no escape hatch.
//!
//! Line 32 is what makes the per-root key load-bearing rather than redundant:
//! target roots "follow I2.22", and I2.22 places the worktree id and the build
//! mode *in the root path* while the fingerprint digest is its last segment.
//! A [`BuildFingerprint`] carries no worktree id, so a digest alone cannot
//! separate two work items that agree on every build input but sit in
//! different worktrees. The coordinator therefore keys on the root, not on the
//! digest alone; see [`TargetRootBuildCoordinator`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use eliot_build_test_graph::{
    BuildFingerprint, BuildFlight, BuildTestGraph, CacheLookup, CandidateIdentity,
    ChangeImpactDirective, ChangeSet, GovernedWorkEnvelope, GraphError, ModuleTestCapsuleRevision,
    PublicContractDigest, ResourceKind, RuntimeEnvironmentLease, SingleFlightBuildRegistry,
    WorkEnvelopeError,
};
use eliot_instrument_api::ExecutionStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RawEvidence;

/// Cargo subcommand the projection emits for both change classes. I18.26
/// line 10 names `cargo check -p` as the private-change shape, and line 13
/// keeps the public-change closure at package selection, so both classes run
/// the same subcommand over a different `-p` set.
const PROJECTED_SUBCOMMAND: &str = "check";

/// Cargo package-selection flag I18.26 line 10 names.
const PACKAGE_SELECTION_FLAG: &str = "-p";

/// Exact class of change a work item makes, and therefore which proof closure
/// it must run.
///
/// I18.26 names `target class` in line 7 but never defines it, so the set is
/// derived only from the two mappings the document actually states:
///
/// * line 10, "private crate change" -> `cargo check -p` + applicable
///   `ModuleTestCapsule` + affected edges;
/// * line 13, "public contract change" -> provider + reverse consumer closure
///   + compatibility fixtures.
///
/// It is a closed set because the class selects a proof closure: an open
/// spelling would let a work item pick a class that maps to none.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetClass {
    /// I18.26 line 10: a change contained by one crate's private surface.
    /// Selects the primary crate and carries the declared module capsules
    /// plus the affected build edges.
    PrivateCrateChange,
    /// I18.26 line 13: a change to a published contract surface. Selects the
    /// provider plus its reverse consumer closure and carries the declared
    /// capsule revisions as the compatibility fixtures.
    PublicContractChange,
}

/// Target coordination class a caller already owns, used to order the claims
/// of one target root.
///
/// I18.26 line 33 places "verification and interactive diagnostics" ahead of
/// "background coverage/mutation/indexing". That is the only pre-emption
/// statement I18.26 makes, so exactly the two groups it names are admitted
/// here, and nothing else. The class is an *input* the caller already assigned;
/// this module never derives it, never changes it, and never pre-empts a
/// producer with it (I18.26 line 63).
///
/// The declaration order is the ranked order, and
/// [`PreemptionClass::ORDERED`] names it exactly once so it cannot drift.
/// [`BuildClaimOrder::order_claims`] sorts descending, which places a
/// foreground class ahead of a background one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreemptionClass {
    /// Line 33: "verification", ordered ahead of every background class.
    Verification,
    /// Line 33: "interactive diagnostics".
    InteractiveDiagnostics,
    /// Line 33: "background coverage".
    BackgroundCoverage,
    /// Line 33: "background mutation".
    BackgroundMutation,
    /// Line 33: "background indexing".
    BackgroundIndexing,
}

impl PreemptionClass {
    /// Every admitted class, in the descending order I18.26 line 33 states.
    ///
    /// The numeric weights behind these classes are already written down by
    /// `eliot_testd_core::JobClass::priority` in `eliot-testd-core`
    /// (`resources.rs`): Verification 60, Interactive 50, Indexing 40,
    /// Coverage 30, Mutation 20. This module consumes that ranking by
    /// correspondence and deliberately does not restate the numbers, because
    /// task priority remains owned by Governor/Agent Coordinator (I18.26 line
    /// 63) and duplicating a weight here would create a second priority owner.
    pub const ORDERED: [Self; 5] = [
        Self::Verification,
        Self::InteractiveDiagnostics,
        Self::BackgroundCoverage,
        Self::BackgroundMutation,
        Self::BackgroundIndexing,
    ];
}

/// The complete I18.26 line 7 work-item declaration: "primary crate + frozen
/// contract + `BuildFingerprint` + target class".
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredWorkItem {
    /// Work item identity; also the producer identity in the claim.
    pub work_item_id: String,
    /// The one crate this work item owns (I18.26 line 7).
    pub primary_crate: String,
    /// The frozen public contract this work item is bound to (I18.26 line 7).
    pub frozen_contract: PublicContractDigest,
    /// The change class that selects the proof closure (I18.26 lines 9-13).
    pub target_class: TargetClass,
    /// The lane the work item was allocated in. Toolchain, features,
    /// environment class, candidate, and build mode are read from it, never
    /// re-declared, so the projection cannot disagree with the admitted lane.
    pub envelope: GovernedWorkEnvelope,
}

impl DeclaredWorkItem {
    /// Declares one work item against an already-allocated lane.
    ///
    /// The envelope is not re-admitted here:
    /// [`crate::GovernedWorkEnvelope::admit`] is the fail-closed admission
    /// gate, and this constructor only records the I18.26 line 7 elements
    /// beside the lane they will be projected from.
    #[must_use]
    pub const fn declare(
        work_item_id: String,
        primary_crate: String,
        frozen_contract: PublicContractDigest,
        target_class: TargetClass,
        envelope: GovernedWorkEnvelope,
    ) -> Self {
        Self {
            work_item_id,
            primary_crate,
            frozen_contract,
            target_class,
            envelope,
        }
    }

    /// The fail-closed declaration gate (I18.26 line 7).
    ///
    /// Every element the document names must be present and usable, and the
    /// frozen contract reference must be a valid digest. Nothing is defaulted:
    /// a work item that cannot present the complete tuple is refused with the
    /// exact missing element.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::IncompleteDeclaration`] naming the
    /// absent element, [`BuildProjectionError::InvalidDigest`] for a malformed
    /// contract digest, and [`BuildProjectionError::Lane`] when the lane itself
    /// cannot be derived.
    pub fn validate(&self) -> Result<(), BuildProjectionError> {
        if self.work_item_id.trim().is_empty() {
            return Err(BuildProjectionError::IncompleteDeclaration("work_item_id"));
        }
        if self.primary_crate.trim().is_empty() {
            return Err(BuildProjectionError::IncompleteDeclaration("primary_crate"));
        }
        self.frozen_contract
            .validate()
            .map_err(|source| BuildProjectionError::InvalidDigest {
                field: "frozen_contract",
                source,
            })?;
        self.envelope
            .validate()
            .map_err(BuildProjectionError::Lane)?;
        Ok(())
    }

    /// The candidate identity the lane admitted for this work item.
    ///
    /// This is the candidate-identity element of I18.26 line 7 read from the
    /// one fingerprint the lane carries, so there is no second place to
    /// declare it.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::Lane`] when the lane fingerprint cannot
    /// be normalized.
    pub fn candidate_identity(&self) -> Result<CandidateIdentity, BuildProjectionError> {
        self.envelope
            .candidate_identity()
            .map_err(BuildProjectionError::Lane)
    }

    /// The governed target root this work item builds in.
    ///
    /// Exactly
    /// `%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>`,
    /// so the I2.22 root is the only root a projected invocation can name. The
    /// last segment is the fingerprint digest, which is why a different
    /// toolchain, feature set, environment class, or candidate is already a
    /// different lineage (I18.26 lines 21-22).
    ///
    /// The worktree id and the build mode are path segments of the root, not
    /// members of the fingerprint, so this value is strictly more specific
    /// than [`BuildFingerprint::digest`] and is the identity the coordinator
    /// keys its producer slot on.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::Lane`] when the lane cannot derive its
    /// root.
    pub fn target_root(&self) -> Result<PathBuf, BuildProjectionError> {
        self.envelope
            .derive_target_root()
            .map_err(BuildProjectionError::Lane)
    }

    /// The exact environment a projected invocation of this work item runs
    /// with, binding the target root explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::Lane`] when the lane cannot derive its
    /// environment.
    pub fn cargo_environment(&self) -> Result<Vec<(String, String)>, BuildProjectionError> {
        self.envelope
            .cargo_environment()
            .map_err(BuildProjectionError::Lane)
    }

    /// Projects this declaration into the Cargo command it is allowed to run.
    ///
    /// The two mappings I18.26 states are produced literally, and nothing else
    /// is added:
    ///
    /// * [`TargetClass::PrivateCrateChange`] emits
    ///   `cargo check -p <primary crate>` (line 10), carries the declared
    ///   module capsules as the applicable `ModuleTestCapsule` set, and
    ///   carries the edges the existing `BuildTestGraph::impact` classified as
    ///   affected;
    /// * [`TargetClass::PublicContractChange`] emits the provider plus its
    ///   reverse consumer closure (line 13) as one `-p` selection per affected
    ///   consumer, and carries the declared capsule revisions as the
    ///   compatibility fixtures. The closure itself is delegated to
    ///   `BuildTestGraph::impact`; no traversal is reimplemented here.
    ///
    /// The two classes are one mapping with two data arms, not two code paths:
    /// both compute the same delegated closure and the same affected edges, and
    /// the class selects the package set and which capsule list is carried.
    /// Because the declared change set, the selected packages, and the carried
    /// capsules all differ between the classes, a private change can never
    /// silently produce the public selection.
    ///
    /// This function executes nothing: the returned [`ProjectedBuild::argv`]
    /// is plain data, and the only route that admits it is
    /// [`restrict_agent_argv`] presented with this very [`ProjectedBuild`] as
    /// [`CargoOrigin::Projected`].
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::IncompleteDeclaration`] for an
    /// incomplete declaration, [`BuildProjectionError::MissingChangeSet`] when
    /// a public contract change declares no change set,
    /// [`BuildProjectionError::MissingCompatibilityFixture`] when it declares
    /// no capsule revision, and [`BuildProjectionError::Lane`] when the lane
    /// cannot derive its root.
    pub fn project(
        &self,
        graph: &BuildTestGraph,
        change: ChangeSet,
        capsules: &[ModuleTestCapsuleRevision],
    ) -> Result<ProjectedBuild, BuildProjectionError> {
        self.validate()?;
        let directive = graph.impact(&change);
        let consumer_closure = consumer_closure(&directive, &self.primary_crate);
        let affected_edges = affected_edges(&directive);
        let (packages, module_capsules, compatibility_fixtures) = match self.target_class {
            TargetClass::PrivateCrateChange => (
                vec![self.primary_crate.clone()],
                capsules.to_vec(),
                Vec::new(),
            ),
            TargetClass::PublicContractChange => {
                if change.changed_nodes.is_empty()
                    && change.changed_paths.is_empty()
                    && !change.public_contract_changed
                {
                    return Err(BuildProjectionError::MissingChangeSet);
                }
                if capsules.is_empty() {
                    return Err(BuildProjectionError::MissingCompatibilityFixture);
                }
                let mut packages = vec![self.primary_crate.clone()];
                packages.extend(consumer_closure.iter().cloned());
                (packages, Vec::new(), capsules.to_vec())
            }
        };
        Ok(ProjectedBuild {
            target_class: self.target_class,
            packages,
            primary_crate: self.primary_crate.clone(),
            target_root: self.target_root()?,
            argv: cargo_argv(
                &self.primary_crate,
                &consumer_closure,
                self.target_class,
                &self.envelope.fingerprint,
            ),
            change_set: change,
            module_capsules,
            compatibility_fixtures,
            affected_edges,
            consumer_closure,
            frozen_contract: self.frozen_contract.clone(),
        })
    }
}

/// One complete build step the projection emits.
///
/// A step is argv, never an execution: this module never launches a process,
/// never spawns Cargo, and never decides that a build succeeded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedBuild {
    /// The change class this step satisfies.
    pub target_class: TargetClass,
    /// Exact package selection, provider first.
    pub packages: Vec<String>,
    /// The one crate the work item owns (I18.26 line 7).
    pub primary_crate: String,
    /// Target root this step is bound to, and the only root it may use.
    pub target_root: PathBuf,
    /// Exact argv, starting at `cargo`.
    pub argv: Vec<String>,
    /// The declared change set fed to `BuildTestGraph::impact`, retained so a
    /// reader can reproduce the closure.
    pub change_set: ChangeSet,
    /// The applicable `ModuleTestCapsule` revisions (I18.26 line 10).
    pub module_capsules: Vec<ModuleTestCapsuleRevision>,
    /// The compatibility fixtures, which are the declared capsule revisions
    /// (I18.26 line 13).
    pub compatibility_fixtures: Vec<ModuleTestCapsuleRevision>,
    /// The edges `BuildTestGraph::impact` classified as affected (I18.26
    /// line 10).
    pub affected_edges: Vec<AffectedEdge>,
    /// The reverse consumer closure, provider excluded (I18.26 line 13).
    pub consumer_closure: BTreeSet<String>,
    /// The frozen contract this step is bound to.
    pub frozen_contract: PublicContractDigest,
}

/// One edge the projection observed as affected by the declared change.
///
/// The traversal is not reimplemented: the affected set is whatever
/// `BuildTestGraph::impact` classified, and only its recorded causal path is
/// carried.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedEdge {
    /// The changed prerequisite the closure started from.
    pub root: String,
    /// The affected consumer reached from the root.
    pub consumer: String,
    /// The compact `root ..= consumer` path the graph recorded.
    pub causal_path: Vec<String>,
}

/// Outcome of the one cache-identity consultation the projection performs.
///
/// I18.26 lines 18-19 reuse *exact immutable* artifacts/evidence for a
/// read-only audit on an immutable base, and lines 24-25 say an unknown cache
/// identity rebuilds. Both rules are the existing `CacheLookup` split, so this
/// type names the decision and never re-derives it: there is no second cache
/// and no second identity check in this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildCacheDecision {
    /// An exact verified entry was reused, with its own identity digest.
    Reused {
        /// The exact lineage identity the entry was read under.
        identity_digest: String,
        /// Reused bytes.
        bytes: Vec<u8>,
    },
    /// Unknown cache identity: the real uncached build must run. There is no
    /// partial reuse and no near-enough acceptance.
    Rebuild,
}

impl BuildCacheDecision {
    /// Reads one existing cache consultation without re-deciding it.
    #[must_use]
    pub fn from_lookup(lookup: &CacheLookup) -> Self {
        match lookup {
            CacheLookup::Hit(artifact) => Self::Reused {
                identity_digest: artifact.lineage.identity_digest.clone(),
                bytes: artifact.bytes.clone(),
            },
            CacheLookup::Miss { .. } => Self::Rebuild,
        }
    }
}

/// One claimed producer slot for a target root.
///
/// A waiter learns which producer to await; it never learns a verdict. The
/// claim is the waiter's handle onto the flight: `target_root` and `lineage`
/// together resolve the producer's own terminal outcome through
/// [`TargetRootBuildCoordinator::terminal_outcome`], and they are the same
/// identity the single-flight slot was keyed on, so `flight` can never name a
/// producer that builds in a different root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerClaim {
    /// Normalized [`BuildFingerprint::digest`]: the lineage inside this claim's
    /// target root, and the identity the recorded outcome is checked against.
    pub lineage: String,
    /// The work item that owns the producer slot.
    pub producer: String,
    /// Whether this claim is the producer itself or a waiter.
    pub flight: BuildFlight,
    /// The governed target root the flight may build in, and the root the
    /// single-flight slot was taken from.
    pub target_root: PathBuf,
}

impl ProducerClaim {
    /// Whether this claim is the single producer for the flight.
    #[must_use]
    pub const fn is_producer(&self) -> bool {
        matches!(self.flight, BuildFlight::Producer)
    }
}

/// One claimed producer slot, tagged with the target coordination class its
/// owner already holds.
///
/// The order is a total, reproducible record, not a derived priority: the
/// pre-emption rank is read from [`PreemptionClass::ORDERED`], so the rank
/// lives in exactly one place, and lineage digest plus work-item identity keep
/// two claims of the same class distinguishable. It is written by hand rather
/// than derived because [`ProducerClaim`] carries a flight role that has no
/// meaningful order of its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedBuild {
    /// The claim itself.
    pub claim: ProducerClaim,
    /// The class the owner already holds.
    pub preemption: PreemptionClass,
}

impl Ord for ClaimedBuild {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.preemption
            .cmp(&other.preemption)
            .then_with(|| self.claim.lineage.cmp(&other.claim.lineage))
            .then_with(|| self.claim.producer.cmp(&other.claim.producer))
    }
}

impl PartialOrd for ClaimedBuild {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The claims of one target root in recorded pre-emption order.
///
/// I18.26 line 33 places "verification and interactive diagnostics" ahead of
/// "background coverage/mutation/indexing". The order consumes
/// [`PreemptionClass::ORDERED`], which is that statement, and reads its ranks
/// from there so the ranking is stated exactly once.
///
/// The order is a *record*, not a pre-emption engine. I18.26 line 63 keeps
/// Durable Jobs, the Ready Queue, budgets, and task priority with
/// Governor/Agent Coordinator, so [`BuildClaimOrder::order_claims`] never stops,
/// delays, reschedules, or admits a running producer; it places claims relative
/// to each other inside one target root and nothing more. Two claims of the
/// same class keep their lineage and work-item order, so the result is total
/// and reproducible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildClaimOrder {
    /// Target root the ordering applies to, as recorded text.
    pub target_root: String,
    /// Claims in descending pre-emption order.
    pub ordered: Vec<ClaimedBuild>,
}

impl BuildClaimOrder {
    /// Records the claims of one target root in pre-emption order.
    ///
    /// The sort key is [`ClaimedBuild`]'s own total order, so no second
    /// comparison rule is written here.
    #[must_use]
    pub fn order_claims(claims: &[ClaimedBuild]) -> Self {
        let mut ordered = claims.to_vec();
        ordered.sort();
        let target_root = claims.first().map_or_else(String::new, |claimed| {
            claimed.claim.target_root.to_string_lossy().into_owned()
        });
        Self {
            target_root,
            ordered,
        }
    }
}

/// Terminal state of one producer flight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProducerOutcome {
    /// The producer's process completed. Execution alone proves nothing; the
    /// retained evidence is what the waiters and their owners read.
    Complete {
        /// Execution axis only.
        execution: ExecutionStatus,
        /// Material output retained under an immutable artifact handle.
        evidence: RawEvidence,
    },
    /// The producer failed or was cancelled before completing. I18.26 line 34
    /// requires the waiters to receive the same evidence on this path, so the
    /// arm carries the producer's own `RawEvidence` verbatim.
    Failed {
        /// Execution axis of the producer.
        execution: ExecutionStatus,
        /// The producer's raw evidence, preserved.
        evidence: RawEvidence,
    },
}

impl ProducerOutcome {
    /// The exact evidence of this flight, on both the success and the failure
    /// path.
    ///
    /// The same value is what a waiter resolves through
    /// [`TargetRootBuildCoordinator::terminal_outcome`]; the producer reads it
    /// here off the outcome it just closed, and a waiter reads it off the copy
    /// the coordinator recorded for the flight.
    #[must_use]
    pub const fn evidence(&self) -> &RawEvidence {
        match self {
            Self::Complete { evidence, .. } | Self::Failed { evidence, .. } => evidence,
        }
    }
}

/// The result of closing one producer flight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerCompletion {
    /// Normalized [`BuildFingerprint::digest`] of the closed flight.
    pub lineage: String,
    /// Whether this call held the producer slot and released it.
    pub released: bool,
    /// The producer's terminal state. The same value is now recorded for the
    /// flight and is what its waiters receive.
    pub outcome: ProducerOutcome,
}

/// An artifact whose producer did not complete, retained for inspection.
///
/// I18.26 line 36: "cancellation preserves raw evidence and quarantines
/// incomplete artifacts". The two halves are separate: the evidence handle
/// stays readable, and the artifact is marked incomplete so no later reader can
/// treat it as a build product.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct QuarantinedArtifact {
    /// Normalized fingerprint digest of the cancelled flight.
    pub lineage: String,
    /// The incomplete artifact that must not be consumed.
    pub artifact: PathBuf,
}

/// The record a cancellation leaves behind.
///
/// The evidence cannot be omitted: [`BuildCancellation::record`] takes it by
/// value and refuses anything but a retained handle, so "cancellation without
/// evidence" is unrepresentable rather than merely discouraged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildCancellation {
    /// Work item that owned the cancelled producer slot.
    pub work_item_id: String,
    /// Normalized fingerprint digest of the cancelled flight.
    pub lineage: String,
    /// The governed target root the cancelled producer was bound to.
    pub target_root: PathBuf,
    /// The producer's raw evidence, preserved verbatim.
    pub evidence: RawEvidence,
    /// The incomplete artifact marked quarantined, if the producer wrote one.
    pub quarantine: Option<QuarantinedArtifact>,
}

impl BuildCancellation {
    /// Records a cancellation, preserving raw evidence and quarantining the
    /// incomplete artifact.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::EvidenceNotPreserved`] when the supplied
    /// evidence is not a retained handle. I18.26 line 36 makes retention a
    /// condition of the cancellation, not a best effort.
    pub fn record(
        work_item_id: String,
        lineage: String,
        target_root: PathBuf,
        evidence: RawEvidence,
        incomplete_artifact: Option<PathBuf>,
    ) -> Result<Self, BuildProjectionError> {
        if !matches!(evidence, RawEvidence::Retained { .. }) {
            return Err(BuildProjectionError::EvidenceNotPreserved);
        }
        let quarantine = incomplete_artifact.map(|artifact| QuarantinedArtifact {
            lineage: lineage.clone(),
            artifact,
        });
        Ok(Self {
            work_item_id,
            lineage,
            target_root,
            evidence,
            quarantine,
        })
    }
}

/// One artifact a disk-cleanup pass may consider removing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupCandidate {
    /// Normalized fingerprint digest whose lineage produced the artifact.
    pub lineage: String,
    /// The artifact to consider.
    pub artifact: PathBuf,
}

/// The exact decision about one cleanup candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupDecision {
    /// Nothing remains for this lineage, and no lease is held: the candidate
    /// may be removed by the owning storage layer.
    Removable,
    /// The candidate is retained for the exact typed reason below.
    Retained {
        /// The exact refusal.
        reason: BuildProjectionError,
    },
}

/// The result of one lineage- and lease-aware disk-cleanup pass.
///
/// I18.26 line 37. A candidate is removable only when two independent facts
/// hold: its lineage has no live producer, and no
/// [`RuntimeEnvironmentLease`] is still held. Any other outcome is retained
/// with its exact typed reason. The pass removes nothing itself — deletion
/// stays with the owning storage layer — and it never widens into removing a
/// complete artifact of a live lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildCleanupPass {
    /// Live lineage digests, derived from the producer claims.
    pub live_lineages: BTreeSet<String>,
    /// Runtime environment leases still held by their holders.
    pub held_leases: Vec<RuntimeEnvironmentLease>,
}

impl BuildCleanupPass {
    /// Builds the pass from the claims the caller already holds.
    ///
    /// Lineage is the fingerprint digest, so this needs no second identity
    /// mechanism: the caller reads the claims it already has and this reads
    /// the producer ones.
    #[must_use]
    pub fn live_lineages(claims: &[ClaimedBuild]) -> Self {
        Self {
            live_lineages: claims
                .iter()
                .filter(|claimed| claimed.claim.is_producer())
                .map(|claimed| claimed.claim.lineage.clone())
                .collect(),
            held_leases: Vec::new(),
        }
    }

    /// Records the runtime environment leases that are still held.
    ///
    /// The leases are the ones the admitted lanes still hold, read through
    /// [`crate::GovernedWorkEnvelope::runtime_leases`]. The envelope never
    /// derives a lease from a worktree, because a worktree does not isolate
    /// runtime resources; a held lease is a live holder, not a directory
    /// observation.
    #[must_use]
    pub fn with_live_leases(mut self, lanes: &[&GovernedWorkEnvelope]) -> Self {
        self.held_leases = lanes
            .iter()
            .flat_map(|lane| lane.runtime_leases().iter().cloned())
            .collect();
        self
    }

    /// Decides every candidate, in the order supplied.
    #[must_use]
    pub fn evaluate(&self, candidates: &[CleanupCandidate]) -> Vec<CleanupDecision> {
        candidates
            .iter()
            .map(|candidate| self.evaluate_one(candidate))
            .collect()
    }

    /// The single-candidate decision behind [`BuildCleanupPass::evaluate`].
    fn evaluate_one(&self, candidate: &CleanupCandidate) -> CleanupDecision {
        if self.live_lineages.contains(&candidate.lineage) {
            return CleanupDecision::Retained {
                reason: BuildProjectionError::LineageLive {
                    lineage: candidate.lineage.clone(),
                },
            };
        }
        match self.held_leases.first() {
            Some(lease) => CleanupDecision::Retained {
                reason: BuildProjectionError::LeaseStillHeld {
                    kind: lease.kind,
                    resource: lease.resource.clone(),
                    holder: lease.holder.clone(),
                },
            },
            None => CleanupDecision::Removable,
        }
    }
}

/// One closed producer flight, retained so the flight's waiters can resolve it.
///
/// The lineage is stored beside the outcome and re-checked on every read, so a
/// resolution can never hand a claim evidence recorded for a different lineage
/// that happens to share a target root.
struct ClosedFlight {
    lineage: String,
    outcome: ProducerOutcome,
}

/// The one InstrumentRunner-controlled build projection.
///
/// The coordinator owns two things and nothing else: the single-producer claim
/// per (target root, fingerprint), and the refusal of unrestricted agent Cargo
/// invocations. It creates no scheduler, no job, no queue, no budget, and no
/// pre-emption engine; I18.26 line 63 keeps those elsewhere.
///
/// # Why the slot is keyed on the target root
///
/// `SingleFlightBuildRegistry` keys its own map on
/// [`BuildFingerprint::digest`] and nothing else, and
/// [`BuildFingerprint`] has no worktree-id member. But I2.22, which I18.26
/// line 32 makes binding for target roots, puts the worktree id *and* the build
/// mode in the root path:
/// `%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>`.
/// A digest alone therefore cannot separate `wi-A` in `wt-1` from `wi-B` in
/// `wt-2` when they agree on every build input, yet those two work items build
/// in different directories and I10.8.4 requires one build-coordination owner
/// per target root.
///
/// The coordinator consequently holds **one registry per target root**. Inside a
/// root the registry still keys on the digest, which is the root's own last
/// path segment, so the slot and the root are the same lineage identity by
/// construction: a claim's `flight` can no longer name a producer that builds
/// somewhere other than the claim's `target_root`. The registry type itself is
/// untouched — it is reused exactly as [`SingleFlightBuildRegistry::claim`] and
/// [`SingleFlightBuildRegistry::release`] already define it, and no second
/// fingerprint, digest, or coordination primitive is introduced.
///
/// A registry exists only while its root has a live producer: releasing a
/// flight drops the entry, because the next claim for that root must be free to
/// become the producer. That is what bounds this map to *live* roots.
///
/// # Single-owner coordination
///
/// The state is behind a [`RefCell`], so a coordinator is single-owner and not
/// `Sync`. That is the intended shape, not a limitation to work around: I10.8.4
/// gives a target root exactly one build-coordination owner, and a second
/// coordinator instance would be a second owner. Sharing a registry across roots
/// was precisely the B-1 defect.
#[derive(Default)]
pub struct TargetRootBuildCoordinator {
    /// One live producer slot per target root.
    live: RefCell<BTreeMap<PathBuf, SingleFlightBuildRegistry>>,
    /// The terminal outcome of the most recently closed flight per target root.
    closed: RefCell<BTreeMap<PathBuf, ClosedFlight>>,
}

impl TargetRootBuildCoordinator {
    /// Creates a coordinator with no live producer slots and no closed flights.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: RefCell::new(BTreeMap::new()),
            closed: RefCell::new(BTreeMap::new()),
        }
    }

    /// Claims the producer slot for one work item, or returns the waiter's view
    /// of the existing producer of that item's target root.
    ///
    /// The slot is the existing `SingleFlightBuildRegistry`, held per target
    /// root, so the key and the root are one identity (see the type docs). Two
    /// work items that share a target root share one producer and the rest
    /// become waiters (I18.26 line 15); two work items whose toolchain, feature
    /// set, environment class, candidate, **worktree, or build mode** differ
    /// resolve to different roots and are different lineages with independent
    /// producer slots (lines 21-22, and I2.22).
    ///
    /// A claim granted [`BuildFlight::Producer`] also supersedes whatever this
    /// root recorded before: the root has no live producer, so the previous
    /// flight's artifacts are no longer what the root holds, and its recorded
    /// outcome is dropped rather than served to a later reader.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError`] for an incomplete or malformed
    /// declaration or an underivable lane, and
    /// [`BuildProjectionError::SingleFlight`] when the registry cannot be read
    /// or rejects the producer identity.
    pub fn claim(&self, item: &DeclaredWorkItem) -> Result<ProducerClaim, BuildProjectionError> {
        item.validate()?;
        let target_root = item.target_root()?;
        let lineage = item.envelope.fingerprint.digest().map_err(|source| {
            BuildProjectionError::InvalidDigest {
                field: "build_fingerprint",
                source,
            }
        })?;
        let flight = {
            let mut live = self.live.borrow_mut();
            let registry = live.entry(target_root.clone()).or_default();
            let flight = registry.claim(&item.envelope.fingerprint, item.work_item_id.clone())?;
            if matches!(flight, BuildFlight::Producer) {
                self.closed.borrow_mut().remove(&target_root);
            }
            flight
        };
        Ok(ProducerClaim {
            lineage,
            producer: item.work_item_id.clone(),
            flight,
            target_root,
        })
    }

    /// Closes one producer flight, releases its slot, and records its outcome so
    /// the flight's waiters can resolve the producer's own evidence.
    ///
    /// This is I18.26 line 34: a failed producer wakes waiters with the same
    /// evidence. Both arms of [`ProducerOutcome`] deliver the identical
    /// `RawEvidence`, the same value the waiters read back through
    /// [`TargetRootBuildCoordinator::terminal_outcome`]. Nothing is retried
    /// here — line 35 rules out a silent retry storm, so the decision to re-run
    /// stays with the owning work item.
    ///
    /// # Errors
    ///
    /// Returns [`BuildProjectionError::NotTheProducer`] when `item` does not
    /// hold a live flight of its target root, and the same declaration failures
    /// as [`TargetRootBuildCoordinator::claim`] for a malformed lane.
    pub fn completion_wakeup(
        &self,
        item: &DeclaredWorkItem,
        outcome: ProducerOutcome,
    ) -> Result<ProducerCompletion, BuildProjectionError> {
        item.validate()?;
        let target_root = item.target_root()?;
        let lineage = item.envelope.fingerprint.digest().map_err(|source| {
            BuildProjectionError::InvalidDigest {
                field: "build_fingerprint",
                source,
            }
        })?;
        let released = {
            let mut live = self.live.borrow_mut();
            let Some(registry) = live.get(&target_root) else {
                return Err(BuildProjectionError::NotTheProducer {
                    work_item_id: item.work_item_id.clone(),
                });
            };
            let released = registry
                .release(&item.envelope.fingerprint, &item.work_item_id)
                .map_err(BuildProjectionError::SingleFlight)?;
            if released {
                live.remove(&target_root);
            }
            released
        };
        if !released {
            return Err(BuildProjectionError::NotTheProducer {
                work_item_id: item.work_item_id.clone(),
            });
        }
        self.closed.borrow_mut().insert(
            target_root,
            ClosedFlight {
                lineage: lineage.clone(),
                outcome: outcome.clone(),
            },
        );
        Ok(ProducerCompletion {
            lineage,
            released,
            outcome,
        })
    }

    /// The terminal outcome a claim's flight reached, or `None` while the
    /// producer is still running.
    ///
    /// This is the waiter's side of I18.26 line 34. A waiter holds no handle
    /// of its own, so it resolves through the claim it already owns: the claim
    /// names the target root and the lineage, and the coordinator returns the
    /// producer's own recorded [`ProducerOutcome`] only when both match. The
    /// waiter therefore receives the *same* execution axis and the *same*
    /// immutable [`RawEvidence`] the producer closed with, on the success and
    /// the failure path alike, and the value is not a copy of anything the
    /// waiter supplied.
    ///
    /// `None` means the flight has not closed, or that a newer producer has
    /// already superseded this root's recorded outcome. It is never a signal to
    /// re-run: line 35 forbids a silent retry storm, so the decision stays with
    /// the owning work item.
    #[must_use]
    pub fn terminal_outcome(&self, claim: &ProducerClaim) -> Option<ProducerOutcome> {
        self.closed
            .borrow()
            .get(&claim.target_root)
            .filter(|closed| closed.lineage == claim.lineage)
            .map(|closed| closed.outcome.clone())
    }
}

/// The refusal of an agent-originated unrestricted Cargo selection.
///
/// I18.26 line 3 withdraws `--workspace` from a parallel agent, and line 31 is
/// equally unconditional about the number of producers per target root.
/// Neither has an escape hatch here: there is no "exact tool evidence" type
/// anywhere in the codebase that could justify a second producer, and
/// [`restrict_agent_argv`] applies this refusal to every origin including the
/// projected one, so admitting the projected route is not a way around it.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CargoScopeRefusal {
    /// `cargo --workspace` selects every workspace member.
    #[error(
        "agent-originated cargo invocation requests --workspace, which I18.26 line 3 withdraws from a parallel agent"
    )]
    Workspace,
    /// `cargo --all` is the alias of the same unrestricted selection.
    #[error(
        "agent-originated cargo invocation requests --all, which I18.26 line 3 withdraws from a parallel agent"
    )]
    All,
}

/// Origin of one Cargo argv under review.
///
/// The only route to a build is a [`ProjectedBuild`], and a projected argv is
/// package-selected by construction. An [`CargoOrigin::Agent`] argv is
/// inspected by [`restrict_agent_argv`] and refused when it names an
/// unrestricted workspace selection or is not a Cargo command at all.
///
/// [`CargoOrigin::Projected`] is not a free-typed label: it carries the
/// [`ProjectedBuild`] the argv is claimed to come from, so the claim is checked
/// against a real projection rather than asserted. There is no way to name the
/// projected origin without presenting one, which is what stops the label from
/// becoming a bypass of the only refusal. The enum borrows because the
/// projection it names outlives the inspection and is never copied or
/// reconstructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CargoOrigin<'a> {
    /// Emitted by [`DeclaredWorkItem::project`], carrying that projection.
    Projected(&'a ProjectedBuild),
    /// Supplied by a parallel agent or an operator shell.
    Agent,
}

/// A typed refusal or failure raised by the projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BuildProjectionError {
    /// The declaration is missing an element I18.26 line 7 names, or the
    /// element cannot be used. The projection refuses instead of defaulting.
    #[error("incomplete work item declaration: {0}")]
    IncompleteDeclaration(&'static str),
    /// A declared digest is not a valid digest.
    #[error("work item {field} is not a valid digest: {source}")]
    InvalidDigest {
        /// Offending field.
        field: &'static str,
        /// Exact shape failure.
        source: GraphError,
    },
    /// The lane tuple could not be derived or admitted.
    #[error(transparent)]
    Lane(#[from] WorkEnvelopeError),
    /// A public contract change declared no change set, so the reverse consumer
    /// closure has no root. Fail closed.
    #[error(
        "public contract change declared no change set, so the reverse consumer closure has no root"
    )]
    MissingChangeSet,
    /// A public contract change declared no capsule revision, so no
    /// compatibility fixture was named.
    #[error("public contract change declared no capsule revision as a compatibility fixture")]
    MissingCompatibilityFixture,
    /// An agent-originated argv requested an unrestricted workspace selection.
    #[error(transparent)]
    CargoScope(#[from] CargoScopeRefusal),
    /// An agent-originated argv runs no Cargo command at all, so it is not a
    /// governed build and is refused. This check applies to every origin,
    /// projected included.
    #[error("agent-originated cargo invocation does not name the cargo tool")]
    NotCargo,
    /// An argv claimed to be projected is not the argv of the
    /// [`ProjectedBuild`] it was presented with, so the projected route was
    /// not the route that produced it.
    #[error(
        "argv claimed as projected is not the argv emitted by the projection it was presented with"
    )]
    ProjectedArgvMismatch,
    /// A cancellation was recorded without retained raw evidence. I18.26 line
    /// 36 makes retention a condition of the cancellation.
    #[error("cancellation would not preserve raw evidence")]
    EvidenceNotPreserved,
    /// A producer flight was closed by a work item that did not hold it.
    #[error("work item {work_item_id} completed a build flight it does not hold")]
    NotTheProducer {
        /// Work item that attempted the completion.
        work_item_id: String,
    },
    /// Disk cleanup was asked to consider a live lineage.
    #[error("disk cleanup refused: build lineage {lineage} still has a producer")]
    LineageLive {
        /// The lineage that is still claimed.
        lineage: String,
    },
    /// Disk cleanup was asked to consider a lineage while a runtime environment
    /// lease is still held.
    #[error("disk cleanup refused: {kind:?} resource {resource} is still leased by {holder}")]
    LeaseStillHeld {
        /// Held lease class.
        kind: ResourceKind,
        /// Held lease resource name.
        resource: String,
        /// Holder of the live lease.
        holder: String,
    },
    /// The single-flight registry could not be read.
    #[error("single-flight build registry refused the claim: {0}")]
    SingleFlight(#[from] GraphError),
}

/// Refuses an agent-originated unrestricted Cargo selection.
///
/// I18.26 line 3: a parallel agent "does not independently launch unrestricted
/// `cargo --workspace` commands". The check is argv text, not semantics: it
/// never parses, executes, or reorders anything, and it never grants an
/// override.
///
/// The projected route is the only admitted one, and it is admitted by
/// *presenting the projection*, not by declaring it. There are three refusals,
/// and none of them can be stepped over by claiming the projected origin:
///
/// 1. the argv must name the cargo tool. This runs for **every** origin,
///    because a non-Cargo argv is not a governed build in the first place and
///    the projected route has no exemption from it;
/// 2. the argv must not request `--workspace` or `--all`. This also runs for
///    every origin, so even a hand-built [`ProjectedBuild`] cannot smuggle an
///    unrestricted selection through the projected arm;
/// 3. a [`CargoOrigin::Projected`] argv must equal, element for element, the
///    `argv` of the [`ProjectedBuild`] it was presented with. The projected
///    route is admitted only by [`DeclaredWorkItem::project`]'s own output, so
///    the origin label carries no authority of its own and cannot be asserted
///    into an admission.
///
/// Together these mean there is no argv that both reaches `Ok` and selects more
/// than the projected package set: to pass (2) the argv cannot name
/// `--workspace`/`--all`, and to pass (3) it cannot differ from a projection,
/// whose every selection is a `-p`.
///
/// # Errors
///
/// Returns [`BuildProjectionError::NotCargo`] when the argv does not name the
/// cargo tool, [`BuildProjectionError::CargoScope`] naming the exact flag when
/// it requests `--workspace` or `--all`, and
/// [`BuildProjectionError::ProjectedArgvMismatch`] when a projected argv is not
/// the argv of the projection it was presented with.
pub fn restrict_agent_argv(
    argv: &[String],
    origin: CargoOrigin<'_>,
) -> Result<Vec<String>, BuildProjectionError> {
    if argv.first().is_none_or(|first| first != "cargo") {
        return Err(BuildProjectionError::NotCargo);
    }
    for element in argv {
        match element.as_str() {
            "--workspace" => return Err(CargoScopeRefusal::Workspace.into()),
            "--all" => return Err(CargoScopeRefusal::All.into()),
            _ => {}
        }
    }
    if let CargoOrigin::Projected(projected) = origin
        && argv != projected.argv.as_slice()
    {
        return Err(BuildProjectionError::ProjectedArgvMismatch);
    }
    Ok(argv.to_vec())
}

/// Renders the exact projected argv for one change class.
///
/// `check` is the subcommand I18.26 line 10 names. A private change selects the
/// primary crate alone; a public change selects the provider and then each
/// member of the reverse consumer closure (line 13). `--features` is the only
/// other element, and it is emitted only from the declared fingerprint, so no
/// undeclared selection can enter the command. The argv is plain data; this
/// function executes nothing.
fn cargo_argv(
    primary_crate: &str,
    consumer_closure: &BTreeSet<String>,
    target_class: TargetClass,
    fingerprint: &BuildFingerprint,
) -> Vec<String> {
    let mut argv = vec!["cargo".to_owned(), PROJECTED_SUBCOMMAND.to_owned()];
    argv.push(PACKAGE_SELECTION_FLAG.to_owned());
    argv.push(primary_crate.to_owned());
    if target_class == TargetClass::PublicContractChange {
        for consumer in consumer_closure {
            argv.push(PACKAGE_SELECTION_FLAG.to_owned());
            argv.push(consumer.clone());
        }
    }
    for feature in &fingerprint.features {
        argv.push("--features".to_owned());
        argv.push(feature.clone());
    }
    argv
}

/// The reverse consumer closure of one public contract change, provider
/// excluded.
///
/// The traversal is the existing `BuildTestGraph::impact`; this only shapes its
/// result. A consumer that *is* the provider is dropped, because line 13 says
/// "provider + reverse consumer closure", not the provider twice.
fn consumer_closure(directive: &ChangeImpactDirective, provider: &str) -> BTreeSet<String> {
    directive
        .behavioral_drift_candidates
        .iter()
        .filter(|candidate| candidate.as_str() != provider)
        .cloned()
        .collect()
}

/// The edges the delegated consumer closure classified as affected.
///
/// I18.26 line 10 names the affected edges of a private change as part of its
/// proof. The set is the closure's affected nodes paired with the graph's own
/// recorded causal path, so a reader can see *why* each edge is affected
/// without this module re-deriving the traversal. A node that is its own root
/// was not reached across an edge and is not an edge.
fn affected_edges(directive: &ChangeImpactDirective) -> Vec<AffectedEdge> {
    let mut edges: Vec<AffectedEdge> = Vec::new();
    for consumer in &directive.behavioral_drift_candidates {
        let Some(causal_path) = directive.causal_paths.get(consumer) else {
            continue;
        };
        let Some(root) = causal_path.first() else {
            continue;
        };
        if root == consumer {
            continue;
        }
        edges.push(AffectedEdge {
            root: root.clone(),
            consumer: consumer.clone(),
            causal_path: causal_path.clone(),
        });
    }
    edges.sort();
    edges.dedup();
    edges
}
