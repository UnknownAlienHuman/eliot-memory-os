//! The canonical `BuildTestGraph` projection and its stored impact plans.
//!
//! This crate owns neither Cargo's compiler graph nor verifier execution.  It
//! accepts immutable observations from those owners and compiles a conservative
//! planning projection.  In particular, absence and impact are never inferred
//! from a missing edge: callers receive an explicit unknown directive when the
//! input cannot establish coverage.
//!
//! A [`BuildExecutionEdge`] `from -> to` declares that consumer `to` depends on
//! prerequisite `from`.  Build products flow along edge direction, and change
//! impact is traced the same way: from a changed prerequisite toward every
//! reachable consumer.  [`BuildTestGraph::impact`] and [`plan_impact`] follow
//! only edges supplied by the owning producer; the planner executes no
//! scanner, shell, or discovery process of its own.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use thiserror::Error;

mod resource_declaration;

pub use resource_declaration::{InvalidResourceClaim, ResourceClaim, ResourceKind, ResourceWeight};

pub const CONTRACT_NAME: &str = "eliot.instrument.build-test-graph";
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);
/// Version of the stored plan semantics.  Every [`ChangeImpactPlan`] carries
/// this exact string; consumers reject anything else.
pub const CHANGE_IMPACT_PLAN_VERSION: &str = "change-impact-plan-v1";
/// Default bound on consumer-closure traversal.  Overflow retains the
/// unresolved frontier instead of silently dropping consumers.
pub const MAX_TRAVERSAL_NODES: usize = 10_000;
/// Cap on a retained causal path (`root ..= node`, oldest entries dropped).
pub const MAX_CAUSAL_PATH_LEN: usize = 16;
/// Owner identity for the compiled build-execution revision commitment.
pub const BUILD_GRAPH_OWNER: &str = "build.execution";
/// Owner identity for the compiled verifier-coverage revision commitment.
pub const VERIFIERS_GRAPH_OWNER: &str = "verifiers.coverage";
/// Bounded broader tiers a plan may explicitly permit (`I18.4`).
pub const ADMITTED_BROADER_TIERS: [&str; 5] = ["T0", "T1", "T2", "T3", "T4"];
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

mod derived_cache;
mod finish_disposition;
mod plan_consumer;
mod work_envelope;

pub use derived_cache::{
    ADMITTED_SCHEMA_REVISIONS, ArtifactLineage, CacheCounters, CacheLimits, CacheLookup,
    CacheRejectReason, CacheStoreError, CachedArtifact, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_REJECTIONS, DERIVED_CACHE_SCHEMA_V1, DerivationOutcome, DerivedCacheIdentity,
    DerivedCacheStore, FreshDerivation, RejectedCacheRecord, RootDisposition, TrustPolicy,
};
pub use finish_disposition::{
    AcceptanceCriticality, AcceptanceOracle, ContractChallenge, ContractChallengeReason,
    DeclaredAcceptance, DispositionError, EvidenceOutcome, EvidenceProof, EvidenceReceipt,
    FinishBoundaryResponse, FinishDisposition, OracleObservation, OracleOrigin,
    ProvenRequiredProof, RequiredProofCompletion, TaskOutcome, apply_finish_boundary,
};
pub use plan_consumer::{ApplicableInputs, ResolverPlanConsumer};
pub use work_envelope::{
    BUILD_ROOT_DIRECTORY, BuildMode, CARGO_HOME_ENV, CARGO_TARGET_DIR_ENV, CandidateIdentity,
    FIXTURE_NAMESPACE_ENV, FIXTURE_ROOT_DIRECTORY, FIXTURE_ROOT_ENV, GovernedWorkEnvelope,
    LaneIdentity, RuntimeEnvironmentLease, WorkEnvelopeError,
};

pub(crate) fn validate_text_shape(value: &str, field: &'static str) -> Result<(), GraphError> {
    text(value, field)
}

pub(crate) fn validate_digest_shape(value: &str, field: &'static str) -> Result<(), GraphError> {
    digest(value, field)
}

pub(crate) fn digest_bytes_for<T: Serialize>(value: &T) -> Result<String, GraphError> {
    canonical(value)
}

pub(crate) fn sha256_of(bytes: &[u8]) -> String {
    digest_bytes(bytes)
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GraphError {
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    #[error("graph input is inconsistent: {0}")]
    Inconsistent(String),
    #[error("conflicting duplicate {owner} identity for key {key}")]
    ConflictingIdentity { owner: String, key: String },
    #[error("build fingerprint overflowed while computing its digest")]
    FingerprintOverflow,
    #[error("single-flight registry lock was poisoned")]
    LockPoisoned,
}

fn text(value: &str, field: &'static str) -> Result<(), GraphError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(GraphError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), GraphError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
    {
        Err(GraphError::InvalidDigest { field })
    } else {
        Ok(())
    }
}

fn digest_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut digest, byte| {
            digest.push(HEX_DIGITS[(byte >> 4) as usize] as char);
            digest.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
            digest
        })
}

fn canonical<T: Serialize>(value: &T) -> Result<String, GraphError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|_| GraphError::FingerprintOverflow)
}

/// Inserts one owner-keyed record.  A byte-identical duplicate is tolerated;
/// a conflicting duplicate is rejected: there is no last-write-wins.
fn insert_unique<T: Eq>(
    map: &mut BTreeMap<String, T>,
    owner: &str,
    key: String,
    value: T,
) -> Result<(), GraphError> {
    use std::collections::btree_map::Entry;
    match map.entry(key) {
        Entry::Vacant(slot) => {
            slot.insert(value);
            Ok(())
        }
        Entry::Occupied(slot) => {
            if *slot.get() == value {
                Ok(())
            } else {
                Err(GraphError::ConflictingIdentity {
                    owner: owner.to_owned(),
                    key: slot.key().clone(),
                })
            }
        }
    }
}

/// Identity of a Cargo package at one source revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CrateIdentity {
    pub package_id: String,
    pub source_revision: String,
}

impl CrateIdentity {
    pub fn new(
        package_id: impl Into<String>,
        source_revision: impl Into<String>,
    ) -> Result<Self, GraphError> {
        let value = Self {
            package_id: package_id.into(),
            source_revision: source_revision.into(),
        };
        text(&value.package_id, "package_id")?;
        text(&value.source_revision, "source_revision")?;
        Ok(value)
    }
}

/// Digest of a public Rust, schema, or protocol surface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PublicContractDigest {
    pub crate_identity: CrateIdentity,
    pub digest: String,
}

impl PublicContractDigest {
    pub fn validate(&self) -> Result<(), GraphError> {
        digest(&self.digest, "contract_digest")
    }
}

/// Exact inputs which make a build artifact reusable.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BuildFingerprint {
    pub workspace: String,
    pub candidate: String,
    pub toolchain: String,
    pub target: String,
    pub profile: String,
    pub features: Vec<String>,
    pub environment_class: String,
    pub source_closure_digest: String,
    pub manifest_digest: String,
    pub build_script_digest: Option<String>,
    pub proc_macro_digest: Option<String>,
    pub build_class: String,
    pub contract_revision: String,
}

impl BuildFingerprint {
    pub fn validate(&self) -> Result<(), GraphError> {
        for (value, field) in [
            (&self.workspace, "workspace"),
            (&self.candidate, "candidate"),
            (&self.toolchain, "toolchain"),
            (&self.target, "target"),
            (&self.profile, "profile"),
            (&self.environment_class, "environment_class"),
            (&self.build_class, "build_class"),
            (&self.contract_revision, "contract_revision"),
        ] {
            text(value, field)?;
        }
        for (value, field) in [
            (&self.source_closure_digest, "source_closure_digest"),
            (&self.manifest_digest, "manifest_digest"),
        ] {
            digest(value, field)?;
        }
        for value in [&self.build_script_digest, &self.proc_macro_digest]
            .into_iter()
            .flatten()
        {
            digest(value, "optional_build_input_digest")?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, GraphError> {
        self.validate()?;
        canonical(self)
    }
}

/// Revision of a discoverable test capsule and its non-discoverable policy.
///
/// The graph projection references the same executable revision the neutral
/// capsule contract (`eliot-contracts`, issue #1804) describes: [`Self::capsule_digest`]
/// carries that revision's digest instead of a separately edited copy, and
/// [`BuildTestGraph::capsules_for_cell`] resolves one cell to its bound
/// projections. This crate owns neither the capsule vocabulary nor execution;
/// it only projects what the owning producers supply.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ModuleTestCapsuleRevision {
    pub capsule_id: String,
    pub revision: String,
    pub selector: String,
    pub fixture_digest: String,
    pub oracle_digest: String,
    pub resource_classes: Vec<String>,
    /// Cell the projected revision proves. Absent on projections emitted
    /// before the cell binding existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    /// Revision of the cell contract surface under proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_revision: Option<String>,
    /// Digest of the neutral executable capsule revision this projection
    /// references. Equality with the descriptor digest is the same-revision
    /// check; inequality means the projection is stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_digest: Option<String>,
    /// Producer revision that emitted the referenced descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_revision: Option<String>,
    /// Exact Instrument profile name the revision executes through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Exact admitted profile revision; zero never names a revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_revision: Option<u64>,
    /// Compilation target the revision is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Required Cargo features.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Highest proof level the revision may claim, in the neutral
    /// vocabulary owned by `eliot-contracts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_ceiling: Option<String>,
    /// Supported-execution disposition in the neutral vocabulary owned by
    /// `eliot-contracts`. This projection never re-decides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
}

impl ModuleTestCapsuleRevision {
    pub fn validate(&self) -> Result<(), GraphError> {
        for (v, f) in [
            (&self.capsule_id, "capsule_id"),
            (&self.revision, "capsule_revision"),
            (&self.selector, "selector"),
        ] {
            text(v, f)?;
        }
        digest(&self.fixture_digest, "fixture_digest")?;
        digest(&self.oracle_digest, "oracle_digest")?;
        self.validate_cell_binding()
    }

    fn validate_cell_binding(&self) -> Result<(), GraphError> {
        for (value, field) in [
            (&self.cell, "capsule_cell"),
            (&self.cell_revision, "capsule_cell_revision"),
            (&self.producer_revision, "capsule_producer_revision"),
            (&self.profile, "capsule_profile"),
            (&self.target, "capsule_target"),
            (&self.proof_ceiling, "capsule_proof_ceiling"),
            (&self.disposition, "capsule_disposition"),
        ] {
            if let Some(value) = value {
                text(value, field)?;
            }
        }
        if let Some(value) = &self.capsule_digest {
            digest(value, "capsule_digest")?;
        }
        if self.profile_revision == Some(0) {
            return Err(GraphError::Inconsistent(
                "capsule profile_revision must be non-zero".to_owned(),
            ));
        }
        for feature in &self.features {
            text(feature, "capsule_feature")?;
        }
        Ok(())
    }

    /// Whether this projection references the neutral capsule revision
    /// `digest`. Inequality means the projection is stale, never that the
    /// descriptor moved.
    pub fn binds_digest(&self, digest: &str) -> bool {
        self.capsule_digest.as_deref() == Some(digest)
    }
}

/// Exact runtime crates, artifacts, and protocol revision used together.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RuntimeBundleIdentity {
    pub bundle_id: String,
    pub revision: String,
    pub crates: Vec<CrateIdentity>,
    pub artifacts: Vec<String>,
    pub protocol_manifest_digest: String,
}

impl RuntimeBundleIdentity {
    pub fn validate(&self) -> Result<(), GraphError> {
        text(&self.bundle_id, "bundle_id")?;
        text(&self.revision, "bundle_revision")?;
        if self.crates.is_empty() {
            return Err(GraphError::Empty {
                field: "runtime_bundle.crates",
            });
        }
        digest(&self.protocol_manifest_digest, "protocol_manifest_digest")
    }
}

/// Dependency-class discriminator preserved from the owning Cargo
/// observation.  Build-time classes (`BuildScript`, `ProcMacro`,
/// `DevDependency`) scope the corresponding build/test proofs; they are never
/// treated as runtime linkage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum BuildEdgeKind {
    Package,
    Target,
    Feature,
    Configuration,
    BuildScript,
    ProcMacro,
    DevDependency,
    Artifact,
    Runner,
}

/// Host-versus-target role preserved from the owning resolve observation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DependencyRole {
    /// Dependency linked into the target artifact.
    Target,
    /// Dependency executed on the build host (build scripts, proc macros).
    Host,
    /// Dependency participating only in the build plan itself.
    Build,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}

/// One supplied build dependency edge.
///
/// Orientation: `from` is the prerequisite and `to` is the consumer (`to`
/// depends on `from`).  Change impact flows along edge direction, from a
/// changed prerequisite toward reachable consumers.  The planner never inverts
/// this relation and never invents an edge.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BuildExecutionEdge {
    pub from: String,
    pub to: String,
    pub kind: BuildEdgeKind,
    /// Cargo `cfg`/feature condition attached by the owner, when any.
    pub condition: Option<String>,
    /// Rename or alias attached by the owner, when any.
    pub alias: Option<String>,
    /// Host-versus-target role of this dependency edge, when recorded.
    pub role: Option<DependencyRole>,
    pub source_revision: String,
    pub profile_revision: String,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BuildExecutionGraph {
    pub revision: String,
    pub nodes: BTreeSet<String>,
    pub edges: Vec<BuildExecutionEdge>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct VerifierCoverageEdge {
    pub verifier: String,
    pub target: String,
    pub property: String,
    pub scope: String,
    pub source_revision: String,
    pub profile_revision: String,
    pub coverage: Coverage,
    pub exact: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct VerifierCoverageGraph {
    pub revision: String,
    pub verifiers: BTreeSet<String>,
    pub targets: BTreeSet<String>,
    pub edges: Vec<VerifierCoverageEdge>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct FailureRecord {
    pub signature: String,
    pub affected_nodes: BTreeSet<String>,
    pub profile_revision: String,
    pub source_revision: String,
    pub escaped_regression: bool,
}

/// Producer commitment retained for freshness verification: the owner, the
/// exact source revision it published, and the content digest of that
/// payload.  Caller revision strings are verified against these retained
/// commitments, never trusted alone.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SourceCommitment {
    pub owner: String,
    pub revision: String,
    pub content_digest: String,
}

impl SourceCommitment {
    pub fn validate(&self) -> Result<(), GraphError> {
        text(&self.owner, "commitment.owner")?;
        text(&self.revision, "commitment.revision")?;
        digest(&self.content_digest, "commitment.content_digest")
    }
}

/// Explicit supported non-applicability: the owning producer declares that a
/// graph node needs no verifier because the stated scope does not apply.
/// This is the only way a node without verifier coverage avoids an unknown
/// classification; absence of an edge alone never qualifies.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NonApplicabilityDeclaration {
    pub node: String,
    pub scope: String,
    pub reason: String,
}

impl NonApplicabilityDeclaration {
    pub fn validate(&self) -> Result<(), GraphError> {
        text(&self.node, "not_applicable.node")?;
        text(&self.scope, "not_applicable.scope")?;
        text(&self.reason, "not_applicable.reason")
    }
}

/// Base/candidate ownership of one changed path.  Deleted paths carry only a
/// base owner and renamed paths carry both, so removed declarations cannot
/// erase the consumer obligations recorded under the base revision.  A path
/// with neither owner keeps unknown ownership and stays a plan gap.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OwnershipObservation {
    pub path: String,
    pub base_owner: Option<String>,
    pub candidate_owner: Option<String>,
}

impl OwnershipObservation {
    pub fn validate(&self) -> Result<(), GraphError> {
        text(&self.path, "changed_path.path")?;
        if let Some(owner) = &self.base_owner {
            text(owner, "changed_path.base_owner")?;
        }
        if let Some(owner) = &self.candidate_owner {
            text(owner, "changed_path.candidate_owner")?;
        }
        Ok(())
    }

    /// Owning node used as an impact root, preferring the candidate revision.
    pub fn impact_root(&self) -> Option<&str> {
        self.candidate_owner
            .as_deref()
            .or(self.base_owner.as_deref())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct GraphInputs {
    pub build: BuildExecutionGraph,
    pub verifiers: VerifierCoverageGraph,
    pub contracts: Vec<PublicContractDigest>,
    pub capsules: Vec<ModuleTestCapsuleRevision>,
    pub runtime_bundles: Vec<RuntimeBundleIdentity>,
    pub failures: Vec<FailureRecord>,
    /// Retained producer commitments used for freshness verification.
    #[serde(default)]
    pub source_commitments: Vec<SourceCommitment>,
    /// Explicit supported non-applicability declarations.
    #[serde(default)]
    pub not_applicable: Vec<NonApplicabilityDeclaration>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BuildTestGraph {
    pub revision: String,
    pub build: BuildExecutionGraph,
    pub verifiers: VerifierCoverageGraph,
    pub contracts: BTreeMap<String, PublicContractDigest>,
    pub capsules: BTreeMap<String, ModuleTestCapsuleRevision>,
    pub runtime_bundles: BTreeMap<String, RuntimeBundleIdentity>,
    pub failures: Vec<FailureRecord>,
    #[serde(default)]
    pub source_commitments: BTreeMap<String, SourceCommitment>,
    #[serde(default)]
    pub not_applicable: BTreeMap<String, NonApplicabilityDeclaration>,
}

impl BuildTestGraph {
    /// Compiles a projection and rejects edges whose endpoints are not supplied
    /// by the owning source graph. No inferred edge is inserted here.
    pub fn compile(inputs: GraphInputs) -> Result<Self, GraphError> {
        if inputs.build.nodes.is_empty() {
            return Err(GraphError::Empty {
                field: "build.nodes",
            });
        }
        text(&inputs.build.revision, "build.revision")?;
        text(&inputs.verifiers.revision, "verifiers.revision")?;
        validate_build_edges(&inputs.build)?;
        validate_verifier_edges(&inputs.verifiers)?;
        let GraphInputs {
            build,
            verifiers,
            contracts,
            capsules,
            runtime_bundles,
            failures,
            source_commitments,
            not_applicable,
        } = inputs;
        let (contracts, capsules, bundles) =
            retain_owner_records(contracts, capsules, runtime_bundles)?;
        let (commitments, not_applicable) =
            retain_planning_records(&build.nodes, source_commitments, not_applicable)?;
        let revision = canonical(&(
            build.revision.clone(),
            verifiers.revision.clone(),
            &contracts,
            &capsules,
            &bundles,
            &failures,
            &commitments,
            &not_applicable,
        ))?;
        Ok(Self {
            revision,
            build,
            verifiers,
            contracts,
            capsules,
            runtime_bundles: bundles,
            failures,
            source_commitments: commitments,
            not_applicable,
        })
    }

    /// Capsule projections bound to one cell, in capsule-id order.
    ///
    /// `BTreeMap` iteration is sorted, so the output is deterministic.
    /// Multiple cells in one package stay separately attributable: each
    /// projection names its own cell rather than the shared package.
    pub fn capsules_for_cell(&self, cell: &str) -> Vec<&ModuleTestCapsuleRevision> {
        self.capsules
            .values()
            .filter(|capsule| capsule.cell.as_deref() == Some(cell))
            .collect()
    }

    /// Produces conservative affected-proof directives for changed graph nodes.
    ///
    /// Impact starts at every changed node plus the owning nodes of changed
    /// paths (candidate owner, else base owner for deleted or renamed paths)
    /// and follows build edges toward consumers.  Every affected node is
    /// classified: complete coverage, explicit supported non-applicability,
    /// or missing/partial/unknown coverage.  An affected node with no
    /// verifier edge is unknown, never safely omitted; heuristics and
    /// history may only widen the missing set, never cancel an exact
    /// requirement.
    pub fn impact(&self, change: &ChangeSet) -> ChangeImpactDirective {
        self.impact_bounded(change, MAX_TRAVERSAL_NODES)
    }

    /// Bounded variant of [`BuildTestGraph::impact`].  When the bound stops
    /// traversal, the queued-but-unvisited consumers are retained as the
    /// unresolved frontier instead of being dropped.
    fn impact_bounded(&self, change: &ChangeSet, bound: usize) -> ChangeImpactDirective {
        let broader = change.workspace_or_toolchain_changed
            || change.lockfile_changed
            || change.feature_graph_changed
            || change.generated_or_build_script_changed;
        let (roots, ownerless_paths) = impact_roots(change);
        let mut seeds: BTreeSet<String> = roots.clone();
        if change.workspace_or_toolchain_changed
            || change.lockfile_changed
            || change.feature_graph_changed
        {
            seeds.extend(self.build.nodes.iter().cloned());
        }
        let (visited, frontier, causal_paths) =
            traverse_consumers(&self.consumer_adjacency(), &seeds, bound.max(1));
        let mut affected = visited;
        affected.extend(frontier.iter().cloned());
        let node_coverage = self.classify_nodes(&affected, &frontier);
        let exact_verifiers: BTreeSet<String> = self
            .verifiers
            .edges
            .iter()
            .filter(|edge| {
                affected.contains(&edge.target) && edge.exact && edge.coverage == Coverage::Complete
            })
            .map(|edge| edge.verifier.clone())
            .collect();
        let coverage_unknown = node_coverage
            .values()
            .any(|coverage| !coverage.is_established());
        let unknown = broader
            || coverage_unknown
            || !change.unsupported_conditions.is_empty()
            || !ownerless_paths.is_empty();
        let missing = self.collect_missing(
            change,
            &roots,
            &ownerless_paths,
            &affected,
            &node_coverage,
            unknown,
        );
        ChangeImpactDirective {
            structural_breaks: change.public_contract_changed
                || change.generated_or_build_script_changed,
            behavioral_drift_candidates: affected,
            missing_expected_cochanges: BTreeSet::new(),
            impacted_verifiers_exact: exact_verifiers,
            missing_tests: missing,
            unknown_coverage: unknown,
            required_broader_profile: broader || unknown,
            node_coverage,
            unresolved_frontier: frontier,
            causal_paths,
        }
    }

    /// Prerequisite-to-consumers adjacency over the supplied build edges.
    fn consumer_adjacency(&self) -> BTreeMap<&str, BTreeSet<&str>> {
        let mut consumers: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for edge in &self.build.edges {
            consumers
                .entry(edge.from.as_str())
                .or_default()
                .insert(edge.to.as_str());
        }
        consumers
    }

    /// Builds the widening-only missing set: uncovered nodes, unknown
    /// owners, unsupported conditions, touched runtime bundles, and
    /// historical escapes.  Nothing here cancels an exact requirement.
    #[allow(clippy::too_many_arguments)]
    fn collect_missing(
        &self,
        change: &ChangeSet,
        roots: &BTreeSet<String>,
        ownerless_paths: &BTreeSet<String>,
        affected: &BTreeSet<String>,
        node_coverage: &BTreeMap<String, NodeCoverage>,
        unknown: bool,
    ) -> BTreeSet<String> {
        let mut missing = BTreeSet::new();
        if unknown {
            missing.insert("broader-profile-required".to_owned());
        }
        for (node, coverage) in node_coverage {
            if !coverage.is_established() && self.build.nodes.contains(node) {
                missing.insert(format!("uncovered-node:{node}"));
            }
        }
        for root in roots {
            if !self.build.nodes.contains(root) {
                missing.insert(format!("unknown-owner:{root}"));
            }
        }
        for path in ownerless_paths {
            missing.insert(format!("unknown-owner:{path}"));
        }
        for condition in &change.unsupported_conditions {
            missing.insert(format!("unsupported-condition:{condition}"));
        }
        for (bundle_id, bundle) in &self.runtime_bundles {
            if bundle
                .crates
                .iter()
                .any(|member| affected.contains(&member.package_id))
            {
                missing.insert(format!("runtime-bundle:{bundle_id}"));
            }
        }
        for failure in &self.failures {
            if failure.escaped_regression && !failure.affected_nodes.is_disjoint(affected) {
                missing.insert(format!("historical-escape:{}", failure.signature));
            }
        }
        missing
    }

    /// Classifies every affected node.  Complete coverage needs an exact
    /// complete verifier edge; explicit owner declaration is the only
    /// waiver.  Anything else — partial edges, zero edges, unknown
    /// ownership, unresolved reachability — stays non-established.
    fn classify_nodes(
        &self,
        affected: &BTreeSet<String>,
        frontier: &BTreeSet<String>,
    ) -> BTreeMap<String, NodeCoverage> {
        let mut coverage = BTreeMap::new();
        for node in affected {
            let classified = if frontier.contains(node) || !self.build.nodes.contains(node) {
                NodeCoverage::Unknown
            } else {
                self.classify_known_node(node)
            };
            coverage.insert(node.clone(), classified);
        }
        coverage
    }

    /// Classifies one node known to the build graph.
    fn classify_known_node(&self, node: &str) -> NodeCoverage {
        let mut any_edge = false;
        for edge in &self.verifiers.edges {
            if edge.target == node {
                if edge.exact && edge.coverage == Coverage::Complete {
                    return NodeCoverage::Complete;
                }
                any_edge = true;
            }
        }
        if let Some(waiver) = self.not_applicable.get(node) {
            NodeCoverage::NotApplicable {
                scope: waiver.scope.clone(),
                reason: waiver.reason.clone(),
            }
        } else if any_edge {
            NodeCoverage::Partial
        } else {
            NodeCoverage::Missing
        }
    }
}

fn validate_build_edges(graph: &BuildExecutionGraph) -> Result<(), GraphError> {
    for edge in &graph.edges {
        if !graph.nodes.contains(&edge.from) || !graph.nodes.contains(&edge.to) {
            return Err(GraphError::Inconsistent(format!(
                "build edge {} -> {} has an unknown endpoint",
                edge.from, edge.to
            )));
        }
        if let Some(condition) = &edge.condition {
            text(condition, "build.edge.condition")?;
        }
        if let Some(alias) = &edge.alias {
            text(alias, "build.edge.alias")?;
        }
    }
    Ok(())
}

fn validate_verifier_edges(graph: &VerifierCoverageGraph) -> Result<(), GraphError> {
    for edge in &graph.edges {
        if !graph.verifiers.contains(&edge.verifier) || !graph.targets.contains(&edge.target) {
            return Err(GraphError::Inconsistent(format!(
                "coverage edge {} -> {} has an unknown endpoint",
                edge.verifier, edge.target
            )));
        }
    }
    Ok(())
}

type OwnerRecordMaps = (
    BTreeMap<String, PublicContractDigest>,
    BTreeMap<String, ModuleTestCapsuleRevision>,
    BTreeMap<String, RuntimeBundleIdentity>,
);

type PlanningRecordMaps = (
    BTreeMap<String, SourceCommitment>,
    BTreeMap<String, NonApplicabilityDeclaration>,
);

/// Retains owner-keyed contract/capsule/bundle records, rejecting
/// conflicting duplicates instead of last-write-wins.
fn retain_owner_records(
    contracts: Vec<PublicContractDigest>,
    capsules: Vec<ModuleTestCapsuleRevision>,
    bundles: Vec<RuntimeBundleIdentity>,
) -> Result<OwnerRecordMaps, GraphError> {
    let mut retained_contracts = BTreeMap::new();
    for contract in contracts {
        contract.validate()?;
        insert_unique(
            &mut retained_contracts,
            "contract",
            contract.crate_identity.package_id.clone(),
            contract,
        )?;
    }
    let mut retained_capsules = BTreeMap::new();
    for capsule in capsules {
        capsule.validate()?;
        insert_unique(
            &mut retained_capsules,
            "capsule",
            capsule.capsule_id.clone(),
            capsule,
        )?;
    }
    let mut retained_bundles = BTreeMap::new();
    for bundle in bundles {
        bundle.validate()?;
        insert_unique(
            &mut retained_bundles,
            "runtime-bundle",
            bundle.bundle_id.clone(),
            bundle,
        )?;
    }
    Ok((retained_contracts, retained_capsules, retained_bundles))
}

/// Retains producer commitments and non-applicability declarations.
/// Declarations for unknown nodes are rejected as inconsistent.
fn retain_planning_records(
    nodes: &BTreeSet<String>,
    commitments: Vec<SourceCommitment>,
    declarations: Vec<NonApplicabilityDeclaration>,
) -> Result<PlanningRecordMaps, GraphError> {
    let mut retained_commitments = BTreeMap::new();
    for commitment in commitments {
        commitment.validate()?;
        insert_unique(
            &mut retained_commitments,
            "source-commitment",
            commitment.owner.clone(),
            commitment,
        )?;
    }
    let mut retained_declarations = BTreeMap::new();
    for declaration in declarations {
        declaration.validate()?;
        if !nodes.contains(&declaration.node) {
            return Err(GraphError::Inconsistent(format!(
                "non-applicability declaration for unknown node {}",
                declaration.node
            )));
        }
        insert_unique(
            &mut retained_declarations,
            "non-applicability",
            declaration.node.clone(),
            declaration,
        )?;
    }
    Ok((retained_commitments, retained_declarations))
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ChangeSet {
    pub changed_nodes: BTreeSet<String>,
    pub public_contract_changed: bool,
    pub generated_or_build_script_changed: bool,
    pub workspace_or_toolchain_changed: bool,
    pub lockfile_changed: bool,
    pub feature_graph_changed: bool,
    /// Changed paths with base/candidate ownership for deleted/renamed mapping.
    #[serde(default)]
    pub changed_paths: Vec<OwnershipObservation>,
    /// Dependency conditions the producer could not evaluate; each stays a gap.
    #[serde(default)]
    pub unsupported_conditions: Vec<String>,
}

/// Per-node verifier coverage classification for one affected node.
///
/// `Missing` (affected node, zero verifier edges) and `Unknown` (node absent
/// from the graph or behind the unresolved traversal frontier) both force
/// unknown coverage: absence of an edge never proves no impact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum NodeCoverage {
    /// At least one exact complete verifier edge covers the node.
    Complete,
    /// The owner explicitly declared verification not applicable.
    NotApplicable { scope: String, reason: String },
    /// Verifier edges exist but none is exact and complete.
    Partial,
    /// The node is affected but has no verifier edge at all.
    Missing,
    /// Ownership or reachability could not be established.
    Unknown,
}

impl NodeCoverage {
    /// Returns true only when coverage is established or explicitly waived.
    pub fn is_established(&self) -> bool {
        matches!(self, Self::Complete | Self::NotApplicable { .. })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChangeImpactDirective {
    pub structural_breaks: bool,
    pub behavioral_drift_candidates: BTreeSet<String>,
    pub missing_expected_cochanges: BTreeSet<String>,
    pub impacted_verifiers_exact: BTreeSet<String>,
    pub missing_tests: BTreeSet<String>,
    pub unknown_coverage: bool,
    pub required_broader_profile: bool,
    /// Per affected node coverage classification, frontier included.
    #[serde(default)]
    pub node_coverage: BTreeMap<String, NodeCoverage>,
    /// Queued consumers left unvisited when the traversal bound stopped.
    #[serde(default)]
    pub unresolved_frontier: BTreeSet<String>,
    /// Compact causal path (`root ..= node`, capped) per affected node.
    #[serde(default)]
    pub causal_paths: BTreeMap<String, Vec<String>>,
}

/// Impact roots: changed nodes plus the owning nodes of changed paths,
/// preferring candidate owners so deleted paths keep their base consumers.
/// Paths with neither owner are returned separately and stay gaps.
fn impact_roots(change: &ChangeSet) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut roots: BTreeSet<String> = change.changed_nodes.clone();
    let mut ownerless_paths: BTreeSet<String> = BTreeSet::new();
    for observation in &change.changed_paths {
        if let Some(owner) = observation.impact_root() {
            roots.insert(owner.to_owned());
        } else {
            ownerless_paths.insert(observation.path.clone());
        }
    }
    (roots, ownerless_paths)
}

/// Breadth-first consumer closure over prerequisite-to-consumers adjacency.
/// Cycles terminate on the visited set; every enqueue is stable and
/// deduplicated; overflow keeps the queued remainder as the frontier.
fn traverse_consumers(
    consumers: &BTreeMap<&str, BTreeSet<&str>>,
    seeds: &BTreeSet<String>,
    bound: usize,
) -> (
    BTreeSet<String>,
    BTreeSet<String>,
    BTreeMap<String, Vec<String>>,
) {
    let mut queued: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for seed in seeds {
        queued.insert(seed.clone());
        queue.push_back(seed.clone());
    }
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut causal_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for seed in seeds {
        causal_paths.insert(seed.clone(), vec![seed.clone()]);
    }
    while let Some(current) = queue.pop_front() {
        if visited.contains(&current) {
            continue;
        }
        if visited.len() >= bound {
            queue.push_front(current);
            break;
        }
        visited.insert(current.clone());
        if let Some(nexts) = consumers.get(current.as_str()) {
            for next in nexts {
                if queued.insert((*next).to_owned()) {
                    queue.push_back((*next).to_owned());
                    let mut path = causal_paths.get(&current).cloned().unwrap_or_default();
                    path.push((*next).to_owned());
                    if path.len() > MAX_CAUSAL_PATH_LEN {
                        let start = path.len() - MAX_CAUSAL_PATH_LEN;
                        path = path.into_iter().skip(start).collect();
                    }
                    causal_paths.insert((*next).to_owned(), path);
                }
            }
        }
    }
    let frontier: BTreeSet<String> = queue
        .into_iter()
        .filter(|node| !visited.contains(node))
        .collect();
    (visited, frontier, causal_paths)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildFlight {
    Producer,
    Waiter { producer: String },
}

/// In-memory coordination identity for one exact build fingerprint. It does
/// not run a build or own artifacts; it only prevents duplicate producers.
#[derive(Clone, Default)]
pub struct SingleFlightBuildRegistry {
    active: Arc<Mutex<BTreeMap<String, String>>>,
}

impl SingleFlightBuildRegistry {
    pub fn claim(
        &self,
        fingerprint: &BuildFingerprint,
        producer: impl Into<String>,
    ) -> Result<BuildFlight, GraphError> {
        let key = fingerprint.digest()?;
        let producer = producer.into();
        text(&producer, "producer")?;
        let mut active = self.active.lock().map_err(|_| GraphError::LockPoisoned)?;
        Ok(
            match active.entry(key).or_insert_with(|| producer.clone()) {
                owner if owner == &producer => BuildFlight::Producer,
                owner => BuildFlight::Waiter {
                    producer: owner.clone(),
                },
            },
        )
    }

    pub fn release(
        &self,
        fingerprint: &BuildFingerprint,
        producer: &str,
    ) -> Result<bool, GraphError> {
        let key = fingerprint.digest()?;
        let mut active = self.active.lock().map_err(|_| GraphError::LockPoisoned)?;
        if active.get(&key).is_some_and(|owner| owner == producer) {
            active.remove(&key);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

/// Failures which prevent a plan from being admitted, stored, or replayed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PlanError {
    /// A graph input or producer commitment was invalid.
    #[error(transparent)]
    Graph(#[from] GraphError),
    /// A required identifier is invalid.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A required digest is invalid.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// A numeric limit cannot be zero.
    #[error("{field} must be non-zero")]
    InvalidLimit { field: &'static str },
    /// A broader tier must name one bounded `I18.4` tier (`T0..=T4`).
    #[error("permitted broader tier must be one of T0..=T4, got {tier}")]
    InvalidTier { tier: String },
    /// A discovery entry occurred more than once.
    #[error("duplicate discovery entry: {entry}")]
    DuplicateEntry { entry: String },
    /// Discovery snapshot identity moved under the plan inputs.
    #[error("discovery snapshot drift in {field}: plan and snapshot disagree")]
    SnapshotDrift { field: &'static str },
    /// A snapshot digest does not bind its contents.
    #[error("discovery snapshot digest does not bind snapshot contents")]
    SnapshotDigestMismatch,
    /// A revalidated plan input moved; the plan revision is invalidated.
    #[error("plan input drift in {field}: build a new linked revision")]
    InputDrift { field: &'static str },
    /// A source revision moved past the retained producer commitment.
    #[error("stale source for owner {owner}: build a new linked revision")]
    StaleSource { owner: String },
    /// An owner receipt does not exactly match the plan digest.
    #[error("owner receipt does not exactly match the plan digest")]
    ReceiptMismatch,
    /// A plan digest does not bind the plan contents.
    #[error("plan digest does not bind plan contents")]
    DigestMismatch,
    /// A narrowing was attempted without an eligible selected check.
    #[error("deviation for {check} rejected: only a selected check may narrow with evidence")]
    DeviationRejected { check: String },
    /// A consumer refused a plan whose completeness is incomplete; the named
    /// regions are the plan's own gaps.
    #[error("plan is incomplete in {} named region(s): build a complete or explicitly permitted revision", regions.len())]
    IncompletePlan { regions: Vec<String> },
    /// A consumer is not admitted for the broader tier the plan permits.
    #[error("resolver is not admitted for the broader tier {tier}")]
    UnpermittedTier { tier: String },
    /// Required checks stay mandatory-but-deferred and were not dropped.
    #[error("plan retains mandatory-but-deferred required check(s): {}", checks.join(", "))]
    DeferredRequiredCheck { checks: Vec<String> },
    /// A considered check has no settled disposition.
    #[error("plan retains a pending check with no settled disposition")]
    PendingCheck,
    /// An affected node's coverage is not established or explicitly waived.
    #[error("unknown verifier coverage for affected node {node:?}")]
    UnknownCoverage { node: Option<String> },
    /// The plan could not be canonicalized for its digest.
    #[error("plan canonicalization failed")]
    Canonicalization,
}

fn plan_text(value: &str, field: &'static str) -> Result<(), PlanError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(PlanError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn plan_digest(value: &str, field: &'static str) -> Result<(), PlanError> {
    digest(value, field).map_err(|_| PlanError::InvalidDigest { field })
}

fn validate_tier(tier: &str) -> Result<(), PlanError> {
    if ADMITTED_BROADER_TIERS.contains(&tier) {
        Ok(())
    } else {
        Err(PlanError::InvalidTier {
            tier: tier.to_owned(),
        })
    }
}

/// Exact plan inputs: product/scope, base/candidate/diff and checkout
/// identity, target/features, lock/toolchain/config, and selector/profile
/// revisions.  Any movement in these fields invalidates the plan revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlanIdentity {
    pub product: String,
    pub work_scope: String,
    pub base_revision: String,
    pub candidate_revision: String,
    pub diff_digest: String,
    pub checkout_identity: String,
    pub target: String,
    pub features: Vec<String>,
    pub lock_digest: String,
    pub toolchain: String,
    pub config_digest: String,
    pub selector_revision: String,
    pub profile_revision: String,
}

impl PlanIdentity {
    pub fn validate(&self) -> Result<(), PlanError> {
        for (value, field) in [
            (&self.product, "identity.product"),
            (&self.work_scope, "identity.work_scope"),
            (&self.base_revision, "identity.base_revision"),
            (&self.candidate_revision, "identity.candidate_revision"),
            (&self.checkout_identity, "identity.checkout_identity"),
            (&self.target, "identity.target"),
            (&self.toolchain, "identity.toolchain"),
            (&self.selector_revision, "identity.selector_revision"),
            (&self.profile_revision, "identity.profile_revision"),
        ] {
            plan_text(value, field)?;
        }
        for (value, field) in [
            (&self.diff_digest, "identity.diff_digest"),
            (&self.lock_digest, "identity.lock_digest"),
            (&self.config_digest, "identity.config_digest"),
        ] {
            plan_digest(value, field)?;
        }
        for feature in &self.features {
            plan_text(feature, "identity.features")?;
        }
        Ok(())
    }
}

/// Disposition of one considered check.  `Omitted` always carries its exact
/// reason; silence is never a disposition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum CheckDisposition {
    Selected,
    Omitted,
    Pending,
    Deferred,
}

/// One considered profile/cell/test/verifier with its exact reason and
/// compact causal path.  The full considered set is retained: selected,
/// omitted, pending, and deferred entries alike.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlannedCheck {
    pub check_id: String,
    pub kind: String,
    pub disposition: CheckDisposition,
    pub reason: String,
    pub causal_path: Vec<String>,
}

impl PlannedCheck {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.check_id, "check.id")?;
        plan_text(&self.kind, "check.kind")?;
        plan_text(&self.reason, "check.reason")?;
        for node in &self.causal_path {
            plan_text(node, "check.causal_path")?;
        }
        Ok(())
    }
}

/// One explicitly named incomplete region: stale graph, missing owner,
/// unsupported condition, exhausted traversal, incomplete inventory, or
/// exhausted budget.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlanGap {
    pub region: String,
    pub reason: String,
}

impl PlanGap {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.region, "gap.region")?;
        plan_text(&self.reason, "gap.reason")
    }
}

/// Plan completeness.  There is no automatic full-workspace success and no
/// empty-success fallback: doubt becomes [`PlanCompleteness::Incomplete`]
/// naming the region, or an explicitly permitted bounded broader tier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum PlanCompleteness {
    Complete,
    Incomplete {
        gaps: Vec<PlanGap>,
    },
    /// Bounded broader tier permitted for this plan.  A wider tier never
    /// upgrades fidelity or proof level; that boundary travels in `reason`.
    BroaderTier {
        tier: String,
        reason: String,
        gaps: Vec<PlanGap>,
    },
}

impl PlanCompleteness {
    pub fn validate(&self) -> Result<(), PlanError> {
        match self {
            Self::Complete => Ok(()),
            Self::Incomplete { gaps } => {
                if gaps.is_empty() {
                    return Err(PlanError::InvalidText {
                        field: "completeness.gaps",
                    });
                }
                for gap in gaps {
                    gap.validate()?;
                }
                Ok(())
            }
            Self::BroaderTier { tier, reason, gaps } => {
                validate_tier(tier)?;
                plan_text(reason, "completeness.reason")?;
                for gap in gaps {
                    gap.validate()?;
                }
                Ok(())
            }
        }
    }
}

/// Pre-run measurement status.  Execution/reference sets, failure recall,
/// and execution cost do not exist at planning time.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum MeasurementStatus {
    Pending,
    Unknown,
    NotApplicable,
}

/// Planned selection quality slots.  Always [`MeasurementStatus::Pending`]
/// before any run; measured values arrive only through a linked
/// [`PlanEvaluation`] and never rewrite the selection.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlanQuality {
    pub failure_recall: MeasurementStatus,
    pub selection_rate: MeasurementStatus,
    pub execution_cost: MeasurementStatus,
}

impl PlanQuality {
    /// Pre-run quality: every measurement pending, never zero or perfect.
    pub fn pre_run() -> Self {
        Self {
            failure_recall: MeasurementStatus::Pending,
            selection_rate: MeasurementStatus::Pending,
            execution_cost: MeasurementStatus::Pending,
        }
    }
}

/// One discovered test with stable package/binary/test identities plus the
/// non-discoverable policy overlay (resource classes, serial group,
/// acceptance relation).  Joins use exact identity only: no name-substring
/// matching and no one-test-per-file assumption.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DiscoveredTestEntry {
    pub package: String,
    pub binary: String,
    pub test_id: String,
    pub resource_classes: Vec<String>,
    pub serial_group: Option<String>,
    pub acceptance: Option<String>,
}

impl DiscoveredTestEntry {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.package, "snapshot.package")?;
        plan_text(&self.binary, "snapshot.binary")?;
        plan_text(&self.test_id, "snapshot.test_id")?;
        for class in &self.resource_classes {
            plan_text(class, "snapshot.resource_class")?;
        }
        if let Some(group) = &self.serial_group {
            plan_text(group, "snapshot.serial_group")?;
        }
        if let Some(acceptance) = &self.acceptance {
            plan_text(acceptance, "snapshot.acceptance")?;
        }
        Ok(())
    }

    /// Stable identity triple used for exact joins.
    pub fn identity_key(&self) -> (String, String, String) {
        (
            self.package.clone(),
            self.binary.clone(),
            self.test_id.clone(),
        )
    }
}

/// Normalized discovery snapshot: the small agreed interface consumed from
/// the discovery producer under the same candidate/target/features.
/// Incomplete inventory is never known-empty.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DiscoveredTestSnapshot {
    pub snapshot_producer: String,
    pub snapshot_revision: String,
    pub candidate_revision: String,
    pub target: String,
    pub features: Vec<String>,
    pub inventory_complete: bool,
    pub entries: Vec<DiscoveredTestEntry>,
    pub snapshot_digest: String,
}

impl DiscoveredTestSnapshot {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.snapshot_producer, "snapshot.producer")?;
        plan_text(&self.snapshot_revision, "snapshot.revision")?;
        plan_text(&self.candidate_revision, "snapshot.candidate")?;
        plan_text(&self.target, "snapshot.target")?;
        for feature in &self.features {
            plan_text(feature, "snapshot.features")?;
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !seen.insert(entry.identity_key()) {
                return Err(PlanError::DuplicateEntry {
                    entry: render_test_identity(&entry.package, &entry.binary, &entry.test_id),
                });
            }
        }
        plan_digest(&self.snapshot_digest, "snapshot.digest")?;
        if snapshot_digest_of(self)? != self.snapshot_digest {
            return Err(PlanError::SnapshotDigestMismatch);
        }
        Ok(())
    }
}

fn snapshot_digest_of(snapshot: &DiscoveredTestSnapshot) -> Result<String, PlanError> {
    canonical(&(
        &snapshot.snapshot_producer,
        &snapshot.snapshot_revision,
        &snapshot.candidate_revision,
        &snapshot.target,
        &snapshot.features,
        snapshot.inventory_complete,
        &snapshot.entries,
    ))
    .map_err(|_| PlanError::Canonicalization)
}

/// Renders the agreed stable test identity shared with the discovery
/// producer: `package/binary/test_id`.  Cargo package/binary names and Rust
/// test paths never contain `/`, so the rendering is unambiguous and joins
/// stay exact, never substring-based.
pub fn render_test_identity(package: &str, binary: &str, test_id: &str) -> String {
    format!("{package}/{binary}/{test_id}")
}

/// Splits an agreed test identity back into its triple.  Returns `None`
/// when the id is not a test identity (profiles, cells, plain verifiers),
/// which simply do not participate in the discovery join.
pub fn parse_test_identity(check_id: &str) -> Option<(String, String, String)> {
    let mut parts = check_id.split('/');
    let package = parts.next()?;
    let binary = parts.next()?;
    let test_id = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if package.is_empty() || binary.is_empty() || test_id.is_empty() {
        return None;
    }
    Some((package.to_owned(), binary.to_owned(), test_id.to_owned()))
}

/// Frozen discovery join: the plan binds the snapshot digest, never a
/// mutable live inventory.  Relevant input movement creates a new linked
/// revision instead of mixing results under the original commitment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SnapshotBinding {
    pub snapshot_producer: String,
    pub snapshot_revision: String,
    pub snapshot_digest: String,
    pub entry_count: usize,
    pub inventory_complete: bool,
}

impl SnapshotBinding {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.snapshot_producer, "binding.producer")?;
        plan_text(&self.snapshot_revision, "binding.revision")?;
        plan_digest(&self.snapshot_digest, "binding.digest")
    }
}

impl DiscoveredTestSnapshot {
    /// The frozen discovery join this normalized snapshot represents.  The
    /// snapshot validates its own digest first, so a binding is never a
    /// caller-asserted identity: the digest covers the normalized entries,
    /// and therefore every stable `package/binary/test_id` identity in them.
    pub fn binding(&self) -> Result<SnapshotBinding, PlanError> {
        self.validate()?;
        Ok(SnapshotBinding {
            snapshot_producer: self.snapshot_producer.clone(),
            snapshot_revision: self.snapshot_revision.clone(),
            snapshot_digest: self.snapshot_digest.clone(),
            entry_count: self.entries.len(),
            inventory_complete: self.inventory_complete,
        })
    }
}

/// One frozen join of actual test discovery into a plan: the normalized
/// discovery snapshot identified under the SAME candidate, target and
/// feature set, with its stable package/binary/test identities bound by the
/// snapshot digest and its non-discoverable policy overlay (resource
/// classes, serial group, acceptance relation) retained in the snapshot.
///
/// The coordinates are the discovery side of the comparison, never an
/// assumption that both sides agree: a plan's coordinates come from its
/// [`PlanIdentity`], an observation's from the snapshot itself, and the join
/// compares them by value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DiscoveryJoin {
    pub candidate_revision: String,
    pub target: String,
    pub features: Vec<String>,
    pub binding: SnapshotBinding,
}

impl DiscoveryJoin {
    /// The join one normalized discovery snapshot represents.  The snapshot
    /// is validated (shape, unique stable identities, self-binding digest)
    /// before its identity is quoted.
    pub fn of(snapshot: &DiscoveredTestSnapshot) -> Result<Self, PlanError> {
        Ok(Self {
            candidate_revision: snapshot.candidate_revision.clone(),
            target: snapshot.target.clone(),
            features: snapshot.features.clone(),
            binding: snapshot.binding()?,
        })
    }

    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.candidate_revision, "join.candidate_revision")?;
        plan_text(&self.target, "join.target")?;
        for feature in &self.features {
            plan_text(feature, "join.features")?;
        }
        self.binding.validate()
    }
}

/// Widening-only hint from historical/co-change/code-intelligence evidence.
/// A hint may add a selected check; it never modifies or cancels one.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct HeuristicHint {
    pub check_id: String,
    pub kind: String,
    pub reason: String,
}

/// Evidence-backed narrowing of one selected check.  Widening needs no
/// deviation; narrowing requires the existing scoped evidence/deviation
/// owner and retains the original obligation in the resulting reason.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlanDeviation {
    pub check_id: String,
    pub evidence_owner: String,
    pub evidence: String,
}

/// Required check that exceeded budget: mandatory-but-deferred, never
/// dropped and never reclassified as irrelevant.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DeferredCheck {
    pub check_id: String,
    pub kind: String,
    pub reason: String,
}

impl DeferredCheck {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.check_id, "deferred.id")?;
        plan_text(&self.kind, "deferred.kind")?;
        plan_text(&self.reason, "deferred.reason")
    }
}

/// Inputs to one reproducible planning operation.  The planner consumes
/// supplied observations only; it runs no scanner, shell, or discovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanRequest {
    pub plan_id: String,
    pub plan_revision: u64,
    #[serde(default)]
    pub supersedes: Option<String>,
    pub identity: PlanIdentity,
    pub change: ChangeSet,
    /// Explicitly permitted bounded broader tier (`T0..=T4`).  Without it a
    /// broader requirement leaves the plan incomplete.
    #[serde(default)]
    pub permitted_broader_tier: Option<String>,
    /// Consumer-closure traversal bound; defaults to [`MAX_TRAVERSAL_NODES`].
    #[serde(default)]
    pub traversal_bound: Option<usize>,
    /// Maximum retained selected checks; excess stays mandatory-but-deferred.
    #[serde(default)]
    pub budget_max_checks: Option<usize>,
    /// Frozen discovery snapshot joined under the same candidate/target/features.
    #[serde(default)]
    pub snapshot: Option<DiscoveredTestSnapshot>,
    /// Widening-only heuristic hints.
    #[serde(default)]
    pub heuristic_widening: Vec<HeuristicHint>,
    /// Evidence-backed narrowings.
    #[serde(default)]
    pub deviations: Vec<PlanDeviation>,
    /// Currently required source revisions, verified against the retained
    /// producer commitments (never trusted from caller strings alone).
    #[serde(default)]
    pub expected_source: Vec<SourceCommitment>,
}

/// Versioned stored plan: reproducible conservative selection from one
/// [`BuildTestGraph`] revision.  The plan authorizes no process and decides
/// no completion; a runner/resolver adapter consumes it through
/// [`PlanConsumer`] and never duplicates [`BuildTestGraph::impact`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChangeImpactPlan {
    pub plan_version: String,
    pub plan_id: String,
    pub plan_revision: u64,
    #[serde(default)]
    pub supersedes: Option<String>,
    pub identity: PlanIdentity,
    /// Producer commitments retained from the source graph at plan time.
    pub source_commitments: BTreeMap<String, SourceCommitment>,
    /// Compiled source graph revision this plan was derived from.
    pub graph_revision: String,
    /// The conservative directive this plan was built from.
    pub directive: ChangeImpactDirective,
    /// Full considered set: selected, omitted, pending, deferred.
    pub checks: Vec<PlannedCheck>,
    #[serde(default)]
    pub snapshot_binding: Option<SnapshotBinding>,
    pub completeness: PlanCompleteness,
    #[serde(default)]
    pub deferred: Vec<DeferredCheck>,
    pub quality: PlanQuality,
    /// Digest binding every field above; verified on readback and replay.
    pub plan_digest: String,
}

impl ChangeImpactPlan {
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.plan_version != CHANGE_IMPACT_PLAN_VERSION {
            return Err(PlanError::InvalidText {
                field: "plan.version",
            });
        }
        plan_text(&self.plan_id, "plan.id")?;
        if self.plan_revision == 0 {
            return Err(PlanError::InvalidLimit {
                field: "plan.revision",
            });
        }
        if let Some(prior) = &self.supersedes {
            plan_digest(prior, "plan.supersedes")?;
        }
        self.identity.validate()?;
        for commitment in self.source_commitments.values() {
            commitment.validate()?;
        }
        plan_text(&self.graph_revision, "plan.graph_revision")?;
        for check in &self.checks {
            check.validate()?;
        }
        if let Some(binding) = &self.snapshot_binding {
            binding.validate()?;
        }
        self.completeness.validate()?;
        for deferred in &self.deferred {
            deferred.validate()?;
        }
        plan_digest(&self.plan_digest, "plan.digest")?;
        if plan_digest_of(self)? != self.plan_digest {
            return Err(PlanError::DigestMismatch);
        }
        Ok(())
    }

    /// The frozen discovery join this plan retains, or `None` when it was
    /// built without a discovery snapshot.  The coordinates are the plan's
    /// own identity; `revalidate_plan` compares them by value against the
    /// coordinates of the snapshot currently observed.
    pub fn discovery_join(&self) -> Option<DiscoveryJoin> {
        self.snapshot_binding.as_ref().map(|binding| DiscoveryJoin {
            candidate_revision: self.identity.candidate_revision.clone(),
            target: self.identity.target.clone(),
            features: self.identity.features.clone(),
            binding: binding.clone(),
        })
    }

    /// Stable reference to this stored plan, emitted by consumers (for
    /// example in a `TestSelectionReceipt`) instead of the full contents.
    /// The reference carries the frozen discovery join, so a downstream
    /// receipt states which normalized discovery snapshot the plan was
    /// joined against under which candidate, target and features.
    pub fn reference(&self) -> PlanReference {
        PlanReference {
            plan_digest: self.plan_digest.clone(),
            plan_revision: self.plan_revision,
            discovery: self.discovery_join(),
        }
    }
}

fn plan_digest_of(plan: &ChangeImpactPlan) -> Result<String, PlanError> {
    let mut value = plan.clone();
    value.plan_digest.clear();
    canonical(&value).map_err(|_| PlanError::Canonicalization)
}

/// Builds a reproducible conservative [`ChangeImpactPlan`] from one compiled
/// graph and the exact supplied inputs.  Same graph plus same request always
/// yields the same digest; any input movement invalidates the revision.
pub fn plan_impact(
    graph: &BuildTestGraph,
    request: &PlanRequest,
) -> Result<ChangeImpactPlan, PlanError> {
    validate_request(request)?;
    let bound = request.traversal_bound.unwrap_or(MAX_TRAVERSAL_NODES);
    let directive = graph.impact_bounded(&request.change, bound);
    let mut gaps: Vec<PlanGap> = Vec::new();
    collect_freshness_gaps(graph, request, &mut gaps);
    collect_directive_gaps(&directive, &mut gaps);
    let mut checks = build_considered_checks(graph, &directive);
    apply_deviations(&mut checks, request)?;
    apply_heuristic_widening(&mut checks, request);
    let snapshot_binding = join_snapshot(&mut checks, &mut gaps, request)?;
    let deferred = apply_budget(&mut checks, &mut gaps, request);
    let completeness = resolve_completeness(&directive, &gaps, request)?;
    let mut plan = ChangeImpactPlan {
        plan_version: CHANGE_IMPACT_PLAN_VERSION.to_owned(),
        plan_id: request.plan_id.clone(),
        plan_revision: request.plan_revision,
        supersedes: request.supersedes.clone(),
        identity: request.identity.clone(),
        source_commitments: graph.source_commitments.clone(),
        graph_revision: graph.revision.clone(),
        directive,
        checks,
        snapshot_binding,
        completeness,
        deferred,
        quality: PlanQuality::pre_run(),
        plan_digest: String::new(),
    };
    plan.plan_digest = plan_digest_of(&plan)?;
    plan.validate()?;
    Ok(plan)
}

fn validate_request(request: &PlanRequest) -> Result<(), PlanError> {
    plan_text(&request.plan_id, "request.plan_id")?;
    if request.plan_revision == 0 {
        return Err(PlanError::InvalidLimit {
            field: "request.plan_revision",
        });
    }
    if let Some(prior) = &request.supersedes {
        plan_digest(prior, "request.supersedes")?;
    }
    request.identity.validate()?;
    for node in &request.change.changed_nodes {
        plan_text(node, "change.changed_node")?;
    }
    for observation in &request.change.changed_paths {
        observation.validate()?;
    }
    for condition in &request.change.unsupported_conditions {
        plan_text(condition, "change.unsupported_condition")?;
    }
    if request.traversal_bound == Some(0) {
        return Err(PlanError::InvalidLimit {
            field: "request.traversal_bound",
        });
    }
    if request.budget_max_checks == Some(0) {
        return Err(PlanError::InvalidLimit {
            field: "request.budget_max_checks",
        });
    }
    if let Some(tier) = &request.permitted_broader_tier {
        validate_tier(tier)?;
    }
    for commitment in &request.expected_source {
        commitment.validate()?;
    }
    for hint in &request.heuristic_widening {
        plan_text(&hint.check_id, "hint.check_id")?;
        plan_text(&hint.kind, "hint.kind")?;
        plan_text(&hint.reason, "hint.reason")?;
    }
    for deviation in &request.deviations {
        plan_text(&deviation.check_id, "deviation.check_id")?;
        plan_text(&deviation.evidence_owner, "deviation.evidence_owner")?;
        plan_text(&deviation.evidence, "deviation.evidence")?;
    }
    if let Some(snapshot) = &request.snapshot {
        snapshot.validate()?;
        if snapshot.candidate_revision != request.identity.candidate_revision {
            return Err(PlanError::SnapshotDrift {
                field: "candidate_revision",
            });
        }
        if snapshot.target != request.identity.target {
            return Err(PlanError::SnapshotDrift { field: "target" });
        }
        if snapshot.features != request.identity.features {
            return Err(PlanError::SnapshotDrift { field: "features" });
        }
    }
    Ok(())
}

/// Verifies required source revisions against the retained producer
/// commitments (never caller strings alone) and records staleness as gaps.
/// Stale graphs keep their known obligations; they never justify narrower
/// coverage.
fn collect_freshness_gaps(graph: &BuildTestGraph, request: &PlanRequest, gaps: &mut Vec<PlanGap>) {
    push_consistency_gap(graph, BUILD_GRAPH_OWNER, &graph.build.revision, gaps);
    push_consistency_gap(
        graph,
        VERIFIERS_GRAPH_OWNER,
        &graph.verifiers.revision,
        gaps,
    );
    for expected in &request.expected_source {
        match graph.source_commitments.get(&expected.owner) {
            None => gaps.push(PlanGap {
                region: format!("source-commitment:{}", expected.owner),
                reason: "required source has no retained producer commitment".to_owned(),
            }),
            Some(retained) => {
                if retained.revision != expected.revision {
                    gaps.push(PlanGap {
                        region: format!("source-commitment:{}", expected.owner),
                        reason: format!(
                            "stale source: retained {} but {} required",
                            retained.revision, expected.revision
                        ),
                    });
                }
            }
        }
    }
}

fn push_consistency_gap(
    graph: &BuildTestGraph,
    owner: &str,
    revision: &str,
    gaps: &mut Vec<PlanGap>,
) {
    if let Some(retained) = graph.source_commitments.get(owner)
        && retained.revision != revision
    {
        gaps.push(PlanGap {
            region: format!("source-commitment:{owner}"),
            reason: format!(
                "compiled graph revision {revision} disagrees with retained producer commitment {}",
                retained.revision
            ),
        });
    }
}

/// Records directive-level doubt (unresolved frontier, unknown ownership,
/// unsupported conditions) as named plan gaps.
fn collect_directive_gaps(directive: &ChangeImpactDirective, gaps: &mut Vec<PlanGap>) {
    if !directive.unresolved_frontier.is_empty() {
        let mut frontier: Vec<&str> = directive
            .unresolved_frontier
            .iter()
            .map(String::as_str)
            .collect();
        frontier.sort_unstable();
        gaps.push(PlanGap {
            region: "traversal-frontier".to_owned(),
            reason: format!(
                "traversal bound exhausted; {} unresolved consumers retained: {}",
                frontier.len(),
                frontier.join(", ")
            ),
        });
    }
    for entry in &directive.missing_tests {
        if let Some(path) = entry.strip_prefix("unknown-owner:") {
            gaps.push(PlanGap {
                region: format!("ownership:{path}"),
                reason: "unknown ownership stays a gap; no impact inferred".to_owned(),
            });
        } else if let Some(condition) = entry.strip_prefix("unsupported-condition:") {
            gaps.push(PlanGap {
                region: format!("condition:{condition}"),
                reason: "unsupported condition could not be evaluated".to_owned(),
            });
        }
    }
}

/// Builds the considered check set from the conservative directive: exact
/// verifier selections with dependency reasons, pending entries for every
/// uncovered region, and selected runtime-bundle proofs.  Deterministic order.
fn build_considered_checks(
    graph: &BuildTestGraph,
    directive: &ChangeImpactDirective,
) -> Vec<PlannedCheck> {
    let mut checks = Vec::new();
    for verifier in &directive.impacted_verifiers_exact {
        checks.push(PlannedCheck {
            check_id: verifier.clone(),
            kind: "verifier".to_owned(),
            disposition: CheckDisposition::Selected,
            reason: exact_selection_reason(graph, directive, verifier),
            causal_path: verifier_causal_path(graph, directive, verifier),
        });
    }
    for (node, coverage) in &directive.node_coverage {
        if coverage.is_established() {
            continue;
        }
        checks.push(PlannedCheck {
            check_id: format!("node-proof:{node}"),
            kind: "node-proof".to_owned(),
            disposition: CheckDisposition::Pending,
            reason: coverage_gap_reason(node, coverage),
            causal_path: directive
                .causal_paths
                .get(node)
                .cloned()
                .unwrap_or_default(),
        });
    }
    for bundle_id in touched_runtime_bundles(graph, directive) {
        checks.push(PlannedCheck {
            check_id: format!("runtime-bundle:{bundle_id}"),
            kind: "runtime-bundle".to_owned(),
            disposition: CheckDisposition::Selected,
            reason: format!(
                "affected node shares runtime bundle {bundle_id}; runtime proof required"
            ),
            causal_path: Vec::new(),
        });
    }
    checks
}

/// Exact dependency reason for one selected verifier: every complete exact
/// edge (property, scope, affected node) that justifies it, in stable order.
fn exact_selection_reason(
    graph: &BuildTestGraph,
    directive: &ChangeImpactDirective,
    verifier: &str,
) -> String {
    let mut justifications: BTreeSet<String> = BTreeSet::new();
    for edge in &graph.verifiers.edges {
        if edge.verifier == verifier
            && directive.behavioral_drift_candidates.contains(&edge.target)
            && edge.exact
            && edge.coverage == Coverage::Complete
        {
            justifications.insert(format!(
                "exact {} scope {} on affected node {}",
                edge.property, edge.scope, edge.target
            ));
        }
    }
    let joined = justifications.into_iter().collect::<Vec<_>>().join("; ");
    format!("exact dependency evidence requires {verifier}: {joined}")
}

/// Causal path of the first (sorted) justifying target of one selection.
fn verifier_causal_path(
    graph: &BuildTestGraph,
    directive: &ChangeImpactDirective,
    verifier: &str,
) -> Vec<String> {
    let mut targets: BTreeSet<&str> = BTreeSet::new();
    for edge in &graph.verifiers.edges {
        if edge.verifier == verifier
            && directive.behavioral_drift_candidates.contains(&edge.target)
            && edge.exact
            && edge.coverage == Coverage::Complete
        {
            targets.insert(edge.target.as_str());
        }
    }
    targets
        .into_iter()
        .find_map(|target| directive.causal_paths.get(target))
        .cloned()
        .unwrap_or_default()
}

fn coverage_gap_reason(node: &str, coverage: &NodeCoverage) -> String {
    match coverage {
        NodeCoverage::Complete => {
            format!("complete applicable verifier coverage for affected node {node}")
        }
        NodeCoverage::NotApplicable { scope, reason } => {
            format!("owner-declared non-applicability for {node} (scope {scope}): {reason}")
        }
        NodeCoverage::Partial => format!(
            "partial verifier coverage for affected node {node}; missing proof stays pending"
        ),
        NodeCoverage::Missing => format!(
            "no verifier edge for affected node {node}; absence of an edge never proves no impact"
        ),
        NodeCoverage::Unknown => {
            format!("unknown ownership or unresolved reachability for affected node {node}")
        }
    }
}

fn touched_runtime_bundles(
    graph: &BuildTestGraph,
    directive: &ChangeImpactDirective,
) -> BTreeSet<String> {
    graph
        .runtime_bundles
        .iter()
        .filter(|(_, bundle)| {
            bundle.crates.iter().any(|member| {
                directive
                    .behavioral_drift_candidates
                    .contains(&member.package_id)
            })
        })
        .map(|(bundle_id, _)| bundle_id.clone())
        .collect()
}

/// Applies evidence-backed narrowings.  Only a `Selected` check may narrow
/// to `Omitted`, and the original obligation is retained in the reason.
fn apply_deviations(checks: &mut [PlannedCheck], request: &PlanRequest) -> Result<(), PlanError> {
    for deviation in &request.deviations {
        let mut narrowed = false;
        for check in checks.iter_mut() {
            if check.check_id == deviation.check_id {
                if check.disposition != CheckDisposition::Selected || narrowed {
                    return Err(PlanError::DeviationRejected {
                        check: deviation.check_id.clone(),
                    });
                }
                let original = std::mem::take(&mut check.reason);
                check.disposition = CheckDisposition::Omitted;
                check.reason = format!(
                    "narrowed from Selected by {} with evidence {}; original obligation retained: {original}",
                    deviation.evidence_owner, deviation.evidence
                );
                narrowed = true;
            }
        }
        if !narrowed {
            return Err(PlanError::DeviationRejected {
                check: deviation.check_id.clone(),
            });
        }
    }
    Ok(())
}

/// Applies widening-only hints.  A hint adds a selected check when its id is
/// new; it never modifies or cancels an existing disposition.
fn apply_heuristic_widening(checks: &mut Vec<PlannedCheck>, request: &PlanRequest) {
    for hint in &request.heuristic_widening {
        if checks.iter().any(|check| check.check_id == hint.check_id) {
            continue;
        }
        checks.push(PlannedCheck {
            check_id: hint.check_id.clone(),
            kind: hint.kind.clone(),
            disposition: CheckDisposition::Selected,
            reason: format!(
                "heuristic widening (never cancels exact requirements): {}",
                hint.reason
            ),
            causal_path: Vec::new(),
        });
    }
}

/// Joins the frozen discovery snapshot by exact stable identity.  Test-kind
/// selections absent from a complete inventory become pending (never
/// silently omitted); unselected inventory entries become one explained
/// summary omission; an incomplete inventory becomes a plan gap.
fn join_snapshot(
    checks: &mut Vec<PlannedCheck>,
    gaps: &mut Vec<PlanGap>,
    request: &PlanRequest,
) -> Result<Option<SnapshotBinding>, PlanError> {
    let Some(snapshot) = &request.snapshot else {
        return Ok(None);
    };
    let mut inventory: BTreeMap<(String, String, String), &DiscoveredTestEntry> = BTreeMap::new();
    for entry in &snapshot.entries {
        inventory.insert(entry.identity_key(), entry);
    }
    let mut matched: BTreeSet<(String, String, String)> = BTreeSet::new();
    for check in checks.iter_mut() {
        let Some(triple) = parse_test_identity(&check.check_id) else {
            continue;
        };
        match inventory.get(&triple) {
            Some(entry) => {
                matched.insert(triple);
                if matches!(
                    check.disposition,
                    CheckDisposition::Selected | CheckDisposition::Pending
                ) {
                    let original = std::mem::take(&mut check.reason);
                    check.reason = format!(
                        "{original}; frozen discovery {} confirms {}/{} with resource overlay [{}]",
                        snapshot.snapshot_digest,
                        entry.package,
                        entry.binary,
                        entry.resource_classes.join(", ")
                    );
                }
            }
            None => {
                if check.kind == "test"
                    && check.disposition == CheckDisposition::Selected
                    && snapshot.inventory_complete
                {
                    check.disposition = CheckDisposition::Pending;
                    let original = std::mem::take(&mut check.reason);
                    check.reason = format!(
                        "{original}; absent from frozen complete discovery inventory {}",
                        snapshot.snapshot_digest
                    );
                }
            }
        }
    }
    let unselected = snapshot.entries.len().saturating_sub(matched.len());
    if unselected > 0 {
        checks.push(PlannedCheck {
            check_id: "snapshot-unselected-tests".to_owned(),
            kind: "test-set".to_owned(),
            disposition: CheckDisposition::Omitted,
            reason: format!(
                "{} of {} frozen discovery entries (inventory {}) matched no exact impact selection and are omitted with this reason; the producer-retained snapshot lists every entry",
                unselected,
                snapshot.entries.len(),
                snapshot.snapshot_digest
            ),
            causal_path: Vec::new(),
        });
    }
    if !snapshot.inventory_complete {
        gaps.push(PlanGap {
            region: "discovery-inventory".to_owned(),
            reason: format!(
                "discovery inventory {} is explicitly incomplete; unselected entries are not known-empty",
                snapshot.snapshot_digest
            ),
        });
    }
    Ok(Some(snapshot.binding()?))
}

/// Applies the selection budget.  Exact selections are built before
/// heuristic widenings, so deferral keeps dependency evidence first.
/// Deferred checks stay mandatory; the budget gap keeps the plan honest.
fn apply_budget(
    checks: &mut [PlannedCheck],
    gaps: &mut Vec<PlanGap>,
    request: &PlanRequest,
) -> Vec<DeferredCheck> {
    let Some(budget) = request.budget_max_checks else {
        return Vec::new();
    };
    let mut retained = 0_usize;
    let mut deferred = Vec::new();
    for check in checks.iter_mut() {
        if check.disposition != CheckDisposition::Selected {
            continue;
        }
        if retained < budget {
            retained += 1;
            continue;
        }
        check.disposition = CheckDisposition::Deferred;
        let original = std::mem::take(&mut check.reason);
        check.reason = format!("{original}; over budget: mandatory-but-deferred");
        deferred.push(DeferredCheck {
            check_id: check.check_id.clone(),
            kind: check.kind.clone(),
            reason: check.reason.clone(),
        });
    }
    if !deferred.is_empty() {
        gaps.push(PlanGap {
            region: "execution-budget".to_owned(),
            reason: format!(
                "{} required checks exceed the budget of {budget} and stay mandatory-but-deferred",
                deferred.len()
            ),
        });
    }
    deferred
}

/// Resolves plan completeness.  Any gap, or any broader requirement without
/// an explicitly permitted tier, leaves the plan incomplete and names the
/// region.  A permitted tier never upgrades fidelity or proof level.
fn resolve_completeness(
    directive: &ChangeImpactDirective,
    gaps: &[PlanGap],
    request: &PlanRequest,
) -> Result<PlanCompleteness, PlanError> {
    let mut gaps = gaps.to_vec();
    if directive.required_broader_profile {
        if let Some(tier) = &request.permitted_broader_tier {
            validate_tier(tier)?;
            return Ok(PlanCompleteness::BroaderTier {
                tier: tier.clone(),
                reason: format!(
                    "explicitly permitted bounded broader tier {tier}; wider tier never upgrades fidelity or proof level"
                ),
                gaps,
            });
        }
        gaps.push(PlanGap {
            region: "broader-profile".to_owned(),
            reason: "broader profile required but no bounded tier was explicitly permitted"
                .to_owned(),
        });
    }
    if gaps.is_empty() {
        Ok(PlanCompleteness::Complete)
    } else {
        Ok(PlanCompleteness::Incomplete { gaps })
    }
}

/// Actual outcome label for one executed check (`I18.3`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum OutcomeLabel {
    Pass,
    StableFailure,
    Flaky,
    Infrastructure,
    Parser,
    Unknown,
}

/// Observed execution evidence appended after runs.  The selection stays
/// untouched; evaluation links to the frozen plan digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedExecution {
    pub evaluation_id: String,
    pub discovered: BTreeSet<String>,
    pub reference: BTreeSet<String>,
    pub executed: BTreeSet<String>,
    pub outcomes: BTreeMap<String, OutcomeLabel>,
    #[serde(default)]
    pub first_failure: Option<String>,
    #[serde(default)]
    pub retries: BTreeMap<String, u32>,
    pub comparator: String,
    pub sampling_policy: String,
}

impl ObservedExecution {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.evaluation_id, "observed.evaluation_id")?;
        plan_text(&self.comparator, "observed.comparator")?;
        plan_text(&self.sampling_policy, "observed.sampling_policy")?;
        for set in [&self.discovered, &self.reference, &self.executed] {
            for entry in set {
                plan_text(entry, "observed.set_entry")?;
            }
        }
        for check in self.outcomes.keys() {
            plan_text(check, "observed.outcome")?;
        }
        if let Some(first) = &self.first_failure {
            plan_text(first, "observed.first_failure")?;
        }
        for check in self.retries.keys() {
            plan_text(check, "observed.retry")?;
        }
        Ok(())
    }
}

/// Linked post-run evaluation of one stored plan.  Failure recall is
/// computed only from the observed applicable denominator: applicable
/// reference failures that were actually executed.  With no observed
/// applicable failure the recall stays unobserved — never zero, never
/// perfect.  Set agreement alone is not safety.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlanEvaluation {
    pub plan_digest: String,
    pub plan_revision: u64,
    pub evaluation_id: String,
    pub discovered: BTreeSet<String>,
    pub selected: BTreeSet<String>,
    pub reference: BTreeSet<String>,
    pub executed: BTreeSet<String>,
    pub outcomes: BTreeMap<String, OutcomeLabel>,
    #[serde(default)]
    pub first_failure: Option<String>,
    #[serde(default)]
    pub retries: BTreeMap<String, u32>,
    pub comparator: String,
    pub sampling_policy: String,
    #[serde(default)]
    pub failure_recall: Option<f64>,
    pub recall_denominator: u64,
    pub disagreement: String,
    #[serde(default)]
    pub uncertainty: Option<String>,
}

/// Appends a linked evaluation to a stored plan without rewriting its
/// selection.  Missing reference execution neither fabricates safety nor
/// prevents a useful explicitly limited evaluation.
pub fn evaluate_plan(
    plan: &ChangeImpactPlan,
    observed: &ObservedExecution,
) -> Result<PlanEvaluation, PlanError> {
    plan.validate()?;
    observed.validate()?;
    let selected: BTreeSet<String> = plan
        .checks
        .iter()
        .filter(|check| check.disposition == CheckDisposition::Selected)
        .map(|check| check.check_id.clone())
        .collect();
    let failed_observed: BTreeSet<&str> = observed
        .reference
        .iter()
        .filter(|check| observed.executed.contains(*check))
        .filter(|check| {
            observed
                .outcomes
                .get(*check)
                .is_some_and(|outcome| *outcome == OutcomeLabel::StableFailure)
        })
        .map(String::as_str)
        .collect();
    let denominator = u64::try_from(failed_observed.len()).unwrap_or(u64::MAX);
    let numerator = failed_observed
        .iter()
        .filter(|check| selected.contains(**check))
        .count();
    let failure_recall = if failed_observed.is_empty() {
        None
    } else {
        #[allow(clippy::cast_precision_loss)]
        let ratio = numerator as f64 / failed_observed.len() as f64;
        Some(ratio)
    };
    let uncertainty = if failure_recall.is_none() {
        Some("no observed applicable failures; recall unobserved".to_owned())
    } else {
        None
    };
    let selected_not_executed = selected.difference(&observed.executed).count();
    let executed_not_selected = observed.executed.difference(&selected).count();
    Ok(PlanEvaluation {
        plan_digest: plan.plan_digest.clone(),
        plan_revision: plan.plan_revision,
        evaluation_id: observed.evaluation_id.clone(),
        discovered: observed.discovered.clone(),
        selected,
        reference: observed.reference.clone(),
        executed: observed.executed.clone(),
        outcomes: observed.outcomes.clone(),
        first_failure: observed.first_failure.clone(),
        retries: observed.retries.clone(),
        comparator: observed.comparator.clone(),
        sampling_policy: observed.sampling_policy.clone(),
        failure_recall,
        recall_denominator: denominator,
        disagreement: format!(
            "selected-not-executed={selected_not_executed} executed-not-selected={executed_not_selected}"
        ),
        uncertainty,
    })
}

/// Stable reference to one stored plan revision, emitted by consumers in
/// place of the full contents.  It carries the plan's frozen
/// [`DiscoveryJoin`]: the normalized discovery snapshot under the same
/// candidate, target and features, verified against the frozen plan before
/// this reference was emitted.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PlanReference {
    pub plan_digest: String,
    pub plan_revision: u64,
    /// The frozen discovery join, or `None` when the plan was built without a
    /// discovery snapshot.  A plan that keeps no join must be dispatched
    /// with no observed snapshot; supplying one would mix results the plan
    /// never considered under its original commitment.
    #[serde(default)]
    pub discovery: Option<DiscoveryJoin>,
}

impl PlanReference {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_digest(&self.plan_digest, "reference.digest")?;
        if self.plan_revision == 0 {
            return Err(PlanError::InvalidLimit {
                field: "reference.revision",
            });
        }
        if let Some(join) = &self.discovery {
            join.validate()?;
        }
        Ok(())
    }
}

/// Exact owner receipt for one stored plan report.  The report is stored
/// only after this receipt matches the plan digest exactly.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OwnerReceipt {
    pub owner: String,
    pub op: String,
    pub content_digest: String,
}

impl OwnerReceipt {
    pub fn validate(&self) -> Result<(), PlanError> {
        plan_text(&self.owner, "receipt.owner")?;
        plan_text(&self.op, "receipt.op")?;
        plan_digest(&self.content_digest, "receipt.content_digest")
    }
}

/// Stored plan envelope: one validated plan plus its exact owner receipt
/// and links to preserved older plan revisions (linked, never overwritten).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StoredPlanEnvelope {
    pub plan: ChangeImpactPlan,
    pub receipt: OwnerReceipt,
    #[serde(default)]
    pub prior_plan_digests: Vec<String>,
}

impl StoredPlanEnvelope {
    pub fn validate(&self) -> Result<(), PlanError> {
        self.plan.validate()?;
        self.receipt.validate()?;
        if self.receipt.content_digest != self.plan.plan_digest {
            return Err(PlanError::ReceiptMismatch);
        }
        for prior in &self.prior_plan_digests {
            plan_digest(prior, "envelope.prior")?;
        }
        Ok(())
    }
}

/// Stores a plan report through the Governor evidence path: the plan must
/// validate and the owner receipt must match the plan digest exactly.
/// Failed publication returns an error and starts no build or test.
pub fn store_plan_report(
    plan: &ChangeImpactPlan,
    receipt: &OwnerReceipt,
    prior_plan_digests: &[String],
) -> Result<StoredPlanEnvelope, PlanError> {
    let envelope = StoredPlanEnvelope {
        plan: plan.clone(),
        receipt: receipt.clone(),
        prior_plan_digests: prior_plan_digests.to_vec(),
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Returns the original publication operation and content for a lost
/// acknowledgement.  A retry reuses the original op and content; it never
/// mints a new revision or mutates the stored plan.
pub fn retry_publication_content(envelope: &StoredPlanEnvelope) -> (&str, &str) {
    (
        envelope.receipt.op.as_str(),
        envelope.receipt.content_digest.as_str(),
    )
}

/// Revalidates a stored plan against the currently applicable inputs before
/// execution.  Candidate, target, feature, graph, discovery, or source
/// movement invalidates the revision: the caller must build a new linked
/// revision.
///
/// Every currently required source owner must carry the exact same owner,
/// revision, and content digest in the retained plan, in the current owner
/// observation, and in the current graph commitments.  Contradictory or
/// missing required evidence fails even when the graph revision string is
/// unchanged; owners outside the applicable set are not revalidated here
/// and explicit non-applicability declarations keep their existing meaning.
///
/// `discovery` is the normalized discovery snapshot currently observed at the
/// consume site.  When it is supplied, the plan's frozen [`DiscoveryJoin`] is
/// joined against it by value; when the plan retains a join it is required,
/// and when the plan retains none, no snapshot may be observed.
pub fn revalidate_plan(
    plan: &ChangeImpactPlan,
    graph: &BuildTestGraph,
    candidate_revision: &str,
    target: &str,
    features: &[String],
    expected_source: &[SourceCommitment],
    discovery: Option<&DiscoveredTestSnapshot>,
) -> Result<(), PlanError> {
    plan.validate()?;
    if candidate_revision != plan.identity.candidate_revision {
        return Err(PlanError::InputDrift {
            field: "candidate_revision",
        });
    }
    if target != plan.identity.target {
        return Err(PlanError::InputDrift { field: "target" });
    }
    if features != plan.identity.features.as_slice() {
        return Err(PlanError::InputDrift { field: "features" });
    }
    if graph.revision != plan.graph_revision {
        return Err(PlanError::InputDrift {
            field: "graph_revision",
        });
    }
    for expected in expected_source {
        expected.validate()?;
        let retained_matches =
            plan.source_commitments
                .get(&expected.owner)
                .is_some_and(|retained| {
                    retained.owner == expected.owner
                        && retained.revision == expected.revision
                        && retained.content_digest == expected.content_digest
                });
        let current_matches =
            graph
                .source_commitments
                .get(&expected.owner)
                .is_some_and(|current| {
                    current.owner == expected.owner
                        && current.revision == expected.revision
                        && current.content_digest == expected.content_digest
                });
        if !retained_matches || !current_matches {
            return Err(PlanError::StaleSource {
                owner: expected.owner.clone(),
            });
        }
    }
    join_discovery(plan, discovery)
}

/// Joins the actually discovered tests into a frozen plan (`I18.6` steps 3/4,
/// `I18.3`).
///
/// The plan side of the join is the plan's frozen [`DiscoveryJoin`], taken
/// from its retained [`SnapshotBinding`] and its own identity.  The observed
/// side is the normalized discovery snapshot the discovery producer reports
/// now; it validates its own digest first, so the join never trusts a
/// caller-asserted identity, and that digest covers the normalized entries —
/// every stable `package/binary/test_id` identity and the resource, serial
/// and acceptance overlay in them.
///
/// Comparison is by value against the frozen plan: movement in candidate,
/// target, features, snapshot producer, snapshot revision, snapshot digest,
/// entry count, or inventory completeness is refused with the crate's typed
/// drift refusal and requires a new linked plan revision, so results from a
/// moved inventory are never mixed under the original commitment.  A plan
/// that moved is refused by `plan.validate()` before this join is reached.
fn join_discovery(
    plan: &ChangeImpactPlan,
    observed: Option<&DiscoveredTestSnapshot>,
) -> Result<(), PlanError> {
    let frozen = plan.discovery_join();
    let Some(snapshot) = observed else {
        return if frozen.is_some() {
            Err(PlanError::InputDrift {
                field: "discovery_snapshot",
            })
        } else {
            Ok(())
        };
    };
    let observed_join = DiscoveryJoin::of(snapshot)?;
    let Some(frozen) = frozen else {
        return Err(PlanError::InputDrift {
            field: "discovery_snapshot",
        });
    };
    if observed_join == frozen {
        return Ok(());
    }
    if observed_join.candidate_revision != frozen.candidate_revision {
        return Err(PlanError::SnapshotDrift {
            field: "candidate_revision",
        });
    }
    if observed_join.target != frozen.target {
        return Err(PlanError::SnapshotDrift { field: "target" });
    }
    if observed_join.features != frozen.features {
        return Err(PlanError::SnapshotDrift { field: "features" });
    }
    if observed_join.binding.snapshot_producer != frozen.binding.snapshot_producer {
        return Err(PlanError::SnapshotDrift {
            field: "snapshot_producer",
        });
    }
    if observed_join.binding.snapshot_revision != frozen.binding.snapshot_revision {
        return Err(PlanError::SnapshotDrift {
            field: "snapshot_revision",
        });
    }
    if observed_join.binding.snapshot_digest != frozen.binding.snapshot_digest {
        return Err(PlanError::SnapshotDrift {
            field: "snapshot_digest",
        });
    }
    if observed_join.binding.entry_count != frozen.binding.entry_count {
        return Err(PlanError::SnapshotDrift {
            field: "entry_count",
        });
    }
    Err(PlanError::SnapshotDrift {
        field: "inventory_complete",
    })
}

/// Replays a stored plan for readback or escaped-regression analysis.
/// Replay validates the envelope binding and returns the plan reference;
/// it starts no build and no test.
pub fn replay_stored_plan(envelope: &StoredPlanEnvelope) -> Result<PlanReference, PlanError> {
    envelope.validate()?;
    Ok(envelope.plan.reference())
}

/// Runner/resolver adapter seam for stored plans.  The adapter consumes the
/// retained plan version, revalidates the applicable inputs before
/// execution, and emits the plan reference; it never duplicates
/// [`BuildTestGraph::impact`].  Consuming a plan authorizes no process and
/// decides no completion.
pub trait PlanConsumer {
    /// Consumes one stored plan envelope and returns its reference for
    /// downstream receipts.
    fn consume_stored_plan(&self, stored: &StoredPlanEnvelope) -> Result<PlanReference, PlanError>;
}
