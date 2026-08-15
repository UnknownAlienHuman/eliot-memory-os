//! The canonical BuildTestGraph projection.
//!
//! This crate owns neither Cargo's compiler graph nor verifier execution.  It
//! accepts immutable observations from those owners and compiles a conservative
//! planning projection.  In particular, absence and impact are never inferred
//! from a missing edge: callers receive an explicit unknown directive when the
//! input cannot establish coverage.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.instrument.build-test-graph";
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

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
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn canonical<T: Serialize>(value: &T) -> Result<String, GraphError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|_| GraphError::FingerprintOverflow)
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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ModuleTestCapsuleRevision {
    pub capsule_id: String,
    pub revision: String,
    pub selector: String,
    pub fixture_digest: String,
    pub oracle_digest: String,
    pub resource_classes: Vec<String>,
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
        digest(&self.oracle_digest, "oracle_digest")
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum BuildEdgeKind {
    Package,
    Target,
    Feature,
    Configuration,
    BuildScript,
    ProcMacro,
    Artifact,
    Runner,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Coverage {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct BuildExecutionEdge {
    pub from: String,
    pub to: String,
    pub kind: BuildEdgeKind,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct GraphInputs {
    pub build: BuildExecutionGraph,
    pub verifiers: VerifierCoverageGraph,
    pub contracts: Vec<PublicContractDigest>,
    pub capsules: Vec<ModuleTestCapsuleRevision>,
    pub runtime_bundles: Vec<RuntimeBundleIdentity>,
    pub failures: Vec<FailureRecord>,
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
        for edge in &inputs.build.edges {
            if !inputs.build.nodes.contains(&edge.from) || !inputs.build.nodes.contains(&edge.to) {
                return Err(GraphError::Inconsistent(format!(
                    "build edge {} -> {} has an unknown endpoint",
                    edge.from, edge.to
                )));
            }
        }
        for edge in &inputs.verifiers.edges {
            if !inputs.verifiers.verifiers.contains(&edge.verifier)
                || !inputs.verifiers.targets.contains(&edge.target)
            {
                return Err(GraphError::Inconsistent(format!(
                    "coverage edge {} -> {} has an unknown endpoint",
                    edge.verifier, edge.target
                )));
            }
        }
        let mut contracts = BTreeMap::new();
        for contract in inputs.contracts {
            contract.validate()?;
            contracts.insert(contract.crate_identity.package_id.clone(), contract);
        }
        let mut capsules = BTreeMap::new();
        for capsule in inputs.capsules {
            capsule.validate()?;
            capsules.insert(capsule.capsule_id.clone(), capsule);
        }
        let mut bundles = BTreeMap::new();
        for bundle in inputs.runtime_bundles {
            bundle.validate()?;
            bundles.insert(bundle.bundle_id.clone(), bundle);
        }
        let revision = canonical(&(
            inputs.build.revision.clone(),
            inputs.verifiers.revision.clone(),
            &contracts,
            &capsules,
            &bundles,
            &inputs.failures,
        ))?;
        Ok(Self {
            revision,
            build: inputs.build,
            verifiers: inputs.verifiers,
            contracts,
            capsules,
            runtime_bundles: bundles,
            failures: inputs.failures,
        })
    }

    /// Produces conservative affected-proof directives for changed graph nodes.
    pub fn impact(&self, change: &ChangeSet) -> ChangeImpactDirective {
        let mut affected = change.changed_nodes.clone();
        let mut broader = false;
        if change.workspace_or_toolchain_changed
            || change.lockfile_changed
            || change.feature_graph_changed
        {
            broader = true;
            affected.extend(self.build.nodes.iter().cloned());
        }
        if change.generated_or_build_script_changed {
            broader = true;
        }
        let exact_verifiers: BTreeSet<String> = self
            .verifiers
            .edges
            .iter()
            .filter(|edge| {
                affected.contains(&edge.target) && edge.exact && edge.coverage == Coverage::Complete
            })
            .map(|edge| edge.verifier.clone())
            .collect();
        let unknown = self.verifiers.edges.iter().any(|edge| {
            affected.contains(&edge.target) && (edge.coverage != Coverage::Complete || !edge.exact)
        }) || broader;
        let mut missing = BTreeSet::new();
        if unknown {
            missing.insert("broader-profile-required".to_owned());
        }
        for failure in &self.failures {
            if failure.escaped_regression && !failure.affected_nodes.is_disjoint(&affected) {
                missing.insert(format!("historical-escape:{}", failure.signature));
            }
        }
        ChangeImpactDirective {
            structural_breaks: change.public_contract_changed
                || change.generated_or_build_script_changed,
            behavioral_drift_candidates: affected,
            missing_expected_cochanges: BTreeSet::new(),
            impacted_verifiers_exact: exact_verifiers,
            missing_tests: missing,
            unknown_coverage: unknown,
            required_broader_profile: broader || unknown,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChangeSet {
    pub changed_nodes: BTreeSet<String>,
    pub public_contract_changed: bool,
    pub generated_or_build_script_changed: bool,
    pub workspace_or_toolchain_changed: bool,
    pub lockfile_changed: bool,
    pub feature_graph_changed: bool,
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
