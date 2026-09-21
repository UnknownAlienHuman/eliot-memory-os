//! Generated effective manifest for one functional capability cell.
//!
//! This module is the owner-neutral foundation primitive for the generated
//! `EffectiveMicroModuleManifest` described by `I2.20`: one manifest
//! represents one `FunctionalCapabilityCell`, never one Cargo package. A crate
//! declaring several cells has several manifests; collapsing them into a
//! single per-crate manifest is rejected. It owns no runtime, process,
//! storage, provider, or UI behavior; every check below rejects ambiguous or
//! incomplete input at the boundary and never manufactures authority.
//!
//! Field authority (`I2.10`, `I2.20`):
//!
//! * Derived from Cargo and contract graphs: `source_crate`,
//!   `affected_edges` (one-hop providers/consumers).
//! * Explicit declarations, never inferred from the crate name:
//!   `lifecycle_owner`, `runtime_bundle`, `execution_contour`,
//!   `runtime_class`, `state_class`, `replacement_class`, `iteration_lane`
//!   bound to a referenced [`ProofLatencyProfileRef`], `proof_entrypoint` and
//!   `proof_ceiling`, `recovery_boundary`, `contract_digest` and
//!   `freshness`. A missing non-derivable field is rejected; a crate-derived
//!   owner spelling is rejected as inferred authority.
//! * Identity: `manifest_id` binds cell and revision; `manifest_digest` is the
//!   lowercase SHA-256 hex of the canonical bytes, recomputed by
//!   [`EffectiveCellManifest::validate`].
//!
//! Deferred to the owning pipeline (not derivable in this island):
//! physical-source STU accounting, loaded-slice/agent-workset profiles, and
//! split/merge/extraction conditions remain consumer-owned projections.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    CapabilityCellId, CellFreshness, CellOwnerRef, ContractDigest, ContractError, ContractVersion,
    DigestSourceRef, EffectiveMicroModuleManifest, ProofCeiling, ProofEntrypointRef,
    RuntimeBundleId, SourceCrateRef, canonical_json_bytes, sha256_hex,
};

/// Exact namespace tag carried by every effective cell manifest digest.
pub const EFFECTIVE_CELL_MANIFEST_NAMESPACE: &str = "eliot.foundation.effective-cell-manifest";

macro_rules! manifest_string {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
        #[schemars(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated value, rejecting blank or control-bearing text.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(ContractError::Blank { field: $label });
                }
                if value.chars().any(char::is_control) {
                    return Err(ContractError::ControlCharacter { field: $label });
                }
                Ok(Self(value))
            }

            /// Returns the canonical text.
            pub fn as_str(&self) -> &str { &self.0 }

            /// Consumes this value and returns its text.
            pub fn into_string(self) -> String { self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer { serializer.serialize_str(&self.0) }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

manifest_string!(
    /// Reference to the `ProofLatencyProfile` evidencing a cell's iteration
    /// lane. The lane never stands without this explicit profile reference.
    ProofLatencyProfileRef, "proof_latency_profile");
manifest_string!(
    /// Boundary governing failure degradation and recovery of a cell.
    RecoveryBoundaryRef, "recovery_boundary");
manifest_string!(
    /// Unique manifest identity binding one cell to one contract revision.
    ManifestId, "manifest_id");

/// Execution contour of a cell (`I2.10`). Descriptive data only; it never
/// grants runtime, process, or storage ownership to this island.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleExecutionContour {
    /// Pure or nearly pure logic with a narrow capability surface.
    WasmComponent,
    /// OS, tool, credential, or long-CPU work in a separate process.
    NativeProcess,
    /// Trusted control path or measured stable hot path in a release.
    StaticNative,
    /// Generators, fuzzers, benchmarks, and migration utilities.
    DevelopmentOnly,
}

/// Runtime role of a cell (`I2.10`). Descriptive data only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleRuntimeClass {
    /// Fencing and front-door core.
    KernelInternal,
    /// Task, context, or job service.
    DaemonService,
    /// MCP, LSP, provider, or tool bridge.
    ProcessBridge,
    /// Wasmtime or native component pool host.
    ComponentHost,
    /// Build, test, or simulation service.
    TestExecutionPlane,
    /// Code graph, cue, or search index.
    DerivedIndex,
    /// Crawler or external queue worker.
    OperationalWorker,
    /// Dreamer or model router.
    CognitiveService,
    /// Watchdog sensor.
    SupervisorSecurity,
    /// UI or notifications surface.
    Surface,
    /// Impact, schema, or simulation generator.
    DevelopmentTool,
}

/// State ownership class of a cell (`I2.10`). No hot-replaceable cell declares
/// canonical semantics here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleStateClass {
    /// No state survives the request or process.
    Stateless,
    /// State remains in ELIOT-owned snapshot or delta form.
    HostStateExternalized,
    /// Derived state recreates from canonical or external sources.
    Rebuildable,
    /// Non-semantic state resumes from a versioned checkpoint.
    CheckpointedOperational,
    /// Adapter owns no ELIOT semantics; data lives behind a declared surface.
    ExternalCanonicalAdapter,
}

/// Runtime replacement class of a cell (`I2.10`). Source decomposition and
/// runtime replacement are independent decisions; the wire stays open so
/// future classes are loss-visible, while generation admits only these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleReplacementClass {
    /// One sandboxed component generation replaces independently.
    ComponentGeneration,
    /// One native process generation replaces through the process contract.
    ProcessGeneration,
    /// Crates linked into `eliotd` change through a side-by-side generation.
    DaemonGeneration,
    /// Host, Kernel, or service shell changes through the cutover contract.
    HostGeneration,
    /// No safe online cutover exists yet; owner, reason, and recovery apply.
    OfflineRelease,
}

/// Development loop lane of a cell (`I2.10`). The lane is always bound to a
/// referenced [`ProofLatencyProfileRef`]; it is never inferred from package
/// size or crate name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IterationLane {
    /// Package proof normally returns within the qualified interactive profile.
    Interactive,
    /// Independently runnable but not expected on every edit.
    Normal,
    /// Long compile, simulation, or integration proof; a Durable Job applies.
    Slow,
    /// Proof or replacement requires an explicit release or platform boundary.
    ManualRelease,
}

/// Declared plus derived inputs for generating one cell manifest.
///
/// Explicit `module.toml` declarations arrive as typed values; a missing
/// non-derivable declaration arrives as `None` and is rejected by generation
/// instead of being defaulted from the crate name. Derived Cargo and graph
/// data (`source_crate`, `affected_edges`) never substitute for a missing
/// declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CellManifestInput {
    /// Cell identity within the capability-cell namespace.
    pub cell: CapabilityCellId,
    /// Revision of the cell contract surface.
    pub cell_revision: ContractVersion,
    /// Cargo package hosting the cell source; never a source of authority.
    pub source_crate: SourceCrateRef,
    /// Explicit lifecycle owner; `None` is rejected, never crate-defaulted.
    pub lifecycle_owner: Option<CellOwnerRef>,
    /// Named runtime bundle hosting the cell, when execution is delegated.
    pub runtime_bundle: Option<RuntimeBundleId>,
    /// Where the cell executes.
    pub execution_contour: ModuleExecutionContour,
    /// Runtime role of the cell.
    pub runtime_class: ModuleRuntimeClass,
    /// State ownership class of the cell.
    pub state_class: ModuleStateClass,
    /// Runtime replacement class of the cell.
    pub replacement_class: ModuleReplacementClass,
    /// Development loop lane, bound to `proof_latency_profile`.
    pub iteration_lane: IterationLane,
    /// Referenced proof-latency profile evidencing the lane.
    pub proof_latency_profile: ProofLatencyProfileRef,
    /// Independently invokable proof entrypoint; `None` is rejected.
    pub proof_entrypoint: Option<ProofEntrypointRef>,
    /// Highest proof level this cell may claim.
    pub proof_ceiling: ProofCeiling,
    /// Failure degradation and recovery boundary.
    pub recovery_boundary: RecoveryBoundaryRef,
    /// Digest of the cell public contract surface.
    pub contract_digest: ContractDigest,
    /// Where `contract_digest` was observed.
    pub contract_digest_source: DigestSourceRef,
    /// Current support and invalidation set.
    pub freshness: CellFreshness,
    /// One-hop provider and consumer cell references from the contract graph.
    pub affected_edges: Vec<CapabilityCellId>,
    /// The mandatory contract/context/test triad manifest for this cell.
    pub manifest: EffectiveMicroModuleManifest,
}

/// Generated effective manifest for one functional capability cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveCellManifest {
    /// Unique identity binding one cell to one contract revision.
    pub manifest_id: ManifestId,
    /// Cell identity within the capability-cell namespace.
    pub functional_cell_ref: CapabilityCellId,
    /// Revision of the cell contract surface.
    pub cell_revision: ContractVersion,
    /// Cargo package hosting the cell source; never a source of authority.
    pub source_crate: SourceCrateRef,
    /// Explicit lifecycle owner of the cell.
    pub lifecycle_owner: CellOwnerRef,
    /// Named runtime bundle hosting the cell, when execution is delegated.
    pub runtime_bundle: Option<RuntimeBundleId>,
    /// Where the cell executes.
    pub execution_contour: ModuleExecutionContour,
    /// Runtime role of the cell.
    pub runtime_class: ModuleRuntimeClass,
    /// State ownership class of the cell.
    pub state_class: ModuleStateClass,
    /// Runtime replacement class of the cell.
    pub replacement_class: ModuleReplacementClass,
    /// Development loop lane of the cell.
    pub iteration_lane: IterationLane,
    /// Referenced proof-latency profile evidencing the lane.
    pub proof_latency_profile: ProofLatencyProfileRef,
    /// Independently invokable proof entrypoint of the cell.
    pub proof_entrypoint: ProofEntrypointRef,
    /// Highest proof level this cell may claim.
    pub proof_ceiling: ProofCeiling,
    /// Failure degradation and recovery boundary of the cell.
    pub recovery_boundary: RecoveryBoundaryRef,
    /// Digest of the cell public contract surface.
    pub contract_digest: ContractDigest,
    /// Where `contract_digest` was observed.
    pub contract_digest_source: DigestSourceRef,
    /// Current support and invalidation set.
    pub freshness: CellFreshness,
    /// One-hop provider and consumer cell references.
    pub affected_edges: Vec<CapabilityCellId>,
    /// The mandatory contract/context/test triad manifest for this cell.
    pub manifest: EffectiveMicroModuleManifest,
    /// Lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    pub manifest_digest: ContractDigest,
}

/// Fail-closed generation failure. Any variant refuses the manifest instead
/// of emitting a defaulted or crate-derived value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellManifestError {
    /// A required non-derivable declaration is absent.
    MissingField {
        /// Cell with the missing declaration.
        cell: String,
        /// Declaration that is absent.
        field: &'static str,
    },
    /// Delegated execution names no runtime bundle. A cell whose contour or
    /// runtime class places execution in a separately replaceable process,
    /// service, or component pool must name that bundle explicitly; `None`
    /// is rejected instead of defaulted.
    MissingRuntimeBundle {
        /// Cell with the delegated execution but no bundle.
        cell: String,
        /// Contour/class pair that requires a bundle.
        detail: String,
    },
    /// The iteration lane is not evidenced by the referenced proof-latency
    /// profile. The lane never stands without its explicit profile reference.
    IncompatibleLaneProfile {
        /// Cell with the inconsistent lane/profile pair.
        cell: String,
        /// Declared iteration lane.
        lane: String,
        /// Referenced proof-latency profile that does not evidence the lane.
        profile: String,
    },
    /// The state class is incompatible with the replacement class under the
    /// documented `I2.10` pairing constraints.
    IncompatibleStateReplacement {
        /// Cell with the incompatible state/replacement pair.
        cell: String,
        /// Declared state ownership class.
        state: String,
        /// Declared runtime replacement class.
        replacement: String,
    },
    /// One multi-cell generation call mixes inputs from more than one source
    /// crate. Generation is crate-scoped: one call describes the cells of
    /// exactly one crate.
    MixedSourceCrates {
        /// Sorted distinct source crates observed in the call.
        crates: Vec<String>,
    },
    /// An owner repeats the hosting crate name instead of naming an
    /// explicitly declared owner. Crate names never confer authority.
    InferredAuthority {
        /// Cell with the crate-derived owner.
        cell: String,
        /// Owner text matching the crate name.
        owner: String,
        /// Hosting crate the owner was derived from.
        source_crate: String,
    },
    /// A cell id is claimed twice in one crate generation.
    DuplicateCell {
        /// Cell claimed by more than one input.
        cell: String,
    },
    /// A single per-crate manifest was requested for a multi-cell crate.
    SingleManifestForMultiCell {
        /// Crate declaring more than one cell.
        source_crate: String,
        /// Number of declared cells that one manifest cannot represent.
        cells: usize,
    },
    /// A manifest digest does not match its recomputed canonical digest.
    DigestMismatch {
        /// Manifest whose digest failed to reverify.
        cell: String,
        /// Digest carried by the manifest value.
        found: String,
    },
    /// A digest could not be constructed or compared at the boundary.
    DigestFailed {
        /// Underlying digest failure detail.
        detail: String,
    },
}

impl fmt::Display for CellManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { cell, field } => write!(
                formatter,
                "cell '{cell}' is missing required declaration '{field}'"
            ),
            Self::MissingRuntimeBundle { cell, detail } => write!(
                formatter,
                "cell '{cell}' delegates execution ({detail}) but names no runtime_bundle"
            ),
            Self::IncompatibleLaneProfile {
                cell,
                lane,
                profile,
            } => write!(
                formatter,
                "cell '{cell}' iteration lane '{lane}' is not evidenced by proof latency profile '{profile}'"
            ),
            Self::IncompatibleStateReplacement {
                cell,
                state,
                replacement,
            } => write!(
                formatter,
                "cell '{cell}' state class '{state}' is incompatible with replacement class '{replacement}'"
            ),
            Self::MixedSourceCrates { crates } => write!(
                formatter,
                "multi-cell generation mixes source crates: {}",
                crates.join(", ")
            ),
            Self::InferredAuthority {
                cell,
                owner,
                source_crate,
            } => write!(
                formatter,
                "cell '{cell}' owner '{owner}' is derived from crate '{source_crate}'"
            ),
            Self::DuplicateCell { cell } => write!(
                formatter,
                "cell '{cell}' is claimed by more than one manifest input"
            ),
            Self::SingleManifestForMultiCell {
                source_crate,
                cells,
            } => write!(
                formatter,
                "crate '{source_crate}' declares {cells} cells: one per-crate manifest is rejected"
            ),
            Self::DigestMismatch { cell, found } => write!(
                formatter,
                "cell '{cell}' manifest digest '{found}' does not match its canonical bytes"
            ),
            Self::DigestFailed { detail } => {
                write!(formatter, "cell manifest digest unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for CellManifestError {}

#[derive(Serialize)]
struct CellManifestDigestInput<'a> {
    namespace: &'static str,
    manifest: &'a EffectiveCellManifestDigestBody<'a>,
}

#[derive(Serialize)]
struct EffectiveCellManifestDigestBody<'a> {
    manifest_id: &'a ManifestId,
    functional_cell_ref: &'a CapabilityCellId,
    cell_revision: &'a ContractVersion,
    source_crate: &'a SourceCrateRef,
    lifecycle_owner: &'a CellOwnerRef,
    runtime_bundle: &'a Option<RuntimeBundleId>,
    execution_contour: &'a ModuleExecutionContour,
    runtime_class: &'a ModuleRuntimeClass,
    state_class: &'a ModuleStateClass,
    replacement_class: &'a ModuleReplacementClass,
    iteration_lane: &'a IterationLane,
    proof_latency_profile: &'a ProofLatencyProfileRef,
    proof_entrypoint: &'a ProofEntrypointRef,
    proof_ceiling: &'a ProofCeiling,
    recovery_boundary: &'a RecoveryBoundaryRef,
    contract_digest: &'a ContractDigest,
    contract_digest_source: &'a DigestSourceRef,
    freshness: &'a CellFreshness,
    affected_edges: &'a [CapabilityCellId],
    manifest: &'a EffectiveMicroModuleManifest,
}

fn manifest_identity(cell: &CapabilityCellId, revision: ContractVersion) -> String {
    format!("{}@{}", cell.as_str(), revision.as_string())
}

fn authority_key(value: &str) -> String {
    value.to_lowercase().replace('_', "-")
}

fn owner_is_crate_derived(owner: &CellOwnerRef, source_crate: &SourceCrateRef) -> bool {
    authority_key(owner.as_str()) == authority_key(source_crate.as_str())
}

/// Returns whether the contour/class pair denotes delegated execution
/// (`I2.10`): the cell runs in a separately replaceable process, service, or
/// component pool, so it must name that bundle explicitly.
///
/// The `NativeProcess` contour always delegates (separate process/Job with a
/// versioned protocol and rolling generation). The service-like runtime
/// classes replace through an independent service, process, host, testd, or
/// job generation and therefore delegate as well. `KernelInternal` is
/// host-managed inline, `DerivedIndex` rebuilds from sources in place,
/// `Surface` restarts host-inline, and `DevelopmentTool` never runs in
/// production, so none of them requires a bundle by itself.
fn requires_runtime_bundle(contour: ModuleExecutionContour, class: ModuleRuntimeClass) -> bool {
    if contour == ModuleExecutionContour::NativeProcess {
        return true;
    }
    matches!(
        class,
        ModuleRuntimeClass::DaemonService
            | ModuleRuntimeClass::ProcessBridge
            | ModuleRuntimeClass::ComponentHost
            | ModuleRuntimeClass::TestExecutionPlane
            | ModuleRuntimeClass::OperationalWorker
            | ModuleRuntimeClass::CognitiveService
            | ModuleRuntimeClass::SupervisorSecurity
    )
}

/// Returns whether the referenced proof-latency profile evidences the
/// declared iteration lane (`I2.10`).
///
/// Verifiable rule: the profile reference is split into lowercase
/// alphanumeric tokens on every other character, and the lane token must be
/// present exactly (`interactive`, `normal`, `slow`). `ManualRelease`
/// requires both `manual` and `release` tokens. Token-exact matching keeps
/// `abnormal` from evidencing `Normal`; the lane is never inferred from
/// package size or crate name.
fn lane_profile_consistent(lane: IterationLane, profile: &ProofLatencyProfileRef) -> bool {
    let tokens: Vec<String> = profile
        .as_str()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let has = |token: &str| tokens.iter().any(|candidate| candidate == token);
    match lane {
        IterationLane::Interactive => has("interactive"),
        IterationLane::Normal => has("normal"),
        IterationLane::Slow => has("slow"),
        IterationLane::ManualRelease => has("manual") && has("release"),
    }
}

/// Returns whether the state/replacement pair is admissible under the
/// documented `I2.10` pairing constraints:
///
/// * `Stateless` cells have no state to migrate, so `OfflineRelease` ("no
///   safe online cutover exists yet") is incoherent for them.
/// * `CheckpointedOperational` state resumes from a versioned
///   checkpoint/reconciliation, which one sandboxed `ComponentGeneration`
///   cannot provide.
/// * `ExternalCanonicalAdapter` owns no ELIOT semantics, so it must not be
///   linked into the daemon (`DaemonGeneration`); it replaces through its
///   declared external surface.
///
/// Every other combination is admitted; source decomposition and runtime
/// replacement remain independent decisions.
fn state_replacement_compatible(
    state: ModuleStateClass,
    replacement: ModuleReplacementClass,
) -> bool {
    !matches!(
        (state, replacement),
        (
            ModuleStateClass::Stateless,
            ModuleReplacementClass::OfflineRelease
        ) | (
            ModuleStateClass::CheckpointedOperational,
            ModuleReplacementClass::ComponentGeneration,
        ) | (
            ModuleStateClass::ExternalCanonicalAdapter,
            ModuleReplacementClass::DaemonGeneration,
        )
    )
}

/// Enforces the cross-field consistency rules shared by generation and
/// validation: delegated execution names a bundle, the lane is evidenced by
/// its profile, and the state/replacement pair is admissible.
#[allow(clippy::too_many_arguments)]
fn check_cross_field_consistency(
    cell: &str,
    contour: ModuleExecutionContour,
    class: ModuleRuntimeClass,
    bundle: Option<&RuntimeBundleId>,
    lane: IterationLane,
    profile: &ProofLatencyProfileRef,
    state: ModuleStateClass,
    replacement: ModuleReplacementClass,
) -> Result<(), CellManifestError> {
    if requires_runtime_bundle(contour, class) && bundle.is_none() {
        return Err(CellManifestError::MissingRuntimeBundle {
            cell: cell.to_owned(),
            detail: format!("{contour:?}/{class:?} delegates execution to a named bundle"),
        });
    }
    if !lane_profile_consistent(lane, profile) {
        return Err(CellManifestError::IncompatibleLaneProfile {
            cell: cell.to_owned(),
            lane: format!("{lane:?}"),
            profile: profile.as_str().to_owned(),
        });
    }
    if !state_replacement_compatible(state, replacement) {
        return Err(CellManifestError::IncompatibleStateReplacement {
            cell: cell.to_owned(),
            state: format!("{state:?}"),
            replacement: format!("{replacement:?}"),
        });
    }
    Ok(())
}

/// Returns the sorted distinct source crates named by one multi-cell call.
fn distinct_source_crates(inputs: &[CellManifestInput]) -> Vec<String> {
    let mut crates: Vec<String> = Vec::new();
    for input in inputs {
        let name = input.source_crate.as_str().to_owned();
        if !crates.contains(&name) {
            crates.push(name);
        }
    }
    crates.sort();
    crates
}

fn contract_digest_of(bytes: &[u8]) -> Result<ContractDigest, CellManifestError> {
    ContractDigest::new(sha256_hex(bytes)).map_err(|error| CellManifestError::DigestFailed {
        detail: error.to_string(),
    })
}

impl EffectiveCellManifest {
    /// Returns deterministic canonical bytes for this manifest value.
    ///
    /// The manifest namespace is bound into the bytes, so generating twice
    /// over equal input is byte-identical without any clock, process id, or
    /// map ordering input.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let body = EffectiveCellManifestDigestBody {
            manifest_id: &self.manifest_id,
            functional_cell_ref: &self.functional_cell_ref,
            cell_revision: &self.cell_revision,
            source_crate: &self.source_crate,
            lifecycle_owner: &self.lifecycle_owner,
            runtime_bundle: &self.runtime_bundle,
            execution_contour: &self.execution_contour,
            runtime_class: &self.runtime_class,
            state_class: &self.state_class,
            replacement_class: &self.replacement_class,
            iteration_lane: &self.iteration_lane,
            proof_latency_profile: &self.proof_latency_profile,
            proof_entrypoint: &self.proof_entrypoint,
            proof_ceiling: &self.proof_ceiling,
            recovery_boundary: &self.recovery_boundary,
            contract_digest: &self.contract_digest,
            contract_digest_source: &self.contract_digest_source,
            freshness: &self.freshness,
            affected_edges: &self.affected_edges,
            manifest: &self.manifest,
        };
        let input = CellManifestDigestInput {
            namespace: EFFECTIVE_CELL_MANIFEST_NAMESPACE,
            manifest: &body,
        };
        canonical_json_bytes(&input)
    }

    /// Recomputes the manifest digest from [`Self::canonical_bytes`].
    pub fn recomputed_digest(&self) -> Result<ContractDigest, CellManifestError> {
        let bytes = self
            .canonical_bytes()
            .map_err(|error| CellManifestError::DigestFailed {
                detail: error.to_string(),
            })?;
        contract_digest_of(&bytes)
    }

    /// Validates identity binding, digest freshness, and explicit authority.
    ///
    /// Returns `Ok(())` only when the manifest id binds the cell revision,
    /// the carried digest matches the recomputed canonical digest, no owner
    /// is derived from the hosting crate name, delegated execution names a
    /// runtime bundle, the iteration lane is evidenced by its referenced
    /// proof-latency profile, and the state/replacement pair is admissible
    /// under `I2.10`.
    pub fn validate(&self) -> Result<(), CellManifestError> {
        let expected_id = manifest_identity(&self.functional_cell_ref, self.cell_revision);
        if self.manifest_id.as_str() != expected_id {
            return Err(CellManifestError::DigestMismatch {
                cell: self.functional_cell_ref.as_str().to_owned(),
                found: self.manifest_id.as_str().to_owned(),
            });
        }
        let recomputed = self.recomputed_digest()?;
        if recomputed != self.manifest_digest {
            return Err(CellManifestError::DigestMismatch {
                cell: self.functional_cell_ref.as_str().to_owned(),
                found: self.manifest_digest.as_str().to_owned(),
            });
        }
        if owner_is_crate_derived(&self.lifecycle_owner, &self.source_crate) {
            return Err(CellManifestError::InferredAuthority {
                cell: self.functional_cell_ref.as_str().to_owned(),
                owner: self.lifecycle_owner.as_str().to_owned(),
                source_crate: self.source_crate.as_str().to_owned(),
            });
        }
        check_cross_field_consistency(
            self.functional_cell_ref.as_str(),
            self.execution_contour,
            self.runtime_class,
            self.runtime_bundle.as_ref(),
            self.iteration_lane,
            &self.proof_latency_profile,
            self.state_class,
            self.replacement_class,
        )?;
        Ok(())
    }
}

/// Generates one effective manifest for one cell input.
///
/// Missing non-derivable declarations (`lifecycle_owner`, `proof_entrypoint`)
/// are rejected; a crate-derived owner spelling is rejected as inferred
/// authority instead of being accepted as a default. Delegated execution
/// without a named `runtime_bundle`, a lane unevidenced by its referenced
/// proof-latency profile, and an inadmissible `I2.10` state/replacement pair
/// are rejected fail-closed as well.
pub fn generate_effective_manifest(
    input: CellManifestInput,
) -> Result<EffectiveCellManifest, CellManifestError> {
    let cell_name = input.cell.as_str().to_owned();
    let lifecycle_owner = input
        .lifecycle_owner
        .ok_or_else(|| CellManifestError::MissingField {
            cell: cell_name.clone(),
            field: "lifecycle_owner",
        })?;
    if owner_is_crate_derived(&lifecycle_owner, &input.source_crate) {
        return Err(CellManifestError::InferredAuthority {
            cell: cell_name.clone(),
            owner: lifecycle_owner.as_str().to_owned(),
            source_crate: input.source_crate.as_str().to_owned(),
        });
    }
    let proof_entrypoint =
        input
            .proof_entrypoint
            .ok_or_else(|| CellManifestError::MissingField {
                cell: cell_name.clone(),
                field: "proof_entrypoint",
            })?;
    check_cross_field_consistency(
        &cell_name,
        input.execution_contour,
        input.runtime_class,
        input.runtime_bundle.as_ref(),
        input.iteration_lane,
        &input.proof_latency_profile,
        input.state_class,
        input.replacement_class,
    )?;
    let manifest_id = ManifestId::new(manifest_identity(&input.cell, input.cell_revision))
        .map_err(|error| CellManifestError::DigestFailed {
            detail: error.to_string(),
        })?;
    let mut manifest = EffectiveCellManifest {
        manifest_id,
        functional_cell_ref: input.cell,
        cell_revision: input.cell_revision,
        source_crate: input.source_crate,
        lifecycle_owner,
        runtime_bundle: input.runtime_bundle,
        execution_contour: input.execution_contour,
        runtime_class: input.runtime_class,
        state_class: input.state_class,
        replacement_class: input.replacement_class,
        iteration_lane: input.iteration_lane,
        proof_latency_profile: input.proof_latency_profile,
        proof_entrypoint,
        proof_ceiling: input.proof_ceiling,
        recovery_boundary: input.recovery_boundary,
        contract_digest: input.contract_digest,
        contract_digest_source: input.contract_digest_source,
        freshness: input.freshness,
        affected_edges: input.affected_edges,
        manifest: input.manifest,
        manifest_digest: ContractDigest::new(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .map_err(|error| CellManifestError::DigestFailed {
            detail: error.to_string(),
        })?,
    };
    let digest = manifest.recomputed_digest()?;
    manifest.manifest_digest = digest;
    manifest.validate()?;
    Ok(manifest)
}

/// Generates one effective manifest per declared cell of a crate.
///
/// The call is crate-scoped: every input must name the same `source_crate`,
/// and mixed-crate inputs fail with [`CellManifestError::MixedSourceCrates`]
/// instead of generating under the first crate. The output preserves input
/// order with one manifest per input cell; a duplicate cell claim fails the
/// whole crate generation. Use [`generate_single_crate_manifest`] only to
/// prove that a single per-crate manifest is rejected for a multi-cell crate.
pub fn generate_effective_manifests_for_crate(
    inputs: Vec<CellManifestInput>,
) -> Result<Vec<EffectiveCellManifest>, CellManifestError> {
    let crates = distinct_source_crates(&inputs);
    if crates.len() > 1 {
        return Err(CellManifestError::MixedSourceCrates { crates });
    }
    let mut seen: Vec<String> = Vec::new();
    for input in &inputs {
        let cell_name = input.cell.as_str().to_owned();
        if seen.contains(&cell_name) {
            return Err(CellManifestError::DuplicateCell { cell: cell_name });
        }
        seen.push(cell_name);
    }
    let mut manifests = Vec::with_capacity(inputs.len());
    for input in inputs {
        manifests.push(generate_effective_manifest(input)?);
    }
    Ok(manifests)
}

/// Proves that a single per-crate manifest cannot represent a multi-cell
/// crate: more than one declared cell is rejected instead of collapsed.
///
/// Mixed-crate inputs fail with [`CellManifestError::MixedSourceCrates`]
/// listing every observed crate; the multi-cell rejection always reports the
/// true shared crate rather than whichever input arrived first.
pub fn generate_single_crate_manifest(
    inputs: Vec<CellManifestInput>,
) -> Result<EffectiveCellManifest, CellManifestError> {
    if inputs.is_empty() {
        return Err(CellManifestError::MissingField {
            cell: "<unknown>".to_owned(),
            field: "functional_cell_ref",
        });
    }
    let crates = distinct_source_crates(&inputs);
    if crates.len() > 1 {
        return Err(CellManifestError::MixedSourceCrates { crates });
    }
    if inputs.len() > 1 {
        let shared = crates
            .first()
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_owned());
        return Err(CellManifestError::SingleManifestForMultiCell {
            source_crate: shared,
            cells: inputs.len(),
        });
    }
    let mut manifests = generate_effective_manifests_for_crate(inputs)?;
    manifests.pop().map_or_else(
        || {
            Err(CellManifestError::MissingField {
                cell: "<unknown>".to_owned(),
                field: "functional_cell_ref",
            })
        },
        Ok,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapsulePresence, CellStateName, SupportStatus};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn triad(owner: &str) -> Result<EffectiveMicroModuleManifest, ContractError> {
        let declaring = CellOwnerRef::new(owner)?;
        Ok(EffectiveMicroModuleManifest {
            contract_kit: CapsulePresence {
                present: true,
                owner: Some(declaring.clone()),
            },
            context_capsule: CapsulePresence {
                present: true,
                owner: Some(declaring.clone()),
            },
            test_capsule: CapsulePresence {
                present: true,
                owner: Some(declaring),
            },
        })
    }

    fn valid_input(cell: &str, owner: &str) -> Result<CellManifestInput, ContractError> {
        let _state: CellStateName = CellStateName::new("stateless-island")?;
        Ok(CellManifestInput {
            cell: CapabilityCellId::new(cell)?,
            cell_revision: ContractVersion::new(1, 0, 0),
            source_crate: SourceCrateRef::new("eliot-contracts")?,
            lifecycle_owner: Some(CellOwnerRef::new(owner)?),
            runtime_bundle: None,
            execution_contour: ModuleExecutionContour::StaticNative,
            runtime_class: ModuleRuntimeClass::KernelInternal,
            state_class: ModuleStateClass::Stateless,
            replacement_class: ModuleReplacementClass::HostGeneration,
            iteration_lane: IterationLane::Normal,
            proof_latency_profile: ProofLatencyProfileRef::new("eliot-contracts/profile/normal")?,
            proof_entrypoint: Some(ProofEntrypointRef::new("eliot-contracts proof")?),
            proof_ceiling: ProofCeiling::ModuleEdgeProof,
            recovery_boundary: RecoveryBoundaryRef::new("foundation ABI review")?,
            contract_digest: ContractDigest::new("ab".repeat(32))?,
            contract_digest_source: DigestSourceRef::new("contract catalogue")?,
            freshness: CellFreshness {
                current_support: SupportStatus::CurrentUnverified,
                invalidation: Vec::new(),
            },
            affected_edges: Vec::new(),
            manifest: triad("foundation-contract-owner")?,
        })
    }

    #[test]
    fn two_cell_crate_yields_two_manifests_and_rejects_missing_field() -> TestResult {
        let inputs = vec![
            valid_input(
                "foundation.contracts.primitives",
                "foundation-contract-owner",
            )?,
            valid_input(
                "foundation.authority.epoch-identity",
                "foundation-epoch-owner",
            )?,
        ];
        let manifests = generate_effective_manifests_for_crate(inputs)?;
        assert_eq!(manifests.len(), 2);
        assert_ne!(
            manifests[0].functional_cell_ref,
            manifests[1].functional_cell_ref
        );
        for manifest in &manifests {
            assert_eq!(
                manifest.execution_contour,
                ModuleExecutionContour::StaticNative
            );
            assert_eq!(manifest.runtime_class, ModuleRuntimeClass::KernelInternal);
            assert_eq!(manifest.state_class, ModuleStateClass::Stateless);
            assert_eq!(
                manifest.replacement_class,
                ModuleReplacementClass::HostGeneration
            );
            assert_eq!(manifest.iteration_lane, IterationLane::Normal);
            manifest.validate().map_err(|error| error.to_string())?;
        }
        assert_ne!(manifests[0].manifest_digest, manifests[1].manifest_digest);

        let missing_proof = {
            let mut missing = valid_input("foundation.contracts.primitives", "foundation-owner")?;
            missing.proof_entrypoint = None;
            missing
        };
        assert!(matches!(
            generate_effective_manifest(missing_proof),
            Err(CellManifestError::MissingField {
                field: "proof_entrypoint",
                ..
            })
        ));

        let crate_derived = valid_input("foundation.contracts.primitives", "eliot-contracts")?;
        assert!(matches!(
            generate_effective_manifest(crate_derived),
            Err(CellManifestError::InferredAuthority { .. })
        ));

        let collapsed = vec![
            valid_input("foundation.contracts.primitives", "foundation-owner-a")?,
            valid_input("foundation.authority.epoch-identity", "foundation-owner-b")?,
        ];
        assert!(matches!(
            generate_single_crate_manifest(collapsed),
            Err(CellManifestError::SingleManifestForMultiCell { cells: 2, .. })
        ));
        Ok(())
    }

    #[test]
    fn delegated_execution_requires_named_runtime_bundle() -> TestResult {
        let mut native = valid_input("foundation.tool.native", "foundation-tool-owner")?;
        native.execution_contour = ModuleExecutionContour::NativeProcess;
        assert!(matches!(
            generate_effective_manifest(native),
            Err(CellManifestError::MissingRuntimeBundle { .. })
        ));

        let mut bundled = valid_input("foundation.tool.native", "foundation-tool-owner")?;
        bundled.execution_contour = ModuleExecutionContour::NativeProcess;
        bundled.runtime_bundle = Some(RuntimeBundleId::new("tool-native-bundle")?);
        let bundled_manifest = generate_effective_manifest(bundled)?;
        bundled_manifest
            .validate()
            .map_err(|error| error.to_string())?;

        for class in [
            ModuleRuntimeClass::DaemonService,
            ModuleRuntimeClass::ProcessBridge,
            ModuleRuntimeClass::ComponentHost,
            ModuleRuntimeClass::TestExecutionPlane,
            ModuleRuntimeClass::OperationalWorker,
            ModuleRuntimeClass::CognitiveService,
            ModuleRuntimeClass::SupervisorSecurity,
        ] {
            let mut input = valid_input("foundation.service.cell", "foundation-service-owner")?;
            input.runtime_class = class;
            assert!(
                matches!(
                    generate_effective_manifest(input),
                    Err(CellManifestError::MissingRuntimeBundle { .. })
                ),
                "runtime class {class:?} must require a runtime bundle"
            );
        }

        for class in [
            ModuleRuntimeClass::KernelInternal,
            ModuleRuntimeClass::DerivedIndex,
            ModuleRuntimeClass::Surface,
            ModuleRuntimeClass::DevelopmentTool,
        ] {
            let mut input = valid_input("foundation.host.cell", "foundation-host-owner")?;
            input.runtime_class = class;
            generate_effective_manifest(input).map_err(|error| error.to_string())?;
        }

        let mut manifest = generate_effective_manifest(valid_input(
            "foundation.contracts.primitives",
            "foundation-contract-owner",
        )?)?;
        manifest.execution_contour = ModuleExecutionContour::NativeProcess;
        manifest.manifest_digest = manifest
            .recomputed_digest()
            .map_err(|error| error.to_string())?;
        assert!(matches!(
            manifest.validate(),
            Err(CellManifestError::MissingRuntimeBundle { .. })
        ));
        Ok(())
    }

    #[test]
    fn iteration_lane_requires_evidencing_profile() -> TestResult {
        let mut mismatched = valid_input("foundation.contracts.primitives", "foundation-owner")?;
        mismatched.iteration_lane = IterationLane::Interactive;
        assert!(matches!(
            generate_effective_manifest(mismatched),
            Err(CellManifestError::IncompatibleLaneProfile { .. })
        ));

        let mut abnormal = valid_input("foundation.contracts.primitives", "foundation-owner")?;
        abnormal.proof_latency_profile =
            ProofLatencyProfileRef::new("eliot-contracts/profile/abnormal")?;
        assert!(matches!(
            generate_effective_manifest(abnormal),
            Err(CellManifestError::IncompatibleLaneProfile { .. })
        ));

        for (lane, profile) in [
            (
                IterationLane::Interactive,
                "eliot-contracts/profile/interactive",
            ),
            (IterationLane::Normal, "eliot-contracts/profile/normal"),
            (IterationLane::Slow, "foundation/proof/slow-durable-job"),
            (
                IterationLane::ManualRelease,
                "foundation/proof/manual-release-gate",
            ),
        ] {
            let mut input = valid_input("foundation.contracts.primitives", "foundation-owner")?;
            input.iteration_lane = lane;
            input.proof_latency_profile = ProofLatencyProfileRef::new(profile)?;
            generate_effective_manifest(input).map_err(|error| error.to_string())?;
        }

        let mut manifest = generate_effective_manifest(valid_input(
            "foundation.contracts.primitives",
            "foundation-contract-owner",
        )?)?;
        manifest.iteration_lane = IterationLane::Slow;
        manifest.manifest_digest = manifest
            .recomputed_digest()
            .map_err(|error| error.to_string())?;
        assert!(matches!(
            manifest.validate(),
            Err(CellManifestError::IncompatibleLaneProfile { .. })
        ));
        Ok(())
    }

    #[test]
    fn state_replacement_pairings_are_constrained() -> TestResult {
        for (state, replacement) in [
            (
                ModuleStateClass::Stateless,
                ModuleReplacementClass::OfflineRelease,
            ),
            (
                ModuleStateClass::CheckpointedOperational,
                ModuleReplacementClass::ComponentGeneration,
            ),
            (
                ModuleStateClass::ExternalCanonicalAdapter,
                ModuleReplacementClass::DaemonGeneration,
            ),
        ] {
            let mut input = valid_input("foundation.contracts.primitives", "foundation-owner")?;
            input.state_class = state;
            input.replacement_class = replacement;
            assert!(
                matches!(
                    generate_effective_manifest(input),
                    Err(CellManifestError::IncompatibleStateReplacement { .. })
                ),
                "state {state:?} with replacement {replacement:?} must be rejected"
            );
        }

        for (state, replacement) in [
            (
                ModuleStateClass::Stateless,
                ModuleReplacementClass::ComponentGeneration,
            ),
            (
                ModuleStateClass::Stateless,
                ModuleReplacementClass::HostGeneration,
            ),
            (
                ModuleStateClass::HostStateExternalized,
                ModuleReplacementClass::DaemonGeneration,
            ),
            (
                ModuleStateClass::Rebuildable,
                ModuleReplacementClass::ProcessGeneration,
            ),
            (
                ModuleStateClass::CheckpointedOperational,
                ModuleReplacementClass::ProcessGeneration,
            ),
            (
                ModuleStateClass::ExternalCanonicalAdapter,
                ModuleReplacementClass::ProcessGeneration,
            ),
            (
                ModuleStateClass::ExternalCanonicalAdapter,
                ModuleReplacementClass::OfflineRelease,
            ),
        ] {
            let mut input = valid_input("foundation.contracts.primitives", "foundation-owner")?;
            input.state_class = state;
            input.replacement_class = replacement;
            generate_effective_manifest(input).map_err(|error| error.to_string())?;
        }

        let mut manifest = generate_effective_manifest(valid_input(
            "foundation.contracts.primitives",
            "foundation-contract-owner",
        )?)?;
        manifest.replacement_class = ModuleReplacementClass::OfflineRelease;
        manifest.manifest_digest = manifest
            .recomputed_digest()
            .map_err(|error| error.to_string())?;
        assert!(matches!(
            manifest.validate(),
            Err(CellManifestError::IncompatibleStateReplacement { .. })
        ));
        Ok(())
    }

    #[test]
    fn multi_cell_generation_is_crate_scoped() -> TestResult {
        fn other_crate_input() -> Result<CellManifestInput, ContractError> {
            let mut input = valid_input("foundation.other.cell", "foundation-other-owner")?;
            input.source_crate = SourceCrateRef::new("eliot-other")?;
            Ok(input)
        }

        let mixed = vec![
            valid_input("foundation.contracts.primitives", "foundation-owner-a")?,
            other_crate_input()?,
        ];
        let Err(CellManifestError::MixedSourceCrates { crates }) =
            generate_effective_manifests_for_crate(mixed)
        else {
            panic!("mixed source crates must be rejected");
        };
        assert_eq!(
            crates,
            vec!["eliot-contracts".to_owned(), "eliot-other".to_owned()]
        );

        let mixed_single = vec![
            valid_input("foundation.contracts.primitives", "foundation-owner-a")?,
            other_crate_input()?,
        ];
        assert!(matches!(
            generate_single_crate_manifest(mixed_single),
            Err(CellManifestError::MixedSourceCrates { .. })
        ));

        let same_crate = vec![
            valid_input("foundation.contracts.primitives", "foundation-owner-a")?,
            valid_input("foundation.authority.epoch-identity", "foundation-owner-b")?,
        ];
        let Err(CellManifestError::SingleManifestForMultiCell {
            source_crate,
            cells,
        }) = generate_single_crate_manifest(same_crate)
        else {
            panic!("single manifest for a multi-cell crate must be rejected");
        };
        assert_eq!(source_crate, "eliot-contracts");
        assert_eq!(cells, 2);
        Ok(())
    }
    #[test]
    fn duplicate_cell_ref_is_rejected() -> TestResult {
        let inputs = vec![
            valid_input("foundation.contracts.primitives", "foundation-owner-a")?,
            valid_input("foundation.contracts.primitives", "foundation-owner-b")?,
        ];
        assert!(matches!(
            generate_effective_manifests_for_crate(inputs),
            Err(CellManifestError::DuplicateCell { .. })
        ));
        Ok(())
    }
}
