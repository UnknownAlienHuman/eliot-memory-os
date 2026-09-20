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
    /// the carried digest matches the recomputed canonical digest, and no
    /// owner is derived from the hosting crate name.
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
        Ok(())
    }
}

/// Generates one effective manifest for one cell input.
///
/// Missing non-derivable declarations (`lifecycle_owner`, `proof_entrypoint`)
/// are rejected; a crate-derived owner spelling is rejected as inferred
/// authority instead of being accepted as a default.
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
/// The output preserves input order with one manifest per input cell; a
/// duplicate cell claim fails the whole crate generation. Use
/// [`generate_single_crate_manifest`] only to prove that a single per-crate
/// manifest is rejected for a multi-cell crate.
pub fn generate_effective_manifests_for_crate(
    inputs: Vec<CellManifestInput>,
) -> Result<Vec<EffectiveCellManifest>, CellManifestError> {
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
pub fn generate_single_crate_manifest(
    inputs: Vec<CellManifestInput>,
) -> Result<EffectiveCellManifest, CellManifestError> {
    if inputs.len() > 1 {
        let first = inputs.first().map_or_else(
            || "<unknown>".to_owned(),
            |input| input.source_crate.as_str().to_owned(),
        );
        return Err(CellManifestError::SingleManifestForMultiCell {
            source_crate: first,
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
}
