//! Executable, versioned registry of functional capability cells.
//!
//! This module is the owner-neutral foundation primitive for the generated
//! `CapabilityCellRegistry` described by `I2.23`: it answers "how many cells
//! exist and who owns what" as validated data. It owns no runtime, process,
//! storage, provider, or UI behavior; every check below rejects ambiguous or
//! stale input at the boundary and never manufactures authority.
//!
//! Identity and namespace rules:
//!
//! * The registry namespace is [`CAPABILITY_CELL_REGISTRY_NAMESPACE`]; a cell,
//!   owner, digest, or pair key with identical spelling from another namespace
//!   is not equal to a value of this family.
//! * The normative pair binding is exact: [`EXPECTED_NORMATIVE_PAIR_KEY`] is
//!   the pair key adopted in `docs/normative-pair.toml`. Any other pair key is
//!   stale and the registry fails closed.
//! * Canonical bytes bind the namespace and use recursively sorted object
//!   keys, so generating twice over equal input is byte-identical without any
//!   clock, process id, or hash-map iteration order.
//! * The manifest triad [`EffectiveMicroModuleManifest`] follows `I2.20`: a
//!   cell missing any of `ModuleContractKit`, `CrateContextCapsule`, or
//!   `ModuleTestCapsule` cannot rise above `CURRENT_UNVERIFIED`, and the
//!   registry reports the gap instead of promoting the cell.

use std::{fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{ContractError, ContractVersion, canonical_json_bytes, sha256_hex};

/// Stable contract name for the owner-neutral capability-cell registry family.
pub const CAPABILITY_CELL_REGISTRY_CONTRACT_NAME: &str =
    "eliot.foundation.capability-cell-registry";
/// Exact namespace tag carried by every value of this family.
///
/// The namespace tag — not the spelling of any single field — determines this
/// identity family. Identical spelling from another namespace is never equal.
pub const CAPABILITY_CELL_REGISTRY_NAMESPACE: &str = "eliot.foundation.capability-cell-registry";
/// Semantic version of the capability-cell registry contract surface.
pub const CAPABILITY_CELL_REGISTRY_CONTRACT_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);
/// Wire revision carried by every [`CapabilityCellRegistry`] value.
pub const CAPABILITY_CELL_REGISTRY_VERSION: u32 = 1;
/// Exact normative pair key adopted in `docs/normative-pair.toml`.
///
/// Any registry bound to another pair key is stale and fails closed.
pub const EXPECTED_NORMATIVE_PAIR_KEY: &str =
    "sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b";
/// Closed replacement-class vocabulary admitted by registry validation.
///
/// The spellings follow the `CrateExtractionDecision` disposition set (`I2.23`)
/// and the `CrateScaleReview` outcomes (`I2.21`).
pub const KNOWN_REPLACEMENT_CLASSES: &[&str] = &[
    "keep",
    "split",
    "merge",
    "extract_contract",
    "isolate_dependency",
    "thin_facade",
    "migration_legacy",
    "experiment",
];

macro_rules! registry_string {
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

        impl FromStr for $name {
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

registry_string!(
    /// Identity of one functional capability cell in the registry namespace.
    CapabilityCellId, "capability_cell_id");
registry_string!(
    /// Declared owner reference for cell lifecycle, maintenance, semantic, or
    /// generation responsibility. The spelling never confers authority by
    /// itself; only explicit declaration in a validated record does.
    CellOwnerRef, "cell_owner");
registry_string!(
    /// Name of one mutable state value owned by a capability cell.
    CellStateName, "cell_state");
registry_string!(
    /// Name of a runtime bundle hosting delegated cell execution. Naming a
    /// bundle records where execution lives; it never grants this foundation
    /// island runtime ownership.
    RuntimeBundleId, "runtime_bundle");
registry_string!(
    /// One effect class a cell may exercise. A stateless island admits none.
    EffectClass, "effect_class");
registry_string!(
    /// Reference to the independently invokable proof entrypoint of a cell.
    ProofEntrypointRef, "proof_entrypoint");
registry_string!(
    /// Reference to the Product Pulse evidencing a cell.
    ProductPulseRef, "product_pulse");
registry_string!(
    /// Toolchain identity recorded in registry source provenance.
    ToolchainRef, "toolchain");
registry_string!(
    /// Generator version that emitted a registry value or digest.
    GeneratorVersion, "generator_version");
registry_string!(
    /// Cargo package hosting a cell's source. Packaging never transfers
    /// lifecycle authority between cells.
    SourceCrateRef, "source_crate");
registry_string!(
    /// Where a cell contract digest was observed (catalogue or generator reference).
    DigestSourceRef, "contract_digest_source");
registry_string!(
    /// Boundary governing removal or rollback of a cell.
    RemovalBoundaryRef, "removal_boundary");
registry_string!(
    /// One reason invalidating a cell's current support claim.
    InvalidationReason, "invalidation_reason");
registry_string!(
    /// Explicit reason the Product Pulse does not apply to a cell.
    PulseExemptionReason, "pulse_exemption_reason");
registry_string!(
    /// Replacement class of a cell. The wire stays open so future classes are
    /// loss-visible; validation admits only [`KNOWN_REPLACEMENT_CLASSES`].
    ReplacementClass, "replacement_class");

fn validate_digest_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::InvalidDigest { field });
    }
    Ok(())
}

/// Lowercase SHA-256 hex digest of a cell public contract surface.
///
/// This is a distinct namespace from any other digest in the workspace:
/// identical hex from another family is not equal to this type.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct ContractDigest(String);

impl ContractDigest {
    /// Constructs a validated digest, rejecting non-lowercase-hex text.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_digest_text(&value, "contract_digest")?;
        Ok(Self(value))
    }

    /// Returns the canonical lowercase hex text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this digest and returns its text.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ContractDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ContractDigest {
    type Err = ContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ContractDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContractDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Exact normative pair key binding a registry to `docs/normative-pair.toml`.
///
/// The wire form is `sha256:` followed by 64 lowercase hex digits. Shape is
/// checked at the boundary; staleness against
/// [`EXPECTED_NORMATIVE_PAIR_KEY`] is reported by validation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct NormativePairKey(String);

impl NormativePairKey {
    /// Constructs a validated pair key, rejecting malformed wire text.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        let digest = value.strip_prefix("sha256:").unwrap_or_default();
        if digest.is_empty() {
            return Err(ContractError::InvalidDigest {
                field: "normative_pair_key",
            });
        }
        validate_digest_text(digest, "normative_pair_key")?;
        Ok(Self(value))
    }

    /// Returns the exact pair key this registry value is bound to.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes this key and returns its text.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Returns the currently adopted pair key from `docs/normative-pair.toml`.
    pub fn expected() -> &'static str {
        EXPECTED_NORMATIVE_PAIR_KEY
    }

    /// Returns whether this key matches the currently adopted pair key.
    pub fn is_current(&self) -> bool {
        self.0 == EXPECTED_NORMATIVE_PAIR_KEY
    }
}

impl fmt::Display for NormativePairKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for NormativePairKey {
    type Err = ContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for NormativePairKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NormativePairKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

/// Wire revision of a [`CapabilityCellRegistry`] value.
///
/// Only [`CAPABILITY_CELL_REGISTRY_VERSION`] is accepted; any other revision
/// is rejected at the boundary instead of being upgraded or coerced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct RegistryVersion(u32);

impl RegistryVersion {
    /// Returns the single accepted wire revision.
    pub const fn current() -> Self {
        Self(CAPABILITY_CELL_REGISTRY_VERSION)
    }

    /// Returns the numeric wire revision.
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl Serialize for RegistryVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for RegistryVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        if value == CAPABILITY_CELL_REGISTRY_VERSION {
            Ok(Self(value))
        } else {
            Err(de::Error::custom(ContractError::VersionOutOfRange))
        }
    }
}

/// Where a capability cell executes. The contour is descriptive data only; it
/// never grants runtime, process, or storage ownership to this island.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionContour {
    /// The cell lives in a stateless contracts/primitives island: no mutable
    /// state, no effects, no delegated bundle.
    StatelessIsland,
    /// The cell executes inside a named runtime bundle owned by another cell.
    DelegatedBundle,
    /// The cell executes inline in its host binary under host ownership.
    HostInline,
}

/// Current support claim for a cell. Staleness is recorded as data; this
/// primitive never silently upgrades a stale claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportStatus {
    /// Independently proven at the declared proof ceiling.
    CurrentVerified,
    /// Current but not yet independently proven.
    CurrentUnverified,
    /// Superseded or regenerated-against-newer-evidence; see `invalidation`.
    Stale,
    /// Suspended pending recovery or migration; see `invalidation`.
    Suspended,
}

/// Highest proof level a cell may claim. The ceiling bounds claims; it never
/// substitutes for running the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofCeiling {
    /// Static field and migration contract proof only.
    StaticFieldAndMigrationContractOnly,
    /// Package-local edge proof across one-hop providers and consumers.
    ModuleEdgeProof,
    /// Full product proof in a live contour.
    ProductProof,
}

/// Product Pulse binding for a cell: a direct reference, or an explicit
/// reason the pulse does not apply. There is no implicit waiver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductPulse {
    /// Direct reference to the Product Pulse evidencing this cell.
    Referenced(ProductPulseRef),
    /// Explicit reason no Product Pulse reference exists.
    NotApplicable {
        /// Why the pulse does not apply; never an implicit waiver.
        reason: PulseExemptionReason,
    },
}

/// One owned state value and the single owner accountable for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateOwnershipEntry {
    /// The owned state value.
    pub state: CellStateName,
    /// The single owner accountable for that state.
    pub owner: CellOwnerRef,
}

/// Current support and invalidation set for a cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CellFreshness {
    /// Current support claim for the cell.
    pub current_support: SupportStatus,
    /// Reasons invalidating the current support claim; empty when none apply.
    pub invalidation: Vec<InvalidationReason>,
}

/// Presence of one capsule of the mandatory `I2.20` triad.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsulePresence {
    /// Whether the capsule is present and executable for this cell.
    pub present: bool,
    /// Owner declaring the capsule; required whenever `present` is true.
    pub owner: Option<CellOwnerRef>,
}

/// The mandatory `ModuleContractKit` + `CrateContextCapsule` +
/// `ModuleTestCapsule` triad for one functional capability cell.
///
/// One manifest represents one cell. A missing capsule is a registry defect,
/// not an acceptable variant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveMicroModuleManifest {
    /// Contract kit presence: without it the cell boundary is undefined.
    pub contract_kit: CapsulePresence,
    /// Context capsule presence: without it no decision-sufficient workset exists.
    pub context_capsule: CapsulePresence,
    /// Test capsule presence: without it no independently invocable proof exists.
    pub test_capsule: CapsulePresence,
}

/// Provenance a registry value was generated from: source tree, lockfile,
/// toolchain, and generator version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistrySourceIdentity {
    /// Digest of the source tree the registry was generated from.
    pub tree_digest: ContractDigest,
    /// Digest of the Cargo lockfile the registry was generated from.
    pub cargo_lock_digest: ContractDigest,
    /// Exact machine toolchain the registry was generated with.
    pub toolchain: ToolchainRef,
    /// Generator version that emitted the registry value.
    pub generator_version: GeneratorVersion,
}

/// One enumerated functional capability cell: owners, state or explicit
/// statelessness, effects, execution contour, replacement class, proof
/// entrypoint and ceiling, edges, pulse, freshness, and triad manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCellRecord {
    /// Cell identity within [`CAPABILITY_CELL_REGISTRY_NAMESPACE`].
    pub cell: CapabilityCellId,
    /// Revision of the cell contract surface.
    pub cell_revision: ContractVersion,
    /// Owner accountable for the cell lifecycle.
    pub lifecycle_owner: CellOwnerRef,
    /// Owner accountable for source maintenance of the cell.
    pub maintenance_owner: CellOwnerRef,
    /// Owner accountable for the cell semantics.
    pub semantic_owner: CellOwnerRef,
    /// Owner accountable for generation and promotion inputs of the cell.
    pub generation_owner: CellOwnerRef,
    /// True when the cell owns no mutable state; then `state_owners` is empty.
    pub stateless: bool,
    /// One entry per owned state value naming its single owning cell owner.
    pub state_owners: Vec<StateOwnershipEntry>,
    /// Digest of the cell public contract surface.
    pub contract_digest: ContractDigest,
    /// Where `contract_digest` was observed.
    pub contract_digest_source: DigestSourceRef,
    /// Named runtime bundle hosting the cell, when execution is delegated.
    pub runtime_bundle: Option<RuntimeBundleId>,
    /// Where the cell executes.
    pub execution_contour: ExecutionContour,
    /// Effect classes the cell may exercise; empty for a stateless island.
    pub allowed_effect_classes: Vec<EffectClass>,
    /// Replacement class from the closed [`KNOWN_REPLACEMENT_CLASSES`] vocabulary.
    pub replacement_class: ReplacementClass,
    /// Boundary governing removal or rollback of the cell.
    pub removal_boundary: RemovalBoundaryRef,
    /// Independently invokable proof entrypoint; absent means no proof.
    pub proof_entrypoint: Option<ProofEntrypointRef>,
    /// Highest proof level this cell may claim.
    pub proof_ceiling: ProofCeiling,
    /// One-hop provider and consumer cell references.
    pub affected_edges: Vec<CapabilityCellId>,
    /// Product Pulse reference or an explicit reason it does not apply.
    pub product_pulse: ProductPulse,
    /// Current support and invalidation set.
    pub freshness: CellFreshness,
    /// Cargo package hosting the cell source; never a source of authority.
    pub source_crate: SourceCrateRef,
    /// The mandatory contract/context/test triad manifest for this cell.
    pub manifest: EffectiveMicroModuleManifest,
}

/// Generated, versioned registry of functional capability cells.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCellRegistry {
    /// Wire revision; only [`CAPABILITY_CELL_REGISTRY_VERSION`] is accepted.
    pub registry_version: RegistryVersion,
    /// Exact normative pair key; stale keys fail closed.
    pub pair_key: NormativePairKey,
    /// Source tree, lockfile, toolchain, and generator provenance.
    pub source_identity: RegistrySourceIdentity,
    /// Generator version that emitted this registry value.
    pub generator_version: GeneratorVersion,
    /// One record per enumerated cell.
    pub cells: Vec<CapabilityCellRecord>,
}

/// One fail-closed registry defect. Any diagnostic fails the whole registry;
/// diagnostics are never promoted, downgraded, or silently dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistryDiagnostic {
    /// A cell id is claimed twice, or one state value names two owners.
    DuplicateOwner {
        /// Cell carrying the duplicate claim.
        cell: String,
        /// Which identity collided and how.
        detail: String,
    },
    /// A present capsule or delegated execution names no declaring owner.
    MissingOwner {
        /// Cell with the missing owner.
        cell: String,
        /// Which owner is missing and where it was required.
        detail: String,
    },
    /// The registry is bound to a superseded normative pair.
    StalePairIdentity {
        /// Adopted pair key from `docs/normative-pair.toml`.
        expected: String,
        /// Pair key carried by the registry value.
        found: String,
    },
    /// The registry generator version disagrees with its source identity.
    StaleSourceIdentity {
        /// Generator version recorded in the source identity.
        expected: String,
        /// Generator version carried by the registry value.
        found: String,
    },
    /// A cell has no proof entrypoint, or its manifest triad is incomplete.
    MissingProof {
        /// Cell without proof.
        cell: String,
        /// Which entrypoint or capsule is missing.
        detail: String,
    },
    /// A stateful cell declares no owned state, or a stateless cell does.
    UndeclaredState {
        /// Cell with the incoherent state declaration.
        cell: String,
        /// How the `stateless` flag contradicts `state_owners`.
        detail: String,
    },
    /// An owner reference repeats the hosting crate name instead of naming an
    /// explicitly declared owner. Crate names never confer authority.
    InferredAuthority {
        /// Cell with the crate-derived owner.
        cell: String,
        /// Owner text matching the crate name.
        owner: String,
        /// Hosting crate the owner was derived from.
        source_crate: String,
    },
    /// A replacement class outside [`KNOWN_REPLACEMENT_CLASSES`].
    UnknownReplacementClass {
        /// Cell carrying the unknown class.
        cell: String,
        /// Replacement class text that was rejected.
        found: String,
    },
    /// A stateless cell claims a runtime bundle or effect classes.
    RuntimeOverclaim {
        /// Cell making the claim.
        cell: String,
        /// Which bundle or effect classes were claimed.
        detail: String,
    },
}

/// Fail-closed validation failure carrying every [`RegistryDiagnostic`]
/// found. Returned by [`CapabilityCellRegistry::validate`] whenever at least
/// one diagnostic exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValidationError {
    diagnostics: Vec<RegistryDiagnostic>,
}

impl RegistryValidationError {
    /// Returns every diagnostic that failed validation, in discovery order.
    pub fn diagnostics(&self) -> &[RegistryDiagnostic] {
        &self.diagnostics
    }

    /// Consumes this error and returns its diagnostics.
    pub fn into_diagnostics(self) -> Vec<RegistryDiagnostic> {
        self.diagnostics
    }
}

impl fmt::Display for RegistryValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capability cell registry rejected with {} diagnostic(s)",
            self.diagnostics.len()
        )
    }
}

impl std::error::Error for RegistryValidationError {}

#[derive(Serialize)]
struct RegistryDigestInput<'a> {
    namespace: &'static str,
    registry: &'a CapabilityCellRegistry,
}

impl CapabilityCellRegistry {
    /// Returns deterministic canonical bytes for this registry value.
    ///
    /// Object keys are sorted recursively and the registry namespace is
    /// bound into the bytes, so generating twice over equal input is
    /// byte-identical without any clock, process id, or map ordering input.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let input = RegistryDigestInput {
            namespace: CAPABILITY_CELL_REGISTRY_NAMESPACE,
            registry: self,
        };
        canonical_json_bytes(&input)
    }

    /// Returns the lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    pub fn registry_digest(&self) -> Result<String, serde_json::Error> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    /// Validates every record and the registry binding, failing closed.
    ///
    /// Returns `Ok(())` only when zero diagnostics exist; any diagnostic —
    /// stale pair or source identity, duplicate or missing owner, missing
    /// proof, undeclared state, inferred authority, unknown replacement
    /// class, or runtime overclaim — returns `Err` with all findings.
    pub fn validate(&self) -> Result<(), RegistryValidationError> {
        let mut diagnostics = Vec::new();
        if !self.pair_key.is_current() {
            diagnostics.push(RegistryDiagnostic::StalePairIdentity {
                expected: EXPECTED_NORMATIVE_PAIR_KEY.to_owned(),
                found: self.pair_key.as_str().to_owned(),
            });
        }
        if self.generator_version.as_str() != self.source_identity.generator_version.as_str() {
            diagnostics.push(RegistryDiagnostic::StaleSourceIdentity {
                expected: self.source_identity.generator_version.as_str().to_owned(),
                found: self.generator_version.as_str().to_owned(),
            });
        }
        push_duplicate_cells(&self.cells, &mut diagnostics);
        for record in &self.cells {
            validate_record(record, &mut diagnostics);
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(RegistryValidationError { diagnostics })
        }
    }
}

fn push_duplicate_cells(cells: &[CapabilityCellRecord], diagnostics: &mut Vec<RegistryDiagnostic>) {
    let mut index = 0;
    while index < cells.len() {
        let mut next = index + 1;
        while next < cells.len() {
            if cells[index].cell.as_str() == cells[next].cell.as_str() {
                diagnostics.push(RegistryDiagnostic::DuplicateOwner {
                    cell: cells[index].cell.as_str().to_owned(),
                    detail: "cell id claimed by more than one record".to_owned(),
                });
            }
            next += 1;
        }
        index += 1;
    }
}

fn authority_key(value: &str) -> String {
    value.to_lowercase().replace('_', "-")
}

fn owner_is_crate_derived(owner: &CellOwnerRef, source_crate: &SourceCrateRef) -> bool {
    authority_key(owner.as_str()) == authority_key(source_crate.as_str())
}

fn validate_record(record: &CapabilityCellRecord, diagnostics: &mut Vec<RegistryDiagnostic>) {
    let cell = record.cell.as_str().to_owned();
    if record.stateless && !record.state_owners.is_empty() {
        diagnostics.push(RegistryDiagnostic::UndeclaredState {
            cell: cell.clone(),
            detail: format!(
                "stateless cell declares {} state owner(s)",
                record.state_owners.len()
            ),
        });
    } else if !record.stateless && record.state_owners.is_empty() {
        diagnostics.push(RegistryDiagnostic::UndeclaredState {
            cell: cell.clone(),
            detail: "stateful cell declares no owned state".to_owned(),
        });
    }
    let mut index = 0;
    while index < record.state_owners.len() {
        let mut next = index + 1;
        while next < record.state_owners.len() {
            let current = &record.state_owners[index];
            let other = &record.state_owners[next];
            if current.state.as_str() == other.state.as_str() {
                diagnostics.push(RegistryDiagnostic::DuplicateOwner {
                    cell: cell.clone(),
                    detail: format!(
                        "state '{}' claimed by '{}' and '{}'",
                        current.state.as_str(),
                        current.owner.as_str(),
                        other.owner.as_str()
                    ),
                });
            }
            next += 1;
        }
        index += 1;
    }
    let declared = [
        &record.lifecycle_owner,
        &record.maintenance_owner,
        &record.semantic_owner,
        &record.generation_owner,
    ];
    for owner in declared {
        if owner_is_crate_derived(owner, &record.source_crate) {
            diagnostics.push(RegistryDiagnostic::InferredAuthority {
                cell: cell.clone(),
                owner: owner.as_str().to_owned(),
                source_crate: record.source_crate.as_str().to_owned(),
            });
        }
    }
    if !KNOWN_REPLACEMENT_CLASSES.contains(&record.replacement_class.as_str()) {
        diagnostics.push(RegistryDiagnostic::UnknownReplacementClass {
            cell: cell.clone(),
            found: record.replacement_class.as_str().to_owned(),
        });
    }
    if record.stateless
        && (record.runtime_bundle.is_some() || !record.allowed_effect_classes.is_empty())
    {
        diagnostics.push(RegistryDiagnostic::RuntimeOverclaim {
            cell: cell.clone(),
            detail: "stateless cell claims a runtime bundle or effect classes".to_owned(),
        });
    }
    if record.proof_entrypoint.is_none() {
        diagnostics.push(RegistryDiagnostic::MissingProof {
            cell: cell.clone(),
            detail: "no independently invokable proof entrypoint".to_owned(),
        });
    }
    validate_manifest(&cell, &record.manifest, diagnostics);
}

fn validate_manifest(
    cell: &str,
    manifest: &EffectiveMicroModuleManifest,
    diagnostics: &mut Vec<RegistryDiagnostic>,
) {
    validate_capsule(
        cell,
        "module-contract-kit",
        &manifest.contract_kit,
        diagnostics,
    );
    validate_capsule(
        cell,
        "crate-context-capsule",
        &manifest.context_capsule,
        diagnostics,
    );
    validate_capsule(
        cell,
        "module-test-capsule",
        &manifest.test_capsule,
        diagnostics,
    );
}

fn validate_capsule(
    cell: &str,
    capsule: &'static str,
    presence: &CapsulePresence,
    diagnostics: &mut Vec<RegistryDiagnostic>,
) {
    if !presence.present {
        diagnostics.push(RegistryDiagnostic::MissingProof {
            cell: cell.to_owned(),
            detail: format!("{capsule} absent: manifest triad is incomplete"),
        });
    } else if presence.owner.is_none() {
        diagnostics.push(RegistryDiagnostic::MissingOwner {
            cell: cell.to_owned(),
            detail: format!("{capsule} present without a declaring owner"),
        });
    }
}
