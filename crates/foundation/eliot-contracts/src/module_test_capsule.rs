//! Executable, versioned `ModuleTestCapsule` revisions bound to capability cells.
//!
//! This module is the owner-neutral foundation primitive for issue #1804: it
//! answers "which exact test capsule proves this cell, and how is it invoked"
//! as validated data. It owns no runtime, process, storage, provider, or UI
//! behavior; every check below rejects ambiguous or stale input at the
//! boundary and never manufactures authority.
//!
//! Owner map (consume, never recreate):
//!
//! * #13 owns the capability-cell registry
//!   ([`CapabilityCellRecord`](crate::CapabilityCellRecord)); this module only
//!   adds the executable binding ([`CellCapsuleBinding`]) a record carries.
//! * #1811 owns standalone-package dispositions; they arrive here as consumed
//!   evidence ([`ConsumedDisposition`]), never re-decided.
//! * #1802 owns discovery, profile execution, and the evidence path; it
//!   supplies the inventory snapshot ([`CapsuleInventorySnapshot`]) this module
//!   resolves against through the small [`resolve_capsule`] interface.
//! * #1803 owns impact selection; the graph projection references the same
//!   capsule revision by digest instead of a separately edited copy.
//! * Class-specific payloads stay under their current owner (for example the
//!   WASM [`ModuleTestCapsule`](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/main/crates/modules/eliot-wasm-runtime/src/capsule.rs)
//!   in `eliot-wasm-runtime`); this module carries only the shared descriptor
//!   plus an opaque class-payload digest, so native services are never forced
//!   into a WASM-shaped descriptor.
//!
//! Identity and namespace rules:
//!
//! * The capsule namespace is [`MODULE_TEST_CAPSULE_NAMESPACE`]; a cell,
//!   digest, or selector with identical spelling from another namespace is not
//!   equal to a value of this family.
//! * One capsule revision describes one cell (`I2.20`): a crate hosting
//!   several cells has several revisions, and each result attributes to the
//!   exact cell and selected tests, never to all cells sharing a package.
//! * Canonical bytes bind the namespace and use recursively sorted object
//!   keys, so generating twice over equal input is byte-identical without any
//!   clock, process id, or hash-map iteration order.
//! * No arbitrary command string is executable authority anywhere in this
//!   module: selectors are typed package/binary/test values, profiles resolve
//!   through the Instrument Registry, and a declared `proof_entrypoint` string
//!   or `present=true` flag can never override resolution.
//! * Binary dependency reachability is not a field here and therefore cannot
//!   be misread as proof of runtime invocation or of death.
//!
//! Seven-step coverage (issue #1804):
//!
//! 1. [`CapsuleDenominator`] records per-package/cell supported execution and
//!    capsule bindings over an explicit candidate, target, features, and
//!    admitted runtime bundles. No historical counts are hardcoded, and
//!    validation never adds or removes entries.
//! 2. [`ExecutableModuleTestCapsuleRevision`] is the one executable revision,
//!    not a Boolean: cell/contract revision, source package, proof class,
//!    exact profile plus typed selector, target/features, fixture/oracle
//!    references, declared services/resources, timeout/cleanup/serial policy,
//!    expected discovery rule, proof ceiling, and retirement/invalidation.
//! 3. [`resolve_capsule`] connects declared selectors to actual discovery.
//!    A missing package/selector, stale fixture/oracle, unsupported feature,
//!    or empty expected-nonzero selection is an explicit [`CapsuleUnavailable`]
//!    value. Unknown discovery is not zero.
//! 4. [`ProofClass::minimum_proof`] applies `I18.7` per class instead of one
//!    template. Resolution starts from existing inventory tests only and adds
//!    no test; cross-cell edge proof stays with the relation owner.
//! 5. [`DeclaredServices`] plus the proof-class service rule make independence
//!    checkable: a pure capsule claiming services is rejected at the boundary,
//!    and a service capsule may name only its declared owned fixtures.
//! 6. [`compile_catalogue`] publishes bound revisions with deterministic
//!    ordering, source/generator identities, and findings. A missing capsule
//!    is a [`CapsuleFinding`] with an owner, never a fabricated entry;
//!    conflicting duplicates and stale input are rejected, never
//!    last-write-wins.
//! 7. [`CapsuleExecutionEvidence`] retains actual execution: capsule/profile
//!    revision, candidate, discovered/selected/executed identities, bindings,
//!    raw artifacts, outcome, and cleanup. Expected-nonzero with zero execution
//!    cannot validate; capture, success, and admission stay distinct fields;
//!    a replay carries no execution; an oracle change requires the separate
//!    oracle review (`I18.7`).

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::{
    ArtifactId, CapabilityCellId, CellOwnerRef, ContractDigest, ContractError, ContractVersion,
    GeneratorVersion, InvalidationReason, ProofCeiling, RegistrySourceIdentity, RuntimeBundleId,
    canonical_json_bytes, sha256_hex,
};

/// Stable contract name for the owner-neutral module-test-capsule family.
pub const MODULE_TEST_CAPSULE_CONTRACT_NAME: &str = "eliot.foundation.module-test-capsule";
/// Exact namespace tag carried by every value of this family.
///
/// The namespace tag — not the spelling of any single field — determines this
/// identity family. Identical spelling from another namespace is never equal.
pub const MODULE_TEST_CAPSULE_NAMESPACE: &str = "eliot.foundation.module-test-capsule";
/// Semantic version of the module-test-capsule contract surface.
pub const MODULE_TEST_CAPSULE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Wire revision carried by every [`ExecutableModuleTestCapsuleRevision`] value.
pub const MODULE_TEST_CAPSULE_VERSION: u32 = 1;
/// Disposition verbs admitted by issue #1811 at the time of writing.
///
/// The vocabulary is owned by #1811; this list is a local readability helper
/// for [`ConsumedDisposition::is_admitted_verb`]. An unknown verb is preserved
/// as evidence, never re-decided or rejected here.
pub const KNOWN_EXTERNAL_DISPOSITIONS: &[&str] = &[
    "KEEP", "WRAP", "EXTRACT", "REWORK", "REPLACE", "RETIRE", "UNKNOWN",
];

macro_rules! capsule_string {
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

capsule_string!(
    /// Identity of one executable module test capsule revision.
    ModuleTestCapsuleId, "capsule_id");
capsule_string!(
    /// Producer revision that emitted a capsule value: generator plus source
    /// binding. The descriptor content and this producer revision together
    /// determine the capsule digest.
    CapsuleProducerRef, "capsule_producer");
capsule_string!(
    /// Exact Instrument profile name a capsule executes through. The name
    /// resolves through the Instrument Registry at bind time; unknown names
    /// are unavailable, never silently promoted.
    CapsuleProfileRef, "capsule_profile");
capsule_string!(
    /// Cargo package hosting a capsule's source and tests. Packaging never
    /// transfers lifecycle authority between cells.
    CapsulePackageRef, "capsule_package");
capsule_string!(
    /// One test binary within a capsule selector, as discovered by nextest
    /// list. Never a command string.
    CapsuleBinaryRef, "capsule_binary");
capsule_string!(
    /// One test identity within a capsule selector, as discovered by nextest
    /// list. Never a command string.
    CapsuleTestRef, "capsule_test");
capsule_string!(
    /// Compilation target a capsule revision is bound to.
    CapsuleTargetRef, "capsule_target");
capsule_string!(
    /// One Cargo feature a capsule revision requires.
    CapsuleFeatureRef, "capsule_feature");
capsule_string!(
    /// Reference to the versioned fixture set a capsule executes against.
    FixtureRef, "fixture_ref");
capsule_string!(
    /// Reference to the expected oracle a capsule compares against. Oracle
    /// content changes require the separate oracle review (`I18.7`).
    OracleRef, "oracle_ref");
capsule_string!(
    /// Reference to the separate oracle review evidencing an oracle change.
    /// Approving implementation and oracle in one step is rejected.
    OracleReviewRef, "oracle_review");
capsule_string!(
    /// One owned fixture service a service-class capsule may start. Only
    /// declared owned fixtures may start; unrelated production services are
    /// never started for any capsule, and pure-class capsules name none.
    CapsuleServiceRef, "capsule_service");
capsule_string!(
    /// One resource class a capsule execution may consume.
    CapsuleResourceRef, "capsule_resource");
capsule_string!(
    /// Serial group a capsule executes in. Capsules sharing a group never run
    /// concurrently; capsules without a group follow the profile default.
    CapsuleSerialGroupRef, "capsule_serial_group");
capsule_string!(
    /// Candidate identity a denominator or evidence value is bound to.
    CapsuleCandidateRef, "capsule_candidate");
capsule_string!(
    /// Reason retiring or invalidating a capsule revision.
    RetirementReason, "retirement_reason");
capsule_string!(
    /// Explicit reason for a capsule disposition or catalogue finding.
    DispositionReason, "disposition_reason");
capsule_string!(
    /// Explicit reason a discovered test was omitted from selection.
    CapsuleOmissionReason, "omission_reason");
capsule_string!(
    /// Standalone-package disposition verb consumed verbatim from issue #1811.
    /// The wire stays open so future #1811 verbs are loss-visible.
    ExternalDispositionVerb, "external_disposition_verb");
capsule_string!(
    /// Source record an external disposition was consumed from.
    DispositionSourceRef, "disposition_source");

/// Wire revision of an [`ExecutableModuleTestCapsuleRevision`] value.
///
/// Only [`MODULE_TEST_CAPSULE_VERSION`] is accepted; any other revision is
/// rejected at the boundary instead of being upgraded or coerced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[schemars(transparent)]
pub struct CapsuleVersion(u32);

impl CapsuleVersion {
    /// Returns the single accepted wire revision.
    pub const fn current() -> Self {
        Self(MODULE_TEST_CAPSULE_VERSION)
    }

    /// Returns the numeric wire revision.
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl Serialize for CapsuleVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for CapsuleVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        if value == MODULE_TEST_CAPSULE_VERSION {
            Ok(Self(value))
        } else {
            Err(de::Error::custom(ContractError::VersionOutOfRange))
        }
    }
}

/// Crate/micro-module class from the `I18.7` minimum-proof table.
///
/// The class selects the minimum proof shape; it never selects a single
/// shared template. Class-specific payloads stay under their current owner;
/// only the shared descriptor lives in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofClass {
    /// Schema/serialization/compatibility/property proof; no runtime.
    FoundationContract,
    /// Unit, property, and adversarial boundary cases; no runtime.
    PureCore,
    /// Transition model, replay, stale revision/epoch, and cancellation.
    StateMachine,
    /// Golden corpus, unknown fields, truncation, non-UTF-8, and fuzz.
    ParserNormalizer,
    /// Fake-executor stage graph plus the exact real-tool fixture.
    ProfileRecipe,
    /// Service contract, restart/replay, and no hidden state owner.
    StatefulService,
    /// Handshake, identity, streams, cancel, cleanup, and fault boundary.
    ProcessAdapter,
    /// Semantic invariants plus snapshot/accessibility where applicable.
    ProjectionRenderer,
    /// Composition/startup/config/health; domain behavior stays in libraries.
    ThinBinary,
}

/// Owner of cross-cell edge proof for capsules of one class.
///
/// Edge proof always stays with the existing relation/scenario owner; it is
/// never duplicated into every participating package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeProofOwner {
    /// The relation/scenario crate owned by the edge, not each participant.
    Relation,
}

/// Minimum `I18.7` proof shape for one [`ProofClass`].
///
/// Derived data, not wire state: [`ProofClass::minimum_proof`] computes it, so
/// no producer can declare a weaker minimum for its class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimumProof {
    /// Whether the minimum proof executes against a live runtime contour.
    /// Pure and foundation classes prove without one.
    pub requires_runtime: bool,
    /// Whether the capsule may declare owned fixture services. Only service
    /// classes may; every other class is rejected when it names any service.
    pub allows_services: bool,
    /// Owner of cross-cell edge proof: always the relation owner.
    pub edge_owner: EdgeProofOwner,
}

impl ProofClass {
    /// Returns the `I18.7` minimum proof shape for this class.
    pub const fn minimum_proof(self) -> MinimumProof {
        match self {
            Self::StatefulService | Self::ProcessAdapter => MinimumProof {
                requires_runtime: true,
                allows_services: true,
                edge_owner: EdgeProofOwner::Relation,
            },
            Self::FoundationContract
            | Self::PureCore
            | Self::StateMachine
            | Self::ParserNormalizer
            | Self::ProfileRecipe
            | Self::ProjectionRenderer
            | Self::ThinBinary => MinimumProof {
                requires_runtime: false,
                allows_services: false,
                edge_owner: EdgeProofOwner::Relation,
            },
        }
    }
}

/// Supported execution and capsule binding for one cell (step 1 denominator).
///
/// Exactly one variant applies per cell. Production reachability of a binary
/// proves neither runtime invocation nor death, so no variant is inferred
/// from reachability: each binding carries its declaring owner and reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapsuleDisposition {
    /// Production cell with a bound executable capsule revision.
    Production,
    /// Cell scheduled or bundled externally with a bound executable capsule
    /// revision resolvable through its owning scheduler.
    ExternallyScheduled,
    /// Test/tooling-only cell: no production execution is claimed, so no
    /// executable production binding exists.
    TestToolingOnly,
    /// Intentionally excluded cell: no executable binding exists by decision,
    /// not by omission.
    Excluded,
    /// Ownership or support is unresolved: no executable binding exists yet.
    Unresolved,
}

impl CapsuleDisposition {
    /// Whether this disposition carries an executable capsule binding.
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Production | Self::ExternallyScheduled)
    }
}

/// Expected discovery rule for one capsule revision.
///
/// Unknown discovery never satisfies any rule: it resolves to
/// [`CapsuleUnavailableKind::UnknownDiscovery`], never to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExpectedDiscovery {
    /// At least one test must be discovered, selected, and executed. Zero
    /// execution cannot pass.
    ExpectedNonZero,
    /// Zero selection is acceptable for this revision.
    AllowZero,
    /// Static compilation stages only; no test execution is claimed. A
    /// successful compile-only stage is never a successful test run.
    CompileOnly,
}

/// One proof stage class bound by a capsule.
///
/// Static compilation stages stay distinct from test stages in the descriptor,
/// the selection, and the retained evidence.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapsuleStage {
    /// Static compilation: package must build under the bound target/features.
    StaticCompile,
    /// Test execution: selected tests must run under the bound profile.
    Test,
}

/// Cleanup action for capsule execution roots after a terminal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CleanupAction {
    /// Remove the isolated root.
    Remove,
    /// Retain the isolated root for diagnosis, within the byte limit.
    Retain,
}

/// Fail-closed capsule failure. Any variant refuses the value instead of
/// emitting a defaulted, reordered, or downgraded substitute.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ModuleTestCapsuleError {
    /// A wrapped foundation contract failure.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// A list violates deterministic ordering: not sorted or duplicated.
    #[error("{field} must be sorted and free of duplicates")]
    UnsortedList {
        /// Field carrying the unordered list.
        field: &'static str,
    },
    /// A required capsule declaration is absent.
    #[error("capsule '{capsule}' is missing required declaration '{field}'")]
    MissingField {
        /// Capsule or cell with the missing declaration.
        capsule: String,
        /// Declaration that is absent.
        field: &'static str,
    },
    /// The typed selector names another package than the capsule source.
    #[error(
        "capsule '{capsule}' selector package '{selector}' does not match source package '{source_package}'"
    )]
    SelectorPackageMismatch {
        /// Capsule with the mismatched selector.
        capsule: String,
        /// Package named by the selector.
        selector: String,
        /// Source package bound by the descriptor.
        source_package: String,
    },
    /// A class that forbids services names a fixture service. Pure capsules
    /// never start services.
    #[error("capsule '{capsule}' class forbids services but names '{service}'")]
    PureCapsuleClaimsServices {
        /// Capsule claiming the service.
        capsule: String,
        /// Service that must not be named.
        service: String,
    },
    /// A class-payload digest names no class owner for the payload.
    #[error("capsule '{capsule}' carries a class payload digest without a class owner")]
    ClassPayloadWithoutOwner {
        /// Capsule with the ownerless payload digest.
        capsule: String,
    },
    /// A non-executable disposition carries an executable capsule binding.
    #[error("cell '{cell}' binding mismatch: {detail}")]
    BindingMismatch {
        /// Cell with the mismatched binding.
        cell: String,
        /// How the disposition contradicts the binding.
        detail: String,
    },
    /// Two inputs claim one capsule or cell identity with different content.
    #[error("conflicting duplicate '{capsule}': {detail}")]
    ConflictingDuplicate {
        /// Capsule or cell identity claimed twice.
        capsule: String,
        /// How the claims differ.
        detail: String,
    },
    /// Producer input is retired, invalidated, or otherwise stale.
    #[error("stale capsule input '{capsule}': {detail}")]
    StaleInput {
        /// Stale capsule identity.
        capsule: String,
        /// Why the input is stale.
        detail: String,
    },
    /// A digest could not be constructed at the boundary.
    #[error("capsule digest unavailable: {detail}")]
    DigestFailed {
        /// Underlying digest failure detail.
        detail: String,
    },
    /// Expected-nonzero evidence carries zero executed tests.
    #[error("capsule '{capsule}' expects nonzero execution but executed zero tests")]
    ZeroExecutionWithNonZeroExpectation {
        /// Capsule with the empty execution.
        capsule: String,
    },
    /// A replay of retained evidence carries fresh execution. Replaying a
    /// retained result starts no fixture or test.
    #[error("capsule '{capsule}' replay carries fresh execution")]
    ReplayCarriesExecution {
        /// Capsule with the executing replay.
        capsule: String,
    },
    /// Evidence carries an oracle digest the capsule did not declare without
    /// the separate oracle review.
    #[error("capsule '{capsule}' oracle changed without the separate oracle review")]
    OracleReviewMissing {
        /// Capsule with the unreviewed oracle change.
        capsule: String,
    },
    /// A passing outcome is claimed without retained raw capture.
    #[error("capsule '{capsule}' claims PASS without retained raw capture")]
    CaptureMissingForPass {
        /// Capsule with the uncaptured pass.
        capsule: String,
    },
    /// Evidence does not match the capsule revision it claims.
    #[error("capsule '{capsule}' evidence mismatch: {detail}")]
    EvidenceMismatch {
        /// Capsule with the mismatched evidence.
        capsule: String,
        /// How the evidence diverges.
        detail: String,
    },
}

/// Rejects unordered or duplicated lists so ordering stays deterministic.
fn validate_sorted_unique<T: Ord>(
    items: &[T],
    field: &'static str,
) -> Result<(), ModuleTestCapsuleError> {
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ModuleTestCapsuleError::UnsortedList { field });
    }
    Ok(())
}

/// Typed package/binary/test selector for one capsule revision.
///
/// An empty `binaries` list selects every binary of the package; an empty
/// `tests` list selects every test of the selected binaries. Both lists stay
/// sorted and duplicate-free so selection is deterministic. This selector is
/// the only executable test authority: no command string exists anywhere in
/// this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedTestSelector {
    /// Package under selection; always equals the capsule source package.
    pub package: CapsulePackageRef,
    /// Selected binaries, sorted and duplicate-free.
    pub binaries: Vec<CapsuleBinaryRef>,
    /// Selected tests, sorted and duplicate-free.
    pub tests: Vec<CapsuleTestRef>,
}

impl TypedTestSelector {
    /// Builds a selector with deterministic list ordering.
    pub fn new(
        package: CapsulePackageRef,
        mut binaries: Vec<CapsuleBinaryRef>,
        mut tests: Vec<CapsuleTestRef>,
    ) -> Self {
        binaries.sort();
        binaries.dedup();
        tests.sort();
        tests.dedup();
        Self {
            package,
            binaries,
            tests,
        }
    }

    /// Validates deterministic ordering of a wire value.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::UnsortedList`] when a list is not
    /// sorted or carries duplicates.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.binaries, "selector.binaries")?;
        validate_sorted_unique(&self.tests, "selector.tests")?;
        Ok(())
    }
}

/// Compilation target and required features for one capsule revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleTargetSpec {
    /// Compilation target the revision is bound to.
    pub target: CapsuleTargetRef,
    /// Required Cargo features, sorted and duplicate-free.
    pub features: Vec<CapsuleFeatureRef>,
}

impl CapsuleTargetSpec {
    /// Builds a target spec with deterministic feature ordering.
    pub fn new(target: CapsuleTargetRef, mut features: Vec<CapsuleFeatureRef>) -> Self {
        features.sort();
        features.dedup();
        Self { target, features }
    }

    /// Validates deterministic ordering of a wire value.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::UnsortedList`] when features are not
    /// sorted or carry duplicates.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.features, "target.features")?;
        Ok(())
    }
}

/// Fixture-set reference with the exact digest the capsule executes against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FixtureBinding {
    /// Referenced versioned fixture set.
    pub fixture: FixtureRef,
    /// Exact digest the revision is bound to; drift fails resolution.
    pub digest: ContractDigest,
}

/// Oracle reference with the exact digest and revision under test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OracleBinding {
    /// Referenced expected oracle.
    pub oracle: OracleRef,
    /// Exact digest the revision is bound to; drift fails resolution.
    pub digest: ContractDigest,
    /// Oracle revision the revision is bound to.
    pub revision: ContractVersion,
}

/// Cleanup policy for capsule execution roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupPolicy {
    /// Cleanup after a successful outcome.
    pub on_success: CleanupAction,
    /// Cleanup after any other terminal outcome.
    pub on_failure: CleanupAction,
    /// Maximum retained bytes when any root is retained.
    pub max_retained_bytes: u64,
}

/// Timeout, cleanup, and serial policy for one capsule revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsulePolicy {
    /// Execution timeout in seconds; zero never names a policy.
    pub timeout_secs: u64,
    /// Whether a timeout cancels through the current fence.
    pub cancel_on_timeout: bool,
    /// Serial group the capsule executes in, when serialization applies.
    pub serial_group: Option<CapsuleSerialGroupRef>,
    /// Whether execution takes the serial group exclusively.
    pub exclusive: bool,
    /// Whether execution requires an isolated root. The runner enforces it;
    /// the descriptor only declares it.
    pub isolated_root: bool,
    /// Cleanup policy for execution roots.
    pub cleanup: CleanupPolicy,
}

impl CapsulePolicy {
    /// Validates the policy: the timeout must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::Zero`] when `timeout_secs` is zero.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.timeout_secs == 0 {
            return Err(ModuleTestCapsuleError::Contract(ContractError::Zero {
                field: "policy.timeout_secs",
            }));
        }
        Ok(())
    }
}

/// Declared services, resources, and policy for one capsule revision.
///
/// `services` names only owned fixture dependencies a service-class capsule
/// may start. Cargo compilation dependencies stay allowed implicitly:
/// independence never means dependency-free compilation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredServices {
    /// Owned fixture services, sorted and duplicate-free. Empty for every
    /// class that forbids services.
    pub services: Vec<CapsuleServiceRef>,
    /// Declared resource classes, sorted and duplicate-free.
    pub resources: Vec<CapsuleResourceRef>,
    /// Timeout, cleanup, and serial policy.
    pub policy: CapsulePolicy,
}

impl DeclaredServices {
    /// Validates ordering and policy of a wire value.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::UnsortedList`] for unordered lists,
    /// or the policy failure.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.services, "services.services")?;
        validate_sorted_unique(&self.resources, "services.resources")?;
        self.policy.validate()?;
        Ok(())
    }
}

/// Retirement record for a superseded capsule revision.
///
/// A retired revision never dispatches: resolution reports it as stale, and
/// catalogue compilation rejects it as producer input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleRetirement {
    /// Why the revision retired.
    pub reason: RetirementReason,
    /// Successor revision, when one is already bound.
    pub superseded_by: Option<ModuleTestCapsuleId>,
}

/// Standalone-package disposition consumed verbatim from issue #1811.
///
/// #1811 owns the verb vocabulary and the promotion decision; this record is
/// read-only evidence attached to the denominator binding. It never admits,
/// removes, or promotes any package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsumedDisposition {
    /// Disposition verb exactly as #1811 records it.
    pub verb: ExternalDispositionVerb,
    /// Source record the verb was consumed from.
    pub source: DispositionSourceRef,
}

impl ConsumedDisposition {
    /// Whether the consumed verb is in the admitted #1811 vocabulary.
    ///
    /// An unknown verb stays preserved as evidence; this helper only reports
    /// membership and never re-decides the disposition.
    pub fn is_admitted_verb(&self) -> bool {
        KNOWN_EXTERNAL_DISPOSITIONS.contains(&self.verb.as_str())
    }
}

/// Executable capsule binding carried by one capability-cell record.
///
/// The binding records supported execution for the cell: an executable
/// disposition always names the exact bound capsule digest, while
/// test-only, excluded, and unresolved dispositions carry an explicit reason
/// instead of a digest. A missing binding on an old record is preserved wire
/// state, not an error; the catalogue reports missing capsules as findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CellCapsuleBinding {
    /// Supported execution for the cell.
    pub disposition: CapsuleDisposition,
    /// Digest of the bound executable capsule revision. Present exactly for
    /// executable dispositions.
    pub capsule_digest: Option<ContractDigest>,
    /// Owner declaring this binding.
    pub owner: CellOwnerRef,
    /// Explicit reason for the disposition.
    pub reason: DispositionReason,
    /// Consumed #1811 disposition, when the cell packages through a
    /// standalone-workspace crate.
    pub external_disposition: Option<ConsumedDisposition>,
}

impl CellCapsuleBinding {
    /// Validates the binding for one cell: executable dispositions require a
    /// digest, and non-executable dispositions must not carry one.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::MissingField`] when an executable
    /// disposition names no digest, or
    /// [`ModuleTestCapsuleError::BindingMismatch`] when a non-executable
    /// disposition carries one.
    pub fn validate(&self, cell: &str) -> Result<(), ModuleTestCapsuleError> {
        if self.disposition.is_executable() {
            if self.capsule_digest.is_none() {
                return Err(ModuleTestCapsuleError::MissingField {
                    capsule: cell.to_owned(),
                    field: "capsule_digest",
                });
            }
        } else if self.capsule_digest.is_some() {
            return Err(ModuleTestCapsuleError::BindingMismatch {
                cell: cell.to_owned(),
                detail: "non-executable disposition carries an executable capsule digest"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

/// One executable module test capsule revision for one capability cell.
///
/// This is the executable authority: cell/contract revision, source package,
/// proof class, exact profile plus typed selector, target/features,
/// fixture/oracle references, declared services/resources, policy, expected
/// discovery rule, proof ceiling, and retirement/invalidation. Shared fields
/// live here in the neutral owner; class-specific payloads stay under their
/// current owner behind [`Self::class_payload_digest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutableModuleTestCapsuleRevision {
    /// Capsule identity within [`MODULE_TEST_CAPSULE_NAMESPACE`].
    pub capsule: ModuleTestCapsuleId,
    /// Wire revision; only [`MODULE_TEST_CAPSULE_VERSION`] is accepted.
    pub capsule_version: CapsuleVersion,
    /// Cell this revision proves. One revision proves one cell.
    pub cell: CapabilityCellId,
    /// Revision of the cell contract surface under proof.
    pub cell_revision: ContractVersion,
    /// Cargo package hosting the cell source and tests.
    pub source_package: CapsulePackageRef,
    /// `I18.7` proof class selecting the minimum proof shape.
    pub proof_class: ProofClass,
    /// Exact Instrument profile name; resolves through the registry.
    pub profile: CapsuleProfileRef,
    /// Exact admitted profile revision; zero never names a revision.
    pub profile_revision: u64,
    /// Typed package/binary/test selector. No command string exists.
    pub selector: TypedTestSelector,
    /// Compilation target and required features.
    pub target: CapsuleTargetSpec,
    /// Declared stage classes, non-empty, sorted, and duplicate-free. Static
    /// compilation and test execution stay distinct stages.
    pub stages: Vec<CapsuleStage>,
    /// Fixture-set binding under execution.
    pub fixture: FixtureBinding,
    /// Oracle binding under test.
    pub oracle: OracleBinding,
    /// Declared services, resources, and policy.
    pub services: DeclaredServices,
    /// Expected discovery rule enforced at resolution and in evidence.
    pub expected_discovery: ExpectedDiscovery,
    /// Highest proof level this capsule may claim. The ceiling bounds claims;
    /// it never substitutes for running the proof, and naming a production
    /// trait never raises it.
    pub proof_ceiling: ProofCeiling,
    /// Producer revision that emitted this descriptor.
    pub producer: CapsuleProducerRef,
    /// Generator version that emitted this descriptor.
    pub generator_version: GeneratorVersion,
    /// Owner of the class-specific payload, when one exists.
    pub class_owner: Option<CellOwnerRef>,
    /// Digest of the opaque class-specific payload kept under its current
    /// owner. Requires [`Self::class_owner`].
    pub class_payload_digest: Option<ContractDigest>,
    /// Retirement record; a retired revision never dispatches.
    pub retirement: Option<CapsuleRetirement>,
    /// Reasons invalidating this revision; a non-empty set never dispatches.
    pub invalidation: Vec<InvalidationReason>,
}

#[derive(Serialize)]
struct CapsuleDigestInput<'a> {
    namespace: &'static str,
    capsule: &'a ExecutableModuleTestCapsuleRevision,
}

impl ExecutableModuleTestCapsuleRevision {
    /// Returns deterministic canonical bytes for this capsule value.
    ///
    /// Object keys are sorted recursively and the capsule namespace is bound
    /// into the bytes, so generating twice over equal input is byte-identical
    /// without any clock, process id, or map ordering input.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let input = CapsuleDigestInput {
            namespace: MODULE_TEST_CAPSULE_NAMESPACE,
            capsule: self,
        };
        canonical_json_bytes(&input)
    }

    /// Returns the lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::DigestFailed`] when canonicalization
    /// fails.
    pub fn capsule_digest(&self) -> Result<String, ModuleTestCapsuleError> {
        self.canonical_bytes()
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| ModuleTestCapsuleError::DigestFailed {
                detail: error.to_string(),
            })
    }

    /// Validates every declaration and cross-field rule, failing closed.
    ///
    /// # Errors
    ///
    /// Returns the first of: a zero profile revision, an unordered list, a
    /// selector/source mismatch, services claimed by a class that forbids
    /// them, a class payload without an owner, or a policy failure.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.profile_revision == 0 {
            return Err(ModuleTestCapsuleError::Contract(ContractError::Zero {
                field: "capsule.profile_revision",
            }));
        }
        self.selector.validate()?;
        self.target.validate()?;
        self.services.validate()?;
        validate_sorted_unique(&self.invalidation, "capsule.invalidation")?;
        self.validate_stages()?;
        self.validate_selector_package()?;
        self.validate_services_for_class()?;
        self.validate_class_payload()?;
        Ok(())
    }

    /// Whether this revision may dispatch: neither retired nor invalidated.
    pub fn is_dispatchable(&self) -> bool {
        self.retirement.is_none() && self.invalidation.is_empty()
    }

    fn validate_stages(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.stages.is_empty() {
            return Err(ModuleTestCapsuleError::MissingField {
                capsule: self.capsule.as_str().to_owned(),
                field: "stages",
            });
        }
        validate_sorted_unique(&self.stages, "capsule.stages")?;
        Ok(())
    }

    fn validate_selector_package(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.selector.package.as_str() != self.source_package.as_str() {
            return Err(ModuleTestCapsuleError::SelectorPackageMismatch {
                capsule: self.capsule.as_str().to_owned(),
                selector: self.selector.package.as_str().to_owned(),
                source_package: self.source_package.as_str().to_owned(),
            });
        }
        Ok(())
    }

    fn validate_services_for_class(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.proof_class.minimum_proof().allows_services {
            return Ok(());
        }
        if let Some(service) = self.services.services.first() {
            return Err(ModuleTestCapsuleError::PureCapsuleClaimsServices {
                capsule: self.capsule.as_str().to_owned(),
                service: service.as_str().to_owned(),
            });
        }
        Ok(())
    }

    fn validate_class_payload(&self) -> Result<(), ModuleTestCapsuleError> {
        if self.class_payload_digest.is_some() && self.class_owner.is_none() {
            return Err(ModuleTestCapsuleError::ClassPayloadWithoutOwner {
                capsule: self.capsule.as_str().to_owned(),
            });
        }
        Ok(())
    }
}

/// One cell entry in a denominator package: the cell plus its binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenominatorCellEntry {
    /// Cell identity within the capability-cell namespace.
    pub cell: CapabilityCellId,
    /// Supported execution and capsule binding for the cell.
    pub binding: CellCapsuleBinding,
}

/// One package entry in the denominator: the package plus every cell it hosts.
///
/// One crate may host several cells; each cell keeps its own binding, and
/// package membership never transfers lifecycle authority between cells.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenominatorPackageEntry {
    /// Cargo package hosting the cells.
    pub package: CapsulePackageRef,
    /// One entry per hosted cell, sorted by cell and duplicate-free.
    pub cells: Vec<DenominatorCellEntry>,
}

/// Current denominator binding candidate, target, features, runtime bundles,
/// and per-package/cell execution (step 1).
///
/// The denominator records what the current producers bind; it invents no
/// support. No historical counts appear here, and validation never adds,
/// removes, or promotes entries: production, externally scheduled, test-only,
/// excluded, and unresolved cells are all retained as declared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleDenominator {
    /// Candidate the denominator is bound to.
    pub candidate: CapsuleCandidateRef,
    /// Target the denominator is bound to.
    pub target: CapsuleTargetRef,
    /// Features the denominator is bound to, sorted and duplicate-free.
    pub features: Vec<CapsuleFeatureRef>,
    /// Admitted runtime bundles hosting delegated execution.
    pub runtime_bundles: Vec<RuntimeBundleId>,
    /// One entry per package, sorted by package and duplicate-free.
    pub packages: Vec<DenominatorPackageEntry>,
}

#[derive(Serialize)]
struct DenominatorDigestInput<'a> {
    namespace: &'static str,
    denominator: &'a CapsuleDenominator,
}

impl CapsuleDenominator {
    /// Returns deterministic canonical bytes for this denominator value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let input = DenominatorDigestInput {
            namespace: MODULE_TEST_CAPSULE_NAMESPACE,
            denominator: self,
        };
        canonical_json_bytes(&input)
    }

    /// Returns the lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::DigestFailed`] when canonicalization
    /// fails.
    pub fn denominator_digest(&self) -> Result<String, ModuleTestCapsuleError> {
        self.canonical_bytes()
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| ModuleTestCapsuleError::DigestFailed {
                detail: error.to_string(),
            })
    }

    /// Validates ordering, uniqueness, and every cell binding, failing closed.
    ///
    /// Validation retains every entry: it never removes unresolved cells and
    /// never admits excluded ones.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::UnsortedList`] for unordered input,
    /// [`ModuleTestCapsuleError::ConflictingDuplicate`] for a twice-claimed
    /// package or cell, or the binding failure.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.features, "denominator.features")?;
        validate_sorted_unique(&self.runtime_bundles, "denominator.runtime_bundles")?;
        let mut previous_package: Option<&str> = None;
        for entry in &self.packages {
            if previous_package.is_some_and(|previous| previous >= entry.package.as_str()) {
                if previous_package == Some(entry.package.as_str()) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: entry.package.as_str().to_owned(),
                        detail: "package claimed by more than one denominator entry".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "denominator.packages",
                });
            }
            previous_package = Some(entry.package.as_str());
            Self::validate_package_cells(entry)?;
        }
        Ok(())
    }

    fn validate_package_cells(
        entry: &DenominatorPackageEntry,
    ) -> Result<(), ModuleTestCapsuleError> {
        let mut previous_cell: Option<&str> = None;
        for cell_entry in &entry.cells {
            let cell = cell_entry.cell.as_str();
            if previous_cell.is_some_and(|previous| previous >= cell) {
                if previous_cell == Some(cell) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: cell.to_owned(),
                        detail: "cell claimed by more than one denominator entry".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "denominator.cells",
                });
            }
            previous_cell = Some(cell);
            cell_entry.binding.validate(cell)?;
        }
        Ok(())
    }
}

/// One test binary discovered in a package, with its tests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredBinary {
    /// Discovered binary identity.
    pub binary: CapsuleBinaryRef,
    /// Discovered test identities, sorted and duplicate-free.
    pub tests: Vec<CapsuleTestRef>,
}

/// One package discovered in the inventory, with its binaries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscoveredPackage {
    /// Discovered package identity.
    pub package: CapsulePackageRef,
    /// Discovered binaries, sorted by binary and duplicate-free.
    pub binaries: Vec<DiscoveredBinary>,
}

/// Observed fixture digest in the inventory snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FixtureDigestEntry {
    /// Observed fixture set.
    pub fixture: FixtureRef,
    /// Observed digest.
    pub digest: ContractDigest,
}

/// Observed oracle digest and revision in the inventory snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OracleDigestEntry {
    /// Observed oracle.
    pub oracle: OracleRef,
    /// Observed digest.
    pub digest: ContractDigest,
    /// Observed revision.
    pub revision: ContractVersion,
}

/// Source-bound test inventory snapshot supplied by #1802 (step 3).
///
/// This is the small agreed interface: #1802 owns discovery and populates the
/// snapshot from `cargo nextest list` plus the metadata overlay, while this
/// module resolves declared selectors against it without waiting for any
/// wider #1802 surface. Only non-discoverable policy lives in the overlay;
/// missing overlay targets are stale metadata, never fabricated entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleInventorySnapshot {
    /// Candidate the snapshot was discovered for.
    pub candidate: CapsuleCandidateRef,
    /// Discovered packages, sorted by package and duplicate-free.
    pub packages: Vec<DiscoveredPackage>,
    /// Supported features, sorted and duplicate-free.
    pub features: Vec<CapsuleFeatureRef>,
    /// Observed fixture digests, sorted by fixture and duplicate-free.
    pub fixture_digests: Vec<FixtureDigestEntry>,
    /// Observed oracle digests, sorted by oracle and duplicate-free.
    pub oracle_digests: Vec<OracleDigestEntry>,
    /// Whether discovery completed. When true, the snapshot establishes
    /// nothing: resolution reports unknown discovery instead of zero.
    pub unknown: bool,
}

#[derive(Serialize)]
struct InventoryDigestInput<'a> {
    namespace: &'static str,
    inventory: &'a CapsuleInventorySnapshot,
}

impl CapsuleInventorySnapshot {
    /// Returns deterministic canonical bytes for this snapshot value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let input = InventoryDigestInput {
            namespace: MODULE_TEST_CAPSULE_NAMESPACE,
            inventory: self,
        };
        canonical_json_bytes(&input)
    }

    /// Returns the lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::DigestFailed`] when canonicalization
    /// fails.
    pub fn inventory_digest(&self) -> Result<String, ModuleTestCapsuleError> {
        self.canonical_bytes()
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| ModuleTestCapsuleError::DigestFailed {
                detail: error.to_string(),
            })
    }

    /// Validates ordering and uniqueness of a wire value, failing closed.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::UnsortedList`] for unordered input or
    /// [`ModuleTestCapsuleError::ConflictingDuplicate`] for twice-claimed
    /// identities.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.features, "inventory.features")?;
        self.validate_packages()?;
        self.validate_fixture_digests()?;
        self.validate_oracle_digests()?;
        Ok(())
    }

    /// Finds one discovered package by identity.
    pub fn package(&self, package: &str) -> Option<&DiscoveredPackage> {
        self.packages
            .iter()
            .find(|candidate| candidate.package.as_str() == package)
    }

    fn validate_packages(&self) -> Result<(), ModuleTestCapsuleError> {
        let mut previous_package: Option<&str> = None;
        for entry in &self.packages {
            if previous_package.is_some_and(|previous| previous >= entry.package.as_str()) {
                if previous_package == Some(entry.package.as_str()) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: entry.package.as_str().to_owned(),
                        detail: "package discovered twice in one snapshot".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "inventory.packages",
                });
            }
            previous_package = Some(entry.package.as_str());
            Self::validate_binaries(entry)?;
        }
        Ok(())
    }

    fn validate_binaries(entry: &DiscoveredPackage) -> Result<(), ModuleTestCapsuleError> {
        let mut previous_binary: Option<&str> = None;
        for binary in &entry.binaries {
            if previous_binary.is_some_and(|previous| previous >= binary.binary.as_str()) {
                if previous_binary == Some(binary.binary.as_str()) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: binary.binary.as_str().to_owned(),
                        detail: "binary discovered twice in one package".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "inventory.binaries",
                });
            }
            previous_binary = Some(binary.binary.as_str());
            validate_sorted_unique(&binary.tests, "inventory.tests")?;
        }
        Ok(())
    }

    fn validate_fixture_digests(&self) -> Result<(), ModuleTestCapsuleError> {
        let mut previous: Option<&str> = None;
        for entry in &self.fixture_digests {
            if previous.is_some_and(|known| known >= entry.fixture.as_str()) {
                if previous == Some(entry.fixture.as_str()) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: entry.fixture.as_str().to_owned(),
                        detail: "fixture digest observed twice in one snapshot".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "inventory.fixture_digests",
                });
            }
            previous = Some(entry.fixture.as_str());
        }
        Ok(())
    }

    fn validate_oracle_digests(&self) -> Result<(), ModuleTestCapsuleError> {
        let mut previous: Option<&str> = None;
        for entry in &self.oracle_digests {
            if previous.is_some_and(|known| known >= entry.oracle.as_str()) {
                if previous == Some(entry.oracle.as_str()) {
                    return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                        capsule: entry.oracle.as_str().to_owned(),
                        detail: "oracle digest observed twice in one snapshot".to_owned(),
                    });
                }
                return Err(ModuleTestCapsuleError::UnsortedList {
                    field: "inventory.oracle_digests",
                });
            }
            previous = Some(entry.oracle.as_str());
        }
        Ok(())
    }
}

/// One test selected for execution, attributed to its exact package/binary.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SelectedTest {
    /// Package containing the test.
    pub package: CapsulePackageRef,
    /// Binary containing the test.
    pub binary: CapsuleBinaryRef,
    /// Selected test identity.
    pub test: CapsuleTestRef,
}

/// One discovered test omitted from selection, with its explicit reason.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct OmittedTest {
    /// Package containing the test.
    pub package: CapsulePackageRef,
    /// Binary containing the test.
    pub binary: CapsuleBinaryRef,
    /// Omitted test identity.
    pub test: CapsuleTestRef,
    /// Why the test was omitted.
    pub reason: CapsuleOmissionReason,
}

/// Bound capsule selection: the executable join of descriptor and discovery.
///
/// The selection identifies the exact cell, capsule digest, profile revision,
/// and nonzero selected set where tests are required, preserving every
/// omitted member with its reason. Counts are always the list lengths, so a
/// count can never diverge from its identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundCapsuleSelection {
    /// Selected capsule identity.
    pub capsule: ModuleTestCapsuleId,
    /// Digest of the exact capsule revision resolved.
    pub capsule_digest: ContractDigest,
    /// Cell under proof.
    pub cell: CapabilityCellId,
    /// Exact profile name; admission is checked by the runner binding.
    pub profile: CapsuleProfileRef,
    /// Exact profile revision; admission is checked by the runner binding.
    pub profile_revision: u64,
    /// Whether this selection covers static compilation only. A compile-only
    /// selection carries no tests and is never a passing test run.
    pub compile_only: bool,
    /// Selected tests, sorted and duplicate-free.
    pub selected: Vec<SelectedTest>,
    /// Omitted discovered tests with reasons, sorted and duplicate-free.
    pub omitted: Vec<OmittedTest>,
    /// Digest of the inventory snapshot resolved against.
    pub inventory_digest: ContractDigest,
}

/// Why a capsule revision is unavailable for execution.
///
/// Every variant is explicit evidence, never a silent pass: a declared
/// `proof_entrypoint` string or `present=true` flag cannot override any of
/// these outcomes because resolution takes no such input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapsuleUnavailableKind {
    /// The selector package is absent from the inventory snapshot.
    MissingPackage,
    /// A selected binary or test is absent from the discovered package.
    MissingSelector,
    /// The observed fixture or oracle digest/revision drifted from the
    /// declared binding.
    StaleFixtureOrOracle,
    /// A required feature is not supported by the snapshot.
    UnsupportedFeature,
    /// An expected-nonzero capsule selected zero tests.
    EmptyExpectedNonZero,
    /// Discovery did not complete; unknown is not zero.
    UnknownDiscovery,
    /// The capsule revision is retired, invalidated, or otherwise stale.
    StaleCapsuleRevision,
    /// The declared profile or revision is not admitted by the Instrument
    /// Registry. Reported by the runner binding, never by resolution.
    ProfileNotAdmitted,
}

/// Explicit unavailable/incomplete capsule outcome with its cause.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleUnavailable {
    /// Capsule that cannot execute.
    pub capsule: ModuleTestCapsuleId,
    /// Cell the capsule would prove.
    pub cell: CapabilityCellId,
    /// Why the capsule is unavailable.
    pub kind: CapsuleUnavailableKind,
    /// Exact cause detail.
    pub detail: String,
}

impl fmt::Display for CapsuleUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "capsule '{}' for cell '{}' is unavailable ({:?}): {}",
            self.capsule.as_str(),
            self.cell.as_str(),
            self.kind,
            self.detail,
        )
    }
}

impl std::error::Error for CapsuleUnavailable {}

fn unavailable(
    capsule: &ExecutableModuleTestCapsuleRevision,
    kind: CapsuleUnavailableKind,
    detail: String,
) -> CapsuleUnavailable {
    CapsuleUnavailable {
        capsule: capsule.capsule.clone(),
        cell: capsule.cell.clone(),
        kind,
        detail,
    }
}

/// Resolves one capsule revision against actual discovery (step 3).
///
/// The join starts from existing inventory tests only: a declared selector
/// can narrow discovery, never invent a test. A missing package/selector,
/// stale fixture/oracle, unsupported feature, unknown discovery, or empty
/// expected-nonzero selection returns an explicit [`CapsuleUnavailable`]
/// value. Selected and omitted members with reasons are preserved in the
/// returned [`BoundCapsuleSelection`].
///
/// Profile admission is not checked here — the Instrument Registry is owned
/// by the runner — but the selected profile and exact revision travel in the
/// selection for the runner binding to admit.
pub fn resolve_capsule(
    capsule: &ExecutableModuleTestCapsuleRevision,
    snapshot: &CapsuleInventorySnapshot,
) -> Result<BoundCapsuleSelection, CapsuleUnavailable> {
    if let Err(error) = capsule.validate() {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            format!("capsule descriptor is stale: {error}"),
        ));
    }
    if let Err(error) = snapshot.validate() {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::UnknownDiscovery,
            format!("inventory snapshot is stale: {error}"),
        ));
    }
    if snapshot.unknown {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::UnknownDiscovery,
            "discovery did not complete; unknown is not zero".to_owned(),
        ));
    }
    if let Some(retirement) = &capsule.retirement {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            format!("capsule retired: {}", retirement.reason.as_str()),
        ));
    }
    if let Some(reason) = capsule.invalidation.first() {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            format!("capsule invalidated: {}", reason.as_str()),
        ));
    }
    check_features(capsule, snapshot)?;
    check_fixture_oracle(capsule, snapshot)?;
    let package = snapshot
        .package(capsule.selector.package.as_str())
        .ok_or_else(|| {
            unavailable(
                capsule,
                CapsuleUnavailableKind::MissingPackage,
                format!(
                    "package '{}' is absent from the inventory snapshot",
                    capsule.selector.package.as_str(),
                ),
            )
        })?;
    resolve_package_selection(capsule, snapshot, package)
}

fn check_features(
    capsule: &ExecutableModuleTestCapsuleRevision,
    snapshot: &CapsuleInventorySnapshot,
) -> Result<(), CapsuleUnavailable> {
    for feature in &capsule.target.features {
        if !snapshot.features.iter().any(|known| known == feature) {
            return Err(unavailable(
                capsule,
                CapsuleUnavailableKind::UnsupportedFeature,
                format!("feature '{}' is not supported", feature.as_str()),
            ));
        }
    }
    Ok(())
}

fn check_fixture_oracle(
    capsule: &ExecutableModuleTestCapsuleRevision,
    snapshot: &CapsuleInventorySnapshot,
) -> Result<(), CapsuleUnavailable> {
    let observed_fixture = snapshot
        .fixture_digests
        .iter()
        .find(|entry| entry.fixture == capsule.fixture.fixture);
    match observed_fixture {
        Some(entry) if entry.digest == capsule.fixture.digest => {}
        Some(entry) => {
            return Err(unavailable(
                capsule,
                CapsuleUnavailableKind::StaleFixtureOrOracle,
                format!(
                    "fixture '{}' digest drifted: declared '{}', observed '{}'",
                    capsule.fixture.fixture.as_str(),
                    capsule.fixture.digest.as_str(),
                    entry.digest.as_str(),
                ),
            ));
        }
        None => {
            return Err(unavailable(
                capsule,
                CapsuleUnavailableKind::StaleFixtureOrOracle,
                format!(
                    "fixture '{}' is absent from the inventory snapshot",
                    capsule.fixture.fixture.as_str(),
                ),
            ));
        }
    }
    let observed_oracle = snapshot
        .oracle_digests
        .iter()
        .find(|entry| entry.oracle == capsule.oracle.oracle);
    match observed_oracle {
        Some(entry)
            if entry.digest == capsule.oracle.digest
                && entry.revision == capsule.oracle.revision => {}
        Some(_) => {
            return Err(unavailable(
                capsule,
                CapsuleUnavailableKind::StaleFixtureOrOracle,
                format!(
                    "oracle '{}' digest or revision drifted from the declared binding",
                    capsule.oracle.oracle.as_str(),
                ),
            ));
        }
        None => {
            return Err(unavailable(
                capsule,
                CapsuleUnavailableKind::StaleFixtureOrOracle,
                format!(
                    "oracle '{}' is absent from the inventory snapshot",
                    capsule.oracle.oracle.as_str(),
                ),
            ));
        }
    }
    Ok(())
}

fn resolve_package_selection(
    capsule: &ExecutableModuleTestCapsuleRevision,
    snapshot: &CapsuleInventorySnapshot,
    package: &DiscoveredPackage,
) -> Result<BoundCapsuleSelection, CapsuleUnavailable> {
    let binaries = select_binaries(capsule, package)?;
    let omission = OmissionReasons::not_matched().map_err(|error| {
        unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            format!("omission reason unavailable: {error}"),
        )
    })?;
    let (selected, omitted) = select_tests(capsule, package, &binaries, &omission)?;
    if matches!(
        capsule.expected_discovery,
        ExpectedDiscovery::ExpectedNonZero
    ) && selected.is_empty()
    {
        return Err(unavailable(
            capsule,
            CapsuleUnavailableKind::EmptyExpectedNonZero,
            "expected-nonzero capsule selected zero tests".to_owned(),
        ));
    }
    let capsule_digest = capsule.capsule_digest().map_err(|error| {
        unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            error.to_string(),
        )
    })?;
    let inventory_digest = snapshot.inventory_digest().map_err(|error| {
        unavailable(
            capsule,
            CapsuleUnavailableKind::UnknownDiscovery,
            error.to_string(),
        )
    })?;
    let capsule_digest = ContractDigest::new(capsule_digest).map_err(|error| {
        unavailable(
            capsule,
            CapsuleUnavailableKind::StaleCapsuleRevision,
            error.to_string(),
        )
    })?;
    let inventory_digest = ContractDigest::new(inventory_digest).map_err(|error| {
        unavailable(
            capsule,
            CapsuleUnavailableKind::UnknownDiscovery,
            error.to_string(),
        )
    })?;
    Ok(BoundCapsuleSelection {
        capsule: capsule.capsule.clone(),
        capsule_digest,
        cell: capsule.cell.clone(),
        profile: capsule.profile.clone(),
        profile_revision: capsule.profile_revision,
        compile_only: matches!(capsule.expected_discovery, ExpectedDiscovery::CompileOnly),
        selected,
        omitted,
        inventory_digest,
    })
}

fn select_binaries<'a>(
    capsule: &ExecutableModuleTestCapsuleRevision,
    package: &'a DiscoveredPackage,
) -> Result<Vec<&'a DiscoveredBinary>, CapsuleUnavailable> {
    if capsule.selector.binaries.is_empty() {
        return Ok(package.binaries.iter().collect());
    }
    let mut selected = Vec::with_capacity(capsule.selector.binaries.len());
    for wanted in &capsule.selector.binaries {
        let found = package
            .binaries
            .iter()
            .find(|binary| binary.binary == *wanted)
            .ok_or_else(|| {
                unavailable(
                    capsule,
                    CapsuleUnavailableKind::MissingSelector,
                    format!(
                        "binary '{}' is absent from discovered package '{}'",
                        wanted.as_str(),
                        package.package.as_str(),
                    ),
                )
            })?;
        selected.push(found);
    }
    Ok(selected)
}

/// Fixed omission reasons for tests discovered but not selected.
///
/// Both literals are validated once here; the defensive error branch reports
/// construction failure as stale input if the literals ever stop validating.
struct OmissionReasons {
    binary_not_selected: CapsuleOmissionReason,
    test_not_matched: CapsuleOmissionReason,
}

impl OmissionReasons {
    fn not_matched() -> Result<Self, ContractError> {
        Ok(Self {
            binary_not_selected: CapsuleOmissionReason::new(
                "binary not selected by the capsule selector",
            )?,
            test_not_matched: CapsuleOmissionReason::new(
                "test not matched by the capsule selector",
            )?,
        })
    }
}

fn select_tests(
    capsule: &ExecutableModuleTestCapsuleRevision,
    package: &DiscoveredPackage,
    binaries: &[&DiscoveredBinary],
    omission: &OmissionReasons,
) -> Result<(Vec<SelectedTest>, Vec<OmittedTest>), CapsuleUnavailable> {
    if matches!(capsule.expected_discovery, ExpectedDiscovery::CompileOnly) {
        return Ok((Vec::new(), Vec::new()));
    }
    if !capsule.selector.tests.is_empty() {
        return select_named_tests(capsule, package, binaries, omission);
    }
    let mut selected = Vec::new();
    for binary in binaries {
        for test in &binary.tests {
            selected.push(SelectedTest {
                package: package.package.clone(),
                binary: binary.binary.clone(),
                test: test.clone(),
            });
        }
    }
    selected.sort_by(|left, right| {
        left.binary
            .as_str()
            .cmp(right.binary.as_str())
            .then_with(|| left.test.as_str().cmp(right.test.as_str()))
    });
    let omitted = omitted_tests(package, binaries, selected.as_slice(), omission);
    Ok((selected, omitted))
}

fn select_named_tests(
    capsule: &ExecutableModuleTestCapsuleRevision,
    package: &DiscoveredPackage,
    binaries: &[&DiscoveredBinary],
    omission: &OmissionReasons,
) -> Result<(Vec<SelectedTest>, Vec<OmittedTest>), CapsuleUnavailable> {
    let mut selected = Vec::with_capacity(capsule.selector.tests.len());
    for wanted in &capsule.selector.tests {
        let mut found = None;
        for binary in binaries {
            if binary.tests.iter().any(|test| test == wanted) {
                found = Some(binary);
                break;
            }
        }
        let binary = found.ok_or_else(|| {
            unavailable(
                capsule,
                CapsuleUnavailableKind::MissingSelector,
                format!(
                    "test '{}' is absent from the selected binaries of package '{}'",
                    wanted.as_str(),
                    package.package.as_str(),
                ),
            )
        })?;
        selected.push(SelectedTest {
            package: package.package.clone(),
            binary: binary.binary.clone(),
            test: wanted.clone(),
        });
    }
    selected.sort_by(|left, right| {
        left.binary
            .as_str()
            .cmp(right.binary.as_str())
            .then_with(|| left.test.as_str().cmp(right.test.as_str()))
    });
    selected.dedup_by(|left, right| left.binary == right.binary && left.test == right.test);
    let omitted = omitted_tests(package, binaries, selected.as_slice(), omission);
    Ok((selected, omitted))
}

/// Collects every discovered test that selection did not take, with reasons.
///
/// Tests in unselected binaries carry the binary reason; tests in selected
/// binaries that the selector did not name carry the test reason. The output
/// is sorted and duplicate-free.
fn omitted_tests(
    package: &DiscoveredPackage,
    binaries: &[&DiscoveredBinary],
    selected: &[SelectedTest],
    omission: &OmissionReasons,
) -> Vec<OmittedTest> {
    let selected_binaries: Vec<&str> = binaries
        .iter()
        .map(|binary| binary.binary.as_str())
        .collect();
    let mut omitted = Vec::new();
    for binary in &package.binaries {
        let binary_selected = selected_binaries.contains(&binary.binary.as_str());
        for test in &binary.tests {
            let taken = selected.iter().any(|entry| {
                entry.binary.as_str() == binary.binary.as_str()
                    && entry.test.as_str() == test.as_str()
            });
            if taken {
                continue;
            }
            let reason = if binary_selected {
                omission.test_not_matched.clone()
            } else {
                omission.binary_not_selected.clone()
            };
            omitted.push(OmittedTest {
                package: package.package.clone(),
                binary: binary.binary.clone(),
                test: test.clone(),
                reason,
            });
        }
    }
    omitted.sort_by(|left, right| {
        left.binary
            .as_str()
            .cmp(right.binary.as_str())
            .then_with(|| left.test.as_str().cmp(right.test.as_str()))
    });
    omitted
}

/// One cell the capsule producer is expected to cover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedCapsule {
    /// Expected cell identity.
    pub cell: CapabilityCellId,
    /// Owner accountable for the missing-capsule finding.
    pub owner: CellOwnerRef,
}

/// Kind of one catalogue finding.
///
/// Findings retain unsupported and missing cells as evidence; they never
/// fabricate a runnable entry.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapsuleFindingKind {
    /// An expected cell has no capsule revision in producer input.
    MissingCapsule,
    /// A capsule revision covers a cell no registry expects.
    UnregisteredCell,
    /// Producer input is retired, invalidated, or otherwise stale.
    StaleInput,
    /// One identity is claimed twice with different content.
    ConflictingDuplicate,
}

/// One catalogue finding with its owning cell and reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleFinding {
    /// Cell the finding concerns.
    pub cell: CapabilityCellId,
    /// Owner accountable for the finding. `None` records explicitly
    /// unresolved ownership.
    pub owner: Option<CellOwnerRef>,
    /// What the finding establishes.
    pub kind: CapsuleFindingKind,
    /// Explicit reason for the finding.
    pub detail: DispositionReason,
}

/// Producer input for catalogue compilation: revisions plus expected cells.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogueInput {
    /// Capsule revisions from the producer.
    pub capsules: Vec<ExecutableModuleTestCapsuleRevision>,
    /// Cells the producer is expected to cover.
    pub expected: Vec<ExpectedCapsule>,
}

/// Published capsule catalogue: bound revisions plus findings (step 6).
///
/// Enumeration retains every revision and every missing/unregistered cell as
/// evidence with deterministic ordering, source/generator identities, and a
/// bound digest. Selection dispatches only currently admissible capsules;
/// the catalogue itself never executes anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleTestCapsuleCatalogue {
    /// Producer revision that emitted this catalogue.
    pub producer: CapsuleProducerRef,
    /// Generator version that emitted this catalogue.
    pub generator_version: GeneratorVersion,
    /// Source tree, lockfile, toolchain, and generator provenance.
    pub source: RegistrySourceIdentity,
    /// Bound revisions, sorted by cell then capsule.
    pub capsules: Vec<ExecutableModuleTestCapsuleRevision>,
    /// Findings for missing/unregistered cells, sorted by cell then kind.
    pub findings: Vec<CapsuleFinding>,
    /// Lowercase SHA-256 hex digest of the canonical catalogue bytes.
    pub catalogue_digest: ContractDigest,
}

#[derive(Serialize)]
struct CatalogueDigestInput<'a> {
    namespace: &'static str,
    catalogue: &'a ModuleTestCapsuleCatalogueDigestBody<'a>,
}

#[derive(Serialize)]
struct ModuleTestCapsuleCatalogueDigestBody<'a> {
    producer: &'a CapsuleProducerRef,
    generator_version: &'a GeneratorVersion,
    source: &'a RegistrySourceIdentity,
    capsules: &'a [ExecutableModuleTestCapsuleRevision],
    findings: &'a [CapsuleFinding],
}

impl ModuleTestCapsuleCatalogue {
    /// Returns deterministic canonical bytes for this catalogue value.
    ///
    /// The digest itself is excluded from the hashed body, so no
    /// self-referential digest exists.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let body = ModuleTestCapsuleCatalogueDigestBody {
            producer: &self.producer,
            generator_version: &self.generator_version,
            source: &self.source,
            capsules: &self.capsules,
            findings: &self.findings,
        };
        let input = CatalogueDigestInput {
            namespace: MODULE_TEST_CAPSULE_NAMESPACE,
            catalogue: &body,
        };
        canonical_json_bytes(&input)
    }

    /// Recomputes the catalogue digest and checks it against the carried one.
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::DigestFailed`] when canonicalization
    /// fails, or [`ModuleTestCapsuleError::EvidenceMismatch`] when the carried
    /// digest does not match. Generated hashes are never hand-edited: a
    /// mismatch fails closed instead of being repaired in place.
    pub fn verify_digest(&self) -> Result<(), ModuleTestCapsuleError> {
        let recomputed = self
            .canonical_bytes()
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| ModuleTestCapsuleError::DigestFailed {
                detail: error.to_string(),
            })?;
        if recomputed != self.catalogue_digest.as_str() {
            return Err(ModuleTestCapsuleError::EvidenceMismatch {
                capsule: "catalogue".to_owned(),
                detail: "carried catalogue digest does not match its canonical bytes".to_owned(),
            });
        }
        Ok(())
    }
}

/// Compiles the published catalogue from producer input without inventing
/// support (step 6).
///
/// Deterministic ordering, source/generator identities, and the bound digest
/// are all computed here. A missing capsule for an expected cell becomes a
/// [`CapsuleFinding`] with that cell's owner — never a fabricated runnable
/// entry. Conflicting duplicate capsule/cell identities and stale input are
/// rejected instead of last-write-wins.
pub fn compile_catalogue(
    input: &CatalogueInput,
    producer: CapsuleProducerRef,
    generator_version: GeneratorVersion,
    source: RegistrySourceIdentity,
) -> Result<ModuleTestCapsuleCatalogue, ModuleTestCapsuleError> {
    let mut capsules: Vec<(String, ExecutableModuleTestCapsuleRevision)> = Vec::new();
    for capsule in &input.capsules {
        capsule
            .validate()
            .map_err(|error| ModuleTestCapsuleError::StaleInput {
                capsule: capsule.capsule.as_str().to_owned(),
                detail: error.to_string(),
            })?;
        if !capsule.is_dispatchable() {
            return Err(ModuleTestCapsuleError::StaleInput {
                capsule: capsule.capsule.as_str().to_owned(),
                detail: "capsule is retired or invalidated".to_owned(),
            });
        }
        let digest = capsule.capsule_digest()?;
        capsules.push((digest, capsule.clone()));
    }
    reject_conflicting_capsules(&capsules)?;
    capsules.sort_by(|left, right| {
        left.1
            .cell
            .as_str()
            .cmp(right.1.cell.as_str())
            .then_with(|| left.1.capsule.as_str().cmp(right.1.capsule.as_str()))
    });
    capsules.dedup_by(|left, right| left.1.capsule == right.1.capsule && left.0 == right.0);
    let mut expected = input.expected.clone();
    expected.sort_by(|left, right| left.cell.as_str().cmp(right.cell.as_str()));
    check_expected(&expected)?;
    expected.dedup_by(|left, right| left.cell == right.cell && left.owner == right.owner);
    let mut findings = missing_capsule_findings(&capsules, &expected)?;
    findings.extend(unregistered_cell_findings(&capsules, &expected)?);
    findings.sort_by(|left, right| {
        left.cell
            .as_str()
            .cmp(right.cell.as_str())
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let mut catalogue = ModuleTestCapsuleCatalogue {
        producer,
        generator_version,
        source,
        capsules: capsules.into_iter().map(|(_, capsule)| capsule).collect(),
        findings,
        catalogue_digest: ContractDigest::new("0".repeat(64))?,
    };
    let digest = catalogue
        .canonical_bytes()
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| ModuleTestCapsuleError::DigestFailed {
            detail: error.to_string(),
        })?;
    catalogue.catalogue_digest = ContractDigest::new(digest)?;
    Ok(catalogue)
}

fn reject_conflicting_capsules(
    capsules: &[(String, ExecutableModuleTestCapsuleRevision)],
) -> Result<(), ModuleTestCapsuleError> {
    let mut index = 0;
    while index < capsules.len() {
        let mut next = index + 1;
        while next < capsules.len() {
            let (left_digest, left) = &capsules[index];
            let (right_digest, right) = &capsules[next];
            if left.capsule == right.capsule && left_digest != right_digest {
                return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                    capsule: left.capsule.as_str().to_owned(),
                    detail: "capsule id claimed twice with different content".to_owned(),
                });
            }
            if left.cell == right.cell && left.capsule != right.capsule {
                return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                    capsule: left.cell.as_str().to_owned(),
                    detail: format!(
                        "cell claimed by two capsule revisions: '{}' and '{}'",
                        left.capsule.as_str(),
                        right.capsule.as_str(),
                    ),
                });
            }
            next += 1;
        }
        index += 1;
    }
    Ok(())
}

fn missing_capsule_findings(
    capsules: &[(String, ExecutableModuleTestCapsuleRevision)],
    expected: &[ExpectedCapsule],
) -> Result<Vec<CapsuleFinding>, ModuleTestCapsuleError> {
    let mut findings = Vec::new();
    for wanted in expected {
        if !capsules
            .iter()
            .any(|(_, capsule)| capsule.cell == wanted.cell)
        {
            findings.push(CapsuleFinding {
                cell: wanted.cell.clone(),
                owner: Some(wanted.owner.clone()),
                kind: CapsuleFindingKind::MissingCapsule,
                detail: DispositionReason::new(format!(
                    "cell '{}' has no capsule revision in producer input",
                    wanted.cell.as_str(),
                ))?,
            });
        }
    }
    Ok(findings)
}

fn unregistered_cell_findings(
    capsules: &[(String, ExecutableModuleTestCapsuleRevision)],
    expected: &[ExpectedCapsule],
) -> Result<Vec<CapsuleFinding>, ModuleTestCapsuleError> {
    let mut findings = Vec::new();
    for (_, capsule) in capsules {
        if !expected.iter().any(|wanted| wanted.cell == capsule.cell) {
            findings.push(CapsuleFinding {
                cell: capsule.cell.clone(),
                owner: capsule.class_owner.clone(),
                kind: CapsuleFindingKind::UnregisteredCell,
                detail: DispositionReason::new(format!(
                    "capsule '{}' covers unregistered cell '{}'",
                    capsule.capsule.as_str(),
                    capsule.cell.as_str(),
                ))?,
            });
        }
    }
    Ok(findings)
}

fn check_expected(expected: &[ExpectedCapsule]) -> Result<(), ModuleTestCapsuleError> {
    let mut index = 1;
    while index < expected.len() {
        if expected[index - 1].cell == expected[index].cell
            && expected[index - 1].owner != expected[index].owner
        {
            return Err(ModuleTestCapsuleError::ConflictingDuplicate {
                capsule: expected[index].cell.as_str().to_owned(),
                detail: "expected cell names two owners".to_owned(),
            });
        }
        index += 1;
    }
    Ok(())
}

/// Terminal outcome of one executed test or capsule run.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    /// Observed success with retained capture.
    Passed,
    /// Observed failure.
    Failed,
    /// Cancelled through the current fence.
    Cancelled,
    /// Unknown outcome; never a pass.
    Unknown,
    /// Never executed; never a pass.
    NotExecuted,
}

/// Raw-output capture state for one run or stage.
///
/// Capture stays distinct from execution success and from Governor admission:
/// retained bytes alone prove no outcome, and an outcome alone retains no
/// bytes.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceCapture {
    /// Material output retained under an immutable artifact handle.
    Retained,
    /// Material output absent for an explicit, typed reason.
    Omitted {
        /// Why the output is absent.
        reason: CapsuleOmissionReason,
    },
    /// The run never produced evidence.
    Missing {
        /// Exact missing proof.
        reason: CapsuleOmissionReason,
    },
}

/// Governor admission state as observed evidence.
///
/// Admission is owned by the Governor verifier; this module only records the
/// observed state on retained evidence and never decides it.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservedAdmission {
    /// The Governor verifier admitted the evidence.
    Admitted,
    /// The Governor verifier refused the evidence.
    Refused,
    /// Admission is unknown or pending; never an admission claim.
    Unknown,
}

/// One executed test with its terminal outcome.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ExecutedTest {
    /// Executed test identity.
    pub test: SelectedTest,
    /// Terminal outcome of the execution.
    pub outcome: ExecutionOutcome,
}

/// One retained raw artifact with its exact byte length.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct RawArtifact {
    /// Stable handle for the retained bytes.
    pub handle: ArtifactId,
    /// Exact retained byte length.
    pub byte_len: u64,
}

/// Cleanup outcome for capsule execution roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupOutcome {
    /// Whether the isolated roots were removed.
    pub removed: bool,
    /// Retained bytes across all roots.
    pub retained_bytes: u64,
    /// Byte limit the cleanup ran under.
    pub limit_bytes: u64,
}

/// Outcome of one declared stage class.
///
/// Static compilation and test execution are separate entries: a successful
/// compile-only stage is never a successful test run.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct StageOutcome {
    /// Stage class this outcome covers.
    pub stage: CapsuleStage,
    /// Terminal status of the stage.
    pub status: ExecutionOutcome,
    /// Capture state of the stage output.
    pub capture: EvidenceCapture,
}

/// Retained actual execution evidence for one capsule revision (step 7).
///
/// The evidence binds capsule/profile revision, candidate, discovered,
/// selected, and executed identities, fixture/oracle/resource bindings, raw
/// artifacts, outcome, and cleanup limits. Counts are always the list
/// lengths, so a count can never diverge from its identities. Capture,
/// success, and admission are distinct fields: none implies another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapsuleExecutionEvidence {
    /// Executed capsule identity.
    pub capsule: ModuleTestCapsuleId,
    /// Digest of the exact capsule revision executed.
    pub capsule_digest: ContractDigest,
    /// Cell under proof.
    pub cell: CapabilityCellId,
    /// Exact profile name executed.
    pub profile: CapsuleProfileRef,
    /// Exact profile revision executed.
    pub profile_revision: u64,
    /// Candidate the execution ran for.
    pub candidate: CapsuleCandidateRef,
    /// Expected discovery rule enforced on this evidence.
    pub expected: ExpectedDiscovery,
    /// Discovered tests, sorted and duplicate-free.
    pub discovered: Vec<SelectedTest>,
    /// Selected tests, sorted and duplicate-free.
    pub selected: Vec<SelectedTest>,
    /// Executed tests with outcomes, sorted and duplicate-free.
    pub executed: Vec<ExecutedTest>,
    /// Omitted discovered tests with reasons, sorted and duplicate-free.
    pub omitted: Vec<OmittedTest>,
    /// Fixture binding the execution ran against.
    pub fixture: FixtureBinding,
    /// Oracle binding the execution ran against.
    pub oracle: OracleBinding,
    /// Separate oracle review, required when the oracle changed.
    pub oracle_review: Option<OracleReviewRef>,
    /// Resource bindings consumed, sorted and duplicate-free.
    pub resources: Vec<CapsuleResourceRef>,
    /// Retained raw artifacts, sorted and duplicate-free.
    pub raw_artifacts: Vec<RawArtifact>,
    /// Terminal outcome of the run.
    pub outcome: ExecutionOutcome,
    /// Raw-output capture state.
    pub capture: EvidenceCapture,
    /// Observed Governor admission state.
    pub admission: ObservedAdmission,
    /// Per-stage outcomes, one per declared stage class.
    pub stages: Vec<StageOutcome>,
    /// Cleanup outcome for execution roots.
    pub cleanup: CleanupOutcome,
    /// Digest of the retained evidence this value replays, when replaying.
    /// A replay carries no fresh execution.
    pub replay_of: Option<ContractDigest>,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    namespace: &'static str,
    evidence: &'a CapsuleExecutionEvidence,
}

impl CapsuleExecutionEvidence {
    /// Returns deterministic canonical bytes for this evidence value.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let input = EvidenceDigestInput {
            namespace: MODULE_TEST_CAPSULE_NAMESPACE,
            evidence: self,
        };
        canonical_json_bytes(&input)
    }

    /// Returns the lowercase SHA-256 hex digest of [`Self::canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`ModuleTestCapsuleError::DigestFailed`] when canonicalization
    /// fails.
    pub fn evidence_digest(&self) -> Result<String, ModuleTestCapsuleError> {
        self.canonical_bytes()
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| ModuleTestCapsuleError::DigestFailed {
                detail: error.to_string(),
            })
    }

    /// Validates internal consistency, failing closed.
    ///
    /// Expected-nonzero with zero execution cannot validate; a replay
    /// carrying execution cannot validate; PASS without retained capture
    /// cannot validate; PASS over a non-passing stage cannot validate; and
    /// executed tests outside the selected set (or selected tests outside
    /// discovery) cannot validate.
    ///
    /// # Errors
    ///
    /// Returns the first inconsistency found.
    pub fn validate(&self) -> Result<(), ModuleTestCapsuleError> {
        validate_sorted_unique(&self.discovered, "evidence.discovered")?;
        validate_sorted_unique(&self.selected, "evidence.selected")?;
        validate_sorted_unique(&self.executed, "evidence.executed")?;
        validate_sorted_unique(&self.omitted, "evidence.omitted")?;
        validate_sorted_unique(&self.resources, "evidence.resources")?;
        validate_sorted_unique(&self.raw_artifacts, "evidence.raw_artifacts")?;
        validate_sorted_unique(&self.stages, "evidence.stages")?;
        self.validate_outcome_rules()?;
        self.validate_membership()?;
        Ok(())
    }

    /// Validates this evidence against the exact capsule revision it claims.
    ///
    /// Identity, digest, cell, profile, fixture, stages, and selector
    /// membership must all match. An oracle digest or revision the capsule
    /// did not declare requires the separate oracle review.
    ///
    /// # Errors
    ///
    /// Returns the capsule failure, [`ModuleTestCapsuleError::EvidenceMismatch`]
    /// for any divergence, or [`ModuleTestCapsuleError::OracleReviewMissing`]
    /// for an unreviewed oracle change.
    pub fn validate_against(
        &self,
        capsule: &ExecutableModuleTestCapsuleRevision,
    ) -> Result<(), ModuleTestCapsuleError> {
        capsule.validate()?;
        self.validate()?;
        self.check_identity(capsule)?;
        self.check_fixture_oracle(capsule)?;
        self.check_stages(capsule)?;
        self.check_selector_membership(capsule)?;
        Ok(())
    }

    fn validate_outcome_rules(&self) -> Result<(), ModuleTestCapsuleError> {
        let capsule = self.capsule.as_str().to_owned();
        if matches!(self.expected, ExpectedDiscovery::ExpectedNonZero) && self.executed.is_empty() {
            return Err(ModuleTestCapsuleError::ZeroExecutionWithNonZeroExpectation { capsule });
        }
        if self.replay_of.is_some() && !self.executed.is_empty() {
            return Err(ModuleTestCapsuleError::ReplayCarriesExecution { capsule });
        }
        if matches!(self.outcome, ExecutionOutcome::Passed) {
            if !matches!(self.capture, EvidenceCapture::Retained) {
                return Err(ModuleTestCapsuleError::CaptureMissingForPass { capsule });
            }
            if self
                .stages
                .iter()
                .any(|stage| !matches!(stage.status, ExecutionOutcome::Passed))
            {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule,
                    detail: "PASS claimed over a non-passing stage".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_membership(&self) -> Result<(), ModuleTestCapsuleError> {
        let capsule = self.capsule.as_str().to_owned();
        for entry in &self.selected {
            if !self.discovered.iter().any(|known| known == entry) {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule,
                    detail: format!(
                        "selected test '{}/{}' was never discovered",
                        entry.binary.as_str(),
                        entry.test.as_str(),
                    ),
                });
            }
        }
        for entry in &self.executed {
            if !self.selected.iter().any(|known| known == &entry.test) {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule,
                    detail: format!(
                        "executed test '{}/{}' was never selected",
                        entry.test.binary.as_str(),
                        entry.test.test.as_str(),
                    ),
                });
            }
        }
        Ok(())
    }

    fn check_identity(
        &self,
        capsule: &ExecutableModuleTestCapsuleRevision,
    ) -> Result<(), ModuleTestCapsuleError> {
        let name = self.capsule.as_str().to_owned();
        if self.capsule != capsule.capsule
            || self.cell != capsule.cell
            || self.profile != capsule.profile
            || self.profile_revision != capsule.profile_revision
        {
            return Err(ModuleTestCapsuleError::EvidenceMismatch {
                capsule: name,
                detail: "evidence identity, cell, or profile does not match the capsule".to_owned(),
            });
        }
        let digest = capsule.capsule_digest()?;
        if digest != self.capsule_digest.as_str() {
            return Err(ModuleTestCapsuleError::EvidenceMismatch {
                capsule: name,
                detail: "evidence capsule digest does not match the capsule revision".to_owned(),
            });
        }
        Ok(())
    }

    fn check_fixture_oracle(
        &self,
        capsule: &ExecutableModuleTestCapsuleRevision,
    ) -> Result<(), ModuleTestCapsuleError> {
        let name = self.capsule.as_str().to_owned();
        if self.fixture != capsule.fixture {
            return Err(ModuleTestCapsuleError::EvidenceMismatch {
                capsule: name,
                detail: "evidence fixture binding does not match the capsule".to_owned(),
            });
        }
        if self.oracle != capsule.oracle && self.oracle_review.is_none() {
            return Err(ModuleTestCapsuleError::OracleReviewMissing { capsule: name });
        }
        Ok(())
    }

    fn check_stages(
        &self,
        capsule: &ExecutableModuleTestCapsuleRevision,
    ) -> Result<(), ModuleTestCapsuleError> {
        for stage in &capsule.stages {
            if !self.stages.iter().any(|known| &known.stage == stage) {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule: self.capsule.as_str().to_owned(),
                    detail: format!("declared stage '{stage:?}' has no retained outcome"),
                });
            }
        }
        Ok(())
    }

    fn check_selector_membership(
        &self,
        capsule: &ExecutableModuleTestCapsuleRevision,
    ) -> Result<(), ModuleTestCapsuleError> {
        for entry in &self.selected {
            if !capsule.selector.binaries.is_empty()
                && !capsule
                    .selector
                    .binaries
                    .iter()
                    .any(|known| known == &entry.binary)
            {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule: self.capsule.as_str().to_owned(),
                    detail: format!(
                        "selected binary '{}' is outside the capsule selector",
                        entry.binary.as_str(),
                    ),
                });
            }
            if !capsule.selector.tests.is_empty()
                && !capsule
                    .selector
                    .tests
                    .iter()
                    .any(|known| known == &entry.test)
            {
                return Err(ModuleTestCapsuleError::EvidenceMismatch {
                    capsule: self.capsule.as_str().to_owned(),
                    detail: format!(
                        "selected test '{}' is outside the capsule selector",
                        entry.test.as_str(),
                    ),
                });
            }
        }
        Ok(())
    }
}
