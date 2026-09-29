//! Versioned instrument definitions, profiles, and the single profile compiler.
//!
//! This module owns the canonical Instrument Plane control path for issue
//! #1813: the [`InstrumentRegistry`] admits versioned [`InstrumentSpec`] and
//! [`InstrumentProfile`] definitions, the [`InstrumentProfileResolver`]
//! binds an exact profile revision to a caller-admitted target layout,
//! [`WorkScope`], and environment, and the [`ProfileCompiler`] is the one
//! admission function shared by every verification entry point. It creates no
//! task, schedule, budget, finish, or canonical-store authority; those stay
//! with Governor and Kernel.
//!
//! Profiles from outside the registry are never silently promoted: the
//! compiler returns them as an explicit [`CompiledProfile::LegacyQuarantine`]
//! record that carries no governed revision, stage graph, or receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use eliot_contracts::{ContractError, ContractId, ContractVersion, StateFence, sha256_hex};
use eliot_instrument_api::{
    BuildClass, InstrumentAdmissionGrant, InstrumentAdmissionRequest, InstrumentKind,
};
use eliot_instrument_cargo::CONTRACT_NAME as CARGO_CONTRACT_NAME;
use eliot_instrument_nextest::{MAX_NEXTEST_OUTPUT_BYTES, NEXTEST_INSTRUMENT};
use eliot_instrument_rustc::{MAX_RUSTC_OUTPUT_BYTES, RUSTC_EXECUTABLE, RUSTC_INSTRUMENT};
use eliot_instrument_rustfmt::{MAX_RUSTFMT_OUTPUT_BYTES, RUSTFMT_INSTRUMENT};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::registry::{ResolvedExecutableIdentity, SupplyChainReceipt, SupplyChainTable};

/// Admitted `compiler` profile name (I10.8.7).
pub const COMPILER_PROFILE: &str = "compiler";
/// Admitted `test` profile name (I10.8.7).
pub const TEST_PROFILE: &str = "test";
/// Exact revision shipped for both builtin profiles.
pub const BUILTIN_PROFILE_REVISION: u64 = 1;
/// Stable wire name of the package verification route.
pub const PACKAGE_VERIFICATION_ROUTE: &str = "package-verification";
/// Stable wire name of the bundle verification route.
pub const BUNDLE_VERIFICATION_ROUTE: &str = "bundle-verification";
/// Spec revision shipped for every builtin [`InstrumentSpec`].
pub const BUILTIN_SPEC_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Target scope class recorded for builtin profiles: the exact worktree
/// binding belongs to admission, never to the profile text.
pub const ADMITTED_WORKTREE_CLASS: &str = "admitted-worktree";
/// Environment class recorded for builtin profiles: isolated P-03 execution.
pub const ISOLATED_PROCESS_CLASS: &str = "isolated-process";
/// Workscope class recorded for builtin profiles.
pub const ADMITTED_SCOPE_CLASS: &str = "admitted-scope";
/// Recorded parser authority for adapters that own no parser.
///
/// Read from `eliot-diagnostic`; recorded here the same way the provider
/// registry records it, without taking a dependency.
pub const DIAGNOSTIC_PARSER_CONTRACT: &str = "eliot.instrument.diagnostic";
/// Parser generation shipped for every builtin [`InstrumentSpec`].
///
/// Parser and profile generations are replaceable independently through
/// ordinary module/daemon cutover; a new generation ships a new admitted
/// spec revision, never a Rust DLL ABI.
pub const BUILTIN_PARSER_GENERATION: u64 = 1;
/// Kind version shipped for every builtin instrument kind.
///
/// The kind version identifies the replaceable concrete kind; the spec
/// revision identifies the admission. Both ship at 1.0.0 for builtins,
/// matching the owning adapter versions.
pub const BUILTIN_KIND_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Credential policy class recorded for builtin specs: the isolated process
/// receives no ambient credentials.
pub const ISOLATED_CREDENTIAL_POLICY: &str = "eliot.policy.credential.isolated-process";
/// Network policy class recorded for builtin specs: network access is scoped
/// to the isolated process class, never ambient.
pub const ISOLATED_NETWORK_POLICY: &str = "eliot.policy.network.isolated-process";
/// Declared per-adapter concurrency shipped for every builtin spec.
///
/// Each adapter/instrument keeps its own declared maximum; the admission
/// binds it into the process grant and the owning execution plane enforces
/// it with its own semaphore and circuit state. A system-wide pool never
/// overrides the module limit, so no global pool exists here.
pub const BUILTIN_MAX_CONCURRENCY: u32 = 1;
/// Stable schema name of the canonical registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA: &str = "eliot.instrument.registry-snapshot";
/// Exact schema wire version of the canonical registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA_VERSION: &str = "1.0.0";

/// Failures raised while admitting, resolving, or compiling profiles.
///
/// Every variant is typed and fail-closed: no stringly-typed catch-all drives
/// control flow.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A profile revision is zero, which never names an admitted revision.
    #[error("profile '{profile}' revision must be non-zero")]
    InvalidRevision {
        /// Profile that named the revision.
        profile: String,
    },
    /// No profile is admitted under the requested name.
    #[error("no admitted instrument profile named '{profile}'")]
    UnknownProfile {
        /// Requested profile name.
        profile: String,
    },
    /// The profile exists but the exact revision is not admitted.
    #[error("profile '{profile}' has no admitted revision {revision}")]
    UnknownRevision {
        /// Requested profile name.
        profile: String,
        /// Requested revision.
        revision: u64,
    },
    /// A stage references an [`InstrumentSpec`] the registry never admitted.
    #[error("profile '{profile}' stage '{stage}' references unknown spec '{spec}'")]
    UnknownSpec {
        /// Profile carrying the dangling reference.
        profile: String,
        /// Stage carrying the dangling reference.
        stage: String,
        /// Referenced spec identity.
        spec: String,
    },
    /// Two specs claim the same kind identity.
    #[error("duplicate instrument spec '{spec}'")]
    DuplicateSpec {
        /// Conflicting kind identity.
        spec: String,
    },
    /// Two profiles claim the same name and revision.
    #[error("duplicate instrument profile '{profile}' revision {revision}")]
    DuplicateProfile {
        /// Conflicting profile name.
        profile: String,
        /// Conflicting revision.
        revision: u64,
    },
    /// Two stages claim the same durable stage identity.
    #[error("duplicate stage '{stage}'")]
    DuplicateStage {
        /// Conflicting stage identity.
        stage: String,
    },
    /// A stage depends on a stage the profile never declares.
    #[error("stage '{stage}' depends on unknown stage '{dependency}'")]
    UnknownStageDependency {
        /// Dependent stage.
        stage: String,
        /// Missing dependency.
        dependency: String,
    },
    /// The declared stage graph is not acyclic.
    #[error("stage graph contains a dependency cycle through '{stage}'")]
    StageCycle {
        /// Stage where the cycle was detected.
        stage: String,
    },
    /// A profile declares no stages, so there is nothing to orchestrate.
    #[error("profile '{profile}' declares no stages")]
    EmptyDag {
        /// Profile without stages.
        profile: String,
    },
    /// A stage kind does not match its bound spec class.
    #[error("stage '{stage}' kind {kind:?} does not match spec '{spec}' class")]
    SpecKindMismatch {
        /// Offending stage.
        stage: String,
        /// Referenced spec identity.
        spec: String,
        /// Declared stage class.
        kind: InstrumentKind,
    },
    /// The invocation class is outside the admitted profile classes.
    #[error("profile '{profile}' revision {revision} does not admit {kind:?} invocations")]
    UnsupportedKind {
        /// Admitted profile name.
        profile: String,
        /// Admitted revision.
        revision: u64,
        /// Requested invocation class.
        kind: InstrumentKind,
    },
    /// A legacy profile bypassed the compiler and carries no governed admission.
    #[error("profile '{profile}' is quarantined: it bypasses the profile compiler")]
    Quarantined {
        /// Bypassed profile name.
        profile: String,
    },
    /// Two target roots collide; layout roots must be pairwise distinct.
    #[error("target layout roots must be pairwise distinct")]
    LayoutCollision,
    /// The attested environment class differs from the admitted profile class.
    #[error("environment class '{observed}' does not match profile '{profile}' class '{expected}'")]
    EnvironmentMismatch {
        /// Profile whose class was expected.
        profile: String,
        /// Admitted class.
        expected: String,
        /// Attested class.
        observed: String,
    },
    /// A contract identity failed validation while assembling definitions.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// A registry snapshot is malformed or names an unsupported schema.
    #[error("registry snapshot is malformed: {detail}")]
    Snapshot {
        /// How the snapshot fails shape or schema validation.
        detail: String,
    },
}

/// Validates one required text value.
fn validate_text(value: &str, field: &'static str) -> Result<(), ProfileError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProfileError::InvalidText { field });
    }
    Ok(())
}

/// Deterministic sort rank for [`InstrumentKind`], following declaration order.
const fn kind_rank(kind: InstrumentKind) -> u8 {
    match kind {
        InstrumentKind::Build => 0,
        InstrumentKind::Test => 1,
        InstrumentKind::Lint => 2,
        InstrumentKind::Inspect => 3,
        InstrumentKind::Verify => 4,
        InstrumentKind::Format => 5,
    }
}

/// Stable semantic instrument class set (I10.8.3).
///
/// The class distinguishes long-lived semantics from the replaceable
/// concrete kind: a new kind is admitted through a versioned
/// Module/Instrument manifest without changing this enum, the Kernel, or
/// any coarse invocation class. Each class projects to exactly one coarse
/// [`InstrumentKind`] for stage binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstrumentClass {
    /// Source identity and version-control observation.
    SourceIdentity,
    /// Compilation and build.
    Compiler,
    /// Source formatting checks.
    Formatter,
    /// Test execution.
    Test,
    /// Semantic index decoding and projection.
    SemanticIndex,
    /// Heuristic analysis and scout observations.
    HeuristicAnalysis,
    /// Runtime diagnostics capture.
    RuntimeDiagnostic,
    /// Dependency and supply-chain hygiene.
    SecurityDependency,
    /// Concurrency model checking and simulation.
    Concurrency,
    /// Unsafe/FFI boundary verification.
    UnsafeFfi,
    /// Benchmark and performance probes.
    Performance,
}

impl InstrumentClass {
    /// Coarse invocation class this semantic class binds stages under.
    ///
    /// Observation classes bind under `Inspect`, static checks under `Lint`,
    /// formatting under `Format`, executable test-like harnesses (including
    /// concurrency, unsafe, and performance rigs) under `Test`, and build
    /// compilers under `Build`.
    pub const fn coarse_kind(self) -> InstrumentKind {
        match self {
            Self::SourceIdentity | Self::SemanticIndex | Self::RuntimeDiagnostic => {
                InstrumentKind::Inspect
            }
            Self::Compiler => InstrumentKind::Build,
            Self::Formatter => InstrumentKind::Format,
            Self::Test | Self::Concurrency | Self::UnsafeFfi | Self::Performance => {
                InstrumentKind::Test
            }
            Self::HeuristicAnalysis | Self::SecurityDependency => InstrumentKind::Lint,
        }
    }
}

/// Opaque versioned instrument kind identifier (I10.8.3).
///
/// The name is opaque to every consumer except the admitting registry: no
/// caller parses, trims, or aliases it. The version identifies the
/// replaceable concrete kind, so a new kind generation is admitted as a new
/// identifier rather than a mutation. Unregistered kind IDs fail before
/// launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentKindId {
    /// Opaque kind name, keyed by the admitting registry.
    name: ContractId,
    /// Replaceable kind generation.
    version: ContractVersion,
}

impl InstrumentKindId {
    /// Admits one versioned kind identifier.
    ///
    /// The name is opaque but never blank: an empty or control-carrying name
    /// is refused here so an unregistered kind can never be keyed.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the kind name is blank or
    /// carries control characters.
    pub fn new(name: ContractId, version: ContractVersion) -> Result<Self, ProfileError> {
        validate_text(name.as_str(), "kind_id")?;
        Ok(Self { name, version })
    }

    /// Opaque kind name for registry keying.
    pub fn as_str(&self) -> &str {
        self.name.as_str()
    }

    /// Replaceable kind generation.
    pub const fn version(&self) -> ContractVersion {
        self.version
    }

    /// Deterministic identity over name and version.
    pub fn digest(&self) -> String {
        let material = format!("{}\0{}", self.name.as_str(), self.version);
        sha256_hex(material.as_bytes())
    }
}

/// Admitted resource ceiling bound into the process grant (I10.8.3).
///
/// `None` leaves the ceiling to the owning execution plane or the
/// composition-root port: the cargo adapter, for example, defines no capture
/// bound of its own. A present value is the admitted ceiling the grant binds;
/// enforcement stays with the plane that owns the process, never with a
/// global pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Admitted wall-clock ceiling in milliseconds, when the spec sets one.
    pub timeout_ms: Option<u64>,
    /// Admitted raw-output capture ceiling in bytes, when the spec sets one.
    pub max_output_bytes: Option<u64>,
}

impl ResourceLimits {
    /// Records the admitted ceiling; `None` defers to the owning plane.
    pub const fn new(timeout_ms: Option<u64>, max_output_bytes: Option<u64>) -> Self {
        Self {
            timeout_ms,
            max_output_bytes,
        }
    }

    /// Deterministic identity over the admitted ceiling.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{}",
            self.timeout_ms
                .map(|timeout| timeout.to_string())
                .unwrap_or_default(),
            self.max_output_bytes
                .map(|limit| limit.to_string())
                .unwrap_or_default(),
        );
        sha256_hex(material.as_bytes())
    }
}

/// Caller-supplied fields for one [`InstrumentSpec`] admission.
///
/// Bundled so admission stays a single validated constructor; every field is
/// bound into the spec digest and, through compilation, into the process
/// grant digest sealed at launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentSpecParams {
    /// Opaque versioned kind identity.
    pub kind: InstrumentKindId,
    /// Stable semantic class.
    pub class: InstrumentClass,
    /// Spec revision.
    pub revision: ContractVersion,
    /// Exact executable file identity bound by the registry.
    pub executable: String,
    /// Admitted tool version requirement, when the manifest pins one.
    pub executable_version: Option<String>,
    /// Parser/normalizer authority for the instrument output.
    pub parser: ContractId,
    /// Admitted parser generation; replaceable through module cutover.
    pub parser_generation: u64,
    /// Admitted environment class.
    pub environment_profile: String,
    /// Invocation schema authority: the contract that validates arguments.
    pub schema: ContractId,
    /// Fixed command template; empty when the manifest declares none, in
    /// which case only the empty argument vector is admitted.
    pub argument_template: Vec<String>,
    /// Admitted credential policy identity.
    pub credential_policy: ContractId,
    /// Admitted network policy identity.
    pub network_policy: ContractId,
    /// Admitted resource ceiling.
    pub limits: ResourceLimits,
    /// Declared per-adapter maximum concurrency; enforced by the owning
    /// plane with its own semaphore and circuit state, never by a global
    /// pool.
    pub max_concurrency: u32,
}

/// Versioned executable authority for one instrument kind (I10.8.3).
///
/// The spec names the exact executable identity, argument schema and fixed
/// template, parser generation, environment/resource/credential/network
/// policy, and declared concurrency an admitted stage may use. It never
/// carries command text or agent-supplied combinations: stages resolve to
/// typed invocations validated against this admission before any child
/// process is created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentSpec {
    /// Opaque versioned kind identity.
    pub kind: InstrumentKindId,
    /// Semantic class of the instrument.
    pub class: InstrumentClass,
    /// Spec revision.
    pub revision: ContractVersion,
    /// Exact executable file identity bound by the registry.
    pub executable: String,
    /// Admitted tool version requirement, when the manifest pins one.
    pub executable_version: Option<String>,
    /// Parser/normalizer authority for the instrument output.
    pub parser: ContractId,
    /// Admitted parser generation.
    pub parser_generation: u64,
    /// Admitted environment class.
    pub environment_profile: String,
    /// Invocation schema authority.
    pub schema: ContractId,
    /// Fixed command template; empty admits only the empty argument vector.
    pub argument_template: Vec<String>,
    /// Admitted credential policy identity.
    pub credential_policy: ContractId,
    /// Admitted network policy identity.
    pub network_policy: ContractId,
    /// Admitted resource ceiling.
    pub limits: ResourceLimits,
    /// Declared per-adapter maximum concurrency.
    pub max_concurrency: u32,
}

impl InstrumentSpec {
    /// Records one instrument spec, validating every field.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the executable name, the
    /// environment class, a pinned version, or a template argument is blank
    /// or carries control characters.
    pub fn new(params: InstrumentSpecParams) -> Result<Self, ProfileError> {
        validate_text(&params.executable, "executable")?;
        validate_text(&params.environment_profile, "environment_profile")?;
        if let Some(version) = params.executable_version.as_deref() {
            validate_text(version, "executable_version")?;
        }
        for argument in &params.argument_template {
            validate_text(argument, "argument_template")?;
        }
        Ok(Self {
            kind: params.kind,
            class: params.class,
            revision: params.revision,
            executable: params.executable,
            executable_version: params.executable_version,
            parser: params.parser,
            parser_generation: params.parser_generation,
            environment_profile: params.environment_profile,
            schema: params.schema,
            argument_template: params.argument_template,
            credential_policy: params.credential_policy,
            network_policy: params.network_policy,
            limits: params.limits,
            max_concurrency: params.max_concurrency,
        })
    }

    /// Registry key: the admitted kind identity.
    pub fn kind_key(&self) -> &str {
        self.kind.as_str()
    }

    /// Deterministic identity over every spec field.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.kind.digest(),
            self.class,
            self.revision,
            self.executable,
            self.executable_version.as_deref().unwrap_or(""),
            self.parser.as_str(),
            self.parser_generation,
            self.environment_profile,
            self.schema.as_str(),
            self.argument_template.join("\0"),
            self.credential_policy.as_str(),
            self.network_policy.as_str(),
            self.limits.digest(),
            self.max_concurrency,
        );
        sha256_hex(material.as_bytes())
    }
}

/// One declared profile stage with durable identity and dependencies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageDecl {
    /// Durable stage identity within the profile revision.
    pub stage_id: String,
    /// Bound [`InstrumentSpec`] kind identity.
    pub spec: ContractId,
    /// Stage class; must equal the bound spec class.
    pub kind: InstrumentKind,
    /// Prerequisite stage identities, sorted and deduplicated.
    pub depends_on: Vec<String>,
    /// Whether the aggregate fails without a successful run of this stage.
    pub required: bool,
    /// Whether the stage dispatches through `TestExecutionPlane`.
    pub external: bool,
}

impl StageDecl {
    /// Declares one stage, validating identities and ordering dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the stage identity or a
    /// dependency is blank or carries control characters.
    pub fn new(
        stage_id: String,
        spec: ContractId,
        kind: InstrumentKind,
        mut depends_on: Vec<String>,
        required: bool,
        external: bool,
    ) -> Result<Self, ProfileError> {
        validate_text(&stage_id, "stage_id")?;
        for dependency in &depends_on {
            validate_text(dependency, "depends_on")?;
        }
        depends_on.sort();
        depends_on.dedup();
        Ok(Self {
            stage_id,
            spec,
            kind,
            depends_on,
            required,
            external,
        })
    }
}

/// Declared bounded stage DAG (I10.8.4).
///
/// Stages are keyed by durable identity in a [`BTreeMap`], so iteration order
/// is sorted and stable. Construction rejects duplicates, dangling
/// dependencies, self-dependencies, and cycles before anything executes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageDag {
    stages: BTreeMap<String, StageDecl>,
}

impl StageDag {
    /// Assembles a stage DAG from caller-supplied declarations.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::EmptyDag`] when no stage is declared,
    /// [`ProfileError::DuplicateStage`] on a conflicting identity,
    /// [`ProfileError::UnknownStageDependency`] on a dangling edge, or
    /// [`ProfileError::StageCycle`] when the graph is not acyclic.
    pub fn build(profile: &str, stages: Vec<StageDecl>) -> Result<Self, ProfileError> {
        if stages.is_empty() {
            return Err(ProfileError::EmptyDag {
                profile: profile.to_owned(),
            });
        }
        let mut map = BTreeMap::new();
        for stage in stages {
            let key = stage.stage_id.clone();
            if map.insert(key.clone(), stage).is_some() {
                return Err(ProfileError::DuplicateStage { stage: key });
            }
        }
        for stage in map.values() {
            for dependency in &stage.depends_on {
                if dependency == &stage.stage_id {
                    return Err(ProfileError::StageCycle {
                        stage: stage.stage_id.clone(),
                    });
                }
                if !map.contains_key(dependency) {
                    return Err(ProfileError::UnknownStageDependency {
                        stage: stage.stage_id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        let dag = Self { stages: map };
        dag.check_acyclic()?;
        Ok(dag)
    }

    /// Rejects cyclic graphs with a deterministic witness stage.
    fn check_acyclic(&self) -> Result<(), ProfileError> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for stage_id in self.stages.keys() {
            self.visit(stage_id, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    /// Depth-first cycle check over sorted stage identities.
    fn visit(
        &self,
        stage_id: &str,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), ProfileError> {
        if !visited.insert(stage_id.to_owned()) {
            return Ok(());
        }
        if !visiting.insert(stage_id.to_owned()) {
            return Err(ProfileError::StageCycle {
                stage: stage_id.to_owned(),
            });
        }
        if let Some(stage) = self.stages.get(stage_id) {
            for dependency in &stage.depends_on {
                if visiting.contains(dependency) {
                    return Err(ProfileError::StageCycle {
                        stage: dependency.clone(),
                    });
                }
                self.visit(dependency, visiting, visited)?;
            }
        }
        visiting.remove(stage_id);
        Ok(())
    }

    /// Deterministic topological order: Kahn over lexicographic identities.
    ///
    /// Independent stages surface in sorted identity order; dependents always
    /// follow their prerequisites. Identical declarations always yield the
    /// identical order.
    pub fn topological_order(&self) -> Vec<&StageDecl> {
        let mut remaining: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for stage in self.stages.values() {
            remaining.insert(
                stage.stage_id.as_str(),
                stage.depends_on.iter().map(String::as_str).collect(),
            );
        }
        let mut order = Vec::with_capacity(self.stages.len());
        while !remaining.is_empty() {
            let ready: Vec<&str> = remaining
                .iter()
                .filter_map(|(stage_id, dependencies)| {
                    if dependencies.is_empty() {
                        Some(*stage_id)
                    } else {
                        None
                    }
                })
                .collect();
            for stage_id in ready {
                remaining.remove(stage_id);
                for dependencies in remaining.values_mut() {
                    dependencies.remove(stage_id);
                }
                if let Some(stage) = self.stages.get(stage_id) {
                    order.push(stage);
                }
            }
        }
        order
    }

    /// Stages in sorted identity order.
    pub fn iter(&self) -> std::collections::btree_map::Values<'_, String, StageDecl> {
        self.stages.values()
    }

    /// Number of declared stages.
    pub fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the DAG declares no stages.
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Deterministic identity over the topological stage sequence.
    pub fn digest(&self) -> String {
        let mut material = String::new();
        for stage in self.topological_order() {
            material.push_str(&stage.stage_id);
            material.push('\0');
            material.push_str(stage.spec.as_str());
            material.push('\0');
            let _ = write!(material, "{:?}", stage.kind);
            material.push('\0');
            material.push_str(&stage.depends_on.join(","));
            material.push('\0');
            material.push_str(if stage.required {
                "required"
            } else {
                "optional"
            });
            material.push('\0');
            material.push_str(if stage.external { "external" } else { "pure" });
            material.push('\0');
        }
        sha256_hex(material.as_bytes())
    }
}

impl<'a> IntoIterator for &'a StageDag {
    type Item = &'a StageDecl;
    type IntoIter = std::collections::btree_map::Values<'a, String, StageDecl>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Declared scope classes carried by one [`InstrumentProfile`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileScopeClasses {
    /// Target layout class; exact roots bind at resolve time.
    pub target_layout: String,
    /// Environment class; the concrete projection binds at resolve time.
    pub environment: String,
    /// Workscope class; the declared scope and fence bind at resolve time.
    pub workscope: String,
}

impl ProfileScopeClasses {
    /// Records the scope classes, validating every value.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when a class is blank or carries
    /// control characters.
    pub fn new(
        target_layout: String,
        environment: String,
        workscope: String,
    ) -> Result<Self, ProfileError> {
        validate_text(&target_layout, "target_layout_class")?;
        validate_text(&environment, "environment_class")?;
        validate_text(&workscope, "workscope_class")?;
        Ok(Self {
            target_layout,
            environment,
            workscope,
        })
    }
}

/// A versioned deterministic verification recipe (I10.8.7).
///
/// The profile declares admitted invocation classes, the stage DAG, and scope
/// classes. Exact revisions, roots, fences, and environment projections bind
/// at resolve time through [`InstrumentProfileResolver`]; the profile text
/// itself never names a concrete path, command, or task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentProfile {
    /// Canonical profile name, such as `compiler` or `test`.
    pub name: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Revision of the bound [`InstrumentSpec`] set.
    pub spec_revision: ContractVersion,
    /// Admitted invocation classes, sorted and deduplicated.
    pub kinds: Vec<InstrumentKind>,
    /// Declared stage DAG.
    pub dag: StageDag,
    /// Declared scope classes.
    pub classes: ProfileScopeClasses,
}

impl InstrumentProfile {
    /// Records one profile, validating identity, revision, and classes.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the name is blank,
    /// [`ProfileError::InvalidRevision`] when the revision is zero, or
    /// [`ProfileError::UnsupportedKind`] when no invocation class is admitted.
    pub fn new(
        name: String,
        revision: u64,
        spec_revision: ContractVersion,
        mut kinds: Vec<InstrumentKind>,
        dag: StageDag,
        classes: ProfileScopeClasses,
    ) -> Result<Self, ProfileError> {
        validate_text(&name, "profile_name")?;
        if revision == 0 {
            return Err(ProfileError::InvalidRevision { profile: name });
        }
        kinds.sort_by_key(|kind| kind_rank(*kind));
        kinds.dedup();
        if kinds.is_empty() {
            return Err(ProfileError::UnsupportedKind {
                profile: name,
                revision,
                kind: InstrumentKind::Build,
            });
        }
        Ok(Self {
            name,
            revision,
            spec_revision,
            kinds,
            dag,
            classes,
        })
    }

    /// Whether the profile admits the invocation class.
    pub fn admits_kind(&self, kind: InstrumentKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// Deterministic identity over revision, classes, and stage graph.
    pub fn digest(&self) -> String {
        let kinds = self
            .kinds
            .iter()
            .map(|kind| format!("{kind:?}"))
            .collect::<Vec<_>>()
            .join(",");
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.name,
            self.revision,
            self.spec_revision,
            kinds,
            self.dag.digest(),
            self.classes.target_layout,
            self.classes.environment,
            self.classes.workscope,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Builds the builtin spec set backing the `compiler`, `test`, and `dev-fast` profiles.
///
/// Builtin specs pin the exact executable file, the owning adapter's schema
/// authority, the isolated-process environment/credential/network classes,
/// and the adapter's real capture bound where the adapter defines one (the
/// cargo adapter defines none, so its ceiling stays with the
/// composition-root port). No fixed command template is declared, so the
/// shared gate admits only the empty invocation argument vector for
/// builtins; a manifest that needs further arguments admits them as an
/// exact fixed template. No machine observation exists at registry
/// construction, so builtins ship no supply-chain receipt and pin no tool
/// version.
pub fn builtin_specs() -> Result<Vec<InstrumentSpec>, ProfileError> {
    let credential = ContractId::new(ISOLATED_CREDENTIAL_POLICY)?;
    let network = ContractId::new(ISOLATED_NETWORK_POLICY)?;
    Ok(vec![
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(
                ContractId::new(CARGO_CONTRACT_NAME)?,
                BUILTIN_KIND_VERSION,
            )?,
            class: InstrumentClass::Compiler,
            revision: BUILTIN_SPEC_VERSION,
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(DIAGNOSTIC_PARSER_CONTRACT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            schema: ContractId::new(CARGO_CONTRACT_NAME)?,
            argument_template: Vec::new(),
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, None),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(ContractId::new(RUSTC_INSTRUMENT)?, BUILTIN_KIND_VERSION)?,
            class: InstrumentClass::Compiler,
            revision: BUILTIN_SPEC_VERSION,
            executable: RUSTC_EXECUTABLE.to_owned(),
            executable_version: None,
            parser: ContractId::new(RUSTC_INSTRUMENT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            schema: ContractId::new(RUSTC_INSTRUMENT)?,
            argument_template: Vec::new(),
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, Some(MAX_RUSTC_OUTPUT_BYTES as u64)),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(
                ContractId::new(NEXTEST_INSTRUMENT)?,
                BUILTIN_KIND_VERSION,
            )?,
            class: InstrumentClass::Test,
            revision: BUILTIN_SPEC_VERSION,
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(NEXTEST_INSTRUMENT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            schema: ContractId::new(NEXTEST_INSTRUMENT)?,
            argument_template: Vec::new(),
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, Some(MAX_NEXTEST_OUTPUT_BYTES as u64)),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(
                ContractId::new(RUSTFMT_INSTRUMENT)?,
                BUILTIN_KIND_VERSION,
            )?,
            class: InstrumentClass::Formatter,
            revision: BUILTIN_SPEC_VERSION,
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(RUSTFMT_INSTRUMENT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            schema: ContractId::new(RUSTFMT_INSTRUMENT)?,
            argument_template: Vec::new(),
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, Some(MAX_RUSTFMT_OUTPUT_BYTES as u64)),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
    ])
}

/// Builds the builtin `compiler` profile: metadata, then the exact build.
///
/// # Errors
///
/// Returns [`ProfileError`] when a builtin literal fails validation or the
/// declared graph is not a DAG.
pub fn compiler_profile() -> Result<InstrumentProfile, ProfileError> {
    let dag = StageDag::build(
        COMPILER_PROFILE,
        vec![
            StageDecl::new(
                "cargo-metadata".to_owned(),
                ContractId::new(CARGO_CONTRACT_NAME)?,
                InstrumentKind::Build,
                Vec::new(),
                true,
                true,
            )?,
            StageDecl::new(
                "rustc-build".to_owned(),
                ContractId::new(RUSTC_INSTRUMENT)?,
                InstrumentKind::Build,
                vec!["cargo-metadata".to_owned()],
                true,
                true,
            )?,
        ],
    )?;
    InstrumentProfile::new(
        COMPILER_PROFILE.to_owned(),
        BUILTIN_PROFILE_REVISION,
        BUILTIN_SPEC_VERSION,
        vec![InstrumentKind::Build],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            ISOLATED_PROCESS_CLASS.to_owned(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Builds the builtin `test` profile: discovery, then the exact test run.
///
/// # Errors
///
/// Returns [`ProfileError`] when a builtin literal fails validation or the
/// declared graph is not a DAG.
pub fn test_profile() -> Result<InstrumentProfile, ProfileError> {
    let dag = StageDag::build(
        TEST_PROFILE,
        vec![
            StageDecl::new(
                "nextest-list".to_owned(),
                ContractId::new(NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                Vec::new(),
                true,
                true,
            )?,
            StageDecl::new(
                "nextest-run".to_owned(),
                ContractId::new(NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                vec!["nextest-list".to_owned()],
                true,
                true,
            )?,
        ],
    )?;
    InstrumentProfile::new(
        TEST_PROFILE.to_owned(),
        BUILTIN_PROFILE_REVISION,
        BUILTIN_SPEC_VERSION,
        vec![InstrumentKind::Test],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            ISOLATED_PROCESS_CLASS.to_owned(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Builds the versioned `package-verification` profile (issue #1914 W1).
///
/// I18.33's crate-local route is `eliot dev crate check <package>`: it resolves
/// the one `ModuleTestCapsule` and runs the applicable contract/schema/format
/// checks, the exact-package compilation, the selected unit/property/model/
/// golden tests, and the separately reported format check. The stage graph
/// declares only what the governing documents already fix — the compilation
/// class, the test class, and the format class — over the same builtin specs
/// `compiler`, `test`, and `dev-fast` already bind, so the route reuses admitted
/// executable identity instead of naming a command, a path, or a package.
///
/// The capsule's own typed selector, services, resources, expected discovery
/// rule, and proof ceiling bind at resolve time through the composition root
/// ([`crate::capsule_binding`]), exactly as they do for `dev-fast`; this profile
/// text never names a package, a test identity, or a task.
///
/// # Errors
///
/// Returns [`ProfileError`] when a builtin literal fails validation or the
/// declared graph is not a DAG.
pub fn package_verification_profile() -> Result<InstrumentProfile, ProfileError> {
    let dag = StageDag::build(
        PACKAGE_VERIFICATION_ROUTE,
        vec![
            StageDecl::new(
                "package-compile".to_owned(),
                ContractId::new(RUSTC_INSTRUMENT)?,
                InstrumentKind::Build,
                Vec::new(),
                true,
                true,
            )?,
            StageDecl::new(
                "package-test".to_owned(),
                ContractId::new(NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                vec!["package-compile".to_owned()],
                true,
                true,
            )?,
            StageDecl::new(
                "package-format".to_owned(),
                ContractId::new(RUSTFMT_INSTRUMENT)?,
                InstrumentKind::Format,
                Vec::new(),
                true,
                true,
            )?,
        ],
    )?;
    InstrumentProfile::new(
        PACKAGE_VERIFICATION_ROUTE.to_owned(),
        BUILTIN_PROFILE_REVISION,
        BUILTIN_SPEC_VERSION,
        vec![
            InstrumentKind::Build,
            InstrumentKind::Test,
            InstrumentKind::Format,
        ],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            ISOLATED_PROCESS_CLASS.to_owned(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Builds the versioned `bundle-verification` profile (issue #1914 W1).
///
/// I18.21's parity contract makes the local and the CI result of one named
/// profile revision comparable, so the bundle route is a versioned profile too
/// rather than a per-run command list. Its graph is the shared compile/test
/// spine every ELIOT verification route needs before any bundle-specific
/// identity is admitted: a bundle that adds release-specific stages binds them
/// as a new admitted revision of this name, never as an undeclared extra stage
/// or a second profile type.
///
/// The bundle identity itself — the published artifact set, its digests, and
/// its provenance — is not profile text. It is caller-attested and compared,
/// and the same `require_provenance` gate that refuses a missing tool identity
/// refuses a bundle stage whose recorded executable digest does not equal its
/// admitted supply-chain receipt.
///
/// # Errors
///
/// Returns [`ProfileError`] when a builtin literal fails validation or the
/// declared graph is not a DAG.
pub fn bundle_verification_profile() -> Result<InstrumentProfile, ProfileError> {
    let dag = StageDag::build(
        BUNDLE_VERIFICATION_ROUTE,
        vec![
            StageDecl::new(
                "bundle-compile".to_owned(),
                ContractId::new(RUSTC_INSTRUMENT)?,
                InstrumentKind::Build,
                Vec::new(),
                true,
                true,
            )?,
            StageDecl::new(
                "bundle-test".to_owned(),
                ContractId::new(NEXTEST_INSTRUMENT)?,
                InstrumentKind::Test,
                vec!["bundle-compile".to_owned()],
                true,
                true,
            )?,
        ],
    )?;
    InstrumentProfile::new(
        BUNDLE_VERIFICATION_ROUTE.to_owned(),
        BUILTIN_PROFILE_REVISION,
        BUILTIN_SPEC_VERSION,
        vec![InstrumentKind::Build, InstrumentKind::Test],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            ISOLATED_PROCESS_CLASS.to_owned(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Admission registry for versioned specs and profiles (I10.8.1).
///
/// The registry owns instrument definitions and profiles; it never spawns a
/// process, admits work to `testd`, schedules a task, writes canonical state,
/// or decides verification. Entries are keyed in [`BTreeMap`]s, so iteration
/// order is sorted and stable. Executable supply-chain receipts are admitted
/// on this same canonical path alongside specs and digested into the
/// registry identity; physical persistence beyond the registry (canonical
/// store, artifact/receipt client) belongs to the Governor write path.
#[derive(Clone, Debug)]
pub struct InstrumentRegistry {
    specs: BTreeMap<String, InstrumentSpec>,
    profiles: BTreeMap<(String, u64), InstrumentProfile>,
    supply_chain: SupplyChainTable,
    generation: u64,
}

impl InstrumentRegistry {
    /// Assembles a registry from caller-supplied definitions and receipts.
    ///
    /// Every profile stage must reference an admitted spec whose class equals
    /// the stage kind; dangling or mismatched references fail closed here,
    /// never at launch. Every receipt must pin an admitted spec digest at
    /// this generation; orphan or spec-drifted receipts fail closed here as
    /// well.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::DuplicateSpec`], [`ProfileError::DuplicateProfile`],
    /// [`ProfileError::UnknownSpec`], or [`ProfileError::SpecKindMismatch`].
    pub fn build(
        specs: Vec<InstrumentSpec>,
        profiles: Vec<InstrumentProfile>,
        generation: u64,
        receipts: Vec<SupplyChainReceipt>,
    ) -> Result<Self, ProfileError> {
        let mut spec_map = BTreeMap::new();
        for spec in specs {
            let key = spec.kind_key().to_owned();
            if spec_map.insert(key.clone(), spec).is_some() {
                return Err(ProfileError::DuplicateSpec { spec: key });
            }
        }
        let mut profile_map = BTreeMap::new();
        for profile in profiles {
            for stage in &profile.dag {
                let Some(spec) = spec_map.get(stage.spec.as_str()) else {
                    return Err(ProfileError::UnknownSpec {
                        profile: profile.name.clone(),
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                    });
                };
                if spec.class.coarse_kind() != stage.kind {
                    return Err(ProfileError::SpecKindMismatch {
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                        kind: stage.kind,
                    });
                }
            }
            let key = (profile.name.clone(), profile.revision);
            if profile_map.insert(key.clone(), profile).is_some() {
                return Err(ProfileError::DuplicateProfile {
                    profile: key.0,
                    revision: key.1,
                });
            }
        }
        let mut supply_chain = SupplyChainTable::default();
        for receipt in receipts {
            let Some(spec) = spec_map.get(receipt.instrument_key()) else {
                return Err(ProfileError::UnknownSpec {
                    profile: "<supply-chain>".to_owned(),
                    stage: "<admission>".to_owned(),
                    spec: receipt.instrument_key().to_owned(),
                });
            };
            if receipt.spec_digest != spec.digest() {
                return Err(ProfileError::SpecKindMismatch {
                    stage: "<supply-chain>".to_owned(),
                    spec: receipt.instrument_key().to_owned(),
                    kind: spec.class.coarse_kind(),
                });
            }
            if receipt.generation != generation {
                return Err(ProfileError::UnknownRevision {
                    profile: receipt.instrument_key().to_owned(),
                    revision: receipt.generation,
                });
            }
            let key = receipt.instrument_key().to_owned();
            if supply_chain.get(&key).is_some() {
                return Err(ProfileError::DuplicateSpec { spec: key });
            }
            supply_chain
                .admit(receipt)
                .map_err(|_| ProfileError::DuplicateSpec { spec: key })?;
        }
        Ok(Self {
            specs: spec_map,
            profiles: profile_map,
            supply_chain,
            generation,
        })
    }

    /// Assembles the registry with the builtin `compiler`/`test` profiles.
    ///
    /// Builtins ship no supply-chain receipt: no machine observation exists
    /// at registry construction, so the pre-launch gate binds the admitted
    /// executable file and schema without a pinned digest or version.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] when a builtin literal fails validation.
    pub fn with_builtin_profiles(generation: u64) -> Result<Self, ProfileError> {
        Self::build(
            builtin_specs()?,
            vec![compiler_profile()?, test_profile()?],
            generation,
            Vec::new(),
        )
    }

    /// Assembles the registry with every builtin profile, including the two
    /// verification routes of issue #1914.
    ///
    /// This is the one registry a local entrypoint and CI both admit, so the
    /// `package-verification` and `bundle-verification` routes resolve to the
    /// same exact revision, digest, and stage DAG on either side. A route that
    /// is missing here is missing on both sides together, never only in CI.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] when a builtin literal fails validation.
    pub fn with_verification_route_profiles(generation: u64) -> Result<Self, ProfileError> {
        Self::build(
            builtin_specs()?,
            vec![
                compiler_profile()?,
                test_profile()?,
                package_verification_profile()?,
                bundle_verification_profile()?,
            ],
            generation,
            Vec::new(),
        )
    }

    /// Admits one profile at its exact revision.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`] when no revision of the name
    /// is admitted, or [`ProfileError::UnknownRevision`] when the name is
    /// known but the exact revision is not.
    pub fn admitted(&self, name: &str, revision: u64) -> Result<&InstrumentProfile, ProfileError> {
        if let Some(profile) = self.profiles.get(&(name.to_owned(), revision)) {
            return Ok(profile);
        }
        if self.profiles.keys().any(|(known, _)| known == name) {
            return Err(ProfileError::UnknownRevision {
                profile: name.to_owned(),
                revision,
            });
        }
        Err(ProfileError::UnknownProfile {
            profile: name.to_owned(),
        })
    }

    /// Admits the exact head revision of one profile name.
    ///
    /// The head is the maximum admitted revision, which is deterministic for
    /// a fixed registry. Callers that must pin a revision use
    /// [`InstrumentRegistry::admitted`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`] when no revision of the name
    /// is admitted.
    pub fn admitted_head(&self, name: &str) -> Result<&InstrumentProfile, ProfileError> {
        self.profiles
            .iter()
            .filter_map(
                |((known, _), profile)| {
                    if known == name { Some(profile) } else { None }
                },
            )
            .max_by_key(|profile| profile.revision)
            .ok_or_else(|| ProfileError::UnknownProfile {
                profile: name.to_owned(),
            })
    }

    /// Looks up one admitted spec by kind identity.
    pub fn spec(&self, kind_id: &str) -> Option<&InstrumentSpec> {
        self.specs.get(kind_id)
    }

    /// Looks up the admitted supply-chain receipt for one kind identity.
    ///
    /// `None` means no machine observation was admitted for the kind at this
    /// generation: the pre-launch gate then binds the admitted executable
    /// file and schema without a pinned digest or version.
    pub fn supply_chain(&self, kind_id: &str) -> Option<&SupplyChainReceipt> {
        self.supply_chain.get(kind_id)
    }

    /// Number of admitted profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the registry admits no profiles.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Registry generation the admission was validated against.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Deterministic identity over generation, specs, profiles, and receipts.
    pub fn digest(&self) -> String {
        let mut material = self.generation.to_string();
        material.push('\0');
        for spec in self.specs.values() {
            material.push_str(&spec.digest());
            material.push('\0');
        }
        for profile in self.profiles.values() {
            material.push_str(&profile.digest());
            material.push('\0');
        }
        material.push_str(&self.supply_chain.digest());
        material.push('\0');
        sha256_hex(material.as_bytes())
    }

    /// Persists the admitted specs, profiles, receipts, and generation.
    ///
    /// The snapshot carries every admitted definition in sorted-identity
    /// order, so the same registry always persists to the same bytes. The
    /// bytes travel to durable storage through the Governor write path,
    /// which owns canonical-store authority; this registry never writes
    /// canonical state itself.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Snapshot`] when the snapshot cannot be
    /// encoded.
    pub fn persist(&self) -> Result<String, ProfileError> {
        let snapshot = InstrumentRegistrySnapshot {
            schema: REGISTRY_SNAPSHOT_SCHEMA.to_owned(),
            version: REGISTRY_SNAPSHOT_SCHEMA_VERSION.to_owned(),
            generation: self.generation,
            specs: self.specs.values().cloned().collect(),
            profiles: self.profiles.values().cloned().collect(),
            receipts: self.supply_chain.receipts().into_iter().cloned().collect(),
        };
        serde_json::to_string(&snapshot).map_err(|error| ProfileError::Snapshot {
            detail: error.to_string(),
        })
    }

    /// Recovers a registry persisted by [`InstrumentRegistry::persist`].
    ///
    /// Recovery treats the snapshot as untrusted input: the schema identity
    /// is checked first, then every spec, stage, profile, and receipt is
    /// rebuilt through its validated constructor, and the rebuilt
    /// definitions are re-admitted through [`InstrumentRegistry::build`], so
    /// orphan receipts, spec drift, generation mismatch, and cyclic stage
    /// graphs fail closed here exactly as they do at first admission. A
    /// receipt admitted at generation N is therefore recovered and
    /// re-validated at generation N+1 instead of being trusted blindly.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Snapshot`] when the bytes are malformed or
    /// name an unsupported schema, or the admission error when a rebuilt
    /// definition fails validation.
    pub fn recover(encoded: &str) -> Result<Self, ProfileError> {
        let snapshot: InstrumentRegistrySnapshot =
            serde_json::from_str(encoded).map_err(|error| ProfileError::Snapshot {
                detail: error.to_string(),
            })?;
        if snapshot.schema != REGISTRY_SNAPSHOT_SCHEMA
            || snapshot.version != REGISTRY_SNAPSHOT_SCHEMA_VERSION
        {
            return Err(ProfileError::Snapshot {
                detail: format!(
                    "unsupported registry snapshot '{}@{}'",
                    snapshot.schema, snapshot.version
                ),
            });
        }
        let mut specs = Vec::with_capacity(snapshot.specs.len());
        for spec in snapshot.specs {
            specs.push(rebuild_spec(spec)?);
        }
        let mut profiles = Vec::with_capacity(snapshot.profiles.len());
        for profile in snapshot.profiles {
            profiles.push(rebuild_profile(profile)?);
        }
        let mut receipts = Vec::with_capacity(snapshot.receipts.len());
        for receipt in snapshot.receipts {
            receipts.push(rebuild_receipt(receipt)?);
        }
        Self::build(specs, profiles, snapshot.generation, receipts)
    }
}

/// Versioned durable form of the canonical admission registry (I10.8.1).
///
/// The snapshot persists the admitted [`InstrumentSpec`] definitions,
/// [`InstrumentProfile`] definitions, and executable
/// [`SupplyChainReceipt`]s at one registry generation. Profiles travel
/// alongside specs and receipts because recovery re-admits the whole
/// registry through [`InstrumentRegistry::build`]: without the profiles the
/// recovered registry could admit no stage graph at generation N+1.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistrySnapshot {
    /// Stable snapshot schema name.
    pub schema: String,
    /// Exact snapshot schema wire version.
    pub version: String,
    /// Registry generation the admission was validated against.
    pub generation: u64,
    /// Admitted spec definitions in sorted kind-identity order.
    pub specs: Vec<InstrumentSpec>,
    /// Admitted profile definitions in sorted name/revision order.
    pub profiles: Vec<InstrumentProfile>,
    /// Admitted supply-chain receipts in sorted instrument-identity order.
    pub receipts: Vec<SupplyChainReceipt>,
}

/// Rebuilds one deserialized spec through its validated constructor.
fn rebuild_spec(spec: InstrumentSpec) -> Result<InstrumentSpec, ProfileError> {
    let kind = InstrumentKindId::new(
        ContractId::new(spec.kind.as_str().to_owned())?,
        spec.kind.version(),
    )?;
    InstrumentSpec::new(InstrumentSpecParams {
        kind,
        class: spec.class,
        revision: spec.revision,
        executable: spec.executable,
        executable_version: spec.executable_version,
        parser: spec.parser,
        parser_generation: spec.parser_generation,
        environment_profile: spec.environment_profile,
        schema: spec.schema,
        argument_template: spec.argument_template,
        credential_policy: spec.credential_policy,
        network_policy: spec.network_policy,
        limits: spec.limits,
        max_concurrency: spec.max_concurrency,
    })
}

/// Rebuilds one deserialized profile through its validated constructors.
fn rebuild_profile(profile: InstrumentProfile) -> Result<InstrumentProfile, ProfileError> {
    let stages: Vec<StageDecl> = profile.dag.stages.into_values().collect();
    let mut decls = Vec::with_capacity(stages.len());
    for stage in stages {
        decls.push(StageDecl::new(
            stage.stage_id,
            stage.spec,
            stage.kind,
            stage.depends_on,
            stage.required,
            stage.external,
        )?);
    }
    let dag = StageDag::build(&profile.name, decls)?;
    let classes = ProfileScopeClasses::new(
        profile.classes.target_layout,
        profile.classes.environment,
        profile.classes.workscope,
    )?;
    InstrumentProfile::new(
        profile.name,
        profile.revision,
        profile.spec_revision,
        profile.kinds,
        dag,
        classes,
    )
}

/// Rebuilds one deserialized receipt through its validated constructor.
fn rebuild_receipt(receipt: SupplyChainReceipt) -> Result<SupplyChainReceipt, ProfileError> {
    SupplyChainReceipt::new(
        receipt.instrument,
        receipt.executable,
        receipt.content_digest,
        receipt.tool_version,
        receipt.spec_digest,
        receipt.generation,
    )
    .map_err(|error| ProfileError::Snapshot {
        detail: error.to_string(),
    })
}

/// Target layout bound at resolve time: admitted roots, never profile text.
///
/// Roots are validated lexically (absolute, no parent traversal) with no
/// filesystem access; existence and lease checks belong to the admitting
/// composition root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetLayout {
    /// Admitted source root; the stage working directory.
    pub source_root: String,
    /// Admitted external build target root.
    pub target_root: String,
    /// Admitted cache root.
    pub cache_root: String,
}

impl TargetLayout {
    /// Binds admitted roots, validating shape only.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when a root is blank, relative,
    /// carries control characters, or traverses to a parent.
    pub fn new(
        source_root: String,
        target_root: String,
        cache_root: String,
    ) -> Result<Self, ProfileError> {
        for (root, field) in [
            (source_root.as_str(), "source_root"),
            (target_root.as_str(), "target_root"),
            (cache_root.as_str(), "cache_root"),
        ] {
            validate_text(root, field)?;
            let path = std::path::Path::new(root);
            if !path.is_absolute()
                || path
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
            {
                return Err(ProfileError::InvalidText { field });
            }
        }
        Ok(Self {
            source_root,
            target_root,
            cache_root,
        })
    }

    /// Deterministic identity over the three admitted roots.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}",
            self.source_root, self.target_root, self.cache_root
        );
        sha256_hex(material.as_bytes())
    }
}

/// Workscope bound at resolve time: declared scope plus state fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkScope {
    /// Declared scope used for coverage and freshness.
    pub declared_scope: String,
    /// State fence captured at admission.
    pub fence: StateFence,
}

impl WorkScope {
    /// Binds a declared scope to its state fence.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the scope is blank, or
    /// [`ProfileError::Contract`] when the fence is invalid.
    pub fn new(declared_scope: String, fence: StateFence) -> Result<Self, ProfileError> {
        validate_text(&declared_scope, "declared_scope")?;
        fence.validate()?;
        Ok(Self {
            declared_scope,
            fence,
        })
    }

    /// Deterministic identity over scope and fence material.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{:?}\0{:?}",
            self.declared_scope, self.fence.authority_epoch, self.fence.resource_generation,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Stage environment bound at resolve time.
///
/// The digest is attested from caller-supplied material and stays attested,
/// never independently observed; only the class equality against the admitted
/// profile is enforced here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageEnvironment {
    /// Environment class, such as `isolated-process`.
    pub class: String,
    /// Lowercase SHA-256 over the attested environment material.
    pub digest: String,
}

impl StageEnvironment {
    /// Attests an environment class with its material digest.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the class is blank or
    /// carries control characters.
    pub fn attest(class: String, material: &str) -> Result<Self, ProfileError> {
        validate_text(&class, "environment_class")?;
        Ok(Self {
            class,
            digest: sha256_hex(material.as_bytes()),
        })
    }
}

/// One fully resolved stage in topological order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedStage {
    /// Durable stage identity.
    pub stage_id: String,
    /// Bound spec kind identity.
    pub spec: ContractId,
    /// Stage class.
    pub kind: InstrumentKind,
    /// Whether the aggregate fails without this stage.
    pub required: bool,
    /// Whether the stage dispatches through `TestExecutionPlane`.
    pub external: bool,
    /// Prerequisite stage identities.
    pub depends_on: Vec<String>,
}

/// One fully resolved profile: exact revision plus bound layout, scope,
/// environment, and stage DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProfile {
    /// Admitted profile name.
    pub name: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Stages in deterministic topological order.
    pub stages: Vec<ResolvedStage>,
    /// Bound target layout.
    pub layout: TargetLayout,
    /// Bound workscope.
    pub scope: WorkScope,
    /// Bound environment.
    pub environment: StageEnvironment,
    /// Registry generation the resolution was validated against.
    pub registry_generation: u64,
    /// Registry digest the resolution was validated against.
    pub registry_digest: String,
    /// Resolution digest over registry, definition, and bindings.
    pub resolution_digest: String,
}

/// Resolves an exact profile revision to its bound execution shape (I10.8.4).
///
/// The resolver admits the exact revision, validates the caller-supplied
/// layout, scope, and environment against the profile classes, and expands
/// the declared stage DAG in deterministic topological order. It synthesizes
/// no commands, paths, or revisions of its own.
pub struct InstrumentProfileResolver<'a> {
    registry: &'a InstrumentRegistry,
}

impl<'a> InstrumentProfileResolver<'a> {
    /// Borrows the registry resolutions are validated against.
    pub fn new(registry: &'a InstrumentRegistry) -> Self {
        Self { registry }
    }

    /// Resolves one exact profile revision with caller-admitted bindings.
    ///
    /// Roots must be pairwise distinct, every stage spec must still bind at
    /// use time, the scope fence must validate, and the attested environment
    /// class must equal the admitted profile class.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`], [`ProfileError::UnknownRevision`],
    /// [`ProfileError::UnknownSpec`], [`ProfileError::SpecKindMismatch`],
    /// [`ProfileError::LayoutCollision`], or [`ProfileError::EnvironmentMismatch`].
    pub fn resolve(
        &self,
        name: &str,
        revision: u64,
        layout: TargetLayout,
        scope: WorkScope,
        environment: StageEnvironment,
    ) -> Result<ResolvedProfile, ProfileError> {
        let profile = self.registry.admitted(name, revision)?;
        for stage in &profile.dag {
            let spec = self.registry.spec(stage.spec.as_str()).ok_or_else(|| {
                ProfileError::UnknownSpec {
                    profile: profile.name.clone(),
                    stage: stage.stage_id.clone(),
                    spec: stage.spec.as_str().to_owned(),
                }
            })?;
            if spec.class.coarse_kind() != stage.kind {
                return Err(ProfileError::SpecKindMismatch {
                    stage: stage.stage_id.clone(),
                    spec: stage.spec.as_str().to_owned(),
                    kind: stage.kind,
                });
            }
        }
        if layout.source_root == layout.target_root
            || layout.source_root == layout.cache_root
            || layout.target_root == layout.cache_root
        {
            return Err(ProfileError::LayoutCollision);
        }
        if environment.class != profile.classes.environment {
            return Err(ProfileError::EnvironmentMismatch {
                profile: profile.name.clone(),
                expected: profile.classes.environment.clone(),
                observed: environment.class.clone(),
            });
        }
        let stages = profile
            .dag
            .topological_order()
            .into_iter()
            .map(|stage| ResolvedStage {
                stage_id: stage.stage_id.clone(),
                spec: stage.spec.clone(),
                kind: stage.kind,
                required: stage.required,
                external: stage.external,
                depends_on: stage.depends_on.clone(),
            })
            .collect::<Vec<_>>();
        let profile_digest = profile.digest();
        let dag_digest = profile.dag.digest();
        let registry_generation = self.registry.generation();
        let registry_digest = self.registry.digest();
        let resolution_digest = sha256_hex(
            format!(
                "{registry_generation}\0{registry_digest}\0{profile_digest}\0{dag_digest}\0{}\0{}\0{}",
                layout.digest(),
                scope.digest(),
                environment.digest,
            )
            .as_bytes(),
        );
        Ok(ResolvedProfile {
            name: profile.name.clone(),
            revision: profile.revision,
            profile_digest,
            dag_digest,
            stages,
            layout,
            scope,
            environment,
            registry_generation,
            registry_digest,
            resolution_digest,
        })
    }
}

/// One admitted compiler stage in topological order.
///
/// The stage carries the full admission the pre-launch gate validates the
/// invocation against: exact executable identity, argument schema and fixed
/// template, environment/scope/credential/network policy, resource ceiling,
/// declared concurrency, and the spec/parser generations the launch receipt
/// records. Nothing here is command text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedStage {
    /// Durable stage identity.
    pub stage_id: String,
    /// Bound spec kind identity.
    pub spec: ContractId,
    /// Stage class.
    pub kind: InstrumentKind,
    /// Whether the aggregate fails without this stage.
    pub required: bool,
    /// Whether the stage dispatches through `TestExecutionPlane`.
    pub external: bool,
    /// Prerequisite stage identities.
    pub depends_on: Vec<String>,
    /// Admitted profile name this stage was compiled from.
    ///
    /// The gate checks the caller-supplied profile label against this
    /// registry-derived identity: a grant never seals a caller label the
    /// registry did not admit.
    pub profile: String,
    /// Exact admitted profile revision this stage was compiled from.
    pub profile_revision: u64,
    /// Admitted spec revision bound to this stage.
    pub spec_revision: ContractVersion,
    /// Digest of the admitted spec revision.
    pub spec_digest: String,
    /// Admitted kind version bound to this stage.
    pub kind_version: ContractVersion,
    /// Exact admitted executable file identity.
    pub executable: String,
    /// Admitted tool version requirement, when the spec pins one.
    pub executable_version: Option<String>,
    /// Admitted supply-chain receipt for the kind, when a machine
    /// observation was admitted for it at this generation.
    pub supply_receipt: Option<SupplyChainReceipt>,
    /// Fixed command template; empty admits only the empty argument vector.
    pub argument_template: Vec<String>,
    /// Invocation schema authority.
    pub schema: ContractId,
    /// Admitted environment class.
    pub environment_class: String,
    /// Admitted credential policy identity.
    pub credential_policy: ContractId,
    /// Admitted network policy identity.
    pub network_policy: ContractId,
    /// Admitted parser identity.
    pub parser: ContractId,
    /// Admitted parser generation.
    pub parser_generation: u64,
    /// Admitted raw-output capture ceiling in bytes, when the spec sets one.
    pub max_output_bytes: Option<u64>,
    /// Admitted wall-clock ceiling in milliseconds, when the spec sets one.
    pub timeout_ms: Option<u64>,
    /// Declared per-adapter maximum concurrency, bound into the process
    /// grant and enforced by the owning plane, never by a global pool.
    pub max_concurrency: u32,
}

/// Typed pre-launch admission failure (I10.8.3).
///
/// Every variant refuses the invocation before any child process is created:
/// unregistered kind IDs, raw shell text, unknown executable identities, and
/// agent-provided executable/argument combinations never reach the execution
/// plane. The failure carries no process, no permit, and no retry directive.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdmissionError {
    /// No admitted spec is registered under the requested instrument identity.
    #[error("unknown instrument kind '{instrument}': no admitted spec")]
    UnknownKind {
        /// Requested instrument contract name.
        instrument: String,
    },
    /// The requested class does not match the admitted stage class.
    #[error("invocation kind {observed:?} does not match admitted stage kind {expected:?}")]
    KindMismatch {
        /// Admitted stage class.
        expected: InstrumentKind,
        /// Requested invocation class.
        observed: InstrumentKind,
    },
    /// One argument carries raw shell text and is refused before launch.
    #[error("argument {index} carries raw shell text and is refused before launch")]
    ShellText {
        /// Position of the offending argument.
        index: usize,
    },
    /// The requested arguments differ from the admitted fixed template.
    #[error("arguments do not match the admitted template: {detail}")]
    ArgumentMismatch {
        /// How the combination differs.
        detail: String,
    },
    /// The executable identity is unknown, changed, or claimed without a
    /// machine observation, and is refused before launch.
    #[error("executable identity refused before launch: {detail}")]
    ExecutableMismatch {
        /// How the identity differs.
        detail: String,
    },
    /// A supply-chain receipt pins an executable digest but the caller
    /// supplied no machine observation to check it against.
    #[error(
        "no machine-observed executable identity for instrument '{instrument}' with an admitted supply-chain receipt"
    )]
    UnresolvedObservation {
        /// Instrument contract name carrying the receipt.
        instrument: String,
    },
    /// The admission request itself is malformed.
    #[error("admission request is malformed: {detail}")]
    InvalidRequest {
        /// How the request fails shape validation.
        detail: String,
    },
}

/// Refuses raw shell text before launch (I10.8.3).
///
/// Arguments are exact argv elements, never a shell line: any element
/// carrying shell operators or expansions fails closed with its position.
/// Admitted fixed templates bypass this scan by matching exactly against the
/// manifest template instead.
fn reject_shell_text(arguments: &[String]) -> Result<(), AdmissionError> {
    const SHELL_OPERATORS: &[char] = &[';', '|', '&', '`', '$', '>', '<'];
    for (index, argument) in arguments.iter().enumerate() {
        if argument.chars().any(|cell| SHELL_OPERATORS.contains(&cell)) {
            return Err(AdmissionError::ShellText { index });
        }
    }
    Ok(())
}

impl AdmittedStage {
    /// Builds the typed pre-launch admission request for one invocation.
    ///
    /// Invocation facts (instrument, class, profile, arguments) come from the
    /// caller; the executable snapshot comes from the launcher-observed
    /// machine identity, when the composition root can observe one. The
    /// shared gate validates the request against this admission.
    pub fn admission_request(
        &self,
        invocation: &eliot_instrument_api::InstrumentInvocation,
        observed: Option<&ResolvedExecutableIdentity>,
    ) -> InstrumentAdmissionRequest {
        InstrumentAdmissionRequest {
            instrument: invocation.instrument.clone(),
            kind: invocation.kind,
            profile: invocation.profile.clone(),
            arguments: invocation.arguments.clone(),
            executable_path: observed.map(|identity| identity.canonical_path.clone()),
            executable_digest: observed.map(|identity| identity.content_digest.clone()),
            executable_version: observed.and_then(|identity| identity.tool_version.clone()),
        }
    }

    /// Checks the executable identity against the admitted file, pinned
    /// version, and supply-chain receipt before launch.
    ///
    /// The caller must supply the launcher-observed machine identity: every
    /// external stage launches only under an owner-observed executable, so a
    /// missing observation never yields a launchable grant. The observation
    /// reference itself is re-validated through the owning constructor under
    /// the admitted spec identity first, so a malformed or forged identity
    /// bridged by any entry point fails closed here instead of reaching the
    /// file, version, and receipt checks. The request snapshot must then
    /// equal the observation, and the observation must name the admitted
    /// file, carry the pinned version, and match the receipt. Returns the
    /// content digest bound into the process grant.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::ExecutableMismatch`] when the identity is
    /// unknown, changed, malformed, or claimed without observation.
    fn check_executable(
        &self,
        request: &InstrumentAdmissionRequest,
        observed: &ResolvedExecutableIdentity,
    ) -> Result<String, AdmissionError> {
        ResolvedExecutableIdentity::new(
            self.spec.as_str(),
            observed.canonical_path.clone(),
            observed.content_digest.clone(),
            observed.tool_version.clone(),
            observed.environment_digest.clone(),
            observed.arguments.clone(),
        )
        .map_err(|error| AdmissionError::ExecutableMismatch {
            detail: error.to_string(),
        })?;
        if request.executable_path.as_deref() != Some(observed.canonical_path.as_str())
            || request.executable_digest.as_deref() != Some(observed.content_digest.as_str())
            || request.executable_version != observed.tool_version
        {
            return Err(AdmissionError::ExecutableMismatch {
                detail: "request executable snapshot differs from machine observation".to_owned(),
            });
        }
        if observed.executable_file_name() != self.executable.to_ascii_lowercase() {
            return Err(AdmissionError::ExecutableMismatch {
                detail: format!(
                    "observed '{}' is not the admitted executable '{}'",
                    observed.canonical_path, self.executable,
                ),
            });
        }
        if let Some(pinned) = self.executable_version.as_deref()
            && observed.tool_version.as_deref() != Some(pinned)
        {
            return Err(AdmissionError::ExecutableMismatch {
                detail: format!("observed version differs from the admitted version '{pinned}'"),
            });
        }
        if let Some(receipt) = &self.supply_receipt {
            receipt.check_observation(observed).map_err(|error| {
                AdmissionError::ExecutableMismatch {
                    detail: error.to_string(),
                }
            })?;
        }
        Ok(observed.content_digest.clone())
    }

    /// Admits one typed invocation against this stage before process creation.
    ///
    /// This is the shared pre-launch admission boundary (I10.8.3): the
    /// request carries only typed invocation facts plus the
    /// launcher-observed machine identity, never shell text or an
    /// agent-composed command. The admitted profile, spec, fixed argument
    /// template, supply-chain receipt, and `profile_revision` come from the
    /// planned stage and the owning route; the caller never supplies them.
    /// Pure in-process stages take no process grant here: they stay on the
    /// non-process path and are refused. Every external stage requires the
    /// owner-observed executable identity; an empty content digest never
    /// yields a launchable grant. The requested arguments must equal the
    /// admitted fixed template exactly; an empty admitted template admits
    /// only the empty argument vector. Success seals every bound field,
    /// including the observed canonical path and the admitted supply-chain
    /// receipt digest, into an [`InstrumentAdmissionGrant`] whose digest the
    /// launch receipt records.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the stage is pure, the caller labels
    /// (profile, revision) differ from the admitted stage identity, the kind
    /// ID is unregistered, the class differs, an argument carries shell text
    /// or leaves the fixed template, or the executable identity is unknown,
    /// changed, malformed, or unobserved.
    pub fn admit(
        &self,
        request: &InstrumentAdmissionRequest,
        observed: Option<&ResolvedExecutableIdentity>,
        profile_revision: u64,
    ) -> Result<InstrumentAdmissionGrant, AdmissionError> {
        request
            .validate()
            .map_err(|error| AdmissionError::InvalidRequest {
                detail: error.to_string(),
            })?;
        if !self.external {
            return Err(AdmissionError::InvalidRequest {
                detail: "pure in-process stage takes no process grant".to_owned(),
            });
        }
        if request.profile != self.profile {
            return Err(AdmissionError::InvalidRequest {
                detail: "invocation profile differs from the admitted stage profile".to_owned(),
            });
        }
        if profile_revision != self.profile_revision {
            return Err(AdmissionError::InvalidRequest {
                detail: "profile revision differs from the admitted stage revision".to_owned(),
            });
        }
        if request.instrument.as_str() != self.spec.as_str() {
            return Err(AdmissionError::UnknownKind {
                instrument: request.instrument.as_str().to_owned(),
            });
        }
        if request.kind != self.kind {
            return Err(AdmissionError::KindMismatch {
                expected: self.kind,
                observed: request.kind,
            });
        }
        if request.arguments != self.argument_template {
            reject_shell_text(&request.arguments)?;
            return Err(AdmissionError::ArgumentMismatch {
                detail: "requested arguments differ from the admitted fixed template".to_owned(),
            });
        }
        let Some(identity) = observed else {
            return Err(AdmissionError::UnresolvedObservation {
                instrument: self.spec.as_str().to_owned(),
            });
        };
        let content_digest = self.check_executable(request, identity)?;
        let mut grant = InstrumentAdmissionGrant {
            kind_id: self.spec.as_str().to_owned(),
            kind_version: self.kind_version,
            kind: self.kind,
            profile: self.profile.clone(),
            profile_revision: self.profile_revision,
            spec_digest: self.spec_digest.clone(),
            executable: self.executable.clone(),
            executable_version: self.executable_version.clone(),
            content_digest,
            executable_path: identity.canonical_path.clone(),
            supply_digest: self
                .supply_receipt
                .as_ref()
                .map(SupplyChainReceipt::digest)
                .unwrap_or_default(),
            arguments: request.arguments.clone(),
            environment_class: self.environment_class.clone(),
            scope_class: ADMITTED_SCOPE_CLASS.to_owned(),
            credential_policy: self.credential_policy.clone(),
            network_policy: self.network_policy.clone(),
            timeout_ms: self.timeout_ms,
            max_output_bytes: self.max_output_bytes,
            parser: self.parser.clone(),
            parser_generation: self.parser_generation,
            grant_digest: String::new(),
        };
        grant.grant_digest = grant.digest();
        Ok(grant)
    }
}

/// The governed output of [`ProfileCompiler::compile`].
///
/// Same admitted name through any entry point yields the same revision,
/// digests, classes, and stage sequence; that determinism is the acceptance
/// surface for cross-entry-point equivalence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedProfile {
    /// Admitted profile name.
    pub name: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Admitted invocation classes.
    pub kinds: Vec<InstrumentKind>,
    /// Stages in deterministic topological order.
    pub stages: Vec<AdmittedStage>,
}

impl AdmittedProfile {
    /// Whether the admission covers the invocation class.
    pub fn admits_kind(&self, kind: InstrumentKind) -> bool {
        self.kinds.contains(&kind)
    }
}

impl AdmittedStage {
    /// Selects the governed build class for this admitted stage definition.
    ///
    /// Returns `None` when the stage kind has no dedicated class; such a
    /// stage emits no build output or requires an explicitly owner-issued
    /// class, and is never silently merged into a neighbor class.
    pub fn build_class(&self) -> Option<BuildClass> {
        BuildClass::for_instrument_kind(self.kind)
    }
}

impl ResolvedStage {
    /// Selects the governed build class for this resolved stage definition.
    ///
    /// Returns `None` when the stage kind has no dedicated class; such a
    /// stage emits no build output or requires an explicitly owner-issued
    /// class, and is never silently merged into a neighbor class.
    pub fn build_class(&self) -> Option<BuildClass> {
        BuildClass::for_instrument_kind(self.kind)
    }
}

/// Compiler output: governed admission or explicit quarantine (I10.8.10).
///
/// Legacy profile text that bypasses the registry is quarantined, never
/// promoted: it proceeds only through its pre-existing path with no governed
/// revision, stage graph, or receipt, so bypass routes stay visible instead
/// of silently becoming canonical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompiledProfile {
    /// The profile resolved to an exact admitted revision.
    Governed(AdmittedProfile),
    /// The profile bypasses the compiler; no governed claim may rest on it.
    LegacyQuarantine {
        /// Bypassed profile text, preserved for attribution.
        profile: String,
    },
}

impl CompiledProfile {
    /// Returns the governed admission, refusing quarantined profiles.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Quarantined`] when the profile bypassed the
    /// compiler.
    pub fn admitted(&self) -> Result<&AdmittedProfile, ProfileError> {
        match self {
            Self::Governed(admitted) => Ok(admitted),
            Self::LegacyQuarantine { profile } => Err(ProfileError::Quarantined {
                profile: profile.clone(),
            }),
        }
    }

    /// Gates one invocation class through the compiler output.
    ///
    /// Governed admissions reject foreign classes fail-closed; quarantined
    /// legacy text passes through untouched so existing capability keeps its
    /// current behavior without gaining a governed claim.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnsupportedKind`] when a governed admission
    /// does not cover the invocation class.
    pub fn require_kind(
        &self,
        kind: InstrumentKind,
    ) -> Result<Option<&AdmittedProfile>, ProfileError> {
        match self {
            Self::Governed(admitted) => {
                if admitted.admits_kind(kind) {
                    Ok(Some(admitted))
                } else {
                    Err(ProfileError::UnsupportedKind {
                        profile: admitted.name.clone(),
                        revision: admitted.revision,
                        kind,
                    })
                }
            }
            Self::LegacyQuarantine { .. } => Ok(None),
        }
    }

    /// Whether the compiler admitted the profile as governed.
    pub fn is_governed(&self) -> bool {
        matches!(self, Self::Governed(_))
    }
}

/// The single profile compiler shared by every verification entry point.
///
/// Local verification, agent verifier requests, and every later lane
/// (external patch verification, wrappers, CI, `FinishService`) compile
/// through this one function, so the same admitted profile always resolves
/// to the same revision and stage graph. There is no second admission path.
pub struct ProfileCompiler<'a> {
    registry: &'a InstrumentRegistry,
}

impl<'a> ProfileCompiler<'a> {
    /// Borrows the registry admissions resolve against.
    pub fn new(registry: &'a InstrumentRegistry) -> Self {
        Self { registry }
    }

    /// Compiles one profile name to governed admission or quarantine.
    ///
    /// Matching is exact: no trimming, case folding, or alias expansion.
    /// Unknown names quarantine; they never resolve to a neighbor profile.
    pub fn compile(&self, profile: &str) -> CompiledProfile {
        match self.registry.admitted_head(profile) {
            Ok(admitted) => match self.compile_exact(&admitted.name.clone(), admitted.revision) {
                Ok(governed) => CompiledProfile::Governed(governed),
                Err(_) => CompiledProfile::LegacyQuarantine {
                    profile: profile.to_owned(),
                },
            },
            Err(_) => CompiledProfile::LegacyQuarantine {
                profile: profile.to_owned(),
            },
        }
    }

    /// Compiles one profile at a caller-pinned exact revision.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`] or [`ProfileError::UnknownRevision`].
    pub fn compile_exact(
        &self,
        profile: &str,
        revision: u64,
    ) -> Result<AdmittedProfile, ProfileError> {
        let admitted = self.registry.admitted(profile, revision)?;
        let mut stages = Vec::with_capacity(admitted.dag.len());
        for stage in admitted.dag.topological_order() {
            let spec = self.registry.spec(stage.spec.as_str()).ok_or_else(|| {
                ProfileError::UnknownSpec {
                    profile: admitted.name.clone(),
                    stage: stage.stage_id.clone(),
                    spec: stage.spec.as_str().to_owned(),
                }
            })?;
            let supply_receipt = self.registry.supply_chain(stage.spec.as_str()).cloned();
            stages.push(AdmittedStage {
                stage_id: stage.stage_id.clone(),
                spec: stage.spec.clone(),
                kind: stage.kind,
                required: stage.required,
                external: stage.external,
                depends_on: stage.depends_on.clone(),
                profile: admitted.name.clone(),
                profile_revision: admitted.revision,
                spec_revision: spec.revision,
                spec_digest: spec.digest(),
                kind_version: spec.kind.version(),
                executable: spec.executable.clone(),
                executable_version: spec.executable_version.clone(),
                supply_receipt,
                argument_template: spec.argument_template.clone(),
                schema: spec.schema.clone(),
                environment_class: spec.environment_profile.clone(),
                credential_policy: spec.credential_policy.clone(),
                network_policy: spec.network_policy.clone(),
                parser: spec.parser.clone(),
                parser_generation: spec.parser_generation,
                max_output_bytes: spec.limits.max_output_bytes,
                timeout_ms: spec.limits.timeout_ms,
                max_concurrency: spec.max_concurrency,
            });
        }
        Ok(AdmittedProfile {
            name: admitted.name.clone(),
            revision: admitted.revision,
            profile_digest: admitted.digest(),
            dag_digest: admitted.dag.digest(),
            kinds: admitted.kinds.clone(),
            stages,
        })
    }

    /// Fully resolves one exact revision with caller-admitted bindings.
    ///
    /// This is the [`InstrumentProfileResolver`] path behind the single
    /// compiler entry point, so resolved revisions always share the compiled
    /// definition.
    ///
    /// # Errors
    ///
    /// Returns the [`InstrumentProfileResolver::resolve`] failures.
    pub fn resolve_full(
        &self,
        profile: &str,
        revision: u64,
        layout: TargetLayout,
        scope: WorkScope,
        environment: StageEnvironment,
    ) -> Result<ResolvedProfile, ProfileError> {
        InstrumentProfileResolver::new(self.registry).resolve(
            profile,
            revision,
            layout,
            scope,
            environment,
        )
    }

    /// Compiles one profile name and resolves its exact admitted revision.
    ///
    /// This is the production resolution entry of the single compiler: the
    /// revision is taken from this compiler's own governed admission instead
    /// of from caller text, so a resolved profile always shares the compiled
    /// definition, and a quarantined name never reaches the resolver. Callers
    /// supply only the admitted execution bindings (target layout, `WorkScope`,
    /// and environment), which the resolver validates against the profile
    /// classes before expanding the stage DAG.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`] when the name quarantines with
    /// no admitted revision, and the [`InstrumentProfileResolver::resolve`]
    /// failures when a binding is refused.
    pub fn resolve_admitted(
        &self,
        profile: &str,
        layout: TargetLayout,
        scope: WorkScope,
        environment: StageEnvironment,
    ) -> Result<ResolvedProfile, ProfileError> {
        let admitted = self.registry.admitted_head(profile)?;
        let admission = self.compile_exact(&admitted.name, admitted.revision)?;
        self.resolve_full(
            &admission.name,
            admission.revision,
            layout,
            scope,
            environment,
        )
    }
}
