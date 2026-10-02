//! Neutral canonical instrument registry definitions and shared admission checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::FileIdentity;
use eliot_contracts::{ContractError, ContractId, ContractVersion, EpochId, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{InstrumentAdmissionGrant, InstrumentInvocation, InstrumentKind};

/// Stable wire name of the canonical instrument registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA: &str = "eliot.instrument.registry-snapshot";
/// Exact current wire version of the canonical instrument registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA_VERSION: &str = "1.3.0";

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
    /// A requested alias is outside the closed [`PROFILE_ALIASES`] table.
    #[error("'{alias}' is not an admitted profile alias")]
    UnknownAlias {
        /// Requested alias name.
        alias: String,
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
    /// The owner-observed `TestD` productive binding, nextest command, and
    /// registry definition do not describe the same closed executable.
    #[error("TestD productive nextest binding differs from its admitted instrument definition")]
    TestdProductiveBindingMismatch,
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
/// Module/Instrument manifest without changing this enum or the Kernel.
/// The semantic class and typed [`InstrumentKind`] are separate spec fields;
/// the profile stage must match the latter exactly.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstrumentClass {
    /// Source identity and version-control observation.
    SourceIdentity,
    /// Compilation and build.
    Compiler,
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
    /// Typed invocation category bound to this admitted instrument kind.
    pub invocation_kind: InstrumentKind,
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
    /// Closed source policy for the exact child environment projection.
    pub environment_policy: EnvironmentPolicy,
    /// Invocation schema authority: the contract that validates arguments.
    pub schema: ContractId,
    /// Fixed command template; empty when the manifest declares none, in
    /// which case only the empty argument vector is admitted.
    pub argument_template: Vec<String>,
    /// The real verification argv this kind runs, declared by the spec that
    /// owns it.
    ///
    /// `argument_template` bounds what a CALLER may request; it admits only
    /// the empty vector for every builtin. This field is the complementary
    /// half: the argv the admitted profile revision actually executes. It is
    /// declared here, on the one admitted-spec registry that both a local
    /// entrypoint and CI resolve, rather than in a second command list beside
    /// it, and it is bound into [`InstrumentSpec::digest`] like every other
    /// admitted field.
    pub verification_command: Vec<String>,
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

/// Owner-resolved fixed-literal invocation schema for one instrument spec.
///
/// The existing schema contract identity owns both the caller argument vector
/// and the exact argv template the instrument executes. This representation
/// intentionally has no substitution language: each vector is validated as
/// exact argv elements before launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedArgumentSchema {
    /// Existing schema authority declared by the instrument owner.
    pub schema_ref: ContractId,
    /// Exact caller invocation arguments admitted by this schema.
    pub caller_arguments: Vec<String>,
    /// Exact executable argv admitted by this schema.
    pub executed_argv: Vec<String>,
}

impl FixedArgumentSchema {
    /// Whether this schema admits the exact schema reference, invocation, and
    /// executable argv supplied by the caller.
    pub fn validates(
        &self,
        schema_ref: &ContractId,
        caller_arguments: &[String],
        executed_argv: &[String],
    ) -> bool {
        &self.schema_ref == schema_ref
            && self.caller_arguments.as_slice() == caller_arguments
            && self.executed_argv.as_slice() == executed_argv
    }
}

/// Canonical owner that produces a registered instrument's exact child
/// environment projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentPolicy {
    /// The exact owner-observed toolchain PATH stored in the original spec.
    ToolchainPath { permitted_path: String },
    /// The productive `TestD` projection derived from its retained envelope.
    TestdProductive,
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
    /// Typed invocation category bound to this admitted instrument kind.
    pub invocation_kind: InstrumentKind,
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
    /// Closed source policy for the exact child environment projection.
    pub environment_policy: EnvironmentPolicy,
    /// Invocation schema authority.
    pub schema: ContractId,
    /// Owner-resolved invocation schema; absent only in historical snapshots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_argument_schema: Option<FixedArgumentSchema>,
    /// Fixed command template; empty admits only the empty argument vector.
    pub argument_template: Vec<String>,
    /// The real verification argv this kind runs, declared by this spec.
    ///
    /// The admitted argv a launched stage runs, as opposed to
    /// [`Self::argument_template`], which is the fixed template a caller's
    /// own arguments must equal. An empty verification command is refused at
    /// construction rather than shipped: a kind that performs real package
    /// verification runs its tool with the arguments that ARE the
    /// verification, and a tool invoked with none is help/version output, not
    /// a compilation.
    pub verification_command: Vec<String>,
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
        validate_text(params.parser.as_str(), "parser")?;
        validate_text(params.schema.as_str(), "schema")?;
        validate_text(params.credential_policy.as_str(), "credential_policy")?;
        validate_text(params.network_policy.as_str(), "network_policy")?;
        if let Some(version) = params.executable_version.as_deref() {
            validate_text(version, "executable_version")?;
        }
        if let EnvironmentPolicy::ToolchainPath { permitted_path } = &params.environment_policy {
            validate_text(permitted_path, "permitted_toolchain_path")?;
        }
        for argument in &params.argument_template {
            validate_text(argument, "argument_template")?;
        }
        for argument in &params.verification_command {
            validate_text(argument, "verification_command")?;
        }
        if params.kind.version() == ContractVersion::new(0, 0, 0)
            || params.revision == ContractVersion::new(0, 0, 0)
            || params.parser_generation == 0
            || params.max_concurrency == 0
            || params.limits.timeout_ms == Some(0)
            || params.limits.max_output_bytes == Some(0)
        {
            return Err(ProfileError::Snapshot {
                detail:
                    "instrument spec carries a zero generation, revision, limit, or concurrency"
                        .to_owned(),
            });
        }
        if params.verification_command.is_empty() {
            return Err(ProfileError::InvalidText {
                field: "verification_command",
            });
        }
        Ok(Self {
            kind: params.kind,
            class: params.class,
            invocation_kind: params.invocation_kind,
            revision: params.revision,
            executable: params.executable,
            executable_version: params.executable_version,
            parser: params.parser,
            parser_generation: params.parser_generation,
            environment_profile: params.environment_profile,
            environment_policy: params.environment_policy,
            schema: params.schema.clone(),
            fixed_argument_schema: Some(FixedArgumentSchema {
                schema_ref: params.schema,
                caller_arguments: params.argument_template.clone(),
                executed_argv: params.verification_command.clone(),
            }),
            argument_template: params.argument_template,
            verification_command: params.verification_command,
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
        let mut material = format!(
            "{}\0{:?}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.kind.digest(),
            self.class,
            self.invocation_kind,
            self.revision,
            self.executable,
            self.executable_version.as_deref().unwrap_or(""),
            self.parser.as_str(),
            self.parser_generation,
            self.environment_profile,
            self.environment_policy,
            self.schema.as_str(),
            self.argument_template.join("\0"),
            self.verification_command.join("\0"),
            self.credential_policy.as_str(),
            self.network_policy.as_str(),
            self.limits.digest(),
            self.max_concurrency,
        );
        if let Some(schema) = &self.fixed_argument_schema {
            material.push('\0');
            material.push_str(schema.schema_ref.as_str());
            material.push('\0');
            material.push_str(&schema.caller_arguments.join("\0"));
            material.push('\0');
            material.push_str(&schema.executed_argv.join("\0"));
        }
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

    /// Consumes the DAG into declarations in deterministic key order.
    pub fn into_stages(self) -> Vec<StageDecl> {
        self.stages.into_values().collect()
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

/// Durable canonical registry snapshot shared by the Kernel and Runner.
/// The pure-transform payload is generic so Runner may retain its typed local
/// handler data while the Kernel validates only external stages from the same
/// wire snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistrySnapshot<P = Value> {
    /// Stable snapshot schema name.
    pub schema: String,
    /// Exact snapshot schema wire version.
    pub version: String,
    /// Registry generation the admission was validated against.
    pub generation: u64,
    /// Admitted specs in sorted kind-identity order.
    pub specs: Vec<InstrumentSpec>,
    /// Admitted deterministic in-process transforms.
    pub pure_transforms: Vec<P>,
    /// Admitted profiles in sorted name/revision order.
    pub profiles: Vec<InstrumentProfile>,
    /// Admitted executable supply-chain receipts.
    pub receipts: Vec<SupplyChainReceipt>,
}

/// The minimal immutable pins selecting one stage from an owner-read registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStagePin {
    /// Exact admitted profile.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Durable stage identity within the profile.
    pub stage_id: String,
    /// Registry generation returned by the canonical owner.
    pub registry_generation: u64,
}

/// Lossless neutral view of the environment fields that affect stage admission.
/// Callers translate the sealed `ProcessIntent` projection using its accessors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentProjectionBinding {
    /// Exact explicitly supplied non-secret values.
    pub non_secret: BTreeMap<String, String>,
    /// Exact opaque secret references; no secret values are representable.
    pub secret_refs: Vec<EnvironmentSecretReference>,
    /// Exact child environment inheritance mode.
    pub inheritance: EnvironmentInheritanceBinding,
}

/// Provider and key of one opaque environment secret reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSecretReference {
    /// Secret provider identifier.
    pub provider: String,
    /// Opaque provider key.
    pub key: String,
}

/// Child environment inheritance mode retained in an admission binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentInheritanceBinding {
    /// Only explicitly supplied values reach the child.
    None,
    /// The executor may merge its platform allowlist.
    Allowlisted,
}

/// Exact resolved WorkScope/layout/environment binding retained by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedExecutionBinding {
    /// Resolved source root, also the stage working directory.
    pub source_root: String,
    /// Resolved environment class.
    pub environment_class: String,
    /// Resolved environment projection digest.
    pub environment_digest: String,
    /// Exact projection produced by the admitted environment owner.
    pub environment_projection: EnvironmentProjectionBinding,
    /// Exact declared `WorkScope` string.
    pub declared_scope: String,
    /// Exact lineage-aware authority epoch.
    pub authority_epoch: EpochId,
    /// Exact resource generation bound by the `WorkScope` fence.
    pub resource_generation: u64,
}

/// Execution facts read directly from the exact sealed process request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionProjection {
    /// Working directory carried by `ProcessIntent`.
    pub working_directory: String,
    /// Digest of the actual `ProcessIntent` environment projection.
    pub environment_digest: String,
    /// Actual `ProcessIntent` projection, compared with the owner-produced one.
    pub environment_projection: EnvironmentProjectionBinding,
    /// Exact OS file object pinned by the sealed `ProcessIntent`.
    pub executable_file_identity: FileIdentity,
    /// Exact authority epoch carried by the authenticated dispatch fence.
    pub authority_epoch: EpochId,
    /// Resource generation carried by the authenticated dispatch fence.
    pub resource_generation: u64,
    /// Wall timeout carried by `ProcessIntent`.
    pub wall_timeout_ms: u64,
    /// Standard output ceiling carried by `ProcessIntent`.
    pub stdout_bytes: u64,
    /// Standard error ceiling carried by `ProcessIntent`.
    pub stderr_bytes: u64,
}

/// Machine-observed executable identity supplied by the owning execution plane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalExecutableObservation {
    /// Canonical file path observed by the owner.
    pub canonical_path: String,
    /// File name derived from that canonical path using the owner platform rules.
    pub executable_file_name: String,
    /// SHA-256 of the exact observed executable bytes.
    pub content_digest: String,
    /// OS file identity observed for these exact executable bytes.
    pub file_identity: FileIdentity,
    /// Observed tool version, if available.
    pub tool_version: Option<String>,
}

/// Typed failure from the shared external-stage admission checker.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryAdmissionError {
    /// The canonical registry generation does not match the owner pin.
    #[error("registry generation differs from the selected stage pin")]
    Generation,
    /// The profile or exact profile revision is absent.
    #[error("selected profile revision is absent from the canonical registry")]
    Profile,
    /// The durable stage identity is absent or duplicated.
    #[error("selected stage is absent or ambiguous in the canonical profile")]
    Stage,
    /// Stage, kind, or schema binding differs from the typed invocation.
    #[error("invocation differs from the canonical stage, kind, or schema binding")]
    Invocation,
    /// Request arguments or launched argv differ from the fixed schema/template.
    #[error("arguments or executable argv differ from the canonical fixed template")]
    Arguments,
    /// Actual `ProcessIntent` limits exceed an admitted spec ceiling.
    #[error("ProcessIntent resource limits exceed the canonical stage ceiling")]
    Limits,
    /// Executable identity is absent, malformed, or differs from its receipt.
    #[error("owner-observed executable differs from the current canonical receipt")]
    Executable,
    /// The snapshot is internally inconsistent or unsupported.
    #[error("canonical registry snapshot is inconsistent")]
    Snapshot,
    /// The owner did not retain a resolved profile/workscope/layout binding.
    #[error("external stage has no exact resolved profile binding")]
    Resolution,
}

#[allow(
    clippy::too_many_lines,
    reason = "one canonical snapshot check must preserve the complete original integrity sequence"
)]
fn validate_snapshot(
    snapshot: &InstrumentRegistrySnapshot<Value>,
) -> Result<(), RegistryAdmissionError> {
    let mut spec_ids = BTreeSet::new();
    for spec in &snapshot.specs {
        if !spec_ids.insert(spec.kind.as_str().to_owned()) {
            return Err(RegistryAdmissionError::Snapshot);
        }
        let kind = InstrumentKindId::new(
            ContractId::new(spec.kind.as_str().to_owned())
                .map_err(|_| RegistryAdmissionError::Snapshot)?,
            spec.kind.version(),
        )
        .map_err(|_| RegistryAdmissionError::Snapshot)?;
        if spec.fixed_argument_schema.as_ref().is_some_and(|schema| {
            !schema.validates(
                &spec.schema,
                &spec.argument_template,
                &spec.verification_command,
            )
        }) {
            return Err(RegistryAdmissionError::Snapshot);
        }
        let mut rebuilt = InstrumentSpec::new(InstrumentSpecParams {
            kind,
            class: spec.class,
            invocation_kind: spec.invocation_kind,
            revision: spec.revision,
            executable: spec.executable.clone(),
            executable_version: spec.executable_version.clone(),
            parser: spec.parser.clone(),
            parser_generation: spec.parser_generation,
            environment_profile: spec.environment_profile.clone(),
            environment_policy: spec.environment_policy.clone(),
            schema: spec.schema.clone(),
            argument_template: spec.argument_template.clone(),
            verification_command: spec.verification_command.clone(),
            credential_policy: spec.credential_policy.clone(),
            network_policy: spec.network_policy.clone(),
            limits: spec.limits,
            max_concurrency: spec.max_concurrency,
        })
        .map_err(|_| RegistryAdmissionError::Snapshot)?;
        // Rebuilding with the current constructor must not silently upgrade a
        // historical spec whose optional resolved schema was absent on disk.
        rebuilt
            .fixed_argument_schema
            .clone_from(&spec.fixed_argument_schema);
        if rebuilt.digest() != spec.digest() {
            return Err(RegistryAdmissionError::Snapshot);
        }
    }
    let mut profile_ids = BTreeSet::new();
    for profile in &snapshot.profiles {
        if !profile_ids.insert((profile.name.clone(), profile.revision)) {
            return Err(RegistryAdmissionError::Snapshot);
        }
        let mut declarations = Vec::new();
        for stage in &profile.dag {
            declarations.push(
                StageDecl::new(
                    stage.stage_id.clone(),
                    stage.spec.clone(),
                    stage.kind,
                    stage.depends_on.clone(),
                    stage.required,
                    stage.external,
                )
                .map_err(|_| RegistryAdmissionError::Snapshot)?,
            );
            if stage.external && !spec_ids.contains(stage.spec.as_str()) {
                return Err(RegistryAdmissionError::Snapshot);
            }
        }
        let dag = StageDag::build(&profile.name, declarations)
            .map_err(|_| RegistryAdmissionError::Snapshot)?;
        let classes = ProfileScopeClasses::new(
            profile.classes.target_layout.clone(),
            profile.classes.environment.clone(),
            profile.classes.workscope.clone(),
        )
        .map_err(|_| RegistryAdmissionError::Snapshot)?;
        let rebuilt = InstrumentProfile::new(
            profile.name.clone(),
            profile.revision,
            profile.spec_revision,
            profile.kinds.clone(),
            dag,
            classes,
        )
        .map_err(|_| RegistryAdmissionError::Snapshot)?;
        if rebuilt.digest() != profile.digest() {
            return Err(RegistryAdmissionError::Snapshot);
        }
    }
    let mut receipt_ids = BTreeSet::new();
    for receipt in &snapshot.receipts {
        if !receipt_ids.insert(receipt.instrument.as_str().to_owned()) {
            return Err(RegistryAdmissionError::Snapshot);
        }
        let rebuilt = SupplyChainReceipt::new(
            receipt.instrument.clone(),
            receipt.executable.clone(),
            receipt.content_digest.clone(),
            receipt.tool_version.clone(),
            receipt.spec_digest.clone(),
            receipt.generation,
        )
        .map_err(|_| RegistryAdmissionError::Snapshot)?;
        let Some(spec) = snapshot
            .specs
            .iter()
            .find(|spec| spec.kind.as_str() == receipt.instrument.as_str())
        else {
            return Err(RegistryAdmissionError::Snapshot);
        };
        if rebuilt.digest() != receipt.digest()
            || receipt.generation != snapshot.generation
            || receipt.spec_digest != spec.digest()
            || receipt.executable != spec.executable
        {
            return Err(RegistryAdmissionError::Snapshot);
        }
    }
    Ok(())
}

/// Validates one external invocation against one owner-read canonical snapshot.
///
/// All policy fields are derived from the looked-up profile, stage, spec, and
/// current supply receipt. Callers provide only selection pins and the
/// execution plane's actual executable observation and requested argv.
pub fn validate_external_stage(
    snapshot: &InstrumentRegistrySnapshot<Value>,
    pin: &ExternalStagePin,
    invocation: &InstrumentInvocation,
    observation: &ExternalExecutableObservation,
    requested_argv: &[String],
    resolution: &ResolvedExecutionBinding,
    process: &ProcessExecutionProjection,
) -> Result<InstrumentAdmissionGrant, RegistryAdmissionError> {
    validate_external_stage_inner(
        snapshot,
        pin,
        invocation,
        observation,
        requested_argv,
        resolution,
        process,
        None,
    )
}

/// Validates a `TestD` productive stage after the `TestD` owner has derived its
/// exact environment projection from the retained governed envelope and
/// `TestdProcessToolIntent::validate_for_roots`.
///
/// Generic profile dispatch must use [`validate_external_stage`], which
/// refuses this owner-specific policy. This entry only compares against the
/// projection supplied by the `TestD` owner; it does not repeat or approximate
/// that owner's environment rules.
#[allow(
    clippy::too_many_arguments,
    reason = "the shared gate must compare each of the eight original owner inputs explicitly"
)]
pub fn validate_testd_productive_stage(
    snapshot: &InstrumentRegistrySnapshot<Value>,
    pin: &ExternalStagePin,
    invocation: &InstrumentInvocation,
    observation: &ExternalExecutableObservation,
    requested_argv: &[String],
    resolution: &ResolvedExecutionBinding,
    process: &ProcessExecutionProjection,
    owner_projection: &EnvironmentProjectionBinding,
) -> Result<InstrumentAdmissionGrant, RegistryAdmissionError> {
    validate_external_stage_inner(
        snapshot,
        pin,
        invocation,
        observation,
        requested_argv,
        resolution,
        process,
        Some(owner_projection),
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one ordered admission gate compares all eight original owner inputs and preserves their refusal order"
)]
fn validate_external_stage_inner(
    snapshot: &InstrumentRegistrySnapshot<Value>,
    pin: &ExternalStagePin,
    invocation: &InstrumentInvocation,
    observation: &ExternalExecutableObservation,
    requested_argv: &[String],
    resolution: &ResolvedExecutionBinding,
    process: &ProcessExecutionProjection,
    testd_owner_projection: Option<&EnvironmentProjectionBinding>,
) -> Result<InstrumentAdmissionGrant, RegistryAdmissionError> {
    invocation
        .validate()
        .map_err(|_| RegistryAdmissionError::Invocation)?;
    if snapshot.generation == 0 || snapshot.generation != pin.registry_generation {
        return Err(RegistryAdmissionError::Generation);
    }
    if resolution.source_root.trim().is_empty()
        || resolution.declared_scope.trim().is_empty()
        || !is_sha256(&resolution.environment_digest)
        || process.working_directory != resolution.source_root
        || process.environment_digest != resolution.environment_digest
        || process.environment_projection != resolution.environment_projection
        || observation.file_identity != process.executable_file_identity
        || process.authority_epoch != resolution.authority_epoch
        || process.resource_generation != resolution.resource_generation
        || invocation.request.state_fence.authority_epoch != resolution.authority_epoch
        || invocation.request.state_fence.resource_generation.value()
            != resolution.resource_generation
        || invocation.request.state_fence.authority_epoch != process.authority_epoch
        || invocation.request.state_fence.resource_generation.value() != process.resource_generation
        || invocation.declared_scope != resolution.declared_scope
        || process.wall_timeout_ms == 0
        || process.stdout_bytes == 0
        || process.stderr_bytes == 0
    {
        return Err(RegistryAdmissionError::Resolution);
    }
    if snapshot.schema != REGISTRY_SNAPSHOT_SCHEMA
        || snapshot.version != REGISTRY_SNAPSHOT_SCHEMA_VERSION
        || pin.profile_revision == 0
    {
        return Err(RegistryAdmissionError::Snapshot);
    }
    validate_snapshot(snapshot)?;
    let mut profiles = snapshot
        .profiles
        .iter()
        .filter(|profile| profile.name == pin.profile && profile.revision == pin.profile_revision);
    let profile = profiles.next().ok_or(RegistryAdmissionError::Profile)?;
    if profiles.next().is_some() || invocation.profile != profile.name {
        return Err(RegistryAdmissionError::Profile);
    }
    let mut stages = profile
        .dag
        .iter()
        .filter(|stage| stage.stage_id == pin.stage_id);
    let stage = stages.next().ok_or(RegistryAdmissionError::Stage)?;
    if stages.next().is_some() || !stage.external {
        return Err(RegistryAdmissionError::Stage);
    }
    let spec = snapshot
        .specs
        .iter()
        .find(|spec| spec.kind.as_str() == stage.spec.as_str())
        .ok_or(RegistryAdmissionError::Snapshot)?;
    if snapshot
        .specs
        .iter()
        .filter(|candidate| candidate.kind.as_str() == stage.spec.as_str())
        .count()
        != 1
        || spec.kind.version() == ContractVersion::new(0, 0, 0)
        || profile.spec_revision != spec.revision
        || !profile.admits_kind(stage.kind)
        || stage.kind != spec.invocation_kind
        || invocation.instrument != stage.spec
        || invocation.kind != stage.kind
    {
        return Err(RegistryAdmissionError::Invocation);
    }
    if resolution.environment_class != spec.environment_profile
        || resolution.environment_class != profile.classes.environment
        || (testd_owner_projection.is_some()
            && !matches!(
                &spec.environment_policy,
                &EnvironmentPolicy::TestdProductive
            ))
    {
        return Err(RegistryAdmissionError::Resolution);
    }
    let environment = &resolution.environment_projection;
    if environment.inheritance != EnvironmentInheritanceBinding::None
        || !environment.secret_refs.is_empty()
    {
        return Err(RegistryAdmissionError::Resolution);
    }
    match &spec.environment_policy {
        EnvironmentPolicy::ToolchainPath { permitted_path } => {
            let variables = &environment.non_secret;
            if variables.len() != 1 || variables.get("PATH") != Some(permitted_path) {
                return Err(RegistryAdmissionError::Resolution);
            }
        }
        EnvironmentPolicy::TestdProductive => {
            if testd_owner_projection != Some(environment) {
                return Err(RegistryAdmissionError::Resolution);
            }
        }
    }
    if spec
        .limits
        .timeout_ms
        .is_some_and(|ceiling| process.wall_timeout_ms > ceiling)
        || spec
            .limits
            .max_output_bytes
            .is_some_and(|ceiling| process.stdout_bytes > ceiling || process.stderr_bytes > ceiling)
    {
        return Err(RegistryAdmissionError::Limits);
    }
    if spec
        .fixed_argument_schema
        .as_ref()
        .is_none_or(|schema| !schema.validates(&spec.schema, &invocation.arguments, requested_argv))
        || requested_argv.is_empty()
        || requested_argv
            .iter()
            .any(|argument| argument.trim().is_empty() || argument.chars().any(char::is_control))
    {
        return Err(RegistryAdmissionError::Arguments);
    }
    if observation.canonical_path.trim().is_empty()
        || observation.canonical_path.chars().any(char::is_control)
        || observation.executable_file_name.trim().is_empty()
        || observation
            .executable_file_name
            .chars()
            .any(char::is_control)
        || !is_sha256(&observation.content_digest)
        || observation.tool_version.as_ref().is_some_and(|version| {
            version.trim().is_empty() || version.chars().any(char::is_control)
        })
    {
        return Err(RegistryAdmissionError::Executable);
    }
    let mut receipts = snapshot
        .receipts
        .iter()
        .filter(|receipt| receipt.instrument == stage.spec);
    let receipt = receipts.next().ok_or(RegistryAdmissionError::Executable)?;
    if receipts.next().is_some()
        || receipt.generation != snapshot.generation
        || receipt.spec_digest != spec.digest()
        || receipt.executable != spec.executable
        || receipt.executable != observation.executable_file_name
        || receipt.content_digest != observation.content_digest
        || receipt
            .tool_version
            .as_deref()
            .is_some_and(|version| Some(version) != observation.tool_version.as_deref())
        || spec
            .executable_version
            .as_deref()
            .is_some_and(|version| Some(version) != observation.tool_version.as_deref())
    {
        return Err(RegistryAdmissionError::Executable);
    }
    let mut grant = InstrumentAdmissionGrant {
        kind_id: spec.kind.as_str().to_owned(),
        kind_version: spec.kind.version(),
        kind: stage.kind,
        profile: profile.name.clone(),
        profile_revision: profile.revision,
        spec_digest: spec.digest(),
        executable: spec.executable.clone(),
        executable_version: spec.executable_version.clone(),
        content_digest: observation.content_digest.clone(),
        executable_path: observation.canonical_path.clone(),
        executable_file_identity: Some(observation.file_identity),
        supply_digest: receipt.digest(),
        arguments: spec.verification_command.clone(),
        environment_class: spec.environment_profile.clone(),
        scope_class: profile.classes.workscope.clone(),
        source_root: Some(resolution.source_root.clone()),
        declared_scope: Some(resolution.declared_scope.clone()),
        environment_digest: Some(process.environment_digest.clone()),
        authority_epoch: Some(process.authority_epoch.clone()),
        resource_generation: Some(process.resource_generation),
        credential_policy: spec.credential_policy.clone(),
        network_policy: spec.network_policy.clone(),
        timeout_ms: spec.limits.timeout_ms,
        max_output_bytes: spec.limits.max_output_bytes,
        parser: spec.parser.clone(),
        parser_generation: spec.parser_generation,
        max_concurrency: spec.max_concurrency,
        grant_digest: String::new(),
    };
    grant.grant_digest = grant.digest();
    Ok(grant)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Failure while validating an executable supply receipt.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SupplyChainReceiptError {
    /// Executable identity is blank or contains control characters.
    #[error("invalid executable identity")]
    Executable,
    /// A digest is not lowercase SHA-256 hex.
    #[error("invalid SHA-256 digest")]
    Digest,
    /// Version text is blank or contains control characters.
    #[error("invalid tool version")]
    Version,
    /// Owner observation differs from this receipt.
    #[error("owner observation differs from the supply-chain receipt")]
    Mismatch,
}

/// Canonical executable file receipt bound to one spec and registry generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainReceipt {
    /// Instrument contract identity the receipt pins.
    pub instrument: ContractId,
    /// Exact admitted executable identity.
    pub executable: String,
    /// Lowercase SHA-256 over exact executable bytes.
    pub content_digest: String,
    /// Admitted tool version, when observed.
    pub tool_version: Option<String>,
    /// Digest of the admitted spec revision.
    pub spec_digest: String,
    /// Registry generation the verification was validated against.
    pub generation: u64,
}

impl SupplyChainReceipt {
    /// Validates and records one owner-observed executable receipt.
    pub fn new(
        instrument: ContractId,
        executable: String,
        content_digest: String,
        tool_version: Option<String>,
        spec_digest: String,
        generation: u64,
    ) -> Result<Self, SupplyChainReceiptError> {
        if executable.trim().is_empty() || executable.chars().any(char::is_control) {
            return Err(SupplyChainReceiptError::Executable);
        }
        if !is_sha256(&content_digest) || !is_sha256(&spec_digest) {
            return Err(SupplyChainReceiptError::Digest);
        }
        if tool_version.as_ref().is_some_and(|version| {
            version.trim().is_empty() || version.chars().any(char::is_control)
        }) {
            return Err(SupplyChainReceiptError::Version);
        }
        Ok(Self {
            instrument,
            executable,
            content_digest,
            tool_version,
            spec_digest,
            generation,
        })
    }

    /// Checks the owner's exact executable observation against this receipt.
    pub fn check_observation(
        &self,
        observation: &ExternalExecutableObservation,
    ) -> Result<(), SupplyChainReceiptError> {
        if self.executable != observation.executable_file_name
            || self.content_digest != observation.content_digest
            || self
                .tool_version
                .as_deref()
                .is_some_and(|version| Some(version) != observation.tool_version.as_deref())
        {
            return Err(SupplyChainReceiptError::Mismatch);
        }
        Ok(())
    }

    /// Registry key: the admitted instrument contract name.
    pub fn instrument_key(&self) -> &str {
        self.instrument.as_str()
    }

    /// Deterministic identity over every receipt field.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.instrument.as_str(),
            self.executable,
            self.content_digest,
            self.tool_version.as_deref().unwrap_or(""),
            self.spec_digest,
            self.generation
        );
        sha256_hex(material.as_bytes())
    }
}
