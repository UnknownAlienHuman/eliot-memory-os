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
use eliot_instrument_api::InstrumentKind;
use eliot_instrument_cargo::CONTRACT_NAME as CARGO_CONTRACT_NAME;
use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_instrument_rustc::{RUSTC_EXECUTABLE, RUSTC_INSTRUMENT};
use thiserror::Error;

/// Admitted `compiler` profile name (I10.8.7).
pub const COMPILER_PROFILE: &str = "compiler";
/// Admitted `test` profile name (I10.8.7).
pub const TEST_PROFILE: &str = "test";
/// Exact revision shipped for both builtin profiles.
pub const BUILTIN_PROFILE_REVISION: u64 = 1;
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

/// Versioned executable authority for one instrument kind (I10.8.3).
///
/// The spec names the exact executable, parser, and environment class an
/// admitted stage may use. It never carries command text: stages resolve to
/// typed invocations bound by the owning request port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentSpec {
    /// Opaque versioned kind identity.
    pub kind_id: ContractId,
    /// Semantic class of the instrument.
    pub class: InstrumentKind,
    /// Spec revision.
    pub revision: ContractVersion,
    /// Exact executable name bound by the registry.
    pub executable: String,
    /// Parser/normalizer authority for the instrument output.
    pub parser: ContractId,
    /// Admitted environment class.
    pub environment_profile: String,
}

impl InstrumentSpec {
    /// Records one instrument spec, validating every field.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the executable name or the
    /// environment class is blank or carries control characters.
    pub fn new(
        kind_id: ContractId,
        class: InstrumentKind,
        revision: ContractVersion,
        executable: String,
        parser: ContractId,
        environment_profile: String,
    ) -> Result<Self, ProfileError> {
        validate_text(&executable, "executable")?;
        validate_text(&environment_profile, "environment_profile")?;
        Ok(Self {
            kind_id,
            class,
            revision,
            executable,
            parser,
            environment_profile,
        })
    }

    /// Registry key: the admitted kind identity.
    pub fn kind_key(&self) -> &str {
        self.kind_id.as_str()
    }

    /// Deterministic identity over every spec field.
    pub fn digest(&self) -> String {
        let material = format!(
            "{}\0{:?}\0{}\0{}\0{}\0{}",
            self.kind_id.as_str(),
            self.class,
            self.revision,
            self.executable,
            self.parser.as_str(),
            self.environment_profile,
        );
        sha256_hex(material.as_bytes())
    }
}

/// One declared profile stage with durable identity and dependencies.
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Builds the builtin spec set backing the `compiler` and `test` profiles.
///
/// # Errors
///
/// Returns [`ProfileError::Contract`] when a contract literal fails
/// validation, or [`ProfileError::InvalidText`] on a malformed builtin field.
pub fn builtin_specs() -> Result<Vec<InstrumentSpec>, ProfileError> {
    Ok(vec![
        InstrumentSpec::new(
            ContractId::new(CARGO_CONTRACT_NAME)?,
            InstrumentKind::Build,
            BUILTIN_SPEC_VERSION,
            "cargo".to_owned(),
            ContractId::new(DIAGNOSTIC_PARSER_CONTRACT)?,
            ISOLATED_PROCESS_CLASS.to_owned(),
        )?,
        InstrumentSpec::new(
            ContractId::new(RUSTC_INSTRUMENT)?,
            InstrumentKind::Build,
            BUILTIN_SPEC_VERSION,
            RUSTC_EXECUTABLE.to_owned(),
            ContractId::new(RUSTC_INSTRUMENT)?,
            ISOLATED_PROCESS_CLASS.to_owned(),
        )?,
        InstrumentSpec::new(
            ContractId::new(NEXTEST_INSTRUMENT)?,
            InstrumentKind::Test,
            BUILTIN_SPEC_VERSION,
            "cargo".to_owned(),
            ContractId::new(NEXTEST_INSTRUMENT)?,
            ISOLATED_PROCESS_CLASS.to_owned(),
        )?,
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

/// Admission registry for versioned specs and profiles (I10.8.1).
///
/// The registry owns instrument definitions and profiles; it never spawns a
/// process, admits work to `testd`, schedules a task, writes canonical state,
/// or decides verification. Entries are keyed in [`BTreeMap`]s, so iteration
/// order is sorted and stable.
#[derive(Clone, Debug)]
pub struct InstrumentRegistry {
    specs: BTreeMap<String, InstrumentSpec>,
    profiles: BTreeMap<(String, u64), InstrumentProfile>,
    generation: u64,
}

impl InstrumentRegistry {
    /// Assembles a registry from caller-supplied definitions.
    ///
    /// Every profile stage must reference an admitted spec whose class equals
    /// the stage kind; dangling or mismatched references fail closed here,
    /// never at launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::DuplicateSpec`], [`ProfileError::DuplicateProfile`],
    /// [`ProfileError::UnknownSpec`], or [`ProfileError::SpecKindMismatch`].
    pub fn build(
        specs: Vec<InstrumentSpec>,
        profiles: Vec<InstrumentProfile>,
        generation: u64,
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
                if spec.class != stage.kind {
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
        Ok(Self {
            specs: spec_map,
            profiles: profile_map,
            generation,
        })
    }

    /// Assembles the registry with the builtin `compiler`/`test` profiles.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] when a builtin literal fails validation.
    pub fn with_builtin_profiles(generation: u64) -> Result<Self, ProfileError> {
        Self::build(
            builtin_specs()?,
            vec![compiler_profile()?, test_profile()?],
            generation,
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

    /// Deterministic identity over generation, specs, and profiles.
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
        sha256_hex(material.as_bytes())
    }
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
            if spec.class != stage.kind {
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
        Ok(AdmittedProfile {
            name: admitted.name.clone(),
            revision: admitted.revision,
            profile_digest: admitted.digest(),
            dag_digest: admitted.dag.digest(),
            kinds: admitted.kinds.clone(),
            stages: admitted
                .dag
                .topological_order()
                .into_iter()
                .map(|stage| AdmittedStage {
                    stage_id: stage.stage_id.clone(),
                    spec: stage.spec.clone(),
                    kind: stage.kind,
                    required: stage.required,
                    external: stage.external,
                    depends_on: stage.depends_on.clone(),
                })
                .collect(),
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
