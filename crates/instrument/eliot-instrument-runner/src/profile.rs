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

use eliot_contracts::{ContractId, ContractVersion, StateFence, sha256_hex};
pub use eliot_instrument_api::registry::{
    FixedArgumentSchema, InstrumentClass, InstrumentKindId, InstrumentProfile, InstrumentSpec,
    InstrumentSpecParams, ProfileError, ProfileScopeClasses, ResourceLimits, StageDag, StageDecl,
};
use eliot_instrument_api::{
    BuildClass, InstrumentAdmissionGrant, InstrumentAdmissionRequest, InstrumentKind,
};
use eliot_instrument_cargo::CONTRACT_NAME as CARGO_CONTRACT_NAME;
use eliot_instrument_nextest::{
    MAX_NEXTEST_OUTPUT_BYTES, NEXTEST_INSTRUMENT, NEXTEST_LIBTEST_JSON_FORMAT_VERSION,
    NextestCommand, NextestScope,
};
use eliot_instrument_rustc::{MAX_RUSTC_OUTPUT_BYTES, RUSTC_INSTRUMENT};
use eliot_instrument_rustfmt::{MAX_RUSTFMT_OUTPUT_BYTES, RUSTFMT_INSTRUMENT};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::registry::{
    ExecutableIdentity, RegistryEntry, ResolvedExecutableIdentity, SupplyChainReceipt,
    SupplyChainTable,
};
use eliot_instrument_scip::{MAX_SCIP_BYTES, SCIP_INSTRUMENT};

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
/// Environment variable naming the tool's executable search path.
///
/// A real verification command locates its own companion tools (the `rustc`
/// a `cargo` build drives, a build script's interpreter) through this value,
/// so it is declared explicitly on the projection rather than inherited from
/// the ambient process: I18.21:10 makes every environment difference an
/// explicit declared dependency instead of an invisible ambient fact, and
/// `EnvironmentInheritance::None` is kept so no other variable leaks in.
pub const TOOLCHAIN_PATH_ENV: &str = "PATH";

/// Stable schema name of the canonical registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA: &str = eliot_instrument_api::registry::REGISTRY_SNAPSHOT_SCHEMA;
/// Exact schema wire version of the canonical registry snapshot.
pub const REGISTRY_SNAPSHOT_SCHEMA_VERSION: &str =
    eliot_instrument_api::registry::REGISTRY_SNAPSHOT_SCHEMA_VERSION;

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

/// Closed in-process operation admitted by one pure-transform registry entry.
///
/// These handlers are compiled implementations, not registry-authored code or
/// executable names. Adding another handler requires a matching registered
/// transform contract and a typed dispatcher branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PureTransformHandler {
    /// Decode retained SCIP index bytes and project one typed graph query.
    ScipGraphQuery,
}

/// Admitted metadata for one bounded deterministic in-process transform.
///
/// Unlike [`InstrumentSpec`], this contract has no executable, argv, or
/// supply-chain receipt. Its metadata is copied only from the existing
/// decoder-only [`RegistryEntry`] and validated against that closed contract
/// when a snapshot is rebuilt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PureTransformSpec {
    /// Existing decoder/instrument contract identity.
    pub instrument: ContractId,
    /// Existing registered profile identity.
    pub profile: ContractId,
    /// Existing profile contract version.
    pub profile_version: ContractVersion,
    /// Exact profile revision selected by the current registry owner.
    pub profile_revision: u64,
    /// Existing adapter identity.
    pub adapter: String,
    /// Existing adapter contract version.
    pub adapter_version: ContractVersion,
    /// Existing parser contract identity.
    pub parser: ContractId,
    /// Existing normalizer contract identity.
    pub normalizer: ContractId,
    /// Existing evaluator contract identity.
    pub evaluator: ContractId,
    /// Parser/provider generation captured by the owning registry.
    pub parser_generation: u64,
    /// Admitted offline decoder environment.
    pub environment_profile: String,
    /// Maximum retained input byte length.
    pub max_input_bytes: usize,
    /// Closed code handler selected by the admitted contract.
    pub handler: PureTransformHandler,
}

impl PureTransformSpec {
    /// Copies the existing SCIP decoder registration into the profile
    /// admission snapshot after checking every identity-bearing field.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Snapshot`] when the entry is not the current
    /// decoder-only SCIP registration.
    pub fn from_registry_entry(entry: &RegistryEntry) -> Result<Self, ProfileError> {
        let expected_resource =
            format!("SCIP decode bounded at {MAX_SCIP_BYTES} bytes (MAX_SCIP_BYTES)");
        if entry.profile.as_str() != SCIP_INSTRUMENT
            || entry.profile_version != ContractVersion::new(1, 0, 0)
            || entry.instrument.as_str() != SCIP_INSTRUMENT
            || entry.kinds.as_slice() != [InstrumentKind::Inspect]
            || entry.adapter != SCIP_INSTRUMENT
            || entry.adapter_version != ContractVersion::new(1, 0, 0)
            || !entry.executable.is_decoder_only()
            || entry.toolchain != "scip-indexer"
            || entry.environment_class != crate::registry::OFFLINE_DECODE
            || entry.resource_contract != expected_resource
            || entry.parser.as_str() != SCIP_INSTRUMENT
            || entry.normalizer.as_str() != SCIP_INSTRUMENT
            || entry.evaluator.as_str() != SCIP_INSTRUMENT
            || entry.generation == 0
        {
            return Err(ProfileError::Snapshot {
                detail: "pure transform metadata differs from the registered SCIP decoder"
                    .to_owned(),
            });
        }
        Ok(Self {
            instrument: entry.instrument.clone(),
            profile: entry.profile.clone(),
            profile_version: entry.profile_version,
            // The profile contract revision and its parser/provider
            // generation cut over independently. The SCIP profile shipped
            // here is the builtin profile revision; the parser generation
            // below comes from the registered decoder entry.
            profile_revision: BUILTIN_PROFILE_REVISION,
            adapter: entry.adapter.clone(),
            adapter_version: entry.adapter_version,
            parser: entry.parser.clone(),
            normalizer: entry.normalizer.clone(),
            evaluator: entry.evaluator.clone(),
            parser_generation: entry.generation,
            environment_profile: entry.environment_class.clone(),
            max_input_bytes: MAX_SCIP_BYTES,
            handler: PureTransformHandler::ScipGraphQuery,
        })
    }

    /// Validates recovered metadata against the one compiled SCIP decoder.
    fn validate(&self) -> Result<(), ProfileError> {
        let expected = Self {
            instrument: ContractId::new(SCIP_INSTRUMENT.to_owned())?,
            profile: ContractId::new(SCIP_INSTRUMENT.to_owned())?,
            profile_version: ContractVersion::new(1, 0, 0),
            profile_revision: self.profile_revision,
            adapter: SCIP_INSTRUMENT.to_owned(),
            adapter_version: ContractVersion::new(1, 0, 0),
            parser: ContractId::new(SCIP_INSTRUMENT.to_owned())?,
            normalizer: ContractId::new(SCIP_INSTRUMENT.to_owned())?,
            evaluator: ContractId::new(SCIP_INSTRUMENT.to_owned())?,
            parser_generation: self.parser_generation,
            environment_profile: crate::registry::OFFLINE_DECODE.to_owned(),
            max_input_bytes: MAX_SCIP_BYTES,
            handler: PureTransformHandler::ScipGraphQuery,
        };
        if self.parser_generation == 0
            || self.profile_revision == 0
            || self.instrument != expected.instrument
            || self.profile != expected.profile
            || self.profile_version != expected.profile_version
            || self.adapter != expected.adapter
            || self.adapter_version != expected.adapter_version
            || self.parser != expected.parser
            || self.normalizer != expected.normalizer
            || self.evaluator != expected.evaluator
            || self.environment_profile != expected.environment_profile
            || self.max_input_bytes != expected.max_input_bytes
            || self.handler != expected.handler
        {
            return Err(ProfileError::Snapshot {
                detail: "recovered pure transform metadata is stale or unsupported".to_owned(),
            });
        }
        Ok(())
    }

    /// Digest of the exact admitted decoder contract and parser generation.
    pub fn spec_digest(&self) -> String {
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            self.instrument.as_str(),
            self.profile.as_str(),
            self.profile_version,
            self.profile_revision,
            self.adapter,
            self.adapter_version,
            self.parser.as_str(),
            self.normalizer.as_str(),
            self.evaluator.as_str(),
            self.parser_generation,
            self.environment_profile,
            self.max_input_bytes,
            match self.handler {
                PureTransformHandler::ScipGraphQuery => "scip-graph-query",
            },
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
/// composition-root port). Each spec ALSO declares its
/// [`InstrumentSpec::verification_command`]: the real verification argv the
/// profile revision executes. That declaration is what an empty
/// `argument_template` no longer costs a stage. `argument_template` stays
/// empty for every builtin, so a CALLER still can contribute only the empty
/// argument vector; what changed is that the registry itself now names the
/// command, on the same admitted spec both a local entrypoint and CI resolve
/// (I18.21:11), instead of the execution path inventing one beside the
/// registry.
///
/// The declared commands are each admitted kind's real verification
/// projection, taken from the crate that owns that instrument rather than
/// restated here, and each is an argument vector FOR the executable the same
/// spec admits, so a sealed request is always `<declared executable> +
/// <declared command>`:
///
/// - cargo: `cargo build --message-format=json ...`, the Cargo
///   `--message-format=json` stream the admitted parser projects;
/// - rustc: `cargo clippy --message-format=json ...`, the Clippy stream
///   [`eliot_instrument_rustc::parse_clippy_jsonl`] is the admitted parser
///   for, matching the Clippy-performs-the-compilation rule `dev-fast` states;
/// - nextest: `cargo nextest run --message-format libtest-json-plus ...`,
///   the exact argument spine [`eliot_instrument_nextest::NextestCommand`]
///   renders;
/// - rustfmt: `cargo fmt --all -- --check`, the exact command
///   [`eliot_instrument_rustfmt::RustfmtCommand::check`] renders.
///
/// `--locked` is on every Cargo invocation because I18.21 and I2.22 make a
/// locked resolution the precondition for a verification result, and
/// `--all-targets` is on the two builds and the test run because the
/// `MergeCompile` ceiling compiles every target. Registry construction records
/// the exact owner-observed toolchain PATH in the admitted environment policy;
/// it has no executable observation, so builtins ship no supply-chain receipt
/// and pin no tool version.
pub fn builtin_specs() -> Result<Vec<InstrumentSpec>, ProfileError> {
    let credential = ContractId::new(ISOLATED_CREDENTIAL_POLICY)?;
    let network = ContractId::new(ISOLATED_NETWORK_POLICY)?;
    let permitted_path = std::env::var(TOOLCHAIN_PATH_ENV).map_err(|_| ProfileError::Snapshot {
        detail: format!(
            "owner-observed {TOOLCHAIN_PATH_ENV} is required for admitted toolchain policy"
        ),
    })?;
    validate_text(&permitted_path, "permitted_toolchain_path")?;
    let toolchain_environment_policy = EnvironmentPolicy::ToolchainPath { permitted_path };
    // The two compilation projections share one locked all-target build spine;
    // only the JSON message format and the subcommand differ, because those
    // are what select the admitted parser.
    let build_spine = |subcommand: &str| {
        vec![
            subcommand.to_owned(),
            "--message-format=json".to_owned(),
            "--locked".to_owned(),
            "--all-targets".to_owned(),
        ]
    };
    Ok(vec![
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(
                ContractId::new(CARGO_CONTRACT_NAME)?,
                BUILTIN_KIND_VERSION,
            )?,
            class: InstrumentClass::Compiler,
            invocation_kind: InstrumentKind::Build,
            revision: BUILTIN_SPEC_VERSION,
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(DIAGNOSTIC_PARSER_CONTRACT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            environment_policy: toolchain_environment_policy.clone(),
            schema: ContractId::new(CARGO_CONTRACT_NAME)?,
            argument_template: Vec::new(),
            verification_command: build_spine("build"),
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, None),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
        InstrumentSpec::new(InstrumentSpecParams {
            kind: InstrumentKindId::new(ContractId::new(RUSTC_INSTRUMENT)?, BUILTIN_KIND_VERSION)?,
            class: InstrumentClass::Compiler,
            invocation_kind: InstrumentKind::Build,
            revision: BUILTIN_SPEC_VERSION,
            // The compilation runs through the cargo subcommand surface of the
            // same toolchain whose `rustc` is the semantic subject: I18.6 says
            // "Clippy performs the same compilation" and I18.33 names
            // "exact-package Cargo check or Clippy". Naming `rustc` here while
            // declaring a cargo subcommand would seal `rustc clippy ...`, which
            // is not a compilation, so the admitted executable is the one the
            // declared command is an argument vector for.
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(RUSTC_INSTRUMENT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            environment_policy: toolchain_environment_policy.clone(),
            schema: ContractId::new(RUSTC_INSTRUMENT)?,
            argument_template: Vec::new(),
            // The admitted parser is the Clippy JSON stream, and this is the
            // one command that produces it.
            verification_command: build_spine("clippy"),
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
            invocation_kind: InstrumentKind::Test,
            revision: BUILTIN_SPEC_VERSION,
            executable: "cargo".to_owned(),
            executable_version: None,
            parser: ContractId::new(NEXTEST_INSTRUMENT)?,
            parser_generation: BUILTIN_PARSER_GENERATION,
            environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
            environment_policy: toolchain_environment_policy.clone(),
            schema: ContractId::new(NEXTEST_INSTRUMENT)?,
            argument_template: Vec::new(),
            // `cargo nextest` is the admitted executable's subcommand surface,
            // and the argument spine is the one
            // `eliot_instrument_nextest::NextestCommand` renders, so the
            // libtest-json-plus stream the admitted nextest parser reads is
            // the one this command produces.
            verification_command: vec![
                "nextest".to_owned(),
                "run".to_owned(),
                "--message-format".to_owned(),
                "libtest-json-plus".to_owned(),
                // The admitted parser reads exactly this message-format version.
                "--message-format-version".to_owned(),
                NEXTEST_LIBTEST_JSON_FORMAT_VERSION.to_owned(),
                "--locked".to_owned(),
                "--all-targets".to_owned(),
            ],
            credential_policy: credential.clone(),
            network_policy: network.clone(),
            limits: ResourceLimits::new(None, Some(MAX_NEXTEST_OUTPUT_BYTES as u64)),
            max_concurrency: BUILTIN_MAX_CONCURRENCY,
        })?,
        builtin_rustfmt_spec(&credential, &network, toolchain_environment_policy)?,
    ])
}

/// The builtin `formatter` profile: metadata plus exactly the command
/// [`eliot_instrument_rustfmt::RustfmtCommand::check`] renders.
///
/// Kept beside the registry rather than inline in it so the declared argv and
/// the ceiling that bounds its output are read together.
///
/// # Errors
///
/// Returns the profile error when a contract id or resource limit is invalid.
fn builtin_rustfmt_spec(
    credential: &ContractId,
    network: &ContractId,
    environment_policy: EnvironmentPolicy,
) -> Result<InstrumentSpec, ProfileError> {
    InstrumentSpec::new(InstrumentSpecParams {
        kind: InstrumentKindId::new(ContractId::new(RUSTFMT_INSTRUMENT)?, BUILTIN_KIND_VERSION)?,
        // Assumption for this mapping: formatting is a deterministic static
        // source check under the documented semantic class; Format remains
        // its typed invocation category.
        class: InstrumentClass::HeuristicAnalysis,
        invocation_kind: InstrumentKind::Format,
        revision: BUILTIN_SPEC_VERSION,
        executable: "cargo".to_owned(),
        executable_version: None,
        parser: ContractId::new(RUSTFMT_INSTRUMENT)?,
        parser_generation: BUILTIN_PARSER_GENERATION,
        environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
        environment_policy,
        schema: ContractId::new(RUSTFMT_INSTRUMENT)?,
        argument_template: Vec::new(),
        verification_command: vec![
            "fmt".to_owned(),
            "--all".to_owned(),
            "--".to_owned(),
            "--check".to_owned(),
        ],
        credential_policy: credential.clone(),
        network_policy: network.clone(),
        limits: ResourceLimits::new(None, Some(MAX_RUSTFMT_OUTPUT_BYTES as u64)),
        max_concurrency: BUILTIN_MAX_CONCURRENCY,
    })
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

fn testd_productive_binding_and_command(
    nextest_sha256: &str,
    target: &str,
) -> Result<(eliot_testd_core::TestdExecutableBinding, NextestCommand), ProfileError> {
    let binding = eliot_testd_core::testd_profile_binding_with_slots(
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        nextest_sha256,
        &[],
    )
    .map_err(|_| ProfileError::TestdProductiveBindingMismatch)?;
    let command = NextestCommand::run_scoped(
        target.to_owned(),
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &NextestScope::default(),
    )
    .map_err(|_| ProfileError::TestdProductiveBindingMismatch)?;
    Ok((binding, command))
}

fn testd_productive_nextest_spec(
    binding: &eliot_testd_core::TestdExecutableBinding,
    command: &NextestCommand,
) -> Result<InstrumentSpec, ProfileError> {
    InstrumentSpec::new(InstrumentSpecParams {
        kind: InstrumentKindId::new(ContractId::new(NEXTEST_INSTRUMENT)?, BUILTIN_KIND_VERSION)?,
        class: InstrumentClass::Test,
        invocation_kind: InstrumentKind::Test,
        revision: BUILTIN_SPEC_VERSION,
        executable: binding.program_path.clone(),
        executable_version: None,
        parser: ContractId::new(NEXTEST_INSTRUMENT)?,
        parser_generation: BUILTIN_PARSER_GENERATION,
        environment_profile: ISOLATED_PROCESS_CLASS.to_owned(),
        environment_policy: EnvironmentPolicy::TestdProductive,
        schema: ContractId::new(NEXTEST_INSTRUMENT)?,
        argument_template: Vec::new(),
        verification_command: command.arguments.clone(),
        credential_policy: ContractId::new(ISOLATED_CREDENTIAL_POLICY)?,
        network_policy: ContractId::new(ISOLATED_NETWORK_POLICY)?,
        limits: ResourceLimits::new(Some(binding.wall_timeout_ms), Some(binding.stdout_bytes)),
        max_concurrency: BUILTIN_MAX_CONCURRENCY,
    })
}

fn testd_productive_profile() -> Result<InstrumentProfile, ProfileError> {
    let profile_name = eliot_testd_core::TESTD_PRODUCTIVE_PROFILE;
    let dag = StageDag::build(
        profile_name,
        vec![StageDecl::new(
            profile_name.to_owned(),
            ContractId::new(NEXTEST_INSTRUMENT)?,
            InstrumentKind::Test,
            Vec::new(),
            true,
            true,
        )?],
    )?;
    InstrumentProfile::new(
        profile_name.to_owned(),
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
/// declares only what the governing documents already fix â€” the compilation
/// class, the test class, and the format class â€” over the same builtin specs
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
/// The bundle identity itself â€” the published artifact set, its digests, and
/// its provenance â€” is not profile text. It is caller-attested and compared,
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

/// Builds the registered SCIP profile as one pure inspection stage.
///
/// The profile and stage use the exact existing SCIP contract identity and
/// owner revision; the stage does not bind an executable or process policy.
pub fn scip_profile(spec: &PureTransformSpec) -> Result<InstrumentProfile, ProfileError> {
    spec.validate()?;
    let dag = StageDag::build(
        spec.profile.as_str(),
        vec![StageDecl::new(
            spec.instrument.as_str().to_owned(),
            spec.instrument.clone(),
            InstrumentKind::Inspect,
            Vec::new(),
            true,
            false,
        )?],
    )?;
    InstrumentProfile::new(
        spec.profile.as_str().to_owned(),
        spec.profile_revision,
        spec.profile_version,
        vec![InstrumentKind::Inspect],
        dag,
        ProfileScopeClasses::new(
            ADMITTED_WORKTREE_CLASS.to_owned(),
            spec.environment_profile.clone(),
            ADMITTED_SCOPE_CLASS.to_owned(),
        )?,
    )
}

/// Alias naming the package-verification route at its shipped revision.
///
/// An alias is a stable, closed name a thin invoker (a workflow, a wrapper
/// script, a Justfile recipe) passes instead of restating a command list. It
/// carries no command, no shell string, no executable path, and no environment
/// selection: it names exactly one admitted profile revision and nothing else.
pub const PACKAGE_VERIFICATION_ALIAS: &str = "package-verification";
/// Alias naming the bundle-verification route at its shipped revision.
pub const BUNDLE_VERIFICATION_ALIAS: &str = "bundle-verification";

/// One entry of the closed [`PROFILE_ALIASES`] table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileAlias {
    /// Stable alias name an invoker passes.
    pub alias: &'static str,
    /// Admitted profile the alias resolves to.
    pub profile: &'static str,
    /// Exact admitted revision the alias pins.
    pub revision: u64,
}

/// The closed alias table: the only way a caller names a verification route
/// (issue #1914 W4).
///
/// I18.21 requires "there is no hidden CI-only verifier command list". A
/// command list is unverifiable precisely because it is a second copy of an
/// order the shared owner already defines: it drifts without failing anything.
/// An alias is the opposite of a command list â€” it is a name, resolved through
/// the same registry both a local entrypoint and CI admit, so a run cannot
/// execute a stage the registry never admitted.
///
/// The table is a `const` slice of a fixed element type, so it cannot grow at
/// runtime, take caller data, or be extended by a stringly-typed lookup. It
/// admits exactly the two versioned verification routes and nothing else: an
/// alias outside this slice is refused with
/// [`ProfileError::UnknownAlias`], never normalized, trimmed, case-folded, or
/// mapped to a neighbouring route. There is no default alias and no
/// head-revision resolution â€” each entry pins one exact revision, so an alias
/// that a registry does not admit at that revision fails closed rather than
/// resolving to whatever revision happens to be the highest.
pub const PROFILE_ALIASES: &[ProfileAlias] = &[
    ProfileAlias {
        alias: PACKAGE_VERIFICATION_ALIAS,
        profile: PACKAGE_VERIFICATION_ROUTE,
        revision: BUILTIN_PROFILE_REVISION,
    },
    ProfileAlias {
        alias: BUNDLE_VERIFICATION_ALIAS,
        profile: BUNDLE_VERIFICATION_ROUTE,
        revision: BUILTIN_PROFILE_REVISION,
    },
];

/// Resolves one closed alias name to its admitted profile at its pinned
/// revision (issue #1914 W4).
///
/// This is the one entry a thin invoker uses to name a verification route. The
/// name is matched exactly against [`PROFILE_ALIASES`] â€” no trimming, case
/// folding, prefix match, or alias-of-alias â€” and the pinned revision is then
/// resolved through the registry at that exact revision, so a registry that
/// does not admit it fails closed with [`ProfileError::UnknownRevision`]
/// instead of falling back to the route's head revision or to another route.
///
/// # Errors
///
/// Returns [`ProfileError::UnknownAlias`] when the name is outside the closed
/// table, and [`ProfileError::UnknownProfile`] or
/// [`ProfileError::UnknownRevision`] when the table's pinned revision is not
/// admitted by this registry.
pub fn admitted_profile_for_alias<'a>(
    alias: &str,
    registry: &'a InstrumentRegistry,
) -> Result<&'a InstrumentProfile, ProfileError> {
    let entry = PROFILE_ALIASES
        .iter()
        .find(|entry| entry.alias == alias)
        .ok_or_else(|| ProfileError::UnknownAlias {
            alias: alias.to_owned(),
        })?;
    registry.admitted(entry.profile, entry.revision)
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
    pure_transforms: BTreeMap<String, PureTransformSpec>,
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
        Self::build_with_pure_transforms(specs, profiles, generation, receipts, Vec::new())
    }

    /// Assembles external specs and explicitly registered pure transforms in
    /// one profile registry generation.
    pub fn build_with_pure_transforms(
        specs: Vec<InstrumentSpec>,
        profiles: Vec<InstrumentProfile>,
        generation: u64,
        receipts: Vec<SupplyChainReceipt>,
        pure_transforms: Vec<PureTransformSpec>,
    ) -> Result<Self, ProfileError> {
        let mut spec_map = BTreeMap::new();
        for spec in specs {
            let key = spec.kind_key().to_owned();
            if spec_map.insert(key.clone(), spec).is_some() {
                return Err(ProfileError::DuplicateSpec { spec: key });
            }
        }
        let mut pure_map = BTreeMap::new();
        for pure in pure_transforms {
            pure.validate()?;
            // These dimensions have distinct owners. Registry generation
            // versions the complete snapshot; profile revision and parser
            // generation are validated against the profile stage below and
            // must remain independently replaceable.
            let key = pure.instrument.as_str().to_owned();
            if spec_map.contains_key(&key) || pure_map.insert(key.clone(), pure).is_some() {
                return Err(ProfileError::DuplicateSpec { spec: key });
            }
        }
        let mut profile_map = BTreeMap::new();
        for profile in profiles {
            for stage in &profile.dag {
                if stage.external {
                    let Some(spec) = spec_map.get(stage.spec.as_str()) else {
                        return Err(ProfileError::UnknownSpec {
                            profile: profile.name.clone(),
                            stage: stage.stage_id.clone(),
                            spec: stage.spec.as_str().to_owned(),
                        });
                    };
                    if spec.invocation_kind != stage.kind {
                        return Err(ProfileError::SpecKindMismatch {
                            stage: stage.stage_id.clone(),
                            spec: stage.spec.as_str().to_owned(),
                            kind: stage.kind,
                        });
                    }
                } else {
                    let Some(pure) = pure_map.get(stage.spec.as_str()) else {
                        return Err(ProfileError::UnknownSpec {
                            profile: profile.name.clone(),
                            stage: stage.stage_id.clone(),
                            spec: stage.spec.as_str().to_owned(),
                        });
                    };
                    if stage.kind != InstrumentKind::Inspect
                        || pure.profile.as_str() != profile.name
                        || pure.profile_revision != profile.revision
                        || pure.profile_version != profile.spec_revision
                    {
                        return Err(ProfileError::Snapshot {
                            detail: format!(
                                "pure stage '{}' differs from its registered transform profile/version",
                                stage.stage_id
                            ),
                        });
                    }
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
                    kind: spec.invocation_kind,
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
            pure_transforms: pure_map,
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
    /// `receipts` are the caller-attested executable supply-chain receipts.
    /// A receipt is validated against the admitted spec digest at exactly this
    /// generation, so a drifted or orphan receipt fails closed here and the
    /// routes refuse to resolve at all. Passing no receipt is admitted as an
    /// explicit absence â€” the pre-launch gate then binds the admitted
    /// executable file and schema without a pinned digest â€” and
    /// `require_provenance` is what later refuses a receipted route whose
    /// stages carry no recorded identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError`] when a builtin literal fails validation, or
    /// the admission error when a receipt is orphan, drifted, or of a
    /// mismatched generation.
    pub fn with_verification_route_profiles(
        generation: u64,
        receipts: Vec<SupplyChainReceipt>,
    ) -> Result<Self, ProfileError> {
        Self::build(
            builtin_specs()?,
            vec![
                compiler_profile()?,
                test_profile()?,
                package_verification_profile()?,
                bundle_verification_profile()?,
            ],
            generation,
            receipts,
        )
    }

    /// Builds the builtin registry with TestD's owner-observed productive
    /// `cargo-nextest` definition and exact profile. The command and TestD
    /// binding must come from the same current owner composition; the supplied
    /// tool observation is the only source for the supply-chain digest.
    pub fn with_testd_productive_profile(
        generation: u64,
        observation: &eliot_testd_core::TestdToolObservation,
        binding: &eliot_testd_core::TestdExecutableBinding,
        command: &NextestCommand,
    ) -> Result<Self, ProfileError> {
        observation
            .validate()
            .map_err(|_| ProfileError::TestdProductiveBindingMismatch)?;
        binding
            .validate()
            .map_err(|_| ProfileError::TestdProductiveBindingMismatch)?;
        if binding.profile != eliot_testd_core::TESTD_PRODUCTIVE_PROFILE
            || binding.program_path != eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_PROGRAM
            || binding.package_artifact_digest != observation.nextest_sha256
            || command.executable != binding.program_path
            || command.arguments != binding.fixed_argv
            || std::path::Path::new(&observation.nextest_path)
                .file_stem()
                .and_then(|name| name.to_str())
                .is_none_or(|name| {
                    !name.eq_ignore_ascii_case(eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_PROGRAM)
                })
        {
            return Err(ProfileError::TestdProductiveBindingMismatch);
        }
        let (expected_binding, expected_command) = testd_productive_binding_and_command(
            observation.nextest_sha256.as_str(),
            command.target.as_str(),
        )?;
        if &expected_binding != binding || &expected_command != command {
            return Err(ProfileError::TestdProductiveBindingMismatch);
        }

        let spec = testd_productive_nextest_spec(binding, command)?;
        let receipt = SupplyChainReceipt::new(
            ContractId::new(NEXTEST_INSTRUMENT)?,
            binding.program_path.clone(),
            observation.nextest_sha256.clone(),
            None,
            spec.digest(),
            generation,
        )
        .map_err(|_| ProfileError::TestdProductiveBindingMismatch)?;
        let mut specs = builtin_specs()?;
        specs.retain(|registered| registered.kind_key() != NEXTEST_INSTRUMENT);
        specs.push(spec);

        Self::build(
            specs,
            vec![
                compiler_profile()?,
                test_profile()?,
                package_verification_profile()?,
                bundle_verification_profile()?,
                testd_productive_profile()?,
            ],
            generation,
            vec![receipt],
        )
    }

    /// Builds the ordinary builtin profile set plus the current registered
    /// decoder-only SCIP inspection profile.
    pub fn with_registered_scip_profile(
        generation: u64,
        receipts: Vec<SupplyChainReceipt>,
        scip_entry: &RegistryEntry,
    ) -> Result<Self, ProfileError> {
        let pure = PureTransformSpec::from_registry_entry(scip_entry)?;
        let scip = scip_profile(&pure)?;
        Self::build_with_pure_transforms(
            builtin_specs()?,
            vec![
                compiler_profile()?,
                test_profile()?,
                package_verification_profile()?,
                bundle_verification_profile()?,
                scip,
            ],
            generation,
            receipts,
            vec![pure],
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

    /// Returns the exact admitted in-process transform under its registered
    /// decoder identity.
    pub fn pure_transform(&self, spec_id: &str) -> Option<&PureTransformSpec> {
        self.pure_transforms.get(spec_id)
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
        for pure in self.pure_transforms.values() {
            material.push_str(&pure.spec_digest());
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
            pure_transforms: self.pure_transforms.values().cloned().collect(),
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
        let mut pure_transforms = Vec::with_capacity(snapshot.pure_transforms.len());
        for pure in snapshot.pure_transforms {
            pure.validate()?;
            pure_transforms.push(pure);
        }
        Self::build_with_pure_transforms(
            specs,
            profiles,
            snapshot.generation,
            receipts,
            pure_transforms,
        )
    }
}

/// Runner-typed view of the neutral canonical registry snapshot.
pub type InstrumentRegistrySnapshot =
    eliot_instrument_api::registry::InstrumentRegistrySnapshot<PureTransformSpec>;

/// Rebuilds one deserialized spec through its validated constructor.
fn rebuild_spec(spec: InstrumentSpec) -> Result<InstrumentSpec, ProfileError> {
    let fixed_argument_schema = spec.fixed_argument_schema.clone();
    let kind = InstrumentKindId::new(
        ContractId::new(spec.kind.as_str().to_owned())?,
        spec.kind.version(),
    )?;
    let mut rebuilt = InstrumentSpec::new(InstrumentSpecParams {
        kind,
        class: spec.class,
        invocation_kind: spec.invocation_kind,
        revision: spec.revision,
        executable: spec.executable,
        executable_version: spec.executable_version,
        parser: spec.parser,
        parser_generation: spec.parser_generation,
        environment_profile: spec.environment_profile,
        environment_policy: spec.environment_policy,
        schema: spec.schema,
        argument_template: spec.argument_template,
        verification_command: spec.verification_command,
        credential_policy: spec.credential_policy,
        network_policy: spec.network_policy,
        limits: spec.limits,
        max_concurrency: spec.max_concurrency,
    })?;
    if fixed_argument_schema.as_ref().is_some_and(|schema| {
        !schema.validates(
            &rebuilt.schema,
            &rebuilt.argument_template,
            &rebuilt.verification_command,
        )
    }) {
        return Err(ProfileError::Snapshot {
            detail: "instrument fixed argument schema differs from its declared templates"
                .to_owned(),
        });
    }
    // Historical snapshots intentionally keep the absent field and digest;
    // external admission checks require a current owner-resolved schema.
    rebuilt.fixed_argument_schema = fixed_argument_schema;
    Ok(rebuilt)
}

/// Rebuilds one deserialized profile through its validated constructors.
fn rebuild_profile(profile: InstrumentProfile) -> Result<InstrumentProfile, ProfileError> {
    let stages: Vec<StageDecl> = profile.dag.into_stages();
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
    /// Exact owner-produced projection retained for external-stage policy checks.
    /// Legacy digest-only callers retain no projection and cannot launch an
    /// externally admitted stage.
    pub projection: Option<eliot_process::EnvironmentProjection>,
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
            projection: None,
        })
    }

    /// Retains an already-computed owner digest for the exact declared process
    /// environment projection. The digest is not hashed a second time.
    pub fn attest_digest(class: String, digest: String) -> Result<Self, ProfileError> {
        validate_text(&class, "environment_class")?;
        if digest.len() != 64
            || digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(ProfileError::Snapshot {
                detail: "environment projection digest is not lowercase SHA-256".to_owned(),
            });
        }
        Ok(Self {
            class,
            digest,
            projection: None,
        })
    }

    /// Retains the exact process environment projection produced by the
    /// environment owner and hashes it with the executor's canonical digest.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidText`] when the class is blank or
    /// carries control characters.
    pub fn attest_projection(
        class: String,
        projection: eliot_process::EnvironmentProjection,
    ) -> Result<Self, ProfileError> {
        validate_text(&class, "environment_class")?;
        let digest = eliot_process_executor::environment_projection_digest(&projection);
        Ok(Self {
            class,
            digest,
            projection: Some(projection),
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
    /// Scope classes the admitted profile revision declares.
    ///
    /// These are the classes the resolution above was validated against, not
    /// a caller-supplied copy: the environment check compares the attested
    /// [`StageEnvironment`] class with [`Self::environment`] against
    /// `profile.classes.environment`, and this field is that same admitted
    /// value. Returning it keeps a later receipt or declared-environment
    /// check bound to the registry's own class instead of text a caller
    /// repeated back, so a caller can never admit a route against classes the
    /// registry never admitted.
    pub classes: ProfileScopeClasses,
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
            if stage.external {
                let spec = self.registry.spec(stage.spec.as_str()).ok_or_else(|| {
                    ProfileError::UnknownSpec {
                        profile: profile.name.clone(),
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                    }
                })?;
                if spec.invocation_kind != stage.kind {
                    return Err(ProfileError::SpecKindMismatch {
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                        kind: stage.kind,
                    });
                }
            } else {
                let pure = self
                    .registry
                    .pure_transform(stage.spec.as_str())
                    .ok_or_else(|| ProfileError::UnknownSpec {
                        profile: profile.name.clone(),
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                    })?;
                if stage.kind != InstrumentKind::Inspect
                    || pure.profile.as_str() != profile.name
                    || pure.profile_revision != profile.revision
                    || pure.profile_version != profile.spec_revision
                {
                    return Err(ProfileError::Snapshot {
                        detail: format!(
                            "pure stage '{}' differs from its registered transform profile/version",
                            stage.stage_id
                        ),
                    });
                }
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
            classes: profile.classes.clone(),
            registry_generation,
            registry_digest,
            resolution_digest,
        })
    }
}

/// Execution contour selected by the admitted profile registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StageExecution {
    /// External stage dispatched through the process execution plane.
    External,
    /// Registered deterministic in-process transform at this parser generation.
    Pure { parser_generation: u64 },
}

/// One admitted profile stage in topological order.
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
    /// Registry-derived execution contour. It must agree with `external`.
    pub execution: StageExecution,
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
    pub executable: Option<String>,
    /// Admitted tool version requirement, when the spec pins one.
    pub executable_version: Option<String>,
    /// Admitted supply-chain receipt for the kind, when a machine
    /// observation was admitted for it at this generation.
    pub supply_receipt: Option<SupplyChainReceipt>,
    /// Fixed command template; empty admits only the empty argument vector.
    pub argument_template: Vec<String>,
    /// The real verification argv this stage runs, carried from the bound
    /// spec's [`InstrumentSpec::verification_command`].
    ///
    /// This is the argv the process grant seals, so it is compiled into the
    /// stage exactly as `argument_template` is: a stage cannot be launched
    /// under an argv the admitted spec did not declare.
    pub verification_command: Vec<String>,
    /// Invocation schema authority.
    pub schema: Option<ContractId>,
    /// Owner-resolved fixed argument schema; absent in historical snapshots.
    pub fixed_argument_schema: Option<FixedArgumentSchema>,
    /// Admitted environment class.
    pub environment_class: String,
    /// Admitted credential policy identity.
    pub credential_policy: Option<ContractId>,
    /// Admitted network policy identity.
    pub network_policy: Option<ContractId>,
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
    pub max_concurrency: Option<u32>,
}

/// Typed pre-launch admission failure (I10.8.3).
///
/// These failures refuse the invocation before child creation: an unregistered
/// kind, an argument vector outside the owner-resolved schema, an unknown
/// executable identity, or an agent-provided executable/argument combination
/// never reaches the execution plane. The failure carries no process, no
/// permit, and no retry directive.
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
    /// Legacy diagnostic retained for callers; current fixed-schema admission
    /// reports an unmatched argument vector as [`Self::ArgumentMismatch`].
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
        let _validated = ResolvedExecutableIdentity::new(
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
        let Some(file_identity) = observed.file_identity else {
            return Err(AdmissionError::ExecutableMismatch {
                detail: "new external admission requires the owner-observed file identity"
                    .to_owned(),
            });
        };
        if request.executable_path.as_deref() != Some(observed.canonical_path.as_str())
            || request.executable_digest.as_deref() != Some(observed.content_digest.as_str())
            || request.executable_version != observed.tool_version
        {
            return Err(AdmissionError::ExecutableMismatch {
                detail: "request executable snapshot differs from machine observation".to_owned(),
            });
        }
        let Some(executable) = self.executable.as_deref() else {
            return Err(AdmissionError::InvalidRequest {
                detail: "external admission has no executable identity".to_owned(),
            });
        };
        if observed.executable_file_name() != executable.to_ascii_lowercase() {
            return Err(AdmissionError::ExecutableMismatch {
                detail: format!(
                    "observed '{}' is not the admitted executable '{}'",
                    observed.canonical_path, executable,
                ),
            });
        }
        // The observed argv must be the argv this spec admits. The executable
        // digest alone cannot witness which arguments ran: two stages of the
        // same tool share one content digest, so without this check an
        // observation carrying substituted argv would be admitted under the
        // admitted identity. `binds_argv` compares argv to argv only.
        if !observed.binds_argv(&self.verification_command) {
            return Err(AdmissionError::ExecutableMismatch {
                detail: format!(
                    "observed argv {:?} is not the admitted verification command {:?}",
                    observed.arguments, self.verification_command,
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
        let Some(receipt) = &self.supply_receipt else {
            return Err(AdmissionError::ExecutableMismatch {
                detail: "external stage has no registered executable supply-chain receipt"
                    .to_owned(),
            });
        };
        receipt
            .check_observation(
                &eliot_instrument_api::registry::ExternalExecutableObservation {
                    canonical_path: observed.canonical_path.clone(),
                    executable_file_name: observed.executable_file_name(),
                    content_digest: observed.content_digest.clone(),
                    file_identity,
                    tool_version: observed.tool_version.clone(),
                },
            )
            .map_err(|error| AdmissionError::ExecutableMismatch {
                detail: error.to_string(),
            })?;
        Ok(observed.content_digest.clone())
    }

    /// Admits one typed invocation against this stage before process creation.
    ///
    /// This is the shared pre-launch admission boundary (I10.8.3): the
    /// request carries typed invocation facts and exact argv elements plus the
    /// launcher-observed machine identity. The admitted profile, spec, fixed
    /// argument template, supply-chain receipt, and `profile_revision` come
    /// from the planned stage and the owning route; the caller never supplies
    /// them.
    /// Pure in-process stages take no process grant here: they stay on the
    /// non-process path and are refused. Every external stage requires the
    /// owner-observed executable identity; an empty content digest never
    /// yields a launchable grant. Both the caller argument vector and the
    /// executed argv must match the owner-resolved fixed schema exactly.
    /// Punctuation is accepted when that schema declares the exact argument.
    ///
    /// The sealed `grant.arguments` is the stage's admitted verification
    /// command, NOT `request.arguments`. Those are different facts: a
    /// caller's `InstrumentInvocation.arguments` is an instrument-level filter
    /// that every builtin admits only as the empty vector, while the argv the
    /// stage actually runs is the spec's `verification_command` (issue #1914,
    /// audit 5918718113 item 3 â€” "an empty argument template or a tool's
    /// default/help output is not package verification"). Sealing the request's
    /// empty vector into the grant left
    /// `InstrumentRunner::launch_admitted` comparing the sealed request's real
    /// argv (`cargo build --message-format=json --locked --all-targets`) against
    /// an empty `grant.arguments` and refusing every launch with
    /// `RunnerError::ReceiptMismatch`, so no stage of a verification route could
    /// ever reach a recorded tool identity. The grant is also the identity the
    /// launch receipt records, so binding the wrong argv there is what makes the
    /// argv unsubstantiated: a run whose argv differed from the admitted command
    /// would still carry a self-consistent grant digest.
    ///
    /// Success seals every bound field, including the observed canonical path,
    /// the admitted verification argv, and the admitted supply-chain receipt
    /// digest, into an [`InstrumentAdmissionGrant`] whose digest the launch
    /// receipt records.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] when the stage is pure, the caller labels
    /// (profile, revision) differ from the admitted stage identity, the kind
    /// ID is unregistered, the class differs, the fixed schema is absent or
    /// mismatched against the caller arguments or executed argv, or the
    /// executable identity is unknown, changed, malformed, or unobserved.
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
        if self.fixed_argument_schema.as_ref().is_none_or(|schema| {
            self.schema.as_ref() != Some(&schema.schema_ref)
                || !schema.validates(
                    &schema.schema_ref,
                    &request.arguments,
                    &self.verification_command,
                )
        }) {
            return Err(AdmissionError::ArgumentMismatch {
                detail: "request or executable argv differs from the owner-resolved fixed argument schema".to_owned(),
            });
        }
        let Some(identity) = observed else {
            return Err(AdmissionError::UnresolvedObservation {
                instrument: self.spec.as_str().to_owned(),
            });
        };
        let content_digest = self.check_executable(request, identity)?;
        let Some(executable) = self.executable.clone() else {
            return Err(AdmissionError::InvalidRequest {
                detail: "external admission has no executable identity".to_owned(),
            });
        };
        let Some(credential_policy) = self.credential_policy.clone() else {
            return Err(AdmissionError::InvalidRequest {
                detail: "external admission has no credential policy".to_owned(),
            });
        };
        let Some(network_policy) = self.network_policy.clone() else {
            return Err(AdmissionError::InvalidRequest {
                detail: "external admission has no network policy".to_owned(),
            });
        };
        let mut grant = InstrumentAdmissionGrant {
            kind_id: self.spec.as_str().to_owned(),
            kind_version: self.kind_version,
            kind: self.kind,
            profile: self.profile.clone(),
            profile_revision: self.profile_revision,
            spec_digest: self.spec_digest.clone(),
            executable,
            executable_version: self.executable_version.clone(),
            content_digest,
            executable_path: identity.canonical_path.clone(),
            executable_file_identity: identity.file_identity,
            supply_digest: self
                .supply_receipt
                .as_ref()
                .map(SupplyChainReceipt::digest)
                .unwrap_or_default(),
            arguments: self.verification_command.clone(),
            environment_class: self.environment_class.clone(),
            scope_class: ADMITTED_SCOPE_CLASS.to_owned(),
            source_root: None,
            declared_scope: None,
            environment_digest: None,
            authority_epoch: None,
            resource_generation: None,
            credential_policy,
            network_policy,
            timeout_ms: self.timeout_ms,
            max_output_bytes: self.max_output_bytes,
            parser: self.parser.clone(),
            parser_generation: self.parser_generation,
            max_concurrency: self.max_concurrency,
            grant_digest: String::new(),
        };
        grant.grant_digest = grant.digest();
        Ok(grant)
    }

    /// Refuses new admission when the live registry replaced the admitted
    /// spec, parser, supply-chain receipt, or route (I10.8.3).
    ///
    /// Replacement ships as a new registry generation: the live spec digest,
    /// parser identity/generation, receipt digest, and stage route must still
    /// equal this compiled admission, or new launches fail closed here.
    /// Historical run evidence is untouched: verdicts never call this path,
    /// so an older permitted attempt keeps its sealed grant and receipt.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError::UnknownKind`] when the live registry no
    /// longer admits the spec, or [`AdmissionError::InvalidRequest`] when the
    /// spec, parser, receipt, or route was replaced since compilation.
    pub fn refuse_if_revoked(&self, registry: &InstrumentRegistry) -> Result<(), AdmissionError> {
        match self.execution {
            StageExecution::External => {
                if !self.external {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "external execution contour differs from the profile stage"
                            .to_owned(),
                    });
                }
                let Some(live) = registry.spec(self.spec.as_str()) else {
                    return Err(AdmissionError::UnknownKind {
                        instrument: self.spec.as_str().to_owned(),
                    });
                };
                if live.digest() != self.spec_digest {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "admitted spec was replaced since compilation".to_owned(),
                    });
                }
                if live.parser.as_str() != self.parser.as_str()
                    || live.parser_generation != self.parser_generation
                {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "admitted parser was replaced since compilation".to_owned(),
                    });
                }
                let live_supply = registry
                    .supply_chain(self.spec.as_str())
                    .map(SupplyChainReceipt::digest)
                    .unwrap_or_default();
                let admitted_supply = self
                    .supply_receipt
                    .as_ref()
                    .map(SupplyChainReceipt::digest)
                    .unwrap_or_default();
                if live_supply != admitted_supply {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "admitted supply-chain receipt was replaced since compilation"
                            .to_owned(),
                    });
                }
            }
            StageExecution::Pure { parser_generation } => {
                if self.external || parser_generation != self.parser_generation {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "pure execution contour differs from the profile stage/parser generation".to_owned(),
                    });
                }
                let Some(live) = registry.pure_transform(self.spec.as_str()) else {
                    return Err(AdmissionError::UnknownKind {
                        instrument: self.spec.as_str().to_owned(),
                    });
                };
                if live.spec_digest() != self.spec_digest
                    || live.parser_generation != parser_generation
                    || self.executable.is_some()
                    || self.executable_version.is_some()
                    || self.supply_receipt.is_some()
                    || self.credential_policy.is_some()
                    || self.network_policy.is_some()
                {
                    return Err(AdmissionError::InvalidRequest {
                        detail: "pure transform contract or process-free contour was replaced"
                            .to_owned(),
                    });
                }
            }
        }
        let exact_stage = ProfileCompiler::new(registry)
            .compile_exact(&self.profile, self.profile_revision)
            .ok()
            .and_then(|profile| {
                profile
                    .stages
                    .into_iter()
                    .find(|stage| stage.stage_id == self.stage_id)
            });
        if exact_stage.as_ref() != Some(self) {
            return Err(AdmissionError::InvalidRequest {
                detail:
                    "admitted stage fields differ from the exact live profile/spec registry entry"
                        .to_owned(),
            });
        }
        Ok(())
    }

    /// Admits one typed invocation against the live registry before process
    /// creation.
    ///
    /// This is the shared pre-launch admission boundary over a registry the
    /// composition root still holds: a replaced spec, parser, receipt, or
    /// route fails closed through [`AdmittedStage::refuse_if_revoked`], and
    /// the surviving admission seals through [`AdmittedStage::admit`].
    ///
    /// # Errors
    ///
    /// Returns the [`AdmittedStage::refuse_if_revoked`] and
    /// [`AdmittedStage::admit`] failures.
    pub fn admit_live(
        &self,
        registry: &InstrumentRegistry,
        request: &InstrumentAdmissionRequest,
        observed: Option<&ResolvedExecutableIdentity>,
        profile_revision: u64,
    ) -> Result<InstrumentAdmissionGrant, AdmissionError> {
        self.refuse_if_revoked(registry)?;
        self.admit(request, observed, profile_revision)
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
    /// Registry generation the admission was compiled against.
    pub registry_generation: u64,
    /// Registry digest the admission was compiled against.
    pub registry_digest: String,
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
            let (
                execution,
                spec_revision,
                spec_digest,
                kind_version,
                executable,
                executable_version,
                supply_receipt,
                argument_template,
                verification_command,
                schema,
                fixed_argument_schema,
                environment_class,
                credential_policy,
                network_policy,
                parser,
                parser_generation,
                max_output_bytes,
                timeout_ms,
                max_concurrency,
            ) = if stage.external {
                let spec = self.registry.spec(stage.spec.as_str()).ok_or_else(|| {
                    ProfileError::UnknownSpec {
                        profile: admitted.name.clone(),
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                    }
                })?;
                (
                    StageExecution::External,
                    spec.revision,
                    spec.digest(),
                    spec.kind.version(),
                    Some(spec.executable.clone()),
                    spec.executable_version.clone(),
                    self.registry.supply_chain(stage.spec.as_str()).cloned(),
                    spec.argument_template.clone(),
                    spec.verification_command.clone(),
                    Some(spec.schema.clone()),
                    spec.fixed_argument_schema.clone(),
                    spec.environment_profile.clone(),
                    Some(spec.credential_policy.clone()),
                    Some(spec.network_policy.clone()),
                    spec.parser.clone(),
                    spec.parser_generation,
                    spec.limits.max_output_bytes,
                    spec.limits.timeout_ms,
                    Some(spec.max_concurrency),
                )
            } else {
                let pure = self
                    .registry
                    .pure_transform(stage.spec.as_str())
                    .ok_or_else(|| ProfileError::UnknownSpec {
                        profile: admitted.name.clone(),
                        stage: stage.stage_id.clone(),
                        spec: stage.spec.as_str().to_owned(),
                    })?;
                if stage.kind != InstrumentKind::Inspect
                    || pure.profile.as_str() != admitted.name
                    || pure.profile_revision != admitted.revision
                    || pure.profile_version != admitted.spec_revision
                {
                    return Err(ProfileError::Snapshot {
                        detail: format!(
                            "pure stage '{}' differs from its registered transform profile/version",
                            stage.stage_id
                        ),
                    });
                }
                (
                    StageExecution::Pure {
                        parser_generation: pure.parser_generation,
                    },
                    pure.profile_version,
                    pure.spec_digest(),
                    pure.adapter_version,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    None,
                    None,
                    pure.environment_profile.clone(),
                    None,
                    None,
                    pure.parser.clone(),
                    pure.parser_generation,
                    Some(pure.max_input_bytes as u64),
                    None,
                    None,
                    None,
                )
            };
            stages.push(AdmittedStage {
                stage_id: stage.stage_id.clone(),
                spec: stage.spec.clone(),
                kind: stage.kind,
                required: stage.required,
                external: stage.external,
                execution,
                depends_on: stage.depends_on.clone(),
                profile: admitted.name.clone(),
                profile_revision: admitted.revision,
                spec_revision,
                spec_digest,
                kind_version,
                executable,
                executable_version,
                supply_receipt,
                argument_template,
                verification_command,
                schema,
                fixed_argument_schema,
                environment_class,
                credential_policy,
                network_policy,
                parser,
                parser_generation,
                max_output_bytes,
                timeout_ms,
                max_concurrency,
            });
        }
        Ok(AdmittedProfile {
            name: admitted.name.clone(),
            revision: admitted.revision,
            registry_generation: self.registry.generation(),
            registry_digest: self.registry.digest(),
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

    /// Resolves the verification route both local and CI invoke (issue #1914
    /// W2).
    ///
    /// I18.21 requires "CI builds the ELIOT verifier/runner bootstrap and then
    /// calls the same versioned profiles used locally", and I10.8.10 requires
    /// "Justfile and CI â†’ thin invokers of the same named profile". Both
    /// requirements are satisfied by exactly this one call: there is no second
    /// gate-order source, no CI-only stage list, and no per-entrypoint profile
    /// choice, because the caller names only the route and supplies only the
    /// admitted execution bindings. The route name is resolved to its admitted
    /// revision here, and the caller learns the exact identity from the returned
    /// [`ResolvedProfile`]; it can never select a revision itself.
    ///
    /// A route that is not admitted fails closed with
    /// [`ProfileError::UnknownProfile`]. A caller that wants a different route
    /// passes a different name, which is an explicit visible change, never an
    /// environment sniff.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnknownProfile`] when the route admits no
    /// revision, and the [`InstrumentProfileResolver::resolve`] failures when a
    /// binding is refused.
    pub fn resolve_route(
        &self,
        route: &str,
        layout: TargetLayout,
        scope: WorkScope,
        environment: StageEnvironment,
    ) -> Result<ResolvedProfile, ProfileError> {
        self.resolve_admitted(route, layout, scope, environment)
    }
}
