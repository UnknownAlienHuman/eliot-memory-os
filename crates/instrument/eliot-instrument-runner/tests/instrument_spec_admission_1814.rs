use std::path::{Path, PathBuf};

use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence, sha256_hex,
};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_instrument_nextest::{NextestCommand, NextestScope};
use eliot_instrument_runner::profile::{InstrumentClass, builtin_specs};
use eliot_instrument_runner::{
    AdmissionError, BUILTIN_PROFILE_REVISION, InstrumentRegistry, PACKAGE_VERIFICATION_ROUTE,
    ProfileCompiler, ResolvedExecutableIdentity, SupplyChainReceipt, bridge_executor_observation,
    prepare_admission_submission,
};
use eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT;

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn cargo_executable() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO").map(PathBuf::from)
        && path.is_file()
    {
        return path;
    }
    std::env::split_paths(&std::env::var_os("PATH").expect("test PATH is available"))
        .map(|directory| directory.join("cargo.exe"))
        .find(|path| path.is_file())
        .expect("the test environment exposes its installed cargo.exe")
}

fn executable_on_path(program: &str) -> Option<PathBuf> {
    let file_names = if cfg!(windows) {
        vec![format!("{program}.exe"), program.to_owned()]
    } else {
        vec![program.to_owned()]
    };
    std::env::split_paths(&std::env::var_os("PATH")?)
        .flat_map(|directory| {
            file_names
                .iter()
                .map(move |file_name| directory.join(file_name))
        })
        .find(|path| path.is_file())
}

fn tool_observation(path: PathBuf) -> (String, String) {
    let canonical = std::fs::canonicalize(path).expect("owner-observed tool path is canonical");
    let bytes = std::fs::read(&canonical).expect("owner-observed tool bytes are readable");
    (canonical.to_string_lossy().into_owned(), sha256_hex(&bytes))
}

fn testd_tool_observation() -> Option<eliot_testd_core::TestdToolObservation> {
    let nextest_path = executable_on_path(eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_PROGRAM)?;
    let cargo_path = cargo_executable();
    let rustc_path = executable_on_path("rustc")?;
    let (nextest_path, nextest_sha256) = tool_observation(nextest_path);
    let (cargo_path, cargo_sha256) = tool_observation(cargo_path);
    let (rustc_path, rustc_sha256) = tool_observation(rustc_path);
    let selected_toolchain = Path::new(&rustc_path)
        .parent()?
        .parent()?
        .file_name()?
        .to_str()?
        .to_owned();
    let observation = eliot_testd_core::TestdToolObservation {
        nextest_path,
        nextest_sha256,
        cargo_path,
        cargo_sha256,
        rustc_path,
        rustc_sha256,
        selected_toolchain,
    };
    observation.validate().ok()?;
    Some(observation)
}

fn observed_identity(
    stage: &eliot_instrument_runner::AdmittedStage,
    path: &Path,
    arguments: Vec<String>,
) -> ResolvedExecutableIdentity {
    let observation = eliot_process_executor::ExecutableObservation::observe_at_path(
        path,
        arguments,
        sha256_hex(b"empty test environment projection"),
        None,
    )
    .expect("metadata-only observation of the installed executable succeeds");
    bridge_executor_observation(stage.spec.as_str(), observation)
        .expect("metadata-only observation has the registered identity shape")
}

fn invocation(stage: &eliot_instrument_runner::AdmittedStage) -> InstrumentInvocation {
    let lineage = EpochLineageId::new(LINEAGE).expect("valid test lineage");
    let epoch = EpochId::new(
        lineage,
        std::num::NonZeroU64::new(1).expect("nonzero epoch"),
    )
    .expect("valid test epoch");
    let clock = ClockReading {
        valid_time_ms: Some(10),
        known_time_ms: Some(11),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    };

    InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new("instrument-spec-admission-1814").expect("valid request ID"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("instrument-spec-admission-1814").expect("valid product ID"),
            source_id: SourceId::new("instrument-spec-admission-1814").expect("valid source ID"),
            state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
            clock,
        },
        instrument: stage.spec.clone(),
        kind: stage.kind,
        profile: stage.profile.clone(),
        target: "worktree:instrument-spec-admission-1814".to_owned(),
        arguments: stage.argument_template.clone(),
        input_artifacts: Vec::new(),
        declared_scope: "package:eliot-instrument-runner".to_owned(),
        requested_at: clock,
    }
}

fn package_stage(registry: &InstrumentRegistry) -> eliot_instrument_runner::AdmittedStage {
    ProfileCompiler::new(registry)
        .compile_exact(PACKAGE_VERIFICATION_ROUTE, BUILTIN_PROFILE_REVISION)
        .expect("the built-in package-verification route is admitted")
        .stages
        .into_iter()
        .find(|stage| stage.external && stage.executable == "cargo")
        .expect("package-verification admits its Cargo process stage")
}

#[test]
fn format_invocation_kind_is_bound_separately_from_semantic_class() {
    let specs = builtin_specs().expect("built-in instrument specs are valid");
    let rustfmt = specs
        .iter()
        .find(|spec| spec.kind_key() == RUSTFMT_INSTRUMENT)
        .expect("rustfmt has one admitted instrument spec");

    assert_eq!(rustfmt.class, InstrumentClass::HeuristicAnalysis);
    assert_eq!(rustfmt.invocation_kind, InstrumentKind::Format);
}

#[test]
fn testd_productive_binding_matches_the_typed_nextest_command() {
    let target = std::env::current_dir()
        .expect("test working directory exists")
        .to_string_lossy()
        .into_owned();
    let command = NextestCommand::run_scoped(
        target,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &NextestScope::default(),
    )
    .expect("the closed productive nextest command is valid");
    let digest = sha256_hex(b"owner-observation test binding");
    let binding = eliot_testd_core::testd_profile_binding_with_slots(
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &digest,
        &[],
    )
    .expect("the TestD owner admits its fixed productive profile");

    assert_eq!(command.executable, binding.program_path);
    assert_eq!(command.arguments, binding.fixed_argv);
    assert_eq!(
        command.arguments,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_ARGV
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        binding.wall_timeout_ms,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_WALL_TIMEOUT_MS
    );
    assert_eq!(
        binding.stdout_bytes,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_STDOUT_BYTES
    );
}

#[test]
fn testd_productive_binding_refuses_command_widening() {
    let target = std::env::current_dir()
        .expect("test working directory exists")
        .to_string_lossy()
        .into_owned();
    let mut command = NextestCommand::run_scoped(
        target,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &NextestScope::default(),
    )
    .expect("the closed productive nextest command is valid");
    let digest = sha256_hex(b"owner-observation test binding");
    let binding = eliot_testd_core::testd_profile_binding_with_slots(
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &digest,
        &[],
    )
    .expect("the TestD owner admits its fixed productive profile");

    command.arguments.push("--unregistered".to_owned());
    assert_ne!(command.arguments, binding.fixed_argv);
    assert!(binding.validate().is_ok());
}

#[test]
#[ignore = "requires owner-observed nextest fixture"]
fn testd_registry_binds_owner_observed_nextest_and_refuses_command_drift() {
    let observation = testd_tool_observation()
        .expect("live TestD proof requires the owner-observed nextest fixture");
    let target = std::env::current_dir()
        .expect("test working directory exists")
        .to_string_lossy()
        .into_owned();
    let command = NextestCommand::run_scoped(
        target,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &NextestScope::default(),
    )
    .expect("the closed productive nextest command is valid");
    let binding = eliot_testd_core::testd_profile_binding_with_slots(
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
        &observation.nextest_sha256,
        &[],
    )
    .expect("the TestD owner binding is valid");
    let registry =
        InstrumentRegistry::with_testd_productive_profile(1, &observation, &binding, &command)
            .expect("owner observation, TestD binding, and typed command admit together");
    let planned = ProfileCompiler::new(&registry)
        .compile_exact(
            eliot_testd_core::TESTD_PRODUCTIVE_PROFILE,
            BUILTIN_PROFILE_REVISION,
        )
        .expect("the exact TestD productive profile is admitted");
    let stage = planned
        .stages
        .first()
        .expect("productive TestD declares its one nextest stage");
    let supply = registry
        .supply_chain(NEXTEST_INSTRUMENT)
        .expect("the actual owner-observed nextest digest is receipted");

    assert_eq!(
        stage.stage.stage_id,
        eliot_testd_core::TESTD_PRODUCTIVE_PROFILE
    );
    assert_eq!(stage.stage.spec.as_str(), NEXTEST_INSTRUMENT);
    assert_eq!(
        stage.stage.executable.as_deref(),
        Some(eliot_testd_core::TESTD_PRODUCTIVE_PROFILE_PROGRAM)
    );
    assert_eq!(supply.content_digest, observation.nextest_sha256);
    assert_eq!(supply.spec_digest, stage.stage.spec_digest);
    assert_eq!(
        registry
            .persist()
            .expect("registry snapshot persists")
            .version,
        eliot_instrument_runner::REGISTRY_SNAPSHOT_SCHEMA_VERSION
    );

    let mut drifted = command;
    drifted.arguments.push("--unregistered".to_owned());
    assert!(matches!(
        InstrumentRegistry::with_testd_productive_profile(1, &observation, &binding, &drifted),
        Err(eliot_instrument_runner::ProfileError::TestdProductiveBindingMismatch)
    ));
}

fn registry_with_matching_supply_receipt() -> (
    InstrumentRegistry,
    eliot_instrument_runner::AdmittedStage,
    ResolvedExecutableIdentity,
) {
    let executable_path = cargo_executable();
    let initial_registry = InstrumentRegistry::with_verification_route_profiles(1, Vec::new())
        .expect("built-in verification registry is valid");
    let initial_stage = package_stage(&initial_registry);
    let observed = observed_identity(
        &initial_stage,
        &executable_path,
        initial_stage.verification_command.clone(),
    );
    let receipt = SupplyChainReceipt::new(
        ContractId::new(initial_stage.spec.as_str()).expect("registered contract ID"),
        initial_stage.executable.clone(),
        observed.content_digest.clone(),
        observed.tool_version.clone(),
        initial_stage.spec_digest.clone(),
        1,
    )
    .expect("receipt pins the observed executable and admitted spec digest");
    let registry = InstrumentRegistry::with_verification_route_profiles(1, vec![receipt])
        .expect("registry admits the matching generation-one receipt");
    let stage = package_stage(&registry);
    let observed = observed_identity(&stage, &executable_path, stage.verification_command.clone());
    (registry, stage, observed)
}

#[test]
fn matching_supply_receipt_admits_and_prepares_the_registered_stage_identity() {
    // Metadata-only proof: the installed Cargo file is hashed but never launched.
    // This is not live Windows process/effect evidence or canonical-store proof.
    let (registry, stage, observed) = registry_with_matching_supply_receipt();
    let invocation = invocation(&stage);
    let request = stage.admission_request(&invocation, Some(&observed));

    let grant = stage
        .admit_live(&registry, &request, Some(&observed), stage.profile_revision)
        .expect("exact executable identity and registered receipt are admitted");
    let submission = prepare_admission_submission(&registry, &stage, &observed)
        .expect("the exact registered snapshot and receipt are accepted for owner persistence");

    assert_eq!(grant.kind_id, stage.spec.as_str());
    assert_eq!(grant.spec_digest, stage.spec_digest);
    assert_eq!(grant.profile, stage.profile);
    assert_eq!(grant.profile_revision, stage.profile_revision);
    assert_eq!(grant.parser, stage.parser);
    assert_eq!(grant.parser_generation, stage.parser_generation);
    assert_eq!(grant.content_digest, observed.content_digest);
    assert_eq!(grant.executable_path, observed.canonical_path);
    assert_eq!(grant.executable_file_identity, observed.file_identity);
    assert_eq!(grant.arguments, stage.verification_command);
    assert!(!grant.supply_digest.is_empty());
    assert_eq!(grant.grant_digest, grant.digest());
    assert_eq!(
        submission.operation(),
        eliot_store_api::NamedMutationOperation::ApplyInstrumentRegistryState
    );
    assert_eq!(
        submission.read_operation(),
        eliot_store_api::NamedReadOperation::GetInstrumentRegistryState
    );
    assert_eq!(
        submission.snapshot_json(),
        registry.persist().expect("registry snapshot serializes")
    );
}

#[test]
fn changed_arguments_or_registered_identity_return_typed_admission_refusals() {
    let (registry, stage, observed) = registry_with_matching_supply_receipt();
    let invocation = invocation(&stage);

    let mut changed_argv = observed.clone();
    changed_argv
        .arguments
        .push("--changed-after-observation".to_owned());
    let request = stage.admission_request(&invocation, Some(&changed_argv));
    assert!(matches!(
        stage.admit_live(
            &registry,
            &request,
            Some(&changed_argv),
            stage.profile_revision
        ),
        Err(AdmissionError::ExecutableMismatch { .. })
    ));

    let mut unknown_kind = stage.admission_request(&invocation, Some(&observed));
    unknown_kind.instrument =
        ContractId::new("eliot.instrument.unregistered-1814-test").expect("valid test ID");
    assert!(matches!(
        stage.admit_live(
            &registry,
            &unknown_kind,
            Some(&observed),
            stage.profile_revision
        ),
        Err(AdmissionError::UnknownKind { .. })
    ));

    let mut raw_shell = stage.admission_request(&invocation, Some(&observed));
    raw_shell.arguments = vec!["--filter; cargo test".to_owned()];
    assert!(matches!(
        stage.admit_live(
            &registry,
            &raw_shell,
            Some(&observed),
            stage.profile_revision
        ),
        Err(AdmissionError::ArgumentMismatch { .. })
    ));

    let mut wrong_profile = stage.admission_request(&invocation, Some(&observed));
    wrong_profile.profile.push_str("-unregistered");
    assert!(matches!(
        stage.admit_live(
            &registry,
            &wrong_profile,
            Some(&observed),
            stage.profile_revision
        ),
        Err(AdmissionError::InvalidRequest { .. })
    ));

    let mut changed_parser = stage.clone();
    changed_parser.parser =
        ContractId::new("eliot.instrument.parser.changed-1814-test").expect("valid test ID");
    let request = changed_parser.admission_request(&invocation, Some(&observed));
    assert!(matches!(
        changed_parser.admit_live(
            &registry,
            &request,
            Some(&observed),
            changed_parser.profile_revision,
        ),
        Err(AdmissionError::InvalidRequest { .. })
    ));

    let mut changed_spec_digest = stage.clone();
    changed_spec_digest.spec_digest = "f".repeat(64);
    let request = changed_spec_digest.admission_request(&invocation, Some(&observed));
    assert!(matches!(
        changed_spec_digest.admit_live(
            &registry,
            &request,
            Some(&observed),
            changed_spec_digest.profile_revision,
        ),
        Err(AdmissionError::InvalidRequest { .. })
    ));

    assert!(matches!(
        stage.admit_live(
            &registry,
            &stage.admission_request(&invocation, Some(&observed)),
            Some(&observed),
            stage.profile_revision + 1,
        ),
        Err(AdmissionError::InvalidRequest { .. })
    ));
}

#[test]
fn historical_spec_without_argument_schema_keeps_its_digest_but_cannot_launch() {
    let registry = InstrumentRegistry::with_verification_route_profiles(1, Vec::new())
        .expect("built-in verification registry is valid");
    let stage = package_stage(&registry);
    let mut historical_spec = builtin_specs()
        .expect("built-in instrument specs are valid")
        .into_iter()
        .find(|spec| spec.kind_key() == stage.spec.as_str())
        .expect("the package stage has its original built-in spec");
    historical_spec.fixed_argument_schema = None;
    let original_historical_digest = historical_spec.digest();

    let mut historical_snapshot: serde_json::Value =
        serde_json::from_str(&registry.persist().expect("registry snapshot serializes"))
            .expect("serialized registry is valid JSON");
    for spec in historical_snapshot["specs"]
        .as_array_mut()
        .expect("registry snapshot contains its specs")
    {
        spec.as_object_mut()
            .expect("each serialized spec is an object")
            .remove("fixed_argument_schema");
    }
    let historical_registry = InstrumentRegistry::recover(
        &serde_json::to_string(&historical_snapshot).expect("historical snapshot serializes"),
    )
    .expect("historical specs remain readable");
    let historical_stage = package_stage(&historical_registry);

    assert_eq!(historical_stage.spec_digest, original_historical_digest);
    assert_eq!(historical_stage.fixed_argument_schema, None);
    let invocation = invocation(&historical_stage);
    let request = historical_stage.admission_request(&invocation, None);
    assert!(matches!(
        historical_stage.admit_live(
            &historical_registry,
            &request,
            None,
            historical_stage.profile_revision,
        ),
        Err(AdmissionError::ArgumentMismatch { .. })
    ));
}
