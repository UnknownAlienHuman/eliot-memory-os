// Test-only constructors are expected to accept the explicit valid fixture values.
#![allow(clippy::expect_used)]

use eliot_contracts::{
    ClockReading, ContractId, ContractVersion, EpochId, EpochLineageId, ProductId, RequestId,
    RequestMetadata, ResourceGeneration, SourceId, StateFence,
};
use eliot_instrument_api::registry::{
    EnvironmentInheritanceBinding, EnvironmentPolicy, EnvironmentProjectionBinding,
    ExternalExecutableObservation, ExternalStagePin, FixedArgumentSchema, InstrumentClass,
    InstrumentKindId, InstrumentProfile, InstrumentRegistrySnapshot, InstrumentSpec,
    InstrumentSpecParams, ProcessExecutionProjection, ProfileScopeClasses,
    REGISTRY_SNAPSHOT_SCHEMA, REGISTRY_SNAPSHOT_SCHEMA_VERSION, ResolvedExecutionBinding,
    ResourceLimits, StageDag, StageDecl, SupplyChainReceipt, validate_external_stage,
    validate_testd_productive_stage,
};
use eliot_instrument_api::{FileIdentity, InstrumentInvocation, InstrumentKind};
use serde_json::Value;
use std::collections::BTreeMap;

const GENERATION: u64 = 9;
const PROFILE: &str = "profile:1814-test";
const STAGE: &str = "stage:1814-test";
const SCOPE: &str = "scope:1814-test";
const ROOT: &str = "C:\\work\\m-cs1";
const VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

fn environment_digest() -> String {
    "b".repeat(64)
}

fn content_digest() -> String {
    "a".repeat(64)
}

fn projection(
    non_secret: BTreeMap<String, String>,
    inheritance: EnvironmentInheritanceBinding,
) -> EnvironmentProjectionBinding {
    EnvironmentProjectionBinding {
        non_secret,
        secret_refs: Vec::new(),
        inheritance,
    }
}

fn toolchain_path_projection() -> EnvironmentProjectionBinding {
    let path = std::env::var("PATH").expect("the admitted root toolchain PATH is available");
    projection(
        BTreeMap::from([("PATH".to_owned(), path)]),
        EnvironmentInheritanceBinding::None,
    )
}

fn id(value: &str) -> ContractId {
    ContractId::new(value).expect("valid contract identity")
}

#[allow(
    clippy::too_many_lines,
    reason = "one coherent validator fixture keeps its spec, profile, supply receipt, and request bindings inspectable together"
)]
fn fixture() -> (
    InstrumentRegistrySnapshot<Value>,
    ExternalStagePin,
    InstrumentInvocation,
    ExternalExecutableObservation,
    ResolvedExecutionBinding,
    ProcessExecutionProjection,
) {
    let environment_projection = toolchain_path_projection();
    let instrument = id("eliot.instrument.testd.fixture");
    let spec = InstrumentSpec::new(InstrumentSpecParams {
        kind: InstrumentKindId::new(instrument.clone(), VERSION).expect("versioned kind"),
        class: InstrumentClass::Test,
        invocation_kind: InstrumentKind::Test,
        revision: VERSION,
        executable: "test-runner.exe".to_owned(),
        executable_version: Some("7.4.1".to_owned()),
        parser: id("eliot.parser.testd.fixture"),
        parser_generation: 3,
        environment_profile: "isolated-process".to_owned(),
        environment_policy: EnvironmentPolicy::ToolchainPath {
            permitted_path: environment_projection.non_secret["PATH"].clone(),
        },
        schema: id("eliot.schema.testd.fixture"),
        argument_template: Vec::new(),
        verification_command: vec!["test".to_owned(), "--locked".to_owned()],
        credential_policy: id("eliot.credentials.none"),
        network_policy: id("eliot.network.disabled"),
        limits: ResourceLimits::new(Some(30_000), Some(1_048_576)),
        max_concurrency: 2,
    })
    .expect("valid test instrument spec");
    let stage = StageDecl::new(
        STAGE.to_owned(),
        instrument.clone(),
        InstrumentKind::Test,
        Vec::new(),
        true,
        true,
    )
    .expect("valid external stage");
    let dag = StageDag::build(PROFILE, vec![stage]).expect("valid stage DAG");
    let profile = InstrumentProfile::new(
        PROFILE.to_owned(),
        4,
        VERSION,
        vec![InstrumentKind::Test],
        dag,
        ProfileScopeClasses::new(
            "workspace-layout".to_owned(),
            "isolated-process".to_owned(),
            "workspace-scope".to_owned(),
        )
        .expect("valid profile scope classes"),
    )
    .expect("valid profile");
    let receipt = SupplyChainReceipt::new(
        instrument.clone(),
        spec.executable.clone(),
        content_digest(),
        spec.executable_version.clone(),
        spec.digest(),
        GENERATION,
    )
    .expect("valid executable supply receipt");
    let snapshot = InstrumentRegistrySnapshot {
        schema: REGISTRY_SNAPSHOT_SCHEMA.to_owned(),
        version: REGISTRY_SNAPSHOT_SCHEMA_VERSION.to_owned(),
        generation: GENERATION,
        specs: vec![spec],
        pure_transforms: Vec::<Value>::new(),
        profiles: vec![profile],
        receipts: vec![receipt],
    };
    let pin = ExternalStagePin {
        profile: PROFILE.to_owned(),
        profile_revision: 4,
        stage_id: STAGE.to_owned(),
        registry_generation: GENERATION,
    };
    let request_clock = ClockReading {
        valid_time_ms: Some(10),
        known_time_ms: Some(11),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    };
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("valid authority lineage"),
        std::num::NonZeroU64::new(1).expect("nonzero epoch sequence"),
    )
    .expect("valid authority epoch");
    let state_fence = StateFence::new(epoch.clone(), ResourceGeneration::genesis());
    let invocation = InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new("request:1814-test").expect("valid request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product:1814-test").expect("valid product id"),
            source_id: SourceId::new("source:1814-test").expect("valid source id"),
            state_fence,
            clock: request_clock.clone(),
        },
        instrument,
        kind: InstrumentKind::Test,
        profile: PROFILE.to_owned(),
        target: "worktree:m-cs1".to_owned(),
        arguments: Vec::new(),
        input_artifacts: Vec::new(),
        declared_scope: SCOPE.to_owned(),
        requested_at: request_clock,
    };
    let observation = ExternalExecutableObservation {
        canonical_path: "C:\\tools\\test-runner.exe".to_owned(),
        executable_file_name: "test-runner.exe".to_owned(),
        content_digest: content_digest(),
        file_identity: FileIdentity {
            volume_serial_number: 41,
            file_index: 1814,
        },
        tool_version: Some("7.4.1".to_owned()),
    };
    let resolution = ResolvedExecutionBinding {
        source_root: ROOT.to_owned(),
        environment_class: "isolated-process".to_owned(),
        environment_digest: environment_digest(),
        environment_projection: environment_projection.clone(),
        declared_scope: SCOPE.to_owned(),
        authority_epoch: epoch.clone(),
        resource_generation: 0,
    };
    let process = ProcessExecutionProjection {
        working_directory: ROOT.to_owned(),
        environment_digest: environment_digest(),
        environment_projection,
        executable_file_identity: observation.file_identity,
        authority_epoch: epoch,
        resource_generation: 0,
        wall_timeout_ms: 30_000,
        stdout_bytes: 1_048_576,
        stderr_bytes: 1_048_576,
    };
    (snapshot, pin, invocation, observation, resolution, process)
}

#[test]
fn registered_external_stage_grant_pins_exact_spec_profile_parser_and_supply() {
    let (snapshot, pin, invocation, observation, resolution, process) = fixture();
    let grant = validate_external_stage(
        &snapshot,
        &pin,
        &invocation,
        &observation,
        &["test".to_owned(), "--locked".to_owned()],
        &resolution,
        &process,
    )
    .expect("exact registered invocation should be admitted");

    assert_eq!(grant.kind_id, "eliot.instrument.testd.fixture");
    assert_eq!(grant.kind_version, VERSION);
    assert_eq!(grant.profile, PROFILE);
    assert_eq!(grant.profile_revision, 4);
    assert_eq!(grant.spec_digest, snapshot.specs[0].digest());
    assert_eq!(grant.executable, "test-runner.exe");
    assert_eq!(grant.executable_version.as_deref(), Some("7.4.1"));
    assert_eq!(grant.executable_path, observation.canonical_path);
    assert_eq!(
        grant.executable_file_identity,
        Some(observation.file_identity)
    );
    assert_eq!(grant.content_digest, content_digest());
    assert_eq!(grant.supply_digest, snapshot.receipts[0].digest());
    assert_eq!(
        grant.arguments,
        vec!["test".to_owned(), "--locked".to_owned()]
    );
    assert_eq!(grant.environment_class, "isolated-process");
    assert_eq!(grant.scope_class, "workspace-scope");
    assert_eq!(grant.credential_policy, id("eliot.credentials.none"));
    assert_eq!(grant.network_policy, id("eliot.network.disabled"));
    assert_eq!(grant.timeout_ms, Some(30_000));
    assert_eq!(grant.max_output_bytes, Some(1_048_576));
    assert_eq!(grant.parser, id("eliot.parser.testd.fixture"));
    assert_eq!(grant.parser_generation, 3);
    assert_eq!(grant.max_concurrency, 2);
    assert_eq!(grant.grant_digest, grant.digest());
}

#[test]
fn external_stage_consumes_the_declared_fixed_argument_schema() {
    let (mut snapshot, pin, mut invocation, observation, resolution, process) = fixture();
    let path = "C:\\work\\m-cs1\\examples\\plugin (draft) [1].toml".to_owned();
    let caller_arguments = vec!["--manifest-path".to_owned(), path.clone()];
    let executed_argv = vec!["test".to_owned(), "--manifest-path".to_owned(), path];
    let spec = &mut snapshot.specs[0];
    spec.argument_template = caller_arguments.clone();
    spec.verification_command = executed_argv.clone();
    spec.fixed_argument_schema = Some(FixedArgumentSchema {
        schema_ref: spec.schema.clone(),
        caller_arguments: caller_arguments.clone(),
        executed_argv: executed_argv.clone(),
    });
    snapshot.receipts[0].spec_digest = spec.digest();
    invocation.arguments = caller_arguments.clone();

    assert!(
        snapshot.specs[0]
            .fixed_argument_schema
            .as_ref()
            .is_some_and(|schema| schema.validates(
                &snapshot.specs[0].schema,
                &caller_arguments,
                &executed_argv
            ))
    );
    let grant = validate_external_stage(
        &snapshot,
        &pin,
        &invocation,
        &observation,
        &executed_argv,
        &resolution,
        &process,
    )
    .expect("the exact owner-declared argv, including its punctuation path, is admitted");
    assert_eq!(grant.arguments, executed_argv);

    let (mut missing_schema, pin, invocation, observation, resolution, process) = fixture();
    missing_schema.specs[0].fixed_argument_schema = None;
    missing_schema.receipts[0].spec_digest = missing_schema.specs[0].digest();
    assert_eq!(
        validate_external_stage(
            &missing_schema,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Arguments)
    );

    let (mut changed_schema, pin, mut invocation, observation, resolution, process) = fixture();
    let changed_caller_arguments = changed_schema.specs[0].verification_command.clone();
    let spec = &mut changed_schema.specs[0];
    spec.argument_template = changed_caller_arguments.clone();
    spec.fixed_argument_schema
        .as_mut()
        .expect("new fixture specs retain their fixed argument schema")
        .caller_arguments = changed_caller_arguments.clone();
    invocation.arguments = changed_caller_arguments;
    assert_eq!(
        validate_external_stage(
            &changed_schema,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Snapshot)
    );
}

#[test]
fn external_stage_admission_refuses_unregistered_identity_and_shell_or_argv_drift() {
    let (snapshot, pin, invocation, observation, resolution, process) = fixture();
    let verify = |invocation: &InstrumentInvocation, argv: &[String]| {
        validate_external_stage(
            &snapshot,
            &pin,
            invocation,
            &observation,
            argv,
            &resolution,
            &process,
        )
    };

    let mut unregistered = invocation.clone();
    unregistered.instrument = id("eliot.instrument.unregistered");
    assert_eq!(
        verify(&unregistered, &["test".to_owned(), "--locked".to_owned()]),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Invocation)
    );

    let mut raw_shell = invocation.clone();
    raw_shell.arguments = vec!["test && whoami".to_owned()];
    assert_eq!(
        verify(&raw_shell, &["test".to_owned(), "--locked".to_owned()]),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Arguments)
    );

    assert_eq!(
        verify(
            &invocation,
            &[
                "test".to_owned(),
                "--locked".to_owned(),
                "--ignored".to_owned()
            ],
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Arguments)
    );
}

#[test]
fn external_stage_environment_policy_refuses_unlisted_keys_and_inheritance() {
    let (snapshot, pin, invocation, observation, mut resolution, mut process) = fixture();
    assert!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        )
        .is_ok(),
        "the original root-produced PATH projection remains admitted"
    );

    let owner_path = resolution.environment_projection.non_secret["PATH"].clone();
    let with_extra = projection(
        BTreeMap::from([
            ("PATH".to_owned(), owner_path),
            (
                "RUSTC_WRAPPER".to_owned(),
                "C:\\unregistered\\rustc-wrapper.exe".to_owned(),
            ),
            ("HTTP_PROXY".to_owned(), "http://127.0.0.1:8888".to_owned()),
        ]),
        EnvironmentInheritanceBinding::None,
    );
    resolution.environment_projection = with_extra.clone();
    process.environment_projection = with_extra;
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );

    let (snapshot, pin, invocation, observation, mut resolution, mut process) = fixture();
    let inherited = projection(
        BTreeMap::from([(
            "PATH".to_owned(),
            resolution.environment_projection.non_secret["PATH"].clone(),
        )]),
        EnvironmentInheritanceBinding::Allowlisted,
    );
    resolution.environment_projection = inherited.clone();
    process.environment_projection = inherited;
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );

    let (snapshot, pin, invocation, observation, mut resolution, mut process) = fixture();
    let unregistered_path = projection(
        BTreeMap::from([("PATH".to_owned(), "C:\\unregistered-toolchain".to_owned())]),
        EnvironmentInheritanceBinding::None,
    );
    resolution.environment_projection = unregistered_path.clone();
    process.environment_projection = unregistered_path;
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );
}

#[test]
fn testd_environment_policy_requires_the_typed_owner_projection() {
    let (mut snapshot, pin, invocation, observation, resolution, process) = fixture();
    snapshot.specs[0].environment_policy = EnvironmentPolicy::TestdProductive;
    snapshot.receipts[0].spec_digest = snapshot.specs[0].digest();
    let owner_projection = resolution.environment_projection.clone();

    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );
    assert!(
        validate_testd_productive_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
            &owner_projection,
        )
        .is_ok()
    );

    let wrong_owner_projection = projection(
        BTreeMap::from([("PATH".to_owned(), "C:\\different-owner-path".to_owned())]),
        EnvironmentInheritanceBinding::None,
    );
    assert_eq!(
        validate_testd_productive_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
            &wrong_owner_projection,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );
}

#[test]
fn external_stage_admission_refuses_executable_version_snapshot_and_scope_drift() {
    let (snapshot, pin, invocation, observation, resolution, process) = fixture();
    let exact_argv = ["test".to_owned(), "--locked".to_owned()];

    let mut changed_executable = observation.clone();
    changed_executable.executable_file_name = "other.exe".to_owned();
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &changed_executable,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Executable)
    );

    let mut changed_hash = observation.clone();
    changed_hash.content_digest = "c".repeat(64);
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &changed_hash,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Executable)
    );

    let mut replaced_file_object = observation.clone();
    replaced_file_object.file_identity.file_index += 1;
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &replaced_file_object,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );

    let mut wrong_retained_version = snapshot.clone();
    wrong_retained_version.receipts[0].tool_version = Some("7.4.2".to_owned());
    let mut observed_wrong_retained_version = observation.clone();
    observed_wrong_retained_version.tool_version = Some("7.4.2".to_owned());
    assert_eq!(
        validate_external_stage(
            &wrong_retained_version,
            &pin,
            &invocation,
            &observed_wrong_retained_version,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Executable)
    );

    let mut changed_version = observation.clone();
    changed_version.tool_version = Some("7.4.2".to_owned());
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &changed_version,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Executable)
    );

    let mut malformed_snapshot = snapshot.clone();
    malformed_snapshot.specs[0].parser_generation += 1;
    assert_eq!(
        validate_external_stage(
            &malformed_snapshot,
            &pin,
            &invocation,
            &changed_version,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Snapshot)
    );

    let mut changed_root = process;
    changed_root.working_directory = "C:\\other-root".to_owned();
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &exact_argv,
            &resolution,
            &changed_root,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );

    let (snapshot, pin, invocation, observation, mut resolution, process) = fixture();
    resolution.declared_scope = "scope:1814-other".to_owned();
    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &exact_argv,
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );
}

#[test]
fn external_stage_admission_refuses_resolution_environment_class_skew() {
    let (snapshot, pin, invocation, observation, mut resolution, process) = fixture();
    resolution.environment_class = "ambient-process".to_owned();

    assert_eq!(
        validate_external_stage(
            &snapshot,
            &pin,
            &invocation,
            &observation,
            &["test".to_owned(), "--locked".to_owned()],
            &resolution,
            &process,
        ),
        Err(eliot_instrument_api::registry::RegistryAdmissionError::Resolution)
    );
}
