// Test-only constructors are expected to accept the explicit valid fixture values.
#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, ContractId, ContractVersion, EpochId, EpochLineageId, OperationId, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence,
};
use eliot_instrument_api::registry::{
    EnvironmentInheritanceBinding, EnvironmentPolicy, EnvironmentProjectionBinding,
    ExternalExecutableObservation, ExternalStagePin, InstrumentClass, InstrumentProfile,
    InstrumentRegistrySnapshot, InstrumentSpec, InstrumentSpecParams, ProcessExecutionProjection,
    ProfileScopeClasses, REGISTRY_SNAPSHOT_SCHEMA, REGISTRY_SNAPSHOT_SCHEMA_VERSION,
    ResolvedExecutionBinding, ResourceLimits as InstrumentResourceLimits, StageDag, StageDecl,
    SupplyChainReceipt, validate_external_stage,
};
use eliot_instrument_api::{FileIdentity, InstrumentInvocation, InstrumentKind};
use eliot_kernel_service::InstrumentStageGrantRequest;
use eliot_process::{
    ContractError, EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId,
    ProcessIntent, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_store_api::ScopeId;
use serde_json::Value;

const GENERATION: u64 = 1;
const PROFILE: &str = "profile:1814-binding";
const STAGE: &str = "stage:1814-binding";
const SCOPE: &str = "scope:1814-binding";
const ROOT: &str = "C:\\work\\m-cs1";
const VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

fn id(value: &str) -> ContractId {
    ContractId::new(value).expect("valid contract identity")
}

#[allow(
    clippy::too_many_lines,
    reason = "one coherent binding fixture keeps the synthetic shared grant and original ProcessIntent visibly joined"
)]
fn bound_request() -> (
    InstrumentStageGrantRequest,
    eliot_instrument_api::InstrumentAdmissionGrant,
) {
    let instrument = id("eliot.instrument.testd.binding");
    let environment_projection = EnvironmentProjection::new(
        BTreeMap::from([(
            "PATH".to_owned(),
            std::env::var("PATH").expect("the owner toolchain PATH is available"),
        )]),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .expect("closed owner toolchain environment");
    let environment_binding = EnvironmentProjectionBinding {
        non_secret: environment_projection.non_secret().clone(),
        secret_refs: Vec::new(),
        inheritance: EnvironmentInheritanceBinding::None,
    };
    let spec = InstrumentSpec::new(InstrumentSpecParams {
        kind: eliot_instrument_api::registry::InstrumentKindId::new(instrument.clone(), VERSION)
            .expect("versioned kind"),
        class: InstrumentClass::Test,
        invocation_kind: InstrumentKind::Test,
        revision: VERSION,
        executable: "test-runner.exe".to_owned(),
        executable_version: Some("7.4.1".to_owned()),
        parser: id("eliot.parser.testd.binding"),
        parser_generation: 3,
        environment_profile: "isolated-process".to_owned(),
        environment_policy: EnvironmentPolicy::ToolchainPath {
            permitted_path: environment_projection.non_secret()["PATH"].clone(),
        },
        schema: id("eliot.schema.testd.binding"),
        argument_template: Vec::new(),
        verification_command: vec!["test".to_owned(), "--locked".to_owned()],
        credential_policy: id("eliot.credentials.none"),
        network_policy: id("eliot.network.disabled"),
        limits: InstrumentResourceLimits::new(Some(30_000), Some(1_048_576)),
        max_concurrency: 2,
    })
    .expect("valid instrument spec");
    let stage = StageDecl::new(
        STAGE.to_owned(),
        instrument.clone(),
        InstrumentKind::Test,
        Vec::new(),
        true,
        true,
    )
    .expect("valid external stage");
    let profile = InstrumentProfile::new(
        PROFILE.to_owned(),
        4,
        VERSION,
        vec![InstrumentKind::Test],
        StageDag::build(PROFILE, vec![stage]).expect("valid stage DAG"),
        ProfileScopeClasses::new(
            "workspace-layout".to_owned(),
            "isolated-process".to_owned(),
            "workspace-scope".to_owned(),
        )
        .expect("valid profile scope classes"),
    )
    .expect("valid profile");
    let environment_digest = "b".repeat(64);
    let snapshot = InstrumentRegistrySnapshot {
        schema: REGISTRY_SNAPSHOT_SCHEMA.to_owned(),
        version: REGISTRY_SNAPSHOT_SCHEMA_VERSION.to_owned(),
        generation: GENERATION,
        specs: vec![spec.clone()],
        pure_transforms: Vec::<Value>::new(),
        profiles: vec![profile],
        receipts: vec![
            SupplyChainReceipt::new(
                instrument.clone(),
                spec.executable.clone(),
                "a".repeat(64),
                spec.executable_version.clone(),
                spec.digest(),
                GENERATION,
            )
            .expect("valid admitted executable receipt"),
        ],
    };
    let pin = ExternalStagePin {
        profile: PROFILE.to_owned(),
        profile_revision: 4,
        stage_id: STAGE.to_owned(),
        registry_generation: GENERATION,
    };
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("valid authority lineage"),
        NonZeroU64::new(1).expect("nonzero epoch sequence"),
    )
    .expect("valid authority epoch");
    let clock = ClockReading {
        valid_time_ms: Some(10),
        known_time_ms: Some(11),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    };
    let request_id = RequestId::new("request:1814-binding").expect("valid request id");
    let state_fence = StateFence::new(
        epoch.clone(),
        ResourceGeneration::new(GENERATION).expect("nonzero resource generation"),
    );
    let invocation = InstrumentInvocation {
        request: eliot_contracts::RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product:1814-binding").expect("valid product id"),
            source_id: SourceId::new("source:1814-binding").expect("valid source id"),
            state_fence,
            clock: clock.clone(),
        },
        instrument,
        kind: InstrumentKind::Test,
        profile: PROFILE.to_owned(),
        target: "worktree:m-cs1".to_owned(),
        arguments: Vec::new(),
        input_artifacts: Vec::new(),
        declared_scope: SCOPE.to_owned(),
        requested_at: clock,
    };
    let resolution = ResolvedExecutionBinding {
        source_root: ROOT.to_owned(),
        environment_class: "isolated-process".to_owned(),
        environment_digest: environment_digest.clone(),
        environment_projection: environment_binding.clone(),
        declared_scope: SCOPE.to_owned(),
        authority_epoch: epoch,
        resource_generation: GENERATION,
    };
    let observation = ExternalExecutableObservation {
        canonical_path: "C:\\tools\\test-runner.exe".to_owned(),
        executable_file_name: "test-runner.exe".to_owned(),
        content_digest: "a".repeat(64),
        file_identity: FileIdentity {
            volume_serial_number: 41,
            file_index: 1814,
        },
        tool_version: Some("7.4.1".to_owned()),
    };
    let process_projection = ProcessExecutionProjection {
        working_directory: ROOT.to_owned(),
        environment_digest,
        environment_projection: environment_binding,
        executable_file_identity: observation.file_identity,
        authority_epoch: resolution.authority_epoch.clone(),
        resource_generation: GENERATION,
        wall_timeout_ms: 30_000,
        stdout_bytes: 1_048_576,
        stderr_bytes: 1_048_576,
    };
    let admission = validate_external_stage(
        &snapshot,
        &pin,
        &invocation,
        &observation,
        &spec.verification_command,
        &resolution,
        &process_projection,
    )
    .expect("fixture stage must be admitted by the shared validator");
    let intent = ProcessIntent::new(
        OperationId::new(request_id.as_str()).expect("operation id matches request"),
        ProcessTreeId::new("tree:1814-binding").expect("process tree id"),
        JobId::new("job:1814-binding").expect("job id"),
        ImageId::new("image:1814-binding").expect("image id"),
        SessionId::new("session:1814-binding").expect("session id"),
        Generation::new(GENERATION).expect("nonzero generation"),
        observation.canonical_path.clone(),
        observation.content_digest.clone(),
        spec.verification_command.clone(),
        ROOT,
        environment_projection,
        ResourceLimits::new(30_000, None, None, 1_048_576, 1_048_576, 4)
            .expect("valid process limits"),
    )
    .expect("valid original process intent")
    .with_executable_file_identity(observation.file_identity)
    .expect("bind original intent to the observed file object")
    .with_instrument_admission_digest(admission.digest.clone())
    .expect("bind original intent to validator grant");
    let request = InstrumentStageGrantRequest {
        scope_id: ScopeId::new("scope:1814-binding").expect("valid scope id"),
        pin,
        invocation,
        resolution,
        intent,
    };
    (request, admission)
}

fn received_intent_with_admission(source: &ProcessIntent, admission_digest: &str) -> ProcessIntent {
    let intent = ProcessIntent::new(
        source.operation_id().clone(),
        source.process_tree_id().clone(),
        source.job_id().clone(),
        source.image_id().clone(),
        source.session_id().clone(),
        source.generation(),
        source.executable().to_owned(),
        source.executable_sha256().to_owned(),
        source.argv().to_vec(),
        source.working_directory().to_owned(),
        source.environment().clone(),
        source.resource_limits().clone(),
    )
    .expect("construct valid received intent");
    let intent = if let Some(identity) = source.executable_file_identity().copied() {
        intent
            .with_executable_file_identity(identity)
            .expect("preserve source executable file identity")
    } else {
        intent
    };
    intent
        .with_instrument_admission_digest(admission_digest.to_owned())
        .expect("seal received intent to the supplied admission digest")
}

#[test]
fn original_intent_admission_digest_must_match_shared_admission() {
    let (request, admission) = bound_request();
    assert_eq!(
        admission.executable_file_identity,
        request.intent.executable_file_identity().copied()
    );

    request
        .validate_admission_binding(&admission)
        .expect("original intent bound to shared admission should validate");

    let mut substituted_policy = admission.clone();
    substituted_policy.max_concurrency = 4;
    substituted_policy.grant_digest = substituted_policy.digest();
    let substituted_digest = substituted_policy.digest();
    assert!(
        matches!(
            request.validate_admission_binding(&substituted_policy),
            Err(ContractError::DigestMismatch {
                field: "instrument_stage.admission_digest",
                expected,
                observed,
            }) if expected == substituted_digest && observed == admission.digest()
        ),
        "a self-consistent changed concurrency declaration cannot match the original process binding"
    );

    let mut substituted = request.clone();
    substituted.intent = substituted
        .intent
        .clone()
        .with_instrument_admission_digest(admission.digest())
        .expect("same admission rebinding is idempotent");
    assert!(
        substituted
            .intent
            .clone()
            .with_instrument_admission_digest("f".repeat(64))
            .is_err(),
        "a sealed original intent cannot be rebound to a substituted grant"
    );

    let mut received_substitution = request.clone();
    received_substitution.intent = received_intent_with_admission(&request.intent, &"f".repeat(64));
    assert!(
        matches!(
            received_substitution.validate_admission_binding(&admission),
            Err(ContractError::DigestMismatch {
                field: "instrument_stage.admission_digest",
                expected,
                observed,
            }) if expected == admission.digest() && observed == "f".repeat(64)
        ),
        "substituted admission digest must be a typed refusal before dispatch grant issuance"
    );
}

#[test]
fn tampered_original_effect_digest_cannot_be_refreshed_or_admitted() {
    let (request, admission) = bound_request();
    let mut wire = serde_json::to_value(&request).expect("serialize received request");
    wire["intent"]["effect_digest"] = Value::String("e".repeat(64));
    let tampered: InstrumentStageGrantRequest =
        serde_json::from_value(wire).expect("tampered wire remains structurally typed");

    assert!(matches!(
        tampered.validate_admission_binding(&admission),
        Err(ContractError::DigestMismatch {
            field: "effect_digest",
            observed,
            ..
        }) if observed == "e".repeat(64)
    ));
    assert!(
        matches!(
            tampered
                .intent
                .clone()
                .with_instrument_admission_digest(admission.digest.clone()),
            Err(ContractError::DigestMismatch {
                field: "effect_digest",
                observed,
                ..
            }) if observed == "e".repeat(64)
        ),
        "binding cannot refresh a tampered original effect digest"
    );
}
