//! Typed, non-live fixtures for the admitted installation-survey probe
//! terminal boundary.

use std::collections::BTreeMap;
use std::error::Error;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, EpochLineageId, sha256_hex};
use eliot_installation::{BoundedProbeInvocation, ProbeBehaviour};
use eliot_instrument_api::EvidenceAxes;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DescendantEvidence, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, EnvironmentInheritance, EnvironmentProjection, ExitDisposition,
    ExitStatus, FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId,
    PermitIssuance, PhysicalProcessBinding, ProcessCallerSession, ProcessEvidence,
    ProcessExecutionBinding, ProcessHealth, ProcessHealthStatus, ProcessId, ProcessIntent,
    ProcessOwnerBinding, ProcessRequest, ProcessSessionClass, ProcessStartReceipt,
    ProcessState, ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, ProcessStreamTransportPrefixIdentity, ProcessTreeId,
    ResourceLimits, SessionId, StreamEvidenceGap, StreamPersistenceStatus,
    StreamTransportStatus, SuspendedProcessIdentity, DurableProcessStreamSource,
    DurableStreamLocatorKind,
};
use eliot_platform::PlatformHandle;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const TEST_EXECUTABLE_IDENTITY: &str = "file-identity:conflicting-probe-test";
const TEST_EXECUTABLE: &str = r"C:\tools\survey-probe.exe";
const TEST_EXECUTABLE_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Clone, Copy)]
enum StreamFixture {
    CompleteExact,
    SourceUnavailable,
    TruncatedSource,
    GappedSource,
    PolicyTransformedSource,
}

struct ProbeFixture {
    invocation: BoundedProbeInvocation,
    operation_id: OperationId,
    owner: ProcessOwnerBinding,
    caller: ProcessCallerSession,
    state_fence: FencingToken,
    executable: PathBuf,
    executable_sha256: String,
    start: ProcessStartReceipt,
    running_state: ProcessState,
}

fn test_epoch() -> TestResult<EpochId> {
    let sequence = NonZeroU64::new(7)
        .ok_or_else(|| std::io::Error::other("test epoch sequence must be non-zero"))?;
    Ok(EpochId::new(
        EpochLineageId::new(TEST_LINEAGE)?,
        sequence,
    )?)
}

fn revision_heads() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

fn state_fence(nonce: &str) -> TestResult<FencingToken> {
    Ok(FencingToken::new(
        test_epoch()?,
        Generation::new(1)?,
        nonce,
    )?)
}

fn probe_invocation(max_output_bytes: u64) -> TestResult<BoundedProbeInvocation> {
    let family_id = eliot_installation::INTEGRATION_SEED_FAMILIES
        .first()
        .map(|(family, _)| *family)
        .ok_or_else(|| std::io::Error::other("installation seed family list is empty"))?;
    Ok(BoundedProbeInvocation {
        family_id: PlatformHandle::new(family_id)?,
        probe_id: PlatformHandle::new("probe:version")?,
        executable_identity: PlatformHandle::new(TEST_EXECUTABLE_IDENTITY)?,
        behaviour: ProbeBehaviour::ReportOwnVersion,
        argument: PlatformHandle::new("--version")?,
        timeout_ms: 1_000,
        max_output_bytes,
        max_descendant_processes: 0,
        working_area: PlatformHandle::new("working-area:temporary")?,
        environment_names: Vec::new(),
    })
}

fn process_fixture(
    operation_id: &str,
    session_id: &str,
    action_lease: &str,
) -> TestResult<ProbeFixture> {
    let generation = Generation::new(1)?;
    let operation_id = OperationId::new(operation_id)?;
    let session_id = SessionId::new(session_id)?;
    let executable = PathBuf::from(TEST_EXECUTABLE);
    let executable_sha256 = TEST_EXECUTABLE_SHA256.to_owned();
    let state_fence = state_fence("survey-probe-fence")?;
    let authority_epoch = test_epoch()?;
    let revision_heads = revision_heads();
    let owner = ProcessOwnerBinding::new(
        "eliotd",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        authority_epoch.clone(),
        generation,
    )?;
    let caller = ProcessCallerSession::new(
        ProcessSessionClass::EliotdGeneration,
        owner.clone(),
        session_id.clone(),
    )?;
    let intent = ProcessIntent::new(
        operation_id.clone(),
        ProcessTreeId::new(operation_id.as_str())?,
        JobId::new(operation_id.as_str())?,
        ImageId::new(TEST_EXECUTABLE_IDENTITY)?,
        session_id,
        generation,
        executable.to_string_lossy(),
        executable_sha256.clone(),
        vec!["--version".to_owned()],
        r"C:\eliot\survey-probe-working",
        EnvironmentProjection::new(
            BTreeMap::new(),
            Vec::new(),
            EnvironmentInheritance::None,
        )?,
        ResourceLimits::new(10_000, Some(5_000), Some(1_048_576), 4096, 4096, 0)?,
    )?;
    let mut authority = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new("survey-probe-test-authority")?,
        KernelDispatchKey::from_secret_bytes([0x5a; 32])?,
    );
    let permit = authority.issue(
        &intent,
        PermitIssuance::new(
            ActionLeaseRef::new(action_lease)?,
            state_fence.clone(),
            revision_heads.clone(),
            100,
            200,
            "survey-probe-test-nonce",
        )?,
    )?;
    let request = ProcessRequest::new(intent.clone(), permit)?;
    let suspended_identity = SuspendedProcessIdentity::new(
        ProcessId::new("survey-probe-root")?,
        intent.process_tree_id().clone(),
        intent.job_id().clone(),
        intent.image_id().clone(),
        intent.session_id().clone(),
        intent.generation(),
        PhysicalProcessBinding::new(
            4242,
            11,
            executable.to_string_lossy(),
            r"Local\Eliot-Survey-Probe-Test",
        )?,
        120,
        executable_sha256.clone(),
    )?;
    let context = DispatchValidationContext::new(
        ClockObservation {
            valid_time_ms: Some(150),
            known_time_ms: Some(150),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        },
        state_fence.clone(),
        authority_epoch,
        revision_heads,
        41,
    )?;
    let validated = authority.validate_and_consume(request, suspended_identity, &context)?;
    let mut running_state = ProcessState::from_validated(&validated);
    running_state.mark_resumed(
        151,
        ProcessHealth::new(ProcessHealthStatus::Healthy, true, 151, None)?,
    )?;
    let start = ProcessStartReceipt::new(&running_state)?;

    Ok(ProbeFixture {
        invocation: probe_invocation(64)?,
        operation_id,
        owner,
        caller,
        state_fence,
        executable,
        executable_sha256,
        start,
        running_state,
    })
}

fn stream_payload(kind: ProcessStreamKind) -> &'static [u8] {
    match kind {
        ProcessStreamKind::Stdout => b"version: 1\n",
        ProcessStreamKind::Stderr => b"diagnostic\n",
    }
}

fn byte_length(bytes: &[u8]) -> TestResult<u64> {
    Ok(u64::try_from(bytes.len())?)
}

fn stream_policy() -> TestResult<ProcessStreamPolicyBinding> {
    Ok(ProcessStreamPolicyBinding::new(
        "policy:1",
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    )?)
}

fn exact_source(bytes: &[u8]) -> TestResult<DurableProcessStreamSource> {
    let digest = sha256_hex(bytes);
    Ok(DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        format!("eliot://blob/{digest}"),
        format!("receipt:blob-ready:{digest}"),
        digest,
        byte_length(bytes)?,
    )?)
}

fn stream_evidence(
    binding: &ProcessExecutionBinding,
    kind: ProcessStreamKind,
    fixture: StreamFixture,
) -> TestResult<ProcessStreamEvidence> {
    let policy = stream_policy()?;
    let observed = stream_payload(kind);
    let observed_length = byte_length(observed)?;
    let observed_sha256 = sha256_hex(observed);

    match fixture {
        StreamFixture::CompleteExact => Ok(ProcessStreamEvidence::new_raw(
            binding.clone(),
            kind,
            policy,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::CompleteSource,
            observed_sha256,
            observed_length,
            ProcessStreamPrefixPreview::from_transport_prefix(
                observed.to_vec(),
                observed_length,
            )?,
            Some(exact_source(observed)?),
            Vec::new(),
        )?),
        StreamFixture::SourceUnavailable => Ok(ProcessStreamEvidence::new_raw(
            binding.clone(),
            kind,
            policy,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            observed_sha256,
            observed_length,
            ProcessStreamPrefixPreview::from_transport_prefix(
                observed.to_vec(),
                observed_length,
            )?,
            None,
            vec![StreamEvidenceGap::PersistenceUnavailable],
        )?),
        StreamFixture::TruncatedSource => {
            let truncated_source_bytes = &observed[..3];
            let source_length = byte_length(truncated_source_bytes)?;
            let source_sha256 = sha256_hex(truncated_source_bytes);
            let source = DurableProcessStreamSource::exact_transport(
                DurableStreamLocatorKind::Blob,
                format!("eliot://blob/{source_sha256}"),
                format!("receipt:blob-ready:{source_sha256}"),
                source_sha256.clone(),
                source_length,
            )?;
            Ok(ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
                binding.clone(),
                kind,
                policy,
                StreamTransportStatus::Complete,
                StreamPersistenceStatus::PartialSource,
                observed_sha256,
                observed_length,
                ProcessStreamPrefixPreview::from_transport_prefix(
                    truncated_source_bytes.to_vec(),
                    observed_length,
                )?,
                Some(source),
                Some(ProcessStreamTransportPrefixIdentity::new(
                    source_sha256,
                    source_length,
                )?),
                vec![StreamEvidenceGap::PersistenceFailed],
            )?)
        }
        StreamFixture::GappedSource => Ok(ProcessStreamEvidence::new_raw(
            binding.clone(),
            kind,
            policy,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::SourceUnavailable,
            observed_sha256,
            observed_length,
            ProcessStreamPrefixPreview::withheld_by_policy(),
            None,
            vec![StreamEvidenceGap::RedactionFailed],
        )?),
        StreamFixture::PolicyTransformedSource => {
            let transformed_bytes = b"scrubbed probe output";
            let transformed_length = byte_length(transformed_bytes)?;
            let transformed_sha256 = sha256_hex(transformed_bytes);
            let transformation = eliot_process::ProcessStreamTransformationBinding::new(
                "receipt:probe-redaction",
                observed_sha256,
                observed_length,
                transformed_sha256.clone(),
                transformed_length,
                policy.policy_ref(),
                policy.redaction_ref(),
            )?;
            let source = DurableProcessStreamSource::policy_transformed(
                DurableStreamLocatorKind::Blob,
                format!("eliot://blob/{transformed_sha256}"),
                format!("receipt:blob-ready:{transformed_sha256}"),
                transformed_sha256,
                transformed_length,
                transformation,
            )?;
            Ok(ProcessStreamEvidence::new_raw(
                binding.clone(),
                kind,
                policy,
                StreamTransportStatus::Complete,
                StreamPersistenceStatus::CompleteSource,
                observed_sha256,
                observed_length,
                ProcessStreamPrefixPreview::from_source_prefix(
                    transformed_bytes.to_vec(),
                    transformed_length,
                )?,
                Some(source),
                Vec::new(),
            )?)
        }
    }
}

fn completed_terminal(
    fixture: &ProbeFixture,
    stdout_fixture: StreamFixture,
    stderr_fixture: StreamFixture,
    include_descendant: bool,
) -> TestResult<ProcessEvidence> {
    let mut state = fixture.running_state.clone();
    let root_process_id = state
        .view()
        .identity()
        .ok_or_else(|| std::io::Error::other("running process fixture has no identity"))?
        .process_id()
        .clone();
    let mut process_ids = vec![root_process_id.clone()];
    if include_descendant {
        process_ids.push(ProcessId::new("survey-probe-descendant")?);
    }
    let process_count = process_ids.len();
    let descendants = DescendantEvidence::new(
        state.binding().clone(),
        root_process_id,
        process_ids,
        true,
        true,
        Some(format!("raw:p04-job-history:{process_count}:true:true")),
    )?;
    state.exit(
        ExitStatus::new(ExitDisposition::Completed, Some(0), None, 160)?,
        descendants,
    )?;
    let view = state.view();
    let binding = view.binding().clone();
    let stdout = stream_evidence(&binding, ProcessStreamKind::Stdout, stdout_fixture)?;
    let stderr = stream_evidence(&binding, ProcessStreamKind::Stderr, stderr_fixture)?;
    Ok(ProcessEvidence::new_typed(
        view,
        Some(stdout),
        Some(stderr),
        EvidenceAxes::observed(),
    )?)
}

fn validate_fixture(
    fixture: &ProbeFixture,
    terminal: &ProcessEvidence,
) -> Result<Vec<PlatformHandle>, super::ProcessExecutionError> {
    super::validate_survey_probe_terminal(
        &fixture.invocation,
        &fixture.operation_id,
        &fixture.owner,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &fixture.start,
        terminal,
    )
}

#[test]
fn completed_leaf_probe_returns_exact_durable_stdout_and_stderr_references() -> TestResult {
    let fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-lease",
    )?;
    let terminal = completed_terminal(
        &fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        false,
    )?;

    let answer_refs = validate_fixture(&fixture, &terminal)?;
    let expected_stdout = PlatformHandle::new(format!(
        "receipt:blob-ready:{}",
        sha256_hex(stream_payload(ProcessStreamKind::Stdout))
    ))?;
    let expected_stderr = PlatformHandle::new(format!(
        "receipt:blob-ready:{}",
        sha256_hex(stream_payload(ProcessStreamKind::Stderr))
    ))?;
    assert_eq!(fixture.invocation.max_descendant_processes, 0);
    assert_eq!(answer_refs, vec![expected_stdout, expected_stderr]);
    Ok(())
}

#[test]
fn completed_probe_refuses_root_plus_one_descendant_when_bound_is_zero() -> TestResult {
    let fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-lease",
    )?;
    let terminal = completed_terminal(
        &fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        true,
    )?;
    let tree = terminal
        .view()
        .descendants()
        .ok_or_else(|| std::io::Error::other("completed terminal has no tree evidence"))?;
    assert_eq!(tree.process_ids().len(), 2);
    assert!(tree
        .process_ids()
        .contains(&ProcessId::new("survey-probe-descendant")?));
    assert!(validate_fixture(&fixture, &terminal).is_err());
    Ok(())
}

#[test]
fn completed_probe_refuses_foreign_session_fence_image_hash_and_operation() -> TestResult {
    let fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-lease",
    )?;
    let terminal = completed_terminal(
        &fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        false,
    )?;
    let validate = |invocation: &BoundedProbeInvocation,
                    operation_id: &OperationId,
                    caller: &ProcessCallerSession,
                    fence: &FencingToken,
                    executable: &Path,
                    executable_sha256: &str,
                    terminal: &ProcessEvidence| {
        super::validate_survey_probe_terminal(
            invocation,
            operation_id,
            &fixture.owner,
            caller,
            fence,
            executable,
            executable_sha256,
            &fixture.start,
            terminal,
        )
    };

    let foreign_caller = ProcessCallerSession::new(
        ProcessSessionClass::EliotdGeneration,
        fixture.owner.clone(),
        SessionId::new("foreign-survey-probe-session")?,
    )?;
    assert!(validate(
        &fixture.invocation,
        &fixture.operation_id,
        &foreign_caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &terminal,
    )
    .is_err());

    let foreign_fence = FencingToken::new(
        fixture.state_fence.authority_epoch().clone(),
        fixture.state_fence.generation(),
        "foreign-survey-probe-fence",
    )?;
    assert!(validate(
        &fixture.invocation,
        &fixture.operation_id,
        &fixture.caller,
        &foreign_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &terminal,
    )
    .is_err());

    let mut foreign_image = fixture.invocation.clone();
    foreign_image.executable_identity = PlatformHandle::new("file-identity:foreign-image")?;
    assert!(validate(
        &foreign_image,
        &fixture.operation_id,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &terminal,
    )
    .is_err());

    let foreign_hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    assert!(validate(
        &fixture.invocation,
        &fixture.operation_id,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        foreign_hash,
        &terminal,
    )
    .is_err());

    let foreign_operation = OperationId::new("foreign-survey-probe-operation")?;
    assert!(validate(
        &fixture.invocation,
        &foreign_operation,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &terminal,
    )
    .is_err());

    let other_lease_fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-other-lease",
    )?;
    let mismatched_terminal = completed_terminal(
        &other_lease_fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        false,
    )?;
    assert_eq!(
        fixture.start.identity(),
        mismatched_terminal
            .view()
            .identity()
            .ok_or_else(|| std::io::Error::other("mismatched terminal has no identity"))?
    );
    assert_ne!(fixture.start.binding(), mismatched_terminal.binding());
    assert!(validate(
        &fixture.invocation,
        &fixture.operation_id,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &mismatched_terminal,
    )
    .is_err());
    Ok(())
}

#[test]
fn survey_probe_stream_answer_ref_requires_exact_complete_durable_source() -> TestResult {
    let fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-lease",
    )?;
    let exact_terminal = completed_terminal(
        &fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        false,
    )?;
    let exact_stdout = exact_terminal
        .stdout()
        .ok_or_else(|| std::io::Error::other("typed stdout evidence is missing"))?;
    let expected = PlatformHandle::new(format!(
        "receipt:blob-ready:{}",
        sha256_hex(stream_payload(ProcessStreamKind::Stdout))
    ))?;
    assert_eq!(
        super::survey_probe_stream_answer_ref(
            Some(exact_stdout),
            ProcessStreamKind::Stdout,
            exact_terminal.binding(),
        )?,
        expected
    );

    let unavailable = completed_terminal(
        &fixture,
        StreamFixture::SourceUnavailable,
        StreamFixture::CompleteExact,
        false,
    )?;
    assert!(super::survey_probe_stream_answer_ref(
        unavailable.stdout(),
        ProcessStreamKind::Stdout,
        unavailable.binding(),
    )
    .is_err());

    let truncated = completed_terminal(
        &fixture,
        StreamFixture::TruncatedSource,
        StreamFixture::CompleteExact,
        false,
    )?;
    assert!(super::survey_probe_stream_answer_ref(
        truncated.stdout(),
        ProcessStreamKind::Stdout,
        truncated.binding(),
    )
    .is_err());

    let gapped = completed_terminal(
        &fixture,
        StreamFixture::GappedSource,
        StreamFixture::CompleteExact,
        false,
    )?;
    assert!(super::survey_probe_stream_answer_ref(
        gapped.stdout(),
        ProcessStreamKind::Stdout,
        gapped.binding(),
    )
    .is_err());

    let transformed = completed_terminal(
        &fixture,
        StreamFixture::PolicyTransformedSource,
        StreamFixture::CompleteExact,
        false,
    )?;
    assert!(super::survey_probe_stream_answer_ref(
        transformed.stdout(),
        ProcessStreamKind::Stdout,
        transformed.binding(),
    )
    .is_err());
    Ok(())
}

#[test]
fn completed_probe_refuses_combined_stdout_and_stderr_over_output_bound() -> TestResult {
    let fixture = process_fixture(
        "survey-probe-operation",
        "survey-probe-session",
        "survey-probe-lease",
    )?;
    let terminal = completed_terminal(
        &fixture,
        StreamFixture::CompleteExact,
        StreamFixture::CompleteExact,
        false,
    )?;
    let observed_output_bytes = byte_length(stream_payload(ProcessStreamKind::Stdout))?
        + byte_length(stream_payload(ProcessStreamKind::Stderr))?;
    let invocation = probe_invocation(observed_output_bytes - 1)?;
    assert!(super::validate_survey_probe_terminal(
        &invocation,
        &fixture.operation_id,
        &fixture.owner,
        &fixture.caller,
        &fixture.state_fence,
        &fixture.executable,
        &fixture.executable_sha256,
        &fixture.start,
        &terminal,
    )
    .is_err());
    Ok(())
}
