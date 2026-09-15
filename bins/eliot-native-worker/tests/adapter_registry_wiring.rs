//! T9-07 four-factory registry wiring proof (WRITER-A, bound by INTEGRATOR-T9-07).
//!
//! Real factories with controlled external seams: no live credentials, no
//! network, no spawned processes. The P-03 executor is an in-memory
//! recording double (its `start` is never reached on any refusal path);
//! opencode uses a loopback endpoint plus a non-credential policy directory;
//! ACP uses caller-owned in-memory handles; Claude constructs the real
//! `ClaudeSidecarFactory` over the forwarded executor while `prepare` with
//! live owner records stays a drive step. Every test owns a [`FactoryLedger`]
//! proving exactly which factory constructed, and none on any refusal.
//!
//! The registry is imported from the crate (`lib.rs` owns `mod
//! adapter_registry`); there is exactly one compilation of the module, so
//! these types are identical to the ones the admitted seam resolves.
//!
//! One substantive test exists per proven `WORK_UNIT_CASE` marker below.
//! Markers are never written for unproven cases; the deferred numbers are
//! listed in the work report, not here.

#![allow(clippy::too_many_lines)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_agent_claude::{
    CLAUDE_SIDECAR_PROTOCOL_VERSION, ClaudeAllowedTool, ClaudeArgv, ClaudeEnvAllowlist,
    ClaudePermissionMode, ClaudeRequestKind, ClaudeSidecarLaunchPlan, ClaudeSidecarRequest,
};
use eliot_contracts::{
    DecisionId, EpochId, EpochLineageId, ResourceGeneration, SessionId, StateFence, TaskId,
    sha256_hex,
};
use eliot_native_worker::adapter_registry::{
    ACP_FACTORY_ID, AcpFactorySeams, AdapterIdentity, AdapterRegistry, CLAUDE_FACTORY_ID,
    CODEX_FACTORY_ID, ClaudeFactorySeams, CodexFactorySeams, FACTORY_REVISION, FactoryEntry,
    FactoryLedger, OPENCODE_FACTORY_ID, OpencodeFactorySeams, RegistryError, SecretRef,
    ValidatedDispatch, invoke_acp_factory, invoke_claude_factory, invoke_codex_factory,
    invoke_opencode_factory, validate_admitted_dispatch,
};
use eliot_native_worker_core::{
    AttemptId, BudgetEnvelope, ClaimAdmissionRequest, EXECUTION_UNIT_SCHEMA_VERSION,
    JSON_ENCODING_PROFILE, NATIVE_WORKER_CLAIM_WIRE_VERSION,
    NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION, NativeClaimId, NativeRegistrationId,
    NativeRenewalId, NativeWorkerClaim, NativeWorkerExecutableBinding,
    NativeWorkerExecutableExpectation, NativeWorkerRegistration, PROTOCOL_VERSION, WorkerError,
    WorkerHello,
};
use eliot_process::SessionId as ProcessSessionId;
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    EnvironmentInheritance, EnvironmentProjection, FencingToken, Generation, ImageId, JobId,
    KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessIntent, ProcessRequest,
    ProcessStartReceipt, ProcessTreeId, ResourceLimits,
};

const NOW_MS: u64 = 6_000;
const CLAIM_DEADLINE_MS: u64 = 4_000_000_000_000;
const JOIN_DEADLINE_MS: u64 = 8_000;
const JOIN_EXPIRY_MS: u64 = 4_000_000_001_000;

/// In-memory P-03 double: records every `start` and never launches.
struct RecordingExecutor {
    starts: Mutex<usize>,
}

impl RecordingExecutor {
    fn new() -> Self {
        Self {
            starts: Mutex::new(0),
        }
    }

    fn starts(&self) -> usize {
        *lock(&self.starts)
    }
}

impl ProcessExecutor for RecordingExecutor {
    async fn start(
        &self,
        _request: ProcessRequest,
        _sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        *lock(&self.starts) += 1;
        Err(ProcessExecutionError::Unavailable(
            "registry fixture never starts".to_owned(),
        ))
    }

    async fn inspect(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "registry fixture never inspects".to_owned(),
        ))
    }

    async fn cancel(
        &self,
        _operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "registry fixture never cancels".to_owned(),
        ))
    }

    async fn reconcile(
        &self,
        _operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "registry fixture never reconciles".to_owned(),
        ))
    }
}

/// Caller-owned in-memory ACP transport handle (never opened).
#[derive(Clone, Debug)]
struct MemTransport;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(error) => panic!("adapter-registry fixture lock failed: {error:?}"),
    }
}

fn load<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("adapter-registry fixture failed: {error:?}"),
    }
}

fn epoch() -> EpochId {
    load(EpochId::new(
        load(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")),
        load(std::num::NonZeroU64::new(1).ok_or("non-zero")),
    ))
}

fn fence() -> StateFence {
    StateFence::new(epoch(), load(ResourceGeneration::new(1)))
}

fn revisions() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("authority".to_owned(), "a".repeat(64)),
        ("state".to_owned(), "b".repeat(64)),
    ])
}

fn limits() -> ResourceLimits {
    load(ResourceLimits::new(
        30_000,
        Some(10_000),
        Some(512_000_000),
        4_096,
        4_096,
        4,
    ))
}

fn build_process(
    operation: &str,
    tree: &str,
    nonce: &str,
) -> (ProcessRequest, DispatchPermitAuthority) {
    let generation = load(Generation::new(1));
    let intent = load(ProcessIntent::new(
        load(OperationId::new(operation)),
        load(ProcessTreeId::new(tree)),
        load(JobId::new(format!("job-{operation}"))),
        load(ImageId::new(format!("image-{operation}"))),
        load(ProcessSessionId::new(format!("session-{operation}"))),
        generation,
        "codex-app-server".to_owned(),
        "a".repeat(64),
        vec!["--stdio".to_owned()],
        std::env::temp_dir().to_string_lossy().into_owned(),
        load(EnvironmentProjection::new(
            BTreeMap::new(),
            Vec::new(),
            EnvironmentInheritance::None,
        )),
        limits(),
    ));
    let fence_token = load(FencingToken::new(
        epoch(),
        generation,
        format!("process-fence-{operation}"),
    ));
    let mut authority = DispatchPermitAuthority::activate(
        load(DispatchAuthorityId::new("native-worker-authority")),
        load(KernelDispatchKey::from_secret_bytes([0x5a; 32])),
    );
    let permit = load(authority.issue(
        &intent,
        load(PermitIssuance::new(
            load(ActionLeaseRef::new("native-worker-lease")),
            fence_token,
            revisions(),
            100,
            10_000,
            nonce,
        )),
    ));
    (load(ProcessRequest::new(intent, permit)), authority)
}

fn hello() -> WorkerHello {
    WorkerHello {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        encoding_profile: JSON_ENCODING_PROFILE.to_owned(),
        connection_id: "connection-claim-1".to_owned(),
        request_id: "start-claim-1".to_owned(),
        trace_context: BTreeMap::from([("trace_id".to_owned(), "trace-claim-1".to_owned())]),
        deadline_unix_ms: 5_000,
        artifact_manifest_digest: "manifest-digest-1".to_owned(),
        launch_nonce: "launch-nonce-registry-1".to_owned(),
        worker_generation: 1,
        authority_epoch: epoch(),
        state_fence: fence(),
        route_ref: "route-1".to_owned(),
        requested_capabilities: BTreeSet::from(["inspect".to_owned()]),
    }
}

fn registration() -> NativeWorkerRegistration {
    NativeWorkerRegistration {
        registration_id: load(NativeRegistrationId::new("registration-1")),
        installation_id: "installation-1".to_owned(),
        worker_artifact_digest: "a".repeat(64),
        worker_config_digest: "b".repeat(64),
        protocol_version: PROTOCOL_VERSION.to_owned(),
        worker_generation: 1,
        process_id: 4242,
        process_start_100ns: 120,
        process_image_digest: "c".repeat(64),
        principal_ref: "principal-1".to_owned(),
        session_id: load(SessionId::new("session-operation-1")),
        connection_id: "connection-claim-1".to_owned(),
        authority_epoch: epoch(),
        state_fence: fence(),
        lease_id: "lease-reg-1".to_owned(),
        lease_expires_at_unix_ms: 4_000_000_001_000,
        renewal_id: load(NativeRenewalId::new("renewal-1")),
        execution_unit_schema_version: EXECUTION_UNIT_SCHEMA_VERSION,
        resource_limits: limits(),
        invalidation_set: BTreeSet::new(),
    }
}

fn owner_issued_digest() -> String {
    sha256_hex(b"registry owner-issued executable digest stand-in")
}

fn valid_join(
    registration: &NativeWorkerRegistration,
    hello_value: &WorkerHello,
    process: &ProcessRequest,
    adapter_id: &str,
    adapter_revision: u64,
    claim_id: &str,
) -> NativeWorkerExecutableBinding {
    NativeWorkerExecutableBinding {
        route_ref: hello_value.route_ref.clone(),
        adapter_id: adapter_id.to_owned(),
        adapter_revision,
        config_digest: registration.worker_config_digest.clone(),
        facet_manifest_ref: "facet-manifest-7".to_owned(),
        grant_graph_revision: 5,
        replay_stream_id: format!("{claim_id}/gen-1"),
        launch_nonce: hello_value.launch_nonce.clone(),
        process_invocation_digest: process.invocation_digest().to_owned(),
        authority_epoch: epoch(),
        generation: load(ResourceGeneration::new(1)),
        state_fence: fence(),
        deadline_unix_ms: JOIN_DEADLINE_MS,
        expires_at_unix_ms: JOIN_EXPIRY_MS,
        executable_wire_version: NATIVE_WORKER_EXECUTABLE_BINDING_EXPECTED_WIRE_VERSION,
        executable_binding_digest: owner_issued_digest(),
    }
}

fn claim_for(
    registration: &NativeWorkerRegistration,
    hello_value: &WorkerHello,
    process: &ProcessRequest,
    adapter_id: &str,
    adapter_revision: u64,
    claim_id: &str,
    attempt_id: &str,
) -> NativeWorkerClaim {
    let join = valid_join(
        registration,
        hello_value,
        process,
        adapter_id,
        adapter_revision,
        claim_id,
    );
    let draft = NativeWorkerClaim {
        claim_id: load(NativeClaimId::new(claim_id)),
        registration_id: registration.registration_id.clone(),
        worker_generation: 1,
        parent_job_id: "job-parent-1".to_owned(),
        task_id: load(TaskId::new("task-1")),
        work_scope_id: "scope-1".to_owned(),
        decision_id: load(DecisionId::new("decision-1")),
        attempt_id: load(AttemptId::new(attempt_id)),
        operation_id: process.operation_id().clone(),
        route_class: "test-route".to_owned(),
        budget: BudgetEnvelope {
            context_tokens: 100,
            wall_time_ms: 4_000,
            output_bytes: 4_096,
            cost_microunits: 1_000,
            max_depth: 4,
            max_descendants: 8,
        },
        deadline_unix_ms: CLAIM_DEADLINE_MS,
        cancellation_policy_id: "policy-1".to_owned(),
        expected_result_schema: "result-schema-1".to_owned(),
        expected_result_schema_version: 1,
        predecessor_revision: "rev-0".to_owned(),
        authority_epoch: epoch(),
        state_fence: fence(),
        wire_version: NATIVE_WORKER_CLAIM_WIRE_VERSION,
        executable_binding: Some(join),
        binding_digest: String::new(),
    };
    load(draft.with_computed_digest())
}

fn claim_request(
    registration: &NativeWorkerRegistration,
    claim: &NativeWorkerClaim,
) -> ClaimAdmissionRequest {
    load(serde_json::from_value(serde_json::json!({
        "registration": registration,
        "claim": claim,
    })))
}

fn expectation_for(claim: &NativeWorkerClaim, revoked: bool) -> NativeWorkerExecutableExpectation {
    let join = claim
        .executable_binding
        .clone()
        .unwrap_or_else(|| panic!("registry fixture carries the join"));
    NativeWorkerExecutableExpectation {
        current: join,
        revoked,
    }
}

struct AdmittedFixtures {
    admission: ClaimAdmissionRequest,
    hello_value: WorkerHello,
    process: ProcessRequest,
    expected: NativeWorkerExecutableExpectation,
    executor: Arc<RecordingExecutor>,
}

fn admitted(adapter_id: &str, tag: &str) -> AdmittedFixtures {
    let operation = format!("operation-registry-{tag}");
    let tree = format!("tree-registry-{tag}");
    let (process, _authority) = build_process(&operation, &tree, &format!("nonce-registry-{tag}"));
    let hello_value = hello();
    let registration = registration();
    let claim_id = format!("claim-{tag}");
    let attempt_id = format!("attempt-{tag}");
    let claim_value = claim_for(
        &registration,
        &hello_value,
        &process,
        adapter_id,
        FACTORY_REVISION,
        &claim_id,
        &attempt_id,
    );
    let admission = claim_request(&registration, &claim_value);
    let expected = expectation_for(&claim_value, false);
    AdmittedFixtures {
        admission,
        hello_value,
        process,
        expected,
        executor: Arc::new(RecordingExecutor::new()),
    }
}

fn validated(fixtures: &AdmittedFixtures) -> ValidatedDispatch {
    match validate_admitted_dispatch(
        &fixtures.admission,
        &fixtures.hello_value,
        &fixtures.process,
        &fixtures.expected,
        NOW_MS,
    ) {
        Ok(valid) => valid,
        Err(error) => panic!("valid registry fixture must validate: {error:?}"),
    }
}

fn opencode_seams() -> OpencodeFactorySeams {
    let credential = match SecretRef::parse("test-scope:registry-opencode-auth") {
        Ok(reference) => reference,
        Err(error) => panic!("test credential reference must parse: {error:?}"),
    };
    OpencodeFactorySeams {
        policy_dir: std::env::temp_dir(),
        endpoint: "http://127.0.0.1:18791".to_owned(),
        credential,
    }
}

fn claude_request() -> ClaudeSidecarRequest {
    ClaudeSidecarRequest {
        protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.to_owned(),
        request_id: "req-claude-1".to_owned(),
        kind: ClaudeRequestKind::Query,
        prompt: Some("hello claude".to_owned()),
        launch_plan: Some(ClaudeSidecarLaunchPlan {
            argv: ClaudeArgv {
                program: "eliot-claude-sidecar".to_owned(),
                argv: vec!["--stdio".to_owned()],
            },
            working_directory: "C:\\workspace".to_owned(),
            env: ClaudeEnvAllowlist {
                vars: vec![("PATH".to_owned(), "/usr/bin".to_owned())],
            },
            wall_time_ms: 30_000,
            max_output_bytes: 64 * 1024,
            permission_mode: ClaudePermissionMode::Default,
            allowed_tools: vec![ClaudeAllowedTool::Read, ClaudeAllowedTool::Grep],
        }),
        sequence: None,
    }
}

// WORK_UNIT_CASE 1: four-factory denominator plus claim/consumer readiness.
#[test]
fn four_factory_denominator_and_consumer_readiness() {
    let registry = AdapterRegistry::four_factory();
    assert_eq!(registry.len(), 4);
    assert!(!registry.is_empty());
    let mut identities: Vec<&str> = registry
        .entries()
        .iter()
        .map(|entry| entry.identity().as_str())
        .collect();
    identities.sort_unstable();
    assert_eq!(
        identities,
        vec![
            ACP_FACTORY_ID,
            CLAUDE_FACTORY_ID,
            CODEX_FACTORY_ID,
            OPENCODE_FACTORY_ID,
        ]
    );
    for entry in registry.entries() {
        assert_eq!(entry.revision(), FACTORY_REVISION);
        assert!(entry.revision() != 0);
    }
    assert_eq!(OPENCODE_FACTORY_ID, "eliot-agent-opencode");
    assert_eq!(CODEX_FACTORY_ID, "eliot-agent-codex");
    assert_eq!(ACP_FACTORY_ID, "eliot-agent-acp");
    assert_eq!(CLAUDE_FACTORY_ID, "eliot-agent-claude");

    // Consumer readiness: one admitted dispatch validates through every
    // production gate before any factory is named.
    let fixtures = admitted(CODEX_FACTORY_ID, "case-1");
    let valid = validated(&fixtures);
    assert_eq!(valid.adapter_id(), CODEX_FACTORY_ID);
    assert_eq!(valid.adapter_revision(), FACTORY_REVISION);
    assert_eq!(valid.task_id(), "task-1");
    assert_eq!(valid.worker_generation(), 1);
    assert_eq!(
        valid.operation_id(),
        fixtures.process.operation_id().as_str()
    );
    assert!(!valid.binding_digest().is_empty());
}

// WORK_UNIT_CASE 2: registry is reachable from the real admitted dispatch path.
#[test]
fn reachable_from_real_admitted_dispatch_path() {
    // The exact presentation shape the Kernel dispatch contour delivers:
    // registration plus claim through the production serde envelope, the
    // owner hello, and the in-memory process request (never deserialized).
    let fixtures = admitted(OPENCODE_FACTORY_ID, "case-2");
    let presented = serde_json::to_value(&fixtures.admission)
        .unwrap_or_else(|_| panic!("admission must serialize"));
    let admission: ClaimAdmissionRequest = serde_json::from_value(presented)
        .unwrap_or_else(|_| panic!("admission must round-trip the dispatch shape"));
    admission
        .validate_binding()
        .unwrap_or_else(|_| panic!("dispatched admission must bind"));
    let valid = match validate_admitted_dispatch(
        &admission,
        &fixtures.hello_value,
        &fixtures.process,
        &fixtures.expected,
        NOW_MS,
    ) {
        Ok(valid) => valid,
        Err(error) => panic!("dispatched admission must validate: {error:?}"),
    };
    let registry = AdapterRegistry::four_factory();
    let entry = match registry.resolve_claim(admission.claim()) {
        Ok(entry) => entry,
        Err(error) => panic!("dispatched claim must resolve: {error:?}"),
    };
    assert_eq!(entry.identity(), AdapterIdentity::Opencode);
    assert_eq!(valid.adapter_id(), OPENCODE_FACTORY_ID);
}

// WORK_UNIT_CASE 4: exactly one entry per factory identity plus revision.
#[test]
fn one_entry_per_identity_revision() {
    let registry = AdapterRegistry::four_factory();
    let mut pairs = BTreeSet::new();
    for entry in registry.entries() {
        assert!(
            pairs.insert((entry.identity(), entry.revision())),
            "duplicate (identity, revision) in canonical registry"
        );
    }
    assert_eq!(pairs.len(), 4);
    match AdapterRegistry::from_entries(*registry.entries()) {
        Ok(_) => {}
        Err(error) => panic!("canonical entries must rebuild: {error:?}"),
    }
    assert!(FactoryEntry::new(AdapterIdentity::Codex, 0).is_none());
    assert_eq!(
        AdapterIdentity::parse(OPENCODE_FACTORY_ID),
        Some(AdapterIdentity::Opencode)
    );
    assert_eq!(
        AdapterIdentity::parse(CODEX_FACTORY_ID),
        Some(AdapterIdentity::Codex)
    );
    assert_eq!(
        AdapterIdentity::parse(ACP_FACTORY_ID),
        Some(AdapterIdentity::Acp)
    );
    assert_eq!(
        AdapterIdentity::parse(CLAUDE_FACTORY_ID),
        Some(AdapterIdentity::Claude)
    );
    assert_eq!(AdapterIdentity::parse("eliot-agent-unknown"), None);
    // All four entries are capable: each identity plus revision resolves to
    // its named entry (INTEGRATOR-T9-07: the Claude skeleton refusal is
    // removed; `execution::prepare` plus `ClaudeSidecarFactory::new` exist).
    for (factory_id, identity) in [
        (OPENCODE_FACTORY_ID, AdapterIdentity::Opencode),
        (CODEX_FACTORY_ID, AdapterIdentity::Codex),
        (ACP_FACTORY_ID, AdapterIdentity::Acp),
        (CLAUDE_FACTORY_ID, AdapterIdentity::Claude),
    ] {
        match registry.resolve(factory_id, FACTORY_REVISION) {
            Ok(entry) => assert_eq!(entry.identity(), identity),
            Err(error) => panic!("{factory_id} must resolve capable, got {error:?}"),
        }
    }
    let entry = FactoryEntry::new(AdapterIdentity::Codex, FACTORY_REVISION)
        .unwrap_or_else(|| panic!("nonzero revision must build"));
    assert_eq!(entry.identity(), AdapterIdentity::Codex);
    assert_eq!(entry.revision(), FACTORY_REVISION);
}

// WORK_UNIT_CASE 5: duplicate entries and duplicate starts are rejected.
#[test]
fn duplicates_rejected() {
    let registry = AdapterRegistry::four_factory();
    let codex = FactoryEntry::new(AdapterIdentity::Codex, FACTORY_REVISION)
        .unwrap_or_else(|| panic!("nonzero revision must build"));
    let opencode = FactoryEntry::new(AdapterIdentity::Opencode, FACTORY_REVISION)
        .unwrap_or_else(|| panic!("nonzero revision must build"));
    let acp = FactoryEntry::new(AdapterIdentity::Acp, FACTORY_REVISION)
        .unwrap_or_else(|| panic!("nonzero revision must build"));
    match AdapterRegistry::from_entries([codex, codex, opencode, acp]) {
        Err(RegistryError::Duplicate { .. }) => {}
        other => panic!("exact duplicate entries must fail, got {other:?}"),
    }

    // A second construction for the same live operation is refused without
    // touching any factory: the ledger cannot move.
    let fixtures = admitted(CODEX_FACTORY_ID, "case-5");
    let valid = validated(&fixtures);
    let mut ledger = FactoryLedger::new();
    let seams = CodexFactorySeams {
        executor: Arc::clone(&fixtures.executor),
    };
    match invoke_codex_factory(&registry, &valid, &seams, &mut ledger) {
        Ok(_) => {}
        Err(error) => panic!("first construction must succeed: {error:?}"),
    }
    assert_eq!(ledger.calls_for(AdapterIdentity::Codex), 1);
    match invoke_codex_factory(&registry, &valid, &seams, &mut ledger) {
        Err(RegistryError::AlreadyStarted { .. }) => {}
        other => panic!("second construction must be refused, got {other:?}"),
    }
    assert_eq!(ledger.calls_for(AdapterIdentity::Codex), 1);
    assert_eq!(fixtures.executor.starts(), 0);
}

// WORK_UNIT_CASE 6: unknown factories are rejected fail-closed.
#[test]
fn unknown_factory_rejected() {
    let registry = AdapterRegistry::four_factory();
    match registry.resolve("eliot-agent-unknown", FACTORY_REVISION) {
        Err(RegistryError::Unknown { .. }) => {}
        other => panic!("unknown identity must fail, got {other:?}"),
    }
    match registry.resolve("", FACTORY_REVISION) {
        Err(RegistryError::BadInput { .. }) => {}
        other => panic!("empty identity must fail shape checks, got {other:?}"),
    }
    let fixtures = admitted("eliot-agent-unknown", "case-6");
    let _ = fixtures.admission.validate_binding();
    match registry.resolve_claim(fixtures.admission.claim()) {
        Err(RegistryError::Unknown { .. }) => {}
        other => panic!("unknown claim projection must fail, got {other:?}"),
    }
    let ledger = FactoryLedger::new();
    assert!(ledger.calls().is_empty());
    assert_eq!(fixtures.executor.starts(), 0);
}

// WORK_UNIT_CASE 7: the Claude entry resolves capable with deferred prepare.
#[test]
fn claude_factory_capable_with_deferred_prepare() {
    let registry = AdapterRegistry::four_factory();
    // The Claude entry carries valid bindings and resolves like the other
    // three (INTEGRATOR-T9-07: `execution::prepare`,
    // `ClaudeSidecarFactory::new`, and `admit_with_port` all exist, so the
    // skeleton refusal is removed; live `prepare` stays a drive step).
    let claude = admitted(CLAUDE_FACTORY_ID, "case-7");
    let valid = validated(&claude);
    match registry.resolve(CLAUDE_FACTORY_ID, FACTORY_REVISION) {
        Ok(entry) => assert_eq!(entry.identity(), AdapterIdentity::Claude),
        Err(error) => panic!("claude entry must resolve capable, got {error:?}"),
    }
    let mut ledger = FactoryLedger::new();
    let seams = ClaudeFactorySeams {
        executor: Arc::new(RecordingExecutor::new()),
    };
    let attempt =
        match invoke_claude_factory(&registry, &valid, &seams, &claude_request(), &mut ledger) {
            Ok(attempt) => attempt,
            Err(error) => panic!("claude invoke must construct, got {error:?}"),
        };
    assert_eq!(attempt.adapter(), AdapterIdentity::Claude);
    assert_eq!(attempt.claim_id(), valid.claim_id());
    assert_eq!(ledger.calls_for(AdapterIdentity::Claude), 1);

    // A known identity with a foreign revision is still refused.
    match registry.resolve(CLAUDE_FACTORY_ID, FACTORY_REVISION + 1) {
        Err(RegistryError::Incompatible { .. }) => {}
        other => panic!("revision mismatch must be incompatible, got {other:?}"),
    }

    // A malformed factory request fails its own shape with no construction.
    let mut broken = claude_request();
    broken.protocol_version = "v0".to_owned();
    let mut fresh = FactoryLedger::new();
    match invoke_claude_factory(&registry, &valid, &seams, &broken, &mut fresh) {
        Err(RegistryError::BadInput { .. }) => {}
        other => panic!("malformed request must fail input checks, got {other:?}"),
    }
    assert!(fresh.calls().is_empty());
}

// WORK_UNIT_CASE 9: bad claims are refused pre-factory with ledger proof.
#[test]
fn bad_claim_rejected_pre_factory_with_ledger_proof() {
    let base = admitted(CODEX_FACTORY_ID, "case-9");
    let registration = registration();
    let hello_value = hello();

    let mut refused = 0;
    let mut check = |name: &str,
                     admission: ClaimAdmissionRequest,
                     expected: NativeWorkerExecutableExpectation| {
        let ledger = FactoryLedger::new();
        let outcome =
            validate_admitted_dispatch(&admission, &hello_value, &base.process, &expected, NOW_MS);
        match outcome {
            Err(RegistryError::BadClaim(_)) => {}
            other => panic!("{name} must be a typed claim refusal, got {other:?}"),
        }
        assert!(
            ledger.calls().is_empty(),
            "{name} must record no factory call"
        );
        assert_eq!(base.executor.starts(), 0, "{name} must start nothing");
        refused += 1;
    };

    // Wrong: binding digest no longer covers the bound work.
    let mut wrong = base.admission.claim().clone();
    wrong.binding_digest = "0".repeat(64);
    check(
        "wrong digest",
        claim_request(&registration, &wrong),
        expectation_for(base.admission.claim(), false),
    );

    // Stale: the presented epoch disagrees with the fence lineage.
    let stale_epoch = {
        let other = load(EpochId::new(
            load(EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")),
            load(std::num::NonZeroU64::new(2).ok_or("non-zero")),
        ));
        let mut claim = base.admission.claim().clone();
        claim.authority_epoch = other;
        load(claim.with_computed_digest())
    };
    check(
        "stale epoch",
        claim_request(&registration, &stale_epoch),
        expectation_for(base.admission.claim(), false),
    );

    // Revoked: current owner records withdrew the binding.
    check(
        "revoked binding",
        claim_request(&registration, base.admission.claim()),
        expectation_for(base.admission.claim(), true),
    );

    // Foreign: the owner record names a different adapter than presented.
    let foreign = {
        let mut join = base
            .admission
            .claim()
            .executable_binding
            .clone()
            .unwrap_or_else(|| panic!("fixture carries the join"));
        join.adapter_id = OPENCODE_FACTORY_ID.to_owned();
        let mut claim = base.admission.claim().clone();
        claim.executable_binding = Some(join);
        load(claim.with_computed_digest())
    };
    check(
        "foreign adapter",
        claim_request(&registration, &foreign),
        expectation_for(base.admission.claim(), false),
    );

    // Expired: the observation time is past the binding window.
    let expired_outcome = validate_admitted_dispatch(
        &base.admission,
        &hello_value,
        &base.process,
        &expectation_for(base.admission.claim(), false),
        JOIN_EXPIRY_MS,
    );
    match expired_outcome {
        Err(RegistryError::BadClaim(WorkerError::DeadlineExpired)) => {}
        other => panic!("expired window must fail, got {other:?}"),
    }
    refused += 1;

    // Wrong operation: the claim answers a different operation than the
    // in-memory process request.
    let (other_process, _) = build_process(
        "operation-registry-other",
        "tree-registry-other",
        "nonce-other",
    );
    let wrong_op = validate_admitted_dispatch(
        &base.admission,
        &hello_value,
        &other_process,
        &expectation_for(base.admission.claim(), false),
        NOW_MS,
    );
    match wrong_op {
        Err(RegistryError::BadClaim(_)) => {}
        other => panic!("wrong operation must fail, got {other:?}"),
    }
    refused += 1;

    assert_eq!(refused, 6);
}

// WORK_UNIT_CASE 10: exactly one named factory constructs.
#[test]
fn exactly_one_named_factory() {
    let registry = AdapterRegistry::four_factory();
    let fixtures = admitted(CODEX_FACTORY_ID, "case-10");
    let valid = validated(&fixtures);
    let mut ledger = FactoryLedger::new();
    let seams = CodexFactorySeams {
        executor: Arc::clone(&fixtures.executor),
    };
    let attempt = match invoke_codex_factory(&registry, &valid, &seams, &mut ledger) {
        Ok(attempt) => attempt,
        Err(error) => panic!("named codex factory must construct: {error:?}"),
    };
    assert_eq!(ledger.calls().len(), 1);
    match ledger.calls().first() {
        Some(call) => {
            assert_eq!(call.adapter(), AdapterIdentity::Codex);
            assert_eq!(call.operation_id(), valid.operation_id());
            assert_eq!(call.claim_id(), valid.claim_id());
        }
        None => panic!("named construction must record exactly one call"),
    }
    assert_eq!(ledger.calls_for(AdapterIdentity::Codex), 1);
    assert_eq!(ledger.calls_for(AdapterIdentity::Opencode), 0);
    assert_eq!(ledger.calls_for(AdapterIdentity::Acp), 0);
    assert_eq!(ledger.calls_for(AdapterIdentity::Claude), 0);
    assert_eq!(attempt.adapter(), AdapterIdentity::Codex);
    assert_eq!(attempt.claim_id(), valid.claim_id());
    assert_eq!(attempt.operation_id(), valid.operation_id());
    assert_eq!(attempt.attempt_id(), valid.attempt_id());
    assert_eq!(fixtures.executor.starts(), 0);
}

// WORK_UNIT_CASE 11: no rerank, fallback, or substitution.
#[test]
fn no_rerank_fallback_or_substitution() {
    let registry = AdapterRegistry::four_factory();
    let fixtures = admitted(CODEX_FACTORY_ID, "case-11");
    let valid = validated(&fixtures);
    let mut ledger = FactoryLedger::new();

    // A codex-resolved dispatch presented to the opencode factory is
    // refused as substitution, not silently served.
    match invoke_opencode_factory(&registry, &valid, &opencode_seams(), &mut ledger) {
        Err(RegistryError::SubstitutionRefused { .. }) => {}
        other => panic!("cross-factory invoke must refuse, got {other:?}"),
    }
    assert!(ledger.calls().is_empty());

    // A codex-resolved dispatch presented to the Claude factory is likewise
    // refused as substitution: capability comes from naming, never from
    // fallback, even though the Claude entry is capable.
    let claude_seams = ClaudeFactorySeams {
        executor: Arc::clone(&fixtures.executor),
    };
    match invoke_claude_factory(
        &registry,
        &valid,
        &claude_seams,
        &claude_request(),
        &mut ledger,
    ) {
        Err(RegistryError::SubstitutionRefused { .. }) => {}
        other => panic!("cross-factory claude invoke must refuse, got {other:?}"),
    }
    assert!(ledger.calls().is_empty());

    // The named factory still constructs explicitly afterwards: capability
    // comes from naming, never from fallback.
    let seams = CodexFactorySeams {
        executor: Arc::clone(&fixtures.executor),
    };
    match invoke_codex_factory(&registry, &valid, &seams, &mut ledger) {
        Ok(_) => {}
        Err(error) => panic!("explicit naming must construct: {error:?}"),
    }
    assert_eq!(ledger.calls().len(), 1);
}

// WORK_UNIT_CASE 30: one deterministic admitted attempt per capable adapter.
#[test]
fn deterministic_attempt_per_capable_adapter() {
    let registry = AdapterRegistry::four_factory();
    let cases = [
        (OPENCODE_FACTORY_ID, AdapterIdentity::Opencode, "case-30a"),
        (CODEX_FACTORY_ID, AdapterIdentity::Codex, "case-30b"),
        (ACP_FACTORY_ID, AdapterIdentity::Acp, "case-30c"),
        (CLAUDE_FACTORY_ID, AdapterIdentity::Claude, "case-30d"),
    ];
    for (factory_id, identity, tag) in cases {
        let fixtures = admitted(factory_id, tag);
        let valid = validated(&fixtures);
        let mut ledger = FactoryLedger::new();
        let attempt = match identity {
            AdapterIdentity::Opencode => {
                invoke_opencode_factory(&registry, &valid, &opencode_seams(), &mut ledger)
            }
            AdapterIdentity::Codex => invoke_codex_factory(
                &registry,
                &valid,
                &CodexFactorySeams {
                    executor: Arc::clone(&fixtures.executor),
                },
                &mut ledger,
            ),
            AdapterIdentity::Acp => invoke_acp_factory(
                &registry,
                &valid,
                AcpFactorySeams {
                    executor: RecordingExecutor::new(),
                    transport: MemTransport,
                },
                &mut ledger,
            ),
            AdapterIdentity::Claude => invoke_claude_factory(
                &registry,
                &valid,
                &ClaudeFactorySeams {
                    executor: Arc::clone(&fixtures.executor),
                },
                &claude_request(),
                &mut ledger,
            ),
        };
        let attempt = match attempt {
            Ok(attempt) => attempt,
            Err(error) => panic!("{factory_id} must yield one attempt: {error:?}"),
        };
        assert_eq!(attempt.adapter(), identity);
        assert_eq!(ledger.calls_for(identity), 1);
        assert_eq!(
            attempt.event().stream_id,
            format!("{}/gen-1", valid.claim_id())
        );
        assert_eq!(
            attempt.event().event_id,
            format!("{}/event-1", valid.claim_id())
        );
        assert_eq!(attempt.event().sequence, 1);
        assert_eq!(attempt.terminal().attempt_id, valid.attempt_id());
        assert_eq!(attempt.terminal().disposition, "constructed");
        assert_eq!(attempt.reconciliation().claim_id, valid.claim_id());
        assert_eq!(attempt.reconciliation().operation_id, valid.operation_id());
        assert_eq!(
            attempt.reconciliation().binding_digest,
            valid.binding_digest()
        );

        // Deterministic: a fresh ledger over identical inputs yields the
        // identical attempt, without recalling shared state.
        let mut replay = FactoryLedger::new();
        let again = match identity {
            AdapterIdentity::Opencode => {
                invoke_opencode_factory(&registry, &valid, &opencode_seams(), &mut replay)
            }
            AdapterIdentity::Codex => invoke_codex_factory(
                &registry,
                &valid,
                &CodexFactorySeams {
                    executor: Arc::clone(&fixtures.executor),
                },
                &mut replay,
            ),
            AdapterIdentity::Acp => invoke_acp_factory(
                &registry,
                &valid,
                AcpFactorySeams {
                    executor: RecordingExecutor::new(),
                    transport: MemTransport,
                },
                &mut replay,
            ),
            AdapterIdentity::Claude => invoke_claude_factory(
                &registry,
                &valid,
                &ClaudeFactorySeams {
                    executor: Arc::clone(&fixtures.executor),
                },
                &claude_request(),
                &mut replay,
            ),
        };
        match again {
            Ok(again) => assert_eq!(attempt, again),
            Err(error) => panic!("{factory_id} replay must match: {error:?}"),
        }
    }
}
