//! Canonical Store and pure SCIP stage proof for #1814.
//!
//! Documentation route receipt: `sha256:8bb9d71effb859a54d12949dd75ef2509e2d9daa3439d84da3cf3168c3aa13cd`;
//! read receipt: `sha256:be0f6f13b87d0103545c76b871b70bd449705e0f32b73e23e335e499406260b0`;
//! verified bundle SHA-256: `82af8d42e6cf9d52dd1d34c014c93d2364f31f588f74a4cc14998e1f8b55b520`.
//! Matched routes: `generic-source`, `host-kernel`, `canonical-storage`,
//! `agent-swarm`, `instrument-verification`, `human-surfaces`,
//! `security-privacy`, `workspace-governance`. The manager read all 123 required
//! items; this proof uses I10.8.4, canonical resource-snapshot read semantics,
//! storage ownership and the reading protocol. Relevant fragment identities:
//! `docs/architecture/I10-08-04-ip2-instrumentrunner.md`
//! (`b9a020dd270e278e5834a775186c0100c52ab85c35dd1e5e102bedb1e115b638`),
//! `crates/storage/AGENTS.md`
//! (`c77891d466c7622e5061430192459d8099304d57b27815b63776f023ae5b59f9`),
//! and `docs/architecture/READING_PROTOCOL.md`
//! (`253cca0f078acd49545baed814c9319d72659ef1e2428edf1ead789beaa4e1c3`).
//! I attest that I opened and read the verified bundle and these required
//! fragments before editing this routed path.
//!
//! This exercises the real Surreal adapter, canonical envelope preparation,
//! Store `apply_prepared`, exact-fence named read, and the live pure SCIP stage
//! consumer. Its authority-ledger JSON is an opaque Store test input; this
//! fixture does not mint Governor or Kernel authority. The no-process executor
//! panics if called. Provider files and temporary data stay under the #1814
//! worker scratch directory, and the fixture starts no production database or
//! user service.

#![cfg(windows)]
#![allow(
    clippy::expect_used,
    clippy::large_futures,
    clippy::print_stdout,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    RequestMetadata, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision,
};
use eliot_graph_api::{
    GraphQuery, GraphQueryKind, GraphQueryResult, GraphQueryStatus, GraphRevision,
};
use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind};
use eliot_instrument_runner::registry::InvalidationSet;
use eliot_instrument_runner::{
    BUILTIN_PROFILE_REVISION, CanonicalRegistryProofPort, InstrumentRegistry,
    InstrumentRequestPort, InstrumentRunner, PlannedStage, ProfileCompiler, ProviderRegistry,
    PureTransformInput, RunnerError, StageEvidence, StageLauncher, StageOrchestrator,
};
use eliot_instrument_scip::SCIP_INSTRUMENT;
use eliot_platform_windows::WindowsPlatform;
use eliot_process::{
    CancellationReceipt, OperationId as ProcessOperationId, ProcessEvidence, ProcessEvidenceSink,
    ProcessExecutionError, ProcessExecutionView, ProcessExecutor, ProcessRequest,
    ProcessStartReceipt,
};
use eliot_store_api::{
    CanonicalStoreClient, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedReadOperation, NamedReadRequest, ReadConsistency, ScopeId,
    SecurityContext, TransitionClass, WriteReceipt, WriteReceiptStatus,
    generated_operation_manifests, operation_manifest_set_digest,
    resource_snapshot_mutation_request, resource_snapshot_read_request,
    supported_admission_contract_set_digest, validate_instrument_registry_registration_readback,
    validate_store_receipt_envelope,
};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use std::sync::Arc;

type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SCRATCH_PARENT: &str =
    r"C:\Development\Rust\projects\eliot-swarm\control-20260923-impl\v2\workers\CS1\scratch\1814";
const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const SCOPE: &str = "scope:instrument-registry-1814";
const TASK: &str = "task:instrument-registry-1814";
const SCIP_SNAPSHOT_URI: &str = "eliot://evidence/instrument-registry-1814-scip-index";
const MISSING_SNAPSHOT_URI: &str = "eliot://evidence/instrument-registry-1814-missing-index";

struct NoProcessExecutor;

#[allow(
    clippy::panic,
    reason = "the registered SCIP transform must never use ProcessExecutor"
)]
impl ProcessExecutor for NoProcessExecutor {
    async fn start(
        &self,
        _request: ProcessRequest,
        _sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        panic!("registered SCIP transform attempted a process start")
    }

    async fn inspect(
        &self,
        _operation_id: ProcessOperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        panic!("registered SCIP transform attempted process inspection")
    }

    async fn cancel(
        &self,
        _operation_id: ProcessOperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        panic!("registered SCIP transform attempted process cancellation")
    }

    async fn reconcile(
        &self,
        _operation_id: ProcessOperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        panic!("registered SCIP transform attempted process reconciliation")
    }
}

struct ScipInputLauncher {
    input: Option<PureTransformInput>,
}

#[allow(
    clippy::panic,
    reason = "the pure SCIP route must not request process provisions"
)]
impl StageLauncher for ScipInputLauncher {
    fn invocation(&self, _stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError> {
        panic!("registered SCIP transform requested a process invocation")
    }

    fn port(&self, _stage: &PlannedStage) -> &dyn InstrumentRequestPort {
        panic!("registered SCIP transform requested a process request port")
    }

    fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
        panic!("registered SCIP transform requested process evidence sink")
    }

    fn pure_input(&self, _stage: &PlannedStage) -> Result<PureTransformInput, RunnerError> {
        self.input.clone().ok_or_else(|| {
            RunnerError::Binding("no canonical resource snapshot was retained".to_owned())
        })
    }
}

fn protobuf_varint(encoded: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        encoded.push(u8::try_from(value & 0x7f).expect("masked protobuf byte") | 0x80);
        value >>= 7;
    }
    encoded.push(u8::try_from(value).expect("terminal protobuf byte"));
}

fn protobuf_bytes_field(field: u8, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 4);
    protobuf_varint(&mut encoded, (u64::from(field) << 3) | 2);
    protobuf_varint(
        &mut encoded,
        u64::try_from(value.len()).expect("fixture protobuf length fits u64"),
    );
    encoded.extend_from_slice(value);
    encoded
}

fn retained_scip_fixture() -> (Vec<u8>, GraphQuery, GraphRevision) {
    let symbol = protobuf_bytes_field(1, SCIP_INSTRUMENT.as_bytes());
    let occurrence = [
        protobuf_bytes_field(1, &[0, 0]),
        protobuf_bytes_field(2, SCIP_INSTRUMENT.as_bytes()),
    ]
    .concat();
    let document = [
        protobuf_bytes_field(1, b"crates/instrument/eliot-instrument-scip/src/lib.rs"),
        protobuf_bytes_field(3, &symbol),
        protobuf_bytes_field(4, &occurrence),
    ]
    .concat();
    let source_bytes = protobuf_bytes_field(2, &document);
    let graph_revision = GraphRevision::new(1).expect("nonzero fixture graph revision");
    (
        source_bytes,
        GraphQuery {
            query_id: RequestId::new("instrument-registry-owner-1814-scip-query")
                .expect("typed SCIP query identity"),
            kind: GraphQueryKind::Search,
            expression: SCIP_INSTRUMENT.to_owned(),
            scope: "workspace".to_owned(),
            root: None,
            expected_revision: Some(graph_revision),
        },
        graph_revision,
    )
}

struct Sandbox {
    parent: PathBuf,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> ProofResult<Self> {
        let parent = PathBuf::from(SCRATCH_PARENT);
        std::fs::create_dir_all(&parent)?;
        let canonical_parent = parent.canonicalize()?;
        let parent_text = canonical_parent.to_string_lossy();
        let parent = PathBuf::from(parent_text.strip_prefix(r"\\?\").unwrap_or(&parent_text));
        let root = parent.join(format!("instrument-registry-1814-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root)?;
        Ok(Self { parent, root })
    }

    fn cleanup(&self) -> ProofResult {
        if !self.root.exists() {
            return Ok(());
        }
        let resolved = self.root.canonicalize()?;
        if resolved.parent() != Some(self.parent.canonicalize()?.as_path()) {
            return Err("test root containment changed".into());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::fs::remove_dir_all(&resolved) {
                Ok(()) => return Ok(()),
                Err(error) if Instant::now() >= deadline => return Err(error.into()),
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Test-owned bootstrap process; every return or panic kills and reaps it.
struct Bootstrap(Child);

impl Drop for Bootstrap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn surreal_exe() -> PathBuf {
    std::env::var_os("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

fn config(
    exe: &Path,
    bind: String,
    data: &Path,
    work: &Path,
    temp: &Path,
) -> ProofResult<SurrealAdapterConfig> {
    let roots_digest = eliot_store_api::sha256_hex(&eliot_contracts::canonical_json_bytes(&(
        data.to_string_lossy(),
        work.to_string_lossy(),
        temp.to_string_lossy(),
    ))?);
    let mut value = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "eliot".to_owned(),
        database: "instrument_registry_1814".to_owned(),
        username: "instrument-registry-test".to_owned(),
        password: SecretString::new(
            format!("instrument-registry-fixture-{}", uuid::Uuid::new_v4()).into(),
        ),
        provider_bootstrap_username: "provider-bootstrap-fixture".to_owned(),
        provider_bootstrap_password: SecretString::new("provider-bootstrap-fixture-secret".into()),
        provider_bind_address: bind,
        installation_id: "instrument-registry-test".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: roots_digest,
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: eliot_store_api::sha256_hex(&std::fs::read(exe)?),
        provider_arguments: Vec::new(),
        store_data_root: data.to_string_lossy().into_owned(),
        store_work_root: work.to_string_lossy().into_owned(),
        store_temp_root: temp.to_string_lossy().into_owned(),
        connect_timeout_ms: 30_000,
        query_timeout_ms: 30_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    value.provider_arguments = value.expected_provider_arguments();
    value.validate()?;
    Ok(value)
}

fn bootstrap(config: &SurrealAdapterConfig) -> ProofResult {
    use std::os::windows::process::CommandExt;

    let system_root = std::env::var_os("SystemRoot").ok_or("SystemRoot absent")?;
    let mut process = Bootstrap(
        Command::new(&config.provider_executable_path)
            .args(&config.provider_arguments)
            .current_dir(&config.store_work_root)
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env("TEMP", &config.store_temp_root)
            .env("TMP", &config.store_temp_root)
            .env("SURREAL_USER", &config.username)
            .env("SURREAL_PASS", config.password.expose_secret())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(&config.provider_bind_address).is_err() {
        if process.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("isolated bootstrap provider did not become ready".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // The pinned provider setup commits the root user before normal operation.
    std::thread::sleep(Duration::from_secs(2));
    drop(process);
    while TcpStream::connect(&config.provider_bind_address).is_ok() {
        if Instant::now() >= deadline {
            return Err("bootstrap listener did not exit".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

struct Harness {
    sandbox: Sandbox,
    adapter: Option<Arc<SurrealStoreAdapter>>,
}

impl Harness {
    async fn fresh() -> ProofResult<Self> {
        let sandbox = Sandbox::new()?;
        let bin = sandbox.root.join("bin");
        let data = sandbox.root.join("data");
        let work = sandbox.root.join("work");
        let temp = sandbox.root.join("temp");
        for path in [&bin, &data, &work, &temp] {
            std::fs::create_dir(path)?;
        }
        let exe = bin.join("surreal.exe");
        std::fs::copy(surreal_exe(), &exe)?;
        let bind = TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string();
        let config = config(&exe, bind, &data, &work, &temp)?;
        println!(
            "instrument-registry-1814 provider: exe={} sha256={} bind={} root={}",
            config.provider_executable_path,
            config.provider_artifact_digest,
            config.provider_bind_address,
            sandbox.root.display()
        );
        bootstrap(&config)?;
        let platform = WindowsPlatform::new(sandbox.root.clone())?;
        let lease = platform.retain_process_path_lease(
            Path::new(&config.provider_executable_path),
            Path::new(&config.store_work_root),
            &config.provider_artifact_digest,
        )?;
        let adapter = SurrealStoreAdapter::new(config, lease)?;
        adapter
            .connect()
            .await
            .map_err(|error| format!("provider connect: {error}"))?;
        adapter
            .apply_migration(
                &SurrealStoreAdapter::v2_baseline_migration(),
                &ClockReading {
                    valid_time_ms: Some(1_000),
                    known_time_ms: Some(1_000),
                    transaction_sequence: None,
                    monotonic_ns: None,
                },
                &fence(false),
            )
            .await
            .map_err(|error| format!("baseline migration: {error}"))?;
        Ok(Self {
            sandbox,
            adapter: Some(Arc::new(adapter)),
        })
    }

    fn adapter(&self) -> &Arc<SurrealStoreAdapter> {
        self.adapter.as_ref().expect("adapter live")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        let _ = self.sandbox.cleanup();
    }
}

fn fence(task_bound: bool) -> StateFence {
    let mut state_fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero epoch"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    );
    if task_bound {
        state_fence.task_revision = Some(TaskRevision::genesis());
    }
    state_fence
}

fn registered_scip_registry() -> ProofResult<InstrumentRegistry> {
    let fingerprints = InvalidationSet {
        source: "source".to_owned(),
        lock: "lock".to_owned(),
        toolchain: "toolchain".to_owned(),
        env: "env".to_owned(),
        exe: "exe".to_owned(),
        profile: "profile".to_owned(),
        parser: "parser".to_owned(),
    };
    let providers = ProviderRegistry::ready(7, "normative".to_owned(), &fingerprints)?;
    let scip_id = ContractId::new(SCIP_INSTRUMENT.to_owned())?;
    let scip_entry = providers.resolve_parts(&scip_id, InstrumentKind::Inspect)?;
    Ok(InstrumentRegistry::with_registered_scip_profile(
        BUILTIN_PROFILE_REVISION,
        Vec::new(),
        scip_entry,
    )?)
}

fn registration_authority_json() -> ProofResult<String> {
    // The Store persists this opaque, versioned test ledger verbatim. The
    // fixture does not issue a Governor action lease or claim admission.
    Ok(serde_json::to_string(&json!({
        "schema": "eliot.governor.registration-authority-ledger",
        "version": 1,
        "grant_uses": [],
        "leases": [],
    }))?)
}

fn registry_command(
    snapshot_json: String,
    registration_authority_json: String,
    expected_registry_revision: u64,
) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyInstrumentRegistryState,
        parameters: BTreeMap::from([
            ("snapshot_json".to_owned(), Value::String(snapshot_json)),
            (
                "registration_authority_json".to_owned(),
                Value::String(registration_authority_json),
            ),
            (
                "expected_registry_revision".to_owned(),
                json!(expected_registry_revision),
            ),
        ]),
    }
}

fn envelope(
    operation: &str,
    task: Option<&str>,
    command: NamedMutationRequest,
) -> ProofResult<CanonicalWriteEnvelope> {
    let state_fence = fence(task.is_some());
    let operation_id = OperationId::new(operation)?;
    let request_id = RequestId::new(operation)?;
    let task_id = task.map(|value| TaskId::new(value)).transpose()?;
    let transition_class = command.operation.transition_class();
    let manifests = generated_operation_manifests()?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: RequestMetadata {
            request_id,
            session_id: None,
            task_id,
            product_id: ProductId::new("instrument-registry-store-fixture")?,
            source_id: SourceId::new("instrument-registry-store-fixture")?,
            state_fence: state_fence.clone(),
            clock: ClockReading::default(),
        },
        idempotency_key: operation.to_owned(),
        scope_id: ScopeId::new(SCOPE)?,
        task_id: task.map(str::to_owned),
        transition_class,
        requested_effect_ceiling: transition_class.maximum_effect(),
        admission_contract_set_digest: supported_admission_contract_set_digest()?,
        operation_manifest_digest: operation_manifest_set_digest(&manifests)?,
        semantic_commands: vec![command],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        // This Store-only fixture carries the original typed task binding in
        // the envelope. Task-proof issuance and admission remain Governor-owned.
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

async fn apply(
    adapter: &SurrealStoreAdapter,
    envelope: &CanonicalWriteEnvelope,
) -> ProofResult<(eliot_store_api::PreparedTransition, WriteReceipt)> {
    let prepared = envelope.prepare()?;
    let receipt = CanonicalStoreClient::apply_prepared(
        adapter,
        &envelope.request,
        prepared.clone(),
        envelope.expected_revision_heads.clone(),
        envelope.expected_ordering_heads.clone(),
    )
    .await?;
    receipt.validate()?;
    validate_store_receipt_envelope(&envelope.request, &prepared, &receipt)?;
    Ok((prepared, receipt))
}

async fn read_registry(
    adapter: &SurrealStoreAdapter,
) -> ProofResult<eliot_store_api::NamedReadResponse> {
    let response = CanonicalStoreClient::execute_named(
        adapter,
        NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(ScopeId::new(SCOPE)?),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence(true),
            parameters: BTreeMap::new(),
        },
    )
    .await?;
    response.validate()?;
    Ok(response)
}

fn assert_original_owner_pins(
    readback: &eliot_store_api::NamedReadResponse,
    envelope: &CanonicalWriteEnvelope,
    prepared: &eliot_store_api::PreparedTransition,
    receipt: &WriteReceipt,
    snapshot_json: &str,
    registration_authority_json: &str,
    expected_local_revision: Option<u64>,
) -> ProofResult<u64> {
    let payload = &readback.payload;
    let scope_revision = receipt
        .revision_before_after
        .iter()
        .find(|delta| delta.key.as_str() == format!("scope:{SCOPE}"))
        .ok_or("original receipt has no matching scope revision delta")?;
    if receipt.operation_id != prepared.identity.operation_id
        || receipt.idempotency_key != envelope.idempotency_key
        || receipt.canonical_request_hash != prepared.identity.canonical_request_hash
    {
        return Err("original Store receipt changed the prepared operation identity".into());
    }
    let recorded_revision = payload
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or("owner read omitted its positive local registry revision")?;
    if recorded_revision == 0
        || expected_local_revision.is_some_and(|expected| recorded_revision != expected)
        || payload.get("snapshot_json").and_then(Value::as_str) != Some(snapshot_json)
        || payload
            .get("registration_authority_json")
            .and_then(Value::as_str)
            != Some(registration_authority_json)
        || payload.get("scope_id").and_then(Value::as_str) != Some(SCOPE)
        || payload.get("task_id").and_then(Value::as_str) != envelope.task_id.as_deref()
        || payload.get("operation_id").and_then(Value::as_str)
            != Some(prepared.identity.operation_id.as_str())
        || payload
            .get("canonical_request_hash")
            .and_then(Value::as_str)
            != Some(prepared.identity.canonical_request_hash.as_str())
        || payload.get("state_fence") != Some(&serde_json::to_value(readback.state_fence.clone())?)
        || readback.state_fence != receipt.state_fence
        || !readback.revision_heads.iter().any(|head| {
            head.key == scope_revision.key
                && head.revision >= scope_revision.after
                && head.state_fence == receipt.state_fence
        })
    {
        return Err("current registry row does not match the original owner pins".into());
    }
    let original = receipt.require_reconciliation_envelope()?;
    if original.core.operation.operation_id != prepared.identity.operation_id
        || receipt.canonical_request_hash != prepared.identity.canonical_request_hash
        || original.core.work_scope.scope_id.as_str() != SCOPE
        || original
            .core
            .task
            .as_ref()
            .map(|task| task.task_id.as_str())
            != envelope.task_id.as_deref()
    {
        return Err("original receipt envelope does not bind the prepared owner operation".into());
    }
    Ok(recorded_revision)
}

#[tokio::test]
async fn original_registry_owner_survives_scope_advance_and_rejects_replacement() -> ProofResult {
    let harness = Harness::fresh().await?;
    let adapter = harness.adapter();

    let registry = registered_scip_registry()?;
    let snapshot_json = registry.persist()?;
    let registration_authority_json = registration_authority_json()?;
    let registration = envelope(
        "operation:instrument-registry-registration-1814",
        Some(TASK),
        registry_command(
            snapshot_json.clone(),
            registration_authority_json.clone(),
            0,
        ),
    )?;
    let (prepared, original_receipt) = apply(adapter, &registration).await?;
    if original_receipt.status != WriteReceiptStatus::Committed
        || original_receipt.commit_id.is_none()
        || original_receipt.transition_class != TransitionClass::InstrumentRegistry
    {
        return Err("canonical store did not commit the original registry owner write".into());
    }
    let initial_readback = read_registry(adapter).await?;
    validate_instrument_registry_registration_readback(&initial_readback, &original_receipt)?;
    let original_local_revision = assert_original_owner_pins(
        &initial_readback,
        &registration,
        &prepared,
        &original_receipt,
        &snapshot_json,
        &registration_authority_json,
        None,
    )?;

    let proof = CanonicalRegistryProofPort::retain_original(
        Arc::clone(adapter),
        NamedReadRequest {
            operation: NamedReadOperation::GetInstrumentRegistryState,
            scope_id: Some(ScopeId::new(SCOPE)?),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence(true),
            parameters: BTreeMap::new(),
        },
    )
    .await?;
    let pure_spec = registry
        .pure_transform(SCIP_INSTRUMENT)
        .ok_or("SCIP pure transform is not registered")?;
    assert_eq!(pure_spec.profile_revision, BUILTIN_PROFILE_REVISION);
    assert_eq!(pure_spec.parser_generation, 7);
    let admitted =
        ProfileCompiler::new(&registry).compile_exact(SCIP_INSTRUMENT, BUILTIN_PROFILE_REVISION)?;
    let plan = StageOrchestrator::plan(&admitted);
    assert_eq!(plan.stages.len(), 1);
    assert!(!plan.stages[0].route.external());
    let (scip_bytes, query, graph_revision) = retained_scip_fixture();
    let source_snapshot_command =
        resource_snapshot_mutation_request(SCIP_SNAPSHOT_URI.to_owned(), &scip_bytes)?;
    let source_snapshot = envelope(
        "operation:instrument-registry-1814-source-snapshot",
        Some(TASK),
        source_snapshot_command,
    )?;
    let (_, source_snapshot_receipt) = apply(adapter, &source_snapshot).await?;
    if source_snapshot_receipt.status != WriteReceiptStatus::Committed {
        return Err("canonical SCIP resource snapshot write did not commit".into());
    }
    let pure_input = PureTransformInput::retain_resource_snapshot(
        Arc::clone(adapter),
        resource_snapshot_read_request(SCIP_SNAPSHOT_URI.to_owned(), fence(true))?,
        query.clone(),
        graph_revision,
    )
    .await?;
    let missing_input = PureTransformInput::retain_resource_snapshot(
        Arc::clone(adapter),
        resource_snapshot_read_request(MISSING_SNAPSHOT_URI.to_owned(), fence(true))?,
        query.clone(),
        graph_revision,
    )
    .await;
    assert!(
        missing_input.is_err(),
        "an absent resource snapshot cannot provide pure transform input"
    );
    let launcher = ScipInputLauncher {
        input: Some(pure_input),
    };
    let missing_input_launcher = ScipInputLauncher {
        input: missing_input.ok(),
    };
    let runner = InstrumentRunner::new(Arc::new(NoProcessExecutor));

    // Advance the same canonical scope through a distinct resource snapshot
    // operation. This does not replace the registry row.
    let unrelated_command = resource_snapshot_mutation_request(
        "eliot://evidence/instrument-registry-1814-unrelated".to_owned(),
        b"unrelated canonical scope write",
    )?;
    let unrelated = envelope(
        "operation:instrument-registry-1814-unrelated",
        Some(TASK),
        unrelated_command,
    )?;
    let (_, unrelated_receipt) = apply(adapter, &unrelated).await?;
    if unrelated_receipt.status != WriteReceiptStatus::Committed {
        return Err("unrelated canonical scope write did not commit".into());
    }
    let original_scope_after = original_receipt
        .revision_before_after
        .iter()
        .find(|delta| delta.key.as_str() == format!("scope:{SCOPE}"))
        .ok_or("original receipt has no matching scope revision delta")?
        .after;
    let unrelated_scope_after = unrelated_receipt
        .revision_before_after
        .iter()
        .find(|delta| delta.key.as_str() == format!("scope:{SCOPE}"))
        .ok_or("unrelated receipt has no matching scope revision delta")?
        .after;
    assert!(unrelated_scope_after > original_scope_after);
    let after_scope_advance = read_registry(adapter).await?;
    validate_instrument_registry_registration_readback(&after_scope_advance, &original_receipt)?;
    let still_original_revision = assert_original_owner_pins(
        &after_scope_advance,
        &registration,
        &prepared,
        &original_receipt,
        &snapshot_json,
        &registration_authority_json,
        Some(original_local_revision),
    )?;
    assert_eq!(still_original_revision, original_local_revision);

    let positive_runs = StageOrchestrator::launch_plan_live_with_proof(
        &runner, &registry, &plan, &launcher, &proof,
    )
    .await;
    assert_eq!(positive_runs.len(), 1);
    let positive_run = &positive_runs[0];
    assert_eq!(positive_run.execution, ExecutionStatus::Succeeded);
    assert!(positive_run.executable_digest.is_none());
    assert!(positive_run.grant_digest.is_none());
    let StageEvidence::Transformed {
        source_artifact,
        source_byte_len,
        source_sha256,
        source_revision,
        result_bytes,
        ..
    } = &positive_run.evidence
    else {
        return Err("registered SCIP decoder did not retain transformed evidence".into());
    };
    assert_eq!(source_artifact.as_str(), SCIP_SNAPSHOT_URI);
    assert_eq!(*source_byte_len, scip_bytes.len() as u64);
    assert_eq!(source_sha256, &eliot_store_api::sha256_hex(&scip_bytes));
    assert!(*source_revision > 0);
    let result: GraphQueryResult = serde_json::from_slice(result_bytes)?;
    assert_eq!(result.status, GraphQueryStatus::Found);
    assert_eq!(result.revision.value(), 1);
    assert_eq!(result.nodes.len(), 1);
    assert_eq!(
        result.nodes[0].coordinate.symbol.as_deref(),
        Some(SCIP_INSTRUMENT)
    );

    let missing_input_runs = StageOrchestrator::launch_plan_live_with_proof(
        &runner,
        &registry,
        &plan,
        &missing_input_launcher,
        &proof,
    )
    .await;
    assert_eq!(missing_input_runs.len(), 1);
    assert_eq!(missing_input_runs[0].execution, ExecutionStatus::Unknown);
    let StageEvidence::Missing { reason } = &missing_input_runs[0].evidence else {
        return Err("pure stage without a canonical retained input did not remain missing".into());
    };
    assert!(reason.contains("pure transform input is unavailable"));

    // A later registry write replaces the exact owner row. Its actual store
    // receipt/readback must no longer satisfy the retained original pins. The
    // replacement bytes are deliberately identical: the new owner operation
    // alone must revoke admission for a later stage attempt.
    let replacement_snapshot = snapshot_json.clone();
    assert_eq!(replacement_snapshot, snapshot_json);
    let replacement = envelope(
        "operation:instrument-registry-registration-1814-replacement",
        Some(TASK),
        registry_command(
            replacement_snapshot.clone(),
            registration_authority_json.clone(),
            original_local_revision,
        ),
    )?;
    let (replacement_prepared, replacement_receipt) = apply(adapter, &replacement).await?;
    if replacement_receipt.status != WriteReceiptStatus::Committed {
        return Err("replacement canonical registry write did not commit".into());
    }
    let replacement_readback = read_registry(adapter).await?;
    validate_instrument_registry_registration_readback(
        &replacement_readback,
        &replacement_receipt,
    )?;
    assert!(
        validate_instrument_registry_registration_readback(
            &replacement_readback,
            &original_receipt
        )
        .is_err()
    );
    assert!(
        assert_original_owner_pins(
            &replacement_readback,
            &registration,
            &prepared,
            &original_receipt,
            &snapshot_json,
            &registration_authority_json,
            Some(original_local_revision),
        )
        .is_err(),
        "replacement owner must be refused under the original receipt/readback pins"
    );
    assert_ne!(
        replacement_readback
            .payload
            .get("operation_id")
            .and_then(Value::as_str),
        Some(prepared.identity.operation_id.as_str())
    );
    assert_ne!(
        replacement_readback
            .payload
            .get("canonical_request_hash")
            .and_then(Value::as_str),
        Some(prepared.identity.canonical_request_hash.as_str())
    );
    let replacement_local_revision = assert_original_owner_pins(
        &replacement_readback,
        &replacement,
        &replacement_prepared,
        &replacement_receipt,
        &replacement_snapshot,
        &registration_authority_json,
        None,
    )?;
    assert!(replacement_local_revision > original_local_revision);

    let refused_runs = StageOrchestrator::launch_plan_live_with_proof(
        &runner, &registry, &plan, &launcher, &proof,
    )
    .await;
    assert_eq!(refused_runs.len(), 1);
    assert_eq!(refused_runs[0].execution, ExecutionStatus::Unknown);
    let StageEvidence::Missing { reason } = &refused_runs[0].evidence else {
        return Err("same-byte owner replacement did not refuse the new pure stage".into());
    };
    assert!(reason.contains("pure transform owner proof unavailable"));
    assert_eq!(positive_run.execution, ExecutionStatus::Succeeded);
    assert!(matches!(
        positive_run.evidence,
        StageEvidence::Transformed { .. }
    ));

    drop(harness);
    Ok(())
}
