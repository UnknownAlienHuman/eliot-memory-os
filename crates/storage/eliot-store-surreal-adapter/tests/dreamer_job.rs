//! Durable Dreamer job ledger tests (B-DRM-S1, owner #775).
//!
//! Proves the full twelve-operation ledger through the public
//! [`CanonicalStoreClient::dreamer_job`](eliot_store_api::CanonicalStoreClient)
//! API against an isolated `surreal.exe` provider (loopback bind, per-test
//! temporary `SurrealKV` roots, redacted test credentials), plus pure
//! contract discriminators where the issue allows them. No in-memory
//! stand-in, no production database, no user credentials.
//!
//! Corrected lifecycle under test (I14.20):
//! `NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED → VERIFYING →`
//! terminal (`COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME`).
//! Candidate results live inside terminal outcomes; cancellation-requested is
//! evidence, never a job state.
//!
//! Declared denominator, exactly one substantive test per case:
//!
//! 1. actual create/load/canonical digest and durable reopen;
//! 2. exact replay and changed same-ID conflict;
//! 3. every allowed/forbidden canonical transition (pure K0 matrix);
//! 4. actual independent clients race one submit: exactly one commit;
//! 5. actual two-worker lease conflict and exact owner replay;
//! 6. stale fence/state/revision/lease pins are deterministic not-applied;
//! 7. canonical VERIFYING versus COMPLETED/PARTIAL semantic result;
//! 8. cancellation request versus terminal CANCELLED;
//! 9. failure before submission is proven-not-applied;
//! 10. ambiguous post-submit stays Store uncertainty (pure mapping proof);
//! 11. unknown reconciles to the exact committed record/event/receipt;
//! 12. independently proven absence versus still-unknown, no blind retry;
//! 13. receipt/record/event digest/revision/fence mismatch (pure);
//! 14. missing receipt cannot claim committed;
//! 15. bounded deterministic lease-next/list, complete-empty versus
//!     partial/exhausted/unavailable;
//! 16. recovery includes the complete Dreamer namespace, others unchanged;
//! 17. unchanged sufficient schema: stock v2 baseline, no extra migration;
//! 18. record/page/payload limits and one-over;
//! 19. secret/semantic payload absence from errors (pure);
//! 20. malformed rows fail closed plus delegation/capability checks (pure).
//!
//! Provider evidence (recorded on failure output and in the work item): the
//! pinned `surreal.exe` path plus its SHA-256, the server version handshake
//! enforced by the adapter, the per-test loopback port, and the temporary
//! data/work/tmp roots.

#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Test-only allowances: provider-evidence logging prints bounded setup facts
//! (no credentials), test futures hold the provider harness plus ledger
//! payloads across awaits, and lifecycle tests necessarily run long flows.
#![allow(clippy::print_stdout, clippy::large_futures, clippy::too_many_lines)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eliot_contracts::{
    ArtifactId, ClockReading, ProductId, RequestId, ResourceGeneration, SourceId, TaskId,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::dreamer_job::{
    DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation, JobOperationKind,
    JobRole, JobState, MutationDisposition,
};
use eliot_store_api::{
    CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION, CAPABILITY_DREAMER_JOB_CHECKPOINT,
    CAPABILITY_DREAMER_JOB_LEASE_EXACT, CAPABILITY_DREAMER_JOB_LEASE_NEXT,
    CAPABILITY_DREAMER_JOB_PUBLISH, CAPABILITY_DREAMER_JOB_RECONCILE, CAPABILITY_DREAMER_JOB_RENEW,
    CAPABILITY_DREAMER_JOB_REQUEST_CANCEL, CAPABILITY_DREAMER_JOB_RESUME,
    CAPABILITY_DREAMER_JOB_START, CAPABILITY_DREAMER_JOB_STATUS, CAPABILITY_DREAMER_JOB_SUBMIT,
    CONTRACT_VERSION, DREAMER_JOB_LEDGER_SCHEMA,
};
use eliot_store_api::{
    CanonicalStoreClient, DreamerJobLedgerEvent, DreamerJobLedgerRecord,
    DreamerJobMutationIdentity, MAX_DREAMER_JOB_HISTORY, RecoveryRecord, RequestMeta, StateFence,
    StoreError, StoreRecoveryRequest, dreamer_job_capability, dreamer_job_queue_key,
};
use eliot_store_surreal_adapter::{
    AdapterError, PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig,
    SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

/// Isolated provider executable for tests. Overridable for local runs; the
/// default is the pinned local installation probed during implementation.
const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const LEASE_TTL_MS: u64 = 60_000;

fn surreal_exe() -> PathBuf {
    std::env::var("ELIOT_TEST_SURREAL_EXE")
        .map_or_else(|_| PathBuf::from(TEST_SURREAL_EXE), PathBuf::from)
}

fn fence() -> StateFence {
    use eliot_contracts::{EpochId, EpochLineageId};
    let lineage = EpochLineageId::new(LINEAGE).expect("lineage");
    let epoch = EpochId::new(lineage, std::num::NonZeroU64::new(1).expect("seq")).expect("epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn fence_json() -> Value {
    json!({
        "authority_epoch": {"lineage_id": LINEAGE, "sequence": 1},
        "resource_generation": 1,
        "task_revision": null,
        "policy_revision": null,
        "integration_revision": null,
    })
}

/// A second valid fence with an unrelated lineage for stale-fence proofs.
fn foreign_fence_json() -> Value {
    json!({
        "authority_epoch": {"lineage_id": "660e8400-e29b-41d4-a716-446655440001", "sequence": 1},
        "resource_generation": 1,
        "task_revision": null,
        "policy_revision": null,
        "integration_revision": null,
    })
}

fn clock() -> ClockReading {
    ClockReading {
        valid_time_ms: Some(1_000),
        known_time_ms: Some(1_001),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn ctx(request_id: &str) -> RequestMeta {
    RequestMeta {
        request_id: RequestId::new(request_id).expect("request id"),
        session_id: None,
        task_id: None,
        product_id: ProductId::new("product-dreamer-775").expect("product"),
        source_id: SourceId::new("source-dreamer-775").expect("source"),
        state_fence: fence(),
        clock: clock(),
    }
}

fn observation() -> ClockObservation {
    clock()
}

/// Builds one valid `Submit` operation via its canonical JSON shape (the
/// nested scope/admission bindings deserialize through their owners).
fn submit_operation(job: &str, attempt: &str, input_revision: &str) -> JobOperation {
    let fence = fence_json();
    let submission: eliot_protocol::dreamer_job::JobSubmission = serde_json::from_value(json!({
        "job_id": job,
        "attempt_id": attempt,
        "work_scope": {
            "scope_id": "scope-dreamer",
            "product_id": "product-dreamer-775",
            "resource_generation": 1,
            "state_fence": fence,
        },
        "semantic_input": content_ref(input_revision),
        "output_contract": content_ref("output"),
        "admission": {
            "authority": {
                "authority_id": "kernel",
                "authority_owner": "kernel",
                "authority_epoch": {"lineage_id": LINEAGE, "sequence": 1},
                "state_fence": fence,
                "allowed_effect": "CANDIDATE",
                "proof_ceiling": "CANDIDATE_ARTIFACT",
            },
            "requester_principal": "requester-775",
            "session": null,
            "scope": {
                "scope_id": "scope-dreamer",
                "product_id": "product-dreamer-775",
                "resource_generation": 1,
                "state_fence": fence,
            },
            "capability": "dreamer.submit",
            "route_class": "bounded",
            "budget_units": 1,
            "deadline_unix_ms": 600_000,
            "validity_epoch": {"lineage_id": LINEAGE, "sequence": 1},
            "resource_generation": 1,
            "admission_receipt": "admission-775",
        },
        "cancellation_id": "cancel-775",
    }))
    .expect("submission");
    JobOperation::Submit {
        submission: Box::new(submission),
    }
}

fn content_ref(revision: &str) -> Value {
    json!({
        "contract": {
            "name": "eliot.smart.dreamer.contracts",
            "version": {"major": 1, "minor": 0, "patch": 0},
            "shape_sha256": "0".repeat(64),
        },
        "source_revision": revision,
        "byte_length": 8,
        "sha256": "1".repeat(64),
        "artifact_id": format!("artifact-{revision}"),
    })
}

fn evidence_value() -> Value {
    json!({
        "artifact_id": "artifact-775-evidence-1",
        "sha256": "2".repeat(64),
        "role": "ARTIFACT",
        "source_revision": "rev-775-1",
    })
}

fn checkpoint_json(id: &str) -> Value {
    json!({
        "checkpoint_id": id,
        "reference": {
            "contract": {
                "name": "eliot.smart.dreamer.contracts",
                "version": {"major": 1, "minor": 0, "patch": 0},
                "shape_sha256": "0".repeat(64),
            },
            "source_revision": id,
            "byte_length": 8,
            "sha256": "3".repeat(64),
            "artifact_id": id,
        },
        "completed_phases": ["phase-a"],
        "remaining_phases": ["phase-b"],
        "budget_remaining": 7,
        "possible_effects": ["CANDIDATE"],
        "state_fence": fence_json(),
    })
}

fn outcome_json(
    state: &str,
    result: Option<&Value>,
    unresolved: &[&str],
    abstention: Option<&str>,
) -> Value {
    json!({
        "state": state,
        "result": result,
        "evidence": [evidence_value()],
        "verifier": null,
        "proof_ceiling": "CANDIDATE_ARTIFACT",
        "abstention_reason": abstention,
        "unresolved": unresolved,
    })
}

fn status_operation(job: &str, attempt: &str, revision: u64) -> JobOperation {
    JobOperation::Status {
        job_id: TaskId::new(job).expect("job"),
        attempt_id: ArtifactId::new(attempt).expect("attempt"),
        expected_revision: revision,
        expected_fence: fence(),
    }
}

fn lease_selector_json(revision: u64, worker: &str, max: u32) -> Value {
    json!({
        "scope_id": "scope-dreamer",
        "expected_revision": revision,
        "expected_fence": fence_json(),
        "worker_artifact_id": worker,
        "max_candidates": max,
    })
}

fn lease_exact_operation(job: &str, worker: &str, revision: u64) -> JobOperation {
    let selector: eliot_protocol::dreamer_job::LeaseSelector =
        serde_json::from_value(lease_selector_json(revision, worker, 8)).expect("selector");
    JobOperation::LeaseExact {
        selector,
        job_id: TaskId::new(job).expect("job"),
    }
}

fn lease_next_operation(worker: &str, revision: u64, max: u32) -> JobOperation {
    let selector: eliot_protocol::dreamer_job::LeaseSelector =
        serde_json::from_value(lease_selector_json(revision, worker, max)).expect("selector");
    JobOperation::LeaseNext { selector }
}

fn lease_op_json(kind: &str, lease: &Value, now: u64) -> JobOperation {
    serde_json::from_value(json!({
        "operation": kind,
        "lease": lease,
        "now_unix_ms": now,
    }))
    .expect("lease-carrying operation")
}

fn checkpoint_op_json(lease: &Value, checkpoint: &Value, now: u64, resume: bool) -> JobOperation {
    serde_json::from_value(json!({
        "operation": if resume { "RESUME_JOB" } else { "CHECKPOINT_JOB" },
        "lease": lease,
        "checkpoint": checkpoint,
        "now_unix_ms": now,
    }))
    .expect("checkpoint operation")
}

fn begin_verify_op_json(lease: &Value, result: &Value, now: u64) -> JobOperation {
    serde_json::from_value(json!({
        "operation": "BEGIN_VERIFICATION",
        "lease": lease,
        "result": result,
        "evidence": [evidence_value()],
        "now_unix_ms": now,
    }))
    .expect("begin-verification operation")
}

fn publish_op_json(lease: &Value, outcome: &Value, now: u64) -> JobOperation {
    serde_json::from_value(json!({
        "operation": "PUBLISH_OUTCOME",
        "lease": lease,
        "outcome": outcome,
        "now_unix_ms": now,
    }))
    .expect("publish operation")
}

fn request_cancel_operation(job: &str, attempt: &str, reason: &str, at: u64) -> JobOperation {
    JobOperation::RequestCancel {
        job_id: TaskId::new(job).expect("job"),
        attempt_id: ArtifactId::new(attempt).expect("attempt"),
        reason: reason.to_owned(),
        requested_at_unix_ms: at,
        expected_fence: fence(),
    }
}

/// Fresh transport correlation shared by request builders.
fn fresh_request_json(fresh: &str) -> Value {
    fresh_request_json_with_fence(fresh, &fence_json())
}

fn fresh_request_json_with_fence(fresh: &str, fence_value: &Value) -> Value {
    json!({
        "request": {
            "metadata": {
                "request_id": fresh,
                "session_id": null,
                "task_id": "job-775",
                "product_id": "product-dreamer-775",
                "source_id": "source-dreamer-775",
                "state_fence": fence_value,
                "clock": {"valid_time_ms": 1_000, "known_time_ms": 1_001,
                          "transaction_sequence": null, "monotonic_ns": null},
            },
            "state_fence": fence_value,
        },
        "idempotency_key": "transport-775",
        "deadline_unix_ms": 600_000,
        "cancellation_id": "cancel-775",
    })
}

/// Binds one closed operation to fresh transport correlation plus stable
/// mutation identity with a recomputed canonical hash.
fn make_request_unchecked(
    operation: JobOperation,
    role: JobRole,
    operation_id: &str,
    idempotency: &str,
    fresh: &str,
) -> DurableJobRequest {
    make_request_unchecked_with_fence(
        operation,
        role,
        operation_id,
        idempotency,
        fresh,
        &fence_json(),
    )
}

/// Builds a request against an explicit fence for stale-fence proofs (the
/// identity, operation, and digest all bind the same fence so K0 construction
/// succeeds and the adapter pin is what refuses).
fn make_request_unchecked_with_fence(
    operation: JobOperation,
    role: JobRole,
    operation_id: &str,
    idempotency: &str,
    fresh: &str,
    fence_value: &Value,
) -> DurableJobRequest {
    let kind = operation.kind().as_str().to_owned();
    let mut identity: DurableRequestIdentity = serde_json::from_value(json!({
        "request": fresh_request_json_with_fence(fresh, fence_value),
        "operation": {
            "operation_id": operation_id,
            "request_id": "originating-775",
            "idempotency_key": idempotency,
            "operation_kind": kind,
            "effect": "CANDIDATE",
            "state_fence": fence_value,
        },
        "canonical_request_hash": "0".repeat(64),
    }))
    .expect("identity");
    let hash = DurableRequestIdentity::digest_for(
        &identity.operation,
        &identity.request,
        &operation,
        role,
    )
    .expect("hash");
    identity.canonical_request_hash = hash;
    DurableJobRequest {
        request_identity: identity,
        role,
        operation,
    }
}

fn make_request(
    operation: JobOperation,
    role: JobRole,
    operation_id: &str,
    idempotency: &str,
    fresh: &str,
) -> DurableJobRequest {
    let request = make_request_unchecked(operation, role, operation_id, idempotency, fresh);
    request.validate().expect("request validates");
    request
}

fn binding_of(request: &DurableJobRequest) -> Value {
    serde_json::to_value(&request.request_identity.operation).expect("binding json")
}

fn hash_of(request: &DurableJobRequest) -> String {
    request.request_identity.canonical_request_hash.clone()
}

/// Builds a reconcile request reusing an exact stable operation binding and
/// canonical hash (K0 requires both to equal the mutation's).
fn make_reconcile_request(
    mutation: Value,
    binding: &Value,
    hash: &str,
    role: JobRole,
    fresh: &str,
) -> DurableJobRequest {
    let identity: DurableRequestIdentity = serde_json::from_value(json!({
        "request": fresh_request_json(fresh),
        "operation": binding,
        "canonical_request_hash": hash,
    }))
    .expect("reconcile identity");
    let request = DurableJobRequest {
        request_identity: identity,
        role,
        operation: JobOperation::Reconcile {
            mutation: Box::new(serde_json::from_value(mutation).expect("mutation")),
        },
    };
    request.validate().expect("reconcile request validates");
    request
}

fn reconcile_mutation_json(
    job: &str,
    attempt: &str,
    binding: &Value,
    hash: &str,
    disposition: &str,
    committed_state: Option<&str>,
    receipt: Option<&str>,
) -> Value {
    let receipt_value = receipt.map_or(Value::Null, |id| Value::String(id.to_owned()));
    json!({
        "job_id": job,
        "attempt_id": attempt,
        "operation": binding,
        "canonical_request_hash": hash,
        "disposition": disposition,
        "committed_state": committed_state,
        "receipt_id": receipt_value,
        "evidence": [evidence_value()],
    })
}

/// Extracts the active lease projection from a response as canonical JSON for
/// exact-equality owner pins in later operations.
fn lease_value_of(response: &DurableJobResponse) -> Value {
    serde_json::to_value(response.lease.clone().expect("active lease")).expect("lease json")
}

fn issued_of(lease: &Value) -> u64 {
    lease
        .get("issued_at_unix_ms")
        .and_then(serde_json::Value::as_u64)
        .expect("issued_at")
}

fn receipt_string_of(response: &DurableJobResponse) -> String {
    serde_json::to_value(response.receipt_id.clone().expect("receipt"))
        .expect("receipt json")
        .as_str()
        .expect("receipt string")
        .to_owned()
}

struct Harness {
    root: PathBuf,
    port: u16,
    adapter: Option<SurrealStoreAdapter>,
}

impl Harness {
    async fn provision(root: PathBuf, port: u16) -> Self {
        let bin = root.join("bin");
        let data = root.join("store").join("data");
        let work = root.join("store").join("work");
        let tmp = root.join("store").join("tmp");
        for dir in [&bin, &data, &work, &tmp] {
            std::fs::create_dir_all(dir).expect("test dirs");
        }
        let source_exe = surreal_exe();
        assert!(
            source_exe.is_file(),
            "pinned test provider is absent: {}",
            source_exe.display()
        );
        let exe = bin.join("surreal.exe");
        std::fs::copy(&source_exe, &exe).expect("stage provider");
        let bytes = std::fs::read(&exe).expect("read staged provider");
        let digest = eliot_store_api::sha256_hex(&bytes);
        println!(
            "dreamer provider: exe={} sha256={} port={} root={}",
            exe.display(),
            digest,
            port,
            root.display()
        );

        let platform = WindowsPlatform::new(root.clone()).expect("platform");
        let bind = format!("127.0.0.1:{port}");
        prepare_initial_root_user(&exe, &bind, &data, &work, &tmp);
        let lease = platform
            .retain_process_path_lease(&exe, &work, &digest)
            .expect("process lease");
        let config = adapter_config(&exe, digest, bind, &data, &work, &tmp);
        let adapter = SurrealStoreAdapter::new(config, lease).expect("adapter");
        adapter.connect().await.expect("provider connect");
        let migration = SurrealStoreAdapter::v2_baseline_migration();
        if let Err(error) = adapter
            .apply_migration(&migration, &observation(), &fence())
            .await
        {
            panic!(
                "baseline migration: {error:?} provider_log={:?}",
                read_provider_log_tail(&root.join("store").join("work")),
            );
        }
        Self {
            root,
            port,
            adapter: Some(adapter),
        }
    }

    async fn fresh(test: &str) -> Self {
        let port = free_port();
        let root = std::env::temp_dir().join(format!(
            "eliot-dreamer-775-{}-{port}-{test}",
            std::process::id()
        ));
        Self::provision(root, port).await
    }

    fn adapter(&self) -> &SurrealStoreAdapter {
        self.adapter.as_ref().expect("adapter live")
    }

    /// Drops the live adapter (killing its provider child and releasing the
    /// data-root claim) so a reopen can be proven over the same files.
    fn shutdown(&mut self) {
        self.adapter = None;
    }

    /// Reopens the same `SurrealKV` files with a fresh adapter + provider.
    /// Retries while the previous generation releases its port and lock.
    async fn reopen(&mut self) {
        self.shutdown();
        let deadline = std::time::Instant::now() + Duration::from_mins(1);
        loop {
            let bin = self.root.join("bin");
            let data = self.root.join("store").join("data");
            let work = self.root.join("store").join("work");
            let tmp = self.root.join("store").join("tmp");
            let exe = bin.join("surreal.exe");
            match (|| -> Result<SurrealStoreAdapter, String> {
                let bytes =
                    std::fs::read(&exe).map_err(|error| format!("read provider: {error}"))?;
                let digest = eliot_store_api::sha256_hex(&bytes);
                let platform = WindowsPlatform::new(self.root.clone())
                    .map_err(|error| format!("{error:?}"))?;
                let lease = platform
                    .retain_process_path_lease(&exe, &work, &digest)
                    .map_err(|error| format!("{error:?}"))?;
                let bind = format!("127.0.0.1:{}", self.port);
                let config = adapter_config(&exe, digest, bind, &data, &work, &tmp);
                SurrealStoreAdapter::new(config, lease).map_err(|error| format!("{error:?}"))
            })() {
                Ok(adapter) => match adapter.connect().await {
                    Ok(()) => {
                        self.adapter = Some(adapter);
                        return;
                    }
                    Err(error) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "reopen connect failed: {error:?}"
                        );
                    }
                },
                Err(error) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "reopen provision failed: {error}"
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.adapter = None;
        if std::env::var("ELIOT_TEST_KEEP_DREAMER_ROOT").is_ok() {
            println!("keeping dreamer test root: {}", self.root.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Reads the bounded tail of the provider log for failure diagnostics.
/// Never includes credentials: the provider argv carries none.
fn read_provider_log_tail(work: &Path) -> String {
    const TAIL: usize = 4_096;
    let log = work.join("surrealdb.log");
    let text = std::fs::read_to_string(&log).unwrap_or_else(|_| "<no provider log>".to_owned());
    let start = text.len().saturating_sub(TAIL);
    text[start..].to_owned()
}

/// Builds the canonical adapter configuration for one isolated provider.
/// Shared by fresh provisioning and reopen so both generations bind the same
/// roots, credential, timeouts, and byte-exact provider argv.
fn adapter_config(
    exe: &Path,
    digest: String,
    bind: String,
    data: &Path,
    work: &Path,
    tmp: &Path,
) -> SurrealAdapterConfig {
    let mut config = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "eliot".to_owned(),
        database: "dreamer_775".to_owned(),
        username: "dreamer-test".to_owned(),
        password: SecretString::new("dreamer-test-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-775".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: "a".repeat(64),
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: digest,
        provider_arguments: Vec::new(),
        store_data_root: data.to_string_lossy().into_owned(),
        store_work_root: work.to_string_lossy().into_owned(),
        store_temp_root: tmp.to_string_lossy().into_owned(),
        connect_timeout_ms: 60_000,
        query_timeout_ms: 30_000,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    config
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("loopback")
        .local_addr()
        .expect("port")
        .port()
}

/// Provisions the initial root credential inside a fresh `SurrealKV` data root.
///
/// A bare `surreal start` creates no root user, and the adapter's canonical
/// argv carries no `--username/--password` (byte-validated by config), so its
/// `signin` would fail against unprepared files. Mirroring installation
/// provisioning, a short-lived preparation provider started once with the
/// test credential creates the initial root user; it is then terminated and
/// its port/files released before the adapter's own provider spawns. The
/// credential travels only to the local loopback child during setup.
fn prepare_initial_root_user(exe: &Path, bind: &str, data: &Path, work: &Path, tmp: &Path) {
    let password = SecretString::new("dreamer-test-secret".into());
    let data_url = format!("surrealkv://{}", data.to_string_lossy().replace('\\', "/"));
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut child = std::process::Command::new(exe)
        .args([
            "start",
            "--no-banner",
            "--bind",
            bind,
            "--username",
            "dreamer-test",
            "--password",
            password.expose_secret(),
            "--temporary-directory",
            &tmp.to_string_lossy(),
            "--log-file-enabled",
            "--log-file-path",
            &work.to_string_lossy(),
            "--log-file-name",
            "surrealdb.log",
            &data_url,
        ])
        .current_dir(work)
        .env_clear()
        .env("SystemRoot", &system_root)
        .env("WINDIR", &system_root)
        .env("TEMP", tmp)
        .env("TMP", tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("preparation provider");

    // Wait until the preparation provider accepts its loopback endpoint.
    let deadline = std::time::Instant::now() + Duration::from_mins(1);
    loop {
        if std::net::TcpStream::connect(bind).is_ok() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            panic!("preparation provider never bound {bind}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // The initial root user is created during startup; allow it to flush.
    std::thread::sleep(Duration::from_secs(2));
    child.kill().expect("stop preparation provider");
    let _ = child.wait();
    // Wait until the endpoint is released so the adapter's provider can bind.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while std::net::TcpStream::connect(bind).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "preparation provider never released {bind}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_secs(1));
}

fn is_revision_conflict(error: &StoreError) -> bool {
    matches!(error, StoreError::RevisionConflict)
}

fn is_identity_conflict(error: &StoreError) -> bool {
    matches!(error, StoreError::IdentityConflict)
}

/// Submits one job and leases it, returning the submit/lease responses plus
/// the lease JSON for exact-equality owner pins.
async fn submit_and_lease(
    harness: &Harness,
    tag: &str,
    job: &str,
    attempt: &str,
    worker: &str,
) -> (DurableJobResponse, DurableJobResponse, Value) {
    let submit = make_request(
        submit_operation(job, attempt, "input-775"),
        JobRole::Requester,
        &format!("operation-775-{tag}-submit"),
        &format!("stable-775-{tag}-submit"),
        &format!("fresh-775-{tag}-submit"),
    );
    let submitted: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx(&format!("ctx-775-{tag}-submit")), submit)
        .await
        .expect("submit commits");
    assert_eq!(submitted.state, JobState::Queued);
    let lease_request = make_request(
        lease_exact_operation(job, worker, submitted.revision),
        JobRole::Worker,
        &format!("operation-775-{tag}-lease"),
        &format!("stable-775-{tag}-lease"),
        &format!("fresh-775-{tag}-lease"),
    );
    let leased: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx(&format!("ctx-775-{tag}-lease")), lease_request)
        .await
        .expect("lease commits");
    assert_eq!(leased.state, JobState::Leased);
    let lease = lease_value_of(&leased);
    (submitted, leased, lease)
}

// WORK_UNIT_CASE: 775/1
#[tokio::test]
async fn case_01_create_load_digest_reopen() {
    let mut harness = Harness::fresh("case-01").await;
    let job = "job-775-01";
    let attempt = "attempt-775-01";

    let submit = make_request(
        submit_operation(job, attempt, "input-775-01"),
        JobRole::Requester,
        "operation-775-01-submit",
        "stable-775-01-submit",
        "fresh-775-01-submit",
    );
    let submitted: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-01-submit"), submit)
        .await
        .expect("submit commits");
    assert_eq!(submitted.state, JobState::Queued);
    assert_eq!(submitted.revision, 1);
    // The owner receipt reference is deterministic per operation identity.
    assert_eq!(
        receipt_string_of(&submitted),
        "dreamer-receipt-operation-775-01-submit"
    );
    assert_eq!(submitted.disposition, Some(MutationDisposition::Committed));
    assert_eq!(submitted.job_id.to_string(), job);
    assert_eq!(submitted.attempt_id.to_string(), attempt);

    // Status observes the durable record without mutating it.
    let status = make_request(
        status_operation(job, attempt, submitted.revision),
        JobRole::Requester,
        "operation-775-01-status",
        "stable-775-01-status",
        "fresh-775-01-status",
    );
    let observed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-01-status"), status)
        .await
        .expect("status observes");
    assert_eq!(observed.state, JobState::Queued);
    assert_eq!(observed.revision, submitted.revision);
    assert_eq!(observed.scope, submitted.scope);
    assert!(observed.disposition.is_none());
    assert!(observed.receipt_id.is_none());

    // Reopen over the same files: the digest-bound record survives reopen and
    // observes identically without a second submit.
    harness.reopen().await;
    let status_after = make_request(
        status_operation(job, attempt, 1),
        JobRole::Requester,
        "operation-775-01-reopen",
        "stable-775-01-reopen",
        "fresh-775-01-reopen",
    );
    let reopened: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-01-reopen"), status_after)
        .await
        .expect("status survives reopen");
    assert_eq!(reopened.state, JobState::Queued);
    assert_eq!(reopened.revision, 1);
    assert_eq!(reopened.scope, submitted.scope);
}

// WORK_UNIT_CASE: 775/2
#[tokio::test]
async fn case_02_replay_vs_conflict() {
    let harness = Harness::fresh("case-02").await;
    let job = "job-775-02";
    let attempt = "attempt-775-02";

    let submit = make_request(
        submit_operation(job, attempt, "input-775-02"),
        JobRole::Requester,
        "operation-775-02-submit",
        "stable-775-02-submit",
        "fresh-775-02-submit",
    );
    let first: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-02-submit"), submit.clone())
        .await
        .expect("submit commits");

    // Exact replay of the identical request returns the original outcome.
    let replayed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-02-replay"), submit)
        .await
        .expect("exact replay succeeds");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(replayed.state, first.state);
    assert_eq!(replayed.receipt_id, first.receipt_id);
    assert_eq!(replayed.disposition, first.disposition);

    // Changed content under the same operation identity conflicts instead of
    // overwriting the committed record.
    let changed = make_request(
        submit_operation(job, attempt, "input-775-02-changed"),
        JobRole::Requester,
        "operation-775-02-submit",
        "stable-775-02-submit",
        "fresh-775-02-changed",
    );
    let conflict = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-02-changed"), changed)
        .await
        .expect_err("changed content conflicts");
    assert!(
        is_identity_conflict(&conflict),
        "changed content fails with identity conflict, got: {conflict:?}"
    );

    // The same job under a fresh operation identity is a duplicate creation.
    let duplicate = make_request(
        submit_operation(job, attempt, "input-775-02"),
        JobRole::Requester,
        "operation-775-02-duplicate",
        "stable-775-02-duplicate",
        "fresh-775-02-duplicate",
    );
    let duplicate_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-02-duplicate"), duplicate)
        .await
        .expect_err("duplicate job conflicts");
    assert!(
        is_identity_conflict(&duplicate_error),
        "duplicate job fails with identity conflict, got: {duplicate_error:?}"
    );
}

// WORK_UNIT_CASE: 775/3
#[test]
fn case_03_transition_matrix() {
    use JobState::{
        Cancelled, Checkpointed, Completed, Failed, Leased, NotStarted, Partial, Queued, Running,
        UnknownOutcome, Verifying,
    };
    // The exact I14.20 edge set (self-edges are separately valid).
    let allowed: &[(JobState, JobState)] = &[
        (NotStarted, Queued),
        (Queued, Leased),
        (Leased, Running),
        (Checkpointed, Running),
        (Running, Checkpointed),
        (Running, Failed),
        (Running, Cancelled),
        (Running, UnknownOutcome),
        (Checkpointed, Verifying),
        (Checkpointed, Failed),
        (Checkpointed, Cancelled),
        (Checkpointed, UnknownOutcome),
        (Verifying, Completed),
        (Verifying, Partial),
        (Verifying, Failed),
        (Verifying, Cancelled),
        (Verifying, UnknownOutcome),
    ];
    let all = [
        NotStarted,
        Queued,
        Leased,
        Running,
        Checkpointed,
        Verifying,
        Completed,
        Partial,
        Failed,
        Cancelled,
        UnknownOutcome,
    ];
    assert_eq!(all.len(), 11);
    for from in all {
        for to in all {
            let expected = from == to || allowed.contains(&(from, to));
            assert_eq!(
                from.can_transition_to(to),
                expected,
                "edge {from:?} -> {to:?}"
            );
        }
    }
    // Terminal states are immutable execution history through the transition
    // entrypoint; a committed semantic UNKNOWN_OUTCOME is terminal too.
    let JobOperation::Submit { submission } =
        submit_operation("job-775-03", "attempt-775-03", "input-775-03")
    else {
        unreachable!("submit builder")
    };
    let record_json = |state: JobState| {
        json!({
            "submission": serde_json::to_value(&submission).expect("submission json"),
            "state": serde_json::to_value(state).expect("state json"),
            "revision": 4,
            "lease": null,
            "checkpoint": null,
            "cancellation": {"state": "NONE"},
            "outcome": null,
        })
    };
    let mut queued: eliot_protocol::dreamer_job::DurableJobRecord =
        serde_json::from_value(record_json(Queued)).expect("queued record");
    queued.transition(Leased).expect("allowed edge applies");
    assert_eq!(queued.revision, 5);
    assert!(queued.transition(JobState::Checkpointed).is_err());
    let mut terminal: eliot_protocol::dreamer_job::DurableJobRecord =
        serde_json::from_value(record_json(Completed)).expect("terminal record");
    assert!(terminal.transition(Partial).is_err());
    assert!(terminal.transition(Completed).is_ok());
    let mut unknown: eliot_protocol::dreamer_job::DurableJobRecord =
        serde_json::from_value(record_json(UnknownOutcome)).expect("unknown record");
    assert!(unknown.transition(Running).is_err());
    // The closed eleven-state vocabulary has no CandidateReady or
    // CancelRequested member: the match below is exhaustive without a
    // wildcard, so adding such a variant breaks this test at compile time.
    for state in all {
        let name = match state {
            NotStarted => "NOT_STARTED",
            Queued => "QUEUED",
            Leased => "LEASED",
            Running => "RUNNING",
            Checkpointed => "CHECKPOINTED",
            Verifying => "VERIFYING",
            Completed => "COMPLETED",
            Partial => "PARTIAL",
            Failed => "FAILED",
            Cancelled => "CANCELLED",
            UnknownOutcome => "UNKNOWN_OUTCOME",
        };
        assert!(!name.is_empty());
    }
}

// WORK_UNIT_CASE: 775/4
#[tokio::test]
async fn case_04_revision_race_single_commit() {
    let harness = Harness::fresh("case-04").await;
    let job = "job-775-04";
    let attempt = "attempt-775-04";

    // Two independent clients submit the same job/attempt under distinct
    // operation identities concurrently: the provider CAS admits exactly one.
    let submit_a = make_request(
        submit_operation(job, attempt, "input-775-04"),
        JobRole::Requester,
        "operation-775-04-submit-a",
        "stable-775-04-submit-a",
        "fresh-775-04-submit-a",
    );
    let submit_b = make_request(
        submit_operation(job, attempt, "input-775-04"),
        JobRole::Requester,
        "operation-775-04-submit-b",
        "stable-775-04-submit-b",
        "fresh-775-04-submit-b",
    );
    let adapter = harness.adapter();
    let ctx_a = ctx("ctx-775-04-a");
    let ctx_b = ctx("ctx-775-04-b");
    let (first, second) = tokio::join!(
        adapter.dreamer_job(&ctx_a, submit_a),
        adapter.dreamer_job(&ctx_b, submit_b),
    );
    let (winner, loser_error) = match (first, second) {
        (Ok(response), Err(error)) | (Err(error), Ok(response)) => (response, error),
        (Ok(_), Ok(_)) => panic!("two submit winners: CAS failed to exclude"),
        (Err(first), Err(second)) => panic!("no submit winner: {first:?} / {second:?}"),
    };
    assert_eq!(winner.state, JobState::Queued);
    assert_eq!(winner.revision, 1);
    assert!(
        is_identity_conflict(&loser_error),
        "submit loser fails with identity conflict, got: {loser_error:?}"
    );

    // Exactly one durable record exists: status observes it once.
    let status = make_request(
        status_operation(job, attempt, 1),
        JobRole::Requester,
        "operation-775-04-status",
        "stable-775-04-status",
        "fresh-775-04-status",
    );
    let observed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-04-status"), status)
        .await
        .expect("single record observes");
    assert_eq!(observed.state, JobState::Queued);
    assert_eq!(observed.revision, 1);
}

// WORK_UNIT_CASE: 775/5
#[tokio::test]
async fn case_05_lease_race_and_owner_replay() {
    let harness = Harness::fresh("case-05").await;
    let job = "job-775-05";
    let attempt = "attempt-775-05";

    let submit = make_request(
        submit_operation(job, attempt, "input-775-05"),
        JobRole::Requester,
        "operation-775-05-submit",
        "stable-775-05-submit",
        "fresh-775-05-submit",
    );
    harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-05-submit"), submit)
        .await
        .expect("submit commits");

    // Two independent workers race `LeaseExact` at one expected revision with
    // distinct operation identities; exclusion is decided by the provider CAS
    // inside one transaction (no process lock is held).
    let lease_a = make_request(
        lease_exact_operation(job, "worker-a-775-05", 1),
        JobRole::Worker,
        "operation-775-05-lease-a",
        "stable-775-05-lease-a",
        "fresh-775-05-lease-a",
    );
    let lease_b = make_request(
        lease_exact_operation(job, "worker-b-775-05", 1),
        JobRole::Worker,
        "operation-775-05-lease-b",
        "stable-775-05-lease-b",
        "fresh-775-05-lease-b",
    );
    let adapter = harness.adapter();
    let ctx_a = ctx("ctx-775-05-a");
    let ctx_b = ctx("ctx-775-05-b");
    let (first, second) = tokio::join!(
        adapter.dreamer_job(&ctx_a, lease_a.clone()),
        adapter.dreamer_job(&ctx_b, lease_b),
    );
    let (winner, loser_error) = match (first, second) {
        (Ok(response), Err(error)) | (Err(error), Ok(response)) => (response, error),
        (Ok(_), Ok(_)) => panic!("two lease winners: CAS failed to exclude"),
        (Err(first), Err(second)) => panic!("no lease winner: {first:?} / {second:?}"),
    };
    assert_eq!(winner.state, JobState::Leased);
    let lease = winner.lease.clone().expect("winner holds a lease");
    assert!(
        lease.owner_artifact_id.as_str() == "worker-a-775-05"
            || lease.owner_artifact_id.as_str() == "worker-b-775-05"
    );
    assert!(
        is_revision_conflict(&loser_error),
        "lease loser fails with CAS conflict, got: {loser_error:?}"
    );

    // Exact owner replay (same operation identity) returns the identical
    // lease instead of conflicting or double-leasing.
    let replayed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-05-replay"), lease_a)
        .await
        .expect("owner replay succeeds");
    assert_eq!(replayed.state, JobState::Leased);
    assert_eq!(replayed.lease, winner.lease);
    assert_eq!(replayed.receipt_id, winner.receipt_id);

    // A fresh lease attempt after the race is stale, not a second lease.
    let late = make_request(
        lease_exact_operation(job, "worker-c-775-05", 1),
        JobRole::Worker,
        "operation-775-05-lease-c",
        "stable-775-05-lease-c",
        "fresh-775-05-lease-c",
    );
    let late_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-05-late"), late)
        .await
        .expect_err("late lease is stale");
    assert!(is_revision_conflict(&late_error));
}

// WORK_UNIT_CASE: 775/6
#[tokio::test]
async fn case_06_stale_pins_not_applied() {
    let harness = Harness::fresh("case-06").await;
    let job = "job-775-06";
    let attempt = "attempt-775-06";
    let (_submitted, leased, lease) =
        submit_and_lease(&harness, "06", job, attempt, "worker-775-06").await;
    let issued = issued_of(&lease);

    // Stale fence: identity, operation, and context agree on a foreign fence
    // so K0 construction succeeds and the adapter's stored-fence pin refuses.
    let foreign = foreign_fence_json();
    let mut stale_selector: eliot_protocol::dreamer_job::LeaseSelector =
        serde_json::from_value(lease_selector_json(1, "worker-stale-775-06", 8)).expect("selector");
    stale_selector.expected_fence = serde_json::from_value(foreign.clone()).expect("foreign fence");
    let stale_fence = make_request_unchecked_with_fence(
        JobOperation::LeaseExact {
            selector: stale_selector,
            job_id: TaskId::new(job).expect("job"),
        },
        JobRole::Worker,
        "operation-775-06-stale-fence",
        "stable-775-06-stale-fence",
        "fresh-775-06-stale-fence",
        &foreign,
    );
    stale_fence.validate().expect("stale request constructs");
    let mut stale_ctx = ctx("ctx-775-06-stale-fence");
    stale_ctx.state_fence = serde_json::from_value(foreign).expect("foreign fence");
    let fence_error = harness
        .adapter()
        .dreamer_job(&stale_ctx, stale_fence)
        .await
        .expect_err("stale fence fails");
    assert!(matches!(fence_error, StoreError::FenceMismatch));

    // Stale revision on a pure observation.
    let stale_status = make_request(
        status_operation(job, attempt, 999),
        JobRole::Worker,
        "operation-775-06-stale-rev",
        "stable-775-06-stale-rev",
        "fresh-775-06-stale-rev",
    );
    let revision_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-06-stale-rev"), stale_status)
        .await
        .expect_err("stale revision fails");
    assert!(is_revision_conflict(&revision_error));

    // Stale state: starting requires the active lease at an executable state,
    // and a fabricated lease is never the active owner.
    let foreign_lease = json!({
        "job_id": job,
        "attempt_id": attempt,
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-775-06-foreign",
        },
        "owner_artifact_id": "worker-foreign-775-06",
        "resource_generation": 1,
        "state_fence": fence_json(),
        "issued_at_unix_ms": 1_000,
        "expires_at_unix_ms": 61_000,
        "revision": 1,
    });
    let foreign_start = make_request(
        lease_op_json("START_JOB", &foreign_lease, 2_000),
        JobRole::Worker,
        "operation-775-06-foreign-start",
        "stable-775-06-foreign-start",
        "fresh-775-06-foreign-start",
    );
    let foreign_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-06-foreign-start"), foreign_start)
        .await
        .expect_err("foreign lease fails");
    assert!(is_revision_conflict(&foreign_error));

    // Expired time evidence: renewal past the server-issued window cannot
    // apply, and the lease is untouched afterwards.
    let expired_renew = make_request_unchecked(
        lease_op_json("RENEW_LEASE", &lease, issued + LEASE_TTL_MS + 1),
        JobRole::Worker,
        "operation-775-06-expired-renew",
        "stable-775-06-expired-renew",
        "fresh-775-06-expired-renew",
    );
    let expired_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-06-expired-renew"), expired_renew)
        .await
        .expect_err("expired renewal fails");
    assert!(is_revision_conflict(&expired_error));

    // Superseded ownership: a timely renewal rotates the expiry, and the
    // pre-renewal lease can no longer start the job.
    let renewed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(
            &ctx("ctx-775-06-renew"),
            make_request(
                lease_op_json("RENEW_LEASE", &lease, issued + 1_000),
                JobRole::Worker,
                "operation-775-06-renew",
                "stable-775-06-renew",
                "fresh-775-06-renew",
            ),
        )
        .await
        .expect("renewal commits");
    assert_eq!(renewed.state, JobState::Leased);
    let renewed_lease = lease_value_of(&renewed);
    assert_eq!(issued_of(&renewed_lease), issued);
    let stale_start = make_request(
        lease_op_json("START_JOB", &lease, issued + 2_000),
        JobRole::Worker,
        "operation-775-06-stale-start",
        "stable-775-06-stale-start",
        "fresh-775-06-stale-start",
    );
    let stale_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-775-06-stale-start"), stale_start)
        .await
        .expect_err("superseded lease fails");
    assert!(is_revision_conflict(&stale_error));

    // The renewed lease starts exactly once; the record is unchanged by every
    // stale attempt above (still leased at revision 1).
    let started: DurableJobResponse = harness
        .adapter()
        .dreamer_job(
            &ctx("ctx-775-06-start"),
            make_request(
                lease_op_json("START_JOB", &renewed_lease, issued + 3_000),
                JobRole::Worker,
                "operation-775-06-start",
                "stable-775-06-start",
                "fresh-775-06-start",
            ),
        )
        .await
        .expect("start commits");
    assert_eq!(started.state, JobState::Running);
    assert_eq!(started.revision, leased.revision + 1);
}

/// Runs one worker lifecycle step through the public API.
async fn lifecycle_step(
    adapter: &SurrealStoreAdapter,
    operation: JobOperation,
    role: JobRole,
    op: &str,
    stable: &str,
    fresh: &str,
) -> DurableJobResponse {
    adapter
        .dreamer_job(
            &ctx(fresh),
            make_request(operation, role, op, stable, fresh),
        )
        .await
        .expect("lifecycle step commits")
}

// WORK_UNIT_CASE: 775/7
#[tokio::test]
async fn case_07_verifying_vs_result() {
    let harness = Harness::fresh("case-07").await;
    let job = "job-775-07";
    let attempt = "attempt-775-07";
    let (_submitted, leased, lease) =
        submit_and_lease(&harness, "07", job, attempt, "worker-775-07").await;
    let issued = issued_of(&lease);
    let checkpoint = checkpoint_json("checkpoint-775-07-1");
    let adapter = harness.adapter();

    let started = lifecycle_step(
        adapter,
        lease_op_json("START_JOB", &lease, issued + 1_000),
        JobRole::Worker,
        "operation-775-07-start",
        "stable-775-07-start",
        "ctx-775-07-start",
    )
    .await;
    assert_eq!(started.state, JobState::Running);

    // A terminal candidate straight from running is illegal: results must
    // pass through verification; VERIFYING itself is not a result.
    let direct = make_request(
        publish_op_json(
            &lease_value_of(&started),
            &outcome_json("COMPLETED", Some(&content_ref("output")), &[], None),
            issued + 2_000,
        ),
        JobRole::Worker,
        "operation-775-07-direct",
        "stable-775-07-direct",
        "ctx-775-07-direct",
    );
    let direct_error = adapter
        .dreamer_job(&ctx("ctx-775-07-direct-ctx"), direct)
        .await
        .expect_err("direct publish is illegal");
    assert!(matches!(direct_error, StoreError::InvalidProjection));

    let checkpointed = lifecycle_step(
        adapter,
        checkpoint_op_json(
            &lease_value_of(&started),
            &checkpoint,
            issued + 3_000,
            false,
        ),
        JobRole::Worker,
        "operation-775-07-checkpoint",
        "stable-775-07-checkpoint",
        "ctx-775-07-checkpoint",
    )
    .await;
    assert_eq!(checkpointed.state, JobState::Checkpointed);
    assert!(checkpointed.checkpoint.is_some());

    let resumed = lifecycle_step(
        adapter,
        checkpoint_op_json(
            &lease_value_of(&checkpointed),
            &checkpoint,
            issued + 4_000,
            true,
        ),
        JobRole::Worker,
        "operation-775-07-resume",
        "stable-775-07-resume",
        "ctx-775-07-resume",
    )
    .await;
    assert_eq!(resumed.state, JobState::Running);

    let checkpointed_again = lifecycle_step(
        adapter,
        checkpoint_op_json(
            &lease_value_of(&resumed),
            &checkpoint,
            issued + 5_000,
            false,
        ),
        JobRole::Worker,
        "operation-775-07-checkpoint-2",
        "stable-775-07-checkpoint-2",
        "ctx-775-07-checkpoint-2",
    )
    .await;
    let verifying = lifecycle_step(
        adapter,
        begin_verify_op_json(
            &lease_value_of(&checkpointed_again),
            &content_ref("result-775-07"),
            issued + 6_000,
        ),
        JobRole::Worker,
        "operation-775-07-verify",
        "stable-775-07-verify",
        "ctx-775-07-verify",
    )
    .await;
    assert_eq!(verifying.state, JobState::Verifying);
    assert!(verifying.result_under_verification.is_some());
    assert!(verifying.outcome.is_none());

    // A partial outcome without unresolved work is invalid evidence: the
    // closed contract refuses it before any provider write.
    let bad_partial = make_request_unchecked(
        publish_op_json(
            &lease_value_of(&verifying),
            &outcome_json("PARTIAL", None, &[], None),
            issued + 7_000,
        ),
        JobRole::Worker,
        "operation-775-07-bad-partial",
        "stable-775-07-bad-partial",
        "ctx-775-07-bad-partial",
    );
    let partial_error = adapter
        .dreamer_job(&ctx("ctx-775-07-bad-partial-ctx"), bad_partial)
        .await
        .expect_err("empty partial is invalid");
    assert!(matches!(partial_error, StoreError::InvalidReceipt));

    let completed = lifecycle_step(
        adapter,
        publish_op_json(
            &lease_value_of(&verifying),
            &outcome_json("COMPLETED", Some(&content_ref("output")), &[], None),
            issued + 8_000,
        ),
        JobRole::Worker,
        "operation-775-07-publish",
        "stable-775-07-publish",
        "ctx-775-07-publish",
    )
    .await;
    assert_eq!(completed.state, JobState::Completed);
    assert!(completed.outcome.is_some());
    assert!(completed.result_under_verification.is_none());
    assert!(completed.lease.is_none());

    // Terminal history is immutable: even the valid active lease (released at
    // publish) can no longer move the job.
    let terminal_start = make_request(
        lease_op_json("START_JOB", &lease_value_of(&verifying), issued + 9_000),
        JobRole::Worker,
        "operation-775-07-terminal-start",
        "stable-775-07-terminal-start",
        "ctx-775-07-terminal-start",
    );
    let terminal_error = adapter
        .dreamer_job(&ctx("ctx-775-07-terminal-start-ctx"), terminal_start)
        .await
        .expect_err("terminal is immutable");
    assert!(is_revision_conflict(&terminal_error));
    assert_eq!(leased.revision, 1);
}

// WORK_UNIT_CASE: 775/8
#[tokio::test]
async fn case_08_cancel_request_vs_cancelled() {
    let harness = Harness::fresh("case-08").await;
    let job = "job-775-08";
    let attempt = "attempt-775-08";
    let (_submitted, leased, lease) =
        submit_and_lease(&harness, "08", job, attempt, "worker-775-08").await;
    let issued = issued_of(&lease);
    let adapter = harness.adapter();

    let started: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-08-start"),
            make_request(
                lease_op_json("START_JOB", &lease, issued + 1_000),
                JobRole::Worker,
                "operation-775-08-start",
                "stable-775-08-start",
                "fresh-775-08-start",
            ),
        )
        .await
        .expect("start commits");
    assert_eq!(started.state, JobState::Running);

    // A worker may not request cancellation: only requester/controller roles.
    let worker_cancel = make_request_unchecked(
        request_cancel_operation(job, attempt, "worker asks", issued + 1_500),
        JobRole::Worker,
        "operation-775-08-worker-cancel",
        "stable-775-08-worker-cancel",
        "fresh-775-08-worker-cancel",
    );
    let role_error = adapter
        .dreamer_job(&ctx("ctx-775-08-worker-cancel"), worker_cancel)
        .await
        .expect_err("worker cancel is denied");
    assert!(matches!(role_error, StoreError::UnknownOperation));

    // Cancellation-requested is recorded evidence: the job keeps running and
    // there is no CancelRequested job state.
    let requested: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-08-cancel"),
            make_request(
                request_cancel_operation(job, attempt, "operator hold", issued + 2_000),
                JobRole::Requester,
                "operation-775-08-cancel",
                "stable-775-08-cancel",
                "fresh-775-08-cancel",
            ),
        )
        .await
        .expect("cancel request commits");
    assert_eq!(requested.state, JobState::Running);
    assert_ne!(requested.state, JobState::Cancelled);
    assert_eq!(requested.revision, started.revision + 1);
    assert_eq!(requested.disposition, Some(MutationDisposition::Committed));

    // Only the terminal publish actually cancels the job.
    let cancelled: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-08-publish"),
            make_request(
                publish_op_json(
                    &lease_value_of(&requested),
                    &outcome_json("CANCELLED", None, &[], Some("operator hold")),
                    issued + 3_000,
                ),
                JobRole::Worker,
                "operation-775-08-publish",
                "stable-775-08-publish",
                "fresh-775-08-publish",
            ),
        )
        .await
        .expect("cancel publish commits");
    assert_eq!(cancelled.state, JobState::Cancelled);

    // Cancellation after the terminal outcome is deterministically refused.
    let late_cancel = make_request(
        request_cancel_operation(job, attempt, "too late", issued + 4_000),
        JobRole::Requester,
        "operation-775-08-late",
        "stable-775-08-late",
        "fresh-775-08-late",
    );
    let late_error = adapter
        .dreamer_job(&ctx("ctx-775-08-late"), late_cancel)
        .await
        .expect_err("cancel after terminal fails");
    assert!(is_revision_conflict(&late_error));
    assert_eq!(leased.revision, 1);
}

// WORK_UNIT_CASE: 775/9
#[tokio::test]
async fn case_09_pre_submit_failure_proven_not_applied() {
    let harness = Harness::fresh("case-09").await;
    let job = "job-775-09";
    let attempt = "attempt-775-09";
    let adapter = harness.adapter();

    // A fence mismatch is refused at the gate, before any provider write.
    let mut bad_ctx = ctx("ctx-775-09-bad");
    bad_ctx.state_fence = serde_json::from_value(foreign_fence_json()).expect("foreign fence");
    let submit = make_request(
        submit_operation(job, attempt, "input-775-09"),
        JobRole::Requester,
        "operation-775-09-submit",
        "stable-775-09-submit",
        "fresh-775-09-submit",
    );
    let fence_error = adapter
        .dreamer_job(&bad_ctx, submit.clone())
        .await
        .expect_err("fence mismatch fails before submission");
    assert!(matches!(fence_error, StoreError::FenceMismatch));

    // A digest mismatch is refused before any provider write as well.
    let mut tampered = submit.clone();
    tampered.request_identity.canonical_request_hash = "4".repeat(64);
    let digest_error = adapter
        .dreamer_job(&ctx("ctx-775-09-tampered"), tampered)
        .await
        .expect_err("digest mismatch fails before submission");
    assert!(is_identity_conflict(&digest_error));

    // Proven not-applied: no row exists, and the clean submit still commits
    // exactly once afterwards.
    let probe = make_request(
        status_operation(job, attempt, 1),
        JobRole::Requester,
        "operation-775-09-probe",
        "stable-775-09-probe",
        "fresh-775-09-probe",
    );
    let absent = adapter
        .dreamer_job(&ctx("ctx-775-09-probe"), probe)
        .await
        .expect_err("nothing was persisted");
    assert!(is_revision_conflict(&absent));
    let committed: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-09-clean"), submit)
        .await
        .expect("clean submit commits");
    assert_eq!((committed.state, committed.revision), (JobState::Queued, 1));
}

// WORK_UNIT_CASE: 775/10
#[test]
fn case_10_ambiguous_post_submit_is_store_uncertainty() {
    // Possible-commit transport outcomes map to reconciling
    // `MissingReceiptEnvelope`, never to generic `Unavailable`: the caller
    // must reconcile by exact operation identity instead of blindly retrying.
    let unknown = AdapterError::UnknownOutcome {
        operation_id: "operation-775-10-ambiguous".to_owned(),
    };
    assert_eq!(
        unknown.into_store_error(),
        StoreError::MissingReceiptEnvelope
    );
    assert_eq!(
        AdapterError::PartialOutcome.into_store_error(),
        StoreError::MissingReceiptEnvelope
    );
    // Pure transport loss stays retryable and distinct from uncertainty.
    assert_eq!(
        AdapterError::ProviderUnavailable.into_store_error(),
        StoreError::Unavailable
    );
    // Provider CAS conflict stays a deterministic revision conflict.
    assert_eq!(
        AdapterError::ProviderConflict.into_store_error(),
        StoreError::RevisionConflict
    );
    // The committed semantic UNKNOWN_OUTCOME lifecycle state is a different
    // type from Store commit uncertainty: one is a terminal job result owned
    // by the ledger, the other is a reconciling store disposition.
    assert!(JobState::UnknownOutcome.is_terminal());
    assert_ne!(
        MutationDisposition::StillUnknown,
        MutationDisposition::Committed
    );
    let display = format!("{}", StoreError::MissingReceiptEnvelope);
    assert!(display.contains("unknown"));
    assert!(!format!("{:?}", JobState::UnknownOutcome).contains("MissingReceiptEnvelope"));
}

// WORK_UNIT_CASE: 775/11
#[tokio::test]
async fn case_11_reconcile_to_committed() {
    let harness = Harness::fresh("case-11").await;
    let job = "job-775-11";
    let attempt = "attempt-775-11";
    let adapter = harness.adapter();

    let submit = make_request(
        submit_operation(job, attempt, "input-775-11"),
        JobRole::Requester,
        "operation-775-11-submit",
        "stable-775-11-submit",
        "fresh-775-11-submit",
    );
    let committed: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-11-submit"), submit.clone())
        .await
        .expect("submit commits");
    let binding = binding_of(&submit);
    let hash = hash_of(&submit);
    let receipt = receipt_string_of(&committed);

    // Reconciliation of the exact committed mutation returns the committed
    // record bound to the fresh reconcile identity: same state, revision,
    // and owner receipt.
    let mutation = reconcile_mutation_json(
        job,
        attempt,
        &binding,
        &hash,
        "COMMITTED",
        Some("QUEUED"),
        Some(&receipt),
    );
    let reconciled: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-11-reconcile"),
            make_reconcile_request(
                mutation,
                &binding,
                &hash,
                JobRole::Requester,
                "fresh-775-11-reconcile",
            ),
        )
        .await
        .expect("reconcile resolves committed");
    assert_eq!(reconciled.state, JobState::Queued);
    assert_eq!(reconciled.revision, committed.revision);
    assert_eq!(reconciled.receipt_id, committed.receipt_id);
    assert_eq!(reconciled.disposition, Some(MutationDisposition::Committed));

    // A mismatched receipt is not committed success.
    let bad_receipt = reconcile_mutation_json(
        job,
        attempt,
        &binding,
        &hash,
        "COMMITTED",
        Some("QUEUED"),
        Some("dreamer-receipt-operation-775-11-other"),
    );
    let receipt_error = adapter
        .dreamer_job(
            &ctx("ctx-775-11-bad-receipt"),
            make_reconcile_request(
                bad_receipt,
                &binding,
                &hash,
                JobRole::Requester,
                "fresh-775-11-bad-receipt",
            ),
        )
        .await
        .expect_err("mismatched receipt fails");
    assert!(matches!(receipt_error, StoreError::InvalidReceipt));

    // A mismatched committed state is not committed success either.
    let bad_state = reconcile_mutation_json(
        job,
        attempt,
        &binding,
        &hash,
        "COMMITTED",
        Some("RUNNING"),
        Some(&receipt),
    );
    let state_error = adapter
        .dreamer_job(
            &ctx("ctx-775-11-bad-state"),
            make_reconcile_request(
                bad_state,
                &binding,
                &hash,
                JobRole::Requester,
                "fresh-775-11-bad-state",
            ),
        )
        .await
        .expect_err("mismatched state fails");
    assert!(matches!(state_error, StoreError::InvalidReceipt));
}

// WORK_UNIT_CASE: 775/12
#[tokio::test]
async fn case_12_absence_vs_unknown() {
    let harness = Harness::fresh("case-12").await;
    let job = "job-775-12";
    let attempt = "attempt-775-12";
    let adapter = harness.adapter();

    let submit = make_request(
        submit_operation(job, attempt, "input-775-12"),
        JobRole::Requester,
        "operation-775-12-submit",
        "stable-775-12-submit",
        "fresh-775-12-submit",
    );
    let committed: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-12-submit"), submit)
        .await
        .expect("submit commits");

    // Proven absence: a never-committed operation identity against an existing
    // job answers not-applied with the current record binding, and the record
    // is unchanged afterwards (no blind retry, no mutation).
    let phantom_binding = json!({
        "operation_id": "operation-775-12-phantom",
        "request_id": "originating-775",
        "idempotency_key": "stable-775-12-phantom",
        "operation_kind": "RENEW_LEASE",
        "effect": "CANDIDATE",
        "state_fence": fence_json(),
    });
    let phantom_hash = "3".repeat(64);
    let phantom = reconcile_mutation_json(
        job,
        attempt,
        &phantom_binding,
        &phantom_hash,
        "PROVEN_NOT_APPLIED",
        None,
        None,
    );
    let proven: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-12-phantom"),
            make_reconcile_request(
                phantom,
                &phantom_binding,
                &phantom_hash,
                JobRole::Worker,
                "fresh-775-12-phantom",
            ),
        )
        .await
        .expect("proven absence resolves");
    assert_eq!(
        proven.disposition,
        Some(MutationDisposition::ProvenNotApplied)
    );
    assert_eq!(proven.state, committed.state);
    assert_eq!(proven.revision, committed.revision);
    assert!(proven.receipt_id.is_none());

    let probe = make_request(
        status_operation(job, attempt, committed.revision),
        JobRole::Requester,
        "operation-775-12-probe",
        "stable-775-12-probe",
        "fresh-775-12-probe",
    );
    let unchanged: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-12-probe"), probe)
        .await
        .expect("record unchanged");
    assert_eq!(unchanged.revision, committed.revision);

    // Still-unknown: with neither operation nor job evidence, reconciliation
    // honestly reports uncertainty instead of fabricating not-applied, and the
    // identical retry is deterministic.
    let ghost_binding = json!({
        "operation_id": "operation-775-12-ghost",
        "request_id": "originating-775",
        "idempotency_key": "stable-775-12-ghost",
        "operation_kind": "SUBMIT_JOB",
        "effect": "CANDIDATE",
        "state_fence": fence_json(),
    });
    let ghost_hash = "5".repeat(64);
    let ghost = reconcile_mutation_json(
        "job-775-12-ghost",
        "attempt-775-12-ghost",
        &ghost_binding,
        &ghost_hash,
        "STILL_UNKNOWN",
        None,
        None,
    );
    for suffix in ["first", "repeat"] {
        let error = adapter
            .dreamer_job(
                &ctx(&format!("ctx-775-12-ghost-{suffix}")),
                make_reconcile_request(
                    ghost.clone(),
                    &ghost_binding,
                    &ghost_hash,
                    JobRole::Requester,
                    &format!("fresh-775-12-ghost-{suffix}"),
                ),
            )
            .await
            .expect_err("ghost stays unknown");
        assert!(
            matches!(error, StoreError::MissingReceiptEnvelope),
            "ghost fails as still-unknown, got: {error:?}"
        );
    }
}

// WORK_UNIT_CASE: 775/13
#[test]
fn case_13_digest_mismatch_fails_closed() {
    let ledger = valid_ledger_record("job-775-13", "attempt-775-13");
    let mut tampered_digest = ledger.clone();
    tampered_digest.record_digest = "f".repeat(64);
    assert!(tampered_digest.validate().is_err());

    let mut tampered_revision = ledger.clone();
    tampered_revision.record.revision += 1;
    assert!(tampered_revision.validate().is_err());

    let event = valid_ledger_event("job-775-13", "attempt-775-13");
    let mut tampered_event = event.clone();
    tampered_event.event_digest = "e".repeat(64);
    assert!(tampered_event.validate().is_err());

    // The recovery envelope digest binds exact payload bytes.
    let record: RecoveryRecord = serde_json::from_value(json!({
        "namespace": "dreamer-job-v1",
        "key": "job_probe",
        "state_fence": fence_json(),
        "revision": 1,
        "schema": "eliot.storage.dreamer-job.v1:ledger-record",
        "payload": [1, 2, 3],
        "value_digest": "0".repeat(64),
    }))
    .expect("recovery record parses");
    assert!(record.validate().is_err());

    // Mutation identity binds the closed vocabulary plus the digest shape.
    let mut identity: DreamerJobMutationIdentity =
        serde_json::from_value(mutation_identity_json("operation-775-13-x")).expect("identity");
    assert!(identity.validate().is_ok());
    identity.canonical_request_hash = "zz".to_owned();
    assert!(identity.validate().is_err());
    identity.canonical_request_hash = "0".repeat(64);
    identity.operation_kind = "CANDIDATE_READY".to_owned();
    assert!(identity.validate().is_err());

    // A receipt binding that disagrees with the record cannot validate as one
    // bundle: the positive control passes, the tampered one fails.
    let submit = make_request(
        submit_operation("job-775-13", "attempt-775-13", "input-775-13"),
        JobRole::Requester,
        "operation-775-13-submit",
        "stable-775-13-submit",
        "fresh-775-13-submit",
    );
    let (response, record_value, event_value) =
        bundle_parts(&submit, "job-775-13", "attempt-775-13");
    response.validate_for(&submit).expect("response binds");
    record_value.validate().expect("record validates");
    event_value.validate().expect("event validates");
    eliot_store_api::validate_ledger_bundle(&submit, &response, &record_value, &event_value)
        .expect("positive bundle validates");
    let mut forked = record_value.clone();
    forked.last_receipt_id = Some(
        serde_json::from_value(Value::String(
            "dreamer-receipt-operation-775-13-other".to_owned(),
        ))
        .expect("receipt id"),
    );
    forked.record_digest = forked.compute_digest().expect("digest");
    assert!(
        eliot_store_api::validate_ledger_bundle(&submit, &response, &forked, &event_value).is_err()
    );
}

// WORK_UNIT_CASE: 775/14
#[tokio::test]
async fn case_14_missing_receipt_cannot_claim_committed() {
    let harness = Harness::fresh("case-14").await;
    let job = "job-775-14";
    let attempt = "attempt-775-14";
    let adapter = harness.adapter();

    // Every committed mutation carries its owner receipt; pure observations
    // never do.
    let submit = make_request(
        submit_operation(job, attempt, "input-775-14"),
        JobRole::Requester,
        "operation-775-14-submit",
        "stable-775-14-submit",
        "fresh-775-14-submit",
    );
    let committed: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-14-submit"), submit.clone())
        .await
        .expect("submit commits");
    assert!(committed.receipt_id.is_some());
    let status = make_request(
        status_operation(job, attempt, committed.revision),
        JobRole::Requester,
        "operation-775-14-status",
        "stable-775-14-status",
        "fresh-775-14-status",
    );
    let observed: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-14-status"), status)
        .await
        .expect("status observes");
    assert!(observed.receipt_id.is_none());
    assert!(observed.disposition.is_none());

    // Claiming committed for an operation with no stored receipt fails as an
    // invalid receipt, and does not create anything.
    let phantom_binding = json!({
        "operation_id": "operation-775-14-phantom",
        "request_id": "originating-775",
        "idempotency_key": "stable-775-14-phantom",
        "operation_kind": "SUBMIT_JOB",
        "effect": "CANDIDATE",
        "state_fence": fence_json(),
    });
    let phantom_hash = "6".repeat(64);
    let claim = reconcile_mutation_json(
        job,
        attempt,
        &phantom_binding,
        &phantom_hash,
        "COMMITTED",
        Some("QUEUED"),
        Some("dreamer-receipt-operation-775-14-phantom"),
    );
    let error = adapter
        .dreamer_job(
            &ctx("ctx-775-14-claim"),
            make_reconcile_request(
                claim,
                &phantom_binding,
                &phantom_hash,
                JobRole::Requester,
                "fresh-775-14-claim",
            ),
        )
        .await
        .expect_err("receipt-less claim fails");
    assert!(
        matches!(error, StoreError::InvalidReceipt),
        "missing receipt fails as invalid receipt, got: {error:?}"
    );
    let probe = make_request(
        status_operation(job, attempt, committed.revision),
        JobRole::Requester,
        "operation-775-14-probe",
        "stable-775-14-probe",
        "fresh-775-14-probe",
    );
    let unchanged: DurableJobResponse = adapter
        .dreamer_job(&ctx("ctx-775-14-probe"), probe)
        .await
        .expect("record unchanged");
    assert_eq!(unchanged.revision, committed.revision);
}

// WORK_UNIT_CASE: 775/15
#[tokio::test]
async fn case_15_bounded_selection() {
    let harness = Harness::fresh("case-15").await;
    let adapter = harness.adapter();
    for suffix in ["a", "b", "c"] {
        let submit = make_request(
            submit_operation(
                &format!("job-775-15-{suffix}"),
                &format!("attempt-775-15-{suffix}"),
                "input-775-15",
            ),
            JobRole::Requester,
            &format!("operation-775-15-submit-{suffix}"),
            &format!("stable-775-15-submit-{suffix}"),
            &format!("fresh-775-15-submit-{suffix}"),
        );
        adapter
            .dreamer_job(&ctx(&format!("ctx-775-15-submit-{suffix}")), submit)
            .await
            .expect("submit commits");
    }

    // Deterministic queue order with complete coverage: the lowest queue key
    // leases first and every candidate is named.
    let first: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-15-next-1"),
            make_request(
                lease_next_operation("worker-775-15-1", 1, 8),
                JobRole::Worker,
                "operation-775-15-next-1",
                "stable-775-15-next-1",
                "fresh-775-15-next-1",
            ),
        )
        .await
        .expect("lease-next selects");
    assert_eq!(first.job_id.to_string(), "job-775-15-a");
    assert_eq!(first.state, JobState::Leased);
    assert_eq!(
        first.selection_coverage,
        vec![
            "job-775-15-a".to_owned(),
            "job-775-15-b".to_owned(),
            "job-775-15-c".to_owned(),
        ]
    );
    assert_eq!(
        first.selection_frontier.as_deref(),
        Some("dreamer-job:job-775-15-a:attempt-775-15-a")
    );

    // A partial page names only its bound while still leasing deterministically.
    let second: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-15-next-2"),
            make_request(
                lease_next_operation("worker-775-15-2", 1, 1),
                JobRole::Worker,
                "operation-775-15-next-2",
                "stable-775-15-next-2",
                "fresh-775-15-next-2",
            ),
        )
        .await
        .expect("bounded page selects");
    assert_eq!(second.job_id.to_string(), "job-775-15-b");
    assert_eq!(second.selection_coverage, vec!["job-775-15-b".to_owned()]);

    let third: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-15-next-3"),
            make_request(
                lease_next_operation("worker-775-15-3", 1, 8),
                JobRole::Worker,
                "operation-775-15-next-3",
                "stable-775-15-next-3",
                "fresh-775-15-next-3",
            ),
        )
        .await
        .expect("last candidate selects");
    assert_eq!(third.job_id.to_string(), "job-775-15-c");

    // Exhausted (candidates exist, none leasable) is distinct from
    // complete-empty (no candidates in scope).
    let exhausted = adapter
        .dreamer_job(
            &ctx("ctx-775-15-exhausted"),
            make_request(
                lease_next_operation("worker-775-15-4", 1, 8),
                JobRole::Worker,
                "operation-775-15-next-4",
                "stable-775-15-next-4",
                "fresh-775-15-next-4",
            ),
        )
        .await
        .expect_err("exhausted selection fails");
    assert!(is_revision_conflict(&exhausted));

    let mut empty_selector: eliot_protocol::dreamer_job::LeaseSelector =
        serde_json::from_value(lease_selector_json(1, "worker-775-15-5", 8)).expect("selector");
    empty_selector.scope_id =
        serde_json::from_value(Value::String("scope-775-15-empty".to_owned()))
            .expect("empty scope");
    let empty = adapter
        .dreamer_job(
            &ctx("ctx-775-15-empty"),
            make_request(
                JobOperation::LeaseNext {
                    selector: empty_selector,
                },
                JobRole::Worker,
                "operation-775-15-next-5",
                "stable-775-15-next-5",
                "fresh-775-15-next-5",
            ),
        )
        .await
        .expect_err("empty selection fails");
    assert!(
        matches!(empty, StoreError::Empty { .. }),
        "complete-empty is distinct, got: {empty:?}"
    );
}

// WORK_UNIT_CASE: 775/16
#[tokio::test]
async fn case_16_recovery_completeness() {
    let harness = Harness::fresh("case-16").await;
    let job = "job-775-16";
    let attempt = "attempt-775-16";
    let (_submitted, leased, _lease) =
        submit_and_lease(&harness, "16", job, attempt, "worker-775-16").await;

    let snapshot = harness
        .adapter()
        .recovery(StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: fence(),
            records: Vec::new(),
            include_receipts: false,
            include_jobs: true,
        })
        .await
        .expect("recovery snapshots");
    snapshot.validate().expect("snapshot validates");

    // The complete Dreamer namespace is present: job, two events (submit at
    // cursor 1, lease at cursor 2), two operation rows, two receipt rows.
    assert_eq!(snapshot.job_records.len(), 7);
    let mut keys: Vec<&str> = snapshot
        .job_records
        .iter()
        .map(|record| record.key.as_str())
        .collect();
    keys.sort_unstable();
    for key in &keys {
        assert!(
            key.starts_with("job_")
                || key.starts_with("event_")
                || key.starts_with("op_")
                || key.starts_with("receipt_"),
            "discriminated dreamer key: {key}"
        );
    }
    assert!(keys.iter().any(|key| key.starts_with("job_")));
    assert_eq!(
        keys.iter().filter(|key| key.starts_with("event_")).count(),
        2
    );
    assert_eq!(keys.iter().filter(|key| key.starts_with("op_")).count(), 2);
    assert_eq!(
        keys.iter()
            .filter(|key| key.starts_with("receipt_"))
            .count(),
        2
    );
    for record in &snapshot.job_records {
        assert_eq!(record.namespace, "dreamer-job-v1");
        record.validate().expect("dreamer row validates");
    }
    // Event cursors are monotonic across the two committed mutations.
    let mut cursors: Vec<u64> = snapshot
        .job_records
        .iter()
        .filter(|record| record.key.starts_with("event_"))
        .map(|record| {
            serde_json::from_slice::<DreamerJobLedgerEvent>(&record.payload)
                .expect("event decodes")
                .event_cursor
        })
        .collect();
    cursors.sort_unstable();
    assert_eq!(cursors, vec![1, 2]);

    // Other namespaces are unchanged: no owner rows, no write receipts.
    assert!(snapshot.owner_records.is_empty());
    assert!(snapshot.receipts.is_empty());
    assert_eq!(leased.state, JobState::Leased);
}

// WORK_UNIT_CASE: 775/17
#[tokio::test]
async fn case_17_schema_sufficiency_no_migration() {
    // The harness applies exactly the stock v2 baseline migration and nothing
    // else; every Dreamer key family plus CAS then works on that schema.
    let harness = Harness::fresh("case-17").await;
    let readiness = harness.adapter().probe_readiness().await.expect("ready");
    assert!(
        matches!(
            readiness,
            eliot_store_surreal_adapter::SemanticReadiness::Ready { .. }
        ),
        "stock v2 baseline is ready, got: {readiness:?}"
    );
    let job = "job-775-17";
    let attempt = "attempt-775-17";
    let (_submitted, leased, _lease) =
        submit_and_lease(&harness, "17", job, attempt, "worker-775-17").await;
    assert_eq!(leased.state, JobState::Leased);
    assert_eq!(DREAMER_JOB_LEDGER_SCHEMA, "eliot.storage.dreamer-job.v1");
    assert_eq!(MAX_DREAMER_JOB_HISTORY, 256);
}

// WORK_UNIT_CASE: 775/18
#[tokio::test]
async fn case_18_limits_and_one_over() {
    let harness = Harness::fresh("case-18").await;
    let adapter = harness.adapter();
    for suffix in ["a", "b"] {
        let submit = make_request(
            submit_operation(
                &format!("job-775-18-{suffix}"),
                &format!("attempt-775-18-{suffix}"),
                "input-775-18",
            ),
            JobRole::Requester,
            &format!("operation-775-18-submit-{suffix}"),
            &format!("stable-775-18-submit-{suffix}"),
            &format!("fresh-775-18-submit-{suffix}"),
        );
        adapter
            .dreamer_job(&ctx(&format!("ctx-775-18-submit-{suffix}")), submit)
            .await
            .expect("submit commits");
    }

    // A zero-candidate page is refused by the closed selector contract.
    let zero = make_request_unchecked(
        lease_next_operation("worker-775-18", 1, 0),
        JobRole::Worker,
        "operation-775-18-zero",
        "stable-775-18-zero",
        "fresh-775-18-zero",
    );
    let zero_error = adapter
        .dreamer_job(&ctx("ctx-775-18-zero"), zero)
        .await
        .expect_err("zero page fails");
    assert!(matches!(zero_error, StoreError::InvalidField { .. }));

    // One over the page bound is refused before any provider I/O.
    let over = make_request(
        lease_next_operation("worker-775-18", 1, 257),
        JobRole::Worker,
        "operation-775-18-over",
        "stable-775-18-over",
        "fresh-775-18-over",
    );
    let over_error = adapter
        .dreamer_job(&ctx("ctx-775-18-over"), over)
        .await
        .expect_err("one-over page fails");
    assert!(matches!(over_error, StoreError::PayloadTooLarge));

    // The bound itself pages exactly: two queued jobs fit in a 256 page.
    let at_bound: DurableJobResponse = adapter
        .dreamer_job(
            &ctx("ctx-775-18-bound"),
            make_request(
                lease_next_operation("worker-775-18", 1, 256),
                JobRole::Worker,
                "operation-775-18-bound",
                "stable-775-18-bound",
                "fresh-775-18-bound",
            ),
        )
        .await
        .expect("bound page selects");
    assert_eq!(at_bound.selection_coverage.len(), 2);
}

// WORK_UNIT_CASE: 775/19
#[test]
fn case_19_no_secrets_in_errors() {
    let marker = "job-775-19-classified-marker";
    // Requests carrying the marker fail on static validation; the typed
    // errors echo only bounded static text, never the payload.
    let mut tampered = make_request(
        submit_operation(marker, "attempt-775-19", "input-775-19"),
        JobRole::Requester,
        "operation-775-19-submit",
        "stable-775-19-submit",
        "fresh-775-19-submit",
    );
    tampered.request_identity.canonical_request_hash = "7".repeat(64);
    let validation_error = tampered.validate().expect_err("tampered hash fails");
    assert!(!format!("{validation_error:?}").contains(marker));

    for error in [
        StoreError::IdentityConflict,
        StoreError::RevisionConflict,
        StoreError::FenceMismatch,
        StoreError::UnknownOperation,
        StoreError::InvalidReceipt,
        StoreError::MissingReceiptEnvelope,
        StoreError::Unavailable,
        StoreError::PayloadTooLarge,
        StoreError::InvalidProjection,
        StoreError::EffectCeilingExceeded,
    ] {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(marker), "leak in {rendered}");
        assert!(!rendered.contains("dreamer-test-secret"));
    }
    for error in [
        AdapterError::ProviderUnavailable,
        AdapterError::PartialOutcome,
        AdapterError::ProviderConflict,
        AdapterError::MigrationRequired,
    ] {
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(marker), "leak in {rendered}");
        assert!(!rendered.contains("dreamer-test-secret"));
    }
    // The unknown-outcome message carries only the operation identity needed
    // for reconciliation, never job content.
    let unknown = format!(
        "{:?}",
        AdapterError::UnknownOutcome {
            operation_id: "operation-775-19".to_owned(),
        }
    );
    assert!(unknown.contains("operation-775-19"));
    assert!(!unknown.contains(marker));
}

// WORK_UNIT_CASE: 775/20
#[test]
fn case_20_malformed_and_delegation() {
    // Fixture rows fail closed without panicking.
    let malformed: DreamerJobMutationIdentity =
        serde_json::from_str(include_str!("data/dreamer-job/malformed-identity.json"))
            .expect("fixture parses");
    assert!(malformed.validate().is_err());
    let obsolete: DreamerJobMutationIdentity = serde_json::from_str(include_str!(
        "data/dreamer-job/obsolete-operation-kind.json"
    ))
    .expect("fixture parses");
    assert_eq!(
        obsolete.validate().expect_err("obsolete kind fails"),
        StoreError::UnknownOperation
    );
    let bad_digest: RecoveryRecord =
        serde_json::from_str(include_str!("data/dreamer-job/bad-digest-record.json"))
            .expect("fixture parses");
    assert!(bad_digest.validate().is_err());

    // Every closed operation kind delegates to a distinct advertised store
    // capability: the match is exhaustive without a wildcard, so a thirteenth
    // kind breaks this test at compile time instead of silently defaulting.
    let lease: Value = json!({
        "job_id": "job-775-20",
        "attempt_id": "attempt-775-20",
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-775-20",
        },
        "owner_artifact_id": "worker-775-20",
        "resource_generation": 1,
        "state_fence": fence_json(),
        "issued_at_unix_ms": 1_000,
        "expires_at_unix_ms": 61_000,
        "revision": 1,
    });
    let ops: Vec<JobOperation> = vec![
        submit_operation("job-775-20", "attempt-775-20", "input-775-20"),
        lease_next_operation("worker-775-20", 1, 8),
        lease_exact_operation("job-775-20", "worker-775-20", 1),
        lease_op_json("RENEW_LEASE", &lease, 2_000),
        lease_op_json("START_JOB", &lease, 2_000),
        checkpoint_op_json(&lease, &checkpoint_json("checkpoint-775-20"), 2_000, false),
        checkpoint_op_json(&lease, &checkpoint_json("checkpoint-775-20"), 2_000, true),
        begin_verify_op_json(&lease, &content_ref("result-775-20"), 2_000),
        publish_op_json(&lease, &outcome_json("FAILED", None, &[], None), 2_000),
        status_operation("job-775-20", "attempt-775-20", 1),
        request_cancel_operation("job-775-20", "attempt-775-20", "probe", 2_000),
        serde_json::from_value(json!({
            "operation": "RECONCILE_MUTATION",
            "mutation": reconcile_mutation_json(
                "job-775-20",
                "attempt-775-20",
                &json!({
                    "operation_id": "operation-775-20",
                    "request_id": "originating-775",
                    "idempotency_key": "stable-775-20",
                    "operation_kind": "SUBMIT_JOB",
                    "effect": "CANDIDATE",
                    "state_fence": fence_json(),
                }),
                &"8".repeat(64),
                "STILL_UNKNOWN",
                None,
                None,
            ),
        }))
        .expect("reconcile operation"),
    ];
    assert_eq!(ops.len(), 12);
    let mut capabilities = Vec::new();
    for operation in &ops {
        let observed = dreamer_job_capability(operation);
        let expected = match operation.kind() {
            JobOperationKind::Submit => CAPABILITY_DREAMER_JOB_SUBMIT,
            JobOperationKind::LeaseNext => CAPABILITY_DREAMER_JOB_LEASE_NEXT,
            JobOperationKind::LeaseExact => CAPABILITY_DREAMER_JOB_LEASE_EXACT,
            JobOperationKind::Renew => CAPABILITY_DREAMER_JOB_RENEW,
            JobOperationKind::Start => CAPABILITY_DREAMER_JOB_START,
            JobOperationKind::Checkpoint => CAPABILITY_DREAMER_JOB_CHECKPOINT,
            JobOperationKind::Resume => CAPABILITY_DREAMER_JOB_RESUME,
            JobOperationKind::BeginVerification => CAPABILITY_DREAMER_JOB_BEGIN_VERIFICATION,
            JobOperationKind::Publish => CAPABILITY_DREAMER_JOB_PUBLISH,
            JobOperationKind::Status => CAPABILITY_DREAMER_JOB_STATUS,
            JobOperationKind::RequestCancel => CAPABILITY_DREAMER_JOB_REQUEST_CANCEL,
            JobOperationKind::Reconcile => CAPABILITY_DREAMER_JOB_RECONCILE,
        };
        assert_eq!(observed, expected);
        assert!(observed.starts_with("store.dreamer_job."));
        capabilities.push(observed);
    }
    capabilities.sort_unstable();
    capabilities.dedup();
    assert_eq!(capabilities.len(), 12);

    // One namespace, four discriminated key families, one queue-key rule: no
    // second table, ledger, or client vocabulary.
    let queue_key = dreamer_job_queue_key(
        &TaskId::new("job-775-20").expect("job"),
        &ArtifactId::new("attempt-775-20").expect("attempt"),
    );
    assert_eq!(queue_key, "dreamer-job:job-775-20:attempt-775-20");
}

/// Builds a fully valid ledger record value for pure digest/limit proofs.
fn valid_ledger_record(job: &str, attempt: &str) -> DreamerJobLedgerRecord {
    let JobOperation::Submit { submission } = submit_operation(job, attempt, "input-775-pure")
    else {
        unreachable!("submit builder")
    };
    let submission_json = serde_json::to_value(&submission).expect("submission json");
    let queue_key = dreamer_job_queue_key(
        &TaskId::new(job).expect("job"),
        &ArtifactId::new(attempt).expect("attempt"),
    );
    let mut ledger: DreamerJobLedgerRecord = serde_json::from_value(json!({
        "record": {
            "submission": submission_json,
            "state": "QUEUED",
            "revision": 1,
            "lease": null,
            "checkpoint": null,
            "cancellation": {"state": "NONE"},
            "outcome": null,
        },
        "event_cursor": 1,
        "queue_key": queue_key,
        "active_lease": null,
        "lease_history": [],
        "result_under_verification": null,
        "last_mutation": mutation_identity_json("operation-775-pure"),
        "last_receipt_id": "dreamer-receipt-operation-775-pure",
        "record_digest": "0".repeat(64),
    }))
    .expect("ledger parses");
    ledger.record_digest = ledger.compute_digest().expect("digest");
    ledger.validate().expect("ledger validates");
    ledger
}

fn mutation_identity_json(operation_id: &str) -> Value {
    json!({
        "operation_id": operation_id,
        "idempotency_key": "stable-775-pure",
        "canonical_request_hash": "0".repeat(64),
        "operation_kind": "SUBMIT_JOB",
    })
}

fn valid_ledger_event(job: &str, attempt: &str) -> DreamerJobLedgerEvent {
    let operation = submit_operation(job, attempt, "input-775-pure");
    let mut event: DreamerJobLedgerEvent = serde_json::from_value(json!({
        "job_id": job,
        "attempt_id": attempt,
        "prior_state": "NOT_STARTED",
        "next_state": "QUEUED",
        "prior_revision": 0,
        "next_revision": 1,
        "event_cursor": 1,
        "operation": serde_json::to_value(&operation).expect("operation json"),
        "role": "REQUESTER",
        "lease": null,
        "checkpoint": null,
        "result_under_verification": null,
        "mutation": mutation_identity_json("operation-775-pure"),
        "receipt_id": "dreamer-receipt-operation-775-pure",
        "event_digest": "0".repeat(64),
    }))
    .expect("event parses");
    event.event_digest = event.compute_digest().expect("digest");
    event.validate().expect("event validates");
    event
}

/// Builds the request/response/record/event bundle parts bound to one submit.
fn bundle_parts(
    request: &DurableJobRequest,
    job: &str,
    attempt: &str,
) -> (
    DurableJobResponse,
    DreamerJobLedgerRecord,
    DreamerJobLedgerEvent,
) {
    let submission = match &request.operation {
        JobOperation::Submit { submission } => serde_json::to_value(submission).expect("json"),
        _ => unreachable!("submit request"),
    };
    let receipt: Value = Value::String("dreamer-receipt-operation-775-13-submit".to_owned());
    let response: DurableJobResponse = serde_json::from_value(json!({
        "request_identity": serde_json::to_value(&request.request_identity).expect("json"),
        "job_id": job,
        "attempt_id": attempt,
        "scope": submission.get("work_scope").cloned().expect("scope"),
        "revision": 1,
        "state": "QUEUED",
        "disposition": "COMMITTED",
        "receipt_id": receipt,
        "lease": null,
        "checkpoint": null,
        "result_under_verification": null,
        "outcome": null,
        "selection_coverage": [],
        "selection_frontier": null,
    }))
    .expect("response parses");
    let mut record = valid_ledger_record(job, attempt);
    record.last_mutation = serde_json::from_value(json!({
        "operation_id": "operation-775-13-submit",
        "idempotency_key": "stable-775-13-submit",
        "canonical_request_hash": request.request_identity.canonical_request_hash,
        "operation_kind": "SUBMIT_JOB",
    }))
    .expect("mutation");
    record.last_receipt_id = Some(serde_json::from_value(receipt.clone()).expect("receipt id"));
    record.record_digest = record.compute_digest().expect("digest");
    record.validate().expect("record validates");
    let mut event = valid_ledger_event(job, attempt);
    event.mutation = record.last_mutation.clone();
    event.receipt_id.clone_from(&record.last_receipt_id);
    event.event_digest = event.compute_digest().expect("digest");
    event.validate().expect("event validates");
    (response, record, event)
}
