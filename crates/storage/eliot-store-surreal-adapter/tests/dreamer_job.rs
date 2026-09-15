//! Real `SurrealDB` Dreamer ledger edge tests (S1, owner #775).
//!
//! Proves the working provider edge through the public
//! [`CanonicalStoreClient::dreamer_job`](eliot_store_api::CanonicalStoreClient)
//! API against an isolated `surreal.exe` provider: loopback bind, per-test
//! temporary `SurrealKV` roots, and redacted test credentials. No in-memory
//! stand-in, no production database, no user credentials.
//!
//! Provider evidence (recorded on failure output and in the work item): the
//! pinned `surreal.exe` path plus its SHA-256, the server `3.1.x` version
//! handshake enforced by the adapter, the per-test loopback port, and the
//! temporary data/work/tmp roots. Two cases:
//!
//! 1. `submit_status_reopen_and_single_lease_winner`: submit persists, status
//!    observes it, a fresh adapter over the same files re-observes it, and two
//!    concurrent `LeaseExact` callers at one expected revision yield exactly
//!    one winner.
//! 2. `exact_replay_returns_outcome_changed_content_conflicts`: resending the
//!    identical submit returns the original receipt/revision, while changed
//!    content under the same operation identity (or the same job under a fresh
//!    operation identity) conflicts deterministically.
//!
//! Deferred (explicitly unadvertised, not defaulted): the remaining K0
//! operations return `UnknownOperation`; the exhaustive crash matrix and
//! multi-generation migration proof belong to later slices.

#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Test-only allowances: provider-evidence logging prints bounded setup facts
//! (no credentials), and test futures necessarily hold the provider harness
//! plus ledger payloads across awaits.
#![allow(clippy::print_stdout, clippy::large_futures)]

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
    DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation, JobRole, JobState,
};
use eliot_store_api::{CanonicalStoreClient, RequestMeta, StateFence, StoreError};
use eliot_store_surreal_adapter::{
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

/// Isolated provider executable for tests. Overridable for local runs; the
/// default is the pinned local installation probed during implementation.
const TEST_SURREAL_EXE: &str = r"C:\Tools\SurrealDB\surreal.exe";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

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
        product_id: ProductId::new("product-dreamer-t12-02").expect("product"),
        source_id: SourceId::new("source-dreamer-t12-02").expect("source"),
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
            "product_id": "product-dreamer-t12-02",
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
            "requester_principal": "requester-t12-02",
            "session": null,
            "scope": {
                "scope_id": "scope-dreamer",
                "product_id": "product-dreamer-t12-02",
                "resource_generation": 1,
                "state_fence": fence,
            },
            "capability": "dreamer.submit",
            "route_class": "bounded",
            "budget_units": 1,
            "deadline_unix_ms": 600_000,
            "validity_epoch": {"lineage_id": LINEAGE, "sequence": 1},
            "resource_generation": 1,
            "admission_receipt": "admission-t12-02",
        },
        "cancellation_id": "cancel-t12-02",
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

fn status_operation(job: &str, attempt: &str, revision: u64) -> JobOperation {
    JobOperation::Status {
        job_id: TaskId::new(job).expect("job"),
        attempt_id: ArtifactId::new(attempt).expect("attempt"),
        expected_revision: revision,
        expected_fence: fence(),
    }
}

fn lease_exact_operation(job: &str, worker: &str, revision: u64) -> JobOperation {
    let selector: eliot_protocol::dreamer_job::LeaseSelector = serde_json::from_value(json!({
        "scope_id": "scope-dreamer",
        "expected_revision": revision,
        "expected_fence": fence_json(),
        "worker_artifact_id": worker,
        "max_candidates": 8,
    }))
    .expect("selector");
    JobOperation::LeaseExact {
        selector,
        job_id: TaskId::new(job).expect("job"),
    }
}

/// Binds one closed operation to fresh transport correlation plus stable
/// mutation identity with a recomputed canonical hash.
fn make_request(
    operation: JobOperation,
    role: JobRole,
    operation_id: &str,
    idempotency: &str,
    fresh: &str,
) -> DurableJobRequest {
    let kind = operation.kind().as_str().to_owned();
    let mut identity: DurableRequestIdentity = serde_json::from_value(json!({
        "request": {
            "request": {
                "metadata": {
                    "request_id": fresh,
                    "session_id": null,
                    "task_id": "job-t12-02",
                    "product_id": "product-dreamer-t12-02",
                    "source_id": "source-dreamer-t12-02",
                    "state_fence": fence_json(),
                    "clock": {"valid_time_ms": 1_000, "known_time_ms": 1_001,
                              "transaction_sequence": null, "monotonic_ns": null},
                },
                "state_fence": fence_json(),
            },
            "idempotency_key": "transport-t12-02",
            "deadline_unix_ms": 600_000,
            "cancellation_id": "cancel-t12-02",
        },
        "operation": {
            "operation_id": operation_id,
            "request_id": "originating-t12-02",
            "idempotency_key": idempotency,
            "operation_kind": kind,
            "effect": "CANDIDATE",
            "state_fence": fence_json(),
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
    let request = DurableJobRequest {
        request_identity: identity,
        role,
        operation,
    };
    request.validate().expect("request validates");
    request
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
            "eliot-dreamer-t12-02-{}-{port}-{test}",
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
        database: "dreamer_t12_02".to_owned(),
        username: "dreamer-test".to_owned(),
        password: SecretString::new("dreamer-test-secret".into()),
        provider_bind_address: bind,
        installation_id: "installation-test-t12-02".to_owned(),
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

/// Races two independent `LeaseExact` callers at one expected revision and
/// returns the single winner plus the loser's deterministic conflict.
///
/// Independence means distinct operation identities and worker artifacts
/// polled concurrently; exclusion is decided by the provider CAS inside one
/// transaction (no process lock is held), so exactly one caller commits.
async fn race_two_leases(
    adapter: &SurrealStoreAdapter,
    ctx_a: &RequestMeta,
    lease_a: DurableJobRequest,
    ctx_b: &RequestMeta,
    lease_b: DurableJobRequest,
) -> (DurableJobResponse, StoreError) {
    let (first, second) = tokio::join!(
        adapter.dreamer_job(ctx_a, lease_a),
        adapter.dreamer_job(ctx_b, lease_b),
    );
    match (first, second) {
        (Ok(response), Err(error)) | (Err(error), Ok(response)) => (response, error),
        (Ok(_), Ok(_)) => panic!("two lease winners: CAS failed to exclude"),
        (Err(first), Err(second)) => {
            panic!("no lease winner: {first:?} / {second:?}")
        }
    }
}

#[tokio::test]
async fn submit_status_reopen_and_single_lease_winner() {
    let mut harness = Harness::fresh("race").await;
    let job = "job-t12-02-race";
    let attempt = "attempt-t12-02-race";

    // Caller submits through the real public API.
    let submit = make_request(
        submit_operation(job, attempt, "input-race"),
        JobRole::Requester,
        "operation-t12-02-submit",
        "stable-t12-02-submit",
        "fresh-t12-02-submit",
    );
    let submitted: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-submit"), submit)
        .await
        .expect("submit commits");
    assert_eq!(submitted.state, JobState::Queued);
    assert_eq!(submitted.revision, 1);
    assert!(submitted.receipt_id.is_some());

    // Status observes the durable record without mutating it.
    let status = make_request(
        status_operation(job, attempt, 1),
        JobRole::Requester,
        "operation-t12-02-status",
        "stable-t12-02-status",
        "fresh-t12-02-status",
    );
    let observed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-status"), status)
        .await
        .expect("status observes");
    assert_eq!(observed.state, JobState::Queued);
    assert_eq!(observed.revision, 1);
    assert!(observed.disposition.is_none());

    // Reopen over the same files: the record survives without a second submit.
    harness.reopen().await;
    let status_after = make_request(
        status_operation(job, attempt, 1),
        JobRole::Requester,
        "operation-t12-02-status-reopen",
        "stable-t12-02-status-reopen",
        "fresh-t12-02-status-reopen",
    );
    let reopened: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-status-reopen"), status_after)
        .await
        .expect("status survives reopen");
    assert_eq!(reopened.state, JobState::Queued);
    assert_eq!(reopened.revision, 1);

    // Two independent workers race `LeaseExact` at the same expected revision.
    let lease_a = make_request(
        lease_exact_operation(job, "worker-a-t12-02", 1),
        JobRole::Worker,
        "operation-t12-02-lease-a",
        "stable-t12-02-lease-a",
        "fresh-t12-02-lease-a",
    );
    let lease_b = make_request(
        lease_exact_operation(job, "worker-b-t12-02", 1),
        JobRole::Worker,
        "operation-t12-02-lease-b",
        "stable-t12-02-lease-b",
        "fresh-t12-02-lease-b",
    );
    let adapter = harness.adapter();
    let ctx_a = ctx("ctx-t12-02-lease-a");
    let ctx_b = ctx("ctx-t12-02-lease-b");
    let (winner, loser_error) = race_two_leases(adapter, &ctx_a, lease_a, &ctx_b, lease_b).await;
    assert_eq!(winner.state, JobState::Leased);
    assert_eq!(winner.revision, 1);
    let lease = winner.lease.clone().expect("winner holds a lease");
    assert!(
        lease.owner_artifact_id.as_str() == "worker-a-t12-02"
            || lease.owner_artifact_id.as_str() == "worker-b-t12-02"
    );
    assert!(
        is_revision_conflict(&loser_error),
        "loser fails with CAS conflict, got: {loser_error:?}"
    );

    // Status now observes the winner's lease.
    let status_leased = make_request(
        status_operation(job, attempt, 1),
        JobRole::Worker,
        "operation-t12-02-status-leased",
        "stable-t12-02-status-leased",
        "fresh-t12-02-status-leased",
    );
    let leased: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-status-leased"), status_leased)
        .await
        .expect("status observes lease");
    assert_eq!(leased.state, JobState::Leased);
    assert_eq!(leased.lease, winner.lease);
}

#[tokio::test]
async fn exact_replay_returns_outcome_changed_content_conflicts() {
    let harness = Harness::fresh("replay").await;
    let job = "job-t12-02-replay";
    let attempt = "attempt-t12-02-replay";

    let submit = make_request(
        submit_operation(job, attempt, "input-replay"),
        JobRole::Requester,
        "operation-t12-02-replay",
        "stable-t12-02-replay",
        "fresh-t12-02-replay",
    );
    let first: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-replay"), submit.clone())
        .await
        .expect("submit commits");
    assert_eq!(first.revision, 1);

    // Exact replay of the identical request returns the original outcome.
    let replayed: DurableJobResponse = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-replay-again"), submit)
        .await
        .expect("exact replay succeeds");
    assert_eq!(replayed.revision, first.revision);
    assert_eq!(replayed.state, first.state);
    assert_eq!(replayed.receipt_id, first.receipt_id);

    // Changed content under the same operation identity conflicts instead of
    // overwriting the committed record.
    let changed = make_request(
        submit_operation(job, attempt, "input-changed"),
        JobRole::Requester,
        "operation-t12-02-replay",
        "stable-t12-02-replay",
        "fresh-t12-02-changed",
    );
    let conflict = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-changed"), changed)
        .await
        .expect_err("changed content conflicts");
    assert!(
        is_identity_conflict(&conflict),
        "changed content fails with identity conflict, got: {conflict:?}"
    );

    // The same job under a fresh operation identity is a duplicate creation.
    let duplicate = make_request(
        submit_operation(job, attempt, "input-replay"),
        JobRole::Requester,
        "operation-t12-02-duplicate",
        "stable-t12-02-duplicate",
        "fresh-t12-02-duplicate",
    );
    let duplicate_error = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-duplicate"), duplicate)
        .await
        .expect_err("duplicate job conflicts");
    assert!(
        is_identity_conflict(&duplicate_error),
        "duplicate job fails with identity conflict, got: {duplicate_error:?}"
    );

    // Unsupported lifecycle branches are explicitly unadvertised, never
    // defaulted to success.
    let renew = make_request(
        renew_operation(),
        JobRole::Worker,
        "operation-t12-02-renew",
        "stable-t12-02-renew",
        "fresh-t12-02-renew",
    );
    let unsupported = harness
        .adapter()
        .dreamer_job(&ctx("ctx-t12-02-renew"), renew)
        .await
        .expect_err("renew is unadvertised");
    assert!(
        matches!(unsupported, StoreError::UnknownOperation),
        "unsupported branch fails as unknown operation, got: {unsupported:?}"
    );
}

fn renew_operation() -> JobOperation {
    let lease: eliot_protocol::dreamer_job::JobLease = serde_json::from_value(json!({
        "job_id": "job-t12-02-replay",
        "attempt_id": "attempt-t12-02-replay",
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-probe",
        },
        "owner_artifact_id": "worker-probe",
        "resource_generation": 1,
        "state_fence": fence_json(),
        "issued_at_unix_ms": 1_000,
        "expires_at_unix_ms": 2_000,
        "revision": 1,
    }))
    .expect("lease");
    JobOperation::Renew {
        lease,
        now_unix_ms: 1_500,
    }
}
