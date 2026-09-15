//! Isolated real-provider transaction proof; no Governor or Kernel proof is
//! claimed by this test. Both adapters use the same neutral envelope fixture.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_epistemic_contracts::{ClaimVerdict, PositionRevision, SupportResult};
use eliot_platform_windows::WindowsPlatform;
use eliot_store_api::{
    CanonicalStoreClient, NamedReadOperation, NamedReadRequest, ReadConsistency, StoreError,
    WriteReceipt, epistemic_revision::EpistemicPositionReadback, sha256_hex,
};
use eliot_store_surreal_adapter::{SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

#[path = "../../eliot-store-api/tests/support/epistemic_envelope.rs"]
mod fixture;

type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Test-only bootstrap process; every return/panic kills and reaps this child.
struct Bootstrap(Child);
impl Drop for Bootstrap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Sandbox {
    parent: PathBuf,
    root: PathBuf,
}
impl Sandbox {
    fn new() -> ProofResult<Self> {
        let parent = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../.eliot");
        std::fs::create_dir_all(&parent)?;
        let canonical_parent = parent.canonicalize()?;
        let parent_text = canonical_parent.to_string_lossy();
        let parent = PathBuf::from(parent_text.strip_prefix(r"\\?\").unwrap_or(&parent_text));
        let root = parent.join(format!("epistemic-provider-{}", uuid::Uuid::new_v4()));
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

fn configuration(sandbox: &Sandbox) -> ProofResult<SurrealAdapterConfig> {
    let source = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
        || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
        PathBuf::from,
    );
    let exe = sandbox.root.join("surreal.exe");
    std::fs::copy(source, &exe)?;
    let data = sandbox.root.join("data");
    let work = sandbox.root.join("work");
    let temp = sandbox.root.join("temp");
    for path in [&data, &work, &temp] {
        std::fs::create_dir(path)?;
    }
    let bind = TcpListener::bind("127.0.0.1:0")?.local_addr()?.to_string();
    let roots_digest = sha256_hex(&eliot_contracts::canonical_json_bytes(&(
        data.to_string_lossy(),
        work.to_string_lossy(),
        temp.to_string_lossy(),
    ))?);
    let mut config = SurrealAdapterConfig {
        endpoint: format!("ws://{bind}/rpc"),
        namespace: "epistemic".to_owned(),
        database: "revision".to_owned(),
        // Surreal 3 decodes UUID-shaped RPC strings as UUID values; root
        // authentication requires text, so preserve an explicit text prefix.
        username: "epistemic-test".to_owned(),
        password: SecretString::new(format!("epistemic-fixture-{}", uuid::Uuid::new_v4()).into()),
        provider_bind_address: bind,
        installation_id: "epistemic-provider-test".to_owned(),
        installation_profile: "portable_dev".to_owned(),
        runtime_state_roots_digest: roots_digest,
        provider_executable_path: exe.to_string_lossy().into_owned(),
        provider_artifact_digest: sha256_hex(&std::fs::read(&exe)?),
        provider_arguments: Vec::new(),
        store_data_root: data.to_string_lossy().into_owned(),
        store_work_root: work.to_string_lossy().into_owned(),
        store_temp_root: temp.to_string_lossy().into_owned(),
        connect_timeout_ms: 30_000,
        query_timeout_ms: 30_000,
        expected_provider_major: 3,
        expected_schema_generation: SchemaGeneration::v2(),
    };
    config.provider_arguments = config.expected_provider_arguments();
    config.validate()?;
    Ok(config)
}

/// Installation-style root-user provisioning on a fresh, isolated data root.
/// Credentials travel through the child environment and never argv or logs.
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
    // The upstream setup path commits its root user before normal operation.
    // Provisioning is outside the mutation proof; reopen validates durability.
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

async fn open(
    sandbox: &Sandbox,
    config: &SurrealAdapterConfig,
) -> ProofResult<SurrealStoreAdapter> {
    let platform = WindowsPlatform::new(sandbox.root.clone())?;
    let lease = platform.retain_process_path_lease(
        std::path::Path::new(&config.provider_executable_path),
        std::path::Path::new(&config.store_work_root),
        &config.provider_artifact_digest,
    )?;
    let adapter = SurrealStoreAdapter::new(config.clone(), lease)?;
    adapter
        .connect()
        .await
        .map_err(|error| format!("provider connect: {error}"))?;
    Ok(adapter)
}

async fn apply(
    adapter: &SurrealStoreAdapter,
    envelope: &CanonicalWriteEnvelope,
) -> ProofResult<WriteReceipt> {
    Ok(CanonicalStoreClient::apply_prepared(
        adapter,
        &envelope.request,
        envelope.prepare()?,
        envelope.expected_revision_heads.clone(),
        envelope.expected_ordering_heads.clone(),
    )
    .await
    .map_err(|error| format!("apply {}: {error}", envelope.operation_id))?)
}

fn query(envelope: &CanonicalWriteEnvelope) -> NamedReadRequest {
    NamedReadRequest {
        operation: NamedReadOperation::GetCurrentEpistemicPosition,
        scope_id: Some(envelope.scope_id.clone()),
        consistency: ReadConsistency::ExactFence,
        state_fence: envelope.request.state_fence.clone(),
        parameters: BTreeMap::from([("position".to_owned(), json!("position"))]),
    }
}

#[tokio::test]
async fn real_position_cas_exact_replay_and_receipt_readback() -> ProofResult {
    let sandbox = Sandbox::new()?;
    let config = configuration(&sandbox)?;
    bootstrap(&config)?;
    let adapter = open(&sandbox, &config).await?;
    let first = fixture::envelope("first", "position", None, None)?;
    adapter
        .apply_migration(
            &SurrealStoreAdapter::v2_baseline_migration(),
            &eliot_contracts::ClockReading {
                valid_time_ms: Some(1000),
                known_time_ms: Some(1000),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            &first.request.state_fence,
        )
        .await
        .map_err(|error| format!("baseline migration: {error}"))?;
    let receipt = apply(&adapter, &first).await?;
    assert_eq!(apply(&adapter, &first).await?, receipt);
    let initial: EpistemicPositionReadback = serde_json::from_value(
        adapter
            .execute_named(query(&first))
            .await
            .map_err(|error| format!("initial position read: {error}"))?
            .payload,
    )?;
    assert_eq!(initial.receipt, receipt);
    assert_eq!(initial.positions[0].admission.position_revision.value(), 1);
    assert_eq!(initial.candidate.support[0].result, SupportResult::Unknown);
    assert_eq!(initial.candidate.claims[0].verdict, ClaimVerdict::Withheld);
    let stale = fixture::envelope("stale", "position", None, None)?;
    assert!(matches!(
        CanonicalStoreClient::apply_prepared(
            &adapter,
            &stale.request,
            stale.prepare()?,
            stale.expected_revision_heads,
            stale.expected_ordering_heads
        )
        .await,
        Err(StoreError::RevisionConflict)
    ));
    let changed = fixture::envelope("first", "other-position", None, None)?;
    assert!(matches!(
        CanonicalStoreClient::apply_prepared(
            &adapter,
            &changed.request,
            changed.prepare()?,
            changed.expected_revision_heads,
            changed.expected_ordering_heads
        )
        .await,
        Err(StoreError::IdentityConflict)
    ));
    let bad_prior = fixture::envelope(
        "bad-prior",
        "position",
        Some(PositionRevision::new(1)?),
        Some("foreign-candidate"),
    )?;
    assert!(matches!(
        CanonicalStoreClient::apply_prepared(
            &adapter,
            &bad_prior.request,
            bad_prior.prepare()?,
            bad_prior.expected_revision_heads,
            bad_prior.expected_ordering_heads
        )
        .await,
        Err(StoreError::RevisionConflict)
    ));
    let untouched: EpistemicPositionReadback =
        serde_json::from_value(adapter.execute_named(query(&first)).await?.payload)?;
    assert_eq!(untouched, initial);
    let second = fixture::envelope(
        "second",
        "position",
        Some(PositionRevision::new(1)?),
        Some(&initial.candidate.digest),
    )?;
    let second_receipt = apply(&adapter, &second).await?;
    let current: EpistemicPositionReadback =
        serde_json::from_value(adapter.execute_named(query(&first)).await?.payload)?;
    assert_eq!(current.receipt, second_receipt);
    assert_eq!(current.positions[0].admission.position_revision.value(), 2);
    assert_eq!(current.candidate.revision, initial.candidate.revision);
    assert_eq!(adapter.receipt(first.operation_id).await?, Some(receipt));
    drop(adapter);
    sandbox.cleanup()?;
    Ok(())
}
