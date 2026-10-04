#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use eliot_observability_runtime::{
    ObservabilityConfig, RollingLogPolicy, RuntimeProfile, SpoolPolicy,
};

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
use eliot_protocol::MessageType;
use eliot_store_surreal::diagnostics::{
    BoundedEventLog, BridgeBoundary, BridgeIdentity, CompatibilityDecision, emit_dispatch_outcome,
    emit_lifecycle, emit_received, emit_validation_rejected, install_startup_subscriber,
    project_compatibility_health, report_events, report_snapshot_budget,
};
use eliot_store_surreal::{
    CompatibilityVerdict, SERVICE_NAME, StoreComposition, StoreHandshakeIdentity,
    admit_authenticated_handshake, dispatch_with_log, install_compatibility_decision,
    load_compatibility_for_config, load_config, load_evidence_snapshot_verification,
    observed_identity_verdict, parse_compatibility_bytes, require_semantic_ready_for_pipe,
    resolve_compatibility_verdict, store_bootstrap_descriptor, validate_request_frame_with_log,
};
#[cfg(any(windows, test))]
use eliot_store_surreal_adapter::SnapshotBudgetDiagnostics;

mod launch_mode;
use launch_mode::{LaunchMode, control_frame, parse_launch_mode, prepare_launch};

/// Stable operational-log stem for this process. The generation name carries
/// the exit code, so a fresh process start is distinguishable from a rolling
/// rotation without any second naming scheme.
const OPERATIONAL_LOG_STEM: &str = "eliot-store-surreal";

/// Bounded operational-log generation size, in bytes, at the crate's own
/// declared ceiling (`eliot-observability-runtime::config::MAX_ROLLING_BYTES`).
const OPERATIONAL_LOG_GENERATION_BYTES: u64 =
    eliot_observability_runtime::config::MAX_ROLLING_BYTES;

/// Bounded operational-log generation count, at the same declared ceiling.
const OPERATIONAL_LOG_GENERATIONS: u32 =
    eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS;

/// Bounded writer-queue depth, in records, before admission starts dropping and
/// the visible dropped-records gauge advances (I16.11 forbids hidden loss), at
/// the crate's own declared ceiling.
const OPERATIONAL_LOG_QUEUED_RECORDS: usize =
    eliot_observability_runtime::config::MAX_ROLLING_QUEUED_RECORDS;

/// Store launch config an installation / release owner wants the I5.9
/// compatibility decision installed beside (issue #1932).
///
/// Setting this variable turns the launch into the one-shot decision
/// installation; leaving it unset is the normal writer launch.
const COMPATIBILITY_CONFIG_VARIABLE: &str = "ELIOT_STORE_SURREAL_COMPATIBILITY_CONFIG";

/// Owner-decided `compatibility.toml` bytes for that Store config. The owner
/// decides the record; the bridge only renders, qualifies and installs it.
const COMPATIBILITY_RECORD_VARIABLE: &str = "ELIOT_STORE_SURREAL_COMPATIBILITY_RECORD";

/// I0.5 `CurrentSystemEvidenceSnapshot` document the owner-decided record
/// cites, by its `evidence_snapshot_sha256`.
const COMPATIBILITY_EVIDENCE_VARIABLE: &str = "ELIOT_STORE_SURREAL_COMPATIBILITY_EVIDENCE";

/// Derives the process observability configuration from the launch contour and
/// the loaded `StoreLaunchConfig`.
///
/// `config.runtime_launch` is the `RuntimeLaunchDescriptor` the installer
/// materialized into `generation.json` and that `load_config` already
/// validated in this binary; it carries the digest-bound
/// `RuntimeStateRoots` for the exact installation, so the operational log and
/// the protected event spool land under roots this process is already bound
/// to. The profile is that same `RuntimeStateRoots::profile`, not an
/// assumption: the store bridge is launched by the Host as the
/// `LocalService` account against the `SystemService` roots in the production
/// contour, and a portable-dev launch resolves to the `PortableDev` roots.
///
/// `metrics_listen` and `otlp_endpoint` stay at the crate's own `None`: no
/// canonical `OpenMetrics` bind address and no approved OTLP collector
/// endpoint exist in the tree, and I16.2 requires the OTLP bridge to stay
/// disabled by default.
fn observability_config(config: &eliot_store_surreal::StoreLaunchConfig) -> ObservabilityConfig {
    let roots = &config.runtime_launch.runtime_state_roots;
    let profile = match roots.profile {
        eliot_installation::InstallationProfile::SystemService => RuntimeProfile::SystemService,
        eliot_installation::InstallationProfile::UserMode => RuntimeProfile::UserMode,
        eliot_installation::InstallationProfile::PortableDev => RuntimeProfile::Portable,
    };
    let ors_root = Path::new(roots.kernel_ors_root.as_str());
    ObservabilityConfig {
        profile,
        rolling_log: RollingLogPolicy {
            directory: ors_root.join("logs"),
            file_stem: OPERATIONAL_LOG_STEM.to_owned(),
            max_bytes_per_generation: OPERATIONAL_LOG_GENERATION_BYTES,
            max_generations: OPERATIONAL_LOG_GENERATIONS,
            max_buffered_records: OPERATIONAL_LOG_QUEUED_RECORDS,
            exit_code: 0,
        },
        // `system_service` uses the Windows Event Log as its last resort, so
        // only the two spool profiles get a protected event spool.
        spool: match profile {
            RuntimeProfile::SystemService => None,
            RuntimeProfile::UserMode | RuntimeProfile::Portable => Some(SpoolPolicy {
                directory: ors_root.join("spool"),
                file_stem: "critical-events".to_owned(),
                max_generations: eliot_observability_runtime::config::MAX_ROLLING_GENERATIONS,
                max_record_bytes: eliot_observability_runtime::config::MAX_SPOOL_RECORD_BYTES,
            }),
        },
        metrics_listen: None,
        otlp_endpoint: None,
    }
}

/// Installs the shared observability runtime from the loaded launch config.
///
/// The Store bridge has no initialized telemetry sink before the launch config
/// is loaded, so the install happens at the first point where the installation
/// roots are known — immediately after `prepare_launch` and before the
/// provider is composed, connected, or the pipe is served. A loaded
/// configuration is mandatory (this binary cannot reach any live work without
/// one), so a refused observability configuration is reported through the same
/// fail-closed launch error path the rest of the launch uses.
fn install_observability(config: &eliot_store_surreal::StoreLaunchConfig) -> Result<(), String> {
    eliot_observability_runtime::install(&observability_config(config))
        .map(|_| ())
        .map_err(|error| format!("observability runtime install: {error}"))
}

#[tokio::main]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor.
#[allow(clippy::print_stderr)]
async fn main() {
    // One bounded structured subscriber for the process lifetime. Reusable
    // compositions never install globals; a duplicate install observes the
    // existing owner instead of creating a second one.
    install_startup_subscriber();
    let outcome = Box::pin(run()).await;
    let mut events = BoundedEventLog::new();
    emit_lifecycle(
        &mut events,
        BridgeBoundary::ProcessExit,
        "process_exit",
        &BridgeIdentity::new(),
        None,
    );
    report_events(&events);
    if let Err(error) = outcome {
        eprintln!("{SERVICE_NAME}: {error}");
        std::process::exit(1);
    }
}

/// Records one launch-stage outcome at its owning boundary.
///
/// Admission emits a lifecycle observation; refusal emits a validation
/// rejection. Both carry only the identity actually present at the stage and
/// no reason prose: untyped stage errors stay explicitly unobserved instead
/// of being guessed from strings. Infallible and bounded.
#[cfg(windows)]
fn report_stage_outcome(
    boundary: BridgeBoundary,
    operation: &'static str,
    identity: &BridgeIdentity,
    admitted: bool,
) {
    let mut events = BoundedEventLog::new();
    if admitted {
        emit_lifecycle(&mut events, boundary, operation, identity, None);
    } else {
        emit_validation_rejected(&mut events, boundary, operation, identity, None);
    }
    report_events(&events);
}

/// Bounded typed defect for a transport/protocol frame rejected before
/// dispatch (the `validate_request_frame` Err arm). Correlates via the
/// frame's `request_id` when present and admits no untrusted
/// operation/fence identity; the validation detail is additive
/// `human_detail` only, which the contract excludes from `PartialEq` and
/// control semantics. Mirrors `StoreFailure::base` + `defect()`:
/// `InternalDefect` / `INTERNAL_STORE_FAILURE` / `NotAttempted` /
/// `ManualRecovery` / `EscalateInternalDefect`.
#[cfg(windows)]
fn frame_rejection_defect(
    request_id: Option<eliot_contracts::RequestId>,
    error: String,
) -> eliot_store_surreal::Response {
    let human_detail = if error.is_empty()
        || error.len() > eliot_store_api::MAX_STORE_FAILURE_DETAIL_LEN
        || error.chars().any(char::is_control)
    {
        None
    } else {
        Some(error)
    };
    let reason_code = eliot_store_api::StoreReasonCode::new("INTERNAL_STORE_FAILURE")
        .ok()
        .or_else(|| eliot_store_api::StoreReasonCode::new("INTERNAL_DEFECT").ok())
        .or_else(|| eliot_store_api::StoreReasonCode::new("STORE_DEFECT").ok());
    match reason_code {
        Some(reason_code) => {
            let mut failure = eliot_store_api::StoreFailure {
                contract_revision: eliot_store_api::STORE_FAILURE_CONTRACT_REVISION.to_owned(),
                disposition: eliot_store_api::StoreFailureDisposition::InternalDefect,
                reason_code,
                request_id,
                operation_id: None,
                idempotency_key_ref_or_digest: None,
                state_fence_ref_or_exact_safe_projection: None,
                mutation_disposition: eliot_store_api::StoreMutationDisposition::NotAttempted,
                retry_directive: eliot_store_api::StoreRetryDirective::ManualRecovery,
                recovery_action: eliot_store_api::StoreRecoveryAction::EscalateInternalDefect,
                conflict: None,
                retry_after_ms: None,
                retry_after_dependency_revision: None,
                evidence_handles: eliot_store_api::StoreEvidenceHandles::default(),
                evidence_ref: None,
                human_detail,
            };
            if failure.validate().is_err() {
                failure.human_detail = None;
            }
            if failure.validate().is_ok() {
                eliot_store_surreal::Response::Failure { failure }
            } else {
                unreachable!(
                    "frame-rejection defect with absent refs/fence must validate; \
                     incompatible failure-contract revision"
                );
            }
        }
        None => {
            unreachable!(
                "store failure contract rejects static defect tokens; \
                 incompatible failure-contract revision"
            );
        }
    }
}

/// I5.9 compatibility gate (issue #1932).
///
/// Reports the exact active `SurrealDB` version and compatibility decision from
/// the installation-visible `compatibility.toml` sibling of the Store config.
///
/// The report is emitted for BOTH verdicts and the stage diagnostic is recorded
/// BEFORE the verdict is interpreted by the caller. The previous ordering put
/// the writer-admission `?` in front of the report, so a maintenance verdict
/// aborted startup with the decision never printed: an unqualified or
/// unrecorded binary produced no visible decision at all. A maintenance verdict
/// is now a RUNNING state — the bridge continues to composition, connect,
/// readiness and the authenticated pipe, answers health/readiness as a non-writer
/// and refuses every canonical mutation (see
/// `StoreComposition::require_canonical_writer`).
#[cfg(windows)]
#[allow(clippy::print_stderr)]
fn enforce_store_compatibility(
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> CompatibilityVerdict {
    let verdict = enforce_store_compatibility_inner(config);
    eprintln!("{SERVICE_NAME}: {}", verdict.report());
    // The decision is projected to the typed diagnostics health projection and
    // recorded at its own boundary, so the structured record carries the same
    // decision the gate reached. A maintenance verdict is recorded as a
    // validation rejection: visible non-writer readiness, never a silent
    // writer.
    let health = project_compatibility_health(&verdict);
    let mut identity = BridgeIdentity::new();
    if let Some(decision_report) = health.decision_report() {
        identity = identity.with_evidence_ref(decision_report);
    }
    let mut events = BoundedEventLog::new();
    match health.decision() {
        CompatibilityDecision::WriterAdmitted => emit_lifecycle(
            &mut events,
            BridgeBoundary::CompatibilityGate,
            "compatibility_gate",
            &identity,
            None,
        ),
        CompatibilityDecision::NonWriterMaintenance => emit_validation_rejected(
            &mut events,
            BridgeBoundary::CompatibilityGate,
            "compatibility_gate",
            &identity,
            None,
        ),
    }
    report_events(&events);
    verdict
}

/// One-shot production producer of the installation-visible I5.9
/// compatibility decision (issue #1932).
///
/// I5.9 makes `compatibility.toml` the installation-visible source of the
/// active store decision and names the installation / release owner as the
/// party that decides it. This is the bridge binary's production install path
/// for that decision pair: the owner points this launch at its decided record
/// and at the I0.5 `CurrentSystemEvidenceSnapshot` document the record cites,
/// and [`install_compatibility_decision`] renders, qualifies and installs both
/// beside the selected Store config.
///
/// The bridge decides nothing here. Every value comes from the owner's files,
/// the record is parsed and validated by the same gate parser this process
/// later reads with, and a pair whose evidence document does not carry the
/// recorded content address is refused before anything is written. An
/// installation that cannot be qualified therefore leaves the previous
/// decision — or no decision, which is fail-closed maintenance — in place.
///
/// Returns true when this launch was that installation, so the caller serves
/// nothing afterwards.
#[cfg(windows)]
#[allow(clippy::print_stderr)]
fn install_release_compatibility_decision() -> Result<bool, String> {
    let config_path = match std::env::var_os(COMPATIBILITY_CONFIG_VARIABLE) {
        Some(value) => PathBuf::from(value),
        None => return Ok(false),
    };
    let record_path = owner_supplied_path(COMPATIBILITY_RECORD_VARIABLE)?;
    let evidence_path = owner_supplied_path(COMPATIBILITY_EVIDENCE_VARIABLE)?;
    let record_bytes = std::fs::read(&record_path)
        .map_err(|error| format!("read the owner-supplied compatibility record: {error}"))?;
    let record = parse_compatibility_bytes(&record_bytes)
        .map_err(|error| format!("owner-supplied compatibility record: {error}"))?
        .surrealdb;
    let evidence_snapshot_bytes = std::fs::read(&evidence_path)
        .map_err(|error| format!("read the owner-supplied evidence snapshot: {error}"))?;
    install_compatibility_decision(&config_path, &record, &evidence_snapshot_bytes)?;
    eprintln!("{SERVICE_NAME}: installed the installation-visible compatibility decision");
    Ok(true)
}

/// Resolves one required owner-supplied path for the compatibility
/// installation, failing closed when a requested installation is incomplete.
#[cfg(windows)]
fn owner_supplied_path(variable: &str) -> Result<PathBuf, String> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is required to install the compatibility decision"))
}

#[cfg(windows)]
fn enforce_store_compatibility_inner(
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> CompatibilityVerdict {
    resolve_compatibility_verdict(
        Path::new(config.runtime_launch.store_config_path.as_str()),
        config
            .runtime_launch
            .canonical_store_artifact_digest
            .as_str(),
        config.schema_generation.as_str(),
    )
}

/// Requires an admitted canonical-writer decision for one write-capable launch
/// mode (issue #1932).
///
/// The portable-dev schema-initialization mode is a provider write, so it passes
/// the same installation-visible gate as the long-running writer: the exact
/// report is emitted and recorded, and a maintenance verdict refuses the mode
/// with that report instead of migrating an unqualified generation.
#[cfg(windows)]
fn require_writer_admission(config: &eliot_store_surreal::StoreLaunchConfig) -> Result<(), String> {
    let verdict = enforce_store_compatibility(config);
    if verdict.is_writer_admitted() {
        Ok(())
    } else {
        Err(verdict.report().to_owned())
    }
}

#[cfg(windows)]
fn emit_bootstrap_descriptor(mode: &LaunchMode) -> Result<bool, String> {
    let outcome = emit_bootstrap_descriptor_inner(mode);
    match &outcome {
        Ok(true) => report_stage_outcome(
            BridgeBoundary::BootstrapDescriptor,
            "bootstrap_descriptor",
            &BridgeIdentity::new(),
            true,
        ),
        Ok(false) => {}
        Err(_) => report_stage_outcome(
            BridgeBoundary::BootstrapDescriptor,
            "bootstrap_descriptor",
            &BridgeIdentity::new(),
            false,
        ),
    }
    outcome
}

#[cfg(windows)]
fn emit_bootstrap_descriptor_inner(mode: &LaunchMode) -> Result<bool, String> {
    if let LaunchMode::EmitBootstrapDescriptor {
        config_path,
        output_path,
    } = mode
    {
        let config = load_config(Some(config_path))?;
        let descriptor = store_bootstrap_descriptor(&config)?;
        let bytes = serde_json::to_vec_pretty(&descriptor)
            .map_err(|error| format!("serialize neutral bootstrap descriptor: {error}"))?;
        std::fs::write(output_path, bytes)
            .map_err(|error| format!("write neutral bootstrap descriptor: {error}"))?;
        return Ok(true);
    }
    Ok(false)
}

#[cfg(windows)]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor.
#[allow(clippy::print_stderr)]
fn bind_observed_identity(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<CompatibilityVerdict, String> {
    let outcome = bind_observed_identity_inner(composition, config);
    report_stage_outcome(
        BridgeBoundary::ObservedIdentityBinding,
        "observed_identity_binding",
        &BridgeIdentity::new(),
        matches!(&outcome, Ok(verdict) if verdict.is_writer_admitted()),
    );
    outcome
}

#[cfg(windows)]
#[allow(clippy::print_stderr)]
fn bind_observed_identity_inner(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
) -> Result<CompatibilityVerdict, String> {
    let observed = composition
        .observed_provider_identity()
        .ok_or_else(|| "provider identity was not proved by connect".to_owned())?;
    let observed_version = format!(
        "{}.{}.{}",
        observed.version_major, observed.version_minor, observed.version_patch
    );
    let config_path = Path::new(config.runtime_launch.store_config_path.as_str());
    // A record swapped, revoked or rotated across the provider-startup window
    // is an explicit maintenance verdict naming the drift, not a startup abort:
    // the installation stays running and queryable as a non-writer, and the
    // mutation path refuses every canonical write.
    let verdict = match load_compatibility_for_config(config_path) {
        Ok(file) => {
            let evidence_verification =
                load_evidence_snapshot_verification(config_path, &file.surrealdb);
            observed_identity_verdict(
                &file.surrealdb,
                &observed_version,
                &observed.artifact_digest,
                &evidence_verification,
            )
        }
        Err(_) => {
            // No readable record at all: the unrecorded maintenance verdict
            // names the exact load refusal in its report.
            resolve_compatibility_verdict(
                config_path,
                config
                    .runtime_launch
                    .canonical_store_artifact_digest
                    .as_str(),
                config.schema_generation.as_str(),
            )
        }
    };
    eprintln!("{SERVICE_NAME}: {}", verdict.report());
    Ok(verdict)
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
async fn serve_handshake_loop(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
    mut owner_quiesce: tokio::sync::watch::Receiver<Option<String>>,
) -> Result<(), String> {
    if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
        let mut events = BoundedEventLog::new();
        emit_lifecycle(
            &mut events,
            BridgeBoundary::Shutdown,
            "shutdown",
            &BridgeIdentity::new(),
            None,
        );
        report_events(&events);
        return Err(error);
    }
    let limits = TransportLimits::default();
    let expectation = match eliot_platform_windows::NamedPipePeerExpectation::new(
        config.expected_client_sid.clone(),
        config.expected_client_session_id,
    )
    .map_err(|error| format!("invalid peer expectation: {error}"))
    {
        Ok(expectation) => expectation,
        Err(error) => {
            report_stage_outcome(
                BridgeBoundary::PipeBind,
                "pipe_bind",
                &BridgeIdentity::new(),
                false,
            );
            return Err(error);
        }
    };
    let mut server = match NamedPipeServer::create(&config.store_pipe, &expectation)
        .map_err(|error| format!("named-pipe creation failed: {error}"))
    {
        Ok(server) => server,
        Err(error) => {
            report_stage_outcome(
                BridgeBoundary::PipeBind,
                "pipe_bind",
                &BridgeIdentity::new(),
                false,
            );
            return Err(error);
        }
    };
    let client_admission = tokio::select! {
        result = server.wait_for_authenticated_client(
            Duration::from_millis(config.connect_timeout_ms),
            &expectation,
        ) => result.map_err(|error| format!("authenticated client admission failed: {error}")),
        _ = owner_quiesce.changed() => Err(owner_quiesce_reason(&owner_quiesce)
            .unwrap_or_else(|| "snapshot owner quiescence signal closed".to_owned())),
    };
    if let Err(error) = client_admission {
        report_stage_outcome(
            BridgeBoundary::PipeBind,
            "pipe_bind",
            &BridgeIdentity::new(),
            false,
        );
        if owner_quiesce_reason(&owner_quiesce).is_some() {
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &BridgeIdentity::new(),
                None,
            );
            report_events(&events);
        }
        return Err(error);
    }
    report_stage_outcome(
        BridgeBoundary::PipeBind,
        "pipe_bind",
        &BridgeIdentity::new(),
        true,
    );
    if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
        let mut events = BoundedEventLog::new();
        emit_lifecycle(
            &mut events,
            BridgeBoundary::Shutdown,
            "shutdown",
            &BridgeIdentity::new(),
            None,
        );
        report_events(&events);
        return Err(error);
    }
    let hello_receive = tokio::select! {
        result = server.receive_frame(limits) => {
            result.map_err(|error| format!("EBP hello receive failed: {error}"))
        }
        _ = owner_quiesce.changed() => Err(owner_quiesce_reason(&owner_quiesce)
            .unwrap_or_else(|| "snapshot owner quiescence signal closed".to_owned())),
    };
    let hello_frame = match hello_receive {
        Ok(frame) => frame,
        Err(error) => {
            report_stage_outcome(
                BridgeBoundary::HandshakeAdmit,
                "handshake",
                &BridgeIdentity::new(),
                false,
            );
            if owner_quiesce_reason(&owner_quiesce).is_some() {
                let mut events = BoundedEventLog::new();
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::Shutdown,
                    "shutdown",
                    &BridgeIdentity::new(),
                    None,
                );
                report_events(&events);
            }
            return Err(error);
        }
    };
    if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
        report_stage_outcome(
            BridgeBoundary::HandshakeAdmit,
            "handshake",
            &BridgeIdentity::new(),
            false,
        );
        let mut events = BoundedEventLog::new();
        emit_lifecycle(
            &mut events,
            BridgeBoundary::Shutdown,
            "shutdown",
            &BridgeIdentity::new(),
            None,
        );
        report_events(&events);
        return Err(error);
    }
    let handshake_identity = StoreHandshakeIdentity::new(
        composition.operation_manifest_digest().to_owned(),
        serde_json::json!({
            "root_id": composition.blob_owner().root_id(),
            "owner_id": composition.blob_owner().owner_id().as_str(),
            "process_id": composition.blob_owner().process_id(),
            "claim_id": composition.blob_owner().claim_id(),
        }),
    );
    let authenticated_peer = server.peer_identity().clone();
    let (mut session, server_hello) = match admit_authenticated_handshake(
        hello_frame,
        limits,
        config,
        &handshake_identity,
        &authenticated_peer,
    ) {
        Ok(admitted) => {
            let mut events = BoundedEventLog::new();
            emit_received(
                &mut events,
                BridgeBoundary::HandshakeAdmit,
                "handshake",
                &BridgeIdentity::new(),
            );
            report_events(&events);
            admitted
        }
        Err(error) => {
            report_stage_outcome(
                BridgeBoundary::HandshakeAdmit,
                "handshake",
                &BridgeIdentity::new(),
                false,
            );
            return Err(error);
        }
    };
    let mut negotiated_limits = limits;
    negotiated_limits.max_frame_bytes = session.max_frame_bytes();
    let handshake_frame = control_frame(
        session.connection_id(),
        session.protocol_version(),
        MessageType::Ready,
        serde_json::to_value(server_hello)
            .map_err(|error| format!("serialize ServerHello: {error}"))?,
    );
    let handshake_send = server
        .send_frame(&handshake_frame, negotiated_limits)
        .await
        .map_err(|error| format!("EBP handshake response failed: {error}"));
    let maintenance = maintain_and_report_snapshot_owner(composition).and_then(|diagnostics| {
        require_snapshot_owner_accounting(&diagnostics)?;
        Ok(diagnostics)
    });
    if let Err(error) = handshake_send {
        // Transport loss only: a failed send records the loss, never delivery.
        // A successful send stays silent because transport acceptance proves
        // no delivery.
        let mut events = BoundedEventLog::new();
        emit_lifecycle(
            &mut events,
            BridgeBoundary::HandshakeRespond,
            "handshake",
            &BridgeIdentity::new(),
            None,
        );
        report_events(&events);
        return match maintenance {
            Ok(_) => Err(error),
            Err(maintenance_error) => Err(format!("{error}; {maintenance_error}")),
        };
    }
    if let Err(error) = maintenance {
        let mut events = BoundedEventLog::new();
        emit_lifecycle(
            &mut events,
            BridgeBoundary::Shutdown,
            "shutdown",
            &BridgeIdentity::new(),
            None,
        );
        report_events(&events);
        return Err(error);
    }

    loop {
        if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &BridgeIdentity::new(),
                None,
            );
            report_events(&events);
            return Err(error);
        }
        let frame_receive = tokio::select! {
            result = server.receive_frame(negotiated_limits) => {
                result.map_err(|error| format!("EBP frame rejected: {error}"))
            }
            _ = owner_quiesce.changed() => {
                let error = owner_quiesce_reason(&owner_quiesce)
                    .unwrap_or_else(|| "snapshot owner quiescence signal closed".to_owned());
                let mut events = BoundedEventLog::new();
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::Shutdown,
                    "shutdown",
                    &BridgeIdentity::new(),
                    None,
                );
                report_events(&events);
                return Err(error);
            }
        };
        let frame = match frame_receive {
            Ok(frame) => frame,
            Err(error) => {
                let mut events = BoundedEventLog::new();
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::FrameReceive,
                    "frame",
                    &BridgeIdentity::new(),
                    None,
                );
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::Shutdown,
                    "shutdown",
                    &BridgeIdentity::new(),
                    None,
                );
                report_events(&events);
                return Err(error);
            }
        };
        if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &BridgeIdentity::new(),
                None,
            );
            report_events(&events);
            return Err(error);
        }
        let mut round = BoundedEventLog::new();
        let (request_identity, response) =
            match validate_request_frame_with_log(&mut session, &frame, &mut round) {
                Ok(request) => {
                    let identity = BridgeIdentity::from_request(&request);
                    let response =
                        Box::pin(dispatch_with_log(composition, request, &mut round)).await;
                    (identity, response)
                }
                Err(error) => {
                    let defect = frame_rejection_defect(frame.request_id.clone(), error);
                    let identity = BridgeIdentity::from_response(&defect);
                    emit_dispatch_outcome(
                        &mut round,
                        BridgeBoundary::FrameRejection,
                        "frame",
                        &identity,
                        &defect,
                    );
                    (identity, defect)
                }
            };
        report_events(&round);
        let identity = request_identity.merge(&BridgeIdentity::from_response(&response));
        let response_frame = match eliot_store_api::response_frame(
            session.connection_id(),
            session.protocol_version(),
            frame.request_id.clone(),
            response,
        )
        .map_err(|error| format!("invalid EBP response: {error}"))
        {
            Ok(frame) => frame,
            Err(error) => {
                let mut events = BoundedEventLog::new();
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::ResponseSend,
                    "response_send",
                    &identity,
                    None,
                );
                emit_lifecycle(
                    &mut events,
                    BridgeBoundary::Shutdown,
                    "shutdown",
                    &identity,
                    None,
                );
                report_events(&events);
                return Err(error);
            }
        };
        let response_send = server
            .send_frame(&response_frame, negotiated_limits)
            .await
            .map_err(|error| format!("EBP response failed: {error}"));
        let maintenance = maintain_and_report_snapshot_owner(composition).and_then(|diagnostics| {
            require_snapshot_owner_accounting(&diagnostics)?;
            Ok(diagnostics)
        });
        if let Err(error) = response_send {
            // Response loss after mutation: the recorded dispatch outcome
            // stands with the same operation identity. Delivery and outcome
            // stay unknown here, never re-decided into commit or rollback.
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::ResponseSend,
                "response_send",
                &identity,
                None,
            );
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &identity,
                None,
            );
            report_events(&events);
            return match maintenance {
                Ok(_) => Err(error),
                Err(maintenance_error) => Err(format!("{error}; {maintenance_error}")),
            };
        }
        // Run the same bounded retirement pass at the completed-request
        // boundary, including begin-only traffic. The supervised interval
        // remains responsible for idle periods with no client requests.
        if let Err(error) = maintenance {
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &identity,
                None,
            );
            report_events(&events);
            return Err(error);
        }
        if let Some(error) = owner_quiesce_reason(&owner_quiesce) {
            let mut events = BoundedEventLog::new();
            emit_lifecycle(
                &mut events,
                BridgeBoundary::Shutdown,
                "shutdown",
                &identity,
                None,
            );
            report_events(&events);
            return Err(error);
        }
    }
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
async fn run() -> Result<(), String> {
    // I5.9 (issue #1932): the one-shot compatibility decision installation runs
    // before any launch-mode decode, so the installation / release owner can
    // install the installation-visible decision for a Store config without a
    // launch profile. An unset variable is the normal writer launch and changes
    // nothing.
    if install_release_compatibility_decision()? {
        return Ok(());
    }
    let mode = match parse_launch_mode(std::env::args_os().skip(1)) {
        Ok(mode) => {
            let mut events = BoundedEventLog::new();
            emit_received(
                &mut events,
                BridgeBoundary::LaunchConfig,
                "launch_config",
                &BridgeIdentity::new(),
            );
            report_events(&events);
            mode
        }
        Err(error) => {
            report_stage_outcome(
                BridgeBoundary::LaunchConfig,
                "launch_config",
                &BridgeIdentity::new(),
                false,
            );
            return Err(error);
        }
    };
    if emit_bootstrap_descriptor(&mode)? {
        return Ok(());
    }
    // The launch future carries every one-shot arm's state (including the
    // `ECXF/1` export, issue #1871), so it is boxed rather than grown: the
    // allocation is paid once per process launch and keeps the caller's frame
    // independent of how many arms this router has.
    let prepared = Box::pin(prepare_launch(mode)).await;
    report_stage_outcome(
        BridgeBoundary::LaunchConfig,
        "launch_config",
        &BridgeIdentity::new(),
        prepared.is_ok(),
    );
    let Some(config) = prepared? else {
        return Ok(());
    };
    // Issue #1836 (W1): the installation roots are known now, so the shared
    // observability runtime is installed before the provider is composed,
    // connected, or the authenticated pipe is served.
    install_observability(&config)?;
    // I5.9 compatibility gate (issue #1932). The verdict is reported and
    // recorded at every stage, and a maintenance verdict does not abort
    // startup: the installation comes up as a running, queryable non-writer
    // whose canonical mutations are refused on the mutation path itself.
    let compatibility = enforce_store_compatibility(&config);
    let composed = StoreComposition::new(&config);
    report_stage_outcome(
        BridgeBoundary::Startup,
        "startup",
        &BridgeIdentity::new(),
        composed.is_ok(),
    );
    let composition = composed?;
    supervise_composed_store_lifetime(&composition, &config, compatibility).await
}

#[cfg(windows)]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor,
// and the visible non-writer readiness state must be reported there.
#[allow(clippy::print_stderr)]
async fn supervise_composed_store_lifetime(
    composition: &StoreComposition,
    config: &eliot_store_surreal::StoreLaunchConfig,
    mut compatibility: CompatibilityVerdict,
) -> Result<(), String> {
    let (owner_quiesce_tx, owner_quiesce_rx) = tokio::sync::watch::channel(None);
    let service = Box::pin(async move {
        let connected = composition.connect().await;
        report_stage_outcome(
            BridgeBoundary::Startup,
            "startup",
            &BridgeIdentity::new(),
            connected.is_ok(),
        );
        connected?;
        // Post-connect re-verification (issue #1932): the adapter has now
        // proved spawned-artifact identity, listener ownership and server
        // major over its ownership-verified channel. Re-resolve the
        // installation-visible decision before serving: a record swapped,
        // revoked or drifted across the provider-startup window keeps the
        // installation non-writer here, never at the first canonical write.
        // `combine` is fail-closed, so an admitted earlier stage can never
        // re-admit a maintenance verdict.
        compatibility = compatibility.combine(enforce_store_compatibility(config));
        // Observed-identity binding (issue #1932, backend handoff §3): the
        // adapter proved the live version and spawn-validated digest over its
        // ownership-verified channel during connect. Bind the record echo to
        // that observation before serving: a rotated binary or drifted record
        // is visible maintenance here, never an accepted write.
        compatibility = compatibility.combine(bind_observed_identity(composition, config)?);
        if !compatibility.is_writer_admitted() {
            // Visible non-writer readiness: the store is up and answers
            // health/readiness, and every canonical mutation is refused. The
            // refusal is enforced on the mutation path, not by refusing to
            // serve.
            eprintln!(
                "{SERVICE_NAME}: serving non-writer readiness: {}",
                compatibility
                    .maintenance_reason()
                    .unwrap_or("unqualified decision")
            );
        }
        let readiness = match composition.readiness().await {
            Ok(receipt) => receipt,
            Err(error) => {
                report_stage_outcome(
                    BridgeBoundary::SemanticReadinessGate,
                    "semantic_readiness_gate",
                    &BridgeIdentity::new(),
                    false,
                );
                return Err(format!("semantic Store readiness failed: {error}"));
            }
        };
        let mut gate_identity = BridgeIdentity::new();
        if let Some(generation) = readiness.observed_generation.as_deref() {
            gate_identity = gate_identity.with_generation(generation);
        }
        let gated = require_semantic_ready_for_pipe(&readiness, &config.schema_generation);
        report_stage_outcome(
            BridgeBoundary::SemanticReadinessGate,
            "semantic_readiness_gate",
            &gate_identity,
            gated.is_ok(),
        );
        gated?;
        serve_handshake_loop(composition, config, owner_quiesce_rx).await
    });
    // `query_timeout_ms` is already validated as non-zero. Reuse it as the
    // owner wake cadence; the adapter supplies maintenance's established clock.
    supervise_with_snapshot_owner_tick(
        std::time::Duration::from_millis(config.query_timeout_ms),
        service,
        || maintain_and_report_snapshot_owner(composition),
        owner_quiesce_tx,
    )
    .await
}

#[cfg(windows)]
fn maintain_and_report_snapshot_owner(
    composition: &StoreComposition,
) -> Result<SnapshotBudgetDiagnostics, String> {
    let budget = composition
        .maintain_snapshot_owner()
        .map_err(|error| format!("snapshot owner maintenance failed: {error}"))?;
    report_snapshot_budget(&budget);
    Ok(budget)
}

#[cfg(any(windows, test))]
const SNAPSHOT_OWNER_DIMENSION_FIELDS: [&str; 8] = [
    "snapshot.budget.v1.begins_in_progress",
    "snapshot.budget.v1.live_captures",
    "snapshot.budget.v1.retained_bytes",
    "snapshot.budget.v1.terminal_entries",
    "snapshot.budget.v1.terminal_bytes",
    "snapshot.budget.v1.enumeration_bytes",
    "snapshot.budget.v1.active_page_calls",
    "snapshot.budget.v1.cleanup_steps",
];

#[cfg(any(windows, test))]
fn snapshot_owner_accounting_is_usable(diagnostics: &SnapshotBudgetDiagnostics) -> bool {
    diagnostics.accounting_usable
        && SNAPSHOT_OWNER_DIMENSION_FIELDS
            .iter()
            .zip(diagnostics.dimensions.iter())
            .all(|(field, dimension)| {
                dimension.field == *field
                    && dimension.charged <= dimension.limit
                    && dimension.high_water >= dimension.charged
                    && dimension.high_water <= dimension.limit
                    && dimension.remaining == dimension.limit.checked_sub(dimension.charged)
            })
}

#[cfg(any(windows, test))]
fn snapshot_owner_is_drained(diagnostics: &SnapshotBudgetDiagnostics) -> bool {
    snapshot_owner_accounting_is_usable(diagnostics)
        && diagnostics
            .dimensions
            .iter()
            .all(|dimension| dimension.charged == 0)
}

#[cfg(windows)]
fn require_snapshot_owner_accounting(
    diagnostics: &SnapshotBudgetDiagnostics,
) -> Result<(), String> {
    if snapshot_owner_accounting_is_usable(diagnostics) {
        Ok(())
    } else {
        Err("snapshot owner accounting is unusable".to_owned())
    }
}

#[cfg(any(windows, test))]
fn owner_quiesce_reason(receiver: &tokio::sync::watch::Receiver<Option<String>>) -> Option<String> {
    receiver.borrow().clone()
}

/// Pins one owner service future while bounded expiry maintenance runs beside
/// it. A timer wake keeps the same future alive, including a partially read
/// frame. Fatal owner failure quiesces only pre-dispatch reads; a received
/// request remains in this future through dispatch and send reconciliation.
#[cfg(any(windows, test))]
async fn supervise_with_snapshot_owner_tick<T, F, M>(
    cadence: std::time::Duration,
    service: F,
    mut maintain_snapshot_owner: M,
    owner_quiesce: tokio::sync::watch::Sender<Option<String>>,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
    M: FnMut() -> Result<SnapshotBudgetDiagnostics, String>,
{
    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(service);
    let mut service_result = None;
    let mut owner_failure: Option<String> = None;
    loop {
        if let Some(error) = owner_failure.take() {
            let _ = owner_quiesce.send_replace(Some(error.clone()));
            let service_result = match service_result.take() {
                Some(result) => result,
                None => (&mut service).await,
            };
            return combine_service_and_owner_failure(service_result, error);
        }

        tokio::select! {
            result = &mut service, if service_result.is_none() => {
                service_result = Some(result);
            }
            _ = interval.tick() => {
                match maintain_snapshot_owner() {
                    Ok(diagnostics) if !snapshot_owner_accounting_is_usable(&diagnostics) => {
                        owner_failure = Some("snapshot owner accounting is unusable".to_owned());
                    }
                    Ok(diagnostics) => {
                        if let Some(result) = service_result.take() {
                            if snapshot_owner_is_drained(&diagnostics) {
                                return result;
                            }
                            service_result = Some(result);
                        }
                    }
                    Err(error) => owner_failure = Some(error),
                }
            }
        }
    }
}

#[cfg(any(windows, test))]
fn combine_service_and_owner_failure<T>(
    service_result: Result<T, String>,
    owner_failure: String,
) -> Result<T, String> {
    match service_result {
        Ok(_) => Err(owner_failure),
        Err(service_error) if service_error == owner_failure => Err(service_error),
        Err(service_error) => Err(format!("{service_error}; {owner_failure}")),
    }
}

#[cfg(not(windows))]
async fn run() -> Result<(), String> {
    Err("the production store endpoint requires Windows authenticated named pipes".to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use eliot_store_surreal_adapter::SnapshotBudgetDimension;
    // The 742/8 boundary-split helpers below name the recorded event type in
    // their signatures, so the import is scoped to the same platform gate.
    #[cfg(windows)]
    use eliot_store_surreal::diagnostics::BridgeDiagnosticEvent;

    use super::*;

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn owner_diagnostics(
        live_capture_charge: u64,
        accounting_usable: bool,
    ) -> SnapshotBudgetDiagnostics {
        let mut dimensions = std::array::from_fn(|index| SnapshotBudgetDimension {
            field: SNAPSHOT_OWNER_DIMENSION_FIELDS[index],
            limit: 1,
            charged: 0,
            high_water: 0,
            remaining: Some(1),
        });
        dimensions[1] = SnapshotBudgetDimension {
            field: SNAPSHOT_OWNER_DIMENSION_FIELDS[1],
            limit: 1,
            charged: live_capture_charge,
            high_water: 1,
            remaining: Some(1 - live_capture_charge),
        };
        SnapshotBudgetDiagnostics {
            accounting_usable,
            dimensions,
        }
    }

    #[tokio::test]
    async fn owner_tick_keeps_an_incomplete_service_future_pinned() {
        // The first poll models an incomplete frame read. It only completes on
        // the next poll of the same future after a timer wake.
        let maintenance_calls = Arc::new(AtomicUsize::new(0));
        let calls_during_partial_read = Arc::clone(&maintenance_calls);
        let mut partial_read_tick = None;
        let service = std::future::poll_fn(move |_| {
            let calls = calls_during_partial_read.load(Ordering::SeqCst);
            match partial_read_tick {
                None => {
                    partial_read_tick = Some(calls);
                    std::task::Poll::Pending
                }
                Some(previous_calls) if calls > previous_calls => {
                    std::task::Poll::Ready(Ok::<(), String>(()))
                }
                Some(_) => std::task::Poll::Pending,
            }
        });
        let calls_during_maintenance = Arc::clone(&maintenance_calls);
        let (owner_quiesce, _owner_quiesce_receiver) = tokio::sync::watch::channel(None);
        let result = supervise_with_snapshot_owner_tick(
            std::time::Duration::from_millis(1),
            service,
            || {
                calls_during_maintenance.fetch_add(1, Ordering::SeqCst);
                Ok(owner_diagnostics(0, true))
            },
            owner_quiesce,
        )
        .await;

        assert_eq!(result, Ok(()));
        assert!(maintenance_calls.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn completed_service_drains_snapshot_work_without_a_client() {
        let maintenance_calls = Arc::new(AtomicUsize::new(0));
        let calls_during_maintenance = Arc::clone(&maintenance_calls);
        let (owner_quiesce, _owner_quiesce_receiver) = tokio::sync::watch::channel(None);
        let result = supervise_with_snapshot_owner_tick(
            std::time::Duration::from_millis(1),
            async { Err::<(), _>("session ended after client loss".to_owned()) },
            move || {
                let call = calls_during_maintenance.fetch_add(1, Ordering::SeqCst);
                let live_capture_charge = u64::from(call == 0);
                Ok(owner_diagnostics(live_capture_charge, true))
            },
            owner_quiesce,
        )
        .await;

        assert_eq!(result, Err("session ended after client loss".to_owned()));
        assert!(maintenance_calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn owner_tick_refusal_quiesces_after_inflight_service_reconciles() {
        let maintenance_refused = Arc::new(AtomicBool::new(false));
        let service_reconciled = Arc::new(AtomicBool::new(false));
        let service_was_dropped = Arc::new(AtomicBool::new(false));
        let refused = Arc::clone(&maintenance_refused);
        let refused_for_maintenance = Arc::clone(&maintenance_refused);
        let reconciled = Arc::clone(&service_reconciled);
        let drop_flag = DropFlag(Arc::clone(&service_was_dropped));
        let service = std::future::poll_fn(move |_| {
            let _drop_flag = &drop_flag;
            if refused.load(Ordering::SeqCst) {
                reconciled.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(Err::<(), _>("dispatch outcome reconciled".to_owned()))
            } else {
                std::task::Poll::Pending
            }
        });
        let (owner_quiesce, _owner_quiesce_receiver) = tokio::sync::watch::channel(None);
        let result = supervise_with_snapshot_owner_tick(
            std::time::Duration::from_millis(1),
            service,
            move || {
                refused_for_maintenance.store(true, Ordering::SeqCst);
                Err("snapshot owner maintenance refused".to_owned())
            },
            owner_quiesce,
        )
        .await;

        assert_eq!(
            result,
            Err("dispatch outcome reconciled; snapshot owner maintenance refused".to_owned())
        );
        assert!(service_reconciled.load(Ordering::SeqCst));
        assert!(service_was_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn latched_owner_failure_blocks_a_ready_frame_at_admission_boundary() {
        let maintenance_refused = Arc::new(AtomicBool::new(false));
        let frame_was_admitted = Arc::new(AtomicBool::new(false));
        let refused = Arc::clone(&maintenance_refused);
        let admitted = Arc::clone(&frame_was_admitted);
        let (owner_quiesce, owner_quiesce_receiver) = tokio::sync::watch::channel(None);
        let service = std::future::poll_fn(move |_| {
            if !refused.load(Ordering::SeqCst) {
                return std::task::Poll::Pending;
            }

            // The frame is ready here; the production admission boundary
            // checks the latched fatal owner state before validating or
            // dispatching it.
            if let Some(error) = owner_quiesce_reason(&owner_quiesce_receiver) {
                return std::task::Poll::Ready(Err(error));
            }
            admitted.store(true, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        });
        let refused_for_maintenance = Arc::clone(&maintenance_refused);
        let result = supervise_with_snapshot_owner_tick(
            std::time::Duration::from_millis(1),
            service,
            move || {
                refused_for_maintenance.store(true, Ordering::SeqCst);
                Err("snapshot owner maintenance refused".to_owned())
            },
            owner_quiesce,
        )
        .await;

        assert_eq!(result, Err("snapshot owner maintenance refused".to_owned()));
        assert!(!frame_was_admitted.load(Ordering::SeqCst));
    }

    #[test]
    fn unknown_or_unusable_snapshot_accounting_never_claims_drain() {
        let mut diagnostics = owner_diagnostics(0, false);
        assert!(!snapshot_owner_is_drained(&diagnostics));

        diagnostics.accounting_usable = true;
        diagnostics.dimensions[1].remaining = None;
        assert!(!snapshot_owner_is_drained(&diagnostics));
    }

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn parser_accepts_protected_config_mode() {
        assert_eq!(
            parse_launch_mode(args(&["--config", "C:\\ProgramData\\Eliot\\store.json"]))
                .expect("protected mode should parse"),
            LaunchMode::Protected {
                config_path: PathBuf::from("C:\\ProgramData\\Eliot\\store.json"),
            }
        );
    }

    #[test]
    fn parser_accepts_exact_portable_dev_form() {
        let root = std::env::current_dir().expect("current directory should exist");
        let config = root.join("store.json");
        assert_eq!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.clone().into_os_string(),
                "--config".into(),
                config.clone().into_os_string(),
            ])
            .expect("portable-dev mode should parse"),
            LaunchMode::PortableDev {
                root,
                config_path: config,
                initialize_schema_only: false,
            }
        );
    }

    #[test]
    fn parser_accepts_schema_initialization_only_and_rejects_it_for_protected_mode() {
        let root = std::env::current_dir().expect("current directory should exist");
        let config = root.join("store.json");
        assert!(matches!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.into_os_string(),
                "--config".into(),
                config.into_os_string(),
                "--initialize-schema-only".into(),
            ])
            .expect("schema initialization mode should parse"),
            LaunchMode::PortableDev {
                initialize_schema_only: true,
                ..
            }
        ));
        assert!(
            parse_launch_mode(args(&[
                "--config",
                "C:\\ProgramData\\Eliot\\store.json",
                "--initialize-schema-only",
            ]))
            .is_err()
        );
    }

    #[test]
    fn parser_rejects_missing_unknown_and_extra_arguments() {
        assert!(parse_launch_mode(args(&[])).is_err());
        assert!(parse_launch_mode(args(&["--unknown", "x"])).is_err());
        assert!(parse_launch_mode(args(&["--config"])).is_err());
        assert!(
            parse_launch_mode(args(&[
                "--portable-dev-root",
                ".",
                "--config",
                "store.json",
            ]))
            .is_err()
        );
        let root = std::env::current_dir().expect("current directory should exist");
        assert!(
            parse_launch_mode(vec![
                "--portable-dev-root".into(),
                root.into_os_string(),
                "--config".into(),
                "store.json".into(),
                "extra".into(),
            ])
            .is_err()
        );
    }

    // WORK_UNIT_CASE: 742/2
    #[cfg(windows)]
    #[test]
    fn launch_gate_states_record_distinct_boundary_codes() {
        use eliot_store_surreal::diagnostics::RequestOutcome;

        // The two launch-gate states this binary distinguishes before any
        // composition, connect or pipe: a launch mode that requests no
        // one-shot bootstrap descriptor, and a descriptor request whose Store
        // config cannot be loaded. Both reach `emit_bootstrap_descriptor`, the
        // one-shot arm `run` reaches after the launch-config decode.
        let writer_launch =
            parse_launch_mode(args(&["--config", "C:\\ProgramData\\Eliot\\store.json"]))
                .expect("protected mode should parse");
        // A directory component nothing in this process creates, so the
        // configuration read is refused rather than skipped.
        let absent_root = std::env::temp_dir().join("eliot-742-case2-absent-root");
        let descriptor_launch = LaunchMode::EmitBootstrapDescriptor {
            config_path: absent_root.join("store.json"),
            output_path: absent_root.join("bootstrap.json"),
        };

        // The states are separated by the gate's own returned outcome: the
        // writer launch asks for no descriptor at all, and the unloadable
        // descriptor request is refused rather than silently skipped.
        assert_eq!(
            emit_bootstrap_descriptor(&writer_launch),
            Ok(false),
            "a writer launch requests no bootstrap descriptor"
        );
        assert!(
            emit_bootstrap_descriptor(&descriptor_launch).is_err(),
            "an unloadable descriptor config is refused, never silently skipped"
        );

        // The admitted launch-config receipt and the refused bootstrap
        // descriptor are recorded through the entries this binary's own call
        // sites use, and each record carries the stable machine code of the
        // boundary that observed it.
        let mut admitted = BoundedEventLog::new();
        emit_received(
            &mut admitted,
            BridgeBoundary::LaunchConfig,
            "launch_config",
            &BridgeIdentity::new(),
        );
        let mut refused = BoundedEventLog::new();
        emit_validation_rejected(
            &mut refused,
            BridgeBoundary::BootstrapDescriptor,
            "bootstrap_descriptor",
            &BridgeIdentity::new(),
            None,
        );
        let admitted_event = admitted.last().expect("the admitted record is retained");
        let refused_event = refused.last().expect("the refused record is retained");

        assert_eq!(admitted_event.boundary().as_str(), "launch_config");
        assert_eq!(refused_event.boundary().as_str(), "bootstrap_descriptor");
        assert_eq!(admitted_event.outcome(), RequestOutcome::Received);
        assert_eq!(
            refused_event.outcome(),
            RequestOutcome::ValidationRejected,
            "a refused launch state is never recorded as an admitted receipt"
        );
        assert_ne!(
            admitted_event.boundary().as_str(),
            refused_event.boundary().as_str(),
            "two different launch states emit two different boundary codes"
        );

        // Startup is a third boundary, reported after launch preparation and
        // again after connect, so a startup state can never be read as either
        // configuration-validation state.
        let startup_code = BridgeBoundary::Startup.as_str();
        assert_eq!(startup_code, "startup");
        assert_ne!(
            startup_code,
            admitted_event.boundary().as_str(),
            "the startup state does not reuse the launch-config code"
        );
        assert_ne!(
            startup_code,
            refused_event.boundary().as_str(),
            "the startup state does not reuse the bootstrap-descriptor code"
        );
    }

    /// Case 742/8 boundary split: the mutation result and the receipt-transport
    /// emission are two records at two boundaries, and neither record borrows
    /// the other's boundary code or outcome.
    #[cfg(windows)]
    fn assert_mutation_result_and_response_send_are_separate(
        mutation_event: &BridgeDiagnosticEvent,
        transport_event: &BridgeDiagnosticEvent,
    ) {
        use eliot_store_surreal::diagnostics::RequestOutcome;

        assert_eq!(mutation_event.boundary().as_str(), "mutation_result");
        assert_eq!(
            mutation_event.outcome(),
            RequestOutcome::Unknown,
            "response loss after mutation preserves the unknown outcome"
        );
        assert_eq!(transport_event.boundary().as_str(), "response_send");
        assert_eq!(
            transport_event.outcome(),
            RequestOutcome::LifecycleObserved,
            "a transport loss is a lifecycle observation, never a result"
        );
        assert_ne!(
            mutation_event.boundary().as_str(),
            transport_event.boundary().as_str(),
            "receipt creation and receipt transport emission are separate boundaries"
        );
    }

    /// Case 742/8 identity survival: the operation identity the unproven
    /// outcome projects is exactly the operation id, carries no receipt-derived
    /// evidence, and reaches the transport-loss record unchanged.
    #[cfg(windows)]
    fn assert_operation_identity_survives_transport_loss(
        identity: &BridgeIdentity,
        transport_event: &BridgeDiagnosticEvent,
    ) {
        use eliot_store_api::OperationId;

        assert_eq!(
            identity.operation_id().map(OperationId::as_str),
            Some("operation-742-8"),
            "the exact operation identity survives an unproven outcome"
        );
        assert!(
            identity.idempotency_ref().is_none(),
            "no idempotency reference is admitted without a receipt"
        );
        assert!(
            identity.manifest_digest().is_none(),
            "no manifest digest is admitted without a receipt"
        );
        assert_eq!(
            transport_event
                .identity()
                .operation_id()
                .map(OperationId::as_str),
            Some("operation-742-8"),
            "the transport loss carries the same operation identity"
        );
    }

    /// Case 742/8 fabricated-delivery absence: neither the mutation-result
    /// record nor the transport-loss record admits a receipt, a recovery action
    /// or response prose that a failed send never earned.
    #[cfg(windows)]
    fn assert_transport_loss_records_fabricate_no_delivery(
        mutation_event: &BridgeDiagnosticEvent,
        transport_event: &BridgeDiagnosticEvent,
    ) {
        assert!(
            mutation_event.receipt_status().is_none(),
            "no receipt status is recorded without owner receipt evidence"
        );
        assert!(
            mutation_event.detail().is_none(),
            "response prose never reaches the recorded outcome"
        );
        assert!(
            transport_event.receipt_status().is_none(),
            "output failure cannot fabricate a delivered receipt"
        );
        assert!(
            transport_event.recovery().is_none(),
            "logging a send loss schedules no reconciliation and no resubmission"
        );
    }

    /// Case 742/8 fabricated-delivery absence on the real output-failure path:
    /// the rejected frame is a typed defect with no mutation attempted, and its
    /// record carries no receipt status.
    #[cfg(windows)]
    fn assert_frame_rejection_defect_fabricates_no_delivery() {
        use eliot_store_api::{StoreFailureDisposition, StoreMutationDisposition};
        use eliot_store_surreal::Response;
        use eliot_store_surreal::diagnostics::{RequestOutcome, classify_response};

        let defect = frame_rejection_defect(None, "EBP frame rejected".to_owned());
        assert_eq!(
            classify_response(&defect),
            RequestOutcome::Defect,
            "an output failure classifies as a defect, never as a delivered receipt"
        );
        let mut round = BoundedEventLog::new();
        emit_dispatch_outcome(
            &mut round,
            BridgeBoundary::FrameRejection,
            "frame",
            &BridgeIdentity::from_response(&defect),
            &defect,
        );
        let defect_event = round.last().expect("the frame rejection is retained");
        assert!(
            defect_event.receipt_status().is_none(),
            "a pre-dispatch defect carries no receipt status"
        );
        assert_eq!(
            defect_event.failure_disposition(),
            Some(StoreFailureDisposition::InternalDefect)
        );
        let Response::Failure { failure } = &defect else {
            panic!("a frame-rejection defect is always the typed failure envelope");
        };
        assert_eq!(
            failure.mutation_disposition,
            StoreMutationDisposition::NotAttempted,
            "the output-failure response attempted no mutation"
        );
    }

    /// Case 742/8 transport-log accounting: reporting the send loss is a
    /// read-only projection — one retained record, nothing dropped, nothing
    /// retried and no receipt manufactured.
    #[cfg(windows)]
    fn assert_transport_log_reporting_is_read_only(transport: &BoundedEventLog) {
        assert_eq!(
            transport.len(),
            1,
            "reporting the send loss never appends a second record"
        );
        assert_eq!(
            transport.dropped(),
            0,
            "reporting the send loss drops nothing and retries nothing"
        );
    }

    // WORK_UNIT_CASE: 742/8
    #[cfg(windows)]
    #[test]
    fn mutation_result_and_response_send_records_stay_separate_on_response_loss() {
        use eliot_store_api::OperationId;
        use eliot_store_surreal::Response;

        // The typed unknown outcome a mutation that crossed the provider
        // boundary without a proven outcome leaves behind.
        let unknown = Response::Unknown {
            operation_id: OperationId::new("operation-742-8")
                .expect("operation id should be admissible"),
            reason: "EBP response failed: pipe closed before send".to_owned(),
        };
        // Receipt creation is logged only with owner evidence. The unknown
        // outcome carries no receipt, so the identity it projects is the
        // operation id alone.
        let identity = BridgeIdentity::from_response(&unknown);

        // The mutation result keeps `Unknown`: response loss after mutation is
        // never re-decided into commit or rollback on the recorded outcome.
        let mut mutation = BoundedEventLog::new();
        emit_dispatch_outcome(
            &mut mutation,
            BridgeBoundary::MutationResult,
            "mutation_result",
            &identity,
            &unknown,
        );
        let mutation_event = mutation.last().expect("the mutation result is retained");

        // Receipt transport emission is a separate record at its own boundary:
        // a created receipt is not a delivered one.
        let mut transport = BoundedEventLog::new();
        emit_lifecycle(
            &mut transport,
            BridgeBoundary::ResponseSend,
            "response_send",
            &identity,
            None,
        );
        let transport_event = transport.last().expect("the transport loss is retained");

        // Each proved property is asserted by the helper named for it: the
        // boundary split, the identity survival, and the two claims that a lost
        // response fabricates no delivery.
        assert_operation_identity_survives_transport_loss(&identity, transport_event);
        assert_mutation_result_and_response_send_are_separate(mutation_event, transport_event);
        assert_transport_loss_records_fabricate_no_delivery(mutation_event, transport_event);
        assert_frame_rejection_defect_fabricates_no_delivery();

        // Logging the send loss is a read-only projection: it appends no second
        // record, drops nothing, retries nothing and manufactures no receipt.
        report_events(&transport);
        assert_transport_log_reporting_is_read_only(&transport);
    }

    // WORK_UNIT_CASE: 742/12
    #[test]
    fn shutdown_and_process_exit_record_their_exact_bridge_dispositions() {
        use eliot_store_surreal::diagnostics::RequestOutcome;

        // Every transport-loop termination site in `serve_handshake_loop` is
        // gated on this exact predicate, so a latched quiesce is the one
        // reachable shutdown state without a live pipe.
        let (owner_quiesce, owner_quiesce_receiver) = tokio::sync::watch::channel(None);
        assert_eq!(
            owner_quiesce_reason(&owner_quiesce_receiver),
            None,
            "an unquiesced owner records no shutdown disposition"
        );
        owner_quiesce.send_replace(Some("snapshot owner accounting is unusable".to_owned()));
        assert_eq!(
            owner_quiesce_reason(&owner_quiesce_receiver).as_deref(),
            Some("snapshot owner accounting is unusable"),
            "the quiesce reason is the exact disposition the termination sites return"
        );

        // The in-flight operation identity the termination sites pass alongside
        // the disposition when a request was already dispatched.
        let operation_id = eliot_store_api::OperationId::new("operation-742-12")
            .expect("operation id should be admissible");
        let identity = BridgeIdentity::new().with_operation(&operation_id);

        // The loop-termination disposition is exactly one lifecycle
        // observation at the shutdown boundary, carrying no fabricated reason,
        // recovery, receipt status or detail.
        let mut shutdown = BoundedEventLog::new();
        emit_lifecycle(
            &mut shutdown,
            BridgeBoundary::Shutdown,
            "shutdown",
            &identity,
            None,
        );
        assert_eq!(
            shutdown.len(),
            1,
            "the loop-termination disposition is recorded exactly once"
        );
        let shutdown_event = shutdown
            .last()
            .expect("the shutdown disposition is retained");
        assert_eq!(shutdown_event.boundary().as_str(), "shutdown");
        assert_eq!(shutdown_event.operation(), "shutdown");
        assert_eq!(shutdown_event.outcome(), RequestOutcome::LifecycleObserved);
        assert_eq!(shutdown_event.reason(), None);
        assert_eq!(shutdown_event.recovery(), None);
        assert_eq!(shutdown_event.receipt_status(), None);
        assert_eq!(shutdown_event.failure_disposition(), None);
        assert_eq!(shutdown_event.detail(), None);
        assert_eq!(
            shutdown_event
                .identity()
                .operation_id()
                .map(eliot_store_api::OperationId::as_str),
            Some("operation-742-12"),
            "the in-flight operation identity survives into the disposition"
        );

        // The exit-code projection is a second, distinct disposition.
        let mut exit = BoundedEventLog::new();
        emit_lifecycle(
            &mut exit,
            BridgeBoundary::ProcessExit,
            "process_exit",
            &BridgeIdentity::new(),
            None,
        );
        let exit_event = exit
            .last()
            .expect("the process-exit disposition is retained");
        assert_eq!(exit_event.boundary().as_str(), "process_exit");
        assert_eq!(exit_event.operation(), "process_exit");
        assert_eq!(exit_event.outcome(), RequestOutcome::LifecycleObserved);
        assert!(
            exit_event.identity().operation_id().is_none(),
            "the exit-code projection admits no operation identity"
        );
        assert_ne!(
            shutdown_event.boundary().as_str(),
            exit_event.boundary().as_str(),
            "loop termination and process exit are distinct dispositions"
        );
        assert_ne!(
            shutdown_event.boundary().as_str(),
            BridgeBoundary::ResponseSend.as_str(),
            "the shutdown disposition is never the transport-loss boundary"
        );

        // Reporting the disposition emits it once and fabricates nothing more.
        report_events(&shutdown);
        assert_eq!(
            shutdown.len(),
            1,
            "reporting the disposition never appends a second record"
        );
        assert_eq!(
            shutdown.dropped(),
            0,
            "reporting the disposition drops nothing and retries nothing"
        );
    }
}
