#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use eliot_observability_runtime::{
    ObservabilityConfig, RollingLogPolicy, RuntimeProfile, SpoolPolicy,
};

#[cfg(windows)]
use eliot_ipc::NamedPipeServer;
use eliot_ipc::TransportLimits;
use eliot_contracts::{RequestId, StateFence};
use eliot_protocol::MessageType;
use eliot_protocol::{EncodingProfile, Frame, FrameKind, ProtocolPayload};
use eliot_store_surreal::diagnostics::{
    BoundedEventLog, BridgeBoundary, BridgeIdentity, CompatibilityDecision, emit_dispatch_outcome,
    emit_lifecycle, emit_received, emit_validation_rejected, install_startup_subscriber,
    project_compatibility_health, report_events,
};
use eliot_store_surreal::{
    CompatibilityVerdict, SERVICE_NAME, StoreComposition, StoreHandshakeIdentity,
    admit_authenticated_handshake, dispatch_with_log, install_compatibility_decision,
    load_compatibility_for_config, load_config, load_evidence_snapshot_verification,
    observed_identity_verdict, parse_compatibility_bytes, require_semantic_ready_for_pipe,
    resolve_compatibility_verdict, store_bootstrap_descriptor, validate_request_frame_with_log,
};

mod launch_mode;
use launch_mode::{LaunchMode, control_frame, parse_launch_mode, prepare_launch};

fn is_blob_process_stream_frame(frame: &Frame) -> bool {
    matches!(
        &frame.payload,
        ProtocolPayload::Json(payload)
            if payload.get("wire_id").and_then(serde_json::Value::as_str)
                == Some(eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_ID)
    )
}

fn blob_process_stream_response_frame(
    session: &eliot_store_surreal::StoreEbpSession,
    request_id: Option<RequestId>,
    response: eliot_blob_api::wire::BlobProcessStreamFrameResponse,
) -> Result<Frame, String> {
    response.validate().map_err(|error| error.to_string())?;
    let payload = serde_json::to_value(response)
        .map_err(|error| format!("Blob process-stream response encoding failed: {error}"))?;
    let frame = Frame {
        protocol_version: session.protocol_version(),
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: session.connection_id().to_owned(),
        request_id,
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate().map_err(|error| error.to_string())?;
    Ok(frame)
}

async fn dispatch_blob_process_stream_sink(
    composition: &StoreComposition,
    transport: &mut eliot_store_surreal::StoreEbpSession,
    identity: &eliot_protocol::RequestIdentity,
    request: eliot_blob_api::wire::ProcessStreamSinkWireRequest,
) -> eliot_blob_api::wire::ProcessStreamSinkWireResponse {
    use eliot_blob_api::wire::{
        ProcessStreamSinkWireRequest as Request, ProcessStreamSinkWireResponse as Response,
        ProcessStreamSinkUnavailableReason as Unavailable,
    };
    use eliot_process::stream_sink::{
        ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend,
        ProcessStreamSinkFinalizeRequest, ProcessStreamSinkOpenRequest,
        ProcessStreamSinkUnknownOutcome,
    };

    fn reject() -> Response {
        Response::Unavailable {
            reason: Unavailable::RequestRejected,
        }
    }

    fn encode<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, Response> {
        serde_json::to_value(value).map_err(|_| Response::Unknown)
    }

    fn binding_ref(binding: &eliot_blob_api::wire::ProcessStreamSinkBindingRef) -> &str {
        &binding.binding_ref
    }

    fn same_fence(
        observed: &StateFence,
        identity: &eliot_protocol::RequestIdentity,
    ) -> bool {
        observed == &identity.request.state_fence
    }

    fn failure(error: eliot_process::stream_sink::ProcessStreamSinkError) -> Response {
        use eliot_process::stream_sink::ProcessStreamSinkError as Error;
        match error {
            Error::ProviderUnavailable => Response::Unavailable {
                reason: Unavailable::ProviderUnavailable,
            },
            Error::AdmissionFenced { .. } => Response::Unavailable {
                reason: Unavailable::AdmissionFenced,
            },
            Error::StorageCapacity {
                possible_effect: false,
                ..
            } => Response::Unavailable {
                reason: Unavailable::Capacity,
            },
            Error::InvalidReference { .. }
            | Error::InvalidDigest { .. }
            | Error::InvalidLimits { .. }
            | Error::InvalidBinding
            | Error::InvalidRequest { .. }
            | Error::SessionMismatch
            | Error::BindingMismatch
            | Error::StreamMismatch
            | Error::PolicyMismatch
            | Error::SourceMismatch
            | Error::OpenDigestMismatch
            | Error::SequenceGap { .. }
            | Error::OffsetMismatch { .. }
            | Error::OverlapOrOutOfOrder
            | Error::MismatchedReplay
            | Error::ChunkLimitExceeded
            | Error::AppendPayloadLimitExceeded
            | Error::TotalLimitExceeded
            | Error::ChunkCountLimitExceeded
            | Error::PreviewLimitExceeded
            | Error::InFlightChunkLimitExceeded
            | Error::InFlightByteLimitExceeded
            | Error::AppendAfterFinalizing
            | Error::Terminal
            | Error::TerminalIdentityConflict
            | Error::TerminalCommandStateMismatch => reject(),
            Error::StorageCapacity {
                possible_effect: true,
                ..
            }
            | Error::PossibleEffectUnknown { .. }
            | Error::EvidenceInvariant { .. }
            | Error::IntegrityFailure { .. }
            | Error::Serialization { .. } => Response::Unknown,
        }
    }

    match request {
        Request::Open {
            capability,
            body,
            owner_facts,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            let open = match serde_json::from_value::<ProcessStreamSinkOpenRequest>(*body) {
                Ok(open) if open.validate().is_ok() => open,
                _ => return reject(),
            };
            match composition
                .blob_sink_open(
                    transport,
                    identity,
                    &capability.reference,
                    &owner_facts,
                    open,
                )
                .await
            {
                Ok((binding_ref, session)) => Response::Opened {
                    binding: eliot_blob_api::wire::ProcessStreamSinkBindingRef {
                        binding_ref,
                        session_id: session.session_id().as_str().to_owned(),
                        source_id: session.source_id().as_str().to_owned(),
                        terminal_id: session.terminal_id().as_str().to_owned(),
                        open_request_sha256: session.open_request_sha256().to_owned(),
                    },
                },
                Err(error) => failure(error),
            }
        }
        Request::Append {
            capability,
            binding,
            body,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            let append = match serde_json::from_value::<ProcessStreamSinkAppend>(*body) {
                Ok(append) if append.validate().is_ok() => append,
                _ => return reject(),
            };
            match composition
                .blob_sink_append(
                    transport,
                    identity,
                    &capability.reference,
                    binding_ref(&binding),
                    append,
                )
                .await
            {
                Ok(disposition) => match encode(&disposition) {
                    Ok(body) => Response::AppendDisposition {
                        body: Box::new(body),
                    },
                    Err(response) => response,
                },
                Err(error) => failure(error),
            }
        }
        Request::Finalize {
            capability,
            binding,
            body,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            let finalize = match serde_json::from_value::<ProcessStreamSinkFinalizeRequest>(*body) {
                Ok(finalize) if finalize.validate().is_ok() => finalize,
                _ => return reject(),
            };
            match composition
                .blob_sink_finalize(
                    transport,
                    identity,
                    &capability.reference,
                    binding_ref(&binding),
                    finalize,
                )
                .await
            {
                Ok(terminal) => match encode(&terminal) {
                    Ok(body) => Response::Finalized {
                        body: Box::new(body),
                    },
                    Err(response) => response,
                },
                Err(error) => failure(error),
            }
        }
        Request::Abort {
            capability,
            binding,
            body,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            let abort = match serde_json::from_value::<ProcessStreamSinkAbortRequest>(*body) {
                Ok(abort) if abort.validate().is_ok() => abort,
                _ => return reject(),
            };
            match composition
                .blob_sink_abort(
                    transport,
                    identity,
                    &capability.reference,
                    binding_ref(&binding),
                    abort,
                )
                .await
            {
                Ok(terminal) => match encode(&terminal) {
                    Ok(body) => Response::Aborted {
                        body: Box::new(body),
                    },
                    Err(response) => response,
                },
                Err(error) => failure(error),
            }
        }
        Request::Readback {
            capability,
            binding,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            match composition
                .blob_sink_readback(
                    transport,
                    identity,
                    &capability.reference,
                    binding_ref(&binding),
                )
                .await
            {
                Ok(readback) => match encode(&readback) {
                    Ok(body) => Response::Readback {
                        body: Box::new(body),
                    },
                    Err(response) => response,
                },
                Err(error) => failure(error),
            }
        }
        Request::Reconcile {
            capability,
            binding,
            body,
            fence,
            deadline_ms,
        } => {
            if !same_fence(&fence, identity) || deadline_elapsed(deadline_ms) {
                return reject();
            }
            let outcome = match serde_json::from_value::<ProcessStreamSinkUnknownOutcome>(*body) {
                Ok(outcome) if outcome.validate().is_ok() => outcome,
                _ => return reject(),
            };
            match composition
                .blob_sink_reconcile(
                    transport,
                    identity,
                    &capability.reference,
                    binding_ref(&binding),
                    outcome,
                )
                .await
            {
                Ok(readback) => match encode(&readback) {
                    Ok(body) => Response::Readback {
                        body: Box::new(body),
                    },
                    Err(response) => response,
                },
                Err(error) => failure(error),
            }
        }
    }
}

async fn dispatch_blob_process_stream(
    composition: &StoreComposition,
    transport: &mut eliot_store_surreal::StoreEbpSession,
    identity: &eliot_protocol::RequestIdentity,
    request: eliot_blob_api::wire::BlobProcessStreamFrameRequest,
) -> Result<eliot_blob_api::wire::BlobProcessStreamFrameResponse, String> {
    use eliot_blob_api::wire::{
        BlobProcessStreamFrameResponse, BlobProcessStreamOperationResponse,
        BlobProcessStreamOperationRequest, ProcessStreamSourceReadbackResponse,
    };

    request.validate().map_err(|error| error.to_string())?;
    let operation = match request.operation {
        BlobProcessStreamOperationRequest::Sink { request } => {
            BlobProcessStreamOperationResponse::Sink {
                response: dispatch_blob_process_stream_sink(
                    composition,
                    transport,
                    identity,
                    request,
                )
                .await,
            }
        }
        BlobProcessStreamOperationRequest::SourceReadback { request } => {
            let response = if deadline_elapsed(request.deadline_ms) {
                ProcessStreamSourceReadbackResponse::Unknown
            } else {
                match composition
                    .blob_source_readback(
                        transport,
                        identity,
                        request.clone(),
                    )
                    .await
                {
                    Ok(response) => {
                        validate_source_readback_response(&request, identity, &response)?;
                        response
                    }
                    Err(eliot_process::stream_sink::ProcessStreamSinkError::AdmissionFenced {
                        ..
                    }) => ProcessStreamSourceReadbackResponse::Unknown,
                    Err(eliot_process::stream_sink::ProcessStreamSinkError::ProviderUnavailable)
                    | Err(eliot_process::stream_sink::ProcessStreamSinkError::PossibleEffectUnknown {
                        ..
                    })
                    | Err(eliot_process::stream_sink::ProcessStreamSinkError::IntegrityFailure {
                        ..
                    }) => ProcessStreamSourceReadbackResponse::Unknown,
                    Err(error) => return Err(error.to_string()),
                }
            };
            BlobProcessStreamOperationResponse::SourceReadback { response }
        }
    };
    let response = BlobProcessStreamFrameResponse {
        wire_id: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_ID.to_owned(),
        wire_revision: eliot_blob_api::wire::BLOB_PROCESS_STREAM_WIRE_REVISION,
        operation,
    };
    response.validate().map_err(|error| error.to_string())?;
    Ok(response)
}

fn validate_source_readback_response(
    request: &eliot_blob_api::wire::ProcessStreamSourceReadbackRequest,
    identity: &eliot_protocol::RequestIdentity,
    response: &eliot_blob_api::wire::ProcessStreamSourceReadbackResponse,
) -> Result<(), String> {
    use eliot_blob_api::wire::{
        ProcessStreamSourceReadbackResponse, PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
    };

    if let ProcessStreamSourceReadbackResponse::Ready {
        bytes,
        whole_source_sha256,
        whole_source_byte_length,
        chunk_offset,
        observed_sha256,
        observed_byte_length,
        ready_receipt_ref,
        source_owner_generation,
        readback_receipt_id,
        observed_fence,
        observed_at_unix_ms,
    } = response
    {
        use sha2::{Digest, Sha256};
        let chunk_sha256 = format!("{:x}", Sha256::digest(bytes));
        let chunk_end = chunk_offset
            .checked_add(*observed_byte_length)
            .ok_or_else(|| "Blob source-readback chunk offset overflow".to_owned())?;
        if *chunk_offset != request.offset
            || bytes.len() > PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES as usize
            || *observed_byte_length != bytes.len() as u64
            || chunk_sha256 != *observed_sha256
            || whole_source_sha256 != &request.expected_sha256
            || *whole_source_byte_length != request.expected_byte_length
            || ready_receipt_ref != &request.ready_receipt_ref
            || chunk_end > request.expected_byte_length
            || source_owner_generation == &0
            || readback_receipt_id.trim().is_empty()
            || *observed_at_unix_ms == 0
            || observed_fence != &identity.request.state_fence
        {
            return Err("Blob source-readback evidence does not match the exact request".to_owned());
        }
    }
    Ok(())
}

fn deadline_elapsed(deadline_ms: u64) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .is_none_or(|now_ms| now_ms >= deadline_ms)
}

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
) -> Result<(), String> {
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
    if let Err(error) = server
        .wait_for_authenticated_client(
            Duration::from_millis(config.connect_timeout_ms),
            &expectation,
        )
        .await
        .map_err(|error| format!("authenticated client admission failed: {error}"))
    {
        report_stage_outcome(
            BridgeBoundary::PipeBind,
            "pipe_bind",
            &BridgeIdentity::new(),
            false,
        );
        return Err(error);
    }
    report_stage_outcome(
        BridgeBoundary::PipeBind,
        "pipe_bind",
        &BridgeIdentity::new(),
        true,
    );
    let hello_frame = match server
        .receive_frame(limits)
        .await
        .map_err(|error| format!("EBP hello receive failed: {error}"))
    {
        Ok(frame) => frame,
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
    let handshake_identity = StoreHandshakeIdentity::new(
        composition.operation_manifest_digest().to_owned(),
        serde_json::json!({
            "root_id": composition.blob_owner().root_id(),
            "owner_id": composition.blob_owner().owner_id().as_str(),
            "process_id": composition.blob_owner().process_id(),
            "claim_id": composition.blob_owner().claim_id(),
        }),
    )
    .with_blob_process_stream_available(composition.blob_process_stream_supported());
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
    if let Err(error) = server
        .send_frame(&handshake_frame, negotiated_limits)
        .await
        .map_err(|error| format!("EBP handshake response failed: {error}"))
    {
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
        return Err(error);
    }

    loop {
        let frame = match server
            .receive_frame(negotiated_limits)
            .await
            .map_err(|error| format!("EBP frame rejected: {error}"))
        {
            Ok(frame) => frame,
            Err(error) => {
                composition
                    .release_blob_stream_session(session.connection_id())
                    .await;
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
        if is_blob_process_stream_frame(&frame) {
            let request_identity = eliot_store_surreal::validate_blob_process_stream_request_frame(
                &mut session,
                &frame,
            );
            let response_frame = match request_identity {
                Ok(identity) => {
                    let request = match &frame.payload {
                        ProtocolPayload::Json(payload) => serde_json::from_value::<
                            eliot_blob_api::wire::BlobProcessStreamFrameRequest,
                        >(payload.clone())
                        .map_err(|error| {
                            format!("invalid Blob process-stream request: {error}")
                        })?,
                        _ => return Err("Blob process-stream request must be JSON".to_owned()),
                    };
                    match dispatch_blob_process_stream(
                        composition,
                        &mut session,
                        &identity,
                        request,
                    )
                    .await
                    {
                        Ok(response) => blob_process_stream_response_frame(
                            &session,
                            frame.request_id.clone(),
                            response,
                        )?,
                        Err(error) => {
                            let defect = frame_rejection_defect(frame.request_id.clone(), error);
                            eliot_store_api::response_frame(
                                session.connection_id(),
                                session.protocol_version(),
                                frame.request_id.clone(),
                                defect,
                            )
                            .map_err(|error| {
                                format!("invalid Blob rejection response: {error}")
                            })?
                        }
                    }
                }
                Err(error) => {
                    let defect = frame_rejection_defect(frame.request_id.clone(), error);
                    eliot_store_api::response_frame(
                        session.connection_id(),
                        session.protocol_version(),
                        frame.request_id.clone(),
                        defect,
                    )
                    .map_err(|error| format!("invalid Blob rejection response: {error}"))?
                }
            };
            if let Err(error) = server
                .send_frame(&response_frame, negotiated_limits)
                .await
                .map_err(|error| format!("Blob process-stream response failed: {error}"))
            {
                composition
                    .release_blob_stream_session(session.connection_id())
                    .await;
                return Err(error);
            }
            continue;
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
                composition
                    .release_blob_stream_session(session.connection_id())
                    .await;
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
        if let Err(error) = server
            .send_frame(&response_frame, negotiated_limits)
            .await
            .map_err(|error| format!("EBP response failed: {error}"))
        {
            composition
                .release_blob_stream_session(session.connection_id())
                .await;
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
            return Err(error);
        }
    }
}

#[cfg(windows)]
#[allow(clippy::print_stdout)]
// This standalone service has no initialized telemetry sink before startup;
// stderr is the only fail-closed launch diagnostic available to its supervisor,
// and the visible non-writer readiness state must be reported there.
#[allow(clippy::print_stderr)]
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
    let mut compatibility = enforce_store_compatibility(&config);
    let composed = StoreComposition::new(&config);
    report_stage_outcome(
        BridgeBoundary::Startup,
        "startup",
        &BridgeIdentity::new(),
        composed.is_ok(),
    );
    let composition = composed?;
    let connected = composition.connect().await;
    report_stage_outcome(
        BridgeBoundary::Startup,
        "startup",
        &BridgeIdentity::new(),
        connected.is_ok(),
    );
    connected?;
    // Post-connect re-verification (issue #1932): the adapter has now proved
    // spawned-artifact identity, listener ownership and server major over its
    // ownership-verified channel. Re-resolve the installation-visible decision
    // before serving: a record swapped, revoked or drifted across the
    // provider-startup window keeps the installation non-writer here, never at
    // the first canonical write. `combine` is fail-closed, so an admitted
    // earlier stage can never re-admit a maintenance verdict.
    compatibility = compatibility.combine(enforce_store_compatibility(&config));
    // Observed-identity binding (issue #1932, backend handoff §3): the
    // adapter proved the live version and spawn-validated digest over its
    // ownership-verified channel during connect. Bind the record echo to
    // that observation before serving: a rotated binary or drifted record is
    // visible maintenance here, never an accepted write.
    compatibility = compatibility.combine(bind_observed_identity(&composition, &config)?);
    if !compatibility.is_writer_admitted() {
        // Visible non-writer readiness: the store is up and answers
        // health/readiness, and every canonical mutation is refused. The
        // refusal is enforced on the mutation path, not by refusing to serve.
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
    serve_handshake_loop(&composition, &config).await
}

#[cfg(not(windows))]
async fn run() -> Result<(), String> {
    Err("the production store endpoint requires Windows authenticated named pipes".to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use super::*;

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
}
