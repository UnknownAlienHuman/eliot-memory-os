//! Closed Dreamer job dispatch (T12-05 K2, owner #781; T12-09 bound-worker
//! claim, Implements #702).
//!
//! Routes one authenticated operation per frame through
//! the K1 gateway ([`KernelStoreGateway::dreamer_job`](eliot_kernel_service::KernelStoreGateway::dreamer_job))
//! using the K0 types (`eliot_protocol::dreamer_job`). Two authenticated
//! callers exist, derived from the actual session only:
//!
//! * the `eliotd` requester ([`JobRole::Requester`]): `Submit`, `Status`,
//!   `RequestCancel`, `Reconcile`;
//! * the managed Dreamer worker (`eliot-dreamer`, `T12-09`,
//!   [`JobRole::Worker`]): exactly `LeaseExact` for the queued job its
//!   launch lineage recorded, and nothing else.
//!
//! A presented [`JobRole`] must agree with the derived role and must permit
//! the operation kind; a payload value never grants rights. The worker claim
//! additionally requires a retained launch lineage for the exact job/scope/
//! revision/fence
//! ([`dreamer_launch_permits_lease`](super::dispatch_launch::dreamer_dispatch_launch::dreamer_launch_permits_lease)):
//! a tampered, foreign, or unlaunched claim fences before any store call.
//!
//! No process is spawned inside this handler: admission and execution stay
//! on the K1 axis, while launch remains the explicit dispatch-launch seam
//! in [`super::dispatch_launch`]. No second launch identity is minted.
//!
//! Architecture: A12.2 Principal, Session and visibility; A13.2 Kernel and
//! failure domains; I1.8 Exact ownership and call paths.
//! Implementation: T12 K2 requester routing over the K0 contract and the K1
//! gateway; I14.21 unknown-commit recovery (unknown outcomes fence, they are
//! never reported as refusals).
//! Forbidden authority: must not fabricate ledger success, must not accept a
//! presented role as authority, must not spawn a worker, must not retry a
//! store call blindly.

use super::dispatch_launch::dreamer_dispatch_launch::{
    DREAMER_MODULE_ID, dreamer_launch_permits_lease,
};
use super::*;
use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse, JobOperation, JobRole};
use eliot_store_api::RequestMeta;
use serde::Deserialize;

/// Closed wire identity for the Dreamer job branch.
///
/// The operation string is the stable wire identity itself; there is no
/// second dispatch vocabulary and no generic JSON command routing. Callers
/// must still prove the typed envelope below: the operation string only
/// selects this closed entry.
pub const DREAMER_JOB_WIRE_ID: &str = "eliot.kernel.dreamer-job";

/// Returns whether the operation string selects the K2 Dreamer job route.
pub(crate) fn is_dreamer_operation(operation: &str) -> bool {
    operation == DREAMER_JOB_WIRE_ID
}

/// Typed K2 envelope: the store context plus one closed K0 job request.
///
/// Unknown fields are rejected at decode so the wire cannot be widened
/// without a contract change.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DreamerJobEnvelope {
    /// Fenced store context crossing the Kernel boundary.
    pub context: RequestMeta,
    /// One closed durable-job operation with its presented role.
    pub request: DurableJobRequest,
}

/// Store peer behind the K2 route.
///
/// Production binds [`KernelStoreGateway`](eliot_kernel_service::KernelStoreGateway)
/// with exactly one call per admitted envelope. Tests bind an in-memory
/// ledger owned by the test. The trait never routes: dispatch plus execute
/// validation always runs first, so a test double can only answer an already
/// admitted envelope, never admit one itself.
#[allow(async_fn_in_trait)]
pub(crate) trait DreamerJobStore {
    /// Applies one admitted Dreamer ledger operation exactly once.
    async fn dreamer_job(
        &self,
        context: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, String>;
}

#[cfg(windows)]
impl DreamerJobStore for KernelStoreGateway {
    async fn dreamer_job(
        &self,
        context: &RequestMeta,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, String> {
        KernelStoreGateway::dreamer_job(self, context, request).await
    }
}

/// Decodes the exact typed K2 envelope from a Dreamer frame payload.
///
/// The payload carries the closed operation string plus the fenced store
/// context under `context` and the full typed K0 request under `request`.
/// The wire is closed: exactly those three top-level keys are admitted. Both
/// halves are re-validated through their owning contracts
/// (`RequestMeta::validate`, `DurableJobRequest::validate`, which already
/// enforces the presented-role capability projection and the canonical digest
/// binding), and the operation fence must equal the context fence. Anything
/// else fences; nothing is defaulted and no admission is fabricated here.
fn dreamer_envelope_from_payload(
    payload: &serde_json::Value,
) -> Result<DreamerJobEnvelope, TransportError> {
    let object = payload
        .as_object()
        .ok_or(TransportError::SessionFenced)?;
    if object.len() != 3 {
        return Err(TransportError::SessionFenced);
    }
    let operation = object
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .ok_or(TransportError::SessionFenced)?;
    if !is_dreamer_operation(operation) {
        return Err(TransportError::SessionFenced);
    }
    let context_value = object
        .get("context")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let request_value = object
        .get("request")
        .cloned()
        .ok_or(TransportError::SessionFenced)?;
    let envelope: DreamerJobEnvelope =
        serde_json::from_value(serde_json::json!({"context": context_value, "request": request_value}))
            .map_err(|_| TransportError::SessionFenced)?;
    envelope
        .context
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    envelope
        .request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if envelope.request.request_identity.operation.state_fence != envelope.context.state_fence {
        return Err(TransportError::SessionFenced);
    }
    Ok(envelope)
}

/// Fail-closed classifier over stringified gateway/store errors.
///
/// Fence and unknown markers fence the session: claiming a typed refusal
/// when the store outcome is unknown (or when the gateway route itself is
/// fenced) would be a false proof. Every other (deterministic, typed) store
/// refusal projects as a typed reply so the requester can reconcile under
/// the same mutation identity. In particular, `UnknownOperation` ("unknown
/// named operation") is a deterministic refusal — the operation is not
/// admitted for this caller — and stays a typed reply, while any
/// outcome-unknown marker fences. The fence marker is the full word
/// "fenced" (a fenced gateway, generation, or session): a bare "fence"
/// also appears in the deterministic `FenceMismatch` refusal, which stays
/// a typed reply.
fn dreamer_store_error_fences(error: &str) -> bool {
    let folded = error.to_lowercase();
    folded.contains("fenced")
        || folded.contains("outcome is unknown")
        || folded.contains("unknown_outcome")
        || folded.contains("timed out")
        || folded.contains("timeout")
}

impl KernelComposition {
    /// Admits one decoded K2 envelope against the presenting session.
    ///
    /// The role is derived from the actual authenticated session only: the
    /// `eliotd` module (plus the current daemon session on Windows) yields
    /// [`JobRole::Requester`]. No Dreamer worker binding exists yet, so any
    /// other module — and any presented role that disagrees with the derived
    /// one — fences. The derived role must additionally permit the operation
    /// kind, and the session fence must equal the admitted context fence:
    /// neither the epoch nor the generation is ever taken from the envelope.
    fn admit_dreamer_caller(
        &self,
        session: &Session,
        envelope: &DreamerJobEnvelope,
    ) -> Result<(), TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
        let derived = JobRole::Requester;
        if envelope.request.role != derived {
            return Err(TransportError::SessionFenced);
        }
        if !derived.permits(envelope.request.operation.kind()) {
            return Err(TransportError::SessionFenced);
        }
        if session.module_generation.state_fence != envelope.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Admits one managed-worker `LeaseExact` claim against the presenting
    /// Dreamer session (T12-09, Implements #702).
    ///
    /// The role is derived from the actual authenticated session only: the
    /// `eliot-dreamer` module yields [`JobRole::Worker`], and only
    /// `LeaseExact` is admitted on this arm (launch/claim only — every other
    /// worker operation fences here even though the K0 projection would
    /// permit it, so a managed child can never Renew, Start, Checkpoint, or
    /// Publish through this path without its exact claim). The presented
    /// role must equal the derived one, the session must carry the Dreamer
    /// wire capability, and the session fence must equal the admitted
    /// context fence. Finally the claim must reproduce a retained launch
    /// lineage exactly (job, scope, revision, fence): a tampered, foreign,
    /// replayed-beyond-terminal, or unlaunched claim fences before any store
    /// call. Neither the epoch nor the generation is ever taken from the
    /// envelope, and no process is spawned here.
    fn admit_dreamer_worker_lease(
        session: &Session,
        envelope: &DreamerJobEnvelope,
    ) -> Result<(), TransportError> {
        if session.module_generation.module_id.as_str() != DREAMER_MODULE_ID {
            return Err(TransportError::SessionFenced);
        }
        if !session
            .capabilities
            .iter()
            .any(|capability| capability == DREAMER_JOB_WIRE_ID)
        {
            return Err(TransportError::SessionFenced);
        }
        let derived = JobRole::Worker;
        if envelope.request.role != derived {
            return Err(TransportError::SessionFenced);
        }
        let JobOperation::LeaseExact { selector, job_id } = &envelope.request.operation else {
            return Err(TransportError::SessionFenced);
        };
        if !derived.permits(envelope.request.operation.kind()) {
            return Err(TransportError::SessionFenced);
        }
        if session.module_generation.state_fence != envelope.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        if !dreamer_launch_permits_lease(
            job_id.as_str(),
            selector.scope_id.as_str(),
            selector.expected_revision,
            &selector.expected_fence,
        ) {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Admits one decoded K2 envelope against the presenting session,
    /// routing to the requester arm or the bound-worker claim arm by the
    /// authenticated session module. Anything that is neither the `eliotd`
    /// requester nor the bound Dreamer worker fences.
    fn admit_dreamer_envelope(
        &self,
        session: &Session,
        envelope: &DreamerJobEnvelope,
    ) -> Result<(), TransportError> {
        if session.module_generation.module_id.as_str() == DREAMER_MODULE_ID {
            Self::admit_dreamer_worker_lease(session, envelope)
        } else {
            self.admit_dreamer_caller(session, envelope)
        }
    }

    /// Dispatches one Dreamer job frame from an admitted session.
    ///
    /// The caller ([`KernelComposition::dispatch_frame`]) has already run the
    /// closed-gateway gates (generation poison, session/frame identity,
    /// daemon-session currency) and the per-kind service gate (intake
    /// requires `Ready`); those joins are re-checked here so direct callers
    /// cannot bypass them. The frame must ride the presenting session's
    /// connection, the operation string must be the exact Dreamer wire
    /// identity, and the payload must carry the typed [`DreamerJobEnvelope`]
    /// with a valid shape, fence binding, and presented role that agrees
    /// with the authenticated caller. The validated call is forwarded as
    /// [`KernelFrameAction::Dreamer`]; ledger-bound execution itself runs in
    /// [`KernelComposition::execute_dreamer_request`]. Unknown operations and
    /// mismatched joins fence; nothing is retried blindly and no admission
    /// is fabricated here. No process is spawned on this path.
    pub(crate) fn dispatch_dreamer_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if frame.kind != FrameKind::Request || frame.message_type != MessageType::Execute {
            return Err(TransportError::SessionFenced);
        }
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&identity.request.state_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        if frame.connection_id != session.connection_id {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let envelope = dreamer_envelope_from_payload(&payload)?;
        self.admit_dreamer_envelope(session, &envelope)?;
        Ok(KernelFrameAction::Dreamer {
            request_id,
            operation: DREAMER_JOB_WIRE_ID.to_owned(),
            payload,
        })
    }

    /// Executes one validated Dreamer job operation (T12-05 K2, T12-09
    /// bound-worker claim).
    ///
    /// Revalidates everything the dispatch path proved (closed operation
    /// name, the presenting session's `eliotd`-or-Dreamer binding, the typed
    /// envelope shape/fence/role/lineage joins), then performs exactly one
    /// [`KernelStoreGateway::dreamer_job`](eliot_kernel_service::KernelStoreGateway::dreamer_job)
    /// call through the retained canonical gateway and projects the answer
    /// with the frame's correlation identity echoed. A response that does
    /// not answer the admitted request fences instead of delivering a
    /// foreign receipt. Typed store refusals return as typed replies;
    /// fence/unknown markers and mechanical failures (missing gateway,
    /// poisoned lock, unprojectable reply) fence the session. No spawn, no
    /// dispatch-launch call, no second launch identity.
    pub async fn execute_dreamer_request(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if !is_dreamer_operation(operation) {
            return Err(TransportError::SessionFenced);
        }
        let module = session.module_generation.module_id.as_str();
        if module != ACTIVE_DAEMON_CALLER && module != DREAMER_MODULE_ID {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        let envelope = dreamer_envelope_from_payload(&payload)?;
        self.admit_dreamer_envelope(session, &envelope)?;
        #[cfg(windows)]
        {
            let gateway = self
                .canonical_store_gateway
                .lock()
                .map_err(|_| TransportError::SessionFenced)?
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            Self::project_dreamer_call(&*gateway, session, request_id, &envelope).await
        }
        #[cfg(not(windows))]
        {
            let _ = envelope;
            Err(TransportError::SessionFenced)
        }
    }

    /// Projects one admitted Dreamer store call into a correlated reply.
    ///
    /// Shared by production (over the retained K1 gateway) and tests (over
    /// an in-memory ledger behind the same [`DreamerJobStore`] port): the
    /// single store call, the `validate_for` answer binding, the
    /// request-identity echo, and the refusal/fence error split run here
    /// exactly once per admitted envelope.
    pub(crate) async fn project_dreamer_call(
        store: &impl DreamerJobStore,
        session: &Session,
        request_id: RequestId,
        envelope: &DreamerJobEnvelope,
    ) -> Result<Frame, TransportError> {
        match store
            .dreamer_job(&envelope.context, envelope.request.clone())
            .await
        {
            Ok(response) => {
                response
                    .validate_for(&envelope.request)
                    .map_err(|_| TransportError::SessionFenced)?;
                let mut reply = status_frame(
                    session,
                    FrameKind::Response,
                    MessageType::Result,
                    serde_json::to_value(&response)
                        .map_err(|_| TransportError::SessionFenced)?,
                )?;
                reply.request_id = Some(request_id);
                reply
                    .validate()
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(reply)
            }
            Err(error) => {
                if dreamer_store_error_fences(&error) {
                    return Err(TransportError::SessionFenced);
                }
                let mut reply = status_frame(
                    session,
                    FrameKind::Response,
                    MessageType::Result,
                    serde_json::json!({
                        "status": "error",
                        "operation": DREAMER_JOB_WIRE_ID,
                        "error": error,
                    }),
                )?;
                reply.request_id = Some(request_id);
                reply
                    .validate()
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(reply)
            }
        }
    }
}

#[cfg(test)]
mod dreamer_job_dispatch_tests {
    //! T12-05 K2 behaviour proofs (owner #781): authenticated requester
    //! routing over the real dispatch plus execute path.
    //!
    //! The Store peer behind the path is the only test double here (an
    //! in-memory ledger implementing [`DreamerJobStore`](super::DreamerJobStore)):
    //! every role, fence, wire, and correlation gate above it is the real
    //! production code. Cross-role denials fence before any store call, and
    //! the tests assert the ledger observed zero calls on each denied path.

    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
    use eliot_ipc::{PeerIdentity, Session};
    use eliot_kernel_service::{
        KernelActivationPermit, KernelControlCommand, KernelReadyReceipt, KernelServiceState,
    };
    use eliot_protocol::dreamer_job::{
        DurableJobRequest, DurableJobResponse, DurableRequestIdentity, JobOperation, JobRole,
        JobState,
    };
    use eliot_protocol::{
        EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
        RequestIdentity,
    };
    use eliot_runtime_contracts::{HealthVector, ServiceProcessState};
    use eliot_store_api::RequestMeta;
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use crate::KernelConfig;
    use crate::dispatch_launch::dreamer_dispatch_launch::{
        DREAMER_MODULE_ID, DreamerChildBinding, DreamerLaunchKeys, DreamerLeaseExpectation,
        DreamerMaterialError, DreamerReconcileOutcome, dreamer_launch_permits_lease,
        parse_dreamer_material_bytes, release_dreamer_launch, validate_dreamer_material,
    };
    use crate::dispatch_launch::{
        DreamerLaunchMaterial, PreparedDreamerLaunch, launch_admitted_dreamer_attempt,
        prepare_dreamer_launch, reconcile_launched_dreamer_attempt,
    };

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SUBMIT_OPERATION_JSON: &str = include_str!(
        "../../../crates/kernel/eliot-kernel-service/tests/data/dreamer-job-store-edge/submit-operation.json"
    );
    const STATUS_OPERATION_JSON: &str = include_str!(
        "../../../crates/kernel/eliot-kernel-service/tests/data/dreamer-job-store-edge/status-operation.json"
    );
    const LEASE_EXACT_OPERATION_JSON: &str = include_str!(
        "../../../crates/kernel/eliot-kernel-service/tests/data/dreamer-job-store-edge/lease-exact-operation.json"
    );
    const CONTEXT_JSON: &str = include_str!(
        "../../../crates/kernel/eliot-kernel-service/tests/data/dreamer-job-store-edge/context.json"
    );

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            NonZeroU64::new(sequence).expect("sequence"),
        )
        .expect("epoch")
    }

    fn temp_root(slug: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-dreamer-k2-{slug}-{}-{}",
            std::process::id(),
            super::super::unix_ms()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        root
    }

    fn handle(value: &str) -> eliot_platform::PlatformHandle {
        eliot_platform::PlatformHandle::new(value).expect("test handle")
    }

    fn candidate_binding() -> eliot_kernel_service::HostKernelCandidateBinding {
        use eliot_kernel_service::{HostFileIdentity, HostJobIdentity, HostJobRoot, RestartBudget};
        use eliot_runtime_contracts::{
            RegisteredActivityWakePolicy, SupervisionJournalEpoch,
            SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
        };
        eliot_kernel_service::HostKernelCandidateBinding {
            installation_id: handle("installation-1"),
            host_epoch: eliot_contracts::AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: test_epoch(1),
            activation_id: handle("activation-1"),
            artifact_hash: handle("artifact-1"),
            config_hash: handle("config-1"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
            host_process: eliot_kernel_service::HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: eliot_kernel_service::HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: eliot_kernel_service::HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "installation-1".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "host-lineage-1".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-1".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-1".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-lineage-1".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "watchdog-lineage-1".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .expect("supervision incarnation"),
            restart_budget: RestartBudget::new(1, 1).expect("restart budget"),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    /// Drives one composition to `Ready` so session binds prove exact
    /// authority agreement.
    fn ready_kernel(root: &Path) -> KernelComposition {
        let kernel = KernelComposition::new(KernelConfig::new(root)).expect("kernel composition");
        let candidate = candidate_binding();
        let mut service = kernel.service.lock().expect("service lock");
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff");
        let permit = KernelActivationPermit {
            operation_id: handle("op-dreamer-k2-1"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("txn-dreamer-k2-1"),
            journal_sequence: 1,
            generation: ResourceGeneration::genesis(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
                .expect("activation nonce"),
        };
        service
            .activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .expect("activate");
        let ready = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: permit.operation_id.clone(),
            activation_nonce_digest: service
                .activation_receipt()
                .expect("activation receipt")
                .activation_nonce_digest
                .clone(),
            process: eliot_kernel_service::ProcessObservation {
                process_id: handle("pid:42:start:10"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ev-dreamer-k2-1")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle("ev-dreamer-k2-1")],
        };
        service.publish_ready(ready).expect("publish ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        drop(service);
        kernel
    }

    /// Binds the authenticated `eliotd` requester session: the only caller
    /// the K2 wire derives a role for.
    fn eliotd_session(kernel: &KernelComposition) -> Session {
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let peer = PeerIdentity::authenticated_for_test(
            eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
                .expect("process binding"),
            "S-1-5-18".to_owned(),
            "0".to_owned(),
        )
        .expect("peer");
        let mut module_generation = policy.module_generation.clone();
        module_generation.module_id =
            eliot_contracts::ContractId::new("eliotd").expect("module id");
        Session {
            connection_id: "dreamer-k2-conn".to_owned(),
            protocol_version: ProtocolVersion::CURRENT,
            peer,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
            module_generation,
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: policy.allowed_capabilities.clone(),
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: policy.allowed_effects.clone(),
            session_epoch: 1,
            state: eliot_ipc::SessionState::Open,
        }
    }

    fn stale_fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("123e4567-e89b-12d3-a456-426614174000")
                    .expect("stale lineage"),
                NonZeroU64::new(9).expect("sequence"),
            )
            .expect("stale epoch"),
            ResourceGeneration::genesis(),
        )
    }

    /// Rebases one frozen operation to `fence`, keeping K0-internal
    /// equalities (`work_scope == admission.scope`, authority/validity
    /// epochs, scalar resource generations) exact.
    fn rebase_operation(
        operation: &mut serde_json::Value,
        fence: &serde_json::Value,
        epoch: &serde_json::Value,
        generation: u64,
    ) {
        if let Some(submission) = operation.get_mut("submission") {
            submission["work_scope"]["state_fence"] = fence.clone();
            submission["work_scope"]["resource_generation"] = serde_json::Value::from(generation);
            let scope = submission["work_scope"].clone();
            submission["admission"]["scope"] = scope;
            submission["admission"]["resource_generation"] = serde_json::Value::from(generation);
            submission["admission"]["authority"]["state_fence"] = fence.clone();
            submission["admission"]["authority"]["authority_epoch"] = epoch.clone();
            submission["admission"]["validity_epoch"] = epoch.clone();
        }
        if let Some(selector) = operation.get_mut("selector") {
            selector["expected_fence"] = fence.clone();
        }
        if operation.get("expected_fence").is_some() {
            operation["expected_fence"] = fence.clone();
        }
    }

    struct K2Request {
        ctx: RequestMeta,
        request: DurableJobRequest,
    }

    /// Builds one K2 request without asserting K0 validity, for callers that
    /// intentionally stage a role-denied or otherwise refused request.
    fn build_k2_request_raw(
        operation_fixture: &str,
        role: JobRole,
        fence: &StateFence,
        ctx_request_id: &str,
        operation_id: &str,
        idempotency_key: &str,
        transport_key: &str,
    ) -> K2Request {
        let mut operation_value: serde_json::Value =
            serde_json::from_str(operation_fixture).expect("operation fixture");
        build_k2_request_from_value(
            &mut operation_value,
            role,
            fence,
            ctx_request_id,
            operation_id,
            idempotency_key,
            transport_key,
        )
    }

    /// Builds one K2 request from an already shaped operation value (used
    /// for the inline lease-next/publish shapes that have no frozen file).
    fn build_k2_request_from_value(
        operation_value: &mut serde_json::Value,
        role: JobRole,
        fence: &StateFence,
        ctx_request_id: &str,
        operation_id: &str,
        idempotency_key: &str,
        transport_key: &str,
    ) -> K2Request {
        let fence_value = serde_json::to_value(fence).expect("fence json");
        let epoch_value =
            serde_json::to_value(&fence.authority_epoch).expect("epoch json");
        rebase_operation(
            operation_value,
            &fence_value,
            &epoch_value,
            fence.resource_generation.value(),
        );
        let operation: JobOperation =
            serde_json::from_value(operation_value.clone()).expect("operation decodes");
        let mut ctx_value: serde_json::Value =
            serde_json::from_str(CONTEXT_JSON).expect("context fixture");
        ctx_value["state_fence"] = fence_value.clone();
        ctx_value["request_id"] = serde_json::Value::String(ctx_request_id.to_owned());
        let ctx: RequestMeta =
            serde_json::from_value(ctx_value.clone()).expect("ctx decodes");
        let kind = operation.kind().as_str().to_owned();
        let identity_value = serde_json::json!({
            "request": {
                "request": {"metadata": ctx_value, "state_fence": fence_value.clone()},
                "idempotency_key": transport_key,
                "deadline_unix_ms": 600_000u64,
                "cancellation_id": "cancel-k2-01",
            },
            "operation": {
                "operation_id": operation_id,
                "request_id": "originating-k2",
                "idempotency_key": idempotency_key,
                "operation_kind": kind,
                "effect": "CANDIDATE",
                "state_fence": fence_value,
            },
            "canonical_request_hash": "0".repeat(64),
        });
        let mut identity: DurableRequestIdentity =
            serde_json::from_value(identity_value).expect("identity decodes");
        identity.canonical_request_hash = DurableRequestIdentity::digest_for(
            &identity.operation,
            &identity.request,
            &operation,
            role,
        )
        .expect("digest computes");
        K2Request {
            ctx,
            request: DurableJobRequest {
                request_identity: identity,
                role,
                operation,
            },
        }
    }

    /// Binds the managed Dreamer worker session: the only caller the K2
    /// bound-worker arm derives a role for. Capabilities are intersected
    /// down to the single Dreamer wire operation with no session effects,
    /// mirroring the dedicated front-door binds Doctor/testd use.
    fn dreamer_worker_session(kernel: &KernelComposition) -> Session {
        let policy = kernel
            .front_door_policy
            .lock()
            .expect("front-door policy")
            .clone();
        let peer = PeerIdentity::authenticated_for_test(
            eliot_ipc::ProcessBinding::from_observation(7, 9, r"C:\eliot\host.exe".to_owned())
                .expect("process binding"),
            "S-1-5-18".to_owned(),
            "0".to_owned(),
        )
        .expect("peer");
        let mut module_generation = policy.module_generation.clone();
        module_generation.module_id =
            eliot_contracts::ContractId::new(DREAMER_MODULE_ID).expect("module id");
        Session {
            connection_id: "dreamer-worker-conn".to_owned(),
            protocol_version: ProtocolVersion::CURRENT,
            peer,
            authority_epoch: policy.module_generation.state_fence.authority_epoch.clone(),
            module_generation,
            launch_nonce: policy.launch_nonce.clone(),
            capabilities: vec![DREAMER_JOB_WIRE_ID.to_owned()],
            privacy_classes: policy.allowed_privacy_classes.clone(),
            effects: Vec::new(),
            session_epoch: 1,
            state: eliot_ipc::SessionState::Open,
        }
    }

    /// Builds one worker `LeaseExact` claim for the exact queued values: the
    /// job/scope/revision the ledger bound, under the live fence. Forgery
    /// cases override one of the three denominators.
    fn lease_exact_request(
        job_id: &str,
        scope_id: &str,
        revision: u64,
        fence: &StateFence,
        tag: &str,
    ) -> K2Request {
        let mut operation_value: serde_json::Value =
            serde_json::from_str(LEASE_EXACT_OPERATION_JSON).expect("lease fixture");
        operation_value["job_id"] = serde_json::Value::String(job_id.to_owned());
        operation_value["selector"]["scope_id"] =
            serde_json::Value::String(scope_id.to_owned());
        operation_value["selector"]["expected_revision"] = serde_json::Value::from(revision);
        build_k2_request_from_value(
            &mut operation_value,
            JobRole::Worker,
            fence,
            &format!("k2-ctx-{tag}"),
            &format!("op-k2-{tag}"),
            &format!("idem-k2-{tag}"),
            &format!("transport-k2-{tag}"),
        )
    }

    fn dreamer_payload(k2: &K2Request) -> serde_json::Value {
        serde_json::json!({
            "operation": DREAMER_JOB_WIRE_ID,
            "context": serde_json::to_value(&k2.ctx).expect("ctx json"),
            "request": serde_json::to_value(&k2.request).expect("request json"),
        })
    }

    fn dreamer_frame(
        session: &Session,
        request_id: &str,
        payload: serde_json::Value,
    ) -> Frame {
        let frame_request_id = RequestId::new(request_id).expect("frame request id");
        let fence = session.module_generation.state_fence.clone();
        let fence_value = serde_json::to_value(&fence).expect("fence json");
        let identity: RequestIdentity = serde_json::from_value(serde_json::json!({
            "request": {
                "metadata": {
                    "request_id": serde_json::to_value(&frame_request_id).expect("id json"),
                    "session_id": null,
                    "task_id": null,
                    "product_id": "product-k2",
                    "source_id": "k2-frame",
                    "state_fence": fence_value.clone(),
                    "clock": {
                        "valid_time_ms": 1000,
                        "known_time_ms": 1001,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    },
                },
                "state_fence": fence_value,
            },
            "idempotency_key": "frame-transport-k2",
            "deadline_unix_ms": 600_000u64,
            "cancellation_id": "frame-cancel-k2",
        }))
        .expect("frame identity decodes");
        Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: session.connection_id.clone(),
            request_id: Some(frame_request_id),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(payload),
            trace_context: BTreeMap::new(),
        }
    }

    #[derive(Clone)]
    struct StoredK2Job {
        job: serde_json::Value,
        attempt: serde_json::Value,
        scope: serde_json::Value,
        revision: u64,
    }

    /// In-memory Store peer behind the real dispatch plus execute path: it
    /// answers Submit and Status from a real (if minimal) ledger and counts
    /// every call so denied paths can assert zero store mutations.
    struct FakeDreamerLedger {
        calls: Mutex<Vec<DurableJobRequest>>,
        jobs: Mutex<BTreeMap<String, StoredK2Job>>,
        leased: Mutex<BTreeSet<String>>,
        refusal: Mutex<Option<String>>,
    }

    impl FakeDreamerLedger {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                jobs: Mutex::new(BTreeMap::new()),
                leased: Mutex::new(BTreeSet::new()),
                refusal: Mutex::new(None),
            }
        }

        fn refusing(message: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                jobs: Mutex::new(BTreeMap::new()),
                leased: Mutex::new(BTreeSet::new()),
                refusal: Mutex::new(Some(message.to_owned())),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().expect("calls lock").len()
        }

        fn job_key(job_id: &serde_json::Value) -> String {
            job_id.as_str().expect("job id string").to_owned()
        }
    }

    impl DreamerJobStore for FakeDreamerLedger {
        async fn dreamer_job(
            &self,
            _context: &RequestMeta,
            request: DurableJobRequest,
        ) -> Result<DurableJobResponse, String> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(request.clone());
            if let Some(message) = self.refusal.lock().expect("refusal lock").clone() {
                return Err(message);
            }
            match &request.operation {
                JobOperation::Submit { submission } => {
                    let job_value =
                        serde_json::to_value(&submission.job_id).expect("job json");
                    let attempt_value =
                        serde_json::to_value(&submission.attempt_id).expect("attempt json");
                    let scope_value =
                        serde_json::to_value(&submission.work_scope).expect("scope json");
                    let response: DurableJobResponse = serde_json::from_value(
                        serde_json::json!({
                            "request_identity": serde_json::to_value(&request.request_identity)
                                .expect("identity json"),
                            "job_id": job_value.clone(),
                            "attempt_id": attempt_value.clone(),
                            "scope": scope_value.clone(),
                            "revision": 1,
                            "state": "QUEUED",
                            "disposition": "COMMITTED",
                            "receipt_id": format!(
                                "dreamer-receipt-{}",
                                request.request_identity.operation.operation_id.as_str()
                            ),
                            "lease": null,
                            "checkpoint": null,
                            "result_under_verification": null,
                            "outcome": null,
                            "selection_coverage": [],
                            "selection_frontier": null,
                        }),
                    )
                    .map_err(|error| error.to_string())?;
                    response
                        .validate_for(&request)
                        .map_err(|error| error.to_string())?;
                    self.jobs.lock().expect("jobs lock").insert(
                        Self::job_key(&job_value),
                        StoredK2Job {
                            job: job_value,
                            attempt: attempt_value,
                            scope: scope_value,
                            revision: 1,
                        },
                    );
                    Ok(response)
                }
                JobOperation::Status {
                    job_id,
                    attempt_id,
                    expected_revision,
                    ..
                } => {
                    let key = Self::job_key(
                        &serde_json::to_value(job_id).expect("job json"),
                    );
                    let stored = self
                        .jobs
                        .lock()
                        .expect("jobs lock")
                        .get(&key)
                        .cloned()
                        .ok_or_else(|| "dreamer test ledger: unknown job".to_owned())?;
                    if stored.revision != *expected_revision
                        || stored.attempt
                            != serde_json::to_value(attempt_id).expect("attempt json")
                    {
                        return Err("dreamer test ledger: revision conflict".to_owned());
                    }
                    let response: DurableJobResponse = serde_json::from_value(
                        serde_json::json!({
                            "request_identity": serde_json::to_value(&request.request_identity)
                                .expect("identity json"),
                            "job_id": stored.job.clone(),
                            "attempt_id": stored.attempt.clone(),
                            "scope": stored.scope.clone(),
                            "revision": stored.revision,
                            "state": "QUEUED",
                            "disposition": null,
                            "receipt_id": null,
                            "lease": null,
                            "checkpoint": null,
                            "result_under_verification": null,
                            "outcome": null,
                            "selection_coverage": [],
                            "selection_frontier": null,
                        }),
                    )
                    .map_err(|error| error.to_string())?;
                    response
                        .validate_for(&request)
                        .map_err(|error| error.to_string())?;
                    Ok(response)
                }
                JobOperation::LeaseExact { selector, job_id } => {
                    let key = Self::job_key(&serde_json::to_value(job_id).expect("job json"));
                    let stored = self
                        .jobs
                        .lock()
                        .expect("jobs lock")
                        .get(&key)
                        .cloned()
                        .ok_or_else(|| "dreamer test ledger: unknown job".to_owned())?;
                    // The selector must reproduce the queued record exactly:
                    // scope, revision, and fence. The K2 lineage gate already
                    // enforces this; the ledger re-proves it.
                    let selector_scope =
                        serde_json::to_value(&selector.scope_id).expect("selector scope json");
                    let selector_fence = serde_json::to_value(&selector.expected_fence)
                        .expect("selector fence json");
                    if stored.scope.get("scope_id") != Some(&selector_scope)
                        || stored.revision != selector.expected_revision
                        || stored.scope.get("state_fence") != Some(&selector_fence)
                    {
                        return Err("dreamer test ledger: lease selector mismatch".to_owned());
                    }
                    if !self.leased.lock().expect("leased lock").insert(key.clone()) {
                        return Err("dreamer test ledger: job already leased".to_owned());
                    }
                    let response: DurableJobResponse = serde_json::from_value(
                        serde_json::json!({
                            "request_identity": serde_json::to_value(&request.request_identity)
                                .expect("identity json"),
                            "job_id": stored.job.clone(),
                            "attempt_id": stored.attempt.clone(),
                            "scope": stored.scope.clone(),
                            "revision": stored.revision,
                            "state": "LEASED",
                            "disposition": "COMMITTED",
                            "receipt_id": format!(
                                "dreamer-receipt-lease-{}",
                                request.request_identity.operation.operation_id.as_str()
                            ),
                            "lease": {
                                "job_id": stored.job.clone(),
                                "attempt_id": stored.attempt.clone(),
                                "lease_id": {
                                    "namespace": "eliot.governor.work-lease",
                                    "revision": "v1",
                                    "value": "lease-t12-09-01",
                                },
                                "owner_artifact_id": serde_json::to_value(&selector.worker_artifact_id)
                                    .expect("worker json"),
                                "resource_generation": stored.scope.get("resource_generation").cloned().unwrap_or(serde_json::Value::from(1)),
                                "state_fence": stored.scope.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
                                "issued_at_unix_ms": 100,
                                "expires_at_unix_ms": 60000,
                                "revision": stored.revision,
                            },
                            "checkpoint": null,
                            "result_under_verification": null,
                            "outcome": null,
                            "selection_coverage": [],
                            "selection_frontier": null,
                        }),
                    )
                    .map_err(|error| error.to_string())?;
                    response
                        .validate_for(&request)
                        .map_err(|error| error.to_string())?;
                    Ok(response)
                }
                _ => Err(
                    "dreamer test ledger: operation not admitted on the requester path"
                        .to_owned(),
                ),
            }
        }
    }

    fn reply_json(frame: &Frame) -> serde_json::Value {
        match &frame.payload {
            ProtocolPayload::Json(value) => value.clone(),
            _ => panic!("dreamer reply must carry a JSON payload"),
        }
    }

    fn reply_response(frame: &Frame) -> DurableJobResponse {
        serde_json::from_value(reply_json(frame)).expect("typed dreamer response")
    }

    /// Mirrors the front-door driver loop: dispatch through the closed
    /// gateway, then project through the store peer only for an admitted
    /// Dreamer action. A fenced dispatch therefore reaches zero store calls
    /// by construction, exactly as in production.
    async fn dispatch_then_project(
        kernel: &KernelComposition,
        store: &FakeDreamerLedger,
        session: &Session,
        frame: &Frame,
    ) -> Result<Frame, TransportError> {
        match kernel.dispatch_frame(session, frame) {
            Ok(KernelFrameAction::Dreamer {
                request_id,
                operation,
                payload,
            }) => {
                assert_eq!(operation, DREAMER_JOB_WIRE_ID);
                let envelope =
                    dreamer_envelope_from_payload(&payload).expect("dispatched envelope");
                KernelComposition::project_dreamer_call(store, session, request_id, &envelope)
                    .await
            }
            Ok(_) => panic!("dreamer frame must dispatch to the Dreamer branch"),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn dreamer_wire_identity_is_closed() {
        assert_eq!(DREAMER_JOB_WIRE_ID, "eliot.kernel.dreamer-job");
        assert!(is_dreamer_operation(DREAMER_JOB_WIRE_ID));
        assert!(!is_dreamer_operation("eliot.kernel.doctor-repair-attempt"));
        assert!(!is_dreamer_operation("SUBMIT_JOB"));
        assert!(!is_dreamer_operation(""));
    }

    #[test]
    fn dreamer_store_error_classifier_fences_only_fence_and_unknown_markers() {
        assert!(dreamer_store_error_fences(
            "canonical-store gateway is fenced for rebind"
        ));
        assert!(dreamer_store_error_fences(
            "Kernel generation is fenced"
        ));
        assert!(dreamer_store_error_fences(
            "receipt envelope is missing; write outcome is unknown"
        ));
        assert!(dreamer_store_error_fences(
            "transport disconnected; application outcome is unknown"
        ));
        assert!(dreamer_store_error_fences("UNKNOWN_OUTCOME"));
        assert!(dreamer_store_error_fences(
            "transport disconnected; application outcome is unknown"
        ));
        assert!(dreamer_store_error_fences(
            "canonical-store gateway in-flight drain timed out"
        ));
        assert!(!dreamer_store_error_fences("revision conflict"));
        assert!(!dreamer_store_error_fences("state fence mismatch"));
        assert!(!dreamer_store_error_fences("store unavailable"));
        assert!(!dreamer_store_error_fences("unknown named operation"));
    }

    #[tokio::test]
    async fn requester_submit_status_round_trip_through_dispatch_and_execute() {
        let root = temp_root("round-trip");
        let kernel = ready_kernel(&root);
        let session = eliotd_session(&kernel);
        let fence = session.module_generation.state_fence.clone();
        let ledger = FakeDreamerLedger::new();

        // Submit -> durable QUEUED with an owner receipt.
        let submit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-submit-1",
            "op-k2-submit-1",
            "idem-k2-submit-1",
            "transport-k2-submit-1",
        );
        submit.request.validate().expect("submit validates");
        let frame = dreamer_frame(&session, "frame-k2-submit-1", dreamer_payload(&submit));
        let reply = dispatch_then_project(&kernel, &ledger, &session, &frame)
            .await
            .expect("submit projects");
        assert_eq!(
            reply.request_id,
            Some(RequestId::new("frame-k2-submit-1").expect("reply correlation"))
        );
        let response = reply_response(&reply);
        response
            .validate_for(&submit.request)
            .expect("submit response answers its request");
        assert_eq!(response.revision, 1);
        assert!(response.receipt_id.is_some());
        assert_eq!(ledger.call_count(), 1);

        // Status -> the same durable revision as a pure observation.
        let status = build_k2_request_raw(
            STATUS_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-status-1",
            "op-k2-status-1",
            "idem-k2-status-1",
            "transport-k2-status-1",
        );
        status.request.validate().expect("status validates");
        let frame = dreamer_frame(&session, "frame-k2-status-1", dreamer_payload(&status));
        let reply = dispatch_then_project(&kernel, &ledger, &session, &frame)
            .await
            .expect("status projects");
        assert_eq!(
            reply.request_id,
            Some(RequestId::new("frame-k2-status-1").expect("reply correlation"))
        );
        let response = reply_response(&reply);
        response
            .validate_for(&status.request)
            .expect("status response answers its request");
        assert_eq!(response.revision, 1);
        assert_eq!(response.disposition, None);
        assert_eq!(ledger.call_count(), 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn requester_cannot_publish_or_lease() {
        let root = temp_root("requester-denied");
        let kernel = ready_kernel(&root);
        let session = eliotd_session(&kernel);
        let fence = session.module_generation.state_fence.clone();
        let ledger = FakeDreamerLedger::new();

        // Requester + Publish: the K0 capability projection already refuses,
        // and K2 fences without a store call.
        let publish = publish_request(JobRole::Requester, &fence, "publish-denied");
        assert!(publish.request.validate().is_err());
        let frame = dreamer_frame(
            &session,
            "frame-k2-publish-denied",
            dreamer_payload(&publish),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "requester publish must fence"
        );

        // Requester + LeaseExact / LeaseNext: same closed denial.
        let lease_exact = build_k2_request_raw(
            LEASE_EXACT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-lease-exact-denied",
            "op-k2-lease-exact-denied",
            "idem-k2-lease-exact-denied",
            "transport-k2-lease-exact-denied",
        );
        assert!(lease_exact.request.validate().is_err());
        let frame = dreamer_frame(
            &session,
            "frame-k2-lease-exact-denied",
            dreamer_payload(&lease_exact),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "requester lease-exact must fence"
        );

        let mut lease_next_value: serde_json::Value =
            serde_json::from_str(LEASE_EXACT_OPERATION_JSON).expect("lease fixture");
        let selector = lease_next_value
            .get("selector")
            .cloned()
            .expect("lease selector");
        lease_next_value = serde_json::json!({"operation": "LEASE_NEXT", "selector": selector});
        let lease_next = build_k2_request_from_value(
            &mut lease_next_value,
            JobRole::Requester,
            &fence,
            "k2-ctx-lease-next-denied",
            "op-k2-lease-next-denied",
            "idem-k2-lease-next-denied",
            "transport-k2-lease-next-denied",
        );
        assert!(lease_next.request.validate().is_err());
        let frame = dreamer_frame(
            &session,
            "frame-k2-lease-next-denied",
            dreamer_payload(&lease_next),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "requester lease-next must fence"
        );

        assert_eq!(
            ledger.call_count(),
            0,
            "no forbidden store mutation may occur"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn worker_and_controller_operations_stay_fail_closed() {
        let root = temp_root("cross-role-denied");
        let kernel = ready_kernel(&root);
        let session = eliotd_session(&kernel);
        let fence = session.module_generation.state_fence.clone();
        let ledger = FakeDreamerLedger::new();

        // Worker + Submit: the K0 projection refuses arbitrary worker
        // submissions before K2 ever sees authority.
        let worker_submit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Worker,
            &fence,
            "k2-ctx-worker-submit",
            "op-k2-worker-submit",
            "idem-k2-worker-submit",
            "transport-k2-worker-submit",
        );
        assert!(worker_submit.request.validate().is_err());
        let frame = dreamer_frame(
            &session,
            "frame-k2-worker-submit",
            dreamer_payload(&worker_submit),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "worker submit must fence"
        );

        // Worker + LeaseExact is K0-valid, so this isolates the K2
        // derived-role gate: the presented Worker disagrees with the
        // authenticated Requester and must never grant lease rights.
        let worker_lease = build_k2_request_raw(
            LEASE_EXACT_OPERATION_JSON,
            JobRole::Worker,
            &fence,
            "k2-ctx-worker-lease",
            "op-k2-worker-lease",
            "idem-k2-worker-lease",
            "transport-k2-worker-lease",
        );
        worker_lease
            .request
            .validate()
            .expect("worker lease is K0-valid, denied only by K2 role agreement");
        let frame = dreamer_frame(
            &session,
            "frame-k2-worker-lease",
            dreamer_payload(&worker_lease),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "presented worker role must not agree with the requester session"
        );

        // Controller + Submit / Publish: K0 refuses both outright.
        for (make, tag, frame_tag) in [
            (
                SUBMIT_OPERATION_JSON,
                "controller-submit",
                "frame-k2-controller-submit",
            ),
            (
                LEASE_EXACT_OPERATION_JSON,
                "controller-lease",
                "frame-k2-controller-lease",
            ),
        ] {
            let denied = if tag == "controller-submit" {
                build_k2_request_raw(
                    make,
                    JobRole::Controller,
                    &fence,
                    "k2-ctx-controller-submit",
                    "op-k2-controller-submit",
                    "idem-k2-controller-submit",
                    "transport-k2-controller-submit",
                )
            } else {
                publish_request(JobRole::Controller, &fence, tag)
            };
            assert!(denied.request.validate().is_err(), "{tag} is K0-denied");
            let frame = dreamer_frame(&session, frame_tag, dreamer_payload(&denied));
            assert!(
                matches!(
                    dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                    Err(TransportError::SessionFenced)
                ),
                "{tag} must fence"
            );
        }

        // Controller + Status is K0-valid, so this isolates the same K2
        // agreement gate on the observation path.
        let controller_status = build_k2_request_raw(
            STATUS_OPERATION_JSON,
            JobRole::Controller,
            &fence,
            "k2-ctx-controller-status",
            "op-k2-controller-status",
            "idem-k2-controller-status",
            "transport-k2-controller-status",
        );
        controller_status
            .request
            .validate()
            .expect("controller status is K0-valid, denied only by K2 role agreement");
        let frame = dreamer_frame(
            &session,
            "frame-k2-controller-status",
            dreamer_payload(&controller_status),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "presented controller role must not agree with the requester session"
        );

        // A non-eliotd module never derives a K2 role, even with a
        // K0-valid requester envelope.
        let mut foreign_session = eliotd_session(&kernel);
        foreign_session.module_generation.module_id =
            eliot_contracts::ContractId::new("eliot-testd").expect("module id");
        foreign_session.connection_id = "dreamer-k2-foreign-conn".to_owned();
        let submit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-foreign-submit",
            "op-k2-foreign-submit",
            "idem-k2-foreign-submit",
            "transport-k2-foreign-submit",
        );
        submit.request.validate().expect("foreign envelope is K0-valid");
        let frame = dreamer_frame(
            &foreign_session,
            "frame-k2-foreign-submit",
            dreamer_payload(&submit),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &foreign_session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "non-eliotd modules must fence"
        );

        assert_eq!(
            ledger.call_count(),
            0,
            "no forbidden store mutation may occur"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn stale_fence_and_wire_violations_fence_without_store_calls() {
        let root = temp_root("fence-denied");
        let kernel = ready_kernel(&root);
        let session = eliotd_session(&kernel);
        let live_fence = session.module_generation.state_fence.clone();
        let ledger = FakeDreamerLedger::new();

        // K0-valid under a foreign fence, but the session fence disagrees.
        let stale = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &stale_fence(),
            "k2-ctx-stale-1",
            "op-k2-stale-1",
            "idem-k2-stale-1",
            "transport-k2-stale-1",
        );
        stale.request.validate().expect("stale request is K0-valid");
        let frame = dreamer_frame(&session, "frame-k2-stale-1", dreamer_payload(&stale));
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "stale fence must fence"
        );

        // Live envelope, but the frame rides the wrong connection.
        let live = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &live_fence,
            "k2-ctx-live-conn",
            "op-k2-live-conn",
            "idem-k2-live-conn",
            "transport-k2-live-conn",
        );
        live.request.validate().expect("live request validates");
        let mut frame = dreamer_frame(&session, "frame-k2-live-conn", dreamer_payload(&live));
        frame.connection_id = "foreign-conn".to_owned();
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "foreign connection must fence"
        );

        // Widened wire: one extra top-level key closes the branch.
        let mut widened = dreamer_payload(&live);
        widened
            .as_object_mut()
            .expect("payload object")
            .insert("debug".to_owned(), serde_json::Value::Bool(true));
        let frame = dreamer_frame(&session, "frame-k2-widened", widened);
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "widened wire must fence"
        );

        // Unknown field inside the typed context half.
        let mut bad_context = dreamer_payload(&live);
        bad_context
            .get_mut("context")
            .expect("context")
            .as_object_mut()
            .expect("context object")
            .insert("unknown_field".to_owned(), serde_json::Value::Null);
        let frame = dreamer_frame(&session, "frame-k2-bad-context", bad_context);
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "unknown context field must fence"
        );

        assert_eq!(
            ledger.call_count(),
            0,
            "no forbidden store mutation may occur"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn execute_without_gateway_fences_and_refusals_split_typed() {
        let root = temp_root("execute-split");
        let kernel = ready_kernel(&root);
        let session = eliotd_session(&kernel);
        let fence = session.module_generation.state_fence.clone();

        // Production entry without a retained gateway fences: the store call
        // can never run unbound.
        let submit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-nogw-1",
            "op-k2-nogw-1",
            "idem-k2-nogw-1",
            "transport-k2-nogw-1",
        );
        submit.request.validate().expect("submit validates");
        let payload = dreamer_payload(&submit);
        let action = kernel
            .dispatch_frame(&session, &dreamer_frame(&session, "frame-k2-nogw-1", payload.clone()))
            .expect("submit dispatches");
        let KernelFrameAction::Dreamer {
            request_id,
            operation,
            payload,
        } = action
        else {
            panic!("submit must dispatch to the Dreamer branch");
        };
        assert!(
            matches!(
                kernel
                    .execute_dreamer_request(&session, request_id, &operation, payload)
                    .await,
                Err(TransportError::SessionFenced)
            ),
            "missing gateway must fence"
        );

        // A deterministic store refusal projects as a typed reply carrying
        // the frame correlation.
        let refusing = FakeDreamerLedger::refusing("revision conflict");
        let envelope = dreamer_envelope_from_payload(
            &dreamer_payload(&submit),
        )
        .expect("envelope decodes");
        let reply = KernelComposition::project_dreamer_call(
            &refusing,
            &session,
            RequestId::new("frame-k2-refused-1").expect("reply correlation"),
            &envelope,
        )
        .await
        .expect("typed refusal must reply, not fence");
        assert_eq!(
            reply.request_id,
            Some(RequestId::new("frame-k2-refused-1").expect("reply correlation"))
        );
        let body = reply_json(&reply);
        assert_eq!(
            body.get("status").and_then(serde_json::Value::as_str),
            Some("error")
        );
        assert_eq!(refusing.call_count(), 1);

        // Fence and unknown markers fence instead of reporting a refusal.
        for marker in [
            "canonical-store gateway is fenced for rebind",
            "receipt envelope is missing; write outcome is unknown",
        ] {
            let fenced = FakeDreamerLedger::refusing(marker);
            assert!(
                matches!(
                    KernelComposition::project_dreamer_call(
                        &fenced,
                        &session,
                        RequestId::new("frame-k2-fenced-1").expect("reply correlation"),
                        &envelope,
                    )
                    .await,
                Err(TransportError::SessionFenced)
                ),
                "marker must fence: {marker}"
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    /// T12-09 protected Dreamer launch + `LeaseExact` claim (Implements
    /// #702): a real managed child claims the exact queued job through the
    /// bound-worker arm; a tampered/foreign/replayed claim spawns no second
    /// worker; termination and no-orphan are observed on reconcile and on
    /// failed spawn. This proves launch/claim only, not model completion.
    ///
    /// The Store peer is the only test double (the in-memory ledger above,
    /// extended with an exact `LeaseExact` arm): every role, fence, wire,
    /// lineage, material, and correlation gate on the path is the real
    /// production code, and every denial below reaches zero new store calls
    /// by construction.
    #[tokio::test]
    async fn managed_child_claims_exact_queued_job_forged_replay_denied() {
        let root = temp_root("dreamer-launch-claim");
        let kernel = ready_kernel(&root);
        let requester = eliotd_session(&kernel);
        let fence = requester.module_generation.state_fence.clone();
        let ledger = FakeDreamerLedger::new();

        // 1. Requester Submit -> durable QUEUED through the real K2 path.
        let submit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-t1209-submit",
            "op-k2-t1209-submit",
            "idem-k2-t1209-submit",
            "transport-k2-t1209-submit",
        );
        submit.request.validate().expect("submit validates");
        let frame = dreamer_frame(&requester, "frame-t1209-submit-1", dreamer_payload(&submit));
        let reply = dispatch_then_project(&kernel, &ledger, &requester, &frame)
            .await
            .expect("submit projects");
        let queued = reply_response(&reply);
        queued
            .validate_for(&submit.request)
            .expect("submit response answers its request");
        assert_eq!(ledger.call_count(), 1);
        let job_id = queued.job_id.as_str().to_owned();
        let attempt_id = queued.attempt_id.as_str().to_owned();
        let scope_id = queued.scope.scope_id.as_str().to_owned();
        let revision = queued.revision;

        // 2. Kernel records one launch lineage and stages the protected
        // handoff next to the composition-pinned child anchor. No spawn
        // happens here.
        let child_dir = root.join("dreamer-child");
        std::fs::create_dir_all(&child_dir).expect("child dir");
        let executable = child_dir.join("eliot-dreamer.exe");
        let executable_sha256 = crate::sha256_hex(b"eliot-dreamer-installed-package-bytes");
        let now_nanos = super::super::unix_ms().saturating_mul(1_000_000).max(1);
        let material = DreamerLaunchMaterial {
            keys: DreamerLaunchKeys {
                job_id: &job_id,
                attempt_id: &attempt_id,
            },
            queued: &queued,
            child: DreamerChildBinding {
                executable: &executable,
                executable_sha256: &executable_sha256,
                working_directory: &child_dir,
            },
        };
        let prepared = prepare_dreamer_launch(&kernel, &material, now_nanos).expect("prepare");
        let (nonce, operation_string, material_path) = match prepared {
            PreparedDreamerLaunch::Ready(ready) => (
                ready.nonce.clone(),
                ready.operation_id.as_str().to_owned(),
                ready.material_path.clone(),
            ),
            _ => panic!("fresh admitted job must prepare ready"),
        };
        assert!(material_path.exists(), "protected handoff must be staged");
        let staged = std::fs::read(&material_path).expect("staged bytes");
        // The staged bytes satisfy the exact child contract under live
        // authority: never caller bytes, always the bound lineage.
        let live_epoch = kernel
            .service
            .lock()
            .expect("service lock")
            .authority_epoch();
        let envelope = parse_dreamer_material_bytes(&staged).expect("staged parses closed");
        let validated =
            validate_dreamer_material(&envelope, &live_epoch).expect("staged validates");
        assert_eq!(validated.job_id, job_id);
        assert_eq!(validated.attempt_id, attempt_id);
        assert_eq!(validated.nonce, nonce);
        let grant_digest = validated.grant.grant_digest.clone();

        // 3. The managed child claims the exact queued job through the real
        // bound-worker arm: one dispatch, one store call, one lease.
        let worker = dreamer_worker_session(&kernel);
        let claim = lease_exact_request(&job_id, &scope_id, revision, &fence, "claim-1");
        claim.request.validate().expect("worker claim is K0-valid");
        let frame = dreamer_frame(&worker, "frame-t1209-claim-1", dreamer_payload(&claim));
        let calls_before = ledger.call_count();
        let reply = dispatch_then_project(&kernel, &ledger, &worker, &frame)
            .await
            .expect("exact claim projects");
        let claimed = reply_response(&reply);
        claimed
            .validate_for(&claim.request)
            .expect("claim response answers its request");
        assert_eq!(claimed.state, JobState::Leased);
        assert!(
            claimed.lease.is_some(),
            "the managed child holds exactly one lease"
        );
        assert_eq!(
            ledger.call_count(),
            calls_before + 1,
            "exactly one store call per admitted claim"
        );

        // 4. Forged, foreign, and off-arm claims fence with zero new store
        // calls: no second worker can be started this way.
        let denials = [
            // Foreign job identity under the live fence.
            lease_exact_request(
                "job-t1209-foreign-01",
                &scope_id,
                revision,
                &fence,
                "denied-job",
            ),
            // Foreign scope under the exact job.
            lease_exact_request(
                &job_id,
                "scope-t1209-foreign",
                revision,
                &fence,
                "denied-scope",
            ),
            // Wrong revision under the exact job and scope.
            lease_exact_request(&job_id, &scope_id, revision + 1, &fence, "denied-rev"),
            // Worker-presented observation (Status) is off the claim-only arm.
            build_k2_request_raw(
                STATUS_OPERATION_JSON,
                JobRole::Worker,
                &fence,
                "k2-ctx-denied-status",
                "op-k2-denied-status",
                "idem-k2-denied-status",
                "transport-k2-denied-status",
            ),
        ];
        for (index, denied) in denials.iter().enumerate() {
            denied
                .request
                .validate()
                .expect("denied claim stays K0-valid");
            let frame = dreamer_frame(
                &worker,
                &format!("frame-t1209-denied-{index}"),
                dreamer_payload(denied),
            );
            assert!(
                matches!(
                    dispatch_then_project(&kernel, &ledger, &worker, &frame).await,
                    Err(TransportError::SessionFenced)
                ),
                "forged claim {index} must fence"
            );
        }
        // The exact claim shape from a foreign module fences as well.
        let mut foreign_session = dreamer_worker_session(&kernel);
        foreign_session.module_generation.module_id =
            eliot_contracts::ContractId::new("eliot-testd").expect("module id");
        foreign_session.connection_id = "dreamer-foreign-conn".to_owned();
        let exact = lease_exact_request(&job_id, &scope_id, revision, &fence, "denied-module");
        let frame = dreamer_frame(
            &foreign_session,
            "frame-t1209-denied-module",
            dreamer_payload(&exact),
        );
        assert!(
            matches!(
                dispatch_then_project(&kernel, &ledger, &foreign_session, &frame).await,
                Err(TransportError::SessionFenced)
            ),
            "foreign module must fence"
        );
        assert_eq!(
            ledger.call_count(),
            calls_before + 1,
            "no denied claim may reach the store"
        );

        // 5. Exact replay wins no second worker: the store refuses typed
        // (the single lease stands) and the launch replays its retained
        // original with byte-identical material.
        let replay_frame =
            dreamer_frame(&worker, "frame-t1209-claim-replay", dreamer_payload(&claim));
        let reply = dispatch_then_project(&kernel, &ledger, &worker, &replay_frame)
            .await
            .expect("replay reaches the ledger as a typed refusal");
        let body = reply_json(&reply);
        assert_eq!(
            body.get("status").and_then(serde_json::Value::as_str),
            Some("error"),
            "replayed claim is a typed refusal, never a second lease"
        );
        let replayed =
            prepare_dreamer_launch(&kernel, &material, now_nanos + 5_000_000).expect("replay");
        match replayed {
            PreparedDreamerLaunch::ReplayOriginal { record } => {
                assert_eq!(record.nonce, nonce, "replay keeps the original nonce");
                assert_eq!(
                    record.operation_id, operation_string,
                    "replay keeps the original operation"
                );
            }
            _ => panic!("replay must return the retained original"),
        }
        assert_eq!(
            std::fs::read(&material_path).expect("material readback"),
            staged,
            "replay keeps byte-identical material"
        );

        // 6. Termination/no-orphan: reconcile closes the slot and reaps the
        // staged file; a stale release never frees, the exact one does.
        let expectation = DreamerLeaseExpectation {
            job_id: job_id.clone(),
            attempt_id: attempt_id.clone(),
            revision,
            scope_id: scope_id.clone(),
            fence: fence.clone(),
        };
        let outcome = reconcile_launched_dreamer_attempt(&kernel, &expectation).expect("reconcile");
        assert!(
            matches!(outcome, DreamerReconcileOutcome::Reconciled { .. }),
            "exact expectation reconciles"
        );
        assert!(
            !material_path.exists(),
            "reconciled launch reaps its material"
        );
        assert!(
            !dreamer_launch_permits_lease(&job_id, &scope_id, revision, &fence),
            "closed lineage permits no further claim"
        );
        assert!(
            release_dreamer_launch(&job_id, &"00".repeat(32))
                .expect("stale release")
                .is_none(),
            "stale release never frees the slot"
        );
        assert!(
            release_dreamer_launch(&job_id, &grant_digest)
                .expect("exact release")
                .is_some(),
            "exact release frees the slot"
        );
        assert!(
            matches!(
                reconcile_launched_dreamer_attempt(&kernel, &expectation).expect("reconcile"),
                DreamerReconcileOutcome::Unknown { .. }
            ),
            "released lineage reports unknown"
        );

        // 7. A failed spawn leaves no orphan: a fresh lineage prepares, the
        // missing executor fails closed, the file is reaped, and no slot
        // remains.
        let resubmit = build_k2_request_raw(
            SUBMIT_OPERATION_JSON,
            JobRole::Requester,
            &fence,
            "k2-ctx-t1209-resubmit",
            "op-k2-t1209-resubmit",
            "idem-k2-t1209-resubmit",
            "transport-k2-t1209-resubmit",
        );
        let frame = dreamer_frame(
            &requester,
            "frame-t1209-resubmit-1",
            dreamer_payload(&resubmit),
        );
        let reply = dispatch_then_project(&kernel, &ledger, &requester, &frame)
            .await
            .expect("resubmit projects");
        let queued_again = reply_response(&reply);
        let material_again = DreamerLaunchMaterial {
            keys: DreamerLaunchKeys {
                job_id: &job_id,
                attempt_id: &attempt_id,
            },
            queued: &queued_again,
            child: DreamerChildBinding {
                executable: &executable,
                executable_sha256: &executable_sha256,
                working_directory: &child_dir,
            },
        };
        let launched =
            launch_admitted_dreamer_attempt(&kernel, &material_again, now_nanos + 9_000_000).await;
        assert!(
            matches!(launched, Err(DreamerMaterialError::Gate(_))),
            "launch without a configured executor fails closed"
        );
        assert!(
            !material_path.exists(),
            "failed launch reaps its material and releases the slot"
        );
        assert!(
            matches!(
                reconcile_launched_dreamer_attempt(&kernel, &expectation).expect("reconcile"),
                DreamerReconcileOutcome::Unknown { .. }
            ),
            "failed launch retains no slot"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    /// Builds a Publish request over the live fence for role-denial proofs.
    /// The envelope is K0-shape-valid; only the role projection decides.
    fn publish_request(role: JobRole, fence: &StateFence, tag: &str) -> K2Request {
        let fence_value = serde_json::to_value(fence).expect("fence json");
        let mut operation_value = serde_json::json!({
            "operation": "PUBLISH_OUTCOME",
            "lease": {
                "job_id": "job-edge-01",
                "attempt_id": "attempt-edge-01",
                "lease_id": {
                    "namespace": "eliot.governor.work-lease",
                    "revision": "v1",
                    "value": format!("lease-{tag}"),
                },
                "owner_artifact_id": format!("worker-{tag}"),
                "resource_generation": fence.resource_generation.value(),
                "state_fence": fence_value,
                "issued_at_unix_ms": 10,
                "expires_at_unix_ms": 100,
                "revision": 1,
            },
            "outcome": {
                "state": "FAILED",
                "result": null,
                "evidence": [{
                    "artifact_id": format!("artifact-{tag}-evidence"),
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "role": "ARTIFACT",
                    "source_revision": format!("{tag}-evidence"),
                }],
                "verifier": null,
                "proof_ceiling": "CANDIDATE_ARTIFACT",
                "abstention_reason": null,
                "unresolved": [],
            },
            "now_unix_ms": 50,
        });
        build_k2_request_from_value(
            &mut operation_value,
            role,
            fence,
            &format!("k2-ctx-{tag}"),
            &format!("op-k2-{tag}"),
            &format!("idem-k2-{tag}"),
            &format!("transport-k2-{tag}"),
        )
    }
}
