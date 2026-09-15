//! Kernel admission client transport for native-worker lifecycle (Wave C).
//!
//! Architecture: Kernel is the governing admission authority per
//! `docs/architecture/ELIOT_ARCHITECTURE.md` (A0.3, A2.2, A12.2, A12.3,
//! A13.2; ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02). Native-worker is a thin
//! composition boundary that must not assume or synthesize admission/authority.
//!
//! Implementation: Uses `eliot-cli::kernel_client::KernelClient` health probe and
//! typed `native_worker.*` transact spans per
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` (I1.2, I7.3, I7.5, I15.2,
//! P.3, I2.23) and the `bins/eliot-native-worker` crate boundary. Fails closed
//! until Kernel supplies a session-bound claim and preserves exact transport
//! error mapping and handshake strings.
//!
//! Responsibility: Kernel admission client transport only — health handshake,
//! typed registration/claim/readiness/heartbeat/checkpoint/result/cancel
//! spans, and typed `KernelAdmissionRequired` error mapping.
//!
//! Forbidden: No Kernel semantic or admission authority, no native process
//! lifecycle/supervision, no Store/canonical writer, no Dreamer/research/curation,
//! no route/provider selection, no default/retry/adoption/mint and no fabrication
//! of process requests or permits. Transport errors stay transport errors:
//! they are never mapped to readiness, admission, or success.

use std::sync::{Arc, Mutex};

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_native_worker_core::{
    CheckpointProviderOutcome, CheckpointReceiptFacts, ClaimAdmissionRequest,
    DurableCheckpointPort, DurableCheckpointRequest, DurableReplayPort, DurableRequestDecision,
    EventAckReceipt, NativeCancellationEnvelope, NativeCheckpointEnvelope, NativeCheckpointId,
    NativeHeartbeatEnvelope, NativeLifecycleBinding, NativeReadyReport, NativeResultEnvelope,
    NativeWorkerClaim, NativeWorkerReadiness, NativeWorkerRegistration, ProviderFailure,
    ReadinessSubmission, WorkerEventDraft, WorkerEventEnvelope,
};
use serde::{Deserialize, Serialize};

use super::NativeWorkerError;
use crate::AdmittedLifecycle;

/// Registers (or renews) one worker generation. Paired with the Kernel route.
pub const NATIVE_WORKER_REGISTRATION_OPERATION: &str = "native_worker.registration";
/// Claims exactly one Kernel-owned execution unit. Paired with the Kernel route.
pub const NATIVE_WORKER_CLAIM_OPERATION: &str = "native_worker.claim";
/// Submits one typed ready-or-blocked verdict. Paired with the Kernel route.
pub const NATIVE_WORKER_READY_OPERATION: &str = "native_worker.ready";
/// Observes generation liveness; never authority. Paired with the Kernel route.
pub const NATIVE_WORKER_HEARTBEAT_OPERATION: &str = "native_worker.heartbeat";
/// Stores one checkpoint reference. Paired with the Kernel route.
pub const NATIVE_WORKER_CHECKPOINT_OPERATION: &str = "native_worker.checkpoint";
/// Submits one result digest; not acceptance. Paired with the Kernel route.
pub const NATIVE_WORKER_RESULT_SUBMIT_OPERATION: &str = "native_worker.result_submit";
/// Observes cancellation for one exact attempt. Paired with the Kernel route.
pub const NATIVE_WORKER_CANCEL_OBSERVE_OPERATION: &str = "native_worker.cancel_observe";
/// Reconciles one exact claim after a lost acknowledgement.
///
/// Paired with `NATIVE_WORKER_RECONCILE_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_reconcile_route.rs:70` and listed in
/// the sibling lifecycle route's `is_native_worker_operation`; both lists
/// must stay identical.
pub const NATIVE_WORKER_RECONCILE_OPERATION: &str = "native_worker.reconcile";
/// Looks up one durable replay identity without claiming it.
///
/// Paired with `NATIVE_WORKER_REPLAY_LOOKUP_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_replay_route.rs:89`; both lists must
/// stay identical.
pub const NATIVE_WORKER_REPLAY_LOOKUP_OPERATION: &str = "native_worker.replay_lookup";
/// Atomically claims one durable replay identity.
///
/// Paired with `NATIVE_WORKER_REPLAY_BEGIN_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_replay_route.rs:91`.
pub const NATIVE_WORKER_REPLAY_BEGIN_OPERATION: &str = "native_worker.replay_begin";
/// Appends one opaque event to the current stream.
///
/// Paired with `NATIVE_WORKER_REPLAY_APPEND_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_replay_route.rs:93`.
pub const NATIVE_WORKER_REPLAY_APPEND_OPERATION: &str = "native_worker.replay_append";
/// Reads one bounded history page past a cursor.
///
/// Paired with `NATIVE_WORKER_REPLAY_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_replay_route.rs:95`.
pub const NATIVE_WORKER_REPLAY_OPERATION: &str = "native_worker.replay";
/// Acknowledges one durable event, advancing only its phase cursor.
///
/// Paired with `NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION` in
/// `bins/eliot-kernel/src/native_worker_replay_route.rs:97`.
pub const NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION: &str = "native_worker.replay_acknowledge";

/// Authenticated Kernel front-door adapter for the worker lifecycle.
///
/// Each span constructs its request from the Wave-A core types, parses the
/// Kernel reply against the submitted identities, and fails closed: without
/// an exact current registration, a claimed unit, and a Ready receipt, every
/// lifecycle span returns a typed `KernelAdmissionRequired` error, never
/// success. Kernel replies carry no authority the client may mint; the client
/// only retains echoed identities it already proved.
pub struct KernelNativeWorkerClient {
    client: KernelClient,
    registration: Option<NativeWorkerRegistration>,
    claim: Option<NativeWorkerClaim>,
    ready: Option<NativeReadyReport>,
}

impl KernelNativeWorkerClient {
    /// Connects and probes Kernel health without claiming any authority.
    ///
    /// A non-OPEN handshake fails closed. Success only proves transport
    /// liveness; it grants no registration, claim, readiness, or admission.
    pub fn connect() -> Result<Self, NativeWorkerError> {
        let mut client = KernelClient::load().map_err(|error| kernel_admission_error(&error))?;
        let health = client
            .probe()
            .map_err(|error| kernel_admission_error(&error))?;
        if health.get("status").and_then(serde_json::Value::as_str) != Some("OPEN") {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "Kernel health handshake was not OPEN".to_owned(),
            ));
        }
        Ok(Self {
            client,
            registration: None,
            claim: None,
            ready: None,
        })
    }

    /// Submits one typed registration (or renewal) and retains its echo.
    pub fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        registration.validate()?;
        let payload = serde_json::to_value(registration)?;
        let reply = self.transact(NATIVE_WORKER_REGISTRATION_OPERATION, payload)?;
        require_echo(
            &reply,
            "registration_id",
            registration.registration_id.as_str(),
        )?;
        require_generation_echo(&reply, registration.worker_generation)?;
        self.registration = Some(registration.clone());
        self.claim = None;
        self.ready = None;
        Ok(reply)
    }

    /// Submits one exact claim presentation bound to the retained registration.
    pub fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        admission.validate_binding()?;
        let registration = self.registration.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact current native-worker registration".to_owned(),
            )
        })?;
        require_registration_binding(registration, admission.claim())?;
        let payload = serde_json::to_value(admission)?;
        let reply = self.transact(NATIVE_WORKER_CLAIM_OPERATION, payload)?;
        require_echo(&reply, "claim_id", admission.claim().claim_id.as_str())?;
        require_echo(
            &reply,
            "binding_digest",
            admission.claim().binding_digest.as_str(),
        )?;
        require_decision_admitted(&reply)?;
        self.claim = Some(admission.claim().clone());
        self.ready = None;
        Ok(reply)
    }

    /// Submits one typed ready-or-blocked verdict for the claimed unit.
    pub fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let now = unix_ms()?;
        submission.validate_binding(now)?;
        self.require_claimed_unit(submission.claim())?;
        let payload = serde_json::to_value(submission)?;
        let reply = self.transact(NATIVE_WORKER_READY_OPERATION, payload)?;
        match submission.readiness() {
            NativeWorkerReadiness::Ready(report) => {
                require_echo(&reply, "kind", "native_worker_ready")?;
                require_echo(&reply, "ready_id", report.ready_id.as_str())?;
                require_echo(&reply, "claim_id", report.claim_id.as_str())?;
                require_decision_admitted(&reply)?;
                self.ready = Some(report.clone());
            }
            NativeWorkerReadiness::Blocked(report) => {
                require_echo(&reply, "kind", "native_worker_blocked")?;
                require_echo(&reply, "ready_id", report.ready_id.as_str())?;
                require_echo(&reply, "claim_id", report.claim_id.as_str())?;
                self.ready = None;
            }
        }
        Ok(reply)
    }

    /// Submits one heartbeat under the exact Ready binding.
    ///
    /// The reply must be a liveness receipt echoing the heartbeat identity;
    /// anything else fails closed and is never treated as readiness.
    pub fn submit_heartbeat(
        &mut self,
        envelope: &NativeHeartbeatEnvelope,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let ready = self.require_ready_unit()?;
        envelope.validate()?;
        require_lifecycle_binding(&ready, &envelope.binding)?;
        let payload = serde_json::to_value(envelope)?;
        let reply = self.transact(NATIVE_WORKER_HEARTBEAT_OPERATION, payload)?;
        require_echo(&reply, "kind", "native_worker_liveness")?;
        require_echo(&reply, "heartbeat_id", envelope.heartbeat_id.as_str())?;
        require_echo(&reply, "claim_id", envelope.binding.claim_id.as_str())?;
        Ok(reply)
    }

    /// Submits one checkpoint reference under the exact Ready binding.
    pub fn submit_checkpoint(
        &mut self,
        envelope: &NativeCheckpointEnvelope,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let ready = self.require_ready_unit()?;
        envelope.validate()?;
        require_lifecycle_binding(&ready, &envelope.binding)?;
        let payload = serde_json::to_value(envelope)?;
        let reply = self.transact(NATIVE_WORKER_CHECKPOINT_OPERATION, payload)?;
        require_echo(&reply, "kind", "native_worker_checkpoint")?;
        require_echo(&reply, "checkpoint_id", envelope.checkpoint_id.as_str())?;
        require_echo(&reply, "claim_id", envelope.binding.claim_id.as_str())?;
        Ok(reply)
    }

    /// Submits one result digest under the exact Ready binding.
    ///
    /// Submission is not acceptance: Kernel reconciles the digest under the
    /// original claim before any reclaim or retry. The admitted claim travels
    /// with the envelope so Kernel can prove the submitted schema is the
    /// admitted schema from the binding digest.
    pub fn submit_result(
        &mut self,
        claim: &NativeWorkerClaim,
        envelope: &NativeResultEnvelope,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let ready = self.require_ready_unit()?;
        envelope.validate()?;
        require_lifecycle_binding(&ready, &envelope.binding)?;
        claim.validate()?;
        if claim.claim_id.as_str() != envelope.binding.claim_id.as_str()
            || claim.claim_id.as_str() != ready.claim_id.as_str()
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "result claim does not match the Ready-bound claimed unit".to_owned(),
            ));
        }
        let mut payload = serde_json::to_value(envelope)?;
        payload["claim"] = serde_json::to_value(claim)?;
        let reply = self.transact(NATIVE_WORKER_RESULT_SUBMIT_OPERATION, payload)?;
        require_echo(&reply, "kind", "native_worker_result")?;
        require_echo(&reply, "result_id", envelope.result_id.as_str())?;
        require_echo(&reply, "claim_id", envelope.binding.claim_id.as_str())?;
        require_echo(&reply, "result_digest", envelope.result_digest.as_str())?;
        Ok(reply)
    }

    /// Observes cancellation for one exact attempt under the Ready binding.
    ///
    /// Stops new provider effects for the attempt; possible work/result state
    /// stays under the original claim for reconciliation.
    pub fn submit_cancellation_observe(
        &mut self,
        envelope: &NativeCancellationEnvelope,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let ready = self.require_ready_unit()?;
        envelope.validate()?;
        require_lifecycle_binding(&ready, &envelope.binding)?;
        let payload = serde_json::to_value(envelope)?;
        let reply = self.transact(NATIVE_WORKER_CANCEL_OBSERVE_OPERATION, payload)?;
        require_process_cancelled(&reply, envelope.binding.operation_id.as_str())?;
        Ok(reply)
    }

    /// Reconciles one exact claim after a lost acknowledgement.
    ///
    /// Typed consumer of `native_worker.reconcile` reusing the actual route
    /// contract (`bins/eliot-kernel/src/native_worker_reconcile_route.rs`):
    /// `reconcile_id` plus the exact `claim` presentation plus the optional
    /// retained `receipt` in, one `native_worker_reconciled` receipt out.
    /// The reply must echo the submitted `reconcile_id`, `claim_id`, and
    /// `binding_digest`; anything else fails closed and never invents a
    /// second process. Requires the retained registration and claimed unit,
    /// like the readiness span. T9-05 coordinator verification is not
    /// consumed by this contour.
    pub fn submit_reconcile(
        &mut self,
        submission: &ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        submission.validate()?;
        self.require_claimed_unit(submission.claim())?;
        let claim = submission.claim();
        let claim_json = serde_json::to_value(claim)?;
        let authority_epoch = claim_json
            .get("authority_epoch")
            .and_then(|epoch| {
                epoch
                    .get("sequence")
                    .and_then(serde_json::Value::as_u64)
                    .or_else(|| epoch.as_u64())
            })
            .ok_or_else(|| {
                NativeWorkerError::KernelAdmissionRequired(
                    "claim authority epoch is missing".to_owned(),
                )
            })?;
        let claim_projection = serde_json::json!({
            "claim_id": claim.claim_id.as_str(),
            "binding_digest": claim.binding_digest.as_str(),
            "worker_generation": claim.worker_generation,
            "authority_epoch": authority_epoch,
            "state_fence": claim_json.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
            "registration_id": claim.registration_id.as_str(),
        });
        if claim_projection
            .get("state_fence")
            .is_none_or(serde_json::Value::is_null)
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "claim state fence is missing".to_owned(),
            ));
        }
        let _ = claim_projection;
        let mut payload = serde_json::json!({
            "reconcile_id": submission.reconcile_id(),
            "claim": {
                "claim_id": claim.claim_id.as_str(),
                "binding_digest": claim.binding_digest.as_str(),
                "worker_generation": claim.worker_generation,
                "authority_epoch": authority_epoch,
                "state_fence": claim_json.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
                "registration_id": claim.registration_id.as_str(),
            },
        });
        if let Some(receipt) = submission.receipt() {
            payload["receipt"] = serde_json::to_value(receipt)?;
        }
        let reply = self.transact(NATIVE_WORKER_RECONCILE_OPERATION, payload)?;
        require_echo(&reply, "kind", "native_worker_reconciled")?;
        require_echo(&reply, "reconcile_id", submission.reconcile_id())?;
        require_echo(&reply, "claim_id", claim.claim_id.as_str())?;
        require_echo(&reply, "binding_digest", claim.binding_digest.as_str())?;
        Ok(reply)
    }

    /// Sends one typed payload; transport failures stay transport failures.
    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.client
            .transact_json(operation, payload)
            .map_err(|error| kernel_admission_error(&error))
    }

    /// Requires the retained registration and claimed unit for a claim.
    fn require_claimed_unit(&self, claim: &NativeWorkerClaim) -> Result<(), NativeWorkerError> {
        let registration = self.registration.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact current native-worker registration".to_owned(),
            )
        })?;
        require_registration_binding(registration, claim)?;
        let retained = self.claim.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact claimed native-worker execution unit".to_owned(),
            )
        })?;
        if retained.claim_id != claim.claim_id || retained.binding_digest != claim.binding_digest {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "presented claim is not the exact claimed execution unit".to_owned(),
            ));
        }
        Ok(())
    }

    /// Requires registration, claimed unit, and a Ready receipt.
    fn require_ready_unit(&self) -> Result<NativeReadyReport, NativeWorkerError> {
        let ready = self.ready.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact current Ready receipt for the claimed unit".to_owned(),
            )
        })?;
        let claim = self.claim.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact claimed native-worker execution unit".to_owned(),
            )
        })?;
        let registration = self.registration.as_ref().ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "no exact current native-worker registration".to_owned(),
            )
        })?;
        if ready.claim_id != claim.claim_id
            || ready.registration_id != registration.registration_id
            || ready.registration_id != claim.registration_id
            || ready.worker_generation != claim.worker_generation
            || ready.worker_generation != registration.worker_generation
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "Ready receipt does not bind the exact current registration and claim".to_owned(),
            ));
        }
        Ok(ready.clone())
    }
}

/// Retained receipt the worker still holds for a lost-acknowledgement
/// reconcile, mirroring the route's optional `receipt` object
/// (`bins/eliot-kernel/src/native_worker_reconcile_route.rs:426-608`).
///
/// Only `claim_id` and `receipt_digest` are required; every other echoed
/// field is optional and, when present, must agree with the durable record
/// (stale generation/epoch/fence fences, changed registration/binding/
/// attempt/operation conflicts before any effect).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRetainedReceipt {
    /// Claim identity the retained receipt belongs to.
    pub claim_id: String,
    /// Durable admission receipt digest the worker retained.
    pub receipt_digest: String,
    /// Optional echoed generation, checked for staleness when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_generation: Option<u64>,
    /// Optional echoed authority sequence, checked for staleness when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_epoch: Option<u64>,
    /// Optional echoed fence, checked for staleness when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_fence: Option<serde_json::Value>,
    /// Optional echoed registration, conflicting when changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    /// Optional echoed binding digest, conflicting when changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_digest: Option<String>,
    /// Optional echoed attempt, conflicting when changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// Optional echoed operation, conflicting when changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}

impl ReconcileRetainedReceipt {
    /// Validates the closed retained-receipt shape without granting authority.
    pub fn validate(&self) -> Result<(), NativeWorkerError> {
        if self.claim_id.trim().is_empty()
            || self.claim_id.chars().any(char::is_control)
            || self.claim_id.len() > 256
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "reconcile receipt claim identity is invalid".to_owned(),
            ));
        }
        if self.receipt_digest.len() != 64
            || !self
                .receipt_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "reconcile receipt digest is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed reconcile submission for `native_worker.reconcile`.
///
/// Reuses the actual accepted route contract, never arbitrary JSON as a
/// claim: the enclosed `NativeWorkerClaim` is validated through the
/// production claim shape before the transport runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileSubmission {
    reconcile_id: String,
    claim: NativeWorkerClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<ReconcileRetainedReceipt>,
}

impl ReconcileSubmission {
    /// Builds one reconcile submission for the exact claimed unit.
    pub fn new(
        reconcile_id: String,
        claim: NativeWorkerClaim,
        receipt: Option<ReconcileRetainedReceipt>,
    ) -> Self {
        Self {
            reconcile_id,
            claim,
            receipt,
        }
    }

    /// Returns the distinct reconcile identity bound to the frame idempotency key.
    #[must_use]
    pub fn reconcile_id(&self) -> &str {
        &self.reconcile_id
    }

    /// Returns the exact claim presentation this reconcile checks.
    #[must_use]
    pub const fn claim(&self) -> &NativeWorkerClaim {
        &self.claim
    }

    /// Returns the optional retained receipt the worker still holds.
    #[must_use]
    pub const fn receipt(&self) -> Option<&ReconcileRetainedReceipt> {
        self.receipt.as_ref()
    }

    /// Validates the closed reconcile shape without granting authority.
    pub fn validate(&self) -> Result<(), NativeWorkerError> {
        if self.reconcile_id.trim().is_empty()
            || self.reconcile_id.chars().any(char::is_control)
            || self.reconcile_id.len() > 256
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "reconcile identity is invalid".to_owned(),
            ));
        }
        self.claim.validate().map_err(NativeWorkerError::from)?;
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
            if receipt.claim_id != self.claim.claim_id.as_str() {
                return Err(NativeWorkerError::KernelAdmissionRequired(
                    "reconcile receipt does not bind the presented claim".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Thin Kernel replay transport behind one exact claim.
///
/// Implemented by [`KernelNativeWorkerClient`] in production (through the
/// authenticated [`KernelClient::transact_json`]) and by clearly-marked test
/// doubles where a live Kernel is unavailable. Transport failures stay
/// transport failures; they are never mapped to readiness or success.
pub trait KernelReplayTransport: Send {
    /// Sends one exact replay payload; the operation string is a contract
    /// selector, not a local command authority.
    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerError>;
}

impl KernelReplayTransport for KernelNativeWorkerClient {
    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.transact(operation, payload)
    }
}

/// `DurableReplayPort` over the accepted T9-03 transport (thin, no journal).
///
/// Carries the exact claim/registration halves plus the replay stream binding
/// on every operation so Kernel re-runs the T9-02 gate before touching
/// durable state. There is no worker-local replay journal (M3): this port
/// only transports; the durable owner stays behind Kernel. Echo checks mirror
/// the lifecycle spans: every sealed `native_worker_replay` receipt must echo
/// the submitted `operation`, `claim_id`, `stream_id`, and
/// `worker_generation`.
///
/// T9-05 coordinator verification is not consumed by this contour.
pub struct KernelReplayPort<T: KernelReplayTransport> {
    transport: T,
    claim: NativeWorkerClaim,
    registration: NativeWorkerRegistration,
}

impl<T: KernelReplayTransport> KernelReplayPort<T> {
    /// Binds one exact claim presentation to the replay transport.
    ///
    /// Validates the claim/registration cross-binding locally before any
    /// transport runs; a mismatched presentation fails closed without
    /// touching Kernel. The executable digest is read from the validated
    /// v2 join; wire v1 has no join and cannot ride this transport.
    pub fn new(
        transport: T,
        claim: NativeWorkerClaim,
        registration: NativeWorkerRegistration,
    ) -> Result<Self, NativeWorkerError> {
        claim.validate().map_err(NativeWorkerError::from)?;
        registration.validate().map_err(NativeWorkerError::from)?;
        if claim.registration_id != registration.registration_id
            || claim.worker_generation != registration.worker_generation
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "replay claim is not bound to the exact registration".to_owned(),
            ));
        }
        let claim_json = serde_json::to_value(&claim)?;
        let registration_json = serde_json::to_value(&registration)?;
        let claim_epoch = claim_json
            .get("authority_epoch")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let registration_epoch = registration_json
            .get("authority_epoch")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if claim_epoch != registration_epoch {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "replay claim epoch does not match the registration".to_owned(),
            ));
        }
        if claim_json
            .get("state_fence")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
            != registration_json
                .get("state_fence")
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "replay claim fence does not match the registration".to_owned(),
            ));
        }
        executable_digest(&claim)?;
        Ok(Self {
            transport,
            claim,
            registration,
        })
    }

    /// Returns the exact stream identity for the bound claim generation.
    fn stream_id(&self) -> String {
        format!(
            "{}/gen-{}",
            self.claim.claim_id.as_str(),
            self.claim.worker_generation
        )
    }

    /// Builds the replay stream binding for the bound claim.
    fn binding(&self) -> Result<serde_json::Value, NativeWorkerError> {
        let claim_json = serde_json::to_value(&self.claim)?;
        Ok(serde_json::json!({
            "claim_id": self.claim.claim_id.as_str(),
            "worker_generation": self.claim.worker_generation,
            "stream_id": self.stream_id(),
            "authority_epoch": claim_json.get("authority_epoch").cloned().unwrap_or(serde_json::Value::Null),
            "state_fence": claim_json.get("state_fence").cloned().unwrap_or(serde_json::Value::Null),
            "executable_binding_digest": executable_digest(&self.claim)?,
        }))
    }

    /// Builds the claim/registration presentation Kernel re-gates on.
    fn presentation(&self) -> Result<serde_json::Value, NativeWorkerError> {
        Ok(serde_json::json!({
            "claim": serde_json::to_value(&self.claim)?,
            "registration": serde_json::to_value(&self.registration)?,
            "binding": self.binding()?,
        }))
    }

    fn transact_replay(
        &mut self,
        operation: &str,
        mut payload: serde_json::Value,
    ) -> Result<serde_json::Value, ProviderFailure> {
        let presentation = self.presentation().map_err(provider_error)?;
        for (key, value) in presentation.as_object().cloned().unwrap_or_default() {
            payload[key] = value;
        }
        let reply = self
            .transport
            .transact(operation, payload)
            .map_err(|error| ProviderFailure::new("kernel-replay", error.to_string()))?;
        require_replay_echo(&reply, operation, &self.claim, &self.stream_id())
            .map_err(provider_error)?;
        Ok(reply)
    }
}

fn provider_error(error: NativeWorkerError) -> ProviderFailure {
    ProviderFailure::new("kernel-replay", error.to_string())
}

fn executable_digest(claim: &NativeWorkerClaim) -> Result<String, NativeWorkerError> {
    let claim_json = serde_json::to_value(claim)?;
    claim_json
        .get("executable_binding")
        .and_then(|join| join.get("executable_binding_digest"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| {
            NativeWorkerError::KernelAdmissionRequired(
                "replay claim carries no owner-produced executable digest".to_owned(),
            )
        })
}

fn require_replay_echo(
    reply: &serde_json::Value,
    operation: &str,
    claim: &NativeWorkerClaim,
    stream_id: &str,
) -> Result<(), NativeWorkerError> {
    require_echo(reply, "kind", "native_worker_replay")?;
    require_echo(reply, "operation", operation)?;
    require_echo(reply, "claim_id", claim.claim_id.as_str())?;
    require_echo(reply, "stream_id", stream_id)?;
    let generation = reply
        .get("worker_generation")
        .and_then(serde_json::Value::as_u64);
    if generation != Some(claim.worker_generation) {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel replay receipt did not echo the submitting worker generation".to_owned(),
        ));
    }
    if reply
        .get("reply")
        .filter(|reply| reply.is_object())
        .is_none()
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel replay receipt carries no typed reply".to_owned(),
        ));
    }
    Ok(())
}

impl<T: KernelReplayTransport> DurableReplayPort for KernelReplayPort<T> {
    fn lookup_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        require_bound_stream(&self.claim, &self.stream_id(), stream_id)?;
        let payload = serde_json::json!({
            "request_id": request_id,
            "fingerprint": fingerprint,
        });
        let reply = self.transact_replay(NATIVE_WORKER_REPLAY_LOOKUP_OPERATION, payload)?;
        parse_decision(&reply)
    }

    fn begin_request(
        &mut self,
        stream_id: &str,
        request_id: &str,
        fingerprint: &str,
    ) -> Result<DurableRequestDecision, ProviderFailure> {
        require_bound_stream(&self.claim, &self.stream_id(), stream_id)?;
        let payload = serde_json::json!({
            "request_id": request_id,
            "fingerprint": fingerprint,
        });
        let reply = self.transact_replay(NATIVE_WORKER_REPLAY_BEGIN_OPERATION, payload)?;
        parse_decision(&reply)
    }

    fn append(&mut self, draft: WorkerEventDraft) -> Result<WorkerEventEnvelope, ProviderFailure> {
        let draft_json = serde_json::to_value(&draft)
            .map_err(|error| ProviderFailure::new("kernel-replay", error.to_string()))?;
        let draft_stream = draft_json
            .get("stream_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        require_bound_stream(&self.claim, &self.stream_id(), draft_stream)?;
        let payload = serde_json::json!({ "draft": draft_json });
        let reply = self.transact_replay(NATIVE_WORKER_REPLAY_APPEND_OPERATION, payload)?;
        parse_envelope(&reply, &self.claim)
    }

    fn replay(
        &mut self,
        stream_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure> {
        require_bound_stream(&self.claim, &self.stream_id(), stream_id)?;
        let payload = serde_json::json!({
            "after_sequence": after_sequence,
            "limit": 256,
        });
        let reply = self.transact_replay(NATIVE_WORKER_REPLAY_OPERATION, payload)?;
        parse_page(&reply, &self.claim)
    }

    fn acknowledge(&mut self, receipt: &EventAckReceipt) -> Result<(), ProviderFailure> {
        require_bound_stream(&self.claim, &self.stream_id(), &receipt.stream_id)?;
        let payload = serde_json::json!({
            "receipt": serde_json::to_value(receipt).map_err(|error| ProviderFailure::new("kernel-replay", error.to_string()))?,
        });
        let reply = self.transact_replay(NATIVE_WORKER_REPLAY_ACKNOWLEDGE_OPERATION, payload)?;
        parse_ack(&reply)?;
        Ok(())
    }
}

fn require_bound_stream(
    claim: &NativeWorkerClaim,
    expected: &str,
    presented: &str,
) -> Result<(), ProviderFailure> {
    if presented != expected {
        return Err(ProviderFailure::new(
            "kernel-replay",
            format!(
                "replay stream {} is not the bound claim stream for {}",
                presented,
                claim.claim_id.as_str()
            ),
        ));
    }
    Ok(())
}

fn inner_reply(reply: &serde_json::Value) -> Result<&serde_json::Value, ProviderFailure> {
    reply
        .get("reply")
        .filter(|reply| reply.is_object())
        .ok_or_else(|| {
            ProviderFailure::new("kernel-replay", "replay receipt carries no typed reply")
        })
}

fn parse_decision(reply: &serde_json::Value) -> Result<DurableRequestDecision, ProviderFailure> {
    let inner = inner_reply(reply)?;
    let decision = inner.get("decision").unwrap_or(inner);
    if let Ok(typed) = serde_json::from_value::<DurableRequestDecision>(decision.clone()) {
        return Ok(typed);
    }
    let kind = decision
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match kind {
        "NEW" => Ok(DurableRequestDecision::New),
        "CONFLICT" => Ok(DurableRequestDecision::Conflict),
        _ => Err(ProviderFailure::new(
            "kernel-replay",
            "replay decision is not a typed durable decision",
        )),
    }
}

fn parse_envelope(
    reply: &serde_json::Value,
    claim: &NativeWorkerClaim,
) -> Result<WorkerEventEnvelope, ProviderFailure> {
    let inner = inner_reply(reply)?;
    let envelope_json = inner.get("envelope").unwrap_or(inner);
    if let Ok(typed) = serde_json::from_value::<WorkerEventEnvelope>(envelope_json.clone()) {
        if typed.stream_id
            != format!(
                "{}/gen-{}",
                claim.claim_id.as_str(),
                claim.worker_generation
            )
        {
            return Err(ProviderFailure::new(
                "kernel-replay",
                "replay envelope does not bind the claimed stream",
            ));
        }
        return Ok(typed);
    }
    Err(ProviderFailure::new(
        "kernel-replay",
        "replay envelope is not a typed durable envelope",
    ))
}

fn parse_page(
    reply: &serde_json::Value,
    claim: &NativeWorkerClaim,
) -> Result<Vec<WorkerEventEnvelope>, ProviderFailure> {
    let inner = inner_reply(reply)?;
    let events = inner
        .get("page")
        .and_then(|page| page.get("events"))
        .or_else(|| inner.get("events"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        let envelope: WorkerEventEnvelope = serde_json::from_value(event)
            .map_err(|error| ProviderFailure::new("kernel-replay", error.to_string()))?;
        if envelope.stream_id
            != format!(
                "{}/gen-{}",
                claim.claim_id.as_str(),
                claim.worker_generation
            )
        {
            return Err(ProviderFailure::new(
                "kernel-replay",
                "replay page event does not bind the claimed stream",
            ));
        }
        out.push(envelope);
    }
    Ok(out)
}

fn parse_ack(reply: &serde_json::Value) -> Result<(), ProviderFailure> {
    let _ = inner_reply(reply)?;
    Ok(())
}

/// Requires the claim to be presented under the exact retained registration.
fn require_registration_binding(
    registration: &NativeWorkerRegistration,
    claim: &NativeWorkerClaim,
) -> Result<(), NativeWorkerError> {
    if claim.registration_id != registration.registration_id
        || claim.worker_generation != registration.worker_generation
        || claim.authority_epoch != registration.authority_epoch
        || claim.state_fence != registration.state_fence
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "claim is not bound to the exact current registration".to_owned(),
        ));
    }
    Ok(())
}

/// Requires a lifecycle envelope binding to match the Ready claim exactly.
fn require_lifecycle_binding(
    ready: &NativeReadyReport,
    binding: &NativeLifecycleBinding,
) -> Result<(), NativeWorkerError> {
    binding.validate().map_err(NativeWorkerError::from)?;
    if binding.claim_id.as_str() != ready.claim_id.as_str()
        || binding.worker_generation != ready.worker_generation
        || binding.authority_epoch != ready.authority_epoch
        || binding.state_fence != ready.state_fence
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "lifecycle binding does not match the exact Ready claim".to_owned(),
        ));
    }
    Ok(())
}

/// Requires one echoed reply field to equal the submitted identity.
fn require_echo(
    reply: &serde_json::Value,
    field: &str,
    expected: &str,
) -> Result<(), NativeWorkerError> {
    if reply.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel reply did not echo the submitted lifecycle identity".to_owned(),
        ));
    }
    Ok(())
}

/// Requires the Kernel decision envelope to be an admission.
///
/// A `REJECTED` or `CONFLICT` verdict is a typed refusal, never a transport
/// failure and never admission: it fails closed carrying the Kernel's
/// reason instead of a claimed unit.
fn require_decision_admitted(reply: &serde_json::Value) -> Result<(), NativeWorkerError> {
    let decision = reply.get("decision").filter(|value| value.is_object());
    let kind = decision
        .and_then(|value| value.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if kind == "ADMITTED" {
        return Ok(());
    }
    let detail: String = decision
        .and_then(|value| serde_json::to_string(value).ok())
        .unwrap_or_default()
        .chars()
        .take(256)
        .collect();
    Err(NativeWorkerError::KernelAdmissionRequired(
        if detail.is_empty() {
            format!("Kernel refused the presentation (verdict {kind})")
        } else {
            format!("Kernel refused the presentation (verdict {kind}): {detail}")
        },
    ))
}

/// Requires the Kernel reply to be the execution owner's typed cancellation
/// verdict for the exact observed attempt operation.
///
/// The observation returns the #100 execution owner's `Cancelled` verdict
/// (which performed the bounded descendant cleanup), not a route-authored
/// receipt, so only the exact cancelled operation counts as fenced.
fn require_process_cancelled(
    reply: &serde_json::Value,
    operation_id: &str,
) -> Result<(), NativeWorkerError> {
    if reply.get("result").and_then(serde_json::Value::as_str) != Some("Cancelled") {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel did not return the execution owner's cancellation verdict".to_owned(),
        ));
    }
    let echoed = reply
        .get("payload")
        .and_then(|payload| payload.get("binding"))
        .and_then(|binding| binding.get("operation_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if echoed != operation_id {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel cancellation verdict did not bind the observed attempt operation".to_owned(),
        ));
    }
    Ok(())
}

/// Requires the reply generation echo to match the submitting generation.
fn require_generation_echo(
    reply: &serde_json::Value,
    expected: u64,
) -> Result<(), NativeWorkerError> {
    if reply
        .get("worker_generation")
        .and_then(serde_json::Value::as_u64)
        != Some(expected)
    {
        return Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel reply did not echo the submitting worker generation".to_owned(),
        ));
    }
    Ok(())
}

/// Current Unix time in milliseconds for readiness deadline checks.
fn unix_ms() -> Result<u64, NativeWorkerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired("worker clock is unavailable".to_owned())
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired("worker clock is out of range".to_owned())
        })
}

pub(super) fn kernel_admission_error(error: &KernelClientError) -> NativeWorkerError {
    NativeWorkerError::KernelAdmissionRequired(error.to_string())
}

/// Shareable handle over one authenticated Kernel front-door session.
///
/// The admitted drive needs the same session twice at different times: as
/// the [`AdmittedLifecycle`] transport (register, claim, reconcile,
/// readiness) and as the [`KernelReplayTransport`] behind the thin replay
/// port. Both handles lock the one client, so the retained
/// registration/claim/Ready echo checks stay coherent. Lock poisoning fails
/// closed; it never mints, replays, or synthesizes a reply.
#[derive(Clone)]
pub struct SharedKernelTransport {
    /// The single connected client behind both handles.
    inner: Arc<Mutex<KernelNativeWorkerClient>>,
}

impl SharedKernelTransport {
    /// Shares one connected client between the lifecycle and replay handles.
    #[must_use]
    pub fn new(client: KernelNativeWorkerClient) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    /// Locks the client or fails closed on poison.
    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, KernelNativeWorkerClient>, NativeWorkerError> {
        self.inner.lock().map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired("Kernel transport lock poisoned".to_owned())
        })
    }
}

impl AdmittedLifecycle for SharedKernelTransport {
    fn submit_registration(
        &mut self,
        registration: &NativeWorkerRegistration,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.lock()?.submit_registration(registration)
    }

    fn submit_claim(
        &mut self,
        admission: &ClaimAdmissionRequest,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.lock()?.submit_claim(admission)
    }

    fn submit_reconcile(
        &mut self,
        submission: &crate::ReconcileSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.lock()?.submit_reconcile(submission)
    }

    fn submit_readiness(
        &mut self,
        submission: &ReadinessSubmission,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.lock()?.submit_readiness(submission)
    }
}

impl KernelReplayTransport for SharedKernelTransport {
    fn transact(
        &mut self,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        self.lock()?.transact(operation, payload)
    }
}

/// Durable checkpoint port over the authenticated Kernel transport.
///
/// Builds the checkpoint envelope from the durable request plus the retained
/// admitted claim (every binding field echoes the claim, so a rewired
/// request is refused before any transport runs), submits it through the
/// shared session — the Kernel verdict is authoritative, and a refusal fails
/// the persist — then seals the request-bound receipt facts the worker
/// re-validates against the submitted request. Used only for serve-time
/// checkpoint frames, which arrive after the Ready receipt exists, so the
/// transport's Ready binding is always satisfied here.
pub struct KernelCheckpointPort {
    /// Shared authenticated session.
    transport: SharedKernelTransport,
    /// Exact admitted claim every checkpoint is stored under.
    claim: NativeWorkerClaim,
}

impl KernelCheckpointPort {
    /// Binds one exact admitted claim to the checkpoint transport.
    pub fn new(
        transport: SharedKernelTransport,
        claim: NativeWorkerClaim,
    ) -> Result<Self, NativeWorkerError> {
        claim.validate().map_err(NativeWorkerError::from)?;
        Ok(Self { transport, claim })
    }
}

impl DurableCheckpointPort for KernelCheckpointPort {
    fn persist_checkpoint(
        &mut self,
        request: &DurableCheckpointRequest,
    ) -> Result<CheckpointProviderOutcome, ProviderFailure> {
        let now = unix_ms().map_err(provider_error)?;
        let checkpoint_id = NativeCheckpointId::new(request.request_id().to_owned())
            .or_else(|_| {
                NativeCheckpointId::new(format!(
                    "native-worker-checkpoint-{}",
                    request.checkpoint_ref()
                ))
            })
            .map_err(|error| ProviderFailure::new("kernel-checkpoint", error.to_string()))?;
        let receipt_id = checkpoint_id.as_str().to_owned();
        let envelope = NativeCheckpointEnvelope {
            checkpoint_id,
            binding: NativeLifecycleBinding {
                claim_id: self.claim.claim_id.clone(),
                attempt_id: self.claim.attempt_id.clone(),
                operation_id: self.claim.operation_id.clone(),
                worker_generation: self.claim.worker_generation,
                route_class: self.claim.route_class.clone(),
                predecessor_revision: self.claim.predecessor_revision.clone(),
                authority_epoch: self.claim.authority_epoch.clone(),
                state_fence: self.claim.state_fence.clone(),
            },
            checkpoint_ref: request.checkpoint_ref().to_owned(),
            observed_at_unix_ms: now,
        };
        envelope
            .validate()
            .map_err(|error| ProviderFailure::new("kernel-checkpoint", error.to_string()))?;
        self.transport
            .lock()
            .map_err(provider_error)?
            .submit_checkpoint(&envelope)
            .map_err(|error| ProviderFailure::new("kernel-checkpoint", error.to_string()))?;
        Ok(CheckpointProviderOutcome::Stored(Box::new(
            CheckpointReceiptFacts::new(
                receipt_id,
                request.checkpoint_ref(),
                request.request_id(),
                request.stream_id(),
                request.producer_generation(),
                request.authority_epoch().clone(),
                request.state_fence().clone(),
                request.admission_revision(),
                request.operation_id().clone(),
                request.process_request_digest(),
                now,
            ),
        )))
    }
}
