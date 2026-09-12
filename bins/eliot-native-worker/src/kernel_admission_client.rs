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

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_native_worker_core::{
    ClaimAdmissionRequest, NativeCancellationEnvelope, NativeCheckpointEnvelope,
    NativeHeartbeatEnvelope, NativeLifecycleBinding, NativeReadyReport, NativeResultEnvelope,
    NativeWorkerClaim, NativeWorkerReadiness, NativeWorkerRegistration, ReadinessSubmission,
};

use super::NativeWorkerError;

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
                require_echo(&reply, "ready_id", report.ready_id.as_str())?;
                require_echo(&reply, "claim_id", report.claim_id.as_str())?;
                self.ready = Some(report.clone());
            }
            NativeWorkerReadiness::Blocked(report) => {
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
    /// original claim before any reclaim or retry.
    pub fn submit_result(
        &mut self,
        envelope: &NativeResultEnvelope,
    ) -> Result<serde_json::Value, NativeWorkerError> {
        let ready = self.require_ready_unit()?;
        envelope.validate()?;
        require_lifecycle_binding(&ready, &envelope.binding)?;
        let payload = serde_json::to_value(envelope)?;
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
        require_echo(&reply, "kind", "native_worker_cancelled")?;
        require_echo(&reply, "cancellation_id", envelope.cancellation_id.as_str())?;
        require_echo(&reply, "claim_id", envelope.binding.claim_id.as_str())?;
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
