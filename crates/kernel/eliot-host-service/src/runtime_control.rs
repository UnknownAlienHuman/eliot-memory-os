#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    dead_code,
    missing_docs,
    reason = "provider-neutral runtime-control wire seam keeps explicit validation and frame plumbing"
)]

use crate::reactive_context_delivery::ReactiveContextDeliveryRequest;
use eliot_contracts::{
    ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_kernel_service::{
    UserAutomationHostExecutionOperation, UserAutomationHostExecutionRequest,
    UserAutomationHostExecutionResponse,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
    RequestIdentity,
};
use eliot_receipts::RequestBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Stable wire identifier for Host runtime-control requests and responses.
pub const HOST_RUNTIME_CONTROL_WIRE: &str = "eliot.host.runtime-control.v2";
/// Stable trace discriminator for the authenticated Host runtime-control contour.
pub const HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR: &str =
    "eliot-host::production-runtime-control:v1";
/// Trace-context key carrying the Host runtime-control discriminator.
pub const HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY: &str =
    "eliot.host.production-discriminator";
const WIRE: &str = HOST_RUNTIME_CONTROL_WIRE;
const UNKNOWN_REF_TAG: &str = "unknown";
const UNKNOWN_REF_REASONS: &[&str] = &[
    "kernel-restart-validation",
    "kernel-restart-queue-lock",
    "kernel-restart-queue-full",
    "kernel-restart-queue-response",
    "kernel-restart",
    "kernel-restart-reconcile",
    "kernel-restart-reconcile-conflict",
    "kernel-restart-pending",
    "kernel-restart-reconcile-snapshot",
    "kernel-restart-reconcile-unknown",
    "store-recovery-validation",
    "store-recovery-queue-lock",
    "store-recovery-queue-full",
    "store-recovery-queue-response",
    "store-recovery",
    "store-recovery-pending",
    "store-recovery-reconcile",
    "store-recovery-reconcile-conflict",
    "store-recovery-reconcile-snapshot",
    "store-recovery-reconcile-unknown",
    "store-recovery-crash-fence-manual-new-lineage",
    "reactive-context-validation",
    "reactive-context-queue-lock",
    "reactive-context-queue-full",
    "reactive-context-queue-response",
    "reactive-context",
    "user-automation-admit-validation",
    "user-automation-admit-queue-lock",
    "user-automation-admit-queue-full",
    "user-automation-admit-queue-response",
    "user-automation-admit",
    "user-automation-cancel-wakes-validation",
    "user-automation-cancel-wakes-queue-lock",
    "user-automation-cancel-wakes-queue-full",
    "user-automation-cancel-wakes-queue-response",
    "user-automation-cancel-wakes",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostRuntimeControlOperation {
    RestartKernel,
    ReconcileKernelRestart,
    RecoverStore,
    ReconcileStoreRecovery,
    DeliverReactiveContext,
    AdmitUserAutomationOccurrence,
    CancelUserAutomationPendingWakes,
}

fn canonical_operation_name(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel => "RestartKernel",
        HostRuntimeControlOperation::ReconcileKernelRestart => "ReconcileKernelRestart",
        HostRuntimeControlOperation::RecoverStore => "RecoverStore",
        HostRuntimeControlOperation::ReconcileStoreRecovery => "ReconcileStoreRecovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "DeliverReactiveContext",
        HostRuntimeControlOperation::AdmitUserAutomationOccurrence => {
            "AdmitUserAutomationOccurrence"
        }
        HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
            "CancelUserAutomationPendingWakes"
        }
    }
}

fn operation_unknown_prefix(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel
        | HostRuntimeControlOperation::ReconcileKernelRestart => "kernel-restart",
        HostRuntimeControlOperation::RecoverStore
        | HostRuntimeControlOperation::ReconcileStoreRecovery => "store-recovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "reactive-context",
        HostRuntimeControlOperation::AdmitUserAutomationOccurrence => "user-automation-admit",
        HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
            "user-automation-cancel-wakes"
        }
    }
}

pub fn operation_unknown_ref(
    operation: &HostRuntimeControlOperation,
    suffix: &str,
    request: &HostRuntimeControlRequest,
) -> PlatformHandle {
    runtime_control_unknown_ref(
        &format!("{}-{suffix}", operation_unknown_prefix(operation)),
        request,
    )
}

fn is_sha256_digest(value: &PlatformHandle) -> bool {
    value.as_str().len() == 64
        && value
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_store_process_identity(value: &PlatformHandle) -> bool {
    let Some(identity) = value.as_str().strip_prefix("pid:") else {
        return false;
    };
    let Some((pid, start)) = identity.split_once(":start:") else {
        return false;
    };
    !pid.is_empty()
        && !start.is_empty()
        && pid.parse::<u32>().is_ok_and(|value| value != 0)
        && start.parse::<u64>().is_ok_and(|value| value != 0)
        && !start.contains(':')
}

fn mutation_digest_for_request_id(wire: &PlatformHandle, request_id: &PlatformHandle) -> String {
    sha256_hex(format!("{}:mutation:{}", wire.as_str(), request_id.as_str()).as_bytes())
}

fn request_digest_for(
    wire: &PlatformHandle,
    operation: &HostRuntimeControlOperation,
    request_id: &PlatformHandle,
    mutation_digest: &PlatformHandle,
) -> String {
    sha256_hex(
        format!(
            "{}:{}:{}:{}",
            wire.as_str(),
            canonical_operation_name(operation),
            request_id.as_str(),
            mutation_digest.as_str()
        )
        .as_bytes(),
    )
}

fn reactive_context_mutation_digest(
    source: &HostReactiveContextRuntimeRequest,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(source)
        .map_err(|_| "reactive Context source could not be encoded".to_owned())?;
    let mut material = Vec::with_capacity(WIRE.len() + encoded.len() + 20);
    material.extend_from_slice(WIRE.as_bytes());
    material.extend_from_slice(b":reactive-context:");
    material.extend_from_slice(&encoded);
    Ok(sha256_hex(&material))
}

fn user_automation_mutation_digest(
    operation: &HostRuntimeControlOperation,
    source: &HostUserAutomationRuntimeRequest,
) -> Result<String, String> {
    let encoded = serde_json::to_vec(source)
        .map_err(|_| "user automation source could not be encoded".to_owned())?;
    let operation_name = canonical_operation_name(operation);
    let mut material = Vec::with_capacity(WIRE.len() + operation_name.len() + encoded.len() + 32);
    material.extend_from_slice(WIRE.as_bytes());
    material.extend_from_slice(b":user-automation:");
    material.extend_from_slice(operation_name.as_bytes());
    material.extend_from_slice(b":");
    material.extend_from_slice(&encoded);
    Ok(sha256_hex(&material))
}

pub fn runtime_control_unknown_ref(
    prefix: &str,
    request: &HostRuntimeControlRequest,
) -> PlatformHandle {
    let payload = serde_json::to_string(&(
        canonical_operation_name(&request.operation),
        request.request_id.as_str(),
        request.mutation_digest.as_str(),
        request.request_digest.as_str(),
    ))
    .unwrap_or_else(|_| unreachable!());
    PlatformHandle::new(format!("{WIRE}:{UNKNOWN_REF_TAG}:{prefix}:{payload}"))
        .unwrap_or_else(|_| unreachable!())
}

fn parse_runtime_control_unknown_ref(
    pending_ref: &PlatformHandle,
) -> Option<HostRuntimeControlRequest> {
    let mut parts = pending_ref.as_str().splitn(4, ':');
    let wire = parts.next()?;
    let tag = parts.next()?;
    let reason = parts.next()?;
    let payload = parts.next()?;
    if wire != WIRE || tag != UNKNOWN_REF_TAG || !UNKNOWN_REF_REASONS.contains(&reason) {
        return None;
    }
    let (operation_name, request_id, mutation_digest, request_digest) =
        serde_json::from_str::<(String, String, String, String)>(payload).ok()?;
    if serde_json::to_string(&(
        operation_name.as_str(),
        request_id.as_str(),
        mutation_digest.as_str(),
        request_digest.as_str(),
    ))
    .ok()
    .as_deref()
        != Some(payload)
    {
        return None;
    }
    let operation = match operation_name.as_str() {
        "RestartKernel" => HostRuntimeControlOperation::RestartKernel,
        "ReconcileKernelRestart" => HostRuntimeControlOperation::ReconcileKernelRestart,
        "RecoverStore" => HostRuntimeControlOperation::RecoverStore,
        "ReconcileStoreRecovery" => HostRuntimeControlOperation::ReconcileStoreRecovery,
        "DeliverReactiveContext" => HostRuntimeControlOperation::DeliverReactiveContext,
        "AdmitUserAutomationOccurrence" => {
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence
        }
        "CancelUserAutomationPendingWakes" => {
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes
        }
        _ => return None,
    };
    let request = HostRuntimeControlRequest {
        wire: PlatformHandle::new(wire.to_owned()).ok()?,
        operation,
        request_id: PlatformHandle::new(request_id).ok()?,
        mutation_digest: PlatformHandle::new(mutation_digest).ok()?,
        request_digest: PlatformHandle::new(request_digest).ok()?,
        reactive_context: None,
        user_automation: None,
    };
    request.validate_identity().ok().map(|_| request)
}

/// Complete owner-produced reactive Context input accepted by the
/// authenticated Host runtime-control front door.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostReactiveContextRuntimeRequest {
    /// Complete typed payload and owner enqueue evidence.
    pub delivery: ReactiveContextDeliveryRequest,
    /// Owner admission reference for this exact request.
    pub admission_ref: PlatformHandle,
}

impl HostReactiveContextRuntimeRequest {
    /// Validate the source handoff before it enters the Host queue.
    pub fn validate(&self) -> Result<(), String> {
        if self.admission_ref.as_str().trim().is_empty() {
            return Err("reactive Context admission_ref is blank".to_owned());
        }
        self.delivery
            .payload
            .validate()
            .map_err(|error| format!("reactive Context payload is invalid: {error}"))?;
        let owner_receipt = self
            .delivery
            .owner_receipt
            .as_ref()
            .ok_or_else(|| "reactive Context owner_receipt is required".to_owned())?;
        owner_receipt
            .validate()
            .map_err(|error| format!("reactive Context owner_receipt is invalid: {error}"))
    }
}

/// Complete owner-produced UserAutomation execution carrier accepted by the
/// authenticated Host runtime-control front door.
///
/// The wrapped value is the existing typed Kernel-to-Host execution carrier;
/// this wire adds only the authenticated runtime-control envelope and digest
/// binding around it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostUserAutomationRuntimeRequest {
    /// Complete typed execution carrier and authenticated channel evidence.
    pub execution: UserAutomationHostExecutionRequest,
}

impl HostUserAutomationRuntimeRequest {
    /// Validate the carrier handoff before it enters the Host queue.
    pub fn validate(&self) -> Result<(), String> {
        self.execution
            .validate()
            .map_err(|error| format!("user automation carrier is invalid: {error}"))
    }

    /// Validate the carrier for the occurrence-admission operation.
    pub fn validate_for_admit(&self) -> Result<(), String> {
        self.validate()?;
        if !matches!(
            self.execution.operation,
            UserAutomationHostExecutionOperation::AdmitOccurrence { .. }
        ) {
            return Err("user automation admit requires an AdmitOccurrence carrier".to_owned());
        }
        Ok(())
    }

    /// Validate the carrier for the pending-wake-cancellation operation.
    pub fn validate_for_cancel(&self) -> Result<(), String> {
        self.validate()?;
        if !matches!(
            self.execution.operation,
            UserAutomationHostExecutionOperation::CancelPendingWakes { .. }
        ) {
            return Err("user automation cancel requires a CancelPendingWakes carrier".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuntimeControlRequest {
    pub wire: PlatformHandle,
    pub operation: HostRuntimeControlOperation,
    pub request_id: PlatformHandle,
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// Complete typed input for the authenticated reactive Context operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactive_context: Option<HostReactiveContextRuntimeRequest>,
    /// Complete typed UserAutomation execution carrier for the authenticated
    /// occurrence-admission and wake-cancellation operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_automation: Option<HostUserAutomationRuntimeRequest>,
}

impl HostRuntimeControlRequest {
    pub fn new(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest =
            PlatformHandle::new(mutation_digest_for_request_id(&wire, &request_id))
                .map_err(|e| e.to_string())?;
        Self::new_with_mutation_digest(operation, request_id, mutation_digest)
    }

    pub fn new_with_mutation_digest(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: None,
        };
        value.validate().map_err(|e| e.to_string())?;
        Ok(value)
    }

    /// Construct an authenticated reactive Context request whose mutation
    /// digest covers the complete typed owner handoff.
    pub fn new_reactive_context(
        request_id: PlatformHandle,
        delivery: ReactiveContextDeliveryRequest,
        admission_ref: PlatformHandle,
    ) -> Result<Self, String> {
        let reactive_context = HostReactiveContextRuntimeRequest {
            delivery,
            admission_ref,
        };
        reactive_context.validate()?;
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest =
            PlatformHandle::new(reactive_context_mutation_digest(&reactive_context)?)
                .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &HostRuntimeControlOperation::DeliverReactiveContext,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation: HostRuntimeControlOperation::DeliverReactiveContext,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: Some(reactive_context),
            user_automation: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_reconcile(
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        Self::new_with_mutation_digest(
            HostRuntimeControlOperation::ReconcileKernelRestart,
            request_id,
            mutation_digest,
        )
    }
    pub fn new_store_reconcile(
        request_id: PlatformHandle,
        mutation_digest: PlatformHandle,
    ) -> Result<Self, String> {
        Self::new_with_mutation_digest(
            HostRuntimeControlOperation::ReconcileStoreRecovery,
            request_id,
            mutation_digest,
        )
    }

    /// Construct an authenticated UserAutomation occurrence-admission request
    /// whose mutation digest covers the complete typed execution carrier.
    pub fn new_admit_user_automation_occurrence(
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        Self::new_user_automation(
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            request_id,
            execution,
        )
    }

    /// Construct an authenticated UserAutomation pending-wake-cancellation
    /// request whose mutation digest covers the complete typed carrier.
    pub fn new_cancel_user_automation_pending_wakes(
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        Self::new_user_automation(
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            request_id,
            execution,
        )
    }

    fn new_user_automation(
        operation: HostRuntimeControlOperation,
        request_id: PlatformHandle,
        execution: UserAutomationHostExecutionRequest,
    ) -> Result<Self, String> {
        let user_automation = HostUserAutomationRuntimeRequest { execution };
        match operation {
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence => {
                user_automation.validate_for_admit()?;
            }
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes => {
                user_automation.validate_for_cancel()?;
            }
            _ => {
                return Err(
                    "user automation input is reserved for AdmitUserAutomationOccurrence and CancelUserAutomationPendingWakes"
                        .to_owned(),
                );
            }
        }
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest = PlatformHandle::new(user_automation_mutation_digest(
            &operation,
            &user_automation,
        )?)
        .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: Some(user_automation),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity()?;
        match (&self.operation, &self.reactive_context) {
            (HostRuntimeControlOperation::DeliverReactiveContext, Some(source)) => {
                source.validate()?;
                let expected = reactive_context_mutation_digest(source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("reactive Context mutation_digest mismatch".to_owned());
                }
            }
            (HostRuntimeControlOperation::DeliverReactiveContext, None) => {
                return Err("reactive Context input is required".to_owned());
            }
            (_, Some(_)) => {
                return Err(
                    "reactive Context input is reserved for DeliverReactiveContext".to_owned(),
                );
            }
            (_, None) => {}
        }
        match (&self.operation, &self.user_automation) {
            (HostRuntimeControlOperation::AdmitUserAutomationOccurrence, Some(source)) => {
                source.validate_for_admit()?;
                let expected = user_automation_mutation_digest(&self.operation, source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("user automation mutation_digest mismatch".to_owned());
                }
            }
            (HostRuntimeControlOperation::CancelUserAutomationPendingWakes, Some(source)) => {
                source.validate_for_cancel()?;
                let expected = user_automation_mutation_digest(&self.operation, source)?;
                if self.mutation_digest.as_str() != expected {
                    return Err("user automation mutation_digest mismatch".to_owned());
                }
            }
            (
                HostRuntimeControlOperation::AdmitUserAutomationOccurrence
                | HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
                None,
            ) => {
                return Err("user automation input is required".to_owned());
            }
            (_, Some(_)) => {
                return Err("user automation input is reserved for AdmitUserAutomationOccurrence and CancelUserAutomationPendingWakes"
                    .to_owned());
            }
            (_, None) => {}
        }
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), String> {
        if self.wire.as_str() != WIRE {
            return Err("unsupported wire".to_owned());
        }
        if self.request_id.as_str().trim().is_empty()
            || self.request_id.as_str().chars().any(char::is_control)
        {
            return Err("request_id invalid".to_owned());
        }
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be lowercase sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be lowercase sha256".to_owned());
        }
        let expected = request_digest_for(
            &self.wire,
            &self.operation,
            &self.request_id,
            &self.mutation_digest,
        );
        if expected != self.request_digest.as_str() {
            return Err("request_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelRestartReceipt {
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    pub old_kernel_generation: PlatformHandle,
    pub new_kernel_generation: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub activation_receipt_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub receipt_digest: PlatformHandle,
}

impl HostKernelRestartReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.old_kernel_generation.as_str(),
            self.new_kernel_generation.as_str(),
            self.store_fence.as_str(),
            self.activation_receipt_digest.as_str(),
            self.ready_receipt_digest.as_str(),
        ))
        .map_err(|e| e.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_sha256_digest(&self.mutation_digest) {
            return Err("mutation_digest must be sha256".to_owned());
        }
        if !is_sha256_digest(&self.request_digest) {
            return Err("request_digest must be sha256".to_owned());
        }
        for (v, name) in [
            (&self.old_kernel_generation, "old_kernel_generation"),
            (&self.new_kernel_generation, "new_kernel_generation"),
            (&self.store_fence, "store_fence"),
            (&self.activation_receipt_digest, "activation_receipt_digest"),
            (&self.ready_receipt_digest, "ready_receipt_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if v.as_str().len() != 64
                || !v
                    .as_str()
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(format!("{name} must be sha256"));
            }
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("receipt_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStoreRecoveryReceipt {
    /// The mutation identity of the external Host runtime-control request.
    pub external_control_mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    /// The canonical payload digest of the inner Kernel StoreRebind request.
    pub store_rebind_request_digest: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub new_store_process_id: PlatformHandle,
    pub kernel_generation: PlatformHandle,
    pub activation_nonce_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub receipt_digest: PlatformHandle,
}

impl HostStoreRecoveryReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.external_control_mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.store_rebind_request_digest.as_str(),
            self.store_fence.as_str(),
            self.new_store_process_id.as_str(),
            self.kernel_generation.as_str(),
            self.activation_nonce_digest.as_str(),
            self.ready_receipt_digest.as_str(),
        ))
        .map_err(|e| e.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|e| e.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        for (v, name) in [
            (
                &self.external_control_mutation_digest,
                "external_control_mutation_digest",
            ),
            (&self.request_digest, "request_digest"),
            (
                &self.store_rebind_request_digest,
                "store_rebind_request_digest",
            ),
            (&self.store_fence, "store_fence"),
            (&self.kernel_generation, "kernel_generation"),
            (&self.activation_nonce_digest, "activation_nonce_digest"),
            (&self.ready_receipt_digest, "ready_receipt_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if !is_sha256_digest(v) {
                return Err(format!("{name} must be sha256"));
            }
        }
        if self.external_control_mutation_digest == self.store_rebind_request_digest {
            return Err(
                "external_control_mutation_digest and store_rebind_request_digest must remain distinct"
                    .to_owned(),
            );
        }
        if !is_store_process_identity(&self.new_store_process_id) {
            return Err("new_store_process_id must be pid:<u32>:start:<u64>".to_owned());
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("receipt_digest mismatch".to_owned());
        }
        Ok(())
    }
}

#[allow(private_interfaces)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostRuntimeControlResponse {
    Restarted {
        receipt: HostKernelRestartReceipt,
    },
    StoreRecovered {
        receipt: HostStoreRecoveryReceipt,
    },
    UserAutomationOccurrenceAdmitted {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        response: UserAutomationHostExecutionResponse,
    },
    UserAutomationPendingWakesCancelled {
        mutation_digest: PlatformHandle,
        request_digest: PlatformHandle,
        response: UserAutomationHostExecutionResponse,
    },
    Unknown {
        pending_ref: PlatformHandle,
    },
}

fn is_sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn validate_user_automation_response(
    expect_admit: bool,
    response: &UserAutomationHostExecutionResponse,
) -> Result<(), String> {
    match response {
        UserAutomationHostExecutionResponse::Admitted { request_sha256, .. } => {
            if !expect_admit {
                return Err("user automation cancel response must be Cancelled".to_owned());
            }
            if !is_sha256_text(request_sha256) {
                return Err("user automation request_sha256 must be sha256".to_owned());
            }
            Ok(())
        }
        UserAutomationHostExecutionResponse::Cancelled { request_sha256, .. } => {
            if expect_admit {
                return Err("user automation admit response must be Admitted".to_owned());
            }
            if !is_sha256_text(request_sha256) {
                return Err("user automation request_sha256 must be sha256".to_owned());
            }
            Ok(())
        }
        UserAutomationHostExecutionResponse::Failed { failure, .. } => {
            failure
                .validate()
                .map_err(|error| format!("user automation failure projection: {error}"))?;
            Ok(())
        }
        UserAutomationHostExecutionResponse::WakeRead { .. } => Err(
            "user automation readback travels over the execution transport, never runtime-control"
                .to_owned(),
        ),
    }
}

impl HostRuntimeControlResponse {
    pub fn restarted_for(
        request: &HostRuntimeControlRequest,
        receipt: HostKernelRestartReceipt,
    ) -> Self {
        let _ = request;
        Self::Restarted { receipt }
    }

    pub fn store_recovered_for(
        request: &HostRuntimeControlRequest,
        receipt: HostStoreRecoveryReceipt,
    ) -> Self {
        let _ = request;
        Self::StoreRecovered { receipt }
    }

    /// Bind a typed occurrence-admission answer to its runtime-control
    /// request. The typed carrier binding itself is checked by
    /// [`response_matches_request`].
    pub fn user_automation_occurrence_admitted_for(
        request: &HostRuntimeControlRequest,
        response: UserAutomationHostExecutionResponse,
    ) -> Self {
        Self::UserAutomationOccurrenceAdmitted {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            response,
        }
    }

    /// Bind a typed wake-cancellation answer to its runtime-control request.
    /// The typed carrier binding itself is checked by
    /// [`response_matches_request`].
    pub fn user_automation_pending_wakes_cancelled_for(
        request: &HostRuntimeControlRequest,
        response: UserAutomationHostExecutionResponse,
    ) -> Self {
        Self::UserAutomationPendingWakesCancelled {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            response,
        }
    }

    pub fn unknown_for(request: &HostRuntimeControlRequest, pending_ref: PlatformHandle) -> Self {
        let _ = request;
        Self::Unknown { pending_ref }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Restarted { receipt, .. } => receipt.validate(),
            Self::StoreRecovered { receipt, .. } => receipt.validate(),
            Self::UserAutomationOccurrenceAdmitted {
                mutation_digest,
                request_digest,
                response,
                ..
            } => {
                if !is_sha256_digest(mutation_digest) {
                    return Err("mutation_digest must be sha256".to_owned());
                }
                if !is_sha256_digest(request_digest) {
                    return Err("request_digest must be sha256".to_owned());
                }
                validate_user_automation_response(true, response)
            }
            Self::UserAutomationPendingWakesCancelled {
                mutation_digest,
                request_digest,
                response,
                ..
            } => {
                if !is_sha256_digest(mutation_digest) {
                    return Err("mutation_digest must be sha256".to_owned());
                }
                if !is_sha256_digest(request_digest) {
                    return Err("request_digest must be sha256".to_owned());
                }
                validate_user_automation_response(false, response)
            }
            Self::Unknown { pending_ref, .. } => parse_runtime_control_unknown_ref(pending_ref)
                .map(|_| ())
                .ok_or_else(|| "pending_ref is not canonical".to_owned()),
        }
    }
}

fn pending_ref_matches_request(
    pending_ref: &PlatformHandle,
    request: &HostRuntimeControlRequest,
) -> bool {
    parse_runtime_control_unknown_ref(pending_ref).is_some_and(|parsed| {
        parsed.wire == request.wire
            && parsed.operation == request.operation
            && parsed.request_id == request.request_id
            && parsed.mutation_digest == request.mutation_digest
            && parsed.request_digest == request.request_digest
    })
}

pub fn response_matches_request(
    request: &HostRuntimeControlRequest,
    response: &HostRuntimeControlResponse,
) -> bool {
    if response.validate().is_err() {
        return false;
    }
    match response {
        HostRuntimeControlResponse::Restarted { receipt } => {
            receipt.request_digest == request.request_digest
                && receipt.mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::StoreRecovered { receipt } => {
            receipt.request_digest == request.request_digest
                && receipt.external_control_mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted {
            mutation_digest,
            request_digest,
            response,
        } => {
            request.operation == HostRuntimeControlOperation::AdmitUserAutomationOccurrence
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
                && user_automation_response_matches_request(request, response)
        }
        HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            mutation_digest,
            request_digest,
            response,
        } => {
            request.operation == HostRuntimeControlOperation::CancelUserAutomationPendingWakes
                && *mutation_digest == request.mutation_digest
                && *request_digest == request.request_digest
                && user_automation_response_matches_request(request, response)
        }
        HostRuntimeControlResponse::Unknown { pending_ref } => {
            pending_ref_matches_request(pending_ref, request)
        }
    }
}

/// Check the typed UserAutomation answer against the exact carrier admitted
/// by the runtime-control request. The carrier digest and fence binding are
/// enforced by the existing typed response validation; a missing carrier or
/// an operation mismatch fails closed.
fn user_automation_response_matches_request(
    request: &HostRuntimeControlRequest,
    response: &UserAutomationHostExecutionResponse,
) -> bool {
    let Some(carrier) = request
        .user_automation
        .as_ref()
        .map(|source| &source.execution)
    else {
        return false;
    };
    let operation_matches = match (&request.operation, &carrier.operation) {
        (
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            UserAutomationHostExecutionOperation::AdmitOccurrence { .. },
        )
        | (
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            UserAutomationHostExecutionOperation::CancelPendingWakes { .. },
        ) => true,
        _ => false,
    };
    if !operation_matches {
        return false;
    }
    response.validate_for(carrier).is_ok()
}
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn durable_frame_identity(digest: &str) -> Result<(RequestId, RequestIdentity), String> {
    let request_id = RequestId::new(digest.to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    // Canonical lineage-A genesis fence for the synthetic frame identity
    // (Implements #64): the frame carries no authority; the exact tuple uses
    // the fixed canonical lineage at sequence 1.
    let genesis_epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .map_err(|_| "SessionFenced".to_owned())?,
        std::num::NonZeroU64::new(1).ok_or("SessionFenced")?,
    )
    .map_err(|_| "SessionFenced".to_owned())?;
    let state_fence = StateFence::new(genesis_epoch, ResourceGeneration::genesis());
    let product_id = ProductId::new("eliot.host.runtime-control".to_owned())
        .map_err(|_| "SessionFenced".to_owned())?;
    let source_id =
        SourceId::new("eliot-host".to_owned()).map_err(|_| "SessionFenced".to_owned())?;
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata: RequestMetadata {
                request_id: request_id.clone(),
                session_id: None,
                task_id: None,
                product_id,
                source_id,
                state_fence: state_fence.clone(),
                clock: ClockReading::default(),
            },
            state_fence,
        },
        idempotency_key: digest.to_owned(),
        deadline_unix_ms: u64::MAX,
        cancellation_id: digest.to_owned(),
    };
    identity
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    Ok((request_id, identity))
}

pub fn runtime_control_request_frame(
    connection_id: impl Into<String>,
    request: &HostRuntimeControlRequest,
) -> Result<Frame, String> {
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let (request_id, request_identity) = durable_frame_identity(request.request_digest.as_str())
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(request).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_request_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlRequest, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Start {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let request: HostRuntimeControlRequest =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    request.validate().map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if frame_request_id.as_str() != request.request_digest.as_str() {
        return Err("SessionFenced".to_owned());
    }
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id.as_str() != request.request_digest.as_str()
        || identity.idempotency_key != request.request_digest.as_str()
        || identity.cancellation_id != request.request_digest.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    if identity.request.metadata.request_id != *frame_request_id {
        return Err("SessionFenced".to_owned());
    }
    Ok(request)
}

pub fn runtime_control_response_frame(
    connection_id: impl Into<String>,
    response: &HostRuntimeControlResponse,
) -> Result<Frame, String> {
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let digest = match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            receipt.request_digest.as_str().to_owned()
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } => {
            receipt.request_digest.as_str().to_owned()
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted { request_digest, .. }
        | HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            request_digest, ..
        } => request_digest.as_str().to_owned(),
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            parse_runtime_control_unknown_ref(pending_ref)
                .ok_or_else(|| "SessionFenced".to_owned())?
                .request_digest
                .as_str()
                .to_owned()
        }
    };
    let (request_id, request_identity) =
        durable_frame_identity(&digest).map_err(|_| "SessionFenced".to_owned())?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: Some(request_id),
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: Some(request_identity),
        payload: ProtocolPayload::Json(
            serde_json::to_value(response).map_err(|_| "SessionFenced".to_owned())?,
        ),
        trace_context: production_trace_context(),
    };
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    Ok(frame)
}

pub fn decode_runtime_control_response_frame(
    frame: &Frame,
) -> Result<HostRuntimeControlResponse, String> {
    frame.validate().map_err(|_| "SessionFenced".to_owned())?;
    validate_production_trace_context(frame)?;
    if frame.kind != FrameKind::Control || frame.message_type != MessageType::Ready {
        return Err("SessionFenced".to_owned());
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err("SessionFenced".to_owned());
    };
    let response: HostRuntimeControlResponse =
        serde_json::from_value(payload.clone()).map_err(|_| "SessionFenced".to_owned())?;
    response
        .validate()
        .map_err(|_| "SessionFenced".to_owned())?;
    let frame_request_id = frame
        .request_id
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    let identity = frame
        .request_identity
        .as_ref()
        .ok_or_else(|| "SessionFenced".to_owned())?;
    if identity.request.metadata.request_id != *frame_request_id
        || identity.idempotency_key != frame_request_id.as_str()
        || identity.cancellation_id != frame_request_id.as_str()
    {
        return Err("SessionFenced".to_owned());
    }
    match &response {
        HostRuntimeControlResponse::Restarted { receipt, .. } => {
            if frame_request_id.as_str() != receipt.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } => {
            if frame_request_id.as_str() != receipt.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
        HostRuntimeControlResponse::UserAutomationOccurrenceAdmitted { request_digest, .. }
        | HostRuntimeControlResponse::UserAutomationPendingWakesCancelled {
            request_digest, ..
        } => {
            if frame_request_id.as_str() != request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            let pending_request = parse_runtime_control_unknown_ref(pending_ref)
                .ok_or_else(|| "SessionFenced".to_owned())?;
            if frame_request_id.as_str() != pending_request.request_digest.as_str() {
                return Err("SessionFenced".to_owned());
            }
        }
    }
    Ok(response)
}

fn production_trace_context() -> std::collections::BTreeMap<String, String> {
    std::collections::BTreeMap::from([(
        HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY.to_owned(),
        HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR.to_owned(),
    )])
}

fn validate_production_trace_context(frame: &Frame) -> Result<(), String> {
    if frame.trace_context.len() != 1
        || frame
            .trace_context
            .get(HOST_RUNTIME_CONTROL_PRODUCTION_TRACE_CONTEXT_KEY)
            .map(String::as_str)
            != Some(HOST_RUNTIME_CONTROL_PRODUCTION_DISCRIMINATOR)
    {
        return Err("SessionFenced".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).unwrap()
    }

    fn digest(seed: &str) -> PlatformHandle {
        handle(&sha256_hex(seed.as_bytes()))
    }

    fn restart_receipt(request: &HostRuntimeControlRequest) -> HostKernelRestartReceipt {
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: request.mutation_digest.clone(),
            request_digest: request.request_digest.clone(),
            old_kernel_generation: digest("old"),
            new_kernel_generation: digest("new"),
            store_fence: digest("fence"),
            activation_receipt_digest: digest("activation"),
            ready_receipt_digest: digest("ready"),
            receipt_digest: digest("placeholder"),
        };
        receipt.receipt_digest = receipt.computed_digest().unwrap();
        receipt
    }

    #[test]
    fn request_roundtrip_preserves_exact_idempotency_and_request_digests() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("shared-roundtrip"),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: HostRuntimeControlRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.mutation_digest, request.mutation_digest);
        assert_eq!(decoded.request_digest, request.request_digest);
        decoded.validate().unwrap();
    }

    #[test]
    fn old_wire_unknown_fields_and_operation_substitution_are_rejected() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("strict-wire"),
        )
        .unwrap();
        let mut old_wire = serde_json::to_value(&request).unwrap();
        old_wire["wire"] = serde_json::json!("eliot.host.runtime-control.v1");
        let old_wire_request: HostRuntimeControlRequest = serde_json::from_value(old_wire).unwrap();
        assert!(old_wire_request.validate().is_err());

        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostRuntimeControlRequest>(unknown).is_err());

        let mut substituted = request.clone();
        substituted.operation = HostRuntimeControlOperation::RecoverStore;
        assert!(substituted.validate().is_err());
    }

    #[test]
    fn response_substitution_is_rejected_and_exact_response_is_accepted() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("response-binding"),
        )
        .unwrap();
        let trusted =
            HostRuntimeControlResponse::restarted_for(&request, restart_receipt(&request));
        assert!(response_matches_request(&request, &trusted));

        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("foreign-response"),
        )
        .unwrap();
        let forged = HostRuntimeControlResponse::restarted_for(&foreign, restart_receipt(&foreign));
        assert!(!response_matches_request(&request, &forged));

        let mut substituted_receipt = restart_receipt(&request);
        substituted_receipt.new_kernel_generation = digest("substituted");
        let substituted = HostRuntimeControlResponse::restarted_for(&request, substituted_receipt);
        assert!(!response_matches_request(&request, &substituted));
    }

    #[test]
    fn request_and_response_frames_roundtrip_and_reject_identity_substitution() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RecoverStore,
            handle("frame-roundtrip"),
        )
        .unwrap();
        let frame = runtime_control_request_frame("request-connection", &request).unwrap();
        let decoded = decode_runtime_control_request_frame(&frame).unwrap();
        assert_eq!(decoded, request);

        let mut tampered = frame.clone();
        tampered.request_id =
            Some(RequestId::new(digest("wrong-frame-id").as_str().to_owned()).unwrap());
        assert!(decode_runtime_control_request_frame(&tampered).is_err());

        let response = HostRuntimeControlResponse::Unknown {
            pending_ref: runtime_control_unknown_ref("store-recovery", &request),
        };
        let response_frame =
            runtime_control_response_frame("response-connection", &response).unwrap();
        let decoded_response = decode_runtime_control_response_frame(&response_frame).unwrap();
        assert_eq!(decoded_response, response);
    }

    fn test_fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let epoch = EpochId::new(lineage, std::num::NonZeroU64::new(1).unwrap()).unwrap();
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn cancelled_wakes() -> UserAutomationHostExecutionResponse {
        UserAutomationHostExecutionResponse::Cancelled {
            request_sha256: sha256_hex(b"cancel-carrier"),
            state_fence: test_fence(),
            wake_ids: vec!["wake-1".to_owned()],
        }
    }

    /// Identity-only request used to prove the Unknown reconciliation path.
    /// Typed UserAutomation requests always carry a validated carrier, so this
    /// helper covers only the digest-identity reconciliation after a lost
    /// response, exactly like `parse_runtime_control_unknown_ref` does.
    fn identity_only_user_automation_request(
        operation: HostRuntimeControlOperation,
        request_id: &str,
    ) -> HostRuntimeControlRequest {
        let wire = PlatformHandle::new(WIRE.to_owned()).unwrap();
        let request_id = handle(request_id);
        let mutation_digest =
            PlatformHandle::new(mutation_digest_for_request_id(&wire, &request_id)).unwrap();
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &operation,
            &request_id,
            &mutation_digest,
        ))
        .unwrap();
        HostRuntimeControlRequest {
            wire,
            operation,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            user_automation: None,
        }
    }

    #[test]
    fn user_automation_requests_fail_closed_without_typed_carrier() {
        let admit = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            handle("ua-admit-no-carrier"),
        );
        assert_eq!(
            admit.unwrap_err(),
            "user automation input is required".to_owned()
        );
        let cancel = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
            handle("ua-cancel-no-carrier"),
        );
        assert_eq!(
            cancel.unwrap_err(),
            "user automation input is required".to_owned()
        );
    }

    #[test]
    fn user_automation_operation_wire_names_are_canonical() {
        assert_eq!(
            serde_json::to_value(HostRuntimeControlOperation::AdmitUserAutomationOccurrence)
                .unwrap(),
            serde_json::json!("ADMIT_USER_AUTOMATION_OCCURRENCE")
        );
        assert_eq!(
            serde_json::to_value(HostRuntimeControlOperation::CancelUserAutomationPendingWakes)
                .unwrap(),
            serde_json::json!("CANCEL_USER_AUTOMATION_PENDING_WAKES")
        );
        assert_eq!(
            serde_json::from_value::<HostRuntimeControlOperation>(serde_json::json!(
                "ADMIT_USER_AUTOMATION_OCCURRENCE"
            ))
            .unwrap(),
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence
        );
        assert_eq!(
            operation_unknown_prefix(&HostRuntimeControlOperation::AdmitUserAutomationOccurrence),
            "user-automation-admit"
        );
        assert_eq!(
            operation_unknown_prefix(
                &HostRuntimeControlOperation::CancelUserAutomationPendingWakes
            ),
            "user-automation-cancel-wakes"
        );
    }

    #[test]
    fn user_automation_unknown_refs_roundtrip_and_reconcile_after_lost_response() {
        for operation in [
            HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
            HostRuntimeControlOperation::CancelUserAutomationPendingWakes,
        ] {
            let request = identity_only_user_automation_request(operation.clone(), "ua-reconcile");
            for suffix in ["validation", "queue-lock", "queue-full", "queue-response"] {
                let pending_ref = operation_unknown_ref(&operation, suffix, &request);
                let parsed = parse_runtime_control_unknown_ref(&pending_ref).unwrap();
                assert_eq!(parsed.operation, operation);
                assert_eq!(parsed.request_digest, request.request_digest);
                let unknown = HostRuntimeControlResponse::Unknown {
                    pending_ref: pending_ref.clone(),
                };
                unknown.validate().unwrap();
                assert!(response_matches_request(&request, &unknown));
                let frame =
                    runtime_control_response_frame("ua-reconcile-connection", &unknown).unwrap();
                let decoded = decode_runtime_control_response_frame(&frame).unwrap();
                assert_eq!(decoded, unknown);
            }
        }

        let restart = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-foreign"),
        )
        .unwrap();
        let foreign = HostRuntimeControlResponse::Unknown {
            pending_ref: operation_unknown_ref(
                &HostRuntimeControlOperation::AdmitUserAutomationOccurrence,
                "validation",
                &restart,
            ),
        };
        foreign.validate().unwrap();
        assert!(!response_matches_request(&restart, &foreign));

        let payload = serde_json::to_string(&(
            "NoSuchOperation",
            "id",
            sha256_hex(b"mutation"),
            sha256_hex(b"request"),
        ))
        .unwrap();
        let unknown_operation =
            PlatformHandle::new(format!("{WIRE}:unknown:reactive-context:{payload}")).unwrap();
        assert!(parse_runtime_control_unknown_ref(&unknown_operation).is_none());
        let unknown_reason =
            PlatformHandle::new(format!("{WIRE}:unknown:no-such-reason:{payload}")).unwrap();
        assert!(parse_runtime_control_unknown_ref(&unknown_reason).is_none());
    }

    #[test]
    fn user_automation_responses_bind_to_exact_request_and_reject_crossed_answers() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-crossed"),
        )
        .unwrap();
        let cancelled = cancelled_wakes();

        let crossed = HostRuntimeControlResponse::user_automation_occurrence_admitted_for(
            &request,
            cancelled.clone(),
        );
        assert!(crossed.validate().is_err());
        assert!(!response_matches_request(&request, &crossed));

        let bound = HostRuntimeControlResponse::user_automation_pending_wakes_cancelled_for(
            &request, cancelled,
        );
        bound.validate().unwrap();
        assert!(!response_matches_request(&request, &bound));
    }

    #[test]
    fn user_automation_response_frames_roundtrip_and_reject_digest_substitution() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("ua-frame"),
        )
        .unwrap();
        let response = HostRuntimeControlResponse::user_automation_pending_wakes_cancelled_for(
            &request,
            cancelled_wakes(),
        );
        let frame = runtime_control_response_frame("ua-connection", &response).unwrap();
        let decoded = decode_runtime_control_response_frame(&frame).unwrap();
        assert_eq!(decoded, response);

        let mut tampered = frame.clone();
        tampered.request_id =
            Some(RequestId::new(digest("wrong-ua-frame-id").as_str().to_owned()).unwrap());
        assert!(decode_runtime_control_response_frame(&tampered).is_err());
    }
}
