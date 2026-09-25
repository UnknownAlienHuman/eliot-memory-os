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
    "demand-start-validation",
    "demand-start-queue-lock",
    "demand-start-queue-full",
    "demand-start-queue-response",
    "demand-start",
    "demand-start-drain-committed",
    "demand-start-reconcile",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HostRuntimeControlOperation {
    RestartKernel,
    ReconcileKernelRestart,
    RecoverStore,
    ReconcileStoreRecovery,
    DeliverReactiveContext,
    RequestDemandStart,
}

fn canonical_operation_name(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel => "RestartKernel",
        HostRuntimeControlOperation::ReconcileKernelRestart => "ReconcileKernelRestart",
        HostRuntimeControlOperation::RecoverStore => "RecoverStore",
        HostRuntimeControlOperation::ReconcileStoreRecovery => "ReconcileStoreRecovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "DeliverReactiveContext",
        HostRuntimeControlOperation::RequestDemandStart => "RequestDemandStart",
    }
}

fn operation_unknown_prefix(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel
        | HostRuntimeControlOperation::ReconcileKernelRestart => "kernel-restart",
        HostRuntimeControlOperation::RecoverStore
        | HostRuntimeControlOperation::ReconcileStoreRecovery => "store-recovery",
        HostRuntimeControlOperation::DeliverReactiveContext => "reactive-context",
        HostRuntimeControlOperation::RequestDemandStart => "demand-start",
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

fn validate_demand_handle(value: &PlatformHandle, field: &str) -> Result<(), String> {
    if value.as_str().trim().is_empty() || value.as_str().chars().any(char::is_control) {
        return Err(format!("{field} is invalid"));
    }
    Ok(())
}

fn validate_demand_handles(
    values: &[PlatformHandle],
    field: &str,
    require_nonempty: bool,
) -> Result<(), String> {
    if require_nonempty && values.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    for value in values {
        validate_demand_handle(value, field)?;
    }
    Ok(())
}

/// Safety class carried by an owner-issued wake. The Host persists this
/// value and never treats it as permission to grant semantic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostDemandStartSafetyClass {
    ServiceSafe,
    UserSessionRequired,
}

/// Complete owner-issued wake material for a demand-start request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDemandStartWakeRequest {
    pub wake_id: PlatformHandle,
    pub reason: PlatformHandle,
    pub earliest_start: PlatformHandle,
    pub deadline: PlatformHandle,
    pub expiry: PlatformHandle,
    pub required_capabilities: Vec<PlatformHandle>,
    pub maintenance_family: PlatformHandle,
    pub safety_class: HostDemandStartSafetyClass,
    pub state_fence_revalidation_ref: PlatformHandle,
    pub budget_ref: PlatformHandle,
}

impl HostDemandStartWakeRequest {
    pub fn validate(&self) -> Result<(), String> {
        for (value, field) in [
            (&self.wake_id, "demand_start.wake_id"),
            (&self.reason, "demand_start.wake.reason"),
            (&self.earliest_start, "demand_start.wake.earliest_start"),
            (&self.deadline, "demand_start.wake.deadline"),
            (&self.expiry, "demand_start.wake.expiry"),
            (
                &self.maintenance_family,
                "demand_start.wake.maintenance_family",
            ),
            (
                &self.state_fence_revalidation_ref,
                "demand_start.wake.state_fence_revalidation_ref",
            ),
            (&self.budget_ref, "demand_start.wake.budget_ref"),
        ] {
            validate_demand_handle(value, field)?;
        }
        validate_demand_handles(
            &self.required_capabilities,
            "demand_start.wake.required_capabilities",
            true,
        )
    }
}

/// Authenticated demand-start intent accepted by Host.
///
/// A stopped installation cannot require a Kernel StateFence or RuntimeLease
/// before asking Host to start Kernel. The optional legacy projections remain
/// decodable for wire compatibility, but Host rejects them as authority and
/// obtains the exact fence and owner admission from the ready Kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDemandStartRuntimeRequest {
    pub requester_principal: PlatformHandle,
    pub candidate_scope: PlatformHandle,
    pub trigger_class: PlatformHandle,
    pub trigger_evidence: Vec<PlatformHandle>,
    pub requested_capabilities: Vec<PlatformHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_fence: Option<StateFence>,
    /// The authenticated owner projection used for the post-start Kernel
    /// RuntimeLease admission.  It is optional on the wire only so older
    /// callers remain decodable; Host fails closed before demand activation
    /// when the current owner cannot provide it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_lease_admission: Option<eliot_kernel_service::RuntimeLeaseAdmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_lease_ref: Option<PlatformHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervision_lease_ref: Option<PlatformHandle>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<HostDemandStartWakeRequest>,
}

impl HostDemandStartRuntimeRequest {
    pub fn validate(&self) -> Result<(), String> {
        for (value, field) in [
            (
                &self.requester_principal,
                "demand_start.requester_principal",
            ),
            (&self.candidate_scope, "demand_start.candidate_scope"),
            (&self.trigger_class, "demand_start.trigger_class"),
        ] {
            validate_demand_handle(value, field)?;
        }
        if let Some(value) = &self.runtime_lease_ref {
            validate_demand_handle(value, "demand_start.runtime_lease_ref")?;
        }
        if let Some(value) = &self.supervision_lease_ref {
            validate_demand_handle(value, "demand_start.supervision_lease_ref")?;
        }
        validate_demand_handles(
            &self.trigger_evidence,
            "demand_start.trigger_evidence",
            true,
        )?;
        validate_demand_handles(
            &self.requested_capabilities,
            "demand_start.requested_capabilities",
            true,
        )?;
        if self.requested_capabilities.len() != 1 {
            return Err(
                "demand_start currently binds exactly one requested capability per owner admission"
                    .to_owned(),
            );
        }
        if let Some(state_fence) = &self.state_fence {
            state_fence
                .validate()
                .map_err(|error| format!("demand_start.state_fence is invalid: {error}"))?;
        }
        if let Some(admission) = &self.runtime_lease_admission {
            admission.validate().map_err(|error| {
                format!("demand_start.runtime_lease_admission is invalid: {error}")
            })?;
            if self.state_fence.as_ref() != Some(&admission.state_fence) {
                return Err(
                    "demand_start.runtime_lease_admission.state_fence does not match demand_start.state_fence"
                        .to_owned(),
                );
            }
        }
        if let Some(wake) = &self.wake {
            wake.validate()?;
        }
        Ok(())
    }
}

fn demand_start_mutation_digest(source: &HostDemandStartRuntimeRequest) -> Result<String, String> {
    let encoded = serde_json::to_vec(source)
        .map_err(|_| "demand-start source could not be encoded".to_owned())?;
    let mut material = Vec::with_capacity(WIRE.len() + encoded.len() + 18);
    material.extend_from_slice(WIRE.as_bytes());
    material.extend_from_slice(b":demand-start:");
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
        "RequestDemandStart" => HostRuntimeControlOperation::RequestDemandStart,
        _ => return None,
    };
    let request = HostRuntimeControlRequest {
        wire: PlatformHandle::new(wire.to_owned()).ok()?,
        operation,
        request_id: PlatformHandle::new(request_id).ok()?,
        mutation_digest: PlatformHandle::new(mutation_digest).ok()?,
        request_digest: PlatformHandle::new(request_digest).ok()?,
        reactive_context: None,
        demand_start: None,
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
    /// Complete owner-issued input for the authenticated demand-start operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub demand_start: Option<HostDemandStartRuntimeRequest>,
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
            demand_start: None,
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
            demand_start: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Construct one authenticated demand-start request. The mutation
    /// digest covers every owner-issued field, including opaque lease refs
    /// and the complete optional WakeIntent material.
    pub fn new_demand_start(
        request_id: PlatformHandle,
        demand_start: HostDemandStartRuntimeRequest,
    ) -> Result<Self, String> {
        demand_start.validate()?;
        let wire = PlatformHandle::new(WIRE.to_owned()).map_err(|e| e.to_string())?;
        let mutation_digest = PlatformHandle::new(demand_start_mutation_digest(&demand_start)?)
            .map_err(|e| e.to_string())?;
        let request_digest = PlatformHandle::new(request_digest_for(
            &wire,
            &HostRuntimeControlOperation::RequestDemandStart,
            &request_id,
            &mutation_digest,
        ))
        .map_err(|e| e.to_string())?;
        let value = Self {
            wire,
            operation: HostRuntimeControlOperation::RequestDemandStart,
            request_id,
            mutation_digest,
            request_digest,
            reactive_context: None,
            demand_start: Some(demand_start),
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

    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity()?;
        if matches!(
            &self.operation,
            HostRuntimeControlOperation::RequestDemandStart
        ) {
            let source = self
                .demand_start
                .as_ref()
                .ok_or_else(|| "demand-start input is required".to_owned())?;
            source.validate()?;
            let expected = demand_start_mutation_digest(source)?;
            if self.mutation_digest.as_str() != expected {
                return Err("demand-start mutation_digest mismatch".to_owned());
            }
        } else if self.demand_start.is_some() {
            return Err("demand-start input is reserved for RequestDemandStart".to_owned());
        }
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

/// Host's authenticated demand-start outcome after journal/reconcile proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostDemandStartState {
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDemandStartReceipt {
    pub mutation_digest: PlatformHandle,
    pub request_digest: PlatformHandle,
    pub activation_id: PlatformHandle,
    pub activation_generation: PlatformHandle,
    pub state: HostDemandStartState,
    pub candidate_scope: PlatformHandle,
    pub governance_profile: PlatformHandle,
    pub readiness_evidence_refs: Vec<PlatformHandle>,
    pub runtime_lease_ref: PlatformHandle,
    pub supervision_lease_ref: PlatformHandle,
    pub drain_disposition: Option<PlatformHandle>,
    pub receipt_digest: PlatformHandle,
}

impl HostDemandStartReceipt {
    pub fn computed_digest(&self) -> Result<PlatformHandle, String> {
        let bytes = serde_json::to_vec(&(
            self.mutation_digest.as_str(),
            self.request_digest.as_str(),
            self.activation_id.as_str(),
            self.activation_generation.as_str(),
            self.state,
            self.candidate_scope.as_str(),
            self.governance_profile.as_str(),
            &self.readiness_evidence_refs,
            self.runtime_lease_ref.as_str(),
            self.supervision_lease_ref.as_str(),
            self.drain_disposition.as_ref().map(PlatformHandle::as_str),
        ))
        .map_err(|error| error.to_string())?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| error.to_string())
    }

    pub fn validate(&self) -> Result<(), String> {
        for (value, name) in [
            (&self.mutation_digest, "mutation_digest"),
            (&self.request_digest, "request_digest"),
            (&self.receipt_digest, "receipt_digest"),
        ] {
            if !is_sha256_digest(value) {
                return Err(format!("{name} must be lowercase sha256"));
            }
        }
        for (value, name) in [
            (&self.activation_id, "activation_id"),
            (&self.activation_generation, "activation_generation"),
            (&self.candidate_scope, "candidate_scope"),
            (&self.governance_profile, "governance_profile"),
            (&self.runtime_lease_ref, "runtime_lease_ref"),
            (&self.supervision_lease_ref, "supervision_lease_ref"),
        ] {
            validate_demand_handle(value, name)?;
        }
        validate_demand_handles(
            &self.readiness_evidence_refs,
            "readiness_evidence_refs",
            true,
        )?;
        if let Some(value) = &self.drain_disposition {
            validate_demand_handle(value, "drain_disposition")?;
        }
        if self.state != HostDemandStartState::Active {
            return Err("demand-start receipt is not active".to_owned());
        }
        if self.receipt_digest != self.computed_digest()? {
            return Err("demand-start receipt_digest mismatch".to_owned());
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
    Restarted { receipt: HostKernelRestartReceipt },
    StoreRecovered { receipt: HostStoreRecoveryReceipt },
    DemandStarted { receipt: HostDemandStartReceipt },
    Unknown { pending_ref: PlatformHandle },
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

    pub fn demand_started_for(
        request: &HostRuntimeControlRequest,
        receipt: HostDemandStartReceipt,
    ) -> Self {
        let _ = request;
        Self::DemandStarted { receipt }
    }

    pub fn unknown_for(request: &HostRuntimeControlRequest, pending_ref: PlatformHandle) -> Self {
        let _ = request;
        Self::Unknown { pending_ref }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Restarted { receipt, .. } => receipt.validate(),
            Self::StoreRecovered { receipt, .. } => receipt.validate(),
            Self::DemandStarted { receipt, .. } => receipt.validate(),
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
        HostRuntimeControlResponse::DemandStarted { receipt } => {
            receipt.request_digest == request.request_digest
                && receipt.mutation_digest == request.mutation_digest
        }
        HostRuntimeControlResponse::Unknown { pending_ref } => {
            pending_ref_matches_request(pending_ref, request)
        }
    }
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
        HostRuntimeControlResponse::DemandStarted { receipt, .. } => {
            receipt.request_digest.as_str().to_owned()
        }
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
        HostRuntimeControlResponse::DemandStarted { receipt, .. } => {
            if frame_request_id.as_str() != receipt.request_digest.as_str() {
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
}
