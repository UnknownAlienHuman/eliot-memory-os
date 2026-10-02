//! Closed typed wire carriers for authenticated external instrument stage
//! admission and Kernel dispatch-grant production.

use eliot_instrument_api::registry::{ExternalStagePin, ResolvedExecutionBinding};
use eliot_instrument_api::{InstrumentAdmissionGrant, InstrumentInvocation};
use eliot_process::{KernelDispatchGrant, ProcessIntent};
use eliot_store_api::ScopeId;
use serde::{Deserialize, Serialize};

/// Closed Execute selector for one canonical external-stage grant request.
pub const INSTRUMENT_STAGE_GRANT_OPERATION: &str = "instrument_stage.grant";

/// Typed, inert selection and exact process intent for stage-grant admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageGrantRequest {
    /// Governor-resolved, fixed WorkScope id.
    pub scope_id: ScopeId,
    /// Exact durable profile/revision/stage and registry generation.
    pub pin: ExternalStagePin,
    /// Typed original request and instrument-level invocation.
    pub invocation: InstrumentInvocation,
    /// Retained exact WorkScope/profile resolution.
    pub resolution: ResolvedExecutionBinding,
    /// Process intent to bind to the unchanged Kernel grant.
    pub intent: ProcessIntent,
}

impl InstrumentStageGrantRequest {
    /// Checks that the original received process intent is sealed to the exact
    /// shared admission recomputed from the canonical registry. This is an
    /// integrity check only; Kernel still authenticates the caller and reads
    /// the canonical owner state before issuing its dispatch grant.
    pub fn validate_admission_binding(
        &self,
        admission: &InstrumentAdmissionGrant,
    ) -> Result<(), eliot_process::ContractError> {
        self.intent.validate()?;
        let expected = admission.digest();
        if admission.grant_digest != expected
            || self.intent.instrument_admission_digest() != Some(expected.as_str())
        {
            return Err(eliot_process::ContractError::DigestMismatch {
                field: "instrument_stage.admission_digest",
                expected,
                observed: self
                    .intent
                    .instrument_admission_digest()
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        if self.intent.operation_id().as_str() != self.invocation.request.request_id.as_str()
            || self.intent.working_directory() != self.resolution.source_root
            || self.resolution.authority_epoch
                != self.invocation.request.state_fence.authority_epoch
            || self.resolution.resource_generation
                != self
                    .invocation
                    .request
                    .state_fence
                    .resource_generation
                    .value()
            || self.intent.generation().get() != self.resolution.resource_generation
        {
            return Err(eliot_process::ContractError::InvalidValue {
                field: "instrument_stage.resolution",
                reason: "intent, invocation, resolved source, or request fence differs",
            });
        }
        Ok(())
    }
}

/// Stage admission plus the original Kernel grant consumed by the existing
/// one-shot process owner. The `dispatch_grant` bytes are never rewritten.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageGrantResponse {
    /// Shared canonical profile/spec/parser admission proof.
    pub admission: InstrumentAdmissionGrant,
    /// Existing process-owner grant, bound to `intent.effect_digest()`.
    pub dispatch_grant: KernelDispatchGrant,
}

/// Closed selector for the owner's fresh suspended-child observation.
pub const INSTRUMENT_STAGE_STARTED_OPERATION: &str = "instrument_stage.started";

/// Closed selector for the owner's terminal process observation.
pub const INSTRUMENT_STAGE_TERMINAL_OPERATION: &str = "instrument_stage.terminal";

/// Exact physical evidence reported by P-04 while the child is still suspended.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageStartedRequest {
    /// Original process operation allocated by the admitted invocation.
    pub operation_id: eliot_process::OperationId,
    /// Digest of the original registry admission grant.
    pub admission_digest: String,
    /// Digest of the original Kernel dispatch grant.
    pub dispatch_grant_digest: Option<String>,
    /// Original TestD retry identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_seq: Option<u32>,
    /// Durable TestD job identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Exact P-03 sealed process request digest produced by the executor owner.
    pub process_request_digest: String,
    /// P-04's exact PID/start-time/image observation captured while suspended.
    pub suspended_identity: eliot_process::SuspendedProcessIdentity,
    /// Exact executable path and file identity observed before resume.
    pub launch: eliot_process::SuspendedLaunchEvidence,
    /// Owner-produced durable binding to the exact native Job and root process.
    pub recoverable_job_binding: eliot_platform_windows::RecoverableJobBinding,
}

/// Echo binding returned only after Kernel retained the same live Job object.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageStartedResponse {
    /// Original process operation.
    pub operation_id: eliot_process::OperationId,
    /// Original registry admission digest.
    pub admission_digest: String,
    /// Original Kernel dispatch grant digest.
    pub dispatch_grant_digest: Option<String>,
    /// Original TestD retry identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_seq: Option<u32>,
    /// Durable TestD job identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Exact P-03 sealed process request digest retained at start.
    pub process_request_digest: String,
}

/// Exact terminal process evidence from the original P-04 executor operation.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageTerminalRequest {
    /// Original process operation allocated by the admitted invocation.
    pub operation_id: eliot_process::OperationId,
    /// Digest of the original registry admission grant.
    pub admission_digest: String,
    /// Digest of the original Kernel dispatch grant.
    pub dispatch_grant_digest: Option<String>,
    /// Original TestD retry identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_seq: Option<u32>,
    /// Durable TestD job identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// P-03's original request digest, echoed from the started observation.
    pub process_request_digest: String,
    /// P-04's exact validated typed evidence; physical terminality is
    /// independently checked against the retained Job before slot release.
    pub evidence: eliot_process::ProcessEvidence,
}

/// Echo binding returned only after the retained whole Job is empty.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageTerminalResponse {
    /// Original process operation.
    pub operation_id: eliot_process::OperationId,
    /// Original registry admission digest.
    pub admission_digest: String,
    /// Original Kernel dispatch grant digest.
    pub dispatch_grant_digest: Option<String>,
    /// Original TestD retry identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_seq: Option<u32>,
    /// Durable TestD job identity; present together for a TestD attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// Exact P-03 request digest retained at start.
    pub process_request_digest: String,
}
