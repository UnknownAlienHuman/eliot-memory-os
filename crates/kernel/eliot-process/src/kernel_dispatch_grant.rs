//! Inert Kernel-issued dispatch grant and the P-04 validation seam.

use eliot_contracts::EpochId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ProcessExecutionError, ProcessRequest, SuspendedLaunchEvidence, SuspendedProcessIdentity,
    ValidatedDispatch,
};

/// Original Kernel-issued material authorizing one exact process intent.
///
/// This carrier is inert. Consumers must validate its digest against the
/// authenticated Kernel admission and exact intent before issuing a local
/// one-shot process permit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelDispatchGrant {
    /// SHA-256 over the original admission identity and every grant field.
    pub grant_digest: String,
    /// Authority epoch observed by Kernel at admission.
    pub authority_epoch: EpochId,
    /// Activation generation observed by Kernel at admission.
    pub fence_generation: u64,
    /// Original state-fence nonce.
    pub fence_nonce: String,
    /// Original idempotency key.
    pub idempotency_key: String,
    /// Original expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Kernel-selected `TestD` owner store path, when this is a `TestD` grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub testd_owner_store_path: Option<String>,
}

/// P-07's injected process-authority seam consumed by the P-04 executor.
///
/// Implementations route validation to the active Kernel process authority.
/// P-04 receives no permit key, replay snapshot, or issuer capability.
pub trait DispatchValidationPort: Send + Sync {
    /// Consumes exactly one P-03 permit after fresh P-02 evidence is bound to
    /// the request.
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError>;

    /// Reports the actual suspended P-04 child to the Kernel's required
    /// instrument lifecycle owner before consuming a new external-stage
    /// permit. The Windows platform binding is produced by the same suspended
    /// child owner that will resume the process; callers cannot substitute a
    /// reconstructed Job or root identity.
    ///
    /// Legacy requests continue through [`Self::validate_and_consume`]. An
    /// instrument request cannot use this default: a production authority
    /// must implement the authenticated start observation explicitly.
    #[cfg(windows)]
    fn validate_and_consume_instrument(
        &self,
        _request: ProcessRequest,
        _observed: SuspendedProcessIdentity,
        _launch: SuspendedLaunchEvidence,
        _recoverable_job_binding: eliot_platform_windows::RecoverableJobBinding,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        Err(ProcessExecutionError::Unavailable(
            "instrument launch requires the authenticated Kernel suspended-child observer"
                .to_owned(),
        ))
    }
}
