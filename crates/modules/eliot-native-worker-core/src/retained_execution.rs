//! Provider-neutral identity and result carriers for retained native-worker
//! operations.
//!
//! These carriers preserve an owner-issued dispatch exactly. They carry no
//! launch capability, provider material, credential, or authority, and they
//! never repair or recompute a presented owner digest. Callers must validate
//! the identity against the independent claim, hello, and sealed process
//! request before using it.

use eliot_contracts::{EpochId, StateFence, sha256_hex};
use eliot_protocol::{
    NativeWorkerProviderProcessIdentityV1, NativeWorkerRetainedProviderMaterialRefV1,
};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ClaimAdmissionRequest, WorkerError, WorkerHello};
use eliot_process::ProcessRequest;

/// Closed carrier for the exact persisted identity of a retained worker
/// operation. Its fields mirror the daemon's persisted dispatch record and
/// the extra material reference resolved by the current owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedOperationIdentity {
    /// Exact durable daemon dispatch identity.
    pub dispatch_id: String,
    /// Governed task identity.
    pub task_id: String,
    /// Exact owner-issued claim-scoped retained-material reference. Its
    /// dispatch operation is the native claim operation and is not reused as
    /// the provider child's operation.
    pub material_reference: NativeWorkerRetainedProviderMaterialRefV1,
    /// Separate Kernel-issued identity for the provider child process.
    pub provider_process: NativeWorkerProviderProcessIdentityV1,
    /// Admitted provider route class.
    pub route_class: String,
    /// Full admitted provider route reference.
    pub route_ref: String,
    /// Worker generation from the persisted dispatch.
    pub worker_generation: u64,
    /// Original owner-issued executable digest, preserved verbatim.
    pub executable_digest: String,
    /// Expected result schema from the persisted dispatch.
    pub expected_result_schema: String,
    /// Exact admitted deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Owner-issued cancellation identity for this operation.
    pub cancellation_id: String,
    /// Exact admitted immutable state fence.
    pub state_fence: StateFence,
    /// Exact admitted authority epoch.
    pub authority_epoch: EpochId,
}

impl NativeWorkerRetainedOperationIdentity {
    /// Exact dispatch operation named by the shared claim-scoped reference.
    #[must_use]
    pub fn dispatch_operation_id(&self) -> &str {
        &self.material_reference.dispatch_operation_id
    }

    /// Exact claim id named by the shared claim-scoped reference.
    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.material_reference.claim_id
    }

    /// Exact admitted attempt named by the shared claim-scoped reference.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.material_reference.attempt_id
    }

    /// Exact binding digest named by the shared claim-scoped reference.
    #[must_use]
    pub fn binding_digest(&self) -> &str {
        &self.material_reference.binding_digest
    }

    /// Exact provider child operation named by the separate process identity.
    #[must_use]
    pub fn provider_operation_id(&self) -> &str {
        &self.provider_process.provider_operation_id
    }

    /// Validates bounded shape without granting authority.
    pub fn validate(&self) -> Result<(), WorkerError> {
        for (value, field) in [
            (&self.dispatch_id, "retained.dispatch_id"),
            (&self.task_id, "retained.task_id"),
            (&self.route_class, "retained.route_class"),
            (&self.route_ref, "retained.route_ref"),
            (
                &self.expected_result_schema,
                "retained.expected_result_schema",
            ),
            (&self.cancellation_id, "retained.cancellation_id"),
        ] {
            validate_identity_text(value, field)?;
        }
        if self.worker_generation == 0 || self.deadline_unix_ms == 0 {
            return Err(WorkerError::InvalidRequest("retained.deadline_generation"));
        }
        self.material_reference
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("retained.material_reference"))?;
        self.provider_process
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("retained.provider_process"))?;
        if self.material_reference.dispatch_operation_id
            == self.provider_process.provider_operation_id
        {
            return Err(WorkerError::AdmissionMismatch(
                "retained_provider_operation_reuses_dispatch",
            ));
        }
        for (digest, field) in [
            (&self.executable_digest, "retained.executable_digest"),
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(WorkerError::InvalidRequest(field));
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkerError::InvalidRequest("retained.state_fence"))?;
        if !self
            .authority_epoch
            .is_same_authority(&self.state_fence.authority_epoch)
        {
            return Err(WorkerError::StaleEpoch);
        }
        Ok(())
    }

    /// Requires the exact worker executable digest from the independently
    /// authenticated admitted-material owner. The provider child's digest is
    /// checked separately against its sealed `ProcessRequest`.
    pub fn validate_dispatch_executable_digest(
        &self,
        owner_executable_digest: &str,
    ) -> Result<(), WorkerError> {
        self.validate()?;
        if owner_executable_digest != self.executable_digest {
            return Err(WorkerError::AdmissionMismatch(
                "retained_dispatch_executable_digest",
            ));
        }
        Ok(())
    }

    /// Joins this persisted identity to the independently presented native
    /// claim, authenticated hello, and sealed process request. Values are
    /// compared as issued; no local digest is substituted for an owner value.
    pub fn validate_against(
        &self,
        admission: &ClaimAdmissionRequest,
        hello: &WorkerHello,
        process: &ProcessRequest,
    ) -> Result<(), WorkerError> {
        self.validate()?;
        admission.validate_binding()?;
        hello.validate()?;
        process.validate()?;
        let claim = admission.claim();
        if self.task_id != claim.task_id.as_str()
            || self.material_reference.dispatch_operation_id != claim.operation_id.as_str()
            || self.material_reference.attempt_id != claim.attempt_id.as_str()
            || self.material_reference.claim_id != claim.claim_id.as_str()
            || self.worker_generation != claim.worker_generation
            || self.material_reference.binding_digest != claim.binding_digest
            || self.route_class != claim.route_class
            || self.expected_result_schema != claim.expected_result_schema
            || self.deadline_unix_ms != claim.deadline_unix_ms
        {
            return Err(WorkerError::AdmissionMismatch("retained_claim_identity"));
        }
        if self.authority_epoch != claim.authority_epoch
            || self.authority_epoch != hello.authority_epoch
        {
            return Err(WorkerError::StaleEpoch);
        }
        if self.state_fence != claim.state_fence || self.state_fence != hello.state_fence {
            return Err(WorkerError::StaleFence);
        }
        if self.route_ref != hello.route_ref
            || self.provider_process.provider_operation_id != process.operation_id().as_str()
            || self.worker_generation != process.generation().get()
            || self.provider_process.provider_executable_digest != process.executable_sha256()
            || self.provider_process.provider_process_invocation_digest
                != process.invocation_digest()
        {
            return Err(WorkerError::AdmissionMismatch(
                "retained_provider_process_identity",
            ));
        }
        if self.material_reference.binding_digest != claim.compute_binding_digest()? {
            return Err(WorkerError::AdmissionMismatch("retained_binding_digest"));
        }
        Ok(())
    }
}

/// Provider-neutral disposition for one retained operation outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeWorkerRetainedOutcomeKind {
    /// A complete candidate was observed under the original operation.
    CandidateReady,
    /// A candidate was observed with explicit incompleteness.
    CandidatePartial,
    /// The provider returned a candidate failure.
    CandidateFailed,
    /// The executor observed cancellation for the original operation.
    CancelledObserved,
    /// The effect may have happened; the original operation needs reconcile.
    UnknownOutcome,
    /// Admission or the provider boundary refused the operation.
    Refused,
}

/// Result carrier bound to one unchanged retained identity. `result_body`
/// contains exact owner-observed bytes for bridge projection; refs are
/// locators, never proof by themselves. `owner_receipt_ref` is forwarded only
/// when the actual owner supplies one, never synthesized here.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerRetainedOperationOutcome {
    /// The exact dispatch identity this result belongs to.
    pub identity: NativeWorkerRetainedOperationIdentity,
    /// Observed provider/process disposition.
    pub kind: NativeWorkerRetainedOutcomeKind,
    /// Exact bounded body bytes, when the owner observed a terminal result.
    pub result_body: Option<Vec<u8>>,
    /// Owner-issued artifact locators, when present.
    pub artifact_refs: Vec<String>,
    /// Evidence locators linked to the same process operation.
    pub evidence_refs: Vec<String>,
    /// Digest of the exact body bytes returned for bridge projection.
    pub result_digest: Option<String>,
    /// Digest of the exact serialized ProcessEvidence used for this outcome.
    pub process_evidence_digest: Option<String>,
    /// Receipt reference supplied by the canonical owner, when available.
    pub owner_receipt_ref: Option<String>,
}

impl fmt::Debug for NativeWorkerRetainedOperationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWorkerRetainedOperationOutcome")
            .field("identity", &"[retained operation identity]")
            .field("kind", &self.kind)
            .field(
                "result_body",
                &self
                    .result_body
                    .as_ref()
                    .map(|body| format!("[redacted {} bytes]", body.len())),
            )
            .field("artifact_ref_count", &self.artifact_refs.len())
            .field("evidence_ref_count", &self.evidence_refs.len())
            .field("result_digest", &self.result_digest)
            .field("process_evidence_digest", &self.process_evidence_digest)
            .field("owner_receipt_ref_present", &self.owner_receipt_ref.is_some())
            .finish()
    }
}

impl NativeWorkerRetainedOperationOutcome {
    /// Validates bounds, same-operation identity, and any body commitment.
    pub fn validate(&self) -> Result<(), WorkerError> {
        self.identity.validate()?;
        if self.artifact_refs.len() > 128 || self.evidence_refs.len() > 128 {
            return Err(WorkerError::InvalidRequest("retained.result_refs"));
        }
        for reference in self
            .artifact_refs
            .iter()
            .chain(self.evidence_refs.iter())
            .chain(self.owner_receipt_ref.iter())
        {
            validate_identity_text(reference, "retained.result_ref")?;
        }
        if let Some(body) = self.result_body.as_ref() {
            if body.len() > MAX_RETAINED_RESULT_BYTES {
                return Err(WorkerError::InvalidRequest("retained.result_body"));
            }
        }
        match (self.result_body.as_ref(), self.result_digest.as_deref()) {
            (Some(body), Some(digest)) if is_lowercase_sha256(digest) => {
                if sha256_hex(body) != digest {
                    return Err(WorkerError::AdmissionMismatch("retained.result_digest"));
                }
            }
            (None, None) => {}
            (Some(_), _) => return Err(WorkerError::InvalidRequest("retained.evidence_digest")),
            (None, Some(_)) => return Err(WorkerError::InvalidRequest("retained.result_body")),
        }
        if self
            .process_evidence_digest
            .as_deref()
            .is_some_and(|digest| !is_lowercase_sha256(digest))
        {
            return Err(WorkerError::InvalidRequest("retained.process_evidence_digest"));
        }
        if matches!(
            self.kind,
            NativeWorkerRetainedOutcomeKind::CandidateReady
                | NativeWorkerRetainedOutcomeKind::CandidatePartial
                | NativeWorkerRetainedOutcomeKind::CandidateFailed
        ) && (self.result_body.is_none()
            || self.result_digest.is_none()
            || self.process_evidence_digest.is_none())
        {
            return Err(WorkerError::InvalidRequest("retained.candidate_body"));
        }
        Ok(())
    }
}

/// Hard bound for bytes carried inline to the bridge result projector.
pub const MAX_RETAINED_RESULT_BYTES: usize = 1_048_576;

fn validate_identity_text(value: &str, field: &'static str) -> Result<(), WorkerError> {
    if value.trim().is_empty()
        || value.chars().any(char::is_control)
        || value.len() > 4_096
    {
        return Err(WorkerError::InvalidRequest(field));
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    fn identity() -> NativeWorkerRetainedOperationIdentity {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid lineage"),
            NonZeroU64::new(7).expect("nonzero epoch"),
        )
        .expect("valid epoch");
        NativeWorkerRetainedOperationIdentity {
            dispatch_id: "dispatch-1".to_owned(),
            task_id: "task-1".to_owned(),
            material_reference: NativeWorkerRetainedProviderMaterialRefV1 {
                claim_id: "claim-1".to_owned(),
                dispatch_operation_id: "operation-dispatch-1".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                binding_digest: "a".repeat(64),
                material_ref: "material:operation-1".to_owned(),
                material_sha256: "e".repeat(64),
            },
            provider_process: NativeWorkerProviderProcessIdentityV1 {
                provider_operation_id: "operation-provider-1".to_owned(),
                provider_process_invocation_digest: "d".repeat(64),
                provider_executable_digest: "c".repeat(64),
                process_ref: "process:provider-1".to_owned(),
            },
            route_class: "claude.agent-sdk.local-sidecar".to_owned(),
            route_ref: "claude.local".to_owned(),
            worker_generation: 3,
            executable_digest: "b".repeat(64),
            expected_result_schema: "claude.candidate/v1".to_owned(),
            deadline_unix_ms: 50_000,
            cancellation_id: "cancel-1".to_owned(),
            state_fence: StateFence::new(epoch.clone(), ResourceGeneration::new(3).expect("generation")),
            authority_epoch: epoch,
        }
    }

    #[test]
    fn retained_identity_accepts_exact_owner_projection_and_bounded_result() {
        let identity = identity();
        identity.validate().expect("valid exact identity");
        let body = b"candidate bytes".to_vec();
        let outcome = NativeWorkerRetainedOperationOutcome {
            identity,
            kind: NativeWorkerRetainedOutcomeKind::CandidateReady,
            result_digest: Some(sha256_hex(&body)),
            process_evidence_digest: Some("c".repeat(64)),
            result_body: Some(body),
            artifact_refs: vec!["artifact:claude-output".to_owned()],
            evidence_refs: vec!["evidence:process-stream".to_owned()],
            owner_receipt_ref: Some("receipt:owner-issued".to_owned()),
        };
        outcome.validate().expect("valid bound result");
    }

    #[test]
    fn retained_identity_refuses_changed_digest_and_uncommitted_candidate() {
        let mut bad = identity();
        bad.material_reference.binding_digest = "A".repeat(64);
        assert!(bad.validate().is_err());

        let mut outcome = NativeWorkerRetainedOperationOutcome {
            identity: identity(),
            kind: NativeWorkerRetainedOutcomeKind::CandidateReady,
            result_body: Some(b"candidate bytes".to_vec()),
            result_digest: Some("c".repeat(64)),
            artifact_refs: Vec::new(),
            evidence_refs: Vec::new(),
            process_evidence_digest: Some("c".repeat(64)),
            owner_receipt_ref: None,
        };
        assert!(outcome.validate().is_err());
        outcome.kind = NativeWorkerRetainedOutcomeKind::UnknownOutcome;
        outcome.result_digest = None;
        outcome.process_evidence_digest = None;
        assert!(outcome.validate().is_err());
    }
}
