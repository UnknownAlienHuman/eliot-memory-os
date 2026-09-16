//! Governor Dreamer orientation intake join (T12-06, integration #702, semantic #18).
//!
//! Architecture: A2.3 (contract → ports → adapters layering); A10.4 delegation (one bounded
//! causal join); A0.3 hard boundaries stay fail-closed. Implementation: T12-06 Governor T1.8
//! plus concrete source/result handoff.
//!
//! [`GovernorDreamerAdapter::submit_orientation`] joins an admitted Orientation intake to the
//! existing Governor admission gate and the K0/K1/K2/Store queue: readiness plus fence binding
//! first, then the read-only material freeze/resolution from
//! [`crate::dreamer_materials`], then exactly one queue submission through the [`DreamerJobQueue`]
//! port, then the `QUEUED` response binding. Every failure fails closed before any queue
//! admission or model work, and this helper never mints a permit: pending T1.8 is implemented in
//! its owning turn, so without a genuinely admitted input (ready Governor, exact fence, matching
//! source digests) nothing queues.
//!
//! The typed `eliot-dreamer-orientation::AdmittedOrientationJob` import stays out of this slice
//! (GAP-1: the Orientation leaf is not workspace-admitted; the controller turn owns that
//! admission). The intake shape here ([`OrientationSubmitInput`]) uses only admitted leaves and
//! types: the K0 submit contract plus the local material claims.

use std::sync::Arc;

use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
use eliot_governor::{CompositionError, CompositionReadiness, KernelPortError};
use eliot_protocol::dreamer_job::{
    DurableJobRequest, DurableJobResponse, JobOperation, JobRole, JobState, JobSubmission,
};
use eliot_read::{LocalReadPort, ReadService};
use eliot_store_api::ScopeId;

use super::dreamer_materials::{
    AdmittedSourceClaim, DreamerMaterialsError, OrientationMaterialBudget,
    freeze_orientation_manifest, resolve_source_claim,
};
use super::{DaemonComposition, DaemonKernelClient, SERVICE_NAME, kernel_port_error};
use crate::kernel_context_read_client::KernelContextReadClient;

/// Closed wire identity of the K2 Dreamer job route.
///
/// Must equal `bins/eliot-kernel/src/dreamer_job_dispatch.rs::DREAMER_JOB_WIRE_ID`; the kernel
/// owns that string. The pin test below guards accidental local drift; a kernel-side change
/// belongs to the K2 owner, never to a silent local edit.
pub const DREAMER_JOB_WIRE_ID: &str = "eliot.kernel.dreamer-job";

/// One Orientation intake for Governor-routed queue submission.
///
/// `request` is the complete K0 submit contract (caller-supplied admission rides inside the
/// submission and is validated as shape only — a presented `AdmissionRef` never grants rights;
/// the actual gate is Governor readiness plus the fence/material joins below). `scope`,
/// `materials`, and `budget` drive the independent read-only verification.
#[derive(Clone, Debug)]
pub struct OrientationSubmitInput {
    /// Closed K0 submit request with the requester role.
    pub request: DurableJobRequest,
    /// Scope the materials were admitted for; must equal the submission work scope.
    pub scope: ScopeId,
    /// Admitted source claims resolved and digest-checked before queueing.
    pub materials: Vec<AdmittedSourceClaim>,
    /// Independent intake bounds enforced in addition to admission budgets.
    pub budget: OrientationMaterialBudget,
}

/// Queue port behind the orientation intake.
///
/// Production binds the K2 route ([`KernelDreamerJobQueue`]: exactly one submission per admitted
/// intake). Tests bind a recording responder owned by the test: the port never routes, so a test
/// double can only answer an already-admitted intake, never admit one itself.
///
/// The method desugars to a lifetime-bound `impl Future` (rather than `async fn`) so no
/// `async_fn_in_trait` lint is introduced.
pub trait DreamerJobQueue {
    /// Submits one admitted K0 request under the fenced store context.
    fn submit(
        &self,
        context: RequestMetadata,
        request: DurableJobRequest,
    ) -> impl Future<Output = Result<DurableJobResponse, CompositionError>>;
}

/// Production [`DreamerJobQueue`] over the authenticated Kernel K2 route.
///
/// Mirrors the `store_named_async` transport template: the validated request travels as the
/// closed `eliot.kernel.dreamer-job` operation with the fenced store context, and the typed
/// response is bound to the request with `validate_for` before return.
pub struct KernelDreamerJobQueue<'a> {
    kernel: &'a DaemonKernelClient,
}

impl<'a> KernelDreamerJobQueue<'a> {
    /// Borrows the already-connected authenticated Kernel client. No new session, no thread.
    #[must_use]
    pub const fn new(kernel: &'a DaemonKernelClient) -> Self {
        Self { kernel }
    }
}

impl DreamerJobQueue for KernelDreamerJobQueue<'_> {
    async fn submit(
        &self,
        context: RequestMetadata,
        request: DurableJobRequest,
    ) -> Result<DurableJobResponse, CompositionError> {
        request
            .validate()
            .map_err(|error| owner_error(format!("dreamer queue request: {error}")))?;
        context
            .validate()
            .map_err(|error| owner_error(format!("dreamer queue context: {error}")))?;
        if context.state_fence != request.request_identity.operation.state_fence {
            return Err(owner_error(
                "dreamer queue context fence does not match the request fence",
            ));
        }
        let value = self
            .kernel
            .transact_async(
                DREAMER_JOB_WIRE_ID,
                serde_json::json!({"context": context, "request": request}),
            )
            .await
            .map_err(kernel_port_error)
            .map_err(CompositionError::Kernel)?;
        let response: DurableJobResponse = serde_json::from_value(value).map_err(|error| {
            CompositionError::Kernel(KernelPortError::Contract(error.to_string()))
        })?;
        response
            .validate_for(&request)
            .map_err(|error| owner_error(format!("dreamer queue response: {error}")))?;
        Ok(response)
    }
}

/// Thin Governor Dreamer intake adapter over the retained daemon owners.
///
/// Holds only borrows (composition plus the already-connected Kernel client), retains no client
/// and no thread, and changes no lifecycle: callers take a fresh adapter per operation through
/// [`DaemonComposition::dreamer_admission`], so a Governor refresh surfaces as an exact fence
/// mismatch instead of silent divergence.
pub struct GovernorDreamerAdapter<'a> {
    composition: &'a DaemonComposition,
    kernel: &'a Arc<DaemonKernelClient>,
}

impl<'a> GovernorDreamerAdapter<'a> {
    /// Borrows the retained composition and the caller-held Kernel client.
    #[must_use]
    pub const fn new(
        composition: &'a DaemonComposition,
        kernel: &'a Arc<DaemonKernelClient>,
    ) -> Self {
        Self {
            composition,
            kernel,
        }
    }

    /// Builds the fence-bound read context for the admitted snapshot.
    ///
    /// Pure registration check with no I/O: validates the admitted fence and the derived
    /// request metadata. Used once at attach time by the daemon runtime and on every intake.
    pub fn dreamer_route_context(&self) -> Result<RequestMetadata, CompositionError> {
        let admitted = self.composition.kernel_snapshot().state_fence();
        admitted
            .validate()
            .map_err(|error| owner_error(format!("dreamer admitted fence: {error}")))?;
        dreamer_read_context(&admitted)
    }

    /// Submits one genuinely admitted Orientation intake and returns its durable `QUEUED`
    /// identity.
    ///
    /// Order is load-bearing: Governor readiness, K0 request admission, fence/scope joins,
    /// material freeze, live read-only resolution with digest checks, exactly one queue
    /// submission, then the `QUEUED` response binding. Any earlier failure returns before the
    /// queue is touched, and no model edge exists on this path at all.
    pub async fn submit_orientation(
        &self,
        input: &OrientationSubmitInput,
        queue: &impl DreamerJobQueue,
    ) -> Result<DurableJobResponse, CompositionError> {
        let admitted = self.composition.kernel_snapshot().state_fence();
        let readiness = self.composition.readiness();
        let ctx = self.dreamer_route_context()?;
        if ctx.state_fence != admitted {
            return Err(owner_error(
                "dreamer route context does not match the admitted snapshot",
            ));
        }
        let service = ReadService::new(KernelContextReadClient::new(Arc::clone(self.kernel)));
        submit_admitted_orientation(readiness, &admitted, &service, &ctx, input, queue).await
    }
}

/// Builds the fence-bound read metadata for orientation material resolution.
pub(crate) fn dreamer_read_context(
    admitted_fence: &StateFence,
) -> Result<RequestMetadata, CompositionError> {
    let context = RequestMetadata {
        request_id: RequestId::new("eliotd:dreamer:orientation:materials")
            .map_err(|error| owner_error(format!("dreamer read context: {error}")))?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| owner_error(format!("dreamer read context: {error}")))?,
        source_id: SourceId::new(SERVICE_NAME)
            .map_err(|error| owner_error(format!("dreamer read context: {error}")))?,
        state_fence: admitted_fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context
        .validate()
        .map_err(|error| owner_error(format!("dreamer read context: {error}")))?;
    Ok(context)
}

/// Core intake flow over explicit authority values.
///
/// `readiness` and `admitted_fence` must come from the live composition (see
/// [`GovernorDreamerAdapter::submit_orientation`]); tests supply exact fences directly. The
/// queue is touched only after every read-only gate passes.
pub(crate) async fn submit_admitted_orientation<'a>(
    readiness: CompositionReadiness,
    admitted_fence: &StateFence,
    reads: &'a impl LocalReadPort,
    ctx: &RequestMetadata,
    input: &OrientationSubmitInput,
    queue: &'a impl DreamerJobQueue,
) -> Result<DurableJobResponse, CompositionError> {
    if readiness != CompositionReadiness::Ready {
        return Err(CompositionError::NotReady);
    }
    let submission = admit_orientation_request(&input.request, admitted_fence)?;
    if ctx.state_fence != *admitted_fence {
        return Err(owner_error(
            "dreamer read context does not match the admitted fence",
        ));
    }
    if input.scope.as_str() != submission.work_scope.scope_id.as_str() {
        return Err(owner_error(
            "dreamer intake scope does not match the submission work scope",
        ));
    }
    let manifest = freeze_orientation_manifest(
        input.scope.as_str(),
        admitted_fence,
        &input.materials,
        &input.budget,
    )
    .map_err(|error| materials_error(&error))?;
    manifest
        .validate()
        .map_err(|error| materials_error(&error))?;
    for claim in &input.materials {
        resolve_source_claim(reads, ctx, &input.scope, claim)
            .await
            .map_err(|error| materials_error(&error))?;
    }
    let response = queue.submit(ctx.clone(), input.request.clone()).await?;
    bind_queued_response(&input.request, response)
}

/// Admits one K0 request for orientation intake: shape-valid `SUBMIT_JOB` with the requester
/// role at the exact admitted fence.
fn admit_orientation_request<'a>(
    request: &'a DurableJobRequest,
    admitted_fence: &StateFence,
) -> Result<&'a JobSubmission, CompositionError> {
    request
        .validate()
        .map_err(|error| owner_error(format!("dreamer orientation request: {error}")))?;
    let JobOperation::Submit { submission } = &request.operation else {
        return Err(owner_error(
            "dreamer orientation intake admits only SUBMIT_JOB",
        ));
    };
    if request.role != JobRole::Requester {
        return Err(owner_error(
            "dreamer orientation intake requires the requester role",
        ));
    }
    if request.request_identity.operation.state_fence != *admitted_fence {
        return Err(owner_error("dreamer orientation request fence is stale"));
    }
    Ok(submission)
}

/// Binds one queue answer to its request and requires the durable `QUEUED` state.
pub(crate) fn bind_queued_response(
    request: &DurableJobRequest,
    response: DurableJobResponse,
) -> Result<DurableJobResponse, CompositionError> {
    response
        .validate_for(request)
        .map_err(|error| owner_error(format!("dreamer queue response: {error}")))?;
    if response.state != JobState::Queued {
        return Err(owner_error(
            "dreamer orientation submit did not reach QUEUED",
        ));
    }
    Ok(response)
}

fn owner_error(reason: impl Into<String>) -> CompositionError {
    CompositionError::Owner(reason.into())
}

fn materials_error(error: &DreamerMaterialsError) -> CompositionError {
    CompositionError::Owner(format!("dreamer orientation materials: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, ContractId, ContractIdentity, ContractVersion, EpochId, EpochLineageId,
        OperationId, ReceiptId, ResourceGeneration, TaskId, WorkLeaseId, canonical_json_bytes,
        sha256_hex,
    };
    use eliot_protocol::dreamer_job::{
        AdmissionRef, DurableRequestIdentity, JobLease, JobOperationKind, MutationDisposition,
        OpaqueContentRef,
    };
    use eliot_read::{
        BranchEnvironmentScope, FreshnessPolicy, ProvenanceDisposition, QueryIntent, QueryMode,
        QueryResult, ReadError, ReadProvenance, RequiredAssurance, StoreReadFailure, TimeScope,
    };
    use eliot_receipts::{
        AuthorityBinding, EffectClass, OperationBinding, ProofCeiling, RequestBinding,
        WorkScopeBinding, WorkScopeId,
    };
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn test_fence_at(sequence: u64) -> TestResult<StateFence> {
        Ok(StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE)?,
                NonZeroU64::new(sequence).ok_or("nonzero test sequence")?,
            )?,
            ResourceGeneration::new(1)?,
        ))
    }

    fn test_context_at(fence: &StateFence) -> TestResult<RequestMetadata> {
        dreamer_read_context(fence).map_err(Into::into)
    }

    fn test_budget() -> OrientationMaterialBudget {
        OrientationMaterialBudget {
            max_sources: 4,
            max_total_bytes: 8 * 1024,
            max_source_bytes: 4 * 1024,
        }
    }

    fn content_ref(tag: &str, bytes_len: u64, digest: &str) -> TestResult<OpaqueContentRef> {
        Ok(OpaqueContentRef {
            contract: ContractIdentity {
                name: ContractId::new(format!("test.{tag}"))?,
                version: ContractVersion::new(1, 0, 0),
                shape_sha256: "a".repeat(64),
            },
            source_revision: format!("rev-{tag}"),
            byte_length: bytes_len,
            sha256: digest.to_owned(),
            artifact_id: Some(ArtifactId::new(format!("artifact-{tag}"))?),
        })
    }

    fn test_submission(fence: &StateFence) -> TestResult<JobSubmission> {
        let epoch = fence.authority_epoch.clone();
        let work_scope = WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-one")?,
            product_id: ProductId::new("eliotd")?,
            resource_generation: fence.resource_generation,
            state_fence: fence.clone(),
        };
        Ok(JobSubmission {
            job_id: TaskId::new("job-1")?,
            attempt_id: ArtifactId::new("attempt-1")?,
            work_scope: work_scope.clone(),
            semantic_input: content_ref("input", 8, &"b".repeat(64))?,
            output_contract: content_ref("output", 8, &"c".repeat(64))?,
            admission: AdmissionRef {
                authority: AuthorityBinding {
                    authority_id: ContractId::new("governor")?,
                    authority_owner: "governor".to_owned(),
                    authority_epoch: epoch.clone(),
                    state_fence: fence.clone(),
                    allowed_effect: EffectClass::Candidate,
                    proof_ceiling: ProofCeiling::CandidateArtifact,
                },
                requester_principal: "requester-1".to_owned(),
                session: None,
                scope: work_scope,
                capability: "dreamer-orient".to_owned(),
                route_class: "local-governed".to_owned(),
                budget_units: 8,
                deadline_unix_ms: 1_000_000,
                validity_epoch: epoch,
                resource_generation: fence.resource_generation,
                admission_receipt: ReceiptId::new("receipt-1")?,
            },
            cancellation_id: "cancel-1".to_owned(),
        })
    }

    fn test_request(
        fence: &StateFence,
        role: JobRole,
        operation: JobOperation,
        operation_kind: &str,
    ) -> TestResult<DurableJobRequest> {
        let metadata = RequestMetadata {
            request_id: RequestId::new("eliotd:test:dreamer:submit")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliotd")?,
            source_id: SourceId::new("eliotd")?,
            state_fence: fence.clone(),
            clock: ClockReading {
                valid_time_ms: None,
                known_time_ms: None,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        };
        let identity = eliot_protocol::RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-1".to_owned(),
            deadline_unix_ms: 1_000_000,
            cancellation_id: "cancel-1".to_owned(),
        };
        let operation_binding = OperationBinding {
            operation_id: OperationId::new("op-1")?,
            request_id: identity.request.metadata.request_id.clone(),
            idempotency_key: "idem-1".to_owned(),
            operation_kind: operation_kind.to_owned(),
            effect: EffectClass::Candidate,
            state_fence: fence.clone(),
        };
        let canonical_request_hash =
            DurableRequestIdentity::digest_for(&operation_binding, &identity, &operation, role)?;
        Ok(DurableJobRequest {
            request_identity: DurableRequestIdentity {
                request: identity,
                operation: operation_binding,
                canonical_request_hash,
            },
            role,
            operation,
        })
    }

    fn submit_input(
        fence: &StateFence,
        payloads: &[(&str, serde_json::Value)],
    ) -> TestResult<(OrientationSubmitInput, BTreeMap<String, serde_json::Value>)> {
        let submission = test_submission(fence)?;
        let operation = JobOperation::Submit {
            submission: Box::new(submission),
        };
        let request = test_request(
            fence,
            JobRole::Requester,
            operation,
            JobOperationKind::Submit.as_str(),
        )?;
        request.validate()?;
        let mut stored = BTreeMap::new();
        let mut materials = Vec::new();
        for (handle, payload) in payloads {
            let bytes = canonical_json_bytes(payload)?;
            stored.insert((*handle).to_owned(), (*payload).clone());
            materials.push(AdmittedSourceClaim {
                source_handle: (*handle).to_owned(),
                expected_digest: sha256_hex(&bytes),
                expected_byte_length: u64::try_from(bytes.len()).map_err(|_| "test bytes")?,
                privacy_class: "governed-internal".to_owned(),
                route_class: "local-governed".to_owned(),
            });
        }
        Ok((
            OrientationSubmitInput {
                request,
                scope: ScopeId::new("scope-one")?,
                materials,
                budget: test_budget(),
            },
            stored,
        ))
    }

    /// Test-only read port answering from caller-held payloads. Payloads are derived from the
    /// held map on every call and call counts are observable; a double can only answer an
    /// already-shaped query, never admit one itself.
    struct AnsweringReads {
        fence: StateFence,
        payloads: BTreeMap<String, serde_json::Value>,
        calls: Mutex<u32>,
    }

    impl LocalReadPort for AnsweringReads {
        async fn evidence_query(
            &self,
            ctx: &RequestMetadata,
            _scope: ScopeId,
            subject: String,
            max_records: u32,
        ) -> Result<QueryResult, ReadError> {
            if let Ok(mut calls) = self.calls.lock() {
                *calls += 1;
            }
            if max_records == 0 || subject.trim().is_empty() {
                return Err(ReadError::InvalidField {
                    field: "test query".to_owned(),
                    reason: "test double requires a subject and bound".to_owned(),
                });
            }
            if ctx.state_fence != self.fence {
                return Err(ReadError::ResponseMismatch);
            }
            let payload = self
                .payloads
                .get(&subject)
                .cloned()
                .ok_or_else(|| ReadError::Store(StoreReadFailure::Unavailable))?;
            Ok(QueryResult {
                intent: QueryIntent {
                    mode: QueryMode::Verification,
                    time_scope: TimeScope::EvidenceWindow,
                    branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
                    freshness_policy: FreshnessPolicy::ExactCapturedRecords,
                    required_assurance: RequiredAssurance::VerifierEvidence,
                },
                operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
                state_fence: self.fence.clone(),
                revision_heads: Vec::new(),
                payload,
                provenance: ReadProvenance {
                    handles: Vec::new(),
                    disposition: ProvenanceDisposition::Unavailable,
                },
                consistency: eliot_store_api::ReadConsistency::Eventual,
            })
        }

        async fn projection_inputs(
            &self,
            _ctx: &RequestMetadata,
            _scope: ScopeId,
            _packet_ref: Option<String>,
            _material_refs: Vec<String>,
        ) -> Result<QueryResult, ReadError> {
            Err(ReadError::Store(
                eliot_store_api::StoreError::Unavailable.into(),
            ))
        }
    }

    /// Test-only queue port recording every call. The responder builds answers from the
    /// presented request through the real K0 validators, never from canned receipts.
    struct RecordingQueue {
        calls: Mutex<u32>,
        seen_is_submit: Mutex<Vec<bool>>,
        respond: fn(&DurableJobRequest) -> TestResult<DurableJobResponse>,
    }

    impl DreamerJobQueue for RecordingQueue {
        async fn submit(
            &self,
            context: RequestMetadata,
            request: DurableJobRequest,
        ) -> Result<DurableJobResponse, CompositionError> {
            if let Ok(mut calls) = self.calls.lock() {
                *calls += 1;
            }
            if let Ok(mut seen) = self.seen_is_submit.lock() {
                seen.push(matches!(request.operation, JobOperation::Submit { .. }));
            }
            context
                .validate()
                .map_err(|error| CompositionError::Owner(error.to_string()))?;
            (self.respond)(&request).map_err(|error| CompositionError::Owner(error.to_string()))
        }
    }

    fn queued_response(request: &DurableJobRequest) -> TestResult<DurableJobResponse> {
        let JobOperation::Submit { submission } = &request.operation else {
            return Err("test queue answers submits only".into());
        };
        Ok(DurableJobResponse {
            request_identity: request.request_identity.clone(),
            job_id: submission.job_id.clone(),
            attempt_id: submission.attempt_id.clone(),
            scope: submission.work_scope.clone(),
            revision: 1,
            state: JobState::Queued,
            disposition: Some(MutationDisposition::Committed),
            receipt_id: Some(ReceiptId::new("receipt-queue-1")?),
            lease: None,
            checkpoint: None,
            result_under_verification: None,
            outcome: None,
            selection_coverage: Vec::new(),
            selection_frontier: None,
        })
    }

    fn test_lease_id() -> TestResult<WorkLeaseId> {
        serde_json::from_value(serde_json::json!({
            "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
            "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
            "value": "lease-1",
        }))
        .map_err(Into::into)
    }

    fn leased_response(request: &DurableJobRequest) -> TestResult<DurableJobResponse> {
        let JobOperation::Submit { submission } = &request.operation else {
            return Err("test queue answers submits only".into());
        };
        let fence = submission.work_scope.state_fence.clone();
        Ok(DurableJobResponse {
            request_identity: request.request_identity.clone(),
            job_id: submission.job_id.clone(),
            attempt_id: submission.attempt_id.clone(),
            scope: submission.work_scope.clone(),
            revision: 1,
            state: JobState::Leased,
            disposition: Some(MutationDisposition::Committed),
            receipt_id: Some(ReceiptId::new("receipt-queue-1")?),
            lease: Some(JobLease {
                job_id: submission.job_id.clone(),
                attempt_id: submission.attempt_id.clone(),
                lease_id: test_lease_id()?,
                owner_artifact_id: ArtifactId::new("owner-1")?,
                resource_generation: fence.resource_generation,
                state_fence: fence,
                issued_at_unix_ms: 100,
                expires_at_unix_ms: 200,
                revision: 1,
            }),
            checkpoint: None,
            result_under_verification: None,
            outcome: None,
            selection_coverage: Vec::new(),
            selection_frontier: None,
        })
    }

    fn queue_calls(queue: &RecordingQueue) -> TestResult<u32> {
        queue
            .calls
            .lock()
            .map(|calls| *calls)
            .map_err(|_| "test queue lock".into())
    }

    fn read_calls(reads: &AnsweringReads) -> TestResult<u32> {
        reads
            .calls
            .lock()
            .map(|calls| *calls)
            .map_err(|_| "test reads lock".into())
    }

    fn harness(
        fence: &StateFence,
        respond: fn(&DurableJobRequest) -> TestResult<DurableJobResponse>,
    ) -> TestResult<(RequestMetadata, AnsweringReads, RecordingQueue)> {
        Ok((
            test_context_at(fence)?,
            AnsweringReads {
                fence: fence.clone(),
                payloads: BTreeMap::new(),
                calls: Mutex::new(0),
            },
            RecordingQueue {
                calls: Mutex::new(0),
                seen_is_submit: Mutex::new(Vec::new()),
                respond,
            },
        ))
    }

    async fn run_intake(
        readiness: CompositionReadiness,
        admitted: &StateFence,
        reads: &AnsweringReads,
        ctx: &RequestMetadata,
        input: &OrientationSubmitInput,
        queue: &RecordingQueue,
    ) -> Result<DurableJobResponse, CompositionError> {
        submit_admitted_orientation(readiness, admitted, reads, ctx, input, queue).await
    }

    #[tokio::test]
    async fn unready_governor_queues_nothing() -> TestResult {
        let fence = test_fence_at(1)?;
        let (input, _) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": []}))],
        )?;
        let (ctx, reads, queue) = harness(&fence, queued_response)?;
        let error = run_intake(
            CompositionReadiness::Constructing,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string());
        assert_eq!(error, Err("Governor is not ready".to_owned()));
        assert_eq!(queue_calls(&queue)?, 0);
        assert_eq!(read_calls(&reads)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn stale_fence_queues_nothing() -> TestResult {
        let admitted = test_fence_at(1)?;
        let stale = test_fence_at(2)?;
        let (input, stored) = submit_input(
            &stale,
            &[("evidence-a", serde_json::json!({"records": []}))],
        )?;
        let (ctx, mut reads, queue) = harness(&admitted, queued_response)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &admitted,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(queue_calls(&queue)?, 0);
        assert_eq!(read_calls(&reads)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn unadmitted_source_digest_queues_nothing() -> TestResult {
        let fence = test_fence_at(1)?;
        let payload = serde_json::json!({"records": [{"capture_index": 0}]});
        let (mut input, stored) = submit_input(&fence, &[("evidence-a", payload)])?;
        let mut altered = canonical_json_bytes(&stored["evidence-a"])?;
        if let Some(first) = altered.first_mut() {
            *first ^= 0x01;
        }
        input.materials[0].expected_digest = sha256_hex(&altered);
        let (ctx, mut reads, queue) = harness(&fence, queued_response)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(read_calls(&reads)?, 1);
        assert_eq!(queue_calls(&queue)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn worker_role_submit_queues_nothing() -> TestResult {
        let fence = test_fence_at(1)?;
        let submission = test_submission(&fence)?;
        let operation = JobOperation::Submit {
            submission: Box::new(submission),
        };
        let request = test_request(
            &fence,
            JobRole::Worker,
            operation,
            JobOperationKind::Submit.as_str(),
        )?;
        let (mut input, stored) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": []}))],
        )?;
        input.request = request;
        let (ctx, mut reads, queue) = harness(&fence, queued_response)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(queue_calls(&queue)?, 0);
        assert_eq!(read_calls(&reads)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn non_submit_operation_queues_nothing() -> TestResult {
        let fence = test_fence_at(1)?;
        let submission = test_submission(&fence)?;
        let operation = JobOperation::Status {
            job_id: submission.job_id.clone(),
            attempt_id: submission.attempt_id.clone(),
            expected_revision: 1,
            expected_fence: fence.clone(),
        };
        let request = test_request(
            &fence,
            JobRole::Requester,
            operation,
            JobOperationKind::Status.as_str(),
        )?;
        request.validate()?;
        let (mut input, stored) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": []}))],
        )?;
        input.request = request;
        let (ctx, mut reads, queue) = harness(&fence, queued_response)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(queue_calls(&queue)?, 0);
        assert_eq!(read_calls(&reads)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn admitted_intake_queues_once_and_binds_queued() -> TestResult {
        let fence = test_fence_at(1)?;
        let (input, stored) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": [1]}))],
        )?;
        let (ctx, mut reads, queue) = harness(&fence, queued_response)?;
        reads.payloads = stored;
        let response = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await
        .map_err(|error| error.to_string())?;
        assert_eq!(response.state, JobState::Queued);
        assert_eq!(response.job_id.as_str(), "job-1");
        response.validate_for(&input.request)?;
        assert_eq!(queue_calls(&queue)?, 1);
        let seen = queue.seen_is_submit.lock().map_err(|_| "test queue lock")?;
        assert_eq!(*seen, vec![true]);
        Ok(())
    }

    #[tokio::test]
    async fn foreign_queue_answer_is_rejected() -> TestResult {
        fn foreign(request: &DurableJobRequest) -> TestResult<DurableJobResponse> {
            let mut response = queued_response(request)?;
            response.job_id = TaskId::new("job-other")?;
            Ok(response)
        }
        let fence = test_fence_at(1)?;
        let (input, stored) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": [1]}))],
        )?;
        let (ctx, mut reads, queue) = harness(&fence, foreign)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(queue_calls(&queue)?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn non_queued_queue_answer_is_rejected() -> TestResult {
        let fence = test_fence_at(1)?;
        let (input, stored) = submit_input(
            &fence,
            &[("evidence-a", serde_json::json!({"records": [1]}))],
        )?;
        let (ctx, mut reads, queue) = harness(&fence, leased_response)?;
        reads.payloads = stored;
        let outcome = run_intake(
            CompositionReadiness::Ready,
            &fence,
            &reads,
            &ctx,
            &input,
            &queue,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(queue_calls(&queue)?, 1);
        Ok(())
    }

    #[test]
    fn wire_identity_pins_the_k2_route() {
        assert_eq!(DREAMER_JOB_WIRE_ID, "eliot.kernel.dreamer-job");
    }

    #[test]
    fn route_context_binds_the_admitted_fence() -> TestResult {
        let fence = test_fence_at(1)?;
        let ctx = dreamer_read_context(&fence)?;
        assert_eq!(ctx.state_fence, fence);
        ctx.validate()?;
        Ok(())
    }
}
