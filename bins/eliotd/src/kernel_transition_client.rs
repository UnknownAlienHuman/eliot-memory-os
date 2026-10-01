//! Neutral authenticated Kernel transition client for the daemon.
//!
//! This module owns only the `KernelTransitionPort` transport adapter: caller
//! metadata, transition/head validation, explicit request identity construction,
//! and exact write-receipt decoding. Store owns canonical persistence and
//! Kernel owns route/fence admission; Governor retains semantic transition
//! planning. Architecture: A2.3, A12.3, A13.2, ARCH-AUTH-01, ARCH-SEC-02.
//! Implementation: I1.8, I2.23, P.3, I14.21, I14.26.
//! Forbidden authority: no Store/provider SDK, canonical ownership, semantic
//! Governor reconstruction, retry/default synthesis, or alternate transport.

use eliot_contracts::{ArtifactId, OperationId, StateFence, TaskId};
use eliot_governor::{
    KernelPortError, KernelPortFuture, KernelTransitionPort, TaskControllerCampaignSourceHeads,
};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignSourceRole, OwnerId, TASK_CONTROLLER_CAMPAIGN_OWNER_ID,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CampaignSourceHead, CampaignSourceReadStatus, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRead, CanonicalRequestView, NamedReadOperation, NamedReadRequest,
    OrderingHeadExpectation, OriginalWriteSubmission, PreparedTransition, PreparedWriteOutcome,
    ReadConsistency, RevisionHeadExpectation, ScopeId, StoreHealth, TaskContractAcceptanceSet,
    WriteReceipt, decode_task_contract_acceptance_set, generated_operation_manifests,
    task_contract_acceptance_read_request, validate_store_receipt_envelope,
    verify_canonical_request_hash,
};
use tracing::Instrument as _;

use super::{kernel_port_error, kind_value};
use crate::daemon_kernel_client::{DaemonKernelClient, KernelClientError, WireOutcome};

struct OwnerSelectionContext<'a> {
    request_identity: (&'a str, &'a str, &'a str, &'a str),
    owner: &'a eliot_governor::TaskSelectionAdmissionBinding,
    observed_scope: &'a eliot_workscope::ObservedScopeResources,
    live_fence: &'a StateFence,
}

/// Checks the admitted identity against the immutable transition before any
/// transport is touched.
///
/// The identity carries the original caller/fence binding plus the admitted
/// idempotency terms and is forwarded unchanged: no deadline/cancellation
/// default is synthesized here. The authenticated daemon transport peer stays
/// distinct from the initiating principal/session, so this check never
/// requires the request source to be the daemon identity and never rewrites
/// it.
fn check_identity_binding(
    identity: &RequestIdentity,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), KernelPortError> {
    check_identity_binding_with_selection(
        identity,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
        None,
    )
}

fn check_identity_binding_with_selection(
    identity: &RequestIdentity,
    transition: &PreparedTransition,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
    task_selection: Option<&OwnerSelectionContext<'_>>,
) -> Result<(), KernelPortError> {
    identity
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    transition
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    // Issue #1929 (I5.5 capture/promotion split): task-free capture remains a
    // cold unbound candidate. Every task-relative transition must arrive on
    // the owner-selection path with the original evidence, independent current
    // WorkScope snapshot, observed Host scope, authenticated request identity,
    // and live fence. Generic callers have no such context and fail closed;
    // selected callers validate it against the immutable prepared operation
    // before any transport. There is no latest-task/open-task/resolver-guess
    // fallback or silent task-relative-to-cold downgrade.
    let admission = super::task_binding_admission::admit_named_mutation_capture(
        &identity.request.metadata,
        transition,
    )
    .map_err(|error| task_binding_kernel_error(&error))?;
    match (&admission, task_selection) {
        (super::task_binding_admission::TaskBindingAdmission::TaskRelative, Some(selection)) => {
            super::task_binding_admission::admit_prepared_transition_with_owner_selection(
                &identity.request.metadata,
                transition,
                selection.request_identity,
                selection.owner,
                selection.observed_scope,
                selection.live_fence,
            )
            .map_err(|error| task_binding_kernel_error(&error))?;
        }
        (super::task_binding_admission::TaskBindingAdmission::TaskRelative, None)
        | (_, Some(_)) => {
            return Err(KernelPortError::TaskSelectionRequired);
        }
        (_, None) => {}
    }
    // Issue #1929: the durable retention of this cold unbound candidate is not
    // this log line. The store admits it as `GateDisposition::ColdUnbound` and
    // its adapter persists one `EvidenceRecord` per `CaptureObservation`
    // regardless of task binding, read back later through `GetEvidencePack`;
    // this is only the operator-visible projection of the admission decision.
    if let super::task_binding_admission::TaskBindingAdmission::ColdUnbound(candidate) = &admission
    {
        tracing::info!(
            candidate_id = %super::diagnostics::sanitize_identity(&candidate.candidate_id),
            "cold unbound observation candidate: durable capture-first bytes retained by the store evidence record, no task activation, support/influence promotion, or finish relevance"
        );
    }
    if transition.state_fence != identity.request.metadata.state_fence {
        return Err(KernelPortError::Contract(
            "daemon transition fence does not match the admitted identity".to_owned(),
        ));
    }
    if transition.identity.idempotency_key != identity.idempotency_key {
        return Err(KernelPortError::Contract(
            "daemon transition idempotency does not match the admitted identity".to_owned(),
        ));
    }
    for head in expected_revision_heads {
        head.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if head.state_fence != identity.request.metadata.state_fence {
            return Err(KernelPortError::Contract(
                "daemon revision head fence does not match the admitted identity".to_owned(),
            ));
        }
    }
    for head in expected_ordering_heads {
        head.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if head.state_fence != identity.request.metadata.state_fence {
            return Err(KernelPortError::Contract(
                "daemon ordering head fence does not match the admitted identity".to_owned(),
            ));
        }
    }
    // 1927: deterministic PreparedTransition admission before transport.
    // Recompute the canonical request hash over the exact executable bytes
    // about to be sent (context + transition + expected heads). A plan whose
    // contents, effect ceiling, scope task binding, named operation
    // parameters, or admission digest changed after staging fails here rather
    // than reaching Kernel/store execution.
    let view = CanonicalRequestView::from_apply(
        &identity.request.metadata,
        transition,
        expected_revision_heads,
        expected_ordering_heads,
    );
    verify_canonical_request_hash(&view, &transition.identity.canonical_request_hash)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    // 1927: the transported plan must be supported by the currently admitted
    // operation catalogue. An unsupported recorded plan is refused here as
    // visible recovery work; it is never reinterpreted or widened for send.
    let entries = generated_operation_manifests()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    transition
        .validate_against_catalogue(&entries)
        .map_err(|error| {
            KernelPortError::Contract(format!(
                "unsupported prepared transition; preserve as recovery, do not reinterpret: {error}"
            ))
        })?;
    Ok(())
}

fn task_binding_kernel_error(
    error: &super::task_binding_admission::TaskBindingError,
) -> KernelPortError {
    match error.code() {
        super::task_binding_admission::TASK_SELECTION_REQUIRED => {
            KernelPortError::TaskSelectionRequired
        }
        super::task_binding_admission::TASK_SCOPE_INCOMPATIBLE => {
            KernelPortError::TaskScopeIncompatible
        }
        _ => KernelPortError::Contract(error.to_string()),
    }
}

async fn read_task_controller_source_head(
    client: &DaemonKernelClient,
    task_id: &TaskId,
    scope_id: &str,
    state_fence: &StateFence,
    role: CampaignSourceRole,
) -> Result<Option<CampaignSourceHead>, KernelPortError> {
    let owner = OwnerId::from_artifact(
        ArtifactId::new(TASK_CONTROLLER_CAMPAIGN_OWNER_ID.to_owned()).map_err(|error| {
            KernelPortError::Contract(format!("invalid Task Controller owner identity: {error}"))
        })?,
    );
    let lookup = CampaignSourceRevisionLookup {
        role,
        owner_id: owner,
        record_id: CampaignOwnerRecordId::Task(task_id.clone()),
        expected_revision: None,
        expected_content_digest: None,
    };
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetCampaignSourceRevision,
        scope_id: Some(ScopeId::new(scope_id.to_owned()).map_err(|error| {
            KernelPortError::Contract(format!("invalid Task Controller source scope: {error}"))
        })?),
        consistency: ReadConsistency::ExactFence,
        state_fence: state_fence.clone(),
        parameters: lookup.named_parameters().map_err(|error| {
            KernelPortError::Contract(format!("invalid Task Controller source lookup: {error}"))
        })?,
    };
    let response = client.store_named_async(request).await?;
    let read =
        CampaignSourceRevisionRead::from_named_read_response(&response).map_err(|error| {
            KernelPortError::Contract(format!("invalid Task Controller source read: {error}"))
        })?;
    if read.read_state_fence != *state_fence {
        return Err(KernelPortError::Contract(
            "Task Controller source read returned a different State Fence".to_owned(),
        ));
    }
    match read.status {
        CampaignSourceReadStatus::Missing => Ok(None),
        CampaignSourceReadStatus::Current | CampaignSourceReadStatus::Stale => {
            let head = read.current_head.ok_or_else(|| {
                KernelPortError::Contract(
                    "Task Controller source read omitted its current head".to_owned(),
                )
            })?;
            if head.role != role
                || head.owner_id != lookup.owner_id
                || head.record_id != lookup.record_id
            {
                return Err(KernelPortError::Contract(
                    "Task Controller source head does not match its exact owner key".to_owned(),
                ));
            }
            Ok(Some(head))
        }
        CampaignSourceReadStatus::Blocked => Err(KernelPortError::Contract(
            "Task Controller source head read was blocked".to_owned(),
        )),
    }
}

impl DaemonKernelClient {
    fn apply_prepared_with_admission_context<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        task_selection: Option<OwnerSelectionContext<'a>>,
        original_write_submission: Option<OriginalWriteSubmission>,
    ) -> KernelPortFuture<'a, PreparedWriteOutcome> {
        let has_original_submission = original_write_submission.is_some();
        let identity = identity.clone();
        let span = tracing::info_span!(
            "eliotd.transition_handoff",
            operation = %super::diagnostics::sanitize_identity(&identity.idempotency_key)
        );
        Box::pin(
            async move {
                check_identity_binding_with_selection(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                    task_selection.as_ref(),
                )?;
                if let Some(source) = &original_write_submission {
                    source
                        .validate()
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                    if transition.transition_class
                        != eliot_store_api::TransitionClass::CaptureCandidate
                        || transition.named_operations.len() != 1
                        || transition.named_operations[0].operation
                            != eliot_store_api::NamedMutationOperation::CaptureObservation
                    {
                        return Err(KernelPortError::Contract(
                            "versioned original write requires one CaptureObservation transition"
                                .to_owned(),
                        ));
                    }
                }
                let _ = super::diagnostics::emit_handoff(
                    super::diagnostics::HandoffKind::Prepared,
                    identity.idempotency_key.as_str(),
                    identity.request.metadata.request_id.as_str(),
                );
                let expected_transition = transition.clone();
                let mut request = serde_json::json!({
                    "context": identity.request.metadata.clone(),
                    "transition": transition,
                    "expected_revision_heads": expected_revision_heads,
                    "expected_ordering_heads": expected_ordering_heads,
                });
                if let Some(source) = original_write_submission {
                    request["original_write_submission"] = serde_json::to_value(source)
                        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                }
                let wire_outcome = self
                    .transact_async_with_identity_outcome(
                        "apply_prepared",
                        request,
                        identity.clone(),
                    )
                    .await
                    .map_err(kernel_port_error)?;
                decode_reserved_apply_outcome(
                    wire_outcome,
                    has_original_submission,
                    &identity,
                    &expected_transition,
                )
            }
            .instrument(span),
        )
    }

    fn apply_prepared_with_owner_selection<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        task_selection: OwnerSelectionContext<'a>,
        original_write_submission: Option<OriginalWriteSubmission>,
    ) -> KernelPortFuture<'a, PreparedWriteOutcome> {
        self.apply_prepared_with_admission_context(
            identity,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            Some(task_selection),
            original_write_submission,
        )
    }
}

fn decode_reserved_apply_outcome(
    outcome: WireOutcome,
    has_original_submission: bool,
    identity: &RequestIdentity,
    transition: &PreparedTransition,
) -> Result<PreparedWriteOutcome, KernelPortError> {
    match outcome {
        WireOutcome::Known { value, recovery } => {
            if recovery.is_some() {
                return Err(KernelPortError::Contract(
                    "known reserved-write response unexpectedly carries recovery".to_owned(),
                ));
            }
            let payload = closed_typed_value(&value, "write_receipt")?;
            let receipt: WriteReceipt = serde_json::from_value(payload)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            validate_store_receipt_envelope(&identity.request.metadata, transition, &receipt)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            let _ = super::diagnostics::emit_handoff(
                super::diagnostics::HandoffKind::Committed,
                identity.idempotency_key.as_str(),
                receipt.operation_id.as_str(),
            );
            Ok(PreparedWriteOutcome::Receipt(Box::new(receipt)))
        }
        WireOutcome::AcceptedPending { value, recovery } => {
            if !has_original_submission || recovery.is_some() {
                return Err(KernelPortError::Contract(
                    "accepted-pending response is not admitted for this exact versioned write"
                        .to_owned(),
                ));
            }
            let payload = closed_typed_value(&value, "write_submission")?;
            let submission: eliot_store_api::WriteSubmission = serde_json::from_value(payload)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            submission
                .validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if submission.state != eliot_store_api::WriteSubmissionState::Staged
                || submission.operation_id != transition.identity.operation_id
                || submission.request_hash != transition.identity.canonical_request_hash
            {
                return Err(KernelPortError::Contract(
                    "staged submission differs from the exact admitted operation and request"
                        .to_owned(),
                ));
            }
            Ok(PreparedWriteOutcome::Staged(Box::new(submission)))
        }
        WireOutcome::Error { code, reason } => Err(kernel_port_error(KernelClientError::Contract(
            format!("{code}: {reason}"),
        ))),
        WireOutcome::Partial { reason, .. } | WireOutcome::Unknown { reason } => {
            Err(kernel_port_error(KernelClientError::Unknown(reason)))
        }
    }
}

fn closed_typed_value(
    value: &serde_json::Value,
    expected_kind: &str,
) -> Result<serde_json::Value, KernelPortError> {
    let object = value.as_object().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed application value is not an object".to_owned())
    })?;
    if object.len() != 2
        || object.get("kind").and_then(serde_json::Value::as_str) != Some(expected_kind)
    {
        return Err(KernelPortError::Contract(format!(
            "Kernel returned an unexpected or open application value; expected closed {expected_kind}"
        )));
    }
    object.get("value").cloned().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed value is missing payload".to_owned())
    })
}

fn require_write_receipt<'a>(
    future: KernelPortFuture<'a, PreparedWriteOutcome>,
) -> KernelPortFuture<'a, WriteReceipt> {
    Box::pin(async move {
        match future.await? {
            PreparedWriteOutcome::Receipt(receipt) => Ok(*receipt),
            PreparedWriteOutcome::Staged(_) => Err(KernelPortError::Contract(
                "legacy prepared-write port received a staged outcome".to_owned(),
            )),
        }
    })
}

impl KernelTransitionPort for DaemonKernelClient {
    fn apply_prepared<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        require_write_receipt(self.apply_prepared_with_admission_context(
            identity,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            None,
            None,
        ))
    }

    fn apply_prepared_with_original_submission<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        original_write_submission: OriginalWriteSubmission,
    ) -> KernelPortFuture<'a, PreparedWriteOutcome> {
        self.apply_prepared_with_admission_context(
            identity,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            None,
            Some(original_write_submission),
        )
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        let state_fence = self.kernel_binding.state_fence.clone();
        // #740: receipt-boundary span over the owning read path
        // (`Send`-safe instrumentation; no entered guard crosses an await).
        let span = tracing::info_span!("eliotd.transition_receipt");
        Box::pin(
            async move {
                let value = self
                    .transact_async(
                        "receipt",
                        serde_json::json!({
                            "operation_id": operation_id.clone(),
                            "state_fence": state_fence.clone(),
                        }),
                    )
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "receipt")?;
                let Some(receipt) = serde_json::from_value::<Option<WriteReceipt>>(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                else {
                    return Ok(None);
                };
                receipt
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if receipt.operation_id != operation_id || receipt.state_fence != state_fence {
                    return Err(KernelPortError::Contract(
                    "daemon receipt does not match the requested operation and active state fence"
                        .to_owned(),
                ));
                }
                Ok(Some(receipt))
            }
            .instrument(span),
        )
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        // #740: health-boundary span over the owning read path
        // (`Send`-safe instrumentation; no entered guard crosses an await).
        let span = tracing::info_span!("eliotd.transition_health");
        Box::pin(
            async move {
                let value = self
                    .transact_async("health", serde_json::json!({}))
                    .await
                    .map_err(kernel_port_error)?;
                let value = kind_value(&value, "health")?;
                serde_json::from_value(value)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))
            }
            .instrument(span),
        )
    }

    fn campaign_source_heads(
        &self,
        task_id: &TaskId,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> KernelPortFuture<'_, TaskControllerCampaignSourceHeads> {
        let task_id = task_id.clone();
        let scope_id = scope_id.to_owned();
        let state_fence = state_fence.clone();
        Box::pin(async move {
            let objective = read_task_controller_source_head(
                self,
                &task_id,
                &scope_id,
                &state_fence,
                CampaignSourceRole::TaskObjective,
            )
            .await?;
            let plan = read_task_controller_source_head(
                self,
                &task_id,
                &scope_id,
                &state_fence,
                CampaignSourceRole::TaskPlan,
            )
            .await?;
            let acceptance = read_task_controller_source_head(
                self,
                &task_id,
                &scope_id,
                &state_fence,
                CampaignSourceRole::TaskAcceptance,
            )
            .await?;
            let open_items = read_task_controller_source_head(
                self,
                &task_id,
                &scope_id,
                &state_fence,
                CampaignSourceRole::TaskOpenItems,
            )
            .await?;
            Ok(TaskControllerCampaignSourceHeads {
                objective,
                plan,
                acceptance,
                open_items,
            })
        })
    }

    /// Reads the contract owner's exact `TaskContract` acceptance-item set for
    /// one task at one task revision (issue #1741, I7.9).
    ///
    /// Same transport template as every other neutral read on this client: the
    /// request is built and validated by the neutral API, travels as the single
    /// `"store_named"` operation over the authenticated Kernel route, and the
    /// typed response is decoded by the neutral API's closed decoder. This adds
    /// no second read path and no raw query surface; Kernel remains the route
    /// and fence authority and the store remains the only owner of the durable
    /// enumeration.
    ///
    /// The exact task id, task revision and fence are forwarded unchanged. A
    /// response that substitutes the task, the revision, or the fence is
    /// refused here as well as in the neutral decoder, so no implementor can
    /// widen the denominator the finish gate is computed over.
    fn task_contract_acceptance_set(
        &self,
        task_id: &TaskId,
        task_revision: u64,
        state_fence: &StateFence,
    ) -> KernelPortFuture<'_, TaskContractAcceptanceSet> {
        let task_id = task_id.clone();
        let state_fence = state_fence.clone();
        Box::pin(async move {
            let request =
                task_contract_acceptance_read_request(&task_id, task_revision, &state_fence)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            let response = self.store_named_async(request).await?;
            let set = decode_task_contract_acceptance_set(&response)
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if set.task_id.as_str() != task_id.as_str()
                || set.task_revision != task_revision
                || set.read_state_fence != state_fence
            {
                return Err(KernelPortError::Contract(
                    "daemon acceptance-set read does not match the requested task, revision, and active state fence"
                        .to_owned(),
                ));
            }
            Ok(set)
        })
    }
}

/// Reusable exact-owner admission port for any production ingress that carries
/// owner-issued task selection evidence and an independent Host observation.
/// The wrapped transport remains the same authenticated daemon client; only
/// the pre-transport gate receives the retained selection bundle.
pub struct OwnerSelectionKernelPort<'a> {
    kernel: &'a DaemonKernelClient,
    request_identity: (&'a str, &'a str, &'a str, &'a str),
    owner: &'a eliot_governor::TaskSelectionAdmissionBinding,
    observed_scope: &'a eliot_workscope::ObservedScopeResources,
    live_fence: &'a StateFence,
}

impl<'a> OwnerSelectionKernelPort<'a> {
    pub fn new(
        kernel: &'a DaemonKernelClient,
        request_identity: (&'a str, &'a str, &'a str, &'a str),
        owner: &'a eliot_governor::TaskSelectionAdmissionBinding,
        observed_scope: &'a eliot_workscope::ObservedScopeResources,
        live_fence: &'a StateFence,
    ) -> Self {
        Self {
            kernel,
            request_identity,
            owner,
            observed_scope,
            live_fence,
        }
    }
}

impl KernelTransitionPort for OwnerSelectionKernelPort<'_> {
    fn apply_prepared<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> KernelPortFuture<'a, WriteReceipt> {
        let task_selection = OwnerSelectionContext {
            request_identity: self.request_identity,
            owner: self.owner,
            observed_scope: self.observed_scope,
            live_fence: self.live_fence,
        };
        require_write_receipt(self.kernel.apply_prepared_with_owner_selection(
            identity,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            task_selection,
            None,
        ))
    }

    fn apply_prepared_with_original_submission<'a>(
        &'a self,
        identity: &RequestIdentity,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        original_write_submission: OriginalWriteSubmission,
    ) -> KernelPortFuture<'a, PreparedWriteOutcome> {
        let task_selection = OwnerSelectionContext {
            request_identity: self.request_identity,
            owner: self.owner,
            observed_scope: self.observed_scope,
            live_fence: self.live_fence,
        };
        self.kernel.apply_prepared_with_owner_selection(
            identity,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            task_selection,
            Some(original_write_submission),
        )
    }

    fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
        self.kernel.receipt(operation_id)
    }

    fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
        self.kernel.health()
    }

    fn campaign_source_heads(
        &self,
        task_id: &TaskId,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> KernelPortFuture<'_, TaskControllerCampaignSourceHeads> {
        self.kernel
            .campaign_source_heads(task_id, scope_id, state_fence)
    }

    fn task_contract_acceptance_set(
        &self,
        task_id: &TaskId,
        task_revision: u64,
        state_fence: &StateFence,
    ) -> KernelPortFuture<'_, TaskContractAcceptanceSet> {
        self.kernel
            .task_contract_acceptance_set(task_id, task_revision, state_fence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId, StateFence,
    };
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        CanonicalRequestView, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
        NamedMutationRequest, OperationIdentity, OperationManifestDigest, OrderingScopeId, ScopeId,
        SecurityContext, TransitionClass, canonical_request_hash, generated_operation_manifests,
        operation_manifest_set_digest,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence(generation: u64) -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(generation).expect("resource generation"),
        )
    }

    fn identity(fence: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-daemon-1").expect("request id"),
            session_id: Some(SessionId::new("session-daemon-1").expect("session id")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product id"),
            source_id: SourceId::new("agent-bridge").expect("source id"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-daemon-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-daemon-1".to_owned(),
        }
    }

    fn transition(fence: &StateFence) -> PreparedTransition {
        let entries = generated_operation_manifests().expect("catalogue");
        let set_digest = operation_manifest_set_digest(&entries).expect("set digest");
        let mut transition = PreparedTransition {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            identity: OperationIdentity {
                operation_id: OperationId::new("op-daemon-1").expect("operation id"),
                idempotency_key: "idem-daemon-1".to_owned(),
                canonical_request_hash: "c".repeat(64),
            },
            state_fence: fence.clone(),
            scope_id: ScopeId::new("governor").expect("scope"),
            task_id: None,
            ordering_scopes: vec![OrderingScopeId::new("scope:governor").expect("ordering scope")],
            transition_class: TransitionClass::CaptureCandidate,
            requested_effect_ceiling: EffectClass::Candidate,
            admission_contract_set_digest: "a".repeat(64),
            operation_manifest_digest: set_digest,
            // Issue-#18 digests are derived below via `bind_issue18_digests`,
            // never defaulted; this fixture leg binds no semantic source (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![NamedMutationRequest {
                operation: NamedMutationOperation::CaptureObservation,
                parameters: BTreeMap::from([(
                    "subject".to_owned(),
                    serde_json::json!("observation-daemon-1"),
                )]),
            }],
            event_projection_relation_intents: EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        eliot_store_api::bind_issue18_digests(&mut transition).expect("issue-18 digests bind");
        transition
    }

    fn ordering_head(fence: &StateFence) -> OrderingHeadExpectation {
        OrderingHeadExpectation {
            scope: OrderingScopeId::new("scope:governor").expect("ordering scope"),
            expected_sequence: 1,
            state_fence: fence.clone(),
        }
    }

    #[test]
    fn transition_identity_binding_is_exact_before_transport() {
        let fence = test_fence(1);
        let identity = identity(&fence);
        let mut transition = transition(&fence);
        // Bind the deterministic admission digest over the exact executable
        // bytes used below (1927): the transported hash must equal the
        // recomputed canonical request hash, or admission fails closed.
        let heads = vec![ordering_head(&fence)];
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&identity.request.metadata, &transition, &[], &heads),
        )
        .expect("admission hash");
        // Exact admitted terms pass with the initiating source preserved:
        // the adapter never rewrites it to the daemon transport peer.
        check_identity_binding(&identity, &transition, &[], &heads).expect("exact binding");
        assert_eq!(identity.request.metadata.source_id.as_str(), "agent-bridge");
        // A substituted fence binding fails closed before any transport,
        // even though the substituted identity is internally consistent.
        let other = test_fence(2);
        let mut substituted = identity.clone();
        substituted.request.metadata.state_fence = other.clone();
        substituted.request.state_fence = other.clone();
        assert!(matches!(
            check_identity_binding(&substituted, &transition, &[], &[]),
            Err(KernelPortError::Contract(_))
        ));
        // A substituted idempotency key fails the same way.
        let mut rekeyed = identity.clone();
        rekeyed.idempotency_key = "idem-substituted".to_owned();
        assert!(matches!(
            check_identity_binding(&rekeyed, &transition, &[], &[]),
            Err(KernelPortError::Contract(_))
        ));
        // A head bound to another fence fails as well.
        assert!(matches!(
            check_identity_binding(&identity, &transition, &[], &[ordering_head(&other)]),
            Err(KernelPortError::Contract(_))
        ));
    }

    #[test]
    fn prepared_admission_rejects_tampered_and_unsupported_plans() {
        // 1927 acceptance: changing the plan contents, effect ceiling, named
        // operation parameters, or admission digest after staging causes
        // rejection rather than execution; an unsupported recorded plan is
        // visible as recovery work and is not reinterpreted.
        let fence = test_fence(1);
        let identity = identity(&fence);
        let mut transition = transition(&fence);
        let heads = vec![ordering_head(&fence)];
        transition.identity.canonical_request_hash = canonical_request_hash(
            &CanonicalRequestView::from_apply(&identity.request.metadata, &transition, &[], &heads),
        )
        .expect("admission hash");
        check_identity_binding(&identity, &transition, &[], &heads).expect("admitted plan");
        // Widened effect ceiling after staging is rejected.
        let mut widened = transition.clone();
        widened.requested_effect_ceiling = EffectClass::ReversibleMutation;
        assert!(matches!(
            check_identity_binding(&identity, &widened, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Mutated named-operation parameters after staging are rejected.
        let mut reparam = transition.clone();
        reparam.named_operations[0].parameters.insert(
            "subject".to_owned(),
            serde_json::json!("observation-substituted"),
        );
        assert!(matches!(
            check_identity_binding(&identity, &reparam, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Mutated admission digest after staging is rejected.
        let mut redigest = transition.clone();
        redigest.admission_contract_set_digest = "d".repeat(64);
        assert!(matches!(
            check_identity_binding(&identity, &redigest, &[], &heads),
            Err(KernelPortError::Contract(_))
        ));
        // Unsupported operation manifest is refused as visible recovery work.
        let mut unsupported = transition.clone();
        unsupported.operation_manifest_digest =
            OperationManifestDigest::new("f".repeat(64)).expect("digest shape");
        unsupported.identity.canonical_request_hash =
            canonical_request_hash(&CanonicalRequestView::from_apply(
                &identity.request.metadata,
                &unsupported,
                &[],
                &heads,
            ))
            .expect("recomputed hash");
        let error = match check_identity_binding(&identity, &unsupported, &[], &heads) {
            Err(error) => error,
            Ok(()) => unreachable!("unsupported manifest must fail"),
        };
        assert!(
            matches!(error, KernelPortError::Contract(ref detail) if detail.contains("recovery")),
            "unsupported plan must name recovery, got: {error:?}"
        );
    }
}
