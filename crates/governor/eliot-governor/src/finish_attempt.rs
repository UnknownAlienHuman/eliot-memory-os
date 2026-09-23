//! Governor-owned production FinishAttempt path.
//!
//! The adapter owns the boundary between the public candidate draft and the
//! rebuildable [`eliot_finish::FinishService`].  It reads the current task and
//! canonical finish-evidence owner at one fence, evaluates a scratch service,
//! persists the complete receipt projection through the existing canonical
//! transition path, and never treats a worker/provider result as task finish.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::{
    AcceptanceCoverage, CanonicalWriteEnvelope, FinishAttemptDraft, FinishEvidence,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex, OperationId, StateFence, TaskId};
use eliot_coordination::CoordinationOwner;
use eliot_finish::{
    FinishAdmission, FinishAttempt, FinishClosureIntent, FinishContext, FinishDecisionReceipt,
    FinishError, FinishService, TaskLifecycleState,
};
use eliot_instrument_api::EvidenceFreshness;
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    generated_operation_manifests, operation_manifest_set_digest, EffectClass,
    EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationManifestDigest, ScopeId, SecurityContext, StoreFailure, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
};
use eliot_observation::{
    ObservationAdmissionResult, ObservationJournal, ObservationPlanBinding,
};
use eliot_task::{TaskCommand, TaskLifecycleOwner, TaskRecord, TaskState};
use eliot_testd_core::TestdStore;
use thiserror::Error;

use crate::{
    CanonicalAdmissionOwner, CanonicalAdmissionSnapshot, CanonicalFinishEvidence,
    CanonicalPlanBinding, CanonicalVerifierExecutionFact, CompositionError, GovernorOwners,
    KernelPortError, KernelTransitionPort, evaluate_testd_verification_current,
};

const GOVERNOR_SCOPE_ID: &str = "governor";

/// Typed failure at the production finish boundary.
#[derive(Debug, Error)]
pub enum FinishAttemptError {
    /// The strict finish service rejected the candidate or rehydrated state.
    #[error("finish owner rejected the attempt: {0}")]
    Finish(#[from] FinishError),
    /// The canonical owner or composition rejected the operation.
    #[error("finish composition rejected the attempt: {0}")]
    Composition(#[from] CompositionError),
    /// The neutral Kernel transition could not establish an outcome.
    #[error("finish Kernel transition failed: {0}")]
    Kernel(#[from] KernelPortError),
    /// The canonical receipt was not a committed finish mutation.
    #[error("finish mutation was not committed: {0}")]
    Store(String),
    /// Canonical bytes or the production manifest could not be built.
    #[error("finish transition serialization failed: {0}")]
    Serialization(String),
}

impl FinishAttemptError {
    /// Returns a typed Store failure when a caller needs the existing failure
    /// projection. Finish owner rejection and transport gaps have no Store
    /// mutation and therefore return `None`.
    #[must_use]
    pub const fn store_failure(&self) -> Option<&StoreFailure> {
        None
    }
}

/// Governor adapter over the single task, canonical, and finish owners.
pub struct GovernorFinishAttempt<'a, P: ?Sized> {
    task: &'a TaskLifecycleOwner,
    canonical: &'a CanonicalAdmissionOwner,
    coordination: &'a CoordinationOwner,
    observation: &'a ObservationJournal,
    finish: &'a FinishService,
    kernel: &'a P,
    finish_owner_revision: u64,
}

impl<'a, P: ?Sized> GovernorFinishAttempt<'a, P> {
    pub(crate) fn new(
        owners: &'a GovernorOwners<P>,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
        finish_owner_revision: u64,
    ) -> Self {
        Self {
            task: &owners.task,
            canonical,
            coordination: &owners.coordination,
            observation: &owners.observation,
            finish: &owners.finish,
            kernel,
            finish_owner_revision,
        }
    }
}

/// Pure output of one canonical finish-evidence derivation. The snapshot is
/// the next owner image; it is committed together with the durable decision.
struct ProducedFinishEvidence {
    canonical: CanonicalFinishEvidence,
    snapshot: CanonicalAdmissionSnapshot,
}

impl<P: ?Sized> GovernorFinishAttempt<'_, P> {
    /// Rehydrates finish evidence from the current owner projections.
    ///
    /// Every handle in the result comes from a same-fence task event,
    /// task-and-plan-bound observation admission, or the coordination owner.
    /// Missing material is retained as an explicit gap where the finish
    /// contract permits it; missing owner identity or acceptance evidence
    /// prevents publication entirely.
    fn produce_finish_evidence(
        &self,
        task_id: &TaskId,
        task: &TaskRecord,
        fence: &StateFence,
        plan: &CanonicalPlanBinding,
    ) -> Result<ProducedFinishEvidence, FinishAttemptError> {
        let mut frame_refs = BTreeSet::new();
        let mut finish_authority_ref = None;
        for event in self.task.events().iter().filter(|event| {
            event.task_id == *task_id && event.state_fence == *fence
        }) {
            let Some(command) = &event.command else {
                continue;
            };
            match command {
                TaskCommand::Frame { frame_ref } => {
                    frame_refs.insert(frame_ref.clone());
                }
                TaskCommand::AuthorizeAction { authority_ref, .. } => {
                    finish_authority_ref = Some(authority_ref.clone());
                }
                _ => {}
            }
        }
        let finish_authority_ref = finish_authority_ref.ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task has no same-fence action authority for finish".to_owned(),
            ))
        })?;
        if frame_refs.is_empty() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task has no same-fence acceptance frame".to_owned(),
            )));
        }

        // Verifier authority comes only from the canonical owner fact
        // produced from the current durable TestD row. Task commands and
        // observation epistemic labels are requests/projections; neither is
        // an executed verifier outcome.
        let verifier_fact = self
            .canonical
            .read_verifier_execution_fact(fence)
            .map_err(FinishAttemptError::Composition)?;
        if verifier_fact.task_id != task_id.as_str()
            || verifier_fact.task_revision != task.revision
            || verifier_fact.plan != *plan
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier execution fact is stale for the current task/plan".to_owned(),
            )));
        }
        let verifier_run_ref = verifier_fact.verification_run.run_id.to_string();
        // This fact has already been rehydrated and validated against the
        // current task, plan, fence, and durable terminal TestD receipt. A
        // failed or partial verifier is still an executed run; its outcome is
        // represented per required test below, not mislabeled as stale.

        let coordination = self
            .coordination
            .finish_projection(task_id.as_str(), fence)
            .map_err(|error| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "coordination finish projection failed: {error}"
                )))
            })?;
        if coordination.state_fence != *fence || coordination.task_id != task_id.as_str() {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "coordination finish projection has a stale task fence".to_owned(),
            )));
        }

        let has_accepted_task_observation = self.observation.snapshot().iter().any(|entry| {
            let ObservationAdmissionResult::Accepted { receipt } = &entry.result else {
                return false;
            };
            receipt.state_fence == *fence
                && receipt.task_selection.as_ref().is_some_and(|selection| {
                    selection.task_ref == task_id.as_str()
                        && selection.task_revision == task.revision
                })
                && matches_plan(receipt.plan.as_ref(), plan, fence)
        });
        if !has_accepted_task_observation {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence has no accepted task-and-plan-bound observation"
                    .to_owned(),
            )));
        }

        let verifier_plan = plan.verifier.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish plan has no verifier item bindings".to_owned(),
            ))
        })?;
        let run_is_current = matches!(
            verifier_fact.verification_run.freshness,
            EvidenceFreshness::ExactCandidate
                | EvidenceFreshness::ExactCommit
                | EvidenceFreshness::ExactQuiescedWorktree
        );
        let stale_verifier_run_refs = if run_is_current {
            Vec::new()
        } else {
            vec![verifier_run_ref.clone()]
        };
        let mut acceptance = Vec::with_capacity(verifier_plan.required_test_ids.len());
        for item_id in &verifier_plan.required_test_ids {
            let item_events = verifier_fact
                .verification_run
                .evidence
                .iter()
                .filter(|event| {
                    event
                        .value
                        .get("nextest_test_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(item_id.as_str())
                })
                .collect::<Vec<_>>();
            let mut item_evidence_refs = BTreeSet::new();
            for event in &item_events {
                item_evidence_refs.insert(event.evidence_id.to_string());
                item_evidence_refs.insert(event.raw_artifact_id.to_string());
                if let Some(handles) = event
                    .value
                    .get("raw_artifact_handles")
                    .and_then(serde_json::Value::as_array)
                {
                    item_evidence_refs.extend(
                        handles.iter().filter_map(serde_json::Value::as_str).map(str::to_owned),
                    );
                }
            }
            if item_events.is_empty() {
                // A missing required event is still an explicit unsatisfied
                // item. Bind the complete raw run artifact set inspected for
                // it so the canonical validator can retain that negative
                // coverage without borrowing another item's event evidence.
                item_evidence_refs.extend(
                    verifier_fact
                        .verification_run
                        .raw_evidence
                        .iter()
                        .map(ToString::to_string),
                );
            }
            let item_passed = run_is_current
                && !item_events.is_empty()
                && item_events.iter().all(|event| {
                    event
                        .value
                        .get("nextest_status")
                        .and_then(serde_json::Value::as_str)
                        == Some("PASS")
                });
            let item_verifier_refs = if item_events.is_empty() {
                Vec::new()
            } else {
                vec![verifier_run_ref.clone()]
            };
            acceptance.push(AcceptanceCoverage {
                item_id: item_id.clone(),
                satisfied: item_passed,
                evidence_refs: item_evidence_refs.into_iter().collect(),
                verifier_run_refs: item_verifier_refs,
                requires_verifier: true,
            });
        }
        let mut artifact_refs = coordination.artifact_refs.clone();
        artifact_refs.sort();
        artifact_refs.dedup();
        let mut unresolved_effect_refs = coordination.unresolved_refs.clone();
        unresolved_effect_refs.sort();
        unresolved_effect_refs.dedup();
        let descendant_closure = if let Some(receipt_ref) = coordination.descendant_receipt_ref {
            eliot_finish::DescendantClosure::Complete { receipt_ref }
        } else {
            eliot_finish::DescendantClosure::Incomplete {
                unresolved_refs: unresolved_effect_refs.clone(),
            }
        };
        let evidence = FinishEvidence {
            task_id: task_id.as_str().to_owned(),
            current_task_revision: task.revision,
            artifact_refs,
            acceptance,
            executed_verifier_run_refs: vec![verifier_run_ref],
            stale_verifier_run_refs,
            unresolved_effect_refs,
        };
        evidence
            .validate()
            .map_err(|error| FinishAttemptError::Finish(FinishError::from(error)))?;
        let canonical = CanonicalFinishEvidence {
            state_fence: fence.clone(),
            evidence,
            descendant_closure,
            finish_authority_ref: finish_authority_ref.clone(),
            // Action authorization permits the governed task action; it is
            // not a separate owner disposition to close partial/cancelled
            // work. Leave closure authority absent until its owner receipt is
            // joined explicitly.
            closure_authority_ref: None,
        };
        let snapshot = self.canonical.prepare_finish_evidence(canonical.clone())?;
        Ok(ProducedFinishEvidence { canonical, snapshot })
    }
}

fn matches_plan(
    observed: Option<&ObservationPlanBinding>,
    plan: &CanonicalPlanBinding,
    fence: &StateFence,
) -> bool {
    observed.is_some_and(|observed| {
        observed.plan_id == plan.plan_id
            && observed.plan_revision == plan.plan_revision
            && observed.state_fence == *fence
    })
}

impl<P: KernelTransitionPort + ?Sized> GovernorFinishAttempt<'_, P> {
    /// Rehydrates and publishes the verifier-execution owner from the
    /// current durable TestD row. `job_id` is the only TestD input crossing
    /// this boundary: the row, receipt, run, canonical task, current plan,
    /// and fence are all read and joined here. A caller-held `TestJob` or
    /// verdict cannot become canonical proof.
    pub async fn publish_testd_verifier_execution_fact(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        task_id: &TaskId,
        task_revision: u64,
        job_id: &str,
        testd: &TestdStore,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        validate_identity(identity)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        if identity.request.metadata.task_id.as_ref() != Some(task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "verifier fact request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(task_id).ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "canonical task {} is absent",
                task_id.as_str()
            )))
        })?;
        if task.revision != task_revision || task.state_fence != fence {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task owner is stale for verifier fact publication".to_owned(),
            )));
        }
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != *task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical verifier plan is task-mismatched".to_owned(),
            )));
        }
        let job = testd
            .get(job_id)
            .map_err(|error| FinishAttemptError::Composition(CompositionError::Recovery(format!(
                "TestD owner read failed: {error}"
            ))))?
            .ok_or_else(|| {
                FinishAttemptError::Composition(CompositionError::Recovery(format!(
                    "durable TestD job {job_id} is absent"
                )))
            })?;
        let receipt = job.verification_receipt.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "durable TestD job has no full verification receipt".to_owned(),
            ))
        })?;
        let verifier_plan = plan.verifier.as_ref().ok_or_else(|| {
            FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical plan has no verifier binding".to_owned(),
            ))
        })?;
        let run = evaluate_testd_verification_current(&job, receipt, verifier_plan)?;
        let fact = CanonicalVerifierExecutionFact::from_testd(
            task_id,
            task_revision,
            &plan,
            &fence,
            &job,
            receipt,
            run,
        )?;
        if self
            .canonical
            .read_verifier_execution_fact(&fence)
            .ok()
            .is_some_and(|existing| existing == fact)
        {
            return Ok(None);
        }
        let snapshot = self.canonical.prepare_verifier_execution_fact(fact.clone())?;
        let fact_operation = OperationId::new(format!("{operation_id}/verifier-execution"))
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let fact_identity = RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: format!("{}:verifier-execution", identity.idempotency_key),
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        let envelope = canonical_owner_snapshot_envelope(
            &fact_identity,
            fact_operation.clone(),
            &snapshot,
            task_id.as_str(),
            &fact.verification_run.run_id.to_string(),
        )?;
        let committed = match self
            .canonical
            .commit(self.kernel, &fact_identity, envelope)
            .await
        {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => self
                .kernel
                .receipt(fact_operation.clone())
                .await?
                .ok_or_else(|| {
                    FinishAttemptError::Kernel(KernelPortError::Unknown(
                        "verifier execution fact receipt is unresolved after an unknown commit outcome"
                            .to_owned(),
                    ))
                })?,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(
            &committed,
            &fact_operation,
            &fence,
            &fact_identity.idempotency_key,
        )?;
        Ok(Some(committed))
    }

    /// Produces and commits the next canonical finish-evidence owner image.
    ///
    /// The derived child identity is created by Governor for this owner leg;
    /// it carries the admitted request binding and never accepts proof or
    /// evidence from the public draft.  An identical current owner image is
    /// already materialized and therefore is a readback no-op.
    pub async fn publish_finish_evidence(
        &self,
        identity: &RequestIdentity,
        operation_id: &OperationId,
        draft: &FinishAttemptDraft,
    ) -> Result<Option<WriteReceipt>, FinishAttemptError> {
        validate_identity(identity)?;
        draft.validate().map_err(FinishError::from)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        if identity.request.metadata.task_id.as_ref() != Some(&task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "finish request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        validate_task(task, &fence, expected_revision)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task does not match the current canonical plan".to_owned(),
            )));
        }
        let produced = self.produce_finish_evidence(&task_id, task, &fence, &plan)?;
        if self
            .canonical
            .read_finish_evidence(&fence)
            .ok()
            .is_some_and(|existing| existing == produced.canonical)
        {
            return Ok(None);
        }

        let evidence_operation = OperationId::new(format!("{operation_id}/finish-evidence"))
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        let evidence_idempotency = format!("{}:finish-evidence", identity.idempotency_key);
        let evidence_identity = RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: evidence_idempotency,
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        let envelope = finish_evidence_envelope(
            &evidence_identity,
            evidence_operation.clone(),
            &produced.snapshot,
        )?;
        let committed = match self
            .canonical
            .commit(self.kernel, &evidence_identity, envelope)
            .await
        {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => self
                .kernel
                .receipt(evidence_operation.clone())
                .await?
                .ok_or_else(|| {
                    FinishAttemptError::Kernel(KernelPortError::Unknown(
                        "finish-evidence receipt is unresolved after an unknown commit outcome"
                            .to_owned(),
                    ))
                })?,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(
            &committed,
            &evidence_operation,
            &fence,
            &evidence_identity.idempotency_key,
        )?;
        Ok(Some(committed))
    }

    /// Rehydrates and evaluates one candidate against canonical owner state.
    ///
    /// The attempt identity is the admitted idempotency identity.  Public
    /// callers provide only the draft; closure intent is a fail-closed owner
    /// mapping, and evidence comes exclusively from the canonical owner.
    pub async fn submit(
        &self,
        identity: &RequestIdentity,
        operation_id: OperationId,
        draft: FinishAttemptDraft,
    ) -> Result<FinishDecisionReceipt, FinishAttemptError> {
        validate_identity(identity)?;
        draft.validate().map_err(FinishError::from)?;
        let fence = identity.request.metadata.state_fence.clone();
        if self.canonical.state_fence() != &fence {
            return Err(FinishError::FenceMismatch.into());
        }
        let task_id = TaskId::new(draft.task_id.clone())
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
        if identity.request.metadata.task_id.as_ref() != Some(&task_id) {
            return Err(FinishError::Canonical(
                eliot_canonical::CanonicalError::TaskBindingMismatch,
            )
            .into());
        }
        let expected_revision = fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or_else(|| {
                FinishAttemptError::Serialization(
                    "finish request is missing its task revision fence".to_owned(),
                )
            })?;
        if expected_revision != draft.expected_task_revision {
            return Err(
                FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
            );
        }
        let task = self.task.task(&task_id).ok_or_else(|| {
            FinishAttemptError::Serialization(format!(
                "canonical task {} is absent",
                task_id.as_str()
            ))
        })?;
        validate_task(task, &fence, expected_revision)?;
        let plan = self.canonical.read_current_plan(&fence)?;
        if plan.task_id != task_id {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical task does not match the current canonical plan".to_owned(),
            )));
        }
        let canonical = self.canonical.read_finish_evidence(&fence)?;
        if canonical.evidence.task_id != task_id.as_str()
            || canonical.evidence.current_task_revision != task.revision
        {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "canonical finish evidence is stale for the current task".to_owned(),
            )));
        }
        if self.finish_owner_revision == 0 {
            return Err(FinishAttemptError::Composition(CompositionError::Recovery(
                "finish owner revision is absent; finish persistence is unavailable".to_owned(),
            )));
        }

        let context = FinishContext {
            task_id: task_id.as_str().to_owned(),
            current_task_revision: task.revision,
            current_state_fence: fence.clone(),
            lifecycle: lifecycle_state(task.state),
            finish_authority_ref: canonical.finish_authority_ref,
            closure_authority_ref: canonical.closure_authority_ref,
            descendant_closure: canonical.descendant_closure,
            evidence: canonical.evidence,
        };
        let requested_outcome = draft.requested_outcome;
        let attempt = FinishAttempt {
            attempt_id: identity.idempotency_key.clone(),
            state_fence: fence.clone(),
            draft,
            closure_intent: closure_intent(requested_outcome),
            completion_proof: None,
        };
        let mut scratch = self.finish.clone();
        let admission = scratch.evaluate(attempt.clone(), &context)?;
        let receipt = match admission {
            FinishAdmission::Replayed { receipt } => return Ok(receipt),
            FinishAdmission::Accepted { receipt } => receipt,
        };
        let receipts = scratch.receipts();
        let envelope = finish_envelope(
            identity,
            operation_id.clone(),
            &attempt,
            &context,
            &receipts,
            self.finish_owner_revision,
        )?;
        let committed = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => self
                .kernel
                .receipt(operation_id.clone())
                .await?
                .ok_or_else(|| {
                    FinishAttemptError::Kernel(KernelPortError::Unknown(
                        "finish receipt is unresolved after an unknown commit outcome".to_owned(),
                    ))
                })?,
            Err(error) => return Err(error.into()),
        };
        check_finish_receipt(&committed, &operation_id, &fence, &identity.idempotency_key)?;
        Ok(receipt)
    }
}

fn validate_identity(identity: &RequestIdentity) -> Result<(), FinishAttemptError> {
    identity
        .validate()
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    if identity.request.state_fence != identity.request.metadata.state_fence {
        return Err(FinishError::FenceMismatch.into());
    }
    Ok(())
}

fn validate_task(
    task: &TaskRecord,
    fence: &StateFence,
    expected_revision: u64,
) -> Result<(), FinishAttemptError> {
    if task.state_fence != *fence {
        return Err(FinishError::FenceMismatch.into());
    }
    if task.revision != expected_revision || task.revision == 0 {
        return Err(
            FinishError::Canonical(eliot_canonical::CanonicalError::StaleTaskRevision).into(),
        );
    }
    Ok(())
}

fn lifecycle_state(state: TaskState) -> TaskLifecycleState {
    match state {
        TaskState::Proposed => TaskLifecycleState::Proposed,
        TaskState::Open => TaskLifecycleState::Open,
        TaskState::Framed => TaskLifecycleState::Framed,
        TaskState::Verifying => TaskLifecycleState::Verifying,
        TaskState::Blocked => TaskLifecycleState::Blocked,
        TaskState::UnderstandingRequired | TaskState::ActionAuthorized | TaskState::Executing => {
            TaskLifecycleState::Active
        }
        TaskState::DoneVerified | TaskState::Failed | TaskState::Partial => {
            TaskLifecycleState::Closing
        }
    }
}

fn closure_intent(outcome: eliot_canonical::RequestedFinishOutcome) -> FinishClosureIntent {
    match outcome {
        eliot_canonical::RequestedFinishOutcome::Cancelled => FinishClosureIntent::Cancel,
        eliot_canonical::RequestedFinishOutcome::Superseded => FinishClosureIntent::Supersede,
        _ => FinishClosureIntent::Continue,
    }
}

fn production_manifest_digest() -> Result<OperationManifestDigest, FinishAttemptError> {
    operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?,
    )
    .map_err(|error| FinishAttemptError::Serialization(error.to_string()))
}

fn canonical_owner_snapshot_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
    task_id: &str,
    required_proof_ref: &str,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let snapshot_bytes = canonical_json_bytes(snapshot)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let snapshot_json = String::from_utf8(snapshot_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let expected_canonical_revision = snapshot
        .owner_revision
        .checked_sub(1)
        .ok_or_else(|| {
            FinishAttemptError::Serialization(
                "canonical owner snapshot has no CAS predecessor".to_owned(),
            )
        })?;
    if task_id.trim().is_empty() || required_proof_ref.trim().is_empty() {
        return Err(FinishAttemptError::Serialization(
            "canonical owner snapshot has an empty task/proof binding".to_owned(),
        ));
    }
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_canonical_revision".to_owned(),
        serde_json::Value::String(expected_canonical_revision.to_string()),
    );
    parameters.insert(
        "snapshot_json".to_owned(),
        serde_json::Value::String(snapshot_json),
    );
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: Some(task_id.to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: sha256_hex(&snapshot_bytes),
        operation_manifest_digest: production_manifest_digest()?,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordFinishEvidence,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![required_proof_ref.to_owned()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

fn finish_evidence_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    snapshot: &CanonicalAdmissionSnapshot,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let evidence = snapshot.finish_evidence.as_ref().ok_or_else(|| {
        FinishAttemptError::Serialization(
            "finish-evidence envelope cannot publish an absent evidence owner".to_owned(),
        )
    })?;
    canonical_owner_snapshot_envelope(
        identity,
        operation_id,
        snapshot,
        &evidence.evidence.task_id,
        &evidence.finish_authority_ref,
    )
}

fn finish_envelope(
    identity: &RequestIdentity,
    operation_id: OperationId,
    attempt: &FinishAttempt,
    context: &FinishContext,
    receipts: &[FinishDecisionReceipt],
    expected_finish_revision: u64,
) -> Result<CanonicalWriteEnvelope, FinishAttemptError> {
    let receipt_bytes = canonical_json_bytes(&receipts)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let receipt_json = String::from_utf8(receipt_bytes.clone())
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let contract_bytes = canonical_json_bytes(&(attempt, context, receipts))
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "attempt_id".to_owned(),
        serde_json::Value::String(attempt.attempt_id.clone()),
    );
    parameters.insert(
        "expected_finish_revision".to_owned(),
        serde_json::Value::String(expected_finish_revision.to_string()),
    );
    parameters.insert(
        "receipt_json".to_owned(),
        serde_json::Value::String(receipt_json),
    );
    let scope_id = ScopeId::new(GOVERNOR_SCOPE_ID)
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: Some(context.task_id.clone()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: sha256_hex(&contract_bytes),
        operation_manifest_digest: production_manifest_digest()?,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordFinishDecision,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![context.finish_authority_ref.clone()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    })
}

fn check_finish_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    fence: &StateFence,
    idempotency_key: &str,
) -> Result<(), FinishAttemptError> {
    receipt
        .validate()
        .map_err(|error| FinishAttemptError::Serialization(error.to_string()))?;
    if receipt.operation_id != *operation_id
        || receipt.state_fence != *fence
        || receipt.idempotency_key != idempotency_key
    {
        return Err(FinishAttemptError::Store(
            "committed receipt does not bind the finish identity".to_owned(),
        ));
    }
    if receipt.transition_class != TransitionClass::RecoverySchema {
        return Err(FinishAttemptError::Store(
            "finish receipt has the wrong transition class".to_owned(),
        ));
    }
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(FinishAttemptError::Store(format!(
            "finish receipt status is {:?}",
            receipt.status
        )));
    }
    Ok(())
}
