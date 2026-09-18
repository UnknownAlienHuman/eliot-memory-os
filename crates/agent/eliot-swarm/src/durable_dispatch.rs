//! A-07 durable-job attachment and admitted child-dispatch lineage.
//!
//! This module is an in-crate composition helper: it validates one admitted
//! plan and delegates the attach-once decision to a Governor canonical owner
//! supplied by the caller, then derives every child dispatch identity from
//! that job, the admitted plan revision, the child slot, and the State Fence.
//! It consumes owner evidence (Governor receipts) and the admitted route grant
//! through the existing ports; it constructs no provider clients, owns no
//! second job/task/session/authority record, and performs no process launch.
//!
//! This module is NOT the production swarm-consumption attachment path: no
//! production Governor-vended attachment-owner port exists yet, and no swarm
//! production caller is wired to this helper as the authoritative consumption
//! path. Singularity here holds only within the single owner instance the
//! caller supplies. The production Governor port/store/composition work is
//! tracked as follow-up issue #2017.
//!
//! The cell stays stateless: an attachment is an inert validated value, and a
//! dispatched launch still requires the owner-side persist-before-launch path
//! ([`super::durable_work::DurableWorkStore`] append, then
//! [`super::durable_work::WorkExecutor`] launch). Unknown outcomes stay
//! unknown here; only an exact-digest replay is idempotent.

use eliot_agent_api::WorkLeaseId;
use eliot_agent_contracts::{AgentAttemptId, RevisionId, WorkItem, WorkItemId};
use eliot_coordination::{SwarmPlanAttachmentError, SwarmPlanAttachmentLedger};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AdmittedSwarmPlan, ProviderBinding, ProviderRequest, ReceiptEnvelope, ReceiptVerificationPort,
    SwarmError, digest,
    durable_work::{LaunchIntent, RouteGrant, WorkUnitId},
    validate_receipt, validate_text,
};

/// Operation kind sealed by the Governor attachment receipt.
pub const JOB_ATTACH_OPERATION: &str = "swarm.job.attach";
/// Durable-job record owner. Only this owner may attach a plan to a job.
pub const JOB_OWNER: &str = "Governor";

/// One admitted plan bound to one durable job through a caller-supplied owner.
///
/// The job handle is opaque owner lineage: this cell never parses, mints, or
/// reassigns it. Attach-once within the supplied owner instance is decided by
/// the Governor canonical decision inside [`attach_plan_job`]; the Governor
/// receipt pins the exact binding. This value carries no wider singularity
/// claim: two independently constructed owners can each hold a different
/// binding for the same plan revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJobAttachment {
    job_handle: String,
    plan_revision: RevisionId,
    state_fence_digest: String,
    attachment_receipt_digest: String,
    attachment_receipt: ReceiptEnvelope,
}

impl DurableJobAttachment {
    /// Opaque Governor-owned job handle this plan is attached to.
    #[must_use]
    pub fn job_handle(&self) -> &str {
        &self.job_handle
    }

    /// Admitted plan revision the attachment was sealed against.
    #[must_use]
    pub fn plan_revision(&self) -> &RevisionId {
        &self.plan_revision
    }

    /// State Fence digest pinned by the attachment receipt.
    #[must_use]
    pub fn state_fence_digest(&self) -> &str {
        &self.state_fence_digest
    }

    /// Canonical digest of the Governor attachment receipt.
    #[must_use]
    pub fn attachment_receipt_digest(&self) -> &str {
        &self.attachment_receipt_digest
    }

    /// Governor attachment receipt that sealed this binding.
    #[must_use]
    pub fn attachment_receipt(&self) -> &ReceiptEnvelope {
        &self.attachment_receipt
    }
}

/// Exact dispatch lineage of one child: parent job, plan revision, child
/// slot, fence, and admitted route/adapter-class evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchLineage {
    pub job_handle: String,
    pub plan_revision: RevisionId,
    pub child_slot: WorkItemId,
    pub state_fence_digest: String,
    pub route_id: String,
    pub route_fingerprint: String,
    pub route_generation: u64,
    pub route_class: String,
    pub route_evidence_digest: String,
    pub launch_digest: String,
}

/// One child launch with its durable-job dispatch lineage.
///
/// The embedded [`LaunchIntent`] travels the existing owner-side
/// persist-before-launch path unchanged; the lineage proves which admitted
/// job/plan/slot/route produced it and blocks same-identity payload drift via
/// [`verify_exact_replay`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchedLaunch {
    pub intent: LaunchIntent,
    pub lineage: DispatchLineage,
}

/// Exact-replay verdict for a candidate intent against a prior dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayVerdict {
    /// Same child identity and same payload digest: safe to re-observe.
    Idempotent,
    /// Different child identity: not a replay of the prior dispatch.
    ForeignIdentity,
}

/// Validates one admitted plan and delegates attach-once to a caller-supplied
/// Governor canonical owner.
///
/// This helper is crate-private and is NOT the production swarm-consumption
/// attachment path. It performs validation plus attach-once delegation only
/// against the owner instance the caller supplies: the canonical
/// [`SwarmPlanAttachmentLedger::attach_plan_once`] decision runs BEFORE the
/// attachment value is constructed, so two calls for the same plan revision
/// with different job handles cannot both succeed against the same owner. An
/// unbound key records and returns the exact binding; an identically bound key
/// replays idempotently; a key bound to a different job or fence digest is
/// [`SwarmError::OwnershipConflict`], naming the canonical winner.
///
/// No production Governor-vended attachment-owner port exists yet, and no
/// swarm production caller is wired to this helper as the authoritative
/// consumption path; singularity across independently acquired production
/// consumers is therefore out of scope here and is tracked as follow-up
/// issue #2017 (production Governor port/store/composition).
///
/// Fail-closed: a blank handle never attaches, a missing verifier is
/// [`SwarmError::PlanGap`], a non-Governor or plan/fence-mismatched receipt is
/// rejected by the shared receipt validation, and a canon binding that does
/// not echo the requested job/fence is refused as an internal contract
/// violation.
///
/// Durable-binding remainder (BLOCKED on #2017): the ledger above is the
/// Governor-owned in-memory canon for this process. Cross-process and restart
/// durability needs a production `SwarmPlanAttachmentStore` behind
/// `attach_plan_once_durable`; no production store implementation exists yet,
/// and binding the trait to the real Governor canonical-write path is queued
/// remainder in the canon crate
/// (`crates/governor/eliot-coordination/src/swarm_plan_attachment.rs`: store
/// contract plus durable entry point). This function does not fake durability:
/// it enforces attach-once against the Governor owner it is given.
//
// NOTE: no non-test caller exists by design (no production consumption path
// yet; see the module docs and follow-up #2017). The helper is retained as
// the in-crate composition primitive that #2017 will wire to a vended owner
// port, and is exercised by the unit tests below.
#[allow(dead_code)]
pub(crate) fn attach_plan_job(
    plan: &AdmittedSwarmPlan,
    owner: &SwarmPlanAttachmentLedger,
    job_handle: &str,
    attachment_receipt: ReceiptEnvelope,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<DurableJobAttachment, SwarmError> {
    validate_text(job_handle, "job_handle")?;
    let binding: &ProviderBinding = plan.provider_binding();
    let fence_digest = binding.state_fence_digest.as_str();
    let canon = owner
        .attach_plan_once(
            plan.admission_receipt().identity.canonical_sha256.as_str(),
            plan.revision().as_str(),
            job_handle,
            fence_digest,
        )
        .map_err(|error| match error {
            SwarmPlanAttachmentError::OwnershipConflict { .. } => SwarmError::OwnershipConflict,
            SwarmPlanAttachmentError::InvalidSnapshot => SwarmError::InvalidSnapshot,
            SwarmPlanAttachmentError::Serialization => SwarmError::Serialization,
            // Unreachable through this path: the handle is validated above and
            // the remaining identities come from the admitted plan, so a canon
            // input refusal is an internal contract violation.
            SwarmPlanAttachmentError::InvalidField(_) => SwarmError::Contract,
        })?;
    // The canon echoes the requested tuple on success; refuse anything else
    // rather than sealing a binding the owner did not decide.
    if canon.job_handle() != job_handle || canon.fence_digest() != fence_digest {
        return Err(SwarmError::Contract);
    }
    let request = ProviderRequest {
        operation_kind: JOB_ATTACH_OPERATION.to_owned(),
        artifact_digest: digest(&(
            job_handle,
            plan.revision().as_str(),
            binding.state_fence_digest.as_str(),
        ))?,
        binding: binding.clone(),
        replay: None,
    };
    validate_receipt(&attachment_receipt, verifier, JOB_OWNER, &request)?;
    Ok(DurableJobAttachment {
        job_handle: job_handle.to_owned(),
        plan_revision: plan.revision().clone(),
        state_fence_digest: binding.state_fence_digest.clone(),
        attachment_receipt_digest: attachment_receipt.identity.canonical_sha256.clone(),
        attachment_receipt,
    })
}

/// Defense-in-depth re-check for one job per plan revision.
///
/// Enforcement lives in the Governor canonical attach-once decision consulted
/// by [`attach_plan_job`] against the caller-supplied owner; this helper only
/// re-compares two already-built attachment values for callers that still hold
/// a prior value (for example, to notice a stale in-memory copy). It cannot
/// see Governor state, so passing `None` or omitting the call never
/// establishes singularity on its own.
/// Re-attaching the same handle is idempotent; a different handle for the
/// same plan revision is [`SwarmError::OwnershipConflict`]. Attachments for
/// other plan revisions are out of scope for this check and pass through.
pub fn assert_single_attachment(
    existing: Option<&DurableJobAttachment>,
    candidate: &DurableJobAttachment,
) -> Result<(), SwarmError> {
    let Some(prior) = existing else {
        return Ok(());
    };
    if prior.plan_revision != candidate.plan_revision {
        return Ok(());
    }
    if prior.job_handle == candidate.job_handle {
        return Ok(());
    }
    Err(SwarmError::OwnershipConflict)
}

/// Derives one child dispatch from the job attachment, plan item, and
/// admitted route grant.
///
/// The child operation/attempt identity is derived from
/// `(job_handle, plan_revision, child_slot)`; the State Fence, route
/// fingerprint/generation/evidence, and lease bind the admitted execution
/// envelope. A stale grant blocks launch with no local fallback.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_child(
    attachment: &DurableJobAttachment,
    item: &WorkItem,
    work_id: &WorkUnitId,
    grant: &RouteGrant,
    route_class: &str,
    lease: WorkLeaseId,
    term: u64,
    epoch: u64,
) -> Result<DispatchedLaunch, SwarmError> {
    if item.plan_revision != *attachment.plan_revision() {
        return Err(SwarmError::StaleLineage);
    }
    if grant.stale {
        return Err(SwarmError::RouteBlocked);
    }
    validate_text(&grant.route_id, "route_id")?;
    validate_text(&grant.fingerprint, "route_fingerprint")?;
    validate_text(&grant.evidence_digest, "route_evidence_digest")?;
    validate_text(route_class, "route_class")?;
    let operation_id = format!(
        "{}:{}:{}",
        attachment.job_handle(),
        attachment.plan_revision().as_str(),
        item.work_item_id.as_str()
    );
    validate_text(&operation_id, "operation_id")?;
    let attempt_id =
        AgentAttemptId::new(format!("{operation_id}-attempt")).map_err(|_| SwarmError::Contract)?;
    let intent = LaunchIntent {
        operation_id,
        attempt_id,
        work_id: work_id.clone(),
        route_id: grant.route_id.clone(),
        route_fingerprint: grant.fingerprint.clone(),
        lease,
        term,
        epoch,
        fence_digest: attachment.state_fence_digest().to_owned(),
    };
    let lineage = DispatchLineage {
        job_handle: attachment.job_handle().to_owned(),
        plan_revision: attachment.plan_revision().clone(),
        child_slot: item.work_item_id.clone(),
        state_fence_digest: attachment.state_fence_digest().to_owned(),
        route_id: grant.route_id.clone(),
        route_fingerprint: grant.fingerprint.clone(),
        route_generation: grant.generation,
        route_class: route_class.to_owned(),
        route_evidence_digest: grant.evidence_digest.clone(),
        launch_digest: digest(&intent)?,
    };
    Ok(DispatchedLaunch { intent, lineage })
}

/// Verifies an exact replay of a prior dispatch.
///
/// Same child identity with the same payload digest is idempotent; same
/// identity with a changed payload is [`SwarmError::PayloadConflict`]
/// (changed input requires a new identity and explicit parent revision, never
/// a silent relaunch). A different identity is
/// [`ReplayVerdict::ForeignIdentity`].
pub fn verify_exact_replay(
    prior: &DispatchedLaunch,
    candidate: &LaunchIntent,
) -> Result<ReplayVerdict, SwarmError> {
    let same_identity = prior.intent.operation_id == candidate.operation_id
        && prior.intent.attempt_id == candidate.attempt_id
        && prior.intent.work_id == candidate.work_id;
    if !same_identity {
        return Ok(ReplayVerdict::ForeignIdentity);
    }
    if digest(candidate)? == prior.lineage.launch_digest {
        return Ok(ReplayVerdict::Idempotent);
    }
    Err(SwarmError::PayloadConflict)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;

    use eliot_agent_contracts::WorkItemState;
    use eliot_coordination::SwarmPlanAttachmentLedger;
    use eliot_receipts::{ReceiptCore, WorkScopeBinding};
    use serde_json::{Value, json};

    use super::super::{
        AgentRouteProvider, BranchId, IndependentMapSubmission, LaneId, ProviderAttestation,
        ProviderBinding, ProviderError, ProviderOutcome, RequiredProvider, RootContextRevision,
        SealedIndependentMaps, SwarmPlanProposal, admit_plan, collect_independent_maps, digest,
        plan_admission_request,
    };
    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn fence() -> Value {
        json!({
            "authority_epoch": epoch(),
            "resource_generation": 1,
            "task_revision": 1,
            "policy_revision": null,
            "integration_revision": null
        })
    }

    fn epoch() -> Value {
        json!({"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1})
    }

    fn work_scope() -> Result<WorkScopeBinding, serde_json::Error> {
        serde_json::from_value(json!({
            "scope_id": "scope-1",
            "product_id": "product-1",
            "resource_generation": 1,
            "state_fence": fence()
        }))
    }

    fn evidence() -> Result<super::super::EvidenceEnvelope, serde_json::Error> {
        serde_json::from_value(json!({
            "authority": "DETERMINISTIC_RUNTIME_TEST",
            "freshness": "EXACT_CANDIDATE",
            "coverage": "COMPLETE_FOR_SCOPE",
            "status": "SUPPORTED",
            "assertability": "ASSERTABLE",
            "provenance": {
                "source_id": "source-1",
                "capture_route": "route-1",
                "scope": "scope-1",
                "raw_handle": "raw-1",
                "revision": "rev-1"
            },
            "verification": null,
            "state_fence": fence()
        }))
    }

    fn assurance() -> Result<super::super::SourceAssurance, serde_json::Error> {
        serde_json::from_value(json!({
            "source_ref": "source-1",
            "provenance_ref": "provenance-1",
            "integrity": "VERIFIED",
            "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED",
            "independence": "INDEPENDENT",
            "privacy_class": "INTERNAL",
            "instruction_taint": "CLEARED",
            "allowed_epistemic_use": ["CANDIDATE_EVIDENCE"],
            "allowed_effects": ["NO_EXTERNAL_EFFECT"],
            "required_verifier": "verifier-1",
            "quarantine": "NONE",
            "state_fence": fence()
        }))
    }

    fn lease() -> Result<WorkLeaseId, serde_json::Error> {
        serde_json::from_value(json!({
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": "lease-attach-1"
        }))
    }

    fn binding_for(task_id: &str) -> Result<ProviderBinding, Box<dyn Error>> {
        let scope = work_scope()?;
        Ok(ProviderBinding {
            task_id: task_id.to_owned(),
            session_id: "session-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            work_scope_digest: digest(&scope)?,
            state_fence_digest: digest(&scope.state_fence)?,
            authority_fence_digest: digest(&scope.state_fence)?,
            root_context_revision: RootContextRevision::new("root-1")?,
            task_revision: "1".to_owned(),
            plan_revision: RevisionId::new("plan-1")?,
            receipt_contract_revision: eliot_receipts::contract_identity()?.version.to_string(),
            work_contract_revision: "contract-1".to_owned(),
            work_item_id: WorkItemId::new("item-1")?,
            role_id: super::super::RoleId::new("role-1")?,
            route_id: "route-1".to_owned(),
            lease_id: lease()?,
            reviewer_attempt_id: None,
            affected_branch: None,
        })
    }

    fn receipt_for(
        owner: &str,
        request: &ProviderRequest,
        attestation: Option<&ProviderAttestation>,
    ) -> Result<ReceiptEnvelope, ProviderError> {
        let contract = eliot_receipts::contract_identity().map_err(|_| ProviderError::Failed)?;
        let request_binding_digest = digest(request).map_err(|_| ProviderError::Invalid)?;
        let task_revision = request
            .binding
            .task_revision
            .parse::<u64>()
            .map_err(|_| ProviderError::Invalid)?;
        let mut artifacts = vec![json!({
            "artifact_id": format!("artifact-{}", request.artifact_digest),
            "sha256": request.artifact_digest,
            "role": "ARTIFACT",
            "source_revision": request_binding_digest
        })];
        let mut artifact_ids = vec![format!("artifact-{}", request.artifact_digest)];
        if let Some(attestation) = attestation {
            let attestation_digest = digest(attestation).map_err(|_| ProviderError::Invalid)?;
            artifact_ids.push(format!("attestation-{attestation_digest}"));
            artifacts.push(json!({
                "artifact_id": format!("attestation-{attestation_digest}"),
                "sha256": attestation_digest,
                "role": "ARTIFACT",
                "source_revision": request_binding_digest
            }));
        }
        let value = json!({
            "contract": contract,
            "kind": "VERIFICATION",
            "work_scope": {
                "scope_id": request.binding.work_scope_id,
                "product_id": "product-1",
                "resource_generation": 1,
                "state_fence": fence()
            },
            "task": {
                "task_id": request.binding.task_id,
                "task_revision": task_revision,
                "state_fence": fence()
            },
            "session": {
                "session_id": request.binding.session_id,
                "authority_epoch": epoch(),
                "state_fence": fence()
            },
            "causal": {
                "state_fence": fence(),
                "transaction_sequence": 1,
                "parent_receipt_id": null,
                "predecessor_receipt_ids": []
            },
            "request": {
                "metadata": {
                    "request_id": format!("request-{}", request.artifact_digest),
                    "session_id": request.binding.session_id,
                    "task_id": request.binding.task_id,
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": fence(),
                    "clock": {
                        "valid_time_ms": 10,
                        "known_time_ms": 11,
                        "transaction_sequence": 1,
                        "monotonic_ns": 12
                    }
                },
                "state_fence": fence()
            },
            "operation": {
                "operation_id": format!("operation-{}", request.artifact_digest),
                "request_id": format!("request-{}", request.artifact_digest),
                "idempotency_key": format!("idem-{}", request.artifact_digest),
                "operation_kind": request.operation_kind,
                "effect": "READ",
                "state_fence": fence()
            },
            "authority": {
                "authority_id": format!("authority-{owner}"),
                "authority_owner": owner,
                "authority_epoch": epoch(),
                "state_fence": fence(),
                "allowed_effect": "READ",
                "proof_ceiling": "SCOPED_VERIFICATION"
            },
            "artifacts": artifacts,
            "verifier": {
                "verifier_id": "verifier-1",
                "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
                "artifact_ids": artifact_ids,
                "proof_ceiling": "SCOPED_VERIFICATION",
                "state_fence": fence()
            },
            "problem": null,
            "coordination": null,
            "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
        });
        let core: ReceiptCore =
            serde_json::from_value(value).map_err(|_| ProviderError::Invalid)?;
        ReceiptEnvelope::issue(core).map_err(|_| ProviderError::Invalid)
    }

    struct Trusted;

    impl ReceiptVerificationPort for Trusted {
        fn verify(&self, _receipt: &ReceiptEnvelope) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct A02;

    impl AgentRouteProvider for A02 {
        fn current_cursor(&self, _stream_id: &str) -> Result<u64, ProviderError> {
            Ok(0)
        }

        fn seal(&self, request: &ProviderRequest) -> Result<ProviderOutcome, ProviderError> {
            if request.operation_kind.as_str() != "swarm.map.seal" {
                return Err(ProviderError::Invalid);
            }
            let attestation = ProviderAttestation::Independent {
                source_assurance: Box::new(assurance().map_err(|_| ProviderError::Invalid)?),
                evidence: Box::new(evidence().map_err(|_| ProviderError::Invalid)?),
                sealed_before_peer_disclosure: true,
                all_disclosures_predate_candidate: true,
                no_sibling_finding_disclosed: true,
            };
            let receipt = receipt_for("A-02", request, Some(&attestation))?;
            Ok(ProviderOutcome {
                receipt,
                attestation,
                committed_cursor: None,
            })
        }
    }

    fn admitted_plan() -> Result<AdmittedSwarmPlan, Box<dyn Error>> {
        let lane = LaneId::new("item-1")?;
        let submission = IndependentMapSubmission {
            lane_id: lane.clone(),
            root_context_revision: RootContextRevision::new("root-1")?,
            dependency_sketch: Vec::new(),
            unknowns: vec!["unknown".to_owned()],
            candidate_subquestions: vec!["bounded subquestion".to_owned()],
            likely_overlaps: Vec::new(),
            provider_binding: binding_for("task-1")?,
        };
        let provider = A02;
        let verifier = Trusted;
        let maps: SealedIndependentMaps = collect_independent_maps(
            vec![lane],
            vec![submission],
            Some(&provider),
            Some(&verifier),
        )?;
        let proposal = SwarmPlanProposal {
            plan_revision: RevisionId::new("plan-1")?,
            root_context_revision: RootContextRevision::new("root-1")?,
            work_items: vec![WorkItem {
                work_item_id: WorkItemId::new("item-1")?,
                responsibility: "investigate item-1".to_owned(),
                plan_revision: RevisionId::new("plan-1")?,
                wave_revision: RevisionId::new("wave-1")?,
                dependency_ids: Vec::new(),
                overlap_ids: Vec::new(),
                assigned_attempt_id: None,
                assigned_role: None,
                mailbox_route_handle: None,
                state: WorkItemState::Planned,
            }],
            branch_roots: BTreeMap::from([(BranchId::new("item-1")?, WorkItemId::new("item-1")?)]),
            global_wip: 1,
            per_route_wip: 1,
            reduction_fan_in: 1,
            preserved_partition_dissent: Vec::new(),
        };
        let request = plan_admission_request(&proposal, &maps)?;
        let receipt = receipt_for("Governor", &request, None)?;
        Ok(admit_plan(proposal, &maps, receipt, Some(&verifier))?)
    }

    fn attach_request(
        bound: &ProviderBinding,
        job_handle: &str,
    ) -> Result<ProviderRequest, SwarmError> {
        Ok(ProviderRequest {
            operation_kind: JOB_ATTACH_OPERATION.to_owned(),
            artifact_digest: digest(&(
                job_handle,
                bound.plan_revision.as_str(),
                bound.state_fence_digest.as_str(),
            ))?,
            binding: bound.clone(),
            replay: None,
        })
    }

    fn attached(
        plan: &AdmittedSwarmPlan,
        owner: &SwarmPlanAttachmentLedger,
        job_handle: &str,
    ) -> Result<DurableJobAttachment, Box<dyn Error>> {
        let request = attach_request(plan.provider_binding(), job_handle)?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;
        Ok(attach_plan_job(
            plan,
            owner,
            job_handle,
            receipt,
            Some(&Trusted),
        )?)
    }

    fn grant(stale: bool) -> RouteGrant {
        RouteGrant {
            route_id: "route-1".to_owned(),
            fingerprint: "fingerprint-1".to_owned(),
            evidence_digest: "evidence-1".to_owned(),
            generation: 7,
            stale,
        }
    }

    fn dispatched() -> Result<DispatchedLaunch, Box<dyn Error>> {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let item = plan
            .work_items()
            .iter()
            .find(|item| item.work_item_id.as_str() == "item-1")
            .ok_or("missing work item")?
            .clone();
        let work_id = WorkUnitId::new("unit-1")?;
        Ok(dispatch_child(
            &attachment,
            &item,
            &work_id,
            &grant(false),
            "provider-class",
            lease()?,
            3,
            5,
        )?)
    }

    #[test]
    fn attach_rejects_plan_or_fence_mismatched_receipt() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let request = attach_request(plan.provider_binding(), "job-1")?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;

        // Plan seal: identical receipt shape with a drifted task revision.
        let mut wrong_plan_core = receipt.core.clone();
        wrong_plan_core
            .task
            .as_mut()
            .ok_or("missing task")?
            .task_revision = serde_json::from_value(json!(2_u64))?;
        let wrong_plan = ReceiptEnvelope::issue(wrong_plan_core)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-1", wrong_plan, Some(&Trusted)),
            Err(SwarmError::BindingMismatch)
        );

        // Fence seal: every fence in the core rotates coherently to a new
        // valid fence the plan was never admitted under. A single-field
        // rotation cannot stay structurally valid (`ReceiptEnvelope::issue`
        // requires all core fences to agree), so the rotation must be coherent
        // for the rejection to prove the binding check rather than issuance.
        let mut wrong_fence_core = receipt.core.clone();
        let mut rotated = wrong_fence_core.work_scope.state_fence.clone();
        rotated.resource_generation = serde_json::from_value(json!(2_u64))?;
        wrong_fence_core.work_scope.resource_generation = rotated.resource_generation;
        wrong_fence_core.work_scope.state_fence = rotated.clone();
        wrong_fence_core
            .task
            .as_mut()
            .ok_or("missing task")?
            .state_fence = rotated.clone();
        wrong_fence_core
            .session
            .as_mut()
            .ok_or("missing session")?
            .state_fence = rotated.clone();
        wrong_fence_core.causal.state_fence = rotated.clone();
        wrong_fence_core.request.metadata.state_fence = rotated.clone();
        wrong_fence_core.request.state_fence = rotated.clone();
        wrong_fence_core.operation.state_fence = rotated.clone();
        if let Some(verifier) = wrong_fence_core.verifier.as_mut() {
            verifier.state_fence = rotated.clone();
        }
        wrong_fence_core.authority.state_fence = rotated;
        let wrong_fence = ReceiptEnvelope::issue(wrong_fence_core)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-1", wrong_fence, Some(&Trusted)),
            Err(SwarmError::BindingMismatch)
        );

        Ok(())
    }

    #[test]
    fn attach_rejects_blank_job_handle_before_receipt_use() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let request = attach_request(plan.provider_binding(), "job-1")?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "   ", receipt, Some(&Trusted)),
            Err(SwarmError::Blank("job_handle"))
        );
        Ok(())
    }

    #[test]
    fn attach_requires_verifier_fail_closed() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let request = attach_request(plan.provider_binding(), "job-1")?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-1", receipt, None),
            Err(SwarmError::PlanGap(RequiredProvider::ReceiptVerifier))
        );
        Ok(())
    }

    #[test]
    fn attach_rejects_foreign_owner_receipt() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let request = attach_request(plan.provider_binding(), "job-1")?;
        let receipt = receipt_for("A-02", &request, None)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-1", receipt, Some(&Trusted)),
            Err(SwarmError::InvalidReceipt)
        );
        Ok(())
    }

    #[test]
    fn attach_rejects_task_mismatched_receipt() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let request = attach_request(plan.provider_binding(), "job-1")?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;
        // Same request digest (artifacts match) but a forged task binding.
        let mut core = receipt.core.clone();
        core.task.as_mut().ok_or("missing task")?.task_id =
            serde_json::from_value(json!("task-2"))?;
        let forged = ReceiptEnvelope::issue(core)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-1", forged, Some(&Trusted)),
            Err(SwarmError::BindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn single_attachment_conflicts_on_second_job() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let first = attached(&plan, &owner, "job-1")?;
        // Identical replay against the Governor canon is idempotent.
        let same = attached(&plan, &owner, "job-1")?;
        assert_eq!(first, same);
        assert!(assert_single_attachment(None, &first).is_ok());
        assert!(assert_single_attachment(Some(&first), &same).is_ok());
        // A second job for the same plan revision loses at the canon: without
        // the Governor call both attaches would succeed. This proof holds
        // only within the single owner instance supplied above; independent
        // owners are out of scope (production owner port: follow-up #2017).
        let request = attach_request(plan.provider_binding(), "job-2")?;
        let receipt = receipt_for(JOB_OWNER, &request, None)?;
        assert_eq!(
            attach_plan_job(&plan, &owner, "job-2", receipt, Some(&Trusted)),
            Err(SwarmError::OwnershipConflict)
        );
        Ok(())
    }

    #[test]
    fn advisory_helper_compares_attachment_values_only() -> TestResult {
        // Value-comparison defense only: the helper re-compares two
        // already-built values and cannot see Governor state, so this test
        // proves nothing about canonical singularity. The divergent pair
        // below is built against two independently constructed owners, which
        // is precisely why the helper stays advisory.
        let plan = admitted_plan()?;
        let first = attached(&plan, &SwarmPlanAttachmentLedger::new(), "job-1")?;
        let second = attached(&plan, &SwarmPlanAttachmentLedger::new(), "job-2")?;
        assert_ne!(first, second);
        assert_eq!(
            assert_single_attachment(Some(&first), &second),
            Err(SwarmError::OwnershipConflict)
        );
        Ok(())
    }

    #[test]
    fn dispatch_derives_exact_child_identity() -> TestResult {
        let launch = dispatched()?;
        assert_eq!(launch.intent.operation_id, "job-1:plan-1:item-1");
        assert_eq!(
            launch.intent.attempt_id,
            AgentAttemptId::new("job-1:plan-1:item-1-attempt")?
        );
        assert_eq!(launch.intent.route_id, "route-1");
        assert_eq!(launch.intent.route_fingerprint, "fingerprint-1");
        assert_eq!(launch.intent.term, 3);
        assert_eq!(launch.intent.epoch, 5);
        assert_eq!(launch.lineage.job_handle, "job-1");
        assert_eq!(launch.lineage.child_slot, WorkItemId::new("item-1")?);
        assert_eq!(launch.lineage.route_generation, 7);
        assert_eq!(launch.lineage.route_class, "provider-class");
        assert_eq!(launch.lineage.route_evidence_digest, "evidence-1");
        assert_eq!(launch.lineage.launch_digest, digest(&launch.intent)?);
        Ok(())
    }

    #[test]
    fn dispatch_blocks_stale_grant_without_fallback() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let item = plan.work_items()[0].clone();
        let work_id = WorkUnitId::new("unit-1")?;
        assert_eq!(
            dispatch_child(
                &attachment,
                &item,
                &work_id,
                &grant(true),
                "provider-class",
                lease()?,
                3,
                5,
            ),
            Err(SwarmError::RouteBlocked)
        );
        Ok(())
    }

    #[test]
    fn dispatch_rejects_foreign_plan_revision() -> TestResult {
        let plan = admitted_plan()?;
        let owner = SwarmPlanAttachmentLedger::new();
        let attachment = attached(&plan, &owner, "job-1")?;
        let mut item = plan.work_items()[0].clone();
        item.plan_revision = RevisionId::new("plan-2")?;
        let work_id = WorkUnitId::new("unit-1")?;
        assert_eq!(
            dispatch_child(
                &attachment,
                &item,
                &work_id,
                &grant(false),
                "provider-class",
                lease()?,
                3,
                5,
            ),
            Err(SwarmError::StaleLineage)
        );
        Ok(())
    }

    #[test]
    fn exact_replay_is_idempotent_and_drift_conflicts() -> TestResult {
        let launch = dispatched()?;
        assert_eq!(
            verify_exact_replay(&launch, &launch.intent)?,
            ReplayVerdict::Idempotent
        );
        let mut drifted = launch.intent.clone();
        drifted.term = 4;
        assert_eq!(
            verify_exact_replay(&launch, &drifted),
            Err(SwarmError::PayloadConflict)
        );
        let mut foreign = launch.intent.clone();
        foreign.operation_id = "job-1:plan-1:item-9".to_owned();
        assert_eq!(
            verify_exact_replay(&launch, &foreign)?,
            ReplayVerdict::ForeignIdentity
        );
        Ok(())
    }
}
