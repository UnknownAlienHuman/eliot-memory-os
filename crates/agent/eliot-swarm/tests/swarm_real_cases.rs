//! Real-case swarm integration tests (issue #1126, slices A2/A6/A9/A12).
//!
//! Focused contract tests over existing public swarm APIs only: no new lib
//! code, no shims. Plan-level facts go through `admit_plan` /
//! `durable_dispatch`; execution facts go through `durable_work` with injected
//! deterministic fakes (same pattern as `durable_work.rs`). The fixture
//! negatives from `scripts/verify-swarm-product-pulse.py --self-test` are
//! ported as a fail-closed contract corpus: every simulated overclaim has a
//! lib-level rejection counterpart.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Mutex;

use eliot_agent_api::WorkLeaseId;
use eliot_agent_contracts::{AgentAttemptId, RevisionId, WorkItem, WorkItemId, WorkItemState};
use eliot_coordination::SwarmPlanAttachmentLedger;
use eliot_receipts::{ReceiptCore, ReceiptEnvelope, WorkScopeBinding};
use eliot_swarm::durable_dispatch::{
    JOB_ATTACH_OPERATION, JOB_OWNER, ReplayVerdict, attach_plan_job_through_port, dispatch_child,
    plan_cancellation_drain, rehydrate_attachment_through_port, verify_exact_replay,
};
use eliot_swarm::durable_work::{
    AdmittedWorkDefinition, BudgetDimension, BudgetSpec, CancelOutcome, ChildDisposition,
    DependencyRef, DurablePorts, DurableWorkMachine, DurableWorkRecord, DurableWorkStore,
    EffectCertainty, ExternalVerdict, LaunchOutcome, ObserveOutcome, OwnerBinding, ParentCandidate,
    PeerChannel, PeerMessageKind, PeerReceipt, ReconcileOutcome, RouteCatalogue, RouteGrant,
    RouteRequest, TerminalKind, WorkExecutor, WorkUnitId, WorkUnitPhase, WorkerResult,
};
use eliot_swarm::{
    AgentRouteProvider, BranchId, IndependentMapSubmission, LaneId, ProviderAttestation,
    ProviderBinding, ProviderError, ProviderOutcome, ProviderRequest, ReceiptVerificationPort,
    RequiredProvider, RootContextRevision, SealedIndependentMaps, SwarmError, SwarmPlanProposal,
    admit_plan, collect_independent_maps, plan_admission_request,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

fn test_digest<T: Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let bytes = serde_json::to_vec(value).map_err(|_| "digest serialize")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

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

fn scope_binding(scope_id: &str) -> Result<WorkScopeBinding, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "scope_id": scope_id,
        "product_id": "product-1",
        "resource_generation": 1,
        "state_fence": fence()
    }))?)
}

fn fence_digest(scope_id: &str) -> Result<String, Box<dyn Error>> {
    test_digest(&scope_binding(scope_id)?.state_fence)
}

// ---------------------------------------------------------------------------
// Durable-work fakes (same pattern as tests/durable_work.rs).
// ---------------------------------------------------------------------------

fn durable_receipt_for(
    scope_id: &str,
    payload_digest: &str,
    contract: &Value,
) -> Result<ReceiptEnvelope, Box<dyn Error>> {
    let binding_digest = test_digest(&format!("task-1:session-1:{scope_id}:{payload_digest}"))?;
    let value = json!({
        "contract": contract,
        "kind": "VERIFICATION",
        "work_scope": {
            "scope_id": scope_id,
            "product_id": "product-1",
            "resource_generation": 1,
            "state_fence": fence()
        },
        "task": {
            "task_id": "task-1",
            "task_revision": 1,
            "state_fence": fence()
        },
        "session": {
            "session_id": "session-1",
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
                "request_id": format!("request-{payload_digest}"),
                "session_id": "session-1",
                "task_id": "task-1",
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
            "operation_id": format!("operation-{payload_digest}"),
            "request_id": format!("request-{payload_digest}"),
            "idempotency_key": format!("idem-{payload_digest}"),
            "operation_kind": "durable.work.admit",
            "effect": "READ",
            "state_fence": fence()
        },
        "authority": {
            "authority_id": "authority-Governor",
            "authority_owner": "Governor",
            "authority_epoch": epoch(),
            "state_fence": fence(),
            "allowed_effect": "READ",
            "proof_ceiling": "SCOPED_VERIFICATION"
        },
        "artifacts": [{
            "artifact_id": format!("artifact-{payload_digest}"),
            "sha256": payload_digest,
            "role": "ARTIFACT",
            "source_revision": binding_digest
        }],
        "verifier": {
            "verifier_id": "verifier-1",
            "verifier_revision": {"major": 1, "minor": 0, "patch": 0},
            "artifact_ids": [format!("artifact-{payload_digest}")],
            "proof_ceiling": "SCOPED_VERIFICATION",
            "state_fence": fence()
        },
        "problem": null,
        "coordination": null,
        "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
    });
    let core: ReceiptCore = serde_json::from_value(value)?;
    Ok(ReceiptEnvelope::issue(core)?)
}

#[derive(Default)]
struct Trusted;

impl ReceiptVerificationPort for Trusted {
    fn verify(&self, _receipt: &ReceiptEnvelope) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[derive(Default)]
struct FakeStore {
    records: Mutex<BTreeMap<String, Vec<DurableWorkRecord>>>,
    fail_appends: Mutex<u64>,
}

impl DurableWorkStore for FakeStore {
    fn append(
        &self,
        record: &DurableWorkRecord,
    ) -> Result<eliot_swarm::durable_work::StoreReceipt, ProviderError> {
        let mut failures = self
            .fail_appends
            .lock()
            .map_err(|_| ProviderError::Failed)?;
        if *failures > 0 {
            *failures -= 1;
            return Err(ProviderError::Failed);
        }
        let receipt = eliot_swarm::durable_work::StoreReceipt {
            sequence: record.sequence,
            digest: record.digest.clone(),
        };
        self.records
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .entry(record.work_id.as_str().to_owned())
            .or_default()
            .push(record.clone());
        Ok(receipt)
    }

    fn load(&self, work_id: &WorkUnitId) -> Result<Vec<DurableWorkRecord>, ProviderError> {
        self.records
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(work_id.as_str())
            .cloned()
            .ok_or(ProviderError::Unavailable)
    }
}

#[derive(Clone, PartialEq)]
enum LaunchMode {
    Started,
    UnknownSilent,
    Invalid,
}

#[derive(Clone)]
enum ChildState {
    Running(eliot_swarm::durable_work::ChildHandle),
}

#[derive(Default)]
struct FakeExecutor {
    modes: Mutex<BTreeMap<String, LaunchMode>>,
    children: Mutex<BTreeMap<String, ChildState>>,
    attempt_index: Mutex<BTreeMap<String, String>>,
    cancel_calls: Mutex<u64>,
}

impl FakeExecutor {
    fn set_mode(&self, work: &str, mode: LaunchMode) -> Result<(), Box<dyn Error>> {
        self.modes
            .lock()
            .map_err(|_| "executor lock")?
            .insert(work.to_owned(), mode);
        Ok(())
    }
}

impl WorkExecutor for FakeExecutor {
    fn launch(
        &self,
        intent: &eliot_swarm::durable_work::LaunchIntent,
    ) -> Result<LaunchOutcome, ProviderError> {
        let work = intent.work_id.as_str().to_owned();
        let mode = self
            .modes
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(&work)
            .cloned()
            .unwrap_or(LaunchMode::Started);
        let child = eliot_swarm::durable_work::ChildHandle {
            child_id: format!("{work}-child"),
            process_identity: format!("proc-{work}-1"),
        };
        match mode {
            LaunchMode::Started => {
                self.children
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .insert(format!("{work}-child"), ChildState::Running(child.clone()));
                self.attempt_index
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .insert(
                        intent.attempt_id.as_str().to_owned(),
                        format!("{work}-child"),
                    );
                Ok(LaunchOutcome::Started { child })
            }
            LaunchMode::UnknownSilent => Ok(LaunchOutcome::Unknown),
            LaunchMode::Invalid => Err(ProviderError::Invalid),
        }
    }

    fn observe(
        &self,
        child: &eliot_swarm::durable_work::ChildHandle,
    ) -> Result<ObserveOutcome, ProviderError> {
        let state = self
            .children
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(&child.child_id)
            .cloned();
        match state {
            Some(ChildState::Running(running)) => Ok(ObserveOutcome::Running { child: running }),
            None => Ok(ObserveOutcome::Unknown),
        }
    }

    fn observe_attempt(
        &self,
        attempt_id: &AgentAttemptId,
    ) -> Result<ObserveOutcome, ProviderError> {
        let child_id = self
            .attempt_index
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(attempt_id.as_str())
            .cloned();
        match child_id {
            Some(id) => {
                let state = self
                    .children
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .get(&id)
                    .cloned();
                match state {
                    Some(ChildState::Running(child)) => Ok(ObserveOutcome::Running { child }),
                    None => Ok(ObserveOutcome::Unknown),
                }
            }
            None => Ok(ObserveOutcome::Unknown),
        }
    }

    fn cancel(
        &self,
        child: &eliot_swarm::durable_work::ChildHandle,
    ) -> Result<CancelOutcome, ProviderError> {
        *self
            .cancel_calls
            .lock()
            .map_err(|_| ProviderError::Failed)? += 1;
        let known = self
            .children
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .contains_key(&child.child_id);
        if known {
            Ok(CancelOutcome::CancelRequested {
                child: child.clone(),
            })
        } else {
            Ok(CancelOutcome::Unknown)
        }
    }
}

#[derive(Clone, PartialEq)]
enum CatalogueMode {
    Fresh,
    Stale,
}

#[derive(Default)]
struct FakeCatalogue {
    modes: Mutex<BTreeMap<String, CatalogueMode>>,
}

impl FakeCatalogue {
    fn set_mode(&self, route_class: &str, mode: CatalogueMode) -> Result<(), Box<dyn Error>> {
        self.modes
            .lock()
            .map_err(|_| "catalogue lock")?
            .insert(route_class.to_owned(), mode);
        Ok(())
    }
}

impl RouteCatalogue for FakeCatalogue {
    fn lookup(&self, request: &RouteRequest) -> Result<RouteGrant, ProviderError> {
        match self
            .modes
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(&request.route_class)
            .cloned()
            .unwrap_or(CatalogueMode::Fresh)
        {
            CatalogueMode::Fresh => Ok(RouteGrant {
                route_id: format!("route-{}", request.route_class),
                fingerprint: format!("fp-{}", request.route_class),
                evidence_digest: format!("route-evidence-{}", request.route_class),
                generation: 7,
                stale: false,
            }),
            CatalogueMode::Stale => Ok(RouteGrant {
                route_id: format!("route-{}", request.route_class),
                fingerprint: "fp-stale".to_owned(),
                evidence_digest: "route-evidence-stale".to_owned(),
                generation: 2,
                stale: true,
            }),
        }
    }
}

#[derive(Default)]
struct FakePeer {
    posts: Mutex<Vec<eliot_swarm::durable_work::PeerMessage>>,
    counter: Mutex<u64>,
}

impl PeerChannel for FakePeer {
    fn post(
        &self,
        message: &eliot_swarm::durable_work::PeerMessage,
    ) -> Result<PeerReceipt, ProviderError> {
        self.posts
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .push(message.clone());
        let mut counter = self.counter.lock().map_err(|_| ProviderError::Failed)?;
        *counter += 1;
        Ok(PeerReceipt {
            message_id: format!("msg-{counter}"),
            sequence: message.sequence,
        })
    }
}

#[derive(Default)]
struct Fixture {
    store: FakeStore,
    executor: FakeExecutor,
    catalogue: FakeCatalogue,
    peer: FakePeer,
    trusted: Trusted,
}

impl Fixture {
    fn ports(&self) -> DurablePorts<'_> {
        DurablePorts {
            store: Some(&self.store as &dyn DurableWorkStore),
            executor: Some(&self.executor as &dyn WorkExecutor),
            catalogue: Some(&self.catalogue as &dyn RouteCatalogue),
            peer: Some(&self.peer as &dyn PeerChannel),
            verifier: Some(&self.trusted as &dyn ReceiptVerificationPort),
        }
    }

    fn machine(&self) -> DurableWorkMachine<'_> {
        DurableWorkMachine::new(self.ports())
    }
}

fn wid(work: &str) -> Result<WorkUnitId, Box<dyn Error>> {
    Ok(WorkUnitId::new(work)?)
}

fn lease_for(work: &str) -> Result<WorkLeaseId, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": format!("lease-{work}")
    }))?)
}

fn owner_for(work: &str) -> Result<OwnerBinding, Box<dyn Error>> {
    Ok(OwnerBinding {
        worker_id: format!("worker-{work}"),
        process_id: format!("proc-owner-{work}"),
        lease: lease_for(work)?,
    })
}

fn admitted_def(
    work: &str,
    scope: &str,
    dependencies: Vec<DependencyRef>,
) -> Result<AdmittedWorkDefinition, Box<dyn Error>> {
    let payload_digest = test_digest(&format!("payload-{work}"))?;
    let contract = eliot_receipts::contract_identity()
        .map_err(|_| "contract identity")?
        .version
        .to_string();
    let contract_value = serde_json::to_value(
        eliot_receipts::contract_identity().map_err(|_| "contract identity")?,
    )?;
    let receipt = durable_receipt_for(scope, &payload_digest, &contract_value)?;
    Ok(AdmittedWorkDefinition {
        work_id: wid(work)?,
        parent_task_id: "parent-task-1".to_owned(),
        cell_id: "swarm-cell-1".to_owned(),
        attempt_ref: format!("attempt-ref-{work}"),
        task_id: "task-1".to_owned(),
        session_id: "session-1".to_owned(),
        task_revision: "1".to_owned(),
        payload_digest,
        input_revision: format!("input-rev-{work}"),
        scope_id: scope.to_owned(),
        state_fence_digest: fence_digest(scope)?,
        authority_epoch: 1,
        term: 1,
        dependencies,
        budgets: vec![
            BudgetSpec {
                dimension: BudgetDimension::ComputeSteps,
                limit: 64,
            },
            BudgetSpec {
                dimension: BudgetDimension::CostMicrounits,
                limit: 64,
            },
            BudgetSpec {
                dimension: BudgetDimension::EvidenceBytes,
                limit: 64,
            },
        ],
        route_class: "test-route-class".to_owned(),
        max_retries: 2,
        max_children: 3,
        max_depth: 2,
        max_pending_reviews: 2,
        evidence_required: true,
        receipt_contract_revision: contract,
        admission_receipt: receipt,
    })
}

fn drive_staged(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    scope: &str,
) -> Result<DurableWorkRecord, Box<dyn Error>> {
    let definition = admitted_def(work, scope, vec![])?;
    machine.admit(definition, format!("{work}-admit"))?;
    Ok(machine.stage_work(&wid(work)?, format!("{work}-stage"))?)
}

fn drive_running(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    scope: &str,
) -> Result<DurableWorkRecord, Box<dyn Error>> {
    drive_staged(machine, work, scope)?;
    machine.assign(&wid(work)?, owner_for(work)?, format!("{work}-assign"))?;
    Ok(machine.request_launch(&wid(work)?, format!("{work}-launch"))?)
}

fn result_for(
    record: &DurableWorkRecord,
    evidence: Option<&str>,
) -> Result<WorkerResult, Box<dyn Error>> {
    let owner = record.owner.clone().ok_or("missing owner")?;
    Ok(WorkerResult {
        lease: owner.lease,
        term: record.term,
        artifacts_digest: format!("artifacts-{}", record.work_id.as_str()),
        evidence_digest: evidence.map(str::to_owned),
        output_ref: format!("output-{}", record.work_id.as_str()),
    })
}

fn drive_completed_child(
    machine: &mut DurableWorkMachine<'_>,
    parent: &str,
    child: &str,
    scope: &str,
    tag: &str,
) -> TestResult {
    drive_staged(machine, child, scope)?;
    machine.register_child(&wid(parent)?, &wid(child)?, format!("{tag}-link"))?;
    machine.assign(&wid(child)?, owner_for(child)?, format!("{tag}-assign"))?;
    machine.request_launch(&wid(child)?, format!("{tag}-launch"))?;
    let running = machine.record(&wid(child)?).ok_or("missing")?;
    machine.submit_result(
        &wid(child)?,
        result_for(&running, Some("evidence-child"))?,
        format!("{tag}-result"),
    )?;
    machine.record_external_verdict(
        &wid(child)?,
        ExternalVerdict::VerifiedComplete,
        format!("{tag}-verdict"),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan-level harness (same pattern as durable_dispatch unit tests).
// ---------------------------------------------------------------------------

fn plan_evidence() -> Result<eliot_evidence::EvidenceEnvelope, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
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
    }))?)
}

fn plan_assurance() -> Result<eliot_security_contracts::SourceAssurance, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
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
    }))?)
}

fn plan_lease() -> Result<WorkLeaseId, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": "lease-plan-1"
    }))?)
}

fn plan_binding_for(lane: &str, plan_revision: &str) -> Result<ProviderBinding, Box<dyn Error>> {
    let scope = scope_binding("scope-1")?;
    Ok(ProviderBinding {
        task_id: "task-1".to_owned(),
        session_id: "session-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        work_scope_digest: test_digest(&scope)?,
        state_fence_digest: test_digest(&scope.state_fence)?,
        authority_fence_digest: test_digest(&scope.state_fence)?,
        root_context_revision: RootContextRevision::new("root-1")?,
        task_revision: "1".to_owned(),
        plan_revision: RevisionId::new(plan_revision)?,
        receipt_contract_revision: eliot_receipts::contract_identity()?.version.to_string(),
        work_contract_revision: "contract-1".to_owned(),
        work_item_id: WorkItemId::new(lane)?,
        role_id: eliot_swarm::RoleId::new("role-1")?,
        route_id: "route-1".to_owned(),
        lease_id: plan_lease()?,
        reviewer_attempt_id: None,
        affected_branch: None,
    })
}

fn plan_receipt_for(
    owner: &str,
    request: &ProviderRequest,
    attestation: Option<&ProviderAttestation>,
) -> Result<ReceiptEnvelope, Box<dyn Error>> {
    let contract = eliot_receipts::contract_identity().map_err(|_| "contract identity")?;
    let request_binding_digest = test_digest(request)?;
    let task_revision = request
        .binding
        .task_revision
        .parse::<u64>()
        .map_err(|_| "task revision")?;
    let mut artifacts = vec![json!({
        "artifact_id": format!("artifact-{}", request.artifact_digest),
        "sha256": request.artifact_digest,
        "role": "ARTIFACT",
        "source_revision": request_binding_digest
    })];
    let mut artifact_ids = vec![format!("artifact-{}", request.artifact_digest)];
    if let Some(attestation) = attestation {
        let attestation_digest = test_digest(attestation)?;
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
    let core: ReceiptCore = serde_json::from_value(value)?;
    Ok(ReceiptEnvelope::issue(core)?)
}

#[derive(Default)]
struct PlanA02;

impl AgentRouteProvider for PlanA02 {
    fn current_cursor(&self, _stream_id: &str) -> Result<u64, ProviderError> {
        Ok(0)
    }

    fn seal(&self, request: &ProviderRequest) -> Result<ProviderOutcome, ProviderError> {
        if request.operation_kind.as_str() != "swarm.map.seal" {
            return Err(ProviderError::Invalid);
        }
        let attestation = ProviderAttestation::Independent {
            source_assurance: Box::new(plan_assurance().map_err(|_| ProviderError::Invalid)?),
            evidence: Box::new(plan_evidence().map_err(|_| ProviderError::Invalid)?),
            sealed_before_peer_disclosure: true,
            all_disclosures_predate_candidate: true,
            no_sibling_finding_disclosed: true,
        };
        let receipt = plan_receipt_for("A-02", request, Some(&attestation))
            .map_err(|_| ProviderError::Invalid)?;
        Ok(ProviderOutcome {
            receipt,
            attestation,
            committed_cursor: None,
        })
    }
}

/// Admit one plan over an explicit lane DAG: `dependencies` maps each lane to
/// its dependency lanes. `roots` must equal the lanes with no dependencies.
fn admitted_dag_plan(
    plan_revision: &str,
    dependencies: &[(&str, &[&str])],
    roots: &[&str],
) -> Result<eliot_swarm::AdmittedSwarmPlan, Box<dyn Error>> {
    let lanes = dependencies
        .iter()
        .map(|(lane, _)| LaneId::new(*lane))
        .collect::<Result<Vec<_>, _>>()?;
    let submissions = dependencies
        .iter()
        .map(|(lane, deps)| {
            Ok(IndependentMapSubmission {
                lane_id: LaneId::new(*lane)?,
                root_context_revision: RootContextRevision::new("root-1")?,
                dependency_sketch: deps
                    .iter()
                    .map(|dep| LaneId::new(*dep))
                    .collect::<Result<Vec<_>, _>>()?,
                unknowns: vec![format!("unknown-{lane}")],
                candidate_subquestions: vec![format!("bounded subquestion {lane}")],
                likely_overlaps: Vec::new(),
                provider_binding: plan_binding_for(lane, plan_revision)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let provider = PlanA02;
    let verifier = Trusted;
    let maps: SealedIndependentMaps =
        collect_independent_maps(lanes, submissions, Some(&provider), Some(&verifier))?;
    let work_items = dependencies
        .iter()
        .map(|(lane, deps)| {
            Ok(WorkItem {
                work_item_id: WorkItemId::new(*lane)?,
                responsibility: format!("investigate {lane}"),
                plan_revision: RevisionId::new(plan_revision)?,
                wave_revision: RevisionId::new("wave-1")?,
                dependency_ids: deps
                    .iter()
                    .map(|dep| WorkItemId::new(*dep))
                    .collect::<Result<Vec<_>, _>>()?,
                overlap_ids: Vec::new(),
                assigned_attempt_id: None,
                assigned_role: None,
                mailbox_route_handle: None,
                state: WorkItemState::Planned,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let branch_roots = roots
        .iter()
        .map(|lane| Ok((BranchId::new(*lane)?, WorkItemId::new(*lane)?)))
        .collect::<Result<BTreeMap<_, _>, Box<dyn Error>>>()?;
    let proposal = SwarmPlanProposal {
        plan_revision: RevisionId::new(plan_revision)?,
        root_context_revision: RootContextRevision::new("root-1")?,
        work_items,
        branch_roots,
        global_wip: 8,
        per_route_wip: 8,
        reduction_fan_in: 4,
        preserved_partition_dissent: Vec::new(),
    };
    let request = plan_admission_request(&proposal, &maps)?;
    let receipt = plan_receipt_for("Governor", &request, None)?;
    Ok(admit_plan(proposal, &maps, receipt, Some(&verifier))?)
}

fn attach_request_for(
    plan: &eliot_swarm::AdmittedSwarmPlan,
    job_handle: &str,
) -> Result<ProviderRequest, Box<dyn Error>> {
    let binding = plan.provider_binding();
    Ok(ProviderRequest {
        operation_kind: JOB_ATTACH_OPERATION.to_owned(),
        artifact_digest: test_digest(&(
            job_handle,
            binding.plan_revision.as_str(),
            binding.state_fence_digest.as_str(),
        ))?,
        binding: binding.clone(),
        replay: None,
    })
}

fn attached_through_port(
    plan: &eliot_swarm::AdmittedSwarmPlan,
    port: &SwarmPlanAttachmentLedger,
    job_handle: &str,
) -> Result<
    (
        eliot_swarm::durable_dispatch::DurableJobAttachment,
        ReceiptEnvelope,
    ),
    Box<dyn Error>,
> {
    let request = attach_request_for(plan, job_handle)?;
    let receipt = plan_receipt_for(JOB_OWNER, &request, None)?;
    let attachment =
        attach_plan_job_through_port(plan, port, job_handle, receipt.clone(), Some(&Trusted))?;
    Ok((attachment, receipt))
}

// ---------------------------------------------------------------------------
// (1) Larger DAG admits; a cyclic DAG is rejected as DependencyCycle.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_dag_admit_and_cycle_rejection() -> TestResult {
    let plan = admitted_dag_plan(
        "plan-dag-1",
        &[
            ("lane-a", &[] as &[&str]),
            ("lane-b", &["lane-a"]),
            ("lane-c", &["lane-a"]),
            ("lane-d", &["lane-b", "lane-c"]),
            ("lane-e", &["lane-d"]),
        ],
        &["lane-a"],
    )?;
    assert_eq!(plan.work_items().len(), 5);
    assert_eq!(plan.revision().as_str(), "plan-dag-1");

    // Same denominator with a back edge lane-a -> lane-e is a cycle: no lane
    // is dependency-free, so the empty root set matches and the topological
    // walk rejects the cycle instead of admitting it.
    let Err(error) = admitted_dag_plan(
        "plan-dag-2",
        &[
            ("lane-a", &["lane-e"]),
            ("lane-b", &["lane-a"]),
            ("lane-c", &["lane-a"]),
            ("lane-d", &["lane-b", "lane-c"]),
            ("lane-e", &["lane-d"]),
        ],
        &[],
    )
    .map_err(|error| {
        error
            .downcast::<SwarmError>()
            .expect("admit_plan surfaces SwarmError")
    }) else {
        return Err("cyclic plan must not admit".into());
    };
    assert_eq!(*error, SwarmError::DependencyCycle);
    Ok(())
}

// ---------------------------------------------------------------------------
// (2) Exact replay is idempotent; changed input conflicts; foreign identity
// passes through as ForeignIdentity.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_exact_replay_idempotent_vs_payload_conflict() -> TestResult {
    let plan = admitted_dag_plan("plan-replay-1", &[("lane-a", &[] as &[&str])], &["lane-a"])?;
    let owner = SwarmPlanAttachmentLedger::new();
    let (attachment, _) = attached_through_port(&plan, &owner, "job-replay-1")?;
    let item = plan
        .work_items()
        .iter()
        .find(|item| item.work_item_id.as_str() == "lane-a")
        .ok_or("missing work item")?
        .clone();
    let grant = RouteGrant {
        route_id: "route-1".to_owned(),
        fingerprint: "fingerprint-1".to_owned(),
        evidence_digest: "evidence-1".to_owned(),
        generation: 7,
        stale: false,
    };
    let dispatched = dispatch_child(
        &attachment,
        &item,
        &wid("unit-replay-1")?,
        &grant,
        "provider-class",
        lease_for("replay-1")?,
        3,
        5,
    )?;

    // Same child identity with the same payload digest is safe to re-observe.
    assert_eq!(
        verify_exact_replay(&dispatched, &dispatched.intent.clone())?,
        ReplayVerdict::Idempotent
    );

    // Same identity with a changed payload (mutated term) is a conflict: a new
    // identity and explicit parent revision are required, never silent relaunch.
    let mut drifted = dispatched.intent.clone();
    drifted.term += 1;
    assert_eq!(
        verify_exact_replay(&dispatched, &drifted),
        Err(SwarmError::PayloadConflict)
    );

    // A different child identity is not a replay of the prior dispatch.
    let mut foreign = dispatched.intent.clone();
    foreign.operation_id = format!("{}:other", foreign.operation_id);
    assert_eq!(
        verify_exact_replay(&dispatched, &foreign)?,
        ReplayVerdict::ForeignIdentity
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// (3) Unknown stays unknown: no timeout promotion, no verdict, no free scope.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_unknown_stays_unknown_without_timeout_promotion() -> TestResult {
    let fixture = Fixture::default();
    fixture
        .executor
        .set_mode("real-unknown", LaunchMode::UnknownSilent)?;
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("real-unknown", "scope-real-unknown", vec![])?,
        "real-unknown-admit",
    )?;
    machine.stage_work(&wid("real-unknown")?, "real-unknown-stage")?;
    machine.assign(
        &wid("real-unknown")?,
        owner_for("real-unknown")?,
        "real-unknown-assign",
    )?;
    let unknown = machine.request_launch(&wid("real-unknown")?, "real-unknown-launch")?;
    assert_eq!(unknown.phase, WorkUnitPhase::UnknownOutcome);
    assert_eq!(unknown.effect, EffectCertainty::PossibleEffect);

    // A timeout never promotes unknown to absent, failed, or safe-to-repeat.
    let timed_out = machine.note_timeout(&wid("real-unknown")?, "real-unknown-timeout")?;
    assert_eq!(timed_out.phase, WorkUnitPhase::UnknownOutcome);
    assert_eq!(timed_out.timeout_count, 1);
    assert_eq!(
        machine.scope_holders().get("scope-real-unknown"),
        Some(&wid("real-unknown")?)
    );

    // Reconcile with no observable child stays blocked; verdicts are refused.
    let (_, outcome) = machine.reconcile(&wid("real-unknown")?)?;
    assert_eq!(outcome, ReconcileOutcome::StillUnknownBlocked);
    let blocked = machine.record(&wid("real-unknown")?).ok_or("missing")?;
    assert_eq!(
        machine.submit_result(
            &wid("real-unknown")?,
            result_for(&blocked, Some("evidence"))?,
            "real-unknown-result"
        ),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.record_external_verdict(
            &wid("real-unknown")?,
            ExternalVerdict::VerifiedComplete,
            "real-unknown-verdict"
        ),
        Err(SwarmError::IllegalTransition)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// (4) Drain terminal_ready is blocked while any unknown descendant is open.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_drain_terminal_ready_blocked_on_unknown_descendant() -> TestResult {
    let running = WorkItemId::new("drain-child-running")?;
    let unknown = WorkItemId::new("drain-child-unknown")?;
    let done = WorkItemId::new("drain-child-done")?;
    let drain = plan_cancellation_drain(
        &[
            (running.clone(), ChildDisposition::Running),
            (unknown.clone(), ChildDisposition::UnknownBlocked),
            (
                done.clone(),
                ChildDisposition::Terminal(TerminalKind::Completed),
            ),
        ],
        16,
    )?;
    assert_eq!(drain.cancel, vec![running]);
    assert_eq!(drain.unknown, vec![unknown]);
    assert_eq!(drain.terminal, vec![(done, TerminalKind::Completed)]);
    assert!(
        !drain.terminal_ready,
        "terminal aggregate must wait for the unknown descendant"
    );

    // The same denominator fully accounted publishes.
    let ready = plan_cancellation_drain(
        &[
            (
                WorkItemId::new("drain-a")?,
                ChildDisposition::Terminal(TerminalKind::Completed),
            ),
            (
                WorkItemId::new("drain-b")?,
                ChildDisposition::Terminal(TerminalKind::FailedProvedNoEffect),
            ),
        ],
        16,
    )?;
    assert!(ready.terminal_ready);
    assert!(ready.cancel.is_empty() && ready.pending.is_empty() && ready.unknown.is_empty());
    Ok(())
}

// ---------------------------------------------------------------------------
// (5) Coverage dimensions stay separate: complete / partial / failed /
// cancelled map to distinct terminals; failed verification returns to
// Running. No scalar coverage value exists.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_coverage_dimensions_preserved_separately() -> TestResult {
    let fixture = Fixture::default();
    let mut machine = fixture.machine();

    let completed = drive_running(&mut machine, "real-cov-complete", "scope-cov-complete")?;
    machine.submit_result(
        &wid("real-cov-complete")?,
        result_for(&completed, Some("evidence-complete"))?,
        "cov-complete-result",
    )?;
    let terminal = machine.record_external_verdict(
        &wid("real-cov-complete")?,
        ExternalVerdict::VerifiedComplete,
        "cov-complete-verdict",
    )?;
    assert_eq!(terminal.terminal, Some(TerminalKind::Completed));

    let partial = drive_running(&mut machine, "real-cov-partial", "scope-cov-partial")?;
    machine.submit_result(
        &wid("real-cov-partial")?,
        result_for(&partial, Some("evidence-partial"))?,
        "cov-partial-result",
    )?;
    let terminal = machine.record_external_verdict(
        &wid("real-cov-partial")?,
        ExternalVerdict::PartialCoverage,
        "cov-partial-verdict",
    )?;
    assert_eq!(terminal.terminal, Some(TerminalKind::Partial));

    let cancelled = drive_running(&mut machine, "real-cov-cancel", "scope-cov-cancel")?;
    machine.submit_result(
        &wid("real-cov-cancel")?,
        result_for(&cancelled, Some("evidence-cancel"))?,
        "cov-cancel-result",
    )?;
    let terminal = machine.record_external_verdict(
        &wid("real-cov-cancel")?,
        ExternalVerdict::CancelledExternal,
        "cov-cancel-verdict",
    )?;
    assert_eq!(terminal.terminal, Some(TerminalKind::CancelledAfterEffect));

    // Failed verification is not a terminal dimension at all: the unit returns
    // to Running with the candidate cleared, awaiting real re-execution.
    let failed = drive_running(&mut machine, "real-cov-failed", "scope-cov-failed")?;
    machine.submit_result(
        &wid("real-cov-failed")?,
        result_for(&failed, Some("evidence-failed"))?,
        "cov-failed-result",
    )?;
    let back = machine.record_external_verdict(
        &wid("real-cov-failed")?,
        ExternalVerdict::FailedVerification,
        "cov-failed-verdict",
    )?;
    assert_eq!(back.phase, WorkUnitPhase::Running);
    assert_eq!(back.terminal, None);
    assert!(back.result_digest.is_none());
    assert_eq!(
        machine.scope_holders().get("scope-cov-failed"),
        Some(&wid("real-cov-failed")?)
    );

    // Terminal inventory keeps every dimension distinct (6 kinds, no scalar).
    let kinds = eliot_swarm::durable_work::terminal_inventory();
    assert_eq!(kinds.len(), 6);
    assert_eq!(
        kinds
            .iter()
            .map(|(kind, _)| *kind)
            .collect::<BTreeSet<_>>()
            .len(),
        6
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// (6) Worker result is a verification candidate, never a task finish.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_worker_result_is_candidate_not_finish() -> TestResult {
    let fixture = Fixture::default();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "real-candidate", "scope-real-candidate")?;
    let candidate = machine.submit_result(
        &wid("real-candidate")?,
        result_for(&running, Some("evidence-real-candidate"))?,
        "real-candidate-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    assert!(!candidate.phase.is_terminal());
    assert!(candidate.result_digest.is_some());
    assert_eq!(
        eliot_swarm::durable_work::WORK_CANDIDATE_CEILING,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    // The scope stays held: a candidate finishes nothing by itself.
    assert_eq!(
        machine.scope_holders().get("scope-real-candidate"),
        Some(&wid("real-candidate")?)
    );
    // Only the external verifier owns the terminal disposition.
    let terminal = machine.record_external_verdict(
        &wid("real-candidate")?,
        ExternalVerdict::VerifiedComplete,
        "real-candidate-verdict",
    )?;
    assert_eq!(terminal.terminal, Some(TerminalKind::Completed));
    assert!(!machine.scope_holders().contains_key("scope-real-candidate"));
    Ok(())
}

// ---------------------------------------------------------------------------
// (7) Fixture-negative corpus: each simulated overclaim rejected by
// `verify-swarm-product-pulse.py --self-test` has a lib-level fail-closed
// counterpart here. Nothing below is live proof; every case must fail closed.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_fixture_negative_corpus() -> TestResult {
    // Corpus 1 (raw/full prompt payload): blank identity material is refused
    // before any admission state exists.
    assert_eq!(
        WorkUnitId::new("   ").map(|_| ()),
        Err(SwarmError::Blank("WorkUnitId"))
    );

    // Corpus 2 (unreceipted selected model): a foreign-owner receipt is not a
    // Governor admission, and no verifier means no admission at all.
    let fixture = Fixture::default();
    let mut machine = fixture.machine();
    let plan = admitted_dag_plan("plan-corpus-1", &[("lane-a", &[] as &[&str])], &["lane-a"])?;
    let owner = SwarmPlanAttachmentLedger::new();
    let request = attach_request_for(&plan, "job-corpus-1")?;
    let foreign = plan_receipt_for("A-02", &request, None)?;
    assert_eq!(
        attach_plan_job_through_port(&plan, &owner, "job-corpus-1", foreign, Some(&Trusted)),
        Err(SwarmError::InvalidReceipt)
    );
    let receipt = plan_receipt_for(JOB_OWNER, &request, None)?;
    assert_eq!(
        attach_plan_job_through_port(&plan, &owner, "job-corpus-1", receipt, None),
        Err(SwarmError::PlanGap(RequiredProvider::ReceiptVerifier))
    );

    // Corpus 3 (provider execution overclaim): an executor failure never
    // becomes an invented outcome; the persisted intent stays put.
    let fixture_b = Fixture::default();
    fixture_b
        .executor
        .set_mode("real-corpus-exec", LaunchMode::Invalid)?;
    let mut machine_b = fixture_b.machine();
    drive_staged(&mut machine_b, "real-corpus-exec", "scope-corpus-exec")?;
    machine_b.assign(
        &wid("real-corpus-exec")?,
        owner_for("real-corpus-exec")?,
        "corpus-exec-assign",
    )?;
    assert_eq!(
        machine_b.request_launch(&wid("real-corpus-exec")?, "corpus-exec-launch"),
        Err(SwarmError::Provider {
            provider: RequiredProvider::WorkExecutor,
            source: ProviderError::Invalid,
        })
    );
    assert_eq!(
        machine_b
            .record(&wid("real-corpus-exec")?)
            .ok_or("missing")?
            .phase,
        WorkUnitPhase::LaunchRequested
    );

    // Corpus 4 (native subagent admission): a second owner cannot take over a
    // bound unit.
    drive_staged(&mut machine, "real-corpus-owner", "scope-corpus-owner")?;
    machine.assign(
        &wid("real-corpus-owner")?,
        owner_for("real-corpus-owner")?,
        "corpus-owner-assign",
    )?;
    let mut rival = owner_for("real-corpus-owner")?;
    rival.worker_id = "rival-worker".to_owned();
    assert_eq!(
        machine.assign(&wid("real-corpus-owner")?, rival, "corpus-owner-rival"),
        Err(SwarmError::OwnershipConflict)
    );

    // Corpus 5 (direct worker group chat): an unreceipted peer acknowledgement
    // is refused as a contract violation.
    let running = drive_running(&mut machine, "real-corpus-peer", "scope-corpus-peer")?;
    let _ = running;
    machine.post_message(
        &wid("real-corpus-peer")?,
        PeerMessageKind::Finding,
        "artifact-corpus".to_owned(),
        "rev-1".to_owned(),
        "payload-corpus".to_owned(),
        "corpus-peer-post",
    )?;
    assert_eq!(
        machine.acknowledge(&wid("real-corpus-peer")?, "msg-unknown"),
        Err(SwarmError::Contract)
    );

    // Corpus 6 (worker result authority): a worker result is only ever a
    // candidate; it cannot self-promote to terminal.
    let candidate_unit = drive_running(&mut machine, "real-corpus-cand", "scope-corpus-cand")?;
    let candidate = machine.submit_result(
        &wid("real-corpus-cand")?,
        result_for(&candidate_unit, Some("evidence-corpus"))?,
        "corpus-cand-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    assert!(!candidate.phase.is_terminal());

    // Corpus 7 (unknown live descendant): an unknown child blocks the parent
    // denominator; the drain refuses to publish a terminal aggregate.
    let parent = drive_running(&mut machine, "real-corpus-p", "scope-corpus-p")?;
    drive_staged(&mut machine, "real-corpus-c", "scope-corpus-c")?;
    machine.register_child(
        &wid("real-corpus-p")?,
        &wid("real-corpus-c")?,
        "corpus-link",
    )?;
    machine.submit_result(
        &wid("real-corpus-p")?,
        result_for(&parent, Some("evidence-parent"))?,
        "corpus-p-result",
    )?;
    assert_eq!(
        machine.close_parent(&wid("real-corpus-p")?),
        Err(SwarmError::ChildDenominatorOpen)
    );
    fixture
        .executor
        .set_mode("real-corpus-c", LaunchMode::UnknownSilent)?;
    machine.assign(
        &wid("real-corpus-c")?,
        owner_for("real-corpus-c")?,
        "corpus-c-assign",
    )?;
    machine.request_launch(&wid("real-corpus-c")?, "corpus-c-launch")?;
    assert_eq!(
        machine.close_parent(&wid("real-corpus-p")?),
        Err(SwarmError::ChildDenominatorOpen)
    );

    // Corpus 8 (concilium without dissent / unsigned aggregate): a tampered
    // parent candidate digest fails verification; a short denominator is open.
    let fixture_d = Fixture::default();
    let mut machine_d = fixture_d.machine();
    let parent_d = drive_running(&mut machine_d, "real-corpus-dp", "scope-corpus-dp")?;
    drive_completed_child(
        &mut machine_d,
        "real-corpus-dp",
        "real-corpus-dc",
        "scope-corpus-dc",
        "corpus-d",
    )?;
    machine_d.submit_result(
        &wid("real-corpus-dp")?,
        result_for(&parent_d, Some("evidence-parent"))?,
        "corpus-dp-result",
    )?;
    let candidate_d = machine_d.close_parent(&wid("real-corpus-dp")?)?;
    assert_eq!(candidate_d.denominator.len(), 1);
    machine_d.verify_parent_candidate(&candidate_d)?;
    let mut tampered = candidate_d.clone();
    tampered.candidate_digest = "tampered".to_owned();
    assert_eq!(
        machine_d.verify_parent_candidate(&tampered),
        Err(SwarmError::InvalidSnapshot)
    );
    let mut short: ParentCandidate = candidate_d.clone();
    short.denominator.remove(&wid("real-corpus-dc")?);
    assert_eq!(
        machine_d.verify_parent_candidate(&short),
        Err(SwarmError::ChildDenominatorOpen)
    );

    // Corpus 9 (worker vote/promotion): nothing self-promotes to terminal; a
    // verdict on a non-candidate is an illegal transition.
    assert_eq!(
        machine_d.record_external_verdict(
            &wid("real-corpus-dc")?,
            ExternalVerdict::VerifiedComplete,
            "corpus-late-verdict"
        ),
        Err(SwarmError::IllegalTransition)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// (8) Stale route grants, stale worker results, and stale rehydration plans
// are rejected without fallback.
// ---------------------------------------------------------------------------

#[test]
fn swarm_real_cases_stale_route_and_result_rejection() -> TestResult {
    // Stale catalogue grant blocks dispatch at the composition boundary.
    let plan = admitted_dag_plan("plan-stale-1", &[("lane-a", &[] as &[&str])], &["lane-a"])?;
    let owner = SwarmPlanAttachmentLedger::new();
    let (attachment, _) = attached_through_port(&plan, &owner, "job-stale-1")?;
    let item = plan
        .work_items()
        .iter()
        .find(|item| item.work_item_id.as_str() == "lane-a")
        .ok_or("missing work item")?
        .clone();
    let stale_grant = RouteGrant {
        route_id: "route-1".to_owned(),
        fingerprint: "fingerprint-1".to_owned(),
        evidence_digest: "evidence-1".to_owned(),
        generation: 2,
        stale: true,
    };
    assert_eq!(
        dispatch_child(
            &attachment,
            &item,
            &wid("unit-stale-1")?,
            &stale_grant,
            "provider-class",
            lease_for("stale-1")?,
            3,
            5,
        ),
        Err(SwarmError::RouteBlocked)
    );

    // A stale grant also blocks launch at the machine boundary (no fallback).
    let fixture = Fixture::default();
    fixture
        .catalogue
        .set_mode("test-route-class", CatalogueMode::Stale)?;
    let mut machine = fixture.machine();
    drive_staged(&mut machine, "real-stale-route", "scope-stale-route")?;
    machine.assign(
        &wid("real-stale-route")?,
        owner_for("real-stale-route")?,
        "stale-route-assign",
    )?;
    assert_eq!(
        machine.request_launch(&wid("real-stale-route")?, "stale-route-launch"),
        Err(SwarmError::RouteBlocked)
    );

    // A dispatch against a drifted plan revision is stale lineage.
    let mut drifted_item = item.clone();
    drifted_item.plan_revision = RevisionId::new("plan-other")?;
    let fresh_grant = RouteGrant {
        route_id: "route-1".to_owned(),
        fingerprint: "fingerprint-1".to_owned(),
        evidence_digest: "evidence-1".to_owned(),
        generation: 7,
        stale: false,
    };
    assert_eq!(
        dispatch_child(
            &attachment,
            &drifted_item,
            &wid("unit-stale-1")?,
            &fresh_grant,
            "provider-class",
            lease_for("stale-1")?,
            3,
            5,
        ),
        Err(SwarmError::StaleLineage)
    );

    // Stale worker results (foreign lease, advanced term) cannot complete a
    // new ownership.
    let fixture_b = Fixture::default();
    let mut machine_b = fixture_b.machine();
    let running = drive_running(&mut machine_b, "real-stale-result", "scope-stale-result")?;
    let mut stale_lease = result_for(&running, Some("evidence"))?;
    stale_lease.lease = lease_for("other-work")?;
    assert_eq!(
        machine_b.submit_result(&wid("real-stale-result")?, stale_lease, "stale-lease"),
        Err(SwarmError::StaleLineage)
    );
    let mut stale_term = result_for(&running, Some("evidence"))?;
    stale_term.term = running.term.saturating_add(1);
    assert_eq!(
        machine_b.submit_result(&wid("real-stale-result")?, stale_term, "stale-term"),
        Err(SwarmError::StaleLineage)
    );

    // Rehydration against a drifted plan revision is stale before any owner
    // contact: the canonical decision stays the source of truth.
    let (expected, receipt) = attached_through_port(&plan, &owner, "job-stale-1")?;
    let other = admitted_dag_plan("plan-stale-2", &[("lane-a", &[] as &[&str])], &["lane-a"])?;
    assert_eq!(
        rehydrate_attachment_through_port(&other, &owner, &expected, receipt, Some(&Trusted)),
        Err(SwarmError::StaleLineage)
    );
    Ok(())
}
