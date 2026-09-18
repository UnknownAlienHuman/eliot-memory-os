//! Durable staged work + no-lost-child proof (issue #698).
//!
//! Caller: an admitted definition plus the Governor admission receipt.
//! Implementation: `eliot_swarm::durable_work` — the staged → assigned →
//! launch → heartbeat/checkpoint → reconcile → terminal state machine.
//! Consumer: this file, with deterministic fake owners (no sleeps, no
//! network), standing in for the future #872 durable control wire.
//!
//! Declared denominator: exactly cases 1..=40, one substantive test per
//! `// WORK_UNIT_CASE: 698/<case>` marker.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::{Arc, Mutex};

use eliot_agent_api::WorkLeaseId;
use eliot_agent_contracts::AgentAttemptId;
use eliot_receipts::{ReceiptCore, ReceiptEnvelope, WorkScopeBinding};
use eliot_swarm::durable_work::{
    AdmittedWorkDefinition, BudgetDimension, BudgetSpec, CancelOutcome, DependencyRef,
    DurablePorts, DurableWorkMachine, DurableWorkRecord, DurableWorkStore, EffectCertainty,
    ExitEffects, ExitRecord, ExternalVerdict, HeartbeatSignal, LaunchOutcome, ObserveOutcome,
    OwnerBinding, ParentCandidate, PeerChannel, PeerMessage, PeerMessageKind, PeerReceipt,
    ReconcileOutcome, RetryOutcome, ReviewProposal, ReviewState, RouteCatalogue, RouteGrant,
    RouteRequest, TerminalKind, UncertainPersistOutcome, WorkCheckpoint, WorkExecutor, WorkUnitId,
    WorkUnitPhase, WorkerResult, phase_inventory, replay_records, terminal_inventory,
};
use eliot_swarm::{ClaimId, ProviderError, ReceiptVerificationPort, RequiredProvider, SwarmError};
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

fn epoch() -> Value {
    json!({"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 1})
}

fn receipt_for(
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

#[derive(Clone, Default)]
struct SharedLog(Arc<Mutex<Vec<String>>>);

impl SharedLog {
    fn push(&self, entry: String) -> Result<(), Box<dyn Error>> {
        self.0.lock().map_err(|_| "order log lock")?.push(entry);
        Ok(())
    }

    fn entries(&self) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(self.0.lock().map_err(|_| "order log lock")?.clone())
    }

    fn position(&self, needle: &str) -> Result<Option<usize>, Box<dyn Error>> {
        Ok(self.entries()?.iter().position(|entry| entry == needle))
    }
}

#[derive(Default)]
struct FakeStore {
    records: Mutex<BTreeMap<String, Vec<DurableWorkRecord>>>,
    log: SharedLog,
    fail_appends: Mutex<u64>,
    response_loss: Mutex<bool>,
}

impl FakeStore {
    fn append_count(&self, work: &str) -> Result<usize, Box<dyn Error>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "store lock")?
            .get(work)
            .map_or(0, Vec::len))
    }

    fn log_records(&self, work: &str) -> Result<Vec<DurableWorkRecord>, Box<dyn Error>> {
        Ok(self
            .records
            .lock()
            .map_err(|_| "store lock")?
            .get(work)
            .cloned()
            .unwrap_or_default())
    }
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
            self.log
                .push(format!("store:append-failed:{}", record.work_id.as_str()))
                .map_err(|_| ProviderError::Failed)?;
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
        self.log
            .push(format!(
                "store:append:{}:{}",
                record.work_id.as_str(),
                record.sequence
            ))
            .map_err(|_| ProviderError::Failed)?;
        if *self
            .response_loss
            .lock()
            .map_err(|_| ProviderError::Failed)?
        {
            return Err(ProviderError::Unknown);
        }
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
    StartedResponseLost,
    UnknownSilent,
    Refused,
    Invalid,
}

#[derive(Clone)]
enum ChildState {
    Running(eliot_swarm::durable_work::ChildHandle),
    Exited(ExitRecord),
}

#[derive(Default)]
struct FakeExecutor {
    log: SharedLog,
    modes: Mutex<BTreeMap<String, LaunchMode>>,
    children: Mutex<BTreeMap<String, ChildState>>,
    attempt_index: Mutex<BTreeMap<String, String>>,
    launch_calls: Mutex<u64>,
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

    fn launch_call_count(&self) -> Result<u64, Box<dyn Error>> {
        Ok(*self.launch_calls.lock().map_err(|_| "executor lock")?)
    }

    fn cancel_call_count(&self) -> Result<u64, Box<dyn Error>> {
        Ok(*self.cancel_calls.lock().map_err(|_| "executor lock")?)
    }

    fn exit_child(&self, work: &str, effects: ExitEffects) -> Result<(), Box<dyn Error>> {
        let mut children = self.children.lock().map_err(|_| "executor lock")?;
        let child_id = format!("{work}-child");
        let running = children.get(&child_id).cloned();
        let Some(ChildState::Running(child)) = running else {
            return Err("child is not running".into());
        };
        children.insert(
            child_id,
            ChildState::Exited(ExitRecord {
                child,
                process_status: 0,
                effects,
            }),
        );
        Ok(())
    }

    fn mark_running(&self, work: &str) -> Result<(), Box<dyn Error>> {
        let mut children = self.children.lock().map_err(|_| "executor lock")?;
        let child_id = format!("{work}-child");
        children.insert(
            child_id.clone(),
            ChildState::Running(eliot_swarm::durable_work::ChildHandle {
                child_id,
                process_identity: format!("proc-{work}-1"),
            }),
        );
        Ok(())
    }
}

impl WorkExecutor for FakeExecutor {
    fn launch(
        &self,
        intent: &eliot_swarm::durable_work::LaunchIntent,
    ) -> Result<LaunchOutcome, ProviderError> {
        *self
            .launch_calls
            .lock()
            .map_err(|_| ProviderError::Failed)? += 1;
        let work = intent.work_id.as_str().to_owned();
        self.log
            .push(format!("executor:launch:{work}"))
            .map_err(|_| ProviderError::Failed)?;
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
            LaunchMode::StartedResponseLost => {
                self.children
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .insert(format!("{work}-child"), ChildState::Running(child));
                self.attempt_index
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .insert(
                        intent.attempt_id.as_str().to_owned(),
                        format!("{work}-child"),
                    );
                Ok(LaunchOutcome::Unknown)
            }
            LaunchMode::UnknownSilent => Ok(LaunchOutcome::Unknown),
            LaunchMode::Refused => Ok(LaunchOutcome::Refused {
                reason: format!("no capacity for {work}"),
            }),
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
            Some(ChildState::Exited(exit)) => Ok(ObserveOutcome::Exited { exit }),
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
                    Some(ChildState::Exited(exit)) => Ok(ObserveOutcome::Exited { exit }),
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
    Unavailable,
}

#[derive(Default)]
struct FakeCatalogue {
    calls: Mutex<BTreeMap<String, u64>>,
    total: Mutex<u64>,
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

    fn calls_for(&self, route_class: &str, fence: &str, epoch: u64) -> Result<u64, Box<dyn Error>> {
        Ok(*self
            .calls
            .lock()
            .map_err(|_| "catalogue lock")?
            .get(&format!("{route_class}|{fence}|{epoch}"))
            .unwrap_or(&0))
    }

    fn total_calls(&self) -> Result<u64, Box<dyn Error>> {
        Ok(*self.total.lock().map_err(|_| "catalogue lock")?)
    }
}

impl RouteCatalogue for FakeCatalogue {
    fn lookup(&self, request: &RouteRequest) -> Result<RouteGrant, ProviderError> {
        *self.total.lock().map_err(|_| ProviderError::Failed)? += 1;
        *self
            .calls
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .entry(format!(
                "{}|{}|{}",
                request.route_class, request.fence_digest, request.epoch
            ))
            .or_default() += 1;
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
            CatalogueMode::Unavailable => Err(ProviderError::Unavailable),
        }
    }
}

#[derive(Default)]
struct FakePeer {
    posts: Mutex<Vec<PeerMessage>>,
    counter: Mutex<u64>,
}

impl FakePeer {
    fn posted(&self) -> Result<Vec<PeerMessage>, Box<dyn Error>> {
        Ok(self.posts.lock().map_err(|_| "peer lock")?.clone())
    }
}

impl PeerChannel for FakePeer {
    fn post(&self, message: &PeerMessage) -> Result<PeerReceipt, ProviderError> {
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
    log: SharedLog,
}

impl Fixture {
    fn with_log() -> Self {
        let log = SharedLog::default();
        Self {
            store: FakeStore {
                log: log.clone(),
                ..FakeStore::default()
            },
            executor: FakeExecutor {
                log: log.clone(),
                ..FakeExecutor::default()
            },
            log,
            ..Fixture::default()
        }
    }

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
    let receipt = receipt_for(scope, &payload_digest, &contract_value)?;
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

fn dependency(work: &str, evidence: &str) -> Result<DependencyRef, Box<dyn Error>> {
    Ok(DependencyRef {
        work_id: wid(work)?,
        evidence_digest: evidence.to_owned(),
    })
}

fn drive_staged(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    scope: &str,
    dependencies: Vec<DependencyRef>,
) -> Result<DurableWorkRecord, Box<dyn Error>> {
    let definition = admitted_def(work, scope, dependencies)?;
    machine.admit(definition, format!("{work}-admit"))?;
    Ok(machine.stage_work(&wid(work)?, format!("{work}-stage"))?)
}

fn drive_assigned(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    scope: &str,
) -> Result<DurableWorkRecord, Box<dyn Error>> {
    drive_staged(machine, work, scope, vec![])?;
    Ok(machine.assign(&wid(work)?, owner_for(work)?, format!("{work}-assign"))?)
}

fn drive_running(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    scope: &str,
) -> Result<DurableWorkRecord, Box<dyn Error>> {
    drive_assigned(machine, work, scope)?;
    Ok(machine.request_launch(&wid(work)?, format!("{work}-launch"))?)
}

fn heartbeat_for(
    record: &DurableWorkRecord,
    sequence: u64,
) -> Result<HeartbeatSignal, Box<dyn Error>> {
    let owner = record.owner.clone().ok_or("missing owner")?;
    Ok(HeartbeatSignal {
        worker_id: owner.worker_id,
        lease: owner.lease,
        term: record.term,
        epoch: record.authority_epoch,
        fence_digest: record.state_fence_digest.clone(),
        sequence,
    })
}

fn checkpoint_for(record: &DurableWorkRecord, id: &str) -> Result<WorkCheckpoint, Box<dyn Error>> {
    let route = record.route.clone().ok_or("missing route")?;
    Ok(WorkCheckpoint {
        checkpoint_id: id.to_owned(),
        input_digest: record.payload_digest.clone(),
        route_fingerprint: route.fingerprint,
        revision: "rev-1".to_owned(),
        remaining_work: vec!["step-1".to_owned(), "step-2".to_owned()],
        evidence_digest: format!("checkpoint-evidence-{id}"),
    })
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

fn review_proposal(id: &str, required: bool) -> Result<ReviewProposal, Box<dyn Error>> {
    Ok(ReviewProposal {
        review_id: ClaimId::new(id)?,
        artifact_id: "artifact-dw-1".to_owned(),
        artifact_revision: "rev-1".to_owned(),
        required,
        content_digest: format!("content-{id}"),
    })
}

fn phase_name(phase: WorkUnitPhase) -> &'static str {
    match phase {
        WorkUnitPhase::AdmittedNotStaged => "ADMITTED_NOT_STAGED",
        WorkUnitPhase::StagedNotAssigned => "STAGED_NOT_ASSIGNED",
        WorkUnitPhase::Assigned => "ASSIGNED",
        WorkUnitPhase::LaunchRequested => "LAUNCH_REQUESTED",
        WorkUnitPhase::LaunchNotAttempted => "LAUNCH_NOT_ATTEMPTED",
        WorkUnitPhase::Running => "RUNNING",
        WorkUnitPhase::Checkpointed => "CHECKPOINTED",
        WorkUnitPhase::CancellationRequested => "CANCELLATION_REQUESTED",
        WorkUnitPhase::CompletionCandidate => "COMPLETION_CANDIDATE",
        WorkUnitPhase::Terminal => "TERMINAL",
        WorkUnitPhase::UnknownOutcome => "UNKNOWN_OUTCOME",
        WorkUnitPhase::Quarantined => "QUARANTINED",
    }
}

fn terminal_name(kind: TerminalKind) -> &'static str {
    match kind {
        TerminalKind::Completed => "COMPLETED",
        TerminalKind::FailedProvedNoEffect => "FAILED_PROVED_NO_EFFECT",
        TerminalKind::FailedExhausted => "FAILED_EXHAUSTED",
        TerminalKind::CancelledBeforeLaunch => "CANCELLED_BEFORE_LAUNCH",
        TerminalKind::CancelledAfterEffect => "CANCELLED_AFTER_EFFECT",
        TerminalKind::Partial => "PARTIAL",
    }
}

fn fixture_profile() -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(
        "data/durable_work.json"
    ))?)
}

fn assert_inventory_tables(profile: &Value) -> TestResult {
    let inventory = phase_inventory();
    assert_eq!(inventory.len(), 12);
    let names = inventory
        .iter()
        .map(|(phase, _)| phase_name(*phase))
        .collect::<Vec<_>>();
    let expected = profile["phases"]
        .as_array()
        .ok_or("fixture phases")?
        .iter()
        .map(|value| value.as_str().ok_or("phase string"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(names, expected);
    for (phase, canonical) in &inventory {
        assert!(!canonical.is_empty(), "phase {phase:?} needs a mapping");
        assert!(
            canonical.contains("I14.20"),
            "phase {phase:?} must map to the canonical vocabulary"
        );
    }
    let terminals = terminal_inventory();
    assert_eq!(terminals.len(), 6);
    let terminal_names = terminals
        .iter()
        .map(|(kind, _)| terminal_name(*kind))
        .collect::<Vec<_>>();
    let expected_terminals = profile["terminal_kinds"]
        .as_array()
        .ok_or("fixture terminals")?
        .iter()
        .map(|value| value.as_str().ok_or("terminal string"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(terminal_names, expected_terminals);
    assert!(WorkUnitPhase::Terminal.is_terminal());
    assert!(WorkUnitPhase::LaunchNotAttempted.is_terminal());
    assert!(!WorkUnitPhase::UnknownOutcome.is_terminal());
    assert!(!WorkUnitPhase::Quarantined.is_terminal());
    assert!(!WorkUnitPhase::Running.is_terminal());
    Ok(())
}

fn drive_completed_child(
    machine: &mut DurableWorkMachine<'_>,
    parent: &str,
    child: &str,
    scope: &str,
    tag: &str,
) -> TestResult {
    drive_staged(machine, child, scope, vec![])?;
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

fn answer_and_resolve(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    review: &str,
    tag: &str,
) -> TestResult {
    machine.answer_review(&wid(work)?, &ClaimId::new(review)?, format!("{tag}-answer"))?;
    machine.resolve_review(
        &wid(work)?,
        &ClaimId::new(review)?,
        format!("{tag}-resolve"),
    )?;
    Ok(())
}

// WORK_UNIT_CASE: 698/1
#[test]
fn durable_work_case_01_state_transition_persistence_inventory() -> TestResult {
    assert_inventory_tables(&fixture_profile()?)?;

    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let definition = admitted_def("case-01", "scope-case-01", vec![])?;
    assert_eq!(
        machine.assign(
            &wid("case-01")?,
            owner_for("case-01")?,
            "case-01-early-assign"
        ),
        Err(SwarmError::WorkUnitUnknown)
    );
    let admitted = machine.admit(definition, "case-01-admit")?;
    assert_eq!(admitted.phase, WorkUnitPhase::AdmittedNotStaged);
    assert_eq!(
        machine.heartbeat(
            &wid("case-01")?,
            &HeartbeatSignal {
                worker_id: "worker-case-01".to_owned(),
                lease: lease_for("case-01")?,
                term: 1,
                epoch: 1,
                fence_digest: fence_digest("scope-case-01")?,
                sequence: 1,
            }
        ),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.submit_result(
            &wid("case-01")?,
            WorkerResult {
                lease: lease_for("case-01")?,
                term: 1,
                artifacts_digest: "artifacts-early".to_owned(),
                evidence_digest: Some("evidence-early".to_owned()),
                output_ref: "output-early".to_owned(),
            },
            "case-01-early-result".to_owned()
        ),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.close_parent(&wid("case-01")?),
        Err(SwarmError::IllegalTransition)
    );
    let staged = machine.stage_work(&wid("case-01")?, "case-01-stage")?;
    assert_eq!(staged.phase, WorkUnitPhase::StagedNotAssigned);
    let assigned = machine.assign(&wid("case-01")?, owner_for("case-01")?, "case-01-assign")?;
    assert_eq!(assigned.phase, WorkUnitPhase::Assigned);
    let running = machine.request_launch(&wid("case-01")?, "case-01-launch")?;
    assert_eq!(running.phase, WorkUnitPhase::Running);
    let beaten = machine.heartbeat(&wid("case-01")?, &heartbeat_for(&running, 1)?)?;
    assert_eq!(beaten.heartbeat_sequence, 1);
    let checkpointed = machine.checkpoint(
        &wid("case-01")?,
        checkpoint_for(&beaten, "cp-01")?,
        "case-01-cp",
    )?;
    assert_eq!(checkpointed.phase, WorkUnitPhase::Checkpointed);
    let candidate = machine.submit_result(
        &wid("case-01")?,
        result_for(&checkpointed, Some("evidence-case-01"))?,
        "case-01-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    let terminal = machine.record_external_verdict(
        &wid("case-01")?,
        ExternalVerdict::VerifiedComplete,
        "case-01-verdict",
    )?;
    assert_eq!(terminal.phase, WorkUnitPhase::Terminal);
    assert_eq!(terminal.terminal, Some(TerminalKind::Completed));
    assert_eq!(
        machine.heartbeat(&wid("case-01")?, &heartbeat_for(&terminal, 4)?),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.request_cancel(&wid("case-01")?, "case-01-late-cancel"),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.submit_result(
            &wid("case-01")?,
            result_for(&terminal, Some("evidence"))?,
            "case-01-late-result".to_owned()
        ),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(
        machine.close_parent(&wid("case-01")?),
        Err(SwarmError::IllegalTransition)
    );
    let log = fixture.store.log_records("case-01")?;
    assert_eq!(replay_records(&log)?.digest, terminal.digest);
    Ok(())
}

// WORK_UNIT_CASE: 698/2
#[test]
fn durable_work_case_02_valid_admitted_to_staged() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let definition = admitted_def(
        "case-02",
        "scope-case-02",
        vec![dependency("dep-1", "ev-1")?],
    )?;
    let admitted = machine.admit(definition, "case-02-admit")?;
    assert_eq!(admitted.phase, WorkUnitPhase::AdmittedNotStaged);
    assert_eq!(admitted.sequence, 1);
    assert_eq!(
        admitted.prev_digest,
        eliot_swarm::durable_work::GENESIS_DIGEST
    );
    let staged = machine.stage_work(&wid("case-02")?, "case-02-stage")?;
    assert_eq!(staged.phase, WorkUnitPhase::StagedNotAssigned);
    assert_eq!(staged.sequence, 2);
    assert_eq!(staged.prev_digest, admitted.digest);
    assert!(staged.route.is_some());
    assert!(staged.owner.is_none());
    let log = fixture.store.log_records("case-02")?;
    assert_eq!(log.len(), 2);
    assert_eq!(replay_records(&log)?.digest, staged.digest);
    Ok(())
}

// WORK_UNIT_CASE: 698/3
#[test]
fn durable_work_case_03_persistence_before_assignment() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    assert_eq!(
        machine.assign(&wid("case-03")?, owner_for("case-03")?, "case-03-ghost"),
        Err(SwarmError::WorkUnitUnknown)
    );
    machine.admit(
        admitted_def("case-03", "scope-case-03", vec![])?,
        "case-03-admit",
    )?;
    assert_eq!(
        machine.assign(&wid("case-03")?, owner_for("case-03")?, "case-03-early"),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(fixture.store.append_count("case-03")?, 1);
    machine.stage_work(&wid("case-03")?, "case-03-stage")?;
    let staged_log = fixture.store.log_records("case-03")?;
    assert_eq!(staged_log.len(), 2);
    assert_eq!(staged_log[1].phase, WorkUnitPhase::StagedNotAssigned);
    machine.assign(&wid("case-03")?, owner_for("case-03")?, "case-03-assign")?;
    let order = fixture.log.entries()?;
    let staged_position = fixture
        .log
        .position("store:append:case-03:2")?
        .ok_or("staged persist missing")?;
    let assigned_position = fixture
        .log
        .position("store:append:case-03:3")?
        .ok_or("assign persist missing")?;
    assert!(
        staged_position < assigned_position,
        "staged record must persist before assignment: {order:?}"
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/4
#[test]
fn durable_work_case_04_singular_assigned_ownership() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-04", "scope-case-04")?;
    let mut other = owner_for("case-04")?;
    other.worker_id = "other-worker".to_owned();
    assert_eq!(
        machine.assign(&wid("case-04")?, other, "case-04-second-owner"),
        Err(SwarmError::OwnershipConflict)
    );
    assert_eq!(
        machine.assign(
            &wid("case-04")?,
            owner_for("case-04")?,
            "case-04-repeat-owner"
        ),
        Err(SwarmError::OwnershipConflict)
    );
    let record = machine.record(&wid("case-04")?).ok_or("missing")?;
    assert_eq!(record.owner, Some(owner_for("case-04")?));
    assert_eq!(record.phase, WorkUnitPhase::Assigned);
    Ok(())
}

// WORK_UNIT_CASE: 698/5
#[test]
fn durable_work_case_05_duplicate_scope_writer_rejected() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("case-05-a", "scope-shared-05", vec![])?,
        "case-05-a-admit",
    )?;
    assert_eq!(
        machine.admit(
            admitted_def("case-05-b", "scope-shared-05", vec![])?,
            "case-05-b-admit"
        ),
        Err(SwarmError::ScopeWriterConflict)
    );
    machine.admit(
        admitted_def("case-05-b", "scope-other-05", vec![])?,
        "case-05-b-admit",
    )?;
    let holders = machine.scope_holders();
    assert_eq!(holders.get("scope-shared-05"), Some(&wid("case-05-a")?));
    assert_eq!(holders.get("scope-other-05"), Some(&wid("case-05-b")?));
    Ok(())
}

// WORK_UNIT_CASE: 698/6
#[test]
fn durable_work_case_06_changed_same_id_payload_conflict() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("case-06", "scope-case-06", vec![])?,
        "case-06-admit",
    )?;
    let mut changed = admitted_def("case-06", "scope-case-06", vec![])?;
    changed.input_revision = "input-rev-changed".to_owned();
    changed.payload_digest = test_digest(&"payload-changed")?;
    let contract_value = serde_json::to_value(
        eliot_receipts::contract_identity().map_err(|_| "contract identity")?,
    )?;
    changed.admission_receipt =
        receipt_for("scope-case-06", &changed.payload_digest, &contract_value)?;
    assert_eq!(
        machine.admit(changed, "case-06-changed"),
        Err(SwarmError::PayloadConflict)
    );
    let same = machine.admit(
        admitted_def("case-06", "scope-case-06", vec![])?,
        "case-06-redeliver",
    )?;
    assert_eq!(same.sequence, 1);
    assert_eq!(same.phase, WorkUnitPhase::AdmittedNotStaged);
    Ok(())
}

// WORK_UNIT_CASE: 698/7
#[test]
fn durable_work_case_07_incomplete_dependency_blocks_staging() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("case-07", "scope-case-07", vec![dependency("dep-1", "")?])?,
        "case-07-admit",
    )?;
    assert_eq!(
        machine.stage_work(&wid("case-07")?, "case-07-stage"),
        Err(SwarmError::Blank("dependency_evidence_digest"))
    );
    assert_eq!(
        machine.record(&wid("case-07")?).ok_or("missing")?.phase,
        WorkUnitPhase::AdmittedNotStaged
    );
    let fixture_b = Fixture::with_log();
    let mut machine_b = fixture_b.machine();
    drive_staged(
        &mut machine_b,
        "case-07-b",
        "scope-case-07-b",
        vec![dependency("dep-1", "ev-1")?],
    )?;
    assert_eq!(
        machine_b.record(&wid("case-07-b")?).ok_or("missing")?.phase,
        WorkUnitPhase::StagedNotAssigned
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/8
#[test]
fn durable_work_case_08_completion_candidate_without_evidence_insufficient() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-08", "scope-case-08")?;
    assert_eq!(
        machine.submit_result(
            &wid("case-08")?,
            result_for(&running, None)?,
            "case-08-no-evidence"
        ),
        Err(SwarmError::EvidenceMissing)
    );
    assert_eq!(
        machine.record(&wid("case-08")?).ok_or("missing")?.phase,
        WorkUnitPhase::Running
    );
    let candidate = machine.submit_result(
        &wid("case-08")?,
        result_for(&running, Some("evidence-case-08"))?,
        "case-08-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    Ok(())
}

// WORK_UNIT_CASE: 698/9
#[test]
fn durable_work_case_09_route_lookup_consumed_once_per_distinct_request() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_staged(&mut machine, "case-09-a", "scope-case-09-a", vec![])?;
    drive_staged(&mut machine, "case-09-b", "scope-case-09-b", vec![])?;
    let fence = fence_digest("scope-case-09-a")?;
    assert_eq!(fence, fence_digest("scope-case-09-b")?);
    assert_eq!(
        fixture.catalogue.calls_for("test-route-class", &fence, 1)?,
        1,
        "one catalogue call per distinct route request"
    );
    assert_eq!(fixture.catalogue.total_calls()?, 1);
    let first = machine.record(&wid("case-09-a")?).ok_or("missing")?;
    let second = machine.record(&wid("case-09-b")?).ok_or("missing")?;
    assert_eq!(first.route, second.route);

    let mut other_class = admitted_def("case-09-c", "scope-case-09-c", vec![])?;
    other_class.route_class = "other-class".to_owned();
    machine.admit(other_class, "case-09-c-admit")?;
    machine.stage_work(&wid("case-09-c")?, "case-09-c-stage")?;
    assert_eq!(fixture.catalogue.total_calls()?, 2);
    assert_eq!(
        machine.stage_work(&wid("case-09-c")?, "case-09-c-restage"),
        Err(SwarmError::IllegalTransition)
    );
    assert_eq!(fixture.catalogue.total_calls()?, 2);
    Ok(())
}

// WORK_UNIT_CASE: 698/10
#[test]
fn durable_work_case_10_stale_unavailable_route_blocks_without_fallback() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .catalogue
        .set_mode("test-route-class", CatalogueMode::Unavailable)?;
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("case-10-a", "scope-case-10-a", vec![])?,
        "case-10-a-admit",
    )?;
    assert_eq!(
        machine.stage_work(&wid("case-10-a")?, "case-10-a-stage"),
        Err(SwarmError::RouteBlocked)
    );
    assert_eq!(fixture.executor.launch_call_count()?, 0);

    let fixture_b = Fixture::with_log();
    fixture_b
        .catalogue
        .set_mode("test-route-class", CatalogueMode::Stale)?;
    let mut machine_b = fixture_b.machine();
    let staged = drive_staged(&mut machine_b, "case-10-b", "scope-case-10-b", vec![])?;
    assert!(staged.route.as_ref().is_some_and(|route| route.stale));
    machine_b.assign(
        &wid("case-10-b")?,
        owner_for("case-10-b")?,
        "case-10-b-assign",
    )?;
    assert_eq!(
        machine_b.request_launch(&wid("case-10-b")?, "case-10-b-launch"),
        Err(SwarmError::RouteBlocked)
    );
    assert_eq!(fixture_b.executor.launch_call_count()?, 0);
    Ok(())
}

// WORK_UNIT_CASE: 698/11
#[test]
fn durable_work_case_11_intent_persisted_before_executor_call() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-11", "scope-case-11")?;
    let running = machine.request_launch(&wid("case-11")?, "case-11-launch")?;
    assert_eq!(running.phase, WorkUnitPhase::Running);
    let order = fixture.log.entries()?;
    let intent_position = fixture
        .log
        .position("store:append:case-11:4")?
        .ok_or("launch intent persist missing")?;
    let call_position = fixture
        .log
        .position("executor:launch:case-11")?
        .ok_or("executor call missing")?;
    assert!(
        intent_position < call_position,
        "intent must persist before the executor call: {order:?}"
    );
    let log = fixture.store.log_records("case-11")?;
    let intent = log
        .iter()
        .find(|record| record.sequence == 4)
        .ok_or("intent")?;
    assert_eq!(intent.phase, WorkUnitPhase::LaunchRequested);
    let launch = intent.launch.clone().ok_or("intent launch")?;
    assert!(!launch.executor_called);
    assert!(launch.child.is_none());
    assert_eq!(
        launch.attempt_id,
        running.launch.ok_or("launch")?.attempt_id
    );
    assert_eq!(
        launch.attempt_id,
        AgentAttemptId::new("case-11-attempt").map_err(|_| "attempt id")?
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/12
#[test]
fn durable_work_case_12_refused_launch_distinct_from_unknown() -> TestResult {
    let fixture = Fixture::with_log();
    fixture.executor.set_mode("case-12", LaunchMode::Refused)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-12", "scope-case-12")?;
    let refused = machine.request_launch(&wid("case-12")?, "case-12-launch")?;
    assert_eq!(refused.phase, WorkUnitPhase::LaunchNotAttempted);
    assert!(refused.phase.is_terminal());
    assert_eq!(refused.effect, EffectCertainty::NoEffect);
    assert!(!machine.scope_holders().contains_key("scope-case-12"));
    assert_eq!(fixture.executor.launch_call_count()?, 1);
    Ok(())
}

// WORK_UNIT_CASE: 698/13
#[test]
fn durable_work_case_13_lost_launch_response_stays_unknown() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .executor
        .set_mode("case-13", LaunchMode::StartedResponseLost)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-13", "scope-case-13")?;
    let unknown = machine.request_launch(&wid("case-13")?, "case-13-launch")?;
    assert_eq!(unknown.phase, WorkUnitPhase::UnknownOutcome);
    assert_eq!(unknown.effect, EffectCertainty::PossibleEffect);
    assert_eq!(
        machine.scope_holders().get("scope-case-13"),
        Some(&wid("case-13")?)
    );
    assert_eq!(
        machine.submit_result(
            &wid("case-13")?,
            result_for(&unknown, Some("evidence"))?,
            "case-13-result"
        ),
        Err(SwarmError::IllegalTransition)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/14
#[test]
fn durable_work_case_14_running_child_reattached_after_restart() -> TestResult {
    let fixture = Fixture::with_log();
    let running = {
        let mut machine = fixture.machine();
        let running = drive_running(&mut machine, "case-14", "scope-case-14")?;
        machine.heartbeat(&wid("case-14")?, &heartbeat_for(&running, 1)?)?;
        machine.record(&wid("case-14")?).ok_or("missing")?
    };
    assert_eq!(running.heartbeat_sequence, 1);
    let mut restarted = fixture.machine();
    let reloaded = restarted.reload(&wid("case-14")?)?;
    assert_eq!(reloaded.digest, running.digest);
    assert_eq!(reloaded.owner, running.owner);
    assert_eq!(reloaded.heartbeat_sequence, 1);
    let (record, outcome) = restarted.reconcile(&wid("case-14")?)?;
    assert_eq!(outcome, ReconcileOutcome::Reattached);
    assert_eq!(record.phase, WorkUnitPhase::Running);
    let beaten = restarted.heartbeat(&wid("case-14")?, &heartbeat_for(&record, 2)?)?;
    assert_eq!(beaten.heartbeat_sequence, 2);
    Ok(())
}

// WORK_UNIT_CASE: 698/15
#[test]
fn durable_work_case_15_exited_child_reconciled_once() -> TestResult {
    let fixture = Fixture::with_log();
    {
        let mut machine = fixture.machine();
        drive_running(&mut machine, "case-15", "scope-case-15")?;
    }
    fixture.executor.exit_child(
        "case-15",
        ExitEffects::CleanWithArtifacts {
            artifacts_digest: "artifacts-case-15".to_owned(),
        },
    )?;
    let mut restarted = fixture.machine();
    restarted.reload(&wid("case-15")?)?;
    let appends_before = fixture.store.append_count("case-15")?;
    let (record, outcome) = restarted.reconcile(&wid("case-15")?)?;
    assert_eq!(outcome, ReconcileOutcome::ExitedApplied);
    assert_eq!(record.phase, WorkUnitPhase::CompletionCandidate);
    let (again, second) = restarted.reconcile(&wid("case-15")?)?;
    assert_eq!(second, ReconcileOutcome::AlreadyApplied);
    assert_eq!(again.digest, record.digest);
    assert_eq!(fixture.store.append_count("case-15")?, appends_before + 1);
    Ok(())
}

// WORK_UNIT_CASE: 698/16
#[test]
fn durable_work_case_16_lost_child_proved_no_effect_safe_terminal() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .executor
        .set_mode("case-16", LaunchMode::StartedResponseLost)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-16", "scope-case-16")?;
    let unknown = machine.request_launch(&wid("case-16")?, "case-16-launch")?;
    assert_eq!(unknown.phase, WorkUnitPhase::UnknownOutcome);
    fixture.executor.exit_child(
        "case-16",
        ExitEffects::ProvedNoEffect {
            proof_digest: "proof-case-16".to_owned(),
        },
    )?;
    let (record, outcome) = machine.reconcile(&wid("case-16")?)?;
    assert_eq!(outcome, ReconcileOutcome::ProvedNoEffectTerminal);
    assert_eq!(record.phase, WorkUnitPhase::Terminal);
    assert_eq!(record.terminal, Some(TerminalKind::FailedProvedNoEffect));
    assert_eq!(record.effect, EffectCertainty::ProvedNoEffect);
    assert!(!machine.scope_holders().contains_key("scope-case-16"));
    Ok(())
}

// WORK_UNIT_CASE: 698/17
#[test]
fn durable_work_case_17_lost_possible_effect_child_stays_unresolved() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .executor
        .set_mode("case-17", LaunchMode::StartedResponseLost)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-17", "scope-case-17")?;
    machine.request_launch(&wid("case-17")?, "case-17-launch")?;
    fixture.executor.exit_child(
        "case-17",
        ExitEffects::PossibleEffect {
            detail: "unobserved side channel".to_owned(),
        },
    )?;
    let (record, outcome) = machine.reconcile(&wid("case-17")?)?;
    assert_eq!(outcome, ReconcileOutcome::ExitedApplied);
    assert_eq!(record.phase, WorkUnitPhase::UnknownOutcome);
    assert_eq!(record.effect, EffectCertainty::PossibleEffect);
    assert_eq!(
        machine.scope_holders().get("scope-case-17"),
        Some(&wid("case-17")?)
    );
    assert_eq!(
        machine.record_external_verdict(
            &wid("case-17")?,
            ExternalVerdict::VerifiedComplete,
            "case-17-verdict"
        ),
        Err(SwarmError::IllegalTransition)
    );
    let (_, second) = machine.reconcile(&wid("case-17")?)?;
    assert_eq!(second, ReconcileOutcome::AlreadyApplied);
    Ok(())
}

// WORK_UNIT_CASE: 698/18
#[test]
fn durable_work_case_18_stale_result_cannot_complete_new_ownership() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-18", "scope-case-18")?;
    let mut stale_lease = result_for(&running, Some("evidence"))?;
    stale_lease.lease = lease_for("other-work")?;
    assert_eq!(
        machine.submit_result(&wid("case-18")?, stale_lease, "case-18-stale-lease"),
        Err(SwarmError::StaleLineage)
    );
    let mut stale_term = result_for(&running, Some("evidence"))?;
    stale_term.term = running.term.saturating_add(1);
    assert_eq!(
        machine.submit_result(&wid("case-18")?, stale_term, "case-18-stale-term"),
        Err(SwarmError::StaleLineage)
    );
    assert_eq!(
        machine.record(&wid("case-18")?).ok_or("missing")?.phase,
        WorkUnitPhase::Running
    );
    let candidate = machine.submit_result(
        &wid("case-18")?,
        result_for(&running, Some("evidence-case-18"))?,
        "case-18-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    Ok(())
}

// WORK_UNIT_CASE: 698/19
#[test]
fn durable_work_case_19_current_heartbeat_monotonic() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-19", "scope-case-19")?;
    let first = machine.heartbeat(&wid("case-19")?, &heartbeat_for(&running, 1)?)?;
    assert_eq!(first.heartbeat_sequence, 1);
    let second = machine.heartbeat(&wid("case-19")?, &heartbeat_for(&first, 2)?)?;
    assert_eq!(second.heartbeat_sequence, 2);
    let third = machine.heartbeat(&wid("case-19")?, &heartbeat_for(&second, 3)?)?;
    assert_eq!(third.heartbeat_sequence, 3);
    assert_eq!(third.sequence, running.sequence + 3);
    Ok(())
}

// WORK_UNIT_CASE: 698/20
#[test]
fn durable_work_case_20_stale_foreign_heartbeat_rejected() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-20", "scope-case-20")?;
    machine.heartbeat(&wid("case-20")?, &heartbeat_for(&running, 1)?)?;
    let appends = fixture.store.append_count("case-20")?;
    let redelivered = machine.heartbeat(&wid("case-20")?, &heartbeat_for(&running, 1)?)?;
    assert_eq!(redelivered.heartbeat_sequence, 1);
    let mut foreign = heartbeat_for(&running, 1)?;
    foreign.lease = lease_for("other-work")?;
    assert_eq!(
        machine.heartbeat(&wid("case-20")?, &foreign),
        Err(SwarmError::BindingMismatch)
    );
    let mut gapped = heartbeat_for(&running, 5)?;
    gapped.sequence = 5;
    assert_eq!(
        machine.heartbeat(&wid("case-20")?, &gapped),
        Err(SwarmError::ReplayDetected)
    );
    let mut stale = heartbeat_for(&running, 1)?;
    stale.sequence = 0;
    assert_eq!(
        machine.heartbeat(&wid("case-20")?, &stale),
        Err(SwarmError::ReplayDetected)
    );
    let mut wrong_term = heartbeat_for(&running, 2)?;
    wrong_term.term = running.term.saturating_add(1);
    assert_eq!(
        machine.heartbeat(&wid("case-20")?, &wrong_term),
        Err(SwarmError::BindingMismatch)
    );
    let mut wrong_fence = heartbeat_for(&running, 2)?;
    wrong_fence.fence_digest = "other-fence".to_owned();
    assert_eq!(
        machine.heartbeat(&wid("case-20")?, &wrong_fence),
        Err(SwarmError::BindingMismatch)
    );
    let record = machine.record(&wid("case-20")?).ok_or("missing")?;
    assert_eq!(record.heartbeat_sequence, 1);
    assert_eq!(fixture.store.append_count("case-20")?, appends);
    Ok(())
}

// WORK_UNIT_CASE: 698/21
#[test]
fn durable_work_case_21_expiry_cannot_free_unknown_effect_scope() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .executor
        .set_mode("case-21", LaunchMode::UnknownSilent)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-21", "scope-case-21")?;
    let unknown = machine.request_launch(&wid("case-21")?, "case-21-launch")?;
    assert_eq!(unknown.phase, WorkUnitPhase::UnknownOutcome);
    let timed_out = machine.note_timeout(&wid("case-21")?, "case-21-timeout")?;
    assert_eq!(timed_out.phase, WorkUnitPhase::UnknownOutcome);
    assert_eq!(timed_out.timeout_count, 1);
    assert_eq!(
        machine.scope_holders().get("scope-case-21"),
        Some(&wid("case-21")?)
    );
    let (_, outcome) = machine.reconcile(&wid("case-21")?)?;
    assert_eq!(outcome, ReconcileOutcome::StillUnknownBlocked);
    Ok(())
}

// WORK_UNIT_CASE: 698/22
#[test]
fn durable_work_case_22_valid_checkpoint_exact_remaining_work_resume() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-22", "scope-case-22")?;
    let checkpointed = machine.checkpoint(
        &wid("case-22")?,
        checkpoint_for(&running, "cp-22")?,
        "case-22-cp",
    )?;
    assert_eq!(checkpointed.phase, WorkUnitPhase::Checkpointed);
    let checkpoint = checkpointed.checkpoint.clone().ok_or("checkpoint")?;
    assert_eq!(checkpoint.remaining_work, vec!["step-1", "step-2"]);
    let resumed = machine.resume(
        &wid("case-22")?,
        &["step-1".to_owned(), "step-2".to_owned()],
        "case-22-resume",
    )?;
    assert_eq!(resumed.phase, WorkUnitPhase::Running);
    assert!(resumed.checkpoint.is_some());
    assert!(resumed.result_digest.is_none());
    Ok(())
}

// WORK_UNIT_CASE: 698/23
#[test]
fn durable_work_case_23_stale_input_route_checkpoint_rejected() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-23", "scope-case-23")?;
    let mut stale_input = checkpoint_for(&running, "cp-23-bad")?;
    stale_input.input_digest = "other-payload".to_owned();
    assert_eq!(
        machine.checkpoint(&wid("case-23")?, stale_input, "case-23-cp-bad-input"),
        Err(SwarmError::BindingMismatch)
    );
    let mut stale_route = checkpoint_for(&running, "cp-23-bad-route")?;
    stale_route.route_fingerprint = "other-fingerprint".to_owned();
    assert_eq!(
        machine.checkpoint(&wid("case-23")?, stale_route, "case-23-cp-bad-route"),
        Err(SwarmError::BindingMismatch)
    );
    let checkpointed = machine.checkpoint(
        &wid("case-23")?,
        checkpoint_for(&running, "cp-23")?,
        "case-23-cp",
    )?;
    assert_eq!(
        machine.resume(
            &wid("case-23")?,
            &["wrong-step".to_owned()],
            "case-23-resume"
        ),
        Err(SwarmError::StaleLineage)
    );
    let quarantined = machine.record(&wid("case-23")?).ok_or("missing")?;
    assert_eq!(quarantined.phase, WorkUnitPhase::Quarantined);
    assert!(quarantined.checkpoint.is_some());
    let _ = checkpointed;
    let mut restart = admitted_def("case-23", "scope-case-23", vec![])?;
    restart.input_revision = "input-rev-restart".to_owned();
    restart.payload_digest = test_digest(&"payload-restart")?;
    let contract_value = serde_json::to_value(
        eliot_receipts::contract_identity().map_err(|_| "contract identity")?,
    )?;
    restart.admission_receipt =
        receipt_for("scope-case-23", &restart.payload_digest, &contract_value)?;
    let staged = machine.request_safe_restart(restart, "case-23-restart")?;
    assert_eq!(staged.phase, WorkUnitPhase::StagedNotAssigned);
    assert!(staged.owner.is_none());
    assert_eq!(
        machine.scope_holders().get("scope-case-23"),
        Some(&wid("case-23")?)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/24
#[test]
fn durable_work_case_24_unresolved_effect_prevents_resume() -> TestResult {
    let fixture = Fixture::with_log();
    fixture
        .executor
        .set_mode("case-24", LaunchMode::StartedResponseLost)?;
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-24", "scope-case-24")?;
    machine.request_launch(&wid("case-24")?, "case-24-launch")?;
    fixture.executor.mark_running("case-24")?;
    let (reattached, outcome) = machine.reconcile(&wid("case-24")?)?;
    assert_eq!(outcome, ReconcileOutcome::Reattached);
    assert_eq!(reattached.phase, WorkUnitPhase::Running);
    assert_eq!(reattached.effect, EffectCertainty::PossibleEffect);
    let checkpointed = machine.checkpoint(
        &wid("case-24")?,
        checkpoint_for(&reattached, "cp-24")?,
        "case-24-cp",
    )?;
    assert_eq!(checkpointed.effect, EffectCertainty::PossibleEffect);
    assert_eq!(
        machine.resume(
            &wid("case-24")?,
            &["step-1".to_owned(), "step-2".to_owned()],
            "case-24-resume"
        ),
        Err(SwarmError::EffectUnresolved)
    );
    assert_eq!(
        machine.record(&wid("case-24")?).ok_or("missing")?.phase,
        WorkUnitPhase::Checkpointed
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/25
#[test]
fn durable_work_case_25_replay_cannot_double_spend() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-25", "scope-case-25")?;
    let spent = machine.consume_budget(
        &wid("case-25")?,
        BudgetDimension::ComputeSteps,
        10,
        "case-25-spend",
    )?;
    assert_eq!(
        spent
            .budgets
            .get(&BudgetDimension::ComputeSteps)
            .ok_or("budget")?
            .spent,
        10
    );
    assert_eq!(
        machine.consume_budget(
            &wid("case-25")?,
            BudgetDimension::ComputeSteps,
            10,
            "case-25-spend"
        ),
        Err(SwarmError::DuplicateOperation)
    );
    let record = machine.record(&wid("case-25")?).ok_or("missing")?;
    assert_eq!(
        record
            .budgets
            .get(&BudgetDimension::ComputeSteps)
            .ok_or("budget")?
            .spent,
        10
    );
    assert_eq!(
        machine.consume_budget(
            &wid("case-25")?,
            BudgetDimension::ComputeSteps,
            100,
            "case-25-overspend"
        ),
        Err(SwarmError::BudgetExceeded)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/26
#[test]
fn durable_work_case_26_independent_budget_bounds_and_one_over() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-26", "scope-case-26")?;
    machine.consume_budget(
        &wid("case-26")?,
        BudgetDimension::ComputeSteps,
        64,
        "case-26-fill",
    )?;
    assert_eq!(
        machine.consume_budget(
            &wid("case-26")?,
            BudgetDimension::ComputeSteps,
            1,
            "case-26-over"
        ),
        Err(SwarmError::BudgetExceeded)
    );
    machine.consume_budget(
        &wid("case-26")?,
        BudgetDimension::CostMicrounits,
        1,
        "case-26-cost",
    )?;
    machine.consume_budget(
        &wid("case-26")?,
        BudgetDimension::EvidenceBytes,
        1,
        "case-26-ev",
    )?;
    let reserved = machine.reserve_budget(
        &wid("case-26")?,
        BudgetDimension::CostMicrounits,
        10,
        "case-26-rsv",
    )?;
    let account = reserved
        .budgets
        .get(&BudgetDimension::CostMicrounits)
        .ok_or("budget")?;
    assert_eq!(account.reserved, 10);
    assert_eq!(account.spent, 1);
    assert_eq!(
        account
            .limit
            .saturating_sub(account.reserved)
            .saturating_sub(account.spent),
        53
    );
    let released = machine.release_budget(
        &wid("case-26")?,
        BudgetDimension::CostMicrounits,
        4,
        "case-26-rel",
    )?;
    let account = released
        .budgets
        .get(&BudgetDimension::CostMicrounits)
        .ok_or("budget")?;
    assert_eq!(account.reserved, 6);
    assert_eq!(
        machine.release_budget(
            &wid("case-26")?,
            BudgetDimension::CostMicrounits,
            7,
            "case-26-rel-over"
        ),
        Err(SwarmError::Contract)
    );
    let record = machine.record(&wid("case-26")?).ok_or("missing")?;
    assert_eq!(
        record
            .budgets
            .get(&BudgetDimension::ComputeSteps)
            .ok_or("budget")?
            .spent,
        64
    );
    assert_eq!(
        record
            .budgets
            .get(&BudgetDimension::EvidenceBytes)
            .ok_or("budget")?
            .spent,
        1
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/27
#[test]
fn durable_work_case_27_review_message_exact_artifact_revision() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-27", "scope-case-27")?;
    let posted = machine.post_review(
        &wid("case-27")?,
        review_proposal("review-27-1", true)?,
        "case-27-post",
    )?;
    assert_eq!(posted.reviews.len(), 1);
    let review = posted.reviews.first().ok_or("review")?;
    assert_eq!(review.artifact_id, "artifact-dw-1");
    assert_eq!(review.artifact_revision, "rev-1");
    assert_eq!(review.state, ReviewState::Delivered);
    let message = posted.messages.first().ok_or("message")?.message.clone();
    assert_eq!(message.artifact_revision, "rev-1");
    assert_eq!(message.sequence, 1);
    assert_eq!(fixture.peer.posted()?.len(), 1);
    assert_eq!(
        machine.post_review(
            &wid("case-27")?,
            review_proposal("review-27-1", true)?,
            "case-27-dup"
        ),
        Err(SwarmError::Duplicate("review_id"))
    );
    let receipt_id = posted
        .messages
        .first()
        .ok_or("message")?
        .receipt
        .message_id
        .clone();
    let before = machine.record(&wid("case-27")?).ok_or("missing")?;
    machine.acknowledge(&wid("case-27")?, &receipt_id)?;
    let after = machine.record(&wid("case-27")?).ok_or("missing")?;
    assert_eq!(before.digest, after.digest);
    assert_eq!(after.phase, WorkUnitPhase::Running);
    assert_eq!(
        machine.acknowledge(&wid("case-27")?, "msg-unknown"),
        Err(SwarmError::Contract)
    );
    machine.answer_review(
        &wid("case-27")?,
        &ClaimId::new("review-27-1")?,
        "case-27-answer",
    )?;
    let resolved = machine.resolve_review(
        &wid("case-27")?,
        &ClaimId::new("review-27-1")?,
        "case-27-resolve",
    )?;
    assert_eq!(
        resolved.reviews.first().ok_or("review")?.state,
        ReviewState::Resolved
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/28
#[test]
fn durable_work_case_28_required_expired_overflowed_review_prevents_closure() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let parent = drive_running(&mut machine, "case-28-p", "scope-case-28-p")?;
    drive_completed_child(
        &mut machine,
        "case-28-p",
        "case-28-c",
        "scope-case-28-c",
        "case-28-c",
    )?;
    machine.submit_result(
        &wid("case-28-p")?,
        result_for(&parent, Some("evidence-parent"))?,
        "case-28-p-result",
    )?;
    machine.post_review(
        &wid("case-28-p")?,
        review_proposal("review-28-1", true)?,
        "case-28-post-1",
    )?;
    machine.post_review(
        &wid("case-28-p")?,
        review_proposal("review-28-2", true)?,
        "case-28-post-2",
    )?;
    let overflowed = machine.post_review(
        &wid("case-28-p")?,
        review_proposal("review-28-3", true)?,
        "case-28-post-3",
    )?;
    let overflowed_id = ClaimId::new("review-28-3").map_err(|_| "claim id")?;
    assert_eq!(
        overflowed
            .reviews
            .iter()
            .find(|review| review.review_id == overflowed_id)
            .ok_or("review")?
            .state,
        ReviewState::Overflowed
    );
    assert_eq!(
        machine.close_parent(&wid("case-28-p")?),
        Err(SwarmError::ReviewBlocksClosure)
    );
    machine.expire_review(
        &wid("case-28-p")?,
        &ClaimId::new("review-28-1")?,
        "case-28-expire",
    )?;
    assert_eq!(
        machine.close_parent(&wid("case-28-p")?),
        Err(SwarmError::ReviewBlocksClosure)
    );
    assert_eq!(
        machine.resolve_review(
            &wid("case-28-p")?,
            &ClaimId::new("review-28-1")?,
            "case-28-bad-resolve"
        ),
        Err(SwarmError::IllegalTransition)
    );
    answer_and_resolve(&mut machine, "case-28-p", "review-28-2", "case-28")?;
    machine.supersede_review(
        &wid("case-28-p")?,
        &ClaimId::new("review-28-1")?,
        review_proposal("review-28-1b", true)?,
        "case-28-supersede-1",
    )?;
    machine.supersede_review(
        &wid("case-28-p")?,
        &ClaimId::new("review-28-3")?,
        review_proposal("review-28-3b", true)?,
        "case-28-supersede-3",
    )?;
    answer_and_resolve(&mut machine, "case-28-p", "review-28-1b", "case-28-1b")?;
    answer_and_resolve(&mut machine, "case-28-p", "review-28-3b", "case-28-3b")?;
    let candidate = machine.close_parent(&wid("case-28-p")?)?;
    assert_eq!(candidate.denominator.len(), 1);
    let record = machine.record(&wid("case-28-p")?).ok_or("missing")?;
    assert_eq!(
        record
            .reviews
            .iter()
            .filter(|review| review.state == ReviewState::Superseded)
            .count(),
        2
    );
    assert!(
        record
            .reviews
            .iter()
            .filter(|review| review.required)
            .all(|review| matches!(
                review.state,
                ReviewState::Resolved | ReviewState::Superseded
            )),
        "every required obligation is resolved or visibly superseded"
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/29
#[test]
fn durable_work_case_29_pre_launch_cancellation_creates_no_process() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    machine.admit(
        admitted_def("case-29-a", "scope-case-29-a", vec![])?,
        "case-29-a-admit",
    )?;
    let admitted_cancelled = machine.request_cancel(&wid("case-29-a")?, "case-29-a-cancel")?;
    assert_eq!(admitted_cancelled.phase, WorkUnitPhase::Terminal);
    assert_eq!(
        admitted_cancelled.terminal,
        Some(TerminalKind::CancelledBeforeLaunch)
    );
    drive_assigned(&mut machine, "case-29-b", "scope-case-29-b")?;
    let assigned_cancelled = machine.request_cancel(&wid("case-29-b")?, "case-29-b-cancel")?;
    assert_eq!(assigned_cancelled.phase, WorkUnitPhase::Terminal);
    assert_eq!(
        assigned_cancelled.terminal,
        Some(TerminalKind::CancelledBeforeLaunch)
    );
    assert_eq!(assigned_cancelled.effect, EffectCertainty::ProvedNoEffect);
    assert_eq!(fixture.executor.launch_call_count()?, 0);
    assert_eq!(fixture.executor.cancel_call_count()?, 0);
    assert!(!machine.scope_holders().contains_key("scope-case-29-b"));
    Ok(())
}

// WORK_UNIT_CASE: 698/30
#[test]
fn durable_work_case_30_post_execution_cancellation_reconciles() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-30", "scope-case-30")?;
    let requested = machine.request_cancel(&wid("case-30")?, "case-30-cancel")?;
    assert_eq!(requested.phase, WorkUnitPhase::CancellationRequested);
    assert_eq!(
        requested.cancellation,
        eliot_swarm::durable_work::CancellationPhase::Requested
    );
    assert_eq!(fixture.executor.cancel_call_count()?, 1);
    let log = fixture.store.log_records("case-30")?;
    assert!(
        log.iter()
            .any(|record| record.phase == WorkUnitPhase::CancellationRequested)
    );
    let (record, outcome) = machine.reconcile(&wid("case-30")?)?;
    assert_eq!(outcome, ReconcileOutcome::Reattached);
    assert_eq!(record.phase, WorkUnitPhase::CancellationRequested);
    fixture.executor.exit_child(
        "case-30",
        ExitEffects::CleanWithArtifacts {
            artifacts_digest: "artifacts-case-30".to_owned(),
        },
    )?;
    let (exited, _) = machine.reconcile(&wid("case-30")?)?;
    assert_eq!(exited.phase, WorkUnitPhase::CompletionCandidate);

    let fixture_b = Fixture::with_log();
    fixture_b
        .executor
        .set_mode("case-30-b", LaunchMode::Invalid)?;
    let mut machine_b = fixture_b.machine();
    drive_assigned(&mut machine_b, "case-30-b", "scope-case-30-b")?;
    assert_eq!(
        machine_b.request_launch(&wid("case-30-b")?, "case-30-b-launch"),
        Err(SwarmError::Provider {
            provider: RequiredProvider::WorkExecutor,
            source: ProviderError::Invalid,
        })
    );
    assert_eq!(
        machine_b.record(&wid("case-30-b")?).ok_or("missing")?.phase,
        WorkUnitPhase::LaunchRequested
    );
    let cancelled = machine_b.request_cancel(&wid("case-30-b")?, "case-30-b-cancel")?;
    assert_eq!(cancelled.phase, WorkUnitPhase::Terminal);
    assert_eq!(
        cancelled.terminal,
        Some(TerminalKind::CancelledBeforeLaunch)
    );
    assert_eq!(fixture_b.executor.cancel_call_count()?, 0);
    Ok(())
}

// WORK_UNIT_CASE: 698/31
#[test]
fn durable_work_case_31_timeout_neither_relaunches_nor_orphans() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-31", "scope-case-31")?;
    let timed_out = machine.note_timeout(&wid("case-31")?, "case-31-timeout-1")?;
    assert_eq!(timed_out.phase, WorkUnitPhase::Running);
    assert_eq!(timed_out.owner, running.owner);
    assert_eq!(timed_out.launch, running.launch);
    assert_eq!(timed_out.timeout_count, 1);
    assert_eq!(fixture.executor.launch_call_count()?, 1);
    let timed_out_again = machine.note_timeout(&wid("case-31")?, "case-31-timeout-2")?;
    assert_eq!(timed_out_again.timeout_count, 2);
    assert_eq!(fixture.executor.launch_call_count()?, 1);
    let beaten = machine.heartbeat(&wid("case-31")?, &heartbeat_for(&timed_out_again, 1)?)?;
    assert_eq!(beaten.heartbeat_sequence, 1);
    Ok(())
}

// WORK_UNIT_CASE: 698/32
#[test]
fn durable_work_case_32_worker_result_is_only_a_verification_candidate() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-32", "scope-case-32")?;
    let candidate = machine.submit_result(
        &wid("case-32")?,
        result_for(&running, Some("evidence-case-32"))?,
        "case-32-result",
    )?;
    assert_eq!(candidate.phase, WorkUnitPhase::CompletionCandidate);
    assert!(candidate.result_digest.is_some());
    assert!(!candidate.phase.is_terminal());
    assert_eq!(
        machine.scope_holders().get("scope-case-32"),
        Some(&wid("case-32")?)
    );
    assert_eq!(
        eliot_swarm::durable_work::WORK_CANDIDATE_CEILING,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    let terminal = machine.record_external_verdict(
        &wid("case-32")?,
        ExternalVerdict::VerifiedComplete,
        "case-32-verdict",
    )?;
    assert_eq!(terminal.terminal, Some(TerminalKind::Completed));
    assert!(!machine.scope_holders().contains_key("scope-case-32"));
    Ok(())
}

// WORK_UNIT_CASE: 698/33
#[test]
fn durable_work_case_33_process_terminal_state_is_not_task_finish() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-33", "scope-case-33")?;
    fixture.executor.exit_child(
        "case-33",
        ExitEffects::CleanWithArtifacts {
            artifacts_digest: "artifacts-case-33".to_owned(),
        },
    )?;
    let observed = machine.observe_child(&wid("case-33")?)?;
    assert_eq!(observed.phase, WorkUnitPhase::CompletionCandidate);
    assert!(!observed.phase.is_terminal());
    assert_eq!(observed.terminal, None);
    assert_eq!(observed.last_exit.ok_or("exit")?.process_status, 0);
    assert_eq!(
        machine.scope_holders().get("scope-case-33"),
        Some(&wid("case-33")?)
    );
    assert_eq!(
        machine
            .record_external_verdict(
                &wid("case-33")?,
                ExternalVerdict::FailedVerification,
                "case-33-verdict"
            )?
            .phase,
        WorkUnitPhase::Running
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/34
#[test]
fn durable_work_case_34_one_unresolved_child_blocks_parent() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let parent = drive_running(&mut machine, "case-34-p", "scope-case-34-p")?;
    drive_staged(&mut machine, "case-34-c", "scope-case-34-c", vec![])?;
    machine.register_child(&wid("case-34-p")?, &wid("case-34-c")?, "case-34-link")?;
    machine.submit_result(
        &wid("case-34-p")?,
        result_for(&parent, Some("evidence-parent"))?,
        "case-34-p-result",
    )?;
    assert_eq!(
        machine.close_parent(&wid("case-34-p")?),
        Err(SwarmError::ChildDenominatorOpen)
    );
    fixture
        .executor
        .set_mode("case-34-c", LaunchMode::UnknownSilent)?;
    machine.assign(
        &wid("case-34-c")?,
        owner_for("case-34-c")?,
        "case-34-c-assign",
    )?;
    machine.request_launch(&wid("case-34-c")?, "case-34-c-launch")?;
    assert_eq!(
        machine.record(&wid("case-34-c")?).ok_or("missing")?.phase,
        WorkUnitPhase::UnknownOutcome
    );
    assert_eq!(
        machine.close_parent(&wid("case-34-p")?),
        Err(SwarmError::ChildDenominatorOpen)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/35
#[test]
fn durable_work_case_35_complete_denominator_yields_exact_parent_candidate() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let parent = drive_running(&mut machine, "case-35-p", "scope-case-35-p")?;
    drive_completed_child(
        &mut machine,
        "case-35-p",
        "case-35-a",
        "scope-case-35-a",
        "case-35-a",
    )?;
    drive_staged(&mut machine, "case-35-b", "scope-case-35-b", vec![])?;
    machine.register_child(&wid("case-35-p")?, &wid("case-35-b")?, "case-35-b-link")?;
    machine.assign(
        &wid("case-35-b")?,
        owner_for("case-35-b")?,
        "case-35-b-assign",
    )?;
    machine.request_launch(&wid("case-35-b")?, "case-35-b-launch")?;
    fixture.executor.exit_child(
        "case-35-b",
        ExitEffects::ProvedNoEffect {
            proof_digest: "proof-b".to_owned(),
        },
    )?;
    machine.observe_child(&wid("case-35-b")?)?;
    machine.submit_result(
        &wid("case-35-p")?,
        result_for(&parent, Some("evidence-parent"))?,
        "case-35-p-result",
    )?;
    let candidate = machine.close_parent(&wid("case-35-p")?)?;
    assert_eq!(candidate.denominator.len(), 2);
    assert_eq!(
        candidate.denominator.get(&wid("case-35-a")?),
        Some(&TerminalKind::Completed)
    );
    assert_eq!(
        candidate.denominator.get(&wid("case-35-b")?),
        Some(&TerminalKind::FailedProvedNoEffect)
    );
    assert_eq!(
        candidate.proof_ceiling,
        eliot_receipts::ProofCeiling::CandidateArtifact
    );
    machine.verify_parent_candidate(&candidate)?;
    let mut tampered = candidate.clone();
    tampered.candidate_digest = "tampered".to_owned();
    assert_eq!(
        machine.verify_parent_candidate(&tampered),
        Err(SwarmError::InvalidSnapshot)
    );
    let mut short: ParentCandidate = candidate.clone();
    short.denominator.remove(&wid("case-35-b")?);
    assert_eq!(
        machine.verify_parent_candidate(&short),
        Err(SwarmError::ChildDenominatorOpen)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/36
#[test]
fn durable_work_case_36_duplicate_reordered_replay_deterministic() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    let running = drive_running(&mut machine, "case-36", "scope-case-36")?;
    machine.heartbeat(&wid("case-36")?, &heartbeat_for(&running, 1)?)?;
    let log = fixture.store.log_records("case-36")?;
    assert!(log.len() >= 4);
    let tip = replay_records(&log)?;
    let replayed = replay_records(&log)?;
    assert_eq!(tip.digest, replayed.digest);
    let mut duplicated = log.clone();
    duplicated.push(tip.clone());
    assert_eq!(replay_records(&duplicated)?.digest, tip.digest);
    let mut reordered = log.clone();
    let len = reordered.len();
    reordered.swap(1, len - 1);
    assert!(replay_records(&reordered).is_err());
    let mut tampered = log.clone();
    tampered[1].phase = WorkUnitPhase::Running;
    assert!(replay_records(&tampered).is_err());
    let prefix = replay_records(&log[..log.len() - 1])?;
    assert_eq!(prefix.digest, log[log.len() - 2].digest);
    assert!(replay_records(&[]).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 698/37
#[test]
fn durable_work_case_37_bounded_retry_fanout_depth_terminates() -> TestResult {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_running(&mut machine, "case-37", "scope-case-37")?;
    let (first, outcome) = machine.note_retry(&wid("case-37")?, "case-37-retry-1")?;
    assert_eq!(outcome, RetryOutcome::Scheduled);
    assert_eq!(first.retry_count, 1);
    let (second, outcome) = machine.note_retry(&wid("case-37")?, "case-37-retry-2")?;
    assert_eq!(outcome, RetryOutcome::Scheduled);
    assert_eq!(second.retry_count, 2);
    let (exhausted, outcome) = machine.note_retry(&wid("case-37")?, "case-37-retry-3")?;
    assert_eq!(outcome, RetryOutcome::Exhausted);
    assert_eq!(exhausted.phase, WorkUnitPhase::Terminal);
    assert_eq!(exhausted.terminal, Some(TerminalKind::FailedExhausted));
    assert!(!machine.scope_holders().contains_key("scope-case-37"));

    drive_running(&mut machine, "case-37-p", "scope-case-37-p")?;
    drive_staged(&mut machine, "case-37-a", "scope-case-37-a", vec![])?;
    drive_staged(&mut machine, "case-37-b", "scope-case-37-b", vec![])?;
    drive_staged(&mut machine, "case-37-c", "scope-case-37-c", vec![])?;
    drive_staged(&mut machine, "case-37-d", "scope-case-37-d", vec![])?;
    machine.register_child(&wid("case-37-p")?, &wid("case-37-a")?, "case-37-link-a")?;
    machine.register_child(&wid("case-37-p")?, &wid("case-37-b")?, "case-37-link-b")?;
    machine.register_child(&wid("case-37-p")?, &wid("case-37-c")?, "case-37-link-c")?;
    assert_eq!(
        machine.register_child(&wid("case-37-p")?, &wid("case-37-d")?, "case-37-link-d"),
        Err(SwarmError::IllegalTransition)
    );
    machine.assign(
        &wid("case-37-a")?,
        owner_for("case-37-a")?,
        "case-37-a-assign",
    )?;
    machine.request_launch(&wid("case-37-a")?, "case-37-a-launch")?;
    drive_running(&mut machine, "case-37-dp", "scope-case-37-dp")?;
    let mut shallow = admitted_def("case-37-s", "scope-case-37-s", vec![])?;
    shallow.max_depth = 1;
    machine.admit(shallow, "case-37-s-admit")?;
    machine.stage_work(&wid("case-37-s")?, "case-37-s-stage")?;
    machine.register_child(&wid("case-37-dp")?, &wid("case-37-s")?, "case-37-link-s")?;
    machine.assign(
        &wid("case-37-s")?,
        owner_for("case-37-s")?,
        "case-37-s-assign",
    )?;
    machine.request_launch(&wid("case-37-s")?, "case-37-s-launch")?;
    drive_staged(&mut machine, "case-37-e", "scope-case-37-e", vec![])?;
    assert_eq!(
        machine.register_child(&wid("case-37-s")?, &wid("case-37-e")?, "case-37-link-deep"),
        Err(SwarmError::IllegalTransition)
    );
    Ok(())
}

// WORK_UNIT_CASE: 698/38
#[test]
fn durable_work_case_38_ten_thousand_seeded_sequences_preserve_invariants() -> TestResult {
    let profile = fixture_profile()?;
    let expected = profile["expected_sequences"].as_u64().ok_or("sequences")?;
    assert_eq!(expected, 10_000);
    let base_seed = profile["base_seed"].as_u64().ok_or("seed")?;
    let min_steps = profile["min_steps"].as_u64().ok_or("min")?;
    let max_steps = profile["max_steps"].as_u64().ok_or("max")?;

    let mut executed: u64 = 0;
    let mut failing_seeds: Vec<u64> = Vec::new();
    for index in 0..expected {
        let seed = base_seed.wrapping_add(index);
        let mut rng = seed;
        if rng == 0 {
            rng = 0x9E37_79B9_7F4A_7C15;
        }
        if seeded_sequence(min_steps, max_steps, &mut rng).is_err() {
            failing_seeds.push(seed);
            if failing_seeds.len() > 8 {
                break;
            }
        }
        executed += 1;
    }
    assert_eq!(executed, expected);
    assert!(
        failing_seeds.is_empty(),
        "seeded invariant failures at seeds: {failing_seeds:?}"
    );
    Ok(())
}

fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn apply_seeded_op(
    machine: &mut DurableWorkMachine<'_>,
    work: &str,
    choice: u64,
    step: usize,
    rng: &mut u64,
) -> TestResult {
    let key = format!("seq-op-{step}");
    let current = machine.record(&wid(work)?).ok_or("missing")?;
    match choice {
        0 => {
            let _ = machine.request_launch(&wid(work)?, key);
        }
        1 => {
            let sequence = current.heartbeat_sequence.saturating_add(1);
            if let Ok(signal) = heartbeat_for(&current, sequence) {
                let _ = machine.heartbeat(&wid(work)?, &signal);
            }
        }
        2 => {
            if let Ok(checkpoint) = checkpoint_for(&current, &format!("seq-cp-{step}")) {
                let _ = machine.checkpoint(&wid(work)?, checkpoint, key);
            }
        }
        3 => {
            let _ = machine.resume(
                &wid(work)?,
                &["step-1".to_owned(), "step-2".to_owned()],
                key,
            );
        }
        4 => {
            if let Ok(result) = result_for(&current, Some(&format!("ev-{step}"))) {
                let _ = machine.submit_result(&wid(work)?, result, key);
            }
        }
        5 => {
            let _ = machine.request_cancel(&wid(work)?, key);
        }
        6 => {
            let _ = machine.note_timeout(&wid(work)?, key);
        }
        7 => {
            let _ = machine.note_retry(&wid(work)?, key);
        }
        8 => {
            let dimension = match next_rand(rng) % 3 {
                0 => BudgetDimension::ComputeSteps,
                1 => BudgetDimension::CostMicrounits,
                _ => BudgetDimension::EvidenceBytes,
            };
            let amount = next_rand(rng) % 5 + 1;
            let _ = machine.consume_budget(&wid(work)?, dimension, amount, key.clone());
            let _ = machine.reserve_budget(&wid(work)?, dimension, 1, format!("{key}-rsv"));
            let _ = machine.release_budget(&wid(work)?, dimension, 1, format!("{key}-rel"));
        }
        9 => {
            let _ = machine.observe_child(&wid(work)?);
        }
        10 => {
            let _ = machine.reconcile(&wid(work)?);
        }
        11 => {
            let id = format!("seq-review-{step}");
            if let Ok(proposal) = review_proposal(&id, step.is_multiple_of(2)) {
                let _ = machine.post_review(&wid(work)?, proposal, key);
            }
        }
        12 => {
            let _ = machine.register_child(&wid(work)?, &wid("seq-child")?, key);
        }
        13 => {
            let _ = machine.record_external_verdict(
                &wid(work)?,
                if step.is_multiple_of(2) {
                    ExternalVerdict::VerifiedComplete
                } else {
                    ExternalVerdict::FailedVerification
                },
                key,
            );
        }
        _ => {
            let _ = machine.post_message(
                &wid(work)?,
                PeerMessageKind::Finding,
                format!("artifact-{step}"),
                "rev-1".to_owned(),
                format!("payload-{step}"),
                key,
            );
        }
    }
    Ok(())
}

fn assert_sequence_invariants(
    machine: &DurableWorkMachine<'_>,
    digests: &mut BTreeMap<String, String>,
    effect_ranks: &mut BTreeMap<String, u8>,
    phases: &mut BTreeMap<String, WorkUnitPhase>,
) {
    for record in machine.all_records() {
        let id = record.work_id.as_str().to_owned();
        if let Some(known) = digests.get(&id) {
            assert_eq!(*known, record.definition_digest, "identity drift for {id}");
        } else {
            digests.insert(id.clone(), record.definition_digest.clone());
        }
        for (dimension, account) in &record.budgets {
            assert!(
                account.spent.saturating_add(account.reserved) <= account.limit,
                "budget overrun for {id} {dimension:?}"
            );
            assert_eq!(
                account
                    .limit
                    .saturating_sub(account.reserved)
                    .saturating_sub(account.spent)
                    + account.reserved
                    + account.spent,
                account.limit,
                "budget conservation for {id} {dimension:?}"
            );
        }
        let rank = record.effect.rank();
        if let Some(previous) = effect_ranks.get(&id) {
            let restarted = record.phase == WorkUnitPhase::StagedNotAssigned
                && phases.get(&id) == Some(&WorkUnitPhase::Quarantined);
            assert!(rank >= *previous || restarted, "effect regression for {id}");
        }
        effect_ranks.insert(id.clone(), rank);
        phases.insert(id, record.phase);
    }
    let holders = machine.scope_holders();
    let unique = holders.values().collect::<BTreeSet<_>>();
    assert_eq!(holders.len(), unique.len(), "scope writer collision");
    for holder in unique {
        assert!(
            machine.record(holder).is_some(),
            "scope held by unknown unit"
        );
    }
}

fn seeded_sequence(min_steps: u64, max_steps: u64, rng: &mut u64) -> TestResult {
    let steps = usize::try_from(min_steps + next_rand(rng) % (max_steps - min_steps + 1))
        .map_err(|_| "steps")?;
    let fixture = Fixture::default();
    let mut machine = fixture.machine();
    let work = "seq-unit";
    let scope = "scope-seq";
    machine.admit(admitted_def(work, scope, vec![])?, "seq-admit")?;
    machine.stage_work(&wid(work)?, "seq-stage")?;
    machine.assign(&wid(work)?, owner_for(work)?, "seq-assign")?;
    machine.admit(
        admitted_def("seq-child", "scope-seq-child", vec![])?,
        "seq-child-admit",
    )?;
    machine.stage_work(&wid("seq-child")?, "seq-child-stage")?;

    let mut digests: BTreeMap<String, String> = BTreeMap::new();
    let mut effect_ranks: BTreeMap<String, u8> = BTreeMap::new();
    let mut phases: BTreeMap<String, WorkUnitPhase> = BTreeMap::new();
    for record in machine.all_records() {
        digests.insert(
            record.work_id.as_str().to_owned(),
            record.definition_digest.clone(),
        );
        effect_ranks.insert(record.work_id.as_str().to_owned(), record.effect.rank());
        phases.insert(record.work_id.as_str().to_owned(), record.phase);
    }
    for step in 0..steps {
        let choice = next_rand(rng) % 16;
        apply_seeded_op(&mut machine, work, choice, step, rng)?;
        assert_sequence_invariants(&machine, &mut digests, &mut effect_ranks, &mut phases);
    }
    Ok(())
}

// WORK_UNIT_CASE: 698/39
#[test]
fn durable_work_case_39_source_guard_excludes_second_owner_and_finish() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "Command::new",
        "std::process",
        "tokio::spawn",
        "ModelRegistry",
        "TaskStore",
        "AttemptJournal",
        "Scheduler",
        "VERIFIED_COMPLETE",
        "commit_effect",
        "TcpListener",
        "UdpSocket",
        "reqwest",
        "issue_grant",
        "GrantIssuer",
        "fn finish",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden second-owner/transport/spawn/authority/effect/finish surface: {forbidden}"
        );
    }
    assert!(source.contains("pub mod durable_work"));
    assert!(source.contains("DurableWorkStore"));
    assert!(source.contains("WorkExecutor"));
    assert!(source.contains("RouteCatalogue"));
    assert!(source.contains("PeerChannel"));
}

fn fail_store_once(fixture: &Fixture) -> TestResult {
    *fixture.store.fail_appends.lock().map_err(|_| "lock")? = 1;
    Ok(())
}

fn assert_no_false_completion(records: &[DurableWorkRecord]) {
    for record in records {
        if record.phase == WorkUnitPhase::Terminal {
            assert!(record.terminal.is_some());
        }
        assert_ne!(record.phase, WorkUnitPhase::CompletionCandidate);
    }
}

fn inject_admission_fault(stage: &str) -> Result<Vec<DurableWorkRecord>, Box<dyn Error>> {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    match stage {
        "stage" => {
            machine.admit(
                admitted_def("case-40-s", "scope-case-40-s", vec![])?,
                "case-40-s-admit",
            )?;
            fail_store_once(&fixture)?;
            assert_eq!(
                machine.stage_work(&wid("case-40-s")?, "case-40-s-stage"),
                Err(SwarmError::Provider {
                    provider: RequiredProvider::DurabilityStore,
                    source: ProviderError::Failed,
                })
            );
            assert_eq!(
                machine.record(&wid("case-40-s")?).ok_or("missing")?.phase,
                WorkUnitPhase::AdmittedNotStaged
            );
            machine.stage_work(&wid("case-40-s")?, "case-40-s-stage-retry")?;
        }
        "assign" => {
            drive_staged(&mut machine, "case-40-a", "scope-case-40-a", vec![])?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .assign(
                        &wid("case-40-a")?,
                        owner_for("case-40-a")?,
                        "case-40-a-assign"
                    )
                    .is_err()
            );
            assert_eq!(
                machine.record(&wid("case-40-a")?).ok_or("missing")?.phase,
                WorkUnitPhase::StagedNotAssigned
            );
            machine.assign(
                &wid("case-40-a")?,
                owner_for("case-40-a")?,
                "case-40-a-retry",
            )?;
        }
        "launch-intent" => {
            drive_assigned(&mut machine, "case-40-li", "scope-case-40-li")?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .request_launch(&wid("case-40-li")?, "case-40-li-launch")
                    .is_err()
            );
            assert_eq!(
                machine.record(&wid("case-40-li")?).ok_or("missing")?.phase,
                WorkUnitPhase::Assigned
            );
            machine.request_launch(&wid("case-40-li")?, "case-40-li-retry")?;
            assert_eq!(
                machine.record(&wid("case-40-li")?).ok_or("missing")?.phase,
                WorkUnitPhase::Running
            );
        }
        "launch-outcome" => {
            fixture
                .executor
                .set_mode("case-40-lo", LaunchMode::UnknownSilent)?;
            drive_assigned(&mut machine, "case-40-lo", "scope-case-40-lo")?;
            let unknown = machine.request_launch(&wid("case-40-lo")?, "case-40-lo-launch")?;
            assert_eq!(unknown.phase, WorkUnitPhase::UnknownOutcome);
        }
        _ => return Err("unknown admission fault stage".into()),
    }
    Ok(machine.all_records())
}

fn inject_execution_fault(stage: &str) -> Result<Vec<DurableWorkRecord>, Box<dyn Error>> {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    match stage {
        "heartbeat" => {
            let running = drive_running(&mut machine, "case-40-h", "scope-case-40-h")?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .heartbeat(&wid("case-40-h")?, &heartbeat_for(&running, 1)?)
                    .is_err()
            );
            assert_eq!(
                machine
                    .record(&wid("case-40-h")?)
                    .ok_or("missing")?
                    .heartbeat_sequence,
                0
            );
        }
        "checkpoint" => {
            let running = drive_running(&mut machine, "case-40-c", "scope-case-40-c")?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .checkpoint(
                        &wid("case-40-c")?,
                        checkpoint_for(&running, "cp")?,
                        "case-40-c-cp"
                    )
                    .is_err()
            );
            assert_eq!(
                machine.record(&wid("case-40-c")?).ok_or("missing")?.phase,
                WorkUnitPhase::Running
            );
        }
        "cancel" => {
            drive_running(&mut machine, "case-40-x", "scope-case-40-x")?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .request_cancel(&wid("case-40-x")?, "case-40-x-cancel")
                    .is_err()
            );
            assert_eq!(
                machine.record(&wid("case-40-x")?).ok_or("missing")?.phase,
                WorkUnitPhase::Running
            );
        }
        "complete" => {
            let running = drive_running(&mut machine, "case-40-d", "scope-case-40-d")?;
            fail_store_once(&fixture)?;
            assert!(
                machine
                    .submit_result(
                        &wid("case-40-d")?,
                        result_for(&running, Some("ev"))?,
                        "case-40-d-r"
                    )
                    .is_err()
            );
            assert_eq!(
                machine.record(&wid("case-40-d")?).ok_or("missing")?.phase,
                WorkUnitPhase::Running
            );
        }
        _ => return Err("unknown execution fault stage".into()),
    }
    Ok(machine.all_records())
}

fn assert_response_loss_recovery() -> Result<Vec<DurableWorkRecord>, Box<dyn Error>> {
    let fixture = Fixture::with_log();
    let mut machine = fixture.machine();
    drive_assigned(&mut machine, "case-40-r", "scope-case-40-r")?;
    *fixture.store.response_loss.lock().map_err(|_| "lock")? = true;
    assert_eq!(
        machine.request_launch(&wid("case-40-r")?, "case-40-r-launch"),
        Err(SwarmError::Provider {
            provider: RequiredProvider::DurabilityStore,
            source: ProviderError::Unknown,
        })
    );
    *fixture.store.response_loss.lock().map_err(|_| "lock")? = false;
    let expected =
        u64::try_from(fixture.store.log_records("case-40-r")?.len()).map_err(|_| "len")?;
    let (recovered, outcome) = machine.recover_after_uncertain_persist(
        &wid("case-40-r")?,
        expected,
        "case-40-r-recover",
    )?;
    assert_eq!(outcome, UncertainPersistOutcome::Recovered);
    assert_eq!(recovered.sequence, expected);
    Ok(machine.all_records())
}

// WORK_UNIT_CASE: 698/40
#[test]
fn durable_work_case_40_injected_failures_preserve_no_lost_child() -> TestResult {
    let profile = fixture_profile()?;
    let stages = profile["fault_stages"]
        .as_array()
        .ok_or("fault stages")?
        .iter()
        .map(|value| value.as_str().ok_or("stage string"))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(stages.len(), 8);

    let mut accounted: Vec<DurableWorkRecord> = Vec::new();
    for stage in &stages {
        if *stage == "heartbeat"
            || *stage == "checkpoint"
            || *stage == "cancel"
            || *stage == "complete"
        {
            accounted.extend(inject_execution_fault(stage)?);
        } else {
            accounted.extend(inject_admission_fault(stage)?);
        }
    }
    accounted.extend(assert_response_loss_recovery()?);
    assert_no_false_completion(&accounted);
    Ok(())
}
