use std::{collections::BTreeMap, error::Error, sync::Mutex};

use eliot_agent_contracts::{AgentAttemptState, ContinuityKind, Route, WorkItemState};
use eliot_receipts::{ReceiptCore, WorkScopeBinding};
use serde_json::{Value, json};

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn fence() -> Value {
    json!({
        "authority_epoch": 1,
        "resource_generation": 1,
        "task_revision": 1,
        "policy_revision": null,
        "integration_revision": null
    })
}

fn work_scope() -> Result<WorkScopeBinding, serde_json::Error> {
    serde_json::from_value(json!({
        "scope_id": "scope-1",
        "product_id": "product-1",
        "resource_generation": 1,
        "state_fence": fence()
    }))
}

fn evidence() -> Result<EvidenceEnvelope, serde_json::Error> {
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

fn assurance() -> Result<SourceAssurance, serde_json::Error> {
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

fn binding(
    work_item_id: &str,
    role_id: &str,
    route_id: &str,
    lease_id: &str,
    plan_revision: &str,
    root_revision: &str,
) -> Result<ProviderBinding, Box<dyn Error>> {
    let scope = work_scope()?;
    Ok(ProviderBinding {
        task_id: "task-1".to_owned(),
        session_id: "session-1".to_owned(),
        work_scope_id: "scope-1".to_owned(),
        work_scope_digest: digest(&scope)?,
        state_fence_digest: digest(&scope.state_fence)?,
        authority_fence_digest: digest(&scope.state_fence)?,
        root_context_revision: RootContextRevision::new(root_revision)?,
        task_revision: "1".to_owned(),
        plan_revision: RevisionId::new(plan_revision)?,
        receipt_contract_revision: eliot_receipts::contract_identity()?.version.to_string(),
        work_contract_revision: "contract-1".to_owned(),
        work_item_id: WorkItemId::new(work_item_id)?,
        role_id: RoleId::new(role_id)?,
        route_id: route_id.to_owned(),
        lease_id: lease_id.to_owned(),
        reviewer_attempt_id: None,
        affected_branch: None,
    })
}

fn receipt_for(owner: &str, request: &ProviderRequest) -> Result<ReceiptEnvelope, ProviderError> {
    receipt_for_attestation(owner, request, None)
}

fn receipt_for_attestation(
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
            "authority_epoch": 1,
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
            "authority_epoch": 1,
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
    let core: ReceiptCore = serde_json::from_value(value).map_err(|_| ProviderError::Invalid)?;
    ReceiptEnvelope::issue(core).map_err(|_| ProviderError::Invalid)
}

#[derive(Default)]
struct A02 {
    cursors: Mutex<BTreeMap<String, u64>>,
    lineages: Mutex<BTreeMap<String, String>>,
    contaminated: bool,
    forged_task: bool,
}

impl A02 {
    fn set_lineage(&self, work_item_id: &str, lineage: &str) -> Result<(), ProviderError> {
        self.lineages
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .insert(work_item_id.to_owned(), lineage.to_owned());
        Ok(())
    }
}

impl AgentRouteProvider for A02 {
    fn current_cursor(&self, stream_id: &str) -> Result<u64, ProviderError> {
        Ok(*self
            .cursors
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(stream_id)
            .unwrap_or(&0))
    }

    fn seal(&self, request: &ProviderRequest) -> Result<ProviderOutcome, ProviderError> {
        let committed_cursor = if let Some(replay) = &request.replay {
            let mut cursors = self.cursors.lock().map_err(|_| ProviderError::Failed)?;
            let current = *cursors.get(&replay.stream_id).unwrap_or(&0);
            if current != replay.prior_cursor || replay.next_cursor != current.saturating_add(1) {
                return Err(ProviderError::Invalid);
            }
            cursors.insert(replay.stream_id.clone(), replay.next_cursor);
            Some(replay.next_cursor)
        } else {
            None
        };
        let attestation = match request.operation_kind.as_str() {
            "swarm.map.seal" | "swarm.blind-audit.seal" => ProviderAttestation::Independent {
                source_assurance: Box::new(assurance().map_err(|_| ProviderError::Invalid)?),
                evidence: Box::new(evidence().map_err(|_| ProviderError::Invalid)?),
                sealed_before_peer_disclosure: !self.contaminated,
                all_disclosures_predate_candidate: !self.contaminated,
                no_sibling_finding_disclosed: !self.contaminated,
            },
            "swarm.synthesis.contribution" => ProviderAttestation::Lineage {
                lineage_digest: self
                    .lineages
                    .lock()
                    .map_err(|_| ProviderError::Failed)?
                    .get(request.binding.work_item_id.as_str())
                    .cloned()
                    .unwrap_or_else(|| {
                        format!("lineage-{}", request.binding.work_item_id.as_str())
                    }),
                provenance_digest: request.artifact_digest.clone(),
            },
            _ => ProviderAttestation::None,
        };
        let mut receipt = receipt_for_attestation("A-02", request, Some(&attestation))?;
        if self.forged_task {
            receipt
                .core
                .task
                .as_mut()
                .ok_or(ProviderError::Invalid)?
                .task_id =
                serde_json::from_value(json!("other-task")).map_err(|_| ProviderError::Invalid)?;
            receipt = ReceiptEnvelope::issue(receipt.core).map_err(|_| ProviderError::Invalid)?;
        }
        Ok(ProviderOutcome {
            receipt,
            attestation,
            committed_cursor,
        })
    }
}

struct Trusted;

impl ReceiptVerificationPort for Trusted {
    fn verify(&self, _receipt: &ReceiptEnvelope) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[derive(Clone)]
struct WorkSpec<'a> {
    id: &'a str,
    dependencies: &'a [&'a str],
}

fn work(spec: &WorkSpec<'_>, plan_revision: &str) -> Result<WorkItem, Box<dyn Error>> {
    Ok(WorkItem {
        work_item_id: WorkItemId::new(spec.id)?,
        responsibility: format!("investigate {}", spec.id),
        plan_revision: RevisionId::new(plan_revision)?,
        wave_revision: RevisionId::new("wave-1")?,
        dependency_ids: spec
            .dependencies
            .iter()
            .map(|id| WorkItemId::new(*id))
            .collect::<Result<Vec<_>, _>>()?,
        overlap_ids: Vec::new(),
        assigned_attempt_id: None,
        assigned_role: None,
        mailbox_route_handle: None,
        state: WorkItemState::Planned,
    })
}

fn map(spec: &WorkSpec<'_>) -> Result<IndependentMapSubmission, Box<dyn Error>> {
    Ok(IndependentMapSubmission {
        lane_id: LaneId::new(spec.id)?,
        root_context_revision: RootContextRevision::new("root-1")?,
        dependency_sketch: spec
            .dependencies
            .iter()
            .map(|id| LaneId::new(*id))
            .collect::<Result<Vec<_>, _>>()?,
        unknowns: vec!["unknown".to_owned()],
        candidate_subquestions: vec!["bounded subquestion".to_owned()],
        likely_overlaps: Vec::new(),
        provider_binding: binding(
            spec.id,
            &format!("role-{}", spec.id),
            &format!("route-{}", spec.id),
            &format!("lease-{}", spec.id),
            "plan-1",
            "root-1",
        )?,
    })
}

fn sealed_maps(
    provider: &A02,
    specs: &[WorkSpec<'_>],
) -> Result<SealedIndependentMaps, Box<dyn Error>> {
    Ok(collect_independent_maps(
        specs
            .iter()
            .map(|spec| LaneId::new(spec.id))
            .collect::<Result<Vec<_>, _>>()?,
        specs.iter().map(map).collect::<Result<Vec<_>, _>>()?,
        Some(provider),
        Some(&Trusted),
    )?)
}

fn admitted_plan(
    provider: &A02,
    specs: &[WorkSpec<'_>],
    global_wip: u32,
    route_wip: u32,
    fan_in: u32,
) -> Result<AdmittedSwarmPlan, Box<dyn Error>> {
    let maps = sealed_maps(provider, specs)?;
    let proposal = SwarmPlanProposal {
        plan_revision: RevisionId::new("plan-1")?,
        root_context_revision: RootContextRevision::new("root-1")?,
        work_items: specs
            .iter()
            .map(|spec| work(spec, "plan-1"))
            .collect::<Result<Vec<_>, _>>()?,
        branch_roots: specs
            .iter()
            .filter(|spec| spec.dependencies.is_empty())
            .map(|spec| -> Result<_, Box<dyn Error>> {
                Ok((BranchId::new(spec.id)?, WorkItemId::new(spec.id)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?,
        global_wip,
        per_route_wip: route_wip,
        reduction_fan_in: fan_in,
        preserved_partition_dissent: vec!["partition dissent".to_owned()],
    };
    let request = plan_admission_request(&proposal, &maps)?;
    let receipt = receipt_for("Governor", &request)?;
    Ok(admit_plan(proposal, &maps, receipt, Some(&Trusted))?)
}

fn assigned(
    plan: &AdmittedSwarmPlan,
    work_item_id: &str,
    route_id: &str,
) -> Result<WaveAssignment, Box<dyn Error>> {
    let mut item = plan
        .work_items()
        .iter()
        .find(|item| item.work_item_id.as_str() == work_item_id)
        .ok_or("missing work item")?
        .clone();
    let attempt_id = AgentAttemptId::new(format!("attempt-{work_item_id}"))?;
    let role_id = RoleId::new(format!("role-{work_item_id}"))?;
    item.assigned_attempt_id = Some(attempt_id.clone());
    item.assigned_role = Some(role_id.as_str().to_owned());
    item.mailbox_route_handle = Some(route_id.to_owned());
    item.state = WorkItemState::Assigned;
    let launch_attempt: LaunchAttempt = serde_json::from_value(json!({
        "id": format!("attempt-{work_item_id}"),
        "launch_request_id": format!("launch-{work_item_id}"),
        "task_id": "task-1",
        "parent_attempt": null,
        "work_unit": {
            "id": work_item_id,
            "objective": "bounded objective",
            "causal_property": "one-property",
            "scope_ref": "scope-1",
            "expected_outputs": ["candidate"],
            "source_refs": ["source-1"],
            "verifier_ref": "verifier-1",
            "integration_owner": "other-owner",
            "contract_revision": "contract-1",
            "budget": {"context_tokens": 10, "wall_time_ms": 10, "output_bytes": 10,
                "cost_microunits": 10, "max_depth": 1, "max_descendants": 0},
            "effect_ceiling": {"scope_ref": "scope-1", "allowed": ["observe"],
                "max_external_effects": 0},
            "stop_condition": "bounded"
        },
        "session": "session-1",
        "lease": format!("lease-{work_item_id}"),
        "state": "ADMITTED",
        "continuity": "Fresh",
        "route": {
            "host_family": "host", "adapter": "adapter", "protocol_transport": "transport",
            "runtime_hash": "runtime", "adapter_hash": "adapter-hash", "provider": "provider",
            "model": "model", "auth_billing": "billing", "serializer_hash": "serializer",
            "tool_semantics_hash": "tools", "reasoning_mode": "reasoning",
            "continuation_behavior": "fresh", "feature_flags_hash": "features"
        },
        "budget": {"context_tokens": 10, "wall_time_ms": 10, "output_bytes": 10,
            "cost_microunits": 10, "max_depth": 1, "max_descendants": 0},
        "authority": {
            "epoch": 1, "scope_ref": "scope-1",
            "effect_ceiling": {"scope_ref": "scope-1", "allowed": ["observe"],
                "max_external_effects": 0},
            "lease": format!("lease-{work_item_id}"),
            "state_fence": fence(),
            "valid_until": "later"
        },
        "cancellation": "NOT_REQUESTED",
        "event_cursor": null,
        "continuation": null
    }))?;
    let attempt = AgentAttempt {
        attempt_id,
        work_item_id: item.work_item_id.clone(),
        route: Route {
            route_id: RouteId::new(route_id)?,
            adapter_id: "adapter".to_owned(),
            fingerprint: digest(&launch_attempt.route)?,
            continuity: ContinuityKind::Fresh,
        },
        state: AgentAttemptState::Admitted,
        state_fence: serde_json::from_value(fence())?,
        evidence_refs: Vec::new(),
        parent_attempt_id: None,
    };
    Ok(WaveAssignment {
        work_item: item,
        attempt,
        launch_attempt,
        role_id,
    })
}

fn terminal(
    work_item_id: &str,
    disposition: TerminalDisposition,
) -> Result<TerminalWorkUpdate, Box<dyn Error>> {
    Ok(TerminalWorkUpdate {
        work_item_id: WorkItemId::new(work_item_id)?,
        attempt_id: AgentAttemptId::new(format!("attempt-{work_item_id}"))?,
        disposition,
        evidence_digest: format!("evidence-{work_item_id}"),
    })
}

#[test]
fn p1_accepts_only_provider_sealed_independence_and_exact_binding() -> TestResult {
    let specs = [WorkSpec {
        id: "lane-a",
        dependencies: &[],
    }];
    let submission = map(&specs[0])?;
    assert_eq!(
        collect_independent_maps(
            vec![LaneId::new("lane-a")?],
            vec![submission.clone()],
            None,
            Some(&Trusted),
        ),
        Err(SwarmError::PlanGap(RequiredProvider::A02))
    );
    let contaminated = A02 {
        contaminated: true,
        ..A02::default()
    };
    assert_eq!(
        collect_independent_maps(
            vec![LaneId::new("lane-a")?],
            vec![submission.clone()],
            Some(&contaminated),
            Some(&Trusted),
        ),
        Err(SwarmError::BlindAuditContaminated)
    );
    let forged = A02 {
        forged_task: true,
        ..A02::default()
    };
    assert_eq!(
        collect_independent_maps(
            vec![LaneId::new("lane-a")?],
            vec![submission],
            Some(&forged),
            Some(&Trusted),
        ),
        Err(SwarmError::BindingMismatch)
    );
    Ok(())
}

#[test]
fn p2_rejects_root_drift_partition_drift_and_dependency_cycles() -> TestResult {
    let provider = A02::default();
    let specs = [
        WorkSpec {
            id: "lane-a",
            dependencies: &["lane-b"],
        },
        WorkSpec {
            id: "lane-b",
            dependencies: &["lane-a"],
        },
    ];
    let maps = sealed_maps(&provider, &specs)?;
    let mut proposal = SwarmPlanProposal {
        plan_revision: RevisionId::new("plan-1")?,
        root_context_revision: RootContextRevision::new("root-2")?,
        work_items: specs
            .iter()
            .map(|spec| work(spec, "plan-1"))
            .collect::<Result<Vec<_>, _>>()?,
        branch_roots: BTreeMap::new(),
        global_wip: 2,
        per_route_wip: 1,
        reduction_fan_in: 2,
        preserved_partition_dissent: Vec::new(),
    };
    let request = plan_admission_request(&proposal, &maps)?;
    assert_eq!(
        admit_plan(
            proposal.clone(),
            &maps,
            receipt_for("Governor", &request)?,
            Some(&Trusted),
        ),
        Err(SwarmError::StaleLineage)
    );
    proposal.root_context_revision = RootContextRevision::new("root-1")?;
    let request = plan_admission_request(&proposal, &maps)?;
    assert_eq!(
        admit_plan(
            proposal,
            &maps,
            receipt_for("Governor", &request)?,
            Some(&Trusted),
        ),
        Err(SwarmError::DependencyCycle)
    );
    Ok(())
}

#[test]
fn p2_rejects_non_planned_work_items() -> TestResult {
    let provider = A02::default();
    let specs = [WorkSpec {
        id: "lane-a",
        dependencies: &[],
    }];
    let maps = sealed_maps(&provider, &specs)?;
    let mut item = work(&specs[0], "plan-1")?;
    item.state = WorkItemState::Completed;
    let proposal = SwarmPlanProposal {
        plan_revision: RevisionId::new("plan-1")?,
        root_context_revision: RootContextRevision::new("root-1")?,
        work_items: vec![item],
        branch_roots: BTreeMap::from([(BranchId::new("lane-a")?, WorkItemId::new("lane-a")?)]),
        global_wip: 1,
        per_route_wip: 1,
        reduction_fan_in: 1,
        preserved_partition_dissent: Vec::new(),
    };
    let request = plan_admission_request(&proposal, &maps)?;
    assert_eq!(
        admit_plan(
            proposal,
            &maps,
            receipt_for("Governor", &request)?,
            Some(&Trusted),
        ),
        Err(SwarmError::Contract)
    );
    Ok(())
}

#[test]
fn p3_enforces_cumulative_wip_dependency_release_and_unknown_fencing() -> TestResult {
    let provider = A02::default();
    let specs = [
        WorkSpec {
            id: "lane-a",
            dependencies: &[],
        },
        WorkSpec {
            id: "lane-b",
            dependencies: &[],
        },
        WorkSpec {
            id: "lane-c",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(&provider, &specs, 2, 1, 3)?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let first = admit_wave(
        &plan,
        &state,
        vec![assigned(&plan, "lane-a", "route-x")?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert_eq!(
        admit_wave(
            &plan,
            first.state(),
            vec![assigned(&plan, "lane-b", "route-x")?],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::RouteWipExceeded)
    );
    let second = admit_wave(
        &plan,
        first.state(),
        vec![assigned(&plan, "lane-b", "route-y")?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert_eq!(
        admit_wave(
            &plan,
            second.state(),
            vec![assigned(&plan, "lane-c", "route-z")?],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::GlobalWipExceeded)
    );
    let unknown = apply_terminal_updates(
        &plan,
        second.state(),
        vec![terminal("lane-a", TerminalDisposition::UnknownOutcome)?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert_eq!(
        admit_wave(
            &plan,
            &unknown,
            vec![assigned(&plan, "lane-c", "route-z")?],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::GlobalWipExceeded)
    );
    let released = apply_terminal_updates(
        &plan,
        &unknown,
        vec![terminal("lane-a", TerminalDisposition::Completed)?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert!(
        admit_wave(
            &plan,
            &released,
            vec![assigned(&plan, "lane-c", "route-z")?],
            Some(&provider),
            Some(&Trusted),
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn p3_requires_completed_dependencies_before_child_admission() -> TestResult {
    let dependency_provider = A02::default();
    let dependency_specs = [
        WorkSpec {
            id: "root",
            dependencies: &[],
        },
        WorkSpec {
            id: "child",
            dependencies: &["root"],
        },
    ];
    let dependency_plan = admitted_plan(&dependency_provider, &dependency_specs, 2, 2, 2)?;
    let dependency_state =
        begin_execution(&dependency_plan, Some(&dependency_provider), Some(&Trusted))?;
    assert_eq!(
        admit_wave(
            &dependency_plan,
            &dependency_state,
            vec![assigned(&dependency_plan, "child", "route-child")?],
            Some(&dependency_provider),
            Some(&Trusted),
        ),
        Err(SwarmError::DependencyNotReady)
    );
    let root = admit_wave(
        &dependency_plan,
        &dependency_state,
        vec![assigned(&dependency_plan, "root", "route-root")?],
        Some(&dependency_provider),
        Some(&Trusted),
    )?;
    let root_done = apply_terminal_updates(
        &dependency_plan,
        root.state(),
        vec![terminal("root", TerminalDisposition::Completed)?],
        Some(&dependency_provider),
        Some(&Trusted),
    )?;
    assert!(
        admit_wave(
            &dependency_plan,
            &root_done,
            vec![assigned(&dependency_plan, "child", "route-child")?],
            Some(&dependency_provider),
            Some(&Trusted),
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn p3_rejects_scope_fence_contract_and_lease_mismatch() -> TestResult {
    let provider = A02::default();
    let specs = [WorkSpec {
        id: "lane-a",
        dependencies: &[],
    }];
    let plan = admitted_plan(&provider, &specs, 1, 1, 1)?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let mut wrong_scope = assigned(&plan, "lane-a", "route-a")?;
    wrong_scope.launch_attempt.work_unit.scope_ref = "other-scope".to_owned();
    assert_eq!(
        admit_wave(
            &plan,
            &state,
            vec![wrong_scope],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::AssignmentMismatch)
    );
    let mut wrong_fence = assigned(&plan, "lane-a", "route-a")?;
    wrong_fence.launch_attempt.authority.state_fence = serde_json::from_value(json!({
        "authority_epoch": 2,
        "resource_generation": 1,
        "task_revision": null,
        "policy_revision": null,
        "integration_revision": null
    }))?;
    assert_eq!(
        admit_wave(
            &plan,
            &state,
            vec![wrong_fence],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::AssignmentMismatch)
    );
    let mut wrong_contract = assigned(&plan, "lane-a", "route-a")?;
    wrong_contract.launch_attempt.work_unit.contract_revision = "other-contract".to_owned();
    assert_eq!(
        admit_wave(
            &plan,
            &state,
            vec![wrong_contract],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::AssignmentMismatch)
    );
    let mut wrong_lease = assigned(&plan, "lane-a", "route-a")?;
    wrong_lease.launch_attempt.lease = eliot_agent_api::WorkLeaseId::new("other-lease")?;
    assert_eq!(
        admit_wave(
            &plan,
            &state,
            vec![wrong_lease],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::AssignmentMismatch)
    );
    let mut wrong_state = assigned(&plan, "lane-a", "route-a")?;
    wrong_state.work_item.state = WorkItemState::Completed;
    assert_eq!(
        admit_wave(
            &plan,
            &state,
            vec![wrong_state],
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::AssignmentMismatch)
    );
    Ok(())
}

fn review_fixture(provider: &A02) -> Result<(AdmittedSwarmPlan, ExecutionState), Box<dyn Error>> {
    let specs = [
        WorkSpec {
            id: "root",
            dependencies: &[],
        },
        WorkSpec {
            id: "child",
            dependencies: &["root"],
        },
        WorkSpec {
            id: "reviewer",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(provider, &specs, 3, 1, 3)?;
    let state = begin_execution(&plan, Some(provider), Some(&Trusted))?;
    let first = admit_wave(
        &plan,
        &state,
        vec![
            assigned(&plan, "root", "route-root")?,
            assigned(&plan, "reviewer", "route-reviewer")?,
        ],
        Some(provider),
        Some(&Trusted),
    )?;
    let completed = apply_terminal_updates(
        &plan,
        first.state(),
        vec![
            terminal("root", TerminalDisposition::Completed)?,
            terminal("reviewer", TerminalDisposition::Completed)?,
        ],
        Some(provider),
        Some(&Trusted),
    )?;
    let child = admit_wave(
        &plan,
        &completed,
        vec![assigned(&plan, "child", "route-child")?],
        Some(provider),
        Some(&Trusted),
    )?;
    Ok((plan, child.into_state()))
}

#[test]
fn p4_rejects_review_without_an_admitted_target_attempt() -> TestResult {
    let provider = A02::default();
    let specs = [
        WorkSpec {
            id: "root",
            dependencies: &[],
        },
        WorkSpec {
            id: "reviewer",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(&provider, &specs, 2, 2, 2)?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let reviewer = admit_wave(
        &plan,
        &state,
        vec![assigned(&plan, "reviewer", "route-reviewer")?],
        Some(&provider),
        Some(&Trusted),
    )?;
    let proposal = CrossReviewProposal {
        plan_revision: plan.revision().clone(),
        work_item_id: WorkItemId::new("root")?,
        reviewer_attempt_id: AgentAttemptId::new("attempt-reviewer")?,
        cause: ReviewCause::ThinEvidence,
        finding: evidence()?,
        affected_branch: BranchId::new("root")?,
        proposed_next_work: "collect discriminating observation".to_owned(),
    };
    assert_eq!(
        accept_cross_review(
            &plan,
            reviewer.state(),
            proposal,
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::ReviewMismatch)
    );
    Ok(())
}

#[test]
fn p4_reviewer_binding_and_descendant_only_replan_are_enforced() -> TestResult {
    let provider = A02::default();
    let (plan, review_state) = review_fixture(&provider)?;
    let proposal = CrossReviewProposal {
        plan_revision: plan.revision().clone(),
        work_item_id: WorkItemId::new("root")?,
        reviewer_attempt_id: AgentAttemptId::new("attempt-reviewer")?,
        cause: ReviewCause::ThinEvidence,
        finding: evidence()?,
        affected_branch: BranchId::new("root")?,
        proposed_next_work: "collect discriminating observation".to_owned(),
    };
    let accepted = accept_cross_review(
        &plan,
        &review_state,
        proposal.clone(),
        Some(&provider),
        Some(&Trusted),
    )?;
    let mut wrong_reviewer = proposal;
    wrong_reviewer.reviewer_attempt_id = AgentAttemptId::new("attempt-root")?;
    assert_eq!(
        accept_cross_review(
            &plan,
            &review_state,
            wrong_reviewer,
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::ReviewMismatch)
    );
    let mut root_replacement = plan.work_items()[0].clone();
    root_replacement.plan_revision = RevisionId::new("plan-2")?;
    root_replacement.wave_revision = RevisionId::new("wave-2")?;
    root_replacement.responsibility = "replanned root".to_owned();
    let mut child_replacement = plan.work_items()[1].clone();
    child_replacement.plan_revision = RevisionId::new("plan-2")?;
    child_replacement.wave_revision = RevisionId::new("wave-2")?;
    child_replacement.responsibility = "replanned descendant".to_owned();
    let replan = SelectiveReplanProposal {
        prior_revision: plan.revision().clone(),
        next_revision: RevisionId::new("plan-2")?,
        replacements: vec![root_replacement, child_replacement],
    };
    let request = replan_admission_request(&plan, std::slice::from_ref(&accepted), &replan)?;
    let next = selectively_replan(
        &plan,
        std::slice::from_ref(&accepted),
        &replan,
        receipt_for("Governor", &request)?,
        Some(&Trusted),
    )?;
    assert_eq!(
        next.work_items()[2].responsibility,
        plan.work_items()[2].responsibility
    );
    let mut unrelated = plan.work_items()[2].clone();
    unrelated.plan_revision = RevisionId::new("plan-2")?;
    let invalid = SelectiveReplanProposal {
        prior_revision: plan.revision().clone(),
        next_revision: RevisionId::new("plan-2")?,
        replacements: vec![unrelated],
    };
    let invalid_request =
        replan_admission_request(&plan, std::slice::from_ref(&accepted), &invalid)?;
    assert_eq!(
        selectively_replan(
            &plan,
            &[accepted],
            &invalid,
            receipt_for("Governor", &invalid_request)?,
            Some(&Trusted),
        ),
        Err(SwarmError::UnaffectedBranchMutation)
    );
    Ok(())
}

#[test]
fn blind_audit_independence_is_provider_observed() -> TestResult {
    let provider = A02::default();
    let specs = [
        WorkSpec {
            id: "candidate",
            dependencies: &[],
        },
        WorkSpec {
            id: "auditor",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(&provider, &specs, 2, 1, 2)?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let wave = admit_wave(
        &plan,
        &state,
        vec![
            assigned(&plan, "candidate", "route-candidate")?,
            assigned(&plan, "auditor", "route-auditor")?,
        ],
        Some(&provider),
        Some(&Trusted),
    )?;
    let packet = BlindAuditPacket {
        plan_revision: plan.revision().clone(),
        root_context_revision: RootContextRevision::new("root-1")?,
        work_item_id: WorkItemId::new("candidate")?,
        acceptance_ref: "acceptance-1".to_owned(),
        candidate_digest: "candidate-digest".to_owned(),
        verifier_state_ref: "verifier-state".to_owned(),
        preexisting_invariants: vec![DisclosureFact {
            reference: "canonical-invariant".to_owned(),
        }],
        coverage_gaps: Vec::new(),
    };
    let contaminated = A02 {
        contaminated: true,
        ..A02::default()
    };
    assert_eq!(
        accept_blind_audit(
            &plan,
            wave.state(),
            &AgentAttemptId::new("attempt-auditor")?,
            packet.clone(),
            Some(&contaminated),
            Some(&Trusted),
        ),
        Err(SwarmError::BlindAuditContaminated)
    );
    assert!(
        accept_blind_audit(
            &plan,
            wave.state(),
            &AgentAttemptId::new("attempt-auditor")?,
            packet,
            Some(&provider),
            Some(&Trusted),
        )
        .is_ok()
    );
    Ok(())
}

fn accepted_contribution(
    plan: &AdmittedSwarmPlan,
    state: &ExecutionState,
    provider: &A02,
    work_item_id: &str,
    stance: Stance,
) -> Result<AcceptedSynthesisContribution, Box<dyn Error>> {
    Ok(accept_synthesis_contribution(
        plan,
        state,
        SynthesisContribution {
            work_item_id: WorkItemId::new(work_item_id)?,
            plan_revision: plan.revision().clone(),
            claim_id: ClaimId::new("claim-1")?,
            stance,
            evidence: evidence()?,
        },
        Some(provider),
        Some(&Trusted),
    )?)
}

#[test]
fn p5_collapses_correlated_lineage_and_bounds_concilium_by_plan() -> TestResult {
    let provider = A02::default();
    let specs = [
        WorkSpec {
            id: "lane-a",
            dependencies: &[],
        },
        WorkSpec {
            id: "lane-b",
            dependencies: &[],
        },
        WorkSpec {
            id: "lane-c",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(&provider, &specs, 3, 3, 3)?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let wave = admit_wave(
        &plan,
        &state,
        vec![
            assigned(&plan, "lane-a", "route-a")?,
            assigned(&plan, "lane-b", "route-b")?,
            assigned(&plan, "lane-c", "route-c")?,
        ],
        Some(&provider),
        Some(&Trusted),
    )?;
    let complete = apply_terminal_updates(
        &plan,
        wave.state(),
        vec![
            terminal("lane-a", TerminalDisposition::Completed)?,
            terminal("lane-b", TerminalDisposition::Completed)?,
            terminal("lane-c", TerminalDisposition::Completed)?,
        ],
        Some(&provider),
        Some(&Trusted),
    )?;
    provider.set_lineage("lane-a", "shared-lineage")?;
    provider.set_lineage("lane-b", "shared-lineage")?;
    provider.set_lineage("lane-c", "dissent-lineage")?;
    let correlated = [
        accepted_contribution(&plan, &complete, &provider, "lane-a", Stance::Support)?,
        accepted_contribution(&plan, &complete, &provider, "lane-b", Stance::Support)?,
        accepted_contribution(&plan, &complete, &provider, "lane-c", Stance::Oppose)?,
    ];
    let synthesis = synthesize(&plan, &correlated, Some(&provider), Some(&Trusted))?;
    assert_eq!(synthesis.claims[0].agreement, AgreementShape::NoMajority);
    assert_eq!(synthesis.claims[0].distinct_lineage_count, 2);
    assert_eq!(synthesis.claims[0].support.len(), 2);
    assert_eq!(synthesis.claims[0].dissent.len(), 1);
    assert_eq!(
        admit_concilium(
            &plan,
            &synthesis,
            ConciliumRequest {
                plan_revision: plan.revision().clone(),
                claim_id: ClaimId::new("claim-1")?,
                rival_lineage_digests: vec!["shared-lineage".to_owned()],
                maximum_panel_size: 4,
            },
            "next discriminating observation".to_owned(),
            Some(&provider),
            Some(&Trusted),
        ),
        Err(SwarmError::FanInExceeded)
    );
    assert!(
        admit_concilium(
            &plan,
            &synthesis,
            ConciliumRequest {
                plan_revision: plan.revision().clone(),
                claim_id: ClaimId::new("claim-1")?,
                rival_lineage_digests: vec![
                    "shared-lineage".to_owned(),
                    "dissent-lineage".to_owned(),
                ],
                maximum_panel_size: 2,
            },
            "next discriminating observation".to_owned(),
            Some(&provider),
            Some(&Trusted),
        )
        .is_ok()
    );
    Ok(())
}

#[derive(Default)]
struct M04 {
    cursor: Mutex<u64>,
    snapshots: Mutex<BTreeMap<String, ControllerSnapshot>>,
}

impl M04 {
    fn request(operation_kind: &str, snapshot: &ControllerSnapshot) -> ProviderRequest {
        ProviderRequest {
            operation_kind: operation_kind.to_owned(),
            artifact_digest: snapshot.digest.clone(),
            binding: snapshot.binding.clone(),
            replay: Some(ReplayBinding {
                stream_id: format!("swarm.checkpoint:{}", snapshot.provider_identity),
                prior_cursor: snapshot.sequence.saturating_sub(1),
                next_cursor: snapshot.sequence,
            }),
        }
    }

    fn tamper_completed(&self, snapshot_id: &str) -> TestResult {
        let mut snapshots = self.snapshots.lock().map_err(|_| "snapshot lock")?;
        let snapshot = snapshots.get_mut(snapshot_id).ok_or("missing snapshot")?;
        snapshot
            .completed_work_items
            .insert(WorkItemId::new("forged-work")?);
        snapshot.digest = snapshot_digest(snapshot)?;
        Ok(())
    }
}

impl SwarmCheckpointProvider for M04 {
    fn provider_identity(&self) -> &'static str {
        "m04-store-1"
    }

    fn cursor(&self) -> Result<CheckpointCursor, ProviderError> {
        Ok(CheckpointCursor {
            current: *self.cursor.lock().map_err(|_| ProviderError::Failed)?,
            monotonic_floor: 0,
        })
    }

    fn persist(&self, snapshot: &ControllerSnapshot) -> Result<CheckpointCommit, ProviderError> {
        let mut cursor = self.cursor.lock().map_err(|_| ProviderError::Failed)?;
        if snapshot.sequence != cursor.saturating_add(1) {
            return Err(ProviderError::Invalid);
        }
        *cursor = snapshot.sequence;
        self.snapshots
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .insert(snapshot.snapshot_id.as_str().to_owned(), snapshot.clone());
        Ok(CheckpointCommit {
            snapshot: snapshot.clone(),
            receipt: receipt_for(
                "M-04",
                &Self::request("swarm.controller.checkpoint", snapshot),
            )?,
            cursor: CheckpointCursor {
                current: *cursor,
                monotonic_floor: 0,
            },
        })
    }

    fn restore(&self, snapshot_id: &SnapshotId) -> Result<CheckpointCommit, ProviderError> {
        let snapshot = self
            .snapshots
            .lock()
            .map_err(|_| ProviderError::Failed)?
            .get(snapshot_id.as_str())
            .cloned()
            .ok_or(ProviderError::Unavailable)?;
        Ok(CheckpointCommit {
            receipt: receipt_for(
                "M-04",
                &Self::request("swarm.controller.restore", &snapshot),
            )?,
            snapshot,
            cursor: self.cursor()?,
        })
    }
}

fn restart_fixture(
    provider: &A02,
) -> Result<(AdmittedSwarmPlan, WaveAdmission, ExecutionState), Box<dyn Error>> {
    let specs = [
        WorkSpec {
            id: "lane-a",
            dependencies: &[],
        },
        WorkSpec {
            id: "lane-b",
            dependencies: &[],
        },
    ];
    let plan = admitted_plan(provider, &specs, 2, 2, 2)?;
    let state = begin_execution(&plan, Some(provider), Some(&Trusted))?;
    let wave = admit_wave(
        &plan,
        &state,
        vec![
            assigned(&plan, "lane-a", "route-a")?,
            assigned(&plan, "lane-b", "route-b")?,
        ],
        Some(provider),
        Some(&Trusted),
    )?;
    let observed = apply_terminal_updates(
        &plan,
        wave.state(),
        vec![
            terminal("lane-a", TerminalDisposition::Completed)?,
            terminal("lane-b", TerminalDisposition::UnknownOutcome)?,
        ],
        Some(provider),
        Some(&Trusted),
    )?;
    Ok((plan, wave, observed))
}

#[test]
fn restart_uses_provider_cursor_and_rejects_stale_or_forged_state() -> TestResult {
    let provider = A02::default();
    let (plan, wave, observed) = restart_fixture(&provider)?;
    let store = M04::default();
    let first = checkpoint_controller(
        &plan,
        &observed,
        Some(wave.wave()),
        None,
        ControllerCheckpointInput {
            snapshot_id: SnapshotId::new("snapshot-1")?,
            controller_id: ControllerId::new("controller-1")?,
        },
        CheckpointProviders {
            a02: Some(&provider),
            m04: Some(&store),
            verifier: Some(&Trusted),
        },
    )?;
    assert_eq!(
        restore_controller(
            &plan,
            &first.snapshot_id,
            Some(&provider),
            Some(&store),
            Some(&Trusted),
        )?,
        first
    );
    let advanced = apply_terminal_updates(
        &plan,
        &observed,
        vec![terminal("lane-b", TerminalDisposition::Completed)?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert_eq!(
        restore_controller(
            &plan,
            &first.snapshot_id,
            Some(&provider),
            Some(&store),
            Some(&Trusted),
        ),
        Err(SwarmError::ReplayDetected)
    );
    let second = checkpoint_controller(
        &plan,
        &advanced,
        Some(wave.wave()),
        None,
        ControllerCheckpointInput {
            snapshot_id: SnapshotId::new("snapshot-2")?,
            controller_id: ControllerId::new("controller-2")?,
        },
        CheckpointProviders {
            a02: Some(&provider),
            m04: Some(&store),
            verifier: Some(&Trusted),
        },
    )?;
    assert_eq!(
        restore_controller(
            &plan,
            &first.snapshot_id,
            Some(&provider),
            Some(&store),
            Some(&Trusted),
        ),
        Err(SwarmError::InvalidSnapshot)
    );
    store.tamper_completed(second.snapshot_id.as_str())?;
    assert_eq!(
        restore_controller(
            &plan,
            &second.snapshot_id,
            Some(&provider),
            Some(&store),
            Some(&Trusted),
        ),
        Err(SwarmError::InvalidSnapshot)
    );
    Ok(())
}

#[test]
fn public_surface_remains_candidate_only_and_read_only() -> TestResult {
    let provider = A02::default();
    let plan = admitted_plan(
        &provider,
        &[WorkSpec {
            id: "lane-a",
            dependencies: &[],
        }],
        1,
        1,
        1,
    )?;
    assert_eq!(plan.coordination_map_view()?.entries.len(), 1);
    assert_eq!(RECIPE, "NegotiatedInterdependentInvestigation");
    assert_eq!(SYNTHESIS_PROOF_CEILING, ProofCeiling::CandidateArtifact);
    Ok(())
}

#[test]
fn swarm_case_23_matching_canonical_epoch_and_whole_fence_admits() -> TestResult {
    let provider = A02::default();
    let plan = admitted_plan(
        &provider,
        &[WorkSpec {
            id: "case-23",
            dependencies: &[],
        }],
        1,
        1,
        1,
    )?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let admission = admit_wave(
        &plan,
        &state,
        vec![assigned(&plan, "case-23", "route-case-23")?],
        Some(&provider),
        Some(&Trusted),
    )?;
    assert_eq!(
        admission.state().core.transition_sequence,
        state.core.transition_sequence + 1
    );
    Ok(())
}

#[test]
fn swarm_case_24_each_fence_component_rejects_before_state_or_cursor_mutation() -> TestResult {
    let provider = A02::default();
    let plan = admitted_plan(
        &provider,
        &[WorkSpec {
            id: "case-24",
            dependencies: &[],
        }],
        1,
        1,
        1,
    )?;
    let state = begin_execution(&plan, Some(&provider), Some(&Trusted))?;
    let baseline_state = state.clone();
    let baseline_cursor = provider.current_cursor(&execution_stream(&plan))?;
    let mutations = [
        (
            "authority_epoch",
            json!({
                "authority_epoch": 2,
                "resource_generation": 1,
                "task_revision": 1,
                "policy_revision": null,
                "integration_revision": null
            }),
        ),
        (
            "resource_generation",
            json!({
                "authority_epoch": 1,
                "resource_generation": 2,
                "task_revision": 1,
                "policy_revision": null,
                "integration_revision": null
            }),
        ),
        (
            "task_revision",
            json!({
                "authority_epoch": 1,
                "resource_generation": 1,
                "task_revision": 2,
                "policy_revision": null,
                "integration_revision": null
            }),
        ),
        (
            "policy_revision",
            json!({
                "authority_epoch": 1,
                "resource_generation": 1,
                "task_revision": 1,
                "policy_revision": 2,
                "integration_revision": null
            }),
        ),
        (
            "integration_revision",
            json!({
                "authority_epoch": 1,
                "resource_generation": 1,
                "task_revision": 1,
                "policy_revision": null,
                "integration_revision": 2
            }),
        ),
    ];
    for (name, mutated_fence) in mutations {
        let mut assignment = assigned(&plan, "case-24", "route-case-24")?;
        assignment.launch_attempt.authority.state_fence = serde_json::from_value(mutated_fence)?;
        assert_eq!(
            admit_wave(
                &plan,
                &state,
                vec![assignment],
                Some(&provider),
                Some(&Trusted),
            ),
            Err(SwarmError::AssignmentMismatch),
            "mutation {name} must be rejected"
        );
        assert_eq!(state, baseline_state);
        assert_eq!(
            provider.current_cursor(&execution_stream(&plan))?,
            baseline_cursor
        );
    }
    Ok(())
}

#[test]
fn swarm_case_25_reverse_consumer_source_discriminator_has_no_local_identity_or_fence_bridge() {
    let source = include_str!("lib.rs");
    assert!(!source.contains("expected_fence_digest"));
    assert!(!source.contains("AgentAttemptId::new(recipient_attempt_id"));
    assert!(!source.contains("digest(&value.launch_attempt.authority.state_fence"));
}
