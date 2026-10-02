//! Issue #1746 daemon admission edge. An ORS terminal with no selected task
//! remains intake-only and cannot cross the Material task-bound gate.

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    ColdStartOwnerReadback, ColdStartSurfaceView, GovernorActivationSnapshot,
};
use eliot_ors::{
    ColdStartReadinessClaim, ColdStartReadinessOrsRecord, ColdStartReadinessOwnerKey,
    ColdStartReadinessTerminalDisposition, ColdStartReadinessTerminalReceipt,
};
use eliot_security_contracts::PrivacyClass;
use eliot_workscope::{
    MemoryState, OnboardingLease, OnboardingLeaseState, OnboardingReadinessReceipt,
    ProofReadiness, ReadinessLifecycle, RepositoryLineageIdentity, ScopeIdentity, ScopeKind,
    ScopeResolutionState, TaskBindingState, WorkspaceInstanceIdentity,
};
use eliotd::task_binding_admission::{
    BootstrapAdmission, ColdStartAttachInput, OwnerBoundBootstrapInput,
    TASK_SELECTION_REQUIRED, admit_owner_bound_bootstrap, require_material_bootstrap_for_task_bound,
    seal_dispatched_binding,
};

const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence() -> StateFence {
    StateFence::new(
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("lineage"),
            std::num::NonZeroU64::new(1).expect("epoch sequence"),
        )
        .expect("epoch"),
        ResourceGeneration::genesis(),
    )
}

fn owner_fixture() -> (OnboardingLease, ColdStartReadinessClaim, ColdStartOwnerReadback) {
    let state_fence = fence();
    let lease = OnboardingLease {
        lease_ref: "lease-1746".to_owned(),
        lineage_candidate_ref: "lineage-1746".to_owned(),
        workspace_instance_candidate_ref: "instance-1746".to_owned(),
        privacy_class: PrivacyClass::Internal,
        governing_source_generation: 1,
        compiler_epoch: 1,
        state: OnboardingLeaseState::Ready,
        deadline: 100,
    };
    let lease_bytes = String::from_utf8(canonical_json_bytes(&lease).expect("lease bytes"))
        .expect("UTF-8 lease");
    let claim = ColdStartReadinessClaim::new(
        ColdStartReadinessOwnerKey {
            installation_id: "install-1746".to_owned(),
            lineage_candidate_ref: lease.lineage_candidate_ref.clone(),
            workspace_instance_candidate_ref: lease.workspace_instance_candidate_ref.clone(),
            filesystem_identity_ref: "root-1746".to_owned(),
            vcs_identity_ref: Some("vcs-1746".to_owned()),
            privacy_boundary_ref: "boundary-1746".to_owned(),
            privacy_class: PrivacyClass::Internal,
            governing_source_set_ref: "sources-1746".to_owned(),
            governing_source_generation: 1,
            governing_source_digests: Vec::new(),
            dirty_summary_ref: None,
            state_fence: state_fence.clone(),
        },
        lease.lease_ref.clone(),
        lease.deadline,
        lease_bytes,
    )
    .expect("full readiness claim");
    let receipt = OnboardingReadinessReceipt {
        receipt_ref: "receipt-1746".to_owned(),
        lease_ref: lease.lease_ref.clone(),
        principal_ref: "principal-1746".to_owned(),
        session_ref: "session-1746".to_owned(),
        scope: ScopeIdentity {
            scope_ref: "scope-1746".to_owned(),
            kind: ScopeKind::GitRepo,
            lineage_ref: Some(lease.lineage_candidate_ref.clone()),
            instance_ref: lease.workspace_instance_candidate_ref.clone(),
            root_identity: "root-1746".to_owned(),
            generation: 1,
        },
        scope_descriptor_revision: 1,
        instance: WorkspaceInstanceIdentity {
            instance_ref: lease.workspace_instance_candidate_ref.clone(),
            root_identity: "root-1746".to_owned(),
            vcs_identity_ref: Some("vcs-1746".to_owned()),
            generation: 1,
        },
        lineage: Some(RepositoryLineageIdentity {
            lineage_ref: lease.lineage_candidate_ref.clone(),
            object_store_ref: "objects-1746".to_owned(),
            initial_history_ref: "history-1746".to_owned(),
            normalized_remote_ref: None,
            manifest_identity_ref: None,
        }),
        scope_resolution: ScopeResolutionState::Provisional,
        task_binding: TaskBindingState::None_,
        state_fence: state_fence.clone(),
        governing_source_set_ref: "sources-1746".to_owned(),
        governing_source_generation: 1,
        governance_profile_ref: "governance-1746".to_owned(),
        limiting_integration_evidence: vec!["coverage-unknown".to_owned()],
        route_profile_ref: "route-1746".to_owned(),
        serializer_id: "serializer".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: "c".repeat(64),
        tokenizer_id: "tokenizer".to_owned(),
        tokenizer_version: "1".to_owned(),
        tokenizer_hash: "d".repeat(64),
        projection_source_ref: "projection-1746".to_owned(),
        projection_generation: 1,
        readiness: ReadinessLifecycle::NeedsTask,
        memory_state: MemoryState::Empty,
        missing_inputs: vec!["task".to_owned()],
        next_safe_action: "select_task".to_owned(),
        receipt_revision: 1,
        discovered_source_refs: Vec::new(),
        admitted_source_refs: Vec::new(),
        conflicting_source_refs: Vec::new(),
        unavailable_source_refs: Vec::new(),
        store_identity_ref: None,
        proof_readiness: ProofReadiness::NoProofSurface,
        minimum_understanding_seed: vec!["scope-1746".to_owned()],
        maintenance_recommendations: Vec::new(),
        expiry_tick: lease.deadline,
        scan_receipt_ref: None,
    };
    receipt.validate().expect("valid owner readiness receipt");
    let receipt_bytes = String::from_utf8(canonical_json_bytes(&receipt).expect("receipt bytes"))
        .expect("UTF-8 receipt");
    let record = ColdStartReadinessOrsRecord {
        contract_version: eliot_ors::CONTRACT_VERSION,
        record_key: format!("cold-start-readiness:{}:{:020}", claim.base_identity_digest, 1),
        record_revision: 1,
        claim: claim.clone(),
        terminal: Some(ColdStartReadinessTerminalReceipt {
            disposition: ColdStartReadinessTerminalDisposition::Failed,
            receipt_ref: receipt.receipt_ref.clone(),
            receipt_revision: 1,
            receipt_digest: sha256_hex(receipt_bytes.as_bytes()),
            receipt_bytes,
        }),
    };
    record.validate().expect("valid retained ORS record");
    let surface = ColdStartSurfaceView {
        receipt_ref: receipt.receipt_ref.clone(), lease_ref: receipt.lease_ref.clone(),
        principal_ref: receipt.principal_ref.clone(), session_ref: receipt.session_ref.clone(),
        scope: receipt.scope.clone(), scope_descriptor_revision: receipt.scope_descriptor_revision,
        instance: receipt.instance.clone(), lineage: receipt.lineage.clone(),
        scope_resolution: receipt.scope_resolution, task_binding: receipt.task_binding.clone(),
        state_fence: receipt.state_fence.clone(), governing_source_set_ref: receipt.governing_source_set_ref.clone(),
        governing_source_generation: receipt.governing_source_generation, governance_profile_ref: receipt.governance_profile_ref.clone(),
        limiting_integration_evidence: receipt.limiting_integration_evidence.clone(), route_profile_ref: receipt.route_profile_ref.clone(),
        serializer_id: receipt.serializer_id.clone(), serializer_version: receipt.serializer_version.clone(),
        serializer_options_digest: receipt.serializer_options_digest.clone(), tokenizer_id: receipt.tokenizer_id.clone(),
        tokenizer_version: receipt.tokenizer_version.clone(), tokenizer_hash: receipt.tokenizer_hash.clone(),
        readiness: "NEEDS_TASK".to_owned(), smallest_missing_question: Some("task".to_owned()),
        lease_deadline: lease.deadline, receipt_revision: receipt.receipt_revision,
        proof_readiness: receipt.proof_readiness, missing_inputs: receipt.missing_inputs.clone(),
        next_safe_action: receipt.next_safe_action.clone(), discovered_source_refs: Vec::new(),
        admitted_source_refs: Vec::new(), conflicting_source_refs: Vec::new(), unavailable_source_refs: Vec::new(),
        scan_receipt_ref: None, workspace_instance_ref: receipt.instance.instance_ref.clone(),
        projection_source_ref: receipt.projection_source_ref.clone(), projection_generation: receipt.projection_generation,
    };
    let readback = ColdStartOwnerReadback { record, lease: lease.clone(), receipt, surface };
    (lease, claim, readback)
}

fn current_task_owner_fixture() -> (OnboardingLease, ColdStartReadinessClaim, ColdStartOwnerReadback) {
    let (lease, claim, mut readback) = owner_fixture();
    let receipt = &mut readback.receipt;
    receipt.scope_resolution = ScopeResolutionState::Authenticated;
    receipt.task_binding = TaskBindingState::CurrentTaskContract {
        task_ref: "task-1746".to_owned(),
        task_revision: 1,
        acceptance_digest: "a".repeat(64),
        selection_source_ref: "selection-source-1746".to_owned(),
        evidence_ref: "selection-evidence-1746".to_owned(),
    };
    receipt.readiness = ReadinessLifecycle::ReadyMaterial;
    receipt.missing_inputs.clear();
    receipt.validate().expect("current material owner receipt");
    let terminal = readback.record.terminal.as_mut().expect("retained terminal");
    terminal.disposition = ColdStartReadinessTerminalDisposition::Ready;
    terminal.receipt_bytes = String::from_utf8(canonical_json_bytes(receipt).expect("receipt bytes"))
        .expect("UTF-8 receipt");
    terminal.receipt_digest = sha256_hex(terminal.receipt_bytes.as_bytes());
    readback.surface.scope_resolution = receipt.scope_resolution;
    readback.surface.task_binding = receipt.task_binding.clone();
    readback.surface.readiness = "READY_MATERIAL".to_owned();
    readback.surface.smallest_missing_question = None;
    readback.surface.missing_inputs.clear();
    readback.record.validate().expect("current task owner terminal");
    (lease, claim, readback)
}

#[test]
fn owner_readiness_without_task_is_intake_and_rejected_at_material_gate() {
    let (lease, claim, readback) = owner_fixture();
    let state_fence = fence();
    let attach = ColdStartAttachInput {
        lease,
        readiness_claim: claim,
        expected_surface: readback.surface.clone(),
        state_fence: state_fence.clone(),
    };
    let admitted = admit_owner_bound_bootstrap(&OwnerBoundBootstrapInput {
        attach: &attach,
        owner_readback: &readback,
        coverage: None,
        governance: None,
        activation: None,
        current_selection: None,
        operation_id: "op-1746-original",
        now: 10,
        live_fence: &state_fence,
    })
    .expect("valid retained owner evidence produces bounded intake");
    assert!(matches!(admitted.admission(), BootstrapAdmission::IntakeRequired(_)));
    assert_eq!(admitted.operation_id(), "op-1746-original");

    let selection = eliot_observation::TaskSelectionEvidence {
        task_ref: "task-1746".to_owned(), task_revision: 1,
        acceptance_digest: "a".repeat(64), work_scope_ref: "scope-1746".to_owned(),
        selection_source_ref: "source-1746".to_owned(), evidence_ref: "evidence-1746".to_owned(),
        contamination_flags: Vec::new(),
    };
    let binding = seal_dispatched_binding(
        selection, "task-1746", "scope-1746", "principal-1746", "session-1746",
        &state_fence, 1, "governance-1746", 1, "op-1746-original".to_owned(),
    ).expect("well-shaped task binding");
    let error = require_material_bootstrap_for_task_bound(&binding, admitted.admission())
        .expect_err("an intake bootstrap never grants task-bound Material authority");
    assert_eq!(error.code(), TASK_SELECTION_REQUIRED);
}

#[test]
fn changed_workspace_or_receipt_projection_cannot_reuse_owner_bootstrap() {
    let (lease, claim, readback) = owner_fixture();
    let state_fence = fence();
    let mut attach = ColdStartAttachInput {
        lease,
        readiness_claim: claim,
        expected_surface: readback.surface.clone(),
        state_fence: state_fence.clone(),
    };
    attach.expected_surface.scope.instance_ref = "workspace-other".to_owned();
    assert!(admit_owner_bound_bootstrap(&OwnerBoundBootstrapInput {
        attach: &attach, owner_readback: &readback, coverage: None, governance: None,
        activation: None, current_selection: None, operation_id: "op-1746-original", now: 10,
        live_fence: &state_fence,
    }).is_err(), "changed workspace projection conflicts with exact retained owner row");

    attach.expected_surface = readback.surface.clone();
    attach.expected_surface.receipt_revision += 1;
    assert!(admit_owner_bound_bootstrap(&OwnerBoundBootstrapInput {
        attach: &attach, owner_readback: &readback, coverage: None, governance: None,
        activation: None, current_selection: None, operation_id: "op-1746-original", now: 10,
        live_fence: &state_fence,
    }).is_err(), "stale receipt projection cannot be rebound under the original operation");
}

#[test]
fn ready_task_projection_without_verified_owner_profiles_stays_diagnostic() {
    let (lease, claim, readback) = current_task_owner_fixture();
    let state_fence = fence();
    let attach = ColdStartAttachInput {
        lease,
        readiness_claim: claim,
        expected_surface: readback.surface.clone(),
        state_fence: state_fence.clone(),
    };
    let activation = GovernorActivationSnapshot {
        state_fence: state_fence.clone(),
        owner_revision: 1,
        principal_id: "principal-1746".to_owned(),
        session_id: "session-1746".to_owned(),
        task_id: eliot_contracts::TaskId::new("task-1746").expect("task id"),
        work_unit_id: "work-1746".to_owned(),
        work_scope_id: "scope-1746".to_owned(),
        task_revision: 1,
        plan_id: "plan-1746".to_owned(),
        plan_revision: "1".to_owned(),
    };
    let current = eliot_observation::CurrentTaskSelection {
        task_ref: "task-1746".to_owned(),
        task_revision: 1,
        acceptance_digest: "a".repeat(64),
        work_scope_ref: "scope-1746".to_owned(),
        state_fence: state_fence.clone(),
    };
    let admitted = admit_owner_bound_bootstrap(&OwnerBoundBootstrapInput {
        attach: &attach,
        owner_readback: &readback,
        coverage: None,
        governance: None,
        activation: Some(&activation),
        current_selection: Some(&current),
        operation_id: "op-1746-owner-task",
        now: 10,
        live_fence: &state_fence,
    })
    .expect("current task evidence joins the exact bootstrap but cannot invent missing profiles");
    assert_eq!(admitted.operation_id(), "op-1746-owner-task");
    assert!(matches!(
        admitted.admission(),
        BootstrapAdmission::Diagnostic { reason: "coverage or governance profile evidence is unknown or unverified", .. }
    ));

    let stale = eliot_observation::CurrentTaskSelection {
        acceptance_digest: "b".repeat(64),
        ..current
    };
    assert!(admit_owner_bound_bootstrap(&OwnerBoundBootstrapInput {
        attach: &attach,
        owner_readback: &readback,
        coverage: None,
        governance: None,
        activation: Some(&activation),
        current_selection: Some(&stale),
        operation_id: "op-1746-owner-task",
        now: 10,
        live_fence: &state_fence,
    })
    .is_err(), "changed TaskContract acceptance cannot be silently rebound under the original operation");
}
