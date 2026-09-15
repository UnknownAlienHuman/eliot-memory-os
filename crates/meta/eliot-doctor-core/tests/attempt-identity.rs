// T6-D1 (issue #461): canonical fence-encoding binding for attempt identity.
//
// DEFERRED (exhaustive matrix, follow-up slices): multi-effect identity
// sequences, crash-recovery replay across restarts, verifier-axis binding,
// guarded-with-live-grant approval binding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_doctor_core::{
    AttemptIdentityBinding, BindingArg, ClosedRepairRequest, ClosedRequestParams, DiagnosticBrief,
    EvidenceHandle, ExecutableBinding, RecoveryLease, RegisteredOperation, RepairAttemptIdentity,
    RepairClass, RepairRecipe, RepairRecipeIdentity, RepairRecipeManifest, StateFence,
};
use time::{Duration, OffsetDateTime};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

fn epoch(lineage: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage).expect("valid test lineage"),
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::seconds(100)
}

fn test_binding() -> ExecutableBinding {
    let binding = ExecutableBinding {
        artifact_digest: "a".repeat(64),
        program: "eliot-doctor.exe".to_owned(),
        argv: vec![BindingArg::Literal {
            value: "--version".to_owned(),
        }],
        env: std::collections::BTreeMap::new(),
        timeout_ms: 5_000,
        max_stdout_bytes: 65_536,
        max_stderr_bytes: 65_536,
    };
    binding.validate().expect("test binding validates");
    binding
}

fn manifest() -> RepairRecipeManifest {
    let binding = test_binding();
    RepairRecipeManifest {
        manifest_id: "manifest".to_owned(),
        manifest_revision: 1,
        operations: vec![RegisteredOperation {
            operation_id: "restart".to_owned(),
            adapter_id: "adapter".to_owned(),
            description: "restart the component".to_owned(),
            definition_digest: binding.digest(),
            binding,
        }],
    }
}

fn recipe() -> RepairRecipe {
    RepairRecipe {
        recipe_id: "recipe".to_owned(),
        revision: 3,
        problem_classes: ["failure".to_owned()].into_iter().collect(),
        components: ["component".to_owned()].into_iter().collect(),
        repair_class: RepairClass::AutomaticSafe,
        prerequisites: vec!["precondition".to_owned()],
        required_authority: "kernel.recovery".to_owned(),
        allowed_effects: ["restart".to_owned()].into_iter().collect(),
        operations: vec!["restart".to_owned()],
        expected_observables: vec!["healthy".to_owned()],
        verification_contract: vec!["verify".to_owned()],
        rollback_or_compensation: vec!["rollback".to_owned()],
        attempt_budget: 8,
        cooldown: Duration::seconds(30),
        stop_conditions: vec!["stop".to_owned()],
        executable_bindings: [("restart".to_owned(), test_binding())]
            .into_iter()
            .collect(),
    }
}

fn brief() -> DiagnosticBrief {
    DiagnosticBrief {
        problem_id: "problem".to_owned(),
        component: "component".to_owned(),
        failure_class: "failure".to_owned(),
        symptom: "symptom".to_owned(),
        impact: "impact".to_owned(),
        evidence: vec![EvidenceHandle::new("evidence", "a".repeat(64)).unwrap()],
        unknowns: Vec::new(),
    }
}

fn fence() -> StateFence {
    StateFence::new(epoch(LINEAGE_A, 4), 7, "b".repeat(64)).unwrap()
}

fn lease() -> RecoveryLease {
    RecoveryLease {
        lease_id: "lease".to_owned(),
        owner: "kernel".to_owned(),
        expires_at: now() + Duration::seconds(60),
        allowed_effects: ["restart".to_owned()].into_iter().collect(),
    }
}

fn closed(recipe: RepairRecipe, fence: StateFence) -> ClosedRepairRequest {
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();
    ClosedRepairRequest::for_effect(ClosedRequestParams {
        request_id: "job-1".to_owned(),
        brief: brief(),
        recipe,
        operations: vec![operation],
        fence,
        lease: lease(),
        approval: None,
        budget_units: 1,
        deadline: now() + Duration::seconds(60),
        cancellation: false,
        escalation_target: "operator".to_owned(),
    })
    .unwrap()
}

fn bind_direct(envelope: &ClosedRepairRequest) -> RepairAttemptIdentity {
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();
    RepairAttemptIdentity::bind(&AttemptIdentityBinding {
        attempt_id: "attempt-1",
        brief: &envelope.brief,
        recipe: &envelope.recipe_identity,
        operation: &operation,
        fence: &envelope.fence,
        epoch: Some(&epoch(LINEAGE_A, 4)),
        approval: envelope.approval.as_deref(),
        budget_units: envelope.budget_units,
        deadline: envelope.deadline,
    })
    .unwrap()
}

#[test]
fn attempt_identity_is_deterministic_and_epoch_bound() {
    let envelope = closed(recipe(), fence());
    let first = bind_direct(&envelope);
    let second = bind_direct(&envelope);
    assert_eq!(first, second);

    // The epoch-bound constructor agrees with the direct live-epoch bind.
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();
    let admitted = envelope
        .bind_attempt_on_epoch(
            &manifest,
            "attempt-1",
            &operation,
            &epoch(LINEAGE_A, 4),
            now(),
        )
        .unwrap();
    assert_eq!(admitted, first);
}

#[test]
fn attempt_identity_senses_each_load_bearing_field() {
    let baseline = bind_direct(&closed(recipe(), fence()));

    let mut changed_recipe = recipe();
    changed_recipe.revision = 4;
    let changed = bind_direct(&closed(changed_recipe, fence()));
    assert_ne!(changed, baseline);

    let changed = bind_direct(&closed(
        recipe(),
        StateFence::new(epoch(LINEAGE_A, 4), 8, "b".repeat(64)).unwrap(),
    ));
    assert_ne!(changed, baseline);

    let changed = bind_direct(&closed(
        recipe(),
        StateFence::new(epoch(LINEAGE_A, 4), 7, "d".repeat(64)).unwrap(),
    ));
    assert_ne!(changed, baseline);

    // Approval presence and budget are bound: silent substitution changes identity.
    let mut envelope = closed(recipe(), fence());
    envelope.approval = Some("approval".to_owned());
    let changed = bind_direct(&envelope);
    assert_ne!(changed, baseline);

    let mut envelope = closed(recipe(), fence());
    envelope.budget_units = 2;
    let changed = bind_direct(&envelope);
    assert_ne!(changed, baseline);
}

#[test]
fn attempt_identity_rejects_foreign_lineage_at_bind() {
    let envelope = closed(recipe(), fence());
    let manifest = manifest();
    let operation = manifest.resolve("restart").unwrap();

    // Same sequence from a different lineage is unrelated authority.
    let foreign = epoch(LINEAGE_B, 4);
    assert!(
        RepairAttemptIdentity::bind(&AttemptIdentityBinding {
            attempt_id: "attempt-1",
            brief: &envelope.brief,
            recipe: &envelope.recipe_identity,
            operation: &operation,
            fence: &envelope.fence,
            epoch: Some(&foreign),
            approval: None,
            budget_units: envelope.budget_units,
            deadline: envelope.deadline,
        })
        .is_err()
    );
    assert!(
        envelope
            .bind_attempt_on_epoch(&manifest, "attempt-1", &operation, &foreign, now())
            .is_err()
    );
}

#[test]
fn recipe_identity_is_stable_over_set_order() {
    // Same set members inserted in opposite orders must bind identically:
    // `BTreeSet` iteration is sorted, so insertion order is not authority.
    let mut first = recipe();
    first.problem_classes = ["failure".to_owned(), "degraded".to_owned()]
        .into_iter()
        .collect();
    first.components = ["component".to_owned(), "aux".to_owned()]
        .into_iter()
        .collect();
    let mut second = recipe();
    second.problem_classes = ["degraded".to_owned(), "failure".to_owned()]
        .into_iter()
        .collect();
    second.components = ["aux".to_owned(), "component".to_owned()]
        .into_iter()
        .collect();
    assert_eq!(
        RepairRecipeIdentity::bind(&first).unwrap(),
        RepairRecipeIdentity::bind(&second).unwrap()
    );
}
