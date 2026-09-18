// T6-D1 (issue #461): ORS Doctor row coherence — live lineage authority,
// binding sensitivity, and budget/quarantine durability across restarts.
//
// Pure in-memory proofs over the existing record and budget vocabulary; the
// redb store implementation lands with Wave E. No test here invents store
// behavior: every assertion exercises the real constructors, validators,
// and pure evaluators.
//
// DEFERRED (exhaustive matrix, follow-up slices): multi-effect intent
// conflicts, crash-between-writes recovery, unknown-outcome reconciliation,
// verifier-axis binding, guarded-with-live-grant approval binding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use eliot_ors::{
    DoctorAttemptRecord, DoctorAttemptState, DoctorBudgetDecision, DoctorBudgetLedger,
    DoctorQuarantineCause, EpochIdentity, EpochLineage, OpaqueLabel,
};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).unwrap()
}

fn lineage(lineage_id: &str, epoch: u64) -> EpochLineage {
    EpochLineage {
        current: EpochIdentity {
            lineage_id: label(lineage_id),
            epoch,
        },
        predecessor: None,
    }
}

/// Mirrors the T6-D1 gate output: live lineage from the context epoch, the
/// `u64` column as the sequence projection only.
fn staged_record() -> DoctorAttemptRecord {
    DoctorAttemptRecord {
        contract_version: eliot_ors::DOCTOR_RECORD_CONTRACT_VERSION,
        attempt_digest: label(&digest('a')),
        recipe_digest: digest('b'),
        manifest_digest: digest('c'),
        operation_id: label("restart"),
        operation_definition_digest: digest('d'),
        problem_ref: label("problem"),
        component_ref: label("component"),
        evidence_digest: digest('e'),
        principal_ref: label("test-principal"),
        fence_digest: digest('f'),
        authority_epoch: 4,
        generation: 7,
        epoch_lineage: Some(lineage(LINEAGE_A, 4)),
        target_resource_digest: digest('1'),
        approval_digest: None,
        budget_units: 1,
        deadline_unix_nanos: 1_890_000_000_000_000_000,
        lease_expires_unix_nanos: 1_890_000_000_000_000_000,
        cooldown_nanos: 30_000_000_000,
        cancelled: false,
        binding_digest: digest('2'),
        request_digest: digest('3'),
        state: DoctorAttemptState::Requested,
        admission_digest: None,
        admitted_at_unix_nanos: None,
        commit_order: 0,
    }
}

#[test]
fn attempt_row_carries_live_lineage_as_authority() {
    // Live lineage validates and round-trips across a restart.
    let record = staged_record();
    record.validate().unwrap();
    let rehydrated: DoctorAttemptRecord =
        serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
    assert_eq!(rehydrated, record);
    assert_eq!(
        rehydrated
            .epoch_lineage
            .as_ref()
            .unwrap()
            .current
            .lineage_id
            .as_str(),
        LINEAGE_A
    );
    assert!(record.same_binding(&rehydrated));

    // A lineage edge that disagrees with the sequence projection fails closed.
    let mut mismatched = staged_record();
    mismatched.epoch_lineage = Some(lineage(LINEAGE_A, 5));
    assert!(mismatched.validate().is_err());

    // A foreign lineage is a different binding, never the same authority.
    let mut foreign = staged_record();
    foreign.epoch_lineage = Some(lineage(LINEAGE_B, 4));
    assert!(!record.same_binding(&foreign));
}

#[test]
fn attempt_row_binding_senses_recipe_target_and_approval() {
    let baseline = staged_record();

    let mut changed = baseline.clone();
    changed.recipe_digest = digest('9');
    assert!(!baseline.same_binding(&changed));

    let mut changed = baseline.clone();
    changed.target_resource_digest = digest('9');
    assert!(!baseline.same_binding(&changed));

    let mut changed = baseline.clone();
    changed.approval_digest = Some(digest('9'));
    assert!(!baseline.same_binding(&changed));

    // ORS-owned progression is not caller binding: state, admission
    // evidence, and commit order never break replay equality.
    let mut progressed = baseline.clone();
    progressed.state = DoctorAttemptState::Admitted;
    progressed.admission_digest = Some(digest('4'));
    progressed.admitted_at_unix_nanos = Some(1_700_000_000_000_000_000);
    progressed.commit_order = 0;
    assert!(baseline.same_binding(&progressed));
}

#[test]
fn budget_ledger_survives_restart_round_trip() {
    let scope = label(&digest('5'));
    let mut ledger = DoctorBudgetLedger::pristine(scope);
    assert!(matches!(
        ledger.evaluate(8, 30_000_000_000, 1_700_000_000_000_000_000),
        DoctorBudgetDecision::Admitted { .. }
    ));

    ledger.note_admission(1_700_000_000_000_000_000).unwrap();

    // Restart: the durable row rehydrates with identical enforcement.
    let rehydrated: DoctorBudgetLedger =
        serde_json::from_str(&serde_json::to_string(&ledger).unwrap()).unwrap();
    assert_eq!(rehydrated, ledger);
    assert!(matches!(
        rehydrated.evaluate(8, 30_000_000_000, 1_700_000_000_000_000_001),
        DoctorBudgetDecision::CooldownActive { .. }
    ));
    assert!(matches!(
        rehydrated.evaluate(
            8,
            30_000_000_000,
            1_700_000_000_000_000_000 + 30_000_000_000
        ),
        DoctorBudgetDecision::Admitted { .. }
    ));
}

#[test]
fn quarantine_holds_across_restart() {
    let scope = label(&digest('6'));
    let mut ledger = DoctorBudgetLedger::pristine(scope);
    ledger
        .record_quarantine(
            DoctorQuarantineCause::RepeatedFailure,
            1_700_000_000_000_000_000,
            None,
        )
        .unwrap();

    let rehydrated: DoctorBudgetLedger =
        serde_json::from_str(&serde_json::to_string(&ledger).unwrap()).unwrap();
    assert!(matches!(
        rehydrated.evaluate(8, 0, 1_800_000_000_000_000_000),
        DoctorBudgetDecision::Quarantined {
            cause: DoctorQuarantineCause::RepeatedFailure
        }
    ));
}
