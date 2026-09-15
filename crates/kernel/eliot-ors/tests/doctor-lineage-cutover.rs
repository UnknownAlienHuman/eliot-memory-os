// T6-E4-C (issue #64): ORS ledger lineage cutover — single affected-edge closure.
//
// Single behaviour proof: a Doctor attempt staged pre-restart is found by
// `attempt_digest` after a same-lineage restart (`Existing`/replayed), then
// after a new-lineage restore the same digest with a new tuple fails as
// `AttemptIdentityConflict`, the old fence fails as `FenceMismatch`, and a new
// admission with the new tuple stages and admits (`Stored`/`Admitted`).
//
// Exercises the real `RedbRecoveryStore::stage/load_doctor_attempt` ledger and
// the exact-tuple fences that back the `projection_page` dual-half check
// (`recovery_projection.rs: authority_tuple_matches`): equal sequences from
// different lineages are unrelated, never equal. Proportionate only: not a
// whole-install pulse.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_ors::{
    DOCTOR_RECORD_CONTRACT_VERSION, DoctorAttemptAdmission, DoctorAttemptRecord,
    DoctorAttemptStageOutcome, DoctorAttemptState, DoctorLedgerError, DoctorRecoveryLedger,
    EpochIdentity, EpochLineage, OpaqueLabel, OrsError, RedbRecoveryStore, StateFenceSnapshot,
};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";
const SEQUENCE: u64 = 4;
const ADMITTED_AT: u64 = 1_700_000_000_000_000_000;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn label(value: &str) -> OpaqueLabel {
    OpaqueLabel::new(value).unwrap()
}

fn contour_lineage(lineage_id: &str, epoch: u64) -> EpochLineage {
    EpochLineage {
        current: EpochIdentity {
            lineage_id: label(lineage_id),
            epoch,
        },
        predecessor: None,
    }
}

fn canonical_epoch(lineage_id: &str, sequence: u64) -> EpochId {
    EpochId::new(
        EpochLineageId::new(lineage_id).unwrap(),
        NonZeroU64::new(sequence).unwrap(),
    )
    .unwrap()
}

fn staged_attempt(attempt_byte: char, lineage_id: &str, sequence: u64) -> DoctorAttemptRecord {
    DoctorAttemptRecord {
        contract_version: DOCTOR_RECORD_CONTRACT_VERSION,
        attempt_digest: label(&digest(attempt_byte)),
        recipe_digest: digest('b'),
        manifest_digest: digest('c'),
        operation_id: label("restart"),
        operation_definition_digest: digest('d'),
        problem_ref: label("problem"),
        component_ref: label("component"),
        evidence_digest: digest('e'),
        principal_ref: label("test-principal"),
        fence_digest: digest('f'),
        // Legacy scalar sequence evidence only; authority is `epoch_lineage`.
        authority_epoch: sequence,
        generation: 7,
        epoch_lineage: Some(contour_lineage(lineage_id, sequence)),
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

fn fence_for(lineage_id: &str, sequence: u64) -> StateFenceSnapshot {
    StateFenceSnapshot::capture(
        &serde_json::json!({
            "authority_epoch": {
                "lineage_id": lineage_id,
                "sequence": sequence
            },
            "integration_revision": null,
            "policy_revision": null,
            "resource_generation": 1,
            "task_revision": null
        }),
        sequence,
    )
    .unwrap()
}

fn temp_path() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "eliot-doctor-lineage-cutover-{}-{}.redb",
        std::process::id(),
        nanos
    ))
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "single affected-edge closure keeps stage/replay/conflict/fence/admit in one proof"
)]
fn doctor_ledger_lineage_cutover_single_edge() {
    let path = temp_path();
    let _ = std::fs::remove_file(&path);
    let store = RedbRecoveryStore::open(&path).unwrap();

    // Pre-restart: stage on lineage A.
    let staged_a = staged_attempt('a', LINEAGE_A, SEQUENCE);
    staged_a.validate().unwrap();
    // Canonical bridge holds for the staged tuple.
    assert!(
        staged_a
            .validate_against_epoch(&canonical_epoch(LINEAGE_A, SEQUENCE))
            .is_ok()
    );
    // Same sequence, foreign lineage is unrelated, never the same authority.
    assert!(
        staged_a
            .validate_against_epoch(&canonical_epoch(LINEAGE_B, SEQUENCE))
            .is_err()
    );
    match DoctorRecoveryLedger::stage_doctor_attempt(&store, &staged_a).unwrap() {
        DoctorAttemptStageOutcome::Stored(record) => assert_eq!(record, staged_a),
        DoctorAttemptStageOutcome::Existing(_) => panic!("first stage must store"),
    }

    // Same-lineage restart: the same digest replays as `Existing`, never a
    // second row. `load_doctor_attempt` finds it by exact digest.
    drop(store);
    let reopened = RedbRecoveryStore::open(&path).unwrap();
    let found = DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged_a.attempt_digest)
        .unwrap()
        .expect("attempt must survive same-lineage restart");
    assert_eq!(found, staged_a);
    match DoctorRecoveryLedger::stage_doctor_attempt(&reopened, &staged_a).unwrap() {
        DoctorAttemptStageOutcome::Existing(record) => assert_eq!(record, staged_a),
        DoctorAttemptStageOutcome::Stored(_) => panic!("same-lineage replay must be existing"),
    }

    // New-lineage restore: the same digest with a new tuple is an identity
    // conflict and never overwrites the durable row. This is the
    // `projection_page` dual-half rule at the ledger: both halves must agree,
    // so `(A,4)` vs `(B,4)` mismatches even though the scalar sequence is equal.
    let mut restored_same_digest = staged_a.clone();
    restored_same_digest.epoch_lineage = Some(contour_lineage(LINEAGE_B, SEQUENCE));
    // Legacy scalar stays the same sequence; lineage changed, so binding differs.
    assert!(!staged_a.same_binding(&restored_same_digest));
    match DoctorRecoveryLedger::stage_doctor_attempt(&reopened, &restored_same_digest) {
        Err(DoctorLedgerError::AttemptIdentityConflict { .. }) => {}
        Ok(_) => panic!("new-lineage same-digest must conflict"),
        Err(error) => panic!("wrong conflict error: {error:?}"),
    }
    let durable = DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged_a.attempt_digest)
        .unwrap()
        .expect("durable row must survive conflict");
    assert_eq!(durable, staged_a);

    // Old fence never authorizes under the new lineage: exact-tuple mismatch.
    let old_fence = fence_for(LINEAGE_A, SEQUENCE);
    old_fence
        .validate_against_lineage(&contour_lineage(LINEAGE_A, SEQUENCE))
        .unwrap();
    assert!(matches!(
        old_fence.validate_against_lineage(&contour_lineage(LINEAGE_B, SEQUENCE)),
        Err(OrsError::FenceMismatch)
    ));
    assert!(matches!(
        old_fence.validate_against_epoch(&canonical_epoch(LINEAGE_B, SEQUENCE)),
        Err(OrsError::FenceMismatch)
    ));
    // The new fence binds the new tuple exactly.
    let new_fence = fence_for(LINEAGE_B, SEQUENCE);
    new_fence
        .validate_against_epoch(&canonical_epoch(LINEAGE_B, SEQUENCE))
        .unwrap();

    // Same-lineage direct-child tightening: `+2` under one lineage fails,
    // `+1` passes, cross-lineage stays allowed (restore mints a new lineage).
    let jump = EpochLineage {
        current: EpochIdentity {
            lineage_id: label(LINEAGE_A),
            epoch: SEQUENCE + 2,
        },
        predecessor: Some(EpochIdentity {
            lineage_id: label(LINEAGE_A),
            epoch: SEQUENCE,
        }),
    };
    assert!(matches!(
        jump.validate(),
        Err(OrsError::InvalidEpochLineage)
    ));
    let step = EpochLineage {
        current: EpochIdentity {
            lineage_id: label(LINEAGE_A),
            epoch: SEQUENCE + 1,
        },
        predecessor: Some(EpochIdentity {
            lineage_id: label(LINEAGE_A),
            epoch: SEQUENCE,
        }),
    };
    step.validate().unwrap();

    // New admission with the new tuple stages and admits on the new lineage.
    let staged_b = staged_attempt('b', LINEAGE_B, SEQUENCE);
    staged_b.validate().unwrap();
    staged_b
        .validate_against_epoch(&canonical_epoch(LINEAGE_B, SEQUENCE))
        .unwrap();
    match DoctorRecoveryLedger::stage_doctor_attempt(&reopened, &staged_b).unwrap() {
        DoctorAttemptStageOutcome::Stored(record) => assert_eq!(record, staged_b),
        DoctorAttemptStageOutcome::Existing(_) => panic!("new tuple must store anew"),
    }
    let admission = DoctorAttemptAdmission {
        admission_digest: digest('4'),
        admitted_at_unix_nanos: ADMITTED_AT,
    };
    let admitted = DoctorRecoveryLedger::advance_doctor_attempt(
        &reopened,
        &staged_b.attempt_digest,
        DoctorAttemptState::Admitted,
        Some(&admission),
    )
    .unwrap()
    .expect("new admission must admit");
    assert_eq!(admitted.state, DoctorAttemptState::Admitted);
    assert_eq!(
        admitted.admission_digest.as_deref(),
        Some(digest('4').as_str())
    );

    drop(reopened);
    let _ = std::fs::remove_file(&path);
}
