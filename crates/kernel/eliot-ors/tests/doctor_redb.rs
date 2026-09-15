// DISPATCH-CONTOUR-2 residual 1 (issue #461): durable production
// DoctorRecoveryLedger over RedbRecoveryStore.
//
// Single behaviour proof: stage -> admit -> effect -> outcome advances,
// Unknown -> Reconciling -> ResultRecorded transitions, first-writer-wins
// conflicts that never overwrite, and budget/quarantine durability across
// redb reopen. Exercises the real store implementation only.

use eliot_ors::{
    DOCTOR_RECORD_CONTRACT_VERSION, DoctorAttemptAdmission, DoctorAttemptRecord,
    DoctorAttemptStageOutcome, DoctorAttemptState, DoctorBudgetDecision, DoctorBudgetLedger,
    DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome, DoctorEffectState,
    DoctorLedgerError, DoctorQuarantineCause, DoctorRecoveryLedger, EpochIdentity, EpochLineage,
    OpaqueLabel, RedbRecoveryStore,
};

const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
const ADMITTED_AT: u64 = 1_700_000_000_000_000_000;
const ADMITTED_AT_B: u64 = 1_700_000_000_000_000_100;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn label(value: &str) -> Result<OpaqueLabel, Box<dyn std::error::Error>> {
    Ok(OpaqueLabel::new(value)?)
}

fn lineage(epoch: u64) -> Result<EpochLineage, Box<dyn std::error::Error>> {
    Ok(EpochLineage {
        current: EpochIdentity {
            lineage_id: label(LINEAGE_A)?,
            epoch,
        },
        predecessor: None,
    })
}

fn staged_attempt(attempt_byte: char) -> Result<DoctorAttemptRecord, Box<dyn std::error::Error>> {
    Ok(DoctorAttemptRecord {
        contract_version: DOCTOR_RECORD_CONTRACT_VERSION,
        attempt_digest: label(&digest(attempt_byte))?,
        recipe_digest: digest('b'),
        manifest_digest: digest('c'),
        operation_id: label("restart")?,
        operation_definition_digest: digest('d'),
        problem_ref: label("problem")?,
        component_ref: label("component")?,
        evidence_digest: digest('e'),
        principal_ref: label("test-principal")?,
        fence_digest: digest('f'),
        authority_epoch: 4,
        generation: 7,
        epoch_lineage: Some(lineage(4)?),
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
    })
}

fn staged_effect(
    effect_digest_byte: char,
    attempt_byte: char,
) -> Result<DoctorEffectRecord, Box<dyn std::error::Error>> {
    Ok(DoctorEffectRecord {
        contract_version: DOCTOR_RECORD_CONTRACT_VERSION,
        effect_digest: label(&digest(effect_digest_byte))?,
        attempt_digest: digest(attempt_byte),
        operation_id: label("restart")?,
        effect_seq: 0,
        intent_digest: digest('8'),
        state: DoctorEffectState::Intended,
        outcome_digest: None,
        adapter_receipt_digest: None,
        reconciliation_key: None,
        commit_order: 0,
    })
}

fn temp_path() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "eliot-doctor-redb-{}-{}.redb",
        std::process::id(),
        nanos
    ))
}

#[test]
fn doctor_redb_ledger_is_durable_across_restart() -> Result<(), Box<dyn std::error::Error>> {
    let path = temp_path();
    let _ = std::fs::remove_file(&path);

    // Happy path: stage -> admit -> effect -> outcome -> terminal.
    let store = RedbRecoveryStore::open(&path)?;
    let staged = staged_attempt('a')?;
    match DoctorRecoveryLedger::stage_doctor_attempt(&store, &staged)? {
        DoctorAttemptStageOutcome::Stored(record) => assert_eq!(record, staged),
        DoctorAttemptStageOutcome::Existing(_) => assert!(false, "first stage must store"),
    }
    match DoctorRecoveryLedger::stage_doctor_attempt(&store, &staged)? {
        DoctorAttemptStageOutcome::Existing(record) => assert_eq!(record, staged),
        DoctorAttemptStageOutcome::Stored(_) => assert!(false, "replay must be existing"),
    }

    let admission = DoctorAttemptAdmission {
        admission_digest: digest('4'),
        admitted_at_unix_nanos: ADMITTED_AT,
    };
    let admitted = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged.attempt_digest,
        DoctorAttemptState::Admitted,
        Some(&admission),
    )?
    .ok_or("admitted attempt disappeared")?;
    assert_eq!(admitted.state, DoctorAttemptState::Admitted);
    assert_eq!(
        admitted.admission_digest.as_deref(),
        Some(digest('4').as_str())
    );
    assert_eq!(admitted.admitted_at_unix_nanos, Some(ADMITTED_AT));

    let replayed = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged.attempt_digest,
        DoctorAttemptState::Admitted,
        Some(&admission),
    )?
    .ok_or("admission replay disappeared")?;
    assert_eq!(replayed, admitted);

    let effect = staged_effect('7', 'a')?;
    match DoctorRecoveryLedger::stage_doctor_effect(&store, &effect)? {
        DoctorEffectStageOutcome::Stored(record) => assert_eq!(record, effect),
        DoctorEffectStageOutcome::Existing(_) => assert!(false, "first effect must store"),
    }

    let report = DoctorEffectOutcomeReport {
        outcome_digest: Some(digest('9')),
        adapter_receipt_digest: Some(digest('0')),
        unknown: false,
    };
    let reported =
        DoctorRecoveryLedger::record_doctor_effect_outcome(&store, &effect.effect_digest, &report)?
            .ok_or("reported effect disappeared")?;
    assert_eq!(reported.state, DoctorEffectState::Reported);
    assert_eq!(
        reported.outcome_digest.as_deref(),
        Some(digest('9').as_str())
    );
    assert_eq!(reported.reconciliation_key, None);
    assert!(reported.commit_order != 0);

    let intended = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged.attempt_digest,
        DoctorAttemptState::EffectIntended,
        None,
    )?
    .ok_or("effect-intended disappeared")?;
    assert_eq!(intended.state, DoctorAttemptState::EffectIntended);

    let recorded = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged.attempt_digest,
        DoctorAttemptState::ResultRecorded,
        None,
    )?
    .ok_or("result-recorded disappeared")?;
    assert_eq!(recorded.state, DoctorAttemptState::ResultRecorded);

    let terminal = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged.attempt_digest,
        DoctorAttemptState::Terminal,
        None,
    )?
    .ok_or("terminal disappeared")?;
    assert_eq!(terminal.state, DoctorAttemptState::Terminal);
    assert!(terminal.commit_order != 0);

    // Unknown -> Reconciling -> ResultRecorded on a second attempt.
    let staged_b = DoctorAttemptRecord {
        attempt_digest: label(&"ab".repeat(32))?,
        ..staged_attempt('a')?
    };
    match DoctorRecoveryLedger::stage_doctor_attempt(&store, &staged_b)? {
        DoctorAttemptStageOutcome::Stored(_) => {}
        DoctorAttemptStageOutcome::Existing(_) => assert!(false, "second attempt must store"),
    }
    let admission_b = DoctorAttemptAdmission {
        admission_digest: digest('6'),
        admitted_at_unix_nanos: ADMITTED_AT_B,
    };
    let admitted_b = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged_b.attempt_digest,
        DoctorAttemptState::Admitted,
        Some(&admission_b),
    )?
    .ok_or("second admission disappeared")?;
    assert_eq!(admitted_b.state, DoctorAttemptState::Admitted);

    let unknown_b = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged_b.attempt_digest,
        DoctorAttemptState::Unknown,
        None,
    )?
    .ok_or("unknown disappeared")?;
    assert_eq!(unknown_b.state, DoctorAttemptState::Unknown);

    let reconciling_b = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged_b.attempt_digest,
        DoctorAttemptState::Reconciling,
        None,
    )?
    .ok_or("reconciling disappeared")?;
    assert_eq!(reconciling_b.state, DoctorAttemptState::Reconciling);

    let rerecorded_b = DoctorRecoveryLedger::advance_doctor_attempt(
        &store,
        &staged_b.attempt_digest,
        DoctorAttemptState::ResultRecorded,
        None,
    )?
    .ok_or("reconciled result disappeared")?;
    assert_eq!(rerecorded_b.state, DoctorAttemptState::ResultRecorded);

    // Budget is Kernel-derived and durable: store, then prove reopen reads it.
    let scope = label(&digest('5'))?;
    let mut budget = DoctorBudgetLedger::pristine(scope.clone());
    budget.note_admission(ADMITTED_AT)?;
    DoctorRecoveryLedger::store_doctor_budget(&store, &budget)?;
    let loaded_budget =
        DoctorRecoveryLedger::load_doctor_budget(&store, &scope)?.ok_or("budget disappeared")?;
    assert_eq!(loaded_budget, budget);

    drop(store);
    let reopened = RedbRecoveryStore::open(&path)?;
    let reloaded = DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged.attempt_digest)?
        .ok_or("attempt did not survive restart")?;
    assert_eq!(reloaded, terminal);
    let reloaded_effect =
        DoctorRecoveryLedger::load_doctor_effect(&reopened, &effect.effect_digest)?
            .ok_or("effect did not survive restart")?;
    assert_eq!(reloaded_effect, reported);
    let reloaded_budget = DoctorRecoveryLedger::load_doctor_budget(&reopened, &scope)?
        .ok_or("budget did not survive restart")?;
    assert_eq!(reloaded_budget, budget);
    assert!(matches!(
        reloaded_budget.evaluate(8, 30_000_000_000, ADMITTED_AT + 1),
        DoctorBudgetDecision::CooldownActive { .. }
    ));

    // Identity conflict never overwrites the durable row.
    let mut conflicting = staged.clone();
    conflicting.recipe_digest = digest('9');
    match DoctorRecoveryLedger::stage_doctor_attempt(&reopened, &conflicting) {
        Err(DoctorLedgerError::AttemptIdentityConflict { .. }) => {}
        Ok(_) => assert!(false, "changed attempt must conflict"),
        Err(_) => assert!(false, "wrong attempt error"),
    }
    let durable_after_conflict =
        DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged.attempt_digest)?
            .ok_or("durable attempt lost after conflict")?;
    assert_eq!(durable_after_conflict, terminal);

    let mut conflicting_effect = effect.clone();
    conflicting_effect.intent_digest = digest('9');
    match DoctorRecoveryLedger::stage_doctor_effect(&reopened, &conflicting_effect) {
        Err(DoctorLedgerError::EffectIdentityConflict { .. }) => {}
        Ok(_) => assert!(false, "changed effect must conflict"),
        Err(_) => assert!(false, "wrong effect error"),
    }

    // Quarantine survives restart and dominates budget.
    let mut quarantined = reloaded_budget.clone();
    quarantined.record_quarantine(DoctorQuarantineCause::RepeatedFailure, ADMITTED_AT, None)?;
    DoctorRecoveryLedger::store_doctor_budget(&reopened, &quarantined)?;
    drop(reopened);
    let rereopened = RedbRecoveryStore::open(&path)?;
    let reloaded_quarantine = DoctorRecoveryLedger::load_doctor_budget(&rereopened, &scope)?
        .ok_or("quarantine did not survive restart")?;
    assert_eq!(reloaded_quarantine, quarantined);
    assert!(matches!(
        reloaded_quarantine.evaluate(8, 0, ADMITTED_AT + 1_000_000),
        DoctorBudgetDecision::Quarantined { .. }
    ));
    drop(rereopened);
    let _ = std::fs::remove_file(&path);
    Ok(())
}
