//! Kernel-owned durable Doctor recovery ledger (DISPATCH-WIRE part D).
//!
//! Thin Kernel-side owner over the store slice's redb implementation: it
//! resolves the Kernel-owned ledger file below the canonical work root,
//! opens the [`RedbRecoveryStore`](eliot_ors::RedbRecoveryStore) there, and
//! delegates every [`DoctorRecoveryLedger`] call unchanged. Staging,
//! advancing, loading, budgeting, first-writer-wins conflicts, and
//! restart durability behave exactly like a direct store call: this file
//! mints no record, invents no identity, and keeps no process-local copy.
//! The in-memory `TestLedger` in `eliot-kernel-service/src/doctor.rs` stays
//! unit-scope only; production composition takes this owner.
//!
//! The ledger file lives next to the Kernel ORS file
//! (`<work-root>/kernel-ors.redb` in `bins/eliot-kernel/src/tests.rs`) but
//! is a separate database (`kernel-doctor-recovery.redb`) so the doctor
//! recovery rows keep exactly one writer and never share a redb handle
//! with the operational store.

use std::path::{Path, PathBuf};

use eliot_ors::{
    DoctorAttemptAdmission, DoctorAttemptRecord, DoctorAttemptStageOutcome, DoctorAttemptState,
    DoctorBudgetLedger, DoctorEffectOutcomeReport, DoctorEffectRecord, DoctorEffectStageOutcome,
    DoctorLedgerError, DoctorRecoveryLedger, OpaqueLabel, OperationIdentity, OrsError,
    RedbRecoveryStore,
};

/// File name of the Kernel-owned durable Doctor recovery ledger below the
/// canonical work root.
pub const DOCTOR_RECOVERY_LEDGER_FILE_NAME: &str = "kernel-doctor-recovery.redb";

/// Resolves the Kernel-owned durable Doctor recovery ledger file below the
/// canonical work root.
///
/// Mirrors the Kernel ORS work-root file pattern
/// (`RedbRecoveryStore::open(root.join("kernel-ors.redb"))` in
/// `bins/eliot-kernel/src/tests.rs`): the caller passes the canonical
/// absolute work root from the authenticated Host launch contour, never a
/// request value or the current directory.
#[must_use]
pub fn doctor_recovery_ledger_path(work_root: &Path) -> PathBuf {
    work_root.join(DOCTOR_RECOVERY_LEDGER_FILE_NAME)
}

/// Kernel-owned durable Doctor recovery ledger.
///
/// Owns the redb file handle for doctor recovery rows and delegates the
/// full [`DoctorRecoveryLedger`] contract to the store slice's
/// implementation. Construct only through [`Self::open`].
pub struct KernelDoctorRecoveryLedger {
    store: RedbRecoveryStore,
}

impl KernelDoctorRecoveryLedger {
    /// Opens (or creates) the Kernel-owned durable Doctor recovery ledger
    /// below the canonical work root.
    ///
    /// Fails closed when `work_root` is not an existing absolute directory;
    /// storage failures propagate unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`OrsError::InvalidField`] when `work_root` is not an
    /// existing absolute directory, or the store slice's error when the
    /// redb file cannot be opened.
    pub fn open(work_root: &Path) -> Result<Self, OrsError> {
        if !work_root.is_absolute() {
            return Err(OrsError::InvalidField {
                field: "doctor_recovery.work_root",
                reason: "the doctor recovery ledger root must be absolute",
            });
        }
        if !work_root.is_dir() {
            return Err(OrsError::InvalidField {
                field: "doctor_recovery.work_root",
                reason: "the doctor recovery ledger root must be an existing directory",
            });
        }
        let store = RedbRecoveryStore::open(doctor_recovery_ledger_path(work_root))?;
        Ok(Self { store })
    }
}

impl DoctorRecoveryLedger for KernelDoctorRecoveryLedger {
    fn stage_doctor_attempt(
        &self,
        record: &DoctorAttemptRecord,
    ) -> Result<DoctorAttemptStageOutcome, DoctorLedgerError> {
        DoctorRecoveryLedger::stage_doctor_attempt(&self.store, record)
    }

    fn load_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::load_doctor_attempt(&self.store, attempt_digest)
    }

    fn advance_doctor_attempt(
        &self,
        attempt_digest: &OperationIdentity,
        target: DoctorAttemptState,
        admission: Option<&DoctorAttemptAdmission>,
    ) -> Result<Option<DoctorAttemptRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::advance_doctor_attempt(&self.store, attempt_digest, target, admission)
    }

    fn stage_doctor_effect(
        &self,
        record: &DoctorEffectRecord,
    ) -> Result<DoctorEffectStageOutcome, DoctorLedgerError> {
        DoctorRecoveryLedger::stage_doctor_effect(&self.store, record)
    }

    fn load_doctor_effect(
        &self,
        effect_digest: &OperationIdentity,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::load_doctor_effect(&self.store, effect_digest)
    }

    fn record_doctor_effect_outcome(
        &self,
        effect_digest: &OperationIdentity,
        report: &DoctorEffectOutcomeReport,
    ) -> Result<Option<DoctorEffectRecord>, DoctorLedgerError> {
        DoctorRecoveryLedger::record_doctor_effect_outcome(&self.store, effect_digest, report)
    }

    fn load_doctor_budget(
        &self,
        scope_key: &OpaqueLabel,
    ) -> Result<Option<DoctorBudgetLedger>, DoctorLedgerError> {
        DoctorRecoveryLedger::load_doctor_budget(&self.store, scope_key)
    }

    fn store_doctor_budget(&self, ledger: &DoctorBudgetLedger) -> Result<(), DoctorLedgerError> {
        DoctorRecoveryLedger::store_doctor_budget(&self.store, ledger)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::too_many_lines)]

    use super::*;
    use eliot_ors::{
        DOCTOR_RECORD_CONTRACT_VERSION, DoctorEffectState, DoctorLedgerError, EpochIdentity,
        EpochLineage,
    };

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const ADMITTED_AT: u64 = 1_700_000_000_000_000_000;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn label(value: &str) -> OpaqueLabel {
        OpaqueLabel::new(value).expect("test label")
    }

    fn temp_work_root(slug: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-doctor-ledger-{slug}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        root
    }

    fn staged_attempt(attempt_byte: char) -> DoctorAttemptRecord {
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
            principal_ref: label("kernel.doctor-owner-principal"),
            fence_digest: digest('f'),
            authority_epoch: 4,
            generation: 7,
            epoch_lineage: Some(EpochLineage {
                current: EpochIdentity {
                    lineage_id: label(LINEAGE),
                    epoch: 4,
                },
                predecessor: None,
            }),
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

    fn staged_effect(effect_digest_byte: char, attempt_byte: char) -> DoctorEffectRecord {
        DoctorEffectRecord {
            contract_version: DOCTOR_RECORD_CONTRACT_VERSION,
            effect_digest: label(&digest(effect_digest_byte)),
            attempt_digest: digest(attempt_byte),
            operation_id: label("restart"),
            effect_seq: 0,
            intent_digest: digest('8'),
            state: DoctorEffectState::Intended,
            outcome_digest: None,
            adapter_receipt_digest: None,
            reconciliation_key: None,
            commit_order: 0,
        }
    }

    #[test]
    fn ledger_path_is_work_root_anchored() {
        let root = temp_work_root("path");
        let path = doctor_recovery_ledger_path(&root);
        assert_eq!(
            path,
            root.join(DOCTOR_RECOVERY_LEDGER_FILE_NAME),
            "the ledger file stays below the canonical work root"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn ledger_open_rejects_a_non_directory_root() {
        let root = temp_work_root("root-guard");
        let missing = root.join("missing-root");
        assert!(matches!(
            KernelDoctorRecoveryLedger::open(&missing),
            Err(OrsError::InvalidField { .. })
        ));
        let relative = PathBuf::from("relative-doctor-ledger-root");
        assert!(matches!(
            KernelDoctorRecoveryLedger::open(&relative),
            Err(OrsError::InvalidField { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    /// The Kernel-owned ledger survives a restart: stage, admit, effect,
    /// outcome, and budget rows reload equal after reopen, and
    /// first-writer-wins conflicts still refuse to overwrite the durable
    /// rows. Exercises the production owner type (real redb file) only.
    #[test]
    fn kernel_ledger_reopens_and_survives_restart() {
        let root = temp_work_root("restart");
        let staged = staged_attempt('a');
        let effect = staged_effect('e', 'a');

        let ledger = KernelDoctorRecoveryLedger::open(&root).expect("owner opens");
        match DoctorRecoveryLedger::stage_doctor_attempt(&ledger, &staged).expect("stage stores") {
            DoctorAttemptStageOutcome::Stored(record) => assert_eq!(record, staged),
            DoctorAttemptStageOutcome::Existing(_) => {
                panic!("first stage must store, not replay")
            }
        }
        let admission = DoctorAttemptAdmission {
            admission_digest: digest('4'),
            admitted_at_unix_nanos: ADMITTED_AT,
        };
        let admitted = DoctorRecoveryLedger::advance_doctor_attempt(
            &ledger,
            &staged.attempt_digest,
            DoctorAttemptState::Admitted,
            Some(&admission),
        )
        .expect("advance admits")
        .expect("admitted attempt loads");
        assert_eq!(admitted.state, DoctorAttemptState::Admitted);

        match DoctorRecoveryLedger::stage_doctor_effect(&ledger, &effect).expect("effect stores") {
            DoctorEffectStageOutcome::Stored(record) => assert_eq!(record, effect),
            DoctorEffectStageOutcome::Existing(_) => {
                panic!("first effect stage must store, not replay")
            }
        }
        let report = DoctorEffectOutcomeReport {
            outcome_digest: Some(digest('0')),
            adapter_receipt_digest: None,
            unknown: false,
        };
        let reported = DoctorRecoveryLedger::record_doctor_effect_outcome(
            &ledger,
            &effect.effect_digest,
            &report,
        )
        .expect("outcome records")
        .expect("reported effect loads");
        assert_eq!(reported.state, DoctorEffectState::Reported);

        let scope = label(&digest('5'));
        let mut budget = DoctorBudgetLedger::pristine(scope.clone());
        budget.note_admission(ADMITTED_AT).expect("budget admits");
        DoctorRecoveryLedger::store_doctor_budget(&ledger, &budget).expect("budget stores");

        drop(ledger);
        let reopened = KernelDoctorRecoveryLedger::open(&root).expect("owner reopens");
        let reloaded = DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged.attempt_digest)
            .expect("attempt reloads")
            .expect("attempt survived restart");
        assert_eq!(reloaded, admitted);
        let reloaded_effect =
            DoctorRecoveryLedger::load_doctor_effect(&reopened, &effect.effect_digest)
                .expect("effect reloads")
                .expect("effect survived restart");
        assert_eq!(reloaded_effect, reported);
        let reloaded_budget = DoctorRecoveryLedger::load_doctor_budget(&reopened, &scope)
            .expect("budget reloads")
            .expect("budget survived restart");
        assert_eq!(reloaded_budget, budget);

        // First-writer-wins still holds after reopen: changed terms under
        // one identity conflict and never overwrite the durable row.
        let mut conflicting = staged.clone();
        conflicting.recipe_digest = digest('9');
        assert!(
            matches!(
                DoctorRecoveryLedger::stage_doctor_attempt(&reopened, &conflicting),
                Err(DoctorLedgerError::AttemptIdentityConflict { .. })
            ),
            "changed attempt terms must conflict after reopen"
        );
        let durable = DoctorRecoveryLedger::load_doctor_attempt(&reopened, &staged.attempt_digest)
            .expect("durable reloads")
            .expect("durable attempt kept");
        assert_eq!(durable, admitted);

        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }
}
