use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use eliot_platform::PlatformHandle;
use eliot_receipts::{ReceiptDispositionKind, ReceiptEnvelope};
use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, GenerationCutoverState,
    HealthDimension, OperationalRecoveryState,
};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::{
    ActiveSessionBinding, AdmissionReservation, AdmissionReservationActivation,
    AdmissionReservationReceipt, AdmissionReservationRelease, AuthorityActivationReceipt,
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState, AuthorityRevocation,
    AuthorityRevocationReceipt, AuthoritySnapshotReceipt, CanonicalDisposition,
    CanonicalReconciliation, CapabilityGrantActivation, CapabilityGrantRevocation,
    CapabilityIntroductionActivation, CapabilityIntroductionFence, CapabilityIntroductionReceipt,
    DeliveryAcknowledgement, DeliveryCursorReceipt, DeliveryCursorState, EpochIdentity,
    EpochLineage, GenerationCutoverReceipt, GenerationCutoverRecord, GenerationCutoverSnapshot,
    GenerationTransition, GenerationTransitionReceipt, JobCheckpoint, KernelAuthoritySnapshot,
    OpaqueLabel, OperationalControlProjection, OperationalMutationReceipt, OperationalPhase,
    OperationalRecordContext, OperationalRecordInput, OrsError, OrsSnapshotReceipt,
    OrsSnapshotRequest, PendingOperationPage, ProcessEvidenceRecord, ProcessStartReplayAbort,
    ProcessStartReplayRecord, ProcessStartReplayState, RecoveredAuthoritySnapshot, RecoveryCursor,
    RecoveryInboxDisposition, RecoveryInboxItem, RecoveryInboxReceipt, RecoveryPage,
    RecoveryPayload, RecoveryPayloadEnvelope, ReservationRecord, ReservationRequest,
    ReservationState, ReservedScope, RetryState, ScopeTerminalReceipt, ScopeTerminalView,
    SessionBindingReceipt, SessionDetach, StageReceipt, StagedOperation, StateFenceSnapshot,
    UserBrokerFence, UserBrokerRegistration, UserBrokerRegistrationReceipt, WriterReservationToken,
};

const META: TableDefinition<&str, &str> = TableDefinition::new("ors_meta_v1");
const ENVELOPES: TableDefinition<&str, &str> = TableDefinition::new("ors_envelopes_v1");
const RESERVATIONS: TableDefinition<&str, &str> = TableDefinition::new("ors_reservations_v1");
const RESERVATION_ORDERS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_reservation_orders_v1");
const OPERATIONS: TableDefinition<&str, &str> = TableDefinition::new("ors_operations_v1");
const SCOPE_HEADS: TableDefinition<&str, &str> = TableDefinition::new("ors_scope_heads_v1");
const SCOPE_TERMINALS: TableDefinition<&str, &str> = TableDefinition::new("ors_scope_terminals_v1");
const OPERATIONAL_CURRENT: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_current_v1");
const OPERATIONAL_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_operational_history_v1");
const RECOVERY_INBOX: TableDefinition<&str, &str> = TableDefinition::new("ors_recovery_inbox_v1");
const RECOVERY_INBOX_HISTORY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_recovery_inbox_history_v1");
const PROCESS_START_REPLAY: TableDefinition<&str, &str> =
    TableDefinition::new("ors_process_start_replay_v1");
const AUTHORITY_HANDOFFS: TableDefinition<&str, &str> =
    TableDefinition::new("ors_authority_handoffs_v1");
const PROCESS_EVIDENCE: TableDefinition<&str, &str> =
    TableDefinition::new("ors_process_evidence_v1");
const NEXT_GLOBAL_ORDER: &str = "next_global_order";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ScopeReservationHead {
    writer_epoch: EpochIdentity,
    canonical_head: crate::ExpectedOrderingHead,
    last_reserved_sequence: u64,
    last_terminal_sequence: u64,
    recovery_blocked: bool,
}

/// Composition-injected canonical/readback authenticator. `Ok(())` is trusted only because
/// composition owns this provider; caller-created receipts never bypass it.
pub trait CanonicalEvidenceProvider: Send + Sync {
    fn verify_ordering_heads(
        &self,
        scopes: &[crate::ScopeReservationRequest],
    ) -> Result<(), OrsError>;

    fn verify_reconciliation(
        &self,
        token: &WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError>;

    fn verify_receipt(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError>;

    fn verify_recovery_inbox(&self, item: &RecoveryInboxItem) -> Result<(), OrsError>;
}

struct RejectUnboundEvidence;

impl CanonicalEvidenceProvider for RejectUnboundEvidence {
    fn verify_ordering_heads(
        &self,
        _scopes: &[crate::ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical ordering provider is not bound".to_owned(),
        ))
    }

    fn verify_reconciliation(
        &self,
        _token: &WriterReservationToken,
        _reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical readback provider is not bound".to_owned(),
        ))
    }

    fn verify_receipt(&self, _receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "canonical receipt provider is not bound".to_owned(),
        ))
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "recovery inbox signer provider is not bound".to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum OperationalKind {
    Operation,
    Retry,
    JobCheckpoint,
    DeliveryCursor,
    AdmissionReservation,
    GenerationTransition,
    GenerationCutover,
    SessionBinding,
    UserBroker,
    AuthoritySnapshot,
    AuthorityRevocation,
    CapabilityGrant,
    CapabilityIntroduction,
}

impl OperationalKind {
    const fn key_prefix(self) -> &'static str {
        match self {
            Self::Operation => "operation",
            Self::Retry => "retry",
            Self::JobCheckpoint => "job_checkpoint",
            Self::DeliveryCursor => "delivery_cursor",
            Self::AdmissionReservation => "admission_reservation",
            Self::GenerationTransition => "generation_transition",
            Self::GenerationCutover => "generation_cutover",
            Self::SessionBinding => "session_binding",
            Self::UserBroker => "user_broker",
            Self::AuthoritySnapshot => "authority_snapshot",
            Self::AuthorityRevocation => "authority_revocation",
            Self::CapabilityGrant => "capability_grant",
            Self::CapabilityIntroduction => "capability_introduction",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableOperationalRecord {
    kind: OperationalKind,
    input: OperationalRecordInput,
    phase: OperationalPhase,
    operation_order: u64,
    terminal_receipt_id: Option<OpaqueLabel>,
    terminal_receipt_sha256: Option<String>,
    /// Typed generation evidence is carried by the same canonical
    /// operational current/history records as every other ORS subject.
    /// `default` keeps older canonical records readable without granting the
    /// retired generation tables any authority.
    #[serde(default)]
    generation_cutover: Option<RuntimeGenerationCutoverRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableInboxRecord {
    item: RecoveryInboxItem,
    disposition: RecoveryInboxDisposition,
    operation_order: u64,
    terminal_receipt_id: Option<OpaqueLabel>,
    terminal_receipt_sha256: Option<String>,
}

/// Durable operational store boundary. Implementations must preserve atomic method semantics.
pub trait OperationalRecoveryStore: Send + Sync {
    fn stage(&self, op: StagedOperation) -> Result<StageReceipt, OrsError>;
    fn mark_applying(&self, operation_id: crate::OperationIdentity) -> Result<(), OrsError>;
    fn record_outcome(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError>;
    fn schedule_retry(
        &self,
        operation_id: crate::OperationIdentity,
        retry: RetryState,
    ) -> Result<(), OrsError>;
    fn checkpoint_job(&self, checkpoint: JobCheckpoint) -> Result<(), OrsError>;
    fn record_delivery_cursor(
        &self,
        cursor: DeliveryCursorState,
    ) -> Result<DeliveryCursorReceipt, OrsError>;
    fn acknowledge_delivery(
        &self,
        ack: DeliveryAcknowledgement,
    ) -> Result<DeliveryCursorReceipt, OrsError>;
    fn stage_admission_reservation(
        &self,
        reservation: AdmissionReservation,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn activate_admission_reservation(
        &self,
        activation: AdmissionReservationActivation,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn release_admission_reservation(
        &self,
        release: AdmissionReservationRelease,
    ) -> Result<AdmissionReservationReceipt, OrsError>;
    fn apply_generation_transition(
        &self,
        transition: GenerationTransition,
    ) -> Result<GenerationTransitionReceipt, OrsError>;
    fn commit_generation_cutover(
        &self,
        cutover: GenerationCutoverRecord,
    ) -> Result<GenerationCutoverReceipt, OrsError>;
    /// Stages typed generation evidence in the canonical operational
    /// current/history path.
    fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError>;
    /// Commits typed generation evidence at the canonical ORS linearization
    /// point and returns its canonical receipt projection.
    fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError>;
    /// Reads the bounded committed generation route projection.
    fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError>;
    /// Reconciles staged generation evidence without activating it.
    fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError>;
    fn bind_session(
        &self,
        binding: ActiveSessionBinding,
    ) -> Result<SessionBindingReceipt, OrsError>;
    fn detach_session(&self, detach: SessionDetach) -> Result<SessionBindingReceipt, OrsError>;
    fn register_user_broker(
        &self,
        registration: UserBrokerRegistration,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError>;
    fn fence_user_broker(
        &self,
        fence: UserBrokerFence,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError>;
    fn commit_authority_snapshot(
        &self,
        snapshot: KernelAuthoritySnapshot,
    ) -> Result<AuthoritySnapshotReceipt, OrsError>;
    /// Loads one active opaque authority snapshot with fresh ORS integrity
    /// validation. The returned value is not Kernel authority.
    fn load_authority_snapshot(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveredAuthoritySnapshot>, OrsError>;
    fn revoke_authority(
        &self,
        revocation: AuthorityRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError>;
    fn activate_capability_grant(
        &self,
        activation: CapabilityGrantActivation,
    ) -> Result<AuthorityActivationReceipt, OrsError>;
    fn revoke_capability_grant(
        &self,
        revocation: CapabilityGrantRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError>;
    fn activate_capability_introduction(
        &self,
        activation: CapabilityIntroductionActivation,
    ) -> Result<CapabilityIntroductionReceipt, OrsError>;
    fn fence_capability_introduction(
        &self,
        fence: CapabilityIntroductionFence,
    ) -> Result<CapabilityIntroductionReceipt, OrsError>;
    fn logical_snapshot(&self, request: OrsSnapshotRequest)
    -> Result<OrsSnapshotReceipt, OrsError>;
    fn scan_pending(
        &self,
        cursor: RecoveryCursor,
        limit: u32,
    ) -> Result<PendingOperationPage, OrsError>;
    fn import_recovery_inbox(
        &self,
        item: RecoveryInboxItem,
    ) -> Result<RecoveryInboxReceipt, OrsError>;
    fn record_recovery_inbox_disposition(
        &self,
        item_id: crate::OperationIdentity,
        disposition: RecoveryInboxDisposition,
        receipt: &ReceiptEnvelope,
    ) -> Result<RecoveryInboxReceipt, OrsError>;
    fn stage_and_reserve(
        &self,
        request: ReservationRequest,
    ) -> Result<WriterReservationToken, OrsError>;
    fn mark_eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError>;
    fn begin_execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError>;
    fn mark_unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError>;
    fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError>;
    fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError>;
    fn expire(
        &self,
        token: &WriterReservationToken,
        now_ms: i64,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<ReservationRecord, OrsError>;
    fn recover_page(&self, cursor: RecoveryCursor) -> Result<RecoveryPage, OrsError>;
    fn get_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryPayloadEnvelope>, OrsError>;
    fn fence_writer_epoch(
        &self,
        scopes: &[crate::OrderingScope],
        successor: &EpochLineage,
    ) -> Result<(), OrsError>;
}

/// redb-backed ORS implementation. Every mutating method commits one short transaction.
pub struct RedbRecoveryStore {
    database: Database,
    evidence: Arc<dyn CanonicalEvidenceProvider>,
    #[cfg(feature = "test-support")]
    authority_handoff_failpoint:
        std::sync::Mutex<Option<Arc<crate::test_support::AuthorityHandoffPersistenceFailpoint>>>,
}

impl RedbRecoveryStore {
    #[cfg(test)]
    pub(crate) fn write_process_start_raw_for_test(
        &self,
        record: &ProcessStartReplayRecord,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            let payload = encode(record)?;
            table
                .insert(record.operation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    #[cfg(test)]
    pub(crate) fn write_process_evidence_raw_for_test(
        &self,
        key: &str,
        record: &ProcessEvidenceRecord,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_EVIDENCE).map_err(storage)?;
            let payload = encode(record)?;
            table.insert(key, payload.as_str()).map_err(storage)?;
        }
        write.commit().map_err(storage)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn substitute_authority_snapshot_metadata_for_test(
        &self,
        substitution: crate::test_support::AuthoritySnapshotMetadataSubstitution,
    ) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current
                .iter()
                .map_err(storage)?
                .find_map(|entry| {
                    let (key, value) = entry.ok()?;
                    let record = decode_named::<DurableOperationalRecord>(
                        value.value(),
                        "operational_current",
                    )
                    .ok()?;
                    (record.kind == OperationalKind::AuthoritySnapshot)
                        .then(|| key.value().to_owned())
                })
                .ok_or(OrsError::AuthoritySnapshotUnavailable)?
        };
        let mut record = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let value = current
                .get(key.as_str())
                .map_err(storage)?
                .ok_or(OrsError::AuthoritySnapshotUnavailable)?;
            decode_named::<DurableOperationalRecord>(value.value(), "operational_current")?
        };
        let key =
            Self::operational_key(OperationalKind::AuthoritySnapshot, &record.input.subject_id);
        record.input.record_id = substitution.record_id;
        record.input.created_at_ms = substitution.created_at_ms;
        record.input.cleanup_after_ms = substitution.cleanup_after_ms;
        record.input.validate()?;
        record.operation_order = Self::next_operational_order(&write)?;
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn install_authority_handoff_failpoint(
        &self,
        failpoint: Arc<crate::test_support::AuthorityHandoffPersistenceFailpoint>,
    ) {
        if let Ok(mut slot) = self.authority_handoff_failpoint.lock() {
            *slot = Some(failpoint);
        }
    }

    /// Atomically reserves a process start, preserving every prior outcome.
    pub fn begin_process_start(
        &self,
        record: &ProcessStartReplayRecord,
    ) -> Result<Option<ProcessStartReplayRecord>, OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.operation_id.as_str();
        let existing = {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            if let Some(existing) = table.get(key).map_err(storage)? {
                let existing: ProcessStartReplayRecord = decode(existing.value())?;
                existing.validate()?;
                if existing.admission_digest != record.admission_digest
                    || existing.owner != record.owner
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "existing operation identity, digest, or owner conflicts"
                            .to_owned(),
                    });
                }
                Some(existing)
            } else {
                let payload = encode(&record)?;
                table.insert(key, payload.as_str()).map_err(storage)?;
                None
            }
        };
        write.commit().map_err(storage)?;
        Ok(existing)
    }

    /// Loads one process-start replay projection.
    pub fn load_process_start(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<ProcessStartReplayRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(PROCESS_START_REPLAY).map_err(storage)?;
        table
            .get(operation_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: ProcessStartReplayRecord = decode(value.value())?;
                record.validate()?;
                if record.operation_id != *operation_id {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "replay record operation identity does not match its key"
                            .to_owned(),
                    });
                }
                Ok(record)
            })
            .transpose()
    }

    /// Persists a replay projection without allowing identity replacement.
    pub fn persist_process_start(&self, record: &ProcessStartReplayRecord) -> Result<(), OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        let key = record.operation_id.as_str();
        {
            let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
            let existing: Option<ProcessStartReplayRecord> = table
                .get(key)
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            if let Some(existing) = &existing {
                existing.validate()?;
                if existing.admission_digest != record.admission_digest
                    || existing.owner != record.owner
                {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "identity replacement rejected".to_owned(),
                    });
                }
                let allowed = match (existing.state, record.state) {
                    (
                        ProcessStartReplayState::Reserved,
                        ProcessStartReplayState::Reserved
                        | ProcessStartReplayState::Completed
                        | ProcessStartReplayState::Unknown,
                    ) => true,
                    (ProcessStartReplayState::Completed, ProcessStartReplayState::Completed)
                    | (ProcessStartReplayState::Unknown, ProcessStartReplayState::Unknown) => {
                        *existing == *record
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_start_replay",
                        reason: "non-monotonic or conflicting replay transition".to_owned(),
                    });
                }
            }
            if existing.as_ref().is_none_or(|current| current != record) {
                let payload = encode(&record)?;
                table.insert(key, payload.as_str()).map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    /// Compare-and-deletes exactly one reserved process-start record.
    pub fn abort_process_start(
        &self,
        operation_id: &crate::OperationIdentity,
        admission_digest: &str,
        owner: &eliot_process::ProcessOwnerBinding,
    ) -> Result<ProcessStartReplayAbort, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let key = operation_id.as_str();
        let mut table = write.open_table(PROCESS_START_REPLAY).map_err(storage)?;
        let existing = {
            let Some(value) = table.get(key).map_err(storage)? else {
                drop(table);
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_start_replay",
                    reason: "reserved replay record disappeared before abort".to_owned(),
                });
            };
            decode::<ProcessStartReplayRecord>(value.value())?
        };
        existing.validate()?;
        if existing.operation_id != *operation_id
            || existing.admission_digest != admission_digest
            || existing.owner != *owner
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_start_replay",
                reason: "pre-effect abort identity mismatch".to_owned(),
            });
        }
        let result = if existing.state == ProcessStartReplayState::Reserved {
            table.remove(key).map_err(storage)?;
            ProcessStartReplayAbort::Released
        } else {
            ProcessStartReplayAbort::NotReleased
        };
        drop(table);
        write.commit().map_err(storage)?;
        Ok(result)
    }

    /// Atomically reserves one typed authority handoff by create-if-absent.
    pub fn begin_authority_handoff(
        &self,
        record: &AuthorityHandoffRecord,
    ) -> Result<AuthorityHandoffBegin, OrsError> {
        record.validate()?;
        if record.state != AuthorityHandoffState::Reserved {
            return Err(OrsError::IntegrityProblem {
                record_type: "authority_handoff",
                reason: "begin requires a RESERVED candidate".to_owned(),
            });
        }
        let write = self.database.begin_write().map_err(storage)?;
        let outcome = {
            let mut table = write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
            if let Some(existing) = table.get(record.handoff_id.as_str()).map_err(storage)? {
                let existing: AuthorityHandoffRecord = decode(existing.value())?;
                existing.validate()?;
                if !existing.same_identity(record) {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "authority_handoff",
                        reason: "same handoff id has conflicting identity".to_owned(),
                    });
                }
                AuthorityHandoffBegin::Existing(existing)
            } else {
                let payload = encode(record)?;
                table
                    .insert(record.handoff_id.as_str(), payload.as_str())
                    .map_err(storage)?;
                AuthorityHandoffBegin::Acquired
            }
        };
        write.commit().map_err(storage)?;
        Ok(outcome)
    }

    /// Commits a handoff outcome without replacing its immutable identity.
    pub fn persist_authority_handoff(
        &self,
        record: &AuthorityHandoffRecord,
    ) -> Result<(), OrsError> {
        record.validate()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
            let existing: Option<AuthorityHandoffRecord> = table
                .get(record.handoff_id.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            let existing: AuthorityHandoffRecord =
                existing.ok_or(OrsError::AuthoritySnapshotUnavailable)?;
            existing.validate()?;
            if !existing.same_identity(record) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "authority_handoff",
                    reason: "handoff identity replacement rejected".to_owned(),
                });
            }
            let allowed = match (existing.state, record.state) {
                (
                    AuthorityHandoffState::Reserved,
                    AuthorityHandoffState::Consumed | AuthorityHandoffState::Unknown,
                )
                | (AuthorityHandoffState::Consumed, AuthorityHandoffState::Unknown) => true,
                (AuthorityHandoffState::Consumed, AuthorityHandoffState::Consumed)
                | (AuthorityHandoffState::Unknown, AuthorityHandoffState::Unknown) => {
                    existing == *record
                }
                _ => false,
            };
            if !allowed {
                return Err(OrsError::IntegrityProblem {
                    record_type: "authority_handoff",
                    reason: "non-monotonic or conflicting handoff transition".to_owned(),
                });
            }
            let payload = encode(record)?;
            table
                .insert(record.handoff_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        #[cfg(feature = "test-support")]
        if record.state == AuthorityHandoffState::Consumed
            && self
                .authority_handoff_failpoint
                .lock()
                .ok()
                .and_then(|slot| slot.as_ref().map(Arc::clone))
                .is_some_and(|failpoint| failpoint.take_consume_commit_failure())
        {
            return Err(OrsError::Storage(
                "test-only uncertain consume commit outcome".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads one handoff for bounded recovery/reconciliation.
    pub fn load_authority_handoff(
        &self,
        handoff_id: &crate::OperationIdentity,
    ) -> Result<Option<AuthorityHandoffRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
        table
            .get(handoff_id.as_str())
            .map_err(storage)?
            .map(|value| {
                let record: AuthorityHandoffRecord = decode(value.value())?;
                record.validate()?;
                Ok(record)
            })
            .transpose()
    }

    /// Appends one observation-only evidence projection, preserving conflicts.
    pub fn persist_process_evidence(&self, record: &ProcessEvidenceRecord) -> Result<(), OrsError> {
        record.validate()?;
        let key = record.record_key()?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let mut table = write.open_table(PROCESS_EVIDENCE).map_err(storage)?;
            let existing: Option<ProcessEvidenceRecord> = table
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            if let Some(existing) = existing {
                existing.validate()?;
                if existing != *record {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "process_evidence",
                        reason: "conflicting evidence replacement rejected".to_owned(),
                    });
                }
            } else {
                let payload = encode(record)?;
                table
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }

    /// Reads bounded observation-only evidence history for one operation.
    pub fn load_process_evidence(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Vec<ProcessEvidenceRecord>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(PROCESS_EVIDENCE).map_err(storage)?;
        let start = format!("{}::", operation_id.as_str());
        let end = format!("{start}\u{10ffff}");
        let mut records = Vec::new();
        for entry in table.range(start.as_str()..end.as_str()).map_err(storage)? {
            let (key, value) = entry.map_err(storage)?;
            let key = key.value();
            let record: ProcessEvidenceRecord = decode(value.value())?;
            record.validate()?;
            let canonical_key = record.record_key()?;
            if record.operation_id != *operation_id || key != canonical_key {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_evidence",
                    reason: "evidence record does not match its canonical key".to_owned(),
                });
            }
            records.push(record);
            if records.len() > usize::from(crate::MAX_PROCESS_EVIDENCE_READBACK) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "process_evidence",
                    reason: "evidence history exceeds the bounded readback limit".to_owned(),
                });
            }
        }
        records.sort_by(|left, right| {
            left.observed_at_ms
                .cmp(&right.observed_at_ms)
                .then_with(|| left.evidence_digest.cmp(&right.evidence_digest))
                .then_with(|| left.record_key().ok().cmp(&right.record_key().ok()))
        });
        Ok(records)
    }

    /// Opens or creates an ORS database and converts interrupted execution to reconciliation.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OrsError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let database = Database::create(path).map_err(storage)?;
        let store = Self {
            database,
            evidence: Arc::new(RejectUnboundEvidence),
            #[cfg(feature = "test-support")]
            authority_handoff_failpoint: std::sync::Mutex::new(None),
        };
        store.initialize()?;
        store.recover_interrupted_execution()?;
        Ok(store)
    }

    /// Opens ORS with the composition-owned canonical/readback authenticator.
    pub fn open_with_evidence(
        path: impl AsRef<Path>,
        evidence: Arc<dyn CanonicalEvidenceProvider>,
    ) -> Result<Self, OrsError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(storage)?;
        }
        let database = Database::create(path).map_err(storage)?;
        let store = Self {
            database,
            evidence,
            #[cfg(feature = "test-support")]
            authority_handoff_failpoint: std::sync::Mutex::new(None),
        };
        store.initialize()?;
        store.recover_interrupted_execution()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        {
            drop(write.open_table(META).map_err(storage)?);
            drop(write.open_table(ENVELOPES).map_err(storage)?);
            drop(write.open_table(RESERVATIONS).map_err(storage)?);
            drop(write.open_table(RESERVATION_ORDERS).map_err(storage)?);
            drop(write.open_table(OPERATIONS).map_err(storage)?);
            drop(write.open_table(SCOPE_HEADS).map_err(storage)?);
            drop(write.open_table(SCOPE_TERMINALS).map_err(storage)?);
            drop(write.open_table(OPERATIONAL_CURRENT).map_err(storage)?);
            drop(write.open_table(OPERATIONAL_HISTORY).map_err(storage)?);
            drop(write.open_table(RECOVERY_INBOX).map_err(storage)?);
            drop(write.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?);
            drop(write.open_table(PROCESS_START_REPLAY).map_err(storage)?);
            drop(write.open_table(AUTHORITY_HANDOFFS).map_err(storage)?);
            drop(write.open_table(PROCESS_EVIDENCE).map_err(storage)?);
        }
        write.commit().map_err(storage)
    }

    fn recover_interrupted_execution(&self) -> Result<(), OrsError> {
        loop {
            let write = self.database.begin_write().map_err(storage)?;
            let mut interrupted = Vec::with_capacity(usize::from(crate::MAX_RECOVERY_PAGE));
            {
                let table = write.open_table(RESERVATIONS).map_err(storage)?;
                for row in table.iter().map_err(storage)? {
                    let (key, value) = row.map_err(storage)?;
                    let record: ReservationRecord = decode(value.value())?;
                    if record.state == ReservationState::Executing {
                        interrupted.push((key.value().to_owned(), record));
                        if interrupted.len() == usize::from(crate::MAX_RECOVERY_PAGE) {
                            break;
                        }
                    }
                }
            }
            if interrupted.is_empty() {
                return Ok(());
            }
            {
                let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                for (key, interrupted_record) in &interrupted {
                    let mut record = interrupted_record.clone();
                    record.state = ReservationState::Reconciling;
                    record.unknown_reason =
                        Some(OpaqueLabel::new("restart interrupted execution")?);
                    let payload = encode(&record)?;
                    reservations
                        .insert(key.as_str(), payload.as_str())
                        .map_err(storage)?;
                }
            }
            {
                let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
                for (_, record) in &interrupted {
                    for reserved in &record.token.scopes {
                        let key = reserved.scope.as_str();
                        let value = heads.get(key).map_err(storage)?.ok_or_else(|| {
                            OrsError::IntegrityProblem {
                                record_type: "scope_head",
                                reason: "interrupted reservation scope head is missing".to_owned(),
                            }
                        })?;
                        let mut head: ScopeReservationHead = decode(value.value())?;
                        drop(value);
                        head.recovery_blocked = true;
                        let payload = encode(&head)?;
                        heads.insert(key, payload.as_str()).map_err(storage)?;
                    }
                }
            }
            write.commit().map_err(storage)?;
        }
    }

    /// Returns one bounded, non-authoritative operational projection page.
    pub fn projection_page(
        &self,
        active_receipt: &ReceiptEnvelope,
        cursor: RecoveryCursor,
    ) -> Result<(OperationalRecoveryState, Option<u64>), OrsError> {
        let page = self.recover_page(cursor)?;
        let next_after_order = page.next_after_order;
        let mut pending_operation_refs = Vec::new();
        let mut recovery_intent_refs = Vec::new();
        for record in page.records {
            pending_operation_refs.push(record.token.operation_id.as_str().to_owned());
            if record.state == ReservationState::Reconciling {
                recovery_intent_refs.push(record.token.reservation_id.as_str().to_owned());
            }
        }
        active_receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        self.evidence.verify_receipt(active_receipt)?;
        let active_epoch = active_receipt.core.authority.authority_epoch.value();
        let read = self.database.begin_read().map_err(storage)?;
        let operational = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut authority_snapshot_found = false;
        for row in operational.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if record.kind == OperationalKind::AuthoritySnapshot
                && record.phase == OperationalPhase::Active
                && record.input.authority_epoch.current.epoch == active_epoch
            {
                authority_snapshot_found = true;
                break;
            }
        }
        if !authority_snapshot_found {
            return Err(OrsError::AuthoritySnapshotUnavailable);
        }
        let active_generation_refs = self.active_operational_refs(
            &[
                OperationalKind::GenerationTransition,
                OperationalKind::GenerationCutover,
            ],
            cursor.limit,
        )?;
        let inbox = read.open_table(RECOVERY_INBOX).map_err(storage)?;
        for row in inbox.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if record.disposition == RecoveryInboxDisposition::Imported {
                push_bounded(
                    &mut recovery_intent_refs,
                    record.item.item_id.as_str().to_owned(),
                    usize::from(cursor.limit),
                )?;
            }
        }
        recovery_intent_refs.sort();
        recovery_intent_refs.dedup();
        let projection = OperationalRecoveryState {
            ors_revision: format!("eliot.kernel.ors/v{}", crate::CONTRACT_VERSION),
            integrity: HealthDimension::Healthy,
            authority_epoch: active_receipt.core.authority.authority_epoch,
            pending_operation_refs,
            active_generation_refs,
            recovery_intent_refs,
        };
        projection
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        Ok((projection, next_after_order))
    }

    /// Rebuilds one bounded generation/epoch/session/control projection from validated ORS rows.
    #[allow(
        clippy::too_many_lines,
        reason = "the projection exhaustively classifies each persisted operational kind in one scan"
    )]
    pub fn control_projection_page(
        &self,
        cursor: RecoveryCursor,
    ) -> Result<(OperationalControlProjection, Option<u64>), OrsError> {
        let page = self.recover_page(cursor)?;
        let next_after_order = page.next_after_order;
        let pending_operation_refs = page
            .records
            .into_iter()
            .map(|record| record.token.operation_id.as_str().to_owned())
            .collect();
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut authority: Option<(u64, EpochLineage)> = None;
        let mut active_generation_refs = Vec::new();
        let mut active_session_refs = Vec::new();
        let mut active_user_broker_refs = Vec::new();
        let mut active_capability_refs = Vec::new();
        let mut job_checkpoint_refs = Vec::new();
        let mut delivery_cursor_refs = Vec::new();
        for row in current.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            let subject = record.input.subject_id.as_str().to_owned();
            match (record.kind, record.phase) {
                (OperationalKind::AuthoritySnapshot, OperationalPhase::Active) => {
                    if authority
                        .as_ref()
                        .is_none_or(|(order, _)| *order < record.operation_order)
                    {
                        authority =
                            Some((record.operation_order, record.input.authority_epoch.clone()));
                    }
                }
                (
                    OperationalKind::GenerationTransition | OperationalKind::GenerationCutover,
                    OperationalPhase::Active | OperationalPhase::Applying,
                ) => push_bounded(
                    &mut active_generation_refs,
                    subject,
                    usize::from(cursor.limit),
                )?,
                (OperationalKind::SessionBinding, OperationalPhase::Active) => {
                    push_bounded(&mut active_session_refs, subject, usize::from(cursor.limit))?;
                }
                (OperationalKind::UserBroker, OperationalPhase::Active) => {
                    push_bounded(
                        &mut active_user_broker_refs,
                        subject,
                        usize::from(cursor.limit),
                    )?;
                }
                (
                    OperationalKind::CapabilityGrant | OperationalKind::CapabilityIntroduction,
                    OperationalPhase::Active,
                ) => push_bounded(
                    &mut active_capability_refs,
                    subject,
                    usize::from(cursor.limit),
                )?,
                (OperationalKind::JobCheckpoint, OperationalPhase::Active) => {
                    push_bounded(&mut job_checkpoint_refs, subject, usize::from(cursor.limit))?;
                }
                (OperationalKind::DeliveryCursor, OperationalPhase::Active) => {
                    push_bounded(
                        &mut delivery_cursor_refs,
                        subject,
                        usize::from(cursor.limit),
                    )?;
                }
                _ => {}
            }
        }
        let authority_lineage = authority
            .map(|(_, lineage)| lineage)
            .ok_or(OrsError::AuthoritySnapshotUnavailable)?;
        let inbox = read.open_table(RECOVERY_INBOX).map_err(storage)?;
        let mut recovery_inbox_refs = Vec::new();
        for row in inbox.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
            if record.disposition == RecoveryInboxDisposition::Imported {
                push_bounded(
                    &mut recovery_inbox_refs,
                    record.item.item_id.as_str().to_owned(),
                    usize::from(cursor.limit),
                )?;
            }
        }
        for refs in [
            &mut active_generation_refs,
            &mut active_session_refs,
            &mut active_user_broker_refs,
            &mut active_capability_refs,
            &mut job_checkpoint_refs,
            &mut delivery_cursor_refs,
            &mut recovery_inbox_refs,
        ] {
            refs.sort();
            refs.dedup();
        }
        Ok((
            OperationalControlProjection {
                authority_lineage,
                pending_operation_refs,
                active_generation_refs,
                active_session_refs,
                active_user_broker_refs,
                active_capability_refs,
                job_checkpoint_refs,
                delivery_cursor_refs,
                recovery_inbox_refs,
            },
            next_after_order,
        ))
    }

    /// Returns one validated terminal sequence binding without exposing a writable receipt type.
    pub fn scope_terminal(
        &self,
        scope: &crate::OrderingScope,
        reserved_sequence: u64,
    ) -> Result<Option<ScopeTerminalView>, OrsError> {
        let key = format!("{}:{reserved_sequence:020}", scope.as_str());
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(SCOPE_TERMINALS).map_err(storage)?;
        table
            .get(key.as_str())
            .map_err(storage)?
            .map(|value| {
                decode::<ScopeTerminalReceipt>(value.value())
                    .map(|receipt| ScopeTerminalView::from_persisted(&receipt))
            })
            .transpose()
    }

    fn load_record(
        table: &impl ReadableTable<&'static str, &'static str>,
        reservation_id: &crate::OperationIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        let value = table
            .get(reservation_id.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        decode(value.value())
    }

    fn validate_token(
        stored: &ReservationRecord,
        supplied: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        if stored.token != *supplied {
            return Err(OrsError::DuplicateConflict);
        }
        Ok(())
    }

    fn ensure_no_predecessor(
        table: &impl ReadableTable<&'static str, &'static str>,
        token: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: ReservationRecord = decode(value.value())?;
            if !record.state.is_terminal()
                && record.token.reservation_order < token.reservation_order
                && shares_scope(&record.token, token)
            {
                return Err(OrsError::PredecessorPending);
            }
        }
        Ok(())
    }

    fn ensure_canonical_heads(
        write: &redb::WriteTransaction,
        token: &WriterReservationToken,
    ) -> Result<(), OrsError> {
        let heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for reserved in &token.scopes {
            let value = heads
                .get(reserved.scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "scope_head",
                    reason: "reserved scope head is missing".to_owned(),
                })?;
            let head: ScopeReservationHead = decode_named(value.value(), "scope_head")?;
            if head.canonical_head != reserved.expected_head {
                return Err(OrsError::OrderingHeadMismatch);
            }
        }
        Ok(())
    }

    fn clear_recovery_blocks(
        write: &redb::WriteTransaction,
        closed: &ReservationRecord,
    ) -> Result<(), OrsError> {
        let blocked_scopes: BTreeSet<_> = closed
            .token
            .scopes
            .iter()
            .map(|scope| scope.scope.clone())
            .collect();
        let mut still_blocked = BTreeSet::new();
        {
            let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for row in reservations.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: ReservationRecord = decode(value.value())?;
                if record.token.reservation_id != closed.token.reservation_id
                    && record.state == ReservationState::Reconciling
                {
                    for scope in &record.token.scopes {
                        if blocked_scopes.contains(&scope.scope) {
                            still_blocked.insert(scope.scope.clone());
                        }
                    }
                }
            }
        }
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for scope in blocked_scopes {
            let value = heads
                .get(scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::Storage("missing scope head".to_owned()))?;
            let mut head: ScopeReservationHead = decode(value.value())?;
            drop(value);
            head.recovery_blocked = still_blocked.contains(&scope);
            let payload = encode(&head)?;
            heads
                .insert(scope.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    fn record_scope_terminals(
        write: &redb::WriteTransaction,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        let mut terminals = write.open_table(SCOPE_TERMINALS).map_err(storage)?;
        for observed in &reconciliation.scopes {
            let value = heads
                .get(observed.scope.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "scope_head",
                    reason: "scope terminal has no durable head".to_owned(),
                })?;
            let mut head: ScopeReservationHead = decode_named(value.value(), "scope_head")?;
            drop(value);
            if head.canonical_head != observed.prior_head
                || observed.committed_sequence > head.last_reserved_sequence
                || observed.committed_sequence <= head.last_terminal_sequence
            {
                return Err(OrsError::OrderingHeadMismatch);
            }
            let gap = reconciliation.disposition == CanonicalDisposition::Rejected;
            if !gap {
                head.canonical_head = crate::ExpectedOrderingHead {
                    sequence: observed.committed_sequence,
                    head_sha256: observed.committed_head_sha256.clone(),
                    revision_head: observed.committed_revision_head.clone(),
                };
            }
            head.last_terminal_sequence = observed.committed_sequence;
            let terminal = ScopeTerminalReceipt {
                scope: observed.scope.clone(),
                reserved_sequence: observed.committed_sequence,
                disposition: reconciliation.disposition,
                gap,
                receipt_id: observed.receipt_id.clone(),
                receipt_sha256: reconciliation.receipt.identity.canonical_sha256.clone(),
            };
            let head_payload = encode(&head)?;
            heads
                .insert(observed.scope.as_str(), head_payload.as_str())
                .map_err(storage)?;
            let terminal_key = format!(
                "{}:{:020}",
                observed.scope.as_str(),
                observed.committed_sequence
            );
            let terminal_payload = encode(&terminal)?;
            terminals
                .insert(terminal_key.as_str(), terminal_payload.as_str())
                .map_err(storage)?;
        }
        Ok(())
    }

    fn existing_token(
        write: &redb::WriteTransaction,
        request: &ReservationRequest,
    ) -> Result<Option<WriterReservationToken>, OrsError> {
        let reservation_id = {
            let operations = write.open_table(OPERATIONS).map_err(storage)?;
            operations
                .get(request.envelope.operation_or_checkpoint_id.as_str())
                .map_err(storage)?
                .map(|value| value.value().to_owned())
        };
        if let Some(reservation_id) = reservation_id {
            let reservation_id =
                OpaqueLabel::new(reservation_id).map_err(|error| OrsError::IntegrityProblem {
                    record_type: "operation_index",
                    reason: error.to_string(),
                })?;
            let record = {
                let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                let value = reservations
                    .get(reservation_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("operation index is dangling".to_owned()))?;
                decode::<ReservationRecord>(value.value())?
            };
            let envelope = {
                let envelopes = write.open_table(ENVELOPES).map_err(storage)?;
                let value = envelopes
                    .get(request.envelope.operation_or_checkpoint_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("operation envelope is missing".to_owned()))?;
                decode::<RecoveryPayloadEnvelope>(value.value())?
            };
            if request_matches(request, &record.token, &envelope) {
                return Ok(Some(record.token));
            }
            return Err(OrsError::DuplicateConflict);
        }
        let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
        if reservations
            .get(request.reservation_id.as_str())
            .map_err(storage)?
            .is_some()
        {
            return Err(OrsError::DuplicateConflict);
        }
        Ok(None)
    }

    fn next_reservation_order(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(NEXT_GLOBAL_ORDER)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        let next = prior
            .checked_add(1)
            .ok_or_else(|| OrsError::Storage("reservation order counter exhausted".to_owned()))?;
        meta.insert(NEXT_GLOBAL_ORDER, next.to_string().as_str())
            .map_err(storage)?;
        Ok(next)
    }

    fn reserve_scope_sequences(
        write: &redb::WriteTransaction,
        request: &ReservationRequest,
    ) -> Result<Vec<ReservedScope>, OrsError> {
        let mut reserved_scopes = Vec::with_capacity(request.scopes.len());
        let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
        for requested in &request.scopes {
            let existing: Option<ScopeReservationHead> = heads
                .get(requested.scope.as_str())
                .map_err(storage)?
                .map(|value| decode(value.value()))
                .transpose()?;
            let mut head = existing.map_or_else(
                || {
                    Ok(ScopeReservationHead {
                        writer_epoch: request.writer_epoch.current.clone(),
                        canonical_head: requested.expected_head.clone(),
                        last_reserved_sequence: requested.expected_head.sequence,
                        last_terminal_sequence: requested.expected_head.sequence,
                        recovery_blocked: false,
                    })
                },
                |decoded| {
                    if decoded.recovery_blocked {
                        return Err(OrsError::ScopeRecoveryRequired);
                    }
                    if decoded.writer_epoch != request.writer_epoch.current {
                        return Err(OrsError::StaleWriterEpoch);
                    }
                    if decoded.canonical_head != requested.expected_head {
                        return Err(OrsError::OrderingHeadMismatch);
                    }
                    Ok(decoded)
                },
            )?;
            let reserved_sequence = head
                .last_reserved_sequence
                .checked_add(1)
                .ok_or_else(|| OrsError::Storage("scope sequence exhausted".to_owned()))?;
            head.last_reserved_sequence = reserved_sequence;
            let payload = encode(&head)?;
            heads
                .insert(requested.scope.as_str(), payload.as_str())
                .map_err(storage)?;
            reserved_scopes.push(ReservedScope {
                scope: requested.scope.clone(),
                reserved_sequence,
                expected_head: requested.expected_head.clone(),
            });
        }
        Ok(reserved_scopes)
    }

    fn persist_new_reservation(
        write: &redb::WriteTransaction,
        envelope: &RecoveryPayloadEnvelope,
        record: &ReservationRecord,
    ) -> Result<(), OrsError> {
        let token = &record.token;
        {
            let mut envelopes = write.open_table(ENVELOPES).map_err(storage)?;
            let payload = encode(envelope)?;
            envelopes
                .insert(token.operation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        {
            let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            let payload = encode(record)?;
            reservations
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        let mut operations = write.open_table(OPERATIONS).map_err(storage)?;
        operations
            .insert(token.operation_id.as_str(), token.reservation_id.as_str())
            .map_err(storage)?;
        drop(operations);
        let order_key = format!("{:020}", token.reservation_order);
        let mut orders = write.open_table(RESERVATION_ORDERS).map_err(storage)?;
        if orders
            .insert(order_key.as_str(), token.reservation_id.as_str())
            .map_err(storage)?
            .is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "reservation_order",
                reason: "duplicate reservation order".to_owned(),
            });
        }
        Ok(())
    }

    fn next_operational_order(write: &redb::WriteTransaction) -> Result<u64, OrsError> {
        let mut meta = write.open_table(META).map_err(storage)?;
        let prior = meta
            .get(NEXT_GLOBAL_ORDER)
            .map_err(storage)?
            .map(|value| value.value().parse::<u64>())
            .transpose()
            .map_err(|error| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: error.to_string(),
            })?
            .unwrap_or(0);
        let next = prior
            .checked_add(1)
            .ok_or_else(|| OrsError::IntegrityProblem {
                record_type: "ors_meta_v1",
                reason: "operational order counter exhausted".to_owned(),
            })?;
        meta.insert(NEXT_GLOBAL_ORDER, next.to_string().as_str())
            .map_err(storage)?;
        Ok(next)
    }

    fn operational_key(kind: OperationalKind, subject: &crate::OperationIdentity) -> String {
        format!("{}:{}", kind.key_prefix(), subject.as_str())
    }

    fn receipt_for(
        record: &DurableOperationalRecord,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        let encoded = encode(record)?;
        OperationalMutationReceipt::issue(
            record.input.record_id.clone(),
            record.input.subject_id.clone(),
            record.operation_order,
            record.phase,
            crate::model::sha256_hex(encoded.as_bytes()),
        )
    }

    fn persist_operational_record(
        write: &redb::WriteTransaction,
        key: &str,
        record: &DurableOperationalRecord,
    ) -> Result<(), OrsError> {
        let encoded = encode(record)?;
        {
            let mut current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current.insert(key, encoded.as_str()).map_err(storage)?;
        }
        let history_key = format!("{:020}:{key}", record.operation_order);
        let mut history = write.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
        history
            .insert(history_key.as_str(), encoded.as_str())
            .map_err(storage)?;
        Ok(())
    }

    fn mutate_operational(
        &self,
        kind: OperationalKind,
        input: OperationalRecordInput,
        require_existing: bool,
        allowed_prior: &[OperationalPhase],
        next_phase: OperationalPhase,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        input.validate()?;
        let key = Self::operational_key(kind, &input.subject_id);
        let write = self.database.begin_write().map_err(storage)?;
        let existing = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current
                .get(key.as_str())
                .map_err(storage)?
                .map(|value| {
                    decode_named::<DurableOperationalRecord>(value.value(), "operational_current")
                })
                .transpose()?
        };
        if let Some(existing) = existing {
            if existing.input.record_id == input.record_id {
                if existing.input == input && existing.phase == next_phase {
                    return Self::receipt_for(&existing);
                }
                return Err(OrsError::DuplicateConflict);
            }
            if !allowed_prior.contains(&existing.phase) {
                return Err(OrsError::InvalidTransition);
            }
            if !input
                .authority_epoch
                .succeeds(&existing.input.authority_epoch.current)
            {
                return Err(OrsError::InvalidEpochLineage);
            }
        } else if require_existing {
            return Err(OrsError::InvalidTransition);
        }
        let record = DurableOperationalRecord {
            kind,
            input,
            phase: next_phase,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: None,
        };
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)?;
        Self::receipt_for(&record)
    }

    fn transition_existing_operational(
        &self,
        kind: OperationalKind,
        subject: &crate::OperationIdentity,
        allowed_prior: &[OperationalPhase],
        next_phase: OperationalPhase,
        terminal_receipt: Option<&ReceiptEnvelope>,
    ) -> Result<OperationalMutationReceipt, OrsError> {
        let key = Self::operational_key(kind, subject);
        let write = self.database.begin_write().map_err(storage)?;
        let mut record = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let value = current
                .get(key.as_str())
                .map_err(storage)?
                .ok_or(OrsError::ReservationNotFound)?;
            decode_named::<DurableOperationalRecord>(value.value(), "operational_current")?
        };
        if record.phase == next_phase {
            if terminal_receipt.is_none()
                || record.terminal_receipt_id.as_ref().map(OpaqueLabel::as_str)
                    == terminal_receipt.map(|receipt| receipt.identity.receipt_id.as_str())
            {
                return Self::receipt_for(&record);
            }
            return Err(OrsError::DuplicateConflict);
        }
        if !allowed_prior.contains(&record.phase) {
            return Err(OrsError::InvalidTransition);
        }
        record.phase = next_phase;
        record.operation_order = Self::next_operational_order(&write)?;
        if let Some(receipt) = terminal_receipt {
            record.terminal_receipt_id =
                Some(OpaqueLabel::new(receipt.identity.receipt_id.as_str())?);
            record.terminal_receipt_sha256 = Some(receipt.identity.canonical_sha256.clone());
        }
        Self::persist_operational_record(&write, &key, &record)?;
        write.commit().map_err(storage)?;
        Self::receipt_for(&record)
    }

    fn active_operational_refs(
        &self,
        kinds: &[OperationalKind],
        limit: u16,
    ) -> Result<Vec<String>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut refs = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let record: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if kinds.contains(&record.kind)
                && matches!(
                    record.phase,
                    OperationalPhase::Active | OperationalPhase::Applying
                )
            {
                push_bounded(
                    &mut refs,
                    record.input.subject_id.as_str().to_owned(),
                    usize::from(limit),
                )?;
            }
        }
        refs.sort();
        Ok(refs)
    }

    fn generation_operational_input(
        record: &RuntimeGenerationCutoverRecord,
    ) -> Result<OperationalRecordInput, OrsError> {
        let epoch = record.old_epoch.value();
        let authority_epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new("generation-cutover")?,
                epoch,
            },
            predecessor: None,
        };
        let state_fence = StateFenceSnapshot::capture(
            &json!({
                "cutover_id": record.cutover_id,
                "route_scope": record.route_scope,
                "authority_epoch": epoch,
            }),
            epoch,
        )?;
        let payload =
            serde_json::to_vec(record).map_err(|error| OrsError::Encoding(error.to_string()))?;
        let payload_length = u64::try_from(payload.len()).map_err(|_| OrsError::PayloadTooLarge)?;
        OperationalRecordInput::immutable_locator(
            OperationalRecordContext {
                record_id: OpaqueLabel::new(format!("generation-cutover:{}", record.cutover_id))?,
                subject_id: OpaqueLabel::new(record.route_scope.clone())?,
                authority_epoch,
                state_fence,
                created_at_ms: 0,
                cleanup_after_ms: None,
            },
            PlatformHandle::new(format!("ors:generation-cutover:{}", record.cutover_id))
                .map_err(|error| OrsError::Contract(error.to_string()))?,
            crate::model::sha256_hex(&payload),
            payload_length,
        )
    }

    fn generation_snapshot(
        durable: &DurableOperationalRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        let record =
            durable
                .generation_cutover
                .clone()
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "operational_record",
                    reason: "generation operational record has no typed cutover".to_owned(),
                })?;
        let receipt = GenerationCutoverReceipt::from_receipt(Self::receipt_for(durable)?);
        Ok(GenerationCutoverSnapshot::new(
            record,
            durable.operation_order,
            receipt,
        ))
    }

    fn decode_operational_current(
        write: &redb::WriteTransaction,
        key: &str,
    ) -> Result<Option<DurableOperationalRecord>, OrsError> {
        let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        current
            .get(key)
            .map_err(storage)?
            .map(|value| {
                decode_named::<DurableOperationalRecord>(value.value(), "operational_current")
            })
            .transpose()
    }

    /// Persists one candidate transition before the cutover linearization
    /// point.  The candidate is stored in the canonical operational current
    /// and history projections and is never an active route.
    pub fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        record
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        let input = Self::generation_operational_input(&record)?;
        let key = Self::operational_key(OperationalKind::GenerationTransition, &input.subject_id);
        let cutover_key =
            Self::operational_key(OperationalKind::GenerationCutover, &input.subject_id);
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(existing) = Self::decode_operational_current(&write, &cutover_key)? {
            let committed = RuntimeGenerationCutoverRecord {
                state: GenerationCutoverState::Committed,
                ..record.clone()
            };
            if existing.kind == OperationalKind::GenerationCutover
                && existing.phase == OperationalPhase::Active
                && existing
                    .generation_cutover
                    .as_ref()
                    .is_some_and(|value| value == &committed)
            {
                return Self::generation_snapshot(&existing);
            }
        }
        if let Some(existing) = Self::decode_operational_current(&write, &key)? {
            if existing.kind == OperationalKind::GenerationTransition
                && existing.phase == OperationalPhase::Applying
                && existing.input == input
                && existing.generation_cutover.as_ref() == Some(&record)
            {
                return Self::generation_snapshot(&existing);
            }
            return Err(OrsError::DuplicateConflict);
        }
        let durable = DurableOperationalRecord {
            kind: OperationalKind::GenerationTransition,
            input,
            phase: OperationalPhase::Applying,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: Some(record),
        };
        Self::persist_operational_record(&write, &key, &durable)?;
        write.commit().map_err(storage)?;
        Self::generation_snapshot(&durable)
    }

    /// Commits one staged transition and records the route atomically in the
    /// canonical operational current/history projections.  The commit record
    /// is the sole durable cutover linearization point.
    #[allow(
        clippy::too_many_lines,
        reason = "the cutover transaction validates route, epoch, receipt, and projection atomically"
    )]
    pub fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        record
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        if record.state != GenerationCutoverState::Armed {
            return Err(OrsError::InvalidTransition);
        }
        let expected_input = Self::generation_operational_input(&record)?;
        let route_key = Self::operational_key(
            OperationalKind::GenerationCutover,
            &expected_input.subject_id,
        );
        let transition_key = Self::operational_key(
            OperationalKind::GenerationTransition,
            &expected_input.subject_id,
        );
        let write = self.database.begin_write().map_err(storage)?;

        if let Some(existing) = Self::decode_operational_current(&write, &route_key)? {
            let committed = RuntimeGenerationCutoverRecord {
                state: GenerationCutoverState::Committed,
                ..record.clone()
            };
            if existing.kind == OperationalKind::GenerationCutover
                && existing.phase == OperationalPhase::Active
                && existing
                    .generation_cutover
                    .as_ref()
                    .is_some_and(|value| value == &committed)
            {
                return Self::generation_snapshot(&existing);
            }
        }

        let transition = Self::decode_operational_current(&write, &transition_key)?
            .ok_or(OrsError::ReservationNotFound)?;
        if transition.kind != OperationalKind::GenerationTransition
            || transition.phase != OperationalPhase::Applying
            || transition.input != expected_input
            || transition.generation_cutover.as_ref() != Some(&record)
        {
            return Err(OrsError::DuplicateConflict);
        }

        let existing_route = Self::decode_operational_current(&write, &route_key)?;
        if let Some(existing) = &existing_route {
            let prior =
                existing
                    .generation_cutover
                    .as_ref()
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "operational_current",
                        reason: "generation route is missing typed cutover".to_owned(),
                    })?;
            if existing.kind != OperationalKind::GenerationCutover
                || existing.phase != OperationalPhase::Active
                || prior.state != GenerationCutoverState::Committed
            {
                return Err(OrsError::InvalidTransition);
            }
            if prior.new_epoch.value() > record.old_epoch.value()
                || Some(prior.new_generation) != record.old_generation
            {
                return Err(OrsError::InvalidEpochLineage);
            }
        } else if record.old_generation.is_some() {
            return Err(OrsError::InvalidEpochLineage);
        }

        let global_epoch = {
            let current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            let mut maximum = None;
            for row in current.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let candidate: DurableOperationalRecord =
                    decode_named(value.value(), "operational_current")?;
                if candidate.kind == OperationalKind::GenerationCutover
                    && candidate.phase == OperationalPhase::Active
                    && let Some(cutover) = candidate.generation_cutover
                {
                    if cutover.state != GenerationCutoverState::Committed {
                        return Err(OrsError::IntegrityProblem {
                            record_type: "operational_current",
                            reason: "active generation route is not committed".to_owned(),
                        });
                    }
                    maximum = Some(maximum.map_or(cutover.new_epoch.value(), |value: u64| {
                        value.max(cutover.new_epoch.value())
                    }));
                }
            }
            maximum
        };
        if let Some(global_epoch) = global_epoch
            && record.old_epoch.value() != global_epoch
        {
            return Err(OrsError::InvalidEpochLineage);
        }
        if global_epoch.is_none() && record.old_epoch.value() != 1 {
            return Err(OrsError::InvalidEpochLineage);
        }

        let committed = RuntimeGenerationCutoverRecord {
            state: GenerationCutoverState::Committed,
            ..record
        };
        let durable = DurableOperationalRecord {
            kind: OperationalKind::GenerationCutover,
            input: transition.input,
            phase: OperationalPhase::Active,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
            generation_cutover: Some(committed),
        };
        Self::persist_operational_record(&write, &route_key, &durable)?;
        {
            let mut current = write.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
            current.remove(transition_key.as_str()).map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Self::generation_snapshot(&durable)
    }

    /// Returns the bounded latest committed route set from canonical current
    /// operational records, ordered by their durable operation order.
    pub fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut records = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (_, value) = row.map_err(storage)?;
            let durable: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            if durable.kind != OperationalKind::GenerationCutover
                || durable.phase != OperationalPhase::Active
            {
                continue;
            }
            let Some(record) = durable.generation_cutover.as_ref() else {
                // Older generic GenerationCutover records have no route
                // projection and are not allowed to become runtime authority.
                continue;
            };
            if record.state != GenerationCutoverState::Committed {
                return Err(OrsError::IntegrityProblem {
                    record_type: "operational_current",
                    reason: "active generation route is not committed".to_owned(),
                });
            }
            if records.len() == usize::from(limit) {
                return Err(OrsError::ProjectionLimitExceeded);
            }
            records.push(Self::generation_snapshot(&durable)?);
        }
        records.sort_by_key(GenerationCutoverSnapshot::operation_order);
        Ok(records)
    }

    /// Reconciles staged candidates through the normative
    /// `Reconciling -> FailedRequiresForwardCutover` runtime path.  The
    /// resulting records remain fenced evidence in the canonical current and
    /// history projections and can never activate a route.
    pub fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        if limit == 0 || limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let mut pending = Vec::new();
        for row in table.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let durable: DurableOperationalRecord =
                decode_named(value.value(), "operational_current")?;
            let Some(record) = durable.generation_cutover.as_ref() else {
                continue;
            };
            if durable.kind == OperationalKind::GenerationTransition
                && matches!(
                    record.state,
                    GenerationCutoverState::Armed
                        | GenerationCutoverState::Reconciling
                        | GenerationCutoverState::FailedRequiresForwardCutover
                )
            {
                if pending.len() == usize::from(limit) {
                    return Err(OrsError::ProjectionLimitExceeded);
                }
                pending.push((key.value().to_owned(), durable));
            }
        }
        drop(table);
        drop(read);

        let write = self.database.begin_write().map_err(storage)?;
        let mut snapshots = Vec::with_capacity(pending.len());
        for (key, prior) in pending {
            let Some(prior_record) = prior.generation_cutover.clone() else {
                return Err(OrsError::IntegrityProblem {
                    record_type: "operational_current",
                    reason: "generation transition has no typed cutover".to_owned(),
                });
            };
            if prior_record.state == GenerationCutoverState::FailedRequiresForwardCutover {
                snapshots.push(Self::generation_snapshot(&prior)?);
                continue;
            }
            let reconciling = match prior_record.state {
                GenerationCutoverState::Armed => RuntimeGenerationCutoverRecord {
                    state: prior_record
                        .state
                        .transition_to(GenerationCutoverState::Reconciling)
                        .map_err(|error| OrsError::Contract(error.to_string()))?,
                    ..prior_record.clone()
                },
                GenerationCutoverState::Reconciling => prior_record.clone(),
                _ => return Err(OrsError::InvalidTransition),
            };
            if prior_record.state == GenerationCutoverState::Armed {
                let mut evidence = prior.clone();
                evidence.phase = OperationalPhase::Reconciling;
                evidence.operation_order = Self::next_operational_order(&write)?;
                evidence.generation_cutover = Some(reconciling.clone());
                Self::persist_operational_record(&write, &key, &evidence)?;
            }
            let failed = RuntimeGenerationCutoverRecord {
                state: reconciling
                    .state
                    .transition_to(GenerationCutoverState::FailedRequiresForwardCutover)
                    .map_err(|error| OrsError::Contract(error.to_string()))?,
                ..reconciling
            };
            let mut evidence = prior;
            evidence.phase = OperationalPhase::Fenced;
            evidence.operation_order = Self::next_operational_order(&write)?;
            evidence.generation_cutover = Some(failed);
            Self::persist_operational_record(&write, &key, &evidence)?;
            snapshots.push(Self::generation_snapshot(&evidence)?);
        }
        write.commit().map_err(storage)?;
        Ok(snapshots)
    }
}

impl OperationalRecoveryStore for RedbRecoveryStore {
    fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        RedbRecoveryStore::stage_generation_cutover(self, record)
    }

    fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        RedbRecoveryStore::commit_generation_cutover_state(self, record)
    }

    fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        RedbRecoveryStore::latest_generation_cutovers(self, limit)
    }

    fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        RedbRecoveryStore::reconcile_staged_generation_cutovers(self, limit)
    }

    fn stage(&self, op: StagedOperation) -> Result<StageReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::Operation,
            op.0,
            false,
            &[],
            OperationalPhase::Staged,
        )
        .map(StageReceipt::from_receipt)
    }

    fn mark_applying(&self, operation_id: crate::OperationIdentity) -> Result<(), OrsError> {
        self.transition_existing_operational(
            OperationalKind::Operation,
            &operation_id,
            &[OperationalPhase::Staged],
            OperationalPhase::Applying,
            None,
        )?;
        Ok(())
    }

    fn record_outcome(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let operation_id = OpaqueLabel::new(receipt.core.operation.operation_id.as_str())?;
        let key = Self::operational_key(OperationalKind::Operation, &operation_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let value = current
            .get(key.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        let operation: DurableOperationalRecord =
            decode_named(value.value(), "operational_current")?;
        let receipt_fence = crate::StateFenceSnapshot::capture(
            &receipt.core.operation.state_fence,
            receipt.core.authority.authority_epoch.value(),
        )?;
        if operation.input.subject_id != operation_id
            || operation.input.authority_epoch.current.epoch
                != receipt.core.authority.authority_epoch.value()
            || operation.input.state_fence != receipt_fence
            || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
            || receipt.core.causal.state_fence != receipt.core.operation.state_fence
            || receipt.core.authority.state_fence != receipt.core.operation.state_fence
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        drop(value);
        drop(current);
        drop(read);
        self.evidence.verify_receipt(receipt)?;
        let next_phase = match receipt.core.disposition.kind() {
            ReceiptDispositionKind::Unknown => OperationalPhase::Reconciling,
            ReceiptDispositionKind::Success
            | ReceiptDispositionKind::Partial
            | ReceiptDispositionKind::Failure
            | ReceiptDispositionKind::Cancelled => OperationalPhase::Terminal,
        };
        self.transition_existing_operational(
            OperationalKind::Operation,
            &operation_id,
            &[OperationalPhase::Applying],
            next_phase,
            Some(receipt),
        )?;
        Ok(())
    }

    fn schedule_retry(
        &self,
        operation_id: crate::OperationIdentity,
        retry: RetryState,
    ) -> Result<(), OrsError> {
        if retry.0.subject_id != operation_id {
            return Err(OrsError::DuplicateConflict);
        }
        let key = Self::operational_key(OperationalKind::Operation, &operation_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let value = current
            .get(key.as_str())
            .map_err(storage)?
            .ok_or(OrsError::ReservationNotFound)?;
        let operation: DurableOperationalRecord =
            decode_named(value.value(), "operational_current")?;
        if operation.phase != OperationalPhase::Terminal || operation.terminal_receipt_id.is_none()
        {
            return Err(OrsError::InvalidTransition);
        }
        drop(value);
        drop(current);
        drop(read);
        self.mutate_operational(
            OperationalKind::Retry,
            retry.0,
            false,
            &[],
            OperationalPhase::Staged,
        )?;
        Ok(())
    }

    fn checkpoint_job(&self, checkpoint: JobCheckpoint) -> Result<(), OrsError> {
        self.mutate_operational(
            OperationalKind::JobCheckpoint,
            checkpoint.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Suspended],
            OperationalPhase::Active,
        )?;
        Ok(())
    }

    fn record_delivery_cursor(
        &self,
        cursor: DeliveryCursorState,
    ) -> Result<DeliveryCursorReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::DeliveryCursor,
            cursor.0,
            false,
            &[OperationalPhase::Active],
            OperationalPhase::Active,
        )
        .map(DeliveryCursorReceipt::from_receipt)
    }

    fn acknowledge_delivery(
        &self,
        ack: DeliveryAcknowledgement,
    ) -> Result<DeliveryCursorReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::DeliveryCursor,
            ack.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Active,
        )
        .map(DeliveryCursorReceipt::from_receipt)
    }

    fn stage_admission_reservation(
        &self,
        reservation: AdmissionReservation,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            reservation.0,
            false,
            &[],
            OperationalPhase::Staged,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn activate_admission_reservation(
        &self,
        activation: AdmissionReservationActivation,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            activation.0,
            true,
            &[OperationalPhase::Staged],
            OperationalPhase::Active,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn release_admission_reservation(
        &self,
        release: AdmissionReservationRelease,
    ) -> Result<AdmissionReservationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AdmissionReservation,
            release.0,
            true,
            &[OperationalPhase::Staged, OperationalPhase::Active],
            OperationalPhase::Released,
        )
        .map(AdmissionReservationReceipt::from_receipt)
    }

    fn apply_generation_transition(
        &self,
        transition: GenerationTransition,
    ) -> Result<GenerationTransitionReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::GenerationTransition,
            transition.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Applying,
        )
        .map(GenerationTransitionReceipt::from_receipt)
    }

    fn commit_generation_cutover(
        &self,
        cutover: GenerationCutoverRecord,
    ) -> Result<GenerationCutoverReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::GenerationCutover,
            cutover.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(GenerationCutoverReceipt::from_receipt)
    }

    fn bind_session(
        &self,
        binding: ActiveSessionBinding,
    ) -> Result<SessionBindingReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::SessionBinding,
            binding.0,
            false,
            &[OperationalPhase::Suspended, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(SessionBindingReceipt::from_receipt)
    }

    fn detach_session(&self, detach: SessionDetach) -> Result<SessionBindingReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::SessionBinding,
            detach.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Suspended,
        )
        .map(SessionBindingReceipt::from_receipt)
    }

    fn register_user_broker(
        &self,
        registration: UserBrokerRegistration,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::UserBroker,
            registration.0,
            false,
            &[OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(UserBrokerRegistrationReceipt::from_receipt)
    }

    fn fence_user_broker(
        &self,
        fence: UserBrokerFence,
    ) -> Result<UserBrokerRegistrationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::UserBroker,
            fence.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(UserBrokerRegistrationReceipt::from_receipt)
    }

    fn commit_authority_snapshot(
        &self,
        snapshot: KernelAuthoritySnapshot,
    ) -> Result<AuthoritySnapshotReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AuthoritySnapshot,
            snapshot.0,
            false,
            &[OperationalPhase::Active, OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(AuthoritySnapshotReceipt::from_receipt)
    }

    fn load_authority_snapshot(
        &self,
        subject_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveredAuthoritySnapshot>, OrsError> {
        let key = Self::operational_key(OperationalKind::AuthoritySnapshot, subject_id);
        let read = self.database.begin_read().map_err(storage)?;
        let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
        let Some(value) = current.get(key.as_str()).map_err(storage)? else {
            return Ok(None);
        };
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        if record.kind != OperationalKind::AuthoritySnapshot
            || record.phase != OperationalPhase::Active
            || &record.input.subject_id != subject_id
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "authority_snapshot",
                reason: "current authority snapshot key, kind, phase, or subject mismatch"
                    .to_owned(),
            });
        }
        record.input.validate()?;
        let receipt = AuthoritySnapshotReceipt::from_receipt(Self::receipt_for(&record)?);
        let snapshot = KernelAuthoritySnapshot::new(record.input)?;
        Ok(Some(RecoveredAuthoritySnapshot::from_store(
            snapshot,
            record.operation_order,
            receipt,
        )))
    }

    fn revoke_authority(
        &self,
        revocation: AuthorityRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::AuthorityRevocation,
            revocation.0,
            false,
            &[OperationalPhase::Fenced],
            OperationalPhase::Fenced,
        )
        .map(AuthorityRevocationReceipt::from_receipt)
    }

    fn activate_capability_grant(
        &self,
        activation: CapabilityGrantActivation,
    ) -> Result<AuthorityActivationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityGrant,
            activation.0,
            false,
            &[OperationalPhase::Fenced, OperationalPhase::Released],
            OperationalPhase::Active,
        )
        .map(AuthorityActivationReceipt::from_receipt)
    }

    fn revoke_capability_grant(
        &self,
        revocation: CapabilityGrantRevocation,
    ) -> Result<AuthorityRevocationReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityGrant,
            revocation.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(AuthorityRevocationReceipt::from_receipt)
    }

    fn activate_capability_introduction(
        &self,
        activation: CapabilityIntroductionActivation,
    ) -> Result<CapabilityIntroductionReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityIntroduction,
            activation.0,
            false,
            &[OperationalPhase::Fenced],
            OperationalPhase::Active,
        )
        .map(CapabilityIntroductionReceipt::from_receipt)
    }

    fn fence_capability_introduction(
        &self,
        fence: CapabilityIntroductionFence,
    ) -> Result<CapabilityIntroductionReceipt, OrsError> {
        self.mutate_operational(
            OperationalKind::CapabilityIntroduction,
            fence.0,
            true,
            &[OperationalPhase::Active],
            OperationalPhase::Fenced,
        )
        .map(CapabilityIntroductionReceipt::from_receipt)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded read transaction binds reservations, envelopes, scope terminals, operational history, and inbox history"
    )]
    fn logical_snapshot(
        &self,
        request: OrsSnapshotRequest,
    ) -> Result<OrsSnapshotReceipt, OrsError> {
        if request.limit == 0 || request.limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let mut entries = BTreeMap::new();
        {
            let history = read.open_table(OPERATIONAL_HISTORY).map_err(storage)?;
            for row in history.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: DurableOperationalRecord =
                    decode_named(value.value(), "operational_history")?;
                if record.operation_order > request.after_order {
                    let encoded = encode(&record)?;
                    entries.insert(
                        (
                            record.operation_order,
                            format!("o:{}", record.input.record_id.as_str()),
                        ),
                        crate::model::sha256_hex(encoded.as_bytes()),
                    );
                    if entries.len() > usize::from(request.limit) {
                        break;
                    }
                }
            }
        }
        {
            let orders = read.open_table(RESERVATION_ORDERS).map_err(storage)?;
            let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
            let envelopes = read.open_table(ENVELOPES).map_err(storage)?;
            let heads = read.open_table(SCOPE_HEADS).map_err(storage)?;
            let terminals = read.open_table(SCOPE_TERMINALS).map_err(storage)?;
            let mut reservation_entries = 0_usize;
            for row in orders.iter().map_err(storage)? {
                let (order, reservation_id) = row.map_err(storage)?;
                let order =
                    order
                        .value()
                        .parse::<u64>()
                        .map_err(|error| OrsError::IntegrityProblem {
                            record_type: "reservation_order",
                            reason: error.to_string(),
                        })?;
                if order <= request.after_order {
                    continue;
                }
                let reservation_id = OpaqueLabel::new(reservation_id.value()).map_err(|error| {
                    OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: error.to_string(),
                    }
                })?;
                let value = reservations
                    .get(reservation_id.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: "snapshot found dangling reservation order".to_owned(),
                    })?;
                let record: ReservationRecord = decode_named(value.value(), "reservation")?;
                if record.token.reservation_order != order {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: "snapshot order index mismatch".to_owned(),
                    });
                }
                let mut encoded = encode(&record)?;
                if let Some(envelope) = envelopes
                    .get(record.token.operation_id.as_str())
                    .map_err(storage)?
                {
                    let envelope: RecoveryPayloadEnvelope =
                        decode_named(envelope.value(), "recovery_envelope")?;
                    encoded.push('\n');
                    encoded.push_str(&encode(&envelope)?);
                } else if !record.state.is_terminal() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "recovery_envelope",
                        reason: "pending snapshot reservation has no envelope".to_owned(),
                    });
                }
                for reserved in &record.token.scopes {
                    let head = heads
                        .get(reserved.scope.as_str())
                        .map_err(storage)?
                        .ok_or_else(|| OrsError::IntegrityProblem {
                            record_type: "scope_head",
                            reason: "snapshot reservation has no scope head".to_owned(),
                        })?;
                    let head: ScopeReservationHead = decode_named(head.value(), "scope_head")?;
                    encoded.push('\n');
                    encoded.push_str(&encode(&head)?);
                    let terminal_key = format!(
                        "{}:{:020}",
                        reserved.scope.as_str(),
                        reserved.reserved_sequence
                    );
                    if let Some(terminal) = terminals.get(terminal_key.as_str()).map_err(storage)? {
                        let terminal: ScopeTerminalReceipt =
                            decode_named(terminal.value(), "scope_terminal")?;
                        encoded.push('\n');
                        encoded.push_str(&encode(&terminal)?);
                    }
                }
                entries.insert(
                    (
                        record.token.reservation_order,
                        format!("r:{}", record.token.reservation_id.as_str()),
                    ),
                    crate::model::sha256_hex(encoded.as_bytes()),
                );
                reservation_entries += 1;
                if reservation_entries > usize::from(request.limit) {
                    break;
                }
            }
        }
        {
            let history = read.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?;
            let mut inbox_entries = 0_usize;
            for row in history.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: DurableInboxRecord =
                    decode_named(value.value(), "recovery_inbox_history")?;
                if record.operation_order > request.after_order {
                    let encoded = encode(&record)?;
                    entries.insert(
                        (
                            record.operation_order,
                            format!("i:{}", record.item.item_id.as_str()),
                        ),
                        crate::model::sha256_hex(encoded.as_bytes()),
                    );
                    inbox_entries += 1;
                    if inbox_entries > usize::from(request.limit) {
                        break;
                    }
                }
            }
        }
        let mut selected: Vec<_> = entries
            .into_iter()
            .take(usize::from(request.limit) + 1)
            .collect();
        let has_more = selected.len() > usize::from(request.limit);
        if has_more {
            selected.pop();
        }
        let next_after_order = has_more
            .then(|| selected.last().map(|entry| entry.0.0))
            .flatten();
        let entry_refs: Vec<_> = selected
            .into_iter()
            .map(|((order, identity), digest)| format!("{order}:{identity}:{digest}"))
            .collect();
        let snapshot_sha256 = crate::model::sha256_hex(entry_refs.join("\n").as_bytes());
        OrsSnapshotReceipt::issue(
            request.snapshot_at_ms,
            entry_refs,
            snapshot_sha256,
            next_after_order,
        )
    }

    fn scan_pending(
        &self,
        cursor: RecoveryCursor,
        limit: u32,
    ) -> Result<PendingOperationPage, OrsError> {
        if limit == 0 || limit > u32::from(crate::MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let bounded = u16::try_from(limit).map_err(|_| OrsError::InvalidCursorLimit)?;
        if cursor.limit != bounded {
            return Err(OrsError::InvalidCursorLimit);
        }
        self.recover_page(cursor)
    }

    fn import_recovery_inbox(
        &self,
        item: RecoveryInboxItem,
    ) -> Result<RecoveryInboxReceipt, OrsError> {
        item.validate()?;
        self.evidence.verify_recovery_inbox(&item)?;
        let write = self.database.begin_write().map_err(storage)?;
        {
            let inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
            if let Some(value) = inbox.get(item.item_id.as_str()).map_err(storage)? {
                let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
                if record.item == item {
                    let receipt = OperationalMutationReceipt::issue(
                        record.item.item_id.clone(),
                        record.item.envelope.operation_or_checkpoint_id.clone(),
                        record.operation_order,
                        OperationalPhase::Staged,
                        crate::model::sha256_hex(encode(&record)?.as_bytes()),
                    )?;
                    return Ok(RecoveryInboxReceipt::from_receipt(receipt));
                }
                return Err(OrsError::DuplicateConflict);
            }
        }
        let record = DurableInboxRecord {
            item,
            disposition: RecoveryInboxDisposition::Imported,
            operation_order: Self::next_operational_order(&write)?,
            terminal_receipt_id: None,
            terminal_receipt_sha256: None,
        };
        let encoded = encode(&record)?;
        let receipt = OperationalMutationReceipt::issue(
            record.item.item_id.clone(),
            record.item.envelope.operation_or_checkpoint_id.clone(),
            record.operation_order,
            OperationalPhase::Staged,
            crate::model::sha256_hex(encoded.as_bytes()),
        )?;
        let mut inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
        inbox
            .insert(record.item.item_id.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(inbox);
        let history_key = format!(
            "{:020}:{}",
            record.operation_order,
            record.item.item_id.as_str()
        );
        let mut history = write.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?;
        history
            .insert(history_key.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(history);
        write.commit().map_err(storage)?;
        Ok(RecoveryInboxReceipt::from_receipt(receipt))
    }

    fn record_recovery_inbox_disposition(
        &self,
        item_id: crate::OperationIdentity,
        disposition: RecoveryInboxDisposition,
        receipt: &ReceiptEnvelope,
    ) -> Result<RecoveryInboxReceipt, OrsError> {
        if disposition == RecoveryInboxDisposition::Imported {
            return Err(OrsError::InvalidTransition);
        }
        receipt
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        self.evidence.verify_receipt(receipt)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record = {
            let inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
            let value = inbox
                .get(item_id.as_str())
                .map_err(storage)?
                .ok_or(OrsError::ReservationNotFound)?;
            decode_named::<DurableInboxRecord>(value.value(), "recovery_inbox")?
        };
        if record.item.envelope.operation_or_checkpoint_id.as_str()
            != receipt.core.operation.operation_id.as_str()
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        let receipt_fence = crate::StateFenceSnapshot::capture(
            &receipt.core.operation.state_fence,
            receipt.core.authority.authority_epoch.value(),
        )?;
        if receipt_fence != record.item.envelope.state_fence
            || receipt.core.authority.authority_epoch.value()
                != record.item.envelope.authority_epoch.current.epoch
            || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
            || receipt.core.causal.state_fence != receipt.core.operation.state_fence
            || receipt.core.authority.state_fence != receipt.core.operation.state_fence
        {
            return Err(OrsError::ReconciliationMismatch);
        }
        let receipt_kind = receipt.core.disposition.kind();
        let disposition_matches = match disposition {
            RecoveryInboxDisposition::Applied => matches!(
                receipt_kind,
                ReceiptDispositionKind::Success | ReceiptDispositionKind::Partial
            ),
            RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter => matches!(
                receipt_kind,
                ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
            ),
            RecoveryInboxDisposition::Imported => false,
        };
        if !disposition_matches {
            return Err(OrsError::ReconciliationMismatch);
        }
        record.disposition = disposition;
        record.operation_order = Self::next_operational_order(&write)?;
        record.terminal_receipt_id = Some(OpaqueLabel::new(receipt.identity.receipt_id.as_str())?);
        record.terminal_receipt_sha256 = Some(receipt.identity.canonical_sha256.clone());
        let encoded = encode(&record)?;
        let operational_phase = match disposition {
            RecoveryInboxDisposition::Applied => OperationalPhase::Terminal,
            RecoveryInboxDisposition::Rejected | RecoveryInboxDisposition::DeadLetter => {
                OperationalPhase::Released
            }
            RecoveryInboxDisposition::Imported => unreachable!(),
        };
        let result = OperationalMutationReceipt::issue(
            record.item.item_id.clone(),
            record.item.envelope.operation_or_checkpoint_id.clone(),
            record.operation_order,
            operational_phase,
            crate::model::sha256_hex(encoded.as_bytes()),
        )?;
        let mut inbox = write.open_table(RECOVERY_INBOX).map_err(storage)?;
        inbox
            .insert(record.item.item_id.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(inbox);
        let history_key = format!(
            "{:020}:{}",
            record.operation_order,
            record.item.item_id.as_str()
        );
        let mut history = write.open_table(RECOVERY_INBOX_HISTORY).map_err(storage)?;
        history
            .insert(history_key.as_str(), encoded.as_str())
            .map_err(storage)?;
        drop(history);
        write.commit().map_err(storage)?;
        Ok(RecoveryInboxReceipt::from_receipt(result))
    }

    fn stage_and_reserve(
        &self,
        mut request: ReservationRequest,
    ) -> Result<WriterReservationToken, OrsError> {
        request.validate()?;
        request
            .scopes
            .sort_by(|left, right| left.scope.cmp(&right.scope));
        let write = self.database.begin_write().map_err(storage)?;
        if let Some(token) = Self::existing_token(&write, &request)? {
            return Ok(token);
        }
        self.evidence.verify_ordering_heads(&request.scopes)?;
        let reservation_order = Self::next_reservation_order(&write)?;
        let reserved_scopes = Self::reserve_scope_sequences(&write, &request)?;

        let token = WriterReservationToken {
            reservation_id: request.reservation_id.clone(),
            operation_id: request.envelope.operation_or_checkpoint_id.clone(),
            writer_epoch: request.writer_epoch,
            state_fence: request.envelope.state_fence.clone(),
            reservation_order,
            scopes: reserved_scopes,
            prepared_transition_sha256: request.prepared_transition_sha256,
            expires_at_ms: request.expires_at_ms,
            recovery_owner: request.recovery_owner,
        };
        let record = ReservationRecord {
            token: token.clone(),
            state: ReservationState::Reserved,
            unknown_reason: None,
            terminal_receipt_id: None,
        };
        Self::persist_new_reservation(&write, &request.envelope, &record)?;
        write.commit().map_err(storage)?;
        Ok(token)
    }

    fn mark_eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Eligible => return Ok(record),
                ReservationState::Reserved => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            Self::ensure_no_predecessor(&table, token)?;
            Self::ensure_canonical_heads(&write, token)?;
            record.state = ReservationState::Eligible;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn begin_execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Executing => return Ok(record),
                ReservationState::Eligible => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            Self::ensure_no_predecessor(&table, token)?;
            Self::ensure_canonical_heads(&write, token)?;
            record.state = ReservationState::Executing;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn mark_unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Reconciling
                    if record.unknown_reason.as_ref() == Some(&reason) =>
                {
                    return Ok(record);
                }
                ReservationState::Executing => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            record.state = ReservationState::Reconciling;
            record.unknown_reason = Some(reason);
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        {
            let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
            for scope in &token.scopes {
                let value = heads
                    .get(scope.scope.as_str())
                    .map_err(storage)?
                    .ok_or_else(|| OrsError::Storage("missing scope head".to_owned()))?;
                let mut head: ScopeReservationHead = decode(value.value())?;
                drop(value);
                head.recovery_blocked = true;
                let payload = encode(&head)?;
                heads
                    .insert(scope.scope.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError> {
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &reconciliation.reservation_id)?;
            if record.state.is_terminal() {
                if record.terminal_receipt_id.as_ref().map(OpaqueLabel::as_str)
                    == Some(reconciliation.receipt.identity.receipt_id.as_str())
                    && reconciliation_matches(&record.token, reconciliation).is_ok()
                {
                    self.evidence
                        .verify_reconciliation(&record.token, reconciliation)?;
                    return Ok(record);
                }
                return Err(OrsError::DuplicateConflict);
            }
            if !matches!(
                record.state,
                ReservationState::Executing | ReservationState::Reconciling
            ) {
                return Err(OrsError::InvalidTransition);
            }
            reconciliation_matches(&record.token, reconciliation)?;
            self.evidence
                .verify_reconciliation(&record.token, reconciliation)?;
            record.state = match reconciliation.disposition {
                CanonicalDisposition::Committed => ReservationState::Finalized,
                CanonicalDisposition::Rejected => ReservationState::Released,
            };
            record.unknown_reason = None;
            record.terminal_receipt_id = Some(OpaqueLabel::new(
                reconciliation.receipt.identity.receipt_id.as_str(),
            )?);
            let payload = encode(&record)?;
            table
                .insert(record.token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        Self::record_scope_terminals(&write, reconciliation)?;
        Self::clear_recovery_blocks(&write, &record)?;
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        require_writer_epoch(token, writer_epoch)?;
        let write = self.database.begin_write().map_err(storage)?;
        let mut record;
        {
            let mut table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            match record.state {
                ReservationState::Released if record.terminal_receipt_id.is_none() => {
                    return Ok(record);
                }
                ReservationState::Reserved | ReservationState::Eligible => {}
                _ => return Err(OrsError::InvalidTransition),
            }
            record.state = ReservationState::Released;
            let payload = encode(&record)?;
            table
                .insert(token.reservation_id.as_str(), payload.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn expire(
        &self,
        token: &WriterReservationToken,
        now_ms: i64,
        recovery_owner: &crate::RecoveryOwner,
    ) -> Result<ReservationRecord, OrsError> {
        if &token.recovery_owner != recovery_owner {
            return Err(OrsError::RecoveryOwnerMismatch);
        }
        if now_ms < token.expires_at_ms {
            return Err(OrsError::InvalidExpiry);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let record;
        {
            let table = write.open_table(RESERVATIONS).map_err(storage)?;
            record = Self::load_record(&table, &token.reservation_id)?;
            Self::validate_token(&record, token)?;
            if !record.state.is_terminal() {
                return Err(OrsError::UnsafeExpiry);
            }
        }
        {
            let mut envelopes = write.open_table(ENVELOPES).map_err(storage)?;
            envelopes
                .remove(token.operation_id.as_str())
                .map_err(storage)?;
        }
        write.commit().map_err(storage)?;
        Ok(record)
    }

    fn recover_page(&self, cursor: RecoveryCursor) -> Result<RecoveryPage, OrsError> {
        if cursor.limit == 0 || cursor.limit > crate::MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        let read = self.database.begin_read().map_err(storage)?;
        let orders = read.open_table(RESERVATION_ORDERS).map_err(storage)?;
        let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
        let mut records = Vec::with_capacity(usize::from(cursor.limit) + 1);
        for row in orders.iter().map_err(storage)? {
            let (order, reservation_id) = row.map_err(storage)?;
            let parsed_order =
                order
                    .value()
                    .parse::<u64>()
                    .map_err(|error| OrsError::IntegrityProblem {
                        record_type: "reservation_order",
                        reason: error.to_string(),
                    })?;
            if parsed_order <= cursor.after_order {
                continue;
            }
            let reservation_id = OpaqueLabel::new(reservation_id.value()).map_err(|error| {
                OrsError::IntegrityProblem {
                    record_type: "reservation_order",
                    reason: error.to_string(),
                }
            })?;
            let value = reservations
                .get(reservation_id.as_str())
                .map_err(storage)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "reservation_order",
                    reason: "dangling reservation order index".to_owned(),
                })?;
            let record: ReservationRecord = decode(value.value())?;
            if record.token.reservation_order != parsed_order {
                return Err(OrsError::IntegrityProblem {
                    record_type: "reservation_order",
                    reason: "order index disagrees with reservation".to_owned(),
                });
            }
            if !record.state.is_terminal() {
                records.push(record);
                if records.len() > usize::from(cursor.limit) {
                    break;
                }
            }
        }
        let has_more = records.len() > usize::from(cursor.limit);
        if has_more {
            records.pop();
        }
        let next_after_order = has_more
            .then(|| records.last().map(|record| record.token.reservation_order))
            .flatten();
        Ok(RecoveryPage {
            records,
            next_after_order,
        })
    }

    fn get_envelope(
        &self,
        operation_id: &crate::OperationIdentity,
    ) -> Result<Option<RecoveryPayloadEnvelope>, OrsError> {
        let read = self.database.begin_read().map_err(storage)?;
        let table = read.open_table(ENVELOPES).map_err(storage)?;
        table
            .get(operation_id.as_str())
            .map_err(storage)?
            .map(|value| decode(value.value()))
            .transpose()
    }

    fn fence_writer_epoch(
        &self,
        scopes: &[crate::OrderingScope],
        successor: &EpochLineage,
    ) -> Result<(), OrsError> {
        successor.validate()?;
        if scopes.is_empty() {
            return Err(OrsError::EmptyScopeSet);
        }
        let unique: BTreeSet<_> = scopes.iter().cloned().collect();
        if unique.len() != scopes.len() {
            return Err(OrsError::DuplicateScope);
        }
        if unique.len() > usize::from(crate::MAX_RECOVERY_PAGE) {
            return Err(OrsError::InvalidCursorLimit);
        }
        let write = self.database.begin_write().map_err(storage)?;
        let mut affected_scopes = BTreeSet::new();
        {
            let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for row in reservations.iter().map_err(storage)? {
                let (_, value) = row.map_err(storage)?;
                let record: ReservationRecord = decode(value.value())?;
                if !record.state.is_terminal()
                    && record.token.writer_epoch.current != successor.current
                {
                    for reserved in &record.token.scopes {
                        if unique.contains(&reserved.scope) {
                            affected_scopes.insert(reserved.scope.clone());
                        }
                    }
                }
            }
        }
        {
            let mut heads = write.open_table(SCOPE_HEADS).map_err(storage)?;
            for scope in &unique {
                let value = heads.get(scope.as_str()).map_err(storage)?.ok_or_else(|| {
                    OrsError::IntegrityProblem {
                        record_type: "scope_head",
                        reason: "scope has no writer epoch".to_owned(),
                    }
                })?;
                let mut head: ScopeReservationHead = decode(value.value())?;
                drop(value);
                if !successor.succeeds(&head.writer_epoch) {
                    return Err(OrsError::InvalidEpochLineage);
                }
                head.writer_epoch = successor.current.clone();
                head.recovery_blocked = affected_scopes.contains(scope);
                let payload = encode(&head)?;
                heads
                    .insert(scope.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        let fenced_reason = OpaqueLabel::new("writer epoch fenced")?;
        loop {
            let mut affected = Vec::with_capacity(usize::from(crate::MAX_RECOVERY_PAGE));
            {
                let reservations = write.open_table(RESERVATIONS).map_err(storage)?;
                for row in reservations.iter().map_err(storage)? {
                    let (key, value) = row.map_err(storage)?;
                    let record: ReservationRecord = decode(value.value())?;
                    if !record.state.is_terminal()
                        && record.token.writer_epoch.current != successor.current
                        && record
                            .token
                            .scopes
                            .iter()
                            .any(|reserved| unique.contains(&reserved.scope))
                        && !(record.state == ReservationState::Reconciling
                            && record.unknown_reason.as_ref() == Some(&fenced_reason))
                    {
                        affected.push((key.value().to_owned(), record));
                        if affected.len() == usize::from(crate::MAX_RECOVERY_PAGE) {
                            break;
                        }
                    }
                }
            }
            if affected.is_empty() {
                break;
            }
            let mut reservations = write.open_table(RESERVATIONS).map_err(storage)?;
            for (key, mut record) in affected {
                record.state = ReservationState::Reconciling;
                record.unknown_reason = Some(fenced_reason.clone());
                let payload = encode(&record)?;
                reservations
                    .insert(key.as_str(), payload.as_str())
                    .map_err(storage)?;
            }
        }
        write.commit().map_err(storage)
    }
}

/// Single coordinator facade. It owns no semantic policy and delegates one durable transition.
pub struct OrsCoordinator<S = RedbRecoveryStore> {
    store: S,
}

impl OrsCoordinator<RedbRecoveryStore> {
    /// Opens the concrete redb-backed coordinator.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OrsError> {
        Ok(Self {
            store: RedbRecoveryStore::open(path)?,
        })
    }
}

impl<S: OperationalRecoveryStore> OrsCoordinator<S> {
    /// Injects one transactional store implementation.
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    /// Returns the injected store for bounded provider-specific observation.
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Stages typed generation evidence through the canonical ORS boundary.
    pub fn stage_generation_cutover(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        self.store.stage_generation_cutover(record)
    }

    /// Commits typed generation evidence at the canonical ORS linearization
    /// point.
    pub fn commit_generation_cutover_state(
        &self,
        record: RuntimeGenerationCutoverRecord,
    ) -> Result<GenerationCutoverSnapshot, OrsError> {
        self.store.commit_generation_cutover_state(record)
    }

    /// Reads the bounded canonical generation route projection.
    pub fn latest_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        self.store.latest_generation_cutovers(limit)
    }

    /// Reconciles interrupted candidates without activating them.
    pub fn reconcile_staged_generation_cutovers(
        &self,
        limit: u16,
    ) -> Result<Vec<GenerationCutoverSnapshot>, OrsError> {
        self.store.reconcile_staged_generation_cutovers(limit)
    }

    /// Atomically stages one envelope and reserves every declared scope.
    pub fn reserve(&self, request: ReservationRequest) -> Result<WriterReservationToken, OrsError> {
        self.store.stage_and_reserve(request)
    }

    /// Advances a head reservation to eligibility after all predecessors close.
    pub fn eligible(&self, token: &WriterReservationToken) -> Result<ReservationRecord, OrsError> {
        self.store.mark_eligible(token)
    }

    /// Starts execution under the exact immutable writer epoch.
    pub fn execute(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.begin_execute(token, writer_epoch)
    }

    /// Makes an ambiguous effect non-replayable until canonical reconciliation.
    pub fn unknown(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
        reason: OpaqueLabel,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.mark_unknown(token, writer_epoch, reason)
    }

    /// Closes an executing/unknown reservation only from exact receipt/read-back evidence.
    pub fn reconcile(
        &self,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.reconcile(reconciliation)
    }

    /// Releases work that has not executed under the exact writer epoch.
    pub fn release(
        &self,
        token: &WriterReservationToken,
        writer_epoch: &EpochIdentity,
    ) -> Result<ReservationRecord, OrsError> {
        self.store.release(token, writer_epoch)
    }
}

fn push_bounded(values: &mut Vec<String>, value: String, limit: usize) -> Result<(), OrsError> {
    if values.len() == limit {
        return Err(OrsError::ProjectionLimitExceeded);
    }
    values.push(value);
    Ok(())
}

fn request_matches(
    request: &ReservationRequest,
    token: &WriterReservationToken,
    envelope: &RecoveryPayloadEnvelope,
) -> bool {
    request.reservation_id == token.reservation_id
        && request.envelope == *envelope
        && request.writer_epoch == token.writer_epoch
        && request.prepared_transition_sha256 == token.prepared_transition_sha256
        && request.expires_at_ms == token.expires_at_ms
        && request.recovery_owner == token.recovery_owner
        && request.scopes.len() == token.scopes.len()
        && request
            .scopes
            .iter()
            .zip(&token.scopes)
            .all(|(left, right)| {
                left.scope == right.scope && left.expected_head == right.expected_head
            })
}

fn require_writer_epoch(
    token: &WriterReservationToken,
    supplied: &EpochIdentity,
) -> Result<(), OrsError> {
    if token.writer_epoch.current != *supplied {
        return Err(OrsError::StaleWriterEpoch);
    }
    Ok(())
}

fn shares_scope(left: &WriterReservationToken, right: &WriterReservationToken) -> bool {
    left.scopes.iter().any(|left_scope| {
        right
            .scopes
            .iter()
            .any(|right_scope| left_scope.scope == right_scope.scope)
    })
}

fn reconciliation_matches(
    token: &WriterReservationToken,
    reconciliation: &CanonicalReconciliation,
) -> Result<(), OrsError> {
    reconciliation
        .receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    let receipt = &reconciliation.receipt;
    if reconciliation.reservation_id != token.reservation_id
        || reconciliation.operation_id != token.operation_id
        || reconciliation.operation_id.as_str() != receipt.core.operation.operation_id.as_str()
        || reconciliation.reservation_order != token.reservation_order
        || reconciliation.state_fence != token.state_fence
        || reconciliation.recovery_owner != token.recovery_owner
        || reconciliation.scopes.len() != token.scopes.len()
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    let receipt_fence = crate::StateFenceSnapshot::capture(
        &receipt.core.operation.state_fence,
        receipt.core.authority.authority_epoch.value(),
    )?;
    if receipt_fence != token.state_fence
        || receipt.core.work_scope.state_fence != receipt.core.operation.state_fence
        || receipt.core.causal.state_fence != receipt.core.operation.state_fence
        || receipt.core.authority.state_fence != receipt.core.operation.state_fence
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    let receipt_kind = receipt.core.disposition.kind();
    let disposition_matches = match reconciliation.disposition {
        CanonicalDisposition::Committed => matches!(
            receipt_kind,
            ReceiptDispositionKind::Success | ReceiptDispositionKind::Partial
        ),
        CanonicalDisposition::Rejected => matches!(
            receipt_kind,
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
        ),
    };
    if receipt_kind == ReceiptDispositionKind::Unknown {
        return Err(OrsError::UnknownReceiptCannotResolve);
    }
    if !disposition_matches {
        return Err(OrsError::ReconciliationMismatch);
    }
    for (reserved, observed) in token.scopes.iter().zip(&reconciliation.scopes) {
        observed.prior_head.validate()?;
        crate::model::validate_digest(&observed.committed_head_sha256, "committed_head_sha256")?;
        if let Some(revision) = &observed.committed_revision_head {
            crate::model::validate_text(revision, "committed_revision_head")?;
        }
        if observed.scope != reserved.scope
            || observed.prior_head != reserved.expected_head
            || observed.committed_sequence != reserved.reserved_sequence
            || observed.committed_head_sha256 != receipt.identity.canonical_sha256
            || observed.receipt_id.as_str() != receipt.identity.receipt_id.as_str()
        {
            return Err(OrsError::ReconciliationMismatch);
        }
    }
    if token.scopes.len() == 1
        && receipt.core.causal.transaction_sequence.value() != token.scopes[0].reserved_sequence
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<String, OrsError> {
    serde_json::to_string(value).map_err(|error| OrsError::Encoding(error.to_string()))
}

trait PersistedValue: DeserializeOwned {
    const RECORD_TYPE: &'static str;

    fn validate_persisted(&self) -> Result<(), OrsError>;
}

impl PersistedValue for RecoveryPayloadEnvelope {
    const RECORD_TYPE: &'static str = "recovery_envelope";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessStartReplayRecord {
    const RECORD_TYPE: &'static str = "process_start_replay";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for AuthorityHandoffRecord {
    const RECORD_TYPE: &'static str = "authority_handoff";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessEvidenceRecord {
    const RECORD_TYPE: &'static str = "process_evidence";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ScopeReservationHead {
    const RECORD_TYPE: &'static str = "scope_head";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.writer_epoch.validate()?;
        self.canonical_head.validate()?;
        if self.last_reserved_sequence < self.canonical_head.sequence
            || self.last_terminal_sequence > self.last_reserved_sequence
        {
            return Err(OrsError::OrderingHeadMismatch);
        }
        Ok(())
    }
}

impl PersistedValue for ReservationRecord {
    const RECORD_TYPE: &'static str = "reservation";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.token.writer_epoch.validate()?;
        self.token.state_fence.validate()?;
        if self.token.reservation_order == 0
            || self.token.scopes.is_empty()
            || self.token.writer_epoch.current.epoch
                != self.token.state_fence.observed_authority_epoch
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid token order, scope set, or epoch fence".to_owned(),
            });
        }
        crate::model::validate_digest(
            &self.token.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        let mut scopes = BTreeSet::new();
        for scope in &self.token.scopes {
            scope.expected_head.validate()?;
            if scope.reserved_sequence <= scope.expected_head.sequence
                || !scopes.insert(scope.scope.clone())
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "invalid or duplicate reserved scope".to_owned(),
                });
            }
        }
        if self.state == ReservationState::Reconciling && self.unknown_reason.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "reconciling record has no recovery reason".to_owned(),
            });
        }
        if self.state != ReservationState::Reconciling && self.unknown_reason.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "terminal and unknown markers conflict".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for DurableOperationalRecord {
    const RECORD_TYPE: &'static str = "operational_record";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.input.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid order or partial terminal receipt binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "terminal_receipt_sha256")?;
        }
        if let Some(record) = &self.generation_cutover {
            record
                .validate()
                .map_err(|error| OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: error.to_string(),
                })?;
            let expected_record_id =
                OpaqueLabel::new(format!("generation-cutover:{}", record.cutover_id))?;
            let expected_subject = OpaqueLabel::new(record.route_scope.clone())?;
            if !matches!(
                self.kind,
                OperationalKind::GenerationTransition | OperationalKind::GenerationCutover
            ) || self.input.record_id != expected_record_id
                || self.input.subject_id != expected_subject
                || self.input.authority_epoch.current.epoch != record.old_epoch.value()
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input identity does not match typed cutover".to_owned(),
                });
            }
            if !matches!(
                &self.input.payload,
                RecoveryPayload::ImmutableLocator { locator }
                    if locator.as_str() == format!("ors:generation-cutover:{}", record.cutover_id)
            ) {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input locator does not match typed cutover".to_owned(),
                });
            }
            let valid_phase = matches!(
                (self.kind, self.phase, record.state),
                (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Applying,
                    GenerationCutoverState::Armed,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Reconciling,
                    GenerationCutoverState::Reconciling,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Fenced,
                    GenerationCutoverState::FailedRequiresForwardCutover,
                ) | (
                    OperationalKind::GenerationCutover,
                    OperationalPhase::Active,
                    GenerationCutoverState::Committed,
                )
            );
            if !valid_phase {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation state and operational phase disagree".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl PersistedValue for DurableInboxRecord {
    const RECORD_TYPE: &'static str = "recovery_inbox";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.item.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
            || (self.disposition == RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_some())
            || (self.disposition != RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_none())
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid inbox phase or terminal binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "inbox_terminal_receipt_sha256")?;
        }
        Ok(())
    }
}

impl PersistedValue for ScopeTerminalReceipt {
    const RECORD_TYPE: &'static str = "scope_terminal";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        crate::model::validate_digest(&self.receipt_sha256, "scope_terminal_receipt_sha256")?;
        if self.reserved_sequence == 0
            || self.gap != (self.disposition == CanonicalDisposition::Rejected)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid terminal sequence or gap disposition".to_owned(),
            });
        }
        Ok(())
    }
}

fn decode<T: PersistedValue>(value: &str) -> Result<T, OrsError> {
    decode_named(value, T::RECORD_TYPE)
}

fn decode_named<T: PersistedValue>(value: &str, record_type: &'static str) -> Result<T, OrsError> {
    let decoded: T = serde_json::from_str(value).map_err(|error| OrsError::IntegrityProblem {
        record_type,
        reason: error.to_string(),
    })?;
    decoded
        .validate_persisted()
        .map_err(|error| OrsError::IntegrityProblem {
            record_type,
            reason: error.to_string(),
        })?;
    Ok(decoded)
}

fn storage(error: impl std::fmt::Display) -> OrsError {
    OrsError::Storage(error.to_string())
}

#[cfg(test)]
mod process_start_abort_tests {
    use super::*;
    use crate::OperationIdentity;

    #[test]
    fn reserved_abort_is_compare_delete_and_survives_reopen() -> Result<(), OrsError> {
        let path = std::env::temp_dir().join(format!(
            "eliot-process-start-abort-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let owner = eliot_process::ProcessOwnerBinding::new(
            "testd",
            "a".repeat(64),
            1,
            eliot_process::Generation::new(1).map_err(|error| OrsError::IntegrityProblem {
                record_type: "test",
                reason: error.to_string(),
            })?,
        )
        .map_err(|error| OrsError::IntegrityProblem {
            record_type: "test",
            reason: error.to_string(),
        })?;
        let operation = OperationIdentity::new("abort-operation")?;
        let record = ProcessStartReplayRecord {
            operation_id: operation.clone(),
            admission_digest: "ab".repeat(32),
            owner: owner.clone(),
            state: ProcessStartReplayState::Reserved,
            receipt: None,
        };
        let store = RedbRecoveryStore::open(&path)?;
        assert!(store.begin_process_start(&record)?.is_none());
        assert_eq!(
            store.abort_process_start(&operation, &record.admission_digest, &owner)?,
            ProcessStartReplayAbort::Released
        );
        assert!(store.load_process_start(&operation)?.is_none());
        drop(store);
        let reopened = RedbRecoveryStore::open(&path)?;
        assert!(reopened.load_process_start(&operation)?.is_none());

        let unknown_operation = OperationIdentity::new("abort-unknown")?;
        let unknown = ProcessStartReplayRecord {
            operation_id: unknown_operation.clone(),
            state: ProcessStartReplayState::Unknown,
            ..record
        };
        assert!(reopened.begin_process_start(&unknown)?.is_none());
        reopened.persist_process_start(&unknown)?;
        assert_eq!(
            reopened.abort_process_start(&unknown_operation, &unknown.admission_digest, &owner)?,
            ProcessStartReplayAbort::NotReleased
        );
        assert_eq!(
            reopened
                .load_process_start(&unknown_operation)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "test",
                    reason: "unknown replay record disappeared".to_owned(),
                })?
                .state,
            ProcessStartReplayState::Unknown
        );
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
