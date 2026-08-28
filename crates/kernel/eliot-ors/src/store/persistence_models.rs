//! Passive ORS persistence models: DTO representation and key-prefix classification only.
//! Architecture A13.6: ORS is non-semantic recovery state with no authority; receipt
//! reconciliation precedes replay.
//! Implementation I5.2: Operational Recovery State redb contains Kernel-owned,
//! non-semantic operational metadata and opaque payload only.
//! Implementation I2.1: module/crate packaging transfers no lifecycle, mutable-state,
//! or authority ownership.
//! This child owns passive persistence DTOs and key-prefix classification; the parent
//! `RedbRecoveryStore`/ORS coordinator owns transactions, durability, reconciliation,
//! lifecycle, and Kernel authority.

use eliot_runtime_contracts::{
    GenerationCutoverRecord as RuntimeGenerationCutoverRecord, SignedSupervisionLease,
};
use serde::{Deserialize, Serialize};

use crate::{
    EpochIdentity, OpaqueLabel, OperationalPhase, OperationalRecordInput, RecoveryInboxDisposition,
    RecoveryInboxItem, SupervisionLeaseCommitTicket, SupervisionLeaseSnapshot,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct ScopeReservationHead {
    pub(super) writer_epoch: EpochIdentity,
    pub(super) canonical_head: crate::ExpectedOrderingHead,
    pub(super) last_reserved_sequence: u64,
    pub(super) last_terminal_sequence: u64,
    pub(super) recovery_blocked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum OperationalKind {
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
    pub(super) const fn key_prefix(self) -> &'static str {
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
pub(super) struct DurableOperationalRecord {
    pub(super) kind: OperationalKind,
    pub(super) input: OperationalRecordInput,
    pub(super) phase: OperationalPhase,
    pub(super) operation_order: u64,
    pub(super) terminal_receipt_id: Option<OpaqueLabel>,
    pub(super) terminal_receipt_sha256: Option<String>,
    /// Typed generation evidence is carried by the same canonical
    /// operational current/history records as every other ORS subject.
    /// `default` keeps older canonical records readable without granting the
    /// retired generation tables any authority.
    #[serde(default)]
    pub(super) generation_cutover: Option<RuntimeGenerationCutoverRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableInboxRecord {
    pub(super) item: RecoveryInboxItem,
    pub(super) disposition: RecoveryInboxDisposition,
    pub(super) operation_order: u64,
    pub(super) terminal_receipt_id: Option<OpaqueLabel>,
    pub(super) terminal_receipt_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableSupervisionLeaseResult {
    pub(super) ticket: SupervisionLeaseCommitTicket,
    pub(super) artifact: SignedSupervisionLease,
    pub(super) snapshot: SupervisionLeaseSnapshot,
}
