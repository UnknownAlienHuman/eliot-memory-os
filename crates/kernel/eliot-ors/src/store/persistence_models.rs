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

use eliot_receipts::ReceiptIdentity;
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

/// Durable grant-closure row: one committed closure operation identity with
/// its exact commit bytes, non-semantic phase, and monotonic order.
///
/// The row never transitions. An exact recommit replays its receipt; any
/// changed content under one operation identity is a durable conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableGrantClosureRecord {
    pub(super) commit: crate::GrantClosureCommit,
    pub(super) phase: OperationalPhase,
    pub(super) operation_order: u64,
}

/// Stable schema identity for the durable canonical second phase of a grant
/// closure. The first-phase row remains immutable; this record is keyed by
/// the same closure operation identity in a separate table.
pub(super) const GRANT_CLOSURE_SECOND_PHASE_SCHEMA: &str = "eliot.ors.grant-closure-second-phase";
/// Current durable second-phase record revision.
pub(super) const GRANT_CLOSURE_SECOND_PHASE_VERSION: u16 = 1;

/// Versioned second-phase link retained beside one committed first-phase
/// closure row. The key is checked by the store against `operation_id`; the
/// receipt identity is copied exactly and is never synthesized by ORS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableGrantClosureSecondPhaseRecord {
    pub(super) schema: String,
    pub(super) version: u16,
    pub(super) operation_id: String,
    pub(super) operation_order: u64,
    pub(super) canonical_receipt: ReceiptIdentity,
}

impl DurableGrantClosureSecondPhaseRecord {
    pub(super) fn validate(&self) -> Result<(), crate::OrsError> {
        if self.schema != GRANT_CLOSURE_SECOND_PHASE_SCHEMA {
            return Err(crate::OrsError::InvalidField {
                field: "grant_closure_second_phase_schema",
                reason: "unsupported grant-closure second-phase schema",
            });
        }
        if self.version != GRANT_CLOSURE_SECOND_PHASE_VERSION {
            return Err(crate::OrsError::InvalidField {
                field: "grant_closure_second_phase_version",
                reason: "unsupported grant-closure second-phase version",
            });
        }
        crate::model::validate_text(
            &self.operation_id,
            "grant_closure_second_phase_operation_id",
        )?;
        if self.operation_order == 0 {
            return Err(crate::OrsError::InvalidField {
                field: "grant_closure_second_phase_operation_order",
                reason: "must be greater than zero",
            });
        }
        crate::model::validate_grant_closure_canonical_receipt(&self.canonical_receipt)
    }
}

/// Durable grant-graph revision watermark: the greatest graph revision
/// observed for one lineage root, with the monotonic order of its last
/// advance.
///
/// The watermark only moves forward. It lets the P-07 port enforce revision
/// monotonicity across restarts instead of trusting a re-presented revision
/// as the first observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableGrantGraphRevision {
    pub(super) root: crate::OpaqueLabel,
    pub(super) revision: u64,
    pub(super) operation_order: u64,
}
