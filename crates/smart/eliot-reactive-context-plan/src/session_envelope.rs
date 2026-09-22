//! Cue-owner item facts and the record-operation envelope gap
//! (issue #1942, lane O1).
//!
//! Owner: at admission time the plan producer owns item selection and the cue
//! source/digest binding (`plan_bridge_admissions` in `bridge_admission.rs`;
//! contract C1 in `control-20260921/1941-1942-runtime-owner-contracts.md`).
//! [`produce_item_cue_facts`] projects the cue owner's own live admission
//! records ([`BridgeAdmissionBatch`]) into per-item cue facts in plan order
//! (deterministic, CPU-side, no caller values beyond the owner record
//! borrow). The bridge ledger mirrors these facts per delivered row through
//! its `item_cue` probe; the delivery-record assembly joins the two sides on
//! the plan-scoped cue identity (`cue_id`, which doubles as the ledger cue
//! identity).
//!
//! Absence: no operation owner exists on the bridge admission path itself
//! (`BridgeAdmissionInstruction` carries cue, firing, scope, governance,
//! fence, and dedup facts — no operation, request, or idempotency identity),
//! so [`produce_record_operation_envelope`] fails closed naming the three
//! facts. The live operation envelope does exist one owner over: the Context
//! owner's payload triple (`operation_id`, `request_id`, `idempotency_key`),
//! durably retained per entry by the Host journal queue and read live by the
//! `eliot-host-service` `session_envelope` producer
//! (`produce_admitted_deliveries`) — that producer, not this one, owns the
//! retained operation-envelope read. Examined and distinct:
//!
//! - the bridge ledger rows (`NormalizedCue`, `FiringEvidence`,
//!   `AdmissionBasis`, `DeliveryPoint` in
//!   `bins/eliot-agent-bridge/src/reactive_injection_receipts.rs`, D2 lane,
//!   read-only reference) carry cue/source/digest/fence evidence plus
//!   hook/response delivery observations — observations, never operations;
//! - the admission instructions (`BridgeAdmissionInstruction`) carry cue,
//!   firing, scope, governance, fence, and dedup facts — no operation,
//!   request, or idempotency identity;
//! - the activation receipt's operation identity
//!   (`KernelActivationReceipt::operation_id`, a `PlatformHandle` in
//!   `crates/kernel/eliot-kernel-service/src/protocol.rs`) is scoped to the
//!   Host-owned activation operation, not to delivered content;
//! - operation/request/idempotency identities on the canonical write path
//!   (I5.5 `CanonicalWriteEnvelope`) are minted by the Governor/Kernel/store
//!   transition, never by reactive rows; the surfaces contract forbids a
//!   host or bridge from minting idempotency identity, so a producer must
//!   not synthesize these values.
//!
//! [`produce_record_operation_envelope`] therefore fails closed naming the
//! three facts. [`RecordOperationFacts`] documents the target shape the
//! operating owner must one day supply (field names and types mirror the D2
//! `RecordEnvelope` consumer); it has no in-tree constructor.
//!
//! Consumer: `resolve_record_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the three missing per-record operation facts.

use eliot_contracts::{OperationId, RequestId};

use crate::bridge_admission::{BridgeAdmissionBatch, BridgeAdmissionInstruction};

/// Per-item cue facts projected from the cue owner's live admission record.
///
/// Every field traces to one [`BridgeAdmissionInstruction`] field produced by
/// `plan_bridge_admissions`: `cue_id` (plan-scoped item identity, doubles as
/// the ledger cue identity), `source` / `source_revision` (owner source
/// identity and revision at observation time), `cue_digest` (SHA-256 over the
/// exact observed bytes), `rule_id` (exact firing-evaluation reference).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ItemCueFacts {
    /// Plan-scoped opaque item identity; the ledger cue identity.
    pub cue_id: String,
    /// Owner source identity (content contract name).
    pub source: String,
    /// Owner revision of the source at observation time.
    pub source_revision: String,
    /// Lowercase SHA-256 over the exact observed bytes.
    pub cue_digest: String,
    /// Exact firing-evaluation reference (`reactive-activation:<digest>`).
    pub rule_id: String,
}

/// Target shape of the per-record operation envelope, for the operating owner
/// to supply. Field names and types mirror the D2 `RecordEnvelope` consumer
/// (`bins/eliot-agent-bridge/src/reactive_owner_publication.rs`); no
/// constructor exists in-tree because no operation owner exists for reactive
/// delivery rows (see the module docs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordOperationFacts {
    /// Canonical operation identity from the operating owner.
    pub operation_id: OperationId,
    /// Request identity from the operating owner.
    pub request_id: RequestId,
    /// Caller idempotency key from the operating owner.
    pub idempotency_key: String,
}

/// Fail-closed record-operation errors. Each names the exact D2 facts that
/// cannot be resolved from live owner state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordOperationError {
    /// No operation owner exists for reactive delivery rows: bridge
    /// hook/response deliveries are observations, the admission path carries
    /// no operation/request/idempotency identity, and the canonical write
    /// path mints those identities for semantic transitions only. Carries
    /// the three exact missing fact names in deterministic order.
    OperationNotOwned {
        /// Exact missing per-record operation facts.
        facts: [String; 3],
    },
}

impl core::fmt::Display for RecordOperationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperationNotOwned { facts } => {
                write!(
                    formatter,
                    "no operation owner for reactive delivery rows: {}",
                    facts.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for RecordOperationError {}

/// Project the cue owner's live admission records into per-item cue facts.
///
/// Reads `batch.items` in plan order (deterministic). An empty batch yields
/// an empty projection — the absence of admitted items, never an error. The
/// delivery-record assembly joins these facts to delivered ledger rows on
/// `cue_id`.
pub fn produce_item_cue_facts(batch: &BridgeAdmissionBatch) -> Vec<ItemCueFacts> {
    batch
        .items
        .iter()
        .map(|item: &BridgeAdmissionInstruction| ItemCueFacts {
            cue_id: item.cue_id.clone(),
            source: item.cue_source.clone(),
            source_revision: item.cue_source_revision.clone(),
            cue_digest: item.cue_digest.clone(),
            rule_id: item.rule_id.clone(),
        })
        .collect()
}

/// Attempt to produce the per-record operation envelope.
///
/// Always fails closed (see [`RecordOperationError::OperationNotOwned`]): no
/// owner holds operation/request/idempotency identity for reactive delivery
/// rows, and minting any of them here would violate the surfaces contract (a
/// host or bridge never mints idempotency identity) and the I5.5 write
/// envelope ownership. The zero-argument shape is deliberate — there is no
/// owner state to read, so no borrow is threaded and no caller value is
/// accepted.
pub fn produce_record_operation_envelope() -> Result<RecordOperationFacts, RecordOperationError> {
    Err(RecordOperationError::OperationNotOwned {
        facts: [
            "record.operation_id".to_owned(),
            "record.request_id".to_owned(),
            "record.idempotency_key".to_owned(),
        ],
    })
}
