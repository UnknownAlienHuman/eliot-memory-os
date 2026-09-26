//! Read-only supervision status projection — mechanical extraction from
//! `crates/kernel/eliot-ors/src/status.rs:25-68` (parent `73e8294b0a6a7d4f750457343693063b91fa50f0`).
//! Architecture: P-06 ORS / A13.6 + ARCH-MOD-02 — durable, non-semantic ORS
//! report boundary (cf. `lib.rs:1-6` "P-06 durable, non-semantic Operational
//! Recovery State", `persistence_codec.rs:1-3` "A13.6 / ARCH-MOD-02").
//! Implementation: I18.7 / I5/I18 — pure projection/codec isolation, existing ORS handles.
//! This module is a **report/projection, not canonical authority**: it only
//! surfaces `HealthDimension` + `SupervisionLeaseSnapshot`/`StageReceipt`
//! evidence observed via `redb::ReadOnlyDatabase`; it never mutates durable
//! state, verifies supervision authority beyond read-only `SupervisionTrustAnchor`
//! checks performed by `status.rs:589-723`, nor advances any canonical ordering
//! head. Canonical supervision authority remains with the ORS writer/Verifier.
//! Source parity: `OrsSupervisionStatusError`, `SupervisionStatusReason`,
//! `SupervisionStatusProjection` moved verbatim (derives, variants, fields,
//! `Display`/`Error` impls unchanged) — `serde` shape unchanged (none derived
//! here; JSON codec in `status.rs:118-124` preserved), public API re-exported
//! via `lib.rs`.
//!
//! Issue #269 adds `ProcessStreamRecoveryStatusProjection` next to the
//! supervision projection: the ORS status/recovery view of process-stream
//! evidence recovery. It reports availability, authenticated handles, the exact
//! durable coverage and the exact gap set. It holds no stream bytes and no
//! parser/evaluator/task/finish field, so it can neither expose raw stdout or
//! stderr nor claim semantic proof.

use eliot_process::{
    ProcessStreamKind, StreamEvidenceGap, StreamPersistenceStatus, StreamTransportStatus,
};
use eliot_runtime_contracts::HealthDimension;

use crate::{
    ProcessStreamRecoveryProjection, StreamRecoveryActivation, StreamRecoveryAvailability,
    StreamRecoveryCoverage, StreamRecoveryEvidenceScope, StreamRecoveryReconciliationState,
    SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrsSupervisionStatusError {
    Missing(String),
    AccessDenied(String),
    MigrationRequired(String),
    Corrupt(String),
    Unknown(String),
}

impl std::fmt::Display for OrsSupervisionStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(r) => write!(f, "missing: {r}"),
            Self::AccessDenied(r) => write!(f, "access denied: {r}"),
            Self::MigrationRequired(r) => write!(f, "migration required: {r}"),
            Self::Corrupt(r) => write!(f, "corrupt: {r}"),
            Self::Unknown(r) => write!(f, "unknown: {r}"),
        }
    }
}

impl std::error::Error for OrsSupervisionStatusError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisionStatusReason {
    Healthy,
    MissingCurrent,
    StagedOnly,
    Expired,
    SignatureInvalid(String),
    BindingMismatch(String),
    CorruptRecord(String),
    VerificationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisionStatusProjection {
    pub lease_id: String,
    pub health: HealthDimension,
    pub heartbeat: HealthDimension,
    pub reason: SupervisionStatusReason,
    pub current: Option<SupervisionLeaseSnapshot>,
    pub staged: Option<SupervisionLeaseStageReceipt>,
    pub history: Vec<SupervisionLeaseSnapshot>,
}

/// Availability and gap view of one process-stream recovery projection
/// (issue #269, I14.26).
///
/// This is the ORS status/recovery view required to inspect stream recovery.
/// It carries handles, counts and exact typed state only:
///
/// - it holds no `Vec<u8>` and no preview bytes, so raw stdout/stderr payload
///   is structurally absent from the view;
/// - it carries no parser, evaluator, task or finish field, and its
///   `evidence_scope` is a single-variant value, so the view cannot claim
///   semantic proof;
/// - `UNKNOWN_OUTCOME`, `PARTIAL_SOURCE` and `SOURCE_UNAVAILABLE` stay
///   distinct typed values and are never flattened into a single code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStreamRecoveryStatusProjection {
    /// Operation that owns the projection.
    pub operation_id: String,
    /// Which physical stream this view describes; stdout and stderr never mix.
    pub stream: ProcessStreamKind,
    /// Typed physical transport completion, preserved exactly.
    pub transport: StreamTransportStatus,
    /// Typed source durability, preserved exactly and never promoted.
    pub persistence: StreamPersistenceStatus,
    /// Durable-source availability as last observed by revalidation.
    pub availability: StreamRecoveryAvailability,
    /// Immutable locator handle, when a durable source exists.
    pub durable_locator: Option<String>,
    /// Ready-receipt handle, when a durable source exists.
    pub ready_receipt_ref: Option<String>,
    /// Exact durable coverage, when a durable source exists.
    pub durable_coverage: Option<StreamRecoveryCoverage>,
    /// Exact coverage gap set, canonically sorted and unique.
    pub gaps: Vec<StreamEvidenceGap>,
    /// Reconciliation state of the owning operation.
    pub reconciliation: StreamRecoveryReconciliationState,
    /// Durable activation state of the projection.
    pub activation: StreamRecoveryActivation,
    /// What this view is allowed to assert.
    pub evidence_scope: StreamRecoveryEvidenceScope,
}

impl ProcessStreamRecoveryStatusProjection {
    /// Projects one durable recovery projection into the status/recovery view.
    pub fn from_projection(projection: &ProcessStreamRecoveryProjection) -> Self {
        Self {
            operation_id: projection.operation_id.as_str().to_owned(),
            stream: projection.stream,
            transport: projection.transport,
            persistence: projection.persistence,
            availability: projection.availability,
            durable_locator: projection
                .source
                .as_ref()
                .map(|source| source.locator().to_owned()),
            ready_receipt_ref: projection
                .source
                .as_ref()
                .map(|source| source.ready_receipt_ref().to_owned()),
            durable_coverage: projection.durable_coverage.clone(),
            gaps: projection.gaps.clone(),
            reconciliation: projection.reconciliation.state,
            activation: projection.activation,
            evidence_scope: projection.scope,
        }
    }

    /// Whether the view reports exact complete durable evidence.
    ///
    /// Complete evidence additionally requires an active projection and a
    /// revalidated source; availability alone never upgrades the typed
    /// persistence state.
    pub fn reports_complete_evidence(&self) -> bool {
        self.persistence == StreamPersistenceStatus::CompleteSource
            && self.transport == StreamTransportStatus::Complete
            && self.gaps.is_empty()
            && self.availability == StreamRecoveryAvailability::Revalidated
            && self.activation == StreamRecoveryActivation::Active
    }
}
