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

use eliot_runtime_contracts::HealthDimension;

use crate::{SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt};

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
