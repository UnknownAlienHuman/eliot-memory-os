//! Explicitly versioned compatibility decoder for durable scalar epoch records.
//!
//! Issue #64 W3: durable records that carry only a scalar authority sequence
//! predate the lineage-aware [`EpochId`] contract and cannot name their own
//! lineage. This module decodes such a record only together with explicit
//! installation/Host lineage evidence (issue #64 A6); an unbound scalar is
//! never assumed to belong to the current lineage.
//!
//! The decode rule mirrors I6.10 and A13.7: equal sequences from different
//! lineages are unrelated, a numerically larger sequence from another lineage
//! is not newer, restore imports snapshots only as historical/suspended
//! evidence, and old epochs never revive. [`decode_scalar_epoch`] therefore
//! requires a [`LineageEvidence`] value whose [`EpochLineageId`] was validated
//! at its own owner boundary (installation records or the `HostStateJournal`
//! `HostInstallationEpoch`, projected here without depending on the kernel).
//! [`suspend_scalar_record`] is the fail-closed disposition for a record that
//! carries no such evidence: the returned [`SuspendedScalarRecord`] preserves
//! the durable bytes for visible recovery and offers no path to [`EpochId`]
//! or authority.
//!
//! Canonical types keep rejecting scalar input at their own boundary
//! (`StateFence` documents that no scalar-to-canonical coercion exists); this
//! decoder is the single explicit migration path, not a second spelling of an
//! epoch.

use std::num::NonZeroU64;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::epoch_identity::{EpochContractError, EpochId, EpochLineageId};

/// Codec tag every durable scalar epoch record must carry.
///
/// Records without exactly this tag predate the versioned migration contour
/// and fail closed with [`EpochCompatError::UnknownCodecVersion`].
pub const SCALAR_EPOCH_RECORD_CODEC: &str = "eliot.epoch-compat.scalar.v1";

/// A durable scalar authority-sequence record in its versioned wire shape.
///
/// This is the pre-lineage durable form: a bare sequence with a codec tag and
/// no lineage of its own. It never authorizes on its own; only
/// [`decode_scalar_epoch`] with explicit [`LineageEvidence`] binds it to an
/// [`EpochId`].
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarEpochRecord {
    /// Codec tag; must equal [`SCALAR_EPOCH_RECORD_CODEC`].
    pub codec: String,
    /// Durable scalar sequence; must be non-zero.
    pub sequence: u64,
}

/// The proven source of the lineage a scalar record is bound to.
///
/// Only the two evidence sources issue #64 A6 admits: installation records and
/// the `HostStateJournal` installation epoch. Wave-4 callers project these from
/// their owning records; this crate defines the closed kind set so the
/// decoder never invents a third source.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageEvidenceKind {
    /// Lineage proven by installation records.
    Installation,
    /// Lineage proven by the `HostStateJournal` installation epoch.
    HostJournal,
}

/// Explicit installation/Host lineage evidence for one scalar record.
///
/// The [`EpochLineageId`] validates its canonical spelling at construction or
/// deserialization; the decoder binds the scalar sequence into exactly this
/// lineage and never into an implicit current lineage.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageEvidence {
    /// Which owning record proved the lineage.
    pub kind: LineageEvidenceKind,
    /// The proven lineage the scalar sequence belongs to.
    pub lineage_id: EpochLineageId,
}

/// A fenced, non-authoritative disposition for an unbound scalar record.
///
/// Carries the validated durable bytes for visible recovery (historical
/// evidence or manual recovery, decided by the recovery owner). By
/// construction this type offers no conversion to [`EpochId`], so a suspended
/// record can never become active authority.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspendedScalarRecord {
    /// Codec tag of the suspended record.
    pub codec: String,
    /// Suspended scalar sequence; always non-zero.
    pub sequence: u64,
}

/// A validation or migration failure in the scalar-epoch compatibility contour.
///
/// Variants are deliberately disjoint from the closed [`EpochContractError`]
/// set: this decoder never reinterprets a canonical contract failure, and a
/// compatibility failure never becomes a canonical epoch value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EpochCompatError {
    /// The record does not carry the versioned migration codec.
    #[error("UNKNOWN_SCALAR_EPOCH_CODEC")]
    UnknownCodecVersion,
    /// The durable scalar sequence is zero, so it names no epoch.
    #[error("SCALAR_EPOCH_ZERO_SEQUENCE")]
    ZeroSequence,
    /// No installation/Host lineage evidence was supplied, so the scalar
    /// stays unbound: historical/suspended or manual recovery, never the
    /// current lineage.
    #[error("MISSING_LINEAGE_EVIDENCE")]
    MissingLineageEvidence,
    /// The canonical epoch constructor refused validated inputs.
    #[error("INVALID_EPOCH_IDENTITY")]
    InvalidEpochIdentity(EpochContractError),
}

/// Validates the versioned wire shape shared by both decoder entry points.
fn validate_wire(record: &ScalarEpochRecord) -> Result<NonZeroU64, EpochCompatError> {
    if record.codec.as_str() != SCALAR_EPOCH_RECORD_CODEC {
        return Err(EpochCompatError::UnknownCodecVersion);
    }
    NonZeroU64::new(record.sequence).ok_or(EpochCompatError::ZeroSequence)
}

/// Binds a durable scalar record to an [`EpochId`] using explicit lineage evidence.
///
/// The returned epoch carries exactly the evidence lineage and the record
/// sequence; cross-lineage ordering is never consulted because only one
/// lineage is ever in scope. `None` evidence fails closed with
/// [`EpochCompatError::MissingLineageEvidence`]: the caller must route the
/// record through [`suspend_scalar_record`] into visible recovery instead of
/// assuming the current lineage.
pub fn decode_scalar_epoch(
    record: &ScalarEpochRecord,
    evidence: Option<&LineageEvidence>,
) -> Result<EpochId, EpochCompatError> {
    let sequence = validate_wire(record)?;
    let evidence = evidence.ok_or(EpochCompatError::MissingLineageEvidence)?;
    EpochId::new(evidence.lineage_id.clone(), sequence)
        .map_err(EpochCompatError::InvalidEpochIdentity)
}

/// Fences a scalar record that carries no lineage evidence.
///
/// Validates the durable bytes (codec tag and non-zero sequence) and returns
/// them as a [`SuspendedScalarRecord`] for visible recovery. The result is
/// historical/suspended evidence or manual-recovery input at the recovery
/// owner; it can never authorize, supersede, or finalize an operation.
pub fn suspend_scalar_record(
    record: &ScalarEpochRecord,
) -> Result<SuspendedScalarRecord, EpochCompatError> {
    let sequence = validate_wire(record)?;
    Ok(SuspendedScalarRecord {
        codec: record.codec.clone(),
        sequence: sequence.get(),
    })
}
