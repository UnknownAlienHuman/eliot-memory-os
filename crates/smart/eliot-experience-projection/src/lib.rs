//! Immutable System Experience journal slice (#223, review repair).
//!
//! [`ExperienceJournalSlice`] is a thin validated envelope over supplied
//! owner-typed `SystemObservationJournalRecord`s (foundation
//! observation-contracts owner, `CONTRACT_VERSION` 1.0.0): every record is
//! validated with the owner's `validate()`, coverage gaps travel as the
//! owner's typed `CoverageGap` records, and coverage provenance echoes each
//! record's owner `denominator_source_ref`.
//!
//! The slice denominator is exactly the supplied validated set.
//! Completeness over the owner journal is never claimed, vector length is
//! never an owner denominator, and revalidation against the owner stays
//! required before any completeness use. Scope, fence, revision, and
//! coverage semantics stay with the owner records; this crate carries no
//! caller-supplied scope/fence, no free-form omission reasons, and no
//! record bodies of its own. The retired `eliot-system-experience`
//! duplicate is reused by reference only: no second self-memory owner,
//! relation store, or lifecycle transition path. This package is not a W9
//! unblock: the typed journal/bank/feedback completeness proofs stay with
//! their owners.

#![forbid(unsafe_code)]

use eliot_contracts::ContractVersion;
use eliot_observation_contracts::{
    CONTRACT_VERSION, CoverageGap, ObservationError, ObservationRecordKind,
    SystemObservationJournalRecord,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";

/// Experience-slice failure: every case fails closed with its reason.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExperienceError {
    /// An owner record shape is invalid.
    #[error("experience journal slice: {0}")]
    Upstream(#[from] ObservationError),
    /// The slice version drifted from the frozen owner contract version.
    #[error("experience journal slice: version drift")]
    VersionMismatch,
    /// The supplied count does not equal the carried record count.
    #[error("experience journal slice: supplied {supplied} contradicts carried {actual}")]
    CountMismatch {
        /// Declared supplied count.
        supplied: usize,
        /// Records actually carried.
        actual: usize,
    },
}

/// Immutable validated envelope over supplied owner journal records.
///
/// `supplied` always equals `records.len()`: it accounts the supplied set,
/// never the owner journal. A consumer that needs owner completeness must
/// revalidate against the owner; this slice never substitutes for that
/// enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceJournalSlice {
    /// Frozen owner contract version this slice was written against.
    pub contract_version: ContractVersion,
    /// Owner-validated records in deterministic supply order.
    pub records: Vec<SystemObservationJournalRecord>,
    /// Supplied-set count; always equals `records.len()`.
    pub supplied: usize,
}

impl ExperienceJournalSlice {
    /// Assemble a validated slice over owner-typed records.
    pub fn assemble(
        records: Vec<SystemObservationJournalRecord>,
    ) -> Result<Self, ExperienceError> {
        let slice = Self {
            contract_version: CONTRACT_VERSION,
            records,
            supplied: 0,
        };
        let supplied = slice.records.len();
        let slice = Self { supplied, ..slice };
        slice.validate()?;
        Ok(slice)
    }

    /// Validate version, per-record owner shapes, and supplied-set
    /// accounting.
    pub fn validate(&self) -> Result<(), ExperienceError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ExperienceError::VersionMismatch);
        }
        for record in &self.records {
            record.validate()?;
        }
        if self.supplied != self.records.len() {
            return Err(ExperienceError::CountMismatch {
                supplied: self.supplied,
                actual: self.records.len(),
            });
        }
        Ok(())
    }

    /// Typed omission surface: the owner's gap records, in supply order.
    #[must_use]
    pub fn gaps(&self) -> Vec<&CoverageGap> {
        self.records
            .iter()
            .filter_map(|record| record.coverage_gap.as_ref())
            .collect()
    }

    /// Records of one owner family, in supply order.
    #[must_use]
    pub fn records_of(
        &self,
        kind: ObservationRecordKind,
    ) -> Vec<&SystemObservationJournalRecord> {
        self.records
            .iter()
            .filter(|record| record.kind == kind)
            .collect()
    }

    /// Coverage provenance refs echoed from event-carrying records, in
    /// supply order without duplicates. These name the owner's denominator
    /// sources; they establish no view-level completeness.
    #[must_use]
    pub fn denominator_source_refs(&self) -> Vec<&str> {
        let mut refs = Vec::new();
        for record in &self.records {
            if let Some(event) = &record.event {
                let candidate = event.coverage_and_blind_intervals.denominator_source_ref.as_str();
                if !refs.contains(&candidate) {
                    refs.push(candidate);
                }
            }
        }
        refs
    }
}
