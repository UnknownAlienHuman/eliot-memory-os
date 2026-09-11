//! Canonical A-04 assembly contracts owned by A-03.
//!
//! This namespace describes the finite recipe and role vocabulary consumed by
//! bundle assembly. It owns no selection, source resolution, screening,
//! admission, or runtime behavior.

#![forbid(unsafe_code)]

use std::io::{self, Write};

use serde::Serialize;

/// Maximum canonical size of the complete retained assembly carrier.
pub(crate) const ASSEMBLY_CARRIER_CEILING: usize = 8 * 1024 * 1024;

/// Count canonical bytes without allocating the serialized payload.
pub(crate) fn preflight<T: Serialize>(
    value: &T,
    field: &'static str,
    ceiling: usize,
) -> Result<usize, crate::error::ContractViolation> {
    let mut writer = CountingWriter::new(ceiling);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(writer.count),
        Err(_error) if writer.exceeded => Err(crate::error::ContractViolation::Budget {
            dimension: field,
            reason: format!("canonical assembly payload exceeds {ceiling} bytes"),
        }),
        Err(error) => Err(crate::error::ContractViolation::Malformed {
            field,
            reason: format!("canonical assembly serialization failed: {error}"),
        }),
    }
}

/// Preflight one payload, then allocate its canonical bytes.
pub(crate) fn canonical_bytes<T: Serialize>(
    value: &T,
    field: &'static str,
    ceiling: usize,
) -> Result<Vec<u8>, crate::error::ContractViolation> {
    preflight(value, field, ceiling)?;
    crate::encoding::canonical_bytes(value)
}

struct CountingWriter {
    count: usize,
    ceiling: usize,
    exceeded: bool,
}

impl CountingWriter {
    const fn new(ceiling: usize) -> Self {
        Self {
            count: 0,
            ceiling,
            exceeded: false,
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("assembly byte counter overflow"))?;
        if self.count > self.ceiling {
            self.exceeded = true;
            return Err(io::Error::other("assembly payload exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub mod material;
pub mod recipe;
pub mod result;

pub use material::{
    AssemblyMaterial, AssemblyMaterialSet, AssemblyOmissionAccounting, AssemblyOmissionConstraint,
    AssemblyOmissionCoverage, BundleMeasurement, ConditionalEvaluation, ConditionalEvaluationState,
    ConflictAtomIdentity, ContextMaterialClosure, ContributionMeasurement, ContributionStatus,
    CurationMaterial, MaterialDisposition, MaterialLedgerEntry, MaterialOutcomeReason,
    MaterialRepresentation, RoleOutcome, RoleOutcomeState, SuppliedItemIdentity,
    material_schema_version,
};
pub use recipe::{
    AssemblyReserve, AssemblyReserveSet, ConditionalCoverageBinding, ConditionalPredicate,
    ConditionalRequirement, DreamInputRole, DreamJobRecipe, RECIPE_SCHEMA_VERSION, RecipeInput,
    RecipeRole, RoleDisposition, RoleOmissionPolicy, SourceRule, SourceRuleKind, required_roles,
};
pub use result::{
    AssemblyFrontier, AssemblyResult, AssemblyStop, AssemblyStopReason, DisclosureAuthorization,
    ReserveUsage, result_schema_version,
};
