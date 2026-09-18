//! Testd-side admission port behind which the provider registry composes.
//!
//! This module mirrors the `KernelProcessAdmissionProvider` boundary owned by
//! issue #20 without depending on `testd-core`: it admits one
//! registry-resolved [`InstrumentInvocation`] into a [`TestdAdmission`] and
//! carries raw evidence through [`RawEvidence`] before any
//! parser/normalizer reduction. It creates no scheduler, task database,
//! budget, `Job`, `Finish`, Governor, canonical-store, or second Testd owner;
//! the absence of those dependencies is structural (only
//! `eliot-instrument-api`, `eliot-contracts`, `thiserror`, and the sibling
//! [`crate::registry`] module are imported) and is documented here rather
//! than enforced with negative trait hacks.
//!
//! Live Testd today admits only [`InstrumentKind::Test`] (see
//! `TestdError::WrongInstrumentKind` in `testd-core`, referenced read-only).
//! Every other class therefore resolves through the registry but stays
//! non-dispatchable via Testd, reported as the typed
//! [`TestdPortError::UnsupportedByTestd`] failure rather than a registry
//! failure. Live dispatch, real fixtures, and admission behavior are
//! follow-up work owned by later slices.
//!
//! [`RawEvidence`] here is a port-local retention handle and is distinct from
//! the `eliot_instrument_api::RawEvidence` byte payload: retention alone
//! establishes no outcome, and no arm of
//! [`RawEvidence::execution_status`] returns [`ExecutionStatus::Succeeded`].

use eliot_contracts::ArtifactId;
use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind};
use thiserror::Error;

use crate::registry::{RegistryEntry, RegistryError};

/// Local mirror of the Testd admission boundary for resolved invocations.
///
/// Implementations belong to the Testd composition root (issue #20). Callers
/// resolve through [`crate::registry::ProviderRegistry`] first and admit the
/// returned entry here; admission performs no second resolution pass.
pub trait TestdAdmissionPort: Send + Sync {
    /// Admits one registry-resolved invocation behind Testd.
    ///
    /// # Errors
    ///
    /// Returns [`TestdPortError::UnsupportedByTestd`] when the invocation
    /// class is not dispatchable through live Testd, or
    /// [`TestdPortError::Registry`] when the entry binding is rejected.
    fn admit(
        &self,
        invocation: &InstrumentInvocation,
        entry: &RegistryEntry,
    ) -> Result<TestdAdmission, TestdPortError>;
}

/// Admission receipt for one resolved invocation.
///
/// The receipt records which adapter the registry selected and at which
/// registry generation. It carries no process permit, contour authority,
/// task, budget, or finish decision; physical admission stays with Testd.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestdAdmission {
    /// Admitted provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// Adapter identity selected by the registry.
    pub adapter: String,
    /// Registry generation the selection was validated against.
    pub registry_generation: u64,
}

impl TestdAdmission {
    /// Records an admission for a resolved entry.
    pub fn new(invocation: InstrumentInvocation, entry: &RegistryEntry) -> Self {
        Self {
            invocation,
            adapter: entry.adapter.clone(),
            registry_generation: entry.generation,
        }
    }
}

/// Failures raised while admitting a resolved invocation behind Testd.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TestdPortError {
    /// The registry binding was rejected.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The class resolves but live Testd cannot dispatch it.
    ///
    /// Live Testd admits only [`InstrumentKind::Test`]; build, lint, inspect,
    /// format, and verify entries resolve successfully and then stop here.
    /// This mirrors `TestdError::WrongInstrumentKind` without depending on
    /// `testd-core`.
    #[error("live testd admits only TEST invocations; {kind:?} is not dispatchable via testd")]
    UnsupportedByTestd {
        /// Requested instrument class.
        kind: InstrumentKind,
    },
}

/// Whether `kind` is dispatchable through live Testd today.
///
/// Only [`InstrumentKind::Test`] returns true. Every other class resolves
/// through the registry and is then reported via
/// [`TestdPortError::UnsupportedByTestd`].
pub fn testd_dispatchable(kind: InstrumentKind) -> bool {
    matches!(kind, InstrumentKind::Test)
}

/// Raw evidence retained (or explicitly omitted) before reduction.
///
/// `Retained` keeps the immutable artifact handle plus its exact byte length
/// so the parser input stays addressable. `Omitted` records why material
/// output is absent. Truncated, omitted, and malformed states can never
/// become `PASS`: see [`RawEvidence::execution_status`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawEvidence {
    /// Material output retained under an immutable artifact handle.
    Retained {
        /// Stable handle for the retained bytes.
        artifact: ArtifactId,
        /// Exact retained byte length.
        byte_len: u64,
    },
    /// Material output absent for an explicit, typed reason.
    Omitted {
        /// Why the output is absent.
        reason: OmissionReason,
    },
}

/// Explicit reason material output never reached the parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    /// Capture stopped at an explicit truncation boundary.
    Truncated {
        /// Bytes retained before truncation.
        byte_len: u64,
        /// Bound that forced truncation.
        limit_bytes: u64,
    },
    /// Output was omitted by policy or environment.
    Omitted {
        /// Owning-policy reason text (evidence, never control flow).
        reason: String,
    },
    /// Output failed well-formedness checks before parsing.
    Malformed {
        /// Owning-parser detail text (evidence, never control flow).
        detail: String,
    },
}

impl RawEvidence {
    /// Maps retention state to execution status without ever succeeding.
    ///
    /// Retention alone establishes no outcome, so `Retained` maps to
    /// [`ExecutionStatus::Unknown`] and leaves the verdict to the parser and
    /// evaluator. Truncation and omission map to
    /// [`ExecutionStatus::Unknown`]; malformed output maps to
    /// [`ExecutionStatus::Failed`]. No arm returns
    /// [`ExecutionStatus::Succeeded`], so incomplete evidence can never
    /// become `PASS`.
    pub fn execution_status(&self) -> ExecutionStatus {
        match self {
            Self::Retained { .. } => ExecutionStatus::Unknown,
            Self::Omitted { reason } => match reason {
                OmissionReason::Truncated { .. } | OmissionReason::Omitted { .. } => {
                    ExecutionStatus::Unknown
                }
                OmissionReason::Malformed { .. } => ExecutionStatus::Failed,
            },
        }
    }

    /// Returns the retained artifact handle, if output was retained.
    pub fn artifact(&self) -> Option<&ArtifactId> {
        match self {
            Self::Retained { artifact, .. } => Some(artifact),
            Self::Omitted { .. } => None,
        }
    }
}
