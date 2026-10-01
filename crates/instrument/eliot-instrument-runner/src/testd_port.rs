//! Testd-side admission port behind which the provider registry composes.
//!
//! This module mirrors the `KernelProcessAdmissionProvider` boundary owned by
//! issue #20: it admits a registry-resolved [`InstrumentInvocation`] or closed
//! [`InstrumentStageRequest`] into a [`TestdAdmission`] and carries raw
//! evidence through [`RawEvidence`] before any
//! parser/normalizer reduction. It creates no scheduler, task database,
//! budget, `Job`, `Finish`, Governor, canonical-store, or second Testd owner;
//! the absence of those owners is structural: this module defines no
//! scheduler, task database, budget, `Job`, `Finish`, Governor, or
//! canonical-store owner.
//!
//! The stage request carries the exact profile, DAG, registry, stage, parser,
//! and adapter identities already admitted by their owning registries. It is
//! a closed description only: executable invocation remains bound through the
//! existing adapter port and sealed process request. Decoder-only entries use
//! a distinct in-process lane and never acquire a process request.
//!
//! [`RawEvidence`] here is a port-local retention handle and is distinct from
//! the `eliot_instrument_api::RawEvidence` byte payload: retention alone
//! establishes no outcome, and no arm of
//! [`RawEvidence::execution_status`] returns [`ExecutionStatus::Succeeded`].

use eliot_contracts::ArtifactId;
use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation, InstrumentKind};
use eliot_testd_core::{InstrumentStageRequest, StageExecutionKind};
use thiserror::Error;

use eliot_instrument_cargo::CONTRACT_NAME as CARGO_ADAPTER;
use eliot_instrument_dotnet::CONTRACT_ID as DOTNET_ADAPTER;
use eliot_instrument_nextest::NEXTEST_INSTRUMENT as NEXTEST_ADAPTER;
use eliot_instrument_rustc::RUSTC_INSTRUMENT as RUSTC_ADAPTER;
use eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT as RUSTFMT_ADAPTER;
use eliot_instrument_scip::SCIP_INSTRUMENT as SCIP_ADAPTER;

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

    /// Admits one exact profile stage against its already selected provider.
    ///
    /// The request contains no executable, argv, process permit, or authority.
    /// The consumer must still bind the selected adapter through its governed
    /// process port, or use the decoder-only lane for a decoder entry.
    ///
    /// # Errors
    ///
    /// Returns a typed error when any stage identity differs from the selected
    /// entry or when the adapter has no governed lane for the requested kind.
    fn admit_stage(
        &self,
        request: &InstrumentStageRequest,
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
    /// Exact governed stage request accepted by the typed stage boundary.
    pub stage: Option<InstrumentStageRequest>,
}

impl TestdAdmission {
    /// Records an admission for a resolved entry.
    pub fn new(invocation: InstrumentInvocation, entry: &RegistryEntry) -> Self {
        Self {
            invocation,
            adapter: entry.adapter.clone(),
            registry_generation: entry.generation,
            stage: None,
        }
    }

    /// Records an admission for the exact stage and selected registry entry.
    pub fn for_stage(request: InstrumentStageRequest, entry: &RegistryEntry) -> Self {
        Self {
            invocation: request.invocation.clone(),
            adapter: entry.adapter.clone(),
            registry_generation: entry.generation,
            stage: Some(request),
        }
    }
}

/// Failures raised while admitting a resolved invocation behind Testd.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TestdPortError {
    /// The registry binding was rejected.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// At least one ready provider claims the class, but no retained adapter
    /// lane accepts it. Lint is currently outside the ready denominator.
    #[error("no ready Testd stage lane accepts {kind:?}")]
    UnsupportedByTestd {
        /// Requested instrument class.
        kind: InstrumentKind,
    },
    /// The stage request does not match its invocation or selected entry.
    #[error("testd stage request does not match the selected provider entry: {detail}")]
    StageBinding {
        /// Exact binding mismatch.
        detail: &'static str,
    },
    /// The selected adapter does not implement a governed lane for this kind.
    #[error("adapter '{adapter}' has no governed Testd lane for {kind:?}/{execution:?}")]
    UnsupportedAdapterStage {
        /// Selected adapter identity.
        adapter: String,
        /// Requested instrument class.
        kind: InstrumentKind,
        /// Requested execution lane.
        execution: StageExecutionKind,
    },
}

/// Whether at least one retained ready provider has a governed lane for `kind`.
///
/// This closed class-level surface intentionally excludes `Lint`: no ready
/// registry entry advertises a Lint adapter. Exact adapter and execution-lane
/// support is checked separately by [`adapter_stage_dispatchable`]. Per-host
/// readiness remains a separate axis decided by
/// [`ProviderRegistry::availability`](crate::ProviderRegistry::availability)
/// and reported as a typed
/// [`ProviderDisposition`](crate::ProviderDisposition), so a provider that
/// Testd could dispatch but this host cannot run stays inside the declared
/// denominator instead of disappearing.
pub fn testd_dispatchable(kind: InstrumentKind) -> bool {
    matches!(
        kind,
        InstrumentKind::Build
            | InstrumentKind::Test
            | InstrumentKind::Inspect
            | InstrumentKind::Verify
            | InstrumentKind::Format
    )
}

/// Whether one retained ready adapter owns this exact typed stage lane.
///
/// The adapter/kind table mirrors [`ProviderRegistry::ready`](crate::ProviderRegistry::ready)
/// and the adapters' existing launch validation. In particular, SCIP Inspect
/// is decoder-only, while Dotnet Inspect is a process lane; Lint has no entry.
pub fn adapter_stage_dispatchable(
    adapter: &str,
    kind: InstrumentKind,
    execution: StageExecutionKind,
) -> bool {
    use InstrumentKind::{Build, Format, Inspect, Test, Verify};
    use StageExecutionKind::{DecoderOnly, Process};

    match (adapter, kind, execution) {
        (CARGO_ADAPTER, Build | Test, Process) => true,
        (RUSTC_ADAPTER, Build, Process) => true,
        (RUSTFMT_ADAPTER, Format, Process) => true,
        (NEXTEST_ADAPTER, Test, Process) => true,
        (DOTNET_ADAPTER, Build | Test | Verify | Inspect, Process) => true,
        (SCIP_ADAPTER, Inspect, DecoderOnly) => true,
        _ => false,
    }
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
