//! P-07 process-health projection: I1.10 health vector kept separate from the
//! I14.20 module-generation lifecycle.
//!
//! The shared lifecycle vocabularies — [`ServiceProcessState`],
//! [`ModuleGenerationState`] and [`GenerationCutoverState`] — are owned once by
//! I14.20 (`eliot-runtime-contracts`). This module defines no local lifecycle
//! equivalents; it only projects the three state spaces side by side with
//! separate persistence/projection fields so an operator can see, at once, a
//! live process, a non-active generation and an incomplete cutover.
//!
//! Health follows I1.10: seven independent dimensions (liveness, readiness,
//! freshness, compatibility, integrity, capacity, supervision coverage). The
//! canonical [`HealthVector`] carries the six process-local dimensions; this
//! module adds the seventh, supervision coverage, without redefining the
//! canonical six. A capability is advertised as current only for the
//! capabilities whose required dimensions pass — a `READY` process state never
//! implies active generation status or a completed cutover.

use eliot_runtime_contracts::{
    GenerationCutoverState, HealthDimension, HealthVector, ModuleGenerationState,
    ServiceProcessState,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, KernelResult, validate_id, validate_text};

/// Names one of the seven I1.10 health dimensions for capability gating.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthDimensionKind {
    /// The process responds.
    Liveness,
    /// The capability may accept the declared work class.
    Readiness,
    /// Derived state is current enough for the declared use.
    Freshness,
    /// Protocol and contract compatibility.
    Compatibility,
    /// Artifact, configuration and state integrity.
    Integrity,
    /// Resource budget is available.
    Capacity,
    /// Independent supervision observes the process.
    SupervisionCoverage,
}

/// The seven-dimensional I1.10 health vector.
///
/// The six process-local dimensions delegate to the canonical [`HealthVector`];
/// `supervision_coverage` is stored as its own independent field so no
/// dimension can be inferred from another and no scalar summary can hide a
/// single failing dimension.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessHealthVector {
    /// Canonical six process-local health dimensions.
    pub canonical: HealthVector,
    /// Independent supervision observes this process (I1.10 seventh dimension).
    pub supervision_coverage: HealthDimension,
}

impl ProcessHealthVector {
    /// Builds a seven-dimensional vector from the canonical six plus the
    /// independently observed supervision-coverage dimension.
    #[must_use]
    pub const fn new(canonical: HealthVector, supervision_coverage: HealthDimension) -> Self {
        Self {
            canonical,
            supervision_coverage,
        }
    }

    /// Returns the observed value of one independent dimension.
    #[must_use]
    pub const fn dimension(self, kind: HealthDimensionKind) -> HealthDimension {
        match kind {
            HealthDimensionKind::Liveness => self.canonical.liveness,
            HealthDimensionKind::Readiness => self.canonical.readiness,
            HealthDimensionKind::Freshness => self.canonical.freshness,
            HealthDimensionKind::Compatibility => self.canonical.compatibility,
            HealthDimensionKind::Integrity => self.canonical.integrity,
            HealthDimensionKind::Capacity => self.canonical.capacity,
            HealthDimensionKind::SupervisionCoverage => self.supervision_coverage,
        }
    }

    /// Returns true only when every one of the seven dimensions is healthy.
    #[must_use]
    pub const fn is_fully_healthy(self) -> bool {
        self.canonical.is_fully_healthy()
            && matches!(self.supervision_coverage, HealthDimension::Healthy)
    }
}

/// Declares which health dimensions one capability requires before it may be
/// advertised as current.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReadiness {
    capability: String,
    required_dimensions: Vec<HealthDimensionKind>,
}

impl CapabilityReadiness {
    /// Declares a capability with its required health dimensions.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability name is blank or no dimension is
    /// required.
    pub fn new(
        capability: impl Into<String>,
        required_dimensions: Vec<HealthDimensionKind>,
    ) -> KernelResult<Self> {
        let capability = capability.into();
        validate_id(&capability, "capability")?;
        if required_dimensions.is_empty() {
            return Err(KernelError::InvalidField {
                field: "required_dimensions",
                reason: "at least one health dimension is required",
            });
        }
        Ok(Self {
            capability,
            required_dimensions,
        })
    }

    /// Returns the capability name.
    #[must_use]
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// Returns the required dimensions.
    #[must_use]
    pub fn required_dimensions(&self) -> &[HealthDimensionKind] {
        &self.required_dimensions
    }

    /// Returns true only when every required dimension is healthy.
    ///
    /// The process lifecycle state is deliberately not consulted here:
    /// capability currency is a function of the required health dimensions,
    /// never of `READY` alone.
    #[must_use]
    pub fn is_advertised_as_current(&self, health: ProcessHealthVector) -> bool {
        self.required_dimensions
            .iter()
            .all(|kind| matches!(health.dimension(*kind), HealthDimension::Healthy))
    }
}

/// Operator-visible projection of one process, its capability generation and
/// its route cutover as three separate state spaces.
///
/// Each space keeps its own field: `process_state` (I14.20 service process),
/// `generation_state` (I14.20 module generation) and `cutover_state` (I14.20
/// generation cutover). A `READY` process with satisfied capability dimensions
/// still reports `generation_is_active() == false` while its generation is
/// `STAGED` or `DEGRADED`, and `cutover_is_complete() == false` until the
/// cutover machine reaches `COMPLETED`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessHealthStatus {
    process_id: String,
    process_state: ServiceProcessState,
    health: ProcessHealthVector,
    generation_state: ModuleGenerationState,
    cutover_state: GenerationCutoverState,
}

impl ProcessHealthStatus {
    /// Records one observation of the three separate state spaces.
    ///
    /// # Errors
    ///
    /// Returns an error when the process identity is blank.
    pub fn new(
        process_id: impl Into<String>,
        process_state: ServiceProcessState,
        health: ProcessHealthVector,
        generation_state: ModuleGenerationState,
        cutover_state: GenerationCutoverState,
    ) -> KernelResult<Self> {
        let process_id = process_id.into();
        validate_text(&process_id, "process_id")?;
        Ok(Self {
            process_id,
            process_state,
            health,
            generation_state,
            cutover_state,
        })
    }

    /// Returns the process identity.
    #[must_use]
    pub fn process_id(&self) -> &str {
        &self.process_id
    }

    /// Returns the canonical I14.20 service-process state.
    #[must_use]
    pub const fn process_state(&self) -> ServiceProcessState {
        self.process_state
    }

    /// Returns the seven-dimensional health vector.
    #[must_use]
    pub const fn health(&self) -> ProcessHealthVector {
        self.health
    }

    /// Returns the canonical I14.20 module-generation state.
    #[must_use]
    pub const fn generation_state(&self) -> ModuleGenerationState {
        self.generation_state
    }

    /// Returns the canonical I14.20 generation-cutover state.
    #[must_use]
    pub const fn cutover_state(&self) -> GenerationCutoverState {
        self.cutover_state
    }

    /// Returns true only when the generation machine has reached `ACTIVE`.
    ///
    /// Never derived from the process state: a live/`READY` process with a
    /// `STAGED` or `DEGRADED` generation reports false here.
    #[must_use]
    pub const fn generation_is_active(&self) -> bool {
        matches!(self.generation_state, ModuleGenerationState::Active)
    }

    /// Returns true only when the cutover machine has reached `COMPLETED`.
    ///
    /// Never derived from the process state or the generation state: route
    /// switching belongs to its own machine.
    #[must_use]
    pub const fn cutover_is_complete(&self) -> bool {
        matches!(self.cutover_state, GenerationCutoverState::Completed)
    }

    /// Returns true when the named capability's required health dimensions
    /// pass, regardless of generation or cutover state.
    #[must_use]
    pub fn capability_is_current(&self, readiness: &CapabilityReadiness) -> bool {
        readiness.is_advertised_as_current(self.health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_but_alive_process_gates_only_freshness_capabilities() -> KernelResult<()> {
        // Acceptance: simultaneously live and compatible but not fresh, a
        // STAGED generation, and an incomplete cutover.
        let mut canonical = HealthVector::healthy();
        canonical.freshness = HealthDimension::Failed;
        let health = ProcessHealthVector::new(canonical, HealthDimension::Healthy);
        let status = ProcessHealthStatus::new(
            "graph-daemon",
            ServiceProcessState::Degraded,
            health,
            ModuleGenerationState::Staged,
            GenerationCutoverState::Preparing,
        )?;

        let fresh_capability = CapabilityReadiness::new(
            "current-impact-analysis",
            vec![
                HealthDimensionKind::Liveness,
                HealthDimensionKind::Compatibility,
                HealthDimensionKind::Freshness,
            ],
        )?;
        let unrelated_capability = CapabilityReadiness::new(
            "protocol-ping",
            vec![
                HealthDimensionKind::Liveness,
                HealthDimensionKind::Compatibility,
            ],
        )?;

        // Only freshness fails, so only the freshness-gated capability is down.
        assert!(!status.capability_is_current(&fresh_capability));
        // Unrelated capabilities with satisfied dimensions remain available.
        assert!(status.capability_is_current(&unrelated_capability));
        // Generation and cutover stay explicitly separated from process health.
        assert!(!status.generation_is_active());
        assert!(!status.cutover_is_complete());
        Ok(())
    }
}
