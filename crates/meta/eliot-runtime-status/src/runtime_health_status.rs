//! Read-only operator projection of the authenticated Kernel health carrier.
//!
//! `KernelRuntimeHealthEvidence` is the owner-produced source of truth for
//! this edge.  This module validates that carrier, preserves process health,
//! module-generation state and generation-cutover state as separate fields,
//! and evaluates each capability against only the dimensions it declares.
//! It never derives health from files, PIDs, ports, labels or the legacy
//! runtime-status contours.

use eliot_contracts::{EpochId, ResourceGeneration};
use eliot_kernel_core::{
    CapabilityReadiness, HealthDimensionKind, KernelRuntimeHealthEvidence, ProcessHealthStatus,
};
use serde::{Deserialize, Serialize};

/// Stable name for the operator-facing projection returned by this module.
pub const RUNTIME_HEALTH_STATUS_CONTRACT: &str = "eliot.runtime.health.status";
/// Version of the operator-facing projection shape.
pub const RUNTIME_HEALTH_STATUS_VERSION: &str = "1.0.0";

/// One capability's currentness result and the dimensions that caused it.
///
/// The result is calculated from the canonical owner declaration.  In
/// particular, a process may be live and compatible while this field is
/// `false` because freshness is one of the required dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCurrentness {
    pub capability: String,
    pub required_dimensions: Vec<HealthDimensionKind>,
    pub current: bool,
}

/// Error returned when the authenticated carrier cannot be consumed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeHealthProjectionError {
    #[error("Kernel runtime-health evidence failed validation: {0}")]
    InvalidEvidence(String),
}

/// Operator-visible projection of one authenticated Kernel health carrier.
///
/// `process` retains the canonical I1.10 vector and the independent I14.20
/// process, generation and cutover state machines.  The projection does not
/// collapse those states into one readiness boolean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeHealthStatusProjection {
    pub contract: String,
    pub contract_version: String,
    pub status: String,
    pub authority_epoch: EpochId,
    pub module_generation: ResourceGeneration,
    pub normative_pair_key: String,
    pub implementation_source_digest: String,
    pub process: ProcessHealthStatus,
    pub capabilities: Vec<CapabilityCurrentness>,
}

impl RuntimeHealthStatusProjection {
    /// Returns the named capability result, if the owner declared it.
    #[must_use]
    pub fn capability(&self, name: &str) -> Option<&CapabilityCurrentness> {
        self.capabilities
            .iter()
            .find(|capability| capability.capability == name)
    }
}

/// Validates and projects one owner-produced authenticated health carrier.
pub fn project_runtime_health(
    evidence: &KernelRuntimeHealthEvidence,
) -> Result<RuntimeHealthStatusProjection, RuntimeHealthProjectionError> {
    evidence
        .validate()
        .map_err(|error| RuntimeHealthProjectionError::InvalidEvidence(error.to_string()))?;

    let process = evidence.process_health().clone();
    let capabilities = evidence
        .capability_readiness()
        .iter()
        .map(|readiness: &CapabilityReadiness| CapabilityCurrentness {
            capability: readiness.capability().to_owned(),
            required_dimensions: readiness.required_dimensions().to_vec(),
            current: process.capability_is_current(readiness),
        })
        .collect();

    Ok(RuntimeHealthStatusProjection {
        contract: RUNTIME_HEALTH_STATUS_CONTRACT.to_owned(),
        contract_version: RUNTIME_HEALTH_STATUS_VERSION.to_owned(),
        status: evidence.status.clone(),
        authority_epoch: evidence.authority_epoch().clone(),
        module_generation: evidence.module_generation(),
        normative_pair_key: evidence.normative_pair_key.clone(),
        implementation_source_digest: evidence.implementation_source_digest.clone(),
        process,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use eliot_kernel_core::{
        AcceptedCompatibilityEvidence, CURRENT_ARCHITECTURE_SOURCE_DIGEST,
        CURRENT_IMPLEMENTATION_SOURCE_DIGEST, CURRENT_NORMATIVE_PAIR_KEY, CapabilityReadiness,
        CompatibilityEnvelope, DurableCompatibilityState, NormativePairReceipt,
        ProcessHealthStatus, ProcessHealthVector, StateMigrationClass, VersionRange,
        admit_handshake, expected_seal_tag,
    };
    use eliot_runtime_contracts::{
        GenerationCutoverState, HealthDimension, HealthVector, ModuleGenerationState,
        ServiceProcessState,
    };
    use std::num::NonZeroU64;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const CONTRACTS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new(LINEAGE).expect("valid lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("valid epoch")
    }

    fn compatibility() -> AcceptedCompatibilityEvidence {
        let authority_epoch = epoch();
        let receipt = NormativePairReceipt::new(
            CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            expected_seal_tag(CURRENT_ARCHITECTURE_SOURCE_DIGEST),
        )
        .expect("valid normative receipt");
        let candidate = CompatibilityEnvelope::new(
            VersionRange::new(1, 3).expect("protocol range"),
            CONTRACTS,
            VersionRange::new(1, 3).expect("canonical range"),
            CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            receipt,
            ResourceGeneration::genesis(),
            authority_epoch.clone(),
            vec!["runtime.health".to_owned()],
            Vec::new(),
            StateMigrationClass::Additive,
        )
        .expect("valid candidate");
        let durable = DurableCompatibilityState::new(
            VersionRange::new(1, 3).expect("protocol range"),
            CONTRACTS,
            VersionRange::new(1, 3).expect("canonical range"),
            CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            authority_epoch,
            vec!["runtime.health".to_owned()],
            StateMigrationClass::Additive,
        )
        .expect("valid durable state");
        admit_handshake(&candidate, &durable).expect("compatible handshake")
    }

    fn evidence(
        process_state: ServiceProcessState,
        freshness: HealthDimension,
        generation_state: ModuleGenerationState,
        cutover_state: GenerationCutoverState,
    ) -> KernelRuntimeHealthEvidence {
        let mut canonical = HealthVector::healthy();
        canonical.freshness = freshness;
        let process = ProcessHealthStatus::new(
            "graph-daemon",
            process_state,
            ProcessHealthVector::new(canonical, HealthDimension::Healthy),
            generation_state,
            cutover_state,
        )
        .expect("valid process health");
        KernelRuntimeHealthEvidence::new(
            "OPEN",
            epoch(),
            ResourceGeneration::genesis(),
            compatibility(),
            CURRENT_NORMATIVE_PAIR_KEY,
            CURRENT_IMPLEMENTATION_SOURCE_DIGEST,
            process,
            vec![
                CapabilityReadiness::new(
                    "current-impact-analysis",
                    vec![
                        eliot_kernel_core::HealthDimensionKind::Liveness,
                        eliot_kernel_core::HealthDimensionKind::Compatibility,
                        eliot_kernel_core::HealthDimensionKind::Freshness,
                    ],
                )
                .expect("fresh capability"),
                CapabilityReadiness::new(
                    "protocol-ping",
                    vec![
                        eliot_kernel_core::HealthDimensionKind::Liveness,
                        eliot_kernel_core::HealthDimensionKind::Compatibility,
                    ],
                )
                .expect("unrelated capability"),
            ],
            false,
        )
        .expect("valid runtime health evidence")
    }

    #[test]
    fn projects_independent_process_generation_and_cutover_states() {
        let projection = project_runtime_health(&evidence(
            ServiceProcessState::Ready,
            HealthDimension::Failed,
            ModuleGenerationState::Staged,
            GenerationCutoverState::Preparing,
        ))
        .expect("projection");

        assert_eq!(
            projection.process.process_state(),
            ServiceProcessState::Ready
        );
        assert_eq!(
            projection.process.health().canonical.freshness,
            HealthDimension::Failed
        );
        assert_eq!(
            projection.process.generation_state(),
            ModuleGenerationState::Staged
        );
        assert_eq!(
            projection.process.cutover_state(),
            GenerationCutoverState::Preparing
        );
        assert!(!projection.process.generation_is_active());
        assert!(!projection.process.cutover_is_complete());
    }

    #[test]
    fn freshness_failure_only_removes_fresh_capability_currentness() {
        let projection = project_runtime_health(&evidence(
            ServiceProcessState::Ready,
            HealthDimension::Failed,
            ModuleGenerationState::Active,
            GenerationCutoverState::Completed,
        ))
        .expect("projection");

        assert!(
            !projection
                .capability("current-impact-analysis")
                .expect("fresh capability")
                .current
        );
        assert!(
            projection
                .capability("protocol-ping")
                .expect("unrelated capability")
                .current
        );
    }

    #[test]
    fn invalid_owner_carrier_is_rejected_before_projection() {
        let mut invalid = evidence(
            ServiceProcessState::Ready,
            HealthDimension::Healthy,
            ModuleGenerationState::Active,
            GenerationCutoverState::Completed,
        );
        invalid.status = "STALE".to_owned();

        assert!(matches!(
            project_runtime_health(&invalid),
            Err(RuntimeHealthProjectionError::InvalidEvidence(_))
        ));
    }
}
