//! Canonical authenticated runtime-health carrier for I1.10/I1.12.
//!
//! The carrier keeps compatibility evidence, process health, capability
//! currency, and the two lifecycle machines in one typed wire projection.
//! Producers must supply the evidence from their owning runtime state; this
//! module validates the projection and never derives authority from `status`.

use std::collections::BTreeSet;

use eliot_contracts::{EpochId, ResourceGeneration};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::compatibility_handshake::{
    AcceptedCompatibilityEvidence, HANDSHAKE_ENVELOPE_VERSION, expected_seal_tag,
};
use super::process_health::{CapabilityReadiness, ProcessHealthStatus};
use crate::error::{KernelError, KernelResult};

/// Architecture digest from the accepted normative-pair receipt.
pub const CURRENT_ARCHITECTURE_SOURCE_DIGEST: &str =
    "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a";
/// Implementation digest from the accepted normative-pair receipt.
pub const CURRENT_IMPLEMENTATION_SOURCE_DIGEST: &str =
    "40b0908a637f46ba6c7c51db08e008673f9232ed74d510d3a4f38489d05d4e89";
/// Pair identity from `docs/normative-pair.toml`.
pub const CURRENT_NORMATIVE_PAIR_KEY: &str =
    "sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea";

/// Authenticated Kernel health evidence consumed by Host and native-worker.
///
/// The transport `status` is deliberately retained beside, rather than used
/// in place of, the canonical projections. `doctor_repair_advertised` is an
/// orthogonal observation and carries no readiness authority.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRuntimeHealthEvidence {
    /// Authenticated front-door state. Only `OPEN` can be consumed.
    pub status: String,
    /// Authority epoch captured by the authenticated session.
    pub authority_epoch: EpochId,
    /// Resource generation captured by the authenticated session.
    pub module_generation: ResourceGeneration,
    /// Kernel-admitted compatibility result for the same generation/epoch.
    pub compatibility_evidence: AcceptedCompatibilityEvidence,
    /// Exact external normative-pair identity used by the producer.
    pub normative_pair_key: String,
    /// Implementation document digest paired with the architecture digest.
    pub implementation_source_digest: String,
    /// Canonical process/generation/cutover and seven-dimensional health.
    pub process_health: ProcessHealthStatus,
    /// Capability-specific dimension requirements.
    pub capability_readiness: Vec<CapabilityReadiness>,
    /// Independent Doctor observation; never a readiness substitute.
    #[serde(default)]
    pub doctor_repair_advertised: bool,
}

impl KernelRuntimeHealthEvidence {
    /// Builds and validates one owner-produced health projection.
    pub fn new(
        status: impl Into<String>,
        authority_epoch: EpochId,
        module_generation: ResourceGeneration,
        compatibility_evidence: AcceptedCompatibilityEvidence,
        normative_pair_key: impl Into<String>,
        implementation_source_digest: impl Into<String>,
        process_health: ProcessHealthStatus,
        capability_readiness: Vec<CapabilityReadiness>,
        doctor_repair_advertised: bool,
    ) -> KernelResult<Self> {
        let evidence = Self {
            status: status.into(),
            authority_epoch,
            module_generation,
            compatibility_evidence,
            normative_pair_key: normative_pair_key.into(),
            implementation_source_digest: implementation_source_digest.into(),
            process_health,
            capability_readiness,
            doctor_repair_advertised,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Revalidates a deserialized carrier at a consumer boundary.
    pub fn validate(&self) -> KernelResult<()> {
        if self.status != "OPEN" {
            return Err(KernelError::InvalidField {
                field: "runtime_health.status",
                reason: "must be OPEN",
            });
        }
        let compatibility = &self.compatibility_evidence;
        if compatibility.envelope_version() != HANDSHAKE_ENVELOPE_VERSION
            || compatibility.protocol_version() == 0
            || compatibility.canonical_format_version() == 0
        {
            return Err(KernelError::InvalidField {
                field: "runtime_health.compatibility_evidence",
                reason: "contains an unsupported or zero version",
            });
        }
        if !is_lower_sha256(compatibility.contract_set_digest())
            || !is_lower_sha256(compatibility.architecture_source_digest())
            || !is_lower_sha256(compatibility.seal_tag())
            || expected_seal_tag(compatibility.architecture_source_digest())
                != compatibility.seal_tag()
        {
            return Err(KernelError::InvalidField {
                field: "runtime_health.compatibility_evidence",
                reason: "contains an invalid digest or normative seal",
            });
        }
        if compatibility.authority_epoch() != &self.authority_epoch
            || compatibility.module_generation() != self.module_generation
        {
            return Err(KernelError::InvalidField {
                field: "runtime_health.compatibility_evidence",
                reason: "does not bind the authenticated epoch and generation",
            });
        }
        if self.normative_pair_key != CURRENT_NORMATIVE_PAIR_KEY
            || compatibility.architecture_source_digest() != CURRENT_ARCHITECTURE_SOURCE_DIGEST
            || self.implementation_source_digest != CURRENT_IMPLEMENTATION_SOURCE_DIGEST
        {
            return Err(KernelError::InvalidField {
                field: "runtime_health.normative_pair",
                reason: "does not match the accepted normative pair",
            });
        }
        if self.process_health.process_id().trim().is_empty() {
            return Err(KernelError::InvalidField {
                field: "runtime_health.process_health.process_id",
                reason: "must be non-blank",
            });
        }
        if self.capability_readiness.is_empty() {
            return Err(KernelError::InvalidField {
                field: "runtime_health.capability_readiness",
                reason: "must contain an owner declaration",
            });
        }
        let mut capabilities = BTreeSet::new();
        for readiness in &self.capability_readiness {
            if readiness.capability().trim().is_empty()
                || readiness.required_dimensions().is_empty()
                || !capabilities.insert(readiness.capability())
            {
                return Err(KernelError::InvalidField {
                    field: "runtime_health.capability_readiness",
                    reason: "contains a blank, duplicate, or dimensionless capability",
                });
            }
        }
        Ok(())
    }

    /// Returns the canonical process-health projection.
    #[must_use]
    pub const fn process_health(&self) -> &ProcessHealthStatus {
        &self.process_health
    }

    /// Returns the capability declarations used for currentness.
    #[must_use]
    pub fn capability_readiness(&self) -> &[CapabilityReadiness] {
        &self.capability_readiness
    }

    /// Returns the authenticated authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the authenticated resource generation.
    #[must_use]
    pub const fn module_generation(&self) -> ResourceGeneration {
        self.module_generation
    }

    /// Returns the admitted compatibility evidence.
    #[must_use]
    pub const fn compatibility_evidence(&self) -> &AcceptedCompatibilityEvidence {
        &self.compatibility_evidence
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
