//! Canonical authenticated runtime-health carrier for I1.10/I1.12.
//!
//! The carrier keeps compatibility evidence, process health, capability
//! currency, and the two lifecycle machines in one typed wire projection.
//! Producers must supply the evidence from their owning runtime state; this
//! module validates the projection and never derives authority from `status`.
//!
//! "Authenticated" here refers to the session that carried the carrier, not to
//! the normative-pair seal inside it: the seal is a published, unkeyed
//! recomputation whose operands travel in the carrier, and no issuer stands
//! behind it. Because [`KernelRuntimeHealthEvidence::validate`] pins one of those
//! operands to a receiver-held constant, the re-derivation there is a real
//! constraint on the carrier's tag rather than a restatement of it — it is still
//! not evidence of who the producer is. See
//! `super::compatibility_handshake::expected_seal_tag`.

use std::collections::BTreeSet;

use eliot_contracts::{EpochId, ResourceGeneration};
use eliot_runtime_contracts::HealthDimension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::compatibility_handshake::{
    AcceptedCompatibilityEvidence, HANDSHAKE_ENVELOPE_VERSION, expected_seal_tag,
};
use super::process_health::{CapabilityHealth, CapabilityReadiness, ProcessHealthStatus};
use crate::error::{KernelError, KernelResult};

/// Compiled Architecture digest, intended to equal `architecture_sha256` in
/// `docs/normative-pair.toml`.
///
/// It currently does NOT: the receipt declares
/// `a3c5b2028d9df89a53cd565f8ff493484be74078e4efd7b534c0f1c3169577c7` under the
/// sharded `eliot-normative-pair-v2-sharded` layout. This constant is not a
/// drift-free statement of the accepted receipt and must not be read as one.
/// Owned by issue #1067, whose acceptance item 3 is the test that reads the
/// receipt and fails if any compiled pair constant disagrees; that acceptance
/// text is itself stale against the sharded receipt, because it still names the
/// pre-shard pair. The constant is left exactly as compiled: correcting it is a
/// behaviour change this lane must not make. The stale Architecture digest also
/// appears in `workstreams/core-daemons/capability-cell-registry.contract.toml`.
pub const CURRENT_ARCHITECTURE_SOURCE_DIGEST: &str =
    "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a";
/// Compiled Implementation digest, intended to equal `implementation_sha256` in
/// `docs/normative-pair.toml`.
///
/// It currently does NOT: the receipt declares
/// `ead4ceff2db254e4202c8fa7ae167225a6f65b720c222075ada61fc45fc407a4`. Same
/// owner, same stale acceptance, and the same prohibition on correcting it here;
/// see [`CURRENT_ARCHITECTURE_SOURCE_DIGEST`]. This file is the only place the
/// stale Implementation digest appears in the repository.
pub const CURRENT_IMPLEMENTATION_SOURCE_DIGEST: &str =
    "40b0908a637f46ba6c7c51db08e008673f9232ed74d510d3a4f38489d05d4e89";
/// Compiled pair key, intended to equal `pair_key` in `docs/normative-pair.toml`.
///
/// It currently does NOT: the receipt declares
/// `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`.
/// Owned by issue #1067 as above. The stale key additionally appears in
/// `scripts/verify-core-daemon-inventory.py`,
/// `workstreams/core-daemons/inventory.json`,
/// `docs/migration/1860-migration-inventory.md`,
/// `crates/smart/cognitive-rev12-contract-schema-freeze.toml` and
/// `crates/smart/cognitive-wave-10.toml`, which are all outside this lane and
/// are reported, not fixed, here.
pub const CURRENT_NORMATIVE_PAIR_KEY: &str =
    "sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea";

/// Authenticated Kernel health evidence consumed by Host and native-worker.
///
/// The transport `status` is deliberately retained beside, rather than used
/// in place of, the canonical projections. `doctor_repair_advertised` is an
/// orthogonal observation and carries no readiness authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
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
    /// Exact normative-pair identity the producer stamped on the carrier.
    ///
    /// The word "external" is the receipt's, not a guarantee about this value:
    /// the producer supplies it and [`KernelRuntimeHealthEvidence::validate`]
    /// compares it against the compiled [`CURRENT_NORMATIVE_PAIR_KEY`], so it is
    /// checked, not trusted.
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
    ///
    /// The normative-pair seal is re-derived here from the carrier's own
    /// architecture digest and its own tag. Both fields travel in the producer's
    /// message, so the re-derivation on its own establishes only that the
    /// message is internally consistent; it cannot say who the producer is.
    ///
    /// It is not redundant in this function, and a former comment here calling
    /// it redundant would have licensed deleting a live check. The comparison
    /// further down against [`CURRENT_ARCHITECTURE_SOURCE_DIGEST`],
    /// [`CURRENT_NORMATIVE_PAIR_KEY`] and
    /// [`CURRENT_IMPLEMENTATION_SOURCE_DIGEST`] FORCES this carrier's
    /// architecture digest to a value the producer cannot choose, so the producer
    /// cannot choose the input to the re-derivation either. That makes the
    /// re-derivation the SOLE check on `seal_tag` in this whole function: a
    /// carrier with the correct Architecture digest, the correct pair key and the
    /// correct implementation digest, but `seal_tag = "c"*64`, is refused here
    /// and nowhere else. It is kept for exactly that reason, and it is strictly
    /// load-bearing rather than a second independent gate.
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
        // The seal re-derivation below reads the carrier's own tag and the
        // carrier's own architecture digest, so it looks like a pair the producer
        // chose on both sides. It is not symmetric with the constant comparison
        // further down: that comparison forces this digest to the receiver's
        // CURRENT_ARCHITECTURE_SOURCE_DIGEST, which makes the re-derivation the
        // only check in this function on the tag itself.
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

    /// Publishes every declared capability's own capability-scoped health
    /// result against this carrier's process observation.
    ///
    /// I1.10 requires that a component be `READY` only for the capabilities
    /// whose required dimensions pass. Each result is computed from that
    /// capability's declared dimensions and their independently observed
    /// values, so the readiness decision consults the real per-capability
    /// dimension results; a capability whose freshness is not healthy is
    /// published as not current with its failing dimension named, rather than
    /// silently advertising a current capability.
    #[must_use]
    pub fn capability_health(&self) -> Vec<CapabilityHealth> {
        self.capability_readiness
            .iter()
            .map(|readiness| self.process_health.capability_health(readiness))
            .collect()
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

/// Projects the I1.10 supervision-coverage dimension from an independently
/// verified Watchdog branch outcome.
///
/// The argument must be the outcome of the five-part Watchdog branch
/// verification (signed active lease, validity window, exact
/// fence/epoch/incarnation join): a verified branch is `Healthy`, and
/// anything else stays `Unknown`, so a supervised claim is never projected
/// from lease continuity or a heartbeat alone. The projected value feeds the
/// process health vector as an input to capability readiness; readiness is
/// decided from the per-capability dimension results, never inferred from
/// transport `status`.
#[must_use]
pub const fn runtime_supervision_coverage(branch_verified: bool) -> HealthDimension {
    if branch_verified {
        HealthDimension::Healthy
    } else {
        HealthDimension::Unknown
    }
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
