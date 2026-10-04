//! Canonical authenticated runtime-health carrier for I1.10/I1.12.
//!
//! The carrier keeps compatibility evidence, process health, capability
//! currency, and the two lifecycle machines in one typed wire projection.
//! Producers must supply the evidence from their owning runtime state; this
//! module validates the projection and never derives authority from `status`.

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

/// Architecture digest from the accepted normative-pair receipt.
pub const CURRENT_ARCHITECTURE_SOURCE_DIGEST: &str =
    "a3c5b2028d9df89a53cd565f8ff493484be74078e4efd7b534c0f1c3169577c7";
/// Implementation digest from the accepted normative-pair receipt.
pub const CURRENT_IMPLEMENTATION_SOURCE_DIGEST: &str =
    "ead4ceff2db254e4202c8fa7ae167225a6f65b720c222075ada61fc45fc407a4";
/// Pair identity from `docs/normative-pair.toml`.
pub const CURRENT_NORMATIVE_PAIR_KEY: &str =
    "sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1";

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

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_ARCHITECTURE_SOURCE_DIGEST, CURRENT_IMPLEMENTATION_SOURCE_DIGEST,
        CURRENT_NORMATIVE_PAIR_KEY,
    };
    use crate::module::compatibility_handshake::NORMATIVE_SEAL_DOMAIN;

    /// The accepted external receipt, embedded at compile time.
    ///
    /// `docs/normative-pair.toml` is the single authority for this module's
    /// current normative identity, so the guard reads the receipt's own bytes
    /// instead of trusting another compiled constant as a proxy for it. Five
    /// hops from `src/module/`; the four-hop form borrowed from `eliot-bootstrap`
    /// resolves to `crates/docs/` and does not exist.
    const RECEIPT_TOML: &str = include_str!("../../../../../docs/normative-pair.toml");

    /// Returns the value of exactly one `key = "value"` assignment line.
    ///
    /// Matching on the key alone is load-bearing. A naive `contains` is
    /// ambiguous in this file: `pair_key_algorithm` (:10) and `pair_key_input`
    /// (:11) both precede `pair_key` (:12), so a first-hit scan returns the
    /// algorithm name and the guard would redden for a reason that looks like
    /// drift; `supersedes_architecture_sha256` (:28) and
    /// `supersedes_implementation_sha256` (:29) embed the target keys as
    /// suffixes. Splitting on the first `=` and comparing the trimmed key side
    /// keeps that discrimination without pinning the spacing around `=`, so a
    /// receipt reformatted to `key="value"` still parses instead of failing as
    /// if the key had been renamed. Exactly one match is required: zero means
    /// the key was renamed, more than one means the receipt grew an ambiguous
    /// spelling, and both are drift rather than a value to pick from.
    ///
    /// A trailing `#` comment is stripped before the quotes are trimmed, since
    /// none of the receipt's values may legitimately contain one.
    fn receipt_value(receipt: &str, key: &str) -> String {
        let values: Vec<&str> = receipt
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then_some(value)
            })
            .collect();
        assert_eq!(
            values.len(),
            1,
            "docs/normative-pair.toml must hold exactly one `{key}` assignment, found {}",
            values.len()
        );
        let assigned = values[0];
        let uncommented = assigned.split_once('#').map_or(assigned, |(head, _)| head);
        uncommented.trim().trim_matches('"').to_owned()
    }

    /// Returns this module's compiled triple beside the receipt's triple.
    fn receipt_identities(receipt: &str) -> ([String; 3], [String; 3]) {
        let compiled = [
            CURRENT_ARCHITECTURE_SOURCE_DIGEST.to_owned(),
            CURRENT_IMPLEMENTATION_SOURCE_DIGEST.to_owned(),
            CURRENT_NORMATIVE_PAIR_KEY.to_owned(),
        ];
        let accepted = [
            receipt_value(receipt, "architecture_sha256"),
            receipt_value(receipt, "implementation_sha256"),
            receipt_value(receipt, "pair_key"),
        ];
        (compiled, accepted)
    }

    /// Recomputes the pair key from the compiled digests under the handshake's
    /// domain-separated, NUL-terminated rule, which the receipt must agree with.
    ///
    /// The rule itself lives in the handshake module, not in the receipt: the
    /// receipt only records its `pair_key_algorithm` and `pair_key_input`
    /// vocabulary. Reusing the handshake's domain tag keeps the two derivations
    /// from being able to diverge.
    ///
    /// The `sha256:` prefix is required: `sha256_hex` returns 64 bare hex
    /// characters while the receipt stores `"sha256:ab2011bd..."`. Without it
    /// the comparison could never succeed, and it would fail in exactly the
    /// "looks like drift" shape this guard exists to catch. The domain tag is
    /// reused from the handshake rather than re-hardcoded.
    fn compiled_pair_key() -> String {
        format!(
            "sha256:{}",
            eliot_contracts::sha256_hex(
                format!(
                    "{NORMATIVE_SEAL_DOMAIN}\0{CURRENT_ARCHITECTURE_SOURCE_DIGEST}\0{CURRENT_IMPLEMENTATION_SOURCE_DIGEST}\0"
                )
                .as_bytes()
            )
        )
    }

    /// Positive: the re-pinned constants are the accepted receipt, as one
    /// atomic triple, and the receipt's key is their derivation.
    #[test]
    fn compiled_normative_pair_equals_the_accepted_receipt() {
        let (compiled, accepted) = receipt_identities(RECEIPT_TOML);
        assert_eq!(
            compiled, accepted,
            "the compiled normative pair must equal the accepted receipt, all three fields at once"
        );
        // Recomputing from the compiled pair is not sufficient on its own: the
        // previously compiled digests are internally self-consistent, so this
        // half only bites because it is compared against the receipt's key.
        assert_eq!(
            compiled_pair_key(),
            accepted[2],
            "the accepted pair key must be the derivation of the compiled digests"
        );
    }

    /// Refusal: one altered field in the receipt fails the guard closed.
    ///
    /// The mutation is applied to an in-memory copy of the embedded receipt
    /// text, never to `docs/normative-pair.toml`, so the guard is exercised
    /// without a second owner of the constant and without an on-disk edit.
    ///
    /// What this proves is narrow and is stated as such: the extraction and the
    /// triple comparison are not vacuous, because a single-field disagreement
    /// between the receipt and the compiled constants is detected. It does not
    /// claim that production rejects anything: the compiled constants and the
    /// on-disk receipt are both untouched here, and the only thing that fails is
    /// this mutated copy.
    #[test]
    fn altered_receipt_digest_is_refused_by_the_compiled_identity() {
        let altered = RECEIPT_TOML.replacen(
            "a3c5b2028d9df89a53cd565f8ff493484be74078e4efd7b534c0f1c3169577c7",
            "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a",
            1,
        );
        assert_ne!(
            altered, RECEIPT_TOML,
            "the mutated in-memory receipt must differ from the embedded bytes"
        );
        let (compiled, accepted) = receipt_identities(&altered);
        assert_ne!(
            compiled, accepted,
            "one altered receipt digest must fail the compiled identity"
        );
        // The compiled constants still match the REAL receipt, so the only thing
        // that moved above is the in-memory copy. Comparing `compiled[0]` with
        // `CURRENT_ARCHITECTURE_SOURCE_DIGEST` would be tautological: `compiled`
        // is built from that constant at the array literal, so it can never fail.
        assert_eq!(
            compiled,
            receipt_identities(RECEIPT_TOML).1,
            "only the in-memory receipt copy may differ from the compiled identity"
        );
        assert_eq!(
            accepted[0],
            "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a"
        );
        // The untouched half still matches, which is what makes this a
        // single-field disagreement rather than a wholesale rewrite.
        assert_eq!(compiled[1], accepted[1]);
    }

    /// Refusal: the triple this module compiled before the re-pin is no longer
    /// the identity it admits.
    ///
    /// `validate` compares the carrier's pair key, the compatibility evidence's
    /// architecture digest and the carrier's implementation digest against these
    /// three constants with `!=`, so a carrier stamped with the previously
    /// compiled pair is refused exactly when it differs from them. This asserts
    /// that difference, and nothing more: it does NOT construct a
    /// `KernelRuntimeHealthEvidence`, because `AcceptedCompatibilityEvidence`
    /// has private fields, no constructor and no test-only builder in this
    /// crate - a valid carrier needs `admit_handshake` over a full
    /// `CompatibilityEnvelope`, `DurableCompatibilityState` and a verifying
    /// `NormativePairIdentity`, none of which this module owns. Asserting the
    /// carrier itself is therefore out of reach here, and claiming it would be
    /// the overstatement this test avoids.
    ///
    /// `PREVIOUS` is a HISTORICAL FIXTURE, not a second source of truth: nothing
    /// reads it except this assertion, and it is deliberately not compared
    /// against the receipt, because it is the identity the receipt replaced. It
    /// fires only on an exact reversion to the values this module used to
    /// compile.
    #[test]
    fn previously_compiled_pair_is_not_the_admitted_identity() {
        const PREVIOUS: [&str; 3] = [
            "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a",
            "40b0908a637f46ba6c7c51db08e008673f9232ed74d510d3a4f38489d05d4e89",
            "sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea",
        ];
        let (compiled, _) = receipt_identities(RECEIPT_TOML);
        for (previous, current) in PREVIOUS.iter().zip(&compiled) {
            assert_ne!(
                previous, current,
                "a carrier stamped with the previously compiled pair must not match the admitted identity"
            );
        }
    }
}
