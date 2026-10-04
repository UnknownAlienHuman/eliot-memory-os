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
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_runtime_contracts::{
        GenerationCutoverState, HealthDimension, HealthVector, ModuleGenerationState,
        ServiceProcessState,
    };

    use super::{
        CURRENT_ARCHITECTURE_SOURCE_DIGEST, CURRENT_IMPLEMENTATION_SOURCE_DIGEST,
        CURRENT_NORMATIVE_PAIR_KEY, KernelRuntimeHealthEvidence,
    };
    use crate::error::{KernelError, KernelResult};
    use crate::module::compatibility_handshake::{
        AcceptedCompatibilityEvidence, CompatibilityEnvelope, DurableCompatibilityState,
        HANDSHAKE_ENVELOPE_VERSION, NORMATIVE_SEAL_DOMAIN, NormativePairReceipt,
        StateMigrationClass, VersionRange, admit_handshake, expected_seal_tag,
    };
    use crate::module::process_health::{
        CapabilityReadiness, HealthDimensionKind, ProcessHealthStatus, ProcessHealthVector,
    };

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
    /// that difference on the compiled triple alone;
    /// `receipt_stamped_carrier_is_accepted_and_the_previous_pair_is_rejected`
    /// carries the same pair onto a real `KernelRuntimeHealthEvidence` and shows
    /// `validate` refusing it.
    ///
    /// `PREVIOUS_PAIR` is a HISTORICAL FIXTURE, not a second source of truth:
    /// nothing reads it except these assertions, and it is deliberately not
    /// compared against the receipt, because it is the identity the receipt
    /// replaced. It fires only on an exact reversion to the values this module
    /// used to compile.
    #[test]
    fn previously_compiled_pair_is_not_the_admitted_identity() {
        let (compiled, _) = receipt_identities(RECEIPT_TOML);
        for (previous, current) in PREVIOUS_PAIR.iter().zip(&compiled) {
            assert_ne!(
                previous, current,
                "a carrier stamped with the previously compiled pair must not match the admitted identity"
            );
        }
    }

    /// The pair this module compiled before the re-pin: the pre-#1067
    /// Architecture digest, Implementation digest and receipt pair key, in the
    /// same order as the compiled triple in `receipt_identities`.
    const PREVIOUS_PAIR: [&str; 3] = [
        "c6932eaf26935e752eefb4de591afc91ea1a7180be5a8ff0005554b8029bac1a",
        "40b0908a637f46ba6c7c51db08e008673f9232ed74d510d3a4f38489d05d4e89",
        "sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea",
    ];

    /// Lineage the handshake fixtures run in, mirroring the fixture lineage in
    /// `compatibility_handshake`'s own tests.
    const FIXTURE_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    /// Contract-set digest the fixture handshake negotiates. It never enters the
    /// normative pair, so any lowercase SHA-256 shape is a legal stand-in for the
    /// real contract-set digest; what the carrier gates on is the shape.
    const FIXTURE_CONTRACT_SET_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// The lineage-aware epoch both fixture envelopes present.
    fn fixture_epoch() -> KernelResult<EpochId> {
        let lineage =
            EpochLineageId::new(FIXTURE_LINEAGE).map_err(|_| KernelError::InvalidField {
                field: "runtime_health.fixture.lineage_id",
                reason: "must be a canonical lowercase hyphenated UUID",
            })?;
        let Some(sequence) = NonZeroU64::new(3) else {
            return Err(KernelError::InvalidField {
                field: "runtime_health.fixture.sequence",
                reason: "must be greater than zero",
            });
        };
        EpochId::new(lineage, sequence).map_err(|_| KernelError::InvalidField {
            field: "runtime_health.fixture.authority_epoch",
            reason: "must be a valid lineage-aware epoch",
        })
    }

    /// Admits one genuine handshake whose Architecture digest is
    /// `architecture_source_digest` and returns the real
    /// `AcceptedCompatibilityEvidence` the carrier consumes.
    ///
    /// The construction sequence mirrors `compatibility_handshake`'s own
    /// `mod tests` exactly, because that module is the only owner of these
    /// constructors: a `VersionRange` protocol pair that overlaps durable state
    /// (`1..=3` against `2..=4`), a canonical-format pair that also overlaps
    /// (`6..=9` against `5..=7`), one required capability the candidate offers,
    /// `Additive` migration on both sides, and a `NormativePairReceipt` sealed
    /// with `expected_seal_tag` so the seal genuinely verifies against the
    /// compiled Implementation half.
    ///
    /// Nothing fabricates the evidence's private fields: it is whatever
    /// `admit_handshake` returns after gating all nine I1.12 fields in order.
    fn admitted_evidence(
        architecture_source_digest: &str,
    ) -> KernelResult<AcceptedCompatibilityEvidence> {
        let epoch = fixture_epoch()?;
        let receipt = NormativePairReceipt::new(
            architecture_source_digest,
            expected_seal_tag(architecture_source_digest),
        )?;
        let candidate = CompatibilityEnvelope::new(
            VersionRange::new(1, 3)?,
            FIXTURE_CONTRACT_SET_DIGEST,
            VersionRange::new(6, 9)?,
            architecture_source_digest,
            receipt,
            ResourceGeneration::genesis(),
            epoch.clone(),
            vec!["blob.read".to_owned()],
            vec!["blob.prefetch".to_owned()],
            StateMigrationClass::Additive,
        )?;
        let durable = DurableCompatibilityState::new(
            VersionRange::new(2, 4)?,
            FIXTURE_CONTRACT_SET_DIGEST,
            VersionRange::new(5, 7)?,
            architecture_source_digest,
            epoch,
            vec!["blob.read".to_owned()],
            StateMigrationClass::Additive,
        )?;
        admit_handshake(&candidate, &durable).map_err(|_| KernelError::InvalidField {
            field: "runtime_health.fixture.handshake",
            reason: "a receipt-stamped candidate must be admitted",
        })
    }

    /// Wraps admitted evidence in one owner-produced carrier stamped with the
    /// supplied normative-pair identity.
    ///
    /// The epoch and generation are taken from the evidence itself, so the
    /// carrier's `runtime_health.compatibility_evidence` binding gate holds and
    /// the only thing this helper varies is the identity triple the carrier
    /// presents.
    fn stamped_carrier(
        evidence: AcceptedCompatibilityEvidence,
        normative_pair_key: &str,
        implementation_source_digest: &str,
    ) -> KernelResult<KernelRuntimeHealthEvidence> {
        let process_health = ProcessHealthStatus::new(
            "kernel-front-door",
            ServiceProcessState::Ready,
            ProcessHealthVector::new(HealthVector::healthy(), HealthDimension::Healthy),
            ModuleGenerationState::Active,
            GenerationCutoverState::Completed,
        )?;
        KernelRuntimeHealthEvidence::new(
            "OPEN",
            evidence.authority_epoch().clone(),
            evidence.module_generation(),
            evidence,
            normative_pair_key,
            implementation_source_digest,
            process_health,
            vec![CapabilityReadiness::new(
                "blob.read",
                vec![
                    HealthDimensionKind::Liveness,
                    HealthDimensionKind::Compatibility,
                ],
            )?],
            false,
        )
    }

    /// Acceptance, at the carrier level rather than the receipt-string level:
    /// a `KernelRuntimeHealthEvidence` stamped with the accepted receipt's
    /// normative pair passes `validate`, and the same carrier stamped with the
    /// pair this module compiled before the re-pin is refused by it.
    ///
    /// The two halves are mutually dependent on the compiled constants, so
    /// neither can pass by accident: with the previous constants restored, the
    /// accept half would fail the normative-pair gate and the reject half would
    /// be admitted. Both halves move real objects - the accept half is built
    /// from an `admit_handshake` result, not from a literal - so this is a
    /// statement about the carrier's behaviour, not about the constants alone.
    #[test]
    fn receipt_stamped_carrier_is_accepted_and_the_previous_pair_is_rejected() -> KernelResult<()> {
        // Accept half: the accepted receipt's own Architecture half is admitted
        // by the compatibility gate, then accepted by the carrier validator.
        let carrier = stamped_carrier(
            admitted_evidence(CURRENT_ARCHITECTURE_SOURCE_DIGEST)?,
            CURRENT_NORMATIVE_PAIR_KEY,
            CURRENT_IMPLEMENTATION_SOURCE_DIGEST,
        )?;
        // `new` already validated; revalidate so the assertion is on `validate`
        // itself, the boundary a deserialized carrier is re-checked at.
        carrier.validate()?;
        let accepted = carrier.compatibility_evidence();
        assert_eq!(accepted.envelope_version(), HANDSHAKE_ENVELOPE_VERSION);
        assert_eq!(accepted.protocol_version(), 3);
        assert_eq!(accepted.canonical_format_version(), 7);
        assert_eq!(
            accepted.architecture_source_digest(),
            CURRENT_ARCHITECTURE_SOURCE_DIGEST
        );
        assert_eq!(
            accepted.seal_tag(),
            expected_seal_tag(CURRENT_ARCHITECTURE_SOURCE_DIGEST)
        );

        // Reject half: the previously compiled Architecture half, genuinely
        // admitted through the same sequence.
        let previous = admitted_evidence(PREVIOUS_PAIR[0])?;
        // Its seal verifies, so the refusal below is the normative-pair gate and
        // not the earlier seal gate: the only wrong thing about this carrier is
        // the identity it presents.
        assert_eq!(previous.seal_tag(), expected_seal_tag(PREVIOUS_PAIR[0]));
        let Err(KernelError::InvalidField { field, reason }) =
            stamped_carrier(previous, PREVIOUS_PAIR[2], PREVIOUS_PAIR[1])
        else {
            panic!("a carrier stamped with the previously compiled pair must be refused");
        };
        assert_eq!(field, "runtime_health.normative_pair");
        assert_eq!(reason, "does not match the accepted normative pair");
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Consumer enumeration guard (issue #1067, card `MAKE` clause, second
    // sentence: "Extend that guard to enumerate every production current-pair
    // consumer ... so a new current-pair literal outside the owner fails
    // it.").
    //
    // WHAT THIS MEASURES, AND WHY IT IS NOT THE CARD'S LIST. The card
    // (`cards/1067.md:17` and the `DONE` clause at `:25`) names seven
    // consumers. Two of the seven are NOT production consumers on this tree,
    // and four production consumers the card does not name exist. Both facts
    // were measured, not assumed:
    //
    //   * `crates/meta/eliot-runtime-status/src/runtime_health_status.rs`
    //     touches the owner constants only at `:105-106`, `:131-152` and
    //     `:182-183`, every one of which is after the `#[cfg(test)]` at
    //     `:100`. It is a test fixture, not a production consumer.
    //   * `bins/eliot-native-worker/src/kernel_admission_client.rs` touches
    //     them only at `:1584` and `:1660-1661`, all after the
    //     `#[cfg(test)]` at `:1555`. Also test-only.
    //   * `crates/foundation/eliot-contracts/src/capability_cell_registry.rs`
    //     (`:59-60`), `bins/eliot-kernel/src/composition_bootstrap.rs`
    //     (`:76`) and `bins/eliot-mod-research/src/capability_cell.rs`
    //     (`:51`) are production and each restates the accepted pair key as
    //     its own literal; the card names none of them.
    //   * `crates/meta/eliot-runtime-status/src/capability_cell_readback.rs`
    //     (`:23`, `:188`) is a fourth production consumer, and a fifth thing
    //     the card does not name: it reads the RESTATED `EXPECTED_NORMATIVE_PAIR_KEY`
    //     rather than the owner, and carries no literal of its own.
    //
    // This test asserts the MEASURED set, not the card's set. Asserting the
    // card's seven would encode a known falsehood as a pass condition. The
    // divergence is stated here and in the work report rather than silently
    // reconciled, because correcting the card is not this file's to do.
    //
    // MECHANISM. Every consumer source below is embedded with `include_str!`,
    // exactly as `RECEIPT_TOML` is at the top of this module. That is a
    // deliberate choice over reading the files at test time: `include_str!`
    // resolves at COMPILE time, so a consumer file that is renamed, moved or
    // deleted breaks the build instead of silently dropping out of the
    // enumeration and turning this guard green by omission. It also keeps the
    // test hermetic - no filesystem access, no `std::fs`, no shell, and no
    // live-run dependency on the working directory.

    /// The owner of the current normative identity: this module.
    const OWNER_SOURCE: &str = include_str!("runtime_health.rs");
    /// The handshake that seals against the owner's implementation digest.
    const HANDSHAKE_SOURCE: &str = include_str!("compatibility_handshake.rs");
    /// The owner crate's public re-export of the three constants.
    const KERNEL_CORE_LIB_SOURCE: &str = include_str!("../lib.rs");
    /// Bootstrap snapshot capture.
    const BOOTSTRAP_CAPTURE_SOURCE: &str =
        include_str!("../../../../../crates/foundation/eliot-bootstrap/src/capture.rs");
    /// The receipt parser the bootstrap capture delegates to.
    const BOOTSTRAP_NORMATIVE_SOURCE: &str =
        include_str!("../../../../../crates/foundation/eliot-bootstrap/src/normative.rs");
    /// The runtime-compiler expected-pair comparison.
    const RUNTIME_COMPILER_SOURCE: &str =
        include_str!("../../../../../workspace/tools/eliot-runtime-compiler/src/lib.rs");
    /// The snapshot-draft consumer of the accepted pair.
    const BOOTSTRAP_DRAFT_SOURCE: &str =
        include_str!("../../../../../bins/eliot/src/bootstrap_draft.rs");
    /// The instrument runner, which embeds the receipt bytes themselves.
    const TESTD_REGISTRY_SOURCE: &str = include_str!(
        "../../../../../crates/instrument/eliot-instrument-runner/src/testd_registry.rs"
    );
    /// Kernel frame dispatch.
    const FRAME_DISPATCH_SOURCE: &str =
        include_str!("../../../../../bins/eliot-kernel/src/frame_dispatch.rs");
    /// Kernel generation recovery.
    const GENERATION_RECOVERY_SOURCE: &str =
        include_str!("../../../../../bins/eliot-kernel/src/generation_recovery.rs");
    /// The capability-cell registry that restates the pair key as a literal.
    const CAPABILITY_CELL_REGISTRY_SOURCE: &str = include_str!(
        "../../../../../crates/foundation/eliot-contracts/src/capability_cell_registry.rs"
    );
    /// The readback that consumes that restated constant.
    const CAPABILITY_CELL_READBACK_SOURCE: &str = include_str!(
        "../../../../../crates/meta/eliot-runtime-status/src/capability_cell_readback.rs"
    );
    /// The Kernel-composed registry projection carrying an embedded literal.
    const COMPOSITION_BOOTSTRAP_SOURCE: &str =
        include_str!("../../../../../bins/eliot-kernel/src/composition_bootstrap.rs");
    /// The research-provider registry projection carrying an embedded literal.
    const RESEARCH_CAPABILITY_CELL_SOURCE: &str =
        include_str!("../../../../../bins/eliot-mod-research/src/capability_cell.rs");
    /// Named by the card as a production consumer; measured test-only.
    const RUNTIME_HEALTH_STATUS_SOURCE: &str = include_str!(
        "../../../../../crates/meta/eliot-runtime-status/src/runtime_health_status.rs"
    );
    /// Named by the card as a production consumer; measured test-only.
    const KERNEL_ADMISSION_CLIENT_SOURCE: &str =
        include_str!("../../../../../bins/eliot-native-worker/src/kernel_admission_client.rs");

    /// The three names that make up the owner's compiled identity.
    const OWNER_CONSTANT_NAMES: [&str; 3] = [
        "CURRENT_ARCHITECTURE_SOURCE_DIGEST",
        "CURRENT_IMPLEMENTATION_SOURCE_DIGEST",
        "CURRENT_NORMATIVE_PAIR_KEY",
    ];

    /// How a production source binds the current normative identity.
    ///
    /// The first three variants are the only bindings that can survive a
    /// re-pin without an edit outside the owner. `RestatedConstant` and
    /// `RestatedLiteral` are MEASURED DEBT, not an aspiration: they are real
    /// production consumers that bind the identity somewhere other than the
    /// owner. They are enumerated explicitly so that the debt is visible and
    /// bounded, and so that a FOURTH such source - a genuinely new
    /// current-pair literal outside the owner - fails this guard instead of
    /// joining them unnoticed. `Unbound` exists so that a consumer which
    /// stops binding the current identity at all is reported as its own
    /// condition rather than being absorbed into the debt.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PairBinding {
        /// Declares the three owner constants. This module.
        OwnerDeclaration,
        /// Reads one of the three owner constants.
        OwnerConstant,
        /// Reads the accepted receipt through the bootstrap parser.
        ReceiptDerived,
        /// Reads the RESTATED `EXPECTED_NORMATIVE_PAIR_KEY`, carrying no literal.
        RestatedConstant,
        /// Carries a pair-key-shaped literal of its own.
        RestatedLiteral,
        /// Binds nothing at all: no owner constant, no receipt read, no
        /// literal. Present so that a source which stops binding the current
        /// identity is reported as such instead of being silently bucketed
        /// with the restated-constant debt.
        Unbound,
    }

    /// Returns every pair-key-shaped string literal in `source`.
    ///
    /// Shape, not value: `"sha256:` followed by exactly 64 lowercase hex
    /// digits and a closing quote. The closing quote is what makes the match
    /// precise - several files in this repository quote `sha256:<hex>` inside
    /// prose as a placeholder for "some digest", and a scan that accepted a
    /// bare `(sha256:...)` would flag those. Restricting to a quoted literal
    /// keeps the signal on real embedded values.
    fn pair_key_literals(source: &str) -> Vec<&str> {
        let bytes = source.as_bytes();
        let mut literals = Vec::new();
        // `"sha256:` is eight bytes including the opening quote.
        for (start, _) in source.match_indices("\"sha256:") {
            let hex = start + 8;
            let Some(end) = hex.checked_add(64) else {
                continue;
            };
            if end >= bytes.len() || bytes[end] != b'"' {
                continue;
            }
            let candidate = &bytes[hex..end];
            if candidate
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            {
                // Safe to slice: all 64 bytes were just checked to be ASCII.
                literals.push(&source[hex..end]);
            }
        }
        literals
    }

    /// Classifies how `source` binds the current normative identity.
    ///
    /// Pure: it takes text and returns a verdict, so it is unit-testable
    /// directly with both an owner-reading input and a literal-bearing one
    /// without a file on disk. That is what gives the negative case below its
    /// teeth.
    ///
    /// Order is load-bearing and runs worst-case-last. `OwnerDeclaration` is
    /// tested first because this module necessarily contains the literal as
    /// well as the names; `RestatedLiteral` is tested before
    /// `RestatedConstant` because a source that does both is carrying its own
    /// literal, which is the worse condition and the one a reader must see.
    fn classify_pair_binding(source: &str) -> PairBinding {
        let declares_owner = OWNER_CONSTANT_NAMES
            .iter()
            .all(|name| source.contains(&format!("pub const {name}")));
        if declares_owner {
            return PairBinding::OwnerDeclaration;
        }
        if OWNER_CONSTANT_NAMES
            .iter()
            .any(|name| source.contains(name))
        {
            return PairBinding::OwnerConstant;
        }
        if source.contains("parse_normative_pair_receipt") || source.contains("load_normative_pair")
        {
            return PairBinding::ReceiptDerived;
        }
        if !pair_key_literals(source).is_empty() {
            return PairBinding::RestatedLiteral;
        }
        if source.contains("EXPECTED_NORMATIVE_PAIR_KEY") {
            return PairBinding::RestatedConstant;
        }
        PairBinding::Unbound
    }

    /// The production sources whose owner-constant or receipt binding was
    /// measured, with the needle each one is DECLARED to carry and the branch
    /// it is DECLARED to take.
    ///
    /// This is the INDEPENDENT expectation. It is written out by hand from the
    /// measurements above and is deliberately not derived from the same scan
    /// that produces the actual result, so a change in either one has to be
    /// reconciled by a human rather than cancelling out.
    ///
    /// The middle column is a NEEDLE, not prose: the enumeration asserts that
    /// each source really contains it inside its production prefix, so
    /// renaming or dropping the declared touchpoint reddens this test instead
    /// of silently leaving the column decorative. The line references live in
    /// the comment above each row.
    const EXPECTED_PRODUCTION_CONSUMERS: [(&str, &str, PairBinding); 14] = [
        // The owner itself. `pub const CURRENT_NORMATIVE_PAIR_KEY` (:22,:25,:28).
        (
            "crates/kernel/eliot-kernel-core/src/module/runtime_health.rs",
            "CURRENT_NORMATIVE_PAIR_KEY",
            PairBinding::OwnerDeclaration,
        ),
        // Seals against the owner's implementation digest: `expected_seal_tag` (:48).
        (
            "crates/kernel/eliot-kernel-core/src/module/compatibility_handshake.rs",
            "expected_seal_tag",
            PairBinding::OwnerConstant,
        ),
        // Re-exports all three: `pub use` (:115-116).
        (
            "crates/kernel/eliot-kernel-core/src/lib.rs",
            "CURRENT_ARCHITECTURE_SOURCE_DIGEST",
            PairBinding::OwnerConstant,
        ),
        // Kernel frame dispatch: `runtime_compatibility_evidence` (:98,:471,:472).
        (
            "bins/eliot-kernel/src/frame_dispatch.rs",
            "runtime_compatibility_evidence",
            PairBinding::OwnerConstant,
        ),
        // Kernel generation recovery: `DurableCompatibilityState::new` (:187).
        (
            "bins/eliot-kernel/src/generation_recovery.rs",
            "DurableCompatibilityState",
            PairBinding::OwnerConstant,
        ),
        // Bootstrap snapshot capture: `load_normative_pair` (:144,:184,:302).
        (
            "crates/foundation/eliot-bootstrap/src/capture.rs",
            "load_normative_pair",
            PairBinding::ReceiptDerived,
        ),
        // The receipt parser itself: `parse_normative_pair_receipt` (:90,:101).
        (
            "crates/foundation/eliot-bootstrap/src/normative.rs",
            "parse_normative_pair_receipt",
            PairBinding::ReceiptDerived,
        ),
        // Runtime-compiler expected-pair comparison: `load_normative_pair` (:2,:3080).
        (
            "workspace/tools/eliot-runtime-compiler/src/lib.rs",
            "load_normative_pair",
            PairBinding::ReceiptDerived,
        ),
        // Snapshot draft: `load_normative_pair` (:16,:111).
        (
            "bins/eliot/src/bootstrap_draft.rs",
            "load_normative_pair",
            PairBinding::ReceiptDerived,
        ),
        // Instrument runner; embeds the receipt bytes: `NORMATIVE_PAIR_RECEIPT` (:32,:197,:459,:503).
        (
            "crates/instrument/eliot-instrument-runner/src/testd_registry.rs",
            "NORMATIVE_PAIR_RECEIPT",
            PairBinding::ReceiptDerived,
        ),
        // MEASURED DEBT: restates the accepted pair key as its own literal,
        // `EXPECTED_NORMATIVE_PAIR_KEY` (:59-60), consumed (:286,:291,:1148).
        (
            "crates/foundation/eliot-contracts/src/capability_cell_registry.rs",
            "EXPECTED_NORMATIVE_PAIR_KEY",
            PairBinding::RestatedLiteral,
        ),
        // MEASURED DEBT: embedded registry projection carrying `"pair_key"` (:76).
        (
            "bins/eliot-kernel/src/composition_bootstrap.rs",
            "pair_key",
            PairBinding::RestatedLiteral,
        ),
        // MEASURED DEBT: embedded registry projection carrying `"pair_key"` (:51).
        (
            "bins/eliot-mod-research/src/capability_cell.rs",
            "pair_key",
            PairBinding::RestatedLiteral,
        ),
        // MEASURED DEBT: consumes the restated constant, carries no literal (:23,:188).
        (
            "crates/meta/eliot-runtime-status/src/capability_cell_readback.rs",
            "EXPECTED_NORMATIVE_PAIR_KEY",
            PairBinding::RestatedConstant,
        ),
    ];

    /// The production sources DECLARED to bind outside the owner, by path.
    ///
    /// Kept as its own list so the debt has one place to be counted, and keyed
    /// by PATH rather than by binding kind so the closed-set property is about
    /// identity: a named file that stops carrying its declared binding, or a new
    /// file that starts carrying one, both fail. The count assertion in
    /// `every_production_current_pair_consumer_is_enumerated` uses its length,
    /// so the two lists cannot drift apart in size.
    const DECLARED_BINDINGS_OUTSIDE_OWNER: [(&str, PairBinding); 4] = [
        (
            "crates/foundation/eliot-contracts/src/capability_cell_registry.rs",
            PairBinding::RestatedLiteral,
        ),
        (
            "bins/eliot-kernel/src/composition_bootstrap.rs",
            PairBinding::RestatedLiteral,
        ),
        (
            "bins/eliot-mod-research/src/capability_cell.rs",
            PairBinding::RestatedLiteral,
        ),
        (
            "crates/meta/eliot-runtime-status/src/capability_cell_readback.rs",
            PairBinding::RestatedConstant,
        ),
    ];

    /// Returns the text before the first test module or `#[cfg(test)]` item.
    ///
    /// Used only to separate production from test text. It matches WHOLE
    /// LINES, not a bare substring: a doc comment or string literal that merely
    /// mentions `#[cfg(test)]` earlier in the file must not truncate the
    /// production prefix, or a real production consumer would be silently
    /// reclassified as test-only.
    fn production_prefix(source: &str) -> &str {
        let boundary = source
            .lines()
            .position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("mod tests")
            })
            .map_or(source.len(), |index| {
                source.lines().take(index).map(str::len).sum::<usize>() + index
            });
        &source[..boundary]
    }

    /// Enumerates every measured production current-pair consumer and checks
    /// each against its independently declared branch.
    ///
    /// Positive: the owner and every owner-reading consumer really do read the
    /// compiled owner, and each measured source lands on exactly the branch
    /// declared for it in `EXPECTED_PRODUCTION_CONSUMERS`.
    #[test]
    fn every_production_current_pair_consumer_is_enumerated() {
        let sources = [
            ("runtime_health.rs", OWNER_SOURCE),
            ("compatibility_handshake.rs", HANDSHAKE_SOURCE),
            ("eliot-kernel-core/src/lib.rs", KERNEL_CORE_LIB_SOURCE),
            ("capture.rs", BOOTSTRAP_CAPTURE_SOURCE),
            ("normative.rs", BOOTSTRAP_NORMATIVE_SOURCE),
            ("eliot-runtime-compiler/src/lib.rs", RUNTIME_COMPILER_SOURCE),
            ("bootstrap_draft.rs", BOOTSTRAP_DRAFT_SOURCE),
            ("testd_registry.rs", TESTD_REGISTRY_SOURCE),
            ("frame_dispatch.rs", FRAME_DISPATCH_SOURCE),
            ("generation_recovery.rs", GENERATION_RECOVERY_SOURCE),
            (
                "capability_cell_registry.rs",
                CAPABILITY_CELL_REGISTRY_SOURCE,
            ),
            (
                "capability_cell_readback.rs",
                CAPABILITY_CELL_READBACK_SOURCE,
            ),
            ("composition_bootstrap.rs", COMPOSITION_BOOTSTRAP_SOURCE),
            ("capability_cell.rs", RESEARCH_CAPABILITY_CELL_SOURCE),
        ];

        // The scan set and the hand-declared set must be the same size and
        // agree on identity. Without this a source could be added to one list
        // and not the other, and the enumeration would quietly stop being
        // complete.
        assert_eq!(
            sources.len(),
            EXPECTED_PRODUCTION_CONSUMERS.len(),
            "the scanned consumer set and the independently declared set must be the same size"
        );

        let mut owner_bound = 0;
        for ((file, source), (expected_file, needle, expected_binding)) in
            sources.iter().zip(&EXPECTED_PRODUCTION_CONSUMERS)
        {
            assert_eq!(
                file, expected_file,
                "the scanned consumer set and the declared set disagree on identity"
            );
            // The declared needle must really be in the PRODUCTION text. Without
            // this the middle column is prose: renaming or dropping the declared
            // touchpoint would leave the guard green while its stated
            // expectation had quietly stopped describing the code.
            assert!(
                production_prefix(source).contains(needle),
                "{file} no longer contains its declared touchpoint {needle:?} outside \
                 its test module, so this enumeration's expectation is out of date"
            );
            let actual = classify_pair_binding(source);
            assert_eq!(
                actual, *expected_binding,
                "{file} ({needle}) no longer binds the current pair the way this \
                 enumeration declares it does"
            );
            if matches!(
                actual,
                PairBinding::OwnerDeclaration
                    | PairBinding::OwnerConstant
                    | PairBinding::ReceiptDerived
            ) {
                owner_bound += 1;
            }
        }

        // Exact, not `>=`. This is the count the DONE clause turns on: the
        // number of measured consumers that bind the current identity through
        // the owner or the receipt. It fails if an owner-reading consumer
        // migrates to its own literal, and it fails if the debt list and the
        // owner-reading population stop summing to the whole enumeration.
        assert_eq!(
            owner_bound + DECLARED_BINDINGS_OUTSIDE_OWNER.len(),
            EXPECTED_PRODUCTION_CONSUMERS.len(),
            "every enumerated consumer is either owner-bound or declared debt"
        );
        assert!(
            owner_bound > 0,
            "at least one enumerated consumer must read the owner; found none"
        );
    }

    /// Fail-closed: the debt is exact, so a NEW current-pair literal outside
    /// the owner fails this guard.
    ///
    /// This is the property the card asks for - "so a new current-pair literal
    /// outside the owner fails it" - expressed as a closed set. Each measured
    /// non-owner binding must be one the enumeration already declares; a
    /// source binding outside the owner that is not in
    /// `DECLARED_BINDINGS_OUTSIDE_OWNER` is undeclared debt and fails here.
    #[test]
    fn a_current_pair_binding_outside_the_owner_must_be_declared() {
        let outside_owner: Vec<(&str, PairBinding)> = EXPECTED_PRODUCTION_CONSUMERS
            .iter()
            .filter(|(_, _, binding)| {
                *binding != PairBinding::OwnerDeclaration
                    && *binding != PairBinding::OwnerConstant
                    && *binding != PairBinding::ReceiptDerived
            })
            .map(|(file, _, binding)| (*file, *binding))
            .collect();

        assert_eq!(
            outside_owner.len(),
            DECLARED_BINDINGS_OUTSIDE_OWNER.len(),
            "every production binding outside the owner must be declared in \
             DECLARED_BINDINGS_OUTSIDE_OWNER; undeclared: {:?}",
            outside_owner
                .iter()
                .map(|(file, _)| *file)
                .collect::<Vec<_>>()
        );
        for (file, binding) in &outside_owner {
            // Matched BY PATH, not by binding kind: kind-only matching would let
            // one declared RestatedLiteral stand in for any other, so a new
            // literal owner could appear while this loop stayed green.
            assert!(
                DECLARED_BINDINGS_OUTSIDE_OWNER.contains(&(*file, *binding)),
                "{file} binds the current pair outside the owner as {binding:?}, which is not declared"
            );
        }
    }

    /// Refusal: a literal-bearing source is detected, and name matching on the
    /// owner's three constants alone would miss it.
    ///
    /// The input is built around `EXPECTED_NORMATIVE_PAIR_KEY` deliberately.
    /// That is the name a scan matching only `CURRENT_ARCHITECTURE_SOURCE_
    /// DIGEST` / `CURRENT_IMPLEMENTATION_SOURCE_DIGEST` /
    /// `CURRENT_NORMATIVE_PAIR_KEY` cannot see, and it is the exact shape of
    /// the three measured production literal owners. So this negative case
    /// proves two things at once: that the classifier returns a non-empty
    /// literal hit set for literal-bearing text, and that the owner-constant
    /// name check does not fire on it - which is what makes the literal check
    /// load-bearing rather than redundant.
    ///
    /// The positive half is the mirror: the same classifier must accept a
    /// source that reads the owner, so the negative half cannot pass merely
    /// because the classifier rejects everything.
    #[test]
    fn a_restated_pair_literal_is_detected_where_owner_name_matching_misses_it() {
        const LITERAL_BEARING: &str = r#"
            pub const EXPECTED_NORMATIVE_PAIR_KEY: &str =
                "sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1";
        "#;
        const OWNER_READING: &str = r"
            let pair_key = eliot_kernel_core::CURRENT_NORMATIVE_PAIR_KEY;
        ";

        // The literal is really there, and it is the ACCEPTED value, so this
        // is not a miss caused by a stale fixture. `pair_key_literals` returns
        // the 64 hex digits without the `sha256:` prefix it matched on, hence
        // the strip; comparing against the owner's own constant is what ties
        // the detected literal to the current identity rather than to some
        // arbitrary well-formed digest.
        const PAIR_KEY_PREFIX: &str = "sha256:";

        // The prefix is asserted rather than unwrapped, so the slice below cannot
        // panic and the constant's own shape is part of what the test states.
        assert!(
            CURRENT_NORMATIVE_PAIR_KEY.starts_with(PAIR_KEY_PREFIX),
            "the owner pair key carries the sha256: prefix"
        );
        let accepted_hex = &CURRENT_NORMATIVE_PAIR_KEY[PAIR_KEY_PREFIX.len()..];
        assert_eq!(
            pair_key_literals(LITERAL_BEARING),
            vec![accepted_hex],
            "a quoted pair-key literal must be found in literal-bearing text"
        );

        // The owner-constant name check does NOT fire here. This is the
        // assertion that gives the literal check its necessity.
        assert!(
            !OWNER_CONSTANT_NAMES
                .iter()
                .any(|name| LITERAL_BEARING.contains(name)),
            "the negative fixture must not mention an owner constant, or it \
             would prove nothing about literal detection"
        );
        assert_eq!(
            classify_pair_binding(LITERAL_BEARING),
            PairBinding::RestatedLiteral,
            "a source carrying its own pair-key literal must classify as RestatedLiteral"
        );
        assert!(
            pair_key_literals(OWNER_READING).is_empty(),
            "a source that reads the owner carries no literal of its own"
        );
        assert_eq!(
            classify_pair_binding(OWNER_READING),
            PairBinding::OwnerConstant,
            "a source reading the owner constant must classify as OwnerConstant"
        );
    }

    /// Pins the measured contradiction with the card's list.
    ///
    /// `cards/1067.md:17` names `runtime_health_status` and
    /// `kernel_admission_client` as production consumers. Both are measured
    /// test-only: every reference to an owner constant in either file sits
    /// after its `#[cfg(test)]`. Asserting that here means the enumeration
    /// cannot quietly start counting them as production, and it records in
    /// code why this guard's expected set differs from the card's.
    #[test]
    fn the_card_named_runtime_health_consumers_are_test_only() {
        for (file, source) in [
            (
                "crates/meta/eliot-runtime-status/src/runtime_health_status.rs",
                RUNTIME_HEALTH_STATUS_SOURCE,
            ),
            (
                "bins/eliot-native-worker/src/kernel_admission_client.rs",
                KERNEL_ADMISSION_CLIENT_SOURCE,
            ),
        ] {
            assert!(
                source.contains("CURRENT_NORMATIVE_PAIR_KEY"),
                "{file} must still reference an owner constant for this \
                 boundary to mean anything"
            );
            assert!(
                production_prefix(source).contains("CURRENT_NORMATIVE_PAIR_KEY"),
                "{file} reads the owner constant outside its test module, so it \
                 is a production consumer after all and this enumeration's \
                 expected set is out of date"
            );
        }
    }
}
