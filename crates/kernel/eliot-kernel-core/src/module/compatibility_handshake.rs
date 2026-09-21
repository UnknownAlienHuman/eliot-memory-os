//! P-07 versioned I1.12 process-handshake compatibility envelope.
//!
//! Every process handshake exchanges the full compatibility envelope: the
//! protocol range, the contract-set digest, the canonical format range, the
//! Architecture source digest plus the externally sealed
//! `NormativePairIdentity` receipt, the module generation and Authority
//! Epoch, the required and optional capabilities, and the state migration
//! class. A candidate is admitted only when every field is compatible with
//! the current durable state; rollback is admitted only when the recorded
//! compatibility evidence still matches the current durable formats and
//! epoch lineage. "Last known good" means verified compatible with current
//! state, never merely previously launched.

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{EpochId, ResourceGeneration, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};

/// Versioned envelope wire revision for the I1.12 handshake.
pub const HANDSHAKE_ENVELOPE_VERSION: u32 = 1;

/// Seal domain separating normative-pair tags from every other digest.
pub const NORMATIVE_SEAL_DOMAIN: &str = "eliot.architecture.normative-pair.v1";

/// Computes the expected externally sealed tag for an Architecture digest.
///
/// The tag binds the seal domain to the exact Architecture source digest, so
/// a receipt sealed against one source tree never verifies against another.
#[must_use]
pub fn expected_seal_tag(architecture_source_digest: &str) -> String {
    sha256_hex(format!("{NORMATIVE_SEAL_DOMAIN}:{architecture_source_digest}").as_bytes())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), KernelError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 hex digest",
        });
    }
    Ok(())
}

fn validate_capabilities(
    values: &[String],
    field: &'static str,
) -> Result<BTreeSet<String>, KernelError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(value, field)?;
        if !seen.insert(value.clone()) {
            return Err(KernelError::InvalidField {
                field,
                reason: "must not contain duplicates",
            });
        }
    }
    Ok(seen)
}

/// A closed inclusive `[min, max]` protocol or format version range.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    min: u32,
    max: u32,
}

impl VersionRange {
    /// Creates a validated inclusive range.
    ///
    /// # Errors
    ///
    /// Returns an error when `min` is zero or `min` exceeds `max`.
    pub fn new(min: u32, max: u32) -> Result<Self, KernelError> {
        if min == 0 {
            return Err(KernelError::InvalidField {
                field: "version_range.min",
                reason: "must be greater than zero",
            });
        }
        if min > max {
            return Err(KernelError::InvalidField {
                field: "version_range.max",
                reason: "must not be less than min",
            });
        }
        Ok(Self { min, max })
    }

    /// Returns the lowest admitted version.
    #[must_use]
    pub const fn min(self) -> u32 {
        self.min
    }

    /// Returns the highest admitted version.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }

    /// Returns `true` when the ranges share at least one version.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        self.min <= other.max && other.min <= self.max
    }

    /// Returns `true` when `version` lies inside the range.
    #[must_use]
    pub const fn contains(self, version: u32) -> bool {
        self.min <= version && version <= self.max
    }

    /// Returns the highest mutually supported version, if any.
    #[must_use]
    pub fn negotiate(self, other: Self) -> Option<u32> {
        if self.overlaps(other) {
            Some(self.max.min(other.max))
        } else {
            None
        }
    }
}

/// The durable state migration class carried by a handshake.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StateMigrationClass {
    /// No state migration is required.
    NoMigration,
    /// Additive migration that preserves every durable format.
    Additive,
    /// Bounded drain after which the old format is retired.
    BoundedDrain,
    /// Breaking rebase that is never compatible across generations.
    BreakingRebase,
}

/// The envelope field that refused admission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MismatchField {
    /// The envelope wire revision is not the current handshake version.
    EnvelopeVersion,
    /// The protocol ranges share no version.
    ProtocolRange,
    /// The contract-set digest differs from durable state.
    ContractSetDigest,
    /// The canonical format ranges share no version.
    CanonicalFormatRange,
    /// The Architecture source digest differs from durable state.
    ArchitectureDigest,
    /// The normative-pair seal does not verify against the source digest.
    NormativeSeal,
    /// The Authority Epoch is not the current durable epoch.
    AuthorityEpoch,
    /// A durable required capability is missing from the candidate.
    RequiredCapability,
    /// The state migration class differs from durable state.
    MigrationClass,
}

impl fmt::Display for MismatchField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::EnvelopeVersion => "envelope_version",
            Self::ProtocolRange => "protocol_range",
            Self::ContractSetDigest => "contract_set_digest",
            Self::CanonicalFormatRange => "canonical_format_range",
            Self::ArchitectureDigest => "architecture_source_digest",
            Self::NormativeSeal => "normative_pair_receipt",
            Self::AuthorityEpoch => "authority_epoch",
            Self::RequiredCapability => "required_capability",
            Self::MigrationClass => "migration_class",
        };
        formatter.write_str(label)
    }
}

/// A structured refusal naming the exact incompatible field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMismatch {
    field: MismatchField,
    reason: String,
}

impl CompatibilityMismatch {
    /// Creates a structured mismatch for `field`.
    pub fn new(field: MismatchField, reason: impl Into<String>) -> Self {
        Self {
            field,
            reason: reason.into(),
        }
    }

    /// Returns the refusing field.
    #[must_use]
    pub const fn field(&self) -> MismatchField {
        self.field
    }

    /// Returns the stable refusal reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for CompatibilityMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "compatibility mismatch at {}: {}",
            self.field, self.reason
        )
    }
}

impl std::error::Error for CompatibilityMismatch {}

/// The externally sealed `NormativePairIdentity` receipt.
///
/// The receipt binds an Architecture source digest to a seal tag issued
/// outside the Kernel. The Kernel never mints seals; it only verifies the
/// presented tag against [`expected_seal_tag`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativePairReceipt {
    architecture_source_digest: String,
    seal_tag: String,
}

impl NormativePairReceipt {
    /// Creates a well-formed receipt without verifying the seal.
    ///
    /// Seal verification happens in [`admit_handshake`] so a forged seal is
    /// reported as a structured [`MismatchField::NormativeSeal`] refusal
    /// rather than a malformed-envelope error.
    ///
    /// # Errors
    ///
    /// Returns an error when either digest is not lowercase SHA-256 hex.
    pub fn new(
        architecture_source_digest: impl Into<String>,
        seal_tag: impl Into<String>,
    ) -> Result<Self, KernelError> {
        let architecture_source_digest = architecture_source_digest.into();
        let seal_tag = seal_tag.into();
        validate_digest(
            &architecture_source_digest,
            "normative_pair_receipt.architecture_source_digest",
        )?;
        validate_digest(&seal_tag, "normative_pair_receipt.seal_tag")?;
        Ok(Self {
            architecture_source_digest,
            seal_tag,
        })
    }

    /// Returns the Architecture source digest this receipt is sealed against.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the externally issued seal tag.
    #[must_use]
    pub fn seal_tag(&self) -> &str {
        &self.seal_tag
    }

    /// Returns `true` only when the tag is the expected seal for the digest.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.seal_tag == expected_seal_tag(&self.architecture_source_digest)
    }
}

/// The full versioned I1.12 process-handshake compatibility envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEnvelope {
    envelope_version: u32,
    protocol_range: VersionRange,
    contract_set_digest: String,
    canonical_format_range: VersionRange,
    architecture_source_digest: String,
    normative_receipt: NormativePairReceipt,
    module_generation: ResourceGeneration,
    authority_epoch: EpochId,
    required_capabilities: Vec<String>,
    optional_capabilities: Vec<String>,
    migration_class: StateMigrationClass,
}

#[allow(clippy::too_many_arguments)]
impl CompatibilityEnvelope {
    /// Creates a validated handshake envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when a digest is malformed, a capability is blank or
    /// duplicated, the required and optional sets overlap, the receipt binds
    /// a different Architecture digest, or the envelope version is not
    /// [`HANDSHAKE_ENVELOPE_VERSION`].
    pub fn new(
        protocol_range: VersionRange,
        contract_set_digest: impl Into<String>,
        canonical_format_range: VersionRange,
        architecture_source_digest: impl Into<String>,
        normative_receipt: NormativePairReceipt,
        module_generation: ResourceGeneration,
        authority_epoch: EpochId,
        required_capabilities: Vec<String>,
        optional_capabilities: Vec<String>,
        migration_class: StateMigrationClass,
    ) -> Result<Self, KernelError> {
        let contract_set_digest = contract_set_digest.into();
        let architecture_source_digest = architecture_source_digest.into();
        validate_digest(
            &contract_set_digest,
            "compatibility_envelope.contract_set_digest",
        )?;
        validate_digest(
            &architecture_source_digest,
            "compatibility_envelope.architecture_source_digest",
        )?;
        if normative_receipt.architecture_source_digest() != architecture_source_digest {
            return Err(KernelError::InvalidField {
                field: "compatibility_envelope.normative_pair_receipt",
                reason: "receipt must bind the envelope architecture digest",
            });
        }
        let required = validate_capabilities(
            &required_capabilities,
            "compatibility_envelope.required_capabilities",
        )?;
        let optional = validate_capabilities(
            &optional_capabilities,
            "compatibility_envelope.optional_capabilities",
        )?;
        if required.intersection(&optional).next().is_some() {
            return Err(KernelError::InvalidField {
                field: "compatibility_envelope.optional_capabilities",
                reason: "must not repeat a required capability",
            });
        }
        Ok(Self {
            envelope_version: HANDSHAKE_ENVELOPE_VERSION,
            protocol_range,
            contract_set_digest,
            canonical_format_range,
            architecture_source_digest,
            normative_receipt,
            module_generation,
            authority_epoch,
            required_capabilities,
            optional_capabilities,
            migration_class,
        })
    }

    /// Returns the envelope wire revision.
    #[must_use]
    pub const fn envelope_version(&self) -> u32 {
        self.envelope_version
    }

    /// Returns the candidate protocol range.
    #[must_use]
    pub const fn protocol_range(&self) -> VersionRange {
        self.protocol_range
    }

    /// Returns the candidate contract-set digest.
    #[must_use]
    pub fn contract_set_digest(&self) -> &str {
        &self.contract_set_digest
    }

    /// Returns the candidate canonical format range.
    #[must_use]
    pub const fn canonical_format_range(&self) -> VersionRange {
        self.canonical_format_range
    }

    /// Returns the candidate Architecture source digest.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the sealed normative-pair receipt.
    #[must_use]
    pub const fn normative_receipt(&self) -> &NormativePairReceipt {
        &self.normative_receipt
    }

    /// Returns the candidate module generation.
    #[must_use]
    pub const fn module_generation(&self) -> ResourceGeneration {
        self.module_generation
    }

    /// Returns the candidate lineage-aware Authority Epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    /// Returns the optional capabilities.
    #[must_use]
    pub fn optional_capabilities(&self) -> &[String] {
        &self.optional_capabilities
    }

    /// Returns the state migration class.
    #[must_use]
    pub const fn migration_class(&self) -> StateMigrationClass {
        self.migration_class
    }
}

/// The current durable compatibility state a candidate must match.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCompatibilityState {
    protocol_range: VersionRange,
    contract_set_digest: String,
    canonical_format_range: VersionRange,
    architecture_source_digest: String,
    authority_epoch: EpochId,
    required_capabilities: Vec<String>,
    migration_class: StateMigrationClass,
}

impl DurableCompatibilityState {
    /// Creates the durable state new handshakes and rollbacks are gated on.
    ///
    /// # Errors
    ///
    /// Returns an error when a digest is malformed or a required capability
    /// is blank or duplicated.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_range: VersionRange,
        contract_set_digest: impl Into<String>,
        canonical_format_range: VersionRange,
        architecture_source_digest: impl Into<String>,
        authority_epoch: EpochId,
        required_capabilities: Vec<String>,
        migration_class: StateMigrationClass,
    ) -> Result<Self, KernelError> {
        let contract_set_digest = contract_set_digest.into();
        let architecture_source_digest = architecture_source_digest.into();
        validate_digest(&contract_set_digest, "durable_state.contract_set_digest")?;
        validate_digest(
            &architecture_source_digest,
            "durable_state.architecture_source_digest",
        )?;
        validate_capabilities(
            &required_capabilities,
            "durable_state.required_capabilities",
        )?;
        Ok(Self {
            protocol_range,
            contract_set_digest,
            canonical_format_range,
            architecture_source_digest,
            authority_epoch,
            required_capabilities,
            migration_class,
        })
    }

    /// Returns the durable protocol range.
    #[must_use]
    pub const fn protocol_range(&self) -> VersionRange {
        self.protocol_range
    }

    /// Returns the durable contract-set digest.
    #[must_use]
    pub fn contract_set_digest(&self) -> &str {
        &self.contract_set_digest
    }

    /// Returns the durable canonical format range.
    #[must_use]
    pub const fn canonical_format_range(&self) -> VersionRange {
        self.canonical_format_range
    }

    /// Returns the durable Architecture source digest.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the durable lineage-aware Authority Epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the durable required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    /// Returns the durable migration class.
    #[must_use]
    pub const fn migration_class(&self) -> StateMigrationClass {
        self.migration_class
    }
}

/// The persisted evidence for one accepted handshake.
///
/// The evidence records the negotiated protocol and canonical format
/// versions together with the generation and epoch lineage, so a later
/// rollback can prove it is still compatible with current durable state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCompatibilityEvidence {
    envelope_version: u32,
    protocol_version: u32,
    contract_set_digest: String,
    canonical_format_version: u32,
    architecture_source_digest: String,
    seal_tag: String,
    module_generation: ResourceGeneration,
    authority_epoch: EpochId,
    migration_class: StateMigrationClass,
}

impl AcceptedCompatibilityEvidence {
    /// Returns the envelope revision that produced this evidence.
    #[must_use]
    pub const fn envelope_version(&self) -> u32 {
        self.envelope_version
    }

    /// Returns the negotiated protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// Returns the accepted contract-set digest.
    #[must_use]
    pub fn contract_set_digest(&self) -> &str {
        &self.contract_set_digest
    }

    /// Returns the negotiated canonical format version.
    #[must_use]
    pub const fn canonical_format_version(&self) -> u32 {
        self.canonical_format_version
    }

    /// Returns the accepted Architecture source digest.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the verified seal tag.
    #[must_use]
    pub fn seal_tag(&self) -> &str {
        &self.seal_tag
    }

    /// Returns the accepted module generation.
    #[must_use]
    pub const fn module_generation(&self) -> ResourceGeneration {
        self.module_generation
    }

    /// Returns the accepted lineage-aware Authority Epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Returns the accepted migration class.
    #[must_use]
    pub const fn migration_class(&self) -> StateMigrationClass {
        self.migration_class
    }
}

/// Admits a process handshake against the current durable state.
///
/// Every I1.12 field is gated in order and the first incompatibility is
/// returned with its exact [`MismatchField`]. Overlapping protocol ranges
/// are negotiated to the highest mutual version; every other field must
/// match the durable state exactly, and the normative-pair seal must verify
/// against the Architecture source digest before the peer is accepted.
pub fn admit_handshake(
    candidate: &CompatibilityEnvelope,
    durable: &DurableCompatibilityState,
) -> Result<AcceptedCompatibilityEvidence, CompatibilityMismatch> {
    if candidate.envelope_version() != HANDSHAKE_ENVELOPE_VERSION {
        return Err(CompatibilityMismatch::new(
            MismatchField::EnvelopeVersion,
            format!(
                "envelope version {} is not the current version {HANDSHAKE_ENVELOPE_VERSION}",
                candidate.envelope_version()
            ),
        ));
    }
    let Some(protocol_version) = candidate
        .protocol_range()
        .negotiate(durable.protocol_range())
    else {
        return Err(CompatibilityMismatch::new(
            MismatchField::ProtocolRange,
            "protocol ranges share no version",
        ));
    };
    if candidate.contract_set_digest() != durable.contract_set_digest() {
        return Err(CompatibilityMismatch::new(
            MismatchField::ContractSetDigest,
            "contract-set digest differs from durable state",
        ));
    }
    let Some(canonical_format_version) = candidate
        .canonical_format_range()
        .negotiate(durable.canonical_format_range())
    else {
        return Err(CompatibilityMismatch::new(
            MismatchField::CanonicalFormatRange,
            "canonical format ranges share no version",
        ));
    };
    if candidate.architecture_source_digest() != durable.architecture_source_digest() {
        return Err(CompatibilityMismatch::new(
            MismatchField::ArchitectureDigest,
            "architecture source digest differs from durable state",
        ));
    }
    if candidate.normative_receipt().architecture_source_digest()
        != candidate.architecture_source_digest()
        || !candidate.normative_receipt().verifies()
    {
        return Err(CompatibilityMismatch::new(
            MismatchField::NormativeSeal,
            "normative-pair seal does not verify against the architecture digest",
        ));
    }
    if !candidate
        .authority_epoch()
        .is_same_authority(durable.authority_epoch())
    {
        return Err(CompatibilityMismatch::new(
            MismatchField::AuthorityEpoch,
            "authority epoch does not match the durable epoch lineage",
        ));
    }
    let offered: BTreeSet<&str> = candidate
        .required_capabilities()
        .iter()
        .chain(candidate.optional_capabilities().iter())
        .map(String::as_str)
        .collect();
    if let Some(missing) = durable
        .required_capabilities()
        .iter()
        .find(|capability| !offered.contains(capability.as_str()))
    {
        return Err(CompatibilityMismatch::new(
            MismatchField::RequiredCapability,
            format!("durable required capability '{missing}' is not offered"),
        ));
    }
    if candidate.migration_class() != durable.migration_class() {
        return Err(CompatibilityMismatch::new(
            MismatchField::MigrationClass,
            "state migration class differs from durable state",
        ));
    }
    Ok(AcceptedCompatibilityEvidence {
        envelope_version: HANDSHAKE_ENVELOPE_VERSION,
        protocol_version,
        contract_set_digest: candidate.contract_set_digest().to_owned(),
        canonical_format_version,
        architecture_source_digest: candidate.architecture_source_digest().to_owned(),
        seal_tag: candidate.normative_receipt().seal_tag().to_owned(),
        module_generation: candidate.module_generation(),
        authority_epoch: candidate.authority_epoch().clone(),
        migration_class: candidate.migration_class(),
    })
}

/// Admits a rollback only when the recorded evidence still matches durable state.
///
/// A previously launched artifact is not "last known good" on its own: its
/// recorded protocol and canonical format versions must lie inside the
/// current durable ranges, its digests, seal and migration class must match,
/// and its epoch lineage must be the durable lineage. Any drift is refused
/// with the exact mismatching field.
pub fn admit_rollback(
    evidence: &AcceptedCompatibilityEvidence,
    durable: &DurableCompatibilityState,
) -> Result<(), CompatibilityMismatch> {
    if evidence.envelope_version != HANDSHAKE_ENVELOPE_VERSION {
        return Err(CompatibilityMismatch::new(
            MismatchField::EnvelopeVersion,
            "rollback evidence predates the current envelope version",
        ));
    }
    if !durable.protocol_range().contains(evidence.protocol_version) {
        return Err(CompatibilityMismatch::new(
            MismatchField::ProtocolRange,
            "recorded protocol version is outside the durable range",
        ));
    }
    if evidence.contract_set_digest != durable.contract_set_digest() {
        return Err(CompatibilityMismatch::new(
            MismatchField::ContractSetDigest,
            "recorded contract-set digest differs from durable state",
        ));
    }
    if !durable
        .canonical_format_range()
        .contains(evidence.canonical_format_version)
    {
        return Err(CompatibilityMismatch::new(
            MismatchField::CanonicalFormatRange,
            "recorded canonical format version is outside the durable range",
        ));
    }
    if evidence.architecture_source_digest != durable.architecture_source_digest() {
        return Err(CompatibilityMismatch::new(
            MismatchField::ArchitectureDigest,
            "recorded architecture digest differs from durable state",
        ));
    }
    if evidence.seal_tag != expected_seal_tag(&evidence.architecture_source_digest) {
        return Err(CompatibilityMismatch::new(
            MismatchField::NormativeSeal,
            "recorded normative-pair seal does not verify",
        ));
    }
    if evidence.authority_epoch.lineage_id != durable.authority_epoch().lineage_id {
        return Err(CompatibilityMismatch::new(
            MismatchField::AuthorityEpoch,
            "recorded epoch lineage differs from the durable lineage",
        ));
    }
    if evidence.migration_class != durable.migration_class() {
        return Err(CompatibilityMismatch::new(
            MismatchField::MigrationClass,
            "recorded migration class differs from durable state",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::EpochLineageId;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    const CONTRACTS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ARCH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).unwrap(),
            NonZeroU64::new(sequence).unwrap(),
        )
        .unwrap()
    }

    fn receipt_for(digest: &str) -> NormativePairReceipt {
        NormativePairReceipt::new(digest, expected_seal_tag(digest)).unwrap()
    }

    fn envelope(
        canonical: VersionRange,
        receipt: NormativePairReceipt,
        authority_epoch: EpochId,
        migration_class: StateMigrationClass,
    ) -> CompatibilityEnvelope {
        CompatibilityEnvelope::new(
            VersionRange::new(1, 3).unwrap(),
            CONTRACTS,
            canonical,
            ARCH,
            receipt,
            ResourceGeneration::genesis(),
            authority_epoch,
            vec!["blob.read".to_owned()],
            vec!["blob.prefetch".to_owned()],
            migration_class,
        )
        .unwrap()
    }

    fn durable() -> DurableCompatibilityState {
        DurableCompatibilityState::new(
            VersionRange::new(2, 4).unwrap(),
            CONTRACTS,
            VersionRange::new(5, 7).unwrap(),
            ARCH,
            epoch(LINEAGE, 3),
            vec!["blob.read".to_owned()],
            StateMigrationClass::Additive,
        )
        .unwrap()
    }

    #[test]
    fn compatible_handshake_is_accepted_with_generation_and_epoch_lineage()
    -> Result<(), KernelError> {
        let candidate = envelope(
            VersionRange::new(6, 9).unwrap(),
            receipt_for(ARCH),
            epoch(LINEAGE, 3),
            StateMigrationClass::Additive,
        );
        let evidence =
            admit_handshake(&candidate, &durable()).map_err(|_| KernelError::InvalidField {
                field: "compatibility_envelope",
                reason: "compatible candidate must be admitted",
            })?;
        assert_eq!(evidence.protocol_version(), 3);
        assert_eq!(evidence.canonical_format_version(), 7);
        assert_eq!(evidence.contract_set_digest(), CONTRACTS);
        assert_eq!(evidence.architecture_source_digest(), ARCH);
        assert_eq!(evidence.module_generation(), ResourceGeneration::genesis());
        assert!(
            evidence
                .authority_epoch()
                .is_same_authority(&epoch(LINEAGE, 3))
        );
        Ok(())
    }

    #[test]
    fn overlapping_protocol_still_refuses_bad_format_seal_epoch_and_migration() {
        let base = durable();
        // Canonical-format range shares the protocol overlap but no format version.
        let mismatch = admit_handshake(
            &envelope(
                VersionRange::new(8, 9).unwrap(),
                receipt_for(ARCH),
                epoch(LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &base,
        )
        .unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::CanonicalFormatRange);

        // Forged seal with an otherwise compatible envelope.
        let forged = NormativePairReceipt::new(
            ARCH,
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        )
        .unwrap();
        let mismatch = admit_handshake(
            &envelope(
                VersionRange::new(6, 9).unwrap(),
                forged,
                epoch(LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &base,
        )
        .unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::NormativeSeal);

        // Same numeric sequence from another lineage is unrelated authority.
        let mismatch = admit_handshake(
            &envelope(
                VersionRange::new(6, 9).unwrap(),
                receipt_for(ARCH),
                epoch(OTHER_LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &base,
        )
        .unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::AuthorityEpoch);

        // Migration class drift is refused.
        let mismatch = admit_handshake(
            &envelope(
                VersionRange::new(6, 9).unwrap(),
                receipt_for(ARCH),
                epoch(LINEAGE, 3),
                StateMigrationClass::BreakingRebase,
            ),
            &base,
        )
        .unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::MigrationClass);
    }

    #[test]
    fn rollback_refuses_previously_launched_evidence_after_durable_drift() -> Result<(), KernelError>
    {
        let candidate = envelope(
            VersionRange::new(6, 9).unwrap(),
            receipt_for(ARCH),
            epoch(LINEAGE, 3),
            StateMigrationClass::Additive,
        );
        let evidence =
            admit_handshake(&candidate, &durable()).map_err(|_| KernelError::InvalidField {
                field: "compatibility_envelope",
                reason: "compatible candidate must be admitted",
            })?;
        // Still compatible: rollback admitted.
        admit_rollback(&evidence, &durable()).map_err(|_| KernelError::InvalidField {
            field: "rollback",
            reason: "matching evidence must be admitted",
        })?;
        // Durable formats moved on: the same evidence is now refused.
        let moved = DurableCompatibilityState::new(
            VersionRange::new(2, 4).unwrap(),
            CONTRACTS,
            VersionRange::new(8, 9).unwrap(),
            ARCH,
            epoch(LINEAGE, 3),
            vec!["blob.read".to_owned()],
            StateMigrationClass::Additive,
        )?;
        let mismatch = admit_rollback(&evidence, &moved).unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::CanonicalFormatRange);
        // Cross-lineage durable state refuses the same evidence.
        let relined = DurableCompatibilityState::new(
            VersionRange::new(2, 4).unwrap(),
            CONTRACTS,
            VersionRange::new(5, 7).unwrap(),
            ARCH,
            epoch(OTHER_LINEAGE, 3),
            vec!["blob.read".to_owned()],
            StateMigrationClass::Additive,
        )?;
        let mismatch = admit_rollback(&evidence, &relined).unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::AuthorityEpoch);
        Ok(())
    }
}
