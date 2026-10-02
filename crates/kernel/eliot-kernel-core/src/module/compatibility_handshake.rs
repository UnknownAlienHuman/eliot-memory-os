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
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};

/// Versioned envelope wire revision for the I1.12 handshake.
pub const HANDSHAKE_ENVELOPE_VERSION: u32 = 1;

/// Seal domain from the accepted external normative-pair receipt
/// (`docs/normative-pair.toml`, `pair_key_algorithm =
/// "sha256-domain-separated-v1"`).
pub const NORMATIVE_SEAL_DOMAIN: &str = "eliot-normative-pair-v1";

/// Computes the externally sealed pair tag expected for an Architecture digest.
///
/// The tag is the `NormativePairIdentity` pair key of the accepted external
/// receipt: SHA-256 over the seal domain and the lowercase Architecture and
/// Implementation digests, separated and terminated by NUL bytes
/// (`docs/normative-pair.toml`, `pair_key_input`; I0.14). The Implementation
/// half is the accepted receipt value owned by [`super::runtime_health`],
/// never a peer-supplied string, so a receipt sealed against one normative
/// pair never verifies as another. The Kernel never mints seals; it only
/// verifies a presented tag against this function and the operation's durable
/// state.
#[must_use]
pub fn expected_seal_tag(architecture_source_digest: &str) -> String {
    sha256_hex(
        format!(
            "{NORMATIVE_SEAL_DOMAIN}\0{architecture_source_digest}\0{}\0",
            super::runtime_health::CURRENT_IMPLEMENTATION_SOURCE_DIGEST
        )
        .as_bytes(),
    )
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
/// The receipt binds an Architecture source digest to the external pair-key
/// seal tag issued with the accepted normative pair outside the Kernel. The
/// Kernel never mints seals; it only verifies the presented tag against
/// [`expected_seal_tag`].
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

    /// Returns `true` only when the tag is the external pair key sealing
    /// this digest under the accepted normative pair.
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

/// The I1.12 verdict that travels WITH one candidate generation, plus the
/// structured refusal when admission was refused (I1.12; I14.14 step 2,
/// "validate protocol/dependency/license/state-class compatibility").
///
/// Both outcomes carry the SAME durable record shape. An admitted candidate
/// keeps every negotiated field and no refusal; a refused one keeps every
/// offered field and adds the exact [`CompatibilityMismatch`]. The record is
/// therefore never replaced by its own refusal, so the versioned-artifact
/// registry reads one evidence shape and can derive a durable degraded
/// condition from a refused row alone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateActivation {
    evidence: eliot_ors::CompatibilityEvidence,
    refusal: Option<CompatibilityMismatch>,
}

impl CandidateActivation {
    /// Returns the durable verdict that travels with the candidate generation.
    #[must_use]
    pub const fn evidence(&self) -> &eliot_ors::CompatibilityEvidence {
        &self.evidence
    }

    /// Returns the exact structured refusal, when admission was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<&CompatibilityMismatch> {
        self.refusal.as_ref()
    }

    /// Fails closed unless this candidate was admitted.
    ///
    /// This is the gate every process boundary and every candidate activation
    /// consults before the peer is accepted or the route is switched: an
    /// incompatible artifact is refused with the mismatching field named, and
    /// the evidence that carried the refusal is already durable.
    ///
    /// # Errors
    ///
    /// Returns the exact [`CompatibilityMismatch`] naming the incompatible
    /// I1.12 field.
    pub fn require_admitted(
        &self,
    ) -> Result<&eliot_ors::CompatibilityEvidence, &CompatibilityMismatch> {
        match &self.refusal {
            Some(mismatch) => Err(mismatch),
            None => Ok(&self.evidence),
        }
    }
}

/// Evaluates one candidate generation for activation and returns the verdict
/// that travels WITH it.
///
/// This is the single producer of the persisted I1.12 evidence a later
/// rollback re-verifies: the record is built from the candidate's own offered
/// fields, so a refused candidate retains its evidence durably instead of
/// having it replaced by the refusal.
///
/// The two `admitted_*` versions are recorded only for an admitted candidate.
/// ORS requires them to be recorded together or not at all, and a refused
/// candidate never completed the whole negotiation, so neither is claimed.
///
/// `observed_at_ms` is the CALLER's observation clock: the decision itself
/// reads no clock, so the same candidate against the same durable state always
/// produces the same verdict and the only wall-clock input is the value the
/// caller already holds.
///
/// # Errors
///
/// Returns a [`KernelError`] only when the candidate's own offered fields
/// cannot be projected onto the durable record shape. An incompatible
/// candidate is NOT an error here: it is an admitted-to-the-record refusal
/// carrying its structured reason.
pub fn admit_candidate_activation(
    candidate: &CompatibilityEnvelope,
    durable: &DurableCompatibilityState,
    observed_at_ms: i64,
) -> Result<CandidateActivation, KernelError> {
    let admitted = admit_handshake(candidate, durable);
    let refusal_record = match admitted.as_ref().err() {
        Some(mismatch) => Some(eliot_ors::CompatibilityRefusal::new(
            mismatch.field().to_string(),
            mismatch.reason(),
            observed_at_ms,
        )?),
        None => None,
    };
    let protocol_range = candidate.protocol_range();
    let canonical_format_range = candidate.canonical_format_range();
    let (admitted_protocol_version, admitted_canonical_format_version) = match &admitted {
        Ok(evidence) => (
            Some(evidence.protocol_version()),
            Some(evidence.canonical_format_version()),
        ),
        Err(_) => (None, None),
    };
    let evidence = eliot_ors::CompatibilityEvidence::new(
        candidate.envelope_version(),
        protocol_range.min(),
        protocol_range.max(),
        candidate.contract_set_digest(),
        canonical_format_range.min(),
        canonical_format_range.max(),
        candidate.architecture_source_digest(),
        candidate.normative_receipt().seal_tag(),
        candidate.module_generation().value(),
        candidate.authority_epoch().lineage_id.to_string(),
        candidate.authority_epoch().sequence.get(),
        candidate.required_capabilities().to_vec(),
        candidate.optional_capabilities().to_vec(),
        recorded_class_text(candidate.migration_class())?,
        admitted_protocol_version,
        admitted_canonical_format_version,
        refusal_record,
    )?;
    Ok(CandidateActivation {
        evidence,
        refusal: admitted.err(),
    })
}

/// The recorded spelling of one state migration class.
///
/// It is the class's own serialized name, so the text ORS stores and the text
/// [`recorded_migration_class`] reads back are the same value by construction
/// instead of by a second hand-maintained list of spellings.
fn recorded_class_text(class: StateMigrationClass) -> Result<String, KernelError> {
    serde_json::to_value(class)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(KernelError::InvalidField {
            field: "compatibility_envelope.migration_class",
            reason: "must project to its recorded spelling",
        })
}

/// Restores the recorded evidence a durable Generation Registry row carries.
///
/// Issue #1890 persists the whole handshake outcome with the candidate
/// generation, so a later rollback has something to re-verify instead of a
/// remembered "it launched once". This is the one way a persisted verdict
/// becomes an [`AcceptedCompatibilityEvidence`] again.
///
/// It reconstructs, it does not decide: every compatibility question is still
/// answered by [`admit_rollback`] against the caller's current
/// [`DurableCompatibilityState`]. A row ORS could not have written - a
/// malformed digest, a non-canonical lineage, a version outside its own
/// offered range - is refused here as [`MismatchField::EnvelopeVersion`],
/// meaning the stored record cannot be read as evidence at the current
/// envelope revision, rather than being repaired into a verdict.
///
/// # Errors
///
/// Returns a [`CompatibilityMismatch`] when the stored record cannot be
/// projected onto the current evidence shape.
pub fn restore_recorded_evidence(
    recorded: &eliot_ors::CompatibilityEvidence,
) -> Result<AcceptedCompatibilityEvidence, CompatibilityMismatch> {
    recorded.validate().map_err(|error| {
        CompatibilityMismatch::new(MismatchField::EnvelopeVersion, error.to_string())
    })?;
    let module_generation =
        ResourceGeneration::new(recorded.module_generation()).map_err(|error| {
            CompatibilityMismatch::new(MismatchField::EnvelopeVersion, error.to_string())
        })?;
    let lineage_id = EpochLineageId::new(recorded.authority_lineage_id()).map_err(|error| {
        CompatibilityMismatch::new(MismatchField::AuthorityEpoch, error.to_string())
    })?;
    let Some(sequence) = NonZeroU64::new(recorded.authority_sequence()) else {
        return Err(CompatibilityMismatch::new(
            MismatchField::AuthorityEpoch,
            "recorded authority epoch sequence is zero",
        ));
    };
    let authority_epoch = EpochId::new(lineage_id, sequence).map_err(|error| {
        CompatibilityMismatch::new(MismatchField::AuthorityEpoch, error.to_string())
    })?;
    Ok(AcceptedCompatibilityEvidence {
        envelope_version: recorded.envelope_version(),
        protocol_version: recorded.admitted_protocol_version().ok_or_else(|| {
            CompatibilityMismatch::new(
                MismatchField::ProtocolRange,
                "recorded evidence never reached protocol negotiation",
            )
        })?,
        contract_set_digest: recorded.contract_set_digest().to_owned(),
        canonical_format_version: recorded.admitted_canonical_format_version().ok_or_else(
            || {
                CompatibilityMismatch::new(
                    MismatchField::CanonicalFormatRange,
                    "recorded evidence never reached canonical-format negotiation",
                )
            },
        )?,
        architecture_source_digest: recorded.architecture_source_digest().to_owned(),
        seal_tag: recorded.normative_seal_tag().to_owned(),
        module_generation,
        authority_epoch,
        migration_class: recorded_migration_class(recorded.migration_class())?,
    })
}

/// Projects the recorded migration-class spelling back onto its closed
/// vocabulary. The stored value is text so ORS carries no Kernel vocabulary of
/// its own; an unrecognised spelling is a refusal, never a default.
fn recorded_migration_class(value: &str) -> Result<StateMigrationClass, CompatibilityMismatch> {
    let unknown = || {
        CompatibilityMismatch::new(
            MismatchField::MigrationClass,
            format!("recorded migration class {value:?} is not a current handshake class"),
        )
    };
    match value {
        "NO_MIGRATION" => Ok(StateMigrationClass::NoMigration),
        "ADDITIVE" => Ok(StateMigrationClass::Additive),
        "BOUNDED_DRAIN" => Ok(StateMigrationClass::BoundedDrain),
        "BREAKING_REBASE" => Ok(StateMigrationClass::BreakingRebase),
        _ => Err(unknown()),
    }
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

    /// I1.12 acceptance: a candidate whose protocol range overlaps but whose
    /// canonical-format range is incompatible is refused before activation,
    /// with the mismatching field reported - and the refusal is carried by the
    /// SAME durable record that carries the generation and epoch lineage, so a
    /// later rollback re-verifies that verdict instead of "it launched once".
    #[test]
    fn refused_candidate_activation_keeps_evidence_and_names_the_field()
    -> Result<(), KernelError> {
        let activation = admit_candidate_activation(
            &envelope(
                VersionRange::new(8, 9).unwrap(),
                receipt_for(ARCH),
                epoch(LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &durable(),
            1_700_000_000_000,
        )?;
        let mismatch = activation.require_admitted().unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::CanonicalFormatRange);
        let evidence = activation.evidence();
        // The protocol range DID overlap, and the refusal names the field that
        // did not: the protocol version is claimed only on a full admission.
        assert_eq!(evidence.protocol_range(), (1, 3));
        assert_eq!(evidence.canonical_format_range(), (8, 9));
        assert_eq!(evidence.admitted_protocol_version(), None);
        let refusal = evidence.refusal().expect("the refusal is durable");
        assert_eq!(refusal.field(), "canonical_format_range");
        // Generation and epoch lineage survive the refusal.
        assert_eq!(evidence.module_generation(), ResourceGeneration::genesis());
        assert_eq!(evidence.authority_lineage_id(), LINEAGE);
        assert_eq!(evidence.authority_sequence(), 3);
        // An admitted candidate keeps the same record with no refusal, and the
        // recorded migration class projects back onto the handshake vocabulary.
        let admitted = admit_candidate_activation(
            &envelope(
                VersionRange::new(6, 9).unwrap(),
                receipt_for(ARCH),
                epoch(LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &durable(),
            1_700_000_000_000,
        )?;
        let evidence = admitted.require_admitted().map_err(|_| KernelError::InvalidField {
            field: "compatibility_envelope",
            reason: "compatible candidate must be admitted",
        })?;
        assert_eq!(evidence.admitted_canonical_format_version(), Some(7));
        assert_eq!(evidence.refusal(), None);
        assert_eq!(evidence.migration_class(), "ADDITIVE");
        Ok(())
    }
}
