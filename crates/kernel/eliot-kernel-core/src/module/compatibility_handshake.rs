//! P-07 versioned I1.12 process-handshake compatibility envelope.
//!
//! Every process handshake exchanges the full compatibility envelope: the
//! protocol range, the contract-set digest, the canonical format range, the
//! Architecture source digest plus the `NormativePairIdentity` receipt I1.12
//! calls externally sealed, the module generation and Authority Epoch, the
//! required and optional capabilities, and the state migration class. A
//! candidate is admitted only when every field is compatible with the current
//! durable state; rollback is admitted only when the recorded compatibility
//! evidence still matches the current durable formats and epoch lineage. "Last
//! known good" means verified compatible with current state, never merely
//! previously launched.
//!
//! # What the normative-pair seal does and does not prove
//!
//! [`expected_seal_tag`] is a published, unkeyed recomputation, and this module
//! treats it as one rather than as an attestation by an external issuer. Read
//! [`expected_seal_tag`] for the precise statement; two properties are worth
//! repeating here:
//!
//! - The seal check adds no assurance about the PEER'S IDENTITY beyond the
//!   Architecture-digest check against durable state, because its operands are
//!   peer-supplied and it can therefore only agree or disagree with the peer
//!   about the peer. That is the accurate reason a tag is forgeable in principle.
//!   It is NOT accurate, and must not be read, that the check is redundant or
//!   dead. It is the only constraint on a presented `seal_tag`, and there is at
//!   least one call site where it is the SOLE check on that field. It is retained
//!   on that basis; it is not retained "pending a threat model", and this module
//!   does not document it as removable.
//!
//! - In [`admit_handshake`] it is the only constraint on the presented
//!   `seal_tag`. With `durable.architecture_source_digest = D` and a candidate
//!   whose `architecture_source_digest` is also `D` and whose receipt is
//!   `NormativePairReceipt::new(D, "c"*64)` — which `new` accepts, because it
//!   requires only lowercase hex — the Architecture-digest check passes and the
//!   seal check is what refuses the peer, with [`MismatchField::NormativeSeal`].
//!   Nothing else in this crate reads the presented tag. Deleting the seal check
//!   admits that envelope.
//!
//! - In [`admit_rollback`] the same holds for a durable row. An ORS row whose
//!   `architecture_source_digest` equals durable and whose `seal_tag` is
//!   `"c"*64` passes the digest comparison and is refused at the seal check
//!   alone. That is the whole reason the check is still here.
//!
//! - In `KernelRuntimeHealthEvidence::validate` the receiver-held constant
//!   comparison FORCES the carrier's `architecture_source_digest` to the
//!   receiver's own `CURRENT_ARCHITECTURE_SOURCE_DIGEST`, so the producer cannot
//!   choose the re-derivation input. The re-derivation is therefore the sole
//!   check on `seal_tag` in that entire function: a carrier with the correct
//!   Architecture digest, the correct pair key and the correct implementation
//!   digest but `seal_tag = "c"*64` is refused there and nowhere else. In this
//!   crate the check is strictly load-bearing, not redundant.
//! - What is genuinely independent of peer-supplied values is
//!   `Session::establish_with_server` in `eliot-ipc`, which compares the peer's
//!   `artifact_hash` and `module_generation` against
//!   `ServerHandshakePolicy.module_generation`, the registry-selected
//!   generation the server owner holds.
//!
//! # Who owns each field a producer must supply
//!
//! These owners are PUBLIC exports, so they are not a secrecy boundary and must
//! not be described as one: `bins/eliotd` already depends on this crate, so any
//! producer in another binary can build an envelope that presents exactly these
//! values. What the exports remove is DRIFT — a producer cannot restate a value
//! and present one this build does not produce — not the possibility of building
//! an envelope at all. A peer whose build differs disagrees at the comparison,
//! which is where it is detected. The field VALUES a producer needs are owned
//! here and exported:
//!
//! - `protocol range` -> [`handshake_protocol_range`];
//! - `canonical format range` -> [`handshake_canonical_format_range`];
//! - `contract-set digest` -> [`contract_set_digest`];
//! - `state migration class` -> **no owner exists**, and none was invented;
//!   read [`StateMigrationClass`] for why I1.12 defines no vocabulary this
//!   crate could derive one from.
//!
//! The remaining fields are not owned here because their owners are already
//! reachable from outside the Kernel binary: the Architecture source digest is
//! `CURRENT_ARCHITECTURE_SOURCE_DIGEST`, the receipt tag is
//! [`expected_seal_tag`], the envelope revision is
//! [`HANDSHAKE_ENVELOPE_VERSION`], and the generation and Authority Epoch come
//! from the registry and the epoch lineage rather than from this crate.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use eliot_contracts::{
    ContractIdentity, EpochId, EpochLineageId, ResourceGeneration, canonical_json_bytes, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};

/// Versioned envelope wire revision for the I1.12 handshake.
pub const HANDSHAKE_ENVELOPE_VERSION: u32 = 1;

/// The I1.12 protocol revision this build speaks.
///
/// Private on purpose. The I1.12 field is the RANGE, and
/// [`handshake_protocol_range`] is its single owner; publishing the bare
/// revision would invite a second spelling of the field at each producer,
/// which is the self-comparison this module exists to prevent. Value unchanged
/// from the single definition this replaced.
const HANDSHAKE_PROTOCOL_REVISION: u32 = 1;

/// The I1.12 canonical format revision this build speaks.
///
/// Private on the same terms as [`HANDSHAKE_PROTOCOL_REVISION`]:
/// [`handshake_canonical_format_range`] is the field's single owner.
const HANDSHAKE_CANONICAL_FORMAT_REVISION: u32 = 1;

/// The number of public contract identities the I1.12 `contract_set_digest`
/// covers.
///
/// A digest over an ordered tuple is only comparable across two sides if both
/// sides contribute the same identities in the same order, so the arity is part
/// of the field's shape and belongs to [`contract_set_digest`] rather than to
/// each producer. Four is the count the single previous definition used.
const CONTRACT_SET_IDENTITY_COUNT: usize = 4;

/// The domain tag this crate separates the normative-pair tag with.
///
/// The literal is named in the prose of the accepted receipt's `pair_key_input`
/// (`docs/normative-pair.toml`: "UTF-8 domain tag eliot-normative-pair-v1 and
/// lowercase document digests separated and terminated by NUL bytes"), and this
/// constant is the executable definition the algorithm below uses. Stated
/// precisely, because the previous wording here claimed the value came "from the
/// accepted external normative-pair receipt" while the next paragraph said the
/// value is published here: the receipt DOCUMENTS the domain tag in prose, and
/// this constant DEFINES it for this crate. The receipt does not issue it,
/// attest to it, or supply it to a peer, and no external seal issuer exists in
/// this repository. The same literal also appears in
/// `crates/foundation/eliot-bootstrap/src/normative.rs`, which is a separate
/// owner of the same value outside this crate; that is not an issuer either.
///
/// Because the value is published in source, the domain separates the tag from
/// other uses of SHA-256 but is not secret and confers no secrecy on anything.
pub const NORMATIVE_SEAL_DOMAIN: &str = "eliot-normative-pair-v1";

/// Computes the pair tag expected for an Architecture digest.
///
/// The algorithm is the one the normative-pair receipt names
/// (`docs/normative-pair.toml`, `pair_key_algorithm =
/// "sha256-domain-separated-v1"`, `pair_key_input`; I0.14): SHA-256 over the
/// seal domain and the lowercase Architecture and Implementation digests,
/// separated and terminated by NUL bytes. The Implementation half is the
/// compiled constant [`super::runtime_health::CURRENT_IMPLEMENTATION_SOURCE_DIGEST`],
/// never a peer-supplied string.
///
/// # This is not a secret, and there is no issuer
///
/// The domain string, the digest constant, the NUL framing and SHA-256 itself
/// are all published in this repository's source. No key, secret or signature
/// participates, so the function is computable by anyone for any input; it
/// cannot witness that a holder of anything proved anything. Production does in
/// fact call it to derive the very tag it later verifies
/// (`bins/eliot-kernel/src/compatibility_gate.rs` builds the process envelope's
/// receipt by calling `expected_seal_tag`). A former comment here asserted the
/// opposite - "The Kernel never mints seals" - and was false in production.
///
/// The precise statement, verified and not overstated:
///
/// > "Anyone can mint a valid tag for any digest" is true of the function but is
/// > **not an admission bypass**, and reads as one. Demonstration: with
/// > `D = "b"*64`, `expected_seal_tag(D)` computes fine,
/// > `NormativePairReceipt::new(D, expected_seal_tag(D))` succeeds, but
/// > `admit_handshake` **refuses at the architecture-digest check** before the
/// > seal check, because durable state in production is the receiver's own
/// > constant. Precise statement: **the seal is not a forged-secret bypass; it is
/// > the absence of any issuer.**
///
/// Minting is not an admission bypass because the Architecture-digest check
/// against durable state runs first and holds a value the receiver did not take
/// from the peer. Given that, the seal check in [`admit_handshake`] adds no
/// assurance about the peer's identity that the digest check does not already
/// establish, because both of its operands are peer-supplied. It is not, however,
/// redundant in the sense of removable, and it must not be described that way:
/// it is the ONLY constraint on the presented `seal_tag`. With durable
/// `architecture_source_digest = D` and a candidate whose digest is also `D` and
/// whose receipt is `NormativePairReceipt::new(D, "c"*64)`, the digest check
/// passes and this seal is the only thing that refuses the envelope, with
/// [`MismatchField::NormativeSeal`]. That is why it is kept. A former comment
/// here called it "strictly redundant with it", which would have licensed
/// deleting a live check.
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

/// Returns the I1.12 `protocol range` a current producer presents.
///
/// This function is the field's only owner, here in the crate that owns the
/// envelope: a producer in any binary calls it instead of restating the range,
/// so the envelope side and the durable side cannot come to disagree about a
/// value one of them invented. The value is the single revision this build
/// already spoke, carried unchanged.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] if the owned revision cannot form a
/// valid range, which the current constant cannot.
pub fn handshake_protocol_range() -> Result<VersionRange, KernelError> {
    VersionRange::new(HANDSHAKE_PROTOCOL_REVISION, HANDSHAKE_PROTOCOL_REVISION)
}

/// Returns the I1.12 `canonical format range` a current producer presents.
///
/// Owned on the same terms as [`handshake_protocol_range`]: one definition, in
/// the envelope's owner crate, that every producer reads rather than restates.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] if the owned revision cannot form a
/// valid range, which the current constant cannot.
pub fn handshake_canonical_format_range() -> Result<VersionRange, KernelError> {
    VersionRange::new(
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
        HANDSHAKE_CANONICAL_FORMAT_REVISION,
    )
}

/// Derives the I1.12 `contract-set digest` from the ordered contract identities.
///
/// The digest is SHA-256 over the canonical JSON encoding of the four public
/// contract identities in wire order - `eliot-contracts`,
/// `eliot-kernel-service`, `eliot-protocol`, `eliot-runtime-contracts` - and
/// never over an artifact or configuration hash, so it states WHICH public
/// surfaces were admitted, never which artifact or configuration was.
///
/// What a matching digest does NOT prove, stated here rather than implied: on a
/// boundary where one producer builds both sides - as the current Kernel ingress
/// does, `compatibility_gate::durable_compatibility_state` against
/// `compatibility_gate::process_compatibility_envelope` - both operands come from
/// this build's own constants, so the value is compared with itself and cannot
/// disagree with a peer. The only comparison on a handshake path whose two
/// operands are genuinely derived in two different processes is the Store API
/// catalogue comparison at the store-bridge seam.
///
/// The derivation lives here, in the envelope's owner crate, so a producer in
/// another binary derives the digest exactly as this crate's own producers do
/// instead of holding a private second spelling. Each owner crate still
/// supplies its own identity; what is owned here is the order, the arity and
/// the hashing, which are the parts two sides must agree on byte for byte.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when the identities have no canonical
/// encoding.
pub fn contract_set_digest(
    identities: &[ContractIdentity; CONTRACT_SET_IDENTITY_COUNT],
) -> Result<String, KernelError> {
    let bytes = canonical_json_bytes(identities).map_err(|_| KernelError::InvalidField {
        field: "contract_set_digest",
        reason: "contract identities have no canonical encoding",
    })?;
    Ok(sha256_hex(&bytes))
}

/// The durable state migration class carried by a handshake.
///
/// # I1.12 names this field but defines no vocabulary for it
///
/// I1.12 lists "state migration class" among the fields every process handshake
/// exchanges and nothing more: it does not enumerate classes, does not say what
/// a class MEANS relative to a durable format, and does not name any owner that
/// derives one. The four variants below are therefore this crate's closed
/// implementation vocabulary, not a projection of a normative list, and no
/// mapping from any other spelling exists or is invented here.
///
/// The consequence is bounded and stated rather than papered over: because I1.12
/// defines no vocabulary, there is no I1.12-derived value this crate can own and
/// export for a producer to present, so this field has no owner export at all.
/// A producer that supplies a migration class supplies one of these variants as
/// its own declaration. [`MismatchField::MigrationClass`] still refuses a
/// candidate whose class differs from durable state, so the gate is exact; what
/// an independently-issued class is *supposed to assert about a durable format*
/// remains undefined because the Architecture does not define it.
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
    /// The presented normative-pair tag is not the recomputed tag of the
    /// presented Architecture source digest.
    NormativeSeal,
    /// The Authority Epoch is not the current durable epoch.
    AuthorityEpoch,
    /// A durable required capability is missing from the candidate.
    RequiredCapability,
    /// The state migration class differs from durable state.
    MigrationClass,
    /// The Store API operation-manifest catalogue the peer presented is not
    /// the one this build's own compiled `eliot_store_api` produces.
    ///
    /// This is a DIFFERENT comparison from [`MismatchField::ContractSetDigest`],
    /// which is the digest over the public contract identities in the envelope.
    /// The two must not share one label: a refusal naming
    /// `contract_set_digest` when that comparison could not have fired points
    /// the diagnosis at a field the operator cannot change.
    StoreApiContractSet,
}

impl MismatchField {
    /// The stable wire label of this field.
    ///
    /// A refusal that crosses a typed boundary has to name the incompatible
    /// field as a `&'static str`, and these are the exact labels the durable
    /// [`eliot_ors::CompatibilityRefusal`] record stores, so the reported field
    /// and the persisted field are one value rather than two spellings.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EnvelopeVersion => "envelope_version",
            Self::ProtocolRange => "protocol_range",
            Self::ContractSetDigest => "contract_set_digest",
            Self::CanonicalFormatRange => "canonical_format_range",
            Self::ArchitectureDigest => "architecture_source_digest",
            Self::NormativeSeal => "normative_pair_receipt",
            Self::AuthorityEpoch => "authority_epoch",
            Self::RequiredCapability => "required_capability",
            Self::MigrationClass => "migration_class",
            Self::StoreApiContractSet => "store_api_contract_set_digest",
        }
    }
}

impl fmt::Display for MismatchField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
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

/// The `NormativePairIdentity` receipt I1.12 describes as externally sealed.
///
/// The receipt carries two peer-supplied values: an Architecture source digest
/// and the pair-key tag derived from it by [`expected_seal_tag`]. Both are
/// published algorithm, so the tag proves that its holder can compute a
/// published hash - it is not a signature and there is no external issuer behind
/// it. Production derives the tag from the build's own identity with
/// [`expected_seal_tag`] rather than reading it from the receipt, so "issued
/// outside the Kernel" is not what this type carries in practice. See
/// [`expected_seal_tag`] for the precise statement and for why minting a tag is
/// not an admission bypass.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativePairReceipt {
    architecture_source_digest: String,
    seal_tag: String,
}

impl NormativePairReceipt {
    /// Creates a well-formed receipt without verifying the seal.
    ///
    /// Seal verification happens in [`admit_handshake`] so an inconsistent seal
    /// is reported as a structured [`MismatchField::NormativeSeal`] refusal
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

    /// Returns the Architecture source digest this receipt carries.
    ///
    /// The value is the peer-supplied field itself. It is what this receipt is
    /// *presented* as sealing, not a digest this receipt independently sealed:
    /// nothing was sealed against it here, and nothing consulted a receiver-held
    /// truth to produce or check it. The digest that can be checked against
    /// receiver-held state is [`DurableCompatibilityState::architecture_source_digest`],
    /// and it is compared separately.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the presented pair tag, exactly as the peer supplied it.
    ///
    /// Nothing is consulted to answer this: the value is the peer-supplied field
    /// itself, so a caller that treats it as an issued seal is reading the peer's
    /// own claim.
    #[must_use]
    pub fn seal_tag(&self) -> &str {
        &self.seal_tag
    }

    /// Returns `true` when the presented tag equals
    /// [`expected_seal_tag`] of the presented digest.
    ///
    /// Both operands are peer-supplied: nothing the receiver holds is consulted, so
    /// this is a self-consistency check between two fields of one peer message
    /// and not a check against receiver-held truth. It therefore adds no
    /// assurance about the peer's identity beyond the Architecture-digest
    /// comparison [`admit_handshake`] performs against durable state. That is the
    /// accurate limit of what this predicate establishes.
    ///
    /// It is NOT redundant, and a former comment here saying it was would have
    /// licensed deleting a live check. This is the only constraint on a presented
    /// `seal_tag` anywhere in the crate: a candidate whose Architecture digest
    /// equals durable but whose tag is arbitrary passes the digest comparison and
    /// is refused at [`MismatchField::NormativeSeal`] here and nowhere else.
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

    /// Returns the presented normative-pair receipt, exactly as the peer supplied it.
    ///
    /// The field carries no issuer behind it: it is a receipt as presented, and a
    /// caller that reads its tag as an issued seal is reading the peer's own
    /// claim. Whether the tag is self-consistent is
    /// [`NormativePairReceipt::verifies`]'s question, answered separately.
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
    /// The Store API operation-manifest catalogue digest THIS receiver's own
    /// compiled `eliot_store_api` produces, when the receiver holds one.
    ///
    /// This is the receiver-held operand of the store-catalogue comparison. It
    /// is derived by the boundary that has the `eliot_store_api` compiled into
    /// it (`eliot_kernel_service::kernel_store_api_contract_set_digest`, i.e.
    /// `generated_operation_manifests` + `operation_manifest_set_digest`) and
    /// handed in here, because this crate does not depend on `eliot_store_api`
    /// and must not restate the derivation. `None` means the receiver holds no
    /// such value, which is the ordinary case for a boundary that runs no store
    /// and a refusal for one that does.
    #[serde(default)]
    store_api_contract_set_digest: Option<String>,
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
            store_api_contract_set_digest: None,
        })
    }

    /// Binds the Store API catalogue digest this receiver's own compiled
    /// `eliot_store_api` produces, as the receiver-held side of the rollback
    /// comparison for that field.
    ///
    /// It is a separate builder rather than a constructor argument so a
    /// boundary that runs no store keeps the ordinary `new` shape, and so the
    /// value can only ever come from the receiver's own compiled catalogue: the
    /// caller supplies what the receiver's build produces, never what a peer
    /// presented.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when the supplied digest is not
    /// lowercase SHA-256 hex.
    pub fn with_store_api_contract_set_digest(
        mut self,
        store_api_contract_set_digest: impl Into<String>,
    ) -> Result<Self, KernelError> {
        let store_api_contract_set_digest = store_api_contract_set_digest.into();
        validate_digest(
            &store_api_contract_set_digest,
            "durable_state.store_api_contract_set_digest",
        )?;
        self.store_api_contract_set_digest = Some(store_api_contract_set_digest);
        Ok(self)
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

    /// Returns the Store API catalogue digest this receiver's own compiled
    /// `eliot_store_api` produces, when the receiver holds one.
    #[must_use]
    pub fn store_api_contract_set_digest(&self) -> Option<&str> {
        self.store_api_contract_set_digest.as_deref()
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
    /// The Store API catalogue digest the STORE PROCESS presented and this
    /// receiver confirmed when the generation was admitted.
    ///
    /// It is the recorded peer operand, kept verbatim so
    /// [`admit_rollback`] re-verifies the ORIGINAL recorded value against the
    /// receiver's own compiled catalogue rather than recomputing something to
    /// compare. `None` is an absent claim, which is refused wherever the
    /// receiver holds an expectation; it is never read as agreement.
    store_api_contract_set_digest: Option<String>,
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

    /// Returns the pair tag recorded with this evidence, as presented.
    ///
    /// It is the tag that [`admit_handshake`] accepted, stored verbatim rather
    /// than recomputed, so a later reader can re-derive it against the recorded
    /// digest.
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

    /// Returns the Store API catalogue digest the store process presented when
    /// this evidence was accepted, when one was recorded.
    #[must_use]
    pub fn store_api_contract_set_digest(&self) -> Option<&str> {
        self.store_api_contract_set_digest.as_deref()
    }
}

/// Admits a process handshake against the current durable state.
///
/// Every I1.12 field is gated in order and the first incompatibility is
/// returned with its exact [`MismatchField`]. Overlapping protocol ranges
/// are negotiated to the highest mutual version; every other field must
/// match the durable state exactly, and the presented normative-pair tag must
/// be the recomputed tag of the presented Architecture source digest before the
/// peer is accepted.
///
/// The Architecture-digest comparison against `durable` is the check that
/// establishes the peer's identity, because `durable` is state the receiver did
/// not take from the peer. The seal comparison that follows it reads only
/// peer-supplied operands ([`NormativePairReceipt::verifies`]), so it adds no
/// assurance about identity beyond the digest comparison just made — which is
/// what makes a presented tag forgeable in principle.
///
/// It is not redundant in the removable sense, and the previous wording here,
/// which called it "strictly redundant", was false in this function. This check
/// is the ONLY constraint on the presented `seal_tag`. With
/// `durable.architecture_source_digest = D` and a candidate whose
/// `architecture_source_digest` is also `D` and whose receipt is
/// `NormativePairReceipt::new(D, "c"*64)` — which `new` accepts, because it
/// requires only lowercase hex — the digest comparison passes and this check
/// refuses the peer with [`MismatchField::NormativeSeal`]. Deleting it would
/// admit that envelope. See [`expected_seal_tag`] for the precise statement on
/// what the seal can and cannot prove.
///
/// # Which operand each comparison holds
///
/// A comparison whose two operands are both supplied by the peer checks the
/// peer's consistency with itself and changes nothing when deleted, so each
/// check below is stated with the side the receiver did NOT take from the
/// candidate. `durable` is state the caller holds; `HANDSHAKE_ENVELOPE_VERSION`
/// is this crate's own constant.
///
/// | Comparison | Receiver-held operand | Independent |
/// |---|---|---|
/// | envelope version | `HANDSHAKE_ENVELOPE_VERSION` | yes |
/// | protocol range | `durable.protocol_range()` | yes |
/// | contract-set digest | `durable.contract_set_digest()` | yes |
/// | canonical format range | `durable.canonical_format_range()` | yes |
/// | architecture digest | `durable.architecture_source_digest()` | yes |
/// | receipt's architecture digest | `durable.architecture_source_digest()` | yes |
/// | presented seal tag | none; see below | NO |
/// | Authority Epoch lineage | `durable.authority_epoch()` | yes |
/// | required capabilities | `durable.required_capabilities()` | yes |
/// | migration class | `durable.migration_class()` | yes, with the stated gap |
///
/// The receipt's Architecture digest is compared with DURABLE state, not with
/// the envelope's own digest field. Both operands used to be taken from the one
/// candidate message, so the arm could only fire for an envelope whose two
/// digest fields disagreed with each other, and it said nothing about the state
/// the receiver holds. Bound to durable it states that the receipt is presented
/// as sealing the Architecture this receiver runs, which the check above has
/// already proved the envelope agrees with; the arm is therefore
/// outcome-preserving, and it is NOT removable: an envelope carrying a receipt
/// over some OTHER digest, with that other digest's own correct tag, is refused
/// by this arm and by nothing else.
///
/// The last two rows are the ones that cannot be bound to a receiver-held
/// value, and are stated here rather than dressed up:
///
/// - **The presented seal tag.** [`NormativePairReceipt::verifies`] compares the
///   tag with the tag recomputed from the SAME presented digest. No
///   receiver-held tag exists to compare against, because no external seal
///   issuer exists in this repository ([`expected_seal_tag`] states the exact
///   consequence). The missing owner is an external normative-pair seal issuer.
///   Until one exists this is a self-consistency check on one field of one
///   message; it is retained only because it is that field's sole constraint,
///   not because it constrains identity.
/// - **The migration class.** Both sides are [`StateMigrationClass`] values the
///   boundary's own producer chose, because I1.12 names the field and defines no
///   vocabulary to derive a class from. The missing owner is the registry that
///   maps a durable canonical-format revision to the class it requires; this
///   crate does not invent one. The comparison itself is exact, so a candidate
///   that DOES declare a different class is refused.
///
/// On a boundary where one producer builds both sides — as the current Kernel
/// ingress does, `bins/eliot-kernel/src/compatibility_gate.rs:80` against `:110`
/// — every row above is decided by the epoch and generation the caller passes.
/// That is a property of that ingress, not of these comparisons, and it is why
/// a boundary that can diverge must present an envelope issued by the candidate
/// artifact's own owner.
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
        != durable.architecture_source_digest()
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
        // The envelope carries no Store API catalogue field: that operand comes
        // from the store PROCESS, and only the boundary that ran the live
        // comparison may record it (`CandidateActivation::record_store_api_contract_set`).
        store_api_contract_set_digest: None,
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
    pub fn refusal(&self) -> Option<&CompatibilityMismatch> {
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

    /// Binds the Store API catalogue digest a store PROCESS presented onto the
    /// durable evidence this activation persists.
    ///
    /// Only a boundary that actually ran the live store comparison calls this,
    /// and only after that comparison passed: the value is the peer's operand,
    /// already checked against the receiver's own compiled `eliot_store_api`, and
    /// recording it is what makes a later rollback re-verify the store's claim
    /// instead of trusting that it once matched. It is deliberately NOT derived
    /// here and NOT taken from `DurableCompatibilityState`: a receiver storing
    /// its own expectation next to the check is the self-comparison this exists
    /// to avoid.
    ///
    /// # Errors
    ///
    /// Returns the candidate's own refusal when the activation was refused —
    /// a refused candidate has no accepted store claim to record — and a
    /// [`MismatchField::StoreApiContractSet`] refusal when the presented value is
    /// not a well-formed digest.
    pub fn record_store_api_contract_set(
        &self,
        presented_store_api_contract_set_digest: &str,
    ) -> Result<Self, CompatibilityMismatch> {
        if let Some(mismatch) = &self.refusal {
            return Err(mismatch.clone());
        }
        let mut evidence = self.evidence.clone();
        evidence
            .record_store_api_contract_set(presented_store_api_contract_set_digest)
            .map_err(|error| {
                CompatibilityMismatch::new(MismatchField::StoreApiContractSet, error.to_string())
            })?;
        Ok(Self {
            evidence,
            refusal: None,
        })
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
/// This function makes no compatibility comparison of its own: it delegates the
/// whole decision to [`admit_handshake`] and then projects the candidate's own
/// offered fields onto the durable record, so a candidate that is refused keeps
/// its evidence durably. The per-field comparisons, and which operand of each
/// one the receiver holds rather than the candidate, are tabulated on
/// [`admit_handshake`]; two of them — the presented seal tag and the migration
/// class — have no receiver-held owner in this repository and are named there
/// rather than implied to be stronger than they are.
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
        // `None` until a boundary that ran the live store comparison records
        // the digest the store process presented. See
        // `CandidateActivation::record_store_api_contract_set`; the envelope has
        // no such field, so no producer could restate it here.
        None,
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
        // The recorded peer operand, kept verbatim. It is NOT validated against
        // anything here: this function reconstructs, and the comparison against
        // the receiver's own compiled catalogue is `admit_rollback`'s.
        store_api_contract_set_digest: recorded.store_api_contract_set_digest().map(str::to_owned),
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
/// current durable ranges, its digests, its seal and its migration class must
/// match, and its epoch lineage must be the durable lineage. Any drift is
/// refused with the exact mismatching field.
///
/// The recorded tag is re-derived here exactly as [`NormativePairReceipt::verifies`]
/// derives it: from the recorded digest, which came from the peer at admission
/// time. It is a consistency check on the stored record, not an independent
/// attestation, and it adds no assurance beyond the recorded-architecture-digest
/// comparison above it. It is NOT removable on that basis, and it is not dead:
/// it is the only constraint on the recorded tag. An ORS row whose
/// `architecture_source_digest` equals durable and whose `seal_tag` is `"c"*64`
/// passes the digest comparison and is refused at
/// [`MismatchField::NormativeSeal`] by this check alone. That is exactly why it
/// is retained: so a corrupted or rewritten ORS row is still refused.
///
/// The Store API catalogue is re-verified here too, through
/// [`admit_recorded_store_api_contract_set`], which is the one field on this
/// path whose two operands come from different builds rather than from one
/// message. The envelope fields were checked once, live, against a store; this
/// check is what stops a rollback from inheriting that one-time result.
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
    admit_recorded_store_api_contract_set(
        durable.store_api_contract_set_digest(),
        evidence.store_api_contract_set_digest.as_deref(),
    )
}

/// Re-verifies the Store API operation-manifest catalogue a generation's
/// accepted handshake was admitted on.
///
/// This is the I1.12 rollback half of the store-bridge comparison, and it is the
/// only comparison on this boundary whose two operands were produced by two
/// different builds of the same source:
/// | side | value | produced by |
/// |---|---|---|
/// | receiver-held | `receiver_held` | the digest of the catalogue generated by the `eliot_store_api` compiled into THIS receiver |
/// | recorded | `recorded` | the digest the store PROCESS presented, stored when that generation was admitted |
///
/// Neither side receives its value from the other, so deleting this comparison
/// cannot be compensated for elsewhere and turning it into `recorded ==
/// recorded` cannot be reached by echoing anything. Every absent case is a
/// refusal except the one absence that is not a claim at all:
///
/// - receiver holds one, record holds none: refused. An absent recorded value is
///   a generation whose store contract set was never proven, and "never proven"
///   is not agreement.
/// - receiver holds none, record holds one: refused. A recorded peer claim the
///   receiver cannot check is exactly the "previously launched" degradation.
/// - neither holds one: admitted, because no store boundary is in scope and
///   there is nothing to compare.
fn admit_recorded_store_api_contract_set(
    receiver_held: Option<&str>,
    recorded: Option<&str>,
) -> Result<(), CompatibilityMismatch> {
    match (receiver_held, recorded) {
        (Some(receiver), Some(recorded_digest)) if receiver == recorded_digest => Ok(()),
        (Some(_), Some(_)) => Err(CompatibilityMismatch::new(
            MismatchField::StoreApiContractSet,
            "recorded Store API contract-set digest is not the one this receiver's own \
             compiled store API produces",
        )),
        (Some(_), None) => Err(CompatibilityMismatch::new(
            MismatchField::StoreApiContractSet,
            "recorded evidence carries no Store API contract-set digest, which is not \
             agreement",
        )),
        (None, Some(_)) => Err(CompatibilityMismatch::new(
            MismatchField::StoreApiContractSet,
            "this receiver holds no Store API contract-set digest of its own, so the \
             recorded one cannot be verified",
        )),
        (None, None) => Ok(()),
    }
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
    /// The Store API catalogue digest THIS build's own compiled `eliot_store_api`
    /// produces - the receiver-held operand, standing in for
    /// `eliot_kernel_service::kernel_store_api_contract_set_digest`, which this
    /// crate cannot call because it does not depend on `eliot_store_api`.
    const RECEIVER_STORE_CATALOGUE: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";
    /// What a DIFFERENTLY BUILT store process presents: the digest of the
    /// catalogue generated by the `eliot_store_api` compiled into IT. It is a
    /// literal that never reads [`RECEIVER_STORE_CATALOGUE`], so the mismatch in
    /// these proofs is produced by editing what a STORE would present, and the
    /// comparison cannot be satisfied by echoing the receiver's own value.
    const STORE_PRESENTED_OTHER_CATALOGUE: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

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
    fn refused_candidate_activation_keeps_evidence_and_names_the_field() -> Result<(), KernelError>
    {
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
        assert_eq!(
            activation.refusal().map(CompatibilityMismatch::field),
            Some(MismatchField::CanonicalFormatRange)
        );
        let evidence = activation.evidence();
        // The protocol range DID overlap, and the refusal names the field that
        // did not: the protocol version is claimed only on a full admission.
        assert_eq!(evidence.protocol_range(), (1, 3));
        assert_eq!(evidence.canonical_format_range(), (8, 9));
        assert_eq!(evidence.admitted_protocol_version(), None);
        let refusal = evidence.refusal().expect("the refusal is durable");
        assert_eq!(refusal.field(), "canonical_format_range");
        // Generation and epoch lineage survive the refusal.
        assert_eq!(
            evidence.module_generation(),
            ResourceGeneration::genesis().value()
        );
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
        let evidence = admitted
            .require_admitted()
            .map_err(|_| KernelError::InvalidField {
                field: "compatibility_envelope",
                reason: "compatible candidate must be admitted",
            })?;
        assert_eq!(evidence.admitted_canonical_format_version(), Some(7));
        assert_eq!(evidence.refusal(), None);
        assert_eq!(evidence.migration_class(), "ADDITIVE");
        Ok(())
    }

    /// Durable state carrying this build's own Store API catalogue digest as the
    /// receiver-held operand of the rollback comparison.
    fn durable_with_receiver_store_catalogue() -> DurableCompatibilityState {
        durable()
            .with_store_api_contract_set_digest(RECEIVER_STORE_CATALOGUE)
            .expect("a well-formed receiver-held digest is accepted")
    }

    /// An ADMITTED activation whose durable evidence records the digest a store
    /// PROCESS presented, or records nothing when `presented` is `None`.
    fn admitted_activation_recording_store_catalogue(
        presented: Option<&str>,
    ) -> Result<CandidateActivation, KernelError> {
        let activation = admit_candidate_activation(
            &envelope(
                VersionRange::new(6, 9).unwrap(),
                receipt_for(ARCH),
                epoch(LINEAGE, 3),
                StateMigrationClass::Additive,
            ),
            &durable(),
            1_700_000_000_000,
        )?;
        let Some(digest) = presented else {
            return Ok(activation);
        };
        activation
            .record_store_api_contract_set(digest)
            .map_err(|_mismatch| KernelError::InvalidField {
                field: "compatibility_evidence.store_api_contract_set_digest",
                reason: "the presented store catalogue digest is not recordable on this verdict",
            })
    }

    /// Restores the durable row's evidence, mapping a refusal onto the test
    /// module's error type.
    ///
    /// `KernelError::InvalidField` carries `&'static str` field and reason, so a
    /// refusal whose reason is computed is surfaced as a fixed reason and the
    /// typed mismatch is asserted separately by the caller. That is why the
    /// proofs below read the `CompatibilityMismatch` rather than its rendering.
    fn restored(
        recorded: &eliot_ors::CompatibilityEvidence,
    ) -> Result<AcceptedCompatibilityEvidence, KernelError> {
        restore_recorded_evidence(recorded).map_err(|_mismatch| KernelError::InvalidField {
            field: "compatibility_evidence",
            reason: "the recorded row cannot be projected onto the current evidence shape",
        })
    }

    /// I1.12 acceptance, the half that was missing: a rollback re-verifies the
    /// store's catalogue claim instead of trusting that it once matched.
    ///
    /// The two operands are the digest THIS build's own compiled `eliot_store_api`
    /// produces (receiver-held, in durable state) and the digest the store PROCESS
    /// presented (recorded on the durable evidence when the generation was
    /// admitted). The mismatch is built by editing what a STORE would present,
    /// never the receiver's value, so this proof fails if the comparison is
    /// deleted or degenerates into a value against itself.
    #[test]
    fn rollback_refuses_a_recorded_store_catalogue_this_build_does_not_produce()
    -> Result<(), KernelError> {
        assert_ne!(
            STORE_PRESENTED_OTHER_CATALOGUE, RECEIVER_STORE_CATALOGUE,
            "the two operands must be distinct, or the refusal proves nothing"
        );
        let activation =
            admitted_activation_recording_store_catalogue(Some(STORE_PRESENTED_OTHER_CATALOGUE))?;
        let recorded = activation.evidence();
        assert_eq!(
            recorded.store_api_contract_set_digest(),
            Some(STORE_PRESENTED_OTHER_CATALOGUE),
            "the record keeps the peer operand, not the receiver's expectation"
        );
        let evidence = restored(recorded)?;
        let mismatch =
            admit_rollback(&evidence, &durable_with_receiver_store_catalogue()).unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::StoreApiContractSet);
        Ok(())
    }

    #[test]
    fn rollback_admits_a_recorded_store_catalogue_this_build_produces() -> Result<(), KernelError> {
        let activation =
            admitted_activation_recording_store_catalogue(Some(RECEIVER_STORE_CATALOGUE))?;
        let evidence = restored(activation.evidence())?;
        assert_eq!(
            evidence.store_api_contract_set_digest(),
            Some(RECEIVER_STORE_CATALOGUE)
        );
        admit_rollback(&evidence, &durable_with_receiver_store_catalogue()).map_err(
            |_mismatch| KernelError::InvalidField {
                field: "rollback",
                reason: "a matching recorded store catalogue must still be admitted",
            },
        )?;
        Ok(())
    }

    #[test]
    fn rollback_refuses_an_absent_recorded_store_catalogue() -> Result<(), KernelError> {
        let activation = admitted_activation_recording_store_catalogue(None)?;
        assert_eq!(activation.evidence().store_api_contract_set_digest(), None);
        let evidence = restored(activation.evidence())?;
        let mismatch =
            admit_rollback(&evidence, &durable_with_receiver_store_catalogue()).unwrap_err();
        assert_eq!(
            mismatch.field(),
            MismatchField::StoreApiContractSet,
            "an absent recorded value is a claim never made, not agreement"
        );
        Ok(())
    }

    #[test]
    fn rollback_refuses_a_recorded_store_catalogue_the_receiver_cannot_check()
    -> Result<(), KernelError> {
        let activation =
            admitted_activation_recording_store_catalogue(Some(STORE_PRESENTED_OTHER_CATALOGUE))?;
        let evidence = restored(activation.evidence())?;
        // Durable state holds no receiver-side catalogue at all: the recorded
        // peer claim is unverifiable here, so it is refused rather than passed.
        let mismatch = admit_rollback(&evidence, &durable()).unwrap_err();
        assert_eq!(mismatch.field(), MismatchField::StoreApiContractSet);
        Ok(())
    }
}
