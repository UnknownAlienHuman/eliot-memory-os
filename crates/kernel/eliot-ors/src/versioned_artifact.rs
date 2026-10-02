//! I1.6 + I1.12 + I14.14: immutable generation-addressed versioned artifacts.
//!
//! Issue #1971: versioned binaries are never replaced in place while running
//! (I1.6). Activation moves through registry/route indirection, prior
//! artifacts are retained until their generation drains and retires, and
//! cutover/rollback verifies the candidate hash plus I1.12 compatibility
//! evidence. Any update targeting the path of an active executable is
//! rejected. This module is pure domain logic: it owns no processes, store
//! handles, or canonical memory. [`VersionedArtifactEntry`] and the
//! registry's `durable_entries`/`from_durable_entries` pair are the pure
//! projection the ORS store writes and reads back, so a restart can rebuild
//! the registry from durable rows instead of an empty map; they are the same
//! registry state, not a second registry owner.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::model::{OrsError, sha256_hex, validate_digest, validate_text};
use eliot_contracts::canonical_json_bytes;

/// Generation-addressed immutable artifact identity.
///
/// The canonical layout follows I14.14:
/// `modules/<module_id>/<generation>/<artifact_hash>/module.exe`.
/// Launchers must use this exact path; activation swaps registry state, never
/// the bytes at the active path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifact {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
}

impl VersionedArtifact {
    /// Canonical generation-addressed path for one immutable artifact.
    #[must_use]
    pub fn canonical_path(module_id: &str, generation: u64, artifact_hash: &str) -> String {
        format!("modules/{module_id}/{generation}/{artifact_hash}/module.exe")
    }

    /// Constructs and validates one immutable artifact identity.
    pub fn new(
        module_id: impl Into<String>,
        generation: u64,
        artifact_hash: impl Into<String>,
        artifact_path: impl Into<String>,
    ) -> Result<Self, OrsError> {
        let artifact = Self {
            module_id: module_id.into(),
            generation,
            artifact_hash: artifact_hash.into(),
            artifact_path: artifact_path.into(),
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Validates generation addressing and the immutable hash/path binding.
    ///
    /// The path must equal the canonical generation-addressed layout
    /// exactly: substring matching would admit a generation `1` artifact at
    /// a generation `10` path, or a suffixed copy (`module.exe.bak`) of the
    /// addressed bytes, silently breaking the on-disk identity the
    /// generation/hash record names.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "versioned_artifact_module_id")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_generation",
                reason: "generation must be non-zero",
            });
        }
        validate_digest(&self.artifact_hash, "versioned_artifact_hash")?;
        validate_text(&self.artifact_path, "versioned_artifact_path")?;
        if self.artifact_path
            != Self::canonical_path(&self.module_id, self.generation, &self.artifact_hash)
        {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_path",
                reason: "path must be exactly the canonical generation-addressed layout",
            });
        }
        Ok(())
    }
}

/// The exact structured reason one I1.12 admission was refused.
///
/// `field` is the `MismatchField` label produced by the Kernel-owned
/// `CompatibilityMismatch` and `reason` is its refusal text, so the durable
/// condition names the incompatible field verbatim instead of a paraphrase.
/// The refused candidate's own evidence is never discarded: it stays in the
/// [`CompatibilityEvidence`] this refusal is attached to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRefusal {
    field: String,
    reason: String,
    observed_at_ms: i64,
}

impl CompatibilityRefusal {
    /// Creates a fail-closed refusal record.
    pub fn new(
        field: impl Into<String>,
        reason: impl Into<String>,
        observed_at_ms: i64,
    ) -> Result<Self, OrsError> {
        let refusal = Self {
            field: field.into(),
            reason: reason.into(),
            observed_at_ms,
        };
        refusal.validate()?;
        Ok(refusal)
    }

    /// Returns the exact incompatible-field label.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Returns the exact refusal reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns when the refusal was observed, in Unix milliseconds.
    #[must_use]
    pub const fn observed_at_ms(&self) -> i64 {
        self.observed_at_ms
    }

    /// Validates the label, the reason, and the observation clock.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.field, "compatibility_refusal_field")?;
        validate_text(&self.reason, "compatibility_refusal_reason")?;
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "compatibility_refusal_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// I1.12 compatibility verdict persisted with one candidate generation.
///
/// Before issue #1890 this record carried two booleans, so a "compatible"
/// verdict proved nothing about the artifact that carried it. It now persists
/// the whole negotiated handshake: the envelope revision, the offered protocol
/// and canonical-format ranges together with the versions actually admitted,
/// the contract-set digest, the Architecture source digest with its
/// normative-pair seal tag, the module generation, the Authority Epoch
/// lineage, the candidate's required and optional capabilities, and the state
/// migration class. A refused candidate keeps every one of those fields and
/// adds the exact [`CompatibilityRefusal`], so the evidence survives the
/// refusal instead of being replaced by it.
///
/// Issue #1968 adds one more, and it is the only field on this record whose two
/// operands do not both come from the same binary: the Store API
/// operation-manifest catalogue digest the store PROCESS presented at the live
/// handshake, recorded only after the receiver confirmed it against the digest
/// its own compiled `eliot_store_api` produces. Without it the one genuinely
/// independent comparison on the store-bridge seam was verified once, live, and
/// a later rollback re-verified only the envelope fields — the acceptance's
/// "previously launched" gap. See [`Self::record_store_api_contract_set`] and
/// [`Self::store_api_contract_set_digest`].
///
/// ORS stores and shape-validates only. Compatibility is decided once, by the
/// Kernel-owned `admit_handshake`/`admit_rollback`; this record never
/// re-decides it, and its migration-class and capability text carry no
/// vocabulary of their own. [`Self::require`] is the fail-closed storage gate
/// that keeps a refusal from becoming an activatable verdict.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    envelope_version: u32,
    protocol_range_min: u32,
    protocol_range_max: u32,
    contract_set_digest: String,
    canonical_format_range_min: u32,
    canonical_format_range_max: u32,
    architecture_source_digest: String,
    normative_seal_tag: String,
    module_generation: u64,
    authority_lineage_id: String,
    authority_sequence: u64,
    required_capabilities: Vec<String>,
    optional_capabilities: Vec<String>,
    migration_class: String,
    admitted_protocol_version: Option<u32>,
    admitted_canonical_format_version: Option<u32>,
    refusal: Option<CompatibilityRefusal>,
    /// The Store API operation-manifest catalogue digest the STORE PROCESS
    /// presented at the live handshake, recorded only after the receiver
    /// confirmed it against the digest its OWN compiled `eliot_store_api`
    /// produces (issue #1968).
    ///
    /// It is the peer's operand, not the receiver's: the receiver recomputes its
    /// own on the rollback path and compares, so this field is never the
    /// receiver's expected value stored beside its own check.
    ///
    /// `None` is the honest absence, and it is NOT agreement. A row written
    /// before this field existed, and a boundary that crossed no store at all,
    /// both read `None`, and the Kernel-owned rollback gate decides which of
    /// those two it is against durable state that does hold a receiver-held
    /// expectation. `#[serde(default)]` keeps such a row readable instead of
    /// refusing to deserialize it; the refusal is raised by the comparison, not
    /// smuggled into the decoder.
    #[serde(default)]
    store_api_contract_set_digest: Option<String>,
}

#[allow(
    clippy::too_many_arguments,
    reason = "one I1.12 verdict is exactly this field set; a builder would hide which field is missing"
)]
impl CompatibilityEvidence {
    /// Creates and shape-validates one persisted I1.12 verdict.
    ///
    /// The two `admitted_*` versions are the values negotiation produced, or
    /// `None` for a candidate that never reached negotiation. A refusal is
    /// optional here: an admitted candidate carries `None`, a refused one
    /// carries its exact structured reason.
    #[allow(
        clippy::too_many_arguments,
        reason = "one I1.12 verdict is exactly this field set; a builder would hide which field is missing"
    )]
    pub fn new(
        envelope_version: u32,
        protocol_range_min: u32,
        protocol_range_max: u32,
        contract_set_digest: impl Into<String>,
        canonical_format_range_min: u32,
        canonical_format_range_max: u32,
        architecture_source_digest: impl Into<String>,
        normative_seal_tag: impl Into<String>,
        module_generation: u64,
        authority_lineage_id: impl Into<String>,
        authority_sequence: u64,
        required_capabilities: Vec<String>,
        optional_capabilities: Vec<String>,
        migration_class: impl Into<String>,
        admitted_protocol_version: Option<u32>,
        admitted_canonical_format_version: Option<u32>,
        refusal: Option<CompatibilityRefusal>,
        store_api_contract_set_digest: Option<String>,
    ) -> Result<Self, OrsError> {
        let evidence = Self {
            envelope_version,
            protocol_range_min,
            protocol_range_max,
            contract_set_digest: contract_set_digest.into(),
            canonical_format_range_min,
            canonical_format_range_max,
            architecture_source_digest: architecture_source_digest.into(),
            normative_seal_tag: normative_seal_tag.into(),
            module_generation,
            authority_lineage_id: authority_lineage_id.into(),
            authority_sequence,
            required_capabilities,
            optional_capabilities,
            migration_class: migration_class.into(),
            admitted_protocol_version,
            admitted_canonical_format_version,
            refusal,
            store_api_contract_set_digest,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Binds the digest a STORE PROCESS presented onto this verdict, after the
    /// receiver confirmed it against its own compiled Store API catalogue.
    ///
    /// The caller passes the value the peer presented, never the receiver's
    /// expected value: storing the expectation here would make the later
    /// rollback comparison a value against itself. This ORS record does not
    /// decide compatibility and never recomputes the digest; it stores the
    /// operand that was compared, so a later rollback re-verifies the ORIGINAL
    /// recorded value rather than a fresh one.
    ///
    /// Fails closed on a verdict that records a refusal, because a refused
    /// candidate was never admitted and has nothing to record agreement about.
    pub fn record_store_api_contract_set(
        &mut self,
        presented_store_api_contract_set_digest: &str,
    ) -> Result<(), OrsError> {
        if self.refusal.is_some() {
            return Err(OrsError::IncompatibleArtifact);
        }
        validate_digest(
            presented_store_api_contract_set_digest,
            "compatibility_store_api_contract_set_digest",
        )?;
        self.store_api_contract_set_digest =
            Some(presented_store_api_contract_set_digest.to_owned());
        Ok(())
    }

    /// Returns the Store API catalogue digest the store process presented and
    /// the receiver confirmed, when this generation crossed a store boundary.
    ///
    /// `None` means no confirmed store claim was recorded. It does not mean the
    /// store agreed: the Kernel-owned rollback gate refuses an absent value
    /// wherever durable state holds a receiver-held expectation.
    #[must_use]
    pub fn store_api_contract_set_digest(&self) -> Option<&str> {
        self.store_api_contract_set_digest.as_deref()
    }

    /// Returns the envelope revision this verdict was produced by.
    #[must_use]
    pub const fn envelope_version(&self) -> u32 {
        self.envelope_version
    }

    /// Returns the candidate's offered protocol range.
    #[must_use]
    pub const fn protocol_range(&self) -> (u32, u32) {
        (self.protocol_range_min, self.protocol_range_max)
    }

    /// Returns the accepted contract-set digest.
    #[must_use]
    pub fn contract_set_digest(&self) -> &str {
        &self.contract_set_digest
    }

    /// Returns the candidate's offered canonical format range.
    #[must_use]
    pub const fn canonical_format_range(&self) -> (u32, u32) {
        (
            self.canonical_format_range_min,
            self.canonical_format_range_max,
        )
    }

    /// Returns the Architecture source digest the candidate was admitted on.
    #[must_use]
    pub fn architecture_source_digest(&self) -> &str {
        &self.architecture_source_digest
    }

    /// Returns the externally sealed `NormativePairIdentity` tag.
    #[must_use]
    pub fn normative_seal_tag(&self) -> &str {
        &self.normative_seal_tag
    }

    /// Returns the module generation this verdict is bound to.
    #[must_use]
    pub const fn module_generation(&self) -> u64 {
        self.module_generation
    }

    /// Returns the Authority Epoch lineage the candidate was admitted on.
    #[must_use]
    pub fn authority_lineage_id(&self) -> &str {
        &self.authority_lineage_id
    }

    /// Returns the Authority Epoch sequence the candidate was admitted at.
    #[must_use]
    pub const fn authority_sequence(&self) -> u64 {
        self.authority_sequence
    }

    /// Returns the candidate's required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    /// Returns the candidate's optional capabilities.
    #[must_use]
    pub fn optional_capabilities(&self) -> &[String] {
        &self.optional_capabilities
    }

    /// Returns the state migration class recorded for the candidate.
    #[must_use]
    pub fn migration_class(&self) -> &str {
        &self.migration_class
    }

    /// Returns the negotiated protocol version, or `None` when the candidate
    /// never reached negotiation.
    #[must_use]
    pub const fn admitted_protocol_version(&self) -> Option<u32> {
        self.admitted_protocol_version
    }

    /// Returns the negotiated canonical format version, or `None` when the
    /// candidate never reached negotiation.
    #[must_use]
    pub const fn admitted_canonical_format_version(&self) -> Option<u32> {
        self.admitted_canonical_format_version
    }

    /// Returns the exact structured refusal, when admission was refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<&CompatibilityRefusal> {
        self.refusal.as_ref()
    }

    /// Returns `true` when this verdict records a refused admission.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        self.refusal.is_some()
    }

    /// Returns every capability the candidate offered, required or optional.
    pub fn offered_capabilities(&self) -> impl Iterator<Item = &str> {
        self.required_capabilities
            .iter()
            .chain(self.optional_capabilities.iter())
            .map(String::as_str)
    }

    /// Fails closed unless this verdict is an admitted, unrefused one.
    ///
    /// This is the storage gate that keeps a refused candidate from becoming an
    /// activatable route. It reads the recorded refusal only; the compatibility
    /// decision itself is the Kernel's, and re-validating one recorded evidence
    /// against current durable state is `admit_rollback`, not this check.
    pub fn require(&self) -> Result<(), OrsError> {
        if self.refusal.is_none() {
            Ok(())
        } else {
            Err(OrsError::IncompatibleArtifact)
        }
    }

    /// Validates the storage shape of the verdict and its binding.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.envelope_version == 0 {
            return Err(OrsError::InvalidField {
                field: "compatibility_envelope_version",
                reason: "must be greater than zero",
            });
        }
        validate_version_range(
            self.protocol_range_min,
            self.protocol_range_max,
            "compatibility_protocol_range",
        )?;
        validate_version_range(
            self.canonical_format_range_min,
            self.canonical_format_range_max,
            "compatibility_canonical_format_range",
        )?;
        validate_digest(
            &self.contract_set_digest,
            "compatibility_contract_set_digest",
        )?;
        validate_digest(
            &self.architecture_source_digest,
            "compatibility_architecture_source_digest",
        )?;
        validate_digest(&self.normative_seal_tag, "compatibility_normative_seal_tag")?;
        if self.module_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "compatibility_module_generation",
                reason: "must be greater than zero",
            });
        }
        validate_epoch_lineage_id(&self.authority_lineage_id, self.authority_sequence)?;
        validate_capability_list(&self.required_capabilities)?;
        validate_capability_list(&self.optional_capabilities)?;
        if self
            .required_capabilities
            .iter()
            .any(|capability| self.optional_capabilities.contains(capability))
        {
            return Err(OrsError::InvalidField {
                field: "compatibility_optional_capabilities",
                reason: "an optional capability must not repeat a required capability",
            });
        }
        validate_text(&self.migration_class, "compatibility_migration_class")?;
        match (
            self.admitted_protocol_version,
            self.admitted_canonical_format_version,
        ) {
            (Some(protocol), Some(format)) => {
                if protocol == 0
                    || format == 0
                    || !(self.protocol_range_min..=self.protocol_range_max).contains(&protocol)
                    || !(self.canonical_format_range_min..=self.canonical_format_range_max)
                        .contains(&format)
                {
                    return Err(OrsError::InvalidField {
                        field: "compatibility_admitted_version",
                        reason: "an admitted version must lie inside the offered range",
                    });
                }
            }
            (None, None) => {}
            _ => {
                return Err(OrsError::InvalidField {
                    field: "compatibility_admitted_version",
                    reason: "the admitted protocol and format versions are recorded together or not at all",
                });
            }
        }
        if let Some(refusal) = &self.refusal {
            refusal.validate()?;
        }
        if let Some(store_digest) = &self.store_api_contract_set_digest {
            validate_digest(store_digest, "compatibility_store_api_contract_set_digest")?;
        }
        Ok(())
    }
}

fn validate_version_range(min: u32, max: u32, field: &'static str) -> Result<(), OrsError> {
    if min == 0 || min > max {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be a non-zero inclusive range whose min does not exceed its max",
        });
    }
    Ok(())
}

fn validate_capability_list(values: &[String]) -> Result<(), OrsError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, "compatibility_capability")?;
        if !seen.insert(value.as_str()) {
            return Err(OrsError::InvalidField {
                field: "compatibility_capability",
                reason: "must not contain duplicates",
            });
        }
    }
    Ok(())
}

/// Validates the lineage half of a canonical `EpochId` as ORS stores it.
///
/// ORS keeps the lineage identifier and the sequence as the two text/scalar
/// members the Kernel's `EpochId` carries; the tuple itself is owned by the
/// Kernel contract, and equality decisions on it are never made here.
fn validate_epoch_lineage_id(lineage_id: &str, sequence: u64) -> Result<(), OrsError> {
    let canonical = lineage_id.len() == 36
        && lineage_id.is_ascii()
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| lineage_id.as_bytes()[index] == b'-')
        && lineage_id.bytes().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
        });
    if !canonical || sequence == 0 {
        return Err(OrsError::InvalidField {
            field: "compatibility_authority_epoch",
            reason: "must be a canonical lineage identifier with a non-zero sequence",
        });
    }
    Ok(())
}

/// Why one generation is held in a degraded recovery condition (I1.12 W5).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityDegradedState {
    /// A handshake was refused; the candidate is staged and never activated.
    HandshakeRefused,
    /// A rollback target's recorded evidence no longer matches current durable
    /// formats, contract set, architecture identity, seal, migration class or
    /// Authority Epoch lineage. The artifact is retained but is not a rollback
    /// target.
    RollbackRefused,
}

/// The durable degraded/recovery condition one generation is held in.
///
/// I1.12 W5 requires incompatibility to be reported as an EXPLICIT condition
/// rather than a silent refusal: this record keeps the exact mismatching field
/// and reason alongside the candidate's own retained evidence, and states that
/// no route was activated for it. It rides the versioned-artifact row, so it is
/// written and read back by the same single-writer ORS family rather than a
/// second table owner, and it stays visible until an explicit owner
/// disposition removes it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityDegradedCondition {
    pub module_id: String,
    pub generation: u64,
    pub state: CompatibilityDegradedState,
    /// The exact incompatible-field label from the Kernel-owned refusal.
    pub mismatch_field: String,
    /// The exact refusal reason from the Kernel-owned refusal.
    pub mismatch_reason: String,
    /// Always `false`: a generation in a degraded condition has never had a
    /// route activated on it, and the record exists precisely because route
    /// activation was refused.
    pub route_activated: bool,
    pub observed_at_ms: i64,
}

impl CompatibilityDegradedCondition {
    /// Creates one open condition from a Kernel-owned refusal.
    ///
    /// `mismatch_field` and `mismatch_reason` are the Kernel-owned
    /// `CompatibilityMismatch` field label and refusal text, passed in by the
    /// Kernel composition that produced them. ORS stores them verbatim and
    /// imports no Kernel vocabulary of its own; the decision that named the
    /// field stays in the Kernel.
    #[must_use]
    pub fn from_refusal(
        module_id: impl Into<String>,
        generation: u64,
        state: CompatibilityDegradedState,
        mismatch_field: impl Into<String>,
        mismatch_reason: impl Into<String>,
        observed_at_ms: i64,
    ) -> Self {
        Self {
            module_id: module_id.into(),
            generation,
            state,
            mismatch_field: mismatch_field.into(),
            mismatch_reason: mismatch_reason.into(),
            route_activated: false,
            observed_at_ms,
        }
    }

    /// Returns the exact incompatible-field label.
    #[must_use]
    pub fn mismatch_field(&self) -> &str {
        &self.mismatch_field
    }

    /// Returns the exact refusal reason.
    #[must_use]
    pub fn mismatch_reason(&self) -> &str {
        &self.mismatch_reason
    }

    /// Returns `true` while route activation is blocked by this condition.
    #[must_use]
    pub const fn blocks_route_activation(&self) -> bool {
        !self.route_activated
    }

    /// Returns the candidate evidence retained alongside this condition.
    ///
    /// The evidence is not stored twice: the caller reads it from the same
    /// registry row the condition is attached to, so the refusal and the
    /// evidence it refused can never disagree.
    #[must_use]
    pub fn retained_evidence<'a>(
        &'a self,
        registry: &'a VersionedArtifactRegistry,
    ) -> Option<&'a CompatibilityEvidence> {
        registry.compatibility(&self.module_id, self.generation)
    }

    /// Validates the condition's own shape.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "compatibility_degraded_module_id")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "compatibility_degraded_generation",
                reason: "must be greater than zero",
            });
        }
        validate_text(
            &self.mismatch_field,
            "compatibility_degraded_mismatch_field",
        )?;
        validate_text(
            &self.mismatch_reason,
            "compatibility_degraded_mismatch_reason",
        )?;
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "compatibility_degraded_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        if self.route_activated {
            return Err(OrsError::InvalidField {
                field: "compatibility_degraded_route_activated",
                reason: "a degraded condition records that route activation was refused",
            });
        }
        Ok(())
    }
}

/// Lifecycle of one retained artifact generation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactGenerationState {
    Staged,
    Active,
    Draining,
    Retired,
}

/// One durable ORS row for one versioned-artifact registry entry.
///
/// The row is a registry entry projected onto storage: it carries the
/// immutable artifact identity, the entry's [`ArtifactGenerationState`], its
/// drain mark, and the I1.12 compatibility verdict that generation was admitted
/// on. `state` also selects which registry map the row belongs to - `Staged` is
/// a staged candidate, `Active`/`Draining` are retained generations - so one
/// durable table holds both maps without a second table owner and without a
/// side field that could disagree with the state it duplicates.
///
/// The persisted verdict is issue #1890's W3: the compatibility decision
/// travels WITH the candidate generation instead of being re-derived from a
/// live process, and a refused candidate keeps its evidence on the row so the
/// refusal is durable rather than transient. `Retired` has no row:
/// [`VersionedArtifactRegistry::retire`] removes the entry from the registry,
/// so no transition can produce one and [`Self::validate`] refuses it on both
/// the write and the read side.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactEntry {
    pub artifact: VersionedArtifact,
    pub state: ArtifactGenerationState,
    pub drained: bool,
    pub compatibility: CompatibilityEvidence,
    /// The open degraded/recovery condition for this generation, when one is
    /// recorded. `None` is the ordinary case and means no refusal is standing.
    pub degraded: Option<CompatibilityDegradedCondition>,
}

impl VersionedArtifactEntry {
    /// Durable key prefix for a retained generation row.
    pub const RETAINED_KEY_PREFIX: &'static str = "retained:";
    /// Durable key prefix for a staged candidate row.
    pub const STAGED_KEY_PREFIX: &'static str = "staged:";

    /// Validates the row-local invariants: the artifact keeps its exact
    /// canonical generation-addressed identity, its recorded I1.12 verdict
    /// satisfies its own shape and is bound to this row's own generation, a
    /// retired generation has no row at all, and only a `Draining` generation
    /// may carry a drain mark.
    ///
    /// The row-local rules only. Whether a set of rows can be a registry at all
    /// (no duplicate registry key within one side, one `Active` generation per
    /// module, staged and retained agreeing on a shared key) is decided by
    /// [`VersionedArtifactRegistry::from_durable_entries`], which sees the whole
    /// family.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.artifact.validate()?;
        self.compatibility.validate()?;
        if self.compatibility.module_generation() != self.artifact.generation {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_compatibility_generation",
                reason: "the recorded compatibility verdict must name this row's own generation",
            });
        }
        if self.state == ArtifactGenerationState::Retired {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_state",
                reason: "a retired generation has no durable registry row",
            });
        }
        if self.drained && self.state != ArtifactGenerationState::Draining {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_drained",
                reason: "only a draining generation may carry a drain mark",
            });
        }
        Ok(())
    }

    /// The exact durable key this row must be stored under.
    ///
    /// Pure key computation, so it is also the read-side check: a stored row
    /// whose key differs from this value is refused rather than reinterpreted.
    /// Only `Staged` selects the staged prefix; every other state is a
    /// retained-side key, so the computation is total and can never produce an
    /// empty or partial key. The generation is rendered last and never contains
    /// a separator, so the key is injective: two distinct registry entries can
    /// never share one.
    #[must_use]
    pub fn record_key(&self) -> String {
        let prefix = match self.state {
            ArtifactGenerationState::Staged => Self::STAGED_KEY_PREFIX,
            ArtifactGenerationState::Active
            | ArtifactGenerationState::Draining
            | ArtifactGenerationState::Retired => Self::RETAINED_KEY_PREFIX,
        };
        format!(
            "{prefix}{}:{}",
            self.artifact.module_id, self.artifact.generation
        )
    }
}

/// Status projection identifying the active generation's exact artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactStatus {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
    pub state: ArtifactGenerationState,
}

/// Durable ORS-side cutover evidence binding old and new artifact identity.
///
/// Status readers and ORS records carry this shape so the active generation's
/// exact hash and path are observable without trusting a live process. The
/// record also carries the candidate's whole I1.12 verdict, so a reader can see
/// WHICH protocol/contract/format/source/identity/generation/epoch/capability/
/// migration evidence admitted the route rather than only that two axes passed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactCutoverRecord {
    pub module_id: String,
    pub old_generation: Option<u64>,
    pub new_generation: u64,
    pub old_artifact_hash: Option<String>,
    pub old_artifact_path: Option<String>,
    pub new_artifact_hash: String,
    pub new_artifact_path: String,
    pub compatibility: CompatibilityEvidence,
    pub record_sha256: String,
}

#[derive(Serialize)]
struct VersionedArtifactCutoverCore<'a> {
    module_id: &'a str,
    old_generation: Option<u64>,
    new_generation: u64,
    old_artifact_hash: Option<&'a str>,
    old_artifact_path: Option<&'a str>,
    new_artifact_hash: &'a str,
    new_artifact_path: &'a str,
    compatibility: &'a CompatibilityEvidence,
}

impl VersionedArtifactCutoverRecord {
    fn core(&self) -> VersionedArtifactCutoverCore<'_> {
        VersionedArtifactCutoverCore {
            module_id: &self.module_id,
            old_generation: self.old_generation,
            new_generation: self.new_generation,
            old_artifact_hash: self.old_artifact_hash.as_deref(),
            old_artifact_path: self.old_artifact_path.as_deref(),
            new_artifact_hash: &self.new_artifact_hash,
            new_artifact_path: &self.new_artifact_path,
            compatibility: &self.compatibility,
        }
    }

    /// Returns the I1.12 verdict that admitted this cutover.
    #[must_use]
    pub const fn compatibility(&self) -> &CompatibilityEvidence {
        &self.compatibility
    }

    pub(crate) fn issue(
        module_id: String,
        old: Option<&VersionedArtifact>,
        new: &VersionedArtifact,
        evidence: CompatibilityEvidence,
    ) -> Result<Self, OrsError> {
        new.validate()?;
        if let Some(old) = old {
            old.validate()?;
        }
        if evidence.module_generation() != new.generation {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_compatibility_generation",
                reason: "the recorded compatibility verdict must name the new generation",
            });
        }
        let mut record = Self {
            module_id,
            old_generation: old.map(|artifact| artifact.generation),
            new_generation: new.generation,
            old_artifact_hash: old.map(|artifact| artifact.artifact_hash.clone()),
            old_artifact_path: old.map(|artifact| artifact.artifact_path.clone()),
            new_artifact_hash: new.artifact_hash.clone(),
            new_artifact_path: new.artifact_path.clone(),
            compatibility: evidence,
            record_sha256: String::new(),
        };
        record.validate_shape()?;
        let bytes = canonical_json_bytes(&record.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        record.record_sha256 = sha256_hex(&bytes);
        Ok(record)
    }

    fn validate_shape(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "artifact_cutover_module_id")?;
        self.compatibility.validate()?;
        if self.compatibility.module_generation() != self.new_generation {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_compatibility_generation",
                reason: "the recorded compatibility verdict must name the new generation",
            });
        }
        if self.new_generation == 0 {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_generation",
                reason: "new generation must be non-zero",
            });
        }
        if self.old_generation == Some(self.new_generation) {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_generation",
                reason: "cutover must select a distinct generation",
            });
        }
        validate_digest(&self.new_artifact_hash, "artifact_cutover_hash")?;
        validate_text(&self.new_artifact_path, "artifact_cutover_path")?;
        if let Some(old_hash) = &self.old_artifact_hash {
            validate_digest(old_hash, "artifact_cutover_old_hash")?;
        }
        if let Some(old_path) = &self.old_artifact_path {
            validate_text(old_path, "artifact_cutover_old_path")?;
        }
        if (self.old_generation.is_none()
            || self.old_artifact_hash.is_none()
            || self.old_artifact_path.is_none())
            && (self.old_generation.is_some()
                || self.old_artifact_hash.is_some()
                || self.old_artifact_path.is_some())
        {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_old",
                reason: "old generation identity must be fully present or absent",
            });
        }
        if let (Some(old_hash), Some(old_path)) = (&self.old_artifact_hash, &self.old_artifact_path)
            && (old_hash == &self.new_artifact_hash || old_path == &self.new_artifact_path)
        {
            return Err(OrsError::InvalidField {
                field: "artifact_cutover_new",
                reason: "update must produce a distinct versioned artifact path",
            });
        }
        Ok(())
    }

    /// Validates the record shape and its canonical digest.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_shape()?;
        validate_digest(&self.record_sha256, "artifact_cutover_sha256")?;
        let bytes = canonical_json_bytes(&self.core())
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        if sha256_hex(&bytes) != self.record_sha256 {
            return Err(OrsError::PayloadIntegrityMismatch);
        }
        Ok(())
    }
}

/// Typed retirement handoff for the file-deletion consumer.
///
/// Emitted only when a drained generation retires bound to the exact cutover
/// record that demoted it. The Host file owner deletes the named bytes; ORS
/// state no longer tracks them afterwards.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedArtifactRetirement {
    pub module_id: String,
    pub generation: u64,
    pub artifact_hash: String,
    pub artifact_path: String,
    /// Digest of the demoting cutover record this retirement is bound to.
    pub cutover_record_sha256: String,
    /// Always true on emission: only drained generations retire.
    pub drained: bool,
}

impl VersionedArtifactRetirement {
    /// Validates the retirement shape. The cutover binding itself is checked
    /// at emission (`retire_with_receipt`); this rejects malformed carriers.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "artifact_retirement_module_id")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "artifact_retirement_generation",
                reason: "generation must be non-zero",
            });
        }
        validate_digest(&self.artifact_hash, "artifact_retirement_hash")?;
        validate_text(&self.artifact_path, "artifact_retirement_path")?;
        validate_digest(&self.cutover_record_sha256, "artifact_retirement_cutover")?;
        if !self.drained {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        Ok(())
    }
}

/// One staged candidate's immutable identity, its I1.12 verdict, and the
/// degraded/recovery condition standing against it, if any (I1.12 W5).
#[derive(Clone, Debug, Eq, PartialEq)]
struct StagedEntry {
    artifact: VersionedArtifact,
    compatibility: CompatibilityEvidence,
    degraded: Option<CompatibilityDegradedCondition>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedEntry {
    artifact: VersionedArtifact,
    state: ArtifactGenerationState,
    drained: bool,
    compatibility: CompatibilityEvidence,
    /// Cleared once the generation is activated: a generation that reached
    /// `Active` is not in a degraded condition, so a staged refusal can never
    /// outlive the refusal that produced it.
    degraded: Option<CompatibilityDegradedCondition>,
}

/// Registry/indirection for immutable versioned artifacts (I1.6 + I14.14).
///
/// Activation swaps which generation is `Active`; it never overwrites the
/// bytes at the active path. Prior generations are retained as `Draining`
/// until drained, and only then eligible for `Retired`.
///
/// Every staged candidate and every retained generation carries the I1.12
/// verdict it was admitted on (issue #1890 W3). The verdict is the ONLY
/// compatibility fact the registry has: it is not recomputed from a live
/// process, and `activate` refuses a candidate whose stored verdict was
/// refused, so a route can never be switched onto evidence that is not
/// recorded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionedArtifactRegistry {
    staged: BTreeMap<(String, u64), StagedEntry>,
    retained: BTreeMap<(String, u64), RetainedEntry>,
}

impl VersionedArtifactRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stages an immutable candidate with its recorded I1.12 verdict, without
    /// touching the active executable.
    ///
    /// The verdict is bound to the candidate's own generation, so a caller
    /// cannot stage one generation's evidence for another. A refused verdict is
    /// staged too: the candidate's evidence is retained on the row so the
    /// refusal is durable and inspectable, and
    /// [`Self::activate`] is what refuses to switch a route onto it.
    ///
    /// Re-staging a retained identical artifact re-stages its recorded verdict
    /// with it, which is the ordinary rollback shape: the bytes stay where they
    /// are and the candidate becomes activatable again. Anything else that
    /// collides with retained or staged state fails closed.
    pub fn install_candidate(
        &mut self,
        artifact: VersionedArtifact,
        compatibility: CompatibilityEvidence,
    ) -> Result<(), OrsError> {
        artifact.validate()?;
        compatibility.validate()?;
        if compatibility.module_generation() != artifact.generation {
            return Err(OrsError::InvalidField {
                field: "versioned_artifact_compatibility_generation",
                reason: "the recorded compatibility verdict must name the staged generation",
            });
        }
        let key = (artifact.module_id.clone(), artifact.generation);
        if let Some(existing) = self.staged.get(&key) {
            if existing.artifact == artifact && existing.compatibility == compatibility {
                return Ok(());
            }
            return Err(OrsError::VersionedArtifactConflict);
        }
        if let Some(existing) = self.retained.get(&key) {
            if existing.artifact != artifact {
                return Err(OrsError::VersionedArtifactConflict);
            }
            self.staged.insert(
                key,
                StagedEntry {
                    artifact,
                    compatibility,
                    // Re-staging for rollback re-proposes the generation, so
                    // the prior candidate's degraded condition does not carry
                    // over: only a refusal against THIS proposal may block it.
                    degraded: None,
                },
            );
            return Ok(());
        }
        // I1.6 guard: no staged path may collide with a retained executable
        // (active or still-draining) unless it is the identical artifact.
        for entry in self.retained.values() {
            if entry.artifact.artifact_path == artifact.artifact_path && entry.artifact != artifact
            {
                return Err(OrsError::ActiveExecutableReplacement);
            }
        }
        for other in self.staged.values() {
            if other.artifact.artifact_path == artifact.artifact_path && other.artifact != artifact
            {
                return Err(OrsError::VersionedArtifactConflict);
            }
        }
        self.staged.insert(
            key,
            StagedEntry {
                artifact,
                compatibility,
                degraded: None,
            },
        );
        Ok(())
    }

    /// Rejects any update targeting the path of an active executable.
    pub fn guard_replacement(&self, target_path: &str) -> Result<(), OrsError> {
        for entry in self.retained.values() {
            if entry.state == ArtifactGenerationState::Active
                && entry.artifact.artifact_path == target_path
            {
                return Err(OrsError::ActiveExecutableReplacement);
            }
        }
        Ok(())
    }

    /// Cuts over to a staged candidate after hash and I1.12 verification.
    ///
    /// The compatibility evidence is READ from the candidate's stored verdict
    /// rather than taken from the caller, so a route switch is bound to the
    /// evidence persisted with that generation and cannot be admitted on a
    /// different verdict presented at cutover time. A stored refusal fails
    /// closed through [`CompatibilityEvidence::require`] before any registry
    /// state changes.
    ///
    /// The prior active generation is retained as `Draining`; its executable
    /// is left unchanged. Returns the durable cutover evidence binding the
    /// exact old and new hash/path pair and the candidate's whole verdict.
    pub fn activate(
        &mut self,
        module_id: &str,
        generation: u64,
        candidate_hash: &str,
    ) -> Result<VersionedArtifactCutoverRecord, OrsError> {
        let key = (module_id.to_owned(), generation);
        let staged = self
            .staged
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?
            .clone();
        // I1.12 W5: a refused activation is recorded as an explicit
        // degraded/recovery condition ON THE CANDIDATE'S OWN ROW before the
        // refusal returns, so the candidate evidence is retained durably and
        // the route-activation block is owned by durable state rather than by
        // a transient return value. The condition is derived from the verdict
        // already stored on the row, so it cannot disagree with it.
        if let Err(error) = staged.compatibility.require() {
            self.record_degraded(&key)?;
            return Err(error);
        }
        let candidate = staged.artifact;
        candidate.validate()?;
        if candidate.artifact_hash != candidate_hash {
            return Err(OrsError::IncompatibleArtifact);
        }
        self.guard_replacement(&candidate.artifact_path)?;
        let active_key = self
            .retained
            .iter()
            .find(|((module, _), entry)| {
                module == module_id && entry.state == ArtifactGenerationState::Active
            })
            .map(|(key, _)| key.clone());
        if let Some(ref active_key) = active_key {
            let active = self
                .retained
                .get(active_key)
                .ok_or(OrsError::VersionedArtifactNotFound)?;
            if active.artifact.generation == generation
                || active.artifact.artifact_hash == candidate.artifact_hash
                || active.artifact.artifact_path == candidate.artifact_path
            {
                return Err(OrsError::VersionedArtifactConflict);
            }
        }
        let old = active_key.as_ref().and_then(|key| {
            self.retained.get_mut(key).map(|entry| {
                entry.state = ArtifactGenerationState::Draining;
                entry.drained = false;
                entry.artifact.clone()
            })
        });
        self.staged.remove(&key);
        self.retained.insert(
            key,
            RetainedEntry {
                artifact: candidate.clone(),
                state: ArtifactGenerationState::Active,
                drained: false,
                compatibility: staged.compatibility.clone(),
                // A generation that reached `Active` is not in a degraded
                // condition, so any refusal recorded while it was a candidate
                // is cleared here rather than outliving its own cause.
                degraded: None,
            },
        );
        VersionedArtifactCutoverRecord::issue(
            module_id.to_owned(),
            old.as_ref(),
            &candidate,
            staged.compatibility,
        )
    }

    /// Records that one draining generation finished its in-flight work.
    pub fn mark_drained(&mut self, module_id: &str, generation: u64) -> Result<(), OrsError> {
        let entry = self
            .retained
            .get_mut(&(module_id.to_owned(), generation))
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if entry.state != ArtifactGenerationState::Draining {
            return Err(OrsError::InvalidTransition);
        }
        entry.drained = true;
        Ok(())
    }

    /// Retires a drained generation; fails closed while it still drains.
    pub fn retire(
        &mut self,
        module_id: &str,
        generation: u64,
    ) -> Result<VersionedArtifact, OrsError> {
        let key = (module_id.to_owned(), generation);
        let entry = self
            .retained
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if entry.state == ArtifactGenerationState::Active {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        if entry.state != ArtifactGenerationState::Draining || !entry.drained {
            return Err(OrsError::VersionedArtifactNotDrained);
        }
        let entry = self
            .retained
            .remove(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        Ok(entry.artifact)
    }

    /// Retires a drained generation bound to the exact cutover record that
    /// demoted it, returning the typed retirement handoff for the file-deletion
    /// consumer (Host owns artifact bytes; ORS never deletes files).
    ///
    /// The record must validate and name this exact generation, hash, and path
    /// as its demoted side; a mismatched record fails WITHOUT removing the
    /// entry, so a wrong receipt can never silently release bytes.
    pub fn retire_with_receipt(
        &mut self,
        module_id: &str,
        generation: u64,
        record: &VersionedArtifactCutoverRecord,
    ) -> Result<VersionedArtifactRetirement, OrsError> {
        record.validate()?;
        let key = (module_id.to_owned(), generation);
        let entry = self
            .retained
            .get(&key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        if record.old_generation != Some(generation)
            || record.old_artifact_hash.as_deref() != Some(entry.artifact.artifact_hash.as_str())
            || record.old_artifact_path.as_deref() != Some(entry.artifact.artifact_path.as_str())
        {
            return Err(OrsError::InvalidField {
                field: "artifact_retirement_cutover",
                reason: "retirement must name the cutover that demoted this generation",
            });
        }
        let artifact = self.retire(module_id, generation)?;
        Ok(VersionedArtifactRetirement {
            module_id: module_id.to_owned(),
            generation: artifact.generation,
            artifact_hash: artifact.artifact_hash,
            artifact_path: artifact.artifact_path,
            cutover_record_sha256: record.record_sha256.clone(),
            drained: true,
        })
    }

    /// Returns the active generation's exact artifact hash and path.
    #[must_use]
    pub fn active_status(&self, module_id: &str) -> Option<VersionedArtifactStatus> {
        self.retained
            .iter()
            .find(|((module, _), entry)| {
                module == module_id && entry.state == ArtifactGenerationState::Active
            })
            .map(|(_, entry)| VersionedArtifactStatus {
                module_id: entry.artifact.module_id.clone(),
                generation: entry.artifact.generation,
                artifact_hash: entry.artifact.artifact_hash.clone(),
                artifact_path: entry.artifact.artifact_path.clone(),
                state: ArtifactGenerationState::Active,
            })
    }

    /// Returns one retained generation and its lifecycle state.
    #[must_use]
    pub fn retained_state(
        &self,
        module_id: &str,
        generation: u64,
    ) -> Option<(VersionedArtifact, ArtifactGenerationState, bool)> {
        self.retained
            .get(&(module_id.to_owned(), generation))
            .map(|entry| (entry.artifact.clone(), entry.state, entry.drained))
    }

    /// Returns the I1.12 verdict recorded for one generation, staged or
    /// retained.
    ///
    /// This is the evidence a rollback target is checked against: it is the
    /// verdict persisted when that generation was admitted, never one
    /// re-derived from a live process.
    #[must_use]
    pub fn compatibility(
        &self,
        module_id: &str,
        generation: u64,
    ) -> Option<&CompatibilityEvidence> {
        let key = (module_id.to_owned(), generation);
        if let Some(entry) = self.staged.get(&key) {
            return Some(&entry.compatibility);
        }
        self.retained.get(&key).map(|entry| &entry.compatibility)
    }

    /// Records the open degraded/recovery condition against one staged
    /// candidate (I1.12 W5).
    ///
    /// The condition is derived from the verdict the row already carries, so it
    /// can never disagree with the evidence it claims to describe: the
    /// mismatching field, reason and observation clock are read from THIS
    /// candidate's own recorded [`CompatibilityRefusal`], not supplied by a
    /// caller. That is what keeps the condition bound to this candidate's own
    /// incompatibility rather than merely present on its row.
    fn record_degraded(&mut self, key: &(String, u64)) -> Result<(), OrsError> {
        let entry = self
            .staged
            .get(key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        let refusal = entry
            .compatibility
            .refusal()
            .ok_or(OrsError::IncompatibleArtifact)?;
        let condition = CompatibilityDegradedCondition::from_refusal(
            entry.artifact.module_id.clone(),
            entry.artifact.generation,
            CompatibilityDegradedState::HandshakeRefused,
            refusal.field(),
            refusal.reason(),
            refusal.observed_at_ms(),
        );
        condition.validate()?;
        let entry = self
            .staged
            .get_mut(key)
            .ok_or(OrsError::VersionedArtifactNotFound)?;
        entry.degraded = Some(condition);
        Ok(())
    }

    /// The open degraded/recovery condition recorded against one generation,
    /// staged or retained, when one is standing (I1.12 W5).
    ///
    /// This is the read surface a recovery consumer uses to learn that route
    /// activation is refused and which field caused it. It reads the durable
    /// row, so a refusal survives restart instead of existing only as the
    /// error value of a call that already returned.
    #[must_use]
    pub fn degraded_condition(
        &self,
        module_id: &str,
        generation: u64,
    ) -> Option<&CompatibilityDegradedCondition> {
        let key = (module_id.to_owned(), generation);
        if let Some(entry) = self.staged.get(&key) {
            return entry.degraded.as_ref();
        }
        self.retained
            .get(&key)
            .and_then(|entry| entry.degraded.as_ref())
    }

    /// Projects every registry entry onto its durable row.
    ///
    /// A staged candidate becomes a `Staged` row and each retained generation
    /// becomes a row carrying its own state, drain mark and I1.12 verdict, so
    /// the rows are exactly the registry's two maps with nothing added. Staged
    /// rows come first, then retained rows, each in `(module_id, generation)`
    /// order, so the projection is a deterministic function of the registry.
    pub fn durable_entries(&self) -> Result<Vec<VersionedArtifactEntry>, OrsError> {
        let mut rows = Vec::with_capacity(self.staged.len() + self.retained.len());
        for entry in self.staged.values() {
            let row = VersionedArtifactEntry {
                artifact: entry.artifact.clone(),
                state: ArtifactGenerationState::Staged,
                drained: false,
                compatibility: entry.compatibility.clone(),
                degraded: entry.degraded.clone(),
            };
            row.validate()?;
            rows.push(row);
        }
        for entry in self.retained.values() {
            let row = VersionedArtifactEntry {
                artifact: entry.artifact.clone(),
                state: entry.state,
                drained: entry.drained,
                compatibility: entry.compatibility.clone(),
                degraded: entry.degraded.clone(),
            };
            row.validate()?;
            rows.push(row);
        }
        Ok(rows)
    }

    /// Rebuilds a registry from durable rows (issue #1971, verdict #1890).
    ///
    /// This is the restart reconstruction path: the staged candidates, the
    /// retained generations, each one's `ArtifactGenerationState`, its drain
    /// mark and its I1.12 verdict all come from the rows, so the
    /// `ActiveExecutableReplacement` refusal, the active generation's exact
    /// hash/path and the recorded compatibility evidence are re-derived from
    /// durable state instead of from process memory.
    ///
    /// A row set that cannot be a registry is refused, never repaired:
    /// [`VersionedArtifactEntry::validate`] rejects a `Retired` row and a
    /// verdict bound to another generation, this loop rejects two rows
    /// projecting onto one registry key within the same side, it rejects two
    /// `Active` generations for one module because that would make the active
    /// generation unidentifiable, and it rejects a key present in both maps
    /// under differing artifact identities, which is exactly the identity
    /// `install_candidate` enforces when it re-stages a retained artifact for
    /// rollback.
    pub fn from_durable_entries(rows: Vec<VersionedArtifactEntry>) -> Result<Self, OrsError> {
        let mut staged: BTreeMap<(String, u64), StagedEntry> = BTreeMap::new();
        let mut retained: BTreeMap<(String, u64), RetainedEntry> = BTreeMap::new();
        let mut active_modules: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            // `validate` is the single row-level gate: it refuses `Retired`, so
            // the `retained` arm below can only ever see `Active` or `Draining`.
            row.validate()?;
            let key = (row.artifact.module_id.clone(), row.artifact.generation);
            if row.state == ArtifactGenerationState::Staged {
                if staged
                    .insert(
                        key.clone(),
                        StagedEntry {
                            artifact: row.artifact.clone(),
                            compatibility: row.compatibility,
                            degraded: row.degraded,
                        },
                    )
                    .is_some()
                {
                    return Err(OrsError::VersionedArtifactConflict);
                }
                continue;
            }
            if retained.contains_key(&key) {
                return Err(OrsError::VersionedArtifactConflict);
            }
            if row.state == ArtifactGenerationState::Active
                && !active_modules.insert(row.artifact.module_id.clone())
            {
                return Err(OrsError::VersionedArtifactConflict);
            }
            retained.insert(
                key,
                RetainedEntry {
                    artifact: row.artifact,
                    state: row.state,
                    drained: row.drained,
                    compatibility: row.compatibility,
                    degraded: row.degraded,
                },
            );
        }
        for (key, entry) in &staged {
            if let Some(retained_entry) = retained.get(key)
                && retained_entry.artifact != entry.artifact
            {
                return Err(OrsError::VersionedArtifactConflict);
            }
        }
        Ok(Self { staged, retained })
    }
}
