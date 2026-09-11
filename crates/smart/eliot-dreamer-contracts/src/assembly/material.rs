//! Exact material closures supplied to Dreamer bundle assembly.
//!
//! This module preserves owner-issued identities and joins them to the
//! recipe's job envelope. It performs no selection, fetching, screening, or
//! interpretation. A-04 supplies the selected entries; these types only make
//! the retained closure auditable and fail closed on drift.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, ContextError, LossPolicy as ContextLossPolicy,
    MeasurementCompositionProfile, MeasurementStatus, MeasurementUnit, SemanticRole, StuEstimate,
    TokenizerObservation,
};
use eliot_contracts::{ArtifactId, RequestId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assembly::recipe::{DreamInputRole, DreamJobRecipe, RoleOmissionPolicy};
use crate::budget::BudgetDimension;
use crate::bundle::{BundleMaterial, OmissionHandle, SourceDisposition};
use crate::curation::CurationPayload;
use crate::encoding::digest_hex;
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};
use crate::grounding::AllowedReferenceManifest;
use crate::registry::TargetDenominator;
use crate::screen::ScreenReference;

const MATERIAL_SCHEMA_VERSION: u32 = 1;
const MAX_MATERIALS: usize = 1_024;
const MAX_SCREENS: usize = 1_024;
const MAX_TEXT: usize = 1_024;
const MAX_LEDGER: usize = 1_024;
const MAX_ROLE_OUTCOMES: usize = 64;
const MAX_MEASUREMENTS: usize = 1_024;

/// Exact A-15 admission/view closure retained for a Dreamer material set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextMaterialClosure {
    /// Complete admitted membership supplied by A-15.
    pub admitted: AdmittedContextSet,
    /// Immutable view projected from that exact membership.
    pub view: ActiveUnderstandingView,
}

impl ContextMaterialClosure {
    /// Validates the view against the exact admitted set; membership is never
    /// reconstructed from rendered fields.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.admitted
            .validate()
            .map_err(context_error("context.admitted"))?;
        self.view
            .validate_against(&self.admitted)
            .map_err(context_error("context.view"))
    }

    /// Validates the A-15 closure against the enclosing Dreamer identity.
    pub fn validate_for(
        &self,
        task_id: &str,
        scope_id: &str,
        state_fence: &StateFence,
        attempt_id: &str,
        operation_id: Option<&str>,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        let binding = &self.admitted.binding;
        if binding.task_id.as_str() != task_id
            || binding.scope_id.as_str() != scope_id
            || binding.state_fence != *state_fence
            || binding.attempt_id.as_str() != attempt_id
            || binding
                .operation_id
                .as_ref()
                .map(eliot_contracts::OperationId::as_str)
                != operation_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "context.binding",
                reason:
                    "A-15 task, scope, attempt, operation, or fence differs from Dreamer material"
                        .to_owned(),
            });
        }
        Ok(())
    }
}

fn context_error(field: &'static str) -> impl FnOnce(ContextError) -> ContractViolation {
    move |error| ContractViolation::BindingMismatch {
        field,
        reason: error.to_string(),
    }
}

/// One selected role item joined to an exact manifest reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyMaterial {
    /// Closed recipe role admitting this material.
    pub role: DreamInputRole,
    /// Deterministic position within the selected role.
    pub ordinal: u32,
    /// Existing bounded material envelope.
    pub material: BundleMaterial,
    /// Exact representation identity and retained content form.
    pub representation: MaterialRepresentation,
    /// Exact key in [`AllowedReferenceManifest::references`].
    pub reference: ArtifactId,
}

impl AssemblyMaterial {
    /// Validates the material envelope and handle/reference identity.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.material.validate()?;
        self.representation.validate_for(&self.material.digest)?;
        if self.reference.as_str() != self.material.handle {
            return Err(ContractViolation::BindingMismatch {
                field: "material.reference",
                reason: "manifest reference key differs from material handle".to_owned(),
            });
        }
        Ok(())
    }
}

/// Bounded source representation carried to a model-visible input preimage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialRepresentation {
    /// Printable source content whose digest is bound to the material digest.
    Utf8 {
        representation_id: ArtifactId,
        content: String,
    },
    /// Opaque bytes whose digest is bound to the material digest.
    Bytes {
        representation_id: ArtifactId,
        content: Vec<u8>,
    },
    /// Owner permits carrying only the exact handle and digest.
    HandleOnly { representation_id: ArtifactId },
}

impl MaterialRepresentation {
    /// Validates bounds and content/digest conservation.
    pub fn validate_for(&self, material_digest: &str) -> Result<(), ContractViolation> {
        match self {
            Self::Utf8 {
                representation_id,
                content,
            } => {
                check_text(
                    representation_id.as_str(),
                    "material.representation.representation_id",
                    128,
                )?;
                check_text(content, "material.representation.content", 1_048_576)?;
                if digest_hex(content.as_bytes()) != material_digest {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.representation",
                        reason: "UTF-8 representation digest differs from material".to_owned(),
                    });
                }
            }
            Self::Bytes {
                representation_id,
                content,
            } => {
                check_text(
                    representation_id.as_str(),
                    "material.representation.representation_id",
                    128,
                )?;
                check_vec_bound(content.len(), 1_048_576, "material.representation.content")?;
                if digest_hex(content) != material_digest {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.representation",
                        reason: "byte representation digest differs from material".to_owned(),
                    });
                }
            }
            Self::HandleOnly { representation_id } => {
                check_text(
                    representation_id.as_str(),
                    "material.representation.representation_id",
                    128,
                )?;
            }
        }
        Ok(())
    }

    fn identity(&self) -> &ArtifactId {
        match self {
            Self::Utf8 {
                representation_id, ..
            }
            | Self::Bytes {
                representation_id, ..
            }
            | Self::HandleOnly { representation_id } => representation_id,
        }
    }

    fn exact_bytes(&self) -> Option<u64> {
        match self {
            Self::Utf8 { content, .. } => Some(content.len() as u64),
            Self::Bytes { content, .. } => Some(content.len() as u64),
            Self::HandleOnly { .. } => None,
        }
    }
}

/// Closed disposition of one role/item ledger entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialDisposition {
    /// The full material is retained in the selected bundle.
    Included,
    /// The material is accounted by an explicit omission handle.
    Omitted,
    /// The owner reported that the material could not be supplied.
    Unavailable,
    /// Assembly cannot proceed for this material under the current closure.
    Blocked,
    /// The role does not apply to this job class.
    NotApplicable,
}

/// Typed reason retained when a supplied item cannot be admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialOutcomeReason {
    Missing,
    Stale,
    Malformed,
    Unknown,
    Conflict,
    ScopeMismatch,
    PrivacyMismatch,
    AuthorityMismatch,
    BudgetExceeded,
    Unprocessed,
}

/// State of one recipe role after the supplied item denominator is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RoleOutcomeState {
    Applicable,
    KnownEmpty,
    Missing,
    Unresolved,
    NotApplicable,
}

/// Exact role-level outcome, independent of the actual supplied-item ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleOutcome {
    pub role: DreamInputRole,
    pub state: RoleOutcomeState,
    pub supplied_count: u32,
    pub retained_count: u32,
    pub reason: Option<MaterialOutcomeReason>,
}

impl RoleOutcome {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.retained_count > self.supplied_count {
            return Err(ContractViolation::BindingMismatch {
                field: "material.role_outcomes",
                reason: "retained count exceeds supplied count".to_owned(),
            });
        }
        match self.state {
            RoleOutcomeState::NotApplicable | RoleOutcomeState::KnownEmpty => {
                if self.supplied_count != 0 || self.retained_count != 0 || self.reason.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.role_outcomes",
                        reason: "empty role state must have zero counts and no reason".to_owned(),
                    });
                }
            }
            RoleOutcomeState::Missing => {
                if self.supplied_count != 0
                    || self.retained_count != 0
                    || self.reason != Some(MaterialOutcomeReason::Missing)
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.role_outcomes",
                        reason: "missing role state has an invalid count or reason".to_owned(),
                    });
                }
            }
            RoleOutcomeState::Applicable => {
                if self.supplied_count == 0 {
                    return Err(ContractViolation::MissingField(
                        "material.role_outcomes.supplied_count",
                    ));
                }
            }
            RoleOutcomeState::Unresolved => {
                if self.reason.is_none() {
                    return Err(ContractViolation::MissingField(
                        "material.role_outcomes.reason",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Conditional evaluation state retained by A-04 without inferring absence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionalEvaluationState {
    True,
    KnownFalse,
    Unresolved,
}

/// Exact A-15 conflict atom identity used by a `ConflictPresent` predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConflictAtomIdentity {
    pub atom_id: ArtifactId,
    pub source_revision: String,
    pub source_digest: String,
}

/// Evaluation of one frozen conditional recipe role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionalEvaluation {
    pub role: DreamInputRole,
    pub condition: crate::assembly::recipe::ConditionalRequirement,
    pub state: ConditionalEvaluationState,
    pub evidence_items: Vec<SuppliedItemIdentity>,
    pub conflict_atom: Option<ConflictAtomIdentity>,
}

impl ConditionalEvaluation {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.evidence_items.len(),
            MAX_LEDGER,
            "material.conditional.evidence_items",
        )?;
        let mut identities = BTreeSet::new();
        for evidence in &self.evidence_items {
            evidence.validate()?;
            if !identities.insert(evidence.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.conditional.evidence_items",
                    reason: "conditional evidence identities must be unique".to_owned(),
                });
            }
        }
        if let Some(conflict) = &self.conflict_atom {
            check_text(
                conflict.atom_id.as_str(),
                "material.conditional.conflict_atom",
                128,
            )?;
            check_text(
                &conflict.source_revision,
                "material.conditional.conflict_revision",
                MAX_TEXT,
            )?;
            if !is_hex64_lower(&conflict.source_digest) {
                return Err(ContractViolation::Malformed {
                    field: "material.conditional.conflict_digest",
                    reason: "expected lowercase SHA-256 digest".to_owned(),
                });
            }
        }
        if self.state == ConditionalEvaluationState::KnownFalse
            && (self.condition.coverage.is_none()
                || !self.evidence_items.is_empty()
                || self.conflict_atom.is_some())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional",
                reason: "known-false requires its exact coverage binding and no witness".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable identity of one item supplied to A-04 before selection.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuppliedItemIdentity {
    pub role: DreamInputRole,
    pub ordinal: u32,
    pub handle: Option<ArtifactId>,
    /// Source-free envelope digest, or the manifest material digest for a
    /// handle-backed source item.
    pub content_digest: Option<String>,
    pub source_revision: Option<String>,
}

impl SuppliedItemIdentity {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.handle.is_none() && self.content_digest.is_none() {
            return Err(ContractViolation::BindingMismatch {
                field: "material.supplied_items",
                reason: "supplied identity requires exactly one handle or content digest"
                    .to_owned(),
            });
        }
        if let Some(handle) = &self.handle {
            check_text(handle.as_str(), "material.supplied_items.handle", 128)?;
            if self.source_revision.is_none() || self.content_digest.is_none() {
                return Err(ContractViolation::MissingField(
                    "material.supplied_items.source_revision",
                ));
            }
        } else if self.source_revision.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "material.supplied_items.source_revision",
                reason: "source-free identity cannot carry a source revision".to_owned(),
            });
        }
        if let Some(digest) = &self.content_digest
            && !is_hex64_lower(digest)
        {
            return Err(ContractViolation::Malformed {
                field: "material.supplied_items.content_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        if let Some(revision) = &self.source_revision {
            check_text(
                revision,
                "material.supplied_items.source_revision",
                MAX_TEXT,
            )?;
        }
        Ok(())
    }
}

/// One exact role/item outcome retained by A-04 assembly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialLedgerEntry {
    /// Closed recipe role.
    pub role: DreamInputRole,
    /// Deterministic item ordinal within that role.
    pub ordinal: u32,
    /// Handle of the retained or accounted item, when applicable.
    pub handle: Option<ArtifactId>,
    /// Digest of the exact source-free value or handle-backed material.
    pub content_digest: Option<String>,
    /// Source revision for a handle-backed supplied item.
    pub source_revision: Option<String>,
    /// Exact disposition of this role/item.
    pub disposition: MaterialDisposition,
    /// Typed owner outcome reason, retained independently of disposition.
    pub reason: Option<MaterialOutcomeReason>,
    /// Required for an omitted item and retained verbatim.
    pub omission: Option<OmissionHandle>,
    /// Bounded owner reason for unavailable/blocked/non-terminal items.
    pub note: Option<String>,
    /// Optional owner-supplied accounting for an omitted item.
    #[serde(default)]
    pub omission_accounting: Option<AssemblyOmissionAccounting>,
}

/// Exact accounting retained for one omitted source item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyOmissionAccounting {
    /// Optional exact contribution observation for the omitted representation.
    pub measured: Option<ContributionMeasurement>,
    /// Typed constraints that compete for this omission's retained capacity.
    pub constraints: Vec<AssemblyOmissionConstraint>,
    /// Optional owner mapping into one exact coverage denominator member.
    pub coverage: Option<AssemblyOmissionCoverage>,
}

/// One bounded accounting constraint supplied with an omission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum AssemblyOmissionConstraint {
    /// Independent budget requirement in an existing budget dimension.
    Budget {
        dimension: BudgetDimension,
        limit: u64,
        required: u64,
    },
    /// Route capacity requirement under the exact measured profile.
    RouteCapacity {
        profile: ArtifactId,
        unit: MeasurementUnit,
        limit: u64,
        required: u64,
    },
    /// Recipe role cardinality requirement.
    RoleMaximum { maximum: u32, supplied_count: u32 },
}

/// Explicit owner mapping from an omission to a coverage member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyOmissionCoverage {
    /// Exact manifest coverage denominator digest.
    pub denominator: String,
    /// Owner-supplied member identity within that denominator.
    pub member: ArtifactId,
}

impl AssemblyOmissionAccounting {
    fn validate(&self, entry: &MaterialLedgerEntry) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.constraints.len(),
            16,
            "material.ledger.omission_accounting.constraints",
        )?;
        if let Some(measured) = &self.measured {
            measured.validate()?;
            let handle = entry
                .handle
                .as_ref()
                .ok_or(ContractViolation::MissingField("material.ledger.handle"))?;
            if measured.material != *handle
                || measured.source_revision != entry.source_revision.as_deref().unwrap_or_default()
                || measured.material_digest != entry.content_digest.as_deref().unwrap_or_default()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission_accounting.measured",
                    reason: "omitted contribution measurement differs from the exact item identity"
                        .to_owned(),
                });
            }
        }
        if let Some(coverage) = &self.coverage {
            if !is_hex64_lower(&coverage.denominator) {
                return Err(ContractViolation::Malformed {
                    field: "material.ledger.omission_accounting.coverage.denominator",
                    reason: "expected lowercase SHA-256 digest".to_owned(),
                });
            }
            check_text(
                coverage.member.as_str(),
                "material.ledger.omission_accounting.coverage.member",
                128,
            )?;
        }
        for constraint in &self.constraints {
            match constraint {
                AssemblyOmissionConstraint::Budget {
                    limit, required, ..
                }
                | AssemblyOmissionConstraint::RouteCapacity {
                    limit, required, ..
                } if required <= limit => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission_accounting.constraints",
                        reason: "omitted accounting constraint must exceed its declared limit"
                            .to_owned(),
                    });
                }
                AssemblyOmissionConstraint::RoleMaximum {
                    maximum,
                    supplied_count,
                } if supplied_count <= maximum => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission_accounting.constraints",
                        reason: "omitted role accounting must exceed the role maximum".to_owned(),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl MaterialLedgerEntry {
    /// Validate local disposition/omission coherence.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(handle) = &self.handle {
            check_text(handle.as_str(), "material.ledger.handle", 128)?;
        }
        if let Some(omission) = &self.omission {
            omission.validate()?;
            if self.handle.as_ref().map(ArtifactId::as_str) != Some(omission.handle.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission",
                    reason: "omission handle differs from ledger item".to_owned(),
                });
            }
        }
        if let Some(note) = &self.note {
            check_text(note, "material.ledger.note", 256)?;
        }
        if let Some(content_digest) = &self.content_digest
            && !is_hex64_lower(content_digest)
        {
            return Err(ContractViolation::Malformed {
                field: "material.ledger.content_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        if let Some(source_revision) = &self.source_revision {
            check_text(source_revision, "material.ledger.source_revision", MAX_TEXT)?;
        }
        match self.disposition {
            MaterialDisposition::Included => {
                if self.omission.is_some() || self.reason.is_some() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.disposition",
                        reason: "included item cannot carry omission or failure reason".to_owned(),
                    });
                }
                let identity_valid = if self.handle.is_some() {
                    self.source_revision.is_some() && self.content_digest.is_some()
                } else {
                    self.source_revision.is_none() && self.content_digest.is_some()
                };
                if !identity_valid {
                    return Err(ContractViolation::MissingField(
                        "material.ledger.content_digest",
                    ));
                }
            }
            MaterialDisposition::Omitted => {
                if self.handle.is_none()
                    || self.content_digest.is_none()
                    || self.omission.is_none()
                    || self.reason.is_none()
                    || self.source_revision.is_none()
                {
                    return Err(ContractViolation::MissingField("material.ledger.omission"));
                }
            }
            MaterialDisposition::NotApplicable => {
                if self.handle.is_some()
                    || self.content_digest.is_some()
                    || self.omission.is_some()
                    || self.reason.is_some()
                    || self.source_revision.is_some()
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.disposition",
                        reason: "not-applicable item cannot carry material or omission".to_owned(),
                    });
                }
            }
            MaterialDisposition::Unavailable | MaterialDisposition::Blocked => {
                if self.note.is_none() || self.reason.is_none() {
                    return Err(ContractViolation::MissingField("material.ledger.note"));
                }
                let identity_valid = if self.handle.is_some() {
                    self.source_revision.is_some() && self.content_digest.is_some()
                } else {
                    self.source_revision.is_none() && self.content_digest.is_some()
                };
                if !identity_valid {
                    return Err(ContractViolation::MissingField(
                        "material.ledger.content_digest",
                    ));
                }
            }
        }
        match (&self.disposition, &self.omission_accounting) {
            (MaterialDisposition::Omitted, Some(accounting)) => accounting.validate(self)?,
            (MaterialDisposition::Omitted, None) => {
                return Err(ContractViolation::MissingField(
                    "material.ledger.omission_accounting",
                ));
            }
            (_, Some(_)) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission_accounting",
                    reason: "omission accounting is only valid for omitted items".to_owned(),
                });
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Qualification state for one additive source contribution measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContributionStatus {
    /// Exact UTF-8 contribution under the supplied serializer profile.
    Exact,
    /// The contribution is retained but cannot establish a numeric cost.
    Unknown,
    /// The measurement owner could not provide the contribution.
    Unavailable,
}

/// A-03 contribution measurement bound to one material representation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContributionMeasurement {
    /// Retained material handle.
    pub material: ArtifactId,
    /// Exact raw representation identity.
    pub representation: ArtifactId,
    /// Source revision included in the measured raw representation.
    pub source_revision: String,
    /// Material digest included in the measured raw representation.
    pub material_digest: String,
    /// Profile that qualifies the raw representation byte measurement.
    pub profile: MeasurementCompositionProfile,
    /// Exact, unknown, or unavailable measurement state.
    pub status: ContributionStatus,
    /// Bytes only when the status is exact; unknown is not zero.
    pub bytes: Option<u64>,
}

/// Qualified measurement of the complete serialized Dreamer bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleMeasurement {
    /// Digest of the exact model-visible assembly input preimage measured.
    pub input_digest: String,
    /// Full A-15 serializer/profile qualification.
    pub profile: MeasurementCompositionProfile,
    /// Explicit measurement status; unknown is not zero.
    pub status: MeasurementStatus,
    /// Exact UTF-8 bytes when measured as such.
    pub input_utf8_bytes: Option<u64>,
    /// Planning-only STU observation, when supplied.
    pub stu_estimate: Option<StuEstimate>,
    /// Exact route tokenizer observation, when supplied.
    pub tokenizer: Option<TokenizerObservation>,
}

impl BundleMeasurement {
    /// Validates the qualified observation against the exact model input.
    pub fn validate_for(&self, materials: &AssemblyMaterialSet) -> Result<(), ContractViolation> {
        materials.validate()?;
        self.profile
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "result.bundle_measurement.profile",
                reason: error.to_string(),
            })?;
        if !is_hex64_lower(&self.input_digest) {
            return Err(ContractViolation::Malformed {
                field: "result.bundle_measurement.input_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        let input = materials.model_input_bytes_unchecked()?;
        if self.input_digest != digest_hex(&input) {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle_measurement.input_digest",
                reason: "measurement is bound to a different model input".to_owned(),
            });
        }
        if matches!(self.status, MeasurementStatus::ExactUtf8)
            && self.input_utf8_bytes != Some(input.len() as u64)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle_measurement.input_utf8_bytes",
                reason: "exact byte observation differs from model input".to_owned(),
            });
        }
        if let Some(tokenizer) = &self.tokenizer {
            check_text(
                &tokenizer.tokenizer_id,
                "result.bundle_measurement.tokenizer.tokenizer_id",
                MAX_TEXT,
            )?;
            check_text(
                &tokenizer.tokenizer_version,
                "result.bundle_measurement.tokenizer.tokenizer_version",
                MAX_TEXT,
            )?;
            if !is_hex64_lower(&tokenizer.tokenizer_hash) {
                return Err(ContractViolation::Malformed {
                    field: "result.bundle_measurement.tokenizer.tokenizer_hash",
                    reason: "expected lowercase SHA-256 digest".to_owned(),
                });
            }
        }
        match self.status {
            MeasurementStatus::ExactUtf8 if self.input_utf8_bytes.is_some() => {}
            MeasurementStatus::ConservativeStu if self.stu_estimate.is_some() => {}
            MeasurementStatus::ExactTokenizer if self.tokenizer.is_some() => {}
            MeasurementStatus::Unknown | MeasurementStatus::Unavailable => {}
            _ => {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle_measurement",
                    reason: "measurement status and observations disagree".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl ContributionMeasurement {
    /// Validates the profile and explicit measurement state.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.profile
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "material.measurement.profile",
                reason: error.to_string(),
            })?;
        check_text(self.material.as_str(), "material.measurement.material", 128)?;
        check_text(
            self.representation.as_str(),
            "material.measurement.representation",
            128,
        )?;
        check_text(
            &self.source_revision,
            "material.measurement.source_revision",
            MAX_TEXT,
        )?;
        if !is_hex64_lower(&self.material_digest) {
            return Err(ContractViolation::Malformed {
                field: "material.measurement.material_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        match (self.status, self.bytes) {
            (ContributionStatus::Exact, Some(_))
            | (ContributionStatus::Unknown | ContributionStatus::Unavailable, None) => Ok(()),
            (ContributionStatus::Exact, None) => Err(ContractViolation::MissingField(
                "material.measurement.bytes",
            )),
            (ContributionStatus::Unknown | ContributionStatus::Unavailable, Some(_)) => {
                Err(ContractViolation::BindingMismatch {
                    field: "material.measurement.bytes",
                    reason: "non-exact contribution cannot carry a byte count".to_owned(),
                })
            }
        }
    }
}

/// Curation-specific immutable screen and target closure.
///
/// The screen vector deliberately retains every owner-issued state, including
/// protected, unknown, stale, partial, unavailable, and unprocessed states.
/// This contract never turns an ineligible state into a dispatch decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationMaterial {
    /// Manifest handle for the immutable source snapshot reference.
    pub source_snapshot_ref: ArtifactId,
    /// Exact source snapshot identity screened by A-20.
    pub source_snapshot: String,
    /// Exact source revision screened by A-20.
    pub source_revision: String,
    /// Manifest handle for the source denominator reference.
    pub source_denominator_ref: ArtifactId,
    /// Exact denominator identity screened by A-20.
    pub source_denominator: String,
    /// Manifest handle for the screen-profile reference.
    pub screen_profile_ref: ArtifactId,
    /// Exact profile identity used by A-20.
    pub screen_profile: String,
    /// Manifest handle for the protection/coverage contract.
    pub protection_coverage_contract: ArtifactId,
    /// Exact typed subtype/payload supplied by the curation owner.
    pub payload: CurationPayload,
    /// Complete changed-target denominator.
    pub target_denominator: TargetDenominator,
    /// Explicit mapping from target identity to retained material handle.
    /// Target IDs and manifest handles are independent namespaces.
    pub target_materials: BTreeMap<String, ArtifactId>,
    /// One exact screen reference for every target, with all states retained.
    pub screens: Vec<ScreenReference>,
    /// Common A-19c request identity shared by the retained target screens.
    pub request_id: RequestId,
}

impl CurationMaterial {
    /// Validates the typed payload, denominator and every screen identity.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.source_snapshot, "curation.source_snapshot", MAX_TEXT)?;
        check_text(&self.source_revision, "curation.source_revision", MAX_TEXT)?;
        check_text(
            &self.source_denominator,
            "curation.source_denominator",
            MAX_TEXT,
        )?;
        check_text(&self.screen_profile, "curation.screen_profile", MAX_TEXT)?;
        self.payload.validate()?;
        self.target_denominator.validate()?;
        check_vec_bound(
            self.target_materials.len(),
            MAX_SCREENS,
            "curation.target_materials",
        )?;
        check_vec_bound(self.screens.len(), MAX_SCREENS, "curation.screens")?;
        if self.screens.len() != self.target_denominator.members.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.screens",
                reason: "one screen reference is required for every target".to_owned(),
            });
        }
        let facets = self.payload.facets();
        if !same_set(&facets.targets, &self.target_denominator.members) {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.target_denominator",
                reason: "payload targets differ from target denominator".to_owned(),
            });
        }
        let mut targets = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        for screen in &self.screens {
            screen.validate()?;
            if screen.request_id != self.request_id
                || screen.source_snapshot != self.source_snapshot
                || screen.source_revision != self.source_revision
                || screen.profile != self.screen_profile
                || screen.denominator != self.source_denominator
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.screens",
                    reason: "screen source/profile/request identity differs".to_owned(),
                });
            }
            if !targets.insert(screen.target_id.clone())
                || !receipts.insert(screen.receipt_id.clone())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.screens",
                    reason: "screen targets and receipts must be unique".to_owned(),
                });
            }
            let Some(handle) = self.target_materials.get(&screen.target_id) else {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.screens.target_materials",
                    reason: "screen target has no retained material mapping".to_owned(),
                });
            };
            check_text(handle.as_str(), "curation.target_materials", 128)?;
        }
        let expected: BTreeSet<_> = self.target_denominator.members.iter().cloned().collect();
        let mapped: BTreeSet<_> = self.target_materials.keys().cloned().collect();
        if mapped != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.target_materials",
                reason: "target mapping must cover the exact target denominator".to_owned(),
            });
        }
        if targets != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.screens",
                reason: "screen target membership differs from denominator".to_owned(),
            });
        }
        Ok(())
    }

    /// Validates screen task, scope and fence against the enclosing material.
    pub fn validate_for(
        &self,
        task_id: &str,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        if self.screens.iter().any(|screen| {
            screen.task_id != task_id
                || screen.scope_id != scope_id
                || screen.state_fence != *state_fence
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.screens",
                reason: "screen task, scope, or fence differs from material".to_owned(),
            });
        }
        Ok(())
    }
}

fn same_set(left: &[String], right: &[String]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn validate_source_rule(
    role: &crate::assembly::recipe::RecipeRole,
    reference: &crate::grounding::AuthorizedReference,
) -> Result<(), ContractViolation> {
    let source_rule = &role.source_rule;
    if let Some(owner) = &source_rule.allowed_owner {
        let actual_owner = reference
            .source_lineage
            .as_ref()
            .map(|lineage| &lineage.owner)
            .or_else(|| {
                reference.provenance.as_ref().and_then(|closure| {
                    closure
                        .lineage
                        .iter()
                        .find(|lineage| {
                            lineage.content_digest == reference.content_digest
                                && lineage.revision == reference.source_revision
                        })
                        .map(|lineage| &lineage.owner)
                })
            });
        if actual_owner != Some(owner) {
            return Err(ContractViolation::BindingMismatch {
                field: "material.source_rule.allowed_owner",
                reason: "reference owner is outside the role source policy".to_owned(),
            });
        }
    }
    if !source_rule.allowed_privacy.contains(&reference.privacy)
        || !source_rule.allowed_authority.contains(&reference.authority)
        || !source_rule
            .allowed_proof
            .contains(&reference.assertability_ceiling)
        || !source_rule
            .allowed_disclosure
            .contains(&reference.disclosure)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "material.source_rule",
            reason: "reference categorical source metadata is outside the role policy".to_owned(),
        });
    }
    Ok(())
}

fn source_free_value_digest(
    recipe: &DreamJobRecipe,
    role: DreamInputRole,
) -> Result<Option<String>, ContractViolation> {
    recipe.source_free_value_digest(role)
}

/// Frozen material closure handed from A-04 selection to result assembly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyMaterialSet {
    /// Exact material-contract schema version.
    pub schema_version: u32,
    /// Complete recipe envelope; common job fields are sourced from here.
    pub recipe: DreamJobRecipe,
    /// Frozen manifest whose references are the only admissible source keys.
    pub manifest: AllowedReferenceManifest,
    /// Exact selected subset of the frozen manifest.
    pub selected_references: BTreeMap<ArtifactId, crate::grounding::AuthorizedReference>,
    /// Digest of the selected subset, separate from the full manifest digest.
    pub selected_manifest_digest: String,
    /// Selected material entries joined to manifest references.
    pub materials: Vec<AssemblyMaterial>,
    /// Exact role/item disposition ledger, including omissions and gaps.
    pub ledger: Vec<MaterialLedgerEntry>,
    /// Immutable role/item identities supplied before A-04 selection.
    pub supplied_items: Vec<SuppliedItemIdentity>,
    /// One explicit outcome for every recipe role, including empty roles.
    pub role_outcomes: Vec<RoleOutcome>,
    /// One typed evaluation for every conditional recipe role.
    pub conditional_evaluations: Vec<ConditionalEvaluation>,
    /// Qualified additive source contribution measurements.
    pub measurements: Vec<ContributionMeasurement>,
    /// Optional exact A-15 context closure.
    pub context: Option<ContextMaterialClosure>,
    /// Curation-only typed screen closure.
    pub curation: Option<CurationMaterial>,
}

impl AssemblyMaterialSet {
    /// Returns the canonical model-visible input preimage after validating the
    /// supplied closure. The preimage contains the recipe/job binding,
    /// selected owner references, retained representations, omissions, and
    /// the exact A-15 view.
    pub fn model_input_bytes(&self) -> Result<Vec<u8>, ContractViolation> {
        self.validate()?;
        self.model_input_bytes_unchecked()
    }

    /// Returns the digest of the exact model-visible input preimage.
    pub fn model_input_digest(&self) -> Result<String, ContractViolation> {
        Ok(digest_hex(&self.model_input_bytes()?))
    }

    /// Computes the selected manifest subset digest without consulting the
    /// retained digest field.
    pub fn computed_selected_manifest_digest(&self) -> Result<String, ContractViolation> {
        let bytes = super::canonical_bytes(
            &self.selected_references,
            "assembly_carrier",
            super::ASSEMBLY_CARRIER_CEILING,
        )?;
        Ok(digest_hex(&bytes))
    }

    pub(crate) fn model_input_bytes_unchecked(&self) -> Result<Vec<u8>, ContractViolation> {
        #[derive(Serialize)]
        struct ModelRoleDiagnostic {
            role: DreamInputRole,
            ordinal: u32,
            disposition: MaterialDisposition,
            reason: Option<MaterialOutcomeReason>,
        }

        #[derive(Serialize)]
        struct ModelInputProjection<'a> {
            recipe_digest: &'a str,
            job: &'a crate::job::DreamJobInput,
            inputs: &'a [crate::assembly::recipe::RecipeInput],
            selected_references: &'a BTreeMap<ArtifactId, crate::grounding::AuthorizedReference>,
            materials: &'a [AssemblyMaterial],
            role_diagnostics: Vec<ModelRoleDiagnostic>,
            role_outcomes: &'a [RoleOutcome],
            context_view: Option<&'a ActiveUnderstandingView>,
            context_closure_digest: Option<&'a str>,
            curation: &'a Option<CurationMaterial>,
        }

        let mut retained_bytes = 0_usize;
        for material in &self.materials {
            let length = match &material.representation {
                MaterialRepresentation::Utf8 { content, .. } => content.len(),
                MaterialRepresentation::Bytes { content, .. } => content.len(),
                MaterialRepresentation::HandleOnly { .. } => 0,
            };
            retained_bytes =
                retained_bytes
                    .checked_add(length)
                    .ok_or(ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "model input representation size overflow".to_owned(),
                    })?;
            if retained_bytes
                > usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?
            {
                return Err(ContractViolation::Budget {
                    dimension: "input_bytes",
                    reason: "model input representations exceed class ceiling".to_owned(),
                });
            }
        }
        let context_closure_digest = self
            .context
            .as_ref()
            .map(|context| {
                super::canonical_bytes(context, "assembly_carrier", super::ASSEMBLY_CARRIER_CEILING)
                    .map(|bytes| digest_hex(&bytes))
            })
            .transpose()?;
        let role_diagnostics = self
            .ledger
            .iter()
            .map(|entry| ModelRoleDiagnostic {
                role: entry.role,
                ordinal: entry.ordinal,
                disposition: entry.disposition,
                reason: entry.reason,
            })
            .collect();
        let bytes = super::canonical_bytes(
            &ModelInputProjection {
                recipe_digest: &self.recipe.recipe_digest,
                job: &self.recipe.job,
                inputs: &self.recipe.inputs,
                selected_references: &self.selected_references,
                materials: &self.materials,
                role_diagnostics,
                role_outcomes: &self.role_outcomes,
                context_view: self.context.as_ref().map(|context| &context.view),
                context_closure_digest: context_closure_digest.as_deref(),
                curation: &self.curation,
            },
            "input_bytes",
            usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                ContractViolation::Budget {
                    dimension: "input_bytes",
                    reason: "input byte ceiling does not fit this platform".to_owned(),
                }
            })?,
        )?;
        Ok(bytes)
    }

    /// Validates the complete manifest/material/context identity closure.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_header()?;
        self.validate_selected_materials()?;
        self.validate_ledger()?;
        self.validate_supplied_identity()?;
        self.validate_role_cardinality()?;
        self.validate_role_outcomes()?;
        self.validate_conditional_evaluations()?;
        self.validate_retained_links()?;
        self.validate_measurements()?;
        self.validate_context()?;
        self.validate_curation()?;
        Ok(())
    }

    fn validate_header(&self) -> Result<(), ContractViolation> {
        super::preflight(self, "assembly_carrier", super::ASSEMBLY_CARRIER_CEILING)?;
        self.preflight_representation_bounds()?;
        if self.schema_version != MATERIAL_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "material.schema_version",
                min: i64::from(MATERIAL_SCHEMA_VERSION),
                max: i64::from(MATERIAL_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        self.recipe.validate()?;
        let job = &self.recipe.job;
        check_text(&job.task_id, "material.job.task_id", 256)?;
        check_text(&job.scope_id, "material.job.scope_id", 256)?;
        self.manifest.validate()?;
        if self.manifest.digest != job.frozen_manifest_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "material.manifest.digest",
                reason: "manifest digest differs from the recipe frozen manifest".to_owned(),
            });
        }
        if self.manifest.task_id.as_str() != job.task_id
            || self.manifest.scope_id != job.scope_id
            || self.manifest.state_fence != job.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.manifest",
                reason: "manifest task, scope, or fence differs from material".to_owned(),
            });
        }
        if !is_hex64_lower(&self.selected_manifest_digest) {
            return Err(ContractViolation::Malformed {
                field: "material.selected_manifest_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_selected_materials(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.materials.len(), MAX_MATERIALS, "material.materials")?;
        let mut handles = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for material in &self.materials {
            material.validate()?;
            if material.material.disposition == SourceDisposition::Excluded {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.material.disposition",
                    reason: "excluded bundle material cannot be selected".to_owned(),
                });
            }
            let role = self
                .recipe
                .roles
                .iter()
                .find(|role| role.role == material.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.role",
                    reason: "material role is absent from recipe denominator".to_owned(),
                })?;
            if role.disposition == crate::assembly::recipe::RoleDisposition::NotApplicable
                || role.source_rule.is_none()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.role",
                    reason: "material violates recipe applicability or cardinality".to_owned(),
                });
            }
            if matches!(
                material.representation,
                MaterialRepresentation::HandleOnly { .. }
            ) && matches!(role.representation_loss, ContextLossPolicy::NonDroppable)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.representation",
                    reason: "handle-only representation is not permitted for a non-droppable role"
                        .to_owned(),
                });
            }
            if !handles.insert(material.reference.clone())
                || !ordinals.insert((material.role.as_str(), material.ordinal))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.materials",
                    reason: "material references and role ordinals must be unique".to_owned(),
                });
            }
            let reference = self.manifest.references.get(&material.reference).ok_or(
                ContractViolation::BindingMismatch {
                    field: "material.reference",
                    reason: "material reference is absent from the frozen manifest".to_owned(),
                },
            )?;
            if reference.content_digest != material.material.digest {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.digest",
                    reason: "material digest differs from manifest reference".to_owned(),
                });
            }
            validate_source_rule(role, reference)?;
        }
        let selected_keys: BTreeSet<_> = self.selected_references.keys().cloned().collect();
        let material_keys: BTreeSet<_> =
            self.materials.iter().map(|m| m.reference.clone()).collect();
        if selected_keys != material_keys {
            return Err(ContractViolation::BindingMismatch {
                field: "material.selected_references",
                reason: "selected manifest subset must equal retained material references"
                    .to_owned(),
            });
        }
        check_vec_bound(
            self.selected_references.len(),
            MAX_MATERIALS,
            "material.selected_references",
        )?;
        for (handle, reference) in &self.selected_references {
            if self.manifest.references.get(handle) != Some(reference) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.selected_references",
                    reason: "selected reference differs from frozen manifest".to_owned(),
                });
            }
        }
        let selected_digest = self.computed_selected_manifest_digest()?;
        if selected_digest != self.selected_manifest_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "material.selected_manifest_digest",
                reason: "selected manifest digest mismatch".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_ledger(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.ledger.len(), MAX_LEDGER, "material.ledger")?;
        let mut ledger_ordinals = BTreeSet::new();
        let mut omission_coverage_members = BTreeSet::new();
        let mut omission_handles = BTreeSet::new();
        for entry in &self.ledger {
            entry.validate()?;
            let role = self
                .recipe
                .roles
                .iter()
                .find(|role| role.role == entry.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.ledger.role",
                    reason: "ledger role is absent from recipe denominator".to_owned(),
                })?;
            if entry.disposition != MaterialDisposition::NotApplicable
                && role.disposition == crate::assembly::recipe::RoleDisposition::NotApplicable
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.disposition",
                    reason: "not-applicable recipe role cannot carry an item outcome".to_owned(),
                });
            }
            Self::validate_ledger_entry(entry, role, &mut omission_handles)?;
            self.validate_ledger_coverage(entry, &mut omission_coverage_members)?;
            self.validate_ledger_identity(entry, role)?;
            if !ledger_ordinals.insert((entry.role.as_str(), entry.ordinal)) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger",
                    reason: "duplicate role/item ledger entry".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_ledger_entry(
        entry: &MaterialLedgerEntry,
        role: &crate::assembly::recipe::RecipeRole,
        omission_handles: &mut BTreeSet<String>,
    ) -> Result<(), ContractViolation> {
        if let Some(omission) = &entry.omission
            && !omission_handles.insert(omission.handle.clone())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.ledger.omission",
                reason: "omission handles must be unique across the complete ledger".to_owned(),
            });
        }
        if entry.disposition == MaterialDisposition::Omitted {
            let omission = entry
                .omission
                .as_ref()
                .ok_or(ContractViolation::MissingField("material.ledger.omission"))?;
            match role.omission_policy {
                RoleOmissionPolicy::NonDroppable => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission",
                        reason: "non-droppable role cannot be omitted".to_owned(),
                    });
                }
                RoleOmissionPolicy::ReversibleHandle if !omission.reversible => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission",
                        reason: "role requires a reversible omission handle".to_owned(),
                    });
                }
                RoleOmissionPolicy::NonRecoverableReason
                    if omission.reversible
                        || omission
                            .nonrecoverable_reason
                            .as_deref()
                            .is_none_or(|reason| reason.trim().is_empty()) =>
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission",
                        reason: "role requires an explicit non-recoverable omission reason"
                            .to_owned(),
                    });
                }
                RoleOmissionPolicy::ReversibleHandle | RoleOmissionPolicy::NonRecoverableReason => {
                }
                RoleOmissionPolicy::NotApplicable => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.omission",
                        reason: "not-applicable role cannot be omitted".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_ledger_coverage(
        &self,
        entry: &MaterialLedgerEntry,
        omission_coverage_members: &mut BTreeSet<(String, ArtifactId)>,
    ) -> Result<(), ContractViolation> {
        if let Some(coverage) = entry
            .omission_accounting
            .as_ref()
            .and_then(|accounting| accounting.coverage.as_ref())
        {
            let denominator = self
                .manifest
                .coverage_denominators
                .get(&coverage.denominator)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission_accounting.coverage",
                    reason: "coverage denominator is absent from the exact manifest".to_owned(),
                })?;
            let receipt = self
                .manifest
                .coverage_receipts
                .get(&coverage.denominator)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission_accounting.coverage",
                    reason: "coverage receipt is absent for the exact denominator".to_owned(),
                })?;
            let receipt_accounts_member = receipt
                .members
                .iter()
                .any(|outcome| outcome.member == coverage.member)
                || receipt
                    .omissions
                    .iter()
                    .any(|omission| omission.member == coverage.member);
            if receipt.denominator != coverage.denominator
                || !denominator.members.contains(&coverage.member)
                || !receipt_accounts_member
                || !omission_coverage_members
                    .insert((coverage.denominator.clone(), coverage.member.clone()))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.omission_accounting.coverage",
                    reason: "coverage mapping does not join one exact manifest member".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_ledger_identity(
        &self,
        entry: &MaterialLedgerEntry,
        role: &crate::assembly::recipe::RecipeRole,
    ) -> Result<(), ContractViolation> {
        if entry.disposition == MaterialDisposition::Included {
            if role.source_rule.is_none() && entry.handle.is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.handle",
                    reason: "source-free role cannot use a manifest handle".to_owned(),
                });
            }
            if !role.source_rule.is_none() && entry.handle.is_none() {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.handle",
                    reason: "source-bearing role requires a manifest handle".to_owned(),
                });
            }
        }
        if entry.disposition != MaterialDisposition::NotApplicable && role.source_rule.is_none() {
            let digest = entry
                .content_digest
                .as_deref()
                .ok_or(ContractViolation::MissingField(
                    "material.ledger.content_digest",
                ))?;
            let expected = source_free_value_digest(&self.recipe, entry.role)?.ok_or(
                ContractViolation::MissingField("material.ledger.content_digest"),
            )?;
            if digest != expected {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.content_digest",
                    reason: "source-free ledger identity differs from retained job input"
                        .to_owned(),
                });
            }
        } else if entry.disposition != MaterialDisposition::NotApplicable {
            let handle = entry
                .handle
                .as_ref()
                .ok_or(ContractViolation::MissingField("material.ledger.handle"))?;
            let mismatch_reason = matches!(
                entry.reason,
                Some(
                    MaterialOutcomeReason::AuthorityMismatch
                        | MaterialOutcomeReason::ScopeMismatch
                        | MaterialOutcomeReason::Stale
                        | MaterialOutcomeReason::Conflict
                )
            );
            let foreign_identity_allowed = matches!(
                entry.disposition,
                MaterialDisposition::Blocked | MaterialDisposition::Unavailable
            ) && mismatch_reason;
            let reference = self.manifest.references.get(handle);
            if let Some(reference) = reference {
                if !foreign_identity_allowed
                    && (entry.source_revision.as_deref()
                        != Some(reference.source_revision.as_str())
                        || entry.content_digest.as_deref()
                            != Some(reference.content_digest.as_str()))
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.ledger.identity",
                        reason: "ledger handle identity differs from the frozen manifest"
                            .to_owned(),
                    });
                }
            } else if !foreign_identity_allowed {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.handle",
                    reason: "ledger handle is absent from the frozen manifest".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_supplied_identity(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.supplied_items.len(),
            MAX_LEDGER,
            "material.supplied_items",
        )?;
        let mut supplied_keys = BTreeSet::new();
        for supplied in &self.supplied_items {
            supplied.validate()?;
            let role = self
                .recipe
                .roles
                .iter()
                .find(|role| role.role == supplied.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.supplied_items.role",
                    reason: "supplied item role is absent from recipe denominator".to_owned(),
                })?;
            if role.disposition == crate::assembly::recipe::RoleDisposition::NotApplicable
                || !supplied_keys.insert(supplied.clone())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.supplied_items",
                    reason: "supplied item is duplicate or not applicable".to_owned(),
                });
            }
            if role.source_rule.is_none() == supplied.handle.is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.supplied_items.identity",
                    reason:
                        "source-bearing roles require handles and source-free roles require digests"
                            .to_owned(),
                });
            }
            if supplied.handle.is_none() {
                let digest =
                    supplied
                        .content_digest
                        .as_deref()
                        .ok_or(ContractViolation::MissingField(
                            "material.supplied_items.content_digest",
                        ))?;
                let expected = source_free_value_digest(&self.recipe, supplied.role)?.ok_or(
                    ContractViolation::MissingField("material.supplied_items.content_digest"),
                )?;
                if digest != expected {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.supplied_items.content_digest",
                        reason: "supplied source-free digest differs from recipe input".to_owned(),
                    });
                }
            }
        }
        let mut ledger_keys = BTreeSet::new();
        for entry in self
            .ledger
            .iter()
            .filter(|entry| entry.disposition != MaterialDisposition::NotApplicable)
        {
            let identity = SuppliedItemIdentity {
                role: entry.role,
                ordinal: entry.ordinal,
                handle: entry.handle.clone(),
                content_digest: entry.content_digest.clone(),
                source_revision: entry.source_revision.clone(),
            };
            identity.validate()?;
            if !ledger_keys.insert(identity) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger",
                    reason: "ledger supplied identity is duplicated".to_owned(),
                });
            }
        }
        if ledger_keys != supplied_keys {
            return Err(ContractViolation::BindingMismatch {
                field: "material.supplied_items",
                reason: "ledger identities differ from the immutable supplied denominator"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_role_cardinality(&self) -> Result<(), ContractViolation> {
        for role in &self.recipe.roles {
            let mut ordinals: Vec<_> = self
                .ledger
                .iter()
                .filter(|entry| entry.role == role.role)
                .map(|entry| entry.ordinal)
                .collect();
            ordinals.sort_unstable();
            if ordinals
                .iter()
                .enumerate()
                .any(|(expected, actual)| u32::try_from(expected).ok() != Some(*actual))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.ordinal",
                    reason: "ledger ordinals must form the complete supplied-item denominator"
                        .to_owned(),
                });
            }
            let retained = self
                .ledger
                .iter()
                .filter(|entry| {
                    entry.role == role.role && entry.disposition == MaterialDisposition::Included
                })
                .count();
            if retained > role.maximum as usize {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger",
                    reason: "retained role items exceed recipe maximum".to_owned(),
                });
            }
        }
        for role in &self.recipe.roles {
            if role.disposition == crate::assembly::recipe::RoleDisposition::NotApplicable
                && self.ledger.iter().any(|entry| {
                    entry.role == role.role
                        && entry.disposition != MaterialDisposition::NotApplicable
                })
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.disposition",
                    reason: "not-applicable recipe role has an applicable ledger item".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_role_outcomes(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.role_outcomes.len(),
            MAX_ROLE_OUTCOMES,
            "material.role_outcomes",
        )?;
        if self.role_outcomes.len() != self.recipe.roles.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "material.role_outcomes",
                reason: "one role outcome is required for every recipe role".to_owned(),
            });
        }
        let mut outcome_roles = BTreeSet::new();
        for outcome in &self.role_outcomes {
            outcome.validate()?;
            let role = self
                .recipe
                .roles
                .iter()
                .find(|role| role.role == outcome.role)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "material.role_outcomes.role",
                    reason: "role outcome is absent from recipe denominator".to_owned(),
                })?;
            if !outcome_roles.insert(outcome.role)
                || (role.disposition == crate::assembly::recipe::RoleDisposition::NotApplicable
                    && outcome.state != RoleOutcomeState::NotApplicable)
                || (role.disposition != crate::assembly::recipe::RoleDisposition::NotApplicable
                    && outcome.state == RoleOutcomeState::NotApplicable)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.role_outcomes.state",
                    reason: "role outcome state conflicts with recipe applicability".to_owned(),
                });
            }
            let supplied_count = u32::try_from(
                self.supplied_items
                    .iter()
                    .filter(|item| item.role == outcome.role)
                    .count(),
            )
            .map_err(|_| ContractViolation::Budget {
                dimension: "source_width",
                reason: "supplied item count overflows role accounting".to_owned(),
            })?;
            let retained_count = u32::try_from(
                self.ledger
                    .iter()
                    .filter(|entry| {
                        entry.role == outcome.role
                            && entry.disposition == MaterialDisposition::Included
                    })
                    .count(),
            )
            .map_err(|_| ContractViolation::Budget {
                dimension: "source_width",
                reason: "retained item count overflows role accounting".to_owned(),
            })?;
            if supplied_count != outcome.supplied_count || retained_count != outcome.retained_count
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.role_outcomes.count",
                    reason: "role outcome counts differ from supplied ledger identities".to_owned(),
                });
            }
        }
        if outcome_roles.len() != self.recipe.roles.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "material.role_outcomes",
                reason: "role outcomes contain a duplicate or missing role".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_retained_links(&self) -> Result<(), ContractViolation> {
        for material in &self.materials {
            let Some(entry) = self.ledger.iter().find(|entry| {
                entry.role == material.role
                    && entry.ordinal == material.ordinal
                    && entry.handle.as_ref() == Some(&material.reference)
            }) else {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger",
                    reason: "retained material has no included ledger entry".to_owned(),
                });
            };
            if entry.disposition != MaterialDisposition::Included {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger.disposition",
                    reason: "retained material must be marked included".to_owned(),
                });
            }
        }
        for entry in self.ledger.iter().filter(|entry| {
            entry.disposition == MaterialDisposition::Included
                && self
                    .recipe
                    .roles
                    .iter()
                    .find(|role| role.role == entry.role)
                    .is_some_and(|role| !role.source_rule.is_none())
        }) {
            if !self.materials.iter().any(|material| {
                material.role == entry.role
                    && material.ordinal == entry.ordinal
                    && entry.handle.as_ref() == Some(&material.reference)
            }) {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.ledger",
                    reason: "included ledger item has no selected material".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_measurements(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.measurements.len(),
            MAX_MEASUREMENTS,
            "material.measurements",
        )?;
        if self.measurements.len() != self.materials.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "material.measurements",
                reason: "every selected material requires exactly one measurement".to_owned(),
            });
        }
        let mut measurement_handles = BTreeSet::new();
        for measurement in &self.measurements {
            measurement.validate()?;
            let Some(material) = self
                .materials
                .iter()
                .find(|material| material.reference == measurement.material)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.measurements",
                    reason: "measurement must name one retained material".to_owned(),
                });
            };
            let reference = self.manifest.references.get(&measurement.material).ok_or(
                ContractViolation::BindingMismatch {
                    field: "material.measurements",
                    reason: "measurement material is absent from manifest".to_owned(),
                },
            )?;
            if material.material.digest != measurement.material_digest
                || reference.source_revision != measurement.source_revision
                || measurement.representation != *material.representation.identity()
                || !measurement_handles.insert(measurement.material.clone())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "material.measurements",
                    reason: "measurement source revision, digest, or identity differs".to_owned(),
                });
            }
            if measurement.status == ContributionStatus::Exact {
                let expected = material.representation.exact_bytes().ok_or(
                    ContractViolation::BindingMismatch {
                        field: "material.measurements",
                        reason: "handle-only representation cannot claim exact contribution bytes"
                            .to_owned(),
                    },
                )?;
                if measurement.bytes != Some(expected) || material.material.bytes != expected {
                    return Err(ContractViolation::BindingMismatch {
                        field: "material.measurements.bytes",
                        reason: "exact contribution bytes differ from retained representation"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_context(&self) -> Result<(), ContractViolation> {
        let job = &self.recipe.job;
        if let Some(context) = &self.context {
            context.validate_for(
                &job.task_id,
                &job.scope_id,
                &job.state_fence,
                &self.recipe.attempt.attempt_id,
                Some(&job.operation_id),
            )?;
        }
        Ok(())
    }

    fn validate_curation(&self) -> Result<(), ContractViolation> {
        let job = &self.recipe.job;
        if let Some(curation) = &self.curation {
            self.validate_curation_header(curation, job)?;
            for (role, handle) in [
                (
                    DreamInputRole::CurationSourceSnapshot,
                    &curation.source_snapshot_ref,
                ),
                (
                    DreamInputRole::CurationSourceDenominator,
                    &curation.source_denominator_ref,
                ),
                (
                    DreamInputRole::CurationScreenProfile,
                    &curation.screen_profile_ref,
                ),
                (
                    DreamInputRole::CurationProtectionCoverage,
                    &curation.protection_coverage_contract,
                ),
            ] {
                if !self.included_role_handle(role, handle) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "curation.reference",
                        reason: "Curation identity is not included in its exact retained role"
                            .to_owned(),
                    });
                }
            }
            let source = self
                .manifest
                .references
                .get(&curation.source_snapshot_ref)
                .ok_or(ContractViolation::BindingMismatch {
                    field: "curation.source_snapshot_ref",
                    reason: "Curation source snapshot is absent from manifest".to_owned(),
                })?;
            if source.source_revision != curation.source_revision {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.source_revision",
                    reason: "screened source revision differs from source reference".to_owned(),
                });
            }
            for evidence in &curation.payload.facets().evidence_refs {
                let included = ArtifactId::new(evidence.as_str())
                    .ok()
                    .is_some_and(|handle| {
                        self.included_role_handle(DreamInputRole::CurationEvidenceSet, &handle)
                    });
                if !included {
                    return Err(ContractViolation::BindingMismatch {
                        field: "curation.evidence_refs",
                        reason: "Curation evidence reference is outside selected material"
                            .to_owned(),
                    });
                }
            }
            for screen in &curation.screens {
                let handle = curation.target_materials.get(&screen.target_id).ok_or(
                    ContractViolation::BindingMismatch {
                        field: "curation.target_materials",
                        reason: "screen target has no retained material mapping".to_owned(),
                    },
                )?;
                if !self.included_role_handle(DreamInputRole::CurationTargetSet, handle) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "curation.target_materials",
                        reason: "target mapping references unselected material".to_owned(),
                    });
                }
                let material = self
                    .materials
                    .iter()
                    .find(|material| material.reference == *handle)
                    .ok_or(ContractViolation::BindingMismatch {
                        field: "curation.target_materials",
                        reason: "target mapping material is absent".to_owned(),
                    })?;
                if screen.item_digest != material.material.digest {
                    return Err(ContractViolation::BindingMismatch {
                        field: "curation.screens.item_digest",
                        reason: "screen item digest differs from mapped retained material"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_curation_header(
        &self,
        curation: &CurationMaterial,
        job: &crate::job::DreamJobInput,
    ) -> Result<(), ContractViolation> {
        if job.job_class != crate::job::JobClass::Curation {
            return Err(ContractViolation::BindingMismatch {
                field: "curation",
                reason: "Curation material is only valid for a Curation job".to_owned(),
            });
        }
        curation.validate_for(&job.task_id, &job.scope_id, &job.state_fence)?;
        if curation.source_snapshot != self.manifest.source_snapshot
            || curation.source_revision != self.manifest.source_revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.source_snapshot",
                reason: "Curation source identity differs from the full manifest".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns whether all mandatory Curation material is retained.
    #[must_use]
    pub fn has_complete_curation_material(&self) -> bool {
        self.curation.as_ref().is_some_and(|curation| {
            curation.validate().is_ok()
                && curation.screens.iter().all(|screen| {
                    matches!(
                        screen.state,
                        crate::screen::ScreenState::Eligible
                            | crate::screen::ScreenState::Protected
                            | crate::screen::ScreenState::ProtectionUnknown
                    )
                })
                && curation
                    .screens
                    .iter()
                    .all(|screen| self.curation_handle_matches_screen(curation, screen))
        })
    }

    fn included_role_handle(&self, role: DreamInputRole, handle: &ArtifactId) -> bool {
        self.materials.iter().any(|material| {
            material.role == role
                && material.reference == *handle
                && self.ledger.iter().any(|entry| {
                    entry.role == role
                        && entry.ordinal == material.ordinal
                        && entry.handle.as_ref() == Some(handle)
                        && entry.disposition == MaterialDisposition::Included
                })
        })
    }

    fn validate_conditional_evaluations(&self) -> Result<(), ContractViolation> {
        let expected = self
            .recipe
            .roles
            .iter()
            .filter(|role| {
                role.disposition == crate::assembly::recipe::RoleDisposition::Conditional
            })
            .count();
        check_vec_bound(
            self.conditional_evaluations.len(),
            MAX_ROLE_OUTCOMES,
            "material.conditional_evaluations",
        )?;
        if self.conditional_evaluations.len() != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional_evaluations",
                reason: "one evaluation is required for every conditional role".to_owned(),
            });
        }
        let mut seen = BTreeSet::new();
        for evaluation in &self.conditional_evaluations {
            self.validate_conditional_header(evaluation, &mut seen)?;
            match evaluation.state {
                ConditionalEvaluationState::True => match evaluation.condition.predicate {
                    crate::assembly::recipe::ConditionalPredicate::EvidenceAvailable
                    | crate::assembly::recipe::ConditionalPredicate::RolePresent => {
                        self.validate_conditional_true_evidence(evaluation)?;
                    }
                    crate::assembly::recipe::ConditionalPredicate::ConflictPresent => {
                        self.validate_conditional_conflict(evaluation)?;
                    }
                },
                ConditionalEvaluationState::KnownFalse => {
                    self.validate_conditional_known_false(evaluation)?;
                }
                ConditionalEvaluationState::Unresolved => {}
            }
        }
        if seen.len() != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional_evaluations",
                reason: "conditional evaluation role set is incomplete".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_conditional_header(
        &self,
        evaluation: &ConditionalEvaluation,
        seen: &mut BTreeSet<DreamInputRole>,
    ) -> Result<(), ContractViolation> {
        evaluation.validate()?;
        let role = self
            .recipe
            .roles
            .iter()
            .find(|role| role.role == evaluation.role)
            .ok_or(ContractViolation::BindingMismatch {
                field: "material.conditional.role",
                reason: "conditional evaluation role is absent from recipe".to_owned(),
            })?;
        if role.disposition != crate::assembly::recipe::RoleDisposition::Conditional
            || !seen.insert(evaluation.role)
            || role.condition.as_ref() != Some(&evaluation.condition)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.condition",
                reason: "evaluation does not bind the exact recipe condition".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_conditional_true_evidence(
        &self,
        evaluation: &ConditionalEvaluation,
    ) -> Result<(), ContractViolation> {
        if evaluation.evidence_items.is_empty()
            || evaluation.conflict_atom.is_some()
            || evaluation.evidence_items.iter().any(|identity| {
                identity.role != evaluation.condition.evidence_role
                    || !self.ledger.iter().any(|entry| {
                        entry.role == identity.role
                            && entry.ordinal == identity.ordinal
                            && entry.handle == identity.handle
                            && entry.content_digest == identity.content_digest
                            && entry.source_revision == identity.source_revision
                            && entry.disposition == MaterialDisposition::Included
                    })
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.evidence_items",
                reason: "true conditional lacks exact included earlier evidence".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_conditional_conflict(
        &self,
        evaluation: &ConditionalEvaluation,
    ) -> Result<(), ContractViolation> {
        if evaluation.evidence_items.is_empty()
            || evaluation.condition.evidence_role != DreamInputRole::ConflictsAndUnknowns
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.conflict",
                reason: "conflict predicate requires earlier conflict evidence".to_owned(),
            });
        }
        let Some(conflict) = &evaluation.conflict_atom else {
            return Err(ContractViolation::MissingField(
                "material.conditional.conflict_atom",
            ));
        };
        let Some(context) = &self.context else {
            return Err(ContractViolation::MissingField("material.context"));
        };
        if !context.view.rendered.iter().any(|atom| {
            atom.atom_id == conflict.atom_id
                && atom.role == SemanticRole::Conflict
                && atom.source_revision == conflict.source_revision
                && atom.source_digest == conflict.source_digest
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.conflict_atom",
                reason: "conflict atom is not an admitted A-15 Conflict witness".to_owned(),
            });
        }
        let conflict_atom = context.view.rendered.iter().find(|atom| {
            atom.atom_id == conflict.atom_id
                && atom.role == SemanticRole::Conflict
                && atom.source_revision == conflict.source_revision
                && atom.source_digest == conflict.source_digest
        });
        let Some(conflict_atom) = conflict_atom else {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.conflict_atom",
                reason: "conflict atom disappeared during identity join".to_owned(),
            });
        };
        if evaluation.evidence_items.iter().any(|identity| {
            identity.role != DreamInputRole::ConflictsAndUnknowns
                || identity.handle.is_none()
                || !self.ledger.iter().any(|entry| {
                    entry.role == identity.role
                        && entry.ordinal == identity.ordinal
                        && entry.handle == identity.handle
                        && entry.content_digest == identity.content_digest
                        && entry.source_revision == identity.source_revision
                        && entry.disposition == MaterialDisposition::Included
                })
                || identity
                    .handle
                    .as_ref()
                    .and_then(|handle| self.selected_references.get(handle))
                    .is_none_or(|reference| {
                        reference.source_revision != conflict.source_revision
                            || reference.content_digest != conflict.source_digest
                            || reference
                                .source_lineage
                                .as_ref()
                                .map(|lineage| lineage.owner != conflict_atom.source_identity)
                                .or_else(|| {
                                    reference.provenance.as_ref().and_then(|provenance| {
                                        provenance
                                            .lineage
                                            .iter()
                                            .find(|lineage| {
                                                lineage.content_digest == reference.content_digest
                                                    && lineage.revision == reference.source_revision
                                            })
                                            .map(|lineage| {
                                                lineage.owner != conflict_atom.source_identity
                                            })
                                    })
                                })
                                .unwrap_or(true)
                    })
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.conflict",
                reason: "conflict witness lacks the exact authorized evidence identity".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_conditional_known_false(
        &self,
        evaluation: &ConditionalEvaluation,
    ) -> Result<(), ContractViolation> {
        let binding = evaluation
            .condition
            .coverage
            .as_ref()
            .ok_or(ContractViolation::MissingField("role.condition.coverage"))?;
        let denominator = self
            .manifest
            .coverage_denominators
            .get(&binding.denominator)
            .ok_or(ContractViolation::BindingMismatch {
                field: "material.conditional.coverage",
                reason: "known-false denominator is absent".to_owned(),
            })?;
        let receipt = self
            .manifest
            .coverage_receipts
            .get(&binding.denominator)
            .ok_or(ContractViolation::BindingMismatch {
                field: "material.conditional.coverage",
                reason: "known-false receipt is absent".to_owned(),
            })?;
        if denominator.kind != eliot_epistemic_contracts::DenominatorKind::CompleteScope
            || denominator.roles.len() != 1
            || denominator.roles.iter().next().map(String::as_str)
                != Some(evaluation.condition.evidence_role.as_str())
            || !denominator.members.is_empty()
            || denominator.bounds.total != 0
            || denominator.bounds.truncated
            || denominator.query.is_none()
            || denominator.frontier.is_none()
            || receipt.digest != binding.receipt
            || receipt.denominator != binding.denominator
            || receipt.denominator_size != 0
            || !receipt.members.is_empty()
            || !receipt.omissions.is_empty()
            || receipt.fence != denominator.fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.conditional.coverage",
                reason: "known-false coverage pair does not close an empty scope".to_owned(),
            });
        }
        Ok(())
    }

    fn curation_handle_matches_screen(
        &self,
        curation: &CurationMaterial,
        screen: &ScreenReference,
    ) -> bool {
        let Some(handle) = curation.target_materials.get(&screen.target_id) else {
            return false;
        };
        self.included_role_handle(DreamInputRole::CurationTargetSet, handle)
            && self
                .materials
                .iter()
                .find(|material| material.reference == *handle)
                .is_some_and(|material| material.material.digest == screen.item_digest)
    }

    fn preflight_representation_bounds(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.materials.len(), MAX_MATERIALS, "material.materials")?;
        let mut total = 0_usize;
        for material in &self.materials {
            let length = match &material.representation {
                MaterialRepresentation::Utf8 { content, .. } => content.len(),
                MaterialRepresentation::Bytes { content, .. } => content.len(),
                MaterialRepresentation::HandleOnly { .. } => 0,
            };
            total = total.checked_add(length).ok_or(ContractViolation::Budget {
                dimension: "input_bytes",
                reason: "retained representation size overflow".to_owned(),
            })?;
            if total
                > usize::try_from(crate::budget::INPUT_BYTES_CEILING).map_err(|_| {
                    ContractViolation::Budget {
                        dimension: "input_bytes",
                        reason: "input byte ceiling does not fit this platform".to_owned(),
                    }
                })?
            {
                return Err(ContractViolation::Budget {
                    dimension: "input_bytes",
                    reason: "retained representations exceed class ceiling".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Schema version used by material closures.
pub const fn material_schema_version() -> u32 {
    MATERIAL_SCHEMA_VERSION
}
