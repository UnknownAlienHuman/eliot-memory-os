//! Typed, candidate-only records for the A-03 Failure handoff.

use eliot_contracts::StateFence;
use eliot_evidence::EvidenceEnvelope;
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptDisposition, ReceiptEnvelope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};
use crate::job::Requester;
use crate::relation::RelationPreservation;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_ITEMS: usize = 1024;
pub const MAX_TEXT: usize = 1024;

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    check_text(value, field, MAX_TEXT)
}
pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be lowercase sha256".to_owned(),
        })
    }
}
pub(crate) fn refs(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, value) in values.iter().enumerate() {
        text(value, field)?;
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate reference".to_owned(),
            });
        }
    }
    Ok(())
}
pub(crate) fn digest_refs(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, value) in values.iter().enumerate() {
        digest(value, field)?;
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate digest reference".to_owned(),
            });
        }
    }
    Ok(())
}
pub(crate) fn fence(fence: &StateFence) -> Result<(), ContractViolation> {
    check_fence(fence)
}

/// Completeness of a finite source, evidence, or history denominator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureCoverage {
    Complete,
    Partial,
    Unknown,
}

/// Failure observation states retained by the handoff.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureObservationState {
    NotAttempted,
    Rejected,
    Unavailable,
    PartiallyApplied,
    UnknownOutcome,
    ExecutedButSemanticallyFailed,
    VerifierFailed,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureExpectedState {
    Success,
    Failure,
    Partial,
    Unknown,
    Cancelled,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureExpectation {
    pub expected: FailureExpectedState,
    pub verifier: String,
}
impl FailureExpectation {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.verifier, "failure.outcome.verifier")
    }
}

struct ProposalWriter {
    len: usize,
    max: usize,
}
impl std::io::Write for ProposalWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("proposal length overflow"))?;
        if self.len > self.max {
            return Err(std::io::Error::other("bounded proposal exceeded"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Typed failure class vocabulary used by the handoff; semantic classification remains downstream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureClass {
    PreconditionOrInput,
    AuthorityOrPolicy,
    InfrastructureOrProvider,
    DispatchProcessOrTransport,
    PartialOrUnknownEffect,
    SemanticOutput,
    Verifier,
    CleanupRollbackOrReconciliation,
    TimeoutOrCancel,
    ChangedEnvironment,
    InternalContract,
}

/// Evidence role, preserving all admitted evidence streams without minting proof.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureEvidenceKind {
    Request,
    Admission,
    Attempt,
    Dispatch,
    Start,
    Acknowledgement,
    PossibleEffect,
    Artifact,
    SemanticVerifier,
    Environment,
    Control,
}

/// Exact trigger comparison profile. Missing dimensions are explicit and never wildcards.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureComparisonProfile {
    pub profile_id: String,
    pub schema_version: u32,
    pub comparator: FailureComparator,
    pub definition: FailureProfileDefinition,
    pub dimensions: Vec<FailureDimension>,
    pub missing_dimensions: Vec<String>,
}

/// Retained owner declaration for a comparison profile.  Observed values live
/// in `FailureDimension`; this record contains only the typed descriptor set
/// and the canonical bytes that were admitted from the current source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureProfileDefinition {
    pub owner: String,
    pub profile_id: String,
    pub schema_version: u32,
    pub revision: String,
    pub comparator: FailureComparator,
    pub descriptors: Vec<FailureDimensionDescriptor>,
    pub source_handle: String,
    pub definition_bytes: Vec<u8>,
    pub definition_digest: String,
    pub definition_bytes_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureDimensionDescriptor {
    pub source: FailureDimensionSource,
    pub field: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct FailureProfileDefinitionBody {
    owner: String,
    profile_id: String,
    schema_version: u32,
    revision: String,
    comparator: FailureComparator,
    descriptors: Vec<FailureDimensionDescriptor>,
    source_handle: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureDimension {
    pub source: FailureDimensionSource,
    pub field: String,
    pub name: String,
    pub value: FailureDimensionValue,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureDimensionSource {
    Action,
    Environment,
    Applicability,
    Scope,
    Receipt,
}

impl FailureDimension {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.name, "failure.profile.dimension.name")?;
        text(&self.field, "failure.profile.dimension.field")?;
        match &self.value {
            FailureDimensionValue::Text(value) => text(value, "failure.profile.dimension.value")?,
            FailureDimensionValue::Digest(value) => {
                digest(value, "failure.profile.dimension.value")?;
            }
            FailureDimensionValue::Bool(_) | FailureDimensionValue::Unsigned(_) => {}
            FailureDimensionValue::Missing => {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.dimension.value",
                    reason: "missing values belong in the explicit missing_dimensions partition"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureDimensionValue {
    Text(String),
    Digest(String),
    Bool(bool),
    Unsigned(u64),
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureComparator {
    ExactEquality,
    Unsupported,
}

impl FailureComparisonProfile {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.profile.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        text(&self.profile_id, "failure.profile.profile_id")?;
        self.definition.validate()?;
        if self.definition.profile_id != self.profile_id
            || self.definition.schema_version != self.schema_version
            || self.definition.comparator != self.comparator
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.definition",
                reason: "profile does not match its retained owner definition".to_owned(),
            });
        }
        check_vec_bound(
            self.dimensions.len(),
            MAX_ITEMS,
            "failure.profile.dimensions",
        )?;
        let mut names = Vec::new();
        let descriptor_names: Vec<&str> = self
            .definition
            .descriptors
            .iter()
            .map(|descriptor| descriptor.name.as_str())
            .collect();
        for dimension in &self.dimensions {
            dimension.validate()?;
            let Some(descriptor) = self
                .definition
                .descriptors
                .iter()
                .find(|descriptor| descriptor.name == dimension.name)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.dimensions",
                    reason: "observed dimension is absent from owner definition".to_owned(),
                });
            };
            if descriptor.source != dimension.source || descriptor.field != dimension.field {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.dimensions",
                    reason: "observed dimension source or field differs from owner definition"
                        .to_owned(),
                });
            }
            if names.contains(&dimension.name) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.dimensions",
                    reason: "duplicate dimension".to_owned(),
                });
            }
            names.push(dimension.name.clone());
        }
        refs(
            &self.missing_dimensions,
            "failure.profile.missing_dimensions",
        )?;
        if self
            .missing_dimensions
            .iter()
            .any(|name| !descriptor_names.contains(&name.as_str()))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.missing_dimensions",
                reason: "missing dimension is absent from owner definition".to_owned(),
            });
        }
        if names.iter().any(|d| self.missing_dimensions.contains(d)) {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.dimensions",
                reason: "dimension cannot be both present and missing".to_owned(),
            });
        }
        if self.definition.descriptors.iter().any(|descriptor| {
            !names.contains(&descriptor.name) && !self.missing_dimensions.contains(&descriptor.name)
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.missing_dimensions",
                reason: "every owner-defined dimension must be represented or explicitly missing"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl FailureProfileDefinition {
    pub fn from_parts(
        owner: String,
        profile_id: String,
        schema_version: u32,
        revision: String,
        comparator: FailureComparator,
        descriptors: Vec<FailureDimensionDescriptor>,
        source_handle: String,
    ) -> Result<Self, ContractViolation> {
        text(&owner, "failure.profile.definition.owner")?;
        text(&profile_id, "failure.profile.definition.profile_id")?;
        text(&revision, "failure.profile.definition.revision")?;
        text(&source_handle, "failure.profile.definition.source_handle")?;
        if schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.profile.definition.schema_version",
                min: 1,
                max: 1,
                got: schema_version.into(),
            });
        }
        check_vec_bound(
            descriptors.len(),
            MAX_ITEMS,
            "failure.profile.definition.descriptors",
        )?;
        let mut names = Vec::new();
        for descriptor in &descriptors {
            text(&descriptor.field, "failure.profile.definition.field")?;
            text(&descriptor.name, "failure.profile.definition.name")?;
            if names.contains(&descriptor.name) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.definition.descriptors",
                    reason: "duplicate owner dimension".to_owned(),
                });
            }
            names.push(descriptor.name.clone());
        }
        let body = FailureProfileDefinitionBody {
            owner: owner.clone(),
            profile_id: profile_id.clone(),
            schema_version,
            revision: revision.clone(),
            comparator,
            descriptors: descriptors.clone(),
            source_handle: source_handle.clone(),
        };
        let definition_bytes = canonical_bytes(&body)?;
        let definition = Self {
            owner,
            profile_id,
            schema_version,
            revision,
            comparator,
            descriptors,
            source_handle,
            definition_digest: eliot_contracts::sha256_hex(&definition_bytes),
            definition_bytes_len: definition_bytes.len() as u64,
            definition_bytes,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.owner, "failure.profile.definition.owner"),
            (&self.profile_id, "failure.profile.definition.profile_id"),
            (&self.revision, "failure.profile.definition.revision"),
            (
                &self.source_handle,
                "failure.profile.definition.source_handle",
            ),
        ] {
            text(value, field)?;
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.profile.definition.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        check_vec_bound(
            self.descriptors.len(),
            MAX_ITEMS,
            "failure.profile.definition.descriptors",
        )?;
        let mut names = Vec::new();
        for descriptor in &self.descriptors {
            text(&descriptor.field, "failure.profile.definition.field")?;
            text(&descriptor.name, "failure.profile.definition.name")?;
            if !names.iter().all(|name: &String| name != &descriptor.name) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.profile.definition.descriptors",
                    reason: "duplicate owner dimension".to_owned(),
                });
            }
            names.push(descriptor.name.clone());
        }
        check_vec_bound(
            self.definition_bytes.len(),
            1_048_576,
            "failure.profile.definition.bytes",
        )?;
        if self.definition_bytes_len != self.definition_bytes.len() as u64
            || eliot_contracts::sha256_hex(&self.definition_bytes) != self.definition_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.definition.bytes",
                reason: "definition byte count or digest differs from retained bytes".to_owned(),
            });
        }
        digest(&self.definition_digest, "failure.profile.definition.digest")?;
        let body = FailureProfileDefinitionBody {
            owner: self.owner.clone(),
            profile_id: self.profile_id.clone(),
            schema_version: self.schema_version,
            revision: self.revision.clone(),
            comparator: self.comparator,
            descriptors: self.descriptors.clone(),
            source_handle: self.source_handle.clone(),
        };
        if canonical_bytes(&body)? != self.definition_bytes {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.profile.definition.bytes",
                reason: "retained bytes are not the canonical owner definition".to_owned(),
            });
        }
        Ok(())
    }
}

/// Operation and identity joins shared by every Failure record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureOperation {
    pub operation_id: String,
    pub idempotency_key: String,
    pub request_id: String,
    pub candidate_id: String,
    pub attempt_id: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub requester: Requester,
}

impl FailureOperation {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.operation_id, "failure.operation_id"),
            (&self.idempotency_key, "failure.idempotency_key"),
            (&self.request_id, "failure.request_id"),
            (&self.candidate_id, "failure.candidate_id"),
            (&self.attempt_id, "failure.attempt_id"),
            (&self.task_id, "failure.task_id"),
            (&self.scope_id, "failure.scope_id"),
        ] {
            text(v, f)?;
        }
        fence(&self.state_fence)?;
        self.requester.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureAction {
    pub action_id: String,
    pub operation_id: String,
    pub attempt_id: String,
    pub target_id: String,
    pub input_schema: String,
    pub input_digest: String,
    pub effect_id: String,
    pub effect_class: EffectClass,
    pub owner: String,
    pub contract_revision: String,
    pub contract_digest: String,
}
impl FailureAction {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.action_id, "failure.action_id"),
            (&self.operation_id, "failure.action.operation_id"),
            (&self.attempt_id, "failure.action.attempt_id"),
            (&self.target_id, "failure.action.target_id"),
            (&self.input_schema, "failure.action.input_schema"),
            (&self.effect_id, "failure.action.effect_id"),
            (&self.owner, "failure.action.owner"),
            (&self.contract_revision, "failure.action.contract_revision"),
        ] {
            text(v, f)?;
        }
        digest(&self.input_digest, "failure.action.input_digest")?;
        digest(&self.contract_digest, "failure.action.contract_digest")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureOutcome {
    pub intended: FailureExpectation,
    pub attempted: Option<FailureExpectation>,
    pub observed: ReceiptDisposition,
    pub verified: ReceiptDisposition,
    /// Fine A-03 observation retained alongside the canonical receipt outcome.
    #[serde(default)]
    pub failure_state: Option<FailureObservationState>,
    /// Receipt that is the source of the observed disposition, when one was retained.
    #[serde(default)]
    pub observed_receipt_ref: Option<String>,
    /// Receipt that is the source of the verified disposition, when one was retained.
    #[serde(default)]
    pub verified_receipt_ref: Option<String>,
    pub output_digest: Option<String>,
    pub possible_effects: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub coverage: FailureCoverage,
}
impl FailureOutcome {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.intended.validate()?;
        if let Some(v) = &self.attempted {
            v.validate()?;
        }
        if let Some(d) = &self.output_digest {
            digest(d, "failure.outcome.output_digest")?;
        }
        refs(&self.possible_effects, "failure.outcome.possible_effects")?;
        refs(&self.receipt_refs, "failure.outcome.receipt_refs")?;
        for (value, field) in [
            (
                &self.observed_receipt_ref,
                "failure.outcome.observed_receipt_ref",
            ),
            (
                &self.verified_receipt_ref,
                "failure.outcome.verified_receipt_ref",
            ),
        ] {
            if let Some(value) = value {
                text(value, field)?;
                if !self.receipt_refs.contains(value) {
                    return Err(ContractViolation::BindingMismatch {
                        field,
                        reason: "disposition receipt must be in receipt_refs".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureEvidence {
    pub evidence_id: String,
    pub kind: FailureEvidenceKind,
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub action_id: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub digest: String,
    pub envelope_digest: String,
    /// Current bundle material that carries the evidence payload.  This is a
    /// separate binding from the envelope's original provenance/raw handle.
    pub material_handle: String,
    pub material_digest: String,
    pub material_bytes: Vec<u8>,
    pub owner: String,
    pub coverage: FailureCoverage,
}
impl FailureEvidence {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.evidence_id, "failure.evidence.evidence_id"),
            (&self.operation_id, "failure.evidence.operation_id"),
            (&self.request_id, "failure.evidence.request_id"),
            (&self.idempotency_key, "failure.evidence.idempotency_key"),
            (&self.action_id, "failure.evidence.action_id"),
            (&self.task_id, "failure.evidence.task_id"),
            (&self.scope_id, "failure.evidence.scope_id"),
            (&self.owner, "failure.evidence.owner"),
        ] {
            text(v, f)?;
        }
        digest(&self.digest, "failure.evidence.digest")?;
        digest(&self.envelope_digest, "failure.evidence.envelope_digest")?;
        text(&self.material_handle, "failure.evidence.material_handle")?;
        digest(&self.material_digest, "failure.evidence.material_digest")?;
        check_vec_bound(
            self.material_bytes.len(),
            1_048_576,
            "failure.evidence.material_bytes",
        )?;
        if eliot_contracts::sha256_hex(&self.material_bytes) != self.material_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.evidence.material_digest",
                reason: "evidence material digest does not match retained bytes".to_owned(),
            });
        }
        fence(&self.state_fence)
    }
}

/// Exact current source material for one canonical receipt envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureReceiptMaterial {
    pub receipt_id: String,
    pub handle: String,
    pub digest: String,
    pub bytes: Vec<u8>,
}
impl FailureReceiptMaterial {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.receipt_id, "failure.receipt_material.receipt_id")?;
        text(&self.handle, "failure.receipt_material.handle")?;
        digest(&self.digest, "failure.receipt_material.digest")?;
        check_vec_bound(
            self.bytes.len(),
            1_048_576,
            "failure.receipt_material.bytes",
        )?;
        if eliot_contracts::sha256_hex(&self.bytes) != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.receipt_material.digest",
                reason: "receipt material digest does not match retained bytes".to_owned(),
            });
        }
        Ok(())
    }
}

/// A retained source member from the frozen bundle/read projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureSourceMember {
    pub handle: String,
    pub digest: String,
    pub bytes: Vec<u8>,
    pub source_snapshot: String,
    pub source_revision: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
}
impl FailureSourceMember {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.handle, "failure.source.handle"),
            (&self.source_snapshot, "failure.source.snapshot"),
            (&self.source_revision, "failure.source.revision"),
            (&self.task_id, "failure.source.task_id"),
            (&self.scope_id, "failure.source.scope_id"),
        ] {
            text(v, f)?;
        }
        digest(&self.digest, "failure.source.digest")?;
        check_vec_bound(self.bytes.len(), 1_048_576, "failure.source.bytes")?;
        if eliot_contracts::sha256_hex(&self.bytes) != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.source.digest",
                reason: "source digest does not match retained bytes".to_owned(),
            });
        }
        fence(&self.state_fence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureActionEvidence {
    pub action_operation: FailureOperation,
    pub action: FailureAction,
    pub outcome: FailureOutcome,
    pub evidence: Vec<FailureEvidence>,
    pub receipts: Vec<ReceiptEnvelope>,
    pub receipt_materials: Vec<FailureReceiptMaterial>,
    pub evidence_envelopes: Vec<EvidenceEnvelope>,
    /// Canonical envelope digests deliberately omitted under partial coverage.
    pub omitted_envelope_refs: Vec<String>,
    pub coverage: FailureCoverage,
}
impl FailureActionEvidence {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_identity_and_receipts()?;
        self.validate_envelopes()
    }

    fn validate_identity_and_receipts(&self) -> Result<(), ContractViolation> {
        self.action_operation.validate()?;
        self.action.validate()?;
        self.outcome.validate()?;
        check_vec_bound(self.evidence.len(), MAX_ITEMS, "failure.evidence")?;
        if matches!(self.coverage, FailureCoverage::Complete)
            && (self.evidence.is_empty()
                || self.receipts.is_empty()
                || self.evidence_envelopes.is_empty())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.action_evidence.coverage",
                reason: "complete action evidence requires retained evidence and receipt streams"
                    .to_owned(),
            });
        }
        let mut ids = Vec::new();
        for e in &self.evidence {
            e.validate()?;
            if ids.contains(&e.evidence_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.evidence",
                    reason: "duplicate evidence identity".to_owned(),
                });
            }
            ids.push(e.evidence_id.clone());
            if e.operation_id != self.action_operation.operation_id
                || e.request_id != self.action_operation.request_id
                || e.idempotency_key != self.action_operation.idempotency_key
                || e.action_id != self.action.action_id
                || e.task_id != self.action_operation.task_id
                || e.scope_id != self.action_operation.scope_id
                || e.state_fence != self.action_operation.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.evidence.join",
                    reason: "evidence action-operation identity/fence mismatch".to_owned(),
                });
            }
        }
        self.validate_receipt_identity()?;
        for receipt_ref in &self.outcome.receipt_refs {
            let Some(receipt) = self
                .receipts
                .iter()
                .find(|r| r.identity.receipt_id.as_str() == receipt_ref)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.outcome.receipt_refs",
                    reason: "receipt reference is outside retained receipt set".to_owned(),
                });
            };
            if self
                .outcome
                .observed_receipt_ref
                .as_deref()
                .is_some_and(|id| id == receipt_ref)
                && self.outcome.observed != receipt.core.disposition
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.outcome.observed",
                    reason: "observed disposition differs from its retained receipt".to_owned(),
                });
            }
            if self
                .outcome
                .verified_receipt_ref
                .as_deref()
                .is_some_and(|id| id == receipt_ref)
                && self.outcome.verified != receipt.core.disposition
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.outcome.verified",
                    reason: "verified disposition differs from its retained receipt".to_owned(),
                });
            }
        }
        if self.action.operation_id != self.action_operation.operation_id
            || self.action_operation.attempt_id != self.action.attempt_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.action.operation_id",
                reason: "failed action operation join mismatch".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_receipt_identity(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.receipts.len(), MAX_ITEMS, "failure.receipts")?;
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|e| ContractViolation::Malformed {
                    field: "failure.receipts",
                    reason: e.to_string(),
                })?;
        }
        check_vec_bound(
            self.receipt_materials.len(),
            MAX_ITEMS,
            "failure.receipt_materials",
        )?;
        let mut material_ids = Vec::new();
        for material in &self.receipt_materials {
            material.validate()?;
            if material_ids.contains(&material.receipt_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipt_materials",
                    reason: "duplicate receipt material identity".to_owned(),
                });
            }
            material_ids.push(material.receipt_id.clone());
            let Some(receipt) = self
                .receipts
                .iter()
                .find(|receipt| receipt.identity.receipt_id.as_str() == material.receipt_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipt_materials.receipt_id",
                    reason: "receipt material is outside retained receipts".to_owned(),
                });
            };
            let canonical =
                receipt
                    .canonical_bytes()
                    .map_err(|e| ContractViolation::Malformed {
                        field: "failure.receipt_materials.bytes",
                        reason: e.to_string(),
                    })?;
            if canonical != material.bytes || receipt.canonical_sha256() != material.digest {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipt_materials.bytes",
                    reason: "receipt material is not the exact canonical envelope".to_owned(),
                });
            }
        }
        if self.receipt_materials.len() != self.receipts.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.receipt_materials",
                reason: "every retained receipt requires one canonical material wrapper".to_owned(),
            });
        }
        let mut receipt_ids = Vec::new();
        for receipt in &self.receipts {
            let receipt_id = receipt.identity.receipt_id.as_str();
            if receipt_ids.iter().any(|id| id == receipt_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.receipts",
                    reason: "duplicate receipt identity".to_owned(),
                });
            }
            receipt_ids.push(receipt_id.to_owned());
            let operation = &receipt.core.operation;
            if operation.operation_id.as_str() != self.action_operation.operation_id
                || operation.request_id.as_str() != self.action_operation.request_id
                || operation.idempotency_key != self.action_operation.idempotency_key
                || operation.effect != self.action.effect_class
                || operation.state_fence != self.action_operation.state_fence
                || receipt.core.request.state_fence != self.action_operation.state_fence
                || receipt.core.work_scope.scope_id.as_str() != self.action_operation.scope_id
                || receipt.core.work_scope.state_fence != self.action_operation.state_fence
                || receipt.core.task.as_ref().is_some_and(|task| {
                    task.task_id.as_str() != self.action_operation.task_id
                        || task.state_fence != self.action_operation.state_fence
                })
            {
                return Err(ContractViolation::BindingMismatch { field: "failure.receipts.join", reason: "failed action receipt does not retain the original operation/request/idempotency/effect/task/scope/fence".to_owned() });
            }
        }
        Ok(())
    }

    fn validate_envelopes(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.evidence_envelopes.len(),
            MAX_ITEMS,
            "failure.evidence_envelopes",
        )?;
        for envelope in &self.evidence_envelopes {
            envelope
                .validate()
                .map_err(|e| ContractViolation::Malformed {
                    field: "failure.evidence_envelopes",
                    reason: e.to_string(),
                })?;
        }
        let envelope_digests: Vec<String> = self
            .evidence_envelopes
            .iter()
            .map(|envelope| canonical_bytes(envelope).map(|bytes| digest_hex(&bytes)))
            .collect::<Result<_, _>>()?;
        if envelope_digests
            .iter()
            .enumerate()
            .any(|(index, digest)| envelope_digests[..index].contains(digest))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.evidence_envelopes",
                reason: "duplicate canonical evidence envelope".to_owned(),
            });
        }
        digest_refs(
            &self.omitted_envelope_refs,
            "failure.evidence.omitted_envelope_refs",
        )?;
        if self
            .omitted_envelope_refs
            .iter()
            .any(|digest| envelope_digests.contains(digest))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.evidence.omitted_envelope_refs",
                reason: "an envelope cannot be both retained and omitted".to_owned(),
            });
        }
        let declared: Vec<&str> = self
            .evidence
            .iter()
            .map(|evidence| evidence.envelope_digest.as_str())
            .collect();
        if self
            .omitted_envelope_refs
            .iter()
            .any(|digest| !declared.contains(&digest.as_str()))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.evidence.omitted_envelope_refs",
                reason: "omitted envelope is outside the declared evidence stream".to_owned(),
            });
        }
        if matches!(self.coverage, FailureCoverage::Complete)
            && !self.omitted_envelope_refs.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.evidence.omitted_envelope_refs",
                reason: "complete action evidence cannot omit envelopes".to_owned(),
            });
        }
        for evidence in &self.evidence {
            let Some(envelope) = self.evidence_envelopes.iter().find(|envelope| {
                canonical_bytes(envelope)
                    .is_ok_and(|bytes| digest_hex(&bytes) == evidence.envelope_digest)
            }) else {
                if self
                    .omitted_envelope_refs
                    .contains(&evidence.envelope_digest)
                {
                    continue;
                }
                return Err(ContractViolation::BindingMismatch { field: "failure.evidence.envelope_digest", reason: "represented evidence lacks a retained or explicitly omitted canonical envelope".to_owned() });
            };
            if envelope.state_fence != evidence.state_fence
                || canonical_bytes(envelope)? != evidence.material_bytes
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.evidence.material_bytes",
                    reason: "evidence material bytes differ from canonical envelope bytes"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureEnvironment {
    pub environment_id: String,
    pub environment_revision: String,
    pub platform: String,
    pub tool_revision: String,
    pub model_revision: Option<String>,
    pub config_revision: String,
    pub capability_revision: String,
    pub policy_revision: String,
    pub state_fence: StateFence,
    pub coverage: FailureCoverage,
}
impl FailureEnvironment {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.environment_id, "failure.environment.id"),
            (&self.environment_revision, "failure.environment.revision"),
            (&self.platform, "failure.environment.platform"),
            (&self.tool_revision, "failure.environment.tool_revision"),
            (&self.config_revision, "failure.environment.config_revision"),
            (
                &self.capability_revision,
                "failure.environment.capability_revision",
            ),
            (&self.policy_revision, "failure.environment.policy_revision"),
        ] {
            text(v, f)?;
        }
        if let Some(v) = &self.model_revision {
            text(v, "failure.environment.model_revision")?;
        }
        fence(&self.state_fence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureApplicability {
    pub task_id: String,
    pub scope_id: String,
    pub target_id: String,
    pub environment_id: String,
    pub platform: String,
    pub tool_revision: String,
    pub model_revision: Option<String>,
    pub config_revision: String,
    pub capability_revision: String,
    pub effect_class: EffectClass,
    pub coverage: FailureCoverage,
}
impl FailureApplicability {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.task_id, "failure.applicability.task_id"),
            (&self.scope_id, "failure.applicability.scope_id"),
            (&self.target_id, "failure.applicability.target_id"),
            (&self.environment_id, "failure.applicability.environment_id"),
            (&self.platform, "failure.applicability.platform"),
            (&self.tool_revision, "failure.applicability.tool_revision"),
            (
                &self.config_revision,
                "failure.applicability.config_revision",
            ),
            (
                &self.capability_revision,
                "failure.applicability.capability_revision",
            ),
        ] {
            text(v, f)?;
        }
        if let Some(v) = &self.model_revision {
            text(v, "failure.applicability.model_revision")?;
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureHistoryEntry {
    pub history_id: String,
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub fingerprint_id: String,
    pub trigger_digest: String,
    pub outcome: ReceiptDisposition,
    pub failure_state: Option<FailureObservationState>,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub independent: bool,
    pub semantic_success: bool,
    pub near_match: bool,
    pub false_activation: bool,
    pub observed: bool,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
    pub coverage: FailureCoverage,
}
impl FailureHistoryEntry {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.history_id, "failure.history.id"),
            (&self.operation_id, "failure.history.operation_id"),
            (&self.request_id, "failure.history.request_id"),
            (&self.idempotency_key, "failure.history.idempotency_key"),
            (&self.fingerprint_id, "failure.history.fingerprint_id"),
            (&self.task_id, "failure.history.task_id"),
            (&self.scope_id, "failure.history.scope_id"),
        ] {
            text(v, f)?;
        }
        digest(&self.trigger_digest, "failure.history.trigger_digest")?;
        refs(&self.evidence_refs, "failure.history.evidence_refs")?;
        refs(&self.receipt_refs, "failure.history.receipt_refs")?;
        fence(&self.state_fence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureHistory {
    pub coverage: FailureCoverage,
    pub expected_total: u32,
    pub entries: Vec<FailureHistoryEntry>,
    pub omitted_refs: Vec<String>,
    pub success_count: u32,
    pub near_match_count: u32,
    pub false_activation_count: u32,
    pub unknown_count: u32,
    pub receipts: Vec<ReceiptEnvelope>,
    pub receipt_materials: Vec<FailureReceiptMaterial>,
    pub historical_evidence: Vec<FailureEvidence>,
    pub historical_evidence_envelopes: Vec<EvidenceEnvelope>,
    /// Canonical envelope digests deliberately omitted under partial coverage.
    pub omitted_evidence_envelope_refs: Vec<String>,
}
impl FailureHistory {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.expected_total as usize,
            MAX_ITEMS,
            "failure.history.expected_total",
        )?;
        check_vec_bound(self.entries.len(), MAX_ITEMS, "failure.history.entries")?;
        refs(&self.omitted_refs, "failure.history.omitted_refs")?;
        self.validate_receipts()?;
        self.validate_historical_evidence_stream()?;
        self.validate_history_entries()
    }

    fn validate_receipts(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.receipts.len(), MAX_ITEMS, "failure.history.receipts")?;
        for receipt in &self.receipts {
            receipt
                .validate()
                .map_err(|e| ContractViolation::Malformed {
                    field: "failure.history.receipts",
                    reason: e.to_string(),
                })?;
        }
        check_vec_bound(
            self.receipt_materials.len(),
            MAX_ITEMS,
            "failure.history.receipt_materials",
        )?;
        let mut material_ids = Vec::new();
        for material in &self.receipt_materials {
            material.validate()?;
            if material_ids.contains(&material.receipt_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipt_materials",
                    reason: "duplicate historical receipt material identity".to_owned(),
                });
            }
            material_ids.push(material.receipt_id.clone());
            let Some(receipt) = self
                .receipts
                .iter()
                .find(|receipt| receipt.identity.receipt_id.as_str() == material.receipt_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipt_materials.receipt_id",
                    reason: "historical receipt material is outside retained receipts".to_owned(),
                });
            };
            let canonical =
                receipt
                    .canonical_bytes()
                    .map_err(|e| ContractViolation::Malformed {
                        field: "failure.history.receipt_materials.bytes",
                        reason: e.to_string(),
                    })?;
            if canonical != material.bytes || receipt.canonical_sha256() != material.digest {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipt_materials.bytes",
                    reason: "historical receipt material is not the exact canonical envelope"
                        .to_owned(),
                });
            }
        }
        if self.receipt_materials.len() != self.receipts.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.receipt_materials",
                reason: "every retained historical receipt requires one canonical material wrapper"
                    .to_owned(),
            });
        }
        let mut receipt_ids = Vec::new();
        for receipt in &self.receipts {
            let id = receipt.identity.receipt_id.as_str();
            if receipt_ids.iter().any(|seen| seen == id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipts",
                    reason: "duplicate historical receipt identity".to_owned(),
                });
            }
            receipt_ids.push(id.to_owned());
        }
        Ok(())
    }

    fn validate_historical_evidence_stream(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.historical_evidence.len(),
            MAX_ITEMS,
            "failure.history.historical_evidence",
        )?;
        let mut ids = Vec::new();
        for evidence in &self.historical_evidence {
            evidence.validate()?;
            if ids.contains(&evidence.evidence_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.historical_evidence",
                    reason: "duplicate historical evidence identity".to_owned(),
                });
            }
            ids.push(evidence.evidence_id.clone());
        }
        self.validate_historical_envelopes()
    }

    fn validate_historical_envelopes(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.historical_evidence_envelopes.len(),
            MAX_ITEMS,
            "failure.history.historical_evidence_envelopes",
        )?;
        for envelope in &self.historical_evidence_envelopes {
            envelope
                .validate()
                .map_err(|e| ContractViolation::Malformed {
                    field: "failure.history.historical_evidence_envelopes",
                    reason: e.to_string(),
                })?;
        }
        let digests: Vec<String> = self
            .historical_evidence_envelopes
            .iter()
            .map(|envelope| canonical_bytes(envelope).map(|bytes| digest_hex(&bytes)))
            .collect::<Result<_, _>>()?;
        if digests
            .iter()
            .enumerate()
            .any(|(index, digest)| digests[..index].contains(digest))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.historical_evidence_envelopes",
                reason: "duplicate canonical historical evidence envelope".to_owned(),
            });
        }
        digest_refs(
            &self.omitted_evidence_envelope_refs,
            "failure.history.omitted_evidence_envelope_refs",
        )?;
        if self
            .omitted_evidence_envelope_refs
            .iter()
            .any(|digest| digests.contains(digest))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.omitted_evidence_envelope_refs",
                reason: "an historical envelope cannot be both retained and omitted".to_owned(),
            });
        }
        let declared: Vec<&str> = self
            .historical_evidence
            .iter()
            .map(|evidence| evidence.envelope_digest.as_str())
            .collect();
        if self
            .omitted_evidence_envelope_refs
            .iter()
            .any(|digest| !declared.contains(&digest.as_str()))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.omitted_evidence_envelope_refs",
                reason: "omitted historical envelope is outside the declared evidence stream"
                    .to_owned(),
            });
        }
        if matches!(self.coverage, FailureCoverage::Complete)
            && !self.omitted_evidence_envelope_refs.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.omitted_evidence_envelope_refs",
                reason: "complete history cannot omit evidence envelopes".to_owned(),
            });
        }
        for evidence in &self.historical_evidence {
            let Some(envelope) = self.historical_evidence_envelopes.iter().find(|envelope| {
                canonical_bytes(envelope)
                    .is_ok_and(|bytes| digest_hex(&bytes) == evidence.envelope_digest)
            }) else {
                if self
                    .omitted_evidence_envelope_refs
                    .contains(&evidence.envelope_digest)
                {
                    continue;
                }
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.evidence.envelope_digest",
                    reason: "represented historical evidence lacks its canonical envelope"
                        .to_owned(),
                });
            };
            if envelope.state_fence != evidence.state_fence
                || canonical_bytes(envelope)? != evidence.material_bytes
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.evidence.material_bytes",
                    reason:
                        "historical evidence material bytes differ from canonical envelope bytes"
                            .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_history_entries(&self) -> Result<(), ContractViolation> {
        let represented = self
            .entries
            .len()
            .checked_add(self.omitted_refs.len())
            .ok_or(ContractViolation::OutOfBounds {
                field: "failure.history.denominator",
                min: 0,
                max: i64::try_from(MAX_ITEMS).unwrap_or(i64::MAX),
                got: i64::MAX,
            })?;
        if represented != self.expected_total as usize {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.denominator",
                reason: "entries plus omitted refs must equal expected_total".to_owned(),
            });
        }
        let mut ids = Vec::new();
        let mut success = 0u32;
        let mut near = 0u32;
        let mut false_activation = 0u32;
        let mut unknown = 0u32;
        for entry in &self.entries {
            entry.validate()?;
            if ids.contains(&entry.history_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.entries",
                    reason: "duplicate history identity".to_owned(),
                });
            }
            ids.push(entry.history_id.clone());
            self.validate_entry_receipts_and_evidence(entry)?;
            success = success
                .checked_add(u32::from(entry.semantic_success))
                .ok_or(ContractViolation::OutOfBounds {
                    field: "failure.history.success_count",
                    min: 0,
                    max: i64::from(u32::MAX),
                    got: i64::MAX,
                })?;
            near = near.checked_add(u32::from(entry.near_match)).ok_or(
                ContractViolation::OutOfBounds {
                    field: "failure.history.near_match_count",
                    min: 0,
                    max: i64::from(u32::MAX),
                    got: i64::MAX,
                },
            )?;
            false_activation = false_activation
                .checked_add(u32::from(entry.false_activation))
                .ok_or(ContractViolation::OutOfBounds {
                    field: "failure.history.false_activation_count",
                    min: 0,
                    max: i64::from(u32::MAX),
                    got: i64::MAX,
                })?;
            unknown = unknown
                .checked_add(u32::from(matches!(
                    entry.outcome.kind(),
                    eliot_receipts::ReceiptDispositionKind::Unknown
                )))
                .ok_or(ContractViolation::OutOfBounds {
                    field: "failure.history.unknown_count",
                    min: 0,
                    max: i64::from(u32::MAX),
                    got: i64::MAX,
                })?;
        }
        if (success, near, false_activation, unknown)
            != (
                self.success_count,
                self.near_match_count,
                self.false_activation_count,
                self.unknown_count,
            )
        {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.counts",
                reason: "history counters do not reconcile with represented entries".to_owned(),
            });
        }
        if matches!(self.coverage, FailureCoverage::Complete) && !self.omitted_refs.is_empty() {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.history.coverage",
                reason: "complete history cannot omit members".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_entry_receipts_and_evidence(
        &self,
        entry: &FailureHistoryEntry,
    ) -> Result<(), ContractViolation> {
        for receipt_ref in &entry.receipt_refs {
            let Some(receipt) = self
                .receipts
                .iter()
                .find(|receipt| receipt.identity.receipt_id.as_str() == receipt_ref)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipt_refs",
                    reason: "historical receipt is outside retained set".to_owned(),
                });
            };
            if receipt.core.operation.operation_id.as_str() != entry.operation_id
                || receipt.core.operation.request_id.as_str() != entry.request_id
                || receipt.core.operation.idempotency_key != entry.idempotency_key
                || receipt.core.operation.state_fence != entry.state_fence
                || receipt.core.work_scope.scope_id.as_str() != entry.scope_id
                || receipt.core.work_scope.state_fence != entry.state_fence
                || receipt.core.task.as_ref().is_some_and(|task| {
                    task.task_id.as_str() != entry.task_id || task.state_fence != entry.state_fence
                })
                || receipt.core.disposition != entry.outcome
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.receipts.join",
                    reason: "historical receipt identity/fence/scope drift".to_owned(),
                });
            }
        }
        for evidence_ref in &entry.evidence_refs {
            let Some(evidence) = self
                .historical_evidence
                .iter()
                .find(|evidence| &evidence.evidence_id == evidence_ref)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.evidence_refs",
                    reason: "historical evidence is outside retained history evidence".to_owned(),
                });
            };
            if evidence.operation_id != entry.operation_id
                || evidence.request_id != entry.request_id
                || evidence.idempotency_key != entry.idempotency_key
                || evidence.task_id != entry.task_id
                || evidence.scope_id != entry.scope_id
                || evidence.state_fence != entry.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "failure.history.evidence.join",
                    reason: "historical evidence operation/fence differs".to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FailureCausalStatus {
    Structural,
    BehavioralCorrelation,
    CausalHypothesis,
    PredictionSupported,
    InterventionSupported,
    Refuted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureHypothesis {
    pub hypothesis_id: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub limitation_refs: Vec<String>,
    pub rival_refs: Vec<String>,
    pub confounder_refs: Vec<String>,
    pub status: FailureCausalStatus,
}
impl FailureHypothesis {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.hypothesis_id, "failure.hypothesis.id")?;
        text(&self.statement, "failure.hypothesis.statement")?;
        refs(&self.evidence_refs, "failure.hypothesis.evidence_refs")?;
        refs(&self.limitation_refs, "failure.hypothesis.limitation_refs")?;
        refs(&self.rival_refs, "failure.hypothesis.rival_refs")?;
        refs(&self.confounder_refs, "failure.hypothesis.confounder_refs")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureMitigation {
    pub do_not_repeat_until: String,
    pub note: String,
    pub owner: String,
    pub safe_reattempt_verifier: String,
    pub verifier_revision: String,
    pub verifier_digest: String,
    pub verifier_receipt_ref: String,
}
impl FailureMitigation {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (
                &self.do_not_repeat_until,
                "failure.mitigation.do_not_repeat_until",
            ),
            (&self.note, "failure.mitigation.note"),
            (&self.owner, "failure.mitigation.owner"),
            (&self.safe_reattempt_verifier, "failure.mitigation.verifier"),
            (
                &self.verifier_revision,
                "failure.mitigation.verifier_revision",
            ),
            (
                &self.verifier_receipt_ref,
                "failure.mitigation.verifier_receipt_ref",
            ),
        ] {
            text(v, f)?;
        }
        digest(&self.verifier_digest, "failure.mitigation.verifier_digest")
    }
}

/// Retained control and counterexample record; it has no admission authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureControlRecord {
    pub control_id: String,
    pub owner: String,
    pub condition: String,
    pub verifier_refs: Vec<String>,
    pub state_fence: StateFence,
    pub task_id: String,
    pub scope_id: String,
}
impl FailureControlRecord {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (v, f) in [
            (&self.control_id, "failure.control.id"),
            (&self.owner, "failure.control.owner"),
            (&self.condition, "failure.control.condition"),
            (&self.task_id, "failure.control.task_id"),
            (&self.scope_id, "failure.control.scope_id"),
        ] {
            text(v, f)?;
        }
        refs(&self.verifier_refs, "failure.control.verifier_refs")?;
        fence(&self.state_fence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureLifecycle {
    pub reopen_condition: String,
    pub extinction_condition: String,
    pub expiry_ms: Option<u64>,
    pub inverse_refs: Vec<String>,
    pub predecessor_fingerprint: Option<String>,
    pub current_fingerprint_revision: String,
    pub raw_history_refs: Vec<String>,
}
impl FailureLifecycle {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        text(&self.reopen_condition, "failure.lifecycle.reopen")?;
        text(&self.extinction_condition, "failure.lifecycle.extinction")?;
        refs(&self.inverse_refs, "failure.lifecycle.inverse_refs")?;
        refs(&self.raw_history_refs, "failure.lifecycle.raw_history_refs")?;
        text(
            &self.current_fingerprint_revision,
            "failure.lifecycle.revision",
        )?;
        if let Some(v) = &self.predecessor_fingerprint {
            digest(v, "failure.lifecycle.predecessor")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureRollback {
    pub predecessor: Option<String>,
    pub inverse_refs: Vec<String>,
    pub invalidation_refs: Vec<String>,
    pub raw_history_refs: Vec<String>,
    pub note: String,
}
impl FailureRollback {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(v) = &self.predecessor {
            text(v, "failure.rollback.predecessor")?;
        }
        refs(&self.inverse_refs, "failure.rollback.inverse_refs")?;
        refs(
            &self.invalidation_refs,
            "failure.rollback.invalidation_refs",
        )?;
        refs(&self.raw_history_refs, "failure.rollback.raw_history_refs")?;
        text(&self.note, "failure.rollback.note")
    }
}

/// Candidate-only structured Failure proposal; it carries no state mutation or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureProposal {
    pub schema_version: u32,
    pub candidate_id: String,
    pub fingerprint: String,
    pub signature: String,
    pub operation: FailureOperation,
    pub class: FailureClass,
    pub target_evidence: crate::curation::TargetEvidence,
    pub comparison: FailureComparisonProfile,
    pub trigger: Vec<FailureDimension>,
    pub action: FailureAction,
    pub outcome: FailureOutcome,
    pub environment: FailureEnvironment,
    pub applicability: FailureApplicability,
    pub violated_invariant: String,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub causal: FailureHypothesis,
    pub controls: Vec<FailureControlRecord>,
    pub mitigation: FailureMitigation,
    pub lifecycle: FailureLifecycle,
    pub history: FailureHistory,
    pub preservation: RelationPreservation,
    pub source_refs: Vec<String>,
    pub policy_digest: String,
    pub proof_ceiling: ProofCeiling,
}
impl FailureProposal {
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        let mut writer = ProposalWriter {
            len: 0,
            max: 4 * 1024 * 1024,
        };
        match serde_json::to_writer(&mut writer, self) {
            Ok(()) => Ok(()),
            Err(_error) if writer.len > writer.max => Err(ContractViolation::OutOfBounds {
                field: "failure.proposal_bytes",
                min: 0,
                max: i64::try_from(writer.max).unwrap_or(i64::MAX),
                got: i64::try_from(writer.len).unwrap_or(i64::MAX),
            }),
            Err(error) => Err(ContractViolation::Malformed {
                field: "failure.proposal",
                reason: error.to_string(),
            }),
        }
    }
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.proposal.schema_version",
                min: 1,
                max: 1,
                got: self.schema_version.into(),
            });
        }
        for (v, f) in [
            (&self.candidate_id, "failure.proposal.candidate_id"),
            (&self.fingerprint, "failure.proposal.fingerprint"),
            (&self.signature, "failure.proposal.signature"),
            (
                &self.violated_invariant,
                "failure.proposal.violated_invariant",
            ),
        ] {
            text(v, f)?;
        }
        digest(&self.policy_digest, "failure.proposal.policy_digest")?;
        refs(&self.evidence_refs, "failure.proposal.evidence_refs")?;
        refs(
            &self.counterevidence_refs,
            "failure.proposal.counterevidence_refs",
        )?;
        refs(&self.source_refs, "failure.proposal.source_refs")?;
        self.operation.validate()?;
        self.target_evidence.validate("failure")?;
        self.comparison.validate()?;
        check_vec_bound(self.trigger.len(), MAX_ITEMS, "failure.proposal.trigger")?;
        for dimension in &self.trigger {
            dimension.validate()?;
        }
        self.action.validate()?;
        self.outcome.validate()?;
        self.environment.validate()?;
        self.applicability.validate()?;
        self.causal.validate()?;
        check_vec_bound(self.controls.len(), MAX_ITEMS, "failure.proposal.controls")?;
        for control in &self.controls {
            control.validate()?;
        }
        self.mitigation.validate()?;
        self.lifecycle.validate()?;
        self.history.validate()?;
        self.preservation.validate()?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "failure proposal exceeds CandidateArtifact".to_owned(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn normalize_outcome(outcome: &mut FailureOutcome) {
    outcome.possible_effects.sort();
    outcome.receipt_refs.sort();
}

pub(crate) fn normalize_history(history: &mut FailureHistory) -> Result<(), ContractViolation> {
    for entry in &mut history.entries {
        entry.evidence_refs.sort();
        entry.receipt_refs.sort();
    }
    history.omitted_refs.sort();
    history.receipts.sort_by(|a, b| {
        a.identity
            .receipt_id
            .as_str()
            .cmp(b.identity.receipt_id.as_str())
    });
    history
        .receipt_materials
        .sort_by(|a, b| a.receipt_id.cmp(&b.receipt_id));
    history
        .historical_evidence
        .sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    let mut envelopes: Vec<(Vec<u8>, EvidenceEnvelope)> = history
        .historical_evidence_envelopes
        .drain(..)
        .map(|envelope| Ok((canonical_bytes(&envelope)?, envelope)))
        .collect::<Result<_, ContractViolation>>()?;
    envelopes.sort_by(|a, b| a.0.cmp(&b.0));
    history.historical_evidence_envelopes = envelopes
        .into_iter()
        .map(|(_, envelope)| envelope)
        .collect();
    history.omitted_evidence_envelope_refs.sort();
    Ok(())
}

pub(crate) fn normalize_action_evidence(
    action: &mut FailureActionEvidence,
) -> Result<(), ContractViolation> {
    normalize_outcome(&mut action.outcome);
    action
        .evidence
        .sort_by(|a, b| a.evidence_id.cmp(&b.evidence_id));
    action.receipts.sort_by(|a, b| {
        a.identity
            .receipt_id
            .as_str()
            .cmp(b.identity.receipt_id.as_str())
    });
    action
        .receipt_materials
        .sort_by(|a, b| a.receipt_id.cmp(&b.receipt_id));
    let mut envelopes: Vec<(Vec<u8>, EvidenceEnvelope)> = action
        .evidence_envelopes
        .drain(..)
        .map(|envelope| Ok((canonical_bytes(&envelope)?, envelope)))
        .collect::<Result<_, ContractViolation>>()?;
    envelopes.sort_by(|a, b| a.0.cmp(&b.0));
    action.evidence_envelopes = envelopes
        .into_iter()
        .map(|(_, envelope)| envelope)
        .collect();
    action.omitted_envelope_refs.sort();
    Ok(())
}

pub(crate) fn normalize_proposal(proposal: &mut FailureProposal) -> Result<(), ContractViolation> {
    normalize_outcome(&mut proposal.outcome);
    normalize_history(&mut proposal.history)?;
    proposal.evidence_refs.sort();
    proposal.counterevidence_refs.sort();
    proposal.source_refs.sort();
    proposal.trigger.sort_by(|a, b| a.name.cmp(&b.name));
    proposal
        .comparison
        .dimensions
        .sort_by(|a, b| a.name.cmp(&b.name));
    proposal.comparison.missing_dimensions.sort();
    proposal
        .controls
        .sort_by(|a, b| a.control_id.cmp(&b.control_id));
    for control in &mut proposal.controls {
        control.verifier_refs.sort();
    }
    proposal.causal.evidence_refs.sort();
    proposal.causal.limitation_refs.sort();
    proposal.causal.rival_refs.sort();
    proposal.causal.confounder_refs.sort();
    proposal.lifecycle.inverse_refs.sort();
    proposal.lifecycle.raw_history_refs.sort();
    Ok(())
}

pub(crate) fn normalize_preservation(preservation: &mut RelationPreservation) {
    preservation
        .verdicts
        .sort_by(|a, b| a.dimension.as_str().cmp(b.dimension.as_str()));
}
