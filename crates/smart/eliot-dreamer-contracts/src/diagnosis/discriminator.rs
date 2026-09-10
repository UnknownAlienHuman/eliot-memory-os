//! `CurrentDiscriminator` evidence for `DevelopmentDiagnosis`.
//!
//! The types here describe a supplied claim and its proof ceiling. They do
//! not execute a verifier, admit a configuration, authenticate an owner, or
//! conclude that a live system currently has the named failure.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, ContractId, ContractVersion, RequestId};
use eliot_evaluation_contracts::{
    CensoringRecord, ExpectedObservableSpec, ProductIdentityRef, TerminalVerifierBinding,
};
use eliot_evidence::{EvidenceEnvelope, VerificationBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::identity::{MAX_DIAGNOSIS_CONTEXT_ITEMS, ProductContext, UnavailableField};
use super::validation::{
    MAX_DIAGNOSIS_TEXT_BYTES, bounded_artifact_refs, bounded_contract_id, bounded_digest,
    bounded_text, canonical_stream_digest, preflight_canonical_stream,
};
use crate::error::{check_text, check_vec_bound};
use crate::{AttemptBinding, ContractViolation, UnavailableEvidence, is_hex64_lower};
use eliot_receipts::ArtifactBinding;

/// Wire revision for the diagnosis current discriminator.
pub const CURRENT_DISCRIMINATOR_SCHEMA_VERSION: u16 = 1;

/// Explicit state of a discriminator precondition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum PreconditionState {
    /// The supplied evidence establishes the condition.
    Satisfied,
    /// The supplied evidence establishes that the condition is absent.
    Unsatisfied,
    /// The condition could not be established.
    Unknown { reason: String },
}

/// One named precondition retained in discriminator order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorPrecondition {
    pub precondition_id: ContractId,
    pub condition: String,
    pub state: PreconditionState,
    pub evidence_refs: Vec<ArtifactId>,
}

impl DiscriminatorPrecondition {
    fn validate(&self) -> Result<(), ContractViolation> {
        bounded_contract_id(&self.precondition_id, "discriminator.precondition.id")?;
        bounded_text(
            &self.condition,
            "discriminator.precondition.condition",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        match &self.state {
            PreconditionState::Satisfied | PreconditionState::Unsatisfied => {
                validate_nonempty_artifact_refs(
                    &self.evidence_refs,
                    "discriminator.precondition.evidence_refs",
                )?;
            }
            PreconditionState::Unknown { reason } => {
                bounded_text(
                    reason,
                    "discriminator.precondition.unknown.reason",
                    MAX_DIAGNOSIS_TEXT_BYTES,
                )?;
                bounded_artifact_refs(
                    &self.evidence_refs,
                    "discriminator.precondition.evidence_refs",
                )?;
            }
        }
        Ok(())
    }
}

/// Distinct current observation states; unknown is never a pass alias.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum CurrentObservation {
    Pass {
        summary: String,
        observed: Option<ObservedValueRef>,
        unavailable: Option<UnavailableEvidence>,
    },
    Fail {
        summary: String,
        observed: Option<ObservedValueRef>,
        unavailable: Option<UnavailableEvidence>,
    },
    Partial {
        summary: String,
        unresolved: Vec<String>,
        observed: Option<ObservedValueRef>,
        unavailable: Option<UnavailableEvidence>,
    },
    Unknown {
        reason: String,
    },
    Censored {
        reason: String,
    },
    InfrastructureFailure {
        reason: String,
    },
}

impl CurrentObservation {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Pass {
                summary,
                observed,
                unavailable,
            }
            | Self::Fail {
                summary,
                observed,
                unavailable,
            } => {
                bounded_text(summary, "discriminator.observation.summary", 512)?;
                validate_observed_ref(observed.as_ref(), unavailable.as_ref())
            }
            Self::Partial {
                summary,
                unresolved,
                observed,
                unavailable,
            } => {
                bounded_text(
                    summary,
                    "discriminator.observation.summary",
                    MAX_DIAGNOSIS_TEXT_BYTES,
                )?;
                validate_nonempty_text_set(unresolved, "discriminator.observation.unresolved")?;
                validate_observed_ref(observed.as_ref(), unavailable.as_ref())
            }
            Self::Unknown { reason }
            | Self::Censored { reason }
            | Self::InfrastructureFailure { reason } => bounded_text(
                reason,
                "discriminator.observation.reason",
                MAX_DIAGNOSIS_TEXT_BYTES,
            ),
        }
    }
}

/// Kind of canonical observed value referenced by a discriminator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ObservedValueKind {
    ObservationRecord,
    RawEvidence,
    NormalizedEvidence,
}

/// Typed reference to a canonical observation and optional raw/normalized
/// preimages; no value algebra or matcher is introduced here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedValueRef {
    pub kind: ObservedValueKind,
    pub observation_artifact_id: ArtifactId,
    pub canonical_observation_digest: String,
    pub raw_preimage_ref: Option<ArtifactId>,
    pub raw_preimage_digest: Option<String>,
    pub normalized_ref: Option<ArtifactId>,
    pub normalized_digest: Option<String>,
}

impl ObservedValueRef {
    fn validate(&self) -> Result<(), ContractViolation> {
        bounded_text(
            self.observation_artifact_id.as_str(),
            "discriminator.observed.observation_artifact_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_digest(
            &self.canonical_observation_digest,
            "discriminator.observed.canonical_observation_digest",
        )?;
        match (&self.raw_preimage_ref, &self.raw_preimage_digest) {
            (Some(reference), Some(digest)) => {
                bounded_text(
                    reference.as_str(),
                    "discriminator.observed.raw_preimage_ref",
                    MAX_DIAGNOSIS_TEXT_BYTES,
                )?;
                bounded_digest(digest, "discriminator.observed.raw_preimage_digest")?;
            }
            (None, None) => {}
            _ => {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.observed.raw_preimage",
                    reason: "raw preimage reference and digest must be supplied together"
                        .to_owned(),
                });
            }
        }
        match (&self.normalized_ref, &self.normalized_digest) {
            (Some(reference), Some(digest)) => {
                bounded_text(
                    reference.as_str(),
                    "discriminator.observed.normalized_ref",
                    MAX_DIAGNOSIS_TEXT_BYTES,
                )?;
                bounded_digest(digest, "discriminator.observed.normalized_digest")?;
            }
            (None, None) => {}
            _ => {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.observed.normalized",
                    reason: "normalized reference and digest must be supplied together".to_owned(),
                });
            }
        }
        let mut digests_by_artifact: BTreeMap<String, String> = BTreeMap::new();
        register_observed_artifact(
            &mut digests_by_artifact,
            &self.observation_artifact_id,
            &self.canonical_observation_digest,
        )?;
        if let (Some(reference), Some(digest)) = (&self.raw_preimage_ref, &self.raw_preimage_digest)
        {
            register_observed_artifact(&mut digests_by_artifact, reference, digest)?;
        }
        if let (Some(reference), Some(digest)) = (&self.normalized_ref, &self.normalized_digest) {
            register_observed_artifact(&mut digests_by_artifact, reference, digest)?;
        }
        Ok(())
    }
}

fn register_observed_artifact(
    digests_by_artifact: &mut BTreeMap<String, String>,
    artifact_id: &ArtifactId,
    digest: &str,
) -> Result<(), ContractViolation> {
    register_artifact_digest(
        digests_by_artifact,
        artifact_id.as_str(),
        digest,
        "discriminator.observed.artifact_digests",
    )
}

fn register_artifact_digest(
    digests_by_artifact: &mut BTreeMap<String, String>,
    artifact_id: &str,
    digest: &str,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if let Some(previous) = digests_by_artifact.get(artifact_id) {
        if previous != digest {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "one artifact id cannot carry conflicting digests".to_owned(),
            });
        }
    } else {
        digests_by_artifact.insert(artifact_id.to_owned(), digest.to_owned());
    }
    Ok(())
}

fn register_observed_aliases(
    digests_by_artifact: &mut BTreeMap<String, String>,
    observed: &ObservedValueRef,
) -> Result<(), ContractViolation> {
    register_observed_artifact(
        digests_by_artifact,
        &observed.observation_artifact_id,
        &observed.canonical_observation_digest,
    )?;
    if let (Some(reference), Some(digest)) =
        (&observed.raw_preimage_ref, &observed.raw_preimage_digest)
    {
        register_artifact_digest(
            digests_by_artifact,
            reference.as_str(),
            digest,
            "discriminator.artifact_digests",
        )?;
    }
    if let (Some(reference), Some(digest)) = (&observed.normalized_ref, &observed.normalized_digest)
    {
        register_artifact_digest(
            digests_by_artifact,
            reference.as_str(),
            digest,
            "discriminator.artifact_digests",
        )?;
    }
    Ok(())
}

fn validate_artifact_binding(
    binding: &ArtifactBinding,
    field_prefix: &'static str,
) -> Result<(), ContractViolation> {
    bounded_text(
        binding.artifact_id.as_str(),
        field_prefix,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_digest(&binding.sha256, field_prefix)?;
    if let Some(revision) = &binding.source_revision {
        bounded_text(revision, field_prefix, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    Ok(())
}

fn validate_terminal_bounds(verifier: &TerminalVerifierBinding) -> Result<(), ContractViolation> {
    bounded_contract_id(
        &verifier.planned.verifier_id,
        "discriminator.verifier.planned.verifier_id",
    )?;
    bounded_text(
        &verifier.planned.scope,
        "discriminator.verifier.planned.scope",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &verifier.planned.verifier_config_hash,
        "discriminator.verifier.planned.verifier_config_hash",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &verifier.planned.environment_binding,
        "discriminator.verifier.planned.environment_binding",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &verifier.planned.verifier_authority_ref,
        "discriminator.verifier.planned.verifier_authority_ref",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    validate_expected_bounds(
        &verifier.planned.expected_observable,
        "discriminator.verifier.planned.expected_observable",
    )?;
    bounded_text(
        verifier.evidence.run_id.as_str(),
        "discriminator.verifier.evidence.run_id",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_contract_id(
        &verifier.evidence.verifier_id,
        "discriminator.verifier.evidence.verifier_id",
    )?;
    bounded_text(
        &verifier.evidence.scope,
        "discriminator.verifier.evidence.scope",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_artifact_refs(
        &verifier.evidence.evidence_refs,
        "discriminator.verifier.evidence.evidence_refs",
    )
}

fn validate_expected_bounds(
    expected: &ExpectedObservableSpec,
    field_prefix: &'static str,
) -> Result<(), ContractViolation> {
    bounded_text(&expected.property, field_prefix, MAX_DIAGNOSIS_TEXT_BYTES)?;
    bounded_text(&expected.matcher, field_prefix, MAX_DIAGNOSIS_TEXT_BYTES)?;
    bounded_text(
        &expected.artifact_selector,
        field_prefix,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )
}

fn validate_evidence_bounds(
    evidence: &EvidenceEnvelope,
    field_prefix: &'static str,
) -> Result<(), ContractViolation> {
    bounded_text(
        evidence.provenance.source_id.as_str(),
        field_prefix,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &evidence.provenance.capture_route,
        field_prefix,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_text(
        &evidence.provenance.scope,
        field_prefix,
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    if let Some(value) = &evidence.provenance.raw_handle {
        bounded_text(value, field_prefix, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    if let Some(value) = &evidence.provenance.revision {
        bounded_text(value, field_prefix, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    if let Some(verification) = &evidence.verification {
        bounded_contract_id(&verification.contract_id, field_prefix)?;
        bounded_text(
            verification.run_id.as_str(),
            field_prefix,
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &verification.revision,
            field_prefix,
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    Ok(())
}

fn validate_text_set(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    if values.len() > MAX_DIAGNOSIS_CONTEXT_ITEMS {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::try_from(MAX_DIAGNOSIS_CONTEXT_ITEMS).unwrap_or(i64::MAX),
            got: i64::try_from(values.len()).unwrap_or(i64::MAX),
        });
    }
    for value in values {
        bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "set values must be unique and in canonical order".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_nonempty_text_set(
    values: &[String],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if values.is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    validate_text_set(values, field)
}

fn validate_nonempty_artifact_refs(
    refs: &[ArtifactId],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if refs.is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    bounded_artifact_refs(refs, field)
}

fn validate_observed_ref(
    observed: Option<&ObservedValueRef>,
    unavailable: Option<&UnavailableEvidence>,
) -> Result<(), ContractViolation> {
    match (observed, unavailable) {
        (Some(_), Some(_)) => Err(ContractViolation::BindingMismatch {
            field: "discriminator.observed",
            reason: "observed reference and unavailable explanation are mutually exclusive"
                .to_owned(),
        }),
        (Some(observed), None) => observed.validate(),
        (None, Some(unavailable)) if unavailable.field == UnavailableField::ObservedValue => {
            unavailable.validate()
        }
        (None, Some(_)) => Err(ContractViolation::BindingMismatch {
            field: "discriminator.observed.unavailable.field",
            reason: "observed value absence must use ObservedValue".to_owned(),
        }),
        (None, None) => Err(ContractViolation::MissingField(
            "discriminator.observed.reference_or_unavailable",
        )),
    }
}

/// Whether a discriminator was declared before or after observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum ObservationDeclaration {
    Predeclared,
    PostHoc {
        /// A post-hoc confirmation claim remains optional data and never
        /// implies evidence-family independence, verifier admission, or run
        /// execution.
        confirmation_claim: Option<Box<PostHocConfirmation>>,
    },
}

/// How much lineage information was supplied for a post-hoc confirmation.
///
/// This is an externally supplied claim. Artifact identity and a lineage
/// artifact digest do not establish independence, owner authenticity, or run
/// admission; missing lineage must remain [`Unknown`](Self::Unknown).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum ConfirmationIndependenceClaim {
    Unknown { reason: String },
    ReportedIndependent { lineage_evidence: ArtifactBinding },
}

impl ConfirmationIndependenceClaim {
    fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Unknown { reason } => bounded_text(
                reason,
                "discriminator.post_hoc.independence.unknown.reason",
                MAX_DIAGNOSIS_TEXT_BYTES,
            ),
            Self::ReportedIndependent { lineage_evidence } => validate_artifact_binding(
                lineage_evidence,
                "discriminator.post_hoc.independence.lineage_evidence",
            ),
        }
    }
}

/// Optional post-hoc confirmation with explicit observable/context/source
/// joins and a separately supplied independence claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostHocConfirmation {
    pub verification: VerificationBinding,
    pub context_digest: String,
    pub expected: ExpectedObservableSpec,
    pub independence: ConfirmationIndependenceClaim,
}

impl PostHocConfirmation {
    fn validate_for_context(
        &self,
        expected: &ExpectedObservableSpec,
        context: &ProductContext,
    ) -> Result<(), ContractViolation> {
        self.verification
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "discriminator.post_hoc.verification",
                reason: error.to_string(),
            })?;
        bounded_contract_id(
            &self.verification.contract_id,
            "discriminator.post_hoc.verification.contract_id",
        )?;
        bounded_text(
            self.verification.run_id.as_str(),
            "discriminator.post_hoc.verification.run_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &self.verification.revision,
            "discriminator.post_hoc.verification.revision",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_digest(
            &self.context_digest,
            "discriminator.post_hoc.context_digest",
        )?;
        bounded_text(
            &self.expected.property,
            "discriminator.post_hoc.expected.property",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &self.expected.matcher,
            "discriminator.post_hoc.expected.matcher",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &self.expected.artifact_selector,
            "discriminator.post_hoc.expected.artifact_selector",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        self.independence.validate()?;
        if self.context_digest != context.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.post_hoc.context_digest",
                reason: "post-hoc confirmation context digest does not match supplied context"
                    .to_owned(),
            });
        }
        if self.expected != *expected {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.post_hoc.expected",
                reason: "post-hoc confirmation observable does not match expected observable"
                    .to_owned(),
            });
        }
        if self.verification.revision != context.product_identity.source_revision {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.post_hoc.verification.revision",
                reason: "post-hoc confirmation revision does not match supplied context".to_owned(),
            });
        }
        Ok(())
    }
}

/// Typed association between a request and independently supplied run evidence.
/// This is a structural claim only; it does not authenticate or admit a run.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunEvidenceAssociation {
    pub request_id: RequestId,
    pub verification_run_id: ArtifactId,
    pub association_evidence: ArtifactBinding,
}

impl RunEvidenceAssociation {
    fn validate(&self) -> Result<(), ContractViolation> {
        bounded_text(
            self.request_id.as_str(),
            "discriminator.run_association.request_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            self.verification_run_id.as_str(),
            "discriminator.run_association.verification_run_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        validate_artifact_binding(
            &self.association_evidence,
            "discriminator.run_association.association_evidence",
        )
    }
}

/// Supplied run/config/revision/current-identity binding for a discriminator.
///
/// Every optional member has an explicit availability list. This preserves
/// unknown input without inventing an empty identity or a successful run.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedRunBinding {
    pub attempt: Option<AttemptBinding>,
    pub run_id: Option<RequestId>,
    pub verifier_config_hash: Option<String>,
    pub verifier_config_revision: Option<String>,
    pub verifier_contract_revision: Option<ContractVersion>,
    pub verifier_environment_binding: Option<String>,
    pub context_digest: Option<String>,
    pub current_product_identity: Option<ProductIdentityRef>,
    pub run_evidence_association: Option<RunEvidenceAssociation>,
    pub unavailable: Vec<UnavailableEvidence>,
}

impl SuppliedRunBinding {
    fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(run_id) = &self.run_id {
            bounded_text(
                run_id.as_str(),
                "discriminator.run_id",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
        }
        if let Some(value) = &self.verifier_config_hash {
            bounded_text(
                value,
                "discriminator.verifier_config_hash",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
        }
        if let Some(value) = &self.verifier_config_revision {
            bounded_text(
                value,
                "discriminator.verifier_config_revision",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
        }
        if let Some(value) = &self.verifier_environment_binding {
            bounded_text(
                value,
                "discriminator.verifier_environment_binding",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
        }
        if let Some(value) = &self.context_digest {
            bounded_digest(value, "discriminator.context_digest")?;
        }
        if let Some(attempt) = &self.attempt {
            attempt
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.attempt",
                    reason: error.to_string(),
                })?;
        }
        if let Some(identity) = &self.current_product_identity {
            bounded_text(
                identity.product_id.as_str(),
                "discriminator.current_product_identity.product_id",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            bounded_text(
                &identity.source_revision,
                "discriminator.current_product_identity.source_revision",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            if identity.contract_revisions.len() > MAX_DIAGNOSIS_CONTEXT_ITEMS {
                return Err(ContractViolation::OutOfBounds {
                    field: "discriminator.current_product_identity.contract_revisions",
                    min: 0,
                    max: i64::try_from(MAX_DIAGNOSIS_CONTEXT_ITEMS).unwrap_or(i64::MAX),
                    got: i64::try_from(identity.contract_revisions.len()).unwrap_or(i64::MAX),
                });
            }
            identity
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.current_product_identity",
                    reason: error.to_string(),
                })?;
        }
        if let Some(association) = &self.run_evidence_association {
            association.validate()?;
        }
        check_vec_bound(
            self.unavailable.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "discriminator.run.unavailable",
        )?;
        for item in &self.unavailable {
            item.validate()?;
        }
        for pair in self.unavailable.windows(2) {
            if pair[0].field >= pair[1].field {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run.unavailable",
                    reason: "availability fields must be unique and in canonical enum order"
                        .to_owned(),
                });
            }
        }
        self.validate_optional_availability()?;
        Ok(())
    }

    fn validate_optional_availability(&self) -> Result<(), ContractViolation> {
        let fields = [
            (self.attempt.is_some(), UnavailableField::Attempt),
            (self.run_id.is_some(), UnavailableField::RunId),
            (
                self.verifier_config_hash.is_some(),
                UnavailableField::VerifierConfigHash,
            ),
            (
                self.verifier_config_revision.is_some(),
                UnavailableField::VerifierConfigRevision,
            ),
            (
                self.verifier_contract_revision.is_some(),
                UnavailableField::VerifierContractRevision,
            ),
            (
                self.verifier_environment_binding.is_some(),
                UnavailableField::VerifierEnvironmentBinding,
            ),
            (
                self.context_digest.is_some(),
                UnavailableField::ContextDigest,
            ),
            (
                self.current_product_identity.is_some(),
                UnavailableField::CurrentProductIdentity,
            ),
            (
                self.run_evidence_association.is_some(),
                UnavailableField::RunEvidenceAssociation,
            ),
        ];
        let mut seen = [0_u8; 9];
        for item in &self.unavailable {
            let Some(slot) = fields.iter().position(|(_, field)| *field == item.field) else {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run.unavailable.field",
                    reason: "field is not valid for supplied run binding".to_owned(),
                });
            };
            seen[slot] = seen[slot].saturating_add(1);
            if seen[slot] > 1 {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run.unavailable",
                    reason: "availability fields must be unique".to_owned(),
                });
            }
        }
        for (slot, (present, field)) in fields.iter().enumerate() {
            if *present == (seen[slot] == 1) {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run.unavailable",
                    reason: format!("field {field:?} must be present or exactly once unavailable"),
                });
            }
        }
        Ok(())
    }
}

/// Replay identity and the conditions under which replay remains meaningful.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBinding {
    pub replay_id: ContractId,
    pub input_digest: Option<String>,
    pub replayable: bool,
    pub conditions: Vec<String>,
    pub unavailable_reason: Option<String>,
}

impl ReplayBinding {
    fn validate(&self) -> Result<(), ContractViolation> {
        bounded_contract_id(&self.replay_id, "discriminator.replay.replay_id")?;
        if let Some(input_digest) = &self.input_digest {
            bounded_digest(input_digest, "discriminator.replay.input_digest")?;
        }
        check_vec_bound(
            self.conditions.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "discriminator.replay.conditions",
        )?;
        validate_text_set(&self.conditions, "discriminator.replay.conditions")?;
        if let Some(reason) = &self.unavailable_reason {
            check_text(reason, "discriminator.replay.unavailable_reason", 512)?;
        }
        if self.input_digest.is_none() && self.unavailable_reason.is_none() {
            return Err(ContractViolation::MissingField(
                "discriminator.replay.unavailable_reason",
            ));
        }
        if self.replayable && self.input_digest.is_none() {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.replay.replayable",
                reason: "replayable claim requires a supplied input digest".to_owned(),
            });
        }
        Ok(())
    }
}

/// A current discriminator claim bound to one product context digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentDiscriminator {
    pub schema_version: u16,
    pub discriminator_id: ContractId,
    pub revision: ContractVersion,
    pub product_context_digest: String,
    pub owner: String,
    pub declaration: ObservationDeclaration,
    pub preconditions: Vec<DiscriminatorPrecondition>,
    pub expected: ExpectedObservableSpec,
    pub observation: CurrentObservation,
    pub supplied_run: SuppliedRunBinding,
    pub replay: ReplayBinding,
    pub verifier: Option<TerminalVerifierBinding>,
    pub evidence: EvidenceEnvelope,
    /// Direct supporting citations, not an exhaustive transitive denominator
    /// or an independence/authentication proof.
    pub evidence_refs: Vec<ArtifactId>,
    pub censoring: Option<CensoringRecord>,
    pub unavailable: Vec<UnavailableEvidence>,
    pub digest: String,
}

impl CurrentDiscriminator {
    /// Computes the identity digest without treating it as authentication.
    pub fn canonical_digest(&self) -> Result<String, ContractViolation> {
        self.validate_shape()?;
        let mut unsigned = self.clone();
        unsigned.digest.clear();
        canonical_stream_digest(&unsigned)
    }

    /// Returns this discriminator with its canonical digest populated.
    pub fn with_digest(mut self) -> Result<Self, ContractViolation> {
        self.validate_shape()?;
        self.digest = self.canonical_digest()?;
        Ok(self)
    }

    /// Checks the bounded artifact claims that are colocated in this
    /// discriminator. A repeated artifact id may alias only the same digest;
    /// this is a structural consistency check, not an independence verdict.
    fn validate_related_artifact_aliases(&self) -> Result<(), ContractViolation> {
        let mut digests_by_artifact = BTreeMap::new();
        let observed = match &self.observation {
            CurrentObservation::Pass { observed, .. }
            | CurrentObservation::Fail { observed, .. }
            | CurrentObservation::Partial { observed, .. } => observed.as_ref(),
            CurrentObservation::Unknown { .. }
            | CurrentObservation::Censored { .. }
            | CurrentObservation::InfrastructureFailure { .. } => None,
        };
        if let Some(observed) = observed {
            register_observed_aliases(&mut digests_by_artifact, observed)?;
        }
        if let Some(association) = &self.supplied_run.run_evidence_association {
            register_artifact_digest(
                &mut digests_by_artifact,
                association.association_evidence.artifact_id.as_str(),
                &association.association_evidence.sha256,
                "discriminator.artifact_digests",
            )?;
        }
        if let ObservationDeclaration::PostHoc {
            confirmation_claim: Some(confirmation),
        } = &self.declaration
            && let ConfirmationIndependenceClaim::ReportedIndependent { lineage_evidence } =
                &confirmation.independence
        {
            register_artifact_digest(
                &mut digests_by_artifact,
                lineage_evidence.artifact_id.as_str(),
                &lineage_evidence.sha256,
                "discriminator.artifact_digests",
            )?;
        }
        Ok(())
    }

    /// Checks joins whose two endpoints are carried by this discriminator.
    /// Missing optional endpoints remain unknown and are handled by their
    /// explicit availability records.
    fn validate_self_joins(&self) -> Result<(), ContractViolation> {
        self.validate_verifier_self_joins()?;
        self.validate_run_association_self_joins()?;
        self.validate_posthoc_self_joins()
    }

    fn validate_verifier_self_joins(&self) -> Result<(), ContractViolation> {
        if let Some(verifier) = &self.verifier
            && verifier.planned.expected_observable != self.expected
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.verifier.planned.expected_observable",
                reason:
                    "planned verifier observable does not match discriminator expected observable"
                        .to_owned(),
            });
        }
        if let Some(verifier) = &self.verifier
            && let Some(run_id) = &self.supplied_run.run_id
            && verifier.evidence.run_id != *run_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.verifier.evidence.run_id",
                reason: "terminal verifier run id does not match supplied run id".to_owned(),
            });
        }
        if let Some(verifier) = &self.verifier
            && let Some(hash) = &self.supplied_run.verifier_config_hash
            && verifier.planned.verifier_config_hash != *hash
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.verifier.planned.verifier_config_hash",
                reason: "planned verifier config hash does not match supplied verifier config hash"
                    .to_owned(),
            });
        }
        if let Some(verifier) = &self.verifier
            && let Some(revision) = self.supplied_run.verifier_contract_revision
            && verifier.planned.contract_revision != revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.verifier.planned.contract_revision",
                reason: "planned verifier contract revision does not match supplied revision"
                    .to_owned(),
            });
        }
        if let Some(verifier) = &self.verifier
            && let Some(environment) = &self.supplied_run.verifier_environment_binding
            && verifier.planned.environment_binding != *environment
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.verifier.planned.environment_binding",
                reason: "planned verifier environment does not match supplied binding".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_run_association_self_joins(&self) -> Result<(), ContractViolation> {
        if let Some(association) = &self.supplied_run.run_evidence_association {
            let Some(run_id) = &self.supplied_run.run_id else {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run_association.request_id",
                    reason: "run evidence association requires supplied run_id".to_owned(),
                });
            };
            if association.request_id != *run_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run_association.request_id",
                    reason: "run evidence association request id does not match supplied run"
                        .to_owned(),
                });
            }
            let Some(verification) = &self.evidence.verification else {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run_association.verification_run_id",
                    reason: "run evidence association requires top-level verification binding"
                        .to_owned(),
                });
            };
            if association.verification_run_id != verification.run_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.run_association.verification_run_id",
                    reason: "run evidence association run id does not match top-level verification"
                        .to_owned(),
                });
            }
        }
        if let Some(association) = &self.supplied_run.run_evidence_association
            && let Some(verifier) = &self.verifier
            && verifier.evidence.run_id != association.request_id
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.run_association.request_id",
                reason: "run evidence association request id does not match terminal verifier request id".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_posthoc_self_joins(&self) -> Result<(), ContractViolation> {
        if let ObservationDeclaration::PostHoc {
            confirmation_claim: Some(confirmation),
        } = &self.declaration
            && confirmation.expected != self.expected
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.post_hoc.expected",
                reason: "post-hoc confirmation observable does not match discriminator expected observable".to_owned(),
            });
        }
        if let ObservationDeclaration::PostHoc {
            confirmation_claim: Some(confirmation),
        } = &self.declaration
            && confirmation.context_digest != self.product_context_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.post_hoc.context_digest",
                reason: "post-hoc confirmation context digest does not match discriminator context digest".to_owned(),
            });
        }
        Ok(())
    }

    /// Performs intrinsic bounded shape checks, excluding digest.
    fn validate_shape(&self) -> Result<(), ContractViolation> {
        self.validate_wire_bounds()?;
        self.validate_precondition_bounds()?;
        self.validate_posthoc_bounds()?;
        validate_evidence_bounds(&self.evidence, "discriminator.evidence")?;
        if let Some(verifier) = &self.verifier {
            validate_terminal_bounds(verifier)?;
        }
        self.validate_censoring_bounds()?;
        self.validate_payloads()?;
        self.validate_unavailable()?;
        self.validate_self_joins()?;
        self.validate_related_artifact_aliases()
    }

    fn validate_wire_bounds(&self) -> Result<(), ContractViolation> {
        preflight_canonical_stream(self)?;
        if !self.digest.is_empty() && !is_hex64_lower(&self.digest) {
            return Err(ContractViolation::Malformed {
                field: "discriminator.digest",
                reason: "digest must be empty or lowercase SHA-256".to_owned(),
            });
        }
        if self.schema_version != CURRENT_DISCRIMINATOR_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "discriminator.schema_version",
                min: i64::from(CURRENT_DISCRIMINATOR_SCHEMA_VERSION),
                max: i64::from(CURRENT_DISCRIMINATOR_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        bounded_contract_id(&self.discriminator_id, "discriminator.discriminator_id")?;
        bounded_text(&self.owner, "discriminator.owner", MAX_DIAGNOSIS_TEXT_BYTES)?;
        bounded_digest(
            &self.product_context_digest,
            "discriminator.product_context_digest",
        )?;
        bounded_text(
            &self.expected.property,
            "discriminator.expected.property",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &self.expected.matcher,
            "discriminator.expected.matcher",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &self.expected.artifact_selector,
            "discriminator.expected.artifact_selector",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        check_vec_bound(
            self.preconditions.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "discriminator.preconditions",
        )?;
        check_vec_bound(
            self.evidence_refs.len(),
            MAX_DIAGNOSIS_CONTEXT_ITEMS,
            "discriminator.evidence_refs",
        )?;
        check_vec_bound(self.unavailable.len(), 1, "discriminator.unavailable")?;
        bounded_artifact_refs(&self.evidence_refs, "discriminator.evidence_refs")
    }

    fn validate_precondition_bounds(&self) -> Result<(), ContractViolation> {
        let mut precondition_ids = BTreeSet::new();
        for precondition in &self.preconditions {
            bounded_contract_id(
                &precondition.precondition_id,
                "discriminator.precondition.id",
            )?;
            bounded_text(
                &precondition.condition,
                "discriminator.precondition.condition",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            check_vec_bound(
                precondition.evidence_refs.len(),
                MAX_DIAGNOSIS_CONTEXT_ITEMS,
                "discriminator.precondition.evidence_refs",
            )?;
            bounded_artifact_refs(
                &precondition.evidence_refs,
                "discriminator.precondition.evidence_refs",
            )?;
            if !precondition_ids.insert(&precondition.precondition_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "discriminator.preconditions",
                    reason: "precondition identifiers must be unique".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_posthoc_bounds(&self) -> Result<(), ContractViolation> {
        let Some(confirmation) = (match &self.declaration {
            ObservationDeclaration::PostHoc { confirmation_claim } => confirmation_claim.as_deref(),
            ObservationDeclaration::Predeclared => None,
        }) else {
            return Ok(());
        };
        bounded_digest(
            &confirmation.context_digest,
            "discriminator.post_hoc.context_digest",
        )?;
        bounded_text(
            &confirmation.expected.property,
            "discriminator.post_hoc.expected.property",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &confirmation.expected.matcher,
            "discriminator.post_hoc.expected.matcher",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &confirmation.expected.artifact_selector,
            "discriminator.post_hoc.expected.artifact_selector",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_contract_id(
            &confirmation.verification.contract_id,
            "discriminator.post_hoc.verification.contract_id",
        )?;
        bounded_text(
            confirmation.verification.run_id.as_str(),
            "discriminator.post_hoc.verification.run_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &confirmation.verification.revision,
            "discriminator.post_hoc.verification.revision",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        confirmation.independence.validate()
    }

    fn validate_censoring_bounds(&self) -> Result<(), ContractViolation> {
        let Some(censoring) = self.censoring.as_ref() else {
            return Ok(());
        };
        bounded_text(
            &censoring.reason,
            "discriminator.censoring.reason",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        bounded_text(
            &censoring.exposure,
            "discriminator.censoring.exposure",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )
    }

    fn validate_payloads(&self) -> Result<(), ContractViolation> {
        self.expected
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "discriminator.expected",
                reason: error.to_string(),
            })?;
        self.observation.validate()?;
        self.supplied_run.validate()?;
        self.replay.validate()?;
        if let ObservationDeclaration::PostHoc {
            confirmation_claim: Some(confirmation),
        } = &self.declaration
        {
            confirmation
                .verification
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.post_hoc.verification",
                    reason: error.to_string(),
                })?;
            confirmation
                .expected
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.post_hoc.expected",
                    reason: error.to_string(),
                })?;
        }
        self.evidence
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "discriminator.evidence",
                reason: error.to_string(),
            })?;
        if let Some(verifier) = &self.verifier {
            verifier
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.verifier",
                    reason: error.to_string(),
                })?;
        }
        self.validate_censoring_observation()?;
        for precondition in &self.preconditions {
            precondition.validate()?;
        }
        Ok(())
    }

    fn validate_censoring_observation(&self) -> Result<(), ContractViolation> {
        let Some(censoring) = self.censoring.as_ref() else {
            return if matches!(self.observation, CurrentObservation::Censored { .. }) {
                Err(ContractViolation::MissingField("discriminator.censoring"))
            } else {
                Ok(())
            };
        };
        if let Some(observed_until) = censoring.observed_until {
            observed_until
                .validate()
                .map_err(|error| ContractViolation::Malformed {
                    field: "discriminator.censoring.observed_until",
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }

    fn validate_unavailable(&self) -> Result<(), ContractViolation> {
        for item in &self.unavailable {
            item.validate()?;
        }
        let verifier_unavailable = self
            .unavailable
            .iter()
            .filter(|item| item.field == UnavailableField::Verifier)
            .count();
        if self
            .unavailable
            .iter()
            .any(|item| item.field != UnavailableField::Verifier)
            || (self.verifier.is_some() == (verifier_unavailable == 1))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.unavailable",
                reason: "verifier must be present or exactly once unavailable".to_owned(),
            });
        }
        Ok(())
    }

    /// Performs intrinsic shape and digest checks only.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        bounded_digest(&self.digest, "discriminator.digest")?;
        let expected = self.canonical_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.digest",
                reason: "supplied digest does not match canonical bytes".to_owned(),
            });
        }
        Ok(())
    }

    /// Joins this supplied claim to one exact product context.
    ///
    /// This checks supplied values only. It does not authenticate their owner
    /// or admit a verifier configuration/run.
    pub fn validate_for_context(&self, context: &ProductContext) -> Result<(), ContractViolation> {
        self.validate()?;
        context.validate()?;
        if self.product_context_digest != context.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.product_context_digest",
                reason: "discriminator context digest does not match supplied context".to_owned(),
            });
        }
        if self.evidence.state_fence != context.evidence.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.evidence.state_fence",
                reason: "discriminator evidence fence does not match product context".to_owned(),
            });
        }
        if let Some(context_digest) = &self.supplied_run.context_digest
            && context_digest != &context.digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.supplied_run.context_digest",
                reason: "supplied run context digest does not match product context".to_owned(),
            });
        }
        if let Some(identity) = &self.supplied_run.current_product_identity
            && identity != &context.product_identity
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.supplied_run.current_product_identity",
                reason: "supplied current product identity does not match product context"
                    .to_owned(),
            });
        }
        if let Some(verification) = &self.evidence.verification
            && verification.revision != context.product_identity.source_revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "discriminator.evidence.verification.revision",
                reason: "evidence verification revision does not match product context".to_owned(),
            });
        }
        if let ObservationDeclaration::PostHoc { confirmation_claim } = &self.declaration
            && let Some(confirmation) = confirmation_claim
        {
            confirmation.validate_for_context(&self.expected, context)?;
        }
        Ok(())
    }
}
