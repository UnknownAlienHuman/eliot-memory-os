//! Typed input closure for one `ArchitectureSelfQuery` job.
//!
//! This module joins the existing v1 Dreamer intake, bundle, grounded draft
//! and A-05 validation receipt. It does not run grounding or validation and
//! does not authenticate any source acceptance claim.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, PolicyRevision, canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::{DisclosureClass, PositionAssertability, PrivacyHandling};
use eliot_receipts::{EffectClass, ProofCeiling};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::result::SelfQueryContractError;
use super::source::{
    ArchitectureAnchor, ArchitectureDependencyDenominator, ArchitectureSourceSnapshot,
    ArchitectureSourceStatus, MAX_TEXT_BYTES, check_canonical_size, check_digest, check_id,
    check_schema, check_text,
};
use crate::{BudgetUsage, JobClass, PreservationReport, SourceDisposition, ValidatedCandidate};

const MAX_PROFILE_ID: usize = 256;
const MAX_QUESTION_BYTES: usize = 64 * 1024;
const MAX_INVALIDATION_CONDITIONS: usize = 4096;
const MAX_INVALIDATION_BYTES: usize = 1024 * 1024;

/// The two authority-separated projections of one self-query job.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SelfQueryOutputProfile {
    ArchitectureBrief,
    ImplementationBrief,
}

/// Versioned identity of a self-query profile.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryProfile {
    pub schema_version: u32,
    pub job_class: JobClass,
    pub output_profile: SelfQueryOutputProfile,
    pub profile_id: String,
    pub profile_digest: String,
}

impl SelfQueryProfile {
    pub fn compute_digest(&self) -> Result<String, SelfQueryContractError> {
        check_schema(self.schema_version, "profile.schema_version")?;
        check_text(&self.profile_id, "profile.profile_id", MAX_PROFILE_ID)?;
        canonical_json_bytes(&(
            self.schema_version,
            self.job_class,
            self.output_profile,
            &self.profile_id,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| SelfQueryContractError::Encoding {
            field: "profile.profile_digest",
        })
    }

    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "profile.schema_version")?;
        if self.job_class != JobClass::ArchitectureSelfQuery {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "profile.job_class",
            });
        }
        check_text(&self.profile_id, "profile.profile_id", MAX_PROFILE_ID)?;
        check_digest(&self.profile_digest, "profile.profile_digest")?;
        if self.profile_digest != self.compute_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "profile.profile_digest",
            });
        }
        Ok(())
    }
}

/// Attempt identity and invalidation predecessors retained across retries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptBinding {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub maximum_attempts: u32,
    pub predecessor: Option<ArtifactId>,
    pub invalidation_refs: Vec<ArtifactId>,
}

impl AttemptBinding {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_text(&self.attempt_id, "attempt.attempt_id", 256)?;
        if self.attempt_number == 0
            || self.maximum_attempts == 0
            || self.attempt_number > self.maximum_attempts
        {
            return Err(SelfQueryContractError::Bound {
                field: "attempt.attempt_number",
                maximum: self.maximum_attempts.max(1) as usize,
                actual: self.attempt_number as usize,
            });
        }
        if self.invalidation_refs.len() > super::source::MAX_REFS {
            return Err(SelfQueryContractError::Bound {
                field: "attempt.invalidation_refs",
                maximum: super::source::MAX_REFS,
                actual: self.invalidation_refs.len(),
            });
        }
        let mut refs = BTreeSet::new();
        if let Some(predecessor) = &self.predecessor {
            check_id(predecessor.as_str(), "attempt.predecessor")?;
        }
        for reference in &self.invalidation_refs {
            check_id(reference.as_str(), "attempt.invalidation_ref")?;
            if !refs.insert(reference) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "attempt.invalidation_refs",
                });
            }
        }
        if self
            .predecessor
            .as_ref()
            .is_some_and(|id| refs.contains(id))
        {
            return Err(SelfQueryContractError::Conflict {
                field: "attempt.predecessor",
            });
        }
        Ok(())
    }
}

/// Policy and independent work ceilings for candidate-only self-query work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_revision: PolicyRevision,
    pub privacy: PrivacyHandling,
    pub disclosure: DisclosureClass,
    pub authority_ceiling: PositionAssertability,
    pub effect_ceiling: EffectClass,
    pub proof_ceiling: ProofCeiling,
    pub max_items: u64,
    pub max_reference_width: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_stu: u64,
    /// Local bounded work units (projection operations), distinct from the
    /// upstream parallel `work_fan_out` budget dimension.
    pub max_work: u64,
    pub now_ms: Option<u64>,
    pub deadline_ms: Option<u64>,
    pub cancellation_requested: bool,
}

impl SelfQueryPolicy {
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "policy.schema_version")?;
        check_text(&self.policy_id, "policy.policy_id", 256)?;
        if self.effect_ceiling == EffectClass::ReversibleMutation
            || self.effect_ceiling == EffectClass::ExternalEffect
            || self.proof_ceiling > ProofCeiling::CandidateArtifact
        {
            return Err(SelfQueryContractError::Conflict {
                field: "policy.effect_or_proof_ceiling",
            });
        }
        for (field, value) in [
            ("policy.max_items", self.max_items),
            ("policy.max_reference_width", self.max_reference_width),
            ("policy.max_input_bytes", self.max_input_bytes),
            ("policy.max_output_bytes", self.max_output_bytes),
            ("policy.max_stu", self.max_stu),
            ("policy.max_work", self.max_work),
        ] {
            if value == 0 {
                return Err(SelfQueryContractError::Missing { field });
            }
        }
        if let (Some(now), Some(deadline)) = (self.now_ms, self.deadline_ms)
            && deadline < now
        {
            return Err(SelfQueryContractError::Conflict {
                field: "policy.deadline_ms",
            });
        }
        Ok(())
    }
}

/// Complete typed input handoff for the self-query projection owners.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryInput {
    pub schema_version: u32,
    pub validated_candidate: ValidatedCandidate,
    pub profile: SelfQueryProfile,
    /// Self-query-layer attempt binding; v1 A-05 receipts do not authenticate
    /// this field, so the projection owner must retain it as an explicit join.
    pub attempt: AttemptBinding,
    /// Exact caller question retained by this profile; it is not supplied by
    /// or authenticated through the older v1 validation receipt.
    pub question: String,
    /// Opaque bundle handle retained separately from the typed source ID.
    pub source_bundle_handle: Option<String>,
    pub source: Option<ArchitectureSourceSnapshot>,
    pub anchors: Vec<ArchitectureAnchor>,
    pub denominator: ArchitectureDependencyDenominator,
    pub policy: SelfQueryPolicy,
    /// Upstream v1 usage; projection limits must be checked independently by
    /// the result owner against its measured usage.
    pub usage: BudgetUsage,
    pub preservation: PreservationReport,
    pub invalidation_conditions: Vec<String>,
}

impl SelfQueryInput {
    /// Computes a stable digest over the complete supplied input closure.
    pub fn input_digest(&self) -> Result<String, SelfQueryContractError> {
        self.validate()?;
        let input_limit = usize::try_from(self.policy.max_input_bytes.min(16 * 1024 * 1024))
            .map_err(|_| SelfQueryContractError::Bound {
                field: "self_query.input_preimage",
                maximum: 16 * 1024 * 1024,
                actual: usize::MAX,
            })?;
        check_canonical_size(self, input_limit, "self_query.input_preimage")?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| SelfQueryContractError::Encoding {
                field: "self_query.input_digest",
            })
    }

    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "input.schema_version")?;
        self.policy.validate()?;
        let input_limit = usize::try_from(self.policy.max_input_bytes.min(16 * 1024 * 1024))
            .map_err(|_| SelfQueryContractError::Bound {
                field: "self_query.input_preimage",
                maximum: 16 * 1024 * 1024,
                actual: usize::MAX,
            })?;
        check_canonical_size(self, input_limit, "self_query.input_preimage")?;
        self.validated_candidate.validate_binding().map_err(|_| {
            SelfQueryContractError::BindingMismatch {
                field: "input.validated_candidate",
            }
        })?;
        let job = &self.validated_candidate.job;
        let bundle = &self.validated_candidate.bundle;
        let grounded = &self.validated_candidate.grounded;
        let validated = &self.validated_candidate.validated;
        if job.job_class != JobClass::ArchitectureSelfQuery {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.job.job_class",
            });
        }
        self.profile.validate()?;
        self.attempt.validate()?;
        self.denominator.validate()?;
        self.preservation
            .validate()
            .map_err(|_| SelfQueryContractError::Conflict {
                field: "input.preservation",
            })?;
        check_text(&self.question, "input.question", MAX_QUESTION_BYTES)?;
        if let Some(handle) = &self.source_bundle_handle {
            check_text(handle, "input.source_bundle_handle", 128)?;
        }
        if self.invalidation_conditions.len() > MAX_INVALIDATION_CONDITIONS {
            return Err(SelfQueryContractError::Bound {
                field: "input.invalidation_conditions",
                maximum: MAX_INVALIDATION_CONDITIONS,
                actual: self.invalidation_conditions.len(),
            });
        }
        let mut invalidation_bytes = 0usize;
        for condition in &self.invalidation_conditions {
            check_text(condition, "input.invalidation_condition", MAX_TEXT_BYTES)?;
            invalidation_bytes = invalidation_bytes.saturating_add(condition.len());
        }
        if invalidation_bytes > MAX_INVALIDATION_BYTES {
            return Err(SelfQueryContractError::Bound {
                field: "input.invalidation_conditions",
                maximum: MAX_INVALIDATION_BYTES,
                actual: invalidation_bytes,
            });
        }

        if bundle.job_id != job.canonical_id()
            || bundle.task_id != job.task_id
            || bundle.scope_id != job.scope_id
            || bundle.manifest_digest != job.frozen_manifest_digest
            || bundle.state_fence != job.state_fence
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.bundle_job_binding",
            });
        }
        let receipt = &validated.receipt;
        if receipt.job_id != bundle.job_id
            || receipt.task_id != job.task_id
            || receipt.scope_id != job.scope_id
            || receipt.manifest_digest != bundle.manifest_digest
            || receipt.state_fence != job.state_fence
            || validated.state_fence != job.state_fence
            || validated.task_id != job.task_id
            || validated.scope_id != job.scope_id
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.validation_receipt_binding",
            });
        }
        if grounded.job_id != receipt.job_id
            || grounded.draft_digest != receipt.draft_digest
            || validated.draft_digest != grounded.draft_digest
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.grounded_validation_binding",
            });
        }
        if self.policy.policy_id != job.policy_ref {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.policy_id",
            });
        }
        if self.policy.policy_revision.value() != self.validated_candidate.policy.policy_revision {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.policy_revision",
            });
        }
        if self.validated_candidate.cancellation_requested && !self.policy.cancellation_requested {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.cancellation_requested",
            });
        }
        if self.policy.now_ms != self.validated_candidate.observation_time_ms {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.observation_time_ms",
            });
        }
        if self
            .validated_candidate
            .job
            .deadline_ms
            .is_some_and(|deadline| self.policy.deadline_ms.is_none_or(|local| local > deadline))
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.deadline_ms",
            });
        }
        for (field, local, upstream) in [
            (
                "input.max_reference_width",
                self.policy.max_reference_width,
                job.budget.reference_width,
            ),
            (
                "input.max_input_bytes",
                self.policy.max_input_bytes,
                job.budget.input_bytes,
            ),
            (
                "input.max_output_bytes",
                self.policy.max_output_bytes,
                job.budget.output_bytes,
            ),
            ("input.max_stu", self.policy.max_stu, job.budget.max_stu),
        ] {
            if upstream.is_none_or(|limit| local > limit) {
                return Err(SelfQueryContractError::BindingMismatch { field });
            }
        }
        let item_count = self
            .anchors
            .len()
            .saturating_add(self.denominator.members.len())
            .saturating_add(self.invalidation_conditions.len());
        let max_items = usize::try_from(self.policy.max_items).unwrap_or(usize::MAX);
        if item_count > max_items {
            return Err(SelfQueryContractError::Bound {
                field: "input.items",
                maximum: max_items,
                actual: item_count,
            });
        }
        if self.preservation != self.validated_candidate.preservation {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.preservation",
            });
        }
        if self.usage != self.validated_candidate.usage {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.usage",
            });
        }
        if let Some(source) = &self.source {
            source.validate()?;
            if source.status == ArchitectureSourceStatus::Accepted
                && source.acceptance_receipt.as_ref() != Some(&source.pair.acceptance_receipt)
            {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "input.acceptance_receipt_binding",
                });
            }
            let Some(handle) = &self.source_bundle_handle else {
                return Err(SelfQueryContractError::Missing {
                    field: "input.source_bundle_handle",
                });
            };
            if source.source_handle.as_str() != handle {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "input.source_bundle_handle",
                });
            }
            if source.bytes.is_empty() && source.status != ArchitectureSourceStatus::Accepted {
                if !bundle
                    .omissions
                    .iter()
                    .any(|omission| omission.handle == *handle)
                {
                    return Err(SelfQueryContractError::Missing {
                        field: "input.source_bundle_omission",
                    });
                }
            } else {
                let material = bundle
                    .materials
                    .iter()
                    .find(|material| material.handle == *handle)
                    .ok_or(SelfQueryContractError::Missing {
                        field: "input.source_bundle_material",
                    })?;
                if material.digest != source.digest
                    || material.bytes != u64::try_from(source.bytes.len()).unwrap_or(u64::MAX)
                    || material.disposition == SourceDisposition::Excluded
                {
                    return Err(SelfQueryContractError::BindingMismatch {
                        field: "input.source_bundle_material",
                    });
                }
            }
        } else if !self.anchors.is_empty()
            || !self.denominator.members.is_empty()
            || self.denominator.complete
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "input.source_absence_closure",
            });
        } else if let Some(handle) = &self.source_bundle_handle
            && !bundle
                .omissions
                .iter()
                .any(|omission| omission.handle == *handle)
        {
            return Err(SelfQueryContractError::Missing {
                field: "input.source_bundle_omission",
            });
        }
        if self.anchors.len() > super::source::MAX_ANCHORS {
            return Err(SelfQueryContractError::Bound {
                field: "input.anchors",
                maximum: super::source::MAX_ANCHORS,
                actual: self.anchors.len(),
            });
        }
        let mut anchor_ids = BTreeSet::new();
        for anchor in &self.anchors {
            let Some(source) = &self.source else {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "input.anchor_without_source",
                });
            };
            anchor.validate_against(source)?;
            if !anchor_ids.insert(&anchor.anchor_id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "input.anchors",
                });
            }
        }
        let mut member_ids = BTreeSet::new();
        for member in &self.denominator.members {
            if self
                .source
                .as_ref()
                .is_some_and(|source| member.source_handle != source.source_handle)
                || self.source.is_none()
            {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "input.denominator.source_handle",
                });
            }
            if !member_ids.insert(&member.member_id) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "input.denominator.members",
                });
            }
            if self.denominator.complete && !anchor_ids.contains(&member.anchor_id) {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "input.denominator.anchor_id",
                });
            }
        }
        if self.anchors.iter().any(|anchor| {
            anchor.applicability.basis
                == super::source::ArchitectureApplicabilityBasis::SimilarityRejected
                && anchor.applicability.state
                    == super::source::ArchitectureApplicabilityState::NotApplicable
        }) {
            return Err(SelfQueryContractError::Conflict {
                field: "input.similarity_exclusion",
            });
        }
        if self.denominator.complete {
            let member_anchor_ids: BTreeSet<&ArtifactId> = self
                .denominator
                .members
                .iter()
                .map(|member| &member.anchor_id)
                .collect();
            let anchor_id_set: BTreeSet<&ArtifactId> = self
                .anchors
                .iter()
                .map(|anchor| &anchor.anchor_id)
                .collect();
            if self.anchors.is_empty()
                || self.anchors.iter().any(|anchor| {
                    anchor.applicability.state
                        == super::source::ArchitectureApplicabilityState::Unknown
                        || anchor.applicability.basis
                            == super::source::ArchitectureApplicabilityBasis::SimilarityRejected
                })
                || self.denominator.members.len() != self.anchors.len()
                || member_anchor_ids != anchor_id_set
            {
                return Err(SelfQueryContractError::Conflict {
                    field: "input.complete_denominator",
                });
            }
        }
        Ok(())
    }
}
