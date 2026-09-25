//! Owner-admitted Curation material handed to the production Dreamer edge.
//!
//! I9.4 keeps [`DreamJobAdmission`] and [`DreamJobInput`] as distinct objects.
//! This carrier adds the owner-resolved A-20 screen binding and the immutable
//! native Curation source/profile/protection closure that the consumer may
//! screen. It creates no source, evidence, authority, or semantic decision.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, fences_match_exact};
use eliot_memory_curation_contracts::{
    CurationScreenRequest, DenominatorCoverage, MemberId, ProtectionClass, ProtectionEvidence,
    ProtectionEvidenceState, ProtectionOutcome, SourceAvailability, SourceSnapshot,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractViolation, check_text, check_vec_bound};
use crate::job::{DreamJobAdmission, DreamJobInput, JobClass};
use crate::screen::ScreenBinding;

/// Maximum owner omission identities retained by one protected launch.
const MAX_CURATION_OMISSIONS: usize = 256;
/// Maximum text length of one retained omission identity.
const MAX_CURATION_OMISSION_TEXT: usize = 1_024;

/// Exact owner-resolved material for one Curation job and native screen.
///
/// The protected launch seam carries this object without interpreting it. The
/// Dreamer child revalidates the whole closure against the Kernel-claimed job,
/// attempt, request, scope, and exact State Fence before the native owner runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedCurationMaterial {
    /// Closed I9.4 admission envelope issued by the semantic owner.
    pub admission: DreamJobAdmission,
    /// Closed I9.4 semantic input issued for the same admission.
    pub job: DreamJobInput,
    /// Complete A-20 owner screen binding, carried without reconstruction.
    pub screen_binding: ScreenBinding,
    /// Exact owner-frozen native screen request.
    pub request: CurationScreenRequest,
    /// Exact immutable native source snapshot.
    pub source: SourceSnapshot,
    /// Owner-issued protection evidence for the changed targets.
    pub protection_evidence: Vec<ProtectionEvidence>,
    /// Explicit source/evidence/frontier omissions retained through the cycle.
    pub omissions: Vec<String>,
}

impl AdmittedCurationMaterial {
    /// Binds the owner admission's frozen-manifest digest to the exact semantic
    /// source/evidence closure, then validates the complete carrier.
    pub fn bind_frozen_manifest(mut self) -> Result<Self, ContractViolation> {
        self.admission.frozen_manifest_digest = self.source_manifest_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the frozen manifest digest consumed by
    /// [`DreamJobAdmission::frozen_manifest_digest`]. The digest covers the
    /// owner screen binding, request, source, protection evidence, and explicit
    /// omissions; it does not recursively include the digest field itself.
    pub fn source_manifest_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct SourceManifest<'a> {
            screen_binding: &'a ScreenBinding,
            request: &'a CurationScreenRequest,
            source: &'a SourceSnapshot,
            protection_evidence: &'a [ProtectionEvidence],
            omissions: &'a [String],
        }
        let bytes = eliot_contracts::canonical_json_bytes(&SourceManifest {
            screen_binding: &self.screen_binding,
            request: &self.request,
            source: &self.source,
            protection_evidence: &self.protection_evidence,
            omissions: &self.omissions,
        })
        .map_err(|error| ContractViolation::BindingMismatch {
            field: "curation.source_manifest_digest",
            reason: error.to_string(),
        })?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validates the complete intrinsic and cross-object owner closure.
    #[allow(
        clippy::too_many_lines,
        reason = "the owner closure validator keeps intrinsic, cross-object, fence, target, protection, omission, and manifest checks together"
    )]
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.admission.validate()?;
        self.job.validate_against(&self.admission)?;
        if self.admission.job_class != JobClass::Curation
            || self.job.job_class != JobClass::Curation
        {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.job_class",
                reason: "admitted Curation material requires the Curation class".to_owned(),
            });
        }
        for effect in ["source_mutation", "authority_mutation"] {
            if !self.job.forbidden_effects.iter().any(|item| item == effect) {
                return Err(ContractViolation::MissingField("job.forbidden_effects"));
            }
        }

        self.screen_binding
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "curation.screen_binding",
                reason: error.to_string(),
            })?;
        self.request
            .validate_snapshot(&self.source)
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "curation.request",
                reason: error.to_string(),
            })?;
        if self.request.cursor.is_some() || self.request.cancellation_requested {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.request",
                reason: "the one-shot production route admits no cursor or cancellation replay"
                    .to_owned(),
            });
        }

        let policy_revision = self.source.identity.state_fence.policy_revision;
        if policy_revision != Some(self.request.profile.policy_revision) {
            return Err(ContractViolation::ImplicitDefault(
                "state_fence.policy_revision",
            ));
        }
        if !fences_match_exact(
            &self.source.identity.state_fence,
            &self.admission.state_fence,
        ) || !fences_match_exact(
            &self.request.binding.state_fence,
            &self.admission.state_fence,
        ) || !fences_match_exact(
            &self.screen_binding.state_fence,
            &self.admission.state_fence,
        ) {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.state_fence",
                reason:
                    "source, native request, A-20 binding, and admission must use one exact fence"
                        .to_owned(),
            });
        }

        let request_scope = self.request.binding.scope.as_str();
        let source_scope = self.source.identity.scope.as_str();
        let request_task = self
            .request
            .binding
            .task_id
            .as_ref()
            .map(eliot_contracts::TaskId::as_str);
        if request_scope != self.admission.scope_id.as_str()
            || source_scope != self.admission.scope_id.as_str()
            || self.screen_binding.scope_id != self.admission.scope_id
            || request_task != Some(self.screen_binding.task_id.as_str())
            || self.screen_binding.task_id != self.admission.task_id
            || self.request.binding.request_id != self.screen_binding.request_id
            || self.request.binding.operation_id.as_str() != self.admission.operation_id
            || self.screen_binding.source_snapshot != self.source.identity.snapshot_id.as_str()
            || self.screen_binding.source_revision != self.source.identity.revision.to_string()
            || self.screen_binding.profile != self.request.profile.profile_id.as_str()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.owner_binding",
                reason:
                    "A-20 binding differs from the native request, source, task, scope, or profile"
                        .to_owned(),
            });
        }

        let expected_targets = string_set(
            self.request
                .partition
                .changed_targets
                .iter()
                .map(|member| member.as_str().to_owned()),
        );
        if !crate::error::sorted_set_eq(&self.screen_binding.screened_targets, &expected_targets) {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.screened_targets",
                reason: "A-20 target set differs from the native changed-target partition"
                    .to_owned(),
            });
        }

        self.validate_protection()?;
        self.validate_omissions()?;

        let expected_manifest = self.source_manifest_digest()?;
        if self.admission.frozen_manifest_digest != expected_manifest {
            return Err(ContractViolation::BindingMismatch {
                field: "admission.frozen_manifest_digest",
                reason: "frozen manifest digest differs from the owner source/evidence closure"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Revalidates this owner material against the exact protected-launch
    /// identity reconstructed by the child after its Kernel claim.
    #[allow(
        clippy::too_many_arguments,
        reason = "the protected launch revalidation must compare each independent job, request, operation, scope, idempotency, and fence binding"
    )]
    pub fn validate_for_launch(
        &self,
        job_id: &str,
        attempt_id: &str,
        request_id: &str,
        operation_id: &str,
        idempotency_key: &str,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        if self.job.job_id != job_id
            || self.request.binding.attempt_id.as_str() != attempt_id
            || self.request.binding.request_id.as_str() != request_id
            || self.request.binding.operation_id.as_str() != operation_id
            || self.admission.operation_id != operation_id
            || self.admission.idempotency_key != idempotency_key
            || self.admission.scope_id != scope_id
            || !fences_match_exact(&self.admission.state_fence, state_fence)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "curation.launch_binding",
                reason: "owner material differs from the claimed job, attempt, request, operation, scope, or fence"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_protection(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.protection_evidence.len(),
            65_536,
            "curation.protection_evidence",
        )?;
        let mut evidence_ids = BTreeSet::new();
        let mut by_member = BTreeMap::<MemberId, BTreeSet<_>>::new();
        for evidence in &self.protection_evidence {
            evidence.validate(&self.source.identity).map_err(|error| {
                ContractViolation::BindingMismatch {
                    field: "curation.protection_evidence",
                    reason: error.to_string(),
                }
            })?;
            if !evidence_ids.insert(evidence.evidence_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.protection_evidence",
                    reason: "owner protection evidence identities must be unique".to_owned(),
                });
            }
            by_member
                .entry(evidence.member_id.clone())
                .or_default()
                .insert(evidence.class);
        }
        for target in &self.request.partition.changed_targets {
            if by_member
                .get(target)
                .is_none_or(std::collections::BTreeSet::is_empty)
            {
                return Err(ContractViolation::MissingField(
                    "curation.protection_evidence.changed_target",
                ));
            }
        }
        Ok(())
    }

    fn validate_omissions(&self) -> Result<(), ContractViolation> {
        check_vec_bound(
            self.omissions.len(),
            MAX_CURATION_OMISSIONS,
            "curation.omissions",
        )?;
        let mut seen = BTreeSet::new();
        for omission in &self.omissions {
            check_text(omission, "curation.omissions", MAX_CURATION_OMISSION_TEXT)?;
            if !seen.insert(omission) {
                return Err(ContractViolation::BindingMismatch {
                    field: "curation.omissions",
                    reason: "omission identities must be unique".to_owned(),
                });
            }
        }
        let required = self.request.profile.rules.iter().fold(
            BTreeSet::<ProtectionClass>::new(),
            |mut classes, rule| {
                classes.extend(rule.required_protection.iter().copied());
                classes
            },
        );
        let evidence_resolves = |target: &MemberId, class: ProtectionClass| {
            self.protection_evidence.iter().any(|evidence| {
                evidence.member_id == *target
                    && evidence.class == class
                    && evidence.state == ProtectionEvidenceState::CurrentVerified
                    && evidence.invalidated_by.is_none()
                    && matches!(
                        evidence.outcome,
                        ProtectionOutcome::Absent | ProtectionOutcome::Present
                    )
            })
        };
        let incomplete = self.source.denominator.coverage == DenominatorCoverage::Partial
            || self.source.availability != SourceAvailability::Available
            || self.source.page.has_more
            || !self.source.page.frontier.is_empty()
            || self.request.partition.changed_targets.iter().any(|target| {
                required
                    .iter()
                    .any(|class| !evidence_resolves(target, *class))
            });
        if incomplete && self.omissions.is_empty() {
            return Err(ContractViolation::MissingField("curation.omissions"));
        }
        Ok(())
    }
}

fn string_set(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values
}
