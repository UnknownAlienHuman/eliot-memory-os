//! Candidate-only source-admissibility records for one inquiry evidence set.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use eliot_contracts::{StateFence, TaskId};
use eliot_research_exchange_api::{AnchorPrecision, DisclosureClass, SourceClass};

use super::inquiry_governance::{
    InquiryGovernanceError, InquiryProtocolProfile, digest, freeze, push_count, push_field, text,
    unique_texts,
};

/// Taint dimensions are preserved separately; they are not collapsed into a
/// confidence or trust score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceTaint {
    UnverifiedProvenance,
    Stale,
    Partial,
    Conflicted,
    UnknownIndependence,
    PolicyDenied,
    UnknownScope,
}

impl SourceTaint {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::UnverifiedProvenance => "unverified_provenance",
            Self::Stale => "stale",
            Self::Partial => "partial",
            Self::Conflicted => "conflicted",
            Self::UnknownIndependence => "unknown_independence",
            Self::PolicyDenied => "policy_denied",
            Self::UnknownScope => "unknown_scope",
        }
    }

    fn pending(self) -> bool {
        matches!(self, Self::UnknownIndependence | Self::UnknownScope)
    }
}

/// Independence evidence is explicit; a provider label or repetition never
/// supplies independence by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceIndependence {
    /// The exact lineage root and family were checked.
    Known,
    /// The source is known to depend on another source in this inquiry.
    Dependent,
    /// No independent-family evidence was supplied.
    Unknown,
}

impl SourceIndependence {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Known => "known",
            Self::Dependent => "dependent",
            Self::Unknown => "unknown",
        }
    }
}

fn disclosure_rank(value: DisclosureClass) -> u8 {
    match value {
        DisclosureClass::Private => 0,
        DisclosureClass::ProjectBound => 1,
        DisclosureClass::ExportableRedacted => 2,
        DisclosureClass::Public => 3,
    }
}

/// Exact acquisition provenance supplied by a provider route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProvenance {
    pub source_handle: String,
    pub source_class: SourceClass,
    pub locator: String,
    pub content_digest: String,
    pub operation_id: String,
    pub receipt_handle: String,
    pub route_id: String,
    pub provider_generation: String,
    pub state_fence: StateFence,
    pub lineage_root: Option<String>,
}

/// Limits carried with a source candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLimits {
    pub max_anchor_precision: AnchorPrecision,
    pub allowed_uses: Vec<String>,
    pub freshness_deadline_ms: Option<i64>,
    pub retrieved_at_ms: Option<i64>,
    pub disclosure: DisclosureClass,
}

impl SourceLimits {
    fn validate(&self) -> Result<(), InquiryGovernanceError> {
        if self.allowed_uses.is_empty() {
            return Err(InquiryGovernanceError::Blank {
                field: "source.allowed_uses",
            });
        }
        unique_texts(&self.allowed_uses, "source.allowed_uses")?;
        if self.freshness_deadline_ms.is_some_and(|value| value <= 0)
            || self.retrieved_at_ms.is_some_and(|value| value <= 0)
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "source.freshness",
            });
        }
        Ok(())
    }
}

/// A provider result proposed for an inquiry evidence set. It is not a
/// canonical source record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProposal {
    pub task_id: TaskId,
    pub task_definition_digest: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub provenance: SourceProvenance,
    pub requested_anchor_precision: AnchorPrecision,
    pub independence: SourceIndependence,
    pub evidence_set_id: String,
    pub scope: String,
    /// Governed observation time used for the currentness decision.
    pub assessment_time_ms: i64,
    pub taint: BTreeSet<SourceTaint>,
    pub limits: SourceLimits,
}

/// Eligibility result for one exact profile/evidence-set association.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceEligibility {
    Eligible,
    Ineligible,
    Pending,
}

impl SourceEligibility {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Eligible => "ELIGIBLE",
            Self::Ineligible => "INELIGIBLE",
            Self::Pending => "PENDING",
        }
    }
}

/// Typed source-admissibility reason codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceAdmissibilityReason {
    ProfileIdentityMismatch,
    ProfileRevisionMismatch,
    ProfileDigestMismatch,
    TaskIdentityMismatch,
    TaskDefinitionMismatch,
    StateFenceMismatch,
    EvidenceSetMismatch,
    ScopeMismatch,
    ProviderNotAdmissible,
    SourceClassNotAdmissible,
    ProvenanceIncomplete,
    AllowedUseDenied,
    PrecisionUnknownOrExceeded,
    IndependenceUnknown,
    IndependenceDependent,
    Tainted,
    FreshnessUnknownOrExceeded,
    DisclosureDenied,
    Eligible,
}

impl SourceAdmissibilityReason {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ProfileIdentityMismatch => "profile_identity_mismatch",
            Self::ProfileRevisionMismatch => "profile_revision_mismatch",
            Self::ProfileDigestMismatch => "profile_digest_mismatch",
            Self::TaskIdentityMismatch => "task_identity_mismatch",
            Self::TaskDefinitionMismatch => "task_definition_mismatch",
            Self::StateFenceMismatch => "state_fence_mismatch",
            Self::EvidenceSetMismatch => "evidence_set_mismatch",
            Self::ScopeMismatch => "scope_mismatch",
            Self::ProviderNotAdmissible => "provider_not_admissible",
            Self::SourceClassNotAdmissible => "source_class_not_admissible",
            Self::ProvenanceIncomplete => "provenance_incomplete",
            Self::AllowedUseDenied => "allowed_use_denied",
            Self::PrecisionUnknownOrExceeded => "precision_unknown_or_exceeded",
            Self::IndependenceUnknown => "independence_unknown",
            Self::IndependenceDependent => "independence_dependent",
            Self::Tainted => "tainted",
            Self::FreshnessUnknownOrExceeded => "freshness_unknown_or_exceeded",
            Self::DisclosureDenied => "disclosure_denied",
            Self::Eligible => "eligible",
        }
    }

    fn pending(self) -> bool {
        matches!(
            self,
            Self::ProvenanceIncomplete
                | Self::PrecisionUnknownOrExceeded
                | Self::IndependenceUnknown
                | Self::FreshnessUnknownOrExceeded
        )
    }
}

/// Non-canonical source-admissibility record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAdmissibilityRecord {
    pub task_id: TaskId,
    pub task_definition_digest: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub evidence_set_id: String,
    pub source_handle: String,
    pub route_id: String,
    pub requested_anchor_precision: AnchorPrecision,
    pub independence: SourceIndependence,
    pub eligibility: SourceEligibility,
    pub scope: String,
    pub assessment_time_ms: i64,
    pub taint: BTreeSet<SourceTaint>,
    pub provenance: SourceProvenance,
    pub limits: SourceLimits,
    pub reasons: Vec<SourceAdmissibilityReason>,
    pub candidate_only: bool,
    pub governor_admission_required: bool,
    pub digest: String,
}

impl SourceAdmissibilityRecord {
    /// Evaluates a proposal only against the supplied exact profile revision.
    #[allow(clippy::too_many_lines)]
    pub fn evaluate(
        profile: &InquiryProtocolProfile,
        evidence_set_id: &str,
        proposal: &SourceProposal,
    ) -> Result<Self, InquiryGovernanceError> {
        text(evidence_set_id, "source.evidence_set_id")?;
        text(&proposal.evidence_set_id, "source.proposal_evidence_set_id")?;
        text(&proposal.provenance.source_handle, "source.source_handle")?;
        text(proposal.task_id.as_str(), "source.task_id")?;
        digest(
            &proposal.task_definition_digest,
            "source.task_definition_digest",
        )?;
        text(&proposal.profile_id, "source.profile_id")?;
        if proposal.profile_revision == 0 {
            return Err(InquiryGovernanceError::InvalidField {
                field: "source.profile_revision",
            });
        }
        digest(&proposal.profile_digest, "source.profile_digest")?;
        text(&proposal.scope, "source.scope")?;
        if proposal.assessment_time_ms <= 0 {
            return Err(InquiryGovernanceError::InvalidField {
                field: "source.assessment_time_ms",
            });
        }
        let mut limits = proposal.limits.clone();
        limits.allowed_uses.sort();
        limits.validate()?;
        proposal.provenance.state_fence.validate().map_err(|_| {
            InquiryGovernanceError::InvalidField {
                field: "source.provenance.state_fence",
            }
        })?;
        text(&proposal.provenance.locator, "source.locator")?;
        digest(&proposal.provenance.content_digest, "source.content_digest")?;
        text(&proposal.provenance.operation_id, "source.operation_id")?;
        text(&proposal.provenance.receipt_handle, "source.receipt_handle")?;
        text(&proposal.provenance.route_id, "source.route_id")?;
        text(
            &proposal.provenance.provider_generation,
            "source.provider_generation",
        )?;
        if let Some(root) = &proposal.provenance.lineage_root {
            text(root, "source.lineage_root")?;
        }

        let mut reasons = BTreeSet::new();
        if proposal.evidence_set_id != evidence_set_id {
            reasons.insert(SourceAdmissibilityReason::EvidenceSetMismatch);
        }
        if proposal.task_id != profile.task_id {
            reasons.insert(SourceAdmissibilityReason::TaskIdentityMismatch);
        }
        if proposal.task_definition_digest != profile.task_definition_digest {
            reasons.insert(SourceAdmissibilityReason::TaskDefinitionMismatch);
        }
        if proposal.profile_id != profile.profile_id {
            reasons.insert(SourceAdmissibilityReason::ProfileIdentityMismatch);
        }
        if proposal.profile_revision != profile.revision {
            reasons.insert(SourceAdmissibilityReason::ProfileRevisionMismatch);
        }
        if proposal.profile_digest != profile.digest {
            reasons.insert(SourceAdmissibilityReason::ProfileDigestMismatch);
        }
        if !profile.matches_task_binding(
            &proposal.task_id,
            &proposal.task_definition_digest,
            &proposal.provenance.state_fence,
        ) {
            reasons.insert(SourceAdmissibilityReason::StateFenceMismatch);
        }
        if proposal.scope != profile.scope {
            reasons.insert(SourceAdmissibilityReason::ScopeMismatch);
        }
        if proposal.provenance.state_fence != profile.state_fence {
            reasons.insert(SourceAdmissibilityReason::StateFenceMismatch);
        }
        if !profile
            .truth_surfaces_and_admissible_providers
            .iter()
            .any(|provider| provider == &proposal.provenance.route_id)
        {
            reasons.insert(SourceAdmissibilityReason::ProviderNotAdmissible);
        }
        if !profile
            .admissible_source_classes
            .contains(&proposal.provenance.source_class)
        {
            reasons.insert(SourceAdmissibilityReason::SourceClassNotAdmissible);
        }
        if limits
            .allowed_uses
            .iter()
            .any(|allowed_use| !profile.allowed_uses.contains(allowed_use))
        {
            reasons.insert(SourceAdmissibilityReason::AllowedUseDenied);
        }
        if limits.max_anchor_precision < proposal.requested_anchor_precision {
            reasons.insert(SourceAdmissibilityReason::PrecisionUnknownOrExceeded);
        }
        if disclosure_rank(limits.disclosure) > disclosure_rank(profile.disclosure_ceiling) {
            reasons.insert(SourceAdmissibilityReason::DisclosureDenied);
        }
        match proposal.independence {
            SourceIndependence::Unknown => {
                reasons.insert(SourceAdmissibilityReason::IndependenceUnknown);
            }
            SourceIndependence::Dependent => {
                reasons.insert(SourceAdmissibilityReason::IndependenceDependent);
            }
            SourceIndependence::Known => {
                if proposal.provenance.lineage_root.is_none() {
                    reasons.insert(SourceAdmissibilityReason::ProvenanceIncomplete);
                }
            }
        }
        if !proposal.taint.is_empty() {
            reasons.insert(SourceAdmissibilityReason::Tainted);
        }
        match (limits.freshness_deadline_ms, limits.retrieved_at_ms) {
            (Some(deadline), Some(retrieved))
                if retrieved <= proposal.assessment_time_ms
                    && proposal.assessment_time_ms <= deadline => {}
            _ => {
                reasons.insert(SourceAdmissibilityReason::FreshnessUnknownOrExceeded);
            }
        }
        let reasons = if reasons.is_empty() {
            BTreeSet::from([SourceAdmissibilityReason::Eligible])
        } else {
            reasons
        };
        let pending_taint = proposal.taint.iter().any(|taint| taint.pending());
        let eligibility = if reasons.contains(&SourceAdmissibilityReason::Eligible) {
            SourceEligibility::Eligible
        } else if pending_taint || reasons.iter().any(|reason| reason.pending()) {
            SourceEligibility::Pending
        } else {
            SourceEligibility::Ineligible
        };
        let mut reason_list = reasons.into_iter().collect::<Vec<_>>();
        reason_list.sort();

        let mut p = String::from("source-admissibility/v1;");
        push_field(&mut p, "task_id", proposal.task_id.as_str());
        push_field(
            &mut p,
            "task_definition_digest",
            &proposal.task_definition_digest,
        );
        push_field(&mut p, "profile_id", &proposal.profile_id);
        push_field(
            &mut p,
            "profile_revision",
            &proposal.profile_revision.to_string(),
        );
        push_field(&mut p, "profile_digest", &proposal.profile_digest);
        push_field(&mut p, "evidence_set_id", evidence_set_id);
        push_field(&mut p, "source_handle", &proposal.provenance.source_handle);
        push_field(&mut p, "route_id", &proposal.provenance.route_id);
        push_field(
            &mut p,
            "requested_anchor_precision",
            &format!("{:?}", proposal.requested_anchor_precision),
        );
        push_field(&mut p, "independence", proposal.independence.wire_name());
        push_field(&mut p, "eligibility", eligibility.wire_name());
        push_field(&mut p, "scope", &proposal.scope);
        push_field(
            &mut p,
            "assessment_time_ms",
            &proposal.assessment_time_ms.to_string(),
        );
        push_count(&mut p, "taint", proposal.taint.len());
        for taint in &proposal.taint {
            push_field(&mut p, "taint", taint.wire_name());
        }
        push_field(
            &mut p,
            "source_class",
            &format!("{:?}", proposal.provenance.source_class),
        );
        push_field(&mut p, "locator", &proposal.provenance.locator);
        push_field(
            &mut p,
            "content_digest",
            &proposal.provenance.content_digest,
        );
        push_field(&mut p, "operation_id", &proposal.provenance.operation_id);
        push_field(
            &mut p,
            "receipt_handle",
            &proposal.provenance.receipt_handle,
        );
        push_field(
            &mut p,
            "provider_generation",
            &proposal.provenance.provider_generation,
        );
        if let Some(root) = &proposal.provenance.lineage_root {
            push_field(&mut p, "lineage_root", root);
        }
        push_field(
            &mut p,
            "max_anchor_precision",
            &format!("{:?}", limits.max_anchor_precision),
        );
        push_count(&mut p, "allowed_uses", limits.allowed_uses.len());
        for allowed_use in &limits.allowed_uses {
            push_field(&mut p, "allowed_use", allowed_use);
        }
        if let Some(value) = limits.freshness_deadline_ms {
            push_field(&mut p, "freshness_deadline_ms", &value.to_string());
        }
        if let Some(value) = limits.retrieved_at_ms {
            push_field(&mut p, "retrieved_at_ms", &value.to_string());
        }
        push_field(&mut p, "disclosure", &format!("{:?}", limits.disclosure));
        push_count(&mut p, "reasons", reason_list.len());
        for reason in &reason_list {
            push_field(&mut p, "reason", reason.wire_name());
        }
        let digest = freeze(&p);
        Ok(Self {
            task_id: proposal.task_id.clone(),
            task_definition_digest: proposal.task_definition_digest.clone(),
            profile_id: proposal.profile_id.clone(),
            profile_revision: proposal.profile_revision,
            profile_digest: proposal.profile_digest.clone(),
            evidence_set_id: evidence_set_id.to_owned(),
            source_handle: proposal.provenance.source_handle.clone(),
            route_id: proposal.provenance.route_id.clone(),
            requested_anchor_precision: proposal.requested_anchor_precision,
            independence: proposal.independence,
            eligibility,
            scope: proposal.scope.clone(),
            assessment_time_ms: proposal.assessment_time_ms,
            taint: proposal.taint.clone(),
            provenance: proposal.provenance.clone(),
            limits: limits.clone(),
            reasons: reason_list,
            candidate_only: true,
            governor_admission_required: true,
            digest,
        })
    }

    #[must_use]
    pub fn is_eligible_for(&self, profile: &InquiryProtocolProfile) -> bool {
        self.eligibility == SourceEligibility::Eligible
            && self.task_id == profile.task_id
            && self.task_definition_digest == profile.task_definition_digest
            && self.profile_id == profile.profile_id
            && self.profile_revision == profile.revision
            && self.profile_digest == profile.digest
            && self.provenance.state_fence == profile.state_fence
            && profile.matches_task_binding(
                &self.task_id,
                &self.task_definition_digest,
                &self.provenance.state_fence,
            )
    }

    #[must_use]
    pub fn governor_admission_request(&self) -> GovernorSourceAdmissionRequest {
        GovernorSourceAdmissionRequest {
            task_id: self.task_id.clone(),
            task_definition_digest: self.task_definition_digest.clone(),
            profile_id: self.profile_id.clone(),
            profile_revision: self.profile_revision,
            profile_digest: self.profile_digest.clone(),
            evidence_set_id: self.evidence_set_id.clone(),
            source_handle: self.source_handle.clone(),
            admissibility_digest: self.digest.clone(),
            candidate_only: self.candidate_only,
            canonical_write_authorized: false,
        }
    }
}

/// Request addressed to the existing Governor/Kernel transition path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernorSourceAdmissionRequest {
    pub task_id: TaskId,
    pub task_definition_digest: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub evidence_set_id: String,
    pub source_handle: String,
    pub admissibility_digest: String,
    pub candidate_only: bool,
    pub canonical_write_authorized: bool,
}
