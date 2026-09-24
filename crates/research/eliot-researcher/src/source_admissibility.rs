//! Candidate-only source-admissibility records for one inquiry evidence set.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use eliot_research_exchange_api::{AnchorPrecision, DisclosureClass, SourceClass};

use super::inquiry_governance::{
    EvidenceGrade, InquiryGovernanceError, InquiryProtocolProfile, digest, freeze, push_count,
    push_field, text, unique_texts,
};

/// Taint dimensions are preserved separately; they are not collapsed into a
/// confidence or trust score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// Exact acquisition provenance supplied by a provider route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceProvenance {
    pub source_handle: String,
    pub source_class: SourceClass,
    pub locator: String,
    pub content_digest: String,
    pub operation_id: String,
    pub receipt_handle: String,
    pub provider_generation: String,
    pub state_fence: StateFence,
    pub lineage_root: Option<String>,
}

/// Limits carried with a source candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLimits {
    pub max_anchor_precision: AnchorPrecision,
    pub allowed_uses: Vec<String>,
    pub freshness_deadline_ms: Option<i64>,
    pub retrieved_at_ms: Option<i64>,
    pub disclosure: DisclosureClass,
}

impl SourceLimits {
    fn validate(&self) -> Result<(), InquiryGovernanceError> {
        unique_texts(&self.allowed_uses, "source.allowed_uses")?;
        if self.freshness_deadline_ms.is_some_and(|value| value <= 0) {
            return Err(InquiryGovernanceError::InvalidField {
                field: "source.freshness_deadline_ms",
            });
        }
        Ok(())
    }
}

/// A provider result proposed for an inquiry evidence set. It is not a
/// canonical source record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceProposal {
    pub provenance: SourceProvenance,
    pub evidence_set_id: String,
    pub scope: String,
    pub taint: BTreeSet<SourceTaint>,
    pub limits: SourceLimits,
}

/// Eligibility result for one exact profile/evidence-set association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceAdmissibilityReason {
    ProfileRevisionMismatch,
    StateFenceMismatch,
    EvidenceSetMismatch,
    ScopeMismatch,
    ProviderNotAdmissible,
    SourceClassNotAdmissible,
    ProvenanceIncomplete,
    Tainted,
    FreshnessUnknownOrExceeded,
    DisclosureDenied,
    Eligible,
}

impl SourceAdmissibilityReason {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ProfileRevisionMismatch => "profile_revision_mismatch",
            Self::StateFenceMismatch => "state_fence_mismatch",
            Self::EvidenceSetMismatch => "evidence_set_mismatch",
            Self::ScopeMismatch => "scope_mismatch",
            Self::ProviderNotAdmissible => "provider_not_admissible",
            Self::SourceClassNotAdmissible => "source_class_not_admissible",
            Self::ProvenanceIncomplete => "provenance_incomplete",
            Self::Tainted => "tainted",
            Self::FreshnessUnknownOrExceeded => "freshness_unknown_or_exceeded",
            Self::DisclosureDenied => "disclosure_denied",
            Self::Eligible => "eligible",
        }
    }

    fn pending(self) -> bool {
        matches!(
            self,
            Self::ProvenanceIncomplete | Self::FreshnessUnknownOrExceeded
        )
    }
}

/// Non-canonical source-admissibility record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceAdmissibilityRecord {
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub evidence_set_id: String,
    pub source_handle: String,
    pub eligibility: SourceEligibility,
    pub scope: String,
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
        text(&proposal.scope, "source.scope")?;
        proposal.limits.validate()?;
        proposal.provenance.state_fence.validate().map_err(|_| {
            InquiryGovernanceError::InvalidField {
                field: "source.provenance.state_fence",
            }
        })?;
        text(&proposal.provenance.locator, "source.locator")?;
        digest(&proposal.provenance.content_digest, "source.content_digest")?;
        text(&proposal.provenance.operation_id, "source.operation_id")?;
        text(&proposal.provenance.receipt_handle, "source.receipt_handle")?;
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
        if proposal.scope != profile.scope {
            reasons.insert(SourceAdmissibilityReason::ScopeMismatch);
        }
        if proposal.provenance.state_fence != profile.state_fence {
            reasons.insert(SourceAdmissibilityReason::StateFenceMismatch);
        }
        if !profile
            .truth_surfaces_and_admissible_providers
            .iter()
            .any(|provider| provider == &proposal.provenance.provider_generation)
        {
            reasons.insert(SourceAdmissibilityReason::ProviderNotAdmissible);
        }
        if !profile.admissible_source_classes.is_empty()
            && !profile
                .admissible_source_classes
                .contains(&proposal.provenance.source_class)
        {
            reasons.insert(SourceAdmissibilityReason::SourceClassNotAdmissible);
        }
        if proposal.limits.disclosure != profile.disclosure_ceiling {
            reasons.insert(SourceAdmissibilityReason::DisclosureDenied);
        }
        if !proposal.taint.is_empty() {
            reasons.insert(SourceAdmissibilityReason::Tainted);
        }
        if profile.evidence_grade >= EvidenceGrade::Corroborated
            && proposal.provenance.lineage_root.is_none()
        {
            reasons.insert(SourceAdmissibilityReason::ProvenanceIncomplete);
        }
        match (
            proposal.limits.freshness_deadline_ms,
            proposal.limits.retrieved_at_ms,
        ) {
            (Some(deadline), Some(retrieved)) if retrieved > deadline => {
                reasons.insert(SourceAdmissibilityReason::FreshnessUnknownOrExceeded);
            }
            (Some(_), None) => {
                reasons.insert(SourceAdmissibilityReason::FreshnessUnknownOrExceeded);
            }
            _ => {}
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
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_field(&mut p, "evidence_set_id", evidence_set_id);
        push_field(&mut p, "source_handle", &proposal.provenance.source_handle);
        push_field(&mut p, "eligibility", eligibility.wire_name());
        push_field(&mut p, "scope", &proposal.scope);
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
            &format!("{:?}", proposal.limits.max_anchor_precision),
        );
        push_count(&mut p, "allowed_uses", proposal.limits.allowed_uses.len());
        for allowed_use in &proposal.limits.allowed_uses {
            push_field(&mut p, "allowed_use", allowed_use);
        }
        if let Some(value) = proposal.limits.freshness_deadline_ms {
            push_field(&mut p, "freshness_deadline_ms", &value.to_string());
        }
        if let Some(value) = proposal.limits.retrieved_at_ms {
            push_field(&mut p, "retrieved_at_ms", &value.to_string());
        }
        push_field(
            &mut p,
            "disclosure",
            &format!("{:?}", proposal.limits.disclosure),
        );
        push_count(&mut p, "reasons", reason_list.len());
        for reason in &reason_list {
            push_field(&mut p, "reason", reason.wire_name());
        }
        let digest = freeze(&p);
        Ok(Self {
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            evidence_set_id: evidence_set_id.to_owned(),
            source_handle: proposal.provenance.source_handle.clone(),
            eligibility,
            scope: proposal.scope.clone(),
            taint: proposal.taint.clone(),
            provenance: proposal.provenance.clone(),
            limits: proposal.limits.clone(),
            reasons: reason_list,
            candidate_only: true,
            governor_admission_required: true,
            digest,
        })
    }

    #[must_use]
    pub fn is_eligible_for(&self, profile: &InquiryProtocolProfile) -> bool {
        self.eligibility == SourceEligibility::Eligible
            && self.profile_id == profile.profile_id
            && self.profile_revision == profile.revision
            && self.profile_digest == profile.digest
            && self.provenance.state_fence == profile.state_fence
    }

    #[must_use]
    pub fn governor_admission_request(&self) -> GovernorSourceAdmissionRequest {
        GovernorSourceAdmissionRequest {
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorSourceAdmissionRequest {
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub evidence_set_id: String,
    pub source_handle: String,
    pub admissibility_digest: String,
    pub candidate_only: bool,
    pub canonical_write_authorized: bool,
}
