//! Source-admissibility disposition for one inquiry evidence set (issue #1762).
//!
//! Source admissibility is not canonical promotion. This module records whether
//! a source is eligible, ineligible or pending for one inquiry evidence set,
//! with scope, taint, provenance and limits; the Governor applies any resulting
//! state transition through the sole canonical writer. Nothing here writes
//! canonical state, mints a citation, or promotes output to current belief.
//!
//! The vetted record itself, with its provenance, integrity, freshness,
//! incentives, risk, allowed use, allowed effects, required verifier and
//! quarantine, is owned by [`crate::evidence_portfolio::SourceRecord`]. This
//! module references that record rather than restating it, and adds only the
//! eligibility decision an inquiry evidence set needs.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use eliot_research_exchange_api::{AllowedReferenceManifest, AnchorPrecision, DisclosureClass};

use crate::evidence_portfolio::{SourceRecord, freeze, push_count, push_field, text};
use crate::inquiry_governance::{InquiryError, InquiryProtocolProfile};

/// Taint carried by one proposed source.
///
/// Taint is a typed fact about the material, never a judgement about its
/// conclusions: an unassessed dimension stays explicit instead of being
/// silently treated as clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceTaint {
    /// Instruction-like text was observed in the material and stays inert data.
    InstructionLikeContent,
    /// Authorship was not established.
    UnverifiedAuthorship,
    /// A declared commercial interest is attached to the material.
    DeclaredCommercialInterest,
    /// The material is derived from a parent summary rather than a source.
    DerivedFromParentSummary,
    /// The material is retracted or superseded.
    RetractedOrSuperseded,
    /// Common lineage could not be established.
    UnresolvedLineage,
    /// The material is past its freshness boundary.
    StaleBeyondFreshnessBoundary,
}

impl SourceTaint {
    /// Stable wire spelling of this taint.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::InstructionLikeContent => "instruction_like_content",
            Self::UnverifiedAuthorship => "unverified_authorship",
            Self::DeclaredCommercialInterest => "declared_commercial_interest",
            Self::DerivedFromParentSummary => "derived_from_parent_summary",
            Self::RetractedOrSuperseded => "retracted_or_superseded",
            Self::UnresolvedLineage => "unresolved_lineage",
            Self::StaleBeyondFreshnessBoundary => "stale_beyond_freshness_boundary",
        }
    }

    /// Whether this taint alone blocks evidentiary use of the source.
    ///
    /// Taints that bound how a source may be used rather than whether it may be
    /// used at all stay non-blocking; the record's own allowed use carries the
    /// bound.
    #[must_use]
    pub const fn blocks_use(self) -> bool {
        matches!(
            self,
            Self::InstructionLikeContent
                | Self::RetractedOrSuperseded
                | Self::StaleBeyondFreshnessBoundary
                | Self::UnresolvedLineage
        )
    }
}

/// Independence facts of one proposed source (I21.6).
///
/// Two outputs are dependent when they share a source, restate one primary
/// work, run on one model family, saw one parent summary, use one evaluator or
/// inherit one mistaken assumption. Independence is a fact about lineage, so it
/// is derived from the vetted record and never declared by a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceIndependence {
    /// Exact common lineage root, when the record carries one.
    pub lineage_root: Option<String>,
    /// Shared context ancestor the material descends from, when known.
    pub shared_context_ancestor: Option<String>,
    /// Assumptions this material is known to share with the rest of the set.
    pub shared_assumptions: Vec<String>,
    /// Material this record was transformed from, when derived.
    pub derived_from: Option<String>,
}

impl SourceIndependence {
    /// Derives the independence facts of one vetted record.
    #[must_use]
    pub fn from_record(record: &SourceRecord) -> Self {
        let mut shared_assumptions: Vec<String> = record.content_flags.iter().cloned().collect();
        shared_assumptions.sort();
        Self {
            lineage_root: record.lineage_root.clone(),
            shared_context_ancestor: record.transformed_from.clone(),
            shared_assumptions,
            derived_from: record.transformed_from.clone(),
        }
    }

    /// Whether independence of this source is established.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.lineage_root.is_some()
    }
}

/// Limits one proposed source carries into an inquiry evidence set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLimits {
    /// Highest anchor precision this source may be cited at.
    pub max_anchor_precision: AnchorPrecision,
    /// Allowed epistemic uses, carried verbatim from the vetted record.
    pub allowed_uses: Vec<String>,
    /// Freshness boundary in Unix milliseconds, when one was frozen.
    pub freshness_boundary_ms: Option<i64>,
    /// Privacy class the source is carried under.
    pub disclosure: DisclosureClass,
    /// Required verifier or quarantine condition.
    pub verifier: String,
}

/// Eligibility of one proposed source for one inquiry evidence set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceEligibility {
    /// The source may enter this evidence set as candidate material.
    Eligible,
    /// The source may not enter this evidence set.
    Ineligible,
    /// The source is admissible in principle but a required fact is still
    /// unresolved, so it waits instead of being admitted or refused.
    Pending,
}

impl SourceEligibility {
    /// Stable wire spelling of this eligibility.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Eligible => "ELIGIBLE",
            Self::Ineligible => "INELIGIBLE",
            Self::Pending => "PENDING",
        }
    }
}

/// Typed reason one source is eligible, ineligible or pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceAdmissibilityReason {
    /// Every declared requirement for this inquiry is met.
    RequirementsMet,
    /// The source class is not admitted by this inquiry profile.
    ClassNotAdmitted,
    /// The reference manifest does not admit this handle yet.
    ///
    /// The material was resolved and snapshotted by an admitted provider, so it
    /// is admissible in principle; it waits for the Governor-admitted
    /// `SourceRecord` transition that adds its handle to the frozen manifest
    /// instead of becoming a citable reference.
    AwaitingReferenceAdmission,
    /// The handle is present in the manifest but stale or revoked.
    ManifestEntryRevoked,
    /// The source is outside the frozen inquiry scope.
    OutsideInquiryScope,
    /// The acquisition did not close, so the material carries no weight.
    AcquisitionDidNotClose,
    /// The material is past its freshness boundary.
    FreshnessBoundaryPassed,
    /// The record is quarantined and cannot be used evidentially.
    Quarantined,
    /// The privacy class is wider than the inquiry's disclosure ceiling.
    DisclosureWiderThanCeiling,
    /// A taint blocks evidentiary use.
    TaintBlocksUse,
    /// Common lineage is unknown, so independence is unproven.
    IndependenceUnproven,
}

impl SourceAdmissibilityReason {
    /// Stable wire spelling of this reason.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::RequirementsMet => "REQUIREMENTS_MET",
            Self::ClassNotAdmitted => "CLASS_NOT_ADMITTED",
            Self::AwaitingReferenceAdmission => "AWAITING_REFERENCE_ADMISSION",
            Self::ManifestEntryRevoked => "MANIFEST_ENTRY_REVOKED",
            Self::OutsideInquiryScope => "OUTSIDE_INQUIRY_SCOPE",
            Self::AcquisitionDidNotClose => "ACQUISITION_DID_NOT_CLOSE",
            Self::FreshnessBoundaryPassed => "FRESHNESS_BOUNDARY_PASSED",
            Self::Quarantined => "QUARANTINED",
            Self::DisclosureWiderThanCeiling => "DISCLOSURE_WIDER_THAN_CEILING",
            Self::TaintBlocksUse => "TAINT_BLOCKS_USE",
            Self::IndependenceUnproven => "INDEPENDENCE_UNPROVEN",
        }
    }

    /// Whether this reason blocks admission outright or only defers it.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        !matches!(self, Self::RequirementsMet)
    }
}

/// Source-admissibility disposition for one inquiry evidence set (I21.1/I21.7).
///
/// The record carries the vetted source it decided on, the scope it is admitted
/// for, its taint, its independence and its limits, the typed reasons behind
/// the decision, and the association with the exact inquiry evidence set. It is
/// candidate-only: Governor admission applies any resulting transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceAdmissibilityRecord {
    /// Inquiry identity this decision belongs to.
    pub inquiry_id: String,
    /// Evidence-set identity this decision belongs to.
    pub evidence_set_id: String,
    /// Profile identity the decision was made under.
    pub profile_id: String,
    /// Profile revision the decision was made under.
    pub profile_revision: u64,
    /// Exact profile revision digest.
    pub profile_digest: String,
    /// The vetted source record this decision is about.
    pub record: SourceRecord,
    /// Exact scope the source is admitted for.
    pub scope: String,
    /// Eligibility decision.
    pub eligibility: SourceEligibility,
    /// Taint observed on the source.
    pub taint: BTreeSet<SourceTaint>,
    /// Independence facts of the source.
    pub independence: SourceIndependence,
    /// Limits the source carries into the evidence set.
    pub limits: SourceLimits,
    /// Typed reasons behind the decision, in canonical order.
    pub reasons: Vec<SourceAdmissibilityReason>,
    /// Assessment instant in Unix milliseconds.
    pub assessment_time_ms: i64,
    /// State Fence the decision was taken under.
    pub state_fence: StateFence,
    /// Always true: an admissibility record stays candidate-only.
    pub candidate_only: bool,
    /// Always true: the transition itself is the Governor's to apply.
    pub governor_admission_required: bool,
    /// Digest over the decision shape.
    pub digest: String,
}

impl SourceAdmissibilityRecord {
    /// Decides whether one vetted source may enter one inquiry evidence set.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank inquiry, evidence-set or scope
    /// identity, and [`InquiryError::Duplicate`] when the record was already
    /// decided for a different evidence set.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate(
        inquiry_id: &str,
        evidence_set_id: &str,
        profile: &InquiryProtocolProfile,
        record: SourceRecord,
        scope: &str,
        manifest: &AllowedReferenceManifest,
        assessment_time_ms: i64,
    ) -> Result<Self, InquiryError> {
        text(inquiry_id, "admissibility.inquiry_id").map_err(InquiryError::from)?;
        text(evidence_set_id, "admissibility.evidence_set_id").map_err(InquiryError::from)?;
        text(scope, "admissibility.scope").map_err(InquiryError::from)?;
        if profile.inquiry_id != inquiry_id {
            return Err(InquiryError::Duplicate {
                field: "admissibility.inquiry_binding",
            });
        }
        let independence = SourceIndependence::from_record(&record);
        let taint = observed_taint(&record, assessment_time_ms);
        let limits = SourceLimits {
            max_anchor_precision: max_anchor_precision(&record),
            allowed_uses: vec![record.allowed_use.clone()],
            freshness_boundary_ms: record.freshness_boundary_ms,
            disclosure: record.disclosure,
            verifier: record.verifier.clone(),
        };
        let reasons = decide(
            &record,
            profile,
            &independence,
            &taint,
            scope,
            manifest,
            assessment_time_ms,
        );
        let eligibility = eligibility_of(&reasons);
        let mut disposition = Self {
            inquiry_id: inquiry_id.to_owned(),
            evidence_set_id: evidence_set_id.to_owned(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.integrity_digest.clone(),
            record,
            scope: scope.to_owned(),
            eligibility,
            taint,
            independence,
            limits,
            reasons,
            assessment_time_ms,
            state_fence: profile.state_fence.clone(),
            candidate_only: true,
            governor_admission_required: true,
            digest: String::new(),
        };
        disposition.digest = disposition.compute_digest();
        Ok(disposition)
    }

    /// Whether this source is admitted to the exact evidence set named by
    /// `profile`.
    #[must_use]
    pub fn is_admitted_to(&self, profile: &InquiryProtocolProfile) -> bool {
        self.eligibility == SourceEligibility::Eligible
            && self.profile_digest == profile.integrity_digest
            && self.inquiry_id == profile.inquiry_id
    }

    /// Builds the Governor-facing source transition request.
    ///
    /// The request asks the existing Governor admission path to apply the
    /// resulting transition. It grants no canonical write, no finish and no
    /// influence over any other source.
    #[must_use]
    pub fn transition_request(&self) -> GovernorSourceTransitionRequest {
        GovernorSourceTransitionRequest {
            request_kind: GovernorSourceTransitionRequest::REQUEST_KIND.to_owned(),
            inquiry_id: self.inquiry_id.clone(),
            evidence_set_id: self.evidence_set_id.clone(),
            profile_id: self.profile_id.clone(),
            profile_revision: self.profile_revision,
            profile_digest: self.profile_digest.clone(),
            source_handle: self.record.handle.clone(),
            source_record_digest: self.record.digest(),
            eligibility: self.eligibility,
            admissibility_digest: self.digest.clone(),
            scope: self.scope.clone(),
            state_fence: self.state_fence.clone(),
            candidate_only: true,
            canonical_write_authorized: false,
        }
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("source-admissibility/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(
            &mut preimage,
            "profile_revision",
            &self.profile_revision.to_string(),
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "source_record", &self.record.digest());
        push_field(&mut preimage, "scope", &self.scope);
        push_field(&mut preimage, "eligibility", self.eligibility.wire_name());
        push_count(&mut preimage, "taint", self.taint.len());
        for taint in &self.taint {
            push_field(&mut preimage, "taint", taint.wire_name());
        }
        push_field(
            &mut preimage,
            "independence_root",
            self.independence
                .lineage_root
                .as_deref()
                .unwrap_or("unknown_lineage"),
        );
        push_field(
            &mut preimage,
            "max_anchor_precision",
            anchor_wire(self.limits.max_anchor_precision),
        );
        push_field(
            &mut preimage,
            "limits_disclosure",
            disclosure_wire(self.limits.disclosure),
        );
        push_field(&mut preimage, "limits_verifier", &self.limits.verifier);
        push_count(&mut preimage, "reasons", self.reasons.len());
        for reason in &self.reasons {
            push_field(&mut preimage, "reason", reason.wire_name());
        }
        push_field(
            &mut preimage,
            "assessment_time_ms",
            &self.assessment_time_ms.to_string(),
        );
        freeze(&preimage)
    }

    /// Re-proves this decision's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "admissibility.digest",
            });
        }
        Ok(())
    }
}

/// Governor-facing source transition request for one admissibility decision.
///
/// The domain records the decision; the Governor applies it. The request carries
/// no canonical-write authority and cannot finish a task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorSourceTransitionRequest {
    /// Closed request-kind discriminator.
    pub request_kind: String,
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Evidence-set identity.
    pub evidence_set_id: String,
    /// Profile identity the decision was made under.
    pub profile_id: String,
    /// Profile revision the decision was made under.
    pub profile_revision: u64,
    /// Exact profile revision digest.
    pub profile_digest: String,
    /// Source handle the decision is about.
    pub source_handle: String,
    /// Exact digest of the vetted source record.
    pub source_record_digest: String,
    /// Eligibility the Researcher recorded.
    pub eligibility: SourceEligibility,
    /// Exact digest of the admissibility decision.
    pub admissibility_digest: String,
    /// Exact scope the decision is scoped to.
    pub scope: String,
    /// State Fence the decision was taken under.
    pub state_fence: StateFence,
    /// Always true: the decision stays candidate-only.
    pub candidate_only: bool,
    /// Always false: this domain never authorizes a canonical write.
    pub canonical_write_authorized: bool,
}

impl GovernorSourceTransitionRequest {
    /// Closed request-kind discriminator for a source transition.
    pub const REQUEST_KIND: &'static str = "inquiry_source_admissibility";
}

/// Derives the highest anchor precision a vetted record may be cited at.
///
/// A record that carries no structured evidence span supports a source-level
/// reference only: a file, document or section anchor is not backed by a span the
/// record actually froze. A frozen span anchor names the strongest coordinate it
/// can carry, and the record supports the strongest span it holds.
fn max_anchor_precision(record: &SourceRecord) -> AnchorPrecision {
    let mut precision = AnchorPrecision::Source;
    for span in &record.evidence_spans {
        let candidate = if span.anchor.contains(':') {
            AnchorPrecision::Section
        } else if span.anchor.contains('#') {
            AnchorPrecision::Page
        } else {
            AnchorPrecision::Document
        };
        if candidate > precision {
            precision = candidate;
        }
    }
    precision
}

/// Derives the taint observed on a vetted record at `assessment_time_ms`.
fn observed_taint(record: &SourceRecord, assessment_time_ms: i64) -> BTreeSet<SourceTaint> {
    let mut taint = BTreeSet::new();
    if record.content_flags.contains("instruction_like_content") {
        taint.insert(SourceTaint::InstructionLikeContent);
    }
    if record.content_flags.contains("unverified_authorship") {
        taint.insert(SourceTaint::UnverifiedAuthorship);
    }
    if record
        .content_flags
        .contains("declared_commercial_interest")
    {
        taint.insert(SourceTaint::DeclaredCommercialInterest);
    }
    if record.transformed_from.is_some() {
        taint.insert(SourceTaint::DerivedFromParentSummary);
    }
    if record.content_flags.contains("retracted_or_superseded") {
        taint.insert(SourceTaint::RetractedOrSuperseded);
    }
    if record.lineage_root.is_none() {
        taint.insert(SourceTaint::UnresolvedLineage);
    }
    if record.is_stale_at(assessment_time_ms) {
        taint.insert(SourceTaint::StaleBeyondFreshnessBoundary);
    }
    taint
}

/// Collects every typed reason this source is not admitted to the evidence set.
#[allow(clippy::too_many_arguments)]
fn decide(
    record: &SourceRecord,
    profile: &InquiryProtocolProfile,
    independence: &SourceIndependence,
    taint: &BTreeSet<SourceTaint>,
    scope: &str,
    manifest: &AllowedReferenceManifest,
    assessment_time_ms: i64,
) -> Vec<SourceAdmissibilityReason> {
    let mut reasons = Vec::new();
    if !profile.admissible_source_classes.contains(&record.class) {
        reasons.push(SourceAdmissibilityReason::ClassNotAdmitted);
    }
    if manifest.stale_or_revoked_handles.contains(&record.handle) {
        reasons.push(SourceAdmissibilityReason::ManifestEntryRevoked);
    }
    if !manifest.allows(&record.handle) {
        reasons.push(SourceAdmissibilityReason::AwaitingReferenceAdmission);
    }
    if !record.covers_domain(scope) {
        reasons.push(SourceAdmissibilityReason::OutsideInquiryScope);
    }
    if !record.acquisition.may_support() {
        reasons.push(SourceAdmissibilityReason::AcquisitionDidNotClose);
    }
    if record.is_stale_at(assessment_time_ms) {
        reasons.push(SourceAdmissibilityReason::FreshnessBoundaryPassed);
    }
    if record.quarantine.is_some() {
        reasons.push(SourceAdmissibilityReason::Quarantined);
    }
    if disclosure_rank(record.disclosure) > disclosure_rank(profile.disclosure_ceiling) {
        reasons.push(SourceAdmissibilityReason::DisclosureWiderThanCeiling);
    }
    if taint.iter().any(|taint| taint.blocks_use()) {
        reasons.push(SourceAdmissibilityReason::TaintBlocksUse);
    }
    if !independence.is_established()
        && profile
            .independence_and_blinding_policy
            .minimum_independent_families
            > 0
    {
        reasons.push(SourceAdmissibilityReason::IndependenceUnproven);
    }
    if reasons.is_empty() {
        reasons.push(SourceAdmissibilityReason::RequirementsMet);
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

/// Maps the collected reasons onto one eligibility decision.
///
/// A source with only a deferrable reason waits instead of being refused, and a
/// source with any blocking reason is refused; nothing here defaults to
/// admitted.
fn eligibility_of(reasons: &[SourceAdmissibilityReason]) -> SourceEligibility {
    if reasons.contains(&SourceAdmissibilityReason::RequirementsMet) {
        return SourceEligibility::Eligible;
    }
    let deferrable = [
        SourceAdmissibilityReason::AwaitingReferenceAdmission,
        SourceAdmissibilityReason::IndependenceUnproven,
        SourceAdmissibilityReason::FreshnessBoundaryPassed,
    ];
    if reasons.iter().any(|reason| deferrable.contains(reason))
        && !reasons
            .iter()
            .any(|reason| reason.is_blocking() && !deferrable.contains(reason))
    {
        SourceEligibility::Pending
    } else {
        SourceEligibility::Ineligible
    }
}

/// Stable wire spelling of one anchor precision.
fn anchor_wire(precision: AnchorPrecision) -> &'static str {
    match precision {
        AnchorPrecision::Source => "source",
        AnchorPrecision::Document => "document",
        AnchorPrecision::Page => "page",
        AnchorPrecision::Section => "section",
        AnchorPrecision::Paragraph => "paragraph",
        AnchorPrecision::Line => "line",
        AnchorPrecision::ByteRange => "byte_range",
    }
}

/// Stable wire spelling of one privacy class.
fn disclosure_wire(class: DisclosureClass) -> &'static str {
    match class {
        DisclosureClass::Private => "private",
        DisclosureClass::ProjectBound => "project_bound",
        DisclosureClass::ExportableRedacted => "exportable_redacted",
        DisclosureClass::Public => "public",
    }
}

/// Disclosure breadth, narrowest first.
///
/// The wire vocabulary has no ordering, and a source may never widen the
/// privacy boundary of the inquiry that admits it, so the comparison needs an
/// explicit breadth. `Private` is the narrowest class and `Public` the widest.
const fn disclosure_rank(class: DisclosureClass) -> u8 {
    match class {
        DisclosureClass::Private => 0,
        DisclosureClass::ProjectBound => 1,
        DisclosureClass::ExportableRedacted => 2,
        DisclosureClass::Public => 3,
    }
}
