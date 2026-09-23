//! Bounded inactive-candidate backlog with cross-task leakage refusal (#1869).
//!
//! Production enforcement for the I12.24 backlog contract
//! (`docs/architecture/I12-24-meta-learning-and-improvement-delivery.md`):
//!
//! - Active candidates are bounded per target surface and value. The bound
//!   policy is owned by the existing Governor decision authority (carried as
//!   a `governor_authority_ref`); this module creates no scheduler, task
//!   graph, journal, or memory owner.
//! - Duplicate candidates merge by canonical evidence lineage, preserving
//!   merged provenance (`merged_from`, unioned evidence/source refs).
//! - Stale, ownerless, or low-value candidates leave the active set only
//!   through an explicit [`ArchivedCandidate`] transition with a summary;
//!   they are never silently dropped or silently retained.
//! - Retrieval refuses expired local overlays and unclosed reusable
//!   candidates. Before closure, only the exact non-expired `LOCAL_ADMITTED`
//!   overlay of the active campaign may influence a compatible attempt.
//!   Draft deltas, unclosed reusable candidates, expired overlays, and
//!   ownerless records are ineligible for retrieval, delivery, compilation,
//!   or use by another task.
//! - Cross-task carryover requires a distinct, newly governed
//!   [`CrossTaskAdmission`] revalidating scope, authority, retention,
//!   evaluator, and rollback.
//!
//! All records here are advisory/candidate evidence. Nothing in this module
//! performs promotion, activation, publication, mutation, or task Finish;
//! Governor admission is referenced, never minted.

use blake3::Hasher;
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_governor::VerifiedLearningAdmission;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use time::OffsetDateTime;

use crate::learning_closure::{
    AdmissionState, AttemptOutcomesAndDeltas, CampaignAndTarget, ClosureAssembly, ClosurePolicy,
    LearningClosureError, OutcomeHarmAndEconomicsEvidence, OverlayAndActivationAssessments,
    PriorClosureHistory, assemble_campaign_learning_closure,
};
use crate::{CandidateState, ImprovementCandidate, ImprovementSurface};

/// Per-surface active-backlog bound, owned by the Governor decision authority.
///
/// `governor_authority_ref` names the existing Governor policy/admission that
/// owns this bound (e.g. a maintenance-admission policy revision). This crate
/// never mints Governor authority; it only binds to it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CandidateBoundPolicy {
    pub target_surface: ImprovementSurface,
    pub max_active: usize,
    pub min_value: f64,
    pub governor_authority_ref: String,
    pub policy_revision: u64,
}

impl CandidateBoundPolicy {
    pub fn validate(&self) -> Result<(), BoundsError> {
        if self.max_active == 0 {
            return Err(BoundsError::InvalidPolicy("max_active must be non-zero"));
        }
        if self.min_value < 0.0 || !self.min_value.is_finite() {
            return Err(BoundsError::InvalidPolicy(
                "min_value must be a finite non-negative value",
            ));
        }
        if self.governor_authority_ref.trim().is_empty() {
            return Err(BoundsError::InvalidPolicy(
                "governor_authority_ref must name the owning Governor decision",
            ));
        }
        Ok(())
    }

    /// Governor-bound validation: the shape check plus confirmation that the
    /// owning authority equals the authority bound in an owner-verified
    /// permit. A well-formed but unissued authority string is refused.
    pub fn validate_governed(
        &self,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<(), BoundsError> {
        self.validate()?;
        if self.governor_authority_ref.trim() != verified.permit().authority_ref() {
            return Err(BoundsError::GovernorAuthorityUnconfirmed);
        }
        Ok(())
    }
}

/// Canonical (sorted, deduplicated) evidence lineage of a candidate.
pub fn canonical_evidence_lineage(evidence_refs: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for item in evidence_refs {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            set.insert(trimmed.to_string());
        }
    }
    set.into_iter().collect()
}

/// Stable digest of a canonical evidence lineage, for dedup comparison.
pub fn evidence_lineage_digest(canonical_lineage: &[String]) -> String {
    let mut hasher = Hasher::new();
    for item in canonical_lineage {
        hasher.update(item.as_bytes());
        hasher.update(b"\0");
    }
    hasher.finalize().to_hex().to_string()
}

/// One tracked backlog entry: the advisory candidate plus backlog metadata.
///
/// `value` is the owner-assessed expected value used for bound ordering;
/// `owner` is the owning decision authority (None = ownerless).
/// `admitted_under_authority` records the Governor authority the entry was
/// admitted under via [`BoundedBacklog::admit_governed`] (`None` for
/// registry-only [`BoundedBacklog::admit`); the producer requires it to
/// match the verified permit, so production binds retained owner identity
/// rather than caller labels.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrackedCandidate {
    pub candidate: ImprovementCandidate,
    pub value: f64,
    pub owner: Option<String>,
    pub lineage_digest: String,
    pub merged_from: Vec<String>,
    pub admitted_under_authority: Option<String>,
}

/// Outcome of [`BoundedBacklog::admit`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmitOutcome {
    /// Stored as a new active candidate.
    Admitted { candidate_id: String },
    /// Merged into an existing active candidate by evidence lineage.
    Merged {
        surviving_candidate_id: String,
        absorbed_candidate_id: String,
    },
}

/// Explicit archive record: the only way out of the active set for
/// stale/ownerless/low-value candidates. Carries the summary so the
/// archival is reviewable, never silent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedCandidate {
    pub candidate_id: String,
    pub target_surface: ImprovementSurface,
    pub cause: ArchiveCause,
    pub summary: String,
    pub merged_from: Vec<String>,
    pub evidence_lineage: Vec<String>,
    pub archived_revision: u64,
}

/// The reviewable reason a candidate was archived.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveCause {
    Stale,
    Ownerless,
    LowValue,
}

/// Reachable bounded backlog: the production candidate/overlay admission path.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BoundedBacklog {
    policies: Vec<CandidateBoundPolicy>,
    entries: Vec<TrackedCandidate>,
}

impl BoundedBacklog {
    pub fn new(policies: Vec<CandidateBoundPolicy>) -> Result<Self, BoundsError> {
        for policy in &policies {
            policy.validate()?;
        }
        Ok(Self {
            policies,
            entries: Vec::new(),
        })
    }

    pub fn policy_for(
        &self,
        surface: ImprovementSurface,
    ) -> Result<&CandidateBoundPolicy, BoundsError> {
        self.policies
            .iter()
            .find(|policy| policy.target_surface == surface)
            .ok_or(BoundsError::NoPolicyForSurface)
    }

    /// Active (non-terminal) entries for one surface.
    pub fn active_for(&self, surface: ImprovementSurface) -> Vec<&TrackedCandidate> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.candidate.target_surface == surface && entry.candidate.state.is_experimental()
            })
            .collect()
    }

    /// Active backlog entry for one candidate id, if currently active.
    pub fn entry_for(&self, candidate_id: &str) -> Option<&TrackedCandidate> {
        self.entries.iter().find(|entry| {
            entry.candidate.candidate_id == candidate_id && entry.candidate.state.is_experimental()
        })
    }

    /// Admit a candidate: dedup-merge on overlapping canonical evidence
    /// lineage, otherwise enforce the surface value floor and active bound.
    ///
    /// A full bound refuses admission (`BoundExceeded`); the caller must run
    /// an explicit [`BoundedBacklog::archive`] first. No silent eviction.
    ///
    /// Registry primitive: the governed consumer path uses
    /// [`BoundedBacklog::admit_governed`], which additionally confirms the
    /// owning Governor authority against live owner evidence.
    pub fn admit(
        &mut self,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
    ) -> Result<AdmitOutcome, BoundsError> {
        let policy = self.policy_for(candidate.target_surface)?.clone();
        self.admit_inner(&policy, candidate, value, owner, None)
    }

    /// Governor-bound admission: as [`BoundedBacklog::admit`], but the
    /// surface policy's owning authority must equal the authority bound in
    /// an owner-verified permit. Forged authority strings are refused. The
    /// verified authority is retained on the entry for production binding.
    pub fn admit_governed(
        &mut self,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<AdmitOutcome, BoundsError> {
        let policy = self.policy_for(candidate.target_surface)?.clone();
        policy.validate_governed(verified)?;
        let authority = verified.permit().authority_ref().to_string();
        self.admit_inner(&policy, candidate, value, owner, Some(&authority))
    }

    fn admit_inner(
        &mut self,
        policy: &CandidateBoundPolicy,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        governed_authority: Option<&str>,
    ) -> Result<AdmitOutcome, BoundsError> {
        candidate.validate().map_err(BoundsError::Candidate)?;
        if !value.is_finite() || value < 0.0 {
            return Err(BoundsError::InvalidValue);
        }
        let lineage = canonical_evidence_lineage(&candidate.evidence_refs);
        if lineage.is_empty() {
            return Err(BoundsError::EmptyEvidenceLineage);
        }
        let digest = evidence_lineage_digest(&lineage);

        // Dedup: same surface with overlapping canonical lineage merges.
        let mut merge_target: Option<usize> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.candidate.target_surface != candidate.target_surface
                || !entry.candidate.state.is_experimental()
            {
                continue;
            }
            let existing_set: BTreeSet<String> =
                canonical_evidence_lineage(&entry.candidate.evidence_refs)
                    .into_iter()
                    .collect();
            let overlap = lineage.iter().any(|item| existing_set.contains(item));
            // Same lineage digest is the exact-duplicate fast path; any
            // overlap merges per the contract.
            if overlap || entry.lineage_digest == digest {
                merge_target = Some(index);
                break;
            }
        }
        if let Some(index) = merge_target {
            let surviving_id = self.entries[index].candidate.candidate_id.clone();
            let absorbed_id = candidate.candidate_id.clone();
            self.merge_into(index, &candidate, value, owner, governed_authority)?;
            return Ok(AdmitOutcome::Merged {
                surviving_candidate_id: surviving_id,
                absorbed_candidate_id: absorbed_id,
            });
        }

        if value < policy.min_value {
            return Err(BoundsError::BelowValueFloor {
                value,
                floor: policy.min_value,
            });
        }
        let active = self.active_for(candidate.target_surface).len();
        if active >= policy.max_active {
            return Err(BoundsError::BoundExceeded {
                surface: candidate.target_surface,
                max_active: policy.max_active,
            });
        }
        let candidate_id = candidate.candidate_id.clone();
        self.entries.push(TrackedCandidate {
            candidate,
            value,
            owner: owner
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty()),
            lineage_digest: digest,
            merged_from: Vec::new(),
            admitted_under_authority: governed_authority.map(str::to_string),
        });
        Ok(AdmitOutcome::Admitted { candidate_id })
    }

    /// Merge an absorbed candidate into the entry at `index`, preserving
    /// provenance: unioned evidence/source refs, recorded `merged_from`,
    /// best value/owner, retained governed authority, and a revision bump.
    fn merge_into(
        &mut self,
        index: usize,
        absorbed: &ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        governed_authority: Option<&str>,
    ) -> Result<(), BoundsError> {
        let entry = &mut self.entries[index];
        let mut evidence: BTreeSet<String> =
            entry.candidate.evidence_refs.iter().cloned().collect();
        evidence.extend(absorbed.evidence_refs.iter().cloned());
        entry.candidate.evidence_refs = evidence.into_iter().collect();
        let mut sources: BTreeSet<String> =
            entry.candidate.source_trace_refs.iter().cloned().collect();
        sources.extend(absorbed.source_trace_refs.iter().cloned());
        entry.candidate.source_trace_refs = sources.into_iter().collect();
        if !entry.merged_from.contains(&absorbed.candidate_id) {
            entry.merged_from.push(absorbed.candidate_id.clone());
        }
        if value > entry.value {
            entry.value = value;
        }
        if entry.owner.is_none() {
            entry.owner = owner
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty());
        }
        if entry.admitted_under_authority.is_none() {
            entry.admitted_under_authority = governed_authority.map(str::to_string);
        }
        entry.candidate.revision += 1;
        entry.candidate.updated_at = OffsetDateTime::now_utc();
        entry.lineage_digest =
            evidence_lineage_digest(&canonical_evidence_lineage(&entry.candidate.evidence_refs));
        entry.candidate.validate().map_err(BoundsError::Candidate)?;
        Ok(())
    }

    /// Explicitly summarize and archive a stale, ownerless, or low-value
    /// active candidate. Drives the advisory lifecycle to `Retired` through
    /// the legal transitions and returns the reviewable archive record.
    pub fn archive(
        &mut self,
        candidate_id: &str,
        cause: ArchiveCause,
        summary: String,
    ) -> Result<ArchivedCandidate, BoundsError> {
        if summary.trim().is_empty() {
            return Err(BoundsError::MissingSummary);
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.candidate.candidate_id == candidate_id)
            .ok_or(BoundsError::UnknownCandidate)?;
        {
            let entry = &self.entries[index];
            if !entry.candidate.state.is_experimental()
                && entry.candidate.state != CandidateState::Rejected
            {
                return Err(BoundsError::NotActive);
            }
            match cause {
                ArchiveCause::Ownerless if entry.owner.is_some() => {
                    return Err(BoundsError::ArchiveCauseMismatch);
                }
                ArchiveCause::LowValue => {
                    let floor = self.policy_for(entry.candidate.target_surface)?.min_value;
                    if entry.value >= floor {
                        return Err(BoundsError::ArchiveCauseMismatch);
                    }
                }
                ArchiveCause::Stale | ArchiveCause::Ownerless => {}
            }
        }
        let entry = &mut self.entries[index];
        retire_candidate(&mut entry.candidate).map_err(BoundsError::Candidate)?;
        Ok(ArchivedCandidate {
            candidate_id: entry.candidate.candidate_id.clone(),
            target_surface: entry.candidate.target_surface,
            cause,
            summary: summary.trim().to_string(),
            merged_from: entry.merged_from.clone(),
            evidence_lineage: canonical_evidence_lineage(&entry.candidate.evidence_refs),
            archived_revision: entry.candidate.revision,
        })
    }
}

/// Drive an advisory candidate to `Retired` through legal transitions.
fn retire_candidate(candidate: &mut ImprovementCandidate) -> Result<(), crate::ImprovementError> {
    match candidate.state {
        CandidateState::Candidate | CandidateState::ReplayPending => {
            let rev = candidate.revision;
            candidate.transition(rev, CandidateState::Rejected)?;
            let rev = candidate.revision;
            candidate.transition(rev, CandidateState::Retired)?;
        }
        CandidateState::Evaluating => {
            let rev = candidate.revision;
            candidate.transition(rev, CandidateState::Retired)?;
        }
        CandidateState::Rejected => {
            let rev = candidate.revision;
            candidate.transition(rev, CandidateState::Retired)?;
        }
        CandidateState::Retired => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Overlay / retrieval / cross-task admission.
// ---------------------------------------------------------------------------

/// Governed lifecycle of a task-local harness overlay.
///
/// Only `LocalAdmitted` (the contract's `LOCAL_ADMITTED`) can ever
/// influence an attempt, and only when non-expired and campaign-bound.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayState {
    Proposed,
    LocalAdmitted,
    Expired,
    RolledBack,
    Invalidated,
}

/// Task-local behavioral overlay presented for retrieval.
///
/// The bound [`StateFence`] is canonical owner vocabulary (no string
/// facade): retrieval requires it to exactly match the fence in the
/// owner-verified permit, so fence drift refuses before values surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedOverlay {
    pub overlay_id: String,
    pub campaign_id: String,
    pub task_id: String,
    pub fence: StateFence,
    pub compatible_recipe_ref: String,
    pub state: OverlayState,
    /// Governor admission receipt for the local effect (required).
    pub admission_ref: Option<String>,
    /// Expiry of the local admission; influence ends here, never lingers.
    pub expires_at: Option<OffsetDateTime>,
}

impl GovernedOverlay {
    pub fn validate(&self) -> Result<(), BoundsError> {
        for (field, value) in [
            ("overlay_id", &self.overlay_id),
            ("campaign_id", &self.campaign_id),
            ("task_id", &self.task_id),
            ("compatible_recipe_ref", &self.compatible_recipe_ref),
        ] {
            if value.trim().is_empty() {
                return Err(BoundsError::MissingField(field));
            }
        }
        self.fence
            .validate()
            .map_err(|_| BoundsError::InvalidFence)?;
        Ok(())
    }

    /// True only for the exact non-expired `LOCAL_ADMITTED` overlay.
    pub fn is_live_local_admitted(&self, now: OffsetDateTime) -> bool {
        if self.state != OverlayState::LocalAdmitted {
            return false;
        }
        if self
            .admission_ref
            .as_ref()
            .is_none_or(|r| r.trim().is_empty())
        {
            return false;
        }
        match self.expires_at {
            Some(expires) => now < expires,
            None => false,
        }
    }

    /// Unix-seconds form of [`GovernedOverlay::is_live_local_admitted`] for
    /// screens whose clock is a `u64`. Fail-closed: out-of-range stamps
    /// report not-live.
    pub fn is_live_local_admitted_at_unix(&self, now_unix_secs: u64) -> bool {
        let stamp = i64::try_from(now_unix_secs)
            .ok()
            .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok());
        stamp.is_some_and(|now| self.is_live_local_admitted(now))
    }
}

/// Reference to a reusable candidate offered for retrieval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReusableCandidateRef {
    pub candidate_id: String,
    /// Closure disposition that closed this candidate (None = unclosed).
    pub closure_ref: Option<String>,
    /// Owning decision authority (None = ownerless, ineligible).
    pub owner: Option<String>,
    pub origin_campaign_id: String,
}

impl ReusableCandidateRef {
    pub fn validate(&self) -> Result<(), BoundsError> {
        if self.candidate_id.trim().is_empty() {
            return Err(BoundsError::MissingField("candidate_id"));
        }
        if self.origin_campaign_id.trim().is_empty() {
            return Err(BoundsError::MissingField("origin_campaign_id"));
        }
        Ok(())
    }
}

/// Distinct, newly governed admission permitting cross-task carryover.
///
/// Revalidates scope, authority, retention, evaluator, and rollback for the
/// target task. Authentication comes from the owner-verified permit: every
/// ref below must equal the corresponding permit-bound value, so the
/// revalidation record cannot be assembled from bare strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossTaskAdmission {
    pub admission_id: String,
    pub source_campaign_id: String,
    pub target_task_id: String,
    pub scope_ref: String,
    pub authority_ref: String,
    pub retention_ref: String,
    pub evaluator_ref: String,
    pub rollback_ref: String,
}

impl CrossTaskAdmission {
    pub fn validate(&self) -> Result<(), BoundsError> {
        for (field, value) in [
            ("admission_id", &self.admission_id),
            ("source_campaign_id", &self.source_campaign_id),
            ("target_task_id", &self.target_task_id),
            ("scope_ref", &self.scope_ref),
            ("authority_ref", &self.authority_ref),
            ("retention_ref", &self.retention_ref),
            ("evaluator_ref", &self.evaluator_ref),
            ("rollback_ref", &self.rollback_ref),
        ] {
            if value.trim().is_empty() {
                return Err(BoundsError::MissingField(field));
            }
        }
        Ok(())
    }

    /// Owner-bound check: the revalidation record must match the verified
    /// permit field-for-field. Bare-string records never pass on their own.
    pub fn matches_permit(&self, verified: &VerifiedLearningAdmission<'_>) -> bool {
        let permit = verified.permit();
        self.source_campaign_id == permit.source_campaign_id()
            && self.target_task_id == permit.target_task_id()
            && self.scope_ref == permit.scope_ref()
            && self.authority_ref == permit.authority_ref()
            && self.retention_ref == permit.retention_ref()
            && self.evaluator_ref == permit.evaluator_ref()
            && self.rollback_ref == permit.rollback_ref()
    }
}

/// Retrieval outcome: what the attempt may be compiled from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalDecision {
    pub overlay_id: String,
    pub reusable_candidate_id: Option<String>,
    pub cross_task: bool,
    pub cross_task_admission_id: Option<String>,
}

/// Retrieval refusal or admission error. Every refusal is fail-closed.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum BoundsError {
    #[error("no bound policy for this target surface")]
    NoPolicyForSurface,
    #[error("bound policy invalid: {0}")]
    InvalidPolicy(&'static str),
    #[error("candidate value must be finite and non-negative")]
    InvalidValue,
    #[error("candidate evidence lineage is empty")]
    EmptyEvidenceLineage,
    #[error("active bound exceeded for surface {surface:?}: max {max_active}")]
    BoundExceeded {
        surface: ImprovementSurface,
        max_active: usize,
    },
    #[error("candidate value {value} below surface floor {floor}")]
    BelowValueFloor { value: f64, floor: f64 },
    #[error("unknown candidate")]
    UnknownCandidate,
    #[error("candidate is not active")]
    NotActive,
    #[error("archive summary is required")]
    MissingSummary,
    #[error("archive cause does not match candidate state")]
    ArchiveCauseMismatch,
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("overlay is not an admitted local overlay")]
    OverlayNotAdmitted,
    #[error("local overlay admission has expired")]
    ExpiredOverlay,
    #[error("draft deltas are ineligible for retrieval")]
    DraftDeltaIneligible,
    #[error("unclosed reusable candidate is ineligible for retrieval")]
    UnclosedReusable,
    #[error("ownerless learning record is ineligible for retrieval")]
    OwnerlessRecord,
    #[error("cross-task use requires a distinct governed admission")]
    CrossTaskAdmissionMissing,
    #[error("cross-task admission does not cover this carryover")]
    CrossTaskAdmissionMismatch,
    #[error("campaign identity mismatch without cross-task admission")]
    CrossCampaignLeakage,
    #[error("overlay fence is invalid")]
    InvalidFence,
    #[error("overlay fence does not exactly match the admitted fence")]
    StaleStateFence,
    #[error("Governor authority does not match the owner-verified permit")]
    GovernorAuthorityUnconfirmed,
    #[error("reusable candidate is not an active backlog entry")]
    NotBacklogAdmitted,
    #[error("presented admitted overlay has no live backing overlay")]
    OverlayBackingMismatch,
    #[error("presented reusable candidate is not bound by the verified permit")]
    ReusableBackingMismatch,
    #[error("learning production identity invalid: {0}")]
    InvalidProduction(&'static str),
    #[error("retrieval campaign does not match the closure campaign")]
    ClosureCampaignMismatch,
    #[error("candidate error: {0}")]
    Candidate(#[from] crate::ImprovementError),
}

/// Retrieval gate for a compatible attempt.
///
/// UNGOVERNED LEGACY: this function checks caller-presented overlays,
/// reusables, and cross-task records as bare data — nothing here is bound
/// to a live Governor issuance. Authority decisions MUST use
/// [`retrieve_governed`] with an owner-verified permit instead. This
/// function remains only for registry-level pre-screening and migration;
/// removal is out of scope for this work unit.
///
/// Enforces, in order: overlay liveness (exact non-expired
/// `LOCAL_ADMITTED`), draft-delta ineligibility, reusable closure/owner
/// eligibility, campaign identity, and cross-task admission.
pub fn retrieve_for_attempt(
    requesting_campaign_id: &str,
    requesting_task_id: &str,
    overlay: &GovernedOverlay,
    reusable: Option<&ReusableCandidateRef>,
    draft_delta_present: bool,
    cross_task_admission: Option<&CrossTaskAdmission>,
    now: OffsetDateTime,
) -> Result<RetrievalDecision, BoundsError> {
    if requesting_campaign_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_campaign_id"));
    }
    if requesting_task_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_task_id"));
    }
    overlay.validate()?;
    if draft_delta_present {
        return Err(BoundsError::DraftDeltaIneligible);
    }
    if overlay.state == OverlayState::Expired
        || matches!(overlay.expires_at, Some(expires) if now >= expires)
    {
        return Err(BoundsError::ExpiredOverlay);
    }
    if !overlay.is_live_local_admitted(now) {
        return Err(BoundsError::OverlayNotAdmitted);
    }

    let mut reusable_candidate_id: Option<String> = None;
    let mut reusable_origin: Option<&str> = None;
    if let Some(candidate) = reusable {
        candidate.validate()?;
        if candidate
            .closure_ref
            .as_ref()
            .is_none_or(|r| r.trim().is_empty())
        {
            return Err(BoundsError::UnclosedReusable);
        }
        if candidate.owner.as_ref().is_none_or(|o| o.trim().is_empty()) {
            return Err(BoundsError::OwnerlessRecord);
        }
        reusable_candidate_id = Some(candidate.candidate_id.clone());
        reusable_origin = Some(candidate.origin_campaign_id.as_str());
    }

    let overlay_foreign = overlay.campaign_id != requesting_campaign_id;
    let reusable_foreign = reusable_origin
        .map(|origin| origin != requesting_campaign_id)
        .unwrap_or(false);
    if overlay_foreign || reusable_foreign {
        let admission = cross_task_admission.ok_or(BoundsError::CrossTaskAdmissionMissing)?;
        admission.validate()?;
        let expected_source = if overlay_foreign {
            overlay.campaign_id.as_str()
        } else {
            reusable_origin.unwrap_or("")
        };
        if admission.source_campaign_id != expected_source
            || admission.target_task_id != requesting_task_id
        {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if reusable_foreign && reusable_origin.is_some_and(|o| o != admission.source_campaign_id) {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if overlay_foreign && overlay.campaign_id != admission.source_campaign_id {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        return Ok(RetrievalDecision {
            overlay_id: overlay.overlay_id.clone(),
            reusable_candidate_id,
            cross_task: true,
            cross_task_admission_id: Some(admission.admission_id.clone()),
        });
    }

    // Same campaign: reusable records must still be closed and owned
    // (checked above); no cross-task admission is needed or accepted.
    if cross_task_admission.is_some() {
        return Err(BoundsError::CrossTaskAdmissionMismatch);
    }
    Ok(RetrievalDecision {
        overlay_id: overlay.overlay_id.clone(),
        reusable_candidate_id,
        cross_task: false,
        cross_task_admission_id: None,
    })
}

// ---------------------------------------------------------------------------
// Owner-verified governed consumer path (round 3).
//
// The round-2 caller-owned evidence sets are removed: every authority and
// admission relied upon below arrives as an owner-verified permit
// (`VerifiedLearningAdmission`, constructible only by the Governor owner).
// Bare strings never authenticate here.
// ---------------------------------------------------------------------------

/// Governed retrieval request: the consumer-facing gate input.
///
/// `verified` carries the owner-issued permit the retrieval is bound to:
/// overlay identity + fence and reusable identity must match it exactly,
/// and cross-task revalidation records must equal its bound refs. A
/// reusable candidate must additionally resolve to an active backlog
/// entry — `admit`/`admit_governed` grants retrieval eligibility and
/// `archive` revokes it. The backlog registry handle is non-optional on
/// this governed path: pass the production [`BoundedBacklog`] even for
/// overlay-only retrieval.
///
/// `now` MUST be owner/host-sourced live time, never a requester value.
pub struct GovernedRetrieval<'a> {
    pub requesting_campaign_id: &'a str,
    pub requesting_task_id: &'a str,
    pub overlay: &'a GovernedOverlay,
    pub reusable: Option<&'a ReusableCandidateRef>,
    pub draft_delta_present: bool,
    pub cross_task_admission: Option<&'a CrossTaskAdmission>,
    pub backlog: &'a BoundedBacklog,
    pub verified: &'a VerifiedLearningAdmission<'a>,
    pub now: OffsetDateTime,
}

/// Owner-verified retrieval gate: as [`retrieve_for_attempt`], but every
/// authority/admission relied upon must arrive inside `verified` (an
/// owner-verified permit), the overlay fence must exactly match the admitted
/// fence, and (when a backlog is presented) reusable candidates must be
/// active backlog entries.
pub fn retrieve_governed(request: GovernedRetrieval<'_>) -> Result<RetrievalDecision, BoundsError> {
    let now = request.now;
    let permit = request.verified.permit();
    if request.requesting_campaign_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_campaign_id"));
    }
    if request.requesting_task_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_task_id"));
    }
    request.overlay.validate()?;
    if request.draft_delta_present {
        return Err(BoundsError::DraftDeltaIneligible);
    }
    if request.overlay.state == OverlayState::Expired
        || matches!(request.overlay.expires_at, Some(expires) if now >= expires)
    {
        return Err(BoundsError::ExpiredOverlay);
    }
    if !request.overlay.is_live_local_admitted(now) {
        return Err(BoundsError::OverlayNotAdmitted);
    }
    // Owner-bound overlay identity + fence: the presented overlay must be
    // the exact overlay the permit was issued for, under the exact fence.
    if Some(request.overlay.overlay_id.as_str()) != permit.overlay_id()
        || !fences_match_exact(&request.overlay.fence, permit.fence())
    {
        if Some(request.overlay.overlay_id.as_str()) != permit.overlay_id() {
            return Err(BoundsError::OverlayBackingMismatch);
        }
        return Err(BoundsError::StaleStateFence);
    }

    let mut reusable_candidate_id: Option<String> = None;
    let mut reusable_origin: Option<&str> = None;
    if let Some(candidate) = request.reusable {
        candidate.validate()?;
        if candidate
            .closure_ref
            .as_ref()
            .is_none_or(|r| r.trim().is_empty())
        {
            return Err(BoundsError::UnclosedReusable);
        }
        if candidate.owner.as_ref().is_none_or(|o| o.trim().is_empty()) {
            return Err(BoundsError::OwnerlessRecord);
        }
        if Some(candidate.candidate_id.as_str()) != permit.candidate_id() {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if request.backlog.entry_for(&candidate.candidate_id).is_none() {
            return Err(BoundsError::NotBacklogAdmitted);
        }
        reusable_candidate_id = Some(candidate.candidate_id.clone());
        reusable_origin = Some(candidate.origin_campaign_id.as_str());
    } else if permit.candidate_id().is_some() {
        // A permit binding a reusable candidate requires that candidate to
        // be presented: influence without the bound subject is refused.
        return Err(BoundsError::CrossTaskAdmissionMismatch);
    }

    // Campaign/task binding comes from the verified permit, never from
    // requester strings alone.
    let source = permit.source_campaign_id();
    let target = permit.target_task_id();
    if request.overlay.campaign_id != source {
        return Err(BoundsError::CrossCampaignLeakage);
    }
    if let Some(origin) = reusable_origin
        && origin != source
    {
        return Err(BoundsError::CrossCampaignLeakage);
    }
    let local = request.requesting_campaign_id == source && request.requesting_task_id == target;
    if !local {
        let admission = request
            .cross_task_admission
            .ok_or(BoundsError::CrossTaskAdmissionMissing)?;
        admission.validate()?;
        if !admission.matches_permit(request.verified) {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if request.requesting_task_id != target {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        return Ok(RetrievalDecision {
            overlay_id: request.overlay.overlay_id.clone(),
            reusable_candidate_id,
            cross_task: true,
            cross_task_admission_id: Some(admission.admission_id.clone()),
        });
    }

    if request.cross_task_admission.is_some() {
        return Err(BoundsError::CrossTaskAdmissionMismatch);
    }
    Ok(RetrievalDecision {
        overlay_id: request.overlay.overlay_id.clone(),
        reusable_candidate_id,
        cross_task: false,
        cross_task_admission_id: None,
    })
}

/// Error from the governed closure consumer path.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum GovernedClosureError {
    #[error("bounds gate refused closure inputs: {0}")]
    Bounds(#[from] BoundsError),
    #[error("closure assembly failed: {0}")]
    Closure(#[from] LearningClosureError),
}

/// Governed entry to the existing closure consumer
/// ([`assemble_campaign_learning_closure`]).
///
/// Runs the #1869 retrieval gate BEFORE assembly: the closure campaign must
/// match the requesting campaign, the closure policy's owner ids must equal
/// the owner-verified permit's bound authority/rollback refs, and every
/// presented `Admitted` overlay record must be backed by the exact live
/// `LOCAL_ADMITTED` overlay in the gate. Expired overlays, fence drift,
/// unclosed/ownerless/unadmitted reusables, draft deltas, and ungoverned
/// cross-task use return [`GovernedClosureError::Bounds`] — they never reach
/// assembly, so they can never surface as a candidate or a silent
/// disposition fill.
#[allow(clippy::too_many_arguments)]
pub fn governed_assemble_campaign_learning_closure(
    exact_campaign_and_target: CampaignAndTarget,
    exact_attempt_outcomes_and_deltas: AttemptOutcomesAndDeltas,
    exact_overlay_and_activation_assessments: OverlayAndActivationAssessments,
    exact_outcome_harm_and_economics_evidence: OutcomeHarmAndEconomicsEvidence,
    prior_closure_history: PriorClosureHistory,
    closure_policy: ClosurePolicy,
    gate: GovernedRetrieval<'_>,
) -> Result<ClosureAssembly, GovernedClosureError> {
    if gate.requesting_campaign_id != exact_campaign_and_target.campaign_id {
        return Err(GovernedClosureError::Bounds(
            BoundsError::ClosureCampaignMismatch,
        ));
    }
    let permit = gate.verified.permit();
    if closure_policy.external_owner_id != permit.authority_ref()
        || closure_policy.rollback_owner_id != permit.rollback_ref()
    {
        return Err(GovernedClosureError::Bounds(
            BoundsError::GovernorAuthorityUnconfirmed,
        ));
    }
    for record in &exact_overlay_and_activation_assessments.overlays {
        if record.admission == AdmissionState::Admitted
            && record.overlay_id != gate.overlay.overlay_id
        {
            return Err(GovernedClosureError::Bounds(
                BoundsError::OverlayBackingMismatch,
            ));
        }
    }
    retrieve_governed(gate)?;
    Ok(assemble_campaign_learning_closure(
        exact_campaign_and_target,
        exact_attempt_outcomes_and_deltas,
        exact_overlay_and_activation_assessments,
        exact_outcome_harm_and_economics_evidence,
        prior_closure_history,
        closure_policy,
    )?)
}
