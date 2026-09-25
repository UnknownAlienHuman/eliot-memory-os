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
//!   they are never silently dropped or silently retained. The governed
//!   production entry [`BoundedBacklog::admit_reporting_pressure`] drives
//!   that transition through [`BoundedBacklog::archive`] itself when the
//!   surface bound is already full, and returns the [`ArchivedCandidate`]
//!   receipts, so the bound-failure path is wired and auditable instead of
//!   an unwired obligation on every caller.
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
//! Overlay and reusable-candidate material is **owner-retained**, not
//! caller-presented: [`BoundedBacklog::bind_local_overlay`] and
//! [`BoundedBacklog::bind_reusable_candidate`] bind it once under an
//! owner-verified permit, and [`BoundedBacklog::live_local_overlay`] /
//! [`BoundedBacklog::active_reusable`] hand the bound material back for
//! retrieval. Campaign identity, task identity, State Fence, admission
//! receipt, expiry and ownership therefore come from a Governor issuance,
//! never from a request string.
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
    AdmissionState, AttemptOutcomesAndDeltas, CampaignAndTarget, ClosureAssembly,
    ClosureDisposition, ClosureDue, ClosureLifecycleEvent, ClosurePolicy, LearningClosureError,
    OutcomeHarmAndEconomicsEvidence, OverlayAndActivationAssessments, PriorClosureHistory,
    assemble_campaign_learning_closure, trigger_closure_due,
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

/// Owner-retained binding record for one task-local overlay.
///
/// Retention is the point. Retrieval reads this record through
/// [`BoundedBacklog::live_local_overlay`] instead of a caller-presented
/// [`GovernedOverlay`], so campaign id, task id, State Fence, admission
/// receipt and expiry are fixed once by a Governor issuance and cannot be
/// re-spelled by a requester (I12.24:218 "An overlay is not canonical
/// doctrine and is not visible to unrelated tasks").
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoundLocalOverlay {
    pub overlay: GovernedOverlay,
    /// Digest of the owner-issued admission permit that authorized binding.
    /// A rotated or re-issued permit no longer matches, so the binding is
    /// refused rather than silently reused.
    pub admission_digest: String,
    /// Governor authority the binding was made under.
    pub authority_ref: String,
}

/// Owner-retained binding record for one reusable candidate's closure and
/// ownership material.
///
/// `reusable.closure_ref` and `reusable.owner` are always present in a bound
/// record: an unclosed or ownerless candidate is never bound, and the owner
/// is copied from the retained backlog entry rather than from the request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoundReusableCandidate {
    pub reusable: ReusableCandidateRef,
    pub admission_digest: String,
    pub authority_ref: String,
}

/// Result of a governed admission that reports the lifecycle transitions it
/// had to perform to respect the surface bound.
///
/// `archived` is the reviewable archive history produced by the bound-failure
/// path, in the order it was applied. It is returned, never logged away, so
/// the owning lane can persist it (I12.24:293 requires the evidence to be
/// durable, not silently process-local).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmitReport {
    pub outcome: AdmitOutcome,
    /// Explicit archive receipts produced while relieving the surface bound.
    /// Empty when the bound was not under pressure.
    pub archived: Vec<ArchivedCandidate>,
}

/// Failure of [`BoundedBacklog::admit_reporting_pressure`].
///
/// Carried as typed variants: no refusal is collapsed into display text.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum PressureAdmissionError {
    /// The candidate itself was refused. Nothing was archived, so there are
    /// no receipts to persist.
    #[error("bounded backlog refused the candidate: {0}")]
    Refused(#[source] BoundsError),
    /// Bound relief was already in progress when the transition failed. The
    /// receipts produced so far travel with the error so a partial lifecycle
    /// transition can never discard its own archive history.
    #[error("bound relief failed: {source}")]
    ReliefFailed {
        #[source]
        source: BoundsError,
        archived: Vec<ArchivedCandidate>,
    },
}

impl PressureAdmissionError {
    /// Split a refusal into the archive history it produced and the typed
    /// refusal that stopped it. Both halves are always explicit: a caller
    /// that ignores the returned receipts is discarding durable history, not
    /// observing an empty receipt list.
    pub fn into_parts(self) -> (Vec<ArchivedCandidate>, BoundsError) {
        match self {
            Self::Refused(error) => (Vec::new(), error),
            Self::ReliefFailed { source, archived } => (archived, source),
        }
    }
}

/// Pre-bound decision for one admission.
///
/// Derived from live registry state without mutating the backlog, so the
/// registry-only bound check and the governed pressure-reporting path share
/// exactly one decision rule and cannot drift.
enum PreBoundAdmission {
    /// The candidate deduplicates by evidence lineage into the entry at this
    /// index of the stable `entries` vector. No bound is consulted: a merge
    /// never grows the active set.
    Merge(usize),
    /// A new active entry, and the number of active slots that must be freed
    /// on this surface before it fits. `0` means the bound is not under
    /// pressure.
    Admit { deficit: usize },
    /// The candidate is below the surface value floor. The incoming candidate
    /// is what is being refused, so the active set is NOT under pressure and
    /// no existing entry is archived to make room for it.
    BelowFloor,
}

/// One assessed admission plus the lineage digest the commit reuses.
struct PreBoundDecision {
    admission: PreBoundAdmission,
    lineage_digest: String,
}

/// One archive target chosen by the bound-pressure selection rule.
struct ArchiveTarget {
    /// `0` for an ownerless entry, `1` for an owned one. Lower sorts first:
    /// an ownerless record has no decision owner to act on it and is already
    /// ineligible for retrieval, delivery and cross-task use (I12.24:295), so
    /// archiving it destroys no reachable influence.
    retention_rank: u8,
    /// IEEE-754 bit pattern of the finite, non-negative admitted value.
    /// Bit order is the value order for that domain and, unlike a float
    /// comparison, stays total for any value reconstructed from storage.
    value_order: u64,
    /// Stable `entries` index; the final, total tiebreak.
    index: usize,
    cause: ArchiveCause,
    candidate_id: String,
    summary: String,
}

/// Reachable bounded backlog: the production candidate/overlay admission path.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct BoundedBacklog {
    policies: Vec<CandidateBoundPolicy>,
    entries: Vec<TrackedCandidate>,
    /// Owner-retained overlay material. Empty by default: a backlog restored
    /// without its bindings refuses retrieval until the Governor owner binds
    /// them again, which is the fail-closed direction.
    #[serde(default)]
    bound_overlays: Vec<BoundLocalOverlay>,
    /// Owner-retained reusable-candidate material. Same fail-closed default
    /// as `bound_overlays`.
    #[serde(default)]
    bound_reusables: Vec<BoundReusableCandidate>,
}

impl BoundedBacklog {
    pub fn new(policies: Vec<CandidateBoundPolicy>) -> Result<Self, BoundsError> {
        for policy in &policies {
            policy.validate()?;
        }
        Ok(Self {
            policies,
            entries: Vec::new(),
            bound_overlays: Vec::new(),
            bound_reusables: Vec::new(),
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
    /// owning Governor authority against live owner evidence, or
    /// [`BoundedBacklog::admit_reporting_pressure`], which additionally
    /// performs and reports the summarized archive transition a full bound
    /// requires.
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

    /// Governor-bound admission that performs the summarized archive
    /// transition the I12.24 backlog contract requires when the surface
    /// bound is already full, and returns the resulting receipts.
    ///
    /// `admit`/`admit_governed` refuse a full bound and leave the caller to
    /// archive; that remains their exact behaviour. This entry is the
    /// production path that closes the loop: the transition is driven
    /// through the existing [`BoundedBacklog::archive`] method, so the legal
    /// `retire_candidate` chain and the [`ArchiveCause`] validation still
    /// govern, and the [`ArchivedCandidate`] receipts come back to the
    /// caller instead of disappearing inside this crate.
    ///
    /// What is and is not claimed:
    ///
    /// - Only causes justified by live state are used. An entry with no
    ///   owner is archived as [`ArchiveCause::Ownerless`]; an owned entry
    ///   below the surface floor is archived as [`ArchiveCause::LowValue`].
    ///   [`ArchiveCause::Stale`] is deliberately NOT claimed: no live
    ///   producer sets `ImprovementLifecycle::Stale` anywhere in this crate,
    ///   and this registry observes no time-based evidence that could
    ///   support the claim. Asserting staleness here would be inventing a
    ///   defect signature (issue #10). When no entry's state justifies a
    ///   cause, nothing is force-archived and the original bound refusal
    ///   surfaces.
    /// - A candidate refused by the value floor is not a bound-pressure
    ///   event. The incoming candidate is what is being refused, so no
    ///   existing entry is archived to make room for it and
    ///   [`BoundsError::BelowValueFloor`] surfaces unchanged.
    /// - Selection is deterministic and minimal: the stable `entries` index
    ///   order is the tiebreak, and only the admission deficit is freed.
    pub fn admit_reporting_pressure(
        &mut self,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<AdmitReport, PressureAdmissionError> {
        let policy = self
            .policy_for(candidate.target_surface)
            .cloned()
            .map_err(PressureAdmissionError::Refused)?;
        policy
            .validate_governed(verified)
            .map_err(PressureAdmissionError::Refused)?;
        let authority = verified.permit().authority_ref().to_string();
        let governed_authority = Some(authority.as_str());
        let decision = self
            .assess_admission(&policy, &candidate, value)
            .map_err(PressureAdmissionError::Refused)?;
        match decision.admission {
            PreBoundAdmission::Merge(index) => {
                let surviving_candidate_id = self.entries[index].candidate.candidate_id.clone();
                let absorbed_candidate_id = candidate.candidate_id.clone();
                self.merge_into(index, &candidate, value, owner, governed_authority)
                    .map_err(PressureAdmissionError::Refused)?;
                Ok(AdmitReport {
                    outcome: AdmitOutcome::Merged {
                        surviving_candidate_id,
                        absorbed_candidate_id,
                    },
                    archived: Vec::new(),
                })
            }
            PreBoundAdmission::BelowFloor => Err(PressureAdmissionError::Refused(
                BoundsError::BelowValueFloor {
                    value,
                    floor: policy.min_value,
                },
            )),
            PreBoundAdmission::Admit { deficit } => {
                let archived = if deficit > 0 {
                    self.relieve_bound(&policy, deficit)?
                } else {
                    Vec::new()
                };
                let candidate_id = candidate.candidate_id.clone();
                self.push_entry(
                    candidate,
                    value,
                    owner,
                    governed_authority,
                    decision.lineage_digest,
                );
                Ok(AdmitReport {
                    outcome: AdmitOutcome::Admitted { candidate_id },
                    archived,
                })
            }
        }
    }

    /// Assess an admission against live registry state without mutating the
    /// backlog. Shared by every admission entry so the value floor, the
    /// lineage dedup merge and the active bound have one implementation.
    fn assess_admission(
        &self,
        policy: &CandidateBoundPolicy,
        candidate: &ImprovementCandidate,
        value: f64,
    ) -> Result<PreBoundDecision, BoundsError> {
        candidate.validate().map_err(BoundsError::Candidate)?;
        if !value.is_finite() || value < 0.0 {
            return Err(BoundsError::InvalidValue);
        }
        let lineage = canonical_evidence_lineage(&candidate.evidence_refs);
        if lineage.is_empty() {
            return Err(BoundsError::EmptyEvidenceLineage);
        }
        let digest = evidence_lineage_digest(&lineage);
        if let Some(index) = self.merge_target(candidate, &lineage, &digest) {
            return Ok(PreBoundDecision {
                admission: PreBoundAdmission::Merge(index),
                lineage_digest: digest,
            });
        }
        // Floor before bound: an existing entry can only sit below the floor
        // if the surface policy floor moved under it, and the incoming
        // candidate is refused on its own merits before the backlog is asked
        // to make room for it.
        if value < policy.min_value {
            return Ok(PreBoundDecision {
                admission: PreBoundAdmission::BelowFloor,
                lineage_digest: digest,
            });
        }
        let active = self.active_for(candidate.target_surface).len();
        if active >= policy.max_active {
            // Bound is full. `deficit` is exactly the number of slots that
            // must be freed before the new entry fits, so the registry-only
            // path can refuse and the pressure path can free precisely that
            // many. A `max_active` of zero leaves the bound permanently
            // full, and relief then runs out of archivable entries and
            // surfaces the same refusal.
            return Ok(PreBoundDecision {
                admission: PreBoundAdmission::Admit {
                    deficit: active - policy.max_active + 1,
                },
                lineage_digest: digest,
            });
        }
        Ok(PreBoundDecision {
            admission: PreBoundAdmission::Admit { deficit: 0 },
            lineage_digest: digest,
        })
    }

    /// Index of the active entry this candidate merges into, if any.
    fn merge_target(
        &self,
        candidate: &ImprovementCandidate,
        lineage: &[String],
        digest: &str,
    ) -> Option<usize> {
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
                return Some(index);
            }
        }
        None
    }

    fn admit_inner(
        &mut self,
        policy: &CandidateBoundPolicy,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        governed_authority: Option<&str>,
    ) -> Result<AdmitOutcome, BoundsError> {
        let surface = candidate.target_surface;
        let decision = self.assess_admission(policy, &candidate, value)?;
        match decision.admission {
            PreBoundAdmission::Merge(index) => {
                let surviving_candidate_id = self.entries[index].candidate.candidate_id.clone();
                let absorbed_candidate_id = candidate.candidate_id.clone();
                self.merge_into(index, &candidate, value, owner, governed_authority)?;
                Ok(AdmitOutcome::Merged {
                    surviving_candidate_id,
                    absorbed_candidate_id,
                })
            }
            PreBoundAdmission::BelowFloor => Err(BoundsError::BelowValueFloor {
                value,
                floor: policy.min_value,
            }),
            PreBoundAdmission::Admit { deficit } => {
                if deficit > 0 {
                    return Err(BoundsError::BoundExceeded {
                        surface,
                        max_active: policy.max_active,
                    });
                }
                let candidate_id = candidate.candidate_id.clone();
                self.push_entry(
                    candidate,
                    value,
                    owner,
                    governed_authority,
                    decision.lineage_digest,
                );
                Ok(AdmitOutcome::Admitted { candidate_id })
            }
        }
    }

    /// Append a validated new active entry. Cannot fail: every refusal was
    /// already produced by [`Self::assess_admission`].
    fn push_entry(
        &mut self,
        candidate: ImprovementCandidate,
        value: f64,
        owner: Option<String>,
        governed_authority: Option<&str>,
        lineage_digest: String,
    ) {
        self.entries.push(TrackedCandidate {
            candidate,
            value,
            owner: owner
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty()),
            lineage_digest,
            merged_from: Vec::new(),
            admitted_under_authority: governed_authority.map(str::to_string),
        });
    }

    /// Free exactly `deficit` active slots on this policy's surface through
    /// the existing [`BoundedBacklog::archive`] transition.
    ///
    /// The archive call is not conditional: it always runs for every freed
    /// slot, and its typed [`BoundsError`] is propagated, never swallowed.
    /// When no remaining active entry's state justifies a cause, the original
    /// bound refusal surfaces with the receipts produced so far.
    fn relieve_bound(
        &mut self,
        policy: &CandidateBoundPolicy,
        deficit: usize,
    ) -> Result<Vec<ArchivedCandidate>, PressureAdmissionError> {
        let surface = policy.target_surface;
        let mut archived: Vec<ArchivedCandidate> = Vec::new();
        for _ in 0..deficit {
            let Some(target) = self.next_archivable(surface, policy.min_value) else {
                return Err(PressureAdmissionError::ReliefFailed {
                    source: BoundsError::BoundExceeded {
                        surface,
                        max_active: policy.max_active,
                    },
                    archived,
                });
            };
            let receipt = self
                .archive(&target.candidate_id, target.cause, target.summary)
                .map_err(|source| PressureAdmissionError::ReliefFailed {
                    source,
                    archived: archived.clone(),
                })?;
            archived.push(receipt);
        }
        Ok(archived)
    }

    /// The single best-justified archive target among the active entries on
    /// `surface`, or `None` when no entry's live state justifies a cause.
    ///
    /// Selection order, applied in stable `entries` index order so the result
    /// is reproducible for the same backlog:
    ///
    /// 1. ownerless entries before owned ones — an ownerless record has no
    ///    decision owner to be deprived of it and is already ineligible for
    ///    retrieval, delivery, compilation and cross-task use;
    /// 2. then the lowest assessed value — I12.24:297 bounds the backlog "by
    ///    target surface and value", so the least valuable entry is the one
    ///    whose expected benefit is cheapest to release;
    /// 3. then the lowest `entries` index as the final total tiebreak.
    fn next_archivable(&self, surface: ImprovementSurface, floor: f64) -> Option<ArchiveTarget> {
        let mut best: Option<ArchiveTarget> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.candidate.target_surface != surface || !entry.candidate.state.is_experimental()
            {
                continue;
            }
            let Some(cause) = archive_cause_for(entry, floor) else {
                continue;
            };
            let candidate = ArchiveTarget {
                retention_rank: u8::from(entry.owner.is_some()),
                value_order: entry.value.to_bits(),
                index,
                cause,
                candidate_id: entry.candidate.candidate_id.clone(),
                summary: pressure_archive_summary(entry, cause, floor),
            };
            let outranks = best.as_ref().is_none_or(|current| {
                (
                    candidate.retention_rank,
                    candidate.value_order,
                    candidate.index,
                ) < (current.retention_rank, current.value_order, current.index)
            });
            if outranks {
                best = Some(candidate);
            }
        }
        best
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

    /// Bind one task-local overlay into the owner-retained registry.
    ///
    /// This is the owner-side binding step: campaign id, task id, State
    /// Fence and overlay id are read from the verified permit, and the
    /// presented overlay is cross-checked against them. A mismatch is
    /// refused with the matching typed [`BoundsError`]; nothing is inferred
    /// and nothing is defaulted.
    ///
    /// Fail-closed preconditions beyond the permit cross-check:
    ///
    /// - the overlay lifecycle state must be `LOCAL_ADMITTED` — a draft,
    ///   rolled-back, invalidated or already-expired state has no local
    ///   effect to retain. Wall-clock expiry is not re-checked here because
    ///   `now` is a retrieval-time input; an overlay whose expiry has since
    ///   passed binds and is then refused by
    ///   [`BoundedBacklog::live_local_overlay`];
    /// - `admission_ref` must be present, because the local effect requires a
    ///   named Governor admission receipt;
    /// - `expires_at` must be present, because an overlay without an expiry
    ///   is never live and must not be retained as if it were.
    ///
    /// Rebinding the same overlay id replaces the previous record, so a
    /// re-issued permit supersedes the older binding instead of leaving two
    /// conflicting records behind.
    pub fn bind_local_overlay(
        &mut self,
        overlay: GovernedOverlay,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<(), BoundsError> {
        overlay.validate()?;
        let permit = verified.permit();
        if permit.overlay_id() != Some(overlay.overlay_id.trim()) {
            return Err(BoundsError::OverlayBackingMismatch);
        }
        if !fences_match_exact(&overlay.fence, permit.fence()) {
            return Err(BoundsError::StaleStateFence);
        }
        if overlay.campaign_id.trim() != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        if overlay.task_id.trim() != permit.target_task_id() {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if overlay.state != OverlayState::LocalAdmitted {
            return Err(BoundsError::OverlayNotAdmitted);
        }
        if overlay
            .admission_ref
            .as_ref()
            .is_none_or(|receipt| receipt.trim().is_empty())
        {
            return Err(BoundsError::MissingField("overlay.admission_ref"));
        }
        if overlay.expires_at.is_none() {
            return Err(BoundsError::MissingField("overlay.expires_at"));
        }
        let binding = BoundLocalOverlay {
            overlay,
            admission_digest: permit.digest().to_string(),
            authority_ref: permit.authority_ref().to_string(),
        };
        match self
            .bound_overlays
            .iter_mut()
            .find(|bound| bound.overlay.overlay_id == binding.overlay.overlay_id)
        {
            Some(existing) => *existing = binding,
            None => self.bound_overlays.push(binding),
        }
        Ok(())
    }

    /// The owner-retained live local overlay for a permit.
    ///
    /// Reads the retained record instead of a caller-presented overlay and
    /// re-confirms it against the same verified permit, so a rotated
    /// admission, a drifted fence, a foreign campaign or task, and an expired
    /// or unadmitted overlay are each refused with their own typed
    /// [`BoundsError`]. `now` MUST be owner/host-sourced live time: expiry
    /// invalidates influence and must never silently retain the last
    /// behaviour (I12.24:295).
    pub fn live_local_overlay(
        &self,
        verified: &VerifiedLearningAdmission<'_>,
        now: OffsetDateTime,
    ) -> Result<&GovernedOverlay, BoundsError> {
        let permit = verified.permit();
        let bound_overlay_id = permit
            .overlay_id()
            .ok_or(BoundsError::OverlayBackingMismatch)?;
        let binding = self
            .bound_overlays
            .iter()
            .find(|bound| bound.overlay.overlay_id == bound_overlay_id)
            .ok_or(BoundsError::OverlayBackingMismatch)?;
        if binding.admission_digest != permit.digest()
            || binding.authority_ref != permit.authority_ref()
        {
            return Err(BoundsError::GovernorAuthorityUnconfirmed);
        }
        if !fences_match_exact(&binding.overlay.fence, permit.fence()) {
            return Err(BoundsError::StaleStateFence);
        }
        if binding.overlay.campaign_id != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        if binding.overlay.task_id != permit.target_task_id() {
            return Err(BoundsError::CrossTaskAdmissionMismatch);
        }
        if binding.overlay.state == OverlayState::Expired
            || binding
                .overlay
                .expires_at
                .is_some_and(|expires| now >= expires)
        {
            return Err(BoundsError::ExpiredOverlay);
        }
        if !binding.overlay.is_live_local_admitted(now) {
            return Err(BoundsError::OverlayNotAdmitted);
        }
        Ok(&binding.overlay)
    }

    /// Bind one reusable candidate's closure and ownership material into the
    /// owner-retained registry.
    ///
    /// Ownership is copied from the retained backlog entry, never taken from
    /// the request: `admit`/`admit_reporting_pressure` recorded who owns the
    /// candidate and under which Governor authority, and a candidate with no
    /// retained owner is refused as [`BoundsError::OwnerlessRecord`]. The
    /// candidate must still be an ACTIVE entry, so `archive` revokes
    /// retrieval eligibility exactly as it revokes it for
    /// [`crate::producer::produce_learning_candidate`].
    ///
    /// `closure_ref` is the owner-issued closure disposition handle and
    /// `origin_campaign_id` must equal the permit's bound source campaign;
    /// a blank closure ref is refused as [`BoundsError::UnclosedReusable`]
    /// because an unclosed candidate is not yet eligible for another task.
    pub fn bind_reusable_candidate(
        &mut self,
        candidate_id: &str,
        closure_ref: &str,
        origin_campaign_id: &str,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<(), BoundsError> {
        let permit = verified.permit();
        if permit.candidate_id() != Some(candidate_id.trim()) {
            return Err(BoundsError::ReusableBackingMismatch);
        }
        if closure_ref.trim().is_empty() {
            return Err(BoundsError::UnclosedReusable);
        }
        if origin_campaign_id.trim().is_empty() {
            return Err(BoundsError::MissingField("origin_campaign_id"));
        }
        if origin_campaign_id.trim() != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        let entry = self
            .entry_for(candidate_id.trim())
            .ok_or(BoundsError::NotBacklogAdmitted)?;
        if entry.admitted_under_authority.as_deref() != Some(permit.authority_ref()) {
            return Err(BoundsError::GovernorAuthorityUnconfirmed);
        }
        let owner = entry
            .owner
            .clone()
            .filter(|owner| !owner.trim().is_empty())
            .ok_or(BoundsError::OwnerlessRecord)?;
        let binding = BoundReusableCandidate {
            reusable: ReusableCandidateRef {
                candidate_id: candidate_id.trim().to_string(),
                closure_ref: Some(closure_ref.trim().to_string()),
                owner: Some(owner),
                origin_campaign_id: origin_campaign_id.trim().to_string(),
            },
            admission_digest: permit.digest().to_string(),
            authority_ref: permit.authority_ref().to_string(),
        };
        match self
            .bound_reusables
            .iter_mut()
            .find(|bound| bound.reusable.candidate_id == binding.reusable.candidate_id)
        {
            Some(existing) => *existing = binding,
            None => self.bound_reusables.push(binding),
        }
        Ok(())
    }

    /// The owner-retained reusable material for a permit's candidate subject.
    ///
    /// Returns the retained [`ReusableCandidateRef`] so the retrieval gate
    /// consumes closure and ownership material that the owner bound, not
    /// strings a requester can re-spell. The permit must still bind this
    /// exact candidate and still be the issuance the binding was made under,
    /// and the candidate must still be an active backlog entry.
    pub fn active_reusable(
        &self,
        candidate_id: &str,
        verified: &VerifiedLearningAdmission<'_>,
    ) -> Result<&ReusableCandidateRef, BoundsError> {
        let permit = verified.permit();
        if permit.candidate_id() != Some(candidate_id.trim()) {
            return Err(BoundsError::ReusableBackingMismatch);
        }
        let binding = self
            .bound_reusables
            .iter()
            .find(|bound| bound.reusable.candidate_id == candidate_id.trim())
            .ok_or(BoundsError::ReusableBackingMismatch)?;
        if binding.admission_digest != permit.digest()
            || binding.authority_ref != permit.authority_ref()
        {
            return Err(BoundsError::GovernorAuthorityUnconfirmed);
        }
        if binding.reusable.origin_campaign_id != permit.source_campaign_id() {
            return Err(BoundsError::CrossCampaignLeakage);
        }
        self.entry_for(candidate_id.trim())
            .ok_or(BoundsError::NotBacklogAdmitted)?;
        Ok(&binding.reusable)
    }
}

/// The archive cause live state justifies for one active entry, or `None`
/// when no cause applies.
///
/// Mirrors exactly the validation [`BoundedBacklog::archive`] performs, so
/// the bound-pressure path can never force a cause the archive transition
/// would reject. An owned entry at or above the floor is never claimed, and
/// [`ArchiveCause::Stale`] is never returned: this crate has no live
/// producer of `ImprovementLifecycle::Stale` and the registry holds no
/// time-based evidence that could support the claim.
fn archive_cause_for(entry: &TrackedCandidate, floor: f64) -> Option<ArchiveCause> {
    if entry.owner.is_none() {
        return Some(ArchiveCause::Ownerless);
    }
    if entry.value < floor {
        return Some(ArchiveCause::LowValue);
    }
    None
}

/// Deterministic, evidence-derived archive summary for the bound-pressure
/// lifecycle transition.
///
/// Fixed `key=value` tokens joined by `;`, so the token separator stays
/// unambiguous even when a canonical record handle contains whitespace.
/// Every token is read from live state — the retained entry, the surface
/// policy floor and the derived cause — so the same backlog and policy
/// always produce the same string, no token is caller text, and the summary
/// is never empty or constant.
///
/// `decision_revision` is the candidate revision at which the archive
/// decision was taken. It is deliberately NOT the receipt's
/// `archived_revision`, which is the post-transition revision produced by
/// the `retire_candidate` chain.
fn pressure_archive_summary(entry: &TrackedCandidate, cause: ArchiveCause, floor: f64) -> String {
    let lineage = canonical_evidence_lineage(&entry.candidate.evidence_refs);
    let fingerprint = evidence_lineage_digest(&lineage)
        .chars()
        .take(16)
        .collect::<String>();
    format!(
        "cause={};surface={};candidate={};decision_revision={};value={};floor={};\
         evidence={};lineage_fp16={};merged_from={};authority={}",
        archive_cause_token(cause),
        surface_token(entry.candidate.target_surface),
        entry.candidate.candidate_id.trim(),
        entry.candidate.revision,
        entry.value,
        floor,
        lineage.len(),
        fingerprint,
        entry.merged_from.len(),
        entry
            .admitted_under_authority
            .as_deref()
            .map(str::trim)
            .filter(|authority| !authority.is_empty())
            .unwrap_or("none"),
    )
}

/// Stable summary token for an archive cause. Mirrors the enum's own
/// `snake_case` wire name.
fn archive_cause_token(cause: ArchiveCause) -> &'static str {
    match cause {
        ArchiveCause::Stale => "stale",
        ArchiveCause::Ownerless => "ownerless",
        ArchiveCause::LowValue => "low_value",
    }
}

/// Stable summary token for a target surface. Mirrors the `snake_case` wire
/// name `ImprovementSurface` serializes under, so the durable summary token
/// cannot drift from the record vocabulary — and never from Rust `Debug`
/// output, which is not a durable encoding.
fn surface_token(surface: ImprovementSurface) -> &'static str {
    match surface {
        ImprovementSurface::Memory => "memory",
        ImprovementSurface::Skill => "skill",
        ImprovementSurface::ToolProfile => "tool_profile",
        ImprovementSurface::Rule => "rule",
        ImprovementSurface::PacketCompiler => "packet_compiler",
        ImprovementSurface::Verifier => "verifier",
        ImprovementSurface::Scheduler => "scheduler",
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
    if let Some(reusable) = gate.reusable {
        closure_candidate_usable_by_task(
            reusable.origin_campaign_id.as_str(),
            reusable.closure_ref.as_deref(),
            gate.requesting_task_id,
            gate.requesting_campaign_id,
            gate.cross_task_admission.map(|a| a.admission_id.as_str()),
        )
        .map_err(GovernedClosureError::Bounds)?;
    }
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

/// Lifecycle-event entry to governed closure assembly (#1866 W1, I12.24).
///
/// Classifies `event` through [`trigger_closure_due`] against the closure
/// policy, then delegates to
/// [`governed_assemble_campaign_learning_closure`]. Terminalization and
/// delayed-outcome/rework/maintenance windows always open closure work; a
/// major checkpoint opens it only when the policy admits checkpoints, else
/// [`BoundsError::InvalidPolicy`] is returned and nothing is assembled.
/// Returns the assembly together with the trigger assessment so the caller
/// (finish job / checkpoint owner) can record debt when closure stays open.
#[allow(clippy::too_many_arguments)]
pub fn governed_assemble_at_lifecycle_event(
    event: ClosureLifecycleEvent,
    exact_campaign_and_target: CampaignAndTarget,
    exact_attempt_outcomes_and_deltas: AttemptOutcomesAndDeltas,
    exact_overlay_and_activation_assessments: OverlayAndActivationAssessments,
    exact_outcome_harm_and_economics_evidence: OutcomeHarmAndEconomicsEvidence,
    prior_closure_history: PriorClosureHistory,
    closure_policy: ClosurePolicy,
    gate: GovernedRetrieval<'_>,
) -> Result<(ClosureAssembly, ClosureDue), GovernedClosureError> {
    let due = trigger_closure_due(event, &closure_policy);
    if event == ClosureLifecycleEvent::MajorCheckpoint && !due.checkpoint {
        return Err(GovernedClosureError::Bounds(BoundsError::InvalidPolicy(
            "checkpoint closure not admitted by closure policy",
        )));
    }
    let assembly = governed_assemble_campaign_learning_closure(
        exact_campaign_and_target,
        exact_attempt_outcomes_and_deltas,
        exact_overlay_and_activation_assessments,
        exact_outcome_harm_and_economics_evidence,
        prior_closure_history,
        closure_policy,
        gate,
    )?;
    Ok((assembly, due))
}

// ---------------------------------------------------------------------------
// Closure-assembly admission (#1866 W5/A4, I12.24 cross-task refusal).
//
// Draft deltas, unclosed reusable candidates, expired overlays, and ownerless
// records must never affect another task: an unclosed reusable from a
// finished campaign cannot be retrieved/applied by a different task. Before
// closure, only the exact non-expired LOCAL_ADMITTED overlay of the active
// campaign may influence a compatible attempt. Cross-task carryover requires
// a new governed admission.
// ---------------------------------------------------------------------------

/// Admission request to assemble (close over) a campaign's learning closure
/// on behalf of a task.
///
/// `campaign_id` identifies the closure campaign whose scope owns the
/// assembly; `requesting_task_id` is the task asking for the assembly.
/// `closure_ref` is the closure disposition that closed the candidate
/// (None/blank = unclosed, ineligible). `cross_task_admission_ref` names the
/// distinct, newly governed admission permitting cross-task carryover, when
/// the requesting task operates outside the closure campaign's scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureAssemblyRequest {
    pub campaign_id: String,
    pub requesting_task_id: String,
    pub closure_ref: Option<String>,
    pub cross_task_admission_ref: Option<String>,
}

impl ClosureAssemblyRequest {
    pub fn validate(&self) -> Result<(), BoundsError> {
        if self.campaign_id.trim().is_empty() {
            return Err(BoundsError::MissingField("campaign_id"));
        }
        if self.requesting_task_id.trim().is_empty() {
            return Err(BoundsError::MissingField("requesting_task_id"));
        }
        Ok(())
    }
}

/// Governed admission gate for closure assembly.
///
/// Reuses [`BoundsError`]: missing closure returns
/// [`BoundsError::UnclosedReusable`]; a requesting task outside the closure
/// campaign's scope without a distinct governed admission returns
/// [`BoundsError::CrossTaskAdmissionMissing`].
///
/// Scope note: the request carries only the closure `campaign_id` and the
/// requesting task id, so the campaign's task scope is identified by the
/// `campaign_id` string itself. A requesting task whose id equals the
/// campaign scope string is treated as local; any other task must present a
/// non-blank `cross_task_admission_ref`. This is fail-closed: ordinary task
/// ids never equal a campaign id, so cross-task assembly always requires
/// the new governed admission.
pub fn governed_closure_assembly_admission(
    request: &ClosureAssemblyRequest,
) -> Result<(), BoundsError> {
    request.validate()?;
    let closure_ref = request
        .closure_ref
        .as_ref()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty());
    let Some(closure_ref) = closure_ref else {
        return Err(BoundsError::UnclosedReusable);
    };
    // Exactly one allowed disposition (I12.24): the closing ref must name one
    // of the eight canonical dispositions (legacy aliases accepted).
    if ClosureDisposition::parse(closure_ref).is_none() {
        return Err(BoundsError::InvalidPolicy(
            "closure_ref is not an allowed closure disposition",
        ));
    }
    if request.requesting_task_id != request.campaign_id
        && request
            .cross_task_admission_ref
            .as_ref()
            .is_none_or(|r| r.trim().is_empty())
    {
        return Err(BoundsError::CrossTaskAdmissionMissing);
    }
    Ok(())
}

/// Pure per-candidate usability check for closure assembly by a task.
///
/// Returns `Ok(())` only when `candidate_closure_ref` is `Some(non-blank)`
/// AND (`requesting_campaign_id == candidate_campaign_id` OR
/// `cross_task_admission_ref` is `Some(non-blank)`). Otherwise returns the
/// existing [`BoundsError`] variant for the failure: [`BoundsError::UnclosedReusable`]
/// for a missing/blank closure ref, [`BoundsError::MissingField`] for blank
/// identity inputs, or [`BoundsError::CrossTaskAdmissionMissing`] for a
/// foreign-campaign candidate without a distinct governed admission.
///
/// Intended call site: the top of [`governed_assemble_campaign_learning_closure`],
/// mapping its existing `gate` parameters (`gate.reusable.map(|r|
/// r.origin_campaign_id)`, `gate.reusable.map(|r| r.closure_ref)`,
/// `gate.requesting_task_id`, `gate.requesting_campaign_id`,
/// `gate.cross_task_admission.map(|a| a.admission_id)`) into this helper and
/// converting `BoundsError` into `GovernedClosureError::Bounds`. The wired
/// call below follows exactly that mapping when a reusable is presented; a
/// `None` reusable carries no closure candidate, so the helper is skipped.
pub fn closure_candidate_usable_by_task(
    candidate_campaign_id: &str,
    candidate_closure_ref: Option<&str>,
    requesting_task_id: &str,
    requesting_campaign_id: &str,
    cross_task_admission_ref: Option<&str>,
) -> Result<(), BoundsError> {
    if candidate_closure_ref.is_none_or(|r| r.trim().is_empty()) {
        return Err(BoundsError::UnclosedReusable);
    }
    if candidate_campaign_id.trim().is_empty() {
        return Err(BoundsError::MissingField("candidate_campaign_id"));
    }
    if requesting_task_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_task_id"));
    }
    if requesting_campaign_id.trim().is_empty() {
        return Err(BoundsError::MissingField("requesting_campaign_id"));
    }
    if requesting_campaign_id == candidate_campaign_id {
        return Ok(());
    }
    if cross_task_admission_ref.is_none_or(|r| r.trim().is_empty()) {
        return Err(BoundsError::CrossTaskAdmissionMissing);
    }
    Ok(())
}
