//! Inert position candidate: everything a resolver needs, nothing it does.
//!
//! An [`EpistemicPositionCandidate`] carries the proposition, revision, and
//! predecessor; scope, time, and version; manifest, claim map, coverage, and
//! conflict references; support records with explicit unknowns; grade,
//! authority, and proof; rivals; proposed assertability; invalidation; and a
//! frozen digest. It carries no admission receipt, no write or allocation
//! record, no material-effect grant, and no finish input: admission, effects,
//! and finishing belong to their owning boundaries, never to a candidate.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, TaskId, TaskRevision};
use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assertability::PositionAssertability;
use crate::claim_map::{ClaimEntry, ClaimMap};
use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::grade::EvidenceGrade;
use crate::identity::{ManifestId, PredecessorId, PropositionId};
use crate::support::SupportRecord;
use crate::transition::InvalidationRecord;

/// Marker proving a document is a candidate and never an admitted view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum CandidateKind {
    /// The single admitted spelling of a position candidate.
    #[serde(rename = "EPISTEMIC_POSITION_CANDIDATE")]
    #[schemars(rename = "EPISTEMIC_POSITION_CANDIDATE")]
    EpistemicPositionCandidate,
}

/// An inert candidate position awaiting admission elsewhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicPositionCandidate {
    /// Marker binding this document to the candidate decoding.
    pub candidate_kind: CandidateKind,
    /// Proposition the candidate bears on.
    pub proposition: PropositionId,
    /// Task-plan revision the candidate was built under.
    pub revision: TaskRevision,
    /// Predecessor retained as history, when one exists.
    pub predecessor: Option<PredecessorId>,
    /// Task binding of the inquiry.
    pub task_id: TaskId,
    /// Scope the candidate covers.
    pub scope: String,
    /// Start of the candidate window in Unix milliseconds, when bounded.
    pub window_start_ms: Option<i64>,
    /// End of the candidate window in Unix milliseconds, when bounded.
    pub window_end_ms: Option<i64>,
    /// Source or protocol version the candidate was built under.
    pub version: String,
    /// Fence the candidate was built under.
    pub fence: StateFence,
    /// Allowed-reference manifest bounding the candidate.
    pub manifest: ManifestId,
    /// Per-claim entries in declaration order.
    pub claims: Vec<ClaimEntry>,
    /// Canonical digest of the governing claim map.
    pub claim_map_digest: String,
    /// Canonical digest of the coverage denominator.
    pub coverage_digest: String,
    /// Conflict set digests touching the candidate; order carries no meaning.
    pub conflict_digests: BTreeSet<String>,
    /// Support records in declaration order.
    pub support: Vec<SupportRecord>,
    /// Explicit unknowns; absence of an entry is not certainty.
    pub unknowns: BTreeSet<String>,
    /// Grade the candidate was produced under.
    pub grade: EvidenceGrade,
    /// Authority class of the evidence behind the candidate.
    pub authority: EvidenceAuthority,
    /// Digest of the bounded proof payload behind the candidate.
    pub proof_digest: String,
    /// Preserved rival explanations; order carries no meaning.
    pub rivals: BTreeSet<String>,
    /// Assertability proposed for the candidate, capped by every ceiling.
    pub proposed_assertability: PositionAssertability,
    /// Invalidation record, when the candidate invalidates history.
    pub invalidation: Option<InvalidationRecord>,
    /// Canonical digest of the candidate shape, excluding this field.
    pub digest: String,
}

/// Canonical digest shape of a candidate, excluding the frozen digest field.
#[derive(Serialize)]
struct CandidateDigestShape<'a> {
    candidate_kind: &'a CandidateKind,
    proposition: &'a PropositionId,
    revision: &'a TaskRevision,
    predecessor: &'a Option<PredecessorId>,
    task_id: &'a TaskId,
    scope: &'a str,
    window_start_ms: &'a Option<i64>,
    window_end_ms: &'a Option<i64>,
    version: &'a str,
    fence: &'a StateFence,
    manifest: &'a ManifestId,
    claims: &'a [ClaimEntry],
    claim_map_digest: &'a str,
    coverage_digest: &'a str,
    conflict_digests: &'a BTreeSet<String>,
    support: &'a [SupportRecord],
    unknowns: &'a BTreeSet<String>,
    grade: &'a EvidenceGrade,
    authority: &'a EvidenceAuthority,
    proof_digest: &'a str,
    rivals: &'a BTreeSet<String>,
    proposed_assertability: &'a PositionAssertability,
    invalidation: &'a Option<InvalidationRecord>,
}

impl EpistemicPositionCandidate {
    /// Constructs a candidate and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposition: PropositionId,
        revision: TaskRevision,
        predecessor: Option<PredecessorId>,
        task_id: TaskId,
        scope: impl Into<String>,
        window_start_ms: Option<i64>,
        window_end_ms: Option<i64>,
        version: impl Into<String>,
        fence: StateFence,
        manifest: ManifestId,
        claims: Vec<ClaimEntry>,
        claim_map: Option<&ClaimMap>,
        coverage_digest: impl Into<String>,
        conflict_digests: BTreeSet<String>,
        support: Vec<SupportRecord>,
        unknowns: BTreeSet<String>,
        grade: EvidenceGrade,
        authority: EvidenceAuthority,
        proof_digest: impl Into<String>,
        rivals: BTreeSet<String>,
        proposed_assertability: PositionAssertability,
        invalidation: Option<InvalidationRecord>,
    ) -> Result<Self, ContractError> {
        let claim_map_digest = match &claim_map {
            Some(map) => {
                map.validate()?;
                map.digest.clone()
            }
            None => {
                return Err(ContractError::EmptyCollection {
                    field: "candidate.claim_map",
                });
            }
        };
        let mut candidate = Self {
            candidate_kind: CandidateKind::EpistemicPositionCandidate,
            proposition,
            revision,
            predecessor,
            task_id,
            scope: scope.into(),
            window_start_ms,
            window_end_ms,
            version: version.into(),
            fence,
            manifest,
            claims,
            claim_map_digest,
            coverage_digest: coverage_digest.into(),
            conflict_digests,
            support,
            unknowns,
            grade,
            authority,
            proof_digest: proof_digest.into(),
            rivals,
            proposed_assertability,
            invalidation,
            digest: String::new(),
        };
        candidate.validate_shape()?;
        candidate.digest = candidate.compute_digest()?;
        Ok(candidate)
    }

    /// Recomputes the canonical digest of the candidate shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&CandidateDigestShape {
            candidate_kind: &self.candidate_kind,
            proposition: &self.proposition,
            revision: &self.revision,
            predecessor: &self.predecessor,
            task_id: &self.task_id,
            scope: self.scope.as_str(),
            window_start_ms: &self.window_start_ms,
            window_end_ms: &self.window_end_ms,
            version: self.version.as_str(),
            fence: &self.fence,
            manifest: &self.manifest,
            claims: self.claims.as_slice(),
            claim_map_digest: self.claim_map_digest.as_str(),
            coverage_digest: self.coverage_digest.as_str(),
            conflict_digests: &self.conflict_digests,
            support: self.support.as_slice(),
            unknowns: &self.unknowns,
            grade: &self.grade,
            authority: &self.authority,
            proof_digest: self.proof_digest.as_str(),
            rivals: &self.rivals,
            proposed_assertability: &self.proposed_assertability,
            invalidation: &self.invalidation,
        })
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.candidate_kind != CandidateKind::EpistemicPositionCandidate {
            return Err(ContractError::ImpossibleCombination {
                field: "candidate.candidate_kind",
            });
        }
        validate_bounded_text(&self.scope, "candidate.scope", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.version, "candidate.version", MAX_SHORT_TEXT)?;
        if let (Some(start), Some(end)) = (self.window_start_ms, self.window_end_ms)
            && end < start
        {
            return Err(ContractError::InvertedInterval {
                field: "candidate.window",
            });
        }
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "candidate.fence",
            })?;
        if self.claims.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "candidate.claims",
            });
        }
        if self.claims.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.claims",
            });
        }
        for entry in &self.claims {
            entry.validate()?;
        }
        validate_digest(&self.claim_map_digest, "candidate.claim_map_digest")?;
        validate_digest(&self.coverage_digest, "candidate.coverage_digest")?;
        if self.conflict_digests.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.conflict_digests",
            });
        }
        for conflict_digest in &self.conflict_digests {
            validate_digest(conflict_digest.as_str(), "candidate.conflict_digests")?;
        }
        if self.support.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "candidate.support",
            });
        }
        if self.support.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.support",
            });
        }
        for record in &self.support {
            record.validate_for(&self.task_id, &self.scope, &self.fence)?;
        }
        if self.unknowns.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.unknowns",
            });
        }
        for unknown in &self.unknowns {
            validate_bounded_text(unknown.as_str(), "candidate.unknowns", MAX_SHORT_TEXT)?;
        }
        validate_digest(&self.proof_digest, "candidate.proof_digest")?;
        if self.rivals.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.rivals",
            });
        }
        for rival in &self.rivals {
            validate_bounded_text(rival.as_str(), "candidate.rivals", MAX_SHORT_TEXT)?;
        }
        let coverage_complete = self.unknowns.is_empty() && self.conflict_digests.is_empty();
        PositionAssertability::check(
            self.proposed_assertability,
            self.grade,
            self.authority,
            coverage_complete,
            !self.conflict_digests.is_empty(),
            true,
        )?;
        if let Some(invalidation) = &self.invalidation {
            invalidation.validate()?;
        }
        Ok(())
    }

    /// Validates the candidate shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "candidate.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "candidate.digest",
            });
        }
        Ok(())
    }
}
