//! Inert position candidate: everything a resolver needs, nothing it does.
//!
//! An [`EpistemicPositionCandidate`] carries the proposition, revision, and
//! predecessor; task, attempt, scope, time, and version; manifest, claim map,
//! coverage, and conflict references; support records with explicit unknowns;
//! grade, authority, disclosure, verifier, and proof; rivals; proposed
//! assertability; invalidation; and a frozen digest. It carries no admission
//! receipt, no write or allocation record, no material-effect grant, and no
//! finish input: admission, effects, and finishing belong to their owning
//! boundaries, never to a candidate.
//!
//! Identity closure is exact. The scoped-claim versus covered-proposition
//! distinction is resolved by set equality: the candidate claim IDs, the
//! claim-map admitted set, and the claim-map entry set coincide exactly —
//! there is no notion of a claim the candidate covers without entering, or
//! enters without the manifest admitting. A candidate entering a strict subset
//! of its map fails closed validation. Support records bind by proposition,
//! task, attempt, scope, and fence instead of by claim ID: evidence handles
//! and claim identities are different families, and equating them would
//! manufacture lineage.
//!
//! Coverage completeness is never inferred from merely-empty unknowns or
//! conflicts. Shape validation caps open assertability at hypothesis
//! candidate; only [`EpistemicPositionCandidate::validate_closed`], given the
//! exact frozen denominator, terminal receipt, claim map, conflict sets,
//! assumptions, and request, derives the closed ceiling from receipt
//! terminality and arithmetic.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskId, TaskRevision};
use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assertability::PositionAssertability;
use crate::assumption::AssumptionRecord;
use crate::claim_map::{ClaimEntry, ClaimMap};
use crate::conflict::ConflictSet;
use crate::coverage::{CoverageDenominator, DenominatorKind};
use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::grade::EvidenceGrade;
use crate::identity::{ManifestId, PredecessorId, PropositionId};
use crate::receipt::CoverageReceipt;
use crate::request::PositionRequest;
use crate::support::{SupportRecord, SupportResult};
use crate::transition::InvalidationRecord;
use crate::verifier::{DisclosureClass, RequiredVerifier};

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
    /// Attempt binding of the inquiry; retries never share an attempt.
    pub attempt_id: String,
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
    /// Per-claim entries in declaration order. The entry IDs coincide exactly
    /// with the claim-map admitted set; see `validate_closed`.
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
    /// How widely the candidate may travel; a ceiling, never evidence.
    pub disclosure: DisclosureClass,
    /// Verifier required to vouch for elevated renderings, when one is bound.
    pub verifier: Option<RequiredVerifier>,
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
    attempt_id: &'a str,
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
    disclosure: &'a DisclosureClass,
    proof_digest: &'a str,
    rivals: &'a BTreeSet<String>,
    proposed_assertability: &'a PositionAssertability,
    invalidation: &'a Option<InvalidationRecord>,
    verifier: &'a Option<RequiredVerifier>,
}

impl EpistemicPositionCandidate {
    /// Constructs a candidate and freezes its canonical digest.
    ///
    /// Construction enforces shape closure only. Open assertability is capped
    /// at hypothesis candidate: coverage completeness is never derived from
    /// merely-empty unknowns or conflicts. The closed ceiling needs
    /// [`EpistemicPositionCandidate::validate_closed`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposition: PropositionId,
        revision: TaskRevision,
        predecessor: Option<PredecessorId>,
        task_id: TaskId,
        attempt_id: impl Into<String>,
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
        disclosure: DisclosureClass,
        verifier: Option<RequiredVerifier>,
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
            attempt_id: attempt_id.into(),
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
            disclosure,
            verifier,
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
            attempt_id: self.attempt_id.as_str(),
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
            disclosure: &self.disclosure,
            proof_digest: self.proof_digest.as_str(),
            rivals: &self.rivals,
            proposed_assertability: &self.proposed_assertability,
            invalidation: &self.invalidation,
            verifier: &self.verifier,
        })
    }

    /// Collects support handles and results after task/scope/fence binding.
    ///
    /// Support records bind by proposition, task, scope, and fence instead of
    /// by claim ID: evidence handles and claim identities are different
    /// families, and equating them would manufacture lineage.
    fn bound_support(&self) -> Result<(BTreeSet<ArtifactId>, Vec<SupportResult>), ContractError> {
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
        let mut handles = BTreeSet::new();
        let mut results = Vec::with_capacity(self.support.len());
        for record in &self.support {
            record.validate_for(&self.task_id, &self.scope, &self.fence)?;
            if record.proposition != self.proposition {
                return Err(ContractError::ScopeMismatch {
                    field: "candidate.proposition",
                });
            }
            handles.extend(record.handles.iter().cloned());
            results.push(record.result);
        }
        Ok((handles, results))
    }

    /// Validates the predecessor/invalidation history chain.
    ///
    /// Predecessors are retained verbatim as history: when an invalidation
    /// names a predecessor it must name the retained one, never a rewritten
    /// chain. Forward moves belong to transitions, never to candidates.
    fn check_history(&self) -> Result<(), ContractError> {
        if let Some(invalidation) = &self.invalidation {
            invalidation.validate()?;
            if let Some(predecessor) = &self.predecessor
                && invalidation.predecessor.as_str() != predecessor.as_str()
            {
                return Err(ContractError::ImpossibleCombination {
                    field: "candidate.invalidation",
                });
            }
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.candidate_kind != CandidateKind::EpistemicPositionCandidate {
            return Err(ContractError::ImpossibleCombination {
                field: "candidate.candidate_kind",
            });
        }
        validate_bounded_text(&self.attempt_id, "candidate.attempt_id", MAX_SHORT_TEXT)?;
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
        let (_, support_results) = self.bound_support()?;
        if self.unknowns.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.unknowns",
            });
        }
        for unknown in &self.unknowns {
            validate_bounded_text(unknown.as_str(), "candidate.unknowns", MAX_SHORT_TEXT)?;
        }
        if let Some(verifier) = &self.verifier {
            verifier.validate()?;
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
        // Open assertability: coverage completeness is never derived from
        // merely-empty unknowns or conflicts, so the open ceiling treats
        // coverage as incomplete. Only `validate_closed` derives completeness
        // from a terminal receipt over a complete denominator.
        PositionAssertability::check_closed(
            self.proposed_assertability,
            self.grade,
            self.authority,
            &support_results,
            false,
            !self.conflict_digests.is_empty(),
            true,
            self.disclosure,
            self.verifier.as_ref(),
        )?;
        self.check_history()?;
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

    /// Closes the candidate against its governing request, denominator,
    /// receipt, claim map, conflict sets, and assumption records.
    ///
    /// Closure is exact in every axis: the request binds task, attempt, scope,
    /// fence, proposition, and revision, and every support handle is admitted
    /// by the request; the coverage digest equals the frozen denominator
    /// digest; the receipt reports on that denominator with matching task,
    /// scope, fence, and size; the claim-map digest equals the frozen map
    /// digest with the same manifest, the candidate claim IDs coinciding
    /// exactly with the admitted set and every entered claim equal by value
    /// (same ID with changed evidence fails); every claim support handle
    /// resolves into candidate support, every unresolved marker resolves into
    /// candidate unknowns, every named assumption resolves into a provided
    /// assumption record, and claimed conflicts resolve exactly into the
    /// provided conflict sets with no foreign, missing, or extra members.
    /// Coverage completeness derives from a complete denominator plus an
    /// all-terminal receipt with exact member arithmetic, and the closed
    /// assertability ceiling is re-derived from that completeness together
    /// with every other ceiling.
    pub fn validate_closed(
        &self,
        request: &PositionRequest,
        denominator: &CoverageDenominator,
        receipt: &CoverageReceipt,
        map: &ClaimMap,
        conflicts: &[ConflictSet],
        assumptions: &[AssumptionRecord],
    ) -> Result<(), ContractError> {
        self.validate()?;
        request.validate()?;
        denominator.validate()?;
        receipt.validate()?;
        map.validate()?;
        for conflict in conflicts {
            conflict.validate()?;
        }
        for assumption in assumptions {
            assumption.validate()?;
        }
        let (support_handles, support_results) = self.bound_support()?;
        self.check_request_binding(request, &support_handles)?;
        let coverage_complete = self.check_coverage_binding(denominator, receipt)?;
        self.check_map_binding(map, &support_handles, assumptions, conflicts)?;
        let conflict_open = self.check_conflict_binding(conflicts)?;
        PositionAssertability::check_closed(
            self.proposed_assertability,
            self.grade,
            self.authority,
            &support_results,
            coverage_complete,
            conflict_open,
            true,
            self.disclosure,
            self.verifier.as_ref(),
        )?;
        Ok(())
    }

    /// Binds task, attempt, scope, proposition, revision, and fence to the
    /// governing request; every support handle is admitted by the request.
    fn check_request_binding(
        &self,
        request: &PositionRequest,
        support_handles: &BTreeSet<ArtifactId>,
    ) -> Result<(), ContractError> {
        if request.task_id != self.task_id {
            return Err(ContractError::TaskMismatch {
                field: "candidate.task_id",
            });
        }
        if request.attempt_id != self.attempt_id {
            return Err(ContractError::TaskMismatch {
                field: "candidate.attempt_id",
            });
        }
        if request.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.scope",
            });
        }
        if !request.applies_to(&self.proposition) {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.proposition",
            });
        }
        if request.revision != self.revision {
            return Err(ContractError::StaleContext {
                field: "candidate.revision",
            });
        }
        if !self.fence.is_compatible_with(&request.fence)
            || !request.fence.is_compatible_with(&self.fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "candidate.fence",
            });
        }
        for handle in support_handles {
            if !request.records.contains(handle) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.support",
                });
            }
        }
        Ok(())
    }

    /// Binds the frozen denominator and its receipt, deriving closed
    /// completeness from a complete denominator plus an all-terminal receipt
    /// with exact member arithmetic. Anything else stays incomplete, no
    /// matter how empty the unknowns or conflicts are.
    fn check_coverage_binding(
        &self,
        denominator: &CoverageDenominator,
        receipt: &CoverageReceipt,
    ) -> Result<bool, ContractError> {
        if self.coverage_digest != denominator.digest {
            return Err(ContractError::DigestMismatch {
                field: "candidate.coverage_digest",
            });
        }
        if denominator.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.coverage",
            });
        }
        if !denominator.fence.is_compatible_with(&self.fence)
            || !self.fence.is_compatible_with(&denominator.fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "candidate.coverage",
            });
        }
        if receipt.denominator != denominator.digest {
            return Err(ContractError::DigestMismatch {
                field: "candidate.coverage",
            });
        }
        if receipt.task_id != self.task_id {
            return Err(ContractError::TaskMismatch {
                field: "candidate.coverage",
            });
        }
        if receipt.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.coverage",
            });
        }
        if !receipt.fence.is_compatible_with(&self.fence)
            || !self.fence.is_compatible_with(&receipt.fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "candidate.coverage",
            });
        }
        if receipt.denominator_size != denominator.members.len() as u64 {
            return Err(ContractError::ArithmeticMismatch {
                field: "candidate.coverage",
            });
        }
        if denominator.kind != DenominatorKind::CompleteScope {
            return Ok(false);
        }
        let frozen: BTreeSet<_> = denominator.members.iter().collect();
        let reported: BTreeSet<_> = receipt
            .members
            .iter()
            .map(|outcome| &outcome.member)
            .collect();
        if reported != frozen {
            if !reported.is_subset(&frozen) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.coverage",
                });
            }
            return Err(ContractError::MissingReference {
                field: "candidate.coverage",
            });
        }
        Ok(receipt.omissions.is_empty() && receipt.is_terminal())
    }

    /// Binds the governing claim map: same digest, same manifest, candidate
    /// claim IDs coinciding exactly with the admitted set, every entered
    /// claim equal by value to its governed shape, and every support handle,
    /// unresolved marker, assumption name, and conflict reference resolved.
    fn check_map_binding(
        &self,
        map: &ClaimMap,
        support_handles: &BTreeSet<ArtifactId>,
        assumptions: &[AssumptionRecord],
        conflicts: &[ConflictSet],
    ) -> Result<(), ContractError> {
        if self.claim_map_digest != map.digest {
            return Err(ContractError::DigestMismatch {
                field: "candidate.claim_map_digest",
            });
        }
        if map.manifest != self.manifest {
            return Err(ContractError::OutsideManifest {
                field: "candidate.manifest",
            });
        }
        let candidate_ids: BTreeSet<_> = self
            .claims
            .iter()
            .map(|entry| entry.claim.clone())
            .collect();
        if candidate_ids.len() != self.claims.len() {
            return Err(ContractError::Duplicate {
                field: "candidate.claims",
            });
        }
        for entry in &self.claims {
            if !map.admitted.contains(&entry.claim) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.claims",
                });
            }
        }
        for admitted in &map.admitted {
            if !candidate_ids.contains(admitted) {
                return Err(ContractError::MissingReference {
                    field: "candidate.claims",
                });
            }
        }
        for entry in &self.claims {
            self.check_claim_entry(map, entry, support_handles, assumptions, conflicts)?;
        }
        Ok(())
    }

    /// Resolves one entered claim against its governed shape.
    fn check_claim_entry(
        &self,
        map: &ClaimMap,
        entry: &ClaimEntry,
        support_handles: &BTreeSet<ArtifactId>,
        assumptions: &[AssumptionRecord],
        conflicts: &[ConflictSet],
    ) -> Result<(), ContractError> {
        let Some(governed) = map
            .entries
            .iter()
            .find(|map_entry| map_entry.claim == entry.claim)
        else {
            return Err(ContractError::MissingReference {
                field: "candidate.claims",
            });
        };
        // Same ID with changed evidence is a different claim, not an update:
        // the entered shape must equal the governed shape by value.
        if governed != entry {
            return Err(ContractError::DigestMismatch {
                field: "candidate.claims",
            });
        }
        for handle in &entry.support {
            if !support_handles.contains(handle) {
                return Err(ContractError::MissingReference {
                    field: "candidate.support",
                });
            }
        }
        for marker in &entry.unresolved_support {
            if !self.unknowns.contains(marker) {
                return Err(ContractError::MissingReference {
                    field: "candidate.unknowns",
                });
            }
        }
        for assumption in &entry.assumptions {
            if !assumptions
                .iter()
                .any(|record| record.assumption_id.as_str() == assumption.as_str())
            {
                return Err(ContractError::MissingReference {
                    field: "candidate.assumptions",
                });
            }
        }
        if entry.conflict.is_some() && conflicts.is_empty() {
            return Err(ContractError::MissingReference {
                field: "candidate.conflicts",
            });
        }
        Ok(())
    }

    /// Binds claimed conflicts exactly to the provided sets and reports
    /// whether any conflict stays open.
    fn check_conflict_binding(&self, conflicts: &[ConflictSet]) -> Result<bool, ContractError> {
        let provided: BTreeSet<_> = conflicts
            .iter()
            .map(|conflict| conflict.digest.clone())
            .collect();
        if provided != self.conflict_digests {
            if !self.conflict_digests.is_subset(&provided) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.conflicts",
                });
            }
            return Err(ContractError::MissingReference {
                field: "candidate.conflicts",
            });
        }
        Ok(!conflicts.is_empty() || !self.conflict_digests.is_empty())
    }
}
