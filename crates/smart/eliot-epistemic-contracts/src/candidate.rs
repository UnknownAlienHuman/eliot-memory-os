//! Inert position candidate: everything a resolver needs, nothing it does.
//!
//! An [`EpistemicPositionCandidate`] carries proposition, revision, predecessor, task/attempt/scope/time/version
//! bindings, manifest, claim map, coverage and conflict references, support with explicit unknowns, grade,
//! authority, disclosure, privacy, verifier, proof, rivals, proposed assertability, invalidation, and a frozen
//! digest. It carries no admission receipt, write record, effect grant, or finish input.
//!
//! Identity closure is exact: candidate claim IDs, claim-map admitted set, and claim-map entry set coincide,
//! and support binds by proposition, task, attempt, scope, and fence rather than claim ID. Coverage completeness
//! is never inferred from empty unknowns or conflicts.
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, OperationId, RequestId, StateFence, TaskId, TaskRevision};
use eliot_evidence::EvidenceAuthority;
use eliot_receipts::WorkScope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::assertability::PositionAssertability;
use crate::assumption::AssumptionRecord;
use crate::claim_map::{ClaimEntry, ClaimMap};
use crate::conflict::ConflictSet;
use crate::coverage::{CoverageDenominator, DenominatorKind, check_receipt_query_frontier};
use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::grade::GradeAssignment;
use crate::identity::{ManifestId, PredecessorId, PropositionId};
use crate::receipt::{CoverageReceipt, check_member_roles};
use crate::request::PositionRequest;
use crate::support::{SupportRecord, SupportResult};
use crate::temporal::TemporalRecord;
use crate::transition::InvalidationRecord;
use crate::verifier::{DisclosureClass, PrivacyHandling, RequiredVerifier};

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
#[serde(deny_unknown_fields, try_from = "EpistemicPositionCandidateWire")]
pub struct EpistemicPositionCandidate {
    /// Marker binding this document to the candidate decoding.
    pub candidate_kind: CandidateKind,
    /// Proposition the candidate bears on.
    pub proposition: PropositionId,
    /// Task-plan revision the candidate was built under.
    pub revision: TaskRevision,
    /// Caller request identity this candidate answers; must equal the governing request's identity.
    pub request_id: RequestId,
    /// Operation identity the candidate is proposed under; must equal the governing request's operation.
    pub operation_id: OperationId,
    /// Idempotency key binding retries of this exact ask; must equal the governing request's key.
    pub idempotency_key: String,
    /// Canonical work scope the candidate was built in; must equal the governing request's scope.
    pub work_scope: WorkScope,
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
    /// Highest precision the candidate asserts, e.g. `file` or `symbol`.
    /// Support finer than this never licenses it.
    pub precision: String,
    /// Fence the candidate was built under.
    pub fence: StateFence,
    /// Allowed-reference manifest bounding the candidate.
    pub manifest: ManifestId,
    /// Per-claim entries in declaration order, coinciding exactly with the claim-map admitted set.
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
    /// Grade assignment the candidate was produced under; unknown caps.
    pub grade: GradeAssignment,
    /// Authority class of the evidence behind the candidate.
    pub authority: EvidenceAuthority,
    /// How widely the candidate may travel; a ceiling, never evidence.
    pub disclosure: DisclosureClass,
    /// Independent privacy handling; purged material caps the candidate regardless of disclosure.
    pub privacy: PrivacyHandling,
    /// Digests of the governing temporal records; support and claim temporals bind here by digest.
    pub temporal_digests: BTreeSet<String>,
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

/// Collected support handles, results, and grade assignments.
type BoundSupport = (
    BTreeSet<ArtifactId>,
    Vec<SupportResult>,
    Vec<GradeAssignment>,
);

/// Canonical digest shape of a candidate, excluding the frozen digest field
/// and the verifier: the verifier vouches for the frozen bytes, so binding
/// a run never rewrites the digest it vouches for.
#[derive(Serialize)]
struct CandidateDigestShape<'a> {
    candidate_kind: &'a CandidateKind,
    proposition: &'a PropositionId,
    revision: &'a TaskRevision,
    request_id: &'a RequestId,
    operation_id: &'a OperationId,
    idempotency_key: &'a str,
    work_scope: &'a WorkScope,
    predecessor: &'a Option<PredecessorId>,
    task_id: &'a TaskId,
    attempt_id: &'a str,
    scope: &'a str,
    window_start_ms: &'a Option<i64>,
    window_end_ms: &'a Option<i64>,
    version: &'a str,
    precision: &'a str,
    fence: &'a StateFence,
    manifest: &'a ManifestId,
    claims: &'a [ClaimEntry],
    claim_map_digest: &'a str,
    coverage_digest: &'a str,
    conflict_digests: &'a BTreeSet<String>,
    support: &'a [SupportRecord],
    unknowns: &'a BTreeSet<String>,
    grade: &'a GradeAssignment,
    authority: &'a EvidenceAuthority,
    disclosure: &'a DisclosureClass,
    privacy: &'a PrivacyHandling,
    temporal_digests: &'a BTreeSet<String>,
    proof_digest: &'a str,
    rivals: &'a BTreeSet<String>,
    proposed_assertability: &'a PositionAssertability,
    invalidation: &'a Option<InvalidationRecord>,
}
/// Named constructor arguments for [`EpistemicPositionCandidate::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct EpistemicPositionCandidateParams {
    pub proposition: PropositionId,
    pub revision: TaskRevision,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub work_scope: WorkScope,
    pub predecessor: Option<PredecessorId>,
    pub task_id: TaskId,
    pub attempt_id: String,
    pub scope: String,
    pub window_start_ms: Option<i64>,
    pub window_end_ms: Option<i64>,
    pub version: String,
    pub precision: String,
    pub fence: StateFence,
    pub manifest: ManifestId,
    pub claims: Vec<ClaimEntry>,
    pub claim_map: Option<ClaimMap>,
    pub coverage_digest: String,
    pub conflict_digests: BTreeSet<String>,
    pub support: Vec<SupportRecord>,
    pub unknowns: BTreeSet<String>,
    pub grade: GradeAssignment,
    pub authority: EvidenceAuthority,
    pub disclosure: DisclosureClass,
    pub privacy: PrivacyHandling,
    pub temporal_digests: BTreeSet<String>,
    pub verifier: Option<RequiredVerifier>,
    pub proof_digest: String,
    pub rivals: BTreeSet<String>,
    pub proposed_assertability: PositionAssertability,
    pub invalidation: Option<InvalidationRecord>,
}
/// Checked wire mirror of [`EpistemicPositionCandidate`]: deserialization validates the full shape.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct EpistemicPositionCandidateWire {
    candidate_kind: CandidateKind,
    proposition: PropositionId,
    revision: TaskRevision,
    request_id: RequestId,
    operation_id: OperationId,
    idempotency_key: String,
    work_scope: WorkScope,
    predecessor: Option<PredecessorId>,
    task_id: TaskId,
    attempt_id: String,
    scope: String,
    window_start_ms: Option<i64>,
    window_end_ms: Option<i64>,
    version: String,
    precision: String,
    fence: StateFence,
    manifest: ManifestId,
    claims: Vec<ClaimEntry>,
    claim_map_digest: String,
    coverage_digest: String,
    conflict_digests: BTreeSet<String>,
    support: Vec<SupportRecord>,
    unknowns: BTreeSet<String>,
    grade: GradeAssignment,
    authority: EvidenceAuthority,
    disclosure: DisclosureClass,
    privacy: PrivacyHandling,
    temporal_digests: BTreeSet<String>,
    verifier: Option<RequiredVerifier>,
    proof_digest: String,
    rivals: BTreeSet<String>,
    proposed_assertability: PositionAssertability,
    invalidation: Option<InvalidationRecord>,
    digest: String,
}
impl TryFrom<EpistemicPositionCandidateWire> for EpistemicPositionCandidate {
    type Error = ContractError;
    // `new` needs the governing map object, so the wire builds the record and runs `validate` directly.
    fn try_from(wire: EpistemicPositionCandidateWire) -> Result<Self, ContractError> {
        let candidate = Self {
            candidate_kind: wire.candidate_kind,
            proposition: wire.proposition,
            revision: wire.revision,
            request_id: wire.request_id,
            operation_id: wire.operation_id,
            idempotency_key: wire.idempotency_key,
            work_scope: wire.work_scope,
            predecessor: wire.predecessor,
            task_id: wire.task_id,
            attempt_id: wire.attempt_id,
            scope: wire.scope,
            window_start_ms: wire.window_start_ms,
            window_end_ms: wire.window_end_ms,
            version: wire.version,
            precision: wire.precision,
            fence: wire.fence,
            manifest: wire.manifest,
            claims: wire.claims,
            claim_map_digest: wire.claim_map_digest,
            coverage_digest: wire.coverage_digest,
            conflict_digests: wire.conflict_digests,
            support: wire.support,
            unknowns: wire.unknowns,
            grade: wire.grade,
            authority: wire.authority,
            disclosure: wire.disclosure,
            privacy: wire.privacy,
            temporal_digests: wire.temporal_digests,
            verifier: wire.verifier,
            proof_digest: wire.proof_digest,
            rivals: wire.rivals,
            proposed_assertability: wire.proposed_assertability,
            invalidation: wire.invalidation,
            digest: wire.digest,
        };
        candidate.validate()?;
        Ok(candidate)
    }
}
impl EpistemicPositionCandidate {
    /// Constructs a candidate and freezes its canonical digest (shape closure
    /// only; the closed ceiling needs
    /// [`EpistemicPositionCandidate::validate_closed`]).
    pub fn new(params: EpistemicPositionCandidateParams) -> Result<Self, ContractError> {
        let claim_map_digest = match &params.claim_map {
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
            proposition: params.proposition,
            revision: params.revision,
            request_id: params.request_id,
            operation_id: params.operation_id,
            idempotency_key: params.idempotency_key,
            work_scope: params.work_scope,
            predecessor: params.predecessor,
            task_id: params.task_id,
            attempt_id: params.attempt_id,
            scope: params.scope,
            window_start_ms: params.window_start_ms,
            window_end_ms: params.window_end_ms,
            version: params.version,
            precision: params.precision,
            fence: params.fence,
            manifest: params.manifest,
            claims: params.claims,
            claim_map_digest,
            coverage_digest: params.coverage_digest,
            conflict_digests: params.conflict_digests,
            support: params.support,
            unknowns: params.unknowns,
            grade: params.grade,
            authority: params.authority,
            disclosure: params.disclosure,
            privacy: params.privacy,
            temporal_digests: params.temporal_digests,
            verifier: params.verifier,
            proof_digest: params.proof_digest,
            rivals: params.rivals,
            proposed_assertability: params.proposed_assertability,
            invalidation: params.invalidation,
            digest: String::new(),
        };
        candidate.validate_shape()?;
        candidate.digest = candidate.compute_digest()?;
        Ok(candidate)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&CandidateDigestShape {
            candidate_kind: &self.candidate_kind,
            proposition: &self.proposition,
            revision: &self.revision,
            request_id: &self.request_id,
            operation_id: &self.operation_id,
            idempotency_key: self.idempotency_key.as_str(),
            work_scope: &self.work_scope,
            predecessor: &self.predecessor,
            task_id: &self.task_id,
            attempt_id: self.attempt_id.as_str(),
            scope: self.scope.as_str(),
            window_start_ms: &self.window_start_ms,
            window_end_ms: &self.window_end_ms,
            version: self.version.as_str(),
            precision: self.precision.as_str(),
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
            privacy: &self.privacy,
            temporal_digests: &self.temporal_digests,
            proof_digest: self.proof_digest.as_str(),
            rivals: &self.rivals,
            proposed_assertability: &self.proposed_assertability,
            invalidation: &self.invalidation,
        })
    }
    /// Collects support handles, results, and grades bound by proposition, never claim ID.
    fn bound_support(&self) -> Result<BoundSupport, ContractError> {
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
        let mut grades = Vec::with_capacity(self.support.len());
        for record in &self.support {
            record.validate_for(&self.task_id, &self.scope, &self.fence)?;
            if record.proposition != self.proposition {
                return Err(ContractError::ScopeMismatch {
                    field: "candidate.proposition",
                });
            }
            handles.extend(record.handles.iter().cloned());
            results.push(record.result);
            grades.push(record.grade.clone());
        }
        Ok((handles, results, grades))
    }
    /// Validates the predecessor/invalidation history chain.
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
        self.check_claims_shape()?;
        let (_, support_results, _) = self.bound_support()?;
        self.check_ceiling_shape(&support_results)?;
        self.check_history()?;
        Ok(())
    }
    fn check_claims_shape(&self) -> Result<(), ContractError> {
        if self.candidate_kind != CandidateKind::EpistemicPositionCandidate {
            return Err(ContractError::ImpossibleCombination {
                field: "candidate.candidate_kind",
            });
        }
        validate_bounded_text(&self.attempt_id, "candidate.attempt_id", MAX_SHORT_TEXT)?;
        let field = "candidate.idempotency_key";
        validate_bounded_text(&self.idempotency_key, field, MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "candidate.scope", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.version, "candidate.version", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.precision, "candidate.precision", MAX_SHORT_TEXT)?;
        if let (Some(start), Some(end)) = (self.window_start_ms, self.window_end_ms)
            && end < start
        {
            return Err(ContractError::InvertedInterval {
                field: "candidate.window",
            });
        }
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "candidate.work_scope",
            })?;
        if self.work_scope.scope_id.as_str() != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.work_scope",
            });
        }
        if !self.work_scope.state_fence.is_compatible_with(&self.fence)
            || !self.fence.is_compatible_with(&self.work_scope.state_fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "candidate.work_scope",
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
        Ok(())
    }
    fn check_ceiling_shape(&self, support_results: &[SupportResult]) -> Result<(), ContractError> {
        if self.unknowns.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.unknowns",
            });
        }
        for unknown in &self.unknowns {
            validate_bounded_text(unknown.as_str(), "candidate.unknowns", MAX_SHORT_TEXT)?;
        }
        if self.temporal_digests.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "candidate.temporal_digests",
            });
        }
        for temporal_digest in &self.temporal_digests {
            validate_digest(temporal_digest.as_str(), "candidate.temporal_digests")?;
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
        // Open assertability treats coverage as incomplete.
        PositionAssertability::check_closed(
            self.proposed_assertability,
            (&self.grade, self.authority),
            support_results,
            false,
            !self.conflict_digests.is_empty(),
            true,
            (self.disclosure, self.privacy, self.verifier.as_ref()),
        )?;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "candidate.digest")
    }
    /// Closes the candidate against request, denominator, receipt, map, and slices.
    pub fn validate_closed(
        &self,
        inputs: (
            &PositionRequest,
            &CoverageDenominator,
            &CoverageReceipt,
            &ClaimMap,
        ),
        slices: (&[ConflictSet], &[AssumptionRecord], &[TemporalRecord]),
    ) -> Result<(), ContractError> {
        let (request, denominator, receipt, map) = inputs;
        let (conflicts, assumptions, temporals) = slices;
        self.validate()?;
        Self::validate_closed_inputs(request, denominator, receipt, map)?;
        for conflict in conflicts {
            conflict.validate()?;
        }
        for assumption in assumptions {
            assumption.validate()?;
        }
        for temporal in temporals {
            temporal.validate()?;
        }
        let (support_handles, support_results, support_grades) = self.bound_support()?;
        self.check_request_binding(request, &support_handles)?;
        let coverage_complete = self.check_coverage_binding(denominator, receipt)?;
        self.check_validity_binding(request, denominator)?;
        self.check_map_binding(map, &support_handles, assumptions, conflicts)?;
        self.check_temporal_binding(temporals)?;
        self.check_grade_binding(map, &support_grades)?;
        let conflict_open = self.check_conflict_binding(conflicts)?;
        if let Some(verifier) = &self.verifier {
            verifier.validate_for(self.digest.as_str())?;
        }
        PositionAssertability::check_closed(
            self.proposed_assertability,
            (&self.grade, self.authority),
            &support_results,
            coverage_complete,
            conflict_open,
            true,
            (self.disclosure, self.privacy, self.verifier.as_ref()),
        )?;
        Ok(())
    }
    fn validate_closed_inputs(
        request: &PositionRequest,
        denominator: &CoverageDenominator,
        receipt: &CoverageReceipt,
        map: &ClaimMap,
    ) -> Result<(), ContractError> {
        request.validate()?;
        denominator.validate()?;
        receipt.validate()?;
        map.validate()
    }
    /// Binds request identity, work scope, task, attempt, scope, proposition,
    /// revision, validity, and fence; every support handle is request-admitted.
    fn check_request_binding(
        &self,
        request: &PositionRequest,
        support_handles: &BTreeSet<ArtifactId>,
    ) -> Result<(), ContractError> {
        if request.request_id != self.request_id {
            return Err(ContractError::TaskMismatch {
                field: "candidate.request_id",
            });
        }
        if request.operation_id != self.operation_id {
            let field = "candidate.operation";
            return Err(ContractError::OutsideManifest { field });
        }
        if request.idempotency_key != self.idempotency_key {
            let field = "candidate.idempotency_key";
            return Err(ContractError::TaskMismatch { field });
        }
        if request.work_scope != self.work_scope {
            return Err(ContractError::ScopeMismatch {
                field: "candidate.work_scope",
            });
        }
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
    /// Derives closed completeness from a complete denominator plus an all-terminal receipt.
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
        check_receipt_query_frontier(
            denominator,
            receipt,
            "candidate.coverage",
            "candidate.coverage",
        )?;
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
        check_member_roles(receipt, denominator, "candidate.coverage")?;
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
    /// Candidate window, version, and precision shared by every validity check.
    fn candidate_window(&self) -> (Option<i64>, Option<i64>) {
        (self.window_start_ms, self.window_end_ms)
    }
    /// Binds validity across request, denominator, and every support record
    /// (same scope/version, containing window, no finer precision).
    fn check_validity_binding(
        &self,
        request: &PositionRequest,
        denominator: &CoverageDenominator,
    ) -> Result<(), ContractError> {
        let window = self.candidate_window();
        if !request.validity.covers_candidate(
            self.scope.as_str(),
            window,
            self.version.as_str(),
            self.precision.as_str(),
        ) {
            return Err(ContractError::StaleContext {
                field: "candidate.validity",
            });
        }
        if !denominator.validity.covers_candidate(
            self.scope.as_str(),
            window,
            self.version.as_str(),
            self.precision.as_str(),
        ) {
            return Err(ContractError::StaleContext {
                field: "candidate.validity",
            });
        }
        for record in &self.support {
            if !record.validity.covers_candidate(
                self.scope.as_str(),
                window,
                self.version.as_str(),
                self.precision.as_str(),
            ) {
                return Err(ContractError::CeilingViolation {
                    field: "candidate.validity",
                });
            }
        }
        Ok(())
    }
    /// Binds every support and claim temporal value to a governing digest by exact set equality.
    fn check_temporal_binding(&self, temporals: &[TemporalRecord]) -> Result<(), ContractError> {
        let mut provided = BTreeSet::new();
        for temporal in temporals {
            provided.insert(shape_digest(temporal)?);
        }
        if provided != self.temporal_digests {
            if !self.temporal_digests.is_subset(&provided) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.temporal_digests",
                });
            }
            return Err(ContractError::MissingReference {
                field: "candidate.temporal_digests",
            });
        }
        for record in &self.support {
            if let Some(temporal) = &record.temporal
                && !self.temporal_digests.contains(&shape_digest(temporal)?)
            {
                return Err(ContractError::MissingReference {
                    field: "candidate.temporal",
                });
            }
        }
        for entry in &self.claims {
            if let Some(temporal) = &entry.temporal
                && !self.temporal_digests.contains(&shape_digest(temporal)?)
            {
                return Err(ContractError::MissingReference {
                    field: "candidate.temporal",
                });
            }
        }
        Ok(())
    }
    /// Caps the candidate grade by the map weakest and every support assignment.
    fn check_grade_binding(
        &self,
        map: &ClaimMap,
        support_grades: &[GradeAssignment],
    ) -> Result<(), ContractError> {
        let map_weakest = map.weakest_assignment()?;
        let support_weakest = GradeAssignment::weakest(support_grades)?;
        for weakest in [&map_weakest, &support_weakest] {
            match (weakest.known_grade(), self.grade.known_grade()) {
                (None, Some(_)) => {
                    return Err(ContractError::CeilingViolation {
                        field: "candidate.grade",
                    });
                }
                (Some(floor), Some(claimed)) if claimed.rank() > floor.rank() => {
                    return Err(ContractError::CeilingViolation {
                        field: "candidate.grade",
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
    /// Binds the governing claim map: same digest and manifest, exact ID coincidence, by-value entries.
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
        // No extra records: every provided assumption is named by an entered claim.
        let named: BTreeSet<&str> = self
            .claims
            .iter()
            .flat_map(|entry| entry.assumptions.iter().map(String::as_str))
            .collect();
        for record in assumptions {
            if !named.contains(record.assumption_id.as_str()) {
                return Err(ContractError::OutsideManifest {
                    field: "candidate.assumptions",
                });
            }
        }
        Ok(())
    }
    /// Caps one entered claim by the weakest grade over its referenced support records: the ceiling is
    /// per-claim from that claim's handles, never the map-wide aggregate.
    fn check_claim_grade(&self, entry: &ClaimEntry) -> Result<(), ContractError> {
        let referenced: Vec<GradeAssignment> = self
            .support
            .iter()
            .filter(|record| {
                let handles = &record.handles;
                handles.iter().any(|handle| entry.support.contains(handle))
            })
            .map(|record| record.grade.clone())
            .collect();
        if referenced.is_empty() {
            return Ok(());
        }
        let floor = GradeAssignment::weakest(&referenced)?;
        let over = match (floor.known_grade(), entry.grade.known_grade()) {
            (Some(floor), Some(claimed)) => claimed.rank() > floor.rank(),
            (None, Some(_)) => true,
            _ => false,
        };
        if over {
            let field = "candidate.grade";
            return Err(ContractError::CeilingViolation { field });
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
        // Same ID with changed evidence is a different claim: shapes must equal by value.
        if governed != entry {
            return Err(ContractError::DigestMismatch {
                field: "candidate.claims",
            });
        }
        // Bounds closure: entered bounds must cover the candidate window, version, and precision.
        if !entry.bounds.covers_candidate(
            self.scope.as_str(),
            self.candidate_window(),
            self.version.as_str(),
            self.precision.as_str(),
        ) {
            return Err(ContractError::StaleContext {
                field: "candidate.bounds",
            });
        }
        for handle in &entry.support {
            if !support_handles.contains(handle) {
                return Err(ContractError::MissingReference {
                    field: "candidate.support",
                });
            }
        }
        // Counterevidence closure: every preserved counter handle resolves against the closed support set.
        for handle in &entry.counterevidence {
            if !support_handles.contains(handle) {
                let field = "candidate.counterevidence";
                return Err(ContractError::MissingReference { field });
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
            let Some(record) = assumptions
                .iter()
                .find(|record| record.assumption_id.as_str() == assumption.as_str())
            else {
                return Err(ContractError::MissingReference {
                    field: "candidate.assumptions",
                });
            };
            // Exact closure: the named record must hold in this task, scope, and fence.
            record.validate_for(&self.task_id, self.scope.as_str(), &self.fence)?;
            // Assumption closure: record bounds must cover the candidate window, version, precision.
            if !record.bounds.covers_candidate(
                self.scope.as_str(),
                self.candidate_window(),
                self.version.as_str(),
                self.precision.as_str(),
            ) {
                let field = "candidate.assumptions";
                return Err(ContractError::StaleContext { field });
            }
        }
        self.check_claim_grade(entry)?;
        if let Some(conflict) = &entry.conflict
            && !conflicts
                .iter()
                .any(|set| set.digest.as_str() == conflict.as_str())
        {
            return Err(ContractError::MissingReference {
                field: "candidate.conflicts",
            });
        }
        Ok(())
    }
    /// Binds claimed conflicts exactly to the provided sets and reports openness.
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
        Ok(conflicts.iter().any(|conflict| !conflict.is_closed()))
    }
}
