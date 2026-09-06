//! Work-unit case coverage for the epistemic contracts boundary: one substantive test per
//! assignment case through the public constructors; each negative mutates one load-bearing property.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, OperationId, ProductId, ReceiptId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EvidenceAuthority, EvidenceFreshness, VerificationBinding};
use eliot_receipts::{WorkScope, WorkScopeId};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::absence::AbsenceClaimParams;
use crate::absence::{AbsenceClaim, BoundedProof, OwnerLookup};
use crate::admitted::{
    AdmittedKind, AdmittedReceipt, AdmittedReceiptParams, ChallengeInvariant, ContractChallenge,
    CurrentEpistemicPosition, CurrentEpistemicPositionView, Currentness, PositionId,
    PositionRevision, PositionState,
};
use crate::assertability::PositionAssertability;
use crate::assumption::{
    AssumptionKind, AssumptionRecord, AssumptionRecordParams, AssumptionRetraction,
};
use crate::candidate::EpistemicPositionCandidateParams;
use crate::candidate::{CandidateKind, EpistemicPositionCandidate};
use crate::causal::CausalClaimParams;
use crate::causal::{CausalClaim, CausalStatus};
use crate::claim_map::ClaimEntryParams;
use crate::claim_map::{ClaimAuditOutcome, ClaimEntry, ClaimMap, ClaimVerdict, DependenceGroup};
use crate::conflict::ConflictSetParams;
use crate::conflict::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
};
use crate::coverage::{
    CoverageDenominator, CoverageDenominatorParams, DenominatorKind, ExclusionReason,
    ExclusionRecord, FrontierRevision, FrontierSpec, PaginationBounds, QueryRevision, QuerySpec,
    SnapshotRef,
};
use crate::error::{ContractError, MAX_HANDLES, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, shape_digest};
use crate::grade::{EvidenceGrade, GRADE_ORDER, GradeAssignment};
use crate::identity::{
    ClaimId, EvidenceSetId, IdentityBundle, IdentityBundleParams, LineageRootId, ManifestId,
    PredecessorId, PropositionId, SourceRevisionId, TransformedLineage, ValidityId,
};
use crate::investigation::{
    InvestigationKind, InvestigationRequirement, InvestigationRequirementParams, RequirementKind,
};
use crate::provenance::{
    ProvenanceClosure, ProvenanceClosureKind, ProvenanceClosureParams, SourceLineage,
};
use crate::receipt::{
    CoverageReceipt, CoverageReceiptParams, MemberDisposition, MemberOutcome, OmittedMember,
    check_member_roles,
};
use crate::request::{PositionRequest, PositionRequestParams, RequestKind};
use crate::support::{
    Precision, SupportRecord, SupportRecordParams, SupportResult, ValidityBounds, weakest_link,
};
use crate::temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
use crate::transition::EpistemicTransitionParams;
use crate::transition::{
    EpistemicTransition, InvalidationKind, InvalidationRecord, SupportDelta, TransitionTrigger,
};
use crate::verifier::{
    DisclosureClass, PrivacyHandling, RequiredVerifier, SourceAssurance, VerifierStanding,
};
// Short fixture spellings shared by the ceiling and role tests below.
use ClaimVerdict::Rejected;
use DisclosureClass::{Open, Quarantined, Restricted};
use EvidenceAuthority::{DeterministicRuntimeTest, ModelInterpretation as Model};
use EvidenceGrade as Grade;
use EvidenceGrade::{Corroborated, Grounded, Orienting, ScienceGrade};
use PositionAssertability::{HypothesisCandidate, MaterialEffect, ObservedFact};
use PositionAssertability::{PlanningOnly, QualifiedInference};
use SupportResult::{Contradicted, Partial, Supported, Unsupported};

type CaseResult = Result<(), ContractError>;

// Asserts exact variant-plus-field equality in one line via `assert_eq!`.
macro_rules! expect_err {
    ($result:expr, $variant:ident, $field:expr) => {
        assert_eq!($result, Err(ContractError::$variant { field: $field }))
    };
}
fn pick_set<T: Clone>(take: bool, full: BTreeSet<T>, empty: BTreeSet<T>) -> BTreeSet<T> {
    if take { full } else { empty }
}
fn member_outcome(
    member: &str,
    disposition: MemberDisposition,
) -> Result<MemberOutcome, ContractError> {
    MemberOutcome::new(artifact(member)?, "primary", disposition)
}
fn parse<T: DeserializeOwned>(wire: &str) -> Result<T, ContractError> {
    serde_json::from_str(wire).map_err(|_| ContractError::Canonicalization)
}
fn case_error(field: &'static str) -> ContractError {
    ContractError::Blank { field }
}
fn case_fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
fn artifact(value: &str) -> Result<ArtifactId, ContractError> {
    ArtifactId::new(value).map_err(|_| case_error("case.artifact"))
}
fn source(value: &str) -> Result<SourceId, ContractError> {
    SourceId::new(value).map_err(|_| case_error("case.source"))
}
fn task() -> Result<TaskId, ContractError> {
    TaskId::new("task-580").map_err(|_| case_error("case.task"))
}
fn case_bounds(
    scope: &str,
    window: (Option<i64>, Option<i64>),
    version: &str,
    prec: &str,
) -> Result<ValidityBounds, ContractError> {
    ValidityBounds::new(scope, window.0, window.1, version, Precision(prec.into()))
}
fn case_frontier() -> Result<FrontierSpec, ContractError> {
    FrontierSpec::new("frontier-1", FrontierRevision("frontier-rev".to_owned()))
}
fn case_work_scope() -> Result<WorkScope, ContractError> {
    Ok(WorkScope {
        scope_id: WorkScopeId::new("scope-580").map_err(|_| case_error("case.scope"))?,
        product_id: ProductId::new("product-580").map_err(|_| case_error("case.product"))?,
        resource_generation: ResourceGeneration::genesis(),
        state_fence: case_fence(),
    })
}
fn encoded<T: Serialize>(value: &T) -> Result<String, ContractError> {
    serde_json::to_string(value).map_err(|_| ContractError::Canonicalization)
}
fn wires<T: Serialize>(values: &[T]) -> Result<Vec<String>, ContractError> {
    values.iter().map(encoded).collect()
}
// Asserts the exact frozen wire spellings of one vocabulary in join order.
fn assert_wires<T: Serialize>(values: &[T], expected: &str) -> CaseResult {
    assert_eq!(wires(values)?.join(","), expected);
    Ok(())
}
fn case_assurance(proof: String) -> Result<SourceAssurance, ContractError> {
    SourceAssurance::new(source("source-a")?, SourceRevisionId::new("r1")?, proof)
}
fn support_with(
    result: SupportResult,
    handles: BTreeSet<ArtifactId>,
    reopen: Option<String>,
    assurance: Option<SourceAssurance>,
) -> Result<SupportRecord, ContractError> {
    SupportRecord::new(SupportRecordParams {
        proposition: PropositionId::new("proposition-580")?,
        result,
        handles,
        validity: case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?,
        grade: GradeAssignment::known(EvidenceGrade::Grounded),
        task_id: task()?,
        fence: case_fence(),
        temporal: None,
        assurance,
        reopen_reason: reopen,
        proof_digest: sha256_hex("proof-support".as_bytes()),
    })
}
fn denominator_params() -> Result<CoverageDenominatorParams, ContractError> {
    Ok(CoverageDenominatorParams {
        class: "source-record".to_owned(),
        schema: "schema-1".to_owned(),
        revision: "rev-1".to_owned(),
        scope: "scope-580".to_owned(),
        fence: case_fence(),
        members: BTreeSet::from([artifact("member-1")?, artifact("member-2")?]),
        roles: BTreeSet::from(["primary".to_owned()]),
        query: Some(QuerySpec::new(
            "query-text",
            QueryRevision("query-rev".to_owned()),
        )?),
        frontier: Some(case_frontier()?),
        snapshot: SnapshotRef::new("snapshot-1", source("owner-1")?)?,
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, 2, 2, false)?,
        validity: case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?,
        kind: DenominatorKind::CompleteScope,
    })
}
fn denominator() -> Result<CoverageDenominator, ContractError> {
    CoverageDenominator::new(denominator_params()?)
}
fn receipt_with(
    denominator_digest: String,
    size: Option<u64>,
    members: Option<Vec<MemberOutcome>>,
    omissions: Option<Vec<OmittedMember>>,
) -> Result<CoverageReceipt, ContractError> {
    // One param-defaults form: omitted size/members/omissions follow the standard observed pair.
    CoverageReceipt::new(CoverageReceiptParams {
        query: QuerySpec::new("query-text", QueryRevision("query-rev".to_owned()))?,
        frontier: FrontierSpec::new("frontier-1", FrontierRevision("frontier-rev".to_owned()))?,
        denominator: denominator_digest,
        denominator_size: size.unwrap_or(2),
        task_id: task()?,
        scope: "scope-580".to_owned(),
        fence: case_fence(),
        policy: "policy-1".to_owned(),
        groups: BTreeSet::from(["group-1".to_owned()]),
        members: members.unwrap_or(vec![
            member_outcome("member-1", MemberDisposition::Observed)?,
            member_outcome("member-2", MemberDisposition::AuthoritativeAbsence)?,
        ]),
        omissions: omissions.unwrap_or_default(),
        proof_digest: sha256_hex("proof-receipt".as_bytes()),
    })
}
fn absence_params(frozen_digest: String) -> Result<AbsenceClaimParams, ContractError> {
    let query = QuerySpec::new("query-text", QueryRevision("query-rev".to_owned()))?;
    let owner = source("owner-1")?;
    let lookup_proof = OwnerLookup::expected_proof(
        &owner,
        frozen_digest.as_str(),
        sha256_hex("proof-receipt".as_bytes()).as_str(),
    )?;
    Ok(AbsenceClaimParams {
        proposition: PropositionId::new("proposition-580")?,
        domain: "source-record".to_owned(),
        schema: "schema-1".to_owned(),
        scope: "scope-580".to_owned(),
        window_start_ms: Some(100),
        window_end_ms: Some(200),
        version: "v1".to_owned(),
        task_id: task()?,
        policy: "policy-1".to_owned(),
        owner_lookup: OwnerLookup::new(owner, lookup_proof)?,
        denominator_digest: frozen_digest.clone(),
        denominator_kind: DenominatorKind::CompleteScope,
        query_digest: shape_digest(&query)?,
        snapshot_id: "snapshot-1".to_owned(),
        receipt: receipt_with(frozen_digest, None, None, None)?,
        proof: BoundedProof::new(sha256_hex("proof-absence".as_bytes()), 64)?,
    })
}
fn absence_with(
    frozen_digest: String,
    receipt: Option<CoverageReceipt>,
    proof_len: u64,
) -> Result<AbsenceClaim, ContractError> {
    // One param-defaults form: an omitted receipt follows the standard observed pair.
    let mut params = absence_params(frozen_digest)?;
    if let Some(receipt) = receipt {
        params.receipt = receipt;
    }
    params.proof = BoundedProof::new(sha256_hex("proof-absence".as_bytes()), proof_len)?;
    AbsenceClaim::new(params)
}
fn claim_entry(
    name: &str,
    verdict: Option<ClaimVerdict>,
    with_counter: bool,
    grade: Option<EvidenceGrade>,
    dependencies: BTreeSet<ClaimId>,
) -> Result<ClaimEntry, ContractError> {
    // One param-defaults form: omitted verdict/grade follow the accepted, grounded shape.
    let verdict = verdict.unwrap_or(ClaimVerdict::Accepted);
    let audit = match verdict {
        ClaimVerdict::Accepted => ClaimAuditOutcome::Supported,
        _ => ClaimAuditOutcome::Contradicted,
    };
    let mut counterevidence = BTreeSet::new();
    if with_counter {
        counterevidence.insert(artifact("counter-1")?);
    }
    ClaimEntry::new(ClaimEntryParams {
        claim: ClaimId::new(name)?,
        statement_digest: sha256_hex(name.as_bytes()),
        verdict,
        audit,
        counterevidence,
        conflict: None,
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        grade: GradeAssignment::known(grade.unwrap_or(EvidenceGrade::Grounded)),
        dependencies,
        bounds: case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?,
        temporal: None,
        coverage_digest: sha256_hex("coverage-claim".as_bytes()),
        support: BTreeSet::from([artifact("handle-1")?]),
        components: BTreeMap::new(),
        unresolved_support: BTreeSet::new(),
        ceiling: grade.unwrap_or(EvidenceGrade::Grounded),
        assumptions: BTreeSet::from(["assumption-1".to_owned()]),
        discriminators: BTreeSet::from(["discriminator-1".to_owned()]),
    })
}
fn try_map(
    admitted: BTreeSet<ClaimId>,
    entries: Vec<ClaimEntry>,
    groups: Vec<DependenceGroup>,
) -> Result<ClaimMap, ContractError> {
    ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        entries,
        groups,
        BTreeSet::new(),
    )
}
fn claim_map() -> Result<ClaimMap, ContractError> {
    try_map(
        BTreeSet::from([ClaimId::new("claim-a")?, ClaimId::new("claim-b")?]),
        vec![
            claim_entry("claim-a", None, false, None, BTreeSet::new())?,
            claim_entry("claim-b", Some(Rejected), false, None, BTreeSet::new())?,
        ],
        vec![DependenceGroup::new(
            "group-1",
            BTreeSet::from([ClaimId::new("claim-a")?]),
            "shared lineage family",
        )?],
    )
}
fn causal_with(mutate: impl FnOnce(&mut CausalClaimParams)) -> Result<CausalClaim, ContractError> {
    // One fixture helper: every other causal argument is fixed; call sites name one axis.
    let proof = sha256_hex("proof-causal".as_bytes());
    let mut params = CausalClaimParams {
        subject: PropositionId::new("proposition-580")?,
        status: CausalStatus::Mechanism,
        mechanism: "mechanism-1".to_owned(),
        rivals: BTreeSet::from(["rival-1".to_owned()]),
        confounders: BTreeSet::from(["confounder-1".to_owned()]),
        evidence_refs: BTreeSet::from([artifact("evidence-1")?]),
        outcome: "outcome-delta-1".to_owned(),
        control: "control-1".to_owned(),
        source: source("source-a")?,
        source_lineage: SourceLineage::new(
            source("source-a")?,
            SourceRevisionId::new("r1")?,
            sha256_hex("content-causal".as_bytes()),
            Some("raw-causal".to_owned()),
            BTreeSet::new(),
            None,
        )?,
        assurance: case_assurance(proof.clone())?,
        lineage: LineageRootId::new("lineage-1")?,
        fence: case_fence(),
        temporal: TemporalRecord::new(10, 11, 12, 13, 14)?,
        proof_digest: proof,
        ceiling: EvidenceGrade::Corroborated,
        scope: "scope-580".to_owned(),
    };
    mutate(&mut params);
    CausalClaim::new(params)
}
fn causal() -> Result<CausalClaim, ContractError> {
    causal_with(|_| {})
}
fn conflict() -> Result<ConflictSet, ContractError> {
    let positions = vec![
        ConflictPosition::new(
            source("source-a")?,
            "stance-a",
            BTreeSet::from(["assumption-p1".to_owned()]),
            BTreeSet::from([artifact("counter-1")?]),
            false,
        )?,
        ConflictPosition::new(
            source("source-b")?,
            "stance-b",
            BTreeSet::new(),
            BTreeSet::new(),
            true,
        )?,
    ];
    ConflictSet::new(ConflictSetParams {
        conflict_id: "conflict-1".to_owned(),
        kind: ConflictKind::Epistemic,
        scope: "scope-580".to_owned(),
        task_id: Some(task()?),
        positions,
        evidence_refs: BTreeSet::from([artifact("evidence-1")?]),
        owners: BTreeSet::from([source("source-a")?, source("source-b")?]),
        common_lineage: BTreeSet::from([LineageRootId::new("lineage-1")?]),
        resolved_parts: BTreeSet::new(),
        unresolved: BTreeSet::from(["open-question-1".to_owned()]),
        unresolved_owners: BTreeSet::from([source("source-b")?]),
        acceptability: ArgumentAcceptability::Contested,
        defeated_refs: BTreeSet::new(),
        probe: Some("probe-1".to_owned()),
        decision_owner: source("source-a")?,
        affected_actions: vec!["action-1".to_owned()],
        lifecycle: ConflictLifecycle::Open,
        receipt_digest: sha256_hex("receipt-conflict".as_bytes()),
    })
}
fn candidate_with(
    claims: Vec<ClaimEntry>,
    map: &ClaimMap,
    digest: String,
) -> Result<EpistemicPositionCandidate, ContractError> {
    // One fixture helper: every other candidate argument is fixed; call sites name one axis.
    let support = support_with(
        Supported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?;
    EpistemicPositionCandidate::new(EpistemicPositionCandidateParams {
        proposition: PropositionId::new("proposition-580")?,
        revision: TaskRevision::genesis(),
        request_id: RequestId::new("request-580").map_err(|_| case_error("case.request"))?,
        operation_id: OperationId::new("operation-580")
            .map_err(|_| case_error("case.operation"))?,
        idempotency_key: "idem-580".to_owned(),
        work_scope: case_work_scope()?,
        predecessor: None,
        task_id: task()?,
        attempt_id: "attempt-580".to_owned(),
        scope: "scope-580".to_owned(),
        window_start_ms: Some(100),
        window_end_ms: Some(200),
        version: "v1".to_owned(),
        precision: "file".to_owned(),
        fence: case_fence(),
        manifest: ManifestId::new("manifest-580")?,
        claims,
        claim_map: Some(map.clone()),
        coverage_digest: digest,
        conflict_digests: BTreeSet::new(),
        support: vec![support],
        unknowns: BTreeSet::new(),
        grade: GradeAssignment::known(EvidenceGrade::Grounded),
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        disclosure: DisclosureClass::Open,
        privacy: PrivacyHandling::Unrestricted,
        temporal_digests: BTreeSet::new(),
        verifier: None,
        proof_digest: sha256_hex("proof-candidate".as_bytes()),
        rivals: BTreeSet::from(["rival-1".to_owned()]),
        proposed_assertability: PositionAssertability::HypothesisCandidate,
        invalidation: None,
    })
}
fn candidate() -> Result<EpistemicPositionCandidate, ContractError> {
    candidate_with(
        vec![
            claim_entry("claim-a", None, false, None, BTreeSet::new())?,
            claim_entry("claim-b", Some(Rejected), false, None, BTreeSet::new())?,
        ],
        &claim_map()?,
        denominator()?.digest.clone(),
    )
}
fn request_with(
    attempt: &str,
    records: BTreeSet<ArtifactId>,
) -> Result<PositionRequest, ContractError> {
    PositionRequest::new(PositionRequestParams {
        question: "question-580".to_owned(),
        request_id: RequestId::new("request-580").map_err(|_| case_error("case.request"))?,
        operation_id: OperationId::new("operation-580")
            .map_err(|_| case_error("case.operation"))?,
        idempotency_key: "idem-580".to_owned(),
        work_scope: case_work_scope()?,
        proposition: PropositionId::new("proposition-580")?,
        task_id: task()?,
        attempt_id: attempt.to_owned(),
        revision: TaskRevision::genesis(),
        scope: "scope-580".to_owned(),
        validity: case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?,
        fence: case_fence(),
        records,
    })
}
fn request() -> Result<PositionRequest, ContractError> {
    request_with("attempt-580", BTreeSet::from([artifact("handle-1")?]))
}
fn assumption_with(id: &str, statement: &str) -> Result<AssumptionRecord, ContractError> {
    AssumptionRecord::new(AssumptionRecordParams {
        assumption_id: id.to_owned(),
        statement: statement.to_owned(),
        origin: "registry-snapshot".to_owned(),
        necessity: "close the world for this read".to_owned(),
        failure_mode: "a stale mirror misstates membership".to_owned(),
        dependents: BTreeSet::new(),
        bounds: case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?,
        holder: source("owner-1")?,
        task_id: task()?,
        fence: case_fence(),
    })
}
fn assumption() -> Result<AssumptionRecord, ContractError> {
    assumption_with("assumption-1", "the registry mirrors the snapshot")
}
fn investigation_with(target: &str) -> Result<InvestigationRequirement, ContractError> {
    InvestigationRequirement::new(InvestigationRequirementParams {
        requirement_id: "requirement-1".to_owned(),
        proposition: PropositionId::new("proposition-580")?,
        scope: "scope-580".to_owned(),
        task_id: task()?,
        fence: case_fence(),
        inquiry: InvestigationKind::ObtainEvidence,
        target: target.to_owned(),
        reason: "no route observed the subject".to_owned(),
    })
}
fn closure() -> Result<ProvenanceClosure, ContractError> {
    ProvenanceClosure::new(ProvenanceClosureParams {
        records: BTreeSet::from([artifact("handle-1")?, artifact("handle-2")?]),
        sources: BTreeSet::from([source("source-a")?]),
        raw_handles: BTreeSet::from(["raw-1".to_owned(), "raw-2".to_owned()]),
        revisions: BTreeSet::from(["r1".to_owned()]),
        lineage: vec![
            SourceLineage::new(
                source("source-a")?,
                SourceRevisionId::new("r1")?,
                sha256_hex("content-a".as_bytes()),
                Some("raw-1".to_owned()),
                BTreeSet::new(),
                None,
            )?,
            SourceLineage::new(
                source("source-a")?,
                SourceRevisionId::new("r1")?,
                sha256_hex("content-b".as_bytes()),
                Some("raw-2".to_owned()),
                BTreeSet::from([sha256_hex("content-a".as_bytes())]),
                None,
            )?,
        ],
        record_origin: BTreeMap::from([
            (artifact("handle-1")?, sha256_hex("content-a".as_bytes())),
            (artifact("handle-2")?, sha256_hex("content-b".as_bytes())),
        ]),
        temporal_digest: None,
        mixed_sources: false,
        assertability: Assertability::NonAssertableUnverified,
        scope: "scope-580".to_owned(),
        fence: case_fence(),
    })
}
fn verifier_with(
    revision: &str,
    freshness: EvidenceFreshness,
) -> Result<RequiredVerifier, ContractError> {
    let contract = ContractId::new("contract-580").map_err(|_| case_error("case.contract"))?;
    let verification = VerificationBinding {
        contract_id: contract.clone(),
        run_id: artifact("run-580")?,
        revision: "r1".to_owned(),
    };
    RequiredVerifier::new(
        contract,
        revision,
        freshness,
        VerifierStanding::Competent,
        None,
        verification,
        sha256_hex("proof-candidate".as_bytes()),
    )
}
fn admitted() -> Result<CurrentEpistemicPosition, ContractError> {
    CurrentEpistemicPosition::new(
        AdmittedReceipt::new(AdmittedReceiptParams {
            receipt_id: ReceiptId::new("receipt-580").map_err(|_| case_error("case.receipt"))?,
            payload_digest: sha256_hex("admission-payload".as_bytes()),
            owner: source("owner-1")?,
            revision: "r1".to_owned(),
            scope: "scope-580".to_owned(),
            fence: case_fence(),
            evidence_digest: sha256_hex("evidence-view".as_bytes()),
            coverage_digest: sha256_hex("coverage-view".as_bytes()),
            conflict_digest: sha256_hex("conflict-view".as_bytes()),
            proof_digest: sha256_hex("proof-view".as_bytes()),
            position: PositionId::new("position-580")?,
            position_revision: PositionRevision::genesis(),
        })?,
        Currentness::Current,
        BTreeSet::new(),
        ClaimId::new("claim-a")?,
    )
}
fn transition_with(
    mutate: impl FnOnce(&mut EpistemicTransitionParams),
) -> Result<EpistemicTransition, ContractError> {
    // One fixture helper: every other transition argument is fixed; call sites name one axis.
    let mut params = EpistemicTransitionParams {
        position: PropositionId::new("proposition-580")?,
        task_id: task()?,
        attempt_id: "attempt-580".to_owned(),
        request_id: RequestId::new("request-580").map_err(|_| case_error("case.request"))?,
        idempotency_key: "idem-580".to_owned(),
        work_scope: case_work_scope()?,
        candidate_digest: sha256_hex("candidate-580".as_bytes()),
        expected_revision: TaskRevision::genesis(),
        expected_fence: case_fence(),
        trigger: TransitionTrigger::NewEvidence,
        evidence_refs: BTreeSet::from([artifact("evidence-1")?]),
        operation: OperationId::new("operation-580").map_err(|_| case_error("case.operation"))?,
        before_support: SupportResult::Partial,
        after_support: SupportResult::Supported,
        before_assertability: PositionAssertability::HypothesisCandidate,
        after_assertability: PositionAssertability::QualifiedInference,
        delta: SupportDelta::new(
            BTreeSet::from([artifact("handle-2")?]),
            BTreeSet::new(),
            BTreeSet::from([artifact("handle-1")?]),
            BTreeSet::from(["fresh observation".to_owned()]),
        )?,
        coverage_delta_digest: sha256_hex("coverage-delta".as_bytes()),
        conflict_delta_digest: sha256_hex("conflict-delta".as_bytes()),
        temporal: None,
        rollback: "revert to predecessor".to_owned(),
        repair: None,
        invalidation: None,
        proof_digest: sha256_hex("proof-transition".as_bytes()),
    };
    mutate(&mut params);
    EpistemicTransition::new(params)
}
fn transition() -> Result<EpistemicTransition, ContractError> {
    transition_with(|_| {})
}
fn identity_bundle() -> Result<IdentityBundle, ContractError> {
    IdentityBundle::new(IdentityBundleParams {
        proposition: PropositionId::new("proposition-580")?,
        claim: ClaimId::new("claim-580")?,
        evidence_set: EvidenceSetId::new("evidence-set-580")?,
        manifest: ManifestId::new("manifest-580")?,
        source_revision: SourceRevisionId::new("revision-580")?,
        lineage_root: LineageRootId::new("lineage-580")?,
        validity: ValidityId::new("validity-580")?,
        predecessors: BTreeSet::new(),
    })
}
// WORK_UNIT_CASE: 580/1
#[test]
fn golden_grade_names_and_order() {
    assert_eq!(
        GRADE_ORDER,
        [
            EvidenceGrade::Orienting,
            EvidenceGrade::Grounded,
            EvidenceGrade::Corroborated,
            EvidenceGrade::ScienceGrade,
        ]
    );
    assert_eq!(
        EvidenceGrade::ordered_names(),
        ["ORIENTING", "GROUNDED", "CORROBORATED", "SCIENCE_GRADE"]
    );
    assert!(EvidenceGrade::Orienting.rank() < EvidenceGrade::Grounded.rank());
    assert!(EvidenceGrade::Grounded.rank() < EvidenceGrade::Corroborated.rank());
    assert!(EvidenceGrade::Corroborated.rank() < EvidenceGrade::ScienceGrade.rank());
}
// WORK_UNIT_CASE: 580/2
#[test]
fn support_coverage_completeness_assertability_invalidation_vocabs() -> CaseResult {
    use MemberDisposition as D;
    use PositionAssertability as A;
    let grades = "\"ORIENTING\",\"GROUNDED\",\"CORROBORATED\",\"SCIENCE_GRADE\"";
    assert_wires(&GRADE_ORDER, grades)?;
    assert_wires(
        &[
            Supported,
            Partial,
            Contradicted,
            Unsupported,
            SupportResult::Unknown,
            SupportResult::OutsideManifest,
            SupportResult::Stale,
            SupportResult::Superseded,
            SupportResult::JustifiedNotApplicable,
        ],
        "\"SUPPORTED\",\"PARTIAL\",\"CONTRADICTED\",\"UNSUPPORTED\",\"UNKNOWN\",\"OUTSIDE_MANIFEST\",\"STALE\",\"SUPERSEDED\",\"JUSTIFIED_NOT_APPLICABLE\"",
    )?;
    assert_wires(
        &[
            DenominatorKind::CompleteScope,
            DenominatorKind::SampledWithMethod,
            DenominatorKind::Unknown,
        ],
        "\"COMPLETE_SCOPE\",\"SAMPLED_WITH_METHOD\",\"UNKNOWN\"",
    )?;
    assert_wires(
        &[
            D::Observed,
            D::AuthoritativeAbsence,
            D::Unavailable,
            D::Blocked,
            D::Stale,
            D::Malformed,
            D::OutOfScope,
            D::PermittedOmission,
            D::Exhaustion,
            D::DependentDuplicate,
            D::Unknown,
        ],
        "\"OBSERVED\",\"AUTHORITATIVE_ABSENCE\",\"UNAVAILABLE\",\"BLOCKED\",\"STALE\",\"MALFORMED\",\"OUT_OF_SCOPE\",\"PERMITTED_OMISSION\",\"EXHAUSTION\",\"DEPENDENT_DUPLICATE\",\"UNKNOWN\"",
    )?;
    assert_wires(
        &[
            A::ObservedFact,
            A::QualifiedInference,
            A::HypothesisCandidate,
            A::ConflictQualificationRequired,
            A::UnknownWithheldQuarantined,
            A::PlanningOnly,
            A::MaterialEffect,
        ],
        "\"OBSERVED_FACT\",\"QUALIFIED_INFERENCE\",\"HYPOTHESIS_CANDIDATE\",\"CONFLICT_QUALIFICATION_REQUIRED\",\"UNKNOWN_WITHHELD_QUARANTINED\",\"PLANNING_ONLY\",\"MATERIAL_EFFECT\"",
    )?;
    assert_wires(
        &[
            InvalidationKind::Superseded,
            InvalidationKind::Withdrawn,
            InvalidationKind::Reopened,
            InvalidationKind::Repaired,
        ],
        "\"SUPERSEDED\",\"WITHDRAWN\",\"REOPENED\",\"REPAIRED\"",
    )?;
    Ok(())
}
// WORK_UNIT_CASE: 580/3
#[test]
fn identity_round_trip() -> CaseResult {
    let bundle = identity_bundle()?;
    bundle.validate()?;
    let encoded_bundle = encoded(&bundle)?;
    let decoded: IdentityBundle = parse(&encoded_bundle)?;
    assert_eq!(bundle, decoded);
    decoded.validate()?;
    let schema = serde_json::to_value(schemars::schema_for!(IdentityBundle))
        .map_err(|_| ContractError::Canonicalization)?;
    assert!(schema.is_object());
    Ok(())
}
// WORK_UNIT_CASE: 580/4
#[test]
fn digest_differs_from_source_identity_and_authority() -> CaseResult {
    let bundle = identity_bundle()?;
    assert_ne!(bundle.digest, bundle.proposition.as_str());
    assert_ne!(bundle.digest, bundle.source_revision.as_str());
    assert_ne!(bundle.digest, bundle.lineage_root.as_str());
    assert_ne!(bundle.digest, bundle.evidence_set.as_str());
    // Authority is a reading, never an identity or digest.
    let authority_wire = encoded(&EvidenceAuthority::DeterministicRuntimeTest)?;
    assert_eq!(authority_wire, "\"DETERMINISTIC_RUNTIME_TEST\"");
    assert_ne!(authority_wire.as_str(), bundle.digest.as_str());
    let source_revision = bundle.source_revision.as_str();
    assert_ne!(source_revision, bundle.lineage_root.as_str());
    let mut other_claim = bundle.clone();
    other_claim.claim = ClaimId::new("claim-other")?;
    other_claim.digest = other_claim.compute_digest()?;
    assert_ne!(bundle.digest, other_claim.digest);
    assert_eq!(bundle.proposition, other_claim.proposition);
    let rival = TransformedLineage::new(
        LineageRootId::new("lineage-580")?,
        SourceRevisionId::new("revision-580")?,
        "normalize",
        SourceRevisionId::new("revision-581")?,
    )?;
    assert_eq!(rival.raw_lineage_root.as_str(), "lineage-580");
    let derived = rival.derived_revision.as_str();
    assert_ne!(derived, rival.raw_source_revision.as_str());
    Ok(())
}
// WORK_UNIT_CASE: 580/5
#[test]
fn transformed_retains_raw_lineage() -> CaseResult {
    let lineage = TransformedLineage::new(
        LineageRootId::new("lineage-raw")?,
        SourceRevisionId::new("revision-raw")?,
        "deduplicate excerpts",
        SourceRevisionId::new("revision-derived")?,
    )?;
    lineage.validate()?;
    assert_eq!(lineage.raw_lineage_root.as_str(), "lineage-raw");
    assert_eq!(lineage.raw_source_revision.as_str(), "revision-raw");
    let restated = TransformedLineage::new(
        LineageRootId::new("lineage-raw")?,
        SourceRevisionId::new("revision-raw")?,
        "restate",
        SourceRevisionId::new("revision-raw")?,
    );
    expect_err!(restated, ImpossibleCombination, "lineage.derived_revision");
    Ok(())
}
// WORK_UNIT_CASE: 580/6
#[test]
fn wrong_task_scope_fence_rejected() -> CaseResult {
    let record = support_with(
        Supported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?;
    let other_task = TaskId::new("task-other").map_err(|_| case_error("case.task"))?;
    let epoch9 = AuthorityEpoch::new(9).map_err(|_| case_error("case.epoch"))?;
    let task_probe = record.validate_for(&other_task, "scope-580", &case_fence());
    expect_err!(task_probe, TaskMismatch, "support.task_id");
    let scope_probe = record.validate_for(&task()?, "scope-other", &case_fence());
    expect_err!(scope_probe, ScopeMismatch, "support.scope");
    let other_fence = StateFence::new(epoch9, ResourceGeneration::genesis());
    let fence_probe = record.validate_for(&task()?, "scope-580", &other_fence);
    expect_err!(fence_probe, FenceMismatch, "support.fence");
    record.validate_for(&task()?, "scope-580", &case_fence())?;
    // Attempt binding: a request is bound to one attempt; retries never share it.
    let inquiry = request()?;
    assert!(inquiry.applies_to(&PropositionId::new("proposition-580")?));
    inquiry.validate_for(&task()?, "attempt-580", "scope-580", &case_fence())?;
    let attempt_probe = inquiry.validate_for(&task()?, "attempt-other", "scope-580", &case_fence());
    expect_err!(attempt_probe, TaskMismatch, "request.attempt_id");
    let task_probe = inquiry.validate_for(&other_task, "attempt-580", "scope-580", &case_fence());
    expect_err!(task_probe, TaskMismatch, "request.task_id");
    let scope_probe = inquiry.validate_for(&task()?, "attempt-580", "scope-other", &case_fence());
    expect_err!(scope_probe, ScopeMismatch, "request.scope");
    let fence_probe = inquiry.validate_for(&task()?, "attempt-580", "scope-580", &other_fence);
    expect_err!(fence_probe, FenceMismatch, "request.fence");
    Ok(())
}
// WORK_UNIT_CASE: 580/7
#[test]
fn unknown_field_variant_and_protected_default_rejected() -> CaseResult {
    let with_unknown = "{\"scope\":\"scope-580\",\"window_start_ms\":null,\"window_end_ms\":null,\"version\":\"v1\",\"precision\":\"file\",\"extra\":1}";
    assert!(serde_json::from_str::<ValidityBounds>(with_unknown).is_err());
    assert!(serde_json::from_str::<SupportResult>("\"SUPPORTISH\"").is_err());
    assert!(serde_json::from_str::<MemberDisposition>("\"PRESENT\"").is_err());
    let missing_scope = "{\"window_start_ms\":null,\"window_end_ms\":null,\"version\":\"v1\",\"precision\":\"file\"}";
    assert!(serde_json::from_str::<ValidityBounds>(missing_scope).is_err());
    let missing_disposition = "{\"member\":\"member-1\"}";
    assert!(serde_json::from_str::<MemberOutcome>(missing_disposition).is_err());
    let missing_role = "{\"member\":\"member-1\",\"disposition\":\"OBSERVED\"}";
    assert!(serde_json::from_str::<MemberOutcome>(missing_role).is_err());
    let minimal_outcome =
        "{\"member\":\"member-1\",\"role\":\"primary\",\"disposition\":\"OBSERVED\"}";
    let outcome: MemberOutcome = parse(minimal_outcome)?;
    assert_eq!(outcome.disposition, MemberDisposition::Observed);
    assert_eq!(outcome.role.as_str(), "primary");
    Ok(())
}
fn assert_short_bound(
    field: &'static str,
    build: &dyn Fn(&str) -> Result<(), ContractError>,
) -> CaseResult {
    let at_max = "x".repeat(MAX_SHORT_TEXT);
    build(at_max.as_str())?;
    let one_over = "x".repeat(MAX_SHORT_TEXT + 1);
    expect_err!(build(one_over.as_str()), TooLong, field);
    Ok(())
}
fn assert_statement_bound() -> CaseResult {
    let statement_max = "x".repeat(MAX_STATEMENT_TEXT);
    assumption_with("assumption-1", statement_max.as_str())?;
    let statement_over = "x".repeat(MAX_STATEMENT_TEXT + 1);
    let overlong = assumption_with("assumption-1", statement_over.as_str());
    expect_err!(overlong, TooLong, "assumption.statement");
    Ok(())
}
// WORK_UNIT_CASE: 580/8
#[test]
fn variable_field_boundaries_and_one_over() -> CaseResult {
    assert_short_bound("support.precision", &|value| {
        case_bounds("scope-580", (None, None), "v1", value).map(|_| ())
    })?;
    assert_short_bound("request.attempt_id", &|value| {
        request_with(value, BTreeSet::from([artifact("handle-1")?])).map(|_| ())
    })?;
    assert_short_bound("investigation.target", &|value| {
        investigation_with(value).map(|_| ())
    })?;
    assert_short_bound("verifier.revision", &|value| {
        verifier_with(value, EvidenceFreshness::ExactCandidate).map(|_| ())
    })?;
    assert_statement_bound()?;
    let mut handles = BTreeSet::new();
    for index in 0..MAX_HANDLES {
        handles.insert(artifact(format!("handle-{index}").as_str())?);
    }
    let full = support_with(Supported, handles, None, None)?;
    full.validate()?;
    let mut overflow = BTreeSet::new();
    for index in 0..=MAX_HANDLES {
        overflow.insert(artifact(format!("overflow-{index}").as_str())?);
    }
    let overflowed = support_with(Supported, overflow, None, None);
    expect_err!(overflowed, TooMany, "support.handles");
    let empty_bounds = PaginationBounds::new(0, 0, 2, false).map(|_| ());
    expect_err!(empty_bounds, OutOfRange, "coverage.limit");
    let control = assumption_with("assumption-1", "a\u{7}b").map(|_| ());
    expect_err!(control, ControlCharacter, "assumption.statement");
    Ok(())
}
// WORK_UNIT_CASE: 580/9
#[test]
fn weakest_ceiling_bounds_grade() -> CaseResult {
    Grade::check_ceiling(Grade::Orienting, Grade::Grounded)?;
    Grade::check_ceiling(Grade::ScienceGrade, Grade::ScienceGrade)?;
    let ceiling = Grade::check_ceiling(Grade::Grounded, Grade::Orienting);
    expect_err!(ceiling, CeilingViolation, "grade.ceiling");
    let science_ceiling = Grade::check_ceiling(Grade::ScienceGrade, Grade::Corroborated);
    expect_err!(science_ceiling, CeilingViolation, "grade.ceiling");
    Ok(())
}
// WORK_UNIT_CASE: 580/10
#[test]
fn dependents_cannot_raise_grade() -> CaseResult {
    Grade::check_dependent(Grade::Corroborated, Grade::Grounded)?;
    Grade::check_dependent(Grade::Grounded, Grade::Grounded)?;
    let dependent = Grade::check_dependent(Grade::Grounded, Grade::Corroborated);
    expect_err!(dependent, CeilingViolation, "grade.dependent");
    Ok(())
}
// WORK_UNIT_CASE: 580/11
#[test]
fn unknown_grade_distinct_from_lowest_known() -> CaseResult {
    let unknown = GradeAssignment::unknown("no inquiry ran")?;
    assert!(unknown.is_unknown());
    assert!(!GradeAssignment::known(EvidenceGrade::Orienting).is_unknown());
    let encoded_unknown = encoded(&unknown)?;
    let encoded_lowest = encoded(&GradeAssignment::known(EvidenceGrade::Orienting))?;
    assert_ne!(encoded_unknown, encoded_lowest);
    let decoded: GradeAssignment = parse(&encoded_unknown)?;
    assert_eq!(decoded, unknown);
    let both = GradeAssignment {
        grade: Some(EvidenceGrade::Grounded),
        unknown_reason: Some("both sides".to_owned()),
    };
    expect_err!(both.validate(), ImpossibleCombination, "grade.assignment");
    let neither = GradeAssignment {
        grade: None,
        unknown_reason: None,
    };
    assert!(neither.validate().is_err());
    Ok(())
}
// WORK_UNIT_CASE: 580/12
#[test]
fn all_support_results_decode() -> CaseResult {
    let results = [
        SupportResult::Supported,
        SupportResult::Partial,
        SupportResult::Contradicted,
        SupportResult::Unsupported,
        SupportResult::Unknown,
        SupportResult::OutsideManifest,
        SupportResult::Stale,
        SupportResult::Superseded,
        SupportResult::JustifiedNotApplicable,
    ];
    assert_eq!(results.len(), 9);
    for result in results {
        let round: SupportResult = parse(&encoded(&result)?)?;
        assert_eq!(round, result);
    }
    let partial = weakest_link(&[Supported, Partial])?;
    assert_eq!(partial, Partial);
    let weakest = weakest_link(&[Supported, Contradicted, Partial])?;
    assert_eq!(weakest, Contradicted);
    Ok(())
}
// WORK_UNIT_CASE: 580/13
#[test]
fn unsupported_valid_is_not_error() -> CaseResult {
    support_with(
        Unsupported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?
    .validate()?;
    support_with(
        Contradicted,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?
    .validate()?;
    support_with(SupportResult::Unknown, BTreeSet::new(), None, None)?.validate()
}
// WORK_UNIT_CASE: 580/14
#[test]
fn handles_preserved_on_support() -> CaseResult {
    let record = support_with(
        Supported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?;
    let decoded: SupportRecord = parse(&encoded(&record)?)?;
    assert_eq!(decoded.handles, record.handles);
    assert!(decoded.handles.contains(&artifact("handle-1")?));
    assert_eq!(encoded(&decoded)?, encoded(&record)?);
    // Source assurance binds the proof to its source.
    let assured = support_with(
        Supported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        Some(case_assurance(sha256_hex("proof-support".as_bytes()))?),
    )?;
    assured.validate()?;
    let mut foreign = assured.clone();
    foreign.assurance = Some(case_assurance(sha256_hex("other-proof".as_bytes()))?);
    expect_err!(foreign.validate(), DigestMismatch, "support.assurance");
    Ok(())
}
// WORK_UNIT_CASE: 580/15
#[test]
fn scope_time_version_precision_mismatch_limits_support() -> CaseResult {
    let bounds = case_bounds("scope-580", (Some(100), Some(200)), "v1", "file")?;
    assert!(bounds.covers("scope-580", Some(150), "v1", "file"));
    assert!(!bounds.covers("scope-other", Some(150), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(50), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(250), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(150), "v2", "file"));
    // Precision participates: `file` covers `file` and coarser, never `symbol`/`line`.
    assert!(!bounds.covers("scope-580", Some(150), "v1", "symbol"));
    assert!(!bounds.covers("scope-580", Some(150), "v1", "line"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "directory"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "package"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "repository"));
    // Unknown precision spellings cover only exact equality.
    let custom = case_bounds("scope-580", (None, None), "v1", "rack-unit")?;
    assert!(custom.covers("scope-580", None, "v1", "rack-unit"));
    assert!(!custom.covers("scope-580", None, "v1", "file"));
    assert!(!bounds.covers("scope-580", None, "v1", "rack-unit"));
    let record = support_with(
        Supported,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?;
    let scope_probe = record.validate_for(&task()?, "scope-other", &case_fence());
    expect_err!(scope_probe, ScopeMismatch, "support.scope");
    let narrowed = case_bounds("scope-580", (Some(100), Some(200)), "v2", "symbol")?;
    assert_ne!(narrowed.version, bounds.version);
    assert_ne!(narrowed.precision, bounds.precision);
    let inverted = case_bounds("scope-580", (Some(200), Some(100)), "v1", "file").map(|_| ());
    expect_err!(inverted, InvertedInterval, "support.window");
    Ok(())
}
// WORK_UNIT_CASE: 580/16
#[test]
fn valid_finite_denominator() -> CaseResult {
    let frozen = denominator()?;
    frozen.validate()?;
    assert_eq!(frozen.members.len(), 2);
    assert_eq!(frozen.kind, DenominatorKind::CompleteScope);
    assert_eq!(frozen.digest, frozen.compute_digest()?);
    let exclusion =
        ExclusionRecord::new("member-9", ExclusionReason("out of scope class".to_owned()))?;
    exclusion.validate()?;
    assert!(ExclusionRecord::new("member-9", ExclusionReason("   ".to_owned())).is_err());
    Ok(())
}
// WORK_UNIT_CASE: 580/17
#[test]
fn vague_denominator_rejected() -> CaseResult {
    use DenominatorKind::CompleteScope;
    let base = denominator()?;
    let mut vague_class = base.clone();
    vague_class.class = "all-relevant".to_owned();
    expect_err!(vague_class.validate(), VagueDenominator, "coverage.class");
    let mut vague_scope = base.clone();
    vague_scope.scope = "*".to_owned();
    expect_err!(vague_scope.validate(), VagueDenominator, "coverage.scope");
    // Known-empty is owned, exact, and bound to its query, frontier, and snapshot.
    let empty = |kind, query, frontier, total| {
        let mut params = denominator_params()?;
        params.kind = kind;
        params.query = query;
        params.frontier = frontier;
        params.members = BTreeSet::new();
        params.roles = BTreeSet::new();
        params.bounds = PaginationBounds::new(0, 1, total, false)?;
        CoverageDenominator::new(params)
    };
    let known_empty = empty(
        DenominatorKind::CompleteScope,
        Some(QuerySpec::new(
            "query-text",
            QueryRevision("query-rev".to_owned()),
        )?),
        Some(case_frontier()?),
        0,
    )?;
    known_empty.validate()?;
    assert!(known_empty.members.is_empty());
    for kind in [DenominatorKind::SampledWithMethod, DenominatorKind::Unknown] {
        let empty_members = empty(kind, None, None, 1);
        expect_err!(empty_members, IncompleteDenominator, "coverage.members");
    }
    let query = QuerySpec::new("query-text", QueryRevision("query-rev".to_owned()))?;
    let incomplete = empty(CompleteScope, Some(query), None, 0);
    expect_err!(incomplete, IncompleteDenominator, "coverage.members");
    // A complete scope is never truncated and its total always equals its enumerated member count.
    let mut truncated = base.clone();
    truncated.bounds = PaginationBounds::new(0, 2, 2, true)?;
    let truncated_check = truncated.validate();
    expect_err!(truncated_check, IncompleteDenominator, "coverage.bounds");
    let mut short = base;
    assert!(short.members.remove(&artifact("member-1")?));
    expect_err!(short.validate(), ArithmeticMismatch, "coverage.bounds");
    Ok(())
}
// WORK_UNIT_CASE: 580/18
#[test]
fn one_disposition_per_member() -> CaseResult {
    use MemberDisposition::{AuthoritativeAbsence, Observed};
    let outcome = member_outcome("member-1", MemberDisposition::Observed)?;
    assert_eq!(encoded(&outcome)?.matches("disposition").count(), 1);
    let frozen = denominator()?;
    let mut duplicated = receipt_with(frozen.digest.clone(), None, None, None)?;
    let stale = member_outcome("member-1", MemberDisposition::Stale)?;
    duplicated.members.push(stale);
    expect_err!(duplicated.validate(), Duplicate, "receipt.members");
    // Role binding against the denominator roles: a foreign role is an extra, an unused role is an omission.
    let standard = receipt_with(frozen.digest.clone(), None, None, None)?;
    check_member_roles(&standard, &frozen, "receipt.role")?;
    let mut foreign_role = receipt_with(frozen.digest.clone(), None, None, None)?;
    foreign_role.members[0].role = "foreign-role".to_owned();
    foreign_role.digest = foreign_role.compute_digest()?;
    let foreign = check_member_roles(&foreign_role, &frozen, "receipt.role");
    expect_err!(foreign, OutsideManifest, "receipt.role");
    let mut role_omitted = denominator()?;
    role_omitted.roles.insert("unused-role".to_owned());
    role_omitted.digest = role_omitted.compute_digest()?;
    let omitted = receipt_with(frozen.digest.clone(), None, None, None)?;
    let roles = check_member_roles(&omitted, &role_omitted, "receipt.role");
    expect_err!(roles, MissingReference, "receipt.role");
    // Exact (member, role) pairs: a shared member under an unrequired role passes shape but fails
    // reconciliation; diagonal receipts keep counts yet miss pairs; duplicate pairs fail in shape.
    let mut shared_member = receipt_with(frozen.digest.clone(), None, None, None)?;
    shared_member.members[1].member = artifact("member-1")?;
    shared_member.members[1].role = "secondary".to_owned();
    shared_member.digest = shared_member.compute_digest()?;
    shared_member.validate()?;
    let shared = check_member_roles(&shared_member, &frozen, "receipt.role");
    expect_err!(shared, OutsideManifest, "receipt.role");
    let mut two_roles = denominator()?;
    two_roles.roles.insert("secondary".to_owned());
    two_roles.digest = two_roles.compute_digest()?;
    let outcomes: Vec<MemberOutcome> = [
        ("member-1", "primary", Observed),
        ("member-1", "secondary", AuthoritativeAbsence),
        ("member-2", "primary", Observed),
        ("member-2", "secondary", AuthoritativeAbsence),
    ]
    .iter()
    .map(|(member, role, disposition)| MemberOutcome::new(artifact(member)?, *role, *disposition))
    .collect::<Result<_, _>>()?;
    let digest = two_roles.digest.clone();
    let full = receipt_with(digest, Some(4), Some(outcomes.clone()), None)?;
    check_member_roles(&full, &two_roles, "receipt.role")?;
    for partial in [
        vec![outcomes[0].clone(), outcomes[3].clone()],
        vec![outcomes[1].clone(), outcomes[2].clone()],
    ] {
        let diagonal = receipt_with(two_roles.digest.clone(), None, Some(partial), None)?;
        let roles = check_member_roles(&diagonal, &two_roles, "receipt.role");
        expect_err!(roles, MissingReference, "receipt.role");
    }
    let pair = vec![outcomes[0].clone(), outcomes[0].clone()];
    let duplicate_pair = receipt_with(two_roles.digest.clone(), None, Some(pair), None);
    expect_err!(duplicate_pair, Duplicate, "receipt.members");
    Ok(())
}
// WORK_UNIT_CASE: 580/19
#[test]
fn coverage_arithmetic_validated() -> CaseResult {
    let frozen = denominator()?;
    receipt_with(frozen.digest.clone(), None, None, None)?.validate()?;
    let observed = member_outcome("member-1", MemberDisposition::Observed)?;
    let omitted = OmittedMember::new(artifact("member-2")?, "duplicate of member-1")?;
    let short = receipt_with(
        frozen.digest.clone(),
        Some(3),
        Some(vec![observed.clone()]),
        Some(vec![omitted.clone()]),
    );
    expect_err!(short, ArithmeticMismatch, "receipt.denominator_size");
    let reconciled = receipt_with(
        frozen.digest.clone(),
        None,
        Some(vec![observed]),
        Some(vec![omitted]),
    )?;
    reconciled.validate()
}
// WORK_UNIT_CASE: 580/20
#[test]
fn all_receipt_dispositions_distinct() -> CaseResult {
    let dispositions = [
        MemberDisposition::Observed,
        MemberDisposition::AuthoritativeAbsence,
        MemberDisposition::Unavailable,
        MemberDisposition::Blocked,
        MemberDisposition::Stale,
        MemberDisposition::Malformed,
        MemberDisposition::OutOfScope,
        MemberDisposition::PermittedOmission,
        MemberDisposition::Exhaustion,
        MemberDisposition::DependentDuplicate,
        MemberDisposition::Unknown,
    ];
    assert_eq!(dispositions.len(), 11);
    let mut names = BTreeSet::new();
    for disposition in dispositions {
        assert!(names.insert(disposition.wire_name()));
        let round: MemberDisposition = serde_json::from_str(&encoded(&disposition)?)
            .map_err(|_| ContractError::Canonicalization)?;
        assert_eq!(round, disposition);
    }
    assert!(MemberDisposition::Observed.is_terminal());
    assert!(MemberDisposition::AuthoritativeAbsence.is_terminal());
    assert!(!MemberDisposition::Exhaustion.is_terminal());
    assert!(!MemberDisposition::Unknown.is_terminal());
    Ok(())
}
// WORK_UNIT_CASE: 580/21
#[test]
fn partial_truncated_unavailable_not_complete_or_known_empty() -> CaseResult {
    let frozen = denominator()?;
    let gapped = receipt_with(
        frozen.digest.clone(),
        None,
        Some(vec![
            member_outcome("member-1", MemberDisposition::Observed)?,
            member_outcome("member-2", MemberDisposition::Unavailable)?,
        ]),
        None,
    )?;
    assert!(!gapped.is_terminal());
    let truncated = PaginationBounds::new(0, 1, 2, true)?;
    assert!(truncated.truncated);
    assert!(PaginationBounds::new(0, 1, 2, false).is_err());
    Ok(())
}
// WORK_UNIT_CASE: 580/22
#[test]
fn valid_absence_claim() -> CaseResult {
    let frozen = denominator()?;
    let claim = absence_with(frozen.digest.clone(), None, 128)?;
    claim.validate()?;
    assert!(claim.receipt.is_terminal());
    claim.validate_closed(&frozen)?;
    let spec = QuerySpec::new("query-text", QueryRevision("query-rev".to_owned()))?;
    let query = shape_digest(&spec)?;
    claim.check_context("scope-580", &case_fence(), query.as_str(), "snapshot-1")
}
fn absence_probe(second: MemberDisposition) -> Result<AbsenceClaim, ContractError> {
    let frozen = denominator()?;
    let receipt = receipt_with(
        frozen.digest.clone(),
        None,
        Some(vec![
            member_outcome("member-1", MemberDisposition::Observed)?,
            member_outcome("member-2", second)?,
        ]),
        None,
    )?;
    absence_with(frozen.digest.clone(), Some(receipt), 64)
}
// WORK_UNIT_CASE: 580/23
#[test]
fn no_match_timeout_silence_exhaustion_not_absence() -> CaseResult {
    let frozen = denominator()?;
    let mut sampled_params = absence_params(frozen.digest.clone())?;
    sampled_params.window_start_ms = None;
    sampled_params.window_end_ms = None;
    sampled_params.denominator_kind = DenominatorKind::SampledWithMethod;
    let sampled = AbsenceClaim::new(sampled_params);
    expect_err!(sampled, IncompleteDenominator, "absence.denominator_kind");
    // Every non-terminal disposition keeps the question open.
    for disposition in [
        MemberDisposition::Unavailable,
        MemberDisposition::Blocked,
        MemberDisposition::Stale,
        MemberDisposition::Malformed,
        MemberDisposition::OutOfScope,
        MemberDisposition::PermittedOmission,
        MemberDisposition::Exhaustion,
        MemberDisposition::DependentDuplicate,
        MemberDisposition::Unknown,
    ] {
        let probe = absence_probe(disposition);
        expect_err!(probe, ImpossibleCombination, "absence.receipt");
    }
    Ok(())
}
// WORK_UNIT_CASE: 580/24
#[test]
fn changed_query_scope_fence_snapshot_invalidates_absence() -> CaseResult {
    let claim = absence_with(denominator()?.digest.clone(), None, 128)?;
    let live_spec = QuerySpec::new("query-text", QueryRevision("query-rev".to_owned()))?;
    let live_query = shape_digest(&live_spec)?;
    let other_query = sha256_hex("other-query".as_bytes());
    let genesis = case_fence();
    let epoch7 = AuthorityEpoch::new(7).map_err(|_| case_error("case.epoch"))?;
    let drifted_fence = StateFence::new(epoch7, ResourceGeneration::genesis());
    let live = live_query.as_str();
    // One drifted axis per row: scope, query, snapshot, and fence each invalidate the claim.
    for (scope, fence, query, snapshot) in [
        ("scope-other", &genesis, live, "snapshot-1"),
        ("scope-580", &genesis, other_query.as_str(), "snapshot-1"),
        ("scope-580", &genesis, live, "snapshot-2"),
        ("scope-580", &drifted_fence, live, "snapshot-1"),
    ] {
        let stale = claim.check_context(scope, fence, query, snapshot);
        expect_err!(stale, StaleContext, "absence.context");
    }
    // Closed binding negatives: each axis fails distinctly against the exact frozen denominator.
    let frozen = denominator()?;
    let valid = absence_with(frozen.digest.clone(), None, 128)?;
    let mut other = denominator()?;
    assert!(other.members.remove(&artifact("member-2")?));
    other.members.insert(artifact("member-9")?);
    other.digest = other.compute_digest()?;
    let unrelated = absence_with(other.digest.clone(), None, 128)?;
    let digest_probe = unrelated.validate_closed(&frozen);
    expect_err!(digest_probe, DigestMismatch, "absence.denominator_digest");
    let mut swapped_query = valid.clone();
    swapped_query.query_digest = sha256_hex("other-query".as_bytes());
    swapped_query.digest = swapped_query.compute_digest()?;
    let query_check = swapped_query.validate_closed(&frozen);
    expect_err!(query_check, DigestMismatch, "absence.query_digest");
    let mut swapped_snapshot = valid.clone();
    swapped_snapshot.snapshot_id = "snapshot-2".to_owned();
    swapped_snapshot.digest = swapped_snapshot.compute_digest()?;
    let snapshot_check = swapped_snapshot.validate_closed(&frozen);
    expect_err!(snapshot_check, StaleContext, "absence.snapshot");
    Ok(())
}
// WORK_UNIT_CASE: 580/25
#[test]
fn valid_claim_map_with_component_coverage() -> CaseResult {
    let map = claim_map()?;
    map.validate()?;
    assert!(map.has_component_coverage());
    assert_eq!(map.entries.len(), 2);
    assert_eq!(map.digest, map.compute_digest()?);
    // Accepted, rejected, countered, and unresolved handle sets validate.
    assert_eq!(map.accepted_ids().len(), 1);
    assert!(map.accepted_ids().contains(&ClaimId::new("claim-a")?));
    assert_eq!(map.rejected_ids().len(), 1);
    assert!(map.rejected_ids().contains(&ClaimId::new("claim-b")?));
    assert!(map.countered_ids().is_empty());
    assert!(map.unresolved.is_empty());
    assert!(map.assumption_names().contains("assumption-1"));
    assert_eq!(map.weakest_grade(), Some(EvidenceGrade::Grounded));
    let decoded: ClaimMap = parse(&encoded(&map)?)?;
    assert_eq!(decoded, map);
    Ok(())
}
// WORK_UNIT_CASE: 580/26
#[test]
fn outside_manifest_rejected() -> CaseResult {
    let admitted = BTreeSet::from([ClaimId::new("claim-a")?]);
    let entries = vec![
        claim_entry("claim-a", None, false, None, BTreeSet::new())?,
        claim_entry("claim-outside", None, false, None, BTreeSet::new())?,
    ];
    let attempt = try_map(admitted, entries, Vec::new());
    expect_err!(attempt, OutsideManifest, "claim.entries");
    // An admitted claim without an entry is unrepresented, not covered.
    let partial_admitted = BTreeSet::from([ClaimId::new("claim-a")?, ClaimId::new("claim-ghost")?]);
    let ghost_entries = vec![claim_entry("claim-a", None, false, None, BTreeSet::new())?];
    let partial = try_map(partial_admitted, ghost_entries, Vec::new());
    expect_err!(partial, MissingReference, "claim.entries");
    Ok(())
}
// WORK_UNIT_CASE: 580/27
#[test]
fn duplicate_and_same_id_changed_rejected() -> CaseResult {
    let admitted = BTreeSet::from([ClaimId::new("claim-a")?]);
    let doubled = vec![
        claim_entry("claim-a", None, false, None, BTreeSet::new())?,
        claim_entry("claim-a", None, false, None, BTreeSet::new())?,
    ];
    let duplicate = try_map(admitted.clone(), doubled, Vec::new());
    expect_err!(duplicate, Duplicate, "claim.entries");
    let changed = try_map(
        admitted,
        vec![
            claim_entry(
                "claim-a",
                Some(ClaimVerdict::Accepted),
                false,
                Some(EvidenceGrade::Grounded),
                BTreeSet::new(),
            )?,
            claim_entry(
                "claim-a",
                Some(ClaimVerdict::Countered),
                true,
                Some(EvidenceGrade::Grounded),
                BTreeSet::new(),
            )?,
        ],
        Vec::new(),
    );
    expect_err!(changed, Duplicate, "claim.entries");
    // An accepted entry with neither handle nor unresolved marker is not component coverage.
    let mut bare = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    bare.support.clear();
    expect_err!(bare.validate(), EmptyCollection, "claim.support");
    Ok(())
}
fn dependent_entry(name: &str, grade: EvidenceGrade) -> Result<ClaimEntry, ContractError> {
    claim_entry(
        name,
        Some(ClaimVerdict::Accepted),
        false,
        Some(grade),
        BTreeSet::from([ClaimId::new("claim-a")?]),
    )
}
// WORK_UNIT_CASE: 580/28
#[test]
fn dependence_groups_explicit() -> CaseResult {
    let map = claim_map()?;
    assert_eq!(map.groups.len(), 1);
    assert!(map.groups[0].members.contains(&ClaimId::new("claim-a")?));
    assert!(DependenceGroup::new("empty-group", BTreeSet::new(), "no members").is_err());
    let admitted = BTreeSet::from([ClaimId::new("claim-a")?]);
    let dangling = BTreeSet::from([ClaimId::new("claim-ghost")?]);
    let mut entry = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    entry.dependencies = dangling;
    let attempt = try_map(admitted, vec![entry], Vec::new());
    expect_err!(attempt, MissingReference, "claim.dependencies");
    // A claim depending on itself names the self-reference, not a missing link.
    let own = BTreeSet::from([ClaimId::new("claim-a")?]);
    let self_dependent = claim_entry("claim-a", None, false, None, own);
    expect_err!(self_dependent, SelfReference, "claim.dependencies");
    // Dependence groups must hold both ends of a dependency edge together.
    let pair_admitted = BTreeSet::from([ClaimId::new("claim-a")?, ClaimId::new("claim-b")?]);
    let lone_members = BTreeSet::from([ClaimId::new("claim-a")?]);
    let lone_group = DependenceGroup::new("group-1", lone_members, "holds only one end")?;
    let uncovered = try_map(
        pair_admitted.clone(),
        vec![
            claim_entry("claim-a", None, false, None, BTreeSet::new())?,
            dependent_entry("claim-b", EvidenceGrade::Grounded)?,
        ],
        vec![lone_group],
    );
    expect_err!(uncovered, MissingReference, "claim.groups");
    // Quoting a claim never upgrades it, even with a covering group.
    let both_members = BTreeSet::from([ClaimId::new("claim-a")?, ClaimId::new("claim-b")?]);
    let full_group = DependenceGroup::new("group-1", both_members, "holds both ends")?;
    let upgraded = try_map(
        pair_admitted,
        vec![
            claim_entry("claim-a", None, false, None, BTreeSet::new())?,
            dependent_entry("claim-b", EvidenceGrade::Corroborated)?,
        ],
        vec![full_group],
    );
    expect_err!(upgraded, CeilingViolation, "grade.dependent");
    Ok(())
}
// WORK_UNIT_CASE: 580/29
#[test]
fn five_temporal_roles_distinct() -> CaseResult {
    let roles = [
        TemporalRole::Event,
        TemporalRole::Effective,
        TemporalRole::Observation,
        TemporalRole::Ingestion,
        TemporalRole::Commit,
    ];
    assert_eq!(
        wires(&roles)?.join(","),
        "\"EVENT\",\"EFFECTIVE\",\"OBSERVATION\",\"INGESTION\",\"COMMIT\""
    );
    let record = TemporalRecord::new(10, 11, 12, 13, 14)?;
    assert_eq!(record.role_time(TemporalRole::Event), 10);
    assert_eq!(record.role_time(TemporalRole::Effective), 11);
    assert_eq!(record.role_time(TemporalRole::Observation), 12);
    assert_eq!(record.role_time(TemporalRole::Ingestion), 13);
    assert_eq!(record.role_time(TemporalRole::Commit), 14);
    assert!(TemporalRecord::new(10, 11, 13, 12, 14).is_err());
    Ok(())
}
// WORK_UNIT_CASE: 580/30
#[test]
fn chrono_corr_dependency_causal_no_cross_decode() -> CaseResult {
    let precedence = TemporalPrecedence::new(10, 20, "clock ordering")?;
    let precedence_json = encoded(&precedence)?;
    assert!(serde_json::from_str::<CausalClaim>(&precedence_json).is_err());
    let causal_json = encoded(&causal()?)?;
    assert!(serde_json::from_str::<TemporalPrecedence>(&causal_json).is_err());
    assert!(!precedence_json.contains("mechanism"));
    assert!(!causal_json.contains("before_ms"));
    // Six-way separation: the six shapes never cross-decode.
    let wires = [
        precedence_json,
        causal_json,
        encoded(&assumption()?)?,
        encoded(&support_with(
            Supported,
            BTreeSet::from([artifact("handle-1")?]),
            None,
            None,
        )?)?,
        encoded(&investigation_with("open-route")?)?,
        encoded(&request()?)?,
    ];
    assert_eq!(wires.len(), 6);
    for (index, wire) in wires.iter().enumerate() {
        if index != 0 {
            assert!(serde_json::from_str::<TemporalPrecedence>(wire).is_err());
        }
        if index != 1 {
            assert!(serde_json::from_str::<CausalClaim>(wire).is_err());
        }
        if index != 2 {
            assert!(serde_json::from_str::<AssumptionRecord>(wire).is_err());
        }
        if index != 3 {
            assert!(serde_json::from_str::<SupportRecord>(wire).is_err());
        }
        if index != 4 {
            assert!(serde_json::from_str::<InvestigationRequirement>(wire).is_err());
        }
        if index != 5 {
            assert!(serde_json::from_str::<PositionRequest>(wire).is_err());
        }
    }
    let association: CausalStatus = parse("\"ASSOCIATION\"")?;
    let correlation: CausalStatus = parse("\"CORRELATION\"")?;
    assert_ne!(association, correlation);
    assert_ne!(correlation, CausalStatus::DependencyPreconditionEnablement);
    let mechanism = CausalStatus::Mechanism;
    assert_ne!(CausalStatus::DependencyPreconditionEnablement, mechanism);
    Ok(())
}
// WORK_UNIT_CASE: 580/31
#[test]
fn causal_needs_mechanism_rivals_evidence() -> CaseResult {
    use CausalStatus::{Association as Assoc, Mechanism as Mech};
    use EvidenceGrade::{Corroborated as Corr, ScienceGrade as Sci};
    const ALL: (bool, bool, bool) = (true, true, true);
    const NO_RIVALS: (bool, bool, bool) = (false, false, true);
    const RIVALS_ONLY: (bool, bool, bool) = (true, false, false);
    const NO_CONF: (bool, bool, bool) = (true, false, true);
    let mechanism = causal()?;
    mechanism.validate()?;
    // Causal fields survive the round-trip.
    let decoded: CausalClaim = parse(&encoded(&mechanism)?)?;
    assert_eq!(decoded, mechanism);
    assert!(decoded.confounders.contains("confounder-1"));
    assert!(decoded.evidence_refs.contains(&artifact("evidence-1")?));
    assert_eq!(decoded.ceiling, EvidenceGrade::Corroborated);
    assert_eq!(CausalStatus::Mechanism.wire_name(), "MECHANISM");
    let mechanism_name = CausalStatus::DependencyPreconditionEnablement.wire_name();
    assert_eq!(mechanism_name, "DEPENDENCY_PRECONDITION_ENABLEMENT");
    let rivals = BTreeSet::from(["rival-1".to_owned()]);
    let confounders = BTreeSet::from(["confounder-1".to_owned()]);
    let evidence_refs = BTreeSet::from([artifact("evidence-1")?]);
    // A dependency reading below science grade validates; science grade never does.
    causal_with(|params| {
        params.status = CausalStatus::DependencyPreconditionEnablement;
        params.mechanism = "enablement sketch".to_owned();
    })?
    .validate()?;
    // One axis per row: rivals, confounders, refs, mechanism, ceiling each fail distinctly.
    let enable = CausalStatus::DependencyPreconditionEnablement;
    let no_names: BTreeSet<String> = BTreeSet::new();
    let no_refs: BTreeSet<ArtifactId> = BTreeSet::new();
    for (status, mechanism, flags, ceiling, field) in [
        (enable, "enablement sketch", ALL, Sci, "causal.ceiling"),
        (Mech, "mechanism-1", NO_RIVALS, Corr, "causal.rivals"),
        (Mech, "mechanism-1", RIVALS_ONLY, Corr, "causal.confounders"),
        (Mech, "mechanism-1", ALL, Sci, "causal.ceiling"),
        (Assoc, "sketch", NO_CONF, Corr, "causal.ceiling"),
    ] {
        let attempt = causal_with(|params| {
            params.status = status;
            params.mechanism = mechanism.to_owned();
            params.rivals = pick_set(flags.0, rivals.clone(), no_names.clone());
            params.confounders = pick_set(flags.1, confounders.clone(), no_names.clone());
            params.evidence_refs = pick_set(flags.2, evidence_refs.clone(), no_refs.clone());
            params.ceiling = ceiling;
        });
        // Ceiling rows name the ceiling; empty-set rows name their collection.
        let expected = if field == "causal.ceiling" {
            ContractError::CeilingViolation { field }
        } else {
            ContractError::EmptyCollection { field }
        };
        assert_eq!(attempt.map(|_| ()), Err(expected));
    }
    let blank = causal_with(|params| {
        params.mechanism = "   ".to_owned();
        params.confounders = no_names.clone();
    });
    assert!(blank.is_err());
    // Frozen source provenance: mutated revision, content, or owner each fail distinctly.
    let mut drifted = causal()?;
    drifted.source_lineage.revision = "r2".to_owned();
    drifted.digest = drifted.compute_digest()?;
    expect_err!(drifted.validate(), StaleContext, "causal.assurance");
    let mut recut = causal()?;
    recut.source_lineage.content_digest = sha256_hex("content-other".as_bytes());
    expect_err!(recut.validate(), DigestMismatch, "causal.digest");
    let mut swapped = causal()?;
    swapped.source_lineage.owner = source("source-b")?;
    expect_err!(swapped.validate(), OutsideManifest, "causal.source");
    Ok(())
}
// WORK_UNIT_CASE: 580/32
#[test]
fn conflict_set_preserves_all_positions() -> CaseResult {
    let set = conflict()?;
    set.validate()?;
    let decoded: ConflictSet = parse(&encoded(&set)?)?;
    assert_eq!(decoded.positions.len(), 2);
    assert_eq!(decoded.positions[0].source, source("source-a")?);
    assert!(decoded.positions[1].minority);
    let counter = artifact("counter-1")?;
    assert!(decoded.positions[0].counters.contains(&counter));
    assert!(decoded.positions[0].assumptions.contains("assumption-p1"));
    let lineage = LineageRootId::new("lineage-1")?;
    assert!(decoded.common_lineage.contains(&lineage));
    assert!(decoded.unresolved_owners.contains(&source("source-b")?));
    assert_eq!(decoded.probe, Some("probe-1".to_owned()));
    assert_eq!(decoded.decision_owner, source("source-a")?);
    assert_eq!(decoded, set);
    Ok(())
}
// WORK_UNIT_CASE: 580/33
#[test]
fn count_recency_confidence_not_resolution() -> CaseResult {
    let set = conflict()?;
    assert!(!set.is_closed());
    let set_json = encoded(&set)?;
    let open = "\"lifecycle\":\"OPEN\"";
    let won = "\"lifecycle\":\"OPEN\",\"winner\":\"source-a\",\"confidence\":0.99";
    assert!(serde_json::from_str::<ConflictSet>(&set_json.replace(open, won)).is_err());
    let mut resolved = set.clone();
    resolved.lifecycle = ConflictLifecycle::Resolved;
    let resolved_check = resolved.validate();
    expect_err!(resolved_check, ImpossibleCombination, "conflict.lifecycle");
    assert_eq!(set.positions.len(), 2);
    Ok(())
}
// WORK_UNIT_CASE: 580/34
#[test]
fn valid_inert_candidate() -> CaseResult {
    let position = candidate()?;
    position.validate()?;
    assert_eq!(position.digest, position.compute_digest()?);
    let expected_kind = CandidateKind::EpistemicPositionCandidate;
    assert_eq!(position.candidate_kind, expected_kind);
    let decoded: EpistemicPositionCandidate = parse(&encoded(&position)?)?;
    assert_eq!(decoded, position);
    // Checked deserialization: `from_str` yields `serde_json::Error`, so pair wire rejection and named `validate` failure.
    let bad_wire = encoded(&position)?.replace("attempt-580", "   ");
    assert!(serde_json::from_str::<EpistemicPositionCandidate>(&bad_wire).is_err());
    let mut blank = position.clone();
    blank.attempt_id = "   ".to_owned();
    expect_err!(blank.validate(), Blank, "candidate.attempt_id");
    // Closed identity: the candidate binds its request, denominator, receipt, map, and assumptions exactly.
    let frozen = denominator()?;
    let receipt = receipt_with(frozen.digest.clone(), None, None, None)?;
    let check =
        |candidate: &EpistemicPositionCandidate, map: &ClaimMap, held: &[AssumptionRecord]| {
            candidate.validate_closed((&request()?, &frozen, &receipt, map), (&[], held, &[]))
        };
    check(&position, &claim_map()?, &[assumption()?])?;
    // A strict subset of the governed claims fails closed validation: exact set equality only.
    let mut subset = position.clone();
    subset.claims = vec![claim_entry("claim-a", None, false, None, BTreeSet::new())?];
    subset.digest = subset.compute_digest()?;
    subset.validate()?;
    let subset_check = check(&subset, &claim_map()?, &[assumption()?]);
    expect_err!(subset_check, MissingReference, "candidate.claims");
    // Same ID with changed evidence fails by value.
    let mut changed = position.clone();
    changed.claims[0] = claim_entry("claim-a", Some(Rejected), false, None, BTreeSet::new())?;
    changed.digest = changed.compute_digest()?;
    let changed_check = check(&changed, &claim_map()?, &[assumption()?]);
    expect_err!(changed_check, DigestMismatch, "candidate.claims");
    // Request binding: the candidate proves which operation and idempotent request it answers.
    let mut foreign_op = position.clone();
    foreign_op.operation_id =
        OperationId::new("operation-other").map_err(|_| case_error("case.operation"))?;
    foreign_op.digest = foreign_op.compute_digest()?;
    let operation_check = check(&foreign_op, &claim_map()?, &[assumption()?]);
    expect_err!(operation_check, OutsideManifest, "candidate.operation");
    let mut foreign_idem = position.clone();
    foreign_idem.idempotency_key = "idem-other".to_owned();
    foreign_idem.digest = foreign_idem.compute_digest()?;
    let idempotency_check = check(&foreign_idem, &claim_map()?, &[assumption()?]);
    expect_err!(idempotency_check, TaskMismatch, "candidate.idempotency_key");
    // Single-claim closure used below: one governed entry, one support record, one named assumption.
    let closed_single = |entry: ClaimEntry, held: &[AssumptionRecord]| {
        let admitted = BTreeSet::from([entry.claim.clone()]);
        let map = try_map(admitted, vec![entry.clone()], Vec::new())?;
        let single = candidate_with(vec![entry], &map, frozen.digest.clone())?;
        single.validate_closed((&request()?, &frozen, &receipt, &map), (&[], held, &[]))
    };
    // Counterevidence closure: a countered claim over a foreign handle fails against the closed support set.
    let entry =
        |verdict, counter, grade| claim_entry("claim-a", verdict, counter, grade, BTreeSet::new());
    let foreign_counter = entry(Some(ClaimVerdict::Countered), true, None)?;
    let counter_check = closed_single(foreign_counter, &[assumption()?]);
    expect_err!(counter_check, MissingReference, "candidate.counterevidence");
    // Per-claim grade ceiling: a corroborated claim over grounded-only support fails, map aggregate aside.
    let overgraded = entry(Some(ClaimVerdict::Accepted), false, Some(Corroborated))?;
    let grade_check = closed_single(overgraded, &[assumption()?]);
    expect_err!(grade_check, CeilingViolation, "candidate.grade");
    // Assumption closure: one negative per load-bearing bound axis (window, version, precision, scope).
    let plain = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    let mut narrowed = assumption()?;
    for bounds in [
        case_bounds("scope-580", (Some(120), Some(180)), "v1", "file")?,
        case_bounds("scope-580", (Some(100), Some(200)), "v2", "file")?,
        case_bounds("scope-580", (Some(100), Some(200)), "v1", "directory")?,
    ] {
        narrowed.bounds = bounds;
        narrowed.digest = narrowed.compute_digest()?;
        let closed_check = closed_single(plain.clone(), &[narrowed.clone()]);
        expect_err!(closed_check, StaleContext, "candidate.assumptions");
    }
    narrowed.bounds = case_bounds("scope-other", (Some(100), Some(200)), "v1", "file")?;
    narrowed.digest = narrowed.compute_digest()?;
    let closed_check = closed_single(plain.clone(), &[narrowed.clone()]);
    expect_err!(closed_check, ScopeMismatch, "assumption.scope");
    // Temporal closure: support and claim temporals bind by digest; a value naming no bound digest fails.
    let mut unbound_support = position.clone();
    unbound_support.support[0].temporal = Some(TemporalRecord::new(10, 11, 12, 13, 14)?);
    unbound_support.digest = unbound_support.compute_digest()?;
    let support_time = check(&unbound_support, &claim_map()?, &[assumption()?]);
    expect_err!(support_time, MissingReference, "candidate.temporal");
    let mut stray = plain.clone();
    stray.temporal = Some(TemporalRecord::new(10, 11, 12, 13, 14)?);
    let stray_check = closed_single(stray, &[assumption()?]);
    expect_err!(stray_check, MissingReference, "candidate.temporal");
    // Withdrawal is mechanical: the retraction names the exact record digest.
    let held = assumption()?;
    let retraction = held.withdraw("mirror rotated")?;
    retraction.validate()?;
    assert_eq!(retraction.assumption_digest.as_str(), held.digest.as_str());
    assert_eq!(retraction.assumption_id.as_str(), "assumption-1");
    Ok(())
}
// WORK_UNIT_CASE: 580/35
#[test]
fn candidate_carries_no_admission_write_effect_finish() -> CaseResult {
    // API-level proof: no admission/write/effect/alloc/apply/resolve/acquire/rank/persist/store/finish/model
    // field exists in the public shape (generic JSON type inferred, never depended on).
    let root = serde_json::to_value(&candidate()?).map_err(|_| ContractError::Canonicalization)?;
    let forbidden = [
        "admission",
        "admission_receipt",
        "write",
        "writes",
        "effect",
        "effects",
        "finish",
        "alloc",
        "allocation",
        "apply",
        "resolve",
        "resolver",
        "acquire",
        "rank",
        "persist",
        "store",
        "model",
    ];
    let mut stack = vec![&root];
    let mut seen = 0;
    while let Some(current) = stack.pop() {
        if let Some(map) = current.as_object() {
            for (key, nested) in map {
                seen += 1;
                let clean = !forbidden.contains(&key.to_lowercase().as_str());
                assert!(clean, "forbidden candidate field present");
                stack.push(nested);
            }
        } else if let Some(items) = current.as_array() {
            stack.extend(items.iter());
        }
    }
    assert!(seen > 0);
    // The top-level field set is exactly the documented contract shape.
    let top = root
        .as_object()
        .map(|map| {
            let mut names: Vec<&str> = map.keys().map(String::as_str).collect();
            names.sort_unstable();
            names
        })
        .ok_or(ContractError::Canonicalization)?;
    assert_eq!(
        top,
        [
            "attempt_id",
            "authority",
            "candidate_kind",
            "claim_map_digest",
            "claims",
            "conflict_digests",
            "coverage_digest",
            "digest",
            "disclosure",
            "fence",
            "grade",
            "idempotency_key",
            "invalidation",
            "manifest",
            "operation_id",
            "precision",
            "predecessor",
            "privacy",
            "proof_digest",
            "proposed_assertability",
            "proposition",
            "request_id",
            "revision",
            "rivals",
            "scope",
            "support",
            "task_id",
            "temporal_digests",
            "unknowns",
            "verifier",
            "version",
            "window_end_ms",
            "window_start_ms",
            "work_scope",
        ]
    );
    // Real-API proof: no admitted-view decode, no envelope, exact request binding.
    let wire = encoded(&candidate()?)?;
    assert!(serde_json::from_str::<CurrentEpistemicPosition>(&wire).is_err());
    let (inquiry, position) = (request()?, candidate()?);
    assert_eq!(position.operation_id, inquiry.operation_id);
    let key = position.idempotency_key.as_str();
    assert_eq!(key, inquiry.idempotency_key.as_str());
    assert_eq!(position.request_id, inquiry.request_id);
    Ok(())
}
// WORK_UNIT_CASE: 580/36
#[test]
fn valid_admitted_view_with_receipt() -> CaseResult {
    let view = admitted()?;
    view.validate()?;
    assert_eq!(view.view_kind, AdmittedKind::CurrentEpistemicPosition);
    assert_eq!(view.receipt_identity(), view.admission.digest.as_str());
    let payload = view.admission.payload_digest.as_str();
    assert_eq!(payload, sha256_hex("admission-payload".as_bytes()).as_str());
    assert_eq!(view.admission.scope.as_str(), "scope-580");
    assert_eq!(view.position_identity().0.as_str(), "position-580");
    assert_eq!(view.position_identity().1, PositionRevision::genesis());
    assert_eq!(PositionRevision::genesis().value(), 1);
    assert!(PositionRevision::new(0).is_err());
    assert_eq!(view.currentness, Currentness::Current);
    let mut superseded = view.clone();
    superseded.currentness = Currentness::Superseded;
    assert!(superseded.validate().is_err());
    // Alias proof: the previous name is the same type, serde, and wire bytes.
    let wire = encoded(&view)?;
    assert!(wire.contains("CURRENT_EPISTEMIC_POSITION"));
    let via_alias: CurrentEpistemicPositionView = parse(&wire)?;
    assert_eq!(via_alias, view);
    assert_eq!(encoded(&via_alias)?, wire);
    // Checked deserialization: `from_str` yields `serde_json::Error`, so pair wire rejection and named `validate` failure.
    let other = sha256_hex("other".as_bytes());
    let bad_wire = wire.replacen(view.digest.as_str(), other.as_str(), 1);
    assert!(serde_json::from_str::<CurrentEpistemicPosition>(&bad_wire).is_err());
    let mut bad_view = view.clone();
    bad_view.digest = sha256_hex("other".as_bytes());
    expect_err!(bad_view.validate(), DigestMismatch, "admitted.digest");
    // Donor-compatible position states round-trip with exact wire names.
    let states = [
        PositionState::Observed,
        PositionState::Supported,
        PositionState::Assumed,
        PositionState::Conflicted,
        PositionState::Stale,
        PositionState::Unknown,
    ];
    let states_wire = "\"OBSERVED\",\"SUPPORTED\",\"ASSUMED\",\"CONFLICTED\",\"STALE\",\"UNKNOWN\"";
    assert_wires(&states, states_wire)?;
    // The closure binds the cited receipt contents exactly.
    let closed = closure()?;
    closed.validate()?;
    let decoded: ProvenanceClosure = parse(&encoded(&closed)?)?;
    assert_eq!(decoded, closed);
    let mut mixed = closed.clone();
    mixed.sources.insert(source("source-b")?);
    mixed.lineage.push(SourceLineage::new(
        source("source-b")?,
        SourceRevisionId::new("r1")?,
        sha256_hex("content-c".as_bytes()),
        Some("raw-3".to_owned()),
        BTreeSet::new(),
        None,
    )?);
    mixed.raw_handles.insert("raw-3".to_owned());
    mixed.digest = mixed.compute_digest()?;
    let check = mixed.validate();
    expect_err!(check, ImpossibleCombination, "provenance.mixed_sources");
    // Relational closure: foreign, unmapped, and dangling references each fail.
    let mut foreign = closed.clone();
    let content_a = sha256_hex("content-a".as_bytes());
    let record_map = &mut foreign.record_origin;
    record_map.insert(artifact("handle-9")?, content_a);
    foreign.digest = foreign.compute_digest()?;
    let foreign_check = foreign.validate();
    expect_err!(foreign_check, OutsideManifest, "provenance.record_origin");
    let mut unmapped = closed.clone();
    unmapped.records.insert(artifact("handle-9")?);
    unmapped.digest = unmapped.compute_digest()?;
    let unmapped_check = unmapped.validate();
    expect_err!(unmapped_check, MissingReference, "provenance.record_origin");
    let mut dangling = closed.clone();
    let content_nine = sha256_hex("content-9".as_bytes());
    let record_map = &mut dangling.record_origin;
    record_map.insert(artifact("handle-1")?, content_nine);
    dangling.digest = dangling.compute_digest()?;
    let dangling_check = dangling.validate();
    expect_err!(dangling_check, MissingReference, "provenance.record_origin");
    // Receipt identity binds receipt-id plus owner; existence is challenged, never claimed.
    assert_eq!(view.admission.receipt_id.as_str(), "receipt-580");
    let missing_id =
        serde_json::to_value(&view.admission).map_err(|_| ContractError::Canonicalization)?;
    let raw_wire = missing_id.to_string();
    let tampered = raw_wire.replace("\"receipt_id\"", "\"no_receipt_id\"");
    assert!(serde_json::from_str::<AdmittedReceipt>(&tampered).is_err());
    let challenge = view.admission.existence_challenge()?;
    challenge.validate()?;
    assert_eq!(challenge.sub_item.as_str(), "admitted.existence");
    assert_eq!(challenge.missing_owner.as_str(), "owner-1");
    assert!(!challenge.missing_api.is_empty());
    assert!(!challenge.missing_invariant.is_empty());
    assert!(!challenge.future_work.is_empty());
    let decoded_challenge: ContractChallenge = parse(&encoded(&challenge)?)?;
    assert_eq!(decoded_challenge, challenge);
    Ok(())
}
// WORK_UNIT_CASE: 580/37
#[test]
fn candidate_admitted_no_cross_decode() -> CaseResult {
    let candidate_json = encoded(&candidate()?)?;
    let view_json = encoded(&admitted()?)?;
    assert!(serde_json::from_str::<CurrentEpistemicPosition>(&candidate_json).is_err());
    assert!(serde_json::from_str::<EpistemicPositionCandidate>(&view_json).is_err());
    assert!(serde_json::from_str::<CurrentEpistemicPositionView>(&candidate_json).is_err());
    assert!(candidate_json.contains("EPISTEMIC_POSITION_CANDIDATE"));
    assert!(view_json.contains("CURRENT_EPISTEMIC_POSITION"));
    assert!(!view_json.contains("CURRENT_EPISTEMIC_POSITION_VIEW"));
    Ok(())
}
fn closed_full(
    claimed: PositionAssertability,
    grade: EvidenceGrade,
    disclosure: DisclosureClass,
    verifier: Option<&RequiredVerifier>,
) -> CaseResult {
    // Short form for the common all-supported, complete-coverage ceiling probe.
    PositionAssertability::check_closed(
        claimed,
        (
            &GradeAssignment::known(grade),
            EvidenceAuthority::DeterministicRuntimeTest,
        ),
        &[SupportResult::Supported],
        true,
        false,
        true,
        (disclosure, PrivacyHandling::Unrestricted, verifier),
    )
}
fn support_ceilings() -> CaseResult {
    let cap = |support: &[SupportResult]| PositionAssertability::support_cap(support);
    // Support ceilings: partial caps at qualified inference, weaker results at hypothesis candidate.
    assert_eq!(cap(&[Supported])?, PositionAssertability::MaterialEffect);
    assert_eq!(cap(&[Supported, Partial])?, QualifiedInference);
    for result in [
        SupportResult::Unknown,
        SupportResult::Stale,
        SupportResult::OutsideManifest,
        SupportResult::Contradicted,
        SupportResult::Unsupported,
        SupportResult::Superseded,
    ] {
        assert_eq!(cap(&[Supported, result])?, HypothesisCandidate);
    }
    assert!(PositionAssertability::support_cap(&[]).is_err());
    for (claimed, support) in [
        (ObservedFact, &[Partial][..]),
        (QualifiedInference, &[SupportResult::Unknown][..]),
    ] {
        let probe = PositionAssertability::check_closed(
            claimed,
            (
                &GradeAssignment::known(Corroborated),
                EvidenceAuthority::DeterministicRuntimeTest,
            ),
            support,
            true,
            false,
            true,
            (Open, PrivacyHandling::Unrestricted, None),
        );
        expect_err!(probe, CeilingViolation, "assertability.support");
    }
    Ok(())
}
fn disclosure_ceilings() -> CaseResult {
    // Disclosure ceilings: restricted caps at qualified inference; quarantined renders only quarantined unknown.
    let verifier = verifier_with("r1", EvidenceFreshness::ExactCandidate)?;
    let probe = closed_full(ObservedFact, ScienceGrade, Restricted, Some(&verifier));
    expect_err!(probe, CeilingViolation, "assertability.disclosure");
    let probe = PositionAssertability::check_closed(
        HypothesisCandidate,
        (
            &GradeAssignment::known(Grounded),
            EvidenceAuthority::DeterministicRuntimeTest,
        ),
        &[Supported],
        false,
        false,
        true,
        (Quarantined, PrivacyHandling::Unrestricted, None),
    );
    expect_err!(probe, CeilingViolation, "assertability.disclosure");
    Ok(())
}
fn verifier_ceilings() -> CaseResult {
    // Verifier ceiling: material effect needs a competent verifier over current freshness.
    let probe = closed_full(MaterialEffect, ScienceGrade, Open, None);
    expect_err!(probe, CeilingViolation, "assertability.verifier");
    let verifier = verifier_with("r1", EvidenceFreshness::ExactCandidate)?;
    closed_full(MaterialEffect, ScienceGrade, Open, Some(&verifier))?;
    let older = verifier_with("r1", EvidenceFreshness::KnownOlderSnapshot)?;
    assert!(!older.is_current());
    assert!(!older.is_competent());
    let probe = closed_full(MaterialEffect, ScienceGrade, Open, Some(&older));
    expect_err!(probe, CeilingViolation, "assertability.verifier");
    Ok(())
}
// WORK_UNIT_CASE: 580/38
#[test]
fn assertability_capped_by_ceilings() -> CaseResult {
    let runtime = DeterministicRuntimeTest;
    PositionAssertability::check(QualifiedInference, Grounded, runtime, true, false, true)?;
    let grade = PositionAssertability::check(MaterialEffect, Grounded, runtime, true, false, true);
    expect_err!(grade, CeilingViolation, "assertability.grade");
    let ceiling =
        PositionAssertability::check(ObservedFact, ScienceGrade, Model, true, false, true);
    expect_err!(ceiling, CeilingViolation, "assertability.ceiling");
    expect_err!(
        PositionAssertability::check(ObservedFact, Corroborated, runtime, false, false, true),
        CeilingViolation,
        "assertability.ceiling"
    );
    support_ceilings()?;
    disclosure_ceilings()?;
    verifier_ceilings()
}
// WORK_UNIT_CASE: 580/39
#[test]
fn planning_grants_no_effect() -> CaseResult {
    let runtime = DeterministicRuntimeTest;
    let ceiling = PositionAssertability::ceiling_for(Orienting, runtime, true, false, true);
    assert_eq!(ceiling, PlanningOnly);
    PositionAssertability::check(PlanningOnly, Orienting, runtime, true, false, true)?;
    let capped =
        PositionAssertability::check(MaterialEffect, Orienting, runtime, true, false, true);
    expect_err!(capped, CeilingViolation, "assertability.grade");
    Ok(())
}
// WORK_UNIT_CASE: 580/40
#[test]
fn transition_preserves_before_after_predecessor() -> CaseResult {
    use InvalidationKind::Superseded;
    let movement = transition()?;
    movement.validate()?;
    assert_eq!(movement.before_support, SupportResult::Partial);
    assert_eq!(movement.after_support, SupportResult::Supported);
    let expected_assertability = PositionAssertability::HypothesisCandidate;
    assert_eq!(movement.before_assertability, expected_assertability);
    let predecessor = PredecessorId::new("predecessor-1")?;
    let invalidation = InvalidationRecord::new(Superseded, "replaced by rerun", predecessor)?;
    let mut with_history = movement.clone();
    with_history.invalidation = Some(invalidation);
    with_history.digest = with_history.compute_digest()?;
    with_history.validate()?;
    let decoded: EpistemicTransition = parse(&encoded(&with_history)?)?;
    let predecessor = decoded
        .invalidation
        .as_ref()
        .map(|record| record.predecessor.as_str());
    assert_eq!(predecessor, Some("predecessor-1"));
    assert_eq!(decoded, with_history);
    // Checked deserialization pairs a wire rejection with the constructor failing named below.
    let bad_wire = encoded(&movement)?.replace("attempt-580", "   ");
    assert!(serde_json::from_str::<EpistemicTransition>(&bad_wire).is_err());
    let mut blank = movement.clone();
    blank.attempt_id = "   ".to_owned();
    expect_err!(blank.validate(), Blank, "transition.attempt_id");
    // Closed binding answers request and candidate with real before/after records.
    let before = vec![support_with(
        Partial,
        BTreeSet::from([artifact("handle-1")?]),
        None,
        None,
    )?];
    let both = BTreeSet::from([artifact("handle-1")?, artifact("handle-2")?]);
    let after = vec![support_with(Supported, both, None, None)?];
    let mut closed_movement = transition()?;
    let digest_check = closed_movement.validate_closed(&request()?, &candidate()?, &before, &after);
    expect_err!(digest_check, DigestMismatch, "transition.candidate_digest");
    closed_movement.candidate_digest = candidate()?.digest.clone();
    closed_movement.evidence_refs = BTreeSet::from([artifact("handle-1")?]);
    closed_movement.digest = closed_movement.compute_digest()?;
    let inquiry = request()?;
    let current = candidate()?;
    closed_movement.validate_closed(&inquiry, &current, &before, &after)?;
    // Candidate revision binding: a candidate from another revision answers another transition.
    let mut drifted_candidate = candidate()?;
    let next = TaskRevision::genesis()
        .next()
        .map_err(|_| case_error("case.revision"))?;
    drifted_candidate.revision = next;
    drifted_candidate.digest = drifted_candidate.compute_digest()?;
    let mut drifted_rev = closed_movement.clone();
    drifted_rev.candidate_digest = drifted_candidate.digest.clone();
    drifted_rev.digest = drifted_rev.compute_digest()?;
    let rev_check = drifted_rev.validate_closed(&inquiry, &drifted_candidate, &before, &after);
    expect_err!(rev_check, StaleContext, "transition.candidate_revision");
    // Fence drift fails at close through the shared work-scope equality chain.
    let epoch9 = AuthorityEpoch::new(9).map_err(|_| case_error("case.epoch"))?;
    let mut drifted_fence = closed_movement.clone();
    drifted_fence.expected_fence = StateFence::new(epoch9, ResourceGeneration::genesis());
    drifted_fence.digest = drifted_fence.compute_digest()?;
    let fence_check = drifted_fence.validate_closed(&inquiry, &current, &before, &after);
    expect_err!(fence_check, FenceMismatch, "transition.work_scope");
    // Candidate fence drift fails the candidate work-scope pin first.
    let mut fenced_candidate = candidate()?;
    fenced_candidate.fence = StateFence::new(epoch9, ResourceGeneration::genesis());
    fenced_candidate.digest = fenced_candidate.compute_digest()?;
    let mut fence_drifted = closed_movement.clone();
    fence_drifted.candidate_digest = fenced_candidate.digest.clone();
    fence_drifted.digest = fence_drifted.compute_digest()?;
    let candidate_fence =
        fence_drifted.validate_closed(&inquiry, &fenced_candidate, &before, &after);
    expect_err!(candidate_fence, FenceMismatch, "candidate.work_scope");
    // Before/after context: foreign records, heady assertability, and unowned temporals fail.
    let mut foreign_task = before.clone();
    foreign_task[0].task_id = TaskId::new("task-other").map_err(|_| case_error("case.task"))?;
    let task_check = closed_movement.validate_closed(&inquiry, &current, &foreign_task, &after);
    expect_err!(task_check, TaskMismatch, "support.task_id");
    // Scope, fence, and proposition axes: foreign-context records are never evidence here.
    let mut foreign_scope = before.clone();
    foreign_scope[0].validity.scope = "scope-other".to_owned();
    foreign_scope[0].validate()?;
    let scope_check = closed_movement.validate_closed(&inquiry, &current, &foreign_scope, &after);
    expect_err!(scope_check, ScopeMismatch, "support.scope");
    let mut foreign_fence = after.clone();
    foreign_fence[0].fence = StateFence::new(epoch9, ResourceGeneration::genesis());
    foreign_fence[0].validate()?;
    let fence = closed_movement.validate_closed(&inquiry, &current, &before, &foreign_fence);
    expect_err!(fence, FenceMismatch, "support.fence");
    let mut foreign_proposition = before.clone();
    foreign_proposition[0].proposition = PropositionId::new("proposition-other")?;
    foreign_proposition[0].validate()?;
    let records = closed_movement.validate_closed(&inquiry, &current, &foreign_proposition, &after);
    expect_err!(records, ScopeMismatch, "transition.records");
    let mut heady_before = closed_movement.clone();
    heady_before.before_assertability = PositionAssertability::MaterialEffect;
    heady_before.digest = heady_before.compute_digest()?;
    let heady = heady_before.validate_closed(&inquiry, &current, &before, &after);
    expect_err!(heady, CeilingViolation, "transition.before_assertability");
    let mut foreign_time = closed_movement.clone();
    foreign_time.temporal = Some(TemporalRecord::new(10, 11, 12, 13, 14)?);
    foreign_time.digest = foreign_time.compute_digest()?;
    let temporal_check = foreign_time.validate_closed(&inquiry, &current, &before, &after);
    expect_err!(temporal_check, MissingReference, "transition.temporal");
    Ok(())
}
// WORK_UNIT_CASE: 580/41
#[test]
fn partial_unknown_not_unconditional_promotion() -> CaseResult {
    let bare = SupportDelta::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::from(["no fresh evidence".to_owned()]),
    )?;
    let partial_promotion = transition_with(|params| {
        params.trigger = TransitionTrigger::Revalidation;
        params.delta = bare.clone();
        params.evidence_refs = BTreeSet::new();
    });
    expect_err!(partial_promotion, CeilingViolation, "transition.promotion");
    let unknown_promotion = transition_with(|params| {
        params.before_support = SupportResult::Unknown;
        params.before_assertability = PositionAssertability::UnknownWithheldQuarantined;
        params.delta = bare;
    });
    expect_err!(unknown_promotion, CeilingViolation, "transition.promotion");
    transition()?.validate()?;
    // Exact partition: misclassified, omitted, and extra handles fail.
    let h1 = BTreeSet::from([artifact("handle-1")?]);
    let h2 = BTreeSet::from([artifact("handle-2")?]);
    let h2b = h2.clone();
    let both = BTreeSet::from([artifact("handle-1")?, artifact("handle-2")?]);
    let reasons = |note: &str| BTreeSet::from([note.to_owned()]);
    let empty: BTreeSet<ArtifactId> = BTreeSet::new();
    let retained = h1.clone();
    let before_rec = support_with(Partial, h1.clone(), None, None)?;
    let after_rec = support_with(Supported, both.clone(), None, None)?;
    let exact = SupportDelta::new(h2b, BTreeSet::new(), retained, reasons("fresh observation"))?;
    let before = std::slice::from_ref(&before_rec);
    let after = std::slice::from_ref(&after_rec);
    EpistemicTransition::reconcile_delta(&exact, before, after)?;
    let two_nine = BTreeSet::from([artifact("handle-2")?, artifact("handle-9")?]);
    for delta in [
        SupportDelta::new(h1.clone(), BTreeSet::new(), h2.clone(), reasons("swap"))?,
        SupportDelta::new(empty.clone(), empty.clone(), h1.clone(), reasons("omit"))?,
        SupportDelta::new(two_nine, BTreeSet::new(), h1.clone(), reasons("extra"))?,
    ] {
        let partition = EpistemicTransition::reconcile_delta(&delta, before, after);
        expect_err!(partition, ArithmeticMismatch, "transition.delta");
    }
    // After-side ceiling: assertability above the after-support cap fails even with all digests recomputed.
    let capped_before = vec![support_with(Partial, h1, None, None)?];
    let capped_after = vec![support_with(Partial, both, None, None)?];
    let mut capped_movement = transition()?;
    capped_movement.after_support = SupportResult::Partial;
    capped_movement.after_assertability = PositionAssertability::MaterialEffect;
    capped_movement.candidate_digest = candidate()?.digest.clone();
    capped_movement.evidence_refs = BTreeSet::from([artifact("handle-1")?]);
    capped_movement.digest = capped_movement.compute_digest()?;
    expect_err!(
        capped_movement.validate_closed(&request()?, &candidate()?, &capped_before, &capped_after),
        CeilingViolation,
        "transition.after_assertability"
    );
    Ok(())
}
// WORK_UNIT_CASE: 580/42
#[test]
fn set_permutation_invariance() -> CaseResult {
    let first_predecessors = BTreeSet::from([
        PredecessorId::new("predecessor-a")?,
        PredecessorId::new("predecessor-b")?,
    ]);
    let second_predecessors = BTreeSet::from([
        PredecessorId::new("predecessor-b")?,
        PredecessorId::new("predecessor-a")?,
    ]);
    let mut first = identity_bundle()?;
    first.predecessors = first_predecessors;
    first.digest = first.compute_digest()?;
    let mut second = first.clone();
    second.predecessors = second_predecessors;
    second.digest = second.compute_digest()?;
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.canonical_json()?, second.canonical_json()?);
    // Order-free relations: insertion order never moves the digest; declaration order never blocks.
    let mut reordered = closure()?;
    reordered.record_origin = BTreeMap::from([
        (artifact("handle-2")?, sha256_hex("content-b".as_bytes())),
        (artifact("handle-1")?, sha256_hex("content-a".as_bytes())),
    ]);
    reordered.digest = reordered.compute_digest()?;
    assert_eq!(reordered.digest, closure()?.digest);
    let mut swapped = closure()?;
    swapped.lineage.reverse();
    swapped.digest = swapped.compute_digest()?;
    swapped.validate()?;
    assert_ne!(swapped.digest, closure()?.digest);
    // Claim component maps are order-free relations too.
    let mut reordered_components = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    reordered_components.components = BTreeMap::from([
        ("zeta".to_owned(), artifact("handle-1")?),
        ("alpha".to_owned(), artifact("handle-1")?),
    ]);
    let mut flipped_components = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    flipped_components.components = BTreeMap::from([
        ("alpha".to_owned(), artifact("handle-1")?),
        ("zeta".to_owned(), artifact("handle-1")?),
    ]);
    flipped_components.validate()?;
    assert_eq!(reordered_components, flipped_components);
    Ok(())
}
// WORK_UNIT_CASE: 580/43
#[test]
fn load_bearing_mutation_invalidates_digest() -> CaseResult {
    let mut bundle = identity_bundle()?;
    bundle.validity = ValidityId::new("validity-changed")?;
    expect_err!(bundle.validate(), DigestMismatch, "identity.digest");
    let mut frozen = denominator()?;
    frozen.revision = "rev-changed".to_owned();
    expect_err!(frozen.validate(), DigestMismatch, "coverage.digest");
    let mut receipt = receipt_with(frozen.compute_digest()?, None, None, None)?;
    receipt.policy = "policy-changed".to_owned();
    expect_err!(receipt.validate(), DigestMismatch, "receipt.digest");
    let mut claim = absence_with(denominator()?.digest.clone(), None, 128)?;
    claim.domain = "domain-changed".to_owned();
    expect_err!(claim.validate(), DigestMismatch, "absence.digest");
    let mut map = claim_map()?;
    map.manifest = ManifestId::new("manifest-changed")?;
    expect_err!(map.validate(), DigestMismatch, "claim.digest");
    let mut set = conflict()?;
    set.scope = "scope-changed".to_owned();
    expect_err!(set.validate(), DigestMismatch, "conflict.digest");
    let mut position = candidate()?;
    position.version = "v2".to_owned();
    expect_err!(position.validate(), DigestMismatch, "candidate.digest");
    let mut view = admitted()?;
    view.admission.scope = "scope-changed".to_owned();
    expect_err!(view.validate(), DigestMismatch, "admitted.digest");
    let mut movement = transition()?;
    movement.rollback = "changed rollback".to_owned();
    expect_err!(movement.validate(), DigestMismatch, "transition.digest");
    // Nested relational mutations attribute to the relation, never the top-level digest.
    let mut origin = closure()?;
    let content_nine = sha256_hex("content-9".as_bytes());
    let record_map = &mut origin.record_origin;
    record_map.insert(artifact("handle-1")?, content_nine);
    origin.digest = origin.compute_digest()?;
    let origin_check = origin.validate();
    expect_err!(origin_check, MissingReference, "provenance.record_origin");
    let mut lineage = causal()?;
    lineage.source_lineage.revision = "r2".to_owned();
    expect_err!(lineage.validate(), StaleContext, "causal.assurance");
    let mut components = claim_entry("claim-a", None, false, None, BTreeSet::new())?;
    components.components = BTreeMap::from([("part".to_owned(), artifact("handle-9")?)]);
    expect_err!(components.validate(), MissingReference, "claim.components");
    let mut role = receipt_with(denominator()?.digest.clone(), None, None, None)?;
    role.members[0].role = "rebound-role".to_owned();
    expect_err!(role.validate(), DigestMismatch, "receipt.digest");
    let mut envelope = admitted()?;
    envelope.admission.receipt_id =
        ReceiptId::new("receipt-other").map_err(|_| case_error("case.receipt"))?;
    expect_err!(envelope.validate(), DigestMismatch, "admitted.digest");
    let mut roles = denominator()?;
    roles.roles.insert("rebound-role".to_owned());
    expect_err!(roles.validate(), DigestMismatch, "coverage.digest");
    Ok(())
}
// WORK_UNIT_CASE: 580/44
#[test]
fn malformed_input_bounded_panic_free() -> CaseResult {
    struct AlwaysFail;
    impl Serialize for AlwaysFail {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("580/44 canonical"))
        }
    }
    // Bounded malformed corpus: every input fails closed on every boundary type, without panicking.
    let corpus = [
        "{\"scope\"",
        "{\"scope\":\"a\u{7}b\",\"window_start_ms\":null,\"window_end_ms\":null,\"version\":\"v1\",\"precision\":\"file\"}",
        "{\"offset\":0,\"limit\":99999999999999999999999,\"total\":2,\"truncated\":true}",
        "\"SUPPORTED \"",
        "\"LIVE\"",
        "\"SUPPORTISH\"",
        "\"PRESENT\"",
        "{\"member\":\"member-1\"}",
        "{\"scope\":\"scope-580\",\"window_start_ms\":null,\"window_end_ms\":null,\"version\":\"v1\",\"precision\":\"file\",\"extra\":1}",
        "not json at all",
        "",
        "null",
        "[]",
        "{\"unknown\":true}",
    ];
    for input in corpus {
        assert!(serde_json::from_str::<SupportResult>(input).is_err());
        assert!(serde_json::from_str::<MemberDisposition>(input).is_err());
        assert!(serde_json::from_str::<ValidityBounds>(input).is_err());
        assert!(serde_json::from_str::<PaginationBounds>(input).is_err());
        assert!(serde_json::from_str::<PositionRequest>(input).is_err());
        assert!(serde_json::from_str::<AssumptionRecord>(input).is_err());
        assert!(serde_json::from_str::<InvestigationRequirement>(input).is_err());
        assert!(serde_json::from_str::<RequiredVerifier>(input).is_err());
    }
    // Full contract matrix: every shape rejects null, arrays, and unknown-only objects.
    macro_rules! malformed {
        ($wire:expr, $($ty:ty),+) => {{ $(assert!(serde_json::from_str::<$ty>($wire).is_err());)+ }};
    }
    for wire in ["null", "[]", "{\"unknown\":true}"] {
        malformed!(wire, IdentityBundle, TransformedLineage, ValidityBounds);
        malformed!(wire, SupportRecord, QuerySpec, FrontierSpec, SnapshotRef);
        malformed!(wire, ExclusionRecord, PaginationBounds, CoverageDenominator);
        malformed!(wire, MemberOutcome, OmittedMember, CoverageReceipt);
        malformed!(wire, OwnerLookup, BoundedProof, AbsenceClaim, ClaimEntry);
        malformed!(wire, DependenceGroup, ClaimMap, TemporalRecord);
        malformed!(wire, TemporalPrecedence, SourceLineage, ProvenanceClosure);
        malformed!(wire, SourceAssurance, RequiredVerifier, PositionRequest);
        malformed!(wire, InvestigationRequirement, AssumptionRecord);
        malformed!(wire, AssumptionRetraction, CausalClaim, ConflictPosition);
        malformed!(wire, ConflictSet, EpistemicPositionCandidate, SupportDelta);
        malformed!(wire, InvalidationRecord, EpistemicTransition);
        malformed!(wire, AdmittedReceipt, ContractChallenge);
        malformed!(wire, CurrentEpistemicPosition, GradeAssignment);
        malformed!(wire, EvidenceGrade, SupportResult, DenominatorKind);
        malformed!(wire, MemberDisposition, PositionAssertability, ClaimVerdict);
        malformed!(wire, ClaimAuditOutcome, TemporalRole, CausalStatus);
        malformed!(wire, ConflictKind, ArgumentAcceptability, ConflictLifecycle);
        malformed!(wire, DisclosureClass, PrivacyHandling, VerifierStanding);
        malformed!(wire, TransitionTrigger, InvalidationKind, PositionState);
        malformed!(wire, Currentness, AdmittedKind, CandidateKind, RequestKind);
        malformed!(wire, AssumptionKind, RequirementKind, ProvenanceClosureKind);
    }
    let owner = SourceId::new("owner-1").map_err(|_| case_error("case.source"))?;
    let outcome = std::panic::catch_unwind(|| {
        let mut failures = 0;
        let absence_proof = sha256_hex("proof-absence".as_bytes());
        failures += usize::from(PaginationBounds::new(0, 0, 2, true).is_err());
        failures += usize::from(PaginationBounds::new(5, 1, 2, true).is_err());
        failures += usize::from(BoundedProof::new(absence_proof, u64::MAX).is_err());
        failures += usize::from(OwnerLookup::new(owner.clone(), "not-a-digest").is_err());
        failures += usize::from(assumption_with("   ", "statement").is_err());
        failures += usize::from(investigation_with("   ").is_err());
        failures += usize::from(request_with("attempt-580", BTreeSet::new()).is_err());
        failures += usize::from(TemporalRecord::new(10, 11, 13, 12, 14).is_err());
        failures += usize::from(GradeAssignment::unknown("   ").is_err());
        failures += usize::from(case_bounds("   ", (None, None), "v1", "file").is_err());
        failures += usize::from(
            ContractChallenge::new(
                "a",
                source("b")?,
                "c",
                ChallengeInvariant("d".to_owned()),
                "   ",
            )
            .is_err(),
        );
        Ok::<usize, ContractError>(failures)
    });
    let failures = outcome.map_err(|_| ContractError::Canonicalization)??;
    assert_eq!(failures, 11);
    let bad_lookup = OwnerLookup::new(owner, "not-a-digest").map(|_| ());
    expect_err!(bad_lookup, InvalidDigest, "absence.lookup_proof");
    assert_eq!(
        crate::error::canonical_bytes(&AlwaysFail),
        Err(ContractError::Canonicalization)
    );
    Ok(())
}
