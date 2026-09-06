//! Work-unit case coverage for the epistemic contracts boundary.
//!
//! One substantive test per assignment case. Fixtures build fully valid
//! records through the public constructors; negative cases mutate exactly one
//! load-bearing property and assert the exact closed error.

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, OperationId, ReceiptId, ResourceGeneration, SourceId,
    StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::{Assertability, EvidenceAuthority, EvidenceFreshness};
use serde::Serialize;

use crate::absence::{AbsenceClaim, BoundedProof, OwnerLookup};
use crate::admitted::{
    AdmittedKind, CurrentEpistemicPosition, CurrentEpistemicPositionView, Currentness,
    PositionState,
};
use crate::assertability::PositionAssertability;
use crate::assumption::AssumptionRecord;
use crate::candidate::{CandidateKind, EpistemicPositionCandidate};
use crate::causal::{CausalClaim, CausalStatus};
use crate::claim_map::{ClaimAuditOutcome, ClaimEntry, ClaimMap, ClaimVerdict, DependenceGroup};
use crate::conflict::{
    ArgumentAcceptability, ConflictKind, ConflictLifecycle, ConflictPosition, ConflictSet,
};
use crate::coverage::{
    CoverageDenominator, DenominatorKind, ExclusionRecord, FrontierSpec, PaginationBounds,
    QuerySpec, SnapshotRef,
};
use crate::error::{ContractError, MAX_HANDLES, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, shape_digest};
use crate::grade::{EvidenceGrade, GRADE_ORDER, GradeAssignment};
use crate::identity::{
    ClaimId, EvidenceSetId, IdentityBundle, LineageRootId, ManifestId, PredecessorId,
    PropositionId, SourceRevisionId, TransformedLineage, ValidityId,
};
use crate::investigation::{InvestigationKind, InvestigationRequirement};
use crate::provenance::ProvenanceClosure;
use crate::receipt::{CoverageReceipt, MemberDisposition, MemberOutcome, OmittedMember};
use crate::request::PositionRequest;
use crate::support::{SupportRecord, SupportResult, ValidityBounds, weakest_link};
use crate::temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
use crate::transition::{
    EpistemicTransition, InvalidationKind, InvalidationRecord, SupportDelta, TransitionTrigger,
};
use crate::verifier::{DisclosureClass, RequiredVerifier, VerifierStanding};

type CaseResult = Result<(), ContractError>;

fn case_error(field: &'static str) -> ContractError {
    ContractError::Blank { field }
}

fn case_digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
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

fn operation() -> Result<OperationId, ContractError> {
    OperationId::new("operation-580").map_err(|_| case_error("case.operation"))
}

fn admission() -> Result<ReceiptId, ContractError> {
    ReceiptId::new("receipt-580").map_err(|_| case_error("case.receipt"))
}

fn prop() -> Result<PropositionId, ContractError> {
    PropositionId::new("proposition-580")
}

fn validity() -> Result<ValidityBounds, ContractError> {
    ValidityBounds::new("scope-580", Some(100), Some(200), "v1", "file")
}

fn encoded<T: Serialize>(value: &T) -> Result<String, ContractError> {
    serde_json::to_string(value).map_err(|_| ContractError::Canonicalization)
}

fn wires<T: Serialize>(values: &[T]) -> Result<Vec<String>, ContractError> {
    values.iter().map(encoded).collect()
}

fn support_record(result: SupportResult) -> Result<SupportRecord, ContractError> {
    let mut handles = BTreeSet::new();
    let handles_required = !matches!(
        result,
        SupportResult::Unknown
            | SupportResult::OutsideManifest
            | SupportResult::JustifiedNotApplicable
    );
    if handles_required {
        handles.insert(artifact("handle-1")?);
    }
    let reopen = if matches!(result, SupportResult::Stale | SupportResult::Superseded) {
        Some("reopen-probe-1".to_owned())
    } else {
        None
    };
    SupportRecord::new(
        prop()?,
        result,
        handles,
        validity()?,
        task()?,
        case_fence(),
        reopen,
        case_digest("proof-support"),
    )
}

fn denominator() -> Result<CoverageDenominator, ContractError> {
    let mut members = BTreeSet::new();
    members.insert(artifact("member-1")?);
    members.insert(artifact("member-2")?);
    let mut roles = BTreeSet::new();
    roles.insert("primary".to_owned());
    CoverageDenominator::new(
        "source-record",
        "schema-1",
        "rev-1",
        "scope-580",
        case_fence(),
        members,
        roles,
        None,
        Some(FrontierSpec::new("frontier-1", "frontier-rev")?),
        SnapshotRef::new("snapshot-1", source("owner-1")?)?,
        Vec::new(),
        PaginationBounds::new(0, 2, 2, false)?,
        validity()?,
        DenominatorKind::CompleteScope,
    )
}

fn frozen_query_digest() -> Result<String, ContractError> {
    shape_digest(&QuerySpec::new("query-text", "query-rev")?)
}

fn receipt_for(denominator_digest: String) -> Result<CoverageReceipt, ContractError> {
    let mut groups = BTreeSet::new();
    groups.insert("group-1".to_owned());
    CoverageReceipt::new(
        QuerySpec::new("query-text", "query-rev")?,
        FrontierSpec::new("frontier-1", "frontier-rev")?,
        denominator_digest,
        2,
        task()?,
        "scope-580",
        case_fence(),
        "policy-1",
        groups,
        vec![
            MemberOutcome::new(artifact("member-1")?, MemberDisposition::Observed),
            MemberOutcome::new(
                artifact("member-2")?,
                MemberDisposition::AuthoritativeAbsence,
            ),
        ],
        Vec::new(),
        case_digest("proof-receipt"),
    )
}

fn absence() -> Result<AbsenceClaim, ContractError> {
    let frozen = denominator()?;
    let frozen_digest = frozen.digest.clone();
    let receipt = receipt_for(frozen_digest.clone())?;
    AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        task()?,
        "policy-1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen_digest,
        DenominatorKind::CompleteScope,
        frozen_query_digest()?,
        "snapshot-1",
        receipt,
        BoundedProof::new(case_digest("proof-absence"), 128)?,
    )
}

fn absence_with_denominator() -> Result<(CoverageDenominator, AbsenceClaim), ContractError> {
    let frozen = denominator()?;
    let frozen_digest = frozen.digest.clone();
    let receipt = receipt_for(frozen_digest.clone())?;
    let claim = AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        task()?,
        "policy-1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen_digest,
        DenominatorKind::CompleteScope,
        frozen_query_digest()?,
        "snapshot-1",
        receipt,
        BoundedProof::new(case_digest("proof-absence"), 128)?,
    )?;
    Ok((frozen, claim))
}

fn claim_entry_with(
    name: &str,
    verdict: ClaimVerdict,
    audit: ClaimAuditOutcome,
    with_counter: bool,
) -> Result<ClaimEntry, ContractError> {
    let mut counterevidence = BTreeSet::new();
    if with_counter {
        counterevidence.insert(artifact("counter-1")?);
    }
    let mut assumptions = BTreeSet::new();
    assumptions.insert("assumption-1".to_owned());
    let mut discriminators = BTreeSet::new();
    discriminators.insert("discriminator-1".to_owned());
    let mut support = BTreeSet::new();
    support.insert(artifact("handle-1")?);
    ClaimEntry::new(
        ClaimId::new(name)?,
        case_digest(name),
        verdict,
        audit,
        counterevidence,
        None,
        EvidenceAuthority::DeterministicRuntimeTest,
        EvidenceGrade::Grounded,
        BTreeSet::new(),
        validity()?,
        case_digest("coverage-claim"),
        support,
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        assumptions,
        discriminators,
    )
}

fn claim_entry(name: &str) -> Result<ClaimEntry, ContractError> {
    claim_entry_with(
        name,
        ClaimVerdict::Accepted,
        ClaimAuditOutcome::Supported,
        false,
    )
}

fn rejected_entry(name: &str) -> Result<ClaimEntry, ContractError> {
    claim_entry_with(
        name,
        ClaimVerdict::Rejected,
        ClaimAuditOutcome::Contradicted,
        false,
    )
}

fn claim_map() -> Result<ClaimMap, ContractError> {
    let mut admitted = BTreeSet::new();
    admitted.insert(ClaimId::new("claim-a")?);
    admitted.insert(ClaimId::new("claim-b")?);
    let mut group_members = BTreeSet::new();
    group_members.insert(ClaimId::new("claim-a")?);
    ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        vec![claim_entry("claim-a")?, rejected_entry("claim-b")?],
        vec![DependenceGroup::new(
            "group-1",
            group_members,
            "shared lineage family",
        )?],
        BTreeSet::new(),
    )
}

fn causal() -> Result<CausalClaim, ContractError> {
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    let mut confounders = BTreeSet::new();
    confounders.insert("confounder-1".to_owned());
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
    CausalClaim::new(
        prop()?,
        CausalStatus::Mechanism,
        "mechanism-1",
        rivals,
        confounders,
        evidence_refs,
        EvidenceGrade::Corroborated,
        "scope-580",
    )
}

fn conflict() -> Result<ConflictSet, ContractError> {
    let mut counters = BTreeSet::new();
    counters.insert(artifact("counter-1")?);
    let mut first_assumptions = BTreeSet::new();
    first_assumptions.insert("assumption-p1".to_owned());
    let positions = vec![
        ConflictPosition::new(
            source("source-a")?,
            "stance-a",
            first_assumptions,
            counters,
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
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
    let mut owners = BTreeSet::new();
    owners.insert(source("source-a")?);
    owners.insert(source("source-b")?);
    let mut lineage = BTreeSet::new();
    lineage.insert(LineageRootId::new("lineage-1")?);
    let mut unresolved = BTreeSet::new();
    unresolved.insert("open-question-1".to_owned());
    let mut unresolved_owners = BTreeSet::new();
    unresolved_owners.insert(source("source-b")?);
    ConflictSet::new(
        "conflict-1",
        ConflictKind::Epistemic,
        "scope-580",
        Some(task()?),
        positions,
        evidence_refs,
        owners,
        lineage,
        BTreeSet::new(),
        unresolved,
        unresolved_owners,
        ArgumentAcceptability::Contested,
        BTreeSet::new(),
        Some("probe-1".to_owned()),
        source("source-a")?,
        vec!["action-1".to_owned()],
        ConflictLifecycle::Open,
        case_digest("receipt-conflict"),
    )
}

fn candidate() -> Result<EpistemicPositionCandidate, ContractError> {
    let map = claim_map()?;
    let frozen = denominator()?;
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    EpistemicPositionCandidate::new(
        prop()?,
        TaskRevision::genesis(),
        None,
        task()?,
        "attempt-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        case_fence(),
        ManifestId::new("manifest-580")?,
        vec![claim_entry("claim-a")?, rejected_entry("claim-b")?],
        Some(&map),
        frozen.digest.clone(),
        BTreeSet::new(),
        vec![support_record(SupportResult::Supported)?],
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        EvidenceAuthority::DeterministicRuntimeTest,
        DisclosureClass::Open,
        None,
        case_digest("proof-candidate"),
        rivals,
        PositionAssertability::HypothesisCandidate,
        None,
    )
}

fn request() -> Result<PositionRequest, ContractError> {
    let mut records = BTreeSet::new();
    records.insert(artifact("handle-1")?);
    PositionRequest::new(
        "question-580",
        prop()?,
        task()?,
        "attempt-580",
        TaskRevision::genesis(),
        "scope-580",
        validity()?,
        case_fence(),
        records,
    )
}

fn assumption() -> Result<AssumptionRecord, ContractError> {
    AssumptionRecord::new(
        "assumption-1",
        "the registry mirrors the snapshot",
        "scope-580",
        source("owner-1")?,
        task()?,
        case_fence(),
    )
}

fn investigation() -> Result<InvestigationRequirement, ContractError> {
    InvestigationRequirement::new(
        "requirement-1",
        prop()?,
        "scope-580",
        task()?,
        case_fence(),
        InvestigationKind::ObtainEvidence,
        "open-route",
        "no route observed the subject",
    )
}

fn closure() -> Result<ProvenanceClosure, ContractError> {
    let mut records = BTreeSet::new();
    records.insert(artifact("handle-1")?);
    let mut sources = BTreeSet::new();
    sources.insert(source("source-a")?);
    let mut raw_handles = BTreeSet::new();
    raw_handles.insert("raw-1".to_owned());
    let mut revisions = BTreeSet::new();
    revisions.insert("r1".to_owned());
    ProvenanceClosure::new(
        records,
        sources,
        raw_handles,
        revisions,
        false,
        Assertability::NonAssertableUnverified,
        "scope-580",
        case_fence(),
    )
}

fn competent_verifier() -> Result<RequiredVerifier, ContractError> {
    let contract = ContractId::new("contract-580").map_err(|_| case_error("case.contract"))?;
    RequiredVerifier::new(
        contract,
        "r1",
        EvidenceFreshness::ExactCandidate,
        VerifierStanding::Competent,
        None,
    )
}

fn admitted() -> Result<CurrentEpistemicPosition, ContractError> {
    CurrentEpistemicPosition::new(
        prop()?,
        TaskRevision::genesis(),
        admission()?,
        case_digest("admission-payload"),
        source("owner-1")?,
        Currentness::Current,
        BTreeSet::new(),
        ClaimId::new("claim-a")?,
        "scope-580",
        case_fence(),
        case_digest("evidence-view"),
        case_digest("coverage-view"),
        case_digest("conflict-view"),
        case_digest("proof-view"),
    )
}

fn transition() -> Result<EpistemicTransition, ContractError> {
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
    let mut added = BTreeSet::new();
    added.insert(artifact("handle-2")?);
    let mut retained = BTreeSet::new();
    retained.insert(artifact("handle-1")?);
    let mut reasons = BTreeSet::new();
    reasons.insert("fresh observation".to_owned());
    EpistemicTransition::new(
        prop()?,
        TaskRevision::genesis(),
        case_fence(),
        TransitionTrigger::NewEvidence,
        evidence_refs,
        operation()?,
        SupportResult::Partial,
        SupportResult::Supported,
        PositionAssertability::HypothesisCandidate,
        PositionAssertability::QualifiedInference,
        SupportDelta::new(added, BTreeSet::new(), retained, reasons)?,
        case_digest("coverage-delta"),
        case_digest("conflict-delta"),
        "revert to predecessor",
        None,
        None,
        case_digest("proof-transition"),
    )
}

fn identity_bundle() -> Result<IdentityBundle, ContractError> {
    IdentityBundle::new(
        prop()?,
        ClaimId::new("claim-580")?,
        EvidenceSetId::new("evidence-set-580")?,
        ManifestId::new("manifest-580")?,
        SourceRevisionId::new("revision-580")?,
        LineageRootId::new("lineage-580")?,
        ValidityId::new("validity-580")?,
        BTreeSet::new(),
    )
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
    assert_eq!(
        wires(&GRADE_ORDER)?.join(","),
        "\"ORIENTING\",\"GROUNDED\",\"CORROBORATED\",\"SCIENCE_GRADE\""
    );
    let support = [
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
    assert_eq!(
        wires(&support)?.join(","),
        "\"SUPPORTED\",\"PARTIAL\",\"CONTRADICTED\",\"UNSUPPORTED\",\"UNKNOWN\",\"OUTSIDE_MANIFEST\",\"STALE\",\"SUPERSEDED\",\"JUSTIFIED_NOT_APPLICABLE\""
    );
    let kinds = [
        DenominatorKind::CompleteScope,
        DenominatorKind::SampledWithMethod,
        DenominatorKind::Unknown,
    ];
    assert_eq!(
        wires(&kinds)?.join(","),
        "\"COMPLETE_SCOPE\",\"SAMPLED_WITH_METHOD\",\"UNKNOWN\""
    );
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
    assert_eq!(
        wires(&dispositions)?.join(","),
        "\"OBSERVED\",\"AUTHORITATIVE_ABSENCE\",\"UNAVAILABLE\",\"BLOCKED\",\"STALE\",\"MALFORMED\",\"OUT_OF_SCOPE\",\"PERMITTED_OMISSION\",\"EXHAUSTION\",\"DEPENDENT_DUPLICATE\",\"UNKNOWN\""
    );
    let assertability = [
        PositionAssertability::ObservedFact,
        PositionAssertability::QualifiedInference,
        PositionAssertability::HypothesisCandidate,
        PositionAssertability::ConflictQualificationRequired,
        PositionAssertability::UnknownWithheldQuarantined,
        PositionAssertability::PlanningOnly,
        PositionAssertability::MaterialEffect,
    ];
    assert_eq!(
        wires(&assertability)?.join(","),
        "\"OBSERVED_FACT\",\"QUALIFIED_INFERENCE\",\"HYPOTHESIS_CANDIDATE\",\"CONFLICT_QUALIFICATION_REQUIRED\",\"UNKNOWN_WITHHELD_QUARANTINED\",\"PLANNING_ONLY\",\"MATERIAL_EFFECT\""
    );
    let invalidations = [
        InvalidationKind::Superseded,
        InvalidationKind::Withdrawn,
        InvalidationKind::Reopened,
        InvalidationKind::Repaired,
    ];
    assert_eq!(
        wires(&invalidations)?.join(","),
        "\"SUPERSEDED\",\"WITHDRAWN\",\"REOPENED\",\"REPAIRED\""
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/3
#[test]
fn identity_round_trip() -> CaseResult {
    let bundle = identity_bundle()?;
    bundle.validate()?;
    let encoded_bundle = encoded(&bundle)?;
    let decoded: IdentityBundle =
        serde_json::from_str(&encoded_bundle).map_err(|_| ContractError::Canonicalization)?;
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
    // Authority is a class of reading, never an identity and never a digest:
    // the authority wire names the reading while the digest covers bytes.
    let authority_wire = encoded(&EvidenceAuthority::DeterministicRuntimeTest)?;
    assert_eq!(authority_wire, "\"DETERMINISTIC_RUNTIME_TEST\"");
    assert_ne!(authority_wire.as_str(), bundle.digest.as_str());
    assert_ne!(
        bundle.source_revision.as_str(),
        bundle.lineage_root.as_str()
    );
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
    assert_ne!(
        rival.derived_revision.as_str(),
        rival.raw_source_revision.as_str()
    );
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
    assert_eq!(
        restated,
        Err(ContractError::ImpossibleCombination {
            field: "lineage.derived_revision",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/6
#[test]
fn wrong_task_scope_fence_rejected() -> CaseResult {
    let record = support_record(SupportResult::Supported)?;
    let other_task = TaskId::new("task-other").map_err(|_| case_error("case.task"))?;
    assert_eq!(
        record.validate_for(&other_task, "scope-580", &case_fence()),
        Err(ContractError::TaskMismatch {
            field: "support.task_id",
        })
    );
    assert_eq!(
        record.validate_for(&task()?, "scope-other", &case_fence()),
        Err(ContractError::ScopeMismatch {
            field: "support.scope",
        })
    );
    let other_fence = StateFence::new(
        AuthorityEpoch::new(9).map_err(|_| case_error("case.epoch"))?,
        ResourceGeneration::genesis(),
    );
    assert_eq!(
        record.validate_for(&task()?, "scope-580", &other_fence),
        Err(ContractError::FenceMismatch {
            field: "support.fence",
        })
    );
    record.validate_for(&task()?, "scope-580", &case_fence())?;
    // Attempt binding: a request is bound to one attempt, and retries never
    // share it. The wrong attempt fails exactly like the wrong task.
    let inquiry = request()?;
    assert!(inquiry.applies_to(&prop()?));
    inquiry.validate_for(&task()?, "attempt-580", "scope-580", &case_fence())?;
    assert_eq!(
        inquiry.validate_for(&task()?, "attempt-other", "scope-580", &case_fence()),
        Err(ContractError::TaskMismatch {
            field: "request.attempt_id",
        })
    );
    assert_eq!(
        inquiry.validate_for(&other_task, "attempt-580", "scope-580", &case_fence()),
        Err(ContractError::TaskMismatch {
            field: "request.task_id",
        })
    );
    assert_eq!(
        inquiry.validate_for(&task()?, "attempt-580", "scope-other", &case_fence()),
        Err(ContractError::ScopeMismatch {
            field: "request.scope",
        })
    );
    assert_eq!(
        inquiry.validate_for(&task()?, "attempt-580", "scope-580", &other_fence),
        Err(ContractError::FenceMismatch {
            field: "request.fence",
        })
    );
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
    let minimal_outcome = "{\"member\":\"member-1\",\"disposition\":\"OBSERVED\"}";
    let outcome: MemberOutcome =
        serde_json::from_str(minimal_outcome).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(outcome.disposition, MemberDisposition::Observed);
    Ok(())
}

fn assert_short_bound(
    field: &'static str,
    build: &dyn Fn(&str) -> Result<(), ContractError>,
) -> CaseResult {
    let at_max = "x".repeat(MAX_SHORT_TEXT);
    build(at_max.as_str())?;
    let one_over = "x".repeat(MAX_SHORT_TEXT + 1);
    assert_eq!(
        build(one_over.as_str()),
        Err(ContractError::TooLong { field })
    );
    Ok(())
}

fn assert_statement_bound() -> CaseResult {
    let statement_max = "x".repeat(MAX_STATEMENT_TEXT);
    AssumptionRecord::new(
        "assumption-1",
        statement_max.as_str(),
        "scope-580",
        source("owner-1")?,
        task()?,
        case_fence(),
    )?;
    let statement_over = "x".repeat(MAX_STATEMENT_TEXT + 1);
    assert_eq!(
        AssumptionRecord::new(
            "assumption-1",
            statement_over.as_str(),
            "scope-580",
            source("owner-1")?,
            task()?,
            case_fence(),
        ),
        Err(ContractError::TooLong {
            field: "assumption.statement",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/8
#[test]
fn variable_field_boundaries_and_one_over() -> CaseResult {
    assert_short_bound("support.precision", &|value| {
        ValidityBounds::new("scope-580", None, None, "v1", value).map(|_| ())
    })?;
    assert_short_bound("request.attempt_id", &|value| {
        let mut records = BTreeSet::new();
        records.insert(artifact("handle-1")?);
        PositionRequest::new(
            "question-580",
            prop()?,
            task()?,
            value,
            TaskRevision::genesis(),
            "scope-580",
            validity()?,
            case_fence(),
            records,
        )
        .map(|_| ())
    })?;
    assert_short_bound("investigation.target", &|value| {
        InvestigationRequirement::new(
            "requirement-1",
            prop()?,
            "scope-580",
            task()?,
            case_fence(),
            InvestigationKind::ObtainEvidence,
            value,
            "reason-1",
        )
        .map(|_| ())
    })?;
    assert_short_bound("verifier.revision", &|value| {
        let contract = ContractId::new("contract-580").map_err(|_| case_error("case.contract"))?;
        RequiredVerifier::new(
            contract,
            value,
            EvidenceFreshness::ExactCandidate,
            VerifierStanding::Competent,
            None,
        )
        .map(|_| ())
    })?;
    assert_statement_bound()?;
    let mut handles = BTreeSet::new();
    for index in 0..MAX_HANDLES {
        handles.insert(artifact(format!("handle-{index}").as_str())?);
    }
    let full = SupportRecord::new(
        prop()?,
        SupportResult::Supported,
        handles,
        validity()?,
        task()?,
        case_fence(),
        None,
        case_digest("proof-support"),
    )?;
    full.validate()?;
    let mut overflow = BTreeSet::new();
    for index in 0..=MAX_HANDLES {
        overflow.insert(artifact(format!("overflow-{index}").as_str())?);
    }
    assert_eq!(
        SupportRecord::new(
            prop()?,
            SupportResult::Supported,
            overflow,
            validity()?,
            task()?,
            case_fence(),
            None,
            case_digest("proof-support"),
        ),
        Err(ContractError::TooMany {
            field: "support.handles",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/9
#[test]
fn weakest_ceiling_bounds_grade() -> CaseResult {
    EvidenceGrade::check_ceiling(EvidenceGrade::Orienting, EvidenceGrade::Grounded)?;
    EvidenceGrade::check_ceiling(EvidenceGrade::ScienceGrade, EvidenceGrade::ScienceGrade)?;
    assert_eq!(
        EvidenceGrade::check_ceiling(EvidenceGrade::Grounded, EvidenceGrade::Orienting),
        Err(ContractError::CeilingViolation {
            field: "grade.ceiling",
        })
    );
    assert_eq!(
        EvidenceGrade::check_ceiling(EvidenceGrade::ScienceGrade, EvidenceGrade::Corroborated),
        Err(ContractError::CeilingViolation {
            field: "grade.ceiling",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/10
#[test]
fn dependents_cannot_raise_grade() -> CaseResult {
    EvidenceGrade::check_dependent(EvidenceGrade::Corroborated, EvidenceGrade::Grounded)?;
    EvidenceGrade::check_dependent(EvidenceGrade::Grounded, EvidenceGrade::Grounded)?;
    assert_eq!(
        EvidenceGrade::check_dependent(EvidenceGrade::Grounded, EvidenceGrade::Corroborated),
        Err(ContractError::CeilingViolation {
            field: "grade.dependent",
        })
    );
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
    let decoded: GradeAssignment =
        serde_json::from_str(&encoded_unknown).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, unknown);
    let both = GradeAssignment {
        grade: Some(EvidenceGrade::Grounded),
        unknown_reason: Some("both sides".to_owned()),
    };
    assert_eq!(
        both.validate(),
        Err(ContractError::ImpossibleCombination {
            field: "grade.assignment",
        })
    );
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
        let round: SupportResult = serde_json::from_str(&encoded(&result)?)
            .map_err(|_| ContractError::Canonicalization)?;
        assert_eq!(round, result);
    }
    assert_eq!(
        weakest_link(&[SupportResult::Supported, SupportResult::Partial])?,
        SupportResult::Partial
    );
    assert_eq!(
        weakest_link(&[
            SupportResult::Supported,
            SupportResult::Contradicted,
            SupportResult::Partial
        ])?,
        SupportResult::Contradicted
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/13
#[test]
fn unsupported_valid_is_not_error() -> CaseResult {
    support_record(SupportResult::Unsupported)?.validate()?;
    support_record(SupportResult::Contradicted)?.validate()?;
    support_record(SupportResult::Unknown)?.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 580/14
#[test]
fn handles_preserved_on_support() -> CaseResult {
    let record = support_record(SupportResult::Supported)?;
    let decoded: SupportRecord =
        serde_json::from_str(&encoded(&record)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded.handles, record.handles);
    assert!(decoded.handles.contains(&artifact("handle-1")?));
    assert_eq!(encoded(&decoded)?, encoded(&record)?);
    Ok(())
}

// WORK_UNIT_CASE: 580/15
#[test]
fn scope_time_version_precision_mismatch_limits_support() -> CaseResult {
    let bounds = validity()?;
    assert!(bounds.covers("scope-580", Some(150), "v1", "file"));
    assert!(!bounds.covers("scope-other", Some(150), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(50), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(250), "v1", "file"));
    assert!(!bounds.covers("scope-580", Some(150), "v2", "file"));
    // Precision participates: a finer assertion than the support is not
    // covered, while a coarser one is. Support at `file` precision covers
    // `file`, `directory`, `package`, and `repository` assertions, never a
    // `symbol` or `line` assertion.
    assert!(!bounds.covers("scope-580", Some(150), "v1", "symbol"));
    assert!(!bounds.covers("scope-580", Some(150), "v1", "line"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "directory"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "package"));
    assert!(bounds.covers("scope-580", Some(150), "v1", "repository"));
    // Unknown precision spellings cover only exact equality.
    let custom = ValidityBounds::new("scope-580", None, None, "v1", "rack-unit")?;
    assert!(custom.covers("scope-580", None, "v1", "rack-unit"));
    assert!(!custom.covers("scope-580", None, "v1", "file"));
    assert!(!bounds.covers("scope-580", None, "v1", "rack-unit"));
    let record = support_record(SupportResult::Supported)?;
    assert_eq!(
        record.validate_for(&task()?, "scope-other", &case_fence()),
        Err(ContractError::ScopeMismatch {
            field: "support.scope",
        })
    );
    let narrowed = ValidityBounds::new("scope-580", Some(100), Some(200), "v2", "symbol")?;
    assert_ne!(narrowed.version, bounds.version);
    assert_ne!(narrowed.precision, bounds.precision);
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
    let exclusion = ExclusionRecord::new("member-9", "out of scope class")?;
    exclusion.validate()?;
    assert!(ExclusionRecord::new("member-9", "   ").is_err());
    Ok(())
}

// WORK_UNIT_CASE: 580/17
#[test]
fn vague_denominator_rejected() -> CaseResult {
    let base = denominator()?;
    let mut vague_class = base.clone();
    vague_class.class = "all-relevant".to_owned();
    assert_eq!(
        vague_class.validate(),
        Err(ContractError::VagueDenominator {
            field: "coverage.class",
        })
    );
    let mut vague_scope = base.clone();
    vague_scope.scope = "*".to_owned();
    assert_eq!(
        vague_scope.validate(),
        Err(ContractError::VagueDenominator {
            field: "coverage.scope",
        })
    );
    // Known-empty is owned, exact, terminal, and bound: an empty member list
    // with the complete marker, no query or frontier standing in, and the
    // owner snapshot the emptiness was read from.
    let known_empty = CoverageDenominator::new(
        "source-record",
        "schema-1",
        "rev-1",
        "scope-580",
        case_fence(),
        BTreeSet::new(),
        BTreeSet::new(),
        None,
        None,
        SnapshotRef::new("snapshot-1", source("owner-1")?)?,
        Vec::new(),
        PaginationBounds::new(0, 1, 0, false)?,
        validity()?,
        DenominatorKind::CompleteScope,
    )?;
    known_empty.validate()?;
    assert!(known_empty.members.is_empty());
    // Unowned empty proves nothing: sampled or unknown kinds with no members
    // and no query standing in fail, and so does a query-fronted empty that
    // claims completeness without enumerating it.
    for kind in [DenominatorKind::SampledWithMethod, DenominatorKind::Unknown] {
        let unowned = CoverageDenominator::new(
            "source-record",
            "schema-1",
            "rev-1",
            "scope-580",
            case_fence(),
            BTreeSet::new(),
            BTreeSet::new(),
            None,
            None,
            SnapshotRef::new("snapshot-1", source("owner-1")?)?,
            Vec::new(),
            PaginationBounds::new(0, 1, 1, false)?,
            validity()?,
            kind,
        );
        assert_eq!(
            unowned,
            Err(ContractError::IncompleteDenominator {
                field: "coverage.members",
            })
        );
    }
    let fronted_empty = CoverageDenominator::new(
        "source-record",
        "schema-1",
        "rev-1",
        "scope-580",
        case_fence(),
        BTreeSet::new(),
        BTreeSet::new(),
        Some(QuerySpec::new("query-text", "query-rev")?),
        None,
        SnapshotRef::new("snapshot-1", source("owner-1")?)?,
        Vec::new(),
        PaginationBounds::new(0, 1, 0, false)?,
        validity()?,
        DenominatorKind::CompleteScope,
    );
    assert_eq!(
        fronted_empty,
        Err(ContractError::IncompleteDenominator {
            field: "coverage.members",
        })
    );
    // A complete scope is never truncated and its total always equals its
    // enumerated member count.
    let mut truncated = base.clone();
    truncated.bounds = PaginationBounds::new(0, 2, 2, true)?;
    assert_eq!(
        truncated.validate(),
        Err(ContractError::IncompleteDenominator {
            field: "coverage.bounds",
        })
    );
    let mut short = base;
    assert!(short.members.remove(&artifact("member-1")?));
    assert_eq!(
        short.validate(),
        Err(ContractError::ArithmeticMismatch {
            field: "coverage.bounds",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/18
#[test]
fn one_disposition_per_member() -> CaseResult {
    let outcome = MemberOutcome::new(artifact("member-1")?, MemberDisposition::Observed);
    assert_eq!(encoded(&outcome)?.matches("disposition").count(), 1);
    let frozen = denominator()?;
    let mut duplicated = receipt_for(frozen.digest.clone())?;
    duplicated.members.push(MemberOutcome::new(
        artifact("member-1")?,
        MemberDisposition::Stale,
    ));
    assert_eq!(
        duplicated.validate(),
        Err(ContractError::Duplicate {
            field: "receipt.members",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/19
#[test]
fn coverage_arithmetic_validated() -> CaseResult {
    let frozen = denominator()?;
    receipt_for(frozen.digest.clone())?.validate()?;
    let mut groups = BTreeSet::new();
    groups.insert("group-1".to_owned());
    let short = CoverageReceipt::new(
        QuerySpec::new("query-text", "query-rev")?,
        FrontierSpec::new("frontier-1", "frontier-rev")?,
        frozen.digest.clone(),
        3,
        task()?,
        "scope-580",
        case_fence(),
        "policy-1",
        groups.clone(),
        vec![MemberOutcome::new(
            artifact("member-1")?,
            MemberDisposition::Observed,
        )],
        vec![OmittedMember::new(
            artifact("member-2")?,
            "duplicate of member-1",
        )?],
        case_digest("proof-receipt"),
    );
    assert_eq!(
        short,
        Err(ContractError::ArithmeticMismatch {
            field: "receipt.denominator_size",
        })
    );
    let reconciled = CoverageReceipt::new(
        QuerySpec::new("query-text", "query-rev")?,
        FrontierSpec::new("frontier-1", "frontier-rev")?,
        frozen.digest.clone(),
        2,
        task()?,
        "scope-580",
        case_fence(),
        "policy-1",
        groups,
        vec![MemberOutcome::new(
            artifact("member-1")?,
            MemberDisposition::Observed,
        )],
        vec![OmittedMember::new(
            artifact("member-2")?,
            "duplicate of member-1",
        )?],
        case_digest("proof-receipt"),
    )?;
    reconciled.validate()?;
    Ok(())
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
    let mut groups = BTreeSet::new();
    groups.insert("group-1".to_owned());
    let gapped = CoverageReceipt::new(
        QuerySpec::new("query-text", "query-rev")?,
        FrontierSpec::new("frontier-1", "frontier-rev")?,
        frozen.digest.clone(),
        2,
        task()?,
        "scope-580",
        case_fence(),
        "policy-1",
        groups,
        vec![
            MemberOutcome::new(artifact("member-1")?, MemberDisposition::Observed),
            MemberOutcome::new(artifact("member-2")?, MemberDisposition::Unavailable),
        ],
        Vec::new(),
        case_digest("proof-receipt"),
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
    let (frozen, claim) = absence_with_denominator()?;
    claim.validate()?;
    assert!(claim.receipt.is_terminal());
    claim.validate_closed(&frozen)?;
    claim.check_context(
        "scope-580",
        &case_fence(),
        frozen_query_digest()?.as_str(),
        "snapshot-1",
    )?;
    Ok(())
}

fn absence_receipt_with(
    second: MemberDisposition,
) -> Result<(CoverageDenominator, CoverageReceipt), ContractError> {
    let frozen = denominator()?;
    let mut groups = BTreeSet::new();
    groups.insert("group-1".to_owned());
    let receipt = CoverageReceipt::new(
        QuerySpec::new("query-text", "query-rev")?,
        FrontierSpec::new("frontier-1", "frontier-rev")?,
        frozen.digest.clone(),
        2,
        task()?,
        "scope-580",
        case_fence(),
        "policy-1",
        groups,
        vec![
            MemberOutcome::new(artifact("member-1")?, MemberDisposition::Observed),
            MemberOutcome::new(artifact("member-2")?, second),
        ],
        Vec::new(),
        case_digest("proof-receipt"),
    )?;
    Ok((frozen, receipt))
}

fn absence_attempt(
    frozen: &CoverageDenominator,
    receipt: CoverageReceipt,
) -> Result<AbsenceClaim, ContractError> {
    AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        task()?,
        "policy-1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen.digest.clone(),
        DenominatorKind::CompleteScope,
        frozen_query_digest()?,
        "snapshot-1",
        receipt,
        BoundedProof::new(case_digest("proof-absence"), 64)?,
    )
}

// WORK_UNIT_CASE: 580/23
#[test]
fn no_match_timeout_silence_exhaustion_not_absence() -> CaseResult {
    let frozen = denominator()?;
    let sampled = AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        None,
        None,
        "v1",
        task()?,
        "policy-1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen.digest.clone(),
        DenominatorKind::SampledWithMethod,
        frozen_query_digest()?,
        "snapshot-1",
        receipt_for(frozen.digest.clone())?,
        BoundedProof::new(case_digest("proof-absence"), 64)?,
    );
    assert_eq!(
        sampled,
        Err(ContractError::IncompleteDenominator {
            field: "absence.denominator_kind",
        })
    );
    // Every non-terminal disposition keeps the question open: no-match,
    // timeout, silence, exhaustion, and every other unresolved outcome can
    // never construct absence evidence.
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
        let (frozen_case, receipt) = absence_receipt_with(disposition)?;
        assert!(!receipt.is_terminal());
        assert_eq!(
            absence_attempt(&frozen_case, receipt),
            Err(ContractError::ImpossibleCombination {
                field: "absence.receipt",
            })
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 580/24
#[test]
fn changed_query_scope_fence_snapshot_invalidates_absence() -> CaseResult {
    let claim = absence()?;
    let live_query = frozen_query_digest()?;
    assert!(
        claim
            .check_context(
                "scope-other",
                &case_fence(),
                live_query.as_str(),
                "snapshot-1"
            )
            .is_err()
    );
    assert!(
        claim
            .check_context(
                "scope-580",
                &case_fence(),
                case_digest("other-query").as_str(),
                "snapshot-1"
            )
            .is_err()
    );
    assert!(
        claim
            .check_context(
                "scope-580",
                &case_fence(),
                live_query.as_str(),
                "snapshot-2"
            )
            .is_err()
    );
    let drifted_fence = StateFence::new(
        AuthorityEpoch::new(7).map_err(|_| case_error("case.epoch"))?,
        ResourceGeneration::genesis(),
    );
    assert_eq!(
        claim.check_context(
            "scope-580",
            &drifted_fence,
            live_query.as_str(),
            "snapshot-1"
        ),
        Err(ContractError::StaleContext {
            field: "absence.context",
        })
    );
    // Closed binding negatives: each axis fails distinctly against the exact
    // frozen denominator, even when the claim is internally valid.
    let (frozen, valid) = absence_with_denominator()?;
    let mut other = denominator()?;
    assert!(other.members.remove(&artifact("member-2")?));
    other.members.insert(artifact("member-9")?);
    other.digest = other.compute_digest()?;
    let unrelated = AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        task()?,
        "policy-1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        other.digest.clone(),
        DenominatorKind::CompleteScope,
        frozen_query_digest()?,
        "snapshot-1",
        receipt_for(other.digest.clone())?,
        BoundedProof::new(case_digest("proof-absence"), 128)?,
    )?;
    assert_eq!(
        unrelated.validate_closed(&frozen),
        Err(ContractError::DigestMismatch {
            field: "absence.denominator_digest",
        })
    );
    let mut swapped_query = valid.clone();
    swapped_query.query_digest = case_digest("other-query");
    swapped_query.digest = swapped_query.compute_digest()?;
    assert_eq!(
        swapped_query.validate_closed(&frozen),
        Err(ContractError::DigestMismatch {
            field: "absence.query_digest",
        })
    );
    let mut swapped_snapshot = valid.clone();
    swapped_snapshot.snapshot_id = "snapshot-2".to_owned();
    swapped_snapshot.digest = swapped_snapshot.compute_digest()?;
    assert_eq!(
        swapped_snapshot.validate_closed(&frozen),
        Err(ContractError::StaleContext {
            field: "absence.snapshot",
        })
    );
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
    // Accepted, rejected, countered, and unresolved handle sets validate:
    // every admitted claim is entered exactly once, verdict sets partition
    // the entries, assumptions are listed, and the weakest link is computed.
    assert_eq!(map.accepted_ids().len(), 1);
    assert!(map.accepted_ids().contains(&ClaimId::new("claim-a")?));
    assert_eq!(map.rejected_ids().len(), 1);
    assert!(map.rejected_ids().contains(&ClaimId::new("claim-b")?));
    assert!(map.countered_ids().is_empty());
    assert!(map.unresolved.is_empty());
    assert!(map.assumption_names().contains("assumption-1"));
    assert_eq!(map.weakest_grade(), Some(EvidenceGrade::Grounded));
    let decoded: ClaimMap =
        serde_json::from_str(&encoded(&map)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, map);
    Ok(())
}

// WORK_UNIT_CASE: 580/26
#[test]
fn outside_manifest_rejected() -> CaseResult {
    let mut admitted = BTreeSet::new();
    admitted.insert(ClaimId::new("claim-a")?);
    let attempt = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        vec![claim_entry("claim-a")?, claim_entry("claim-outside")?],
        Vec::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        attempt,
        Err(ContractError::OutsideManifest {
            field: "claim.entries",
        })
    );
    // An admitted claim without an entry is unrepresented, not covered.
    let mut partial_admitted = BTreeSet::new();
    partial_admitted.insert(ClaimId::new("claim-a")?);
    partial_admitted.insert(ClaimId::new("claim-ghost")?);
    let partial = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        partial_admitted,
        vec![claim_entry("claim-a")?],
        Vec::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        partial,
        Err(ContractError::MissingReference {
            field: "claim.entries",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/27
#[test]
fn duplicate_and_same_id_changed_rejected() -> CaseResult {
    let mut admitted = BTreeSet::new();
    admitted.insert(ClaimId::new("claim-a")?);
    let duplicate = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted.clone(),
        vec![claim_entry("claim-a")?, claim_entry("claim-a")?],
        Vec::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        duplicate,
        Err(ContractError::Duplicate {
            field: "claim.entries",
        })
    );
    let changed = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        vec![
            claim_entry_with(
                "claim-a",
                ClaimVerdict::Accepted,
                ClaimAuditOutcome::Supported,
                false,
            )?,
            claim_entry_with(
                "claim-a",
                ClaimVerdict::Countered,
                ClaimAuditOutcome::Contradicted,
                true,
            )?,
        ],
        Vec::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        changed,
        Err(ContractError::Duplicate {
            field: "claim.entries",
        })
    );
    // An accepted entry with neither a supporting handle nor an explicit
    // unresolved marker is not component coverage: digest, assumption, and
    // discriminator presence never counts on its own.
    let mut bare = claim_entry("claim-a")?;
    bare.support.clear();
    assert_eq!(
        bare.validate(),
        Err(ContractError::EmptyCollection {
            field: "claim.support",
        })
    );
    Ok(())
}

fn dependent_entry(name: &str, grade: EvidenceGrade) -> Result<ClaimEntry, ContractError> {
    let mut dependencies = BTreeSet::new();
    dependencies.insert(ClaimId::new("claim-a")?);
    let mut assumptions = BTreeSet::new();
    assumptions.insert("assumption-1".to_owned());
    let mut discriminators = BTreeSet::new();
    discriminators.insert("discriminator-1".to_owned());
    let mut support = BTreeSet::new();
    support.insert(artifact("handle-1")?);
    ClaimEntry::new(
        ClaimId::new(name)?,
        case_digest(name),
        ClaimVerdict::Accepted,
        ClaimAuditOutcome::Supported,
        BTreeSet::new(),
        None,
        EvidenceAuthority::DeterministicRuntimeTest,
        grade,
        dependencies,
        validity()?,
        case_digest("coverage-claim"),
        support,
        BTreeSet::new(),
        grade,
        assumptions,
        discriminators,
    )
}

// WORK_UNIT_CASE: 580/28
#[test]
fn dependence_groups_explicit() -> CaseResult {
    let map = claim_map()?;
    assert_eq!(map.groups.len(), 1);
    assert!(map.groups[0].members.contains(&ClaimId::new("claim-a")?));
    assert!(DependenceGroup::new("empty-group", BTreeSet::new(), "no members").is_err());
    let mut admitted = BTreeSet::new();
    admitted.insert(ClaimId::new("claim-a")?);
    let mut dangling = BTreeSet::new();
    dangling.insert(ClaimId::new("claim-ghost")?);
    let mut entry = claim_entry("claim-a")?;
    entry.dependencies = dangling;
    let attempt = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        vec![entry],
        Vec::new(),
        BTreeSet::new(),
    );
    assert_eq!(
        attempt,
        Err(ContractError::MissingReference {
            field: "claim.dependencies",
        })
    );
    // Dependence groups cover dependent claims: a dependency edge with no
    // group holding both ends together fails, even at equal grades.
    let mut pair_admitted = BTreeSet::new();
    pair_admitted.insert(ClaimId::new("claim-a")?);
    pair_admitted.insert(ClaimId::new("claim-b")?);
    let mut lone_members = BTreeSet::new();
    lone_members.insert(ClaimId::new("claim-a")?);
    let uncovered = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        pair_admitted.clone(),
        vec![
            claim_entry("claim-a")?,
            dependent_entry("claim-b", EvidenceGrade::Grounded)?,
        ],
        vec![DependenceGroup::new(
            "group-1",
            lone_members,
            "holds only one end",
        )?],
        BTreeSet::new(),
    );
    assert_eq!(
        uncovered,
        Err(ContractError::MissingReference {
            field: "claim.groups",
        })
    );
    // Quoting a claim never upgrades it: a dependent above its parent grade
    // fails even with a covering group.
    let mut both_members = BTreeSet::new();
    both_members.insert(ClaimId::new("claim-a")?);
    both_members.insert(ClaimId::new("claim-b")?);
    let upgraded = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        pair_admitted,
        vec![
            claim_entry("claim-a")?,
            dependent_entry("claim-b", EvidenceGrade::Corroborated)?,
        ],
        vec![DependenceGroup::new(
            "group-1",
            both_members,
            "holds both ends",
        )?],
        BTreeSet::new(),
    );
    assert_eq!(
        upgraded,
        Err(ContractError::CeilingViolation {
            field: "grade.dependent",
        })
    );
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
        wires(&roles)?,
        vec![
            "\"EVENT\"",
            "\"EFFECTIVE\"",
            "\"OBSERVATION\"",
            "\"INGESTION\"",
            "\"COMMIT\""
        ]
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
    // Six-way separation: chronology, mechanism, assumption, support,
    // investigation, and request never cross-decode in any direction.
    let wires = [
        precedence_json,
        causal_json,
        encoded(&AssumptionRecord::new(
            "assumption-1",
            "the registry mirrors the snapshot",
            "scope-580",
            source("owner-1")?,
            task()?,
            case_fence(),
        )?)?,
        encoded(&support_record(SupportResult::Supported)?)?,
        encoded(&investigation()?)?,
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
    let association: CausalStatus =
        serde_json::from_str("\"ASSOCIATION\"").map_err(|_| ContractError::Canonicalization)?;
    let correlation: CausalStatus =
        serde_json::from_str("\"CORRELATION\"").map_err(|_| ContractError::Canonicalization)?;
    assert_ne!(association, correlation);
    assert_ne!(correlation, CausalStatus::DependencyPreconditionEnablement);
    assert_ne!(
        CausalStatus::DependencyPreconditionEnablement,
        CausalStatus::Mechanism
    );
    Ok(())
}

fn dependency_reading_ceiling(
    rivals: &BTreeSet<String>,
    confounders: &BTreeSet<String>,
    evidence_refs: &BTreeSet<ArtifactId>,
) -> CaseResult {
    // A dependency reading below science grade validates; science grade never
    // does, for any reading.
    CausalClaim::new(
        prop()?,
        CausalStatus::DependencyPreconditionEnablement,
        "enablement sketch",
        rivals.clone(),
        confounders.clone(),
        evidence_refs.clone(),
        EvidenceGrade::Corroborated,
        "scope-580",
    )?
    .validate()?;
    assert_eq!(
        CausalClaim::new(
            prop()?,
            CausalStatus::DependencyPreconditionEnablement,
            "enablement sketch",
            rivals.clone(),
            confounders.clone(),
            evidence_refs.clone(),
            EvidenceGrade::ScienceGrade,
            "scope-580",
        ),
        Err(ContractError::CeilingViolation {
            field: "causal.ceiling",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/31
#[test]
fn causal_needs_mechanism_rivals_evidence() -> CaseResult {
    let mechanism = causal()?;
    mechanism.validate()?;
    // Causal fields survive the round-trip: mechanism sketch, rivals,
    // confounders, evidence references, ceiling, and scope are all preserved.
    let decoded: CausalClaim =
        serde_json::from_str(&encoded(&mechanism)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, mechanism);
    assert!(decoded.confounders.contains("confounder-1"));
    assert!(decoded.evidence_refs.contains(&artifact("evidence-1")?));
    assert_eq!(decoded.ceiling, EvidenceGrade::Corroborated);
    assert_eq!(CausalStatus::Mechanism.wire_name(), "MECHANISM");
    assert_eq!(
        CausalStatus::DependencyPreconditionEnablement.wire_name(),
        "DEPENDENCY_PRECONDITION_ENABLEMENT",
    );
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    let mut confounders = BTreeSet::new();
    confounders.insert("confounder-1".to_owned());
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
    dependency_reading_ceiling(&rivals, &confounders, &evidence_refs)?;
    assert!(
        CausalClaim::new(
            prop()?,
            CausalStatus::Mechanism,
            "mechanism-1",
            BTreeSet::new(),
            BTreeSet::new(),
            evidence_refs.clone(),
            EvidenceGrade::Corroborated,
            "scope-580",
        )
        .is_err()
    );
    assert!(
        CausalClaim::new(
            prop()?,
            CausalStatus::Mechanism,
            "mechanism-1",
            rivals.clone(),
            BTreeSet::new(),
            BTreeSet::new(),
            EvidenceGrade::Corroborated,
            "scope-580",
        )
        .is_err()
    );
    assert!(
        CausalClaim::new(
            prop()?,
            CausalStatus::Mechanism,
            "   ",
            rivals.clone(),
            BTreeSet::new(),
            evidence_refs.clone(),
            EvidenceGrade::Corroborated,
            "scope-580",
        )
        .is_err()
    );
    assert_eq!(
        CausalClaim::new(
            prop()?,
            CausalStatus::Mechanism,
            "mechanism-1",
            rivals.clone(),
            BTreeSet::new(),
            evidence_refs.clone(),
            EvidenceGrade::ScienceGrade,
            "scope-580",
        ),
        Err(ContractError::CeilingViolation {
            field: "causal.ceiling",
        })
    );
    assert_eq!(
        CausalClaim::new(
            prop()?,
            CausalStatus::Association,
            "sketch",
            rivals,
            BTreeSet::new(),
            evidence_refs,
            EvidenceGrade::Corroborated,
            "scope-580",
        ),
        Err(ContractError::CeilingViolation {
            field: "causal.ceiling",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/32
#[test]
fn conflict_set_preserves_all_positions() -> CaseResult {
    let set = conflict()?;
    set.validate()?;
    let decoded: ConflictSet =
        serde_json::from_str(&encoded(&set)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded.positions.len(), 2);
    assert_eq!(decoded.positions[0].source, source("source-a")?);
    assert!(decoded.positions[1].minority);
    assert!(
        decoded.positions[0]
            .counters
            .contains(&artifact("counter-1")?)
    );
    assert!(decoded.positions[0].assumptions.contains("assumption-p1"));
    assert!(
        decoded
            .common_lineage
            .contains(&LineageRootId::new("lineage-1")?)
    );
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
    let with_winner = set_json.replace(
        "\"lifecycle\":\"OPEN\"",
        "\"lifecycle\":\"OPEN\",\"winner\":\"source-a\",\"confidence\":0.99",
    );
    assert!(serde_json::from_str::<ConflictSet>(&with_winner).is_err());
    let mut resolved = set.clone();
    resolved.lifecycle = ConflictLifecycle::Resolved;
    assert_eq!(
        resolved.validate(),
        Err(ContractError::ImpossibleCombination {
            field: "conflict.lifecycle",
        })
    );
    assert_eq!(set.positions.len(), 2);
    Ok(())
}

// WORK_UNIT_CASE: 580/34
#[test]
fn valid_inert_candidate() -> CaseResult {
    let position = candidate()?;
    position.validate()?;
    assert_eq!(position.digest, position.compute_digest()?);
    assert_eq!(
        position.candidate_kind,
        CandidateKind::EpistemicPositionCandidate
    );
    let decoded: EpistemicPositionCandidate =
        serde_json::from_str(&encoded(&position)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, position);
    // Closed identity: the candidate binds its request, denominator, receipt,
    // map, and assumptions exactly, with no foreign, missing, or extra
    // members anywhere in the closure.
    let frozen = denominator()?;
    let receipt = receipt_for(frozen.digest.clone())?;
    position.validate_closed(
        &request()?,
        &frozen,
        &receipt,
        &claim_map()?,
        &[],
        &[assumption()?],
    )?;
    // A strict subset of the governed claims fails closed validation: there
    // is no scoped-claim versus covered-proposition distinction, only exact
    // set equality between candidate claims and admitted claims.
    let mut subset = position.clone();
    subset.claims = vec![claim_entry("claim-a")?];
    subset.digest = subset.compute_digest()?;
    subset.validate()?;
    assert_eq!(
        subset.validate_closed(
            &request()?,
            &frozen,
            &receipt,
            &claim_map()?,
            &[],
            &[assumption()?],
        ),
        Err(ContractError::MissingReference {
            field: "candidate.claims",
        })
    );
    // Same ID with changed evidence fails: the entered shape must equal the
    // governed shape by value.
    let mut changed = position.clone();
    changed.claims[0] = rejected_entry("claim-a")?;
    changed.digest = changed.compute_digest()?;
    assert_eq!(
        changed.validate_closed(
            &request()?,
            &frozen,
            &receipt,
            &claim_map()?,
            &[],
            &[assumption()?],
        ),
        Err(ContractError::DigestMismatch {
            field: "candidate.claims",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/35
#[test]
fn candidate_carries_no_admission_write_effect_finish() -> CaseResult {
    // API-level proof: walk every object key of the constructed candidate and
    // its nested records. No admission, write, effect, allocation, apply, or
    // finish field exists anywhere in the public shape. The traversal keeps
    // the generic JSON type inferred, so the contract surface never depends
    // on it.
    let root = serde_json::to_value(&candidate()?).map_err(|_| ContractError::Canonicalization)?;
    let mut stack = vec![&root];
    let mut keys = Vec::new();
    while let Some(current) = stack.pop() {
        if let Some(map) = current.as_object() {
            for (key, nested) in map {
                keys.push(key.to_lowercase());
                stack.push(nested);
            }
        } else if let Some(items) = current.as_array() {
            stack.extend(items.iter());
        }
    }
    assert!(!keys.is_empty());
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
    ];
    for key in &keys {
        assert!(
            !forbidden.contains(&key.as_str()),
            "forbidden candidate field present"
        );
    }
    // The top-level field set is exactly the documented contract shape: no
    // more, no fewer.
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
            "invalidation",
            "manifest",
            "predecessor",
            "proof_digest",
            "proposed_assertability",
            "proposition",
            "revision",
            "rivals",
            "scope",
            "support",
            "task_id",
            "unknowns",
            "verifier",
            "version",
            "window_end_ms",
            "window_start_ms",
        ]
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/36
#[test]
fn valid_admitted_view_with_receipt() -> CaseResult {
    let view = admitted()?;
    view.validate()?;
    assert_eq!(view.view_kind, AdmittedKind::CurrentEpistemicPosition);
    let (receipt, digest) = view.receipt_identity();
    assert_eq!(receipt, &admission()?);
    assert_eq!(digest, case_digest("admission-payload").as_str());
    assert_eq!(view.currentness, Currentness::Current);
    let mut superseded = view.clone();
    superseded.currentness = Currentness::Superseded;
    assert!(superseded.validate().is_err());
    // Alias proof: the previous name is the same type with the same serde and
    // the same wire bytes as the canonical `CurrentEpistemicPosition`.
    let wire = encoded(&view)?;
    assert!(wire.contains("CURRENT_EPISTEMIC_POSITION"));
    let via_alias: CurrentEpistemicPositionView =
        serde_json::from_str(&wire).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(via_alias, view);
    assert_eq!(encoded(&via_alias)?, wire);
    // Donor-compatible position states round-trip with exact wire names.
    let states = [
        PositionState::Observed,
        PositionState::Supported,
        PositionState::Assumed,
        PositionState::Conflicted,
        PositionState::Stale,
        PositionState::Unknown,
    ];
    assert_eq!(
        wires(&states)?.join(","),
        "\"OBSERVED\",\"SUPPORTED\",\"ASSUMED\",\"CONFLICTED\",\"STALE\",\"UNKNOWN\""
    );
    // The provenance closure binds the receipt contents the view cites: every
    // consulted record is listed, and mixed sources are derived, never
    // asserted.
    let closed = closure()?;
    closed.validate()?;
    let decoded: ProvenanceClosure =
        serde_json::from_str(&encoded(&closed)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, closed);
    let mut mixed = closed.clone();
    mixed.sources.insert(source("source-b")?);
    mixed.digest = mixed.compute_digest()?;
    assert_eq!(
        mixed.validate(),
        Err(ContractError::ImpossibleCombination {
            field: "provenance.mixed_sources",
        })
    );
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

fn support_ceilings() -> CaseResult {
    // Support ceilings: partial caps at qualified inference, while unknown,
    // stale, and outside-manifest cap at hypothesis candidate — none of them
    // yields unconditional, elevated, or material-effect assertability.
    assert_eq!(
        PositionAssertability::support_cap(&[SupportResult::Supported])?,
        PositionAssertability::MaterialEffect
    );
    assert_eq!(
        PositionAssertability::support_cap(&[SupportResult::Supported, SupportResult::Partial])?,
        PositionAssertability::QualifiedInference
    );
    for result in [
        SupportResult::Unknown,
        SupportResult::Stale,
        SupportResult::OutsideManifest,
        SupportResult::Contradicted,
        SupportResult::Unsupported,
        SupportResult::Superseded,
    ] {
        assert_eq!(
            PositionAssertability::support_cap(&[SupportResult::Supported, result])?,
            PositionAssertability::HypothesisCandidate
        );
    }
    assert!(PositionAssertability::support_cap(&[]).is_err());
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::ObservedFact,
            EvidenceGrade::Corroborated,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Partial],
            true,
            false,
            true,
            DisclosureClass::Open,
            None,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.support",
        })
    );
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::QualifiedInference,
            EvidenceGrade::Corroborated,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Unknown],
            true,
            false,
            true,
            DisclosureClass::Open,
            None,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.support",
        })
    );
    Ok(())
}

fn disclosure_ceilings() -> CaseResult {
    // Disclosure ceilings: restricted never rises above qualified inference,
    // quarantined renders only as quarantined unknown.
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::ObservedFact,
            EvidenceGrade::ScienceGrade,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Supported],
            true,
            false,
            true,
            DisclosureClass::Restricted,
            Some(&competent_verifier()?),
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.disclosure",
        })
    );
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::HypothesisCandidate,
            EvidenceGrade::Grounded,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Supported],
            false,
            false,
            true,
            DisclosureClass::Quarantined,
            None,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.disclosure",
        })
    );
    Ok(())
}

fn verifier_ceilings() -> CaseResult {
    // Verifier ceiling: a material effect requires a competent verifier over
    // a current freshness; without one the effect is not licensed.
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::MaterialEffect,
            EvidenceGrade::ScienceGrade,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Supported],
            true,
            false,
            true,
            DisclosureClass::Open,
            None,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.verifier",
        })
    );
    PositionAssertability::check_closed(
        PositionAssertability::MaterialEffect,
        EvidenceGrade::ScienceGrade,
        EvidenceAuthority::DeterministicRuntimeTest,
        &[SupportResult::Supported],
        true,
        false,
        true,
        DisclosureClass::Open,
        Some(&competent_verifier()?),
    )?;
    let contract = ContractId::new("contract-580").map_err(|_| case_error("case.contract"))?;
    let older = RequiredVerifier::new(
        contract,
        "r1",
        EvidenceFreshness::KnownOlderSnapshot,
        VerifierStanding::Competent,
        None,
    )?;
    assert!(!older.is_current());
    assert!(!older.is_competent());
    assert_eq!(
        PositionAssertability::check_closed(
            PositionAssertability::MaterialEffect,
            EvidenceGrade::ScienceGrade,
            EvidenceAuthority::DeterministicRuntimeTest,
            &[SupportResult::Supported],
            true,
            false,
            true,
            DisclosureClass::Open,
            Some(&older),
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.verifier",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/38
#[test]
fn assertability_capped_by_ceilings() -> CaseResult {
    PositionAssertability::check(
        PositionAssertability::QualifiedInference,
        EvidenceGrade::Grounded,
        EvidenceAuthority::DeterministicRuntimeTest,
        true,
        false,
        true,
    )?;
    assert_eq!(
        PositionAssertability::check(
            PositionAssertability::MaterialEffect,
            EvidenceGrade::Grounded,
            EvidenceAuthority::DeterministicRuntimeTest,
            true,
            false,
            true,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.grade",
        })
    );
    assert_eq!(
        PositionAssertability::check(
            PositionAssertability::ObservedFact,
            EvidenceGrade::ScienceGrade,
            EvidenceAuthority::ModelInterpretation,
            true,
            false,
            true,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.ceiling",
        })
    );
    assert_eq!(
        PositionAssertability::check(
            PositionAssertability::ObservedFact,
            EvidenceGrade::Corroborated,
            EvidenceAuthority::DeterministicRuntimeTest,
            false,
            false,
            true,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.ceiling",
        })
    );
    support_ceilings()?;
    disclosure_ceilings()?;
    verifier_ceilings()?;
    Ok(())
}

// WORK_UNIT_CASE: 580/39
#[test]
fn planning_grants_no_effect() -> CaseResult {
    assert_eq!(
        PositionAssertability::ceiling_for(
            EvidenceGrade::Orienting,
            EvidenceAuthority::DeterministicRuntimeTest,
            true,
            false,
            true,
        ),
        PositionAssertability::PlanningOnly
    );
    PositionAssertability::check(
        PositionAssertability::PlanningOnly,
        EvidenceGrade::Orienting,
        EvidenceAuthority::DeterministicRuntimeTest,
        true,
        false,
        true,
    )?;
    assert_eq!(
        PositionAssertability::check(
            PositionAssertability::MaterialEffect,
            EvidenceGrade::Orienting,
            EvidenceAuthority::DeterministicRuntimeTest,
            true,
            false,
            true,
        ),
        Err(ContractError::CeilingViolation {
            field: "assertability.grade",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/40
#[test]
fn transition_preserves_before_after_predecessor() -> CaseResult {
    let movement = transition()?;
    movement.validate()?;
    assert_eq!(movement.before_support, SupportResult::Partial);
    assert_eq!(movement.after_support, SupportResult::Supported);
    assert_eq!(
        movement.before_assertability,
        PositionAssertability::HypothesisCandidate
    );
    let invalidation = InvalidationRecord::new(
        InvalidationKind::Superseded,
        "replaced by rerun",
        PredecessorId::new("predecessor-1")?,
    )?;
    let mut with_history = movement.clone();
    with_history.invalidation = Some(invalidation);
    with_history.digest = with_history.compute_digest()?;
    with_history.validate()?;
    let decoded: EpistemicTransition = serde_json::from_str(&encoded(&with_history)?)
        .map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(
        decoded
            .invalidation
            .as_ref()
            .map(|record| record.predecessor.as_str()),
        Some("predecessor-1")
    );
    assert_eq!(decoded, with_history);
    Ok(())
}

// WORK_UNIT_CASE: 580/41
#[test]
fn partial_unknown_not_unconditional_promotion() -> CaseResult {
    let mut reasons = BTreeSet::new();
    reasons.insert("no fresh evidence".to_owned());
    let bare = SupportDelta::new(BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), reasons)?;
    let partial_promotion = EpistemicTransition::new(
        prop()?,
        TaskRevision::genesis(),
        case_fence(),
        TransitionTrigger::Revalidation,
        BTreeSet::new(),
        operation()?,
        SupportResult::Partial,
        SupportResult::Supported,
        PositionAssertability::HypothesisCandidate,
        PositionAssertability::QualifiedInference,
        bare.clone(),
        case_digest("coverage-delta"),
        case_digest("conflict-delta"),
        "revert to predecessor",
        None,
        None,
        case_digest("proof-transition"),
    );
    assert_eq!(
        partial_promotion,
        Err(ContractError::CeilingViolation {
            field: "transition.promotion",
        })
    );
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
    let unknown_promotion = EpistemicTransition::new(
        prop()?,
        TaskRevision::genesis(),
        case_fence(),
        TransitionTrigger::NewEvidence,
        evidence_refs,
        operation()?,
        SupportResult::Unknown,
        SupportResult::Supported,
        PositionAssertability::UnknownWithheldQuarantined,
        PositionAssertability::QualifiedInference,
        bare,
        case_digest("coverage-delta"),
        case_digest("conflict-delta"),
        "revert to predecessor",
        None,
        None,
        case_digest("proof-transition"),
    );
    assert_eq!(
        unknown_promotion,
        Err(ContractError::CeilingViolation {
            field: "transition.promotion",
        })
    );
    transition()?.validate()?;
    Ok(())
}

// WORK_UNIT_CASE: 580/42
#[test]
fn set_permutation_invariance() -> CaseResult {
    let mut first_predecessors = BTreeSet::new();
    first_predecessors.insert(PredecessorId::new("predecessor-a")?);
    first_predecessors.insert(PredecessorId::new("predecessor-b")?);
    let mut second_predecessors = BTreeSet::new();
    second_predecessors.insert(PredecessorId::new("predecessor-b")?);
    second_predecessors.insert(PredecessorId::new("predecessor-a")?);
    let shared = (
        prop()?,
        ClaimId::new("claim-580")?,
        EvidenceSetId::new("evidence-set-580")?,
        ManifestId::new("manifest-580")?,
        SourceRevisionId::new("revision-580")?,
        LineageRootId::new("lineage-580")?,
        ValidityId::new("validity-580")?,
    );
    let first = IdentityBundle::new(
        shared.0.clone(),
        shared.1.clone(),
        shared.2.clone(),
        shared.3.clone(),
        shared.4.clone(),
        shared.5.clone(),
        shared.6.clone(),
        first_predecessors,
    )?;
    let second = IdentityBundle::new(
        shared.0,
        shared.1,
        shared.2,
        shared.3,
        shared.4,
        shared.5,
        shared.6,
        second_predecessors,
    )?;
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.canonical_json()?, second.canonical_json()?);
    Ok(())
}

// WORK_UNIT_CASE: 580/43
#[test]
fn load_bearing_mutation_invalidates_digest() -> CaseResult {
    let mut bundle = identity_bundle()?;
    bundle.validity = ValidityId::new("validity-changed")?;
    assert_eq!(
        bundle.validate(),
        Err(ContractError::DigestMismatch {
            field: "identity.digest",
        })
    );
    let mut frozen = denominator()?;
    frozen.revision = "rev-changed".to_owned();
    assert_eq!(
        frozen.validate(),
        Err(ContractError::DigestMismatch {
            field: "coverage.digest",
        })
    );
    let mut receipt = receipt_for(frozen.compute_digest()?)?;
    receipt.policy = "policy-changed".to_owned();
    assert_eq!(
        receipt.validate(),
        Err(ContractError::DigestMismatch {
            field: "receipt.digest",
        })
    );
    let mut claim = absence()?;
    claim.domain = "domain-changed".to_owned();
    assert_eq!(
        claim.validate(),
        Err(ContractError::DigestMismatch {
            field: "absence.digest",
        })
    );
    let mut map = claim_map()?;
    map.manifest = ManifestId::new("manifest-changed")?;
    assert_eq!(
        map.validate(),
        Err(ContractError::DigestMismatch {
            field: "claim.digest",
        })
    );
    let mut set = conflict()?;
    set.scope = "scope-changed".to_owned();
    assert_eq!(
        set.validate(),
        Err(ContractError::DigestMismatch {
            field: "conflict.digest",
        })
    );
    let mut position = candidate()?;
    position.version = "v2".to_owned();
    assert_eq!(
        position.validate(),
        Err(ContractError::DigestMismatch {
            field: "candidate.digest",
        })
    );
    let mut view = admitted()?;
    view.scope = "scope-changed".to_owned();
    assert_eq!(
        view.validate(),
        Err(ContractError::DigestMismatch {
            field: "admitted.digest",
        })
    );
    let mut movement = transition()?;
    movement.rollback = "changed rollback".to_owned();
    assert_eq!(
        movement.validate(),
        Err(ContractError::DigestMismatch {
            field: "transition.digest",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/44
#[test]
fn malformed_input_bounded_panic_free() -> CaseResult {
    // Bounded malformed corpus: every input fails closed on every boundary
    // type, without panicking and without reading past the corpus.
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
    let outcome = std::panic::catch_unwind(|| {
        let mut failures = 0;
        failures += usize::from(PaginationBounds::new(0, 0, 2, true).is_err());
        failures += usize::from(PaginationBounds::new(5, 1, 2, true).is_err());
        failures += usize::from(BoundedProof::new(case_digest("proof-absence"), u64::MAX).is_err());
        failures += usize::from(
            OwnerLookup::new(
                SourceId::new("owner-1").map_err(|_| case_error("case.source"))?,
                "not-a-digest",
            )
            .is_err(),
        );
        failures += usize::from(
            AssumptionRecord::new(
                "   ",
                "statement",
                "scope-580",
                SourceId::new("owner-1").map_err(|_| case_error("case.source"))?,
                TaskId::new("task-580").map_err(|_| case_error("case.task"))?,
                StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            )
            .is_err(),
        );
        failures += usize::from(
            InvestigationRequirement::new(
                "requirement-1",
                PropositionId::new("proposition-580")?,
                "scope-580",
                TaskId::new("task-580").map_err(|_| case_error("case.task"))?,
                StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
                InvestigationKind::ObtainEvidence,
                "   ",
                "reason-1",
            )
            .is_err(),
        );
        failures += usize::from(
            PositionRequest::new(
                "question-580",
                PropositionId::new("proposition-580")?,
                TaskId::new("task-580").map_err(|_| case_error("case.task"))?,
                "attempt-580",
                TaskRevision::genesis(),
                "scope-580",
                ValidityBounds::new("scope-580", None, None, "v1", "file")?,
                StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
                BTreeSet::new(),
            )
            .is_err(),
        );
        Ok::<usize, ContractError>(failures)
    });
    let failures = outcome.map_err(|_| ContractError::Canonicalization)??;
    assert_eq!(failures, 7);
    Ok(())
}
