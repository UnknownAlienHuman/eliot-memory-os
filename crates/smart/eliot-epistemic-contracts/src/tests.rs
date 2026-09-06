//! Work-unit case coverage for the epistemic contracts boundary.
//!
//! One substantive test per assignment case. Fixtures build fully valid
//! records through the public constructors; negative cases mutate exactly one
//! load-bearing property and assert the exact closed error.

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceAuthority;
use serde::{Deserialize, Serialize};

use crate::absence::{AbsenceClaim, BoundedProof, OwnerLookup};
use crate::admitted::{AdmittedKind, CurrentEpistemicPositionView, Currentness};
use crate::assertability::PositionAssertability;
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
use crate::error::{ContractError, MAX_HANDLES, MAX_SHORT_TEXT};
use crate::grade::{EvidenceGrade, GRADE_ORDER, GradeAssignment};
use crate::identity::{
    ClaimId, EvidenceSetId, IdentityBundle, LineageRootId, ManifestId, PredecessorId,
    PropositionId, SourceRevisionId, TransformedLineage, ValidityId,
};
use crate::receipt::{CoverageReceipt, MemberDisposition, MemberOutcome, OmittedMember};
use crate::support::{SupportRecord, SupportResult, ValidityBounds, weakest_link};
use crate::temporal::{TemporalPrecedence, TemporalRecord, TemporalRole};
use crate::transition::{
    EpistemicTransition, InvalidationKind, InvalidationRecord, SupportDelta, TransitionTrigger,
};

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
        None,
        SnapshotRef::new("snapshot-1", source("owner-1")?)?,
        Vec::new(),
        PaginationBounds::new(0, 2, 2, false)?,
        validity()?,
        DenominatorKind::CompleteScope,
    )
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
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen_digest,
        DenominatorKind::CompleteScope,
        case_digest("query-text"),
        "snapshot-1",
        receipt,
        BoundedProof::new(case_digest("proof-absence"), 128)?,
    )
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
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    EpistemicPositionCandidate::new(
        prop()?,
        TaskRevision::genesis(),
        None,
        task()?,
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        case_fence(),
        ManifestId::new("manifest-580")?,
        vec![claim_entry("claim-a")?],
        Some(&map),
        case_digest("coverage-candidate"),
        BTreeSet::new(),
        vec![support_record(SupportResult::Supported)?],
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        EvidenceAuthority::DeterministicRuntimeTest,
        case_digest("proof-candidate"),
        rivals,
        PositionAssertability::QualifiedInference,
        None,
    )
}

fn admitted() -> Result<CurrentEpistemicPositionView, ContractError> {
    CurrentEpistemicPositionView::new(
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

// WORK_UNIT_CASE: 580/8
#[test]
fn variable_field_boundaries_and_one_over() -> CaseResult {
    let at_max = "x".repeat(MAX_SHORT_TEXT);
    ValidityBounds::new("scope-580", None, None, "v1", at_max.as_str())?;
    let one_over = "x".repeat(MAX_SHORT_TEXT + 1);
    assert_eq!(
        ValidityBounds::new("scope-580", None, None, "v1", one_over.as_str()),
        Err(ContractError::TooLong {
            field: "support.precision",
        })
    );
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
    assert!(bounds.covers("scope-580", Some(150)));
    assert!(!bounds.covers("scope-other", Some(150)));
    assert!(!bounds.covers("scope-580", Some(50)));
    assert!(!bounds.covers("scope-580", Some(250)));
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
    let unowned_empty = CoverageDenominator::new(
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
        DenominatorKind::CompleteScope,
    );
    assert_eq!(
        unowned_empty,
        Err(ContractError::IncompleteDenominator {
            field: "coverage.members",
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
    let claim = absence()?;
    claim.validate()?;
    assert!(claim.receipt.is_terminal());
    claim.check_context(
        "scope-580",
        &case_fence(),
        case_digest("query-text").as_str(),
        "snapshot-1",
    )?;
    Ok(())
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
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen.digest.clone(),
        DenominatorKind::SampledWithMethod,
        case_digest("query-text"),
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
    let mut groups = BTreeSet::new();
    groups.insert("group-1".to_owned());
    let exhausted_receipt = CoverageReceipt::new(
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
            MemberOutcome::new(artifact("member-2")?, MemberDisposition::Exhaustion),
        ],
        Vec::new(),
        case_digest("proof-receipt"),
    )?;
    let exhausted = AbsenceClaim::new(
        prop()?,
        "domain-580",
        "scope-580",
        None,
        None,
        "v1",
        OwnerLookup::new(source("owner-1")?, case_digest("lookup-580"))?,
        frozen.digest.clone(),
        DenominatorKind::CompleteScope,
        case_digest("query-text"),
        "snapshot-1",
        exhausted_receipt,
        BoundedProof::new(case_digest("proof-absence"), 64)?,
    );
    assert_eq!(
        exhausted,
        Err(ContractError::ImpossibleCombination {
            field: "absence.receipt",
        })
    );
    Ok(())
}

// WORK_UNIT_CASE: 580/24
#[test]
fn changed_query_scope_fence_snapshot_invalidates_absence() -> CaseResult {
    let claim = absence()?;
    let live_query = case_digest("query-text");
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
    );
    assert_eq!(
        attempt,
        Err(ContractError::OutsideManifest {
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
    );
    assert_eq!(
        changed,
        Err(ContractError::Duplicate {
            field: "claim.entries",
        })
    );
    Ok(())
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
    );
    assert_eq!(
        attempt,
        Err(ContractError::MissingReference {
            field: "claim.dependencies",
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

// WORK_UNIT_CASE: 580/31
#[test]
fn causal_needs_mechanism_rivals_evidence() -> CaseResult {
    causal()?.validate()?;
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    let mut evidence_refs = BTreeSet::new();
    evidence_refs.insert(artifact("evidence-1")?);
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
    Ok(())
}

// WORK_UNIT_CASE: 580/35
#[test]
fn candidate_carries_no_admission_write_effect_finish() -> CaseResult {
    let lowered = encoded(&candidate()?)?.to_lowercase();
    for forbidden in ["admission", "write", "effect", "finish", "alloc", "apply"] {
        assert!(!lowered.contains(forbidden));
    }
    Ok(())
}

// WORK_UNIT_CASE: 580/36
#[test]
fn valid_admitted_view_with_receipt() -> CaseResult {
    let view = admitted()?;
    view.validate()?;
    assert_eq!(view.view_kind, AdmittedKind::CurrentEpistemicPositionView);
    let (receipt, digest) = view.receipt_identity();
    assert_eq!(receipt, &admission()?);
    assert_eq!(digest, case_digest("admission-payload").as_str());
    assert_eq!(view.currentness, Currentness::Current);
    let mut superseded = view.clone();
    superseded.currentness = Currentness::Superseded;
    assert!(superseded.validate().is_err());
    Ok(())
}

// WORK_UNIT_CASE: 580/37
#[test]
fn candidate_admitted_no_cross_decode() -> CaseResult {
    let candidate_json = encoded(&candidate()?)?;
    let view_json = encoded(&admitted()?)?;
    assert!(serde_json::from_str::<CurrentEpistemicPositionView>(&candidate_json).is_err());
    assert!(serde_json::from_str::<EpistemicPositionCandidate>(&view_json).is_err());
    assert!(candidate_json.contains("EPISTEMIC_POSITION_CANDIDATE"));
    assert!(view_json.contains("CURRENT_EPISTEMIC_POSITION_VIEW"));
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
    assert!(serde_json::from_str::<SupportResult>("\"SUPPORTED \"").is_err());
    assert!(serde_json::from_str::<MemberDisposition>("\"LIVE\"").is_err());
    assert!(serde_json::from_str::<ValidityBounds>("{\"scope\"").is_err());
    let control_scope = "{\"scope\":\"a\u{7}b\",\"window_start_ms\":null,\"window_end_ms\":null,\"version\":\"v1\",\"precision\":\"file\"}";
    assert!(serde_json::from_str::<ValidityBounds>(control_scope).is_err());
    let overflow =
        "{\"offset\":0,\"limit\":99999999999999999999999,\"total\":2,\"truncated\":true}";
    assert!(serde_json::from_str::<PaginationBounds>(overflow).is_err());
    assert!(PaginationBounds::new(0, 0, 2, true).is_err());
    assert!(PaginationBounds::new(5, 1, 2, true).is_err());
    assert!(BoundedProof::new(case_digest("proof-absence"), u64::MAX).is_err());
    assert!(OwnerLookup::new(source("owner-1")?, "not-a-digest").is_err());
    Ok(())
}

// WORK_UNIT_CASE: 580/45
#[test]
fn consumer_compile_fixtures_without_forbidden_symbols() -> CaseResult {
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResearcherPositionView {
        position: PropositionId,
        grade: EvidenceGrade,
        support: SupportResult,
    }
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DreamerPositionView {
        proposition: PropositionId,
        assertability: PositionAssertability,
        unknowns: BTreeSet<String>,
    }
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ContextPositionPacket {
        researcher: ResearcherPositionView,
        dreamer: DreamerPositionView,
        coverage: String,
    }
    let mut unknowns = BTreeSet::new();
    unknowns.insert("open-route".to_owned());
    let packet = ContextPositionPacket {
        researcher: ResearcherPositionView {
            position: prop()?,
            grade: EvidenceGrade::Grounded,
            support: SupportResult::Partial,
        },
        dreamer: DreamerPositionView {
            proposition: prop()?,
            assertability: PositionAssertability::HypothesisCandidate,
            unknowns,
        },
        coverage: case_digest("coverage-view"),
    };
    let decoded: ContextPositionPacket =
        serde_json::from_str(&encoded(&packet)?).map_err(|_| ContractError::Canonicalization)?;
    assert_eq!(decoded, packet);
    let surface = [
        std::any::type_name::<IdentityBundle>(),
        std::any::type_name::<EvidenceGrade>(),
        std::any::type_name::<SupportRecord>(),
        std::any::type_name::<CoverageDenominator>(),
        std::any::type_name::<CoverageReceipt>(),
        std::any::type_name::<AbsenceClaim>(),
        std::any::type_name::<ClaimMap>(),
        std::any::type_name::<TemporalRecord>(),
        std::any::type_name::<CausalClaim>(),
        std::any::type_name::<ConflictSet>(),
        std::any::type_name::<EpistemicPositionCandidate>(),
        std::any::type_name::<CurrentEpistemicPositionView>(),
        std::any::type_name::<PositionAssertability>(),
        std::any::type_name::<EpistemicTransition>(),
        std::any::type_name::<ContractError>(),
    ];
    let forbidden = [
        "Resolver",
        "Acquisition",
        "Entailment",
        "Model",
        "Store",
        "State",
        "Authority",
        "Effect",
        "Finish",
    ];
    for name in surface {
        let short = name.rsplit("::").next().unwrap_or(name);
        for blocked in forbidden {
            assert_ne!(short, blocked);
        }
    }
    Ok(())
}
