//! Consumer fixtures: Researcher, Dreamer, and Context roles using only the
//! public contract surface, exactly as the cognitive edge-map prescribes.
use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, ProductId, ReceiptId, RequestId, ResourceGeneration,
    SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_epistemic_contracts::{
    AdmittedKind, AdmittedReceipt, AssumptionRecord, ClaimAuditOutcome, ClaimEntry, ClaimMap,
    ClaimVerdict, ContractError, CurrentEpistemicPosition, Currentness, DisclosureClass,
    EpistemicPositionCandidate, EvidenceGrade, GradeAssignment, InvestigationKind,
    InvestigationRequirement, ManifestId, MemberDisposition, MemberOutcome, PositionAssertability,
    PositionId, PositionRequest, PositionRevision, PrivacyHandling, PropositionId,
    ProvenanceClosure, SourceLineage, SupportDelta, SupportRecord, SupportResult, TemporalRecord,
    TemporalRole, ValidityBounds,
};
use eliot_evidence::{Assertability, EvidenceAuthority};
use eliot_receipts::{WorkScope, WorkScopeId};
type FixtureResult = Result<(), Box<dyn std::error::Error>>;
fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
fn work_scope() -> Result<WorkScope, Box<dyn std::error::Error>> {
    Ok(WorkScope {
        scope_id: WorkScopeId::new("scope-580")?,
        product_id: ProductId::new("product-580")?,
        resource_generation: ResourceGeneration::genesis(),
        state_fence: fence(),
    })
}
fn assert_no_hidden_ops(value: &impl serde::Serialize) -> FixtureResult {
    // Iterative key walk with the generic JSON type inferred: contract code
    // under test never depends on it.
    let root = serde_json::to_value(value)?;
    let forbidden = [
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
        "acquisition",
        "rank",
        "entailment",
        "model",
        "store",
    ];
    let mut stack = vec![&root];
    let mut seen = 0;
    while let Some(current) = stack.pop() {
        if let Some(map) = current.as_object() {
            for (key, nested) in map {
                seen += 1;
                assert!(
                    !forbidden.contains(&key.to_lowercase().as_str()),
                    "hidden operation field present"
                );
                stack.push(nested);
            }
        } else if let Some(items) = current.as_array() {
            stack.extend(items.iter());
        }
    }
    assert!(seen > 0);
    Ok(())
}
fn researcher_role(
    proposition: &PropositionId,
    task: &TaskId,
    validity: &ValidityBounds,
    handles: &BTreeSet<ArtifactId>,
) -> FixtureResult {
    // Researcher drafts the bounded inquiry and its typed follow-ups: a
    // position request plus an investigation requirement, both read-only.
    let inquiry = PositionRequest::new(
        "question-580",
        RequestId::new("request-580")?,
        OperationId::new("operation-580")?,
        "idem-580",
        work_scope()?,
        proposition.clone(),
        task.clone(),
        "attempt-580",
        TaskRevision::genesis(),
        "scope-580",
        validity.clone(),
        fence(),
        handles.clone(),
    )?;
    inquiry.validate()?;
    assert_eq!(inquiry.operation_id.as_str(), "operation-580");
    assert_eq!(inquiry.idempotency_key.as_str(), "idem-580");
    let follow_up = InvestigationRequirement::new(
        "requirement-1",
        proposition.clone(),
        "scope-580",
        task.clone(),
        fence(),
        InvestigationKind::ObtainEvidence,
        "open-route",
        "no route observed the subject",
    )?;
    follow_up.validate()?;
    assert_no_hidden_ops(&inquiry)?;
    assert_no_hidden_ops(&follow_up)?;
    Ok(())
}
fn dreamer_role(
    proposition: &PropositionId,
    task: &TaskId,
    validity: &ValidityBounds,
    handles: &BTreeSet<ArtifactId>,
) -> FixtureResult {
    // Dreamer builds the inert candidate read-only: claim map, support, and
    // assumption records in, no resolver, store, or effect out.
    let assumptions = BTreeSet::from(["assumption-1".to_owned()]);
    let discriminators = BTreeSet::from(["discriminator-1".to_owned()]);
    let entry = ClaimEntry::new(
        eliot_epistemic_contracts::ClaimId::new("claim-a")?,
        digest("claim-a"),
        ClaimVerdict::Accepted,
        ClaimAuditOutcome::Supported,
        BTreeSet::new(),
        None,
        EvidenceAuthority::DeterministicRuntimeTest,
        GradeAssignment::known(EvidenceGrade::Grounded),
        BTreeSet::new(),
        validity.clone(),
        None,
        digest("coverage-claim"),
        handles.clone(),
        BTreeMap::new(),
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        assumptions,
        discriminators,
    )?;
    let admitted = BTreeSet::from([eliot_epistemic_contracts::ClaimId::new("claim-a")?]);
    let map = ClaimMap::new(
        ManifestId::new("manifest-580")?,
        admitted,
        vec![entry.clone()],
        Vec::new(),
        BTreeSet::new(),
    )?;
    let record = SupportRecord::new(
        proposition.clone(),
        SupportResult::Supported,
        handles.clone(),
        validity.clone(),
        GradeAssignment::known(EvidenceGrade::Grounded),
        task.clone(),
        fence(),
        None,
        None,
        None,
        digest("proof-support"),
    )?;
    let held = AssumptionRecord::new(
        "assumption-1",
        "the registry mirrors the snapshot",
        "registry-snapshot",
        "close the world for this read",
        "a stale mirror misstates membership",
        BTreeSet::new(),
        validity.clone(),
        SourceId::new("owner-1")?,
        task.clone(),
        fence(),
    )?;
    let rivals = BTreeSet::from(["rival-1".to_owned()]);
    let draft = EpistemicPositionCandidate::new(
        proposition.clone(),
        TaskRevision::genesis(),
        RequestId::new("request-580")?,
        OperationId::new("operation-580")?,
        "idem-580",
        work_scope()?,
        None,
        task.clone(),
        "attempt-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        "file",
        fence(),
        ManifestId::new("manifest-580")?,
        vec![entry],
        Some(&map),
        digest("coverage-580"),
        BTreeSet::new(),
        vec![record],
        BTreeSet::new(),
        GradeAssignment::known(EvidenceGrade::Grounded),
        EvidenceAuthority::DeterministicRuntimeTest,
        DisclosureClass::Open,
        PrivacyHandling::Unrestricted,
        BTreeSet::new(),
        None,
        digest("proof-candidate"),
        rivals,
        PositionAssertability::HypothesisCandidate,
        None,
    )?;
    draft.validate()?;
    assert_eq!(draft.operation_id, OperationId::new("operation-580")?);
    assert_eq!(draft.idempotency_key.as_str(), "idem-580");
    assert_no_hidden_ops(&draft)?;
    assert_no_hidden_ops(&held)?;
    Ok(())
}
fn context_role(
    _proposition: &PropositionId,
    owner: &SourceId,
    handles: &BTreeSet<ArtifactId>,
) -> FixtureResult {
    // Context reads the admitted projection and its provenance closure: the
    // projection cites its external admission receipt and proves nothing
    // beyond it.
    let envelope = AdmittedReceipt::new(
        ReceiptId::new("receipt-580")?,
        digest("admission-payload"),
        owner.clone(),
        "r1",
        "scope-580",
        fence(),
        digest("evidence-view"),
        digest("coverage-view"),
        digest("conflict-view"),
        digest("proof-view"),
        PositionId::new("position-580")?,
        PositionRevision::genesis(),
    )?;
    let view = CurrentEpistemicPosition::new(
        envelope,
        Currentness::Current,
        BTreeSet::new(),
        eliot_epistemic_contracts::ClaimId::new("claim-a")?,
    )?;
    view.validate()?;
    assert_eq!(view.view_kind, AdmittedKind::CurrentEpistemicPosition);
    assert_eq!(view.admission.receipt_id.as_str(), "receipt-580");
    let challenge = view.admission.existence_challenge()?;
    assert_eq!(challenge.sub_item.as_str(), "admitted.existence");
    let wire = serde_json::to_string(&view)?;
    assert!(wire.contains("CURRENT_EPISTEMIC_POSITION"));
    let sources = BTreeSet::from([SourceId::new("source-a")?]);
    let raw_handles = BTreeSet::from(["raw-1".to_owned()]);
    let revisions = BTreeSet::from(["r1".to_owned()]);
    let stopped = ProvenanceClosure::new(
        handles.clone(),
        sources,
        raw_handles,
        revisions,
        vec![SourceLineage::new(
            SourceId::new("source-a")?,
            "r1",
            digest("content-a"),
            Some("raw-1".to_owned()),
            BTreeSet::new(),
            None,
        )?],
        BTreeMap::from([(ArtifactId::new("handle-1")?, digest("content-a"))]),
        None,
        false,
        Assertability::NonAssertableUnverified,
        "scope-580",
        fence(),
    )?;
    stopped.validate()?;
    // New closure surface through the public API only: role-bound outcomes, exact support deltas,
    // and temporal roles travel with the same read-only fixtures.
    let outcome = MemberOutcome::new(
        ArtifactId::new("handle-1")?,
        "primary",
        MemberDisposition::Observed,
    )?;
    assert_eq!(outcome.role.as_str(), "primary");
    let delta = SupportDelta::new(
        BTreeSet::from([ArtifactId::new("handle-2")?]),
        BTreeSet::new(),
        handles.clone(),
        BTreeSet::from(["fresh read".to_owned()]),
    )?;
    delta.validate()?;
    let staged = TemporalRecord::new(10, 11, 12, 13, 14)?;
    assert_eq!(staged.role_time(TemporalRole::Event), 10);
    let view_value = serde_json::to_value(&view)?;
    assert!(
        view_value
            .as_object()
            .is_some_and(|map| map.contains_key("admission"))
    );
    assert_no_hidden_ops(&stopped)?;
    Ok(())
}
// WORK_UNIT_CASE: 580/45
#[test]
fn consumer_roles_use_public_contracts_without_hidden_ops() -> FixtureResult {
    let proposition = PropositionId::new("proposition-580")?;
    let task = TaskId::new("task-580")?;
    let owner = SourceId::new("owner-1")?;
    let validity = ValidityBounds::new("scope-580", Some(100), Some(200), "v1", "file")?;
    let handle_set = BTreeSet::from([ArtifactId::new("handle-1")?]);
    researcher_role(&proposition, &task, &validity, &handle_set)?;
    // Dreamer builds the inert candidate read-only: claim map, support, and
    // assumption records in, no resolver, store, or effect out.
    dreamer_role(&proposition, &task, &validity, &handle_set)?;
    // Context reads the admitted projection and its provenance closure: the
    // projection cites its external admission receipt and proves nothing
    // beyond it.
    context_role(&proposition, &owner, &handle_set)?;
    // The public surface offers contracts, not operations.
    let surface = [
        std::any::type_name::<PositionRequest>(),
        std::any::type_name::<InvestigationRequirement>(),
        std::any::type_name::<AssumptionRecord>(),
        std::any::type_name::<ClaimMap>(),
        std::any::type_name::<SupportRecord>(),
        std::any::type_name::<EpistemicPositionCandidate>(),
        std::any::type_name::<CurrentEpistemicPosition>(),
        std::any::type_name::<ProvenanceClosure>(),
        std::any::type_name::<PositionAssertability>(),
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
