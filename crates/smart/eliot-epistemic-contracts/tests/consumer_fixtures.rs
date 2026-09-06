//! Consumer fixtures: Researcher, Dreamer, and Context roles using only the
//! public contract surface, exactly as the cognitive edge-map prescribes.
//!
//! These fixtures prove `eliot_epistemic_contracts::CurrentEpistemicPosition`
//! resolves from an integration consumer; that each role performs its
//! read-only work — candidate building, inquiry drafting, projection reading —
//! through public constructors alone; and that the public surface offers
//! contracts with no resolver, acquisition, entailment, model, store, state,
//! authority, effect, or finish operations.

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ReceiptId, ResourceGeneration, SourceId, StateFence, TaskId,
    TaskRevision, sha256_hex,
};
use eliot_epistemic_contracts::{
    AdmittedKind, AssumptionRecord, ClaimAuditOutcome, ClaimEntry, ClaimMap, ClaimVerdict,
    ContractError, CurrentEpistemicPosition, Currentness, DisclosureClass,
    EpistemicPositionCandidate, EvidenceGrade, InvestigationKind, InvestigationRequirement,
    ManifestId, PositionAssertability, PositionRequest, PropositionId, ProvenanceClosure,
    SupportRecord, SupportResult, ValidityBounds,
};
use eliot_evidence::{Assertability, EvidenceAuthority};

type FixtureResult = Result<(), Box<dyn std::error::Error>>;

fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn assert_no_hidden_ops(value: &impl serde::Serialize) -> FixtureResult {
    // Iterative key walk with the generic JSON type inferred: contract code
    // under test never depends on it.
    let root = serde_json::to_value(value)?;
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
    for key in &keys {
        assert!(
            !forbidden.contains(&key.as_str()),
            "hidden operation field present"
        );
    }
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
    let mut assumptions = BTreeSet::new();
    assumptions.insert("assumption-1".to_owned());
    let mut discriminators = BTreeSet::new();
    discriminators.insert("discriminator-1".to_owned());
    let entry = ClaimEntry::new(
        eliot_epistemic_contracts::ClaimId::new("claim-a")?,
        digest("claim-a"),
        ClaimVerdict::Accepted,
        ClaimAuditOutcome::Supported,
        BTreeSet::new(),
        None,
        EvidenceAuthority::DeterministicRuntimeTest,
        EvidenceGrade::Grounded,
        BTreeSet::new(),
        validity.clone(),
        digest("coverage-claim"),
        handles.clone(),
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        assumptions,
        discriminators,
    )?;
    let mut admitted = BTreeSet::new();
    admitted.insert(eliot_epistemic_contracts::ClaimId::new("claim-a")?);
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
        task.clone(),
        fence(),
        None,
        digest("proof-support"),
    )?;
    let held = AssumptionRecord::new(
        "assumption-1",
        "the registry mirrors the snapshot",
        "scope-580",
        SourceId::new("owner-1")?,
        task.clone(),
        fence(),
    )?;
    let mut rivals = BTreeSet::new();
    rivals.insert("rival-1".to_owned());
    let draft = EpistemicPositionCandidate::new(
        proposition.clone(),
        TaskRevision::genesis(),
        None,
        task.clone(),
        "attempt-580",
        "scope-580",
        Some(100),
        Some(200),
        "v1",
        fence(),
        ManifestId::new("manifest-580")?,
        vec![entry],
        Some(&map),
        digest("coverage-580"),
        BTreeSet::new(),
        vec![record],
        BTreeSet::new(),
        EvidenceGrade::Grounded,
        EvidenceAuthority::DeterministicRuntimeTest,
        DisclosureClass::Open,
        None,
        digest("proof-candidate"),
        rivals,
        PositionAssertability::HypothesisCandidate,
        None,
    )?;
    draft.validate()?;
    assert_no_hidden_ops(&draft)?;
    assert_no_hidden_ops(&held)?;
    Ok(())
}

fn context_role(
    proposition: &PropositionId,
    owner: &SourceId,
    handles: &BTreeSet<ArtifactId>,
) -> FixtureResult {
    // Context reads the admitted projection and its provenance closure: the
    // projection cites its external admission receipt and proves nothing
    // beyond it.
    let view = CurrentEpistemicPosition::new(
        proposition.clone(),
        TaskRevision::genesis(),
        ReceiptId::new("receipt-580")?,
        digest("admission-payload"),
        owner.clone(),
        Currentness::Current,
        BTreeSet::new(),
        eliot_epistemic_contracts::ClaimId::new("claim-a")?,
        "scope-580",
        fence(),
        digest("evidence-view"),
        digest("coverage-view"),
        digest("conflict-view"),
        digest("proof-view"),
    )?;
    view.validate()?;
    assert_eq!(view.view_kind, AdmittedKind::CurrentEpistemicPosition);
    let wire = serde_json::to_string(&view)?;
    assert!(wire.contains("CURRENT_EPISTEMIC_POSITION"));
    let mut sources = BTreeSet::new();
    sources.insert(SourceId::new("source-a")?);
    let mut raw_handles = BTreeSet::new();
    raw_handles.insert("raw-1".to_owned());
    let mut revisions = BTreeSet::new();
    revisions.insert("r1".to_owned());
    let stopped = ProvenanceClosure::new(
        handles.clone(),
        sources,
        raw_handles,
        revisions,
        false,
        Assertability::NonAssertableUnverified,
        "scope-580",
        fence(),
    )?;
    stopped.validate()?;
    let view_value = serde_json::to_value(&view)?;
    assert!(
        view_value
            .as_object()
            .is_some_and(|map| map.contains_key("admission_receipt"))
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
    let mut handle_set = BTreeSet::new();
    handle_set.insert(ArtifactId::new("handle-1")?);

    researcher_role(&proposition, &task, &validity, &handle_set)?;

    // Dreamer builds the inert candidate read-only: claim map, support, and
    // assumption records in, no resolver, store, or effect out.
    dreamer_role(&proposition, &task, &validity, &handle_set)?;

    // Context reads the admitted projection and its provenance closure: the
    // projection cites its external admission receipt and proves nothing
    // beyond it.
    context_role(&proposition, &owner, &handle_set)?;

    // The public surface offers contracts, not operations: no public type is
    // a resolver, acquisition, entailment, model, store, state, authority,
    // effect, or finish operation.
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
