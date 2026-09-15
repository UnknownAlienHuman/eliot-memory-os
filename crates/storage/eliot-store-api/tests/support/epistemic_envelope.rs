//! Neutral envelope fixture shared by reference and real-provider Store tests.
use eliot_canonical::{CanonicalWriteEnvelope, epistemic_revision::epistemic_revision_command};
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
    TaskId, TaskRevision,
};
use eliot_epistemic_contracts::*;
use eliot_evidence::EvidenceAuthority;
use eliot_receipts::{WorkScope, WorkScopeId};
use eliot_store_api::*;
use eliot_store_api::{SecurityContext, TransitionClass, operation_manifest_set_digest};
use std::collections::{BTreeMap, BTreeSet};

type ProofResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[allow(
    clippy::too_many_lines,
    reason = "One explicit typed fixture keeps every boundary field visible without implicit defaults."
)]
pub fn envelope(
    operation: &str,
    position: &str,
    expected: Option<PositionRevision>,
    predecessor: Option<&str>,
) -> ProofResult<CanonicalWriteEnvelope> {
    let fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?,
            std::num::NonZeroU64::MIN,
        )?,
        ResourceGeneration::genesis(),
    );
    let task_id = TaskId::new("task")?;
    let request_id = RequestId::new(operation)?;
    let operation_id = OperationId::new(operation)?;
    let work_scope = WorkScope {
        scope_id: WorkScopeId::new("scope")?,
        product_id: ProductId::new("product")?,
        resource_generation: ResourceGeneration::genesis(),
        state_fence: fence.clone(),
    };
    let handles = BTreeSet::from([ArtifactId::new("observed-source")?]);
    let bounds = ValidityBounds::new("scope", None, None, "v1", Precision("record".to_owned()))?;
    let grade = GradeAssignment::unknown("observation retained without truth promotion")?;
    let proof = sha256_hex(b"captured exact source bytes");
    let coverage_digest = sha256_hex(b"bounded coverage fixture");
    let claim = ClaimEntry::new(ClaimEntryParams {
        claim: ClaimId::new("claim")?,
        statement_digest: sha256_hex(b"observed proposition"),
        verdict: ClaimVerdict::Withheld,
        audit: ClaimAuditOutcome::NotVerifiableInScope,
        counterevidence: BTreeSet::new(),
        conflict: None,
        authority: EvidenceAuthority::SourceIdentity,
        grade: grade.clone(),
        dependencies: BTreeSet::new(),
        bounds: bounds.clone(),
        temporal: None,
        coverage_digest: coverage_digest.clone(),
        support: handles.clone(),
        components: BTreeMap::new(),
        unresolved_support: BTreeSet::from(["verification".to_owned()]),
        ceiling: EvidenceGrade::Orienting,
        assumptions: BTreeSet::new(),
        discriminators: BTreeSet::new(),
    })?;
    let map = ClaimMap::new(
        ManifestId::new("claims")?,
        BTreeSet::from([claim.claim.clone()]),
        vec![claim.clone()],
        Vec::new(),
        BTreeSet::new(),
    )?;
    let support = SupportRecord::new(SupportRecordParams {
        proposition: PropositionId::new("proposition")?,
        result: SupportResult::Unknown,
        handles: handles.clone(),
        validity: bounds,
        grade: grade.clone(),
        task_id: task_id.clone(),
        fence: fence.clone(),
        temporal: None,
        assurance: None,
        reopen_reason: None,
        proof_digest: proof.clone(),
    })?;
    let candidate = EpistemicPositionCandidate::new(EpistemicPositionCandidateParams {
        proposition: support.proposition.clone(),
        revision: TaskRevision::genesis(),
        request_id: request_id.clone(),
        operation_id: operation_id.clone(),
        idempotency_key: operation.to_owned(),
        work_scope: work_scope.clone(),
        predecessor: predecessor.map(PredecessorId::new).transpose()?,
        task_id: task_id.clone(),
        attempt_id: operation.to_owned(),
        scope: "scope".to_owned(),
        window_start_ms: None,
        window_end_ms: None,
        version: "v1".to_owned(),
        precision: "record".to_owned(),
        fence: fence.clone(),
        manifest: map.manifest.clone(),
        claims: vec![claim],
        claim_map: Some(map),
        coverage_digest,
        conflict_digests: BTreeSet::new(),
        support: vec![support],
        unknowns: BTreeSet::from(["verification".to_owned()]),
        grade,
        authority: EvidenceAuthority::SourceIdentity,
        disclosure: DisclosureClass::Open,
        privacy: PrivacyHandling::Unrestricted,
        temporal_digests: BTreeSet::new(),
        verifier: None,
        proof_digest: proof.clone(),
        rivals: BTreeSet::new(),
        proposed_assertability: PositionAssertability::UnknownWithheldQuarantined,
        invalidation: None,
    })?;
    let transition = EpistemicTransition::new(EpistemicTransitionParams {
        position: candidate.proposition.clone(),
        task_id: task_id.clone(),
        attempt_id: operation.to_owned(),
        request_id: request_id.clone(),
        idempotency_key: operation.to_owned(),
        work_scope,
        candidate_digest: candidate.digest.clone(),
        expected_revision: TaskRevision::genesis(),
        expected_fence: fence.clone(),
        trigger: TransitionTrigger::NewEvidence,
        evidence_refs: handles.clone(),
        operation: operation_id.clone(),
        before_support: SupportResult::Unknown,
        after_support: SupportResult::Unknown,
        before_assertability: PositionAssertability::UnknownWithheldQuarantined,
        after_assertability: candidate.proposed_assertability,
        delta: SupportDelta::new(
            handles,
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from(["source change".to_owned()]),
        )?,
        coverage_delta_digest: candidate.coverage_digest.clone(),
        conflict_delta_digest: sha256_hex(b"no conflicts"),
        temporal: None,
        rollback: "restore prior withheld view".to_owned(),
        repair: None,
        invalidation: None,
        proof_digest: proof,
    })?;
    Ok(CanonicalWriteEnvelope {
        operation_id,
        request: RequestMeta {
            request_id,
            session_id: None,
            task_id: Some(task_id),
            product_id: ProductId::new("product")?,
            source_id: SourceId::new("governor")?,
            state_fence: fence.clone(),
            clock: eliot_contracts::ClockReading::default(),
        },
        idempotency_key: operation.to_owned(),
        scope_id: ScopeId::new("scope")?,
        task_id: Some("task".to_owned()),
        transition_class: TransitionClass::Epistemic,
        requested_effect_ceiling: TransitionClass::Epistemic.maximum_effect(),
        admission_contract_set_digest: sha256_hex(b"reference admission fixture"),
        operation_manifest_digest: operation_manifest_set_digest(&generated_operation_manifests()?)?,
        semantic_commands: vec![epistemic_revision_command(
            PositionId::new(position)?,
            expected,
            &transition,
            &candidate,
        )?],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: vec![EventId::new(operation)?],
            projection_kinds: vec!["CurrentEpistemicPosition".to_owned()],
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec!["observed-source".to_owned()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(format!("order-{operation}"))?,
            expected_sequence: 1,
            state_fence: fence,
        }],
    })
}
