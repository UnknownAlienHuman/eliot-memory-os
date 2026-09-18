use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence, TaskRevision,
};
use eliot_memory_curation_contracts::*;
use eliot_receipts::WorkScopeId;

fn must<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("fixture failed: {error:?}"))
}

fn must_some<T>(option: Option<T>) -> T {
    option.unwrap_or_else(|| panic!("fixture failed: unexpected none"))
}

fn digest() -> Digest {
    must(Digest::new(
        "0000000000000000000000000000000000000000000000000000000000000000",
    ))
}

fn seed_digest(seed: &str) -> Digest {
    must(Digest::from_bytes(seed.as_bytes()))
}

fn u64len<T>(items: &[T]) -> u64 {
    u64::try_from(items.len()).unwrap_or_else(|_| panic!("fixture too long"))
}

fn fence() -> StateFence {
    fence_with_lineage("550e8400-e29b-41d4-a716-446655440000")
}

fn fence_alt() -> StateFence {
    fence_with_lineage("660e8400-e29b-41d4-a716-446655440000")
}

fn fence_with_lineage(lineage: &str) -> StateFence {
    let epoch = must(EpochId::new(
        must(EpochLineageId::new(lineage)),
        must_some(std::num::NonZeroU64::new(1)),
    ));
    let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
    fence.policy_revision = Some(PolicyRevision::genesis());
    fence
}

fn member(index: usize) -> SourceMember {
    SourceMember {
        member_id: must(MemberId::new(format!("member-{index}"))),
        kind: SourceMemberKind::Observation,
        revision: TaskRevision::genesis(),
        content_digest: seed_digest(&format!("content-{index}")),
        evidence: MemberEvidenceRefs::default(),
    }
}

fn snapshot_identity(tag: &str) -> SourceIdentity {
    SourceIdentity {
        product_id: must(ProductId::new("eliot")),
        source_id: must(SourceId::new("canonical-memory")),
        snapshot_id: must(SnapshotId::new(format!("snapshot-{tag}"))),
        query: QueryIdentity {
            query_id: must(QueryId::new(format!("query-{tag}"))),
            query_digest: seed_digest(&format!("query-{tag}")),
        },
        revision: 1,
        digest: seed_digest(&format!("snapshot-digest-{tag}")),
        scope: must(WorkScopeId::new("test-scope")),
        state_fence: fence(),
    }
}

fn snap(count: usize) -> SourceSnapshot {
    snap_split(count, count, "1")
}

fn snap_split(count: usize, changed: usize, tag: &str) -> SourceSnapshot {
    let members: Vec<SourceMember> = (0..count).map(member).collect();
    let declared: Vec<MemberId> = members.iter().map(|item| item.member_id.clone()).collect();
    let changed_targets: BTreeSet<MemberId> = declared.iter().take(changed).cloned().collect();
    let immutable_references: BTreeSet<MemberId> = declared.iter().skip(changed).cloned().collect();
    SourceSnapshot {
        identity: snapshot_identity(tag),
        denominator: FiniteDenominator {
            coverage: DenominatorCoverage::Complete,
            total_members: u64len(&declared),
            declared_member_ids: declared,
        },
        partition: MemberPartition {
            changed_targets,
            immutable_references,
        },
        availability: SourceAvailability::Available,
        members,
        page: SourcePage {
            page_number: 0,
            has_more: false,
            frontier: Vec::new(),
        },
    }
}

fn snap_partial(count: usize) -> SourceSnapshot {
    let mut snapshot = snap(count);
    snapshot.denominator.coverage = DenominatorCoverage::Partial;
    snapshot.denominator.total_members = u64len(&snapshot.members) + 1;
    snapshot.availability = SourceAvailability::Partial;
    snapshot
}

fn rule_first() -> RuleId {
    must(RuleId::new("rule-1"))
}

fn rule_second() -> RuleId {
    must(RuleId::new("rule-2"))
}

fn prof() -> ScreenProfile {
    ScreenProfile {
        profile_id: must(ProfileId::new("profile-1")),
        schema_revision: PolicyRevision::genesis(),
        policy_revision: PolicyRevision::genesis(),
        rules: vec![
            RuleSpec {
                rule_id: rule_first(),
                finding_class: FindingClass::Duplicate,
                precedence: 1,
                required_protection: BTreeSet::from([ProtectionClass::CurrentTruth]),
            },
            RuleSpec {
                rule_id: rule_second(),
                finding_class: FindingClass::ProvenanceGap,
                precedence: 2,
                required_protection: BTreeSet::new(),
            },
        ],
        requested_findings: BTreeSet::from([FindingClass::Duplicate, FindingClass::ProvenanceGap]),
        precedence: vec![rule_first(), rule_second()],
        limits: ScreenLimits {
            max_items: 10,
            max_references: 10,
            max_bytes: 10_000,
            max_work_units: 10,
            max_output_bytes: 10_000,
            deadline_ms: Some(100),
            cancellation_grace_ms: Some(10),
        },
    }
}

fn req(snapshot: &SourceSnapshot) -> CurationScreenRequest {
    CurationScreenRequest {
        source: snapshot.identity.clone(),
        denominator: snapshot.denominator.clone(),
        partition: snapshot.partition.clone(),
        binding: RequestBinding {
            request_id: must(RequestId::new("request-1")),
            operation_id: must(OperationId::new("operation-1")),
            task_id: None,
            attempt_id: must(AgentAttemptId::new("attempt-1")),
            scope: snapshot.identity.scope.clone(),
            state_fence: snapshot.identity.state_fence.clone(),
        },
        profile: prof(),
        cursor: None,
        cancellation_requested: false,
    }
}

fn ev(
    snapshot: &SourceSnapshot,
    member_id: &MemberId,
    tag: &str,
    class: ProtectionClass,
    state: ProtectionEvidenceState,
    outcome: ProtectionOutcome,
) -> ProtectionEvidence {
    ProtectionEvidence {
        evidence_id: must(ProtectionEvidenceId::new(format!("ev-{tag}"))),
        member_id: member_id.clone(),
        source_id: snapshot.identity.source_id.clone(),
        snapshot_id: snapshot.identity.snapshot_id.clone(),
        class,
        state,
        outcome,
        references: BTreeSet::new(),
        state_fence: snapshot.identity.state_fence.clone(),
        scope: snapshot.identity.scope.clone(),
        disclosure_ceiling: DisclosureCeiling::ReferenceOnly,
        invalidated_by: None,
        digest: seed_digest(&format!("ev-digest-{tag}")),
    }
}

fn assess(
    snapshot: &SourceSnapshot,
    member_id: &MemberId,
    tag: &str,
    decision: ProtectionDecision,
    outcome: ProtectionOutcome,
) -> ProtectionAssessment {
    ProtectionAssessment {
        source: snapshot.identity.clone(),
        member_id: member_id.clone(),
        applicable_rule_ids: BTreeSet::from([rule_first()]),
        required: BTreeSet::from([ProtectionClass::CurrentTruth]),
        evidence: vec![ev(
            snapshot,
            member_id,
            tag,
            ProtectionClass::CurrentTruth,
            ProtectionEvidenceState::CurrentVerified,
            outcome,
        )],
        decision,
    }
}

fn find(
    snapshot: &SourceSnapshot,
    profile: &ScreenProfile,
    member_id: &MemberId,
    tag: &str,
    rule: &RuleId,
    class: FindingClass,
) -> CurationFinding {
    CurationFinding {
        finding_id: must(FindingId::new(format!("finding-{tag}"))),
        source: snapshot.identity.clone(),
        profile_id: profile.profile_id.clone(),
        member_id: member_id.clone(),
        rule_id: rule.clone(),
        class,
        evidence: BTreeSet::new(),
        invariant: format!("invariant-{tag}"),
        proof: FindingProof::Deterministic,
        invalidated_by: None,
        digest: seed_digest(&format!("finding-digest-{tag}")),
    }
}

fn elig(
    snapshot: &SourceSnapshot,
    member_id: &MemberId,
    protection: ProtectionDecision,
    status: EligibilityStatus,
) -> Eligibility {
    Eligibility {
        source: snapshot.identity.clone(),
        member_id: member_id.clone(),
        protection,
        finding_ids: BTreeSet::new(),
        status,
    }
}

fn usage(processed: u64) -> WorkUsage {
    WorkUsage {
        processed_items: processed,
        work_units: processed,
        input_bytes: processed,
        output_bytes: processed,
    }
}

fn coverage_full(snapshot: &SourceSnapshot, dispositions: &[MemberDisposition]) -> ScreenCoverage {
    assert_eq!(snapshot.members.len(), dispositions.len());
    let members: Vec<MemberCoverage> = snapshot
        .members
        .iter()
        .zip(dispositions.iter())
        .map(|(item, disposition)| MemberCoverage {
            member_id: item.member_id.clone(),
            disposition: *disposition,
            finding_ids: BTreeSet::new(),
            eligible: *disposition == MemberDisposition::Eligible,
        })
        .collect();
    let processed = u64::try_from(
        members
            .iter()
            .filter(|item| item.disposition != MemberDisposition::Unprocessed)
            .count(),
    )
    .unwrap_or_else(|_| panic!("fixture too long"));
    let remaining: Vec<MemberId> = members
        .iter()
        .filter(|item| item.disposition == MemberDisposition::Unprocessed)
        .map(|item| item.member_id.clone())
        .collect();
    let frontier = ScreenFrontier {
        complete: remaining.is_empty(),
        remaining,
    };
    let mut coverage = ScreenCoverage {
        denominator: snapshot.denominator.clone(),
        start_position: 0,
        members,
        frontier,
        usage: usage(processed),
        next_cursor: None,
        digest: digest(),
    };
    coverage.digest = must(coverage.computed_digest());
    coverage
}

fn result_skeleton(
    snapshot: &SourceSnapshot,
    request: CurationScreenRequest,
    coverage: ScreenCoverage,
    state: ResultState,
) -> CurationScreenResult {
    let mut result = CurationScreenResult {
        request,
        source: snapshot.clone(),
        findings: Vec::new(),
        protection: Vec::new(),
        eligibility: Vec::new(),
        coverage,
        member_sets: MemberSets {
            changed_targets: BTreeSet::new(),
            immutable_references: BTreeSet::new(),
        },
        state,
        result_digest: digest(),
    };
    result.member_sets.changed_targets = result.request.partition.changed_targets.clone();
    result.member_sets.immutable_references = result.request.partition.immutable_references.clone();
    resign(&mut result);
    result
}

fn resign(result: &mut CurationScreenResult) {
    result.coverage.digest = must(result.coverage.computed_digest());
    result.result_digest = must(result.computed_digest());
}

fn cursor_gen(
    request: &CurationScreenRequest,
    snapshot: &SourceSnapshot,
    processed: &[MemberId],
    budget: WorkUsage,
    predecessor: Option<Digest>,
) -> CumulativeCursor {
    CumulativeCursor {
        request_id: request.binding.request_id.clone(),
        request_fingerprint: must(request.request_fingerprint()),
        snapshot_id: snapshot.identity.snapshot_id.clone(),
        query: snapshot.identity.query.clone(),
        source_revision: snapshot.identity.revision,
        source_digest: snapshot.identity.digest.clone(),
        profile_id: request.profile.profile_id.clone(),
        profile_digest: must(contract_digest(&request.profile)),
        denominator: request.denominator.clone(),
        scope: snapshot.identity.scope.clone(),
        state_fence: snapshot.identity.state_fence.clone(),
        processed_member_digest: must(contract_digest(&processed)),
        position: u64len(processed),
        usage: budget,
        predecessor,
    }
}

fn roundtrip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let encoded = must(serde_json::to_string(value));
    must(serde_json::from_str(&encoded))
}

fn with_unknown_field(encoded: &str) -> String {
    with_field(encoded, "\"unexpected\":true")
}

fn with_field(base: &str, extra: &str) -> String {
    let trimmed = must_some(base.strip_suffix('}'));
    format!("{trimmed},{extra}}}")
}

fn without_field(encoded: &str, marker: &str) -> String {
    match encoded.find(marker) {
        Some(index) => format!("{}{}", &encoded[..index], "}"),
        None => panic!("fixture marker missing: {marker}"),
    }
}

fn schema_text<T: schemars::JsonSchema>() -> String {
    must(serde_json::to_string(&schemars::schema_for!(T)))
}

fn assert_no_keys(schema: &str, keys: &[&str]) {
    for key in keys {
        let pattern = format!("\"{key}\":");
        assert!(
            !schema.contains(&pattern),
            "schema must not expose key {key}"
        );
    }
}

/// Entry shape an A-20 screen producer builds from the immutable snapshot and
/// the frozen profile, using only this contract crate.
fn consumer_request(
    snapshot: &SourceSnapshot,
    profile: &ScreenProfile,
) -> Result<CurationScreenRequest, ContractError> {
    let request = CurationScreenRequest {
        source: snapshot.identity.clone(),
        denominator: snapshot.denominator.clone(),
        partition: snapshot.partition.clone(),
        binding: RequestBinding {
            request_id: must(RequestId::new("consumer-request")),
            operation_id: must(OperationId::new("consumer-operation")),
            task_id: None,
            attempt_id: must(AgentAttemptId::new("consumer-attempt")),
            scope: snapshot.identity.scope.clone(),
            state_fence: snapshot.identity.state_fence.clone(),
        },
        profile: profile.clone(),
        cursor: None,
        cancellation_requested: false,
    };
    request.validate()?;
    Ok(request)
}

/// Target-set gate an A-31 fan-in consumer applies to a screen result, using
/// only this contract crate: exact changed-target compatibility with the bound
/// partition, and rejection of protected, unknown, stale, incomplete, or
/// unscreened members as changed targets.
fn consumer_gate(result: &CurationScreenResult) -> Result<(), ContractError> {
    result.validate()?;
    if result.member_sets.changed_targets != result.request.partition.changed_targets
        || result.member_sets.immutable_references != result.request.partition.immutable_references
    {
        return Err(ContractError::Reconciliation {
            field: "consumer.target_sets",
        });
    }
    for target in &result.member_sets.changed_targets {
        let member = result
            .coverage
            .members
            .iter()
            .find(|item| item.member_id == *target)
            .ok_or(ContractError::BindingMismatch {
                field: "consumer.unscreened_target",
            })?;
        if member.disposition != MemberDisposition::Eligible {
            return Err(ContractError::Reconciliation {
                field: "consumer.blocked_target",
            });
        }
        let decision = result
            .eligibility
            .iter()
            .find(|item| item.member_id == *target)
            .ok_or(ContractError::BindingMismatch {
                field: "consumer.missing_eligibility",
            })?;
        if decision.status != EligibilityStatus::EligibleForSemanticCuration
            || decision.protection != ProtectionDecision::Unprotected
        {
            return Err(ContractError::Reconciliation {
                field: "consumer.ineligible_target",
            });
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 586/1
#[test]
fn golden_vocabulary_round_trip() {
    assert_eq!(CONTRACT_NAME, "eliot.smart.memory-curation-screen");
    assert_eq!(
        CONTRACT_VERSION,
        eliot_contracts::ContractVersion::new(1, 0, 0)
    );
    let snapshot = snap(2);
    assert!(snapshot.validate().is_ok());
    let profile = prof();
    assert!(profile.validate().is_ok());
    let request = req(&snapshot);
    assert!(request.validate().is_ok());
    let member_id = snapshot.members[0].member_id.clone();
    let finding = find(
        &snapshot,
        &profile,
        &member_id,
        "golden",
        &rule_first(),
        FindingClass::Duplicate,
    );
    assert!(
        finding
            .validate(&profile.profile_id, &snapshot.identity.snapshot_id)
            .is_ok()
    );
    let assessment = assess(
        &snapshot,
        &member_id,
        "golden",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    assert!(assessment.validate().is_ok());
    assert!(evidence_clears_protection(
        &assessment.required,
        &assessment.evidence
    ));
    let decision = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    assert!(decision.validate(&[], &profile.profile_id).is_ok());
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        "golden-0",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[1].member_id.clone(),
        "golden-1",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    for index in 0..2 {
        result.eligibility.push(elig(
            &snapshot,
            &snapshot.members[index].member_id.clone(),
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut result);
    assert!(result.validate().is_ok());
    assert_eq!(roundtrip(&snapshot), snapshot);
    assert_eq!(roundtrip(&profile), profile);
    assert_eq!(roundtrip(&finding), finding);
    assert_eq!(roundtrip(&assessment), assessment);
    assert_eq!(roundtrip(&decision), decision);
    assert_eq!(roundtrip(&result.coverage), result.coverage);
    assert_eq!(roundtrip(&result), result);
}

// WORK_UNIT_CASE: 586/2
#[test]
fn unknown_schema_field_variant_and_protected_default_rejected() {
    let snapshot = snap(1);
    let encoded = must(serde_json::to_string(&snapshot));
    assert!(serde_json::from_str::<SourceSnapshot>(&with_unknown_field(&encoded)).is_err());
    let profile = prof();
    let encoded = must(serde_json::to_string(&profile));
    assert!(serde_json::from_str::<ScreenProfile>(&with_unknown_field(&encoded)).is_err());
    let finding = find(
        &snapshot,
        &profile,
        &snapshot.members[0].member_id.clone(),
        "unknown",
        &rule_first(),
        FindingClass::Duplicate,
    );
    let encoded = must(serde_json::to_string(&finding));
    assert!(serde_json::from_str::<CurationFinding>(&with_unknown_field(&encoded)).is_err());
    let assessment = assess(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        "unknown",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    let encoded = must(serde_json::to_string(&assessment));
    assert!(serde_json::from_str::<ProtectionAssessment>(&with_unknown_field(&encoded)).is_err());
    assert!(serde_json::from_str::<FindingClass>("\"ARCHIVE\"").is_err());
    assert!(serde_json::from_str::<MemberDisposition>("\"DELETED\"").is_err());
    assert!(serde_json::from_str::<ResultState>("\"TRUNCATED\"").is_err());
    assert!(serde_json::from_str::<ProtectionDecision>("\"MAYBE\"").is_err());
    assert!(serde_json::from_str::<SourceAvailability>("\"VISIBLE\"").is_err());
    assert!(serde_json::from_str::<EligibilityStatus>("\"READY\"").is_err());
    let without_decision = without_field(&encoded, ",\"decision\":\"UNPROTECTED\"}");
    assert!(serde_json::from_str::<ProtectionAssessment>(&without_decision).is_err());
    let snapshot_encoded = must(serde_json::to_string(&snapshot));
    let without_availability = without_field(&snapshot_encoded, ",\"availability\":\"AVAILABLE\"");
    assert!(serde_json::from_str::<SourceSnapshot>(&without_availability).is_err());
}

// WORK_UNIT_CASE: 586/3
#[test]
fn complete_finite_snapshot_denominator() {
    let snapshot = snap(3);
    assert!(snapshot.validate().is_ok());
    assert!(snapshot.denominator.is_complete());
    assert_eq!(snapshot.denominator.coverage, DenominatorCoverage::Complete);
    assert_eq!(snapshot.denominator.total_members, 3);
    assert_eq!(snapshot.denominator.declared_member_ids.len(), 3);
    assert_eq!(snapshot.member_ids().len(), 3);
    assert_eq!(snapshot.availability, SourceAvailability::Available);
    assert!(!snapshot.page.has_more);
    assert!(snapshot.page.frontier.is_empty());
}

// WORK_UNIT_CASE: 586/4
#[test]
fn explicitly_partial_snapshot() {
    let snapshot = snap_partial(2);
    assert!(snapshot.validate().is_ok());
    assert!(!snapshot.denominator.is_complete());
    assert_eq!(snapshot.denominator.coverage, DenominatorCoverage::Partial);
    assert_eq!(snapshot.denominator.total_members, 3);
    assert_eq!(snapshot.denominator.declared_member_ids.len(), 2);
    assert_eq!(snapshot.availability, SourceAvailability::Partial);
    assert_ne!(snap(0).denominator.coverage, snapshot.denominator.coverage);
}

// WORK_UNIT_CASE: 586/5
#[test]
fn source_scope_fence_and_profile_mismatch_rejected() {
    let snapshot = snap(1);
    let mut request = req(&snapshot);
    assert!(request.validate().is_ok());
    let fingerprint_before = must(request.request_fingerprint());
    request.binding.scope = must(WorkScopeId::new("other-scope"));
    assert!(request.validate().is_err());
    request.binding.scope = snapshot.identity.scope.clone();
    request.binding.state_fence = fence_alt();
    assert!(request.validate().is_err());
    request.binding.state_fence = snapshot.identity.state_fence.clone();
    request.profile.policy_revision = must(PolicyRevision::new(2));
    assert!(request.validate().is_err());
    request.profile.policy_revision = PolicyRevision::genesis();
    assert!(request.validate().is_ok());
    let mut with_task = request.clone();
    with_task.binding.task_id = None;
    assert!(with_task.validate().is_ok());
    assert_eq!(must(with_task.request_fingerprint()), fingerprint_before);
}

// WORK_UNIT_CASE: 586/6
#[test]
fn duplicate_identities_rejected() {
    let mut snapshot = snap(2);
    snapshot.members[1].member_id = snapshot.members[0].member_id.clone();
    assert!(snapshot.validate().is_err());
    let mut snapshot = snap(2);
    snapshot.denominator.declared_member_ids[1] =
        snapshot.denominator.declared_member_ids[0].clone();
    assert!(snapshot.validate().is_err());
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let finding = find(
        &snapshot,
        &profile,
        &member_id,
        "dup",
        &rule_first(),
        FindingClass::Duplicate,
    );
    let repeated = [finding.clone(), finding];
    assert!(validate_findings(&repeated, &snapshot.identity, &profile.profile_id).is_err());
    let mut assessment = assess(
        &snapshot,
        &member_id,
        "dup",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    assessment.evidence.push(assessment.evidence[0].clone());
    assert!(assessment.validate().is_err());
    let mut profile = prof();
    profile.precedence = vec![rule_first(), rule_first()];
    assert!(profile.validate().is_err());
    let request = req(&snapshot);
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible]);
    let mut doubled = coverage.clone();
    doubled.members.push(coverage.members[0].clone());
    let mut result = result_skeleton(&snapshot, request, doubled, ResultState::Partial);
    resign(&mut result);
    assert!(result.validate().is_err());
    let request = req(&snapshot);
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    let record = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    result.eligibility.push(record.clone());
    result.eligibility.push(record);
    result.protection.push(assess(
        &snapshot,
        &member_id,
        "dup-elig",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    resign(&mut result);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/7
#[test]
fn changed_same_id_content_conflict_rejected() {
    let snapshot = snap(1);
    let mut changed = snapshot.identity.clone();
    changed.digest = seed_digest("different-content");
    assert!(source_matches(&snapshot.identity, &changed).is_err());
    let mut moved = snapshot.clone();
    moved.identity.snapshot_id = must(SnapshotId::new("snapshot-9"));
    assert!(source_matches(&snapshot.identity, &moved.identity).is_err());
    let first = snap(1);
    let mut second = snap(1);
    second.members[0].content_digest = seed_digest("replaced-content");
    assert_ne!(
        must(contract_digest(&first)),
        must(contract_digest(&second))
    );
    let profile = prof();
    let mut reissued = second.clone();
    reissued.identity.digest = seed_digest("reissued-digest");
    let stale_finding = find(
        &first,
        &profile,
        &first.members[0].member_id.clone(),
        "stale",
        &rule_first(),
        FindingClass::Duplicate,
    );
    assert!(validate_findings(&[stale_finding], &reissued.identity, &profile.profile_id).is_err());
    let message = format!(
        "{}",
        ContractError::ChangedIdentity {
            field: "source.content"
        }
    );
    assert!(message.contains("source.content"));
}

// WORK_UNIT_CASE: 586/8
#[test]
fn one_aggregate_disposition_per_member() {
    let snapshot = snap_split(2, 1, "1");
    let request = req(&snapshot);
    let coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Protected,
            MemberDisposition::PreservedReference,
        ],
    );
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        "one-0",
        ProtectionDecision::Protected,
        ProtectionOutcome::Present,
    ));
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[1].member_id.clone(),
        "one-1",
        ProtectionDecision::Protected,
        ProtectionOutcome::Present,
    ));
    resign(&mut result);
    assert!(result.validate().is_ok());
    assert_eq!(result.coverage.members.len(), 2);
    let mut conflict = result;
    conflict.coverage.members[0].disposition = MemberDisposition::Eligible;
    conflict.coverage.members[0].eligible = true;
    resign(&mut conflict);
    assert!(conflict.validate().is_err());
}

// WORK_UNIT_CASE: 586/9
#[test]
fn count_and_denominator_mismatch_rejected() {
    let mut snapshot = snap(2);
    snapshot.denominator.total_members = 1;
    assert!(snapshot.validate().is_err());
    let mut snapshot = snap(2);
    snapshot.denominator.total_members = 5;
    assert!(snapshot.validate().is_err());
    let mut snapshot = snap(2);
    snapshot.partition.changed_targets = BTreeSet::from([must(MemberId::new("member-0"))]);
    snapshot.partition.immutable_references = BTreeSet::new();
    assert!(snapshot.validate().is_err());
    let mut snapshot = snap(1);
    snapshot.partition.immutable_references = BTreeSet::from([must(MemberId::new("member-9"))]);
    assert!(snapshot.validate().is_err());
}

// WORK_UNIT_CASE: 586/10
#[test]
fn complete_with_unresolved_member_or_frontier_rejected() {
    let snapshot = snap(2);
    let request = req(&snapshot);
    let coverage = coverage_full(
        &snapshot,
        &[MemberDisposition::Eligible, MemberDisposition::Unprocessed],
    );
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        "ten-0",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    result.eligibility.push(elig(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    ));
    resign(&mut result);
    assert!(matches!(
        result.validate(),
        Err(ContractError::Reconciliation {
            field: "result.complete"
        })
    ));
    let request = req(&snapshot);
    let mut coverage = coverage_full(
        &snapshot,
        &[MemberDisposition::Eligible, MemberDisposition::Eligible],
    );
    coverage.frontier = ScreenFrontier {
        complete: false,
        remaining: vec![snapshot.members[1].member_id.clone()],
    };
    coverage.digest = must(coverage.computed_digest());
    let result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/11
#[test]
fn known_empty_needs_authoritative_complete_denominator() {
    let empty_complete = snap(0);
    assert!(empty_complete.validate().is_ok());
    assert!(empty_complete.denominator.is_complete());
    let request = req(&empty_complete);
    let coverage = coverage_full(&empty_complete, &[]);
    let result = result_skeleton(&empty_complete, request, coverage, ResultState::Complete);
    assert!(result.validate().is_ok());
    assert!(result.coverage.members.is_empty());
    let partial_empty = snap_partial(0);
    assert!(partial_empty.validate().is_ok());
    assert!(!partial_empty.denominator.is_complete());
    let request = req(&partial_empty);
    let coverage = coverage_full(&partial_empty, &[]);
    let result = result_skeleton(&partial_empty, request, coverage, ResultState::Complete);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/12
#[test]
fn availability_states_are_distinct() {
    let wires = [
        (SourceAvailability::Available, "AVAILABLE"),
        (SourceAvailability::Partial, "PARTIAL"),
        (SourceAvailability::Unavailable, "UNAVAILABLE"),
        (SourceAvailability::Blocked, "BLOCKED"),
        (SourceAvailability::Stale, "STALE"),
        (SourceAvailability::Malformed, "MALFORMED"),
        (SourceAvailability::Unknown, "UNKNOWN"),
    ];
    for (state, wire) in wires {
        assert_eq!(must(serde_json::to_string(&state)), format!("\"{wire}\""));
    }
    for state in [
        SourceAvailability::Partial,
        SourceAvailability::Unavailable,
        SourceAvailability::Blocked,
        SourceAvailability::Stale,
        SourceAvailability::Malformed,
        SourceAvailability::Unknown,
    ] {
        let mut shaped = snap_partial(1);
        shaped.availability = state;
        assert!(shaped.validate().is_ok());
    }
    let mut complete = snap(1);
    complete.availability = SourceAvailability::Partial;
    assert!(complete.validate().is_err());
}

// WORK_UNIT_CASE: 586/13
#[test]
fn source_order_page_cursor_frontier_round_trip() {
    let snapshot = snap(3);
    let request = req(&snapshot);
    let mut first_page = snapshot.clone();
    first_page.members.truncate(1);
    first_page.page.has_more = true;
    first_page.page.frontier = vec![
        must(MemberId::new("member-1")),
        must(MemberId::new("member-2")),
    ];
    assert!(first_page.validate().is_ok());
    let first_ids: Vec<MemberId> = first_page
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let first_cursor = cursor_gen(&request, &snapshot, &first_ids, usage(1), None);
    assert!(first_cursor.validate(&request).is_ok());
    assert!(
        first_cursor
            .validate_progress(&request, &first_page, None, &first_ids)
            .is_ok()
    );
    let all_ids: Vec<MemberId> = snapshot
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let second_cursor = cursor_gen(
        &request,
        &snapshot,
        &all_ids,
        usage(3),
        Some(must(contract_digest(&first_cursor))),
    );
    let page_ids = vec![all_ids[1].clone(), all_ids[2].clone()];
    assert!(
        second_cursor
            .validate_progress(&request, &snapshot, Some(&first_cursor), &page_ids)
            .is_ok()
    );
    let mut regressed = second_cursor;
    regressed.usage = usage(1);
    assert!(
        regressed
            .validate_progress(&request, &snapshot, None, &[])
            .is_err()
    );
}

// WORK_UNIT_CASE: 586/14
#[test]
fn cursor_identity_cannot_cross_request_bindings() {
    let snapshot = snap(2);
    let request = req(&snapshot);
    let ids: Vec<MemberId> = snapshot
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let cursor = cursor_gen(&request, &snapshot, &ids, usage(2), None);
    assert!(cursor.validate(&request).is_ok());
    let mut crossed = request.clone();
    crossed.binding.request_id = must(RequestId::new("other-request"));
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.source.snapshot_id = must(SnapshotId::new("snapshot-other"));
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.source.query.query_id = must(QueryId::new("query-other"));
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.source.revision = 7;
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.source.digest = seed_digest("other-digest");
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.profile.profile_id = must(ProfileId::new("profile-other"));
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.profile.rules.pop();
    crossed.profile.precedence.pop();
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.denominator.total_members = 99;
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.binding.scope = must(WorkScopeId::new("other-scope"));
    assert!(cursor.validate(&crossed).is_err());
    let mut crossed = request.clone();
    crossed.binding.state_fence = fence_alt();
    crossed.source.state_fence = fence_alt();
    assert!(cursor.validate(&crossed).is_err());
}

// WORK_UNIT_CASE: 586/15
#[test]
fn cumulative_item_and_work_limits_cannot_reset() {
    let snapshot = snap(2);
    let request = req(&snapshot);
    let ids: Vec<MemberId> = snapshot
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let over = WorkUsage {
        processed_items: 2,
        work_units: 11,
        input_bytes: 2,
        output_bytes: 2,
    };
    let cursor = cursor_gen(&request, &snapshot, &ids, over, None);
    assert!(matches!(
        cursor.validate(&request),
        Err(ContractError::Bound {
            field: "cursor.cumulative_usage"
        })
    ));
    let mut drifted = cursor_gen(&request, &snapshot, &ids, usage(2), None);
    drifted.position = 1;
    assert!(drifted.validate(&request).is_err());
    let snapshot = snap(3);
    let request = req(&snapshot);
    let prefix: Vec<MemberId> = snapshot.members[..2]
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let prior = cursor_gen(
        &request,
        &snapshot,
        &prefix,
        WorkUsage {
            processed_items: 2,
            work_units: 5,
            input_bytes: 5,
            output_bytes: 5,
        },
        None,
    );
    let mut continued = req(&snapshot);
    continued.cursor = Some(prior);
    let coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
        ],
    );
    let mut regressed = coverage;
    regressed.start_position = 2;
    regressed.usage = WorkUsage {
        processed_items: 3,
        work_units: 1,
        input_bytes: 1,
        output_bytes: 1,
    };
    regressed.digest = must(regressed.computed_digest());
    let mut result = result_skeleton(&snapshot, continued, regressed, ResultState::Complete);
    for index in 0..3 {
        let id = snapshot.members[index].member_id.clone();
        result.protection.push(assess(
            &snapshot,
            &id,
            &format!("fifteen-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        result.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut result);
    assert!(matches!(
        result.validate(),
        Err(ContractError::Reconciliation {
            field: "result.cumulative_usage"
        })
    ));
}

// WORK_UNIT_CASE: 586/16
#[test]
fn cursor_cannot_silently_skip_or_reprocess() {
    let snapshot = snap(3);
    let request = req(&snapshot);
    let prefix: Vec<MemberId> = snapshot.members[..2]
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let prior = cursor_gen(&request, &snapshot, &prefix, usage(2), None);
    let all: Vec<MemberId> = snapshot
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let mut skipped = cursor_gen(&request, &snapshot, &all, usage(3), None);
    assert!(
        skipped
            .validate_progress(&request, &snapshot, Some(&prior), &all[1..])
            .is_err()
    );
    skipped.predecessor = Some(digest());
    assert!(
        skipped
            .validate_progress(&request, &snapshot, Some(&prior), &all[1..])
            .is_err()
    );
    let wrong_page = cursor_gen(
        &request,
        &snapshot,
        &all,
        usage(3),
        Some(must(contract_digest(&prior))),
    );
    assert!(
        wrong_page
            .validate_progress(&request, &snapshot, Some(&prior), &all[..1])
            .is_err()
    );
    let mut tampered = wrong_page;
    tampered.processed_member_digest = digest();
    assert!(
        tampered
            .validate_progress(&request, &snapshot, Some(&prior), &all[1..])
            .is_err()
    );
    let genesis = cursor_gen(&request, &snapshot, &prefix, usage(2), Some(digest()));
    assert!(
        genesis
            .validate_progress(&request, &snapshot, None, &prefix)
            .is_err()
    );
}

// WORK_UNIT_CASE: 586/17
#[test]
fn exact_rule_profile_source_item_evidence_bound_finding() {
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let finding = find(
        &snapshot,
        &profile,
        &member_id,
        "bound",
        &rule_first(),
        FindingClass::Duplicate,
    );
    assert!(finding.validate_against_profile(&profile).is_ok());
    assert!(
        validate_findings(
            std::slice::from_ref(&finding),
            &snapshot.identity,
            &profile.profile_id
        )
        .is_ok()
    );
    let mut unknown_rule = finding.clone();
    unknown_rule.rule_id = must(RuleId::new("rule-9"));
    assert!(unknown_rule.validate_against_profile(&profile).is_err());
    let mut wrong_class = finding.clone();
    wrong_class.class = FindingClass::ProvenanceGap;
    assert!(wrong_class.validate_against_profile(&profile).is_err());
    let mut wrong_profile = finding.clone();
    wrong_profile.profile_id = must(ProfileId::new("profile-other"));
    assert!(wrong_profile.validate_against_profile(&profile).is_err());
    let second = find(
        &snapshot,
        &profile,
        &member_id,
        "second-rule",
        &rule_second(),
        FindingClass::ProvenanceGap,
    );
    assert!(second.validate_against_profile(&profile).is_ok());
    let request = req(&snapshot);
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Blocked]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    result.findings.push(unknown_rule);
    result.protection.push(assess(
        &snapshot,
        &member_id,
        "seventeen",
        ProtectionDecision::Unknown,
        ProtectionOutcome::Unknown,
    ));
    resign(&mut result);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/18
#[test]
fn distinct_collision_stale_malformed_gap_conflict_bounded_findings() {
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let wires = [
        (
            FindingClass::Duplicate,
            "DUPLICATE",
            CurationDimension::Support,
        ),
        (
            FindingClass::StaleSuperseded,
            "STALE_SUPERSEDED",
            CurationDimension::Support,
        ),
        (
            FindingClass::MalformedIncomplete,
            "MALFORMED_INCOMPLETE",
            CurationDimension::Existence,
        ),
        (
            FindingClass::ProvenanceGap,
            "PROVENANCE_GAP",
            CurationDimension::Support,
        ),
        (
            FindingClass::ProtectionGap,
            "PROTECTION_GAP",
            CurationDimension::PermittedInfluence,
        ),
        (
            FindingClass::ConflictAmbiguity,
            "CONFLICT_AMBIGUITY",
            CurationDimension::Support,
        ),
        (
            FindingClass::BoundedOut,
            "BOUNDED_OUT",
            CurationDimension::Existence,
        ),
        (
            FindingClass::Unprocessed,
            "UNPROCESSED",
            CurationDimension::Existence,
        ),
    ];
    let mut seen = BTreeSet::new();
    for (class, wire, dimension) in wires {
        assert_eq!(must(serde_json::to_string(&class)), format!("\"{wire}\""));
        assert_eq!(class.dimension(), dimension);
        assert!(seen.insert(wire));
        let finding = find(&snapshot, &profile, &member_id, wire, &rule_first(), class);
        assert!(
            finding
                .validate(&profile.profile_id, &snapshot.identity.snapshot_id)
                .is_ok()
        );
    }
    assert_eq!(seen.len(), 8);
}

// WORK_UNIT_CASE: 586/19
#[test]
fn findings_cannot_carry_prohibited_canonical_actions() {
    for class in [
        FindingClass::Duplicate,
        FindingClass::StaleSuperseded,
        FindingClass::MalformedIncomplete,
        FindingClass::ProvenanceGap,
        FindingClass::ProtectionGap,
        FindingClass::ConflictAmbiguity,
        FindingClass::BoundedOut,
        FindingClass::Unprocessed,
    ] {
        let wire = must(serde_json::to_string(&class));
        assert!(!wire.contains("ARCHIVE"));
        assert!(!wire.contains("SUPPRESS"));
        assert!(!wire.contains("DELETE"));
        assert!(!wire.contains("PROMOTE"));
    }
    let schema = schema_text::<CurationFinding>();
    assert_no_keys(
        &schema,
        &[
            "action",
            "lifecycle",
            "transition",
            "archive",
            "suppress",
            "forget",
            "delete",
            "promote",
            "demote",
            "revoke",
        ],
    );
}

// WORK_UNIT_CASE: 586/20
#[test]
fn findings_cannot_select_kind_family_or_handler() {
    let schema = schema_text::<CurationFinding>();
    assert_no_keys(
        &schema,
        &[
            "kind",
            "family",
            "handler",
            "semantic_kind",
            "route",
            "candidate",
        ],
    );
    let profile_schema = schema_text::<ScreenProfile>();
    assert_no_keys(
        &profile_schema,
        &["kind", "family", "handler", "route_table", "candidate"],
    );
    for proof in [
        FindingProof::Deterministic,
        FindingProof::Observed,
        FindingProof::Unknown,
    ] {
        let wire = must(serde_json::to_string(&proof));
        assert!(!wire.contains("CONFIDENCE"));
        assert!(!wire.contains("PRIORITY"));
    }
}

// WORK_UNIT_CASE: 586/21
#[test]
fn every_protection_class_has_explicit_evidence() {
    let snapshot = snap(1);
    let member_id = snapshot.members[0].member_id.clone();
    let wires = [
        (ProtectionClass::CurrentTruth, "CURRENT_TRUTH"),
        (ProtectionClass::MinorityDissent, "MINORITY_DISSENT"),
        (ProtectionClass::Counterexample, "COUNTEREXAMPLE"),
        (ProtectionClass::UnresolvedConflict, "UNRESOLVED_CONFLICT"),
        (ProtectionClass::NegativeMemory, "NEGATIVE_MEMORY"),
        (ProtectionClass::AuditHistory, "AUDIT_HISTORY"),
        (ProtectionClass::RetentionErasure, "RETENTION_ERASURE"),
        (ProtectionClass::ProtectedDependency, "PROTECTED_DEPENDENCY"),
    ];
    let mut seen = BTreeSet::new();
    for (class, wire) in wires {
        assert_eq!(must(serde_json::to_string(&class)), format!("\"{wire}\""));
        assert!(seen.insert(wire));
        let record = ev(
            &snapshot,
            &member_id,
            wire,
            class,
            ProtectionEvidenceState::CurrentVerified,
            ProtectionOutcome::Present,
        );
        assert!(record.validate(&snapshot.identity).is_ok());
        let assessment = ProtectionAssessment {
            source: snapshot.identity.clone(),
            member_id: member_id.clone(),
            applicable_rule_ids: BTreeSet::new(),
            required: BTreeSet::from([class]),
            evidence: vec![record],
            decision: ProtectionDecision::Protected,
        };
        assert!(assessment.validate().is_ok());
    }
    assert_eq!(seen.len(), 8);
}

// WORK_UNIT_CASE: 586/22
#[test]
fn missing_stale_unknown_protection_fails_closed() {
    let snapshot = snap(1);
    let member_id = snapshot.members[0].member_id.clone();
    let empty = ProtectionAssessment {
        source: snapshot.identity.clone(),
        member_id: member_id.clone(),
        applicable_rule_ids: BTreeSet::from([rule_first()]),
        required: BTreeSet::from([ProtectionClass::CurrentTruth]),
        evidence: Vec::new(),
        decision: ProtectionDecision::Unprotected,
    };
    assert!(empty.validate().is_err());
    for state in [
        ProtectionEvidenceState::Stale,
        ProtectionEvidenceState::Missing,
        ProtectionEvidenceState::Malformed,
        ProtectionEvidenceState::Unavailable,
        ProtectionEvidenceState::Unknown,
    ] {
        let assessment = ProtectionAssessment {
            source: snapshot.identity.clone(),
            member_id: member_id.clone(),
            applicable_rule_ids: BTreeSet::from([rule_first()]),
            required: BTreeSet::from([ProtectionClass::CurrentTruth]),
            evidence: vec![ev(
                &snapshot,
                &member_id,
                "closed",
                ProtectionClass::CurrentTruth,
                state,
                ProtectionOutcome::Absent,
            )],
            decision: ProtectionDecision::Unprotected,
        };
        assert!(assessment.validate().is_err());
    }
    let mut invalidated = assess(
        &snapshot,
        &member_id,
        "closed-inv",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    invalidated.evidence[0].invalidated_by = Some(must(ProtectionEvidenceId::new("ev-closer")));
    assert!(invalidated.validate().is_err());
    let unknown = ProtectionAssessment {
        source: snapshot.identity.clone(),
        member_id: member_id.clone(),
        applicable_rule_ids: BTreeSet::from([rule_first()]),
        required: BTreeSet::from([ProtectionClass::CurrentTruth]),
        evidence: Vec::new(),
        decision: ProtectionDecision::Unknown,
    };
    assert!(unknown.validate().is_ok());
    assert!(!evidence_clears_protection(
        &unknown.required,
        &unknown.evidence
    ));
}

// WORK_UNIT_CASE: 586/23
#[test]
fn protected_item_cannot_be_eligible() {
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let blocked = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Protected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    assert!(blocked.validate(&[], &profile.profile_id).is_err());
    let unknown = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unknown,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    assert!(unknown.validate(&[], &profile.profile_id).is_err());
    let mismatched = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::Protected,
    );
    let request = req(&snapshot);
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Protected]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    result.protection.push(assess(
        &snapshot,
        &member_id,
        "twentythree",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    result.eligibility.push(mismatched);
    resign(&mut result);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/24
#[test]
fn protection_scope_fence_source_mismatch_rejected() {
    let snapshot = snap(1);
    let member_id = snapshot.members[0].member_id.clone();
    let record = ev(
        &snapshot,
        &member_id,
        "scope",
        ProtectionClass::CurrentTruth,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
    );
    assert!(record.validate(&snapshot.identity).is_ok());
    let mut crossed = record.clone();
    crossed.scope = must(WorkScopeId::new("other-scope"));
    assert!(crossed.validate(&snapshot.identity).is_err());
    let mut crossed = record.clone();
    crossed.state_fence = fence_alt();
    assert!(crossed.validate(&snapshot.identity).is_err());
    let mut crossed = record.clone();
    crossed.source_id = must(SourceId::new("other-source"));
    assert!(crossed.validate(&snapshot.identity).is_err());
    let mut crossed = record.clone();
    crossed.snapshot_id = must(SnapshotId::new("snapshot-other"));
    assert!(crossed.validate(&snapshot.identity).is_err());
    let mut assessment = assess(
        &snapshot,
        &member_id,
        "scope-member",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    assessment.evidence[0].member_id = must(MemberId::new("member-other"));
    assert!(assessment.validate().is_err());
}

// WORK_UNIT_CASE: 586/25
#[test]
fn protection_cannot_grant_support_or_change_lifecycle() {
    for decision in [
        ProtectionDecision::Unprotected,
        ProtectionDecision::Protected,
        ProtectionDecision::Unknown,
    ] {
        let wire = must(serde_json::to_string(&decision));
        assert!(!wire.contains("SUPPORT"));
        assert!(!wire.contains("LIFECYCLE"));
    }
    for ceiling in [
        DisclosureCeiling::Structural,
        DisclosureCeiling::ReferenceOnly,
        DisclosureCeiling::Redacted,
    ] {
        let wire = must(serde_json::to_string(&ceiling));
        assert!(!wire.contains("PROOF"));
    }
    let schema = schema_text::<ProtectionAssessment>();
    assert_no_keys(
        &schema,
        &[
            "lifecycle",
            "support",
            "grant",
            "archive",
            "suppress",
            "kind",
            "handler",
            "action",
        ],
    );
    let schema = schema_text::<ProtectionEvidence>();
    assert_no_keys(&schema, &["lifecycle", "support", "grant", "action"]);
}

// WORK_UNIT_CASE: 586/26
#[test]
fn valid_generic_eligible_item() {
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let assessment = assess(
        &snapshot,
        &member_id,
        "eligible",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    );
    assert!(assessment.validate().is_ok());
    assert!(!assessment.applicable_rule_ids.is_empty());
    let decision = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    assert!(decision.validate(&[], &profile.profile_id).is_ok());
    let request = req(&snapshot);
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    result.protection.push(assessment);
    result.eligibility.push(decision);
    resign(&mut result);
    assert!(result.validate().is_ok());
    assert!(consumer_gate(&result).is_ok());
}

// WORK_UNIT_CASE: 586/27
#[test]
fn eligibility_statuses_are_distinct() {
    let snapshot = snap(1);
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let wires = [
        (
            EligibilityStatus::EligibleForSemanticCuration,
            "ELIGIBLE_FOR_SEMANTIC_CURATION",
        ),
        (EligibilityStatus::Protected, "PROTECTED"),
        (EligibilityStatus::Malformed, "MALFORMED"),
        (EligibilityStatus::StaleUnavailable, "STALE_UNAVAILABLE"),
        (EligibilityStatus::OutsideScope, "OUTSIDE_SCOPE"),
        (
            EligibilityStatus::IncompleteTruncated,
            "INCOMPLETE_TRUNCATED",
        ),
        (EligibilityStatus::UnknownBlocked, "UNKNOWN_BLOCKED"),
    ];
    let mut seen = BTreeSet::new();
    for (status, wire) in wires {
        assert_eq!(must(serde_json::to_string(&status)), format!("\"{wire}\""));
        assert!(seen.insert(wire));
        if status == EligibilityStatus::EligibleForSemanticCuration {
            continue;
        }
        let decision = elig(
            &snapshot,
            &member_id,
            ProtectionDecision::Unprotected,
            status,
        );
        assert!(decision.validate(&[], &profile.profile_id).is_ok());
    }
    assert_eq!(seen.len(), 7);
}

// WORK_UNIT_CASE: 586/28
#[test]
fn eligibility_schema_has_no_kind_surface() {
    let schema = schema_text::<Eligibility>();
    assert_no_keys(
        &schema,
        &[
            "kind",
            "family",
            "handler",
            "action",
            "route",
            "candidate",
            "confidence",
            "priority",
        ],
    );
    let status_schema = schema_text::<EligibilityStatus>();
    assert_no_keys(&status_schema, &["kind", "handler", "action"]);
}

// WORK_UNIT_CASE: 586/29
#[test]
fn valid_complete_result_with_targets_and_references() {
    let snapshot = snap_split(3, 2, "1");
    let request = req(&snapshot);
    let coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
            MemberDisposition::PreservedReference,
        ],
    );
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    for index in 0..2 {
        let id = snapshot.members[index].member_id.clone();
        result.protection.push(assess(
            &snapshot,
            &id,
            &format!("twentynine-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        result.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut result);
    assert!(result.validate().is_ok());
    assert_eq!(result.member_sets.changed_targets.len(), 2);
    assert_eq!(result.member_sets.immutable_references.len(), 1);
    assert!(consumer_gate(&result).is_ok());
}

// WORK_UNIT_CASE: 586/30
#[test]
fn protected_eligible_blocked_unprocessed_sets_reconcile() {
    let snapshot = snap_split(4, 3, "1");
    let request = req(&snapshot);
    let coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Protected,
            MemberDisposition::Eligible,
            MemberDisposition::Unprocessed,
            MemberDisposition::PreservedReference,
        ],
    );
    assert!(!coverage.frontier.complete);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[0].member_id.clone(),
        "thirty-protected",
        ProtectionDecision::Protected,
        ProtectionOutcome::Present,
    ));
    result.protection.push(assess(
        &snapshot,
        &snapshot.members[1].member_id.clone(),
        "thirty-eligible",
        ProtectionDecision::Unprotected,
        ProtectionOutcome::Absent,
    ));
    result.eligibility.push(elig(
        &snapshot,
        &snapshot.members[1].member_id.clone(),
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    ));
    resign(&mut result);
    assert!(result.validate().is_ok());
    let mut overlapped = result;
    let target = must_some(
        overlapped
            .member_sets
            .changed_targets
            .iter()
            .next()
            .cloned(),
    );
    overlapped.member_sets.immutable_references.insert(target);
    resign(&mut overlapped);
    assert!(overlapped.validate().is_err());
}

// WORK_UNIT_CASE: 586/31
#[test]
fn every_independent_limit_boundary_and_one_over() {
    let limits = prof().limits;
    assert!(limits.validate().is_ok());
    for make_zero in [
        ScreenLimits {
            max_items: 0,
            ..limits
        },
        ScreenLimits {
            max_references: 0,
            ..limits
        },
        ScreenLimits {
            max_bytes: 0,
            ..limits
        },
        ScreenLimits {
            max_work_units: 0,
            ..limits
        },
        ScreenLimits {
            max_output_bytes: 0,
            ..limits
        },
        ScreenLimits {
            deadline_ms: Some(0),
            ..limits
        },
    ] {
        assert!(make_zero.validate().is_err());
    }
    let snapshot = snap(2);
    let mut request = req(&snapshot);
    request.profile.limits.max_items = 2;
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
    let mut boundary = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    for index in 0..2 {
        let id = snapshot.members[index].member_id.clone();
        boundary.protection.push(assess(
            &snapshot,
            &id,
            &format!("thirtyone-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        boundary.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut boundary);
    assert!(boundary.validate().is_ok());
    let mut tight = req(&snapshot);
    tight.profile.limits.max_items = 1;
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
    let result = result_skeleton(&snapshot, tight, coverage, ResultState::Partial);
    assert!(matches!(
        result.validate(),
        Err(ContractError::Bound {
            field: "result.limits"
        })
    ));
    for field in ["work_units", "input_bytes", "output_bytes"] {
        let request = req(&snapshot);
        let mut coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
        if field == "work_units" {
            coverage.usage.work_units = 11;
        } else if field == "input_bytes" {
            coverage.usage.input_bytes = 10_001;
        } else {
            coverage.usage.output_bytes = 10_001;
        }
        coverage.digest = must(coverage.computed_digest());
        let result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
        assert!(result.validate().is_err(), "over-limit {field} must fail");
    }
}

// WORK_UNIT_CASE: 586/32
#[test]
fn bound_hit_preserves_exact_frontier_and_cannot_be_complete() {
    let snapshot = snap(3);
    let mut request = req(&snapshot);
    request.profile.limits.max_items = 2;
    let mut coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
            MemberDisposition::Unprocessed,
        ],
    );
    coverage.members.truncate(2);
    coverage.usage = usage(2);
    coverage.frontier = ScreenFrontier {
        complete: false,
        remaining: vec![snapshot.members[2].member_id.clone()],
    };
    coverage.digest = must(coverage.computed_digest());
    assert_eq!(
        coverage.frontier.remaining,
        vec![snapshot.members[2].member_id.clone()]
    );
    let mut partial = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    for index in 0..2 {
        let id = snapshot.members[index].member_id.clone();
        partial.protection.push(assess(
            &snapshot,
            &id,
            &format!("thirtytwo-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        partial.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut partial);
    assert!(partial.validate().is_ok());
    let mut claimed = partial;
    claimed.state = ResultState::Complete;
    resign(&mut claimed);
    assert!(claimed.validate().is_err());
}

// WORK_UNIT_CASE: 586/33
#[test]
fn exact_replay_bytes_and_digest() {
    let snapshot = snap(2);
    let request = req(&snapshot);
    let first_bytes = must(serde_json::to_string(&request));
    let replayed: CurationScreenRequest = must(serde_json::from_str(&first_bytes));
    assert_eq!(replayed, request);
    let second_bytes = must(serde_json::to_string(&replayed));
    assert_eq!(first_bytes, second_bytes);
    assert_eq!(
        must(request.request_fingerprint()),
        must(replayed.request_fingerprint())
    );
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
    let result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    let result_bytes = must(serde_json::to_string(&result));
    let replayed: CurationScreenResult = must(serde_json::from_str(&result_bytes));
    assert_eq!(
        must(replayed.computed_digest()),
        must(result.computed_digest())
    );
    let cut = result_bytes.len() - 8;
    assert!(serde_json::from_str::<CurationScreenResult>(&result_bytes[..cut]).is_err());
    let mut forged = result;
    forged.coverage.digest = digest();
    assert!(forged.validate().is_err());
}

// WORK_UNIT_CASE: 586/34
#[test]
fn changed_snapshot_profile_payload_conflict_rejected() {
    let snapshot = snap(2);
    let request = req(&snapshot);
    assert!(request.validate_snapshot(&snapshot).is_ok());
    let mut drifted = snapshot.clone();
    drifted.identity.digest = seed_digest("drifted");
    assert!(request.validate_snapshot(&drifted).is_err());
    let mut drifted = snapshot.clone();
    drifted.denominator.total_members = 3;
    drifted.denominator.coverage = DenominatorCoverage::Partial;
    drifted.availability = SourceAvailability::Partial;
    assert!(request.validate_snapshot(&drifted).is_err());
    let mut drifted = snapshot.clone();
    drifted.partition.immutable_references =
        BTreeSet::from([snapshot.members[0].member_id.clone()]);
    drifted
        .partition
        .changed_targets
        .remove(&snapshot.members[0].member_id);
    assert!(request.validate_snapshot(&drifted).is_err());
    let coverage = coverage_full(&snapshot, &[MemberDisposition::Eligible; 2]);
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    for index in 0..2 {
        let id = snapshot.members[index].member_id.clone();
        result.protection.push(assess(
            &snapshot,
            &id,
            &format!("thirtyfour-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        result.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut result);
    assert!(result.validate().is_ok());
    result.result_digest = digest();
    assert!(result.validate().is_err());
    result.coverage.digest = digest();
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/35
#[test]
fn canonical_set_order_invariance() {
    let snapshot = snap(3);
    let forward: BTreeSet<MemberId> = snapshot
        .members
        .iter()
        .map(|item| item.member_id.clone())
        .collect();
    let mut reversed_insert: BTreeSet<MemberId> = BTreeSet::new();
    for id in forward.iter().rev() {
        reversed_insert.insert(id.clone());
    }
    assert_eq!(forward, reversed_insert);
    assert_eq!(
        must(contract_digest(&forward)),
        must(contract_digest(&reversed_insert))
    );
    let mut reordered = snap(3);
    reordered.partition.changed_targets = reversed_insert;
    assert!(reordered.partition.validate(&reordered.denominator).is_ok());
    assert_eq!(
        must(contract_digest(&reordered.partition)),
        must(contract_digest(&snap(3).partition))
    );
}

// WORK_UNIT_CASE: 586/36
#[test]
fn meaningful_source_order_remains_identity_visible() {
    let snapshot = snap(3);
    let encoded = must(serde_json::to_string(&snapshot));
    let first = must_some(encoded.find("member-0"));
    let second = must_some(encoded.find("member-1"));
    let third = must_some(encoded.find("member-2"));
    assert!(first < second);
    assert!(second < third);
    let mut reordered = snapshot.clone();
    reordered.members.reverse();
    assert!(reordered.validate().is_err());
    let request = req(&snapshot);
    let mut coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
        ],
    );
    coverage.members.reverse();
    coverage.digest = must(coverage.computed_digest());
    let result = result_skeleton(&snapshot, request, coverage, ResultState::Partial);
    assert!(result.validate().is_err());
}

// WORK_UNIT_CASE: 586/37
#[test]
fn legacy_preview_candidate_profile_finding_cannot_decode_current() {
    let legacy_preview = "{\"candidate_id\":\"preview-1\",\"kind\":\"classification\",\"proposed_transformation\":{\"action\":\"Archive\"},\"support\":0.9}";
    assert!(serde_json::from_str::<CurationFinding>(legacy_preview).is_err());
    assert!(serde_json::from_str::<Eligibility>(legacy_preview).is_err());
    assert!(serde_json::from_str::<SourceSnapshot>(legacy_preview).is_err());
    assert!(serde_json::from_str::<CurationScreenResult>(legacy_preview).is_err());
    let legacy_finding = "{\"finding_kind\":\"MemoryCurationFindingKind::Duplicate\",\"action\":\"Suppress\",\"confidence\":0.7}";
    assert!(serde_json::from_str::<CurationFinding>(legacy_finding).is_err());
    let descriptor = LegacyMigrationDescriptor {
        descriptor_version: LEGACY_DESCRIPTOR_VERSION.to_string(),
        source_version: "memory-curation-v0".to_string(),
        lost_fields: vec!["action".to_string(), "utility_score".to_string()],
        target_owner: "smart.memory.curation_contracts".to_string(),
        migration_issue: 586,
        descriptor_digest: digest(),
    };
    assert!(descriptor.validate().is_ok());
    assert_eq!(roundtrip(&descriptor), descriptor);
}

// WORK_UNIT_CASE: 586/38
#[test]
fn inert_migration_preserves_version_loss_owner_without_action() {
    let descriptor = LegacyMigrationDescriptor {
        descriptor_version: LEGACY_DESCRIPTOR_VERSION.to_string(),
        source_version: "memory-curation-v0".to_string(),
        lost_fields: vec!["action".to_string(), "lifecycle".to_string()],
        target_owner: "smart.memory.curation_contracts".to_string(),
        migration_issue: 586,
        descriptor_digest: digest(),
    };
    assert!(descriptor.validate().is_ok());
    let decoded = roundtrip(&descriptor);
    assert_eq!(decoded.source_version, "memory-curation-v0");
    assert_eq!(decoded.lost_fields.len(), 2);
    assert_eq!(decoded.target_owner, "smart.memory.curation_contracts");
    assert_eq!(decoded.migration_issue, 586);
    let mut bad_version = descriptor.clone();
    bad_version.descriptor_version = "v9".to_string();
    assert!(bad_version.validate().is_err());
    let mut blank_source = descriptor.clone();
    blank_source.source_version = "  ".to_string();
    assert!(blank_source.validate().is_err());
    let mut blank_owner = descriptor.clone();
    blank_owner.target_owner = String::new();
    assert!(blank_owner.validate().is_err());
    let mut zero_issue = descriptor.clone();
    zero_issue.migration_issue = 0;
    assert!(zero_issue.validate().is_err());
    let mut blank_loss = descriptor.clone();
    blank_loss.lost_fields = vec![String::new()];
    assert!(blank_loss.validate().is_err());
    let schema = schema_text::<LegacyMigrationDescriptor>();
    assert_no_keys(&schema, &["action", "decode", "apply", "handler", "kind"]);
}

// WORK_UNIT_CASE: 586/39
#[test]
fn current_schema_rejects_legacy_action_lifecycle_stringly_fields() {
    let snapshot = snap(1);
    let base = must(serde_json::to_string(&snapshot));
    for legacy in [
        "\"action\":\"ARCHIVE\"",
        "\"lifecycle\":\"ARCHIVED\"",
        "\"kind\":\"classification\"",
        "\"handler\":\"dreamer-handler\"",
        "\"status\":\"done\"",
    ] {
        let injected = with_field(&base, legacy);
        assert!(
            serde_json::from_str::<SourceSnapshot>(&injected).is_err(),
            "legacy field {legacy} must be rejected"
        );
    }
    let profile = prof();
    let member_id = snapshot.members[0].member_id.clone();
    let finding = find(
        &snapshot,
        &profile,
        &member_id,
        "legacy",
        &rule_first(),
        FindingClass::Duplicate,
    );
    let base = must(serde_json::to_string(&finding));
    let injected = with_field(&base, "\"action\":\"SUPPRESS\"");
    assert!(serde_json::from_str::<CurationFinding>(&injected).is_err());
    let decision = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    let base = must(serde_json::to_string(&decision));
    let injected = with_field(&base, "\"kind\":\"merge\"");
    assert!(serde_json::from_str::<Eligibility>(&injected).is_err());
}

// WORK_UNIT_CASE: 586/40
#[test]
fn consumer_compile_fixtures_without_algorithm_imports() {
    let snapshot = snap_split(3, 2, "1");
    let profile = prof();
    let request = must(consumer_request(&snapshot, &profile));
    assert!(request.validate_snapshot(&snapshot).is_ok());
    let mut changed_profile = profile.clone();
    changed_profile.rules.pop();
    changed_profile.precedence.pop();
    assert!(consumer_request(&snapshot, &changed_profile).is_ok());
    let mut mismatched = snapshot.clone();
    mismatched.identity.digest = seed_digest("other");
    assert!(consumer_request(&mismatched, &profile).is_ok());
    let coverage = coverage_full(
        &snapshot,
        &[
            MemberDisposition::Eligible,
            MemberDisposition::Eligible,
            MemberDisposition::PreservedReference,
        ],
    );
    let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
    for index in 0..2 {
        let id = snapshot.members[index].member_id.clone();
        result.protection.push(assess(
            &snapshot,
            &id,
            &format!("forty-{index}"),
            ProtectionDecision::Unprotected,
            ProtectionOutcome::Absent,
        ));
        result.eligibility.push(elig(
            &snapshot,
            &id,
            ProtectionDecision::Unprotected,
            EligibilityStatus::EligibleForSemanticCuration,
        ));
    }
    resign(&mut result);
    assert!(consumer_gate(&result).is_ok());
    let mut protected_target = result.clone();
    protected_target.coverage.members[0].disposition = MemberDisposition::Protected;
    protected_target.coverage.members[0].eligible = false;
    protected_target.eligibility.remove(0);
    protected_target.protection[0].decision = ProtectionDecision::Protected;
    protected_target.protection[0].evidence[0].outcome = ProtectionOutcome::Present;
    resign(&mut protected_target);
    assert!(protected_target.validate().is_ok());
    assert!(consumer_gate(&protected_target).is_err());
    let mut unscreened = result.clone();
    unscreened.coverage.members.remove(0);
    unscreened.coverage.usage.processed_items = 2;
    resign(&mut unscreened);
    assert!(consumer_gate(&unscreened).is_err());
}

// WORK_UNIT_CASE: 586/41
#[test]
fn no_handler_screen_or_fanin_implementation_dependency() {
    const MANIFEST: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let start_marker = "[dependencies]\n";
    let start = must_some(MANIFEST.find(start_marker)) + start_marker.len();
    let tail = &MANIFEST[start..];
    let end = tail.find("\n[").unwrap_or(tail.len());
    let section = &tail[..end];
    let mut names = BTreeSet::new();
    for line in section.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let name = must_some(line.split(['.', '=']).next()).trim().to_string();
        names.insert(name);
    }
    let expected: BTreeSet<String> = [
        "eliot-contracts",
        "eliot-evidence",
        "eliot-agent-contracts",
        "eliot-receipts",
        "schemars",
        "serde",
        "thiserror",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(names, expected);
    for forbidden in [
        "eliot-memory-curation-screen",
        "eliot-dreamer-curation",
        "eliot-dreamer-candidate-validation",
        "eliot-dreamer-contracts",
        "Store",
        "provider",
    ] {
        assert!(
            !section.contains(forbidden),
            "dependency {forbidden} must be absent"
        );
    }
}

fn assert_send_sync<T: Send + Sync>() {}

// WORK_UNIT_CASE: 586/42
#[test]
fn no_store_provider_io_or_mutable_state_path() {
    const MODULE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/module.toml"));
    assert!(MODULE.contains("owned_mutable_state = []"));
    assert!(MODULE.contains("allowed_effects = []"));
    assert_send_sync::<SourceSnapshot>();
    assert_send_sync::<CurationScreenRequest>();
    assert_send_sync::<ScreenProfile>();
    assert_send_sync::<CurationFinding>();
    assert_send_sync::<ProtectionAssessment>();
    assert_send_sync::<Eligibility>();
    assert_send_sync::<ScreenCoverage>();
    assert_send_sync::<CumulativeCursor>();
    assert_send_sync::<CurationScreenResult>();
    assert_send_sync::<MemberDimensions>();
    assert_send_sync::<LegacyMigrationDescriptor>();
    assert!(!CONTRACT_NAME.is_empty());
    assert_eq!(
        CONTRACT_VERSION,
        eliot_contracts::ContractVersion::new(1, 0, 0)
    );
    let digest_text = must(serde_json::to_string(&digest()));
    assert_eq!(digest_text.len(), 66);
}

// WORK_UNIT_CASE: 586/43
#[test]
fn bounded_panic_free_malformed_inputs() {
    for text in ["", "   ", "a\tb", "a\nb"] {
        assert!(MemberId::new(text).is_err());
        assert!(SnapshotId::new(text).is_err());
        assert!(ProfileId::new(text).is_err());
        assert!(RuleId::new(text).is_err());
        assert!(FindingId::new(text).is_err());
        assert!(ProtectionEvidenceId::new(text).is_err());
        assert!(QueryId::new(text).is_err());
    }
    assert!(MemberId::new("x".repeat(300)).is_err());
    for text in [
        "",
        "abc",
        "ZZZZ",
        "000",
        "000000000000000000000000000000000000000000000000000000000000000G",
    ] {
        assert!(Digest::new(text).is_err());
    }
    assert!(
        Digest::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err()
    );
    let mut snapshot = snap(1);
    snapshot.identity.revision = 0;
    assert!(snapshot.validate().is_err());
    let mut profile = prof();
    profile.rules.clear();
    assert!(profile.validate().is_err());
    let mut profile = prof();
    profile.rules[0].rule_id = profile.rules[1].rule_id.clone();
    assert!(profile.validate().is_err());
    let snapshot = snap(1);
    let member_id = snapshot.members[0].member_id.clone();
    let mut decision = elig(
        &snapshot,
        &member_id,
        ProtectionDecision::Unprotected,
        EligibilityStatus::EligibleForSemanticCuration,
    );
    for index in 0..257 {
        decision
            .finding_ids
            .insert(must(FindingId::new(format!("f-{index}"))));
    }
    assert!(decision.validate(&[], &prof().profile_id).is_err());
    let mut assessment = assess(
        &snapshot,
        &member_id,
        "malformed",
        ProtectionDecision::Unknown,
        ProtectionOutcome::Unknown,
    );
    assessment.applicable_rule_ids.clear();
    for index in 0..33 {
        assessment
            .applicable_rule_ids
            .insert(must(RuleId::new(format!("rule-{index}"))));
    }
    assert!(assessment.validate().is_err());
}

// WORK_UNIT_CASE: 586/44
#[test]
fn complete_means_one_terminal_result_per_member_no_frontier() {
    for count in 0..5 {
        for changed in 0..=count {
            let snapshot = snap_split(count, changed, "44");
            let request = req(&snapshot);
            let dispositions: Vec<MemberDisposition> = (0..count)
                .map(|index| {
                    if index < changed {
                        MemberDisposition::Eligible
                    } else {
                        MemberDisposition::PreservedReference
                    }
                })
                .collect();
            let coverage = coverage_full(&snapshot, &dispositions);
            let mut result = result_skeleton(&snapshot, request, coverage, ResultState::Complete);
            for index in 0..changed {
                let id = snapshot.members[index].member_id.clone();
                result.protection.push(assess(
                    &snapshot,
                    &id,
                    &format!("fortyfour-{count}-{index}"),
                    ProtectionDecision::Unprotected,
                    ProtectionOutcome::Absent,
                ));
                result.eligibility.push(elig(
                    &snapshot,
                    &id,
                    ProtectionDecision::Unprotected,
                    EligibilityStatus::EligibleForSemanticCuration,
                ));
            }
            resign(&mut result);
            assert!(result.validate().is_ok());
            assert_eq!(result.coverage.members.len(), count);
            assert!(result.coverage.frontier.complete);
            assert!(result.coverage.frontier.remaining.is_empty());
            assert!(result.coverage.next_cursor.is_none());
            for position in 0..count {
                let mut open = result.clone();
                open.coverage.members[position].disposition = MemberDisposition::Unprocessed;
                open.coverage.members[position].eligible = false;
                resign(&mut open);
                assert!(open.validate().is_err());
            }
        }
    }
}

// WORK_UNIT_CASE: 586/45
#[test]
fn no_routing_application_lifecycle_or_authority_surface() {
    for schema in [
        schema_text::<CurationScreenRequest>(),
        schema_text::<CurationScreenResult>(),
        schema_text::<CurationFinding>(),
        schema_text::<Eligibility>(),
        schema_text::<ProtectionAssessment>(),
        schema_text::<ScreenCoverage>(),
        schema_text::<CumulativeCursor>(),
    ] {
        assert_no_keys(
            &schema,
            &[
                "routing",
                "route",
                "candidate",
                "finish",
                "apply",
                "execute",
                "store",
                "provider",
                "model",
                "authority",
                "effect",
                "lifecycle",
                "support",
                "accessibility",
                "influence",
                "erasure",
            ],
        );
    }
    for state in [
        ResultState::Complete,
        ResultState::Partial,
        ResultState::Blocked,
        ResultState::Unknown,
    ] {
        let wire = must(serde_json::to_string(&state));
        assert!(!wire.contains("FINISH"));
        assert!(!wire.contains("EFFECT"));
    }
    for disposition in [
        MemberDisposition::Eligible,
        MemberDisposition::Protected,
        MemberDisposition::Blocked,
        MemberDisposition::PreservedReference,
        MemberDisposition::Unprocessed,
    ] {
        let wire = must(serde_json::to_string(&disposition));
        assert!(!wire.contains("ROUTED"));
    }
}
