#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    AuthorityEpoch, OperationId, PolicyRevision, ProductId, RequestId, ResourceGeneration,
    SourceId, StateFence, TaskRevision,
};
use eliot_memory_curation_contracts::*;
use eliot_receipts::WorkScopeId;

fn digest() -> Digest {
    Digest::new("0000000000000000000000000000000000000000000000000000000000000000")
        .expect("fixture digest")
}

fn fence() -> StateFence {
    let mut fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    fence.policy_revision = Some(PolicyRevision::genesis());
    fence
}

fn source(member_count: usize, coverage: DenominatorCoverage) -> SourceSnapshot {
    let members = (0..member_count)
        .map(|index| SourceMember {
            member_id: MemberId::new(format!("member-{index}")).expect("member id"),
            kind: SourceMemberKind::Observation,
            revision: TaskRevision::genesis(),
            content_digest: digest(),
            evidence: MemberEvidenceRefs::default(),
        })
        .collect::<Vec<_>>();
    let declared_member_ids = members
        .iter()
        .map(|member| member.member_id.clone())
        .collect::<Vec<_>>();
    let denominator = FiniteDenominator {
        coverage,
        total_members: if coverage == DenominatorCoverage::Complete {
            member_count as u64
        } else {
            member_count as u64 + 1
        },
        declared_member_ids: declared_member_ids.clone(),
    };
    SourceSnapshot {
        identity: SourceIdentity {
            product_id: ProductId::new("eliot").expect("product"),
            source_id: SourceId::new("canonical-memory").expect("source"),
            snapshot_id: SnapshotId::new("snapshot-1").expect("snapshot"),
            query: QueryIdentity {
                query_id: QueryId::new("query-1").expect("query"),
                query_digest: digest(),
            },
            revision: 1,
            digest: digest(),
            scope: WorkScopeId::new("test-scope").expect("scope"),
            state_fence: fence(),
        },
        denominator,
        partition: MemberPartition {
            changed_targets: declared_member_ids.into_iter().collect(),
            immutable_references: BTreeSet::new(),
        },
        availability: if coverage == DenominatorCoverage::Complete {
            SourceAvailability::Available
        } else {
            SourceAvailability::Partial
        },
        members,
        page: SourcePage {
            page_number: 0,
            has_more: false,
            frontier: Vec::new(),
        },
    }
}

fn profile() -> ScreenProfile {
    let rule_id = RuleId::new("rule-1").expect("rule");
    ScreenProfile {
        profile_id: ProfileId::new("profile-1").expect("profile"),
        schema_revision: PolicyRevision::genesis(),
        policy_revision: PolicyRevision::genesis(),
        rules: vec![RuleSpec {
            rule_id: rule_id.clone(),
            finding_class: FindingClass::Duplicate,
            precedence: 1,
            required_protection: [ProtectionClass::CurrentTruth].into_iter().collect(),
        }],
        requested_findings: [FindingClass::Duplicate].into_iter().collect(),
        precedence: vec![rule_id],
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

fn request(snapshot: &SourceSnapshot) -> CurationScreenRequest {
    CurationScreenRequest {
        source: snapshot.identity.clone(),
        denominator: snapshot.denominator.clone(),
        partition: snapshot.partition.clone(),
        binding: RequestBinding {
            request_id: RequestId::new("request-1").expect("request"),
            operation_id: OperationId::new("operation-1").expect("operation"),
            task_id: None,
            attempt_id: AgentAttemptId::new("attempt-1").expect("attempt"),
            scope: snapshot.identity.scope.clone(),
            state_fence: snapshot.identity.state_fence.clone(),
        },
        profile: profile(),
        cursor: None,
        cancellation_requested: false,
    }
}

fn owner_evidence(snapshot: &SourceSnapshot, member_id: MemberId) -> ProtectionEvidence {
    owner_evidence_with_outcome(snapshot, member_id, ProtectionOutcome::Absent)
}

fn owner_evidence_with_outcome(
    snapshot: &SourceSnapshot,
    member_id: MemberId,
    outcome: ProtectionOutcome,
) -> ProtectionEvidence {
    ProtectionEvidence {
        evidence_id: ProtectionEvidenceId::new("protection-1").expect("evidence"),
        member_id,
        source_id: snapshot.identity.source_id.clone(),
        snapshot_id: snapshot.identity.snapshot_id.clone(),
        class: ProtectionClass::CurrentTruth,
        state: ProtectionEvidenceState::CurrentVerified,
        outcome,
        references: BTreeSet::new(),
        state_fence: snapshot.identity.state_fence.clone(),
        scope: snapshot.identity.scope.clone(),
        disclosure_ceiling: DisclosureCeiling::ReferenceOnly,
        invalidated_by: None,
        digest: digest(),
    }
}

#[test]
fn complete_source_and_partial_empty_are_distinct() {
    let mut page = source(3, DenominatorCoverage::Complete);
    page.members.truncate(1);
    page.page.has_more = true;
    page.page.frontier = vec![
        MemberId::new("member-1").expect("member"),
        MemberId::new("member-2").expect("member"),
    ];
    assert!(page.validate().is_ok());
    let complete = source(0, DenominatorCoverage::Complete);
    assert!(complete.validate().is_ok());
    let partial = source(0, DenominatorCoverage::Partial);
    assert!(partial.validate().is_ok());
    assert_ne!(complete.denominator.coverage, partial.denominator.coverage);
}

#[test]
fn source_round_trip_rejects_unknown_fields() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let encoded = serde_json::to_string(&snapshot).expect("encode");
    let decoded: SourceSnapshot = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(snapshot, decoded);
    let malformed = encoded.trim_end_matches('}').to_owned() + ",\"unexpected\":true}";
    assert!(serde_json::from_str::<SourceSnapshot>(&malformed).is_err());
}

#[test]
fn protection_unknown_cannot_clear_required_evidence() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let assessment = ProtectionAssessment {
        source: snapshot.identity.clone(),
        member_id: snapshot.members[0].member_id.clone(),
        applicable_rule_ids: [RuleId::new("rule-1").expect("rule")].into_iter().collect(),
        required: [ProtectionClass::CurrentTruth].into_iter().collect(),
        evidence: Vec::new(),
        decision: ProtectionDecision::Unprotected,
    };
    assert!(assessment.validate().is_err());
}

#[test]
fn cursor_binds_request_and_conserves_processed_work() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let mut req = request(&snapshot);
    req.cursor = Some(CumulativeCursor {
        request_id: req.binding.request_id.clone(),
        request_fingerprint: req.request_fingerprint().expect("request fingerprint"),
        snapshot_id: snapshot.identity.snapshot_id.clone(),
        profile_id: req.profile.profile_id.clone(),
        query: req.source.query.clone(),
        source_revision: req.source.revision,
        source_digest: req.source.digest.clone(),
        profile_digest: contract_digest(&req.profile).expect("profile digest"),
        denominator: req.denominator.clone(),
        scope: req.source.scope.clone(),
        state_fence: req.source.state_fence.clone(),
        processed_member_digest: contract_digest(&vec![snapshot.members[0].member_id.clone()])
            .expect("processed digest"),
        position: 1,
        usage: WorkUsage {
            processed_items: 1,
            work_units: 1,
            input_bytes: 1,
            output_bytes: 1,
        },
        predecessor: None,
    });
    assert!(req.validate().is_ok());
    let cursor = req.cursor.clone().expect("cursor");
    assert!(
        cursor
            .validate_progress(
                &req,
                &snapshot,
                None,
                &[snapshot.members[0].member_id.clone()]
            )
            .is_ok()
    );
    req.binding.request_id = RequestId::new("other-request").expect("request");
    assert!(req.validate().is_err());
}

#[test]
fn complete_result_reconciles_one_terminal_disposition() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let req = request(&snapshot);
    let member_id = snapshot.members[0].member_id.clone();
    let mut coverage = ScreenCoverage {
        denominator: FiniteDenominator {
            coverage: DenominatorCoverage::Complete,
            total_members: 1,
            declared_member_ids: vec![member_id.clone()],
        },
        start_position: 0,
        members: vec![MemberCoverage {
            member_id: member_id.clone(),
            disposition: MemberDisposition::Eligible,
            finding_ids: BTreeSet::new(),
            eligible: true,
        }],
        frontier: ScreenFrontier {
            complete: true,
            remaining: Vec::new(),
        },
        usage: WorkUsage {
            processed_items: 1,
            work_units: 1,
            input_bytes: 1,
            output_bytes: 1,
        },
        next_cursor: None,
        digest: digest(),
    };
    coverage.digest = coverage.computed_digest().expect("coverage digest");
    let mut result = CurationScreenResult {
        request: req,
        source: snapshot,
        findings: Vec::new(),
        protection: vec![ProtectionAssessment {
            source: source(1, DenominatorCoverage::Complete).identity,
            member_id: member_id.clone(),
            applicable_rule_ids: [RuleId::new("rule-1").expect("rule")].into_iter().collect(),
            required: [ProtectionClass::CurrentTruth].into_iter().collect(),
            evidence: vec![owner_evidence(
                &source(1, DenominatorCoverage::Complete),
                member_id.clone(),
            )],
            decision: ProtectionDecision::Unprotected,
        }],
        eligibility: vec![Eligibility {
            source: source(1, DenominatorCoverage::Complete).identity,
            member_id: member_id.clone(),
            protection: ProtectionDecision::Unprotected,
            finding_ids: BTreeSet::new(),
            status: EligibilityStatus::EligibleForSemanticCuration,
        }],
        coverage,
        member_sets: MemberSets {
            changed_targets: [member_id].into_iter().collect(),
            immutable_references: BTreeSet::new(),
        },
        state: ResultState::Complete,
        result_digest: digest(),
    };
    result.result_digest = result.computed_digest().expect("result digest");
    assert!(result.validate().is_ok());
    let mut conflicting = result;
    let target = conflicting
        .member_sets
        .changed_targets
        .iter()
        .next()
        .cloned()
        .expect("target");
    conflicting.member_sets.immutable_references.insert(target);
    assert!(
        conflicting.validate().is_err(),
        "changed targets and immutable references must be disjoint"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn two_page_result_reconciles_targets_references_and_terminal_protection() {
    let mut full = source(3, DenominatorCoverage::Complete);
    let first = full.members[0].member_id.clone();
    let reference = full.members[1].member_id.clone();
    let last = full.members[2].member_id.clone();
    full.partition = MemberPartition {
        changed_targets: [first.clone(), last.clone()].into_iter().collect(),
        immutable_references: [reference.clone()].into_iter().collect(),
    };
    let req = request(&full);
    let protected_first = ProtectionAssessment {
        source: full.identity.clone(),
        member_id: first.clone(),
        applicable_rule_ids: [RuleId::new("rule-1").expect("rule")].into_iter().collect(),
        required: [ProtectionClass::CurrentTruth].into_iter().collect(),
        evidence: vec![owner_evidence_with_outcome(
            &full,
            first.clone(),
            ProtectionOutcome::Present,
        )],
        decision: ProtectionDecision::Protected,
    };
    let protected_reference = ProtectionAssessment {
        source: full.identity.clone(),
        member_id: reference.clone(),
        applicable_rule_ids: [RuleId::new("rule-1").expect("rule")].into_iter().collect(),
        required: [ProtectionClass::CurrentTruth].into_iter().collect(),
        evidence: vec![owner_evidence_with_outcome(
            &full,
            reference.clone(),
            ProtectionOutcome::Present,
        )],
        decision: ProtectionDecision::Protected,
    };
    let clear_last = ProtectionAssessment {
        source: full.identity.clone(),
        member_id: last.clone(),
        applicable_rule_ids: [RuleId::new("rule-1").expect("rule")].into_iter().collect(),
        required: [ProtectionClass::CurrentTruth].into_iter().collect(),
        evidence: vec![owner_evidence_with_outcome(
            &full,
            last.clone(),
            ProtectionOutcome::Absent,
        )],
        decision: ProtectionDecision::Unprotected,
    };
    let first_cursor = CumulativeCursor {
        request_id: req.binding.request_id.clone(),
        request_fingerprint: req.request_fingerprint().expect("request fingerprint"),
        snapshot_id: full.identity.snapshot_id.clone(),
        profile_id: req.profile.profile_id.clone(),
        query: req.source.query.clone(),
        source_revision: req.source.revision,
        source_digest: req.source.digest.clone(),
        profile_digest: contract_digest(&req.profile).expect("profile digest"),
        denominator: req.denominator.clone(),
        scope: req.source.scope.clone(),
        state_fence: req.source.state_fence.clone(),
        processed_member_digest: contract_digest(&vec![first.clone(), reference.clone()])
            .expect("processed digest"),
        position: 2,
        usage: WorkUsage {
            processed_items: 2,
            work_units: 2,
            input_bytes: 2,
            output_bytes: 2,
        },
        predecessor: None,
    };
    let mut first_coverage = ScreenCoverage {
        denominator: req.denominator.clone(),
        start_position: 0,
        members: vec![
            MemberCoverage {
                member_id: first.clone(),
                disposition: MemberDisposition::Protected,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
            MemberCoverage {
                member_id: reference.clone(),
                disposition: MemberDisposition::PreservedReference,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
        ],
        frontier: ScreenFrontier {
            complete: false,
            remaining: vec![last.clone()],
        },
        usage: first_cursor.usage,
        next_cursor: Some(first_cursor.clone()),
        digest: digest(),
    };
    first_coverage.digest = first_coverage.computed_digest().expect("coverage digest");
    let mut first_result = CurationScreenResult {
        request: req,
        source: full.clone(),
        findings: Vec::new(),
        protection: vec![protected_first.clone(), protected_reference.clone()],
        eligibility: Vec::new(),
        coverage: first_coverage,
        member_sets: MemberSets {
            changed_targets: [first.clone(), last.clone()].into_iter().collect(),
            immutable_references: [reference.clone()].into_iter().collect(),
        },
        state: ResultState::Partial,
        result_digest: digest(),
    };
    first_result.result_digest = first_result.computed_digest().expect("result digest");
    assert!(first_result.validate().is_ok());

    let mut second_request = request(&full);
    second_request.cursor = Some(first_cursor);
    let mut second_coverage = ScreenCoverage {
        denominator: second_request.denominator.clone(),
        start_position: 2,
        members: vec![
            MemberCoverage {
                member_id: first,
                disposition: MemberDisposition::Protected,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
            MemberCoverage {
                member_id: reference,
                disposition: MemberDisposition::PreservedReference,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
            MemberCoverage {
                member_id: last.clone(),
                disposition: MemberDisposition::Eligible,
                finding_ids: BTreeSet::new(),
                eligible: true,
            },
        ],
        frontier: ScreenFrontier {
            complete: true,
            remaining: Vec::new(),
        },
        usage: WorkUsage {
            processed_items: 3,
            work_units: 3,
            input_bytes: 3,
            output_bytes: 3,
        },
        next_cursor: None,
        digest: digest(),
    };
    second_coverage.digest = second_coverage.computed_digest().expect("coverage digest");
    let mut second_result = CurationScreenResult {
        request: second_request,
        source: full,
        findings: Vec::new(),
        protection: vec![protected_first, protected_reference, clear_last],
        eligibility: vec![Eligibility {
            source: source(3, DenominatorCoverage::Complete).identity,
            member_id: last,
            protection: ProtectionDecision::Unprotected,
            finding_ids: BTreeSet::new(),
            status: EligibilityStatus::EligibleForSemanticCuration,
        }],
        coverage: second_coverage,
        member_sets: MemberSets {
            changed_targets: [
                MemberId::new("member-0").expect("member"),
                MemberId::new("member-2").expect("member"),
            ]
            .into_iter()
            .collect(),
            immutable_references: [MemberId::new("member-1").expect("member")]
                .into_iter()
                .collect(),
        },
        state: ResultState::Complete,
        result_digest: digest(),
    };
    second_result.result_digest = second_result.computed_digest().expect("result digest");
    assert!(second_result.validate().is_ok());
}
