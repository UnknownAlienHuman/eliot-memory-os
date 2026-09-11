#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskRevision,
};
use eliot_memory_curation_contracts::*;
use eliot_memory_curation_screen::{CurationScreenError, screen_memory_curation};
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

fn source(count: usize, coverage: DenominatorCoverage) -> SourceSnapshot {
    let members = (0..count)
        .map(|index| SourceMember {
            member_id: MemberId::new(format!("member-{index}")).expect("member"),
            kind: SourceMemberKind::Observation,
            revision: TaskRevision::genesis(),
            content_digest: digest(),
            evidence: MemberEvidenceRefs::default(),
        })
        .collect::<Vec<_>>();
    let declared = members
        .iter()
        .map(|member| member.member_id.clone())
        .collect::<Vec<_>>();
    SourceSnapshot {
        identity: SourceIdentity {
            product_id: ProductId::new("eliot").expect("product"),
            source_id: SourceId::new("memory").expect("source"),
            snapshot_id: SnapshotId::new("snapshot-1").expect("snapshot"),
            query: QueryIdentity {
                query_id: QueryId::new("query-1").expect("query"),
                query_digest: digest(),
            },
            revision: 1,
            digest: digest(),
            scope: WorkScopeId::new("screen-scope").expect("scope"),
            state_fence: fence(),
        },
        denominator: FiniteDenominator {
            coverage,
            total_members: if coverage == DenominatorCoverage::Complete {
                count as u64
            } else {
                count as u64 + 1
            },
            declared_member_ids: declared.clone(),
        },
        partition: MemberPartition {
            changed_targets: declared.into_iter().collect(),
            immutable_references: BTreeSet::new(),
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

fn profile(rules: Vec<RuleSpec>) -> ScreenProfile {
    let requested_findings = rules.iter().map(|rule| rule.finding_class).collect();
    let precedence = rules.iter().map(|rule| rule.rule_id.clone()).collect();
    ScreenProfile {
        profile_id: ProfileId::new("profile-1").expect("profile"),
        schema_revision: PolicyRevision::genesis(),
        policy_revision: PolicyRevision::genesis(),
        rules,
        requested_findings,
        precedence,
        limits: ScreenLimits {
            max_items: 64,
            max_references: 256,
            max_bytes: 4 * 1024 * 1024,
            max_work_units: 100_000,
            max_output_bytes: 4 * 1024 * 1024,
            deadline_ms: None,
            cancellation_grace_ms: None,
        },
    }
}

fn request(snapshot: &SourceSnapshot, profile: ScreenProfile) -> CurationScreenRequest {
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
        profile,
        cursor: None,
        cancellation_requested: false,
    }
}

fn rule(id: &str, class: FindingClass, precedence: u16) -> RuleSpec {
    RuleSpec {
        rule_id: RuleId::new(id).expect("rule"),
        finding_class: class,
        precedence,
        required_protection: [ProtectionClass::CurrentTruth].into_iter().collect(),
    }
}

fn evidence(
    snapshot: &SourceSnapshot,
    member_id: MemberId,
    id: &str,
    state: ProtectionEvidenceState,
    outcome: ProtectionOutcome,
    invalidated: bool,
) -> ProtectionEvidence {
    ProtectionEvidence {
        evidence_id: ProtectionEvidenceId::new(id).expect("evidence"),
        member_id,
        source_id: snapshot.identity.source_id.clone(),
        snapshot_id: snapshot.identity.snapshot_id.clone(),
        class: ProtectionClass::CurrentTruth,
        state,
        outcome,
        references: BTreeSet::new(),
        state_fence: snapshot.identity.state_fence.clone(),
        scope: snapshot.identity.scope.clone(),
        disclosure_ceiling: DisclosureCeiling::ReferenceOnly,
        invalidated_by: invalidated.then(|| ProtectionEvidenceId::new("invalidation").expect("id")),
        digest: digest(),
    }
}

#[test]
fn complete_screen_preserves_reference_and_protection() {
    let mut snapshot = source(3, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    snapshot.members[1].evidence.provenance.clear();
    snapshot.members[2]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-2").expect("artifact"));
    let reference = snapshot.members[2].member_id.clone();
    snapshot.partition = MemberPartition {
        changed_targets: [
            snapshot.members[0].member_id.clone(),
            snapshot.members[1].member_id.clone(),
        ]
        .into_iter()
        .collect(),
        immutable_references: [reference.clone()].into_iter().collect(),
    };
    let profile = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let request = request(&snapshot, profile);
    let evidence = snapshot
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            evidence(
                &snapshot,
                member.member_id.clone(),
                &format!("evidence-{index}"),
                ProtectionEvidenceState::CurrentVerified,
                if index == 1 {
                    ProtectionOutcome::Present
                } else {
                    ProtectionOutcome::Absent
                },
                false,
            )
        })
        .collect::<Vec<_>>();
    let result = screen_memory_curation(&request, &snapshot, &evidence).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Eligible
    );
    assert_eq!(
        result.coverage.members[1].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[1].eligible);
    assert_eq!(
        result.coverage.members[2].disposition,
        MemberDisposition::PreservedReference
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

#[test]
fn findings_block_member_eligibility_and_keep_evidence_order_deterministic() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    snapshot.members[1]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let profile = profile(vec![
        rule("provenance_gap_v1", FindingClass::ProvenanceGap, 1),
        rule("conflict_ambiguity_v1", FindingClass::ConflictAmbiguity, 2),
    ]);
    let request = request(&snapshot, profile);
    let first = evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-a",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    );
    let second = evidence(
        &snapshot,
        snapshot.members[1].member_id.clone(),
        "evidence-b",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    );
    let third = evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-c",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    );
    let left = screen_memory_curation(
        &request,
        &snapshot,
        &[second.clone(), third.clone(), first.clone()],
    )
    .expect("screen");
    let right =
        screen_memory_curation(&request, &snapshot, &[first, second, third]).expect("screen");
    assert_eq!(left.result_digest, right.result_digest);
    assert!(
        left.eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::UnknownBlocked)
    );
    assert!(left.coverage.members.iter().all(|item| !item.eligible));
    assert_eq!(left.state, ResultState::Complete);
    assert!(left.coverage.frontier.complete);
    assert_eq!(left.findings.len(), 3);
}

#[test]
fn unknown_stale_and_invalidated_protection_fail_closed() {
    let snapshot = source(3, DenominatorCoverage::Complete);
    let request = request(
        &snapshot,
        profile(vec![rule(
            "provenance_gap_v1",
            FindingClass::ProvenanceGap,
            1,
        )]),
    );
    let evidence = vec![
        evidence(
            &snapshot,
            snapshot.members[0].member_id.clone(),
            "evidence-0",
            ProtectionEvidenceState::Unknown,
            ProtectionOutcome::Unknown,
            false,
        ),
        evidence(
            &snapshot,
            snapshot.members[1].member_id.clone(),
            "evidence-1",
            ProtectionEvidenceState::Stale,
            ProtectionOutcome::Absent,
            false,
        ),
        evidence(
            &snapshot,
            snapshot.members[2].member_id.clone(),
            "evidence-2",
            ProtectionEvidenceState::CurrentVerified,
            ProtectionOutcome::Present,
            true,
        ),
    ];
    let result = screen_memory_curation(&request, &snapshot, &evidence).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(
        result
            .protection
            .iter()
            .all(|item| item.decision == ProtectionDecision::Unknown)
    );
    assert!(result.findings.is_empty());
    assert!(
        result
            .eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::UnknownBlocked)
    );
}

#[test]
fn fully_observed_partial_denominator_is_partial_and_ineligible() {
    let mut snapshot = source(2, DenominatorCoverage::Partial);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let request = request(
        &snapshot,
        profile(vec![rule(
            "provenance_gap_v1",
            FindingClass::ProvenanceGap,
            1,
        )]),
    );
    let evidence = snapshot
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            evidence(
                &snapshot,
                member.member_id.clone(),
                &format!("evidence-{index}"),
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
                false,
            )
        })
        .collect::<Vec<_>>();
    let result = screen_memory_curation(&request, &snapshot, &evidence).expect("screen");
    assert_eq!(result.state, ResultState::Partial);
    assert!(!result.coverage.frontier.complete);
    assert!(
        result
            .eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::IncompleteTruncated)
    );
}

#[test]
fn unsupported_continuation_page_time_and_cancellation_are_explicit() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let profile = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let base = request(&snapshot, profile);
    let mut cursor_request = base.clone();
    cursor_request.cursor = Some(CumulativeCursor {
        request_id: base.binding.request_id.clone(),
        request_fingerprint: digest(),
        snapshot_id: base.source.snapshot_id.clone(),
        query: base.source.query.clone(),
        source_revision: 1,
        source_digest: digest(),
        profile_id: base.profile.profile_id.clone(),
        profile_digest: digest(),
        denominator: base.denominator.clone(),
        scope: base.source.scope.clone(),
        state_fence: base.source.state_fence.clone(),
        processed_member_digest: digest(),
        position: 0,
        usage: WorkUsage::default(),
        predecessor: None,
    });
    assert!(matches!(
        screen_memory_curation(&cursor_request, &snapshot, &[]),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "request.cursor"
        }))
    ));
    let mut paged = snapshot.clone();
    paged.page.has_more = true;
    assert!(matches!(
        screen_memory_curation(&base, &paged, &[]),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "source.page.frontier"
        }))
    ));
    let mut timed = base.clone();
    timed.profile.limits.deadline_ms = Some(1);
    assert!(matches!(
        screen_memory_curation(&timed, &snapshot, &[]),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "profile.limits.time"
        }))
    ));
    let mut cancelled = base;
    cancelled.cancellation_requested = true;
    assert!(matches!(
        screen_memory_curation(&cancelled, &snapshot, &[]),
        Err(CurationScreenError::Cancelled)
    ));
}

#[test]
fn independent_items_and_encoded_input_limits_fail_before_screening() {
    let snapshot = source(2, DenominatorCoverage::Complete);
    let mut item_limited = request(
        &snapshot,
        profile(vec![rule(
            "provenance_gap_v1",
            FindingClass::ProvenanceGap,
            1,
        )]),
    );
    item_limited.profile.limits.max_items = 1;
    assert!(matches!(
        screen_memory_curation(&item_limited, &snapshot, &[]),
        Err(CurationScreenError::Contract(ContractError::Bound {
            field: "screen.items"
        }))
    ));
    let mut byte_limited = item_limited;
    byte_limited.profile.limits.max_items = 64;
    byte_limited.profile.limits.max_bytes = 1;
    assert!(matches!(
        screen_memory_curation(&byte_limited, &snapshot, &[]),
        Err(CurationScreenError::Contract(ContractError::Bound {
            field: "screen.input_bytes"
        }))
    ));

    let mut complete = source(1, DenominatorCoverage::Complete);
    complete.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let complete_request = request(
        &complete,
        profile(vec![rule(
            "provenance_gap_v1",
            FindingClass::ProvenanceGap,
            1,
        )]),
    );
    let complete_evidence = vec![evidence(
        &complete,
        complete.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&complete_request, &complete, &complete_evidence)
        .expect("bounded result");
    assert!(result.coverage.usage.input_bytes > 0);
    assert!(result.coverage.usage.work_units > 0);
    let encoded = eliot_contracts::canonical_json_bytes(&result).expect("encoded result");
    assert_eq!(result.coverage.usage.output_bytes, encoded.len() as u64);
    assert!(result.coverage.usage.output_bytes <= complete_request.profile.limits.max_output_bytes);
    let mut output_limited = complete_request;
    output_limited.profile.limits.max_output_bytes = result.coverage.usage.output_bytes - 32;
    let limited_outcome = screen_memory_curation(&output_limited, &complete, &complete_evidence);
    assert!(matches!(
        limited_outcome,
        Err(CurationScreenError::Contract(ContractError::Bound {
            field: "result.output_bytes"
        }))
    ));
}
