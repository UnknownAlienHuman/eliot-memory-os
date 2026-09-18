#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskRevision,
};
use eliot_memory_curation_contracts::*;
use eliot_memory_curation_screen::{
    CurationScreenError, assess_dimensions, screen_memory_curation,
};
use eliot_receipts::WorkScopeId;

fn digest() -> Digest {
    Digest::new("0000000000000000000000000000000000000000000000000000000000000000")
        .expect("fixture digest")
}

fn fence() -> StateFence {
    let mut fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
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
fn screen_dispositions_agree_with_dimension_derivation() {
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
        immutable_references: [reference].into_iter().collect(),
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
    assert!(result.validate().is_ok());
    for member in &result.coverage.members {
        let assessment = result
            .protection
            .iter()
            .find(|item| item.member_id == member.member_id)
            .expect("protection assessment");
        let dimensions = assess_dimensions(
            &member.member_id,
            assessment,
            &result.findings,
            request
                .partition
                .immutable_references
                .contains(&member.member_id),
            true,
            true,
        )
        .expect("dimension assessment");
        assert_eq!(
            dimensions.derive_disposition().expect("derive"),
            member.disposition,
            "emitted disposition must equal the dimension derivation"
        );
    }
    let eligible = result
        .coverage
        .members
        .iter()
        .find(|item| item.disposition == MemberDisposition::Eligible)
        .expect("eligible member");
    let eligible_dimensions = assess_dimensions(
        &eligible.member_id,
        result
            .protection
            .iter()
            .find(|item| item.member_id == eligible.member_id)
            .expect("protection assessment"),
        &result.findings,
        false,
        true,
        true,
    )
    .expect("dimension assessment");
    assert!(
        eligible_dimensions
            .verdicts
            .iter()
            .all(|verdict| verdict.outcome == DimensionOutcome::Clear)
    );
}

#[test]
fn provenance_gap_taints_only_the_support_dimension() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let request = request(
        &snapshot,
        profile(vec![rule(
            "provenance_gap_v1",
            FindingClass::ProvenanceGap,
            1,
        )]),
    );
    let evidence = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&request, &snapshot, &evidence).expect("screen");
    assert_eq!(result.findings.len(), 1);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    let assessment = result.protection.first().expect("protection assessment");
    let dimensions = assess_dimensions(
        &snapshot.members[0].member_id,
        assessment,
        &result.findings,
        false,
        true,
        true,
    )
    .expect("dimension assessment");
    for verdict in &dimensions.verdicts {
        if verdict.dimension == CurationDimension::Support {
            assert_eq!(verdict.outcome, DimensionOutcome::Flagged);
            assert_eq!(verdict.finding_ids.len(), 1);
        } else {
            assert_eq!(
                verdict.outcome,
                DimensionOutcome::Clear,
                "finding must not leak into {dimension:?}",
                dimension = verdict.dimension
            );
        }
    }
    assert_eq!(
        dimensions.derive_disposition().expect("derive"),
        MemberDisposition::Blocked
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

// WORK_UNIT_CASE: 588/1
#[test]
fn bounded_single_call_complete_screen_is_deterministic() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let ev = snapshot
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
    let first = screen_memory_curation(&req, &snapshot, &ev).expect("screen");
    let second = screen_memory_curation(&req, &snapshot, &ev).expect("replay");
    assert_eq!(first.state, ResultState::Complete);
    assert!(first.coverage.frontier.complete);
    assert!(first.coverage.next_cursor.is_none());
    assert!(first.findings.is_empty());
    assert_eq!(first.result_digest, second.result_digest);
    assert!(first.validate().is_ok());
    assert_eq!(first.coverage.members.len(), 2);
    for member in &first.coverage.members {
        assert_eq!(member.disposition, MemberDisposition::Eligible);
        assert!(member.eligible);
    }
    assert!(first.coverage.usage.input_bytes > 0);
    assert!(first.coverage.usage.work_units > 0);
}

// WORK_UNIT_CASE: 588/15
#[test]
fn protection_wins_over_structural_findings() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    assert!(snapshot.members[0].evidence.provenance.is_empty());
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof.clone());
    let protected_ev = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-protected",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let protected_result =
        screen_memory_curation(&req, &snapshot, &protected_ev).expect("protected screen");
    assert!(protected_result.findings.is_empty());
    assert_eq!(
        protected_result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!protected_result.coverage.members[0].eligible);
    let req2 = request(&snapshot, prof);
    let unprotected_ev = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-clear",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let unprotected_result =
        screen_memory_curation(&req2, &snapshot, &unprotected_ev).expect("unprotected screen");
    assert_eq!(unprotected_result.findings.len(), 1);
    assert_eq!(
        unprotected_result.findings[0].class,
        FindingClass::ProvenanceGap
    );
}

// WORK_UNIT_CASE: 588/26
#[test]
fn each_member_has_one_disjoint_disposition() {
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
        immutable_references: [reference].into_iter().collect(),
    };
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let ev = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &ev).expect("screen");
    assert!(result.validate().is_ok());
    assert_eq!(result.coverage.members.len(), snapshot.members.len());
    let mut seen = BTreeSet::new();
    for (coverage, member) in result.coverage.members.iter().zip(snapshot.members.iter()) {
        assert_eq!(coverage.member_id, member.member_id);
        assert!(seen.insert(coverage.member_id.clone()));
        assert_eq!(
            coverage.eligible,
            coverage.disposition == MemberDisposition::Eligible
        );
    }
    assert_eq!(seen.len(), 3);
    assert!(result.coverage.frontier.complete);
    assert!(result.coverage.frontier.remaining.is_empty());
}

// WORK_UNIT_CASE: 588/32
#[test]
fn cursor_continuation_rejected_single_call_only() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let base = request(&snapshot, prof);
    let ev = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let ok = screen_memory_curation(&base, &snapshot, &ev).expect("single call works");
    assert_eq!(ok.state, ResultState::Complete);
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
        screen_memory_curation(&cursor_request, &snapshot, &ev),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "request.cursor"
        }))
    ));
}

// WORK_UNIT_CASE: 588/35
#[test]
fn exact_replay_stable_changed_input_invalidates() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let clear_ev = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let first = screen_memory_curation(&req, &snapshot, &clear_ev).expect("screen");
    let replay = screen_memory_curation(&req, &snapshot, &clear_ev).expect("replay");
    assert_eq!(first.result_digest, replay.result_digest);
    let changed_ev = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let changed = screen_memory_curation(&req, &snapshot, &changed_ev).expect("changed screen");
    assert_ne!(first.result_digest, changed.result_digest);
    assert_ne!(
        first.coverage.members[0].disposition,
        changed.coverage.members[0].disposition
    );
}

// WORK_UNIT_CASE: 588/44
#[test]
fn eligible_output_has_no_kind_handler_action_path() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let ev = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &ev).expect("screen");
    assert!(result.validate().is_ok());
    assert_eq!(result.state, ResultState::Complete);
    assert!(result.coverage.next_cursor.is_none());
    let eligibility_bytes =
        eliot_contracts::canonical_json_bytes(&result.eligibility).expect("eligibility json");
    let eligibility_text = String::from_utf8(eligibility_bytes).expect("eligibility utf8");
    for forbidden in [
        "handler", "family", "action", "route", "mutation", "Finish", "provider", "Store", "model",
        "\"kind\"",
    ] {
        assert!(
            !eligibility_text.contains(forbidden),
            "eligibility must not contain {forbidden}"
        );
    }
    for item in &result.eligibility {
        assert_ne!(item.status, EligibilityStatus::UnknownBlocked);
    }
    for finding in &result.findings {
        assert!(matches!(
            finding.class,
            FindingClass::ProvenanceGap | FindingClass::ConflictAmbiguity
        ));
    }
}

fn rule_with_protection(
    id: &str,
    class: FindingClass,
    precedence: u16,
    required: ProtectionClass,
) -> RuleSpec {
    RuleSpec {
        rule_id: RuleId::new(id).expect("rule"),
        finding_class: class,
        precedence,
        required_protection: [required].into_iter().collect(),
    }
}

fn evidence_with_class(
    snapshot: &SourceSnapshot,
    member_id: MemberId,
    id: &str,
    class: ProtectionClass,
    state: ProtectionEvidenceState,
    outcome: ProtectionOutcome,
    invalidated: bool,
) -> ProtectionEvidence {
    let mut record = evidence(snapshot, member_id, id, state, outcome, invalidated);
    record.class = class;
    record
}

// WORK_UNIT_CASE: 588/2
#[test]
fn current_truth_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::CurrentTruth)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/3
#[test]
fn minority_dissent_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::MinorityDissent,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::MinorityDissent,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::MinorityDissent)
    );
    assert_eq!(
        result.protection[0].evidence[0].class,
        ProtectionClass::MinorityDissent
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/4
#[test]
fn unresolved_conflict_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::UnresolvedConflict,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::UnresolvedConflict,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::UnresolvedConflict)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/5
#[test]
fn negative_memory_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::NegativeMemory,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::NegativeMemory,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::NegativeMemory)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/6
#[test]
fn counterexample_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::Counterexample,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::Counterexample,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::Counterexample)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/7
#[test]
fn retention_erasure_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::RetentionErasure,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::RetentionErasure,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::RetentionErasure)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/8
#[test]
fn protected_dependency_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::ProtectedDependency,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::ProtectedDependency,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::ProtectedDependency)
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/9
#[test]
fn audit_history_present_is_protected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::AuditHistory,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::AuditHistory,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Protected);
    assert!(
        result.protection[0]
            .required
            .contains(&ProtectionClass::AuditHistory)
    );
    assert_eq!(
        result.protection[0].evidence[0].class,
        ProtectionClass::AuditHistory
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Protected
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(result.eligibility[0].status, EligibilityStatus::Protected);
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/10
#[test]
fn dissent_absent_clears_to_eligible() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::MinorityDissent,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::MinorityDissent,
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert!(result.coverage.frontier.complete);
    assert_eq!(
        result.protection[0].decision,
        ProtectionDecision::Unprotected
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Eligible
    );
    assert!(result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::EligibleForSemanticCuration
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/11
#[test]
fn missing_evidence_fails_closed_unknown() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::MinorityDissent,
    )]);
    let req = request(&snapshot, prof);
    let records: Vec<ProtectionEvidence> = Vec::new();
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/12
#[test]
fn stale_dissent_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::MinorityDissent,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence_with_class(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionClass::MinorityDissent,
        ProtectionEvidenceState::Stale,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/13
#[test]
fn invalidated_present_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Present,
        true,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/14
#[test]
fn wrong_class_clear_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule_with_protection(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
        ProtectionClass::MinorityDissent,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/16
#[test]
fn malformed_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::Malformed,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/17
#[test]
fn unavailable_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::Unavailable,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/18
#[test]
fn unknown_state_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::Unknown,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/19
#[test]
fn unknown_outcome_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Unknown,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/20
#[test]
fn invalidated_absent_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        true,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/21
#[test]
fn empty_evidence_fails_closed() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records: Vec<ProtectionEvidence> = Vec::new();
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert_eq!(result.protection[0].decision, ProtectionDecision::Unknown);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.findings.is_empty());
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/22
#[test]
fn conflict_ambiguity_finding_blocks_member() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    snapshot.members[0]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let prof = profile(vec![rule(
        "conflict_ambiguity_v1",
        FindingClass::ConflictAmbiguity,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert!(result.coverage.frontier.complete);
    assert_eq!(
        result.protection[0].decision,
        ProtectionDecision::Unprotected
    );
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].class, FindingClass::ConflictAmbiguity);
    assert_eq!(result.findings[0].proof, FindingProof::Deterministic);
    assert_eq!(
        result.findings[0].invariant,
        "member retains one or more conflict references"
    );
    assert!(
        result.findings[0]
            .evidence
            .contains(&ArtifactId::new("conflict-1").expect("artifact"))
    );
    assert!(result.findings[0].invalidated_by.is_none());
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    let assessment = result.protection.first().expect("protection assessment");
    let dimensions = assess_dimensions(
        &snapshot.members[0].member_id,
        assessment,
        &result.findings,
        false,
        true,
        true,
    )
    .expect("dimension assessment");
    let support = dimensions
        .verdict(CurationDimension::Support)
        .expect("support verdict");
    assert_eq!(support.outcome, DimensionOutcome::Flagged);
    assert_eq!(support.finding_ids.len(), 1);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/23
#[test]
fn provenance_gap_finding_blocks_member() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    assert!(snapshot.members[0].evidence.provenance.is_empty());
    assert!(snapshot.members[0].evidence.conflict.is_empty());
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert!(result.coverage.frontier.complete);
    assert_eq!(
        result.protection[0].decision,
        ProtectionDecision::Unprotected
    );
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].class, FindingClass::ProvenanceGap);
    assert_eq!(result.findings[0].proof, FindingProof::Deterministic);
    assert_eq!(
        result.findings[0].invariant,
        "member has no supplied provenance handle"
    );
    assert!(result.findings[0].evidence.is_empty());
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/24
#[test]
fn both_structural_rules_fire_deterministically() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let prof = profile(vec![
        rule("provenance_gap_v1", FindingClass::ProvenanceGap, 1),
        rule("conflict_ambiguity_v1", FindingClass::ConflictAmbiguity, 2),
    ]);
    let req = request(&snapshot, prof);
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
        snapshot.members[0].member_id.clone(),
        "evidence-b",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    );
    let left =
        screen_memory_curation(&req, &snapshot, &[second.clone(), first.clone()]).expect("screen");
    let right = screen_memory_curation(&req, &snapshot, &[first, second]).expect("screen");
    assert_eq!(left.result_digest, right.result_digest);
    assert_eq!(left.findings.len(), 2);
    assert_eq!(left.findings[0].class, FindingClass::ProvenanceGap);
    assert_eq!(left.findings[1].class, FindingClass::ConflictAmbiguity);
    assert_eq!(left.state, ResultState::Complete);
    assert_eq!(
        left.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!left.coverage.members[0].eligible);
    assert_eq!(
        left.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    assert!(left.validate().is_ok());
    assert!(right.validate().is_ok());
}

// WORK_UNIT_CASE: 588/25
#[test]
fn unsupported_rule_id_rejected() {
    let snapshot = source(1, DenominatorCoverage::Complete);
    let prof = profile(vec![rule(
        "unknown_rule_v9",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    assert!(matches!(
        screen_memory_curation(&req, &snapshot, &records),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "profile.rule_id"
        }))
    ));
}

// WORK_UNIT_CASE: 588/27
#[test]
fn stale_source_availability_blocks() {
    // source_status() maps Stale to StaleUnavailable, but a Complete
    // denominator with non-Available availability is unrepresentable
    // (SourceSnapshot::validate rejects it), so this Partial case asserts
    // IncompleteTruncated while the Blocked state proves fail-closed.
    let mut snapshot = source(1, DenominatorCoverage::Partial);
    snapshot.availability = SourceAvailability::Stale;
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::IncompleteTruncated
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/28
#[test]
fn malformed_source_availability_blocks() {
    // source_status() maps Malformed to UnknownBlocked; Partial denominator
    // shadows the per-member status to IncompleteTruncated (see 588/27).
    let mut snapshot = source(1, DenominatorCoverage::Partial);
    snapshot.availability = SourceAvailability::Malformed;
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::IncompleteTruncated
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/29
#[test]
fn unavailable_source_availability_blocks() {
    // source_status() maps Unavailable to StaleUnavailable; Partial
    // denominator shadows the per-member status (see 588/27).
    let mut snapshot = source(1, DenominatorCoverage::Partial);
    snapshot.availability = SourceAvailability::Unavailable;
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::IncompleteTruncated
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/30
#[test]
fn unknown_source_availability_blocks() {
    // source_status() maps Unknown to UnknownBlocked; Partial denominator
    // shadows the per-member status (see 588/27).
    let mut snapshot = source(1, DenominatorCoverage::Partial);
    snapshot.availability = SourceAvailability::Unknown;
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::IncompleteTruncated
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/31
#[test]
fn blocked_source_availability_blocks() {
    // source_status() maps Blocked to UnknownBlocked; Partial denominator
    // shadows the per-member status (see 588/27).
    let mut snapshot = source(1, DenominatorCoverage::Partial);
    snapshot.availability = SourceAvailability::Blocked;
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Blocked);
    assert!(!result.coverage.frontier.complete);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::IncompleteTruncated
    );
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert!(!result.coverage.members[0].eligible);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/33
#[test]
fn partial_denominator_is_partial_not_complete() {
    let mut snapshot = source(2, DenominatorCoverage::Partial);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Partial);
    assert!(!result.coverage.frontier.complete);
    assert!(result.coverage.next_cursor.is_none());
    assert_eq!(result.coverage.members.len(), 2);
    assert!(
        result
            .eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::IncompleteTruncated)
    );
    for member in &result.coverage.members {
        assert_eq!(member.disposition, MemberDisposition::Blocked);
        assert!(!member.eligible);
    }
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/34
#[test]
fn immutable_reference_is_preserved_outside_scope() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let changed = snapshot.members[0].member_id.clone();
    let reference = snapshot.members[1].member_id.clone();
    snapshot.partition = MemberPartition {
        changed_targets: [changed].into_iter().collect(),
        immutable_references: [reference].into_iter().collect(),
    };
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Complete);
    assert!(result.coverage.frontier.complete);
    assert_eq!(
        result.coverage.members[0].disposition,
        MemberDisposition::Eligible
    );
    assert!(result.coverage.members[0].eligible);
    assert_eq!(
        result.eligibility[0].status,
        EligibilityStatus::EligibleForSemanticCuration
    );
    assert_eq!(
        result.coverage.members[1].disposition,
        MemberDisposition::PreservedReference
    );
    assert!(!result.coverage.members[1].eligible);
    assert_eq!(
        result.eligibility[1].status,
        EligibilityStatus::OutsideScope
    );
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/36
#[test]
fn snapshot_mutation_invalidates_digest_and_disposition() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let before = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(before.findings.len(), 1);
    assert_eq!(
        before.coverage.members[0].disposition,
        MemberDisposition::Blocked
    );
    assert_eq!(
        before.eligibility[0].status,
        EligibilityStatus::UnknownBlocked
    );
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let after = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert!(after.findings.is_empty());
    assert_eq!(
        after.coverage.members[0].disposition,
        MemberDisposition::Eligible
    );
    assert_eq!(
        after.eligibility[0].status,
        EligibilityStatus::EligibleForSemanticCuration
    );
    assert_ne!(before.result_digest, after.result_digest);
    assert!(before.validate().is_ok());
    assert!(after.validate().is_ok());
}

// WORK_UNIT_CASE: 588/37
#[test]
fn rule_set_change_invalidates_digest() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let base_profile = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let base_request = request(&snapshot, base_profile);
    let alt_profile = profile(vec![
        rule("provenance_gap_v1", FindingClass::ProvenanceGap, 1),
        rule("conflict_ambiguity_v1", FindingClass::ConflictAmbiguity, 2),
    ]);
    assert!(
        alt_profile
            .requested_findings
            .contains(&FindingClass::ConflictAmbiguity)
    );
    let alt_request = request(&snapshot, alt_profile);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let base = screen_memory_curation(&base_request, &snapshot, &records).expect("screen");
    let alt = screen_memory_curation(&alt_request, &snapshot, &records).expect("screen");
    assert_ne!(base.result_digest, alt.result_digest);
    assert_eq!(base.state, ResultState::Complete);
    assert_eq!(alt.state, ResultState::Complete);
    assert!(base.validate().is_ok());
    assert!(alt.validate().is_ok());
}

// WORK_UNIT_CASE: 588/38
#[test]
fn work_unit_and_byte_accounting_exact() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    // work_units == members + evidence_records + members * profile_rules
    // with n = 2 members, e = 2 records, r = 1 rule.
    assert_eq!(result.coverage.usage.work_units, 6);
    assert_eq!(result.coverage.usage.processed_items, 2);
    assert!(result.coverage.usage.input_bytes > 0);
    assert!(result.coverage.usage.work_units > 0);
    let encoded = eliot_contracts::canonical_json_bytes(&result).expect("encoded result");
    assert_eq!(result.coverage.usage.output_bytes, encoded.len() as u64);
    let partial = source(2, DenominatorCoverage::Partial);
    assert_eq!(
        partial.denominator.total_members,
        partial.denominator.declared_member_ids.len() as u64 + 1
    );
    assert_eq!(partial.denominator.total_members, 3);
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/39
#[test]
fn partial_prefix_accounting_without_unprocessed() {
    let mut snapshot = source(2, DenominatorCoverage::Partial);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.state, ResultState::Partial);
    assert!(!result.coverage.frontier.complete);
    assert!(result.coverage.frontier.remaining.is_empty());
    assert!(result.coverage.next_cursor.is_none());
    assert_eq!(result.coverage.members.len(), 2);
    assert_eq!(result.coverage.denominator.total_members, 3);
    for member in &result.coverage.members {
        assert_ne!(member.disposition, MemberDisposition::Unprocessed);
    }
    assert!(
        result
            .eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::IncompleteTruncated)
    );
    assert!(result.coverage.members.iter().all(|item| !item.eligible));
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/40
#[test]
fn full_result_has_no_effect_paths() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
    let prof = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert!(result.validate().is_ok());
    assert_eq!(result.state, ResultState::Complete);
    let bytes = eliot_contracts::canonical_json_bytes(&result).expect("result json");
    let text = String::from_utf8(bytes).expect("result utf8");
    // "kind" is excluded here: SourceMember.kind is a legitimate JSON key,
    // so it is covered by the eligibility-scoped 588/44 check instead.
    for forbidden in [
        "handler", "family", "action", "route", "mutation", "Finish", "provider", "Store", "model",
    ] {
        assert!(
            !text.contains(forbidden),
            "result must not contain {forbidden}"
        );
    }
}

// WORK_UNIT_CASE: 588/41
#[test]
fn findings_are_closed_and_deterministic() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    snapshot.members[1]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-1").expect("artifact"));
    snapshot.members[1]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let prof = profile(vec![
        rule("provenance_gap_v1", FindingClass::ProvenanceGap, 1),
        rule("conflict_ambiguity_v1", FindingClass::ConflictAmbiguity, 2),
    ]);
    let req = request(&snapshot, prof);
    let records = snapshot
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
    let result = screen_memory_curation(&req, &snapshot, &records).expect("screen");
    assert_eq!(result.findings.len(), 2);
    let gap = result
        .findings
        .iter()
        .find(|finding| finding.class == FindingClass::ProvenanceGap)
        .expect("provenance gap");
    assert_eq!(gap.invariant, "member has no supplied provenance handle");
    let ambiguity = result
        .findings
        .iter()
        .find(|finding| finding.class == FindingClass::ConflictAmbiguity)
        .expect("conflict ambiguity");
    assert_eq!(
        ambiguity.invariant,
        "member retains one or more conflict references"
    );
    for finding in &result.findings {
        assert!(matches!(
            finding.class,
            FindingClass::ProvenanceGap | FindingClass::ConflictAmbiguity
        ));
        assert_eq!(finding.proof, FindingProof::Deterministic);
        assert!(!finding.invariant.is_empty());
        assert!(
            finding
                .validate_against_profile(&result.request.profile)
                .is_ok()
        );
        let bytes = eliot_contracts::canonical_json_bytes(finding).expect("finding json");
        let text = String::from_utf8(bytes).expect("finding utf8");
        for forbidden in [
            "handler", "family", "action", "route", "mutation", "Finish", "provider", "Store",
            "model",
        ] {
            assert!(
                !text.contains(forbidden),
                "finding must not contain {forbidden}"
            );
        }
    }
    assert!(result.validate().is_ok());
}

// WORK_UNIT_CASE: 588/42
#[test]
fn item_input_output_bounds_rejected() {
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
    let mut output_limited = complete_request;
    output_limited.profile.limits.max_output_bytes = result.coverage.usage.output_bytes - 32;
    assert!(matches!(
        screen_memory_curation(&output_limited, &complete, &complete_evidence),
        Err(CurationScreenError::Contract(ContractError::Bound {
            field: "result.output_bytes"
        }))
    ));
}

// WORK_UNIT_CASE: 588/43
#[test]
fn page_time_cancellation_rejected() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    snapshot.members[0]
        .evidence
        .provenance
        .insert(ArtifactId::new("prov-0").expect("artifact"));
    let profile_value = profile(vec![rule(
        "provenance_gap_v1",
        FindingClass::ProvenanceGap,
        1,
    )]);
    let base = request(&snapshot, profile_value);
    let records = vec![evidence(
        &snapshot,
        snapshot.members[0].member_id.clone(),
        "evidence-0",
        ProtectionEvidenceState::CurrentVerified,
        ProtectionOutcome::Absent,
        false,
    )];
    let ok = screen_memory_curation(&base, &snapshot, &records).expect("single call works");
    assert_eq!(ok.state, ResultState::Complete);
    let mut paged = snapshot.clone();
    paged.page.has_more = true;
    assert!(matches!(
        screen_memory_curation(&base, &paged, &records),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "source.page.frontier"
        }))
    ));
    let mut timed = base.clone();
    timed.profile.limits.deadline_ms = Some(1);
    assert!(matches!(
        screen_memory_curation(&timed, &snapshot, &records),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "profile.limits.time"
        }))
    ));
    let mut cancelled = base;
    cancelled.cancellation_requested = true;
    assert!(matches!(
        screen_memory_curation(&cancelled, &snapshot, &records),
        Err(CurationScreenError::Cancelled)
    ));
}
