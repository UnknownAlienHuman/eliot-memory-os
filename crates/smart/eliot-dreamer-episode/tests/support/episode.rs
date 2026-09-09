#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ProductId, ResourceGeneration, SourceId, StateFence,
    TaskRevision,
};
use eliot_dreamer_contracts::curation::{EpisodePayload, TargetEvidence};
use eliot_dreamer_contracts::*;
use eliot_epistemic_contracts::{
    CoverageDenominator, CoverageDenominatorParams, CoverageReceipt, CoverageReceiptParams,
    DenominatorKind, FrontierRevision, FrontierSpec, MemberDisposition as ReceiptDisposition,
    MemberOutcome, PaginationBounds, QueryRevision, QuerySpec, SnapshotRef, ValidityBounds,
};
use eliot_evidence::EpistemicStatus;
use eliot_memory_curation_contracts::{
    DenominatorCoverage, Digest, FiniteDenominator, MemberCoverage, MemberDisposition,
    MemberEvidenceRefs, MemberPartition, ScreenCoverage, ScreenFrontier, SourceAvailability,
    SourceIdentity, SourceMember, SourceMemberKind, SourcePage, SourceSnapshot,
};
use eliot_observation_contracts::{
    CoverageDisposition, CoverageEvidence, ObservationEventCore, ObservationEventIdentity,
    ObservationKind, ObservationScope, PrivacyRetentionDisclosure, ProducerTrace,
};
use eliot_receipts::WorkScopeId;

use eliot_dreamer_episode::{
    BoundaryRule, EpisodeOutcome, EpisodeParticipant, EpisodePolicy, EventAndSourceSnapshot,
    EvidenceBinding, ExistingEpisodeMember, ExistingEpisodeSnapshot, GroundedEvent,
    GroundedEventSet, OverlapRule, ValidatedCurationInput,
};
use eliot_dreamer_episode::{
    event_material_preimage, outcome_material_preimage, participant_material_preimage,
    temporal_material_preimage,
};

pub struct Fixture {
    pub input: ValidatedCurationInput<'static>,
    pub events: GroundedEventSet,
    pub snapshot: EventAndSourceSnapshot,
    pub existing: ExistingEpisodeSnapshot,
    pub policy: EpisodePolicy,
}

pub fn digest(value: &str) -> String {
    eliot_contracts::sha256_hex(value.as_bytes())
}

pub fn digest_value(value: &str) -> Digest {
    Digest::new(digest(value)).expect("digest")
}

pub fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("artifact id")
}

fn member(value: &str) -> eliot_memory_curation_contracts::MemberId {
    eliot_memory_curation_contracts::MemberId::new(value).expect("member id")
}

fn binding(subject: &str, member_id: &str, material: &str) -> EvidenceBinding {
    EvidenceBinding {
        subject: subject.to_owned(),
        member_id: member(member_id),
        member_revision: TaskRevision::new(1).expect("revision"),
        member_content_digest: digest_value(member_id),
        material_handle: material.to_owned(),
        material_digest: digest(material),
        material_bytes: 16,
        evidence_handles: vec![id(member_id)],
    }
}

fn core(event_id: &str, valid_time_ms: Option<i64>) -> ObservationEventCore {
    ObservationEventCore {
        event_id_and_time: ObservationEventIdentity {
            event_id: event_id.to_owned(),
            clock: ClockReading {
                valid_time_ms,
                known_time_ms: valid_time_ms,
                transaction_sequence: None,
                monotonic_ns: None,
            },
        },
        producer_generation_and_trace: ProducerTrace {
            producer: "episode-test-producer".to_owned(),
            generation: "generation-1".to_owned(),
            trace_ref: Some(event_id.to_owned()),
        },
        kind: ObservationKind::TaskProgress,
        affected_scope: ObservationScope {
            work_scope: WorkScopeId::new("scope-1").expect("scope"),
            task_ref: Some("task-1".to_owned()),
            attempt_ref: Some("attempt-1".to_owned()),
            module_or_route_ref: Some("episode".to_owned()),
        },
        observed_delta: format!("delta-{event_id}"),
        expected_baseline: Some("baseline".to_owned()),
        evidence_and_raw_handles: vec![event_id.to_owned()],
        coverage_and_blind_intervals: CoverageEvidence {
            disposition: CoverageDisposition::Complete,
            denominator_source_ref: "source-1".to_owned(),
            interval: None,
            blind_intervals: Vec::new(),
            observed_count: 1,
        },
        privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
            privacy_domain_ref: "local".to_owned(),
            retention_policy_ref: "retain".to_owned(),
            disclosure_class: "internal".to_owned(),
        },
        candidate_importance: 1,
        dedup_key: format!("dedup-{event_id}"),
    }
}

fn temporal(
    valid_time_ms: Option<i64>,
    clock_ref: &str,
    uncertainty_ms: u64,
) -> eliot_dreamer_contracts::RelationTemporalEvidence {
    let point = valid_time_ms.map(|value| eliot_dreamer_contracts::RelationTimePoint {
        reading: ClockReading {
            valid_time_ms: Some(value),
            known_time_ms: Some(value),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        clock_ref: clock_ref.to_owned(),
        uncertainty_ms,
        conversion_ref: None,
    });
    eliot_dreamer_contracts::RelationTemporalEvidence {
        event_time: point.clone(),
        effective_time: point.clone(),
        observation_time: point.clone(),
        ingestion_time: point.clone(),
        commit_time: point,
        temporal_status: EpistemicStatus::Supported,
        uncertainty_ref: None,
    }
}

fn source_snapshot() -> SourceSnapshot {
    let denominator = FiniteDenominator {
        coverage: DenominatorCoverage::Complete,
        total_members: 3,
        declared_member_ids: vec![
            member("event-start"),
            member("event-end"),
            member("episode-1"),
        ],
    };
    let source_member = |member_id: &str, kind: SourceMemberKind| SourceMember {
        member_id: member(member_id),
        kind,
        revision: TaskRevision::new(1).expect("revision"),
        content_digest: digest_value(member_id),
        evidence: MemberEvidenceRefs {
            provenance: [id(member_id)].into_iter().collect(),
            owner_status: [id(&format!("status-{member_id}"))].into_iter().collect(),
            protection: BTreeSet::new(),
            conflict: BTreeSet::new(),
            audit: BTreeSet::new(),
        },
    };
    SourceSnapshot {
        identity: SourceIdentity {
            product_id: ProductId::new("product-1").expect("product"),
            source_id: SourceId::new("source-1").expect("source"),
            snapshot_id: eliot_memory_curation_contracts::SnapshotId::new("snapshot-1")
                .expect("snapshot"),
            query: eliot_memory_curation_contracts::QueryIdentity {
                query_id: eliot_memory_curation_contracts::QueryId::new("query-1").expect("query"),
                query_digest: digest_value("query"),
            },
            revision: 1,
            digest: digest_value("source-snapshot"),
            scope: WorkScopeId::new("scope-1").expect("scope"),
            state_fence: fence(),
        },
        denominator,
        partition: MemberPartition {
            changed_targets: [member("episode-1")].into_iter().collect(),
            immutable_references: [member("event-start"), member("event-end")]
                .into_iter()
                .collect(),
        },
        availability: SourceAvailability::Available,
        members: vec![
            source_member("event-start", SourceMemberKind::Observation),
            source_member("event-end", SourceMemberKind::Observation),
            source_member("episode-1", SourceMemberKind::Experience),
        ],
        page: SourcePage {
            page_number: 0,
            has_more: false,
            frontier: Vec::new(),
        },
    }
}

fn coverage(source: &SourceSnapshot) -> ScreenCoverage {
    let mut value = ScreenCoverage {
        denominator: source.denominator.clone(),
        start_position: 0,
        members: vec![
            MemberCoverage {
                member_id: member("event-start"),
                disposition: MemberDisposition::PreservedReference,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
            MemberCoverage {
                member_id: member("event-end"),
                disposition: MemberDisposition::PreservedReference,
                finding_ids: BTreeSet::new(),
                eligible: false,
            },
            MemberCoverage {
                member_id: member("episode-1"),
                disposition: MemberDisposition::Eligible,
                finding_ids: BTreeSet::new(),
                eligible: true,
            },
        ],
        frontier: ScreenFrontier {
            complete: true,
            remaining: Vec::new(),
        },
        usage: eliot_memory_curation_contracts::WorkUsage {
            processed_items: 3,
            work_units: 3,
            input_bytes: 48,
            output_bytes: 48,
        },
        next_cursor: None,
        digest: digest_value("placeholder"),
    };
    value.digest = value.computed_digest().expect("coverage digest");
    value
}

fn event_denominator(source: &SourceSnapshot) -> CoverageDenominator {
    CoverageDenominator::new(CoverageDenominatorParams {
        class: "observation".to_owned(),
        schema: "observation-event".to_owned(),
        revision: "1".to_owned(),
        scope: "scope-1".to_owned(),
        fence: fence(),
        members: ["event-start", "event-end"].into_iter().map(id).collect(),
        roles: ["event".to_owned()].into_iter().collect(),
        query: Some(
            QuerySpec::new("episode-events", QueryRevision("1".to_owned())).expect("query"),
        ),
        frontier: Some(
            FrontierSpec::new("frontier-1", FrontierRevision("1".to_owned())).expect("frontier"),
        ),
        snapshot: SnapshotRef::new(
            source.identity.snapshot_id.as_str(),
            source.identity.source_id.clone(),
        )
        .expect("snapshot"),
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, 2, 2, false).expect("bounds"),
        validity: ValidityBounds {
            scope: "scope-1".to_owned(),
            window_start_ms: None,
            window_end_ms: None,
            version: "1".to_owned(),
            precision: "file".to_owned(),
        },
        kind: DenominatorKind::CompleteScope,
    })
    .expect("event denominator")
}

fn enumeration(denominator: &CoverageDenominator) -> CoverageReceipt {
    CoverageReceipt::new(CoverageReceiptParams {
        query: denominator.query.clone().expect("query"),
        frontier: denominator.frontier.clone().expect("frontier"),
        denominator: denominator.digest.clone(),
        denominator_size: 2,
        task_id: eliot_contracts::TaskId::new("task-1").expect("task"),
        scope: "scope-1".to_owned(),
        fence: fence(),
        policy: "policy-1".to_owned(),
        groups: BTreeSet::new(),
        members: vec![
            MemberOutcome::new(id("event-start"), "event", ReceiptDisposition::Observed)
                .expect("member"),
            MemberOutcome::new(id("event-end"), "event", ReceiptDisposition::Observed)
                .expect("member"),
        ],
        omissions: Vec::new(),
        proof_digest: digest("enumeration-proof"),
    })
    .expect("enumeration")
}

fn event_with_uncertainty(
    event_id: &str,
    value: Option<i64>,
    clock_ref: &str,
    uncertainty_ms: u64,
) -> GroundedEvent {
    GroundedEvent {
        core: core(event_id, value),
        source_member_id: member(event_id),
        source_revision: TaskRevision::new(1).expect("revision"),
        source_content_digest: digest_value(event_id),
        event_binding: binding("event", event_id, event_id),
        temporal: temporal(value, clock_ref, uncertainty_ms),
        temporal_binding: value
            .map(|_| binding("temporal", event_id, &format!("{event_id}-temporal"))),
        participants: vec![EpisodeParticipant {
            participant_id: id("participant-1"),
            role: "actor".to_owned(),
            binding: binding("participant", event_id, &format!("{event_id}-participant")),
        }],
        outcomes: vec![EpisodeOutcome {
            outcome_id: id(&format!("outcome-{event_id}")),
            status: "observed".to_owned(),
            binding: binding("outcome", event_id, &format!("{event_id}-outcome")),
        }],
    }
}

fn job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".to_owned(),
            session: None,
        },
        operation_id: "operation-1".to_owned(),
        idempotency_key: "idempotency-1".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        privacy_profile: "local_only".to_owned(),
        contract_ref: "contract-1".to_owned(),
        policy_ref: "policy-1".to_owned(),
        budget: BudgetLimits {
            input_bytes: Some(1_000_000),
            output_bytes: Some(1_000_000),
            source_width: Some(100),
            reference_width: Some(100),
            model_calls: Some(1),
            attempts: Some(1),
            candidates: Some(1),
            wall_ms: Some(1_000),
            work_fan_out: Some(32),
            report_bytes: Some(1_000_000),
            max_stu: Some(100),
        },
        deadline_ms: None,
        frozen_manifest_digest: digest("manifest-1"),
    }
}

#[allow(clippy::too_many_lines)]
pub fn fixture() -> Fixture {
    fixture_with_modes(false, false, false)
}

#[allow(clippy::too_many_lines)]
pub fn fixture_with_modes(unknown_start: bool, cross_domain: bool, near_overlap: bool) -> Fixture {
    let source = source_snapshot();
    let source_ref = Box::leak(Box::new(source.clone()));
    let coverage_ref = Box::leak(Box::new(coverage(source_ref)));
    let event_denominator = event_denominator(&source);
    let enumeration_ref = Box::leak(Box::new(enumeration(&event_denominator)));
    let mut events = GroundedEventSet {
        denominator: FiniteDenominator {
            coverage: DenominatorCoverage::Complete,
            total_members: 2,
            declared_member_ids: vec![member("event-start"), member("event-end")],
        },
        events: vec![
            event_with_uncertainty(
                "event-start",
                (!unknown_start).then_some(100),
                "clock-1",
                if near_overlap { 10 } else { 0 },
            ),
            event_with_uncertainty(
                "event-end",
                Some(if near_overlap { 105 } else { 200 }),
                if cross_domain { "clock-2" } else { "clock-1" },
                if near_overlap { 10 } else { 0 },
            ),
        ],
    };
    let mut materials = vec![BundleMaterial {
        handle: "episode-1".to_owned(),
        disposition: SourceDisposition::Required,
        bytes: 16,
        digest: digest("episode-1"),
    }];
    for grounded in &mut events.events {
        for participant in &mut grounded.participants {
            let preimage =
                participant_material_preimage(participant).expect("participant preimage");
            participant
                .binding
                .material_digest
                .clone_from(&preimage.digest);
            participant.binding.material_bytes = preimage.bytes;
            materials.push(BundleMaterial {
                handle: participant.binding.material_handle.clone(),
                disposition: SourceDisposition::Required,
                bytes: preimage.bytes,
                digest: preimage.digest,
            });
        }
        for outcome in &mut grounded.outcomes {
            let preimage = outcome_material_preimage(outcome).expect("outcome preimage");
            outcome.binding.material_digest.clone_from(&preimage.digest);
            outcome.binding.material_bytes = preimage.bytes;
            materials.push(BundleMaterial {
                handle: outcome.binding.material_handle.clone(),
                disposition: SourceDisposition::Required,
                bytes: preimage.bytes,
                digest: preimage.digest,
            });
        }
        if let Some(binding) = &mut grounded.temporal_binding {
            let preimage =
                temporal_material_preimage(&grounded.temporal).expect("temporal preimage");
            binding.material_digest.clone_from(&preimage.digest);
            binding.material_bytes = preimage.bytes;
            materials.push(BundleMaterial {
                handle: binding.material_handle.clone(),
                disposition: SourceDisposition::Required,
                bytes: preimage.bytes,
                digest: preimage.digest,
            });
        }
        let event_preimage = event_material_preimage(grounded).expect("event preimage");
        grounded
            .event_binding
            .material_digest
            .clone_from(&event_preimage.digest);
        grounded.event_binding.material_bytes = event_preimage.bytes;
        materials.push(BundleMaterial {
            handle: grounded.event_binding.material_handle.clone(),
            disposition: SourceDisposition::Required,
            bytes: event_preimage.bytes,
            digest: event_preimage.digest,
        });
    }
    let job_ref = Box::leak(Box::new(job()));
    let grounded_ref = Box::leak(Box::new(GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        draft_digest: digest("draft-1"),
        residues: vec![ClaimResidue {
            claim: "episode".to_owned(),
            state: SupportState::Supported,
            detail: "events grounded".to_owned(),
        }],
        coverage_note: "complete".to_owned(),
    }));
    let bundle_ref = Box::leak(Box::new(DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        manifest_digest: digest("manifest-1"),
        materials,
        omissions: Vec::new(),
        completeness: BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("event-denominator".to_owned()),
    }));
    let receipt_ref = Box::leak(Box::new(ValidationReceipt {
        schema_version: 1,
        validator_contract: "validator-1".to_owned(),
        validator_policy: "policy-1".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest: digest("draft-1"),
        bundle_digest: digest("manifest-1"),
        manifest_digest: digest("manifest-1"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: digest("input-1"),
        output_digest: digest("output-1"),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: digest("preservation-1"),
        budget_digest: digest("budget-1"),
    }));
    let payload = CurationPayload::Episode(EpisodePayload {
        episode: "episode-1".to_owned(),
        observed_at_ms: 200,
        target_evidence: TargetEvidence {
            targets: vec!["episode-1".to_owned()],
            evidence_refs: vec!["event-start".to_owned(), "event-end".to_owned()],
        },
    });
    let item_base = ValidatedCurationItem {
        receipt: receipt_ref.clone(),
        kind_spelling: "episode".to_owned(),
        family_spelling: "episode".to_owned(),
        payload: payload.clone(),
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["episode-1".to_owned()],
            expected_total: 1,
        },
        source_digest: digest("episode-1"),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        job_digest: digest(
            &String::from_utf8(canonical_bytes(job_ref).expect("job bytes")).expect("job utf8"),
        ),
        requester: job_ref.requester.clone(),
        budget_note: "bounded".to_owned(),
    };
    let item_digest = item_base.item_digest(grounded_ref).expect("item digest");
    let screen_ref = Box::leak(Box::new(ScreenBinding {
        request_id: eliot_contracts::RequestId::new("request-1").expect("request"),
        receipt_id: eliot_contracts::ReceiptId::new("screen-1").expect("receipt"),
        screened_targets: vec!["episode-1".to_owned()],
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: digest("screen-1"),
        item_digest,
    }));
    let request_ref = Box::leak(Box::new(TypedCurationHandlerRequest {
        request_id: "request-1".to_owned(),
        receipt_id: "screen-1".to_owned(),
        source_snapshot: "snapshot-1".to_owned(),
        source_revision: "1".to_owned(),
        profile: "default".to_owned(),
        kind: CurationKind::Episode,
        family: CurationFamily::Episode,
        job_id: "job-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        task_id: "task-1".to_owned(),
        state_fence: fence(),
        payload,
        denominator: TargetDenominator {
            mode: AtomicityMode::AllOrNothing,
            members: vec!["episode-1".to_owned()],
            expected_total: 1,
        },
        screen_binding: Some(screen_ref.clone()),
    }));
    let job_digest =
        digest(&String::from_utf8(canonical_bytes(job_ref).expect("job bytes")).expect("job utf8"));
    let mut item = item_base;
    item.job_digest = job_digest;
    let ctx_ref = Box::leak(Box::new(CurationAcceptanceCtx {
        job: job_ref,
        bundle: bundle_ref,
        receipt: receipt_ref,
        screen: screen_ref,
        grounded: grounded_ref,
        request: request_ref,
        usage: Box::leak(Box::new(BudgetUsage::default())),
    }));
    let existing = ExistingEpisodeSnapshot {
        episode_id: "episode-1".to_owned(),
        revision: TaskRevision::new(1).expect("revision"),
        content_digest: digest_value("episode-1"),
        state_fence: fence(),
        boundary_start_event_id: "event-start".to_owned(),
        boundary_end_event_id: Some("event-end".to_owned()),
        predecessor_episode_id: None,
        members: vec![
            ExistingEpisodeMember {
                event_id: "event-start".to_owned(),
                source_member_id: member("event-start"),
                revision: TaskRevision::new(1).expect("revision"),
                content_digest: digest_value("event-start"),
            },
            ExistingEpisodeMember {
                event_id: "event-end".to_owned(),
                source_member_id: member("event-end"),
                revision: TaskRevision::new(1).expect("revision"),
                content_digest: digest_value("event-end"),
            },
        ],
        coverage: Some(enumeration_ref.clone()),
        evidence_bindings: Vec::new(),
    };
    let mut policy = EpisodePolicy {
        schema_version: 1,
        policy_id: "policy-1".to_owned(),
        policy_digest: digest("policy-1"),
        state_fence: fence(),
        boundary_rule: BoundaryRule::ExplicitEventAnchors,
        start_event_id: Some("event-start".to_owned()),
        end_event_id: Some("event-end".to_owned()),
        overlap_rule: OverlapRule::PreserveConflict,
        max_events: 32,
        max_participants: 64,
        max_output_bytes: 1_000_000,
        max_source_members: 64,
        max_gaps: 64,
        max_neighborhood: 1024,
        max_work: 10_000,
        max_input_bytes: 1_000_000,
        max_stu: 100,
        deadline_ms: None,
        now_ms: None,
        cancellation_requested: false,
    };
    policy.policy_digest = policy.computed_digest().expect("policy digest");
    Fixture {
        input: ValidatedCurationInput {
            item: Box::leak(Box::new(item)),
            ctx: ctx_ref,
        },
        events,
        snapshot: EventAndSourceSnapshot {
            source,
            coverage: (*coverage_ref).clone(),
            event_denominator,
            enumeration: (*enumeration_ref).clone(),
        },
        existing,
        policy,
    }
}
