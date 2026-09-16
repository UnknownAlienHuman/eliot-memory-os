//! Issue #642 proof matrix: exactly cases 1..16, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskRevision, canonical_json_bytes, sha256_hex,
};
use eliot_memory_curation_contracts::{
    CONTRACT_NAME, CONTRACT_VERSION, ContractError, CumulativeCursor, CurationScreenRequest,
    DenominatorCoverage, Digest, DisclosureCeiling, Eligibility, EligibilityStatus, FindingClass,
    FindingProof, FiniteDenominator, MemberDisposition, MemberEvidenceRefs, MemberId,
    MemberPartition, ProfileId, ProtectionAssessment, ProtectionClass, ProtectionDecision,
    ProtectionEvidence, ProtectionEvidenceId, ProtectionEvidenceState, ProtectionOutcome, QueryId,
    QueryIdentity, RequestBinding, ResultState, RuleId, RuleSpec, ScreenLimits, ScreenProfile,
    SnapshotId, SourceAvailability, SourceIdentity, SourceMember, SourceMemberKind, SourcePage,
    SourceSnapshot, WorkUsage,
};
use eliot_memory_curation_screen::{CurationScreenError, screen_memory_curation};
use eliot_memory_curation_screen_wasm::{
    CallLedger, EXPORT_NAME, GUEST_ABI_VERSION, GUEST_TARGET, GuestError, GuestRequest,
    GuestResponse, HANDLER_SUBTYPE, NATIVE_CONTRACT, NATIVE_CONTRACT_VERSION, NATIVE_OWNER,
    TOOLCHAIN_CHANNEL, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS, WORLD_NAME,
    WORLD_PACKAGE, availability_as_str, check_wasm_imports, decode_request, decode_response,
    descriptor, descriptor_digest, disposition_as_str, eligibility_as_str, encode_request,
    encode_response, finding_class_as_str, finding_proof_as_str, handle_request_typed,
    handle_with_ledger, is_forbidden_import, list_wasm_imports, parse_availability,
    parse_disposition, parse_eligibility, parse_finding_class, parse_finding_proof,
    parse_protection, parse_result_state, protection_as_str, qualified_export_name, request_digest,
    result_state_as_str, screen, screen_with_ledger, wit_export_name,
};
use eliot_receipts::WorkScopeId;

type NativeTriple = (
    CurationScreenRequest,
    SourceSnapshot,
    Vec<ProtectionEvidence>,
);

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
            snapshot_id: SnapshotId::new("snapshot-642").expect("snapshot"),
            query: QueryIdentity {
                query_id: QueryId::new("query-642").expect("query"),
                query_digest: digest(),
            },
            revision: 1,
            digest: digest(),
            scope: WorkScopeId::new("screen-scope-642").expect("scope"),
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
        profile_id: ProfileId::new("profile-642").expect("profile"),
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
            request_id: RequestId::new("request-642").expect("request"),
            operation_id: OperationId::new("operation-642").expect("operation"),
            task_id: None,
            attempt_id: AgentAttemptId::new("attempt-642").expect("attempt"),
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

fn both_rules() -> Vec<RuleSpec> {
    vec![
        rule("provenance_gap_v1", FindingClass::ProvenanceGap, 1),
        rule("conflict_ambiguity_v1", FindingClass::ConflictAmbiguity, 2),
    ]
}

fn evidence(
    snapshot: &SourceSnapshot,
    member_id: MemberId,
    id: &str,
    state: ProtectionEvidenceState,
    outcome: ProtectionOutcome,
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
        invalidated_by: None,
        digest: digest(),
    }
}

fn clear_evidence(snapshot: &SourceSnapshot) -> Vec<ProtectionEvidence> {
    snapshot
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            evidence(
                snapshot,
                member.member_id.clone(),
                &format!("evidence-{index}"),
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
            )
        })
        .collect()
}

fn with_provenance(snapshot: &mut SourceSnapshot) {
    for (index, member) in snapshot.members.iter_mut().enumerate() {
        member
            .evidence
            .provenance
            .insert(ArtifactId::new(format!("prov-{index}")).expect("artifact"));
    }
}

fn guest_request(
    snapshot: &SourceSnapshot,
    profile: ScreenProfile,
    evidence: Vec<ProtectionEvidence>,
) -> (GuestRequest, NativeTriple) {
    let native_request = request(snapshot, profile);
    let guest = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        request: native_request.clone(),
        source: snapshot.clone(),
        evidence: evidence.clone(),
    };
    (guest, (native_request, snapshot.clone(), evidence))
}

fn native_of(
    triple: &NativeTriple,
) -> Result<eliot_memory_curation_contracts::CurationScreenResult, CurationScreenError> {
    screen_memory_curation(&triple.0, &triple.1, &triple.2)
}

fn assert_single_outcome(response: &GuestResponse) {
    assert_eq!(
        response.result.is_some(),
        response.error.is_none(),
        "exactly one of result or error must be present"
    );
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn root_cargo_lock() -> &'static str {
    include_str!("../../../../Cargo.lock")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 642/1
#[test]
fn exact_world_descriptor_native_abi_target() {
    assert_eq!(WORLD_PACKAGE, "eliot:current@0.1.0");
    assert_eq!(WORLD_NAME, "memory-curation-screen");
    assert_eq!(EXPORT_NAME, "screen");
    assert_eq!(HANDLER_SUBTYPE, "screen");
    assert_eq!(GUEST_ABI_VERSION, 1);
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    assert_eq!(TOOLCHAIN_CHANNEL, "1.97.1");
    assert_eq!(TYPED_WORLD_NAME, "memory-curation-screen");
    assert_eq!(TYPED_WORLD_STATUS, "PRESENT_NOT_ACCEPTED");
    assert_eq!(TYPED_WORLD_OWNER, "#756");
    assert_eq!(NATIVE_OWNER, "#588");
    assert_eq!(NATIVE_CONTRACT, CONTRACT_NAME);
    assert_eq!(NATIVE_CONTRACT_VERSION, CONTRACT_VERSION.to_string());
    assert_eq!(NATIVE_CONTRACT_VERSION, "1.0.0");
    assert_eq!(wit_export_name(), "screen");
    assert_eq!(
        qualified_export_name(),
        format!("{WORLD_NAME}#{EXPORT_NAME}")
    );
    assert_eq!(qualified_export_name(), "memory-curation-screen#screen");
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.export_name, EXPORT_NAME);
    assert_eq!(descriptor.handler_subtype, HANDLER_SUBTYPE);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert_eq!(descriptor.target, GUEST_TARGET);
    assert_eq!(descriptor.toolchain_channel, TOOLCHAIN_CHANNEL);
    assert_eq!(
        descriptor.wit_digest,
        sha256_hex(eliot_memory_curation_screen_wasm::GUEST_WIT_BYTES)
    );
    assert!(descriptor.capability_envelope.is_empty());
    assert_eq!(descriptor.native_contract, NATIVE_CONTRACT);
    assert_eq!(descriptor.native_contract_version, NATIVE_CONTRACT_VERSION);
    assert_eq!(descriptor.typed_world, TYPED_WORLD_NAME);
    assert_eq!(descriptor.typed_world_status, TYPED_WORLD_STATUS);
    let wit = String::from_utf8(eliot_memory_curation_screen_wasm::GUEST_WIT_BYTES.to_vec())
        .expect("WIT UTF-8");
    assert!(wit.contains("world memory-curation-screen"));
    assert!(wit.contains("Consumer: #642"));
    assert!(wit.contains("package eliot:current@0.1.0"));
}

// WORK_UNIT_CASE: 642/2
#[test]
fn wrong_world_version_subtype_rejected_before_native_call() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (base, _) = guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    for mutated in [
        GuestRequest {
            abi_version: 999,
            ..base.clone()
        },
        GuestRequest {
            world: "dreamer-handler".to_owned(),
            ..base.clone()
        },
        GuestRequest {
            handler_subtype: "orientation".to_owned(),
            ..base.clone()
        },
    ] {
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&mutated, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert_eq!(response.native_calls, 0);
        assert!(response.result.is_none());
        assert!(
            matches!(response.error, Some(GuestError::RejectedEnvelope(_))),
            "wrong envelope must fail closed"
        );
        assert_single_outcome(&response);
    }
    let ledger = CallLedger::new();
    let input = encode_request(&base).expect("encode");
    let output = screen_with_ledger(&input, &ledger).expect("transport ok");
    let response = decode_response(&output).expect("decode");
    assert_eq!(ledger.calls(), 1);
    assert!(response.result.is_some());
    // Undecodable, oversize and unknown-field inputs never reach native.
    assert!(screen(b"not a guest envelope").is_err());
    let oversize =
        vec![
            0u8;
            usize::try_from(eliot_memory_curation_screen_wasm::MAX_GUEST_INPUT_BYTES + 1)
                .expect("oversize length")
        ];
    assert!(decode_request(&oversize).is_err());
    let json = String::from_utf8(input).expect("canonical UTF-8");
    let injected = json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_request(injected.as_bytes()).is_err());
    assert_eq!(ledger.calls(), 1);
}

// WORK_UNIT_CASE: 642/3
#[test]
fn exhaustive_input_output_error_conversion() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (guest, _) = guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let bytes = encode_request(&guest).expect("encode");
    let decoded = decode_request(&bytes).expect("decode");
    assert_eq!(decoded, guest);
    assert_eq!(encode_request(&decoded).expect("re-encode"), bytes);
    assert_eq!(
        request_digest(&guest),
        sha256_hex(&canonical_json_bytes(&guest).expect("canonical"))
    );
    let response = handle_request_typed(&guest);
    let response_bytes = encode_response(&response).expect("encode response");
    assert_eq!(decode_response(&response_bytes).expect("decode"), response);
    // Every native contract error maps through the closed guest error.
    let pairs: Vec<(ContractError, GuestError)> = vec![
        (
            ContractError::Blank { field: "f" },
            GuestError::ContractBlank { field: "f".into() },
        ),
        (
            ContractError::ControlCharacter { field: "f" },
            GuestError::ContractControl { field: "f".into() },
        ),
        (
            ContractError::Zero { field: "f" },
            GuestError::ContractZero { field: "f".into() },
        ),
        (
            ContractError::Bound { field: "f" },
            GuestError::ContractBound { field: "f".into() },
        ),
        (
            ContractError::Duplicate { field: "f" },
            GuestError::ContractDuplicate { field: "f".into() },
        ),
        (
            ContractError::BindingMismatch { field: "f" },
            GuestError::ContractBinding { field: "f".into() },
        ),
        (
            ContractError::ChangedIdentity { field: "f" },
            GuestError::ContractChanged { field: "f".into() },
        ),
        (
            ContractError::Unsupported { field: "f" },
            GuestError::ContractUnsupported { field: "f".into() },
        ),
        (
            ContractError::InvalidDigest { field: "f" },
            GuestError::ContractDigest { field: "f".into() },
        ),
        (
            ContractError::Reconciliation { field: "f" },
            GuestError::ContractReconciliation { field: "f".into() },
        ),
        (
            ContractError::Canonicalization("d".into()),
            GuestError::ContractCanonical { detail: "d".into() },
        ),
    ];
    for (native, expected) in &pairs {
        assert_eq!(GuestError::from(native), *expected);
        assert!(!GuestError::from(native).to_string().is_empty());
    }
    assert_eq!(
        GuestError::from(&CurationScreenError::Cancelled),
        GuestError::Cancelled
    );
    assert_eq!(
        GuestError::from(&CurationScreenError::Contract(ContractError::Bound {
            field: "screen.items"
        })),
        GuestError::ContractBound {
            field: "screen.items".into()
        }
    );
    // WIT spelling tables: total where the readable world covers native.
    for status in [
        EligibilityStatus::EligibleForSemanticCuration,
        EligibilityStatus::Protected,
        EligibilityStatus::Malformed,
        EligibilityStatus::StaleUnavailable,
        EligibilityStatus::OutsideScope,
        EligibilityStatus::IncompleteTruncated,
        EligibilityStatus::UnknownBlocked,
    ] {
        assert_eq!(parse_eligibility(eligibility_as_str(status)), Some(status));
    }
    assert_eq!(
        parse_eligibility("ineligible-stale"),
        Some(EligibilityStatus::StaleUnavailable)
    );
    assert_eq!(
        parse_eligibility("ineligible-unavailable"),
        Some(EligibilityStatus::OutsideScope)
    );
    assert!(parse_eligibility("eligible-for-everything").is_none());
    for decision in [
        ProtectionDecision::Protected,
        ProtectionDecision::Unprotected,
        ProtectionDecision::Unknown,
    ] {
        assert_eq!(
            parse_protection(protection_as_str(decision)),
            Some(decision)
        );
    }
    assert!(parse_protection("shielded").is_none());
    assert_eq!(
        finding_class_as_str(FindingClass::ProvenanceGap),
        Some("provenance-gap")
    );
    assert_eq!(
        finding_class_as_str(FindingClass::ConflictAmbiguity),
        Some("conflict-ambiguity")
    );
    for class in [
        FindingClass::Duplicate,
        FindingClass::StaleSuperseded,
        FindingClass::MalformedIncomplete,
        FindingClass::ProtectionGap,
        FindingClass::BoundedOut,
        FindingClass::Unprocessed,
    ] {
        assert_eq!(finding_class_as_str(class), None);
    }
    assert_eq!(
        parse_finding_class("provenance-gap"),
        Some(FindingClass::ProvenanceGap)
    );
    assert_eq!(
        parse_finding_class("conflict-ambiguity"),
        Some(FindingClass::ConflictAmbiguity)
    );
    assert!(parse_finding_class("duplicate").is_none());
    assert_eq!(
        finding_proof_as_str(FindingProof::Deterministic),
        Some("deterministic")
    );
    assert_eq!(finding_proof_as_str(FindingProof::Observed), None);
    assert_eq!(finding_proof_as_str(FindingProof::Unknown), None);
    assert_eq!(
        parse_finding_proof("deterministic"),
        Some(FindingProof::Deterministic)
    );
    assert!(parse_finding_proof("observed").is_none());
    for availability in [
        SourceAvailability::Available,
        SourceAvailability::Partial,
        SourceAvailability::Unavailable,
        SourceAvailability::Stale,
    ] {
        let spelling = availability_as_str(availability).expect("covered availability");
        assert_eq!(parse_availability(spelling), Some(availability));
    }
    for availability in [
        SourceAvailability::Blocked,
        SourceAvailability::Malformed,
        SourceAvailability::Unknown,
    ] {
        assert_eq!(availability_as_str(availability), None);
    }
    assert!(parse_availability("truncated").is_none());
    assert!(parse_availability("unprocessed").is_none());
    for state in [
        ResultState::Complete,
        ResultState::Partial,
        ResultState::Unknown,
    ] {
        let spelling = result_state_as_str(state).expect("covered state");
        assert_eq!(parse_result_state(spelling), Some(state));
    }
    assert_eq!(result_state_as_str(ResultState::Blocked), None);
    assert!(parse_result_state("incomplete").is_none());
    for disposition in [
        MemberDisposition::Eligible,
        MemberDisposition::Protected,
        MemberDisposition::Blocked,
        MemberDisposition::PreservedReference,
        MemberDisposition::Unprocessed,
    ] {
        assert_eq!(
            parse_disposition(disposition_as_str(disposition)),
            Some(disposition)
        );
    }
    assert!(parse_disposition("eligible-ish").is_none());
}

// WORK_UNIT_CASE: 642/4
#[test]
fn every_protection_per_item_disposition() {
    let mut snapshot = source(4, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    // Member 2 loses provenance so the structural rule flags it.
    snapshot.members[2].evidence.provenance.clear();
    let reference = snapshot.members[3].member_id.clone();
    snapshot.partition = MemberPartition {
        changed_targets: [
            snapshot.members[0].member_id.clone(),
            snapshot.members[1].member_id.clone(),
            snapshot.members[2].member_id.clone(),
        ]
        .into_iter()
        .collect(),
        immutable_references: [reference].into_iter().collect(),
    };
    let (guest, triple) = guest_request(
        &snapshot,
        profile(both_rules()),
        vec![
            evidence(
                &snapshot,
                snapshot.members[0].member_id.clone(),
                "evidence-0",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
            ),
            evidence(
                &snapshot,
                snapshot.members[1].member_id.clone(),
                "evidence-1",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Present,
            ),
            evidence(
                &snapshot,
                snapshot.members[2].member_id.clone(),
                "evidence-2",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
            ),
            evidence(
                &snapshot,
                snapshot.members[3].member_id.clone(),
                "evidence-3",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
            ),
        ],
    );
    let native = native_of(&triple).expect("native screen");
    let response = handle_request_typed(&guest);
    let result = response.result.as_ref().expect("result");
    assert_eq!(*result, native);
    assert!(result.validate().is_ok());
    let disposition_of = |index: usize| result.coverage.members[index].disposition;
    assert_eq!(disposition_of(0), MemberDisposition::Eligible);
    assert_eq!(disposition_of(1), MemberDisposition::Protected);
    assert_eq!(disposition_of(2), MemberDisposition::Blocked);
    assert_eq!(disposition_of(3), MemberDisposition::PreservedReference);
    assert!(result.coverage.members[0].eligible);
    assert!(!result.coverage.members[1].eligible);
    assert!(!result.coverage.members[2].eligible);
    assert!(!result.coverage.members[3].eligible);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].member_id, snapshot.members[2].member_id);
    // The single-call native surface never emits Unprocessed; the guest
    // mapping still covers the variant so no disposition is unrepresentable.
    assert!(
        result
            .coverage
            .members
            .iter()
            .all(|member| member.disposition != MemberDisposition::Unprocessed)
    );
    assert_eq!(
        parse_disposition(disposition_as_str(MemberDisposition::Unprocessed)),
        Some(MemberDisposition::Unprocessed)
    );
}

// WORK_UNIT_CASE: 642/5
#[test]
fn coverage_parity_complete_partial_unavailable_unknown() {
    // Complete denominator, available source.
    let mut complete = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut complete);
    let (guest, triple) =
        guest_request(&complete, profile(both_rules()), clear_evidence(&complete));
    let native = native_of(&triple).expect("native complete");
    assert_eq!(native.state, ResultState::Complete);
    let response = handle_request_typed(&guest);
    let result = response.result.as_ref().expect("result").clone();
    assert_eq!(result, native);
    assert!(result.coverage.frontier.complete);
    assert!(result.coverage.next_cursor.is_none());
    assert_eq!(result.coverage.members.len(), complete.members.len());
    // Partial denominator stays partial with truncated eligibility.
    let mut partial = source(2, DenominatorCoverage::Partial);
    with_provenance(&mut partial);
    let (guest, triple) = guest_request(&partial, profile(both_rules()), clear_evidence(&partial));
    let native = native_of(&triple).expect("native partial");
    assert_eq!(native.state, ResultState::Partial);
    assert!(!native.coverage.frontier.complete);
    assert!(
        native
            .eligibility
            .iter()
            .all(|item| item.status == EligibilityStatus::IncompleteTruncated)
    );
    let response = handle_request_typed(&guest);
    assert_eq!(response.result.as_ref().expect("result"), &native);
    // Stale source is blocked, never an empty success.
    let mut stale = source(2, DenominatorCoverage::Partial);
    with_provenance(&mut stale);
    stale.availability = SourceAvailability::Stale;
    let (guest, triple) = guest_request(&stale, profile(both_rules()), clear_evidence(&stale));
    let native = native_of(&triple).expect("native stale");
    assert_eq!(native.state, ResultState::Blocked);
    assert!(native.findings.is_empty());
    let response = handle_request_typed(&guest);
    assert_eq!(response.result.as_ref().expect("result"), &native);
    // Unknown protection is blocked, never eligible.
    let mut unknown = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut unknown);
    let unknown_evidence = unknown
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| {
            evidence(
                &unknown,
                member.member_id.clone(),
                &format!("evidence-{index}"),
                ProtectionEvidenceState::Unknown,
                ProtectionOutcome::Unknown,
            )
        })
        .collect();
    let (guest, triple) = guest_request(&unknown, profile(both_rules()), unknown_evidence);
    let native = native_of(&triple).expect("native unknown");
    assert_eq!(native.state, ResultState::Blocked);
    assert!(
        native
            .protection
            .iter()
            .all(|item| item.decision == ProtectionDecision::Unknown)
    );
    assert!(
        native
            .coverage
            .members
            .iter()
            .all(|member| !member.eligible)
    );
    let response = handle_request_typed(&guest);
    assert_eq!(response.result.as_ref().expect("result"), &native);
}

// WORK_UNIT_CASE: 642/6
#[test]
fn protected_unknown_non_eligibility_matches_native_no_shortcut() {
    let mut snapshot = source(3, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (guest, triple) = guest_request(
        &snapshot,
        profile(both_rules()),
        vec![
            evidence(
                &snapshot,
                snapshot.members[0].member_id.clone(),
                "evidence-0",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Absent,
            ),
            evidence(
                &snapshot,
                snapshot.members[1].member_id.clone(),
                "evidence-1",
                ProtectionEvidenceState::CurrentVerified,
                ProtectionOutcome::Present,
            ),
            evidence(
                &snapshot,
                snapshot.members[2].member_id.clone(),
                "evidence-2",
                ProtectionEvidenceState::Stale,
                ProtectionOutcome::Absent,
            ),
        ],
    );
    let native = native_of(&triple).expect("native screen");
    let response = handle_request_typed(&guest);
    let result = response.result.as_ref().expect("result");
    assert_eq!(*result, native);
    let status_of = |id: &MemberId| {
        result
            .eligibility
            .iter()
            .find(|item| &item.member_id == id)
            .expect("eligibility")
            .status
    };
    assert_eq!(
        status_of(&snapshot.members[0].member_id),
        EligibilityStatus::EligibleForSemanticCuration
    );
    assert_eq!(
        status_of(&snapshot.members[1].member_id),
        EligibilityStatus::Protected
    );
    assert_eq!(
        status_of(&snapshot.members[2].member_id),
        EligibilityStatus::UnknownBlocked
    );
    for item in &result.eligibility {
        if item.status == EligibilityStatus::EligibleForSemanticCuration {
            assert_eq!(item.protection, ProtectionDecision::Unprotected);
        }
    }
    // No guest shortcut: the envelope carries no second eligibility
    // procedure, only verbatim native records and read-only projections.
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source_text = read_src(name);
        assert!(
            !source_text.contains("assess_dimensions"),
            "{name} must not re-derive dimensions"
        );
        assert!(
            !source_text.contains("derive_disposition"),
            "{name} must not re-derive dispositions"
        );
        assert!(
            !source_text.contains("derive_protection"),
            "{name} must not re-derive protection"
        );
    }
}

// WORK_UNIT_CASE: 642/7
#[test]
fn structural_findings_generic_eligibility_no_kind_selection() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    snapshot.members[0].evidence.provenance.clear();
    snapshot.members[1]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let (guest, triple) =
        guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let native = native_of(&triple).expect("native screen");
    assert_eq!(native.findings.len(), 2);
    let classes: BTreeSet<FindingClass> = native
        .findings
        .iter()
        .map(|finding| finding.class)
        .collect();
    assert_eq!(
        classes,
        [FindingClass::ProvenanceGap, FindingClass::ConflictAmbiguity]
            .into_iter()
            .collect()
    );
    assert!(
        native
            .findings
            .iter()
            .all(|finding| finding.proof == FindingProof::Deterministic)
    );
    let response = handle_request_typed(&guest);
    let result = response.result.as_ref().expect("result");
    assert_eq!(*result, native);
    assert_eq!(result.result_digest, native.result_digest);
    // Generic eligibility only: no Curation kind/family/handler selection
    // anywhere in guest source or the response envelope.
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source_text = read_src(name);
        for forbidden in [
            "CurationKind",
            "CurationFamily",
            "TypedCuration",
            "NativeCuration",
            "dreamer-handler",
            "route_validated",
        ] {
            assert!(
                !source_text.contains(forbidden),
                "{name} must not select {forbidden}"
            );
        }
    }
    let json =
        String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
    for absent in [
        "curation-kind",
        "curation_kind",
        "curation-family",
        "curation_family",
        "handler_id",
        "TypedCuration",
    ] {
        assert!(!json.contains(absent), "response must not raise {absent}");
    }
}

// WORK_UNIT_CASE: 642/8
#[test]
fn cursor_frontier_work_parity() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (base_guest, base_triple) =
        guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    // Cursor continuation is native-owned: the guest preserves the native
    // Unsupported outcome with one native call, never a second paging path.
    let mut cursor_request = base_triple.0.clone();
    cursor_request.cursor = Some(CumulativeCursor {
        request_id: base_triple.0.binding.request_id.clone(),
        request_fingerprint: digest(),
        snapshot_id: base_triple.0.source.snapshot_id.clone(),
        query: base_triple.0.source.query.clone(),
        source_revision: 1,
        source_digest: digest(),
        profile_id: base_triple.0.profile.profile_id.clone(),
        profile_digest: digest(),
        denominator: base_triple.0.denominator.clone(),
        scope: base_triple.0.source.scope.clone(),
        state_fence: base_triple.0.source.state_fence.clone(),
        processed_member_digest: digest(),
        position: 0,
        usage: WorkUsage::default(),
        predecessor: None,
    });
    let cursor_guest = GuestRequest {
        request: cursor_request,
        ..base_guest.clone()
    };
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&cursor_guest, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert_eq!(
        response.error,
        Some(GuestError::ContractUnsupported {
            field: "request.cursor".into()
        })
    );
    // Page frontiers, live deadlines and cancellation behave identically.
    let mut paged = snapshot.clone();
    paged.page.has_more = true;
    let (guest, triple) = guest_request(&paged, profile(both_rules()), Vec::new());
    let native_error = native_of(&triple).expect_err("native rejects frontier");
    assert!(matches!(
        native_error,
        CurationScreenError::Contract(ContractError::Unsupported {
            field: "source.page.frontier"
        })
    ));
    let response = handle_request_typed(&guest);
    assert_eq!(response.native_calls, 1);
    assert_eq!(
        response.error,
        Some(GuestError::ContractUnsupported {
            field: "source.page.frontier".into()
        })
    );
    let mut timed_profile = profile(both_rules());
    timed_profile.limits.deadline_ms = Some(1);
    let (guest, triple) = guest_request(&snapshot, timed_profile, Vec::new());
    assert!(matches!(
        native_of(&triple),
        Err(CurationScreenError::Contract(ContractError::Unsupported {
            field: "profile.limits.time"
        }))
    ));
    assert_eq!(
        handle_request_typed(&guest).error,
        Some(GuestError::ContractUnsupported {
            field: "profile.limits.time".into()
        })
    );
    let mut cancelled = base_triple.0.clone();
    cancelled.cancellation_requested = true;
    let cancelled_guest = GuestRequest {
        request: cancelled,
        ..base_guest.clone()
    };
    let response = handle_request_typed(&cancelled_guest);
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::Cancelled));
    // Cumulative work accounting is preserved verbatim on success.
    let response = handle_request_typed(&base_guest);
    let result = response.result.as_ref().expect("result");
    let native = native_of(&base_triple).expect("native");
    assert_eq!(result.coverage.usage, native.coverage.usage);
    assert!(result.coverage.usage.input_bytes > 0);
    assert!(result.coverage.usage.work_units > 0);
    let encoded = canonical_json_bytes(&native).expect("encoded result");
    assert_eq!(result.coverage.usage.output_bytes, encoded.len() as u64);
    assert!(result.coverage.next_cursor.is_none());
}

// WORK_UNIT_CASE: 642/9
#[test]
fn stale_identities_duplicates_all_bounds() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (base_guest, base_triple) =
        guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    // Stale snapshot identity mismatches the request binding.
    let mut stale_snapshot = snapshot.clone();
    stale_snapshot.identity.snapshot_id = SnapshotId::new("snapshot-stale").expect("snapshot");
    let stale_guest = GuestRequest {
        source: stale_snapshot,
        ..base_guest.clone()
    };
    let native_error = screen_memory_curation(&base_triple.0, &stale_guest.source, &base_triple.2)
        .expect_err("native rejects stale identity");
    assert!(matches!(
        native_error,
        CurationScreenError::Contract(ContractError::BindingMismatch { .. })
    ));
    let response = handle_request_typed(&stale_guest);
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::from(&native_error)));
    // Duplicate evidence identities fail closed with one native call.
    let mut duplicated = base_triple.2.clone();
    duplicated.push(duplicated[0].clone());
    let duplicate_guest = GuestRequest {
        evidence: duplicated.clone(),
        ..base_guest.clone()
    };
    let native_error = screen_memory_curation(&base_triple.0, &base_triple.1, &duplicated)
        .expect_err("native rejects duplicates");
    assert!(matches!(
        native_error,
        CurationScreenError::Contract(ContractError::Duplicate { .. })
    ));
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&duplicate_guest, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.error, Some(GuestError::from(&native_error)));
    // Every bound surfaces as the exact native bound error.
    let mut item_limited = base_triple.0.clone();
    item_limited.profile.limits.max_items = 1;
    let limited_guest = GuestRequest {
        request: item_limited,
        ..base_guest.clone()
    };
    assert_eq!(
        handle_request_typed(&limited_guest).error,
        Some(GuestError::ContractBound {
            field: "screen.items".into()
        })
    );
    let mut byte_limited = base_triple.0.clone();
    byte_limited.profile.limits.max_bytes = 1;
    let byte_guest = GuestRequest {
        request: byte_limited,
        ..base_guest.clone()
    };
    assert_eq!(
        handle_request_typed(&byte_guest).error,
        Some(GuestError::ContractBound {
            field: "screen.input_bytes".into()
        })
    );
    let native = native_of(&base_triple).expect("native");
    let mut output_limited = base_triple.0.clone();
    output_limited.profile.limits.max_output_bytes =
        native.coverage.usage.output_bytes.saturating_sub(32);
    let output_guest = GuestRequest {
        request: output_limited,
        ..base_guest.clone()
    };
    assert_eq!(
        handle_request_typed(&output_guest).error,
        Some(GuestError::ContractBound {
            field: "result.output_bytes".into()
        })
    );
}

// WORK_UNIT_CASE: 642/10
#[test]
fn native_component_fields_and_digest_equal() {
    let mut snapshot = source(3, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    snapshot.members[1]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let (guest, triple) =
        guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let native = native_of(&triple).expect("native screen");
    let response = handle_request_typed(&guest);
    assert_eq!(response.native_calls, 1);
    assert_eq!(
        response.request_digest,
        sha256_hex(&canonical_json_bytes(&guest).expect("canonical"))
    );
    let result = response.result.as_ref().expect("result");
    assert_eq!(*result, native);
    assert_eq!(result.request, native.request);
    assert_eq!(result.source, native.source);
    assert_eq!(result.findings, native.findings);
    assert_eq!(result.protection, native.protection);
    assert_eq!(result.eligibility, native.eligibility);
    assert_eq!(result.coverage, native.coverage);
    assert_eq!(result.member_sets, native.member_sets);
    assert_eq!(result.state, native.state);
    assert_eq!(result.result_digest, native.result_digest);
    assert_eq!(
        result.result_digest,
        result.computed_digest().expect("digest")
    );
    assert_eq!(
        result.coverage.digest,
        result.coverage.computed_digest().expect("coverage digest")
    );
    assert_eq!(
        canonical_json_bytes(result).expect("component bytes"),
        canonical_json_bytes(&native).expect("native bytes")
    );
}

// WORK_UNIT_CASE: 642/11
#[test]
fn permutation_determinism() {
    let mut snapshot = source(2, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    snapshot.members[1]
        .evidence
        .conflict
        .insert(ArtifactId::new("conflict-1").expect("artifact"));
    let triple_evidence = |order: &[usize]| {
        let all = clear_evidence(&snapshot);
        let extra = evidence(
            &snapshot,
            snapshot.members[0].member_id.clone(),
            "evidence-extra",
            ProtectionEvidenceState::CurrentVerified,
            ProtectionOutcome::Absent,
        );
        let pool = [all[0].clone(), all[1].clone(), extra];
        order
            .iter()
            .map(|index| pool[*index].clone())
            .collect::<Vec<_>>()
    };
    let mut digests = BTreeSet::new();
    let mut encodings = BTreeSet::new();
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
        let (guest, triple) =
            guest_request(&snapshot, profile(both_rules()), triple_evidence(&order));
        let native = native_of(&triple).expect("native screen");
        let response = handle_request_typed(&guest);
        let result = response.result.as_ref().expect("result").clone();
        assert_eq!(result, native);
        digests.insert(result.result_digest.as_str().to_owned());
        encodings.insert(canonical_json_bytes(&result).expect("bytes"));
    }
    assert_eq!(digests.len(), 1, "evidence order must not move the digest");
    assert_eq!(encodings.len(), 1, "evidence order must not move bytes");
    let (guest, _) = guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let first = screen(&encode_request(&guest).expect("encode")).expect("screen");
    let second = screen(&encode_request(&guest).expect("encode")).expect("screen");
    assert_eq!(first, second);
}

// WORK_UNIT_CASE: 642/12
#[test]
fn built_forbidden_import_rejected_before_execution() {
    for forbidden in eliot_memory_curation_screen_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
        assert!(
            is_forbidden_import(&format!("cap:{forbidden}"), "f"),
            "gate covers {forbidden}"
        );
    }
    for required in [
        "filesystem",
        "stdio",
        "network",
        "env",
        "args",
        "clock",
        "random",
        "process",
        "thread",
        "credential",
        "store",
        "kernel",
        "provider",
    ] {
        assert!(
            eliot_memory_curation_screen_wasm::FORBIDDEN_IMPORT_SUBSTRINGS
                .iter()
                .any(|forbidden| required.contains(forbidden) || forbidden.contains(required)),
            "issue namespace {required} is gated"
        );
    }
    for (module, name) in [
        ("wasi:filesystem/types@0.2.10", "stat"),
        ("wasi:sockets/tcp@0.2.10", "connect"),
        ("wasi:http/outgoing-handler@0.2.10", "handle"),
        ("wasi:cli/stdin@0.2.10", "get-stdin"),
        ("wasi:clocks/wall-clock@0.2.10", "now"),
        ("wasi:random/random@0.2.10", "get-random-bytes"),
        ("wasi_snapshot_preview1", "fd_write"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("wasi fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_memory_curation_screen_wasm::DescriptorError::ForbiddenImport {
                module: module.into(),
                name: name.into(),
            }
        );
    }
    // Component Model binaries (current wasm32-wasip2 rustc output) parse too.
    let component_header = [0x00, 0x61, 0x73, 0x6D, 0x0D, 0x00, 0x01, 0x00];
    assert_eq!(
        list_wasm_imports(&component_header).expect("component header"),
        vec![]
    );
    let benign =
        wat::parse_str("(module (func (export \"screen\") (param i32) (result i32) local.get 0))")
            .expect("benign fixture");
    assert_eq!(list_wasm_imports(&benign).expect("imports"), vec![]);
    assert!(
        check_wasm_imports(&benign)
            .expect("benign passes")
            .is_empty()
    );
    assert!(check_wasm_imports(b"not a module").is_err());
}

// WORK_UNIT_CASE: 642/13
#[test]
fn one_native_call_no_duplicate_algorithm() {
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (guest, triple) =
        guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&guest, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.result.is_some());
    // A native error still costs exactly one call, never a retry loop.
    let mut cancelled = triple.0.clone();
    cancelled.cancellation_requested = true;
    let cancelled_guest = GuestRequest {
        request: cancelled,
        ..guest.clone()
    };
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&cancelled_guest, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert_eq!(response.error, Some(GuestError::Cancelled));
    // Structural proof: exactly one native call site outside tests, no
    // duplicate screen/A-31/Store algorithm and no capability escape.
    let mut sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source_text = read_src(name);
        sites += source_text.matches("screen_memory_curation(").count();
        for forbidden in [
            "serde_json::Value",
            "unimplemented!",
            "todo!",
            "std::process",
            "std::fs",
            "tokio",
            "reqwest",
            "surrealdb",
        ] {
            assert!(
                !source_text.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
        for duplicate in [
            "route_validated",
            "NativeCuration",
            "assess_dimensions",
            "derive_protection",
        ] {
            assert!(
                !source_text.contains(duplicate),
                "{name} must not duplicate {duplicate}"
            );
        }
    }
    assert_eq!(sites, 1);
}

// WORK_UNIT_CASE: 642/14
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (guest, _) = guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    let input = encode_request(&guest).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-642-capsule").expect("invocation"),
        CapabilityId::new("fixture-screen-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-642").expect("work unit"),
        WorkScopeRef::new("fixture-scope-642").expect("scope"),
        ExecutionContour::Shadow,
        input,
        642,
        false,
    )
    .expect("capsule request");
    invocation.validate().expect("capsule digest");
    // #758/#760 are OPEN: no engine/port surface is injected, so the real
    // facade must return the typed PLAN_GAP instead of executing.
    let mut runtime = WasmRuntime::new(None);
    let result = runtime.execute(invocation);
    assert_eq!(
        result.receipt.disposition,
        InvocationDisposition::Unavailable
    );
    assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    assert!(result.output.is_none());
    assert!(result.proposed_effects.is_empty());
    assert!(result.observed_state_delta.is_none());
    assert!(!result.receipt.reconciliation_required);
    // Cancellation preserves the real host's typed rejection path.
    let cancelled = InvocationRequest::new(
        InvocationId::new("fixture-642-cancelled").expect("invocation"),
        CapabilityId::new("fixture-screen-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-642").expect("work unit"),
        WorkScopeRef::new("fixture-scope-642").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        642,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 642/15
#[test]
fn clean_warm_artifact_identity_and_later_admission() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-memory-curation-screen-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Controller-owned handoff (issue #642): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-memory-curation-screen-wasm"));
    assert!(!root_cargo_lock().contains("eliot-memory-curation-screen-wasm"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(eliot_memory_curation_screen_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
    // Warm identity: repeated envelopes and descriptors are byte-identical.
    let mut snapshot = source(1, DenominatorCoverage::Complete);
    with_provenance(&mut snapshot);
    let (guest, _) = guest_request(&snapshot, profile(both_rules()), clear_evidence(&snapshot));
    assert_eq!(
        encode_request(&guest).expect("encode"),
        encode_request(&guest).expect("encode")
    );
    assert_eq!(
        request_digest(&guest),
        request_digest(&guest),
        "request binding is stable"
    );
}

// WORK_UNIT_CASE: 642/16
#[test]
fn property_component_equals_native_protected_never_eligible() {
    let mut unicode = source(2, DenominatorCoverage::Complete);
    unicode.members[0].member_id = MemberId::new("mitglied-ß-✓-01").expect("unicode member");
    unicode.members[1].member_id = MemberId::new("mitglied-ß-✓-02").expect("unicode member");
    unicode.denominator.declared_member_ids = unicode
        .members
        .iter()
        .map(|member| member.member_id.clone())
        .collect();
    unicode.partition.changed_targets = unicode
        .denominator
        .declared_member_ids
        .iter()
        .cloned()
        .collect();
    with_provenance(&mut unicode);
    for count in 1..=3usize {
        for coverage in [DenominatorCoverage::Complete, DenominatorCoverage::Partial] {
            let mut snapshot = source(count, coverage);
            with_provenance(&mut snapshot);
            if coverage == DenominatorCoverage::Partial {
                snapshot.availability = SourceAvailability::Available;
            }
            let snapshot_protected = snapshot.clone();
            for (label, evidence) in [
                ("clear", clear_evidence(&snapshot)),
                (
                    "first-protected",
                    snapshot
                        .members
                        .iter()
                        .enumerate()
                        .map(|(index, member)| {
                            evidence(
                                &snapshot_protected,
                                member.member_id.clone(),
                                &format!("evidence-{index}"),
                                ProtectionEvidenceState::CurrentVerified,
                                if index == 0 {
                                    ProtectionOutcome::Present
                                } else {
                                    ProtectionOutcome::Absent
                                },
                            )
                        })
                        .collect::<Vec<_>>(),
                ),
            ] {
                let (guest, triple) = guest_request(&snapshot, profile(both_rules()), evidence);
                let native = native_of(&triple).expect("native screen");
                let response = handle_request_typed(&guest);
                let result = response.result.as_ref().expect("result").clone();
                assert_eq!(
                    result, native,
                    "count={count} coverage={coverage:?} {label}"
                );
                assert!(result.validate().is_ok());
                // Every member is accounted exactly once in each record set.
                let source_ids: BTreeSet<MemberId> = snapshot
                    .members
                    .iter()
                    .map(|member| member.member_id.clone())
                    .collect();
                for (set, name) in [
                    (
                        result
                            .protection
                            .iter()
                            .map(|item| item.member_id.clone())
                            .collect::<BTreeSet<_>>(),
                        "protection",
                    ),
                    (
                        result
                            .eligibility
                            .iter()
                            .map(|item| item.member_id.clone())
                            .collect::<BTreeSet<_>>(),
                        "eligibility",
                    ),
                    (
                        result
                            .coverage
                            .members
                            .iter()
                            .map(|member| member.member_id.clone())
                            .collect::<BTreeSet<_>>(),
                        "coverage",
                    ),
                ] {
                    assert_eq!(set, source_ids, "count={count} {label} {name}");
                }
                assert_eq!(result.protection.len(), source_ids.len());
                assert_eq!(result.eligibility.len(), source_ids.len());
                // A protected member never becomes an eligible mutable target.
                for member in &result.coverage.members {
                    let assessment: &ProtectionAssessment = result
                        .protection
                        .iter()
                        .find(|item| item.member_id == member.member_id)
                        .expect("assessment");
                    let eligibility: &Eligibility = result
                        .eligibility
                        .iter()
                        .find(|item| item.member_id == member.member_id)
                        .expect("eligibility");
                    if assessment.decision == ProtectionDecision::Protected {
                        assert_ne!(
                            member.disposition,
                            MemberDisposition::Eligible,
                            "protected member must not be eligible"
                        );
                        assert_ne!(
                            eligibility.status,
                            EligibilityStatus::EligibleForSemanticCuration
                        );
                        assert!(!member.eligible);
                    }
                    if member.disposition == MemberDisposition::Eligible {
                        assert!(member.eligible);
                        assert_eq!(
                            eligibility.status,
                            EligibilityStatus::EligibleForSemanticCuration
                        );
                        assert_eq!(eligibility.protection, ProtectionDecision::Unprotected);
                        assert!(
                            triple
                                .0
                                .partition
                                .changed_targets
                                .contains(&member.member_id),
                            "eligible member must be a changed target"
                        );
                        let findings: Vec<_> = result
                            .findings
                            .iter()
                            .filter(|finding| finding.member_id == member.member_id)
                            .collect();
                        assert!(
                            findings.is_empty(),
                            "eligible member must carry no findings"
                        );
                    }
                }
            }
        }
    }
    // Unicode identities round-trip through the guest envelope unchanged.
    let (guest, triple) = guest_request(&unicode, profile(both_rules()), clear_evidence(&unicode));
    let native = native_of(&triple).expect("native unicode screen");
    let response = handle_request_typed(&guest);
    assert_eq!(response.result.as_ref().expect("result"), &native);
}
