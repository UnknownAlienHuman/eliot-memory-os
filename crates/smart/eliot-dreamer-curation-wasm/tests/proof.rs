//! Issue #636 proof matrix: exactly cases 1..14, one test per case.
//!
//! Faithful test-only doubles (`EchoHandler`) stand at the typed Rust
//! boundary where owner-published live handlers are absent; they live in this
//! test file, never in shipped code, mirroring the native A-31 crate's own
//! `CountingHandler` proof pattern. Every dispatch assertion runs the real
//! [`route_validated_curation`] on both the guest path and the direct native
//! path over the same accepted registry identities.
#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::uninlined_format_args
)]

use std::cell::{Cell, RefCell};
use std::num::NonZeroU64;

use eliot_contracts::{
    EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, StateFence, sha256_hex,
};
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::curation::{
    AccessibilityPayload, ClassificationPayload, ConceptPayload, EpisodePayload, FailurePayload,
    MergePayload, ProcedurePayload, ReconsolidationPayload, RelationPayload, RepairPayload,
    SplitPayload, TargetEvidence, kind_family,
};
use eliot_dreamer_contracts::job::{PRIVACY_LOCAL_ONLY, RequesterOrigin};
use eliot_dreamer_contracts::registry::family_kinds;
use eliot_dreamer_contracts::{
    AtomicityMode, BoundCurationCall, BudgetLimits, BudgetUsage, CURATION_FAMILIES,
    CURATION_WIRE_KINDS, CandidateDisposition, ContractViolation, CurationFamily,
    CurationHandlerDescriptor, CurationHandlerRegistry, CurationKind, CurationPayload,
    CurationRejectionCode, NativeCurationHandler, PRESERVATION_DIMENSIONS, PreservationDimension,
    PreservationReport, ProducedCurationContent, Requester, ScreenBinding, ScreenState,
    TargetDenominator, ValidatedCurationItem, ValidationReceipt, family_of, parse_family,
};
use eliot_dreamer_curation::{
    CurationRoutingError, MAX_BATCH_ITEMS, NativeCurationPortSet, OwnerRevisionPin,
    RoutingDisposition, RoutingPolicy, ValidatedCurationBatch, compute_input_digest,
    expected_owner_package, route_validated_curation, routing_rejection_hint,
};
use eliot_dreamer_curation_wasm::{
    COMPONENT_VERSION, CallLedger, EXPORT_NAME, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES,
    GuestError, GuestRequest, GuestResponse, HANDLER_SUBTYPE, MISSING_OWNER_ISSUES,
    TOOLCHAIN_BYTES, TOOLCHAIN_CHANNEL, TYPED_WORLD_STATUS, WORLD_NAME, WORLD_PACKAGE,
    assemble_ports, check_wasm_imports, decode_request, decode_response, descriptor,
    descriptor_digest, disposition_as_str, encode_request, encode_response, family_as_str, handle,
    handle_request_typed, handle_with_ledger, handle_with_ports, is_forbidden_import, kind_as_str,
    list_wasm_imports, missing_owner_families, owner_issue, parse_disposition,
    parse_family_spelling, parse_kind_spelling, qualified_export_name, rejection_hint_as_str,
    request_digest, resolve_family, resolve_rejection_hint, static_port_challenge, static_registry,
    static_registry_digest, wit_export_name,
};

// ---------------------------------------------------------------------------
// Fixtures (public APIs only; mirror the native crate's sealed-batch shape).
// ---------------------------------------------------------------------------

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("canonical lineage"),
        NonZeroU64::new(1).expect("non-zero sequence"),
    )
    .expect("valid epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn receipt() -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".to_owned(),
        validator_policy: "policy-7".to_owned(),
        job_id: "job-1".to_owned(),
        draft_digest: "a".repeat(64),
        bundle_digest: "b".repeat(64),
        manifest_digest: "c".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        input_digest: "d".repeat(64),
        output_digest: "e".repeat(64),
        terminal_disposition: "accepted".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        state_fence: fence(),
        preservation_digest: "f".repeat(64),
        budget_digest: "0".repeat(64),
    }
}

fn facets(targets: &[&str]) -> TargetEvidence {
    TargetEvidence {
        targets: targets.iter().map(|item| (*item).to_owned()).collect(),
        evidence_refs: vec!["e-1".to_owned()],
    }
}

fn payload_for(kind: CurationKind, targets: &[&str]) -> CurationPayload {
    use CurationPayload as Payload;
    match kind {
        CurationKind::Classification => Payload::Classification(ClassificationPayload {
            label: "memory".to_owned(),
            confidence_bps: 9000,
            target_evidence: facets(targets),
        }),
        CurationKind::Relation => Payload::Relation(RelationPayload {
            from_handle: targets[0].to_owned(),
            to_handle: targets[1].to_owned(),
            relation: "refines".to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Episode => Payload::Episode(EpisodePayload {
            episode: "ep-7".to_owned(),
            observed_at_ms: 1_700_000_000_000,
            target_evidence: facets(targets),
        }),
        CurationKind::Concept => Payload::Concept(ConceptPayload {
            concept: "fence".to_owned(),
            definition: "state dependency".to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Procedure => Payload::Procedure(ProcedurePayload {
            procedure: "rotate".to_owned(),
            steps: 3,
            target_evidence: facets(targets),
        }),
        CurationKind::Failure => Payload::Failure(FailurePayload {
            fingerprint: "fp-1".to_owned(),
            signature: "sig-1".to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Merge => Payload::Merge(MergePayload {
            left: targets[0].to_owned(),
            right: targets[1].to_owned(),
            merged: targets[2].to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Split => Payload::Split(SplitPayload {
            whole: targets[2].to_owned(),
            first: targets[0].to_owned(),
            second: targets[1].to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Reconsolidation => Payload::Reconsolidation(ReconsolidationPayload {
            target: targets[0].to_owned(),
            update: "refresh".to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Accessibility => Payload::Accessibility(AccessibilityPayload {
            handle: targets[0].to_owned(),
            note: "captioned".to_owned(),
            target_evidence: facets(targets),
        }),
        CurationKind::Repair => Payload::Repair(RepairPayload {
            target: targets[0].to_owned(),
            repair: "relink".to_owned(),
            target_evidence: facets(targets),
        }),
    }
}

fn item(kind: CurationKind, targets: &[&str]) -> ValidatedCurationItem {
    ValidatedCurationItem {
        receipt: receipt(),
        kind_spelling: kind.as_str().to_owned(),
        family_spelling: kind_family(kind).to_owned(),
        payload: payload_for(kind, targets),
        denominator: TargetDenominator {
            mode: AtomicityMode::PerMember,
            members: targets.iter().map(|item| (*item).to_owned()).collect(),
            expected_total: u32::try_from(targets.len()).expect("denominator fits u32"),
        },
        source_digest: "1".repeat(64),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        job_digest: "2".repeat(64),
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "op-1".to_owned(),
            session: None,
        },
        budget_note: "within budget".to_owned(),
    }
}

fn screen(targets: &[&str]) -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-1").expect("request id"),
        receipt_id: ReceiptId::new("rcpt-1").expect("receipt id"),
        screened_targets: targets.iter().map(|item| (*item).to_owned()).collect(),
        source_snapshot: "snap-1".to_owned(),
        source_revision: "rev-1".to_owned(),
        profile: "default".to_owned(),
        task_id: "task-1".to_owned(),
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: "b".repeat(64),
    }
}

fn pins() -> Vec<OwnerRevisionPin> {
    CURATION_FAMILIES
        .iter()
        .map(|spelling| OwnerRevisionPin {
            family: parse_family(spelling).expect("known family"),
            revision: "rev-1".to_owned(),
        })
        .collect()
}

fn policy(allow_partial: bool) -> RoutingPolicy {
    RoutingPolicy {
        policy_id: "routing-policy-1".to_owned(),
        policy_revision: 1,
        allow_partial,
        max_items: u32::try_from(MAX_BATCH_ITEMS).expect("batch bound fits u32"),
    }
}

fn budgets() -> (BudgetLimits, BudgetUsage) {
    (
        BudgetLimits {
            input_bytes: Some(4096),
            output_bytes: Some(4096),
            source_width: Some(16),
            reference_width: Some(16),
            model_calls: Some(8),
            attempts: Some(8),
            candidates: Some(8),
            wall_ms: Some(1000),
            work_fan_out: Some(8),
            report_bytes: Some(4096),
            max_stu: Some(100),
        },
        BudgetUsage::default(),
    )
}

fn seal(
    items: Vec<ValidatedCurationItem>,
    denom: &[&str],
    atomicity: AtomicityMode,
    screen: &ScreenBinding,
    registry: &CurationHandlerRegistry,
    policy: &RoutingPolicy,
    pins: &[OwnerRevisionPin],
) -> ValidatedCurationBatch {
    let (limits, usage) = budgets();
    let mut batch = ValidatedCurationBatch {
        job_id: "job-1".to_owned(),
        request_id: "req-1".to_owned(),
        operation_id: "op-1".to_owned(),
        idempotency_key: "idem-1".to_owned(),
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "op-1".to_owned(),
            session: None,
        },
        task_id: "task-1".to_owned(),
        attempt: 1,
        scope_id: "scope-1".to_owned(),
        state_fence: fence(),
        bundle_digest: "b".repeat(64),
        manifest_digest: "c".repeat(64),
        grounding_digest: "d".repeat(64),
        receipt: receipt(),
        items,
        denominator: TargetDenominator {
            mode: atomicity,
            members: denom.iter().map(|item| (*item).to_owned()).collect(),
            expected_total: u32::try_from(denom.len()).expect("denominator fits u32"),
        },
        privacy_profile: PRIVACY_LOCAL_ONLY.to_owned(),
        authority_ref: "epoch-genesis".to_owned(),
        effect_note: "routing exercises no effect".to_owned(),
        proof_ceiling: "candidate-only".to_owned(),
        atomicity,
        budgets: limits,
        usage,
        deadline_ms: None,
        observation_time_ms: None,
        cancelled: false,
        predecessor_digests: Vec::new(),
        invalidation_note: "no invalidation".to_owned(),
        registry_digest: registry.digest().expect("closed registry"),
        owner_pins: pins.to_vec(),
        input_digest: "0".repeat(64),
    };
    let digest = compute_input_digest(&batch, screen, &batch.registry_digest, policy)
        .expect("sealed input digest");
    batch.input_digest = digest;
    batch
}

fn guest_request(
    items: Vec<ValidatedCurationItem>,
    denom: &[&str],
    atomicity: AtomicityMode,
    screen: &ScreenBinding,
    registry: &CurationHandlerRegistry,
    policy: &RoutingPolicy,
) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        batch: seal(items, denom, atomicity, screen, registry, policy, &pins()),
        screen: screen.clone(),
        policy: policy.clone(),
    }
}

fn guest_request_pinned(
    items: Vec<ValidatedCurationItem>,
    denom: &[&str],
    atomicity: AtomicityMode,
    screen: &ScreenBinding,
    registry: &CurationHandlerRegistry,
    policy: &RoutingPolicy,
    pins: &[OwnerRevisionPin],
) -> GuestRequest {
    GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        batch: seal(items, denom, atomicity, screen, registry, policy, pins),
        screen: screen.clone(),
        policy: policy.clone(),
    }
}

// ---------------------------------------------------------------------------
// Faithful test-only doubles (never shipped): echo the frozen request
// payload with a chosen disposition and count real invocations.
// ---------------------------------------------------------------------------

fn passing_report() -> PreservationReport {
    PreservationReport {
        verdicts: PRESERVATION_DIMENSIONS
            .iter()
            .map(|dimension| DimensionVerdict {
                dimension: PreservationDimension::parse(dimension).expect("known dimension"),
                passed: true,
                known: true,
                note: std::format!("{dimension} holds"),
            })
            .collect(),
    }
}

struct EchoHandler {
    descriptor: CurationHandlerDescriptor,
    calls: Cell<usize>,
    disposition: Cell<CandidateDisposition>,
    counterevidence: Vec<String>,
    seen_payloads: RefCell<Vec<CurationPayload>>,
}

impl EchoHandler {
    fn echoing(family: CurationFamily, disposition: CandidateDisposition) -> Self {
        Self {
            descriptor: descriptor_for(family),
            calls: Cell::new(0),
            disposition: Cell::new(disposition),
            counterevidence: Vec::new(),
            seen_payloads: RefCell::new(Vec::new()),
        }
    }
}

fn descriptor_for(family: CurationFamily) -> CurationHandlerDescriptor {
    CurationHandlerDescriptor {
        family,
        handler_id: expected_owner_package(family).to_owned(),
        accepted_kinds: family_kinds(family).to_vec(),
    }
}

impl NativeCurationHandler for EchoHandler {
    fn handle(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ProducedCurationContent, ContractViolation> {
        self.calls.set(self.calls.get().saturating_add(1));
        if call.port.descriptor != self.descriptor {
            return Err(ContractViolation::BindingMismatch {
                field: "handler_descriptor",
                reason: "double observed an unselected binding".to_owned(),
            });
        }
        self.seen_payloads
            .borrow_mut()
            .push(call.request.payload.clone());
        Ok(ProducedCurationContent {
            payload: call.request.payload.clone(),
            disposition: self.disposition.get(),
            preservation: passing_report(),
            support_note: "supported by source-b".to_owned(),
            rollback_note: "drop result to roll back".to_owned(),
            counterevidence_refs: self.counterevidence.clone(),
        })
    }
}

fn echo_handlers(disposition: CandidateDisposition) -> Vec<EchoHandler> {
    CURATION_FAMILIES
        .iter()
        .map(|spelling| {
            EchoHandler::echoing(parse_family(spelling).expect("known family"), disposition)
        })
        .collect()
}

fn ports_for<'a>(
    handlers: &'a [EchoHandler],
    registry: &CurationHandlerRegistry,
    pins: &[OwnerRevisionPin],
) -> NativeCurationPortSet<'a> {
    let pairs: Vec<(CurationFamily, &'a dyn NativeCurationHandler)> = handlers
        .iter()
        .map(|handler| {
            let live: &'a dyn NativeCurationHandler = handler;
            (handler.descriptor.family, live)
        })
        .collect();
    assemble_ports(registry, pins, &pairs).expect("closed assembly")
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 636/1
#[test]
fn exact_world_subtype_descriptor_abi_target_and_registry_identity() {
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.world, "dreamer-handler");
    assert_eq!(descriptor.export_name, EXPORT_NAME);
    assert_eq!(descriptor.export_name, wit_export_name());
    assert_eq!(descriptor.handler_subtype, HANDLER_SUBTYPE);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert_eq!(descriptor.target, GUEST_TARGET);
    assert_eq!(descriptor.toolchain_channel, TOOLCHAIN_CHANNEL);
    assert_eq!(descriptor.wit_digest, sha256_hex(GUEST_WIT_BYTES));
    assert!(descriptor.capability_envelope.is_empty());
    assert_eq!(descriptor.typed_world_status, TYPED_WORLD_STATUS);
    assert_eq!(qualified_export_name(), "dreamer-handler#handle");
    assert_eq!(
        qualified_export_name(),
        std::format!("{WORLD_NAME}#{EXPORT_NAME}")
    );
    // Static registry identity: ten closed descriptors bound to accepted
    // owner packages with exact canonical kind coverage.
    let registry = static_registry().expect("static registry");
    assert_eq!(registry.handlers.len(), 10);
    assert_eq!(
        static_registry_digest().expect("digest"),
        registry.digest().expect("digest")
    );
    for spelling in CURATION_FAMILIES {
        let family = parse_family(spelling).expect("known family");
        let declared = registry
            .handlers
            .iter()
            .find(|item| item.family == family)
            .expect("family declared");
        assert_eq!(declared.handler_id, expected_owner_package(family));
        assert_eq!(declared.accepted_kinds, family_kinds(family));
    }
    registry.validate_closure().expect("closed registry");
    // Sealed batches pin exactly this registry identity.
    let policy = policy(true);
    let targets = ["a"];
    let screen = screen(&targets);
    let request = guest_request(
        vec![item(CurationKind::Classification, &targets)],
        &targets,
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    assert_eq!(
        request.batch.registry_digest,
        registry.digest().expect("digest")
    );
    assert_eq!(descriptor.typed_world, "dreamer-handler");
}

// WORK_UNIT_CASE: 636/2
#[test]
fn wrong_subtype_version_payload_rejected_before_native_call() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let targets = ["a"];
    let screen = screen(&targets);
    let envelope = || {
        guest_request(
            vec![item(CurationKind::Classification, &targets)],
            &targets,
            AtomicityMode::PerMember,
            &screen,
            &registry,
            &policy,
        )
    };
    let ledger = CallLedger::new();
    let rejection_handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&rejection_handlers, &registry, &pins());
    // Wrong ABI version.
    let mut bad = envelope();
    bad.abi_version += 1;
    let response = handle_with_ports(&bad, &ports, &ledger);
    assert_eq!(
        response.error,
        Some(GuestError::RejectedEnvelope("abi_version".to_owned()))
    );
    assert_eq!(ledger.calls(), 0);
    assert_eq!(response.native_calls, 0);
    // Wrong world.
    let mut bad = envelope();
    bad.world = "guest".to_owned();
    let response = handle_with_ports(&bad, &ports, &ledger);
    assert_eq!(
        response.error,
        Some(GuestError::RejectedEnvelope("world".to_owned()))
    );
    assert_eq!(ledger.calls(), 0);
    // Wrong subtype.
    let mut bad = envelope();
    bad.handler_subtype = "orientation".to_owned();
    let response = handle_with_ports(&bad, &ports, &ledger);
    assert_eq!(
        response.error,
        Some(GuestError::RejectedEnvelope("handler_subtype".to_owned()))
    );
    assert_eq!(ledger.calls(), 0);
    // Undecodable payload keeps the transport-level error.
    assert!(handle(b"not canonical").is_err());
    assert_eq!(ledger.calls(), 0);
    // Oversize payload keeps the transport-level error.
    let huge = vec![0x7Bu8; 1_048_577];
    assert!(handle(&huge).is_err());
    assert_eq!(ledger.calls(), 0);
    // Unknown fields fail decoding: no silent reshaping.
    let mut hacked = envelope();
    hacked.world = WORLD_NAME.to_owned();
    let bytes = encode_request(&hacked).expect("encode");
    let json = String::from_utf8(bytes).expect("canonical UTF-8");
    let injected = json.replacen('{', "{\"guest_unknown_field\":1,", 1);
    assert!(decode_request(injected.as_bytes()).is_err());
    assert_eq!(ledger.calls(), 0);
}

// WORK_UNIT_CASE: 636/3
#[test]
fn exhaustive_input_output_error_conversion() {
    // Every native routing error variant converts and round-trips.
    let natives = [
        CurationRoutingError::Batch {
            field: "job_id",
            detail: "blank".to_owned(),
        },
        CurationRoutingError::Binding {
            field: "atomicity",
            detail: "drift".to_owned(),
        },
        CurationRoutingError::Receipt {
            detail: "receipt".to_owned(),
        },
        CurationRoutingError::Screen {
            detail: "screen".to_owned(),
        },
        CurationRoutingError::Registry {
            detail: "registry".to_owned(),
        },
        CurationRoutingError::Port {
            detail: "port".to_owned(),
        },
        CurationRoutingError::Policy {
            detail: "policy".to_owned(),
        },
        CurationRoutingError::Denominator {
            detail: "denominator".to_owned(),
        },
        CurationRoutingError::Handler {
            handler_id: "h".to_owned(),
            detail: "handler".to_owned(),
        },
        CurationRoutingError::HandlerPanicked {
            handler_id: "h".to_owned(),
        },
        CurationRoutingError::Envelope {
            handler_id: "h".to_owned(),
            detail: "envelope".to_owned(),
        },
        CurationRoutingError::Atomicity {
            detail: "atomicity".to_owned(),
        },
        CurationRoutingError::Digest {
            detail: "digest".to_owned(),
        },
    ];
    assert_eq!(natives.len(), 13);
    for native in &natives {
        let guest = GuestError::from(native);
        assert!(!guest.to_string().is_empty());
        let response = GuestResponse {
            abi_version: GUEST_ABI_VERSION,
            handler_subtype: HANDLER_SUBTYPE.to_owned(),
            set: None,
            error: Some(guest.clone()),
            native_calls: 1,
            static_registry_digest: "d".repeat(64),
        };
        let bytes = encode_response(&response).expect("encode");
        let back = decode_response(&bytes).expect("decode");
        assert_eq!(back, response);
    }
    // Envelope and missing-owner errors round-trip too.
    for extra in [
        GuestError::RejectedEnvelope("world".to_owned()),
        GuestError::RejectedBytes("input bytes".to_owned()),
        GuestError::MissingStaticPorts {
            detail: "frozen".to_owned(),
            missing_handlers: missing_owner_families(),
        },
    ] {
        let response = GuestResponse {
            abi_version: GUEST_ABI_VERSION,
            handler_subtype: HANDLER_SUBTYPE.to_owned(),
            set: None,
            error: Some(extra),
            native_calls: 0,
            static_registry_digest: "d".repeat(64),
        };
        let bytes = encode_response(&response).expect("encode");
        assert_eq!(decode_response(&bytes).expect("decode"), response);
    }
    // All 11 kinds, 10 families and 9 dispositions round-trip; the mapping
    // resolves only through the accepted function.
    assert_eq!(CURATION_WIRE_KINDS.len(), 11);
    for spelling in CURATION_WIRE_KINDS {
        let kind = parse_kind_spelling(spelling).expect("closed kind");
        assert_eq!(kind_as_str(kind), *spelling);
        assert_eq!(resolve_family(kind), family_of(kind));
    }
    assert_eq!(CURATION_FAMILIES.len(), 10);
    for spelling in CURATION_FAMILIES {
        let family = parse_family_spelling(spelling).expect("closed family");
        assert_eq!(family_as_str(family), *spelling);
    }
    assert!(parse_kind_spelling("abstraction").is_none());
    assert!(parse_family_spelling("structure-repair").is_none());
    let dispositions = [
        RoutingDisposition::Candidate,
        RoutingDisposition::Duplicate,
        RoutingDisposition::Conflict,
        RoutingDisposition::Abstention,
        RoutingDisposition::Partial,
        RoutingDisposition::Blocked,
        RoutingDisposition::Unsupported,
        RoutingDisposition::InternalDefect,
        RoutingDisposition::Unprocessed,
    ];
    for disposition in dispositions {
        let spelling = disposition_as_str(disposition);
        assert_eq!(parse_disposition(spelling), Some(disposition));
    }
    assert_eq!(parse_disposition("other"), None);
    // Hint mapping is total over the closed disposition set.
    for disposition in dispositions {
        assert_eq!(
            resolve_rejection_hint(disposition),
            routing_rejection_hint(disposition)
        );
        assert_eq!(
            rejection_hint_as_str(resolve_rejection_hint(disposition)),
            resolve_rejection_hint(disposition).map(CurationRejectionCode::as_str)
        );
    }
    assert_eq!(resolve_rejection_hint(RoutingDisposition::Candidate), None);
}

// WORK_UNIT_CASE: 636/4
#[test]
fn all_eleven_kinds_ten_families_and_every_disposition() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    // One item per wire kind; Merge and Split share StructureRepair.
    let notes: &[(&[&str], CurationKind)] = &[
        (&["c0"], CurationKind::Classification),
        (&["r0", "r1"], CurationKind::Relation),
        (&["e0"], CurationKind::Episode),
        (&["n0"], CurationKind::Concept),
        (&["p0"], CurationKind::Procedure),
        (&["f0"], CurationKind::Failure),
        (&["m0", "m1", "m2"], CurationKind::Merge),
        (&["s0", "s1", "s2"], CurationKind::Split),
        (&["x0"], CurationKind::Reconsolidation),
        (&["a0"], CurationKind::Accessibility),
        (&["y0"], CurationKind::Repair),
    ];
    let mut denom: Vec<&str> = Vec::new();
    for (targets, _) in notes {
        denom.extend(targets.iter());
    }
    let screen8 = screen(&["q0"]);
    let screen = screen(&denom);
    let items: Vec<ValidatedCurationItem> = notes
        .iter()
        .map(|(targets, kind)| item(*kind, targets))
        .collect();
    let request = guest_request(
        items,
        &denom,
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    let ledger = CallLedger::new();
    let response = handle_with_ports(&request, &ports, &ledger);
    assert!(response.error.is_none());
    let set = response.set.expect("candidate set");
    assert_eq!(set.members.len(), 11);
    for (index, (targets, kind)) in notes.iter().enumerate() {
        let member = &set.members[index];
        assert_eq!(member.item_index, u32::try_from(index).expect("index fits"));
        assert_eq!(member.kind, *kind);
        assert_eq!(member.family, family_of(*kind));
        assert_eq!(member.disposition, RoutingDisposition::Candidate);
        assert_eq!(member.calls, 1);
        let expected_targets: Vec<String> = targets.iter().map(|item| (*item).to_owned()).collect();
        assert_eq!(member.targets, expected_targets);
        assert_eq!(member.evidence_refs, vec!["e-1".to_owned()]);
        assert_eq!(member.request_digest.as_ref().expect("digest").len(), 64);
        assert_eq!(member.result_digest.as_ref().expect("digest").len(), 64);
    }
    assert_eq!(
        set.members
            .iter()
            .filter(|member| member.family == CurationFamily::StructureRepair)
            .count(),
        2
    );
    assert_eq!(set.accepted, 11);
    assert_eq!(set.total_handler_calls, 11);
    // Every terminal disposition is preserved exactly (one family each).
    let want = [
        (
            CurationKind::Classification,
            CandidateDisposition::Duplicate,
        ),
        (CurationKind::Episode, CandidateDisposition::Conflict),
        (CurationKind::Concept, CandidateDisposition::Abstention),
        (CurationKind::Procedure, CandidateDisposition::Partial),
        (CurationKind::Failure, CandidateDisposition::Blocked),
        (
            CurationKind::Reconsolidation,
            CandidateDisposition::Unsupported,
        ),
        (
            CurationKind::Accessibility,
            CandidateDisposition::InternalDefect,
        ),
    ];
    for (kind, disposition) in want {
        let single = guest_request(
            vec![item(kind, &["q0"])],
            &["q0"],
            AtomicityMode::PerMember,
            &screen8,
            &registry,
            &policy,
        );
        let solo_handlers = echo_handlers(disposition);
        let solo_ports = ports_for(&solo_handlers, &registry, &pins());
        let solo = handle_request_typed(&single, &solo_ports);
        assert!(solo.error.is_none());
        let member = &solo.set.expect("set").members[0];
        assert_eq!(
            member.disposition,
            RoutingDisposition::from(disposition),
            "kind {} preserves {disposition:?}",
            kind.as_str()
        );
        assert_eq!(member.calls, 1);
    }
}

// WORK_UNIT_CASE: 636/5
#[test]
fn protected_target_zero_dispatch_with_retained_evidence() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a", "b", "ab"]);
    let request = guest_request(
        vec![
            item(CurationKind::Classification, &["a"]),
            item(CurationKind::Repair, &["zz"]),
        ],
        &["a", "b", "ab"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    let ledger = CallLedger::new();
    let response = handle_with_ports(&request, &ports, &ledger);
    assert!(response.error.is_none());
    let set = response.set.expect("partial set");
    // Full item accounting: both members present exactly once.
    assert_eq!(set.members.len(), 2);
    assert_eq!(set.members[0].disposition, RoutingDisposition::Candidate);
    assert_eq!(set.members[0].calls, 1);
    // Protected (unscreened) target: zero dispatch, evidence retained.
    assert_eq!(set.members[1].disposition, RoutingDisposition::Blocked);
    assert_eq!(set.members[1].calls, 0);
    assert_eq!(set.members[1].handler_id, "family:memory_repair");
    assert_eq!(set.members[1].targets, vec!["zz".to_owned()]);
    assert_eq!(set.members[1].evidence_refs, vec!["e-1".to_owned()]);
    assert_eq!(set.accepted, 1);
    assert_eq!(set.blocked, 1);
    assert_eq!(set.total_handler_calls, 1);
    assert_eq!(ledger.calls(), 1);
    // A protected screen state fails closed before any dispatch. The batch
    // was sealed against the eligible screen, so the mutated screen trips
    // the screen binding check deterministically (never a digest confusion).
    let mut guarded = screen.clone();
    guarded.state = ScreenState::Protected;
    let guarded_request = GuestRequest {
        screen: guarded,
        ..request.clone()
    };
    let before = handlers
        .iter()
        .map(|handler| handler.calls.get())
        .collect::<Vec<_>>();
    let guarded_response = handle_request_typed(&guarded_request, &ports);
    assert!(
        matches!(guarded_response.error, Some(GuestError::Screen { .. })),
        "protected screen must fail closed, got {:?}",
        guarded_response.error
    );
    assert_eq!(guarded_response.native_calls, 1);
    for (handler, calls) in handlers.iter().zip(before.iter()) {
        assert_eq!(
            handler.calls.get(),
            *calls,
            "no handler runs on screen failure"
        );
    }
}
// WORK_UNIT_CASE: 636/6
#[test]
fn all_or_nothing_partial_native_component_parity() {
    let registry = static_registry().expect("static registry");
    let strict_targets = ["a", "r0", "r1"];
    let strict_screen = screen(&strict_targets);
    // All-or-nothing with one partial member fails closed identically.
    // Denominator coverage holds exactly; the Relation echo stays partial.
    let strict = policy(false);
    let strict_request = guest_request(
        vec![
            item(CurationKind::Classification, &["a"]),
            item(CurationKind::Relation, &["r0", "r1"]),
        ],
        &["a", "r0", "r1"],
        AtomicityMode::AllOrNothing,
        &strict_screen,
        &registry,
        &strict,
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    handlers
        .iter()
        .find(|handler| handler.descriptor.family == CurationFamily::Relation)
        .expect("relation double")
        .disposition
        .set(CandidateDisposition::Partial);
    let ports = ports_for(&handlers, &registry, &pins());
    let guest = handle_request_typed(&strict_request, &ports);
    let native = route_validated_curation(
        &strict_request.batch,
        &strict_request.screen,
        &registry,
        &strict_request.policy,
        &ports,
    );
    assert!(matches!(guest.error, Some(GuestError::Atomicity { .. })));
    let native_error = native.expect_err("native all-or-nothing fails");
    assert_eq!(guest.error, Some(GuestError::from(&native_error)));
    assert_eq!(guest.set, None);
    // Explicit partial preserves the exact frontier on both paths.
    let partial = policy(true);
    let partial_targets = ["a", "zz", "b"];
    let partial_screen = screen(&partial_targets);
    let partial_request = guest_request(
        vec![
            item(CurationKind::Classification, &["a"]),
            item(CurationKind::Repair, &["qq"]),
        ],
        &partial_targets,
        AtomicityMode::PerMember,
        &partial_screen,
        &registry,
        &partial,
    );
    let guest_partial = handle_request_typed(&partial_request, &ports);
    let native_partial = route_validated_curation(
        &partial_request.batch,
        &partial_request.screen,
        &registry,
        &partial_request.policy,
        &ports,
    )
    .expect("native partial routes");
    assert!(guest_partial.error.is_none());
    let guest_set = guest_partial.set.expect("guest set");
    assert_eq!(guest_set, native_partial);
    assert_eq!(
        guest_set.unprocessed_frontier,
        native_partial.unprocessed_frontier
    );
    assert_eq!(
        guest_set.members[1].disposition,
        RoutingDisposition::Blocked
    );
    assert_eq!(guest_set.members[1].calls, 0);
    assert_eq!(
        guest_set.omitted_targets,
        vec!["b".to_owned(), "zz".to_owned()]
    );
}

// WORK_UNIT_CASE: 636/7
#[test]
fn preservation_lineage_counterevidence_parity() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a"]);
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    // Counterevidence doubles on both paths; content must match exactly.
    let mut guest_handlers = echo_handlers(CandidateDisposition::Candidate);
    guest_handlers[0].counterevidence = vec!["ce-1".to_owned()];
    let guest_ports = ports_for(&guest_handlers, &registry, &pins());
    let guest = handle_request_typed(&request, &guest_ports);
    let mut native_handlers = echo_handlers(CandidateDisposition::Candidate);
    native_handlers[0].counterevidence = vec!["ce-1".to_owned()];
    let native_ports = ports_for(&native_handlers, &registry, &pins());
    let native = route_validated_curation(
        &request.batch,
        &request.screen,
        &registry,
        &request.policy,
        &native_ports,
    )
    .expect("native routes");
    assert!(guest.error.is_none());
    let guest_set = guest.set.expect("guest set");
    assert_eq!(guest_set, native);
    // Seven preservation dimensions pass; lineage binds handler and digests.
    let seen = guest_handlers[0].seen_payloads.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].kind(), CurationKind::Classification);
    let member = &guest_set.members[0];
    assert_eq!(
        member.handler_id,
        expected_owner_package(CurationFamily::Classification)
    );
    assert_eq!(member.request_digest, native.members[0].request_digest);
    assert_eq!(member.result_digest, native.members[0].result_digest);
    assert_eq!(guest_set.set_digest, native.set_digest);
    guest_set.validate().expect("emitted set validates");
    assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
}

// WORK_UNIT_CASE: 636/8
#[test]
fn stale_identity_duplicates_and_all_bounds() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a"]);
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    // Stale owner pin fails closed as a port error with zero handler calls.
    // Ports bind the sealed pins; the batch sealed against a drifted pin
    // trips the real staleness check at dispatch, never at assembly.
    let mut stale = pins();
    stale[0].revision = "rev-2".to_owned();
    let stale_request = guest_request_pinned(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
        &stale,
    );
    let stale_response = handle_request_typed(&stale_request, &ports);
    assert!(
        matches!(stale_response.error, Some(GuestError::Port { .. })),
        "stale pin must fail closed, got {:?}",
        stale_response.error
    );
    assert!(handlers.iter().all(|handler| handler.calls.get() == 0));
    // Duplicate item content fails closed as a binding error.
    let dupe = guest_request(
        vec![
            item(CurationKind::Classification, &["a"]),
            item(CurationKind::Classification, &["a"]),
        ],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let dupe_response = handle_request_typed(&dupe, &ports);
    assert!(matches!(
        dupe_response.error,
        Some(GuestError::Binding { .. })
    ));
    // Defaulted policy revision fails closed before any digest check.
    let loose = RoutingPolicy {
        policy_id: "routing-policy-1".to_owned(),
        policy_revision: 0,
        allow_partial: true,
        max_items: 0,
    };
    let loose_request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &loose,
    );
    let loose_response = handle_request_typed(&loose_request, &ports);
    assert!(matches!(
        loose_response.error,
        Some(GuestError::Policy { .. })
    ));
    // Overlong identity fails closed as a batch error.
    let mut wide = request.clone();
    wide.batch.task_id = "t".repeat(300);
    let wide_response = handle_request_typed(&wide, &ports);
    assert!(matches!(
        wide_response.error,
        Some(GuestError::Batch { .. } | GuestError::Digest { .. })
    ));
    // Oversize batch fails closed as a batch error.
    let big: Vec<ValidatedCurationItem> = (0..65)
        .map(|_| item(CurationKind::Classification, &["a"]))
        .collect();
    let big_request = guest_request(
        big,
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let big_response = handle_request_typed(&big_request, &ports);
    assert!(matches!(big_response.error, Some(GuestError::Batch { .. })));
}

// WORK_UNIT_CASE: 636/9
#[test]
fn deterministic_permutation_parity() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a", "e0"]);
    let forward = guest_request(
        vec![
            item(CurationKind::Classification, &["a"]),
            item(CurationKind::Episode, &["e0"]),
        ],
        &["a", "e0"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    // Resealed reversal: per-member outcomes permute, nothing is lost.
    let reversed = guest_request(
        vec![
            item(CurationKind::Episode, &["e0"]),
            item(CurationKind::Classification, &["a"]),
        ],
        &["a", "e0"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    assert_ne!(
        forward.batch.input_digest, reversed.batch.input_digest,
        "item order stays digest-visible"
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    let first = handle_request_typed(&forward, &ports)
        .set
        .expect("forward set");
    let second = handle_request_typed(&reversed, &ports)
        .set
        .expect("reversed set");
    assert_eq!(first.members.len(), 2);
    assert_eq!(second.members[0].kind, CurationKind::Episode);
    assert_eq!(second.members[1].kind, CurationKind::Classification);
    let mut first_ids: Vec<&str> = first
        .members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect();
    let mut second_ids: Vec<&str> = second
        .members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect();
    first_ids.sort_unstable();
    second_ids.sort_unstable();
    assert_eq!(first_ids, second_ids);
    // Registration order never moves the registry digest.
    let mut shuffled = CurationHandlerRegistry::new();
    for descriptor in registry.handlers.iter().rev().cloned() {
        shuffled.register(descriptor).expect("fixture descriptor");
    }
    assert_eq!(
        shuffled.digest().expect("digest"),
        registry.digest().expect("digest")
    );
}

// WORK_UNIT_CASE: 636/10
#[test]
fn one_a31_call_inert_static_registration_only() {
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a"]);
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    // Typed path: exactly one A-31 call, inert registration digest attached.
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    let ledger = CallLedger::new();
    let response = handle_with_ports(&request, &ports, &ledger);
    assert!(response.error.is_none());
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.set.is_some());
    assert_eq!(
        response.static_registry_digest,
        static_registry_digest().expect("static digest")
    );
    // Bytes path: static composition proves closed, zero A-31 calls, frozen
    // missing-owner error (no handler fabricated to register it).
    let bytes = encode_request(&request).expect("encode");
    let static_ledger = CallLedger::new();
    let transport = handle_with_ledger(&bytes, &static_ledger).expect("transport");
    let static_response = decode_response(&transport).expect("decode");
    assert_eq!(static_ledger.calls(), 0);
    assert_eq!(static_response.native_calls, 0);
    assert!(static_response.set.is_none());
    match static_response.error.expect("missing-owner error") {
        GuestError::MissingStaticPorts {
            detail,
            missing_handlers,
        } => {
            assert_eq!(missing_handlers.len(), 10);
            assert_eq!(missing_handlers, missing_owner_families());
            assert!(detail.contains("CC-636-STATIC-PORTS"));
        }
        other => panic!("expected missing-owner error, got {other:?}"),
    }
    assert_eq!(
        static_response.static_registry_digest,
        static_registry_digest().expect("static digest")
    );
    // Structural proof: exactly one native call site; no direct handler
    // invocation and no kind table in the dispatch path.
    let mut sites = 0;
    for name in ["conversion.rs", "export.rs"] {
        sites += read_src(name).matches("route_validated_curation(").count();
    }
    assert_eq!(sites, 1);
    for name in ["conversion.rs", "export.rs"] {
        let source = read_src(name);
        assert!(
            !source.contains(".handle("),
            "{name} must not invoke handlers"
        );
        assert!(
            !source.contains("CurationKind::"),
            "{name} must not table kinds"
        );
        assert!(
            !source.contains("CurationFamily::"),
            "{name} must not table families"
        );
    }
    // The frozen challenge names every absent owner exactly once.
    let challenge = static_port_challenge();
    assert_eq!(challenge.challenge_id, "CC-636-STATIC-PORTS");
    assert_eq!(challenge.status, "OPEN_MISSING_OWNER");
    assert_eq!(challenge.required_owner, MISSING_OWNER_ISSUES);
    assert_eq!(challenge.required_owner.len(), 10);
    for spelling in CURATION_FAMILIES {
        let family = parse_family(spelling).expect("known family");
        assert!(
            challenge
                .required_owner
                .iter()
                .any(|owner| owner == owner_issue(family)),
            "family {} names its owner",
            family.as_str()
        );
    }
}

// WORK_UNIT_CASE: 636/11
#[test]
fn built_forbidden_imports_and_canonical_application_fields_rejected() {
    // A module importing a forbidden capability is rejected by name.
    let hostile = r#"(module
        (import "wasi:filesystem/types@0.2.10" "x" (func))
        (memory (export "memory") 1)
    )"#;
    let hostile_bytes = wat::parse_str(hostile).expect("hostile module");
    let rejected = check_wasm_imports(&hostile_bytes).expect_err("forbidden import");
    assert_eq!(
        rejected.to_string(),
        "forbidden import wasi:filesystem/types@0.2.10::x"
    );
    // A clean module passes with its exact import list.
    let clean = r#"(module (memory (export "memory") 1))"#;
    let clean_bytes = wat::parse_str(clean).expect("clean module");
    assert!(
        check_wasm_imports(&clean_bytes)
            .expect("clean passes")
            .is_empty()
    );
    assert!(list_wasm_imports(&clean_bytes).expect("listed").is_empty());
    assert!(check_wasm_imports(b"not a module").is_err());
    assert!(is_forbidden_import("wasi:clocks/wall-clock@0.2.10", "now"));
    assert!(is_forbidden_import("env", "random_get"));
    assert!(!is_forbidden_import("canonical", "handle"));
    // Canonical application fields are rejected, never absorbed.
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a"]);
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let bytes = encode_request(&request).expect("encode");
    let json = String::from_utf8(bytes).expect("canonical UTF-8");
    for field in [
        "\"authority_granted\"",
        "\"effect\"",
        "\"finish\"",
        "\"promotion\"",
    ] {
        let injected = json.replacen('{', &std::format!("{{\"guest_{field}\":1,"), 1);
        assert!(
            decode_request(injected.as_bytes()).is_err(),
            "unknown field {field} must fail"
        );
    }
    // No wildcard, stub, ambient-capability or network surface in shipped code.
    for name in [
        "lib.rs",
        "conversion.rs",
        "descriptor.rs",
        "export.rs",
        "static_registry.rs",
    ] {
        let source = read_src(name);
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
                !source.contains(forbidden),
                "{name} must not contain {forbidden}"
            );
        }
    }
}

// WORK_UNIT_CASE: 636/12
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let registry = static_registry().expect("static registry");
    let policy = policy(true);
    let screen = screen(&["a"]);
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen,
        &registry,
        &policy,
    );
    let input = encode_request(&request).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-636-capsule").expect("invocation"),
        CapabilityId::new("fixture-curation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-636").expect("work unit"),
        WorkScopeRef::new("fixture-scope-636").expect("scope"),
        ExecutionContour::Shadow,
        input,
        636,
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
        InvocationId::new("fixture-636-cancelled").expect("invocation"),
        CapabilityId::new("fixture-curation-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-636").expect("work unit"),
        WorkScopeRef::new("fixture-scope-636").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        636,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 636/13
#[test]
fn clean_warm_artifact_hash_size_world_abi_toolchain_and_admission() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-dreamer-curation-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Controller-owned handoff (issue #636): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-dreamer-curation-wasm"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(TOOLCHAIN_BYTES.to_vec()).expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
    // The real release artifact: stable hash, non-empty, exact pure world.
    // Current rustc emits a Component Model component (not a core module);
    // the gate parses both, descending into the nested core module.
    let target = std::env::var("CARGO_TARGET_DIR").expect("gate sets CARGO_TARGET_DIR");
    let artifact = std::format!("{target}/wasm32-wasip2/release/eliot_dreamer_curation_wasm.wasm");
    let bytes = std::fs::read(&artifact).unwrap_or_else(|_| panic!("read {artifact}"));
    assert!(!bytes.is_empty(), "release artifact is non-empty");
    assert_eq!(bytes[0..4], [0x00, 0x61, 0x73, 0x6D]);
    assert_eq!(bytes[4..8], COMPONENT_VERSION);
    let first = sha256_hex(&bytes);
    let again = std::fs::read(&artifact).unwrap_or_else(|_| panic!("read {artifact}"));
    assert_eq!(sha256_hex(&again), first, "artifact hash is stable");
    let imports = check_wasm_imports(&bytes).expect("pure-world artifact");
    assert!(
        imports.is_empty(),
        "release artifact grants zero host capabilities, got {imports:?}"
    );
    let descriptor = descriptor();
    assert_eq!(descriptor.wit_digest, sha256_hex(GUEST_WIT_BYTES));
    assert!(
        GUEST_WIT_BYTES
            .windows(16)
            .any(|window| window == b"world dreamer-ha")
    );
}

// WORK_UNIT_CASE: 636/14
#[test]
#[allow(clippy::type_complexity)]
fn property_component_equals_native_every_member_accounted_once() {
    let registry = static_registry().expect("static registry");
    let wide_screen = screen(&["a", "e0"]);
    let narrow_screen = screen(&["a"]);
    let screen = wide_screen;
    let shapes: &[(AtomicityMode, bool, &[(&[&str], CurationKind)])] = &[
        (
            AtomicityMode::PerMember,
            true,
            &[(&["a"], CurationKind::Classification)],
        ),
        (
            AtomicityMode::PerMember,
            true,
            &[
                (&["a"], CurationKind::Classification),
                (&["e0"], CurationKind::Episode),
            ],
        ),
        (
            AtomicityMode::AllOrNothing,
            false,
            &[
                (&["a"], CurationKind::Classification),
                (&["e0"], CurationKind::Episode),
            ],
        ),
    ];
    for (atomicity, allow_partial, notes) in shapes {
        let policy = policy(*allow_partial);
        let items: Vec<ValidatedCurationItem> = notes
            .iter()
            .map(|(targets, kind)| item(*kind, targets))
            .collect();
        let request = guest_request(items, &["a", "e0"], *atomicity, &screen, &registry, &policy);
        let guest_handlers = echo_handlers(CandidateDisposition::Candidate);
        let guest_ports = ports_for(&guest_handlers, &registry, &pins());
        let guest = handle_request_typed(&request, &guest_ports);
        let native_handlers = echo_handlers(CandidateDisposition::Candidate);
        let native_ports = ports_for(&native_handlers, &registry, &pins());
        match route_validated_curation(
            &request.batch,
            &request.screen,
            &registry,
            &request.policy,
            &native_ports,
        ) {
            Ok(native_set) => {
                let guest_set = guest.set.expect("guest set matches native success");
                assert_eq!(guest_set, native_set);
                guest_set.validate().expect("emitted set validates");
                // Every member accounted exactly once, in batch order.
                let mut indexes: Vec<u32> = guest_set
                    .members
                    .iter()
                    .map(|member| member.item_index)
                    .collect();
                indexes.sort_unstable();
                let expect: Vec<u32> = (0..u32::try_from(guest_set.members.len())
                    .expect("member count fits u32"))
                    .collect();
                assert_eq!(indexes, expect);
                let tallies = guest_set.accepted
                    + guest_set.rejected
                    + guest_set.blocked
                    + guest_set.unprocessed;
                assert_eq!(
                    tallies,
                    u32::try_from(guest_set.members.len()).expect("member count fits u32")
                );
                let calls: u32 = guest_set.members.iter().map(|member| member.calls).sum();
                assert_eq!(guest_set.total_handler_calls, calls);
                for member in &guest_set.members {
                    // No protected mutation target and no stronger authority:
                    // dispatched members stay inside the screened denominator;
                    // undispatched members made zero calls.
                    if member.calls > 0 {
                        for target in &member.targets {
                            assert!(
                                screen.screened_targets.contains(target),
                                "dispatched target {target} is screened"
                            );
                        }
                    } else {
                        assert_eq!(member.calls, 0);
                    }
                }
            }
            Err(native_error) => {
                assert_eq!(guest.error, Some(GuestError::from(&native_error)));
                assert_eq!(guest.set, None);
            }
        }
    }
    // The response envelope carries no grant/authority/effect surface.
    let policy = policy(true);
    let screen1 = narrow_screen;
    let request = guest_request(
        vec![item(CurationKind::Classification, &["a"])],
        &["a"],
        AtomicityMode::PerMember,
        &screen1,
        &registry,
        &policy,
    );
    let handlers = echo_handlers(CandidateDisposition::Candidate);
    let ports = ports_for(&handlers, &registry, &pins());
    let response = handle_request_typed(&request, &ports);
    let json =
        String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
    for absent in [
        "\"authority_granted\"",
        "\"effect_granted\"",
        "\"finish\"",
        "\"promotion\"",
        "\"executed_effect\"",
    ] {
        assert!(!json.contains(absent), "response must not raise {absent}");
    }
    // Request digests bind capsules to responses.
    assert_eq!(request_digest(&request).len(), 64);
}
