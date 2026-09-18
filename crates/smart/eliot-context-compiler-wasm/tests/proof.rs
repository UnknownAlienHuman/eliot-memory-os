//! Issue #638 proof matrix: exactly cases 1..13, one test per case.
#![allow(
    clippy::assigning_clones,
    clippy::expect_used,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_admission::admit_context;
use eliot_context_compiler_wasm::{
    ADMISSION_WIT_BYTES, CallLedger, EXPORT_NAME, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES,
    GuestError, GuestRequest, HANDLER_SUBTYPE, INCOMPLETE_CODE, TYPED_OPS, TYPED_WORLD_INTERFACE,
    TYPED_WORLD_STATUS, WORLD_NAME, WORLD_PACKAGE, admission_disposition_as_str,
    availability_as_str, check_wasm_imports, decode_request, decode_response, descriptor,
    descriptor_digest, encode_request, encode_response, handle_request_typed, handle_with_ledger,
    is_forbidden_import, list_wasm_imports, loss_policy_as_str, parse_admission_disposition,
    parse_availability, parse_loss_policy, parse_representation_kind, qualified_export_name,
    representation_kind_as_str, request_digest, run,
};
use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionMeasuredCost, AdmissionMeasurement,
    AdmissionMeasurementBinding, AdmissionPriorityClass, AdmissionResult, AdmissionRuleIdentity,
    AtomAvailability, AtomRepresentation, AuthorityClass, CandidatePriority, CapacityLimits,
    ContextBinding, ContextCandidate, ContextCandidateSet, ContextError, ContextErrorCode,
    ContextOutcome, ContextRecipe, DecisionContextIncomplete, DecisionRevision,
    DecisionSafetyFloor, LossPolicy, MeasurementAggregationMode, MeasurementCompositionProfile,
    MeasurementRef, MeasurementUnit, NonRecoverableReason, PrivacyClass, ProviderDisposition,
    ProviderId, ProviderRole, ProviderRoleDenominator, RepresentationKind, RoleLossRule,
    SafetyFloorIdentity, SafetyFloorMember, SemanticRole, SourceSnapshot, SuppliedOmissionBinding,
    canonical_digest,
};
use eliot_context_contracts::{CONTEXT_CONTRACT_VERSION, ExpansionHandle};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, SourceId, StateFence,
    TaskId, TaskRevision, canonical_json_bytes, sha256_hex,
};
use eliot_evidence::{Assertability, EpistemicStatus};
use eliot_receipts::{ProofCeiling, WorkScopeId};

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact id")
}

fn digest(byte: u8) -> String {
    char::from(byte).to_string().repeat(64)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn binding() -> ContextBinding {
    let mut fence = StateFence::new(
        test_epoch(),
        ResourceGeneration::new(1).expect("generation"),
    );
    fence.task_revision = Some(TaskRevision::new(1).expect("task revision"));
    ContextBinding {
        task_id: TaskId::new("task").expect("task"),
        attempt_id: AgentAttemptId::new("attempt").expect("attempt"),
        scope_id: WorkScopeId::new("scope").expect("scope"),
        state_fence: fence,
        decision_id: DecisionId::new("decision").expect("decision"),
        operation_id: None,
    }
}

fn role(provider: &str, semantic: SemanticRole) -> ProviderRole {
    ProviderRole {
        provider: ProviderId::new(provider).expect("provider"),
        role: semantic,
    }
}

fn decision(context: &ContextBinding) -> DecisionRevision {
    DecisionRevision {
        decision_id: context.decision_id.clone(),
        recipe_revision: TaskRevision::new(1).expect("revision"),
        policy_sha256: digest(b'a'),
    }
}

fn candidate(
    context: &ContextBinding,
    atom_id: &str,
    provider_role: ProviderRole,
    content: &str,
    loss_policy: LossPolicy,
    protected: bool,
) -> ContextCandidate {
    ContextCandidate {
        binding: context.clone(),
        atom_id: id(atom_id),
        provider_role,
        source: SourceSnapshot {
            source_id: SourceId::new(format!("source-{atom_id}")).expect("source"),
            owner: ProviderId::new(format!("owner-{atom_id}")).expect("owner"),
            snapshot_id: id(&format!("snapshot-{atom_id}")),
            revision: "r1".to_owned(),
            content_sha256: digest(b'b'),
            predecessor: None,
        },
        representation: AtomRepresentation::Whole {
            content: content.to_owned(),
        },
        loss_policy,
        availability: AtomAvailability::PresentCurrent,
        protected,
        privacy: PrivacyClass::Public,
        authority: AuthorityClass::DecisionRelevant,
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        measurement: MeasurementRef {
            digest: digest(b'c'),
            serializer: "json-v1".to_owned(),
        },
        dependencies: Vec::new(),
        proof: eliot_context_contracts::ProofBinding {
            evidence_id: id(&format!("evidence-{atom_id}")),
            ceiling: ProofCeiling::Observation,
        },
    }
}

fn measurement(
    context: &ContextBinding,
    candidate: &ContextCandidate,
    measurement_id: &str,
    cost: AdmissionMeasuredCost,
) -> AdmissionMeasurement {
    AdmissionMeasurement {
        measurement_id: id(measurement_id),
        atom_id: candidate.atom_id.clone(),
        representation: candidate.representation.kind(),
        unit: MeasurementUnit::Utf8Bytes,
        binding: AdmissionMeasurementBinding {
            context: context.clone(),
            schema_version: CONTEXT_CONTRACT_VERSION,
            subject_digest: canonical_digest(candidate).expect("candidate subject"),
            input_digest: candidate.measurement.digest.clone(),
            output_digest: digest(b'e'),
            serializer_id: "json-v1".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(b'f'),
            route_id: "route".to_owned(),
            model_id: "model".to_owned(),
        },
        cost,
        observation: None,
    }
}

fn expansion(
    context: &ContextBinding,
    candidate: &ContextCandidate,
    policy: LossPolicy,
) -> ExpansionHandle {
    ExpansionHandle {
        handle_id: id(&format!("handle-{}", candidate.atom_id)),
        atom_id: candidate.atom_id.clone(),
        source_id: id(candidate.source.source_id.as_str()),
        source_revision: candidate.source.revision.clone(),
        context: context.clone(),
        decision: decision(context),
        policy,
        provider_role: candidate.provider_role.clone(),
        handle_digest: digest(b'a'),
        expires: None,
        invalidation: None,
    }
}

fn make_handle_optional(input: &mut AdmissionInput) {
    let context = input.binding.clone();
    let candidate = &mut input.candidates.candidates[1];
    let handle = id(&format!("handle-{}", candidate.atom_id));
    candidate.representation = AtomRepresentation::Handle { handle };
    candidate.loss_policy = LossPolicy::HandleOnly;
    let policy = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
        .expect("optional policy");
    policy.loss_policy = LossPolicy::HandleOnly;
    policy.allowed_representations = vec![RepresentationKind::Handle];
    input.supplied_omissions[0].policy = LossPolicy::HandleOnly;
    input.supplied_omissions[0].expansion =
        Some(expansion(&context, candidate, LossPolicy::HandleOnly));
    input.supplied_omissions[0].non_recoverable_reason = None;
    input.measurements[1] = measurement(
        &context,
        candidate,
        "optional-measurement",
        input.measurements[1].cost.clone(),
    );
    input.recipe.recipe_sha256 = input
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
}

fn refresh_recipe(input: &mut AdmissionInput) {
    input.recipe.recipe_sha256 = input
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
}

fn input_with_optional(optional_cost: AdmissionMeasuredCost) -> AdmissionInput {
    let context = binding();
    let required_role = role("required-provider", SemanticRole::Goal);
    let optional_role = role("optional-provider", SemanticRole::Optional);
    let required = candidate(
        &context,
        "required",
        required_role.clone(),
        "required",
        LossPolicy::NonDroppable,
        true,
    );
    let optional = candidate(
        &context,
        "optional",
        optional_role.clone(),
        "optional",
        LossPolicy::Summarizable,
        false,
    );
    let requested = vec![required_role.clone(), optional_role.clone()];
    let dispositions = requested
        .iter()
        .cloned()
        .map(|slot| ProviderDisposition {
            slot,
            state: AtomAvailability::PresentCurrent,
            evidence: None,
        })
        .collect::<Vec<_>>();
    let denominator = ProviderRoleDenominator {
        requested,
        dispositions,
    };
    let capacity = CapacityLimits {
        route_capacity: 100,
        fixed_overhead: 10,
        output_reserve: 10,
        review_reserve: 10,
    };
    let mut recipe = ContextRecipe {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        decision: decision(&context),
        recipe_sha256: digest(b'd'),
        denominator: denominator.clone(),
        mandatory_roles: vec![SemanticRole::Goal],
        role_policies: vec![
            RoleLossRule {
                role: SemanticRole::Goal,
                loss_policy: LossPolicy::NonDroppable,
                required: true,
                allowed_representations: vec![RepresentationKind::Whole],
            },
            RoleLossRule {
                role: SemanticRole::Optional,
                loss_policy: LossPolicy::Summarizable,
                required: false,
                allowed_representations: vec![
                    RepresentationKind::Whole,
                    RepresentationKind::Summary,
                ],
            },
        ],
        capacity,
        predecessor: None,
        invalidation: None,
    };
    recipe.recipe_sha256 = recipe.canonical_policy_digest().expect("recipe digest");
    let floor = DecisionSafetyFloor {
        binding: context.clone(),
        mandatory_atoms: vec![required.atom_id.clone()],
        mandatory_roles: vec![SemanticRole::Goal],
        providers: ProviderRoleDenominator {
            requested: vec![required_role.clone()],
            dispositions: vec![ProviderDisposition {
                slot: required_role,
                state: AtomAvailability::PresentCurrent,
                evidence: None,
            }],
        },
        members: vec![SafetyFloorMember {
            atom_id: required.atom_id.clone(),
            role: SemanticRole::Goal,
            availability: AtomAvailability::PresentCurrent,
            measurement: Some(required.measurement.clone()),
            required_dependencies: Vec::new(),
        }],
        interpretation_dependencies: Vec::new(),
        rule_evidence: id("floor-rule"),
        capacity,
    };
    AdmissionInput {
        schema_version: CONTEXT_CONTRACT_VERSION,
        binding: context.clone(),
        recipe: recipe.clone(),
        candidates: ContextCandidateSet {
            binding: context.clone(),
            candidates: vec![required.clone(), optional.clone()],
            denominator: denominator.clone(),
        },
        floor: SafetyFloorIdentity {
            floor_id: id("floor"),
            decision: recipe.decision.clone(),
            floor,
        },
        priority: eliot_context_contracts::PriorityPolicyIdentity {
            policy_id: id("priority"),
            decision: recipe.decision.clone(),
            priorities: vec![
                CandidatePriority {
                    atom_id: required.atom_id.clone(),
                    class: AdmissionPriorityClass::Required,
                    ordinal: 0,
                },
                CandidatePriority {
                    atom_id: optional.atom_id.clone(),
                    class: AdmissionPriorityClass::Normal,
                    ordinal: 1,
                },
            ],
        },
        rule: AdmissionRuleIdentity {
            rule_id: id("rule"),
            decision: recipe.decision,
            rule_sha256: digest(b'a'),
        },
        measurement_profile: MeasurementCompositionProfile {
            profile_id: id("profile"),
            schema_version: CONTEXT_CONTRACT_VERSION,
            serializer_id: "json-v1".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(b'f'),
            route_id: "route".to_owned(),
            model_id: "model".to_owned(),
            unit: MeasurementUnit::Utf8Bytes,
            aggregation: MeasurementAggregationMode::QualifiedUtf8Contribution,
            qualification: id("qualification"),
            capacity,
        },
        supplied_omissions: vec![SuppliedOmissionBinding {
            atom_id: optional.atom_id.clone(),
            policy: LossPolicy::Summarizable,
            expansion: None,
            non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
            authorization_requirement: "owner".to_owned(),
            privacy_requirement: "scoped".to_owned(),
            proof_requirement: "observation".to_owned(),
            expires: None,
            invalidation: None,
        }],
        measurements: vec![
            measurement(
                &context,
                &required,
                "required-measurement",
                AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 },
            ),
            measurement(&context, &optional, "optional-measurement", optional_cost),
        ],
    }
}

fn push_extractive(
    input: &mut AdmissionInput,
    atom: &str,
    content: &str,
    manifest: Vec<String>,
    cost_value: u64,
    class: AdmissionPriorityClass,
    ordinal: u32,
) {
    let context = input.binding.clone();
    let slot = input.candidates.candidates[1].provider_role.clone();
    let mut atom_candidate =
        candidate(&context, atom, slot, content, LossPolicy::Extractive, false);
    atom_candidate.representation = AtomRepresentation::Extractive {
        content: content.to_owned(),
        manifest,
    };
    if let Some(policy) = input
        .recipe
        .role_policies
        .iter_mut()
        .find(|policy| policy.role == SemanticRole::Optional)
    {
        policy.loss_policy = LossPolicy::Extractive;
        policy.allowed_representations =
            vec![RepresentationKind::Whole, RepresentationKind::Extractive];
    }
    let cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: cost_value };
    input.measurements.push(measurement(
        &context,
        &atom_candidate,
        &format!("{atom}-measurement"),
        cost,
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: atom_candidate.atom_id.clone(),
        class,
        ordinal,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: atom_candidate.atom_id.clone(),
        policy: LossPolicy::Extractive,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(atom_candidate);
    refresh_recipe(input);
}

fn push_summary(
    input: &mut AdmissionInput,
    atom: &str,
    content: &str,
    cost_value: u64,
    class: AdmissionPriorityClass,
    ordinal: u32,
) {
    let context = input.binding.clone();
    let slot = input.candidates.candidates[1].provider_role.clone();
    let mut atom_candidate = candidate(
        &context,
        atom,
        slot,
        content,
        LossPolicy::Summarizable,
        false,
    );
    atom_candidate.representation = AtomRepresentation::Summary {
        content: content.to_owned(),
        source_digest: digest(b'b'),
    };
    let cost = AdmissionMeasuredCost::ExactUtf8Bytes { value: cost_value };
    input.measurements.push(measurement(
        &context,
        &atom_candidate,
        &format!("{atom}-measurement"),
        cost,
    ));
    input.priority.priorities.push(CandidatePriority {
        atom_id: atom_candidate.atom_id.clone(),
        class,
        ordinal,
    });
    input.supplied_omissions.push(SuppliedOmissionBinding {
        atom_id: atom_candidate.atom_id.clone(),
        policy: LossPolicy::Summarizable,
        expansion: None,
        non_recoverable_reason: Some(NonRecoverableReason::SourceUnavailable),
        authorization_requirement: "owner".to_owned(),
        privacy_requirement: "scoped".to_owned(),
        proof_requirement: "observation".to_owned(),
        expires: None,
        invalidation: None,
    });
    input.candidates.candidates.push(atom_candidate);
    refresh_recipe(input);
}

fn complete_set(result: &AdmissionResult) -> &eliot_context_contracts::AdmittedContextSet {
    match &result.outcome {
        ContextOutcome::Complete(set) => set,
        ContextOutcome::Incomplete(_) => panic!("expected complete admission"),
    }
}

fn incomplete_gap(result: &AdmissionResult) -> &DecisionContextIncomplete {
    match &result.outcome {
        ContextOutcome::Incomplete(gap) => gap,
        ContextOutcome::Complete(_) => panic!("expected incomplete outcome"),
    }
}

fn guest_request(cost: AdmissionMeasuredCost) -> (GuestRequest, AdmissionInput) {
    let input = input_with_optional(cost);
    let request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: input.clone(),
    };
    (request, input)
}

fn root_cargo_toml() -> &'static str {
    include_str!("../../../../Cargo.toml")
}

fn read_src(name: &str) -> String {
    let path = format!("{}/src/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {path}"))
}

// WORK_UNIT_CASE: 638/1
#[test]
fn exact_world_descriptor_abi_and_target() {
    let descriptor = descriptor();
    assert_eq!(descriptor.world_package, WORLD_PACKAGE);
    assert_eq!(descriptor.world, WORLD_NAME);
    assert_eq!(descriptor.world_package, "eliot:current@0.1.0");
    assert_eq!(descriptor.world, "context-admission");
    assert_eq!(descriptor.interface, TYPED_WORLD_INTERFACE);
    assert_eq!(descriptor.interface, "admission");
    assert_eq!(descriptor.typed_ops, TYPED_OPS);
    assert_eq!(descriptor.typed_ops, vec!["admit", "describe"]);
    assert_eq!(descriptor.export_name, EXPORT_NAME);
    assert_eq!(descriptor.export_name, "run");
    assert_eq!(descriptor.handler_subtype, HANDLER_SUBTYPE);
    assert_eq!(descriptor.abi_version, GUEST_ABI_VERSION);
    assert_eq!(descriptor.target, GUEST_TARGET);
    assert_eq!(
        descriptor.toolchain_channel,
        eliot_context_compiler_wasm::TOOLCHAIN_CHANNEL
    );
    assert!(descriptor.capability_envelope.is_empty());
    assert_eq!(descriptor.typed_world_status, TYPED_WORLD_STATUS);
    assert_eq!(descriptor.typed_world_status, "ACCEPTED");
    // Accepted typed world bytes carry the exact #756 contract.
    let wit = String::from_utf8(ADMISSION_WIT_BYTES.to_vec()).expect("admission WIT is UTF-8");
    assert!(wit.contains("package eliot:current@0.1.0"));
    assert!(wit.contains("world context-admission"));
    assert!(wit.contains("admit: func(request: admission-request)"));
    assert!(wit.contains("describe: func()"));
    assert!(wit.contains("non-droppable"));
    assert!(wit.contains("decision-context-incomplete"));
    assert_eq!(descriptor.wit_digest, sha256_hex(ADMISSION_WIT_BYTES));
    // Byte transport shape is the accepted guest world.
    let guest = String::from_utf8(GUEST_WIT_BYTES.to_vec()).expect("guest.wit is UTF-8");
    assert!(guest.contains("package eliot:wasm@1.0.0"));
    assert!(guest.contains("world guest"));
    assert!(guest.contains("export run"));
    assert_eq!(descriptor.guest_wit_digest, sha256_hex(GUEST_WIT_BYTES));
    assert_eq!(qualified_export_name(), "guest#run");
    assert_eq!(eliot_context_compiler_wasm::wit_export_name(), "run");
    // #870 readiness: pinned target and channel from the owning toolchain file.
    let toolchain = String::from_utf8(eliot_context_compiler_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("rust-toolchain.toml is UTF-8");
    assert!(toolchain.contains("wasm32-wasip2"));
    assert!(toolchain.contains(eliot_context_compiler_wasm::TOOLCHAIN_CHANNEL));
    assert_eq!(GUEST_TARGET, eliot_wasm_runtime::DEFAULT_GUEST_TARGET);
    assert_eq!(descriptor_digest(), descriptor_digest());
}

// WORK_UNIT_CASE: 638/2
#[test]
fn wrong_world_version_subtype_rejected_before_native_call() {
    let (mut request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    for mutate in [
        |request: &mut GuestRequest| request.handler_subtype = "assembly".into(),
        |request: &mut GuestRequest| request.world = "context-assembly".into(),
        |request: &mut GuestRequest| request.world = "guest".into(),
        |request: &mut GuestRequest| request.abi_version = 999,
        |request: &mut GuestRequest| request.handler_subtype = String::new(),
    ] {
        let mut bad = request.clone();
        mutate(&mut bad);
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&bad, &ledger);
        assert_eq!(ledger.calls(), 0);
        assert_eq!(response.native_calls, 0);
        assert!(response.result.is_none());
        assert!(matches!(
            response.error,
            Some(GuestError::RejectedEnvelope(_))
        ));
    }
    request.handler_subtype = HANDLER_SUBTYPE.to_owned();
    // Undecodable and trailing-garbage payloads never reach native either.
    assert!(run(&[0xFF, 0xFE, 0x00]).is_err());
    let mut trailing = encode_request(&request).expect("encode");
    trailing.extend_from_slice(b"trailing");
    assert!(run(&trailing).is_err());
}

// WORK_UNIT_CASE: 638/3
#[test]
fn exhaustive_input_output_error_conversion() {
    let natives = [
        ContextError::MissingField("field"),
        ContextError::InvalidField("field"),
        ContextError::Bounds { field: "field" },
        ContextError::InvalidFence,
        ContextError::Duplicate("field"),
        ContextError::DenominatorMismatch,
        ContextError::IdentityConflict,
        ContextError::WholeUnitRequired,
        ContextError::MissingFloor,
        ContextError::StaleFloor,
        ContextError::BlockedFloor,
        ContextError::OversizedFloor,
        ContextError::Overflow,
        ContextError::CapacityExceeded,
        ContextError::UnknownMeasurement,
        ContextError::OmissionHandleInvalid,
        ContextError::EconomyMismatch,
        ContextError::QualityIncomplete,
        ContextError::SelectionIntegrityMismatch,
        ContextError::InvalidDigest("field"),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for native in &natives {
        let guest = GuestError::from(native);
        let json = canonical_json_bytes(&guest).expect("guest error json");
        assert!(seen.insert(json), "every native error maps distinctly");
    }
    assert_eq!(seen.len(), 20);
    // Closed wire vocabularies round-trip exhaustively.
    let dispositions = [
        AdmissionDisposition::Include,
        AdmissionDisposition::HandleOnly,
        AdmissionDisposition::Revalidate,
        AdmissionDisposition::Suppress,
        AdmissionDisposition::Quarantine,
        AdmissionDisposition::Unavailable,
        AdmissionDisposition::Blocked,
        AdmissionDisposition::OverBudget,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for disposition in dispositions {
        let code = admission_disposition_as_str(disposition);
        assert!(codes.insert(code), "disposition codes are distinct");
        assert_eq!(parse_admission_disposition(code), Some(disposition));
    }
    assert_eq!(codes.len(), 8);
    assert_eq!(parse_admission_disposition("winner"), None);
    let policies = [
        LossPolicy::NonDroppable,
        LossPolicy::HandleOnly,
        LossPolicy::Extractive,
        LossPolicy::Summarizable,
    ];
    let mut policy_codes = std::collections::BTreeSet::new();
    for policy in policies {
        let code = loss_policy_as_str(policy);
        assert!(policy_codes.insert(code), "loss codes are distinct");
        assert_eq!(parse_loss_policy(code), Some(policy));
    }
    assert_eq!(policy_codes.len(), 4);
    assert_eq!(parse_loss_policy("droppable"), None);
    let states = [
        AtomAvailability::PresentCurrent,
        AtomAvailability::Missing,
        AtomAvailability::Stale,
        AtomAvailability::Blocked,
        AtomAvailability::Unavailable,
        AtomAvailability::Omitted,
        AtomAvailability::Exhausted,
        AtomAvailability::Unknown,
        AtomAvailability::KnownEmpty,
        AtomAvailability::Partial,
    ];
    let mut state_codes = std::collections::BTreeSet::new();
    for state in states {
        let code = availability_as_str(state);
        assert!(state_codes.insert(code), "availability codes are distinct");
        assert_eq!(parse_availability(code), Some(state));
    }
    assert_eq!(state_codes.len(), 10);
    assert_eq!(parse_availability("current"), None);
    let kinds = [
        RepresentationKind::Whole,
        RepresentationKind::Handle,
        RepresentationKind::Extractive,
        RepresentationKind::Summary,
    ];
    let mut kind_codes = std::collections::BTreeSet::new();
    for kind in kinds {
        let code = representation_kind_as_str(kind);
        assert!(kind_codes.insert(code), "representation codes are distinct");
        assert_eq!(parse_representation_kind(code), Some(kind));
    }
    assert_eq!(kind_codes.len(), 4);
    assert_eq!(parse_representation_kind("bytes"), None);
    // Typed envelopes round-trip through canonical bytes.
    let (request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let bytes = encode_request(&request).expect("encode");
    assert_eq!(decode_request(&bytes).expect("decode"), request);
    let response = handle_request_typed(&request);
    let response_bytes = encode_response(&response).expect("encode response");
    assert_eq!(decode_response(&response_bytes).expect("decode"), response);
}

// WORK_UNIT_CASE: 638/4
#[test]
fn all_dispositions_four_loss_policies_and_incomplete_preserved() {
    // Two valid inputs together carry all four loss policies: NonDroppable
    // (required whole) and Summarizable (optional whole) in the base input,
    // Extractive (pushed excerpt) alongside them, and HandleOnly (optional
    // handle) in a second input. One role policy cannot admit a handle and
    // an extract under the same role, so no single input carries all four.
    let mut three = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_extractive(
        &mut three,
        "excerpt",
        "extract content",
        vec!["field-a".to_owned(), "field-b".to_owned()],
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    let three_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: three,
    };
    let three_response = handle_request_typed(&three_request);
    assert_eq!(three_response.native_calls, 1);
    assert!(three_response.error.is_none());
    let three_result = three_response.result.expect("admission result");
    let three_admitted = complete_set(&three_result);
    let mut policies: Vec<&str> = three_admitted
        .records
        .iter()
        .map(|record| loss_policy_as_str(record.candidate.loss_policy))
        .collect();
    policies.sort_unstable();
    assert_eq!(
        policies,
        vec!["extractive", "non-droppable", "summarizable"]
    );
    let mut two = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    make_handle_optional(&mut two);
    let two_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: two,
    };
    let two_response = handle_request_typed(&two_request);
    assert!(two_response.error.is_none());
    let two_result = two_response.result.expect("handle result");
    let two_admitted = complete_set(&two_result);
    let mut handle_policies: Vec<&str> = two_admitted
        .records
        .iter()
        .map(|record| loss_policy_as_str(record.candidate.loss_policy))
        .collect();
    handle_policies.sort_unstable();
    assert_eq!(handle_policies, vec!["handle-only", "non-droppable"]);
    let mut dispositions: Vec<&str> = three_admitted
        .records
        .iter()
        .chain(two_admitted.records.iter())
        .map(|record| admission_disposition_as_str(record.disposition))
        .collect();
    dispositions.sort_unstable();
    dispositions.dedup();
    assert!(dispositions.contains(&"include-member"));
    assert!(dispositions.contains(&"handle-only"));
    // DECISION_CONTEXT_INCOMPLETE is a first-class result, not an error.
    let mut missing = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    missing.candidates.candidates[0].availability = AtomAvailability::Missing;
    missing.candidates.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing.recipe.denominator.dispositions[0].state = AtomAvailability::Missing;
    missing.recipe.recipe_sha256 = missing
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    missing.measurements[0].binding.subject_digest =
        canonical_digest(&missing.candidates.candidates[0]).expect("missing subject");
    missing.floor.floor.members[0].availability = AtomAvailability::Missing;
    missing.floor.floor.members[0].measurement = None;
    missing.floor.floor.providers.dispositions[0].state = AtomAvailability::Missing;
    let missing_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: missing,
    };
    let missing_response = handle_request_typed(&missing_request);
    assert_eq!(missing_response.native_calls, 1);
    assert!(missing_response.error.is_none());
    let missing_result = missing_response.result.expect("incomplete result");
    let gap = incomplete_gap(&missing_result);
    assert_eq!(gap.code, ContextErrorCode::DecisionContextIncomplete);
    assert_eq!(INCOMPLETE_CODE, "DECISION_CONTEXT_INCOMPLETE");
    assert_eq!(gap.missing, vec![id("required")]);
}

// WORK_UNIT_CASE: 638/5
#[test]
fn candidate_provider_denominator_parity() {
    let (request, input) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let native = admit_context(&input).expect("native");
    let response = handle_request_typed(&request);
    let result = response.result.expect("result");
    let native_set = complete_set(&native);
    let guest_set = complete_set(&result);
    assert_eq!(guest_set.records.len(), native_set.records.len());
    assert_eq!(guest_set.economy.requested, native_set.economy.requested);
    assert_eq!(guest_set.economy.admitted, native_set.economy.admitted);
    assert_eq!(guest_set.economy.displaced, native_set.economy.displaced);
    assert_eq!(
        result.evidence.decisions.len(),
        native.evidence.decisions.len()
    );
    // A denominator that no longer reconciles is the exact native failure.
    let mut broken = input.clone();
    broken.candidates.candidates.pop();
    let broken_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: broken,
    };
    let ledger = CallLedger::new();
    let broken_response = handle_with_ledger(&broken_request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert!(broken_response.result.is_none());
    assert_eq!(broken_response.error, Some(GuestError::DenominatorMismatch));
}

// WORK_UNIT_CASE: 638/6
#[test]
fn floor_headroom_unknown_measurement_omission_economy_parity() {
    // Validly represented unknown measurement is a native domain input: the
    // guest must not invent a rejection or thin success for it.
    let mut unknown = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unknown.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    let unknown_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: unknown.clone(),
    };
    let ledger = CallLedger::new();
    let unknown_response = handle_with_ledger(&unknown_request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert!(unknown_response.error.is_none());
    let native_unknown = admit_context(&unknown).expect("unknown is explicit");
    assert_eq!(unknown_response.result.expect("result"), native_unknown);
    let gap = incomplete_gap(&native_unknown);
    assert_eq!(gap.unknown, vec![id("required")]);
    // Optional over-budget is a reversible omission with economy displacement.
    let mut over = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    make_handle_optional(&mut over);
    let over_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: over.clone(),
    };
    let over_response = handle_request_typed(&over_request);
    assert!(over_response.error.is_none());
    let over_result = over_response.result.expect("result");
    let native_over = admit_context(&over).expect("omission is valid");
    assert_eq!(over_result, native_over);
    let admitted = complete_set(&over_result);
    assert_eq!(admitted.records.len(), 1);
    assert_eq!(admitted.economy.allocations.admitted_required, 20);
    assert_eq!(admitted.economy.allocations.remaining_headroom, 50);
    assert!(admitted.economy.displaced.contains(&id("optional")));
    let omission = over_result
        .evidence
        .omissions
        .first()
        .expect("omission evidence");
    assert_eq!(omission.measured_cost, Some(80));
}

// WORK_UNIT_CASE: 638/7
#[test]
fn stale_identity_ceilings_and_bounds() {
    // Stale mandatory material is an exact incomplete gap, not a guest error.
    let mut stale = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    stale.candidates.candidates[0].availability = AtomAvailability::Stale;
    stale.candidates.denominator.dispositions[0].state = AtomAvailability::Stale;
    stale.recipe.denominator.dispositions[0].state = AtomAvailability::Stale;
    stale.floor.floor.members[0].availability = AtomAvailability::Stale;
    stale.floor.floor.providers.dispositions[0].state = AtomAvailability::Stale;
    stale.recipe.recipe_sha256 = stale
        .recipe
        .canonical_policy_digest()
        .expect("recipe digest");
    stale.measurements[0].binding.subject_digest =
        canonical_digest(&stale.candidates.candidates[0]).expect("stale subject");
    stale.measurements[1].binding.subject_digest =
        canonical_digest(&stale.candidates.candidates[1]).expect("optional subject");
    let stale_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: stale,
    };
    let stale_response = handle_request_typed(&stale_request);
    assert!(stale_response.error.is_none());
    let stale_result = stale_response.result.expect("result");
    let gap = incomplete_gap(&stale_result);
    assert_eq!(gap.stale, vec![id("required")]);
    // Collapsed capacity is the exact native capacity failure.
    let (request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let mut tight = request.input.clone();
    tight.recipe.capacity.route_capacity = 10;
    tight.floor.floor.capacity = tight.recipe.capacity;
    tight.measurement_profile.capacity = tight.recipe.capacity;
    refresh_recipe(&mut tight);
    let tight_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: tight,
    };
    let tight_response = handle_request_typed(&tight_request);
    assert_eq!(tight_response.native_calls, 1);
    assert!(tight_response.result.is_none());
    assert_eq!(tight_response.error, Some(GuestError::CapacityExceeded));
    // Wrong contract schema is the exact native identity failure.
    let mut wrong_schema = request.input.clone();
    wrong_schema.schema_version = eliot_contracts::ContractVersion::new(9, 9, 9);
    let schema_request = GuestRequest {
        abi_version: GUEST_ABI_VERSION,
        world: WORLD_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        input: wrong_schema,
    };
    let schema_response = handle_request_typed(&schema_request);
    assert!(schema_response.result.is_none());
    assert!(matches!(
        schema_response.error,
        Some(GuestError::InvalidField(_))
    ));
    // Guest byte ceiling at the boundary.
    assert!(decode_request(&vec![0u8; 2_097_152]).is_err());
}

// WORK_UNIT_CASE: 638/8
#[test]
fn deterministic_native_component_parity() {
    let (request, input) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let native = admit_context(&input).expect("native");
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    let result = response.result.expect("result");
    assert!(response.error.is_none());
    assert_eq!(result, native);
    assert_eq!(result.input_digest, native.input_digest);
    assert_eq!(result.recipe_digest, native.recipe_digest);
    assert_eq!(result.profile_digest, native.profile_digest);
    assert_eq!(result.selection_digest, native.selection_digest);
    assert_eq!(result.result_digest, native.result_digest);
    // Parity also holds through the `run` byte boundary, deterministically.
    let bytes = run(&encode_request(&request).expect("encode")).expect("run");
    let through_bytes = decode_response(&bytes)
        .expect("decode")
        .result
        .expect("result");
    assert_eq!(through_bytes, native);
    let again = encode_response(&handle_request_typed(&request)).expect("encode");
    assert_eq!(bytes, again);
    assert_eq!(request_digest(&request), request_digest(&request));
}

// WORK_UNIT_CASE: 638/9
#[test]
fn exactly_one_native_call_no_foreign_algorithm() {
    let (request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let ledger = CallLedger::new();
    let response = handle_with_ledger(&request, &ledger);
    assert_eq!(ledger.calls(), 1);
    assert_eq!(response.native_calls, 1);
    assert!(response.result.is_some());
    // Structural proof: exactly one A-17a call site outside tests, and no
    // candidate/assembly/measurement algorithm inside the guest.
    let mut sites = 0;
    for name in ["lib.rs", "conversion.rs", "descriptor.rs", "export.rs"] {
        let source = read_src(name);
        sites += source.matches("admit_context(").count();
        for foreign in [
            "fn admit_context",
            "fn prepare_floor",
            "fn select_required",
            "fn select_optional",
            "fn assemble_result",
            "eliot-context-assembly",
            "eliot-context-candidates",
            "eliot-context-measurement",
            "ContextAssembly",
        ] {
            assert!(
                !source.contains(foreign),
                "{name} must not contain {foreign}"
            );
        }
    }
    assert_eq!(sites, 1);
}

// WORK_UNIT_CASE: 638/10
#[test]
fn forbidden_import_delivery_use_authority_rejected() {
    for forbidden in eliot_context_compiler_wasm::FORBIDDEN_IMPORT_SUBSTRINGS {
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
        "model",
        "tool",
    ] {
        assert!(
            eliot_context_compiler_wasm::FORBIDDEN_IMPORT_SUBSTRINGS
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
        ("eliot:provider/model@0.1.0", "invoke"),
        ("eliot:tool/delivery@0.1.0", "deliver"),
    ] {
        let wasm = wat::parse_str(format!("(module (import \"{module}\" \"{name}\" (func)))"))
            .expect("capability fixture");
        let error = check_wasm_imports(&wasm).expect_err("forbidden import must fail");
        assert_eq!(
            error,
            eliot_context_compiler_wasm::DescriptorError::ForbiddenImport {
                module: module.into(),
                name: name.into(),
            }
        );
    }
    let benign =
        wat::parse_str("(module (func (export \"run\") (param i32) (result i32) local.get 0))")
            .expect("benign fixture");
    assert_eq!(list_wasm_imports(&benign).expect("imports"), vec![]);
    assert!(
        check_wasm_imports(&benign)
            .expect("benign passes")
            .is_empty()
    );
    assert!(check_wasm_imports(b"not a module").is_err());
    // Delivery/use/authority subtypes cannot be smuggled through the envelope.
    let (mut request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    for subtype in ["assembly", "delivery", "renderer", "provider", "model"] {
        request.handler_subtype = subtype.into();
        let ledger = CallLedger::new();
        let response = handle_with_ledger(&request, &ledger);
        assert_eq!(ledger.calls(), 0, "subtype {subtype} must not reach native");
        assert!(response.result.is_none());
    }
}

// WORK_UNIT_CASE: 638/11
#[test]
fn standalone_capsule_through_e_host() {
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };
    let (request, _) = guest_request(AdmissionMeasuredCost::ExactUtf8Bytes { value: 20 });
    let input = encode_request(&request).expect("encode");
    let invocation = InvocationRequest::new(
        InvocationId::new("fixture-638-capsule").expect("invocation"),
        CapabilityId::new("fixture-compiler-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-638").expect("work unit"),
        WorkScopeRef::new("fixture-scope-638").expect("scope"),
        ExecutionContour::Shadow,
        input,
        638,
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
        InvocationId::new("fixture-638-cancelled").expect("invocation"),
        CapabilityId::new("fixture-compiler-guest").expect("component"),
        WorkUnitId::new("fixture-work-unit-638").expect("work unit"),
        WorkScopeRef::new("fixture-scope-638").expect("scope"),
        ExecutionContour::Shadow,
        Vec::new(),
        638,
        true,
    )
    .expect("cancelled request");
    let result = runtime.execute(cancelled);
    assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
    assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
}

// WORK_UNIT_CASE: 638/12
#[test]
fn build_artifact_identity_and_admission_state() {
    assert_eq!(env!("CARGO_PKG_NAME"), "eliot-context-compiler-wasm");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    assert_eq!(descriptor_digest(), descriptor_digest());
    assert_eq!(GUEST_TARGET, "wasm32-wasip2");
    // Controller-owned handoff (issue #638): the package must NOT be a root
    // workspace member on this branch; admission is a separate serialized turn.
    assert!(!root_cargo_toml().contains("eliot-context-compiler-wasm"));
    // The manifest keeps the standalone shape: its own workspace table and a
    // cdylib target for the component build.
    let manifest = std::fs::read_to_string(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR")))
        .expect("package manifest");
    assert!(manifest.contains("crate-type = [\"cdylib\", \"rlib\"]"));
    assert!(manifest.contains("[workspace]"));
    // Frozen toolchain identity matches the owning file.
    let toolchain = String::from_utf8(eliot_context_compiler_wasm::TOOLCHAIN_BYTES.to_vec())
        .expect("toolchain UTF-8");
    assert!(toolchain.contains("channel = \"1.97.1\""));
    assert!(toolchain.contains("wasm32-wasip2"));
}

// WORK_UNIT_CASE: 638/13
#[test]
fn property_component_equals_native_membership_is_decision() {
    // Complete fit: small exact costs admit both atoms.
    let mut fitted = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    push_summary(
        &mut fitted,
        "digest-a",
        "summary content",
        5,
        AdmissionPriorityClass::Normal,
        2,
    );
    // Unknown measurement: explicit incomplete.
    let mut unknown = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 1 });
    unknown.measurements[0].cost = AdmissionMeasuredCost::Unknown;
    // Over-budget optional: reversible omission, floor still admitted.
    let mut over = input_with_optional(AdmissionMeasuredCost::ExactUtf8Bytes { value: 80 });
    make_handle_optional(&mut over);
    for input in [fitted, unknown, over] {
        let native = admit_context(&input).expect("native decides");
        let request = GuestRequest {
            abi_version: GUEST_ABI_VERSION,
            world: WORLD_NAME.to_owned(),
            handler_subtype: HANDLER_SUBTYPE.to_owned(),
            input: input.clone(),
        };
        let response = handle_request_typed(&request);
        assert!(response.error.is_none());
        let component = response.result.as_ref().expect("component decides");
        assert_eq!(*component, native);
        match (&component.outcome, &native.outcome) {
            (ContextOutcome::Complete(component_set), ContextOutcome::Complete(native_set)) => {
                let mut component_ids: Vec<_> = component_set
                    .records
                    .iter()
                    .map(|record| record.candidate.atom_id.clone())
                    .collect();
                let mut native_ids: Vec<_> = native_set
                    .records
                    .iter()
                    .map(|record| record.candidate.atom_id.clone())
                    .collect();
                component_ids.sort();
                native_ids.sort();
                assert_eq!(component_ids, native_ids);
                for record in &component_set.records {
                    let native_record = native_set
                        .records
                        .iter()
                        .find(|native| native.candidate.atom_id == record.candidate.atom_id)
                        .expect("native decides the same member");
                    assert_eq!(record.disposition, native_record.disposition);
                    assert_eq!(
                        record.candidate.representation.kind(),
                        native_record.candidate.representation.kind()
                    );
                    assert_eq!(
                        record.candidate.loss_policy,
                        native_record.candidate.loss_policy
                    );
                }
                assert_eq!(
                    component_set.economy.receipt_digest,
                    native_set.economy.receipt_digest
                );
            }
            (ContextOutcome::Incomplete(component_gap), ContextOutcome::Incomplete(native_gap)) => {
                assert_eq!(component_gap, native_gap);
                assert_eq!(
                    component_gap.code,
                    ContextErrorCode::DecisionContextIncomplete
                );
            }
            _ => panic!("component and native must agree on complete vs incomplete"),
        }
        // The response envelope carries no assembly/delivery/use surface.
        let json =
            String::from_utf8(encode_response(&response).expect("encode")).expect("response UTF-8");
        for absent in [
            "\"finish\"",
            "\"delivered\"",
            "\"assembled\"",
            "\"rendered\"",
            "\"executed_probe\"",
            "\"answer\"",
        ] {
            assert!(!json.contains(absent), "response must not raise {absent}");
        }
    }
}
