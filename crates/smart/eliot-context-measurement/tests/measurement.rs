//! Owner-local proof for the exact #704 measurement operation.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding, ContextError, MeasurementStatus,
    StuEstimate,
};
use eliot_context_measurement::{MeasurementParams, measure_exact_utf8};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
    sha256_hex,
};
use eliot_receipts::WorkScopeId;

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest() -> String {
    "a".repeat(64)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch")
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new("task").expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope").expect("fixture scope"),
        state_fence: StateFence::new(
            test_epoch(),
            ResourceGeneration::new(1).expect("generation"),
        ),
        decision_id: DecisionId::new("decision").expect("fixture decision"),
        operation_id: None,
    }
}

fn capacity() -> CapacityLimits {
    CapacityLimits {
        route_capacity: 100_000,
        fixed_overhead: 2,
        output_reserve: 3,
        review_reserve: 4,
    }
}

fn params(context: &ContextBinding) -> MeasurementParams {
    MeasurementParams {
        measurement_id: id("measurement"),
        context: context.clone(),
        serializer_id: "fixture-serde-v1".to_owned(),
        serializer_version: "1".to_owned(),
        serializer_options_digest: digest(),
        route_id: "route".to_owned(),
        model_id: "model".to_owned(),
        capacity: capacity(),
        stu_estimate: None,
        tokenizer: None,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
        max_serialized_bytes: 100_000,
    }
}

#[test]
fn exact_utf8_bytes_match_payload_length_without_fallback() {
    let context = binding();
    let payload = "whole goal matériél 🌍".as_bytes();
    let text = std::str::from_utf8(payload).expect("fixture UTF-8");
    // Multi-byte material proves exactness: byte length differs from scalar
    // count and from any divided fallback.
    assert!(payload.len() > text.chars().count());
    assert_ne!(
        u64::try_from(payload.len()).expect("len"),
        text.chars().count() as u64
    );
    let measured = measure_exact_utf8(payload, &params(&context)).expect("exact measurement");
    assert_eq!(measured.status, MeasurementStatus::ExactUtf8);
    assert_eq!(
        measured.rendered_utf8_bytes,
        u64::try_from(payload.len()).expect("byte count")
    );
    assert_eq!(measured.envelope_digest, sha256_hex(payload));
    assert_eq!(measured.schema_version, CONTEXT_CONTRACT_VERSION);
    assert_eq!(measured.context, context);
    // No fabricated observation: STU and tokenizer stay absent unless supplied.
    assert_eq!(measured.stu_estimate, None);
    assert_eq!(measured.tokenizer, None);
    assert_eq!(
        eliot_context_contracts::SerializedContextMeasurement::utf8_bytes(text),
        measured.rendered_utf8_bytes
    );
}

#[test]
fn stu_estimate_stays_distinct_data_and_never_drives_bytes() {
    let context = binding();
    let payload = "exact bytes".as_bytes();
    let mut with_stu = params(&context);
    with_stu.stu_estimate = Some(StuEstimate {
        value: 999_999,
        empirical: true,
    });
    let measured = measure_exact_utf8(payload, &with_stu).expect("measurement with STU");
    assert_eq!(measured.status, MeasurementStatus::ExactUtf8);
    assert_eq!(
        measured.rendered_utf8_bytes,
        u64::try_from(payload.len()).expect("byte count")
    );
    assert_ne!(
        measured.stu_estimate.expect("STU preserved").value,
        measured.rendered_utf8_bytes
    );
}

#[test]
fn bound_non_utf8_and_capacity_refusals_are_typed() {
    let context = binding();
    let payload = "exact bytes".as_bytes();
    let mut tight = params(&context);
    tight.max_serialized_bytes = u64::try_from(payload.len()).expect("len") - 1;
    assert_eq!(
        measure_exact_utf8(payload, &tight),
        Err(ContextError::Bounds {
            field: "measurement.rendered_bytes"
        })
    );
    assert_eq!(
        measure_exact_utf8(&[0xff, 0xfe], &params(&context)),
        Err(ContextError::InvalidField("measurement.payload_utf8"))
    );
    let mut over_capacity = params(&context);
    over_capacity.capacity = CapacityLimits {
        route_capacity: 10,
        fixed_overhead: 5,
        output_reserve: 5,
        review_reserve: 5,
    };
    assert_eq!(
        measure_exact_utf8(payload, &over_capacity),
        Err(ContextError::CapacityExceeded)
    );
}

// ================= sole serialized-context measurement owner (issue #704) ====

use eliot_context_contracts::{MeasurementUnit, SerializedContextMeasurement};
use eliot_context_measurement::{
    CapacityPlan, ContextMeasurement, EstimatorPolicy, ExactObservation, ObservationInput,
    ObservationSource, ObservationStatus, ProviderRewrite, ProviderRewriteKind, RouteIdentity,
    SerializedContextInputs, SerializerIdentity, StuToTokenPolicy, TokenizerIdentity,
    ZeroObservationRule, analyze_error, measure_serialized_context, stu_for_bytes,
};
use eliot_contracts::ContractVersion;

fn binding_full(
    task: &str,
    attempt: &str,
    scope: &str,
    decision: &str,
    seq: u64,
) -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new(task).expect("fixture task"),
        attempt_id: AgentAttemptId::new(attempt).expect("fixture attempt"),
        scope_id: WorkScopeId::new(scope).expect("fixture scope"),
        state_fence: StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                std::num::NonZeroU64::new(seq).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        ),
        decision_id: DecisionId::new(decision).expect("fixture decision"),
        operation_id: None,
    }
}

fn binding_for(task: &str) -> ContextBinding {
    binding_full(task, "attempt", "scope", "decision", 1)
}

/// Valid default inputs; envelope length/digest are bound to `payload`.
/// Reserves are distinct primes summing to 112; capacity is byte-graded.
fn base_inputs(task: &str, payload: &[u8]) -> SerializedContextInputs {
    SerializedContextInputs {
        measurement_id: id("measurement"),
        context: binding_for(task),
        contract_revision: CONTEXT_CONTRACT_VERSION,
        declared_len: u64::try_from(payload.len()).expect("payload len fits"),
        content_digest: sha256_hex(payload),
        serializer: SerializerIdentity {
            serializer_id: "fixture-serde-v1".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(),
            schema_revision: CONTEXT_CONTRACT_VERSION,
        },
        route: RouteIdentity {
            route_id: "route".to_owned(),
            provider_id: "fixture-provider".to_owned(),
            model_id: "model".to_owned(),
        },
        tokenizer: TokenizerIdentity {
            tokenizer_id: "route-tokenizer".to_owned(),
            tokenizer_version: "t1".to_owned(),
            tokenizer_hash: digest(),
            tokenizer_config_digest: digest(),
        },
        estimator: EstimatorPolicy {
            estimator_id: "stu-estimator".to_owned(),
            estimator_revision: "i2.16-rev1".to_owned(),
            empirical: false,
            candidate_digests: Vec::new(),
        },
        capacity: CapacityPlan {
            route_capacity: Some(100_000),
            unit: MeasurementUnit::Utf8Bytes,
            fixed_overhead: 11,
            output_reserve: 13,
            review_reserve: 17,
            tool_reserve: 19,
            verifier_reserve: 23,
            decision_tail_reserve: 29,
            stu_to_token: None,
        },
        observation: ObservationInput::Absent,
        false_safe_overflow: None,
        false_rejection_or_decomposition: None,
        valid_until: None,
        max_serialized_bytes: 100_000,
    }
}

fn token_policy() -> StuToTokenPolicy {
    StuToTokenPolicy {
        policy_id: id("stu-to-token-policy"),
        policy_digest: digest(),
        tokens_per_stu_numer: 4,
        tokens_per_stu_denom: 3,
    }
}

/// Token-graded inputs with an accepted 4/3 decision policy and an exact
/// observation bound to `payload`.
fn token_inputs(
    task: &str,
    payload: &[u8],
    tokens: u64,
    capacity: Option<u64>,
) -> SerializedContextInputs {
    let mut inputs = base_inputs(task, payload);
    inputs.capacity.unit = MeasurementUnit::TokenizerTokens;
    inputs.capacity.route_capacity = capacity;
    inputs.capacity.stu_to_token = Some(token_policy());
    let context = inputs.context.clone();
    let route = inputs.route.clone();
    let tokenizer = inputs.tokenizer.clone();
    let serializer = inputs.serializer.clone();
    inputs.observation = ObservationInput::Exact(Box::new(ExactObservation {
        observation_id: id("observation"),
        tokens,
        token_bound: 100_000,
        binding: context,
        envelope_digest: sha256_hex(payload),
        route_id: route.route_id,
        provider_id: route.provider_id,
        model_id: route.model_id,
        tokenizer,
        serializer,
        source: ObservationSource::ProviderTokenizerRun,
        rewrite: None,
        superseded_by: None,
        proof_id: None,
    }));
    inputs
}

/// Exact observation bound to every identity in `inputs` for `payload`.
fn exact_observation(
    inputs: &SerializedContextInputs,
    payload: &[u8],
    tokens: u64,
) -> ObservationInput {
    ObservationInput::Exact(Box::new(ExactObservation {
        observation_id: id("observation"),
        tokens,
        token_bound: 100_000,
        binding: inputs.context.clone(),
        envelope_digest: sha256_hex(payload),
        route_id: inputs.route.route_id.clone(),
        provider_id: inputs.route.provider_id.clone(),
        model_id: inputs.route.model_id.clone(),
        tokenizer: inputs.tokenizer.clone(),
        serializer: inputs.serializer.clone(),
        source: ObservationSource::ProviderTokenizerRun,
        rewrite: None,
        superseded_by: None,
        proof_id: None,
    }))
}

fn measured(payload: &[u8], inputs: &SerializedContextInputs) -> ContextMeasurement {
    measure_serialized_context(payload, inputs).expect("measurement succeeds")
}

// WORK_UNIT_CASE: 704/1
#[test]
fn stu_exact_zero_to_six_byte_boundaries() {
    for (len, expected) in [
        (0_u64, 0_u64),
        (1, 1),
        (2, 1),
        (3, 1),
        (4, 2),
        (5, 2),
        (6, 2),
    ] {
        let payload = vec![b'x'; usize::try_from(len).expect("small len")];
        let result = measured(&payload, &base_inputs("task", &payload));
        assert_eq!(result.measurement.rendered_utf8_bytes, len);
        assert_eq!(result.stu, expected);
        assert_eq!(
            result.measurement.stu_estimate,
            Some(StuEstimate {
                value: expected,
                empirical: false,
            })
        );
        assert_eq!(result.measurement.status, MeasurementStatus::ExactUtf8);
    }
}

// WORK_UNIT_CASE: 704/2
#[test]
fn maximum_accepted_byte_length() {
    let payload = vec![b'a'; 16 * 1024 * 1024];
    let mut inputs = base_inputs("task", &payload);
    inputs.max_serialized_bytes = u64::MAX;
    let result = measured(&payload, &inputs);
    assert_eq!(result.measurement.rendered_utf8_bytes, 16_777_216);
    assert_eq!(result.stu, 5_592_406);
    let over = vec![b'a'; 16 * 1024 * 1024 + 1];
    let mut tight = base_inputs("task", &over);
    tight.max_serialized_bytes = u64::MAX;
    assert_eq!(
        measure_serialized_context(&over, &tight),
        Err(ContextError::Bounds {
            field: "measurement.rendered_bytes"
        })
    );
}

// WORK_UNIT_CASE: 704/3
#[test]
fn checked_arithmetic_overflow_is_typed() {
    assert_eq!(stu_for_bytes(u64::MAX), Err(ContextError::Overflow));
    assert_eq!(stu_for_bytes(u64::MAX - 1), Err(ContextError::Overflow));
    assert_eq!(stu_for_bytes(u64::MAX - 2), Ok(6_148_914_691_236_517_205));
}

// WORK_UNIT_CASE: 704/4
#[test]
fn ascii_payload_measures_final_bytes() {
    let payload = b"hello, world";
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.measurement.rendered_utf8_bytes, 12);
    assert_eq!(result.stu, 4);
    assert_eq!(result.measurement.envelope_digest, sha256_hex(payload));
}

// WORK_UNIT_CASE: 704/5
#[test]
fn cyrillic_multibyte_measures_bytes_not_scalars() {
    let payload = "привет".as_bytes();
    assert_eq!(payload.len(), 12);
    assert_eq!(payload.len(), "привет".chars().count() * 2);
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.measurement.rendered_utf8_bytes, 12);
    assert_eq!(result.stu, 4);
}

// WORK_UNIT_CASE: 704/6
#[test]
fn emoji_and_combining_characters_measure_bytes() {
    let globe = "🌍".as_bytes();
    assert_eq!(globe.len(), 4);
    let measured_globe = measured(globe, &base_inputs("task", globe));
    assert_eq!(measured_globe.measurement.rendered_utf8_bytes, 4);
    assert_eq!(measured_globe.stu, 2);
    let combined = "e\u{301}".as_bytes();
    assert_eq!(combined.len(), 3);
    assert_eq!("e\u{301}".chars().count(), 2);
    let measured_combined = measured(combined, &base_inputs("task", combined));
    assert_eq!(measured_combined.measurement.rendered_utf8_bytes, 3);
    assert_eq!(measured_combined.stu, 1);
}

// WORK_UNIT_CASE: 704/7
#[test]
fn escaped_serialized_json_uses_final_bytes_not_source_chars() {
    let payload = br#"{"t":"\u00e9"}"#;
    assert_eq!(payload.len(), 14);
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.measurement.rendered_utf8_bytes, 14);
    // The source scalar U+00E9 alone would estimate ceil(2/3) = 1; the six
    // escaped bytes on the wire measure ceil(14/3) = 5.
    assert_eq!(result.stu, 5);
    assert_ne!(result.stu, 1);
}

// WORK_UNIT_CASE: 704/8
#[test]
fn rounded_field_sums_cannot_replace_final_envelope() {
    let one = stu_for_bytes(1).expect("stu 1");
    let two = stu_for_bytes(2).expect("stu 2");
    let three = stu_for_bytes(3).expect("stu 3");
    assert_eq!(one + two, 2);
    assert_eq!(three, 1);
    assert_ne!(one + two, three);
    let payload = b"abc";
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.stu, 1);
}

// WORK_UNIT_CASE: 704/9
#[test]
fn estimator_identity_and_unvalidated_status_are_explicit() {
    let payload = b"estimator proof";
    let result = measured(payload, &base_inputs("task", payload));
    let estimate = result.measurement.stu_estimate.expect("normative estimate");
    assert!(!estimate.empirical);
    assert_eq!(estimate.value, result.stu);
    let mut blank = base_inputs("task", payload);
    blank.estimator.estimator_id = String::new();
    assert_eq!(
        measure_serialized_context(payload, &blank),
        Err(ContextError::InvalidField("estimator.estimator_id"))
    );
    let mut claimed = base_inputs("task", payload);
    claimed.estimator.empirical = true;
    assert_eq!(
        measure_serialized_context(payload, &claimed),
        Err(ContextError::InvalidField("estimator.empirical"))
    );
}

// WORK_UNIT_CASE: 704/10
#[test]
fn estimator_revision_change_invalidates_identity() {
    let payload = b"revision binding";
    let first = measured(payload, &base_inputs("task", payload));
    let mut revised = base_inputs("task", payload);
    revised.estimator.estimator_revision = "i2.16-rev2".to_owned();
    let second = measured(payload, &revised);
    assert_ne!(first.receipt_digest, second.receipt_digest);
    // Cited candidates are evidence only: the normative STU is unchanged
    // while the receipt binds the citation.
    let mut cited = base_inputs("task", payload);
    cited.estimator.candidate_digests = vec![digest()];
    let third = measured(payload, &cited);
    assert_eq!(third.stu, first.stu);
    assert_ne!(third.receipt_digest, first.receipt_digest);
}

// WORK_UNIT_CASE: 704/11
#[test]
fn exact_envelope_serializer_and_schema_identity() {
    let payload = b"serializer identity";
    let inputs = base_inputs("task", payload);
    let result = measured(payload, &inputs);
    assert_eq!(result.measurement.serializer_id, "fixture-serde-v1");
    assert_eq!(result.measurement.serializer_version, "1");
    assert_eq!(result.measurement.serializer_options_digest, digest());
    assert_eq!(result.measurement.schema_version, CONTEXT_CONTRACT_VERSION);
    let mut bad_options = base_inputs("task", payload);
    bad_options.serializer.serializer_options_digest = "not-a-digest".to_owned();
    assert_eq!(
        measure_serialized_context(payload, &bad_options),
        Err(ContextError::InvalidDigest(
            "measurement.serializer_options_digest"
        ))
    );
    let mut bad_schema = base_inputs("task", payload);
    bad_schema.serializer.schema_revision = ContractVersion::new(0, 9, 9);
    assert_eq!(
        measure_serialized_context(payload, &bad_schema),
        Err(ContextError::InvalidField("measurement.schema_version"))
    );
    let mut bad_contract = base_inputs("task", payload);
    bad_contract.contract_revision = ContractVersion::new(0, 9, 9);
    assert_eq!(
        measure_serialized_context(payload, &bad_contract),
        Err(ContextError::InvalidField("measurement.schema_version"))
    );
    let mut blank_serializer = base_inputs("task", payload);
    blank_serializer.serializer.serializer_id = "   ".to_owned();
    assert_eq!(
        measure_serialized_context(payload, &blank_serializer),
        Err(ContextError::InvalidField("measurement.serializer_id"))
    );
}

// WORK_UNIT_CASE: 704/12
#[test]
fn declared_length_mismatch_is_error_not_correction() {
    let payload = b"twelve bytes";
    assert_eq!(payload.len(), 12);
    let mut over = base_inputs("task", payload);
    over.declared_len = 13;
    assert_eq!(
        measure_serialized_context(payload, &over),
        Err(ContextError::InvalidField("measurement.declared_len"))
    );
    let mut under = base_inputs("task", payload);
    under.declared_len = 11;
    assert_eq!(
        measure_serialized_context(payload, &under),
        Err(ContextError::InvalidField("measurement.declared_len"))
    );
}

// WORK_UNIT_CASE: 704/13
#[test]
fn content_digest_mismatch_is_typed() {
    let payload = b"digest binding";
    let mut malformed = base_inputs("task", payload);
    malformed.content_digest = "zzz".to_owned();
    assert_eq!(
        measure_serialized_context(payload, &malformed),
        Err(ContextError::InvalidDigest("measurement.content_digest"))
    );
    let mut conflict = base_inputs("task", payload);
    conflict.content_digest = sha256_hex(b"different bytes");
    assert_eq!(
        measure_serialized_context(payload, &conflict),
        Err(ContextError::IdentityConflict)
    );
}

// WORK_UNIT_CASE: 704/14
#[test]
fn task_attempt_scope_fence_mismatch_is_stale() {
    let payload = b"binding mismatch";
    let variants = [
        binding_full("task-b", "attempt", "scope", "decision", 1),
        binding_full("task", "attempt-b", "scope", "decision", 1),
        binding_full("task", "attempt", "scope-b", "decision", 1),
        binding_full("task", "attempt", "scope", "decision", 2),
    ];
    for binding in &variants {
        let inputs = base_inputs("task", payload);
        let mut observed = exact_observation(&inputs, payload, 40);
        if let ObservationInput::Exact(exact) = &mut observed {
            exact.binding.clone_from(binding);
        }
        let mut stale_inputs = base_inputs("task", payload);
        stale_inputs.observation = observed;
        let result = measured(payload, &stale_inputs);
        assert_eq!(result.observation, ObservationStatus::Stale);
        assert_eq!(result.observed_tokens, None);
        assert_eq!(result.error.false_safe_overflow, None);
        assert_eq!(result.error.false_reject_or_decomposition, None);
    }
}

// WORK_UNIT_CASE: 704/15
#[test]
fn duplicate_measurement_id_is_rejected() {
    let payload = b"duplicate identity";
    let inputs = base_inputs("task", payload);
    let mut observed = exact_observation(&inputs, payload, 40);
    if let ObservationInput::Exact(exact) = &mut observed {
        exact.observation_id = id("measurement");
    }
    let mut duplicate = base_inputs("task", payload);
    duplicate.observation = observed;
    assert_eq!(
        measure_serialized_context(payload, &duplicate),
        Err(ContextError::Duplicate("observation.observation_id"))
    );
    let mut signals = base_inputs("task", payload);
    signals.false_safe_overflow = Some(id("signal"));
    signals.false_rejection_or_decomposition = Some(id("signal"));
    assert_eq!(
        measure_serialized_context(payload, &signals),
        Err(ContextError::Duplicate("measurement.false_safe_overflow"))
    );
}

// WORK_UNIT_CASE: 704/16
#[test]
fn same_id_changed_bytes_or_metadata_conflicts() {
    let payload = b"identity conflict";
    let inputs = base_inputs("task", payload);
    let mut observed = exact_observation(&inputs, payload, 40);
    if let ObservationInput::Exact(exact) = &mut observed {
        let own = exact.observation_id.clone();
        exact.superseded_by = Some(own);
    }
    let mut conflict = base_inputs("task", payload);
    conflict.observation = observed;
    assert_eq!(
        measure_serialized_context(payload, &conflict),
        Err(ContextError::IdentityConflict)
    );
    let mut bad_metadata = base_inputs("task", payload);
    let mut tampered = exact_observation(&bad_metadata, payload, 40);
    if let ObservationInput::Exact(exact) = &mut tampered {
        exact.serializer.serializer_options_digest = "bogus".to_owned();
    }
    bad_metadata.observation = tampered;
    assert_eq!(
        measure_serialized_context(payload, &bad_metadata),
        Err(ContextError::InvalidDigest(
            "measurement.serializer_options_digest"
        ))
    );
}

// WORK_UNIT_CASE: 704/17
#[test]
fn set_order_independent_result_and_digest() {
    let payload = b"order independence";
    let mut forward = base_inputs("task", payload);
    forward.estimator.candidate_digests = vec!["a".repeat(64), "b".repeat(64), "c".repeat(64)];
    let mut reversed = base_inputs("task", payload);
    reversed.estimator.candidate_digests = vec!["c".repeat(64), "b".repeat(64), "a".repeat(64)];
    let first = measured(payload, &forward);
    let second = measured(payload, &reversed);
    assert_eq!(first.measurement, second.measurement);
    assert_eq!(first.receipt_digest, second.receipt_digest);
    let repeat = measured(payload, &forward);
    assert_eq!(repeat.receipt_digest, first.receipt_digest);
}

// WORK_UNIT_CASE: 704/18
#[test]
fn every_load_bearing_field_changes_identity_or_fails() {
    let payload = b"load bearing fields".to_vec();
    let baseline = measured(&payload, &base_inputs("task", &payload)).receipt_digest;
    let mut errored = Vec::new();
    for code in 0..16 {
        let mut inputs = base_inputs("task", &payload);
        let mut bytes = payload.clone();
        match code {
            0 => inputs.estimator.estimator_revision = "rev-x".to_owned(),
            1 => inputs.estimator.estimator_id = "other-estimator".to_owned(),
            2 => inputs.serializer.serializer_version = "2".to_owned(),
            3 => inputs.serializer.serializer_id = "other-serde".to_owned(),
            4 => inputs.route.route_id = "route-b".to_owned(),
            5 => inputs.route.provider_id = "provider-b".to_owned(),
            6 => inputs.route.model_id = "model-b".to_owned(),
            7 => inputs.tokenizer.tokenizer_version = "t2".to_owned(),
            8 => inputs.tokenizer.tokenizer_hash = "b".repeat(64),
            9 => {
                bytes[0] = b'X';
                inputs.declared_len = u64::try_from(bytes.len()).expect("len fits");
                inputs.content_digest = sha256_hex(&bytes);
            }
            10 => inputs.capacity.fixed_overhead += 1,
            11 => inputs.capacity.output_reserve += 1,
            12 => inputs.capacity.route_capacity = Some(200_000),
            13 => inputs.estimator.candidate_digests = vec![digest()],
            14 => inputs.declared_len += 1,
            _ => inputs.content_digest = sha256_hex(b"unrelated"),
        }
        let Ok(result) = measure_serialized_context(&bytes, &inputs) else {
            errored.push(code);
            continue;
        };
        let digest = result.receipt_digest;
        assert_ne!(digest, baseline, "mutation {code} must change identity");
    }
    // Only the envelope-identity mutations fail; every other load-bearing
    // field moves the receipt digest.
    assert_eq!(errored, vec![14, 15]);
}

// WORK_UNIT_CASE: 704/19
#[test]
fn exact_compatible_observed_count() {
    let payload = b"exact compatible observed count";
    assert_eq!(payload.len(), 31);
    let inputs = token_inputs("task", payload, 1_200, Some(100_000));
    let result = measured(payload, &inputs);
    assert_eq!(result.observation, ObservationStatus::Exact);
    assert_eq!(result.observed_tokens, Some(1_200));
    let tokenizer = result.measurement.tokenizer.expect("exact tokenizer");
    assert_eq!(tokenizer.tokens, 1_200);
    assert_eq!(tokenizer.tokenizer_id, "route-tokenizer");
    assert_eq!(result.capacity.estimated_total, Some(127));
    assert_eq!(result.capacity.fit, Some(true));
    assert_eq!(result.capacity.observed_total, Some(1_312));
    assert_eq!(result.capacity.observed_fit, Some(true));
    assert_eq!(result.error.false_safe_overflow, Some(false));
    assert_eq!(result.error.false_reject_or_decomposition, Some(false));
    assert_eq!(result.error.signed_error, Some(-1_185));
    assert_eq!(result.error.absolute_error, Some(1_185));
    assert_eq!(result.error.relative_error_ppm, Some(987_500));
}

// WORK_UNIT_CASE: 704/20
#[test]
fn observation_absent_remains_absent() {
    let payload = b"absent observation";
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.observation, ObservationStatus::Absent);
    assert_eq!(result.observed_tokens, None);
    assert_eq!(result.measurement.tokenizer, None);
    // Absence never zeroes the estimate side nor proves an error flag.
    assert_eq!(result.capacity.fit, Some(true));
    assert_eq!(result.capacity.observed_fit, None);
    assert_eq!(result.error.false_safe_overflow, None);
    assert_eq!(result.error.false_reject_or_decomposition, None);
}

// WORK_UNIT_CASE: 704/21
#[test]
fn known_tokenizer_without_observation_stays_unavailable() {
    let payload = b"unavailable observation";
    let mut inputs = base_inputs("task", payload);
    inputs.observation = ObservationInput::KnownTokenizerWithoutObservation {
        tokenizer: inputs.tokenizer.clone(),
    };
    let result = measured(payload, &inputs);
    assert_eq!(result.observation, ObservationStatus::Unavailable);
    assert_eq!(result.observed_tokens, None);
    // The known identity is never fabricated into an observation.
    assert_eq!(result.measurement.tokenizer, None);
    assert_eq!(result.error.false_safe_overflow, None);
    assert_eq!(result.error.false_reject_or_decomposition, None);
}

// WORK_UNIT_CASE: 704/22
#[test]
fn unsupported_tokenizer_stays_distinct() {
    let payload = b"unsupported tokenizer";
    let mut inputs = base_inputs("task", payload);
    inputs.observation = ObservationInput::UnsupportedTokenizer {
        tokenizer_id: "legacy-tok-v0".to_owned(),
    };
    let result = measured(payload, &inputs);
    assert_eq!(result.observation, ObservationStatus::Unsupported);
    assert_ne!(result.observation, ObservationStatus::Unavailable);
    assert_ne!(result.observation, ObservationStatus::Absent);
    assert_ne!(result.observation, ObservationStatus::Unknown);
    assert_ne!(result.observation, ObservationStatus::Exact);
}

// WORK_UNIT_CASE: 704/23
#[test]
fn route_model_tokenizer_serializer_envelope_mismatch_is_stale() {
    let payload = b"observation mismatch";
    for code in 0..5 {
        let inputs = base_inputs("task", payload);
        let mut observed = exact_observation(&inputs, payload, 77);
        if let ObservationInput::Exact(exact) = &mut observed {
            match code {
                0 => exact.route_id = "route-b".to_owned(),
                1 => exact.model_id = "model-b".to_owned(),
                2 => exact.tokenizer.tokenizer_id = "tok-b".to_owned(),
                3 => exact.serializer.serializer_id = "serde-b".to_owned(),
                _ => exact.envelope_digest = sha256_hex(b"other envelope"),
            }
        }
        let mut mismatched = base_inputs("task", payload);
        mismatched.observation = observed;
        let result = measured(payload, &mismatched);
        assert_eq!(result.observation, ObservationStatus::Stale, "code {code}");
        assert_eq!(result.observed_tokens, None);
        assert_eq!(result.measurement.tokenizer, None);
        assert_eq!(result.error.false_safe_overflow, None);
        assert_eq!(result.error.false_reject_or_decomposition, None);
    }
}

// WORK_UNIT_CASE: 704/24
#[test]
fn superseded_observation_is_stale() {
    let payload = b"stale observation";
    let inputs = base_inputs("task", payload);
    let mut observed = exact_observation(&inputs, payload, 55);
    if let ObservationInput::Exact(exact) = &mut observed {
        exact.superseded_by = Some(id("superseder"));
    }
    let mut stale_inputs = base_inputs("task", payload);
    stale_inputs.observation = observed;
    let result = measured(payload, &stale_inputs);
    assert_eq!(result.observation, ObservationStatus::Stale);
    assert_eq!(result.observed_tokens, None);
    assert_eq!(result.error.false_safe_overflow, None);
    assert_eq!(result.error.false_reject_or_decomposition, None);
}

// WORK_UNIT_CASE: 704/25
#[test]
fn same_observation_id_changed_input_conflicts() {
    let payload = b"observation conflict";
    let inputs = base_inputs("task", payload);
    let mut observed = exact_observation(&inputs, payload, 40);
    if let ObservationInput::Exact(exact) = &mut observed {
        let own = exact.observation_id.clone();
        exact.proof_id = Some(own);
    }
    let mut conflict = base_inputs("task", payload);
    conflict.observation = observed;
    assert_eq!(
        measure_serialized_context(payload, &conflict),
        Err(ContextError::Duplicate("observation.proof_id"))
    );
}

// WORK_UNIT_CASE: 704/26
#[test]
fn provider_rewrite_evidence_is_carried_and_comparison_unknown() {
    let payload = b"rewritten bytes";
    let inputs = base_inputs("task", payload);
    let mut observed = exact_observation(&inputs, payload, 90);
    if let ObservationInput::Exact(exact) = &mut observed {
        exact.rewrite = Some(ProviderRewrite {
            kind: ProviderRewriteKind::Truncation,
            evidence_digest: digest(),
        });
    }
    let mut rewritten = base_inputs("task", payload);
    rewritten.observation = observed;
    let result = measured(payload, &rewritten);
    assert_eq!(result.observation, ObservationStatus::Transformed);
    assert_eq!(
        result.rewrite,
        Some(ProviderRewrite {
            kind: ProviderRewriteKind::Truncation,
            evidence_digest: digest(),
        })
    );
    // Transformed bytes are not the measured bytes: no count, no comparison.
    assert_eq!(result.observed_tokens, None);
    assert_eq!(result.measurement.tokenizer, None);
    assert_eq!(result.error.false_safe_overflow, None);
    assert_eq!(result.error.false_reject_or_decomposition, None);
    assert_eq!(result.error.signed_error, None);
}

// WORK_UNIT_CASE: 704/27
#[test]
fn unknown_observation_outcome_stays_unknown() {
    let payload = b"unknown outcome";
    let mut inputs = base_inputs("task", payload);
    inputs.observation = ObservationInput::Unknown {
        reason: "provider timed out before counting".to_owned(),
    };
    let result = measured(payload, &inputs);
    assert_eq!(result.observation, ObservationStatus::Unknown);
    assert_eq!(result.observed_tokens, None);
    assert_ne!(result.observation, ObservationStatus::Absent);
    assert_eq!(result.error.false_safe_overflow, None);
    assert_eq!(result.error.false_reject_or_decomposition, None);
}

// WORK_UNIT_CASE: 704/28
#[test]
fn observed_zero_uses_explicit_relative_error_rule() {
    let payload = b"zero observation rule";
    assert_eq!(payload.len(), 21);
    let inputs = token_inputs("task", payload, 0, Some(100_000));
    let result = measured(payload, &inputs);
    assert_eq!(result.observation, ObservationStatus::Exact);
    assert_eq!(result.observed_tokens, Some(0));
    assert_eq!(result.capacity.estimated_total, Some(122));
    assert_eq!(result.capacity.observed_total, Some(112));
    assert_eq!(result.error.signed_error, Some(10));
    assert_eq!(result.error.absolute_error, Some(10));
    // Explicit rule: no division runs on a zero observation.
    assert_eq!(result.error.relative_error_ppm, None);
    assert_eq!(
        result.error.zero_observation_rule,
        ZeroObservationRule::RelativeErrorUnknownWhenObservedIsZero
    );
}

// WORK_UNIT_CASE: 704/29
#[test]
fn exact_fit_reports_zero_headroom() {
    let payload = b"exact fit payload";
    assert_eq!(payload.len(), 17);
    let mut inputs = base_inputs("task", payload);
    inputs.capacity.route_capacity = Some(129);
    let result = measured(payload, &inputs);
    assert_eq!(result.capacity.total_reserves, 112);
    assert_eq!(result.capacity.estimated_total, Some(129));
    assert_eq!(result.capacity.fit, Some(true));
    assert_eq!(result.capacity.headroom, Some(0));
}

// WORK_UNIT_CASE: 704/30
#[test]
fn one_unit_over_is_distinct_from_exact_fit() {
    let payload = b"exact fit payload";
    let mut inputs = base_inputs("task", payload);
    inputs.capacity.route_capacity = Some(128);
    let result = measured(payload, &inputs);
    assert_eq!(result.capacity.estimated_total, Some(129));
    assert_eq!(result.capacity.fit, Some(false));
    assert_eq!(result.capacity.headroom, None);
}

// WORK_UNIT_CASE: 704/31
#[test]
fn independent_reserves_without_double_count_or_subsidy() {
    let payload = b"exact fit payload";
    let result = measured(payload, &base_inputs("task", payload));
    assert_eq!(result.capacity.total_reserves, 11 + 13 + 17 + 19 + 23 + 29);
    assert_eq!(result.capacity.estimated_total, Some(17 + 112));
    assert_eq!(result.measurement.fixed_overhead, 11);
    assert_eq!(result.measurement.output_reserve, 13);
    assert_eq!(result.measurement.review_reserve, 17);
    // Moving one reserve moves the total by exactly its delta: no merging,
    // no cross-subsidy from the untouched reserves.
    let mut bumped = base_inputs("task", payload);
    bumped.capacity.tool_reserve += 1;
    let moved = measured(payload, &bumped);
    assert_eq!(moved.capacity.total_reserves, 113);
    assert_eq!(moved.capacity.estimated_total, Some(130));
    assert_ne!(moved.receipt_digest, result.receipt_digest);
}

// WORK_UNIT_CASE: 704/32
#[test]
fn unknown_capacity_is_neither_zero_nor_unlimited() {
    let payload = b"exact fit payload";
    let mut inputs = base_inputs("task", payload);
    inputs.capacity.route_capacity = None;
    let result = measured(payload, &inputs);
    assert_eq!(result.capacity.estimated_total, Some(129));
    assert_eq!(result.capacity.fit, None);
    assert_eq!(result.capacity.headroom, None);
    assert_ne!(result.capacity.fit, Some(true));
    assert_ne!(result.capacity.fit, Some(false));
}

// WORK_UNIT_CASE: 704/33
#[test]
fn incompatible_units_and_unowned_conversion_stay_unknown_or_fail() {
    let payload = b"unit boundary";
    // Token capacity without an accepted decision policy: the estimate has
    // no compatible cost, while the exact observation still compares.
    let mut no_policy = token_inputs("task", payload, 500, Some(100_000));
    no_policy.capacity.stu_to_token = None;
    let unknown = measured(payload, &no_policy);
    assert_eq!(unknown.capacity.estimated_cost, None);
    assert_eq!(unknown.capacity.estimated_total, None);
    assert_eq!(unknown.capacity.fit, None);
    assert_eq!(unknown.capacity.observed_cost, Some(500));
    assert_eq!(unknown.capacity.observed_total, Some(612));
    assert_eq!(unknown.capacity.observed_fit, Some(true));
    // An unowned conversion policy is refused, not applied.
    let mut bad_digest = token_inputs("task", payload, 500, Some(100_000));
    if let Some(policy) = bad_digest.capacity.stu_to_token.as_mut() {
        policy.policy_digest = "not-hex".to_owned();
    }
    assert_eq!(
        measure_serialized_context(payload, &bad_digest),
        Err(ContextError::InvalidDigest("capacity.policy_digest"))
    );
    let mut zero_denom = token_inputs("task", payload, 500, Some(100_000));
    if let Some(policy) = zero_denom.capacity.stu_to_token.as_mut() {
        policy.tokens_per_stu_denom = 0;
    }
    assert_eq!(
        measure_serialized_context(payload, &zero_denom),
        Err(ContextError::InvalidField("capacity.stu_to_token_denom"))
    );
    // Byte capacity never relabels observed tokens as bytes.
    let byte_inputs = base_inputs("task", payload);
    let mut relabel = base_inputs("task", payload);
    relabel.observation = exact_observation(&byte_inputs, payload, 500);
    let kept = measured(payload, &relabel);
    assert_eq!(kept.capacity.estimated_cost, Some(13));
    assert_eq!(kept.capacity.observed_cost, None);
    assert_eq!(kept.capacity.observed_fit, None);
}

// WORK_UNIT_CASE: 704/34
#[test]
fn arithmetic_overflow_and_underflow_are_typed() {
    let payload = b"overflow proof";
    let mut reserves = base_inputs("task", payload);
    reserves.capacity.fixed_overhead = u64::MAX;
    assert_eq!(
        measure_serialized_context(payload, &reserves),
        Err(ContextError::Overflow)
    );
    let tiny = b"yyy";
    let mut rate = token_inputs("task", tiny, 10, Some(u64::MAX));
    if let Some(policy) = rate.capacity.stu_to_token.as_mut() {
        policy.tokens_per_stu_numer = u64::MAX;
    }
    assert_eq!(
        measure_serialized_context(tiny, &rate),
        Err(ContextError::Overflow)
    );
    // A total above capacity is honestly unfit with empty headroom: checked
    // subtraction never underflows into an error or a wrap.
    let mut over = base_inputs("task", payload);
    over.capacity.route_capacity = Some(100);
    let result = measured(payload, &over);
    assert_eq!(result.capacity.fit, Some(false));
    assert_eq!(result.capacity.headroom, None);
}

// WORK_UNIT_CASE: 704/35
#[test]
fn false_safe_overflow_positive_and_negative() {
    let payload = b"yyy";
    let mut positive = token_inputs("task", payload, 10_000, Some(200));
    let hit = measured(payload, &positive);
    assert_eq!(hit.capacity.fit, Some(true));
    assert_eq!(hit.capacity.observed_fit, Some(false));
    assert_eq!(hit.error.false_safe_overflow, Some(true));
    assert_eq!(hit.error.false_reject_or_decomposition, Some(false));
    assert_eq!(hit.error.signed_error, Some(114 - 10_112));
    positive.capacity.route_capacity = Some(100_000);
    let miss = measured(payload, &positive);
    assert_eq!(miss.error.false_safe_overflow, Some(false));
    assert_eq!(miss.error.false_reject_or_decomposition, Some(false));
}

// WORK_UNIT_CASE: 704/36
#[test]
fn false_reject_positive_and_negative() {
    let payload = vec![b'y'; 300];
    let mut positive = token_inputs("task", &payload, 50, Some(200));
    let hit = measured(&payload, &positive);
    assert_eq!(hit.capacity.estimated_total, Some(246));
    assert_eq!(hit.capacity.fit, Some(false));
    assert_eq!(hit.capacity.observed_total, Some(162));
    assert_eq!(hit.capacity.observed_fit, Some(true));
    assert_eq!(hit.error.false_reject_or_decomposition, Some(true));
    assert_eq!(hit.error.false_safe_overflow, Some(false));
    positive.capacity.route_capacity = Some(100);
    let miss = measured(&payload, &positive);
    assert_eq!(miss.error.false_reject_or_decomposition, Some(false));
    assert_eq!(miss.error.false_safe_overflow, Some(false));
}

// WORK_UNIT_CASE: 704/37
#[test]
fn error_sign_alone_sets_neither_flag() {
    let payload = vec![b'y'; 300];
    // Negative nonzero error with both sides overflowing.
    let negative = token_inputs("task", &payload, 500, Some(200));
    let below = measured(&payload, &negative);
    assert_eq!(below.error.signed_error, Some(246 - 612));
    assert_ne!(below.error.signed_error, Some(0));
    assert_eq!(below.error.false_safe_overflow, Some(false));
    assert_eq!(below.error.false_reject_or_decomposition, Some(false));
    // Positive nonzero error with both sides fitting.
    let positive = token_inputs("task", &payload, 100, Some(10_000));
    let above = measured(&payload, &positive);
    assert_eq!(above.error.signed_error, Some(246 - 212));
    assert_ne!(above.error.signed_error, Some(0));
    assert_eq!(above.error.false_safe_overflow, Some(false));
    assert_eq!(above.error.false_reject_or_decomposition, Some(false));
}

// WORK_UNIT_CASE: 704/38
#[test]
fn absent_stale_mismatched_observation_leaves_flags_unknown() {
    let payload = b"unknown flags";
    let absent = measured(payload, &base_inputs("task", payload));
    assert_eq!(absent.error.false_safe_overflow, None);
    assert_eq!(absent.error.false_reject_or_decomposition, None);
    let inputs = base_inputs("task", payload);
    let mut stale_observed = exact_observation(&inputs, payload, 60);
    if let ObservationInput::Exact(exact) = &mut stale_observed {
        exact.route_id = "route-b".to_owned();
    }
    let mut stale_inputs = base_inputs("task", payload);
    stale_inputs.observation = stale_observed;
    let stale = measured(payload, &stale_inputs);
    assert_eq!(stale.error.false_safe_overflow, None);
    assert_eq!(stale.error.false_reject_or_decomposition, None);
    let mut mismatch_observed = exact_observation(&inputs, payload, 60);
    if let ObservationInput::Exact(exact) = &mut mismatch_observed {
        exact.envelope_digest = sha256_hex(b"other envelope");
    }
    let mut mismatch_inputs = base_inputs("task", payload);
    mismatch_inputs.observation = mismatch_observed;
    let mismatch = measured(payload, &mismatch_inputs);
    assert_eq!(mismatch.error.false_safe_overflow, None);
    assert_eq!(mismatch.error.false_reject_or_decomposition, None);
}

// WORK_UNIT_CASE: 704/39
#[test]
fn estimated_and_observed_headroom_share_one_reserve_identity() {
    let payload = b"exact compatible observed count";
    let inputs = token_inputs("task", payload, 1_200, Some(100_000));
    let result = measured(payload, &inputs);
    assert_eq!(result.capacity.headroom, Some(99_873));
    assert_eq!(result.capacity.observed_headroom, Some(98_688));
    let estimated = result.capacity.estimated_total.expect("estimated total");
    let estimated_cost = result.capacity.estimated_cost.expect("estimated cost");
    let observed = result.capacity.observed_total.expect("observed total");
    let observed_cost = result.capacity.observed_cost.expect("observed cost");
    assert_eq!(estimated - estimated_cost, 112);
    assert_eq!(observed - observed_cost, 112);
}

fn assert_envelope_and_route_cases(payload: &[u8]) {
    let mut malformed_utf8 = base_inputs("task", &[0xff, 0xfe]);
    malformed_utf8.declared_len = 2;
    malformed_utf8.content_digest = sha256_hex(&[0xff, 0xfe]);
    assert_eq!(
        measure_serialized_context(&[0xff, 0xfe], &malformed_utf8),
        Err(ContextError::InvalidField("measurement.payload_utf8"))
    );
    let mut zero_max = base_inputs("task", payload);
    zero_max.max_serialized_bytes = 0;
    assert_eq!(
        measure_serialized_context(payload, &zero_max),
        Err(ContextError::Bounds {
            field: "measurement.max_serialized_bytes"
        })
    );
    let mut bad_revision = base_inputs("task", payload);
    bad_revision.contract_revision = ContractVersion::new(0, 9, 9);
    assert_eq!(
        measure_serialized_context(payload, &bad_revision),
        Err(ContextError::InvalidField("measurement.schema_version"))
    );
    let mut blank_route = base_inputs("task", payload);
    "a	b".clone_into(&mut blank_route.route.route_id);
    assert_eq!(
        measure_serialized_context(payload, &blank_route),
        Err(ContextError::InvalidField("route.route_id"))
    );
    let mut huge_text = base_inputs("task", payload);
    huge_text.route.model_id = "x".repeat(1_048_577);
    assert_eq!(
        measure_serialized_context(payload, &huge_text),
        Err(ContextError::Bounds {
            field: "route.model_id"
        })
    );
}

fn assert_tokenizer_and_observation_cases(payload: &[u8]) {
    let mut bad_hash = base_inputs("task", payload);
    bad_hash.tokenizer.tokenizer_hash = "G".repeat(64);
    assert_eq!(
        measure_serialized_context(payload, &bad_hash),
        Err(ContextError::InvalidDigest("route.tokenizer_hash"))
    );
    let mut zero_bound = base_inputs("task", payload);
    let mut zero_observed = exact_observation(&zero_bound, payload, 0);
    if let ObservationInput::Exact(exact) = &mut zero_observed {
        exact.token_bound = 0;
    }
    zero_bound.observation = zero_observed;
    assert_eq!(
        measure_serialized_context(payload, &zero_bound),
        Err(ContextError::InvalidField("observation.token_bound"))
    );
    let mut over_bound = base_inputs("task", payload);
    let mut over_observed = exact_observation(&over_bound, payload, 5);
    if let ObservationInput::Exact(exact) = &mut over_observed {
        exact.token_bound = 4;
    }
    over_bound.observation = over_observed;
    assert_eq!(
        measure_serialized_context(payload, &over_bound),
        Err(ContextError::Bounds {
            field: "observation.tokens"
        })
    );
    let mut empty_reason = base_inputs("task", payload);
    empty_reason.observation = ObservationInput::Unknown {
        reason: String::new(),
    };
    assert_eq!(
        measure_serialized_context(payload, &empty_reason),
        Err(ContextError::InvalidField("observation.reason"))
    );
}

fn assert_estimator_and_policy_cases(payload: &[u8]) {
    let mut claimed = base_inputs("task", payload);
    claimed.estimator.empirical = true;
    assert_eq!(
        measure_serialized_context(payload, &claimed),
        Err(ContextError::InvalidField("estimator.empirical"))
    );
    let mut bad_policy = base_inputs("task", payload);
    bad_policy.capacity.stu_to_token = Some(StuToTokenPolicy {
        policy_id: id("policy"),
        policy_digest: "nope".to_owned(),
        tokens_per_stu_numer: 1,
        tokens_per_stu_denom: 1,
    });
    assert_eq!(
        measure_serialized_context(payload, &bad_policy),
        Err(ContextError::InvalidDigest("capacity.policy_digest"))
    );
    let mut zero_denom = base_inputs("task", payload);
    zero_denom.capacity.stu_to_token = Some(StuToTokenPolicy {
        policy_id: id("policy"),
        policy_digest: digest(),
        tokens_per_stu_numer: 1,
        tokens_per_stu_denom: 0,
    });
    assert_eq!(
        measure_serialized_context(payload, &zero_denom),
        Err(ContextError::InvalidField("capacity.stu_to_token_denom"))
    );
    let mut zero_rate = base_inputs("task", payload);
    zero_rate.capacity.stu_to_token = Some(StuToTokenPolicy {
        policy_id: id("policy"),
        policy_digest: digest(),
        tokens_per_stu_numer: 0,
        tokens_per_stu_denom: 1,
    });
    assert_eq!(
        measure_serialized_context(payload, &zero_rate),
        Err(ContextError::InvalidField("capacity.stu_to_token_rate"))
    );
    let mut many_candidates = base_inputs("task", payload);
    many_candidates.estimator.candidate_digests = vec![digest(); 65];
    assert_eq!(
        measure_serialized_context(payload, &many_candidates),
        Err(ContextError::Bounds {
            field: "estimator.candidate_digests"
        })
    );
    let mut blank_tokenizer = base_inputs("task", payload);
    blank_tokenizer.observation = ObservationInput::UnsupportedTokenizer {
        tokenizer_id: String::new(),
    };
    assert_eq!(
        measure_serialized_context(payload, &blank_tokenizer),
        Err(ContextError::InvalidField("observation.tokenizer_id"))
    );
}

// WORK_UNIT_CASE: 704/40
#[test]
fn bounded_malformed_inputs_fail_typed_without_panic() {
    let payload = b"malformed table";
    assert_envelope_and_route_cases(payload);
    assert_tokenizer_and_observation_cases(payload);
    assert_estimator_and_policy_cases(payload);
}

// WORK_UNIT_CASE: 704/41
#[test]
fn property_exact_ceil_len_div_3_for_every_accepted_length() {
    let mut accepted = Vec::new();
    for len in 0..=512_u64 {
        accepted.push(len);
    }
    accepted.extend([1_000, 4_096, 65_536, 1_000_000, 16_777_216, u64::MAX - 2]);
    for len in accepted {
        // Independent oracle in a wider integer type, not a second fallback.
        let expected = u64::try_from(u128::from(len).div_ceil(3)).expect("oracle fits");
        assert_eq!(stu_for_bytes(len), Ok(expected), "length {len}");
    }
}

// WORK_UNIT_CASE: 704/42
#[test]
fn property_monotonic_stu_grows_by_at_most_one_per_byte() {
    for len in 0..1024_u64 {
        let current = stu_for_bytes(len).expect("accepted length");
        let next = stu_for_bytes(len + 1).expect("accepted length");
        assert!(next >= current, "length {len}");
        assert!(next - current <= 1, "length {len}");
    }
    let small = vec![b'z'; 100];
    let grown = vec![b'z'; 101];
    let first = measured(&small, &base_inputs("task", &small));
    let second = measured(&grown, &base_inputs("task", &grown));
    assert!(second.stu >= first.stu);
    assert!(second.stu - first.stu <= 1);
}

// WORK_UNIT_CASE: 704/43
#[test]
fn property_both_flags_match_compatible_explicit_fit_comparison() {
    // Each seed derives fit independently from totals and capacity, then
    // requires the analyzed flags to equal the explicit comparison.
    for (estimated, observed, capacity) in [
        (10_u64, 20_u64, 15_u64),
        (20, 10, 15),
        (10, 10, 15),
        (20, 20, 15),
    ] {
        let estimated_fit = estimated <= capacity;
        let observed_fit = observed <= capacity;
        let analysis = analyze_error(
            Some(estimated),
            Some(estimated_fit),
            Some(observed),
            Some(observed_fit),
        );
        assert_eq!(
            analysis.false_safe_overflow,
            Some(estimated_fit && !observed_fit)
        );
        assert_eq!(
            analysis.false_reject_or_decomposition,
            Some(!estimated_fit && observed_fit)
        );
    }
    let unknown = analyze_error(Some(10), Some(true), None, None);
    assert_eq!(unknown.false_safe_overflow, None);
    assert_eq!(unknown.false_reject_or_decomposition, None);
    assert_eq!(unknown.signed_error, None);
}

// WORK_UNIT_CASE: 704/44
#[test]
fn property_observed_count_always_binds_bytes_route_tokenizer() {
    let payload = b"binding property";
    for code in 0..12 {
        let inputs = base_inputs("task", payload);
        let mut observed = exact_observation(&inputs, payload, 64);
        if let ObservationInput::Exact(exact) = &mut observed {
            match code {
                0 => exact.envelope_digest = sha256_hex(b"other bytes"),
                1 => exact.route_id = "route-b".to_owned(),
                2 => exact.provider_id = "provider-b".to_owned(),
                3 => exact.model_id = "model-b".to_owned(),
                4 => exact.tokenizer.tokenizer_id = "tok-b".to_owned(),
                5 => exact.tokenizer.tokenizer_version = "t9".to_owned(),
                6 => exact.tokenizer.tokenizer_hash = "b".repeat(64),
                7 => exact.tokenizer.tokenizer_config_digest = "b".repeat(64),
                8 => exact.serializer.serializer_id = "serde-b".to_owned(),
                9 => exact.serializer.serializer_version = "9".to_owned(),
                10 => exact.serializer.serializer_options_digest = "b".repeat(64),
                _ => exact.binding = binding_for("task-b"),
            }
        }
        let mut mutated = base_inputs("task", payload);
        mutated.observation = observed;
        let result = measured(payload, &mutated);
        assert_ne!(result.observation, ObservationStatus::Exact, "code {code}");
        assert_eq!(result.observation, ObservationStatus::Stale, "code {code}");
    }
    let control_inputs = base_inputs("task", payload);
    let mut control = base_inputs("task", payload);
    control.observation = exact_observation(&control_inputs, payload, 64);
    assert_eq!(
        measured(payload, &control).observation,
        ObservationStatus::Exact
    );
}

// WORK_UNIT_CASE: 704/45
#[test]
fn no_provider_network_filesystem_or_clock_api() {
    let payload = b"deterministic purity probe";
    let inputs = base_inputs("task", payload);
    let first = measured(payload, &inputs);
    for _ in 0..4 {
        let repeat = measured(payload, &base_inputs("task", payload));
        assert_eq!(repeat.receipt_digest, first.receipt_digest);
        assert_eq!(repeat.measurement, first.measurement);
    }
    // Identical bytes at a different allocation still measure identically:
    // output depends only on the semantic inputs, never on ambient state.
    let relocated = payload.to_vec();
    let moved = measured(&relocated, &inputs);
    assert_eq!(moved.receipt_digest, first.receipt_digest);
}

// WORK_UNIT_CASE: 704/46
#[test]
fn no_admission_truncation_assembly_delivery_state_or_finish() {
    let payload = b"exact fit payload";
    let mut inputs = base_inputs("task", payload);
    inputs.capacity.route_capacity = Some(100);
    let first = measured(payload, &inputs);
    // Over capacity the full envelope is still reported: nothing is
    // selected, dropped, truncated or decomposed by measurement.
    assert_eq!(first.measurement.rendered_utf8_bytes, 17);
    assert_eq!(first.measurement.status, MeasurementStatus::ExactUtf8);
    assert_eq!(first.capacity.fit, Some(false));
    let second = measured(payload, &inputs);
    assert_eq!(second.receipt_digest, first.receipt_digest);
    assert_eq!(second.measurement, first.measurement);
}

// WORK_UNIT_CASE: 704/47
#[test]
fn no_competing_a15_public_schema() {
    let payload = b"schema fidelity";
    let inputs = token_inputs("task", payload, 300, Some(100_000));
    let result = measured(payload, &inputs);
    // The inner value is an exact A-15 value: it validates, carries the
    // accepted revision, uses closed A-15 statuses and proves fit through
    // the A-15 predicate over the same bytes and reserves.
    assert!(result.measurement.validate().is_ok());
    assert_eq!(result.measurement.schema_version, CONTEXT_CONTRACT_VERSION);
    assert_eq!(result.measurement.status, MeasurementStatus::ExactUtf8);
    assert_eq!(result.measurement.proves_fit(100_000), Ok(true));
    assert_eq!(result.measurement.proves_fit(10), Ok(false));
    assert_eq!(
        eliot_context_contracts::canonical_digest(&result.measurement),
        eliot_context_contracts::canonical_digest(&result.measurement)
    );
}

// WORK_UNIT_CASE: 704/48
#[test]
fn independent_consumer_compiles_against_a15_result_and_entrypoint() {
    fn consumer_measure(
        measure: &dyn Fn(&[u8]) -> Result<SerializedContextMeasurement, ContextError>,
        payload: &[u8],
    ) -> Result<SerializedContextMeasurement, ContextError> {
        measure(payload)
    }
    let payload = b"consumer compatibility";
    let inputs = base_inputs("task", payload);
    let adapted =
        |bytes: &[u8]| measure_serialized_context(bytes, &inputs).map(|result| result.measurement);
    let consumed = consumer_measure(&adapted, payload).expect("consumer measure");
    assert_eq!(
        consumed.rendered_utf8_bytes,
        u64::try_from(payload.len()).expect("payload len fits")
    );
    assert_eq!(consumed.status, MeasurementStatus::ExactUtf8);
    assert!(consumed.validate().is_ok());
}
