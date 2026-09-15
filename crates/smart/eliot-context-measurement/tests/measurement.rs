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
        state_fence: StateFence::new(test_epoch(), ResourceGeneration::new(1).expect("generation")),
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
    assert_ne!(u64::try_from(payload.len()).expect("len"), text.chars().count() as u64);
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
