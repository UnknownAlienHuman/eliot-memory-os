//! Issue #939 (`F-DENY-T10`): closed protected decoders for the four owned
//! `eliot-types` files (`skill.rs`, `lifecycle.rs`, `eval.rs`, `metrics.rs`).
//!
//! Invalid input must not create Skill/run/revision identity, complete sample
//! coverage, measured benefit, execution evidence or authority. Every case
//! below drives a real decode path; none of them constructs the protected
//! record directly to make a refusal look like a pass. Named raw-byte
//! fixtures live in `tests/serde_t10_skill_eval.json`; adversarial payloads
//! that must survive fixture loading intact (duplicate keys, malformed
//! bytes) are stored as JSON strings.
//!
//! Cases 1-2 cover allocation and byte stability, 3-4 unknown outer/nested
//! protected fields, 5-6 duplicate keys and unknown tags, 7-8 missing
//! protected meaning and version/tag selection, 9-10 named legacy defaults
//! versus unsafe absence, 11-12 `Value`/map paths and zero-sample or unknown
//! never becoming measured, 13-14 source-change invalidation and
//! panic-free bounded input, 15 the decoder refusing before trusted output,
//! and 16 the untouched lifecycle/evaluation/metric algorithms.

#![allow(clippy::expect_used)]

use eliot_types::{
    EvalBaseline, EvalCaseResult, EvalIntegrityFingerprintSet, MetricSample, MetricSeries,
    SkillLifecycleRecord,
};
use serde_json::{Map, Value};

fn corpus() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("serde_t10_skill_eval.json");
    let text = std::fs::read_to_string(&path).expect("serde_t10_skill_eval.json must exist");
    serde_json::from_str(&text).expect("serde_t10_skill_eval.json must be valid JSON")
}

fn case(name: &str) -> Value {
    corpus()
        .get(name)
        .unwrap_or_else(|| panic!("corpus must contain case {name}"))
        .clone()
}

fn raw_case(name: &str) -> String {
    case(name)
        .as_str()
        .unwrap_or_else(|| panic!("corpus case {name} must be a raw JSON string"))
        .to_owned()
}

fn object(value: &Value) -> Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("fixture must be a JSON object"))
        .clone()
}

fn with_extra(value: &Value, key: &str, extra: Value) -> Value {
    let mut map = object(value);
    map.insert(key.to_owned(), extra);
    Value::Object(map)
}

fn without(value: &Value, key: &str) -> Value {
    let mut map = object(value);
    assert!(
        map.remove(key).is_some(),
        "fixture must contain {key} for this mutation"
    );
    Value::Object(map)
}

fn nested<'a>(value: &'a Value, pointer: &'a str) -> &'a Value {
    value
        .pointer(pointer)
        .unwrap_or_else(|| panic!("fixture must contain nested pointer {pointer}"))
}

const PRODUCT: &str =
    "eliot-memory-os/eliot-engine-eval:product:01920000-0000-7000-8000-000000000001";

// WORK_UNIT_CASE: 939/1
// Cases 1-2: exact four-file/type allocation. Every public record in the four
// owned files must be a closed decoder, so the finite type denominator this
// issue accepts cannot silently grow an open member.
#[test]
fn every_owned_record_in_the_four_files_is_a_closed_decoder() {
    let mut total = 0usize;
    for file in ["skill.rs", "lifecycle.rs", "eval.rs", "metrics.rs"] {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("owned file {file} must be readable: {error}"));
        let lines: Vec<&str> = source.lines().collect();
        let mut open = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("pub struct ") {
                continue;
            }
            let name = trimmed
                .trim_start_matches("pub struct ")
                .split(['<', '(', '{', ';', ':', ' '])
                .next()
                .unwrap_or_default()
                .to_owned();
            let start = index.saturating_sub(8);
            let attributes = lines[start..=index].join("\n");
            if !attributes.contains("deny_unknown_fields") {
                open.push(name);
            }
        }
        assert!(
            open.is_empty(),
            "{file} owns open (unknown-field absorbing) records: {open:?}"
        );
        total += lines
            .iter()
            .filter(|line| line.trim_start().starts_with("pub struct "))
            .count();
    }
    assert!(
        total >= 100,
        "the accepted denominator is four files with over 100 owned records, found {total}"
    );
}

// WORK_UNIT_CASE: 939/2
// Cases 1-2: valid current canonical bytes are unchanged. A closed decoder
// must not alter accepted bytes: every owned record round-trips byte stably
// and a re-decode of those bytes reproduces the identical value.
#[test]
fn valid_current_canonical_bytes_round_trip_byte_stably() {
    let record: SkillLifecycleRecord =
        serde_json::from_value(case("skill_lifecycle_record_accept")).expect("accept fixture");
    let bytes = serde_json::to_vec(&record).expect("record must serialize");
    let again: SkillLifecycleRecord = serde_json::from_slice(&bytes).expect("bytes must re-decode");
    assert_eq!(record, again, "canonical bytes must be byte stable");
    assert_eq!(
        serde_json::to_vec(&again).expect("re-serialize"),
        bytes,
        "re-serialization must reproduce the identical byte sequence"
    );

    let sample: MetricSample =
        serde_json::from_value(case("metric_sample_accept")).expect("metric accept fixture");
    let sample_bytes = serde_json::to_vec(&sample).expect("sample must serialize");
    assert_eq!(
        serde_json::from_slice::<MetricSample>(&sample_bytes).expect("sample re-decode"),
        sample
    );

    let result: EvalCaseResult =
        serde_json::from_value(case("eval_case_result_accept")).expect("eval accept fixture");
    let result_bytes = serde_json::to_vec(&result).expect("result must serialize");
    assert_eq!(
        serde_json::from_slice::<EvalCaseResult>(&result_bytes).expect("result re-decode"),
        result
    );
    assert_eq!(
        result
            .integrity_fingerprints
            .as_ref()
            .map(|fingerprints| fingerprints.product_identity.as_str()),
        Some(PRODUCT),
        "accepted product identity bytes must survive the closed decoder unchanged"
    );
}

// WORK_UNIT_CASE: 939/3
// Cases 3-4: an unknown protected OUTER field rejects before typed output.
#[test]
fn unknown_outer_protected_fields_reject() {
    let record = with_extra(
        &case("skill_lifecycle_record_accept"),
        "verified_by_owner",
        Value::Bool(true),
    );
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(record).is_err(),
        "an added outer lifecycle field must not be silently dropped"
    );

    let sample = with_extra(
        &case("metric_sample_accept"),
        "measured_tokens",
        Value::from(4096),
    );
    assert!(
        serde_json::from_value::<MetricSample>(sample).is_err(),
        "an added outer metric field must not be silently dropped"
    );

    let result = with_extra(
        &case("eval_case_result_accept"),
        "grants_authority",
        Value::Bool(true),
    );
    assert!(
        serde_json::from_value::<EvalCaseResult>(result).is_err(),
        "an added outer evaluation field must not be silently dropped"
    );

    let baseline = with_extra(&case("eval_baseline_accept"), "approved", Value::Bool(true));
    assert!(
        serde_json::from_value::<EvalBaseline>(baseline).is_err(),
        "an added outer baseline field must not be silently dropped"
    );
}

// WORK_UNIT_CASE: 939/4
// Cases 3-4: an unknown protected NESTED field rejects through the real
// container decode paths, not only by constructing the nested record alone.
#[test]
fn unknown_nested_protected_fields_reject_through_container_paths() {
    let fingerprints = with_extra(
        &case("nine_field_accept"),
        "evaluator_tier",
        Value::String("gold".to_owned()),
    );

    let result = case("eval_case_result_accept");
    let mut result_map = object(&result);
    result_map.insert("integrity_fingerprints".to_owned(), fingerprints.clone());
    assert!(
        serde_json::from_value::<EvalCaseResult>(Value::Object(result_map)).is_err(),
        "EvalCaseResult must refuse an unknown nested identity dimension"
    );

    let baseline = case("eval_baseline_accept");
    let mut baseline_map = object(&baseline);
    baseline_map.insert("integrity_fingerprints".to_owned(), fingerprints.clone());
    assert!(
        serde_json::from_value::<EvalBaseline>(Value::Object(baseline_map)).is_err(),
        "EvalBaseline must refuse an unknown nested identity dimension"
    );

    // Positive control through the same two container paths: the same payload
    // without the unrecognized dimension decodes and keeps the nine fields.
    let accepted = case("nine_field_accept");
    let mut ok_result = object(&case("eval_case_result_accept"));
    ok_result.insert("integrity_fingerprints".to_owned(), accepted.clone());
    let decoded: EvalCaseResult = serde_json::from_value(Value::Object(ok_result))
        .expect("nine known nested fields must decode through EvalCaseResult");
    assert_eq!(
        decoded
            .integrity_fingerprints
            .as_ref()
            .map(|fingerprints| fingerprints.oracle_owner.as_str()),
        Some("eliot_engine::eval::EvalMeasurementService"),
        "the accepted nested record must survive the container decode intact"
    );

    let mut ok_baseline = object(&case("eval_baseline_accept"));
    ok_baseline.insert("integrity_fingerprints".to_owned(), accepted);
    let decoded: EvalBaseline =
        serde_json::from_value(Value::Object(ok_baseline)).expect("baseline nested decode");
    assert!(decoded.integrity_fingerprints.is_some());

    // Nested scope rule and nested metric label are protected too.
    let record = case("skill_lifecycle_record_accept");
    let poisoned_rule = with_extra(
        &nested(&record, "/where_applies/0").clone(),
        "required_authority",
        Value::String("owner-1".to_owned()),
    );
    let mut record_map = object(&record);
    record_map.insert(
        "where_applies".to_owned(),
        Value::Array(vec![poisoned_rule.clone()]),
    );
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(Value::Object(record_map.clone())).is_err(),
        "a nested SkillScopeRule with an added field must be refused"
    );

    // Positive control on the same nested path: the unmodified nested rule
    // still decodes, so the refusal above is caused by the added field alone.
    record_map.insert(
        "where_applies".to_owned(),
        Value::Array(vec![
            nested(&case("skill_lifecycle_record_accept"), "/where_applies/0").clone(),
        ]),
    );
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(Value::Object(record_map)).is_ok(),
        "the accepted nested scope rule must still decode"
    );

    let sample = case("metric_sample_accept");
    let label = with_extra(
        &nested(&sample, "/labels/0").clone(),
        "redaction_verified",
        Value::Bool(true),
    );
    let mut sample_map = object(&sample);
    sample_map.insert("labels".to_owned(), Value::Array(vec![label]));
    assert!(
        serde_json::from_value::<MetricSample>(Value::Object(sample_map)).is_err(),
        "a nested MetricLabel with an added field must be refused"
    );
}

// WORK_UNIT_CASE: 939/5
// Cases 5-6: duplicate Skill/revision/identity/cursor keys reject on raw bytes,
// before any map insertion can collapse them.
#[test]
fn duplicate_identity_and_nested_keys_reject_on_raw_bytes() {
    assert!(
        serde_json::from_str::<SkillLifecycleRecord>(&raw_case(
            "raw_skill_record_duplicate_identity_key"
        ))
        .is_err(),
        "a duplicated outer identity key must be refused, not last-write-wins"
    );
    assert!(
        serde_json::from_str::<SkillLifecycleRecord>(&raw_case(
            "raw_skill_record_duplicate_nested_key"
        ))
        .is_err(),
        "a duplicated nested scope-rule key must be refused"
    );
    assert!(
        serde_json::from_str::<MetricSample>(&raw_case("raw_metric_sample_duplicate_metric_key"))
            .is_err(),
        "a duplicated metric identity key must be refused"
    );
    assert!(
        serde_json::from_str::<EvalCaseResult>(&raw_case(
            "raw_eval_case_result_duplicate_nested_fingerprint_key"
        ))
        .is_err(),
        "a duplicated nested fingerprint identity key must be refused"
    );
}

// WORK_UNIT_CASE: 939/6
// Cases 5-6: unknown control tags and misselected payloads reject instead of
// defaulting into a valid current value.
#[test]
fn unknown_control_tags_and_wrong_payload_shapes_reject() {
    let record = case("skill_lifecycle_record_accept");
    for tag in ["ACTIVE", "promoted", "", "Active"] {
        let wrong = with_extra(&record.clone(), "state", Value::String(tag.to_owned()));
        assert!(
            serde_json::from_value::<SkillLifecycleRecord>(wrong).is_err(),
            "lifecycle state {tag:?} is not a declared wire tag and must be refused"
        );
    }
    let result = case("eval_case_result_accept");
    for tag in ["Understand", "UNDERSTAND", ""] {
        let wrong = with_extra(&result.clone(), "family", Value::String(tag.to_owned()));
        assert!(
            serde_json::from_value::<EvalCaseResult>(wrong).is_err(),
            "eval family {tag:?} is not a declared wire tag and must be refused"
        );
    }
    for tag in ["Passed", "PASS", ""] {
        let wrong = with_extra(&result.clone(), "status", Value::String(tag.to_owned()));
        assert!(
            serde_json::from_value::<EvalCaseResult>(wrong).is_err(),
            "eval case status {tag:?} is not a declared snake_case wire tag and must be refused"
        );
    }
    // The declared snake_case tag is the only accepted spelling.
    assert!(
        serde_json::from_value::<EvalCaseResult>(result.clone()).is_ok(),
        "the declared snake_case tags must keep decoding"
    );
    // A misselected payload: an object where a string is declared, and a list
    // where a record is declared.
    let sample = case("metric_sample_accept");
    let wrong = with_extra(
        &sample.clone(),
        "metric_id",
        Value::Array(vec![Value::Bool(true)]),
    );
    assert!(
        serde_json::from_value::<MetricSample>(wrong).is_err(),
        "a misselected payload shape must be refused"
    );
    let wrong = with_extra(&sample, "integrity_fingerprints", Value::Array(vec![]));
    assert!(
        serde_json::from_value::<EvalCaseResult>(wrong).is_err(),
        "a list where a nested fingerprint record is declared must be refused"
    );
}

// WORK_UNIT_CASE: 939/7
// Cases 7-8: missing protected identity cannot become a valid current record.
// Absence of an owned identity field is a refusal, never an empty identity.
#[test]
fn missing_protected_identity_refuses() {
    for key in [
        "record_id",
        "skill_ref",
        "state",
        "created_at",
        "promotion_evidence",
    ] {
        let mutated = without(&case("skill_lifecycle_record_accept"), key);
        assert!(
            serde_json::from_value::<SkillLifecycleRecord>(mutated).is_err(),
            "a lifecycle record without protected field {key} must be refused"
        );
    }
    for key in ["sample_id", "metric_id", "value", "observed_at"] {
        let mutated = without(&case("metric_sample_accept"), key);
        assert!(
            serde_json::from_value::<MetricSample>(mutated).is_err(),
            "a metric sample without protected field {key} must be refused"
        );
    }
    for key in ["result_id", "eval_case_id", "family", "duration_ms"] {
        let mutated = without(&case("eval_case_result_accept"), key);
        assert!(
            serde_json::from_value::<EvalCaseResult>(mutated).is_err(),
            "an eval case result without protected field {key} must be refused"
        );
    }
    // An empty string is not an identity either.
    let empty = with_extra(
        &case("skill_lifecycle_record_accept"),
        "skill_ref",
        Value::String(String::new()),
    );
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(empty).is_err(),
        "an empty Skill identity must not decode as a valid current record"
    );
}

// WORK_UNIT_CASE: 939/8
// Cases 7-8: unsupported or misselected versions cannot default into valid
// current values. These owned records carry no version field of their own, so
// their compatibility boundary is the enclosing closed record: an added
// version discriminator is an unknown protected field, and a legacy-shaped
// tag is not accepted as the current tag.
#[test]
fn unsupported_versions_and_legacy_tags_cannot_default_into_current_values() {
    for key in ["version", "schema_version", "wire_version", "revision"] {
        let mutated = with_extra(&case("skill_lifecycle_record_accept"), key, Value::from(2));
        assert!(
            serde_json::from_value::<SkillLifecycleRecord>(mutated).is_err(),
            "an added {key} discriminator must not be absorbed as a current value"
        );
    }
    // A numeric version where the declared tag is a string.
    let mutated = with_extra(&case("eval_case_result_accept"), "status", Value::from(1));
    assert!(
        serde_json::from_value::<EvalCaseResult>(mutated).is_err(),
        "a misselected version type must be refused, not coerced"
    );
    // Out-of-range unit-bearing values are refused by the declared type.
    let mutated = with_extra(
        &case("metric_series_zero_samples_accept"),
        "rollups",
        Value::Array(vec![serde_json::json!({
            "rollup_id": "r-1",
            "metric_id": "metric-latency",
            "window": "one_minute",
            "count": 1,
            "min": 1.0,
            "max": 1.0,
            "avg": 1.0,
            "p50": 1.0,
            "p95": 1.0,
            "p99": 1.0,
            "started_at": "2026-10-04T09:00:00Z",
            "ended_at": "2026-10-04T09:01:00Z"
        })]),
    );
    let series: MetricSeries =
        serde_json::from_value(mutated).expect("a declared snake_case window tag must decode");
    assert_eq!(
        series.rollups.len(),
        1,
        "the accepted window tag must decode"
    );
}

// WORK_UNIT_CASE: 939/9
// Cases 9-10: the explicitly declared historical defaults preserve their
// documented absence. A payload predating the additive reference vectors and
// the promotion outcome decodes to empty/None, never to synthesized evidence.
#[test]
fn named_legacy_defaults_preserve_declared_absence() {
    let record: SkillLifecycleRecord =
        serde_json::from_value(case("skill_lifecycle_record_legacy_defaults"))
            .expect("a historic lifecycle payload must still decode");
    assert!(
        record.source_case_refs.is_empty()
            && record.source_pattern_refs.is_empty()
            && record.mechanism_refs.is_empty()
            && record.local_check_refs.is_empty()
            && record.transfer_evidence_refs.is_empty()
            && record.holdout_evidence_refs.is_empty()
            && record.negative_transfer_refs.is_empty(),
        "absent historical reference vectors must stay empty, never be invented"
    );
    assert_eq!(
        record.promotion_outcome, None,
        "an absent historical promotion outcome must stay unknown, never default to a value"
    );
    assert_eq!(record.rollback_ref, None);
    assert_eq!(record.write_receipt, None);
    assert_eq!(record.context_cost, None);
    assert_eq!(record.last_verified, None);

    let result: EvalCaseResult = serde_json::from_value(case("eval_case_result_legacy_defaults"))
        .expect("a historic eval payload must still decode");
    let fingerprints = result
        .integrity_fingerprints
        .expect("the historic nested record itself is present");
    assert_eq!(
        fingerprints.oracle_version, "",
        "a payload predating oracle_version decodes empty and therefore stale"
    );
    assert_eq!(fingerprints.product_identity, "");
    let current = EvalIntegrityFingerprintSet {
        oracle_version: "0.1.0".to_owned(),
        product_identity: PRODUCT.to_owned(),
        ..fingerprints.clone()
    };
    assert!(
        fingerprints.is_stale_against(&current),
        "empty historic defaults must compare stale against current nonempty identity"
    );
}

// WORK_UNIT_CASE: 939/10
// Cases 9-10: an unsafe migration that drops protected meaning still refuses.
// Preserved legacy absence is limited to the fields that are actually
// declared optional; a payload that loses protected identity is refused even
// though it otherwise looks historic.
#[test]
fn unsafe_migration_missing_protected_meaning_refuses() {
    let legacy = case("skill_lifecycle_record_legacy_defaults");
    let without_skill_ref = without(&legacy.clone(), "skill_ref");
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(without_skill_ref).is_err(),
        "declared optional references do not extend to the Skill identity"
    );
    let without_created = without(&legacy, "created_at");
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(without_created).is_err(),
        "declared optional references do not extend to the durable creation time"
    );
    // The declared optional surface stops at the top level: a nested owned
    // record loses no protection because its container was historic.
    let mut map = object(&case("skill_lifecycle_record_legacy_defaults"));
    map.insert(
        "where_applies".to_owned(),
        Value::Array(vec![without(
            &nested(&case("skill_lifecycle_record_accept"), "/where_applies/0").clone(),
            "rule_id",
        )]),
    );
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(Value::Object(map)).is_err(),
        "a nested scope rule without its identity must be refused even in a historic payload"
    );
}

// WORK_UNIT_CASE: 939/11
// Cases 11-12: a `Value`/map normalization path cannot absorb a control field.
// Round-tripping through an untyped `Value` and re-injecting an unrecognized
// key must still be refused by the typed decoder, because the decoder is the
// authority and never trusts a normalized map.
#[test]
fn value_and_map_paths_cannot_absorb_control_fields() {
    let record: SkillLifecycleRecord =
        serde_json::from_value(case("skill_lifecycle_record_accept")).expect("accept fixture");
    let mut normalized = serde_json::to_value(&record).expect("normalize to Value");
    let map = normalized
        .as_object_mut()
        .expect("normalized record is an object");
    map.insert("verified_by_owner".to_owned(), Value::Bool(true));
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(normalized).is_err(),
        "a control field added through a Value path must still be refused"
    );

    let mut nested_map = serde_json::to_value(&record).expect("normalize again");
    let applies = nested_map
        .get_mut("where_applies")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(Value::as_object_mut)
        .expect("first scope rule is an object");
    applies.insert("grants_authority".to_owned(), Value::Bool(true));
    assert!(
        serde_json::from_value::<SkillLifecycleRecord>(nested_map).is_err(),
        "a control field added to a nested Value map must still be refused"
    );

    // The same holds for the evaluation container.
    let result: EvalCaseResult =
        serde_json::from_value(case("eval_case_result_accept")).expect("accept fixture");
    let mut normalized = serde_json::to_value(&result).expect("normalize result");
    normalized
        .as_object_mut()
        .expect("normalized result is an object")
        .insert("mutates_current_truth".to_owned(), Value::Bool(true));
    assert!(
        serde_json::from_value::<EvalCaseResult>(normalized).is_err(),
        "an authority canary added through a Value path must still be refused"
    );
}

// WORK_UNIT_CASE: 939/12
// Cases 11-12: zero samples and unknown never become passed, active or
// measured. An empty series carries no coverage and an unknown optional
// percentile stays unknown; neither is synthesized into a measurement.
#[test]
fn zero_sample_and_unknown_never_become_measured() {
    let series: MetricSeries =
        serde_json::from_value(case("metric_series_zero_samples_accept")).expect("empty series");
    assert!(
        series.samples.is_empty() && series.rollups.is_empty(),
        "an empty series must carry no synthesized sample coverage"
    );

    let record: SkillLifecycleRecord =
        serde_json::from_value(case("skill_lifecycle_record_legacy_defaults"))
            .expect("historic record");
    assert_eq!(
        (record.uses, record.successes, record.failures),
        (0, 0, 0),
        "declared zero counters stay zero and are never read as measured benefit"
    );
    assert_eq!(
        record.promotion_evidence.len(),
        0,
        "an absent evidence list is absence, never verified benefit"
    );

    let sample: MetricSample =
        serde_json::from_value(case("metric_sample_accept")).expect("accept sample");
    assert_eq!(
        (sample.trace_id.as_deref(), sample.source_ref.as_deref()),
        (None, Some("src-1")),
        "the decoder keeps exactly the provenance the wire stated and fills in nothing"
    );
    let without_source = without(&case("metric_sample_accept"), "source_ref");
    assert!(
        serde_json::from_value::<MetricSample>(without_source).is_ok(),
        "an absent optional provenance field stays unknown, never synthesized"
    );
    assert!(
        !sample.labels[0].redacted,
        "an explicit redaction flag must not be reinterpreted by the decoder"
    );
}

// WORK_UNIT_CASE: 939/13
// Cases 13-14: the accepted internal dispositions invalidate when the source
// changes. This is the executable form of "a later addition in the four owned
// files cannot silently escape the closed set": it fails the moment any owned
// record drops its closure, so the exception cannot outlive its reason.
#[test]
fn closure_dispositions_invalidate_when_the_owned_source_changes() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("eval.rs");
    let source = std::fs::read_to_string(&path).expect("eval.rs must be readable");
    assert!(
        source.contains("pub struct EvalIntegrityFingerprintSet"),
        "the audited record must still exist in the owned file"
    );
    let anchor = source
        .find("pub struct EvalIntegrityFingerprintSet")
        .expect("anchored record");
    let window = &source[anchor.saturating_sub(400)..anchor];
    assert!(
        window.contains("deny_unknown_fields"),
        "the audited record's closure attribute must sit directly above it, so removing it \
         invalidates this disposition instead of silently reopening the decoder"
    );
    // The four owned files must still be exactly the files this issue names.
    for file in ["skill.rs", "lifecycle.rs", "eval.rs", "metrics.rs"] {
        assert!(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join(file)
                .exists(),
            "owned file {file} must remain in eliot-types"
        );
    }
}

// WORK_UNIT_CASE: 939/14
// Cases 13-14: bounded malformed input is panic-free and fails closed. Every
// bounded payload either refuses or decodes to exactly what the wire said; no
// input may panic, abort or silently widen.
#[test]
fn bounded_malformed_input_is_panic_free_and_fails_closed() {
    let raw = case("raw_malformed_bounded");
    let payloads = raw
        .as_array()
        .unwrap_or_else(|| panic!("raw_malformed_bounded must be an array of raw strings"));
    assert!(
        !payloads.is_empty(),
        "the bounded malformed corpus must not be empty"
    );
    for payload in payloads {
        let text = payload
            .as_str()
            .unwrap_or_else(|| panic!("every bounded payload must be a raw JSON string"));
        let as_record = serde_json::from_str::<SkillLifecycleRecord>(text);
        let as_sample = serde_json::from_str::<MetricSample>(text);
        let as_result = serde_json::from_str::<EvalCaseResult>(text);
        let as_baseline = serde_json::from_str::<EvalBaseline>(text);
        let as_series = serde_json::from_str::<MetricSeries>(text);
        // A decode that succeeds must be faithful: re-serializing it and
        // decoding again yields the identical value (no silent absorption).
        if let Ok(record) = &as_record {
            let bytes = serde_json::to_vec(record).expect("decoded record must re-serialize");
            assert_eq!(
                serde_json::from_slice::<SkillLifecycleRecord>(&bytes).expect("re-decode"),
                *record
            );
        }
        if let Ok(sample) = &as_sample {
            let bytes = serde_json::to_vec(sample).expect("decoded sample must re-serialize");
            assert_eq!(
                serde_json::from_slice::<MetricSample>(&bytes).expect("re-decode"),
                *sample
            );
        }
        if let Ok(result) = &as_result {
            let bytes = serde_json::to_vec(result).expect("decoded result must re-serialize");
            assert_eq!(
                serde_json::from_slice::<EvalCaseResult>(&bytes).expect("re-decode"),
                *result
            );
        }
        let _ = (as_baseline, as_series);
    }
}

// WORK_UNIT_CASE: 939/15
// Cases 15-16: the actual decoder refuses before trusted output. Added
// activation, benefit, actual-token and success canaries must not raise proof:
// each one is an unknown protected field on a real decode path.
#[test]
fn the_actual_decoder_refuses_before_trusted_output() {
    let canaries = [
        ("grants_authority", Value::Bool(true)),
        ("mutates_current_truth", Value::Bool(true)),
        ("benefits_verified", Value::Bool(true)),
        ("activation_granted", Value::Bool(true)),
        ("actual_tokens", Value::from(4096)),
        ("measured_benefit", Value::Bool(true)),
        ("verified_success", Value::Bool(true)),
        ("authority_basis", Value::String("owner-1".to_owned())),
    ];
    for (key, value) in canaries {
        let record = with_extra(&case("skill_lifecycle_record_accept"), key, value.clone());
        assert!(
            serde_json::from_value::<SkillLifecycleRecord>(record).is_err(),
            "lifecycle canary {key} must be refused, never raise proof"
        );
        let sample = with_extra(&case("metric_sample_accept"), key, value.clone());
        assert!(
            serde_json::from_value::<MetricSample>(sample).is_err(),
            "metric canary {key} must be refused, never raise proof"
        );
        let result = with_extra(&case("eval_case_result_accept"), key, value);
        assert!(
            serde_json::from_value::<EvalCaseResult>(result).is_err(),
            "evaluation canary {key} must be refused, never raise proof"
        );
    }
}

// WORK_UNIT_CASE: 939/16
// Cases 15-16: the lifecycle, evaluation and metric algorithms, dependencies
// and visibility in the other slices are unchanged. Freshness stays exact
// equality over the nine recorded dimensions, and every accepted record keeps
// its declared field set and unit-bearing values.
#[test]
fn lifecycle_evaluation_and_metric_algorithms_are_unchanged() {
    let base = case("nine_field_accept");
    let current: EvalIntegrityFingerprintSet =
        serde_json::from_value(base.clone()).expect("nine known fields must decode");
    assert!(
        !current.is_stale_against(&current),
        "the freshness algorithm is exact equality: an identical set is fresh"
    );
    for key in [
        "harness_fingerprint",
        "evaluator_fingerprint",
        "environment_fingerprint",
        "actual_route",
        "requested_route",
        "acceptance_relation",
        "oracle_owner",
        "oracle_version",
        "product_identity",
    ] {
        let mutated = with_extra(&base.clone(), key, Value::String("other".to_owned()));
        let other: EvalIntegrityFingerprintSet =
            serde_json::from_value(mutated).expect("a changed known field still decodes");
        assert!(
            current.is_stale_against(&other),
            "a difference in {key} must mark the recorded evidence stale"
        );
    }

    let record: SkillLifecycleRecord =
        serde_json::from_value(case("skill_lifecycle_record_accept")).expect("accept record");
    assert_eq!(record.uses, 12);
    assert_eq!(record.successes, 9);
    assert_eq!(record.failures, 3);
    assert_eq!(
        record.context_cost,
        Some(4096),
        "the declared unit-bearing counter must keep its exact value"
    );

    let sample: MetricSample =
        serde_json::from_value(case("metric_sample_accept")).expect("accept sample");
    assert_eq!(
        sample.value.to_bits(),
        12.5_f64.to_bits(),
        "a measured metric value must keep its exact declared unit-bearing value"
    );
}
