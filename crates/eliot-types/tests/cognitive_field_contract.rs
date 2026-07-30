use eliot_types::{
    COGNITIVE_FIELD_SUITE_SCHEMA_VERSION, CognitiveFieldFamily, CognitiveFieldSuite,
    CognitiveJudgeResult, CognitiveMemoryCondition, CognitiveUnderstandingAnswer,
    cognitive_judge_result_schema, cognitive_understanding_answer_schema,
    minimal_cognitive_judge_result, minimal_cognitive_understanding_answer,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn reader_and_judge_contracts_roundtrip_and_publish_required_fields() -> TestResult {
    let mut reader = minimal_cognitive_understanding_answer();
    reader.case_id = "U03".to_owned();
    reader.memory_condition = CognitiveMemoryCondition::Treatment;
    reader.files_to_change = vec!["crates/eliot-engine/src/host.rs".to_owned()];
    reader.known_failures = vec!["failure:stale-cli-discovery".to_owned()];
    reader.stale_or_rejected_memory_refs = vec!["claim:rejected-route".to_owned()];
    reader.open_unknowns = vec!["unknown:future-cache-layout".to_owned()];
    reader.predicted_changed_paths = vec!["crates/eliot-engine/src/host.rs".to_owned()];
    reader.predicted_failing_verifiers = vec!["cargo:test:host-integration".to_owned()];
    reader.memory_handles_received = vec!["claim:received".to_owned()];
    reader.memory_handles_expanded = vec!["claim:expanded".to_owned()];
    reader.memory_handles_used = vec!["claim:used".to_owned()];
    reader.influence_receipt_refs = vec!["influence:verified".to_owned()];
    let reader_roundtrip: CognitiveUnderstandingAnswer =
        serde_json::from_value(serde_json::to_value(&reader)?)?;
    assert_eq!(reader_roundtrip, reader);

    let judge = minimal_cognitive_judge_result();
    let judge_roundtrip: CognitiveJudgeResult =
        serde_json::from_value(serde_json::to_value(&judge)?)?;
    assert_eq!(judge_roundtrip, judge);

    let reader_schema = cognitive_understanding_answer_schema();
    assert_eq!(
        reader_schema["properties"]["desired_state"]["type"],
        Value::String("array".to_owned())
    );
    assert_eq!(
        reader_schema["properties"]["desired_state"]["items"]["type"],
        Value::String("string".to_owned())
    );
    assert_eq!(reader_schema["additionalProperties"], Value::Bool(false));
    let serialized_keys = serde_json::to_value(&reader)?
        .as_object()
        .ok_or_else(|| std::io::Error::other("reader must serialize as object"))?
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let published_keys = reader_schema["properties"]
        .as_object()
        .ok_or_else(|| std::io::Error::other("reader schema must publish properties"))?
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(serialized_keys, published_keys);
    for field in [
        "case_id",
        "project_id",
        "task_id",
        "memory_condition",
        "user_goal",
        "desired_state",
        "causal_hops",
        "invariants",
        "current_truth_refs",
        "open_unknowns",
        "next_action",
        "expected_observable",
        "verifier_ref",
        "stop_condition",
        "memory_handles_received",
        "memory_handles_expanded",
        "memory_handles_used",
        "influence_receipt_refs",
        "confidence_by_section",
    ] {
        assert!(required_fields(&reader_schema)?.contains(&field.to_owned()));
    }

    let judge_schema = cognitive_judge_result_schema()?;
    for field in [
        "case_id",
        "oracle_hash",
        "reader_output_hash",
        "deterministic_report_hash",
        "scores",
        "exact_discrepancies",
        "forbidden_conclusion_detected",
        "semantic_pass",
    ] {
        assert!(required_fields(&judge_schema)?.contains(&field.to_owned()));
    }
    Ok(())
}

#[test]
fn field_v2_manifest_contains_exactly_all_forty_eight_cases() -> TestResult {
    let path = workspace_root()?.join("tests/cognitive/field-v2/suite.json");
    let suite: CognitiveFieldSuite = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(suite.schema_version, COGNITIVE_FIELD_SUITE_SCHEMA_VERSION);
    assert_eq!(suite.cases.len(), 48);
    assert_eq!(suite.hard_provider_call_cap, 24);

    let mut counts = BTreeMap::new();
    for case in &suite.cases {
        *counts.entry(case.family).or_insert(0usize) += 1;
    }
    assert_eq!(counts.get(&CognitiveFieldFamily::U), Some(&12));
    assert_eq!(counts.get(&CognitiveFieldFamily::M), Some(&8));
    assert_eq!(counts.get(&CognitiveFieldFamily::D), Some(&10));
    assert_eq!(counts.get(&CognitiveFieldFamily::A), Some(&6));
    assert_eq!(counts.get(&CognitiveFieldFamily::H), Some(&6));
    assert_eq!(counts.get(&CognitiveFieldFamily::R), Some(&6));
    Ok(())
}

fn required_fields(schema: &Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("root schema must publish required fields"))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect())
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("resolve workspace root"))?
        .to_path_buf())
}
