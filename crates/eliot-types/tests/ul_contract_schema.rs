use eliot_types::{
    CompilePacketL3Request, CompilePacketToolInput, MaterialPacketFrame, MemoryExposureMode,
    ProjectId, compile_packet_input_schema,
};
use serde_json::Value;

#[test]
fn t01_schema_required_set_is_exact() -> Result<(), Box<dyn std::error::Error>> {
    let schema = compile_packet_input_schema();
    let material_schema = schema
        .pointer("/properties/material_frame")
        .and_then(|value| object_schema(&schema, value))
        .ok_or_else(|| std::io::Error::other("material_frame must resolve to an object schema"))?;
    let mut actual = material_schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| std::io::Error::other("material_frame must publish required fields"))?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = vec![
        "acceptance_items",
        "active_plan",
        "causal_bridge",
        "cheapest_discriminative_probes",
        "completed_work",
        "environment",
        "exact_load_bearing_atoms",
        "expected_observable",
        "instruction_hotset_size",
        "killed_paths",
        "negative_memory_checked",
        "next_allowed_action",
        "responsibility_contour_route_refs",
        "stop_condition",
        "tool_schema_bytes_visible",
        "verifier",
    ];
    expected.sort_unstable();
    assert_eq!(actual, expected);

    let complete = serde_json::to_value(CompilePacketToolInput {
        request: CompilePacketL3Request {
            project_id: ProjectId::new_v7(),
            task_id: "task-example".to_owned(),
            goal: "Describe the required change".to_owned(),
            candidate_handles: Vec::new(),
            max_tokens: 1_200,
        },
        material_frame: Some(MaterialPacketFrame::default()),
        memory_mode: Some(MemoryExposureMode::IncludeCaseCandidates),
    })?;
    let frame = complete
        .get("material_frame")
        .and_then(Value::as_object)
        .ok_or_else(|| std::io::Error::other("complete input must contain a material frame"))?;
    for field in expected {
        assert!(
            frame.contains_key(field),
            "serialized complete input is missing {field}"
        );
    }
    Ok(())
}

fn object_schema<'a>(root: &'a Value, schema: &'a Value) -> Option<&'a Value> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
        && let Some(target) = reference
            .strip_prefix('#')
            .and_then(|pointer| root.pointer(pointer))
    {
        return object_schema(root, target);
    }
    if schema.get("type").and_then(Value::as_str) == Some("object")
        || schema.get("properties").is_some()
    {
        return Some(schema);
    }
    ["anyOf", "oneOf", "allOf"]
        .iter()
        .filter_map(|keyword| schema.get(*keyword).and_then(Value::as_array))
        .flatten()
        .find_map(|branch| object_schema(root, branch))
}
