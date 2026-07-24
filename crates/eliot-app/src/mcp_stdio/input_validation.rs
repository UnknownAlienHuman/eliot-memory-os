use anyhow::Result;
use eliot_types::{
    CompilePacketToolInput, InvalidField, ToolInputError, ToolInputErrorData,
    compile_packet_input_schema, compile_packet_minimal_example,
};
use serde_json::Value;

pub(super) fn decode_compile_packet_input(value: Value) -> Result<CompilePacketToolInput> {
    let schema = compile_packet_input_schema();
    let mut missing = Vec::new();
    let mut invalid = Vec::new();
    validate_node(&schema, &schema, &value, "", &mut missing, &mut invalid);
    missing.sort();
    missing.dedup();
    invalid.sort_by(|left, right| {
        left.field
            .cmp(&right.field)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    invalid.dedup();

    if !missing.is_empty() || !invalid.is_empty() {
        return Err(ToolInputError {
            data: ToolInputErrorData {
                code: "INVALID_TOOL_INPUT".to_owned(),
                missing,
                invalid,
                minimal_valid_example: compile_packet_minimal_example(),
            },
        }
        .into());
    }

    serde_json::from_value(value).map_err(|error| {
        ToolInputError {
            data: ToolInputErrorData {
                code: "INVALID_TOOL_INPUT".to_owned(),
                missing: Vec::new(),
                invalid: vec![InvalidField {
                    field: "$".to_owned(),
                    reason: error.to_string(),
                }],
                minimal_valid_example: compile_packet_minimal_example(),
            },
        }
        .into()
    })
}

fn validate_node(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    missing: &mut Vec<String>,
    invalid: &mut Vec<InvalidField>,
) {
    if let Some(target) = resolve_local_ref(root, schema) {
        validate_node(root, target, value, path, missing, invalid);
        return;
    }

    let types = declared_types(root, schema);
    if !types.is_empty() && !types.iter().any(|kind| value_matches_type(value, kind)) {
        invalid.push(InvalidField {
            field: root_path(path),
            reason: format!("expected {}", types.join(" or ")),
        });
        return;
    }

    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            validate_node(root, branch, value, path, missing, invalid);
        }
    }

    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            if let Some(branch) = branches.iter().find(|branch| {
                let branch_types = declared_types(root, branch);
                branch_types.is_empty()
                    || branch_types
                        .iter()
                        .any(|kind| value_matches_type(value, kind))
            }) {
                validate_node(root, branch, value, path, missing, invalid);
            }
            return;
        }
    }

    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(field) {
                    missing.push(child_path(path, field));
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (field, field_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_node(
                        root,
                        field_schema,
                        field_value,
                        &child_path(path, field),
                        missing,
                        invalid,
                    );
                }
            }
        }
    } else if let Some(items) = value.as_array()
        && let Some(item_schema) = schema.get("items")
    {
        for (index, item) in items.iter().enumerate() {
            validate_node(
                root,
                item_schema,
                item,
                &format!("{}[{index}]", root_path(path)),
                missing,
                invalid,
            );
        }
    }
}

fn declared_types(root: &Value, schema: &Value) -> Vec<String> {
    if let Some(target) = resolve_local_ref(root, schema) {
        return declared_types(root, target);
    }
    let mut types = Vec::new();
    match schema.get("type") {
        Some(Value::String(kind)) => types.push(kind.clone()),
        Some(Value::Array(kinds)) => {
            types.extend(kinds.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        _ => {}
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                types.extend(declared_types(root, branch));
            }
        }
    }
    types.sort();
    types.dedup();
    types
}

fn resolve_local_ref<'a>(root: &'a Value, schema: &Value) -> Option<&'a Value> {
    let reference = schema.get("$ref")?.as_str()?;
    reference
        .strip_prefix('#')
        .and_then(|pointer| root.pointer(pointer))
}

fn value_matches_type(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value
            .as_number()
            .is_some_and(|number| number.is_i64() || number.is_u64()),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn child_path(path: &str, field: &str) -> String {
    if path.is_empty() {
        field.to_owned()
    } else {
        format!("{path}.{field}")
    }
}

fn root_path(path: &str) -> String {
    if path.is_empty() {
        "$".to_owned()
    } else {
        path.to_owned()
    }
}
