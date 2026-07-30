use super::rejected;
use crate::EngineError;
use serde_json::Value;
use std::collections::BTreeSet;

pub fn validate_json_schema_instance(schema: &Value, instance: &Value) -> Result<(), EngineError> {
    let errors = json_schema_errors(schema, schema, instance, "$", 0);
    if errors.is_empty() {
        Ok(())
    } else {
        rejected(format!(
            "provider output failed JSON Schema validation: {}",
            errors.join("; ")
        ))
    }
}

#[allow(clippy::too_many_lines)]
fn json_schema_errors(
    root: &Value,
    schema: &Value,
    instance: &Value,
    path: &str,
    depth: usize,
) -> Vec<String> {
    if depth > 64 {
        return vec![format!("{path}: schema recursion exceeded 64 levels")];
    }
    if schema == &Value::Bool(true) {
        return Vec::new();
    }
    if schema == &Value::Bool(false) {
        return vec![format!("{path}: rejected by false schema")];
    }
    let Some(object) = schema.as_object() else {
        return vec![format!("{path}: schema node is not an object or boolean")];
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let Some(pointer) = reference.strip_prefix('#') else {
            return vec![format!(
                "{path}: non-local schema ref {reference} is unsupported"
            )];
        };
        let Some(target) = root.pointer(pointer) else {
            return vec![format!("{path}: unresolved schema ref {reference}")];
        };
        return json_schema_errors(root, target, instance, path, depth + 1);
    }

    let mut errors = Vec::new();
    if let Some(expected) = object.get("const")
        && expected != instance
    {
        errors.push(format!("{path}: value differs from const"));
    }
    if let Some(variants) = object.get("enum").and_then(Value::as_array)
        && !variants.contains(instance)
    {
        errors.push(format!("{path}: value is outside enum"));
    }
    if let Some(types) = object.get("type") {
        let type_matches = match types {
            Value::String(expected) => json_type_matches(expected, instance),
            Value::Array(expected) => expected
                .iter()
                .filter_map(Value::as_str)
                .any(|expected| json_type_matches(expected, instance)),
            _ => false,
        };
        if !type_matches {
            errors.push(format!(
                "{path}: actual type {} does not satisfy schema type {types}",
                json_type_name(instance)
            ));
            return errors;
        }
    }

    if let Some(all_of) = object.get("allOf").and_then(Value::as_array) {
        for branch in all_of {
            errors.extend(json_schema_errors(root, branch, instance, path, depth + 1));
        }
    }
    if let Some(any_of) = object.get("anyOf").and_then(Value::as_array)
        && !any_of
            .iter()
            .any(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
    {
        errors.push(format!("{path}: no anyOf branch accepted the value"));
    }
    if let Some(one_of) = object.get("oneOf").and_then(Value::as_array) {
        let accepted = one_of
            .iter()
            .filter(|branch| json_schema_errors(root, branch, instance, path, depth + 1).is_empty())
            .count();
        if accepted != 1 {
            errors.push(format!(
                "{path}: expected exactly one oneOf branch, accepted {accepted}"
            ));
        }
    }

    if let Some(actual) = instance.as_object() {
        let required = object
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        for key in required {
            if !actual.contains_key(key) {
                errors.push(format!("{path}/{key}: required property is missing"));
            }
        }
        let properties = object.get("properties").and_then(Value::as_object);
        if let Some(properties) = properties {
            for (key, value) in actual {
                if let Some(property_schema) = properties.get(key) {
                    errors.extend(json_schema_errors(
                        root,
                        property_schema,
                        value,
                        &format!("{path}/{}", escape_json_pointer(key)),
                        depth + 1,
                    ));
                    continue;
                }
                match object.get("additionalProperties") {
                    Some(Value::Bool(false)) => errors.push(format!(
                        "{path}/{}: additional property is forbidden",
                        escape_json_pointer(key)
                    )),
                    Some(additional @ (Value::Object(_) | Value::Bool(true))) => {
                        errors.extend(json_schema_errors(
                            root,
                            additional,
                            value,
                            &format!("{path}/{}", escape_json_pointer(key)),
                            depth + 1,
                        ));
                    }
                    _ => {}
                }
            }
        } else if let Some(additional @ Value::Object(_)) = object.get("additionalProperties") {
            for (key, value) in actual {
                errors.extend(json_schema_errors(
                    root,
                    additional,
                    value,
                    &format!("{path}/{}", escape_json_pointer(key)),
                    depth + 1,
                ));
            }
        }
        check_size_bound(
            object,
            "minProperties",
            actual.len(),
            path,
            true,
            &mut errors,
        );
        check_size_bound(
            object,
            "maxProperties",
            actual.len(),
            path,
            false,
            &mut errors,
        );
    }

    if let Some(actual) = instance.as_array() {
        if let Some(item_schema) = object.get("items") {
            for (index, value) in actual.iter().enumerate() {
                errors.extend(json_schema_errors(
                    root,
                    item_schema,
                    value,
                    &format!("{path}/{index}"),
                    depth + 1,
                ));
            }
        }
        check_size_bound(object, "minItems", actual.len(), path, true, &mut errors);
        check_size_bound(object, "maxItems", actual.len(), path, false, &mut errors);
        if object.get("uniqueItems") == Some(&Value::Bool(true)) {
            for (index, value) in actual.iter().enumerate() {
                if actual[..index].contains(value) {
                    errors.push(format!("{path}/{index}: array item is not unique"));
                }
            }
        }
    }

    if let Some(actual) = instance.as_str() {
        let length = actual.chars().count();
        check_size_bound(object, "minLength", length, path, true, &mut errors);
        check_size_bound(object, "maxLength", length, path, false, &mut errors);
    }

    if let Some(actual) = instance.as_f64() {
        for (keyword, comparison) in [
            ("minimum", std::cmp::Ordering::Less),
            ("maximum", std::cmp::Ordering::Greater),
        ] {
            if let Some(bound) = object.get(keyword).and_then(Value::as_f64)
                && actual.partial_cmp(&bound) == Some(comparison)
            {
                errors.push(format!("{path}: number violates {keyword} {bound}"));
            }
        }
        if let Some(bound) = object.get("exclusiveMinimum").and_then(Value::as_f64)
            && actual <= bound
        {
            errors.push(format!("{path}: number violates exclusiveMinimum {bound}"));
        }
        if let Some(bound) = object.get("exclusiveMaximum").and_then(Value::as_f64)
            && actual >= bound
        {
            errors.push(format!("{path}: number violates exclusiveMaximum {bound}"));
        }
    }
    errors
}

fn check_size_bound(
    schema: &serde_json::Map<String, Value>,
    keyword: &str,
    actual: usize,
    path: &str,
    minimum: bool,
    errors: &mut Vec<String>,
) {
    let Some(bound) = schema
        .get(keyword)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return;
    };
    if (minimum && actual < bound) || (!minimum && actual > bound) {
        errors.push(format!("{path}: size {actual} violates {keyword} {bound}"));
    }
}

fn json_type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "string" => value.is_string(),
        _ => false,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub(super) fn json_events(bytes: &[u8]) -> Result<Vec<Value>, EngineError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| EngineError::WriteRejected("provider output is not UTF-8".to_owned()))?;
    let mut events = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line.trim()).map_err(EngineError::from))
        .collect::<Result<Vec<_>, _>>()?;
    if events.is_empty()
        && let Ok(value) = serde_json::from_str::<Value>(text.trim())
    {
        events.push(value);
    }
    Ok(events)
}

pub(super) fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object
                    .get(*key)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                {
                    return Some(value.to_owned());
                }
            }
            object.values().find_map(|value| first_string(value, keys))
        }
        Value::Array(values) => values.iter().find_map(|value| first_string(value, keys)),
        _ => None,
    }
}

pub(super) fn exact_requested_model(
    observed: Option<String>,
    requested: &str,
) -> Result<String, EngineError> {
    let observed = observed.ok_or_else(|| {
        EngineError::WriteRejected("provider terminal result did not attest a model".to_owned())
    })?;
    if observed == requested {
        Ok(observed)
    } else {
        rejected(format!(
            "provider resolved model {observed} differs from requested model {requested}"
        ))
    }
}

pub(super) fn observed_tool_names(events: &[Value]) -> Vec<String> {
    let mut names = BTreeSet::new();
    for event in events {
        collect_tool_names(event, &mut names);
    }
    names.into_iter().collect()
}

fn collect_tool_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            let is_tool = object
                .get("type")
                .or_else(|| object.get("event"))
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind,
                        "tool" | "tool_use" | "tool_call" | "tool.result" | "tool_use_summary"
                    ) || kind.contains("tool")
                });
            let delegated_mcp_name = [
                "/tool_info/parameters/ToolName",
                "/tool_info/parameters/tool_name",
                "/parameters/ToolName",
                "/parameters/tool_name",
            ]
            .into_iter()
            .find_map(|pointer| value.pointer(pointer).and_then(Value::as_str))
            .filter(|name| !name.trim().is_empty());
            if let Some(name) = delegated_mcp_name {
                names.insert(name.to_owned());
            } else if is_tool
                && let Some(name) = first_string(value, &["name", "tool", "tool_name", "toolName"])
            {
                names.insert(name);
            }
            for child in object.values() {
                collect_tool_names(child, names);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_tool_names(child, names);
            }
        }
        _ => {}
    }
}
