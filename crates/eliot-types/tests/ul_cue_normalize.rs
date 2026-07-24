use eliot_types::{
    AgentCandidateSubmitInput, CueBinding, CueKind, CueMatchMode, CueStrength,
    agent_candidate_input_schema, command_pattern, error_signature, normalize_path,
    normalize_query_tokens,
};
use serde_json::{Value, json};

#[test]
fn t03_normalizers_are_stable() {
    let path = normalize_path(r"C:\Repo\Crates\Eliot-Store\src\LIB.rs", Some("C:/Repo"));
    assert_eq!(path, "crates/eliot-store/src/lib.rs");
    assert_eq!(
        normalize_query_tokens("Это проверка и проверка для Ошибки в STORE"),
        ["проверка", "ошибки", "store"]
    );
    assert_eq!(
        command_pattern(&strings(&["cargo", "test", "-p", "eliot-store"])),
        "cargo test"
    );
    assert_eq!(
        command_pattern(&strings(&[r"C:\Git\bin\git.exe", "status", "--short"])),
        "git.exe status"
    );
    let signature = error_signature(
        "rustc",
        "E0308",
        "error at line 42 address deadbeef: expected 'u32'",
        r"C:\Repo\src\line42.rs",
        Some("C:/Repo"),
    );
    let moved = error_signature(
        "rustc",
        "E0308",
        "error at line 731 address 0123456789abcdef: expected 'usize'",
        r"C:\Repo\src\line731.rs",
        Some("C:/Repo"),
    );
    assert!(signature.starts_with("sig:"));
    assert_eq!(signature.len(), 68);
    assert_eq!(signature, moved);
    assert_eq!(
        path,
        normalize_path(r"C:\Repo\Crates\Eliot-Store\src\LIB.rs", Some("C:/Repo"))
    );
    assert_eq!(
        signature,
        error_signature(
            "rustc",
            "E0308",
            "error at line 42 address deadbeef: expected 'u32'",
            r"C:\Repo\src\line42.rs",
            Some("C:/Repo"),
        )
    );
}

#[test]
fn t03_candidate_schema_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let input = AgentCandidateSubmitInput {
        project_id: "00000000-0000-7000-8000-000000000001".to_owned(),
        task_id: "00000000-0000-7000-8000-000000000002".to_owned(),
        write_id: "00000000-0000-7000-8000-000000000003".to_owned(),
        topic: "cue addressing".to_owned(),
        statement: "The store path is a reusable cue.".to_owned(),
        where_applicable: vec!["canonical store changes".to_owned()],
        where_not_applicable: Vec::new(),
        negative_constraints: Vec::new(),
        provenance_refs: vec!["task:03".to_owned()],
        freshness_rule: "recheck after store layout changes".to_owned(),
        cue_bindings: vec![CueBinding {
            cue_kind: CueKind::FilePath,
            cue_value: "crates/eliot-store/src/lib.rs".to_owned(),
            match_mode: CueMatchMode::Exact,
            strength: CueStrength::Primary,
            expected_reuse_note: "Reuse for canonical store changes.".to_owned(),
        }],
        auto_bind: None,
        expected_reuse_note: "Reuse when the canonical store is in scope.".to_owned(),
        curation: None,
    };
    let value = serde_json::to_value(&input)?;
    let schema = agent_candidate_input_schema();
    validate_schema(&value, &schema, &schema)?;
    let required = schema["required"]
        .as_array()
        .ok_or("candidate schema omitted required")?;
    assert!(!required.contains(&json!("cue_bindings")));
    assert!(required.contains(&json!("expected_reuse_note")));
    assert_eq!(
        serde_json::from_value::<AgentCandidateSubmitInput>(value)?,
        input
    );
    Ok(())
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_schema(
    value: &Value,
    schema: &Value,
    root: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let pointer = reference
            .strip_prefix('#')
            .ok_or("only local schema references are supported")?;
        return validate_schema(
            value,
            root.pointer(pointer).ok_or("schema reference missing")?,
            root,
        );
    }
    if let Some(variants) = schema.get("enum").and_then(Value::as_array)
        && !variants.contains(value)
    {
        return Err("value is outside schema enum".into());
    }
    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        let valid = match expected {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "boolean" => value.is_boolean(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "null" => value.is_null(),
            _ => true,
        };
        if !valid {
            return Err(format!("schema type mismatch: expected {expected}").into());
        }
    }
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        let object = value.as_object().ok_or("required fields need an object")?;
        for name in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(name) {
                return Err(format!("required field missing: {name}").into());
            }
        }
    }
    if let (Some(object), Some(properties)) = (
        value.as_object(),
        schema.get("properties").and_then(Value::as_object),
    ) {
        for (name, field) in object {
            if let Some(field_schema) = properties.get(name) {
                validate_schema(field, field_schema, root)?;
            }
        }
    }
    if let (Some(items), Some(item_schema)) = (
        value.as_array(),
        schema.get("items").filter(|item| !item.is_null()),
    ) {
        for item in items {
            validate_schema(item, item_schema, root)?;
        }
    }
    Ok(())
}
