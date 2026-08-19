use eliot_types::{
    AgentCandidateSubmitInput, BlobRef, CUE_BINDING_PAGE_SCHEMA_VERSION_V1,
    CUE_BINDING_PAGE_SCHEMA_VERSION_V2, CueBinding, CueKind, CueMatchMode, CueStrength,
    ObserveInput, agent_candidate_input_schema, command_pattern, cue_binding_page_id,
    error_signature, normalize_binding, normalize_binding_pages, normalize_path,
    normalize_query_tokens, observe_input_schema, path_matches_boundary,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn fv1_a_project_boundary_matcher_has_one_shared_definition()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        ("root covers src", ".", "src/lib.rs", true),
        ("root covers nested", ".", "nested/a.rs", true),
        ("directory matches itself", "src", "src", true),
        ("directory covers child", "src", "src/lib.rs", true),
        (
            "directory does not cover sibling prefix",
            "src",
            "src2/lib.rs",
            false,
        ),
        ("slash forms normalize", "./src/", r"src\lib.rs", true),
        (
            "package boundary does not cover sibling prefix",
            "crates/eliot-store",
            "crates/eliot-store2/src/lib.rs",
            false,
        ),
    ];
    for (name, boundary, path, expected) in cases {
        assert_eq!(
            path_matches_boundary(path, boundary),
            expected,
            "boundary case failed: {name}"
        );
    }

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut definitions = Vec::new();
    collect_boundary_definitions(&workspace.join("crates"), &mut definitions)?;
    assert_eq!(
        definitions,
        [workspace.join("crates/eliot-types/src/ul/normalize.rs")]
    );
    Ok(())
}

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
fn query_tokenizer_is_uncapped_and_preserves_first_occurrence() {
    assert_eq!(
        normalize_query_tokens(
            "Zulu alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron alpha zulu",
        ),
        [
            "zulu", "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota",
            "kappa", "lambda", "mu", "nu", "xi", "omicron",
        ]
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
            expected_reuse_note: Some("Reuse for canonical store changes.".to_owned()),
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
    let Some(cue_binding) = schema
        .get("$defs")
        .or_else(|| schema.get("definitions"))
        .and_then(Value::as_object)
        .and_then(|definitions| definitions.get("CueBinding"))
    else {
        return Err("legacy schema omitted CueBinding definition".into());
    };
    assert!(
        cue_binding["required"]
            .as_array()
            .is_some_and(|required| required.contains(&json!("expected_reuse_note")))
    );
    assert_eq!(
        serde_json::from_value::<AgentCandidateSubmitInput>(value)?,
        input
    );
    Ok(())
}

#[test]
fn canonical_observe_optional_note_keeps_legacy_some_and_uses_v2_for_none()
-> Result<(), Box<dyn std::error::Error>> {
    let observe: ObserveInput = serde_json::from_value(json!({
        "text_or_structured_payload": "safe capture",
        "hint": "observation"
    }))?;
    assert!(observe.expected_reuse_note.is_none());
    assert!(
        observe_input_schema()["properties"]
            .get("project_id")
            .is_none()
    );

    let legacy: CueBinding = serde_json::from_value(json!({
        "cue_kind": "file_path",
        "cue_value": "crates/eliot-store/src/lib.rs",
        "match_mode": "exact",
        "strength": "primary",
        "expected_reuse_note": "legacy v1 note"
    }))?;
    assert_eq!(
        legacy.expected_reuse_note.as_deref(),
        Some("legacy v1 note")
    );
    let long_note = Some("n".repeat(201));
    assert!(
        normalize_binding(
            CueBinding {
                expected_reuse_note: long_note,
                ..legacy.clone()
            },
            None
        )
        .is_ok()
    );

    let blob = BlobRef {
        algorithm: "blake3".to_owned(),
        digest_hex: "a".repeat(64),
        size_bytes: 1,
        relative_path: "observations/raw".to_owned(),
    };
    let legacy_pages = normalize_binding_pages("memory:legacy", &blob, vec![legacy.clone()], None)?;
    assert_eq!(
        legacy_pages[0].schema_version,
        CUE_BINDING_PAGE_SCHEMA_VERSION_V1
    );
    assert_eq!(
        legacy_pages[0].page_id,
        cue_binding_page_id("memory:legacy", &blob, 0, &legacy_pages[0].cue_bindings)
    );
    assert_eq!(
        legacy_pages[0].page_id,
        "cue-page:3a70a8a3ae2f949c30b8cdea6cef2a8d74f04864a684bab59820f895ca4a0c30"
    );

    let legacy_marker = normalize_binding_pages(
        "memory:marker",
        &blob,
        vec![CueBinding {
            expected_reuse_note: Some("<none>".to_owned()),
            ..legacy.clone()
        }],
        None,
    )?;

    let cold_pages = normalize_binding_pages(
        "memory:marker",
        &blob,
        vec![CueBinding {
            expected_reuse_note: None,
            ..legacy.clone()
        }],
        None,
    )?;
    assert_eq!(
        cold_pages[0].schema_version,
        CUE_BINDING_PAGE_SCHEMA_VERSION_V2
    );
    assert_ne!(legacy_marker[0].page_id, cold_pages[0].page_id);

    let mixed_bindings = (0..12)
        .map(|index| CueBinding {
            cue_value: format!("crates/eliot-store/src/file-{index}.rs"),
            expected_reuse_note: Some("legacy v1 note".to_owned()),
            ..legacy.clone()
        })
        .chain(std::iter::once(CueBinding {
            cue_value: "crates/eliot-store/src/zzzz-cold.rs".to_owned(),
            expected_reuse_note: None,
            ..legacy
        }))
        .collect();
    let mixed_pages = normalize_binding_pages("memory:mixed", &blob, mixed_bindings, None)?;
    assert_eq!(mixed_pages.len(), 2);
    assert_eq!(
        mixed_pages[0].schema_version,
        CUE_BINDING_PAGE_SCHEMA_VERSION_V1
    );
    assert_eq!(
        mixed_pages[1].schema_version,
        CUE_BINDING_PAGE_SCHEMA_VERSION_V2
    );
    Ok(())
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn collect_boundary_definitions(
    directory: &Path,
    definitions: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let needle = ["fn ", "path_matches_boundary"].concat();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_boundary_definitions(&path, definitions)?;
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && fs::read_to_string(&path)?.contains(&needle)
        {
            definitions.push(path);
        }
    }
    definitions.sort();
    Ok(())
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
