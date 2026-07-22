use super::claude_surface_catalog;
use eliot_types::ClaudeSurface;
use serde_json::Value;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn catalog_names(catalog: &Value, field: &str) -> Vec<String> {
    catalog
        .get(field)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The tracked Desktop manifest is only a package template. Keeping generated
/// catalog entries there would create a second authority beside the Governor.
#[test]
fn the_desktop_manifest_has_no_hand_maintained_catalog() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(
        repo_root().join("integrations/claude/claude-desktop/mcpb/manifest.json"),
    )?)?;
    assert_eq!(manifest["tools"], serde_json::json!([]));
    assert_eq!(manifest["prompts"], serde_json::json!([]));
    assert_eq!(manifest["tools_generated"], Value::Bool(true));
    assert_eq!(manifest["prompts_generated"], Value::Bool(true));
    Ok(())
}

#[test]
fn the_governor_catalog_contains_complete_mcpb_metadata() -> Result<(), Box<dyn std::error::Error>>
{
    let catalog = claude_surface_catalog(ClaudeSurface::ClaudeDesktopMcpb);
    let tools = catalog["mcpb_tools"].as_array().ok_or("tool catalog")?;
    let prompts = catalog["mcpb_prompts"].as_array().ok_or("prompt catalog")?;
    assert_eq!(tools.len(), catalog_names(&catalog, "tools").len());
    assert_eq!(prompts.len(), catalog_names(&catalog, "prompts").len());
    assert!(tools.iter().all(|tool| {
        tool.get("name").and_then(Value::as_str).is_some()
            && tool.get("description").and_then(Value::as_str).is_some()
    }));
    assert!(prompts.iter().all(|prompt| {
        prompt.get("name").and_then(Value::as_str).is_some()
            && prompt.get("description").and_then(Value::as_str).is_some()
            && prompt.get("arguments").and_then(Value::as_array).is_some()
            && prompt.get("text").and_then(Value::as_str).is_some()
    }));
    Ok(())
}

/// ELIOT is MIT. Every place ELIOT declares its own license must say so,
/// and a dual-license string in a shipped package manifest is a claim about
/// terms the project does not offer.
#[test]
fn the_desktop_manifest_declares_the_project_license() -> Result<(), Box<dyn std::error::Error>> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(
        repo_root().join("integrations/claude/claude-desktop/mcpb/manifest.json"),
    )?)?;
    assert_eq!(manifest.get("license").and_then(Value::as_str), Some("MIT"));
    Ok(())
}

/// Both Claude surfaces are one host family behind one Governor authority,
/// so they see the same tools. Only hook capability differs.
#[test]
fn both_claude_surfaces_expose_the_same_tool_set() {
    let code = claude_surface_catalog(ClaudeSurface::ClaudeCodePlugin);
    let desktop = claude_surface_catalog(ClaudeSurface::ClaudeDesktopMcpb);
    assert_eq!(
        catalog_names(&code, "tools"),
        catalog_names(&desktop, "tools")
    );
    assert_eq!(code["supports_lifecycle_hooks"], Value::Bool(true));
    assert_eq!(desktop["supports_lifecycle_hooks"], Value::Bool(false));
}

/// The profile Claude Code and Claude Desktop share was named after one of
/// them. Records written under the retired spelling must keep loading, but
/// it is never what the Governor writes back.
#[test]
fn the_retired_profile_spelling_reads_but_is_never_emitted()
-> Result<(), Box<dyn std::error::Error>> {
    let from_retired = super::McpAccessProfile::parse("claude_desktop")?;
    let from_current = super::McpAccessProfile::parse("claude_governed")?;
    assert_eq!(
        from_retired, from_current,
        "both spellings name one profile"
    );
    assert_eq!(from_retired.as_str(), "claude_governed");
    assert_ne!(from_retired.as_str(), "claude_desktop");
    Ok(())
}

/// The catalog is what package generation reads, so it must report the
/// profile under its current name.
#[test]
fn the_catalog_reports_the_semantic_profile_name() {
    for surface in [
        ClaudeSurface::ClaudeCodePlugin,
        ClaudeSurface::ClaudeDesktopMcpb,
    ] {
        assert_eq!(
            claude_surface_catalog(surface)["access_profile"],
            Value::String("claude_governed".to_owned())
        );
    }
}

/// Sorted output keeps generated manifests byte-stable across runs.
#[test]
fn the_catalog_is_deterministically_ordered() {
    let catalog = claude_surface_catalog(ClaudeSurface::ClaudeDesktopMcpb);
    let tools = catalog_names(&catalog, "tools");
    let mut sorted = tools.clone();
    sorted.sort();
    assert_eq!(tools, sorted);
    assert!(!tools.is_empty());
}
