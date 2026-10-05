//! Packager catalog renderer for issue #18 (CATALOG-REFINED step 4).
//!
//! Renders the `eliot-mcp-catalog-v2` envelope the Desktop MCPB
//! packager generates manifests from. Tools come from the same
//! `tools/list` source the bridge serves (`eliot_mcp::tools_list_result`),
//! never from a transcription of the retiring facade; prompts come
//! from `crate::packager_prompts`, so the rendered prompt text is
//! byte-identical to the facade catalog it replaces.

use std::fmt;

use eliot_mcp::tools_list_result;
use serde_json::{Value, json};

use crate::packager_prompts::{prompt_definitions, prompt_text};

/// The packager catalog envelope version this renderer emits.
const CATALOG_SCHEMA_VERSION: &str = "eliot-mcp-catalog-v2";

/// Failure of one packager catalog render.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    /// The host is outside the Claude host family.
    BadHost(String),
    /// One catalog source could not be rendered.
    Render(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHost(host) => write!(
                formatter,
                "only the Claude host family exposes surface catalogs (got {host})"
            ),
            Self::Render(detail) => write!(formatter, "catalog render failed: {detail}"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Renders the `eliot-mcp-catalog-v2` envelope for one Claude host
/// surface: the served tool set from the bridge `tools/list` source
/// and the packager prompts, each sorted by name so the catalog is
/// comparable byte for byte across runs.
pub fn render_mcp_catalog(
    host: &str,
    surface: eliot_types::ClaudeSurface,
) -> Result<Value, CatalogError> {
    if !host.trim().eq_ignore_ascii_case("claude") {
        return Err(CatalogError::BadHost(host.to_owned()));
    }
    let served = tools_list_result().map_err(|rejection| {
        CatalogError::Render(format!(
            "tools/list source is unavailable (code {}: {})",
            rejection.code, rejection.message
        ))
    })?;
    let served_tools = served
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CatalogError::Render("tools/list source carries no tools array".to_owned())
        })?;
    let mut mcpb_tools: Vec<Value> = served_tools
        .iter()
        .filter_map(|tool| {
            Some(json!({
                "name": tool.get("name")?.as_str()?,
                "description": tool.get("description")?.as_str()?,
            }))
        })
        .collect();
    let mut mcpb_prompts: Vec<Value> = prompt_definitions()
        .into_iter()
        .filter_map(|definition| {
            let name = definition.get("name")?.as_str()?;
            let description = definition.get("description")?.as_str()?;
            let arguments = definition
                .get("arguments")?
                .as_array()?
                .iter()
                .filter_map(|argument| argument.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>();
            let text = prompt_text(name, "${arguments.task}").ok()?;
            Some(json!({
                "name": name,
                "description": description,
                "arguments": arguments,
                "text": text,
            }))
        })
        .collect();
    // Sorted so the catalog is comparable byte for byte across runs.
    mcpb_tools.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    mcpb_prompts.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let tools = mcpb_tools
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let prompts = mcpb_prompts
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    Ok(json!({
        "schema_version": CATALOG_SCHEMA_VERSION,
        "host": host,
        "surface": surface.as_str(),
        "tools": tools,
        "prompts": prompts,
        "mcpb_tools": mcpb_tools,
        "mcpb_prompts": mcpb_prompts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_types::ClaudeSurface;

    #[test]
    fn defaults_render_the_desktop_envelope_with_four_prompts() {
        let catalog = render_mcp_catalog("claude", ClaudeSurface::ClaudeDesktopMcpb)
            .expect("desktop catalog renders");
        assert_eq!(
            catalog["schema_version"].as_str(),
            Some("eliot-mcp-catalog-v2")
        );
        assert_eq!(catalog["surface"].as_str(), Some("claude_desktop_mcpb"));
        let prompts = catalog["mcpb_prompts"]
            .as_array()
            .expect("mcpb_prompts is an array");
        assert_eq!(prompts.len(), 4);
        let names: Vec<&str> = prompts
            .iter()
            .filter_map(|prompt| prompt.get("name").and_then(Value::as_str))
            .collect();
        assert_eq!(
            names,
            vec![
                "eliot-delegate",
                "eliot-finish",
                "eliot-start",
                "eliot-understand",
            ]
        );
    }

    #[test]
    fn code_surface_renders() {
        let catalog = render_mcp_catalog("claude", ClaudeSurface::ClaudeCodePlugin)
            .expect("code catalog renders");
        assert_eq!(catalog["surface"].as_str(), Some("claude_code_plugin"));
        assert_eq!(
            catalog["schema_version"].as_str(),
            Some("eliot-mcp-catalog-v2")
        );
        assert_eq!(catalog["mcpb_prompts"].as_array().map(Vec::len), Some(4));
    }

    #[test]
    fn non_claude_host_is_rejected() {
        let error = render_mcp_catalog("codex", ClaudeSurface::ClaudeDesktopMcpb)
            .expect_err("non-claude host refuses");
        assert!(matches!(error, CatalogError::BadHost(_)));
        assert!(error.to_string().contains("Claude host family"));
    }
}
