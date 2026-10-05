//! Desktop MCPB packager prompts for issue #18, bridge-owned and aligned
//! to the served I07-06 canonical surface (`docs/architecture/I07-06-mcp-surface.md`).
//! The facade copy (`crates/eliot-app/src/mcp_stdio/catalog.rs`) stays with
//! the retiring facade until facade retirement and is no longer the
//! byte-identity source: this module intentionally diverges from it where
//! the facade names facade-only tools the bridge never serves.

use anyhow::Result;
use serde_json::{Value, json};

pub fn prompt_definitions() -> Vec<Value> {
    vec![
        prompt_definition(
            "eliot-start",
            "Start or resume a material task through the live Eliot task cycle.",
        ),
        prompt_definition(
            "eliot-understand",
            "Build decision-sufficient understanding from current truth and exact evidence.",
        ),
        prompt_definition(
            "eliot-delegate",
            "Delegate or accept one bounded, role-leased Eliot work item.",
        ),
        prompt_definition(
            "eliot-finish",
            "Verify current artifacts and submit an honest completion proof.",
        ),
    ]
}

fn prompt_definition(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "arguments": [
            {
                "name": "task",
                "description": "Optional concise task goal or task identifier.",
                "required": false
            }
        ]
    })
}

pub fn prompt_text(name: &str, task: &str) -> Result<String> {
    let text = match name {
        "eliot-start" => format!(
            "Start or resume {task}. Call eliot.state, read current task/current state, and compile only the smallest packet needed. Confirm the task-scoped role and revision before any material action."
        ),
        "eliot-understand" => format!(
            "For {task}, separate current verified truth from supported, assumed, conflicted, stale, and unknown state. Expand exact handles, check negative memory, trace goal -> owner -> symbol or artifact -> observable -> verifier, then submit an UnderstandingProof or run the cheapest discriminative probe."
        ),
        "eliot-delegate" => format!(
            "For {task}, confirm that delegation has positive value and that the current session has the required task-scoped role. Delegate one bounded work item with exact acceptance, packet refs, expected result, verifier, leases, and an idempotency key; reconcile unknown outcomes before retrying."
        ),
        "eliot-finish" => format!(
            "For {task}, read exact finish gaps, run mapped verifiers against the accepted artifact scope, account for every acceptance item, and submit CompletionProof with the honest status. A model response is candidate evidence, not a verifier."
        ),
        other => anyhow::bail!("unknown Eliot prompt: {other}"),
    };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_definitions_return_the_four_names_in_order() {
        let definitions = prompt_definitions();
        let names: Vec<&str> = definitions
            .iter()
            .filter_map(|definition| definition.get("name").and_then(Value::as_str))
            .collect();
        assert_eq!(
            names,
            vec![
                "eliot-start",
                "eliot-understand",
                "eliot-delegate",
                "eliot-finish",
            ]
        );
    }

    #[test]
    fn prompt_text_substitutes_the_task_and_refuses_unknown_name() {
        for name in [
            "eliot-start",
            "eliot-understand",
            "eliot-delegate",
            "eliot-finish",
        ] {
            let text = prompt_text(name, "probe-task")
                .unwrap_or_else(|error| panic!("known prompt renders: {error:?}"));
            assert!(
                text.contains("probe-task"),
                "{name} must substitute the task"
            );
        }
        assert!(prompt_text("eliot-unknown", "probe-task").is_err());
    }

    /// Issue #18 stitch-return W12/catalog-prompts: prompt texts must name
    /// only served canonical tools. The forbidden literals below live in this
    /// test intentionally: the return point constrains generated catalog
    /// content, never test source.
    #[test]
    fn prompt_text_names_only_served_canonical_tools() {
        const FORBIDDEN_FACADE_TOOLS: [&str; 6] = [
            "eliot_host_session_status",
            "eliot_project_identity",
            "eliot_task_state",
            "eliot_recall_l0",
            "eliot_governor",
            "eliot_operator_",
        ];
        const NAMES: [&str; 4] = [
            "eliot-start",
            "eliot-understand",
            "eliot-delegate",
            "eliot-finish",
        ];
        for name in NAMES {
            let text = prompt_text(name, "probe-task")
                .unwrap_or_else(|error| panic!("known prompt renders: {error:?}"));
            for forbidden in FORBIDDEN_FACADE_TOOLS {
                assert!(
                    !text.contains(forbidden),
                    "{name} prompt text must not name facade-only {forbidden}"
                );
            }
        }
        let start = prompt_text("eliot-start", "probe-task")
            .unwrap_or_else(|error| panic!("eliot-start renders: {error:?}"));
        assert!(
            start.contains("eliot.state"),
            "eliot-start must name the served canonical eliot.state tool"
        );
        let catalog = crate::packager_catalog::render_mcp_catalog(
            "claude",
            eliot_types::ClaudeSurface::ClaudeDesktopMcpb,
        )
        .unwrap_or_else(|error| panic!("desktop catalog renders: {error:?}"));
        let prompts = catalog["mcpb_prompts"]
            .as_array()
            .unwrap_or_else(|| panic!("mcpb_prompts is an array: {}", catalog["mcpb_prompts"]));
        assert_eq!(prompts.len(), 4);
        for prompt in prompts {
            let text = prompt
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("mcpb_prompts entry carries text: {prompt}"));
            for forbidden in FORBIDDEN_FACADE_TOOLS {
                assert!(
                    !text.contains(forbidden),
                    "rendered prompt text must not name facade-only {forbidden}"
                );
            }
        }
    }
}
