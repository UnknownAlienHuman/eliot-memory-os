//! I7.24 tool-call intent gate wiring.
//!
//! This module wires the [`eliot_receipts`] tool-exposure intent contract into
//! the Kernel orchestration boundary. It validates a lightweight
//! [`ToolCallIntent`] before dispatch so an expensive, model-backed, swarm,
//! network, broad-search, or effect-capable call is rejected when it carries no
//! intent, while cheap exact reads stay exempt. It also compares each staging
//! candidate against the retained per-route stage so a materially repeated
//! call on unchanged inputs without a new expected delta surfaces a
//! [`LoopSignal`] instead of staging as progress.

#![forbid(unsafe_code)]

use eliot_contracts::sha256_hex;
use eliot_receipts::{LoopSignal, ToolCallClass, ToolCallIntent, ToolCallRequest};

/// Route fingerprint for tool calls admitted through the local-read boundary.
fn route_fingerprint(envelope: &eliot_protocol::HostRequestEnvelope) -> String {
    let session = envelope
        .identity
        .session_id
        .as_deref()
        .unwrap_or("unknown-session");
    format!(
        "{}:{:?}:{:?}",
        session, envelope.state_fence.authority_epoch, envelope.state_fence.resource_generation
    )
}

/// Derives the tool call class from the tool name.
fn call_class(name: &str) -> Option<ToolCallClass> {
    match name {
        "eliot.query" => Some(ToolCallClass::BroadSearch),
        "eliot.packet" => Some(ToolCallClass::EffectCapable),
        name if is_expensive_skill_tool(name) => Some(ToolCallClass::Expensive),
        _ => None,
    }
}

fn is_expensive_skill_tool(name: &str) -> bool {
    matches!(
        name,
        "skill.inject" | "skill.display" | "skill.activate" | "skill.execute"
    )
}

/// Computes the SHA-256 digest over the canonical JSON form of the tool.
fn inputs_digest(tool: &serde_json::Value) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(tool)?;
    Ok(sha256_hex(&bytes))
}

/// Builds a [`ToolCallRequest`] from the admitted envelope and tool.
pub(crate) fn build_tool_call_request(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
) -> Option<ToolCallRequest> {
    let name = tool.as_object()?.get("name")?.as_str()?.to_owned();
    let class = call_class(&name)?;
    let arguments = tool.as_object()?.get("arguments")?.as_object()?;
    let intent = build_tool_intent(arguments)?;
    let digest = inputs_digest(tool).ok()?;
    Some(ToolCallRequest {
        tool_definition: name,
        route_fingerprint: route_fingerprint(envelope),
        call_class: class,
        inputs_digest: digest,
        intent: Some(intent),
    })
}

/// Extracts a [`ToolCallIntent`] from the tool arguments.
fn build_tool_intent(
    arguments: &serde_json::Map<String, serde_json::Value>,
) -> Option<ToolCallIntent> {
    let intent_obj = arguments.get("intent")?.as_object()?;
    let expected_delta = intent_obj
        .get("expected_delta")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let cheaper_route_insufficient = intent_obj
        .get("cheaper_route_insufficient")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let budget = intent_obj
        .get("budget")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let stop_conditions = intent_obj
        .get("stop_conditions")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let retry_conditions = intent_obj
        .get("retry_conditions")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)?;
    let operation_identity = intent_obj
        .get("operation_identity")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    ToolCallIntent::new(
        expected_delta,
        cheaper_route_insufficient,
        budget,
        stop_conditions,
        retry_conditions,
        operation_identity,
    )
    .ok()
}

/// Pre-dispatch gate: validates the tool call intent before dispatch.
///
/// # Errors
///
/// Returns [`eliot_receipts::ToolExposureError`] when the intent is missing,
/// malformed, or lacks required operation identity.
pub(crate) fn authorize_pre_dispatch(
    request: &ToolCallRequest,
) -> Result<(), eliot_receipts::ToolExposureError> {
    eliot_receipts::authorize_pre_dispatch(request)
}

/// Returns whether the tool class requires an intent before dispatch.
pub(crate) fn requires_intent(name: &str) -> bool {
    call_class(name).is_some_and(eliot_receipts::ToolCallClass::requires_intent)
}

/// Reports a staging-time loop/no-progress signal for a materially repeated call.
///
/// Rebuilds each retained candidate's [`ToolCallRequest`] from its staged
/// envelope and tool bytes and applies
/// [`eliot_receipts::detect_repeat_without_progress`] against the staging
/// candidate. Returns the first [`LoopSignal`] when tool definition, route
/// fingerprint, and inputs are identical without a new expected delta, and
/// `None` for non-expensive tools, unreconstructible pairs, or fresh
/// inputs/routes/deltas. Pure and total: reads only, never stages, never fails.
pub(crate) fn staged_repeat_without_progress<'a>(
    mut retained: impl Iterator<
        Item = (
            &'a eliot_protocol::HostRequestEnvelope,
            &'a serde_json::Value,
        ),
    >,
    current: &ToolCallRequest,
) -> Option<LoopSignal> {
    retained.find_map(|(envelope, tool)| {
        let previous = build_tool_call_request(envelope, tool)?;
        eliot_receipts::detect_repeat_without_progress(&previous, current)
    })
}
