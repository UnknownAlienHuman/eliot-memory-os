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
use eliot_receipts::{
    LoopSignal, ToolCallClass, ToolCallIntent, ToolCallRequest,
    tool_exposure::{AttemptEvidence, detect_repeat_without_progress_with_evidence},
};

use super::host_request_route::LocalReadAdmission;

/// Route fingerprint for tool calls admitted through the local-read boundary.
///
/// The fingerprint joins the authenticated envelope session, authority epoch,
/// and resource generation with the admitted campaign task identity when the
/// accepted method carries one. A campaign packet re-requested under a new
/// task revision is new work, not a material repeat, while the same packet
/// under the same task revision keeps its repeat identity. The task identity
/// comes from the accepted [`LocalReadAdmission`] — never caller tool text —
/// so the repeat join stays admission-derived exactly like the call class.
fn route_fingerprint(
    envelope: &eliot_protocol::HostRequestEnvelope,
    admission: &LocalReadAdmission,
) -> String {
    let session = envelope
        .identity
        .session_id
        .as_deref()
        .unwrap_or("unknown-session");
    let base = format!(
        "{}:{:?}:{:?}",
        session, envelope.state_fence.authority_epoch, envelope.state_fence.resource_generation
    );
    match admission {
        LocalReadAdmission::CampaignPacket {
            task_id,
            task_revision,
            ..
        } => format!("{base}:packet:{task_id}:{task_revision}"),
        LocalReadAdmission::Query(_) | LocalReadAdmission::Skill => base,
    }
}

/// Derives the tool call class from the accepted Kernel admission.
///
/// Tool names, descriptions, and shell substrings never define call
/// semantics: the class comes from the admitted method. The bounded evidence
/// query is broad-search, an exact Skill lifecycle tool is expensive, and a
/// task-bound campaign packet is effect-capable. A name outside the admitted
/// set never reaches classification; admission fails closed first.
pub(crate) fn call_class(admission: &LocalReadAdmission) -> ToolCallClass {
    match admission {
        LocalReadAdmission::Query(_) => ToolCallClass::BroadSearch,
        LocalReadAdmission::Skill => ToolCallClass::Expensive,
        LocalReadAdmission::CampaignPacket { .. } => ToolCallClass::EffectCapable,
    }
}

/// Computes the SHA-256 identity digest over the effective call inputs.
///
/// The caller-declared `intent` block is stripped before canonicalization:
/// it is gate justification, not tool inputs. Folding justification text
/// into the identity would let a reworded `expected_delta` change the
/// digest and evade the evidence-bound repeat comparison as a
/// never-before-seen call, which step 5 forbids — a reworded delta alone
/// is not progress. Retries that advance real inputs still hash
/// differently and stay fresh; retries that change only justification
/// keep the identity and meet the [`LoopSignal::NoProgress`] arm unless
/// owner-observed evidence advanced.
fn inputs_digest(tool: &serde_json::Value) -> Result<String, serde_json::Error> {
    let mut canonical = tool.clone();
    if let Some(object) = canonical.as_object_mut()
        && let Some(arguments) = object
            .get_mut("arguments")
            .and_then(serde_json::Value::as_object_mut)
    {
        arguments.remove("intent");
    }
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(sha256_hex(&bytes))
}

/// Builds a [`ToolCallRequest`] from the admitted envelope, tool, and accepted admission.
///
/// The cost/effect class derives from `admission` — the accepted method —
/// never from the caller-supplied name string. The versioned tool definition
/// identity still names the invoked tool; classification does not. The route
/// fingerprint likewise joins the admitted campaign task identity for packet
/// methods, so a new task revision is new work rather than a material repeat.
/// The inputs digest covers the effective call inputs with the caller-declared
/// `intent` block stripped, so a reworded `expected_delta` keeps the repeat
/// identity and meets the evidence-bound comparison instead of hashing as
/// fresh inputs.
pub(crate) fn build_tool_call_request(
    envelope: &eliot_protocol::HostRequestEnvelope,
    tool: &serde_json::Value,
    admission: &LocalReadAdmission,
) -> Option<ToolCallRequest> {
    let name = tool.as_object()?.get("name")?.as_str()?.to_owned();
    let class = call_class(admission);
    let arguments = tool.as_object()?.get("arguments")?.as_object()?;
    let intent = build_tool_intent(arguments)?;
    let digest = inputs_digest(tool).ok()?;
    Some(ToolCallRequest {
        tool_definition: name,
        route_fingerprint: route_fingerprint(envelope, admission),
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

/// Returns whether the accepted admission requires an intent before dispatch.
///
/// The answer reads off the admission-derived class, so cheap exact reads
/// stay exempt by construction while every currently admitted method —
/// broad-search query, expensive Skill lifecycle tool, effect-capable
/// campaign packet — carries an intent.
pub(crate) fn requires_intent(admission: &LocalReadAdmission) -> bool {
    call_class(admission).requires_intent()
}

/// Returns whether the accepted admission dispatches Material effects and
/// therefore requires live Governor-issued material authority before
/// dispatch.
///
/// The answer reads off the admission-derived class, so cheap exact reads
/// stay exempt by construction while the effect-capable campaign packet —
/// the only currently admitted Material lane — always requires it. The
/// class derives from the accepted admission, never from the tool name, so
/// a hidden effect-capable method invoked by name faces the identical
/// requirement: advertisement is neither a capability grant nor a security
/// boundary.
pub(crate) fn requires_material_authority(admission: &LocalReadAdmission) -> bool {
    matches!(admission, LocalReadAdmission::CampaignPacket { .. })
}

/// Re-joins the live Governor-issued material authority for one accepted
/// effect-capable (Material) admission before it dispatches.
///
/// This is the tool-lane revalidation of the envelope-level material gate:
/// it runs the single production gate behind every Material effect
/// ([`super::KernelComposition::admit_material_authority_for_governor_issued_fence`])
/// against the same live Governor derivation, so a missing derivation or a
/// revocation that landed after envelope admission still fails the
/// effect-capable lane closed. Read-only admissions are exempt by
/// construction ([`requires_material_authority`]); no second catalogue or
/// authorization service is consulted.
///
/// # Errors
///
/// Returns [`super::TransportError::SessionFenced`] when the admission is
/// Material and no current Governor-derived coverage profile admits it.
pub(crate) fn authorize_material_lane(
    composition: &super::KernelComposition,
    admission: &LocalReadAdmission,
    fence: &eliot_contracts::StateFence,
) -> Result<(), super::TransportError> {
    if !requires_material_authority(admission) {
        return Ok(());
    }
    composition
        .admit_material_authority_for_governor_issued_fence(fence)
        .map_err(|_| super::TransportError::SessionFenced)
}

/// Reports a staging-time loop/no-progress signal for a materially repeated call.
///
/// Each retained candidate is rebuilt into a [`ToolCallRequest`] through the
/// existing admission owner
/// ([`super::host_request_route::check_local_read_admission`]), so the
/// cost/effect class derives from the accepted admission exactly as it does
/// for the staging candidate; unreconstructible pairs never match. The
/// retained per-route stage is the existing attempt history — no new loop
/// ledger — and the comparison is the evidence-bound
/// [`detect_repeat_without_progress_with_evidence`] join. The compared
/// inputs digest excludes caller-declared intent text by construction
/// ([`build_tool_call_request`]), so a reworded `expected_delta` keeps the
/// repeat identity and yields [`LoopSignal::NoProgress`], never a fresh
/// staging as progress.
///
/// No owner-observed evidence is joined at this gate: payloads travel by
/// digest only, so the source revision, poll cursor, and prior outcome the
/// issue names are unobserved here rather than invented. An unobserved
/// dimension is never new evidence, so a reworded `expected_delta` alone
/// yields [`LoopSignal::NoProgress`] instead of staging as progress. Only
/// genuinely advanced owner evidence — joined by the evidence owners, never
/// inferred here — counts as potential progress.
///
/// Pure and total: reads only, never stages, never fails. Exact-idempotent
/// replay, required unknown-effect reconciliation, and admitted polling keep
/// their own semantics at their owners; the signal only refuses a materially
/// repeated staging, never permission to execute again.
pub(crate) fn staged_repeat_without_progress<'a>(
    mut retained: impl Iterator<
        Item = (
            &'a eliot_protocol::HostRequestEnvelope,
            &'a serde_json::Value,
        ),
    >,
    current: &ToolCallRequest,
) -> Option<LoopSignal> {
    // Both sides carry no owner-observed evidence at this gate: the staging
    // path holds digest-bound pairs only, and inventing a revision, cursor,
    // or outcome to obtain a valid-looking pass is forbidden.
    let unobserved = AttemptEvidence {
        source_revision: None,
        poll_cursor: None,
        prior_outcome: None,
    };
    retained.find_map(|(envelope, tool)| {
        let admission =
            super::host_request_route::check_local_read_admission(envelope, tool).ok()?;
        let previous = build_tool_call_request(envelope, tool, &admission)?;
        detect_repeat_without_progress_with_evidence(&previous, &unobserved, current, &unobserved)
    })
}
