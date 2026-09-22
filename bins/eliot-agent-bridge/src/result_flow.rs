//! Issue #1941 result flow: measured tool-result delivery joining exact
//! result bytes, the admitted route's provider model, the live route
//! observation, and the current admission plus execution binding.
//!
//! The codex adapter measures exact result bytes with the route's actual
//! tokenizer
//! ([`measure_result_tokens`](eliot_agent_codex::route_tokenizer::measure_result_tokens));
//! the bridge core verifies the attestation and projects the receipt
//! ([`AgentBridgeCore::project_produced_tool_result`]). Neither crate may
//! depend on the other — provider-side measurement never depends on surface
//! contracts, and the surface never runs a tokenizer — so the join lives
//! here: this bridge crate already depends on the core and is the layer
//! that holds the Invoke callsite. All join logic stays in this module; no
//! parallel measurement types, facades, or `From` bridges are introduced —
//! every boundary type is the canonical owner type.
//!
//! Call chain (exact):
//!
//! ```text
//! record_measured_tool_result_delivery(outcome, inputs)        [lib.rs hook]
//! → supported outcome only (Responded + Candidate/Projection, else None)
//! → canonical content bytes (serde_json, else None)
//! → measure_and_project_tool_result(core, bytes, inputs)      [this module]
//!   → measure_result_tokens(model_id, bytes)
//!     else UnmeasuredTokens{NoObservation} (withhold, never estimate)
//!   → TokenMeasurementPayload{contract_version: v1, observation,
//!       result_digest: measured digest, tokens: measured count}
//!   → core.project_produced_tool_result(bytes, handle, Some(payload),
//!       admission, binding, delivery)
//!     (NotAttached | InvalidContract | UnmeasuredTokens propagate)
//! → Ok(receipt) for the attaching caller; auxiliary hook maps to None
//!   without affecting forwarding.
//! ```
//!
//! Measurement withhold (unknown/community-only model, non-text bytes,
//! unavailable tokenizer) maps to [`UnmeasuredReason::NoObservation`]: the
//! route supports no measurement on this delivery, so the view-only
//! evidence snapshot stands and no count is ever estimated. A measurement
//! that succeeds but fails intake verification (digest, admission linkage,
//! route state) withholds with the intake's own reason.

use eliot_agent_api::{
    AdmittedRouteReceipt, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
};
use eliot_agent_bridge_core::{
    AgentBridgeCore, BridgeError, DeliveryStatus, ResourceUri, TOKEN_MEASUREMENT_VERSION,
    TokenMeasurementPayload, ToolResultReceipt, UnmeasuredReason,
};
use eliot_agent_codex::route_tokenizer::measure_result_tokens;

/// Live inputs for one measured tool-result delivery.
///
/// The bridge cannot source any of these itself: the exact provider model
/// string comes from the admitted route, the observation from the route
/// owner at render time, the admission and execution binding from the
/// current admission/binding authorities, the source handle from the
/// C3-recorded view, and delivery from the owner's observed completeness.
/// All are borrowed — this flow mints nothing.
#[derive(Clone, Debug)]
pub struct ResultFlowInputs<'a> {
    /// Exact provider model string of the admitted route, verbatim (the
    /// owner gate withholds community-only and unknown IDs).
    pub model_id: &'a str,
    /// Live route observation, passed through unmodified into the payload.
    pub observation: &'a PhysicalRouteObservationReceipt,
    /// Current admission the observation must link against.
    pub admission: &'a AdmittedRouteReceipt,
    /// Live execution binding the observation must link against.
    pub binding: &'a ProviderExecutionBinding,
    /// Admissible source handle for the receipt (C3-recorded view handle).
    pub source_handle: ResourceUri,
    /// Owner-observed delivery completeness.
    pub delivery: DeliveryStatus,
}

/// Measures exact result bytes with the admitted route's actual tokenizer
/// and projects the byte-bound delivery receipt.
///
/// The measured digest and count enter the versioned wire payload; the core
/// re-verifies admission linkage, route state, and byte binding at intake
/// and passes the attested count through unaltered.
///
/// # Errors
///
/// Returns [`BridgeError::UnmeasuredTokens`] when the route supports no
/// measurement on this delivery (withheld model or bytes) or when the
/// attestation fails intake verification; [`BridgeError::InvalidContract`]
/// for malformed payload/admission/binding inputs; [`BridgeError::NotAttached`]
/// while detached.
pub fn measure_and_project_tool_result(
    core: &AgentBridgeCore,
    result_bytes: &[u8],
    inputs: &ResultFlowInputs<'_>,
) -> Result<ToolResultReceipt, BridgeError> {
    let measured = measure_result_tokens(inputs.model_id, result_bytes).map_err(|_| {
        BridgeError::UnmeasuredTokens {
            reason: UnmeasuredReason::NoObservation,
        }
    })?;
    let payload = TokenMeasurementPayload {
        contract_version: TOKEN_MEASUREMENT_VERSION,
        observation: inputs.observation.clone(),
        result_digest: measured.result_digest().to_owned(),
        tokens: measured.tokens(),
    };
    core.project_produced_tool_result(
        result_bytes,
        inputs.source_handle.clone(),
        Some(&payload),
        inputs.admission,
        inputs.binding,
        inputs.delivery,
    )
}
