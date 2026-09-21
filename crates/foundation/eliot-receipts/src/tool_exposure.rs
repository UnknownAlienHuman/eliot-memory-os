//! Expensive tool-call intent gate and exposure receipt for I7.24.
//!
//! This module is the orchestration-boundary contract for tool surface economy
//! and cognitive exposure. It owns no transport, execution, persistence, or
//! finish authority. It validates a lightweight [`ToolCallIntent`] before
//! dispatch, signals repeated calls without a new expected delta, and records
//! a [`ToolExposureReceipt`] whose delivery and use fields stay orthogonal:
//! an advertised tool may remain ineligible, a completed call may deliver a
//! truncated result, and a delivered result may be unused.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Validation failure for tool intent and exposure records.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ToolExposureError {
    /// A required text field was blank or carried control characters.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    /// An expensive-class call arrived without an intent.
    #[error("tool call requires an intent before dispatch")]
    IntentRequired,
    /// An effect-capable call arrived without durable operation identity.
    #[error("effect-capable tool call requires a durable operation identity")]
    OperationIdentityRequired,
    /// A materially repeated call carried no new expected delta.
    #[error("repeated tool call without a new expected delta: {signal:?}")]
    NoProgress { signal: LoopSignal },
}

fn text(value: &str, field: &'static str) -> Result<(), ToolExposureError> {
    if value.trim().is_empty() {
        return Err(ToolExposureError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ToolExposureError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ToolExposureError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ToolExposureError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 hex digest",
        });
    }
    Ok(())
}

/// Cost and effect class of one tool call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ToolCallClass {
    /// Cheap exact read; exempt from the intent gate.
    CheapExactRead,
    /// Costly call that must carry an intent.
    Expensive,
    /// Model-backed call that must carry an intent.
    ModelBacked,
    /// Swarm/fan-out call that must carry an intent.
    Swarm,
    /// Network call that must carry an intent.
    Network,
    /// Broad search that must carry an intent.
    BroadSearch,
    /// Effect-capable call that must carry an intent plus operation identity.
    EffectCapable,
}

impl ToolCallClass {
    /// Whether the class requires an intent before dispatch.
    #[must_use]
    pub const fn requires_intent(self) -> bool {
        !matches!(self, Self::CheapExactRead)
    }

    /// Whether the class requires durable operation identity in its intent.
    #[must_use]
    pub const fn requires_operation_identity(self) -> bool {
        matches!(self, Self::EffectCapable)
    }
}

/// Lightweight intent carried by expensive-class calls.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolCallIntent {
    /// Expected evidence, decision, artifact, or proof delta.
    pub expected_delta: String,
    /// Why a cheaper cached or exact route is insufficient.
    pub cheaper_route_insufficient: String,
    /// Budget bound for the call.
    pub budget: String,
    /// Stop conditions for the call.
    pub stop_conditions: String,
    /// Retry conditions for the call.
    pub retry_conditions: String,
    /// Durable operation identity; required for effect-capable calls.
    pub operation_identity: Option<String>,
}

impl ToolCallIntent {
    /// Validates every intent field without executing anything.
    ///
    /// Text fields are stored trimmed so materially identical deltas with
    /// stray surrounding whitespace still compare equal in
    /// [`detect_repeat_without_progress`] instead of evading the
    /// loop/no-progress signal.
    ///
    /// # Errors
    ///
    /// Returns an error when any required field is blank, carries control
    /// characters, or holds a blank operation identity.
    pub fn new(
        expected_delta: impl Into<String>,
        cheaper_route_insufficient: impl Into<String>,
        budget: impl Into<String>,
        stop_conditions: impl Into<String>,
        retry_conditions: impl Into<String>,
        operation_identity: Option<String>,
    ) -> Result<Self, ToolExposureError> {
        let intent = Self {
            expected_delta: expected_delta.into().trim().to_owned(),
            cheaper_route_insufficient: cheaper_route_insufficient.into().trim().to_owned(),
            budget: budget.into().trim().to_owned(),
            stop_conditions: stop_conditions.into().trim().to_owned(),
            retry_conditions: retry_conditions.into().trim().to_owned(),
            operation_identity: operation_identity.map(|identity| identity.trim().to_owned()),
        };
        intent.validate()?;
        Ok(intent)
    }

    /// Validates the intent fields.
    ///
    /// # Errors
    ///
    /// Returns an error when a field is blank or carries control characters.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        text(&self.expected_delta, "intent.expected_delta")?;
        text(
            &self.cheaper_route_insufficient,
            "intent.cheaper_route_insufficient",
        )?;
        text(&self.budget, "intent.budget")?;
        text(&self.stop_conditions, "intent.stop_conditions")?;
        text(&self.retry_conditions, "intent.retry_conditions")?;
        if let Some(identity) = &self.operation_identity {
            text(identity, "intent.operation_identity")?;
        }
        Ok(())
    }
}

/// One tool call awaiting a pre-dispatch intent decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolCallRequest {
    /// Versioned tool definition identity.
    pub tool_definition: String,
    /// Route the call would execute on.
    pub route_fingerprint: String,
    /// Cost and effect class of the call.
    pub call_class: ToolCallClass,
    /// Lowercase SHA-256 over canonical call inputs.
    pub inputs_digest: String,
    /// Intent; required for every class except cheap exact reads.
    pub intent: Option<ToolCallIntent>,
}

impl ToolCallRequest {
    /// Validates identities, digest shape, and any attached intent.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is blank, the digest is malformed,
    /// or the attached intent is invalid.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        text(&self.tool_definition, "call.tool_definition")?;
        text(&self.route_fingerprint, "call.route_fingerprint")?;
        digest(&self.inputs_digest, "call.inputs_digest")?;
        if let Some(intent) = &self.intent {
            intent.validate()?;
        }
        Ok(())
    }
}

/// Pre-dispatch gate: rejects expensive-class calls without an intent.
///
/// Cheap exact reads pass without an intent. Every other class requires a
/// valid intent, and effect-capable calls additionally require durable
/// operation identity.
///
/// # Errors
///
/// Returns [`ToolExposureError::IntentRequired`] when an intent is missing,
/// [`ToolExposureError::OperationIdentityRequired`] when an effect-capable
/// call lacks operation identity, or [`ToolExposureError::InvalidField`]
/// when any field is malformed.
pub fn authorize_pre_dispatch(request: &ToolCallRequest) -> Result<(), ToolExposureError> {
    request.validate()?;
    if !request.call_class.requires_intent() {
        return Ok(());
    }
    let intent = request
        .intent
        .as_ref()
        .ok_or(ToolExposureError::IntentRequired)?;
    intent.validate()?;
    if request.call_class.requires_operation_identity() && intent.operation_identity.is_none() {
        return Err(ToolExposureError::OperationIdentityRequired);
    }
    Ok(())
}

/// Loop or no-progress signal for materially repeated calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoopSignal {
    /// Identical tool, route, inputs, and expected delta repeated.
    Loop,
    /// Identical tool, route, and inputs repeated with the delta dropped.
    NoProgress,
}

/// Detects a materially repeated call without a new expected delta.
///
/// Returns a [`LoopSignal`] when tool definition, route fingerprint, and
/// inputs digest are identical and the current call carries no new expected
/// delta. A current call that introduces a fresh expected delta returns
/// `None` and is treated as potential progress.
#[must_use]
pub fn detect_repeat_without_progress(
    previous: &ToolCallRequest,
    current: &ToolCallRequest,
) -> Option<LoopSignal> {
    if previous.tool_definition != current.tool_definition
        || previous.route_fingerprint != current.route_fingerprint
        || previous.inputs_digest != current.inputs_digest
    {
        return None;
    }
    let previous_delta = previous
        .intent
        .as_ref()
        .map(|intent| intent.expected_delta.as_str());
    let current_delta = current
        .intent
        .as_ref()
        .map(|intent| intent.expected_delta.as_str());
    match (previous_delta, current_delta) {
        (None, None) => Some(LoopSignal::Loop),
        (Some(previous_text), Some(current_text)) if previous_text == current_text => {
            Some(LoopSignal::Loop)
        }
        (Some(_), None) => Some(LoopSignal::NoProgress),
        (None | Some(_), Some(_)) => None,
    }
}

/// Completeness of one tool-result delivery, measured separately from
/// transport completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultDelivery {
    Full,
    Partial,
    Truncated,
    Missing,
}

/// Orthogonal exposure record for one evaluated turn or run.
///
/// The fields are not one success ladder: an advertised tool may never be
/// eligible, a completed call may deliver a truncated result, and a delivered
/// result may be unused.
///
/// The eight boolean stages are the I7.24-specified orthogonal observations,
/// not collapsible flags, so the pedantic bool-count lint is allowed here by
/// the same precedent used across `eliot-types` contract records.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolExposureReceipt {
    /// Versioned tool definition identity.
    pub tool_definition: String,
    /// Route fingerprint the tool was evaluated on.
    pub route_fingerprint: String,
    /// The tool version is registered.
    pub registered: bool,
    /// The tool was advertised to the route.
    pub advertised_to_route: bool,
    /// The tool was eligible under scope, policy, and grant.
    pub eligible_under_scope_policy_and_grant: bool,
    /// The planner or model selected the tool.
    pub selected_by_planner_or_model: bool,
    /// The tool was called.
    pub called: bool,
    /// Transport for the call completed.
    pub transport_completed: bool,
    /// Delivery completeness, independent of transport completion.
    pub result_delivery: ResultDelivery,
    /// Exact result digest; required unless delivery is missing.
    pub result_digest: Option<String>,
    /// Exact rendered token cost under the actual tokenizer.
    pub exact_token_cost: Option<u64>,
    /// The call was expanded or retried.
    pub expanded_or_retried: bool,
    /// The result was observably used in a decision, action, or verifier.
    pub observably_used_in_decision_action_or_verifier: bool,
    /// Terminal task or product outcome reference, when known.
    pub terminal_task_or_product_outcome_ref: Option<String>,
}

impl ToolExposureReceipt {
    /// Validates identities, digest and token presence, and outcome text.
    ///
    /// The check keeps availability and use orthogonal: no ladder is
    /// enforced between advertised, eligible, selected, called, delivered,
    /// and used states.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is blank, a digest is malformed, a
    /// required digest or token cost is absent, a missing delivery still
    /// carries payload identity, or the terminal reference is blank.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        text(&self.tool_definition, "receipt.tool_definition")?;
        text(&self.route_fingerprint, "receipt.route_fingerprint")?;
        match self.result_delivery {
            ResultDelivery::Full | ResultDelivery::Partial | ResultDelivery::Truncated => {
                let digest_value =
                    self.result_digest
                        .as_deref()
                        .ok_or(ToolExposureError::InvalidField {
                            field: "receipt.result_digest",
                            reason: "delivery without a digest cannot be measured",
                        })?;
                digest(digest_value, "receipt.result_digest")?;
                if self.exact_token_cost.is_none() {
                    return Err(ToolExposureError::InvalidField {
                        field: "receipt.exact_token_cost",
                        reason: "delivery without an exact token cost cannot be measured",
                    });
                }
            }
            ResultDelivery::Missing => {
                if self.result_digest.is_some() || self.exact_token_cost.is_some() {
                    return Err(ToolExposureError::InvalidField {
                        field: "receipt.result_digest",
                        reason: "missing delivery cannot carry a digest or token cost",
                    });
                }
            }
        }
        if let Some(reference) = &self.terminal_task_or_product_outcome_ref {
            text(reference, "receipt.terminal_task_or_product_outcome_ref")?;
        }
        Ok(())
    }

    /// Whether the result counts as delivered-full.
    ///
    /// Only a called, transport-completed, `FULL` delivery qualifies. A
    /// truncated or partial delivery never counts, even when transport
    /// completed.
    #[must_use]
    pub const fn is_delivered_full(&self) -> bool {
        self.called
            && self.transport_completed
            && matches!(self.result_delivery, ResultDelivery::Full)
    }

    /// Whether the result counts as evidence-used.
    ///
    /// Only a delivered-full result that was observably used qualifies. A
    /// truncated delivery or an unused result never counts.
    #[must_use]
    pub const fn is_evidence_used(&self) -> bool {
        self.is_delivered_full() && self.observably_used_in_decision_action_or_verifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_hex;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn digest_of(label: &[u8]) -> String {
        sha256_hex(label)
    }

    fn intent(delta: &str) -> Result<ToolCallIntent, ToolExposureError> {
        ToolCallIntent::new(
            delta,
            "cached route lacks the evidence dimension",
            "budget 1 call, stop on truncation, no retry without new delta",
            "stop when truncated or budget spent",
            "retry only with a new expected delta",
            None,
        )
    }

    fn request(
        class: ToolCallClass,
        inputs_digest: &str,
        intent: Option<ToolCallIntent>,
    ) -> ToolCallRequest {
        ToolCallRequest {
            tool_definition: "broad-search.v3".to_owned(),
            route_fingerprint: "route-fingerprint-1".to_owned(),
            call_class: class,
            inputs_digest: inputs_digest.to_owned(),
            intent,
        }
    }

    #[test]
    fn network_call_without_intent_rejected_pre_dispatch() -> TestResult {
        let missing = request(ToolCallClass::Network, &digest_of(b"inputs"), None);
        assert_eq!(
            authorize_pre_dispatch(&missing),
            Err(ToolExposureError::IntentRequired)
        );

        let effect_missing_identity = ToolCallRequest {
            intent: Some(intent("decision delta")?),
            ..request(ToolCallClass::EffectCapable, &digest_of(b"inputs"), None)
        };
        assert_eq!(
            authorize_pre_dispatch(&effect_missing_identity),
            Err(ToolExposureError::OperationIdentityRequired)
        );

        let admitted = request(
            ToolCallClass::Network,
            &digest_of(b"inputs"),
            Some(intent("decision delta")?),
        );
        assert_eq!(authorize_pre_dispatch(&admitted), Ok(()));

        let cheap = request(ToolCallClass::CheapExactRead, &digest_of(b"inputs"), None);
        assert_eq!(authorize_pre_dispatch(&cheap), Ok(()));
        Ok(())
    }

    #[test]
    fn identical_repeat_broad_search_yields_loop_or_no_progress() -> TestResult {
        let inputs = digest_of(b"broad-search-inputs");
        let first = request(
            ToolCallClass::BroadSearch,
            &inputs,
            Some(intent("candidate evidence delta")?),
        );
        let repeat_same_delta = request(
            ToolCallClass::BroadSearch,
            &inputs,
            Some(intent("candidate evidence delta")?),
        );
        assert_eq!(
            detect_repeat_without_progress(&first, &repeat_same_delta),
            Some(LoopSignal::Loop)
        );

        let dropped_delta = request(ToolCallClass::BroadSearch, &inputs, None);
        assert_eq!(
            detect_repeat_without_progress(&first, &dropped_delta),
            Some(LoopSignal::NoProgress)
        );

        let fresh_delta = request(
            ToolCallClass::BroadSearch,
            &inputs,
            Some(intent("a new decision delta")?),
        );
        assert_eq!(detect_repeat_without_progress(&first, &fresh_delta), None);

        // Stray surrounding whitespace does not evade the loop signal:
        // deltas are stored trimmed at construction.
        let padded_delta = request(
            ToolCallClass::BroadSearch,
            &inputs,
            Some(intent("  candidate evidence delta\n")?),
        );
        assert_eq!(
            detect_repeat_without_progress(&first, &padded_delta),
            Some(LoopSignal::Loop)
        );

        let changed_inputs = request(
            ToolCallClass::BroadSearch,
            &digest_of(b"other-inputs"),
            Some(intent("candidate evidence delta")?),
        );
        assert_eq!(
            detect_repeat_without_progress(&first, &changed_inputs),
            None
        );
        Ok(())
    }

    #[test]
    fn truncated_result_never_counts_as_delivered_full_or_evidence_used() -> TestResult {
        let receipt = ToolExposureReceipt {
            tool_definition: "broad-search.v3".to_owned(),
            route_fingerprint: "route-fingerprint-1".to_owned(),
            registered: true,
            advertised_to_route: true,
            eligible_under_scope_policy_and_grant: true,
            selected_by_planner_or_model: true,
            called: true,
            transport_completed: true,
            result_delivery: ResultDelivery::Truncated,
            result_digest: Some(digest_of(b"truncated-result")),
            exact_token_cost: Some(1_024),
            expanded_or_retried: false,
            observably_used_in_decision_action_or_verifier: false,
            terminal_task_or_product_outcome_ref: None,
        };
        receipt.validate()?;
        assert!(receipt.transport_completed);
        assert_eq!(receipt.result_delivery, ResultDelivery::Truncated);
        assert!(!receipt.is_delivered_full());
        assert!(!receipt.is_evidence_used());

        let unused_full = ToolExposureReceipt {
            result_delivery: ResultDelivery::Full,
            ..receipt.clone()
        };
        unused_full.validate()?;
        assert!(unused_full.is_delivered_full());
        assert!(!unused_full.is_evidence_used());

        let used_full = ToolExposureReceipt {
            result_delivery: ResultDelivery::Full,
            observably_used_in_decision_action_or_verifier: true,
            ..receipt.clone()
        };
        used_full.validate()?;
        assert!(used_full.is_delivered_full());
        assert!(used_full.is_evidence_used());
        Ok(())
    }
}
