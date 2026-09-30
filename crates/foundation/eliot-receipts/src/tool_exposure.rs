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

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), ToolExposureError> {
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

pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), ToolExposureError> {
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
    /// Lowercase SHA-256 over canonical call inputs, excluding
    /// caller-declared intent text: builders must hash the effective tool
    /// inputs so a reworded `expected_delta` keeps the repeat identity and
    /// meets the evidence-bound comparison instead of evading it as fresh
    /// inputs.
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

/// Compares caller-declared expected-delta text for two otherwise identical calls.
///
/// Returns a [`LoopSignal`] when tool definition, route fingerprint, and
/// inputs digest are identical and the current call carries no new
/// expected-delta *text*. A current call whose delta text differs returns
/// `None`, but that is undecided — not progress. A reworded delta alone is
/// not new evidence, state transition, or effect, and this shape-only
/// comparison observes none of those dimensions. Repeat detection that must
/// treat a reworded delta as no-progress belongs to
/// [`detect_repeat_without_progress_with_evidence`], which joins the actual
/// source revision, pagination/poll cursor, and prior outcome before any
/// delta counts as potential progress.
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

/// Owner-observed evidence joined to one tool-call attempt for repeat detection.
///
/// The joined dimensions are the step-5 identity join minus the
/// caller-declared delta already carried by [`ToolCallRequest`]: the actual
/// source revision the attempt read, the pagination/poll cursor it consumed,
/// and the prior attempt outcome it reconciles. `None` in any field means
/// that dimension was unobserved for the attempt — never new evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttemptEvidence {
    /// Actual source revision observed by the attempt, when known.
    pub source_revision: Option<String>,
    /// Pagination or poll cursor consumed by the attempt, when known.
    pub poll_cursor: Option<String>,
    /// Prior attempt outcome this attempt reconciles, when known.
    pub prior_outcome: Option<String>,
}

impl AttemptEvidence {
    /// Validates observed evidence text without executing anything.
    ///
    /// # Errors
    ///
    /// Returns an error when an observed dimension is blank or carries
    /// control characters.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if let Some(revision) = &self.source_revision {
            text(revision, "evidence.source_revision")?;
        }
        if let Some(cursor) = &self.poll_cursor {
            text(cursor, "evidence.poll_cursor")?;
        }
        if let Some(outcome) = &self.prior_outcome {
            text(outcome, "evidence.prior_outcome")?;
        }
        Ok(())
    }
}

/// Detects a materially repeated call without new evidence or state.
///
/// The identity join comes first: tool definition, route fingerprint, and
/// inputs digest must be identical or the calls are not repeats and this
/// returns `None`. A repeat then emits a bounded [`LoopSignal`] unless the
/// current attempt carries genuinely new evidence — an observed source
/// revision, poll cursor, or prior outcome the previous attempt did not
/// carry.
///
/// A reworded `expected_delta` alone is not progress: when the joined
/// evidence dimensions are identical or unobserved on both sides, a changed
/// delta string yields `Some(LoopSignal::NoProgress)`. Only advanced
/// evidence returns `None`, and even then only as *potential* progress —
/// each stage is reported separately, never inferred.
///
/// Exact-idempotent replay, required unknown-effect reconciliation, and
/// admitted polling keep their own semantics at their owners; this signal is
/// evidence for the caller to reconcile, not permission to execute again or
/// to suppress a legitimate retry.
#[must_use]
pub fn detect_repeat_without_progress_with_evidence(
    previous: &ToolCallRequest,
    previous_evidence: &AttemptEvidence,
    current: &ToolCallRequest,
    current_evidence: &AttemptEvidence,
) -> Option<LoopSignal> {
    if previous.tool_definition != current.tool_definition
        || previous.route_fingerprint != current.route_fingerprint
        || previous.inputs_digest != current.inputs_digest
    {
        return None;
    }
    if evidence_advanced(previous_evidence, current_evidence) {
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
        _ => Some(LoopSignal::NoProgress),
    }
}

/// Returns whether the current attempt observed evidence the previous attempt
/// did not carry: a new source revision, poll cursor, or prior outcome.
fn evidence_advanced(previous: &AttemptEvidence, current: &AttemptEvidence) -> bool {
    dimension_advanced(
        previous.source_revision.as_ref(),
        current.source_revision.as_ref(),
    ) || dimension_advanced(previous.poll_cursor.as_ref(), current.poll_cursor.as_ref())
        || dimension_advanced(
            previous.prior_outcome.as_ref(),
            current.prior_outcome.as_ref(),
        )
}

/// One joined dimension counts as advanced only when the current attempt
/// observed a value the previous attempt did not carry. An unobserved
/// current dimension is never new evidence, even against an unobserved
/// previous one.
fn dimension_advanced(previous: Option<&String>, current: Option<&String>) -> bool {
    match (previous, current) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(previous_value), Some(current_value)) => previous_value != current_value,
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

/// Explicitly versioned exposure receipt that separates an executed result
/// from the representation delivered to a consumer.
///
/// `ToolExposureReceipt` remains the legacy V1 wire contract. V2 does not
/// reinterpret its `result_digest` or `exact_token_cost` fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolExposureReceiptV2 {
    /// Wire contract revision. Must equal [`TOOL_EXPOSURE_RECEIPT_V2_VERSION`].
    pub schema_version: u16,
    /// Stable identity of this immutable exposure receipt.
    pub receipt_id: String,
    /// Versioned tool definition identity.
    pub tool_definition: String,
    /// Route fingerprint the tool was evaluated on.
    pub route_fingerprint: String,
    /// The tool version is registered; `None` means unobserved.
    pub registered: Option<bool>,
    /// The tool was advertised to the route; `None` means unobserved.
    pub advertised_to_route: Option<bool>,
    /// The tool was eligible under scope, policy, and grant; `None` means unobserved.
    pub eligible_under_scope_policy_and_grant: Option<bool>,
    /// The planner or model selected the tool; `None` means unobserved.
    pub selected_by_planner_or_model: Option<bool>,
    /// The tool was called; `None` means unobserved.
    pub called: Option<bool>,
    /// Transport for the call completed; `None` means unobserved.
    pub transport_completed: Option<bool>,
    /// Delivery completeness, independent of execution and transport completion.
    pub result_delivery: ResultDelivery,
    /// Identity and digest of the produced execution result, if one was retained.
    pub produced_result: Option<ProducedToolResultIdentity>,
    /// Exact rendered representation evidence; absent only when delivery is missing.
    pub delivered_representation: Option<DeliveredToolRepresentation>,
    /// The call was expanded or retried; `None` means unobserved.
    pub expanded_or_retried: Option<bool>,
    /// The result was observably used in a decision, action, or verifier; `None` means unobserved.
    pub observably_used_in_decision_action_or_verifier: Option<bool>,
    /// Terminal task or product outcome reference, when known.
    pub terminal_task_or_product_outcome_ref: Option<String>,
}

/// Wire version for [`ToolExposureReceiptV2`].
pub const TOOL_EXPOSURE_RECEIPT_V2_VERSION: u16 = 2;

/// Retained identity of a result produced by execution, independently of delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProducedToolResultIdentity {
    /// Exact artifact digest for the produced result.
    pub result_digest: String,
    /// Stable artifact identity, when the result has one.
    pub artifact_ref: Option<String>,
    /// Admissible source handle for retrieving the produced result, when available.
    pub source_handle: Option<String>,
}

/// Exact representation delivered to the consumer boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveredToolRepresentation {
    /// Digest of the exact rendered/delivered representation bytes.
    pub representation_digest: String,
    /// Admissible handle for the delivered representation.
    pub source_handle: String,
    /// Exact number of delivered representation bytes.
    pub byte_count: u64,
    /// Token observation bound to the delivered representation.
    pub token_observation: TokenCountObservation,
    /// Prior receipt identity when this is a later authorized expansion delivery.
    pub prior_delivery_receipt_id: Option<String>,
}

/// Token measurement for exact delivered bytes, or explicit measurement uncertainty.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum TokenCountObservation {
    /// Exact owner-reported token count bound to the representation digest.
    Observed {
        /// Exact token count reported by the actual route tokenizer.
        exact_token_cost: u64,
        /// Digest of the exact representation counted by the tokenizer.
        representation_digest: String,
        /// Reference to the owner attestation for this digest and count.
        tokenizer_evidence_ref: String,
    },
    /// Token count was not observed; this is not a zero-token measurement.
    Unavailable {
        /// Why the exact token count is unavailable.
        reason: TokenCountUnavailableReason,
    },
}

/// Bounded reasons an exact token observation may be unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TokenCountUnavailableReason {
    /// The actual route tokenizer was unavailable.
    TokenizerUnavailable,
    /// The count was not supplied by its observation owner.
    MeasurementUnavailable,
}

impl ToolExposureReceiptV2 {
    /// Validates V2 identities and delivery evidence without inferring unknown stages.
    ///
    /// A missing delivery may retain a produced result. Non-missing deliveries
    /// require an exact representation digest, source handle, and byte count;
    /// token measurement may remain explicitly unavailable. This local shape
    /// validator does not verify external artifact or prior-receipt references.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, malformed digest,
    /// blank identity/reference, or inconsistent delivery evidence.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if self.schema_version != TOOL_EXPOSURE_RECEIPT_V2_VERSION {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.schema_version",
                reason: "unsupported tool exposure schema version",
            });
        }
        text(&self.receipt_id, "receipt.receipt_id")?;
        text(&self.tool_definition, "receipt.tool_definition")?;
        text(&self.route_fingerprint, "receipt.route_fingerprint")?;
        if let Some(result) = &self.produced_result {
            digest(
                &result.result_digest,
                "receipt.produced_result.result_digest",
            )?;
            if let Some(reference) = &result.artifact_ref {
                text(reference, "receipt.produced_result.artifact_ref")?;
            }
            if let Some(handle) = &result.source_handle {
                text(handle, "receipt.produced_result.source_handle")?;
            }
        }
        match (&self.result_delivery, &self.delivered_representation) {
            (ResultDelivery::Missing, None) => {}
            (ResultDelivery::Missing, Some(_)) => {
                return Err(ToolExposureError::InvalidField {
                    field: "receipt.delivered_representation",
                    reason: "missing delivery cannot carry rendered representation evidence",
                });
            }
            (ResultDelivery::Full | ResultDelivery::Partial | ResultDelivery::Truncated, None) => {
                return Err(ToolExposureError::InvalidField {
                    field: "receipt.delivered_representation",
                    reason: "non-missing delivery requires rendered representation evidence",
                });
            }
            (
                ResultDelivery::Full | ResultDelivery::Partial | ResultDelivery::Truncated,
                Some(representation),
            ) => {
                digest(
                    &representation.representation_digest,
                    "receipt.delivered_representation.representation_digest",
                )?;
                text(
                    &representation.source_handle,
                    "receipt.delivered_representation.source_handle",
                )?;
                match &representation.token_observation {
                    TokenCountObservation::Observed {
                        representation_digest,
                        tokenizer_evidence_ref,
                        ..
                    } => {
                        digest(
                            representation_digest,
                            "receipt.delivered_representation.tokenizer_representation_digest",
                        )?;
                        if representation_digest != &representation.representation_digest {
                            return Err(ToolExposureError::InvalidField {
                                field: "receipt.delivered_representation.tokenizer_representation_digest",
                                reason: "token observation must bind the delivered representation digest",
                            });
                        }
                        text(
                            tokenizer_evidence_ref,
                            "receipt.delivered_representation.tokenizer_evidence_ref",
                        )?;
                    }
                    TokenCountObservation::Unavailable { .. } => {}
                }
                if let Some(prior_id) = &representation.prior_delivery_receipt_id {
                    text(
                        prior_id,
                        "receipt.delivered_representation.prior_delivery_receipt_id",
                    )?;
                    if prior_id == &self.receipt_id {
                        return Err(ToolExposureError::InvalidField {
                            field: "receipt.delivered_representation.prior_delivery_receipt_id",
                            reason: "delivery receipt cannot link to itself",
                        });
                    }
                }
            }
        }
        if let Some(reference) = &self.terminal_task_or_product_outcome_ref {
            text(reference, "receipt.terminal_task_or_product_outcome_ref")?;
        }
        Ok(())
    }

    /// Whether a valid complete result delivery and transport completion were observed.
    ///
    /// Unknown observations do not qualify. A `TRUNCATED`, `PARTIAL`, or
    /// `MISSING` delivery cannot satisfy complete-evidence requirements. Local
    /// receipt validation does not establish external reference authority.
    #[must_use]
    pub fn is_delivered_full(&self) -> bool {
        self.validate().is_ok()
            && matches!(self.called, Some(true))
            && matches!(self.transport_completed, Some(true))
            && matches!(self.result_delivery, ResultDelivery::Full)
            && self.delivered_representation.is_some()
    }

    /// Whether a complete delivery was observably used in a public decision, action, or verifier.
    #[must_use]
    pub fn is_evidence_used(&self) -> bool {
        self.is_delivered_full()
            && matches!(
                self.observably_used_in_decision_action_or_verifier,
                Some(true)
            )
    }

    /// Builds the per-evaluation admission skeleton for one authorized request.
    ///
    /// Only the stages this boundary observes are set: eligibility and
    /// selection hold because the authorized request was presented for
    /// dispatch and admitted. Registration, advertisement, call, transport,
    /// retry, use, and terminal stages stay `None` (unobserved, never
    /// inferred), delivery is `MISSING` with no digest or token cost, and no
    /// representation evidence is attached. Measurement owners populate the
    /// remaining stages; this constructor never invents them.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity is blank.
    pub fn admission_observed(
        receipt_id: String,
        tool_definition: String,
        route_fingerprint: String,
    ) -> Result<Self, ToolExposureError> {
        let receipt = Self {
            schema_version: TOOL_EXPOSURE_RECEIPT_V2_VERSION,
            receipt_id,
            tool_definition,
            route_fingerprint,
            registered: None,
            advertised_to_route: None,
            eligible_under_scope_policy_and_grant: Some(true),
            selected_by_planner_or_model: Some(true),
            called: None,
            transport_completed: None,
            result_delivery: ResultDelivery::Missing,
            produced_result: None,
            delivered_representation: None,
            expanded_or_retried: None,
            observably_used_in_decision_action_or_verifier: None,
            terminal_task_or_product_outcome_ref: None,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Records a token-truncated delivery on an evaluated receipt.
    ///
    /// The completed call keeps `transport_completed` as `Some(true)` while
    /// `result_delivery` becomes `TRUNCATED`, reusing the existing
    /// [`ResultDelivery`] outcome rather than a new type. Produced identity
    /// and the exact delivered representation (with its token observation)
    /// must be supplied by their observation owners; nothing is inferred. A
    /// truncated receipt never satisfies [`Self::is_delivered_full`] or
    /// [`Self::is_evidence_used`].
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt already records the call as
    /// not-called, when transport is already recorded as not completed, or
    /// when the resulting receipt is inconsistent.
    pub fn record_truncated_delivery(
        mut self,
        produced: ProducedToolResultIdentity,
        delivered: DeliveredToolRepresentation,
    ) -> Result<Self, ToolExposureError> {
        if matches!(self.called, Some(false)) {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.called",
                reason: "a truncated delivery requires an executed call",
            });
        }
        if matches!(self.transport_completed, Some(false)) {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.transport_completed",
                reason: "a truncated delivery requires completed transport",
            });
        }
        self.called = Some(true);
        self.transport_completed = Some(true);
        self.result_delivery = ResultDelivery::Truncated;
        self.produced_result = Some(produced);
        self.delivered_representation = Some(delivered);
        self.validate()?;
        Ok(self)
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
