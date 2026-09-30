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
    /// A Material dispatch arrived without a current grant standing.
    #[error("material dispatch requires a current grant")]
    GrantRequired,
    /// A Material dispatch arrived under a revoked grant.
    #[error("grant is revoked")]
    GrantRevoked,
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
    /// First delivery only: a receipt that already carries delivered
    /// representation evidence never has it overwritten here. A later
    /// authorized delivery for the same result links through
    /// [`Self::record_expanded_delivery`], which preserves the original
    /// truncation instead of rewriting it.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt already records the call as
    /// not-called, when transport is already recorded as not completed, when
    /// a delivery outcome was already recorded, or when the resulting receipt
    /// is inconsistent.
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
        if self.delivered_representation.is_some()
            || !matches!(self.result_delivery, ResultDelivery::Missing)
        {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation",
                reason: "recorded delivery evidence is never overwritten; later deliveries link through record_expanded_delivery",
            });
        }
        if delivered.prior_delivery_receipt_id.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation.prior_delivery_receipt_id",
                reason: "a first truncated delivery is not an expansion and carries no prior link",
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

    /// Records a first complete delivery on an evaluated receipt.
    ///
    /// The direct path from an unevaluated (`MISSING`, nothing recorded)
    /// receipt to `FULL`: the call keeps `transport_completed` as `Some(true)`
    /// while `result_delivery` becomes `FULL` with the produced identity and
    /// the exact delivered representation supplied by their observation
    /// owners. Only a receipt returned by this constructor (or by
    /// [`Self::record_expanded_delivery`]) satisfies
    /// [`Self::is_delivered_full`].
    ///
    /// A recorded `TRUNCATED` outcome — or a completed call whose delivery
    /// outcome is already recorded — is never rewritten as `FULL` here. The
    /// original truncation stays intact; a later authorized delivery links a
    /// new receipt through [`Self::record_expanded_delivery`].
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt already records the call as
    /// not-called, when transport is already recorded as not completed, when
    /// a delivery outcome was already recorded, when the supplied
    /// representation already links a prior delivery, or when the resulting
    /// receipt is inconsistent.
    pub fn record_full_delivery(
        mut self,
        produced: ProducedToolResultIdentity,
        delivered: DeliveredToolRepresentation,
    ) -> Result<Self, ToolExposureError> {
        if matches!(self.called, Some(false)) {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.called",
                reason: "a full delivery requires an executed call",
            });
        }
        if matches!(self.transport_completed, Some(false)) {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.transport_completed",
                reason: "a full delivery requires completed transport",
            });
        }
        if self.delivered_representation.is_some()
            || !matches!(self.result_delivery, ResultDelivery::Missing)
            || matches!(self.called, Some(true))
        {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation",
                reason: "a recorded truncated or missing delivery outcome is never rewritten as full; later deliveries link through record_expanded_delivery",
            });
        }
        if delivered.prior_delivery_receipt_id.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation.prior_delivery_receipt_id",
                reason: "a direct full delivery is not an expansion and carries no prior link",
            });
        }
        self.called = Some(true);
        self.transport_completed = Some(true);
        self.result_delivery = ResultDelivery::Full;
        self.produced_result = Some(produced);
        self.delivered_representation = Some(delivered);
        self.validate()?;
        Ok(self)
    }

    /// Links a later authorized delivery for a recorded truncated (or
    /// completed-missing) outcome without rewriting it.
    ///
    /// The original receipt is untouched: this builds a NEW receipt with its
    /// own identity whose delivered representation links
    /// `prior_delivery_receipt_id` to the original. The expansion delivers
    /// the SAME produced result — a supplied produced identity whose digest
    /// disagrees with the retained one is refused — with its own exact
    /// representation evidence, and records `FULL` plus
    /// `expanded_or_retried`. Eligibility, selection, registration,
    /// advertisement, use, and terminal stages carry over verbatim; unknown
    /// stays unknown and is never inferred.
    ///
    /// # Errors
    ///
    /// Returns an error when the original receipt is inconsistent, when it
    /// records no expandable truncated or completed-missing outcome, when the
    /// new identity is blank or self-linking, when the supplied produced
    /// digest disagrees with the retained one, when the supplied
    /// representation already links a prior delivery, or when the resulting
    /// receipt is inconsistent.
    pub fn record_expanded_delivery(
        &self,
        new_receipt_id: String,
        produced: ProducedToolResultIdentity,
        mut delivered: DeliveredToolRepresentation,
    ) -> Result<Self, ToolExposureError> {
        self.validate()?;
        let expandable = matches!(self.result_delivery, ResultDelivery::Truncated)
            || (matches!(self.result_delivery, ResultDelivery::Missing)
                && matches!(self.called, Some(true)));
        if !expandable {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.result_delivery",
                reason: "only a recorded truncated or completed-missing delivery can be expanded",
            });
        }
        text(&new_receipt_id, "receipt.receipt_id")?;
        if new_receipt_id == self.receipt_id {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation.prior_delivery_receipt_id",
                reason: "an expansion links a prior delivery receipt, never itself",
            });
        }
        if let Some(retained) = &self.produced_result
            && retained.result_digest != produced.result_digest
        {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.produced_result.result_digest",
                reason: "an expansion delivers the same produced result, never a different one",
            });
        }
        if delivered.prior_delivery_receipt_id.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.delivered_representation.prior_delivery_receipt_id",
                reason: "the expansion link is set here, never supplied by the caller",
            });
        }
        delivered.prior_delivery_receipt_id = Some(self.receipt_id.clone());
        let expanded = Self {
            schema_version: TOOL_EXPOSURE_RECEIPT_V2_VERSION,
            receipt_id: new_receipt_id,
            tool_definition: self.tool_definition.clone(),
            route_fingerprint: self.route_fingerprint.clone(),
            registered: self.registered,
            advertised_to_route: self.advertised_to_route,
            eligible_under_scope_policy_and_grant: self.eligible_under_scope_policy_and_grant,
            selected_by_planner_or_model: self.selected_by_planner_or_model,
            called: Some(true),
            transport_completed: Some(true),
            result_delivery: ResultDelivery::Full,
            produced_result: Some(produced),
            delivered_representation: Some(delivered),
            expanded_or_retried: Some(true),
            observably_used_in_decision_action_or_verifier: self
                .observably_used_in_decision_action_or_verifier,
            terminal_task_or_product_outcome_ref: self.terminal_task_or_product_outcome_ref.clone(),
        };
        expanded.validate()?;
        Ok(expanded)
    }

    /// Records observable downstream use of the delivered result.
    ///
    /// Sets `observably_used_in_decision_action_or_verifier` without touching
    /// delivery: marking a truncated or missing delivery as used never makes
    /// [`Self::is_delivered_full`] or [`Self::is_evidence_used`] hold. Only a
    /// delivered-full result that was observably used counts as evidence-used.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is inconsistent, or when recorded
    /// non-use would be rewritten as use; observations are monotonic.
    pub fn record_observable_use(mut self) -> Result<Self, ToolExposureError> {
        self.validate()?;
        if matches!(
            self.observably_used_in_decision_action_or_verifier,
            Some(false)
        ) {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.observably_used_in_decision_action_or_verifier",
                reason: "recorded non-use is never rewritten as use",
            });
        }
        self.observably_used_in_decision_action_or_verifier = Some(true);
        self.validate()?;
        Ok(self)
    }

    /// Records the terminal task or product outcome reference.
    ///
    /// The reference is carried verbatim; only its presence is observed here.
    /// Recording a terminal outcome never changes delivery or use.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt is inconsistent, the reference is
    /// blank, or a recorded reference would be overwritten.
    pub fn record_terminal_outcome(
        mut self,
        outcome_ref: String,
    ) -> Result<Self, ToolExposureError> {
        self.validate()?;
        text(
            &outcome_ref,
            "receipt.terminal_task_or_product_outcome_ref",
        )?;
        if self.terminal_task_or_product_outcome_ref.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "receipt.terminal_task_or_product_outcome_ref",
                reason: "a recorded terminal outcome is never overwritten",
            });
        }
        self.terminal_task_or_product_outcome_ref = Some(outcome_ref);
        self.validate()?;
        Ok(self)
    }
}

/// Wire version for [`ToolExposureHistoryEntry`].
pub const EXPOSURE_HISTORY_VERSION: u16 = 1;

/// Replay disposition for two recorded exposure revisions on one lineage.
///
/// Returned by [`detect_exposure_replay`]. A signal is evidence for the
/// caller to reconcile through the existing observation/receipt path; it is
/// never permission to execute again. An
/// [`ExposureReplaySignal::IdempotentReplay`] obliges the caller to reconcile
/// the original event — execute nothing again and record no new use — while a
/// conflicting same-identity revision fails as a typed error so it can never
/// validate as a quiet rewrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExposureReplaySignal {
    /// Same receipt identity with identical recorded evidence: a replayed
    /// publication or result redelivery, not new work.
    IdempotentReplay,
    /// New receipt identity linked through the recorded
    /// `prior_delivery_receipt_id` to the recorded prior while retaining the
    /// same produced result digest: a later authorized expansion delivery of
    /// the same result.
    LinkedExpansion,
}

/// Classifies a repeated exposure revision against the recorded original.
///
/// Both revisions validate as recorded first:
/// [`ToolExposureReceiptV2::validate`] checks the original recorded digest
/// values and never recomputes them. Recorded content then decides, compared
/// with this operation:
/// - same `receipt_id` with identical recorded evidence is
///   [`ExposureReplaySignal::IdempotentReplay`];
/// - same `receipt_id` with divergent recorded evidence is a typed conflict;
///   the caller persists a linked revision through the existing
///   observation/receipt path instead of rewriting, so a replay can produce
///   neither duplicate execution nor false usage evidence;
/// - different identities link only through the recorded
///   `prior_delivery_receipt_id` on the current revision plus the same
///   retained produced result digest, yielding
///   [`ExposureReplaySignal::LinkedExpansion`];
/// - anything else is `Ok(None)`: not a replay pair, routed to its owners.
///
/// An unrecorded produced digest never proves same-result lineage: pairs with
/// a missing digest on either side stay `None` for owner reconciliation
/// instead of validating as expansions.
///
/// # Errors
///
/// Returns an error when either revision is inconsistent, or when one receipt
/// identity carries conflicting recorded evidence.
pub fn detect_exposure_replay(
    previous: &ToolExposureReceiptV2,
    current: &ToolExposureReceiptV2,
) -> Result<Option<ExposureReplaySignal>, ToolExposureError> {
    previous.validate()?;
    current.validate()?;
    if previous.receipt_id == current.receipt_id {
        if previous == current {
            return Ok(Some(ExposureReplaySignal::IdempotentReplay));
        }
        return Err(ToolExposureError::InvalidField {
            field: "receipt.receipt_id",
            reason: "replayed receipt identity carries conflicting recorded evidence; persist a linked revision instead of rewriting",
        });
    }
    let linked = current
        .delivered_representation
        .as_ref()
        .and_then(|representation| representation.prior_delivery_receipt_id.as_deref())
        == Some(previous.receipt_id.as_str());
    if linked && produced_digest_agrees(previous, current) {
        return Ok(Some(ExposureReplaySignal::LinkedExpansion));
    }
    Ok(None)
}

/// Whether both revisions retain the same produced result digest as recorded.
fn produced_digest_agrees(
    previous: &ToolExposureReceiptV2,
    current: &ToolExposureReceiptV2,
) -> bool {
    matches!(
        (&previous.produced_result, &current.produced_result),
        (Some(previous_produced), Some(current_produced))
            if previous_produced.result_digest == current_produced.result_digest
    )
}

/// One owner-supplied fact for a single exposure stage: supplied or explicitly
/// unresolved.
///
/// `observed: Some(_)` is a positive owner claim and requires a non-blank
/// `source_ref` naming the owner evidence (definition revision, grant
/// verdict, attempt record, projection handle). `observed: None` is explicitly
/// unresolved unknown coverage — never a silent `false`, never omitted: the
/// field stays present under `deny_unknown_fields`, so deserialization fails
/// closed on omission instead of validating a valid-looking gap.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerStageFact {
    /// Owner observation for the stage; `None` means explicitly unresolved.
    pub observed: Option<bool>,
    /// Owner evidence reference; required with a supplied observation.
    pub source_ref: Option<String>,
}

impl OwnerStageFact {
    /// Records an owner-supplied observation bound to its evidence reference.
    ///
    /// # Errors
    ///
    /// Returns an error when the source reference is blank or carries control
    /// characters.
    pub fn supplied(observed: bool, source_ref: String) -> Result<Self, ToolExposureError> {
        let fact = Self {
            observed: Some(observed),
            source_ref: Some(source_ref),
        };
        fact.validate("history.stage")?;
        Ok(fact)
    }

    /// Records explicitly unresolved coverage for a stage owned elsewhere.
    #[must_use]
    pub const fn unresolved() -> Self {
        Self {
            observed: None,
            source_ref: None,
        }
    }

    /// Validates the supplied-or-unresolved shape without consulting any owner.
    ///
    /// A supplied observation without its owner source reference fails; an
    /// unresolved stage without a source stays unresolved and is never
    /// coerced.
    ///
    /// # Errors
    ///
    /// Returns an error when a supplied observation lacks its source
    /// reference, or when a carried reference is blank or carries control
    /// characters.
    pub fn validate(&self, field: &'static str) -> Result<(), ToolExposureError> {
        match (&self.observed, &self.source_ref) {
            (Some(_), None) => {
                return Err(ToolExposureError::InvalidField {
                    field,
                    reason: "a supplied stage observation requires its owner source reference",
                });
            }
            (_, Some(source)) => text(source, field)?,
            (None, None) => {}
        }
        Ok(())
    }
}

/// Turn/run/attempt/surface identities bound to one exposure-history entry.
///
/// Identities arrive from their owners; a seam that never mints an identity
/// binds `None` (explicitly unresolved) rather than inventing one. The
/// surface identity is always required: a history fact about no surface
/// proves nothing and cannot join any revision lineage.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExposureIdentities {
    /// Turn identity from the loop owner, when joined.
    pub turn_ref: Option<String>,
    /// Run identity from the execution owner, when joined.
    pub run_ref: Option<String>,
    /// Attempt identity from the attempt-history owner, when joined.
    pub attempt_ref: Option<String>,
    /// Surface identity the history is bound to; always required.
    pub surface_ref: Option<String>,
}

impl ExposureIdentities {
    /// Validates carried identity text and the required surface binding.
    ///
    /// # Errors
    ///
    /// Returns an error when a carried identity is blank or carries control
    /// characters, or when the surface identity is missing.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if let Some(turn) = &self.turn_ref {
            text(turn, "history.identities.turn_ref")?;
        }
        if let Some(run) = &self.run_ref {
            text(run, "history.identities.run_ref")?;
        }
        if let Some(attempt) = &self.attempt_ref {
            text(attempt, "history.identities.attempt_ref")?;
        }
        match &self.surface_ref {
            Some(surface) => text(surface, "history.identities.surface_ref")?,
            None => {
                return Err(ToolExposureError::InvalidField {
                    field: "history.identities.surface_ref",
                    reason: "exposure history requires its surface identity",
                });
            }
        }
        Ok(())
    }
}

/// Orthogonal owner-populated exposure history for one tool on one surface.
///
/// Every applicable stage field is present on the wire
/// (`deny_unknown_fields`, no defaults): each stage is either supplied
/// (`Some` with its owner source reference) or explicitly unresolved
/// (`None`), never omitted to obtain a valid-looking record. Unknown stays
/// unknown: no stage is inferred from another, `None` never coerces to
/// `false`, and model-authored success flags without an owner source
/// reference fail validation. Revisions persist as immutable linked revisions
/// through the existing observation/receipt path keyed by the bound receipt
/// lineage — never rewrites (see [`detect_exposure_replay`]) — while lost
/// acknowledgements reconcile the original event and unavailable writeback
/// stays a visible pending obligation on the owning seam.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolExposureHistoryEntry {
    /// Wire contract revision. Must equal [`EXPOSURE_HISTORY_VERSION`].
    pub schema_version: u16,
    /// Versioned tool definition identity this history is about.
    pub tool_definition: String,
    /// Tool Definition version bound by the populating owner.
    pub definition_version: String,
    /// Route fingerprint, when the joining seam owns one.
    pub route_fingerprint: Option<String>,
    /// Owner-supplied turn/run/attempt/surface identities.
    pub identities: ExposureIdentities,
    /// The tool version is registered (definition/facet owner).
    pub registered: OwnerStageFact,
    /// The tool was advertised to the route (publish seam).
    pub advertised_to_route: OwnerStageFact,
    /// The tool was eligible under scope, policy, and grant (Governor/Kernel
    /// owners).
    pub eligible_under_scope_policy_and_grant: OwnerStageFact,
    /// The planner or model selected the tool (selection owner).
    pub selected_by_planner_or_model: OwnerStageFact,
    /// The tool was called (execution owner).
    pub called: OwnerStageFact,
    /// Transport for the call completed (transport owner).
    pub transport_completed: OwnerStageFact,
    /// Delivery completeness; `None` means explicitly unresolved.
    pub result_delivery: Option<ResultDelivery>,
    /// Owner evidence reference for the delivery observation.
    pub delivery_source_ref: Option<String>,
    /// The call was expanded or retried (retry owner).
    pub expanded_or_retried: OwnerStageFact,
    /// The result was observably used in a public decision, action, or
    /// verifier (use owner).
    pub observably_used_in_decision_action_or_verifier: OwnerStageFact,
    /// Terminal task or product outcome reference, when known.
    pub terminal_task_or_product_outcome_ref: Option<String>,
}

impl ToolExposureHistoryEntry {
    /// Validates identities and every stage's supplied-or-unresolved shape
    /// without consulting any owner or inferring any stage.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, blank identity or
    /// version text, a supplied stage without its owner source reference, a
    /// supplied delivery without its source, or a blank reference.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if self.schema_version != EXPOSURE_HISTORY_VERSION {
            return Err(ToolExposureError::InvalidField {
                field: "history.schema_version",
                reason: "unsupported exposure history version",
            });
        }
        text(&self.tool_definition, "history.tool_definition")?;
        text(&self.definition_version, "history.definition_version")?;
        if let Some(route) = &self.route_fingerprint {
            text(route, "history.route_fingerprint")?;
        }
        self.identities.validate()?;
        self.registered.validate("history.registered")?;
        self.advertised_to_route
            .validate("history.advertised_to_route")?;
        self.eligible_under_scope_policy_and_grant
            .validate("history.eligible_under_scope_policy_and_grant")?;
        self.selected_by_planner_or_model
            .validate("history.selected_by_planner_or_model")?;
        self.called.validate("history.called")?;
        self.transport_completed
            .validate("history.transport_completed")?;
        match (&self.result_delivery, &self.delivery_source_ref) {
            (Some(_), None) => {
                return Err(ToolExposureError::InvalidField {
                    field: "history.delivery_source_ref",
                    reason: "a supplied delivery observation requires its owner source reference",
                });
            }
            (_, Some(source)) => text(source, "history.delivery_source_ref")?,
            (None, None) => {}
        }
        self.expanded_or_retried
            .validate("history.expanded_or_retried")?;
        self.observably_used_in_decision_action_or_verifier
            .validate("history.observably_used_in_decision_action_or_verifier")?;
        if let Some(reference) = &self.terminal_task_or_product_outcome_ref {
            text(reference, "history.terminal_task_or_product_outcome_ref")?;
        }
        Ok(())
    }
}

/// Refuses a second supply for one recorded history stage.
///
/// Recorded owner evidence is never overwritten in place: a changed observation
/// persists as a successor revision through [`dispose_exposure_revision`], never
/// as a rewrite of the recorded fact.
fn require_stage_unrecorded(
    stage: &OwnerStageFact,
    field: &'static str,
) -> Result<(), ToolExposureError> {
    if stage.observed.is_some() {
        return Err(ToolExposureError::InvalidField {
            field,
            reason: "recorded stage evidence is never overwritten; persist a successor revision",
        });
    }
    Ok(())
}

impl ToolExposureHistoryEntry {
    /// Records the registration fact from the definition/facet owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference (the `canonical-name@profile-version` evidence staged
    /// by the semantic-registry owner). No neighbouring stage is read or
    /// inferred, and an already recorded registration is never overwritten —
    /// a changed owner verdict persists as a successor revision through the
    /// existing observation/receipt path.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_registered(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(&self.registered, "history.registered")?;
        self.registered = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the advertisement fact from the publish-seam owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference (the surface-decision reference that rendered the
    /// advertised surface). Advertisement never implies eligibility, and an
    /// already recorded advertisement is never overwritten — a changed owner
    /// verdict persists as a successor revision through the existing
    /// observation/receipt path.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_advertised(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(&self.advertised_to_route, "history.advertised_to_route")?;
        self.advertised_to_route = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the eligibility fact from the scope/policy/grant owners.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference (the Governor/Kernel grant verdict bound to the
    /// surface decision). Eligibility is never inferred from advertisement or
    /// selection, and an already recorded eligibility is never overwritten —
    /// a changed owner verdict persists as a successor revision through the
    /// existing observation/receipt path.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_eligible(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(
            &self.eligible_under_scope_policy_and_grant,
            "history.eligible_under_scope_policy_and_grant",
        )?;
        self.eligible_under_scope_policy_and_grant =
            OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the planner/model selection fact from the selection owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference. No neighbouring stage is read or inferred, and an
    /// already recorded selection is never overwritten. The dispatch admission
    /// seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_selected(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(
            &self.selected_by_planner_or_model,
            "history.selected_by_planner_or_model",
        )?;
        self.selected_by_planner_or_model = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the call fact from the execution owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference. Selection, transport, and delivery stages are never
    /// inferred from the call, and an already recorded call is never
    /// overwritten. The execution seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_called(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(&self.called, "history.called")?;
        self.called = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the transport-completion fact from the transport owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference. Transport completion never implies delivery
    /// completeness, and an already recorded transport fact is never
    /// overwritten. The transport seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_transport_completed(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(&self.transport_completed, "history.transport_completed")?;
        self.transport_completed = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the delivery-completeness fact from the bridge/host projection owner.
    ///
    /// Delivery and its owner source reference are set as one pair: a supplied
    /// delivery without its projection source fails, and unknown coverage stays
    /// `None`. Execution and transport stages are never re-read here, and a
    /// recorded delivery is never overwritten — a later authorized expansion
    /// persists as a successor revision. The bridge/host projection seam is the
    /// STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when delivery is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_delivery(
        mut self,
        delivery: ResultDelivery,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        if self.result_delivery.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "history.result_delivery",
                reason: "recorded delivery evidence is never overwritten; persist a successor revision",
            });
        }
        text(&source_ref, "history.delivery_source_ref")?;
        self.result_delivery = Some(delivery);
        self.delivery_source_ref = Some(source_ref);
        self.validate()?;
        Ok(self)
    }

    /// Records the expansion/retry fact from the retry owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference. Retry never implies progress — the no-progress signal
    /// stays with the repeat-detection owner — and an already recorded retry
    /// fact is never overwritten. The retry seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_retry(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(&self.expanded_or_retried, "history.expanded_or_retried")?;
        self.expanded_or_retried = OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the observable-use fact from the use owner.
    ///
    /// Only this stage is set, from the supplied owner observation and its
    /// source reference. Observable use requires a public action/decision/
    /// verifier link carried in the source reference; delivery alone never
    /// implies use, and an already recorded use fact is never overwritten. The
    /// verifier/use seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the stage is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_use(
        mut self,
        observed: bool,
        source_ref: String,
    ) -> Result<Self, ToolExposureError> {
        require_stage_unrecorded(
            &self.observably_used_in_decision_action_or_verifier,
            "history.observably_used_in_decision_action_or_verifier",
        )?;
        self.observably_used_in_decision_action_or_verifier =
            OwnerStageFact::supplied(observed, source_ref)?;
        self.validate()?;
        Ok(self)
    }

    /// Records the terminal task/product outcome reference from the outcome owner.
    ///
    /// Only the outcome reference is set; no stage is inferred from it, and a
    /// recorded outcome is never overwritten — a later outcome persists as a
    /// successor revision. The task-completion seam is the STITCH caller.
    ///
    /// # Errors
    ///
    /// Returns an error when an outcome is already recorded or the resulting
    /// entry is inconsistent.
    pub fn record_outcome(mut self, outcome_ref: String) -> Result<Self, ToolExposureError> {
        if self.terminal_task_or_product_outcome_ref.is_some() {
            return Err(ToolExposureError::InvalidField {
                field: "history.terminal_task_or_product_outcome_ref",
                reason: "a recorded outcome reference is never overwritten; persist a successor revision",
            });
        }
        text(&outcome_ref, "history.terminal_task_or_product_outcome_ref")?;
        self.terminal_task_or_product_outcome_ref = Some(outcome_ref);
        self.validate()?;
        Ok(self)
    }
}

/// Replay disposition for one exposure-history revision against the recorded prior.
///
/// Returned by [`dispose_exposure_revision`]. A signal is evidence for the
/// existing observation/receipt/outbox owner; it is never permission to execute
/// again. [`ExposureRevisionDisposition::IdempotentReplay`] obliges the owner to
/// reconcile the original event — persist nothing new and record no new use —
/// while a [`ExposureRevisionDisposition::SuccessorRevision`] persists alongside
/// the retained prior, never as an overwrite.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExposureRevisionDisposition {
    /// No prior recorded revision on this lineage: the entry persists first.
    FirstRevision,
    /// Same lineage with identical recorded evidence: a replayed publication,
    /// not new work.
    IdempotentReplay,
    /// Same lineage with divergent recorded evidence: a later linked revision
    /// of the same evaluation.
    SuccessorRevision,
}

/// Classifies one owner-populated history entry against the recorded prior.
///
/// Both revisions validate first; recorded content then decides. Comparisons
/// run on the revision lineage — tool definition and version, route, and the
/// owner-joined turn/run/attempt/surface identities — never on a single stage:
/// - no prior revision yields [`ExposureRevisionDisposition::FirstRevision`];
/// - same lineage with identical recorded evidence yields
///   [`ExposureRevisionDisposition::IdempotentReplay`];
/// - same lineage with divergent recorded evidence yields
///   [`ExposureRevisionDisposition::SuccessorRevision`], so a replay can
///   produce neither duplicate execution nor false usage evidence;
/// - different lineages fail as a typed error: they are not a revision pair
///   and route back to their owners.
///
/// Unknown coverage never decides: `None` stages compare as recorded unknown
/// on both sides, never coerced to `false` to force a replay or a successor.
///
/// # Errors
///
/// Returns an error when either revision is inconsistent or the two entries
/// belong to different revision lineages.
pub fn dispose_exposure_revision(
    previous: Option<&ToolExposureHistoryEntry>,
    current: &ToolExposureHistoryEntry,
) -> Result<ExposureRevisionDisposition, ToolExposureError> {
    current.validate()?;
    let Some(previous) = previous else {
        return Ok(ExposureRevisionDisposition::FirstRevision);
    };
    previous.validate()?;
    if history_lineage(previous) != history_lineage(current) {
        return Err(ToolExposureError::InvalidField {
            field: "history.identities",
            reason: "exposure revisions on different lineages are not a revision pair; route to their owners",
        });
    }
    if previous == current {
        Ok(ExposureRevisionDisposition::IdempotentReplay)
    } else {
        Ok(ExposureRevisionDisposition::SuccessorRevision)
    }
}

/// Revision lineage of one history entry: the identities that join revisions
/// of a single evaluation. Stage observations play no part in the lineage.
type HistoryLineage<'a> = (
    &'a str,
    &'a str,
    Option<&'a String>,
    Option<&'a String>,
    Option<&'a String>,
    Option<&'a String>,
    Option<&'a String>,
);

fn history_lineage(entry: &ToolExposureHistoryEntry) -> HistoryLineage<'_> {
    (
        entry.tool_definition.as_str(),
        entry.definition_version.as_str(),
        entry.route_fingerprint.as_ref(),
        entry.identities.turn_ref.as_ref(),
        entry.identities.run_ref.as_ref(),
        entry.identities.attempt_ref.as_ref(),
        entry.identities.surface_ref.as_ref(),
    )
}

/// One replay-safe exposure-history revision packaged for the existing
/// observation/receipt/outbox path.
///
/// This boundary performs no store write: the observation owner persists
/// [`ExposureHistoryRevision::entry`] for
/// [`ExposureRevisionDisposition::FirstRevision`] and
/// [`ExposureRevisionDisposition::SuccessorRevision`] alongside the retained
/// prior, keyed by [`ExposureHistoryRevision::lineage_digest`], and reconciles
/// the original event for [`ExposureRevisionDisposition::IdempotentReplay`]
/// where the entry is `None` so a replay cannot persist a duplicate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExposureHistoryRevision {
    /// Replay disposition of the current entry against the recorded prior.
    pub disposition: ExposureRevisionDisposition,
    /// Stable digest of the revision lineage joining one evaluation's revisions.
    pub lineage_digest: String,
    /// Canonical digest of the current entry bytes.
    pub entry_digest: String,
    /// The validated entry to persist, or `None` for an idempotent replay.
    pub entry: Option<ToolExposureHistoryEntry>,
}

/// Packages one owner-populated history entry as a replay-safe revision for
/// the existing observation/receipt/outbox path.
///
/// The entry is classified with [`dispose_exposure_revision`], then bound to
/// its lineage and canonical digests computed over canonical JSON bytes. The
/// observation/receipt/outbox owner (STITCH caller) performs the durable
/// write; this constructor only guarantees the revision is validated,
/// replay-safe, and content-addressed before it leaves this boundary.
///
/// # Errors
///
/// Returns an error when either revision is inconsistent, the two entries
/// belong to different lineages, or canonical bytes cannot be produced.
pub fn persist_exposure_history_revision(
    previous: Option<&ToolExposureHistoryEntry>,
    current: &ToolExposureHistoryEntry,
) -> Result<ExposureHistoryRevision, ToolExposureError> {
    let disposition = dispose_exposure_revision(previous, current)?;
    let lineage_digest = digest_history_lineage(current)?;
    let entry_digest = digest_history_entry(current)?;
    let entry = match disposition {
        ExposureRevisionDisposition::IdempotentReplay => None,
        ExposureRevisionDisposition::FirstRevision
        | ExposureRevisionDisposition::SuccessorRevision => Some(current.clone()),
    };
    Ok(ExposureHistoryRevision {
        disposition,
        lineage_digest,
        entry_digest,
        entry,
    })
}

/// Canonical digest of one history entry's recorded bytes.
fn digest_history_entry(entry: &ToolExposureHistoryEntry) -> Result<String, ToolExposureError> {
    let bytes =
        crate::canonical_json_bytes(entry).map_err(|_| ToolExposureError::InvalidField {
            field: "history.revision",
            reason: "exposure history entry is not canonically serializable",
        })?;
    Ok(crate::sha256_hex(&bytes))
}

/// Canonical digest of one history entry's revision lineage.
fn digest_history_lineage(entry: &ToolExposureHistoryEntry) -> Result<String, ToolExposureError> {
    let bytes = crate::canonical_json_bytes(&history_lineage(entry)).map_err(|_| {
        ToolExposureError::InvalidField {
            field: "history.revision",
            reason: "exposure history lineage is not canonically serializable",
        }
    })?;
    Ok(crate::sha256_hex(&bytes))
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
