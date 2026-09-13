//! Single-owner route candidate, admitted-route, and physical-observation
//! contracts (issue #369 S4, T4 section 5.2).
//!
//! Three different facts have three different owners, all declared here:
//!
//! ```text
//! RouteSelectionCandidate         transient deterministic candidate projection;
//!                                 candidate-only, cannot encode admission.
//! AdmittedRouteReceipt            durable logical decision issued only by the
//!                                 external admission owner; A-01 validates
//!                                 shape and links.
//! PhysicalRouteObservationReceipt immutable adapter observation of what the
//!                                 provider actually executed.
//! ```
//!
//! [`RouteFingerprint`](crate::RouteFingerprint) remains the identity role:
//! behavior-bearing hashes are canonical lowercase 64-hex SHA-256
//! ([`LowercaseSha256`](eliot_contracts::LowercaseSha256), domain
//! `eliot.agent.route-fingerprint.v6`); display names and provider locators
//! are not identity proof and stay validated non-blank strings.
//!
//! Receipt self digests are `sha256_hex(canonical_json_bytes(payload minus
//! the digest field))` and bind the schema version plus every
//! authority/evidence-bearing field. A copied unchecked string never
//! validates. Times are [`ClockReading`](eliot_contracts::ClockReading):
//! unknown stays unknown and is never fabricated into causal order.
//! Policy revisions use the typed [`PolicyRevision`](eliot_contracts::PolicyRevision)
//! owner, never a bare string. Proof ceilings reuse
//! [`ProofCeiling`](eliot_receipts::ProofCeiling); this module introduces no
//! replacement receipt envelope.
//!
//! The physical observation carries two independent axes: route state
//! (`MATCHED` / `DIVERGED` / `UNOBSERVED`) and execution outcome (including
//! `UNKNOWN_OUTCOME`). An unknown outcome can coexist with an independently
//! known route; the axes are never collapsed into one lossy enum. A mismatch
//! is material evidence with a reduced ceiling and a passive
//! recovery/reconciliation handle, never malformed schema.

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{
    ClockReading, DecisionId, LowercaseSha256, PolicyRevision, ResourceGeneration, StateFence,
    WorkLeaseId, canonical_json_bytes, sha256_hex,
};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    AdmissionDecision, CONTRACT_VERSION, CancellationState, ContractError, EventCursor,
    ProviderExecutionBinding, RouteFingerprint, UsageReceipt,
};

/// Maximum number of considered routes in one candidate.
pub const MAX_ROUTE_CANDIDATES: usize = 64;
/// Maximum number of rejected alternatives recorded in one candidate.
pub const MAX_REJECTED_CANDIDATES: usize = 64;
/// Maximum number of evidence references carried by one receipt.
pub const MAX_EVIDENCE_REFS: usize = 64;
/// Maximum length of an evidence/reason/recovery/raw handle, in Unicode
/// scalar values.
pub const MAX_TEXT_REF_CHARS: usize = 1024;
/// Maximum length of a sanitized public error message, in Unicode scalar
/// values. Adapters sanitize before recording; this bound keeps the receipt
/// a bounded observation, not a log sink.
pub const MAX_SAFE_ERROR_CHARS: usize = 2048;
/// Schema identity of the v5 legacy candidate wire accepted only by the
/// explicit versioned legacy decoder.
pub const LEGACY_CANDIDATE_SCHEMA_V5: &str = "eliot-agent-api/v5:CapabilityRouteDecision";

/// Rejects blank, whitespace-only, control-bearing, or over-long opaque text.
fn validate_bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::EmptyField(field));
    }
    if value.chars().any(char::is_control) {
        return Err(ContractError::EmptyIdentity(field));
    }
    if value.chars().count() > max_chars {
        return Err(ContractError::OversizeField { field });
    }
    Ok(())
}

/// Validates a bounded list of opaque evidence references.
fn validate_evidence_refs(refs: &[String], field: &'static str) -> Result<(), ContractError> {
    if refs.len() > MAX_EVIDENCE_REFS {
        return Err(ContractError::OversizeField { field });
    }
    for value in refs {
        validate_bounded_text(value, field, MAX_TEXT_REF_CHARS)?;
    }
    Ok(())
}

/// Computes `sha256_hex(canonical_json_bytes(payload minus "self_digest"))`.
fn compute_self_digest_hex(payload: &impl Serialize) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(payload)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("self_digest");
    }
    Ok(sha256_hex(&canonical_json_bytes(&value)?))
}

/// Lifts computed hex into the shared typed digest. Only fails when the
/// computed hex is malformed, which cannot happen for canonical SHA-256
/// output; the error is propagated rather than panicked on.
fn typed_digest(hex: String) -> Result<LowercaseSha256, serde_json::Error> {
    serde_json::from_value(serde_json::Value::String(hex))
}

/// Recomputes the canonical self digest and rejects an unchecked copy.
fn check_self_digest(
    payload: &impl Serialize,
    stored: &LowercaseSha256,
) -> Result<(), ContractError> {
    let computed = compute_self_digest_hex(payload).map_err(|_| ContractError::DigestMismatch)?;
    if computed != stored.as_str() {
        return Err(ContractError::DigestMismatch);
    }
    Ok(())
}

/// Returns the differing [`RouteFingerprint`] field names in canonical field
/// order. An empty result means the fingerprints are field-complete equal.
pub fn route_divergence_fields(
    requested: &RouteFingerprint,
    observed: &RouteFingerprint,
) -> Vec<String> {
    let mut fields = Vec::new();
    if requested.host_family != observed.host_family {
        fields.push("host_family".to_owned());
    }
    if requested.adapter != observed.adapter {
        fields.push("adapter".to_owned());
    }
    if requested.protocol_transport != observed.protocol_transport {
        fields.push("protocol_transport".to_owned());
    }
    if requested.runtime_hash != observed.runtime_hash {
        fields.push("runtime_hash".to_owned());
    }
    if requested.adapter_hash != observed.adapter_hash {
        fields.push("adapter_hash".to_owned());
    }
    if requested.provider != observed.provider {
        fields.push("provider".to_owned());
    }
    if requested.model != observed.model {
        fields.push("model".to_owned());
    }
    if requested.auth_billing != observed.auth_billing {
        fields.push("auth_billing".to_owned());
    }
    if requested.serializer_hash != observed.serializer_hash {
        fields.push("serializer_hash".to_owned());
    }
    if requested.tool_semantics_hash != observed.tool_semantics_hash {
        fields.push("tool_semantics_hash".to_owned());
    }
    if requested.reasoning_mode != observed.reasoning_mode {
        fields.push("reasoning_mode".to_owned());
    }
    if requested.continuation_behavior != observed.continuation_behavior {
        fields.push("continuation_behavior".to_owned());
    }
    if requested.feature_flags_hash != observed.feature_flags_hash {
        fields.push("feature_flags_hash".to_owned());
    }
    fields
}

/// Candidate-only selection disposition. It records whether the deterministic
/// projection selected a route; it cannot encode an issued admission.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateSelectionDisposition {
    Selected,
    NoRoute,
}

/// One rejected alternative with its reason code and supporting evidence
/// handle. Rejection reasons are opaque codes owned by the selector; they
/// never prove admission, availability, or capability by themselves.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedRouteCandidate {
    pub route: RouteFingerprint,
    pub reason_code: String,
    pub evidence_ref: Option<String>,
}

impl RejectedRouteCandidate {
    fn validate(&self) -> Result<(), ContractError> {
        self.route.validate()?;
        validate_bounded_text(&self.reason_code, "reason_code", MAX_TEXT_REF_CHARS)?;
        if let Some(reference) = &self.evidence_ref {
            validate_bounded_text(reference, "evidence_ref", MAX_TEXT_REF_CHARS)?;
        }
        Ok(())
    }
}

/// Transient deterministic candidate projection over current
/// policy/capability/capacity evidence (T4 §5.2 row 1, `RENAME` of
/// `CapabilityRouteDecision`).
///
/// Candidate-only: it cannot claim admission or execution. The admission-like
/// `decision` tag of the legacy shape is replaced by
/// [`CandidateSelectionDisposition`], which has no admission-claiming case.
/// Policy revisions use the typed [`PolicyRevision`] owner, never a string.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSelectionCandidate {
    pub capability: String,
    pub query_intent: String,
    pub scope_ref: String,
    pub policy_revision: PolicyRevision,
    pub candidates: Vec<RouteFingerprint>,
    pub selected: Option<RouteFingerprint>,
    pub rejected: Vec<RejectedRouteCandidate>,
    pub selection: CandidateSelectionDisposition,
    pub evidence_refs: Vec<String>,
}

impl RouteSelectionCandidate {
    /// Validates candidate shape. A candidate selecting a route absent from
    /// its candidate set is rejected with [`ContractError::RouteMismatch`];
    /// that arm is preserved exactly: absence is selector error, while a
    /// requested/observed divergence in a physical observation is evidence
    /// and never takes this path.
    pub fn validate(&self) -> Result<(), ContractError> {
        for (field, value) in [
            ("capability", &self.capability),
            ("query_intent", &self.query_intent),
            ("scope_ref", &self.scope_ref),
        ] {
            validate_bounded_text(value, field, MAX_TEXT_REF_CHARS)?;
        }
        if self.candidates.is_empty() {
            return Err(ContractError::EmptyCollection("candidates"));
        }
        if self.candidates.len() > MAX_ROUTE_CANDIDATES {
            return Err(ContractError::OversizeField {
                field: "candidates",
            });
        }
        for candidate in &self.candidates {
            candidate.validate()?;
        }
        if self.rejected.len() > MAX_REJECTED_CANDIDATES {
            return Err(ContractError::OversizeField { field: "rejected" });
        }
        for rejected in &self.rejected {
            rejected.validate()?;
        }
        validate_evidence_refs(&self.evidence_refs, "evidence_refs")?;
        match (&self.selection, &self.selected) {
            (CandidateSelectionDisposition::Selected, Some(selected)) => {
                if !self.candidates.contains(selected) {
                    return Err(ContractError::RouteMismatch);
                }
                Ok(())
            }
            (CandidateSelectionDisposition::NoRoute, None) => {
                if self.rejected.is_empty() {
                    return Err(ContractError::EmptyCollection("rejected"));
                }
                Ok(())
            }
            _ => Err(ContractError::InvalidRouteDisposition),
        }
    }
}

/// Computes the exact candidate identity: the canonical digest of the
/// candidate bytes. The admitted receipt stores this value as
/// `candidate_digest`; both sides compute it with this function so the link
/// is recomputable, never an unchecked copy.
pub fn candidate_digest_for(
    candidate: &RouteSelectionCandidate,
) -> Result<LowercaseSha256, serde_json::Error> {
    let bytes = canonical_json_bytes(candidate)?;
    typed_digest(sha256_hex(&bytes))
}

/// Why a v5 legacy candidate wire cannot become a current candidate. Every
/// reason is evidence-preserving: the legacy bytes digest stays addressable
/// in [`LegacyRouteQuarantine`] instead of being silently upgraded.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyQuarantineReason {
    /// A fingerprint fails canonical validation (including `sha256:*`
    /// placeholders and non-digest hashes).
    InvalidRoute,
    /// The legacy selection names a route absent from its candidate set.
    InvalidSelection,
    /// The legacy admission-like tag has no representation in a schema that
    /// cannot encode issued admission.
    AdmissionTagNotRepresentable,
    /// The legacy bare-string policy revision has no mapping to the typed
    /// [`PolicyRevision`] owner.
    UntypedPolicyRevision,
}

/// Typed legacy/quarantine evidence for one v5 `CapabilityRouteDecision`
/// wire. The legacy payload is preserved by digest, never reinterpreted as
/// a current candidate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyRouteQuarantine {
    pub legacy_schema: String,
    pub legacy_digest: LowercaseSha256,
    pub reasons: Vec<LegacyQuarantineReason>,
}

impl LegacyRouteQuarantine {
    /// Validates quarantine shape: the schema tag is exact and at least one
    /// reason is recorded.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.legacy_schema != LEGACY_CANDIDATE_SCHEMA_V5 {
            return Err(ContractError::UnknownContractVersion);
        }
        if self.reasons.is_empty() {
            return Err(ContractError::EmptyCollection("reasons"));
        }
        Ok(())
    }
}

/// Explicit versioned legacy decoder for v5 `CapabilityRouteDecision` wires.
/// There is no `From` conversion, no untagged fallback, and no silent
/// upgrade: callers handle both outcomes explicitly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCapabilityRouteDecisionV5 {
    pub capability: String,
    pub query_intent: String,
    pub scope_ref: String,
    pub policy_revision: String,
    pub candidates: Vec<RouteFingerprint>,
    pub selected: Option<RouteFingerprint>,
    pub decision: AdmissionDecision,
    pub evidence_refs: Vec<String>,
}

/// Decoder outcome: either a losslessly migrated candidate or typed
/// quarantine evidence. A v5 wire migrates losslessly only when its shape is
/// canonically valid, its selection is consistent, its tag claims no
/// admission, and its revision maps to the typed owner; otherwise every
/// applicable quarantine reason is recorded in deterministic order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyCandidateMigration {
    Candidate(RouteSelectionCandidate),
    Quarantined(LegacyRouteQuarantine),
}

impl LegacyCapabilityRouteDecisionV5 {
    /// Decodes one v5 legacy wire into either a current candidate or typed
    /// quarantine evidence. The legacy tag and the bare-string revision have
    /// no current representation, so every decodable v5 wire quarantines with
    /// its exact reasons instead of upgrading silently.
    pub fn migrate(self) -> Result<LegacyCandidateMigration, serde_json::Error> {
        let legacy_digest = typed_digest(sha256_hex(&canonical_json_bytes(&self)?))?;
        let mut reasons = Vec::new();
        let routes_valid = !self.candidates.is_empty()
            && self.candidates.iter().all(|route| route.validate().is_ok())
            && self
                .selected
                .as_ref()
                .is_none_or(|selected| selected.validate().is_ok());
        if !routes_valid {
            reasons.push(LegacyQuarantineReason::InvalidRoute);
        }
        if let Some(selected) = &self.selected
            && !self.candidates.contains(selected)
        {
            reasons.push(LegacyQuarantineReason::InvalidSelection);
        }
        // The legacy tag always claims an admission disposition, which the
        // candidate schema cannot encode by construction.
        reasons.push(LegacyQuarantineReason::AdmissionTagNotRepresentable);
        // The bare-string revision never maps to the typed owner without
        // parsing display text, which compatibility forbids.
        reasons.push(LegacyQuarantineReason::UntypedPolicyRevision);
        Ok(LegacyCandidateMigration::Quarantined(
            LegacyRouteQuarantine {
                legacy_schema: LEGACY_CANDIDATE_SCHEMA_V5.to_owned(),
                legacy_digest,
                reasons,
            },
        ))
    }
}

/// Typed no-route disposition for an admitted decision: either no candidate
/// was eligible or the admission owner denied the route. Both cases carry no
/// authorized execution.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NoRouteDisposition {
    NoEligibleCandidate,
    AdmissionDenied,
}

/// Durable logical route decision (T4 §5.2 row 2, `MIGRATE` of the API
/// `RoutingReceipt`).
///
/// Only the external admission owner issues this receipt; A-01 validates its
/// shape and links. It records what ELIOT authorized, never what the
/// provider executed. The coordinator-local duplicate is owned by the
/// coordinator slice (`IMPORT_OWNER`); this type is the single public
/// field-level owner of the admitted decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedRouteReceipt {
    pub schema_version: String,
    /// Wire/contract version bound into the self digest.
    pub decision_id: DecisionId,
    /// Exact candidate identity: [`candidate_digest_for`] of the admitted
    /// candidate bytes. A digest reference alone proves nothing; validators
    /// recompute it from the candidate.
    pub candidate_digest: LowercaseSha256,
    pub attempt_id: AgentAttemptId,
    pub lease_id: WorkLeaseId,
    pub state_fence: StateFence,
    pub runtime_generation: ResourceGeneration,
    /// Typed policy owner, never a bare string.
    pub policy_revision: PolicyRevision,
    pub requested_route: RouteFingerprint,
    pub selected_route: Option<RouteFingerprint>,
    /// Required exactly when `selected_route` is absent.
    pub no_route: Option<NoRouteDisposition>,
    pub evidence_refs: Vec<String>,
    /// Admission authorizes candidate work only: anything stronger than
    /// [`ProofCeiling::CandidateArtifact`] is rejected, since verification
    /// and finish authority live elsewhere.
    pub proof_ceiling: ProofCeiling,
    /// Canonical self digest over the payload minus this field.
    pub self_digest: LowercaseSha256,
}

impl AdmittedRouteReceipt {
    /// Computes the canonical self digest for this payload. Minting owners
    /// store the result in `self_digest` before publishing.
    pub fn compute_digest(&self) -> Result<LowercaseSha256, serde_json::Error> {
        typed_digest(compute_self_digest_hex(self)?)
    }

    /// Validates shape and links: schema version, route validity, the
    /// selected/no-route exclusive-or, fence validity, ceiling bound, and a
    /// recomputed self digest. An unchecked copy is rejected with
    /// [`ContractError::DigestMismatch`].
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_VERSION {
            return Err(ContractError::UnknownContractVersion);
        }
        self.requested_route.validate()?;
        match (&self.selected_route, &self.no_route) {
            (Some(route), None) => route.validate()?,
            (None, Some(_)) => {}
            _ => return Err(ContractError::InvalidRouteDisposition),
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::InvalidStateFence)?;
        validate_evidence_refs(&self.evidence_refs, "evidence_refs")?;
        if !self
            .proof_ceiling
            .is_at_most(ProofCeiling::CandidateArtifact)
        {
            return Err(ContractError::InsufficientAuthority);
        }
        check_self_digest(self, &self.self_digest)
    }
}

/// Route observation axis of a physical observation: whether the observed
/// route equals the requested route, diverges from it, or could not be
/// observed at all. Absence never means `requested == observed`.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteObservationState {
    Matched,
    Diverged,
    Unobserved,
}

/// Execution-outcome axis of a physical observation, independent of the route
/// axis. `UnknownOutcome` retains the admitted request, the exact execution
/// binding, the last observation boundary, and a passive
/// recovery/reconciliation handle without asserting provider effect or
/// termination.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionOutcome {
    Observed,
    UnknownOutcome,
}

/// Single immutable physical route observation (T4 §5.2 rows 4-5: `MERGE` of
/// `ActualRouteReceipt` and `MIGRATE` of `PhysicalModelAttemptReceipt`).
///
/// The adapter records what it actually observed: requested and observed
/// fingerprints separately, the exact #361 execution binding snapshot, the
/// admitted-route linkage, typed times, usage, and safe/restricted evidence
/// handles. Endpoint, session locator, workspace, file, and raw payload
/// references remain observations here, never authority or shared identity;
/// credentials, tokens, cookies, command lines, unrestricted environment,
/// and raw payload bytes never enter this receipt (enforced structurally by
/// the absence of such fields).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalRouteObservationReceipt {
    /// Wire/contract version bound into the self digest.
    pub schema_version: String,
    pub attempt_id: AgentAttemptId,
    pub state_fence: StateFence,
    pub runtime_generation: ResourceGeneration,
    /// Link to the admitted decision: the `self_digest` of the governing
    /// [`AdmittedRouteReceipt`]. Recomputed by [`validate_against`](Self::validate_against),
    /// never trusted as identity by itself.
    pub admitted_route_digest: LowercaseSha256,
    /// Exact #361 execution-unit binding snapshot this observation was taken
    /// under. Embedded so the self digest binds it; agreement with the live
    /// binding is enforced by [`validate_against`](Self::validate_against).
    pub binding: ProviderExecutionBinding,
    pub requested_route: RouteFingerprint,
    /// The observed route. `None` exactly when `route_state` is
    /// `Unobserved`: absence is never synthesized from the requested route.
    pub observed_route: Option<RouteFingerprint>,
    pub route_state: RouteObservationState,
    /// Deterministic difference classification, required exactly for
    /// `DIVERGED` and equal to
    /// [`route_divergence_fields`] of the two fingerprints.
    pub diverged_fields: Vec<String>,
    pub execution_outcome: ExecutionOutcome,
    /// Exact admitted request commitment.
    pub request_digest: LowercaseSha256,
    pub translation_digest: Option<LowercaseSha256>,
    /// Immutable digest-bound raw-evidence linkage: a reference is valid
    /// only together with its digest, and the digest alone never implies
    /// the raw bytes were inspected.
    pub raw_evidence_digest: Option<LowercaseSha256>,
    pub raw_evidence_ref: Option<String>,
    /// Usage is retained in every state, including divergence and unknown
    /// outcome; a mismatch never discards it.
    pub usage: UsageReceipt,
    pub started: ClockReading,
    pub first_byte: ClockReading,
    pub first_semantic: ClockReading,
    /// Terminal observation. Unknown (including all-unknown) while the
    /// outcome is unproven; an `UnknownOutcome` record must not assert a
    /// terminal wall time.
    pub terminal: ClockReading,
    /// Causal position of this observation inside the bound execution unit.
    pub event_cursor: EventCursor,
    pub event_sequence: u64,
    /// Observed cancellation, when any. Present means observed: a present
    /// `NotRequested` is rejected.
    pub cancellation: Option<CancellationState>,
    /// Bounded reason for `UNOBSERVED`. Required exactly then, forbidden
    /// otherwise.
    pub unobserved_reason: Option<String>,
    /// Passive recovery/reconciliation handle. Present exactly when the
    /// record needs reconciliation: `DIVERGED` (quarantine handle) or
    /// `UNKNOWN_OUTCOME` (recovery handle).
    pub recovery_ref: Option<String>,
    /// Adapter-sanitized public error message. Sanitization happens at the
    /// adapter boundary; this field never carries secrets.
    pub safe_public_error: Option<String>,
    /// Handle to restricted raw error evidence, kept separate from the safe
    /// public message.
    pub restricted_raw_error_ref: Option<String>,
    /// Canonical self digest over the payload minus this field.
    pub self_digest: LowercaseSha256,
}

impl PhysicalRouteObservationReceipt {
    /// Computes the canonical self digest for this payload. Observers store
    /// the result in `self_digest` before publishing.
    pub fn compute_digest(&self) -> Result<LowercaseSha256, serde_json::Error> {
        typed_digest(compute_self_digest_hex(self)?)
    }

    /// The usable proof ceiling of any physical observation. Divergence,
    /// absence, and unknown outcome can never raise it: observation evidence
    /// stays at [`ProofCeiling::Observation`], at most the admitted ceiling.
    pub fn observation_ceiling(&self) -> ProofCeiling {
        ProofCeiling::Observation
    }

    /// Validates observation shape: schema version, routes, disposition
    /// coherence on both independent axes, clock ordering, handle linkage,
    /// and a recomputed self digest. Linkage against the live admission and
    /// binding is [`validate_against`](Self::validate_against), not here.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_VERSION {
            return Err(ContractError::UnknownContractVersion);
        }
        self.requested_route.validate()?;
        if let Some(observed) = &self.observed_route {
            observed.validate()?;
        }
        self.binding.validate_internal()?;
        for reading in [
            &self.started,
            &self.first_byte,
            &self.first_semantic,
            &self.terminal,
        ] {
            reading
                .validate()
                .map_err(|_| ContractError::InvalidClock)?;
        }
        validate_bounded_text(
            self.event_cursor.as_str(),
            "event_cursor",
            MAX_TEXT_REF_CHARS,
        )?;
        if self.event_sequence == 0 {
            return Err(ContractError::ZeroLimit {
                field: "event_sequence",
            });
        }
        self.validate_route_axis()?;
        self.validate_execution_axis()?;
        let needs_reconciliation = self.route_state == RouteObservationState::Diverged
            || self.execution_outcome == ExecutionOutcome::UnknownOutcome;
        if self.recovery_ref.is_some() != needs_reconciliation {
            return Err(ContractError::InvalidRouteDisposition);
        }
        if let Some(reference) = &self.recovery_ref {
            validate_bounded_text(reference, "recovery_ref", MAX_TEXT_REF_CHARS)?;
        }
        if self.raw_evidence_ref.is_some() != self.raw_evidence_digest.is_some() {
            return Err(ContractError::InvalidRouteDisposition);
        }
        if let Some(reference) = &self.raw_evidence_ref {
            validate_bounded_text(reference, "raw_evidence_ref", MAX_TEXT_REF_CHARS)?;
        }
        if let Some(message) = &self.safe_public_error {
            validate_bounded_text(message, "safe_public_error", MAX_SAFE_ERROR_CHARS)?;
        }
        if let Some(reference) = &self.restricted_raw_error_ref {
            validate_bounded_text(reference, "restricted_raw_error_ref", MAX_TEXT_REF_CHARS)?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::InvalidStateFence)?;
        check_self_digest(self, &self.self_digest)
    }

    /// Validates the route axis: `MATCHED` requires both exact fingerprints
    /// and field-complete equality; `DIVERGED` preserves both plus the exact
    /// deterministic difference classification; `UNOBSERVED` carries no
    /// fabricated observed fingerprint and a bounded reason.
    fn validate_route_axis(&self) -> Result<(), ContractError> {
        match self.route_state {
            RouteObservationState::Matched => {
                if self.observed_route.as_ref() != Some(&self.requested_route) {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                if !self.diverged_fields.is_empty() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                if self.unobserved_reason.is_some() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                Ok(())
            }
            RouteObservationState::Diverged => {
                let Some(observed) = &self.observed_route else {
                    return Err(ContractError::InvalidRouteDisposition);
                };
                if observed == &self.requested_route {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                if self.diverged_fields != route_divergence_fields(&self.requested_route, observed)
                {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                if self.unobserved_reason.is_some() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                Ok(())
            }
            RouteObservationState::Unobserved => {
                if self.observed_route.is_some() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                if !self.diverged_fields.is_empty() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                match &self.unobserved_reason {
                    Some(reason) => {
                        validate_bounded_text(reason, "unobserved_reason", MAX_TEXT_REF_CHARS)
                    }
                    None => Err(ContractError::MissingObservationReason),
                }
            }
        }
    }

    /// Validates the execution axis independently of the route axis: an
    /// `UNKNOWN_OUTCOME` record retains evidence without asserting provider
    /// effect or termination, while an `Observed` record must carry terminal
    /// or cancellation evidence.
    fn validate_execution_axis(&self) -> Result<(), ContractError> {
        if let Some(cancellation) = &self.cancellation
            && *cancellation == CancellationState::NotRequested
        {
            return Err(ContractError::InvalidRouteDisposition);
        }
        match self.execution_outcome {
            ExecutionOutcome::UnknownOutcome => {
                if self.terminal.valid_time_ms.is_some() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                Ok(())
            }
            ExecutionOutcome::Observed => {
                if self.terminal.valid_time_ms.is_none() && self.cancellation.is_none() {
                    return Err(ContractError::InvalidRouteDisposition);
                }
                Ok(())
            }
        }
    }

    /// Validates this observation against the live admission and provider
    /// execution binding: exact attempt/lease/fence/generation agreement,
    /// exact embedded-binding agreement (a same-session observation for the
    /// wrong execution unit fails closed), exact admitted-digest linkage,
    /// and requested-route agreement with the admitted selected route.
    /// Capability claims are never validated from the requested side.
    pub fn validate_against(
        &self,
        binding: &ProviderExecutionBinding,
        admission: &AdmittedRouteReceipt,
    ) -> Result<(), ContractError> {
        self.validate()?;
        admission.validate()?;
        binding.validate_internal()?;
        if self.binding != *binding {
            return Err(ContractError::BindingMismatch);
        }
        if self.attempt_id != admission.attempt_id || self.attempt_id != binding.attempt_id {
            return Err(ContractError::BindingMismatch);
        }
        if admission.lease_id != binding.lease_id {
            return Err(ContractError::BindingMismatch);
        }
        if self.admitted_route_digest != admission.self_digest {
            return Err(ContractError::BindingMismatch);
        }
        if self.state_fence != admission.state_fence || self.state_fence != binding.state_fence {
            return Err(ContractError::BindingMismatch);
        }
        if self.runtime_generation != admission.runtime_generation
            || self.runtime_generation != binding.runtime_generation
        {
            return Err(ContractError::BindingMismatch);
        }
        match &admission.selected_route {
            Some(selected) => {
                if self.requested_route != *selected {
                    return Err(ContractError::BindingMismatch);
                }
            }
            // No authorized execution exists under a no-route admission, so
            // no physical observation can attach to one.
            None => return Err(ContractError::BindingMismatch),
        }
        Ok(())
    }

    /// Checks a replayed observation against the accepted record: an
    /// identical replay (same receipt/execution identity and digest) is
    /// idempotent, while a conflicting observation under the same identity
    /// is rejected for quarantine, never last-write-wins. A replay naming a
    /// different observation identity is not a replay at all.
    pub fn validate_replay_against(&self, previous: &Self) -> Result<(), ContractError> {
        self.validate()?;
        previous.validate()?;
        let same_identity = self.attempt_id == previous.attempt_id
            && self.binding.execution_unit == previous.binding.execution_unit
            && self.event_cursor == previous.event_cursor
            && self.event_sequence == previous.event_sequence;
        if !same_identity {
            return Err(ContractError::BindingMismatch);
        }
        if self.self_digest == previous.self_digest {
            Ok(())
        } else {
            Err(ContractError::ConflictingObservation)
        }
    }
}
