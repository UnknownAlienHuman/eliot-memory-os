//! Canonical Route Continuation kinds and causally fenced handoff links.
//!
//! This module is the protocol-line contract surface for I7.15: the closed
//! [`ContinuityKind`] enum, the [`HandoffCausalLink`] binding every non-fresh
//! admission to one persisted causal link, the opaque
//! [`RouteContinuationState`] scoped to an exact [`RouteFingerprint`], and
//! the sealed [`RehydrationBundle`] packet used when a cross-runtime transfer
//! defaults to `Rehydrated`.
//!
//! These types validate shape only. They do not open transports, persist
//! links, mint authority, or decide admission. Persistence and admission
//! belong to the Kernel continuation/attempt owner; causal-continuity
//! inheritance is rejected here whenever the link is `PARTIAL`, `STALE`, or
//! missing required cursor/effect information.

#![forbid(unsafe_code)]

use eliot_contracts::{
    ContractIdentity, ContractVersion, EpochId, LowercaseSha256, StateFence, canonical_json_bytes,
    contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ProtocolError;

/// Stable identity of the Route Continuation contract family.
pub const ROUTE_CONTINUATION_CONTRACT_NAME: &str = "eliot.foundation.route-continuation";
/// Current semantic revision of the Route Continuation contract family.
pub const ROUTE_CONTINUATION_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Exact payload discriminator for Route Continuation envelopes.
pub const ROUTE_CONTINUATION_PAYLOAD_TYPE: &str = "route-continuation/v1";
/// Maximum bytes for one bounded text field.
pub const MAX_ROUTE_CONTINUATION_TEXT_BYTES: usize = 8 * 1024;
/// Maximum bytes for one opaque native continuation state.
pub const MAX_ROUTE_CONTINUATION_OPAQUE_STATE_BYTES: usize = 64 * 1024;
/// Maximum handles carried by one sealed rehydration packet list.
pub const MAX_ROUTE_CONTINUATION_HANDLES: usize = 32;
/// Maximum in-flight effect dispositions carried by one causal link.
pub const MAX_ROUTE_CONTINUATION_IN_FLIGHT_DISPOSITIONS: usize = 32;

/// Returns the deterministic identity of the Route Continuation contract family.
pub fn route_continuation_contract_identity() -> Result<ContractIdentity, ProtocolError> {
    let shape = schemars::schema_for!(HandoffCausalLink);
    contract_identity(
        ROUTE_CONTINUATION_CONTRACT_NAME,
        ROUTE_CONTINUATION_CONTRACT_VERSION,
        &shape,
    )
    .map_err(|_| ProtocolError::InvalidField {
        field: "route_continuation.contract",
        reason: "cannot derive contract identity",
    })
}

/// Closed continuity kind for the current protocol line (I7.15).
///
/// Only [`ContinuityKind::NativeResume`] preserves native session identity.
/// Every other kind creates a new ELIOT attempt;
/// [`ContinuityKind::NativeFork`] remains a child attempt even when the
/// runtime calls it a continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum ContinuityKind {
    /// Same compatible runtime/route continues the same native session.
    NativeResume,
    /// Runtime creates a child/branch with native history semantics.
    NativeFork,
    /// ELIOT replays durable public messages/events into a new attempt.
    ///
    /// A replayed attempt re-emits only public messages/events as inert
    /// context; it never re-executes prior tool calls or external effects,
    /// and its UI/report identity is distinct from the source session.
    Replayed,
    /// A new attempt receives compiled state/artifacts without prior dialogue.
    Rehydrated,
    /// No prior conversational state is transferred.
    Fresh,
}

impl ContinuityKind {
    /// Returns whether this kind must create a new ELIOT attempt identity.
    ///
    /// Every kind except [`ContinuityKind::NativeResume`] creates a new
    /// attempt, including [`ContinuityKind::NativeFork`].
    #[must_use]
    pub const fn creates_new_attempt_identity(self) -> bool {
        !matches!(self, Self::NativeResume)
    }

    /// Returns the default continuity kind for a cross-runtime transfer.
    ///
    /// A transfer to a different runtime never preserves native session
    /// identity, so it defaults to [`ContinuityKind::Rehydrated`] with a
    /// sealed [`RehydrationBundle`] and explicit unknowns.
    #[must_use]
    pub const fn cross_runtime_transfer_default() -> Self {
        Self::Rehydrated
    }

    /// Returns whether admission under this kind must be bound to one
    /// persisted [`HandoffCausalLink`].
    ///
    /// Every non-fresh kind requires the link; only [`ContinuityKind::Fresh`]
    /// starts without prior conversational state.
    #[must_use]
    pub const fn requires_causal_link(self) -> bool {
        !matches!(self, Self::Fresh)
    }
}

/// Completeness of a causal handoff link (I7.15).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoffCompleteness {
    /// Every required source fact is present and current.
    Complete,
    /// A required source fact is absent.
    Partial,
    /// A required source fact is stale.
    Stale,
    /// Completeness could not be established.
    Unknown,
}

/// Exact route/runtime/adapter fingerprint scoping one attempt or
/// continuation-state binding.
///
/// The contract does not interpret provider/model names or select a
/// fallback; the content-addressed `fingerprint` binds the exact triple.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteFingerprint {
    /// Stable route identity.
    pub route_id: String,
    /// Runtime identity.
    pub runtime_id: String,
    /// Adapter identity.
    pub adapter_id: String,
    /// Content-addressed fingerprint over the exact route/runtime/adapter triple.
    pub fingerprint: LowercaseSha256,
}

impl RouteFingerprint {
    /// Validates the identity components without interpreting provider claims.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        for (field, value) in [
            ("route_fingerprint.route_id", &self.route_id),
            ("route_fingerprint.runtime_id", &self.runtime_id),
            ("route_fingerprint.adapter_id", &self.adapter_id),
        ] {
            text(value, field)?;
        }
        Ok(())
    }
}

/// One in-flight operation and its recorded effect disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InFlightEffectDisposition {
    /// Stable in-flight operation identity.
    pub operation_id: String,
    /// Recorded effect disposition for the operation.
    pub effect_disposition: String,
}

impl InFlightEffectDisposition {
    fn validate(&self) -> Result<(), ProtocolError> {
        text(
            &self.operation_id,
            "in_flight_effect_disposition.operation_id",
        )?;
        text(
            &self.effect_disposition,
            "in_flight_effect_disposition.effect_disposition",
        )
    }
}

/// Explicit public causal link between a source and a target attempt (I7.15).
///
/// Every non-fresh admission is bound to exactly one persisted link. The link
/// carries digests, cursors, fences, and dispositions only; it never carries
/// native transcripts, reasoning signatures, tool-call IDs, or compaction
/// summaries. A target may start as a new `Rehydrated` attempt with
/// explicit unknowns, but it cannot inherit completion, authority, or proof
/// from an incomplete link ([`HandoffCausalLink::admits_causal_continuity`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffCausalLink {
    /// Source attempt identity.
    pub source_attempt_id: String,
    /// Source session public reference.
    pub source_session_ref: String,
    /// Source revision observed at handoff.
    pub source_revision: String,
    /// Source state fence.
    pub source_state_fence: StateFence,
    /// Source authority epoch; must match `source_state_fence.authority_epoch`.
    pub source_authority_epoch: EpochId,
    /// Source event cursor observed at handoff.
    pub source_event_cursor: Option<String>,
    /// Source outbox cursor observed at handoff.
    pub source_outbox_cursor: Option<String>,
    /// In-flight operations and their effect dispositions.
    pub in_flight_effect_dispositions: Vec<InFlightEffectDisposition>,
    /// Handoff checkpoint public reference.
    pub handoff_checkpoint_ref: String,
    /// Omission manifest digest.
    pub omission_manifest_digest: LowercaseSha256,
    /// Cursor a replay resumes from, when the handoff replays.
    pub replay_from_cursor: Option<String>,
    /// Sealed rehydration bundle digest, when the handoff rehydrates.
    pub rehydration_bundle_digest: Option<LowercaseSha256>,
    /// Target attempt identity.
    pub target_attempt_id: String,
    /// Target route fingerprint.
    pub target_route_fingerprint: RouteFingerprint,
    /// Post-resume revalidation receipt reference.
    pub post_resume_revalidation_ref: String,
    /// Completeness of this link.
    pub completeness: HandoffCompleteness,
}

impl HandoffCausalLink {
    /// Validates the causal link shape and the `COMPLETE` completeness floor.
    ///
    /// A `COMPLETE` link must carry both source cursors and a replay cursor
    /// or rehydration bundle digest; every other completeness level admits
    /// partial information.
    ///
    /// The attempt-identity rule applied here is the strict new-attempt
    /// shape: equal source and target attempts are refused. Callers that
    /// know the declared continuity mode use
    /// [`Self::validate_for_continuity`], which admits an equal attempt
    /// only for [`ContinuityKind::NativeResume`] (I7.15).
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_shape()?;
        if self.source_attempt_id == self.target_attempt_id {
            return Err(ProtocolError::InvalidField {
                field: "handoff_causal_link.target_attempt_id",
                reason: "target attempt must differ from the source attempt",
            });
        }
        Ok(())
    }

    /// Validates the link under its declared continuity mode (I7.15).
    ///
    /// Shape and completeness checks are unchanged from [`Self::validate`];
    /// only the attempt-identity rule is mode-derived through
    /// [`ContinuityKind::creates_new_attempt_identity`]: every mode except
    /// [`ContinuityKind::NativeResume`] creates a new ELIOT attempt, so an
    /// equal source/target attempt is refused exactly as in
    /// [`Self::validate`]. A `NativeResume` link may name the same attempt
    /// it continues; the compatible session and route, the fresh authority
    /// epoch, and the fingerprinted continuation state are then enforced by
    /// the owning admission validator, never by this shape check.
    pub fn validate_for_continuity(&self, continuity: ContinuityKind) -> Result<(), ProtocolError> {
        self.validate_shape()?;
        if self.source_attempt_id == self.target_attempt_id
            && continuity.creates_new_attempt_identity()
        {
            return Err(ProtocolError::InvalidField {
                field: "handoff_causal_link.target_attempt_id",
                reason: "target attempt must differ from the source attempt",
            });
        }
        Ok(())
    }

    /// Validates every link field except the attempt-identity rule.
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        text(
            &self.source_attempt_id,
            "handoff_causal_link.source_attempt_id",
        )?;
        text(
            &self.source_session_ref,
            "handoff_causal_link.source_session_ref",
        )?;
        text(&self.source_revision, "handoff_causal_link.source_revision")?;
        text(
            &self.target_attempt_id,
            "handoff_causal_link.target_attempt_id",
        )?;
        self.source_state_fence.validate()?;
        if !self
            .source_authority_epoch
            .is_same_authority(&self.source_state_fence.authority_epoch)
        {
            return Err(ProtocolError::InvalidField {
                field: "handoff_causal_link.source_authority_epoch",
                reason: "must match source_state_fence.authority_epoch",
            });
        }
        if let Some(cursor) = &self.source_event_cursor {
            text(cursor, "handoff_causal_link.source_event_cursor")?;
        }
        if let Some(cursor) = &self.source_outbox_cursor {
            text(cursor, "handoff_causal_link.source_outbox_cursor")?;
        }
        let mut seen_operations = std::collections::BTreeSet::new();
        for disposition in &self.in_flight_effect_dispositions {
            disposition.validate()?;
            if !seen_operations.insert(disposition.operation_id.as_str()) {
                return Err(ProtocolError::InvalidField {
                    field: "handoff_causal_link.in_flight_effect_dispositions",
                    reason: "must not contain duplicate operation_id values",
                });
            }
        }
        if self.in_flight_effect_dispositions.len() > MAX_ROUTE_CONTINUATION_IN_FLIGHT_DISPOSITIONS
        {
            return Err(ProtocolError::InvalidField {
                field: "handoff_causal_link.in_flight_effect_dispositions",
                reason: "exceeds the bounded disposition ceiling",
            });
        }
        text(
            &self.handoff_checkpoint_ref,
            "handoff_causal_link.handoff_checkpoint_ref",
        )?;
        if let Some(cursor) = &self.replay_from_cursor {
            text(cursor, "handoff_causal_link.replay_from_cursor")?;
        }
        self.target_route_fingerprint.validate()?;
        text(
            &self.post_resume_revalidation_ref,
            "handoff_causal_link.post_resume_revalidation_ref",
        )?;
        if self.completeness == HandoffCompleteness::Complete
            && (self.source_event_cursor.is_none()
                || self.source_outbox_cursor.is_none()
                || (self.replay_from_cursor.is_none() && self.rehydration_bundle_digest.is_none()))
        {
            return Err(ProtocolError::InvalidField {
                field: "handoff_causal_link.completeness",
                reason: "COMPLETE requires event/outbox cursors and a replay cursor or rehydration bundle digest",
            });
        }
        Ok(())
    }

    /// Returns whether the target may inherit completion, authority, or proof
    /// from this link.
    ///
    /// Inheritance is admitted only for a `COMPLETE` link whose source
    /// revision, state fence, authority epoch, cursors, and replay/rehydration
    /// binding are present and valid. A `PARTIAL`, `STALE`, or `UNKNOWN` link
    /// — or any link missing required cursor/effect information — never
    /// admits causal-continuity inheritance.
    #[must_use]
    pub fn admits_causal_continuity(&self) -> bool {
        self.completeness == HandoffCompleteness::Complete && self.validate().is_ok()
    }
}

/// Sealed inert compiled-state/evidence packet for a `Rehydrated` attempt.
///
/// The packet carries only the portable compiled state named by I7.15:
/// task/acceptance and current plan, current Epistemic Position and
/// Architecture constraints, base/diff/environment receipts, artifacts and
/// exact evidence handles, failed paths and reopen conditions, and open
/// unknowns with permissions, budgets, and output schema.
///
/// The bundle is sealed: a native transcript, reasoning signature, tool-call
/// ID, or compaction summary is not portable state and has no field here.
/// `deny_unknown_fields` rejects any attempt to smuggle non-portable state
/// into the packet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RehydrationBundle {
    /// Task/acceptance criteria and the current plan.
    pub task_acceptance_and_plan: String,
    /// Current Epistemic Position and Architecture constraints.
    pub epistemic_position_and_architecture_constraints: String,
    /// Base/diff/environment receipt handles.
    pub base_diff_environment_receipts: Vec<String>,
    /// Artifact and exact evidence handles.
    pub artifacts_and_evidence_handles: Vec<String>,
    /// Failed paths and their reopen conditions.
    pub failed_paths_and_reopen_conditions: Vec<String>,
    /// Open unknowns, permissions, budgets, and output schema.
    pub open_unknowns_permissions_budgets_output_schema: String,
}

impl RehydrationBundle {
    /// Validates the sealed packet shape and bounds.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        bounded_text(
            &self.task_acceptance_and_plan,
            "rehydration_bundle.task_acceptance_and_plan",
        )?;
        bounded_text(
            &self.epistemic_position_and_architecture_constraints,
            "rehydration_bundle.epistemic_position_and_architecture_constraints",
        )?;
        validate_handles(
            &self.base_diff_environment_receipts,
            "rehydration_bundle.base_diff_environment_receipts",
        )?;
        validate_handles(
            &self.artifacts_and_evidence_handles,
            "rehydration_bundle.artifacts_and_evidence_handles",
        )?;
        validate_handles(
            &self.failed_paths_and_reopen_conditions,
            "rehydration_bundle.failed_paths_and_reopen_conditions",
        )?;
        bounded_text(
            &self.open_unknowns_permissions_budgets_output_schema,
            "rehydration_bundle.open_unknowns_permissions_budgets_output_schema",
        )
    }

    /// Returns the canonical content digest of the sealed packet.
    pub fn canonical_digest(&self) -> Result<String, ProtocolError> {
        let bytes =
            canonical_json_bytes(self).map_err(|error| ProtocolError::Json(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Opaque provider/harness continuation state required for exact resume.
///
/// Route Continuation State is separate from canonical cognitive inheritance;
/// it is never evidence, authority, or rationale; it is not indexed and is
/// never sent to another route automatically; it is protected by
/// privacy/retention; it is scoped to its exact [`RouteFingerprint`]; and it
/// is deleted on expiry, route invalidation, or provider-policy request
/// ([`RouteContinuationDeletionReason`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteContinuationState {
    /// Exact route/runtime/adapter fingerprint this state is scoped to.
    pub route_fingerprint: RouteFingerprint,
    /// Opaque provider/harness continuation bytes, never interpreted here.
    pub opaque_state: String,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl RouteContinuationState {
    /// Validates the opaque state shape and expiry.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.route_fingerprint.validate()?;
        text(&self.opaque_state, "route_continuation_state.opaque_state")?;
        if self.opaque_state.len() > MAX_ROUTE_CONTINUATION_OPAQUE_STATE_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "route_continuation_state.opaque_state",
                reason: "exceeds the bounded opaque state ceiling",
            });
        }
        if self.expires_at_unix_ms == 0 {
            return Err(ProtocolError::InvalidField {
                field: "route_continuation_state.expires_at_unix_ms",
                reason: "expiry must be greater than zero",
            });
        }
        Ok(())
    }

    /// Returns whether this state is scoped to the exact given fingerprint.
    #[must_use]
    pub fn is_scoped_to(&self, fingerprint: &RouteFingerprint) -> bool {
        &self.route_fingerprint == fingerprint
    }

    /// Returns whether this state is expired at the given Unix millisecond.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.expires_at_unix_ms
    }
}

/// Deletion trigger for opaque Route Continuation State (I7.15).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum RouteContinuationDeletionReason {
    /// The state reached its absolute expiry.
    Expired,
    /// The route was invalidated.
    RouteInvalidated,
    /// A provider-policy request demanded deletion.
    ProviderPolicyRequest,
}

fn text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    text(value, field)?;
    if value.len() > MAX_ROUTE_CONTINUATION_TEXT_BYTES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}

fn validate_handles(values: &[String], field: &'static str) -> Result<(), ProtocolError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(ProtocolError::InvalidField {
                field,
                reason: "must not contain duplicate handles",
            });
        }
    }
    if values.len() > MAX_ROUTE_CONTINUATION_HANDLES {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded handle ceiling",
        });
    }
    Ok(())
}
