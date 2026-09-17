//! Explicit user-requested canonical erasure admission (issue #1712).
//!
//! This module owns the single deterministic builder that turns an explicit
//! user erasure request into the admitted [`PreparedTransition`] carrying the
//! [`NamedMutationOperation::ApplyErasure`] named operation under
//! [`TransitionClass::Erasure`]. There is exactly one path and no automatic
//! trigger: the caller must supply the user-initiated request identity (exact
//! scope, explicit reason, requester handle) and non-empty proof/approval
//! handles. Maintenance, curation, Dreamer, and scheduler paths furnish none
//! of these, so they can never reach the erasure transaction.
//!
//! The builder preserves the original privacy, visibility, retention, and
//! provenance context by carrying the caller's [`SecurityContext`] unchanged
//! into the transition. The store bridge applies only the recorded plan: the
//! subject, scope, and surface denominator below are copied verbatim from the
//! admitted parameters at dispatch, never derived.
//!
//! Surface denominator encoding: `surfaces` carries the handler-surface names
//! in deterministic canonical (sorted, comma-joined) order. Closed-enum
//! membership is enforced at dispatch by each handler against its own surface
//! vocabulary; this module enforces the canonical shape (non-empty, unique,
//! sorted, non-blank) shared by every handler.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OperationManifestDigest, OrderingScopeId, PreparedTransition, ScopeId,
    SecurityContext, StoreError, TransitionClass,
};
use eliot_contracts::StateFence;

/// Separator of the canonical surface-denominator encoding.
pub const ERASURE_SURFACE_SEPARATOR: &str = ",";

/// Typed parameter carrying the exact admitted erasure target.
pub const ERASURE_PARAM_SUBJECT: &str = "subject";
/// Typed parameter carrying the canonical surface denominator.
pub const ERASURE_PARAM_SURFACES: &str = "surfaces";
/// Typed parameter carrying the explicit user reason (never automatic).
pub const ERASURE_PARAM_REASON: &str = "reason";
/// Typed parameter carrying the user-initiated requester identity handle.
pub const ERASURE_PARAM_REQUESTER: &str = "requester";
/// Typed parameter binding the stable intent/execution identity.
pub const ERASURE_PARAM_OPERATION_ID: &str = "erasure_operation_id";

/// Encodes handler-surface names into the canonical denominator string.
///
/// Names must be non-empty, non-blank, unique, and are emitted in sorted
/// order so the same admitted set always yields the same bytes.
pub fn encode_erasure_surfaces(names: &[&str]) -> Result<String, StoreError> {
    if names.is_empty() {
        return Err(StoreError::Empty {
            field: "erasure.surfaces",
        });
    }
    let mut sorted: Vec<&str> = names.to_vec();
    sorted.sort_unstable();
    let mut seen: Option<&str> = None;
    for name in &sorted {
        super::validate_text(name, "erasure.surfaces")?;
        if seen == Some(*name) {
            return Err(StoreError::Duplicate {
                field: "erasure.surfaces",
            });
        }
        seen = Some(*name);
    }
    Ok(sorted.join(ERASURE_SURFACE_SEPARATOR))
}

/// Decodes the canonical denominator back into surface names.
///
/// Rejects empty, blank, or duplicated entries fail-closed; order is
/// preserved as admitted.
pub fn decode_erasure_surfaces(value: &str) -> Result<Vec<String>, StoreError> {
    let names: Vec<String> = value
        .split(ERASURE_SURFACE_SEPARATOR)
        .map(str::to_owned)
        .collect();
    if names.is_empty() {
        return Err(StoreError::Empty {
            field: "erasure.surfaces",
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for name in &names {
        super::validate_text(name, "erasure.surfaces")?;
        if !seen.insert(name.clone()) {
            return Err(StoreError::Duplicate {
                field: "erasure.surfaces",
            });
        }
    }
    Ok(names)
}

/// Explicit user erasure admission request (issue #1712).
///
/// Every field is required except where noted: there are no silent defaults
/// for authority, scope, effect, or identity material.
#[derive(Clone, Debug)]
pub struct ErasureAdmissionRequest {
    /// Stable operation identity shared by staging, execution, and receipt.
    pub identity: OperationIdentity,
    /// Exact admitted scope: the only scope the deletion may touch.
    pub scope_id: ScopeId,
    /// Ordering scope serializing this transition.
    pub ordering_scope: OrderingScopeId,
    /// State fence the destructive calls execute under.
    pub state_fence: StateFence,
    /// Exact admitted target subject.
    pub subject: String,
    /// Handler-surface denominator (validated canonical shape here, closed
    /// membership at dispatch).
    pub surfaces: Vec<String>,
    /// Explicit user reason; automatic paths have none.
    pub reason: String,
    /// User-initiated requester identity handle.
    pub requester: String,
    /// Non-empty explicit user approval handles (authority/proof refs).
    pub approval_refs: Vec<String>,
    /// Digest of the admission contract set bound at admission time.
    pub admission_contract_set_digest: String,
    /// Digest of the operation manifest set admitting `ApplyErasure`.
    pub operation_manifest_digest: OperationManifestDigest,
    /// Original privacy, visibility, retention, and provenance context,
    /// carried unchanged.
    pub security: SecurityContext,
    /// Event/projection/relation intents for the committing transition.
    pub event_projection_relation_intents: EventProjectionRelationIntents,
}

impl ErasureAdmissionRequest {
    /// Validates the explicit-request shape without issuing any authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.identity.validate()?;
        super::validate_text(&self.subject, "erasure.subject")?;
        if self.surfaces.is_empty() {
            return Err(StoreError::Empty {
                field: "erasure.surfaces",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for surface in &self.surfaces {
            super::validate_text(surface, "erasure.surfaces")?;
            if !seen.insert(surface.clone()) {
                return Err(StoreError::Duplicate {
                    field: "erasure.surfaces",
                });
            }
        }
        super::validate_text(&self.reason, "erasure.reason")?;
        super::validate_text(&self.requester, "erasure.requester")?;
        if self.approval_refs.is_empty() {
            return Err(StoreError::InvalidField {
                field: "proof_or_approval_ref",
                reason: "erasure requires explicit user approval",
            });
        }
        super::unique(
            self.approval_refs.iter().cloned(),
            "proof_and_approval_refs",
        )?;
        for reference in &self.approval_refs {
            super::validate_text(reference, "proof_or_approval_ref")?;
        }
        super::validate_digest(
            &self.admission_contract_set_digest,
            "admission_contract_set_digest",
        )?;
        self.event_projection_relation_intents.validate()?;
        self.security.validate(&self.state_fence)?;
        Ok(())
    }
}

/// Builds the deterministic admitted erasure transition.
///
/// Same inputs always yield the same transition bytes: surfaces are encoded
/// in canonical order and parameters travel in a `BTreeMap`. The result still
/// requires catalogue admission
/// ([`PreparedTransition::validate_against_catalogue`]) and canonical-request
/// hash binding by the caller before staging; this builder issues no
/// authority and performs no store effect.
pub fn admit_erasure_transition(
    request: &ErasureAdmissionRequest,
) -> Result<PreparedTransition, StoreError> {
    request.validate()?;
    let surface_refs: Vec<&str> = request.surfaces.iter().map(String::as_str).collect();
    let surfaces = encode_erasure_surfaces(&surface_refs)?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        ERASURE_PARAM_SUBJECT.to_owned(),
        Value::String(request.subject.clone()),
    );
    parameters.insert(
        ERASURE_PARAM_SURFACES.to_owned(),
        Value::String(surfaces),
    );
    parameters.insert(
        ERASURE_PARAM_REASON.to_owned(),
        Value::String(request.reason.clone()),
    );
    parameters.insert(
        ERASURE_PARAM_REQUESTER.to_owned(),
        Value::String(request.requester.clone()),
    );
    parameters.insert(
        ERASURE_PARAM_OPERATION_ID.to_owned(),
        Value::String(request.identity.operation_id.to_string()),
    );
    let transition = PreparedTransition {
        identity: request.identity.clone(),
        state_fence: request.state_fence.clone(),
        scope_id: request.scope_id.clone(),
        task_id: None,
        ordering_scopes: vec![request.ordering_scope.clone()],
        transition_class: TransitionClass::Erasure,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: request.admission_contract_set_digest.clone(),
        operation_manifest_digest: request.operation_manifest_digest.clone(),
        named_operations: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ApplyErasure,
            parameters,
        }],
        event_projection_relation_intents: request.event_projection_relation_intents.clone(),
        security: request.security.clone(),
        required_proof_and_approval_refs: request.approval_refs.clone(),
    };
    transition.validate()?;
    Ok(transition)
}
