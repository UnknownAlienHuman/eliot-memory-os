//! Governor restore-coordination transition builder (issues #959/#960).
//!
//! Architecture: A12.3 One Governed Write Path (this builder stages
//! nothing and commits nothing — it assembles the deterministic,
//! immutable execution plan the Kernel mechanically checks and the store
//! bridge executes); I1.8 Exact Ownership and Call Paths (single canonical
//! `PreparedTransition` carrying operation identity, admission decision
//! digest, fence, ordering, class, and proof handles; mismatch conflicts,
//! never retries as the same decision); I5.6 Admission and staging (the
//! admission decision digest is built at the semantic-admission point and
//! travels in `required_proof_and_approval_refs`); crates/governor/AGENTS.md
//! owned semantics (semantic admission and immutable `PreparedTransition`
//! construction live in the Governor subtree).
//!
//! This cell owns Governor-side construction of the restore coordination
//! transition: the caller supplies the minter-bound restore identity, the
//! live fence, the Governor-known scope/ordering/task/security/catalogue
//! bindings, the coordination values, and its proof handles; the builder
//! validates every binding, assembles the closed `RecoverySchema`
//! transition carrying the six coordination parameters, and validates the
//! assembled plan. It invents no semantics: the restore identity,
//! digests, fence, and destination arrive as explicit inputs already
//! bound by the kernel minter, and every one is re-verified here
//! (shapes, class fit, digest presence, parameter equality against the
//! inputs) before the plan exists. A diverged input refuses instead of
//! producing a plan.
//!
//! The coordination parameter vocabulary below shadows the kernel
//! restore owner's closed keys value-for-value until the Store catalogue
//! owns them (M1B owner): if the vocabularies ever diverge, the commit
//! wire's parameter equality refuses fail-closed — never a silent pass.
//! The named operation variant stays Store-owned: the caller supplies it
//! and this builder requires its class to be `RecoverySchema`, so the
//! builder works unchanged whichever converged variant the paired
//! candidate lands (a dedicated coordination record or a
//! coordination-carrying reconcile), without naming either.
//!
//! Forbidden authority: no staging, no commit, no receipt synthesis, no
//! catalogue reinterpretation, no ambient clock, I/O, or live query. Like
//! the neighboring admission joins, this builder never mints admission:
//! it assembles the admitted plan from already-bound inputs.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationIdentity, OperationManifestDigest, OrderingScopeId, PreparedTransition, ScopeId,
    SecurityContext, TransitionClass,
};
use serde_json::Value;

/// Closed coordination parameter carrying the admitted operation identity.
pub const COORD_PARAM_OPERATION_ID: &str = "coordination_operation_id";
/// Closed coordination parameter carrying the admitted destination.
pub const COORD_PARAM_DESTINATION: &str = "coordination_destination";
/// Closed coordination parameter carrying the admitted payload digest
/// (the restore identity's canonical request hash).
pub const COORD_PARAM_PAYLOAD_DIGEST: &str = "coordination_payload_digest";
/// Closed coordination parameter carrying the admitted fence digest.
pub const COORD_PARAM_FENCE_DIGEST: &str = "coordination_fence_digest";
/// Closed coordination parameter carrying the coordination decision digest.
pub const COORD_PARAM_DECISION_DIGEST: &str = "coordination_decision_digest";
/// Closed coordination parameter carrying the Governor admission digest
/// this coordination was built from.
pub const COORD_PARAM_ADMISSION_DIGEST: &str = "coordination_admission_digest";

fn non_blank(value: &str, field: &'static str) -> Result<(), CoordinationBuildError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CoordinationBuildError::InvalidField {
            field,
            reason: "must be non-blank with no control characters",
        });
    }
    Ok(())
}

fn hex64(value: &str, field: &'static str) -> Result<(), CoordinationBuildError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CoordinationBuildError::InvalidField {
            field,
            reason: "must be a lowercase 64-hex digest",
        });
    }
    Ok(())
}

/// Typed coordination-transition build failures. Malformed or diverged
/// input never produces a plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinationBuildError {
    /// A required field is malformed.
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Why it failed.
        reason: &'static str,
    },
    /// A Store contract check failed.
    Store(String),
    /// A foundation contract check failed.
    Foundation(String),
    /// Canonical encoding failed.
    Serialization(String),
}

impl std::fmt::Display for CoordinationBuildError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidField { field, reason } => {
                write!(
                    formatter,
                    "coordination build field is invalid: {field}: {reason}"
                )
            }
            Self::Store(detail) => {
                write!(formatter, "coordination store contract failure: {detail}")
            }
            Self::Foundation(detail) => {
                write!(
                    formatter,
                    "coordination foundation contract failure: {detail}"
                )
            }
            Self::Serialization(detail) => {
                write!(formatter, "coordination serialization failure: {detail}")
            }
        }
    }
}

impl std::error::Error for CoordinationBuildError {}

/// Governor inputs for one restore coordination transition.
///
/// Identity, fence, digests, and destination arrive already bound by the
/// kernel minter; scope, ordering, task, catalogue, security, and proof
/// handles arrive from Governor context. The builder re-verifies every
/// binding below; nothing is trusted from spelling alone.
#[derive(Clone, Debug)]
pub struct CoordinationTransitionRequest {
    /// Minter-built restore identity triple (operation, idempotency,
    /// canonical request hash). Never invented here.
    pub identity: OperationIdentity,
    /// Live fence the coordination commits under.
    pub state_fence: StateFence,
    /// Governor-known coordination scope.
    pub scope_id: ScopeId,
    /// Task binding, when the coordination is task-relative.
    pub task_id: Option<String>,
    /// Governor-known ordering scopes serializing the commit (non-empty).
    pub ordering_scopes: Vec<OrderingScopeId>,
    /// Catalogue admission digest of the supported contract set.
    pub admission_contract_set_digest: String,
    /// Catalogue manifest digest of the supported named operations.
    pub operation_manifest_digest: OperationManifestDigest,
    /// Store-owned named operation carrying the coordination payload.
    /// Its class must be `RecoverySchema`; the exact variant stays
    /// Store-owned (M1B), so it is supplied, never named, here.
    pub operation: NamedMutationOperation,
    /// Admitted isolated destination (plan target).
    pub destination: String,
    /// Admitted payload digest (restore identity's canonical request hash).
    pub payload_digest: String,
    /// Governor admission decision digest the coordination links.
    pub admission_decision_digest: String,
    /// Coordination decision digest over the exact tuple.
    pub coordination_decision_digest: String,
    /// Governor security context carried unchanged.
    pub security: SecurityContext,
    /// Caller proof handles; the admission digest is appended.
    pub proof_refs: Vec<String>,
}

/// Builds the deterministic restore coordination transition.
///
/// Pure function of the request: validates every binding (identity,
/// fence, class fit, digest shapes, destination, security, proof
/// handles), assembles the single-operation `RecoverySchema` plan
/// carrying the six closed coordination parameters, binds the admission
/// decision digest into the proof handles, and validates the assembled
/// plan. Returns the executable transition or a typed refusal; it stages,
/// commits, and receipts nothing.
pub fn build_coordination_transition(
    request: CoordinationTransitionRequest,
) -> Result<PreparedTransition, CoordinationBuildError> {
    request
        .identity
        .validate()
        .map_err(|error| CoordinationBuildError::Store(error.to_string()))?;
    request
        .state_fence
        .validate()
        .map_err(|error| CoordinationBuildError::Foundation(error.to_string()))?;
    if request.ordering_scopes.is_empty() {
        return Err(CoordinationBuildError::InvalidField {
            field: "coordination.ordering_scopes",
            reason: "at least one ordering scope is required",
        });
    }
    if let Some(task_id) = request.task_id.as_deref() {
        non_blank(task_id, "coordination.task_id")?;
    }
    if request.operation.transition_class() != TransitionClass::RecoverySchema {
        return Err(CoordinationBuildError::InvalidField {
            field: "coordination.transition_class",
            reason: "coordination commits only under RecoverySchema",
        });
    }
    hex64(
        &request.admission_contract_set_digest,
        "coordination.admission_contract_set_digest",
    )?;
    non_blank(&request.destination, "coordination.destination")?;
    hex64(&request.payload_digest, "coordination.payload_digest")?;
    hex64(
        &request.admission_decision_digest,
        "coordination.admission_decision_digest",
    )?;
    hex64(
        &request.coordination_decision_digest,
        "coordination.coordination_decision_digest",
    )?;
    request
        .security
        .validate(&request.state_fence)
        .map_err(|error| CoordinationBuildError::Store(error.to_string()))?;
    for proof in &request.proof_refs {
        non_blank(proof, "coordination.proof_refs")?;
    }
    if request.identity.canonical_request_hash != request.payload_digest {
        return Err(CoordinationBuildError::InvalidField {
            field: "coordination.payload_digest",
            reason: "payload digest must equal the restore identity hash",
        });
    }
    let fence_bytes = canonical_json_bytes(&request.state_fence)
        .map_err(|error| CoordinationBuildError::Serialization(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        COORD_PARAM_OPERATION_ID.to_owned(),
        Value::String(request.identity.operation_id.to_string()),
    );
    parameters.insert(
        COORD_PARAM_DESTINATION.to_owned(),
        Value::String(request.destination.clone()),
    );
    parameters.insert(
        COORD_PARAM_PAYLOAD_DIGEST.to_owned(),
        Value::String(request.payload_digest.clone()),
    );
    parameters.insert(
        COORD_PARAM_FENCE_DIGEST.to_owned(),
        Value::String(sha256_hex(&fence_bytes)),
    );
    parameters.insert(
        COORD_PARAM_DECISION_DIGEST.to_owned(),
        Value::String(request.coordination_decision_digest.clone()),
    );
    parameters.insert(
        COORD_PARAM_ADMISSION_DIGEST.to_owned(),
        Value::String(request.admission_decision_digest.clone()),
    );
    let mut proof_refs: BTreeSet<String> = request.proof_refs.into_iter().collect();
    proof_refs.insert(request.admission_decision_digest.clone());
    let transition = PreparedTransition {
        identity: request.identity,
        state_fence: request.state_fence,
        scope_id: request.scope_id,
        task_id: request.task_id,
        ordering_scopes: request.ordering_scopes,
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: request.admission_contract_set_digest,
        operation_manifest_digest: request.operation_manifest_digest,
        named_operations: vec![NamedMutationRequest {
            operation: request.operation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: request.security,
        required_proof_and_approval_refs: proof_refs.into_iter().collect(),
    };
    transition
        .validate()
        .map_err(|error| CoordinationBuildError::Store(error.to_string()))?;
    Ok(transition)
}
