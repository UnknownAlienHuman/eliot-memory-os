//! Initial WorkScope source admission and canonical snapshot preparation.
//!
//! This module joins the authenticated request and authority fence, a real
//! initial WorkScope binding admission, the exact Bootstrap source capture,
//! and a fresh WorkScope-owner CAS expectation. It does not resolve a scope,
//! infer an observed workspace, admit source candidates, or install a Store
//! row. Those facts come from their respective owners and are supplied by the
//! owning daemon ingress.

use std::collections::BTreeMap;

use eliot_bootstrap::capture::NormativePairSourceCapture;
use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{AuthorityBinding, CausalBinding};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationId, OperationManifestDigest, ScopeId, SecurityContext, TransitionClass,
    generated_operation_manifests, operation_manifest_set_digest,
    supported_admission_contract_set_digest,
};
use crate::composition::WorkScopeOwnerSnapshotReadback;
use eliot_workscope::{
    GoverningSourceSet, PrivacyProfile, ScopeBinding, WorkScopeBindingOwner,
    WorkScopeBindingSnapshot, WorkScopeDescriptor, admit_initial_binding,
};
use serde_json::Value;
use thiserror::Error;

/// Fully prepared initial owner snapshot and the ordinary canonical write
/// transition that persists it.
#[derive(Clone, Debug)]
pub struct PreparedWorkScopeSourceAdmission {
    /// Initial owner candidate to install only after canonical Store readback.
    pub owner: WorkScopeBindingOwner,
    /// Exact source-capture-enriched owner snapshot encoded in the transition.
    pub snapshot: WorkScopeBindingSnapshot,
    /// Canonical envelope admitted by the Governor.
    pub envelope: CanonicalWriteEnvelope,
    /// Immutable transition prepared from `envelope`.
    pub transition: eliot_store_api::PreparedTransition,
    /// The exact authority and causal inputs checked against the request fence.
    pub authority_binding: AuthorityBinding,
    /// The exact causal binding checked against the request fence.
    pub causal_binding: CausalBinding,
    /// Receipt-domain scope binding using the request's admitted ProductId.
    pub receipt_work_scope_binding: eliot_receipts::WorkScopeBinding,
    /// Canonical JSON projection of `receipt_work_scope_binding`.
    pub receipt_work_scope_binding_json: String,
    /// SHA-256 of the canonical receipt scope-binding projection.
    pub receipt_work_scope_binding_sha256: String,
}

/// Refusal while preparing an initial WorkScope source-admission transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkScopeSourceAdmissionError {
    /// A supplied identity, authority, causal, binding, or CAS fence differed.
    #[error("WorkScope source admission inputs do not share the exact request fence")]
    FenceMismatch,
    /// Initial admission was attempted over an already bound owner row.
    #[error("initial WorkScope source admission requires an empty baseline owner")]
    OwnerAlreadyExists,
    /// The empty owner row lacks a nonzero revision or Store digest.
    #[error("empty WorkScope owner readback has an invalid revision or Store digest")]
    InvalidOwnerReadback,
    /// The owner revision overflowed while advancing the admitted snapshot.
    #[error("WorkScope owner revision overflowed")]
    OwnerRevisionOverflow,
    /// The source capture could not be rendered as canonical JSON.
    #[error("normative pair source capture serialization failed: {0}")]
    CaptureSerialization(String),
    /// The initial scope, source closure, or matched-guard admission refused.
    #[error("initial WorkScope binding admission refused: {0}")]
    InitialAdmission(String),
    /// The source-capture-enriched snapshot failed owner validation.
    #[error("WorkScope source-admission snapshot is invalid: {0}")]
    Snapshot(String),
    /// The canonical transition could not be constructed or validated.
    #[error("canonical WorkScope source-admission transition is invalid: {0}")]
    Transition(String),
}

/// Creates a source-admission snapshot from genuine initial-scope inputs and
/// prepares its normal canonical `RecordWorkScopeSnapshot` transition.
///
/// `binding`, `observed`, `descriptor`, `sources`, and `privacy` must be the
/// exact values obtained at the authenticated cold-start/initial-scope edge.
/// The function re-runs the existing initial binding admission and computes
/// the matched guard itself. It never accepts a caller-created guard receipt.
/// `capture` must be the parsed result of
/// `capture_normative_pair_sources` over the same explicit repository root;
/// WorkScope validates its canonical bytes and the role/reference/content
/// digest join against the admitted `sources` before accepting the snapshot.
///
/// `owner_readback` must be the exact-fence named `owner/work_scope` read.
/// This initial-admission function accepts only an empty baseline row; a bound
/// owner must use its dedicated update/admission flow. The Store operation
/// receives the exact empty-row revision and provider digest and performs the
/// CAS.
#[allow(
    clippy::too_many_arguments,
    reason = "this one owner boundary joins every independently owned admission input without hiding authority in a generic bundle"
)]
pub fn prepare_initial_work_scope_source_admission(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    authority: &AuthorityBinding,
    causal: &CausalBinding,
    descriptor: &WorkScopeDescriptor,
    binding: &ScopeBinding,
    observed: &ScopeBinding,
    sources: &GoverningSourceSet,
    privacy: &PrivacyProfile,
    capture: &NormativePairSourceCapture,
    owner_readback: &WorkScopeOwnerSnapshotReadback,
) -> Result<PreparedWorkScopeSourceAdmission, WorkScopeSourceAdmissionError> {
    identity
        .validate()
        .map_err(|_| WorkScopeSourceAdmissionError::FenceMismatch)?;
    let fence = &identity.request.state_fence;
    if identity.request.metadata.state_fence != *fence
        || authority.state_fence != *fence
        || causal.state_fence != *fence
        || !fence.authority_epoch.is_same_authority(&authority.authority_epoch)
        || !eliot_store_api::effect_is_at_most(
            EffectClass::ReversibleMutation,
            authority.allowed_effect,
        )
        || binding.scope.generation != fence.resource_generation.value()
        || observed.scope.generation != fence.resource_generation.value()
    {
        return Err(WorkScopeSourceAdmissionError::FenceMismatch);
    }
    let (expected_revision, expected_digest) = match owner_readback {
        WorkScopeOwnerSnapshotReadback::Empty {
            state_fence,
            owner_revision,
            value_digest,
        } if state_fence == fence
            && *owner_revision > 0
            && is_sha256(value_digest) => (*owner_revision, value_digest.clone()),
        WorkScopeOwnerSnapshotReadback::Empty { state_fence, .. }
            if state_fence != fence =>
        {
            return Err(WorkScopeSourceAdmissionError::FenceMismatch);
        }
        WorkScopeOwnerSnapshotReadback::Empty { .. } => {
            return Err(WorkScopeSourceAdmissionError::InvalidOwnerReadback);
        }
        WorkScopeOwnerSnapshotReadback::Bound(owner) => {
            if owner.state_fence != *fence {
                return Err(WorkScopeSourceAdmissionError::FenceMismatch);
            }
            return Err(WorkScopeSourceAdmissionError::OwnerAlreadyExists);
        }
    };
    let owner_revision = expected_revision
        .checked_add(1)
        .ok_or(WorkScopeSourceAdmissionError::OwnerRevisionOverflow)?;

    // The same source set that proved the initial MATCHED guard is retained
    // with the capture; callers cannot guard one closure and persist another.
    let initially_admitted = admit_initial_binding(
        descriptor,
        owner_revision,
        fence,
        binding,
        observed,
        sources,
        privacy,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    let initial_snapshot = initially_admitted
        .read_current(fence)
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;

    let capture_bytes = canonical_json_bytes(capture)
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_json = String::from_utf8(capture_bytes.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_sha256 = sha256_hex(&capture_bytes);
    let product_id = identity.request.metadata.product_id.clone();
    let snapshot = WorkScopeBindingSnapshot::new_with_normative_pair_source_capture_for_product(
        fence.clone(),
        owner_revision,
        initial_snapshot.binding.clone(),
        initial_snapshot.guard_receipt.clone(),
        sources.clone(),
        privacy.clone(),
        product_id.clone(),
        capture_json,
        capture_sha256,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;
    let owner = WorkScopeBindingOwner::new(snapshot.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;

    let receipt_work_scope_binding = eliot_receipts::WorkScopeBinding {
        scope_id: eliot_receipts::WorkScopeId::new(binding.scope.scope_ref.clone())
            .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?,
        product_id,
        resource_generation: fence.resource_generation,
        state_fence: fence.clone(),
    };
    let receipt_binding_bytes = canonical_json_bytes(&receipt_work_scope_binding)
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let receipt_work_scope_binding_json = String::from_utf8(receipt_binding_bytes.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let receipt_work_scope_binding_sha256 = sha256_hex(&receipt_binding_bytes);

    let snapshot_json = String::from_utf8(
        canonical_json_bytes(&snapshot)
            .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_work_scope_revision".to_owned(),
        Value::String(expected_revision.to_string()),
    );
    parameters.insert(
        "expected_work_scope_digest".to_owned(),
        Value::String(expected_digest),
    );
    parameters.insert(
        "snapshot_json".to_owned(),
        Value::String(snapshot_json),
    );
    let operation_manifest_digest = operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let admission_contract_set_digest = supported_admission_contract_set_digest()
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let scope_id = ScopeId::new(binding.scope.scope_ref.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest,
        operation_manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordWorkScopeSnapshot,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let transition = envelope
        .prepare()
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    if transition.state_fence != *fence || transition.scope_id != envelope.scope_id {
        return Err(WorkScopeSourceAdmissionError::FenceMismatch);
    }

    Ok(PreparedWorkScopeSourceAdmission {
        owner,
        snapshot,
        envelope,
        transition,
        authority_binding: authority.clone(),
        causal_binding: causal.clone(),
        receipt_work_scope_binding,
        receipt_work_scope_binding_json,
        receipt_work_scope_binding_sha256,
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
