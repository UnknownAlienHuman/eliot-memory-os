//! Exact current use-site facts for Instrument Registry authority admission.
//!
//! Values are compiled from current Governor owner records and the canonical
//! registration operation profile. The mechanical subset is never used as a
//! source for the use site being checked against it.

use crate::instrument_registry_registration::INSTRUMENT_REGISTRY_REGISTER_OPERATION;
use eliot_authority::{AuthorityError, AuthorityUseSite, GrantRecoveryRecord, LogicalTime};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{EffectClass, OperationBinding, ProofCeiling, WorkScopeBinding};
use eliot_session::{AgentSession, SessionState};
use eliot_store_api::TransitionClass;
use eliot_workscope::WorkScopeBindingSnapshot;

/// Compiles the current exact use site for one canonical grant and the
/// Instrument Registry registration operation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_instrument_registry_use_site(
    canonical_grant: &GrantRecoveryRecord,
    holder_principal: &str,
    work_scope: &WorkScopeBinding,
    work_scope_snapshot: &WorkScopeBindingSnapshot,
    session: &AgentSession,
    request_identity: &RequestIdentity,
    operation: &OperationBinding,
    operation_name: &str,
    resource_ref: &str,
    canonical_payload_sha256: &str,
    now: LogicalTime,
) -> Result<AuthorityUseSite, AuthorityError> {
    work_scope_snapshot
        .validate()
        .map_err(|_| AuthorityError::StaleEffectAuthority("work_scope_snapshot_invalid"))?;
    request_identity
        .validate()
        .map_err(|_| AuthorityError::IdentityConflict)?;
    if holder_principal.trim().is_empty()
        || canonical_grant.holder != holder_principal
        || canonical_grant.status != eliot_authority::GrantStatus::Active
        || now.value() < canonical_grant.issued_at
        || now.value() >= canonical_grant.expires_at
        || canonical_grant.binding.state_fence != work_scope.state_fence
        || work_scope_snapshot.state_fence != work_scope.state_fence
        || work_scope_snapshot.binding.scope.scope_ref != work_scope.scope_id.as_str()
        || work_scope_snapshot.binding.scope.generation != work_scope.resource_generation.value()
        || request_identity.request.state_fence != work_scope.state_fence
        || operation.state_fence != work_scope.state_fence
        || operation.effect != EffectClass::ReversibleMutation
        || operation.effect > canonical_grant.binding.allowed_effect
        || operation.operation_kind != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || operation_name != INSTRUMENT_REGISTRY_REGISTER_OPERATION
        || resource_ref != work_scope.scope_id.as_str()
        || operation.request_id != request_identity.request.metadata.request_id
        || operation.idempotency_key != request_identity.idempotency_key
        || request_identity.request.metadata.session_id.as_ref() != Some(&session.session_id)
        || session.state_fence != work_scope.state_fence
        || !session
            .authority_epoch
            .is_same_authority(&canonical_grant.binding.authority_epoch)
        || now.value() >= request_identity.deadline_unix_ms
        || now.value() >= session.expires_at
        || session.heartbeat_at > now.value()
        || matches!(
            session.status,
            SessionState::Expired | SessionState::Revoked | SessionState::Closed
        )
    {
        return Err(AuthorityError::IdentityConflict);
    }
    if !canonical_grant
        .allowed_operations
        .iter()
        .any(|allowed| allowed == operation_name)
        || !canonical_grant
            .allowed_resources
            .iter()
            .any(|allowed| allowed == resource_ref)
        || !is_sha256_hex(canonical_payload_sha256)
    {
        return Err(AuthorityError::InvalidField(
            "use_site.registration_binding",
        ));
    }
    if !canonical_grant
        .binding
        .authority_epoch
        .is_same_authority(&work_scope.state_fence.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    let now_ms =
        i64::try_from(now.value()).map_err(|_| AuthorityError::InvalidField("use_site.now_ms"))?;
    let heartbeat_age_ms = now
        .value()
        .checked_sub(session.heartbeat_at)
        .ok_or(AuthorityError::InvalidField("use_site.heartbeat_age_ms"))?;
    let transition_class = serde_json::to_value(TransitionClass::InstrumentRegistry)
        .map_err(|_| AuthorityError::InvalidField("use_site.transition_class"))?
        .as_str()
        .map(str::to_owned)
        .ok_or(AuthorityError::InvalidField("use_site.transition_class"))?;
    let data_class = serde_json::to_value(work_scope_snapshot.binding.privacy_class)
        .map_err(|_| AuthorityError::InvalidField("use_site.data_class"))?
        .as_str()
        .map(str::to_owned)
        .ok_or(AuthorityError::InvalidField("use_site.data_class"))?;

    Ok(AuthorityUseSite {
        holder_principal: holder_principal.to_owned(),
        session_id: session.session_id.as_str().to_owned(),
        scope_id: work_scope.scope_id.as_str().to_owned(),
        authority_epoch: canonical_grant.binding.authority_epoch.clone(),
        state_fence: work_scope.state_fence.clone(),
        binding: canonical_grant.binding.clone(),
        operation_name: operation_name.to_owned(),
        transition_class,
        resource_ref: resource_ref.to_owned(),
        data_class,
        effect: operation.effect,
        proof_ceiling: ProofCeiling::ScopedVerification,
        action_canonical_hash: canonical_payload_sha256.to_owned(),
        now_ms,
        heartbeat_age_ms,
        consumed_uses: 0,
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
