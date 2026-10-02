use std::fmt;

use eliot_receipts::{AuthorityBinding, EffectClass, SessionBinding, WorkScopeBinding};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::grants::{AuthoritySet, LogicalTime, PrincipalRef, ReceiptObligation, effect_rank};
use crate::{AuthorityError, ProposedEffect, validate_text};

macro_rules! lease_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

lease_id!(LeaseId, "lease_id");
lease_id!(TokenId, "token_id");

fn validate_bindings(
    authority: &AuthorityBinding,
    work_scope: &WorkScopeBinding,
    session: &SessionBinding,
) -> Result<(), AuthorityError> {
    authority
        .state_fence
        .validate()
        .map_err(|_| AuthorityError::FenceMismatch)?;
    if authority.state_fence != work_scope.state_fence
        || authority.state_fence != session.state_fence
    {
        return Err(AuthorityError::FenceMismatch);
    }
    if !authority
        .authority_epoch
        .is_same_authority(&session.authority_epoch)
        || !authority
            .authority_epoch
            .is_same_authority(&authority.state_fence.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    Ok(())
}

/// Compact, bounded projection of activated authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityToken {
    pub token_id: TokenId,
    pub holder: PrincipalRef,
    pub authority_set: AuthoritySet,
    pub authority_binding: AuthorityBinding,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub expires_at: LogicalTime,
    pub remaining_uses: u32,
    pub receipt_obligations: Vec<ReceiptObligation>,
    revoked: bool,
}

impl CapabilityToken {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: TokenId,
        holder: PrincipalRef,
        authority_set: AuthoritySet,
        authority_binding: AuthorityBinding,
        work_scope: WorkScopeBinding,
        session: SessionBinding,
        expires_at: LogicalTime,
        max_uses: u32,
        receipt_obligations: Vec<ReceiptObligation>,
    ) -> Result<Self, AuthorityError> {
        validate_bindings(&authority_binding, &work_scope, &session)?;
        if max_uses == 0 || receipt_obligations.is_empty() {
            return Err(AuthorityError::InvalidField("token_budget_or_obligations"));
        }
        for obligation in &receipt_obligations {
            obligation.validate()?;
        }
        if effect_rank(authority_set.max_effect()) > effect_rank(authority_binding.allowed_effect) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        Ok(Self {
            token_id,
            holder,
            authority_set,
            authority_binding,
            work_scope,
            session,
            expires_at,
            remaining_uses: max_uses,
            receipt_obligations,
            revoked: false,
        })
    }

    pub fn consume(
        &mut self,
        operation: &str,
        resource: &str,
        effect: EffectClass,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        self.validate_current(current_work_scope, current_session, now)?;
        if !self.authority_set.operations().contains(operation) {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        if !self.authority_set.resources().contains(resource) {
            return Err(AuthorityError::UnauthorizedResource);
        }
        if !self.authority_set.allows(operation, resource, effect) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        self.remaining_uses -= 1;
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn validate_current(
        &self,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        if self.revoked {
            return Err(AuthorityError::Revoked);
        }
        if now >= self.expires_at {
            return Err(AuthorityError::Expired);
        }
        if self.remaining_uses == 0 {
            return Err(AuthorityError::UseBudgetExhausted);
        }
        validate_bindings(&self.authority_binding, current_work_scope, current_session)?;
        if self.work_scope.state_fence != current_work_scope.state_fence
            || self.session.session_id != current_session.session_id
        {
            return Err(AuthorityError::FenceMismatch);
        }
        Ok(())
    }
}

/// Short-lived authority for one exact effect identity and bounded use count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetRecoveryRecord {
    /// Exact named operation set retained by the lease.
    pub operations: Vec<String>,
    /// Exact resource set retained by the lease.
    pub resources: Vec<String>,
    /// Effect ceiling retained by the lease.
    pub max_effect: EffectClass,
}

/// Complete durable state of one Governor-issued exact-operation lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionLeaseRecoveryRecord {
    pub lease_id: String,
    pub holder: String,
    pub exact_idempotency_key: String,
    pub authority_set: AuthoritySetRecoveryRecord,
    pub authority_binding: AuthorityBinding,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub expires_at: u64,
    pub max_uses: u32,
    pub remaining_uses: u32,
    pub receipt_obligations: Vec<ReceiptObligation>,
    pub revoked: bool,
}

/// Short-lived authority for one exact effect identity and bounded use count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionLease {
    pub lease_id: LeaseId,
    pub holder: PrincipalRef,
    pub exact_idempotency_key: String,
    pub authority_set: AuthoritySet,
    pub authority_binding: AuthorityBinding,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub expires_at: LogicalTime,
    pub max_uses: u32,
    pub remaining_uses: u32,
    pub receipt_obligations: Vec<ReceiptObligation>,
    revoked: bool,
}

impl ActionLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lease_id: LeaseId,
        holder: PrincipalRef,
        exact_idempotency_key: impl Into<String>,
        authority_set: AuthoritySet,
        authority_binding: AuthorityBinding,
        work_scope: WorkScopeBinding,
        session: SessionBinding,
        expires_at: LogicalTime,
        max_uses: u32,
        receipt_obligations: Vec<ReceiptObligation>,
    ) -> Result<Self, AuthorityError> {
        let exact_idempotency_key = exact_idempotency_key.into();
        validate_text(&exact_idempotency_key, "exact_idempotency_key")?;
        validate_bindings(&authority_binding, &work_scope, &session)?;
        if max_uses == 0 || receipt_obligations.is_empty() {
            return Err(AuthorityError::InvalidField("lease_budget_or_obligations"));
        }
        for obligation in &receipt_obligations {
            obligation.validate()?;
        }
        if effect_rank(authority_set.max_effect()) > effect_rank(authority_binding.allowed_effect) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        Ok(Self {
            lease_id,
            holder,
            exact_idempotency_key,
            authority_set,
            authority_binding,
            work_scope,
            session,
            expires_at,
            max_uses,
            remaining_uses: max_uses,
            receipt_obligations,
            revoked: false,
        })
    }

    /// Returns a closed durable projection of this lease, including its
    /// original ceiling and remaining uses. This projection retains issuance
    /// and use accounting across registration retries and owner restarts.
    #[must_use]
    pub fn recovery_record(&self) -> ActionLeaseRecoveryRecord {
        ActionLeaseRecoveryRecord {
            lease_id: self.lease_id.as_str().to_owned(),
            holder: self.holder.as_str().to_owned(),
            exact_idempotency_key: self.exact_idempotency_key.clone(),
            authority_set: AuthoritySetRecoveryRecord {
                operations: self.authority_set.operations().iter().cloned().collect(),
                resources: self.authority_set.resources().iter().cloned().collect(),
                max_effect: self.authority_set.max_effect(),
            },
            authority_binding: self.authority_binding.clone(),
            work_scope: self.work_scope.clone(),
            session: self.session.clone(),
            expires_at: self.expires_at.value(),
            max_uses: self.max_uses,
            remaining_uses: self.remaining_uses,
            receipt_obligations: self.receipt_obligations.clone(),
            revoked: self.revoked,
        }
    }

    /// Restores one complete retained lease record. A recovered lease is
    /// historical/current state as recorded; it is never renewed by restore.
    pub fn from_recovery_record(record: ActionLeaseRecoveryRecord) -> Result<Self, AuthorityError> {
        if record.max_uses == 0 || record.remaining_uses > record.max_uses {
            return Err(AuthorityError::InvalidField("action_lease_recovery.budget"));
        }
        if record.receipt_obligations.is_empty() {
            return Err(AuthorityError::InvalidField(
                "action_lease_recovery.receipt_obligations",
            ));
        }
        for obligation in &record.receipt_obligations {
            obligation.validate()?;
        }
        validate_bindings(
            &record.authority_binding,
            &record.work_scope,
            &record.session,
        )?;
        let authority_set = AuthoritySet::new(
            record.authority_set.operations,
            record.authority_set.resources,
            record.authority_set.max_effect,
        )?;
        if effect_rank(authority_set.max_effect())
            > effect_rank(record.authority_binding.allowed_effect)
        {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        Ok(Self {
            lease_id: LeaseId::new(record.lease_id)?,
            holder: PrincipalRef::new(record.holder)?,
            exact_idempotency_key: {
                validate_text(&record.exact_idempotency_key, "exact_idempotency_key")?;
                record.exact_idempotency_key
            },
            authority_set,
            authority_binding: record.authority_binding,
            work_scope: record.work_scope,
            session: record.session,
            expires_at: LogicalTime::new(record.expires_at),
            max_uses: record.max_uses,
            remaining_uses: record.remaining_uses,
            receipt_obligations: record.receipt_obligations,
            revoked: record.revoked,
        })
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub(crate) fn authorize(
        &mut self,
        proposed: &ProposedEffect,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        if self.revoked {
            return Err(AuthorityError::Revoked);
        }
        if now >= self.expires_at {
            return Err(AuthorityError::Expired);
        }
        if self.remaining_uses == 0 {
            return Err(AuthorityError::UseBudgetExhausted);
        }
        validate_bindings(&self.authority_binding, current_work_scope, current_session)?;
        if self.work_scope.state_fence != current_work_scope.state_fence
            || self.session.session_id != current_session.session_id
            || proposed.operation.state_fence != current_work_scope.state_fence
        {
            return Err(AuthorityError::FenceMismatch);
        }
        if proposed.operation.idempotency_key != self.exact_idempotency_key {
            return Err(AuthorityError::IdentityConflict);
        }
        if !self
            .authority_set
            .operations()
            .contains(&proposed.operation_name)
        {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        if !self
            .authority_set
            .resources()
            .contains(&proposed.resource_ref)
        {
            return Err(AuthorityError::UnauthorizedResource);
        }
        if !self.authority_set.allows(
            &proposed.operation_name,
            &proposed.resource_ref,
            proposed.operation.effect,
        ) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        self.remaining_uses -= 1;
        Ok(())
    }

    /// Non-consuming current-standing check for one already authorized effect
    /// at the effect boundary.
    ///
    /// This answers only whether the lease is still current for this exact
    /// effect: not revoked, not expired, bound to the current work scope,
    /// session and authority epoch, naming the same idempotency identity, and
    /// still allowing this operation, resource and effect class. The use
    /// budget is deliberately not re-charged: admission already consumed the
    /// use, and this check is a read of current standing, not a second
    /// admission.
    pub(crate) fn still_current(
        &self,
        proposed: &ProposedEffect,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<(), AuthorityError> {
        if self.revoked {
            return Err(AuthorityError::Revoked);
        }
        if now >= self.expires_at {
            return Err(AuthorityError::Expired);
        }
        validate_bindings(&self.authority_binding, current_work_scope, current_session)?;
        if self.work_scope.state_fence != current_work_scope.state_fence
            || self.session.session_id != current_session.session_id
            || proposed.operation.state_fence != current_work_scope.state_fence
        {
            return Err(AuthorityError::FenceMismatch);
        }
        if proposed.operation.idempotency_key != self.exact_idempotency_key {
            return Err(AuthorityError::IdentityConflict);
        }
        if !self.authority_set.allows(
            &proposed.operation_name,
            &proposed.resource_ref,
            proposed.operation.effect,
        ) {
            return Err(AuthorityError::EffectCeilingExceeded);
        }
        Ok(())
    }
}
