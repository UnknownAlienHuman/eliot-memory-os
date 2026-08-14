use std::fmt;

use eliot_receipts::{AuthorityBinding, OperationBinding, SessionBinding, WorkScopeBinding};

use crate::{AuthorityError, LogicalTime, PrincipalRef, ReceiptObligation, validate_text};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BreakGlassAuthorizationId(String);

impl BreakGlassAuthorizationId {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityError> {
        let value = value.into();
        validate_text(&value, "break_glass_authorization_id")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BreakGlassAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BreakGlassState {
    Available,
    Consumed,
    Revoked,
    Expired,
}

/// One-shot authorization model. It exposes no execution method.
#[derive(Debug)]
pub struct BreakGlassAuthorization {
    pub authorization_id: BreakGlassAuthorizationId,
    pub recovery_principal: PrincipalRef,
    pub exact_operation: OperationBinding,
    pub authority_binding: AuthorityBinding,
    pub work_scope: WorkScopeBinding,
    pub session: SessionBinding,
    pub expires_at: LogicalTime,
    pub audit_obligations: Vec<ReceiptObligation>,
    pub state: BreakGlassState,
}

impl BreakGlassAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: BreakGlassAuthorizationId,
        recovery_principal: PrincipalRef,
        exact_operation: OperationBinding,
        authority_binding: AuthorityBinding,
        work_scope: WorkScopeBinding,
        session: SessionBinding,
        expires_at: LogicalTime,
        audit_obligations: Vec<ReceiptObligation>,
    ) -> Result<Self, AuthorityError> {
        if audit_obligations.is_empty() {
            return Err(AuthorityError::InvalidField(
                "break_glass_audit_obligations",
            ));
        }
        for obligation in &audit_obligations {
            obligation.validate()?;
        }
        validate_binding(&authority_binding, &work_scope, &session)?;
        if exact_operation.state_fence != work_scope.state_fence
            || exact_operation.effect != authority_binding.allowed_effect
        {
            return Err(AuthorityError::FenceMismatch);
        }
        Ok(Self {
            authorization_id,
            recovery_principal,
            exact_operation,
            authority_binding,
            work_scope,
            session,
            expires_at,
            audit_obligations,
            state: BreakGlassState::Available,
        })
    }

    pub fn authorize_once(
        &mut self,
        principal: &PrincipalRef,
        operation: &OperationBinding,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<BreakGlassPermit, AuthorityError> {
        match self.state {
            BreakGlassState::Available => {}
            BreakGlassState::Consumed => return Err(AuthorityError::Consumed),
            BreakGlassState::Revoked => return Err(AuthorityError::Revoked),
            BreakGlassState::Expired => return Err(AuthorityError::Expired),
        }
        if now >= self.expires_at {
            self.state = BreakGlassState::Expired;
            return Err(AuthorityError::Expired);
        }
        validate_binding(&self.authority_binding, current_work_scope, current_session)?;
        if principal != &self.recovery_principal
            || operation != &self.exact_operation
            || self.work_scope.state_fence != current_work_scope.state_fence
            || self.session.session_id != current_session.session_id
        {
            return Err(AuthorityError::UnauthorizedOperation);
        }
        self.state = BreakGlassState::Consumed;
        Ok(BreakGlassPermit {
            authorization_id: self.authorization_id.clone(),
            exact_operation: self.exact_operation.clone(),
            audit_obligations: self.audit_obligations.clone(),
        })
    }

    pub fn revoke(&mut self) {
        if self.state == BreakGlassState::Available {
            self.state = BreakGlassState::Revoked;
        }
    }
}

/// Pure proof that one exact operation was authorized. No execution API exists.
#[derive(Debug, Eq, PartialEq)]
pub struct BreakGlassPermit {
    pub authorization_id: BreakGlassAuthorizationId,
    pub exact_operation: OperationBinding,
    pub audit_obligations: Vec<ReceiptObligation>,
}

fn validate_binding(
    authority: &AuthorityBinding,
    work_scope: &WorkScopeBinding,
    session: &SessionBinding,
) -> Result<(), AuthorityError> {
    if authority.state_fence != work_scope.state_fence
        || authority.state_fence != session.state_fence
    {
        return Err(AuthorityError::FenceMismatch);
    }
    if authority.authority_epoch != session.authority_epoch
        || authority.authority_epoch != authority.state_fence.authority_epoch
    {
        return Err(AuthorityError::EpochMismatch);
    }
    Ok(())
}
