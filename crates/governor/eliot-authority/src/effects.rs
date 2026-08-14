use std::collections::{BTreeMap, BTreeSet};

use eliot_receipts::{
    OperationBinding, ReceiptDispositionKind, ReceiptEnvelope, SessionBinding, WorkScopeBinding,
};

use crate::{
    ActionLease, AuthorityError, LeaseId, LogicalTime, ReceiptObligation, validate_digest,
    validate_text,
};

/// Exact action frame from which effect proposals are derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionContract {
    pub action_id: String,
    pub intent: String,
    pub work_scope: WorkScopeBinding,
    pub authority_ref: String,
    pub read_set: BTreeSet<String>,
    pub effect_set: BTreeSet<String>,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub rollback_or_compensation: String,
    pub stop_conditions: BTreeSet<String>,
}

impl ActionContract {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: impl Into<String>,
        intent: impl Into<String>,
        work_scope: WorkScopeBinding,
        authority_ref: impl Into<String>,
        read_set: impl IntoIterator<Item = String>,
        effect_set: impl IntoIterator<Item = String>,
        expected_observable: impl Into<String>,
        verifier_ref: impl Into<String>,
        rollback_or_compensation: impl Into<String>,
        stop_conditions: impl IntoIterator<Item = String>,
    ) -> Result<Self, AuthorityError> {
        let contract = Self {
            action_id: action_id.into(),
            intent: intent.into(),
            work_scope,
            authority_ref: authority_ref.into(),
            read_set: read_set.into_iter().collect(),
            effect_set: effect_set.into_iter().collect(),
            expected_observable: expected_observable.into(),
            verifier_ref: verifier_ref.into(),
            rollback_or_compensation: rollback_or_compensation.into(),
            stop_conditions: stop_conditions.into_iter().collect(),
        };
        for (value, field) in [
            (&contract.action_id, "action_id"),
            (&contract.intent, "intent"),
            (&contract.authority_ref, "authority_ref"),
            (&contract.expected_observable, "expected_observable"),
            (&contract.verifier_ref, "verifier_ref"),
            (
                &contract.rollback_or_compensation,
                "rollback_or_compensation",
            ),
        ] {
            validate_text(value, field)?;
        }
        if contract.effect_set.is_empty() || contract.stop_conditions.is_empty() {
            return Err(AuthorityError::InvalidField(
                "effect_set_or_stop_conditions",
            ));
        }
        for value in contract
            .read_set
            .iter()
            .chain(&contract.effect_set)
            .chain(&contract.stop_conditions)
        {
            validate_text(value, "action_contract_set")?;
        }
        contract
            .work_scope
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        Ok(contract)
    }
}

/// Effect request only; this value carries no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedEffect {
    pub action_id: String,
    pub operation: OperationBinding,
    pub operation_name: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
}

impl ProposedEffect {
    pub fn new(
        action_id: impl Into<String>,
        operation: OperationBinding,
        operation_name: impl Into<String>,
        resource_ref: impl Into<String>,
        canonical_payload_sha256: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let action_id = action_id.into();
        let operation_name = operation_name.into();
        let resource_ref = resource_ref.into();
        let canonical_payload_sha256 = canonical_payload_sha256.into();
        validate_text(&action_id, "action_id")?;
        validate_text(&operation_name, "operation_name")?;
        validate_text(&resource_ref, "resource_ref")?;
        validate_text(&operation.idempotency_key, "idempotency_key")?;
        validate_text(&operation.operation_kind, "operation_kind")?;
        validate_digest(&canonical_payload_sha256, "canonical_payload_sha256")?;
        operation
            .state_fence
            .validate()
            .map_err(|_| AuthorityError::FenceMismatch)?;
        Ok(Self {
            action_id,
            operation,
            operation_name,
            resource_ref,
            canonical_payload_sha256,
        })
    }
}

/// Exact proposal admitted by one `ActionLease`. It still has no execution API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedEffect {
    pub proposal: ProposedEffect,
    pub lease_id: LeaseId,
    pub executor_boundary: String,
    pub receipt_obligations: Vec<ReceiptObligation>,
}

/// Pure idempotency and lease admission registry.
#[derive(Clone, Debug, Default)]
pub struct EffectAuthorizer {
    authorized_by_idempotency: BTreeMap<String, AuthorizedEffect>,
}

impl EffectAuthorizer {
    pub fn authorize(
        &mut self,
        lease: &mut ActionLease,
        proposed: ProposedEffect,
        executor_boundary: impl Into<String>,
        current_work_scope: &WorkScopeBinding,
        current_session: &SessionBinding,
        now: LogicalTime,
    ) -> Result<AuthorizedEffect, AuthorityError> {
        let executor_boundary = executor_boundary.into();
        validate_text(&executor_boundary, "executor_boundary")?;
        if let Some(existing) = self
            .authorized_by_idempotency
            .get(&proposed.operation.idempotency_key)
        {
            if same_logical_effect(&existing.proposal, &proposed) {
                return Ok(existing.clone());
            }
            return Err(AuthorityError::IdentityConflict);
        }
        lease.authorize(&proposed, current_work_scope, current_session, now)?;
        let authorized = AuthorizedEffect {
            proposal: proposed,
            lease_id: lease.lease_id.clone(),
            executor_boundary,
            receipt_obligations: lease.receipt_obligations.clone(),
        };
        self.authorized_by_idempotency.insert(
            authorized.proposal.operation.idempotency_key.clone(),
            authorized.clone(),
        );
        Ok(authorized)
    }
}

fn same_logical_effect(left: &ProposedEffect, right: &ProposedEffect) -> bool {
    left.action_id == right.action_id
        && left.canonical_payload_sha256 == right.canonical_payload_sha256
        && left.operation_name == right.operation_name
        && left.resource_ref == right.resource_ref
        && left.operation.operation_kind == right.operation.operation_kind
        && left.operation.effect == right.operation.effect
        && left.operation.state_fence == right.operation.state_fence
}

/// Effect outcome. Unknown outcome is explicitly non-terminal until reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectOutcome {
    Committed,
    Rejected,
    Compensated,
    UnknownOutcome { reason: String },
}

/// Outcome projection over a provider-owned canonical receipt. Common receipt
/// identity, fence and authority fields are not duplicated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReceipt {
    pub authorized_effect: AuthorizedEffect,
    pub outcome: EffectOutcome,
    pub canonical_receipt: Option<ReceiptEnvelope>,
}

impl EffectReceipt {
    pub fn unknown(
        authorized_effect: AuthorizedEffect,
        reason: impl Into<String>,
    ) -> Result<Self, AuthorityError> {
        let reason = reason.into();
        validate_text(&reason, "unknown_outcome_reason")?;
        Ok(Self {
            authorized_effect,
            outcome: EffectOutcome::UnknownOutcome { reason },
            canonical_receipt: None,
        })
    }

    pub fn terminal(
        authorized_effect: AuthorizedEffect,
        outcome: EffectOutcome,
        canonical_receipt: ReceiptEnvelope,
    ) -> Result<Self, AuthorityError> {
        if matches!(outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(AuthorityError::InvalidLifecycleTransition);
        }
        validate_terminal_receipt(&authorized_effect, &outcome, &canonical_receipt)?;
        Ok(Self {
            authorized_effect,
            outcome,
            canonical_receipt: Some(canonical_receipt),
        })
    }

    pub fn reconcile(
        self,
        outcome: EffectOutcome,
        canonical_receipt: ReceiptEnvelope,
    ) -> Result<Self, AuthorityError> {
        if !matches!(self.outcome, EffectOutcome::UnknownOutcome { .. }) {
            return Err(AuthorityError::InvalidLifecycleTransition);
        }
        Self::terminal(self.authorized_effect, outcome, canonical_receipt)
    }
}

fn validate_terminal_receipt(
    authorized: &AuthorizedEffect,
    outcome: &EffectOutcome,
    receipt: &ReceiptEnvelope,
) -> Result<(), AuthorityError> {
    receipt
        .validate()
        .map_err(|_| AuthorityError::ReceiptMismatch)?;
    if receipt.core.operation.operation_id != authorized.proposal.operation.operation_id
        || receipt.core.operation.idempotency_key != authorized.proposal.operation.idempotency_key
        || receipt.core.operation.state_fence != authorized.proposal.operation.state_fence
    {
        return Err(AuthorityError::ReceiptMismatch);
    }
    let disposition = receipt.core.disposition.kind();
    let valid = match outcome {
        EffectOutcome::Committed | EffectOutcome::Compensated => {
            disposition == ReceiptDispositionKind::Success
        }
        EffectOutcome::Rejected => matches!(
            disposition,
            ReceiptDispositionKind::Failure | ReceiptDispositionKind::Cancelled
        ),
        EffectOutcome::UnknownOutcome { .. } => false,
    };
    if !valid {
        return Err(AuthorityError::ReceiptMismatch);
    }
    Ok(())
}
