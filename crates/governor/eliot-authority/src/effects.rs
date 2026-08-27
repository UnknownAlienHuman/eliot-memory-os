use std::collections::{BTreeMap, BTreeSet};

use eliot_receipts::{
    OperationBinding, ReceiptDispositionKind, ReceiptEnvelope, SessionBinding, WorkScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

pub const EFFECT_AUTHORIZER_RECOVERY_SCHEMA: &str = "eliot.authority.effect-authorizer-recovery";
pub const EFFECT_AUTHORIZER_RECOVERY_VERSION: u16 = 1;

/// Complete durable idempotency ledger state, in deterministic wire form.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorizerRecoverySnapshot {
    pub schema: String,
    pub version: u16,
    pub records: Vec<AuthorizedEffectRecoveryRecord>,
}

/// One complete admitted effect retained by a recovery snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedEffectRecoveryRecord {
    pub idempotency_key: String,
    pub action_id: String,
    pub operation: OperationBinding,
    pub operation_name: String,
    pub resource_ref: String,
    pub canonical_payload_sha256: String,
    pub lease_id: String,
    pub executor_boundary: String,
    pub receipt_obligations: Vec<ReceiptObligation>,
}

impl EffectAuthorizerRecoverySnapshot {
    /// Validates both the deterministic wire shape and the ledger semantics
    /// that would be enforced when this snapshot is restored.
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_wire()?;
        EffectAuthorizer::restore_records(self.records.clone()).map(|_| ())
    }

    fn validate_wire(&self) -> Result<(), AuthorityError> {
        if self.schema != EFFECT_AUTHORIZER_RECOVERY_SCHEMA {
            return Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.schema",
            ));
        }
        if self.version != EFFECT_AUTHORIZER_RECOVERY_VERSION {
            return Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.version",
            ));
        }
        let mut previous = None;
        for record in &self.records {
            validate_text(&record.idempotency_key, "idempotency_key")?;
            if let Some(previous) = previous
                && previous >= record.idempotency_key.as_str()
            {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.records",
                ));
            }
            previous = Some(record.idempotency_key.as_str());
        }
        Ok(())
    }
}

impl EffectAuthorizer {
    pub fn snapshot(&self) -> Result<EffectAuthorizerRecoverySnapshot, AuthorityError> {
        let records = self
            .authorized_by_idempotency
            .iter()
            .map(
                |(idempotency_key, authorized)| AuthorizedEffectRecoveryRecord {
                    idempotency_key: idempotency_key.clone(),
                    action_id: authorized.proposal.action_id.clone(),
                    operation: authorized.proposal.operation.clone(),
                    operation_name: authorized.proposal.operation_name.clone(),
                    resource_ref: authorized.proposal.resource_ref.clone(),
                    canonical_payload_sha256: authorized.proposal.canonical_payload_sha256.clone(),
                    lease_id: authorized.lease_id.as_str().to_owned(),
                    executor_boundary: authorized.executor_boundary.clone(),
                    receipt_obligations: authorized.receipt_obligations.clone(),
                },
            )
            .collect();
        let snapshot = EffectAuthorizerRecoverySnapshot {
            schema: EFFECT_AUTHORIZER_RECOVERY_SCHEMA.to_owned(),
            version: EFFECT_AUTHORIZER_RECOVERY_VERSION,
            records,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn from_snapshot(
        snapshot: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, AuthorityError> {
        snapshot.validate_wire()?;
        let EffectAuthorizerRecoverySnapshot {
            records,
            schema: _,
            version: _,
        } = snapshot;
        Self::restore_records(records)
    }

    fn restore_records(
        records: Vec<AuthorizedEffectRecoveryRecord>,
    ) -> Result<Self, AuthorityError> {
        let mut authorized_by_idempotency = BTreeMap::new();
        for record in records {
            if record.idempotency_key != record.operation.idempotency_key {
                return Err(AuthorityError::InvalidField(
                    "effect_authorizer_recovery.idempotency_key",
                ));
            }
            let proposal = ProposedEffect::new(
                record.action_id,
                record.operation,
                record.operation_name,
                record.resource_ref,
                record.canonical_payload_sha256,
            )?;
            let lease_id = LeaseId::new(record.lease_id)?;
            for obligation in &record.receipt_obligations {
                obligation.validate()?;
            }
            let authorized = AuthorizedEffect {
                proposal,
                lease_id,
                executor_boundary: {
                    validate_text(&record.executor_boundary, "executor_boundary")?;
                    record.executor_boundary
                },
                receipt_obligations: record.receipt_obligations,
            };
            if authorized_by_idempotency
                .insert(record.idempotency_key, authorized)
                .is_some()
            {
                return Err(AuthorityError::IdentityConflict);
            }
        }
        Ok(Self {
            authorized_by_idempotency,
        })
    }

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

#[cfg(test)]
mod recovery_tests {
    use std::error::Error;

    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, OperationId, RequestId, ResourceGeneration, StateFence,
        canonical_json_bytes,
    };
    use eliot_receipts::EffectClass;

    type TestResult = Result<(), Box<dyn Error>>;

    fn operation(key: &str) -> Result<OperationBinding, Box<dyn Error>> {
        Ok(OperationBinding {
            operation_id: OperationId::new("operation:test")?,
            request_id: RequestId::new("request:test")?,
            idempotency_key: key.to_owned(),
            operation_kind: "test.effect".to_owned(),
            effect: EffectClass::ReversibleMutation,
            state_fence: StateFence::new(AuthorityEpoch::new(1)?, ResourceGeneration::new(1)?),
        })
    }

    fn authorizer() -> Result<EffectAuthorizer, Box<dyn Error>> {
        let proposal = ProposedEffect::new(
            "action:test",
            operation("idem:test")?,
            "operation:test",
            "resource:test",
            "a".repeat(64),
        )?;
        let authorized = AuthorizedEffect {
            proposal,
            lease_id: LeaseId::new("lease:test")?,
            executor_boundary: "executor:test".to_owned(),
            receipt_obligations: vec![ReceiptObligation::CanonicalEffectReceipt],
        };
        let mut authorizer_state = EffectAuthorizer::default();
        authorizer_state
            .authorized_by_idempotency
            .insert("idem:test".to_owned(), authorized);
        Ok(authorizer_state)
    }

    #[test]
    fn recovery_roundtrip_preserves_complete_effect_ledger() -> TestResult {
        let authorizer = authorizer()?;
        let snapshot = authorizer.snapshot()?;
        let restored = EffectAuthorizer::from_snapshot(snapshot.clone())?;
        assert_eq!(restored.snapshot()?, snapshot);
        Ok(())
    }

    #[test]
    fn recovery_rejects_duplicate_key_substitution_and_malformed_digest() -> TestResult {
        let base = authorizer()?.snapshot()?;

        let mut duplicate = base.clone();
        duplicate.records.push(duplicate.records[0].clone());
        assert!(matches!(
            EffectAuthorizer::from_snapshot(duplicate),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.records"
            ))
        ));

        let mut substituted_key = base.clone();
        substituted_key.records[0].idempotency_key = "idem:substituted".to_owned();
        assert!(matches!(
            EffectAuthorizer::from_snapshot(substituted_key),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.idempotency_key"
            ))
        ));

        let mut malformed_digest = base;
        malformed_digest.records[0].canonical_payload_sha256 = "A".repeat(64);
        assert!(matches!(
            EffectAuthorizer::from_snapshot(malformed_digest),
            Err(AuthorityError::InvalidField("canonical_payload_sha256"))
        ));
        Ok(())
    }

    #[test]
    fn recovery_validate_is_semantic_and_empty_state_is_explicit() -> TestResult {
        let empty = EffectAuthorizer::default().snapshot()?;
        empty.validate()?;
        assert_eq!(
            EffectAuthorizer::from_snapshot(empty.clone())?.snapshot()?,
            empty
        );

        let mut invalid = authorizer()?.snapshot()?;
        invalid.records[0].operation_name.clear();
        assert!(matches!(
            invalid.validate(),
            Err(AuthorityError::InvalidField("operation_name"))
        ));

        let mut invalid_executor = authorizer()?.snapshot()?;
        invalid_executor.records[0].executor_boundary.clear();
        assert!(matches!(
            invalid_executor.validate(),
            Err(AuthorityError::InvalidField("executor_boundary"))
        ));
        Ok(())
    }

    #[test]
    fn recovery_json_roundtrip_and_unknown_fields_are_rejected() -> TestResult {
        let snapshot = authorizer()?.snapshot()?;
        let encoded = serde_json::to_string(&snapshot)?;
        let decoded: EffectAuthorizerRecoverySnapshot = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, snapshot);

        let mut unknown_top_level = serde_json::to_value(&snapshot)?;
        unknown_top_level
            .as_object_mut()
            .ok_or("snapshot was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<EffectAuthorizerRecoverySnapshot>(unknown_top_level).is_err()
        );

        let mut unknown_record = serde_json::to_value(&snapshot)?;
        let records = unknown_record
            .get_mut("records")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or("records was not a JSON array")?;
        records
            .first_mut()
            .ok_or("expected an effect record")?
            .as_object_mut()
            .ok_or("effect record was not a JSON object")?
            .insert("unexpected".to_owned(), serde_json::Value::Null);
        assert!(
            serde_json::from_value::<EffectAuthorizerRecoverySnapshot>(unknown_record).is_err()
        );
        Ok(())
    }

    #[test]
    fn recovery_order_and_canonical_bytes_are_insertion_independent() -> TestResult {
        fn authorized(key: &str) -> Result<AuthorizedEffectRecoveryRecord, Box<dyn Error>> {
            let operation = operation(key)?;
            Ok(AuthorizedEffectRecoveryRecord {
                idempotency_key: key.to_owned(),
                action_id: format!("action:{key}"),
                operation,
                operation_name: "operation:test".to_owned(),
                resource_ref: "resource:test".to_owned(),
                canonical_payload_sha256: "a".repeat(64),
                lease_id: format!("lease:{key}"),
                executor_boundary: "executor:test".to_owned(),
                receipt_obligations: vec![ReceiptObligation::CanonicalEffectReceipt],
            })
        }

        fn state(order: &[&str]) -> Result<EffectAuthorizer, Box<dyn Error>> {
            let mut state = EffectAuthorizer::default();
            for key in order {
                let record = authorized(key)?;
                let proposal = ProposedEffect::new(
                    record.action_id,
                    record.operation,
                    record.operation_name,
                    record.resource_ref,
                    record.canonical_payload_sha256,
                )?;
                let authorized_effect = AuthorizedEffect {
                    proposal,
                    lease_id: LeaseId::new(record.lease_id)?,
                    executor_boundary: record.executor_boundary,
                    receipt_obligations: record.receipt_obligations,
                };
                state
                    .authorized_by_idempotency
                    .insert((*key).to_owned(), authorized_effect);
            }
            Ok(state)
        }

        let first_state = state(&["idem:a", "idem:b"])?;
        let second_state = state(&["idem:b", "idem:a"])?;
        let first_canonical = first_state.snapshot()?;
        let second_canonical = second_state.snapshot()?;
        assert_eq!(first_canonical, second_canonical);
        assert_eq!(
            canonical_json_bytes(&first_canonical)?,
            canonical_json_bytes(&second_canonical)?
        );

        let mut reordered = first_canonical;
        reordered.records.reverse();
        assert!(matches!(
            reordered.validate(),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.records"
            ))
        ));

        let mut substituted_operation_key = second_state.snapshot()?;
        substituted_operation_key.records[0]
            .operation
            .idempotency_key = "idem:other".to_owned();
        assert!(matches!(
            substituted_operation_key.validate(),
            Err(AuthorityError::InvalidField(
                "effect_authorizer_recovery.idempotency_key"
            ))
        ));
        Ok(())
    }
}
