//! Exact admitted epistemic payload and position compare-and-swap contract.
//!
//! Position revisions are independent of task and Store scope revisions.
//! This module checks identity and representation; Governor owns semantic
//! admission, including evidence existence and the closed candidate checks.

use std::collections::{BTreeMap, BTreeSet};

use eliot_epistemic_contracts::{
    AdmittedReceipt, AdmittedReceiptParams, CurrentEpistemicPosition, Currentness,
    EpistemicPositionCandidate, EpistemicTransition, PositionId, PositionRevision,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, PreparedTransition, RequestMeta, StoreError,
    WriteReceipt, WriteReceiptStatus, canonical_json_bytes, sha256_hex,
    validate_store_receipt_envelope,
};

pub const EPISTEMIC_REVISION_SCHEMA: &str = "eliot.storage.epistemic-revision.v1";

/// One position mutation. `None` requires absence, never a blind upsert.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicRevisionPayload {
    pub schema: String,
    pub position: PositionId,
    pub expected_position_revision: Option<PositionRevision>,
    pub candidate: EpistemicPositionCandidate,
    pub transition: EpistemicTransition,
}

impl EpistemicRevisionPayload {
    /// Stable scope-local projection key, independent of operation identity.
    pub fn position_key(&self) -> Result<String, StoreError> {
        position_key(&self.candidate.scope, self.position.as_str())
    }
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.schema != EPISTEMIC_REVISION_SCHEMA {
            return Err(invalid("epistemic.schema", "unsupported schema"));
        }
        self.candidate.validate().map_err(contract_error)?;
        self.transition.validate().map_err(contract_error)?;
        if self
            .expected_position_revision
            .is_some_and(|revision| revision.value() == 0)
        {
            return Err(invalid(
                "epistemic.position_revision",
                "zero is not a position revision",
            ));
        }
        let candidate = &self.candidate;
        let transition = &self.transition;
        if transition.candidate_digest != candidate.digest
            || transition.operation != candidate.operation_id
            || transition.request_id != candidate.request_id
            || transition.idempotency_key != candidate.idempotency_key
            || transition.work_scope != candidate.work_scope
            || transition.position != candidate.proposition
            || transition.task_id != candidate.task_id
            || transition.attempt_id != candidate.attempt_id
            || transition.expected_revision != candidate.revision
            || transition.expected_fence != candidate.fence
            || transition.after_assertability != candidate.proposed_assertability
        {
            return Err(invalid(
                "epistemic.binding",
                "candidate and transition disagree",
            ));
        }
        self.next_revision()?;
        Ok(())
    }

    pub fn next_revision(&self) -> Result<PositionRevision, StoreError> {
        let value = self
            .expected_position_revision
            .map_or(0, PositionRevision::value);
        let next = value
            .checked_add(1)
            .ok_or_else(|| invalid("epistemic.position_revision", "position revision overflow"))?;
        PositionRevision::new(next).map_err(contract_error)
    }

    /// Mechanically binds the already admitted payload to its execution envelope.
    pub fn validate_for(&self, prepared: &PreparedTransition) -> Result<(), StoreError> {
        self.validate()?;
        if prepared.named_operations.len() != 1
            || prepared.identity.operation_id != self.candidate.operation_id
            || prepared.identity.idempotency_key != self.candidate.idempotency_key
            || prepared.scope_id.as_str() != self.candidate.scope
            || prepared.task_id.as_deref() != Some(self.candidate.task_id.as_str())
            || prepared.state_fence != self.candidate.fence
        {
            return Err(invalid(
                "epistemic.binding",
                "payload and prepared transition disagree",
            ));
        }
        Ok(())
    }

    pub fn command(&self) -> Result<NamedMutationRequest, StoreError> {
        self.validate()?;
        Ok(NamedMutationRequest {
            operation: NamedMutationOperation::ApplyEpistemicRevision,
            parameters: BTreeMap::from([(
                "revision".to_owned(),
                serde_json::to_value(self)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?,
            )]),
        })
    }

    pub fn from_parameters(parameters: &BTreeMap<String, Value>) -> Result<Self, StoreError> {
        if parameters.len() != 1 {
            return Err(invalid(
                "epistemic.parameters",
                "exact revision parameter required",
            ));
        }
        let value = parameters
            .get("revision")
            .ok_or_else(|| invalid("epistemic.parameters", "missing revision payload"))?;
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }
}

/// Exact prepared bytes retained beside the external receipt. A candidate's
/// receipt is derived only on readback; its own digest never contains it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicCommit {
    pub payload: EpistemicRevisionPayload,
    pub prepared: PreparedTransition,
    pub context: RequestMeta,
}

impl EpistemicCommit {
    pub fn from_prepared(
        context: &RequestMeta,
        prepared: &PreparedTransition,
    ) -> Result<Option<Self>, StoreError> {
        let Some(command) = prepared
            .named_operations
            .iter()
            .find(|command| command.operation == NamedMutationOperation::ApplyEpistemicRevision)
        else {
            return Ok(None);
        };
        let payload = EpistemicRevisionPayload::from_parameters(&command.parameters)?;
        payload.validate_for(prepared)?;
        if context.request_id != payload.candidate.request_id
            || context.task_id.as_ref() != Some(&payload.candidate.task_id)
            || context.product_id != payload.candidate.work_scope.product_id
            || context.state_fence != payload.candidate.fence
        {
            return Err(invalid(
                "epistemic.binding",
                "payload and request metadata disagree",
            ));
        }
        Ok(Some(Self {
            payload,
            prepared: prepared.clone(),
            context: context.clone(),
        }))
    }

    /// Validates the external receipt and constructs the admitted wire view.
    pub fn readback(
        &self,
        receipt: &WriteReceipt,
    ) -> Result<EpistemicPositionReadback, StoreError> {
        let reconstructed = Self::from_prepared(&self.context, &self.prepared)?
            .ok_or(StoreError::InvalidReceipt)?;
        if reconstructed != *self || receipt.status != WriteReceiptStatus::Committed {
            return Err(StoreError::InvalidReceipt);
        }
        validate_store_receipt_envelope(&self.context, &self.prepared, receipt)?;
        let envelope = receipt.require_reconciliation_envelope()?;
        let candidate = &self.payload.candidate;
        let admission = AdmittedReceipt::new(AdmittedReceiptParams {
            receipt_id: envelope.identity.receipt_id.clone(),
            payload_digest: candidate.digest.clone(),
            owner: self.context.source_id.clone(),
            revision: self.payload.next_revision()?.value().to_string(),
            scope: candidate.scope.clone(),
            fence: candidate.fence.clone(),
            evidence_digest: digest(&candidate.support)?,
            coverage_digest: candidate.coverage_digest.clone(),
            conflict_digest: digest(&candidate.conflict_digests)?,
            proof_digest: candidate.proof_digest.clone(),
            position: self.payload.position.clone(),
            position_revision: self.payload.next_revision()?,
        })
        .map_err(contract_error)?;
        let positions = candidate
            .claims
            .iter()
            .map(|claim| {
                CurrentEpistemicPosition::new(
                    admission.clone(),
                    Currentness::Current,
                    BTreeSet::new(),
                    claim.claim.clone(),
                )
                .map_err(contract_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(EpistemicPositionReadback {
            schema: EPISTEMIC_REVISION_SCHEMA.to_owned(),
            positions,
            candidate: candidate.clone(),
            transition: self.payload.transition.clone(),
            receipt: receipt.clone(),
        })
    }
}

/// The admitted CEP for every claim together with its exact supporting
/// candidate/transition and the external receipt that proves persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EpistemicPositionReadback {
    pub schema: String,
    pub positions: Vec<CurrentEpistemicPosition>,
    pub candidate: EpistemicPositionCandidate,
    pub transition: EpistemicTransition,
    pub receipt: WriteReceipt,
}

pub fn position_key(scope: &str, position: &str) -> Result<String, StoreError> {
    PositionId::new(position).map_err(contract_error)?;
    digest(&(EPISTEMIC_REVISION_SCHEMA, scope, position))
}

fn digest(value: &impl Serialize) -> Result<String, StoreError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| StoreError::Serialization(error.to_string()))
}

fn invalid(field: &'static str, reason: &'static str) -> StoreError {
    StoreError::InvalidField { field, reason }
}

fn contract_error(error: eliot_epistemic_contracts::ContractError) -> StoreError {
    StoreError::Serialization(error.to_string())
}
