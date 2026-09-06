//! Owner-neutral position request: what is asked, under which bindings.
//!
//! A [`PositionRequest`] carries the question, proposition, task, attempt, revision, scope with validity,
//! fence, and admitted record handles. It resolves, acquires, ranks, and writes nothing. Donor disposition
//! (`crates/smart/eliot-epistemic/src/lib.rs`, donor scope `PositionRequest`): `question`, `scope`,
//! `state_fence`, and `records` are preserved (records as handle sets, never embedded envelopes); task,
//! attempt, revision, proposition, and validity close the request; the donor `resolve` algorithm is not carried.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, OperationId, RequestId, StateFence, TaskId, TaskRevision};
use eliot_receipts::WorkScope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, MAX_STATEMENT_TEXT, check_frozen, shape_digest,
    validate_bounded_text,
};
use crate::identity::PropositionId;
use crate::support::ValidityBounds;

/// Marker proving a document is a position request and never a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RequestKind {
    /// The single admitted spelling of a position request.
    #[serde(rename = "POSITION_REQUEST")]
    #[schemars(rename = "POSITION_REQUEST")]
    PositionRequest,
}

/// A bounded, fully bound request for an epistemic position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositionRequest {
    /// Marker binding this document to the request decoding.
    pub request_kind: RequestKind,
    /// Bounded question the position must bear on.
    pub question: String,
    /// Caller request identity: retries share it, distinct asks never do.
    pub request_id: RequestId,
    /// Operation identity the position is proposed under.
    pub operation_id: OperationId,
    /// Idempotency key binding retries of this exact ask.
    pub idempotency_key: String,
    /// Canonical work scope the inquiry runs in, reused from `eliot-receipts`
    /// and never redefined here: there is exactly one `WorkScope` owner.
    pub work_scope: WorkScope,
    /// Proposition the question bears on; applicability is explicit.
    pub proposition: PropositionId,
    /// Task binding of the inquiry.
    pub task_id: TaskId,
    /// Attempt binding of the inquiry; retries never share an attempt.
    pub attempt_id: String,
    /// Task-plan revision the request was built under.
    pub revision: TaskRevision,
    /// Scope the request covers.
    pub scope: String,
    /// Scope, time, version, and precision validity of the ask.
    pub validity: ValidityBounds,
    /// Fence the request was built under.
    pub fence: StateFence,
    /// Admitted record handles the position may draw on; order is meaningless.
    pub records: BTreeSet<ArtifactId>,
    /// Canonical digest of the request shape, excluding this field.
    pub digest: String,
}

impl PositionRequest {
    /// Constructs a request and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        question: impl Into<String>,
        request_id: RequestId,
        operation_id: OperationId,
        idempotency_key: impl Into<String>,
        work_scope: WorkScope,
        proposition: PropositionId,
        task_id: TaskId,
        attempt_id: impl Into<String>,
        revision: TaskRevision,
        scope: impl Into<String>,
        validity: ValidityBounds,
        fence: StateFence,
        records: BTreeSet<ArtifactId>,
    ) -> Result<Self, ContractError> {
        let mut request = Self {
            request_kind: RequestKind::PositionRequest,
            question: question.into(),
            request_id,
            operation_id,
            idempotency_key: idempotency_key.into(),
            work_scope,
            proposition,
            task_id,
            attempt_id: attempt_id.into(),
            revision,
            scope: scope.into(),
            validity,
            fence,
            records,
            digest: String::new(),
        };
        request.validate_shape()?;
        request.digest = request.compute_digest()?;
        Ok(request)
    }

    /// Recomputes the canonical digest of the request shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.request_kind,
            &self.question,
            &self.request_id,
            &self.operation_id,
            &self.idempotency_key,
            &self.work_scope,
            &self.proposition,
            &self.task_id,
            &self.attempt_id,
            &self.revision,
            &self.scope,
            &self.validity,
            &self.fence,
            &self.records,
        ))
    }

    /// Returns whether this request applies to the given proposition.
    pub fn applies_to(&self, proposition: &PropositionId) -> bool {
        &self.proposition == proposition
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.request_kind != RequestKind::PositionRequest {
            return Err(ContractError::ImpossibleCombination {
                field: "request.request_kind",
            });
        }
        validate_bounded_text(&self.question, "request.question", MAX_STATEMENT_TEXT)?;
        validate_bounded_text(
            &self.idempotency_key,
            "request.idempotency_key",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.attempt_id, "request.attempt_id", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "request.scope", MAX_SHORT_TEXT)?;
        self.work_scope
            .state_fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "request.work_scope",
            })?;
        if self.work_scope.resource_generation != self.work_scope.state_fence.resource_generation {
            return Err(ContractError::FenceMismatch {
                field: "request.work_scope",
            });
        }
        if self.work_scope.scope_id.as_str() != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "request.work_scope",
            });
        }
        if !self.work_scope.state_fence.is_compatible_with(&self.fence)
            || !self.fence.is_compatible_with(&self.work_scope.state_fence)
        {
            return Err(ContractError::FenceMismatch {
                field: "request.work_scope",
            });
        }
        self.validity.validate()?;
        if self.validity.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "request.validity",
            });
        }
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "request.fence",
            })?;
        if self.records.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "request.records",
            });
        }
        if self.records.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "request.records",
            });
        }
        Ok(())
    }

    /// Validates the request shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "request.digest")
    }

    /// Validates this request against the live task, attempt, scope, and fence.
    pub fn validate_for(
        &self,
        task_id: &TaskId,
        attempt_id: &str,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if &self.task_id != task_id {
            return Err(ContractError::TaskMismatch {
                field: "request.task_id",
            });
        }
        if self.attempt_id.as_str() != attempt_id {
            return Err(ContractError::TaskMismatch {
                field: "request.attempt_id",
            });
        }
        if self.scope != scope {
            return Err(ContractError::ScopeMismatch {
                field: "request.scope",
            });
        }
        if !self.fence.is_compatible_with(fence) {
            return Err(ContractError::FenceMismatch {
                field: "request.fence",
            });
        }
        Ok(())
    }
}
