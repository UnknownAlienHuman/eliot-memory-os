//! Strict, proof-bearing task finish evaluation.
//!
//! This crate owns the finish-service boundary and its rebuildable idempotency
//! projection.  The semantic proof calculation remains in
//! [`eliot_canonical`]; this layer binds that calculation to the current task
//! revision, State Fence, descendant closure and lifecycle disposition.  It
//! never accepts caller-supplied completion proof, executes verifiers, or
//! persists canonical state itself.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::{
    CanonicalError, FinishAttemptDraft, FinishDecision, FinishDecisionOutcome, FinishEvidence,
    ProofCeiling, RequestedFinishOutcome, derive_finish_decision,
};
use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, StateFence, canonical_json_bytes,
    contract_identity as foundation_contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this Governor finish contract.
pub const CONTRACT_NAME: &str = "eliot.governor.finish";
/// Current wire revision of this contract.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Failures at the strict finish boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FinishError {
    /// A shared foundation contract rejected a fence or identity.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// Canonical semantic derivation rejected the strict input.
    #[error("canonical finish: {0}")]
    Canonical(CanonicalError),
    /// A required field is blank or malformed.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable reason.
        reason: &'static str,
    },
    /// A required collection has no members.
    #[error("empty field {field}")]
    Empty {
        /// Stable field path.
        field: &'static str,
    },
    /// A collection contains duplicate identities.
    #[error("duplicate values in {field}")]
    Duplicate {
        /// Stable field path.
        field: &'static str,
    },
    /// The attempt was captured under a different current State Fence.
    #[error("finish State Fence is stale")]
    FenceMismatch,
    /// A finish attempt identity was reused with different content.
    #[error("finish attempt identity conflict")]
    IdentityConflict,
    /// A task already closed and cannot accept another finish attempt.
    #[error("closed task cannot accept a finish attempt")]
    ClosedTask,
    /// An external effect or descendant remains live, unreachable, or unknown.
    #[error("descendant or external effect requires reconciliation")]
    DescendantUnreconciled,
    /// A disposition that closes a task lacks an explicit authority binding.
    #[error("closing finish disposition requires an authority reference")]
    MissingClosureAuthority,
    /// A caller attempted to provide proof through the finish wrapper.
    #[error("caller-supplied completion proof is not accepted")]
    CallerProofRejected,
}

impl From<ContractError> for FinishError {
    fn from(error: ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<CanonicalError> for FinishError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), FinishError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(FinishError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    field: &'static str,
) -> Result<(), FinishError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().any(|value| !seen.insert(value)) {
        return Err(FinishError::Duplicate { field });
    }
    Ok(())
}

/// Operational task lifecycle, kept separate from one finish outcome.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskLifecycleState {
    Proposed,
    Open,
    Framed,
    Active,
    Verifying,
    Suspended,
    Blocked,
    Closing,
    Closed,
    Reopened,
}

impl TaskLifecycleState {
    /// Whether a new finish attempt is forbidden by lifecycle state.
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Explicit closure intent for outcomes whose task disposition is not implied
/// by evidence alone.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinishClosureIntent {
    /// Keep incomplete work available for continuation.
    Continue,
    /// Close a partial task with an explicit owner disposition.
    ClosePartial,
    /// Close after authorized cancellation and effect disposition.
    Cancel,
    /// Close after authorized supersession and effect disposition.
    Supersede,
}

/// Descendant/effect closure observation required before terminal finish.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum DescendantClosure {
    /// Every admitted descendant and effect has a terminal, reconciled state.
    Complete { receipt_ref: String },
    /// One or more descendants/effects remain live or unresolved.
    Incomplete { unresolved_refs: Vec<String> },
    /// The route cannot establish whether descendants/effects still exist.
    Unknown { reason_ref: String },
}

impl DescendantClosure {
    fn validate(&self) -> Result<(), FinishError> {
        match self {
            Self::Complete { receipt_ref } => text(receipt_ref, "descendant_closure.receipt_ref"),
            Self::Incomplete { unresolved_refs } => {
                if unresolved_refs.is_empty() {
                    return Err(FinishError::Empty {
                        field: "descendant_closure.unresolved_refs",
                    });
                }
                unique(unresolved_refs.iter(), "descendant_closure.unresolved_refs")?;
                for reference in unresolved_refs {
                    text(reference, "descendant_closure.unresolved_ref")?;
                }
                Ok(())
            }
            Self::Unknown { reason_ref } => text(reason_ref, "descendant_closure.reason_ref"),
        }
    }

    fn unresolved_refs(&self) -> Vec<String> {
        match self {
            Self::Complete { .. } => Vec::new(),
            Self::Incomplete { unresolved_refs } => unresolved_refs.clone(),
            Self::Unknown { reason_ref } => vec![format!("unknown-descendants:{reason_ref}")],
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// Rehydrated task state required by the finish service.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishContext {
    /// Task identity from canonical state.
    pub task_id: String,
    /// Current task revision from canonical state.
    pub current_task_revision: u64,
    /// Current State Fence; finish requires exact equality.
    pub current_state_fence: StateFence,
    /// Current operational lifecycle.
    pub lifecycle: TaskLifecycleState,
    /// Opaque binding for the authority that owns finish evaluation.
    pub finish_authority_ref: String,
    /// Explicit owner binding required for partial/cancel/supersede closure.
    pub closure_authority_ref: Option<String>,
    /// Current descendant/effect reconciliation result.
    pub descendant_closure: DescendantClosure,
}

impl FinishContext {
    /// Validates the exact state needed to derive one finish decision.
    pub fn validate(&self) -> Result<(), FinishError> {
        text(&self.task_id, "finish_context.task_id")?;
        if self.current_task_revision == 0 {
            return Err(FinishError::InvalidField {
                field: "finish_context.current_task_revision",
                reason: "must be non-zero",
            });
        }
        self.current_state_fence.validate()?;
        text(
            &self.finish_authority_ref,
            "finish_context.finish_authority_ref",
        )?;
        if let Some(reference) = &self.closure_authority_ref {
            text(reference, "finish_context.closure_authority_ref")?;
        }
        self.descendant_closure.validate()
    }
}

/// Strict public finish input.  It contains a candidate draft and rehydrated
/// evidence only; there is intentionally no completion-proof field.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishAttempt {
    /// Idempotency identity for this finish attempt.
    pub attempt_id: String,
    /// Fence captured by the caller before submitting the candidate.
    pub state_fence: StateFence,
    /// Caller candidate; the canonical crate derives the decision.
    pub draft: FinishAttemptDraft,
    /// Evidence rehydrated by the service from current canonical state.
    pub evidence: FinishEvidence,
    /// Explicit lifecycle disposition requested by the owner.
    pub closure_intent: FinishClosureIntent,
}

impl FinishAttempt {
    /// Validates strict fields before any state-dependent evaluation.
    pub fn validate(&self) -> Result<(), FinishError> {
        text(&self.attempt_id, "finish_attempt.attempt_id")?;
        self.state_fence.validate()?;
        self.draft.validate()?;
        self.evidence.validate()?;
        validate_closure_intent(self.draft.requested_outcome, self.closure_intent)
    }

    /// Computes the immutable attempt identity used for replay detection.
    pub fn digest(&self) -> Result<String, FinishError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| FinishError::InvalidField {
            field: "finish_attempt",
            reason: "cannot serialize finish attempt",
        })?;
        Ok(sha256_hex(&bytes))
    }
}

fn validate_closure_intent(
    outcome: RequestedFinishOutcome,
    intent: FinishClosureIntent,
) -> Result<(), FinishError> {
    let valid = match outcome {
        RequestedFinishOutcome::CompleteCandidate
        | RequestedFinishOutcome::Blocked
        | RequestedFinishOutcome::FailedVerification
        | RequestedFinishOutcome::DegradedNoProof
        | RequestedFinishOutcome::UnsafeToFinish => intent == FinishClosureIntent::Continue,
        RequestedFinishOutcome::Partial => {
            matches!(
                intent,
                FinishClosureIntent::Continue | FinishClosureIntent::ClosePartial
            )
        }
        RequestedFinishOutcome::Cancelled => intent == FinishClosureIntent::Cancel,
        RequestedFinishOutcome::Superseded => intent == FinishClosureIntent::Supersede,
    };
    if valid {
        Ok(())
    } else {
        Err(FinishError::InvalidField {
            field: "finish_attempt.closure_intent",
            reason: "does not match requested outcome",
        })
    }
}

/// Lifecycle effect derived from the eight closed finish outcomes.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinishLifecycleAction {
    CloseCompleted,
    ContinueActive,
    EnterSuspended,
    EnterBlocked,
    ClosePartial,
    CloseCancelled,
    CloseSuperseded,
}

/// Immutable receipt returned after deriving one finish decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishDecisionReceipt {
    /// Stable identity of this derived receipt.
    pub decision_id: String,
    /// Original idempotency identity.
    pub attempt_id: String,
    /// Task identity and revision evaluated.
    pub task_id: String,
    pub task_revision: u64,
    /// Exact fence used by the derivation.
    pub state_fence: StateFence,
    /// Authority binding that permitted this finish evaluation.
    pub finish_authority_ref: String,
    /// Optional owner binding used for a closing disposition.
    pub closure_authority_ref: Option<String>,
    /// Candidate requested by the caller, retained for transparency.
    pub requested_outcome: RequestedFinishOutcome,
    /// Canonical, evidence-derived decision.
    pub decision: FinishDecision,
    /// Lifecycle effect; task state remains owned by canonical transition.
    pub lifecycle_action: FinishLifecycleAction,
    /// Descendant/effect handles that prevented terminal closure, if any.
    pub unresolved_descendant_refs: Vec<String>,
    /// Digest of the exact submitted attempt.
    pub attempt_digest: String,
    /// Digest of this receipt's semantic fields.
    pub receipt_digest: String,
}

impl FinishDecisionReceipt {
    /// Validates an immutable receipt loaded into a rebuildable projection.
    pub fn validate(&self) -> Result<(), FinishError> {
        text(&self.decision_id, "finish_receipt.decision_id")?;
        text(&self.attempt_id, "finish_receipt.attempt_id")?;
        text(&self.task_id, "finish_receipt.task_id")?;
        if self.task_revision == 0 {
            return Err(FinishError::InvalidField {
                field: "finish_receipt.task_revision",
                reason: "must be non-zero",
            });
        }
        self.state_fence.validate()?;
        text(
            &self.finish_authority_ref,
            "finish_receipt.finish_authority_ref",
        )?;
        if let Some(reference) = &self.closure_authority_ref {
            text(reference, "finish_receipt.closure_authority_ref")?;
        }
        if self.decision.proof.task_id != self.task_id
            || self.decision.proof.task_revision != self.task_revision
        {
            return Err(FinishError::InvalidField {
                field: "finish_receipt.decision.proof",
                reason: "proof task binding does not match receipt",
            });
        }
        text(
            &self.decision.next_allowed_action,
            "finish_receipt.next_allowed_action",
        )?;
        unique(
            self.unresolved_descendant_refs.iter(),
            "finish_receipt.unresolved_descendant_refs",
        )?;
        for reference in &self.unresolved_descendant_refs {
            text(reference, "finish_receipt.unresolved_descendant_ref")?;
        }
        text(&self.attempt_digest, "finish_receipt.attempt_digest")?;
        text(&self.receipt_digest, "finish_receipt.receipt_digest")?;
        if self.decision_id != format!("finish:{}", self.attempt_id) {
            return Err(FinishError::InvalidField {
                field: "finish_receipt.decision_id",
                reason: "must be derived from attempt identity",
            });
        }
        let expected = receipt_digest(
            &self.decision_id,
            &self.attempt_id,
            &self.task_id,
            self.task_revision,
            &self.state_fence,
            &self.finish_authority_ref,
            self.closure_authority_ref.as_deref(),
            self.requested_outcome,
            &self.decision,
            self.lifecycle_action,
            &self.unresolved_descendant_refs,
            &self.attempt_digest,
        )?;
        if expected != self.receipt_digest {
            return Err(FinishError::InvalidField {
                field: "finish_receipt.receipt_digest",
                reason: "does not match receipt content",
            });
        }
        Ok(())
    }
}

/// Idempotent admission result from the local finish projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum FinishAdmission {
    Accepted { receipt: FinishDecisionReceipt },
    Replayed { receipt: FinishDecisionReceipt },
}

/// Rebuildable finish service projection.  Canonical persistence remains the
/// responsibility of Governor's transition owner.
#[derive(Clone, Debug, Default)]
pub struct FinishService {
    receipts: BTreeMap<String, FinishDecisionReceipt>,
}

impl FinishService {
    /// Rebuilds the local projection from immutable accepted receipts.
    pub fn from_receipts(
        receipts: impl IntoIterator<Item = FinishDecisionReceipt>,
    ) -> Result<Self, FinishError> {
        let mut service = Self::default();
        for receipt in receipts {
            receipt.validate()?;
            if service
                .receipts
                .insert(receipt.attempt_id.clone(), receipt)
                .is_some()
            {
                return Err(FinishError::IdentityConflict);
            }
        }
        Ok(service)
    }

    /// Evaluates one strict finish candidate against the exact current context.
    pub fn evaluate(
        &mut self,
        attempt: FinishAttempt,
        context: &FinishContext,
    ) -> Result<FinishAdmission, FinishError> {
        attempt.validate()?;
        context.validate()?;
        if context.lifecycle.is_closed() {
            return Err(FinishError::ClosedTask);
        }
        if attempt.state_fence != context.current_state_fence {
            return Err(FinishError::FenceMismatch);
        }
        if attempt.draft.task_id != context.task_id || attempt.evidence.task_id != context.task_id {
            return Err(FinishError::Canonical(CanonicalError::TaskBindingMismatch));
        }
        if attempt.draft.expected_task_revision != context.current_task_revision
            || attempt.evidence.current_task_revision != context.current_task_revision
        {
            return Err(FinishError::Canonical(CanonicalError::StaleTaskRevision));
        }
        let attempt_digest = attempt.digest()?;
        if let Some(existing) = self.receipts.get(&attempt.attempt_id) {
            if existing.attempt_digest != attempt_digest {
                return Err(FinishError::IdentityConflict);
            }
            return Ok(FinishAdmission::Replayed {
                receipt: existing.clone(),
            });
        }

        let mut evidence = attempt.evidence.clone();
        let unresolved_descendant_refs = context.descendant_closure.unresolved_refs();
        if !unresolved_descendant_refs.is_empty() {
            evidence
                .unresolved_effect_refs
                .extend(unresolved_descendant_refs.iter().cloned());
            evidence.unresolved_effect_refs.sort();
            evidence.unresolved_effect_refs.dedup();
        }
        let mut draft = attempt.draft.clone();
        if !context.descendant_closure.is_complete()
            && matches!(
                draft.requested_outcome,
                RequestedFinishOutcome::CompleteCandidate
                    | RequestedFinishOutcome::Cancelled
                    | RequestedFinishOutcome::Superseded
            )
        {
            draft.requested_outcome = RequestedFinishOutcome::Blocked;
        }
        let decision = derive_finish_decision(&draft, &evidence)?;
        let lifecycle_action = lifecycle_action(
            decision.outcome,
            attempt.closure_intent,
            context.lifecycle,
            context.closure_authority_ref.as_deref(),
        )?;
        let decision_id = format!("finish:{}", attempt.attempt_id);
        let receipt_digest = receipt_digest(
            &decision_id,
            &attempt.attempt_id,
            &context.task_id,
            context.current_task_revision,
            &attempt.state_fence,
            &context.finish_authority_ref,
            context.closure_authority_ref.as_deref(),
            attempt.draft.requested_outcome,
            &decision,
            lifecycle_action,
            &unresolved_descendant_refs,
            &attempt_digest,
        )?;
        let receipt = FinishDecisionReceipt {
            decision_id,
            attempt_id: attempt.attempt_id.clone(),
            task_id: context.task_id.clone(),
            task_revision: context.current_task_revision,
            state_fence: attempt.state_fence,
            finish_authority_ref: context.finish_authority_ref.clone(),
            closure_authority_ref: context.closure_authority_ref.clone(),
            requested_outcome: attempt.draft.requested_outcome,
            decision,
            lifecycle_action,
            unresolved_descendant_refs,
            attempt_digest,
            receipt_digest,
        };
        self.receipts.insert(attempt.attempt_id, receipt.clone());
        Ok(FinishAdmission::Accepted { receipt })
    }

    /// Returns a previously accepted receipt without re-evaluating it.
    pub fn receipt(&self, attempt_id: &str) -> Option<&FinishDecisionReceipt> {
        self.receipts.get(attempt_id)
    }

    /// Returns the deterministic projection of all accepted receipts.
    pub fn receipts(&self) -> Vec<FinishDecisionReceipt> {
        self.receipts.values().cloned().collect()
    }
}

#[allow(clippy::too_many_arguments)]
fn receipt_digest(
    decision_id: &str,
    attempt_id: &str,
    task_id: &str,
    task_revision: u64,
    state_fence: &StateFence,
    finish_authority_ref: &str,
    closure_authority_ref: Option<&str>,
    requested_outcome: RequestedFinishOutcome,
    decision: &FinishDecision,
    lifecycle_action: FinishLifecycleAction,
    unresolved_descendant_refs: &[String],
    attempt_digest: &str,
) -> Result<String, FinishError> {
    let receipt_shape = (
        decision_id,
        attempt_id,
        task_id,
        task_revision,
        state_fence,
        finish_authority_ref,
        closure_authority_ref,
        requested_outcome,
        decision,
        lifecycle_action,
        unresolved_descendant_refs,
        attempt_digest,
    );
    let receipt_bytes =
        canonical_json_bytes(&receipt_shape).map_err(|_| FinishError::InvalidField {
            field: "finish_decision_receipt",
            reason: "cannot serialize decision receipt",
        })?;
    Ok(sha256_hex(&receipt_bytes))
}

fn lifecycle_action(
    outcome: FinishDecisionOutcome,
    intent: FinishClosureIntent,
    lifecycle: TaskLifecycleState,
    closure_authority_ref: Option<&str>,
) -> Result<FinishLifecycleAction, FinishError> {
    let action = match outcome {
        FinishDecisionOutcome::VerifiedComplete => FinishLifecycleAction::CloseCompleted,
        FinishDecisionOutcome::Partial if intent == FinishClosureIntent::ClosePartial => {
            FinishLifecycleAction::ClosePartial
        }
        FinishDecisionOutcome::Partial | FinishDecisionOutcome::DegradedNoProof => {
            FinishLifecycleAction::EnterSuspended
        }
        FinishDecisionOutcome::Blocked | FinishDecisionOutcome::UnsafeToFinish => {
            FinishLifecycleAction::EnterBlocked
        }
        FinishDecisionOutcome::FailedVerification => {
            if lifecycle == TaskLifecycleState::Blocked {
                FinishLifecycleAction::EnterBlocked
            } else {
                FinishLifecycleAction::ContinueActive
            }
        }
        FinishDecisionOutcome::Cancelled => FinishLifecycleAction::CloseCancelled,
        FinishDecisionOutcome::Superseded => FinishLifecycleAction::CloseSuperseded,
    };
    if matches!(
        action,
        FinishLifecycleAction::CloseCompleted
            | FinishLifecycleAction::ClosePartial
            | FinishLifecycleAction::CloseCancelled
            | FinishLifecycleAction::CloseSuperseded
    ) && closure_authority_ref.is_none()
    {
        return Err(FinishError::MissingClosureAuthority);
    }
    Ok(action)
}

/// Returns the content-addressed identity of this finish contract.
pub fn contract_identity() -> Result<ContractIdentity, FinishError> {
    foundation_contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &serde_json::json!({
            "finish_attempt": schemars::schema_for!(FinishAttempt),
            "finish_context": schemars::schema_for!(FinishContext),
            "finish_decision_receipt": schemars::schema_for!(FinishDecisionReceipt),
            "finish_admission": schemars::schema_for!(FinishAdmission),
            "proof_ceiling": schemars::schema_for!(ProofCeiling),
        }),
    )
    .map_err(FinishError::Foundation)
}
