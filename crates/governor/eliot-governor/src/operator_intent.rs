//! Candidate-only contract for a public operator request and inspectable plan.
//!
//! The public surface supplies principal/session claims and an authentication
//! evidence handle. This module validates shape only: it does not authenticate, admit authority,
//! resolve policy, execute effects, create a durable episode, or persist a
//! plan. STITCH is the intended production caller; no caller is wired here.
//! Authentication receipt claims, role requests, and capability requests
//! remain unverified until their owning surface checks them.
//!
//! Episode durability is owned by the shared experience contracts. This
//! module owns no mutable or durable state, performs no persistence, and
//! executes no effects.

use std::collections::BTreeSet;

use eliot_authority::PrincipalRef;
use eliot_budget::{BudgetEnvelope, ObservedAmount};
use eliot_contracts::{ArtifactId, ContractVersion, ReceiptId, RequestId, SessionId, TaskId};
use eliot_protocol::RouteFingerprint;
use eliot_receipts::{EffectClass, SessionBinding, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable name of the candidate-only operator-intent contract.
pub const OPERATOR_INTENT_CONTRACT_NAME: &str = "eliot.governor.operator-intent";
/// Initial wire version for candidate and plan fields in this contract.
pub const OPERATOR_INTENT_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Stable request/message identity paired with its intended episode identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentIdentity {
    /// Common request identity used for the public message.
    pub message_id: RequestId,
    /// Common artifact identity reserved for the corresponding episode.
    pub episode_id: ArtifactId,
}

/// User Broker or local IPC authentication claims carried by the candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentAuthenticationBinding {
    /// Exact common receipt handle for the authentication evidence.
    pub authentication_receipt_ref: ReceiptId,
    /// Principal claim the evidence resolver must match against the receipt.
    pub principal_ref: String,
    /// Session claim the evidence resolver must match against the receipt.
    pub session_id: SessionId,
    /// Requested role handles; references do not grant those roles.
    pub requested_role_refs: Vec<ArtifactId>,
    /// Requested capability handles; references do not grant those capabilities.
    pub requested_capability_refs: Vec<ArtifactId>,
}

/// Stable reference to the immediately preceding plan revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentPlanRevisionRef {
    /// Common artifact identity for the predecessor revision.
    pub revision_id: ArtifactId,
    /// Producer-supplied nonzero revision number.
    pub revision: u64,
}

/// Producer-supplied plan revision, separate from the wire contract version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentPlanRevision {
    /// Common artifact identity for this revision.
    pub revision_id: ArtifactId,
    /// Producer-supplied nonzero revision number.
    pub revision: u64,
    /// Immediate predecessor, when this plan revises an earlier plan.
    ///
    /// The linkage is structural only; it does not prove either revision is
    /// persisted or that the predecessor exists.
    pub predecessor: Option<OperatorIntentPlanRevisionRef>,
}

impl OperatorIntentPlanRevision {
    fn validate(&self) -> Result<(), OperatorIntentValidationError> {
        match (&self.predecessor, self.revision) {
            (None, 1) => Ok(()),
            (Some(predecessor), revision)
                if predecessor.revision != 0
                    && predecessor.revision.checked_add(1) == Some(revision)
                    && predecessor.revision_id != self.revision_id =>
            {
                Ok(())
            }
            _ => Err(OperatorIntentValidationError::InvalidPlanRevision),
        }
    }
}

/// Scope and task resolution, or the explicit selection requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentScope {
    /// The existing scope is resolved; task may remain absent for orientation.
    Resolved {
        work_scope_id: WorkScopeId,
        task_id: Option<TaskId>,
    },
    /// The plan cannot continue until the caller obtains this selection.
    Unresolved { selection_requirement: String },
}

/// Route selection recorded for planning, with no route authority implied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentRoute {
    /// Exact route fingerprint supplied by the route owner.
    Selected { fingerprint: RouteFingerprint },
    /// Route choice is still unresolved.
    Unresolved { reason: String },
}

/// Cumulative budget facts supplied by their existing owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentBudget {
    /// Existing budget envelope and cumulative owner observations.
    Bound {
        envelope: Box<BudgetEnvelope>,
        /// Cumulative cost observation, including estimated/unavailable states.
        cumulative_cost_micros: ObservedAmount,
        /// Cumulative quota observation, including estimated/unavailable states.
        cumulative_quota_units: ObservedAmount,
        /// Owner-issued receipt references presented alongside the amounts;
        /// this contract does not verify their association or truth.
        cumulative_usage_receipts: Vec<ReceiptId>,
    },
    /// Budget admission or cumulative usage is not yet available.
    Unresolved { reason: String },
}

/// Risk evidence state without inventing a risk tier or score.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum OperatorIntentRisk {
    /// No risk assessment is attached yet.
    Unassessed,
    /// Handles to the assessment evidence; they do not prove policy admission.
    Assessed { assessment_refs: Vec<ArtifactId> },
}

/// Approval policy and receipt handles associated with the plan.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentApprovals {
    /// References to the applicable approval requirements or policies.
    pub requirement_refs: Vec<ArtifactId>,
    /// Receipts presented as approval evidence; this contract does not verify them.
    pub receipt_refs: Vec<ReceiptId>,
}

/// One proposed effect class and its human-readable description.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentEffect {
    /// Existing shared effect classification.
    pub class: EffectClass,
    /// The requested or proposed effect, not an executed result.
    pub description: String,
}

/// Inspectable plan linked to one candidate's stable request and episode IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentPlan {
    /// Version of this plan wire shape.
    pub contract_version: ContractVersion,
    /// Producer-supplied plan revision, distinct from the schema version.
    pub revision: OperatorIntentPlanRevision,
    /// Identity shared with the candidate.
    pub identity: OperatorIntentIdentity,
    /// Resolved scope/task or explicit selection requirement.
    pub scope: OperatorIntentScope,
    /// Existing source/evidence handles referenced by the plan.
    pub source_handles: Vec<ArtifactId>,
    /// Requested semantic change or read-only question.
    pub requested_delta: String,
    /// Selected or explicitly unresolved route.
    pub route: OperatorIntentRoute,
    /// Capability-introduction references; handles alone grant no authority.
    pub capability_refs: Vec<ArtifactId>,
    /// Exact context/evidence artifacts presented to the planning owner.
    pub context_refs: Vec<ArtifactId>,
    /// Budget envelope and cumulative observations with their receipt refs,
    /// or an explicit unresolved reason.
    pub budget: OperatorIntentBudget,
    /// Risk assessment status/evidence, without a fabricated rating.
    pub risk: OperatorIntentRisk,
    /// Applicable approval requirements and any supplied receipts.
    pub approvals: OperatorIntentApprovals,
    /// Proposed effect classes and descriptions; no effect is executed here.
    pub effects: Vec<OperatorIntentEffect>,
    /// Known rollback limits. An empty list is missing information, not a
    /// guarantee that every proposed effect is reversible.
    pub rollback_limitations: Vec<String>,
}

impl OperatorIntentPlan {
    /// Validates the plan's serialized structure, not authority or truth.
    pub fn validate(&self) -> Result<(), OperatorIntentValidationError> {
        if self.contract_version != OPERATOR_INTENT_CONTRACT_VERSION {
            return Err(OperatorIntentValidationError::UnsupportedVersion);
        }
        self.revision.validate()?;
        match &self.scope {
            OperatorIntentScope::Resolved { .. } => {}
            OperatorIntentScope::Unresolved {
                selection_requirement,
            } => required_text(selection_requirement, "scope.selection_requirement")?,
        }
        unique(&self.source_handles, "source_handles")?;
        required_text(&self.requested_delta, "requested_delta")?;
        match &self.route {
            OperatorIntentRoute::Selected { fingerprint } => {
                fingerprint.validate().map_err(|_| {
                    OperatorIntentValidationError::InvalidField {
                        field: "route.fingerprint",
                    }
                })?;
            }
            OperatorIntentRoute::Unresolved { reason } => required_text(reason, "route.reason")?,
        }
        unique(&self.capability_refs, "capability_refs")?;
        unique(&self.context_refs, "context_refs")?;
        match &self.budget {
            OperatorIntentBudget::Bound {
                envelope,
                cumulative_cost_micros,
                cumulative_quota_units,
                cumulative_usage_receipts,
            } => {
                envelope
                    .validate()
                    .map_err(|_| OperatorIntentValidationError::InvalidField {
                        field: "budget.envelope",
                    })?;
                unique(
                    cumulative_usage_receipts,
                    "budget.cumulative_usage_receipts",
                )?;
                if cumulative_usage_receipts.is_empty()
                    && (requires_usage_receipt(cumulative_cost_micros)
                        || requires_usage_receipt(cumulative_quota_units))
                {
                    return Err(OperatorIntentValidationError::InvalidField {
                        field: "budget.cumulative_usage_receipts",
                    });
                }
            }
            OperatorIntentBudget::Unresolved { reason } => {
                required_text(reason, "budget.reason")?;
            }
        }
        if let OperatorIntentRisk::Assessed { assessment_refs } = &self.risk {
            if assessment_refs.is_empty() {
                return Err(OperatorIntentValidationError::InvalidField {
                    field: "risk.assessment_refs",
                });
            }
            unique(assessment_refs, "risk.assessment_refs")?;
        }
        unique(
            &self.approvals.requirement_refs,
            "approvals.requirement_refs",
        )?;
        unique(&self.approvals.receipt_refs, "approvals.receipt_refs")?;
        for effect in &self.effects {
            required_text(&effect.description, "effects.description")?;
        }
        for limitation in &self.rollback_limitations {
            required_text(limitation, "rollback_limitations")?;
        }
        Ok(())
    }
}

/// Candidate envelope from a public operator surface; authentication remains
/// externally verified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorIntentCandidate {
    /// Version of this candidate wire shape.
    pub contract_version: ContractVersion,
    /// Stable public message and intended episode identity.
    pub identity: OperatorIntentIdentity,
    /// Authentication evidence handle and claims to be checked by its owner.
    pub authentication: OperatorIntentAuthenticationBinding,
    /// Session, authority epoch, and fence claims supplied by the public surface.
    pub session: SessionBinding,
    /// Original public request, preserved separately from its interpretation.
    pub original_public_request: String,
    /// The inspectable, candidate-only plan associated with this request.
    pub plan: OperatorIntentPlan,
}

impl OperatorIntentCandidate {
    /// Validates shape and cross-links while making no authority claim.
    pub fn validate(&self) -> Result<(), OperatorIntentValidationError> {
        if self.contract_version != OPERATOR_INTENT_CONTRACT_VERSION
            || self.plan.contract_version != OPERATOR_INTENT_CONTRACT_VERSION
        {
            return Err(OperatorIntentValidationError::UnsupportedVersion);
        }
        if self.identity != self.plan.identity {
            return Err(OperatorIntentValidationError::IdentityMismatch);
        }
        PrincipalRef::new(self.authentication.principal_ref.clone()).map_err(|_| {
            OperatorIntentValidationError::InvalidField {
                field: "authentication.principal_ref",
            }
        })?;
        if self.authentication.session_id != self.session.session_id {
            return Err(OperatorIntentValidationError::InvalidField {
                field: "authentication.session_id",
            });
        }
        unique(
            &self.authentication.requested_role_refs,
            "authentication.requested_role_refs",
        )?;
        unique(
            &self.authentication.requested_capability_refs,
            "authentication.requested_capability_refs",
        )?;
        self.session.state_fence.validate().map_err(|_| {
            OperatorIntentValidationError::InvalidField {
                field: "session.state_fence",
            }
        })?;
        if !self
            .session
            .state_fence
            .authority_epoch
            .is_same_authority(&self.session.authority_epoch)
        {
            return Err(OperatorIntentValidationError::InvalidField {
                field: "session.state_fence.authority_epoch",
            });
        }
        required_text(&self.original_public_request, "original_public_request")?;
        self.plan.validate()
    }
}

/// Structural validation errors for the operator-intent wire contract.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OperatorIntentValidationError {
    /// A field is blank, duplicated, or malformed.
    #[error("operator intent field is invalid: {field}")]
    InvalidField { field: &'static str },
    /// Candidate/plan wire version is not supported by this contract.
    #[error("operator intent contract version is unsupported")]
    UnsupportedVersion,
    /// Candidate and plan bind different stable request/episode identities.
    #[error("operator intent candidate and plan identities differ")]
    IdentityMismatch,
    /// Initial revision is not one or a later revision is not sequentially linked.
    #[error("operator intent plan revision linkage is invalid")]
    InvalidPlanRevision,
}

fn required_text(value: &str, field: &'static str) -> Result<(), OperatorIntentValidationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OperatorIntentValidationError::InvalidField { field });
    }
    Ok(())
}

fn requires_usage_receipt(amount: &ObservedAmount) -> bool {
    match amount {
        ObservedAmount::Known(value) => *value > 0,
        ObservedAmount::Estimated(_) => true,
        ObservedAmount::Unknown | ObservedAmount::NotExposed | ObservedAmount::NotApplicable => {
            false
        }
    }
}

fn unique<T: Ord>(values: &[T], field: &'static str) -> Result<(), OperatorIntentValidationError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value)) {
        return Err(OperatorIntentValidationError::InvalidField { field });
    }
    Ok(())
}
