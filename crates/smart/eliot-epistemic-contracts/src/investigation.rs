//! Investigation requirement: a typed inquiry outcome, never prose.
//!
//! An [`InvestigationRequirement`] states what further inquiry a position needs: proposition, scope, task,
//! fence, inquiry kind, target, and reason. Donor disposition (`crates/smart/eliot-epistemic/src/lib.rs`):
//! free-text vectors are disposed; each becomes a typed requirement or an explicit `unknowns` entry.
use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
};
use crate::identity::PropositionId;

/// The closed vocabulary of inquiry kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InvestigationKind {
    /// Revalidate a stale or superseded record.
    Revalidate,
    /// Obtain evidence for an unknown subject.
    ObtainEvidence,
    /// Run the cheapest discriminative probe separating rivals.
    DiscriminativeProbe,
    /// Establish freshness for a record of unknown freshness.
    EstablishFreshness,
    /// Reassess a rejected record.
    ReassessRejected,
}

/// Marker proving a document is an investigation requirement, never prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RequirementKind {
    /// The single admitted spelling of an investigation requirement.
    #[serde(rename = "INVESTIGATION_REQUIREMENT")]
    #[schemars(rename = "INVESTIGATION_REQUIREMENT")]
    InvestigationRequirement,
}

/// One typed further-inquiry requirement of a position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InvestigationRequirement {
    /// Marker binding this document to the requirement decoding.
    pub requirement_kind: RequirementKind,
    /// Stable requirement identity.
    pub requirement_id: String,
    /// Proposition the inquiry bears on.
    pub proposition: PropositionId,
    /// Scope the inquiry must run under.
    pub scope: String,
    /// Task binding of the inquiry.
    pub task_id: TaskId,
    /// Fence the inquiry must run under.
    pub fence: StateFence,
    /// Which kind of inquiry is required.
    pub inquiry: InvestigationKind,
    /// Bounded target of the inquiry: a handle or subject, never prose.
    pub target: String,
    /// Bounded reason the inquiry is required.
    pub reason: String,
    /// Canonical digest of the requirement shape, excluding this field.
    pub digest: String,
}
/// Named constructor arguments for [`InvestigationRequirement::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct InvestigationRequirementParams {
    pub requirement_id: String,
    pub proposition: PropositionId,
    pub scope: String,
    pub task_id: TaskId,
    pub fence: StateFence,
    pub inquiry: InvestigationKind,
    pub target: String,
    pub reason: String,
}
impl InvestigationRequirement {
    pub fn new(params: InvestigationRequirementParams) -> Result<Self, ContractError> {
        let mut requirement = Self {
            requirement_kind: RequirementKind::InvestigationRequirement,
            requirement_id: params.requirement_id,
            proposition: params.proposition,
            scope: params.scope,
            task_id: params.task_id,
            fence: params.fence,
            inquiry: params.inquiry,
            target: params.target,
            reason: params.reason,
            digest: String::new(),
        };
        requirement.validate_shape()?;
        requirement.digest = requirement.compute_digest()?;
        Ok(requirement)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.requirement_kind,
            &self.requirement_id,
            &self.proposition,
            &self.scope,
            &self.task_id,
            &self.fence,
            &self.inquiry,
            &self.target,
            &self.reason,
        ))
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.requirement_kind != RequirementKind::InvestigationRequirement {
            return Err(ContractError::ImpossibleCombination {
                field: "investigation.requirement_kind",
            });
        }
        validate_bounded_text(
            &self.requirement_id,
            "investigation.requirement_id",
            MAX_SHORT_TEXT,
        )?;
        validate_bounded_text(&self.scope, "investigation.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "investigation.fence",
            })?;
        validate_bounded_text(&self.target, "investigation.target", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.reason, "investigation.reason", MAX_SHORT_TEXT)?;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(
            &self.digest,
            &self.compute_digest()?,
            "investigation.digest",
        )
    }
}
