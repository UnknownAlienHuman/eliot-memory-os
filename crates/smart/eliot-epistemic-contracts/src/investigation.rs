//! Investigation requirement: a typed inquiry outcome, never prose.
//!
//! An [`InvestigationRequirement`] states exactly what further inquiry a
//! position needs: which proposition, under which scope, task, and fence, what
//! kind of inquiry, which target it bears on, and why. Inquiry kinds are a
//! closed vocabulary; free-text inquiry lists never cross this boundary.
//!
//! Donor disposition (`crates/smart/eliot-epistemic/src/lib.rs`, donor scope
//! assumption/investigation fields): the donor `required_inquiry` and
//! `unknowns` free-text vectors are disposed — prose cannot be validated, so
//! it cannot be a contract. Each required inquiry becomes one typed
//! [`InvestigationRequirement`]; each unknown becomes either a typed
//! requirement or an explicit entry in a candidate `unknowns` set, never both
//! silently. The donor inquiry-derivation policy (which statuses and freshness
//! levels demand which inquiry) is explicitly not carried: deriving inquiries
//! is resolver policy, and this crate carries no resolver.

use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_SHORT_TEXT, shape_digest, validate_bounded_text, validate_digest,
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

impl InvestigationKind {
    /// Returns the exact frozen wire name of this inquiry kind.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Revalidate => "REVALIDATE",
            Self::ObtainEvidence => "OBTAIN_EVIDENCE",
            Self::DiscriminativeProbe => "DISCRIMINATIVE_PROBE",
            Self::EstablishFreshness => "ESTABLISH_FRESHNESS",
            Self::ReassessRejected => "REASSESS_REJECTED",
        }
    }
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

impl InvestigationRequirement {
    /// Constructs an investigation requirement and freezes its digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requirement_id: impl Into<String>,
        proposition: PropositionId,
        scope: impl Into<String>,
        task_id: TaskId,
        fence: StateFence,
        inquiry: InvestigationKind,
        target: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut requirement = Self {
            requirement_kind: RequirementKind::InvestigationRequirement,
            requirement_id: requirement_id.into(),
            proposition,
            scope: scope.into(),
            task_id,
            fence,
            inquiry,
            target: target.into(),
            reason: reason.into(),
            digest: String::new(),
        };
        requirement.validate_shape()?;
        requirement.digest = requirement.compute_digest()?;
        Ok(requirement)
    }

    /// Recomputes the canonical digest of the requirement shape.
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

    /// Validates the requirement shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "investigation.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "investigation.digest",
            });
        }
        Ok(())
    }
}
