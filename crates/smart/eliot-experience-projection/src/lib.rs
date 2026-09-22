//! Immutable experience read-aid view over owner projection vocabulary
//! (#223, review repair, unit #4).
//!
//! [`ExperienceView`] carries opaque record refs for Smart-side candidate
//! handling without bodies, framed by the owner coverage binding
//! ([`ProjectionCoverage`]) and closed-class [`ProjectionOmission`]s. The
//! view echoes coverage posture; it never establishes it: a `Complete`
//! disposition is structurally rejected, because a bare ref list cannot
//! recheck the owner enumeration behind the coverage digest. Completeness
//! lives in the owner projection envelopes
//! (`JournalProjection`/`BankProjection`/`FeedbackProjection`) with their
//! reconciled counts, empty omissions, and empty blind intervals.
//!
//! Scope and fence are bound to owner metadata: every ref echoes its
//! owner-reported scope and fence, checked here for scope equality and
//! fence compatibility against the envelope. Omission reasons use only the
//! closed [`ProjectionOmissionClass`]; free-form strings cannot cross this
//! boundary. This package performs no admission, enumeration, retrieval,
//! ranking, or promotion, and it is not edge, product, or W9-consumer
//! proof.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use eliot_observation_contracts::{
    ExperienceRecordRef, ExperienceSourceFamily, ObservationError, ObservationScope,
    ProjectionCoverage, ProjectionOmission, MAX_PROJECTION_MEMBERS, MAX_PROJECTION_OMISSIONS,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";

/// Immutable read-aid view: opaque refs plus the owner coverage binding.
///
/// The view accounts exactly its carried refs against the echoed owner
/// coverage and names every loss with a closed omission class. It claims
/// no completeness: use owner projections where completeness matters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceView {
    /// Source family this view reads.
    pub family: ExperienceSourceFamily,
    /// Read scope governing this view.
    pub scope: ObservationScope,
    /// Fence this view was read under, carried for edge gating.
    pub fence: StateFence,
    /// Opaque refs in deterministic supply order; no bodies travel.
    pub refs: Vec<ExperienceRecordRef>,
    /// Owner coverage binding echoed for this view.
    pub coverage: ProjectionCoverage,
    /// Closed-class omissions for this view.
    pub omissions: Vec<ProjectionOmission>,
}

impl ExperienceView {
    /// Assemble a validated view over opaque refs with owner coverage.
    pub fn assemble(
        family: ExperienceSourceFamily,
        scope: ObservationScope,
        fence: StateFence,
        refs: Vec<ExperienceRecordRef>,
        coverage: ProjectionCoverage,
        omissions: Vec<ProjectionOmission>,
    ) -> Result<Self, ObservationError> {
        let view = Self {
            family,
            scope,
            fence,
            refs,
            coverage,
            omissions,
        };
        view.validate()?;
        Ok(view)
    }

    /// Validate shapes, ref echoes, omission classes, and coverage
    /// consistency. A `Complete` coverage posture is rejected: views never
    /// establish completeness.
    pub fn validate(&self) -> Result<(), ObservationError> {
        self.scope.validate()?;
        if self.fence.validate().is_err() {
            return Err(ObservationError::InvalidField {
                field: "view.fence",
                reason: "fence interval is invalid",
            });
        }
        if self.refs.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "view.refs",
                reason: "exceeds bounded length",
            });
        }
        for reference in &self.refs {
            reference.validate()?;
            if reference.scope != self.scope {
                return Err(ObservationError::InvalidField {
                    field: "view.refs",
                    reason: "ref scope does not match view scope",
                });
            }
            if !reference.fence.is_compatible_with(&self.fence) {
                return Err(ObservationError::InvalidField {
                    field: "view.refs",
                    reason: "ref fence is not compatible with view fence",
                });
            }
        }
        if self.omissions.len() > MAX_PROJECTION_OMISSIONS {
            return Err(ObservationError::InvalidField {
                field: "view.omissions",
                reason: "exceeds bounded length",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        self.coverage.validate()?;
        let carried = u64::try_from(self.refs.len()).unwrap_or(u64::MAX);
        if carried > self.coverage.evidence.observed_count {
            return Err(ObservationError::CoverageIncomplete {
                reason: "carried refs exceed the owner-observed volume",
            });
        }
        if self.coverage.evidence.disposition
            == eliot_observation_contracts::CoverageDisposition::Complete
        {
            return Err(ObservationError::CoverageIncomplete {
                reason: "views never establish completeness",
            });
        }
        Ok(())
    }

    /// Refs of one omission-free reading: handles in supply order.
    #[must_use]
    pub fn handles(&self) -> Vec<&eliot_contracts::ArtifactId> {
        self.refs.iter().map(|item| &item.handle).collect()
    }
}
