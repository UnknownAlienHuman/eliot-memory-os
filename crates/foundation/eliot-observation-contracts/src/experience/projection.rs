//! Versioned owner-neutral experience projection contracts.
//!
//! This module closes the experience side of the #223 projection freeze
//! with one shared core plus one explicit envelope per source family:
//! [`JournalProjection`] carries full owner journal records,
//! [`BankProjection`] and [`FeedbackProjection`] carry opaque refs (no
//! bank record type and no feedback receipt type exist upstream, so bodies
//! cannot travel). Every envelope binds source identity, observed-volume
//! evidence, source revision, coverage cursor, closed omission classes,
//! fence, and denominator provenance.
//!
//! Placement: the wave briefs name no separate bank or feedback owner; the
//! Governor live journal (`eliot-observation`) owns admission and rebuild,
//! while every versioned wire shape here reuses this crate's record,
//! coverage, gap, handle, scope, and fence vocabulary. This module is the
//! projection-schema owner; live enumeration stays with the Governor owner.
//!
//! Completeness doctrine, enforced below: observed volume arrives as owner
//! coverage evidence ([`ProjectionCoverage`] with disposition,
//! denominator source ref, coverage digest, observed count, and blind
//! intervals), never as caller arithmetic. Carried members reconciling
//! against that evidence is necessary but never sufficient: completeness
//! additionally requires the owner `Complete` disposition with empty
//! omissions and empty blind intervals. Anything else is an explicit
//! partial read. Omissions use the closed [`ProjectionOmissionClass`];
//! free-form reason strings cannot cross this boundary.
//!
//! Fences are carried, not gated: each envelope freezes the fence it was
//! read under, opaque refs echo their own fence for a compatibility check,
//! and consumers gate compatibility at their edge. Record-level fence
//! recovery stays a live-owner capability. This module performs no
//! admission, enumeration, retrieval, ranking, or promotion.

use eliot_contracts::{ArtifactId, ContractVersion, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, CoverageDisposition, CoverageEvidence, ObservationError, ObservationScope,
    SourceRevisionHandle, SystemObservationJournalRecord,
};

/// Maximum records or refs carried by one projection envelope.
pub const MAX_PROJECTION_MEMBERS: usize = 1024;
/// Maximum omission entries carried by one projection envelope.
pub const MAX_PROJECTION_OMISSIONS: usize = 256;
/// Maximum characters accepted for a denominator source ref.
pub const MAX_DENOMINATOR_REF_CHARS: usize = 1024;
/// Maximum characters accepted for an omission detail note.
pub const MAX_OMISSION_DETAIL_CHARS: usize = 256;
/// Maximum characters accepted for an owner revision marker.
pub const MAX_SOURCE_REVISION_CHARS: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ObservationError> {
    text(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ObservationError::InvalidField {
            field,
            reason: "exceeds bounded length",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

fn fence_shape(value: &StateFence, field: &'static str) -> Result<(), ObservationError> {
    value
        .validate()
        .map_err(|_| ObservationError::InvalidField {
            field,
            reason: "fence interval is invalid",
        })
}

/// Closed source-family marker for experience projections.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExperienceSourceFamily {
    /// Governor observation journal family.
    SystemObservationJournal,
    /// Self-scope experience bank family.
    SystemExperienceBank,
    /// Agent feedback family.
    AgentFeedback,
}

/// Opaque record ref with owner revision cursor plus scope/fence echoes.
///
/// No record body travels: identity, the owner revision cursor, and the
/// scope/fence the owner metadata reported at assembly time. Echoes are
/// checked against the envelope scope/fence; fabrication beyond shape
/// stays an owner-revalidation concern.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceRecordRef {
    /// Exact canonical handle of the record.
    pub handle: ArtifactId,
    /// Owner revision cursor: identity, revision, content digest, length.
    pub revision: SourceRevisionHandle,
    /// Scope the owner metadata reported for this record.
    pub scope: ObservationScope,
    /// Fence the owner metadata reported for this record.
    pub fence: StateFence,
}

impl ExperienceRecordRef {
    /// Validate cursor, scope, and fence shape.
    pub fn validate(&self) -> Result<(), ObservationError> {
        self.revision.validate()?;
        self.scope.validate()?;
        fence_shape(&self.fence, "record_ref.fence")
    }
}

/// Closed omission classes for experience projections.
///
/// Free-form reason strings cannot cross this boundary; operational context
/// travels in the bounded detail note beside the class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionOmissionClass {
    /// Record scope differs from the projection scope.
    ScopeMismatch,
    /// Record fence is incompatible with the projection fence.
    FenceMismatch,
    /// Protected role withheld from this projection.
    ProtectedWithheld,
    /// Volume beyond the assembly bound, named per handle.
    TruncatedAtBound,
    /// Record superseded before the projection was read.
    SupersededBeforeProjection,
}

/// One explicitly omitted record: handle plus its closed class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionOmission {
    /// Handle of the omitted record.
    pub handle: ArtifactId,
    /// Closed class of the omission.
    pub class: ProjectionOmissionClass,
    /// Bounded operational context for the class.
    pub detail: String,
}

impl ProjectionOmission {
    /// Validate the omission shape.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(
            &self.detail,
            "projection_omission.detail",
            MAX_OMISSION_DETAIL_CHARS,
        )
    }
}

/// Owner coverage binding for one projection.
///
/// The disposition is owner-declared posture; the denominator source ref
/// names the owner enumeration for independent rechecking; the coverage
/// digest binds the owner coverage evidence. Counts reconcile against
/// carried members but never establish completeness alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCoverage {
    /// Owner coverage evidence: posture, denominator ref, cursor range,
    /// blind spots, and owner-observed volume.
    pub evidence: CoverageEvidence,
    /// Digest of the owner coverage evidence this binding repeats.
    pub coverage_digest: String,
}

impl ProjectionCoverage {
    /// Validate evidence, digest shape, and denominator ref bound.
    pub fn validate(&self) -> Result<(), ObservationError> {
        self.evidence.validate()?;
        if self.evidence.denominator_source_ref.chars().count() > MAX_DENOMINATOR_REF_CHARS {
            return Err(ObservationError::InvalidField {
                field: "projection_coverage.denominator_source_ref",
                reason: "exceeds bounded length",
            });
        }
        digest(&self.coverage_digest, "projection_coverage.coverage_digest")
    }
}

/// Count members without lossy casts.
fn len_u64<T>(values: &[T]) -> u64 {
    u64::try_from(values.len()).unwrap_or(u64::MAX)
}

/// Shared envelope header validated once per projection.
struct EnvelopeHeader<'a> {
    contract_version: ContractVersion,
    family: ExperienceSourceFamily,
    expected_family: ExperienceSourceFamily,
    scope: &'a ObservationScope,
    fence: &'a StateFence,
    source_revision: &'a str,
    carried: u64,
    coverage: &'a ProjectionCoverage,
    omissions: &'a [ProjectionOmission],
}

impl EnvelopeHeader<'_> {
    fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "projection.contract_version",
                reason: "unsupported contract version",
            });
        }
        if self.family != self.expected_family {
            return Err(ObservationError::InvalidField {
                field: "projection.family",
                reason: "family marker does not match this envelope",
            });
        }
        self.scope.validate()?;
        fence_shape(self.fence, "projection.fence")?;
        bounded_text(
            self.source_revision,
            "projection.source_revision",
            MAX_SOURCE_REVISION_CHARS,
        )?;
        self.coverage.validate()?;
        if self.omissions.len() > MAX_PROJECTION_OMISSIONS {
            return Err(ObservationError::InvalidField {
                field: "projection.omissions",
                reason: "exceeds bounded length",
            });
        }
        for omission in self.omissions {
            omission.validate()?;
        }
        // Counts reconcile against carried members but never establish
        // completeness alone: over-count is always inconsistent, while
        // completeness additionally requires the owner Complete posture
        // with empty omissions and empty blind intervals.
        if self.carried > self.coverage.evidence.observed_count {
            return Err(ObservationError::CoverageIncomplete {
                reason: "carried members exceed the owner-observed volume",
            });
        }
        if self.coverage.evidence.disposition == CoverageDisposition::Complete
            && (self.carried != self.coverage.evidence.observed_count
                || !self.omissions.is_empty()
                || !self.coverage.evidence.blind_intervals.is_empty())
        {
            return Err(ObservationError::CoverageIncomplete {
                reason: "complete posture requires exact count with no omissions or blind intervals",
            });
        }
        Ok(())
    }
}

/// Projection over Governor journal records: full owner records travel.
///
/// Event-carrying records must name the projection scope; gap and control
/// records carry no event scope and are checked by their owner shapes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalProjection {
    /// Frozen contract version this projection was written against.
    pub contract_version: ContractVersion,
    /// Stable projection identity.
    pub projection_id: ArtifactId,
    /// Family marker; always `SYSTEM_OBSERVATION_JOURNAL`.
    pub family: ExperienceSourceFamily,
    /// Read scope governing this projection.
    pub scope: ObservationScope,
    /// Fence this projection was read under, carried for edge gating.
    pub fence: StateFence,
    /// Owner revision marker read at.
    pub source_revision: String,
    /// Owner-validated records in deterministic supply order.
    pub records: Vec<SystemObservationJournalRecord>,
    /// Owner coverage binding for this projection.
    pub coverage: ProjectionCoverage,
    /// Closed-class omissions for this projection.
    pub omissions: Vec<ProjectionOmission>,
    /// Frozen digest over the projection shape, excluding this field.
    pub digest: String,
}

impl JournalProjection {
    /// Assemble a validated projection over owner journal records.
    pub fn assemble(
        projection_id: ArtifactId,
        scope: ObservationScope,
        fence: StateFence,
        source_revision: String,
        records: Vec<SystemObservationJournalRecord>,
        coverage: ProjectionCoverage,
        omissions: Vec<ProjectionOmission>,
    ) -> Result<Self, ObservationError> {
        let mut projection = Self {
            contract_version: CONTRACT_VERSION,
            projection_id,
            family: ExperienceSourceFamily::SystemObservationJournal,
            scope,
            fence,
            source_revision,
            records,
            coverage,
            omissions,
            digest: String::new(),
        };
        projection.digest = projection.compute_digest()?;
        projection.validate()?;
        Ok(projection)
    }

    /// Compute the frozen digest over the projection shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        if self.records.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.records",
                reason: "exceeds bounded length",
            });
        }
        eliot_contracts::canonical_json_bytes(&(
            &self.contract_version,
            &self.projection_id,
            &self.family,
            &self.scope,
            &self.fence,
            &self.source_revision,
            &self.records,
            &self.coverage,
            &self.omissions,
        ))
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field: "projection.digest",
            reason: "projection is not canonically encodable",
        })
    }

    /// Validate header, per-record owner shapes with scope binding,
    /// coverage rules, and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.records.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.records",
                reason: "exceeds bounded length",
            });
        }
        EnvelopeHeader {
            contract_version: self.contract_version,
            family: self.family,
            expected_family: ExperienceSourceFamily::SystemObservationJournal,
            scope: &self.scope,
            fence: &self.fence,
            source_revision: &self.source_revision,
            carried: len_u64(&self.records),
            coverage: &self.coverage,
            omissions: &self.omissions,
        }
        .validate()?;
        for record in &self.records {
            record.validate()?;
            if let Some(event) = &record.event
                && event.affected_scope != self.scope
            {
                return Err(ObservationError::InvalidField {
                    field: "projection.records",
                    reason: "record scope does not match projection scope",
                });
            }
        }
        digest(&self.digest, "projection.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ObservationError::InvalidField {
                field: "projection.digest",
                reason: "does not match projection preimage",
            });
        }
        Ok(())
    }
}

/// Projection over experience bank refs: opaque handles travel.
///
/// No bank record type exists upstream, so bodies cannot travel; refs
/// carry the owner revision cursor with scope/fence echoes checked
/// against the envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BankProjection {
    /// Frozen contract version this projection was written against.
    pub contract_version: ContractVersion,
    /// Stable projection identity.
    pub projection_id: ArtifactId,
    /// Family marker; always `SYSTEM_EXPERIENCE_BANK`.
    pub family: ExperienceSourceFamily,
    /// Read scope governing this projection.
    pub scope: ObservationScope,
    /// Fence this projection was read under, carried for edge gating.
    pub fence: StateFence,
    /// Owner revision marker read at.
    pub source_revision: String,
    /// Opaque bank refs in deterministic supply order.
    pub refs: Vec<ExperienceRecordRef>,
    /// Owner coverage binding for this projection.
    pub coverage: ProjectionCoverage,
    /// Closed-class omissions for this projection.
    pub omissions: Vec<ProjectionOmission>,
    /// Frozen digest over the projection shape, excluding this field.
    pub digest: String,
}

impl BankProjection {
    /// Assemble a validated projection over opaque bank refs.
    pub fn assemble(
        projection_id: ArtifactId,
        scope: ObservationScope,
        fence: StateFence,
        source_revision: String,
        refs: Vec<ExperienceRecordRef>,
        coverage: ProjectionCoverage,
        omissions: Vec<ProjectionOmission>,
    ) -> Result<Self, ObservationError> {
        let mut projection = Self {
            contract_version: CONTRACT_VERSION,
            projection_id,
            family: ExperienceSourceFamily::SystemExperienceBank,
            scope,
            fence,
            source_revision,
            refs,
            coverage,
            omissions,
            digest: String::new(),
        };
        projection.digest = projection.compute_digest()?;
        projection.validate()?;
        Ok(projection)
    }

    /// Compute the frozen digest over the projection shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        if self.refs.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.refs",
                reason: "exceeds bounded length",
            });
        }
        eliot_contracts::canonical_json_bytes(&(
            &self.contract_version,
            &self.projection_id,
            &self.family,
            &self.scope,
            &self.fence,
            &self.source_revision,
            &self.refs,
            &self.coverage,
            &self.omissions,
        ))
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field: "projection.digest",
            reason: "projection is not canonically encodable",
        })
    }

    /// Validate header, per-ref echoes against the envelope scope/fence,
    /// coverage rules, and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.refs.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.refs",
                reason: "exceeds bounded length",
            });
        }
        EnvelopeHeader {
            contract_version: self.contract_version,
            family: self.family,
            expected_family: ExperienceSourceFamily::SystemExperienceBank,
            scope: &self.scope,
            fence: &self.fence,
            source_revision: &self.source_revision,
            carried: len_u64(&self.refs),
            coverage: &self.coverage,
            omissions: &self.omissions,
        }
        .validate()?;
        for reference in &self.refs {
            reference.validate()?;
            if reference.scope != self.scope {
                return Err(ObservationError::InvalidField {
                    field: "projection.refs",
                    reason: "ref scope does not match projection scope",
                });
            }
            if !reference.fence.is_compatible_with(&self.fence) {
                return Err(ObservationError::InvalidField {
                    field: "projection.refs",
                    reason: "ref fence is not compatible with projection fence",
                });
            }
        }
        digest(&self.digest, "projection.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ObservationError::InvalidField {
                field: "projection.digest",
                reason: "does not match projection preimage",
            });
        }
        Ok(())
    }
}

/// Projection over agent feedback refs: opaque handles travel.
///
/// No feedback receipt type exists upstream, so bodies cannot travel;
/// refs carry the owner revision cursor with scope/fence echoes checked
/// against the envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackProjection {
    /// Frozen contract version this projection was written against.
    pub contract_version: ContractVersion,
    /// Stable projection identity.
    pub projection_id: ArtifactId,
    /// Family marker; always `AGENT_FEEDBACK`.
    pub family: ExperienceSourceFamily,
    /// Read scope governing this projection.
    pub scope: ObservationScope,
    /// Fence this projection was read under, carried for edge gating.
    pub fence: StateFence,
    /// Owner revision marker read at.
    pub source_revision: String,
    /// Opaque feedback refs in deterministic supply order.
    pub refs: Vec<ExperienceRecordRef>,
    /// Owner coverage binding for this projection.
    pub coverage: ProjectionCoverage,
    /// Closed-class omissions for this projection.
    pub omissions: Vec<ProjectionOmission>,
    /// Frozen digest over the projection shape, excluding this field.
    pub digest: String,
}

impl FeedbackProjection {
    /// Assemble a validated projection over opaque feedback refs.
    pub fn assemble(
        projection_id: ArtifactId,
        scope: ObservationScope,
        fence: StateFence,
        source_revision: String,
        refs: Vec<ExperienceRecordRef>,
        coverage: ProjectionCoverage,
        omissions: Vec<ProjectionOmission>,
    ) -> Result<Self, ObservationError> {
        let mut projection = Self {
            contract_version: CONTRACT_VERSION,
            projection_id,
            family: ExperienceSourceFamily::AgentFeedback,
            scope,
            fence,
            source_revision,
            refs,
            coverage,
            omissions,
            digest: String::new(),
        };
        projection.digest = projection.compute_digest()?;
        projection.validate()?;
        Ok(projection)
    }

    /// Compute the frozen digest over the projection shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        if self.refs.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.refs",
                reason: "exceeds bounded length",
            });
        }
        eliot_contracts::canonical_json_bytes(&(
            &self.contract_version,
            &self.projection_id,
            &self.family,
            &self.scope,
            &self.fence,
            &self.source_revision,
            &self.refs,
            &self.coverage,
            &self.omissions,
        ))
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field: "projection.digest",
            reason: "projection is not canonically encodable",
        })
    }

    /// Validate header, per-ref echoes against the envelope scope/fence,
    /// coverage rules, and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.refs.len() > MAX_PROJECTION_MEMBERS {
            return Err(ObservationError::InvalidField {
                field: "projection.refs",
                reason: "exceeds bounded length",
            });
        }
        EnvelopeHeader {
            contract_version: self.contract_version,
            family: self.family,
            expected_family: ExperienceSourceFamily::AgentFeedback,
            scope: &self.scope,
            fence: &self.fence,
            source_revision: &self.source_revision,
            carried: len_u64(&self.refs),
            coverage: &self.coverage,
            omissions: &self.omissions,
        }
        .validate()?;
        for reference in &self.refs {
            reference.validate()?;
            if reference.scope != self.scope {
                return Err(ObservationError::InvalidField {
                    field: "projection.refs",
                    reason: "ref scope does not match projection scope",
                });
            }
            if !reference.fence.is_compatible_with(&self.fence) {
                return Err(ObservationError::InvalidField {
                    field: "projection.refs",
                    reason: "ref fence is not compatible with projection fence",
                });
            }
        }
        digest(&self.digest, "projection.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ObservationError::InvalidField {
                field: "projection.digest",
                reason: "does not match projection preimage",
            });
        }
        Ok(())
    }
}
