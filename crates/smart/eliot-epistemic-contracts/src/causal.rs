//! Causal claims: mechanism, rivals, confounders, and a limited ceiling.
//!
//! Association, correlation, dependency, mechanism, intervention, refuted, and unknown are separate readings
//! that never cross-decode. A [`CausalClaim`] earns the mechanism reading only with a named mechanism, rivals,
//! confounders, outcome and control observations, source, lineage, fence, temporal record, and proof binding —
//! and even then never reaches science grade alone.
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, validate_bounded_text,
    validate_digest,
};
use crate::grade::EvidenceGrade;
use crate::identity::{LineageRootId, PropositionId};
use crate::provenance::SourceLineage;
use crate::temporal::TemporalRecord;
use crate::verifier::SourceAssurance;

/// Separate causal readings; declaration order is not a ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalStatus {
    /// Joint occurrence without a dependence claim.
    Association,
    /// Behavioral co-variation without a dependence claim.
    Correlation,
    /// Precondition or enablement dependence without a mechanism claim.
    DependencyPreconditionEnablement,
    /// Claimed mechanism with rivals and evidence.
    Mechanism,
    /// Intervention with a credible control supports the causal reading.
    InterventionSupported,
    /// The intervention refutes the claimed causal reading.
    Refuted,
    /// Whether the reading holds cannot be established.
    Unknown,
    /// Observed correlation per I12.38, without an intervention claim.
    ObservedCorrelation,
    /// Ablation with a credible intervention and control per I12.38.
    AblationSupported,
    /// Known confounders defeat the causal reading.
    Confounded,
}
impl CausalStatus {
    /// Returns the exact frozen wire name of this status.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Association => "ASSOCIATION",
            Self::Correlation => "CORRELATION",
            Self::DependencyPreconditionEnablement => "DEPENDENCY_PRECONDITION_ENABLEMENT",
            Self::Mechanism => "MECHANISM",
            Self::InterventionSupported => "INTERVENTION_SUPPORTED",
            Self::Refuted => "REFUTED",
            Self::Unknown => "UNKNOWN",
            Self::ObservedCorrelation => "OBSERVED_CORRELATION",
            Self::AblationSupported => "ABLATION_SUPPORTED",
            Self::Confounded => "CONFOUNDED",
        }
    }
}

/// One causal claim with its mechanism, rivals, confounders, and evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalClaim {
    /// Proposition the causal reading bears on.
    pub subject: PropositionId,
    /// Which of the readings is claimed.
    pub status: CausalStatus,
    /// Named mechanism; required in full only for the mechanism reading, but
    /// a bounded mechanism sketch is carried for every reading so weaker
    /// readings stay falsifiable.
    pub mechanism: String,
    /// Preserved rival explanations; order carries no meaning.
    pub rivals: BTreeSet<String>,
    /// Preserved confounders and their dispositions; order carries no meaning.
    /// Non-empty for mechanism and intervention readings.
    pub confounders: BTreeSet<String>,
    /// Evidence references behind the reading; order carries no meaning.
    pub evidence_refs: BTreeSet<ArtifactId>,
    /// Observed outcome delta behind the reading.
    pub outcome: String,
    /// Control condition the outcome is read against.
    pub control: String,
    /// Source owning the reading.
    pub source: SourceId,
    /// Frozen lineage entry binding the canonical source identity, revision, and content digest
    /// (reuses [`SourceLineage`]; no parallel source type is carried).
    pub source_lineage: SourceLineage,
    /// Assurance binding the proof digest to its source and lineage revision.
    pub assurance: SourceAssurance,
    /// Lineage root the reading traces back to.
    pub lineage: LineageRootId,
    /// Fence the reading was captured under.
    pub fence: StateFence,
    /// Capture times of the reading; the five temporal roles stay separate
    /// and never merge into the mechanism.
    pub temporal: TemporalRecord,
    /// Digest of the bounded proof payload behind the reading.
    pub proof_digest: String,
    /// Grade ceiling of this causal reading; always limited.
    pub ceiling: EvidenceGrade,
    /// Scope the reading applies to.
    pub scope: String,
    /// Canonical digest of the causal shape, excluding this field.
    pub digest: String,
}
impl CausalClaim {
    /// Constructs a causal claim after validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: PropositionId,
        status: CausalStatus,
        mechanism: impl Into<String>,
        rivals: BTreeSet<String>,
        confounders: BTreeSet<String>,
        evidence_refs: BTreeSet<ArtifactId>,
        outcome: impl Into<String>,
        control: impl Into<String>,
        source: SourceId,
        source_lineage: SourceLineage,
        assurance: SourceAssurance,
        lineage: LineageRootId,
        fence: StateFence,
        temporal: TemporalRecord,
        proof_digest: impl Into<String>,
        ceiling: EvidenceGrade,
        scope: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut claim = Self {
            subject,
            status,
            mechanism: mechanism.into(),
            rivals,
            confounders,
            evidence_refs,
            outcome: outcome.into(),
            control: control.into(),
            source,
            source_lineage,
            assurance,
            lineage,
            fence,
            temporal,
            proof_digest: proof_digest.into(),
            ceiling,
            scope: scope.into(),
            digest: String::new(),
        };
        claim.validate_shape()?;
        claim.digest = claim.compute_digest()?;
        Ok(claim)
    }

    /// Recomputes the canonical digest of the causal shape (nested tuples keep every arity at or
    /// below the sixteen-element serde bound without dropping a load-bearing field).
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        crate::error::shape_digest(&(
            (
                &self.subject,
                &self.status,
                &self.mechanism,
                &self.rivals,
                &self.confounders,
                &self.evidence_refs,
                &self.outcome,
                &self.control,
            ),
            (
                &self.source,
                &self.source_lineage,
                &self.assurance,
                &self.lineage,
                &self.fence,
                &self.temporal,
                &self.proof_digest,
                &self.ceiling,
                &self.scope,
            ),
        ))
    }

    /// Validates mechanism, rivals, confounders, evidence, outcome, control,
    /// source, lineage, fence, temporal roles, proof binding, and the ceiling.
    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.mechanism, "causal.mechanism", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "causal.scope", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.outcome, "causal.outcome", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.control, "causal.control", MAX_SHORT_TEXT)?;
        // Frozen source provenance: the lineage entry names this source, and the assurance pins the
        // same source, lineage revision, and proof digest, so mutating revision or content under the
        // same source ID breaks the binding even with a recomputed shape digest.
        self.source_lineage.validate()?;
        self.assurance.validate()?;
        if self.source_lineage.owner != self.source || self.assurance.source != self.source {
            let field = "causal.source";
            return Err(ContractError::OutsideManifest { field });
        }
        if self.source_lineage.revision != self.assurance.revision {
            let field = "causal.assurance";
            return Err(ContractError::StaleContext { field });
        }
        if self.assurance.proof_digest != self.proof_digest {
            let field = "causal.assurance";
            return Err(ContractError::DigestMismatch { field });
        }
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "causal.fence",
            })?;
        self.temporal.validate()?;
        validate_digest(&self.proof_digest, "causal.proof_digest")?;
        if self.rivals.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "causal.rivals",
            });
        }
        if self.rivals.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.rivals",
            });
        }
        for rival in &self.rivals {
            validate_bounded_text(rival.as_str(), "causal.rivals", MAX_SHORT_TEXT)?;
        }
        if self.confounders.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.confounders",
            });
        }
        for confounder in &self.confounders {
            validate_bounded_text(confounder.as_str(), "causal.confounders", MAX_SHORT_TEXT)?;
        }
        // Mechanism and intervention readings without confounders are
        // mechanism-plus-identifiers alone, which never suffice.
        if matches!(
            self.status,
            CausalStatus::Mechanism
                | CausalStatus::InterventionSupported
                | CausalStatus::AblationSupported
        ) && self.confounders.is_empty()
        {
            return Err(ContractError::EmptyCollection {
                field: "causal.confounders",
            });
        }
        if self.evidence_refs.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "causal.evidence_refs",
            });
        }
        if self.evidence_refs.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.evidence_refs",
            });
        }
        if self.ceiling == EvidenceGrade::ScienceGrade {
            return Err(ContractError::CeilingViolation {
                field: "causal.ceiling",
            });
        }
        if matches!(
            self.status,
            CausalStatus::Association
                | CausalStatus::Correlation
                | CausalStatus::ObservedCorrelation
                | CausalStatus::Unknown
                | CausalStatus::Refuted
                | CausalStatus::Confounded
        ) && self.ceiling.rank() > EvidenceGrade::Grounded.rank()
        {
            return Err(ContractError::CeilingViolation {
                field: "causal.ceiling",
            });
        }
        Ok(())
    }

    /// Validates the causal shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "causal.digest")
    }
}
