//! Shared, source-bound metadata for logical Context units and transforms.
//!
//! Each envelope describes one unit with its own task/scope/fence binding.
//! Source units carry immutable snapshots; source-less parents refer to child
//! envelopes by identity without overwriting their source, order, or scope.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_agent_contracts::AgentAttemptId;
use eliot_contracts::{ArtifactId, ContractVersion, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContextBinding, ContextError, NonRecoverableReason, SourceSnapshot, validate_digest,
    validate_text,
};

/// Only this schema revision is interpreted by this validator.
///
/// `1.2.0` adds the required `BoundaryMetadataEnvelope::disposition` member, so a
/// payload that names a disposition it never recorded is rejected by name.
/// `1.1.0` added the required `BoundaryMetadataSet::transforms` member relation.
/// Both older revisions are rejected in `validate()` instead of being read as a
/// set that declares no transform or no disposition.
pub const BOUNDARY_METADATA_SCHEMA_REVISION: ContractVersion = ContractVersion::new(1, 2, 0);

/// Semantic form of a logical unit represented by one boundary envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryUnitKind {
    /// One addressable source or derived unit.
    Unit,
    /// A zero-based, half-open contiguous extract from one source snapshot.
    ContiguousExtract,
    /// A batch whose members are independently described child units.
    Batch,
    /// An indivisible call and corresponding result pair.
    CallResultPair,
    /// An evidence edge with source, relation, and target members.
    EvidenceEdge,
}

/// Membership completeness of one logical unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryCompleteness {
    /// The declared denominator is fully represented.
    Complete,
    /// The denominator is known, and one or more members are gaps.
    Incomplete,
    /// Legacy data did not carry enough information to establish a denominator.
    UnknownLegacy,
}

/// Precision of the boundary information carried by an envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryPrecision {
    /// Identities, ranges, and source revision are exact.
    Exact,
    /// Some boundary detail is degraded but the known denominator is retained.
    BoundedDegraded,
    /// Legacy data did not carry enough information to establish precision.
    UnknownLegacy,
}

/// Coordinate system for an exact source range.
///
/// Both systems use zero-based, half-open `[start, end_exclusive)` endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryCoordinateSystem {
    /// UTF-8 byte offsets in the immutable source snapshot.
    Utf8ByteOffset,
    /// Unicode scalar-value offsets in the immutable source snapshot.
    UnicodeScalarOffset,
}

/// Exact range pinned to a source snapshot and revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactSourceRange {
    /// Immutable source snapshot identity.
    pub snapshot_id: ArtifactId,
    /// Exact source revision used to interpret both endpoints.
    pub source_revision: String,
    /// Explicit coordinate system for the endpoints.
    pub coordinate_system: BoundaryCoordinateSystem,
    /// Inclusive start endpoint.
    pub start: u64,
    /// Exclusive end endpoint.
    pub end_exclusive: u64,
    /// Declared span; must equal `end_exclusive - start`.
    pub length: u64,
}

impl ExactSourceRange {
    /// Check this range against the immutable snapshot it claims to sit in.
    ///
    /// Crate-visible so the one range type in this crate is validated by one
    /// rule wherever it is carried. `ContextCandidate::source_range` reuses this
    /// exact check rather than restating it, so a range admitted on a candidate
    /// and a range admitted on a boundary member cannot disagree about which
    /// snapshot, which source revision, or which endpoint order is valid.
    pub(crate) fn validate(&self, source: &SourceSnapshot) -> Result<(), ContextError> {
        validate_text(&self.source_revision, "boundary.range.source_revision")?;
        if self.snapshot_id != source.snapshot_id || self.source_revision != source.revision {
            return Err(ContextError::IdentityConflict);
        }
        if self.end_exclusive <= self.start
            || self.end_exclusive.checked_sub(self.start) != Some(self.length)
        {
            return Err(ContextError::InvalidField("boundary.range.endpoints"));
        }
        Ok(())
    }
}

/// Semantic role of a member in a composite logical unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryMemberRole {
    /// A source member, optionally pinned to an exact range.
    SourceMember,
    /// A child logical unit in a batch.
    ChildUnit,
    /// The call member of a call/result pair.
    Call,
    /// The result member of a call/result pair.
    Result,
    /// Source endpoint of an evidence edge.
    EvidenceSource,
    /// Relation or evidence assertion of an evidence edge.
    EvidenceRelation,
    /// Target endpoint of an evidence edge.
    EvidenceTarget,
}

/// Exact identity used by one declared denominator member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum BoundaryMemberReference {
    /// Addressable source member and optional source range.
    SourceMember {
        /// Stable source-member identity.
        member_id: ArtifactId,
        /// Exact range when the transform preserves one.
        range: Option<ExactSourceRange>,
    },
    /// Identity of a separately described child boundary.
    ChildUnit {
        /// Child envelope identity; it is never replaced with parent metadata.
        unit_id: ArtifactId,
    },
}

impl BoundaryMemberReference {
    fn identity(&self) -> &ArtifactId {
        match self {
            Self::SourceMember { member_id, .. } => member_id,
            Self::ChildUnit { unit_id } => unit_id,
        }
    }
}

/// One ordered member in the declared source or child denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryMember {
    /// Stable order within this unit's own source/member sequence.
    pub order: u64,
    /// Role required by the unit kind, when it is composite.
    pub role: BoundaryMemberRole,
    /// Source member or child-boundary reference.
    pub reference: BoundaryMemberReference,
}

/// Why a declared member is not retained by this representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryGapReason {
    /// The member was unavailable to the transform.
    Unavailable,
    /// The member was explicitly omitted by policy.
    Omitted,
    /// The transform truncated the member.
    Truncated,
    /// The operation does not support this member kind.
    Unsupported,
}

/// One known denominator member that is absent from the retained output.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryGap {
    /// Exact identity of the declared but unretained member.
    pub member_id: ArtifactId,
    /// Explicit reason it is unavailable in this representation.
    pub reason: BoundaryGapReason,
}

/// The five permitted dispositions when a unit cannot be preserved exactly.
///
/// I12.13 allows exactly these degradations, each whole-unit and
/// operation-specific. A representation that needs none of them carries no
/// disposition record at all; one that needs one must say which, and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryDisposition {
    /// Only an exact expansion handle stands in for the original.
    ExactHandleOnly,
    /// A narrower extractive view; omitted members are named as gaps.
    NarrowerExtractiveView,
    /// The whole unit is incomplete or unsupported by this operation.
    WholeUnitIncompleteUnsupported,
    /// A proposal to route to a compatible contour.
    RouteToCompatibleContour,
    /// Only the dependent decision or effect is blocked.
    BlockDependentDecisionOrEffect,
}

/// How material this operation did not retain may be reopened.
///
/// The absence of a handle is never inferred: it is stated as an explicit
/// non-recoverable reason or as an unknown observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "handles", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryRecovery {
    /// Exact expansion handles this operation retained.
    ExpansionHandles(Vec<ArtifactId>),
    /// The original is unavailable or forbidden and cannot be reopened.
    NonRecoverable(NonRecoverableReason),
    /// No reopen path was observed; this is not a claim of non-recoverability.
    Unknown,
}

/// One explicit degradation disposition with its reason and source binding.
///
/// `None` on the envelope means no permitted degradation applied. `Some` is the
/// only way to represent a narrowed, blocked or unsupported unit, so a partial
/// representation can never be read as a complete original.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryDispositionRecord {
    /// Which permitted disposition this operation applied.
    pub disposition: BoundaryDisposition,
    /// Non-empty reason this disposition applied to this unit.
    pub reason: String,
    /// Rule/evidence identity that authorized the disposition.
    pub rule_evidence: ArtifactId,
    /// Boundary precision actually delivered by this representation.
    pub delivered_precision: BoundaryPrecision,
    /// How the material this operation did not retain may be reopened.
    pub recovery: BoundaryRecovery,
    /// Whether this disposition authorizes the dependent effect.
    ///
    /// A route proposal and a blocking disposition both leave this `false`: the
    /// first names a contour, the second names a stop, and neither is authority
    /// to launch anything.
    pub grants_launch_authority: bool,
}

/// Exact denominator, retained sequence, and explicit member gaps.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryMemberCoverage {
    /// Known denominator, or an explicit legacy-unknown marker.
    pub denominator: BoundaryDenominator,
    /// Members actually retained, in their output order.
    pub retained_members: Vec<ArtifactId>,
    /// Declared members known to be absent from the output.
    pub known_gaps: Vec<BoundaryGap>,
}

/// Denominator declaration for a unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "members", deny_unknown_fields)]
pub enum BoundaryDenominator {
    /// Complete list of members expected from the source operation.
    Declared(Vec<BoundaryMember>),
    /// Historical payload had no checkable denominator.
    UnknownLegacy,
}

/// Externally versioned transform identity and configuration digest.
///
/// The boundary contract preserves this exact external revision as provenance;
/// it does not interpret the transform's semantics or claim that the transform
/// is executable in this crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryTransformerRevision {
    /// Stable transformer identity.
    pub transformer_id: String,
    /// Transformer contract revision.
    pub revision: ContractVersion,
    /// Digest of the exact transform configuration.
    pub configuration_sha256: String,
}

/// Boundary metadata for exactly one logical unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryMetadataEnvelope {
    /// Stable identity of this logical unit.
    pub unit_id: ArtifactId,
    /// Kind of logical unit carried by this envelope.
    pub unit_kind: BoundaryUnitKind,
    /// Existing task, scope, and State Fence binding for this unit.
    pub binding: ContextBinding,
    /// Immutable source lineage; absent for source-less parents or unknown legacy data.
    pub source: Option<SourceSnapshot>,
    /// Attempt that produced this source unit, when known.
    pub source_attempt_id: Option<AgentAttemptId>,
    /// Causal stage that produced this source unit, when known.
    pub source_stage: Option<String>,
    /// Source-local order, absent for a source-less composite parent.
    pub source_order: Option<u64>,
    /// Declared denominator, retained members, and explicit known gaps.
    pub coverage: BoundaryMemberCoverage,
    /// Provenance artifacts supporting this unit's lineage.
    pub provenance_refs: Vec<ArtifactId>,
    /// Disclosure/authority boundary references for this unit.
    pub disclosure_refs: Vec<ArtifactId>,
    /// References closing influence lineage for membership-changing transforms.
    pub influence_closure_refs: Vec<ArtifactId>,
    /// Explicit omission records or policies applied to this unit.
    pub omission_refs: Vec<ArtifactId>,
    /// Handles by which omitted or degraded material can be expanded.
    pub expansion_refs: Vec<ArtifactId>,
    /// Membership completeness established for this envelope.
    pub completeness: BoundaryCompleteness,
    /// Precision established for its source/member boundaries.
    pub precision: BoundaryPrecision,
    /// The permitted degradation applied to this unit, absent when none applied.
    ///
    /// A unit that carries no disposition is represented exactly. A unit that
    /// carries one names which of the five permitted degradations it took, why,
    /// and how the omitted material may be reopened, so a narrowed representation
    /// cannot be read as a complete original.
    pub disposition: Option<BoundaryDispositionRecord>,
    /// Schema revision of this wire contract.
    pub schema_revision: ContractVersion,
    /// Exact transformer revision and configuration, absent only for legacy data.
    pub transformer: Option<BoundaryTransformerRevision>,
}

/// Caller-supplied resource bounds for validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryValidationLimits {
    /// Maximum number of envelopes in a set.
    pub max_units: usize,
    /// Maximum number of nodes on a child-reference path.
    pub max_depth: usize,
    /// Maximum declared, retained, or gap members in one unit.
    pub max_members_per_unit: usize,
    /// Maximum declared denominator identities across the complete set.
    pub max_total_members: usize,
    /// Maximum lineage references in one unit.
    pub max_references_per_unit: usize,
    /// Maximum UTF-8 bytes of metadata strings across the complete set.
    pub max_metadata_bytes: usize,
}

impl BoundaryValidationLimits {
    /// Reject zero limits, which would make validation silently vacuous.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.max_units == 0
            || self.max_depth == 0
            || self.max_members_per_unit == 0
            || self.max_total_members == 0
            || self.max_references_per_unit == 0
            || self.max_metadata_bytes == 0
        {
            return Err(ContextError::InvalidField("boundary.limits"));
        }
        Ok(())
    }
}

impl BoundaryMetadataEnvelope {
    /// Validate one envelope's intrinsic identity, membership, lineage, and bounds.
    pub fn validate(&self, limits: &BoundaryValidationLimits) -> Result<(), ContextError> {
        limits.validate()?;
        self.validate_local(limits).map(|_| ())
    }

    fn validate_local(
        &self,
        limits: &BoundaryValidationLimits,
    ) -> Result<(usize, usize), ContextError> {
        let member_count = self.validate_header(limits)?;
        let mut metadata_bytes = self.account_identity_metadata(limits)?;

        match (
            &self.completeness,
            &self.precision,
            &self.coverage.denominator,
        ) {
            (
                BoundaryCompleteness::UnknownLegacy,
                BoundaryPrecision::UnknownLegacy,
                BoundaryDenominator::UnknownLegacy,
            ) => {
                if !self.coverage.retained_members.is_empty()
                    || !self.coverage.known_gaps.is_empty()
                {
                    return Err(ContextError::InvalidField(
                        "boundary.unknown_legacy_coverage",
                    ));
                }
            }
            (BoundaryCompleteness::UnknownLegacy, _, _)
            | (_, BoundaryPrecision::UnknownLegacy, _) => {
                return Err(ContextError::InvalidField("boundary.unknown_legacy_status"));
            }
            (_, _, BoundaryDenominator::UnknownLegacy) => {
                return Err(ContextError::InvalidField(
                    "boundary.unknown_legacy_denominator",
                ));
            }
            _ => self.validate_declared_coverage(limits, &mut metadata_bytes)?,
        }

        if self.source.is_none() && self.source_order.is_some() {
            return Err(ContextError::InvalidField(
                "boundary.source_order_without_source",
            ));
        }
        if self.completeness != BoundaryCompleteness::UnknownLegacy
            && self.source.is_some() != self.source_order.is_some()
        {
            return Err(ContextError::InvalidField("boundary.source_order"));
        }
        if self.completeness != BoundaryCompleteness::UnknownLegacy && self.transformer.is_none() {
            return Err(ContextError::MissingField("boundary.transformer"));
        }

        self.validate_lineage_refs(limits, &mut metadata_bytes)?;
        self.validate_disposition(limits, &mut metadata_bytes)?;

        if metadata_bytes > limits.max_metadata_bytes {
            return Err(ContextError::Bounds {
                field: "boundary.metadata_bytes",
            });
        }
        Ok((member_count, metadata_bytes))
    }

    fn validate_header(&self, limits: &BoundaryValidationLimits) -> Result<usize, ContextError> {
        self.binding.validate()?;
        if self.schema_revision != BOUNDARY_METADATA_SCHEMA_REVISION {
            return Err(ContextError::InvalidField("boundary.schema_revision"));
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        if let Some(stage) = &self.source_stage {
            validate_text(stage, "boundary.source_stage")?;
        }
        if let Some(transformer) = &self.transformer {
            validate_text(&transformer.transformer_id, "boundary.transformer_id")?;
            if transformer.revision.major == 0 {
                return Err(ContextError::InvalidField("boundary.transformer.revision"));
            }
            validate_digest(
                &transformer.configuration_sha256,
                "boundary.transformer.configuration_sha256",
            )?;
        }
        let member_count = match &self.coverage.denominator {
            BoundaryDenominator::Declared(members) => members.len(),
            BoundaryDenominator::UnknownLegacy => 0,
        };
        if member_count > limits.max_members_per_unit
            || self.coverage.retained_members.len() > limits.max_members_per_unit
            || self.coverage.known_gaps.len() > limits.max_members_per_unit
        {
            return Err(ContextError::Bounds {
                field: "boundary.members",
            });
        }
        let ref_count = self
            .provenance_refs
            .len()
            .checked_add(self.disclosure_refs.len())
            .and_then(|count| count.checked_add(self.influence_closure_refs.len()))
            .and_then(|count| count.checked_add(self.omission_refs.len()))
            .and_then(|count| count.checked_add(self.expansion_refs.len()))
            .ok_or(ContextError::Overflow)?;
        if ref_count > limits.max_references_per_unit {
            return Err(ContextError::Bounds {
                field: "boundary.references",
            });
        }
        Ok(member_count)
    }

    fn account_identity_metadata(
        &self,
        limits: &BoundaryValidationLimits,
    ) -> Result<usize, ContextError> {
        let mut bytes = 0usize;
        for (field, value) in [
            ("boundary.unit_id", self.unit_id.as_str()),
            ("boundary.binding.task_id", self.binding.task_id.as_str()),
            (
                "boundary.binding.attempt_id",
                self.binding.attempt_id.as_str(),
            ),
            ("boundary.binding.scope_id", self.binding.scope_id.as_str()),
            (
                "boundary.binding.decision_id",
                self.binding.decision_id.as_str(),
            ),
        ] {
            account_text(&mut bytes, limits, value, field)?;
        }
        if let Some(operation) = &self.binding.operation_id {
            account_text(
                &mut bytes,
                limits,
                operation.as_str(),
                "boundary.binding.operation_id",
            )?;
        }
        if let Some(source) = &self.source {
            for (field, value) in [
                ("boundary.source.source_id", source.source_id.as_str()),
                ("boundary.source.owner", source.owner.as_str()),
                ("boundary.source.snapshot_id", source.snapshot_id.as_str()),
                ("boundary.source.revision", source.revision.as_str()),
                (
                    "boundary.source.content_sha256",
                    source.content_sha256.as_str(),
                ),
            ] {
                account_text(&mut bytes, limits, value, field)?;
            }
            if let Some(predecessor) = &source.predecessor {
                account_text(
                    &mut bytes,
                    limits,
                    predecessor.as_str(),
                    "boundary.source.predecessor",
                )?;
            }
        }
        if let Some(attempt) = &self.source_attempt_id {
            account_text(
                &mut bytes,
                limits,
                attempt.as_str(),
                "boundary.source_attempt_id",
            )?;
        }
        if let Some(stage) = &self.source_stage {
            account_text(&mut bytes, limits, stage, "boundary.source_stage")?;
        }
        if let Some(transformer) = &self.transformer {
            account_text(
                &mut bytes,
                limits,
                &transformer.transformer_id,
                "boundary.transformer_id",
            )?;
            account_text(
                &mut bytes,
                limits,
                &transformer.configuration_sha256,
                "boundary.transformer.configuration_sha256",
            )?;
        }
        Ok(bytes)
    }

    /// Validate the permitted degradation this unit declares, against the rest of
    /// the envelope rather than against itself.
    ///
    /// Each rule compares the disposition with an independent field of the same
    /// envelope — coverage, precision, completeness, or the retained handle list —
    /// and the handle comparison checks length as well as membership, because set
    /// equality alone cannot see a dropped or duplicated member. A rule that only
    /// checked the disposition for internal shape would be satisfied by a
    /// producer that wrote a disposition and nothing else.
    fn validate_disposition(
        &self,
        limits: &BoundaryValidationLimits,
        metadata_bytes: &mut usize,
    ) -> Result<(), ContextError> {
        let gaps = self.coverage.known_gaps.len();
        let legacy = self.completeness == BoundaryCompleteness::UnknownLegacy;
        let Some(disposition) = &self.disposition else {
            // No permitted degradation: the unit must actually be exact. A
            // Complete/Exact envelope with no disposition is the only combination
            // that claims nothing was lost. Explicit legacy handling is exempt:
            // it already declares that nothing about it is established.
            if !legacy
                && (self.completeness != BoundaryCompleteness::Complete
                    || self.precision != BoundaryPrecision::Exact)
            {
                return Err(ContextError::MissingField("boundary.disposition"));
            }
            return Ok(());
        };
        if legacy {
            return Err(ContextError::InvalidField("boundary.disposition.legacy"));
        }
        account_text(
            metadata_bytes,
            limits,
            &disposition.reason,
            "boundary.disposition.reason",
        )?;
        account_text(
            metadata_bytes,
            limits,
            disposition.rule_evidence.as_str(),
            "boundary.disposition.rule_evidence",
        )?;

        match disposition.disposition {
            BoundaryDisposition::NarrowerExtractiveView => {
                // An extract states its losses: it must actually be degraded, and
                // it must name the members it left out. A mixed exact/degraded
                // record that calls itself Complete is exactly what this rejects.
                if self.precision == BoundaryPrecision::Exact
                    || self.completeness != BoundaryCompleteness::Incomplete
                    || gaps == 0
                    || disposition.delivered_precision != self.precision
                {
                    return Err(ContextError::InvalidField("boundary.disposition.extract"));
                }
            }
            BoundaryDisposition::WholeUnitIncompleteUnsupported => {
                if self.completeness == BoundaryCompleteness::Complete
                    || disposition.grants_launch_authority
                {
                    return Err(ContextError::WholeUnitRequired);
                }
            }
            BoundaryDisposition::RouteToCompatibleContour => {
                // Nothing was delivered here, so the unit cannot also claim to be
                // complete, and naming a contour is never authority to launch.
                if self.completeness == BoundaryCompleteness::Complete
                    || disposition.grants_launch_authority
                {
                    return Err(ContextError::InvalidField(
                        "boundary.disposition.route_authority",
                    ));
                }
            }
            BoundaryDisposition::BlockDependentDecisionOrEffect => {
                if disposition.grants_launch_authority {
                    return Err(ContextError::InvalidField(
                        "boundary.disposition.block_authority",
                    ));
                }
            }
            BoundaryDisposition::ExactHandleOnly => {
                self.validate_handle_only(disposition)?;
            }
        }
        Ok(())
    }

    /// Check a handle-only disposition against the retained handle list.
    ///
    /// The claimed handles and the retained expansion references are compared by
    /// length as well as membership, because two copies of one identity collapse
    /// in a set and a duplicate would otherwise pass unnoticed.
    fn validate_handle_only(
        &self,
        disposition: &BoundaryDispositionRecord,
    ) -> Result<(), ContextError> {
        let claimed = match &disposition.recovery {
            BoundaryRecovery::ExpansionHandles(handles) => handles.as_slice(),
            BoundaryRecovery::NonRecoverable(_) | BoundaryRecovery::Unknown => &[],
        };
        if claimed.len() != self.expansion_refs.len()
            || !claimed
                .iter()
                .all(|handle| self.expansion_refs.contains(handle))
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
        if disposition.delivered_precision != BoundaryPrecision::Exact {
            return Err(ContextError::InvalidField(
                "boundary.disposition.handle_precision",
            ));
        }
        if claimed.is_empty()
            && self.completeness == BoundaryCompleteness::Complete
            && !matches!(disposition.recovery, BoundaryRecovery::Unknown)
        {
            // No handle, yet nothing is missing and nothing is marked unknown: the
            // record would promise a reopen path it does not carry.
            return Err(ContextError::OmissionHandleInvalid);
        }
        Ok(())
    }

    fn validate_lineage_refs(
        &self,
        limits: &BoundaryValidationLimits,
        metadata_bytes: &mut usize,
    ) -> Result<(), ContextError> {
        for (field, refs) in [
            ("boundary.provenance_refs", &self.provenance_refs),
            ("boundary.disclosure_refs", &self.disclosure_refs),
            (
                "boundary.influence_closure_refs",
                &self.influence_closure_refs,
            ),
            ("boundary.omission_refs", &self.omission_refs),
            ("boundary.expansion_refs", &self.expansion_refs),
        ] {
            let mut unique = BTreeSet::new();
            for id in refs {
                if !unique.insert(id) {
                    return Err(ContextError::Duplicate(field));
                }
                account_text(metadata_bytes, limits, id.as_str(), field)?;
            }
        }
        Ok(())
    }

    fn validate_declared_coverage(
        &self,
        limits: &BoundaryValidationLimits,
        metadata_bytes: &mut usize,
    ) -> Result<(), ContextError> {
        let BoundaryDenominator::Declared(members) = &self.coverage.denominator else {
            return Err(ContextError::InvalidField("boundary.denominator"));
        };
        let declared = self.validate_declared_members(members, limits, metadata_bytes)?;

        let mut retained = BTreeSet::new();
        let mut prior_index = None;
        for id in &self.coverage.retained_members {
            if !retained.insert(id) {
                return Err(ContextError::Duplicate("boundary.retained_members"));
            }
            let member = declared.get(id).ok_or(ContextError::DenominatorMismatch)?;
            let order = member.order;
            if prior_index.is_some_and(|previous| order <= previous) {
                return Err(ContextError::InvalidField("boundary.retained_order"));
            }
            prior_index = Some(order);
            account_text(
                metadata_bytes,
                limits,
                id.as_str(),
                "boundary.retained_member",
            )?;
        }

        let mut gaps = BTreeSet::new();
        for gap in &self.coverage.known_gaps {
            if !gaps.insert(&gap.member_id) {
                return Err(ContextError::Duplicate("boundary.known_gaps"));
            }
            if !declared.contains_key(&gap.member_id) || retained.contains(&gap.member_id) {
                return Err(ContextError::DenominatorMismatch);
            }
            account_text(
                metadata_bytes,
                limits,
                gap.member_id.as_str(),
                "boundary.gap.member_id",
            )?;
        }
        if retained
            .len()
            .checked_add(gaps.len())
            .ok_or(ContextError::Overflow)?
            != declared.len()
        {
            return Err(ContextError::DenominatorMismatch);
        }

        self.validate_source_and_completeness(members, retained.len(), gaps.len())?;
        self.validate_unit_kind(members)
    }

    fn validate_declared_members<'a>(
        &self,
        members: &'a [BoundaryMember],
        limits: &BoundaryValidationLimits,
        metadata_bytes: &mut usize,
    ) -> Result<BTreeMap<ArtifactId, &'a BoundaryMember>, ContextError> {
        let mut declared = BTreeMap::new();
        let mut last_order = None;
        for member in members {
            if last_order.is_some_and(|previous| member.order <= previous) {
                return Err(ContextError::InvalidField("boundary.member_order"));
            }
            last_order = Some(member.order);
            let id = member.reference.identity();
            if declared.insert(id.clone(), member).is_some() {
                return Err(ContextError::Duplicate("boundary.declared_members"));
            }
            account_text(metadata_bytes, limits, id.as_str(), "boundary.member_id")?;
            if let BoundaryMemberReference::SourceMember {
                range: Some(range), ..
            } = &member.reference
            {
                account_text(
                    metadata_bytes,
                    limits,
                    range.snapshot_id.as_str(),
                    "boundary.range.snapshot_id",
                )?;
                account_text(
                    metadata_bytes,
                    limits,
                    &range.source_revision,
                    "boundary.range.source_revision",
                )?;
                let source = self
                    .source
                    .as_ref()
                    .ok_or(ContextError::MissingField("boundary.source_for_range"))?;
                range.validate(source)?;
            }
            Self::validate_member_role(member)?;
        }
        Ok(declared)
    }

    fn validate_source_and_completeness(
        &self,
        members: &[BoundaryMember],
        retained_count: usize,
        gap_count: usize,
    ) -> Result<(), ContextError> {
        let child_only_composite = !members.is_empty()
            && matches!(
                self.unit_kind,
                BoundaryUnitKind::Batch
                    | BoundaryUnitKind::CallResultPair
                    | BoundaryUnitKind::EvidenceEdge
            )
            && members.iter().all(|member| {
                matches!(&member.reference, BoundaryMemberReference::ChildUnit { .. })
            });
        if self.precision == BoundaryPrecision::Exact {
            if child_only_composite {
                if self.source.is_some()
                    || self.source_attempt_id.is_some()
                    || self.source_stage.is_some()
                    || self.source_order.is_some()
                {
                    return Err(ContextError::InvalidField(
                        "boundary.composite_parent_has_source_origin",
                    ));
                }
            } else if self.source.is_none()
                || self.source_attempt_id.is_none()
                || self.source_stage.is_none()
                || self.source_order.is_none()
            {
                return Err(ContextError::WholeUnitRequired);
            }
        }

        match self.completeness {
            BoundaryCompleteness::Complete => {
                if self.precision != BoundaryPrecision::Exact
                    || gap_count != 0
                    || retained_count != members.len()
                {
                    return Err(ContextError::WholeUnitRequired);
                }
            }
            BoundaryCompleteness::Incomplete => {
                // `Incomplete` promises that one or more declared members are gaps. That
                // promise is enforced for every precision: a degraded record may still
                // carry its denominator, so zero gaps is never a checkable incompleteness.
                if gap_count == 0 {
                    return Err(ContextError::InvalidField(
                        "boundary.incomplete_without_gap",
                    ));
                }
            }
            BoundaryCompleteness::UnknownLegacy => {
                return Err(ContextError::InvalidField("boundary.unknown_legacy_status"));
            }
        }

        Ok(())
    }

    fn validate_unit_kind(&self, members: &[BoundaryMember]) -> Result<(), ContextError> {
        match self.unit_kind {
            BoundaryUnitKind::Unit => {
                if members.iter().any(|member| {
                    !matches!(
                        member.role,
                        BoundaryMemberRole::SourceMember | BoundaryMemberRole::ChildUnit
                    )
                }) {
                    return Err(ContextError::InvalidField("boundary.unit.member_role"));
                }
            }
            BoundaryUnitKind::ContiguousExtract => {
                if members.is_empty() {
                    return Err(ContextError::InvalidField(
                        "boundary.contiguous_extract.empty",
                    ));
                }
                let mut previous: Option<&ExactSourceRange> = None;
                for member in members {
                    let BoundaryMemberReference::SourceMember {
                        range: Some(range), ..
                    } = &member.reference
                    else {
                        return Err(ContextError::InvalidField("boundary.contiguous_extract"));
                    };
                    if member.role != BoundaryMemberRole::SourceMember {
                        return Err(ContextError::InvalidField(
                            "boundary.contiguous_extract.role",
                        ));
                    }
                    if let Some(prior) = previous
                        && (prior.end_exclusive != range.start
                            || prior.coordinate_system != range.coordinate_system
                            || prior.snapshot_id != range.snapshot_id
                            || prior.source_revision != range.source_revision)
                    {
                        return Err(ContextError::InvalidField(
                            "boundary.contiguous_extract.sequence",
                        ));
                    }
                    previous = Some(range);
                }
            }
            BoundaryUnitKind::Batch => {
                if members.is_empty()
                    || self.source.is_some()
                    || self.source_attempt_id.is_some()
                    || self.source_stage.is_some()
                    || self.source_order.is_some()
                    || members.iter().any(|member| {
                        member.role != BoundaryMemberRole::ChildUnit
                            || !matches!(
                                &member.reference,
                                BoundaryMemberReference::ChildUnit { .. }
                            )
                    })
                {
                    return Err(ContextError::InvalidField("boundary.batch.child_members"));
                }
            }
            BoundaryUnitKind::CallResultPair => {
                if members.len() != 2
                    || members[0].role != BoundaryMemberRole::Call
                    || members[1].role != BoundaryMemberRole::Result
                    || members.iter().any(|member| {
                        !matches!(&member.reference, BoundaryMemberReference::ChildUnit { .. })
                    })
                {
                    return Err(ContextError::WholeUnitRequired);
                }
            }
            BoundaryUnitKind::EvidenceEdge => {
                if members.len() != 3
                    || members[0].role != BoundaryMemberRole::EvidenceSource
                    || members[1].role != BoundaryMemberRole::EvidenceRelation
                    || members[2].role != BoundaryMemberRole::EvidenceTarget
                {
                    return Err(ContextError::WholeUnitRequired);
                }
            }
        }
        Ok(())
    }

    fn validate_member_role(member: &BoundaryMember) -> Result<(), ContextError> {
        let reference_is_child =
            matches!(&member.reference, BoundaryMemberReference::ChildUnit { .. });
        let valid = match member.role {
            BoundaryMemberRole::SourceMember => !reference_is_child,
            BoundaryMemberRole::ChildUnit
            | BoundaryMemberRole::Call
            | BoundaryMemberRole::Result => reference_is_child,
            BoundaryMemberRole::EvidenceSource
            | BoundaryMemberRole::EvidenceRelation
            | BoundaryMemberRole::EvidenceTarget => true,
        };
        if valid {
            Ok(())
        } else {
            Err(ContextError::InvalidField("boundary.member_role_reference"))
        }
    }

    /// Retained member identities, or `None` when no denominator is declared.
    fn retained_member_ids(&self) -> Option<BTreeSet<ArtifactId>> {
        if matches!(
            self.coverage.denominator,
            BoundaryDenominator::UnknownLegacy
        ) {
            return None;
        }
        Some(self.coverage.retained_members.iter().cloned().collect())
    }
}

/// How one output member of a transform was produced from one input member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BoundaryMemberOrigin {
    /// The single contributing input member is carried into the output unchanged.
    Retained,
    /// The output member was produced from this input member.
    Derived,
}

/// One exact input-to-output member relation emitted by one transform.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryMemberRelation {
    /// Unit that supplied the input member.
    pub input_unit_id: ArtifactId,
    /// Declared and retained member of the input unit.
    pub input_member_id: ArtifactId,
    /// Declared and retained member of the output unit.
    pub output_member_id: ArtifactId,
    /// Whether the input member is carried through or synthesized.
    pub origin: BoundaryMemberOrigin,
}

/// One membership-changing transform and the member relation it emitted.
///
/// The transformer revision repeats the exact configuration of the transform that
/// produced the output unit, so a relation cannot bind an output to a configuration
/// other than the one its own envelope declares.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryTransformRelation {
    /// Transformer revision and configuration that produced the output unit.
    pub transformer: BoundaryTransformerRevision,
    /// Unit this transform produced; one transform application per output unit.
    pub output_unit_id: ArtifactId,
    /// Every contributing input member for every retained output member.
    pub member_relations: Vec<BoundaryMemberRelation>,
}

/// A finite collection of per-unit envelopes, including referenced children.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryMetadataSet {
    /// Envelopes indexed by their stable unit identities.
    pub units: Vec<BoundaryMetadataEnvelope>,
    /// Exact input-to-output member relation for every declared transform.
    pub transforms: Vec<BoundaryTransformRelation>,
    /// Recorded digest over the canonical envelope and member-relation payload.
    ///
    /// This is the ORIGINAL recorded value. `validate()` compares it against the
    /// digest recomputed from the payload actually held, so substituted boundaries,
    /// reordered members or same-identity changed content are rejected even when
    /// each object would still validate on its own.
    pub boundary_digest: String,
}

#[derive(Serialize)]
struct CanonicalBoundaryPayload<'a> {
    schema_version: ContractVersion,
    units: &'a [BoundaryMetadataEnvelope],
    transforms: &'a [BoundaryTransformRelation],
}

impl BoundaryMetadataSet {
    fn canonical_payload(&self) -> CanonicalBoundaryPayload<'_> {
        CanonicalBoundaryPayload {
            schema_version: BOUNDARY_METADATA_SCHEMA_REVISION,
            units: &self.units,
            transforms: &self.transforms,
        }
    }

    /// Canonical representation digest over envelopes and ordered member relations.
    pub fn canonical_digest(&self) -> Result<String, ContextError> {
        let bytes = canonical_json_bytes(&self.canonical_payload())
            .map_err(|_| ContextError::InvalidField("boundary.canonical_payload"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Canonical wire bytes for this set, used when a container packs it.
    ///
    /// These bytes carry the envelopes and the ordered member relations and
    /// nothing else, so byte transport chunking stays separate from logical
    /// segmentation: reassembling the exact bytes restores the exact units.
    pub fn pack(&self) -> Result<Vec<u8>, ContextError> {
        canonical_json_bytes(self).map_err(|_| ContextError::InvalidField("boundary.pack_payload"))
    }

    /// Reassemble a packed set from canonical wire bytes and validate it.
    ///
    /// This restores the exact units a container packed and proves nothing was
    /// lost in transport. It deliberately does NOT certify identity on its own:
    /// a `boundary_digest` travelling inside the same bytes is a second copy of
    /// the same producer's claim, so a consumer checks the reassembled payload
    /// against the separately recorded binding value, which incorporates the
    /// upstream admission receipt digest.
    pub fn unpack(bytes: &[u8], limits: &BoundaryValidationLimits) -> Result<Self, ContextError> {
        limits.validate()?;
        let reconstructed: Self = serde_json::from_slice(bytes)
            .map_err(|_| ContextError::InvalidField("boundary.unpack_payload"))?;
        reconstructed.validate(limits)?;
        Ok(reconstructed)
    }

    /// Exact UTF-8 byte length of the canonical boundary payload.
    ///
    /// Boundary metadata is accounted in the same units as the rendered payload,
    /// so a caller can add it to final byte/token accounting rather than dropping
    /// it outside the measured surface.
    pub fn canonical_utf8_bytes(&self) -> Result<u64, ContextError> {
        let bytes = canonical_json_bytes(&self.canonical_payload())
            .map_err(|_| ContextError::InvalidField("boundary.canonical_payload"))?;
        u64::try_from(bytes.len()).map_err(|_| ContextError::Overflow)
    }

    /// Record the canonical digest over the payload held, once, at production.
    ///
    /// The digest is not part of the payload it covers, so a producer binds it here
    /// instead of restating the payload shape at every call site.
    pub fn bind_recorded_digest(mut self) -> Result<Self, ContextError> {
        self.boundary_digest = self.canonical_digest()?;
        Ok(self)
    }

    /// Compare the recorded digest against the payload actually held.
    fn validate_digest_binding(&self) -> Result<(), ContextError> {
        validate_digest(&self.boundary_digest, "boundary.boundary_digest")?;
        if self.boundary_digest != self.canonical_digest()? {
            return Err(ContextError::SelectionIntegrityMismatch);
        }
        Ok(())
    }
    /// Validate every envelope and transform in one bounded pass.
    ///
    /// A payload without a bound digest is rejected here by name, so a set can
    /// never be read as one that carries no boundary identity at all.
    fn validate_bound_digest(&self) -> Result<(), ContextError> {
        if self.boundary_digest.is_empty() {
            return Err(ContextError::MissingField("boundary.boundary_digest"));
        }
        self.validate_digest_binding()
    }
}

impl BoundaryMetadataSet {
    /// Validate all envelopes and the complete bounded, acyclic child graph.
    pub fn validate(&self, limits: &BoundaryValidationLimits) -> Result<(), ContextError> {
        limits.validate()?;
        if self.units.len() > limits.max_units {
            return Err(ContextError::Bounds {
                field: "boundary.units",
            });
        }
        let mut indices = BTreeMap::new();
        let mut total_members = 0usize;
        let mut total_metadata = 0usize;
        for (index, unit) in self.units.iter().enumerate() {
            if indices.insert(unit.unit_id.clone(), index).is_some() {
                return Err(ContextError::Duplicate("boundary.unit_ids"));
            }
            let (members, metadata) = unit.validate_local(limits)?;
            total_members = total_members
                .checked_add(members)
                .ok_or(ContextError::Overflow)?;
            if total_members > limits.max_total_members {
                return Err(ContextError::Bounds {
                    field: "boundary.total_members",
                });
            }
            total_metadata = total_metadata
                .checked_add(metadata)
                .ok_or(ContextError::Overflow)?;
            if total_metadata > limits.max_metadata_bytes {
                return Err(ContextError::Bounds {
                    field: "boundary.metadata_bytes",
                });
            }
        }

        self.validate_transforms(&indices, limits, &mut total_members, &mut total_metadata)?;
        self.validate_child_graph(&indices, limits)?;
        self.validate_bound_digest()
    }

    /// Validate the bounded, acyclic child-reference graph over the whole set.
    fn validate_child_graph(
        &self,
        indices: &BTreeMap<ArtifactId, usize>,
        limits: &BoundaryValidationLimits,
    ) -> Result<(), ContextError> {
        let mut edges = vec![Vec::new(); self.units.len()];
        let mut indegree = vec![0usize; self.units.len()];
        for (parent, unit) in self.units.iter().enumerate() {
            let BoundaryDenominator::Declared(members) = &unit.coverage.denominator else {
                continue;
            };
            let retained: BTreeSet<_> = unit.coverage.retained_members.iter().collect();
            for member in members {
                let BoundaryMemberReference::ChildUnit { unit_id } = &member.reference else {
                    continue;
                };
                if !retained.contains(unit_id) {
                    continue;
                }
                let child = *indices
                    .get(unit_id)
                    .ok_or(ContextError::MissingField("boundary.child_envelope"))?;
                if unit.completeness == BoundaryCompleteness::Complete
                    && unit.precision == BoundaryPrecision::Exact
                    && (self.units[child].completeness != BoundaryCompleteness::Complete
                        || self.units[child].precision != BoundaryPrecision::Exact)
                {
                    return Err(ContextError::WholeUnitRequired);
                }
                edges[parent].push(child);
                indegree[child] = indegree[child]
                    .checked_add(1)
                    .ok_or(ContextError::Overflow)?;
            }
        }

        let mut ready = VecDeque::new();
        for (index, degree) in indegree.iter().enumerate() {
            if *degree == 0 {
                ready.push_back(index);
            }
        }
        let mut topological = Vec::with_capacity(self.units.len());
        while let Some(parent) = ready.pop_front() {
            topological.push(parent);
            for child in &edges[parent] {
                indegree[*child] -= 1;
                if indegree[*child] == 0 {
                    ready.push_back(*child);
                }
            }
        }
        if topological.len() != self.units.len() {
            return Err(ContextError::IdentityConflict);
        }
        let mut height = vec![1usize; self.units.len()];
        for parent in topological.into_iter().rev() {
            for child in &edges[parent] {
                height[parent] = height[parent].max(
                    height[*child]
                        .checked_add(1)
                        .ok_or(ContextError::Overflow)?,
                );
            }
            if height[parent] > limits.max_depth {
                return Err(ContextError::Bounds {
                    field: "boundary.child_depth",
                });
            }
        }
        Ok(())
    }

    /// Validate the exact input-to-output member relation of every declared transform.
    ///
    /// The relation is checked against the units themselves, not against a second
    /// caller-supplied list: every contributing member must be a declared, retained
    /// member of a retained input envelope, and every retained output member must
    /// name its inputs. One input member may be claimed as `Retained` by at most one
    /// output member, so equal content from two sources keeps two provenance
    /// relations instead of collapsing into one.
    fn validate_transforms(
        &self,
        indices: &BTreeMap<ArtifactId, usize>,
        limits: &BoundaryValidationLimits,
        total_members: &mut usize,
        metadata_bytes: &mut usize,
    ) -> Result<(), ContextError> {
        if self.transforms.len() > limits.max_units {
            return Err(ContextError::Bounds {
                field: "boundary.transforms",
            });
        }
        let mut outputs = BTreeSet::new();
        for transform in &self.transforms {
            if !outputs.insert(transform.output_unit_id.clone()) {
                return Err(ContextError::Duplicate("boundary.transform_outputs"));
            }
            let output = &self.units[*indices.get(&transform.output_unit_id).ok_or(
                ContextError::MissingField("boundary.transform_output_envelope"),
            )?];
            if output.transformer.as_ref() != Some(&transform.transformer) {
                return Err(ContextError::IdentityConflict);
            }
            let output_members = output
                .retained_member_ids()
                .ok_or(ContextError::InvalidField(
                    "boundary.transform_output_coverage",
                ))?;
            if transform.member_relations.len() > limits.max_members_per_unit {
                return Err(ContextError::Bounds {
                    field: "boundary.transform_members",
                });
            }
            *total_members = total_members
                .checked_add(transform.member_relations.len())
                .ok_or(ContextError::Overflow)?;
            if *total_members > limits.max_total_members {
                return Err(ContextError::Bounds {
                    field: "boundary.total_members",
                });
            }
            account_text(
                metadata_bytes,
                limits,
                &transform.transformer.transformer_id,
                "boundary.transformer_id",
            )?;
            account_text(
                metadata_bytes,
                limits,
                &transform.transformer.configuration_sha256,
                "boundary.transformer.configuration_sha256",
            )?;
            self.validate_member_relations(
                transform,
                indices,
                limits,
                &output_members,
                metadata_bytes,
            )?;
        }
        Ok(())
    }

    /// Validate one transform's member relation against the units it names.
    fn validate_member_relations(
        &self,
        transform: &BoundaryTransformRelation,
        indices: &BTreeMap<ArtifactId, usize>,
        limits: &BoundaryValidationLimits,
        output_members: &BTreeSet<ArtifactId>,
        metadata_bytes: &mut usize,
    ) -> Result<(), ContextError> {
        let mut related = BTreeSet::new();
        let mut retained_origins: BTreeMap<&ArtifactId, usize> = BTreeMap::new();
        let mut claimed = BTreeSet::new();
        for relation in &transform.member_relations {
            if !output_members.contains(&relation.output_member_id) {
                return Err(ContextError::DenominatorMismatch);
            }
            let input = &self.units[*indices.get(&relation.input_unit_id).ok_or(
                ContextError::MissingField("boundary.transform_input_envelope"),
            )?];
            if !input
                .retained_member_ids()
                .ok_or(ContextError::InvalidField(
                    "boundary.transform_input_coverage",
                ))?
                .contains(&relation.input_member_id)
            {
                return Err(ContextError::DenominatorMismatch);
            }
            if !claimed.insert((
                relation.input_unit_id.clone(),
                relation.input_member_id.clone(),
                relation.output_member_id.clone(),
            )) {
                return Err(ContextError::Duplicate("boundary.transform_relations"));
            }
            if relation.origin == BoundaryMemberOrigin::Retained {
                *retained_origins
                    .entry(&relation.output_member_id)
                    .or_insert(0) += 1;
            }
            related.insert(relation.output_member_id.clone());
            account_text(
                metadata_bytes,
                limits,
                relation.input_unit_id.as_str(),
                "boundary.transform_input_unit",
            )?;
            account_text(
                metadata_bytes,
                limits,
                relation.input_member_id.as_str(),
                "boundary.transform_input_member",
            )?;
            account_text(
                metadata_bytes,
                limits,
                relation.output_member_id.as_str(),
                "boundary.transform_output_member",
            )?;
        }
        if related.len() != output_members.len()
            || retained_origins.values().any(|count| *count != 1)
        {
            return Err(ContextError::DenominatorMismatch);
        }
        Ok(())
    }
}

fn account_text(
    total: &mut usize,
    limits: &BoundaryValidationLimits,
    value: &str,
    field: &'static str,
) -> Result<(), ContextError> {
    validate_text(value, field)?;
    *total = total
        .checked_add(value.len())
        .ok_or(ContextError::Overflow)?;
    if *total > limits.max_metadata_bytes {
        return Err(ContextError::Bounds {
            field: "boundary.metadata_bytes",
        });
    }
    Ok(())
}
