//! Pure memory ecology and gravity assessment over bounded projections.
//!
//! [`assess_quality`] maps one owner [`MemoryProjectionBatch`], the owner
//! [`ApplicableMemorySet`] verdict over that batch, one admitted
//! [`CanonicalProjectionSet`], and advisory [`HarnessActivationReceiptCandidate`]
//! handles into a [`MemoryEcologyAssessment`] with gravity, maintenance, and
//! counter-metric sections. The consumer is Smart-owned and pure:
//!
//! - it never queries storage and never expands the read set; the batch it
//!   receives is the entire denominator it may consider;
//! - selection and applicability owners retain authority: the batch binding,
//!   the set verdict, and every projection/receipt binding are resolved and
//!   verified here, and bare caller handles or structural digests are never
//!   promoted to accepted facts;
//! - canonical identity comes from the batch record, never from the repeated
//!   fields of the caller-supplied verdict: `kind`, `roles`, and
//!   `projection_revision` are derived from the [`MemoryProjectionRecord`];
//!   the set contributes only the verdict, the substantive reason, and the
//!   advisory cue flag. `projection_revision` travels as the owner currency
//!   assertion it is: carried and echoed, never independently established
//!   here, so this result is not advertised as a current canonical view;
//! - no score, rank, similarity, retrieval count, or model judgment is read
//!   or emitted, because no frozen contract carries one; gravity and
//!   maintenance sections are per-record advisory dispositions with exact
//!   identities, never an aggregate scalar;
//! - low use never reduces support and retrieval never reinforces it: gravity
//!   marks narrowing or suppression *candidates* and preservation notes, never
//!   deletion, lifecycle transition, or support promotion (A14.4);
//! - receipt candidates are advisory only: each contributes a bound
//!   [`ReceiptObservation`] (identity, member denominator, stage/metric
//!   volume, digest lineage), never a merged verdict; observed counts never
//!   substitute for the batch denominator, and no observation proves use,
//!   decision delta, or benefit;
//! - coverage is explicit, never a bare count: the request and assessment
//!   carry the exact read receipt, canonical source-batch digest, and named
//!   missing owner alongside a closed [`CoverageStatus`], the exact truncation
//!   frontier, the named batch omissions, and the admitted projection
//!   omissions. A `Complete` result exists only for lossless, fully accounted
//!   coverage; anything else is `Inconclusive` with the exact evidence needed
//!   for recheck;
//! - assessment order is deterministic input order; counter-metric rule
//!   counts are sorted by rule name.
//!
//! Failures are typed errors, never silent drops. [`MemoryEcologyAssessment`]
//! serializes self-validating evidence: version, known denominator bound to
//! the metric total, recomputed applicability/rule counts, closed rule names,
//! deterministic ordering, and coverage/status invariants are all rechecked
//! by [`MemoryEcologyAssessment::validate`].

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    CanonicalProjectionSet, ContextBinding, ContextError, OmissionRecord,
};
use eliot_contracts::{ArtifactId, ContractVersion, SourceId, fences_match_exact};
use eliot_evidence::LifecycleState;
use eliot_learning_contracts::identity::validate_digest as validate_learning_digest;
use eliot_memory_projection_contracts::{
    ApplicableMemorySet, CoverageOmission, DenominatorState, ExclusionReason, FreshnessState,
    MemoryKind, MemoryProjectionBatch, MemoryProjectionError, MemoryRole, MemoryScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-exported so consumers name the advisory receipt and denominator types
// without depending on the learning owner crate directly.
use eliot_learning_contracts::LearningContractError;
pub use eliot_learning_contracts::{HarnessActivationReceiptCandidate, SourceDenominator};

/// Stable wire name for this consumer contract family.
pub const QUALITY_CONTRACT_NAME: &str = "eliot.smart.memory-quality";
/// Current wire revision for this consumer contract family.
///
/// Exact equality only: an assessment written against any other revision is
/// rejected with [`QualityError::VersionMismatch`].
pub const QUALITY_CONTRACT_VERSION: ContractVersion = ContractVersion::new(0, 1, 0);
/// Freeze identity this consumer package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const CONSUMED_FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r6";

/// Fail closed unless this package builds against the delivered r6 freeze.
fn check_consumed_freeze() -> Result<(), QualityError> {
    if CONSUMED_FREEZE_ID != "cognitive-rev12-contract-schema-freeze-2026-09-22-r6" {
        return Err(QualityError::VersionMismatch);
    }
    Ok(())
}
/// Hard ceiling on advisory receipt candidates carried by one request.
pub const MAX_QUALITY_RECEIPTS: usize = 64;

/// Closed coverage posture of one assessment.
///
/// `Complete` is bound to lossless, fully accounted evidence by
/// [`MemoryEcologyAssessment::validate`]: no truncation, no batch or
/// projection omissions, an empty frontier, and a denominator total exactly
/// equal to the assessed records. Any truncation, omission, or unaccounted
/// volume yields `Inconclusive`, which carries the exact frontier and
/// omission identities needed for independent recheck.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageStatus {
    /// Lossless, fully accounted coverage with an exact denominator.
    Complete,
    /// Truncated, lossy, or partially bound evidence; recheck required.
    Inconclusive,
}

/// Assessment failure for a memory quality request.
///
/// Errors name only the failing field and the violated rule. They never echo
/// record content, digests, or scope identities.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QualityError {
    /// The supplied batch or applicability set is invalid.
    #[error("memory projection: {0}")]
    Projection(#[from] MemoryProjectionError),
    /// A supplied canonical projection is invalid.
    #[error("context projection: {0}")]
    Context(#[from] ContextError),
    /// A supplied receipt candidate is invalid.
    #[error("learning receipt: {0}")]
    Learning(#[from] LearningContractError),
    /// A required request field is absent or malformed.
    #[error("{field} is invalid: {reason}")]
    InvalidField {
        /// Field that failed validation.
        field: &'static str,
        /// Short machine-stable rule description.
        reason: &'static str,
    },
    /// Two bindings that must agree on one scope and fence disagree.
    #[error("{left} and {right} disagree on scope or state fence")]
    BindingMismatch {
        /// Left side of the comparison.
        left: &'static str,
        /// Right side of the comparison.
        right: &'static str,
    },
    /// A record names a contract version this crate cannot read.
    #[error("unsupported contract version")]
    VersionMismatch,
    /// The batch denominator is unknown: ecology without a denominator is
    /// unprovable, so assessment fails closed instead of guessing.
    #[error("cannot assess ecology without a known denominator")]
    MissingDenominator,
    /// The applicability set does not cover exactly the batch records.
    #[error("{field} is inconsistent: {reason}")]
    HandleMismatch {
        /// Field that failed the union check.
        field: &'static str,
        /// Short machine-stable rule description.
        reason: &'static str,
    },
}

fn text(value: &str, field: &'static str) -> Result<(), QualityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(QualityError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn sha256_digest(value: &str, field: &'static str) -> Result<(), QualityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(QualityError::InvalidField {
            field,
            reason: "must be 64 lowercase SHA-256 hex characters",
        });
    }
    Ok(())
}

/// Memory quality request over one bounded projection and its owner verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityRequest {
    /// Bounded projection to assess; the entire denominator.
    pub batch: MemoryProjectionBatch,
    /// Exact read receipt that produced the searched-memory state.
    pub projection_read_receipt: ArtifactId,
    /// Canonical digest of the complete source batch, including recovery state.
    pub source_batch_digest: String,
    /// Owner that prevented complete search, when applicable.
    pub missing_owner: Option<SourceId>,
    /// Owner applicability verdict over exactly this batch.
    pub applicable: ApplicableMemorySet,
    /// Admitted task/continuity/safety/affordance projections by handle.
    pub projections: CanonicalProjectionSet,
    /// Advisory receipt candidates; observed, never merged into verdicts.
    pub receipts: Vec<HarnessActivationReceiptCandidate>,
}

impl QualityRequest {
    /// Validate owner shapes, binding echoes, and the handle union.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), QualityError> {
        check_consumed_freeze()?;
        self.batch.validate()?;
        if self.source_batch_digest != self.batch.canonical_digest()? {
            return Err(QualityError::BindingMismatch {
                left: "request.source_batch_digest",
                right: "batch.canonical_digest",
            });
        }
        let DenominatorState::Known { .. } = &self.batch.coverage.denominator else {
            return Err(QualityError::MissingDenominator);
        };
        self.applicable.validate_against_batch(&self.batch)?;
        if self.applicable.binding != self.batch.binding {
            return Err(QualityError::BindingMismatch {
                left: "applicable.binding",
                right: "batch.binding",
            });
        }
        if self.applicable.denominator != self.batch.coverage.denominator
            || self.applicable.truncated != self.batch.coverage.truncated
            || self.applicable.revalidation_required != self.batch.coverage.revalidation_required
        {
            return Err(QualityError::BindingMismatch {
                left: "applicable.denominator",
                right: "batch.coverage",
            });
        }
        self.projections.validate()?;
        if self.missing_owner.is_some()
            && self.batch.coverage.omissions.is_empty()
            && self.batch.coverage.frontier.is_empty()
            && self.projections.omissions.is_empty()
        {
            return Err(QualityError::InvalidField {
                field: "request.missing_owner",
                reason: "named missing owner requires explicit recovery evidence",
            });
        }
        let projection_binding = &self.projections.binding;
        if projection_binding.task_id != self.batch.binding.task_id
            || projection_binding.scope_id != self.batch.binding.scope_id
        {
            return Err(QualityError::BindingMismatch {
                left: "projections.binding",
                right: "batch.binding",
            });
        }
        if !fences_match_exact(
            &projection_binding.state_fence,
            &self.batch.binding.state_fence,
        ) {
            return Err(QualityError::BindingMismatch {
                left: "projections.binding.state_fence",
                right: "batch.binding.state_fence",
            });
        }
        if self.receipts.len() > MAX_QUALITY_RECEIPTS {
            return Err(QualityError::InvalidField {
                field: "request.receipts",
                reason: "exceeds the advisory bound",
            });
        }
        for receipt in &self.receipts {
            receipt.validate()?;
            if receipt.binding.task_id != self.batch.binding.task_id
                || receipt.binding.scope != self.batch.binding.scope_id
            {
                return Err(QualityError::BindingMismatch {
                    left: "receipt.binding",
                    right: "batch.binding",
                });
            }
            if !fences_match_exact(
                &receipt.binding.state_fence,
                &self.batch.binding.state_fence,
            ) {
                return Err(QualityError::BindingMismatch {
                    left: "receipt.binding.state_fence",
                    right: "batch.binding.state_fence",
                });
            }
        }
        // The set verdict must cover exactly the batch records: neither a
        // bare caller handle smuggled in nor a projected record left without
        // a verdict is promoted to an accepted fact.
        let batch_handles: BTreeSet<&str> = self
            .batch
            .records
            .iter()
            .map(|record| record.handle.as_str())
            .collect();
        let mut set_handles = BTreeSet::new();
        for entry in self
            .applicable
            .applicable
            .iter()
            .map(|entry| entry.handle.as_str())
            .chain(
                self.applicable
                    .excluded
                    .iter()
                    .map(|entry| entry.handle.as_str()),
            )
        {
            if !set_handles.insert(entry) {
                return Err(QualityError::HandleMismatch {
                    field: "applicable",
                    reason: "duplicate handle across the verdict lists",
                });
            }
        }
        if set_handles != batch_handles {
            return Err(QualityError::HandleMismatch {
                field: "applicable",
                reason: "verdict handles must equal exactly the batch record handles",
            });
        }
        Ok(())
    }
}

/// One assessed record: canonical identity from the batch, verdict from the set.
///
/// `kind`, `roles`, and `projection_revision` are derived from the
/// [`MemoryProjectionRecord`], never from the repeated fields of the
/// caller-supplied verdict entry. The verdict contributes only
/// applicability, the substantive reason, and the advisory cue flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemAssessment {
    /// Exact canonical handle of the assessed record.
    pub handle: ArtifactId,
    /// Canonical kind derived from the batch record.
    pub kind: MemoryKind,
    /// Roles preserved from the batch record, never stripped.
    pub roles: Vec<MemoryRole>,
    /// Owner projection revision: currency assertion echoed, not established.
    pub projection_revision: u64,
    /// Whether the owner verdict holds this record applicable.
    pub applicable: bool,
    /// Substantive owner rule for excluded records; absent when applicable.
    pub reason: Option<ExclusionReason>,
    /// Whether cue-hit evidence named this record (advisory only).
    pub cue_hit: bool,
}

impl ItemAssessment {
    /// Validate the item shape: reason presence matches applicability.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.applicable == self.reason.is_some() {
            return Err(QualityError::InvalidField {
                field: "item.reason",
                reason: "reason must be present exactly for excluded records",
            });
        }
        if let Some(reason) = &self.reason {
            reason.validate()?;
        }
        Ok(())
    }
}

/// Closed advisory gravity dispositions for one record.
///
/// Every variant is derived from exact owner fields by identity or equality.
/// No variant scores, ranks, or promotes: each names an advisory candidate
/// (narrowing, suppression, or preservation) for the Governor disposition
/// path, which owns every transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GravityNoteKind {
    /// The record carries a negative trigger whose exact identity appears
    /// verbatim in the admitted safety projection triggers.
    SafetySurfacedNegativeTrigger,
    /// Cue-hit evidence named a record the owner verdict excludes: the cue
    /// fired and the record is still not applicable.
    CueHitButExcluded,
    /// Low-use minority evidence that stays addressable regardless of
    /// popularity; a promotion must not delete it.
    MinorityPreserved,
    /// Rival evidence a promotion must reconcile, never delete.
    CounterexamplePreserved,
    /// Protected role withheld from task-local applicability pending a
    /// governed release.
    ProtectedWithheld,
    /// The record is ineligible for downstream influence at all.
    InfluenceIneligible,
}

/// One advisory gravity note bound to an assessed record handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GravityNote {
    /// Exact canonical handle of the noted record.
    pub handle: ArtifactId,
    /// Advisory gravity disposition.
    pub kind: GravityNoteKind,
}

/// Closed maintenance dispositions for one record.
///
/// Every variant echoes an owner lifecycle, freshness, or lineage fact and
/// names the revalidation or retention posture it implies. No variant
/// deletes, transitions, or purges: history stays addressable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaintenanceNoteKind {
    /// Freshness reports a known older snapshot; `rationale` names the
    /// boundary that passed.
    StaleMaterial,
    /// Freshness cannot be established; `rationale` names what is missing.
    FreshnessUnknown,
    /// The record retains a predecessor in the immutable lineage while
    /// superseded content stays addressable as history.
    SupersededWithLineage,
    /// Lifecycle is archived: retained but not normally activated.
    LifecycleArchived,
    /// Lifecycle is quarantined: isolated pending a release condition.
    LifecycleQuarantined,
    /// Lifecycle is suppressed: temporarily held from normal activation.
    LifecycleSuppressed,
    /// Lifecycle is extinguished: logically ended while history remains
    /// addressable.
    LifecycleExtinguished,
}

/// One maintenance note bound to an assessed record handle.
///
/// `rationale` carries the exact owner freshness note for stale/unknown
/// dispositions so the stale-hit reason survives without inventing a
/// storage resolver; `source_revision` echoes the owner provenance
/// revision. No resolution or canonical retention is decided here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceNote {
    /// Exact canonical handle of the noted record.
    pub handle: ArtifactId,
    /// Maintenance disposition echoing the owner fact.
    pub kind: MaintenanceNoteKind,
    /// Predecessor handle for supersession lineage; absent otherwise.
    pub predecessor: Option<ArtifactId>,
    /// Owner freshness rationale; present exactly for stale/unknown kinds.
    pub rationale: Option<String>,
    /// Owner provenance revision echoed from the assessed record.
    pub source_revision: Option<String>,
}

impl MaintenanceNote {
    /// Validate the note shape: lineage, rationale, and revision echoes.
    pub fn validate(&self) -> Result<(), QualityError> {
        if (self.kind == MaintenanceNoteKind::SupersededWithLineage) != self.predecessor.is_some() {
            return Err(QualityError::InvalidField {
                field: "maintenance.predecessor",
                reason: "predecessor must be present exactly for supersession lineage",
            });
        }
        let needs_rationale = matches!(
            self.kind,
            MaintenanceNoteKind::StaleMaterial | MaintenanceNoteKind::FreshnessUnknown
        );
        if needs_rationale != self.rationale.is_some() {
            return Err(QualityError::InvalidField {
                field: "maintenance.rationale",
                reason: "rationale must be present exactly for stale/unknown dispositions",
            });
        }
        if let Some(rationale) = &self.rationale {
            text(rationale, "maintenance.rationale")?;
        }
        if let Some(revision) = &self.source_revision {
            text(revision, "maintenance.source_revision")?;
        }
        Ok(())
    }
}

/// One bound advisory receipt observation.
///
/// A separately bound echo of one validated receipt candidate: identity,
/// member denominator, stage/metric volume, and digest lineage. Advisory
/// only: it establishes no retrieval, use, decision delta, or benefit, and
/// its counts never substitute for the batch denominator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptObservation {
    /// Stable activation receipt identity echoed from the candidate.
    pub activation_id: ArtifactId,
    /// Member/stage denominator retained separately from observed counts.
    pub member_denominator: SourceDenominator,
    /// Stage observations carried by the candidate.
    pub stages_observed: usize,
    /// Metric observations carried by the candidate.
    pub metrics_observed: usize,
    /// Canonical receipt candidate digest echoed from the candidate.
    pub canonical_digest: String,
}

impl ReceiptObservation {
    /// Validate the observation: denominator bounds and digest shape.
    pub fn validate(&self) -> Result<(), QualityError> {
        self.member_denominator.validate()?;
        validate_learning_digest(&self.canonical_digest, "receipt.canonical_digest")?;
        Ok(())
    }
}

/// One exclusion-rule count in the counter-metric section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleCount {
    /// Closed owner rule name (e.g. `STALE`, `PRECONDITION_FAILED`).
    pub rule: String,
    /// Records excluded under this rule.
    pub count: usize,
}

/// Closed owner rule names admissible in [`RuleCount`].
///
/// The [`rule_name`] match is exhaustive over [`ExclusionReason`]; this list
/// mirrors it so serialized validation rejects invented rules without
/// relying on a silent default.
const CLOSED_RULES: [&str; 11] = [
    "CONFLICTED",
    "EPISTEMICALLY_UNKNOWN",
    "FENCE_MISMATCH",
    "LIFECYCLE_INACTIVE",
    "NEGATIVE_MEMORY",
    "PRECONDITION_FAILED",
    "PRECONDITION_UNASSESSED",
    "PROTECTED",
    "REJECTED",
    "SCOPE_MISMATCH",
    "STALE",
];

/// Exact counter-metrics with the independently recheckable denominator.
///
/// Every count reconciles exactly: the denominator total equals assessed
/// plus omitted plus unaccounted volume, applicable plus excluded equals
/// assessed, and rule counts sum to excluded. No rate, ratio, or score is
/// derived: cold-capture ratios and weak-claim rates stay proof fixtures
/// with their own horizons, not assessment fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CounterMetrics {
    /// Exact canonical records the read side observed.
    pub denominator_total: usize,
    /// Batch records assessed.
    pub records_assessed: usize,
    /// Named batch omissions carried alongside the records.
    pub omissions_carried: usize,
    /// Declared volume not represented by an assessed record or named batch
    /// omission. Deferred frontier identities are carried separately on the
    /// assessment and remain part of this residual metric until rechecked.
    pub unaccounted_volume: usize,
    /// Admitted projection omissions carried alongside the batch.
    pub projection_omissions: usize,
    /// Records the owner verdict holds applicable.
    pub applicable_count: usize,
    /// Records the owner verdict excludes.
    pub excluded_count: usize,
    /// Exclusions per closed owner rule, sorted by rule name.
    pub excluded_by_rule: Vec<RuleCount>,
    /// Gravity notes emitted.
    pub gravity_notes: usize,
    /// Maintenance notes emitted.
    pub maintenance_notes: usize,
}

impl CounterMetrics {
    /// Validate metric reconciliation and closed, ordered rule names.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.applicable_count + self.excluded_count != self.records_assessed {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "applicable plus excluded must equal assessed",
            });
        }
        if self.denominator_total
            != self.records_assessed + self.omissions_carried + self.unaccounted_volume
        {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "denominator must equal assessed plus omitted plus unaccounted volume",
            });
        }
        let mut previous: Option<&str> = None;
        for entry in &self.excluded_by_rule {
            if entry.rule.trim().is_empty() || entry.count == 0 {
                return Err(QualityError::InvalidField {
                    field: "counter_metrics.excluded_by_rule",
                    reason: "rule counts must be named and nonzero",
                });
            }
            if !CLOSED_RULES.contains(&entry.rule.as_str()) {
                return Err(QualityError::InvalidField {
                    field: "counter_metrics.excluded_by_rule",
                    reason: "rule names must be closed owner rules",
                });
            }
            if previous.is_some_and(|prior| prior >= entry.rule.as_str()) {
                return Err(QualityError::InvalidField {
                    field: "counter_metrics.excluded_by_rule",
                    reason: "rule counts must be sorted by rule name without duplicates",
                });
            }
            previous = Some(entry.rule.as_str());
        }
        Ok(())
    }
}

/// Memory ecology assessment over one bounded scope.
///
/// `status` reports the exact coverage posture: `Complete` only for
/// lossless, fully accounted evidence, `Inconclusive` otherwise with the
/// frontier and omission identities needed for recheck. The assessment
/// serializes self-validating evidence: version, known denominator bound to
/// the metric total, applicability and rule counts recomputed from `items`,
/// closed ordered rule names, and coverage/status invariants are all
/// rechecked by [`MemoryEcologyAssessment::validate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryEcologyAssessment {
    /// Contract version this assessment was written against.
    pub contract_version: ContractVersion,
    /// Exact coverage posture of this assessment.
    pub status: CoverageStatus,
    /// Read receipt echoed from the quality request.
    pub projection_read_receipt: ArtifactId,
    /// Canonical source-batch digest echoed from the quality request.
    pub source_batch_digest: String,
    /// Named owner that prevented complete search, when applicable.
    pub missing_owner: Option<SourceId>,
    /// Binding echoed from the evaluated batch.
    pub binding: MemoryScopeBinding,
    /// Binding echoed from the admitted projection set.
    pub projections_binding: ContextBinding,
    /// Denominator echoed from the evaluated batch; always known.
    pub denominator: DenominatorState,
    /// Truncation flag echoed from the evaluated batch.
    pub truncated: bool,
    /// Revalidation requirement echoed from the evaluated batch.
    pub revalidation_required: bool,
    /// Resume handles for truncated volume; echoed from the batch.
    pub frontier: Vec<String>,
    /// Named batch omissions with exact reasons; echoed from the batch.
    pub batch_omissions: Vec<CoverageOmission>,
    /// Admitted projection omissions; echoed from the projection set.
    pub projection_omissions: Vec<OmissionRecord>,
    /// Per-record verdicts in deterministic batch order.
    pub items: Vec<ItemAssessment>,
    /// Advisory gravity dispositions in deterministic record order.
    pub gravity: Vec<GravityNote>,
    /// Maintenance dispositions in deterministic record order.
    pub maintenance: Vec<MaintenanceNote>,
    /// Reconciled counter-metrics with the exact denominator.
    pub counter_metrics: CounterMetrics,
    /// Bound advisory receipt observations; observed, never merged.
    pub receipts: Vec<ReceiptObservation>,
}

impl MemoryEcologyAssessment {
    /// Validate the assessment: version, echoes, handle coverage, recomputed
    /// metrics, closed rules, and coverage/status invariants.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.contract_version != QUALITY_CONTRACT_VERSION {
            return Err(QualityError::VersionMismatch);
        }
        sha256_digest(&self.source_batch_digest, "assessment.source_batch_digest")?;
        self.binding.validate()?;
        let DenominatorState::Known { total } = &self.denominator else {
            return Err(QualityError::MissingDenominator);
        };
        if self.counter_metrics.denominator_total != *total {
            return Err(QualityError::InvalidField {
                field: "counter_metrics.denominator_total",
                reason: "metric total must equal the echoed known denominator",
            });
        }
        if self.projections_binding.task_id != self.binding.task_id
            || self.projections_binding.scope_id != self.binding.scope_id
        {
            return Err(QualityError::BindingMismatch {
                left: "projections_binding",
                right: "binding",
            });
        }
        if !fences_match_exact(
            &self.projections_binding.state_fence,
            &self.binding.state_fence,
        ) {
            return Err(QualityError::BindingMismatch {
                left: "projections_binding.state_fence",
                right: "binding.state_fence",
            });
        }
        for omission in &self.projection_omissions {
            omission.validate(&self.projections_binding)?;
        }
        let mut seen = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !seen.insert(item.handle.as_str().to_owned()) {
                return Err(QualityError::HandleMismatch {
                    field: "assessment.items",
                    reason: "item handles must be unique",
                });
            }
        }
        self.validate_section_handles(&seen)?;
        self.validate_recovery_partition(&seen)?;
        for observation in &self.receipts {
            observation.validate()?;
        }
        self.counter_metrics.validate()?;
        self.validate_section_counts()?;
        self.validate_recomputed()?;
        self.validate_status()?;
        Ok(())
    }

    /// Validate gravity/maintenance note handles against assessed items.
    fn validate_section_handles(&self, seen: &BTreeSet<String>) -> Result<(), QualityError> {
        for note in &self.gravity {
            if !seen.contains(note.handle.as_str()) {
                return Err(QualityError::HandleMismatch {
                    field: "assessment.gravity",
                    reason: "gravity notes must name assessed records",
                });
            }
        }
        for note in &self.maintenance {
            note.validate()?;
            if !seen.contains(note.handle.as_str()) {
                return Err(QualityError::HandleMismatch {
                    field: "assessment.maintenance",
                    reason: "maintenance notes must name assessed records",
                });
            }
        }
        Ok(())
    }

    /// Validate that carried recovery identities are unique, disjoint from
    /// assessed records, and exactly partition the known denominator.
    fn validate_recovery_partition(&self, assessed: &BTreeSet<String>) -> Result<(), QualityError> {
        let mut recovery = BTreeSet::new();
        for handle in &self.frontier {
            text(handle, "assessment.frontier")?;
            if !recovery.insert(handle.clone()) {
                return Err(QualityError::HandleMismatch {
                    field: "assessment.frontier",
                    reason: "frontier handles must be unique",
                });
            }
        }
        for omission in &self.batch_omissions {
            omission.validate()?;
            if !recovery.insert(omission.handle.as_str().to_owned()) {
                return Err(QualityError::HandleMismatch {
                    field: "assessment.batch_omissions",
                    reason: "batch omission handles must be unique and disjoint from the frontier",
                });
            }
        }
        if assessed.iter().any(|handle| recovery.contains(handle)) {
            return Err(QualityError::HandleMismatch {
                field: "assessment.coverage",
                reason: "recovery identities cannot overlap assessed records",
            });
        }

        let accounted = self
            .items
            .len()
            .checked_add(self.batch_omissions.len())
            .and_then(|volume| volume.checked_add(self.frontier.len()))
            .ok_or(QualityError::InvalidField {
                field: "assessment.coverage",
                reason: "recovery-accounting volume overflows",
            })?;
        let DenominatorState::Known { total } = &self.denominator else {
            return Err(QualityError::MissingDenominator);
        };
        if *total != accounted {
            return Err(QualityError::InvalidField {
                field: "assessment.coverage",
                reason: "known denominator must exactly partition items, omissions, and frontier",
            });
        }
        if self.truncated == self.frontier.is_empty() {
            return Err(QualityError::InvalidField {
                field: "assessment.truncated",
                reason: "truncation flag must exactly match frontier presence",
            });
        }
        if (self.truncated || !self.batch_omissions.is_empty()) && !self.revalidation_required {
            return Err(QualityError::InvalidField {
                field: "assessment.revalidation_required",
                reason: "lossy recovery requires revalidation",
            });
        }
        if self.counter_metrics.unaccounted_volume != self.frontier.len() {
            return Err(QualityError::InvalidField {
                field: "counter_metrics.unaccounted_volume",
                reason: "unaccounted volume must equal the carried frontier remainder",
            });
        }
        Ok(())
    }

    /// Validate metric section counts against the carried sections.
    fn validate_section_counts(&self) -> Result<(), QualityError> {
        if self.counter_metrics.records_assessed != self.items.len()
            || self.counter_metrics.omissions_carried != self.batch_omissions.len()
            || self.counter_metrics.projection_omissions != self.projection_omissions.len()
            || self.counter_metrics.gravity_notes != self.gravity.len()
            || self.counter_metrics.maintenance_notes != self.maintenance.len()
        {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "section counts must equal the carried sections",
            });
        }
        Ok(())
    }

    /// Recompute applicability and every closed rule count from items:
    /// serialized counts are re-derived, never trusted.
    fn validate_recomputed(&self) -> Result<(), QualityError> {
        let mut applicable = 0_usize;
        let mut recomputed: BTreeMap<&str, usize> = BTreeMap::new();
        for item in &self.items {
            if item.applicable {
                applicable += 1;
            } else if let Some(reason) = &item.reason {
                *recomputed.entry(rule_name(reason)).or_insert(0) += 1;
            } else {
                return Err(QualityError::InvalidField {
                    field: "assessment.items",
                    reason: "excluded records must carry a substantive reason",
                });
            }
        }
        if self.counter_metrics.applicable_count != applicable
            || self.counter_metrics.excluded_count != self.items.len() - applicable
        {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "applicability counts must equal the carried items",
            });
        }
        let expected: Vec<RuleCount> = recomputed
            .into_iter()
            .map(|(rule, count)| RuleCount {
                rule: rule.to_owned(),
                count,
            })
            .collect();
        if self.counter_metrics.excluded_by_rule != expected {
            return Err(QualityError::InvalidField {
                field: "counter_metrics.excluded_by_rule",
                reason: "rule counts must be recomputed exactly from items",
            });
        }
        Ok(())
    }

    /// Validate coverage/status invariants: Complete binds lossless, fully
    /// accounted evidence; anything else is Inconclusive.
    fn validate_status(&self) -> Result<(), QualityError> {
        if self.missing_owner.is_some()
            && self.batch_omissions.is_empty()
            && self.frontier.is_empty()
            && self.projection_omissions.is_empty()
        {
            return Err(QualityError::InvalidField {
                field: "assessment.missing_owner",
                reason: "named missing owner requires explicit recovery evidence",
            });
        }
        let lossy = self.truncated
            || !self.batch_omissions.is_empty()
            || !self.projection_omissions.is_empty()
            || self.missing_owner.is_some()
            || self.counter_metrics.unaccounted_volume != 0;
        if self.status == CoverageStatus::Complete
            && (lossy
                || !self.frontier.is_empty()
                || self.counter_metrics.denominator_total != self.items.len())
        {
            return Err(QualityError::InvalidField {
                field: "assessment.status",
                reason: "complete requires lossless fully-accounted coverage",
            });
        }
        Ok(())
    }
}

/// Closed owner rule name for one exclusion reason.
///
/// The match is exhaustive on purpose: a new owner rule must receive a
/// conscious name here, never a silent default.
fn rule_name(reason: &ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::Stale => "STALE",
        ExclusionReason::Conflicted => "CONFLICTED",
        ExclusionReason::Rejected => "REJECTED",
        ExclusionReason::EpistemicallyUnknown => "EPISTEMICALLY_UNKNOWN",
        ExclusionReason::Protected => "PROTECTED",
        ExclusionReason::NegativeMemory => "NEGATIVE_MEMORY",
        ExclusionReason::PreconditionFailed { .. } => "PRECONDITION_FAILED",
        ExclusionReason::PreconditionUnassessed { .. } => "PRECONDITION_UNASSESSED",
        ExclusionReason::LifecycleInactive => "LIFECYCLE_INACTIVE",
        ExclusionReason::FenceMismatch => "FENCE_MISMATCH",
        ExclusionReason::ScopeMismatch => "SCOPE_MISMATCH",
    }
}

/// Derive advisory gravity notes for one record.
///
/// Every note is an identity or equality join over exact owner fields.
/// Semantic similarity never creates a note.
fn gravity_for(
    handle: &ArtifactId,
    applicable: bool,
    cue_hit: bool,
    record: &eliot_memory_projection_contracts::MemoryProjectionRecord,
    safety_triggers: &BTreeSet<&str>,
    out: &mut Vec<GravityNote>,
) {
    if record
        .negative_trigger
        .as_ref()
        .is_some_and(|trigger| safety_triggers.contains(trigger.trigger.as_str()))
    {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::SafetySurfacedNegativeTrigger,
        });
    }
    if cue_hit && !applicable {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::CueHitButExcluded,
        });
    }
    if record.roles.contains(&MemoryRole::Minority) {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::MinorityPreserved,
        });
    }
    if record.roles.contains(&MemoryRole::Counterexample) {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::CounterexamplePreserved,
        });
    }
    if record.roles.contains(&MemoryRole::Protected) {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::ProtectedWithheld,
        });
    }
    if !record.influence_eligible {
        out.push(GravityNote {
            handle: handle.clone(),
            kind: GravityNoteKind::InfluenceIneligible,
        });
    }
}

/// Derive maintenance notes for one record from owner lifecycle facts.
///
/// Stale/unknown dispositions retain the exact owner freshness rationale;
/// the owner provenance revision travels as the retention reference. No
/// storage resolver is invented: resolvability stays an owner boundary.
fn maintenance_for(
    handle: &ArtifactId,
    record: &eliot_memory_projection_contracts::MemoryProjectionRecord,
    out: &mut Vec<MaintenanceNote>,
) {
    match record.freshness.state {
        FreshnessState::Stale => out.push(MaintenanceNote {
            handle: handle.clone(),
            kind: MaintenanceNoteKind::StaleMaterial,
            predecessor: None,
            rationale: Some(record.freshness.note.clone()),
            source_revision: record.provenance.revision.clone(),
        }),
        FreshnessState::Unknown => out.push(MaintenanceNote {
            handle: handle.clone(),
            kind: MaintenanceNoteKind::FreshnessUnknown,
            predecessor: None,
            rationale: Some(record.freshness.note.clone()),
            source_revision: record.provenance.revision.clone(),
        }),
        FreshnessState::Current => {}
    }
    if let Some(predecessor) = &record.predecessor {
        out.push(MaintenanceNote {
            handle: handle.clone(),
            kind: MaintenanceNoteKind::SupersededWithLineage,
            predecessor: Some(predecessor.clone()),
            rationale: None,
            source_revision: record.provenance.revision.clone(),
        });
    }
    let lifecycle_note = match record.lifecycle {
        LifecycleState::Active => None,
        LifecycleState::Archived => Some(MaintenanceNoteKind::LifecycleArchived),
        LifecycleState::Quarantined => Some(MaintenanceNoteKind::LifecycleQuarantined),
        LifecycleState::Suppressed => Some(MaintenanceNoteKind::LifecycleSuppressed),
        LifecycleState::Extinguished => Some(MaintenanceNoteKind::LifecycleExtinguished),
    };
    if let Some(kind) = lifecycle_note {
        out.push(MaintenanceNote {
            handle: handle.clone(),
            kind,
            predecessor: None,
            rationale: None,
            source_revision: record.provenance.revision.clone(),
        });
    }
}

/// Derived per-record sections: items, gravity, maintenance, and rule counts.
type DerivedSections = (
    Vec<ItemAssessment>,
    Vec<GravityNote>,
    Vec<MaintenanceNote>,
    BTreeMap<&'static str, usize>,
);

/// Derive per-record items, gravity, and maintenance sections.
///
/// Canonical identity (`kind`, `roles`, `projection_revision`) is joined
/// from the batch records; the verdict map contributes only applicability,
/// the substantive reason, and the advisory cue flag.
fn derive_sections(
    request: &QualityRequest,
    verdicts: &BTreeMap<&str, (Option<&ExclusionReason>, bool)>,
) -> Result<DerivedSections, QualityError> {
    let safety_triggers: BTreeSet<&str> = request
        .projections
        .safety
        .negative_memory_triggers
        .iter()
        .map(String::as_str)
        .collect();
    let mut items = Vec::with_capacity(request.batch.records.len());
    let mut gravity = Vec::new();
    let mut maintenance = Vec::new();
    let mut rules: BTreeMap<&'static str, usize> = BTreeMap::new();
    for record in &request.batch.records {
        let Some((reason, cue_hit)) = verdicts.get(record.handle.as_str()) else {
            // Unreachable: validate() enforces the exact handle union.
            return Err(QualityError::HandleMismatch {
                field: "applicable",
                reason: "verdict handles must equal exactly the batch record handles",
            });
        };
        let applicable = reason.is_none();
        items.push(ItemAssessment {
            handle: record.handle.clone(),
            kind: record.kind,
            roles: record.roles.clone(),
            projection_revision: record.projection_revision,
            applicable,
            reason: reason.cloned(),
            cue_hit: *cue_hit,
        });
        if let Some(exclusion) = reason {
            *rules.entry(rule_name(exclusion)).or_insert(0) += 1;
        }
        gravity_for(
            &record.handle,
            applicable,
            *cue_hit,
            record,
            &safety_triggers,
            &mut gravity,
        );
        maintenance_for(&record.handle, record, &mut maintenance);
    }
    Ok((items, gravity, maintenance, rules))
}

/// Assess memory ecology over one bounded projection and its owner verdict.
///
/// The request is validated and canonical identity is joined from the batch
/// records while the verdict contributes only applicability, reason, and
/// cue flag. A known denominator is required; coverage then decides the
/// posture: lossless, fully accounted evidence yields `Complete`, anything
/// truncated, omitted, or unaccounted yields `Inconclusive` carrying the
/// exact frontier and omission identities. Receipt candidates become bound
/// advisory observations, never merged verdicts.
pub fn assess_quality(request: &QualityRequest) -> Result<MemoryEcologyAssessment, QualityError> {
    request.validate()?;
    let DenominatorState::Known { total } = &request.batch.coverage.denominator else {
        return Err(QualityError::MissingDenominator);
    };
    let mut verdicts: BTreeMap<&str, (Option<&ExclusionReason>, bool)> = BTreeMap::new();
    for entry in &request.applicable.applicable {
        verdicts.insert(entry.handle.as_str(), (None, entry.cue_hit));
    }
    for entry in &request.applicable.excluded {
        verdicts.insert(entry.handle.as_str(), (Some(&entry.reason), entry.cue_hit));
    }
    let (items, gravity, maintenance, rules) = derive_sections(request, &verdicts)?;
    // The exact batch owner has already checked projected + omitted +
    // frontier = total. The quality counter schema has no frontier slot, so
    // its residual intentionally includes the deferred frontier volume; the
    // exact identities remain on the batch/assessment for recheck.
    let unaccounted_volume =
        total.saturating_sub(request.batch.records.len() + request.batch.coverage.omissions.len());
    let lossy = request.batch.coverage.truncated
        || !request.batch.coverage.omissions.is_empty()
        || !request.projections.omissions.is_empty()
        || request.missing_owner.is_some()
        || unaccounted_volume != 0;
    let receipts = request
        .receipts
        .iter()
        .map(|receipt| ReceiptObservation {
            activation_id: receipt.activation_id.clone(),
            member_denominator: receipt.member_denominator,
            stages_observed: receipt.stages.len(),
            metrics_observed: receipt.metrics.len(),
            canonical_digest: receipt.canonical_digest.clone(),
        })
        .collect();
    let assessment = MemoryEcologyAssessment {
        contract_version: QUALITY_CONTRACT_VERSION,
        status: if lossy {
            CoverageStatus::Inconclusive
        } else {
            CoverageStatus::Complete
        },
        projection_read_receipt: request.projection_read_receipt.clone(),
        source_batch_digest: request.source_batch_digest.clone(),
        missing_owner: request.missing_owner.clone(),
        binding: request.batch.binding.clone(),
        projections_binding: request.projections.binding.clone(),
        denominator: request.batch.coverage.denominator.clone(),
        truncated: request.batch.coverage.truncated,
        revalidation_required: request.batch.coverage.revalidation_required,
        frontier: request.batch.coverage.frontier.clone(),
        batch_omissions: request.batch.coverage.omissions.clone(),
        projection_omissions: request.projections.omissions.clone(),
        counter_metrics: CounterMetrics {
            denominator_total: *total,
            records_assessed: request.batch.records.len(),
            omissions_carried: request.batch.coverage.omissions.len(),
            unaccounted_volume,
            projection_omissions: request.projections.omissions.len(),
            applicable_count: items.iter().filter(|item| item.applicable).count(),
            excluded_count: items.iter().filter(|item| !item.applicable).count(),
            excluded_by_rule: rules
                .into_iter()
                .map(|(rule, count)| RuleCount {
                    rule: rule.to_owned(),
                    count,
                })
                .collect(),
            gravity_notes: gravity.len(),
            maintenance_notes: maintenance.len(),
        },
        items,
        gravity,
        maintenance,
        receipts,
    };
    assessment.validate()?;
    Ok(assessment)
}
