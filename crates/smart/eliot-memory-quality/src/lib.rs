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
//! - coverage is explicit, never a bare count: the assessment carries a
//!   closed [`CoverageStatus`], the exact truncation frontier, the named
//!   batch omissions, and the admitted projection omissions. A `Complete`
//!   result exists only for lossless, fully accounted coverage; anything
//!   else is `Inconclusive` with the exact evidence needed for recheck;
//! - assessment order is deterministic input order; counter-metric rule
//!   counts are sorted by rule name;
//! - the package is bound to one exact freeze candidate and cannot read a
//!   moved or edited one: the freeze bytes are embedded at compile time and
//!   every request re-checks both the declared `freeze_id` and the sha256 of
//!   those exact bytes against the recorded pins, so drift fails closed with
//!   [`QualityError::VersionMismatch`] instead of being read as compatible.
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
use eliot_contracts::{ArtifactId, ContractVersion, fences_match_exact, sha256_hex};
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
// Freeze identity this consumer package builds against, and the exact bytes it
// is bound to, are declared in the freeze-binding block at the end of this
// file: CONSUMED_FREEZE_ID, CONSUMED_FREEZE_DIGEST, FREEZE_BYTES and the
// private guard `check_consumed_freeze` that reads them. That block sits after
// the serde-carrying types so the generated protected-wire inventory
// `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
// keeps a small uniform line offset for those declarations; its accepted sync
// belongs to the #929 owner, not to this crate.

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

/// Memory quality request over one bounded projection and its owner verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualityRequest {
    /// Bounded projection to assess; the entire denominator.
    pub batch: MemoryProjectionBatch,
    /// Owner applicability verdict over exactly this batch.
    pub applicable: ApplicableMemorySet,
    /// Admitted task/continuity/safety/affordance projections by handle.
    pub projections: CanonicalProjectionSet,
    /// Advisory receipt candidates; observed, never merged into verdicts.
    pub receipts: Vec<HarnessActivationReceiptCandidate>,
}

impl QualityRequest {
    /// Validate owner shapes, binding echoes, and the handle union.
    pub fn validate(&self) -> Result<(), QualityError> {
        check_consumed_freeze()?;
        self.batch.validate()?;
        // The denominator is the batch owner's fact, so its absence is
        // reported as the owner's typed refusal before the verdict is asked
        // to carry a proof ceiling for it.
        if !matches!(
            self.batch.coverage.denominator,
            DenominatorState::Known { .. }
        ) {
            return Err(QualityError::MissingDenominator);
        }
        // The owner's own join proves the verdict covers exactly this batch:
        // its echoes match and its dispositions equal the projected handles.
        // It replaces the separate echo comparison and handle-union walk that
        // previously restated the same rule here.
        self.applicable.validate_against_batch(&self.batch)?;
        self.projections.validate()?;
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
        // The verdict-must-cover-the-batch rule is enforced above, at its owner.
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
const CLOSED_RULES: [&str; 12] = [
    "CONFLICTED",
    "EPISTEMICALLY_UNKNOWN",
    "FENCE_MISMATCH",
    "INFLUENCE_INELIGIBLE",
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
/// assessed, rule counts sum to excluded, and `unaccounted_volume` equals the
/// carried frontier remainder whose identities name it. No rate, ratio, or
/// score is derived: cold-capture ratios and weak-claim rates stay proof
/// fixtures with their own horizons, not assessment fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CounterMetrics {
    /// Exact canonical records the read side observed.
    pub denominator_total: usize,
    /// Batch records assessed.
    pub records_assessed: usize,
    /// Named batch omissions carried alongside the records.
    pub omissions_carried: usize,
    /// Declared volume represented by no assessed record and no named
    /// omission: exactly the carried resume-frontier remainder.
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
        for omission in &self.batch_omissions {
            omission.validate()?;
        }
        for handle in &self.frontier {
            text(handle, "assessment.frontier")?;
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

    /// Validate that the carried recovery identities are unique, disjoint from
    /// the assessed records, and account for exactly the known denominator.
    ///
    /// The batch owner proved this partition once, over the batch it produced;
    /// this assessment is independently deserializable and persists its own
    /// copy of the frontier and the named omissions, so it must be able to
    /// recheck the partition against itself. Without this, a persisted
    /// assessment could name a frontier handle that is also an assessed item,
    /// or leave `unaccounted_volume` inconsistent with the identities that
    /// account for it, while every carried count still reconciled.
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
                reason: "truncation must match frontier presence exactly",
            });
        }
        let lossy_recovery = self.truncated || !self.batch_omissions.is_empty();
        if lossy_recovery && !self.revalidation_required {
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
        let lossy = self.truncated
            || !self.batch_omissions.is_empty()
            || !self.projection_omissions.is_empty()
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
        ExclusionReason::InfluenceIneligible => "INFLUENCE_INELIGIBLE",
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
    // `MemoryProjectionBatch::validate` already proved the exact
    // projected/omitted/deferred partition, so the residual this metric
    // reports is precisely the deferred frontier remainder. Reading it as
    // `total - records - omissions` would be the same number by that proof,
    // but deriving it from the identities keeps the metric honest if the
    // partition rule ever admits a fourth disposition.
    let unaccounted_volume = request.batch.coverage.frontier.len();
    let lossy = request.batch.coverage.truncated
        || !request.batch.coverage.omissions.is_empty()
        || !request.projections.omissions.is_empty()
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

// The freeze-binding block below sits after the serde-carrying types so the
// generated protected-wire inventory in
// `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
// records a small uniform line offset for those declarations instead of one
// larger than the whole block. Either way that inventory is a generated
// snapshot whose accepted sync belongs to the #929 owner, not to this crate.

/// Exact bytes of the contract-schema freeze this consumer is bound to, read
/// at compile time from its owning path.
///
/// `include_bytes!` is the fail-closed choice for the same reason it is in
/// `crates/smart/eliot-dreamer-memory-revision`: a missing, moved, or renamed
/// freeze is a compile error in this crate, so no build of this consumer can
/// ship against an absent freeze input. A runtime path lookup would instead
/// depend on the process working directory and on the repository layout
/// surviving packaging, which is a hidden failure source rather than a closed
/// one. The accepted cost is that the freeze bytes are embedded in every
/// consumer binary.
pub const FREEZE_BYTES: &[u8] = include_bytes!("../../cognitive-rev12-contract-schema-freeze.toml");

/// Freeze identity this consumer package builds against.
///
/// Repointed to the r12 candidate under `CC-W2-CONSUMER-REPIN`, which
/// enumerates this exact constant together with "its self-comparison assertion"
/// as a pin that must move in the same work unit as any freeze byte change.
/// The string alone proves nothing about the bytes, so it is only ever read
/// next to [`CONSUMED_FREEZE_DIGEST`]; the previous r8 pin and its
/// identical-literal self-comparison were removed because a constant compared
/// with itself can never detect the freeze moving under it.
pub const CONSUMED_FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r12";

/// Lowercase sha256 over the exact [`FREEZE_BYTES`] this consumer is bound to.
///
/// Recorded out of band, never here, because a digest of a file's own bytes
/// cannot live inside those bytes: this is the recorded readback digest and
/// byte length in the `CC-W9-REV12-HANDOFF` row of
/// `crates/smart/cognitive-contract-challenges.toml`, which
/// `scripts/read_freeze_digest.py` re-reads against the freeze file. It is the
/// same recorded value `crates/smart/eliot-dreamer-memory-revision/src/lib.rs`
/// pins as `REQUIRED_FREEZE_DIGEST`, so the two consumers cannot disagree about
/// which candidate is current. `CC-W2-CONSUMER-REPIN` lists "updating the
/// string pins without the byte digest pin" as a forbidden workaround, which is
/// why this constant exists next to [`CONSUMED_FREEZE_ID`].
pub const CONSUMED_FREEZE_DIGEST: &str =
    "eeb5449712a373c1087496005b97007f8632a885952c812152c46ea537857596";

/// Read the single column-0 `freeze_id` the freeze bytes declare.
///
/// The column-0 anchor is load-bearing: it is what keeps the freeze's own
/// `supersedes_freeze_id` line from being read as the current identity. A
/// document that declares no such line, or more than one, yields `None` rather
/// than a best-effort value.
fn declared_freeze_id(source: &str) -> Option<&str> {
    const PREFIX: &str = "freeze_id = \"";
    let mut declared: Option<&str> = None;
    let mut lines = 0usize;
    for line in source.lines() {
        let Some(rest) = line.strip_prefix(PREFIX) else {
            continue;
        };
        lines += 1;
        declared = rest.strip_suffix('"');
    }
    match (lines, declared) {
        (1, Some(value)) => Some(value),
        _ => None,
    }
}

/// Fail closed unless these exact bytes are the freeze revision this package
/// pins.
///
/// Takes the bytes as an argument so the comparison is over a document rather
/// than over a constant compared with itself; [`check_consumed_freeze`] is the
/// production entry and passes [`FREEZE_BYTES`]. Both sides are read from the
/// given bytes: the declared `freeze_id` against [`CONSUMED_FREEZE_ID`], and the
/// sha256 of the same bytes against [`CONSUMED_FREEZE_DIGEST`]. Divergence is
/// the existing typed [`QualityError::VersionMismatch`] -- never a boolean --
/// and never echoes the observed identity or digest, because this crate's
/// error contract states that errors name only the failing field and the
/// violated rule.
fn verify_consumed_freeze(bytes: &[u8]) -> Result<(), QualityError> {
    let source = std::str::from_utf8(bytes).map_err(|_| QualityError::VersionMismatch)?;
    let observed_id = declared_freeze_id(source).ok_or(QualityError::VersionMismatch)?;
    if observed_id != CONSUMED_FREEZE_ID || sha256_hex(bytes) != CONSUMED_FREEZE_DIGEST {
        return Err(QualityError::VersionMismatch);
    }
    Ok(())
}

/// Fail closed unless this package builds against the delivered freeze bytes.
///
/// A freeze that is absent cannot reach this function: [`FREEZE_BYTES`] would
/// not have compiled.
fn check_consumed_freeze() -> Result<(), QualityError> {
    verify_consumed_freeze(FREEZE_BYTES)
}

#[cfg(test)]
mod freeze_binding {
    //! The freeze pin is a byte binding, so both cases are measured against
    //! real documents: the delivered bytes pass, and any other freeze identity
    //! is refused with the existing typed error.

    #![allow(clippy::expect_used)]

    use super::{
        CONSUMED_FREEZE_DIGEST, CONSUMED_FREEZE_ID, FREEZE_BYTES, QualityError,
        check_consumed_freeze, declared_freeze_id, verify_consumed_freeze,
    };
    use eliot_contracts::sha256_hex;

    #[test]
    fn delivered_freeze_bytes_satisfy_both_recorded_pins() {
        assert_eq!(check_consumed_freeze(), Ok(()));
        assert_eq!(verify_consumed_freeze(FREEZE_BYTES), Ok(()));
        // The identity is read out of the bytes, not asserted beside them.
        assert_eq!(
            declared_freeze_id(std::str::from_utf8(FREEZE_BYTES).expect("freeze is utf-8")),
            Some(CONSUMED_FREEZE_ID)
        );
        assert_eq!(sha256_hex(FREEZE_BYTES), CONSUMED_FREEZE_DIGEST);
    }

    #[test]
    fn a_moved_freeze_identity_is_refused() {
        // Same document shape, a different published candidate: this is what a
        // freeze that moved to another revision looks like at this guard.
        let mut moved = String::from_utf8(FREEZE_BYTES.to_vec()).expect("freeze is utf-8");
        let id_line = format!("freeze_id = \"{CONSUMED_FREEZE_ID}\"");
        assert!(moved.contains(&id_line), "expected the declared id line");
        moved = moved.replacen(
            &id_line,
            "freeze_id = \"cognitive-rev12-contract-schema-freeze-2026-09-22-r11\"",
            1,
        );
        assert_eq!(
            verify_consumed_freeze(moved.as_bytes()),
            Err(QualityError::VersionMismatch)
        );
    }

    #[test]
    fn an_edited_freeze_under_an_unchanged_id_is_refused() {
        // The id alone cannot detect the bytes moving, so this case holds the
        // identity fixed and changes the digest's input. A line-ending rewrite
        // would not do: it breaks the column-0 id read as well, so the refusal
        // could not be attributed to the byte pin alone.
        let source = std::str::from_utf8(FREEZE_BYTES).expect("freeze is utf-8");
        let edited = source.replacen("revision = 12", "revision = 13", 1);
        assert_ne!(edited, source, "the edited bytes must differ");
        assert_eq!(
            declared_freeze_id(&edited),
            Some(CONSUMED_FREEZE_ID),
            "the id is unchanged, so only the byte digest can refuse this"
        );
        assert_eq!(
            verify_consumed_freeze(edited.as_bytes()),
            Err(QualityError::VersionMismatch)
        );
    }

    #[test]
    fn bytes_with_no_single_declared_identity_are_refused() {
        for source in [
            "",
            "[readback]\nrule = \"no identity here\"\n",
            "freeze_id = \"a\"\nfreeze_id = \"b\"\n",
            "supersedes_freeze_id = \"cognitive-rev12-contract-schema-freeze-2026-09-22-r11\"\n",
        ] {
            assert_eq!(
                verify_consumed_freeze(source.as_bytes()),
                Err(QualityError::VersionMismatch),
                "expected a refusal for {source:?}"
            );
        }
        assert_eq!(
            verify_consumed_freeze(&[0xff, 0xfe]),
            Err(QualityError::VersionMismatch),
            "bytes that are not UTF-8 carry no readable identity"
        );
    }
}
