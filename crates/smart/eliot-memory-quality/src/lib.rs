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
//! - no score, rank, similarity, retrieval count, or model judgment is read
//!   or emitted, because no frozen contract carries one; gravity and
//!   maintenance sections are per-record advisory dispositions with exact
//!   identities, never an aggregate scalar;
//! - low use never reduces support and retrieval never reinforces it: gravity
//!   marks narrowing or suppression *candidates* and preservation notes, never
//!   deletion, lifecycle transition, or support promotion (A14.4);
//! - receipt candidates are advisory only: their member/stage denominators
//!   are retained separately and observed counts never substitute for the
//!   batch denominator;
//! - assessment order is deterministic input order; counter-metric rule
//!   counts are sorted by rule name.
//!
//! A returned assessment is `Complete` by construction: a known denominator,
//! exact binding echoes, and a handle union identical to the batch records
//! are all enforced before any section is derived. Failures are typed
//! errors, never silent drops.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{CanonicalProjectionSet, ContextError};
use eliot_contracts::{ArtifactId, ContractVersion, fences_match_exact};
use eliot_evidence::LifecycleState;
use eliot_memory_projection_contracts::{
    ApplicableMemorySet, DenominatorState, ExclusionReason, FreshnessState, MemoryKind,
    MemoryProjectionBatch, MemoryProjectionError, MemoryRole, MemoryScopeBinding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-exported so consumers name the advisory receipt type without
// depending on the learning owner crate directly.
pub use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_learning_contracts::LearningContractError;

/// Stable wire name for this consumer contract family.
pub const QUALITY_CONTRACT_NAME: &str = "eliot.smart.memory-quality";
/// Current wire revision for this consumer contract family.
///
/// Exact equality only: an assessment written against any other revision is
/// rejected with [`QualityError::VersionMismatch`].
pub const QUALITY_CONTRACT_VERSION: ContractVersion = ContractVersion::new(0, 1, 0);
/// Hard ceiling on advisory receipt candidates carried by one request.
pub const MAX_QUALITY_RECEIPTS: usize = 64;

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
        self.batch.validate()?;
        self.applicable.validate()?;
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

/// One assessed record: owner verdict joined by handle, roles preserved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ItemAssessment {
    /// Exact canonical handle of the assessed record.
    pub handle: ArtifactId,
    /// Canonical kind of the record.
    pub kind: MemoryKind,
    /// Roles preserved with the record, never stripped.
    pub roles: Vec<MemoryRole>,
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
    /// Freshness reports a known older snapshot; revalidation names the
    /// boundary that passed.
    StaleMaterial,
    /// Freshness cannot be established; the owner note names what is missing.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceNote {
    /// Exact canonical handle of the noted record.
    pub handle: ArtifactId,
    /// Maintenance disposition echoing the owner fact.
    pub kind: MaintenanceNoteKind,
    /// Predecessor handle for supersession lineage; absent otherwise.
    pub predecessor: Option<ArtifactId>,
}

impl MaintenanceNote {
    /// Validate the note shape: lineage presence matches the lineage kind.
    pub fn validate(&self) -> Result<(), QualityError> {
        if (self.kind == MaintenanceNoteKind::SupersededWithLineage) != self.predecessor.is_some()
        {
            return Err(QualityError::InvalidField {
                field: "maintenance.predecessor",
                reason: "predecessor must be present exactly for supersession lineage",
            });
        }
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

/// Exact counter-metrics with the independently recheckable denominator.
///
/// Every count reconciles against the echoed denominator: assessed plus
/// omitted volume is covered by the batch total, applicable plus excluded
/// equals assessed, and rule counts sum to excluded. No rate, ratio, or
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
    /// Validate metric reconciliation (rule-count summation is checked by
    /// the assessment, which sees the emitted notes).
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.applicable_count + self.excluded_count != self.records_assessed {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "applicable plus excluded must equal assessed",
            });
        }
        if self.denominator_total < self.records_assessed + self.omissions_carried {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "denominator must cover assessed plus omitted volume",
            });
        }
        let mut seen = BTreeSet::new();
        for entry in &self.excluded_by_rule {
            if entry.rule.trim().is_empty() || entry.count == 0 {
                return Err(QualityError::InvalidField {
                    field: "counter_metrics.excluded_by_rule",
                    reason: "rule counts must be named and nonzero",
                });
            }
            if !seen.insert(entry.rule.clone()) {
                return Err(QualityError::InvalidField {
                    field: "counter_metrics.excluded_by_rule",
                    reason: "rule names must be unique",
                });
            }
        }
        Ok(())
    }
}

/// Memory ecology assessment over one bounded scope.
///
/// Complete by construction: the echoed denominator is known, bindings echo
/// the evaluated owners, and every section derives deterministically from
/// the validated request in input order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryEcologyAssessment {
    /// Contract version this assessment was written against.
    pub contract_version: ContractVersion,
    /// Binding echoed from the evaluated batch.
    pub binding: MemoryScopeBinding,
    /// Denominator echoed from the evaluated batch; always known.
    pub denominator: DenominatorState,
    /// Truncation flag echoed from the evaluated batch.
    pub truncated: bool,
    /// Revalidation requirement echoed from the evaluated batch.
    pub revalidation_required: bool,
    /// Per-record verdicts in deterministic batch order.
    pub items: Vec<ItemAssessment>,
    /// Advisory gravity dispositions in deterministic record order.
    pub gravity: Vec<GravityNote>,
    /// Maintenance dispositions in deterministic record order.
    pub maintenance: Vec<MaintenanceNote>,
    /// Reconciled counter-metrics with the exact denominator.
    pub counter_metrics: CounterMetrics,
    /// Advisory receipt candidates considered; observed, never merged.
    pub receipts_considered: usize,
}

impl MemoryEcologyAssessment {
    /// Validate the assessment: version, echoes, handle coverage, and
    /// metric reconciliation.
    pub fn validate(&self) -> Result<(), QualityError> {
        if self.contract_version != QUALITY_CONTRACT_VERSION {
            return Err(QualityError::VersionMismatch);
        }
        self.binding.validate()?;
        if !matches!(
            self.denominator,
            DenominatorState::Known { .. }
        ) {
            return Err(QualityError::MissingDenominator);
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
        self.counter_metrics.validate()?;
        if self.counter_metrics.records_assessed != self.items.len()
            || self.counter_metrics.gravity_notes != self.gravity.len()
            || self.counter_metrics.maintenance_notes != self.maintenance.len()
        {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "section counts must equal the carried sections",
            });
        }
        let applicable = self.items.iter().filter(|item| item.applicable).count();
        if self.counter_metrics.applicable_count != applicable
            || self.counter_metrics.excluded_count != self.items.len() - applicable
        {
            return Err(QualityError::InvalidField {
                field: "counter_metrics",
                reason: "applicability counts must equal the carried items",
            });
        }
        let mut ruled: usize = 0;
        for entry in &self.counter_metrics.excluded_by_rule {
            ruled += entry.count;
        }
        if ruled != self.counter_metrics.excluded_count {
            return Err(QualityError::InvalidField {
                field: "counter_metrics.excluded_by_rule",
                reason: "rule counts must sum to excluded",
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
        }),
        FreshnessState::Unknown => out.push(MaintenanceNote {
            handle: handle.clone(),
            kind: MaintenanceNoteKind::FreshnessUnknown,
            predecessor: None,
        }),
        FreshnessState::Current => {}
    }
    if let Some(predecessor) = &record.predecessor {
        out.push(MaintenanceNote {
            handle: handle.clone(),
            kind: MaintenanceNoteKind::SupersededWithLineage,
            predecessor: Some(predecessor.clone()),
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
        });
    }
}

/// Assess memory ecology over one bounded projection and its owner verdict.
///
/// The request is validated, a known denominator is required, and every
/// batch record receives its owner verdict joined by handle plus advisory
/// gravity and maintenance notes. Receipt candidates are counted, never
/// merged: their metrics stay observations with their own denominators.
pub fn assess_quality(
    request: &QualityRequest,
) -> Result<MemoryEcologyAssessment, QualityError> {
    request.validate()?;
    let DenominatorState::Known { total } = &request.batch.coverage.denominator else {
        return Err(QualityError::MissingDenominator);
    };
    let safety_triggers: BTreeSet<&str> = request
        .projections
        .safety
        .negative_memory_triggers
        .iter()
        .map(String::as_str)
        .collect();
    let mut verdicts: BTreeMap<&str, (&MemoryKind, Option<&ExclusionReason>, bool)> =
        BTreeMap::new();
    for entry in &request.applicable.applicable {
        verdicts.insert(entry.handle.as_str(), (&entry.kind, None, entry.cue_hit));
    }
    for entry in &request.applicable.excluded {
        verdicts.insert(
            entry.handle.as_str(),
            (&entry.kind, Some(&entry.reason), entry.cue_hit),
        );
    }
    let mut items = Vec::with_capacity(request.batch.records.len());
    let mut gravity = Vec::new();
    let mut maintenance = Vec::new();
    let mut rules: BTreeMap<&'static str, usize> = BTreeMap::new();
    for record in &request.batch.records {
        let Some((kind, reason, cue_hit)) = verdicts.get(record.handle.as_str()) else {
            // Unreachable: validate() enforces the exact handle union.
            return Err(QualityError::HandleMismatch {
                field: "applicable",
                reason: "verdict handles must equal exactly the batch record handles",
            });
        };
        let applicable = reason.is_none();
        items.push(ItemAssessment {
            handle: record.handle.clone(),
            kind: **kind,
            roles: record.roles.clone(),
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
    let excluded_by_rule = rules
        .into_iter()
        .map(|(rule, count)| RuleCount {
            rule: rule.to_owned(),
            count,
        })
        .collect();
    let assessment = MemoryEcologyAssessment {
        contract_version: QUALITY_CONTRACT_VERSION,
        binding: request.batch.binding.clone(),
        denominator: request.batch.coverage.denominator.clone(),
        truncated: request.batch.coverage.truncated,
        revalidation_required: request.batch.coverage.revalidation_required,
        counter_metrics: CounterMetrics {
            denominator_total: *total,
            records_assessed: request.batch.records.len(),
            omissions_carried: request.batch.coverage.omissions.len(),
            applicable_count: items.iter().filter(|item| item.applicable).count(),
            excluded_count: items.iter().filter(|item| !item.applicable).count(),
            excluded_by_rule,
            gravity_notes: gravity.len(),
            maintenance_notes: maintenance.len(),
        },
        items,
        gravity,
        maintenance,
        receipts_considered: request.receipts.len(),
    };
    assessment.validate()?;
    Ok(assessment)
}
