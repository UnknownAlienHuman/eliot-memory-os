//! Retained result carrier for the first rival-model phase.

use crate::analysis::{
    self, DiscriminatorRequirementFacet, DiscriminatorSearch, InertDiscriminator, ModelDisposition,
    OmissionFrontier, RivalEquivalenceClass, RivalModelAssessment,
};
use crate::bounds::{self, MAX_RIVAL_ITEMS, MAX_RIVAL_WIRE_BYTES};
use crate::comparison::{
    ComparisonCompletion, ComparisonField, ComparisonMap, SharedInputKind, SourceAddress,
};
use crate::error::RivalModelError;
use crate::meter::{MeterCharge, OperationMeter};
use crate::model_detail::{ModelBodyOmissionReason, RivalModelDetail};
use crate::packing;
use crate::policy::RivalPolicy;
use crate::states::{ModelOmissionReason, ModelUnavailableReason, OutputSection, WorkStage};
use crate::unknown::UnknownSlotRef;
use eliot_dreamer_contracts::grounding::{ArtifactId, StateFence, TaskId};
use eliot_dreamer_contracts::rival::{
    CurrentPositionBinding, DeclarationAvailability, RivalCoverageDeclaration,
    RivalCoverageReceipt, RivalDeclarationSet, RivalModelDeclaration, RivalModelRef,
    RivalModelSlot,
};
use eliot_dreamer_contracts::{DreamInputBundle, ValidatedGroundingCandidate};
use eliot_epistemic_contracts::{CurrentEpistemicPosition, DenominatorKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Wire version for the retained rival result.
pub const RIVAL_MODEL_SET_SCHEMA_VERSION: u32 = 1;

/// Phase-one disposition; neither variant promotes a model or chooses a winner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RivalModelDisposition {
    /// Sufficient retained models were structured without omission or unknown bodies.
    Structured,
    /// Some supplied model data is unknown or outside the deterministic frontier.
    Partial,
    /// Fewer than two retained model declarations were supplied.
    InsufficientRivals,
}

/// Exact identity of the declaration source set retained by this result.
///
/// The result's `validated_input_digest` also anchors the input-owned
/// `UnknownTable::ConsultedSources` basis; this reference carries no source
/// authentication or current-truth claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSetRef {
    pub set_id: ArtifactId,
    pub digest: String,
}

impl SourceSetRef {
    pub fn validate(&self) -> Result<(), RivalModelError> {
        if self.set_id.as_str().trim().is_empty()
            || self.digest.len() != 64
            || !eliot_dreamer_contracts::is_hex64_lower(&self.digest)
        {
            return Err(RivalModelError::InvalidContract("result.source_set"));
        }
        Ok(())
    }
}

/// Coverage state retained without copying the owner receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unknown,
}

/// Immutable result retaining the exact supplied rival declaration set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalModelSet {
    /// Result wire version.
    pub schema_version: u32,
    /// Stable result artifact identity.
    pub set_id: ArtifactId,
    /// Task inherited from the validated grounding candidate.
    pub task_id: TaskId,
    /// Scope inherited from the validated grounding candidate.
    pub scope: String,
    /// State fence inherited from the validated grounding candidate.
    pub state_fence: StateFence,
    /// Exact bundle digest retained as source context.
    pub bundle_digest: String,
    /// Receipt-bound structured input digest.
    ///
    /// This digest anchors the validated input, including the source-width
    /// basis used to address `UnknownTable::ConsultedSources` entries.
    pub validated_input_digest: String,
    /// Exact supplied current-position binding.
    pub current_position: CurrentPositionBinding,
    /// Exact declaration source-set identity used by this result.
    pub source_set: SourceSetRef,
    /// Policy identity used to bound this operation.
    pub policy_id: String,
    /// Frozen policy digest.
    pub policy_digest: String,
    /// Complete declarations retained without coalescing or projection.
    pub declarations: Option<Box<RivalDeclarationSet>>,
    /// Per-model retained, unavailable, and deterministic omission accounting.
    pub assessments: Vec<RivalModelAssessment>,
    /// One source-body row for every canonical model slot.
    pub model_details: Vec<RivalModelDetail>,
    /// Exact material-equivalence classes, retaining all member identities.
    pub equivalence_classes: Vec<RivalEquivalenceClass>,
    /// Inert exact expected/falsifier cross-matches.
    pub discriminators: Vec<InertDiscriminator>,
    /// Completion and unresolved requirements for discriminator search.
    pub discriminator_search: DiscriminatorSearch,
    /// Bounded repeated-input comparison map; it carries no independence or truth claim.
    pub comparison: ComparisonMap,
    /// Explicit bounded output frontier for omitted declarations.
    pub omission_frontier: OmissionFrontier,
    /// Compact unknown facets retained from the declaration input.
    pub unknown_slots: Vec<UnknownSlotRef>,
    /// Total unknown facets observed before any future output truncation.
    pub unknown_total: usize,
    /// Number of unknown facets omitted from the retained prefix.
    pub unknown_omitted_count: usize,
    /// Number of model assessment slots explicitly omitted by analysis.
    pub omitted_count: usize,
    /// Distinct material classes represented by retained assessments.
    pub distinct_material_classes: usize,
    /// Minimum distinct classes required by the supplied operation policy.
    pub required_min_classes: usize,
    /// Model-table coverage state derived from the supplied owner values.
    pub model_coverage: CoverageStatus,
    /// Source-table coverage state derived from the supplied owner values.
    pub source_coverage: CoverageStatus,
    /// Explicit phase-one disposition.
    pub disposition: RivalModelDisposition,
    /// Canonical result digest excluding this field.
    pub digest: String,
}

impl RivalModelSet {
    #[allow(
        clippy::too_many_lines,
        reason = "result construction joins validated sections before atomic packing"
    )]
    pub(crate) fn from_validated(
        candidate: &ValidatedGroundingCandidate,
        current_position: CurrentPositionBinding,
        declarations: &RivalDeclarationSet,
        policy: &RivalPolicy,
        meter: &mut OperationMeter,
    ) -> Result<Self, RivalModelError> {
        if declarations.models.len() > MAX_RIVAL_ITEMS {
            return Err(RivalModelError::Bound {
                field: "rival.models",
                maximum: MAX_RIVAL_ITEMS,
                actual: declarations.models.len(),
            });
        }
        let output_ceiling = packing::output_ceiling(candidate, policy)?;
        let unknown_total = meter.unknowns().len();
        let unknown_prefix_limit = usize::try_from(policy.reserved_unknown_slots)
            .unwrap_or(usize::MAX)
            .min(unknown_total);
        let unknown_slots = meter
            .unknowns()
            .iter()
            .take(unknown_prefix_limit)
            .cloned()
            .collect::<Vec<_>>();
        let unknown_omitted_count = unknown_total.saturating_sub(unknown_slots.len());
        let minimum_classes = usize::try_from(policy.min_models)
            .unwrap_or(usize::MAX)
            .max(2);
        let grounded = &candidate.input.grounded;
        let bundle_digest = candidate.input.grounded.input.bundle_digest.clone();
        let source_set = SourceSetRef {
            set_id: declarations.set_id.clone(),
            digest: declarations.digest.clone(),
        };
        let validated_input_digest = candidate.validated.receipt.input_digest.clone();
        let identity = SetIdentity {
            validated_input_digest: &validated_input_digest,
            bundle_digest: &bundle_digest,
            task_id: &grounded.task_id,
            scope: &grounded.scope_id,
            state_fence: &grounded.state_fence,
            current_position: &current_position,
            policy_id: &policy.policy_id,
            policy_digest: &policy.digest,
            source_set: &source_set,
        };
        let set_id = derive_set_id_from_bindings(&identity)?;
        let mut result = Self {
            schema_version: RIVAL_MODEL_SET_SCHEMA_VERSION,
            set_id,
            task_id: grounded.task_id.clone(),
            scope: grounded.scope_id.clone(),
            state_fence: grounded.state_fence.clone(),
            bundle_digest,
            validated_input_digest,
            current_position,
            source_set,
            policy_id: policy.policy_id.clone(),
            policy_digest: policy.digest.clone(),
            declarations: None,
            assessments: skeleton_assessments(declarations),
            model_details: initial_model_details(declarations)?,
            equivalence_classes: Vec::new(),
            discriminators: Vec::new(),
            discriminator_search: DiscriminatorSearch::not_started(),
            comparison: ComparisonMap {
                completion: ComparisonCompletion::NotStarted,
                phase: crate::comparison::ComparisonPhase::Walk,
                frontier: None,
                model_context: Vec::new(),
                groups: Vec::new(),
            },
            omission_frontier: OmissionFrontier {
                model_ids: Vec::new(),
                sections: vec![OutputSection::Models],
                exhausted_stage: None,
                exhausted_model_id: None,
                exhausted_prediction_id: None,
                exhausted_pair: None,
                exhausted_prediction_pair: None,
            },
            unknown_total,
            unknown_slots,
            unknown_omitted_count,
            omitted_count: 0,
            distinct_material_classes: 0,
            required_min_classes: minimum_classes,
            model_coverage: coverage_status(&declarations.model_coverage),
            source_coverage: coverage_status(&declarations.source_coverage),
            disposition: RivalModelDisposition::InsufficientRivals,
            digest: "0".repeat(64),
        };
        result.omitted_count = omitted_count(&result.assessments);
        let mandatory_capacity = packing::mandatory_capacity_bytes(&result, declarations, meter)?;
        if mandatory_capacity > output_ceiling {
            return Err(RivalModelError::Bound {
                field: "result.mandatory_skeleton",
                maximum: output_ceiling,
                actual: mandatory_capacity,
            });
        }
        meter.reserve(result.assessments.len(), "result.model_assessment_skeleton")?;
        meter.reserve(result.unknown_slots.len(), "result.unknown_skeleton")?;
        let mut packing_ledger = packing::PackingLedger::fund(mandatory_capacity, meter)?;

        let analysis = analysis::analyze(declarations, policy, meter, output_ceiling)?;
        let distinct_material_classes = analysis.equivalence_classes.len();
        let all_assessments_retained = analysis
            .assessments
            .iter()
            .all(|assessment| matches!(assessment.disposition, ModelDisposition::Retained));
        result.assessments = analysis.assessments;
        result.equivalence_classes = analysis.equivalence_classes;
        result.discriminators = analysis.discriminators;
        result.discriminator_search = analysis.discriminator_search;
        result.omission_frontier = analysis.omission_frontier;
        result.comparison =
            crate::comparison::build_comparison_map(declarations, meter, output_ceiling)?;
        if result.comparison.completion == ComparisonCompletion::Bounded {
            push_section(
                &mut result.omission_frontier.sections,
                OutputSection::Comparisons,
            );
        }
        result.omitted_count = omitted_count(&result.assessments);
        result.distinct_material_classes = distinct_material_classes;
        result.disposition = if distinct_material_classes < minimum_classes {
            RivalModelDisposition::InsufficientRivals
        } else if !crate::candidate_is_complete(candidate)
            || unknown_total != 0
            || result.omission_frontier.exhausted_stage.is_some()
            || result.comparison.completion == ComparisonCompletion::Bounded
            || !all_assessments_retained
        {
            RivalModelDisposition::Partial
        } else {
            RivalModelDisposition::Structured
        };

        let candidate_wire_bytes =
            bounded_probe(packing::preflight_result(&result, output_ceiling, meter))?;
        let candidate_fits = match candidate_wire_bytes {
            ProbeResult::Fits(bytes) => packing_ledger.admit(bytes, meter)?,
            ProbeResult::Exhausted(_) => false,
        };
        if candidate_fits {
            let pending_details =
                std::mem::replace(&mut result.model_details, source_set_details(declarations)?);
            let source_wire_bytes = bounded_probe(packing::preflight_with_declarations(
                &result,
                declarations,
                output_ceiling,
                meter,
            ))?;
            if let ProbeResult::Fits(bytes) = source_wire_bytes {
                if packing_ledger.admit(bytes, meter)? {
                    match bounded_probe(packing::preflight_declarations_materialization(
                        declarations,
                        meter,
                    ))? {
                        ProbeResult::Fits(bytes) => {
                            if matches!(
                                meter.charge_materialization(bytes, None)?,
                                MeterCharge::Charged
                            ) {
                                result.declarations = Some(Box::new(declarations.clone()));
                            } else {
                                result.model_details = pending_details;
                                pack_model_bodies(
                                    &mut result,
                                    declarations,
                                    output_ceiling,
                                    &mut packing_ledger,
                                    meter,
                                )?;
                            }
                        }
                        ProbeResult::Exhausted(_) => {
                            result.model_details = pending_details;
                            pack_model_bodies(
                                &mut result,
                                declarations,
                                output_ceiling,
                                &mut packing_ledger,
                                meter,
                            )?;
                        }
                    }
                } else {
                    result.model_details = pending_details;
                    pack_model_bodies(
                        &mut result,
                        declarations,
                        output_ceiling,
                        &mut packing_ledger,
                        meter,
                    )?;
                }
            } else {
                result.model_details = pending_details;
                pack_model_bodies(
                    &mut result,
                    declarations,
                    output_ceiling,
                    &mut packing_ledger,
                    meter,
                )?;
            }
        } else {
            reset_to_skeleton(&mut result, declarations)?;
        }
        sync_meter_frontier(&mut result, meter);
        let final_wire_bytes = bounds::preflight(&result, output_ceiling)?;
        if !packing_ledger.covers(final_wire_bytes) {
            return Err(RivalModelError::Bound {
                field: "result.final_passes",
                maximum: packing_ledger.funded_bytes(),
                actual: final_wire_bytes,
            });
        }
        result.digest = result.compute_digest()?;
        let final_bytes = u64::try_from(final_wire_bytes).map_err(|_| RivalModelError::Bound {
            field: "result.output_bytes",
            maximum: usize::MAX,
            actual: final_wire_bytes,
        })?;
        let mut final_usage = policy.current_usage;
        final_usage.output_bytes = final_usage.output_bytes.max(final_bytes);
        final_usage.report_bytes = final_usage.report_bytes.max(final_bytes);
        crate::check_budget(
            candidate,
            &final_usage,
            meter.input_wire_bytes,
            meter.reference_width,
            meter.source_width.upper_bound,
        )?;
        Ok(result)
    }

    /// Validates intrinsic result integrity and its canonical digest.
    ///
    /// This checks supplied bindings and retained partition metadata only; it
    /// does not authenticate sources, establish current truth, or issue an
    /// admission decision. Use `validate_against` for bounded replay against
    /// independently supplied inputs.
    #[allow(
        clippy::too_many_lines,
        reason = "intrinsic result validation keeps wire, rows, and frontier checks atomic"
    )]
    pub fn validate(&self) -> Result<(), RivalModelError> {
        bounds::preflight(self, MAX_RIVAL_WIRE_BYTES)?;
        if self.schema_version != RIVAL_MODEL_SET_SCHEMA_VERSION
            || self.scope.trim().is_empty()
            || self.bundle_digest.len() != 64
            || !eliot_dreamer_contracts::is_hex64_lower(&self.bundle_digest)
            || self.validated_input_digest.len() != 64
            || !eliot_dreamer_contracts::is_hex64_lower(&self.validated_input_digest)
            || self.policy_id.trim().is_empty()
            || self.policy_digest.len() != 64
            || !eliot_dreamer_contracts::is_hex64_lower(&self.policy_digest)
            || !(2..=256).contains(&self.required_min_classes)
        {
            return Err(RivalModelError::InvalidContract("rival_model_set"));
        }
        self.source_set.validate()?;
        self.discriminator_search.validate()?;
        if self.unknown_total
            != self
                .unknown_slots
                .len()
                .saturating_add(self.unknown_omitted_count)
            || self.unknown_slots.len() > crate::unknown::MAX_UNKNOWN_SLOTS
        {
            return Err(RivalModelError::InvalidContract("unknown_slots"));
        }
        self.current_position
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("current_position"))?;
        let identity = SetIdentity {
            validated_input_digest: &self.validated_input_digest,
            bundle_digest: &self.bundle_digest,
            task_id: &self.task_id,
            scope: &self.scope,
            state_fence: &self.state_fence,
            current_position: &self.current_position,
            policy_id: &self.policy_id,
            policy_digest: &self.policy_digest,
            source_set: &self.source_set,
        };
        if self.set_id != derive_set_id_from_bindings(&identity)? {
            return Err(RivalModelError::IdentityMismatch("result.set_id"));
        }
        if let Some(declarations) = self.declarations.as_deref() {
            declarations
                .validate()
                .map_err(|_| RivalModelError::InvalidContract("rival_declarations"))?;
            if self.task_id != declarations.task_id
                || self.scope != declarations.scope
                || self.state_fence != declarations.state_fence
            {
                return Err(RivalModelError::IdentityMismatch("declaration_context"));
            }
            if self.source_set.set_id != declarations.set_id
                || self.source_set.digest != declarations.digest
                || self.assessments.len() != declarations.models.len()
            {
                return Err(RivalModelError::IdentityMismatch(
                    "source_set_or_assessments",
                ));
            }
            for (assessment, slot) in self.assessments.iter().zip(&declarations.models) {
                if assessment.model_id != *slot.stable_id() {
                    return Err(RivalModelError::IdentityMismatch("assessment_model_id"));
                }
                match slot {
                    RivalModelSlot::Retained { declaration } => {
                        if assessment.model_revision != Some(declaration.model_revision)
                            || assessment.declaration_digest.as_deref()
                                != Some(declaration.digest.as_str())
                            || matches!(
                                assessment.disposition,
                                crate::analysis::ModelDisposition::Unavailable { .. }
                            )
                        {
                            return Err(RivalModelError::IdentityMismatch(
                                "assessment_model_binding",
                            ));
                        }
                    }
                    RivalModelSlot::Unavailable {
                        model_revision,
                        declaration_digest,
                        ..
                    } => {
                        if assessment.model_revision != *model_revision
                            || assessment.declaration_digest.as_ref() != declaration_digest.as_ref()
                            || !matches!(
                                assessment.disposition,
                                crate::analysis::ModelDisposition::Unavailable { .. }
                            )
                        {
                            return Err(RivalModelError::IdentityMismatch(
                                "assessment_unavailable_binding",
                            ));
                        }
                    }
                }
            }
            if coverage_status(&declarations.model_coverage) != self.model_coverage
                || coverage_status(&declarations.source_coverage) != self.source_coverage
            {
                return Err(RivalModelError::IdentityMismatch("coverage_status"));
            }
        }
        validate_requirement_addresses(self, self.declarations.as_deref())?;
        self.validate_metadata()?;
        if self.compute_digest()? != self.digest {
            return Err(RivalModelError::InvalidContract("rival_model_set.digest"));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "metadata validation preserves canonical identity and section invariants"
    )]
    fn validate_metadata(&self) -> Result<(), RivalModelError> {
        self.validate_model_details()?;
        validate_comparison_map(&self.comparison, &self.assessments)?;
        let comparison_section = self
            .omission_frontier
            .sections
            .contains(&OutputSection::Comparisons);
        if (self.comparison.completion == ComparisonCompletion::Bounded) != comparison_section {
            return Err(RivalModelError::InvalidContract(
                "comparison.omission_section",
            ));
        }
        let mut assessment_ids = std::collections::BTreeSet::new();
        let mut previous_model_id: Option<&ArtifactId> = None;
        for assessment in &self.assessments {
            if previous_model_id
                .is_some_and(|previous| assessment.model_id.as_str() <= previous.as_str())
            {
                return Err(RivalModelError::InvalidContract("assessment_model_order"));
            }
            if !assessment_ids.insert(assessment.model_id.clone()) {
                return Err(RivalModelError::InvalidContract("assessment_model_id"));
            }
            if assessment
                .declaration_digest
                .as_deref()
                .is_some_and(|digest| {
                    digest.len() != 64 || !eliot_dreamer_contracts::is_hex64_lower(digest)
                })
            {
                return Err(RivalModelError::InvalidContract("assessment_digest"));
            }
            if !matches!(
                assessment.disposition,
                crate::analysis::ModelDisposition::Retained
            ) && (assessment.equivalence_class.is_some()
                || assessment.material_projection_digest.is_some())
            {
                return Err(RivalModelError::InvalidContract(
                    "non_retained_assessment_metadata",
                ));
            }
            previous_model_id = Some(&assessment.model_id);
        }
        let retained = self
            .assessments
            .iter()
            .filter(|assessment| {
                matches!(
                    assessment.disposition,
                    crate::analysis::ModelDisposition::Retained
                )
            })
            .count();
        let omitted = self
            .assessments
            .iter()
            .filter(|assessment| {
                matches!(
                    assessment.disposition,
                    crate::analysis::ModelDisposition::Omitted { .. }
                )
            })
            .count();
        if omitted != self.omitted_count {
            return Err(RivalModelError::InvalidContract("omitted_count"));
        }
        if self.distinct_material_classes != self.equivalence_classes.len() {
            return Err(RivalModelError::InvalidContract("material_class_count"));
        }
        let mut class_members = std::collections::BTreeSet::new();
        let mut class_projections = std::collections::BTreeSet::new();
        for (expected_id, class) in self.equivalence_classes.iter().enumerate() {
            if class.class_id != u32::try_from(expected_id).unwrap_or(u32::MAX) {
                return Err(RivalModelError::InvalidContract("equivalence_class_id"));
            }
            if class.members.is_empty() || class.members.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(RivalModelError::InvalidContract(
                    "equivalence_class_members",
                ));
            }
            let mut projection: Option<&str> = None;
            for member in &class.members {
                if !class_members.insert(member.clone()) {
                    return Err(RivalModelError::InvalidContract("equivalence_class_member"));
                }
                let Some(assessment) = self.assessments.iter().find(|assessment| {
                    assessment.model_id == member.model_id
                        && assessment.equivalence_class == Some(class.class_id)
                }) else {
                    return Err(RivalModelError::InvalidContract(
                        "equivalence_class_partition",
                    ));
                };
                if !matches!(
                    assessment.disposition,
                    crate::analysis::ModelDisposition::Retained
                ) || assessment.model_revision != Some(member.model_revision)
                    || assessment.declaration_digest.as_deref()
                        != Some(member.declaration_digest.as_str())
                    || assessment
                        .material_projection_digest
                        .as_deref()
                        .is_none_or(|digest| {
                            digest.len() != 64 || !eliot_dreamer_contracts::is_hex64_lower(digest)
                        })
                {
                    return Err(RivalModelError::InvalidContract("equivalence_class_status"));
                }
                let Some(member_projection) = assessment.material_projection_digest.as_deref()
                else {
                    return Err(RivalModelError::InvalidContract(
                        "equivalence_class_projection",
                    ));
                };
                if projection.is_some_and(|known| known != member_projection) {
                    return Err(RivalModelError::InvalidContract(
                        "equivalence_class_projection",
                    ));
                }
                projection = Some(member_projection);
            }
            if !class_projections.insert(projection.unwrap_or_default().to_owned()) {
                return Err(RivalModelError::InvalidContract(
                    "equivalence_class_projection",
                ));
            }
        }
        if class_members.len() != retained
            || self.assessments.iter().any(|assessment| {
                matches!(
                    assessment.disposition,
                    crate::analysis::ModelDisposition::Retained
                ) && assessment.equivalence_class.is_none()
            })
        {
            return Err(RivalModelError::InvalidContract(
                "equivalence_class_partition",
            ));
        }
        let search = &self.discriminator_search;
        let known_classes = self.distinct_material_classes;
        let matches = !self.discriminators.is_empty();
        let requirements = !search.requirements.is_empty();
        if known_classes < 2 {
            if search.completion == analysis::SearchCompletion::Complete
                || matches
                || search.outcome != analysis::DiscriminatorOutcome::InsufficientRivals
            {
                return Err(RivalModelError::InvalidContract("discriminator_summary"));
            }
        } else {
            if search.completion == analysis::SearchCompletion::NotStarted {
                return Err(RivalModelError::InvalidContract("discriminator_completion"));
            }
            let expected_outcome = if matches {
                analysis::DiscriminatorOutcome::Matches
            } else if search.completion == analysis::SearchCompletion::Bounded || requirements {
                analysis::DiscriminatorOutcome::Unprobeable
            } else {
                analysis::DiscriminatorOutcome::NoExact
            };
            if search.outcome != expected_outcome {
                return Err(RivalModelError::InvalidContract("discriminator_summary"));
            }
        }
        validate_discriminator_records(self)?;
        if self.disposition == RivalModelDisposition::InsufficientRivals
            && self.distinct_material_classes >= self.required_min_classes
        {
            return Err(RivalModelError::InvalidContract("disposition"));
        }
        if self.disposition == RivalModelDisposition::Structured
            && (self.declarations.is_none()
                || self.distinct_material_classes < self.required_min_classes
                || retained != self.assessments.len()
                || self.unknown_total != 0
                || self.model_coverage != CoverageStatus::Complete
                || self.source_coverage != CoverageStatus::Complete
                || !frontier_is_empty(&self.omission_frontier))
        {
            return Err(RivalModelError::InvalidContract("disposition"));
        }
        if self.disposition == RivalModelDisposition::Partial
            && self.distinct_material_classes < self.required_min_classes
        {
            return Err(RivalModelError::InvalidContract("disposition"));
        }
        Ok(())
    }

    fn validate_model_details(&self) -> Result<(), RivalModelError> {
        if self.model_details.len() != self.assessments.len() {
            return Err(RivalModelError::InvalidContract("model_details.length"));
        }
        let has_source_set = self
            .model_details
            .iter()
            .any(|detail| matches!(detail, RivalModelDetail::SourceSet { .. }));
        let has_retained_body = self
            .model_details
            .iter()
            .any(|detail| matches!(detail, RivalModelDetail::Retained { .. }));
        if has_source_set != self.declarations.is_some() {
            return Err(RivalModelError::InvalidContract("model_details.source_set"));
        }
        if has_source_set && has_retained_body {
            return Err(RivalModelError::InvalidContract(
                "model_details.duplicate_source",
            ));
        }
        let mut previous_row = None;
        for (index, (detail, assessment)) in
            self.model_details.iter().zip(&self.assessments).enumerate()
        {
            let row = match detail {
                RivalModelDetail::SourceSet { source_row }
                | RivalModelDetail::Retained { source_row, .. }
                | RivalModelDetail::Omitted { source_row, .. }
                | RivalModelDetail::Unavailable { source_row } => *source_row,
            };
            if row != u32::try_from(index).unwrap_or(u32::MAX)
                || previous_row.is_some_and(|previous| row <= previous)
            {
                return Err(RivalModelError::InvalidContract("model_details.order"));
            }
            previous_row = Some(row);
            match detail {
                RivalModelDetail::SourceSet { .. } => {
                    if matches!(assessment.disposition, ModelDisposition::Unavailable { .. }) {
                        return Err(RivalModelError::IdentityMismatch(
                            "model_details.source_assessment",
                        ));
                    }
                }
                RivalModelDetail::Retained { declaration, .. } => {
                    declaration.validate().map_err(|_| {
                        RivalModelError::InvalidContract("model_detail.declaration")
                    })?;
                    if assessment.model_id != declaration.model_id
                        || assessment.model_revision != Some(declaration.model_revision)
                        || assessment.declaration_digest.as_deref()
                            != Some(declaration.digest.as_str())
                        || declaration.task_id != self.task_id
                        || declaration.applicability.scope != self.scope
                        || declaration.state_fence != self.state_fence
                    {
                        return Err(RivalModelError::IdentityMismatch("model_detail.assessment"));
                    }
                }
                RivalModelDetail::Omitted { .. } => {
                    if matches!(assessment.disposition, ModelDisposition::Unavailable { .. }) {
                        return Err(RivalModelError::IdentityMismatch(
                            "model_detail.omitted_assessment",
                        ));
                    }
                }
                RivalModelDetail::Unavailable { .. } => {
                    if !matches!(assessment.disposition, ModelDisposition::Unavailable { .. }) {
                        return Err(RivalModelError::IdentityMismatch(
                            "model_detail.unavailable_assessment",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, RivalModelError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            set_id: &'a ArtifactId,
            task_id: &'a TaskId,
            scope: &'a str,
            state_fence: &'a StateFence,
            bundle_digest: &'a str,
            validated_input_digest: &'a str,
            current_position: &'a CurrentPositionBinding,
            source_set: &'a SourceSetRef,
            policy_id: &'a str,
            policy_digest: &'a str,
            declarations: &'a Option<Box<RivalDeclarationSet>>,
            assessments: &'a [RivalModelAssessment],
            model_details: &'a [RivalModelDetail],
            equivalence_classes: &'a [RivalEquivalenceClass],
            discriminators: &'a [InertDiscriminator],
            discriminator_search: &'a DiscriminatorSearch,
            comparison: &'a ComparisonMap,
            omission_frontier: &'a OmissionFrontier,
            unknown_slots: &'a [UnknownSlotRef],
            unknown_total: usize,
            unknown_omitted_count: usize,
            omitted_count: usize,
            distinct_material_classes: usize,
            required_min_classes: usize,
            model_coverage: CoverageStatus,
            source_coverage: CoverageStatus,
            disposition: RivalModelDisposition,
        }
        let bytes = eliot_dreamer_contracts::canonical_bytes(&Preimage {
            schema_version: self.schema_version,
            set_id: &self.set_id,
            task_id: &self.task_id,
            scope: &self.scope,
            state_fence: &self.state_fence,
            bundle_digest: &self.bundle_digest,
            validated_input_digest: &self.validated_input_digest,
            current_position: &self.current_position,
            source_set: &self.source_set,
            policy_id: &self.policy_id,
            policy_digest: &self.policy_digest,
            declarations: &self.declarations,
            assessments: &self.assessments,
            model_details: &self.model_details,
            equivalence_classes: &self.equivalence_classes,
            discriminators: &self.discriminators,
            discriminator_search: &self.discriminator_search,
            comparison: &self.comparison,
            omission_frontier: &self.omission_frontier,
            unknown_slots: &self.unknown_slots,
            unknown_total: self.unknown_total,
            unknown_omitted_count: self.unknown_omitted_count,
            omitted_count: self.omitted_count,
            distinct_material_classes: self.distinct_material_classes,
            required_min_classes: self.required_min_classes,
            model_coverage: self.model_coverage,
            source_coverage: self.source_coverage,
            disposition: self.disposition,
        })
        .map_err(|_| RivalModelError::InvalidContract("rival_model_set.preimage"))?;
        Ok(eliot_dreamer_contracts::digest_hex(&bytes))
    }

    /// Replays the public operation against independently supplied inputs and
    /// compares the complete retained result. This is an integrity replay;
    /// it does not authenticate a source, establish current truth, or issue
    /// an admission decision.
    pub fn validate_against(
        &self,
        bundle: &DreamInputBundle,
        candidate: &ValidatedGroundingCandidate,
        current_position: &CurrentEpistemicPosition,
        policy: &RivalPolicy,
    ) -> Result<(), RivalModelError> {
        self.validate()?;
        bounds::preflight(bundle, MAX_RIVAL_WIRE_BYTES)?;
        bounds::preflight(candidate, MAX_RIVAL_WIRE_BYTES)?;
        bounds::preflight(current_position, MAX_RIVAL_WIRE_BYTES)?;
        bounds::preflight(policy, MAX_RIVAL_WIRE_BYTES)?;
        let replayed = crate::structure_rival_models(bundle, candidate, current_position, policy)?;
        if replayed != *self {
            return Err(RivalModelError::IdentityMismatch("result.replay"));
        }
        Ok(())
    }
}

fn validate_comparison_map(
    map: &ComparisonMap,
    assessments: &[RivalModelAssessment],
) -> Result<(), RivalModelError> {
    if map.model_context.len() > 4096 || map.groups.len() > 4096 {
        return Err(RivalModelError::Bound {
            field: "comparison.items",
            maximum: 4096,
            actual: map.model_context.len().max(map.groups.len()),
        });
    }
    let mut previous_context: Option<SourceAddress> = None;
    for address in &map.model_context {
        validate_comparison_address(address, assessments, true, None)?;
        if previous_context.is_some_and(|previous| *address <= previous) {
            return Err(RivalModelError::InvalidContract("comparison.context_order"));
        }
        previous_context = Some(*address);
    }
    let mut previous_group = None;
    for group in &map.groups {
        if group.occurrences.is_empty() || group.occurrences.len() > 4096 {
            return Err(RivalModelError::InvalidContract(
                "comparison.group_occurrences",
            ));
        }
        let mut models = BTreeSet::new();
        let mut previous_occurrence: Option<SourceAddress> = None;
        for address in &group.occurrences {
            validate_comparison_address(address, assessments, false, Some(group.kind))?;
            if previous_occurrence.is_some_and(|previous| *address <= previous) {
                return Err(RivalModelError::InvalidContract(
                    "comparison.occurrence_order",
                ));
            }
            previous_occurrence = Some(*address);
            models.insert(address.model_row);
        }
        if models.len() < 2 {
            return Err(RivalModelError::InvalidContract("comparison.group_models"));
        }
        let first = group.occurrences[0];
        let key = (group.kind, first);
        if previous_group.is_some_and(|previous| key <= previous) {
            return Err(RivalModelError::InvalidContract("comparison.group_order"));
        }
        previous_group = Some(key);
    }
    if map.completion == ComparisonCompletion::NotStarted
        && (!map.model_context.is_empty() || !map.groups.is_empty() || map.frontier.is_some())
    {
        return Err(RivalModelError::InvalidContract("comparison.not_started"));
    }
    if map.completion == ComparisonCompletion::Complete && map.frontier.is_some() {
        return Err(RivalModelError::InvalidContract(
            "comparison.complete_frontier",
        ));
    }
    if let Some(frontier) = map.frontier {
        let context_result = validate_comparison_address(&frontier, assessments, true, None);
        let group_result = validate_comparison_address(&frontier, assessments, false, None);
        if context_result.is_err() && group_result.is_err() {
            return Err(RivalModelError::InvalidContract(
                "comparison.frontier_shape",
            ));
        }
    }
    if (map.completion == ComparisonCompletion::NotStarted
        && map.phase != crate::comparison::ComparisonPhase::Walk)
        || (map.completion == ComparisonCompletion::Complete
            && map.phase != crate::comparison::ComparisonPhase::Output)
    {
        return Err(RivalModelError::InvalidContract("comparison.phase"));
    }
    Ok(())
}

fn validate_comparison_address(
    address: &SourceAddress,
    assessments: &[RivalModelAssessment],
    context: bool,
    kind: Option<SharedInputKind>,
) -> Result<(), RivalModelError> {
    let row = usize::try_from(address.model_row)
        .ok()
        .ok_or(RivalModelError::InvalidContract("comparison.model_row"))?;
    let Some(assessment) = assessments.get(row) else {
        return Err(RivalModelError::InvalidContract("comparison.model_row"));
    };
    if matches!(assessment.disposition, ModelDisposition::Unavailable { .. }) {
        return Err(RivalModelError::InvalidContract(
            "comparison.unavailable_model_row",
        ));
    }
    let shape_ok = if context {
        match address.field {
            ComparisonField::ConflictPosition => {
                address.entry.is_some() && address.member.is_some()
            }
            ComparisonField::Conflicts => address.member.is_none(),
            ComparisonField::Applicability
            | ComparisonField::Question
            | ComparisonField::AssumptionsAvailability
            | ComparisonField::PredictionRefsAvailability
            | ComparisonField::DependencyRefsAvailability
            | ComparisonField::CurrentPosition
            | ComparisonField::Temporal
            | ComparisonField::Lineage
            | ComparisonField::CommonMode
            | ComparisonField::SupportObservations
            | ComparisonField::CausalReadings
            | ComparisonField::SupportingClaims
            | ComparisonField::CounterevidenceClaims
            | ComparisonField::RevisionConditions
            | ComparisonField::InvalidationConditions
            | ComparisonField::SuccessfulTransfers
            | ComparisonField::FailedTransfers
            | ComparisonField::DownstreamEffects => {
                address.entry.is_none() && address.member.is_none()
            }
            _ => false,
        }
    } else {
        match address.field {
            ComparisonField::CommonModeRoot => address.entry.is_none() && address.member.is_some(),
            ComparisonField::CausalLineage
            | ComparisonField::Explanations
            | ComparisonField::SupportingClaims
            | ComparisonField::CounterevidenceClaims
            | ComparisonField::RevisionConditions
            | ComparisonField::InvalidationConditions
            | ComparisonField::SuccessfulTransfers
            | ComparisonField::FailedTransfers
            | ComparisonField::DownstreamEffects
            | ComparisonField::CommonModeClaims
            | ComparisonField::Assumptions
            | ComparisonField::SupportObservations
            | ComparisonField::CausalReadings
            | ComparisonField::SourceLineage => address.entry.is_some() && address.member.is_none(),
            ComparisonField::ConflictCommonLineage => {
                address.entry.is_some() && address.member.is_some()
            }
            _ => false,
        }
    };
    if !shape_ok {
        return Err(RivalModelError::InvalidContract("comparison.address_shape"));
    }
    if let Some(kind) = kind {
        let allowed = match kind {
            SharedInputKind::Claim => matches!(
                address.field,
                ComparisonField::Explanations
                    | ComparisonField::SupportingClaims
                    | ComparisonField::CounterevidenceClaims
                    | ComparisonField::RevisionConditions
                    | ComparisonField::InvalidationConditions
                    | ComparisonField::SuccessfulTransfers
                    | ComparisonField::FailedTransfers
                    | ComparisonField::DownstreamEffects
                    | ComparisonField::CommonModeClaims
            ),
            SharedInputKind::Assumption => address.field == ComparisonField::Assumptions,
            SharedInputKind::SupportRecord => address.field == ComparisonField::SupportObservations,
            SharedInputKind::CausalRecord => address.field == ComparisonField::CausalReadings,
            SharedInputKind::SourceOwner => address.field == ComparisonField::SourceLineage,
            SharedInputKind::CommonModeRoot => matches!(
                address.field,
                ComparisonField::CommonModeRoot
                    | ComparisonField::CausalLineage
                    | ComparisonField::ConflictCommonLineage
            ),
        };
        if !allowed {
            return Err(RivalModelError::InvalidContract("comparison.kind_field"));
        }
    }
    Ok(())
}

fn validate_requirement_addresses(
    result: &RivalModelSet,
    declarations: Option<&RivalDeclarationSet>,
) -> Result<(), RivalModelError> {
    for requirement in &result.discriminator_search.requirements {
        let Some(assessment) = result.assessments.get(requirement.model_row as usize) else {
            return Err(RivalModelError::InvalidContract("discriminator.model_row"));
        };
        if matches!(assessment.disposition, ModelDisposition::Unavailable { .. })
            && requirement.prediction_ref_entry.is_some()
        {
            return Err(RivalModelError::InvalidContract(
                "discriminator.unavailable_model_entry",
            ));
        }
        match requirement.facet {
            DiscriminatorRequirementFacet::ModelFrontier
            | DiscriminatorRequirementFacet::PredictionReferences => {
                if requirement.prediction_ref_entry.is_some() {
                    return Err(RivalModelError::InvalidContract(
                        "discriminator.model_facet_entry",
                    ));
                }
            }
            DiscriminatorRequirementFacet::Expected | DiscriminatorRequirementFacet::Falsifier => {
                if requirement.prediction_ref_entry.is_none() {
                    return Err(RivalModelError::InvalidContract(
                        "discriminator.prediction_ref_entry",
                    ));
                }
            }
        }
        if let Some(peer) = requirement.peer {
            let Some(peer_assessment) = result.assessments.get(peer.model_row as usize) else {
                return Err(RivalModelError::InvalidContract("discriminator.peer_row"));
            };
            if matches!(
                peer_assessment.disposition,
                ModelDisposition::Unavailable { .. }
            ) && peer.prediction_ref_entry.is_some()
            {
                return Err(RivalModelError::InvalidContract(
                    "discriminator.unavailable_peer_entry",
                ));
            }
        }
        let Some(declarations) = declarations else {
            continue;
        };
        let Some(slot) = declarations.models.get(requirement.model_row as usize) else {
            return Err(RivalModelError::InvalidContract("discriminator.model_row"));
        };
        if matches!(
            requirement.facet,
            DiscriminatorRequirementFacet::Expected | DiscriminatorRequirementFacet::Falsifier
        ) {
            let entry =
                requirement
                    .prediction_ref_entry
                    .ok_or(RivalModelError::InvalidContract(
                        "discriminator.prediction_ref_entry",
                    ))?;
            let RivalModelSlot::Retained { declaration } = slot else {
                return Err(RivalModelError::InvalidContract(
                    "discriminator.prediction_model",
                ));
            };
            let DeclarationAvailability::Supplied { entries } = &declaration.prediction_refs else {
                return Err(RivalModelError::InvalidContract(
                    "discriminator.prediction_refs",
                ));
            };
            if entries.get(entry as usize).is_none() {
                return Err(RivalModelError::InvalidContract(
                    "discriminator.prediction_ref_entry",
                ));
            }
        }
        if let Some(peer) = requirement.peer {
            let Some(peer_slot) = declarations.models.get(peer.model_row as usize) else {
                return Err(RivalModelError::InvalidContract("discriminator.peer_row"));
            };
            if let Some(entry) = peer.prediction_ref_entry {
                let RivalModelSlot::Retained { declaration } = peer_slot else {
                    return Err(RivalModelError::InvalidContract("discriminator.peer_model"));
                };
                let DeclarationAvailability::Supplied { entries } = &declaration.prediction_refs
                else {
                    return Err(RivalModelError::InvalidContract("discriminator.peer_refs"));
                };
                if entries.get(entry as usize).is_none() {
                    return Err(RivalModelError::InvalidContract("discriminator.peer_entry"));
                }
            }
        }
    }
    Ok(())
}

fn validate_discriminator_records(result: &RivalModelSet) -> Result<(), RivalModelError> {
    for discriminator in &result.discriminators {
        discriminator
            .expected_model
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("discriminator.expected_model"))?;
        discriminator
            .falsifying_model
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("discriminator.falsifying_model"))?;
        discriminator
            .expected_prediction
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("discriminator.expected_prediction"))?;
        discriminator
            .falsifying_prediction
            .validate()
            .map_err(|_| RivalModelError::InvalidContract("discriminator.falsifying_prediction"))?;
        if discriminator.expected_model.model_id == discriminator.falsifying_model.model_id {
            return Err(RivalModelError::InvalidContract("discriminator.same_model"));
        }
        let expected = retained_assessment(result, &discriminator.expected_model)?;
        let falsifying = retained_assessment(result, &discriminator.falsifying_model)?;
        let (Some(expected_class), Some(falsifying_class)) =
            (expected.equivalence_class, falsifying.equivalence_class)
        else {
            return Err(RivalModelError::InvalidContract(
                "discriminator.missing_equivalence_class",
            ));
        };
        if expected_class == falsifying_class {
            return Err(RivalModelError::InvalidContract(
                "discriminator.same_equivalence_class",
            ));
        }
    }
    Ok(())
}

fn retained_assessment<'a>(
    result: &'a RivalModelSet,
    reference: &RivalModelRef,
) -> Result<&'a RivalModelAssessment, RivalModelError> {
    let Some(assessment) = result
        .assessments
        .iter()
        .find(|assessment| assessment.model_id == reference.model_id)
    else {
        return Err(RivalModelError::InvalidContract(
            "discriminator.model_assessment",
        ));
    };
    if !matches!(assessment.disposition, ModelDisposition::Retained)
        || assessment.model_revision != Some(reference.model_revision)
        || assessment.declaration_digest.as_deref() != Some(reference.declaration_digest.as_str())
    {
        return Err(RivalModelError::IdentityMismatch(
            "discriminator.model_binding",
        ));
    }
    Ok(assessment)
}

fn skeleton_assessments(declarations: &RivalDeclarationSet) -> Vec<RivalModelAssessment> {
    let mut assessments = Vec::with_capacity(declarations.models.len());
    for slot in &declarations.models {
        match slot {
            RivalModelSlot::Retained { declaration } => assessments.push(RivalModelAssessment {
                model_id: declaration.model_id.clone(),
                model_revision: Some(declaration.model_revision),
                declaration_digest: Some(declaration.digest.clone()),
                disposition: ModelDisposition::Omitted {
                    reason: ModelOmissionReason::AnalysisWorkFrontier,
                },
                material_projection_digest: None,
                equivalence_class: None,
            }),
            RivalModelSlot::Unavailable {
                model_id,
                model_revision,
                declaration_digest,
                ..
            } => assessments.push(RivalModelAssessment {
                model_id: model_id.clone(),
                model_revision: *model_revision,
                declaration_digest: declaration_digest.clone(),
                disposition: ModelDisposition::Unavailable {
                    reason: ModelUnavailableReason::BodyUnavailable,
                },
                material_projection_digest: None,
                equivalence_class: None,
            }),
        }
    }
    assessments
}

fn initial_model_details(
    declarations: &RivalDeclarationSet,
) -> Result<Vec<RivalModelDetail>, RivalModelError> {
    declarations
        .models
        .iter()
        .enumerate()
        .map(|(source_row, slot)| {
            let source_row = u32::try_from(source_row).map_err(|_| RivalModelError::Bound {
                field: "result.model_details.source_row",
                maximum: u32::MAX as usize,
                actual: source_row,
            })?;
            Ok(match slot {
                RivalModelSlot::Retained { .. } => RivalModelDetail::Omitted {
                    source_row,
                    reason: ModelBodyOmissionReason::OutputBytes,
                },
                RivalModelSlot::Unavailable { .. } => RivalModelDetail::Unavailable { source_row },
            })
        })
        .collect()
}

fn omitted_count(assessments: &[RivalModelAssessment]) -> usize {
    assessments
        .iter()
        .filter(|assessment| matches!(assessment.disposition, ModelDisposition::Omitted { .. }))
        .count()
}

enum ProbeResult {
    Fits(usize),
    Exhausted(ModelBodyOmissionReason),
}

fn bounded_probe(measured: Result<usize, RivalModelError>) -> Result<ProbeResult, RivalModelError> {
    match measured {
        Ok(bytes) => Ok(ProbeResult::Fits(bytes)),
        Err(RivalModelError::Bound { field, .. }) => {
            Ok(ProbeResult::Exhausted(if field == "result.packing_work" {
                ModelBodyOmissionReason::WorkBudget
            } else {
                ModelBodyOmissionReason::OutputBytes
            }))
        }
        Err(error) => Err(error),
    }
}

fn source_set_details(
    declarations: &RivalDeclarationSet,
) -> Result<Vec<RivalModelDetail>, RivalModelError> {
    declarations
        .models
        .iter()
        .enumerate()
        .map(|(source_row, slot)| {
            let source_row = source_row_u32(source_row)?;
            Ok(match slot {
                RivalModelSlot::Retained { .. } => RivalModelDetail::SourceSet { source_row },
                RivalModelSlot::Unavailable { .. } => RivalModelDetail::Unavailable { source_row },
            })
        })
        .collect()
}

fn pack_model_bodies(
    result: &mut RivalModelSet,
    declarations: &RivalDeclarationSet,
    ceiling: usize,
    ledger: &mut packing::PackingLedger,
    meter: &mut OperationMeter,
) -> Result<(), RivalModelError> {
    result.declarations = None;
    push_section(
        &mut result.omission_frontier.sections,
        OutputSection::SourceDeclarations,
    );
    let mut bodies: Vec<Option<Box<RivalModelDeclaration>>> =
        (0..declarations.models.len()).map(|_| None).collect();
    let mut reasons = vec![Some(ModelBodyOmissionReason::OutputBytes); declarations.models.len()];
    let mut retained_rows = Vec::new();
    let mut stopped = false;
    for (source_row, slot) in declarations.models.iter().enumerate() {
        let RivalModelSlot::Retained { declaration } = slot else {
            reasons[source_row] = None;
            continue;
        };
        if stopped {
            reasons[source_row] = Some(ModelBodyOmissionReason::WorkBudget);
            continue;
        }
        let mut selected = retained_rows.clone();
        selected.push(source_row);
        let borrowed = borrowed_model_details(declarations, &selected, &reasons)?;
        let probe = bounded_probe(packing::preflight_with_model_details(
            result,
            &borrowed,
            ceiling,
            meter,
            Some(&declaration.model_id),
        ))?;
        let bytes = match probe {
            ProbeResult::Fits(bytes) => bytes,
            ProbeResult::Exhausted(reason) => {
                reasons[source_row] = Some(reason);
                stopped = reason == ModelBodyOmissionReason::WorkBudget;
                continue;
            }
        };
        if !ledger.admit(bytes, meter)? {
            reasons[source_row] = Some(ModelBodyOmissionReason::WorkBudget);
            meter.mark_packing_frontier(&declaration.model_id);
            stopped = true;
            continue;
        }
        match bounded_probe(packing::preflight_model_body(declaration, ceiling, meter))? {
            ProbeResult::Fits(bytes) => {
                if !matches!(
                    meter.charge_materialization(bytes, Some(&declaration.model_id))?,
                    MeterCharge::Charged
                ) {
                    reasons[source_row] = Some(ModelBodyOmissionReason::WorkBudget);
                    meter.mark_packing_frontier(&declaration.model_id);
                    stopped = true;
                    continue;
                }
                reasons[source_row] = None;
                bodies[source_row] = Some(declaration.clone());
                retained_rows.push(source_row);
            }
            ProbeResult::Exhausted(ModelBodyOmissionReason::OutputBytes) => {
                reasons[source_row] = Some(ModelBodyOmissionReason::OutputBytes);
            }
            ProbeResult::Exhausted(ModelBodyOmissionReason::WorkBudget) => {
                reasons[source_row] = Some(ModelBodyOmissionReason::WorkBudget);
                stopped = true;
            }
        }
    }
    result.model_details = declarations
        .models
        .iter()
        .enumerate()
        .map(|(source_index, slot)| {
            let source_row = source_row_u32(source_index)?;
            Ok(match slot {
                RivalModelSlot::Unavailable { .. } => RivalModelDetail::Unavailable { source_row },
                RivalModelSlot::Retained { .. } => match bodies[source_row as usize].take() {
                    Some(declaration) => RivalModelDetail::Retained {
                        source_row,
                        declaration,
                    },
                    None => RivalModelDetail::Omitted {
                        source_row,
                        reason: reasons[source_row as usize]
                            .unwrap_or(ModelBodyOmissionReason::OutputBytes),
                    },
                },
            })
        })
        .collect::<Result<_, RivalModelError>>()?;
    if result.disposition != RivalModelDisposition::InsufficientRivals {
        result.disposition = RivalModelDisposition::Partial;
    }
    Ok(())
}

fn borrowed_model_details<'a>(
    declarations: &'a RivalDeclarationSet,
    retained_rows: &[usize],
    reasons: &[Option<ModelBodyOmissionReason>],
) -> Result<Vec<packing::BorrowedModelDetail<'a>>, RivalModelError> {
    declarations
        .models
        .iter()
        .enumerate()
        .map(|(source_index, slot)| {
            let source_row = source_row_u32(source_index)?;
            Ok(match slot {
                RivalModelSlot::Unavailable { .. } => {
                    packing::BorrowedModelDetail::Unavailable { source_row }
                }
                RivalModelSlot::Retained { declaration }
                    if retained_rows.contains(&source_index) =>
                {
                    packing::BorrowedModelDetail::Retained {
                        source_row,
                        declaration,
                    }
                }
                RivalModelSlot::Retained { .. } => packing::BorrowedModelDetail::Omitted {
                    source_row,
                    reason: reasons[source_index].unwrap_or(ModelBodyOmissionReason::OutputBytes),
                },
            })
        })
        .collect()
}

fn source_row_u32(source_row: usize) -> Result<u32, RivalModelError> {
    u32::try_from(source_row).map_err(|_| RivalModelError::Bound {
        field: "result.model_details.source_row",
        maximum: u32::MAX as usize,
        actual: source_row,
    })
}

fn sync_meter_frontier(result: &mut RivalModelSet, meter: &OperationMeter) {
    let Some(frontier) = meter.frontier() else {
        return;
    };
    if result.omission_frontier.exhausted_stage.is_some()
        && frontier.stage != WorkStage::ResultPacking
    {
        return;
    }
    result.omission_frontier.exhausted_stage = Some(frontier.stage);
    if frontier.model_id.is_some() {
        result
            .omission_frontier
            .exhausted_model_id
            .clone_from(&frontier.model_id);
    }
    if frontier.prediction_id.is_some() {
        result
            .omission_frontier
            .exhausted_prediction_id
            .clone_from(&frontier.prediction_id);
    }
    if frontier.pair.is_some() {
        result
            .omission_frontier
            .exhausted_pair
            .clone_from(&frontier.pair);
    }
    if frontier.prediction_pair.is_some() {
        result
            .omission_frontier
            .exhausted_prediction_pair
            .clone_from(&frontier.prediction_pair);
    }
}

fn reset_to_skeleton(
    result: &mut RivalModelSet,
    declarations: &RivalDeclarationSet,
) -> Result<(), RivalModelError> {
    reset_comparison_to_skeleton(result);
    result.declarations = None;
    result.assessments = skeleton_assessments(declarations);
    result.model_details = initial_model_details(declarations)?;
    result.equivalence_classes.clear();
    result.discriminators.clear();
    result.discriminator_search = DiscriminatorSearch::not_started();
    result.omitted_count = omitted_count(&result.assessments);
    result.distinct_material_classes = 0;
    result.disposition = RivalModelDisposition::InsufficientRivals;
    result.omission_frontier.model_ids = result
        .assessments
        .iter()
        .filter_map(|assessment| match &assessment.disposition {
            ModelDisposition::Omitted { .. } => Some(RivalModelRef {
                model_id: assessment.model_id.clone(),
                model_revision: assessment.model_revision?,
                declaration_digest: assessment.declaration_digest.clone()?,
            }),
            _ => None,
        })
        .collect();
    result.omission_frontier.model_ids.sort();
    push_section(
        &mut result.omission_frontier.sections,
        OutputSection::SourceDeclarations,
    );
    push_section(
        &mut result.omission_frontier.sections,
        OutputSection::AnalysisWork,
    );
    Ok(())
}

fn reset_comparison_to_skeleton(result: &mut RivalModelSet) {
    let previous = std::mem::replace(
        &mut result.comparison,
        ComparisonMap {
            completion: ComparisonCompletion::NotStarted,
            phase: crate::comparison::ComparisonPhase::Walk,
            frontier: None,
            model_context: Vec::new(),
            groups: Vec::new(),
        },
    );
    let first_discarded = previous
        .model_context
        .first()
        .copied()
        .or_else(|| {
            previous
                .groups
                .first()
                .and_then(|group| group.occurrences.first().copied())
        })
        .or(previous.frontier);
    if previous.completion == ComparisonCompletion::Bounded {
        result.comparison = ComparisonMap {
            completion: ComparisonCompletion::Bounded,
            phase: previous.phase,
            frontier: previous.frontier,
            model_context: Vec::new(),
            groups: Vec::new(),
        };
        push_section(
            &mut result.omission_frontier.sections,
            OutputSection::Comparisons,
        );
    } else if previous.completion == ComparisonCompletion::Complete && first_discarded.is_some() {
        result.comparison = ComparisonMap {
            completion: ComparisonCompletion::Bounded,
            phase: crate::comparison::ComparisonPhase::Output,
            frontier: first_discarded,
            model_context: Vec::new(),
            groups: Vec::new(),
        };
        push_section(
            &mut result.omission_frontier.sections,
            OutputSection::Comparisons,
        );
    } else {
        result.comparison = previous;
        result
            .omission_frontier
            .sections
            .retain(|section| *section != OutputSection::Comparisons);
    }
}

fn push_section(sections: &mut Vec<OutputSection>, section: OutputSection) {
    if !sections.contains(&section) {
        sections.push(section);
    }
}

#[derive(Serialize)]
struct SetIdentity<'a> {
    validated_input_digest: &'a str,
    bundle_digest: &'a str,
    task_id: &'a TaskId,
    scope: &'a str,
    state_fence: &'a StateFence,
    current_position: &'a CurrentPositionBinding,
    policy_id: &'a str,
    policy_digest: &'a str,
    source_set: &'a SourceSetRef,
}

fn derive_set_id_from_bindings(identity: &SetIdentity<'_>) -> Result<ArtifactId, RivalModelError> {
    let bytes = eliot_dreamer_contracts::canonical_bytes(identity)
        .map_err(|_| RivalModelError::InvalidContract("result.set_id.preimage"))?;
    ArtifactId::new(format!(
        "rival-set:{}",
        eliot_dreamer_contracts::digest_hex(&bytes)
    ))
    .map_err(|_| RivalModelError::InvalidContract("result.set_id"))
}

fn frontier_is_empty(frontier: &OmissionFrontier) -> bool {
    frontier.model_ids.is_empty()
        && frontier.sections.is_empty()
        && frontier.exhausted_stage.is_none()
        && frontier.exhausted_model_id.is_none()
        && frontier.exhausted_prediction_id.is_none()
        && frontier.exhausted_pair.is_none()
        && frontier.exhausted_prediction_pair.is_none()
}

fn coverage_status(declaration: &RivalCoverageDeclaration) -> CoverageStatus {
    match declaration {
        RivalCoverageDeclaration::Unknown { .. } => CoverageStatus::Unknown,
        RivalCoverageDeclaration::Supplied {
            denominator,
            receipt: RivalCoverageReceipt::Supplied { receipt },
        } if denominator.kind == DenominatorKind::CompleteScope && receipt.is_terminal() => {
            CoverageStatus::Complete
        }
        RivalCoverageDeclaration::Supplied { .. } => CoverageStatus::Partial,
    }
}
