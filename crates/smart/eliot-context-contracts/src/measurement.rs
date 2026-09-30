//! Exact byte, conservative STU and optional tokenizer observations.

use eliot_contracts::{ArtifactId, ContractVersion, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContextBinding, ContextError, QualityDimension, QualityDimensionResult, QualityInvalidation,
    QualityInvalidationReason, QualityScorecard, SourceSnapshot, QUALITY_DIMENSIONS, validate_digest,
    validate_text,
};

/// Whether a measurement is independently qualified for capacity decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementStatus {
    ExactUtf8,
    ConservativeStu,
    ExactTokenizer,
    Unknown,
    Unavailable,
}

/// Conservative Source Token Unit estimate. It never proves route fit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StuEstimate {
    pub value: u64,
    pub empirical: bool,
}

/// Exact tokenizer observation when the route tokenizer was actually run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenizerObservation {
    pub tokenizer_id: String,
    pub tokenizer_version: String,
    pub tokenizer_hash: String,
    pub tokens: u64,
}

/// Exact serialized Context measurement and its qualified binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SerializedContextMeasurement {
    pub measurement_id: ArtifactId,
    pub context: ContextBinding,
    pub schema_version: ContractVersion,
    pub envelope_digest: String,
    pub serializer_id: String,
    pub serializer_version: String,
    pub serializer_options_digest: String,
    pub route_id: String,
    pub model_id: String,
    pub rendered_utf8_bytes: u64,
    pub stu_estimate: Option<StuEstimate>,
    pub tokenizer: Option<TokenizerObservation>,
    pub status: MeasurementStatus,
    pub fixed_overhead: u64,
    pub output_reserve: u64,
    pub review_reserve: u64,
    pub false_safe_overflow: Option<ArtifactId>,
    pub false_rejection_or_decomposition: Option<ArtifactId>,
    pub valid_until: Option<ArtifactId>,
    /// Digest of the recipe revision this packet was compiled under.
    ///
    /// This measurement is the record of *what was produced*, and the governing
    /// policy that produced it is part of that. A card records the same value on
    /// its output binding, so the two are independent records of one governing
    /// revision: a re-observation compiled under a different recipe differs
    /// here even when every other recorded value agrees, which is what makes a
    /// governing-instruction change observable instead of silent.
    pub recipe_digest: String,
    /// Source snapshots the measured packet carried, in admitted order.
    ///
    /// This measurement is the owner of the route identity, and a route is
    /// served from a named set of source snapshots. The exact snapshots the
    /// route read therefore have to be readable from the record that describes
    /// that route: without them nothing downstream can tell which source
    /// revision a grade was read from, and a source change becomes invisible
    /// exactly where the route identity is already being checked.
    ///
    /// Each entry is the admitted source's own [`SourceSnapshot`], projected
    /// with no change to a load-bearing field (the same projection
    /// `RenderedAtom::from_admitted` applies), so the recorded
    /// `snapshot_id` and `revision` are the source owner's own values.
    pub sources: Vec<SourceSnapshot>,
    /// Verifier contract revisions in force per graded dimension on this route.
    ///
    /// Empty means this route declares no verifier identity, which is reported
    /// as absent rather than inferred: a dimension with no declared verifier
    /// has no verifier revision to compare, and inventing one would let an
    /// absent declaration invalidate a grade.
    ///
    /// A repeated dimension states no additional verifier identity, so the
    /// dimension is the key and the list carries one entry per dimension.
    pub verifier_rule_revisions: Vec<(QualityDimension, ArtifactId)>,
}

impl SerializedContextMeasurement {
    /// Validate bindings and distinguish unknown from measured zero.
    pub fn validate(&self) -> Result<(), ContextError> {
        self.context.validate()?;
        validate_digest(&self.envelope_digest, "measurement.envelope_digest")?;
        validate_digest(
            &self.serializer_options_digest,
            "measurement.serializer_options_digest",
        )?;
        validate_text(&self.serializer_id, "measurement.serializer_id")?;
        validate_text(&self.serializer_version, "measurement.serializer_version")?;
        validate_text(&self.route_id, "measurement.route_id")?;
        validate_text(&self.model_id, "measurement.model_id")?;
        let _ = self
            .fixed_overhead
            .checked_add(self.output_reserve)
            .and_then(|v| v.checked_add(self.review_reserve))
            .ok_or(ContextError::Overflow)?;
        if matches!(self.status, MeasurementStatus::ConservativeStu) && self.stu_estimate.is_none()
        {
            return Err(ContextError::UnknownMeasurement);
        }
        if matches!(self.status, MeasurementStatus::ExactTokenizer) && self.tokenizer.is_none() {
            return Err(ContextError::UnknownMeasurement);
        }
        if let Some(tokenizer) = &self.tokenizer {
            validate_text(&tokenizer.tokenizer_id, "measurement.tokenizer_id")?;
            validate_text(
                &tokenizer.tokenizer_version,
                "measurement.tokenizer_version",
            )?;
            validate_digest(&tokenizer.tokenizer_hash, "measurement.tokenizer_hash")?;
        }
        validate_digest(&self.recipe_digest, "measurement.recipe_digest")?;
        // The source snapshots are this route's own source records, so each is
        // validated by its own owner rather than trusted because it is here.
        // A repeated snapshot states no additional source revision, so a
        // duplicated entry cannot pose as wider source coverage.
        let mut snapshots = std::collections::BTreeSet::new();
        for source in &self.sources {
            source.validate()?;
            if !snapshots.insert(source.snapshot_id.clone()) {
                return Err(ContextError::Duplicate("measurement.sources"));
            }
        }
        // The dimension is the key here too: a repeated dimension would state
        // two different verifier revisions for one graded dimension.
        let mut verifier_dimensions = std::collections::BTreeSet::new();
        for (dimension, rule_revision) in &self.verifier_rule_revisions {
            if !QUALITY_DIMENSIONS.contains(dimension)
                || !verifier_dimensions.insert(*dimension)
            {
                return Err(ContextError::Duplicate("measurement.verifier_rule_revisions"));
            }
            validate_text(
                rule_revision.as_str(),
                "measurement.verifier_rule_revisions.rule_revision",
            )?;
        }
        Ok(())
    }

    /// Exact UTF-8 byte count for a serialized string.
    #[must_use]
    pub fn utf8_bytes(serialized: &str) -> u64 {
        serialized.len() as u64
    }

    /// Return whether this observation can prove capacity fit.
    pub fn proves_fit(&self, capacity: u64) -> Result<bool, ContextError> {
        self.validate()?;
        let measured = match self.status {
            MeasurementStatus::ExactUtf8 => self.rendered_utf8_bytes,
            MeasurementStatus::ExactTokenizer => {
                self.tokenizer
                    .as_ref()
                    .ok_or(ContextError::UnknownMeasurement)?
                    .tokens
            }
            MeasurementStatus::ConservativeStu
            | MeasurementStatus::Unknown
            | MeasurementStatus::Unavailable => return Err(ContextError::UnknownMeasurement),
        };
        let total = self
            .fixed_overhead
            .checked_add(self.output_reserve)
            .and_then(|v| v.checked_add(self.review_reserve))
            .and_then(|v| v.checked_add(measured))
            .ok_or(ContextError::Overflow)?;
        Ok(total <= capacity)
    }

    /// Re-evaluate one recorded card against this re-observation and mark every
    /// grade whose recorded owner dependency now differs.
    ///
    /// This measurement is the record that owns the route identity, and a route
    /// carries the exact source snapshots it served from and the verifier
    /// revision in force per dimension, so this is the one place where a
    /// recorded card and a re-observation can disagree about those. Both
    /// arguments are full measurements carrying the route identity, so both
    /// sides of every comparison are recorded values of the same owner field.
    ///
    /// The reasons are evaluated against
    /// [`QualityInvalidationReason::INVALIDATION_REASONS`], the independent
    /// denominator declared by the reason type. A caller does not choose which
    /// reasons run. A reason this re-observation declares nothing for produces
    /// no invalidation rather than one built from an invented value.
    ///
    /// Returns the exact results that were marked, or `None` when the
    /// re-observation agrees with the card on every reason. The card is not
    /// touched in that case, so a re-evaluation that finds nothing new never
    /// rewrites history.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when this measurement, the observed
    /// measurement, or the card fails its own validation, so a malformed
    /// record is never compared field by field.
    pub fn reevaluate_against(
        observed: &SerializedContextMeasurement,
        card: &mut QualityScorecard,
    ) -> Result<Option<Vec<QualityDimensionResult>>, ContextError> {
        observed.validate()?;
        let observed = observed.recorded_invalidations(card)?;
        card.mark_invalidated(&observed)
    }

    /// The invalidations this re-observation observes against a recorded card.
    ///
    /// Every value compared is read from a record: the graded side from the
    /// card, the current side from this measurement. No digest is recomputed
    /// and no value is synthesised to stand in for an absent one, so an absent
    /// declaration is reported as absent and cannot invalidate a grade.
    fn recorded_invalidations(
        &self,
        card: &QualityScorecard,
    ) -> Result<Vec<QualityInvalidation>, ContextError> {
        card.validate()?;
        let mut observed = Vec::new();
        for reason in QualityInvalidationReason::INVALIDATION_REASONS {
            observed.extend(self.recorded_invalidation(reason, card)?);
        }
        Ok(observed)
    }

    /// The invalidations one reason observes against a recorded card, in
    /// canonical dimension order. Empty when this re-observation agrees with
    /// the card on that reason, or declares nothing for it.
    fn recorded_invalidation(
        &self,
        reason: QualityInvalidationReason,
        card: &QualityScorecard,
    ) -> Result<Vec<QualityInvalidation>, ContextError> {
        // `Verifier` compares per result, because its graded value is that
        // result's own `rule_revision` rather than one card-wide value. Every
        // other reason compares one recorded value on each side, so it
        // invalidates the whole card at once.
        if reason == QualityInvalidationReason::Verifier {
            let mut observed = Vec::new();
            for result in &card.results {
                let Some((_, revision)) = self
                    .verifier_rule_revisions
                    .iter()
                    .find(|(dimension, _)| *dimension == result.dimension)
                else {
                    // No verifier revision is declared for this dimension on
                    // this re-observation, so there is nothing to compare it
                    // against and no value is invented for one.
                    continue;
                };
                let graded_value = result.rule_revision.as_str().to_owned();
                let current_value = revision.as_str().to_owned();
                if graded_value == current_value {
                    continue;
                }
                observed.push(QualityInvalidation {
                    reason,
                    dimension: result.dimension,
                    graded_value,
                    current_value,
                });
            }
            return Ok(observed);
        }
        let (graded_value, current_value) = match reason {
            QualityInvalidationReason::Route => {
                (card.output.route_id.clone(), self.route_id.clone())
            }
            // The governing policy revision. The graded side is the recipe
            // digest the card records; the current side is the recipe digest
            // this re-observation was compiled under. `card.output.fence_digest`
            // is deliberately NOT used here: `ActiveUnderstandingView::validate`
            // already requires the card's fence digest to equal the packet's own
            // fence, so comparing it would compare one value with a copy of
            // itself and could never fire.
            QualityInvalidationReason::GoverningInstruction => {
                (card.output.recipe_digest.clone(), self.recipe_digest.clone())
            }
            // The source revisions. The graded side is the source-revision set
            // the card records; the current side is the set this route read. The
            // admitted payload digest is deliberately not used on either side:
            // `require_graded_output` already binds the card's admitted digest to
            // this exact admitted set, so a differing source set could not reach
            // here through assembly, and comparing digests instead of the source
            // revisions would hide the reason behind a different label.
            QualityInvalidationReason::Source => (
                card.output
                    .evidence_revisions
                    .iter()
                    .map(|revision| revision.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.sources
                    .iter()
                    .map(|source| format!("{}@{}", source.snapshot_id.as_str(), source.revision))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            // The task/acceptance revision. It is bound to the card's own
            // `ContextBinding` on the graded side and to this re-observation's
            // binding on the current side, which is the recorded field that
            // carries `task_revision` on both records.
            QualityInvalidationReason::Task => (
                fence_revision(card.binding.state_fence.task_revision),
                fence_revision(self.context.state_fence.task_revision),
            ),
            // Handled above; excluded from the single-value reasons by
            // `INVALIDATION_REASONS`, so there is no fourth spelling to keep in
            // step with this one.
            QualityInvalidationReason::Verifier => {
                return Err(ContextError::InvalidField("quality.invalidation.reason"));
            }
        };
        if graded_value == current_value {
            return Ok(Vec::new());
        }
        // A single recorded difference invalidates every dimension on the card,
        // because every one of the twelve was graded under the same route,
        // binding and source set. Narrowing it to a subset would leave a
        // dimension reading as a current pass on a packet it was never graded
        // against.
        Ok(card
            .results
            .iter()
            .map(|result| QualityInvalidation {
                reason,
                dimension: result.dimension,
                graded_value: graded_value.clone(),
                current_value: current_value.clone(),
            })
            .collect())
    }
}

/// Render one optional fence revision as a comparable recorded value.
///
/// An absent revision is reported as the closed token `none`, not as an empty
/// string: a blank value would satisfy [`crate::validate_text`] as unequal to
/// nothing and would make two different absent revisions look like a change
/// while also making it impossible to read the recorded value back.
fn fence_revision(revision: Option<TaskRevision>) -> String {
    match revision {
        Some(revision) => revision.value().to_string(),
        None => "none".to_owned(),
    }
}
