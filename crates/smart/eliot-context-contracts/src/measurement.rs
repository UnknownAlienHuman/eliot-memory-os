//! Exact byte, conservative STU and optional tokenizer observations.

use eliot_contracts::{ArtifactId, ContractVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContextBinding, ContextError, QualityDimension, SourceSnapshot, QUALITY_DIMENSIONS,
    validate_digest, validate_text,
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
}
