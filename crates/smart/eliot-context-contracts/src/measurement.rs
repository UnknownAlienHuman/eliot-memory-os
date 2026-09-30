//! Exact byte, conservative STU and optional tokenizer observations.

use eliot_contracts::{ArtifactId, ContractVersion};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextBinding, ContextError, validate_digest, validate_text};

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

/// The revisions that produced one serialized Context output.
///
/// #1724 W4/W5: the rendered-ordering revision, the serializer identity and
/// options digest, the route and model identity, and the measurement status all
/// change what bytes leave this compilation, and none of them was named by any
/// delivered record: two compilations of the same admitted set under different
/// ordering or serializer revisions produced two byte-identical views. This
/// record is what the executing path states it applied, so the output identity
/// a consumer re-checks includes the execution that produced it.
///
/// The values are the executing path's own, never a caller's claim about
/// another path: the assembly owner fills this from the ordering revision it
/// compiled in and the policy it validated, and
/// [`ContextExecutionIdentity::binds_measurement`] compares it against the
/// independently recorded [`SerializedContextMeasurement`] of the same view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextExecutionIdentity {
    /// Stable ordering revision the rendered projection was produced under.
    pub ordering_revision: String,
    /// Serializer identity that produced the delivered bytes.
    pub serializer_id: String,
    /// Serializer revision that produced the delivered bytes.
    pub serializer_version: String,
    /// Serializer-options digest the delivered bytes were produced with.
    pub serializer_options_digest: String,
    /// Route identity the delivered bytes were produced for.
    pub route_id: String,
    /// Model/tokenizer route identity the delivered bytes were produced for.
    pub model_id: String,
    /// Measurement status qualified for this route.
    pub measurement_status: MeasurementStatus,
}

impl ContextExecutionIdentity {
    /// Validate the closed execution record.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.ordering_revision, "execution.ordering_revision")?;
        validate_text(&self.serializer_id, "execution.serializer_id")?;
        validate_text(&self.serializer_version, "execution.serializer_version")?;
        validate_text(&self.route_id, "execution.route_id")?;
        validate_text(&self.model_id, "execution.model_id")?;
        validate_digest(
            &self.serializer_options_digest,
            "execution.serializer_options_digest",
        )
    }

    /// Require that the independently recorded measurement is this execution's.
    ///
    /// The ORIGINAL recorded values of both records are compared. No digest is
    /// recomputed to stand in for the measurement, and this execution identity
    /// is not an input to any digest the measurement is checked against, so the
    /// comparison cannot be satisfied by a record describing itself.
    pub fn binds_measurement(
        &self,
        measurement: &SerializedContextMeasurement,
    ) -> Result<(), ContextError> {
        self.validate()?;
        measurement.validate()?;
        if self.serializer_id != measurement.serializer_id
            || self.serializer_version != measurement.serializer_version
            || self.serializer_options_digest != measurement.serializer_options_digest
            || self.route_id != measurement.route_id
            || self.model_id != measurement.model_id
            || self.measurement_status != measurement.status
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
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
