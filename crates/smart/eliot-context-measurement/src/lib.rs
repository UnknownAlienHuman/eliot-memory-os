//! Exact UTF-8 measurement for one canonical rendered context payload.
//!
//! This crate owns the sole #704 measurement operation consumed by
//! `eliot-context-assembly::assemble_active_view` as its
//! `measure: FnOnce(&[u8]) -> Result<SerializedContextMeasurement, ContextError>`
//! callback. It measures the exact payload bytes as UTF-8, derives the
//! envelope digest with SHA-256, and keeps the three route-cost signals
//! distinct:
//!
//! * exact `rendered_utf8_bytes` proves route fit;
//! * `stu_estimate` remains a conservative estimate and never proves fit;
//! * `tokenizer` remains an observation from an actually-run route tokenizer
//!   and is never fabricated locally.
//!
//! There is no byte/3 fallback and no tokenizer synthesis. A non-UTF-8
//! payload, an oversized payload, or an invalid binding is refused with a
//! typed [`ContextError`]. The operation is leaf-local and pure: no I/O,
//! no retrieval, no ranking, no admission, no persistence.

#![forbid(unsafe_code)]

use eliot_context_contracts::{
    CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding, ContextError, MeasurementStatus,
    SerializedContextMeasurement, StuEstimate, TokenizerObservation,
};
use eliot_contracts::{ArtifactId, sha256_hex};

/// Maximum canonical payload bytes accepted by one measurement operation.
///
/// This is a leaf-local denial bound, not a route admission decision. The
/// caller route bound in [`MeasurementParams::max_serialized_bytes`] applies
/// first when it is smaller.
pub const MAX_MEASUREMENT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum bytes retained from one caller-supplied identity string before
/// contract validation.
pub const MAX_IDENTITY_TEXT_BYTES: usize = 1_048_576;

/// Caller-owned immutable parameters for one exact measurement.
///
/// `stu_estimate` and `tokenizer` are passed through unchanged when present.
/// Supply `None` unless the value was empirically observed for this payload;
/// this crate never derives an STU estimate from the byte count and never
/// synthesizes a tokenizer observation.
#[derive(Clone, Debug)]
pub struct MeasurementParams {
    /// Stable identity for the produced measurement record.
    pub measurement_id: ArtifactId,
    /// Task/scope/fence binding the measured payload must satisfy.
    pub context: ContextBinding,
    /// Required serializer identity, matching the assembly route policy.
    pub serializer_id: String,
    /// Required serializer revision, matching the assembly route policy.
    pub serializer_version: String,
    /// Required serializer-options digest (lowercase SHA-256 hex).
    pub serializer_options_digest: String,
    /// Required route identity.
    pub route_id: String,
    /// Required model/tokenizer route identity.
    pub model_id: String,
    /// Independent route capacity components carrying the reserves.
    pub capacity: CapacityLimits,
    /// Conservative STU estimate, when empirically observed elsewhere.
    pub stu_estimate: Option<StuEstimate>,
    /// Exact tokenizer observation, only when the route tokenizer ran.
    pub tokenizer: Option<TokenizerObservation>,
    /// False-safe overflow identity, when the caller tracks one.
    pub false_safe_overflow: Option<ArtifactId>,
    /// False-rejection/decomposition identity, when the caller tracks one.
    pub false_rejection_or_decomposition: Option<ArtifactId>,
    /// Expiry identity, when the caller tracks one.
    pub valid_until: Option<ArtifactId>,
    /// Maximum canonical payload bytes accepted by this route.
    pub max_serialized_bytes: u64,
}

fn preflight_text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.len() > MAX_IDENTITY_TEXT_BYTES {
        return Err(ContextError::Bounds { field });
    }
    Ok(())
}

/// Measure one canonical rendered payload as exact UTF-8 bytes.
///
/// The returned [`SerializedContextMeasurement`] always carries
/// [`MeasurementStatus::ExactUtf8`], `rendered_utf8_bytes` equal to
/// `payload.len()`, and `envelope_digest` equal to `sha256_hex(payload)`.
/// The caller-supplied `stu_estimate` and `tokenizer` are preserved as data
/// and never influence the byte count.
///
/// Use as the assembly callback by capturing the parameters:
/// `|bytes| measure_exact_utf8(bytes, &params)`.
pub fn measure_exact_utf8(
    payload: &[u8],
    params: &MeasurementParams,
) -> Result<SerializedContextMeasurement, ContextError> {
    if params.max_serialized_bytes == 0 {
        return Err(ContextError::Bounds {
            field: "measurement.max_serialized_bytes",
        });
    }
    let rendered =
        u64::try_from(payload.len()).map_err(|_| ContextError::Overflow)?;
    if rendered > MAX_MEASUREMENT_BYTES {
        return Err(ContextError::Bounds {
            field: "measurement.rendered_bytes",
        });
    }
    if rendered > params.max_serialized_bytes {
        return Err(ContextError::Bounds {
            field: "measurement.rendered_bytes",
        });
    }
    std::str::from_utf8(payload)
        .map_err(|_| ContextError::InvalidField("measurement.payload_utf8"))?;
    params.context.validate()?;
    params.capacity.validate()?;
    preflight_text(&params.serializer_id, "measurement.serializer_id")?;
    preflight_text(
        &params.serializer_version,
        "measurement.serializer_version",
    )?;
    preflight_text(&params.route_id, "measurement.route_id")?;
    preflight_text(&params.model_id, "measurement.model_id")?;
    let measurement = SerializedContextMeasurement {
        measurement_id: params.measurement_id.clone(),
        context: params.context.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: sha256_hex(payload),
        serializer_id: params.serializer_id.clone(),
        serializer_version: params.serializer_version.clone(),
        serializer_options_digest: params.serializer_options_digest.clone(),
        route_id: params.route_id.clone(),
        model_id: params.model_id.clone(),
        rendered_utf8_bytes: rendered,
        stu_estimate: params.stu_estimate,
        tokenizer: params.tokenizer.clone(),
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: params.capacity.fixed_overhead,
        output_reserve: params.capacity.output_reserve,
        review_reserve: params.capacity.review_reserve,
        false_safe_overflow: params.false_safe_overflow.clone(),
        false_rejection_or_decomposition: params
            .false_rejection_or_decomposition
            .clone(),
        valid_until: params.valid_until.clone(),
    };
    measurement.validate()?;
    Ok(measurement)
}
