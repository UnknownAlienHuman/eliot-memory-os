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
//!
//! The canonical #704 entrypoint is [`measure_serialized_context`], which
//! measures one exact serialized Context envelope and additionally owns the
//! normative `STU(bytes) = ceil(UTF-8 byte length / 3)` estimate (computed
//! once by [`stu::stu_for_bytes`]), immutable observation validation,
//! unit-compatible capacity/error analysis and deterministic receipt
//! construction. It returns exact A-15 values plus the package-local
//! analysis; [`measure_exact_utf8`] remains available as the narrow
//! byte-measurement callback shape consumed by context assembly.

#![forbid(unsafe_code)]

pub mod capacity;
pub mod envelope;
pub mod error_analysis;
pub mod observation;
pub mod receipt;
pub mod stu;

pub use capacity::{CapacityAnalysis, CapacityPlan, StuToTokenPolicy, analyze_capacity};
pub use envelope::{SerializerIdentity, ValidatedEnvelope, validate_envelope};
pub use error_analysis::{ErrorAnalysis, ZeroObservationRule, analyze_error};
pub use observation::{
    ExactObservation, ObservationExpectation, ObservationInput, ObservationSource,
    ObservationStatus, ProviderRewrite, ProviderRewriteKind, TokenizerIdentity,
    ValidatedObservation, validate_observation,
};
pub use receipt::{ReceiptInput, receipt_digest};
pub use stu::stu_for_bytes;

use eliot_context_contracts::{
    CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding, ContextError, MeasurementStatus,
    SerializedContextMeasurement, StuEstimate, TokenizerObservation,
};
use eliot_contracts::{ArtifactId, ContractVersion, sha256_hex};

use capacity::unit_as_str;
use envelope::{validate_digest, validate_identity_text};

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

/// Route/provider/model identity for one serialized-context measurement.
#[derive(Clone, Debug)]
pub struct RouteIdentity {
    /// Required route identity.
    pub route_id: String,
    /// Required provider identity.
    pub provider_id: String,
    /// Required model identity.
    pub model_id: String,
}

impl RouteIdentity {
    /// Validate route identity texts.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_identity_text(&self.route_id, "route.route_id")?;
        validate_identity_text(&self.provider_id, "route.provider_id")?;
        validate_identity_text(&self.model_id, "route.model_id")?;
        Ok(())
    }
}

/// Estimator policy for the normative STU estimate.
///
/// The estimator stays UNVALIDATED planning evidence: `empirical` must be
/// false, and cited Appendix-O candidate digests are evidence only. They
/// are normalized for set-order independence and can never replace
/// [`stu_for_bytes`].
#[derive(Clone, Debug)]
pub struct EstimatorPolicy {
    /// Required estimator identity.
    pub estimator_id: String,
    /// Required estimator revision; any change invalidates identity.
    pub estimator_revision: String,
    /// Must stay false: the normative estimate is not observed provider tokens.
    pub empirical: bool,
    /// Cited candidate digests (evidence only, never adopted silently).
    pub candidate_digests: Vec<String>,
}

impl EstimatorPolicy {
    /// Validate estimator identity, UNVALIDATED status and candidate shapes.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_identity_text(&self.estimator_id, "estimator.estimator_id")?;
        validate_identity_text(&self.estimator_revision, "estimator.estimator_revision")?;
        if self.empirical {
            return Err(ContextError::InvalidField("estimator.empirical"));
        }
        if self.candidate_digests.len() > 64 {
            return Err(ContextError::Bounds {
                field: "estimator.candidate_digests",
            });
        }
        for candidate in &self.candidate_digests {
            validate_digest(candidate, "estimator.candidate_digest")?;
        }
        Ok(())
    }
}

/// Canonical immutable inputs for one serialized-context measurement.
///
/// The six groups map the normative signature: exact serialized envelope
/// (`payload` plus `declared_len`/`content_digest`), serializer identity,
/// route and tokenizer identity, estimator policy, capacity and headroom,
/// and the optional observed token count.
#[derive(Clone, Debug)]
pub struct SerializedContextInputs {
    /// Stable identity for the produced measurement record.
    pub measurement_id: ArtifactId,
    /// Task/scope/fence binding the measured envelope must satisfy.
    pub context: ContextBinding,
    /// Required A-15 contract revision; only the accepted revision passes.
    pub contract_revision: ContractVersion,
    /// Declared envelope length; wrong values fail, never silently corrected.
    pub declared_len: u64,
    /// Declared envelope digest; must equal `sha256_hex(payload)`.
    pub content_digest: String,
    /// Required serializer/schema identity.
    pub serializer: SerializerIdentity,
    /// Required route/provider/model identity.
    pub route: RouteIdentity,
    /// Required route tokenizer identity.
    pub tokenizer: TokenizerIdentity,
    /// Required estimator policy (UNVALIDATED, candidates cited only).
    pub estimator: EstimatorPolicy,
    /// Capacity, reserves and decision policy for fit/headroom analysis.
    pub capacity: CapacityPlan,
    /// Optional externally-supplied observed token count.
    pub observation: ObservationInput,
    /// False-safe overflow identity, when the caller tracks one.
    pub false_safe_overflow: Option<ArtifactId>,
    /// False-rejection/decomposition identity, when the caller tracks one.
    pub false_rejection_or_decomposition: Option<ArtifactId>,
    /// Expiry identity, when the caller tracks one.
    pub valid_until: Option<ArtifactId>,
    /// Maximum canonical envelope bytes accepted by this route.
    pub max_serialized_bytes: u64,
}

/// Complete result of one serialized-context measurement: the exact A-15
/// value plus the package-local observation, capacity, error and receipt
/// analysis.
#[derive(Clone, Debug)]
pub struct ContextMeasurement {
    /// Exact A-15 measurement value (status always `ExactUtf8`).
    pub measurement: SerializedContextMeasurement,
    /// Normative `STU = ceil(bytes / 3)` estimate.
    pub stu: u64,
    /// Preserved observation outcome.
    pub observation: ObservationStatus,
    /// Observed count, present only for an exact observation.
    pub observed_tokens: Option<u64>,
    /// Evidence source class, when an exact observation was supplied.
    pub source: Option<ObservationSource>,
    /// Provider rewrite evidence, present only when transformed.
    pub rewrite: Option<ProviderRewrite>,
    /// Unit-compatible capacity fit and headroom.
    pub capacity: CapacityAnalysis,
    /// Two-direction error analysis with the explicit zero rule.
    pub error: ErrorAnalysis,
    /// Deterministic receipt digest over every load-bearing field.
    pub receipt_digest: String,
}

/// Reject identity reuse across distinct roles in one call.
///
/// Roles are compared in sorted role order so the reported duplicate is
/// deterministic regardless of construction order.
fn check_distinct_identities(roles: &[(&'static str, &ArtifactId)]) -> Result<(), ContextError> {
    let mut ordered: Vec<(&'static str, &ArtifactId)> = roles.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    for (index, (_, id)) in ordered.iter().enumerate() {
        for (other_role, other) in ordered.iter().skip(index + 1) {
            if id == other {
                return Err(ContextError::Duplicate(other_role));
            }
        }
    }
    Ok(())
}

/// Measure one exact serialized Context envelope as the sole #704 owner.
///
/// Returns the exact A-15 [`SerializedContextMeasurement`] (status always
/// [`MeasurementStatus::ExactUtf8`], `stu_estimate` always the normative
/// `ceil(bytes / 3)` with `empirical: false`, `tokenizer` populated only
/// for an exact observation) plus observation status, independent
/// reserve/fit/headroom analysis, both error directions and a deterministic
/// receipt digest. Identical semantic inputs yield identical output
/// regardless of set-like order; typed [`ContextError`] failures
/// distinguish unsupported revisions, malformed/oversized bytes,
/// length/digest mismatch, duplicate/conflicting identities, stale or
/// transformed observations, checked arithmetic, unknown/incompatible
/// units and invalid reserves. Never truncates, selects, admits, delivers
/// or mutates state.
pub fn measure_serialized_context(
    payload: &[u8],
    inputs: &SerializedContextInputs,
) -> Result<ContextMeasurement, ContextError> {
    if inputs.contract_revision != CONTEXT_CONTRACT_VERSION {
        return Err(ContextError::InvalidField("measurement.schema_version"));
    }
    let envelope = validate_envelope(
        payload,
        inputs.declared_len,
        &inputs.content_digest,
        inputs.max_serialized_bytes,
    )?;
    inputs.context.validate()?;
    inputs.serializer.validate()?;
    inputs.route.validate()?;
    inputs.tokenizer.validate()?;
    inputs.estimator.validate()?;
    let expectation = ObservationExpectation {
        binding: &inputs.context,
        envelope_digest: &envelope.digest,
        route_id: &inputs.route.route_id,
        provider_id: &inputs.route.provider_id,
        model_id: &inputs.route.model_id,
        tokenizer: &inputs.tokenizer,
        serializer: &inputs.serializer,
    };
    let observed = validate_observation(&inputs.observation, &expectation)?;
    let mut roles = vec![("measurement.measurement_id", &inputs.measurement_id)];
    if let ObservationInput::Exact(exact) = &inputs.observation {
        roles.extend(exact.identity_roles());
    }
    if let Some(policy) = &inputs.capacity.stu_to_token {
        roles.push(("capacity.policy_id", &policy.policy_id));
    }
    for (field, id) in [
        ("measurement.false_safe_overflow", &inputs.false_safe_overflow),
        (
            "measurement.false_rejection_or_decomposition",
            &inputs.false_rejection_or_decomposition,
        ),
        ("measurement.valid_until", &inputs.valid_until),
    ] {
        if let Some(id) = id {
            roles.push((field, id));
        }
    }
    check_distinct_identities(&roles)?;
    let stu = stu_for_bytes(envelope.byte_len)?;
    let analysis = analyze_capacity(
        &inputs.capacity,
        envelope.byte_len,
        stu,
        observed.tokens,
    )?;
    let error = analyze_error(
        analysis.estimated_total,
        analysis.fit,
        analysis.observed_total,
        analysis.observed_fit,
    );
    let tokenizer = match observed.status {
        ObservationStatus::Exact => observed.tokens.map(|tokens| TokenizerObservation {
            tokenizer_id: inputs.tokenizer.tokenizer_id.clone(),
            tokenizer_version: inputs.tokenizer.tokenizer_version.clone(),
            tokenizer_hash: inputs.tokenizer.tokenizer_hash.clone(),
            tokens,
        }),
        _ => None,
    };
    let measurement = SerializedContextMeasurement {
        measurement_id: inputs.measurement_id.clone(),
        context: inputs.context.clone(),
        schema_version: CONTEXT_CONTRACT_VERSION,
        envelope_digest: envelope.digest.clone(),
        serializer_id: inputs.serializer.serializer_id.clone(),
        serializer_version: inputs.serializer.serializer_version.clone(),
        serializer_options_digest: inputs.serializer.serializer_options_digest.clone(),
        route_id: inputs.route.route_id.clone(),
        model_id: inputs.route.model_id.clone(),
        rendered_utf8_bytes: envelope.byte_len,
        stu_estimate: Some(StuEstimate {
            value: stu,
            empirical: false,
        }),
        tokenizer,
        status: MeasurementStatus::ExactUtf8,
        fixed_overhead: inputs.capacity.fixed_overhead,
        output_reserve: inputs.capacity.output_reserve,
        review_reserve: inputs.capacity.review_reserve,
        false_safe_overflow: inputs.false_safe_overflow.clone(),
        false_rejection_or_decomposition: inputs
            .false_rejection_or_decomposition
            .clone(),
        valid_until: inputs.valid_until.clone(),
    };
    measurement.validate()?;
    let policy = inputs.capacity.stu_to_token.as_ref();
    let receipt = receipt_digest(&ReceiptInput {
        measurement_id: inputs.measurement_id.as_str().to_owned(),
        contract_revision: CONTEXT_CONTRACT_VERSION.to_string(),
        envelope_digest: envelope.digest.clone(),
        byte_len: envelope.byte_len,
        stu,
        serializer_id: inputs.serializer.serializer_id.clone(),
        serializer_version: inputs.serializer.serializer_version.clone(),
        serializer_options_digest: inputs.serializer.serializer_options_digest.clone(),
        route_id: inputs.route.route_id.clone(),
        provider_id: inputs.route.provider_id.clone(),
        model_id: inputs.route.model_id.clone(),
        tokenizer_id: inputs.tokenizer.tokenizer_id.clone(),
        tokenizer_version: inputs.tokenizer.tokenizer_version.clone(),
        tokenizer_hash: inputs.tokenizer.tokenizer_hash.clone(),
        tokenizer_config_digest: inputs.tokenizer.tokenizer_config_digest.clone(),
        estimator_id: inputs.estimator.estimator_id.clone(),
        estimator_revision: inputs.estimator.estimator_revision.clone(),
        estimator_empirical: inputs.estimator.empirical,
        candidate_digests: inputs.estimator.candidate_digests.clone(),
        capacity_unit: unit_as_str(inputs.capacity.unit),
        route_capacity: inputs.capacity.route_capacity,
        reserves: [
            inputs.capacity.fixed_overhead,
            inputs.capacity.output_reserve,
            inputs.capacity.review_reserve,
            inputs.capacity.tool_reserve,
            inputs.capacity.verifier_reserve,
            inputs.capacity.decision_tail_reserve,
        ],
        policy_id: policy.map(|policy| policy.policy_id.as_str().to_owned()),
        policy_digest: policy.map(|policy| policy.policy_digest.clone()),
        policy_numer: policy.map(|policy| policy.tokens_per_stu_numer),
        policy_denom: policy.map(|policy| policy.tokens_per_stu_denom),
        observation_status: observed.status.as_str(),
        source: observed.source.map(ObservationSource::as_str),
        observed_tokens: observed.tokens,
        observation_id: observed
            .observation_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        rewrite_kind: observed.rewrite.as_ref().map(|rewrite| rewrite.kind.as_str()),
        rewrite_evidence: observed.rewrite.as_ref().map(|rewrite| rewrite.evidence_digest.clone()),
        estimated_total: analysis.estimated_total,
        estimated_fit: analysis.fit,
        observed_total: analysis.observed_total,
        observed_fit: analysis.observed_fit,
        false_safe: error.false_safe_overflow,
        false_reject: error.false_reject_or_decomposition,
    });
    Ok(ContextMeasurement {
        measurement,
        stu,
        observation: observed.status,
        observed_tokens: observed.tokens,
        source: observed.source,
        rewrite: observed.rewrite,
        capacity: analysis,
        error,
        receipt_digest: receipt,
    })
}
