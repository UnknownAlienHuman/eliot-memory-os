//! Canonical rendered payload bytes and measurement closure.

use eliot_context_contracts::{
    ActiveUnderstandingView, CONTEXT_CONTRACT_VERSION, CapacityLimits, ContextBinding,
    ContextError, MeasurementStatus, RenderedAtom, SerializedContextMeasurement,
};
use eliot_contracts::{ContractVersion, canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::AssemblyError;

#[derive(Serialize)]
struct CanonicalRenderedPayload<'a> {
    schema_version: ContractVersion,
    binding: &'a ContextBinding,
    recipe_digest: &'a str,
    fence_digest: &'a str,
    rendered: &'a [RenderedAtom],
}

pub(crate) fn final_bytes(
    binding: &ContextBinding,
    recipe_digest: &str,
    fence_digest: &str,
    rendered: &[RenderedAtom],
) -> Result<Vec<u8>, AssemblyError> {
    let payload = CanonicalRenderedPayload {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding,
        recipe_digest,
        fence_digest,
        rendered,
    };
    canonical_json_bytes(&payload)
        .map_err(|_| AssemblyError::Contract(ContextError::InvalidField("view.canonical_payload")))
}

pub(crate) fn verify(
    measurement: SerializedContextMeasurement,
    binding: &ContextBinding,
    bytes: &[u8],
    output_digest: &str,
    capacity: &CapacityLimits,
    policy: &crate::AssemblyPolicy,
    max_bytes: u64,
) -> Result<SerializedContextMeasurement, AssemblyError> {
    crate::bounds::measurement(&measurement)?;
    measurement.validate()?;
    if measurement.schema_version != CONTEXT_CONTRACT_VERSION {
        return Err(AssemblyError::Contract(ContextError::InvalidField(
            "measurement.schema_version",
        )));
    }
    if measurement.status != MeasurementStatus::ExactUtf8 {
        return Err(AssemblyError::Contract(ContextError::UnknownMeasurement));
    }
    let length =
        u64::try_from(bytes.len()).map_err(|_| AssemblyError::Contract(ContextError::Overflow))?;
    if length > max_bytes {
        return Err(AssemblyError::Bounds("assembly.final_bytes"));
    }
    if measurement.context != *binding {
        return Err(AssemblyError::MeasurementMismatch("context"));
    }
    if measurement.envelope_digest != output_digest {
        return Err(AssemblyError::MeasurementMismatch("envelope_digest"));
    }
    if measurement.rendered_utf8_bytes != length {
        return Err(AssemblyError::MeasurementMismatch("rendered_utf8_bytes"));
    }
    if measurement.fixed_overhead != capacity.fixed_overhead
        || measurement.output_reserve != capacity.output_reserve
        || measurement.review_reserve != capacity.review_reserve
    {
        return Err(AssemblyError::MeasurementMismatch("capacity_reserves"));
    }
    if measurement.serializer_id != policy.serializer_id
        || measurement.serializer_version != policy.serializer_version
        || measurement.serializer_options_digest != policy.serializer_options_digest
        || measurement.route_id != policy.route_id
        || measurement.model_id != policy.model_id
        || measurement.status != policy.measurement_status
    {
        return Err(AssemblyError::MeasurementMismatch("measurement_identity"));
    }
    if !measurement.proves_fit(capacity.route_capacity)? {
        return Err(AssemblyError::Contract(ContextError::CapacityExceeded));
    }
    Ok(measurement)
}

pub(crate) fn canonical_matches(
    binding: &ContextBinding,
    recipe_digest: &str,
    fence_digest: &str,
    rendered: &[RenderedAtom],
) -> Result<(String, Vec<u8>), AssemblyError> {
    let bytes = final_bytes(binding, recipe_digest, fence_digest, rendered)?;
    let expected = ActiveUnderstandingView::canonical_output_digest(
        binding,
        recipe_digest,
        fence_digest,
        rendered,
    )?;
    if sha256_hex(&bytes) != expected {
        return Err(AssemblyError::MeasurementMismatch("canonical_payload"));
    }
    Ok((expected, bytes))
}
