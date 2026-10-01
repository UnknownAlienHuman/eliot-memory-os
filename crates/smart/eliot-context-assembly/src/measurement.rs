//! Canonical rendered payload bytes and measurement closure.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, CONTEXT_CONTRACT_VERSION, CapacityLimits,
    ContextBinding, ContextError, ContextRecipe, MeasurementStatus, QualityScorecard, RenderedAtom,
    SerializedContextMeasurement,
};
use eliot_context_measurement::{MeasurementParams, measure_exact_utf8};
use eliot_contracts::{ContractVersion, canonical_json_bytes, sha256_hex};
use serde::Serialize;

use crate::{ActiveUnderstandingViewResult, AssemblyError, AssemblyPolicy, assemble_active_view};

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

/// Assemble one admitted set by invoking the sole #704 measurement owner.
///
/// This is the declared consumer edge from `eliot-context-measurement` to
/// this crate: it is the composition that forms the canonical
/// `|bytes| measure_exact_utf8(bytes, &params)` callback, so a route no
/// longer supplies a hand-rolled byte/3 fallback or a fabricated tokenizer
/// observation. Every load-bearing value stays caller-owned and arrives
/// through `params`; nothing here synthesizes an identity, digest, capacity
/// number, revision or timestamp.
///
/// #1862 BLOCK-2: `params` no longer carries a serializer identity at all. The
/// codec identity in the returned measurement is stamped by the Context
/// contracts owner (`canonical_render_serializer`), and the composing route's
/// `policy` triple is bound to that same owner record by
/// `require_context_render_codec` in
/// `bins/eliotd/src/kernel_context_read_client.rs` before any byte is
/// rendered, so `verify` below compares the render owner against the render
/// owner rather than two
/// caller-declared triples that could agree with each other on a codec neither
/// of them renders with.
///
/// The returned measurement is still bound to the canonical rendered payload
/// by this module's `verify` - unchanged and still authoritative - and a
/// `ContextError` from the owner stays typed as [`AssemblyError::Contract`]
/// rather than being collapsed into a string or a generic code.
///
/// [`assemble_active_view`] itself is not modified, but this entry is not
/// ceiling-equivalent to it. `AssemblyPolicy::validate` rejects only a zero
/// `max_serialized_bytes`, so the injected-callback path bounds the payload
/// by the policy alone. The owner additionally refuses a payload above its
/// own `MAX_MEASUREMENT_BYTES` (16 MiB) and above
/// `params.max_serialized_bytes`, so the effective ceiling here is
/// `min(policy.max_serialized_bytes, params.max_serialized_bytes,
/// 16 MiB)` and a payload admitted under a larger policy bound can be
/// refused here as `ContextError::Bounds`. A caller must keep
/// `params.max_serialized_bytes` consistent with its policy; this is a
/// narrowing, never a widening, and no check is skipped to reach it.
pub fn assemble_active_view_with_measurement(
    admitted: &AdmittedContextSet,
    recipe: &ContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    params: &MeasurementParams,
) -> Result<ActiveUnderstandingViewResult, AssemblyError> {
    assemble_active_view(admitted, recipe, quality, policy, |bytes| {
        measure_exact_utf8(bytes, params)
    })
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
