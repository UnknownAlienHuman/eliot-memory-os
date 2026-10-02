//! Canonical rendered payload bytes and measurement closure.

use eliot_context_contracts::{
    ActiveUnderstandingView, AdmittedContextSet, CONTEXT_CONTRACT_VERSION, CapacityLimits,
    ContextBinding, ContextError, ContextRecipe, MeasurementStatus, QualityScorecard, RenderedAtom,
    ResolvedContextRecipe, SerializedContextMeasurement, canonical_render_serializer,
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
/// [`compile_context_render_codec`] before any byte is rendered, so `verify`
/// compares the render owner against the render owner rather than two
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
    approved: &ResolvedContextRecipe,
    quality: QualityScorecard,
    policy: &AssemblyPolicy,
    params: &MeasurementParams,
) -> Result<ActiveUnderstandingViewResult, AssemblyError> {
    // The render owner's identity is issued once and consumed once on this
    // path, before any byte is rendered. Nothing below can be reached under a
    // policy that names a codec the owner did not issue.
    compile_context_render_codec(policy)?;
    assemble_active_view(admitted, recipe, approved, quality, policy, |bytes| {
        measure_exact_utf8(bytes, params)
    })
}

/// Bind one route's declared codec triple to the canonical render owner.
///
/// #1862 BLOCK-2. I2.16:168 places `serializer_id_version_and_options` on the
/// `SerializedContextMeasurement` record that profile qualification compares
/// against, and I2.16:163 requires that "Context admission and profile
/// qualification use the exact bytes that the selected route will receive".
/// Those bytes are produced by the codec
/// [`canonical_render_serializer`] publishes, so this is where the ROUTE half
/// of that record is consumed: the triple `AssemblyPolicy` declares is
/// compared against the owner record itself, before any byte is rendered and
/// before the measurement callback runs.
///
/// This is the production consumer of the render owner on the route that
/// actually issues a measurement. This cell is the composition that forms the
/// `|bytes| measure_exact_utf8(bytes, &params)` callback
/// ([`assemble_active_view_with_measurement`]), so this module is where the
/// route's own triple and the owner record meet; the previous bind lived only
/// in `require_context_render_codec` inside
/// `bins/eliotd/src/kernel_context_read_client.rs`, behind
/// `KernelContextReadClient::compile_context_packet`, which has no call site in
/// the tree and therefore issued no measurement at all.
///
/// The owner record is issued once per call by the single producer
/// ([`canonical_render_serializer`]) and consumed immediately by `binds`. It is
/// never cached on this cell, never copied out of `policy`, and never
/// reconstructed, and the owner type publishes no constructor, so a route
/// cannot hold a second identity to compare a measurement against. The record
/// is drawn fresh from the sole producer and spent inside this one call; it is
/// never retained on the route, so a second comparison would have to draw a
/// second record from the same single producer and could not be handed a
/// substitute.
///
/// Both sides are compared as recorded. Nothing is recomputed to stand in for
/// `policy`, and a policy naming another codec, another revision or another
/// options digest is REFUSED rather than re-described or normalised into the
/// owner's values, so this can only ever narrow what a route may assert.
///
/// # Errors
///
/// Returns [`AssemblyError::Contract`] carrying
/// [`ContextError::IdentityConflict`] when the policy names another codec,
/// another revision or another options digest, and carrying
/// [`ContextError::InvalidField`] when either the owner record or a declared
/// member does not satisfy its own closed contract. Both are the existing typed
/// errors this crate already returns; neither is collapsed into a string or a
/// boolean.
pub fn compile_context_render_codec(policy: &AssemblyPolicy) -> Result<(), AssemblyError> {
    canonical_render_serializer()?
        .binds(
            &policy.serializer_id,
            &policy.serializer_version,
            &policy.serializer_options_digest,
        )
        .map_err(AssemblyError::Contract)
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
