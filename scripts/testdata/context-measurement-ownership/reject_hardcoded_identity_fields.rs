// Frozen fixture for #787 audit section 4, bullet 4 GAP 3: the identity conjunct
// is satisfied by FIELD NAMES only. `serializer`, `route` and `tokenizer` are all
// present (so the old name-only conjunct holds), the payload is a real non-empty
// final serialized byte payload, and `declared_len` is the real length -- but the
// identity sub-records are HARD-CODED INTEGERS (1, 1, 1): no ID, no version, no
// hash, no provider, no model. The content digest is the literal placeholder
// "sha256:00".
//
// This MUST be REJECTED. The issue asks the binding to carry "provider/model/
// tokenizer ID/version/hash and content digest"; a name spelled beside a
// fabricated integer is not that binding.
//
// Before the repair `PORT_IDENTITY_BINDING_FIELDS` was only ("serializer",
// "route", "tokenizer"), matched as bare substrings of the enclosing item's
// masked span, so this site was ACCEPTED with no ID, no version, no hash, no
// provider, no model and a literal "sha256:00" content digest.
use eliot_context_measurement::{SerializedContextInputs, measure_serialized_context};

pub fn measure_hardcoded_identity(payload: &[u8]) -> Result<u64, String> {
    let inputs = SerializedContextInputs {
        measurement_id: "measurement".to_string(),
        declared_len: payload.len() as u64,
        content_digest: "sha256:00",
        serializer: 1,
        route: 1,
        tokenizer: 1,
        max_serialized_bytes: u64::MAX,
    };
    let measured = measure_serialized_context(payload, &inputs)
        .map_err(|error| format!("{error:?}"))?;
    Ok(measured.measurement.rendered_utf8_bytes)
}