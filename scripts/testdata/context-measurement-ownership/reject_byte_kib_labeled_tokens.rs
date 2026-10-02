// Frozen fixture for #787 case 12: a byte/KiB value LABELED as tokens.
//
// The audit rejects "byte/KiB value labeled tokens" and "STU/byte ratios as
// actual tokens". A raw byte length and a KiB figure are assigned to fields
// whose names claim tokens, and the KiB conversion is fed straight into a
// `token_units` field. The #866 classifier must reject the conversion as
// `bare_measurement_field_or_conversion` and the oracle must report the
// resulting unit/name mismatch.
pub struct PayloadAccounting {
    pub payload_utf8: u64,
    pub token_units: u64,
    pub context_cost: u64,
}

pub fn account_payload(text: &str) -> PayloadAccounting {
    let payload_utf8 = text.len() as u64;
    let token_units = payload_utf8 / 1024;
    let context_cost = (payload_utf8 / 1024) as usize;
    PayloadAccounting {
        payload_utf8,
        token_units,
        context_cost,
    }
}
