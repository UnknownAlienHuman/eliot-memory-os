// Frozen fixture for #787 case 25: an EXPIRED closed legacy adapter.
//
// The audit requires case 25 -- "exact closed legacy adapter with expiry
// accepted" -- and the audit's defect 5 records that the oracle cannot reach
// that disposition under any admissible input today, because no field in
// #866's closed ROW_KEYS records an adapter identity, a version bound or an
// expiry. This fixture is the consumer-side shape such an adapter would take:
// a named legacy adapter implementing the canonical port, carrying an explicit
// version and an explicit retirement date that has PASSED. It is materialised
// by the case 25 test, which asserts the CURRENT behaviour of the
// `_derive_baseline_disposition` / `_adapter_record` production path and
// reports the reachability gap rather than hiding it.
use eliot_context_measurement::measure_serialized_context;

pub const LEGACY_ADAPTER_IDENTITY: &str = "legacy-serial-token-counter";
pub const LEGACY_ADAPTER_VERSION: &str = "1.4.2";
pub const LEGACY_ADAPTER_EXPIRES: &str = "2024-06-30";

pub struct LegacyAdapter;

impl LegacyAdapter {
    pub fn measure(&self, bytes: &[u8]) -> u64 {
        let fallback = bytes.len() as u64;
        match measure_serialized_context(bytes) {
            Ok(measured) => measured.measurement.rendered_utf8_bytes,
            Err(_) => fallback,
        }
    }
}

pub fn retained_legacy_path(bytes: &[u8]) -> u64 {
    LegacyAdapter.measure(bytes)
}
