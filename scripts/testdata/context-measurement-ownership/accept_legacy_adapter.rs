// Bounded accept fixture: an exact, closed, versioned legacy adapter.
//
// The pre-migration byte/4 ratio survives only as a named, versioned, closed
// adapter with a declared expiry. It is quarantined, never widened, and never
// re-opened. While the expiry has not passed and the caller's route is the one
// exact legacy profile it was qualified for, it is an accepted adapter rather
// than an unaccounted estimator.

pub const LEGACY_ADAPTER_ID: &str = "context-bytes-div4-legacy";
pub const LEGACY_ADAPTER_VERSION: u32 = 1;
pub const LEGACY_ADAPTER_EXPIRES_AT_MS: u64 = 1_800_000_000_000;

pub struct LegacyAdapterReceipt {
    pub adapter_id: &'static str,
    pub adapter_version: u32,
    pub expires_at_ms: u64,
    pub estimated_tokens: u64,
    pub actual_tokens: Option<u64>,
}

pub fn legacy_bytes_div4_adapter(
    route_id: &str,
    serialized_bytes: u64,
    now_ms: u64,
) -> Result<LegacyAdapterReceipt, ContextError> {
    if now_ms >= LEGACY_ADAPTER_EXPIRES_AT_MS {
        return Err(ContextError::LegacyAdapterExpired);
    }
    if route_id != "legacy-profile-1" {
        return Err(ContextError::LegacyAdapterRouteMismatch);
    }
    Ok(LegacyAdapterReceipt {
        adapter_id: LEGACY_ADAPTER_ID,
        adapter_version: LEGACY_ADAPTER_VERSION,
        expires_at_ms: LEGACY_ADAPTER_EXPIRES_AT_MS,
        estimated_tokens: serialized_bytes.div_ceil(4),
        actual_tokens: None,
    })
}
