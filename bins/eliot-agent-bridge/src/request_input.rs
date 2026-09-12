//! Private bounded acquisition profile for the Agent Bridge stdin transport.
//!
//! Issue #977 owns the parser and dispatch cutover. This module freezes the
//! independent outer-record and decoder-resource ceilings before the existing
//! `Request` enum is exposed to a streaming decoder. It grants no authority and
//! performs no dispatch.

/// Stable identity of the private input profile.
pub(crate) const REQUEST_INPUT_PROFILE_ID: &str = "eliot.agent-bridge.request-input.v1";

/// Action after an oversized record is detected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OversizeDisposition {
    /// Discard bytes without buffering until one line terminator is observed,
    /// then emit one typed rejection and continue with the next record.
    DiscardThroughTerminator,
}

/// Independent bounds for one bridge process and one encoded request record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestInputProfile {
    /// Maximum encoded bytes in one complete newline-delimited JSON record,
    /// excluding the line terminator.
    pub max_record_bytes: usize,
    /// Maximum bytes retained by the acquisition and decoder layers together.
    pub max_buffered_bytes: usize,
    /// Maximum UTF-8 bytes in any one decoded JSON string before typed request
    /// validation applies its narrower field-specific limits.
    pub max_json_string_bytes: usize,
    /// Maximum items in any one decoded array or object.
    pub max_container_items: usize,
    /// Maximum total scalar values in one decoded record.
    pub max_scalar_values: usize,
    /// Maximum JSON nesting depth.
    pub max_nesting_depth: usize,
    /// Maximum requests accepted during one process lifetime.
    pub max_requests_per_process: u64,
    /// Maximum consecutive malformed or oversized records before fail-closed
    /// termination. A valid record resets this counter.
    pub max_consecutive_invalid_records: u32,
    /// Maximum bytes discarded after an oversized record before the process
    /// terminates because record resynchronization was not proven.
    pub max_oversize_discard_bytes: usize,
    /// Maximum idle interval before bounded shutdown.
    pub idle_timeout_ms: u64,
    /// Maximum process lifetime independent of request activity.
    pub lifetime_timeout_ms: u64,
    /// Declared oversized-record recovery policy.
    pub oversize_disposition: OversizeDisposition,
}

/// Reviewed candidate profile for the first bounded stdin implementation.
///
/// The 1 MiB outer record limit is intentionally separate from every nested
/// MCP/host-contract limit. The 2 MiB aggregate buffer ceiling permits one
/// complete record plus bounded decoder state without permitting two unbounded
/// records to accumulate. Oversize resynchronization is bounded to 4 MiB; a
/// missing terminator beyond that point terminates the process.
pub(crate) const REQUEST_INPUT_PROFILE: RequestInputProfile = RequestInputProfile {
    max_record_bytes: 1_048_576,
    max_buffered_bytes: 2_097_152,
    max_json_string_bytes: 524_288,
    max_container_items: 4_096,
    max_scalar_values: 16_384,
    max_nesting_depth: 64,
    max_requests_per_process: 65_536,
    max_consecutive_invalid_records: 8,
    max_oversize_discard_bytes: 4_194_304,
    idle_timeout_ms: 300_000,
    lifetime_timeout_ms: 86_400_000,
    oversize_disposition: OversizeDisposition::DiscardThroughTerminator,
};

/// Intrinsic profile defect detected before stdin acquisition begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestInputProfileError {
    ZeroBound,
    BufferSmallerThanRecord,
    StringLargerThanRecord,
    DiscardSmallerThanRecord,
    IdleExceedsLifetime,
}

impl RequestInputProfile {
    /// Validates internal relationships between independent limits.
    pub(crate) const fn validate(self) -> Result<(), RequestInputProfileError> {
        if self.max_record_bytes == 0
            || self.max_buffered_bytes == 0
            || self.max_json_string_bytes == 0
            || self.max_container_items == 0
            || self.max_scalar_values == 0
            || self.max_nesting_depth == 0
            || self.max_requests_per_process == 0
            || self.max_consecutive_invalid_records == 0
            || self.max_oversize_discard_bytes == 0
            || self.idle_timeout_ms == 0
            || self.lifetime_timeout_ms == 0
        {
            return Err(RequestInputProfileError::ZeroBound);
        }
        if self.max_buffered_bytes < self.max_record_bytes {
            return Err(RequestInputProfileError::BufferSmallerThanRecord);
        }
        if self.max_json_string_bytes > self.max_record_bytes {
            return Err(RequestInputProfileError::StringLargerThanRecord);
        }
        if self.max_oversize_discard_bytes < self.max_record_bytes {
            return Err(RequestInputProfileError::DiscardSmallerThanRecord);
        }
        if self.idle_timeout_ms > self.lifetime_timeout_ms {
            return Err(RequestInputProfileError::IdleExceedsLifetime);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_profile_is_intrinsically_valid() {
        assert_eq!(REQUEST_INPUT_PROFILE.validate(), Ok(()));
        assert_eq!(REQUEST_INPUT_PROFILE_ID, "eliot.agent-bridge.request-input.v1");
    }

    #[test]
    fn independent_limit_relationships_fail_closed() {
        let mut profile = REQUEST_INPUT_PROFILE;
        profile.max_buffered_bytes = profile.max_record_bytes - 1;
        assert_eq!(
            profile.validate(),
            Err(RequestInputProfileError::BufferSmallerThanRecord)
        );

        let mut profile = REQUEST_INPUT_PROFILE;
        profile.max_json_string_bytes = profile.max_record_bytes + 1;
        assert_eq!(
            profile.validate(),
            Err(RequestInputProfileError::StringLargerThanRecord)
        );

        let mut profile = REQUEST_INPUT_PROFILE;
        profile.max_oversize_discard_bytes = profile.max_record_bytes - 1;
        assert_eq!(
            profile.validate(),
            Err(RequestInputProfileError::DiscardSmallerThanRecord)
        );
    }
}
