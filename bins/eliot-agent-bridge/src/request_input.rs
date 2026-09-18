//! Binary-private bounded acquisition profile for the Agent Bridge stdin transport.
//!
//! Slice A of issue #977 freezes the outer-record acquisition ceiling and the
//! fail-closed framing policy before the existing `Request` enum is exposed to
//! a streaming decoder. This module grants no authority and performs no
//! dispatch: duplicate-key / escape-equivalent member rejection and detailed
//! depth / member enforcement are deferred to later slices, as are the
//! compatibility fixtures.
//!
//! Bridge-local decisions: the 1 MiB outer-record ceiling
//! (`max_record_bytes`), the 2 MiB aggregate buffer ceiling
//! (`max_buffered_bytes`), and the 4 MiB oversize-resynchronization bound
//! (`max_oversize_discard_bytes`) are new Bridge-local acquisition decisions
//! made for this stdin boundary. I7.2's 4 MiB frame default is NOT reused as
//! the Bridge stdin-line limit: a transport frame, a JSON outer line, and a
//! decoded body are distinct budgets, and neither that default nor the 64 KiB
//! hot-response / 256 KiB structured-response figures can be reused as request
//! limits.
//!
//! Time bounds (`idle_timeout_ms`, `lifetime_timeout_ms`) are declared here so
//! the profile is complete, but they are NOT enforced on blocking stdin by
//! this slice: a byte / work bound on returned chunks does not prove a
//! wall-clock deadline on a blocking read, and enforcement needs a separately
//! supported transport mechanism. No deadline is claimed.

/// Stable identity of the private input profile.
pub(crate) const REQUEST_INPUT_PROFILE_ID: &str = "eliot.agent-bridge.request-input.v1";

/// Action taken after an oversized record is detected.
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
    /// Maximum idle interval before bounded shutdown (declared, not enforced
    /// on blocking stdin by this slice).
    pub idle_timeout_ms: u64,
    /// Maximum process lifetime independent of request activity (declared, not
    /// enforced on blocking stdin by this slice).
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
/// missing terminator beyond that point terminates the process. These three
/// values are new Bridge-local decisions; I7.2's 4 MiB frame default is not
/// reused here.
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

/// Outcome of one bounded record acquisition.
///
/// A `Record` payload never exceeds the profile's outer-record ceiling and is
/// always valid UTF-8; anything else is reported as a typed framing outcome
/// that must be rejected without dispatch.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ReadOutcome {
    /// One complete newline-delimited record with the terminator and a single
    /// trailing carriage return removed.
    Record(Vec<u8>),
    /// End of input with no pending bytes.
    Eof,
    /// The record exceeded the outer-record ceiling. Buffering stopped
    /// immediately at detection; `discarded_bytes` counts only the bytes
    /// consumed while resynchronizing (including the terminator when found),
    /// never the dropped prefix and never request content.
    Oversize {
        discarded_bytes: usize,
        found_terminator: bool,
    },
    /// A complete within-bound framed record that is not valid UTF-8.
    InvalidUtf8,
}

/// Reads one newline-delimited record without ever buffering past the
/// profile's outer-record ceiling.
///
/// The ceiling is enforced incrementally with checked arithmetic while
/// collecting, before any `String` / `Value` allocation. LF terminates a
/// record; a single trailing CR is stripped as part of a CRLF terminator, and
/// neither terminator byte counts toward the ceiling. A final record at EOF
/// without a newline is returned when within bound. A complete within-bound
/// record that is not valid UTF-8 yields `InvalidUtf8`. An overlong record
/// stops buffering immediately and is resynchronized according to the
/// profile's oversize disposition without buffering during discard.
pub(crate) fn read_bounded_record<R: std::io::BufRead>(
    reader: &mut R,
    profile: RequestInputProfile,
) -> std::io::Result<ReadOutcome> {
    let mut record: Vec<u8> = Vec::new();
    loop {
        let (content_len, consume_len, terminated) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                if record.is_empty() {
                    return Ok(ReadOutcome::Eof);
                }
                if std::str::from_utf8(&record).is_err() {
                    return Ok(ReadOutcome::InvalidUtf8);
                }
                return Ok(ReadOutcome::Record(record));
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(newline) => {
                    let mut content_len = newline;
                    if content_len > 0 && available[content_len - 1] == b'\r' {
                        content_len -= 1;
                    }
                    (content_len, newline.saturating_add(1), true)
                }
                None => (available.len(), available.len(), false),
            }
        };
        if terminated {
            let Some(combined_len) = record.len().checked_add(content_len) else {
                return discard_oversize_record(reader, profile);
            };
            if combined_len > profile.max_record_bytes {
                return discard_oversize_record(reader, profile);
            }
            {
                let available = reader.fill_buf()?;
                record.extend_from_slice(&available[..content_len]);
            }
            reader.consume(consume_len);
            if content_len == 0 && record.last() == Some(&b'\r') {
                // A CRLF terminator split across buffer fills: the carriage
                // return was buffered as content by an earlier chunk because
                // the newline had not been observed yet. Removing it keeps
                // split and unsplit CRLF identical; both terminator bytes stay
                // excluded from the ceiling since removal only shrinks the
                // already-bounded record.
                record.pop();
            }
            if std::str::from_utf8(&record).is_err() {
                return Ok(ReadOutcome::InvalidUtf8);
            }
            return Ok(ReadOutcome::Record(record));
        }
        let Some(combined_len) = record.len().checked_add(content_len) else {
            return discard_oversize_record(reader, profile);
        };
        if combined_len > profile.max_record_bytes {
            return discard_oversize_record(reader, profile);
        }
        {
            let available = reader.fill_buf()?;
            record.extend_from_slice(&available[..content_len]);
        }
        reader.consume(consume_len);
    }
}

/// Stops buffering an overlong record and resynchronizes per the profile's
/// declared oversize disposition.
///
/// Only `DiscardThroughTerminator` exists, so both overlong exits route
/// through it; the exhaustive match keeps a future disposition from compiling
/// here silently. The already-collected prefix (at most `max_record_bytes`)
/// is dropped with the outcome and no bytes are buffered during discard.
fn discard_oversize_record<R: std::io::BufRead>(
    reader: &mut R,
    profile: RequestInputProfile,
) -> std::io::Result<ReadOutcome> {
    let (discarded_bytes, found_terminator) = match profile.oversize_disposition {
        OversizeDisposition::DiscardThroughTerminator => {
            discard_through_terminator(reader, profile.max_oversize_discard_bytes)?
        }
    };
    Ok(ReadOutcome::Oversize {
        discarded_bytes,
        found_terminator,
    })
}

/// Consumes bytes without buffering until one `\n` is observed.
///
/// Returns the discard-phase byte count with checked accumulation alongside
/// whether the terminator was found within budget. EOF, checked-addition
/// overflow, or budget exhaustion without a terminator all report
/// `found_terminator` as false so the caller fails closed.
fn discard_through_terminator<R: std::io::BufRead>(
    reader: &mut R,
    max_discard_bytes: usize,
) -> std::io::Result<(usize, bool)> {
    let mut discarded_bytes: usize = 0;
    loop {
        let (consume_len, found) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok((discarded_bytes, false));
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(newline) => (newline.saturating_add(1), true),
                None => (available.len(), false),
            }
        };
        if found {
            let Some(next) = discarded_bytes.checked_add(consume_len) else {
                return Ok((discarded_bytes, false));
            };
            if next > max_discard_bytes {
                let remaining = max_discard_bytes.saturating_sub(discarded_bytes);
                reader.consume(remaining);
                return Ok((max_discard_bytes, false));
            }
            reader.consume(consume_len);
            return Ok((next, true));
        }
        let Some(next) = discarded_bytes.checked_add(consume_len) else {
            return Ok((discarded_bytes, false));
        };
        if next >= max_discard_bytes {
            let remaining = max_discard_bytes.saturating_sub(discarded_bytes);
            reader.consume(remaining);
            return Ok((max_discard_bytes, false));
        }
        reader.consume(consume_len);
        discarded_bytes = next;
    }
}
