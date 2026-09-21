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

/// Complete limit/source/version/stage table for the private input profile.
///
/// Every row is either an inherited public limit (reused unchanged through the
/// real owner contract) or a new Bridge-local acquisition decision made for
/// this stdin boundary in issue #977. I7.2's 4 MiB frame default, 64 KiB
/// hot-response figure, and 256 KiB structured-response ceiling are NOT reused
/// as request limits: a transport frame, a JSON outer record, and a decoded
/// body are distinct budgets.
///
/// ```text
/// limit                          value        unit    source owner / revision          stage
/// ------------------------------ ------------ ------- ------------------------------- ----------------
/// max_record_bytes               1_048_576    bytes   NEW Bridge-local (#977, v1)      acquisition
/// max_buffered_bytes             2_097_152    bytes   NEW Bridge-local (#977, v1)      acquisition
/// max_json_string_bytes          524_288      bytes   NEW Bridge-local (#977, v1)      decode pre-scan
/// max_container_items            4_096        items   NEW Bridge-local (#977, v1)      decode pre-scan
/// max_scalar_values              16_384       values  NEW Bridge-local (#977, v1)      decode pre-scan
/// max_nesting_depth              64           levels  NEW Bridge-local (#977, v1)      decode pre-scan
/// max_requests_per_process       65_536       records NEW Bridge-local (#977, v1)      dispatch loop
/// max_consecutive_invalid_records 8           records NEW Bridge-local (#977, v1)      dispatch loop
/// max_oversize_discard_bytes     4_194_304    bytes   NEW Bridge-local (#977, v1)      resynchronization
/// idle_timeout_ms                300_000      ms      NEW declared, NOT enforced       (no transport
/// lifetime_timeout_ms            86_400_000   ms      NEW declared, NOT enforced        mechanism yet)
/// oversize_disposition           discard-     policy  NEW Bridge-local (#977, v1)      resynchronization
///                                through-
///                                terminator
/// host.correlation_id            512          bytes   eliot-mcp host.rs rev 1.0.0      typed contracts
/// host.operation_handle          2_048        bytes   eliot-mcp host.rs rev 1.0.0      typed contracts
/// host observed resource refs    32 x 2_048   items   eliot-mcp host.rs rev 1.0.0      typed contracts
/// host event cursors             16           items   eliot-mcp host.rs rev 1.0.0      typed contracts
/// host trace entries             16           items   eliot-mcp host.rs rev 1.0.0      typed contracts
/// host deadline preference       1..86.4M     ms      eliot-mcp host.rs rev 1.0.0      gateway validation
/// admitted tool variants         8 names      enum    eliot-mcp contract.rs            typed contracts
/// attach/event/fence shapes      owner rules  typed   agent-bridge-core / protocol     typed contracts
/// ```
///
/// A byte/work bound on returned chunks does not prove a wall-clock deadline
/// on blocking stdin: the two timeout rows are declared so the profile is
/// complete, but they are NOT enforced on blocking stdin by this module and no
/// slow-reader interruption is claimed without a separately supported
/// transport mechanism.
pub(crate) const REQUEST_INPUT_LIMIT_TABLE: &str = "eliot.agent-bridge.request-input.v1 limits";

/// Maximum decoded control-name characters echoed in a redacted diagnostic.
///
/// Longer names are truncated so diagnostics never echo protected bodies,
/// credentials, or oversized variant strings wholesale.
const MAX_CONTROL_NAME_CHARS: usize = 64;

/// Fail-closed rejection of one decoded record before typed construction.
///
/// Diagnostics carry only static reasons and bounded control names; they never
/// echo raw request bytes, unknown-key text, variant strings, body content, or
/// credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DecodeReject {
    /// Bytes are not well-formed JSON for this boundary.
    Malformed {
        /// Static redacted reason.
        reason: &'static str,
    },
    /// A duplicate object key was observed, comparing fully decoded key
    /// strings so escape-equivalent spellings conflict.
    DuplicateKey {
        /// Bounded decoded duplicate key name.
        key: String,
    },
    /// An explicitly unsupported operation or tool variant was observed.
    UnknownVariant {
        /// Bounded variant name.
        variant: String,
    },
    /// JSON nesting exceeds `max_nesting_depth`.
    DepthExceeded,
    /// One array/object exceeds `max_container_items`.
    TooManyMembers,
    /// The record exceeds `max_scalar_values` scalar values.
    TooManyScalars,
    /// One decoded string exceeds `max_json_string_bytes`.
    StringTooLong,
    /// Trailing bytes follow the single top-level JSON value.
    TrailingBytes,
    /// The encoded record exceeds `max_record_bytes` for direct callers.
    OversizeRecord,
    /// The presented profile identity is not the accepted profile.
    ProfileMismatch,
}

impl std::fmt::Display for DecodeReject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { reason } => {
                write!(
                    formatter,
                    "record is not a well-formed request ({REQUEST_INPUT_PROFILE_ID}): {reason}"
                )
            }
            Self::DuplicateKey { key } => {
                write!(
                    formatter,
                    "record carries a duplicate protected key ({REQUEST_INPUT_PROFILE_ID}): {key}"
                )
            }
            Self::UnknownVariant { variant } => {
                write!(
                    formatter,
                    "record carries an unsupported operation variant ({REQUEST_INPUT_PROFILE_ID}): {variant}"
                )
            }
            Self::DepthExceeded => {
                write!(
                    formatter,
                    "record nesting exceeds the admitted depth ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::TooManyMembers => {
                write!(
                    formatter,
                    "record container exceeds the admitted member bound ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::TooManyScalars => {
                write!(
                    formatter,
                    "record exceeds the admitted scalar bound ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::StringTooLong => {
                write!(
                    formatter,
                    "record string exceeds the admitted decoded bound ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::TrailingBytes => {
                write!(
                    formatter,
                    "record has trailing bytes after the request ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::OversizeRecord => {
                write!(
                    formatter,
                    "record exceeds the admitted encoded bound ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
            Self::ProfileMismatch => {
                write!(
                    formatter,
                    "input profile is not the accepted profile ({REQUEST_INPUT_PROFILE_ID})"
                )
            }
        }
    }
}

/// Requires the presented profile identity to be the accepted profile.
///
/// Any missing, unsupported, or stale profile identity fails closed without a
/// fallback, a default, or an unlimited mode.
pub(crate) fn check_profile_id(provided: &str) -> Result<(), DecodeReject> {
    if provided == REQUEST_INPUT_PROFILE_ID {
        Ok(())
    } else {
        Err(DecodeReject::ProfileMismatch)
    }
}

/// Bounded retained-scratch budget for acquisition plus one decoded record.
///
/// Returns the checked sum of the outer-record, buffered, and decoded-string
/// ceilings, or `None` when the checked arithmetic overflows. The `None` case
/// fails closed: no allocation size is derived from wrapping arithmetic.
#[must_use]
pub(crate) fn scratch_budget(profile: RequestInputProfile) -> Option<usize> {
    profile
        .max_record_bytes
        .checked_add(profile.max_buffered_bytes)?
        .checked_add(profile.max_json_string_bytes)
}

/// Truncates one decoded control name for redacted diagnostics.
fn bound_control_name(value: &str) -> String {
    value.chars().take(MAX_CONTROL_NAME_CHARS).collect()
}

/// Validates one complete framed record against the accepted profile before
/// typed `Request` construction.
///
/// Enforces, in order: profile internal consistency, presented-profile
/// binding, the encoded byte ceiling (for direct callers; acquisition already
/// enforces it incrementally), single-value JSON shape, nesting depth,
/// per-container member counts, total scalar counts, per-string decoded
/// bounds, and duplicate-key rejection with escape-equivalent comparison.
/// Opaque observation strings are measured but never interpreted: they stay
/// inert bounded data. This function grants no authority and performs no
/// dispatch.
pub(crate) fn prevalidate_record(
    text: &str,
    profile: RequestInputProfile,
) -> Result<(), DecodeReject> {
    if profile.validate().is_err() {
        return Err(DecodeReject::Malformed {
            reason: "input profile is internally inconsistent",
        });
    }
    if text.len() > profile.max_record_bytes {
        return Err(DecodeReject::OversizeRecord);
    }
    let bytes = text.as_bytes();
    let mut scanner = BoundsScanner {
        profile,
        depth: 0,
        scalars: 0,
    };
    let mut pos = skip_whitespace(bytes, 0);
    pos = scanner.parse_value(bytes, pos)?;
    pos = skip_whitespace(bytes, pos);
    if pos != bytes.len() {
        return Err(DecodeReject::TrailingBytes);
    }
    Ok(())
}

/// Maps one typed-construction failure to a redacted rejection.
///
/// Only static reasons and bounded control names cross into diagnostics; raw
/// unknown keys, variant strings, body content, and credentials are never
/// echoed wholesale through Serde errors.
pub(crate) fn classify_serde_error(error: &serde_json::Error) -> DecodeReject {
    let message = error.to_string();
    if message.starts_with("duplicate field") {
        DecodeReject::DuplicateKey {
            key: bound_control_name(&field_between_backticks(&message)),
        }
    } else if message.starts_with("unknown variant") {
        DecodeReject::UnknownVariant {
            variant: bound_control_name(&field_between_backticks(&message)),
        }
    } else if message.contains("unknown field") {
        DecodeReject::Malformed {
            reason: "request carries an unknown protected field",
        }
    } else if message.contains("missing field") {
        DecodeReject::Malformed {
            reason: "request is missing a required protected field",
        }
    } else if message.contains("invalid type") || message.contains("invalid value") {
        DecodeReject::Malformed {
            reason: "request carries a mistyped protected field",
        }
    } else {
        DecodeReject::Malformed {
            reason: "request is not a supported operation shape",
        }
    }
}

fn field_between_backticks(message: &str) -> String {
    let Some(start) = message.find('`') else {
        return "request".to_owned();
    };
    let rest = &message[start + 1..];
    let Some(end) = rest.find('`') else {
        return "request".to_owned();
    };
    bound_control_name(&rest[..end])
}

/// Every top-level envelope key admitted by the binary-private `Request`
/// contract: the discriminant plus every payload member across all variants.
///
/// Derived read-only from `bins/eliot-agent-bridge/src/main.rs` `Request`;
/// this table moves with that enum when its owner changes the operation set.
const GLOBAL_ENVELOPE_KEYS: [&str; 9] = [
    "op",
    "request",
    "event",
    "expected_connection_id",
    "new_connection_id",
    "session_id",
    "activation_generation",
    "authority_epoch",
    "fence_nonce",
];

/// Validates the top-level operation envelope before typed construction.
///
/// Serde unit variants (`status`, `stop`, `reconcile_external`) would silently
/// ignore extra members, so the exact key set is enforced here per operation:
/// attach/invoke/cancel carry exactly `request`; forward_hook/forward_event
/// carry exactly `event`; reconnect carries exactly its seven authority-claim
/// members; the terminal operations carry only `op`. Keys outside the global
/// allowlist are unknown protected fields; known keys on the wrong operation
/// are mismatched payloads. Unknown operation names are rejected with a
/// bounded control name following the shared-contract precedent, never with
/// raw body text.
pub(crate) fn check_request_envelope(
    text: &str,
    profile: RequestInputProfile,
) -> Result<(), DecodeReject> {
    let bytes = text.as_bytes();
    let mut pos = skip_whitespace(bytes, 0);
    if bytes.get(pos) != Some(&b'{') {
        return Err(DecodeReject::Malformed {
            reason: "request envelope must be an object",
        });
    }
    pos = skip_whitespace(bytes, pos + 1);
    if bytes.get(pos) == Some(&b'}') {
        return Err(DecodeReject::Malformed {
            reason: "request is missing its operation",
        });
    }
    let mut keys: Vec<String> = Vec::new();
    let mut operation: Option<String> = None;
    loop {
        let key_pos = skip_whitespace(bytes, pos);
        if bytes.get(key_pos) != Some(&b'"') {
            return Err(DecodeReject::Malformed {
                reason: "object keys must be strings",
            });
        }
        let (key, _, after_key) = parse_key(bytes, key_pos, profile.max_json_string_bytes)?;
        if keys.contains(&key) {
            return Err(DecodeReject::DuplicateKey {
                key: bound_control_name(&key),
            });
        }
        let separator = skip_whitespace(bytes, after_key);
        if bytes.get(separator) != Some(&b':') {
            return Err(DecodeReject::Malformed {
                reason: "object key is missing its separator",
            });
        }
        let value_pos = separator + 1;
        let mut next = if key == "op" {
            let string_pos = skip_whitespace(bytes, value_pos);
            if bytes.get(string_pos) != Some(&b'"') {
                return Err(DecodeReject::Malformed {
                    reason: "request operation must be a string",
                });
            }
            let (name, after) = decode_string(bytes, string_pos, profile.max_json_string_bytes)?;
            operation = Some(name);
            after
        } else {
            skip_json_value(
                bytes,
                value_pos,
                1,
                profile.max_nesting_depth,
                profile.max_json_string_bytes,
            )?
        };
        keys.push(key);
        next = skip_whitespace(bytes, next);
        match bytes.get(next) {
            Some(b',') => {
                pos = skip_whitespace(bytes, next + 1);
                if bytes.get(pos) == Some(&b'}') {
                    return Err(DecodeReject::Malformed {
                        reason: "object has a trailing separator",
                    });
                }
            }
            Some(b'}') => {
                pos = skip_whitespace(bytes, next + 1);
                break;
            }
            _ => {
                return Err(DecodeReject::Malformed {
                    reason: "object is not closed",
                });
            }
        }
    }
    if pos != bytes.len() {
        return Err(DecodeReject::TrailingBytes);
    }
    let Some(operation) = operation else {
        return Err(DecodeReject::Malformed {
            reason: "request is missing its operation",
        });
    };
    check_operation_shape(&operation, &keys)
}

fn check_operation_shape(operation: &str, keys: &[String]) -> Result<(), DecodeReject> {
    let expected: &[&str] = match operation {
        "attach" | "invoke" | "cancel" => &["op", "request"],
        "forward_hook" | "forward_event" => &["op", "event"],
        "reconcile_external" | "status" | "stop" => &["op"],
        "bootstrap" => &["op", "context", "tasks", "requested_assessment"],
        "reconnect" => &[
            "op",
            "expected_connection_id",
            "new_connection_id",
            "session_id",
            "activation_generation",
            "authority_epoch",
            "fence_nonce",
        ],
        _ => {
            return Err(DecodeReject::UnknownVariant {
                variant: bound_control_name(operation),
            });
        }
    };
    if keys.len() == expected.len()
        && expected
            .iter()
            .all(|want| keys.iter().any(|got| got.as_str() == *want))
    {
        return Ok(());
    }
    if keys
        .iter()
        .all(|key| GLOBAL_ENVELOPE_KEYS.contains(&key.as_str()))
    {
        return Err(DecodeReject::Malformed {
            reason: "request operation and payload shape do not match",
        });
    }
    Err(DecodeReject::Malformed {
        reason: "request carries an unknown protected field",
    })
}

/// Skips one JSON value without interpreting it.
///
/// The envelope check runs after the bounded pre-scan, so this only walks
/// already-validated structure to the next top-level member boundary.
fn skip_json_value(
    input: &[u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
    max_string_bytes: usize,
) -> Result<usize, DecodeReject> {
    if depth > max_depth {
        return Err(DecodeReject::DepthExceeded);
    }
    let pos = skip_whitespace(input, pos);
    let byte = input.get(pos).ok_or(DecodeReject::Malformed {
        reason: "record ends inside a value",
    })?;
    match byte {
        b'{' => skip_object(input, pos, depth, max_depth, max_string_bytes),
        b'[' => skip_array(input, pos, depth, max_depth, max_string_bytes),
        b'"' => {
            let (_, next) = decode_string(input, pos, max_string_bytes)?;
            Ok(next)
        }
        b't' => parse_literal(input, pos, "true"),
        b'f' => parse_literal(input, pos, "false"),
        b'n' => parse_literal(input, pos, "null"),
        b'-' | b'0'..=b'9' => parse_number(input, pos),
        _ => Err(DecodeReject::Malformed {
            reason: "record contains an unexpected value",
        }),
    }
}

fn skip_object(
    input: &[u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
    max_string_bytes: usize,
) -> Result<usize, DecodeReject> {
    let mut pos = skip_whitespace(input, pos + 1);
    if input.get(pos) == Some(&b'}') {
        return Ok(pos + 1);
    }
    loop {
        let key_pos = skip_whitespace(input, pos);
        if input.get(key_pos) != Some(&b'"') {
            return Err(DecodeReject::Malformed {
                reason: "object keys must be strings",
            });
        }
        let (_, after_key) = decode_string(input, key_pos, max_string_bytes)?;
        let separator = skip_whitespace(input, after_key);
        if input.get(separator) != Some(&b':') {
            return Err(DecodeReject::Malformed {
                reason: "object key is missing its separator",
            });
        }
        pos = skip_json_value(input, separator + 1, depth + 1, max_depth, max_string_bytes)?;
        pos = skip_whitespace(input, pos);
        match input.get(pos) {
            Some(b',') => {
                pos = skip_whitespace(input, pos + 1);
            }
            Some(b'}') => return Ok(pos + 1),
            _ => {
                return Err(DecodeReject::Malformed {
                    reason: "object is not closed",
                });
            }
        }
    }
}

fn skip_array(
    input: &[u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
    max_string_bytes: usize,
) -> Result<usize, DecodeReject> {
    let mut pos = skip_whitespace(input, pos + 1);
    if input.get(pos) == Some(&b']') {
        return Ok(pos + 1);
    }
    loop {
        pos = skip_json_value(input, pos, depth + 1, max_depth, max_string_bytes)?;
        pos = skip_whitespace(input, pos);
        match input.get(pos) {
            Some(b',') => {
                pos = skip_whitespace(input, pos + 1);
            }
            Some(b']') => return Ok(pos + 1),
            _ => {
                return Err(DecodeReject::Malformed {
                    reason: "array is not closed",
                });
            }
        }
    }
}

/// Bounded structural scanner enforcing the decode-stage profile rows.
struct BoundsScanner {
    profile: RequestInputProfile,
    depth: usize,
    scalars: usize,
}

impl BoundsScanner {
    fn count_scalar(&mut self) -> Result<(), DecodeReject> {
        let Some(next) = self.scalars.checked_add(1) else {
            return Err(DecodeReject::TooManyScalars);
        };
        if next > self.profile.max_scalar_values {
            return Err(DecodeReject::TooManyScalars);
        }
        self.scalars = next;
        Ok(())
    }

    fn check_string(&self, decoded_len: usize) -> Result<(), DecodeReject> {
        if decoded_len > self.profile.max_json_string_bytes {
            return Err(DecodeReject::StringTooLong);
        }
        Ok(())
    }

    fn enter_container(&mut self) -> Result<(), DecodeReject> {
        let Some(next) = self.depth.checked_add(1) else {
            return Err(DecodeReject::DepthExceeded);
        };
        if next > self.profile.max_nesting_depth {
            return Err(DecodeReject::DepthExceeded);
        }
        self.depth = next;
        Ok(())
    }

    fn leave_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self, input: &[u8], pos: usize) -> Result<usize, DecodeReject> {
        let pos = skip_whitespace(input, pos);
        let byte = input.get(pos).ok_or(DecodeReject::Malformed {
            reason: "record ends inside a value",
        })?;
        match byte {
            b'{' => self.parse_object(input, pos),
            b'[' => self.parse_array(input, pos),
            b'"' => {
                let (decoded_len, next) =
                    parse_string_decoded_len(input, pos, self.profile.max_json_string_bytes)?;
                self.check_string(decoded_len)?;
                self.count_scalar()?;
                Ok(next)
            }
            b't' => {
                let next = parse_literal(input, pos, "true")?;
                self.count_scalar()?;
                Ok(next)
            }
            b'f' => {
                let next = parse_literal(input, pos, "false")?;
                self.count_scalar()?;
                Ok(next)
            }
            b'n' => {
                let next = parse_literal(input, pos, "null")?;
                self.count_scalar()?;
                Ok(next)
            }
            b'-' | b'0'..=b'9' => {
                let next = parse_number(input, pos)?;
                self.count_scalar()?;
                Ok(next)
            }
            _ => Err(DecodeReject::Malformed {
                reason: "record contains an unexpected value",
            }),
        }
    }

    fn parse_object(&mut self, input: &[u8], pos: usize) -> Result<usize, DecodeReject> {
        self.enter_container()?;
        let mut pos = skip_whitespace(input, pos + 1);
        if input.get(pos) == Some(&b'}') {
            self.leave_container();
            return Ok(pos + 1);
        }
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut members: usize = 0;
        loop {
            let key_pos = skip_whitespace(input, pos);
            if input.get(key_pos) != Some(&b'"') {
                self.leave_container();
                return Err(DecodeReject::Malformed {
                    reason: "object keys must be strings",
                });
            }
            let (key, decoded_len, next) =
                parse_key(input, key_pos, self.profile.max_json_string_bytes)?;
            self.check_string(decoded_len)?;
            if !seen.insert(key.clone()) {
                self.leave_container();
                return Err(DecodeReject::DuplicateKey {
                    key: bound_control_name(&key),
                });
            }
            let Some(next_members) = members.checked_add(1) else {
                self.leave_container();
                return Err(DecodeReject::TooManyMembers);
            };
            if next_members > self.profile.max_container_items {
                self.leave_container();
                return Err(DecodeReject::TooManyMembers);
            }
            members = next_members;
            pos = skip_whitespace(input, next);
            if input.get(pos) != Some(&b':') {
                self.leave_container();
                return Err(DecodeReject::Malformed {
                    reason: "object key is missing its separator",
                });
            }
            let after_value = self.parse_value(input, pos + 1);
            match after_value {
                Ok(next_pos) => pos = skip_whitespace(input, next_pos),
                Err(error) => {
                    self.leave_container();
                    return Err(error);
                }
            }
            match input.get(pos) {
                Some(b',') => {
                    pos = skip_whitespace(input, pos + 1);
                    if input.get(pos) == Some(&b'}') {
                        self.leave_container();
                        return Err(DecodeReject::Malformed {
                            reason: "object has a trailing separator",
                        });
                    }
                }
                Some(b'}') => {
                    self.leave_container();
                    return Ok(pos + 1);
                }
                _ => {
                    self.leave_container();
                    return Err(DecodeReject::Malformed {
                        reason: "object is not closed",
                    });
                }
            }
        }
    }

    fn parse_array(&mut self, input: &[u8], pos: usize) -> Result<usize, DecodeReject> {
        self.enter_container()?;
        let mut pos = skip_whitespace(input, pos + 1);
        if input.get(pos) == Some(&b']') {
            self.leave_container();
            return Ok(pos + 1);
        }
        let mut items: usize = 0;
        loop {
            let next_pos = match self.parse_value(input, pos) {
                Ok(next_pos) => next_pos,
                Err(error) => {
                    self.leave_container();
                    return Err(error);
                }
            };
            let Some(next_items) = items.checked_add(1) else {
                self.leave_container();
                return Err(DecodeReject::TooManyMembers);
            };
            if next_items > self.profile.max_container_items {
                self.leave_container();
                return Err(DecodeReject::TooManyMembers);
            }
            items = next_items;
            pos = skip_whitespace(input, next_pos);
            match input.get(pos) {
                Some(b',') => {
                    pos = skip_whitespace(input, pos + 1);
                    if input.get(pos) == Some(&b']') {
                        self.leave_container();
                        return Err(DecodeReject::Malformed {
                            reason: "array has a trailing separator",
                        });
                    }
                }
                Some(b']') => {
                    self.leave_container();
                    return Ok(pos + 1);
                }
                _ => {
                    self.leave_container();
                    return Err(DecodeReject::Malformed {
                        reason: "array is not closed",
                    });
                }
            }
        }
    }
}

fn skip_whitespace(input: &[u8], mut pos: usize) -> usize {
    while pos < input.len() && matches!(input[pos], b' ' | b'\n' | b'\r' | b'\t') {
        pos += 1;
    }
    pos
}

/// Parses one JSON string key, returning its decoded form, decoded UTF-8 byte
/// length, and the offset past its closing quote.
///
/// Decoding compares fully decoded key strings, so escape-equivalent spellings
/// such as `"op"` and `"\u006f\u0070"` conflict as duplicates. The decoded
/// bound is enforced incrementally inside [`decode_string`], so an overlong
/// key fails before its full text is retained.
fn parse_key(
    input: &[u8],
    pos: usize,
    max_string_bytes: usize,
) -> Result<(String, usize, usize), DecodeReject> {
    let (decoded, next) = decode_string(input, pos, max_string_bytes)?;
    let len = decoded.len();
    Ok((decoded, len, next))
}

/// Parses one JSON string value, returning its decoded UTF-8 byte length and
/// the offset past its closing quote.
///
/// The decoded bound is enforced incrementally inside [`decode_string`], so
/// an overlong value fails before its full text is retained; the caller
/// re-checks the returned length against its stage bound as defense in depth.
fn parse_string_decoded_len(
    input: &[u8],
    pos: usize,
    max_string_bytes: usize,
) -> Result<(usize, usize), DecodeReject> {
    let (decoded, next) = decode_string(input, pos, max_string_bytes)?;
    Ok((decoded.len(), next))
}

fn decode_string(
    input: &[u8],
    pos: usize,
    max_string_bytes: usize,
) -> Result<(String, usize), DecodeReject> {
    if input.get(pos) != Some(&b'"') {
        return Err(DecodeReject::Malformed {
            reason: "string is not opened",
        });
    }
    let mut out = String::new();
    let mut pos = pos + 1;
    while let Some(byte) = input.get(pos) {
        match byte {
            b'"' => return Ok((out, pos + 1)),
            b'\\' => {
                let (ch, next) = decode_escape(input, pos)?;
                out.push(ch);
                if out.len() > max_string_bytes {
                    return Err(DecodeReject::StringTooLong);
                }
                pos = next;
            }
            0x00..=0x1F => {
                return Err(DecodeReject::Malformed {
                    reason: "string contains an unescaped control character",
                });
            }
            _ => {
                let start = pos;
                while pos < input.len()
                    && input[pos] >= 0x20
                    && input[pos] != b'"'
                    && input[pos] != b'\\'
                {
                    pos += 1;
                }
                let chunk = std::str::from_utf8(&input[start..pos]).map_err(|_| {
                    DecodeReject::Malformed {
                        reason: "string is not valid UTF-8",
                    }
                })?;
                out.push_str(chunk);
                if out.len() > max_string_bytes {
                    return Err(DecodeReject::StringTooLong);
                }
            }
        }
    }
    Err(DecodeReject::Malformed {
        reason: "string is not terminated",
    })
}

fn decode_escape(input: &[u8], pos: usize) -> Result<(char, usize), DecodeReject> {
    let esc = *input.get(pos + 1).ok_or(DecodeReject::Malformed {
        reason: "escape sequence is truncated",
    })?;
    match esc {
        b'"' => Ok(('"', pos + 2)),
        b'\\' => Ok(('\\', pos + 2)),
        b'/' => Ok(('/', pos + 2)),
        b'b' => Ok(('\u{0008}', pos + 2)),
        b'f' => Ok(('\u{000C}', pos + 2)),
        b'n' => Ok(('\n', pos + 2)),
        b'r' => Ok(('\r', pos + 2)),
        b't' => Ok(('\t', pos + 2)),
        b'u' => decode_unicode_escape(input, pos),
        _ => Err(DecodeReject::Malformed {
            reason: "escape sequence is not supported",
        }),
    }
}

fn decode_unicode_escape(input: &[u8], pos: usize) -> Result<(char, usize), DecodeReject> {
    let first = decode_hex4(input, pos + 2)?;
    let mut next = pos + 6;
    let code = if (0xD800..0xDC00).contains(&first) {
        if input.get(next) == Some(&b'\\') && input.get(next + 1) == Some(&b'u') {
            let second = decode_hex4(input, next + 2)?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(DecodeReject::Malformed {
                    reason: "lone surrogate escape is not allowed",
                });
            }
            next += 6;
            0x10000 + ((u32::from(first - 0xD800) << 10) | u32::from(second - 0xDC00))
        } else {
            return Err(DecodeReject::Malformed {
                reason: "lone surrogate escape is not allowed",
            });
        }
    } else {
        if (0xDC00..0xE000).contains(&first) {
            return Err(DecodeReject::Malformed {
                reason: "lone surrogate escape is not allowed",
            });
        }
        u32::from(first)
    };
    char::from_u32(code).map_or(
        Err(DecodeReject::Malformed {
            reason: "unicode escape is not a valid character",
        }),
        |ch| Ok((ch, next)),
    )
}

fn decode_hex4(input: &[u8], pos: usize) -> Result<u16, DecodeReject> {
    if pos + 4 > input.len() {
        return Err(DecodeReject::Malformed {
            reason: "unicode escape is truncated",
        });
    }
    let mut value: u16 = 0;
    for byte in &input[pos..pos + 4] {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            b'A'..=b'F' => u16::from(byte - b'A') + 10,
            _ => {
                return Err(DecodeReject::Malformed {
                    reason: "unicode escape is not hexadecimal",
                });
            }
        };
        value = value.saturating_mul(16).saturating_add(digit);
    }
    Ok(value)
}

fn parse_literal(input: &[u8], pos: usize, expected: &'static str) -> Result<usize, DecodeReject> {
    if input.len() >= pos + expected.len()
        && &input[pos..pos + expected.len()] == expected.as_bytes()
    {
        Ok(pos + expected.len())
    } else {
        Err(DecodeReject::Malformed {
            reason: "literal is not well-formed",
        })
    }
}

fn parse_number(input: &[u8], mut pos: usize) -> Result<usize, DecodeReject> {
    if input.get(pos) == Some(&b'-') {
        pos += 1;
    }
    match input.get(pos) {
        Some(b'0') => {
            pos += 1;
        }
        Some(b'1'..=b'9') => {
            while matches!(input.get(pos), Some(b'0'..=b'9')) {
                pos += 1;
            }
        }
        _ => {
            return Err(DecodeReject::Malformed {
                reason: "number is not well-formed",
            });
        }
    }
    if input.get(pos) == Some(&b'.') {
        pos += 1;
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(DecodeReject::Malformed {
                reason: "number is not well-formed",
            });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos += 1;
        }
    }
    if matches!(input.get(pos), Some(b'e' | b'E')) {
        pos += 1;
        if matches!(input.get(pos), Some(b'+' | b'-')) {
            pos += 1;
        }
        if !matches!(input.get(pos), Some(b'0'..=b'9')) {
            return Err(DecodeReject::Malformed {
                reason: "number is not well-formed",
            });
        }
        while matches!(input.get(pos), Some(b'0'..=b'9')) {
            pos += 1;
        }
    }
    Ok(pos)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const SMALL: RequestInputProfile = RequestInputProfile {
        max_record_bytes: 256,
        max_buffered_bytes: 512,
        max_json_string_bytes: 32,
        max_container_items: 4,
        max_scalar_values: 16,
        max_nesting_depth: 4,
        max_requests_per_process: 16,
        max_consecutive_invalid_records: 2,
        max_oversize_discard_bytes: 256,
        idle_timeout_ms: 1_000,
        lifetime_timeout_ms: 60_000,
        oversize_disposition: OversizeDisposition::DiscardThroughTerminator,
    };

    // WORK_UNIT_CASE: 977/1
    #[test]
    fn profile_table_identity_is_stable() {
        assert_eq!(
            REQUEST_INPUT_PROFILE_ID,
            "eliot.agent-bridge.request-input.v1"
        );
        assert!(REQUEST_INPUT_PROFILE.validate().is_ok());
        assert!(scratch_budget(REQUEST_INPUT_PROFILE).is_some());
        assert!(REQUEST_INPUT_LIMIT_TABLE.contains("request-input"));
    }

    // WORK_UNIT_CASE: 977/10
    #[test]
    fn duplicate_and_escape_equivalent_keys_rejected() {
        assert!(matches!(
            prevalidate_record(r#"{"a":1,"a":2}"#, SMALL),
            Err(DecodeReject::DuplicateKey { .. })
        ));
        assert!(matches!(
            prevalidate_record("{\"\\u0061\":1,\"a\":2}", SMALL),
            Err(DecodeReject::DuplicateKey { .. })
        ));
        assert!(prevalidate_record(r#"{"a":1,"b":2}"#, SMALL).is_ok());
    }

    // WORK_UNIT_CASE: 977/11
    // WORK_UNIT_CASE: 977/19
    #[test]
    fn independent_bounds_reject_without_large_allocation() {
        assert!(matches!(
            prevalidate_record("[[[[[]]]]]", SMALL),
            Err(DecodeReject::DepthExceeded)
        ));
        assert!(matches!(
            prevalidate_record(r#"{"a":1,"b":2,"c":3,"d":4,"e":5}"#, SMALL),
            Err(DecodeReject::TooManyMembers)
        ));
        assert!(matches!(
            prevalidate_record(r#"{"s":"0123456789abcdef0123456789abcdefX"}"#, SMALL),
            Err(DecodeReject::StringTooLong)
        ));
        assert!(check_profile_id("stale-profile").is_err());
        assert!(check_profile_id(REQUEST_INPUT_PROFILE_ID).is_ok());
    }

    /// Returns a `BufRead` yielding at most `chunk` bytes per fill over `data`.
    struct ChunkReader<'data> {
        rest: &'data [u8],
        chunk: usize,
        scratch: Vec<u8>,
    }

    impl<'data> ChunkReader<'data> {
        fn new(data: &'data [u8], chunk: usize) -> Self {
            Self {
                rest: data,
                chunk: chunk.max(1),
                scratch: Vec::new(),
            }
        }
    }

    impl std::io::Read for ChunkReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let take = out.len().min(self.chunk).min(self.rest.len());
            out[..take].copy_from_slice(&self.rest[..take]);
            self.rest = &self.rest[take..];
            Ok(take)
        }
    }

    impl std::io::BufRead for ChunkReader<'_> {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            self.scratch.clear();
            let take = self.rest.len().min(self.chunk);
            self.scratch.extend_from_slice(&self.rest[..take]);
            Ok(&self.scratch)
        }

        fn consume(&mut self, amount: usize) {
            self.rest = &self.rest[amount.min(self.rest.len())..];
            self.scratch.drain(..amount.min(self.scratch.len()));
        }
    }

    // WORK_UNIT_CASE: 977/3
    // WORK_UNIT_CASE: 977/7
    #[test]
    fn chunked_crlf_blank_and_eof_final_records_frame_exactly() {
        // CRLF split across 5-byte fills must frame identically to an
        // unsplit terminator: the carriage return is transport framing, not
        // record content.
        let mut split = ChunkReader::new(b"{\"a\":1}\r\n{\"b\":2}", 5);
        assert!(matches!(
            read_bounded_record(&mut split, SMALL),
            Ok(ReadOutcome::Record(record)) if record == b"{\"a\":1}"
        ));
        // The final record at EOF without a newline is returned when in
        // bound; no byte is lost and none is invented.
        assert!(matches!(
            read_bounded_record(&mut split, SMALL),
            Ok(ReadOutcome::Record(record)) if record == b"{\"b\":2}"
        ));
        assert!(matches!(
            read_bounded_record(&mut split, SMALL),
            Ok(ReadOutcome::Eof)
        ));

        // A bare blank line yields an empty record the dispatch loop skips;
        // it consumes no request budget and resets nothing.
        let mut blank = ChunkReader::new(b"\n", 5);
        assert!(matches!(
            read_bounded_record(&mut blank, SMALL),
            Ok(ReadOutcome::Record(record)) if record.is_empty()
        ));

        // A CRLF-only line likewise yields an empty record: both terminator
        // bytes stay excluded from the ceiling.
        let mut crlf_blank = ChunkReader::new(b"\r\n", 1);
        assert!(matches!(
            read_bounded_record(&mut crlf_blank, SMALL),
            Ok(ReadOutcome::Record(record)) if record.is_empty()
        ));
    }

    // WORK_UNIT_CASE: 977/5
    #[test]
    fn exact_record_limit_accepts_and_one_over_rejects_at_acquisition() {
        // A schema-shaped record of exactly `max_record_bytes` (padded with
        // JSON whitespace, which the pre-scan skips) is accepted at both the
        // acquisition and the decode-pre-scan stages without allocating a
        // huge input: the SMALL profile keeps the proof small.
        let body = "{\"a\":1,\"b\":2}";
        let padding = SMALL.max_record_bytes - body.len();
        let exact = format!("{body}{}", " ".repeat(padding));
        assert_eq!(exact.len(), SMALL.max_record_bytes);
        let exact_framed = format!("{exact}\n");
        let mut reader = std::io::BufReader::new(exact_framed.as_bytes());
        assert!(matches!(
            read_bounded_record(&mut reader, SMALL),
            Ok(ReadOutcome::Record(record)) if record.len() == SMALL.max_record_bytes
        ));
        assert!(prevalidate_record(&exact, SMALL).is_ok());

        // One byte over the ceiling is rejected during acquisition, before
        // any String/Value/tree exists, and the pre-scan reports the encoded
        // bound for direct callers.
        let over = format!("{exact} ");
        assert_eq!(over.len(), SMALL.max_record_bytes + 1);
        let over_framed = format!("{over}\n");
        let mut reader = std::io::BufReader::new(over_framed.as_bytes());
        assert!(matches!(
            read_bounded_record(&mut reader, SMALL),
            Ok(ReadOutcome::Oversize { .. })
        ));
        assert!(matches!(
            prevalidate_record(&over, SMALL),
            Err(DecodeReject::OversizeRecord)
        ));
    }

    // WORK_UNIT_CASE: 977/6
    // WORK_UNIT_CASE: 977/16
    #[test]
    fn unterminated_stream_is_bounded_and_unrecoverable() {
        // An endless newline-free stream cannot make acquisition allocate or
        // drain indefinitely: discard stops at the resynchronization bound
        // and reports the missing terminator so the caller breaks
        // fail-closed instead of reading a salvaged suffix.
        let endless = std::io::repeat(b'a');
        let mut reader = std::io::BufReader::with_capacity(64, endless);
        assert!(matches!(
            read_bounded_record(&mut reader, SMALL),
            Ok(ReadOutcome::Oversize {
                discarded_bytes,
                found_terminator: false,
            }) if discarded_bytes == SMALL.max_oversize_discard_bytes
        ));
    }

    // WORK_UNIT_CASE: 977/8
    #[test]
    fn oversize_suffix_never_becomes_the_next_request() {
        // An overlong record resynchronizes through its terminator within
        // the discard bound; the following valid record still frames
        // exactly, proving the overlong bytes were neither truncated into a
        // request nor parsed by suffix.
        let mut input = vec![b'a'; SMALL.max_record_bytes + 44];
        input.push(b'\n');
        input.extend_from_slice(b"{\"ok\":true}\n");
        let mut reader = ChunkReader::new(&input, 64);
        assert!(matches!(
            read_bounded_record(&mut reader, SMALL),
            Ok(ReadOutcome::Oversize {
                found_terminator: true,
                ..
            })
        ));
        assert!(matches!(
            read_bounded_record(&mut reader, SMALL),
            Ok(ReadOutcome::Record(record)) if record == b"{\"ok\":true}"
        ));
    }

    // WORK_UNIT_CASE: 977/19
    #[test]
    fn escape_expanded_strings_hit_the_decoded_bound_before_retention() {
        // Forty `\u0041` escapes decode to 40 bytes but encode 240: the
        // decoded bound (32 under SMALL) must fire during the scan, not
        // after the full text is retained, and the outcome is identical to
        // the plain-spelling rejection.
        let escaped = format!("\"{}\"", "\\u0041".repeat(40));
        assert!(matches!(
            prevalidate_record(&escaped, SMALL),
            Err(DecodeReject::StringTooLong)
        ));
        let plain = format!("\"{}\"", "A".repeat(40));
        assert!(matches!(
            prevalidate_record(&plain, SMALL),
            Err(DecodeReject::StringTooLong)
        ));
    }
}
