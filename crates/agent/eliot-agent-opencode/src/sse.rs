//! Incremental, bounded decoding of Server-Sent Events.
//!
//! The decoder deliberately keeps the wire representation of `data` intact
//! (apart from the newline folding required by the SSE protocol).  This is
//! important for JSON: callers can retain the exact data string for evidence,
//! while using [`SseEvent::json`] only when they want a typed interpretation.

use std::fmt;

/// Limits applied before allocating or retaining an SSE frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SseLimits {
    /// Maximum bytes in one logical frame, excluding the blank-line delimiter.
    pub max_frame_bytes: usize,
    /// Maximum bytes in one line, excluding its line ending.
    pub max_line_bytes: usize,
    /// Maximum bytes in an event name or id value.
    pub max_field_bytes: usize,
    /// Maximum bytes in the folded data value of one event.
    pub max_data_bytes: usize,
    /// Maximum number of decimal digits accepted in a retry field.
    pub max_retry_digits: usize,
}

impl Default for SseLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_line_bytes: 64 * 1024,
            max_field_bytes: 64 * 1024,
            max_data_bytes: 512 * 1024,
            max_retry_digits: 20,
        }
    }
}

/// The reconnect state that can safely be carried to a subsequent request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconnectCursor {
    /// The last dispatched event id, if one was supplied by the server.
    pub last_event_id: Option<String>,
    /// The most recently accepted retry delay, in milliseconds.
    pub retry_ms: Option<u64>,
}

/// One dispatched SSE event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    /// The `event` field, or `None` for the protocol's default `message` type.
    pub event: Option<String>,
    /// The `id` field. An empty id resets the reconnect cursor and is exposed as
    /// `None`.
    pub id: Option<String>,
    /// The accepted `retry` value in milliseconds, if present in this frame.
    pub retry_ms: Option<u64>,
    /// Folded `data` fields, with one `\n` between consecutive fields.
    pub data: String,
}

impl SseEvent {
    /// Returns the event name, defaulting to the SSE `message` event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        self.event.as_deref().unwrap_or("message")
    }

    /// Parses the preserved data into a JSON value without changing the raw
    /// payload stored in [`Self::data`].
    ///
    /// # Errors
    ///
    /// Returns [`SseError::Json`] when the preserved payload cannot be
    /// deserialized as `T`.
    pub fn json<T>(&self) -> Result<T, SseError>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_str(&self.data).map_err(SseError::json)
    }

    /// Parses the preserved data as a JSON value.
    ///
    /// # Errors
    ///
    /// Returns [`SseError::Json`] when the preserved payload is not valid
    /// JSON.
    pub fn json_value(&self) -> Result<serde_json::Value, SseError> {
        self.json()
    }
}

/// A typed decoder failure. Unknown SSE fields are intentionally ignored, as
/// required by the protocol; malformed known fields are rejected explicitly.
#[derive(Debug)]
pub enum SseError {
    /// A complete frame exceeded the configured ceiling.
    FrameTooLarge { limit: usize, observed: usize },
    /// A line exceeded the configured ceiling before its delimiter arrived.
    LineTooLarge { limit: usize, observed: usize },
    /// An event name or id exceeded the configured ceiling.
    FieldTooLarge {
        field: &'static str,
        limit: usize,
        observed: usize,
    },
    /// The folded data value exceeded the configured ceiling.
    DataTooLarge { limit: usize, observed: usize },
    /// A complete line was not valid UTF-8.
    InvalidUtf8(std::str::Utf8Error),
    /// An id contained the forbidden NUL character.
    InvalidId,
    /// A retry field was not a bounded decimal millisecond value.
    InvalidRetry { value: String },
    /// The input ended with an incomplete line or frame.
    UnexpectedEof { buffered_bytes: usize },
    /// The event data was not valid JSON.
    Json(serde_json::Error),
}

/// Public name used by the `OpenCode` crate facade.
pub type SseDecodeError = SseError;

impl SseError {
    fn json(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl fmt::Display for SseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { limit, observed } => {
                write!(
                    formatter,
                    "SSE frame exceeds {limit} bytes (observed {observed})"
                )
            }
            Self::LineTooLarge { limit, observed } => {
                write!(
                    formatter,
                    "SSE line exceeds {limit} bytes (observed {observed})"
                )
            }
            Self::FieldTooLarge {
                field,
                limit,
                observed,
            } => write!(
                formatter,
                "SSE {field} field exceeds {limit} bytes (observed {observed})"
            ),
            Self::DataTooLarge { limit, observed } => write!(
                formatter,
                "SSE data exceeds {limit} bytes (observed {observed})"
            ),
            Self::InvalidUtf8(error) => write!(formatter, "SSE line is not UTF-8: {error}"),
            Self::InvalidId => formatter.write_str("SSE id contains NUL"),
            Self::InvalidRetry { value } => {
                write!(
                    formatter,
                    "SSE retry is not a bounded decimal value: {value:?}"
                )
            }
            Self::UnexpectedEof { buffered_bytes } => write!(
                formatter,
                "SSE input ended with {buffered_bytes} buffered bytes"
            ),
            Self::Json(error) => write!(formatter, "SSE data is not valid JSON: {error}"),
        }
    }
}

impl std::error::Error for SseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct EventBuilder {
    event: Option<String>,
    id: Option<String>,
    retry_ms: Option<u64>,
    data: String,
    has_data: bool,
    frame_bytes: usize,
}

impl EventBuilder {
    fn is_empty(&self) -> bool {
        !self.has_data
    }

    fn reset_for_next_event(&mut self) {
        self.event = None;
        self.retry_ms = None;
        self.data.clear();
        self.has_data = false;
        self.frame_bytes = 0;
    }
}

/// Incremental SSE decoder. It retains only the incomplete line and the
/// current bounded event; completed events are returned from [`Self::feed`].
#[derive(Debug)]
pub struct SseDecoder {
    limits: SseLimits,
    line: Vec<u8>,
    event: EventBuilder,
    cursor: ReconnectCursor,
    pending_cr: bool,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self::new(SseLimits::default())
    }
}

impl SseDecoder {
    /// Creates a decoder with explicit ceilings.
    #[must_use]
    pub fn new(limits: SseLimits) -> Self {
        Self {
            limits,
            line: Vec::new(),
            event: EventBuilder::default(),
            cursor: ReconnectCursor::default(),
            pending_cr: false,
        }
    }

    /// Returns the immutable limits used by this decoder.
    #[must_use]
    pub fn limits(&self) -> SseLimits {
        self.limits
    }

    /// Returns the reconnect state accumulated so far.
    #[must_use]
    pub fn cursor(&self) -> &ReconnectCursor {
        &self.cursor
    }

    /// Number of bytes retained from an incomplete line or frame.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.line.len() + self.event.frame_bytes
    }

    /// Whether this decoder currently holds an incomplete line or event.
    #[must_use]
    pub fn has_partial_frame(&self) -> bool {
        !self.line.is_empty() || !self.event.is_empty()
    }

    /// Feeds arbitrary bytes and returns every event whose blank-line
    /// delimiter was observed. A chunk may split anywhere, including inside a
    /// UTF-8 codepoint or between CR and LF.
    ///
    /// # Errors
    ///
    /// Returns a typed error when an input line, frame, field, or folded data
    /// value exceeds its configured ceiling, or when malformed UTF-8, ids, or
    /// retry values are encountered.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        let mut index = 0;
        if self.pending_cr {
            self.pending_cr = false;
            if bytes.first() == Some(&b'\n') {
                index = 1;
            }
        }
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'\n' {
                self.consume_line(&mut events)?;
                index += 1;
                continue;
            }
            if byte == b'\r' {
                self.consume_line(&mut events)?;
                index += 1;
                if index < bytes.len() && bytes[index] == b'\n' {
                    index += 1;
                } else if index == bytes.len() {
                    self.pending_cr = true;
                }
                continue;
            }
            self.line.push(byte);
            if self.line.len() > self.limits.max_line_bytes {
                return Err(SseError::LineTooLarge {
                    limit: self.limits.max_line_bytes,
                    observed: self.line.len(),
                });
            }
            index += 1;
        }
        Ok(events)
    }

    /// Signals end-of-stream. SSE dispatch requires a blank line, so a
    /// partial line/frame is reported rather than silently emitted.
    ///
    /// # Errors
    ///
    /// Returns [`SseError::UnexpectedEof`] when the stream ends with an
    /// incomplete line or event frame.
    pub fn finish(&self) -> Result<(), SseError> {
        if self.has_partial_frame() {
            Err(SseError::UnexpectedEof {
                buffered_bytes: self.buffered_bytes(),
            })
        } else {
            Ok(())
        }
    }

    fn consume_line(&mut self, events: &mut Vec<SseEvent>) -> Result<(), SseError> {
        let line = std::mem::take(&mut self.line);
        self.event.frame_bytes =
            self.event
                .frame_bytes
                .checked_add(line.len())
                .ok_or(SseError::FrameTooLarge {
                    limit: self.limits.max_frame_bytes,
                    observed: usize::MAX,
                })?;
        if self.event.frame_bytes > self.limits.max_frame_bytes {
            return Err(SseError::FrameTooLarge {
                limit: self.limits.max_frame_bytes,
                observed: self.event.frame_bytes,
            });
        }

        if line.is_empty() {
            if self.event.has_data {
                let event = SseEvent {
                    event: self.event.event.clone(),
                    id: self.event.id.clone(),
                    retry_ms: self.event.retry_ms,
                    // The protocol removes exactly the final folding newline;
                    // removing all trailing newlines would corrupt consecutive
                    // empty `data:` fields.
                    data: self
                        .event
                        .data
                        .strip_suffix('\n')
                        .unwrap_or(&self.event.data)
                        .to_owned(),
                };
                if event.retry_ms.is_some() {
                    self.cursor.retry_ms = event.retry_ms;
                }
                events.push(event);
            }
            self.event.reset_for_next_event();
            return Ok(());
        }

        if line[0] == b':' {
            return Ok(());
        }
        let text = std::str::from_utf8(&line).map_err(SseError::InvalidUtf8)?;
        let (field, value) = text.split_once(':').map_or((text, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        match field {
            "data" => self.append_data(value)?,
            "event" => self.set_field("event", value)?,
            "id" => self.set_id(value)?,
            "retry" => self.set_retry(value)?,
            _ => {}
        }
        Ok(())
    }

    fn append_data(&mut self, value: &str) -> Result<(), SseError> {
        let extra = value.len() + usize::from(self.event.has_data);
        let observed = self
            .event
            .data
            .len()
            .checked_add(extra)
            .ok_or(SseError::DataTooLarge {
                limit: self.limits.max_data_bytes,
                observed: usize::MAX,
            })?;
        if observed > self.limits.max_data_bytes {
            return Err(SseError::DataTooLarge {
                limit: self.limits.max_data_bytes,
                observed,
            });
        }
        if self.event.has_data {
            self.event.data.push('\n');
        }
        self.event.data.push_str(value);
        self.event.has_data = true;
        Ok(())
    }

    fn set_field(&mut self, field: &'static str, value: &str) -> Result<(), SseError> {
        if value.len() > self.limits.max_field_bytes {
            return Err(SseError::FieldTooLarge {
                field,
                limit: self.limits.max_field_bytes,
                observed: value.len(),
            });
        }
        self.event.event = Some(value.to_owned());
        Ok(())
    }

    fn set_id(&mut self, value: &str) -> Result<(), SseError> {
        if value.contains('\0') {
            return Err(SseError::InvalidId);
        }
        if value.len() > self.limits.max_field_bytes {
            return Err(SseError::FieldTooLarge {
                field: "id",
                limit: self.limits.max_field_bytes,
                observed: value.len(),
            });
        }
        self.event.id = (!value.is_empty()).then(|| value.to_owned());
        self.cursor.last_event_id = self.event.id.clone();
        Ok(())
    }

    fn set_retry(&mut self, value: &str) -> Result<(), SseError> {
        if value.is_empty()
            || value.len() > self.limits.max_retry_digits
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(SseError::InvalidRetry {
                value: value.to_owned(),
            });
        }
        let retry_ms = value.parse::<u64>().map_err(|_| SseError::InvalidRetry {
            value: value.to_owned(),
        })?;
        self.event.retry_ms = Some(retry_ms);
        self.cursor.retry_ms = Some(retry_ms);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ReconnectCursor, SseDecoder, SseError, SseLimits};
    use serde_json::json;

    type TestResult = Result<(), SseError>;

    fn make_decoder() -> SseDecoder {
        SseDecoder::new(SseLimits {
            max_frame_bytes: 128,
            max_line_bytes: 32,
            max_field_bytes: 16,
            max_data_bytes: 64,
            max_retry_digits: 5,
        })
    }

    #[test]
    fn folds_data_and_preserves_json_bytes() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b"event:patch\nid:abc\ndata:{\"a\":\ndata:1}\n\n")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type(), "patch");
        assert_eq!(events[0].id.as_deref(), Some("abc"));
        assert_eq!(events[0].data, "{\"a\":\n1}");
        assert_eq!(events[0].json_value()?, json!({"a": 1}));
        Ok(())
    }

    #[test]
    fn accepts_lf_crlf_and_split_chunks() -> TestResult {
        let mut decoder = make_decoder();
        assert!(decoder.feed(b"data:one\r")?.is_empty());
        assert_eq!(decoder.feed(b"\ndata:two\n\n")?.len(), 1);
        assert_eq!(decoder.cursor().last_event_id, None);
        Ok(())
    }

    #[test]
    fn comments_and_heartbeats_do_not_emit_events() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b": heartbeat\n\n:\n\n")?;
        assert!(events.is_empty());
        assert!(!decoder.has_partial_frame());
        Ok(())
    }

    #[test]
    fn fields_without_data_are_not_dispatched_but_cursor_is_updated() -> TestResult {
        let mut decoder = make_decoder();
        assert!(decoder.feed(b"id:old\nretry:250\n\n")?.is_empty());
        assert_eq!(
            decoder.cursor(),
            &ReconnectCursor {
                last_event_id: Some("old".to_owned()),
                retry_ms: Some(250),
            }
        );
        Ok(())
    }

    #[test]
    fn id_and_retry_are_returned_and_saved_for_reconnect() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b"id:next\nretry:250\ndata:{}\n\n")?;
        assert_eq!(events[0].id.as_deref(), Some("next"));
        assert_eq!(events[0].retry_ms, Some(250));
        assert_eq!(
            decoder.cursor(),
            &ReconnectCursor {
                last_event_id: Some("next".to_owned()),
                retry_ms: Some(250),
            }
        );
        Ok(())
    }

    #[test]
    fn empty_id_resets_reconnect_cursor_on_event() -> TestResult {
        let mut decoder = make_decoder();
        decoder.feed(b"id:first\ndata:x\n\n")?;
        decoder.feed(b"id:\ndata:y\n\n")?;
        assert_eq!(decoder.cursor().last_event_id, None);
        Ok(())
    }

    #[test]
    fn an_event_without_id_inherits_the_last_event_id() -> TestResult {
        let mut decoder = make_decoder();
        decoder.feed(b"id:first\ndata:x\n\n")?;
        let events = decoder.feed(b"data:y\n\n")?;
        assert_eq!(events[0].id.as_deref(), Some("first"));
        assert_eq!(decoder.cursor().last_event_id.as_deref(), Some("first"));
        Ok(())
    }

    #[test]
    fn unknown_fields_are_ignored() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b"x-vendor:opaque\ndata:ok\n\n")?;
        assert_eq!(events[0].data, "ok");
        Ok(())
    }

    #[test]
    fn line_ceiling_covers_a_partial_line() {
        let mut decoder = make_decoder();
        assert!(matches!(
            decoder.feed(b"data:1234567890123456789012345678901"),
            Err(SseError::LineTooLarge { .. })
        ));
    }

    #[test]
    fn frame_ceiling_covers_multiple_valid_lines() {
        let mut decoder = SseDecoder::new(SseLimits {
            max_frame_bytes: 10,
            max_line_bytes: 32,
            ..SseLimits::default()
        });
        assert!(matches!(
            decoder.feed(b"data:12345\ndata:12345\n\n"),
            Err(SseError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn data_ceiling_accounts_for_folded_newlines() {
        let mut decoder = SseDecoder::new(SseLimits {
            max_data_bytes: 5,
            ..SseLimits::default()
        });
        assert!(matches!(
            decoder.feed(b"data:abc\ndata:de\n\n"),
            Err(SseError::DataTooLarge { .. })
        ));
    }

    #[test]
    fn event_and_id_field_ceilings_are_typed() {
        let mut decoder = SseDecoder::new(SseLimits {
            max_field_bytes: 2,
            ..SseLimits::default()
        });
        assert!(matches!(
            decoder.feed(b"event:abc\n"),
            Err(SseError::FieldTooLarge { field: "event", .. })
        ));
        let mut decoder = SseDecoder::new(SseLimits {
            max_field_bytes: 2,
            ..SseLimits::default()
        });
        assert!(matches!(
            decoder.feed(b"id:abc\n"),
            Err(SseError::FieldTooLarge { field: "id", .. })
        ));
    }

    #[test]
    fn retry_is_strictly_bounded_decimal() {
        let mut decoder = make_decoder();
        assert!(matches!(
            decoder.feed(b"retry:abc\n"),
            Err(SseError::InvalidRetry { .. })
        ));
        let mut decoder = make_decoder();
        assert!(matches!(
            decoder.feed(b"retry:123456\n"),
            Err(SseError::InvalidRetry { .. })
        ));
    }

    #[test]
    fn nul_ids_are_rejected() {
        let mut decoder = make_decoder();
        assert!(matches!(
            decoder.feed(b"id:a\0b\n"),
            Err(SseError::InvalidId)
        ));
    }

    #[test]
    fn invalid_utf8_is_reported_only_after_a_complete_line() {
        let mut decoder = make_decoder();
        assert!(decoder.feed(&[b'd', b'a', b't', b'a', b':', 0xff]).is_ok());
        assert!(matches!(decoder.feed(b"\n"), Err(SseError::InvalidUtf8(_))));
    }

    #[test]
    fn partial_frame_is_retained_and_finish_reports_it() -> TestResult {
        let mut decoder = make_decoder();
        decoder.feed(b"id:resume\ndata:{\"x\":")?;
        assert!(decoder.has_partial_frame());
        assert!(decoder.buffered_bytes() > 0);
        assert!(matches!(
            decoder.finish(),
            Err(SseError::UnexpectedEof { .. })
        ));
        Ok(())
    }

    #[test]
    fn eof_after_complete_event_is_clean() -> TestResult {
        let mut decoder = make_decoder();
        decoder.feed(b"data:done\n\n")?;
        decoder.finish()?;
        Ok(())
    }

    #[test]
    fn empty_data_dispatches_an_empty_event() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b"data:\n\n")?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
        Ok(())
    }

    #[test]
    fn dispatch_removes_only_the_protocol_folding_newline() -> TestResult {
        let mut decoder = make_decoder();
        let events = decoder.feed(b"data:a\ndata:\ndata:\n\n")?;
        assert_eq!(events[0].data, "a\n");
        Ok(())
    }
}
