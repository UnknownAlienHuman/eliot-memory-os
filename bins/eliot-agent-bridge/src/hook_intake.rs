//! Lifecycle hook intake for host plugin bridges (issue #18 W11).
//!
//! Hosts invoke `eliot-agent-bridge.exe hook <event>` with the host hook JSON
//! on stdin. The intake decodes the event name from argv (never sniffed from
//! payload bytes), reads stdin under the retired facade contract (empty input
//! means `{}`), attaches `ELIOT_TASK_ID`, evaluates through the existing owner
//! [`EliotHookService`], and writes `decision.stdout` — the host decision
//! schema — to stdout. Per-event identity is preserved: every hooks.json row
//! keeps its own `<event>` argv. The intake takes no
//! `--profile`/`--transport`/`--client-declaration` flags and never enters the
//! MCP JSON-RPC front door or the private `op` loop.
//!
//! Issue #4601 bounds this branch's stdin acquisition. Host hook stdin is read
//! through the accepted versioned finite raw-input owner
//! [`crate::request_input::HOOK_INPUT_PROFILE`] and its
//! [`crate::request_input::read_bounded_record`], so the byte ceiling is
//! enforced incrementally with checked arithmetic before any `String` or
//! `serde_json::Value` is constructed. An over-limit or invalid-UTF-8 payload is
//! rejected fail-closed without reaching [`EliotHookService`], without writing a
//! spool record, and without unbounded draining: the owner bounds its
//! resynchronization to `max_oversize_discard_bytes`. Over-limit input is never
//! truncated into a valid accepted prefix and no salvaged suffix is dispatched.
//! Host decision/output compatibility is unchanged: an accepted payload still
//! writes only `result.decision.stdout`, pretty-printed plus a newline.
//!
//! This boundary bounds acquisition only. It does not establish a wall-clock
//! deadline on a blocking slow stdin producer, so no timeout or interruption is
//! claimed here: every read here is a plain blocking `read`/`fill_buf`, a byte
//! bound says nothing about how long a producer may stall, and neither
//! `idle_timeout_ms` nor `lifetime_timeout_ms` is enforced on this branch. A
//! producer that never writes and never closes leaves this process blocked.
//! Hook mode keeps its existing legacy task/environment/spool semantics:
//! bounded input is not authenticated event admission, and this intake mints no
//! task or session authority.
//!
//! Every disposition named above is exercised in this module's `tests` against
//! finite readers at the published `HOOK_INPUT_PROFILE` ceiling: accepted empty
//! input, a multi-chunk EOF-final record with no trailing newline, both
//! invalid-UTF-8 arms, invalid JSON, a huge newline-free stream, the exact
//! ceiling accepted, and one byte over it refused.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::request_input::{
    HOOK_INPUT_LIMIT_TABLE, HOOK_INPUT_PROFILE, HOOK_INPUT_PROFILE_ID, ReadOutcome,
    read_bounded_record,
};
use eliot_engine::EliotHookService;
use eliot_types::HookEventKind;
use thiserror::Error;

/// Leading argv token selecting the lifecycle hook intake (issue #18).
///
/// It mirrors the `mcp` token discipline: the mode is named by argv, stripped
/// before dispatch, and never inferred from payload bytes.
pub const HOOK_MODE_TOKEN: &str = "hook";

/// Typed lifecycle hook intake failure. Each variant carries its stable
/// emission code and process exit status.
#[derive(Debug, Error)]
pub enum HookIntakeError {
    /// `hook` without exactly one event name.
    #[error("hook intake requires exactly one event name, got {0}")]
    MissingEvent(usize),
    /// `hook <event>` names no hook the retired facade contract served.
    #[error("unknown hook event: {0}")]
    UnknownEvent(String),
    /// Host hook JSON stdin could not be read.
    #[error("hook stdin unreadable: {0}")]
    StdinUnreadable(#[source] std::io::Error),
    /// Host hook JSON stdin exceeded the accepted bounded input ceiling.
    ///
    /// Rejected during bounded acquisition, before any payload string or JSON
    /// value exists, before dispatch, and without any spool write. The detail
    /// carries only the published ceiling, the bounded resynchronization byte
    /// count, and whether a terminator was observed — never payload content.
    #[error(
        "hook stdin exceeds {limit_bytes} bytes ({HOOK_INPUT_PROFILE_ID}); \
         discarded {discarded_bytes}, found terminator: {found_terminator}"
    )]
    StdinOversize {
        /// Published ceiling for this host payload, in bytes.
        limit_bytes: usize,
        /// Bytes consumed while resynchronizing, bounded by the profile's
        /// `max_oversize_discard_bytes`. Never the dropped prefix and never
        /// request content.
        discarded_bytes: usize,
        /// Whether resynchronization proved framing by observing a terminator.
        found_terminator: bool,
    },
    /// Host hook JSON stdin is not valid UTF-8.
    ///
    /// Reported for a complete within-bound framed record that failed UTF-8
    /// decoding. Rejected without dispatch and without any spool write; the
    /// detail never echoes the offending bytes.
    #[error("hook stdin is not valid UTF-8 ({HOOK_INPUT_PROFILE_ID})")]
    StdinInvalidUtf8,
    /// Host hook JSON stdin is not JSON.
    #[error("hook stdin is not JSON: {0}")]
    StdinNotJson(#[from] serde_json::Error),
    /// No runtime home resolves for hook spool state.
    #[error("hook runtime home unresolved: {0}")]
    RuntimeHomeUnresolved(String),
    /// The hook owner refused the event.
    #[error("hook evaluation refused: {0}")]
    EvaluationRefused(#[from] eliot_engine::EngineError),
    /// The host decision schema could not be written to stdout.
    #[error("hook decision unwritable: {0}")]
    DecisionUnwritable(#[source] std::io::Error),
}

impl HookIntakeError {
    /// Stable emission code for the stderr envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingEvent(_) => "HOOK_MISSING_EVENT",
            Self::UnknownEvent(_) => "HOOK_UNKNOWN_EVENT",
            Self::StdinUnreadable(_) => "HOOK_STDIN_UNREADABLE",
            Self::StdinOversize { .. } => "HOOK_STDIN_OVERSIZE",
            Self::StdinInvalidUtf8 => "HOOK_STDIN_INVALID_UTF8",
            Self::StdinNotJson(_) => "HOOK_STDIN_NOT_JSON",
            Self::RuntimeHomeUnresolved(_) => "HOOK_RUNTIME_HOME_UNRESOLVED",
            Self::EvaluationRefused(_) => "HOOK_EVALUATION_REFUSED",
            Self::DecisionUnwritable(_) => "HOOK_DECISION_UNWRITABLE",
        }
    }

    /// Human detail for the stderr envelope.
    ///
    /// The over-limit disposition additionally names the published limit table
    /// so the emitted envelope is self-describing about which source owner the
    /// ceiling came from. Only the table identity, the ceiling, the bounded
    /// resynchronization byte count, and the framing result cross into the
    /// detail; payload bytes and payload content never do.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::StdinOversize { .. } => {
                format!("{self} [{HOOK_INPUT_LIMIT_TABLE}]")
            }
            _ => self.to_string(),
        }
    }

    /// Process exit status: malformed intake input mirrors the CLI argument
    /// exit, runtime/service failures mirror the composition exit.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingEvent(_)
            | Self::UnknownEvent(_)
            | Self::StdinUnreadable(_)
            | Self::StdinOversize { .. }
            | Self::StdinInvalidUtf8
            | Self::StdinNotJson(_) => crate::INVALID_ARGUMENT_EXIT,
            Self::RuntimeHomeUnresolved(_)
            | Self::EvaluationRefused(_)
            | Self::DecisionUnwritable(_) => crate::PROVIDER_PORT_EXIT,
        }
    }
}

/// The kebab-case argv spelling of one retired facade hook event.
///
/// This mirrors clap's default subcommand renaming for the facade
/// `HookCommand` (`SessionStart` → `session-start`): the exact argv the
/// hooks.json rows name today.
fn parse_hook_event(name: &str) -> Option<HookEventKind> {
    match name {
        "session-start" => Some(HookEventKind::SessionStart),
        "user-prompt-submit" => Some(HookEventKind::UserPromptSubmit),
        "subagent-start" => Some(HookEventKind::SubagentStart),
        "pre-tool-use" => Some(HookEventKind::PreToolUse),
        "permission-request" => Some(HookEventKind::PermissionRequest),
        "post-tool-use" => Some(HookEventKind::PostToolUse),
        "pre-compact" => Some(HookEventKind::PreCompact),
        "post-compact" => Some(HookEventKind::PostCompact),
        "subagent-stop" => Some(HookEventKind::SubagentStop),
        "stop" => Some(HookEventKind::Stop),
        _ => None,
    }
}

/// Runtime root the hook owner spools under.
///
/// This mirrors the retired facade resolution: `ELIOT_GOVERNOR_CONFIG` names
/// the config file whose grandparent directory is the root, otherwise the
/// standalone `LOCALAPPDATA\Eliot` home applies.
fn hook_runtime_root() -> Result<PathBuf, HookIntakeError> {
    if let Some(config) = std::env::var_os("ELIOT_GOVERNOR_CONFIG") {
        let path = PathBuf::from(config);
        let resolved = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        };
        return Ok(resolved
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new(".eliot-governor"))
            .to_path_buf());
    }
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            HookIntakeError::RuntimeHomeUnresolved(
                "LOCALAPPDATA is required for a standalone Eliot instance".to_owned(),
            )
        })?;
    Ok(local_app_data.join("Eliot"))
}

/// Reads the host hook payload under the published finite byte ceiling.
///
/// The returned bytes are accepted bytes only: they are empty for the accepted
/// EMPTY input case, and they are always within the published ceiling and valid
/// UTF-8. Every other disposition is a typed [`HookIntakeError`] raised before
/// dispatch.
///
/// # Where the ceiling is compared
///
/// The comparison is the owner's, not this function's:
/// [`crate::request_input::read_bounded_record`] accumulates each buffered
/// chunk with `checked_add` and refuses the moment the running content total is
/// GREATER THAN [`HOOK_INPUT_PROFILE`]::`max_record_bytes`. That test is strict,
/// so the boundary falls exactly as follows:
///
/// - content length == `max_record_bytes` is ACCEPTED;
/// - content length == `max_record_bytes + 1` is REFUSED as
///   [`HookIntakeError::StdinOversize`];
/// - the framing byte is excluded from the total (and a single trailing
///   carriage return is removed as part of CRLF), so an accepted terminated
///   record may be `max_record_bytes` content bytes plus its terminator.
///
/// Because the check runs per chunk, the same boundary holds whether the record
/// arrives in one read or many. [`ReadOutcome::Record`] is reachable only when
/// the ceiling held for every chunk of it, so an accepted payload is never a
/// truncation of a longer record, and no `String` or `serde_json::Value` is
/// constructed before the bound has been observed against THIS input.
///
/// # Framing: exactly one record is the contract
///
/// The owner reads exactly one newline-delimited record, so the first terminator
/// ends the payload. Bytes after that terminator are neither inspected nor
/// dispatched by this branch, which serves one host hook payload per process.
/// Two consequences are worth stating rather than leaving accidental: a payload
/// whose JSON spans an embedded newline (pretty-printed host JSON) is read only
/// up to that newline and is then refused as
/// [`HookIntakeError::StdinNotJson`] instead of being partially accepted; and a
/// host that wrote a second complete JSON document after the first line is
/// outside this branch's framing contract, and that second document is not
/// dispatched.
///
/// # Dispositions
///
/// - accepted EMPTY input (no bytes at all, or a blank framed record) yields
///   empty bytes, preserving the retired facade contract where empty input
///   parses as `{}`;
/// - a within-bound record that is not valid UTF-8 is
///   [`HookIntakeError::StdinInvalidUtf8`], whether it was terminator-framed or
///   EOF-final with no trailing newline;
/// - a record exceeding the ceiling is [`HookIntakeError::StdinOversize`] and
///   is rejected without truncation into a valid accepted prefix, without
///   dispatch, and with the owner's bounded resynchronization rather than an
///   unbounded drain.
fn acquire_hook_payload<R: std::io::BufRead>(reader: &mut R) -> Result<Vec<u8>, HookIntakeError> {
    let outcome = read_bounded_record(reader, HOOK_INPUT_PROFILE)
        .map_err(HookIntakeError::StdinUnreadable)?;
    let record = match outcome {
        // End of input with no pending bytes is the accepted EMPTY input case;
        // it parses as `{}` exactly as the retired facade contract did.
        ReadOutcome::Eof => Vec::new(),
        ReadOutcome::InvalidUtf8 => return Err(HookIntakeError::StdinInvalidUtf8),
        ReadOutcome::Oversize {
            discarded_bytes,
            found_terminator,
        } => {
            return Err(HookIntakeError::StdinOversize {
                limit_bytes: HOOK_INPUT_PROFILE.max_record_bytes,
                discarded_bytes,
                found_terminator,
            });
        }
        ReadOutcome::Record(bytes) => bytes,
    };
    Ok(record)
}

/// Decodes one already-acquired hook record into its dispatch payload.
///
/// This is the second stage of the hook boundary, and it runs only on bytes
/// [`acquire_hook_payload`] already accepted, so the ceiling has been observed
/// against this input before the first `serde_json` allocation.
///
/// The UTF-8 conversion is a borrow, not a second unbounded copy. Empty (or
/// whitespace-only) input parses as `{}`, preserving the retired facade
/// contract; any other input must be a complete JSON document or it is
/// [`HookIntakeError::StdinNotJson`]. Both refusals are returned before any
/// [`EliotHookService`] construction, so a malformed payload is never
/// dispatched and never spooled.
fn decode_hook_payload(record: &[u8]) -> Result<serde_json::Value, HookIntakeError> {
    let Ok(text) = std::str::from_utf8(record) else {
        return Err(HookIntakeError::StdinInvalidUtf8);
    };
    Ok(if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(text)?
    })
}

/// Serves one `hook <event>` invocation: stdin in, host decision on stdout.
///
/// The stdin/attach/decision contract is the retired `run_hook` contract:
/// empty input parses as `{}`, a set non-empty `ELIOT_TASK_ID` attaches the
/// session to a task, and only `result.decision.stdout` is written. Host stdin
/// is first acquired under the published finite ceiling by
/// [`acquire_hook_payload`], then decoded by [`decode_hook_payload`]; only an
/// accepted and decodable payload is dispatched to [`EliotHookService`].
pub fn run_hook_intake(argv: &[String]) -> Result<(), HookIntakeError> {
    if argv.len() != 1 {
        return Err(HookIntakeError::MissingEvent(argv.len()));
    }
    let kind =
        parse_hook_event(&argv[0]).ok_or_else(|| HookIntakeError::UnknownEvent(argv[0].clone()))?;
    let mut stdin = std::io::stdin().lock();
    let record = acquire_hook_payload(&mut stdin)?;
    let payload = decode_hook_payload(&record)?;
    let task_attached = std::env::var("ELIOT_TASK_ID")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let result = EliotHookService::for_session(hook_runtime_root()?, task_attached)
        .process(kind, &payload)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &result.decision.stdout)
        .map_err(|e| HookIntakeError::DecisionUnwritable(std::io::Error::other(e)))?;
    writeln!(lock).map_err(HookIntakeError::DecisionUnwritable)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::request_input::REQUEST_INPUT_PROFILE;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A finite reader that hands the acquisition owner at most `chunk` bytes
    /// per `fill_buf`, so a multi-chunk arrival is a real re-entry into
    /// `read_bounded_record`'s loop rather than a single large fill.
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

    /// An endless newline-free producer that counts every byte the owner asks
    /// the underlying reader for, so a test can tell "stopped at the published
    /// bound" from "kept draining". This models the host that never writes a
    /// terminator.
    struct EndlessNoNewline {
        inner: std::io::Repeat,
        read_bytes: AtomicUsize,
    }

    impl EndlessNoNewline {
        fn new() -> Self {
            Self {
                inner: std::io::repeat(b'a'),
                read_bytes: AtomicUsize::new(0),
            }
        }

        fn read_bytes(&self) -> usize {
            self.read_bytes.load(Ordering::Relaxed)
        }
    }

    impl std::io::Read for EndlessNoNewline {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(out)?;
            self.read_bytes.fetch_add(read, Ordering::Relaxed);
            Ok(read)
        }
    }

    /// Fill size used by every test that needs a large-chunk reader, and the
    /// buffer slack the D5 stop-path bound allows for.
    const CHUNK: usize = 64 * 1024;

    /// Convenience: acquire through the production `acquire_hook_payload` and
    /// decode through the production `decode_hook_payload`, i.e. exactly the
    /// two stages `run_hook_intake` runs before `EliotHookService`.
    fn acquire_and_decode<R: std::io::BufRead>(
        reader: &mut R,
    ) -> Result<serde_json::Value, HookIntakeError> {
        let record = acquire_hook_payload(reader)?;
        decode_hook_payload(&record)
    }

    // WORK_UNIT_CASE comment intentionally omitted: the work-unit case gate
    // reconciles markers against issue descriptor tables this lane does not
    // own, so an unbound marker would be a reconciliation defect.

    /// A1/D1: accepted empty input yields `{}`.
    ///
    /// Drives the real `acquire_hook_payload` with a finite reader carrying
    /// zero bytes and with a whitespace-only framed record. Both must be
    /// ACCEPTED (this issue keeps the retired empty-input contract), and both
    /// must decode to an empty JSON object rather than being refused.
    #[test]
    fn accepted_empty_input_acquires_empty_bytes_and_decodes_to_empty_object() {
        let mut nothing = ChunkReader::new(b"", 8);
        let record = acquire_hook_payload(&mut nothing).expect("zero-byte input is accepted");
        assert!(record.is_empty());
        assert_eq!(
            decode_hook_payload(&record).expect("empty input parses"),
            serde_json::json!({})
        );

        // A blank framed record takes the owner's `content_len == 0` route and
        // is accepted the same way.
        let mut blank = ChunkReader::new(b"\n", 8);
        assert!(
            acquire_hook_payload(&mut blank)
                .expect("blank framed record is accepted")
                .is_empty()
        );

        // Whitespace-only content is accepted and still parses as `{}`,
        // because the retired facade contract trims before the empty test.
        let mut spaces = ChunkReader::new(b"   \t  \n", 4);
        let record = acquire_hook_payload(&mut spaces).expect("whitespace record is accepted");
        assert_eq!(
            decode_hook_payload(&record).expect("whitespace parses"),
            serde_json::json!({})
        );
    }

    /// D2: a multi-chunk, EOF-final record with no trailing newline is
    /// accepted complete.
    ///
    /// The payload is delivered across many small `fill_buf` fills, forcing the
    /// owner's re-entering loop, and it ends at EOF rather than at a
    /// terminator. The accepted record must be byte-complete.
    #[test]
    fn multi_chunk_eof_final_record_without_trailing_newline_is_accepted_complete() {
        let payload = r#"{"session_id":"abc","cwd":"C:\\work","tool_name":"Read"}"#;
        // Small fills so the record genuinely spans many chunks.
        let mut reader = ChunkReader::new(payload.as_bytes(), 7);
        let record = acquire_hook_payload(&mut reader).expect("multi-chunk record is accepted");
        assert_eq!(record, payload.as_bytes());
        assert_eq!(
            decode_hook_payload(&record).expect("multi-chunk record parses"),
            serde_json::json!({
                "session_id": "abc",
                "cwd": "C:\\work",
                "tool_name": "Read",
            })
        );
    }

    /// D3: invalid UTF-8 is refused before dispatch.
    ///
    /// Both owner arms are exercised against the production profile: the
    /// terminator-framed arm and the EOF-final arm. The refusal is the typed
    /// `StdinInvalidUtf8` on the hook path, which propagates out of
    /// `acquire_hook_payload` before any service call, so nothing is decoded,
    /// dispatched or spooled.
    #[test]
    fn invalid_utf8_is_refused_before_dispatch_in_both_framing_arms() {
        // Terminator-framed invalid UTF-8.
        let mut framed = ChunkReader::new(&[b'{', b'"', 0xC3, 0x28, b'"', b'}', b'\n'], 3);
        let error = acquire_hook_payload(&mut framed).expect_err("invalid UTF-8 must be refused");
        assert!(matches!(error, HookIntakeError::StdinInvalidUtf8));

        // EOF-final invalid UTF-8 with no trailing newline.
        let mut eof_final = ChunkReader::new(&[b'{', b'"', 0xFF, b'"', b'}'], 2);
        let error =
            acquire_hook_payload(&mut eof_final).expect_err("invalid UTF-8 must be refused");
        assert!(matches!(error, HookIntakeError::StdinInvalidUtf8));
    }

    /// D4: invalid JSON is refused before dispatch.
    ///
    /// A within-bound, valid-UTF-8 record that is not JSON must be refused by
    /// the production decode as `StdinNotJson`, carrying the CLI argument exit
    /// code and the stable `HOOK_STDIN_NOT_JSON` emission code. This is the
    /// exact `serde_json::from_str(text)?` arm `run_hook_intake` now reaches
    /// through `decode_hook_payload`, before `EliotHookService`.
    #[test]
    fn invalid_json_is_refused_before_dispatch() {
        let mut reader = ChunkReader::new(b"{not json}\n", 4);
        let error = acquire_and_decode(&mut reader).expect_err("invalid JSON must be refused");
        assert!(matches!(error, HookIntakeError::StdinNotJson(_)));
        assert_eq!(error.code(), "HOOK_STDIN_NOT_JSON");
        assert_eq!(error.exit_code(), crate::INVALID_ARGUMENT_EXIT);
    }

    /// D5: a huge newline-free stream fails closed with
    /// `found_terminator: false` and is not drained past the discard bound.
    ///
    /// The owner must stop at `max_oversize_discard_bytes` rather than drain an
    /// endless producer. Reaching the end of this test at all is the
    /// termination proof: an owner that kept draining an endless stream would
    /// never return. The byte counter then pins the bound: the producer is
    /// asked for at most the accumulated record ceiling plus the discard bound
    /// plus the one buffer the final stop-path `fill_buf` had already pulled.
    #[test]
    fn huge_no_newline_stream_fails_closed_with_found_terminator_false_and_is_not_drained() {
        let reader = EndlessNoNewline::new();
        let mut reader = std::io::BufReader::with_capacity(CHUNK, reader);
        // Drive the production acquisition; an endless stream must terminate.
        let error = acquire_hook_payload(&mut reader).expect_err("endless stream must be refused");
        match error {
            HookIntakeError::StdinOversize {
                limit_bytes,
                discarded_bytes,
                found_terminator,
            } => {
                assert_eq!(limit_bytes, HOOK_INPUT_PROFILE.max_record_bytes);
                assert!(!found_terminator, "no terminator was ever observed");
                assert_eq!(
                    discarded_bytes, HOOK_INPUT_PROFILE.max_oversize_discard_bytes,
                    "discard must stop at the published bound, not drain"
                );
            }
            other => panic!("expected StdinOversize, got {other:?}"),
        }
        // The process is not reading forever: the owner returned rather than
        // continuing to pull from an endless producer. Reaching this line is
        // the proof. The counter then bounds how much the producer was asked
        // for: the record ceiling while accumulating, plus the discard bound
        // while resynchronizing, plus at most one buffer of slack from the
        // final `fill_buf` the stop path had already pulled.
        let read_bytes = reader.into_inner().read_bytes();
        assert!(
            read_bytes
                <= HOOK_INPUT_PROFILE.max_oversize_discard_bytes
                    + HOOK_INPUT_PROFILE.max_record_bytes
                    + CHUNK,
            "the reader must not be drained past the published discard bound, saw {read_bytes}"
        );
    }

    /// D6: content of exactly `max_record_bytes` is ACCEPTED.
    ///
    /// The owner's comparison is a strict `>`, so equality must not trip it.
    /// The fixture is built at the real published ceiling (1 MiB), padded with
    /// JSON whitespace so it is also a well-formed document, and the accepted
    /// record must be exactly the ceiling long.
    #[test]
    fn exact_record_limit_is_accepted_at_the_published_ceiling() {
        let body = r#"{"a":1}"#;
        let ceiling = HOOK_INPUT_PROFILE.max_record_bytes;
        assert_eq!(ceiling, REQUEST_INPUT_PROFILE.max_record_bytes);
        assert_eq!(ceiling, 1_048_576);
        let mut exact = String::with_capacity(ceiling + 1);
        exact.push_str(body);
        exact.extend(std::iter::repeat_n(' ', ceiling - body.len()));
        assert_eq!(exact.len(), ceiling);
        // Framed with a terminator; the terminator is excluded from the bound.
        let mut framed = exact.clone();
        framed.push('\n');
        let mut reader = ChunkReader::new(framed.as_bytes(), CHUNK);
        let record = acquire_hook_payload(&mut reader).expect("exact ceiling must be accepted");
        assert_eq!(record.len(), ceiling);
        // And it decodes: the accepted prefix is a whole valid document, not a
        // truncated one.
        decode_hook_payload(&record).expect("exact ceiling record parses");
    }

    /// D7: content of `max_record_bytes + 1` is REFUSED as oversize.
    ///
    /// One byte over the ceiling must trip the strict `>`, be discarded without
    /// copying the offending chunk, and surface as `StdinOversize` with the
    /// published limit (not a measured value) and the terminator found during
    /// bounded resynchronization.
    #[test]
    fn one_byte_over_the_limit_is_refused_as_oversize() {
        let body = r#"{"a":1}"#;
        let ceiling = HOOK_INPUT_PROFILE.max_record_bytes;
        let mut over = String::with_capacity(ceiling + 2);
        over.push_str(body);
        over.extend(std::iter::repeat_n(' ', ceiling - body.len()));
        over.push(' ');
        assert_eq!(over.len(), ceiling + 1);
        let mut framed = over;
        framed.push('\n');
        let mut reader = ChunkReader::new(framed.as_bytes(), CHUNK);
        let error = acquire_hook_payload(&mut reader).expect_err("one over must be refused");
        match error {
            HookIntakeError::StdinOversize {
                limit_bytes,
                found_terminator,
                ..
            } => {
                assert_eq!(limit_bytes, ceiling);
                assert!(found_terminator, "resynchronization found the terminator");
            }
            other => panic!("expected StdinOversize, got {other:?}"),
        }
    }

    /// A2: over-limit and malformed acquisition never reach dispatch or spool.
    ///
    /// Executed half: every refusal disposition is produced by the production
    /// functions BEFORE any service could be constructed, and each carries the
    /// invalid-argument exit code, so the process fails closed without calling
    /// `EliotHookService` (whose only spool write lives behind that call).
    ///
    /// Structural half (source ordering): this test pins the ordering in the
    /// real file so the `?` on acquisition/decode provably precedes the
    /// `EliotHookService::for_session` construction. A fake service is not used
    /// (forbidden), so "no spool record is written" is argued from this
    /// ordering plus the fact that `EliotHookService::process` is the only
    /// writer and is only reached after both `?`.
    #[test]
    fn refusals_never_reach_dispatch_or_spool_and_ordering_precedes_service() {
        // Executed: the over-limit and malformed dispositions, and their
        // invalid-argument exit codes, all produced by production code.
        let mut framed = Vec::new();
        framed.extend(std::iter::repeat_n(
            b'a',
            HOOK_INPUT_PROFILE.max_record_bytes + 1,
        ));
        framed.push(b'\n');
        let mut over_reader = ChunkReader::new(&framed, CHUNK);
        let error = acquire_hook_payload(&mut over_reader).expect_err("oversize must be refused");
        assert_eq!(error.exit_code(), crate::INVALID_ARGUMENT_EXIT);

        let mut bad_json = ChunkReader::new(b"{oops}\n", 4);
        let error = acquire_and_decode(&mut bad_json).expect_err("bad JSON must be refused");
        assert_eq!(error.exit_code(), crate::INVALID_ARGUMENT_EXIT);

        let mut bad_utf8 = ChunkReader::new(&[0xC3, 0x28, b'\n'], 3);
        let error = acquire_hook_payload(&mut bad_utf8).expect_err("bad UTF-8 must be refused");
        assert_eq!(error.exit_code(), crate::INVALID_ARGUMENT_EXIT);

        // A REFACTOR TRIPWIRE, not a proof of "no spool record".
        //
        // What this genuinely pins: in the production region of this file,
        // acquisition and decode each `?` before the only
        // `EliotHookService` construction. The search is restricted to the
        // region above the test module, so this test's own string literals
        // cannot satisfy it.
        //
        // What it does NOT pin, stated honestly so no reader over-trusts it:
        // it is a byte-offset scan of ONE file. A dispatch added in a
        // neighbouring module, or a second service construction introduced
        // above this one, would not be visible here. The real no-spool
        // property rests on the executed refusals above plus the owner's own
        // ordering (`for_session` is a pure constructor; the only spool write
        // is inside `process`), which this scan deliberately does not claim to
        // re-prove.
        let source = include_str!("hook_intake.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(head, _)| head);
        let acquire_at = production
            .find("let record = acquire_hook_payload(&mut stdin)?;")
            .expect("acquire call");
        let decode_at = production
            .find("let payload = decode_hook_payload(&record)?;")
            .expect("decode call");
        let service_at = production
            .find("EliotHookService::for_session(")
            .expect("service construction");
        assert!(
            acquire_at < service_at && decode_at < service_at,
            "acquisition and decode must precede the service construction"
        );
        assert_eq!(
            production.matches("EliotHookService::for_session(").count(),
            1,
            "one service construction on this branch, and it is last"
        );
    }
}
