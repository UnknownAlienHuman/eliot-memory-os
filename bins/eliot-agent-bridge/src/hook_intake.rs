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
//! # What this module's `tests` exercise, and what they do not
//!
//! These tests run against finite readers at the published
//! `HOOK_INPUT_PROFILE` ceiling, and they cover:
//!
//! - accepted empty input, and the retired empty-input decode to `{}`;
//! - a multi-chunk EOF-final record with no trailing newline;
//! - both invalid-UTF-8 arms (terminator-framed and EOF-final), and invalid
//!   JSON, each refused before any service construction;
//! - a huge newline-free stream, refused fail-closed with
//!   `found_terminator: false` and without draining past the owner's discard
//!   bound;
//! - the exact ceiling ACCEPTED and one byte over it REFUSED, in a single fill,
//!   in fills that split the record, in fills that leave the CRLF
//!   terminator's carriage return on a fill of its own, in a one-byte fill, and
//!   in a 1_000_000-byte fill that divides neither the ceiling nor the
//!   terminator — the same byte stream, one content total, one disposition,
//!   because a fill ending on a lone CR is consumed whole with the CR held out
//!   of the charge and that held CR is charged exactly once by whichever later
//!   fill resolves it, while every other fill charges its content bytes once
//!   and consumes every byte it charges;
//! - the public hook branch itself, end to end through argv, bounded
//!   acquisition, decode, the real [`EliotHookService`], and the host decision
//!   write, with the runtime root supplied by the caller: an accepted payload
//!   spools exactly one record into that root, and an over-limit payload is
//!   refused carrying the published ceiling and the terminator finding, leaving
//!   the record count where the accepted run left it.
//!
//! They do not run [`run_hook_intake`], which takes no reader and no root and
//! can only be served with the process's own standard input and the process's
//! own runtime home; it is exercised through [`run_hook_intake_with`], which is
//! that function's entire body apart from those two supplies. The runtime root
//! is therefore a parameter rather than an ambient read: a test must not move
//! process-global state to relocate the spool, and `std::env::set_var` /
//! `remove_var` are `unsafe` in edition 2024, which this crate forbids outright
//! (`#![forbid(unsafe_code)]`) — there is no honest way to observe this branch's
//! spool from a test without threading the root in, and threading it in keeps
//! one production resolution path rather than adding a second. Nothing here is
//! proved about [`hook_runtime_root`]'s own environment reading, for the same
//! reason, and nothing here is proved about the decision document the process
//! writes to its own stdout, because tests cannot capture the process stdout
//! port.

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
/// chunk with `checked_add` and refuses the moment the running CONTENT total is
/// GREATER THAN [`HOOK_INPUT_PROFILE`]::`max_record_bytes`. That test is strict,
/// so the boundary falls exactly as follows:
///
/// - content length == `max_record_bytes` is ACCEPTED;
/// - content length == `max_record_bytes + 1` is REFUSED as
///   [`HookIntakeError::StdinOversize`];
/// - the framing bytes are excluded from the total, and a single trailing
///   carriage return is removed as part of CRLF, so an accepted terminated
///   record may be `max_record_bytes` content bytes plus its terminator.
///
/// The content total is the length of the record with BOTH terminator bytes
/// removed, and it is that total the owner compares — on every chunking path,
/// because the owner makes the fills not matter: every fill charges its content
/// bytes once and consumes every byte it charges, and a fill that ends on a
/// lone CR leaves the stream whole with the CR held out of the charge, so that
/// held CR is charged exactly once by whichever later fill resolves it rather
/// than re-delivered with the content behind it. The one arrival the owner's
/// LF-only scan cannot classify in the fill that carries it is therefore that
/// fill ending on a lone CR, because the CR and the newline that would prove it
/// framing land in different fills. A record of `max_record_bytes` content
/// bytes, `\r`, `\n` is ACCEPTED in one fill, in 64 KiB fills that divide the
/// content evenly, in fills that leave the `\r` on a fill of its own, in a
/// one-byte fill, and in fills that divide neither the ceiling nor the
/// terminator — the same total, from all of them — and the byte stream is
/// refused identically once it carries one byte more of content. (Before the
/// held-CR arm existed, the fourth of those arrivals was refused at exactly
/// `max_record_bytes` content bytes, so the disposition depended on the
/// caller's buffer size rather than on the bytes.) A carriage return that no
/// newline follows is content, not framing: it is charged against the ceiling
/// and kept in the record, so an EOF-final record that ends on a CR is not
/// silently shortened.
///
/// [`ReadOutcome::Record`] is reachable only when the ceiling held for every
/// chunk of it, so an accepted payload is never a truncation of a longer
/// record, and no `String` or `serde_json::Value` is constructed before the
/// bound has been observed against THIS input.
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
/// This is the argv entry point the binary's `main` calls with the process's
/// real standard input. It adds nothing to [`run_hook_intake_with`] beyond
/// supplying that reader and resolving the runtime root from the process
/// environment, which is the ONLY place the shipped process reads
/// `ELIOT_GOVERNOR_CONFIG` / `LOCALAPPDATA` for this branch.
pub fn run_hook_intake(argv: &[String]) -> Result<(), HookIntakeError> {
    let stdin = std::io::stdin();
    let stdin = stdin.lock();
    let runtime_root = hook_runtime_root()?;
    run_hook_intake_with(argv, &mut std::io::BufReader::new(stdin), &runtime_root)
}

/// Serves one `hook <event>` invocation against an injected host stdin and an
/// injected runtime root.
///
/// The stdin/attach/decision contract is the retired `run_hook` contract:
/// empty input parses as `{}`, a set non-empty `ELIOT_TASK_ID` attaches the
/// session to a task, and only `result.decision.stdout` is written. Host stdin
/// is first acquired under the published finite ceiling by
/// [`acquire_hook_payload`], then decoded by [`decode_hook_payload`]; only an
/// accepted and decodable payload is dispatched to [`EliotHookService`], which
/// spools under `runtime_root`.
///
/// This is the whole public hook branch behind [`run_hook_intake`]. It takes
/// host stdin as an ordinary `BufRead` parameter rather than reaching for the
/// process handle, and it takes the runtime root as an ordinary `&Path`
/// parameter rather than resolving it from the process environment here. Both
/// are supplies the caller owes the branch, and [`run_hook_intake`] supplies
/// exactly what the shipped process supplies: the real standard input and the
/// one real [`hook_runtime_root`] resolution.
///
/// The root is a parameter and not an ambient read for a reason beyond
/// convenience. `std::env::set_var` / `std::env::remove_var` are `unsafe` in
/// edition 2024 and this crate is `#![forbid(unsafe_code)]`, so relocating a
/// run's spool by pointing `ELIOT_GOVERNOR_CONFIG` at a temporary directory is
/// not an option a test here may take — the alternative would be to wrap those
/// calls in `unsafe` or to `#[allow]` the lint, and both would be worse than
/// passing the value the caller already has. Because the service takes its root
/// as a plain constructor argument, one parameter carries it all the way down,
/// so this adds no second resolution path: production still resolves the root
/// exactly once, still from the same environment, and still hands it to the
/// same [`EliotHookService::for_session`].
///
/// The event name still comes from argv alone, the `ELIOT_TASK_ID` attach
/// signal is still read from the process environment exactly as before, and
/// stdout is still the process stdout.
pub fn run_hook_intake_with<R: std::io::BufRead>(
    argv: &[String],
    stdin: &mut R,
    runtime_root: &Path,
) -> Result<(), HookIntakeError> {
    if argv.len() != 1 {
        return Err(HookIntakeError::MissingEvent(argv.len()));
    }
    let kind =
        parse_hook_event(&argv[0]).ok_or_else(|| HookIntakeError::UnknownEvent(argv[0].clone()))?;
    let record = acquire_hook_payload(stdin)?;
    let payload = decode_hook_payload(&record)?;
    let task_attached = std::env::var("ELIOT_TASK_ID")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let result = EliotHookService::for_session(runtime_root.to_path_buf(), task_attached)
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

    /// Fill size that leaves the CRLF terminator's carriage return on a fill
    /// of its own at the published 1 MiB ceiling: one byte more than the
    /// ceiling, so the content fills divide evenly and only the terminator
    /// straddles the boundary.
    const CR_SPLIT_FILL_CHUNK: usize = 1_048_576 + 1;

    /// Fill size that leaves a CONTENT carriage return on a fill of its own at
    /// the published 1 MiB ceiling: the ceiling plus one more, so the byte that
    /// follows the content CR is a fill of its own and the byte after that - the
    /// terminator's CR - shares a fill with the terminator's LF.
    ///
    /// This is the only shape that distinguishes a genuine content CR from the
    /// CRLF terminator's own CR: `read_bounded_record` holds a lone CR out of
    /// the charge, and the next fill decides whether it was content. Here the
    /// next fill after the content CR is not the LF, so the byte is content and
    /// must be charged exactly once and kept.
    const CONTENT_CR_FILL_CHUNK: usize = 1_048_576 + 2;

    /// Fill size that leaves the CONTENT carriage return, the terminator's own
    /// carriage return, and the terminator's LF all on fills of their own, so
    /// the terminator's CRLF is one fill whose content chunk is empty.
    const CONTENT_CR_SPLIT_CRLF_FILL_CHUNK: usize = 1_048_577 + 2;

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
                // The published ceiling, as a literal: the same 1_048_576 the
                // D6 test asserts, so this pins the emitted number against the
                // profile instead of against the constant it was copied from.
                assert_eq!(limit_bytes, 1_048_576);
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

    /// D6: content of exactly `max_record_bytes` is ACCEPTED, and the
    /// disposition does not depend on how the bytes arrive.
    ///
    /// The owner's comparison is a strict `>`, so equality must not trip it.
    /// The fixture is built at the real published ceiling (1 MiB), padded with
    /// JSON whitespace so it is also a well-formed document, and the accepted
    /// record must be exactly the ceiling long.
    ///
    /// The arrival is the point. The byte stream is CRLF-terminated and is
    /// driven through five readers: one fill holding everything, `CHUNK` fills
    /// that divide the ceiling evenly, `CR_SPLIT_FILL_CHUNK` (one byte more
    /// than the ceiling) fills that leave the terminator's carriage return on a
    /// fill of its own, a one-byte fill that leaves it alone, and a
    /// 1_000_000-byte fill that divides neither the ceiling nor the terminator
    /// and so lands that carriage return at neither boundary. That
    /// `CR_SPLIT_FILL_CHUNK` arrival is the contested one — it is the only
    /// shape whose carriage return cannot be classified by the owner's LF-only
    /// scan in the fill that carries it — so a ceiling charged for a
    /// not-yet-proven terminator byte would refuse there while accepting the
    /// others; the 1_000_000 arrival covers the case the deferred-CR mechanism
    /// does not touch, where the same bytes are charged by ordinary content
    /// charging instead.
    #[test]
    fn exact_record_limit_is_accepted_at_the_published_ceiling_for_every_chunking() {
        let body = r#"{"a":1}"#;
        let ceiling = HOOK_INPUT_PROFILE.max_record_bytes;
        assert_eq!(ceiling, REQUEST_INPUT_PROFILE.max_record_bytes);
        assert_eq!(ceiling, 1_048_576);
        let mut exact = String::with_capacity(ceiling + 2);
        exact.push_str(body);
        exact.extend(std::iter::repeat_n(' ', ceiling - body.len()));
        assert_eq!(exact.len(), ceiling);
        // Framed with a CRLF terminator; neither terminator byte is bound.
        let mut framed = exact.clone();
        framed.push('\r');
        framed.push('\n');
        let framed = framed.as_bytes();

        for (arrival, chunk) in [
            ("one fill", framed.len()),
            ("fills dividing the ceiling", CHUNK),
            (
                "fills splitting the carriage return onto its own fill",
                CR_SPLIT_FILL_CHUNK,
            ),
            ("the carriage return on a one-byte fill", 1),
            // A fill that divides NEITHER the ceiling nor the terminator: it
            // lands the carriage return at neither boundary — not on a fill's
            // last byte, so the lone-CR arm never fires at all, and not on the
            // byte after the ceiling, so no boundary is hit by construction
            // here. Every byte is charged exactly once by ordinary content
            // charging, which is the point: the invariant cannot be credited
            // to the deferred-CR mechanism alone.
            (
                "fills dividing neither the ceiling nor the terminator",
                1_000_000,
            ),
        ] {
            assert_ne!(
                chunk, 0,
                "arrival {arrival} would not produce multiple fills"
            );
            let mut reader = ChunkReader::new(framed, chunk);
            let record = acquire_hook_payload(&mut reader).unwrap_or_else(|error| {
                panic!("exact ceiling must be accepted: {arrival}: {error:?}")
            });
            assert_eq!(
                record,
                exact.as_bytes(),
                "accepted record differs: {arrival}"
            );
            assert_eq!(record.len(), ceiling, "accepted length differs: {arrival}");
            // And it decodes: the accepted prefix is a whole valid document,
            // not a truncated one.
            decode_hook_payload(&record).unwrap_or_else(|error| {
                panic!("exact ceiling record parses: {arrival}: {error:?}")
            });
        }

        // The same read size that splits the carriage return onto its own fill
        // refuses the byte-identical stream one byte of content longer, so the
        // two dispositions cannot disagree about the same arrival.
        let mut over = exact.clone();
        over.push(' ');
        over.push('\r');
        over.push('\n');
        assert_eq!(over.len(), ceiling + 3);
        let mut reader = ChunkReader::new(over.as_bytes(), CR_SPLIT_FILL_CHUNK);
        let error = acquire_hook_payload(&mut reader)
            .expect_err("one over the ceiling must be refused on the split-CR arrival");
        assert!(matches!(error, HookIntakeError::StdinOversize { .. }));
    }

    /// The published ceiling is a function of the byte stream alone, not of the
    /// caller's read size.
    ///
    /// One byte over the published ceiling is REFUSED - `StdinOversize`, the
    /// published limit, bounded resynchronization - on EVERY fill size, and the
    /// refusal is observed at the production acquisition the shipped
    /// `hook <event>` branch runs.
    ///
    /// The fixture is the one that distinguishes the two defects from a
    /// well-behaved record: the content is `max_record_bytes + 1` bytes whose
    /// LAST CONTENT BYTE is a carriage return, framed `\r\n`. So the byte stream
    /// ends `...\r\r\n` and the acceptance question is only ever about the
    /// first of those two CRs.
    ///
    /// `read_bounded_record` holds a lone CR out of the ceiling charge and lets
    /// the next fill resolve it. Resolving it correctly means resolving it from
    /// the byte that FOLLOWS it: the CR is this record's terminator only when
    /// the very next byte in the stream is the LF, and content in every other
    /// case. Resolving it from how many content bytes the next fill happened to
    /// carry - which is what the boundary did before this fix - accepts this
    /// record whenever the terminator's CRLF lands alone in one fill:
    /// `CONTENT_CR_SPLIT_CRLF_FILL_CHUNK` (1_048_579) makes that fill exactly
    /// `"\r\n"`, so the content CR was declared framing and dropped uncharged,
    /// the ceiling compared `1_048_577 - 1`, and an over-limit record reached
    /// `EliotHookService`.
    ///
    /// Every fill size below is therefore a real arrival, not a formality: they
    /// are chosen to cover one fill holding everything, a one-byte fill, the
    /// fills that divide the ceiling, the two fills that split the trailing CR
    /// differently (`CONTENT_CR_FILL_CHUNK`, and `CR_SPLIT_FILL_CHUNK`, which
    /// makes the terminator's CRLF one fill without the content CR ever ending
    /// a fill), the fill that divides neither the ceiling nor the terminator, the
    /// shipped 8 KiB arrival, and the contested one.
    #[test]
    fn content_cr_record_one_over_the_ceiling_is_refused_for_every_chunking() {
        let ceiling = HOOK_INPUT_PROFILE.max_record_bytes;
        let mut over = Vec::with_capacity(ceiling + 3);
        // Content is JSON whitespace padding, whose last byte is the carriage
        // return under test. The document prefix keeps the test honest about
        // what a hook payload looks like without the ceiling being decided by
        // it: the raw byte stream is what the boundary bounds.
        over.extend_from_slice(r#"{"a":1}"#);
        let prefix = r#"{"a":1}"#.len();
        over.extend(std::iter::repeat_n(b' ', ceiling + 1 - prefix - 1));
        over.push(b'\r');
        assert_eq!(over.len(), ceiling + 1);
        let mut framed = over.clone();
        framed.push(b'\r');
        framed.push(b'\n');

        for (arrival, chunk) in [
            ("one fill holding everything", framed.len()),
            ("a one-byte fill", 1),
            ("two-byte fills", 2),
            ("a fill that divides the ceiling", CHUNK),
            ("the shipped 8 KiB arrival", 8 * 1024),
            ("fills dividing neither boundary", 1_000_000),
            (
                "the CR and the terminator CR on fills of their own",
                CR_SPLIT_FILL_CHUNK,
            ),
            (
                "the CR followed by a fill of its own",
                CONTENT_CR_FILL_CHUNK,
            ),
            (
                "the terminator CRLF alone in one fill",
                CONTENT_CR_SPLIT_CRLF_FILL_CHUNK,
            ),
        ] {
            assert_ne!(chunk, 0, "arrival {arrival} would not produce fills");
            let mut reader = ChunkReader::new(&framed, chunk);
            let error = acquire_hook_payload(&mut reader)
                .unwrap_or_else(|| panic!("{arrival} must refuse the over-limit record"));
            match error {
                HookIntakeError::StdinOversize {
                    limit_bytes,
                    found_terminator,
                    ..
                } => {
                    // The published ceiling as a literal, not as the alias this
                    // test derived it from: an invented ceiling would satisfy
                    // the alias comparison for any value.
                    assert_eq!(limit_bytes, 1_048_576, "published limit: {arrival}");
                    assert!(
                        found_terminator,
                        "bounded resynchronization found the terminator: {arrival}"
                    );
                }
                other => panic!("{arrival}: expected StdinOversize, got {other:?}"),
            }
        }
    }

    /// The published ceiling is a function of the byte stream alone, not of the
    /// caller's read size: a record AT the ceiling is accepted complete on every
    /// fill size.
    ///
    /// This is the acceptance half of the same fixture the refusal above pins:
    /// content of exactly `max_record_bytes` whose LAST CONTENT BYTE is a
    /// carriage return, framed `\r\n`, so the byte stream ends `...\r\r\n`.
    ///
    /// ACCEPTANCE ALONE IS NOT THE ASSERTION, and that is the point. The
    /// boundary used to resolve a held carriage return from the next fill's
    /// CONTENT COUNT rather than from the byte that follows it, and the visible
    /// symptom was not a wrong disposition but a silently SHORTENED record: when
    /// the terminator's CRLF landed alone in one fill, the content CR was called
    /// framing, dropped, and never charged - so the record was accepted at
    /// `ceiling - 1` bytes and the host was never told one byte had gone
    /// missing. On the SHIPPED arrival (`BufReader::new(stdin)`, 8 KiB) that is
    /// exactly what happened to this fixture, every time.
    ///
    /// So each arrival asserts the accepted record is byte-identical to the
    /// content that was written - `record == exact`, which pins both the length
    /// and every byte - with `record.len() == max_record_bytes` stated directly
    /// as well, and then decodes, so the accepted bytes are a whole document
    /// rather than a truncated one.
    ///
    /// The fill sizes are the same set as the refusal test's, including the two
    /// that put the terminator's CRLF alone in a fill and the shipped 8 KiB
    /// arrival. A one-byte fill must give the byte-complete answer too: that
    /// arrival puts each byte on its own fill, so the content CR and the
    /// terminator CR are never in the same fill and the acceptance is decided
    /// one byte at a time.
    #[test]
    fn content_cr_record_at_the_ceiling_is_accepted_byte_complete_for_every_chunking() {
        let ceiling = HOOK_INPUT_PROFILE.max_record_bytes;
        let mut exact = Vec::with_capacity(ceiling + 2);
        exact.extend_from_slice(r#"{"a":1}"#);
        let prefix = r#"{"a":1}"#.len();
        exact.extend(std::iter::repeat_n(b' ', ceiling - prefix - 1));
        exact.push(b'\r');
        assert_eq!(exact.len(), ceiling);
        assert_eq!(exact.last(), Some(&b'\r'), "the content CR is the last byte");
        let mut framed = exact.clone();
        framed.push(b'\r');
        framed.push(b'\n');

        for (arrival, chunk) in [
            ("one fill holding everything", framed.len()),
            ("a one-byte fill", 1),
            ("two-byte fills", 2),
            ("a fill that divides the ceiling", CHUNK),
            ("the shipped 8 KiB arrival", 8 * 1024),
            ("fills dividing neither boundary", 1_000_000),
            (
                "the CR and the terminator CR on fills of their own",
                CR_SPLIT_FILL_CHUNK,
            ),
            (
                "the CR followed by a fill of its own",
                CONTENT_CR_FILL_CHUNK,
            ),
            (
                "the terminator CRLF alone in one fill",
                CONTENT_CR_SPLIT_CRLF_FILL_CHUNK,
            ),
        ] {
            assert_ne!(chunk, 0, "arrival {arrival} would not produce fills");
            let mut reader = ChunkReader::new(&framed, chunk);
            let record = acquire_hook_payload(&mut reader)
                .unwrap_or_else(|error| panic!("{arrival} must accept the record: {error:?}"));
            assert_eq!(
                record.len(),
                ceiling,
                "the ceiling-exact record must not lose its content CR: {arrival}"
            );
            assert_eq!(
                record,
                exact,
                "the accepted record must be byte-identical to the content written: {arrival}"
            );
            // And it decodes: the accepted bytes are a whole document.
            decode_hook_payload(&record)
                .unwrap_or_else(|error| panic!("{arrival}: ceiling record parses: {error:?}"));
        }
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
                // The published ceiling as a literal, not as the local alias
                // this test derived it from: an invented ceiling would satisfy
                // the alias comparison for any value.
                assert_eq!(limit_bytes, 1_048_576);
                assert!(found_terminator, "resynchronization found the terminator");
            }
            other => panic!("expected StdinOversize, got {other:?}"),
        }
    }

    /// A2: over-limit and malformed acquisition fail closed, and the
    /// acquisition/decode ordering precedes the one service construction.
    ///
    /// What this test proves, precisely: every refusal disposition is produced
    /// by the production functions with the invalid-argument exit code, and in
    /// the production region of this file both `?` come before the single
    /// `EliotHookService::for_session` construction, whose `process` call owns
    /// the branch's only spool write.
    ///
    /// What it does NOT prove, and no reader should take from it: that no
    /// service was ever BUILT. `exit_code()` is a pure match that returns the
    /// argument exit for every intake refusal whether or not a service exists,
    /// so the executed half cannot observe construction. What the executed half
    /// does observe is that the refusal carried the right typed disposition and
    /// that no additional spool record appeared under the root the same branch
    /// runs against; that half is asserted in
    /// `public_hook_branch_serves_an_accepted_payload_and_refuses_an_oversize_one`,
    ///
    /// A fake service is not used (forbidden), so the ordering is what carries
    /// the rest: the source scan below pins it in the real file.
    #[test]
    fn over_limit_and_malformed_dispositions_fail_closed_and_ordering_precedes_service() {
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
            .find("let record = acquire_hook_payload(stdin)?;")
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

    /// A private directory under the OS temp root that removes itself, so this
    /// test's spool observations are its own and leave nothing behind.
    ///
    /// The name carries the process id and the tag only. Two runs of this test
    /// live in different processes (and two harnesses in different sessions),
    /// and the tag is distinct per call, so that pair is unique without a clock:
    /// adding a timestamp would only reintroduce the `u128`-versus-`u64`
    /// uniqueness arithmetic that the pid makes unnecessary here.
    struct PrivateTempDir(PathBuf);

    impl PrivateTempDir {
        fn new(tag: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("eliot-hook-4601-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp dir must be creatable");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Number of JSON records the branch's only spool writer left behind.
        fn spool_records(&self) -> usize {
            std::fs::read_dir(self.0.join("hook-spool").join("pending"))
                .map(|entries| entries.filter_map(Result::ok).count())
                .unwrap_or(0)
        }
    }

    impl Drop for PrivateTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// D2: the public hook branch is driven end to end with finite readers and
    /// a caller-supplied runtime root.
    ///
    /// This runs the same code the process runs for `hook session-start`,
    /// through argv, bounded acquisition, decode, the real
    /// [`EliotHookService`], and the host decision write — with host stdin and
    /// the runtime root injected instead of taken from the process. Nothing
    /// below is substituted: there is no fake service and no stand-in decision,
    /// so the spool directory the run touches is the owner's own, under a
    /// temporary root instead of the developer's `LOCALAPPDATA`.
    ///
    /// It asserts:
    ///
    /// - an accepted payload runs the whole branch and spools exactly one
    ///   record into that root — the accepted payload is dispatched, not
    ///   silently dropped;
    /// - an over-limit payload is refused as `StdinOversize`, carrying the
    ///   published ceiling and `found_terminator: true` for the terminator the
    ///   bounded resynchronization found, and exiting with the argument status.
    ///
    /// It then asserts, from the filesystem, that the refused run left the
    /// record count exactly where the accepted run put it: one. That is the
    /// observed no-spool half of the property, and it is observed against the
    /// branch's own root rather than asserted from an ordering, so an
    /// over-limit payload that dispatched would show up here as a second
    /// record.
    ///
    /// The root reaches this run as a parameter, and the honest reason is the
    /// one recorded on [`run_hook_intake_with`]: this crate is
    /// `#![forbid(unsafe_code)]` and `std::env::set_var` / `remove_var` are
    /// `unsafe` in edition 2024, so there is no way to point
    /// `ELIOT_GOVERNOR_CONFIG` at a temporary directory from a test without
    /// wrapping the call in `unsafe` or allowing the lint. Threading the root
    /// in — to a service that takes its root as a plain constructor argument —
    /// relocates the spool without touching process-global state and leaves one
    /// production resolution path, which is [`run_hook_intake`] calling
    /// [`hook_runtime_root`] exactly once.
    ///
    /// What this therefore does NOT cover, stated so no reader over-trusts it:
    /// [`hook_runtime_root`]'s own reading of `ELIOT_GOVERNOR_CONFIG` and
    /// `LOCALAPPDATA` is unexercised here and remains covered only by its own
    /// contract, and the host decision document itself is written to the
    /// process's stdout port, which a unit test cannot capture, so the decision
    /// CONTENT is not asserted and is not claimed to be.
    #[test]
    fn public_hook_branch_serves_an_accepted_payload_and_refuses_an_oversize_one() {
        let temp = PrivateTempDir::new("public-branch");
        let root = temp.path();
        let event = vec!["session-start".to_owned()];

        // Accepted: the retired empty-input contract, so the payload is `{}`
        // and no host field is required.
        let mut empty_stdin = ChunkReader::new(b"", 4);
        run_hook_intake_with(&event, &mut empty_stdin, root)
            .expect("the public branch must serve an accepted empty payload");
        assert_eq!(
            temp.spool_records(),
            1,
            "an accepted payload reaches the service and spools one record"
        );

        // Refused: the same branch, one byte over the published ceiling, run
        // through the arrival that splits the terminator's carriage return onto
        // a fill of its own so the contested path is the one being refused.
        let mut over = Vec::new();
        over.extend(std::iter::repeat_n(
            b'a',
            HOOK_INPUT_PROFILE.max_record_bytes + 1,
        ));
        over.push(b'\r');
        over.push(b'\n');
        let mut over_stdin = ChunkReader::new(&over, CR_SPLIT_FILL_CHUNK);
        let error = run_hook_intake_with(&event, &mut over_stdin, root)
            .expect_err("an over-limit payload must be refused by the public branch");
        assert_eq!(error.code(), "HOOK_STDIN_OVERSIZE");
        assert_eq!(error.exit_code(), crate::INVALID_ARGUMENT_EXIT);
        assert!(matches!(
            error,
            HookIntakeError::StdinOversize {
                limit_bytes: 1_048_576,
                found_terminator: true,
                ..
            }
        ));
        assert_eq!(
            temp.spool_records(),
            1,
            "an over-limit payload must not spool a record; the count is still \
             the one the accepted run wrote"
        );
    }
}
