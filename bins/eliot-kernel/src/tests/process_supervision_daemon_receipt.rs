#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(
    clippy::too_many_lines,
    reason = "each case drives several real boundaries of one frozen #901 item"
)]

//! Kernel daemon live-receipt and supervision observation proof — issue #901
//! (F-LOG-KERNEL-3), checklist items W3, W14, W15, W16 and W19.
//!
//! The five #901-owned Kernel modules are private `mod`s of the crate root and
//! their observation helpers are `pub(crate)`, so this suite is registered as a
//! crate-internal `#[cfg(test)]` module and reaches them through
//! `use super::*`. Every case below drives a REAL production callsite of
//! `daemon_live_receipt.rs`, `daemon_supervision.rs`, `daemon_runtime.rs` or
//! `daemon_supervision.rs::bind_live_receipt_publication_operation` on a REAL
//! `KernelComposition`, captures the emitted bytes through the #895
//! `tracing_subscriber` seam, and asserts the DISTINCTION its item names —
//! never merely that a string was logged.
//!
//! * W3 — the frozen selected boundary set for daemon receipt request /
//!   publication / validation / expiry and readiness. TWO SEPARATE CLAIMS are
//!   pinned for it, and each is pinned by its own assertion. (1) The captured
//!   set equality asserts what the three DRIVEN functions emit on the arms this
//!   suite reaches, which is a strict subset of the module's callsites.
//!   (2) TWO SOURCE ABSENCES over `daemon_live_receipt.rs` itself, neither of
//!   which a capture can make. The first enumerates every one of that module's
//!   `observe_live_receipt` callsites and asserts that NONE of them carries an
//!   expiry / expired / ttl / stale / deadline / lapse literal. The second
//!   reads the module's WHOLE text and asserts that no `kernel.`-prefixed event
//!   literal in it carries one either, so a name emitted by a DIFFERENT or
//!   renamed helper in that module cannot pass the first absence unread.
//!   Together they pin the ABSENCE of a receipt EXPIRY observation in that
//!   module, including on arms this suite never drives. Claim (1) alone cannot
//!   pin that absence, and no expiry event name is invented to stand in for
//!   it.
//! * W14 — an invalid, stale or expired receipt cannot imply readiness.
//! * W15 — liveness differs from semantic readiness.
//! * W16 — requested, published and validated are distinct observations.
//! * W19 — an old or late generation receipt cannot restore current state.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01; implementation I1.5, I13.11,
//! I14.20, I14.21, I15.4, and I02.20 (Module Test Capsule). Test-oracle only:
//! no process, authority, Store or daemon ownership, and no production logic
//! cloned into the fixture.

#![cfg(windows)]

use super::*;
use std::io::Write;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_contracts::{EpochId, EpochLineageId};
use eliot_kernel_service::KernelActivationReceipt;
use eliot_runtime_contracts::{
    DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME, DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION,
    DAEMON_SUPERVISION_HEARTBEAT_SCHEMA, DaemonHeartbeatHealth, DaemonProgressChannel,
    DaemonProgressDisposition, DaemonProgressObservation, DaemonSupervisionRenewalPolicy,
    RegisteredActivityWakePolicy, SupervisionGenerationBinding, SupervisionJournalEpoch,
    SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
};

// ---------------------------------------------------------------------------
// Fixture constants. Every value below is fixture data for a real contract
// constructor; no production rule, digest or threshold is restated here.
// ---------------------------------------------------------------------------

const RECEIPT_ROOT: &str = r"C:\ProgramData\Eliot\HostState";
const LEASE_ID: &str = "eliot-supervision-lease:v1:current";
const EPOCH_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
const EPOCH_SEQUENCE: u64 = 1;
const AUTHORITY_SEQUENCE: u64 = 1;
const READY_REQUEST_ID: &str = "daemon-ready-1";
const OWNER_STATUS_CANARY: &str = "degraded-901-canary";

/// The frozen selected `kernel.live_receipt.*` boundary set of W3, in first
/// observed order across the request / publication / validation / readiness
/// callsites this suite DRIVES. This is the captured-bytes claim only: it says
/// what those callsites emit on the arms reached here, and it is not the
/// evidence for receipt EXPIRY being absent from the module. No expiry name is
/// fabricated to fill that gap; `LIVE_RECEIPT_CALLSITE_EVENTS` is.
const SELECTED_RECEIPT_BOUNDARIES: [&str; 6] = [
    "kernel.live_receipt.publication_requested",
    "kernel.live_receipt.publication_rejected",
    "kernel.live_receipt.validation_requested",
    "kernel.live_receipt.validation_observed",
    "kernel.live_receipt.readiness_requested",
    "kernel.live_receipt.readiness_rejected",
];

/// The event literal carried by EVERY production `observe_live_receipt`
/// callsite in `daemon_live_receipt.rs`, in source order, as read from that
/// file's own text by `observe_live_receipt_callsites`. It is the whole
/// observation vocabulary of the module: eleven callsites, ten distinct names,
/// because the two store-availability callsites share one name (the `:829`
/// arm names its own outcome literal, the `:902` arm names the refusing
/// owner). Adding, removing or renaming ANY callsite in that module reddens
/// this list, expiry-shaped or not.
const LIVE_RECEIPT_CALLSITE_EVENTS: [&str; 11] = [
    "kernel.live_receipt.publication_requested",
    "kernel.live_receipt.publication_replayed",
    "kernel.live_receipt.published",
    "kernel.live_receipt.publication_rejected",
    "kernel.live_receipt.validation_requested",
    "kernel.live_receipt.validation_observed",
    "kernel.live_receipt.readiness_requested",
    "kernel.live_receipt.readiness_proven",
    "kernel.live_receipt.readiness_rejected",
    "kernel.live_receipt.store_availability_refused",
    "kernel.live_receipt.store_availability_refused",
];

/// Substrings that would make an observed event literal expiry-shaped. Receipt
/// EXPIRY is one of the boundaries the issue selects, so a literal carrying any
/// of these at any `observe_live_receipt` callsite in
/// `daemon_live_receipt.rs` is exactly the production gap this suite records;
/// the module must carry none. The word list is the assertion's whole
/// vocabulary, so a new expiry name under a different word is a review item
/// rather than a silent pass.
///
/// The comparison behind that list is CASE-INSENSITIVE on both sides, because
/// an event vocabulary that differs from this one only in case is not this
/// vocabulary either: `kernel.live_receipt.TTL` is exactly as expiry-shaped as
/// `kernel.live_receipt.ttl`, and it is read through `carries_expiry_word`.
const EXPIRY_EVENT_WORDS: [&str; 6] = ["expiry", "expired", "ttl", "stale", "deadline", "lapse"];

// ---------------------------------------------------------------------------
// Capture seam (per-file duplication is the house pattern).
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("capture lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_with<F, R>(run: F) -> (String, R)
where
    F: FnOnce() -> R,
{
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let result = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

fn capture(run: impl FnOnce()) -> String {
    capture_with(run).0
}

/// Reads the RECORDED value of one `kernel.operation` span slot out of one
/// captured line, if that line carries it at all.
///
/// Two properties of the real renderer (tracing-subscriber 0.3.23) force this
/// shape, and both were read from that crate rather than assumed:
///
/// * `fmt::format::Format::format_event` writes exactly one opening brace
///   around the whole `FormattedFields` run, so the needle must be the bare
///   `slot="` and never `{slot="`.
/// * `FmtLayer::on_record` appends through `add_fields`, which pushes a space
///   and formats; it never rewrites the declared slot. A recorded value
///   therefore appears AFTER its declared default, so the LAST occurrence on
///   the line is the recorded value and the first is the declared default.
fn span_field<'a>(line: &'a str, slot: &str) -> Option<&'a str> {
    let needle = format!("{slot}=\"");
    let last = line.rfind(&needle)?;
    let rest = &line[last + needle.len()..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn captured_line<'a>(logs: &'a str, event: &str) -> &'a str {
    logs.lines()
        .find(|line| line.contains(&format!("event=\"{event}\"")))
        .unwrap_or_else(|| panic!("no captured line carries event={event}; captured: {logs}"))
}

/// Reads the value after the LAST occurrence of `key="` on one line.
fn quoted<'a>(line: &'a str, key: &str) -> &'a str {
    let needle = format!("{key}=\"");
    let start = line
        .rfind(&needle)
        .unwrap_or_else(|| panic!("field {key} absent from captured line: {line}"))
        + needle.len();
    let rest = &line[start..];
    let end = rest
        .find('"')
        .unwrap_or_else(|| panic!("unterminated field {key} in captured line: {line}"));
    &rest[..end]
}

/// The recorded value of one span slot under the given event, panicking with
/// the whole capture when the renderer dropped the line.
fn recorded(logs: &str, event: &str, slot: &str) -> String {
    let line = captured_line(logs, event);
    span_field(line, slot)
        .unwrap_or_else(|| panic!("span slot {slot} absent from captured line: {line}"))
        .to_owned()
}

fn event_outcome(logs: &str, event: &str) -> String {
    quoted(captured_line(logs, event), "outcome").to_owned()
}

fn event_count(logs: &str, event: &str) -> usize {
    logs.matches(&format!("event=\"{event}\"")).count()
}

fn terminal_codes(logs: &str) -> Vec<String> {
    logs.lines()
        .filter(|line| line.contains("event=\"kernel.terminal_error\""))
        .map(|line| quoted(line, "code").to_owned())
        .collect()
}

fn byte_offset(logs: &str, needle: &str) -> usize {
    logs.find(needle)
        .unwrap_or_else(|| panic!("{needle} absent from captured run: {logs}"))
}

/// Distinct `kernel.live_receipt.*` event names, in first observed order.
fn selected_receipt_events(logs: &str) -> Vec<String> {
    let mut events: Vec<String> = Vec::new();
    for line in logs.lines() {
        if !line.contains("event=\"kernel.live_receipt.") {
            continue;
        }
        let event = quoted(line, "event").to_owned();
        if !events.contains(&event) {
            events.push(event);
        }
    }
    events
}

/// One production `observe_live_receipt` callsite, as the source text states
/// it: the 1-based line it starts on, and every string literal its argument
/// list carries.
struct LiveReceiptCallsite {
    line: usize,
    literals: Vec<String>,
}

/// Reads `daemon_live_receipt.rs` from disk at test time, so the W3 absence
/// assertion reads the production module itself and never a copy of it.
///
/// The path is rooted at `env!("CARGO_MANIFEST_DIR")` — the manifest
/// directory of the crate this capsule is compiled into, fixed when the test
/// binary was built — joined with `src/daemon_live_receipt.rs`, which is where
/// this crate's own module lives. It therefore never depends on the working
/// directory the test binary happened to be launched from.
fn daemon_live_receipt_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("daemon_live_receipt.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} must be readable: {error}", path.display()))
}

/// Whether the FIRST argument of one argument list is itself a string literal.
///
/// The eleven-literal equality reads exactly that argument's literal, so an
/// argument that is a constant, a `static` or a macro-generated identifier
/// yields no literal at all — the collection cannot see inside it, and an
/// expiry-shaped name held there would be invisible to the absence scan while
/// the equality kept reading this callsite's other literals. Only whitespace,
/// comments and WRAPPING may come before or after that literal, all read with
/// the same literal-first ordering every other scanner here uses: a leading
/// comment then a literal (`/* why */ "x"`), a parenthesised literal (`("x")`)
/// and a block expression (`{ "x" }`) are the SAME single literal argument to
/// Rust, so reddening production code that spells them that way would be a
/// false red on correct code.
///
/// A MACRO CALL is still rejected, and must stay so: `concat!("a","b")` is not
/// one string literal, `string_literals` would collect its arguments instead,
/// and the frozen equality would then compare against the wrong value — a
/// loud, correct failure rather than a silent pass.
fn first_argument_is_a_string_literal(arguments: &str) -> bool {
    let bytes = arguments.as_bytes();
    let mut cursor = 0usize;
    // Wrappers the first argument may be spelled inside, as the closing
    // delimiter each one opened, innermost last.
    let mut wrapping: Vec<u8> = Vec::new();
    loop {
        if !skip_trivia(bytes, &mut cursor) {
            return false;
        }
        match bytes.get(cursor) {
            Some(b'(') => {
                wrapping.push(b')');
                cursor += 1;
            }
            Some(b'{') => {
                wrapping.push(b'}');
                cursor += 1;
            }
            Some(_) => break,
            // An empty first argument carries no literal.
            None => return false,
        }
    }
    let LiteralAt::Terminated(body) = string_literal_body(bytes, cursor) else {
        return false;
    };
    let mut cursor = body.resume;
    loop {
        if !skip_trivia(bytes, &mut cursor) {
            return false;
        }
        match bytes.get(cursor) {
            // A closing wrapper ends the same argument the literal started.
            Some(closed) if wrapping.last() == Some(closed) => {
                wrapping.pop();
                cursor += 1;
            }
            // The literal IS the whole first argument once every wrapper it was
            // spelled inside is closed; `None` here is the one-argument list.
            Some(b',') | None => return wrapping.is_empty(),
            // Anything else after the literal is a second expression, so the
            // first argument is not a literal.
            Some(_) => return false,
        }
    }
}

/// Advances `cursor` past whitespace and comments, in the literal-first order
/// every other scanner here uses. `false` means an unterminated block comment
/// was met here, which no shape this fixture models and which every caller
/// reports rather than scanning past.
fn skip_trivia(bytes: &[u8], cursor: &mut usize) -> bool {
    loop {
        while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
            *cursor += 1;
        }
        match comment_span(bytes, *cursor) {
            CommentAt::Terminated(end) => *cursor = end,
            CommentAt::Unterminated => return false,
            CommentAt::NoComment => return true,
        }
    }
}

/// The source text of the FIRST argument of one argument list, cut at the first
/// comma that sits OUTSIDE any literal, comment or nesting. It is read for a
/// failure message only, and it exists because `split(',')` reports `"a` for a
/// first argument spelled `("a,b", …)`, which names a value the callsite never
/// had.
fn first_argument_text(arguments: &str) -> &str {
    let bytes = arguments.as_bytes();
    let mut cursor = 0usize;
    let mut depth = 0usize;
    while cursor < bytes.len() {
        if !skip_trivia(bytes, &mut cursor) {
            break;
        }
        match string_literal_body(bytes, cursor) {
            LiteralAt::Terminated(body) => {
                cursor = body.resume;
                continue;
            }
            // An unterminated literal is the list scanner's own failure; the
            // message quotes what was read up to it.
            LiteralAt::Unterminated => break,
            LiteralAt::NoLiteral => {}
        }
        match bytes.get(cursor) {
            Some(b',') if depth == 0 => break,
            Some(b'(' | b'{') => depth += 1,
            Some(b')' | b'}') => depth = depth.saturating_sub(1),
            None => break,
            Some(_) => {}
        }
        cursor += 1;
    }
    arguments.get(..cursor).unwrap_or(arguments).trim()
}

/// Every `observe_live_receipt(` callsite in one source text, in source order.
///
/// The `fn observe_live_receipt` declaration is skipped by its `fn ` prefix, so
/// only calls are listed. Each argument list is read between balanced
/// parentheses, so a `(` inside one of its string literals cannot end the scan
/// early, and the scan resumes past the closing parenthesis so an argument list
/// is never read twice. Comments inside an argument list are skipped by both
/// the balance walk and the literal collection, so no callsite can be read as a
/// shorter one. The FIRST argument of every listed callsite must itself be a
/// string literal, because that is the value the frozen eleven-literal equality
/// is about. A callsite whose argument list is never balanced, whose last
/// literal is never terminated, or whose first argument is not a literal is a
/// source shape this fixture does not model and fails loudly rather than being
/// skipped.
fn observe_live_receipt_callsites(source: &str) -> Vec<LiveReceiptCallsite> {
    const CALL: &str = "observe_live_receipt(";
    let mut sites: Vec<LiveReceiptCallsite> = Vec::new();
    // Every index below is an index into `source` itself, so the reported line
    // and the scanned text are both absolute.
    let mut scanned = 0usize;
    while let Some(found) = source[scanned..].find(CALL) {
        let at = scanned + found;
        let arguments_start = at + CALL.len();
        let line = 1 + source[..at].matches('\n').count();
        let Some(arguments_end) = balanced_argument_end(source, arguments_start) else {
            panic!(
                "observe_live_receipt( at daemon_live_receipt.rs:{line} has no balanced argument list"
            );
        };
        if !source[..at].ends_with("fn ") {
            let arguments = &source[arguments_start..arguments_end];
            assert!(
                first_argument_is_a_string_literal(arguments),
                "the FIRST argument of the observe_live_receipt( callsite at daemon_live_receipt.rs:{line} must be a string literal, so the frozen eleven-literal equality compares a real value instead of nothing; it passed {first_argument:?}, and a macro call such as concat!(\"a\",\"b\") is not one literal — string_literals would collect its arguments instead and the equality would compare against the wrong value",
                first_argument = first_argument_text(arguments)
            );
            sites.push(LiveReceiptCallsite {
                line,
                literals: string_literals(arguments),
            });
        }
        scanned = arguments_end;
    }
    sites
}

/// Index of the `)` closing an argument list whose `(` sits just before
/// `start`. EVERY string literal form is skipped by `string_literal_body` —
/// plain `"`, byte `b"`, raw `r"`/`r#".."#` with any `#` count, and byte-raw
/// `br"`/`br#".."#` — so a `(` inside any of them cannot end the scan
/// early, and the scan resumes past the closing parenthesis so an argument list
/// is never read twice. EVERY comment form is then skipped by `comment_span`,
/// so a `)` inside a comment cannot end the scan early and a `(` inside one
/// cannot over-collect either. A callsite whose argument list is never
/// balanced, or whose last literal or last block comment is never terminated,
/// is a source shape this fixture does not model and fails loudly rather than
/// being skipped.
fn balanced_argument_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 1usize;
    let mut index = start;
    while index < bytes.len() {
        match string_literal_body(bytes, index) {
            LiteralAt::Terminated(body) => index = body.resume,
            // An opened but unterminated literal would swallow the rest of the
            // file if it were scanned as code; report it as unbalanced.
            LiteralAt::Unterminated => return None,
            // Comments are consulted only AFTER the literal forms at this index,
            // so a `//` or `/*` inside a literal body is content and never opens
            // a comment. An unterminated block comment would otherwise swallow
            // the rest of the file, so it is unbalanced, not truncated.
            LiteralAt::NoLiteral => match comment_span(bytes, index) {
                CommentAt::Terminated(end) => index = end,
                CommentAt::Unterminated => return None,
                CommentAt::NoComment => {
                    match bytes[index] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                return Some(index);
                            }
                        }
                        _ => {}
                    }
                    index += 1;
                }
            },
        }
    }
    None
}

/// One terminated string literal, as TWO ranges: the `interior` the literal's
/// own text occupies, which excludes the opening delimiter, the closing
/// delimiter and any closing `#` run, and the `resume` index a scanner
/// continues at, which is just PAST that closing delimiter. They are separate
/// because a caller that COLLECTS the literal reads `interior` while a caller
/// that SCANS for delimiters resumes at `resume`; a `(` or a quote inside the
/// literal can only be skipped by resuming past the delimiter, and a value
/// compared against production's own spelling can only be the interior.
#[derive(Clone)]
struct StringLiteralBody {
    interior: Range<usize>,
    resume: usize,
}

/// What a string literal form DOES at the byte a scanner is standing on, as
/// the deliberate TRI-STATE every scanner here depends on. An enum names all
/// three at each call site, so the state a scanner must answer for can never be
/// dropped or widened the way a nested `Option` at a callsite can.
enum LiteralAt {
    /// No literal form opens here, so the byte is ordinary source text and the
    /// scanner decides for itself what it means.
    NoLiteral,
    /// A literal opened at this byte and is never terminated, which no shape
    /// this fixture models and which every scanner reports loudly rather than
    /// treating the rest of the file as literal text.
    Unterminated,
    /// A terminated literal, whose `interior` excludes BOTH delimiters and any
    /// `#` run and whose `resume` sits just past the closing delimiter.
    Terminated(StringLiteralBody),
}

/// The body of the string literal that opens at `index`, as `LiteralAt`.
///
/// Escapes inside a plain or byte literal are not decoded: every literal at
/// these callsites is plain ASCII text, and a decoded value would be a second
/// reading of the same source rather than the source itself.
fn string_literal_body(bytes: &[u8], index: usize) -> LiteralAt {
    let mut cursor = index;
    let mut raw = false;
    match bytes.get(cursor) {
        Some(b'"') => {}
        Some(b'r') => {
            raw = true;
            cursor += 1;
        }
        Some(b'b') => {
            cursor += 1;
            if bytes.get(cursor) == Some(&b'r') {
                raw = true;
                cursor += 1;
            }
        }
        _ => return LiteralAt::NoLiteral,
    }
    let mut hashes = 0usize;
    if raw {
        while bytes.get(cursor) == Some(&b'#') {
            hashes += 1;
            cursor += 1;
        }
    }
    if bytes.get(cursor) != Some(&b'"') {
        return LiteralAt::NoLiteral;
    }
    let body_start = cursor + 1;
    let found = if raw {
        raw_body(bytes, body_start, hashes)
    } else {
        quoted_body(bytes, body_start)
    };
    match found {
        Some(body) => LiteralAt::Terminated(body),
        None => LiteralAt::Unterminated,
    }
}

/// The interior of a plain or byte literal, honouring backslash escapes, plus
/// the index just past its closing `"` to resume at, or `None` when it is never
/// closed.
fn quoted_body(bytes: &[u8], body_start: usize) -> Option<StringLiteralBody> {
    let mut cursor = body_start;
    let mut escaped = false;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => {
                return Some(StringLiteralBody {
                    interior: body_start..cursor,
                    resume: cursor + 1,
                });
            }
            _ => escaped = false,
        }
        cursor += 1;
    }
    None
}

/// The interior of a raw or byte-raw literal, plus the index just past its
/// closing `"` and `hashes` `#` to resume at, or `None` when it is never closed.
/// A `"` inside the body is content, not a terminator, unless its own `#` run
/// closes the literal, so `r#"a"expiry"b"#` is the single body `a"expiry"b`
/// rather than `a`.
fn raw_body(bytes: &[u8], body_start: usize, hashes: usize) -> Option<StringLiteralBody> {
    let mut cursor = body_start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"'
            && (1..=hashes).all(|offset| bytes.get(cursor + offset) == Some(&b'#'))
        {
            return Some(StringLiteralBody {
                interior: body_start..cursor,
                resume: cursor + 1 + hashes,
            });
        }
        cursor += 1;
    }
    None
}

/// What a comment form DOES at the byte a scanner is standing on, as the same
/// deliberate TRI-STATE `LiteralAt` names for the literal forms.
enum CommentAt {
    /// No comment form opens here, so the byte is ordinary source text.
    NoComment,
    /// A block comment opened at this byte and is never closed, which no shape
    /// this fixture models and which every caller reports loudly rather than
    /// truncating at the opening `/*`.
    Unterminated,
    /// The index just past the comment's end, for a terminated comment.
    Terminated(usize),
}

/// End just past the comment that opens at `index`, in the two forms Rust
/// spells. A line comment runs to the newline or to the end of the file; a
/// block comment runs to the `*/` that closes it at NESTING DEPTH ZERO, because
/// Rust nests block comments, so `/* /* */ */` is one comment.
///
/// Both callers consult this ONLY AFTER `string_literal_body` has reported that
/// no literal opens at the same index, so a `//` or `/*` inside a literal body
/// — including inside `r#".."#` — is literal content and never opens a comment.
/// `balanced_argument_end` and `string_literals` share it so neither can read a
/// comment the other skipped.
fn comment_span(bytes: &[u8], index: usize) -> CommentAt {
    if bytes.get(index) != Some(&b'/') {
        return CommentAt::NoComment;
    }
    match bytes.get(index + 1) {
        Some(b'/') => {
            let mut end = index + 2;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            CommentAt::Terminated(if end < bytes.len() { end + 1 } else { end })
        }
        Some(b'*') => {
            let mut cursor = index + 2;
            let mut depth = 1usize;
            while cursor < bytes.len() {
                if bytes[cursor..].starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                    if depth == 0 {
                        return CommentAt::Terminated(cursor);
                    }
                } else if bytes[cursor..].starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            CommentAt::Unterminated
        }
        _ => CommentAt::NoComment,
    }
}

/// The string literals of one source text, in order, in EVERY form Rust
/// spells them: plain `"`, byte `b"`, raw `r"` through `r###".."###` and
/// byte-raw `br"`. A literal written in any of those forms is collected and
/// scanned exactly like a plain one, so an expiry observation cannot hide
/// behind a raw spelling. Comments are skipped AFTER the literal forms, so no
/// literal inside a comment is collected and a comment cannot split a list into
/// a shorter one. An unterminated literal or block comment is loud, never a
/// short list. It reads one `observe_live_receipt` argument list below and one
/// whole module in `kernel_event_literals`, so its failures name no single
/// caller.
fn string_literals(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut literals: Vec<String> = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        match string_literal_body(bytes, index) {
            LiteralAt::Terminated(body) => {
                literals.push(
                    String::from_utf8_lossy(&bytes[body.interior.start..body.interior.end])
                        .into_owned(),
                );
                index = body.resume;
            }
            LiteralAt::Unterminated => {
                panic!("a string literal of the scanned source is never terminated")
            }
            LiteralAt::NoLiteral => match comment_span(bytes, index) {
                CommentAt::Terminated(end) => index = end,
                CommentAt::Unterminated => {
                    panic!("a block comment of the scanned source is never terminated")
                }
                CommentAt::NoComment => index += 1,
            },
        }
    }
    literals
}

/// The decoded reading of ONE collected literal: the escapes a plain Rust
/// literal can carry, resolved to the characters they denote — the hex form
/// `\xNN`, the Unicode scalar form `\u{...}`, and the single-character forms
/// `\\`, `\"`, `\'`, `\n`, `\r`, `\t` and `\0`. `"\x73tale"` decodes to `stale`,
/// which the raw eight characters backslash-x-7-3-t-a-l-e do not carry, and
/// `"\u{73}tale"` decodes to the same `stale` through the other spelling Rust
/// offers for the same character. Both are read here because a literal that
/// DENOTES an expiry word is expiry-shaped however Rust spells it.
///
/// Decoding happens HERE, for the absence scan alone. `string_literals` and
/// `quoted_body` still return the source text, because the frozen
/// eleven-literal equality compares production's own literal SPELLING against
/// `LIVE_RECEIPT_CALLSITE_EVENTS` and must keep reading exactly that. An escape
/// this reader does not model is left written as it stands, so the raw text is
/// still scanned; a raw `r"…"` literal carries no escapes, so decoding one can
/// only err towards red, never towards a silent pass.
fn decode_literal_escapes(literal: &str) -> String {
    let mut decoded = String::with_capacity(literal.len());
    let mut rest = literal;
    while let Some(at) = rest.find('\\') {
        decoded.push_str(&rest[..at]);
        let escape = &rest[at + 1..];
        let Some(escaped) = escape.chars().next() else {
            decoded.push('\\');
            break;
        };
        let (character, consumed) = match escaped {
            '\\' => ('\\', 1),
            '"' => ('"', 1),
            '\'' => ('\'', 1),
            'n' => ('\n', 1),
            'r' => ('\r', 1),
            't' => ('\t', 1),
            '0' => ('\0', 1),
            // `\xNN` denotes the character whose value is NN; `\u{...}` is that
            // same character written as a Unicode scalar. A short or non-hex
            // digit run is neither and stays written as it is. The tail is read
            // through `get`, exactly as the `\xNN` digits are, because an
            // escape with no tail at all must stay written rather than panic.
            'x' => match u8::from_str_radix(escape.get(1..3).unwrap_or_default(), 16) {
                Ok(byte) => (char::from(byte), 3),
                Err(_) => ('\\', 0),
            },
            'u' => match escape.get(1..).and_then(|tail| tail.strip_prefix('{')) {
                // `map_or` not `and_then`: a missing closing brace and an
                // undecodable scalar are the SAME outcome here, both the literal
                // backslash, so the fallback is the one the `None` arms return.
                Some(digits) => digits.find('}').map_or(('\\', 0), |end| {
                    u32::from_str_radix(&digits[..end], 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map_or(('\\', 0), |scalar| (scalar, 2 + end + 1))
                }),
                None => ('\\', 0),
            },
            _ => ('\\', 0),
        };
        decoded.push(character);
        rest = if consumed == 0 {
            escape
        } else {
            &escape[consumed..]
        };
    }
    decoded.push_str(rest);
    decoded
}

/// Whether one collected literal carries any word of `EXPIRY_EVENT_WORDS`,
/// tested against BOTH its raw source spelling and its decoded reading, and
/// CASE-INSENSITIVELY on both sides, so neither an escaped letter nor a
/// different case can hide the word: the absence this assertion records is
/// about the VALUE a callsite emits, and `kernel.live_receipt.TTL` spelled with
/// `\x54` bytes is as expiry-shaped as `kernel.live_receipt.ttl` is plainly.
fn carries_expiry_word(literal: &str) -> bool {
    let raw = literal.to_lowercase();
    let decoded = decode_literal_escapes(literal).to_lowercase();
    EXPIRY_EVENT_WORDS
        .iter()
        .any(|word| raw.contains(*word) || decoded.contains(*word))
}

/// Every `kernel.`-prefixed string literal in one source text, in source order —
/// that is, every literal in the module that names a Kernel diagnostic EVENT.
///
/// `observe_live_receipt_callsites` is scoped to ONE helper by name, so a
/// renamed or newly added `observe_*` helper in `daemon_live_receipt.rs` would
/// carry an expiry-shaped event name past it with no word ever scanned. This
/// scan reads the module's WHOLE text instead, so WHICH helper spells a name no
/// longer decides whether the absence assertion sees it. It reuses
/// `string_literals`, so every literal form is read alike and comments are
/// skipped, and the `kernel.`-prefixed literals the module holds are exactly
/// its event names: the module's other strings are `kernel`-HYPHENATED handle
/// prefixes (`kernel-process:`, `kernel-job:`, `kernel-store-…`) and owner error
/// text, which this prefix does not match.
fn kernel_event_literals(source: &str) -> Vec<String> {
    string_literals(source)
        .into_iter()
        .filter(|literal| literal.starts_with("kernel."))
        .collect()
}

// ---------------------------------------------------------------------------
// Fixture builders. Each one constructs a real contract value through its own
// constructor so the production validators, not the test, decide validity.
// ---------------------------------------------------------------------------

struct TempRoot(PathBuf);

impl TempRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_root(tag: &str) -> TempRoot {
    let root = std::env::temp_dir().join(format!(
        "eliot-901-receipt-{tag}-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    std::fs::create_dir_all(&root).expect("fixture work root");
    TempRoot(root)
}

/// The root guard is returned first, so every call site binds it first and
/// reverse declaration order drops the composition (which holds the fixture's
/// open ORS file) before the guard removes the work root, exactly as the other
/// in-crate Kernel suites do.
fn test_kernel(tag: &str) -> (TempRoot, KernelComposition) {
    let root = test_root(tag);
    let kernel =
        KernelComposition::new(KernelConfig::new(root.path())).expect("kernel composition");
    (root, kernel)
}

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new(EPOCH_LINEAGE).expect("epoch lineage"),
        std::num::NonZeroU64::new(EPOCH_SEQUENCE).expect("epoch sequence"),
    )
    .expect("epoch")
}

fn test_generation(generation: u64) -> ResourceGeneration {
    ResourceGeneration::new(generation).expect("resource generation")
}

/// One real `ProcessStartReceipt` for the given admitted generation. The
/// binding, its state fence and the identity all carry the same generation, so
/// the contract's own `matches_identity` accepts it; nothing here decides
/// validity.
fn test_process_start_receipt(generation: u64) -> ProcessStartReceipt {
    let receipt: ProcessStartReceipt = serde_json::from_value(serde_json::json!({
        "binding": {
            "operation_id": "eliotd-901-receipt-operation",
            "process_tree_id": "eliotd-901-receipt-tree",
            "job_id": "eliotd-901-receipt-job",
            "image_id": "eliotd-901-receipt-image",
            "session_id": "eliotd-901-receipt-session",
            "generation": generation,
            "action_lease_ref": "eliotd-901-receipt-lease",
            "authority_id": "eliotd",
            "authority_epoch": {
                "lineage_id": EPOCH_LINEAGE,
                "sequence": EPOCH_SEQUENCE
            },
            "state_fence": {
                "authority_epoch": {
                    "lineage_id": EPOCH_LINEAGE,
                    "sequence": EPOCH_SEQUENCE
                },
                "generation": generation,
                "nonce": "eliotd-901-receipt-fence"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 1
        },
        "identity": {
            "suspended": {
                "process_id": "eliotd-901-receipt-process",
                "process_tree_id": "eliotd-901-receipt-tree",
                "job_id": "eliotd-901-receipt-job",
                "image_id": "eliotd-901-receipt-image",
                "session_id": "eliotd-901-receipt-session",
                "generation": generation,
                "physical": {
                    "process_id": 4401,
                    "start_time_100ns": 1,
                    "image_path": r"C:\ProgramData\Eliot\bin\eliotd.exe",
                    "executor_job_name": r"Local\Eliot-P04-901"
                },
                "created_suspended_at_unix_ms": 1,
                "executable_sha256": "a".repeat(64)
            },
            "resumed_at_unix_ms": 2
        },
        "lifecycle": "running"
    }))
    .expect("test process start receipt");
    receipt
        .validate()
        .expect("receipt passes the contract validator");
    receipt
}

fn test_ready_evidence(generation: u64, request_id: &str) -> EliotdLiveReadyEvidence {
    EliotdLiveReadyEvidence {
        request_id: request_id.to_owned(),
        request_payload_sha256: "9".repeat(64),
        connection_id: "connection-1".to_owned(),
        session_epoch: EPOCH_SEQUENCE,
        authority_epoch: AUTHORITY_SEQUENCE,
        generation,
        launch_nonce_sha256: "a".repeat(64),
    }
}

/// One real `EliotdLiveReceipt` at the given generation and supervision
/// revision. The digest the receipt cites is the one its own constructor
/// computes, so a mutation made afterwards is exactly what invalidates it.
fn test_live_receipt(
    generation: u64,
    revision: u64,
    ors_receipt_sha256: &str,
    request_id: &str,
) -> EliotdLiveReceipt {
    EliotdLiveReceipt::new(
        RECEIPT_ROOT,
        "1".repeat(64),
        "2".repeat(64),
        "installation-901",
        format!("generation-{generation}"),
        generation,
        AUTHORITY_SEQUENCE,
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        test_process_start_receipt(generation),
        EliotdLiveSupervisionEvidence {
            lease_id: LEASE_ID.to_owned(),
            record_id: format!("{LEASE_ID}::r{revision:020}"),
            revision,
            receipt_sha256: ors_receipt_sha256.to_owned(),
            envelope_sha256: "6".repeat(64),
            payload_sha256: "7".repeat(64),
            public_key_fingerprint: "8".repeat(64),
        },
        test_ready_evidence(generation, request_id),
        1_000 + revision,
    )
    .expect("valid test eliotd live receipt")
}

fn test_supervision_incarnation() -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:901".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: "installation-901".to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: "host-lineage-901".to_owned(),
            sequence: EPOCH_SEQUENCE,
        },
        activation_id: "activation-901".to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-901".to_owned(),
            sequence: EPOCH_SEQUENCE,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: "kernel-lineage-901".to_owned(),
            sequence: EPOCH_SEQUENCE,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-901".to_owned(),
            sequence: EPOCH_SEQUENCE,
        },
        observation_scope: SupervisionObservationScope {
            targets: vec!["eliot-kernel".to_owned()],
            sensor_profile: "eliot-runtime-live-v3".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live-v3".to_owned(),
        },
        wake_policy: RegisteredActivityWakePolicy::Disabled,
        predecessor: None,
    }
    .with_derived_ids()
    .expect("sealed supervision incarnation")
}

/// One real `KernelActivationReceipt`, assembled from its own published fields.
fn test_activation_receipt(generation: u64) -> KernelActivationReceipt {
    KernelActivationReceipt {
        operation_id: PlatformHandle::new("eliot-901-activation-operation").expect("activation op"),
        candidate_binding_digest: "a".repeat(64),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: PlatformHandle::new("eliot-901-journal-transaction")
            .expect("journal transaction"),
        journal_sequence: 1,
        generation: test_generation(generation),
        authority_epoch: test_epoch(),
        activation_nonce_digest: "c".repeat(64),
    }
}

fn test_contour(generation: u64) -> DaemonSupervisionContour {
    DaemonSupervisionContour {
        candidate_digest: "a".repeat(64),
        incarnation: test_supervision_incarnation(),
        activation: test_activation_receipt(generation),
        generation_binding: SupervisionGenerationBinding {
            target_id: "eliot-901-artifact".to_owned(),
            target_generation: test_generation(generation),
            module_id: "eliotd".to_owned(),
            module_generation: test_generation(generation),
            process_id: "pid:4401:start:1".to_owned(),
            process_generation: test_generation(generation),
        },
        state_fence: StateFence::new(test_epoch(), test_generation(generation)),
    }
}

fn test_launch(root: &Path) -> EliotdLaunchDescriptor {
    let executable =
        PlatformHandle::new(root.join("eliotd.exe").to_string_lossy()).expect("eliotd path");
    let config = PlatformHandle::new(root.join("eliotd-governor.json").to_string_lossy())
        .expect("eliotd config path");
    let working_directory = PlatformHandle::new(root.to_string_lossy()).expect("working directory");
    let executable_sha256 = "a".repeat(64);
    let config_sha256 = "b".repeat(64);
    let nonce =
        PlatformHandle::new("eliotd:9010123456789abcdef0123456789ab").expect("launch nonce");
    EliotdLaunchDescriptor {
        wire_id: "eliot.kernel.eliotd-launch".to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable,
        executable_sha256: executable_sha256.clone(),
        arguments: vec![
            PlatformHandle::new("--config-descriptor").expect("argument"),
            config.clone(),
            PlatformHandle::new("--config-descriptor-sha256").expect("argument"),
            PlatformHandle::new(&config_sha256).expect("argument"),
            PlatformHandle::new("--launch-nonce").expect("argument"),
            nonce.clone(),
            PlatformHandle::new("--executable-sha256").expect("argument"),
            PlatformHandle::new(&executable_sha256).expect("argument"),
        ],
        working_directory,
        config_descriptor: config,
        config_descriptor_sha256: config_sha256,
        protected_snapshot_digest: "c".repeat(64),
        launch_nonce: nonce,
        authority_epoch: test_epoch(),
        generation: test_generation(1),
        restart_policy: None,
        job_object_limits: None,
        health_readiness_contract_ref: None,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("descriptor digest")
}

fn test_renewal_policy() -> DaemonSupervisionRenewalPolicy {
    DaemonSupervisionRenewalPolicy {
        validity_ms: 60_000,
        renew_after_ms: 30_000,
        max_observation_age_ms: 10_000,
        max_wall_skew_ms: 5_000,
        require_watchdog_coverage: false,
    }
}

/// One real `DaemonProgressObservation` on the same epoch, generation, lease
/// and artifact identities the contour builder above uses, so the contract's
/// own `validate` accepts it. Every field is ordinary fixture data: this value
/// decides nothing, it is the evidence a verified renewal is recorded against.
fn test_progress_observation() -> DaemonProgressObservation {
    let kernel_epoch = test_epoch();
    let activation_generation = test_generation(1);
    let observation = DaemonProgressObservation {
        schema: DAEMON_SUPERVISION_HEARTBEAT_SCHEMA.to_owned(),
        contract_name: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_NAME.to_owned(),
        contract_version: DAEMON_SUPERVISION_HEARTBEAT_CONTRACT_VERSION,
        observation_id: "eliot-901-progress-observation".to_owned(),
        installation_id: "installation-901".to_owned(),
        activation_id: "activation-901".to_owned(),
        activation_generation,
        generation_binding: SupervisionGenerationBinding {
            target_id: "eliot-901-artifact".to_owned(),
            target_generation: test_generation(1),
            module_id: "eliotd".to_owned(),
            module_generation: test_generation(1),
            process_id: "pid:4401:start:1".to_owned(),
            process_generation: test_generation(1),
        },
        daemon_artifact_id: "eliotd-901-artifact".to_owned(),
        daemon_config_digest: "7".repeat(64),
        kernel_epoch: kernel_epoch.clone(),
        state_fence: StateFence::new(kernel_epoch, activation_generation),
        boot_id: "boot-901".to_owned(),
        transport_session_evidence: "session-901".to_owned(),
        transport_connection_evidence: "connection-901".to_owned(),
        lease_id: LEASE_ID.to_owned(),
        lease_revision: 4,
        predecessor_receipt_sha256: "8".repeat(64),
        progress_channel: DaemonProgressChannel::Claim,
        progress_cursor: 2,
        previous_progress_cursor: 1,
        observed_monotonic_ms: 2_000,
        observed_wall_ms: 1_000,
        disposition: DaemonProgressDisposition::ForwardProgress,
        idle_contract_id: None,
        waiting_on_dependency: None,
        evidence_refs: vec!["process:eliotd-901:alive".to_owned()],
        health: DaemonHeartbeatHealth::healthy(),
        watchdog_covered: true,
    };
    observation
        .validate()
        .expect("the progress observation passes the contract validator");
    observation
}

/// The ORS renewal successor that the production classifier requires before it
/// will replace an existing receipt. Its `state` is left to the caller because
/// the lease state IS the claim under test.
fn renewal_successor(
    expected: &EliotdLiveReceipt,
    previous_ors_receipt_sha256: &str,
    state: LeaseState,
) -> EliotdSupervisionSuccessorEvidence {
    EliotdSupervisionSuccessorEvidence {
        operation: SupervisionLeaseOperation::Renew,
        state,
        lease_id: expected.supervision.lease_id.clone(),
        revision: expected.supervision.revision,
        receipt_sha256: expected.supervision.receipt_sha256.clone(),
        previous_receipt_sha256: Some(previous_ors_receipt_sha256.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// W3 — the frozen selected boundary set.
// ---------------------------------------------------------------------------

#[test]
fn live_receipt_boundaries_are_exactly_the_frozen_selection() {
    // The issue freezes "daemon receipt request/publication/validation/expiry"
    // plus readiness as the selected boundaries. Each one is driven here at its
    // real callsite in `daemon_live_receipt.rs`: the request and publication
    // events at `publish_eliotd_live_receipt` (daemon_live_receipt.rs:146 and
    // :182), the validation pair at `verify_published_eliotd_live_receipt`
    // (:456 and :462), and the readiness pair at
    // `validate_daemon_process_readiness_in_context` (:577 and :591).
    let (root_guard, kernel) = test_kernel("case5");
    let launch = test_launch(root_guard.path());
    let process = test_process_start_receipt(1);
    let ready = test_ready_evidence(1, READY_REQUEST_ID);
    let contour = test_contour(1);
    let receipt = test_live_receipt(1, 4, &"b".repeat(64), READY_REQUEST_ID);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");

    let (publication_logs, publication) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        kernel.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, None, &context)
    });
    // A composition assembled without a manifest-bound receipt root cannot
    // publish, so this case observes the refused arm of both boundaries. The
    // refusal is the real owner decision, not a substituted expectation.
    assert!(
        matches!(&publication, Err(KernelServiceError::ReadinessNotProven)),
        "an unproven receipt root cannot publish: {publication:?}"
    );

    let (validation_logs, validation) =
        capture_with(|| kernel.verify_published_eliotd_live_receipt(&receipt, &noop_context()));
    assert!(
        matches!(&validation, Err(KernelServiceError::ReadinessNotProven)),
        "an unread published receipt cannot validate: {validation:?}"
    );

    let (readiness_logs, readiness) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        runtime.block_on(
            kernel.validate_daemon_process_readiness_in_context(&launch, &process, &context, true),
        )
    });
    assert!(
        matches!(&readiness, Err(KernelServiceError::ReadinessNotProven)),
        "readiness is not proven without physical process authority: {readiness:?}"
    );

    // Claim (1): the captured bytes of the three DRIVEN functions are exactly
    // the frozen set, in first observed order. This says what those arms emit,
    // and nothing more: the drive reaches five of the module's eleven
    // callsites, so on its own it cannot speak for the other six.
    let all = format!("{publication_logs}{validation_logs}{readiness_logs}");
    assert_eq!(
        selected_receipt_events(&all),
        SELECTED_RECEIPT_BOUNDARIES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<String>>(),
        "the three driven daemon-receipt boundaries emit exactly these names; the module-wide absence of an expiry callsite is asserted by the source enumeration below, not by this capture: {all}"
    );

    // Claim (2), and the only one a capture cannot make: receipt EXPIRY has no
    // callsite ANYWHERE in `daemon_live_receipt.rs`, including on the arms this
    // suite never drives (the publication success arm, the replay arm, the
    // validation success literal, the readiness success arm, and both
    // store-availability arms). That is a property of the module's whole text,
    // so it is asserted by reading the module TWICE: once by enumerating every
    // one of its `observe_live_receipt` callsites, and once by reading every
    // `kernel.`-prefixed event literal in its whole text, so the absence does
    // not depend on which helper spells a name. First the enumeration itself is
    // pinned to the callsites the module has, so this assertion cannot go
    // vacuous by finding nothing.
    let source = daemon_live_receipt_source();
    let callsites = observe_live_receipt_callsites(&source);
    let callsite_events: Vec<&str> = callsites
        .iter()
        .map(|site| {
            site.literals
                .first()
                .map_or("<no event literal>", String::as_str)
        })
        .collect();
    assert_eq!(
        callsite_events,
        LIVE_RECEIPT_CALLSITE_EVENTS.to_vec(),
        "these are every observe_live_receipt callsite of daemon_live_receipt.rs, in source order, with the event literal each one carries; the two store-availability callsites share one name"
    );
    // And then the absence the issue's EXPIRY item names: no callsite of that
    // module may carry an expiry-shaped literal, so adding one anywhere in it
    // — on a driven arm or an undriven one — reddens this case. The test is on
    // the VALUE each literal carries, so it reads both the raw source spelling
    // and its escapes, on either side of the letter case.
    //
    // REGRESSION GUARD (absence). The positive role of this leg is the
    // eleven-literal equality immediately above, which is also its
    // non-vacuity anchor: it cannot pass while finding nothing.
    for site in &callsites {
        for literal in &site.literals {
            assert!(
                !carries_expiry_word(literal),
                "REGRESSION GUARD (absence): no observe_live_receipt callsite of daemon_live_receipt.rs may carry an expiry-shaped literal ({EXPIRY_EVENT_WORDS:?}, compared case-insensitively and through its escapes); {literal:?} at daemon_live_receipt.rs:{} would be a receipt-EXPIRY observation this issue's selected boundary set requires to exist",
                site.line
            );
        }
    }
    // The same absence, read from the module's WHOLE text instead of from one
    // helper's callsites, so an expiry-shaped EVENT NAME cannot hide behind a
    // helper the enumeration above does not know by name. The first assertion
    // is its non-vacuity anchor and is true by construction: it states that
    // this broader scan sees every event the per-callsite scan found, so an
    // empty result here would be a broken scan rather than a clean module.
    let module_events = kernel_event_literals(&source);
    assert!(
        LIVE_RECEIPT_CALLSITE_EVENTS
            .iter()
            .all(|event| module_events
                .iter()
                .any(|literal| literal.as_str() == *event)),
        "REGRESSION GUARD (absence): the module-wide event-literal scan must see every event the callsite enumeration found, or the expiry absence below is vacuous; module events: {module_events:?}"
    );
    // REGRESSION GUARD (absence): no `kernel.`-prefixed event name anywhere in
    // `daemon_live_receipt.rs` may be expiry-shaped, whichever helper spells
    // it. The positive role of this leg is that module-wide read; it asserts
    // the ABSENCE of a name, not the behaviour of any driven callsite.
    for literal in &module_events {
        assert!(
            !carries_expiry_word(literal),
            "REGRESSION GUARD (absence): no `kernel.`-prefixed event literal anywhere in daemon_live_receipt.rs may carry an expiry-shaped word ({EXPIRY_EVENT_WORDS:?}, compared case-insensitively and through its escapes), whichever helper spells it; {literal:?} would be a receipt-EXPIRY observation"
        );
    }

    // Each selected boundary keeps its own request-then-outcome pair, in that
    // order, once per driven operation.
    for (request, outcome, outcome_value, logs) in [
        (
            "kernel.live_receipt.publication_requested",
            "kernel.live_receipt.publication_rejected",
            "fenced",
            publication_logs.as_str(),
        ),
        (
            "kernel.live_receipt.validation_requested",
            "kernel.live_receipt.validation_observed",
            "rejected",
            validation_logs.as_str(),
        ),
        (
            "kernel.live_receipt.readiness_requested",
            "kernel.live_receipt.readiness_rejected",
            "fenced",
            readiness_logs.as_str(),
        ),
    ] {
        assert_eq!(event_count(logs, request), 1, "one request record: {logs}");
        assert_eq!(event_count(logs, outcome), 1, "one outcome record: {logs}");
        assert_eq!(event_outcome(logs, request), "attempt", "{logs}");
        assert_eq!(event_outcome(logs, outcome), outcome_value, "{logs}");
        assert!(
            byte_offset(logs, &format!("event=\"{request}\""))
                < byte_offset(logs, &format!("event=\"{outcome}\"")),
            "the request precedes its outcome: {logs}"
        );
    }

    // One terminal per failed publication and per failed readiness; the
    // validation boundary deliberately emits none because the calling control
    // request owns it (daemon_live_receipt.rs:471).
    assert_eq!(
        terminal_codes(&publication_logs),
        vec!["READINESS_NOT_PROVEN".to_owned()],
        "publication owns exactly one terminal: {publication_logs}"
    );
    // REGRESSION GUARD (absence): validation emits no terminal of its own. The
    // positive role of this leg is the two `kernel.live_receipt.validation_*`
    // records the same capture DOES carry above, so an empty terminal vector
    // here is the production boundary at :471 and not a silent capture.
    assert!(
        terminal_codes(&validation_logs).is_empty(),
        "validation emits no terminal of its own: {validation_logs}"
    );
    assert_eq!(
        terminal_codes(&readiness_logs),
        vec!["READINESS_NOT_PROVEN".to_owned()],
        "readiness owns exactly one terminal: {readiness_logs}"
    );

    // The success arms of publication and validation are NOT reachable through
    // these refusals, which is what keeps "published" and "validated" separate
    // records rather than aliases of a refusal.
    //
    // REGRESSION GUARD (absence), one per driven boundary. The positive role of
    // each leg is the exact request/outcome pair asserted just above, on the
    // same capture: the absence is read over captured bytes that are known to
    // carry that boundary's own `outcome=` field, so it cannot pass by finding
    // nothing.
    assert!(
        !publication_logs.contains("outcome=\"success\"")
            && !publication_logs.contains("event=\"kernel.live_receipt.published\""),
        "a refused publication never reads as published: {publication_logs}"
    );
    assert!(
        !validation_logs.contains("outcome=\"validated\"")
            && !validation_logs.contains("outcome=\"success\""),
        "a refused validation never reads as validated: {validation_logs}"
    );
    assert!(
        !readiness_logs.contains("event=\"kernel.live_receipt.readiness_proven\""),
        "a refused readiness never reads as proven: {readiness_logs}"
    );
}

// ---------------------------------------------------------------------------
// W16 — requested, published and validated are distinct observations.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/12
#[test]
fn live_receipt_request_publication_and_validation_are_distinct_observations() {
    let (root_guard, kernel) = test_kernel("case6");
    let launch = test_launch(root_guard.path());
    let process = test_process_start_receipt(1);
    let ready = test_ready_evidence(1, READY_REQUEST_ID);
    let contour = test_contour(1);
    let receipt = test_live_receipt(1, 4, &"b".repeat(64), READY_REQUEST_ID);

    let (publication_logs, _) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        kernel.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, None, &context)
    });
    let (validation_logs, _) =
        capture_with(|| kernel.verify_published_eliotd_live_receipt(&receipt, &noop_context()));

    // The two boundaries emit disjoint record sets: driving one never produces
    // the other's name.
    //
    // REGRESSION GUARD (absence), twice over. The positive role of each leg is
    // the exact two-record event list asserted for the SAME capture immediately
    // below, so a publication capture is known to carry its own pair and a
    // validation capture its own: the absence cannot pass by finding nothing.
    assert!(
        !publication_logs.contains("event=\"kernel.live_receipt.validation_"),
        "publication never emits a validation record: {publication_logs}"
    );
    assert!(
        !validation_logs.contains("event=\"kernel.live_receipt.publication_"),
        "validation never emits a publication record: {validation_logs}"
    );
    assert_eq!(
        selected_receipt_events(&publication_logs),
        vec![
            "kernel.live_receipt.publication_requested".to_owned(),
            "kernel.live_receipt.publication_rejected".to_owned(),
        ],
        "publication is its own two-record boundary: {publication_logs}"
    );
    assert_eq!(
        selected_receipt_events(&validation_logs),
        vec![
            "kernel.live_receipt.validation_requested".to_owned(),
            "kernel.live_receipt.validation_observed".to_owned(),
        ],
        "validation is its own two-record boundary: {validation_logs}"
    );

    // The outcomes are the operations' own content, not a shared constant: a
    // fenced publication and a rejected validation are different words for
    // different owners.
    assert_eq!(
        event_outcome(
            &publication_logs,
            "kernel.live_receipt.publication_rejected"
        ),
        "fenced"
    );
    assert_eq!(
        event_outcome(&validation_logs, "kernel.live_receipt.validation_observed"),
        "rejected"
    );
    // And the terminal ownership differs: publication carries one, validation
    // carries none because the calling control request owns it.
    assert_eq!(terminal_codes(&publication_logs).len(), 1);
    // REGRESSION GUARD (absence): a validated receipt propagates its failure to
    // the calling control request, which owns the terminal. The positive role of
    // this leg is the two `kernel.live_receipt.validation_*` records asserted
    // for this same capture above.
    assert!(terminal_codes(&validation_logs).is_empty());

    // The accepted side of the same distinction: an EXACT replay of an
    // already-published receipt is read back, not republished, and it is
    // observed by the supervision classifier (daemon_supervision.rs:556) as
    // `receipt_replayed`, never as a second `published` record.
    let (replay_logs, disposition) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context, &receipt, &receipt, false, None, None,
        )
    });
    assert_eq!(
        disposition.expect("exact replay disposition"),
        EliotdLiveReceiptDisposition::ExactReplay
    );
    assert_eq!(
        event_outcome(&replay_logs, "kernel.supervision.receipt_replayed"),
        "success"
    );
    // REGRESSION GUARD (absence), twice over: an exact replay publishes no
    // receipt boundary record and emits no terminal. The positive role is the
    // `kernel.supervision.receipt_replayed`/`success` line asserted on this
    // same capture above, so neither vector can be empty because nothing was
    // captured at all.
    assert!(
        selected_receipt_events(&replay_logs).is_empty(),
        "an exact replay publishes nothing: {replay_logs}"
    );
    assert!(
        terminal_codes(&replay_logs).is_empty(),
        "an accepted replay is not a failure: {replay_logs}"
    );
}

// ---------------------------------------------------------------------------
// W14 — an invalid, stale or expired receipt cannot imply readiness.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/13
#[test]
fn invalid_stale_or_expired_receipt_cannot_imply_readiness() {
    let (_root_guard, kernel) = test_kernel("case8");
    let valid = test_live_receipt(1, 4, &"b".repeat(64), READY_REQUEST_ID);
    let renewed = test_live_receipt(1, 5, &"c".repeat(64), READY_REQUEST_ID);

    // An INVALID receipt: the shape is copied from the valid one and one field
    // is changed without recomputing the canonical digest, so the contract's own
    // `validate` refuses it. The fixture asserts that refusal first.
    let mut tampered = valid.clone();
    tampered.generation = 2;
    assert!(
        tampered.validate().is_err(),
        "an edited receipt cannot pass the contract validator"
    );

    let (valid_logs, _) =
        capture_with(|| kernel.verify_published_eliotd_live_receipt(&valid, &noop_context()));
    let (invalid_logs, invalid_result) =
        capture_with(|| kernel.verify_published_eliotd_live_receipt(&tampered, &noop_context()));
    assert!(
        matches!(&invalid_result, Err(KernelServiceError::ReadinessNotProven)),
        "an invalid receipt cannot validate: {invalid_result:?}"
    );

    // The invalid receipt's identities are never recorded on the span, while the
    // valid one records exactly its own lease and receipt digest — compared
    // against the receipt's own content, not against a shape.
    assert_eq!(
        recorded(
            &valid_logs,
            "kernel.live_receipt.validation_observed",
            "receipt"
        ),
        valid.receipt_sha256()
    );
    assert_eq!(
        recorded(
            &valid_logs,
            "kernel.live_receipt.validation_observed",
            "lease"
        ),
        valid.supervision.lease_id
    );
    assert_eq!(
        recorded(
            &invalid_logs,
            "kernel.live_receipt.validation_observed",
            "receipt"
        ),
        "unavailable",
        "an invalid receipt contributes no receipt identity: {invalid_logs}"
    );
    assert_eq!(
        recorded(
            &invalid_logs,
            "kernel.live_receipt.validation_observed",
            "lease"
        ),
        "unavailable",
        "an invalid receipt contributes no lease identity: {invalid_logs}"
    );
    // Neither arm may read as validated.
    //
    // REGRESSION GUARD (absence), per capture. The positive role of each leg is
    // the `validation_observed`/`rejected` outcome and the recorded `receipt` /
    // `lease` comparison asserted for the SAME captures above, so neither
    // capture is empty and the absence is read over records that exist.
    for logs in [&valid_logs, &invalid_logs] {
        assert!(
            !logs.contains("outcome=\"validated\""),
            "a refused validation never reads as validated: {logs}"
        );
        assert!(
            !logs.contains("event=\"kernel.live_receipt.readiness_proven\"")
                && !logs.contains("event=\"kernel.daemon.ready_proven\""),
            "a refused validation cannot imply readiness: {logs}"
        );
    }

    // A STALE receipt: a newer supervision revision exists, but no ORS renewal
    // successor is presented, so the classifier refuses and never replaces.
    let (stale_logs, stale_result) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context, &valid, &renewed, true, None, None,
        )
    });
    assert!(
        stale_result.is_err(),
        "a stale receipt without an exact renewal successor is refused"
    );
    assert_eq!(
        event_outcome(&stale_logs, "kernel.supervision.receipt_rejected"),
        "fenced"
    );
    // REGRESSION GUARD (absence): a stale receipt never replaces the current one.
    // The positive role of this leg is the `receipt_rejected`/`fenced` outcome
    // asserted on this same capture one line above.
    assert!(
        !stale_logs.contains("event=\"kernel.supervision.receipt_replaced\""),
        "a stale receipt never replaces the current one: {stale_logs}"
    );

    // A receipt whose cited supervision lease is NOT ACTIVE. Every other
    // conjunct of the exact-forward condition is satisfied, so the single
    // discriminator is `successor.state == LeaseState::Active`
    // (daemon_supervision.rs:576), which fails closed for a lease in ANY
    // non-Active state. No time value is read, no clock is consulted and no
    // lease timestamp is compared on this arm: `LeaseState::Expired`,
    // `LeaseState::Revoked` and `LeaseState::Released` would all produce the
    // identical observation, so the arm is named for what it discriminates (a
    // lease that is no longer Active) and not for a TTL. `Expired` is the
    // state presented here because it is the state an expired receipt cites.
    // The accepted arm below is the same successor with an Active lease.
    let inactive_lease_successor =
        renewal_successor(&renewed, &"b".repeat(64), LeaseState::Expired);
    let (inactive_lease_logs, inactive_lease_result) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context,
            &valid,
            &renewed,
            true,
            None,
            Some(&inactive_lease_successor),
        )
    });
    assert!(
        inactive_lease_result.is_err(),
        "a successor whose cited lease is not Active cannot replace the receipt"
    );
    assert_eq!(
        event_outcome(&inactive_lease_logs, "kernel.supervision.receipt_rejected"),
        "fenced"
    );
    // REGRESSION GUARD (absence), twice over: a lease that is no longer Active
    // implies no replacement and no readiness. The positive role is the
    // `receipt_rejected`/`fenced` outcome asserted on this same capture above;
    // and the ACCEPTED arm below is the same successor with `LeaseState::Active`
    // and nothing else changed, so this refusal is attributable to
    // `successor.state` alone (daemon_supervision.rs:576).
    assert!(
        !inactive_lease_logs.contains("event=\"kernel.supervision.receipt_replaced\"")
            && !inactive_lease_logs.contains("event=\"kernel.daemon.ready_proven\""),
        "a lease that is no longer Active implies no replacement and no readiness: {inactive_lease_logs}"
    );

    let active_successor = renewal_successor(&renewed, &"b".repeat(64), LeaseState::Active);
    let (active_logs, active_result) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context,
            &valid,
            &renewed,
            true,
            None,
            Some(&active_successor),
        )
    });
    assert_eq!(
        active_result.expect("exact forward renewal is the accepted arm"),
        EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor
    );
    assert_eq!(
        event_outcome(&active_logs, "kernel.supervision.receipt_replaced"),
        "renewal_predecessor"
    );
    // REGRESSION GUARD (absence): an accepted forward renewal is not also a
    // rejection. The positive role is the `receipt_replaced`/`renewal_predecessor`
    // outcome asserted on this same capture above.
    assert!(
        !active_logs.contains("event=\"kernel.supervision.receipt_rejected\""),
        "an accepted forward renewal is not a rejection: {active_logs}"
    );

    // A supervision lease that never renews stale-expires on its own owner
    // terms (daemon_supervision.rs:707), and every blocked renewal is observed
    // while no replacement is claimed. On THIS arm the only thing that decides
    // is the consecutive-missed-renewal counter (daemon_supervision.rs:712):
    // nothing here records a renewal, so `last_eligible_observation_ms` is None
    // throughout and the time arm at :715-717 is never reached. The `now_ms`
    // argument below is therefore INERT here, and it is deliberately the same
    // instant the horizon arm below starts from, so the difference between the
    // two arms is the recorded renewal and never the clock value.
    let policy = test_renewal_policy();
    let base_ms = 1_000_000;
    let expiry_logs = capture(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        let mut progress = DaemonSupervisionProgressState::unbound();
        assert!(!progress.stale_renewal_expired(&policy, base_ms));
        progress.note_missed_renewal_in_context(&context);
        progress.note_missed_renewal_in_context(&context);
        assert!(
            !progress.stale_renewal_expired(&policy, base_ms),
            "two blocked renewals do not expire a lease"
        );
        progress.note_missed_renewal_in_context(&context);
        assert!(
            progress.stale_renewal_expired(&policy, base_ms),
            "the third consecutive blocked renewal expires the lease"
        );
    });
    assert_eq!(
        event_count(&expiry_logs, "kernel.supervision.renewal_missed"),
        3,
        "each blocked renewal is observed: {expiry_logs}"
    );
    assert_eq!(
        event_outcome(&expiry_logs, "kernel.supervision.renewal_missed"),
        "deferred"
    );
    // REGRESSION GUARD (absence), twice over: a stale-expired lease implies no
    // replacement and no readiness. The positive role is the three
    // `renewal_missed`/`deferred` records asserted for this same capture above.
    assert!(
        !expiry_logs.contains("event=\"kernel.supervision.receipt_replaced\"")
            && !expiry_logs.contains("event=\"kernel.daemon.ready_proven\""),
        "a stale-expired lease implies no replacement and no readiness: {expiry_logs}"
    );

    // The OTHER arm of the same decision, driven for real instead of asserted
    // around. `record_renewed_in_context` (daemon_supervision.rs:753) is the
    // only writer of `last_eligible_observation_ms`, and it is reachable from
    // this crate-internal capsule, so it is called here: it stamps eligibility
    // at `base_ms` (:779) and resets the miss counter (:778). That is exactly
    // what makes the horizon arm at :715-717 reachable, and it separates the
    // two arms of the decision on one progress state at named instants:
    // stale by HORIZON with the counter still below its threshold, and stale by
    // COUNTER with no time elapsed at all. No clock is read and none is
    // fabricated — `now_ms` is a fixture instant the owner stamps itself.
    let horizon_ms = DaemonSupervisionProgressState::stale_horizon_ms(&policy);
    let missed_intervals = super::daemon_supervision::SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS;
    assert_eq!(
        horizon_ms,
        policy.renew_after_ms * missed_intervals,
        "the stale horizon is the policy's renew_after_ms times the production missed-interval constant (daemon_supervision.rs:641)"
    );
    let observation = test_progress_observation();
    let horizon_logs = capture(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        let mut progress = DaemonSupervisionProgressState::unbound();
        progress.record_renewed_in_context(
            &context,
            &observation,
            observation
                .digest()
                .expect("the observation's own canonical digest"),
            renewed.supervision.revision,
            base_ms,
        );
        assert_eq!(
            progress.missed_renewals, 0,
            "a recorded renewal clears the counter (:778)"
        );
        assert_eq!(
            progress.last_eligible_observation_ms,
            Some(base_ms),
            "the recorded renewal is what makes the horizon arm reachable at all (:779)"
        );
        // One blocked renewal is below the counter threshold, so only the
        // elapsed time against `last_eligible_observation_ms` can decide these.
        progress.note_missed_renewal_in_context(&context);
        assert!(
            !progress.stale_renewal_expired(&policy, base_ms + horizon_ms - 1),
            "one millisecond short of the horizon, with the counter below its threshold, the lease is not stale"
        );
        assert!(
            progress.stale_renewal_expired(&policy, base_ms + horizon_ms),
            "at the horizon the SAME progress state is stale by time, with the counter still below its threshold"
        );
        // The reverse: no time has elapsed at all, so only the counter can
        // decide, and it does.
        assert!(
            !progress.stale_renewal_expired(&policy, base_ms),
            "at the eligibility instant itself nothing has aged"
        );
        progress.note_missed_renewal_in_context(&context);
        progress.note_missed_renewal_in_context(&context);
        assert!(
            progress.stale_renewal_expired(&policy, base_ms),
            "three consecutive blocked renewals expire the lease with zero elapsed time"
        );
    });
    assert_eq!(
        event_count(&horizon_logs, "kernel.supervision.renewal_recorded"),
        1,
        "the verified renewal is observed once, by the production recorder: {horizon_logs}"
    );
    assert_eq!(
        event_outcome(&horizon_logs, "kernel.supervision.renewal_recorded"),
        "success",
        "{horizon_logs}"
    );
    assert_eq!(
        event_count(&horizon_logs, "kernel.supervision.renewal_missed"),
        3,
        "each blocked renewal after the recorded one is observed: {horizon_logs}"
    );
    assert_eq!(
        event_outcome(&horizon_logs, "kernel.supervision.renewal_missed"),
        "deferred"
    );
    // REGRESSION GUARD (absence), twice over: a horizon-stale or counter-stale
    // lease implies no replacement and no readiness. The positive role is the
    // `renewal_recorded`/`success` and three `renewal_missed`/`deferred` records
    // asserted for this same capture above.
    assert!(
        !horizon_logs.contains("event=\"kernel.supervision.receipt_replaced\"")
            && !horizon_logs.contains("event=\"kernel.daemon.ready_proven\""),
        "a horizon-stale or counter-stale lease implies no replacement and no readiness: {horizon_logs}"
    );
}

// ---------------------------------------------------------------------------
// W15 — liveness differs from semantic readiness.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/14
#[test]
fn liveness_is_not_semantic_readiness() {
    // The distinction itself is carried by `daemon_supervision.rs:91-92`
    // (`daemon_status_proves_ready` is `matches!(status,
    // DaemonRuntimeStatus::Ready)`), which `KernelComposition::daemon_ready`
    // reads at `daemon_runtime.rs:510`. A RUNNING process is live and is still
    // not ready; that predicate is asserted directly first.
    assert!(!daemon_status_proves_ready(
        &DaemonRuntimeStatus::NotLaunched
    ));
    assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Launching));
    assert!(
        !daemon_status_proves_ready(&DaemonRuntimeStatus::Running),
        "a live running daemon is not semantically ready"
    );
    assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
    assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Degraded(
        OWNER_STATUS_CANARY.to_owned()
    )));

    let (root_guard, kernel) = test_kernel("case9");
    let process = test_process_start_receipt(1);
    let contour = test_contour(1);
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        // The process is live: it holds the exact executor receipt AND a bound
        // supervision contour. Only its semantic readiness status differs below.
        state.receipt = Some(process);
        state.supervision = Some(contour);
        state.status = DaemonRuntimeStatus::Degraded(OWNER_STATUS_CANARY.to_owned());
    }

    // Liveness alone cannot promote the daemon.
    assert!(
        !kernel.daemon_ready(),
        "a degraded but live daemon is not ready"
    );
    let (degraded_logs, degraded) = capture_with(|| kernel.mark_daemon_ready());
    assert!(
        matches!(&degraded, Err(KernelServiceError::ReadinessNotProven)),
        "readiness cannot be reported over a degraded status: {degraded:?}"
    );
    assert_eq!(
        event_outcome(&degraded_logs, "kernel.daemon.ready_reported"),
        "readiness_unproven"
    );
    // REGRESSION GUARD (absence): the live-but-not-ready arm never emits
    // ready_proven. The positive role is the `ready_reported`/`readiness_unproven`
    // outcome asserted for this same capture above.
    assert!(
        !degraded_logs.contains("event=\"kernel.daemon.ready_proven\""),
        "the live-but-not-ready arm never emits ready_proven: {degraded_logs}"
    );

    // Exactly the same live evidence — same process receipt, same supervision
    // contour — with the semantic readiness status the owner actually records.
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Running;
    }
    let (running_logs, running) = capture_with(|| kernel.mark_daemon_ready());
    assert!(
        running.is_ok(),
        "the running arm with the same live evidence reports readiness: {running:?}"
    );
    assert_eq!(
        event_outcome(&running_logs, "kernel.daemon.ready_proven"),
        "success"
    );
    // REGRESSION GUARD (absence): an accepted ready report is not also a refusal.
    // The positive role is the `ready_proven`/`success` outcome asserted for
    // this same capture above.
    assert!(
        !running_logs.contains("event=\"kernel.daemon.ready_reported\""),
        "an accepted ready report is not also a refusal: {running_logs}"
    );
    assert!(
        kernel.daemon_ready(),
        "the semantic readiness status is what daemon_ready reads"
    );
    // REGRESSION GUARD (absence): the first acceptance is not the idempotent
    // read-back arm. The positive role is the `ready_proven`/`success` outcome
    // above and the `daemon_ready()` reading on this same composition.
    assert!(
        !running_logs.contains("outcome=\"already_ready\""),
        "the first acceptance is not the idempotent read-back arm: {running_logs}"
    );

    // The owner's status payload is never carried into the record.
    //
    // REGRESSION GUARD (absence): the degraded status payload the owner holds
    // never reaches the sink. The positive role is that the very same captures
    // carry the `ready_reported`/`readiness_unproven` and `ready_proven`/`success`
    // records asserted above, so the canary is absent from records that exist.
    for logs in [&degraded_logs, &running_logs] {
        assert!(
            !logs.contains(OWNER_STATUS_CANARY),
            "the owner status payload never reaches the sink: {logs}"
        );
    }

    // The SAME distinction at the readiness boundary this issue owns:
    // `daemon_live_receipt.rs:567` `validate_daemon_process_readiness_in_context`.
    // The launch descriptor is admitted and the process receipt is a REAL live
    // `running` receipt for this same admitted generation, so every liveness
    // coordinate is present on the input - and the boundary still refuses to
    // call that semantic readiness.
    let launch = test_launch(root_guard.path());
    let live_receipt = test_process_start_receipt(1);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let (readiness_logs, readiness) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        runtime.block_on(kernel.validate_daemon_process_readiness_in_context(
            &launch,
            &live_receipt,
            &context,
            true,
        ))
    });
    assert!(
        matches!(&readiness, Err(KernelServiceError::ReadinessNotProven)),
        "a live launch and receipt still do not prove semantic readiness: {readiness:?}"
    );

    // LIVENESS IS VISIBLE HERE AND READINESS IS NOT. The request record already
    // carries the live receipt's own operation, generation and physical process
    // id, recorded by `record_process_receipt_context`
    // (daemon_live_receipt.rs:574), which records only for a receipt that passes
    // its own `validate` (:65). Compared against the receipt's own content, not
    // against a shape.
    assert_eq!(
        recorded(
            &readiness_logs,
            "kernel.live_receipt.readiness_requested",
            "operation"
        ),
        live_receipt.operation_id().as_str(),
        "the live receipt's own operation is the request record's operation: {readiness_logs}"
    );
    assert_eq!(
        recorded(
            &readiness_logs,
            "kernel.live_receipt.readiness_requested",
            "generation"
        ),
        live_receipt.accepted_generation().get().to_string(),
        "the live receipt's own generation is the request record's generation: {readiness_logs}"
    );
    assert_eq!(
        recorded(
            &readiness_logs,
            "kernel.live_receipt.readiness_requested",
            "process_id"
        ),
        live_receipt.identity().physical().process_id().to_string(),
        "the live receipt's own physical process is the request record's process: {readiness_logs}"
    );

    // The boundary's ENTIRE record set for that live evidence is its own
    // request/outcome pair, with the literals production emits at :577-581 and
    // :591, in that order.
    assert_eq!(
        selected_receipt_events(&readiness_logs),
        vec![
            "kernel.live_receipt.readiness_requested".to_owned(),
            "kernel.live_receipt.readiness_rejected".to_owned(),
        ],
        "live evidence at the readiness boundary yields the refusal pair alone: {readiness_logs}"
    );
    assert_eq!(
        event_outcome(&readiness_logs, "kernel.live_receipt.readiness_requested"),
        "attempt",
        "the request record keeps its own attempt outcome: {readiness_logs}"
    );
    assert_eq!(
        event_outcome(&readiness_logs, "kernel.live_receipt.readiness_rejected"),
        "fenced",
        "the refusal record keeps its own fenced outcome: {readiness_logs}"
    );
    // `readiness_proven` is the only name this boundary emits for an ACCEPTED
    // validation, and its literal is `success` (:587) against the refusal's
    // `fenced` (:591); the accepted arm owns no terminal at all (the `Ok` arm
    // at :586-589 emits none) while the refused arm owns exactly one. A live
    // receipt that reached the accepted arm would therefore change the name,
    // this literal, and the terminal vector below.
    // REGRESSION GUARD (absence): a live receipt never reaches the proven arm. The
    // positive role is the `readiness_requested`/`attempt` and
    // `readiness_rejected`/`fenced` pair and the three recorded live identities
    // asserted for this same capture above, plus the one terminal below.
    assert_eq!(
        event_count(&readiness_logs, "kernel.live_receipt.readiness_proven"),
        0,
        "a live receipt never reaches the proven arm: {readiness_logs}"
    );
    assert_eq!(
        terminal_codes(&readiness_logs),
        vec!["READINESS_NOT_PROVEN".to_owned()],
        "the refused arm owns one terminal, which the proven arm never emits: {readiness_logs}"
    );
    // And the owned boundary's refusal leaves this same composition not ready:
    // the fence is recorded as a failure (daemon_runtime.rs:2282), never as
    // semantic readiness.
    assert!(
        !kernel.daemon_ready(),
        "the readiness boundary's refusal leaves no semantic readiness behind"
    );
}

// ---------------------------------------------------------------------------
// W19 — an old or late generation receipt cannot restore current state.
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 901/17
#[test]
fn old_or_late_generation_receipt_cannot_restore_current_state() {
    let (root_guard, kernel) = test_kernel("case10");
    let launch = test_launch(root_guard.path());

    // The ORS record digest each supervision record carries. Production records
    // `expected.supervision.receipt_sha256` on the span
    // (daemon_supervision.rs:79-89, `record_live_receipt_context`), which is the
    // DURABLE RECORD digest - NOT `EliotdLiveReceipt::receipt_sha256()`, which is
    // the whole-receipt canonical digest. The two differ by construction, so an
    // assertion against the whole-receipt value is red for the wrong reason.
    let gen1_ors_digest = "b".repeat(64);
    let gen2_ors_digest = "d".repeat(64);
    let gen1_rev4 = test_live_receipt(1, 4, &gen1_ors_digest, READY_REQUEST_ID);
    let gen1_rev5 = test_live_receipt(1, 5, &"c".repeat(64), READY_REQUEST_ID);
    let gen2_rev6 = test_live_receipt(2, 6, &gen2_ors_digest, READY_REQUEST_ID);

    // The ONLY forward chain production accepts: same generation, same process,
    // same ready evidence, exactly one supervision revision ahead, with the ORS
    // successor naming that exact revision and predecessor.
    let gen1_successor = renewal_successor(&gen1_rev5, &"b".repeat(64), LeaseState::Active);
    let (forward_logs, forward) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context,
            &gen1_rev4,
            &gen1_rev5,
            true,
            None,
            Some(&gen1_successor),
        )
    });
    assert_eq!(
        forward.expect("the exact forward renewal is accepted"),
        EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor
    );
    assert_eq!(
        event_outcome(&forward_logs, "kernel.supervision.receipt_replaced"),
        "renewal_predecessor"
    );

    // An OLD generation presented as the expected receipt, with a successor that
    // matches it in every other coordinate. The generation is the discriminator:
    // `old.process == expected.process`, `old.ready == expected.ready` and
    // `old.generation == expected.generation` (daemon_supervision.rs:583-588)
    // are the conjuncts that fail, so no amount of ORS evidence from the older
    // lineage can restore current state.
    let gen2_successor = renewal_successor(&gen2_rev6, &"c".repeat(64), LeaseState::Active);
    let (old_generation_logs, old_generation) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context,
            &gen1_rev5,
            &gen2_rev6,
            true,
            None,
            Some(&gen2_successor),
        )
    });
    assert!(
        old_generation.is_err(),
        "an old-generation receipt cannot replace the current one"
    );
    assert_eq!(
        event_outcome(&old_generation_logs, "kernel.supervision.receipt_rejected"),
        "fenced"
    );
    assert!(
        !old_generation_logs.contains("event=\"kernel.supervision.receipt_replaced\""),
        "no replacement is observed for an old generation: {old_generation_logs}"
    );
    // The refusal records exactly the receipt that was refused.
    assert_eq!(
        recorded(
            &old_generation_logs,
            "kernel.supervision.receipt_rejected",
            "receipt"
        ),
        gen2_rev6.supervision.receipt_sha256.as_str(),
        "the refusal records the refused receipt's OWN supervision record digest, the field `record_live_receipt_context` reads at daemon_supervision.rs:88: {gen2_rev6:?}"
    );

    // A LATE arrival of the previous revision after the current one exists: the
    // revision chain runs backwards, so it is refused even though the same ORS
    // successor is still presented.
    let (late_logs, late) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        classify_eliotd_live_receipt_transition_in_context(
            &context,
            &gen1_rev5,
            &gen1_rev4,
            true,
            None,
            Some(&gen1_successor),
        )
    });
    assert!(
        late.is_err(),
        "a late previous-revision receipt cannot replace the current one"
    );
    assert_eq!(
        recorded(&late_logs, "kernel.supervision.receipt_rejected", "receipt"),
        gen1_rev4.supervision.receipt_sha256.as_str(),
        "the late receipt's OWN supervision record digest is the one recorded: {gen1_rev4:?}"
    );
    // REGRESSION GUARD (absence): a late receipt restores nothing. The positive
    // role is the `receipt_rejected`/`fenced` outcome and the recorded receipt
    // digest asserted for this same capture above.
    assert!(
        !late_logs.contains("event=\"kernel.supervision.receipt_replaced\""),
        "a late receipt restores nothing: {late_logs}"
    );

    // The publication boundary binds the generation of the receipt it is
    // actually publishing (daemon_live_receipt.rs:141 records the process
    // receipt context before the request record at :146), so a late publication
    // cannot be read as the current generation.
    let gen1_process = test_process_start_receipt(1);
    let gen2_process = test_process_start_receipt(2);
    let (gen1_logs, _) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        kernel.publish_eliotd_live_receipt(
            &launch,
            &gen1_process,
            &test_ready_evidence(1, READY_REQUEST_ID),
            &test_contour(1),
            None,
            &context,
        )
    });
    let (gen2_logs, _) = capture_with(|| {
        let context = crate::kernel_diagnostics::operation_context(None, None, None, None);
        kernel.publish_eliotd_live_receipt(
            &launch,
            &gen2_process,
            &test_ready_evidence(2, READY_REQUEST_ID),
            &test_contour(2),
            None,
            &context,
        )
    });
    assert_eq!(
        recorded(
            &gen1_logs,
            "kernel.live_receipt.publication_requested",
            "generation"
        ),
        gen1_process.accepted_generation().get().to_string(),
        "the request record already carries the generation OF THE RECEIPT PUBLISHED, read from that receipt's own field and not from a test-side literal: {gen1_logs}"
    );
    assert_eq!(
        recorded(
            &gen2_logs,
            "kernel.live_receipt.publication_requested",
            "generation"
        ),
        gen2_process.accepted_generation().get().to_string(),
        "a different generation reads as a different generation, each from its own receipt field: {gen2_logs}"
    );

    // The readiness owner refuses to rebind a live-receipt publication operation
    // onto a status that is no longer running (daemon_supervision.rs:487-494),
    // so a late ready report cannot restore the current state either.
    //
    // The refusal carries THREE conjuncts there: the status must be Running or
    // Ready, an executor receipt must be present, and no DIFFERENT ready
    // evidence may already be bound. This composition satisfies the second and
    // third in BOTH legs — the executor receipt is installed once, before the
    // refused leg, and `live_ready` is cleared and never rebound — so the ONLY
    // thing that differs between the two legs below is `status`. That is what
    // makes the refusal attributable to `matches!(status, Running | Ready)`
    // rather than to an absent receipt the composition happened to lack.
    let late_ready = test_ready_evidence(1, READY_REQUEST_ID);
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.receipt = Some(gen1_process.clone());
        state.live_ready = None;
        state.status = DaemonRuntimeStatus::Failed(OWNER_STATUS_CANARY.to_owned());
    }
    let refused_bind = kernel
        .daemon_runtime
        .lock()
        .expect("daemon runtime lock")
        .bind_live_receipt_publication_operation(&late_ready);
    assert!(
        matches!(&refused_bind, Err(KernelServiceError::ReadinessNotProven)),
        "a failed daemon refuses a late live-receipt publication binding: {refused_bind:?}"
    );
    // REGRESSION GUARD (absence): the refused binding restores no current state.
    // The positive role is the refusal itself and the `live_ready` read-back
    // below, on the same state this leg left behind.
    assert!(
        kernel
            .daemon_runtime
            .lock()
            .expect("daemon runtime lock")
            .live_ready
            .is_none(),
        "the refused binding restores no current state"
    );
    {
        let mut state = kernel.daemon_runtime.lock().expect("daemon runtime lock");
        state.status = DaemonRuntimeStatus::Running;
    }
    let accepted_bind = kernel
        .daemon_runtime
        .lock()
        .expect("daemon runtime lock")
        .bind_live_receipt_publication_operation(&late_ready);
    assert!(
        accepted_bind.is_ok(),
        "the running arm accepts the same binding, with the same executor receipt and the same unbound ready evidence as the refused leg: {accepted_bind:?}"
    );
    assert_eq!(
        kernel
            .daemon_runtime
            .lock()
            .expect("daemon runtime lock")
            .live_ready
            .as_ref(),
        Some(&late_ready),
        "the accepted binding records exactly the ready evidence presented"
    );
}

/// A context span for the capture closures whose driven call needs no other
/// fixture value. It is built INSIDE the capture because the span's rendered
/// field set is fixed by the subscriber that is current when the span is
/// created.
fn noop_context() -> tracing::Span {
    crate::kernel_diagnostics::operation_context(None, None, None, None)
}
