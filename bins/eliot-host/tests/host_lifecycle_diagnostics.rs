#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Starter probes for F-LOG-HOST-1 item 891 (Implements, not Closes).
//!
//! Through the #889 facade only (`host_diagnostics::observe_entrypoint`,
//! `observe_entrypoint_with_detail`, `observe_terminal_error`); the Windows
//! Event Log seam stays typed-Unavailable (`event_log_sink_status`), never
//! implemented here (#984 still open).
//!
//! Two named probes plus four matrix-denominator guards:
//! - T-A stop/drain distinct (`Requested` -> `Draining` -> `StoppedClean` via
//!   existing `HostComposition::stop` seams; three distinct records sharing
//!   one `drain_generation` correlation, exactly one terminal on failure;
//!   allowed-diff: no duplicate evaluation, lifecycle delta, or new
//!   visibility).
//! - T-B SCM receipt + `Unknown` (unsupported op + expired-deadline/pending
//!   intent via `handle_kernel_restart_request` /
//!   `reconcile_kernel_restart_request` shapes; typed non-success preserving
//!   identity, `Unknown` never false-success, single terminal emission).
//! - `case_matrix_denominator_is_exactly_1_to_22` proves the case markers
//!   really exist once each, with no gap and no doubling.
//! - `case_bodies_assert_against_production_seams` is the half that carries
//!   the PROOF claim: every one of the 22 case bodies makes at least one
//!   assertion that reads a real production seam, so a marker over an empty
//!   `fn` no longer reads as a landed case.
//! - `boundary_fixture_binds_production_table` binds the `boundary_table`
//!   fixture to the production table in both directions.
//! - `boundary_rows_bind_a_landed_case` binds every production row to a landed
//!   case that actually asserts, so the table cannot claim proof that does not
//!   exist.
//!
//! The 22-case matrix itself is LANDED, with no gap: all 22 cases carry a
//! `// WORK_UNIT_CASE: 891/<n>` marker, and each marker's `fn` is a real
//! `#[test]`. The `deferred_cases` list in
//! `tests/data/host_lifecycle_diagnostics.json` is the stale artefact, not
//! this file: those entries now describe landed cases, and only the
//! whole-Host child-union coverage proof (#837/#852) remains open. These
//! probes drive the real facade plus the real runtime-control wire types and
//! read the real `lib.rs` call sites; a hand-built expected log alone is
//! never call-site proof. Fake clocks/SCM ports do not establish live SCM
//! behavior. Diagnostics are evidence only: they never change control flow,
//! state, errors, receipts, order, status, or cleanup, and stdout framing
//! stays exactly one-JSON-per-line.
//!
//! Where a pin could only bind a SOURCE SHAPE, it says so in its own
//! documentation instead of implying an executed observation:
//! - `case_bodies_assert_against_production_seams` proves each of the 22 case
//!   bodies asserts against a real production seam. It does NOT prove the
//!   assertion is correct or discriminating; executing the `#[cfg(test)]` case
//!   bodies is not reachable from this integration target, and that residual
//!   is a named ceiling, not a covered claim.
//! - T-B's kernel-restart terminal pin binds the RESOLVED CONSTANT value
//!   (`resolved_boundary_event`), which is what production renders as `code=`,
//!   not the number of call sites that mention it. The handler's control flow
//!   itself is not driven here and is likewise a named ceiling.

use std::io::Write;
use std::sync::{Arc, Mutex};

use eliot_host::host_diagnostics::{
    DiagnosticSink, EntrypointStage, HOST_DIAGNOSTICS_TARGET, observe_entrypoint_with_detail,
    observe_terminal_error, sink_status,
};
use eliot_host::windows_event_log::{AdmittedEvent, event_log_sink_status, report_event};
use serde_json::Value;

/// Shared in-memory sink proving bounded formatter output without contending
/// for the process-global subscriber.
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

fn lifecycle_fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/host_lifecycle_diagnostics.json");
    let bytes = std::fs::read(&path).expect("lifecycle fixture must be readable");
    serde_json::from_slice(&bytes).expect("lifecycle fixture must be valid JSON")
}

fn manifest_source(relative: &str) -> String {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).expect("tracked source must be readable")
}

/// Runs `emit` under a scoped subscriber and returns the captured text.
fn capture_emit(emit: impl FnOnce()) -> String {
    let sink = CaptureSink::default();
    let writer_sink = sink.clone();
    let captured = {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer_sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        sink.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&captured).into_owned()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// One source line reduced to its CODE view: `//` comments dropped and every
/// string/char literal body replaced by an empty pair of quotes.
///
/// The `#891` case bodies contain braces, parentheses and the word `assert`
/// inside their assertion messages, so counting brackets or assertions on raw
/// text would read a message as structure. This reduction keeps the literal
/// delimiters (so `\"` never escapes a scan) and keeps lifetimes (`'static`,
/// `'a`) intact by only treating `'` as a char literal when a closing `'` is
/// within four characters.
fn code_view(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        if current == '/' && chars.get(index + 1) == Some(&'/') {
            break;
        }
        if current == '"' {
            out.push('"');
            index += 1;
            while index < chars.len() {
                if chars[index] == '\\' {
                    index += 2;
                    continue;
                }
                if chars[index] == '"' {
                    index += 1;
                    break;
                }
                index += 1;
            }
            out.push('"');
            continue;
        }
        if current == '\'' {
            let close = (index + 1..(index + 5).min(chars.len()))
                .find(|candidate| chars[*candidate] == '\'');
            if let Some(close) = close {
                out.push_str("''");
                index = close + 1;
                continue;
            }
        }
        out.push(current);
        index += 1;
    }
    out
}

/// The `lib.rs` case-module start line index, located on the CODE view.
///
/// `production_source()` and the denominator proof must agree on exactly which
/// lines are the case module, so both locate the header through [`code_view`].
fn case_module_start(lines: &[&str]) -> usize {
    lines
        .iter()
        .position(|line| code_view(line).trim() == "mod host_lifecycle_boundary_table_tests {")
        .expect("the #891 boundary-table case module must exist in lib.rs")
}

/// Every identifier `lib.rs` DECLARES or RE-EXPORTS outside the case module.
///
/// This is the authority set the denominator proof resolves each `super::…`
/// seam against. A case that asserts against `super::whatever` proves nothing
/// if `whatever` is not a real production item, so the proof requires every
/// seam a case touches to resolve here.
///
/// `use` clauses are read as balanced text rather than line by line because a
/// clause may span several lines (`pub use a::{B, C};`); brace/paren depth
/// finds the true terminating `;`.
fn production_identifiers(production: &str) -> Vec<String> {
    let flattened = production
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut names: Vec<String> = Vec::new();

    // Declarations, including those nested inside `impl` blocks.
    let declaration_bytes = flattened.as_bytes();
    let mut index = 0;
    while index < declaration_bytes.len() {
        if declaration_bytes[index].is_ascii_alphabetic() || declaration_bytes[index] == b'_' {
            let start = index;
            while index < declaration_bytes.len()
                && (declaration_bytes[index].is_ascii_alphanumeric()
                    || declaration_bytes[index] == b'_')
            {
                index += 1;
            }
            let word = &flattened[start..index];
            let is_item_keyword = matches!(
                word,
                "const" | "static" | "fn" | "struct" | "enum" | "trait" | "type" | "union" | "mod"
            );
            if is_item_keyword {
                let mut cursor = index;
                while cursor < flattened.len()
                    && (flattened.as_bytes()[cursor] == b' '
                        || flattened.as_bytes()[cursor] == b'\t')
                {
                    cursor += 1;
                }
                let name_start = cursor;
                while cursor < flattened.len()
                    && (flattened.as_bytes()[cursor].is_ascii_alphanumeric()
                        || flattened.as_bytes()[cursor] == b'_')
                {
                    cursor += 1;
                }
                if cursor > name_start {
                    names.push(flattened[name_start..cursor].to_owned());
                }
            }
            continue;
        }
        index += 1;
    }

    // `use` / `pub use` clauses: every identifier they name is a production
    // item this target may legitimately reach through `super::`.
    let mut cursor = 0;
    while let Some(at) = flattened[cursor..].find("use ") {
        let start = cursor + at + "use ".len();
        let bytes = flattened.as_bytes();
        let mut depth = 0_i32;
        let mut end = start;
        while end < bytes.len() {
            match bytes[end] {
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => depth -= 1,
                b';' if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }
        for token in flattened[start..end].split(|c: char| !c.is_alphanumeric() && c != '_') {
            if !token.is_empty() && !token.starts_with(|c: char| c.is_ascii_digit()) {
                names.push(token.to_owned());
            }
        }
        cursor = (end + 1).max(start);
    }

    names.sort();
    names.dedup();
    names
}

/// `lib.rs` with its `#[cfg(test)]` boundary-table case module excised.
///
/// The landed case proofs live in that module and legitimately re-spell the
/// exact literals the T-A/T-B pins count (the single stop terminal site, the
/// dual restart-unknown sites, the `static DEDUP` and
/// `pub fn host_lifecycle_` absences), so a whole-file haystack lets those
/// proofs satisfy their own guards. The module header and its closing brace
/// are both column-0, so the first column-0 `}` after the header is its end.
fn production_source() -> String {
    let lib = manifest_source("src/lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let start = case_module_start(&lines);
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|line| *line == "}")
        .map_or_else(
            || panic!("the #891 boundary-table case module must close in lib.rs"),
            |offset| start + 1 + offset,
        );
    lines
        .iter()
        .enumerate()
        .filter(|(index, _)| *index < start || *index > end)
        .map(|(_, line)| *line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One row of the production `HOST_LIFECYCLE_BOUNDARY_TABLE`, read out of
/// the real `lib.rs` source so the duplicated fixture cannot drift from it.
struct BoundaryRow {
    name: String,
    event: String,
    test: String,
}

/// The CODE view of one `fn case_<n>_..` body, located by brace balance.
///
/// Brackets are counted through [`code_view`] so a brace inside an assertion
/// message cannot end the body early. The returned text excludes the `fn`
/// signature line and the final `}`, and is exactly what the denominator proof
/// reasons about: an empty body yields an empty string, which is the state
/// Defect 7 showed was previously indistinguishable from a real proof.
fn case_body_code(lines: &[&str], fn_line: usize) -> String {
    let mut depth = 0_i32;
    let mut opened = false;
    let mut body: Vec<String> = Vec::new();
    for line in &lines[fn_line..] {
        let code = code_view(line);
        for character in code.chars() {
            if character == '{' {
                depth += 1;
                opened = true;
            } else if character == '}' {
                depth -= 1;
            }
        }
        if opened && depth == 0 {
            return body.join("\n");
        }
        body.push(code);
    }
    String::new()
}

/// Every assertion-macro invocation in `body`, with its balanced argument span.
///
/// Counting the bare word `assert` would read an assertion MESSAGE mentioning
/// "assertions" as a proof, and would count a commented-out assertion as live.
/// This walks the CODE view, matches only `assert!`/`assert_eq!`/`assert_ne!`
/// invocation heads, and captures the balanced parenthesised arguments.
fn assertion_spans(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut spans: Vec<String> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &body[index..];
        let head_len = if rest.starts_with("assert_eq!") || rest.starts_with("assert_ne!") {
            "assert_eq!".len()
        } else if rest.starts_with("assert!") {
            "assert!".len()
        } else {
            index += 1;
            continue;
        };
        let mut cursor = index + head_len;
        while cursor < bytes.len() && bytes[cursor] == b' ' {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'(' {
            index += head_len;
            continue;
        }
        let mut depth = 0_i32;
        let mut end = cursor;
        while end < bytes.len() {
            match bytes[end] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            end += 1;
        }
        let stop = (end + 1).min(bytes.len());
        spans.push(body[index..stop].to_owned());
        index = stop;
    }
    spans
}

/// Locals a case body binds FROM PRODUCTION, one hop deep.
///
/// A local is production-bound when its initialiser reads a `super::…`
/// production seam or calls the case module's own production-source reader
/// `lib_source()`. This is the taint step that lets an assertion count as
/// proof: `assert_eq!(row.event, other.event)` proves something only because
/// `row` was resolved out of the real production table.
fn production_bound_locals(body: &str) -> Vec<String> {
    let bytes = body.as_bytes();
    let mut bound: Vec<String> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !body[index..].starts_with("let ") {
            index += 1;
            continue;
        }
        let mut cursor = index + "let ".len();
        if body[cursor..].starts_with("mut ") {
            cursor += "mut ".len();
        }
        let name_start = cursor;
        while cursor < bytes.len() && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
        {
            cursor += 1;
        }
        let name = body[name_start..cursor].to_owned();
        // Skip a type annotation up to the initialising `=`.
        while cursor < bytes.len() && bytes[cursor] != b'=' && bytes[cursor] != b';' {
            cursor += 1;
        }
        if cursor >= bytes.len() || bytes[cursor] != b'=' {
            index += 1;
            continue;
        }
        cursor += 1;
        let value_start = cursor;
        let mut depth = 0_i32;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b';' if depth <= 0 => break,
                _ => {}
            }
            cursor += 1;
        }
        let initialiser = &body[value_start..cursor];
        if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
            index += 1;
            continue;
        }
        if initialiser.contains("super::") || initialiser.contains("lib_source()") {
            bound.push(name);
        }
        index = (cursor + 1).max(index + 1);
    }
    bound
}

/// Whether `span` reads a production seam, directly or through a bound local.
fn span_reads_production(span: &str, bound: &[String]) -> bool {
    if span.contains("super::") {
        return true;
    }
    bound
        .iter()
        .any(|name| token_bounded(span, name))
}

/// Whether `identifier` occurs in `haystack` delimited by non-identifier
/// characters, so `pending` never matches `pending_ref`.
fn token_bounded(haystack: &str, identifier: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(at) = haystack[from..].find(identifier) {
        let start = from + at;
        let end = start + identifier.len();
        let before_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_identifier_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
        if from >= haystack.len() {
            break;
        }
    }
    false
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Returns the first `"..."` literal in `text`.
fn quoted(text: &str) -> String {
    let rest = text.strip_prefix('"').unwrap_or(text);
    match rest.split_once('"') {
        Some((value, _)) => value.to_owned(),
        None => rest.to_owned(),
    }
}

/// Resolves a frozen `event:` field value.
///
/// Three terminal rows spell their code with `concat!` so the source keeps
/// the literal counts the landed probes pin, so the concatenated spelling is
/// the row's real frozen event.
fn frozen_event(value: &str) -> String {
    let value = value.trim();
    let Some(inner) = value.strip_prefix("concat!(") else {
        return quoted(value);
    };
    let inner = inner
        .split_once(')')
        .map_or(inner, |(arguments, _)| arguments);
    inner.split(',').fold(String::new(), |mut joined, part| {
        joined.push_str(&quoted(part.trim()));
        joined
    })
}

/// Resolves a `BOUNDARY_*` owner's `boundary_by_event(…)` argument to its
/// frozen value, straight out of the real production constant.
///
/// This is the RESOLVED-VALUE binding Defect 8 lacked: the owner resolves its
/// row by calling `boundary_by_event(<literal>)`, so reading that literal back
/// yields the exact value `host_lifecycle_frozen_event` renders as `code=`.
/// Repointing the constant at a different event changes this result, which is
/// precisely what counting call sites could not detect.
///
/// The three terminal rows spell their code with `concat!`, so the literal
/// arguments are concatenated in source order exactly as `concat!` does.
fn resolved_boundary_event(lib: &str, constant: &str) -> String {
    let flattened = lib
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let declaration = format!("const {constant}:");
    let start = flattened
        .find(&declaration)
        .unwrap_or_else(|| panic!("the production table must own a {constant} constant"));
    let call = flattened[start..]
        .find("boundary_by_event(")
        .map(|at| start + at + "boundary_by_event(".len())
        .unwrap_or_else(|| panic!("{constant} must resolve its row through boundary_by_event"));
    let close = flattened[call..]
        .find(')')
        .map(|at| call + at)
        .unwrap_or_else(|| panic!("{constant} must close its boundary_by_event call"));
    let arguments = &flattened[call..close];
    let mut resolved = String::new();
    let mut rest = arguments;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let end = after
            .find('"')
            .unwrap_or_else(|| panic!("{constant} must close its boundary_by_event literal"));
        resolved.push_str(&after[..end]);
        rest = &after[end + 1..];
    }
    assert!(
        !resolved.is_empty(),
        "{constant} must resolve to a non-empty frozen event"
    );
    resolved
}

/// How many production call sites pass `constant` to a terminal emitter.
///
/// Reads the CODE view line by line: a site is a line whose code opens
/// `host_lifecycle_observe_terminal…(` followed by a line naming the constant
/// as that call's first argument. This is a SUPPLEMENTARY call-site census
/// only — it counts sites and says nothing about which event they render — so
/// every pin that depends on the emitted VALUE must bind
/// [`resolved_boundary_event`] instead.
fn terminal_emission_sites(lib: &str, constant: &str) -> usize {
    let lines: Vec<String> = lib.lines().map(code_view).collect();
    let mut sites = 0;
    for (index, line) in lines.iter().enumerate() {
        // The production call sites wrap their arguments, so the opening line
        // ENDS in `(`. Accept an opener whose `(` is the line's last character
        // as well as one with further arguments on the same line.
        let opens = line
            .find("host_lifecycle_observe_terminal")
            .is_some_and(|at| line[at..].contains('('));
        if !opens {
            continue;
        }
        if lines[index + 1..]
            .iter()
            .find(|next| !next.trim().is_empty())
            .is_some_and(|next| next.trim_start().starts_with(constant))
        {
            sites += 1;
        }
    }
    sites
}

/// Parses the frozen production boundary table out of `src/lib.rs`.
///
/// Line-oriented on purpose: the table is a `const` slice of struct literals
/// with one field per line, so this reads the real production rows without
/// inventing a second copy of the table.
fn production_boundary_rows(lib: &str) -> Vec<BoundaryRow> {
    let mut rows: Vec<BoundaryRow> = Vec::new();
    let mut in_table = false;
    let mut current: Option<BoundaryRow> = None;
    for line in lib.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const HOST_LIFECYCLE_BOUNDARY_TABLE") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if trimmed == "];" {
            break;
        }
        if trimmed == "HostLifecycleBoundary {" {
            current = Some(BoundaryRow {
                name: String::new(),
                event: String::new(),
                test: String::new(),
            });
            continue;
        }
        if trimmed == "}," {
            if let Some(row) = current.take() {
                rows.push(row);
            }
            continue;
        }
        let Some(row) = current.as_mut() else {
            continue;
        };
        if let Some(value) = trimmed.strip_prefix("name: ") {
            row.name = quoted(value);
        } else if let Some(value) = trimmed.strip_prefix("event: ") {
            row.event = frozen_event(value);
        } else if let Some(value) = trimmed.strip_prefix("test: ") {
            row.test = quoted(value);
        }
    }
    rows
}

/// The real `HostComposition::stop` contour contains the three durable drain
/// states with one shared correlation and one designated terminal code, and
/// those three durable writes stay distinct from each other.
fn assert_stop_contour_pins_three_distinct_durable_states_and_one_terminal(lib: &str) {
    for required in [
        "DrainState::Requested",
        "DrainState::Draining",
        "ActivationState::StoppedClean",
        "drain_generation",
        "host.stop requested",
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
        "host.stop stopped",
        "\"host-stop-failed\"",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs stop contour must contain {required:?}"
        );
    }
    // Requested vs Draining vs StoppedClean are three distinct durable writes.
    assert_ne!("Requested", "Draining");
    assert_ne!("Draining", "StoppedClean");
}

/// The stop terminal code is singular for this operation, and it is bound by
/// the RESOLVED VALUE rather than by a spelling count.
///
/// `BOUNDARY_STOP_TERMINAL` resolves through the owner's own
/// `boundary_by_event` call, so the PRIMARY pin binds the exact `code=`
/// production renders and fails if the constant were repointed at another
/// event. (The previous count of the `"host-stop-failed"` literal could not
/// detect that repointing at all — it counted a spelling, not the emitted
/// value.) The resolved value must additionally be a REAL production row, so
/// the pin cannot be satisfied by a spelling no row owns, and no second stop
/// terminal may exist anywhere in production.
fn assert_stop_terminal_code_is_singular_and_resolves_to_the_stop_terminal_row(
    lib: &str,
    fixture: &Value,
) {
    assert_eq!(
        resolved_boundary_event(lib, "BOUNDARY_STOP_TERMINAL"),
        fixture["terminal_codes"]["stop_failed"]
            .as_str()
            .expect("fixture must pin the stop failed code"),
        "the stop terminal constant must resolve to the exact code production renders"
    );
    // The resolved value must be a REAL production row, so the pin cannot be
    // satisfied by a spelling no row owns.
    assert_eq!(
        production_boundary_rows(lib)
            .iter()
            .find(|row| row.name == "stop.terminal")
            .map(|row| row.event.clone())
            .as_deref(),
        Some(resolved_boundary_event(lib, "BOUNDARY_STOP_TERMINAL").as_str()),
        "the stop constant must resolve to the stop.terminal row's own frozen event"
    );
    // SUPPLEMENTARY (source scan, clearly marked): the literal is spelled once,
    // so no duplicate spelling of this code exists in production.
    assert_eq!(
        count_occurrences(lib, "\"host-stop-failed\""),
        1,
        "stop must spell its terminal code at exactly one production site"
    );
    // Inner terminates are phase-only; they must not own a second stop
    // terminal.
    assert!(
        !lib.contains("\"host-stop-failed-2\""),
        "no second stop terminal may exist"
    );
}

/// Driving the same facade vocabulary the call sites use emits three distinct
/// drain records that share ONE correlation, each under the production target
/// and the fixture's entrypoint event.
fn assert_three_drain_records_share_one_correlation(fixture: &Value, correlation: &str) {
    let text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.drain draining {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop stopped-clean drained {correlation}"),
        );
    });
    for detail in [
        "host.drain requested",
        "host.drain draining",
        "host.stop stopped-clean drained",
    ] {
        assert!(
            text.contains(detail),
            "capture must contain distinct drain detail {detail:?}, got: {text}"
        );
    }
    // One correlation shared by three distinct records.
    assert_eq!(
        count_occurrences(&text, correlation),
        3,
        "three drain records must share one correlation, got: {text}"
    );
    assert!(text.contains(HOST_DIAGNOSTICS_TARGET));
    assert!(
        text.contains(
            fixture["entrypoint_event"]
                .as_str()
                .expect("fixture must pin the entrypoint event")
        ),
        "capture must contain the entrypoint event, got: {text}"
    );
}

/// A failed stop emits exactly ONE terminal for the shared correlation: the
/// lower-phase `Requested` observation never counts as a second terminal.
fn assert_failed_stop_emits_exactly_one_terminal(fixture: &Value, correlation: &str) {
    let failed = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ShutdownDrain,
            &format!("host.stop requested {correlation}"),
        );
        observe_terminal_error("host-stop-failed");
    });
    assert_eq!(
        count_occurrences(
            &failed,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "failed stop must emit exactly one terminal, got: {failed}"
    );
    assert!(failed.contains("host-stop-failed"));
}

/// Sink failure never alters result/order/status/cleanup: the surrounding
/// operation result stays intact around every observation, and the Event Log
/// seam stays typed-Unavailable — never FFI, never faked.
fn assert_sink_failure_leaves_the_stop_result_intact_and_event_log_unavailable() {
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ShutdownDrain, "host.stop requested");
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");
    // Event Log seam stays typed-Unavailable; never FFI, never faked.
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(eliot_host::host_diagnostics::HostDiagnosticsError::EventLogUnavailable)
    );
    let record = eliot_host::windows_event_log::EventLogRecord::new(
        AdmittedEvent::ServiceStop,
        "host.stop stopped",
    );
    assert_eq!(
        report_event(&record),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
}

/// The T-A allowed diff holds: no duplicate evaluation (each drain detail
/// emitted once per site), no lifecycle delta, no new visibility, no mutable
/// global dedup, no secret material at any logging call site, and unchanged
/// stdout framing.
fn assert_stop_contour_adds_no_dedup_no_new_visibility_and_no_secret_canaries(
    lib: &str,
    fixture: &Value,
) {
    for detail in fixture["drain_details"]
        .as_array()
        .expect("fixture must pin drain details")
    {
        let detail = detail.as_str().expect("drain detail must be a string");
        // Each frozen detail string is emitted from a bounded set of sites;
        // the terminal code itself is singular (checked above).
        assert!(!detail.is_empty(), "fixture drain detail must not be empty");
    }
    assert!(
        !lib.contains("static DEDUP"),
        "no mutable global dedup cache may exist"
    );
    assert!(
        !lib.contains("pub fn host_lifecycle_"),
        "no new public logging surface may exist"
    );
    // Secrets/SCM payloads/env/credentials never cross into diagnostics:
    // logging call sites pass only frozen literals, never secret material.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        // The check is scoped to observation lines, not the whole file
        // (which legitimately names credential types elsewhere).
        for line in lib
            .lines()
            .filter(|line| line.contains("host_lifecycle_observe_"))
        {
            assert!(
                !line.contains(canary),
                "observation call must not contain canary {canary:?}: {line}"
            );
        }
    }
    // Stdout protocol unchanged: tracing never contaminates stdout framing.
    assert_eq!(
        fixture["stdout_protocol_contamination"].as_bool(),
        Some(false)
    );
}

// WORK_UNIT_CASE: 891/T-A
#[test]
fn lifecycle_stop_drain_distinct_single_terminal() {
    // T-A: `HostComposition::stop` durable states `Requested` -> `Draining` ->
    // StoppedClean share one `drain_generation` correlation; draining vs
    // drained and requested vs stopped stay distinct; exactly one terminal on
    // failure. Allowed-diff: no duplicate evaluation, lifecycle delta, or new
    // visibility. Liveness is never readiness here.
    let fixture = lifecycle_fixture();
    // The literal-count pins below measure PRODUCTION call sites. The landed
    // case proofs in `lib.rs` re-spell those same literals, so they are read
    // from the production source: a whole-file haystack would let a proof
    // satisfy its own guard.
    let lib = production_source();

    assert_stop_contour_pins_three_distinct_durable_states_and_one_terminal(&lib);
    assert_stop_terminal_code_is_singular_and_resolves_to_the_stop_terminal_row(&lib, &fixture);
    let correlation = "drain-generation:891-T-A";
    assert_three_drain_records_share_one_correlation(&fixture, correlation);
    assert_failed_stop_emits_exactly_one_terminal(&fixture, correlation);
    assert_sink_failure_leaves_the_stop_result_intact_and_event_log_unavailable();
    assert_stop_contour_adds_no_dedup_no_new_visibility_and_no_secret_canaries(&lib, &fixture);
}

/// The real SCM handlers distinguish receipt from `Unknown`, preserve request
/// identity, and own one terminal per `Unknown` outcome.
fn assert_scm_contour_pins_receipt_unknown_and_reconcile_distinctions(lib: &str) {
    for required in [
        "pub fn handle_kernel_restart_request",
        "pub fn reconcile_kernel_restart_request",
        "fn execute_kernel_restart",
        "unsupported runtime-control operation",
        "host.kernel-restart requested",
        "host.kernel-restart receipt completion",
        "host.kernel-restart unknown",
        "\"host-kernel-restart-unknown\"",
        "host.kernel-restart-reconcile requested",
        "host.kernel-restart-reconcile unknown",
        "\"host-kernel-restart-reconcile-unknown\"",
        "readback replay",
    ] {
        assert!(
            lib.contains(required),
            "lib.rs SCM contour must contain {required:?}"
        );
    }
}

/// The kernel-restart terminal code binds the RESOLVED CONSTANT, its real
/// production row, and the supplementary two-site call-site census.
///
/// PRIMARY: the `code=` value production actually renders for the
/// kernel-restart terminal. The previous pin counted the SPELLING of two
/// `const`-call sites, so repointing `BOUNDARY_KERNEL_RESTART_TERMINAL` at a
/// different event left the count at 2 and the assertion green while
/// production emitted something else entirely. This binds the resolved
/// constant instead: the owner resolves the row through its own
/// `boundary_by_event(…)` call, so the resolved value IS the value
/// `host_lifecycle_frozen_event` renders as `code=` at every kernel-restart
/// terminal emission.
///
/// PROOF CEILING, stated plainly: this pins the RESOLVED CONSTANT, not an
/// observed emission. The `#[cfg(windows)]` `HostComposition` that owns
/// `handle_kernel_restart_request` needs a live owner lease, job branches,
/// readiness gate and registry, none of which this non-`cfg(test)`
/// integration target can construct, so the emission cannot be driven from
/// here. What IS executed is that the facade renders the resolved value as
/// `code=`: the capture in
/// `assert_one_unknown_outcome_emits_one_terminal_rendering_the_resolved_code`
/// observes production's own formatter emitting
/// `code="host-kernel-restart-unknown"` through `observe_terminal_error`,
/// which is the same owner function
/// `host_lifecycle_observe_terminal_with_request_identity` calls. The
/// unresolved gap is the handler CONTROL FLOW, which no assertion here can
/// reach and which is reported as a named ceiling rather than claimed.
fn assert_kernel_restart_terminal_code_resolves_to_its_own_production_row(
    lib: &str,
    fixture: &Value,
) {
    assert_eq!(
        resolved_boundary_event(lib, "BOUNDARY_KERNEL_RESTART_TERMINAL"),
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("fixture must pin the restart unknown code"),
        "the kernel-restart terminal constant must resolve to the exact code production renders"
    );
    // The resolved constant must be a REAL production row, so the pin cannot
    // be satisfied by a spelling that no table row owns.
    let rows = production_boundary_rows(lib);
    let terminal_row = rows
        .iter()
        .find(|row| row.name == "kernel-restart.terminal")
        .expect("the production table must own a kernel-restart.terminal row");
    assert_eq!(
        terminal_row.event,
        resolved_boundary_event(lib, "BOUNDARY_KERNEL_RESTART_TERMINAL"),
        "the constant must resolve to the kernel-restart.terminal row's own frozen event"
    );
    assert_eq!(
        terminal_row.test, "891/T-B",
        "the kernel-restart terminal row must remain this probe's proof claim"
    );

    // SUPPLEMENTARY (source scan, clearly marked): the resolved constant is
    // passed to a terminal emitter at exactly the two production Unknown exits.
    // This is retained only as a call-site census; it is NOT what proves the
    // emitted code, because it is insensitive to which event the constant
    // names.
    assert_eq!(
        terminal_emission_sites(lib, "BOUNDARY_KERNEL_RESTART_TERMINAL"),
        2,
        "handle must own exactly its owner-fenced + unknown terminal emissions"
    );
}

/// A well-formed RestartKernel request and a well-formed but unsupported
/// RecoverStore request are DISTINCT in both operation and request identity.
///
/// A RecoverStore request is well-formed on the wire but must never become a
/// Restarted success in the handler; the typed `Unknown` half is asserted by
/// [`assert_unsupported_operation_answers_typed_unknown_preserving_its_identity`].
fn assert_unsupported_operation_differs_from_restart_in_operation_and_request_digest() -> (
    eliot_host::HostRuntimeControlRequest,
    eliot_host::HostRuntimeControlRequest,
) {
    let restart = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RestartKernel,
        eliot_platform::PlatformHandle::new("891-T-B-restart".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("restart request must validate");
    restart.validate().expect("restart request must be valid");
    let unsupported = eliot_host::HostRuntimeControlRequest::new(
        eliot_host::HostRuntimeControlOperation::RecoverStore,
        eliot_platform::PlatformHandle::new("891-T-B-unsupported".to_owned())
            .expect("test handle must be valid"),
    )
    .expect("unsupported request must still be well-formed on the wire");
    unsupported
        .validate()
        .expect("unsupported request must validate on the wire");
    assert_ne!(
        restart.operation, unsupported.operation,
        "unsupported op must differ from the restart op"
    );
    // Identity: mutation and request digests are exact per request.
    assert_ne!(
        restart.request_digest.as_str(),
        unsupported.request_digest.as_str()
    );
    (restart, unsupported)
}

/// An unsupported operation answers with a typed `Unknown` that preserves the
/// exact request's identity and is never a false Restarted success.
///
/// The `Unknown` carries the exact request's pending ref and validates; it
/// matches that request and no other, and the pending ref binds the exact
/// request digest (identity preserved, no payload copied).
fn assert_unsupported_operation_answers_typed_unknown_preserving_its_identity(
    unsupported: &eliot_host::HostRuntimeControlRequest,
    restart: &eliot_host::HostRuntimeControlRequest,
) {
    let pending_ref = eliot_host_service::runtime_control::runtime_control_unknown_ref(
        "kernel-restart",
        unsupported,
    );
    let unknown =
        eliot_host::HostRuntimeControlResponse::unknown_for(unsupported, pending_ref.clone());
    unknown.validate().expect("unknown response must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(unsupported, &unknown),
        "unknown must preserve the exact request identity"
    );
    assert!(
        !eliot_host_service::runtime_control::response_matches_request(restart, &unknown),
        "unknown for one request must not match another request"
    );
    assert!(
        matches!(
            unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "unsupported op must stay Unknown, never false-success"
    );
    // The pending ref binds the exact request digest (identity preserved,
    // no payload copied).
    assert!(
        pending_ref
            .as_str()
            .contains(unsupported.request_digest.as_str()),
        "pending ref must preserve request identity"
    );
}

/// An expired-deadline/pending intent stays `Unknown`: the reconcile-unknown
/// for the same mutation digest validates, matches its own request, and never
/// succeeds.
fn assert_pending_intent_answers_typed_unknown_never_false_success(
    restart: &eliot_host::HostRuntimeControlRequest,
) {
    let reconcile_unknown = eliot_host::HostRuntimeControlResponse::unknown_for(
        restart,
        eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart-pending",
            restart,
        ),
    );
    reconcile_unknown
        .validate()
        .expect("pending unknown must validate");
    assert!(
        eliot_host_service::runtime_control::response_matches_request(restart, &reconcile_unknown),
        "pending unknown must preserve identity"
    );
    assert!(
        matches!(
            reconcile_unknown,
            eliot_host::HostRuntimeControlResponse::Unknown { .. }
        ),
        "pending/timeout must stay Unknown, never false-success"
    );
}

/// One `Unknown` outcome emits exactly ONE terminal, and production's own
/// formatter renders the RESOLVED terminal constant as `code=`.
///
/// Receipt vs Unknown share correlation by detail order, not by a dedup cache.
/// The failed/Unknown distinction is pinned by EXACT equality against the
/// value the owner's constant resolves to, not by a substring: the old
/// `.contains("unknown")` was satisfied by any code merely mentioning the word,
/// so it could not distinguish the Unknown code from the reconcile-Unknown code
/// or from any future sibling. Because this capture is production's own
/// `observe_terminal_error`, the same owner function
/// `host_lifecycle_observe_terminal_with_request_identity` calls, the rendered
/// `code=` field is the emitted value rather than a re-spelling.
///
/// Returns the captured SCM text so the canary and sink checks read the very
/// same observation this proof captured.
fn assert_one_unknown_outcome_emits_one_terminal_rendering_the_resolved_code(
    lib: &str,
    fixture: &Value,
    correlation: &str,
) -> String {
    let scm_text = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart requested {correlation}"),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            &format!("host.kernel-restart unknown {correlation}"),
        );
        observe_terminal_error("host-kernel-restart-unknown");
    });
    assert!(scm_text.contains("host.kernel-restart requested"));
    assert!(scm_text.contains("host.kernel-restart unknown"));
    assert_eq!(
        count_occurrences(
            &scm_text,
            fixture["terminal_event"]
                .as_str()
                .expect("fixture must pin the terminal event")
        ),
        1,
        "one Unknown outcome must emit exactly one terminal, got: {scm_text}"
    );
    // Failed vs Unknown preserved by distinct codes. The pin is EXACT equality
    // against the value the owner's constant resolves to, not a substring: the
    // old `.contains("unknown")` was satisfied by any code merely mentioning
    // the word, so it could not distinguish the Unknown code from the
    // reconcile-Unknown code or from any future sibling.
    assert_eq!(
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("fixture must pin the restart unknown code"),
        resolved_boundary_event(lib, "BOUNDARY_KERNEL_RESTART_TERMINAL"),
        "the pinned Unknown code must be exactly the value the terminal constant resolves to"
    );
    assert_ne!(
        fixture["terminal_codes"]["kernel_restart_unknown"]
            .as_str()
            .expect("fixture must pin the restart unknown code"),
        fixture["terminal_codes"]["kernel_restart_reconcile_unknown"]
            .as_str()
            .expect("fixture must pin the reconcile unknown code"),
        "the failed/Unknown distinction requires the restart and reconcile codes to differ"
    );
    // The facade really renders the resolved value as `code=`: this capture is
    // production's own `observe_terminal_error`, the same owner function
    // `host_lifecycle_observe_terminal_with_request_identity` calls, so the
    // rendered `code=` field is the emitted value rather than a re-spelling.
    assert!(
        scm_text.contains(&format!(
            "code={:?}",
            resolved_boundary_event(lib, "BOUNDARY_KERNEL_RESTART_TERMINAL")
        )),
        "production must render the resolved terminal constant as `code=`, got: {scm_text}"
    );
    scm_text
}

/// Sink failure never alters result/order/status/cleanup on the SCM path, no
/// secret canary appears in any SCM observation, and the Event Log seam stays
/// typed-Unavailable.
fn assert_scm_sink_failure_is_inert_and_observations_carry_no_secret_canaries(
    scm_text: &str,
) {
    let host_result: Result<(), &'static str> = Ok(());
    let _ = capture_emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.kernel-restart-reconcile requested",
        );
    });
    assert!(host_result.is_ok(), "sink outcome must not change result");

    // Canaries absent from SCM observations; Event Log stays unavailable.
    for canary in [
        "password",
        "token=",
        "connection_string",
        "BEGIN PRIVATE",
        "AKIA",
    ] {
        assert!(
            !scm_text.contains(canary),
            "SCM observation must not contain canary {canary:?}, got: {scm_text}"
        );
    }
    assert_eq!(
        event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
}

// WORK_UNIT_CASE: 891/T-B
#[test]
fn scm_receipt_and_unknown_preserve_identity_single_terminal() {
    // T-B: SCM receipt vs `Unknown` via the real `handle_kernel_restart_request`
    // / `reconcile_kernel_restart_request` shapes. Unsupported op stays typed
    // Unknown preserving identity; expired-deadline/pending intent stays
    // Unknown (never false-success); single terminal emission per Unknown
    // outcome. Failed vs Unknown preserved by distinct codes.
    let fixture = lifecycle_fixture();
    // Production source only: the landed case proofs re-spell the very
    // literals this test counts, so a whole-file haystack would let a proof
    // satisfy its own guard.
    let lib = production_source();

    assert_scm_contour_pins_receipt_unknown_and_reconcile_distinctions(&lib);
    assert_kernel_restart_terminal_code_resolves_to_its_own_production_row(&lib, &fixture);
    let (restart, unsupported) =
        assert_unsupported_operation_differs_from_restart_in_operation_and_request_digest();
    assert_unsupported_operation_answers_typed_unknown_preserving_its_identity(
        &unsupported,
        &restart,
    );
    assert_pending_intent_answers_typed_unknown_never_false_success(&restart);
    // Single terminal emission per Unknown outcome; receipt vs Unknown share
    // correlation by detail order, not by a dedup cache.
    let correlation = restart.request_digest.as_str();
    let scm_text = assert_one_unknown_outcome_emits_one_terminal_rendering_the_resolved_code(
        &lib,
        &fixture,
        correlation,
    );
    assert_scm_sink_failure_is_inert_and_observations_carry_no_secret_canaries(&scm_text);
}

/// The 22-case denominator, asserted exactly: every case in `1..=22` carries
/// exactly one `// WORK_UNIT_CASE: 891/<n>` marker and each marker's `fn` is a
/// real `#[test]` named for its case.
///
/// This is the EXECUTED proof that the matrix really runs. A marker without a
/// live test, or a doubled marker, fails here rather than being described as
/// coverage. Case 2 was the last case whose proof was not landed; its four
/// production rows now name a real `#[test] fn case_2_..`, so the matrix has
/// no gap and the denominator is exactly `1..=22`. The absence of an exception
/// list is itself pinned here: the inverse check below proves every
/// `fn case_<n>_` test in `lib.rs` is paid for by a marker, so a case cannot
/// re-open a silent gap by keeping its proof while dropping its marker.
///
/// The marker census is only the DENOMINATOR half. It is deliberately not the
/// claim that a case proves anything, because a marker plus an `#[test]` plus
/// an empty body is exactly what "the 22-case matrix landed" looks like while
/// being false. [`case_bodies_assert_against_production_seams`] is the half
/// that carries the proof claim, and the two together are the honest
/// denominator: no gap, and every occupied case is occupied by something.
#[test]
fn case_matrix_denominator_is_exactly_1_to_22() {
    let lib = manifest_source("src/lib.rs");

    // Every marker this issue owns, in source order, paired with the `fn`
    // name it immediately precedes.
    let mut markers: Vec<(u32, String)> = Vec::new();
    let lines: Vec<&str> = lib.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("// WORK_UNIT_CASE: 891/") else {
            continue;
        };
        // Skip the named T-A/T-B probes: they are not matrix cases.
        let Ok(case) = rest.trim().parse::<u32>() else {
            continue;
        };
        assert!(
            (1..=22).contains(&case),
            "case marker {case} is outside the 1..=22 matrix"
        );
        let owner = lines[index + 1..]
            .iter()
            .take(8)
            .find_map(|next| {
                next.trim()
                    .strip_prefix("fn ")
                    .map(|name| name.split(['(', ' ']).next().unwrap_or(name).to_owned())
            })
            .unwrap_or_else(|| panic!("case {case} marker has no following `fn`"));
        assert!(
            owner.starts_with(&format!("case_{case}_")),
            "case {case} marker must precede its own `fn case_{case}_..`, got {owner:?}"
        );
        markers.push((case, owner));
    }

    // No doubling: a case claimed twice is a phantom denominator.
    for pair in markers.windows(2) {
        assert_ne!(
            pair[0].0, pair[1].0,
            "case {} is marked twice, so the denominator is inflated",
            pair[0].0
        );
    }

    // Exact denominator: every case in the matrix, once each, no gap.
    let mut covered: Vec<u32> = markers.iter().map(|(case, _)| *case).collect();
    covered.sort_unstable();
    let expected: Vec<u32> = (1..=22).collect();
    assert_eq!(
        covered, expected,
        "the landed case markers must be exactly 1..=22, with no gap"
    );

    // The inverse of the denominator, so no case can re-open a silent gap: a
    // case proof that is not paid for by a marker is a claim the denominator
    // never admitted, and a marker with no proof is coverage that does not
    // run. Case 2 is held here exactly like the other 21.
    let mut proved: Vec<u32> = Vec::new();
    for line in lines.iter() {
        let trimmed = line.trim();
        let Some(name) = trimmed.strip_prefix("fn case_") else {
            continue;
        };
        let Some((number, _)) = name.split_once('_') else {
            panic!("a case test must name its case number, got {name:?}");
        };
        let number = number
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("a case test must name its case number, got {name:?}"));
        assert!(
            markers.iter().any(|(case, _)| *case == number),
            "{name} claims matrix case {number} with no WORK_UNIT_CASE marker"
        );
        proved.push(number);
    }
    proved.sort_unstable();
    assert_eq!(
        proved, expected,
        "every matrix case must be proved by exactly one `fn case_<n>_` test"
    );

    // Each marker is a real test, not a comment: `#[test]` precedes every one.
    for (case, _) in &markers {
        let marker_line = lib
            .lines()
            .position(|line| line.trim() == format!("// WORK_UNIT_CASE: 891/{case}"))
            .expect("marker line must be locatable");
        let window = lib
            .lines()
            .skip(marker_line)
            .take(8)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            window.contains("#[test]"),
            "case {case} marker must sit on a #[test], got: {window}"
        );
    }
}

/// The half of the denominator that carries the PROOF claim: every one of the
/// 22 case bodies makes at least one assertion against a real production seam.
///
/// #891 previously proved only that 22 markers existed and that a `#[test]`
/// attribute sat nearby. That admits a marker over an empty `fn`, which is
/// exactly the state in which "the 22-case matrix is LANDED" is false while
/// every marker assertion stays green — so the fixture's `LANDED` note was
/// recording an unproved claim as data.
///
/// The property proved here is per case `n` in `1..=22`:
///
/// 1. `fn case_<n>_..` has a real, brace-balanced body (an empty body fails);
/// 2. that body contains at least one `assert!`/`assert_eq!`/`assert_ne!`
///    invocation, read on the CODE view so a commented-out assertion and the
///    word "assertions" inside an assertion message are both excluded;
/// 3. at least one such assertion READS PRODUCTION — it either names a
///    `super::…` seam directly, or names a local that was bound from a
///    `super::…` seam or from the case module's production-source reader
///    `lib_source()`; and
/// 4. every `super::…` identifier the body names RESOLVES to a real
///    production declaration or re-export outside the case module, so an
///    assertion cannot be pointed at a seam that does not exist.
///
/// Point 3 is what defeats the empty-body demonstration: replacing
/// `case_13_…`'s body with `{}` leaves 0 assertion spans, and a body of
/// `assert!(true);` leaves 0 production-reading assertions, so both fail here.
///
/// PROOF CEILING, stated plainly: this proves each case body ASSERTS against a
/// real production seam. It does NOT prove the assertion is correct, that its
/// expectation is the right one, or that it would fail if production regressed
/// — only that a production-derived value is actually compared rather than a
/// marker being present. An assertion that reads a production seam and then
/// asserts something trivially true about it (`assert!(x == x)`) still passes.
/// Closing that would require executing each case body, which this target
/// cannot do: the cases are `#[cfg(test)]` items inside `src/lib.rs` and are
/// not reachable from a non-`cfg(test)` integration target. That residual is
/// named here rather than claimed as covered.
#[test]
fn case_bodies_assert_against_production_seams() {
    let lib = manifest_source("src/lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let production = production_source();
    let identifiers = production_identifiers(&production);

    for case in 1_u32..=22 {
        let fn_line = lines
            .iter()
            .position(|line| {
                code_view(line).trim_start().starts_with(&format!("fn case_{case}_"))
            })
            .unwrap_or_else(|| panic!("matrix case {case} must own a `fn case_{case}_..` test"));
        let body = case_body_code(&lines, fn_line);
        assert!(
            !body.trim().is_empty(),
            "case {case} must have a real body, not an empty one"
        );

        let spans = assertion_spans(&body);
        assert!(
            !spans.is_empty(),
            "case {case} must assert something, not merely exist"
        );

        let bound = production_bound_locals(&body);
        let reading = spans
            .iter()
            .filter(|span| span_reads_production(span, &bound))
            .count();
        assert!(
            reading >= 1,
            "case {case} must assert against a real production seam, got {}/{} \
             production-reading assertions",
            reading,
            spans.len()
        );

        for seam in body
            .match_indices("super::")
            .map(|(at, _)| &body[at + "super::".len()..])
            .map(|rest| {
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty())
        {
            assert!(
                identifiers.iter().any(|known| known == &seam),
                "case {case} reads `super::{seam}`, which is not a real production item"
            );
        }
    }
}

/// Binds the duplicated `boundary_table` fixture to the real production table.
///
/// The fixture is a hand-maintained copy, so without this it could drift from
/// `HOST_LIFECYCLE_BOUNDARY_TABLE` in either direction. Both directions are
/// asserted here and both are achievable, because the fixture pins every row:
///
/// - fixture -> production: every name the fixture lists exists as a real
///   production row, with the SAME frozen event spelling;
/// - production -> fixture: every production row appears in the fixture, so a
///   new boundary row cannot ship without the fixture naming it.
///
/// The emitting/propagated split and the explicit propagated exclusions are
/// pinned too, so a row cannot quietly change ownership.
#[test]
fn boundary_fixture_binds_production_table() {
    let lib = production_source();
    let fixture = lifecycle_fixture();
    let table = &fixture["boundary_table"];

    // The fixture names its source; it must name the real frozen table.
    assert_eq!(
        table["source"].as_str(),
        Some("bins/eliot-host/src/lib.rs::HOST_LIFECYCLE_BOUNDARY_TABLE"),
        "fixture must point at the actual frozen table"
    );

    let rows = production_boundary_rows(&lib);
    assert!(
        !rows.is_empty(),
        "the production boundary table must yield rows from lib.rs"
    );
    let fixture_names: Vec<&str> = table["names"]
        .as_array()
        .expect("fixture must pin boundary_table.names")
        .iter()
        .map(|name| name.as_str().expect("boundary name must be a string"))
        .collect();

    // production -> fixture: no production row may be missing from the copy.
    for row in &rows {
        assert!(
            fixture_names.contains(&row.name.as_str()),
            "production boundary row {:?} is absent from the fixture",
            row.name
        );
    }
    // fixture -> production: no fixture name may be invented.
    for name in &fixture_names {
        assert!(
            rows.iter().any(|row| row.name == *name),
            "fixture boundary row {name:?} does not exist in the production table"
        );
    }
    // Same rows in the same order: order drift is drift too.
    assert_eq!(
        rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
        fixture_names,
        "fixture names must equal the production table in source order"
    );

    // Every emitting row's frozen event resolves through the production
    // `boundary_by_event` binding, so the fixture can only name real
    // production vocabulary.
    for row in &rows {
        if row.event.starts_with("propagated:") {
            continue;
        }
        assert!(
            lib.contains(&format!("boundary_by_event({:?})", row.event)),
            "emitting row {:?} event {:?} has no production boundary_by_event binding",
            row.name,
            row.event
        );
    }

    // The emitting/propagated split, pinned against the real rows.
    let propagated: Vec<&str> = rows
        .iter()
        .filter(|row| row.event.starts_with("propagated:"))
        .map(|row| row.name.as_str())
        .collect();
    let rows_len = u64::try_from(rows.len()).expect("table length fits u64");
    let propagated_len = u64::try_from(propagated.len()).expect("table length fits u64");
    assert_eq!(
        table["rows"].as_u64(),
        Some(rows_len),
        "fixture must pin one row per production row"
    );
    assert_eq!(
        table["emitting"].as_u64(),
        Some(rows_len - propagated_len),
        "fixture must pin the emitting count"
    );
    assert_eq!(
        table["propagated"].as_u64(),
        Some(propagated_len),
        "fixture must pin the propagated count"
    );
    let exclusions: Vec<&str> = table["propagated_exclusions"]
        .as_array()
        .expect("fixture must pin propagated exclusions")
        .iter()
        .map(|name| name.as_str().expect("exclusion must be a string"))
        .collect();
    assert_eq!(
        exclusions, propagated,
        "propagated exclusions must cover exactly the propagated production rows"
    );
}

/// Binds every production boundary row to a case proof that actually exists.
///
/// The table's `test` field is the claim of proof. A row naming a case with no
/// landed proof is proof that does not exist, so this fails on it instead of
/// leaving the claim unchecked. Every row is now bound the same way and there
/// is no exception list, because every case the table names is landed - case
/// 2's four rows included. Each claim must resolve to both the
/// `// WORK_UNIT_CASE: 891/<n>` marker and the live `#[test] fn case_<n>_`
/// behind it.
#[test]
fn boundary_rows_bind_a_landed_case() {
    let lib = production_source();
    // The markers and the case tests live in the `#[cfg(test)]` case module
    // that `production_source()` excises by design, so they are read from the
    // whole source. Scanning the production haystack finds no marker at all,
    // which made "case 2 is not landed" vacuously true and every other row's
    // binding unprovable.
    let whole = manifest_source("src/lib.rs");
    let rows = production_boundary_rows(&lib);
    assert!(
        !rows.is_empty(),
        "the production boundary table must yield rows from lib.rs"
    );

    let marked: Vec<String> = whole
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("// WORK_UNIT_CASE: 891/")
                .map(|rest| rest.trim().to_owned())
        })
        .collect();

    let mut bound: Vec<&str> = Vec::new();
    for row in &rows {
        let Some(case) = row.test.strip_prefix("891/case-") else {
            // T-A/T-B probes and other issues' cases are not this matrix.
            continue;
        };
        assert!(
            marked.contains(&case.to_owned()),
            "boundary row {:?} names case {case}, which has no WORK_UNIT_CASE marker",
            row.name
        );
        assert!(
            whole.contains(&format!("fn case_{case}_")),
            "boundary row {:?} names case {case}, whose marker sits on no live test",
            row.name
        );
        // The marker and the `fn` name are the DENOMINATOR half only: together
        // they still admit a marker over an empty body, which is not proof. So
        // this binding additionally requires the named case to make at least
        // one assertion that READS PRODUCTION, which is what makes the row's
        // `test` claim a real proof claim rather than a comment plus a symbol.
        let body = case_body_code(
            &whole.lines().collect::<Vec<_>>(),
            whole
                .lines()
                .position(|line| {
                    code_view(line).trim_start().starts_with(&format!("fn case_{case}_"))
                })
                .unwrap_or_else(|| {
                    panic!(
                        "boundary row {:?} names case {case}, which owns no case test",
                        row.name
                    )
                }),
        );
        let spans = assertion_spans(&body);
        let bound_locals = production_bound_locals(&body);
        let reading = spans
            .iter()
            .filter(|span| span_reads_production(span, &bound_locals))
            .count();
        assert!(
            reading >= 1,
            "boundary row {:?} names case {case}, whose body asserts against no production seam \
             ({} assertions, {reading} of them production-reading)",
            row.name,
            spans.len()
        );
        bound.push(row.name.as_str());
    }
    // The bindings above must not be an empty set: a table that renamed every
    // `test` field out of the `891/case-` namespace would pass this loop by
    // skipping every row, which is unproved, not proved.
    assert!(
        !bound.is_empty(),
        "the boundary table must name matrix cases, or no row binding is proved"
    );

    // The four rows that used to be the named exception are now bound by the
    // same path, so the closure of that gap is pinned rather than assumed:
    // each is still a real production row and each still names case 2.
    for name in [
        "open.requested",
        "open.admitted",
        "start.requested",
        "start.started",
    ] {
        let row = rows.iter().find(|row| row.name == name).unwrap_or_else(|| {
            panic!("the closed case-2 gap pins row {name:?}, which is not a production row")
        });
        assert_eq!(
            row.test, "891/case-2",
            "row {name:?} must still name the landed case 2"
        );
    }
}

// ---------------------------------------------------------------------------
// #893 audit comment 5917124913, blocking defect 1: a terminal failure must be
// correlated to the operation whose subordinate phases carry the identities,
// and a pre-subject failure must say so explicitly instead of relying on order.
//
// The seam driven below is the REAL production terminal owner
// `scm_launch::validate_host_scm_bootstrap` (`src/scm_launch.rs`), reached
// through its public export. It arms its own single `ScmLaunchTerminalGuard`
// on entry and every failure after that point returns through the armed guard,
// so what is asserted here is what production actually emitted through the
// #889 facade - never a hand-built expected record.
// ---------------------------------------------------------------------------

/// The isolated temp root one `scm_launch` contour is launched against.
///
/// The path is deliberately never created: the driven contour refuses before
/// it touches the filesystem, and the tests below assert exactly that, which
/// is what keeps the capture free of any wall-clock, thread-order or ambient
/// state dependence.
fn scm_launch_root(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("eliot-host-893-{tag}"))
}

/// Real `HostLaunchOptions` for one SCM bootstrap contour.
///
/// Built with the canonical ten-pair argv and NO `--registration-nonce` pair,
/// which is the exact pre-subject state production refuses: the launch options
/// parse (the owner identity exists), but the SCM bootstrap has no registration
/// nonce yet, so no operation subject exists at the terminal boundary.
fn scm_launch_options(tag: &str) -> eliot_host::HostLaunchOptions {
    let root = scm_launch_root(tag);
    eliot_host::HostLaunchOptions::parse([
        std::ffi::OsString::from("--config-descriptor"),
        root.join("auth.json").into_os_string(),
        std::ffi::OsString::from("--config-descriptor-sha256"),
        std::ffi::OsString::from("a".repeat(64)),
        std::ffi::OsString::from("--installation-id"),
        std::ffi::OsString::from(format!("installation-{tag}")),
        std::ffi::OsString::from("--tx-plan-generation"),
        std::ffi::OsString::from("7"),
        std::ffi::OsString::from("--host-state-root"),
        root.into_os_string(),
    ])
    .expect("the canonical launch argv must admit")
}

/// #893 D1: a pre-subject terminal states that correlation is UNAVAILABLE.
///
/// Drives the real `validate_host_scm_bootstrap` owner to its failure and
/// asserts the disposition production actually rendered: one terminal record,
/// `correlation_available=false`, and all three owner-issued slots explicitly
/// missing with empty values. The sibling phase record for the SAME operation
/// carries the installation/generation/config identity the contour really held,
/// which is what makes the terminal's explicit "unavailable" the honest
/// disposition rather than a missing correlation this test could not supply.
#[test]
fn lifecycle_scm_pre_subject_failure_states_correlation_unavailable() {
    let options = scm_launch_options("pre-subject");
    let root = scm_launch_root("pre-subject");

    // The owner identity is genuinely in hand before the terminal boundary:
    // production itself renders it into the requested phase record.
    let requested = format!(
        "detail=\"host.scm-launch requested installation=installation-pre-subject \
plan_generation=7 config_digest={}\"",
        "a".repeat(64)
    );

    let emitted = capture_emit(|| {
        let outcome = eliot_host::validate_host_scm_bootstrap(&options);
        assert!(
            outcome.is_err(),
            "a nonce-free SystemService bootstrap must be refused by production, not admitted"
        );
    });

    assert!(
        emitted.contains(&requested),
        "production must render the owner identity it holds, got: {emitted}"
    );
    assert_eq!(
        count_occurrences(&emitted, "host.terminal_error"),
        1,
        "one failed operation must emit exactly one terminal, got: {emitted}"
    );
    assert!(
        emitted.contains("code=\"host-scm-launch-unknown\""),
        "the terminal must carry production's own typed code, got: {emitted}"
    );
    // The disposition the audit demands: correlation is stated unavailable,
    // never left to be inferred from record order (I13.11).
    assert!(
        emitted.contains("correlation_available=false"),
        "a pre-subject terminal must state correlation is unavailable, got: {emitted}"
    );
    for missing in ["tx_missing=true", "effect_missing=true", "req_missing=true"] {
        assert!(
            emitted.contains(missing),
            "every absent identity slot must be explicitly missing ({missing}), got: {emitted}"
        );
    }
    // And the absent slots render empty: no derived, defaulted or borrowed
    // value ever stands in for an identity the owner does not hold.
    for empty in ["tx=\"\"", "effect=\"\"", "req=\"\""] {
        assert!(
            emitted.contains(empty),
            "an absent identity slot must render empty ({empty}), got: {emitted}"
        );
    }
    // Determinism: the refusal happened before any filesystem effect, so the
    // isolated root this test names was never created and nothing outside the
    // capture can influence it.
    assert!(
        !root.exists(),
        "the driven failure must not touch the filesystem, but {} exists",
        root.display()
    );
}

/// #893 D1/case 22: exactly ONE terminal per failed operation, and none for an
/// operation that owns no terminal.
///
/// Two independent failed `validate_host_scm_bootstrap` operations each return
/// through their own armed `ScmLaunchTerminalGuard` through a `?` in the
/// guarded body, so the terminal count must track the failed operation (two),
/// never the process (one) and never the guard's internal `?` chain (more).
/// A rejected `HostLaunchOptions::parse` operation owns no terminal at all and
/// must therefore add none to the same accounting.
#[test]
fn lifecycle_each_failed_operation_emits_exactly_one_terminal() {
    let first = scm_launch_options("op-a");
    let second = scm_launch_options("op-b");

    let emitted = capture_emit(|| {
        assert!(eliot_host::validate_host_scm_bootstrap(&first).is_err());
        assert!(eliot_host::validate_host_scm_bootstrap(&second).is_err());
    });

    assert_eq!(
        count_occurrences(&emitted, "host.terminal_error"),
        2,
        "two failed operations must emit two terminals, not one and not more, got: {emitted}"
    );
    assert_eq!(
        count_occurrences(&emitted, "correlation_available=false"),
        2,
        "both terminals must state their own unavailable disposition, got: {emitted}"
    );
    // Each failed operation also produced its own requested phase record, so
    // the two terminals are two per-operation dispositions rather than one
    // duplicated observation.
    assert_eq!(
        count_occurrences(&emitted, "detail=\"host.scm-launch requested"),
        2,
        "each failed operation must record its own requested phase, got: {emitted}"
    );
    // The two operations are distinct by the owner-issued identity production
    // itself rendered, so the pair is joinable by field equality.
    assert!(
        emitted.contains("installation=installation-op-a")
            && emitted.contains("installation=installation-op-b"),
        "the two operations must carry distinct owner identities, got: {emitted}"
    );

    // An operation whose owner owns no terminal boundary contributes none.
    let rejected = capture_emit(|| {
        let outcome = eliot_host::HostLaunchOptions::parse([std::ffi::OsString::from(
            "--config-descriptor",
        )]);
        assert!(outcome.is_err(), "a one-pair argv must be refused");
    });
    assert!(
        rejected.contains("detail=\"host.launch-options parse typed rejection\""),
        "production must render its own typed rejection, got: {rejected}"
    );
    assert_eq!(
        count_occurrences(&rejected, "host.terminal_error"),
        0,
        "an operation with no terminal owner must emit no terminal, got: {rejected}"
    );
}

/// #893 D1 item 4: a partial identity renders only what the owner holds.
///
/// Drives the real `HostTerminalCorrelation` projection production itself
/// builds at every `bind_operation` site. `correlation_available` is the flag
/// the terminal record renders, so the projection's own answer must never
/// over-claim: a partial binding is not an available correlation, it is
/// distinct from both the full and the fully-unavailable projection, and it is
/// a value - two operations with different owner handles never collapse onto
/// one correlation.
#[test]
fn lifecycle_terminal_correlation_never_over_claims_availability() {
    use eliot_host::host_diagnostics::HostTerminalCorrelation;

    assert!(
        HostTerminalCorrelation::bound("tx", "effect", "req").is_available(),
        "a fully bound correlation is the available one"
    );
    assert!(
        !HostTerminalCorrelation::partially_bound(Some("tx"), None, None).is_available(),
        "a partial binding must never claim full correlation availability"
    );
    assert!(
        !HostTerminalCorrelation::unavailable().is_available(),
        "the explicitly uncorrelated projection claims nothing"
    );

    // A partial binding is a distinct value from both neighbours: it is not the
    // full correlation, and it is not the "nothing held" projection either.
    let partial = HostTerminalCorrelation::partially_bound(Some("operation"), None, None);
    assert_eq!(
        partial,
        HostTerminalCorrelation::partially_bound(Some("operation"), None, None),
        "the same owner handles project the same immutable correlation"
    );
    assert_ne!(
        partial,
        HostTerminalCorrelation::unavailable(),
        "holding one identity must not render as holding none"
    );
    assert_ne!(
        partial,
        HostTerminalCorrelation::bound("operation", "effect", "req"),
        "a partial binding must not render as the full correlation"
    );

    // Content, not position: two operations with different owner-issued handles
    // project to two different correlations, so a terminal carrying one can
    // never be confused with a terminal carrying the other.
    assert_ne!(
        HostTerminalCorrelation::bound("tx-a", "effect-a", "req-a"),
        HostTerminalCorrelation::bound("tx-b", "effect-b", "req-b"),
        "distinct owner identities must project to distinct correlations"
    );
}
