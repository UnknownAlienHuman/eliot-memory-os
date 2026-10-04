#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Kernel generation/control-plane/recovery/health/identity diagnostics
//! integrator matrix (F-LOG-KERNEL-4, issue #903).
//!
//! Thirty cases, exactly `WORK_UNIT_CASE 903/1..30`, each driven through the
//! `pub` seams `eliot_kernel` already exposes
//! (`generation_route_snapshot`, `apply_generation_cutover`, `apply_control`,
//! `control_capacity`, `request_shutdown`, `mark_daemon_ready`,
//! `activation_operational_view`, `blob_capability_projection`,
//! `active_generation_registry_projection`,
//! `verify_active_generation_registry_fingerprint`, `service_state`,
//! `daemon_launch`, `daemon_ready`, `daemon_route_metrics_projection`,
//! `diagnostic_brief_projection`). No visibility is widened and no public test
//! API is added: a case whose surface is `pub(super)`/`pub(crate)` or
//! `#[cfg(windows)]` names the owning inline module in its comment instead of
//! faking reachability.
//!
//! Every assertion pins a comparison PRODUCTION performs, named inline with its
//! `path.rs:line`. A case whose premises only compare two values this file built
//! would be a formatter test, not a proof, so none is written that way.
//!
//! `tests/data/kernel_generation_control_diagnostics.json` freezes the six-file
//! denominator, the complete `kernel.*` event inventory of those six modules and
//! one boundary row per case. Case 1 re-measures both lists from source and
//! compares them two ways, so the map cannot be satisfied by a fabricated list.
//!
//! Not proven here, by the card's own DEFER clause and by the module ownership
//! below: live Windows kernel-owner and daemon-launch execution, live cutover or
//! reserve recovery from real owner evidence, the `pub(super)` health snapshot
//! omission arms, the `pub(crate)` runtime-identity and ORS-recovery slices, and
//! Control Reserve Product behaviour.

// -------------------- capture seam (single, shared) --------------------

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use eliot_contracts::{ResourceGeneration, StateFence};
use eliot_kernel::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET;
use eliot_kernel::{KernelComposition, KernelConfig};
use eliot_kernel_core::{CutoverDecision, RouteScope};
use eliot_kernel_service::{KernelControlCommand, KernelServiceError, KernelServiceState};
use eliot_runtime_contracts::GenerationCutoverState;
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

/// A sink that refuses every write, used by case 29 to prove a failing sink
/// changes no production call or result.
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sink failed"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("sink failed"))
    }
}

/// A sink that accepts and discards every record, used by case 29 to prove a
/// dropped sink changes no production call or result.
struct DiscardWriter;

impl Write for DiscardWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capture_with<F, R>(f: F) -> (String, R)
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
        tracing::subscriber::with_default(subscriber, f)
    };
    let bytes = sink.bytes.lock().expect("capture lock").clone();
    (String::from_utf8_lossy(&bytes).into_owned(), result)
}

/// Case 29: delivery through a writer that fails every write.
fn capture_with_failing_sink<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(FailingWriter)
        .finish();
    tracing::subscriber::with_default(subscriber, f)
}

/// Case 29: delivery through a writer that accepts and discards every record.
fn capture_with_discarding_sink<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(DiscardWriter)
        .finish();
    tracing::subscriber::with_default(subscriber, f)
}

/// Case 29: delivery with no subscriber at all, so every record is dropped at
/// the dispatcher exactly as it would be before the observability owner exists.
fn capture_with_disabled_sink<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), f)
}

// -------------------- fixture --------------------

fn fixture() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/kernel_generation_control_diagnostics.json");
    let bytes = std::fs::read(&path).expect("generation/control fixture must be readable");
    serde_json::from_slice(&bytes).expect("generation/control fixture must be valid JSON")
}

fn fixture_str(fixture: &Value, pointer: &str) -> String {
    fixture
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture must pin {pointer}"))
        .to_owned()
}

// -------------------- work roots --------------------

struct TempGuard {
    root: std::path::PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn work_root(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("eliot-903-{tag}-{}-{nanos}", std::process::id()))
}

fn test_kernel() -> (KernelComposition, TempGuard) {
    build_kernel("base")
}

fn build_kernel(tag: &str) -> (KernelComposition, TempGuard) {
    let root = work_root(tag);
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    (kernel, TempGuard { root })
}

/// Composition construction under capture, for the recovery phase inventory
/// that composition bootstrap drives.
fn build_kernel_captured(tag: &str) -> (String, KernelComposition, TempGuard) {
    let root = work_root(tag);
    std::fs::create_dir_all(&root).expect("test work root");
    let (text, kernel) = capture_with(|| {
        KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition")
    });
    (text, kernel, TempGuard { root })
}

// -------------------- identities --------------------

fn test_epoch(sequence: u64) -> eliot_contracts::EpochId {
    eliot_contracts::EpochId::new(
        eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("test lineage"),
        std::num::NonZeroU64::new(sequence).expect("test sequence"),
    )
    .expect("test epoch")
}

fn daemon_scope() -> RouteScope {
    RouteScope::new("daemon").expect("daemon scope")
}

/// An uncommitted cutover decision: structurally valid (distinct generations,
/// strictly rising epoch) but never `Committed`, so the router refuses it before
/// any ORS staging and the gateway fences with a `Platform` terminal.
fn uncommitted_cutover() -> CutoverDecision {
    CutoverDecision::new(
        "eliot-903-integrator-cutover",
        daemon_scope(),
        Some(ResourceGeneration::new(1).expect("old generation")),
        ResourceGeneration::new(2).expect("new generation"),
        test_epoch(1),
        test_epoch(2),
        GenerationCutoverState::Preparing,
    )
    .expect("uncommitted cutover decision")
}

/// A `Committed` decision whose prior generation is not the live route's, so
/// production classifies it read-only (`classify_generation_cutover_live_endpoint`
/// returns `Mismatch` at `generation_control.rs:881`) and refuses it as a typed
/// `HandshakeMismatch` WITHOUT poisoning the gateway. Every case that needs the
/// generation axis to stay usable afterwards uses this leg.
fn stale_committed_cutover(cutover_id: &str) -> CutoverDecision {
    CutoverDecision::new(
        cutover_id,
        daemon_scope(),
        Some(ResourceGeneration::new(5).expect("stale generation")),
        ResourceGeneration::new(6).expect("candidate generation"),
        test_epoch(1),
        test_epoch(2),
        GenerationCutoverState::Committed,
    )
    .expect("stale committed cutover decision")
}

/// A `Committed` decision naming the owner's exact live route generation and
/// epoch tuple. Production admits it past the live-state classification
/// (`generation_control.rs:612`-`:617`) and into the ORS staging owner, so the
/// staged/committed/applied phases are all reachable through this decision.
fn owner_committed_cutover(cutover_id: &str) -> CutoverDecision {
    CutoverDecision::new(
        cutover_id,
        daemon_scope(),
        Some(ResourceGeneration::genesis()),
        ResourceGeneration::new(2).expect("candidate generation"),
        test_epoch(1),
        test_epoch(2),
        GenerationCutoverState::Committed,
    )
    .expect("owner committed cutover decision")
}

/// The exact live fence a fresh standalone composition runs under: lineage
/// `550e8400-…`, sequence 1, generation `ResourceGeneration::genesis()`.
fn live_fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

// -------------------- captured-surface assertions --------------------

fn index_of(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("captured surface is missing {needle}:\n{text}"))
}

fn assert_present(text: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            text.contains(needle),
            "captured surface is missing {needle}:\n{text}"
        );
    }
}

fn assert_absent(text: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !text.contains(needle),
            "captured surface must not contain {needle}:\n{text}"
        );
    }
}

/// Asserts the spans appear in the listed causal order. Production emits its
/// phase records in that order synchronously, so a reordered or dropped phase
/// is a real regression, not a formatting artefact.
fn assert_causal_order(text: &str, needles: &[&str]) {
    let mut previous = 0usize;
    for needle in needles {
        let at = index_of(text, needle);
        assert!(
            at >= previous,
            "span {needle} breaks the causal order {needles:?}:\n{text}"
        );
        previous = at;
    }
}

fn occurrences(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

// -------------------- source measurement (case 1) --------------------

/// The #903 observation helpers this crate's own six card modules write through.
///
/// This list holds ELEVEN helper names, and it is the whole denominator of the
/// case-1 guard. It is deliberately NOT a claim that no other production module
/// emits a `kernel.*` record. Three files outside the six card modules do, none
/// of them through these helpers: `daemon_process_launch.rs` writes
/// `kernel.daemon.launch_*` through #901's `observe_daemon_launch`,
/// `daemon_request_dispatch.rs` writes
/// `kernel.daemon.supervision_expired_effects_revoked` through its own
/// `observe_daemon_request`, and `frame_dispatch.rs` writes
/// `kernel.health.capability_projected` from a raw `tracing::info!` with no
/// helper at all. The guard therefore measures only which files write THROUGH
/// THESE HELPERS.
const OBSERVER_HELPERS: [&str; 11] = [
    "observe_control",
    "observe_control_in_context",
    "observe_control_capacity",
    "observe_generation",
    "observe_generation_cutover",
    "observe_recovery",
    "observe_recovery_cutover",
    "observe_health",
    "observe_daemon_runtime",
    "observe_daemon_runtime_in_context",
    "observe_identity",
];

/// Removes `//` line comments (quote-aware) so a helper name mentioned in prose
/// is never mistaken for a call site.
fn strip_line_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let bytes = line.as_bytes();
        let mut end = bytes.len();
        let mut in_string = false;
        let mut index = 0usize;
        while index < bytes.len() {
            let byte = bytes[index];
            let escaped = index > 0 && bytes[index - 1] == b'\\';
            if byte == b'"' && !escaped {
                in_string = !in_string;
            } else if byte == b'/' && !in_string && bytes.get(index + 1) == Some(&b'/') {
                end = index;
                break;
            }
            index += 1;
        }
        out.push_str(&line[..end]);
        out.push('\n');
    }
    out
}

/// Drops every `#[cfg(test…)]`-gated test module: the completeness map is about
/// production emitters, and the modules' inline source-string guards are their
/// own proof.
///
/// The cut point is a test MODULE, not the first `#[cfg(test…)]` attribute. In
/// `generation_control.rs` a test-only `#[cfg(test)] fn` is defined above the
/// production `generation_route_snapshot`, so cutting at the first attribute
/// would silently drop four production event literals
/// (`kernel.generation.snapshot_requested`, `kernel.generation.snapshot_committed`,
/// `kernel.generation.snapshot_failed` and `kernel.generation.cutover_committed`)
/// which the boundary rows name as spans. A test-only `fn` outside a test module
/// is kept instead of being dropped by brace matching, because both such
/// helpers across the six card modules emit no event literal of their own:
/// `generation_control.rs:648` `fence_service_after_generation_failure` only
/// calls `ServiceFenceObservation::emit_for_cutover`, which is measured where
/// it is written, and `control_plane.rs:2159` `verify_probe_watchdog_branch`
/// only returns `TransportError::SessionFenced`.
///
/// Measured over the six card modules this rule yields 77 distinct production
/// literals (13/10/9/21/14/10); the old first-attribute rule yielded 73,
/// because it lost exactly the four named above in `generation_control.rs`.
fn production_source(path: &Path) -> String {
    let source = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "production source must be readable: {}: {error}",
            path.display()
        )
    });
    let lines: Vec<&str> = source.lines().collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim_start();
        if trimmed.starts_with("#[cfg(test") || trimmed.starts_with("#[cfg(all(test") {
            // Walk past the rest of this item's attribute list to the item it
            // gates. Only a gated module ends the file's production prefix.
            let mut item = index + 1;
            while item < lines.len() && lines[item].trim_start().starts_with("#[") {
                item += 1;
            }
            if lines
                .get(item)
                .is_some_and(|line| line.trim_start().starts_with("mod "))
            {
                break;
            }
        }
        kept.push(lines[index]);
        index += 1;
    }
    kept.join("\n")
}

fn is_event_literal(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("kernel.") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// Every `"kernel.…"` event literal a production module emits, measured with the
/// same rule the fixture was frozen from.
fn kernel_event_literals(path: &Path) -> BTreeSet<String> {
    let source = production_source(path);
    let mut found = BTreeSet::new();
    let needle = "\"kernel.";
    let mut cursor = 0usize;
    while let Some(start) = source[cursor..].find(needle) {
        let literal_start = cursor + start + 1;
        let Some(end) = source[literal_start..].find('"') else {
            break;
        };
        let literal = &source[literal_start..literal_start + end];
        if is_event_literal(literal) {
            found.insert(literal.to_owned());
        }
        cursor = literal_start + end + 1;
    }
    found
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path.clone());
        }
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The frozen event vocabulary, for case 30's semantic-record extraction.
fn frozen_event_vocabulary(fixture: &Value) -> Vec<String> {
    let by_file = fixture
        .get("events_by_file")
        .and_then(Value::as_object)
        .expect("fixture must pin events_by_file");
    let mut all: BTreeSet<String> = BTreeSet::new();
    for values in by_file.values() {
        for value in values.as_array().expect("event list") {
            all.insert(value.as_str().expect("event literal").to_owned());
        }
    }
    all.insert(fixture_str(fixture, "/terminal_event"));
    for code in fixture["terminal_codes"]
        .as_array()
        .expect("fixture must pin terminal_codes")
    {
        all.insert(code.as_str().expect("terminal code").to_owned());
    }
    all.into_iter().collect()
}

/// The ordered sequence of semantic diagnostic facts in one capture: every
/// frozen event literal plus every frozen terminal code, in emission order,
/// without the timestamps, paths and formatting the delivery is allowed to vary.
fn semantic_records(text: &str, vocabulary: &[String]) -> Vec<String> {
    let mut ordered: Vec<(usize, String)> = Vec::new();
    for literal in vocabulary {
        let mut cursor = 0usize;
        while let Some(offset) = text[cursor..].find(literal.as_str()) {
            let at = cursor + offset;
            ordered.push((at, literal.clone()));
            cursor = at + literal.len();
        }
    }
    ordered.sort_by_key(|(at, _)| *at);
    let mut records: Vec<String> = Vec::new();
    for (_, literal) in ordered {
        if records.last() != Some(&literal) {
            records.push(literal);
        }
    }
    records
}

// -------------------- test-denominator measurement (case 1) --------------------

/// This test file's own source, verbatim.
///
/// The third denominator binds each frozen boundary row to the case that reads
/// it, and it needs the file in two readings. The `WORK_UNIT_CASE` markers and
/// the `#[test]` attributes between them are themselves comments and attributes,
/// so `marked_cases` must see the RAW text or it would find none. The `fn`
/// bodies must be comment-stripped instead, so a span named only in a case's
/// prose cannot satisfy its own row. `strip_line_comments` keeps one output line
/// per input line, so both readings describe the same line numbering.
///
/// An unreadable file yields an empty source, and the marker-count assertion
/// below then fails with the empty list rather than passing vacuously.
fn self_source() -> String {
    let path = manifest_dir().join("tests/kernel_generation_control_diagnostics.rs");
    std::fs::read_to_string(path).unwrap_or_default()
}

/// True when this line opens a new top-level item, which is where one `fn`'s
/// body ends and the next begins in a file that declares no nested `mod`.
fn opens_top_level_item(line: &str) -> bool {
    [
        "fn ", "struct ", "impl ", "const ", "static ", "use ", "type ", "mod ",
    ]
    .iter()
    .any(|keyword| line.starts_with(keyword))
}

/// The name a top-level `fn` declares on this line, stopping before any generic
/// parameter list. `None` for every other line, including indented (nested)
/// `fn`s, which are therefore never treated as a body boundary.
fn top_level_fn_name(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("fn ")?;
    let length = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(rest.len(), |at| at);
    (length > 0).then_some(&rest[..length])
}

/// Every top-level `fn` in this file as `(name, body)` in file order, each body
/// running from its own declaration to the next top-level item. The caller
/// supplies comment-stripped source, so a body carries code and doc comments
/// only in its non-comment part.
fn top_level_fn_bodies(source: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut bodies: Vec<(String, String)> = Vec::new();
    for (start, line) in lines.iter().enumerate() {
        let Some(name) = top_level_fn_name(line) else {
            continue;
        };
        let mut end = lines.len();
        for next in (start + 1)..lines.len() {
            if opens_top_level_item(lines[next]) {
                end = next;
                break;
            }
        }
        bodies.push((name.to_owned(), lines[start..end].join("\n")));
    }
    bodies
}

/// Each `WORK_UNIT_CASE: 903/N` marker paired with the top-level `fn` it gates
/// and the number of `#[test]` attributes standing between them, in file order.
fn marked_cases(source: &str) -> Vec<(u64, String, usize)> {
    let mut marked: Vec<(u64, String, usize)> = Vec::new();
    let mut pending: Option<u64> = None;
    let mut tests = 0usize;
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(digits) = trimmed.strip_prefix("// WORK_UNIT_CASE: 903/") {
            pending = digits.parse::<u64>().ok();
            tests = 0;
            continue;
        }
        let Some(case) = pending else {
            continue;
        };
        if trimmed == "#[test]" {
            tests += 1;
            continue;
        }
        if let Some(name) = top_level_fn_name(line) {
            marked.push((case, name.to_owned(), tests));
            pending = None;
        }
    }
    marked
}

/// Whether `token` occurs in `source` as a complete token and never as a piece
/// of a longer one.
///
/// "Complete" means a quoted literal equal to the token, or an occurrence whose
/// neighbours are both delimiters. The delimiter set carries `.` as well as the
/// alphanumerics and `_`, so a `.`-composed typed field matches only as its own
/// identifier: `generation_registry.route` is satisfied by
/// `field: "generation_registry.route"` and NOT by
/// `field: "generation_registry.route_scope"`, which a bare `contains` cannot
/// tell apart.
fn token_present(source: &str, token: &str) -> bool {
    if source.contains(&format!("\"{token}\"")) {
        return true;
    }
    source.match_indices(token).any(|(at, _)| {
        let before = source[..at].as_bytes().last().copied();
        let after = source[at + token.len()..].as_bytes().first().copied();
        let delimited = |byte: Option<u8>| match byte {
            Some(byte) => !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'),
            None => true,
        };
        delimited(before) && delimited(after)
    })
}

/// The text between the delimiter at `open` and its match, or `None` when the
/// source runs out first. String literals are skipped, so a delimiter inside
/// one cannot unbalance the scan.
fn balanced_delimited(source: &str, open: usize) -> Option<&str> {
    let bytes = source.as_bytes();
    let open_byte = bytes.get(open).copied()?;
    let close_byte = match open_byte {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut depth = 0i32;
    let mut index = open;
    let mut in_string = false;
    while let Some(byte) = bytes.get(index).copied() {
        if in_string {
            if byte == b'\\' {
                index += 1;
            } else if byte == b'"' {
                in_string = false;
            }
        } else {
            match byte {
                b'"' => in_string = true,
                _ if byte == open_byte => depth += 1,
                _ if byte == close_byte => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&source[open..=index]);
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    None
}

/// Whether the span is a real token in the production source of the file the
/// row names: one literal or stable code, or both halves of a typed-error span,
/// each half matched as a complete token.
///
/// `production` is the COMMENT-STRIPPED production prefix (see the `// WORK_UNIT
/// CASE: 903/1` caller), so a span that survives only inside a production `//`
/// comment cannot satisfy a row.
///
/// This is the half of the span denominator that keeps the map honest about the
/// OWNER. It cannot tell which case reads the span, which is what
/// `case_reads_span` measures; it answers only "the module the row cites really
/// does write this".
fn span_is_in_production(span: &str, production: &str) -> bool {
    match span.split_once(':') {
        Some((variant, field)) if !is_event_literal(span) => {
            token_present(production, variant) && token_present(production, field)
        }
        _ => token_present(production, span),
    }
}

/// The body of the first `fn <bare>` declared in `source`, or `None` when no
/// such declaration is there. The name may be written bare or after a `::`
/// path; the caller always compares on the bare segment, because a fixture that
/// qualifies a free function with a type it does not belong to must fail.
///
/// The signature is walked to the body's own opening brace, skipping `->` so a
/// return type's angle brackets do not unbalance the scan, and the body itself
/// is brace-matched by `balanced_delimited`.
fn production_fn_body<'a>(source: &'a str, bare: &str) -> Option<&'a str> {
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find(bare) {
        let at = cursor + found;
        cursor = at + bare.len();
        let is_identifier = |byte: Option<u8>| match byte {
            Some(byte) => byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.',
            None => false,
        };
        if is_identifier(at.checked_sub(1).and_then(|i| bytes.get(i).copied()))
            || is_identifier(bytes.get(at + bare.len()).copied())
        {
            continue;
        }
        let mut index = at + bare.len();
        let mut round = 0i32;
        let mut angle = 0i32;
        loop {
            let Some(byte) = bytes.get(index).copied() else {
                return None;
            };
            if byte == b'-' && bytes.get(index + 1) == Some(&b'>') {
                index += 2;
                continue;
            }
            match byte {
                b'(' | b'[' => round += 1,
                b')' | b']' => round -= 1,
                b'<' => angle += 1,
                b'>' => angle -= 1,
                b'{' if round == 0 && angle == 0 => break,
                _ => {}
            }
            index += 1;
        }
        if let Some(body) = balanced_delimited(source, index) {
            return Some(body);
        }
    }
    None
}

/// Every 1-based line in `source` where the span is passed to a call of `bare`
/// as an argument, in file order.
///
/// This is the measured form of the only alternative an `emitter` row has when
/// the named function does not write the literal itself: the observation helper
/// the literal is handed to. A call shape is required, so a bare mention of the
/// name in the same file is not a call site.
fn span_argument_sites(source: &str, bare: &str, span: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut sites: Vec<usize> = Vec::new();
    let mut cursor = 0usize;
    while let Some(found) = source[cursor..].find(bare) {
        let at = cursor + found;
        cursor = at + bare.len();
        let previous = at.checked_sub(1).and_then(|i| bytes.get(i).copied());
        if previous.is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
        {
            continue;
        }
        let mut index = at + bare.len();
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if bytes.get(index) != Some(&b'(') {
            continue;
        }
        let Some(arguments) = balanced_delimited(source, index) else {
            continue;
        };
        if span_is_in_production(span, arguments) {
            sites.push(source[..at].matches('\n').count() + 1);
        }
    }
    sites
}

/// Whether the case whose `body` this is reads the row's `span`.
///
/// Three real shapes occur in the frozen rows, and all three are read off the
/// fixture rather than assumed here. A span is either one production literal or
/// stable terminal code the case matches against a capture; a typed-error span
/// composed as `Variant:field`, where production raises the variant carrying a
/// `field` the case pins, so both halves must be carried; or a value the case
/// reads out of the fixture by JSON pointer instead of repeating it, in which
/// case a pointer the case's own body hands to `fixture_str` must resolve to
/// exactly this span. `is_event_literal` decides the composite test, so no event
/// span is ever split on a `:` it does not contain, and `token_present` matches
/// both halves of a composite as complete tokens for the same reason production
/// side does.
///
/// The pointer arm requires the CALL SHAPE `fixture_str(…, "<pointer>")`, not a
/// quoted token starting with `/`. A pointer that appears only inside an
/// assertion MESSAGE names the span in prose and never reads it, so accepting
/// any quoted token would let a message satisfy the row.
///
/// `body` is already comment-stripped, so a span that appears only in a case's
/// prose does not count as read.
fn case_reads_span(span: &str, body: &str, fixture: &Value) -> bool {
    if let Some((variant, field)) = span.split_once(':') {
        if !is_event_literal(span) {
            return token_present(body, variant) && token_present(body, field);
        }
    }
    if body.contains(span) {
        return true;
    }
    let mut cursor = 0usize;
    while let Some(found) = body[cursor..].find("fixture_str(") {
        let open = cursor + found + "fixture_str(".len() - 1;
        let Some(arguments) = balanced_delimited(body, open) else {
            cursor = open + 1;
            continue;
        };
        let mut rest = arguments;
        while let Some(open_quote) = rest.find('"') {
            rest = &rest[open_quote + 1..];
            let Some(close_quote) = rest.find('"') else {
                return false;
            };
            let pointer = &rest[..close_quote];
            rest = &rest[close_quote + 1..];
            if pointer.starts_with('/')
                && fixture.pointer(pointer).and_then(Value::as_str) == Some(span)
            {
                return true;
            }
        }
        cursor = open + 1;
    }
    false
}

/// How many `#[test]` attributes this file carries, counted over the RAW source.
///
/// `marked_cases` counts the `#[test]` attributes standing BETWEEN a marker and
/// the `fn` it gates, so a `#[test] fn` written after its own case's `fn` and
/// before the next marker is invisible to it while the marker count and the
/// row-count equality both still hold. This total closes that window.
fn test_attribute_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| line.trim() == "#[test]")
        .count()
}

// -------------------- result probes (cases 29, 30) --------------------

#[derive(Debug, Eq, PartialEq)]
struct ProbeResults {
    route_generation: u64,
    route_epoch_sequence: u64,
    projection_generation: u64,
    projection_fingerprint: String,
    control_capacity: usize,
    service_is_cold: bool,
    blob_projection: String,
    route_metrics_gauges: String,
}

/// Reads the generation, reserve and health results the composition's own seams
/// return. Two runs of this probe are compared byte for byte, so it asserts
/// production results and never a diagnostic rendering.
fn probe(kernel: &KernelComposition) -> ProbeResults {
    let router = kernel.generation_route_snapshot().expect("route snapshot");
    let route = router.route(&daemon_scope()).expect("daemon route");
    let projection = kernel
        .active_generation_registry_projection("daemon")
        .expect("active generation projection");
    ProbeResults {
        route_generation: route.active_generation().value(),
        route_epoch_sequence: router.epoch().sequence.get(),
        projection_generation: projection.active_generation().value(),
        projection_fingerprint: projection.generation_fingerprint().to_owned(),
        control_capacity: kernel.control_capacity(),
        service_is_cold: matches!(kernel.service_state(), Ok(KernelServiceState::Cold)),
        blob_projection: kernel.blob_capability_projection().to_string(),
        route_metrics_gauges: kernel.daemon_route_metrics_projection()["gauges"].to_string(),
    }
}

/// The observed operation sequence cases 29 and 30 replay. Every leg is an
/// existing `pub` seam; `request_shutdown` runs last because it is the one leg
/// that records durable drain intent.
fn drive(kernel: &KernelComposition) {
    let _ = kernel.generation_route_snapshot();
    let _ = kernel.control_capacity();
    let _ = kernel.apply_control(KernelControlCommand::ProbeReady);
    let _ = kernel.activation_operational_view();
    let _ = kernel.blob_capability_projection();
    let _ = kernel.daemon_route_metrics_projection();
    let _ = kernel.diagnostic_brief_projection();
    let _ = kernel.daemon_ready();
    let _ = kernel.daemon_launch().is_some();
    let _ = kernel.mark_daemon_ready();
    let _ = kernel.request_shutdown();
}

// WORK_UNIT_CASE: 903/1
// I14.20:265: "`COMMITTED` is the ORS linearization point; unresolved scopes
// remain explicit during reconciliation." and I1.8:18: "No component alone can
// invent semantics, authorize them and commit them."
// Pins the six-file denominator of issue #903 against the production source and
// drives one real callsite (`generation_control.rs:765`) so the map's emitter
// exists rather than being a description.
#[allow(
    clippy::too_many_lines,
    reason = "the three source denominators and the ownership cross-check read one snapshot"
)]
#[test]
fn six_file_boundary_denominator_is_complete() {
    let fx = fixture();
    let files = fx["files"].as_array().expect("fixture must pin files");
    assert_eq!(
        files.len(),
        6,
        "issue #903 owns exactly six production modules for this axis"
    );
    let expected = [
        "bins/eliot-kernel/src/control_plane.rs",
        "bins/eliot-kernel/src/daemon_runtime.rs",
        "bins/eliot-kernel/src/generation_control.rs",
        "bins/eliot-kernel/src/generation_recovery.rs",
        "bins/eliot-kernel/src/health_view.rs",
        "bins/eliot-kernel/src/runtime_identity.rs",
    ];
    let by_file = fx["events_by_file"]
        .as_object()
        .expect("fixture must pin events_by_file");
    for (index, file) in files.iter().enumerate() {
        let relative = file.as_str().expect("file path");
        assert_eq!(
            relative, expected[index],
            "fixture file order must match the card's EDIT list"
        );
        let path = manifest_dir().join(
            relative
                .strip_prefix("bins/eliot-kernel/")
                .unwrap_or(relative),
        );
        assert!(path.exists(), "fixture file must exist: {relative}");
        // Two-way equality per (file, event): a fabricated list fails the
        // "missing from fixture" direction and a moved/renamed emitter fails the
        // "measured but not frozen" direction. A bare difference count is not a
        // completeness proof, so both directions are reported by name.
        let measured = kernel_event_literals(&path);
        let frozen: BTreeSet<String> = by_file[relative]
            .as_array()
            .unwrap_or_else(|| panic!("fixture must pin events for {relative}"))
            .iter()
            .map(|value| value.as_str().expect("event literal").to_owned())
            .collect();
        // The comparison below is a set difference, so it is trivially TRUE if BOTH
        // sides went to zero for this file, and `path.exists()` above proves only
        // that the source is READABLE, not that it yields any measured event at
        // all. Fix both sides to non-empty event sets first, so a source that
        // stopped emitting and a fixture row emptied to match it both fail here
        // instead of passing the difference vacuously. What is being counted is
        // the number of distinct `kernel.*` event literals measured in this file
        // versus frozen for it, and both counts are reported on failure.
        assert!(
            !measured.is_empty() && !frozen.is_empty(),
            "{relative} must measure and freeze at least one event literal each: \
             measured={measured:?} frozen={frozen:?}"
        );
        let only_measured: Vec<&String> = measured.difference(&frozen).collect();
        let only_frozen: Vec<&String> = frozen.difference(&measured).collect();
        assert!(
            only_measured.is_empty() && only_frozen.is_empty(),
            "{relative} event inventory drifted: only-in-source={only_measured:?} only-in-fixture={only_frozen:?}"
        );
    }
    // Whole-tree helper-call denominator. What this asserts, and the only thing
    // it can assert, is that the complete set of production files under
    // `bins/eliot-kernel/src` which write THROUGH the #903 observation helpers in
    // `OBSERVER_HELPERS` is exactly the six card modules. The comparison is
    // `assert_eq!` over two sorted vectors, so it holds in both directions: a
    // seventh module that adopted one of these helpers fails, and a card module
    // that stopped using them fails.
    //
    // It is NOT a claim that no other production module emits a `kernel.*`
    // record for this axis. Three files outside the six do, none of them
    // through these helpers: `daemon_process_launch.rs` writes `kernel.daemon.*`
    // through #901's `observe_daemon_launch`, `daemon_request_dispatch.rs`
    // writes `kernel.daemon.supervision_expired_effects_revoked` itself, and
    // `frame_dispatch.rs` writes `kernel.health.capability_projected` from a
    // raw `tracing::info!` with no helper. Those axes belong to their own owners
    // and their own fixtures.
    let mut sources = Vec::new();
    collect_rust_sources(&manifest_dir().join("src"), &mut sources);
    assert!(
        !sources.is_empty(),
        "the production source tree must be readable"
    );
    let mut owning: Vec<String> = Vec::new();
    for path in &sources {
        let stripped = strip_line_comments(&std::fs::read_to_string(path).unwrap_or_default());
        if OBSERVER_HELPERS
            .iter()
            .any(|helper| stripped.contains(helper))
        {
            let relative = path
                .strip_prefix(manifest_dir())
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            owning.push(relative);
        }
    }
    owning.sort();
    let mut expected_owning: Vec<String> = expected
        .iter()
        .map(|path| {
            path.strip_prefix("bins/eliot-kernel/")
                .unwrap_or(path)
                .to_owned()
        })
        .collect();
    expected_owning.sort();
    assert_eq!(
        owning, expected_owning,
        "the files writing through the #903 observation helpers must be exactly the six card modules, in both directions"
    );
    // ---------------------------------------------------------------------
    // THIRD DENOMINATOR: the TEST denominator. The two above measure which
    // production FILES and which helper CALLSITES belong to #903. This one
    // measures which CASES the thirty frozen boundary rows are bound to, and
    // every part of it is measured from source read at run time rather than
    // from the fixture's own word.
    //
    // MEASURED HERE, four ways:
    //   (a) PAIRING. This file must carry exactly thirty
    //       `// WORK_UNIT_CASE: 903/N` markers numbered 1..=30 in file order,
    //       each followed by exactly one `#[test]`, and it must carry exactly
    //       thirty `#[test]` attributes IN TOTAL, and the fixture must freeze one
    //       row per marked case, at that case's own index, naming the `fn` its
    //       own marker gates. The total is not redundant with the per-marker
    //       count: the per-marker walk only sees a `#[test]` standing BETWEEN a
    //       marker and the `fn` it gates, so a `#[test] fn` written after its own
    //       case's `fn` and before the next marker would leave both the marker
    //       sequence and the row-count equality intact while adding a test the
    //       map does not know about. Counting the attributes over the whole raw
    //       source closes that window. The pairing itself is then held in both
    //       directions by length equality: a row naming a case that does not
    //       exist, another case's `fn`, or a marker that gates no test all fail
    //       here.
    //   (b) SPAN REALNESS. Each row's `span` must be a COMPLETE TOKEN in the
    //       COMMENT-STRIPPED production source of the `file` that row names, so
    //       no row can cite a span the owner module never writes and no span can
    //       satisfy a row from inside a production `//` comment. A typed-error
    //       span must carry both of its halves as complete tokens each, which is
    //       why `generation_registry.route` is not satisfied by
    //       `generation_registry.route_scope`.
    //   (c) SPAN BINDING. Each row's `span` must be readable out of the body of
    //       the `fn` its row names: as a literal or stable code the case matches
    //       against a capture, as both halves of a `Variant:field` typed-error
    //       span, or through a JSON pointer the case's own body hands to
    //       `fixture_str` and that resolves to exactly that span. Bodies are
    //       comment-stripped, so a span that appears only in a case's prose does
    //       not count, and the pointer arm needs the CALL SHAPE, so a pointer
    //       that appears only in an assertion message does not count either.
    //   (d) OWNERSHIP. The four columns no other part of this denominator reads
    //       are read here and cross-checked against the same production source:
    //       the row's `function` must be declared in the row's own `file` (on its
    //       BARE segment, so a row that qualifies a free function with a type it
    //       does not belong to fails); `stage` and `owner_evidence` must be
    //       present and non-empty; and `role` must hold against what the named
    //       function's own body contains — `emitter` means the span is inside
    //       that body OR the row lists the exact lines where the span is passed
    //       to that function as an argument, and `propagated` means it is
    //       neither. The listed lines are compared to the measured ones in BOTH
    //       directions, so an invented line and an unlisted real one both fail.
    //
    // NOT FULLY MEASURED, and disclosed here rather than asserted away: (c) does
    // not hold for every row. Rows 10, 16, 19 and 29 name a span their OWN case
    // never reads. Case 10 asserts the authority-epoch tuples and the refusal's
    // request/failure pair, not the handshake record it names; case 16 asserts
    // the control lane's own health records and terminal absences, not the
    // transition failure it names; case 19 asserts liveness/readiness
    // separation, not the readiness report it names; case 29 asserts sink
    // non-interference, not the service-state record it names. All four spans
    // are real in production and every one of them IS read by other cases, so
    // the map is not false about the owner; it is false about WHICH case reads
    // it. The residue is pinned by exact identity below, so repairing one of the
    // four, or letting a fifth appear, fails here until the map and the case
    // agree. That is deliberate: this is a tripwire on disclosed debt, not a
    // standing exemption.
    //
    // WHAT WOULD CLOSE (c) COMPLETELY is fixture data this map does not carry:
    // per row, the set of literals the named case is expected to assert on. A
    // `span` names ONE production literal, while a case such as case 29 asserts
    // a whole driven sequence of them, so "this span" cannot be the unit of
    // expected needles without inventing a per-row list. Inventing that list
    // here would fabricate evidence, so it is not invented; (c) is therefore
    // honestly bounded at "the named case carries this literal in its code",
    // which is weaker than "the named case asserts this literal against a
    // capture" and is reported as such.
    //
    // (d) IS A CROSS-CHECK, and its two directions are both real: `emitter` is
    // falsified by a function whose body carries neither the span nor an
    // argument call for it, and `propagated` is falsified by a function whose
    // body carries the span. Neither direction is a restatement of the other,
    // and neither is a claim about `owner_evidence`, whose prose is verified by
    // reading and NOT by this file: only its presence is asserted here, because
    // no mechanical check can decide whether a durable ORS row really is the
    // evidence a stage turns on.
    let source = self_source();
    let marked = marked_cases(&source);
    assert_eq!(
        marked
            .iter()
            .map(|(case, _, _)| *case)
            .collect::<Vec<u64>>(),
        (1..=30).collect::<Vec<u64>>(),
        "this file must carry exactly 30 WORK_UNIT_CASE markers numbered 1..30 in file order"
    );
    assert!(
        marked.iter().all(|(_, _, tests)| *tests == 1),
        "every marker must be followed by exactly one #[test], got {marked:?}"
    );
    assert_eq!(
        test_attribute_count(&source),
        30,
        "this file must carry exactly 30 #[test] attributes IN TOTAL: the per-marker walk above \
         only sees a #[test] standing between a marker and the fn it gates, so a test placed \
         after its own case's fn would otherwise be invisible to it"
    );
    let no_rows: Vec<Value> = Vec::new();
    assert!(fx["boundaries"].is_array(), "fixture must pin boundaries");
    let rows = fx["boundaries"].as_array().unwrap_or(&no_rows);
    assert_eq!(
        rows.len(),
        marked.len(),
        "the fixture must freeze exactly one boundary row per marked case, in both directions"
    );
    let bodies = top_level_fn_bodies(&strip_line_comments(&source));
    let mut unbound: Vec<u64> = Vec::new();
    for (row, (case, name, _)) in rows.iter().zip(&marked) {
        assert!(
            row["span"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty())
                && row["file"]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
            "boundary row for case {case} must pin a NON-EMPTY span and its production file: an \
             empty span satisfies BOTH halves of this row vacuously, because \
             `match_indices(\"\")` yields every position in `token_present` and \
             `body.contains(\"\")` is unconditionally true in `case_reads_span`"
        );
        // The assertions above make each of these a real string, so the empty
        // default is unreachable rather than a silent pass.
        let span = row["span"].as_str().map_or("", |value| value);
        assert_eq!(
            row["case"].as_u64(),
            Some(*case),
            "boundary row for case {case} must sit at the fixture position that marker gates"
        );
        assert_eq!(
            row["test"].as_str(),
            Some(name.as_str()),
            "boundary row for case {case} must name the fn its own marker gates"
        );
        let relative = row["file"].as_str().map_or("", |value| value);
        // (b) reads the COMMENT-STRIPPED production prefix, so a span that
        // survives only inside a production `//` comment cannot satisfy a row.
        let production = strip_line_comments(&production_source(
            &manifest_dir().join(
                relative
                    .strip_prefix("bins/eliot-kernel/")
                    .unwrap_or(relative),
            ),
        ));
        assert!(
            span_is_in_production(span, &production),
            "boundary row for case {case} names span {span}, which is not a complete token in \
             the comment-stripped production source of {relative}"
        );
        // ---------------------------------------------------------------------
        // (d) OWNERSHIP CROSS-CHECK. These four columns are read here for the
        // first time; nothing else in this denominator ever read `function`,
        // `role`, `stage` or `owner_evidence`, so before this a row could name
        // any function, any stage and any role and still pass.
        let function = row["function"].as_str().map_or("", |value| value);
        let role = row["role"].as_str().map_or("", |value| value);
        assert!(
            !function.is_empty()
                && !role.is_empty()
                && row["stage"]
                    .as_str()
                    .is_some_and(|value| !value.trim().is_empty()),
            "boundary row for case {case} must pin a non-empty function, role and stage"
        );
        assert!(
            row["owner_evidence"]
                .as_str()
                .is_some_and(|value| !value.trim().is_empty()),
            "boundary row for case {case} must pin the owner evidence its stage turns on"
        );
        assert!(
            matches!(role, "emitter" | "propagated"),
            "boundary row for case {case} pins role {role}, which is neither emitter nor \
             propagated"
        );
        // The fixture qualifies a method with the type that owns it, so the
        // lookup is on the segment after the last `::`. A row that qualifies a
        // FREE function with a type it does not belong to therefore still has to
        // resolve, and stops resolving the moment that qualification is a lie
        // only if the bare name is checked on its own: this is that check.
        let bare = function.rsplit("::").next().map_or("", |name| name);
        let declared = production_fn_body(&production, bare);
        assert!(
            declared.is_some(),
            "boundary row for case {case} names function {function}, whose bare name {bare} is \
             not declared in {relative}"
        );
        let at_function_scope = declared.is_some_and(|body| span_is_in_production(span, body));
        // An `emitter` whose own body does not carry the span is only honest if
        // it is the observation helper the span is PASSED to, and the row then
        // owes the exact lines it does that on. Both directions are compared, so
        // an invented line fails and an unlisted real one fails.
        let mut declared_sites: Vec<usize> = row["argument_call_sites"]
            .as_array()
            .map_or(&[] as &[Value], |values| values.as_slice())
            .iter()
            .map(|value| value.as_u64().map_or(0, |site| site as usize))
            .collect();
        declared_sites.sort_unstable();
        let mut measured_sites = span_argument_sites(&production, bare, span);
        measured_sites.sort_unstable();
        assert_eq!(
            declared_sites, measured_sites,
            "boundary row for case {case} must list exactly the lines where {bare} is passed \
             span {span} as an argument in {relative}, and no others"
        );
        if role == "emitter" {
            assert!(
                at_function_scope || !measured_sites.is_empty(),
                "boundary row for case {case} declares role emitter for {bare}, but span {span} \
                 is neither inside that function's own body nor passed to it as an argument in \
                 {relative}"
            );
        } else {
            assert!(
                !at_function_scope,
                "boundary row for case {case} declares role propagated for {bare}, but span {span} \
                 is written inside that function's own body in {relative}"
            );
        }
        let body = bodies
            .iter()
            .find_map(|(candidate, body)| (candidate == name).then_some(body.as_str()))
            .unwrap_or_default();
        if !case_reads_span(span, body, &fx) {
            unbound.push(*case);
        }
    }
    assert_eq!(
        unbound,
        vec![10, 16, 19, 29],
        "the disclosed span-binding residue changed: either a row stopped naming a span its own \
         case reads, or a fifth row now does. Repair the map or the case and restate this list; \
         the four rows are the ones whose span their named case provably never reads"
    );
    // Drive one real callsite so the frozen emitter names exist in a capture.
    let (kernel, _guard) = test_kernel();
    let (text, snapshot) = capture_with(|| kernel.generation_route_snapshot());
    assert!(
        snapshot.is_ok(),
        "fresh composition must serve a route read"
    );
    assert_present(
        &text,
        &[
            KERNEL_DIAGNOSTICS_TARGET,
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
        ],
    );
}

// WORK_UNIT_CASE: 903/2
// I14.20:260 generation cutover: "PREPARING → ARMED → COMMITTED → RECONCILING
// → COMPLETED"; a candidate identity is not a validated identity.
// Pins `GenerationRouter::cutover`'s `decision.state() != Committed` refusal
// (crates/kernel/eliot-kernel-core/src/module/generation_routing.rs:379) and the
// recovery pair it decides (`generation_recovery.rs:137` / `:153`).
#[test]
fn candidate_identity_is_not_validated_identity() {
    let fx = fixture();
    let requested = fixture_str(&fx, "/generation/cutover_requested");
    let failed = fixture_str(&fx, "/generation/cutover_failed");
    let terminal = fixture_str(&fx, "/generation/cutover_uncommitted_terminal");
    let staged = "kernel.recovery.cutover_staged";
    let persist_requested = "kernel.recovery.persist_requested";
    let persist_failed = "kernel.recovery.persist_failed";

    let (candidate_kernel, _candidate_guard) = test_kernel();
    let (candidate_text, candidate) =
        capture_with(|| candidate_kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(
        candidate.is_err(),
        "a Preparing candidate must not be applied by the gateway"
    );
    assert_present(
        &candidate_text,
        &[
            requested.as_str(),
            failed.as_str(),
            terminal.as_str(),
            persist_requested,
            persist_failed,
        ],
    );
    assert_absent(&candidate_text, &[staged]);
    // The candidate never reached the ORS staging owner at all: production sets
    // `observations.cutover_staged` only after `stage_generation_cutover`
    // returned Ok (`generation_recovery.rs:451`). Its own refusal is the gateway
    // fence `apply_generation_cutover_inner` records in `generation_poison`
    // (`generation_control.rs:922`) and returns as `KernelServiceError::Platform`,
    // which `generation_cutover_terminal_code` maps to `CUTOVER_PLATFORM`; it is
    // not the handshake-mismatch code the live-state classifier produces, which
    // needs a Committed decision to be reached at all.
    assert_eq!(
        occurrences(&candidate_text, "kernel.terminal_error"),
        1,
        "the refused candidate owns exactly one designated terminal, got: {candidate_text}"
    );
    assert_eq!(
        occurrences(&candidate_text, "CUTOVER_HANDSHAKE_MISMATCH"),
        0,
        "a non-committed candidate is a gateway fence, not a live-state mismatch"
    );
    assert_causal_order(
        &candidate_text,
        &[requested.as_str(), persist_requested, persist_failed],
    );

    // The validated (Committed) identity of the very same switch reaches the
    // ORS staging owner, so the two identities are distinguished by production's
    // own state gate and not by anything this file chose.
    let (validated_kernel, _validated_guard) = test_kernel();
    let (validated_text, validated) = capture_with(|| {
        validated_kernel
            .apply_generation_cutover(&owner_committed_cutover("eliot-903-case2-validated"))
    });
    assert!(
        validated.is_err(),
        "the cutover cannot commit without the owner's durable ORS route row"
    );
    assert_present(&validated_text, &[requested.as_str(), staged]);
    assert_absent(&validated_text, &["kernel.recovery.cutover_committed"]);
}

// WORK_UNIT_CASE: 903/3
// I1.8:18 exact ownership: "No component alone can invent semantics, authorize
// them and commit them." and I14.20:99: "`ACTIVE` requires the exact canonical
// admission receipt, unchanged State Fence and matching Authority Epoch."
// Pins the route-identity lookup production performs in
// `generation_control.rs:714` (a scope it does not own is a typed
// `HandshakeMismatch`, never a substituted route).
// Unreachable slice: `runtime_identity::observed_session_principal_binding` and
// `eliotd_operation_id` are `pub(crate)` and `#[cfg(windows)]`; their
// candidate-vs-validated and invalid/foreign-identity proofs belong to the
// `runtime_identity_diagnostics_tests` inline module in
// `bins/eliot-kernel/src/runtime_identity.rs`.
#[test]
fn invalid_or_foreign_generation_identity_stays_typed() {
    let (kernel, _guard) = test_kernel();
    let (text, unknown_scope) =
        capture_with(|| kernel.active_generation_registry_projection("eliot-903-foreign-scope"));
    match unknown_scope {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_registry.route",
            "a foreign route scope must stay the typed route mismatch"
        ),
        other => panic!("foreign route scope must be refused, got {other:?}"),
    }
    assert_present(&text, &["kernel.generation.snapshot_requested"]);
    // A refusal of the identity never manufactures a projection and never
    // terminalises a second operation.
    assert_absent(
        &text,
        &[
            "kernel.terminal_error",
            "kernel.generation.cutover_committed",
        ],
    );

    // The known scope still answers, so the refusal is about the presented
    // identity and not about a broken gateway.
    let (second_text, known_scope) =
        capture_with(|| kernel.active_generation_registry_projection("daemon"));
    assert!(
        known_scope.is_ok(),
        "the owned route scope must still answer"
    );
    assert_eq!(
        known_scope.expect("projection").route_scope(),
        "daemon",
        "the projection must name production's own route scope"
    );
    assert_present(&second_text, &["kernel.generation.snapshot_committed"]);
}

// WORK_UNIT_CASE: 903/4
// I14.20:265 (truncated at the semicolon, which continues with the
// unresolved-scopes clause): "`COMMITTED` is the ORS linearization point";
// I14.20:27 ORS operation machine: "STAGED → ASSIGNED → APPLYING → RESOLVED".
// Pins `generation_recovery.rs:451` (staged only after the ORS write returned)
// against `:456`-`:459` (committed only after the ORS returned a `Committed`
// snapshot), and `:147`-`:153` (applied and completed are separate phases).
#[test]
fn staged_generation_is_not_committed_generation() {
    let (kernel, _guard) = test_kernel();
    let (text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(&owner_committed_cutover("eliot-903-case4-staged"))
    });
    assert!(outcome.is_err(), "the stale decision must stay refused");
    assert_present(
        &text,
        &[
            "kernel.recovery.persist_requested",
            "kernel.recovery.cutover_staged",
            "kernel.recovery.persist_failed",
        ],
    );
    assert_causal_order(
        &text,
        &[
            "kernel.recovery.persist_requested",
            "kernel.recovery.cutover_staged",
            "kernel.recovery.persist_failed",
        ],
    );
    // Staged is not committed, not applied, not completed and not a handshake
    // projection: every later phase is absent over the WHOLE captured surface.
    assert_absent(
        &text,
        &[
            "kernel.recovery.cutover_committed",
            "kernel.recovery.cutover_applied",
            "kernel.recovery.persist_completed",
            "kernel.recovery.handshake_projected",
            "kernel.recovery.routes_applied",
        ],
    );
}

// WORK_UNIT_CASE: 903/5
// I14.20:248 module generation: "STAGED → STARTING | RETIRED | QUARANTINED" — a
// staged generation is never the active route.
// Pins `generation_recovery.rs:471` (`*generations = candidate` is reached only
// on `Ok`) together with `generation_control.rs:705`-`:729` (the owner's live
// projection reads the router, not the staged record).
#[test]
fn staged_generation_is_never_the_active_route() {
    let (kernel, _guard) = test_kernel();
    let before = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection before the cutover attempt");
    let (text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(&stale_committed_cutover("eliot-903-case5-staged"))
    });
    assert!(outcome.is_err(), "the stale decision must stay refused");
    let after = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection after the refused cutover");
    assert_eq!(
        before.active_generation(),
        after.active_generation(),
        "a refused cutover must not move the owner's active generation"
    );
    assert_eq!(
        before.generation_fingerprint(),
        after.generation_fingerprint(),
        "the owner's fingerprint is derived from the live route, not from the candidate"
    );
    assert_ne!(
        before.active_generation().value(),
        6,
        "the refused candidate generation must never be reported active"
    );
    // The commit absence below reads this capture, so the capture is proved to
    // carry the refused cutover's own request/failure pair FIRST: an empty
    // surface fails here instead of passing the absence vacuously.
    assert_present(
        &text,
        &[
            "kernel.generation.cutover_requested",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_absent(&text, &["kernel.generation.cutover_committed"]);
}

// WORK_UNIT_CASE: 903/6
// I14.20:18: "Process liveness/readiness and capability-generation state remain
// separate." and I1.10:19 (truncated at the semicolon): "A process may be
// alive/READY while its generation is only STAGED or DEGRADED" — the source
// continues "; the two state spaces are never merged into one enum, and route
// switching belongs to the separate `GenerationCutover` machine."
// Pins `control_plane.rs:189`/`:192` (requested versus committed) against the
// owner's own state read at `health_view.rs:243`, which is the only source of
// the view's `service_state` code (`health_view.rs:74`).
#[test]
fn activation_request_is_not_an_observed_activation() {
    let (kernel, _guard) = test_kernel();
    let requested = fixture_str(&fixture(), "/control/transition_requested");
    let (text, outcome) = capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "the readiness probe must stay refused, got {outcome:?}"
    );
    assert_present(&text, &[requested.as_str()]);
    assert_absent(&text, &["kernel.control.transition_committed"]);
    // The owner's own lifecycle state is untouched by the request.
    let (state_text, state) = capture_with(|| kernel.service_state());
    assert!(
        matches!(state, Ok(KernelServiceState::Cold)),
        "a requested transition must not move the owner's lifecycle state, got {state:?}"
    );
    let (view_text, view) = capture_with(|| kernel.activation_operational_view());
    assert_eq!(
        view.service_state, "cold",
        "the derived view must report the owner's state, never a stronger one"
    );
    assert_eq!(
        view.generation, "bound",
        "the generation field is bound/unbound from the live policy generation only"
    );
    assert_present(&view_text, &["kernel.activation.view_projected"]);
    assert_absent(
        &view_text,
        &[
            "kernel.daemon.ready_proven",
            "kernel.control.request_admitted",
        ],
    );
}

// WORK_UNIT_CASE: 903/7
// I14.20:12: "READY | DEGRADED → QUIESCING → STOPPED" — and I14.20:11 keeps
// "READY ↔ DEGRADED" a pair, not a one-way edge; the blueprint/module machines
// keep DRAINING and RETIRED distinct (I14.20:229, `:231`), and I14.24:50 requires
// the old route to stay active until a candidate update commits.
// Pins `control_plane.rs:1570`-`:1574` (the drain observation's outcome IS the
// owner's own `drain_disposition` code from
// `bins/eliot-kernel/src/shutdown_drain.rs:1673`) and `health_view.rs:212`
// (the lifecycle state is the service owner's own read).
#[test]
fn drain_requested_is_not_drained() {
    let (kernel, _guard) = test_kernel();
    let (before_text, before) = capture_with(|| kernel.activation_operational_view());
    assert_eq!(
        before.drain_disposition, "proceed",
        "an undrained composition reports the pre-drain disposition"
    );
    assert_present(&before_text, &["kernel.activation.view_projected"]);

    let (text, _requested) = capture_with(|| kernel.request_shutdown());
    assert!(
        text.contains("kernel.control.drain_requested_observed"),
        "the drain request must be observed, got: {text}"
    );
    let outcome_at = index_of(&text, "kernel.control.drain_requested_observed");
    let recorded = outcome_marker_after(&text, outcome_at);
    let (after_text, after) = capture_with(|| kernel.activation_operational_view());
    assert_eq!(
        recorded, after.drain_disposition,
        "the recorded drain outcome must be the owner's own drain disposition code"
    );
    assert_eq!(
        after.drain_disposition, "draining",
        "the requested drain is reported as draining, never as drained"
    );
    // The two drain-disposition absences below read THIS capture, so it is
    // proved to carry the projected view's own record first: an empty surface
    // fails here instead of passing the absences vacuously.
    assert_present(&after_text, &["kernel.activation.view_projected"]);
    assert_absent(
        &after_text,
        &[
            "terminated-intentional",
            "terminated-incomplete",
            "queue-next-generation",
        ],
    );
    assert_eq!(
        after.service_state, "cold",
        "a requested drain must not advance the owner's lifecycle state"
    );
    assert_eq!(
        before.service_state, after.service_state,
        "requesting a drain must not change the owner's observed state"
    );
}

// WORK_UNIT_CASE: 903/8
// I1.8:22: "Kernel rechecks only properties it owns and binds the
// activation/staging receipt to the same `admission_decision_digest`."
// Pins `classify_generation_cutover_live_endpoint` (`generation_control.rs:587`,
// only a `Committed` decision is classified) and the ORS commit gate
// (`generation_recovery.rs:456`), which is the only place a cutover becomes
// authority.
#[test]
fn cutover_requires_the_owners_committed_receipt() {
    let fx = fixture();
    let requested = fixture_str(&fx, "/generation/cutover_requested");
    let failed = fixture_str(&fx, "/generation/cutover_failed");
    let terminal = fixture_str(&fx, "/generation/cutover_uncommitted_terminal");

    // Candidate leg: no owner receipt at all, so the gateway fences.
    let (candidate_kernel, _candidate_guard) = test_kernel();
    let (candidate_text, candidate) =
        capture_with(|| candidate_kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(
        matches!(candidate, Err(KernelServiceError::Platform(_))),
        "a candidate cutover is refused as a gateway failure, got {candidate:?}"
    );
    assert_present(
        &candidate_text,
        &[requested.as_str(), failed.as_str(), terminal.as_str()],
    );
    assert!(
        occurrences(&candidate_text, "kernel.terminal_error") == 1,
        "the refused cutover owns exactly one terminal record, got: {candidate_text}"
    );

    // Committed-leg leg: a committed decision whose prior generation the owner
    // never had is still refused, and it is refused TYPED (not fenced), so the
    // gateway keeps answering afterwards.
    let (committed_kernel, _committed_guard) = test_kernel();
    let (committed_text, committed) = capture_with(|| {
        committed_kernel
            .apply_generation_cutover(&stale_committed_cutover("eliot-903-case8-committed"))
    });
    match committed {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_cutover.live_state",
            "the owner's live route state must decide the refusal"
        ),
        other => panic!("a non-owner committed cutover must be refused, got {other:?}"),
    }
    assert_present(
        &committed_text,
        &[
            requested.as_str(),
            failed.as_str(),
            "CUTOVER_HANDSHAKE_MISMATCH",
        ],
    );
    assert_absent(
        &committed_text,
        &[
            "kernel.recovery.cutover_committed",
            "kernel.generation.cutover_committed",
        ],
    );
    let (still_text, still) = capture_with(|| committed_kernel.generation_route_snapshot());
    assert!(
        still.is_ok(),
        "a typed refusal must not fence the generation gateway, got {still:?}"
    );
    assert_present(&still_text, &["kernel.generation.snapshot_committed"]);
}

// WORK_UNIT_CASE: 903/9
// I14.20:275: "A failed candidate never inherits the old Kernel epoch, and
// restore never revives an activation record as current authority"; I14.20:81:
// "`REOPENED` is a new lifecycle revision, not a rewrite of the prior
// `FinishDecision`."
// Pins `generation_control.rs:687`-`:691` (the projection's fence must equal the
// authenticated live fence) and `:723` (the route epoch must be the same
// authority tuple as the live service epoch).
#[test]
fn old_generation_cannot_be_current_after_cutover() {
    let (kernel, _guard) = test_kernel();
    let projection = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection");
    assert_eq!(
        projection.active_generation(),
        ResourceGeneration::genesis(),
        "the owner's active route is the genesis generation until a cutover commits"
    );
    assert_eq!(
        projection.state_fence(),
        &live_fence(),
        "the projection's fence is the owner's live fence, not a candidate's"
    );
    // The refused candidate's prior generation was never the active one, so the
    // owner's own answer is unchanged by the attempt.
    let (text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(&stale_committed_cutover("eliot-903-case9-old"))
    });
    assert!(outcome.is_err(), "the stale decision must stay refused");
    let (read_text, after) =
        capture_with(|| kernel.active_generation_registry_projection("daemon"));
    assert!(
        after.is_ok(),
        "the owner must still answer after the refusal"
    );
    let after = after.expect("projection");
    assert_eq!(
        after.active_generation(),
        projection.active_generation(),
        "the active generation must not move under a refused cutover"
    );
    assert_eq!(
        after.state_fence(),
        &live_fence(),
        "the live fence must not adopt the refused cutover's epochs"
    );
    // The commit absence below reads THIS capture, so it is proved to carry the
    // refused cutover's own request/failure pair FIRST: an empty surface fails
    // here instead of passing the absence vacuously.
    assert_present(
        &text,
        &[
            "kernel.generation.cutover_requested",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_absent(&text, &["kernel.generation.cutover_committed"]);
    assert_present(&read_text, &["kernel.generation.snapshot_committed"]);
}

// WORK_UNIT_CASE: 903/10
// I14.20:265: "Rollback is never a backward state transition. It is a new cutover
// with a newer Authority Epoch"; I1.8:34: "Session exists only while transport
// identity and semantic Session refer to the same State Fence/epoch."
// Pins the exact-tuple epoch bridge at `generation_recovery.rs:464`-`:467`
// (`synchronize_authority_epoch(decision.new_epoch())`) by proving the refused
// cutover advanced NEITHER the router epoch NOR the live service epoch, and by
// proving production's own same-authority comparison still holds afterwards
// (`generation_control.rs:723`).
#[test]
fn old_and_new_authority_epochs_are_both_preserved() {
    let (kernel, _guard) = test_kernel();
    let before = kernel.generation_route_snapshot().expect("route snapshot");
    assert!(
        before.epoch().is_same_authority(&test_epoch(1)),
        "the standalone composition starts on the canonical lineage at sequence 1"
    );
    let (text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(&stale_committed_cutover("eliot-903-case10-epoch"))
    });
    assert!(outcome.is_err(), "the stale decision must stay refused");
    let after = kernel.generation_route_snapshot().expect("route snapshot");
    assert!(
        after.epoch().is_same_authority(&test_epoch(1)),
        "the router epoch must be the OLD exact tuple: the refused cutover's new epoch is not authority"
    );
    assert!(
        !after.epoch().is_same_authority(&test_epoch(2)),
        "the refused cutover's new epoch must never become the router's active epoch"
    );
    assert_eq!(
        after.epoch().lineage_id,
        before.epoch().lineage_id,
        "a cutover never mints a lineage (I14.20)"
    );
    let projection = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection");
    assert!(
        projection
            .authority_epoch()
            .is_same_authority(&test_epoch(1)),
        "the owner's live epoch must still be the old exact tuple"
    );
    // Neither epoch tuple is ever rendered into a diagnostic record. The
    // capture is proved to carry the refused cutover's own request/failure pair
    // FIRST, so an empty surface fails here instead of passing the epoch
    // absences vacuously.
    assert_present(
        &text,
        &[
            "kernel.generation.cutover_requested",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_absent(&text, &["550e8400-e29b-41d4-a716", "epoch="]);
}

// WORK_UNIT_CASE: 903/11
// I14.24:7 (elided at the containment cell): "Kernel crash … fences its epoch
// and permits no new Session/write/lease/Material authority" — condensed from
// the row "| Kernel crash | Host closes the failed Kernel Job Object lineage,
// fences its epoch and permits no new Session/write/lease/Material authority |"
// (truncated at the row end); the fence is the owner's, not the log's.
// Pins `ServiceFenceObservation::emit_for_cutover` (`generation_control.rs:629`)
// and its call site at `:945`, which runs only after `drop(poison)` at `:941`.
#[test]
fn old_and_new_fences_are_both_preserved() {
    let cutover_id = "eliot-903-case11-fence";
    let (kernel, _guard) = test_kernel();
    let decision = CutoverDecision::new(
        cutover_id,
        daemon_scope(),
        Some(ResourceGeneration::new(1).expect("old generation")),
        ResourceGeneration::new(2).expect("new generation"),
        test_epoch(1),
        test_epoch(2),
        GenerationCutoverState::Preparing,
    )
    .expect("candidate cutover decision");
    let (text, outcome) = capture_with(|| kernel.apply_generation_cutover(&decision));
    assert!(outcome.is_err(), "the candidate cutover must be refused");
    assert_present(
        &text,
        &[
            "kernel.generation.service_fence_requested",
            "kernel.generation.service_fenced",
        ],
    );
    assert_causal_order(
        &text,
        &[
            "kernel.generation.cutover_requested",
            "kernel.recovery.persist_requested",
            "kernel.generation.service_fence_requested",
            "kernel.generation.service_fenced",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_eq!(
        occurrences(&text, "kernel.generation.service_fence_requested"),
        1,
        "the subordinate fence pair is emitted once per cutover"
    );
    assert_eq!(
        occurrences(&text, "kernel.generation.service_fenced"),
        1,
        "the subordinate fence pair is emitted once per cutover"
    );
    assert_absent(&text, &["kernel.generation.service_fence_rejected"]);
    // The fence is correlated to the cutover's own operation identity and to
    // nothing else; the old fence's reason body never crosses the boundary.
    assert!(
        text.contains(cutover_id),
        "the fence pair must carry the cutover's own validated operation identity"
    );
    assert_eq!(
        occurrences(&text, "kernel.terminal_error"),
        1,
        "the failed cutover keeps exactly one designated terminal"
    );
    assert!(text.contains("CUTOVER_PLATFORM"), "the cutover's own code");
    // The fenced gateway now refuses reads with its OWN distinct code, proving
    // the two terminals are not the same record re-emitted.
    let (read_text, read) = capture_with(|| kernel.generation_route_snapshot());
    assert!(read.is_err(), "the fenced gateway must refuse route reads");
    assert_present(&read_text, &["kernel.generation.snapshot_failed"]);
    assert!(
        read_text.contains("SNAPSHOT_PLATFORM"),
        "the read's own code"
    );
}

// WORK_UNIT_CASE: 903/12
// I14.20:99: "`ACTIVE` requires the exact canonical admission receipt,
// unchanged State Fence and matching Authority Epoch."
// Pins the two exact comparisons production performs in
// `generation_control.rs:744` (admitted fence) and `:749` (fingerprint), and
// shows they stay DISTINCT typed refusals rather than collapsing.
// Unreachable slice: the authenticated ingress arms of
// `apply_authenticated_generation_cutover` (`generation_control.rs:1024`, `:1101`,
// `:1112`) are not nameable outside the crate because `generation_control` is a
// private module; their live-path proof belongs to `generation_control::tests`.
#[test]
fn stale_or_foreign_fence_stays_typed() {
    let (kernel, _guard) = test_kernel();
    let projection = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection");

    // A stale fence (the owner's generation at a superseded epoch) is refused by
    // the admitted-fence comparison alone.
    let stale = StateFence::new(
        test_epoch(1),
        ResourceGeneration::new(5).expect("stale generation"),
    );
    let (stale_text, stale_outcome) = capture_with(|| {
        kernel.verify_active_generation_registry_fingerprint(
            "daemon",
            &stale,
            projection.generation_fingerprint(),
        )
    });
    match stale_outcome {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_registry.admitted_fence",
            "a stale fence must stay the typed admitted-fence refusal"
        ),
        other => panic!("a stale fence must be refused, got {other:?}"),
    }
    // The terminal absence below reads THIS capture, so it is proved to carry
    // the projection read it actually drove FIRST: this seam calls
    // `active_generation_registry_projection`, which emits the route snapshot
    // pair through `generation_control.rs:765`/`:768` before the admitted-fence
    // comparison it refused. An empty surface fails here instead of passing the
    // terminal absence vacuously.
    assert_present(
        &stale_text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
        ],
    );
    assert_absent(&stale_text, &["kernel.terminal_error"]);

    // The exact fence with a foreign payload is refused by the fingerprint
    // comparison alone: a different typed field, not the same one.
    let (foreign_text, foreign_outcome) = capture_with(|| {
        kernel.verify_active_generation_registry_fingerprint(
            "daemon",
            projection.state_fence(),
            "e".repeat(64).as_str(),
        )
    });
    match foreign_outcome {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_registry.fingerprint",
            "a changed payload must stay the typed fingerprint refusal"
        ),
        other => panic!("a foreign fingerprint must be refused, got {other:?}"),
    }
    // Same rule on this capture: the route snapshot pair the same seam emitted
    // is asserted FIRST, so an empty surface fails on presence before the
    // terminal absence is evaluated.
    assert_present(
        &foreign_text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
        ],
    );
    assert_absent(&foreign_text, &["kernel.terminal_error"]);

    // The exact fence and the exact fingerprint still verify, so neither refusal
    // above was a broken gateway.
    assert!(
        kernel
            .verify_active_generation_registry_fingerprint(
                "daemon",
                projection.state_fence(),
                projection.generation_fingerprint(),
            )
            .is_ok(),
        "the owner's exact fence and fingerprint must verify"
    );
}

// WORK_UNIT_CASE: 903/13
// I14.3:29: "Reserve accounting is multidimensional. Admission checks the exact
// bottleneck vector rather than one scalar percentage" and I14.3:27: "Normal
// workload cannot consume it."
// Pins `control_plane.rs:1547`-`:1553`: the reserve observation is a READ of
// `available_capacity(ExecutionClass::ProtectedControl)` that never acquires,
// releases or resizes anything, and `control_plane.rs:273` — an admitted request
// is a different record from a request received.
// Unreachable slice: `kernel.control.request_received` / `request_admitted` /
// `request_denied` are emitted only from the `pub async`
// `apply_control_request`, whose request needs the full authenticated
// `HostKernelCandidateBinding` contour; its admitted/denied proof belongs to the
// `control_plane_diagnostics_tests` inline module in
// `bins/eliot-kernel/src/control_plane.rs`.
#[test]
fn control_request_is_not_reserve_admission() {
    let fx = fixture();
    let capacity_event = "kernel.control.capacity_observed";
    let (kernel, _guard) = test_kernel();
    let (before_text, before) = capture_with(|| kernel.control_capacity());
    assert_present(&before_text, &[capacity_event]);
    assert_eq!(
        occurrences(&before_text, capacity_event),
        1,
        "one reserve read emits exactly one capacity record"
    );

    // A requested control transition changes nothing about the reserve.
    let (transition_text, outcome) =
        capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "the transition must stay refused, got {outcome:?}"
    );
    assert_present(
        &transition_text,
        &[
            fixture_str(&fx, "/control/transition_requested").as_str(),
            fixture_str(&fx, "/control/transition_failed").as_str(),
        ],
    );
    let (after_text, after) = capture_with(|| kernel.control_capacity());
    assert_eq!(
        before, after,
        "observing or requesting control must not acquire, release or resize the reserve"
    );
    assert_absent(&transition_text, &["kernel.control.request_admitted"]);
    // The reserve-read absence below reads THIS capture, so it is proved to
    // carry the second reserve read's own capacity record FIRST: an empty
    // surface fails here instead of passing the absence vacuously.
    assert_present(&after_text, &[capacity_event]);
    assert_absent(&after_text, &["kernel.control.request_admitted"]);
}

// WORK_UNIT_CASE: 903/14
// I14.3:3: "Capacity reserved independently at every applicable bottleneck:" and
// I14.3:27: "Normal workload cannot consume it." — the reserve is a closed
// accounting scope, so observing it can never move work into it.
// Pins `control_plane.rs:116`-`:126`: `observe_control_capacity` carries a
// bounded count and a fixed event name and nothing else, so no diagnostic record
// can carry an admission class. Any number of reads leaves the owner's own
// admission verdict byte-identical.
#[test]
fn diagnostics_cannot_promote_normal_work_to_protected_control() {
    let capacity_event = "kernel.control.capacity_observed";
    let (kernel, _guard) = test_kernel();
    let (first_text, first) = capture_with(|| kernel.control_capacity());
    let (many_text, many) = capture_with(|| {
        let mut last = 0usize;
        for _ in 0..8 {
            last = kernel.control_capacity();
        }
        last
    });
    assert_eq!(
        first, many,
        "the observed protected capacity must not change because it was observed"
    );
    assert_eq!(
        occurrences(&first_text, capacity_event),
        1,
        "each read emits one bounded count, never a class or a promotion"
    );
    assert_eq!(
        occurrences(&many_text, capacity_event),
        8,
        "each read emits exactly one bounded count"
    );
    // The whole captured surface carries no class, no priority and no promotion.
    for forbidden in ["protected", "promot", "priority", "class="] {
        assert_absent(&many_text, &[forbidden]);
    }
    // The owner's own admission verdict for a normal command is unchanged.
    let (text, outcome) = capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "diagnostics must not admit a normal command into the protected class, got {outcome:?}"
    );
    // The commit absence below reads THIS capture, so it is proved to carry the
    // refused transition's own requested/failed pair FIRST
    // (`control_plane.rs:189`/`:200`): an empty surface fails here instead of
    // passing the absence vacuously.
    assert_present(
        &text,
        &[
            "kernel.control.transition_requested",
            "kernel.control.transition_failed",
        ],
    );
    assert_absent(&text, &["kernel.control.transition_committed"]);
}

// WORK_UNIT_CASE: 903/15
// I14.3:29: "Each disposition names the exhausted resource and the work shed,
// deferred or quarantined" — the reserve lifecycle vocabulary is closed and
// each member stays distinct.
// Pins the reachable reserve terminal (`control_plane.rs:52`-`:66`) and shows
// the exhausted/admission-closed codes are neither emitted nor confusable with
// it. Unreachable slice: actually exhausting the protected reserve and driving
// `AdmissionClosed` needs the real runtime reserve owner; the mapping table's
// exhausted/closed arms are proven by `control_plane_diagnostics_tests`.
#[test]
fn reserve_lifecycle_vocabulary_stays_distinct() {
    let fx = fixture();
    let emitted = fixture_str(&fx, "/control/probe_ready_terminal");
    let exhausted = fixture_str(&fx, "/refusal_codes/control_reserve_exhausted");
    let closed = fixture_str(&fx, "/refusal_codes/control_admission_closed");
    let capacity_event = "kernel.control.capacity_observed";

    let (kernel, _guard) = test_kernel();
    let (capacity_text, _capacity) = capture_with(|| kernel.control_capacity());
    assert_present(&capacity_text, &[capacity_event]);
    let (text, outcome) = capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "the transition must stay refused, got {outcome:?}"
    );
    assert_eq!(
        occurrences(&text, "kernel.terminal_error"),
        1,
        "one refused transition carries one terminal record"
    );
    assert!(
        text.contains(&emitted),
        "the readiness refusal owns {emitted}"
    );
    // Exhaustion and admission closure are distinct members of the same closed
    // vocabulary; neither is reachable from this surface, and neither is
    // substituted for the readiness refusal.
    // FIXTURE GUARD, NOT PRODUCTION EVIDENCE, and the distinction matters: these
    // three operands are values this file's own fixture supplies, so no
    // production input reaches them. They are kept because the two assertions
    // below bind `emitted`, `exhausted` and `closed` POSITIONALLY to one
    // production capture (:2109 asserts production carries `emitted`, :2118
    // asserts production carries neither of the others), and a fixture that
    // collapsed two of its three codes would silently retarget both bindings.
    assert_ne!(emitted, exhausted);
    assert_ne!(emitted, closed);
    assert_ne!(exhausted, closed);
    assert_absent(&text, &[exhausted.as_str(), closed.as_str()]);
    // Admission, consumption, release and expiry are separate owner events, so
    // the reserve axis this seam reaches is exactly one read and nothing else.
    assert_eq!(
        occurrences(&capacity_text, capacity_event),
        1,
        "a reserve read is one observation, never an admitted/consumed/released/expired claim"
    );
    for forbidden in ["admitted", "consumed", "released", "expired"] {
        assert_absent(&capacity_text, &[forbidden]);
    }
}

// WORK_UNIT_CASE: 903/16
// I14.3:29: "exhaustion of CPU, memory, pipe bytes, ORS writes, disk queue or
// handles may independently close normal/background admission while preserving
// the applicable recovery/control lane."
// Pins `control_plane.rs:199`-`:208` (a refused transition emits a record and a
// terminal and returns the typed error; it never mutates the service state or
// the generation gateway) against `health_view.rs:212` and
// `generation_control.rs:783`.
#[test]
fn reserve_degradation_is_not_total_kernel_failure() {
    let fx = fixture();
    let refused = fixture_str(&fx, "/control/probe_ready_terminal");
    let (kernel, _guard) = test_kernel();
    let (text, outcome) = capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(
        matches!(outcome, Err(KernelServiceError::ReadinessNotProven)),
        "the control lane is degraded, not repaired, got {outcome:?}"
    );
    assert!(
        text.contains(&refused),
        "the refusal keeps its own stable code"
    );
    // A degraded control lane is not a whole-Kernel failure: the service state
    // and the generation gateway keep answering, and no core/platform code is
    // substituted for the control code.
    let (state_text, state) = capture_with(|| kernel.service_state());
    assert!(
        matches!(state, Ok(KernelServiceState::Cold)),
        "a refused control transition must not fail the service, got {state:?}"
    );
    // The omission absence below reads THIS capture, so the readable leg's own
    // observed record is asserted FIRST (`health_view.rs:214`): an empty surface
    // fails here instead of passing the absence vacuously. The two arms are the
    // only two this seam can take, so a present observed record is exactly the
    // disproof of an empty capture.
    assert_present(&state_text, &["kernel.health.service_state_observed"]);
    assert_absent(&state_text, &["kernel.health.service_state_omitted"]);
    let (route_text, route) = capture_with(|| kernel.generation_route_snapshot());
    assert!(route.is_ok(), "the generation gateway keeps serving");
    assert_present(&route_text, &["kernel.generation.snapshot_committed"]);
    for total_failure in ["CONTROL_CORE", "CONTROL_PLATFORM", "SNAPSHOT_PLATFORM"] {
        assert_absent(&text, &[total_failure]);
    }
}

// WORK_UNIT_CASE: 903/17
// I14.3:31: "`Last-resort Control Slot` is preallocated outside normal
// accounting for reserve-exhaustion/gap record. If unavailable, system enters
// platform/manual recovery boundary"; I14.20:18:
// "Process liveness/readiness and capability-generation state remain separate."
// Pins the fenced gateway's own terminal (`generation_control.rs:772`-`:775`)
// against the daemon readiness refusals at `daemon_runtime.rs:2199`/`:2204`, so
// an exhausted generation lane is visible without any readiness being invented.
#[test]
fn reserve_exhaustion_is_visible_without_fabricated_readiness() {
    let fx = fixture();
    let fenced = fixture_str(&fx, "/refusal_codes/snapshot_platform");
    let (kernel, _guard) = test_kernel();
    let (cutover_text, cutover) =
        capture_with(|| kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(cutover.is_err(), "the candidate cutover must be refused");
    assert_present(&cutover_text, &["kernel.generation.service_fenced"]);

    // The exhaustion is visible on the read boundary that actually hit it.
    let (text, read) = capture_with(|| kernel.generation_route_snapshot());
    assert!(read.is_err(), "the fenced gateway must refuse route reads");
    assert_eq!(
        occurrences(&text, "kernel.terminal_error"),
        1,
        "one refused read carries one terminal record"
    );
    assert!(text.contains(&fenced), "the read's own stable code");
    assert_absent(&text, &["kernel.generation.snapshot_committed"]);

    // No readiness is fabricated anywhere on the exhausted composition.
    assert!(
        !kernel.daemon_ready(),
        "a fenced lane is not daemon readiness"
    );
    let (ready_text, ready) = capture_with(|| kernel.mark_daemon_ready());
    assert!(
        matches!(ready, Err(KernelServiceError::ReadinessNotProven)),
        "readiness must stay unproven, got {ready:?}"
    );
    assert_present(&ready_text, &["kernel.daemon.ready_reported"]);
    // Each absence below is read on the capture whose OWN operation is the only
    // reachable emitter of its token, so neither is true by construction.
    // `daemon_runtime.rs:2215` is the sole `kernel.daemon.ready_proven` site and
    // is gated on a launched receipt plus a `Running` status this exhausted
    // composition never has, so the refusal recorded at `:2206` is precisely the
    // claim this scan now tests.
    assert_absent(&ready_text, &["kernel.daemon.ready_proven"]);
    // `kernel.generation.cutover_committed` is emitted only from
    // `apply_generation_cutover` (`generation_control.rs:813`), so it is scanned
    // on the cutover capture — already proved non-empty by the fence record
    // asserted above — and never on the route read, which cannot emit it.
    assert_absent(&cutover_text, &["kernel.generation.cutover_committed"]);
    // `kernel.control.request_admitted` is deliberately NOT scanned in this case,
    // and that is a binding decision, not an oversight. Its only site
    // (`control_plane.rs:273`) sits inside `pub async fn apply_control_request`,
    // which needs a `PeerIdentity` and the full authenticated
    // `HostKernelCandidateBinding` contour; case 903/17 drives no control request
    // at all, so the absence would hold on all three of its captures by
    // construction and would prove nothing. It is disclosed as an unreachable
    // slice in case 903/13 and is absence-checked there, on control captures
    // that do record a transition of their own.
}

// WORK_UNIT_CASE: 903/18
// I14.20:8-`:9` service process machine (two separate rows, elided at the row
// break): "STOPPED → STARTING" and "STARTING → RECOVERING | READY"; and
// I14.20:18: "Process liveness/readiness and capability-generation state remain
// separate."
// Pins `daemon_runtime.rs:485`-`:492` (contour presence only) and `:507`-`:511`
// (the readiness predicate `daemon_status_proves_ready` at `:510` is the only
// one production consults), plus the typed refusal at `:2199`/`:2204`.
// Deferred slice (card DEFER): the `Ready`/`Running`/`Degraded`/`Failed`
// rendezvous outcomes of `await_daemon_ready` need a live `#[cfg(windows)]`
// launch receipt and belong to the `daemon_manifest_restart_admission_tests`
// inline module.
#[test]
fn daemon_lifecycle_states_stay_distinct() {
    let (kernel, _guard) = test_kernel();
    let (contour_text, contour) = capture_with(|| kernel.daemon_launch());
    assert!(
        contour.is_none(),
        "a standalone composition carries no approved daemon contour"
    );
    assert_present(&contour_text, &["kernel.daemon.contour_observed", "absent"]);
    assert_absent(&contour_text, &["present"]);

    // The readiness predicate itself records nothing: a liveness read is not a
    // lifecycle observation.
    let (liveness_text, liveness) = capture_with(|| kernel.daemon_ready());
    assert!(!liveness, "no launched process can be semantically ready");
    assert!(
        liveness_text.trim().is_empty(),
        "the readiness predicate emits no record at all, got: {liveness_text}"
    );

    let (ready_text, ready) = capture_with(|| kernel.mark_daemon_ready());
    assert!(
        matches!(ready, Err(KernelServiceError::ReadinessNotProven)),
        "a ready report without a receipt must stay unproven, got {ready:?}"
    );
    assert_present(&ready_text, &["kernel.daemon.ready_reported"]);
    assert_absent(
        &ready_text,
        &["kernel.daemon.ready_proven", "already_ready", "success"],
    );
}

// WORK_UNIT_CASE: 903/19
// I1.10:17: "A component is `READY` only for the capabilities whose required
// dimensions pass"; I14.20:18: "Process liveness/readiness and
// capability-generation state remain separate."
// Pins `daemon_runtime.rs:510` — `daemon_ready` reads
// `daemon_status_proves_ready(&state.status)`, and a composition with no
// launched receipt can never satisfy it, so no observation may report readiness.
#[test]
fn daemon_liveness_is_not_semantic_readiness() {
    let (kernel, _guard) = test_kernel();
    let (liveness_text, liveness) = capture_with(|| kernel.daemon_ready());
    assert!(!liveness, "liveness without a receipt is not readiness");
    let (state_text, state) = capture_with(|| kernel.service_state());
    assert!(
        matches!(state, Ok(KernelServiceState::Cold)),
        "the Kernel service itself is Cold, never Ready, got {state:?}"
    );
    let (view_text, view) = capture_with(|| kernel.activation_operational_view());
    assert_ne!(
        view.service_state, "ready",
        "the derived view must not report readiness the owner never reached"
    );
    assert_eq!(
        view.governance, "unsupervised",
        "governance is derived from the observed census, never assumed"
    );
    // The two readable surfaces are proved non-empty BEFORE they are scanned, so an
    // empty capture fails on presence instead of passing the absences vacuously:
    // `service_state()` always takes one of its two arms (`health_view.rs:207`
    // omitted / `:214` observed) and `activation_operational_view()` always
    // records its projection (`health_view.rs:244`/`:253`/`:267`).
    assert_present(&state_text, &["kernel.health.service_state_observed"]);
    assert_present(&view_text, &["kernel.activation.view_projected"]);
    // DISCLOSED, not repaired: the `liveness_text` absence below is vacuous BY
    // CONSTRUCTION. `daemon_ready()` is a pure predicate (`daemon_runtime.rs:510`)
    // that deliberately emits NO record, so that capture is legitimately EMPTY and
    // no honest positive can exist for it — any positive written here would be
    // fabricated. Case 903/18 pins the emptiness directly and non-vacuously
    // (`liveness_text.trim().is_empty()` IS that case's proposition, not a scan),
    // so this leg is retained only as a whole-surface cross-check beside the two
    // surfaces this test has just proved non-empty.
    for forbidden in [
        "kernel.daemon.ready_proven",
        "kernel.daemon.await_satisfied",
        "kernel.daemon.recovery_committed",
    ] {
        assert_absent(&liveness_text, &[forbidden]);
        assert_absent(&state_text, &[forbidden]);
        assert_absent(&view_text, &[forbidden]);
    }
}

// WORK_UNIT_CASE: 903/20
// I14.21:6-`:8` unknown-commit recovery (elided at the row breaks): "if
// committed → reconcile ORS; if known rollback → retry under same identity; if
// unknown → pause Ordering Scope".
// Pins the five distinct recovery phase records production emits from five
// distinct sites: `generation_recovery.rs:293` (`recover_requested`), `:313`
// (`cutovers_reconciled`), `:318` (`cutovers_loaded`), `:320` (`load_empty`) and
// `:296` (`recover_completed`), driven through the real composition build that
// calls `recover` at `composition_bootstrap.rs:1922`. Unreachable slice:
// `cutovers_validated` (`generation_recovery.rs:341`) and `routes_applied`
// (`:397`) need a non-empty ORS cutover set, which the composition does not
// expose; that slice belongs to `generation_recovery_diagnostics_tests`.
#[test]
fn recovery_phases_stay_distinct() {
    let (text, _kernel, _guard) = build_kernel_captured("case20-recovery");
    assert_present(
        &text,
        &[
            "kernel.recovery.recover_requested",
            "kernel.recovery.cutovers_reconciled",
            "kernel.recovery.cutovers_loaded",
            "kernel.recovery.load_empty",
            "kernel.recovery.recover_completed",
            "kernel.recovery.cutover_ownership_requested",
        ],
    );
    assert_causal_order(
        &text,
        &[
            "kernel.recovery.recover_requested",
            "kernel.recovery.cutovers_reconciled",
            "kernel.recovery.cutovers_loaded",
            "kernel.recovery.load_empty",
            "kernel.recovery.recover_completed",
            "kernel.recovery.cutover_ownership_requested",
        ],
    );
    // Requested, load and completed are separate facts: an empty durable set is
    // reported as its own phase and never as a success it did not reach.
    assert_absent(
        &text,
        &[
            "kernel.recovery.recover_failed",
            "kernel.recovery.routes_applied",
        ],
    );
    for phase in [
        "kernel.recovery.recover_requested",
        "kernel.recovery.cutovers_reconciled",
        "kernel.recovery.cutovers_loaded",
        "kernel.recovery.load_empty",
        "kernel.recovery.recover_completed",
    ] {
        assert_eq!(
            occurrences(&text, phase),
            1,
            "each recovery phase is recorded exactly once per replay: {phase}"
        );
    }
}

// WORK_UNIT_CASE: 903/21
// I14.21:8-`:9` (elided at the row break, which drops "Human/Doctor chooses
// evidence-backed reconciliation; "): "if unknown → pause Ordering Scope,
// preserve operation and open Problem State … no blind duplicate effect."
// Pins `generation_control.rs:833`-`:843`: a cutover that is not provably applied
// records `cutover_failed` plus ONE terminal and never a commit claim, and
// logging never repairs it.
#[test]
fn unknown_commit_outcome_is_never_repaired_by_diagnostics() {
    let (kernel, _guard) = test_kernel();
    let (text, outcome) = capture_with(|| kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(
        outcome.is_err(),
        "the possible-but-unproven cutover stays unknown"
    );
    assert_present(&text, &["kernel.generation.cutover_failed"]);
    assert_eq!(
        occurrences(&text, "kernel.terminal_error"),
        1,
        "an unknown outcome carries exactly one designated terminal"
    );
    // The whole captured surface carries no commit, applied or success claim for
    // this operation — not one record, not a differently-named helper's record.
    for claim in [
        "kernel.generation.cutover_committed",
        "kernel.recovery.cutover_committed",
        "kernel.recovery.cutover_applied",
        "kernel.recovery.persist_completed",
        "kernel.recovery.handshake_projected",
    ] {
        assert_absent(&text, &[claim]);
    }
    // The gateway is fenced rather than repaired, and the fence is the owner's.
    let (read_text, read) = capture_with(|| kernel.generation_route_snapshot());
    assert!(read.is_err(), "an unproven cutover fences the gateway");
    // The commit absence below reads THIS capture, so the fenced read's own
    // requested/failed pair is asserted FIRST (`generation_control.rs:765`/`:772`):
    // an empty surface fails here instead of passing the absence vacuously.
    assert_present(
        &read_text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_failed",
        ],
    );
    assert_absent(&read_text, &["kernel.generation.snapshot_committed"]);
}

// WORK_UNIT_CASE: 903/22
// I14.21:5: "Kernel queries WriteReceipt by idempotency key" — an exact replay is
// a readback, never a second transition.
// Pins `classify_generation_cutover_live_endpoint` (`generation_control.rs:582`)
// reached from `apply_generation_cutover_inner` (`:851`): the replay of one exact
// decision is classified against the live state and refused identically, with no
// new commit record, no new terminal code and no moved route.
#[test]
fn cutover_replay_is_readback_not_a_second_transition() {
    let decision = stale_committed_cutover("eliot-903-case22-replay");
    let (kernel, _guard) = test_kernel();
    let route_before = kernel.generation_route_snapshot().expect("route snapshot");
    let (first_text, first) = capture_with(|| kernel.apply_generation_cutover(&decision));
    assert!(matches!(
        first,
        Err(KernelServiceError::HandshakeMismatch { .. })
    ));
    let (second_text, second) = capture_with(|| kernel.apply_generation_cutover(&decision));
    match (&first, &second) {
        (
            Err(KernelServiceError::HandshakeMismatch { field: first_field }),
            Err(KernelServiceError::HandshakeMismatch {
                field: second_field,
            }),
        ) => assert_eq!(
            first_field, second_field,
            "an exact replay must answer the identical typed refusal"
        ),
        other => panic!("an exact replay must be refused identically, got {other:?}"),
    }
    // Each attempt is one request, one failure and one terminal — the replay
    // adds no transition claim of any kind.
    for text in [&first_text, &second_text] {
        assert_eq!(
            occurrences(text, "kernel.generation.cutover_requested"),
            1,
            "one request record per attempt"
        );
        assert_eq!(
            occurrences(text, "kernel.generation.cutover_failed"),
            1,
            "one failure record per attempt"
        );
        assert_eq!(
            occurrences(text, "kernel.terminal_error"),
            1,
            "exactly one designated terminal per refused attempt"
        );
        assert_absent(
            text,
            &[
                "kernel.generation.cutover_committed",
                "kernel.recovery.cutover_committed",
                "kernel.recovery.persist_completed",
            ],
        );
    }
    assert_eq!(
        occurrences(&first_text, "CUTOVER_HANDSHAKE_MISMATCH"),
        1,
        "the replay's code is the same stable code, not a new one"
    );
    let route_after = kernel.generation_route_snapshot().expect("route snapshot");
    assert_eq!(
        route_after.epoch().sequence.get(),
        route_before.epoch().sequence.get(),
        "a replay must not advance the router epoch"
    );
    let scope = daemon_scope();
    assert_eq!(
        route_after
            .route(&scope)
            .expect("daemon route")
            .active_generation(),
        route_before
            .route(&scope)
            .expect("daemon route")
            .active_generation(),
        "a replay must not move the active generation"
    );
}

// WORK_UNIT_CASE: 903/23
// I1.8:22: "A digest, source-revision or mutation-plan mismatch returns
// `TRANSITION_DIGEST_MISMATCH`/conflict and never retries as the same decision."
// Pins `generation_control.rs:749` (fingerprint mismatch) and `:881`-`:886`
// (live-state mismatch): a changed payload under one operation identity stays a
// typed conflict and is never applied as the same decision.
#[test]
fn changed_payload_for_one_operation_stays_a_conflict() {
    let (kernel, _guard) = test_kernel();
    let projection = kernel
        .active_generation_registry_projection("daemon")
        .expect("owner projection");
    let (text, conflict) = capture_with(|| {
        kernel.verify_active_generation_registry_fingerprint(
            "daemon",
            projection.state_fence(),
            "0".repeat(64).as_str(),
        )
    });
    match conflict {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_registry.fingerprint",
            "a changed payload must stay a typed conflict"
        ),
        other => panic!("a changed payload must be refused, got {other:?}"),
    }
    // Both absences below read THIS capture, so the route snapshot pair its own
    // seam emitted is asserted FIRST (`generation_control.rs:765`/`:768`): an
    // empty surface fails here instead of passing the absences vacuously.
    assert_present(
        &text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
        ],
    );
    assert_absent(
        &text,
        &[
            "kernel.terminal_error",
            "kernel.generation.cutover_committed",
        ],
    );

    // The same cutover identity carrying a different generation pair is refused
    // against the owner's live state, never re-applied as the same decision.
    let (cutover_text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(&stale_committed_cutover("eliot-903-case23-payload"))
    });
    match outcome {
        Err(KernelServiceError::HandshakeMismatch { field }) => assert_eq!(
            field, "generation_cutover.live_state",
            "a changed cutover payload must stay a typed live-state conflict"
        ),
        other => panic!("a changed cutover payload must be refused, got {other:?}"),
    }
    // The commit absence below reads THIS capture, so the refused cutover's own
    // request/failure pair is asserted FIRST
    // (`generation_control.rs:817`/`:835`): an empty surface fails here instead
    // of passing the absence vacuously.
    assert_present(
        &cutover_text,
        &[
            "kernel.generation.cutover_requested",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_absent(&cutover_text, &["kernel.generation.cutover_committed"]);
    assert_eq!(
        occurrences(&cutover_text, "kernel.terminal_error"),
        1,
        "the refused cutover carries exactly one designated terminal"
    );
}

// WORK_UNIT_CASE: 903/24
// I13.11:9: the diagnostic brief carries "exact evidence/log handles" and
// I13.11:13 "current hypotheses and unknowns"; I1.10:17: "A stale graph can be
// alive and compatible but not fresh; it must not advertise current impact
// analysis."
// Pins the health denominator production builds at `health_view.rs:374`-`:384`
// (the five queue families it iterates at `:338`-`:372`) and the unknown
// projection at `health_view.rs:450`. `daemon_snapshot`'s omission arms are
// `pub(super)` and belong to `health_view`'s own inline tests.
#[test]
fn health_input_denominator_and_omissions_come_from_evidence() {
    let (kernel, _guard) = test_kernel();
    let (text, projection) = capture_with(|| kernel.daemon_route_metrics_projection());
    assert_present(&text, &["kernel.health.route_metrics_projected"]);
    let gauges = projection
        .get("gauges")
        .and_then(Value::as_object)
        .expect("the gauge denominator must be present");
    // The denominator is exactly the set production iterates; a family silently
    // dropped from the projection is a real regression, not a formatting change.
    let mut families: Vec<&str> = gauges
        .get("queued_pairs")
        .and_then(Value::as_object)
        .expect("the queued_pairs denominator must be present")
        .keys()
        .map(String::as_str)
        .collect();
    families.sort_unstable();
    assert_eq!(
        families,
        vec![
            "campaign_packet",
            "finish",
            "observe",
            "query",
            "task_controller"
        ],
        "the health denominator must name every queue family production reads"
    );
    for gauge in ["live_claims", "observe_reservations_outstanding"] {
        assert!(gauges.contains_key(gauge), "missing gauge {gauge}");
    }
    // A missing retained brief is reported as unknown, never as a healthy system.
    let (brief_text, brief) = capture_with(|| kernel.diagnostic_brief_projection());
    assert_present(&brief_text, &["kernel.health.diagnostic_brief_projected"]);
    let brief_unknown = brief == serde_json::json!({"status": "unknown"});
    assert_eq!(
        brief_text.contains("success"),
        !brief_unknown,
        "the recorded brief outcome must agree with the projection production returned"
    );
    assert_absent(
        &text,
        &[
            "kernel.health.service_state_omitted",
            "kernel.health.snapshot_omitted",
        ],
    );
}

// WORK_UNIT_CASE: 903/25
// I1.10:5: "Health is a vector, not one boolean:" and I1.10:17: "A component is
// `READY` only for the capabilities whose required dimensions pass."
// Pins `health_view.rs:267` (the emitted outcome IS the returned view's own
// `lease_state`), `health_view.rs:243`/`:74`-`:88` (the `service_state` code is
// the owner's own state), and `health_view.rs:279`-`:284` (an absent blob probe
// projects `degraded`, never `ready`). The `KernelActivationView::FENCED`
// constant at `health_view.rs:64` is the closed fallback for unreadable inputs.
#[test]
fn missing_health_inputs_never_strengthen_the_derived_claim() {
    let (kernel, _guard) = test_kernel();
    let (text, view) = capture_with(|| kernel.activation_operational_view());
    assert_present(&text, &["kernel.activation.view_projected"]);
    let owner_state = kernel.service_state().expect("owner service state");
    assert!(
        matches!(owner_state, KernelServiceState::Cold),
        "the owner is Cold, so the view may not claim anything stronger"
    );
    assert_eq!(
        view.service_state, "cold",
        "the view's state code is the owner's own state, never an upgrade"
    );
    assert!(
        text.contains(view.lease_state),
        "the emitted outcome must be the returned view's own lease-state code"
    );
    for stronger in ["ready", "active", "healthy", "ready_proven"] {
        assert_absent(&text, &[stronger]);
    }

    // An absent blob capability is projected as degraded, not as ready.
    let (blob_text, blob) = capture_with(|| kernel.blob_capability_projection());
    assert_present(&blob_text, &["kernel.health.blob_projected", "absent"]);
    assert_eq!(
        blob["large_payload"], "degraded",
        "an absent blob probe must not project ready"
    );
    assert_eq!(blob["process"], "not_started");
    assert_absent(&blob_text, &["ready"]);
}

// WORK_UNIT_CASE: 903/26
// I14.24:9: "optional module crash | fence generation; reject new calls |
// continues" and I14.24:11 (truncated at "/checkpointed/rebuildable"): "independent
// daemon capabilities continue only when the actor state is disposable".
// Pins `health_view.rs:277`-`:285` (a component projection is per component) and
// `health_view.rs:205`-`:216` (the whole-Kernel state is the service owner's own
// read, untouched by a component projection).
#[test]
fn component_degradation_is_not_whole_kernel_failure() {
    let (kernel, _guard) = test_kernel();
    let (blob_text, blob) = capture_with(|| kernel.blob_capability_projection());
    assert_present(&blob_text, &["kernel.health.blob_projected"]);
    assert_eq!(blob["manifest"], "absent");
    // The component is degraded while the Kernel keeps its own lifecycle.
    let (state_text, state) = capture_with(|| kernel.service_state());
    assert!(
        matches!(state, Ok(KernelServiceState::Cold)),
        "a degraded component must not fail the whole Kernel, got {state:?}"
    );
    assert_present(&state_text, &["kernel.health.service_state_observed"]);
    let (route_text, route) = capture_with(|| kernel.generation_route_snapshot());
    assert!(
        route.is_ok(),
        "a degraded component must not fence the gateway"
    );
    assert_present(&route_text, &["kernel.generation.snapshot_committed"]);
    // Each total-failure token is scanned on the capture whose OWN read is the
    // only thing that could have written it, and each of those captures is
    // proved non-empty by the record its own read emitted, so neither absence is
    // true by construction. `blob_capability_projection` writes neither token:
    // it is a per-component projection (`health_view.rs:277`-`:285`) and can
    // carry no whole-Kernel state omission and no gateway terminal code at all,
    // so it is not a surface either claim can be read from.
    //
    // `kernel.health.service_state_omitted` belongs to the `service_state()` read
    // itself (`health_view.rs:207`), whose observed record — asserted above at
    // the same binding — is the only other arm that seam can take.
    assert_absent(&state_text, &["kernel.health.service_state_omitted"]);
    // `SNAPSHOT_PLATFORM` is the fenced route read's own terminal code, so it
    // belongs on the route read. That read is proved above to have SERVED
    // (`route.is_ok()`) and to have recorded its own committed record, which is
    // exactly the disproof of the platform terminal it must never have written.
    assert_absent(&route_text, &["SNAPSHOT_PLATFORM"]);
}

// WORK_UNIT_CASE: 903/27
// #895's terminal contract, quoted from the owning source's own doc comment
// rather than from a document (`bins/eliot-kernel/src/kernel_diagnostics.rs:683`
// truncated at the semicolon, which `:684` continues): "One underlying failed
// operation yields exactly one terminal record here".
// Pins `generation_control.rs:771`-`:776`: the failed route read binds its own
// single terminal to the operation whose own record names it, and no other
// operation's terminal is emitted under it.
#[test]
fn one_operation_yields_exactly_one_designated_terminal() {
    let fx = fixture();
    let code = fixture_str(&fx, "/refusal_codes/snapshot_platform");
    let (fencing_kernel, _fencing_guard) = test_kernel();
    let (fencing_text, fencing) =
        capture_with(|| fencing_kernel.apply_generation_cutover(&uncommitted_cutover()));
    assert!(fencing.is_err(), "the candidate cutover must be refused");
    assert_eq!(
        occurrences(&fencing_text, "kernel.terminal_error"),
        1,
        "the cutover owns exactly one terminal, got: {fencing_text}"
    );
    assert!(
        fencing_text
            .contains(fixture_str(&fx, "/generation/cutover_uncommitted_terminal").as_str()),
        "the cutover's terminal is the cutover's own stable code"
    );

    // The already-terminalised cutover failure is never terminalised again when
    // the fenced read boundary runs: a different operation, its own code.
    let (text, read) = capture_with(|| fencing_kernel.generation_route_snapshot());
    assert!(read.is_err(), "the fenced gateway must refuse route reads");
    assert_eq!(
        occurrences(&text, "kernel.terminal_error"),
        1,
        "the refused read owns exactly one terminal, got: {text}"
    );
    assert!(text.contains(&code), "the read's own stable code");
    // The read's own requested-phase record is proved present BEFORE the scan
    // below, on the same binding, so the absence is read against a surface
    // demonstrably carrying this operation's record rather than one that could
    // be empty. It is a distinct fact from the terminal count and the stable
    // code above, so it is kept rather than folded into them.
    assert_present(&text, &["kernel.generation.snapshot_requested"]);
    // The read's terminal is bound to the read's own phases: no cutover or
    // recovery record of any kind is emitted under it.
    for foreign in [
        "kernel.generation.cutover",
        "kernel.generation.service_fence",
        "kernel.recovery.",
    ] {
        assert_absent(&text, &[foreign]);
    }
}

// WORK_UNIT_CASE: 903/28
// I13.11:18: "Agent receives problem model, not raw log dump." I15.4/I07.20 (as
// cited by `health_view.rs:22`-`:28`): no digests, generations, epochs, Store
// payloads, paths or owner error strings.
// Pins `control_plane.rs:37`-`:38` (only the event and the outcome are bound),
// `generation_control.rs:448` (only the cutover identity is bound) and
// `generation_control.rs:420`-`:423` (never route contents, generation values or
// epoch/fence material). Unreachable slice: the inline canary proofs of
// `stable_owner_principal_digest` belong to
// `runtime_identity_diagnostics_tests`.
#[test]
fn environment_config_path_and_payload_canaries_are_absent() {
    let path_canary = "ELIOT903PATHCANARY".to_owned();
    let scope_canary = "ELIOT903SCOPECANARY".to_owned();
    let cutover_id = "eliot-903-case28-operation";
    let (kernel, guard) = build_kernel(&path_canary.to_lowercase());
    let work_root = guard.root.to_string_lossy().into_owned();

    let (text, outcome) = capture_with(|| {
        kernel.apply_generation_cutover(
            &CutoverDecision::new(
                cutover_id,
                RouteScope::new(scope_canary.to_lowercase()).expect("foreign scope"),
                Some(ResourceGeneration::new(5).expect("stale generation")),
                ResourceGeneration::new(6).expect("candidate generation"),
                test_epoch(1),
                test_epoch(2),
                GenerationCutoverState::Committed,
            )
            .expect("foreign-scope cutover decision"),
        )
    });
    assert!(outcome.is_err(), "an unknown route scope is refused");
    let (control_text, control) =
        capture_with(|| kernel.apply_control(KernelControlCommand::ProbeReady));
    assert!(control.is_err(), "the control probe is refused");
    let (view_text, _view) = capture_with(|| kernel.activation_operational_view());

    // The scan below is not vacuous, and it is not vacuous PER SURFACE: each of
    // the three captures is proved to carry the event/outcome pair its own call
    // actually produced FIRST, so an empty or wrongly-routed capture fails on
    // presence before any canary absence is evaluated. Without these, a surface
    // that recorded nothing would satisfy all eight canaries.
    assert!(
        text.contains(cutover_id),
        "the cutover's own validated operation identity must be recorded"
    );
    assert_present(
        &text,
        &[
            KERNEL_DIAGNOSTICS_TARGET,
            "kernel.generation.cutover_requested",
            "kernel.generation.cutover_failed",
        ],
    );
    assert_present(
        &control_text,
        &[
            KERNEL_DIAGNOSTICS_TARGET,
            "kernel.control.transition_requested",
            "kernel.control.transition_failed",
        ],
    );
    // The third surface has no positive of its own in this file's history, so it
    // gets one here: `activation_operational_view` reaches
    // `observe_health("kernel.activation.view_projected", ...)` on all three of
    // its arms (`health_view.rs:244`, `:253`, `:267`) and reads the owner's state
    // through `service_state()` (`health_view.rs:243`), so the observed state
    // record is on the surface on the readable arm too.
    assert_present(
        &view_text,
        &[
            KERNEL_DIAGNOSTICS_TARGET,
            "kernel.health.service_state_observed",
            "kernel.activation.view_projected",
        ],
    );
    // Scanned over the WHOLE captured surface of all three operations, never over
    // a hand-listed set of field names, so a differently-named helper that leaked
    // the same material would still be caught.
    for surface in [&text, &control_text, &view_text] {
        for canary in [
            path_canary.as_str(),
            scope_canary.as_str(),
            path_canary.to_lowercase().as_str(),
            scope_canary.to_lowercase().as_str(),
            work_root.as_str(),
            "550e8400-e29b-41d4-a716",
            "ReadinessNotProven",
            "generation gateway fenced",
        ] {
            assert_absent(surface, &[canary]);
        }
    }
}

// WORK_UNIT_CASE: 903/29
// I14.24:8 (truncated at the trailing "; authority snapshots cannot be assumed"):
// "ORS unavailable/corrupt | close durable mutation and effect admission; never
// return `ACCEPTED_PENDING`"; and issue #903's own noninterference requirement,
// quoted from the card rather than from a document: "sink failure/drop/disabled
// noninterference" (`ROOT-continuation/workstreams/swarm/cards/903.md`:24).
// Pins that the four delivery conditions — a healthy sink, a failing sink, a
// discarding sink and no subscriber at all — return byte-identical generation,
// reserve and health results, and that the healthy capture keeps the causal
// phase order.
#[allow(
    clippy::too_many_lines,
    reason = "four sink delivery conditions compared byte for byte are one noninterference claim"
)]
#[test]
fn sink_failure_drop_and_disable_preserve_calls_and_results() {
    let capacity_event = "kernel.control.capacity_observed";
    let (healthy_kernel, _healthy_guard) = test_kernel();
    let (healthy_text, healthy) = capture_with(|| {
        drive(&healthy_kernel);
        probe(&healthy_kernel)
    });

    let (failing_kernel, _failing_guard) = test_kernel();
    let failing = capture_with_failing_sink(|| {
        drive(&failing_kernel);
        probe(&failing_kernel)
    });

    let (discarding_kernel, _discarding_guard) = test_kernel();
    let discarding = capture_with_discarding_sink(|| {
        drive(&discarding_kernel);
        probe(&discarding_kernel)
    });

    let (disabled_kernel, _disabled_guard) = test_kernel();
    let disabled = capture_with_disabled_sink(|| {
        drive(&disabled_kernel);
        probe(&disabled_kernel)
    });

    assert_eq!(healthy, failing, "a failing sink must change no result");
    assert_eq!(healthy, discarding, "a dropping sink must change no result");
    assert_eq!(healthy, disabled, "a disabled sink must change no result");
    // The compared results are the owner's own answers, read field by field so
    // the equality above is a byte-identity claim about production output and not
    // about a diagnostic rendering.
    assert_eq!(
        healthy.route_epoch_sequence, 1,
        "the owner's live epoch sequence is unchanged on every delivery"
    );
    assert_eq!(
        healthy.projection_fingerprint.len(),
        64,
        "the owner's fingerprint is the exact lowercase SHA-256 it derives"
    );
    assert!(
        healthy.blob_projection.contains("degraded"),
        "the blob component projection is the owner's own, got {blob}",
        blob = healthy.blob_projection
    );
    assert!(
        healthy.route_metrics_gauges.contains("queued_pairs"),
        "the health denominator is the owner's own, got {gauges}",
        gauges = healthy.route_metrics_gauges
    );
    assert!(
        healthy.service_is_cold,
        "a refused control transition never fails the service on any delivery"
    );
    assert_eq!(
        healthy.projection_generation, healthy.route_generation,
        "the owner's active route and its projection agree on every delivery"
    );
    assert_eq!(
        healthy.control_capacity, failing.control_capacity,
        "the reserve read is delivery-independent"
    );
    assert!(
        healthy_text.contains(capacity_event),
        "the healthy capture must carry the records"
    );
    assert_causal_order(
        &healthy_text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
            capacity_event,
            "kernel.control.transition_requested",
            "kernel.control.transition_failed",
        ],
    );
    assert_eq!(
        occurrences(&healthy_text, "kernel.terminal_error"),
        1,
        "exactly one designated terminal across the whole driven sequence, and it is the refused `apply_control` operation's own; the driven sequence's SECOND refused operation carries none, which its own capture below proves. Got: {healthy_text}"
    );

    // `drive` contains two refused operations, not one: `apply_control`
    // (`ReadinessNotProven`, which owns the single terminal above) and
    // `mark_daemon_ready`, whose refusal path at `daemon_runtime.rs:2201`/`:2202`
    // (and `:2206`/`:2207`) returns `ReadinessNotProven` after emitting only
    // `kernel.daemon.ready_reported`. So `== 1` above is the first refusal's
    // terminal and NOT one per refused operation; this capture demonstrates the
    // second refusal's terminal absence on its OWN whole captured surface.
    // It cannot pass vacuously: the presence assertion runs FIRST and fails
    // unless that capture carries that refusal's real record, so the surface
    // being searched for the absent terminal is known to be non-empty.
    let (refusal_kernel, _refusal_guard) = test_kernel();
    let (refusal_text, refusal) = capture_with(|| refusal_kernel.mark_daemon_ready());
    assert!(
        matches!(refusal, Err(KernelServiceError::ReadinessNotProven)),
        "the second refused operation must stay refused, got {refusal:?}"
    );
    assert_present(&refusal_text, &["kernel.daemon.ready_reported"]);
    assert_absent(&refusal_text, &["kernel.terminal_error"]);
}

// WORK_UNIT_CASE: 903/30
// I14.20:3 (elided at TWO dropped spans: the middle sentence, and the leading
// clause of the sentence this quote ends inside): "This is the single
// normative vocabulary for shared cross-component runtime lifecycles … this
// section only prevents incompatible lifecycle meanings."
// Pins that the instrumented paths yield deterministic semantic fields and
// causal order (two independent compositions emit the identical ordered record
// sequence and return byte-identical results).
//
// WHAT THIS CASE DOES NOT CLAIM, after an adversarial read: it does NOT compare
// anything to `main`. Two compositions of the SAME build agreeing is determinism,
// not a diff against the base, and a git diff is not a runtime assertion. The
// diagnostic-only property is proved elsewhere and structurally, not here: every
// hunk of the delivery lies inside a `#[cfg(test)]` module (the six production
// files are insertions-only, numstat deletions 0), so no production line was
// removed or rewritten; and case 1's `events_by_file` denominator pins every
// `kernel.*` literal in the six modules against the frozen fixture vocabulary, so
// an added or renamed event would fail there rather than here.
#[test]
fn instrumented_paths_are_deterministic_and_diagnostic_only() {
    let fx = fixture();
    let vocabulary = frozen_event_vocabulary(&fx);

    let (first_text, first_kernel, _first_guard) = build_kernel_captured("case30-alpha");
    let (first_drive_text, first_results) = capture_with(|| {
        drive(&first_kernel);
        probe(&first_kernel)
    });
    let (second_text, second_kernel, _second_guard) = build_kernel_captured("case30-beta");
    let (second_drive_text, second_results) = capture_with(|| {
        drive(&second_kernel);
        probe(&second_kernel)
    });

    // Deterministic semantic fields and causal order: the ordered record
    // sequence, not the timestamps, is what the delivery must fix.
    let first_records = semantic_records(&first_text, &vocabulary);
    let second_records = semantic_records(&second_text, &vocabulary);
    assert!(
        !first_records.is_empty(),
        "the construction capture must carry frozen records, got: {first_text}"
    );
    assert_eq!(
        first_records, second_records,
        "two compositions must emit the identical ordered semantic record sequence"
    );
    // Bounded output. This proof existed on `main` in the single test this file
    // carried before the 30-case matrix replaced it, and the rewrite dropped it
    // without a successor: a diagnostic capture that grows without bound would
    // satisfy every ordering and absence assertion in this file while becoming
    // a denial-of-service surface, so the bound is re-asserted here on both the
    // construction capture and the drive capture.
    assert!(
        first_text.len() < 8 * 1024 && first_drive_text.len() < 8 * 1024,
        "diagnostic capture must stay bounded, got {} and {} bytes",
        first_text.len(),
        first_drive_text.len()
    );
    assert_causal_order(
        &first_text,
        &[
            "kernel.recovery.recover_requested",
            "kernel.recovery.cutovers_loaded",
            "kernel.recovery.recover_completed",
        ],
    );
    assert_causal_order(
        &first_drive_text,
        &[
            "kernel.generation.snapshot_requested",
            "kernel.generation.snapshot_committed",
        ],
    );
    assert!(
        second_drive_text.contains("kernel.generation.snapshot_committed"),
        "the second composition must emit the same deterministic records, got: {second_drive_text}"
    );

    // The exact diagnostic-only diff: the drive's own returned results are
    // byte-identical, so no event, terminal, reserve, health, state or error
    // result changed; only the observation vocabulary is new.
    assert_eq!(
        first_results, second_results,
        "the delivered instrumentation must not change any production result"
    );
    assert!(
        first_results.route_generation > 0 && first_results.projection_generation > 0,
        "both compositions must return a real owner route, got {first_results:?}"
    );
    // Both boundary rows exist in the frozen map, and both name this test.
    let rows = fx["boundaries"].as_array().expect("boundaries");
    assert_eq!(rows.len(), 30, "the fixture must freeze exactly 30 rows");
    let mut cases: Vec<u64> = rows
        .iter()
        .map(|row| row["case"].as_u64().expect("case"))
        .collect();
    cases.sort_unstable();
    assert_eq!(cases, (1..=30).collect::<Vec<u64>>());
    let this_row = rows
        .iter()
        .find(|row| row["case"].as_u64() == Some(30))
        .expect("case 30 row");
    assert_eq!(
        this_row["test"].as_str(),
        Some("instrumented_paths_are_deterministic_and_diagnostic_only")
    );
    assert!(this_row["noninterference"].is_string());
}

/// Reads the bounded `outcome=` token that follows one span in a capture. Used
/// only where production binds an observation's outcome to the SAME owner value
/// it returns to the caller (`control_plane.rs:1571` passes
/// `activation_operational_view().drain_disposition`), so the two can be compared.
fn outcome_marker_after(text: &str, span_at: usize) -> String {
    let tail = &text[span_at..];
    let marker = index_of(tail, "outcome=") + "outcome=".len();
    let rest = &tail[marker..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == '}')
        .unwrap_or(rest.len());
    rest[..end].trim_matches('"').to_owned()
}
