//! Focused port proofs for issue #984.
//!
//! Fourteen marker-bound cases cover the safe local Windows Event Log port: the
//! two-variant severity surface with its private `u16` report-type mapping and
//! the admitted source name and bounds constants, the closed local-only source
//! profile, the admitted HOST event/severity mapping with both admitted variant
//! lists and its frozen fixture, the pre-FFI byte and UTF-16 bounds, NUL and
//! protected-marker refusal without content, the wide-buffer and count-guard
//! source proof, the acquisition-failure and report-failure shapes, the
//! exactly-once deregistration owner, the fail-closed platform gate, the
//! never-substituted availability state, the published blocking and non-delivery
//! disclaimers, the isolated write/readback correlation attempt, and the
//! single-FFI-island and unsafe-block review. The scope/diff half of case 14 is
//! NOT observable from frozen text and is discharged in the #984 work-unit
//! report; case 14 says so at its own site.
//!
//! `mod event_log` is private and its reexport list publishes none of the leaf's
//! private items (`encode_wide_nul`, `report_validated`, `submit_validated`,
//! `RegisteredEventSource`, `AdmittedLocalEventLogEvent`), so none of them can be
//! named from an integration test. CLOSURE of that list is NOT proved: case 14
//! pins 25 names PRESENT and refuses nine name FRAGMENTS, so a new export whose
//! name avoids those fragments satisfies every pin. Cases 1, 2, 3, 5, 6, 7, 8, 9,
//! 10, 11, 12, 13 and 14 therefore prove against the frozen leaf, facade and
//! manifest text. Host queue consumption belongs to #889, not this file.
//!
//! Where a TEXT search would accept a spelling that never runs, the claim is
//! stated structurally instead: `brace_depth_of` requires a pinned submission to
//! be a top-level statement of its item, `preceding_attributes` binds each
//! platform-gated item to the gate it carries, and the public-member census
//! classifies `union` field lists and refuses a member typed by a generic
//! parameter. Those are properties of the shape, so a parking wrapper, an
//! exchanged gate and a monomorphised member are all red facts.
//!
//! Every ordered and counted search over frozen text reads `code_text`, the
//! single comment-free rendering built on `code_lines`: a guard, call site or
//! conversion deleted from the leaf and left behind as a `//` comment satisfies
//! no step and no count. Three censuses are named EXCEPTIONS rather than
//! instances of that rule: they read the RAW leaf or facade text on purpose,
//! because a commented-out public function head, a commented-out marker entry
//! and a commented-out reexport are exactly what they exist to refuse - case 2's
//! public-function census, `admitted_protected_markers` and
//! `event_log_reexport_names`. The two obligations that ARE prose - the published
//! limitations and the `// SAFETY:` annotations - are proved deliberately over
//! the raw text by `preceding_doc` and `check_safety_comment_precedes`.
//!
//! Declared denominator: 14 cases, exactly 1..14, one `#[test]` per work-unit
//! case marker in the `984/<n>` form, ascending, and no unmarked test in this
//! file. The number is not chosen here; it is declared verbatim by the #984 issue
//! body and by the continuation plan card `cards/984.md`, and this file only
//! carries it. The marker itself is spelled out only by the fourteen markers
//! below, so that a plain marker count over this file returns exactly 14.
//!
//! Denominator history: `main` carried 4 unmarked tests; this delivery makes the
//! 14 declared cases, so 4 to 14 IS the change the delivery makes. No case was
//! merged, dropped or renumbered in this delivery.
//!
//! Execution status: nothing in this file has been executed, because the
//! writing lane runs no `cargo test`, so no case is claimed to pass. The source
//! binding is this working tree plus the commit. The discovery binding is the
//! repository's own `scripts/work_unit_gate/case_binding.py::parse_rust_markers`,
//! which over these bytes reports 14 markers, cases 1..14, and no skip, ignore,
//! cfg or adequacy problem. The executed-pass binding is
//! `cargo test --locked -p eliot-platform-windows --test event_log`, and it
//! belongs to OR or root rather than to this lane.
//!
//! Case 13 proves the run-correlated write is real. Its readback half is
//! INCOMPLETE LIVE SUPPORT, because the approved isolated registered Event Log
//! source is an external setup prerequisite, so it is reported as incomplete
//! rather than as a skipped success.

use eliot_platform_windows::{
    AdmittedEventLogEvent, EVENT_LOG_MAX_INSERTION_BYTES, EVENT_LOG_MAX_INSERTION_UTF16_UNITS,
    EVENT_LOG_MAX_INSERTIONS, EVENT_LOG_QUEUE_CAPACITY, EVENT_LOG_SOURCE, EventLogError,
    EventLogReceipt, EventLogSeverity, EventLogSourceAvailability, KERNEL_EVENT_LOG_SOURCE,
    is_event_log_supported, report_local_event, validate_event_log_insertion,
};

/// Frozen admitted-profile fixture (issue #984).
const FIXTURE: &str = include_str!("data/event-log/admitted-profile.json");

/// Frozen platform leaf text; the source of truth for cases 1-3 and 5-14.
const LEAF: &str = include_str!("../src/event_log.rs");

/// Frozen crate facade text; the source of truth for the reexport list.
///
/// What is proved about that list is stated exactly: the 25 pinned names are all
/// PRESENT, and nine name FRAGMENTS are refused. Closure is NOT proved, because a
/// new export whose name avoids those fragments satisfies both.
const LIB_RS: &str = include_str!("../src/lib.rs");

/// Frozen manifest text; the source of truth for the single Event Log feature.
const MANIFEST: &str = include_str!("../Cargo.toml");

/// Occurrence count of `needle` over the comment-free lines of `haystack`.
///
/// Comment-blind by construction: a commented-out call site is not a call site,
/// so it cannot satisfy a count. `code_lines` is the only comment filter used
/// here, so this counts exactly the text the ordered and counted proofs read. The
/// three RAW-text censuses named in the module doc - case 2's public-function
/// census, `admitted_protected_markers` and `event_log_reexport_names` - are not
/// routed through this filter and are not counted here.
fn occurrence_count(haystack: &str, needle: &str) -> usize {
    code_text(haystack).matches(needle).count()
}

/// Trimmed non-empty source lines that are not comments.
fn code_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect()
}

/// The comment-free rendering of `source`: its non-comment lines, trimmed, one
/// per line.
///
/// This is the single normalization the ordered and counted searches read, so a
/// frozen statement that survives only as a `//` comment satisfies none of them.
/// Line based on purpose, because that is what `code_lines` filters: a pinned
/// step must therefore be a whole line of code, never a wrapped fragment. The
/// filter keys on a line-leading `//`, and the frozen leaf carries no `//`
/// inside a string literal, URL or Windows path, so no literal text is split.
/// Prose proofs (`preceding_doc`, `check_safety_comment_precedes`) read the raw
/// text on purpose and are never routed through here.
fn code_text(source: &str) -> String {
    code_lines(source).join("\n")
}

/// Collapses whitespace runs so wrapped frozen text compares as one line.
fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Inner block text of the first frozen item whose declaration contains
/// `anchor`. The braces are excluded so declaration comparisons see only the
/// frozen declarations, never the block punctuation.
fn item_block(source: &str, anchor: &str) -> Result<String, String> {
    let start = source
        .find(anchor)
        .ok_or_else(|| format!("frozen source must declare {anchor}"))?;
    let open = start
        + source[start..]
            .find('{')
            .ok_or_else(|| format!("{anchor} must open a block"))?;
    let mut depth = 0_u32;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(source[open + 1..open + offset].to_string());
                }
            }
            _ => {}
        }
    }
    Err(format!("{anchor} block is unbalanced"))
}

/// Balanced `(...)` parameter text starting at the `(` located at `open`.
fn parameter_list(source: &str, open: usize) -> Result<String, String> {
    let mut depth = 0_usize;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(source[open..=open + offset].to_string());
                }
            }
            _ => {}
        }
    }
    Err("frozen source has an unbalanced parameter list".to_string())
}

/// Wrapping-independent parameter declarations of the list starting at `open`.
fn normalized_parameters(source: &str, open: usize) -> Result<Vec<String>, String> {
    let list = parameter_list(source, open)?;
    let declared = list.trim_start_matches('(').trim_end_matches(')');
    Ok(declared
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect())
}

/// The brace DEPTH inside `block` at which `needle` first appears, or `None`
/// when `block` does not contain it at all.
///
/// Depth zero is a TOP-LEVEL statement of the item the block came from: an
/// `if`, `match`, `loop`, `while`, `for` or bare block that wraps the statement
/// opens a brace before it, so a parked spelling reads as depth one or more.
/// Read over `code_text`, the comment-free rendering every ordered search in
/// this file reads, so a statement that survives only as a `//` comment is not
/// found here at all rather than being measured at depth zero.
fn brace_depth_of(block: &str, needle: &str) -> Option<u32> {
    let at = block.find(needle)?;
    let mut depth = 0_u32;
    for ch in block[..at].chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Some(depth)
}

/// Requires every step to appear strictly after the previous one, over the
/// comment-free text of `haystack`.
///
/// Comment-blind by construction, like `occurrence_count`: deleting a guard and
/// leaving it behind as a `//` comment cannot satisfy a pinned step, because
/// the comment is removed before the search. Whole statements are pinned, so a
/// fallible-to-infallible conversion or an emptied guard body still fails on the
/// literal rather than on a substring.
fn check_step_order(haystack: &str, steps: &[&str]) -> Result<(), String> {
    let haystack = code_text(haystack);
    let mut cursor = 0_usize;
    for step in steps {
        let found = haystack[cursor..]
            .find(step)
            .ok_or_else(|| format!("required source step missing or out of order: {step}"))?;
        cursor += found + step.len();
    }
    Ok(())
}

/// Requires the pinned `call` to be documented by a `// SAFETY:` comment in the
/// contiguous comment run directly above it.
///
/// A safety obligation IS a comment, so it cannot be pinned through the
/// comment-free ordered scan and is proved here over the raw frozen text
/// instead. Adjacency is required, which is strictly stronger than the mere
/// presence this replaces: a stale safety comment left above unrelated code no
/// longer documents the call.
fn check_safety_comment_precedes(source: &str, call: &str) -> Result<(), String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let at = lines
        .iter()
        .position(|line| line.contains(call))
        .ok_or_else(|| format!("the frozen source must contain {call}"))?;
    let first = lines[..at]
        .iter()
        .rposition(|line| !line.starts_with("//"))
        .map_or(0, |below| below + 1);
    if first == at || !lines[first].starts_with("// SAFETY:") {
        return Err(format!(
            "{call} must carry a SAFETY comment directly above it"
        ));
    }
    Ok(())
}

/// Fails when any non-comment source line mentions `token`, ASCII-insensitively.
fn check_no_code_token(source: &str, token: &str) -> Result<(), String> {
    let needle = token.to_ascii_lowercase();
    for line in code_lines(source) {
        if line.to_ascii_lowercase().contains(&needle) {
            return Err(format!("no code line may mention {token}: {line}"));
        }
    }
    Ok(())
}

/// Case 6: the `ReportEventW` argument list, pinned whole-line and in position.
///
/// Each of the nine arguments is pinned as a whole statement, in order, and the
/// call's own closing parenthesis is pinned as the last step, so no argument can
/// be reordered or dropped. An ADDITIONAL argument would NOT be seen here:
/// `check_step_order` is a SEARCH and not adjacency, so a tenth argument appended
/// after the ninth is still followed by the `)` step. The card body names both
/// properties this exists for: "the one insertion pointer array has a checked
/// `u16` count" and "SID and raw data are null with zero lengths" - the pointer
/// array could otherwise be handed over as `std::ptr::null()` and the raw-data
/// length declared `4096` with every case still green. `code_text` trims, so the
/// steps carry no indentation.
fn check_report_event_arguments(report: &str) -> Result<(), String> {
    check_step_order(
        report,
        &[
            "let strings = [insertion_wide.as_ptr()];",
            "let string_count = u16::try_from(strings.len()).map_err(|_| EventLogError::InvalidInput)?;",
            "if string_count != EVENT_LOG_MAX_INSERTIONS {",
            "return Err(EventLogError::InvalidInput);",
            "ReportEventW(",
            "handle,",
            "event.severity().as_report_type(),",
            "0,",
            "event.event_id(),",
            "std::ptr::null_mut(),",
            "string_count,",
            "0,",
            "strings.as_ptr(),",
            "std::ptr::null(),",
            ")",
            "GetLastError()",
        ],
    )
}

/// The contiguous doc-comment block immediately above `anchor`.
///
/// Line based so the frozen text keeps working under either line ending.
fn preceding_doc(source: &str, anchor: &str) -> Result<String, String> {
    let index = source
        .find(anchor)
        .ok_or_else(|| format!("frozen source must declare {anchor}"))?;
    let mut lines = Vec::new();
    for line in source[..index].lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            continue;
        }
        if !trimmed.starts_with("///") {
            break;
        }
        lines.push(trimmed);
    }
    if lines.is_empty() {
        return Err(format!("{anchor} must carry an adjacent doc block"));
    }
    lines.reverse();
    Ok(lines.join("\n"))
}

/// The `#[...]` attribute lines directly above `anchor`.
fn preceding_attributes(source: &str, anchor: &str) -> Result<Vec<String>, String> {
    let index = source
        .find(anchor)
        .ok_or_else(|| format!("frozen source must declare {anchor}"))?;
    let mut attributes = Vec::new();
    for line in source[..index].lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            attributes.push(trimmed.to_string());
        } else {
            break;
        }
    }
    Ok(attributes)
}

/// Every marker the frozen leaf admits as not-redacted vocabulary.
fn admitted_protected_markers() -> Result<Vec<String>, String> {
    let anchor = "const PROTECTED_MARKERS: &[&str] = &[";
    let start = LEAF
        .find(anchor)
        .ok_or_else(|| "the leaf must declare the protected-marker vocabulary".to_string())?;
    let open = start + anchor.len() - 1;
    let close = open
        + LEAF[open..]
            .find(']')
            .ok_or_else(|| "the protected-marker vocabulary is unterminated".to_string())?;
    let mut markers = Vec::new();
    for line in LEAF[open..close].lines() {
        let quoted = line.trim().trim_end_matches(',');
        if let Some(marker) = quoted
            .strip_prefix('"')
            .and_then(|text| text.strip_suffix('"'))
        {
            markers.push(marker.to_string());
        }
    }
    if markers.is_empty() {
        return Err("the protected-marker vocabulary must not be empty".to_string());
    }
    Ok(markers)
}

/// Names the closed facade reexports from the private `event_log` module.
fn event_log_reexport_names() -> Result<Vec<String>, String> {
    let anchor = "pub use event_log::{";
    let start = LIB_RS
        .find(anchor)
        .ok_or_else(|| "the facade must reexport the Event Log surface".to_string())?;
    let open = start + anchor.len() - 1;
    let close = open
        + LIB_RS[open..]
            .find('}')
            .ok_or_else(|| "the Event Log reexport list is unterminated".to_string())?;
    Ok(LIB_RS[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect())
}

/// Case 1: the public severity surface is closed and carries no Win32 type.
fn check_closed_severity_surface() -> Result<(), String> {
    let enum_block = item_block(LEAF, "pub enum EventLogSeverity")?;
    let variants = code_lines(&enum_block);
    if variants != ["Information,", "Error,"] {
        return Err(format!("severity variants drifted: {variants:?}"));
    }
    if !normalize(LEAF).contains("const fn as_report_type(self) -> u16") {
        return Err("severity must map to a plain u16 report type".to_string());
    }
    if LEAF.contains("pub const fn as_report_type") {
        return Err("the Win32 report-type mapping must stay private".to_string());
    }
    // The mapping VALUES are part of the admitted profile and are pinned here,
    // in order. Only the `-> u16` signature was pinned before, so swapping
    // `EVENTLOG_INFORMATION_TYPE` and `EVENTLOG_ERROR_TYPE` left all fourteen
    // cases in this file green while every Host failure record became
    // informational. Pinned without indentation because `code_text` trims.
    let mapping = item_block(LEAF, "const fn as_report_type")?;
    check_step_order(&mapping, &["Self::Information => 4,", "Self::Error => 1,"])?;
    if occurrence_count(&mapping, "=>") != 2 {
        return Err("the report-type mapping must stay exactly two arms".to_string());
    }
    let information = EventLogSeverity::Information;
    let error = EventLogSeverity::Error;
    if information.as_str() != "information" || error.as_str() != "error" {
        return Err("severity names drifted from the admitted contract".to_string());
    }
    Ok(())
}

/// Case 2: every public leaf function takes only the closed admitted inputs.
///
/// `pub` reaches `fn` through a modifier, so the scan is driven by the modifier
/// set rather than by the bare `pub fn ` spelling, and every public `pub` line
/// that mentions `fn` is classified against it: a `pub const fn` or a
/// `pub unsafe fn` taking a caller-supplied server, log or source name declares
/// exactly the same input surface as a `pub fn` and must not pass unexamined.
/// A restricted visibility (`pub(crate)`) is not the public surface this proves,
/// and a `pub const`/`pub enum`/`pub struct` line declares no parameter at all.
fn check_public_input_surface_is_closed() -> Result<(), String> {
    const MODIFIERS: [&str; 5] = ["", "const ", "async ", "unsafe ", "extern "];
    for line in code_lines(LEAF) {
        let Some(head) = line.strip_prefix("pub ") else {
            continue;
        };
        if head.starts_with('(') {
            continue;
        }
        let Some(at) = head.find("fn ") else {
            continue;
        };
        if !MODIFIERS.contains(&&head[..at]) {
            return Err(format!("unexamined public function head: {line}"));
        }
    }
    let mut observed = Vec::new();
    for modifier in MODIFIERS {
        let head = format!("pub {modifier}fn ");
        let mut cursor = 0_usize;
        while let Some(found) = LEAF[cursor..].find(head.as_str()) {
            let at = cursor + found;
            cursor = at + head.len();
            let open = at
                + LEAF[at..].find('(').ok_or_else(|| {
                    "every public leaf function takes a parameter list".to_string()
                })?;
            observed.push(normalized_parameters(LEAF, open)?.join(", "));
        }
    }
    let mut expected = vec![
        // Zero-parameter public surface: `is_event_log_supported`,
        // `admits_watchdog_audit`, `watchdog_audit_sink_owner`.
        "",
        "",
        "",
        // `&self` accessors, five on each receipt type.
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        "&self",
        // The three reporting/validation entry points and the two closed
        // identifier classifiers: the only admitted inputs in the crate.
        "event: AdmittedEventLogEvent, insertion: &str",
        "event: AdmittedKernelEventLogEvent, insertion: &str",
        "event_id: u32",
        "event_id: u32",
        "insertion: &str",
        // `self` accessors: severity name, then name/id/severity per event enum.
        "self",
        "self",
        "self",
        "self",
        "self",
        "self",
        "self",
    ];
    expected.sort_unstable();
    observed.sort_unstable();
    if observed != expected {
        return Err(format!("public input surface drifted: {observed:?}"));
    }
    Ok(())
}

/// The text that follows a `pub ` TOKEN on `line`, or `None` when the line
/// declares no `pub` token at all or carries a restricted visibility.
///
/// `pub` is located as a TOKEN inside the line and never as a line prefix, so a
/// member that carries an attribute before its visibility is still classified.
/// A restricted visibility (`pub(crate)`) is not the public surface this file
/// proves and is skipped here for the same reason the parameter census skips
/// it; a member with NO `pub` token is not public either, and must not be
/// classified as if it were.
fn after_public_token(line: &str) -> Option<&str> {
    let at = line.find("pub ")?;
    let rest = line[at + "pub ".len()..].trim_start();
    if rest.starts_with('(') {
        return None;
    }
    Some(rest)
}

/// A code line with its `pub ` token removed, whether or not it has one.
///
/// Visibility is OPTIONAL here, unlike `after_public_token`, because an item
/// declaration is located whether it is public or not and the census reads the
/// blocks of both: `struct RegisteredEventSource` and `enum
/// AdmittedLocalEventLogEvent` are private items that publish nothing today.
fn declaration_without_visibility(line: &str) -> &str {
    match line.find("pub ") {
        Some(at) => line[at + "pub ".len()..].trim_start(),
        None => line,
    }
}

/// The declared type of one `pub` member line of a struct, enum or union block.
///
/// `pub` is again read as a token, so `#[doc(hidden)] pub server: String,`
/// classifies exactly as `pub server: String,` does; requiring the line to
/// START with `pub ` silently dropped every attributed member.
fn declared_member_type(line: &str) -> Option<String> {
    let (_, ty) = after_public_token(line)?.split_once(':')?;
    Some(ty.trim().trim_end_matches(',').to_string())
}

/// The `pub` member types declared inside one frozen struct, enum or union
/// block.
///
/// An enum block is read by this pass exactly as a struct's is, so a `pub`
/// member declared beside the variants is classified. The enum's own VARIANTS
/// are not members and are NOT classified here - an enum variant field can never
/// carry `pub` - and they are covered instead by the explicit variant-list
/// censuses in cases 1, 2, 3 and 11.
///
/// `generics` are the parameter names the enclosing declaration introduces: a
/// member typed BY one of them is a hole in the census rather than a classified
/// type, so it is refused here instead of being collected as a word that matches
/// nothing.
fn block_member_types(block: &str, generics: &[String]) -> Result<Vec<String>, String> {
    let mut members = Vec::new();
    for line in code_lines(block) {
        let Some(member) = declared_member_type(line) else {
            continue;
        };
        check_member_type_is_not_generic(&member, generics, line)?;
        members.push(member);
    }
    Ok(members)
}

/// The generic parameter NAMES one item head declares, e.g. `T` and `U` for
/// `pub struct Pair<T, U: Clone> {`.
///
/// Only the names matter, so a bound, a lifetime and a const parameter are all
/// reduced to the word a member type would have to spell to escape the census.
/// A head with no `<` declares none, which is the case for every item on the
/// frozen leaf.
fn generic_parameter_names(head: &str) -> Vec<String> {
    let Some(open) = head.find('<') else {
        return Vec::new();
    };
    let Some(close) = head[open..].find('>') else {
        return Vec::new();
    };
    head[open + 1..open + close]
        .split(',')
        .filter_map(|parameter| {
            let mut words = parameter.split(':').next()?.split_whitespace();
            let mut name = words.next()?;
            if name == "const" {
                name = words.next()?;
            }
            Some(name.to_string())
        })
        .collect()
}

/// Fails when a public member type is, or is built out of, one of the
/// enclosing item's own generic parameters.
///
/// A BARE parameter is the sharpest hole in this census: `pub struct
/// Selector<T> { pub value: T }` instantiated with `String` collects the member
/// type as `T`, which matches none of the caller-selected types the case 2
/// caller rejects, while the instantiated member IS a caller-selected string.
/// The WORDS of the type are compared rather than the whole type, so a
/// container over the parameter (`Vec<T>`) is refused for the same reason, and
/// an unrelated type that merely shares a letter (`TextHandle`) is not a false
/// positive because the comparison is per word.
fn check_member_type_is_not_generic(
    member: &str,
    generics: &[String],
    context: &str,
) -> Result<(), String> {
    let words: Vec<&str> = member
        .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    if let Some(parameter) = generics.iter().find(|name| words.contains(&name.as_str())) {
        return Err(format!(
            "a public member must not be typed by a generic parameter: {context} is typed by {parameter}"
        ));
    }
    Ok(())
}

/// Declared `pub` members of every struct, enum, union and type alias in the
/// leaf.
///
/// Struct and enum items are located through their own declaration line and
/// read with the same `item_block` brace matcher, so a member is classified
/// from the frozen block it lives in instead of a bare word scan over the file:
/// a whole-file scan for `pub ... :` would also collect the `pub const` profile
/// constants (`EVENT_LOG_SOURCE: &str`), which are admitted values, not caller
/// members. FIVE shapes reach this census, and each is a place a
/// caller-selected server, log or source name can hide:
///
/// - a named `pub` field of a struct, with or without a preceding attribute;
/// - a named `pub` field of a `pub union`, whose overlapping storage can reinterpret
///   the bytes of whichever field a caller sets, so its field list is classified
///   exactly like a struct's rather than skipped;
/// - a named `pub` member declared inside an `enum` block, which the `enum`
///   branch reads with the same `item_block` matcher a struct's is read with, so
///   a member sitting beside the variants is classified rather than skipped;
/// - a tuple struct's parenthesised payload, read from the declaration line
///   itself because such a declaration opens no brace and the brace matcher
///   would otherwise read a LATER item's block;
/// - the right-hand side of a `type` alias, which hides a string from any
///   substring scan of a member list.
///
/// The payload and the alias side are read WHOLE rather than split per member:
/// splitting on `,` would break a generic argument list. `code_lines` is the one
/// comment filter in this file, so a member that survives only as a `//`
/// comment is not a member. Every classified type is finally checked against
/// the generic parameters of the item that declares it, because a parameter is
/// substituted only at the USE site: the frozen text names the parameter, and
/// only the instantiation says what the member really carries.
fn public_field_types(source: &str) -> Result<Vec<String>, String> {
    let mut members = Vec::new();
    for line in code_lines(source) {
        let declaration = declaration_without_visibility(line);
        if declaration.starts_with("type ") {
            let Some((_, right)) = declaration.split_once('=') else {
                continue;
            };
            members.push(right.trim().trim_end_matches(';').to_string());
            continue;
        }
        if declaration.starts_with("enum ") {
            let generics = generic_parameter_names(declaration);
            members.extend(block_member_types(&item_block(source, line)?, &generics)?);
            continue;
        }
        // `union` reaches this census through the same path as `struct`: its
        // field list is a brace block of named `pub` fields, and a `union`
        // declaration that classified nothing was a hole rather than a
        // permission.
        let Some(struct_head) = declaration
            .strip_prefix("struct ")
            .or_else(|| declaration.strip_prefix("union "))
        else {
            continue;
        };
        let generics = generic_parameter_names(struct_head);
        let payload = struct_head
            .find('(')
            .filter(|open| struct_head.find('{').is_none_or(|brace| *open < brace));
        let Some(open) = payload else {
            members.extend(block_member_types(&item_block(source, line)?, &generics)?);
            continue;
        };
        let group = parameter_list(struct_head, open)?;
        // The group must be the payload, i.e. nothing but a terminator or a
        // `where` clause may follow it on the declaration line. An attribute
        // such as `#[doc(hidden)]` supplies a `(` of its own, and a `where
        // T: Fn(u32)` bound supplies one inside a braced declaration, so this
        // guard is what keeps either of those out of the payload position; when
        // it fires the declaration is braced and the block is read instead.
        let after = struct_head[open + group.len()..].trim_start();
        if !(after.is_empty() || after.starts_with(';') || after.starts_with("where")) {
            members.extend(block_member_types(&item_block(source, line)?, &generics)?);
            continue;
        }
        check_member_type_is_not_generic(&group, &generics, line)?;
        members.push(group);
    }
    Ok(members)
}

/// Case 3: the frozen admitted-profile fixture agrees with the live mapping.
fn verify_frozen_fixture_agrees_with_mapping() -> Result<(), String> {
    let profile: serde_json::Value =
        serde_json::from_str(FIXTURE).map_err(|e| format!("fixture must parse: {e}"))?;
    let get = |key: &str| {
        profile
            .get(key)
            .ok_or_else(|| format!("fixture missing {key}"))
    };
    if get("issue")?.as_u64() != Some(984) {
        return Err("fixture issue must stay 984".to_string());
    }
    if get("source")?.as_str() != Some(EVENT_LOG_SOURCE) {
        return Err("fixture source drifted".to_string());
    }
    let bounds = [
        (
            "max_insertion_bytes",
            u64::try_from(EVENT_LOG_MAX_INSERTION_BYTES).ok(),
        ),
        (
            "max_insertion_utf16_units",
            u64::try_from(EVENT_LOG_MAX_INSERTION_UTF16_UNITS).ok(),
        ),
        ("max_insertions", Some(u64::from(EVENT_LOG_MAX_INSERTIONS))),
        (
            "queue_capacity",
            u64::try_from(EVENT_LOG_QUEUE_CAPACITY).ok(),
        ),
    ];
    for (key, constant) in bounds {
        let constant =
            constant.ok_or_else(|| format!("port constant {key} must fit the fixture"))?;
        let recorded = get(key)?
            .as_u64()
            .ok_or_else(|| format!("fixture {key} must be an integer"))?;
        if recorded != constant {
            return Err(format!("fixture {key} must equal the port constant"));
        }
    }
    let events = get("events")?
        .as_array()
        .ok_or_else(|| "fixture events must be an array".to_string())?;
    if events.len() != 3 {
        return Err("fixture must admit exactly three events".to_string());
    }
    for entry in events {
        let raw = entry
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "fixture event id must be present".to_string())?;
        let id = u32::try_from(raw).map_err(|_| "fixture event id must fit u32".to_string())?;
        let event = AdmittedEventLogEvent::from_event_id(id)
            .map_err(|e| format!("fixture event id must be admitted: {e}"))?;
        let name = entry.get("name").and_then(serde_json::Value::as_str);
        let severity = entry.get("severity").and_then(serde_json::Value::as_str);
        if name != Some(event.as_str()) || severity != Some(event.severity().as_str()) {
            return Err(format!("fixture event drifted for id {id}"));
        }
    }
    Ok(())
}

/// Case 10: an unavailable or refused port fails closed and stays content-free.
fn check_fail_closed_probe(
    probe: &str,
    outcome: Result<EventLogReceipt, EventLogError>,
) -> Result<(), String> {
    match outcome {
        Ok(receipt) => {
            if !cfg!(windows) {
                return Err("non-Windows must never report success".to_string());
            }
            if receipt.event_id() != 100
                || receipt.source() != EVENT_LOG_SOURCE
                || receipt.source_availability() != EventLogSourceAvailability::Unknown
            {
                return Err("receipt must carry the admitted mapping".to_string());
            }
        }
        Err(EventLogError::UnsupportedPlatform) => {
            if cfg!(windows) {
                return Err("Windows must attempt the OS port".to_string());
            }
        }
        Err(
            EventLogError::RegistrationFailed { .. }
            | EventLogError::ReportFailed { .. }
            | EventLogError::Unavailable,
        ) => {
            if !cfg!(windows) {
                return Err("non-Windows must report UnsupportedPlatform".to_string());
            }
        }
        Err(EventLogError::InvalidInput) => {
            return Err("valid probe must not fail validation".to_string());
        }
    }
    for category in [
        EventLogError::InvalidInput,
        EventLogError::Unavailable,
        EventLogError::UnsupportedPlatform,
    ] {
        if format!("{category}").contains(probe) {
            return Err("typed error text must stay free of insertion content".to_string());
        }
    }
    Ok(())
}

/// Case 11: the only declared constant whose name ENDS IN `_SOURCE` is one of the
/// two fixed ones.
///
/// This is the suffix half only, and it says so rather than claiming every
/// declared source name in the leaf: the scan collects constants whose name ends
/// in `_SOURCE`, so a differently named constant would not be collected here. The
/// string-VALUED published-constant census and the forbidden
/// SERVER/HOST/UNC/LOG_NAME/SECURITY name scan are case 2's, not this one's.
fn check_known_source_constants_are_the_only_sources() -> Result<(), String> {
    let mut declared = Vec::new();
    for line in code_lines(LEAF) {
        // Both visibilities must be collected, so an optional leading `pub ` is
        // stripped before `const ` is matched: a private substituted source
        // name is as substitutable as a public one, and the `pub`-only prefix
        // made it invisible to the only structural source-name check here.
        // Requiring the line to START with `const ` instead would miss both
        // required names, because both are declared `pub const`; the match is
        // therefore optional-visibility, never bare-`const`-only.
        let Some(rest) = line
            .strip_prefix("pub ")
            .and_then(|rest| rest.strip_prefix("const "))
            .or_else(|| line.strip_prefix("const "))
        else {
            continue;
        };
        if let Some((name, _)) = rest.split_once(':')
            && name.trim().ends_with("_SOURCE")
        {
            declared.push(name.trim().to_string());
        }
    }
    let mut expected = ["EVENT_LOG_SOURCE", "KERNEL_EVENT_LOG_SOURCE"].to_vec();
    expected.sort_unstable();
    declared.sort();
    if declared != expected {
        return Err(format!("Event Log source constants drifted: {declared:?}"));
    }
    Ok(())
}

/// Case 10: every unsafe and FFI item is gated on `#[cfg(windows)]`, and the
/// one `#[cfg(not(windows))]` arm is the REFUSING `submit_validated`.
///
/// Every `unsafe` block and every FFI item of the leaf is behind a `#[cfg]`
/// attribute, and the two `submit_validated` declarations share one name, so
/// `item_block` binds them to the FIRST declaration whatever gate each carries.
/// Exchanging the gate at src/event_log.rs:715 with the one at :727 leaves both
/// bodies byte-identical: every frozen-text proof in this file still reads the
/// untouched Windows declaration, while a WINDOWS build binds the REFUSING body
/// to the live name and the whole write path collapses to
/// `Err(UnsupportedPlatform)`, and a non-Windows build binds the Windows body,
/// whose callees are all gated off by the very pins below. The eight-attribute
/// census in case 7 cannot see that swap, because it counts the lines and
/// accepts either platform spelling. So the gate is pinned here PER ITEM - which
/// item each attribute opens - with the file's existing `preceding_attributes`,
/// which reads the attribute run directly above an anchor.
fn check_platform_gate_ownership() -> Result<(), String> {
    for item in [
        "use windows_sys::Win32::Foundation::HANDLE;",
        "fn encode_wide_nul",
        "struct RegisteredEventSource",
        "impl RegisteredEventSource",
        "impl Drop for RegisteredEventSource",
        "fn report_validated",
        "fn submit_validated",
    ] {
        let attributes = preceding_attributes(LEAF, item)?;
        if attributes != ["#[cfg(windows)]"] {
            return Err(format!(
                "{item} must be gated on exactly #[cfg(windows)] and on no other gate, found {attributes:?}"
            ));
        }
    }
    // The other gate. Exactly ONE `#[cfg(not(windows))]` attribute may exist, so
    // the refusal arm cannot be duplicated, and the item it opens must be that
    // arm: `preceding_attributes` reports the attribute run above the FIRST
    // `submit_validated`, which is the Windows declaration here, so reusing it
    // would read the wrong item. The leaf's lines are therefore scanned directly
    // and the declaration below the gate is pinned whole, spelled
    // `fn submit_validated(`, so a renamed or decoy arm cannot pass as it.
    let leaves: Vec<&str> = LEAF.lines().collect();
    let refusals: Vec<usize> = leaves
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == "#[cfg(not(windows))]")
        .map(|(at, _)| at)
        .collect();
    if refusals.len() != 1 {
        return Err(format!(
            "the leaf must declare exactly one #[cfg(not(windows))] gate, found {}",
            refusals.len()
        ));
    }
    let declaration = leaves[refusals[0] + 1..]
        .iter()
        .map(|line| line.trim())
        .find(|line| !line.is_empty() && !line.starts_with("//"))
        .ok_or_else(|| "the #[cfg(not(windows))] gate must open an item".to_string())?;
    if !declaration.starts_with("fn submit_validated(") {
        return Err(format!(
            "#[cfg(not(windows))] must gate the non-Windows submit_validated, found {declaration}"
        ));
    }
    // And that arm must REFUSE, so the gate cannot be swapped AND the arm cannot
    // be rewritten to fabricate success. The steps are the existing ordered
    // machinery, read from the tail after the gate so the Windows declaration
    // cannot stand in for the refusal, and the arm carries no `Ok(` at all.
    let (_, tail) = LEAF
        .split_once("#[cfg(not(windows))]")
        .ok_or_else(|| "the leaf must declare the non-Windows gate".to_string())?;
    let refusal = code_text(&item_block(tail, "fn submit_validated(")?);
    check_step_order(
        &refusal,
        &[
            "let _ = (event, insertion);",
            "Err(EventLogError::UnsupportedPlatform)",
        ],
    )?;
    if refusal.contains("Ok(") {
        return Err("the non-Windows submit_validated must never report success".to_string());
    }
    Ok(())
}

/// Unique run correlation for case 13: the current process plus the wall
/// clock. The clock reading keeps two runs of one process distinguishable.
fn run_correlation() -> Result<String, String> {
    let pid = std::process::id();
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("the system clock must follow the Unix epoch: {e}"))?
        .as_nanos();
    Ok(format!("{pid:x}-{clock:x}"))
}

/// Case 13: no Event Log readback surface is reachable from this test target.
fn check_readback_half_is_unreachable() -> Result<(), String> {
    for token in [
        "pub fn read",
        "pub fn export",
        "OpenEventLog",
        "EvtExportLog",
        "readback",
    ] {
        for line in code_lines(LEAF) {
            if line.contains(token) {
                return Err(format!("the leaf must publish no readback path: {token}"));
            }
        }
    }
    for section in ["[dev-dependencies]", "[[test]]"] {
        if MANIFEST.contains(section) {
            return Err(format!("the frozen manifest must not declare {section}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: 14 substantive cases for issue #984
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 984/1
#[test]
fn port_surface_exposes_only_the_typed_local_profile() -> Result<(), String> {
    if EVENT_LOG_SOURCE != "EliotHost" {
        return Err("source must stay EliotHost".to_string());
    }
    if EVENT_LOG_MAX_INSERTION_BYTES != 1024 || EVENT_LOG_QUEUE_CAPACITY != 64 {
        return Err("bounds must stay 1024B/64".to_string());
    }
    check_closed_severity_surface()
}

// WORK_UNIT_CASE: 984/2
#[test]
fn local_only_profile_has_no_remote_or_log_selector() -> Result<(), String> {
    // The proven claim is "no caller-selected source, log or server exists",
    // not "only one source string exists": `KERNEL_EVENT_LOG_SOURCE` is a
    // second admitted source reachable only through its own closed enum, and
    // neither it nor any server/log/source name is a public parameter.
    check_public_input_surface_is_closed()?;
    let union = item_block(LEAF, "enum AdmittedLocalEventLogEvent")?;
    let variants = code_lines(&union);
    if variants
        != [
            "Host(AdmittedEventLogEvent),",
            "Kernel(AdmittedKernelEventLogEvent),",
        ]
    {
        return Err(format!("the admitted union must stay closed: {variants:?}"));
    }
    if LEAF.contains("pub enum AdmittedLocalEventLogEvent") {
        return Err("the admitted source union must stay private".to_string());
    }
    let selection = item_block(LEAF, "const fn source(self) -> &'static str")?;
    check_step_order(&selection, &["EVENT_LOG_SOURCE", "KERNEL_EVENT_LOG_SOURCE"])?;
    if occurrence_count(&selection, "=>") != 2 {
        return Err("source selection must resolve only the two admitted constants".to_string());
    }
    if EVENT_LOG_SOURCE == KERNEL_EVENT_LOG_SOURCE {
        return Err("the two admitted profiles must keep distinct sources".to_string());
    }
    // The signature census above closes the PARAMETER surface. A `pub` member
    // of a string, path, raw-pointer or handle type would be the very
    // caller-selected remote host, log name or Security-log selector this case
    // excludes, reached through a member or an alias instead of a parameter, so
    // the member surface is closed on its own terms. The frozen leaf publishes
    // no public member at all, so this is the empty census today and turns red
    // the moment a public member of a REFUSED TYPE is added, whichever of the
    // five shapes carries it, and whether it is typed directly or by a generic
    // parameter. A public member whose type mentions no refused spelling is
    // collected and is not refused, so this refusal is narrower than "no public
    // member".
    let caller_selected_types = [
        "str", "String", "Path", "OsStr", "OsString", "CStr", "CString", "PCWSTR", "HANDLE",
        "NonNull", "*",
    ];
    for member in public_field_types(LEAF)? {
        if caller_selected_types.iter().any(|ty| member.contains(ty)) {
            return Err(format!(
                "a public member must carry no caller-selected text or handle type: {member}"
            ));
        }
    }
    // And the same claim over PUBLISHED CONSTANT VALUES. The signature, member
    // and `_SOURCE`-suffix censuses above all read names, types and suffixes:
    // `pub const EVENT_LOG_SECURITY_LOG_NAME: &str = "Security";` or `pub
    // static SELECTOR: Option<&str> = None;` reaches every one of them
    // unnoticed, because neither carries a `fn`, a `pub` member or a `_SOURCE`
    // ending. So the string-typed `pub const`/`pub static` items are censused by
    // IDENTITY, with their VALUES: exactly the two admitted sources, nothing
    // else. Measured on the frozen leaf, the only two `pub` items whose declared
    // type mentions `str` are `EVENT_LOG_SOURCE` and `KERNEL_EVENT_LOG_SOURCE`;
    // the other twelve `pub const`s are `usize`, `u32` or `u16`, and the
    // marker vocabulary is a private `const`, so the census is exactly those two
    // today. The forbidden-name scan below covers the numeric items too, so a
    // published SERVER/HOST/UNC/LOG_NAME/SECURITY selector is refused whatever
    // its type is. `write!` is NOT refused: it appears in the leaf's own `Display`
    // impl and banning it would be a false positive.
    let mut published_strings: Vec<String> = Vec::new();
    for line in code_lines(LEAF) {
        let Some(after_visibility) = line.strip_prefix("pub ") else {
            continue;
        };
        let item = after_visibility
            .strip_prefix("const ")
            .or_else(|| after_visibility.strip_prefix("static "));
        let Some(item) = item else {
            continue;
        };
        let Some((name, after_name)) = item.split_once(':') else {
            continue;
        };
        let name = name.trim();
        for forbidden in ["SERVER", "HOST", "UNC", "LOG_NAME", "SECURITY"] {
            if name.contains(forbidden) {
                return Err(format!(
                    "no published Event Log constant may name a {forbidden} selector: {name}"
                ));
            }
        }
        let Some((ty, value)) = after_name.split_once('=') else {
            continue;
        };
        let words: Vec<&str> = ty
            .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
            .collect();
        if words.contains(&"str") {
            published_strings.push(format!("{name} = {}", value.trim().trim_end_matches(';')));
        }
    }
    published_strings.sort();
    let mut expected_published = vec![
        "EVENT_LOG_SOURCE = \"EliotHost\"",
        "KERNEL_EVENT_LOG_SOURCE = \"EliotKernel\"",
    ];
    expected_published.sort_unstable();
    if published_strings != expected_published {
        return Err(format!(
            "the only published Event Log text must be the two admitted sources, found {published_strings:?}"
        ));
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/3
#[test]
fn frozen_fixture_matches_the_port() -> Result<(), String> {
    let mapping = [
        (AdmittedEventLogEvent::ServiceStart, 100_u32, "information"),
        (AdmittedEventLogEvent::ServiceStop, 101_u32, "information"),
        (AdmittedEventLogEvent::ServiceFailure, 102_u32, "error"),
    ];
    for (event, id, severity) in mapping {
        if event.event_id() != id || event.severity().as_str() != severity {
            return Err("event/severity mapping drifted".to_string());
        }
        if AdmittedEventLogEvent::from_event_id(id).map_err(|e| format!("{e}"))? != event {
            return Err("event id round-trip failed".to_string());
        }
    }
    if AdmittedEventLogEvent::from_event_id(999).is_ok() {
        return Err("unknown event id must be rejected".to_string());
    }
    // The round trip above is a CLOSED-WORLD argument over the three ids the test
    // itself supplies, so it is blind in both directions at once: a fourth
    // admitted Host variant (`AdmittedEventLogEvent::from_event_id(103) == Ok(
    // ..)`) and any drift of the five Kernel identifiers are invisible to it,
    // because nothing here enumerates either enum and nothing reads the id
    // constants at all. Card case 3 is "exact event/severity mapping and
    // unknown values rejected", so the exact variant LIST of both admitted
    // enums is censused here, with `code_lines` and an exact comparison, and
    // the eight id constants are pinned to their values as whole statements in
    // declaration order. SCOPE, stated exactly: this closes the two variant
    // LISTS and the eight id VALUES, and nothing else - the Kernel `as_str`
    // names and the two severity arms are still unpinned text and are reported
    // as open, not claimed here. Measured on the frozen leaf (src/event_log.rs
    // 144-151, 90-111) both censuses and all eight constants hold.
    let host_enum = item_block(LEAF, "pub enum AdmittedEventLogEvent")?;
    let host_variants = code_lines(&host_enum);
    if host_variants != ["ServiceStart,", "ServiceStop,", "ServiceFailure,"] {
        return Err(format!(
            "the admitted Host event variants drifted: {host_variants:?}"
        ));
    }
    let kernel_enum = item_block(LEAF, "pub enum AdmittedKernelEventLogEvent")?;
    let kernel_variants = code_lines(&kernel_enum);
    let admitted_kernel_variant_lines = [
        "Startup,",
        "Crash,",
        "Recovery,",
        "RestartExhausted,",
        "Quarantine,",
    ];
    if kernel_variants != admitted_kernel_variant_lines {
        return Err(format!(
            "the admitted Kernel event variants drifted: {kernel_variants:?}"
        ));
    }
    check_step_order(
        LEAF,
        &[
            "pub const EVENT_LOG_SERVICE_START_ID: u32 = 100;",
            "pub const EVENT_LOG_SERVICE_STOP_ID: u32 = 101;",
            "pub const EVENT_LOG_SERVICE_FAILURE_ID: u32 = 102;",
            "pub const KERNEL_EVENT_LOG_STARTUP_ID: u32 = 200;",
            "pub const KERNEL_EVENT_LOG_CRASH_ID: u32 = 201;",
            "pub const KERNEL_EVENT_LOG_RECOVERY_ID: u32 = 202;",
            "pub const KERNEL_EVENT_LOG_RESTART_EXHAUSTED_ID: u32 = 203;",
            "pub const KERNEL_EVENT_LOG_QUARANTINE_ID: u32 = 204;",
        ],
    )?;
    verify_frozen_fixture_agrees_with_mapping()
}

/// Requires production to refuse `insertion` before any FFI call, naming the
/// bound whose one-over input it is.
///
/// A named checked result, so the refusal is a step this file makes visible
/// rather than an unlabelled discard inside a loop.
fn check_rejected_before_ffi(label: &str, insertion: &str) -> Result<(), String> {
    match validate_event_log_insertion(insertion) {
        Err(EventLogError::InvalidInput) => Ok(()),
        _ => Err(format!("{label} must be rejected before FFI")),
    }
}

// NAME, disclosed: the name is the card's own START sentence verbatim, so the
// redaction half of that sentence is NOT proved here; case 5 proves it, under the
// same START sentence. The name is not renamed, because a card requirement names
// it.
// WORK_UNIT_CASE: 984/4
#[test]
fn bounds_and_redaction_rejected_before_ffi() -> Result<(), String> {
    if EVENT_LOG_MAX_INSERTIONS != 1 {
        return Err("the admitted profile carries exactly one insertion".to_string());
    }
    let boundary = "a".repeat(EVENT_LOG_MAX_INSERTION_BYTES);
    let one_over = "a".repeat(EVENT_LOG_MAX_INSERTION_BYTES + 1);
    let units_boundary = "a".repeat(EVENT_LOG_MAX_INSERTION_UTF16_UNITS);
    let units_one_over = "a".repeat(EVENT_LOG_MAX_INSERTION_UTF16_UNITS + 1);
    let multibyte_one_over = "\u{20ac}".repeat(EVENT_LOG_MAX_INSERTION_UTF16_UNITS + 1);
    validate_event_log_insertion(boundary.as_str())
        .map_err(|_| "the exact byte bound must validate".to_string())?;
    validate_event_log_insertion(units_boundary.as_str())
        .map_err(|_| "the exact UTF-16 unit bound must validate".to_string())?;
    validate_event_log_insertion("").map_err(|_| "an empty insertion must validate".to_string())?;
    // A UTF-8 string never uses more UTF-16 code units than it has bytes, so
    // the byte bound is reached first for every reachable input; both one-over
    // inputs are still refused before any FFI. Case 6 proves the UTF-16 unit
    // guard inside `encode_wide_nul` and, over the whole
    // `validate_event_log_insertion` item, the production guard order: byte
    // bound, UTF-16 unit bound, embedded NUL, then protected marker. It does
    // not prove the byte guard's runtime reach here: the multibyte one-over
    // input above is refused by that byte guard, not by the UTF-16 guard.
    for (label, rejected) in [
        ("byte one-over", one_over.as_str()),
        ("UTF-16 unit one-over", units_one_over.as_str()),
        ("multibyte UTF-16 one-over", multibyte_one_over.as_str()),
    ] {
        check_rejected_before_ffi(label, rejected)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/5
#[test]
fn nul_and_protected_markers_refused_without_content() -> Result<(), String> {
    // The admitted vocabulary is pinned here by IDENTITY, not by count and not
    // by its own parse. `admitted_protected_markers` reads the production list,
    // so building the expectation from it would only attest self-consistency:
    // a mutation that substitutes a marker for a same-length or shorter word
    // (`authorization` -> `authorisation`, `authorization` -> `auth`,
    // `connectionstring` -> `connstr`, `passwd` -> `pwd2`) would keep every
    // count intact and still pass. The literal below is copied verbatim, in
    // order, from `PROTECTED_MARKERS` in src/event_log.rs (lines 491-503) and
    // is the independent expectation. With the identity pinned, the refusal
    // loop that follows is no longer self-attesting: it proves each pinned
    // marker is really refused by production.
    const PINNED_PROTECTED_MARKERS: [&str; 13] = [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "connectionstring",
        "connection_string",
        "privatekey",
        "private_key",
        "apikey",
        "api_key",
        "bearer",
        "authorization",
    ];
    let markers = admitted_protected_markers()?;
    if markers != PINNED_PROTECTED_MARKERS {
        return Err(format!(
            "protected-marker vocabulary identity drifted: parsed {markers:?} pinned {PINNED_PROTECTED_MARKERS:?}"
        ));
    }
    let mut candidates = vec![
        "before\0after".to_string(),
        "trailing\0".to_string(),
        "restarted with password=hunter2".to_string(),
        "token abc123 rotated".to_string(),
        "leaked SECRET value".to_string(),
        "bearer eyJhbGciOiJIUzI1NiJ9".to_string(),
    ];
    for marker in &markers {
        candidates.push(format!("probe {marker} probe"));
    }
    // The four independent hardcoded literals above already exercise `password`,
    // `token`, `secret` and `bearer` outside the generated probes. The control
    // below closes the other direction: an otherwise identical admissible
    // insertion must still validate, so the refusals are caused by the pinned
    // marker and not by the surrounding probe text or by a blanket refusal.
    validate_event_log_insertion("probe control probe")
        .map_err(|_| "an insertion carrying no pinned marker must still validate".to_string())?;
    let mut refused = Vec::new();
    for candidate in candidates {
        match validate_event_log_insertion(candidate.as_str()) {
            Ok(()) => {
                return Err("NUL and protected markers must be refused before FFI".to_string());
            }
            Err(error) => refused.push((candidate, error)),
        }
    }
    for (content, error) in refused {
        if error != EventLogError::InvalidInput {
            return Err("a refusal must be the typed InvalidInput category".to_string());
        }
        let rendered = format!("{error}");
        // The echo scan runs BEFORE the category pin below, so it is a check
        // this test actually reaches. Pinned behind the equality assert it could
        // only ever observe the one literal that carries no rejected token, so
        // an error text that started echoing the refused content would panic on
        // the assert and this scan would be dead code.
        for token in content.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            if token.len() > 3 && rendered.contains(token) {
                return Err(format!("refusal text echoed the rejected token {token}"));
            }
        }
        assert!(
            rendered == "event log record failed pre-FFI validation",
            "the refusal text must stay a fixed category, got {rendered}"
        );
    }
    // The refusal text above is only ONE channel. I15.4 requires that secret and
    // operator text never lands in logs, and a `println!`/`eprintln!`/`print!`/
    // `dbg!` on the report path carries the very insertion into stdout or
    // stderr, where the typed-category checks and the `EventLogError` shape
    // proofs above cannot see it: the leaf's own vocabulary, ports and
    // censuses are untouched by any of the four, so all fourteen cases stay
    // green while the first successful report leaks the operator text. The
    // crate lint table is NOT the proof either: `print_stdout`, `print_stderr`
    // and `dbg_macro` are only `warn` there (Cargo.toml 55-62), so they surface
    // under the `-D warnings` clippy gate and nowhere in this suite. So the
    // leaf's code text is refused those four macros outright, through the file's
    // existing `check_no_code_token`, which reads the one comment filter and so
    // cannot be satisfied by a `//`-commented call site either. `write!(` is
    // deliberately NOT in this list: the leaf's own `Display` impl uses it to
    // render a bounded numeric code, and banning the `fmt` spelling would be a
    // false positive.
    for macro_token in ["eprintln!", "dbg!", "println!", "print!"] {
        check_no_code_token(LEAF, macro_token)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/6
#[test]
fn wide_buffers_and_count_guard_are_source_proved() -> Result<(), String> {
    // The terminator is appended after both guard HEADS, so the buffer handed to
    // Win32 is one NUL-terminated UTF-16 payload. That is an ORDER property and
    // nothing more: the two guards are pinned by HEAD only, so emptying either
    // guard body leaves every step, the `wide.push(0)` count and the
    // after-terminator census below green. Their refusals are therefore NOT
    // nesting-proved here, exactly as the count guard's refusal IS nesting-proved
    // later in this same case.
    let encode = item_block(LEAF, "fn encode_wide_nul")?;
    check_step_order(
        &encode,
        &[
            "contains(&0)",
            "text.encode_utf16()",
            "EVENT_LOG_MAX_INSERTION_UTF16_UNITS",
            "wide.push(0)",
        ],
    )?;
    if occurrence_count(&encode, "wide.push(0)") != 1 {
        return Err("exactly one terminating NUL must be appended".to_string());
    }
    // And the buffer may not be disturbed AFTER that terminator. `wide.clear()`
    // between `wide.push(0);` and `Ok(wide)` satisfies every ordered step above,
    // satisfies the exactly-one-`push` count above, and hands Win32 an EMPTY
    // buffer that is still typed `&[u16]` - the report path would then format a
    // record from nothing, and every one of the fourteen cases would still be
    // green. So the lines after the terminator that mention `wide` must be
    // exactly the one return line that hands it to the caller. Measured on the
    // frozen leaf (src/event_log.rs 612-613) the only such line is `Ok(wide)`.
    let encode_lines = code_lines(&encode);
    let terminated = encode_lines
        .iter()
        .position(|line| *line == "wide.push(0);")
        .ok_or_else(|| "the terminating NUL statement must be a whole code line".to_string())?;
    let after_terminator: Vec<&str> = encode_lines[terminated + 1..]
        .iter()
        .copied()
        .filter(|line| line.contains("wide"))
        .collect();
    if after_terminator != ["Ok(wide)"] {
        return Err(format!(
            "nothing may touch the wide buffer after its terminator, found {after_terminator:?}"
        ));
    }
    // The registration call site keeps a null server, a retained caller buffer
    // and an adjacent safety obligation. Every search here is comment-blind, so
    // the steps are satisfied by code only: commenting any of them out, guards
    // included, fails this case instead of being read as the step.
    let register = item_block(LEAF, "fn register_local")?;
    check_step_order(
        &register,
        &["RegisterEventSourceW(std::ptr::null(), source_wide.as_ptr())"],
    )?;
    check_safety_comment_precedes(&register, "RegisterEventSourceW(")?;
    // The report call site keeps the one-element pointer array, the checked
    // `u16` count, the closed-profile count guard and its safety obligation. The
    // report type and the identifier are pinned as the admitted mapping reaching
    // Win32, not as literals: replacing either with a constant would make every
    // Host record informational and would satisfy no other proof in this file.
    // The two count steps are pinned as whole statements, tail and guard body
    // included, so a fallible-to-infallible conversion or an emptied guard body
    // fails here instead of passing on a substring. Neither step survives as a
    // comment either: the search reads the code text only.
    // The nine `ReportEventW` arguments are pinned whole-line and in position by
    // the shared helper, together with the call's closing parenthesis.
    let report = item_block(LEAF, "fn report_validated")?;
    check_report_event_arguments(&report)?;
    check_safety_comment_precedes(&report, "ReportEventW(")?;
    // NESTING, not order, for the same trap case 9 already refuses for the null
    // guard: an emptied `if string_count != EVENT_LOG_MAX_INSERTIONS {}` body
    // followed by an unconditional `return Err(EventLogError::InvalidInput);`
    // LATER in the same item satisfies every ordered step above, and the report
    // would then run with an over-count. So the guard's own slice is taken with
    // the same brace matcher, and the refusal must live INSIDE it.
    let refusal = "return Err(EventLogError::InvalidInput);";
    let guard_anchor = "if string_count != EVENT_LOG_MAX_INSERTIONS";
    let guard_at = report
        .find(guard_anchor)
        .ok_or_else(|| "the count guard must exist".to_string())?;
    let count_guard = code_text(&item_block(&report, guard_anchor)?);
    check_step_order(&count_guard, &[refusal])?;
    // No return may precede the guard either, or the report is reachable with an
    // over-count by a route the guard never sees.
    if code_text(&report[..guard_at]).contains("return") {
        return Err("no return may precede the count guard".to_string());
    }
    // And the refusal must never run outside the guard as an unconditional
    // late exit, which the inside/outside counts make fail.
    if occurrence_count(&report, refusal) != occurrence_count(&count_guard, refusal) {
        return Err("the over-count refusal must never run outside the count guard".to_string());
    }
    // The public validator proves the pre-FFI guard order inside production:
    // byte bound, then UTF-16 unit bound, then embedded NUL, then the
    // protected-marker scan. This is the validator's own UTF-16 guard, not the
    // one inside `encode_wide_nul` above.
    let validate = item_block(LEAF, "pub fn validate_event_log_insertion")?;
    check_step_order(
        &validate,
        &[
            "insertion.len() > EVENT_LOG_MAX_INSERTION_BYTES",
            "insertion.encode_utf16().count() > EVENT_LOG_MAX_INSERTION_UTF16_UNITS",
            "insertion.as_bytes().contains(&0)",
            "contains_protected_marker(insertion)",
        ],
    )?;
    // Both retained buffers stay live across both calls in the same scope. The
    // proof reads the code text, so a commented-out call site proves nothing.
    let submit = code_text(&item_block(LEAF, "fn submit_validated")?);
    if !submit.contains("report_validated(") {
        return Err("the retained-buffer proof must read the Windows scope".to_string());
    }
    check_step_order(
        &submit,
        &[
            "let source_wide = encode_wide_nul(event.source())?;",
            "let insertion_wide = encode_wide_nul(insertion)?;",
            "let source = RegisteredEventSource::register_local(&source_wide)?;",
            "report_validated(source.handle, event, &insertion_wide)?;",
        ],
    )?;
    // ORDER alone is not the retained-buffer property, and a BLACKLIST of
    // release spellings over the slice between the two steps is not either:
    // `clear()`, `truncate(0)`, `resize(0, 0)`, `dedup()`, `fill(0)`,
    // `as_mut_slice().fill(0)`, `mem::take`, `mem::replace`, `swap_with_vec`,
    // `drop_in_place`, a hand-off to a helper and a shadowing redeclaration all
    // release or duplicate the very buffer Win32 is handed, none of them
    // spelling `drop(`, `mem::forget` or `ManuallyDrop`, and a release placed
    // BEFORE the registration step or AFTER the report step is not in that
    // slice at all. The POSITIVE property is stated instead, and it is stronger
    // and simpler: inside this item each wide buffer name may appear EXACTLY
    // TWICE - once where it is created and once where it is passed to the call -
    // so no release, no reborrow, no shadow, no helper hand-off and no extra use
    // can exist anywhere in the item, on either side of either call. Measured on
    // the frozen leaf (src/event_log.rs 720-723): `source_wide` occurs twice,
    // `insertion_wide` occurs twice, and the item contains zero `drop(`,
    // `clear(` and `mem::forget`, so the count holds today. The three-token
    // blacklist is dropped rather than kept: this count subsumes every spelling
    // it listed, in strictly more of the item, so retaining it would add a
    // second, weaker statement of the same property instead of new binding.
    for buffer in ["source_wide", "insertion_wide"] {
        let uses = occurrence_count(&submit, buffer);
        if uses != 2 {
            return Err(format!(
                "each wide buffer must be used exactly twice in submit_validated, {buffer} appears {uses} times"
            ));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/7
#[test]
fn acquisition_failure_yields_no_receipt() -> Result<(), String> {
    // Runtime type proof: the value carries a bounded numeric code and nothing
    // else, so insertion text cannot travel with an acquisition failure.
    let failure = EventLogError::RegistrationFailed { code: 15007 };
    if format!("{failure}") != "event log source acquisition failed (15007)" {
        return Err("acquisition failure must carry only its numeric code".to_string());
    }
    // Source proof: the variant declares exactly one numeric field.
    let variant = item_block(LEAF, "RegistrationFailed {")?;
    let fields = code_lines(&variant);
    if fields != ["code: u32,"] {
        return Err(format!("acquisition failure fields drifted: {fields:?}"));
    }
    // Source proof: a null handle branch yields that error and no owner. This
    // cannot be runtime-induced: the leaf has no injection seam and a mocked
    // API is forbidden, so the branch is proved against the frozen text.
    let register = item_block(LEAF, "fn register_local")?;
    let branch_start = register
        .find("if handle.is_null() {")
        .ok_or_else(|| "the null-handle branch must exist".to_string())?;
    let branch_end = register
        .find("} else {")
        .ok_or_else(|| "the null-handle branch must not construct an owner".to_string())?;
    let null_branch = code_text(&register[branch_start..branch_end]);
    check_step_order(
        &null_branch,
        &[
            "GetLastError()",
            "Err(EventLogError::RegistrationFailed { code })",
        ],
    )?;
    if null_branch.contains("Ok(") {
        return Err("a null handle must never yield a source owner".to_string());
    }
    // Source proof: the public function returns a fallible receipt. That it
    // propagates before building one is pinned by the two ordered steps further
    // below, not by the assertion this comment sits above.
    if !code_text(LEAF).contains(") -> Result<EventLogReceipt, EventLogError> {") {
        return Err("the public report function must return a fallible receipt".to_string());
    }
    // The propagation is pinned WITH its `?`, as a whole statement, exactly as
    // case 9 pins `register_local(&source_wide)?;` and
    // `report_validated(...)?;`. Pinning only the call name admitted the
    // fallible-to-infallible edit: a bare `report_admitted_local_event(...);`
    // that discards the `Result` satisfies both steps below while
    // `report_local_event` returns `Ok(receipt)` after a FAILED registration.
    let host = item_block(LEAF, "pub fn report_local_event")?;
    check_step_order(
        &host,
        &[
            "report_admitted_local_event(AdmittedLocalEventLogEvent::Host(event), insertion)?;",
            "Ok(EventLogReceipt::accepted(event))",
        ],
    )?;
    // The Kernel sibling (src/event_log.rs 587-593) is the same call with the
    // same shape, so it carries the same obligation and gets the same proof
    // rather than being left to the Host step: a discarded `Result` there would
    // still let `report_kernel_event` return `Ok(receipt)` after a FAILED
    // registration, and the Host proof reads a different item entirely.
    let kernel = item_block(LEAF, "pub fn report_kernel_event")?;
    check_step_order(
        &kernel,
        &[
            "report_admitted_local_event(AdmittedLocalEventLogEvent::Kernel(event), insertion)?;",
            "Ok(KernelEventLogReceipt::accepted(event))",
        ],
    )?;
    // Both step pins above are TEXT matches, so a leaf can satisfy them and
    // still return a receipt for a FAILED acquisition, in the two ways an
    // ordered search over frozen text cannot see: parking the pinned statement
    // where it never runs while the real call discards its `Result`, and
    // shadowing the callee with a second, permissive item. Both are closed
    // structurally below rather than by more pinned text.
    //
    // The unique declaration is what kills the shadow. The frozen leaf declares
    // `report_admitted_local_event` EXACTLY ONCE (src/event_log.rs 595), so a
    // second declaration - a decoy that returns `Ok(())` while the pinned
    // statement still sits in the real item - is now a red fact instead of an
    // item the two call sites could silently bind to.
    if occurrence_count(LEAF, "fn report_admitted_local_event") != 1 {
        return Err(
            "the leaf must declare exactly one report_admitted_local_event item".to_string(),
        );
    }
    // The unique declaration is also READ, not merely counted, because a decoy
    // that RENAMES the real callee and hands the pinned call site to a
    // permissive item still leaves exactly one declaration of that name. The
    // declared body is pinned to the two steps the two pinned call sites reach -
    // pre-FFI validation, then the submission - so the item the pinned call sites
    // reach cannot return `Ok(())` without doing the work. Uniqueness of that path
    // is NOT censused: nothing here counts `submit_validated` call sites, so a
    // second route to the submission would satisfy every pin. Both steps hold on
    // the frozen leaf (src/event_log.rs 599-600).
    let admitted = item_block(LEAF, "fn report_admitted_local_event")?;
    let admitted_code = code_text(&admitted);
    let submitted = "submit_validated(event, insertion)";
    check_step_order(
        &admitted_code,
        &["validate_event_log_insertion(insertion)?;", submitted],
    )?;
    // A pinned statement can be PRESENT and IN ORDER and still never run: parked
    // inside an `if`, a `match`, a `loop`, a `while`, a `for` or a bare block,
    // while the real call discards its `Result`. A two-literal parking blacklist
    // does not see that - six compile-clean spellings survive `if false` and
    // `cfg(any())`, the sharpest being
    // `validate_event_log_insertion(insertion)?; if insertion.is_empty()
    //  { submit_validated(event, insertion) } else { Ok(()) }`,
    // which fabricates an accepted receipt for EVERY valid report while both
    // pinned steps stay present and in order. So the POSITIVE property is
    // stated instead, in the same shape cases 6 and 9 already use for the null
    // guard and the count guard: the submission must be a TOP-LEVEL statement of
    // this item, at brace depth zero. Measured on the frozen leaf
    // (src/event_log.rs 599-600) the depth is 0.
    let Some(depth) = brace_depth_of(&admitted_code, submitted) else {
        return Err("the pinned submission step is missing from this item".to_string());
    };
    if depth != 0 {
        return Err(format!(
            "the pinned submission must be top-level, found brace depth {depth}"
        ));
    }
    // The two parking literals are kept as a READABILITY TRIPWIRE for the two
    // spellings a reader is most likely to write on sight. They are NOT the
    // proof: the depth scan above is what carries the claim, and it names the
    // whole class rather than two members of it. Both read `code_lines` through
    // `check_no_code_token`, the one comment filter in this file.
    for parking in ["if false", "cfg(any())"] {
        check_no_code_token(LEAF, parking)?;
    }
    // And the conditional-compilation surface is whitelisted to the platform
    // gates the leaf already declares - seven `#[cfg(windows)]` (src/event_log.rs
    // 67, 603, 621, 626, 652, 670, 715) and one `#[cfg(not(windows))]` (727) -
    // so no OTHER `cfg` can switch a body off either. `cfg!(windows)` at
    // src/event_log.rs 485 is a macro invocation, not an attribute: it does not
    // start a `#[cfg` line, so the build-flag body case 10 proves is untouched.
    // Measured on the frozen leaf: `if false` is absent from the code text,
    // `cfg(any())` is absent, and the eight attribute lines above are exactly
    // those eight. This is a COUNT and deliberately not more: it says how many
    // platform gates there are and that no third spelling exists, which is
    // blind to two of the eight being exchanged. Which gate each ITEM carries is
    // pinned per item, by name, in case 10.
    let mut cfg_attributes = 0_usize;
    for line in code_lines(LEAF) {
        if !line.starts_with("#[cfg") {
            continue;
        }
        cfg_attributes += 1;
        if line != "#[cfg(windows)]" && line != "#[cfg(not(windows))]" {
            return Err(format!(
                "the leaf must add no further cfg attribute: {line}"
            ));
        }
    }
    if cfg_attributes != 8 {
        return Err(format!(
            "the leaf must keep exactly eight cfg attributes, found {cfg_attributes}"
        ));
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/8
#[test]
fn report_failure_keeps_only_the_numeric_code() -> Result<(), String> {
    // Runtime type proof: the refused-report value carries only the bounded
    // Win32 code, never the reported insertion text.
    let failure = EventLogError::ReportFailed { code: 15005 };
    if format!("{failure}") != "event log report failed (15005)" {
        return Err("report failure must carry only its numeric code".to_string());
    }
    let variant = item_block(LEAF, "ReportFailed {")?;
    let fields = code_lines(&variant);
    if fields != ["code: u32,"] {
        return Err(format!("report failure fields drifted: {fields:?}"));
    }
    // Source proof, stated exactly as far as the assertion reaches: the refused
    // branch carries no `Ok(`, an `Ok(())` exists somewhere at or after
    // `} else {`, and `GetLastError()` appears inside the refused branch.
    // "Immediately after the failed call" is NOT pinned: the search is a
    // substring search over the branch, so an intervening statement between them
    // would be invisible here.
    let report = item_block(LEAF, "fn report_validated")?;
    let branch_start = report
        .find("if accepted == 0 {")
        .ok_or_else(|| "the refused-report branch must exist".to_string())?;
    let branch_end = report
        .find("} else {")
        .ok_or_else(|| "the refused-report branch must not accept".to_string())?;
    let refused_branch = code_text(&report[branch_start..branch_end]);
    check_step_order(
        &refused_branch,
        &[
            "GetLastError()",
            "Err(EventLogError::ReportFailed { code })",
        ],
    )?;
    if refused_branch.contains("Ok(") || !code_text(&report[branch_end..]).contains("Ok(())") {
        return Err("only the accepted branch may return success".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/9
#[test]
fn handle_deregisters_exactly_once_and_is_private() -> Result<(), String> {
    // No derive at all: the owner is neither Copy nor Clone.
    let attributes = preceding_attributes(LEAF, "struct RegisteredEventSource")?;
    if attributes.iter().any(|line| line.starts_with("#[derive")) {
        return Err("the handle owner must stay neither Copy nor Clone".to_string());
    }
    let owner = item_block(LEAF, "struct RegisteredEventSource")?;
    let fields = code_lines(&owner);
    if fields != ["handle: HANDLE,"] {
        return Err(format!(
            "the handle owner must keep one private field: {fields:?}"
        ));
    }
    if occurrence_count(LEAF, "DeregisterEventSource(") != 1 {
        return Err("deregistration must appear exactly once in the leaf".to_string());
    }
    check_no_code_token(LEAF, "CloseHandle")?;
    let release = item_block(LEAF, "impl Drop for RegisteredEventSource")?;
    // NESTING, not order. Ordered search over the whole block only proves that
    // the guard precedes the call, which still holds if the call moves out of
    // the guard body or the guard is inverted to `==`. The property that
    // matters is that deregistration runs ONLY under the null guard, so the
    // proof reads the guard's own slice, taken with the same brace matcher the
    // other slices use: the call must be inside it, no second call may sit
    // outside it, and no `return` may appear inside the guard.
    let guard_anchor = "if !self.handle.is_null()";
    let guard_at = release
        .find(guard_anchor)
        .ok_or_else(|| "the release must keep the null guard".to_string())?;
    let guarded = code_text(&item_block(&release, guard_anchor)?);
    check_step_order(&guarded, &["DeregisterEventSource(self.handle)"])?;
    if guarded.contains("return") {
        return Err("the null guard must not return before deregistering".to_string());
    }
    if occurrence_count(&release, "DeregisterEventSource(")
        != occurrence_count(&guarded, "DeregisterEventSource(")
    {
        return Err("deregistration must never run outside the null guard".to_string());
    }
    check_safety_comment_precedes(&release, "DeregisterEventSource(self.handle)")?;
    // And no `return` may appear BEFORE the guard either. The scan above reads
    // the guard's own slice, so it cannot see one that leaves `drop` before the
    // guard is even reached, and three such suppressions satisfy every
    // assertion above: a bare `return;` placed above the guard; the handle
    // zeroed (`self.handle = std::ptr::null_mut();`) and an early `return;`
    // above the guard, which makes the deregistration provably dead. Each of the
    // two keeps all fourteen cases green today, because the pinned steps, the
    // counts, the safety-comment adjacency and the "never outside the guard" count
    // are all unaffected by a statement that runs before the slice they read. A
    // `return` left behind as a `//` comment is deliberately NOT in that
    // enumeration: the scan below is comment-blind and cannot see one at all. So
    // the whole block from `fn drop` up to the guard is refused any `return` word,
    // comment-blind like every other search here, so this - and only this - is
    // what makes "nothing can leave `drop` before the deregistration runs" true.
    if code_text(&release[..guard_at]).contains("return") {
        return Err("nothing may return from drop before the null guard".to_string());
    }
    // Finally the CALL ITSELF, which the guard slice above admits at any depth:
    // a bare block, an `if`, a `while`, a `for` or a hand-off wrapper around it
    // all keep the pinned step present, in order and inside the guard, while
    // making the deregistration never run. Measured on the frozen leaf the call
    // sits at brace depth 1 inside the guard slice and the ONLY line in that
    // slice that opens a brace is the `unsafe` block that carries the FFI
    // obligation - which is exactly why the depth is 1 and not 0, and why a
    // second brace-opening line anywhere in the guard is refused. Read over
    // `code_text`, so a wrapper that survives only as a `//` comment is not
    // found here at all rather than being measured at depth zero.
    let release_call = "DeregisterEventSource(self.handle)";
    let Some(depth) = brace_depth_of(&guarded, release_call) else {
        return Err("the deregistration call must exist inside the null guard".to_string());
    };
    let openings: Vec<&str> = code_lines(&guarded)
        .into_iter()
        .filter(|line| line.contains('{'))
        .collect();
    if depth != 1 || openings != ["unsafe {"] {
        return Err(format!(
            "the deregistration must be a top-level statement of the null guard wrapped in the unsafe block only, found brace depth {depth} and brace-opening lines {openings:?}"
        ));
    }
    // The error path unwinds the same scope while the owner is still live, so
    // `Drop` releases exactly once there too.
    let submit = code_text(&item_block(LEAF, "fn submit_validated")?);
    if !submit.contains("report_validated(") {
        return Err("the release proof must read the Windows scope".to_string());
    }
    check_step_order(
        &submit,
        &[
            "let source = RegisteredEventSource::register_local(&source_wide)?;",
            "report_validated(source.handle, event, &insertion_wide)?;",
        ],
    )?;
    let exported = event_log_reexport_names()?;
    for private in [
        "RegisteredEventSource",
        "AdmittedLocalEventLogEvent",
        "encode_wide_nul",
        "submit_validated",
        "report_validated",
    ] {
        if exported.iter().any(|name| name.contains(private)) {
            return Err(format!("{private} must stay unexported"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 984/10
#[test]
fn unavailable_path_is_fail_closed_without_content() -> Result<(), String> {
    if is_event_log_supported() != cfg!(windows) {
        return Err("support flag must match the Windows build".to_string());
    }
    // The runtime comparison above holds for any body that returns the build
    // flag, so a hardcoded `true` body would satisfy it on Windows without ever
    // consulting `cfg!`. The gate itself is therefore pinned in the frozen
    // text: the flag's body is the build predicate and nothing else.
    let gate = item_block(LEAF, "pub const fn is_event_log_supported")?;
    let body = code_lines(&gate);
    if body != ["cfg!(windows)"] {
        return Err(format!(
            "the support flag must stay gated on cfg!: {body:?}"
        ));
    }
    // Which gate each platform-gated item carries is the other half of platform
    // gating, and it is what keeps the fail-closed arm above from becoming the
    // live one on Windows. Proved per item in the helper; stated here because
    // the property is this case's, not the helper's.
    check_platform_gate_ownership()?;
    // And the OUTCOME SEPARATION the issue body requires ("Keep
    // validated/not-attempted/submitted/OS-accepted/failed/unknown outcomes
    // separate") is decided in one place at the platform boundary, in
    // `impl From<EventLogError> for WindowsAdapterError`, and no case in this
    // file read it. So `UnsupportedPlatform` - the one error that says nothing
    // was attempted - could be remapped to `Self::Failed`, which says an
    // attempt failed, or merged away entirely, with every other case here still
    // green. The arms are therefore pinned as a whole ordered sequence, in the
    // order the issue lists them. Measured on the frozen leaf (src/event_log.rs
    // 329-339) the impl is exactly the three arms below, the third wrapped over
    // two lines by the rustfmt width, so its pattern and its outcome are pinned
    // as the two steps it really is on the frozen text.
    let outcome_mapping = item_block(LEAF, "impl From<EventLogError> for WindowsAdapterError")?;
    check_step_order(
        &outcome_mapping,
        &[
            "EventLogError::InvalidInput => Self::InvalidInput,",
            "EventLogError::Unavailable | EventLogError::UnsupportedPlatform => Self::Unavailable,",
            "EventLogError::RegistrationFailed { .. } | EventLogError::ReportFailed { .. } => {",
            "Self::Failed",
        ],
    )?;
    if occurrence_count(&outcome_mapping, "=>") != 3 {
        return Err("the outcome mapping must stay exactly three match arms".to_string());
    }
    let probe = "probe-984-redacted-boundary-ok";
    let outcome = report_local_event(AdmittedEventLogEvent::ServiceStart, probe);
    check_fail_closed_probe(probe, outcome)
}

// WORK_UNIT_CASE: 984/11
#[test]
fn availability_stays_unknown_without_application_substitution() -> Result<(), String> {
    let availability = item_block(LEAF, "pub enum EventLogSourceAvailability")?;
    let variants = code_lines(&availability);
    if variants != ["Unknown,"] {
        return Err(format!(
            "availability must stay a single Unknown state: {variants:?}"
        ));
    }
    let host = item_block(LEAF, "impl EventLogReceipt")?;
    check_step_order(
        &host,
        &[
            "const fn accepted(event: AdmittedEventLogEvent) -> Self {",
            "availability: EventLogSourceAvailability::Unknown",
        ],
    )?;
    let kernel = item_block(LEAF, "impl KernelEventLogReceipt")?;
    check_step_order(
        &kernel,
        &[
            "const fn accepted(event: AdmittedKernelEventLogEvent) -> Self {",
            "availability: EventLogSourceAvailability::Unknown",
        ],
    )?;
    // No degraded Application profile is substituted anywhere in the port.
    check_no_code_token(LEAF, "application")?;
    check_known_source_constants_are_the_only_sources()?;
    // No runtime `format!("{state:?}")` comparison here: both sides of that
    // comparison come from the same binding, so it can fail only on a rename,
    // and a rename already breaks the variants census above. The availability
    // state is therefore proved where it is decided: a single `Unknown`
    // variant, and that every receipt constructor stores exactly it.
    Ok(())
}

// WORK_UNIT_CASE: 984/12
#[test]
fn no_timeout_cancellation_or_delivery_guarantee_is_published() -> Result<(), String> {
    // The port offers no timeout, cancellation, retry or delivery control. This
    // vocabulary IS the whole claim, so it names the near-synonyms a future edit
    // could reach for (a deadline, a polled wait, a clock read, a sleep) and not
    // only the six words of the card sentence. The scan stays comment-blind on
    // purpose: `timeout` and `deliver` survive in the leaf only inside the
    // published disclaimers proved over raw text below.
    for token in [
        "timeout", "cancel", "retry", "deliver", "abort", "backoff", "deadline", "wait_ms", "poll",
        "instant", "sleep",
    ] {
        check_no_code_token(LEAF, token)?;
    }
    for anchor in ["pub fn report_local_event", "pub fn report_kernel_event"] {
        let published = preceding_doc(LEAF, anchor)?;
        for phrase in [
            "synchronous",
            "may block",
            "no timeout",
            "does not interrupt",
            "OS acceptance only",
        ] {
            if !published.contains(phrase) {
                return Err(format!("{anchor} must publish the limitation: {phrase}"));
            }
        }
    }
    let receipt = preceding_doc(LEAF, "pub struct EventLogReceipt")?;
    for phrase in [
        "OS acceptance only",
        "not delivery",
        "not registered-source proof",
    ] {
        if !receipt.contains(phrase) {
            return Err(format!("the receipt must publish the limitation: {phrase}"));
        }
    }
    let exported = event_log_reexport_names()?;
    if exported.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        lower.contains("deliver") || lower.contains("timeout")
    }) {
        return Err("no delivery or timeout guarantee may be exported".to_string());
    }
    Ok(())
}

/// Case 13 writes a run-correlated record for real through the port. The
/// readback half is INCOMPLETE LIVE SUPPORT, not a skipped success: no approved
/// isolated registered test source exists on this machine (the card defers its
/// provisioning to approved test/installation setup).
///
/// The in-leaf readback item the card describes cannot be NAMED from this
/// integration target, and NOT because the crate declares no test-only `cfg`:
/// the feature EXISTS. `Cargo.toml:9-11` is `[features]` / `default = []` /
/// `test-support = []`. What is absent is any way to enable it for this target.
/// The 63-line manifest declares no `[dev-dependencies]` and no `[[test]]`, and
/// `cfg(test)` does not apply to the library when it is compiled as a dependency
/// of an integration test, so `test-support` is enabled by no test target here.
/// The feature-gated surface in `src/lib.rs:39-92` belongs to other cells'
/// proofs, and the `event_log` reexport at `src/lib.rs:132-141` is
/// unconditional and publishes no readback item. `src/lib.rs` is card READ
/// ONLY, so no readback reexport may be added here to close the gap.
///
/// Reading the Application log is refused as a fallback: it would prove nothing
/// about the intended registered-source profile. What follows therefore proves
/// the correlation and the honest write disposition only, and
/// `check_readback_half_is_unreachable` is a deliberate TRIPWIRE: whoever later
/// adds the deferred readback must rewrite this case on purpose, not discover
/// the change through a red test.
// WORK_UNIT_CASE: 984/13
#[test]
fn isolated_windows_write_by_run_correlation_reports_its_disposition() -> Result<(), String> {
    let correlation = run_correlation()?;
    let probe = format!("probe-984-run {correlation}");
    // NO length inequality here: the probe is a 14-byte prefix plus the pid in
    // hex, a dash and a nanosecond clock in hex, so it is at most 39 bytes
    // against the 1024-byte bound at src/event_log.rs:77. A bounded correlation
    // string cannot approach that bound, so `probe.len() >= 1024` can never
    // hold and asserting it would be an unfalsifiable guard rather than a
    // proof. The bound is pinned by the constants in cases 1 and 4, and the
    // probe's own admissibility is proved by the validation call below, which
    // is the check that can actually fail.
    validate_event_log_insertion(probe.as_str())
        .map_err(|_| "the run-correlated probe must be admissible".to_string())?;
    // DISPOSITION, named rather than silently accepted. Both outcomes are
    // admissible: the OS may accept the record, and a machine without the
    // approved isolated registered source refuses it typed. A refusal is
    // therefore NOT a failure of this case and no requirement that the write
    // succeed is invented here; what is required is that the outcome is one of
    // these typed values rather than something unexamined, and that an accepted
    // receipt carries the admitted mapping. Each refusal arm NAMES its typed
    // value so the disposition is explicit in the source rather than silently
    // absorbed into an accepted outcome; the arm itself is empty, so a passing
    // run reveals nothing about which disposition occurred. The package lints are
    // only `warn` (`print_stdout`, `print_stderr`, `dbg_macro`: Cargo.toml
    // 55-62), so it is the workspace `-D warnings` clippy gate that makes a print
    // here a failure, and the disposition is carried by the arm that ran rather
    // than by a log line.
    match report_local_event(AdmittedEventLogEvent::ServiceStart, probe.as_str()) {
        Ok(receipt) => {
            if receipt.event_id() != 100 || receipt.source() != EVENT_LOG_SOURCE {
                return Err("the correlated write must carry the admitted event".to_string());
            }
            if receipt.source_availability() != EventLogSourceAvailability::Unknown {
                return Err("a correlated write must not claim source registration".to_string());
            }
        }
        Err(EventLogError::InvalidInput) => {
            return Err("an admissible correlated probe must not fail validation".to_string());
        }
        Err(
            EventLogError::UnsupportedPlatform
            | EventLogError::Unavailable
            | EventLogError::RegistrationFailed { .. }
            | EventLogError::ReportFailed { .. },
        ) => {}
    }
    check_readback_half_is_unreachable()
}

// NAME, disclosed: the name carries both halves of the card sentence, but this
// case proves only the FFI-island and unsafe-block half; the "no authority
// change" half is not observable from frozen text and is discharged in the #984
// work-unit report. The name is not renamed, because the checklist evidence and
// the accepted filing reference it.
// WORK_UNIT_CASE: 984/14
#[test]
fn port_keeps_single_ffi_island_and_no_authority_change() -> Result<(), String> {
    for call in [
        "RegisterEventSourceW(",
        "ReportEventW(",
        "DeregisterEventSource(",
    ] {
        if occurrence_count(LEAF, call) != 1 {
            return Err(format!("expected exactly one {call} call site in the leaf"));
        }
    }
    for token in [
        "CloseHandle",
        "RegOpenKey",
        "RegSetValue",
        "RegCreateKey",
        "RegDeleteKey",
        "OpenSCManager",
        "CreateService",
        "DeleteService",
        "ChangeServiceConfig",
        "wevtutil",
        "std::process",
        "thread::spawn",
    ] {
        check_no_code_token(LEAF, token)?;
    }

    // No unsafe DECLARATION surface: an `unsafe fn`, `unsafe impl` or
    // `unsafe trait` would relocate an FFI obligation away from the call sites
    // that carry the `// SAFETY:` annotations checked below and in cases 6 and
    // 9. This is an obligation INDEPENDENT of the census below and both must
    // hold: an added declaration breaks this scan and the census as well, while
    // a plain added unsafe block breaks only the census. Which of the two runs
    // first is therefore a readability choice, not a correctness argument.
    for declaration in ["unsafe fn", "unsafe impl", "unsafe trait"] {
        check_no_code_token(LEAF, declaration)?;
    }

    // Unsafe CENSUS, over CODE LINES. The literal `unsafe {` occurs once,
    // because four of the five blocks read `let x = unsafe {`; counting that
    // spelling would see one block and miss four. Required: exactly five
    // (src/event_log.rs 632, 639, 658, 684, 703).
    let unsafe_blocks = code_lines(LEAF)
        .into_iter()
        .filter(|line| line.contains("unsafe"))
        .count();
    if unsafe_blocks != 5 {
        return Err(format!(
            "the leaf must keep exactly five unsafe blocks, found {unsafe_blocks}"
        ));
    }
    // The two `GetLastError()` obligations look undocumented at a glance and
    // are not: in both items the `// SAFETY:` comment is the FIRST STATEMENT
    // INSIDE the unsafe block, directly above the call (src/event_log.rs 640-642
    // and 704-706), which is exactly what `check_safety_comment_precedes` reads.
    check_safety_comment_precedes(&item_block(LEAF, "fn register_local")?, "GetLastError()")?;
    check_safety_comment_precedes(&item_block(LEAF, "fn report_validated")?, "GetLastError()")?;
    // The scope/diff half of this case's card sentence ("no authority change")
    // is not a property any test over frozen text can observe: it is discharged
    // in the #984 work-unit report, which shows the diff confined to this test
    // file plus the optional in-leaf readback. #837/#852 own handle descriptors,
    // so no case here pins the `HANDLE` newtype or its ownership contract.

    if occurrence_count(MANIFEST, "windows-sys") != 1 {
        return Err("the port must keep exactly one windows-sys island".to_string());
    }
    if occurrence_count(MANIFEST, "Win32_System_EventLog") != 1 {
        return Err("the Event Log feature must be declared exactly once".to_string());
    }
    let exported = event_log_reexport_names()?;
    for pinned in [
        "AdmittedEventLogEvent",
        "AdmittedKernelEventLogEvent",
        "EVENT_LOG_MAX_INSERTION_BYTES",
        "EVENT_LOG_MAX_INSERTION_UTF16_UNITS",
        "EVENT_LOG_MAX_INSERTIONS",
        "EVENT_LOG_QUEUE_CAPACITY",
        "EVENT_LOG_SERVICE_FAILURE_ID",
        "EVENT_LOG_SERVICE_START_ID",
        "EVENT_LOG_SERVICE_STOP_ID",
        "EVENT_LOG_SOURCE",
        "EventLogError",
        "EventLogReceipt",
        "EventLogSeverity",
        "EventLogSourceAvailability",
        "KERNEL_EVENT_LOG_CRASH_ID",
        "KERNEL_EVENT_LOG_QUARANTINE_ID",
        "KERNEL_EVENT_LOG_RECOVERY_ID",
        "KERNEL_EVENT_LOG_RESTART_EXHAUSTED_ID",
        "KERNEL_EVENT_LOG_SOURCE",
        "KERNEL_EVENT_LOG_STARTUP_ID",
        "KernelEventLogReceipt",
        "is_event_log_supported",
        "report_kernel_event",
        "report_local_event",
        "validate_event_log_insertion",
    ] {
        if !exported.iter().any(|name| name.as_str() == pinned) {
            return Err(format!("the facade must still export {pinned}"));
        }
    }
    for fragment in [
        "remote", "registry", "collect", "forward", "export", "readback", "config", "scm",
        "install",
    ] {
        if exported
            .iter()
            .any(|name| name.to_ascii_lowercase().contains(fragment))
        {
            return Err(format!("no authority export may contain {fragment}"));
        }
    }
    Ok(())
}
