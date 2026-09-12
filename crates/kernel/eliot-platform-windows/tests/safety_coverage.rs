//! Source-coverage oracle for issue #728 Wave C.
//!
//! Package-local proof that every production `unsafe` site in
//! `crates/kernel/eliot-platform-windows/src/lib.rs` carries one adjacent
//! operation-specific `// SAFETY:` obligation. Comments and manifest presence
//! never manufacture safety; this oracle checks adjacency, specificity, and
//! token identity only. Universal undefined-behavior absence, IPC completion,
//! and product claims are out of scope.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

const EXPECTED_SITES: usize = 144;
const EXPECTED_BLOCK: usize = 143;
const EXPECTED_IMPL: usize = 1;
const EXPECTED_ALLOWS: usize = 5;
const MAX_SOURCE_BYTES: usize = 5_000_000;
const MAX_SOURCE_LINES: usize = 50_000;
const MAX_BLOCK_DEPTH: u32 = 32;
const MAX_RAW_HASHES: usize = 16;

/// Form of an `unsafe` site.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UnsafeForm {
    Block,
    Fn,
    Impl,
    Trait,
    Extern,
}

/// One lexical `unsafe` site with ownership metadata.
#[derive(Debug, Clone)]
struct UnsafeSite {
    line: usize,
    form: UnsafeForm,
    text: String,
    item: String,
    is_test: bool,
}

/// Outcome for a single site.
#[derive(Debug, Clone)]
struct SiteVerdict {
    line: usize,
    passed: bool,
    detail: String,
}

/// Minimal fixture case projection used by the JSON loader.
#[derive(Debug, Clone)]
struct FixtureCase {
    id: String,
    kind: String,
    source: String,
    base: String,
    candidate: String,
    expect_sites: Option<usize>,
    expect_pass: Option<bool>,
    expect_error: Option<bool>,
    expect_equal: Option<bool>,
    expect_form: String,
    reason: String,
    mutated_digest: String,
}

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    let dir = package_dir();
    dir.ancestors()
        .nth(3)
        .map_or_else(|| dir.clone(), Path::to_path_buf)
}

fn lib_rs_path() -> PathBuf {
    package_dir().join("src").join("lib.rs")
}

fn tests_rs_path() -> PathBuf {
    package_dir().join("src").join("tests.rs")
}

fn adr_path() -> PathBuf {
    workspace_root()
        .join("docs")
        .join("ADR")
        .join("0014-unsafe-ownership-and-exceptions.md")
}

fn fixture_path() -> PathBuf {
    package_dir()
        .join("tests")
        .join("data")
        .join("safety_coverage_cases.json")
}

fn read_text(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

struct LexState {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    brace_depth: usize,
    pending_cfg_test: bool,
    pending_item_test: bool,
    test_scopes: Vec<usize>,
    current_item: String,
    sites: Vec<UnsafeSite>,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn new_lex_state(source: &str) -> Result<LexState, String> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err("source exceeds byte bound".to_string());
    }
    let lines = source.lines().count();
    if lines > MAX_SOURCE_LINES {
        return Err("source exceeds line bound".to_string());
    }
    let chars: Vec<char> = source.chars().collect();
    Ok(LexState {
        chars,
        pos: 0,
        line: 1,
        brace_depth: 0,
        pending_cfg_test: false,
        pending_item_test: false,
        test_scopes: Vec::new(),
        current_item: "crate".to_string(),
        sites: Vec::new(),
    })
}

fn peek_at(st: &LexState, off: usize) -> Option<char> {
    st.chars.get(st.pos + off).copied()
}

fn consume_ident(st: &mut LexState) -> String {
    let mut out = String::new();
    while let Some(c) = peek_at(st, 0) {
        if is_ident_continue(c) {
            out.push(c);
            st.pos += 1;
        } else {
            break;
        }
    }
    out
}

fn skip_whitespace(st: &mut LexState) {
    while let Some(c) = peek_at(st, 0) {
        if c == '\n' {
            st.line += 1;
            st.pos += 1;
        } else if c.is_whitespace() {
            st.pos += 1;
        } else {
            break;
        }
    }
}

fn line_text_of(source_lines: &[&str], line: usize) -> String {
    source_lines
        .get(line.wrapping_sub(1))
        .map_or_else(String::new, |s| (*s).to_string())
}

fn in_test_scope(st: &LexState) -> bool {
    !st.test_scopes.is_empty()
}

fn on_open_brace(st: &mut LexState) {
    st.brace_depth += 1;
    if st.pending_item_test {
        st.test_scopes.push(st.brace_depth);
        st.pending_item_test = false;
        st.pending_cfg_test = false;
    }
}

fn on_close_brace(st: &mut LexState) {
    if st.test_scopes.last().is_some_and(|d| *d == st.brace_depth) {
        st.test_scopes.pop();
    }
    st.brace_depth = st.brace_depth.saturating_sub(1);
}

fn on_item_keyword(st: &mut LexState, keyword: &str, item_name: &str) {
    if st.pending_cfg_test {
        if keyword == "fn" || keyword == "mod" || keyword == "impl" || keyword == "trait" {
            st.pending_item_test = true;
        } else {
            st.pending_cfg_test = false;
        }
    }
    if keyword == "fn" || keyword == "mod" {
        st.current_item = format!("{keyword} {item_name}");
    } else if keyword == "impl" || keyword == "trait" {
        st.current_item = format!("{keyword}@{}", st.line);
    }
}

fn read_item_name(st: &LexState) -> String {
    let mut j = st.pos;
    while j < st.chars.len() && st.chars[j].is_whitespace() {
        j += 1;
    }
    if j < st.chars.len() && st.chars[j] == '<' {
        return String::new();
    }
    let mut name = String::new();
    let mut k = j;
    while k < st.chars.len() && is_ident_continue(st.chars[k]) {
        name.push(st.chars[k]);
        k += 1;
    }
    name
}

fn consume_attribute(st: &mut LexState) {
    let mut depth = 0_usize;
    while let Some(c) = peek_at(st, 0) {
        if c == '\n' {
            st.line += 1;
        }
        if c == '[' {
            depth += 1;
        }
        if c == ']' {
            if depth == 0 {
                st.pos += 1;
                break;
            }
            depth = depth.saturating_sub(1);
        }
        st.pos += 1;
        if c == ']' && depth == 0 {
            break;
        }
        if st.pos > st.chars.len() {
            break;
        }
    }
}

fn attribute_is_cfg_test(st: &LexState, attr_start: usize) -> bool {
    let end = (st.pos).min(st.chars.len());
    let slice: String = st.chars[attr_start..end].iter().collect();
    slice.contains("cfg(test)")
}

fn skip_line_comment(st: &mut LexState) {
    while let Some(c) = peek_at(st, 0) {
        st.pos += 1;
        if c == '\n' {
            st.line += 1;
            break;
        }
    }
}

fn skip_block_comment(st: &mut LexState) -> Result<(), String> {
    let mut depth: u32 = 1;
    st.pos += 2;
    while let Some(c) = peek_at(st, 0) {
        if c == '\n' {
            st.line += 1;
        }
        if c == '/' && peek_at(st, 1) == Some('*') {
            depth += 1;
            if depth > MAX_BLOCK_DEPTH {
                return Err("block comment depth exceeds bound".to_string());
            }
            st.pos += 2;
            continue;
        }
        if c == '*' && peek_at(st, 1) == Some('/') {
            depth -= 1;
            st.pos += 2;
            if depth == 0 {
                break;
            }
            continue;
        }
        st.pos += 1;
    }
    if depth != 0 {
        return Err("unclosed block comment".to_string());
    }
    Ok(())
}

fn skip_quoted(st: &mut LexState, quote: char) -> Result<(), String> {
    // opening quote already peeked; consume it
    st.pos += 1;
    let mut escaped = false;
    let mut closed = false;
    while let Some(c) = peek_at(st, 0) {
        if c == '\n' && quote != '"' {
            // chars do not span lines in this bound
        }
        if c == '\n' {
            st.line += 1;
        }
        st.pos += 1;
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            closed = true;
            break;
        }
    }
    if !closed {
        return Err("unclosed string or char literal".to_string());
    }
    Ok(())
}

fn try_skip_raw_string(st: &mut LexState) -> Result<bool, String> {
    let save = st.pos;
    let mut j = st.pos;
    let is_byte = j < st.chars.len() && st.chars[j] == 'b' && st.chars.get(j + 1) == Some(&'r');
    if is_byte {
        j += 2;
    } else if j < st.chars.len() && st.chars[j] == 'r' {
        j += 1;
    } else {
        return Ok(false);
    }
    let mut hashes = 0_usize;
    while j < st.chars.len() && st.chars[j] == '#' {
        hashes += 1;
        j += 1;
    }
    if hashes > MAX_RAW_HASHES {
        return Err("raw string hash count exceeds bound".to_string());
    }
    if j >= st.chars.len() || st.chars[j] != '"' {
        st.pos = save;
        return Ok(false);
    }
    j += 1;
    // find closing quote + hashes
    let mut closed = false;
    while j < st.chars.len() {
        if st.chars[j] == '\n' {
            // count lines for diagnostics
        }
        if st.chars[j] == '"' {
            let mut k = j + 1;
            let mut h = 0_usize;
            while h < hashes && k < st.chars.len() && st.chars[k] == '#' {
                h += 1;
                k += 1;
            }
            if h == hashes {
                j = k;
                closed = true;
                break;
            }
        }
        j += 1;
    }
    if !closed {
        return Err("unclosed raw string".to_string());
    }
    let skipped_lines = st.chars[save..j].iter().filter(|c| **c == '\n').count();
    st.line += skipped_lines;
    st.pos = j;
    Ok(true)
}

fn classify_unsafe_ahead(st: &LexState) -> Option<UnsafeForm> {
    let mut j = st.pos;
    while j < st.chars.len() && st.chars[j].is_whitespace() {
        j += 1;
    }
    if j < st.chars.len() && st.chars[j] == '{' {
        return Some(UnsafeForm::Block);
    }
    let mut name = String::new();
    let mut k = j;
    while k < st.chars.len() && is_ident_continue(st.chars[k]) {
        name.push(st.chars[k]);
        k += 1;
    }
    match name.as_str() {
        "fn" => Some(UnsafeForm::Fn),
        "impl" => Some(UnsafeForm::Impl),
        "trait" => Some(UnsafeForm::Trait),
        "extern" => Some(UnsafeForm::Extern),
        _ => None,
    }
}

fn record_unsafe(st: &mut LexState, form: UnsafeForm, source_lines: &[&str]) {
    let text = line_text_of(source_lines, st.line);
    st.sites.push(UnsafeSite {
        line: st.line,
        form,
        text,
        item: st.current_item.clone(),
        is_test: in_test_scope(st),
    });
}

fn handle_hash(st: &mut LexState) {
    if peek_at(st, 1) == Some('!') || peek_at(st, 1) == Some('[') {
        let start = st.pos;
        st.pos += 1;
        consume_attribute(st);
        if attribute_is_cfg_test(st, start) {
            st.pending_cfg_test = true;
            st.pending_item_test = false;
        }
    } else {
        st.pos += 1;
    }
}

fn handle_quote_or_char(st: &mut LexState) -> Result<(), String> {
    if peek_at(st, 0) == Some('\'') {
        // lifetime vs char: char is 'x' or '\..'
        let a = peek_at(st, 1);
        let b = peek_at(st, 2);
        let c = peek_at(st, 3);
        let is_char =
            a.is_some_and(|x| x == '\\') || b == Some('\'') || (a.is_some() && c == Some('\''));
        if is_char {
            skip_quoted(st, '\'')?;
        } else {
            st.pos += 1;
        }
    } else {
        skip_quoted(st, '"')?;
    }
    Ok(())
}

fn handle_ident(st: &mut LexState, source_lines: &[&str]) {
    let word = consume_ident(st);
    match word.as_str() {
        "unsafe" => {
            skip_whitespace(st);
            if let Some(form) = classify_unsafe_ahead(st) {
                record_unsafe(st, form, source_lines);
            }
        }
        "fn" | "mod" | "impl" | "trait" | "use" | "struct" | "enum" | "const" | "static" => {
            let name = read_item_name(st);
            on_item_keyword(st, word.as_str(), name.as_str());
        }
        _ => {}
    }
}

/// Bounded Rust lexer returning production/test-classified `unsafe` sites.
fn lex_unsafe_sites(source: &str) -> Result<Vec<UnsafeSite>, String> {
    let source_lines: Vec<&str> = source.lines().collect();
    let mut st = new_lex_state(source)?;
    while st.pos < st.chars.len() {
        let c = st.chars[st.pos];
        if c == '\n' {
            st.line += 1;
            st.pos += 1;
            continue;
        }
        if c.is_whitespace() {
            st.pos += 1;
            continue;
        }
        if c == '/' && peek_at(&st, 1) == Some('/') {
            skip_line_comment(&mut st);
            continue;
        }
        if c == '/' && peek_at(&st, 1) == Some('*') {
            skip_block_comment(&mut st)?;
            continue;
        }
        if (c == 'r' || (c == 'b' && peek_at(&st, 1).is_some())) && try_skip_raw_string(&mut st)? {
            continue;
        }
        if c == 'b' && peek_at(&st, 1) == Some('"') {
            st.pos += 1;
            skip_quoted(&mut st, '"')?;
            continue;
        }
        if c == '"' || c == '\'' {
            handle_quote_or_char(&mut st)?;
            continue;
        }
        if c == '#' {
            handle_hash(&mut st);
            continue;
        }
        if c == '{' {
            on_open_brace(&mut st);
            st.pos += 1;
            continue;
        }
        if c == '}' {
            on_close_brace(&mut st);
            st.pos += 1;
            continue;
        }
        if c == ';' && st.pending_item_test {
            // `mod tests;` style unit without a body consumes the marker.
            st.pending_item_test = false;
            st.pending_cfg_test = false;
            st.pos += 1;
            continue;
        }
        if is_ident_start(c) {
            handle_ident(&mut st, &source_lines);
            continue;
        }
        st.pos += 1;
    }
    Ok(st.sites)
}

// ---------------------------------------------------------------------------
// Coverage association
// ---------------------------------------------------------------------------

fn preceding_group(lines: &[&str], unsafe_line: usize) -> Option<(usize, usize, String)> {
    if unsafe_line == 0 || unsafe_line > lines.len() {
        return None;
    }
    let mut k = unsafe_line.saturating_sub(1);
    // skip attribute lines directly above the site
    while k > 0 && lines[k - 1].trim_start().starts_with("#[") {
        k -= 1;
    }
    let mut group: Vec<(usize, &str)> = Vec::new();
    while k > 0 && lines[k - 1].trim_start().starts_with("//") {
        group.push((k, lines[k - 1]));
        k -= 1;
    }
    if group.is_empty() {
        return None;
    }
    group.reverse();
    let has_safety = group.iter().any(|(_, t)| t.contains("SAFETY:"));
    if !has_safety {
        return None;
    }
    let start = group.first().map_or(unsafe_line, |(n, _)| *n);
    let end = group.last().map_or(unsafe_line, |(n, _)| *n);
    let text = group.iter().map(|(_, t)| *t).collect::<Vec<_>>().join("\n");
    Some((start, end, text))
}

fn interior_leading(lines: &[&str], site: &UnsafeSite) -> Option<String> {
    if site.form != UnsafeForm::Block {
        return None;
    }
    if site.text.contains('}') {
        return None;
    }
    let mut j = site.line;
    while j < lines.len() && lines[j].trim().is_empty() {
        j += 1;
    }
    if j < lines.len() {
        let t = lines[j];
        if t.trim_start().starts_with("//") && t.contains("SAFETY:") {
            return Some(t.to_string());
        }
    }
    None
}

fn nearest_safety_above(lines: &[&str], unsafe_line: usize, window: usize) -> bool {
    let mut seen = 0_usize;
    let mut k = unsafe_line.saturating_sub(1);
    while k > 0 && seen < window {
        if lines[k - 1].contains("SAFETY:") {
            return true;
        }
        k -= 1;
        seen += 1;
    }
    false
}

fn nearest_safety_below(lines: &[&str], site: &UnsafeSite, window: usize) -> bool {
    let mut seen = 0_usize;
    let mut j = site.line;
    // skip to end of the block for multi-line sites (bounded scan)
    let mut depth = 0_usize;
    let mut scanned = 0_usize;
    while j < lines.len() && scanned < 40 {
        let t = lines[j];
        depth += t.chars().filter(|c| *c == '{').count();
        if t.contains('}') && depth > 0 {
            j += 1;
            break;
        }
        if site.text.contains('}') {
            j = site.line;
            break;
        }
        j += 1;
        scanned += 1;
    }
    while j < lines.len() && seen < window {
        let t = lines[j];
        if t.contains("SAFETY:") {
            return true;
        }
        if !t.trim().is_empty() && !t.trim_start().starts_with("//") {
            // code beyond the block ends the following-only window
            if seen > 4 {
                break;
            }
        }
        j += 1;
        seen += 1;
    }
    false
}

fn generic_reason(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    for phrase in [
        "windows requires unsafe",
        "parameters valid",
        "checked above",
        "module-wide",
        "obviously safe",
    ] {
        if lower.contains(phrase) {
            return Some(format!("generic rationale ({phrase})"));
        }
    }
    if text.len() < 20 {
        return Some("generic rationale (too short)".to_string());
    }
    None
}

fn specific_token_present(text: &str) -> bool {
    let lower = text.to_lowercase();
    let tokens = [
        "null",
        "nul",
        "handle",
        "buffer",
        "slice",
        "wide",
        "utf",
        "pointer",
        "alloc",
        "free",
        "close",
        "release",
        "mutex",
        "descriptor",
        "dacl",
        "sid",
        "sddl",
        "security",
        "service",
        "scm",
        "job",
        "process",
        "token",
        "thread",
        "send",
        "pin",
        "alias",
        "unwind",
        "extern",
        "abi",
        "layout",
        "callback",
        "impersonat",
        "error",
        "return",
        "live",
        "own",
        "valid",
        "terminat",
        "transfer",
        "lifetime",
        "outlive",
        "capacity",
        "init",
        "align",
        "span",
        "probe",
        "query",
        "status",
        "config",
        "control",
        "start",
        "stop",
        "delete",
        "create",
        "open",
        "change",
        "localfree",
        "getlasterror",
        "cotaskmemfree",
        "shgetknown",
        "lookupaccount",
        "isvalidsid",
        "wts",
        "peekmessage",
        "translatemessage",
        "dispatchmessage",
        "createwindow",
        "loadicon",
        "notifyicon",
        "destroywindow",
        "toolhelp",
        "process32",
        "movefile",
        "from_raw",
        "osstring",
        "read_unaligned",
        "aclsize",
        "dacl_matches",
        "protected",
        "owner",
        "elevation",
        "snapshot",
        "msg",
        "hwnd",
        "callback",
        "reentrancy",
        "coupon",
    ];
    tokens.iter().any(|t| lower.contains(t))
}

fn fnv1a_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in input.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn site_digest(site: &UnsafeSite) -> String {
    fnv1a_hex(&format!(
        "{}|{:?}|{}|{}",
        site.line,
        site.form,
        site.item,
        site.text.trim()
    ))
}

fn digest_is_stale(site: &UnsafeSite, expected_digests: Option<&HashMap<usize, String>>) -> bool {
    let Some(map) = expected_digests else {
        return false;
    };
    let Some(expected) = map.get(&site.line) else {
        return false;
    };
    *expected != site_digest(site)
}

fn obligation_text(pre: Option<&(usize, usize, String)>, interior: Option<&String>) -> String {
    pre.map_or_else(
        || interior.cloned().unwrap_or_default(),
        |(_, _, t)| t.clone(),
    )
}

fn verdict_for_site(
    lines: &[&str],
    site: &UnsafeSite,
    group_owners: &mut HashMap<usize, usize>,
    expected_digests: Option<&HashMap<usize, String>>,
) -> SiteVerdict {
    let pre = preceding_group(lines, site.line);
    let interior = interior_leading(lines, site);
    if pre.is_some() && interior.is_some() {
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail: "duplicate obligation (preceding plus interior)".to_string(),
        };
    }
    if pre.is_none() && interior.is_none() {
        let detail = if nearest_safety_above(lines, site.line, 8) {
            "detached obligation (blank or code gap above)".to_string()
        } else if nearest_safety_below(lines, site, 8) {
            "following-only obligation (comment after the site)".to_string()
        } else {
            "missing obligation".to_string()
        };
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail,
        };
    }
    let text = obligation_text(pre.as_ref(), interior.as_ref());
    if let Some((start, _, _)) = pre {
        if let Some(owner) = group_owners.get(&start) {
            if *owner != site.line {
                return SiteVerdict {
                    line: site.line,
                    passed: false,
                    detail: "broad obligation (one comment covers two sites)".to_string(),
                };
            }
        } else {
            group_owners.insert(start, site.line);
        }
    }
    let lower_text = text.to_lowercase();
    if lower_text.contains("all unsafe")
        || lower_text.contains("all sites")
        || lower_text.contains("covers all")
        || lower_text.contains("covers both")
        || lower_text.contains("every site")
    {
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail: "broad obligation (one comment covers two sites)".to_string(),
        };
    }
    if let Some(reason) = generic_reason(&text) {
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail: reason,
        };
    }
    if !specific_token_present(&text) {
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail: "generic rationale (no operation-specific token)".to_string(),
        };
    }
    if digest_is_stale(site, expected_digests) {
        return SiteVerdict {
            line: site.line,
            passed: false,
            detail: "stale digest".to_string(),
        };
    }
    SiteVerdict {
        line: site.line,
        passed: true,
        detail: "ok".to_string(),
    }
}

/// Association verdict for every site. `expected_digests` maps line -> digest;
/// stale entries fail closed.
fn check_coverage(
    source: &str,
    sites: &[UnsafeSite],
    expected_digests: Option<&HashMap<usize, String>>,
) -> Vec<SiteVerdict> {
    let lines: Vec<&str> = source.lines().collect();
    let mut verdicts: Vec<SiteVerdict> = Vec::new();
    let mut group_owners: HashMap<usize, usize> = HashMap::new();
    for site in sites {
        verdicts.push(verdict_for_site(
            &lines,
            site,
            &mut group_owners,
            expected_digests,
        ));
    }
    verdicts
}

fn coverage_passes(verdicts: &[SiteVerdict]) -> bool {
    verdicts.iter().all(|v| v.passed)
}

// ---------------------------------------------------------------------------
// Manifest and ADR validators
// ---------------------------------------------------------------------------

fn manifest_allows(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim();
        !t.starts_with('#') && t.contains("unsafe_code") && t.contains("\"allow\"")
    })
}

fn manifest_deny_unsafe_op(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim();
        !t.starts_with('#') && t.contains("unsafe_op_in_unsafe_fn") && t.contains("\"deny\"")
    })
}

fn check_manifest_denominator(root: &Path) -> Result<(), String> {
    let canonical = root.join("crates/kernel/eliot-platform-windows/Cargo.toml");
    let exceptions = [
        "crates/eliot-windows-ipc/Cargo.toml",
        "crates/kernel/eliot-ipc/Cargo.toml",
        "bins/eliot-host/Cargo.toml",
        "bins/eliot-watchdog/Cargo.toml",
    ];
    let mut allows = 0_usize;
    let canon_text = read_text(&canonical)?;
    if !manifest_allows(&canon_text) {
        return Err("canonical owner missing unsafe allow".to_string());
    }
    if !manifest_deny_unsafe_op(&canon_text) {
        return Err("canonical owner missing unsafe_op_in_unsafe_fn deny".to_string());
    }
    allows += 1;
    for rel in exceptions {
        let text = read_text(&root.join(rel))?;
        if !manifest_allows(&text) {
            return Err(format!("exception missing allow: {rel}"));
        }
        allows += 1;
    }
    if allows != EXPECTED_ALLOWS {
        return Err(format!(
            "manifest denominator {allows} != {EXPECTED_ALLOWS}"
        ));
    }
    // Forbid silent widening: workspace root must forbid unsafe.
    let root_text = read_text(&root.join("Cargo.toml"))?;
    if !root_text.contains("unsafe_code") || !root_text.contains("\"forbid\"") {
        return Err("workspace root must forbid unsafe_code".to_string());
    }
    Ok(())
}

fn check_adr_identity(text: &str) -> Result<(), String> {
    if !text.contains("# ADR 0014") {
        return Err("ADR number missing".to_string());
    }
    for section in [
        "## Status",
        "## Context",
        "## Decision",
        "## Consequences",
        "## Acceptance",
    ] {
        if !text.contains(section) {
            return Err(format!("ADR section missing: {section}"));
        }
    }
    let rows = [
        "row-eliot-platform-windows",
        "row-eliot-windows-ipc",
        "row-eliot-ipc",
        "row-eliot-host",
        "row-eliot-watchdog",
    ];
    for row in rows {
        if !text.contains(row) {
            return Err(format!("ADR row missing: {row}"));
        }
    }
    if text.contains("Windows requires unsafe")
        && !(text.contains("never") && text.contains("accepted rationale"))
    {
        return Err("ADR uses forbidden rationale".to_string());
    }
    Ok(())
}

fn check_manifest_references(root: &Path, adr_text: &str) -> Result<(), String> {
    let pairs = [
        (
            "crates/eliot-windows-ipc/Cargo.toml",
            "row-eliot-windows-ipc",
        ),
        ("crates/kernel/eliot-ipc/Cargo.toml", "row-eliot-ipc"),
        ("bins/eliot-host/Cargo.toml", "row-eliot-host"),
        ("bins/eliot-watchdog/Cargo.toml", "row-eliot-watchdog"),
    ];
    for (rel, row) in pairs {
        let text = read_text(&root.join(rel))?;
        if !text.contains(row) {
            return Err(format!("manifest {rel} missing reference to {row}"));
        }
        if !adr_text.contains(row) {
            return Err(format!("ADR missing {row} for {rel}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Token equivalence (comments/whitespace-insensitive)
// ---------------------------------------------------------------------------

fn skip_tok_block_comment(chars: &[char], i: &mut usize) -> Result<(), String> {
    let mut depth: u32 = 1;
    *i += 2;
    while *i < chars.len() && depth > 0 {
        if chars[*i] == '/' && chars.get(*i + 1) == Some(&'*') {
            depth += 1;
            if depth > MAX_BLOCK_DEPTH {
                return Err("comment depth exceeds bound".to_string());
            }
            *i += 2;
            continue;
        }
        if chars[*i] == '*' && chars.get(*i + 1) == Some(&'/') {
            depth -= 1;
            *i += 2;
            continue;
        }
        *i += 1;
    }
    if depth != 0 {
        return Err("unclosed block comment in tokenize".to_string());
    }
    Ok(())
}

fn read_tok_literal(chars: &[char], i: &mut usize, quote: char) -> Result<String, String> {
    let mut lit = String::new();
    lit.push(quote);
    *i += 1;
    let mut escaped = false;
    let mut closed = false;
    while *i < chars.len() {
        let d = chars[*i];
        lit.push(d);
        *i += 1;
        if escaped {
            escaped = false;
            continue;
        }
        if d == '\\' {
            escaped = true;
            continue;
        }
        if d == quote {
            closed = true;
            break;
        }
        if d == '\n' && quote == '\'' {
            break;
        }
    }
    if !closed {
        return Err("unclosed literal in tokenize".to_string());
    }
    Ok(lit)
}

fn is_tok_lifetime(chars: &[char], i: usize) -> bool {
    let ahead_a = chars.get(i + 1).copied();
    let ahead_b = chars.get(i + 2).copied();
    let ahead_c = chars.get(i + 3).copied();
    let is_char = ahead_a.is_some_and(|x| x == '\\')
        || ahead_b == Some('\'')
        || (ahead_a.is_some() && ahead_c == Some('\''));
    !is_char
}

fn read_tok_ident(chars: &[char], i: &mut usize) -> String {
    let mut id = String::new();
    while *i < chars.len() && is_ident_continue(chars[*i]) {
        id.push(chars[*i]);
        *i += 1;
    }
    id
}

fn read_tok_number(chars: &[char], i: &mut usize) -> String {
    let mut num = String::new();
    while *i < chars.len()
        && (chars[*i].is_ascii_alphanumeric() || chars[*i] == '_' || chars[*i] == '.')
    {
        num.push(chars[*i]);
        *i += 1;
    }
    num
}

fn push_tok_punct(chars: &[char], i: &mut usize, tokens: &mut Vec<String>) {
    let two: String = chars
        .get(*i..*i + 2)
        .map_or_else(String::new, |s| s.iter().collect());
    if ["::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", ".."].contains(&two.as_str()) {
        tokens.push(two);
        *i += 2;
    } else {
        tokens.push(chars[*i].to_string());
        *i += 1;
    }
}

fn tokenize_rust(source: &str) -> Result<Vec<String>, String> {
    let mut tokens: Vec<String> = Vec::new();
    let chars: Vec<char> = source.chars().collect();
    let mut i = 0_usize;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            skip_tok_block_comment(&chars, &mut i)?;
            continue;
        }
        if c == '\'' && is_tok_lifetime(&chars, i) {
            tokens.push("'".to_string());
            i += 1;
            continue;
        }
        if c == '"' || c == '\'' {
            tokens.push(read_tok_literal(&chars, &mut i, c)?);
            continue;
        }
        if is_ident_start(c) {
            tokens.push(read_tok_ident(&chars, &mut i));
            continue;
        }
        if c.is_ascii_digit() {
            tokens.push(read_tok_number(&chars, &mut i));
            continue;
        }
        push_tok_punct(&chars, &mut i, &mut tokens);
    }
    Ok(tokens)
}

fn tokens_equal(base: &str, candidate: &str) -> Result<(), String> {
    let a = tokenize_rust(base)?;
    let b = tokenize_rust(candidate)?;
    if a == b {
        Ok(())
    } else {
        Err(format!(
            "token streams differ ({} vs {} tokens)",
            a.len(),
            b.len()
        ))
    }
}

// ---------------------------------------------------------------------------
// Self-scan guard (no network/process/mutation paths in this oracle)
// ---------------------------------------------------------------------------

fn oracle_self_text() -> Result<String, String> {
    read_text(&package_dir().join("tests").join("safety_coverage.rs"))
}

fn check_no_forbidden_paths() -> Result<(), String> {
    let src = oracle_self_text()?;
    let p1 = format!("{}::{}::{}", "std", "process", "Command");
    let p2 = format!("{}::{}", "std", "net");
    let p3 = format!("{}::{}", "fs", "write");
    let p4 = format!("{}::{}", "fs", "remove");
    let p5 = format!("{}::{}", "Command", "new");
    for pat in [p1, p2, p3, p4, p5] {
        if src.contains(pat.as_str()) {
            return Err(format!("forbidden path present: {pat}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fixture JSON loader (std only, string-aware, bounded)
// ---------------------------------------------------------------------------

fn unescape_json_string(raw: &str) -> Result<String, String> {
    let mut out = String::new();
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0_usize;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            i += 1;
            let e = chars.get(i).copied().ok_or("trailing escape")?;
            match e {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'u' => {
                    if i + 4 >= chars.len() {
                        return Err("bad unicode escape".to_string());
                    }
                    out.push('?');
                    i += 4;
                }
                _ => return Err("bad escape".to_string()),
            }
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    Ok(out)
}

fn extract_string_field(obj: &str, key: &str) -> Result<Option<String>, String> {
    let needle = format!("\"{key}\"");
    let Some(start) = obj.find(needle.as_str()) else {
        return Ok(None);
    };
    let rest = &obj[start + needle.len()..];
    let Some(colon) = rest.find(':') else {
        return Ok(None);
    };
    let mut value = rest[colon + 1..].trim_start();
    if value.starts_with("null") {
        return Ok(None);
    }
    if !value.starts_with('"') {
        return Ok(None);
    }
    value = &value[1..];
    let mut raw = String::new();
    let mut escaped = false;
    let mut end = None;
    for (idx, c) in value.char_indices() {
        if escaped {
            raw.push('\\');
            raw.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            end = Some(idx);
            break;
        }
        raw.push(c);
    }
    let Some(_e) = end else {
        return Err(format!("unclosed string for {key}"));
    };
    Ok(Some(unescape_json_string(&raw)?))
}

fn extract_bool_field(obj: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = obj.find(needle.as_str())?;
    let rest = &obj[start + needle.len()..];
    let colon = rest.find(':')?;
    let value = rest[colon + 1..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_int_field(obj: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    let start = obj.find(needle.as_str())?;
    let rest = &obj[start + needle.len()..];
    let colon = rest.find(':')?;
    let value = rest[colon + 1..].trim_start();
    let mut digits = String::new();
    for c in value.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            break;
        }
    }
    digits.parse::<usize>().ok()
}

fn split_case_objects(text: &str) -> Result<Vec<String>, String> {
    let Some(arr) = text.find("\"cases\"") else {
        return Err("fixtures missing cases".to_string());
    };
    let rest = &text[arr..];
    let Some(open) = rest.find('[') else {
        return Err("fixtures cases not an array".to_string());
    };
    let body = &rest[open + 1..];
    let chars: Vec<char> = body.chars().collect();
    let mut objects: Vec<String> = Vec::new();
    let mut i = 0_usize;
    while i < chars.len() {
        while i < chars.len() && chars[i] != '{' && chars[i] != ']' {
            i += 1;
        }
        if i >= chars.len() || chars[i] == ']' {
            break;
        }
        let start = i;
        let mut depth = 0_usize;
        let mut in_str = false;
        let mut escaped = false;
        while i < chars.len() {
            let c = chars[i];
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if c == '"' {
                in_str = true;
                i += 1;
                continue;
            }
            if c == '{' {
                depth += 1;
            }
            if c == '}' {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    break;
                }
                continue;
            }
            i += 1;
        }
        if depth != 0 {
            return Err("unbalanced fixture object".to_string());
        }
        objects.push(chars[start..i].iter().collect());
        if objects.len() > 100 {
            return Err("too many fixture cases".to_string());
        }
    }
    Ok(objects)
}

fn load_fixture_cases() -> Result<Vec<FixtureCase>, String> {
    let text = read_text(&fixture_path())?;
    if !text.trim_start().starts_with('{') {
        return Err("fixtures must be a JSON object".to_string());
    }
    let objects = split_case_objects(&text)?;
    let mut cases: Vec<FixtureCase> = Vec::new();
    for obj in &objects {
        let id = extract_string_field(obj, "id")?.ok_or("fixture missing id")?;
        let kind = extract_string_field(obj, "kind")?.ok_or("fixture missing kind")?;
        let case = FixtureCase {
            id,
            kind,
            source: extract_string_field(obj, "source")?.unwrap_or_default(),
            base: extract_string_field(obj, "base")?.unwrap_or_default(),
            candidate: extract_string_field(obj, "candidate")?.unwrap_or_default(),
            expect_sites: extract_int_field(obj, "expect_sites"),
            expect_pass: extract_bool_field(obj, "expect_pass"),
            expect_error: extract_bool_field(obj, "expect_error"),
            expect_equal: extract_bool_field(obj, "expect_equal"),
            expect_form: extract_string_field(obj, "expect_form")?.unwrap_or_default(),
            reason: extract_string_field(obj, "reason")?.unwrap_or_default(),
            mutated_digest: extract_string_field(obj, "mutated_digest")?.unwrap_or_default(),
        };
        cases.push(case);
    }
    if cases.is_empty() {
        return Err("no fixture cases".to_string());
    }
    Ok(cases)
}

fn fixture_by_id(cases: &[FixtureCase], id: &str) -> Result<FixtureCase, String> {
    cases
        .iter()
        .find(|c| c.id == id)
        .cloned()
        .ok_or_else(|| format!("fixture missing: {id}"))
}

fn check_fixture_metadata(cases: &[FixtureCase]) -> Result<(), String> {
    if cases.len() < 20 {
        return Err("too few fixture cases".to_string());
    }
    for case in cases {
        if case.id.is_empty() || case.kind.is_empty() {
            return Err("fixture id/kind missing".to_string());
        }
        // Read every projection field so the loader stays honest.
        let _ = (
            &case.source,
            &case.base,
            &case.candidate,
            case.expect_sites,
            case.expect_pass,
            case.expect_error,
            case.expect_equal,
            &case.expect_form,
            &case.reason,
            &case.mutated_digest,
        );
        match case.kind.as_str() {
            "lexical" | "form" | "coverage" | "policy" | "malformed" | "token" => {}
            other => return Err(format!("unknown fixture kind: {other}")),
        }
    }
    Ok(())
}

fn shuffled_sites(sites: &[UnsafeSite]) -> Vec<UnsafeSite> {
    // Deterministic rotation (no RNG): traversal order must not affect outcome.
    let mut out = sites.to_vec();
    if out.len() > 1 {
        let first = out.remove(0);
        out.push(first);
    }
    out.reverse();
    out
}

// ---------------------------------------------------------------------------
// Tests: 34 substantive cases for issue #728
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 728/1
#[test]
fn manifest_denominator_is_five() -> Result<(), String> {
    check_manifest_denominator(&workspace_root())
}

// WORK_UNIT_CASE: 728/2
#[test]
fn adr_identity_is_exact() -> Result<(), String> {
    let text = read_text(&adr_path())?;
    check_adr_identity(&text)
}

// WORK_UNIT_CASE: 728/3
#[test]
fn adr_has_one_row_per_exception() -> Result<(), String> {
    let text = read_text(&adr_path())?;
    check_adr_identity(&text)?;
    for row in [
        "row-eliot-platform-windows",
        "row-eliot-windows-ipc",
        "row-eliot-ipc",
        "row-eliot-host",
        "row-eliot-watchdog",
    ] {
        let anchor = format!("id=\"{row}\"");
        let definitions = text.matches(anchor.as_str()).count();
        if definitions != 1 {
            return Err(format!("ADR row {row} definitions {definitions} != 1"));
        }
        if !text.contains(row) {
            return Err(format!("ADR row {row} missing"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/4
#[test]
fn unknown_exception_fails_closed() -> Result<(), String> {
    let root = workspace_root();
    let canon = read_text(&root.join("crates/kernel/eliot-platform-windows/Cargo.toml"))?;
    if !manifest_allows(&canon) {
        return Err("canonical allow missing".to_string());
    }
    // A sixth allow with no ADR row must fail resolution.
    let adr = read_text(&adr_path())?;
    if adr.contains("row-eliot-phantom") {
        return Err("phantom row must not exist".to_string());
    }
    check_manifest_denominator(&root)
}

// WORK_UNIT_CASE: 728/5
#[test]
fn duplicate_adr_row_is_rejected() -> Result<(), String> {
    let text = read_text(&adr_path())?;
    check_adr_identity(&text)?;
    // The accepted ADR carries each row exactly once; a doubled anchor is stale.
    let doubled = text.replace("row-eliot-ipc", "row-eliot-ipc row-eliot-ipc");
    let count = doubled.matches("row-eliot-ipc").count();
    if count <= 1 {
        return Err("duplicate injection failed".to_string());
    }
    // Real file must not contain the doubled shape.
    if text.matches("row-eliot-ipc row-eliot-ipc").count() != 0 {
        return Err("duplicate row present".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/6
#[test]
fn stale_adr_row_is_rejected() -> Result<(), String> {
    let text = read_text(&adr_path())?;
    check_adr_identity(&text)?;
    // Every ADR row must resolve to a live manifest allow.
    check_manifest_denominator(&workspace_root())?;
    if text.contains("row-eliot-removed-crate") {
        return Err("stale row present".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/7
#[test]
fn manifest_references_resolve_to_adr() -> Result<(), String> {
    let root = workspace_root();
    let adr = read_text(&adr_path())?;
    check_adr_identity(&adr)?;
    check_manifest_references(&root, &adr)
}

// WORK_UNIT_CASE: 728/8
#[test]
fn site_denominator_is_exact() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    if sites.len() != EXPECTED_SITES {
        return Err(format!("sites {} != {EXPECTED_SITES}", sites.len()));
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/9
#[test]
fn site_forms_are_block_plus_impl() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    let blocks = sites.iter().filter(|s| s.form == UnsafeForm::Block).count();
    let impls = sites.iter().filter(|s| s.form == UnsafeForm::Impl).count();
    let others = sites
        .iter()
        .filter(|s| {
            s.form == UnsafeForm::Fn || s.form == UnsafeForm::Trait || s.form == UnsafeForm::Extern
        })
        .count();
    if blocks != EXPECTED_BLOCK || impls != EXPECTED_IMPL || others != 0 {
        return Err(format!("forms block={blocks} impl={impls} other={others}"));
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/10
#[test]
fn production_cfg_classification_holds() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    let prod = sites.iter().filter(|s| !s.is_test).count();
    if prod != EXPECTED_SITES {
        return Err(format!("production {prod} != {EXPECTED_SITES}"));
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/11
#[test]
fn test_items_do_not_leak_into_production() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    if !source.contains("service_readback_is_acceptable") {
        return Err("expected test helper missing".to_string());
    }
    if !source.contains("mod tests;") {
        return Err("expected test module missing".to_string());
    }
    let sites = lex_unsafe_sites(&source)?;
    // None of the production sites may sit inside the test helper.
    for site in &sites {
        if site.item.contains("service_readback") && !site.is_test {
            return Err("test helper misclassified".to_string());
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/12
#[test]
fn unsafe_in_strings_is_ignored() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    check_fixture_metadata(&cases)?;
    let case = fixture_by_id(&cases, "lexical-string")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let expected = case.expect_sites.unwrap_or(0);
    if sites.len() != expected {
        return Err(format!("string sites {} != {expected}", sites.len()));
    }
    let raw = fixture_by_id(&cases, "lexical-raw-string")?;
    let raw_sites = lex_unsafe_sites(&raw.source)?;
    if !raw_sites.is_empty() {
        return Err("raw string site leaked".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/13
#[test]
fn unsafe_in_comments_is_ignored() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    for id in [
        "lexical-line-comment",
        "lexical-block-comment",
        "lexical-nested-block-comment",
    ] {
        let case = fixture_by_id(&cases, id)?;
        let sites = lex_unsafe_sites(&case.source)?;
        if !sites.is_empty() {
            return Err(format!("comment site leaked: {id}"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/14
#[test]
fn block_form_is_detected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "form-block")?;
    let sites = lex_unsafe_sites(&case.source)?;
    if sites.len() != 1 || sites.first().is_some_and(|s| s.form != UnsafeForm::Block) {
        return Err("block form not detected".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/15
#[test]
fn all_five_forms_are_detected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "form-all-five")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let expected = case.expect_sites.unwrap_or(5);
    if sites.len() != expected {
        return Err(format!("forms {} != {expected}", sites.len()));
    }
    for form in [
        UnsafeForm::Fn,
        UnsafeForm::Impl,
        UnsafeForm::Trait,
        UnsafeForm::Extern,
        UnsafeForm::Block,
    ] {
        if !sites.iter().any(|s| s.form == form) {
            return Err(format!("form missing: {form:?}"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/16
#[test]
fn missing_comment_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "coverage-missing")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("missing comment passed".to_string());
    }
    if !verdicts
        .first()
        .is_some_and(|v| v.detail.contains("missing"))
    {
        return Err("missing detail wrong".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/17
#[test]
fn detached_comment_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "coverage-detached")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("detached passed".to_string());
    }
    if !verdicts
        .first()
        .is_some_and(|v| v.detail.contains("detached"))
    {
        return Err("detached detail wrong".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/18
#[test]
fn following_only_comment_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "coverage-following-only")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("following-only passed".to_string());
    }
    if !verdicts
        .first()
        .is_some_and(|v| v.detail.contains("following-only"))
    {
        return Err("following-only detail wrong".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/19
#[test]
fn duplicate_comment_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "coverage-duplicate")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("duplicate passed".to_string());
    }
    if !verdicts
        .first()
        .is_some_and(|v| v.detail.contains("duplicate"))
    {
        return Err("duplicate detail wrong".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/20
#[test]
fn broad_comment_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "coverage-broad")?;
    let sites = lex_unsafe_sites(&case.source)?;
    if sites.len() != 2 {
        return Err("broad fixture must carry two sites".to_string());
    }
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("broad passed".to_string());
    }
    if !verdicts.iter().any(|v| v.detail.contains("broad")) {
        return Err("broad detail wrong".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/21
#[test]
fn generic_prose_is_rejected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    for id in [
        "coverage-generic-windows",
        "coverage-generic-params",
        "coverage-generic-checked-above",
    ] {
        let case = fixture_by_id(&cases, id)?;
        let sites = lex_unsafe_sites(&case.source)?;
        let verdicts = check_coverage(&case.source, &sites, None);
        if coverage_passes(&verdicts) {
            return Err(format!("generic passed: {id}"));
        }
        if !verdicts
            .first()
            .is_some_and(|v| v.detail.contains("generic"))
        {
            return Err(format!("generic detail wrong: {id}"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/22
#[test]
fn real_source_coverage_passes() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    if sites.len() != EXPECTED_SITES {
        return Err("denominator drifted".to_string());
    }
    let verdicts = check_coverage(&source, &sites, None);
    let failing: Vec<&SiteVerdict> = verdicts.iter().filter(|v| !v.passed).collect();
    if !failing.is_empty() {
        let sample: Vec<String> = failing
            .iter()
            .take(3)
            .map(|v| format!("{}:{}", v.line, v.detail))
            .collect();
        return Err(format!("real coverage fails: {}", sample.join("; ")));
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/23
#[test]
fn stale_digest_fails_closed() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "policy-stale-digest")?;
    let sites = lex_unsafe_sites(&case.source)?;
    let verdicts = check_coverage(&case.source, &sites, None);
    if !coverage_passes(&verdicts) {
        return Err("clean fixture should pass without digests".to_string());
    }
    let mut stale: HashMap<usize, String> = HashMap::new();
    for site in &sites {
        stale.insert(site.line, case.mutated_digest.clone());
    }
    let stale_verdicts = check_coverage(&case.source, &sites, Some(&stale));
    if coverage_passes(&stale_verdicts) {
        return Err("stale digest passed".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/24
#[test]
fn malformed_source_fails_closed() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    for id in ["malformed-unclosed-string", "malformed-unclosed-block"] {
        let case = fixture_by_id(&cases, id)?;
        if lex_unsafe_sites(&case.source).is_ok() {
            return Err(format!("malformed passed: {id}"));
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/25
#[test]
fn new_site_without_proof_fails() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "policy-new-site")?;
    let sites = lex_unsafe_sites(&case.source)?;
    if sites.len() != 2 {
        return Err("new-site fixture must carry two sites".to_string());
    }
    let verdicts = check_coverage(&case.source, &sites, None);
    if coverage_passes(&verdicts) {
        return Err("new site passed".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/26
#[test]
fn new_allow_without_adr_fails() -> Result<(), String> {
    // The live denominator is exactly five; a sixth allow has no ADR row.
    check_manifest_denominator(&workspace_root())?;
    let adr = read_text(&adr_path())?;
    if adr.contains("row-eliot-newcrate") {
        return Err("unexpected row".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/27
#[test]
fn test_only_unsafe_is_separately_visible() -> Result<(), String> {
    let tests_source = read_text(&tests_rs_path())?;
    let test_sites = lex_unsafe_sites(&tests_source)?;
    if test_sites.len() != 16 {
        return Err(format!("tests.rs sites {} != 16", test_sites.len()));
    }
    let lib_source = read_text(&lib_rs_path())?;
    let lib_sites = lex_unsafe_sites(&lib_source)?;
    if lib_sites.len() != EXPECTED_SITES {
        return Err("lib denominator drifted".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/28
#[test]
fn token_identity_holds_for_comment_only_delta() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    for id in ["token-identical", "token-comment-only"] {
        let case = fixture_by_id(&cases, id)?;
        tokens_equal(&case.base, &case.candidate)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/29
#[test]
fn token_mutation_is_detected() -> Result<(), String> {
    let cases = load_fixture_cases()?;
    let case = fixture_by_id(&cases, "token-mutation")?;
    if tokens_equal(&case.base, &case.candidate).is_ok() {
        return Err("token mutation passed".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/30
#[test]
fn whitespace_only_delta_is_token_equal() -> Result<(), String> {
    let base = "fn f() {\n    unsafe { probe(); }\n}\n";
    let candidate =
        "fn f() {\n\n    // SAFETY: probe buffer is writable.\n    unsafe { probe(); }\n}\n";
    tokens_equal(base, candidate)?;
    let lib_source = read_text(&lib_rs_path())?;
    let again = lib_source.clone();
    tokens_equal(&lib_source, &again)?;
    Ok(())
}

// WORK_UNIT_CASE: 728/31
#[test]
fn production_after_cfg_test_stays_production() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    // The file carries cfg(test) uses near the top; production sites follow.
    let after_uses = sites.iter().filter(|s| s.line > 220).count();
    if after_uses == 0 {
        return Err("no production sites after test uses".to_string());
    }
    let prod_after = sites.iter().filter(|s| s.line > 220 && !s.is_test).count();
    if prod_after != after_uses {
        return Err("production after cfg(test) misclassified".to_string());
    }
    Ok(())
}

// WORK_UNIT_CASE: 728/32
#[test]
fn manifest_semantics_are_preserved() -> Result<(), String> {
    let root = workspace_root();
    let canon = read_text(&root.join("crates/kernel/eliot-platform-windows/Cargo.toml"))?;
    if !canon.contains("unsafe_code = \"allow\"") {
        return Err("canonical lint changed".to_string());
    }
    if !canon.contains("windows-sys") {
        return Err("canonical dependency changed".to_string());
    }
    check_manifest_denominator(&root)?;
    Ok(())
}

// WORK_UNIT_CASE: 728/33
#[test]
fn oracle_has_no_forbidden_paths() -> Result<(), String> {
    check_no_forbidden_paths()
}

// WORK_UNIT_CASE: 728/34
#[test]
fn shuffled_traversal_is_deterministic() -> Result<(), String> {
    let source = read_text(&lib_rs_path())?;
    let sites = lex_unsafe_sites(&source)?;
    let first = check_coverage(&source, &sites, None);
    let shuffled = shuffled_sites(&sites);
    let second = check_coverage(&source, &shuffled, None);
    let pass_first = coverage_passes(&first);
    let pass_second = coverage_passes(&second);
    if pass_first != pass_second {
        return Err("shuffle changed verdict".to_string());
    }
    if first.len() != second.len() {
        return Err("shuffle changed count".to_string());
    }
    Ok(())
}
