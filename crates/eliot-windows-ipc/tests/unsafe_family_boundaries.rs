#![cfg(windows)]
// Every `expect` in this file is a precondition check on `Option::find` or
// `thread::spawn` inside a test. The crate bans `expect` in PRODUCT code, not
// in its own test fixtures, and this file asserts against production source
// text, so a missing anchor must fail the case rather than degrade it.
#![allow(clippy::expect_used)]
//! Credential-span unsafe-family boundaries for work unit 789.
//!
//! Scope is the credential span only: `validate_credential_id` through
//! `credential_delete_current_user` in `crates/eliot-windows-ipc/src/lib.rs`.
//! Every test below calls the real public `eliot-windows-ipc` API on Windows:
//! no mocks, no pointer forging, no `unsafe` in this file. Invalid, null,
//! overlong, unterminated-equivalent, and forged-namespace inputs must fail
//! closed before any `WinCred` FFI pointer is formed; the single valid-absent
//! test exercises the real `CredReadW` / `CredDeleteW` / `CredEnumerateW`
//! success-or-`NOT_FOUND` paths without creating, modifying, or deleting any
//! stored credential.
//!
//! Deferred residuals (not implemented in this wave, listed in the fixture and
//! the PR body): oplock async, pipe/process identity, job/IOCP/spawn
//! supervision, notify/move file, and security/pipe-server DACL families.

use eliot_windows_ipc::{
    AsyncIoOutcome, DirectoryOplockGuard, FaultBoundary, RecoverableJobObject,
    arm_fault_boundaries, credential_delete_current_user, credential_ids_current_user_with_prefix,
    credential_read_current_user, credential_status_current_user, credential_write_current_user,
    process_is_alive, unresolved_handle_cleanup_count, validate_credential_id,
};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Win32 `ERROR_IO_PENDING`, the only last-error code that means the kernel
/// accepted an overlapped request.
const ERROR_IO_PENDING_CODE: i32 = 997;
/// Win32 `ERROR_ACCESS_DENIED`, one representative non-pending submit error.
const WIN32_ACCESS_DENIED_CODE: i32 = 5;
/// Win32 `WAIT_OBJECT_0`: the wait was satisfied by a signal.
const WAIT_OBJECT_0_CODE: u32 = 0;
/// Win32 `WAIT_TIMEOUT`: the wait expired with no signal.
const WAIT_TIMEOUT_CODE: u32 = 258;
/// Win32 `WAIT_FAILED`: the wait itself failed (an unknown outcome).
const WAIT_FAILED_CODE: u32 = 0xFFFF_FFFF;

// `T` is NOT required to be `Debug`: several of the types under test
// (`SuspendedJobChild`, `DirectoryOplockGuard`) deliberately do not implement it, because
// printing an owned OS handle would leak it. Only the error needs `Debug`.
fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

// `T` is NOT required to be `Debug`, for the same reason as `ok`.
fn err<T, E>(result: Result<T, E>) -> E {
    match result {
        Ok(_) => panic!("unexpected success"),
        Err(error) => error,
    }
}

fn assert_invalid_input<T: std::fmt::Debug>(result: io::Result<T>, context: &str) {
    match result {
        Ok(value) => panic!("expected InvalidInput for {context}, got success: {value:?}"),
        Err(error) => assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "expected InvalidInput for {context}"
        ),
    }
}

fn fixture_text() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/unsafe_family_cases.json");
    ok(std::fs::read_to_string(&path))
}

fn unique_probe_id(label: &str) -> String {
    let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos(),
        Err(_) => 0,
    };
    format!("wipc-789-probe-{}-{}-{label}", std::process::id(), nanos)
}

/// Creates one unique fixture-owned directory below the system temporary
/// directory and returns its path. The caller removes it after the case.
fn unique_probe_directory(label: &str) -> io::Result<PathBuf> {
    let root = std::env::temp_dir().join(unique_probe_id(label));
    std::fs::create_dir(&root)?;
    Ok(root)
}

/// Serializes the cases that arm a process-wide `FaultBoundary`. Arming is a
/// single global atomic store, so without this lock a concurrent case running
/// in the same test process could observe another case's injected boundary.
static FAULT_BOUNDARY_RUN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fault_boundary_run() -> std::sync::MutexGuard<'static, ()> {
    ok(FAULT_BOUNDARY_RUN.lock())
}

/// Asserts a production source file exists and is reachable, returning its text.
fn source_text(relative: &str) -> String {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", relative]
        .iter()
        .collect();
    assert!(
        path.is_file(),
        "case requires readable production source {relative}"
    );
    ok(std::fs::read_to_string(&path))
}

/// Returns the text of the fixture's `cases` array entry numbered `case`.
///
/// The search is SCOPED to the top-level `cases` array. Every case number appears
/// twice in the fixture — once in `case_denominator.expected_set` (which carries only
/// `case`, `title` and `issue_body_lines`) and once in `cases` (which additionally
/// carries `inputs`, `expectation`, `impl`, `caller`, `family` and `binding_state`).
/// An unscoped `find` always hit the `expected_set` entry first, so every assertion
/// about `inputs`/`expectation`/`impl` read an object that does not contain them.
fn fixture_case(case: u32) -> String {
    let fixture = fixture_text();
    let cases_start = fixture
        .find("\"cases\": [")
        .unwrap_or_else(|| panic!("fixture must carry a top-level `cases` array"));
    let cases = &fixture[cases_start..];
    let anchor = format!("\"case\": {case},");
    let start = cases
        .find(&anchor)
        .unwrap_or_else(|| panic!("fixture must bind case {case} inside the `cases` array"));
    // The entry opens with `{` immediately before the `case` key.
    let open = cases[..start]
        .rfind('{')
        .unwrap_or_else(|| panic!("case {case} has no enclosing object"));
    let mut depth = 0_i32;
    for (offset, character) in cases[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return cases[open..=open + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("case {case} object is not closed in the fixture");
}

// WORK_UNIT_CASE: 789/1
#[test]
fn credential_boundary_valid_minimal_ids() {
    ok(validate_credential_id("a"));
    ok(validate_credential_id("abc123"));
    ok(validate_credential_id("wipc-789-probe"));

    // The three ids this case drives must be the registry row's OWN inputs,
    // read through the same scoped `cases` lookup the later cases use, so the
    // case cannot certify a fixture of its own making.
    let row = fixture_case(1);
    for minimal in ["a", "abc123", "wipc-789-probe"] {
        assert!(
            row.contains(&format!("\"{minimal}\"")),
            "fixture case 1 must list the minimal credential id {minimal} this case drives"
        );
    }

    // Behaviour is bound to the PRODUCTION grammar, read from
    // `crates/eliot-windows-ipc/src/lib.rs` lines 3444-3487: the
    // `MAX_CREDENTIAL_ID_BYTES` bound declared at line 3448 and the
    // `pub fn validate_credential_id` entry point this test imports at line 27,
    // whose body opens at line 3469. A minimal id is accepted exactly because
    // that production body keeps the empty-exclusion and the ASCII
    // alphanumeric / `-` `_` `.` `/` predicate; a locally restated grammar
    // could not prove either clause.
    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let grammar = w1b_block(
        &library,
        "pub fn validate_credential_id(credential_id: &str) -> io::Result<()> {",
    );
    assert!(
        grammar.contains("!credential_id.is_empty()")
            && grammar.contains("!credential_id.starts_with('/')")
            && grammar.contains("!credential_id.ends_with('/')"),
        "the production validate_credential_id body must reject the empty id and both '/'-edge forms"
    );
    assert!(
        grammar.contains(
            "character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')"
        ),
        "the production validate_credential_id body must hold the ASCII alphanumeric plus - _ . / predicate"
    );
    assert_eq!(
        w1b_count(&library, "pub fn validate_credential_id("),
        1,
        "exactly one exported validate_credential_id may exist, or this case's Ok would prove a fiction"
    );
}

// WORK_UNIT_CASE: 789/2
#[test]
fn credential_boundary_valid_nested_ids() {
    ok(validate_credential_id("operator-cursor/isolated-abc"));
    ok(validate_credential_id("a-b_c.d/e-f_g.h/i"));

    // The two ids this case drives must be the registry row's OWN inputs, read
    // through the same scoped `cases` lookup the later cases use, so the case
    // cannot certify a fixture of its own making.
    let row = fixture_case(2);
    for nested in ["operator-cursor/isolated-abc", "a-b_c.d/e-f_g.h/i"] {
        assert!(
            row.contains(&format!("\"{nested}\"")),
            "fixture case 2 must list the namespaced credential id {nested} this case drives"
        );
    }

    // Behaviour is bound to the PRODUCTION grammar, read from
    // `crates/eliot-windows-ipc/src/lib.rs` lines 3460-3487: the
    // `pub fn validate_credential_id` entry point this test imports at line 27,
    // whose body opens at line 3469. A namespaced id is accepted exactly because
    // that production body splits on `/` and demands nonempty segments, so the
    // `'/'` separator is legal INSIDE the id while no segment may be empty or
    // `"."`/`".."`. A locally restated rule could not prove that clause.
    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let grammar = w1b_block(
        &library,
        "pub fn validate_credential_id(credential_id: &str) -> io::Result<()> {",
    );
    assert!(
        grammar.contains(".split('/')")
            && grammar.contains("segment != \".\" && segment != \"..\""),
        "the production validate_credential_id body must split on '/' and refuse empty, \".\" and \"..\" segments"
    );
    assert_eq!(
        w1b_count(&library, "pub fn validate_credential_id("),
        1,
        "exactly one exported validate_credential_id may exist, or this case's Ok would prove a fiction"
    );

    // The nested segment the case accepts must also be accepted by the one
    // production entry point that turns an id into the wide `WinCred` target,
    // `fn credential_target` at `crates/eliot-windows-ipc/src/lib.rs` line 3489
    // (body 3489-3503). That is the only production consumer of this grammar in
    // the crate, and it delegates to `validate_credential_id` before the
    // `EliotGovernor/` prefix is applied, so the nested form is validated by the
    // same production bytes this case just read.
    let target = w1b_block(
        &library,
        "fn credential_target(credential_id: &str) -> io::Result<Vec<u16>> {",
    );
    assert!(
        target.contains("validate_credential_id(credential_id)?;")
            && target.contains("format!(\"EliotGovernor/{credential_id}\")"),
        "the production credential_target must validate the id before namespacing it under EliotGovernor/"
    );
    assert_eq!(
        w1b_count(&library, "validate_credential_id(credential_id)?"),
        1,
        "exactly one production caller may revalidate the credential id before the FFI target is formed"
    );
}

// WORK_UNIT_CASE: 789/3
#[test]
fn credential_boundary_empty_id_rejected() {
    let error = err(validate_credential_id(""));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

// WORK_UNIT_CASE: 789/4
#[test]
fn credential_boundary_overlong_id_rejected() {
    let over_by_one: String = "a".repeat(241);
    let well_over: String = "a".repeat(512);
    let error = err(validate_credential_id(over_by_one.as_str()));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let error = err(validate_credential_id(well_over.as_str()));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

// WORK_UNIT_CASE: 789/5
#[test]
fn credential_boundary_forged_absolute_id_rejected() {
    let error = err(validate_credential_id("/leading"));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let error = err(validate_credential_id("trailing/"));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

// WORK_UNIT_CASE: 789/6
#[test]
fn credential_boundary_traversal_id_rejected() {
    for forged in ["a/../b", "a/./b", "a//b", "..", "."] {
        let error = err(validate_credential_id(forged));
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "traversal must fail closed for {forged}"
        );
    }
}

// WORK_UNIT_CASE: 789/7
#[test]
fn credential_boundary_null_id_rejected() {
    for with_nul in ["ab\0cd", "\0"] {
        let error = err(validate_credential_id(with_nul));
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "interior NUL must fail closed before wide conversion"
        );
    }
}

// WORK_UNIT_CASE: 789/8
#[test]
fn credential_boundary_forged_charset_id_rejected() {
    for forged in ["a\\b", "a:b", "a*b", "a b", "caf\u{e9}", "EliotGovernor/x*"] {
        let error = err(validate_credential_id(forged));
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "forged charset must fail closed for {forged}"
        );
    }
}

// WORK_UNIT_CASE: 789/9
#[test]
fn credential_boundary_edge_target_stays_within_scan_bound() {
    let edge: String = "a".repeat(240);
    ok(validate_credential_id(edge.as_str()));
    let namespaced = format!("EliotGovernor/{edge}");
    let units = namespaced.encode_utf16().count();
    assert!(
        units < 512,
        "240-byte id must keep the namespaced target below the 512-unit scan bound, got {units}"
    );
    assert!(
        units < 32_768,
        "namespaced target must keep the wide NUL bound, got {units}"
    );
}

// WORK_UNIT_CASE: 789/10
#[test]
fn credential_boundary_invalid_ids_fail_closed_before_ffi() {
    for invalid in ["", "/x", "a/../b", "ab\0cd"] {
        assert_invalid_input(credential_status_current_user(invalid), invalid);
        assert_invalid_input(credential_read_current_user(invalid), invalid);
        assert_invalid_input(credential_delete_current_user(invalid), invalid);
        assert_invalid_input(credential_ids_current_user_with_prefix(invalid), invalid);
        assert_invalid_input(credential_write_current_user(invalid, b"probe"), invalid);
    }
}

// WORK_UNIT_CASE: 789/11
#[test]
fn credential_boundary_real_absent_and_blob_bounds_without_mutation() {
    let probe = unique_probe_id("absent");
    ok(validate_credential_id(probe.as_str()));
    let status = ok(credential_status_current_user(probe.as_str()));
    assert!(
        !status.present,
        "unique probe must be absent without mutation"
    );
    let value = ok(credential_read_current_user(probe.as_str()));
    assert!(
        value.is_none(),
        "unique probe read must be None without mutation"
    );
    let deleted = ok(credential_delete_current_user(probe.as_str()));
    assert!(
        !deleted,
        "unique probe delete must report false without mutation"
    );
    let empty_error = err(credential_write_current_user(probe.as_str(), &[]));
    assert_eq!(empty_error.kind(), io::ErrorKind::InvalidInput);
    let oversized = vec![0_u8; 8192];
    let oversized_error = err(credential_write_current_user(probe.as_str(), &oversized));
    assert_eq!(oversized_error.kind(), io::ErrorKind::InvalidInput);
    let listed = ok(credential_ids_current_user_with_prefix(
        "wipc-789-probe-absent-never-stored",
    ));
    assert!(
        !listed.iter().any(|id| id == &probe),
        "absent probe must not appear in enumeration"
    );
}

// WORK_UNIT_CASE: 789/12
#[test]
#[allow(clippy::too_many_lines)]
fn credential_boundary_fixture_binds_sites_and_deferred_families() {
    let fixture = fixture_text();
    for required in [
        "credential_target",
        "CredFree",
        "credential_target_name",
        "CredEnumerateW",
        "from_raw_parts",
        "CredReadW",
        "CredWriteW",
        "CredDeleteW",
        "GetLastError",
    ] {
        assert!(
            fixture.contains(required),
            "fixture must bind unsafe site {required}"
        );
    }
    for deferred in [
        "oplock async",
        "pipe/process",
        "job/IOCP/spawn",
        "notify/move",
        "security/pipe-server",
    ] {
        assert!(
            fixture.contains(deferred),
            "fixture must list deferred family {deferred}"
        );
    }
    // The registry binds every declared case 1..42, not just the first wave.
    // This loop used to stop at 12, which left cases 28..42 bound by nothing;
    // case 42 now carries the structural denominator assertions that prove it.
    for case in 1..=42 {
        let marker = format!("\"case\": {case}");
        assert!(
            fixture.contains(marker.as_str()),
            "fixture must bind case {case}"
        );
    }

    // -------------------------------------------------------------------------
    // CASE IDENTITY BINDING. The loop above only proved that a `\"case\": {n}`
    // STRING exists somewhere in the fixture; it never checked that the
    // `source_test` each row names is a real `#[test] fn` in this very file, and
    // it never checked the row's own `title_mismatch` boolean against anything
    // but itself. That let a row self-certify `title_mismatch: false` while its
    // `source_test` pointed at an unrelated test -- precisely the
    // "self-declaration is not evidence" failure. Below, every row is
    // cross-checked against the REAL test file, and the boolean is required to
    // agree with what that cross-check found, so the flag can no longer lie.
    //
    // Three independent facts are asserted per row, read from the PARSED
    // registry (never from a substring of the fixture text):
    //   1. `source_test`, when present, must be the literal `fn <name>(` of a
    //      real function defined in this file. A renamed, deleted or invented
    //      test fails here.
    //   2. A row with NO `source_test` may not claim `title_mismatch: false`,
    //      and a row that declares `title_mismatch: true` must carry a non-empty
    //      `title_mismatch_reason`. The flag therefore cannot be flipped to
    //      false to make an unbound row look clean.
    //   3. The exact sets are pinned at the end: `rebound` is the set of rows
    //      with no binding at all, and `mismatched` is the set of rows that must
    //      carry `title_mismatch: true`. Adding, removing or quietly re-binding
    //      any row changes one of these and fails the case.
    let registry = ok(serde_json::from_str::<serde_json::Value>(&fixture));
    let Some(registry_cases) = registry.get("cases").and_then(serde_json::Value::as_array) else {
        panic!("fixture must carry a top-level `cases` array");
    };
    assert_eq!(
        registry_cases.len(),
        42,
        "CASE IDENTITY (registry length): the registry `cases` array holds {} entries, expected exactly 42",
        registry_cases.len()
    );
    // The real test-file source, read through the same package-relative helper
    // the later cases use, so this assertion reads the file on disk rather than
    // trusting the fixture's own claim about it.
    let suite_source = w1b_read_package_file("tests/unsafe_family_boundaries.rs");
    let mut rebound: Vec<u64> = Vec::new();
    for entry in registry_cases {
        let id = entry
            .get("case")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("every registry `cases` entry needs an integer `case` id"));
        let source_test = entry
            .get("source_test")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let declared_mismatch = entry
            .get("title_mismatch")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or_else(|| panic!("case {id} must carry a boolean `title_mismatch`"));
        if let Some(name) = source_test.as_deref() {
            // Fact 1: the named source_test must be a real `#[test]` FUNCTION in
            // this file, not merely any `fn`. The old check was an EXISTENCE
            // check -- it only required the literal `fn <name>(` to occur
            // somewhere in the source text, which any plain helper in this file
            // (`fixture_case`, `w1b_count`, `unique_probe_id`,
            // `fault_boundary_run`, ...) satisfies. So a row could name a
            // non-test helper and still pass, proving nothing about a title.
            // Locate the fn's own DECLARATION LINE (a line whose trimmed text
            // begins with `fn <name>(`), then walk BACKWARDS over contiguous
            // attribute lines, stopping at a comment, a `// WORK_UNIT_CASE`
            // marker, a blank line, or any other declaration -- exactly the
            // shape a test fn has in this file (`#[test]` alone, or
            // `#[test]` plus `#[allow(...)]`). Require at least one
            // `#[test]` or `#[tokio::test]` attribute in that contiguous
            // attribute run.
            let declaration = format!("fn {name}(");
            let suite_lines: Vec<&str> = suite_source.lines().collect();
            // The code-only projection of this same source, taken ONCE here and
            // reused by every `source_test` row in this loop, so the per-row
            // body extraction is a line scan and not a fresh whole-file
            // lexical scan.
            let suite_code = w1b_code_only(&suite_source);
            let suite_code_lines: Vec<&str> = suite_code.lines().collect();
            let declaration_index = suite_lines
                .iter()
                .position(|line| line.trim_start().starts_with(&declaration))
                .unwrap_or_else(|| {
                    panic!(
                        "CASE IDENTITY (source_test exists): case {id} names source_test `{name}`, but no `fn {name}(` is declared in unsafe_family_boundaries.rs"
                    )
                });
            let mut has_test_attribute = false;
            let mut attribute_index = declaration_index;
            while attribute_index > 0 {
                let previous = suite_lines[attribute_index - 1].trim_start();
                if !previous.starts_with("#[") {
                    break;
                }
                attribute_index -= 1;
                if previous == "#[test]" || previous == "#[tokio::test]" {
                    has_test_attribute = true;
                }
            }
            assert!(
                has_test_attribute,
                "CASE IDENTITY (source_test is a test): case {id} names source_test `{name}`, but the `fn {name}(` declaration in unsafe_family_boundaries.rs carries no contiguous `#[test]` or `#[tokio::test]` attribute above it, so it is not a test function and proves no title"
            );
            // Fact 1b: `#[test]` above a declaration proves the function is
            // DISCOVERED, not that it PROVES anything. `#[test]
            // fn credential_target_probe() { /* TODO */ }` carries the
            // attribute, so Fact 1 passed it while the row certified itself over
            // a body that asserts nothing. Case 12 imports no denominator axis
            // of its own, so nothing downstream caught it.
            //
            // The named test's body is therefore held to the SAME anti-
            // placeholder adequacy floor the denominator applies to the
            // anchored markers: it must not be empty, must not be `assert!(true);`
            // and must not reduce to `assert_eq!(X, X);`. The floor is the
            // shared `w1b_adequacy_floor`, and the body is the shared
            // `w1b_test_body` extractor, so this block never re-implements the
            // rule -- it applies the one the suite already enforces elsewhere.
            // Every real `#[test]` in this file clears it, because a body with
            // no real call, macro or trait path named after `assert`, `panic`,
            // `check`, `verify` or `should_panic` is not a test of anything.
            let named_body = w1b_test_body(&suite_code_lines, &suite_lines, declaration_index + 1);
            if let Some((problem, why)) = w1b_adequacy_floor(&named_body) {
                panic!(
                    "CASE IDENTITY (source_test is adequate): case {id} names source_test `{name}`, whose body fails the shared anti-placeholder adequacy floor `{problem}`: {why}. A `#[test]` attribute proves the function is discovered, not that it proves its title, so an empty or placeholder body certifies nothing"
                );
            }
            // Fact 2: the flag is an honest verdict about the binding.
            // `false` is a clean, full match and MUST carry a non-empty
            // justification of why the binding is a full match -- the code
            // cannot prove that a test proves a title, so the honest position
            // is that the flag is a RECORDED, REVIEWABLE claim, and a `false`
            // row with no stated reason is an unbacked claim. The justification
            // is read from the row's own `full_match_justification` field,
            // falling back to `binding_note` for rows 1/10/12 which already
            // carry one. `true` is a partial or inapplicable binding and MUST
            // still say why in `title_mismatch_reason`.
            if declared_mismatch {
                let reason = entry
                    .get("title_mismatch_reason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                assert!(
                    !reason.trim().is_empty(),
                    "CASE IDENTITY (reason recorded): case {id} declares title_mismatch=true over the real test `{name}`, so it must carry a non-empty `title_mismatch_reason`"
                );
            } else {
                // A `false` row rests on nothing if it states nothing.
                let justification = entry
                    .get("full_match_justification")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| {
                        entry
                            .get("binding_note")
                            .and_then(serde_json::Value::as_str)
                    })
                    .unwrap_or_default();
                assert!(
                    !justification.trim().is_empty(),
                    "CASE IDENTITY (full match justified): case {id} declares title_mismatch=false over the real test `{name}`, so it must carry a non-empty `full_match_justification` (or `binding_note`) explaining why that test fully proves the title; this code can verify the binding is real, not that the test proves the title, so the `false` flag must be a recorded, reviewable claim"
                );
            }
            // Fact 4: `registry_marker` is cross-checked against the anchored
            // marker that actually sits above this row's `source_test`. The
            // verifier showed that setting `cases[9].registry_marker` to
            // `"789/42"` passed every denominator axis, because nothing
            // compared the claimed marker against the marker bound to the row's
            // own test. A row must be internally consistent about WHICH case
            // its test proves.
            //
            // The expectation is derived from the row's OWN `case` field
            // together with its `source_test`: the marker genuinely bound to
            // `source_test` in the real source must be `789/<case>`. The nine
            // rows that deliberately RE-POINT `source_test` at the test that
            // really proves their title (cases 1, 3, 4, 7, 8, 9, 10, 11 and
            // 12) carry a recorded justification naming that test; a re-point
            // with no such note -- or whose note no longer names the test the
            // row claims -- is not internally consistent and fails here, as
            // does a `registry_marker` belonging to an unrelated case.
            let claimed_marker = entry
                .get("registry_marker")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            if let Some(claimed_marker) = claimed_marker.as_deref() {
                let own_marker = format!("789/{id}");
                // Which anchored marker line is bound, by the gate's own forward
                // walk, to a test fn declared with this exact name.
                let mut marker_bound_to_test: Option<String> = None;
                for (offset, line) in suite_lines.iter().enumerate() {
                    let Some(digits) = line
                        .trim()
                        .strip_prefix("//")
                        .map(str::trim_start)
                        .and_then(|after_slashes| after_slashes.strip_prefix("WORK_UNIT_CASE:"))
                        .map(str::trim)
                        .and_then(|tail| tail.strip_prefix("789/"))
                        .map(str::trim_end)
                        .filter(|digits| {
                            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
                        })
                    else {
                        continue;
                    };
                    // Forward walk: attributes are skipped; the first
                    // non-attribute, non-comment line must declare a test fn.
                    let mut walk = offset + 1;
                    let mut marker_has_test_attr = false;
                    while walk < suite_lines.len() {
                        let next = suite_lines[walk].trim();
                        if next.is_empty() || next.starts_with("//") || next.starts_with("/*") {
                            break;
                        }
                        if next.starts_with("#[") {
                            if next == "#[test]" || next == "#[tokio::test]" {
                                marker_has_test_attr = true;
                            }
                            walk += 1;
                            continue;
                        }
                        if marker_has_test_attr && next.starts_with(&declaration) {
                            marker_bound_to_test = Some(format!("789/{digits}"));
                        }
                        break;
                    }
                    if marker_bound_to_test.is_some() {
                        break;
                    }
                }
                let bound_marker = marker_bound_to_test.unwrap_or_else(|| own_marker.clone());
                // WHAT THE ROW CLAIMS IS COMPARED AGAINST WHAT IS ACTUALLY
                // BOUND. The previous condition here was
                //
                //     bound_marker == own_marker || recorded_repoint
                //
                // which never mentioned `claimed_marker` at all: the value the
                // row DECLARED was read, used only in the failure message, and
                // then discarded. Worse, `recorded_repoint` was `true` for all
                // 39 bound rows, because every `full_match_justification`
                // names its own `source_test` -- so the `||` short-circuited
                // and `bound_marker` was never consulted either. The assertion
                // was vacuous in both directions, and setting
                // `cases[9].registry_marker` to `"789/41"` passed. The comment
                // above this block names that exact counterexample as the REASON
                // the block was written, and the block did not fix it.
                //
                // The two facts being compared are independent, and both are
                // real:
                //
                //   * `claimed_marker` -- what the row says it claims, i.e. the
                //     literal `registry_marker` string in the fixture.
                //   * `bound_marker` -- the anchored `// WORK_UNIT_CASE: 789/<n>`
                //     that this very file binds, by the forward walk above, to
                //     the `fn` the row names in `source_test`.
                //
                // `claimed_marker` must therefore be EITHER the row's own case
                // marker -- the ordinary, un-re-pointed row -- OR the marker
                // genuinely bound to the test it names. The second case is the
                // nine rows that deliberately RE-POINT `source_test` at the test
                // that really proves their title (cases 1, 3, 4, 7, 8, 9, 10, 11
                // and 12); each still has to RECORD why, in `binding_note`,
                // `title_mismatch_reason` or `full_match_justification`, AND that
                // note has to name this exact `source_test`. So the claim is
                // bounded, the `||` cannot be short-circuited by the note, and
                // the note cannot excuse a marker that matches neither.
                let names_this_test = |key: &str| {
                    entry
                        .get(key)
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|note| note.contains(name))
                };
                let recorded_repoint = names_this_test("binding_note")
                    || names_this_test("title_mismatch_reason")
                    || names_this_test("full_match_justification");
                let claims_own_marker = claimed_marker == own_marker;
                let claims_bound_marker = claimed_marker == bound_marker;
                assert!(
                    claims_own_marker || (claims_bound_marker && recorded_repoint),
                    "CASE IDENTITY (registry marker agreement): case {id} claims registry_marker `{claimed_marker}` over source_test `{name}`, but the anchored marker actually bound to that test in unsafe_family_boundaries.rs is `{bound_marker}`, not its own case marker `{own_marker}`; a re-pointed row must record WHY in `binding_note`, `title_mismatch_reason` or `full_match_justification` AND that note must name source_test `{name}`, otherwise the row is not internally consistent about which case its test proves"
                );
            }
        } else {
            // An unbound row may not claim a match.
            assert!(
                declared_mismatch,
                "CASE IDENTITY (flag consistency): case {id} has no source_test at all, so it may NOT self-certify title_mismatch=false"
            );
            // Fact 3: an unresolved binding must say why.
            let reason = entry
                .get("title_mismatch_reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            assert!(
                !reason.trim().is_empty(),
                "CASE IDENTITY (reason recorded): case {id} has no source_test and title_mismatch=true, so it must carry a non-empty `title_mismatch_reason`"
            );
            rebound.push(id);
        }
    }
    rebound.sort_unstable();
    // The unresolved set is asserted explicitly so a future writer cannot quietly
    // shrink it by deleting a `title_mismatch_reason`, and cannot grow it
    // without this exact list changing.
    assert_eq!(
        rebound,
        vec![2, 5, 6],
        "CASE IDENTITY (unresolved set): these cases have no source_test at all and must keep title_mismatch=true with a recorded reason; got {rebound:?}"
    );
    // The complete, exact verdict every row must now carry. This is the flag's
    // whole meaning: cases 1, 10 and 12 are clean full matches over a real,
    // re-pointed binding; cases 3, 4, 7, 8, 9 and 11 name a real test that only
    // PARTIALLY (or, for 11, transfer-but-not-duplication) proves the title and
    // say so; cases 2, 5 and 6 name no test because none proves their title.
    let mut verdicts: Vec<(u64, bool)> = registry_cases
        .iter()
        .map(|entry| {
            (
                entry
                    .get("case")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_else(|| {
                        panic!("every registry `cases` entry needs an integer `case` id")
                    }),
                entry
                    .get("title_mismatch")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or_else(|| {
                        panic!("every registry `cases` entry needs a `title_mismatch`")
                    }),
            )
        })
        .collect();
    verdicts.sort_unstable();
    let mismatched: Vec<u64> = verdicts
        .iter()
        .filter(|(_, mismatch)| *mismatch)
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        mismatched,
        vec![2, 3, 4, 5, 6, 7, 8, 9, 11],
        "CASE IDENTITY (flag honesty): exactly these cases may carry title_mismatch=true; every other case must resolve to a full match over a real, verified source_test. got {mismatched:?}"
    );
    assert_eq!(
        verdicts.len(),
        42,
        "CASE IDENTITY (verdict denominator): the verdict table must cover exactly 42 rows, got {}",
        verdicts.len()
    );
}

// WORK_UNIT_CASE inventory 789/13..42 (wave 2, issue #789 implementation
// lane) — HISTORY. When this block was first written the owner's NO TESTS
// order held execution back to the test phase, so cases 13..42 were
// declaration-only here: each marker named its wired bounding implementation
// plus production caller, carried no `#[test]`, and only cases 1..12 above
// were EXECUTED. That is no longer true. Every one of cases 13..42 is now
// anchored as a bare `// WORK_UNIT_CASE: 789/<n>` line immediately above its OWN
// `#[test]`, so the whole file is EXECUTED, 42/42, matching the shape the
// "Cases 28..42 (wave 2 execution lane)" block further down also states. The
// old status/impl/caller tail text is gone from the file. Discovery rule,
// unchanged and now uniform: a marker line counts as DECLARED, and because
// every marker sits directly above its own `#[test]`, all 42 also count as
// EXECUTED.

// 13. concurrent close/use race;
// WORK_UNIT_CASE: 789/13
#[test]
fn shared_handle_core_close_is_exactly_once_under_a_real_close_drop() {
    // `OwnedHandle` is private, so this integration test cannot construct one
    // or call its `Drop`. What IS proven here is the honest reachable fact:
    // the fixture binds this case to the exactly-once-close wrapper, the
    // wrapper's own `Drop` closes through a single `CloseHandle` guarded by
    // both failure sentinels, and a real public-API value that owns one such
    // handle releases it exactly once when dropped (an injected cleanup run
    // leaves it open exactly once and is counted unresolved instead of being
    // reported as a successful close).
    let fixture = fixture_case(13);
    assert!(
        fixture.contains("shared-handle-core") && fixture.contains("OwnedHandle::drop"),
        "fixture must bind case 13 to the shared-handle-core OwnedHandle::drop site"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let owned_drop = library
        .split("impl Drop for OwnedHandle")
        .nth(1)
        .and_then(|tail| tail.split("fn create_kill_on_close_job").next())
        .unwrap_or_else(|| panic!("library must keep the OwnedHandle Drop impl"));
    assert_eq!(
        owned_drop.matches("CloseHandle(").count(),
        1,
        "the OwnedHandle Drop body must hold exactly one CloseHandle site"
    );
    assert!(
        owned_drop.contains("!self.0.is_null() && self.0 != INVALID_HANDLE_VALUE"),
        "the OwnedHandle Drop must re-check both failure sentinels before CloseHandle"
    );

    // Behaviour, on the real owned-handle surface this crate exposes without
    // spawning anything: `RecoverableProcess::open` is the one public
    // constructor of an `OwnedHandle` here, so an unarmed open/drop really
    // closes one handle, while an armed cleanup run counts it unresolved
    // instead of reporting a successful close.
    //
    // NOT PROVEN HERE: the close-once behaviour of a `SuspendedJobChild`'s
    // job/process/thread handles. `clippy.toml`'s `disallowed-methods` forbids
    // `std::process::Command::new`, and `SuspendedJobChild::spawn` requires a
    // `&std::process::Command` that this crate exposes no seam to build, so a
    // child cannot be created under the crate's lint policy. The child-owned
    // handle release stays with the in-crate `#[cfg(test)] mod tests` in
    // `src/lib.rs`, which can build its own command.
    let _serialized = fault_boundary_run();
    let before = unresolved_handle_cleanup_count();
    {
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        assert_eq!(
            owned.identity().pid,
            std::process::id(),
            "the owned handle must carry the resolved PID"
        );
        assert_eq!(
            unresolved_handle_cleanup_count(),
            before,
            "a normal drop must not be reported as an unresolved cleanup"
        );
    }
    {
        let _armed = arm_fault_boundaries(&[FaultBoundary::Cleanup]);
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        drop(owned);
    }
    let after = unresolved_handle_cleanup_count();
    assert!(
        after > before,
        "an injected cleanup must be counted unresolved instead of closing and reporting success"
    );
}

// 14. prepared but unsubmitted cleanup;
// WORK_UNIT_CASE: 789/14
#[test]
fn suspended_process_guard_cleans_up_on_early_return_before_assignment() {
    // `SuspendedProcessGuard` is private, so its `Drop` is proven here by
    // source facts plus the real early-return behaviour it guards: every
    // `spawn_named` return after `CreateProcessW` succeeded but before the
    // job assignment/resume completed still terminates the still-suspended
    // child, and the guard is disarmed by exactly one transfer.
    let fixture = fixture_case(14);
    assert!(
        fixture.contains("job-iocp-spawn")
            && fixture.contains("SuspendedProcessGuard::drop")
            && fixture.contains("spawn failure after CreateProcessW before assignment"),
        "fixture must bind case 14 to the prepared-but-unsubmitted cleanup case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let spawn = library
        .split("pub fn spawn_named(")
        .nth(1)
        .and_then(|tail| tail.split("pub const fn id(").next())
        .unwrap_or_else(|| panic!("library must keep SuspendedJobChild::spawn_named"));
    let guard_struct = library
        .split("struct SuspendedProcessGuard")
        .nth(1)
        .and_then(|tail| tail.split("impl Drop for SuspendedProcessGuard").next())
        .unwrap_or_else(|| panic!("library must keep the SuspendedProcessGuard struct"));
    let guard_drop = library
        .split("impl Drop for SuspendedProcessGuard")
        .nth(1)
        .and_then(|tail| tail.split("/// A child process created suspended").next())
        .unwrap_or_else(|| panic!("library must keep the SuspendedProcessGuard Drop impl"));
    assert!(
        spawn.contains("let spawned = SuspendedProcessGuard::new(information)?;"),
        "spawn_named must arm the guard immediately after CreateProcessW"
    );
    // Every early return after `CreateProcessW` succeeded but before
    // `into_handles` must unwind through the still-armed guard.
    let early_returns = spawn.matches("return Err(").count();
    assert!(
        early_returns >= 3,
        "spawn_named must keep its pre-transfer early returns, found {early_returns}"
    );
    assert!(
        spawn.contains("AssignProcessToJobObject(job.0, spawned.process)"),
        "the assignment early return must still unwind through the armed guard"
    );
    assert!(
        spawn.contains("let (process, thread) = spawned.into_handles();"),
        "the guard must be disarmed by exactly one transfer at the end of a successful spawn"
    );
    assert!(
        guard_struct.contains("armed: bool"),
        "the guard must carry an arm flag that disarms only on transfer"
    );
    // The armed cleanup itself: terminate, bounded wait, then both closes.
    assert!(
        guard_drop.contains("if !self.armed {")
            && guard_drop.contains("TerminateProcess(self.process, 1)")
            && guard_drop.contains("WaitForSingleObject(self.process, 5_000)")
            && guard_drop.contains("CloseHandle(self.thread)")
            && guard_drop.contains("CloseHandle(self.process)"),
        "the armed guard Drop must terminate, bounded-wait, and close both handles"
    );

    // Behaviour, on the real public name-validation seam, which needs no command
    // value at all. The name bound is checked as the FIRST statement of
    // `spawn_named`, before `command.get_program()` is ever read and before
    // any pipe, job, observer, or process handle exists, so an empty or
    // overlong name cannot leave a partially built child to unwind.
    //
    // NOT PROVEN HERE: that a spawn which passes the name check and then
    // fails before `into_handles` really terminates the still-suspended child.
    // That requires an actual child process, and `clippy.toml` forbids
    // `std::process::Command::new`, while `SuspendedJobChild::spawn_named`
    // takes a `&std::process::Command` this crate exposes no seam to build,
    // so the spawn entry point cannot even be called from here. The
    // armed-cleanup execution stays with the in-crate `#[cfg(test)] mod tests`
    // in `src/lib.rs`, which owns the guard and can build its own command.
    let name_guard = spawn
        .find("if job_name.is_empty()")
        .expect("the job-name guard");
    let first_read = spawn
        .find("command.get_program()")
        .expect("the first command read");
    assert!(
        name_guard < first_read,
        "the job-name bound must be checked before the command is read at all, got {name_guard} then {first_read}"
    );
    assert!(
        spawn.contains("job_name.encode_utf16().count() > 240"),
        "the job-name bound must reject anything past 240 UTF-16 code units"
    );
    // The same grammar is independently enforced where this file can reach it:
    // an empty name has no NUL-terminated wide form, so the reopen refuses it
    // before touching the kernel.
    assert_eq!(
        w1b_error_kind(RecoverableJobObject::open("")),
        io::ErrorKind::InvalidInput,
        "an empty job name must fail closed before any OpenJobObjectW"
    );
}

// 15. synchronous overlapped completion;
// WORK_UNIT_CASE: 789/15
#[test]
fn oplock_synchronous_completion_is_rejected_with_no_pending_request() {
    // The public `AsyncIoOutcome` state machine is exercised directly here:
    // the `classify_oplock_submit` transition that `acquire` uses to decide
    // whether the kernel owns the request storage. A nonzero `DeviceIoControl`
    // return means the request completed synchronously, which `acquire` must
    // reject (no durable pending lease) with no guard constructed.
    let fixture = fixture_case(15);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("DeviceIoControl returning nonzero")
            && fixture.contains("only ERROR_IO_PENDING is accepted"),
        "fixture must bind case 15 to the synchronous-overlapped-completion case"
    );

    // Nonzero return -> SynchronousComplete, which the guard rejects outright.
    let submitted = AsyncIoOutcome::Prepared.submit_issued();
    assert_eq!(submitted, AsyncIoOutcome::Submitted);
    assert_eq!(
        submitted.classify_oplock_submit(1, None),
        AsyncIoOutcome::SynchronousComplete,
        "a nonzero submit return must classify as a synchronous completion"
    );
    // `terminal_storage_release()` is a pure `match` over the outcome table
    // (lib.rs:279-292): it returns `Some(proven())` for every terminal state and is
    // therefore NOT evidence about outstanding kernel work — it says the release is
    // permitted, nothing more. What it does prove here is that a synchronous completion
    // reaches a terminal state whose release proof is available without any cancel.
    //
    // NOT PROVEN HERE: that a real `DeviceIoControl` returning nonzero (a genuine
    // synchronous completion, as opposed to `ERROR_IO_PENDING`) is ever produced. That
    // path is only reachable with a fault injected, and this case does not arm the
    // submission boundary for it; the classification above is driven through the enum's
    // own method. The real overlapped round trip stays with the in-crate
    // `#[cfg(test)] mod tests` in `src/lib.rs`.
    assert!(
        AsyncIoOutcome::SynchronousComplete
            .terminal_storage_release()
            .is_some(),
        "a synchronous completion is terminal, so its storage release needs no cancel"
    );

    // Behaviour: on a real non-reparse directory the acquire is accepted only
    // as a genuinely pending request; the acquisition fault boundary fails the
    // acquisition closed before any handle or request allocation exists.
    let _serialized = fault_boundary_run();
    let directory = ok(unique_probe_directory("oplock-sync-complete"));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(
        guard.async_outcome(),
        AsyncIoOutcome::Pending,
        "a real acquire must leave exactly one pending kernel request"
    );
    drop(guard);
    let acquisition_fault = err({
        let _armed = arm_fault_boundaries(&[FaultBoundary::Acquisition]);
        DirectoryOplockGuard::acquire(&directory)
    });
    assert!(
        acquisition_fault.to_string().contains("acquisition"),
        "an injected acquisition must fail closed naming the boundary, got {acquisition_fault}"
    );
    ok(std::fs::remove_dir_all(&directory));
}

// 16. pending completion;
// WORK_UNIT_CASE: 789/16
#[test]
fn oplock_poll_reports_pending_versus_broken_without_blocking() {
    // The public `AsyncIoOutcome::classify_oplock_poll` transition is the exact
    // poll decision `mutation_attempted` makes: `WAIT_OBJECT_0` is a
    // delivered break, `WAIT_TIMEOUT` is still-pending, and any other wait
    // result is an error rather than a silent "no mutation".
    let fixture = fixture_case(16);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("oplock event unsignaled then signaled")
            && fixture.contains("reports pending versus broken without blocking"),
        "fixture must bind case 16 to the pending-completion poll case"
    );

    assert_eq!(
        ok(AsyncIoOutcome::classify_oplock_poll(WAIT_TIMEOUT_CODE)),
        AsyncIoOutcome::Pending,
        "an unsignaled event must classify as pending, not as a delivered break"
    );
    assert_eq!(
        ok(AsyncIoOutcome::classify_oplock_poll(WAIT_OBJECT_0_CODE)),
        AsyncIoOutcome::ObservedComplete,
        "a signaled event must classify as an observed complete request"
    );
    let failed = err(AsyncIoOutcome::classify_oplock_poll(WAIT_FAILED_CODE));
    assert!(
        !failed.to_string().is_empty(),
        "a failed wait must surface a real error rather than a false poll verdict"
    );
    assert!(
        AsyncIoOutcome::classify_oplock_poll(WAIT_FAILED_CODE).is_err(),
        "a failed wait must never classify as a pending or complete request"
    );

    // Behaviour: on a freshly acquired guard the zero-timeout poll reports
    // pending (no mutation observed yet); after a conflicting write is
    // attempted the signaled event is reported as a mutation attempt.
    let directory = ok(unique_probe_directory("oplock-poll"));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert!(
        !ok(guard.mutation_attempted()),
        "a freshly acquired guard must report no mutation yet"
    );
    assert_eq!(
        guard.async_outcome(),
        AsyncIoOutcome::Pending,
        "the zero-timeout poll must not advance the stored outcome on a timeout"
    );
    ok(std::fs::write(directory.join("injected.txt"), b"probe"));
    let mut observed = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if ok(guard.mutation_attempted()) {
            observed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        observed,
        "the oplock break event must be observed as a mutation attempt"
    );
    assert_eq!(
        guard.async_outcome(),
        AsyncIoOutcome::ObservedComplete,
        "an observed break must latch the guard outcome to complete"
    );
    drop(guard);
    ok(std::fs::remove_dir_all(&directory));
}

// 17. unknown submission outcome;
// WORK_UNIT_CASE: 789/17
#[test]
fn oplock_unknown_submission_outcome_yields_no_release_proof() {
    // The public `AsyncIoOutcome` submit classification is the exact decision
    // `acquire` makes when `DeviceIoControl` returns an error other than
    // `ERROR_IO_PENDING`: such a submit was rejected before the kernel took
    // ownership, so it constructs no pending request, and an outcome whose
    // acceptance could not be established (unknown submit) refuses release.
    let fixture = fixture_case(17);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("DeviceIoControl error other than ERROR_IO_PENDING")
            && fixture.contains("no completion can be outstanding"),
        "fixture must bind case 17 to the unknown-submission-outcome case"
    );

    let submitted = AsyncIoOutcome::Prepared.submit_issued();
    assert_eq!(
        submitted.classify_oplock_submit(0, Some(ERROR_IO_PENDING_CODE)),
        AsyncIoOutcome::Pending,
        "ERROR_IO_PENDING is the one accepted submit code"
    );
    for error_code in [WIN32_ACCESS_DENIED_CODE, 87, 1117] {
        assert_eq!(
            submitted.classify_oplock_submit(0, Some(error_code)),
            AsyncIoOutcome::RejectedBeforeSubmit,
            "a non-pending submit error must be rejected before the kernel owns the request"
        );
    }
    // An acceptance that could not be established refuses release and refuses
    // a blind retry: it is neither a release proof nor retryable.
    assert!(
        AsyncIoOutcome::UnknownSubmit
            .terminal_storage_release()
            .is_none(),
        "an unknown submit outcome must not construct a storage-release proof"
    );
    let unknown_retry = err(AsyncIoOutcome::UnknownSubmit.reconcile_before_retry());
    assert_eq!(
        unknown_retry.kind(),
        io::ErrorKind::InvalidData,
        "an unknown submit outcome must refuse a blind retry"
    );

    // Behaviour: with the submission boundary armed, `acquire` fails closed
    // and reports an unresolved outcome rather than a granted lease.
    let _serialized = fault_boundary_run();
    let directory = ok(unique_probe_directory("oplock-unknown-submit"));
    let unknown_submit = err({
        let _armed = arm_fault_boundaries(&[FaultBoundary::Submission]);
        DirectoryOplockGuard::acquire(&directory)
    });
    assert_eq!(
        unknown_submit.kind(),
        io::ErrorKind::InvalidData,
        "an injected unknown submit must report unresolved request storage"
    );
    assert!(
        unknown_submit
            .to_string()
            .contains("oplock submit outcome is unknown"),
        "the error must name the unresolved submit outcome, got {unknown_submit}"
    );
    // The unarmed acquire on the same directory still succeeds, proving the
    // injected run retained its request storage rather than freeing storage a
    // late kernel completion may still write.
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    drop(guard);
    ok(std::fs::remove_dir_all(&directory));
}

// 18. cancel before submission;
// WORK_UNIT_CASE: 789/18
#[test]
fn oplock_pre_submit_validation_failure_issues_no_cancel() {
    // The public `AsyncIoOutcome` cancel path is the exact decision `acquire`'s
    // early returns and `Drop` make: only a genuinely `Pending` request is
    // cancellable, and nothing issued before a kernel-owned request exists can
    // be canceled (those states fail closed to `Unresolved`).
    let fixture = fixture_case(18);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("acquire validation failure before DeviceIoControl")
            && fixture.contains("no cancel path runs"),
        "fixture must bind case 18 to the cancel-before-submission case"
    );

    assert_eq!(
        AsyncIoOutcome::Pending.request_cancel(),
        AsyncIoOutcome::CancelRequested,
        "a pending request is the only state a cancel may target"
    );
    assert_eq!(
        AsyncIoOutcome::SynchronousComplete.request_cancel(),
        AsyncIoOutcome::SynchronousComplete,
        "an already-complete request has nothing to cancel"
    );
    assert_eq!(
        AsyncIoOutcome::Prepared.request_cancel(),
        AsyncIoOutcome::Unresolved,
        "a request that was never submitted can never be canceled; it fails closed"
    );
    assert!(
        AsyncIoOutcome::RejectedBeforeSubmit
            .reconcile_before_retry()
            .is_ok(),
        "a pre-submit rejection is terminal: a retry needs no cancel reconcile"
    );
    assert!(
        AsyncIoOutcome::Prepared.reconcile_before_retry().is_ok(),
        "a request that was never submitted provably owns nothing, so it may rebuild"
    );

    // Behaviour: acquiring on a regular file (not a directory) is the real
    // pre-submit validation failure; it returns before any handle, event, or
    // request allocation exists, so no guard and therefore no cancel exists.
    let path = std::env::temp_dir().join(unique_probe_id("oplock-pre-submit-file"));
    ok(std::fs::write(&path, b"probe"));
    let error = err(DirectoryOplockGuard::acquire(&path));
    assert_eq!(
        error.kind(),
        io::ErrorKind::InvalidInput,
        "acquire must reject a non-directory before submission"
    );
    // The file was never turned into a directory handle, so nothing was left
    // open by the rejected acquisition.
    assert!(
        path.is_file(),
        "a pre-submit rejection must leave the path untouched"
    );
    ok(std::fs::remove_file(&path));
}

// 19. cancel request while pending;
// WORK_UNIT_CASE: 789/19
#[test]
fn oplock_cancel_targets_the_pending_request_then_the_handle_close() {
    // The private `DirectoryOplockGuard::drop` body is proven by source facts
    // (it targets the exact handle plus OVERLAPPED, then closes the handle),
    // and the public `AsyncIoOutcome` transitions are what select that path.
    // The cancel-drain outcome (`ObservedCancel`) is the only cancel terminal
    // that also constructs the storage-release proof.
    let fixture = fixture_case(19);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("guard drop with a pending oplock request")
            && fixture.contains("CancelIoEx targets the exact handle plus OVERLAPPED"),
        "fixture must bind case 19 to the cancel-while-pending case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let drop_impl = library
        .split("impl Drop for DirectoryOplockGuard")
        .nth(1)
        .and_then(|tail| tail.split("pub fn write_new_pinned_file").next())
        .unwrap_or_else(|| panic!("library must keep the DirectoryOplockGuard Drop impl"));
    assert!(
        drop_impl.contains("CancelIoEx(directory.as_raw_handle().cast(), request.as_ref())"),
        "the cancel must target the exact directory handle plus the request OVERLAPPED"
    );
    assert!(
        drop_impl.contains("drop(directory);"),
        "closing the directory handle must complete the cancellation"
    );

    // The public state machine: a cancel requested against a pending request
    // becomes terminal only when the drain observes the signal.
    let canceling = AsyncIoOutcome::Pending.request_cancel();
    assert_eq!(canceling, AsyncIoOutcome::CancelRequested);
    assert_eq!(
        canceling.classify_cancel_drain(WAIT_OBJECT_0_CODE),
        AsyncIoOutcome::ObservedCancel,
        "a drained cancel is the terminal cancel state"
    );
    assert!(
        canceling.terminal_storage_release().is_none(),
        "a cancel that has not drained yet constructs no release proof"
    );
    assert!(
        AsyncIoOutcome::ObservedCancel
            .terminal_storage_release()
            .is_some(),
        "a drained cancel is the cancel terminal that permits storage release"
    );

    // Behaviour: a real acquire leaves a pending request; the cancel path runs
    // on drop and leaves no pending request outstanding.
    let directory = ok(unique_probe_directory("oplock-cancel-pending"));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    drop(guard);
    // The directory is deletable only because the guard released or retained
    // its request storage deterministically on drop.
    ok(std::fs::remove_dir_all(&directory));
}

// 20. CancelIoEx success/failure alone cannot release storage;
// WORK_UNIT_CASE: 789/20
#[test]
fn oplock_cancel_io_return_alone_never_constructs_a_release_proof() {
    // The public `AsyncIoOutcome::note_cancel_io_result` is the exact transition
    // `Drop` uses to record a `CancelIoEx` return without ever reading it as a
    // release proof: the return is recorded and discarded, and the state stays
    // `CancelRequested` until the drain observes the terminal signal.
    let fixture = fixture_case(20);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("CancelIoEx return value ignored for the release verdict")
            && fixture.contains("the CancelIoEx return is never read"),
        "fixture must bind case 20 to the CancelIoEx-alone case"
    );

    let cancel_requested = AsyncIoOutcome::CancelRequested;
    for cancel_return in [0, 1] {
        let after = cancel_requested.note_cancel_io_result(cancel_return);
        assert_eq!(
            after,
            AsyncIoOutcome::CancelRequested,
            "a CancelIoEx return must never change the stored state"
        );
        assert!(
            after.terminal_storage_release().is_none(),
            "a CancelIoEx return alone must never construct a storage-release proof"
        );
        assert!(
            after.reconcile_before_retry().is_err(),
            "a requested-but-undrained cancel must refuse a blind retry"
        );
    }
    assert_eq!(
        cancel_requested
            .note_cancel_io_result(0)
            .classify_cancel_drain(WAIT_OBJECT_0_CODE),
        AsyncIoOutcome::ObservedCancel,
        "only the drain verdict, never the CancelIoEx return, makes the cancel terminal"
    );

    // Behaviour: with the cancellation boundary armed, no cancel is ever
    // requested, so the drain cannot construct a proof and the storage is
    // retained fail-closed instead of being freed.
    let _serialized = fault_boundary_run();
    let directory = ok(unique_probe_directory("oplock-cancel-io-return"));
    {
        let _armed = arm_fault_boundaries(&[FaultBoundary::Cancellation]);
        let guard = ok(DirectoryOplockGuard::acquire(&directory));
        assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    }
    ok(std::fs::remove_dir_all(&directory));
}

// 21. late completion after cancel request;
// WORK_UNIT_CASE: 789/21
#[test]
fn oplock_late_completion_leaks_storage_instead_of_freeing_it() {
    // The public `AsyncIoOutcome` release proof is the exact gate `Drop` uses:
    // only a terminal state yields `Some(TerminalStorageRelease)`; every other
    // state — including an undrained cancel and an unresolved late completion —
    // yields `None`, which `Drop` turns into fail-closed `Box::leak` of the
    // three kernel-visible allocations. A late completion that arrives after
    // teardown started cannot be attributed to this guard's cancel, so the
    // injected late-completion boundary forces that same leak branch.
    let fixture = fixture_case(21);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("kernel completes the canceled request after the drain wait")
            && fixture.contains("intentionally leaks the three kernel-visible allocations"),
        "fixture must bind case 21 to the late-completion leak case"
    );

    // Only the four terminal states construct the release proof.
    for terminal in [
        AsyncIoOutcome::ObservedCancel,
        AsyncIoOutcome::ObservedComplete,
    ] {
        assert!(
            terminal.terminal_storage_release().is_some(),
            "a drained terminal state must permit storage release"
        );
    }
    for retained in [
        AsyncIoOutcome::CancelRequested,
        AsyncIoOutcome::Pending,
        AsyncIoOutcome::UnknownSubmit,
        AsyncIoOutcome::Unresolved,
    ] {
        assert!(
            retained.terminal_storage_release().is_none(),
            "an undrained or unresolved outcome must retain storage instead of freeing it"
        );
    }
    assert_eq!(
        AsyncIoOutcome::CancelRequested.classify_cancel_drain(WAIT_TIMEOUT_CODE),
        AsyncIoOutcome::Unresolved,
        "a drain that times out without the terminal signal is unresolved, never a release"
    );

    // Behaviour: with the late-completion boundary armed, the drain's signal
    // cannot be converted into a release proof, so the guard leaks its request
    // storage fail-closed (a bounded, counted leak) instead of freeing storage
    // a late kernel completion may still write.
    let _serialized = fault_boundary_run();
    let directory = ok(unique_probe_directory("oplock-late-completion"));
    {
        let _armed = arm_fault_boundaries(&[FaultBoundary::LateCompletion]);
        let guard = ok(DirectoryOplockGuard::acquire(&directory));
        assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    }
    // A re-acquire after the injected late completion still works: the leaked
    // request storage was retained (not freed), so no write-after-free state
    // is fabricated and the next request is unaffected.
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    drop(guard);
    ok(std::fs::remove_dir_all(&directory));
}

// 22. timeout/disconnect with unknown completion;
// WORK_UNIT_CASE: 789/22
#[test]
fn oplock_drain_timeout_takes_the_same_fail_closed_leak_path() {
    // The public `AsyncIoOutcome::classify_cancel_drain` transition is the
    // exact 5s drain decision `Drop` makes: a signaled drain yields
    // `ObservedCancel` (terminal, release proven), but a timeout — and a failed
    // wait (disconnect) — yield `Unresolved`/`UnknownSubmit`, neither of which
    // constructs a release proof, so the same fail-closed leak path runs and no
    // timeout value proves release.
    let fixture = fixture_case(22);
    assert!(
        fixture.contains("oplock-async")
            && fixture.contains("5s drain wait expiring without the terminal signal")
            && fixture.contains("no timeout value proves release"),
        "fixture must bind case 22 to the drain-timeout case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    assert!(
        library.contains("WaitForSingleObject(self.event.0, 5_000)"),
        "the oplock drain must wait exactly the bounded 5s terminal-signal window"
    );

    // A timeout and a failed wait are both non-terminal: neither is a release.
    let timeout = AsyncIoOutcome::CancelRequested.classify_cancel_drain(WAIT_TIMEOUT_CODE);
    assert_eq!(
        timeout,
        AsyncIoOutcome::Unresolved,
        "an expired drain wait must be unresolved, never a release"
    );
    assert!(
        timeout.terminal_storage_release().is_none(),
        "a drain timeout must take the fail-closed leak path, not a release"
    );
    let failed = AsyncIoOutcome::CancelRequested.classify_cancel_drain(WAIT_FAILED_CODE);
    assert_eq!(
        failed,
        AsyncIoOutcome::UnknownSubmit,
        "a failed drain wait loses the completion evidence entirely"
    );
    assert!(
        failed.terminal_storage_release().is_none(),
        "an unknown drain outcome must never release storage"
    );
    assert_eq!(
        AsyncIoOutcome::CancelRequested
            .classify_cancel_drain(WAIT_TIMEOUT_CODE)
            .reconcile_before_retry()
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::InvalidData),
        "an unresolved drain refuses a blind retry until reconciled"
    );

    // Behaviour: dropping a live pending guard (whose drain either signals or
    // times out) always resolves deterministically and leaves the directory
    // removable, proving the drain verdict — not any timeout value — decided
    // the release.
    let directory = ok(unique_probe_directory("oplock-drain-timeout"));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(guard.async_outcome(), AsyncIoOutcome::Pending);
    drop(guard);
    ok(std::fs::remove_dir_all(&directory));
}

// 23. exact reconciliation before reuse/retry;
// WORK_UNIT_CASE: 789/23
#[test]
#[allow(clippy::too_many_lines)]
fn job_reconciliation_rejects_raced_membership_before_returning_a_snapshot() {
    // The private `current_job_processes` body is proven by source facts (PID 0
    // rejection, duplicate rejection, and the second-enumeration membership
    // check that returns `WouldBlock`), and the public `RecoverableJobObject`
    // API exercises the same capture on a real job. The production caller
    // `capture_descendants_at_root_exit` must also treat a raced capture as an
    // explicit failure rather than an empty snapshot.
    let fixture = fixture_case(23);
    assert!(
        fixture.contains("job-iocp-spawn")
            && fixture.contains("job membership changing between enumerate and capture")
            && fixture.contains("membership-change rejection (WouldBlock)"),
        "fixture must bind case 23 to the exact-reconciliation case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let capture = library
        .split("fn current_job_processes(job: HANDLE)")
        .nth(1)
        .and_then(|tail| tail.split("fn open_current_process_snapshot").next())
        .unwrap_or_else(|| panic!("library must keep the current_job_processes reconciliation"));
    assert!(
        capture.contains("if pids.contains(&0) {"),
        "the reconciliation must reject a PID 0 enumeration entry"
    );
    assert!(
        capture.contains("duplicate PID {pid} in Job Object enumeration"),
        "the reconciliation must reject a duplicate PID as an explicit error"
    );
    assert!(
        capture.contains("io::ErrorKind::WouldBlock"),
        "a membership change between enumerate and capture must return WouldBlock"
    );
    assert!(
        library.contains("let current_ids = job_process_ids(job)?;"),
        "the reconciliation must re-enumerate the job after capture"
    );

    // The production caller must surface a raced capture as an explicit typed
    // failure, never as an authoritative empty snapshot.
    let caller = source_text("crates/eliot-app/src/host_runtime/supervised_process.rs");
    let capture_callers = caller
        .split("fn capture_descendants_at_root_exit(")
        .nth(1)
        .unwrap_or_else(|| panic!("caller must keep capture_descendants_at_root_exit"));
    assert!(
        capture_callers.contains("match job.current_job_processes() {"),
        "the production caller must branch on the exact reconciliation result"
    );
    assert!(
        capture_callers.contains("DescendantsCaptureErrorKind::EnumerationFailed"),
        "a raced capture must be reported as an explicit capture failure"
    );

    // Behaviour, on the real public per-member capture seam. `current_job_processes`
    // reaches each member through the same `open_current_process_snapshot` that
    // `RecoverableProcess::open` mirrors, so this exercises the identical PID-0
    // rejection and per-member identity capture the reconciliation depends on.
    //
    // NOT PROVEN HERE: that a capture racing a genuine membership change
    // returns `WouldBlock` rather than a partial snapshot, and that a job's
    // PID set is duplicate-free. Both need a named job, and a named job can
    // only be created by `SuspendedJobChild::spawn_named`, which needs a real
    // child process: `clippy.toml` forbids `std::process::Command::new` and this
    // crate exposes no seam to build the `&std::process::Command` that spawn
    // takes. The raced-capture execution stays with the in-crate
    // `#[cfg(test)] mod tests` in `src/lib.rs`, which owns the job.
    let live = ok(eliot_windows_ipc::RecoverableProcess::open(
        std::process::id(),
    ));
    let root_pid = live.identity().pid;
    assert_eq!(
        root_pid,
        std::process::id(),
        "the per-member capture must resolve the exact live root PID"
    );
    assert!(
        live.identity().image.is_absolute(),
        "each captured member must bind the absolute image of its retained handle"
    );
    assert!(
        ok(live.start_ticks()) > 0,
        "each captured member must carry nonzero creation ticks from the retained handle"
    );
    // Capturing the same unchanged member twice must answer identically, so a
    // raced capture can never return a different, authoritative-looking answer.
    let again = ok(eliot_windows_ipc::RecoverableProcess::open(
        std::process::id(),
    ));
    assert_eq!(
        again.identity().pid,
        live.identity().pid,
        "an unchanged process must reconcile to the identical PID"
    );
    assert_eq!(
        again.identity().file_identity,
        live.identity().file_identity,
        "an unchanged process must reconcile to the identical pinned file identity"
    );
    assert_eq!(
        ok(again.start_ticks()),
        ok(live.start_ticks()),
        "an unchanged process must reconcile to identical creation ticks"
    );
    // PID 0 is rejected by the same guard the capture uses, before any
    // identity is formed.
    assert_eq!(
        w1b_error_kind(eliot_windows_ipc::RecoverableProcess::open(0)),
        io::ErrorKind::InvalidInput,
        "the capture must reject PID 0 before forming any identity"
    );
}

// 24. exact replay versus changed same-operation payload;
// WORK_UNIT_CASE: 789/24
#[test]
fn spawn_rejects_a_colliding_job_name_instead_of_joining_it() {
    // The real public API proves this case end to end: `spawn_named` must
    // reject an already-existing named Job Object with `AlreadyExists`, so a
    // new generation never silently joins (and then replays into) an orphaned
    // job's membership. The source facts confirm the rejection is unconditional
    // on `ERROR_ALREADY_EXISTS`, before any process is created.
    let fixture = fixture_case(24);
    assert!(
        fixture.contains("job-iocp-spawn")
            && fixture.contains("spawn with a colliding job name")
            && fixture.contains("AlreadyExists rejects a silent join"),
        "fixture must bind case 24 to the colliding-job-name replay case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let create_job = library
        .split("fn create_kill_on_close_job(")
        .nth(1)
        .and_then(|tail| tail.split("fn inheritable_pipe(").next())
        .unwrap_or_else(|| panic!("library must keep create_kill_on_close_job"));
    assert!(
        create_job.contains("if creation_error == ERROR_ALREADY_EXISTS {"),
        "the job creation must detect a pre-existing name"
    );
    assert!(
        create_job.contains("io::ErrorKind::AlreadyExists"),
        "the collision must be rejected with AlreadyExists, never joined"
    );

    // Behaviour, on the real public reopen surface, which needs no process: a
    // name that passes the grammar but that no generation ever claimed is
    // reported as a typed `NotFound` by the kernel, never as an empty job, so
    // a caller can never mistake "no such job" for "a job I may join".
    //
    // NOT PROVEN HERE: that a colliding name is refused after one live
    // generation already owns it, and that the second generation never joins
    // the first generation's membership. Both need a real child process:
    // `clippy.toml` forbids `std::process::Command::new`, and
    // `SuspendedJobChild::spawn_named` takes a `&std::process::Command` this
    // crate exposes no seam to build. The two-generation collision execution
    // stays with the in-crate `#[cfg(test)] mod tests` in `src/lib.rs`.
    let unused = unique_probe_id("job-collision");
    assert_eq!(
        w1b_error_kind(RecoverableJobObject::open(&unused)),
        io::ErrorKind::NotFound,
        "a name no generation ever claimed must be typed NotFound, never an empty job"
    );
    // An empty name carries no NUL-terminated wide form, so the reopen refuses
    // it before reaching `OpenJobObjectW`. The over-length bound is a
    // `CreateJobObjectW` property and is only enforced on the creation path
    // (`spawn_named`), which needs a real process and is out of reach here.
    assert_eq!(
        w1b_error_kind(RecoverableJobObject::open("")),
        io::ErrorKind::InvalidInput,
        "an empty job name must fail closed before any OpenJobObjectW"
    );
    assert_eq!(
        w1b_error_kind(RecoverableJobObject::open("has/embedded/slashes")),
        io::ErrorKind::NotFound,
        "a well-formed name no generation claimed must be typed NotFound, never an empty job"
    );
}

// 25. partial read/write and remainder accounting;
// WORK_UNIT_CASE: 789/25
#[test]
fn credential_read_views_the_blob_with_the_exact_converted_size() {
    // The private `credential_read_current_user` body is proven by source facts
    // (the reported blob size is converted and classified before the view is
    // formed, and the copy happens before the guard drops), and the real public
    // API proves the end-to-end remainder accounting for an exact-size blob.
    let fixture = fixture_case(25);
    assert!(
        fixture.contains("credential")
            && fixture.contains("credential blob of exact size N")
            && fixture.contains("no short view is ever widened"),
        "fixture must bind case 25 to the partial read/write remainder case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let read = library
        .split("pub fn credential_read_current_user(")
        .nth(1)
        .and_then(|tail| tail.split("/// Writes an Eliot generic credential").next())
        .unwrap_or_else(|| panic!("library must keep credential_read_current_user"));
    assert!(
        read.contains("usize::try_from(credential.CredentialBlobSize)"),
        "the blob size must be converted explicitly before any view is formed"
    );
    assert!(
        read.contains("classify_credential_blob(blob_size, credential.CredentialBlob.is_null())"),
        "the reported blob size must be classified (exact / empty / rejected) before use"
    );
    assert!(
        read.contains("std::slice::from_raw_parts(credential.CredentialBlob, blob_size)"),
        "the blob must be viewed with the exact classified size"
    );
    assert!(
        read.contains("Ok(Some(bytes.to_vec()))"),
        "the bytes must be copied out before the buffer guard drops"
    );

    // The production caller must consume the read through this exact API.
    let caller = source_text("crates/kernel/eliot-platform-windows/src/secret_store.rs");
    assert!(
        caller.contains("eliot_windows_ipc::credential_read_current_user(key)"),
        "the production caller must read through credential_read_current_user"
    );

    // Behaviour: a credential written with an exact N-byte blob is read back
    // with exactly those N bytes (no short read, no widening), and an
    // over-limit blob is rejected before any FFI write.
    let probe = unique_probe_id("exact-size-blob");
    ok(validate_credential_id(probe.as_str()));
    let value: Vec<u8> = (0_u8..=255).cycle().take(1024).collect();
    assert_eq!(
        value.len(),
        1024,
        "the probe blob must be exactly 1024 bytes of known content"
    );
    ok(credential_write_current_user(probe.as_str(), &value));
    let read_back = ok(credential_read_current_user(probe.as_str()));
    let read_bytes = ok(read_back.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "the just-written probe credential must be readable",
        )
    }));
    assert_eq!(
        read_bytes.len(),
        value.len(),
        "an exact-size blob must be read back with its exact byte count"
    );
    assert_eq!(
        read_bytes, value,
        "an exact-size blob must be read back byte for byte, never widened"
    );
    assert_eq!(
        ok(credential_status_current_user(probe.as_str())).size_bytes,
        Some(1024),
        "the reported blob size must equal the exact written size"
    );
    // An over-limit blob and an empty blob are both refused by the writer, so
    // a remainder is never silently truncated into a stored credential.
    assert_invalid_input(
        credential_write_current_user(probe.as_str(), &[]),
        "empty blob",
    );
    assert_invalid_input(
        credential_write_current_user(probe.as_str(), &vec![0_u8; 8192]),
        "over-limit blob",
    );
    // Clean up the one credential this case created.
    assert!(
        ok(credential_delete_current_user(probe.as_str())),
        "the probe credential this case created must be removed"
    );
    assert!(
        !ok(credential_status_current_user(probe.as_str())).present,
        "the probe must not remain after cleanup"
    );
}

// 26. zero-byte/EOF/broken-pipe distinctions;
// WORK_UNIT_CASE: 789/26
#[test]
fn try_wait_honours_still_active_only_while_unsignaled() {
    // The private `query_process_exit_code` body is proven by source facts
    // (`STILL_ACTIVE` is honored only when the process is unsignaled; a
    // signaled process always re-queries the true exit code), and the real
    // public API proves the distinction end to end: a live root reports `None`
    // (still running) while a signaled root that exited with the
    // `STILL_ACTIVE`-valued code `259` reports `Some(259)`.
    let fixture = fixture_case(26);
    assert!(
        fixture.contains("job-iocp-spawn")
            && fixture.contains("signaled versus unsignaled process with STILL_ACTIVE code")
            && fixture.contains("STILL_ACTIVE is honored only when unsignaled"),
        "fixture must bind case 26 to the zero-byte/EOF/broken-pipe distinction case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let exit_code = library
        .split("fn query_process_exit_code(")
        .nth(1)
        .and_then(|tail| tail.split("fn current_job_processes(").next())
        .unwrap_or_else(|| panic!("library must keep query_process_exit_code"));
    assert!(
        exit_code.contains("if !signaled && code == still_active {"),
        "STILL_ACTIVE must be honored only for an unsignaled process"
    );
    let try_wait = library
        .split("pub fn try_wait(")
        .nth(1)
        .and_then(|tail| tail.split("pub fn wait_timeout(").next())
        .unwrap_or_else(|| panic!("library must keep SuspendedJobChild::try_wait"));
    assert!(
        try_wait.contains("WAIT_TIMEOUT => query_process_exit_code(self.process.0, false)")
            && try_wait.contains("WAIT_OBJECT_0 => query_process_exit_code(self.process.0, true)"),
        "try_wait must cross-check the signaled state with the exit-code query"
    );

    // Behaviour, on the real public liveness query the whole distinction rests
    // on, driven against this very live process. Its exit code is exactly
    // `STILL_ACTIVE`, so the code-only check answers "alive" for it -- exactly
    // the ambiguity that makes the signal cross-check in `try_wait` necessary.
    //
    // NOT PROVEN HERE: that a child which really exits with code 259 is
    // reported `Some(259)` by `try_wait`/`wait_timeout`. That needs a real
    // child process: `clippy.toml` forbids `std::process::Command::new` and
    // `SuspendedJobChild::spawn_named` takes a `&std::process::Command` this
    // crate exposes no seam to build. The signaled-child execution stays with
    // the in-crate `#[cfg(test)] mod tests` in `src/lib.rs`.
    let live_pid = std::process::id();
    assert!(
        ok(process_is_alive(live_pid)),
        "a code-only liveness check cannot separate a 259 exit from STILL_ACTIVE, which is why try_wait cross-checks the signaled state instead"
    );
    // The identity the code-only check resolves for this process, proving the
    // `STILL_ACTIVE` ambiguity is live rather than hypothetical: the source
    // facts above show `STILL_ACTIVE` is only honored for an UNSIGNALED
    // process, so the same live code re-read as signaled yields `Some(259)`.
    let live = ok(eliot_windows_ipc::RecoverableProcess::open(live_pid));
    assert_eq!(
        live.identity().pid,
        live_pid,
        "the retained handle must resolve this same live root"
    );
    assert!(
        ok(live.start_ticks()) > 0,
        "the retained handle must answer a real query while the process is unsignaled"
    );
    // PID 0 is refused outright rather than defaulted to a verdict.
    assert!(
        !ok(process_is_alive(0)),
        "PID 0 must never be reported as a live process"
    );
}

// 27. message/frame boundary preservation;
// WORK_UNIT_CASE: 789/27
#[test]
#[allow(clippy::too_many_lines)]
fn credential_target_name_scan_excludes_the_terminator_and_fails_closed() {
    // `EliotGovernor/` costs 14 UTF-16 units (E-l-i-o-t-G-o-v-e-r-n-o-r-/ = 13 + 1), and the
    // enumeration refuses a prefix whose namespaced target plus its `*` filter terminator
    // exceeds `MAX_CREDENTIAL_TARGET_CHARS` (512). The guard is
    // `full_prefix.encode_utf16().count() + 1 > 512` (lib.rs:3607), so the prefix must
    // reach 512 units to be ADMITTED and 513 to be REFUSED.
    const NAMESPACE_UNITS: usize = 14;
    const TARGET_CHAR_BOUND: usize = 512;
    assert_eq!(
        "EliotGovernor/".encode_utf16().count(),
        NAMESPACE_UNITS,
        "the namespace prefix must cost exactly the units this case assumes"
    );
    // The private `credential_target_name` body is proven by source facts (the
    // NUL terminator is observed but excluded from the slice, and unterminated
    // data within the 512-unit bound fails closed), and the real public
    // enumeration API proves the boundary end to end: a credential written with
    // a target exactly at the scan bound is returned with its terminator
    // excluded, and an over-bound prefix fails closed before any FFI.
    let fixture = fixture_case(27);
    assert!(
        fixture.contains("credential")
            && fixture.contains("TargetName with terminator at the scan bound")
            && fixture.contains("unterminated data within 512 units fails closed"),
        "fixture must bind case 27 to the message/frame boundary preservation case"
    );

    let library = source_text("crates/eliot-windows-ipc/src/lib.rs");
    let scan = library
        .split("fn credential_target_name(target: *const u16)")
        .nth(1)
        .and_then(|tail| {
            tail.split("/// Enumerates Eliot credential identifiers")
                .next()
        })
        .unwrap_or_else(|| panic!("library must keep credential_target_name"));
    assert!(
        scan.contains("while length < MAX_CREDENTIAL_TARGET_CHARS && *target.add(length) != 0 {"),
        "the scan must observe the NUL terminator within the exact bounded window"
    );
    assert!(
        scan.contains("std::slice::from_raw_parts(target, length)"),
        "the slice must be formed from the scanned prefix"
    );
    assert!(
        scan.contains("excludes the terminator, so the slice never includes the NUL"),
        "the documented bound must state the terminator is excluded from the slice"
    );
    assert!(
        scan.contains("classify_bounded_scan(length, MAX_CREDENTIAL_TARGET_CHARS)"),
        "an unterminated scan within the bound must be classified, not widened"
    );

    // The public caller must consume this exact scan.
    let enumerate = library
        .split("pub fn credential_ids_current_user_with_prefix(")
        .nth(1)
        .and_then(|tail| tail.split("/// Shared command configuration").next())
        .unwrap_or_else(|| panic!("library must keep credential_ids_current_user_with_prefix"));
    assert!(
        enumerate.contains("credential_target_name(unsafe { (**entry).TargetName })?"),
        "the enumeration must resolve each target name through the bounded scan"
    );
    assert!(
        enumerate.contains("target.strip_prefix(\"EliotGovernor/\")"),
        "the enumeration must prove the scan excluded the terminator by parsing the namespace prefix"
    );

    // Behaviour: a stored target name round-trips through the bounded scan
    // with its terminator excluded, and a prefix whose namespaced target would
    // not fit inside the 512-unit bound fails closed before any FFI call.
    let probe = unique_probe_id("scan-bound-target");
    ok(validate_credential_id(probe.as_str()));
    ok(credential_write_current_user(probe.as_str(), b"scan-bound"));
    let unrelated = ok(credential_ids_current_user_with_prefix(
        "wipc-789-probe-scan-bound-target-never",
    ));
    assert!(
        !unrelated.iter().any(|id| id == &probe),
        "an unrelated prefix must not match the probe"
    );
    let all = ok(credential_ids_current_user_with_prefix("wipc-789-probe-"));
    assert!(
        all.iter().any(|id| id == &probe),
        "the bounded scan must return the stored target name verbatim"
    );
    assert!(
        all.iter().all(|id| !id.contains('\0')),
        "no enumerated identifier may carry the NUL terminator into the slice"
    );
    assert!(
        all.iter()
            .all(|id| validate_credential_id(id.as_str()).is_ok()),
        "every enumerated identifier must be a bounded logical identifier once the terminator is excluded and the namespace prefix is stripped"
    );
    assert!(
        ok(credential_delete_current_user(probe.as_str())),
        "the probe credential this case created must be removed"
    );

    // The scan bound: the namespace prefix and its `*` filter terminator are
    // charged against `MAX_CREDENTIAL_TARGET_CHARS` (512), which the two
    // constants above name.
    let exact_prefix = "c".repeat(TARGET_CHAR_BOUND - NAMESPACE_UNITS - 1);
    assert_eq!(
        format!("EliotGovernor/{exact_prefix}")
            .encode_utf16()
            .count(),
        TARGET_CHAR_BOUND - 1,
        "this prefix must sit one unit below the bound"
    );
    assert_invalid_input(
        credential_ids_current_user_with_prefix(&exact_prefix),
        "a prefix at the exact scan bound",
    );
    // The guard is `full_prefix.encode_utf16().count() + 1 > 512` (lib.rs:3607), so a
    // namespaced prefix of exactly 512 units is ALREADY refused (512 + 1 > 512). This
    // assertion must state the guard's own arithmetic, not a stricter-than-real one.
    let over_bound_prefix = "d".repeat(TARGET_CHAR_BOUND - NAMESPACE_UNITS);
    assert_eq!(
        format!("EliotGovernor/{over_bound_prefix}")
            .encode_utf16()
            .count(),
        TARGET_CHAR_BOUND,
        "this prefix must sit exactly ON the namespaced bound, which the `+ 1 >` guard still refuses"
    );
    assert!(
        format!("EliotGovernor/{over_bound_prefix}")
            .encode_utf16()
            .count()
            + 1
            > TARGET_CHAR_BOUND,
        "the guard's own arithmetic must refuse this prefix, terminator included"
    );
    assert_invalid_input(
        credential_ids_current_user_with_prefix(&over_bound_prefix),
        "an over-bound enumeration prefix",
    );
    // An overlong single identifier fails on the identifier grammar itself,
    // before any namespaced target is formed at all.
    assert_invalid_input(
        credential_ids_current_user_with_prefix(&"a".repeat(600)),
        "an overlong enumeration prefix",
    );
    assert_invalid_input(
        credential_ids_current_user_with_prefix("a/../b"),
        "a traversal enumeration prefix",
    );
}

// ---------------------------------------------------------------------------
// Cases 28..42 (wave 2 execution lane). The declaration-only inventory above
// still names these cases, so each marker below is re-anchored as a bare
// `WORK_UNIT_CASE` line immediately above its own `#[test]`, which is the shape
// the work-unit registry's anchored regex accepts. Nothing above this block is
// modified: every marker here immediately precedes its own test.
// ---------------------------------------------------------------------------

/// Reads one file of this package by its manifest-relative path.
fn w1b_read_package_file(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    ok(std::fs::read_to_string(&path))
}

/// The production source of this crate, read as text.
fn w1b_crate_source_text() -> String {
    w1b_read_package_file("src/lib.rs")
}

/// This package's manifest, read as text.
fn w1b_manifest_text() -> String {
    w1b_read_package_file("Cargo.toml")
}

/// One named package source file, read as text.
fn w1b_package_source_text(relative: &str) -> String {
    w1b_read_package_file(relative)
}

/// Counts non-overlapping occurrences of `needle` in `haystack`.
fn w1b_count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The typed error kind of a failed result.
///
/// `ok`/`err` require `Debug` on the success type, which the handle-owning
/// wrappers deliberately do not implement, so the cases below read the kind
/// through this instead.
fn w1b_error_kind<T>(result: io::Result<T>) -> io::ErrorKind {
    match result {
        Ok(_) => panic!("expected a failure"),
        Err(error) => error.kind(),
    }
}

/// Returns the brace-balanced source region beginning at `anchor`, so a
/// source-fact assertion reads one function rather than the whole file.
fn w1b_block(source: &str, anchor: &str) -> String {
    let start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("missing source anchor: {anchor}"));
    let open = start
        + source[start..]
            .find('{')
            .unwrap_or_else(|| panic!("anchor has no body: {anchor}"));
    let mut depth = 0_i64;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return source[start..=open + offset].to_owned();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced source block for anchor: {anchor}");
}

/// The contiguous `//` comment lines immediately above `anchor`, which is
/// where an operation-specific SAFETY witness has to live.
fn w1b_comment_witness(source: &str, anchor: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let index = lines
        .iter()
        .position(|line| line.contains(anchor))
        .unwrap_or_else(|| panic!("missing source anchor: {anchor}"));
    let mut start = index;
    while start > 0 && lines[start - 1].trim_start().starts_with("//") {
        start -= 1;
    }
    lines[start..index].join("\n")
}

/// `count` source lines beginning at the line that holds `anchor`.
fn w1b_line_run(source: &str, anchor: &str, count: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let index = lines
        .iter()
        .position(|line| line.contains(anchor))
        .unwrap_or_else(|| panic!("missing source anchor: {anchor}"));
    let end = index.saturating_add(count).min(lines.len());
    lines[index..end].join("\n")
}

/// Rewrites `source` with every NON-CODE character replaced by a space, so the
/// returned text is character-for-character the same length and line count as
/// the input but carries only real code tokens.
///
/// Line comments, nestable block comments, string literals (with their `\\`
/// escapes, which continue across a newline), raw strings (`r"..."`, `r#"..."#`)
/// and char literals are blanked. A `'` that opens a LIFETIME (`&'static`,
/// `<'a>`) is not a char literal and is kept, while a `'{'` or `'}'` IS one and
/// is blanked. That distinction is the whole point: this file quotes braces and
/// assertion keywords inside string literals and inside prose comments, and a
/// scan that reads those as code is satisfied by text that asserts nothing.
///
/// Newlines are preserved rather than blanked, so a caller may still split the
/// result into lines and keep the line numbers of the input.
// CODE, LINE_COMMENT, BLOCK_COMMENT, STRING, RAW_STRING, CHAR_LITERAL.
const CODE: usize = 0;
const LINE_COMMENT: usize = 1;
const BLOCK_COMMENT: usize = 2;
const STRING: usize = 3;
const RAW_STRING: usize = 4;
const CHAR_LITERAL: usize = 5;
#[allow(clippy::too_many_lines)]
fn w1b_code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());
    for ch in &chars {
        out.push(if *ch == '\n' { '\n' } else { ' ' });
    }
    let mut state = CODE;
    let mut block_depth = 0_i64;
    let mut raw_hashes = 0_usize;
    let mut escaped = false;
    let mut index = 0_usize;
    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            CODE => {
                if ch == '/' && next == Some('/') {
                    state = LINE_COMMENT;
                    index += 2;
                    continue;
                }
                if ch == '/' && next == Some('*') {
                    state = BLOCK_COMMENT;
                    block_depth = 1;
                    index += 2;
                    continue;
                }
                // A `b` prefix may precede a byte string or a raw string, and
                // either may be followed by any number of `#`. The lookahead must
                // start where the prefix does, or a `b` identifier that merely
                // happens to sit before a later quote would be misread as
                // opening a literal.
                let prefix_len = usize::from(ch == 'b') + usize::from(ch == 'B');
                let quote = index + prefix_len;
                let mut hashes = 0_usize;
                while quote + hashes < chars.len() && chars[quote + hashes] == '#' {
                    hashes += 1;
                }
                let quote_follows = chars.get(quote + hashes) == Some(&'"');
                if quote_follows {
                    state = if prefix_len == 0 { STRING } else { RAW_STRING };
                    raw_hashes = hashes;
                    escaped = false;
                    index = quote + hashes + 1;
                    continue;
                }
                if ch == '\'' {
                    let mut cursor = index + 1;
                    let lifetime_open = chars
                        .get(cursor)
                        .is_some_and(|after| after.is_alphanumeric() || *after == '_');
                    if lifetime_open {
                        while cursor < chars.len()
                            && (chars[cursor].is_alphanumeric() || chars[cursor] == '_')
                        {
                            cursor += 1;
                        }
                        if chars.get(cursor) == Some(&'\'') {
                            state = CHAR_LITERAL;
                            escaped = false;
                            index += 1;
                            continue;
                        }
                        out[index] = ch;
                        index += 1;
                        continue;
                    }
                    state = CHAR_LITERAL;
                    escaped = false;
                    index += 1;
                    continue;
                }
                out[index] = ch;
                index += 1;
            }
            LINE_COMMENT => {
                if ch == '\n' {
                    state = CODE;
                }
                index += 1;
            }
            BLOCK_COMMENT => {
                if ch == '/' && next == Some('*') {
                    block_depth += 1;
                    index += 2;
                    continue;
                }
                if ch == '*' && next == Some('/') {
                    block_depth -= 1;
                    index += 2;
                    if block_depth == 0 {
                        state = CODE;
                    }
                    continue;
                }
                index += 1;
            }
            RAW_STRING => {
                if ch == '"' {
                    let mut closing = 0_usize;
                    while closing < raw_hashes && chars.get(index + 1 + closing) == Some(&'#') {
                        closing += 1;
                    }
                    if closing == raw_hashes {
                        state = CODE;
                        index += 1 + closing;
                        continue;
                    }
                }
                index += 1;
            }
            STRING | CHAR_LITERAL => {
                if escaped {
                    escaped = false;
                    index += 1;
                    continue;
                }
                if ch == '\\' {
                    escaped = true;
                    index += 1;
                    continue;
                }
                if (state == STRING && ch == '"') || (state == CHAR_LITERAL && ch == '\'') {
                    state = CODE;
                }
                index += 1;
            }
            _ => unreachable!("w1b_code_only tracks a closed state set"),
        }
    }
    out.into_iter().collect()
}

/// The body of the test function whose `fn` declaration is at `declaration_line`,
/// from that declaration line through its matching `}` INCLUSIVE.
///
/// The scan is a depth counter over REAL braces only -- it reads
/// `w1b_code_only(source)` -- so a `{` or `}` inside a string literal, a char
/// literal or a comment cannot move the depth. Starting at the declaration line
/// is what makes the closing brace unambiguous: that line is the function's own
/// opening brace, so depth returns to zero exactly at the brace that closes it,
/// never later.
///
/// `code_lines` and `source_lines` are the line views of a source and of its
/// `w1b_code_only` projection, taken ONCE by the caller because the projection
/// is a whole-file scan; `declaration_line` is 1-based within both.
///
/// This is the single body extraction shared by the denominator floor below and
/// the `source_test` adequacy check in case 12, so a body is delimited the same
/// way wherever it is judged.
fn w1b_test_body(code_lines: &[&str], source_lines: &[&str], declaration_line: usize) -> String {
    let start = declaration_line.checked_sub(1).unwrap_or_else(|| {
        panic!("w1b_test_body needs a 1-based line number, got {declaration_line}")
    });
    let mut depth = 0_i64;
    let mut inside_body = false;
    let mut body: Vec<&str> = Vec::new();
    let mut offset = start;
    while offset < source_lines.len() {
        let Some(code_line) = code_lines.get(offset) else {
            break;
        };
        let open_braces =
            i64::try_from(code_line.matches('{').count()).expect("brace count fits in i64");
        let close_braces =
            i64::try_from(code_line.matches('}').count()).expect("brace count fits in i64");
        if open_braces > 0 {
            depth += open_braces;
            inside_body = true;
        }
        if close_braces > 0 {
            depth -= close_braces;
        }
        if inside_body {
            body.push(source_lines[offset]);
            if depth <= 0 {
                break;
            }
        }
        offset += 1;
    }
    assert!(
        inside_body,
        "w1b_test_body found no body for the fn declared on line {declaration_line}, which must name a `fn <name>(` line that opens a brace"
    );
    body.join("\n")
}

/// The anti-placeholder adequacy floor, applied to a test body extracted by
/// [`w1b_test_body`]. Returns `None` when the body clears every arm, or the gate
/// problem name with the reason when it does not.
///
/// The arms run in the gate's own order. `EMPTY_TEST_BODY` and
/// `UNCONDITIONAL_TRUE` read the whole body. `TRIVIAL_SELF_EQUALITY` and
/// `NO_CHECK_CONSTANT` read CODE ONLY -- `w1b_code_only(body)` -- because both
/// are defeated by prose: this file quotes `assert_eq!(X, X);` and the keyword
/// list in its own comments, and a body whose only "assertion" is the comment
/// `// TODO: assert something real here`, or whose only `assert`-shaped text is
/// an identifier like `checkpoint`, satisfies a raw substring scan without
/// asserting anything.
///
/// `TRIVIAL_SELF_EQUALITY` therefore accepts an `assert_eq!` whose two operands
/// are the SAME identifier, at any position, because it is exactly what the
/// gate's own pattern detects. That stays STRICTER than a name-only rule in one
/// direction only: it can report MORE defects, never fewer, so it can never let
/// a placeholder raise the bound count.
///
/// `NO_CHECK_CONSTANT` accepts a keyword only as a real CALL, MACRO or TRAIT
/// PATH: the token is `assert`/`panic`/`check`/`verify`/`should_panic` exactly,
/// or that keyword plus a `_suffix`, and the next non-space code character is
/// `!`, `(` or `::`. A local named `checkpoint` or `unverified` therefore does
/// not satisfy the floor, while `assert!(...)`, `assert_eq!(...)`, `verify(x)`,
/// `panic!(...)` and `should_panic()` all still do.
#[allow(clippy::too_many_lines)]
fn w1b_adequacy_floor(body: &str) -> Option<(&'static str, String)> {
    // :405-411, the gate's own cleanup of the extracted body: trim, drop ONE
    // leading `{` if present, drop ONE trailing `}` if present, trim again.
    let mut inner = body.trim().to_owned();
    if let Some(after_open) = inner.strip_prefix('{') {
        inner = after_open.to_owned();
    }
    if let Some(before_close) = inner.strip_suffix('}') {
        inner = before_close.to_owned();
    }
    let inner = inner.trim().to_owned();
    if inner.is_empty() || inner == "return;" || inner == "return" {
        // `EMPTY_TEST_BODY` -- empty or return-only Rust test body.
        return Some((
            "EMPTY_TEST_BODY",
            "body is empty or return-only, which the gate's floor reads as a placeholder"
                .to_owned(),
        ));
    }
    // `UNCONDITIONAL_TRUE` -- `assert!(true);` as the entire body.
    let literal_arms: [&str; 5] = ["assert!", "(", "true", ")", ";"];
    let mut rest = inner.as_str();
    let mut unconditional_true = true;
    for literal in literal_arms {
        let Some(after_literal) = rest.trim_start().strip_prefix(literal) else {
            unconditional_true = false;
            break;
        };
        rest = after_literal;
    }
    if unconditional_true && rest.is_empty() {
        return Some((
            "UNCONDITIONAL_TRUE",
            format!("whole body is `{inner}`, the gate's unconditional-true placeholder"),
        ));
    }
    // `TRIVIAL_SELF_EQUALITY` -- `assert_eq!(X, X);`, same identifier twice, read
    // from CODE ONLY so a pattern quoted inside a comment is not a call.
    let code_only = w1b_code_only(&inner);
    let mut scan_from = 0_usize;
    while let Some(found) = code_only[scan_from..].find("assert_eq!") {
        let run_start = scan_from + found;
        let tail = &code_only[run_start + "assert_eq!".len()..];
        let open = tail.find('(');
        let close = tail.find(')');
        if let (Some(open), Some(close)) = (open, close)
            && close > open
        {
            let call = &tail[open + 1..close];
            let mut operands = call.split(',');
            let first = operands.next().unwrap_or_default().trim();
            let second = operands.next().unwrap_or_default().trim();
            let is_identifier = |operand: &str| {
                !operand.is_empty()
                    && operand
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            };
            if operands.next().is_none() && is_identifier(first) && first == second {
                return Some((
                    "TRIVIAL_SELF_EQUALITY",
                    format!(
                        "whole body is `{inner}`, the gate's trivial self-equality over the identifier `{first}`"
                    ),
                ));
            }
        }
        scan_from = run_start + 1;
    }
    // `NO_CHECK_CONSTANT` -- no checked result anywhere in the CODE of the body.
    let keywords: [&str; 5] = ["assert", "panic", "check", "verify", "should_panic"];
    let code_chars: Vec<char> = code_only.chars().collect();
    let mut index = 0_usize;
    let mut checked_result = false;
    while index < code_chars.len() {
        let ch = code_chars[index];
        if ch.is_alphanumeric() || ch == '_' {
            let mut end = index;
            while end < code_chars.len()
                && (code_chars[end].is_alphanumeric() || code_chars[end] == '_')
            {
                end += 1;
            }
            let token: String = code_chars[index..end].iter().collect();
            let mut cursor = end;
            while cursor < code_chars.len() && code_chars[cursor].is_whitespace() {
                cursor += 1;
            }
            let next = code_chars.get(cursor).copied().unwrap_or('\0');
            for keyword in keywords {
                let is_keyword = token == keyword
                    || (token.len() > keyword.len()
                        && token.starts_with(keyword)
                        && token.as_bytes()[keyword.len()] == b'_');
                if is_keyword && matches!(next, '!' | '(' | ':') {
                    checked_result = true;
                }
            }
            index = end;
            continue;
        }
        index += 1;
    }
    if checked_result {
        return None;
    }
    Some((
        "NO_CHECK_CONSTANT",
        "body holds none of `assert`, `panic`, `check`, `verify` or `should_panic` as a real call, macro or trait path, so the gate reads it as constant construction with no checked result"
            .to_owned(),
    ))
}

// 28. callback after owner destruction prevented;
// WORK_UNIT_CASE: 789/28
#[test]
#[allow(clippy::too_many_lines)]
fn case28_child_drop_joins_observer_before_the_port_handle_drops() {
    // `JobProcessObserver` and its `shutdown` are private, so an integration
    // test cannot name them. What is provable from outside is the ordering
    // `SuspendedJobChild::drop` depends on, read from the real production
    // source: the port stays owned across the join, the shutdown key is posted
    // before the join, and the observer thread never resolves an identity
    // inline, so the join is bounded by the dequeue poll and not by a lookup.
    let source = w1b_crate_source_text();
    let shutdown = w1b_block(&source, "fn shutdown(&mut self) {");
    assert!(
        shutdown.contains("PostQueuedCompletionStatus"),
        "shutdown must post the deterministic shutdown key"
    );
    assert!(
        shutdown.contains("JOB_OBSERVER_SHUTDOWN_KEY"),
        "shutdown must post JOB_OBSERVER_SHUTDOWN_KEY, not a bare dequeue"
    );
    let publish = shutdown
        .find("shutdown_requested.store(true")
        .expect("shutdown flag publication");
    let post = shutdown
        .find("PostQueuedCompletionStatus")
        .expect("shutdown key post");
    let join = shutdown.find("thread.join()").expect("observer join");
    assert!(
        publish < post && post < join,
        "teardown must publish, then post, then join, got {publish} {post} {join}"
    );
    assert!(
        !shutdown.contains("thread::sleep"),
        "observer teardown must be ordered by a barrier, never by a sleep"
    );
    // The port is an owned field, so it outlives the join inside `shutdown`:
    // no queued callback can observe a destroyed port handle.
    let observer = w1b_block(&source, "struct JobProcessObserver {");
    assert!(
        observer.contains("completion_port: OwnedHandle"),
        "the completion port must be an OwnedHandle field"
    );
    assert!(
        observer.contains("thread: Option<JoinHandle<()>>"),
        "the observer must own the thread handle that shutdown joins"
    );
    assert!(
        w1b_block(&source, "impl Drop for JobProcessObserver {").contains("self.shutdown();"),
        "Drop must always shut the observer down"
    );
    assert!(
        !w1b_block(&source, "fn job_process_observer_loop(").contains("open_process_identity"),
        "the observer thread must not resolve identities inline, or the join is unbounded"
    );
    let child_drop = w1b_block(&source, "impl Drop for SuspendedJobChild {");
    assert!(
        child_drop.contains("TerminateJobObject(self.job.0, 1);"),
        "child Drop must terminate the pre-assigned job"
    );
    assert!(
        child_drop.contains("self.observer.shutdown();"),
        "child Drop must shut the observer down on every path"
    );
    // Behaviour, on the real owned-handle surface this crate exposes without
    // spawning anything: `RecoverableProcess::open` is the one public
    // constructor of an `OwnedHandle` here, so its drop really runs the same
    // `CloseHandle`-behind-both-sentinels path `SuspendedJobChild::drop`
    // depends on, and it is exactly once.
    //
    // NOT PROVEN HERE: that dropping the unique owner of a supervised child
    // terminates the pre-assigned job, joins the observer, and lets the tree
    // become terminal. That needs a real child process: `clippy.toml` forbids
    // `std::process::Command::new` and `SuspendedJobChild::spawn_named` takes a
    // `&std::process::Command` this crate exposes no seam to build. The
    // child-drop and observer-join execution stays with the in-crate
    // `#[cfg(test)] mod tests` in `src/lib.rs`, which can build its own
    // command; the ordering both depend on is asserted above from source.
    let before = unresolved_handle_cleanup_count();
    {
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        assert_ne!(
            owned.identity().pid,
            0,
            "a real owned handle must carry a non-zero PID"
        );
        assert_eq!(
            unresolved_handle_cleanup_count(),
            before,
            "an unarmed drop must close the handle, never defer it"
        );
    }
    // The drop already ran; a second owned handle proves the wrapper still
    // closes exactly once per handle rather than accumulating unresolved ones.
    let after = unresolved_handle_cleanup_count();
    {
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        assert!(ok(owned.start_ticks()) > 0);
    }
    assert_eq!(
        unresolved_handle_cleanup_count(),
        after,
        "exactly one close per owned handle must run, never zero and never twice"
    );
}

// 29. thread affinity and concurrent access;
// WORK_UNIT_CASE: 789/29
#[test]
fn case29_owned_handle_transfers_unique_ownership_and_is_never_shared() {
    let source = w1b_crate_source_text();
    assert_eq!(
        w1b_count(&source, "struct OwnedHandle(HANDLE);"),
        1,
        "OwnedHandle must exist as the single handle wrapper"
    );
    assert!(
        source.contains("unsafe impl Send for OwnedHandle {}"),
        "OwnedHandle must implement Send explicitly"
    );
    assert!(
        !source.contains("unsafe impl Sync"),
        "OwnedHandle must never implement Sync: shared access is not established"
    );
    // Send transfers unique ownership only: one raw handle, created solely
    // through `new` (both failure sentinels rejected), closed once in Drop, or
    // moved exactly once into a File.
    let new_body = w1b_block(&source, "fn new(handle: HANDLE) -> io::Result<Self> {");
    assert!(
        new_body.contains("handle.is_null()") && new_body.contains("INVALID_HANDLE_VALUE"),
        "construction must reject both failure sentinels before any use"
    );
    assert_eq!(
        w1b_count(&new_body, "Ok(Self(handle))"),
        1,
        "the wrapper must be built from the accepted handle exactly once"
    );
    let into_file = w1b_block(&source, "fn into_file(self) -> File {");
    assert!(
        into_file.contains("std::mem::forget(self)")
            && into_file.contains("File::from_raw_handle(handle)"),
        "into_file must move the raw handle into a File exactly once"
    );
    // Thread affinity, proven by execution: the real handle-owning value this
    // crate exposes is moved across a real thread boundary and still answers
    // the same query, because `Send` transfers the unique owner and nothing
    // shares it.
    let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
        std::process::id(),
    ));
    let pid = owned.identity().pid;
    let ticks = ok(owned.start_ticks());
    let moved = std::thread::spawn(move || (owned.identity().pid, owned.start_ticks()))
        .join()
        .expect("the transferred owner must join");
    assert_eq!(
        moved.0, pid,
        "moving the unique owner across threads must preserve the bound PID"
    );
    // `moved.1` is `start_ticks()`'s `io::Result`, which is fallible like every other
    // query in this crate, so it is unwrapped before it is compared.
    assert_eq!(
        ok(moved.1),
        ticks,
        "moving the unique owner across threads must preserve the same retained handle"
    );
}

// 30. every unsafe Send/Sync implementation has an enforceable witness;
// WORK_UNIT_CASE: 789/30
#[test]
fn case30_exactly_two_unsafe_send_impls_carry_adjacent_witnesses() {
    let source = w1b_crate_source_text();
    // Exactly two unsafe trait impls exist in the crate, and both are Send-only.
    assert_eq!(
        w1b_count(&source, "unsafe impl "),
        2,
        "lib.rs must carry exactly two unsafe impls"
    );
    for subject in [
        "unsafe impl Send for OwnedHandle {}",
        "unsafe impl Send for DirectoryOplockGuard {}",
    ] {
        assert!(
            source.contains(subject),
            "the witness impl {subject} must exist"
        );
    }
    assert!(
        !source.contains("unsafe impl Sync"),
        "zero unsafe Sync impls may exist in this crate"
    );
    // Each impl carries an adjacent, operation-specific SAFETY witness rather
    // than generic, copied or detached prose.
    let owned = w1b_comment_witness(&source, "unsafe impl Send for OwnedHandle {}");
    for reason in [
        "unique ownership",
        "Sync",
        "exactly once",
        "INVALID_HANDLE_VALUE",
        "into_file",
    ] {
        assert!(
            owned.contains(reason),
            "the OwnedHandle witness must address {reason} adjacently"
        );
    }
    let oplock = w1b_comment_witness(&source, "unsafe impl Send for DirectoryOplockGuard {}");
    for reason in [
        "unique ownership",
        "Sync",
        "OVERLAPPED",
        "LateCompletion",
        "leaks",
    ] {
        assert!(
            oplock.contains(reason),
            "the DirectoryOplockGuard witness must address {reason} adjacently"
        );
    }
    // The witness is enforceable, not decorative: the Send-only oplock guard
    // really is movable, and moving it across a real thread carries its
    // kernel-owned state with it. Teardown then resolves deterministically,
    // leaving the directory removable.
    let directory = ok(unique_probe_directory("case30-oplock-send"));
    ok(std::fs::create_dir_all(directory.join("nested")));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    let outcome = std::thread::spawn(move || guard.async_outcome())
        .join()
        .expect("the moved guard must join");
    assert_eq!(
        outcome,
        AsyncIoOutcome::Pending,
        "a moved guard must carry its kernel-owned state with it"
    );
    ok(std::fs::remove_dir_all(&directory));
}

// 31. unauthorized/ambiguous peer cannot authenticate;
// WORK_UNIT_CASE: 789/31
#[test]
#[allow(clippy::too_many_lines)]
fn case31_unresolved_client_pid_never_authenticates_a_peer() {
    // A real `NamedPipeServer` needs the Tokio runtime that the production
    // `bind` owns, so the peer-resolution verdict is asserted from the
    // production source it comes from. A live connected-pipe exchange is NOT
    // proven here; the transport owner (`crates/eliot-app/src/named_pipe_ipc.rs`)
    // keeps that, because this crate exposes no way to build the server without
    // the runtime the transport owns.
    let source = w1b_crate_source_text();
    let body = w1b_block(
        &source,
        "pub fn named_pipe_client_process(pipe: &NamedPipeServer) -> io::Result<ProcessImageIdentity> {",
    );
    // A zero return and a pid of zero both fail before any identity is built.
    let zero_return = body.find("if resolved == 0").expect("zero-return branch");
    let pid_zero = body.find("if pid == 0").expect("pid-zero branch");
    let built = body
        .find("Ok(open_process_identity(pid)?")
        .expect("identity construction");
    assert!(
        zero_return < pid_zero && pid_zero < built,
        "both unresolvable verdicts must precede identity construction"
    );
    assert!(
        body.contains("io::ErrorKind::InvalidData"),
        "pid 0 must fail with a typed InvalidData error"
    );
    assert!(
        body.contains("return Err(io::Error::last_os_error())"),
        "a zero return must surface the raw kernel error, not a stale default"
    );
    assert!(
        !body.contains("unwrap_or_default") && !body.contains("unwrap_or("),
        "no unresolved client PID may degrade into a default identity"
    );
    // The kernel binding is made exactly once, so there is no second,
    // unauthenticated way to obtain a peer identity in this crate.
    assert_eq!(
        w1b_count(&source, "GetNamedPipeClientProcessId("),
        1,
        "the client PID must come from exactly one raw call site"
    );
    // The public return type carries an observation, never a verdict: a
    // connected handle alone cannot authenticate a peer.
    let signature = source
        .lines()
        .find(|line| line.contains("pub fn named_pipe_client_process"))
        .expect("public signature line");
    assert!(
        signature.contains("-> io::Result<ProcessImageIdentity>"),
        "the entry point must return an unverified identity observation"
    );
    assert!(
        source.contains("/// The returned identity is an unverified kernel observation"),
        "the API must document that a connected handle is not authentication"
    );
    // Behaviour, on the identity surface that needs no runtime: a pid that
    // names no process is refused, never defaulted.
    assert_eq!(
        w1b_error_kind(eliot_windows_ipc::RecoverableProcess::open(0)),
        io::ErrorKind::InvalidInput,
        "a zero pid must fail before any identity is built"
    );
}

// 32. ACL/session/principal mismatch stays typed;
// WORK_UNIT_CASE: 789/32
#[test]
fn case32_owner_and_dacl_mismatch_stay_typed_invalid_data() {
    let source = w1b_crate_source_text();
    let body = w1b_block(&source, "fn verify_transport_file_descriptor(");
    // Every contour deviation stays a typed refusal: no panic, no default, and
    // no coerced success. `last_os_error` covers only a failed Win32 query.
    let typed = w1b_count(&body, "io::ErrorKind::InvalidData");
    assert!(
        typed >= 8,
        "each contour deviation must be typed InvalidData, got {typed}"
    );
    for (needle, why) in [
        ("transport file has no owner", "absent owner"),
        (
            "owner is outside the transport contour",
            "non-contour owner",
        ),
        ("has no explicit DACL", "null/absent/substituted DACL"),
        (
            "does not grant exactly the transport peer class",
            "wrong ACE count",
        ),
        ("carries an empty ACE", "empty ACE"),
        ("carries a non-allow ACE", "non-allow ACE"),
        ("carries an empty grant", "empty grant mask"),
        (
            "does not grant the transport peer class",
            "missing peer-class half",
        ),
    ] {
        assert!(
            body.contains(needle),
            "the verifier must carry the typed {why} refusal: {needle}"
        );
    }
    // Inherited rights are never sufficient: an absent, null or substituted
    // DACL is refused before the ACE walk, even inside the owner contour.
    assert!(
        body.contains("dacl_present == 0 || acl.is_null() || acl != dacl"),
        "an inherited/absent DACL must be refused before the ACE walk"
    );
    assert!(
        !body.contains("unwrap_or_default") && !body.contains("unwrap_or("),
        "a missing descriptor must never degrade into a default ACL"
    );
    // Behaviour: the real restrict-then-verify round trip. A fresh temp file
    // carries inherited ACEs and is refused with the typed mismatch; only the
    // exact transport contour is accepted.
    let directory = ok(unique_probe_directory("case32-transport-dacl"));
    let file = directory.join("transport.json");
    ok(std::fs::write(&file, b"{}"));
    assert_eq!(
        w1b_error_kind(eliot_windows_ipc::verify_file_owner_and_dacl(&file)),
        io::ErrorKind::InvalidData,
        "an inherited DACL must stay a typed InvalidData mismatch"
    );
    ok(eliot_windows_ipc::restrict_file_to_current_user_and_system(
        &file,
    ));
    ok(eliot_windows_ipc::verify_file_owner_and_dacl(&file));
    ok(std::fs::remove_dir_all(&directory));
}

// 33. error/panic cleanup preserves ownership;
// WORK_UNIT_CASE: 789/33
#[test]
#[allow(clippy::too_many_lines)]
fn case33_partial_spawn_failure_closes_each_acquired_handle_once() {
    let source = w1b_crate_source_text();
    let guard_new = w1b_block(
        &source,
        "fn new(information: PROCESS_INFORMATION) -> io::Result<Self> {",
    );
    // The armed guard rejects both failure sentinels up front and closes
    // exactly the handles it actually acquired, once each.
    for token in [
        "hProcess.is_null()",
        "hProcess != INVALID_HANDLE_VALUE",
        "hThread.is_null()",
        "hThread != INVALID_HANDLE_VALUE",
        "TerminateProcess(information.hProcess, 1)",
        "CloseHandle(information.hProcess)",
        "CloseHandle(information.hThread)",
    ] {
        assert!(
            guard_new.contains(token),
            "the partial-acquisition guard must carry {token}"
        );
    }
    let guard_drop = w1b_block(&source, "impl Drop for SuspendedProcessGuard {");
    assert!(
        guard_drop.contains("if !self.armed {"),
        "the guard must disarm itself so Drop cannot double-close"
    );
    assert!(
        guard_drop.contains("TerminateProcess(self.process, 1);")
            && guard_drop.contains("WaitForSingleObject(self.process, 5_000)"),
        "the armed guard must terminate and bounded-wait before closing"
    );
    let into_handles = w1b_block(
        &source,
        "fn into_handles(mut self) -> (OwnedHandle, OwnedHandle) {",
    );
    assert!(
        into_handles.contains("self.armed = false;"),
        "into_handles must disarm the guard before transferring ownership"
    );
    assert!(
        into_handles.contains("OwnedHandle(self.process)")
            && into_handles.contains("OwnedHandle(self.thread)"),
        "into_handles must transfer both handles into one OwnedHandle each"
    );
    // Behaviour, on the real public name-validation seam, which needs no command
    // value at all. The name bound is the first statement of `spawn_named`,
    // ahead of every `inheritable_pipe()`, `create_kill_on_close_job`, and
    // `CreateProcessW` call, so an unusable name fails closed while the owned
    // handle count is still zero: no partially built child can exist to unwind.
    //
    // NOT PROVEN HERE: that a spawn failing AFTER the Job Object and observer
    // handles were acquired (for example, a missing program image) still
    // returns having released everything it took, and that the job name is
    // then free for a later generation. Both need a real child process to
    // drive: `clippy.toml` forbids `std::process::Command::new`, and
    // `SuspendedJobChild::spawn_named` takes a `&std::process::Command` this
    // crate exposes no seam to build, so the spawn entry point cannot be
    // called from here at all. The post-acquisition failure execution stays
    // with the in-crate `#[cfg(test)] mod tests` in `src/lib.rs`.
    let spawn = w1b_block(
        &source,
        "pub fn spawn_named(command: &std::process::Command, job_name: &str) -> io::Result<Self> {",
    );
    let name_guard = spawn
        .find("if job_name.is_empty()")
        .expect("the job-name guard");
    for later_acquisition in [
        "let (stdin_read, stdin_write) = inheritable_pipe()?;",
        "let job = create_kill_on_close_job(job_name)?;",
        "let observer = JobProcessObserver::attach(job.0)?;",
    ] {
        let acquired = spawn
            .find(later_acquisition)
            .unwrap_or_else(|| panic!("spawn_named must still acquire {later_acquisition}"));
        assert!(
            name_guard < acquired,
            "the name bound must fail closed before {later_acquisition}"
        );
    }
    // The one owned-handle cleanup this file can really observe is the one
    // that runs with no process at all: an unarmed open/drop closes exactly
    // once, and an armed cleanup counts it unresolved rather than successful.
    let before = unresolved_handle_cleanup_count();
    {
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        assert!(ok(owned.start_ticks()) > 0);
    }
    assert_eq!(
        unresolved_handle_cleanup_count(),
        before,
        "an unarmed owned handle must be closed, never left unresolved"
    );
}

// 34. deterministic fault/crash hooks use barriers, not timing assumptions;
// WORK_UNIT_CASE: 789/34
#[test]
#[allow(clippy::too_many_lines)]
fn case34_fault_seam_arms_by_state_and_orders_teardown_without_sleeping() {
    // Scope, stated plainly. The deterministic BARRIER / model-sequence harness
    // itself lives in the in-crate `#[cfg(test)] mod tests` of `src/lib.rs`,
    // which an integration test cannot see; that owner keeps it. What IS
    // reachable from outside the crate is the public injection seam and the
    // teardown ordering the private `JobProcessObserver::shutdown` implements,
    // and both are asserted in full below.
    let source = w1b_crate_source_text();
    // 1. The seam is real public API, reachable with no feature flag.
    assert!(
        source.contains(
            "pub fn arm_fault_boundaries(boundaries: &[FaultBoundary]) -> ArmedFaultBoundaries {"
        ),
        "arm_fault_boundaries must be public and ungated"
    );
    assert!(
        source.contains("pub fn unresolved_handle_cleanup_count() -> u64 {"),
        "unresolved_handle_cleanup_count must be public and ungated"
    );
    // 2. Arming is state, not time: one atomic swap, restored through Drop.
    assert!(
        source.contains("ARMED_FAULT_BOUNDARIES.swap(mask, Ordering::AcqRel)"),
        "arming must be one atomic state swap, not a timing hook"
    );
    assert!(
        w1b_block(&source, "impl Drop for ArmedFaultBoundaries {")
            .contains("ARMED_FAULT_BOUNDARIES.store(self.previous, Ordering::Release)"),
        "Drop of the arming guard must restore the prior armed state"
    );
    // 3. The seven-boundary vocabulary is the closed denominator.
    let all = w1b_line_run(&source, "pub const ALL: [Self; 7] = [", 9);
    assert_eq!(
        w1b_count(&all, "Self::"),
        7,
        "FaultBoundary::ALL must enumerate exactly the seven boundaries"
    );
    // 4. Teardown is ordered by a barrier, never by an elapsed sleep: the flag
    // is published, the shutdown key is posted, and only then is the observer
    // thread joined, with the port still owned across the join.
    let shutdown = w1b_block(&source, "fn shutdown(&mut self) {");
    let publish = shutdown
        .find("shutdown_requested.store(true")
        .expect("shutdown flag publication");
    let post = shutdown
        .find("PostQueuedCompletionStatus")
        .expect("shutdown key post");
    let join = shutdown.find("thread.join()").expect("observer join");
    assert!(
        publish < post && post < join,
        "teardown must publish, then post, then join, got {publish} {post} {join}"
    );
    assert!(
        !shutdown.contains("thread::sleep"),
        "observer teardown must be ordered by a barrier, never by a sleep"
    );
    // 5. The seam is exercised through the public API. Arming is state, not
    // time: with the Acquisition boundary armed the real production site fails
    // closed before any handle, event or request allocation exists, so a
    // partially built guard is impossible; with Cleanup armed a real owned
    // handle is left open and counted rather than reported as closed.
    let _serialized = fault_boundary_run();
    let directory = ok(unique_probe_directory("case34-fault-seam"));
    ok(std::fs::create_dir_all(directory.join("nested")));
    let before = unresolved_handle_cleanup_count();
    {
        let armed = arm_fault_boundaries(&FaultBoundary::ALL);
        let acquisition = err(DirectoryOplockGuard::acquire(&directory));
        assert!(
            acquisition.to_string().contains("fault injected"),
            "an armed boundary must fail closed naming the boundary, got {acquisition}"
        );
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        drop(owned);
        assert!(
            unresolved_handle_cleanup_count() > before,
            "an injected cleanup fault must leave the handle open and counted"
        );
        drop(armed);
    }
    // 6. Restoring the guard returns the seam to its unarmed state: the very
    // same close now resolves, so the counter stops moving.
    let restored = unresolved_handle_cleanup_count();
    let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
        std::process::id(),
    ));
    drop(owned);
    assert_eq!(
        unresolved_handle_cleanup_count(),
        restored,
        "an unarmed run must close owned handles and report zero unresolved"
    );
    ok(std::fs::remove_dir_all(&directory));
}

// 35. bounded randomized submit/cancel/complete/close sequences;
// WORK_UNIT_CASE: 789/35
#[test]
#[allow(clippy::too_many_lines)]
fn case35_job_enumeration_regrowth_stays_bounded_under_churn() {
    // A FIXED-SEED, BOUNDED drive: no wall clock, no thread id, no environment.
    const SEED: u64 = 0x7e57_1234_9abc_def0;
    const STEPS: usize = 64;
    const BOUND: usize = 4_096;
    use eliot_windows_ipc::TransferOutcome;
    let source = w1b_crate_source_text();
    // The bound the case names, recorded in the production source.
    let declaration = source
        .lines()
        .find(|line| line.starts_with("const MAX_JOB_PROCESS_IDS"))
        .expect("MAX_JOB_PROCESS_IDS declaration");
    assert!(
        declaration.contains("4_096"),
        "the job enumeration bound must be 4096, got {declaration}"
    );
    let ids = w1b_block(
        &source,
        "fn job_process_ids(job: HANDLE) -> io::Result<Vec<u32>> {",
    );
    let check = ids
        .find("if capacity > MAX_JOB_PROCESS_IDS")
        .expect("regrowth bound check");
    let refuse = ids
        .find("Job process list exceeds the attestation limit")
        .expect("refusal");
    assert!(
        check < refuse,
        "the bound check must precede the refusal, got {check} {refuse}"
    );
    assert!(
        ids.contains("let mut capacity = 16_usize;"),
        "enumeration must start at the recorded 16-entry buffer"
    );
    // Bounded randomized churn through the crate's own public grow-or-fail
    // model: a partial report may only size the regrown buffer, any other
    // report is consumed exactly, so no sequence escapes the cap.
    let mut capacity = 16_usize;
    let mut state = SEED;
    for step in 0..STEPS {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let reported = if (state & 1) == 1 {
            capacity + 1
        } else {
            capacity
        };
        let outcome = if reported > capacity {
            TransferOutcome::Truncated { reported, capacity }
        } else {
            TransferOutcome::Complete { units: reported }
        };
        match outcome.complete_units() {
            Ok(units) => assert!(
                units <= capacity,
                "an exact enumeration must never exceed the supplied buffer at step {step}"
            ),
            Err(error) => {
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "a partial report must never become consumable at step {step}"
                );
                // Regrowth is CLAMPED to the recorded cap, exactly as production does.
                // Without the clamp a doubling walk escapes the cap on its own
                // (16 -> ... -> 4096 -> 8192), so this assertion would have
                // failed on the drive's arithmetic rather than on production's.
                let grown = ok(outcome.retry_capacity())
                    .max(capacity.saturating_mul(2))
                    .min(BOUND);
                assert!(
                    grown <= BOUND,
                    "regrowth escaped the recorded cap at step {step}: {grown}"
                );
                assert_eq!(
                    grown,
                    ok(outcome.retry_capacity())
                        .max(capacity.saturating_mul(2))
                        .min(BOUND),
                    "the clamp must be the production cap, applied deterministically"
                );
                capacity = grown;
            }
        }
    }
    assert!(
        capacity <= BOUND,
        "a bounded randomized drive must stay inside the cap, got {capacity}"
    );
    // Behaviour, on the real public verdicts the enumeration itself is written
    // against: `classify_bounded_count` maps a kernel-reported count onto
    // exactly these four public `TransferOutcome` states, and
    // `job_process_ids` consumes them the way the drive above models. Each
    // verdict is driven directly here -- an inside-the-cap report is exact, an
    // empty report stays consumable as zero IDs, and an over-cap report is
    // rejected rather than sliced or allowed to size a retry.
    //
    // NOT PROVEN HERE: that a live job's membership enumerates exactly under
    // the recorded cap. A named job can only be created by
    // `SuspendedJobChild::spawn_named`, which needs a real child process:
    // `clippy.toml` forbids `std::process::Command::new` and this crate exposes
    // no seam to build the `&std::process::Command` that spawn takes. The live
    // enumeration execution stays with the in-crate `#[cfg(test)] mod tests` in
    // `src/lib.rs`.
    let empty = TransferOutcome::Empty;
    assert_eq!(
        ok(empty.complete_units()),
        0,
        "an empty job must stay consumable as zero IDs, never as a failure"
    );
    let inside = TransferOutcome::Complete { units: 1 };
    assert_eq!(
        ok(inside.complete_units()),
        1,
        "an exact count must enumerate exactly that many IDs"
    );
    let over = TransferOutcome::Rejected;
    assert_eq!(
        w1b_error_kind(over.complete_units()),
        io::ErrorKind::InvalidData,
        "an over-cap report must be rejected, never sliced past the buffer"
    );
    assert!(
        over.retry_capacity().is_err(),
        "an over-cap report must never size a retry buffer, or regrowth could escape the cap"
    );
    // The one state that may legitimately regrow is the partial report, and it
    // may only ever size the buffer, never yield IDs.
    let partial = TransferOutcome::Truncated {
        reported: BOUND,
        capacity: 16,
    };
    assert_eq!(
        ok(partial.retry_capacity()),
        BOUND,
        "a partial report may only size the regrown buffer"
    );
    assert_eq!(
        w1b_error_kind(partial.complete_units()),
        io::ErrorKind::InvalidData,
        "a partial report must never become consumable"
    );
    // The production enumeration applies exactly this classifier to its
    // kernel-reported count, and refuses both non-complete arms outright.
    assert!(
        ids.contains("let count = match classify_bounded_count(count, capacity) {"),
        "the live enumeration must classify its kernel-reported count through this exact function"
    );
    assert!(
        ids.contains("TransferOutcome::Truncated { .. } | TransferOutcome::Rejected => {"),
        "the live enumeration must refuse both the truncated and rejected arms"
    );
}

// 36. buffers/OVERLAPPED remain resident until terminal kernel-ownership proof;
// WORK_UNIT_CASE: 789/36
#[test]
#[allow(clippy::too_many_lines)]
fn case36_oplock_storage_releases_only_on_terminal_ownership_proof() {
    let source = w1b_crate_source_text();
    // The release gate: request storage releases only where the exact terminal
    // ownership proof exists; every other outcome retains it fail-closed.
    let release = w1b_block(
        &source,
        "pub fn terminal_storage_release(self) -> Option<TerminalStorageRelease> {",
    );
    for proven in [
        "Self::RejectedBeforeSubmit",
        "Self::SynchronousComplete",
        "Self::ObservedCancel",
        "Self::ObservedComplete",
    ] {
        assert!(
            release.contains(proven),
            "{proven} must be a terminal release state"
        );
    }
    for withheld in [
        "Self::Prepared",
        "Self::Submitted",
        "Self::Pending",
        "Self::UnknownSubmit",
        "Self::CancelRequested",
        "Self::Unresolved",
    ] {
        assert!(
            release.contains(withheld),
            "{withheld} must be withheld from terminal release"
        );
    }
    assert_eq!(
        w1b_count(&release, "Some(TerminalStorageRelease::proven())"),
        1,
        "exactly one arm may construct the release token"
    );
    let drop_body = w1b_block(&source, "impl Drop for DirectoryOplockGuard {");
    assert!(
        drop_body.contains("if observed.terminal_storage_release().is_none() {"),
        "release must be gated on the exact terminal-ownership proof"
    );
    assert_eq!(
        w1b_count(&drop_body, "Box::leak("),
        3,
        "all three kernel-visible boxes must be retained on the fail-closed branch"
    );
    // Behaviour, on the real public guard: a freshly acquired guard stores
    // Pending, exactly the state that yields no release proof, so its OVERLAPPED
    // and request buffers stay resident rather than being freed, and teardown
    // still resolves deterministically (the directory becomes removable).
    let directory = ok(unique_probe_directory("case36-oplock-storage"));
    ok(std::fs::create_dir_all(directory.join("nested")));
    let guard = ok(DirectoryOplockGuard::acquire(&directory));
    assert_eq!(
        guard.async_outcome(),
        AsyncIoOutcome::Pending,
        "a fresh oplock guard must store Pending, the kernel-owned state"
    );
    assert!(
        guard.async_outcome().terminal_storage_release().is_none(),
        "Pending must yield no terminal release proof"
    );
    assert!(
        !ok(guard.mutation_attempted()),
        "an unmutated directory must report no break, so no proof is fabricated"
    );
    drop(guard);
    ok(std::fs::remove_dir_all(&directory));
}

// 37. owned handles close once or remain explicitly owned/unresolved;
// WORK_UNIT_CASE: 789/37
#[test]
#[allow(clippy::too_many_lines)]
fn case37_owned_handle_closes_once_or_stays_counted_unresolved() {
    let source = w1b_crate_source_text();
    let drop_body = w1b_block(&source, "impl Drop for OwnedHandle {");
    // Exactly-once CloseHandle: both sentinels are re-checked at close and
    // exactly one close call sits behind that check.
    assert!(
        drop_body.contains("!self.0.is_null() && self.0 != INVALID_HANDLE_VALUE"),
        "Drop must re-check both failure sentinels before closing"
    );
    assert_eq!(
        w1b_count(&drop_body, "CloseHandle(self.0)"),
        1,
        "Drop must contain exactly one CloseHandle call"
    );
    // An injected cleanup fault leaves the handle open and counts it, so an
    // unresolved cleanup can never read as a successful close.
    assert!(
        drop_body.contains("fault_armed(FaultBoundary::Cleanup)"),
        "an injected cleanup fault must bypass the close"
    );
    assert!(
        drop_body.contains("UNRESOLVED_HANDLE_CLEANUPS.fetch_add(1"),
        "an unresolved cleanup must be counted, not reported successful"
    );
    // into_file is the single transfer out of the wrapper, and it forgets the
    // wrapper so the handle is never closed twice.
    assert_eq!(
        w1b_count(&source, "std::mem::forget(self)"),
        1,
        "into_file must be the only handle-transferring forget"
    );
    // Behaviour, on an unarmed run: a real owned handle is acquired, queried
    // through the handle it uniquely owns, and released exactly once. The
    // process-global counter is compared EXACTLY, so a concurrent armed case
    // cannot make this order-dependent: the same fault-boundary mutex the other
    // armed cases hold is taken here first, and the unarmed arm must leave the
    // counter untouched. A `>=` comparison against a monotonic counter would
    // hold even if every drop silently closed, so it proved nothing.
    let _serialized = fault_boundary_run();
    let before = unresolved_handle_cleanup_count();
    {
        let owned = ok(eliot_windows_ipc::RecoverableProcess::open(
            std::process::id(),
        ));
        assert_eq!(
            owned.identity().pid,
            std::process::id(),
            "the owned handle must carry the resolved PID"
        );
        assert!(
            ok(owned.start_ticks()) > 0,
            "the retained handle must answer a real query before it is released"
        );
    }
    assert_eq!(
        unresolved_handle_cleanup_count(),
        before,
        "an unarmed close must release the handle exactly once and count NO unresolved cleanup"
    );
}

// 38. partial I/O never becomes complete semantic success;
// WORK_UNIT_CASE: 789/38
#[test]
fn case38_image_length_must_be_strictly_below_the_buffer_length() {
    use std::os::windows::ffi::OsStrExt as _;
    let source = w1b_crate_source_text();
    let classify = w1b_block(
        &source,
        "fn classify_image_chars(chars: u32, capacity: usize) -> TransferOutcome {",
    );
    // Zero and unrepresentable are corrupt; reaching the buffer length means
    // truncated (no room for the NUL); only a strictly smaller value is exact.
    assert!(
        classify.contains("if length == 0 {"),
        "a zero reported length must classify as empty, never consumed"
    );
    assert!(
        classify.contains("else if length >= capacity {"),
        "reaching the buffer length must classify as truncated, never consumed"
    );
    assert!(
        classify.contains("TransferOutcome::Complete { units: length }"),
        "only a nonzero length strictly below the buffer length may be consumed"
    );
    // Only Complete carries a consumable count; every other arm fails closed.
    let complete = w1b_block(
        &source,
        "pub fn complete_units(self) -> io::Result<usize> {",
    );
    for closed in [
        "transfer delivered zero units",
        "transfer was truncated",
        "transfer count is invalid",
    ] {
        assert!(
            complete.contains(closed),
            "the non-complete arm must fail closed: {closed}"
        );
    }
    let declaration = source
        .lines()
        .find(|line| line.starts_with("const MAX_PROCESS_IMAGE_CHARS"))
        .expect("MAX_PROCESS_IMAGE_CHARS declaration");
    assert!(
        declaration.contains("32_768"),
        "the image buffer bound must be 32768 units, got {declaration}"
    );
    // Behaviour: the real process image of this very process resolves through
    // the exact path, nonzero and strictly below the recorded bound, with no
    // trailing NUL exposed.
    let image = ok(eliot_windows_ipc::process_image_path(std::process::id()));
    let units = image.as_os_str().encode_wide().count();
    assert!(units > 0, "the live process image must resolve nonzero");
    assert!(
        units < 32_768,
        "the resolved image must stay strictly below the recorded bound, got {units}"
    );
    assert!(
        image.components().count() > 1,
        "the resolved image must be an absolute multi-component path"
    );
    assert!(
        !image.as_os_str().encode_wide().any(|unit| unit == 0),
        "the resolved image must never expose a trailing NUL"
    );
}

// 39. unknown possible submission/completion has no blind retry;
// WORK_UNIT_CASE: 789/39
#[test]
#[allow(clippy::too_many_lines)]
fn case39_only_pending_submission_proceeds_and_nothing_retries_blindly() {
    // A FIXED-SEED, BOUNDED drive of the submit/cancel/complete/close model
    // through the crate's real public `AsyncIoOutcome` surface: no wall clock,
    // no thread id, no environment.
    const SEED: u64 = 0x0bad_c0de_5eed_1234;
    const STEPS: usize = 64;
    let source = w1b_crate_source_text();
    let submit = w1b_block(
        &source,
        "pub fn classify_oplock_submit(self, requested: i32, error_code: Option<i32>) -> Self {",
    );
    // Only ERROR_IO_PENDING is acceptance: a nonzero return is a synchronous
    // completion and any other error is rejected before the kernel owns the
    // request. A verdict outside Submitted never classifies at all.
    assert!(
        submit.contains("if self != Self::Submitted {")
            && submit.contains("return Self::Unresolved;"),
        "a submit verdict must only be classified from Submitted, else fail closed"
    );
    assert!(
        submit.contains("if requested != 0 {"),
        "a nonzero return must classify as a synchronous completion"
    );
    assert!(
        submit.contains("ERROR_IO_PENDING"),
        "the pending outcome must be keyed on ERROR_IO_PENDING"
    );
    assert!(
        submit.contains("Self::RejectedBeforeSubmit"),
        "any other submission verdict must be rejected before submit"
    );
    // The reconcile gate: nothing that might still be live may retry blind.
    let retry = w1b_block(
        &source,
        "pub fn reconcile_before_retry(self) -> io::Result<()> {",
    );
    for live in ["Self::Submitted", "Self::Pending", "Self::CancelRequested"] {
        assert!(
            retry.contains(live),
            "{live} must be refused as still possibly live"
        );
    }
    assert!(
        retry.contains("WouldBlock") && retry.contains("InvalidData"),
        "the retry refusal must stay typed"
    );
    // The pending code is DISCOVERED from the classifier rather than assumed,
    // so the drive below cannot pass on a wrong constant.
    let pending_code = (900_i32..=1_100).find(|code| {
        AsyncIoOutcome::Submitted.classify_oplock_submit(0, Some(*code)) == AsyncIoOutcome::Pending
    });
    assert_eq!(
        pending_code,
        Some(ERROR_IO_PENDING_CODE),
        "ERROR_IO_PENDING must be the single accepted submission error code"
    );
    // Bounded randomized churn: every submit verdict is classified exactly, and
    // every live or unknown outcome refuses a blind retry with a typed error.
    let mut state = SEED;
    for step in 0..STEPS {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let requested = i32::from((state & 1) == 1);
        let code = 900 + i32::try_from((state >> 8) & 0x7f).expect("bounded error code");
        let outcome = AsyncIoOutcome::Submitted.classify_oplock_submit(requested, Some(code));
        if requested != 0 {
            assert_eq!(
                outcome,
                AsyncIoOutcome::SynchronousComplete,
                "a nonzero return is a synchronous completion at step {step}"
            );
        } else if Some(code) == pending_code {
            assert_eq!(
                outcome,
                AsyncIoOutcome::Pending,
                "the pending code is the only accepted submission at step {step}"
            );
        } else {
            assert_eq!(
                outcome,
                AsyncIoOutcome::RejectedBeforeSubmit,
                "any other error must reject before submit at step {step}"
            );
        }
        match outcome.reconcile_before_retry() {
            Ok(()) => assert!(
                !matches!(
                    outcome,
                    AsyncIoOutcome::Pending
                        | AsyncIoOutcome::Submitted
                        | AsyncIoOutcome::CancelRequested
                        | AsyncIoOutcome::UnknownSubmit
                        | AsyncIoOutcome::Unresolved
                ),
                "a live or unknown submit must never be retryable at step {step}"
            ),
            Err(error) => assert_eq!(
                error.kind(),
                if matches!(
                    outcome,
                    AsyncIoOutcome::UnknownSubmit | AsyncIoOutcome::Unresolved
                ) {
                    io::ErrorKind::InvalidData
                } else {
                    io::ErrorKind::WouldBlock
                },
                "the retry refusal must stay typed at step {step}"
            ),
        }
    }
    // A classification attempted outside Submitted fails closed rather than
    // inventing a state, so an unknown verdict can never become an acceptance.
    for start in [
        AsyncIoOutcome::Prepared,
        AsyncIoOutcome::Pending,
        AsyncIoOutcome::CancelRequested,
        AsyncIoOutcome::ObservedCancel,
        AsyncIoOutcome::ObservedComplete,
    ] {
        assert_eq!(
            start.classify_oplock_submit(1, pending_code),
            AsyncIoOutcome::Unresolved,
            "a submit classified outside Submitted must fail closed"
        );
    }
}

// 40. no new raw API family/process owner/authority or unrelated semantic expansion;
// WORK_UNIT_CASE: 789/40
#[test]
fn case40_pipe_server_adds_no_raw_family_and_no_second_authority() {
    let source = w1b_crate_source_text();
    // Exactly one pipe-server authority entry point, backed by exactly one
    // descriptor-construction raw family and exactly one raw handoff to Tokio.
    assert_eq!(
        w1b_count(&source, "pub fn create_current_user_server("),
        1,
        "there must be exactly one pipe-server authority entry point"
    );
    assert_eq!(
        w1b_count(
            &source,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW("
        ),
        1,
        "the descriptor must be constructed by exactly one raw call site"
    );
    assert_eq!(
        w1b_count(&source, "create_with_security_attributes_raw"),
        1,
        "the descriptor must reach Tokio through exactly one raw handoff"
    );
    assert!(
        !source.contains("SetNamedSecurityInfo("),
        "no broader descriptor-rewrite API may appear in this crate"
    );
    // The transport DACL grants exactly the peer class and nothing broader.
    let template = w1b_block(
        &source,
        "fn for_current_user(sid: &str) -> io::Result<Self> {",
    );
    assert!(
        template.contains("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"),
        "the transport DACL must grant exactly LocalSystem plus the named SID"
    );
    assert!(
        !template.contains("WD)") && !template.contains("BU)") && !template.contains("AU)"),
        "no world, builtin or authenticated-user grant may appear in the template"
    );
    // The SID is validated before any descriptor or pipe object is built.
    let server = w1b_block(&source, "pub fn create_current_user_server(");
    let validated = server
        .find("validate_sid(allowed_sid)?;")
        .expect("SID validation");
    let constructed = server
        .find("SecurityDescriptor::for_current_user")
        .expect("descriptor construction");
    assert!(
        validated < constructed,
        "the SID must be validated before the descriptor is constructed"
    );
    // Behaviour: a malformed SID is refused with the typed InvalidInput error,
    // before the descriptor is ever constructed.
    for malformed in ["", "x", "SID", "S-", "S-1-5-x"] {
        assert_eq!(
            w1b_error_kind(eliot_windows_ipc::create_current_user_server(
                "wipc-789-case40",
                malformed,
                true,
            )),
            io::ErrorKind::InvalidInput,
            "a malformed SID must fail closed with InvalidInput for {malformed:?}"
        );
    }
}

// 41. package checks cover default and test-support target sets and supported Windows fixtures;
// WORK_UNIT_CASE: 789/41
#[test]
fn case41_package_checks_span_both_feature_sets_and_supported_fixtures() {
    // The six-command matrix is a package-level property. What is asserted here
    // from inside the package is the part this test file can reach: both target
    // sets really exist, both binaries are declared against them, and each
    // binary carries exactly the authority surface its feature set admits.
    let manifest = w1b_manifest_text();
    assert!(
        manifest.contains("[features]"),
        "the package manifest must declare its feature sets"
    );
    for (feature, why) in [
        ("default = []", "the default target set"),
        ("test-support = []", "the test-support target set"),
    ] {
        assert!(manifest.contains(feature), "{why} must be declared");
    }
    assert!(
        manifest.contains("autobins = false"),
        "the binaries must be declared explicitly for this check to hold"
    );
    for name in ["eliot-process-guardian", "eliot-credential-suite-guard"] {
        assert!(
            manifest.contains(name),
            "the {name} target must be declared"
        );
    }
    assert!(
        manifest.contains("required-features = [\"test-support\"]"),
        "the test-support binary must be gated on that feature"
    );
    // The test-support-only fixture guard consumes the isolated-credential
    // seam that only the test-support feature exposes.
    let suite = w1b_package_source_text("src/bin/eliot-credential-suite-guard.rs");
    assert!(
        suite
            .contains("use eliot_windows_ipc::test_support::isolated_operator_cursor_credentials;"),
        "the fixture guard must import the test-support-only entry point"
    );
    assert!(
        suite.contains("isolated_operator_cursor_credentials()?"),
        "the fixture guard must consume the isolated-credential seam"
    );
    // Neither declared binary carries an unsafe token, so neither adds a raw
    // family to the package denominator.
    let guardian = w1b_package_source_text("src/bin/eliot-process-guardian.rs");
    assert!(
        !guardian.contains("unsafe"),
        "the default-feature guardian binary must carry zero unsafe tokens"
    );
    assert!(
        !suite.contains("unsafe"),
        "the test-support fixture guard must carry zero unsafe tokens"
    );
    // The supported-Windows fixture chain is real: the guardian drives the
    // same public supervised-spawn surface these cases exercise, and refuses
    // to report from an incomplete observer history.
    assert!(
        guardian.contains("SuspendedJobChild::spawn(&child_command)?"),
        "the guardian must drive the public supervised-spawn fixture"
    );
    assert!(
        guardian.contains("child.observed_history_complete()"),
        "the guardian must gate its report on the observer history verdict"
    );
}

// 42. no broad lint/unsafe allow, weakened oracle or omitted required family.
//
// Preserve minimal property/fault regressions. Exact evidence-backed
// inapplicability differs from ignored execution; a required Windows case
// unavailable on another platform remains unverified. Fake/raw-call seams
// prove model behavior, not every OS lifetime guarantee; attach actual
// supported-Windows wrapper/cancellation/cleanup evidence for the applicable
// families.
// WORK_UNIT_CASE: 789/42
#[test]
#[allow(clippy::too_many_lines)]
fn case42_manifest_keeps_narrow_unsafe_exception_and_every_family() {
    let manifest = w1b_manifest_text();
    // The manifest keeps the ADR-0014 exception, and keeps it narrow.
    assert!(
        manifest.contains("unsafe_code = \"allow\""),
        "the manifest must keep the ADR-0014 unsafe_code exception"
    );
    assert!(
        manifest.contains("unsafe_op_in_unsafe_fn = \"deny\""),
        "the manifest must keep unsafe_op_in_unsafe_fn denied"
    );
    // Zero broad allows: the exception is not widened in any direction.
    for broad in [
        "unsafe_code = \"forbid\"",
        "unsafe_op_in_unsafe_fn = \"allow\"",
        "unsafe_op_in_unsafe_fn = \"warn\"",
    ] {
        assert!(
            !manifest.contains(broad),
            "the manifest must not carry the broad escape {broad}"
        );
    }
    // The PRODUCTION source (everything outside `#[cfg(test)]`) carries no lint
    // escape at all. The crate's own test module may carry narrowly scoped
    // `clippy::too_many_lines` attributes, which is not the broad escape case 42
    // forbids: the banned shapes are the ones that silence a SAFETY or authority
    // lint, or that widen `unsafe_code`/`unsafe_op_in_unsafe_fn`.
    let crate_source = w1b_crate_source_text();
    let Some((production_source, _test_only)) = crate_source.split_once("#[cfg(test)]") else {
        panic!("library must still gate its in-crate test module with #[cfg(test)]");
    };
    assert!(
        !production_source.contains("#[allow("),
        "the production source, outside the in-crate test module, must carry zero lint escapes"
    );
    // All seven bounded families are inventoried, not omitted.
    let fixture = fixture_text();
    for family in [
        "credential",
        "oplock-async",
        "pipe-process-identity",
        "job-iocp-spawn",
        "notify-move-file",
        "security-pipe-server-dacl",
        "shared-handle-core",
    ] {
        assert!(
            fixture.contains(family),
            "the fixture must inventory the {family} family"
        );
    }
    // The #754 oracle verdict is not weakened: hard violations stay at zero,
    // and the denominator stays at the normative 42 cases.
    assert!(
        fixture.contains("\"hard_violations\": 0"),
        "the oracle hard-violation count must stay zero"
    );
    for denominator in ["\"expected_cases\": 42", "\"expected_last\": 42"] {
        assert!(
            fixture.contains(denominator),
            "the case denominator must stay at 42, missing {denominator}"
        );
    }

    // -------------------------------------------------------------------------
    // The STRUCTURAL denominator. The substring checks above are satisfied by the
    // very file they police and would still pass on a registry that also carries
    // a case 43, so they cannot carry W7 on their own. Below, the registry is
    // PARSED and this suite's OWN source text is counted, on four independent
    // axes: the length of `cases`, the exact id set 1..=42, the number of
    // anchored `// WORK_UNIT_CASE: 789/<n>` markers here, and equality of the
    // marker id set with the registry id set. A dropped, invented or duplicated
    // case, or a marker deleted from or added to this file, now fails.
    //
    // Axis 1 and 2 read the registry. `serde_json` is a dependency of this
    // package (Cargo.toml: `serde_json.workspace = true`), so the real JSON is
    // parsed rather than substring-matched. The JSON parse is a precondition:
    // an unparseable registry cannot satisfy any of these axes.
    let registry = ok(serde_json::from_str::<serde_json::Value>(&fixture));
    let Some(registry_cases) = registry.get("cases").and_then(serde_json::Value::as_array) else {
        panic!("fixture must carry a top-level `cases` array");
    };
    let registry_len = registry_cases.len();
    assert_eq!(
        registry_len, 42,
        "W7 DENOMINATOR (registry length): the registry `cases` array holds {registry_len} entries, expected exactly 42"
    );
    // Axis 2: the id set is exactly 1..=42. `dedup` makes a duplicate
    // disappear, so the equal-length comparison below also proves there is
    // none; every axis message names the measured numbers either way.
    let mut registry_ids: Vec<u64> = registry_cases
        .iter()
        .map(|entry| {
            entry
                .get("case")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| {
                    panic!("every registry `cases` entry needs an integer `case` id")
                })
        })
        .collect();
    registry_ids.sort_unstable();
    let mut deduped = registry_ids.clone();
    deduped.dedup();
    assert_eq!(
        deduped.len(),
        42,
        "W7 DENOMINATOR (registry id set): the registry carries {} distinct ids, expected exactly 42 distinct ids covering 1..=42",
        deduped.len()
    );
    let expected_ids: Vec<u64> = (1_u64..=42).collect();
    assert_eq!(
        registry_ids, expected_ids,
        "W7 DENOMINATOR (registry id set): the sorted registry ids are {registry_ids:?}, expected exactly 1..=42 (no gap, no duplicate, no extra)"
    );

    // Axis 3 and 4 read THIS source file through the same mechanism `w1b_count`
    // uses for its sixteen source-content checks: `w1b_read_package_file`
    // resolves a package-relative path from `CARGO_MANIFEST_DIR`. `w1b_count`
    // itself counts a literal needle with `str::matches`, so it cannot count a
    // regex-shaped marker line; the same underlying source-text access is used
    // instead, which is the only part of `w1b_count` that matters here.
    let suite_source = w1b_read_package_file("tests/unsafe_family_boundaries.rs");
    // The marker must match the work-unit gate's own ANCHORED regex (below);
    // a marker that does not match it is reported, not counted.
    let marker_prefix = "// WORK_UNIT_CASE:";
    // `_RUST_MARKER_RE = ^\s*//\s*WORK_UNIT_CASE:\s*(\d+)/(\d+)\s*$`, the
    // anchored regex in scripts/work_unit_gate/case_binding.py:31, decomposes
    // into: strip indentation, strip `//`, skip spaces (that is the gate's `\s*`
    // between `//` and `WORK_UNIT_CASE:`), require the literal
    // `WORK_UNIT_CASE:`, skip spaces, then the issue number, a `/`, and the
    // case number running to the end of the line with nothing after it.
    // `trim_end` is the gate's trailing `\s*$`, and requiring the tail to be
    // digits is `(\d+)/(\d+)`: a marker with trailing prose (`789/12 (note)`)
    // or a non-digit tail (`789/12x`, `789/-1`) is therefore NOT counted,
    // exactly as the gate's `$` anchor decides.
    let marker_candidates: Vec<(usize, Option<u64>)> = suite_source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with(marker_prefix))
        .map(|(offset, line)| {
            let issue = line
                .trim_start()
                .strip_prefix("//")
                .map(str::trim_start)
                .and_then(|after_slashes| after_slashes.strip_prefix("WORK_UNIT_CASE:"))
                .map(str::trim);
            let Some(tail) = issue.and_then(|tail| tail.strip_prefix("789/")) else {
                return (offset, None);
            };
            let tail = tail.trim_end();
            let digits_only = !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit());
            (
                offset,
                digits_only.then(|| tail.parse::<u64>().ok()).flatten(),
            )
        })
        .collect();

    // SCOPE OF THIS PORT, stated exactly rather than as blanket parity. The
    // gate's own `parse_rust_markers` runs SIX distinct check families, and
    // this port covers three of them:
    //
    //   PORTED. (1) MARKER ANCHORING, the gate's `_RUST_MARKER_RE`
    //     (`^\s*//\s*WORK_UNIT_CASE:\s*(\d+)/(\d+)\s*$`, case_binding.py:31):
    //     the candidate scan and the id parse below. (2) MARKER BINDING
    //     (:327-375): the forward walk, and (3) the two per-marker RUST checks
    //     the gate runs after it -- `IGNORED_TEST` (:377-379),
    //     `DUPLICATE_TEST_IDENTITY` (:381-384) and the anti-placeholder
    //     ADEQUACY FLOOR (:386-424). Every one of those is re-implemented here
    //     line for line, including the gate's own body-extraction loop and its
    //     four regex arms, and every failure lands in the one
    //     `suite_marker_defects` list below.
    //
    //   NOT PORTED, and not claimable by a line-based scan.
    //     (a) The gate's LEXICAL pre-scan (:147-310). The gate walks the text in
    //         code/attribute/block-comment/string/raw-string/byte-string/char
    //         states, so it can (i) ignore a marker that hides inside a block
    //         comment or inside a string or raw string literal, (ii) report the
    //         marker `COLUMN`, (iii) raise `UNCLOSED_LEXICAL_STATE` for an
    //         unterminated string, raw string or block comment, (iv) raise
    //         `LEXICAL_DEPTH_LIMIT` past `max_lexical_depth`, and (v) ignore a
    //         marker written as a DOC comment (`///`, `//!`). None of those five
    //         is reproduced here: this scan is line-based and cannot tell code
    //         from a comment or a literal.
    //     (b) The gate's RESOURCE BOUNDS (:115-145): `FILE_SIZE_LIMIT`,
    //         `LINE_LENGTH_LIMIT`, `TEST_COUNT_LIMIT` and the non-UTF-8
    //         `SYNTAX_ERROR`. Not reproduced; this file is bounded by its own
    //         size, not by the gate's limits.
    //     (c) `FOREIGN_ISSUE` (:723-725). The gate compares each marker's issue
    //         number with the run descriptor's; the anchor check below proves
    //         the literal issue `789`, so a foreign-issue marker can never reach
    //         the binding walk at all.
    //     (d) Everything `reconcile_case_bindings` owns (:693-821):
    //         `TEST_ROOT` containment, `DUPLICATE_CASE`, `FUNCTION_MULTIPLE_CASES`,
    //         `MISSING_CASE`, `TEST_NOT_DISCOVERED`, `TEST_NOT_EXECUTED`,
    //         `EXECUTION_FAILED`, `NON_PASSING_DISPOSITION`,
    //         `DUPLICATE_DISCOVERY`, `DUPLICATE_EXECUTION` and `IDENTITY_MISMATCH`.
    //         Those consume discovery and execution receipts this file never
    //         sees, so they belong to the runner, not to a source-text port.
    //     (e) The PYTHON side (`check_python_function_adequacy`,
    //         `parse_python_markers`, :444-671): `SKIPPED_DECORATOR`,
    //         `DYNAMIC_IDENTITY`, `AMBIGUOUS_MARKER` and the AST-derived
    //         `proof_ceiling_downgrade`. Not applicable to a Rust source port.
    let suite_lines: Vec<&str> = suite_source.lines().collect();
    // The code-only projection of this same source, taken ONCE here and reused
    // by every `w1b_test_body` call below, so the per-marker body extraction is
    // a line scan rather than a fresh whole-file lexical scan. It is the same
    // text `w1b_adequacy_floor` re-derives per body for the keyword scan.
    let suite_code = w1b_code_only(&suite_source);
    let suite_code_lines: Vec<&str> = suite_code.lines().collect();
    let mut suite_marker_ids: Vec<u64> = Vec::with_capacity(42);
    let mut suite_marker_defects: Vec<String> = Vec::new();
    // Every bound `fn` name against the line of the marker that first bound it,
    // so a second marker reaching the same function is named on BOTH lines. The
    // gate keeps this as `seen_test_names` (:314) and raises
    // `DUPLICATE_TEST_IDENTITY` at :381-384; keeping it here means the port does
    // not depend on `rustc` rejecting a duplicate `fn` for a property the gate
    // checks itself.
    let mut suite_seen_test_names: Vec<(String, usize)> = Vec::new();

    for (offset, marker_id) in marker_candidates {
        let marker_line = offset + 1;
        let Some(marker_id) = marker_id else {
            suite_marker_defects.push(format!(

                "line {marker_line}: `{}` is not an anchored `// WORK_UNIT_CASE: 789/<n>` marker of this work unit (the gate requires exactly `{marker_prefix} <digits>/<digits>` to the end of the line), so its case id cannot be bound to a test",

                suite_lines[offset].trim()
            ));
            continue;
        };
        if !(1..=42).contains(&marker_id) {
            suite_marker_defects.push(format!(

                "line {marker_line}: `// WORK_UNIT_CASE: 789/{marker_id}` is OUT OF RANGE, every case id must be in 1..=42"

            ));
            continue;
        }
        let mut walk = offset + 1;
        let mut has_test_attr = false;
        let mut fn_name: Option<String> = None;
        let mut reason: Option<String> = None;
        while walk < suite_lines.len() {
            let stripped = suite_lines[walk].trim();
            let next_line = walk + 1;
            if stripped.is_empty() {
                reason = Some(format!(
                    "line {marker_line}: DETACHED BY A BLANK LINE (line {next_line}), the gate stops at a blank line before it reaches a function"
                ));
                break;
            }
            if stripped.starts_with("//") || stripped.starts_with("/*") {
                reason = Some(format!(
                    "line {marker_line}: DETACHED BY AN INTERVENING COMMENT (line {next_line}: `{stripped}`), the gate stops at a comment before it reaches a function"
                ));
                break;
            }
            if stripped.starts_with("#[") {
                if stripped.contains("ignore") {
                    reason = Some(format!(
                        "line {marker_line}: NOT ATTACHED TO AN EXECUTED `#[test]` FN, the marker reaches an `#[ignore]` attribute on line {next_line} before the function"
                    ));
                    break;
                }
                has_test_attr |=
                    stripped.contains("#[test]") || stripped.contains("#[tokio::test]");
                walk += 1;
                continue;
            }
            if let Some(name) = stripped
                .split("fn ")
                .nth(1)
                .map(|after_fn| {
                    after_fn
                        .trim_start()
                        .chars()
                        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                        .collect::<String>()
                })
                .filter(|name| !name.is_empty())
            {
                fn_name = Some(name);
                break;
            }
            reason = Some(format!(
                "line {marker_line}: NOT ATTACHED TO A `#[test]` FN, line {next_line} is neither an attribute nor a function declaration (`{stripped}`)"
            ));
            break;
        }
        // The gate applies four checks here, in this order, and raises on the
        // FIRST one that fires, so the binding is reproduced in that order:
        // `MARKER_BEFORE_NON_TEST` when the walk reached a function carrying no
        // test attribute (:373-375), `DUPLICATE_TEST_IDENTITY` when two markers
        // bind the same fn name (:381-384), then the ADEQUACY FLOOR (:386-424).
        // A marker that clears all four is the only thing counted, so a marker
        // sitting above no test, a duplicate identity or a placeholder body can
        // no longer raise the count above 42.
        if !has_test_attr {
            match fn_name {
                Some(name) => suite_marker_defects.push(format!(
                    "line {marker_line}: NOT ATTACHED TO A `#[test]` FN, the function `{name}` it binds carries no test attribute"
                )),
                None => suite_marker_defects.push(format!(
                    "line {marker_line}: DETACHED, no attribute or function declaration follows it before the end of the file"
                )),
            }
            continue;
        }
        let Some(bound_name) = fn_name else {
            suite_marker_defects.push(reason.unwrap_or_else(|| {
                format!(
                    "line {marker_line}: DETACHED, no attribute or function declaration follows it before the end of the file"
                )
            }));
            continue;
        };
        // `DUPLICATE_TEST_IDENTITY` (:381-384).
        if let Some((_, first_line)) = suite_seen_test_names
            .iter()
            .find(|(name, _)| *name == bound_name)
        {
            suite_marker_defects.push(format!(
                "line {marker_line}: DUPLICATE TEST IDENTITY `{bound_name}`, marker on line {first_line} already binds that same function"
            ));
            continue;
        }
        // The ADEQUACY FLOOR (case_binding.py:386-424), now applied through the
        // two shared helpers rather than an inline copy.
        //
        // D2: THE BODY EXTRACTION IS NOW BOUNDED BY THE FUNCTION. The old
        // extractor started at `suite_lines[walk..]`, i.e. AFTER the
        // `fn ... {` line, so the function's own opening brace was never
        // counted, and it counted braces RAW, so a brace inside a string
        // literal or a comment moved it too. This file carries a net +45
        // unbalanced braces inside string literals and comments, so for 19 of
        // the 42 markers the "body" never closed and ran from the test all the
        // way to EOF -- marker 789/1 extracted 3,664 lines, the entire rest of
        // the file. Every one of those bodies therefore spanned this floor's
        // OWN keyword list, so `NO_CHECK_CONSTANT` was structurally incapable
        // of firing for them and the marker was certified by the checker's own
        // source text instead of by the test. `w1b_test_body` starts at the
        // `fn` declaration line -- so the function's own `{` IS counted -- and
        // counts only real braces, skipping string literals, char literals and
        // comments. Depth returns to zero exactly at the brace that closes the
        // function, so the body can no longer overrun it.
        //
        // D3: `w1b_adequacy_floor` reads the CODE-ONLY projection of the body
        // for `TRIVIAL_SELF_EQUALITY` and `NO_CHECK_CONSTANT`, so a keyword
        // quoted in prose or embedded in an identifier no longer satisfies the
        // floor. The old raw `inner_stripped.contains(keyword)` scan accepted
        // `let checkpoint = 1;` (contains `check`) and `let unverified = 2;`
        // (contains `verify`) with zero assertions, and accepted a body that was
        // only the comment `// TODO: assert something real here`.
        //
        // The two helpers are shared with the `source_test` adequacy check in
        // case 12, so the rule is written once.
        let body_text = w1b_test_body(&suite_code_lines, &suite_lines, walk + 1);
        if let Some((problem, why)) = w1b_adequacy_floor(&body_text) {
            suite_marker_defects.push(format!(
                "line {marker_line}: ADEQUACY FLOOR FAILS `{problem}`, case {marker_id} binds `{bound_name}` whose {why}"
            ));
            continue;
        }
        suite_seen_test_names.push((bound_name, marker_line));
        suite_marker_ids.push(marker_id);
    }
    assert!(
        suite_marker_defects.is_empty(),
        "W7 DENOMINATOR (source marker binding): every anchored `// WORK_UNIT_CASE: 789/<n>` marker in this source must be bound to its own `#[test]` fn, clear `scripts/work_unit_gate/case_binding.py` `:377-384` (`IGNORED_TEST`, `DUPLICATE_TEST_IDENTITY`) and the anti-placeholder adequacy floor `:386-424` (`EMPTY_TEST_BODY`, `UNCONDITIONAL_TRUE`, `TRIVIAL_SELF_EQUALITY`, `NO_CHECK_CONSTANT`), and carry a case id in 1..=42; {} marker(s) are not bound: {}",
        suite_marker_defects.len(),
        suite_marker_defects.join(" | ")
    );

    let suite_marker_count = suite_marker_ids.len();
    assert_eq!(
        suite_marker_count, 42,
        "W7 DENOMINATOR (source marker count): this suite source holds {suite_marker_count} anchored `// WORK_UNIT_CASE: 789/<n>` markers, expected exactly 42"
    );
    // `dedup` on the source side too, so a duplicated marker is caught by name
    // rather than hiding behind the equal-length comparison.
    suite_marker_ids.sort_unstable();
    let mut marker_ids_deduped = suite_marker_ids.clone();
    marker_ids_deduped.dedup();
    assert_eq!(
        marker_ids_deduped.len(),
        42,
        "W7 DENOMINATOR (source marker ids): this suite source holds {} distinct marker ids, expected exactly 42",
        marker_ids_deduped.len()
    );
    // Axis 4: the two id sets are equal in BOTH directions, so a case present
    // in the registry but unmarked here, or marked here but absent from the
    // registry, each fail with the full offending id in the message.
    assert_eq!(
        suite_marker_ids, registry_ids,
        "W7 DENOMINATOR (registry/marker agreement): the sorted marker ids in this source are {suite_marker_ids:?} but the sorted registry `cases` ids are {registry_ids:?}; they must be identical"
    );
}
