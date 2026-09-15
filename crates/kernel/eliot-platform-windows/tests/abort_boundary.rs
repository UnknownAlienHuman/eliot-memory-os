//! Abort-boundary oracle for issue #860.
//!
//! Package-local proof that the `std::process::abort()` sites in the two
//! Windows guard modules reconcile exactly with the documented retained
//! fail-stop boundary, and that every fixture fault preserves its exact
//! typed restoration stage/code instead of aborting or collapsing into a
//! boolean/string outcome.
//!
//! Scope: `src/installer_root.rs` (scoped restore guard) and
//! `src/named_pipe_peer_auth.rs` (impersonation guard) only. The fatal
//! branches themselves are never executed here: emergency termination is
//! proved by source reconciliation below plus the crate's inline typed
//! restoration tests, never by killing this harness. Fixtures are finite
//! and nonsecret (symbolic stages plus numeric codes).

use std::collections::HashMap;
use std::path::PathBuf;

use eliot_platform_windows::{InstallerRootError, InstallerRootStage};

fn package_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_path() -> PathBuf {
    package_dir()
        .join("tests")
        .join("data")
        .join("abort_boundary.json")
}

fn source_path(relative: &str) -> PathBuf {
    package_dir().join(relative.replace('/', std::path::MAIN_SEPARATOR_STR))
}

fn load_fixtures() -> serde_json::Value {
    let text = std::fs::read_to_string(fixture_path())
        .unwrap_or_else(|error| panic!("read abort_boundary.json: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse abort_boundary.json: {error}"))
}

fn fixture_string(value: &serde_json::Value, field: &str) -> String {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("fixture field missing or not a string: {field}"))
        .to_owned()
}

fn stage_by_name(name: &str) -> InstallerRootStage {
    match name {
        "OpenThreadToken" => InstallerRootStage::OpenThreadToken,
        "OpenProcessToken" => InstallerRootStage::OpenProcessToken,
        "DuplicateToken" => InstallerRootStage::DuplicateToken,
        "QueryPrivilege" => InstallerRootStage::QueryPrivilege,
        "EnablePrivilege" => InstallerRootStage::EnablePrivilege,
        "BindThreadToken" => InstallerRootStage::BindThreadToken,
        "RestorePrivilege" => InstallerRootStage::RestorePrivilege,
        "RestoreThreadToken" => InstallerRootStage::RestoreThreadToken,
        "CreateDirectory" => InstallerRootStage::CreateDirectory,
        "CreateProtectedFile" => InstallerRootStage::CreateProtectedFile,
        "OpenReadback" => InstallerRootStage::OpenReadback,
        "Readback" => InstallerRootStage::Readback,
        other => panic!("unknown InstallerRootStage fixture name: {other}"),
    }
}

/// Every current `abort()` reconciles to exactly one documented retained
/// fail-stop site, and every documented site carries its marker, invariant,
/// and bounded-evidence reference in source. No site may be omitted or
/// silently added.
#[test]
fn retained_fail_stop_sites_reconcile_with_documented_boundary() {
    let fixtures = load_fixtures();
    assert_eq!(
        fixtures.get("schema").and_then(serde_json::Value::as_str),
        Some("eliot.abort-boundary-cases.v1"),
        "abort_boundary.json schema mismatch"
    );
    assert_eq!(
        fixtures.get("issue").and_then(serde_json::Value::as_u64),
        Some(860),
        "abort_boundary.json must belong to issue 860"
    );
    let sites = fixtures
        .get("sites")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("abort_boundary.json sites must be an array"));
    assert!(!sites.is_empty(), "abort boundary must document its sites");

    let mut sources: HashMap<String, String> = HashMap::new();
    let mut expected_per_file: HashMap<String, usize> = HashMap::new();
    for site in sites {
        let id = fixture_string(site, "id");
        let file = fixture_string(site, "file");
        let disposition = fixture_string(site, "disposition");
        let invariant = fixture_string(site, "invariant");
        let evidence = fixture_string(site, "evidence");
        let typed_stage = fixture_string(site, "typed_stage");
        assert_eq!(
            disposition, "retained-fail-stop",
            "site {id} must declare its retained fail-stop disposition"
        );
        let source = if let Some(source) = sources.get(&file) {
            source.clone()
        } else {
            let text = std::fs::read_to_string(source_path(&file))
                .unwrap_or_else(|error| panic!("read {file}: {error}"));
            sources.insert(file.clone(), text.clone());
            text
        };
        assert!(
            source.contains(&format!("ABORT_BOUNDARY site=\"{id}\"")),
            "site {id} must carry its ABORT_BOUNDARY marker in {file}"
        );
        assert!(
            source.contains(&format!("invariant=\"{invariant}\"")),
            "site {id} must cite its invariant ({invariant}) in {file}"
        );
        assert!(
            source.contains(&evidence),
            "site {id} must reference its bounded evidence emitter ({evidence}) in {file}"
        );
        assert!(
            source.contains(&typed_stage),
            "site {id} must keep its typed restoration stage ({typed_stage}) in {file}"
        );
        *expected_per_file.entry(file).or_insert(0) += 1;
    }

    for (file, expected) in &expected_per_file {
        let source = sources
            .get(file)
            .unwrap_or_else(|| panic!("missing source {file}"));
        let actual = source.matches("std::process::abort()").count();
        assert_eq!(
            actual, *expected,
            "abort count in {file} must reconcile to documented sites: \
             found {actual} std::process::abort() for {expected} documented sites"
        );
        let evidence_refs = source.matches("emit_abort_boundary_evidence").count();
        assert!(
            evidence_refs >= *expected,
            "every retained site in {file} must emit bounded evidence before termination"
        );
    }

    // Both impersonation callers keep the explicit typed revert path: the
    // typed `revert()` result is propagated with `?`, never discarded.
    let peer_auth = sources
        .get("src/named_pipe_peer_auth.rs")
        .unwrap_or_else(|| panic!("peer-auth source must be loaded"));
    assert_eq!(
        peer_auth.matches("impersonation.revert()?").count(),
        2,
        "both impersonation callers must propagate the typed revert outcome"
    );
}

/// Every fixture fault preserves its exact typed stage/code in the public
/// error type: distinct outcomes stay distinct, and nothing collapses into
/// a boolean, string, or silent success.
#[test]
fn fault_fixtures_preserve_exact_typed_stage_and_code() {
    let fixtures = load_fixtures();
    let cases = fixtures
        .get("fault_cases")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("abort_boundary.json fault_cases must be an array"));
    assert!(
        cases.len() >= 2,
        "abort boundary needs more than one fault fixture"
    );
    let mut seen_ids = std::collections::HashSet::new();
    let mut outcomes: Vec<(String, InstallerRootError)> = Vec::new();
    for case in cases {
        let id = fixture_string(case, "id");
        assert!(
            seen_ids.insert(id.clone()),
            "duplicate fault fixture id: {id}"
        );
        let stage = stage_by_name(&fixture_string(case, "stage"));
        let code = case
            .get("code")
            .and_then(serde_json::Value::as_u64)
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or_else(|| panic!("fault fixture {id} needs a numeric u32 code"));
        let error = InstallerRootError::Win32 { stage, code };
        let debug = format!("{error:?}");
        assert!(
            debug.contains(&fixture_string(case, "stage")),
            "fault {id} must keep its stage in the typed outcome: {debug}"
        );
        assert!(
            debug.contains(&code.to_string()),
            "fault {id} must keep its exact code in the typed outcome: {debug}"
        );
        let display = format!("{error}");
        assert!(
            !display.is_empty() && display.contains(&fixture_string(case, "stage")),
            "fault {id} display must stay stage-typed, never a bare string: {display}"
        );
        outcomes.push((id, error));
    }
    for (index, (left_id, left)) in outcomes.iter().enumerate() {
        for (right_id, right) in outcomes.iter().skip(index + 1) {
            assert_ne!(
                left, right,
                "fault fixtures {left_id} and {right_id} must stay distinct typed outcomes"
            );
        }
    }
}
