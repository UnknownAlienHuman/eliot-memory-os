//! Abort-boundary oracle for issue #860.
//!
//! This package-local proof keeps the four historical sites separate: three
//! installer-root aborts now return typed `InstallerRootError` outcomes, and
//! the named-pipe impersonation Drop path retains fail-stop with bounded
//! evidence and an explicit invariant. The current installer dual-failure
//! containment boundary is reconciled separately because it is a live
//! fail-stop site introduced by the typed restoration wrapper.

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

/// Each historical site has its own source marker and disposition proof.
/// Converted sites must show the typed outcome expression that replaced the
/// abort; the retained named-pipe site must show both evidence and invariant.
#[test]
fn historical_sites_have_individual_disposition_proof() {
    let fixtures = load_fixtures();
    assert_eq!(
        fixtures.get("schema").and_then(serde_json::Value::as_str),
        Some("eliot.abort-boundary-cases.v2"),
        "abort_boundary.json schema mismatch"
    );
    assert_eq!(
        fixtures.get("issue").and_then(serde_json::Value::as_u64),
        Some(860),
        "abort_boundary.json must belong to issue 860"
    );
    let sites = fixtures
        .get("historical_sites")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("abort_boundary.json historical_sites must be an array"));
    assert_eq!(
        sites.len(),
        4,
        "issue 860 requires exactly four historical sites"
    );

    for site in sites {
        let id = fixture_string(site, "id");
        let file = fixture_string(site, "file");
        let disposition = fixture_string(site, "disposition");
        let proof = fixture_string(site, "proof");
        let source = std::fs::read_to_string(source_path(&file))
            .unwrap_or_else(|error| panic!("read {file} for {id}: {error}"));

        assert!(
            source.contains(&format!("ABORT_BOUNDARY_CONVERTED site=\"{id}\""))
                || source.contains(&format!("ABORT_BOUNDARY site=\"{id}\"")),
            "site {id} must carry its individual disposition marker in {file}"
        );
        assert!(
            source.contains(&proof),
            "site {id} must show its exact disposition proof in {file}"
        );

        match disposition.as_str() {
            "typed-outcome" => {
                let outcome = fixture_string(site, "typed_outcome");
                assert!(
                    source.contains(&outcome),
                    "converted site {id} must retain its typed outcome expression"
                );
                assert!(
                    !source.contains(&format!("ABORT_BOUNDARY site=\"{id}\"")),
                    "converted site {id} must not be marked as retained fail-stop"
                );
            }
            "retained-fail-stop" => {
                let invariant = fixture_string(site, "invariant");
                let evidence = fixture_string(site, "evidence");
                assert!(
                    source.contains(&format!("invariant=\"{invariant}\"")),
                    "retained site {id} must cite invariant {invariant}"
                );
                assert!(
                    source.contains(&evidence),
                    "retained site {id} must emit bounded evidence through {evidence}"
                );
                assert!(
                    source.contains("std::process::abort()"),
                    "retained site {id} must retain the fail-stop boundary"
                );
            }
            other => panic!("unknown disposition for {id}: {other}"),
        }
    }
}

/// Every live installer abort is explicitly reconciled to the retained
/// containment boundary, including the dual-failure case outside the four
/// historical conversions. The named-pipe site has the same exact proof.
#[test]
fn live_retained_fail_stop_sites_emit_bounded_evidence() {
    let installer = std::fs::read_to_string(source_path("src/installer_root.rs"))
        .unwrap_or_else(|error| panic!("read installer_root.rs: {error}"));
    assert_eq!(
        installer.matches("std::process::abort()").count(),
        2,
        "installer_root.rs must retain only its two documented containment sites"
    );
    assert_eq!(
        installer.matches("ABORT_BOUNDARY site=").count(),
        2,
        "each installer fail-stop site must carry its own marker"
    );
    assert_eq!(
        installer.matches("emit_abort_boundary_evidence(").count(),
        3,
        "helper declaration plus both installer fail-stop emissions must remain"
    );

    let peer_auth = std::fs::read_to_string(source_path("src/named_pipe_peer_auth.rs"))
        .unwrap_or_else(|error| panic!("read named_pipe_peer_auth.rs: {error}"));
    assert_eq!(
        peer_auth.matches("std::process::abort()").count(),
        1,
        "named_pipe_peer_auth.rs must retain exactly its one containment site"
    );
    assert_eq!(
        peer_auth.matches("ABORT_BOUNDARY site=").count(),
        1,
        "the named-pipe fail-stop site must carry its own marker"
    );
    assert!(peer_auth.contains("installer_root::emit_abort_boundary_evidence"));
    assert!(peer_auth.contains("invariant=\"untrusted-client-token\""));
}

/// Every fixture fault preserves its exact typed stage/code: distinct
/// outcomes stay distinct and nothing collapses into a boolean or string.
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
    let mut outcomes: Vec<(String, InstallerRootError)> = Vec::new();
    for case in cases {
        let id = fixture_string(case, "id");
        let stage = stage_by_name(&fixture_string(case, "stage"));
        let code = case
            .get("code")
            .and_then(serde_json::Value::as_u64)
            .and_then(|code| u32::try_from(code).ok())
            .unwrap_or_else(|| panic!("fault fixture {id} needs a numeric u32 code"));
        let error = InstallerRootError::Win32 { stage, code };
        let debug = format!("{error:?}");
        assert!(
            debug.contains(&fixture_string(case, "stage")) && debug.contains(&code.to_string()),
            "fault {id} must keep its exact stage/code in the typed outcome: {debug}"
        );
        let display = format!("{error}");
        assert!(
            !display.is_empty() && display.contains(&fixture_string(case, "stage")),
            "fault {id} display must stay stage-typed: {display}"
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
