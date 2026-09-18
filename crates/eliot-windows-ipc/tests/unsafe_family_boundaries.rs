#![cfg(windows)]
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
    credential_delete_current_user, credential_ids_current_user_with_prefix,
    credential_read_current_user, credential_status_current_user, credential_write_current_user,
    validate_credential_id,
};
use std::io;
use std::path::Path;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => panic!("unexpected success: {value:?}"),
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

// WORK_UNIT_CASE: 789/1
#[test]
fn credential_boundary_valid_minimal_ids() {
    ok(validate_credential_id("a"));
    ok(validate_credential_id("abc123"));
    ok(validate_credential_id("wipc-789-probe"));
}

// WORK_UNIT_CASE: 789/2
#[test]
fn credential_boundary_valid_nested_ids() {
    ok(validate_credential_id("operator-cursor/isolated-abc"));
    ok(validate_credential_id("a-b_c.d/e-f_g.h/i"));
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
    for case in 1..=12 {
        let marker = format!("\"case\": {case}");
        assert!(
            fixture.contains(marker.as_str()),
            "fixture must bind case {case}"
        );
    }
}
