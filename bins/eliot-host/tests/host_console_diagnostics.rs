//! F-LOG-HOST-7 proof (#982): console failure observations preserve wire/exit/fallback/cleanup and record B1-B14 via #889 facade to stderr only.
use serde_json::Value;
use std::process::Command;
const MAIN: &str = include_str!("../src/main.rs");
const PROTOCOL: &str = include_str!("../src/host_console_protocol.rs");
const FIXTURE: &str = include_str!("data/host_console_diagnostics.json");
const BANNED: [&str; 4] = ["to_string()", "args", "env::", "nonce"];
fn console_binary() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("exe: {e}"));
    let top = exe.ancestors().nth(2).unwrap_or_else(|| panic!("dir"));
    top.join(format!("eliot-host{}", std::env::consts::EXE_SUFFIX))
}
// WORK_UNIT_CASE: 982/1, 982/2, 982/10, 982/12, 982/13
#[test]
fn host_console_boundaries_are_complete_and_singular() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap_or_else(|e| panic!("json: {e}"));
    let bounds = fixture["boundaries"].as_array();
    for m in bounds.unwrap_or_else(|| panic!("array")) {
        let m = m.as_str().unwrap_or_else(|| panic!("strings"));
        assert!(MAIN.contains(m), "marker missing: {m}");
    }
    assert_eq!(MAIN.matches("install_host_diagnostics").count(), 1);
    assert_eq!(MAIN.matches("observe_terminal_error").count(), 1);
    assert_eq!(MAIN.matches("write_response(&").count(), 4);
    assert_eq!(MAIN.matches("std::process::exit(").count(), 2);
    assert_eq!(MAIN.matches("match host.stop()").count(), 2);
    assert!(PROTOCOL.contains("io::stdout"));
    assert!(!PROTOCOL.contains("stderr") && !PROTOCOL.contains("observe_"));
    for line in MAIN.lines().filter(|l| l.contains("observe_entrypoint")) {
        let hit = BANNED.iter().any(|b| line.contains(b));
        assert!(!hit, "diagnostic line must stay static: {line}");
    }
}
// WORK_UNIT_CASE: 982/3, 982/14
#[test]
fn host_console_binary_keeps_protocol_on_stdout_only() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap_or_else(|e| panic!("json: {e}"));
    let out = Command::new(console_binary())
        .arg("--no-such-flag-982")
        .output();
    let child = out.unwrap_or_else(|e| panic!("run: {e}"));
    #[cfg(windows)]
    assert_eq!(child.status.code(), Some(1066));
    #[cfg(not(windows))]
    assert_eq!(child.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    let frame: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("frame: {e}"));
    assert_eq!(frame["status"], fixture["expected_error_status"]);
    let marks = fixture["marks"].as_array();
    for m in marks.unwrap_or_else(|| panic!("array")) {
        let m = m.as_str().unwrap_or_else(|| panic!("strings"));
        assert!(!stdout.contains(m), "diagnostics on stdout: {m}");
    }
    assert!(!stderr.contains("\"status\""), "protocol on stderr");
}
