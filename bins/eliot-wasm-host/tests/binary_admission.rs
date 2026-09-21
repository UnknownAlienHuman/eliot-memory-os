//! Binary-path admission proof for issue #1955.
//!
//! Executes the real `eliot-wasm-host` experimental flow end to end: the
//! contour admission wiring in `main.rs` runs before describe, and denial
//! codes flow to the process exit. Contour denial arms that no CLI input
//! can reach (missing decision, static/native contours, undeclared
//! imports) stay covered by the unit gates in `contour.rs`; this file
//! proves the wired binary sequence runs them in order without breaking
//! the established describe denials.

use std::io::Write;
use std::process::Command;

fn binary_under_test() -> std::path::PathBuf {
    // Prefer cargo's binary path when the harness provides it; otherwise
    // derive the sibling binary next to this test executable. Both resolve
    // to the exact binary cargo just built for this package.
    if let Some(path) = std::option_env!("CARGO_BIN_EXE_eliot_wasm_host") {
        return std::path::PathBuf::from(path);
    }
    let mut dir = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => panic!("test executable path unavailable: {error:?}"),
    };
    dir.pop();
    if dir.file_name().is_some_and(|name| name == "deps") {
        dir.pop();
    }
    dir.join(format!("eliot-wasm-host{}", std::env::consts::EXE_SUFFIX))
}

fn stage_artifact(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lc-binary-admission-{name}-{}-{}.wasm",
        std::process::id(),
        bytes.len()
    ));
    let mut file = match std::fs::File::create(&path) {
        Ok(file) => file,
        Err(error) => panic!("temp artifact create failed: {error:?}"),
    };
    if let Err(error) = file.write_all(bytes) {
        panic!("temp artifact write failed: {error:?}");
    }
    path
}

fn run_experimental(component: &std::path::Path) -> std::process::Output {
    match Command::new(binary_under_test())
        .arg("--profile")
        .arg("D2_OPERATIONAL")
        .arg("--experimental-typed-component")
        .arg(component)
        .arg("--world")
        .arg("context-admission")
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("binary spawn failed: {error:?}"),
    }
}

#[test]
fn legacy_guest_keeps_typed_denial_through_wired_admission() {
    // The legacy `run` guest passes contour admission (automatic default
    // decision, valid manifest) and is then denied by the established
    // describe gate. Exit code and denial channel prove the wired sequence
    // runs end to end without altering existing behavior.
    let bytes = match wat::parse_file("tests/fixtures/guest.wat") {
        Ok(bytes) => bytes,
        Err(error) => panic!("fixture compile failed: {error:?}"),
    };
    let path = stage_artifact("legacy", &bytes);
    let output = run_experimental(&path);
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TYPED_EXECUTION_DENIED"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("\"proof\""),
        "no success receipt may be emitted on denial"
    );
}

#[test]
fn malformed_artifact_dies_in_preflight_before_admission() {
    // Ordering proof: bytes that cannot be a component never reach contour
    // admission or describe; preflight owns this rejection.
    let path = stage_artifact("malformed", b"not-webassembly-at-all");
    let output = run_experimental(&path);
    let _ = std::fs::remove_file(&path);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PREFLIGHT_DENIED"),
        "unexpected stderr: {stderr}"
    );
}
