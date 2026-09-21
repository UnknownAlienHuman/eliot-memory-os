// Wiring proof for `eliot installation stage-update`: declared channels,
// new versioned directories, the running-binary guard, and the
// release-versus-generation record.
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

fn eliot() -> Command {
    Command::new(env!("CARGO_BIN_EXE_eliot"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn staged_name(package: &str) -> String {
    if cfg!(windows) {
        format!("{package}.exe")
    } else {
        package.to_owned()
    }
}

fn stage_update(root: &Path, args: &[String]) -> (i32, String, String) {
    let _ = root;
    let output = eliot()
        .arg("installation")
        .arg("stage-update")
        .args(args)
        .output()
        .expect("run eliot installation stage-update");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn arg(value: impl Into<String>) -> String {
    value.into()
}

#[test]
fn stage_update_creates_new_versioned_dir_and_leaves_running_exe_unchanged() {
    let root = tempfile::tempdir().expect("temp root");
    let install_root = root.path().join("install");
    let running_dir = install_root.join("example-module").join("1.0.0");
    fs::create_dir_all(&running_dir).expect("create running version dir");
    let running_exe = running_dir.join(staged_name("example-module"));
    fs::write(&running_exe, b"running-v1").expect("write running exe");

    let payload_path = root.path().join("payload.bin");
    fs::write(&payload_path, b"updated-v2").expect("write payload");
    let record_path = root.path().join("record.json");

    let (code, stdout, _) = stage_update(
        root.path(),
        &[
            arg("--install-root"),
            arg(install_root.to_string_lossy()),
            arg("--package"),
            arg("example-module"),
            arg("--version"),
            arg("1.0.1"),
            arg("--channel"),
            arg("preview"),
            arg("--artifact-sha256"),
            arg(sha256_hex(b"updated-v2")),
            arg("--payload"),
            arg(payload_path.to_string_lossy()),
            arg("--running-exe"),
            arg(running_exe.to_string_lossy()),
            arg("--previous-version-dir"),
            arg(running_dir.to_string_lossy()),
            arg("--output"),
            arg(record_path.to_string_lossy()),
        ],
    );
    assert_eq!(code, 0, "stdout: {stdout}");
    let receipt: Value = serde_json::from_str(&stdout).expect("receipt JSON");
    assert_eq!(receipt["status"], "STAGED");
    assert_eq!(receipt["channel"], "preview");
    assert_eq!(receipt["kind"], "module-generation");

    let staged_exe = install_root
        .join("example-module")
        .join("1.0.1")
        .join(staged_name("example-module"));
    assert_eq!(
        fs::read(&staged_exe).expect("read staged exe"),
        b"updated-v2"
    );
    assert_eq!(
        fs::read(&running_exe).expect("reread running exe"),
        b"running-v1"
    );

    let record: Value =
        serde_json::from_str(&fs::read_to_string(&record_path).expect("read record"))
            .expect("record JSON");
    assert_eq!(record["package_name"], "example-module");
    assert_eq!(record["channel"], "preview");
    assert_eq!(record["kind"], "module-generation");
    assert_eq!(record["generation"], "example-module@1.0.1");
    assert!(record["rollback_from"].is_string());
}

#[test]
fn stage_update_rejects_undeclared_channel_without_mutation() {
    let root = tempfile::tempdir().expect("temp root");
    let install_root = root.path().join("install");
    let payload_path = root.path().join("payload.bin");
    fs::write(&payload_path, b"payload").expect("write payload");
    let record_path = root.path().join("record.json");

    let (code, _, _) = stage_update(
        root.path(),
        &[
            arg("--install-root"),
            arg(install_root.to_string_lossy()),
            arg("--package"),
            arg("example-module"),
            arg("--version"),
            arg("1.0.0"),
            arg("--channel"),
            arg("nightly"),
            arg("--artifact-sha256"),
            arg(sha256_hex(b"payload")),
            arg("--payload"),
            arg(payload_path.to_string_lossy()),
            arg("--output"),
            arg(record_path.to_string_lossy()),
        ],
    );
    assert_eq!(code, 2);
    assert!(!install_root.exists());
    assert!(!record_path.exists());
}

#[test]
fn stage_update_requires_release_approval_for_kernel_host() {
    let root = tempfile::tempdir().expect("temp root");
    let install_root = root.path().join("install");
    let payload_path = root.path().join("payload.bin");
    fs::write(&payload_path, b"kernel-payload").expect("write payload");

    let base: Vec<String> = [
        "--install-root",
        &install_root.to_string_lossy(),
        "--package",
        "eliot-kernel",
        "--version",
        "9.9.9",
        "--channel",
        "stable",
        "--artifact-sha256",
        &sha256_hex(b"kernel-payload"),
        "--payload",
        &payload_path.to_string_lossy(),
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();

    let denied_record = root.path().join("denied.json");
    let mut denied_args = base.clone();
    denied_args.extend([arg("--output"), arg(denied_record.to_string_lossy())]);
    let (code, stdout, _) = stage_update(root.path(), &denied_args);
    assert_eq!(code, 2, "stdout: {stdout}");
    let refused: Value = serde_json::from_str(&stdout).expect("refusal JSON");
    assert_eq!(
        refused["code"],
        "INSTALLATION_UPDATE_RELEASE_APPROVAL_REQUIRED"
    );

    let allowed_record = root.path().join("allowed.json");
    let mut allowed_args = base;
    allowed_args.extend([
        arg("--release-approved"),
        arg("--output"),
        arg(allowed_record.to_string_lossy()),
    ]);
    let (code, stdout, _) = stage_update(root.path(), &allowed_args);
    assert_eq!(code, 0, "stdout: {stdout}");
    let receipt: Value = serde_json::from_str(&stdout).expect("receipt JSON");
    assert_eq!(receipt["channel"], "stable");
    assert_eq!(receipt["kind"], "kernel-host-release");
    let record: Value =
        serde_json::from_str(&fs::read_to_string(&allowed_record).expect("read record"))
            .expect("record JSON");
    assert_eq!(record["kind"], "kernel-host-release");
    assert!(record["rollback_from"].is_null());

    assert!(PathBuf::from(receipt["installed_dir"].as_str().expect("installed dir")).exists());
}
