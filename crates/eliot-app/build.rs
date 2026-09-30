use std::path::PathBuf;
use std::process::Command;

fn main() {
    let Some(manifest_dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
        panic!("CARGO_MANIFEST_DIR is not set by Cargo");
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let Some(workspace) = manifest_dir.parent().and_then(|path| path.parent()) else {
        panic!("eliot-app is not nested under crates");
    };
    let workspace = workspace.to_path_buf();
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&workspace)
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            panic!("git is required to bind the Eliot binary to its source commit: {error}")
        }
    };
    assert!(output.status.success(), "git rev-parse HEAD failed");
    let source_commit = match String::from_utf8(output.stdout) {
        Ok(source_commit) => source_commit.trim().to_owned(),
        Err(error) => panic!("git source commit is not UTF-8: {error}"),
    };
    assert!(
        source_commit.len() == 40 && source_commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "git source commit must be a 40-character hexadecimal object id"
    );
    println!("cargo:rustc-env=ELIOT_BUILD_SOURCE_COMMIT={source_commit}");
    // Issue #1897: the governed engine verifier lane's `BuildFingerprint.target`
    // must be the real compilation target, not a literal. Cargo exports `TARGET`
    // to build scripts, so the value is observed rather than invented.
    let target = match std::env::var("TARGET") {
        Ok(target) => target,
        Err(error) => panic!("Cargo does not export TARGET to build scripts: {error}"),
    };
    assert!(
        !target.trim().is_empty(),
        "Cargo exported an empty compilation target"
    );
    println!("cargo:rustc-env=ELIOT_BUILD_TARGET={target}");
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join(".git/HEAD").display()
    );
    if let Ok(symbolic) = Command::new("git")
        .args(["symbolic-ref", "HEAD"])
        .current_dir(&workspace)
        .output()
        && symbolic.status.success()
    {
        let reference = String::from_utf8_lossy(&symbolic.stdout).trim().to_owned();
        if let Ok(path) = Command::new("git")
            .args(["rev-parse", "--git-path", &reference])
            .current_dir(&workspace)
            .output()
            && path.status.success()
        {
            let path = String::from_utf8_lossy(&path.stdout).trim().to_owned();
            println!("cargo:rerun-if-changed={}", workspace.join(path).display());
        }
    }
}
