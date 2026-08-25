use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn git(root: &Path, args: &[&str]) -> TestResult {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
    }
    Ok(())
}

fn repository_fixture() -> TestResult<tempfile::TempDir> {
    let repository = tempfile::tempdir()?;
    git(repository.path(), &["init", "-q"])?;
    git(repository.path(), &["config", "user.name", "eliot-test"])?;
    git(
        repository.path(),
        &["config", "user.email", "eliot-test@example.invalid"],
    )?;
    fs::write(repository.path().join("tracked.txt"), "source\n")?;
    git(repository.path(), &["add", "tracked.txt"])?;
    git(
        repository.path(),
        &["-c", "commit.gpgSign=false", "commit", "-qm", "initial"],
    )?;
    Ok(repository)
}

fn seed(root: &Path) -> TestResult<PathBuf> {
    let path = root.join("work-unit.json");
    let value = json!({
        "id": "W0-06",
        "objective": "compile a bounded bootstrap brief",
        "causal_property": "the route receives explicit evidence and normative coverage",
        "scope_ref": "eliot-memory-os",
        "expected_outputs": ["BootstrapBrief", "NormativeCoverageManifest"],
        "source_refs": ["a".repeat(64)],
        "verifier_ref": "cargo test -p eliot-bootstrap",
        "integration_owner": "Luna-A",
        "contract_revision": "recovery-v1",
        "budget": {
            "context_tokens": 1000,
            "wall_time_ms": 1000,
            "output_bytes": 1000,
            "cost_microunits": 1,
            "max_depth": 1,
            "max_descendants": 1
        },
        "effect_ceiling": {
            "scope_ref": "eliot-memory-os",
            "allowed": ["write_candidate"],
            "max_external_effects": 0
        },
        "stop_condition": "stop after one candidate artifact"
    });
    fs::write(&path, serde_json::to_vec(&value)?)?;
    Ok(path)
}

fn run(root: &Path, seed: &Path, cwd: &Path) -> TestResult<std::process::Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(cwd)
        .args([
            "bootstrap",
            "brief",
            "--work-unit",
            seed.to_str().ok_or("seed path is not utf8")?,
            "--repo-root",
            root.to_str().ok_or("repo path is not utf8")?,
        ])
        .output()?)
}

fn cleanup_draft(output: &Value) {
    if let Some(path) = output
        .get("draft_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
    {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn bootstrap_is_independent_of_process_cwd() -> TestResult {
    let repository = repository_fixture()?;
    let root = repository.path().canonicalize()?;
    let temp = tempfile::tempdir()?;
    let seed_path = seed(temp.path())?;
    let cwd_a = temp.path().join("cwd-a");
    let cwd_b = temp.path().join("cwd-b");
    fs::create_dir_all(&cwd_a)?;
    fs::create_dir_all(&cwd_b)?;

    let first = run(&root, &seed_path, &cwd_a)?;
    let second = run(&root, &seed_path, &cwd_b)?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stdout)
    );
    assert_eq!(first.stdout, second.stdout);
    let output: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(
        output
            .pointer("/response/result/kind")
            .and_then(Value::as_str),
        Some("BOOTSTRAP_BRIEF")
    );
    cleanup_draft(&output);
    Ok(())
}

#[test]
fn bootstrap_rejects_relative_root_and_reports_json() -> TestResult {
    let temp = tempfile::tempdir()?;
    let seed_path = seed(temp.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(temp.path())
        .args([
            "bootstrap",
            "brief",
            "--work-unit",
            seed_path.to_str().ok_or("seed path is not utf8")?,
            "--repo-root",
            "relative-root",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        envelope.get("code").and_then(Value::as_str),
        Some("INVALID_INPUT")
    );
    Ok(())
}

#[test]
fn bootstrap_tampered_existing_draft_is_digest_mismatch() -> TestResult {
    let repository = repository_fixture()?;
    let root = repository.path().canonicalize()?;
    let temp = tempfile::tempdir()?;
    let seed_path = seed(temp.path())?;
    let cwd = temp.path().join("cwd");
    fs::create_dir_all(&cwd)?;
    let first = run(&root, &seed_path, &cwd)?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    let output: Value = serde_json::from_slice(&first.stdout)?;
    let draft_path = output
        .get("draft_path")
        .and_then(Value::as_str)
        .ok_or("draft path")?;
    fs::write(draft_path, b"{\"tampered\":true}\n")?;

    let second = run(&root, &seed_path, &cwd)?;
    assert_eq!(second.status.code(), Some(65));
    let envelope: Value = serde_json::from_slice(&second.stdout)?;
    assert_eq!(
        envelope.get("code").and_then(Value::as_str),
        Some("DIGEST_MISMATCH")
    );
    let _ = fs::remove_file(draft_path);
    Ok(())
}
