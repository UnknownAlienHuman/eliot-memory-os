//! Retire-candidate disposition proof for `eliot-swarm` (issue #1699).
//!
//! Issue #1139 closed with the provider adapters (ACP/Claude/Codex/OpenCode)
//! wired through `eliot-native-worker` while `eliot-swarm` itself was
//! dispositioned retire-candidate with a manifest to follow (PR #1673). This
//! test pins that manifest: the exact `[package.metadata.eliot]
//! .workspace_admission` value plus the current no-production-binary-consumer
//! state. Removing the crate or admitting it to a reachable owner path must
//! update the manifest first, so neither state can drift silently.

use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-swarm";
const EXPECTED_ADMISSION: &str = "retire-candidate per #1139 (closed via PR #1673)";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut dir = manifest_dir();
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            let text = std::fs::read_to_string(manifest)?;
            if text.contains("[workspace]") && text.contains("members") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            return Err("workspace root not found".into());
        }
    }
}

fn production_dependency_lines(manifest: &std::path::Path) -> Result<Vec<String>, Box<dyn Error>> {
    let text = std::fs::read_to_string(manifest)?;
    let mut lines = Vec::new();
    let mut in_dev = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dev = trimmed == "[dev-dependencies]"
                || trimmed == "[build-dependencies]"
                || trimmed.starts_with("[dev-dependencies.")
                || trimmed.starts_with("[build-dependencies.");
            continue;
        }
        if !(trimmed.starts_with(PACKAGE)
            || trimmed.starts_with(&format!("\"{PACKAGE}\"")))
        {
            continue;
        }
        if !in_dev {
            lines.push(trimmed.to_owned());
        }
    }
    Ok(lines)
}

#[test]
fn retire_candidate_disposition_is_recorded() -> TestResult {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    assert!(
        text.contains(EXPECTED_ADMISSION),
        "workspace_admission must record the #1139 retire-candidate disposition"
    );
    Ok(())
}

#[test]
fn no_production_binary_selects_the_crate() -> TestResult {
    let root = workspace_root()?;
    let mut offenders = Vec::new();
    let mut entries: Vec<_> =
        std::fs::read_dir(root.join("bins"))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        for line in production_dependency_lines(&manifest)? {
            offenders.push(format!(
                "{}: {line}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "production binary selects {PACKAGE} without an owner admission: {offenders:?}"
    );
    Ok(())
}
