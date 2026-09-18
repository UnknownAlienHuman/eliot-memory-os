//! Non-runtime disposition proof for `eliot-store-memory` (issue #1715).
//!
//! The crate is a deterministic in-memory reference implementation for the
//! store contracts: a test/reference contour, never a production storage
//! fallback. This test pins the explicit `[package.metadata.eliot]
//! .workspace_admission` marking plus the current no-production-binary
//! consumer state, so a future production selection must update the
//! disposition first instead of happening silently.

use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-store-memory";
const EXPECTED_ADMISSION: &str = "non-runtime implementation-support reference per #1715";

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
fn non_runtime_disposition_is_recorded() -> TestResult {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    assert!(
        text.contains(EXPECTED_ADMISSION),
        "workspace_admission must record the #1715 non-runtime disposition"
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
