//! Explicit-disposition proof for `eliot-ecxf` (issue #1716).
//!
//! Disposition: KEEP with one reachable owner. `eliot-backup` is the only
//! workspace package that selects the crate (its governed
//! `export_ecxf_package` is the single ECXF/1 builder, #1871), and it reaches
//! production only through that edge: no production binary declares the
//! crate directly. This test pins the recorded
//! `[package.metadata.eliot].workspace_admission` disposition plus that exact
//! consumer state, so the crate can neither become a silent production
//! fallback nor gain a second, ungoverned owner.

use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-ecxf";
const EXPECTED_ADMISSION: &str = "#1716 disposition: KEEP with reachable owner eliot-backup";
/// Exact workspace consumer allowlist: the governed export owner only.
const REACHABLE_OWNERS: [&str; 1] = ["crates/storage/eliot-backup: dependencies.eliot-ecxf"];

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

fn production_dependency_selects_package(manifest: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    fn scan_table(
        table: &toml::map::Map<String, toml::Value>,
        section: &str,
        matches: &mut Vec<String>,
    ) {
        for (name, spec) in table {
            let package = spec
                .as_table()
                .and_then(|spec| spec.get("package"))
                .and_then(toml::Value::as_str);

            if name == PACKAGE || package == Some(PACKAGE) {
                matches.push(format!("{section}.{name}"));
            }
        }
    }

    let text = std::fs::read_to_string(manifest)?;
    let value: toml::Value = toml::from_str(&text)?;
    let mut matches = Vec::new();

    if let Some(table) = value.get("dependencies").and_then(toml::Value::as_table) {
        scan_table(table, "dependencies", &mut matches);
    }

    if let Some(targets) = value.get("target").and_then(toml::Value::as_table) {
        for (target, target_value) in targets {
            if let Some(table) = target_value
                .get("dependencies")
                .and_then(toml::Value::as_table)
            {
                scan_table(
                    table,
                    &format!("target.{target}.dependencies"),
                    &mut matches,
                );
            }
        }
    }

    Ok(matches)
}

#[test]
fn owner_disposition_is_recorded() -> TestResult {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    assert!(
        text.contains(EXPECTED_ADMISSION),
        "workspace_admission must record the #1716 KEEP disposition and its reachable owner"
    );
    Ok(())
}

#[test]
fn no_production_binary_selects_the_crate() -> TestResult {
    let root = workspace_root()?;
    let mut offenders = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(root.join("bins"))?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        for selection in production_dependency_selects_package(&manifest)? {
            offenders.push(format!(
                "{}: {selection}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "production binary selects {PACKAGE} directly instead of through its owner: {offenders:?}"
    );
    Ok(())
}

#[test]
fn the_reachable_owner_is_the_only_workspace_consumer() -> TestResult {
    let root = workspace_root()?;
    let workspace: toml::Value =
        toml::from_str(&std::fs::read_to_string(root.join("Cargo.toml"))?)?;
    let members = workspace
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or("workspace members not found")?;
    let mut consumers = Vec::new();
    for member in members {
        let member = member.as_str().ok_or("workspace member is not a path")?;
        for selection in
            production_dependency_selects_package(&root.join(member).join("Cargo.toml"))?
        {
            consumers.push(format!("{member}: {selection}"));
        }
    }
    assert_eq!(
        consumers, REACHABLE_OWNERS,
        "{PACKAGE} must be selected only by its governed export owner"
    );
    Ok(())
}
