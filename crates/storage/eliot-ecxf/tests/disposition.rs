//! Explicit-disposition proof for `eliot-ecxf` (issues #1141/#1716).
//!
//! The crate is the live governed ECXF/1 interchange source: sole owner of
//! `ExportFence`/`EventRange`, consumed by `eliot-backup` on every backup
//! build/validate/restore path bound to the governed export path of #1871.
//! No production binary selects it directly, and it is not a selectable
//! production fallback. This test pins the explicit
//! `[package.metadata.eliot].workspace_admission` disposition, the
//! no-production-binary state, and the exact live library consumer, so the
//! crate can neither become a silent production fallback nor lose its
//! governed consumer silently.

use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-ecxf";
const EXPECTED_ADMISSION: &str = "live governed interchange source per #1141";
/// Exact live library consumer: `eliot-backup` selects the crate for the
/// governed export/restore fence contract. Losing this edge fails the gate.
const LIVE_CONSUMER_MANIFEST: &str = "crates/storage/eliot-backup/Cargo.toml";

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

fn production_dependency_selects_package(
    manifest: &std::path::Path,
) -> Result<Vec<String>, Box<dyn Error>> {
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
                scan_table(table, &format!("target.{target}.dependencies"), &mut matches);
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
        "workspace_admission must record the #1141 live interchange-source state"
    );
    Ok(())
}

#[test]
fn live_governed_consumer_selects_the_crate() -> TestResult {
    let root = workspace_root()?;
    let text = std::fs::read_to_string(root.join(LIVE_CONSUMER_MANIFEST))?;
    let value: toml::Value = toml::from_str(&text)?;
    let selected = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .is_some_and(|table| {
            table.keys().any(|name| name == PACKAGE)
                || table.values().any(|spec| {
                    spec.as_table()
                        .and_then(|spec| spec.get("package"))
                        .and_then(toml::Value::as_str)
                        == Some(PACKAGE)
                })
        });
    assert!(
        selected,
        "live governed consumer {LIVE_CONSUMER_MANIFEST} must select {PACKAGE}"
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
        for selection in production_dependency_selects_package(&manifest)? {
            offenders.push(format!(
                "{}: {selection}",
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
