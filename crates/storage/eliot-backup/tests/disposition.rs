//! Explicit-disposition proof for `eliot-backup` (issues #1141/#1716/#1873).
//!
//! The crate is admitted with a bounded non-runtime product role: the
//! operator CLI preview/coverage surface plus the isolated rehearsal runner,
//! bound to the governed export path of #1871 and the recoverability evidence
//! of #1873, plus the Kernel-owned governed capture/restore coordination of
//! #959/#960. Production execution and cutover stay with the #960/#961 owners,
//! and the crate is not a selectable storage fallback. This test pins the
//! exact `[package.metadata.eliot].workspace_admission` disposition plus the
//! exact production-binary consumer allowlist (only `eliot` for the preview
//! surface and `eliot-kernel` for governed capture/restore), so no silent
//! third consumer can appear.

use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-backup";
const EXPECTED_ADMISSION: &str = "admitted bounded non-runtime product surface per #1873";
/// Exact production-binary consumer allowlist for the admitted surfaces:
/// `bins/eliot` selects the crate for CLI previews, coverage checks, issuance
/// and isolated restore runs only; `bins/eliot-kernel` selects it for the
/// Kernel-owned governed capture/restore coordination (#959/#960). Any other
/// (or additional) consumer fails this gate.
const ADMITTED_CONSUMERS: [&str; 2] = [
    "eliot: dependencies.eliot-backup",
    "eliot-kernel: dependencies.eliot-backup",
];

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
        "workspace_admission must record the #1873 admitted product-surface state"
    );
    Ok(())
}

#[test]
fn only_the_admitted_preview_consumer_selects_the_crate() -> TestResult {
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
    assert_eq!(
        offenders, ADMITTED_CONSUMERS,
        "production selection of {PACKAGE} must stay exactly the admitted preview consumer"
    );
    Ok(())
}
