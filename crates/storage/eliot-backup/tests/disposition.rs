//! Explicit-disposition proof for `eliot-backup` (issues #1716/#1873).
//!
//! Disposition (#1716): KEEP with declared reachable owners. The crate is
//! admitted per #1873 and, per #1141, is a live governed portability/recovery
//! consumer of four production binaries: `eliot` (operator previews,
//! issuance and isolated rehearsal), `eliot-host` (backup cutover/config
//! projection), `eliot-kernel` (capture, publication and journaled restore)
//! and `eliot-store-surreal` (the one-shot ECXF/1 export, #1871). Cutover
//! stays with the #960/#961 owners and the crate is not a selectable storage
//! fallback. This test pins the recorded
//! `[package.metadata.eliot].workspace_admission` disposition, the exact
//! production-binary consumer allowlist, and the bound that the crate holds
//! no canonical-database handle: its only store dependency is the
//! store-neutral `eliot-store-api`, so every store access crosses a port the
//! owning binary implements instead of reaching the canonical database
//! directly.

use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const PACKAGE: &str = "eliot-backup";
const EXPECTED_ADMISSION: &str = "admitted bounded non-runtime product surface per #1873";
const EXPECTED_DISPOSITION: &str = "#1716 disposition: KEEP - reachable production owners are exactly bins/eliot, bins/eliot-host, bins/eliot-kernel and bins/eliot-store-surreal";
/// Exact production-binary consumer allowlist. Any other (or additional)
/// consumer fails this gate.
const ADMITTED_CONSUMERS: [&str; 4] = [
    "eliot: dependencies.eliot-backup",
    "eliot-host: dependencies.eliot-backup",
    "eliot-kernel: dependencies.eliot-backup",
    "eliot-store-surreal: dependencies.eliot-backup",
];
/// The only store crate the backup owner may depend on: the store-neutral
/// semantic API. Concrete store adapters and database drivers stay with the
/// binaries that implement the backup ports.
const ADMITTED_STORE_DEPENDENCY: &str = "eliot-store-api";
const DATABASE_DRIVER_MARKERS: [&str; 6] =
    ["surreal", "sqlite", "rocksdb", "redb", "sled", "postgres"];

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
    assert!(
        text.contains(EXPECTED_DISPOSITION),
        "workspace_admission must record the #1716 KEEP disposition and its reachable owners"
    );
    Ok(())
}

#[test]
fn the_crate_holds_no_canonical_database_handle() -> TestResult {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    let value: toml::Value = toml::from_str(&text)?;
    let dependencies = value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or("eliot-backup declares no [dependencies] table")?;
    let mut offenders = Vec::new();
    for (name, spec) in dependencies {
        let package = spec
            .as_table()
            .and_then(|spec| spec.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(name);
        let store_adapter =
            package.starts_with("eliot-store") && package != ADMITTED_STORE_DEPENDENCY;
        let database_driver = DATABASE_DRIVER_MARKERS
            .iter()
            .any(|marker| package.contains(marker));
        if store_adapter || database_driver {
            offenders.push(package.to_owned());
        }
    }
    assert!(
        offenders.is_empty(),
        "{PACKAGE} must reach the store only through {ADMITTED_STORE_DEPENDENCY} ports: {offenders:?}"
    );
    assert!(
        dependencies.contains_key(ADMITTED_STORE_DEPENDENCY),
        "{PACKAGE} store access is bound to the store-neutral {ADMITTED_STORE_DEPENDENCY} contract"
    );
    Ok(())
}

#[test]
fn only_the_admitted_production_owners_select_the_crate() -> TestResult {
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
        "production selection of {PACKAGE} must stay exactly the admitted owners"
    );
    Ok(())
}
