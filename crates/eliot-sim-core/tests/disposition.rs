//! Boundary and admission proof for `eliot-sim-core` (issue #1916).
//!
//! The crate owns the pure deterministic simulation boundary, so its
//! admission terms and its dependency Vuforbid must be pinned, not prose:
//! this test reads the manifests and the adapter source to prove that the
//! `[package.metadata.eliot].workspace_admission` disposition is recorded,
//! the crate is a root-workspace member, the manifest carries no
//! dependencies, no excluded framework is named by the manifest, and the
//! adapter boundary constants are actually wired into the crate.

use std::error::Error;
use std::path::PathBuf;

type TestResult<T> = Result<T, Box<dyn Error>>;

const EXPECTED_ADMISSION: &str = "admitted via #1916";
const MEMBER_PATH: &str = "\"crates/eliot-sim-core\"";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> TestResult<PathBuf> {
    let mut dir = manifest_dir();
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            let text = std::fs::read_to_string(&manifest)?;
            if text.contains("[workspace]") && text.contains("members") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            return Err("workspace root not found".into());
        }
    }
}

/// Returns the non-comment entries under one TOML section header.
fn section_entries(text: &str, header: &str) -> Vec<String> {
    let mut entries = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == header;
            continue;
        }
        if inside && !trimmed.is_empty() && !trimmed.starts_with('#') {
            entries.push(trimmed.to_owned());
        }
    }
    entries
}

#[test]
fn owner_disposition_is_recorded() -> TestResult<()> {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    assert!(
        text.contains(EXPECTED_ADMISSION),
        "workspace_admission must record the #1916 admission disposition"
    );
    Ok(())
}

#[test]
fn workspace_membership_is_recorded() -> TestResult<()> {
    let root = workspace_root()?;
    let text = std::fs::read_to_string(root.join("Cargo.toml"))?;
    assert!(
        text.contains(MEMBER_PATH),
        "root workspace members must admit crates/eliot-sim-core"
    );
    Ok(())
}

#[test]
fn manifest_carries_no_dependencies() -> TestResult<()> {
    let text = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    for header in [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
    ] {
        let entries = section_entries(&text, header);
        assert!(
            entries.is_empty(),
            "{header} must stay empty for the pure simulation boundary, found: {entries:?}"
        );
    }
    Ok(())
}

#[test]
fn boundary_claim_is_pinned() -> TestResult<()> {
    assert!(
        !eliot_sim_core::ADAPTER_BOUNDARY_NOTE.is_empty(),
        "adapter boundary note must be present"
    );
    assert!(
        eliot_sim_core::ADAPTER_BOUNDARY_NOTE.contains("outside via adapters"),
        "adapter boundary note must state the outside-via-adapters rule"
    );
    for framework in ["tokio", "wasmtime"] {
        assert!(
            eliot_sim_core::EXCLUDED_FRAMEWORKS.contains(&framework),
            "excluded frameworks must name {framework}"
        );
    }
    let manifest = std::fs::read_to_string(manifest_dir().join("Cargo.toml"))?;
    for framework in ["tokio", "wasmtime", "surrealdb", "reqwest", "axum"] {
        assert!(
            !manifest.contains(framework),
            "manifest must not name excluded framework {framework}"
        );
    }
    let adapters = std::fs::read_to_string(manifest_dir().join("src/adapters.rs"))?;
    assert!(
        adapters.contains("ADAPTER_BOUNDARY_NOTE") && adapters.contains("EXCLUDED_FRAMEWORKS"),
        "adapter boundary constants must be declared in adapters.rs"
    );
    Ok(())
}
