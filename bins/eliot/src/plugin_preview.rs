#![forbid(unsafe_code)]

//! Plugin/bridge install preview and rollback front door (I3.7).
//!
//! Bins-local composition helper for the `eliot` operator CLI: before any
//! installation attempt it renders the exact required preview fields and
//! preserves a rollback artifact. No admitted target-mutation port exists in
//! this front door (`PLAN_GAP` pending A-06), so the attempt stops after
//! rollback preservation with an honest `NOT_ATTEMPTED` receipt: the targets
//! are left unmodified and no installed success is ever claimed. The Governor integration-record shape is
//! consumed as-is (read-only projection into the preview); this module mints
//! no Governor authority and mutates nothing outside the caller-selected
//! rollback directory plus a single install receipt written there.
//!
//! Required preview fields (I3.7): files to modify, exact config block,
//! installed hooks, registered MCP server, tool/skill count, rollback copy,
//! expected `IntegrationCoverageProfile`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Expected integration coverage consumed as-is from the Governor-side
/// record shape. This struct is a read-only projection; it never writes
/// back to the Governor.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExpectedCoverageProfile {
    /// Integration profile name checked later by
    /// `eliot doctor integration <profile>`.
    pub profile: String,
    /// Expected SHA-256 (lowercase hex) per file path named in
    /// `files_to_modify`.
    #[serde(default)]
    pub expected_file_hashes: BTreeMap<String, String>,
    /// Registrations expected to be active after installation.
    #[serde(default)]
    pub expected_registrations: Vec<String>,
    /// Hook events expected to be observed after installation.
    #[serde(default)]
    pub expected_hook_events: Vec<String>,
}

/// Caller-supplied plugin/bridge install proposal. Deserialized from the
/// `--manifest` JSON file; never inferred from the current directory.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PluginManifest {
    /// Stable plugin/bridge identity (non-empty).
    pub plugin_id: String,
    /// Integration profile name (non-empty).
    pub profile: String,
    /// Files the install would modify (non-empty).
    pub files_to_modify: Vec<String>,
    /// Exact config block the install would write (non-empty).
    pub config_block: String,
    /// Hooks the install would register.
    #[serde(default)]
    pub hooks: Vec<String>,
    /// MCP server registration name (non-empty).
    pub mcp_server: String,
    /// Tool count exposed by the plugin/bridge.
    #[serde(default)]
    pub tool_count: u32,
    /// Skill count exposed by the plugin/bridge.
    #[serde(default)]
    pub skill_count: u32,
    /// Expected coverage consumed as-is from the integration record.
    pub expected_coverage: ExpectedCoverageProfile,
}

/// Rendered preview: every required I3.7 field plus the rollback copy path.
/// No filesystem mutation has happened when this value is produced.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PluginPreview {
    /// Stable plugin/bridge identity.
    pub plugin_id: String,
    /// Integration profile name.
    pub profile: String,
    /// Files the install would modify.
    pub files_to_modify: Vec<String>,
    /// Exact config block the install would write.
    pub config_block: String,
    /// Hooks the install would register.
    pub hooks: Vec<String>,
    /// MCP server registration name.
    pub mcp_server: String,
    /// Tool count.
    pub tool_count: u32,
    /// Skill count.
    pub skill_count: u32,
    /// Rollback copy location preserved before mutation.
    pub rollback_copy: String,
    /// Expected coverage profile (Governor record consumed as-is).
    pub expected_coverage: ExpectedCoverageProfile,
}

/// Typed preview/install failure. All variants are caller-actionable and
/// perform no hidden mutation.
#[derive(Debug, thiserror::Error)]
pub enum PluginPreviewError {
    /// The manifest file could not be read.
    #[error("read plugin manifest {path}: {detail}")]
    ManifestRead {
        /// Manifest path that failed.
        path: String,
        /// Underlying detail.
        detail: String,
    },
    /// The manifest JSON is malformed or violates a field contract.
    #[error("invalid plugin manifest: {0}")]
    ManifestInvalid(String),
    /// The rollback directory or artifact could not be prepared.
    #[error("prepare rollback artifact: {0}")]
    Rollback(String),
    /// The install receipt could not be recorded.
    #[error("record install receipt: {0}")]
    Receipt(String),
    /// The install mutation was not attempted: rollback was preserved, but
    /// no admitted target-mutation port exists in this front door (`PLAN_GAP`
    /// pending A-06 provider injection). Carries the preserved artifact
    /// paths as evidence. Never an installed-success claim: a backup-only
    /// path cannot yield one.
    #[error("install not attempted (PLAN_GAP): {detail}")]
    InstallNotAttempted {
        /// Why no mutation port exists and which owner must admit one.
        detail: String,
        /// Rollback artifact preserved before the refused mutation.
        rollback_artifact: PathBuf,
        /// Honest `NOT_ATTEMPTED` receipt written beside the artifact.
        receipt_path: PathBuf,
    },
}

/// Loads and validates a manifest. The path must be absolute.
pub fn load_manifest(path: &Path) -> Result<PluginManifest, PluginPreviewError> {
    if !path.is_absolute() {
        return Err(PluginPreviewError::ManifestInvalid(
            "manifest path must be absolute".to_owned(),
        ));
    }
    let bytes = std::fs::read(path).map_err(|error| PluginPreviewError::ManifestRead {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    let manifest: PluginManifest = serde_json::from_slice(&bytes)
        .map_err(|error| PluginPreviewError::ManifestInvalid(error.to_string()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &PluginManifest) -> Result<(), PluginPreviewError> {
    if manifest.plugin_id.trim().is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "plugin_id must be non-empty".to_owned(),
        ));
    }
    if manifest.profile.trim().is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "profile must be non-empty".to_owned(),
        ));
    }
    if manifest.files_to_modify.is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "files_to_modify must be non-empty".to_owned(),
        ));
    }
    if manifest.config_block.trim().is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "config_block must be non-empty".to_owned(),
        ));
    }
    if manifest.mcp_server.trim().is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "mcp_server must be non-empty".to_owned(),
        ));
    }
    if manifest.expected_coverage.profile.trim().is_empty() {
        return Err(PluginPreviewError::ManifestInvalid(
            "expected_coverage.profile must be non-empty".to_owned(),
        ));
    }
    // I3.7 binds one installation to one expected IntegrationCoverageProfile,
    // and `integration <profile>` rejects an expectation naming another
    // profile. A manifest whose expected coverage names a different profile
    // than the install would record an incoherent chain: the install receipt
    // could later underpin a live claim for a profile it was never bound to.
    // Reject it here, before any preview or rollback artifact exists.
    if manifest.expected_coverage.profile.trim() != manifest.profile.trim() {
        return Err(PluginPreviewError::ManifestInvalid(
            "expected_coverage.profile must equal profile".to_owned(),
        ));
    }
    Ok(())
}

/// Renders the full preview, binding the rollback copy path without touching
/// the filesystem.
#[must_use]
pub fn render_preview(manifest: &PluginManifest, rollback_dir: &Path) -> PluginPreview {
    let rollback_copy = rollback_dir
        .join(format!("{}.rollback.json", manifest.plugin_id))
        .display()
        .to_string();
    PluginPreview {
        plugin_id: manifest.plugin_id.clone(),
        files_to_modify: manifest.files_to_modify.clone(),
        config_block: manifest.config_block.clone(),
        hooks: manifest.hooks.clone(),
        mcp_server: manifest.mcp_server.clone(),
        tool_count: manifest.tool_count,
        skill_count: manifest.skill_count,
        profile: manifest.profile.clone(),
        rollback_copy,
        expected_coverage: manifest.expected_coverage.clone(),
    }
}

/// Projects the preview to the machine-readable contract JSON. Contains all
/// seven required I3.7 fields.
#[must_use]
pub fn preview_json(preview: &PluginPreview) -> serde_json::Value {
    serde_json::json!({
        "contract": "eliot.plugin.preview",
        "contract_version": "1.0.0",
        "plugin_id": preview.plugin_id,
        "profile": preview.profile,
        "files_to_modify": preview.files_to_modify,
        "config_block": preview.config_block,
        "hooks": preview.hooks,
        "mcp_server": preview.mcp_server,
        "tool_count": preview.tool_count,
        "skill_count": preview.skill_count,
        "rollback_copy": preview.rollback_copy,
        "expected_coverage_profile": preview.expected_coverage,
        "completed": false,
        "note": "preview only; no mutation was attempted",
    })
}

/// Preserves the rollback artifact before any mutation. Creates the rollback
/// directory, copies any already-existing target files beside the artifact
/// (recording per-file `copied`/`absent`/`error`), and writes the
/// `<plugin_id>.rollback.json` artifact. Returns the artifact path.
///
/// Backup copies are numbered by manifest position
/// (`<plugin_id>.<index>.<file_name>.bak`) so two targets sharing a file
/// name never overwrite each other; the artifact's `per_file` map binds
/// every target path to its exact backup.
pub fn ensure_rollback_artifact(
    manifest: &PluginManifest,
    preview: &PluginPreview,
    rollback_dir: &Path,
) -> Result<PathBuf, PluginPreviewError> {
    if !rollback_dir.is_absolute() {
        return Err(PluginPreviewError::Rollback(
            "rollback directory must be absolute".to_owned(),
        ));
    }
    std::fs::create_dir_all(rollback_dir)
        .map_err(|error| PluginPreviewError::Rollback(error.to_string()))?;
    let mut per_file: BTreeMap<String, String> = BTreeMap::new();
    for (index, target) in manifest.files_to_modify.iter().enumerate() {
        let target_path = PathBuf::from(target);
        if !target_path.is_absolute() {
            per_file.insert(target.clone(), "skipped_non_absolute".to_owned());
            continue;
        }
        if !target_path.exists() {
            per_file.insert(target.clone(), "absent".to_owned());
            continue;
        }
        let bytes = match std::fs::read(&target_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                per_file.insert(target.clone(), format!("error:{error}"));
                continue;
            }
        };
        let file_name = target_path.file_name().map_or_else(
            || "file".to_owned(),
            |name| name.to_string_lossy().into_owned(),
        );
        let backup_path = rollback_dir.join(format!(
            "{}.{}.{}.bak",
            manifest.plugin_id, index, file_name
        ));
        match std::fs::write(&backup_path, &bytes) {
            Ok(()) => {
                per_file.insert(target.clone(), backup_path.display().to_string());
            }
            Err(error) => {
                per_file.insert(target.clone(), format!("error:{error}"));
            }
        }
    }
    let artifact_path = PathBuf::from(preview.rollback_copy.clone());
    let artifact = serde_json::json!({
        "contract": "eliot.plugin.rollback",
        "contract_version": "1.0.0",
        "plugin_id": manifest.plugin_id,
        "profile": manifest.profile,
        "preview": preview_json(preview),
        "per_file": per_file,
        "note": "rollback preserved before mutation; restore these bytes to roll back",
    });
    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|error| PluginPreviewError::Rollback(error.to_string()))?;
    std::fs::write(&artifact_path, &bytes)
        .map_err(|error| PluginPreviewError::Rollback(error.to_string()))?;
    Ok(artifact_path)
}

/// Why the install mutation is refused: the exact missing port and the owner
/// that must admit it. Mirrors the admitted `eliot-cli` catalogue, where the
/// install/verify family is `PLAN_GAP` pending A-06 provider injection.
const INSTALL_GAP_DETAIL: &str = "no admitted plugin target-mutation port in this front door (PLAN_GAP pending A-06 provider injection); targets left unmodified. Handoff: plugin install mutation requires a Governor-admitted install effect (owner: Governor application, eliotd #18); registration, hook-event, and handshake observers are likewise absent (see eliot doctor integration UNVERIFIED_PLAN_GAP). Tracker: #1964";

/// Attempts the governed install: renders the preview, preserves the
/// rollback artifact first, then records an honest receipt scoped to the
/// rollback directory. Never modifies the target files themselves.
///
/// No admitted target-mutation port exists in this front door, so the
/// mutation is refused after rollback preservation: this function records an
/// `INSTALL_NOT_ATTEMPTED` receipt and returns
/// [`PluginPreviewError::InstallNotAttempted`]. A backup-only path cannot
/// yield installed success. The `Ok` receipt path is reserved for a future
/// admitted-port mutation, which will hash-read back every target before
/// claiming anything installed.
pub fn install_with_rollback(
    manifest: &PluginManifest,
    rollback_dir: &Path,
) -> Result<PathBuf, PluginPreviewError> {
    let preview = render_preview(manifest, rollback_dir);
    let rollback_artifact = ensure_rollback_artifact(manifest, &preview, rollback_dir)?;
    let receipt_path = rollback_dir.join(format!("{}.installed.json", manifest.plugin_id));
    let receipt = serde_json::json!({
        "contract": "eliot.plugin.install",
        "contract_version": "1.0.0",
        "plugin_id": manifest.plugin_id,
        "profile": manifest.profile,
        "status": "INSTALL_NOT_ATTEMPTED",
        "code": "PLAN_GAP",
        "completed": false,
        "rollback_copy": preview.rollback_copy,
        "preview": preview_json(&preview),
        "detail": INSTALL_GAP_DETAIL,
        "note": "targets unmodified; rollback preserved; no installation occurred",
    });
    let bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|error| PluginPreviewError::Receipt(error.to_string()))?;
    std::fs::write(&receipt_path, &bytes)
        .map_err(|error| PluginPreviewError::Receipt(error.to_string()))?;
    Err(PluginPreviewError::InstallNotAttempted {
        detail: INSTALL_GAP_DETAIL.to_owned(),
        rollback_artifact,
        receipt_path,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "small pure preview tests use explicit fixtures with absolute temp paths"
)]
mod tests {
    use super::*;

    fn fixture_manifest() -> PluginManifest {
        PluginManifest {
            plugin_id: "demo-bridge".to_owned(),
            profile: "demo".to_owned(),
            files_to_modify: vec!["C:\\eliot\\demo\\config.json".to_owned()],
            config_block: "{\"bridge\":\"demo\"}".to_owned(),
            hooks: vec!["on_task".to_owned()],
            mcp_server: "demo-mcp".to_owned(),
            tool_count: 3,
            skill_count: 2,
            expected_coverage: ExpectedCoverageProfile {
                profile: "demo".to_owned(),
                expected_file_hashes: BTreeMap::from([(
                    "C:\\eliot\\demo\\config.json".to_owned(),
                    "ab".repeat(32),
                )]),
                expected_registrations: vec!["demo-mcp".to_owned()],
                expected_hook_events: vec!["on_task".to_owned()],
            },
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("eliot-go19-1964-{tag}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn preview_renders_all_required_fields() {
        let manifest = fixture_manifest();
        let rollback_dir = temp_dir("preview");
        let preview = render_preview(&manifest, &rollback_dir);
        let value = preview_json(&preview);
        for field in [
            "files_to_modify",
            "config_block",
            "hooks",
            "mcp_server",
            "tool_count",
            "skill_count",
            "rollback_copy",
            "expected_coverage_profile",
        ] {
            assert!(value.get(field).is_some(), "preview must carry {field}");
        }
        assert_eq!(value["plugin_id"], "demo-bridge");
        assert_eq!(value["tool_count"], 3);
        assert_eq!(value["skill_count"], 2);
        let _ = std::fs::remove_dir_all(&rollback_dir);
    }

    #[test]
    fn install_preserves_rollback_then_refuses_success() {
        // No admitted mutation port: rollback must exist, but the result is
        // an honest NOT_ATTEMPTED refusal, never installed success.
        let manifest = fixture_manifest();
        let rollback_dir = temp_dir("install");
        let error = install_with_rollback(&manifest, &rollback_dir)
            .expect_err("backup-only path cannot yield installed success");
        let PluginPreviewError::InstallNotAttempted {
            detail,
            rollback_artifact,
            receipt_path,
        } = error
        else {
            panic!("expected InstallNotAttempted, refusal with rollback evidence");
        };
        assert!(detail.contains("PLAN_GAP"));
        assert!(rollback_artifact.exists());
        assert!(receipt_path.exists());
        let receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt_path).expect("read receipt"))
                .expect("parse receipt");
        assert_eq!(receipt["status"], "INSTALL_NOT_ATTEMPTED");
        assert_eq!(receipt["code"], "PLAN_GAP");
        assert_eq!(receipt["completed"], false);
        assert!(receipt.get("preview").is_some());
        assert!(
            receipt
                .get("rollback_copy")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|copy| copy == rollback_artifact.display().to_string())
        );
        let _ = std::fs::remove_dir_all(&rollback_dir);
    }

    #[test]
    fn backup_only_path_yields_no_installed_success() {
        // Regression: whatever the manifest claims, a rollback-only run must
        // never produce an installed-success marker.
        let manifest = fixture_manifest();
        let rollback_dir = temp_dir("install-no-success");
        let error = install_with_rollback(&manifest, &rollback_dir)
            .expect_err("install without an admitted port cannot succeed");
        assert!(matches!(
            error,
            PluginPreviewError::InstallNotAttempted { .. }
        ));
        assert!(!error.to_string().contains("INSTALLED"));
        let _ = std::fs::remove_dir_all(&rollback_dir);
    }

    #[test]
    fn rollback_keeps_same_named_targets_distinct() {
        let root = temp_dir("same-name");
        let first_dir = root.join("a");
        let second_dir = root.join("b");
        std::fs::create_dir_all(&first_dir).expect("create first dir");
        std::fs::create_dir_all(&second_dir).expect("create second dir");
        let first = first_dir.join("config.json");
        let second = second_dir.join("config.json");
        std::fs::write(&first, b"{\"side\":\"a\"}").expect("write first target");
        std::fs::write(&second, b"{\"side\":\"b\"}").expect("write second target");
        let mut manifest = fixture_manifest();
        manifest.files_to_modify = vec![first.display().to_string(), second.display().to_string()];
        let rollback_dir = root.join("rollback");
        let error = install_with_rollback(&manifest, &rollback_dir)
            .expect_err("no admitted port: refusal carries the rollback paths");
        let PluginPreviewError::InstallNotAttempted {
            rollback_artifact, ..
        } = error
        else {
            panic!("expected InstallNotAttempted with rollback evidence");
        };
        assert!(rollback_artifact.exists());
        let artifact: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&rollback_artifact).expect("read rollback artifact"),
        )
        .expect("parse rollback artifact");
        let per_file = artifact.get("per_file").expect("rollback carries per_file");
        let first_backup = per_file
            .get(first.display().to_string())
            .and_then(serde_json::Value::as_str)
            .expect("first target has a backup path");
        let second_backup = per_file
            .get(second.display().to_string())
            .and_then(serde_json::Value::as_str)
            .expect("second target has a backup path");
        assert_ne!(first_backup, second_backup);
        assert_eq!(
            std::fs::read(first_backup).expect("read first backup"),
            b"{\"side\":\"a\"}"
        );
        assert_eq!(
            std::fs::read(second_backup).expect("read second backup"),
            b"{\"side\":\"b\"}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mismatched_expected_coverage_profile_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.expected_coverage.profile = "other".to_owned();
        let error =
            validate_manifest(&manifest).expect_err("cross-profile coverage must not validate");
        assert!(error.to_string().contains("expected_coverage.profile"));
    }

    #[test]
    fn empty_plugin_id_is_rejected() {
        let mut manifest = fixture_manifest();
        manifest.plugin_id = "  ".to_owned();
        assert!(validate_manifest(&manifest).is_err());
    }
}
