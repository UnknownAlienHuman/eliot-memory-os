#![forbid(unsafe_code)]
//! Retired legacy Governor configuration: read-only migration rejector.
//!
//! Issue #1687 (eliot-binary half). The `eliot` binary never adopts
//! `LocalAppData\Eliot\config\governor.toml` as authority. When the OS-known
//! file is present, the binary fails closed with a migration action naming
//! the Kernel canonical surface. When it is absent, the canary/install path
//! proceeds with no legacy config.
//!
//! Field classification (all DELETED, never parsed into authority):
//! - `schema_version` / service identity (`service.service_name`,
//!   `service.instance_id`): deleted. Identity comes from the installation
//!   manifest / Host retention, not the Governor file.
//! - `db` / `db.surreal` (exe, bind, endpoint, storage, ns, db, user,
//!   log/timeout/backoff/capabilities): deleted. Store authority lives in
//!   Kernel/Host (`StoreLaunchConfig` bound to the installation manifest and
//!   the runtime-live Store identity); executable identity comes from the
//!   approved generation manifest, never PATH text.
//! - `store` (`surql_dir`, `migrations_dir`): deleted. Legacy
//!   `crates/eliot-store` paths are owned by #1189; current Store surface is
//!   Kernel/Host-owned.
//! - credential fields (`credential_provider`, `credential_id`,
//!   `password_file`): deleted. Secrets are owner-resolved references, never
//!   adopted from this file here.
//! - `control_wal.path`, `blob_store.root`: deleted (Host-managed roots).
//! - `supervision`, `ul` / `ul.activation`: deleted dead policy (no consumer).
//! - `delegation_calibration`: deleted here; its policy semantics need a
//!   Kernel surface that does not exist yet (handoff to the Kernel owner,
//!   #1687 follow-up). This module does not invent one.
//! - `DbMode`, `CredentialProviderKind`, `ConfigError`, defaults, validators,
//!   collision helpers: deleted with the structs above.
//!
//! No `runtime.toml` exists in-tree; the Appendix C candidate is FORBIDDEN to
//! load or create here (handoff to the Kernel owner).
//!
//! Lifecycle note (not duplicated here):
//! `workstreams/legacy/retirement-1189.toml` owns this file's lifecycle
//! (T7-S1 ledger; final removal is S9 integrator-owned) and #1219 owns the
//! adjacent root `config/` family. This module records disposition only for
//! the #1189 S9 integrator via the draft, it does not mutate that ledger.
//!
//! Design: decode (UTF-8 + case-insensitive legacy-marker scan) -> always
//! reject when present. No TOML crate, no field structs, no adoption.

use std::path::Path;

/// Full migration action emitted when legacy config is present. Names the
/// Kernel canonical surface.
#[must_use]
pub(super) fn migration_action() -> &'static str {
    "Migration action: delete LocalAppData\\Eliot\\config\\governor.toml and configure queue/admission/durable state only through the Kernel canonical configuration surface (Host-managed StoreLaunchConfig bound to the installation manifest / durable transaction store; Governor operates only as outbound-only eliotd polling Kernel). delegation_calibration policy has no Kernel surface yet (handoff to the Kernel owner, #1687 follow-up); no runtime.toml exists in-tree and must not be created or loaded (Appendix C candidate FORBIDDEN). File lifecycle: workstreams/legacy/retirement-1189.toml (T7-S1 ledger, S9 integrator-owned); adjacent root config/: #1219. Remove the legacy file and retry with no legacy config."
}

/// Detects which retired legacy sections/keys a decoded text mentions, in
/// fixed order. Pure marker scan; confers no authority.
#[must_use]
pub(super) fn detect_legacy_markers(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    let mut markers: Vec<&'static str> = Vec::new();
    if lower.contains("schema_version") {
        markers.push("schema_version");
    }
    if lower.contains("[service]")
        || lower.contains("service_name")
        || lower.contains("instance_id")
    {
        markers.push("service identity");
    }
    if lower.contains("[db")
        || lower.contains("surreal")
        || lower.contains("127.0.0.1")
        || lower.contains("rocksdb:")
    {
        markers.push("db/surreal");
    }
    if lower.contains("[store]") || lower.contains("surql_dir") || lower.contains("migrations_dir")
    {
        markers.push("store");
    }
    if lower.contains("credential") || lower.contains("password_file") {
        markers.push("credential");
    }
    if lower.contains("control_wal") {
        markers.push("control_wal");
    }
    if lower.contains("blob_store") || lower.contains("[blob") {
        markers.push("blob_store");
    }
    if lower.contains("[supervision]") || lower.contains("watchdog") {
        markers.push("supervision");
    }
    if lower.contains("delegation_calibration") {
        markers.push("delegation_calibration");
    }
    if lower.contains("[ul") || lower.contains("enable_min_edges") {
        markers.push("ul (dead)");
    }
    markers
}

/// Builds the fail-closed rejection for a present legacy config file. Always
/// names the Kernel canonical surface. Never adopts content as authority.
#[must_use]
pub(super) fn reject_present_legacy_config(path: &Path, bytes: &[u8]) -> String {
    let detail = match std::str::from_utf8(bytes) {
        Ok(text) => {
            let markers = detect_legacy_markers(text);
            let mut detail = if markers.is_empty() {
                "unrecognized legacy content".to_owned()
            } else {
                format!("legacy sections present: {}", markers.join(", "))
            };
            let lower = text.to_ascii_lowercase();
            if lower.contains("127.0.0.1:8000") || lower.contains("ws://127.0.0.1:8000/rpc") {
                detail.push_str("; claims runtime-live store identity");
            }
            detail
        }
        Err(_) => "not UTF-8".to_owned(),
    };
    format!(
        "legacy Governor config at {} is retired and never adopted as authority ({detail}). {}",
        path.display(),
        migration_action()
    )
}

/// Pure gate: absent legacy config proceeds; present legacy config rejects
/// with the Kernel-surface migration action. The OS-observation caller maps
/// `Absent => None` and `Present => Some((path, bytes))`.
pub(super) fn gate_legacy_config_observation(
    present: Option<(&Path, &[u8])>,
) -> Result<(), String> {
    match present {
        None => Ok(()),
        Some((path, bytes)) => Err(reject_present_legacy_config(path, bytes)),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "migration-rejector unit tests assert exact fail-closed shapes with real inputs"
)]
mod tests {
    use super::{gate_legacy_config_observation, reject_present_legacy_config};
    use std::path::Path;

    const LEGACY_PATH: &str = r"C:\Users\test\AppData\Local\Eliot\config\governor.toml";

    #[test]
    fn legacy_store_identity_toml_rejected_naming_kernel_surface() {
        let toml = concat!(
            "schema_version = \"1\"\n",
            "[service]\n",
            "service_name = \"EliotGovernor\"\n",
            "instance_id = \"local-dev\"\n",
            "[db.surreal]\n",
            "bind = \"127.0.0.1:8000\"\n",
            "endpoint = \"ws://127.0.0.1:8000/rpc\"\n",
            "ns = \"eliot\"\n",
        );
        let error = reject_present_legacy_config(Path::new(LEGACY_PATH), toml.as_bytes());
        assert!(
            error.contains("never adopted as authority"),
            "unexpected: {error}"
        );
        assert!(
            error.contains("Kernel"),
            "must name Kernel surface: {error}"
        );
        assert!(
            error.contains("runtime-live store identity"),
            "unexpected: {error}"
        );
        assert!(
            gate_legacy_config_observation(Some((Path::new(LEGACY_PATH), toml.as_bytes())))
                .is_err()
        );
    }

    #[test]
    fn legacy_db_store_calibration_presence_rejected_never_adopted() {
        let toml = concat!(
            "schema_version = \"1\"\n",
            "[db]\n",
            "mode = \"surreal_rpc_server\"\n",
            "[store]\n",
            "surql_dir = \"crates/eliot-store/src/surql\"\n",
            "migrations_dir = \"crates/eliot-store/migrations\"\n",
            "[delegation_calibration]\n",
            "minimum_real_tasks_total = 12\n",
        );
        let error = reject_present_legacy_config(Path::new(LEGACY_PATH), toml.as_bytes());
        for marker in ["db/surreal", "store", "delegation_calibration"] {
            assert!(error.contains(marker), "missing {marker}: {error}");
        }
        assert!(
            error.contains("Kernel"),
            "must name Kernel surface: {error}"
        );
        assert!(
            error.contains("no runtime.toml"),
            "must forbid runtime.toml: {error}"
        );
        // Never adopted: the gate returns Err (no Ok path carries config).
        assert!(
            gate_legacy_config_observation(Some((Path::new(LEGACY_PATH), toml.as_bytes())))
                .is_err()
        );
    }

    #[test]
    fn absent_legacy_config_allows_canary_install_path() {
        assert!(gate_legacy_config_observation(None).is_ok());
    }
}
