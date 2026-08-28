//! Pure Surreal smoke report/status cell extracted from `crates/eliot-store/src/surreal_store.rs`.
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01 — micro-modular Surreal bridge/status surface, transport-isolated.
//! Implementation: I5.1, I5.9, I5.22 — Surreal bridge status reporting, version-string handling and `ensure_query_ok` validation.
//! Source anchors: `crates/eliot-store/src/surreal_store.rs:14-184` (types, impls, helpers) and `crates/eliot-store/src/surreal_server.rs` (transport boundary, not owned here).
//! Responsibility: `SurrealSmokeReport`, `SurrealSmokeChecks`, `SmokeCheckStatus` with `is_ready`/`to_markdown`, plus `ensure_query_ok` and `version_string` only.
//! Explicit non-ownership: no `SurrealServerSupervisor`/`ReadySurrealServer` lifecycle, process spawn/stop, credential/auth/security, transport/handshake, migration application, provider-port, frozen/Luna/Dreamer handle; not canonical or lifecycle authority (retained in `surreal_store.rs`/`surreal_server.rs`).

#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::Value;

use crate::StoreError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SurrealSmokeReport {
    pub server_started: bool,
    pub version: String,
    pub checks: SurrealSmokeChecks,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SurrealSmokeChecks {
    pub return_query: SmokeCheckStatus,
    pub write_read: SmokeCheckStatus,
    pub cleanup: SmokeCheckStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmokeCheckStatus {
    Pass,
    Fail,
}

impl SurrealSmokeReport {
    pub const fn is_ready(&self) -> bool {
        matches!(self.checks.return_query, SmokeCheckStatus::Pass)
            && matches!(self.checks.write_read, SmokeCheckStatus::Pass)
            && matches!(self.checks.cleanup, SmokeCheckStatus::Pass)
    }

    pub fn to_markdown(&self) -> String {
        format!(
            concat!(
                "# SurrealDB RPC Smoke Report\n\n",
                "- server_started: `{}`\n",
                "- version: `{}`\n",
                "- return_query: `{:?}`\n",
                "- write_read: `{:?}`\n",
                "- cleanup: `{:?}`\n"
            ),
            self.server_started,
            self.version,
            self.checks.return_query,
            self.checks.write_read,
            self.checks.cleanup
        )
    }
}

pub(super) fn ensure_query_ok(op: &str, raw: &Value) -> Result<(), StoreError> {
    let Value::Array(results) = raw else {
        return Err(StoreError::QueryFailed {
            op: op.to_owned(),
            message: "query response was not an array".to_owned(),
            raw: raw.clone(),
        });
    };

    for result in results {
        if result.get("status").and_then(Value::as_str) == Some("ERR") {
            let message = result
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or("SurrealDB query returned ERR")
                .to_owned();
            return Err(StoreError::QueryFailed {
                op: op.to_owned(),
                message,
                raw: raw.clone(),
            });
        }
    }

    Ok(())
}

pub(super) fn version_string(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}
