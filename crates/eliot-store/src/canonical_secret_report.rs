//! Canonical secret-scan report projection cell.
//!
//! Owns the canonical secret-scan report projection extracted from
//! `crates/eliot-store/src/canonical_store.rs`:
//! `CanonicalSecretScanFinding`, `CanonicalSecretScanReport`, privileged
//! deterministic scan `privileged_secret_scan`, and its direct private
//! `secret_scan_query`/`secret_scan_query_records` seams plus bounded paging
//! constants `SECRET_SCAN_PAGE_SIZE`, `SECRET_SCAN_MAX_RECORDS_PER_TABLE`,
//! `SECRET_SCAN_TABLES`. Validates no raw rows or credential material leave
//! the store boundary; findings expose only `value_fingerprint`
//! (`active_credential_fingerprint_if_exposed` or `Sha256` hex), `secret_kind`
//! (`active_database_credential` or `inspect_secret_bytes` rule), and
//! `active_credential` flag.
//!
//! Architecture: P.6 canonical Store — secret-scan report boundary; A13.2
//! Kernel failure domains — report is a read-only projection, not canonical
//! history/state; A13.8 Integrity — deterministic scan with bounded paging.
//! Implementation: I2.23 — extracted report cell owns only its projection;
//! parent `canonical_store` retains the store, receipt, and transport boundary.
//! Mechanical split from `crates/eliot-store/src/canonical_store.rs` — behavior
//! preserved. This is a read-only report projection with no canonical authority;
//! it is not canonical truth/authority and acquires no write, receipt, or
//! transport authority. Forbidden: capacity/L2/recall/record/cognitive, write
//! authority, provider, Dreamer/Luna/frozen/integrated cells.

use crate::StoreError;
use crate::surreal_server::{ReadySurrealServer, SurrealServerSupervisor};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const SECRET_SCAN_PAGE_SIZE: usize = 50;
const SECRET_SCAN_MAX_RECORDS_PER_TABLE: usize = 10_000;
const SECRET_SCAN_TABLES: &[&str] = &[
    "scope_head",
    "task_contract",
    "source_snapshot",
    "evidence_atom",
    "tool_observation",
    "claim_card",
    "verification_run",
    "failure_fingerprint",
    "write_receipt",
    "memory_transition",
    "canonical_record",
    "trace_span",
    "context_packet_receipt",
    "supports",
    "verified_by",
    "contradicts",
    "supersedes",
    "mentions",
    "belongs_to",
    "produces",
    "invalidated_by",
    "co_change",
    "concept_implemented_by",
    "concept_depends_on",
    "capsule_covers",
    "card_covers",
];

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CanonicalSecretScanFinding {
    pub table: String,
    pub record_ordinal: u64,
    pub value_fingerprint: String,
    pub secret_kind: String,
    pub active_credential: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CanonicalSecretScanReport {
    pub schema_version: String,
    pub scanner_version: String,
    pub complete: bool,
    pub tables_scanned: usize,
    pub records_scanned: u64,
    pub bytes_scanned: u64,
    pub findings: Vec<CanonicalSecretScanFinding>,
}

impl super::CanonicalStore {
    /// Privileged deterministic secret scan over canonical records. Raw rows
    /// and credential material never leave the store boundary.
    pub async fn privileged_secret_scan(&self) -> Result<CanonicalSecretScanReport, StoreError> {
        let supervisor = SurrealServerSupervisor::new(self.config.clone());
        let server = if self.client_set.is_some() {
            None
        } else {
            Some(supervisor.start_or_connect().await?)
        };
        let report_result = async {
            let mut report = CanonicalSecretScanReport {
                schema_version: "eliot-canonical-secret-scan-v1".to_owned(),
                scanner_version: "l14-canonical-secret-scan-v1".to_owned(),
                complete: true,
                tables_scanned: 0,
                records_scanned: 0,
                bytes_scanned: 0,
                findings: Vec::new(),
            };
            for table in SECRET_SCAN_TABLES {
                report.tables_scanned += 1;
                let mut start = 0usize;
                loop {
                    let sql = format!(
                        "SELECT * FROM {table} LIMIT {SECRET_SCAN_PAGE_SIZE} START {start};"
                    );
                    let raw = self.secret_scan_query(server.as_ref(), &sql).await?;
                    let records = secret_scan_query_records(table, &raw)?;
                    if records.is_empty() {
                        break;
                    }
                    for (page_index, record) in records.iter().enumerate() {
                        let bytes = serde_json::to_vec(record)
                            .map_err(|error| StoreError::Decode(error.to_string()))?;
                        report.records_scanned = report.records_scanned.saturating_add(1);
                        report.bytes_scanned = report
                            .bytes_scanned
                            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                        let active_fingerprint =
                            supervisor.active_credential_fingerprint_if_exposed(&bytes)?;
                        let boundary = eliot_types::inspect_secret_bytes(&bytes).err();
                        if active_fingerprint.is_some() || boundary.is_some() {
                            let active_credential = active_fingerprint.is_some();
                            let value_fingerprint = active_fingerprint
                                .unwrap_or_else(|| format!("{:x}", Sha256::digest(&bytes)));
                            report.findings.push(CanonicalSecretScanFinding {
                                table: (*table).to_owned(),
                                record_ordinal: u64::try_from(start.saturating_add(page_index))
                                    .unwrap_or(u64::MAX),
                                value_fingerprint,
                                secret_kind: if active_credential {
                                    "active_database_credential".to_owned()
                                } else {
                                    boundary.map_or_else(
                                        || "unknown".to_owned(),
                                        |violation| violation.rule.as_str().to_owned(),
                                    )
                                },
                                active_credential,
                            });
                        }
                    }
                    start = start.saturating_add(records.len());
                    if records.len() < SECRET_SCAN_PAGE_SIZE {
                        break;
                    }
                    if start >= SECRET_SCAN_MAX_RECORDS_PER_TABLE {
                        report.complete = false;
                        break;
                    }
                }
            }
            Ok::<CanonicalSecretScanReport, StoreError>(report)
        }
        .await;
        if let Some(server) = server {
            let shutdown_result = server.shutdown_if_spawned().await;
            let report = report_result?;
            shutdown_result?;
            Ok(report)
        } else {
            report_result
        }
    }

    async fn secret_scan_query(
        &self,
        transient_server: Option<&ReadySurrealServer>,
        sql: &str,
    ) -> Result<Value, StoreError> {
        let vars = Value::Object(serde_json::Map::new());
        if let Some(client_set) = self.client_set.as_ref() {
            return client_set.execute_admin_sql(sql, vars).await;
        }
        let server = transient_server.ok_or_else(|| {
            StoreError::PolicyViolation(
                "secret scan has neither persistent nor transient admin transport".to_owned(),
            )
        })?;
        server.transport()?.query(sql, vars).await
    }
}

fn secret_scan_query_records(table: &str, raw: &Value) -> Result<Vec<Value>, StoreError> {
    let Value::Array(results) = raw else {
        return Err(StoreError::QueryFailed {
            op: "privileged_secret_scan".to_owned(),
            message: format!("canonical table {table} response was not an array"),
            raw: Value::Null,
        });
    };
    let mut records = Vec::new();
    for result in results {
        if result.get("status").and_then(Value::as_str) == Some("ERR") {
            return Err(StoreError::QueryFailed {
                op: "privileged_secret_scan".to_owned(),
                message: format!("canonical table {table} scan query failed"),
                raw: Value::Null,
            });
        }
        if let Some(values) = result.get("result").and_then(Value::as_array) {
            records.extend(values.iter().cloned());
        }
    }
    Ok(records)
}
