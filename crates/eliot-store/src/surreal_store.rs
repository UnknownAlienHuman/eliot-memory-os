use crate::StoreError;
use crate::surreal_server::SurrealServerSupervisor;
use eliot_types::{HealthRecord, SurrealServerConfig};
use serde_json::{Value, json};
use uuid::Uuid;

#[path = "surreal_smoke_report.rs"]
mod surreal_smoke_report;

pub use surreal_smoke_report::{SmokeCheckStatus, SurrealSmokeChecks, SurrealSmokeReport};

use surreal_smoke_report::{ensure_query_ok, version_string};

#[derive(Clone, Debug)]
pub struct SurrealStore {
    config: SurrealServerConfig,
}

impl SurrealStore {
    pub const fn new(config: SurrealServerConfig) -> Self {
        Self { config }
    }

    pub async fn health_check(&self) -> Result<HealthRecord, StoreError> {
        let server = SurrealServerSupervisor::new(self.config.clone())
            .start_or_connect()
            .await?;
        let version_result = server.transport()?.version().await;
        let shutdown_result = server.shutdown_if_spawned().await;
        let version_value = version_result?;
        shutdown_result?;
        let version = version_string(&version_value);

        Ok(HealthRecord {
            component: "surrealdb".to_owned(),
            status: "ready".to_owned(),
            detail: format!("local rpc server version={version}"),
        })
    }

    pub async fn apply_migration(
        &self,
        migration_id: &str,
        sql: &str,
    ) -> Result<HealthRecord, StoreError> {
        let server = SurrealServerSupervisor::new(self.config.clone())
            .start_or_connect()
            .await?;
        let raw_result = server
            .transport()?
            .query(sql, Value::Object(serde_json::Map::new()))
            .await;
        let shutdown_result = server.shutdown_if_spawned().await;
        let raw = raw_result?;
        shutdown_result?;
        ensure_query_ok(migration_id, &raw)?;

        Ok(HealthRecord {
            component: "migration".to_owned(),
            status: "applied".to_owned(),
            detail: migration_id.to_owned(),
        })
    }

    pub async fn smoke(&self) -> Result<SurrealSmokeReport, StoreError> {
        let server = SurrealServerSupervisor::new(self.config.clone())
            .start_or_connect()
            .await?;
        let server_started = server.started_pid().is_some();
        let report_result = async {
            let transport = server.transport()?;
            let version_value = transport.version().await?;
            let version = version_string(&version_value);

            let return_raw = transport
                .query("RETURN 1;", Value::Object(serde_json::Map::new()))
                .await?;
            ensure_query_ok("smoke.return", &return_raw)?;

            let record_id = Uuid::new_v4().to_string();
            let write_read_raw = transport
                .query(
                    "LET $id = type::record('eliot_smoke', $record_id); CREATE $id SET transport = 'rpc', created_at = time::now(); SELECT * FROM $id; DELETE $id;",
                    json!({ "record_id": record_id }),
                )
                .await?;
            ensure_query_ok("smoke.write_read_cleanup", &write_read_raw)?;
            let write_read_ok = write_read_raw.to_string().contains("rpc");

            Ok::<SurrealSmokeReport, StoreError>(SurrealSmokeReport {
                server_started,
                version,
                checks: SurrealSmokeChecks {
                    return_query: SmokeCheckStatus::Pass,
                    write_read: if write_read_ok {
                        SmokeCheckStatus::Pass
                    } else {
                        SmokeCheckStatus::Fail
                    },
                    cleanup: SmokeCheckStatus::Pass,
                },
            })
        }
        .await;
        let shutdown_result = server.shutdown_if_spawned().await;
        let report = report_result?;
        shutdown_result?;
        Ok(report)
    }
}
