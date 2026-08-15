#![forbid(unsafe_code)]

use eliot_store::{CompiledMigration, MigrationRunner, SurrealSmokeReport, SurrealStore, StoreError};
use eliot_types::{GovernorConfig, HealthRecord, MigrationRecord};
use serde::Serialize;
use std::path::Path;

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "0.17";

const MIGRATIONS: &[(&str, &str)] = &[
    ("000_schema", include_str!("../../../crates/eliot-store/src/surql/000_schema.surql")),
    ("001_observability", include_str!("../../../crates/eliot-store/src/surql/001_observability.surql")),
    ("002_ul_core", include_str!("../../../crates/eliot-store/src/surql/002_ul_core.surql")),
    ("003_ul_delivery", include_str!("../../../crates/eliot-store/src/surql/003_ul_delivery.surql")),
    ("004_ul_artifacts", include_str!("../../../crates/eliot-store/src/surql/004_ul_artifacts.surql")),
    ("005_ul_pyramid", include_str!("../../../crates/eliot-store/src/surql/005_ul_pyramid.surql")),
    ("006_ul_measurement", include_str!("../../../crates/eliot-store/src/surql/006_ul_measurement.surql")),
    ("007_ul_dependency_activation", include_str!("../../../crates/eliot-store/src/surql/007_ul_dependency_activation.surql")),
    ("008_ul_token_policy", include_str!("../../../crates/eliot-store/src/surql/008_ul_token_policy.surql")),
    ("009_memory_search", include_str!("../../../crates/eliot-store/src/surql/009_memory_search.surql")),
    ("010_memory_search_fts", include_str!("../../../crates/eliot-store/src/surql/010_memory_search_fts.surql")),
];

#[derive(Debug)]
pub struct StoreComposition {
    store: SurrealStore,
    migrations: MigrationRunner,
}

impl StoreComposition {
    pub fn new(config: GovernorConfig) -> Result<Self, String> {
        config.validate().map_err(|error| error.to_string())?;
        let migrations = MigrationRunner::new(
            MIGRATIONS
                .iter()
                .map(|(id, sql)| CompiledMigration::new(*id, *sql))
                .collect(),
        );
        Ok(Self {
            store: SurrealStore::new(config.db.surreal),
            migrations,
        })
    }

    pub async fn health(&self) -> Result<HealthRecord, StoreError> {
        self.store.health_check().await
    }

    pub async fn smoke(&self) -> Result<SurrealSmokeReport, StoreError> {
        self.store.smoke().await
    }

    pub async fn migrate(&self) -> Result<Vec<MigrationRecord>, StoreError> {
        self.migrations.run_all(&self.store).await
    }
}

pub fn load_config(path: Option<&Path>) -> Result<GovernorConfig, String> {
    let Some(path) = path else {
        return Ok(GovernorConfig::default());
    };
    let bytes = std::fs::read(path).map_err(|error| format!("read config: {error}"))?;
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => serde_json::from_slice(&bytes).map_err(|error| format!("parse JSON config: {error}")),
        _ => toml::from_slice(&bytes).map_err(|error| format!("parse TOML config: {error}")),
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ready { service: &'static str, protocol: &'static str },
    Health { record: HealthRecord },
    Smoke { report: SurrealSmokeReport },
    Migrated { records: Vec<MigrationRecord> },
    Stopped,
    Error { error: String },
}
