use crate::{StoreError, SurrealStore};
use eliot_types::MigrationRecord;

#[derive(Clone, Debug)]
pub struct CompiledMigration {
    pub migration_id: String,
    pub sql: String,
    pub checksum_blake3: String,
}

impl CompiledMigration {
    pub fn new(migration_id: impl Into<String>, sql: impl Into<String>) -> Self {
        let sql = sql.into();
        let checksum_blake3 = blake3::hash(sql.as_bytes()).to_hex().to_string();
        Self {
            migration_id: migration_id.into(),
            sql,
            checksum_blake3,
        }
    }

    pub fn record(&self, applied: bool) -> MigrationRecord {
        MigrationRecord {
            migration_id: self.migration_id.clone(),
            checksum_blake3: self.checksum_blake3.clone(),
            applied,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MigrationRunner {
    migrations: Vec<CompiledMigration>,
}

impl MigrationRunner {
    pub fn new(migrations: Vec<CompiledMigration>) -> Self {
        Self { migrations }
    }

    pub async fn run_all(&self, store: &SurrealStore) -> Result<Vec<MigrationRecord>, StoreError> {
        let mut records = Vec::with_capacity(self.migrations.len());
        for migration in &self.migrations {
            store
                .apply_migration(&migration.migration_id, &migration.sql)
                .await?;
            records.push(migration.record(true));
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::CompiledMigration;

    #[test]
    fn migration_checksum_is_stable() {
        let first = CompiledMigration::new("001", "DEFINE TABLE health_record SCHEMAFULL;");
        let second = CompiledMigration::new("001", "DEFINE TABLE health_record SCHEMAFULL;");

        assert_eq!(first.checksum_blake3, second.checksum_blake3);
    }
}
