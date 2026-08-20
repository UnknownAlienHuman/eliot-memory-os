//! Semantic readiness, schema generation and migration.
//!
//! The bridge never migrates implicitly. It observes the database's recorded
//! schema generation against the configured expectation and gates canonical
//! access on a match. Schema changes are applied only through an explicit
//! [`SurrealStoreAdapter::apply_migration`] call issued by the composition owner
//! under migration authority.

use eliot_store_api::sha256_hex;

use crate::config::SchemaGeneration;

/// Observed semantic position of the database relative to the bridge contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticReadiness {
    /// Not probed or provider unreachable.
    Unavailable,
    /// Database is not at the expected schema generation.
    MigrationRequired {
        expected: SchemaGeneration,
        observed: Option<String>,
    },
    /// Database matches the expected schema generation.
    Ready { generation: SchemaGeneration },
}

/// A single explicit, checksummed schema migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledMigration {
    /// Stable migration identity.
    pub(crate) migration_id: String,
    /// `SurrealQL` statements applied inside a transaction.
    pub(crate) statements: String,
    /// SHA-256 checksum of the statements.
    pub(crate) checksum_sha256: String,
    /// Schema generation the database is at after this migration.
    pub(crate) generation_after: SchemaGeneration,
}

impl CompiledMigration {
    /// Builds a migration and derives its stable checksum.
    pub(crate) fn new(
        migration_id: impl Into<String>,
        statements: impl Into<String>,
        generation_after: SchemaGeneration,
    ) -> Self {
        let statements = statements.into();
        let checksum_sha256 = sha256_hex(statements.as_bytes());
        Self {
            migration_id: migration_id.into(),
            statements,
            checksum_sha256,
            generation_after,
        }
    }

    /// Validates the opaque plan identity before provider execution.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.migration_id.trim().is_empty()
            || self.statements.trim().is_empty()
            || self.checksum_sha256 != sha256_hex(self.statements.as_bytes())
        {
            return Err("migration plan identity or checksum is invalid");
        }
        Ok(())
    }

    /// Returns the sealed migration identity without exposing its `SurrealQL`.
    ///
    /// Store-side orchestration may bind an authenticated command to the
    /// compiler-approved identity, while the physical statements remain
    /// private to this adapter crate.
    pub fn migration_id(&self) -> &str {
        &self.migration_id
    }

    /// Returns the compiler-derived lowercase SHA-256 of the migration body.
    #[must_use]
    pub fn checksum_sha256(&self) -> &str {
        &self.checksum_sha256
    }

    /// Returns the schema generation reached by this migration.
    #[must_use]
    pub fn generation_after(&self) -> &SchemaGeneration {
        &self.generation_after
    }
}

/// Durable outcome of one applied migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationReceipt {
    pub migration_id: String,
    pub checksum_sha256: String,
    pub generation_after: SchemaGeneration,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn migration_checksum_is_stable() {
        let generation = SchemaGeneration::new("2.0.0").expect("valid");
        let first = CompiledMigration::new("001", "DEFINE TABLE t SCHEMALESS;", generation.clone());
        let second = CompiledMigration::new("001", "DEFINE TABLE t SCHEMALESS;", generation);
        assert_eq!(first.checksum_sha256, second.checksum_sha256);
        assert_ne!(first.checksum_sha256, "");
    }

    #[test]
    fn readiness_is_comparable() {
        let expected = SchemaGeneration::new("1.0.0").expect("valid");
        let ready = SemanticReadiness::Ready {
            generation: expected.clone(),
        };
        let missing = SemanticReadiness::MigrationRequired {
            expected: expected.clone(),
            observed: None,
        };
        assert_eq!(ready, ready);
        assert_ne!(ready, missing);
    }
}
