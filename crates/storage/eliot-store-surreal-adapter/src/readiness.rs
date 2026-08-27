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
    use crate::schema;

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

    #[test]
    fn v1_ddl_bytes_are_immutable() {
        let ddl = schema::SCHEMA_DDL;
        assert!(ddl.contains("DEFINE TABLE schema_meta SCHEMALESS;"));
        assert!(ddl.contains("DEFINE TABLE canonical_fence SCHEMALESS;"));
        assert!(!ddl.contains("recovery_owner"));
        assert!(!ddl.contains("recovery_job"));
        let checksum = eliot_store_api::sha256_hex(ddl.as_bytes());
        assert_eq!(checksum, schema::SCHEMA_DDL_V1_SHA256);
        let migration = CompiledMigration::new(
            schema::MIGRATION_ID_V1,
            ddl,
            SchemaGeneration::new(schema::GENERATION_V1).expect("valid"),
        );
        assert_eq!(migration.checksum_sha256(), checksum);
        assert_eq!(migration.checksum_sha256(), schema::SCHEMA_DDL_V1_SHA256);
        assert_eq!(migration.migration_id(), schema::MIGRATION_ID_V1);
        assert_eq!(migration.generation_after().as_str(), schema::GENERATION_V1);
    }

    #[test]
    fn v1_byte_drift_is_detected() {
        let checksum = eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes());
        assert_eq!(checksum, schema::SCHEMA_DDL_V1_SHA256);
        let mut drifted = schema::SCHEMA_DDL.to_owned();
        drifted.push(' ');
        assert_ne!(
            eliot_store_api::sha256_hex(drifted.as_bytes()),
            schema::SCHEMA_DDL_V1_SHA256
        );
        let mut drifted2 = schema::SCHEMA_DDL.to_owned();
        drifted2.push('x');
        assert_ne!(
            eliot_store_api::sha256_hex(drifted2.as_bytes()),
            schema::SCHEMA_DDL_V1_SHA256
        );
    }

    #[test]
    fn v2_baseline_is_additive_and_contains_recovery() {
        let v1 = schema::SCHEMA_DDL.trim();
        let v2 = schema::SCHEMA_DDL_V2;
        let delta = schema::SCHEMA_MIGRATION_V1_TO_V2_DDL;
        assert!(v2.contains(v1));
        assert!(v2.contains(schema::table::RECOVERY_OWNER));
        assert!(v2.contains(schema::table::RECOVERY_JOB));
        assert!(delta.contains(schema::table::RECOVERY_OWNER));
        assert!(delta.contains(schema::table::RECOVERY_JOB));
        assert!(!delta.contains("DEFINE TABLE schema_meta"));
        assert!(v2.contains("DEFINE FIELD namespace ON recovery_owner TYPE string;"));
        assert!(v2.contains("DEFINE FIELD key ON recovery_owner TYPE string;"));
        assert!(v2.contains("DEFINE FIELD state_fence ON recovery_owner TYPE object;"));
        assert!(v2.contains("DEFINE FIELD revision ON recovery_owner TYPE int;"));
        assert!(v2.contains("DEFINE FIELD schema ON recovery_owner TYPE string;"));
        assert!(v2.contains("DEFINE FIELD payload ON recovery_owner TYPE bytes;"));
        assert!(v2.contains("DEFINE FIELD value_digest ON recovery_owner TYPE string;"));
        assert!(v2.contains(
            "DEFINE INDEX ro_namespace_key ON recovery_owner FIELDS namespace, key UNIQUE;"
        ));
        assert!(v2.contains(
            "DEFINE INDEX rj_namespace_key ON recovery_job FIELDS namespace, key UNIQUE;"
        ));
    }

    #[test]
    fn migrations_have_no_destructive_statements() {
        for ddl in [
            schema::SCHEMA_DDL,
            schema::SCHEMA_DDL_V2,
            schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
        ] {
            let lower = ddl.to_ascii_lowercase();
            assert!(!lower.contains("drop "), "ddl must not contain DROP");
            assert!(!lower.contains("delete "), "ddl must not contain DELETE");
            assert!(!lower.contains("remove "), "ddl must not contain REMOVE");
            assert!(!lower.contains("reset"), "ddl must not contain reset");
        }
        let v2 = CompiledMigration::new(
            schema::MIGRATION_ID_V2,
            schema::SCHEMA_DDL_V2,
            SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
        );
        let v1_to_v2 = CompiledMigration::new(
            schema::MIGRATION_ID_V1_TO_V2,
            schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
            SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
        );
        assert_ne!(v2.checksum_sha256(), v1_to_v2.checksum_sha256());
        assert_eq!(v2.generation_after().as_str(), schema::GENERATION_V2);
        assert_eq!(v1_to_v2.generation_after().as_str(), schema::GENERATION_V2);
    }

    #[test]
    fn v2_migrations_are_distinct_from_v1() {
        let v1 = CompiledMigration::new(
            schema::MIGRATION_ID_V1,
            schema::SCHEMA_DDL,
            SchemaGeneration::new(schema::GENERATION_V1).expect("valid"),
        );
        let v2 = CompiledMigration::new(
            schema::MIGRATION_ID_V2,
            schema::SCHEMA_DDL_V2,
            SchemaGeneration::new(schema::GENERATION_V2).expect("valid"),
        );
        assert_ne!(v1.checksum_sha256(), v2.checksum_sha256());
        assert_ne!(v1.migration_id(), v2.migration_id());
        assert_ne!(
            v1.generation_after().as_str(),
            v2.generation_after().as_str()
        );
    }
}
