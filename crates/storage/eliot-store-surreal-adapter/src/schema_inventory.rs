//! Machine-readable inventory of every schema/migration body and every
//! migration root known to the current Store schema-generation owner
//! (issue #1221, wave A).
//!
//! This module is the single place that answers "is this `SurrealQL` DDL body
//! executable by the current owner?". It publishes the closed, ordered
//! denominators work item W1 names and one fail-closed resolution over them:
//!
//! - [`EMBEDDED_SCHEMA_BODIES`] — every DDL body this owner embeds, each
//!   bound to its migration id, schema generation, predecessor generation,
//!   derived SHA-256 and disposition. The entries marked
//!   [`BodyDisposition::ExecutableGraph`] are the one current executable
//!   migration graph; everything else this owner declares is published as
//!   [`BodyDisposition::DeclaredNotAdmitted`] with the reason it is not
//!   admitted, so no embedded body is silently omitted.
//! - [`NON_EXECUTABLE_MIGRATION_ROOTS`] — every migration root that exists in
//!   the repository but that this owner never executes, each with its
//!   disposition, rationale and named removal condition.
//! - [`MIGRATION_CONSTRUCTORS`] — every constructor that mints a
//!   [`crate::readiness::CompiledMigration`], the exact bodies it builds, and
//!   whether the admission gate resolves its output.
//! - [`MIGRATION_EXECUTORS`] — every code path that applies DDL, including the
//!   second executor that passes caller-supplied SQL straight through.
//! - [`CONFIG_MIGRATION_PATHS`] — every configuration key that could name a
//!   migration directory, with whether current configuration can still select
//!   one.
//! - [`PACKAGE_RELEASE_CONSUMERS`] — every packaging, installation and release
//!   path that reads, stages or refuses a migration root.
//! - [`RESTORE_SCHEMA_DEPENDENCIES`] — every backup/restore path that depends on
//!   the current graph's tables and statements.
//!
//! The first two are derived from the same [`crate::schema`] constants the
//! executor applies. The rest are the executable callers, config keys, package
//! and restore consumers around them: a class is only inventoried if the class
//! names a location that exists. None restates DDL bytes, none names a
//! filesystem location as authority, and no caller can supply a migration
//! directory: repository filename presence is not execution ownership.
//! [`resolve_executable_body`] is the only admission entry point and refuses
//! everything outside the executable set with a typed reason — never a
//! default-allow.
//!
//! Maintenance invariant: every DDL constant declared in [`crate::schema`]
//! must appear in exactly one inventory entry. Rust cannot reflect over
//! `const`s, so no compile-time link exists between the two lists; a body
//! added to [`crate::schema`] without an entry here is the silent omission
//! this module exists to prevent.
//!
//! The same invariant is enforced against the legacy roots at run time, not by
//! a list: [`census_legacy_schema_objects`] reads the declared legacy DDL bytes
//! and [`validate_legacy_table_mapping`] compares that census against
//! [`LEGACY_TABLE_MAPPINGS`] in both directions. Because the expected set comes
//! from the legacy bytes rather than from the roster or from any caller, a
//! legacy table, index or field nobody mapped is a refusal, and so is a row
//! naming an object the legacy DDL no longer declares. The mapping runs as a
//! gate on the migration admission path, because the declared legacy roots may
//! leave the tree only once the mapping closes.

use std::fmt;

use eliot_store_api::sha256_hex;

use crate::schema;

/// The one current Store schema-generation owner.
///
/// Bound to this crate's own `Cargo.toml` package name, so the published
/// owner identity cannot drift from the crate that actually owns the
/// executable graph.
pub(crate) const CURRENT_MIGRATION_OWNER: &str = env!("CARGO_PKG_NAME");

/// Disposition of one embedded DDL body inside the current owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyDisposition {
    /// Member of the one current executable migration graph: an explicit,
    /// admission-checked migration the current owner may apply.
    ExecutableGraph,
    /// Declared by the current owner but not admitted by the executable
    /// graph. Published with its reason so a body that exists but is not
    /// applied is a stated fact rather than a silent omission.
    DeclaredNotAdmitted,
}

/// Disposition of one migration root the current owner does not execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootDisposition {
    /// A legacy pre-split migration/schema root whose bytes are still owned
    /// by the legacy core, pending that owner's retirement.
    LegacyRoot,
}

/// One embedded DDL body owned by the current Store schema owner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EmbeddedSchemaBody {
    /// Name of the owning `crate::schema` constant holding the exact bytes.
    pub(crate) const_name: &'static str,
    /// Stable migration identity, absent for an assembled or unattributed
    /// body that no migration plan may claim.
    pub(crate) migration_id: Option<&'static str>,
    /// Schema generation the body reaches, absent when the body belongs to
    /// no admitted generation.
    pub(crate) generation: Option<&'static str>,
    /// Schema generation the body requires as its predecessor, absent for a
    /// fresh-database baseline.
    pub(crate) predecessor_generation: Option<&'static str>,
    /// The exact DDL bytes. Derived, never restated elsewhere.
    pub(crate) ddl: &'static str,
    /// Executable-graph membership.
    pub(crate) disposition: BodyDisposition,
    /// Why this body holds this disposition.
    pub(crate) note: &'static str,
    /// Committed digest the body is pinned to, where the bytes are a
    /// published immutability anchor and byte drift must fail closed.
    pub(crate) pinned_sha256: Option<&'static str>,
}

impl EmbeddedSchemaBody {
    /// SHA-256 of the exact DDL bytes, derived from the same constant the
    /// executor applies. Uses the crate's existing store-API digest helper;
    /// this module adds no second hashing mechanism.
    pub(crate) fn body_sha256(&self) -> String {
        sha256_hex(self.ddl.as_bytes())
    }
}

/// Every DDL body the current owner embeds, in canonical migration-graph
/// order: the executable graph first (v1 baseline, the v1-to-v2 additive
/// delta, the v2 fresh-database baseline), then the bodies this owner
/// declares but does not admit.
pub(crate) static EMBEDDED_SCHEMA_BODIES: [EmbeddedSchemaBody; 11] = [
    EmbeddedSchemaBody {
        const_name: "SCHEMA_DDL",
        migration_id: Some(schema::MIGRATION_ID_V1),
        generation: Some(schema::GENERATION_V1),
        predecessor_generation: None,
        ddl: schema::SCHEMA_DDL,
        disposition: BodyDisposition::ExecutableGraph,
        note: "first-generation baseline; applied only through an explicit admitted migration and pinned to its committed digest",
        pinned_sha256: Some(schema::SCHEMA_DDL_V1_SHA256),
    },
    EmbeddedSchemaBody {
        const_name: "SCHEMA_MIGRATION_V1_TO_V2_DDL",
        migration_id: Some(schema::MIGRATION_ID_V1_TO_V2),
        generation: Some(schema::GENERATION_V2),
        predecessor_generation: Some(schema::GENERATION_V1),
        ddl: schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
        disposition: BodyDisposition::ExecutableGraph,
        note: "additive v1-to-v2 delta; the same bytes as the RECOVERY_TABLES_DDL body it aliases",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "SCHEMA_DDL_V2",
        migration_id: Some(schema::MIGRATION_ID_V2),
        generation: Some(schema::GENERATION_V2),
        predecessor_generation: None,
        ddl: schema::SCHEMA_DDL_V2,
        disposition: BodyDisposition::ExecutableGraph,
        note: "second-generation fresh-database baseline; the only plan an empty database admits",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "SCHEMA_MIGRATION_V2_TO_V3_DDL",
        migration_id: Some(schema::MIGRATION_ID_V2_TO_V3),
        generation: Some(schema::GENERATION_V3),
        predecessor_generation: Some(schema::GENERATION_V2),
        ddl: schema::SCHEMA_MIGRATION_V2_TO_V3_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "additive erasure-table delta; the same bytes as the ERASURE_TABLES_DDL body it aliases; declared for the v2-to-v3 step but no current admission resolves it, so the closed ordered graph of issue #1221 wave B must admit or retire it",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "SCHEMA_DDL_V3",
        migration_id: None,
        generation: Some(schema::GENERATION_V3),
        predecessor_generation: None,
        ddl: schema::SCHEMA_DDL_V3,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "assembled third-generation baseline carrying no migration id; read only to census the table set of the v3 generation, never applied as a migration plan",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "NOTIFICATION_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::NOTIFICATION_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "index-bearing notification body; the notification_record table is created by the closed notification ensure-tables operation, so this body is declared but has no migration identity",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "REACTIVE_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::REACTIVE_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "index-bearing reactive body; the reactive_session and resource_snapshot tables are created by the closed reactive ensure-tables operation, so this body is declared but has no migration identity",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "AUTOMATION_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::AUTOMATION_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "index-bearing automation body; the automation tables are created by the closed automation ensure-tables operation, so this body is declared but has no migration identity",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "EXPERIENCE_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::EXPERIENCE_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "experience body; the experience_bank and experience_feedback tables are created by the closed experience ensure-tables operation, so this body is declared but has no migration identity",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "LEARNING_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::LEARNING_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "learning body; the learning_record table is created by the closed learning ensure-tables operation, so this body is declared but has no migration identity",
        pinned_sha256: None,
    },
    EmbeddedSchemaBody {
        const_name: "ORIENTATION_OWNER_SOURCE_TABLES_DDL",
        migration_id: None,
        generation: None,
        predecessor_generation: None,
        ddl: schema::ORIENTATION_OWNER_SOURCE_TABLES_DDL,
        disposition: BodyDisposition::DeclaredNotAdmitted,
        note: "the campaign_source table is created only by the closed Orientation owner-source publication operation and has no migration identity",
        pinned_sha256: None,
    },
];

/// One migration root that exists in the repository and that the current
/// owner never executes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NonExecutableRoot {
    /// Repository path of the root exactly as it exists in the tree.
    pub(crate) path: &'static str,
    /// Stable identity of the root for refusal reporting.
    pub(crate) identity: &'static str,
    /// What the root is retained as.
    pub(crate) disposition: RootDisposition,
    /// Why the current owner does not execute it, with the disposition
    /// source it is recorded from.
    pub(crate) rationale: &'static str,
    /// The named condition under which the root leaves the tree.
    pub(crate) removal_condition: &'static str,
}

/// Every migration root the current owner declares non-executable.
///
/// The orphan root `migrations/0001_bootstrap.surql` is absent: issue #1221
/// acceptance A3 permits retaining it only as an explicitly named
/// non-executable fixture with a current consumer and a removal condition, the
/// owner's own record stated `consumers_found = 0`, and no current consumer
/// exists, so the retained branch could not be made true and the body is
/// deleted. It is recoverable from Git history at the commit that removed it.
///
/// The remaining rows are the legacy roots recorded from
/// `workstreams/storage/assignments/1221-schema-migration-owner.toml`
/// `current_source`. The legacy bodies are still owned by the legacy core and
/// still resolved by legacy app code, so this owner records their disposition
/// and removal condition rather than removing them.
pub(crate) static NON_EXECUTABLE_MIGRATION_ROOTS: [NonExecutableRoot; 2] = [
    NonExecutableRoot {
        path: "crates/eliot-store/migrations",
        identity: "eliot.surql.legacy-root.migrations",
        disposition: RootDisposition::LegacyRoot,
        rationale: "pre-split canonical schema root still owned by the legacy core; no current configuration key selects it (the legacy store.migrations_dir key is deleted under issue #1221 work item W4) and only legacy app/engine code still resolves it, and it is retired by the legacy core retirement issue #1189 — the current owner records the disposition and never executes it",
        removal_condition: "removed from current config, launch, packaging and restore only after the complete table-by-table mapping closes under issue #1221 wave D and the legacy core retirement issue #1189",
    },
    NonExecutableRoot {
        path: "crates/eliot-store/src/surql",
        identity: "eliot.surql.legacy-root.src-surql",
        disposition: RootDisposition::LegacyRoot,
        rationale: "pre-split named-operation SurrealQL root compiled into the legacy store facade through include_str!; owned by the legacy core, mapped to current capability owners under issue #1221, and never executable by the current owner",
        removal_condition: "removed from current config, launch, packaging and restore only after the complete table-by-table mapping closes under issue #1221 wave D and the legacy core retirement issue #1189",
    },
];

// -- Adjacent classes (issue #1221 work item W1) ---------------------------
//
// The two tables above record what a DDL body and a migration root *are*. They
// do not record the rest of the world that can reach them, and an owner asking
// "can a current config, launch, packaging or restore path select or execute a
// legacy migration root?" cannot answer it from bodies and roots alone. The
// five classes below are that missing world, each one a typed entry with its own
// producer, and each one checked on the admission path by
// [`validate_adjacent_classes`]:
//
// - [`MIGRATION_CONSTRUCTORS`] — every constructor that mints a migration plan.
//   The three adapter constructors build published bodies; the legacy
//   `CompiledMigration::new` mints whatever statement text its caller supplies.
//   The check proves every admitted body has a constructor and no constructor
//   names a body this owner does not publish.
// - [`MIGRATION_EXECUTORS`] — every path that applies DDL. The current owner's
//   `apply_migration` resolves the published graph; the legacy
//   `MigrationRunner::run_all` -> `SurrealStore::apply_migration` pair passes
//   caller-supplied SQL straight to the provider. The check refuses a
//   constructor or executor the current owner does not admit, so the second
//   executor is a stated fact at the gate rather than an unrecorded one.
// - [`CONFIG_MIGRATION_PATHS`] — every configuration key that could name a
//   migration directory. The check proves a *current* key selects only a
//   declared non-executable root, so no current configuration can select a
//   body or an undeclared root.
// - [`PACKAGE_RELEASE_CONSUMERS`] — every packaging, installation and release
//   path that reads, stages or refuses a migration root. The check proves a
//   staging consumer stages only a declared non-executable root.
// - [`RESTORE_SCHEMA_DEPENDENCIES`] — every backup/restore path that depends on
//   the current graph. The check compares the tables those modules name against
//   the owner's own `crate::schema::table::ALL_TABLES` denominator in both
//   directions, and proves every generation they pin is a published one, so a
//   restore path cannot depend on a table or generation this owner does not
//   declare.
//
// Every declared non-executable root must additionally be named by at least one
// recorded config path or packaging consumer. That is the closure that makes
// the record complete: a root nobody can reach and nobody stages has no
// recorded consumer, which is the orphan shape issue #1221 acceptance A3
// refuses, and a root that is reachable but undeclared is the second-executable-
// root shape the same acceptance refuses.

/// Whether the current owner admits one recorded location as a path to the
/// executable migration graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessDisposition {
    /// The current owner's own path: it reaches DDL only through
    /// [`resolve_executable_body`].
    OwnerAdmitted,
    /// A path that exists in the repository and that the current owner never
    /// executes. Recorded with its reason so the class is a stated fact rather
    /// than a silent omission.
    LegacyNotAdmitted,
}

impl fmt::Display for AccessDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerAdmitted => {
                write!(formatter, "admitted by the current schema owner")
            }
            Self::LegacyNotAdmitted => {
                write!(formatter, "not admitted by the current schema owner")
            }
        }
    }
}

/// The statement text one migration executor can be handed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutorInput {
    /// The executor resolves the published executable graph first, so arbitrary
    /// caller SQL is not a possible input.
    PublishedGraph,
    /// The executor applies whatever statement text its caller supplies, with no
    /// graph resolution in front of it. This is the "arbitrary raw SQL
    /// execution" issue #1221 names as a thing to eliminate, recorded as the
    /// second migration executor it is.
    CallerSuppliedSql,
}

/// The state of one configuration key that could name a migration directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigKeyState {
    /// The key exists in current configuration.
    Current,
    /// The key is deleted; `deny_unknown_fields` refuses a document that still
    /// carries it rather than defaulting it silently.
    Deleted,
}

/// What one packaging or release consumer does with a migration root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackagingAction {
    /// The consumer copies a root into an installed runtime and can therefore
    /// make it selectable.
    StagesDirectory,
    /// The consumer refuses a root: it is a prohibition, so it may name a path
    /// that no longer exists in the tree.
    RefusesDirectory,
}

/// One constructor that mints a migration plan for the current owner to admit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MigrationConstructor {
    /// `path.rs::symbol` of the constructor.
    pub(crate) location: &'static str,
    /// The `crate::schema` constants the constructor can build a plan from.
    pub(crate) builds: &'static [&'static str],
    /// Whether the current owner admits the constructor.
    pub(crate) disposition: AccessDisposition,
    /// Why the constructor holds this disposition.
    pub(crate) note: &'static str,
}

/// One path that applies DDL.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MigrationExecutor {
    /// `path.rs::symbol` of the executor.
    pub(crate) location: &'static str,
    /// The statement text the executor can be handed.
    pub(crate) input: ExecutorInput,
    /// Whether the current owner admits the executor.
    pub(crate) disposition: AccessDisposition,
    /// Why the executor holds this disposition.
    pub(crate) note: &'static str,
}

/// One configuration key that could name a migration directory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConfigMigrationPath {
    /// The exact configuration key, as the configuration document spells it.
    pub(crate) key: &'static str,
    /// The default the key carries in current configuration, or the value it
    /// carried before it was deleted.
    pub(crate) default_value: &'static str,
    /// Whether current configuration still carries the key.
    pub(crate) state: ConfigKeyState,
    /// The non-executable root the key selects, for a key that selects one. A
    /// `Current` key names one; a `Deleted` key records the root it used to
    /// name so the root's own closure check has a counterexample to fail on.
    pub(crate) selects_root: Option<&'static str>,
    /// Why the key holds this state.
    pub(crate) note: &'static str,
}

/// One packaging, installation or release consumer of a migration root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackageReleaseConsumer {
    /// `path.rs::symbol`, or the script path for a non-Rust consumer.
    pub(crate) location: &'static str,
    /// Whether the consumer stages the root or refuses it.
    pub(crate) action: PackagingAction,
    /// The root path the consumer reads, stages or refuses.
    pub(crate) root: &'static str,
    /// Why the current owner records this consumer.
    pub(crate) note: &'static str,
}

/// One backup/restore path that depends on the current graph.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RestoreSchemaDependency {
    /// `path.rs::symbol` of the module.
    pub(crate) location: &'static str,
    /// Every physical table the module names, taken from the owner's own
    /// `crate::schema::table` constants rather than restated, and compared in
    /// both directions against the owner's own `ALL_TABLES` denominator.
    pub(crate) tables: &'static [&'static str],
    /// Every generation the module pins, taken from the owner's own
    /// `crate::schema` constants. Empty for a module that reads no baseline
    /// DDL.
    pub(crate) pinned_generations: &'static [&'static str],
    /// Why the current owner records this dependency.
    pub(crate) note: &'static str,
}

/// Every migration constructor the current owner records.
///
/// The three `SurrealStoreAdapter` constructors are the current owner's own and
/// admit through [`resolve_executable_body`]. The legacy
/// `crates/eliot-store/src/migration.rs::CompiledMigration::new` is recorded
/// because it exists and mints a plan from caller text; the legacy
/// `crates/eliot-store/src/readiness.rs` `CompiledMigration::new` is the same
/// minting point as the three adapter constructors and is therefore not a
/// separate row.
pub(crate) static MIGRATION_CONSTRUCTORS: [MigrationConstructor; 4] = [
    MigrationConstructor {
        location: "crates/storage/eliot-store-surreal-adapter/src/lib.rs::SurrealStoreAdapter::initial_schema_migration",
        builds: &["SCHEMA_DDL", "SCHEMA_DDL_V2"],
        disposition: AccessDisposition::OwnerAdmitted,
        note: "builds the fresh-database baseline plan from the published first-generation or second-generation constant, and the admission gate resolves the result",
    },
    MigrationConstructor {
        location: "crates/storage/eliot-store-surreal-adapter/src/lib.rs::SurrealStoreAdapter::v1_to_v2_migration",
        builds: &["SCHEMA_MIGRATION_V1_TO_V2_DDL"],
        disposition: AccessDisposition::OwnerAdmitted,
        note: "builds the additive v1-to-v2 plan from the published delta constant, and the admission gate resolves the result",
    },
    MigrationConstructor {
        location: "crates/storage/eliot-store-surreal-adapter/src/lib.rs::SurrealStoreAdapter::v2_baseline_migration",
        builds: &["SCHEMA_DDL_V2"],
        disposition: AccessDisposition::OwnerAdmitted,
        note: "builds the second-generation baseline plan; the only plan an empty database admits",
    },
    MigrationConstructor {
        location: "crates/eliot-store/src/migration.rs::CompiledMigration::new",
        builds: &[],
        disposition: AccessDisposition::LegacyNotAdmitted,
        note: "legacy constructor: it hashes and stores whatever statement text its caller supplies, so it mints a plan from no published body and the current owner admits none of its output",
    },
];

/// Every migration executor the current owner records.
pub(crate) static MIGRATION_EXECUTORS: [MigrationExecutor; 3] = [
    MigrationExecutor {
        location: "crates/storage/eliot-store-surreal-adapter/src/apply.rs::apply_migration",
        input: ExecutorInput::PublishedGraph,
        disposition: AccessDisposition::OwnerAdmitted,
        note: "the one current executor: it runs the durable intent, then admit_migration resolves the plan against the published executable graph before any DDL reaches the provider",
    },
    MigrationExecutor {
        location: "crates/eliot-store/src/migration.rs::MigrationRunner::run_all",
        input: ExecutorInput::CallerSuppliedSql,
        disposition: AccessDisposition::LegacyNotAdmitted,
        note: "second migration executor: it iterates a caller-supplied plan list and hands each plan's own statement text to the legacy store, with no graph resolution in front of it",
    },
    MigrationExecutor {
        location: "crates/eliot-store/src/surreal_store.rs::SurrealStore::apply_migration",
        input: ExecutorInput::CallerSuppliedSql,
        disposition: AccessDisposition::LegacyNotAdmitted,
        note: "the sink that actually issues the caller-supplied statement text as one provider query; the raw-SQL execution the issue assigns to eliminate, recorded so the class is not silent",
    },
];

/// Every configuration key that could name a migration directory.
pub(crate) static CONFIG_MIGRATION_PATHS: [ConfigMigrationPath; 2] = [
    ConfigMigrationPath {
        key: "store.surql_dir",
        default_value: "crates/eliot-store/src/surql",
        state: ConfigKeyState::Current,
        selects_root: Some("crates/eliot-store/src/surql"),
        note: "the only current configuration key that names a schema directory; it selects the legacy named-operation root, which this owner declares non-executable and never executes, and the current adapter resolves nothing from it",
    },
    ConfigMigrationPath {
        key: "store.migrations_dir",
        default_value: "crates/eliot-store/migrations",
        state: ConfigKeyState::Deleted,
        selects_root: Some("crates/eliot-store/migrations"),
        note: "deleted under issue #1221 work item W4; StoreConfig is deny_unknown_fields, so a document that still carries the key is refused rather than defaulted, and current configuration can no longer select a migration root",
    },
];

/// Every packaging, installation or release consumer of a migration root.
pub(crate) static PACKAGE_RELEASE_CONSUMERS: [PackageReleaseConsumer; 2] = [
    PackageReleaseConsumer {
        location: "crates/eliot-app/src/commands/operations.rs::daemon_init_default",
        action: PackagingAction::StagesDirectory,
        root: "crates/eliot-store/src/surql",
        note: "the installed-default packaging path: it resolves config.store.surql_dir, copies the whole legacy .surql tree into <eliot_home>/resources/surql with copy_resource_tree, and writes the copied path back into the installed config, so it stages a root this owner declares non-executable",
    },
    PackageReleaseConsumer {
        location: "scripts/build-eliot-windows-x64-release.ps1",
        action: PackagingAction::RefusesDirectory,
        root: "migrations",
        note: "the release packaging check: the staged payload manifest must list the wholesale config and migrations roots as exclusions and a release bundle containing either directory is rejected, so the root migration directory cannot enter a release. The directory itself left the tree when issue #1221 acceptance A3 deleted its only member, and the prohibition is recorded so a future root migration file cannot be staged by a release unnoticed",
    },
];

/// Every backup/restore path that depends on the current graph.
pub(crate) static RESTORE_SCHEMA_DEPENDENCIES: [RestoreSchemaDependency; 4] = [
    RestoreSchemaDependency {
        location: "crates/storage/eliot-store-surreal-adapter/src/backup_restore.rs",
        tables: &[
            schema::table::CANONICAL_EVENT,
            schema::table::ORDERING_HEAD,
            schema::table::OUTBOX_EVENT,
            schema::table::PROJECTION_RECORD,
            schema::table::RELATION_RECORD,
            schema::table::REVISION_HEAD,
            schema::table::WRITE_RECEIPT,
        ],
        pinned_generations: &[],
        note: "restore/import carrier: it reads and writes the current graph's canonical tables and the current revision/ordering statement constants, and names no migration root",
    },
    RestoreSchemaDependency {
        location: "crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs",
        tables: &[
            schema::table::AUTOMATION_CONTINUATION,
            schema::table::AUTOMATION_CURRENT,
            schema::table::AUTOMATION_FAILURE,
            schema::table::AUTOMATION_INVOCATION,
            schema::table::AUTOMATION_LAST_FAILURE,
            schema::table::AUTOMATION_REVISION,
            schema::table::CAMPAIGN_SOURCE,
            schema::table::CANONICAL_EVENT,
            schema::table::CANONICAL_FENCE,
            schema::table::ERASURE_INTENT,
            schema::table::ERASURE_OUTCOME,
            schema::table::EXPERIENCE_BANK,
            schema::table::EXPERIENCE_FEEDBACK,
            schema::table::INSTRUMENT_REGISTRY,
            schema::table::LEARNING_RECORD,
            schema::table::NOTIFICATION_RECORD,
            schema::table::ORDERING_HEAD,
            schema::table::OUTBOX_EVENT,
            schema::table::PROJECTION_RECORD,
            schema::table::REACTIVE_SESSION,
            schema::table::RECOVERY_JOB,
            schema::table::RECOVERY_OWNER,
            schema::table::RELATION_RECORD,
            schema::table::RESOURCE_SNAPSHOT,
            schema::table::REVISION_HEAD,
            schema::table::SCHEMA_META,
            schema::table::WRITE_RECEIPT,
        ],
        pinned_generations: &[schema::GENERATION_V2, schema::GENERATION_V3],
        note: "snapshot carrier: it walks the owner's own ALL_TABLES denominator and classifies each table against the baseline DDL of the generation the adapter itself admits",
    },
    RestoreSchemaDependency {
        location: "crates/storage/eliot-store-surreal-adapter/src/client/backup_restore.rs",
        tables: &[schema::table::RECOVERY_JOB],
        pinned_generations: &[],
        note: "the restore provider contour: it reads and writes the current recovery_job table and the current revision statement constants, and names no migration root",
    },
    RestoreSchemaDependency {
        location: "crates/storage/eliot-store-surreal-adapter/src/client/backup_snapshot.rs",
        tables: &[],
        pinned_generations: &[],
        note: "the snapshot provider contour: it issues only the current transaction and genesis-read statement constants, so it names no table and no baseline DDL",
    },
];

/// One of the five adjacent classes, for refusal reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdjacentClass {
    /// A constructor that mints a migration plan.
    MigrationConstructor,
    /// A path that applies DDL.
    MigrationExecutor,
    /// A configuration key that could name a migration directory.
    ConfigMigrationPath,
    /// A packaging, installation or release consumer of a migration root.
    PackageReleaseConsumer,
    /// A backup/restore path that depends on the current graph.
    RestoreSchemaDependency,
}

impl fmt::Display for AdjacentClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::MigrationConstructor => "migration constructor",
            Self::MigrationExecutor => "migration executor",
            Self::ConfigMigrationPath => "configuration migration path",
            Self::PackageReleaseConsumer => "package/release consumer",
            Self::RestoreSchemaDependency => "restore schema dependency",
        };
        write!(formatter, "{class}")
    }
}

/// Why the adjacent-class record does not close.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdjacentClassOmission {
    /// Two adjacent rows claim the same location, so one of them is
    /// unreachable in the refusal resolution.
    DuplicateLocation {
        /// The location claimed twice.
        location: &'static str,
    },
    /// A constructor builds a body this owner does not publish.
    ConstructorBuildsUndeclaredBody {
        /// The constructor.
        location: &'static str,
        /// The `crate::schema` constant it names.
        const_name: &'static str,
    },
    /// An admitted body has no constructor, so no current plan can carry it.
    AdmittedBodyWithoutConstructor {
        /// The `crate::schema` constant with no constructor.
        const_name: &'static str,
    },
    /// A current configuration key selects a root this owner does not declare
    /// non-executable, so current configuration can select something the
    /// inventory cannot answer for.
    CurrentConfigPathSelectsUndeclaredRoot {
        /// The configuration key.
        key: &'static str,
        /// The root it selects.
        root: &'static str,
    },
    /// A packaging consumer stages a root this owner does not declare
    /// non-executable.
    PackagedRootNotDeclared {
        /// The consumer.
        location: &'static str,
        /// The root it stages.
        root: &'static str,
    },
    /// A declared non-executable root that no recorded configuration path and
    /// no recorded packaging consumer names: the orphan shape, with no
    /// discovered consumer.
    RootWithoutRecordedConsumer {
        /// The unclaimed root.
        path: &'static str,
    },
    /// A restore path depends on a table this owner does not declare.
    RestoreDependencyNamesUndeclaredTable {
        /// The restore module.
        location: &'static str,
        /// The physical table it names.
        table: &'static str,
    },
    /// A table this owner declares that no recorded restore path depends on, so
    /// the restore record does not cover the current graph.
    RestoreDependencyMissesTable {
        /// The uncovered physical table.
        table: &'static str,
    },
    /// A restore path pins a generation this owner does not publish.
    RestoreDependencyPinsUndeclaredGeneration {
        /// The restore module.
        location: &'static str,
        /// The generation constant it pins.
        generation: &'static str,
    },
    /// An executor the current owner admits that can still be handed
    /// caller-supplied SQL, which is the second executable root the closed
    /// ordered graph forbids.
    AdmittedExecutorAcceptsCallerSql {
        /// The executor.
        location: &'static str,
    },
}

impl fmt::Display for AdjacentClassOmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateLocation { location } => {
                write!(formatter, "{location} has more than one adjacent-class row")
            }
            Self::ConstructorBuildsUndeclaredBody {
                location,
                const_name,
            } => write!(
                formatter,
                "the migration constructor {location} builds {const_name}, which the current owner does not publish"
            ),
            Self::AdmittedBodyWithoutConstructor { const_name } => write!(
                formatter,
                "the admitted body {const_name} has no migration constructor, so no current plan can carry it"
            ),
            Self::CurrentConfigPathSelectsUndeclaredRoot { key, root } => write!(
                formatter,
                "the current configuration key {key} selects {root}, which is not a declared non-executable root"
            ),
            Self::PackagedRootNotDeclared { location, root } => write!(
                formatter,
                "the packaging consumer {location} stages {root}, which is not a declared non-executable root"
            ),
            Self::RootWithoutRecordedConsumer { path } => write!(
                formatter,
                "the non-executable root {path} is named by no recorded configuration path and no recorded packaging consumer"
            ),
            Self::RestoreDependencyNamesUndeclaredTable { location, table } => write!(
                formatter,
                "the restore path {location} depends on {table}, which the current owner does not declare"
            ),
            Self::RestoreDependencyMissesTable { table } => write!(
                formatter,
                "the current table {table} is named by no recorded restore path, so the restore record does not cover the current graph"
            ),
            Self::RestoreDependencyPinsUndeclaredGeneration {
                location,
                generation,
            } => write!(
                formatter,
                "the restore path {location} pins {generation}, which the current owner does not publish"
            ),
            Self::AdmittedExecutorAcceptsCallerSql { location } => write!(
                formatter,
                "the migration executor {location} is admitted by the current owner but can still be handed caller-supplied SQL"
            ),
        }
    }
}

/// Fails closed unless the adjacent-class record closes over the current graph.
///
/// Every check compares a recorded class against a denominator the current owner
/// already publishes — the executable bodies, the declared non-executable roots,
/// the `ALL_TABLES` table list and the published generations — so an omission is
/// visible without trusting the roster itself:
///
/// - a location is claimed by at most one row;
/// - a constructor builds only published bodies, and every admitted body has a
///   constructor;
/// - no executor the current owner admits can be handed caller-supplied SQL;
/// - a current configuration key selects only a declared non-executable root;
/// - a packaging consumer stages only a declared non-executable root;
/// - every declared non-executable root is named by some recorded configuration
///   path or packaging consumer;
/// - a restore path names only declared tables and pins only published
///   generations, and every declared table is named by some restore path.
///
/// The result is a typed [`AdjacentClassOmission`]. It runs on the same
/// admission path as [`validate_legacy_table_mapping`], because an incomplete
/// record of who can reach a migration root must close before a migration is
/// applied, not after.
pub(crate) fn validate_adjacent_classes() -> Result<(), AdjacentClassOmission> {
    validate_adjacent_locations()?;
    validate_adjacent_bodies()?;
    validate_adjacent_access()?;
    validate_adjacent_roots()?;
    validate_adjacent_restore_dependencies()
}

/// Whether some recorded configuration path or packaging consumer names this
/// declared non-executable root.
///
/// A retained root with no recorded consumer is the orphan shape `A3` names: a
/// body the owner still classifies but nothing can reach. Both adjacent classes
/// that can select a root are consulted, so a consumer recorded in either place
/// discharges the check.
fn root_has_recorded_consumer(root: &'static str) -> bool {
    CONFIG_MIGRATION_PATHS
        .iter()
        .any(|path| path.selects_root == Some(root))
        || PACKAGE_RELEASE_CONSUMERS
            .iter()
            .any(|consumer| consumer.root == root)
}

/// Refuses when one source location is claimed by two adjacent-class rows.
fn validate_adjacent_locations() -> Result<(), AdjacentClassOmission> {
    let mut claimed: Vec<&'static str> = Vec::new();
    for location in MIGRATION_CONSTRUCTORS
        .iter()
        .map(|row| row.location)
        .chain(MIGRATION_EXECUTORS.iter().map(|row| row.location))
        .chain(CONFIG_MIGRATION_PATHS.iter().map(|row| row.key))
        .chain(PACKAGE_RELEASE_CONSUMERS.iter().map(|row| row.location))
        .chain(RESTORE_SCHEMA_DEPENDENCIES.iter().map(|row| row.location))
    {
        if claimed.contains(&location) {
            return Err(AdjacentClassOmission::DuplicateLocation { location });
        }
        claimed.push(location);
    }
    Ok(())
}

/// Cross-checks the constructor rows against the executable bodies in both
/// directions, so neither an undeclared body nor an unconstructed admitted body
/// can sit in the record unnoticed.
fn validate_adjacent_bodies() -> Result<(), AdjacentClassOmission> {
    for constructor in &MIGRATION_CONSTRUCTORS {
        for const_name in constructor.builds {
            if embedded_body_by_const_name(const_name).is_none() {
                return Err(AdjacentClassOmission::ConstructorBuildsUndeclaredBody {
                    location: constructor.location,
                    const_name,
                });
            }
        }
    }
    for body in EMBEDDED_SCHEMA_BODIES
        .iter()
        .filter(|body| body.disposition == BodyDisposition::ExecutableGraph)
    {
        if !MIGRATION_CONSTRUCTORS.iter().any(|constructor| {
            constructor.disposition == AccessDisposition::OwnerAdmitted
                && constructor.builds.contains(&body.const_name)
        }) {
            return Err(AdjacentClassOmission::AdmittedBodyWithoutConstructor {
                const_name: body.const_name,
            });
        }
    }
    Ok(())
}

/// Refuses when an owner-admitted executor can be handed caller-supplied SQL,
/// and when a current configuration key or a packaging consumer selects a root
/// the owner never declared.
fn validate_adjacent_access() -> Result<(), AdjacentClassOmission> {
    for path in CONFIG_MIGRATION_PATHS {
        if path.state == ConfigKeyState::Current
            && non_executable_root_for(path.default_value).is_none()
        {
            return Err(
                AdjacentClassOmission::CurrentConfigPathSelectsUndeclaredRoot {
                    key: path.key,
                    root: path.default_value,
                },
            );
        }
    }
    for executor in &MIGRATION_EXECUTORS {
        if executor.disposition == AccessDisposition::OwnerAdmitted
            && executor.input == ExecutorInput::CallerSuppliedSql
        {
            return Err(AdjacentClassOmission::AdmittedExecutorAcceptsCallerSql {
                location: executor.location,
            });
        }
    }
    Ok(())
}

/// Refuses a declared non-executable root that no recorded configuration path or
/// packaging consumer names, and a packaging consumer staging an undeclared one.
fn validate_adjacent_roots() -> Result<(), AdjacentClassOmission> {
    for consumer in &PACKAGE_RELEASE_CONSUMERS {
        if consumer.action == PackagingAction::StagesDirectory
            && non_executable_root_for(consumer.root).is_none()
        {
            return Err(AdjacentClassOmission::PackagedRootNotDeclared {
                location: consumer.location,
                root: consumer.root,
            });
        }
    }
    for root in &NON_EXECUTABLE_MIGRATION_ROOTS {
        if !root_has_recorded_consumer(root.path) {
            return Err(AdjacentClassOmission::RootWithoutRecordedConsumer { path: root.path });
        }
    }
    Ok(())
}

/// Cross-checks the restore-path rows against the owner's own table list and
/// published generations in both directions.
fn validate_adjacent_restore_dependencies() -> Result<(), AdjacentClassOmission> {
    for dependency in &RESTORE_SCHEMA_DEPENDENCIES {
        for table in dependency.tables {
            if !schema::table::ALL_TABLES.contains(table) {
                return Err(
                    AdjacentClassOmission::RestoreDependencyNamesUndeclaredTable {
                        location: dependency.location,
                        table,
                    },
                );
            }
        }
        for generation in dependency.pinned_generations {
            if !EMBEDDED_SCHEMA_BODIES
                .iter()
                .any(|body| body.generation == Some(generation))
            {
                return Err(
                    AdjacentClassOmission::RestoreDependencyPinsUndeclaredGeneration {
                        location: dependency.location,
                        generation,
                    },
                );
            }
        }
    }
    for table in schema::table::ALL_TABLES {
        if !RESTORE_SCHEMA_DEPENDENCIES
            .iter()
            .any(|dependency| dependency.tables.contains(&table))
        {
            return Err(AdjacentClassOmission::RestoreDependencyMissesTable { table });
        }
    }
    Ok(())
}

/// Returns the embedded body a `crate::schema` constant name publishes.
fn embedded_body_by_const_name(const_name: &str) -> Option<&'static EmbeddedSchemaBody> {
    EMBEDDED_SCHEMA_BODIES
        .iter()
        .find(|body| body.const_name == const_name)
}

/// Typed reason a presented body is not executable by the current owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExecutableBodyRefusal {
    /// The presented identity is neither a current embedded body nor a
    /// declared non-executable root.
    UnknownIdentity {
        /// The identity that was presented.
        identity: String,
    },
    /// The presented identity names a body this owner declares, but the
    /// executable migration graph does not admit it.
    DeclaredNotAdmitted {
        /// Name of the owning DDL constant.
        const_name: &'static str,
        /// Why the body is not admitted.
        note: &'static str,
    },
    /// The presented identity names a migration root the current owner
    /// declares non-executable: the root's recorded identity, its exact
    /// repository path, or a path beneath its directory prefix (see
    /// [`non_executable_root_for`]).
    NonExecutableRoot {
        /// Repository path of the root.
        path: &'static str,
        /// What the root is retained as.
        disposition: RootDisposition,
        /// Why the current owner does not execute it.
        rationale: &'static str,
        /// The named condition under which the root leaves the tree.
        removal_condition: &'static str,
    },
    /// The presented identity names a legacy table, which has a stated
    /// disposition but is never an executable migration body.
    LegacyTableNotExecutable {
        /// The legacy table that was presented.
        table: &'static str,
        /// What the current owner does with that table.
        disposition: LegacyTableDisposition,
    },
    /// The presented identity names a recorded location of one of the five
    /// adjacent classes — a migration constructor, a migration executor, a
    /// configuration migration path, a package/release consumer or a restore
    /// schema dependency — rather than a DDL body. Each of those locations is
    /// inventoried (see [`validate_adjacent_classes`]) with the disposition the
    /// current owner holds for it, and none of them is an executable body.
    NotAnAdjacentBody {
        /// The recorded location that was presented.
        location: &'static str,
        /// Which of the five adjacent classes the location belongs to.
        class: AdjacentClass,
        /// Whether the current owner admits that location.
        disposition: AccessDisposition,
        /// Why the location holds this disposition.
        note: &'static str,
    },
    /// The adjacent-class record does not close over the current graph, so the
    /// inventory cannot answer which configuration, launch, packaging or restore
    /// path can reach a migration root. Checked before any body is resolved
    /// (see [`validate_adjacent_classes`]).
    AdjacentClassRecordIncomplete {
        /// Why the record does not close.
        omission: AdjacentClassOmission,
    },
    /// The presented statements differ from the current bytes published for
    /// that migration id.
    BodyBytesDiffer {
        /// Migration identity whose bytes are fixed.
        migration_id: &'static str,
    },
    /// The presented checksum is not the digest of the current published
    /// bytes.
    BodyDigestDiffer {
        /// Migration identity whose digest is fixed.
        migration_id: &'static str,
    },
    /// The presented target generation is not the generation the current
    /// body reaches.
    GenerationDiffer {
        /// Migration identity whose target generation is fixed.
        migration_id: &'static str,
        /// Generation the current body reaches, absent when it reaches none.
        current_generation: Option<&'static str>,
    },
    /// The published bytes of a pinned body drifted from their committed
    /// digest.
    PinnedBodyDrift {
        /// Migration identity whose bytes are pinned.
        migration_id: &'static str,
        /// The committed digest the body is pinned to.
        pinned_sha256: &'static str,
    },
}

impl fmt::Display for ExecutableBodyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIdentity { identity } => {
                write!(formatter, "unknown identity {identity}")
            }
            Self::DeclaredNotAdmitted { const_name, note } => {
                write!(formatter, "{const_name} is not admitted: {note}")
            }
            Self::NonExecutableRoot {
                path,
                disposition,
                rationale,
                removal_condition,
            } => {
                let disposition = match disposition {
                    RootDisposition::LegacyRoot => "legacy root",
                };
                write!(
                    formatter,
                    "{path} is a {disposition}: {rationale} Removal condition: {removal_condition}"
                )
            }
            Self::LegacyTableNotExecutable { table, disposition } => {
                let disposition = match disposition {
                    LegacyTableDisposition::Transform {
                        capability_owner,
                        current_table,
                        transform,
                    } => format!(
                        "an explicit transform into {current_table} owned by {capability_owner}: {transform}"
                    ),
                    LegacyTableDisposition::ArchiveOnly { rationale } => {
                        format!("an archive-only disposition: {rationale}")
                    }
                };
                write!(
                    formatter,
                    "legacy table {table} carries {disposition} and is not an executable migration body"
                )
            }
            Self::NotAnAdjacentBody {
                location,
                class,
                disposition,
                note,
            } => {
                write!(
                    formatter,
                    "{location} is a recorded {class} that is {disposition}: {note}"
                )
            }
            Self::AdjacentClassRecordIncomplete { omission } => {
                write!(
                    formatter,
                    "the recorded constructor, executor, configuration, packaging and restore classes do not close: {omission}"
                )
            }
            Self::BodyBytesDiffer { migration_id } => {
                write!(
                    formatter,
                    "{migration_id} bytes differ from the published body"
                )
            }
            Self::BodyDigestDiffer { migration_id } => {
                write!(
                    formatter,
                    "{migration_id} digest differs from the published body"
                )
            }
            Self::GenerationDiffer {
                migration_id,
                current_generation,
            } => {
                let current = current_generation.unwrap_or("none");
                write!(
                    formatter,
                    "{migration_id} targets a generation other than {current}"
                )
            }
            Self::PinnedBodyDrift {
                migration_id,
                pinned_sha256,
            } => {
                write!(
                    formatter,
                    "{migration_id} drifted from its pinned digest {pinned_sha256}"
                )
            }
        }
    }
}

/// Returns the embedded body published for a migration identity.
fn embedded_body_by_migration_id(identity: &str) -> Option<&'static EmbeddedSchemaBody> {
    EMBEDDED_SCHEMA_BODIES
        .iter()
        .find(|body| body.migration_id == Some(identity))
}

/// Returns the schema generation the current owner requires the named
/// migration to migrate *from*, or `None` for a fresh-database baseline and
/// for any identity outside the published executable graph.
pub(crate) fn required_predecessor_generation(migration_id: &str) -> Option<&'static str> {
    embedded_body_by_migration_id(migration_id)?.predecessor_generation
}

/// Returns the exact migration identity the named migration must follow.
///
/// Derived from the published executable graph rather than restated: the
/// predecessor is the unique admitted node that reaches the generation this
/// node migrates *from*. A fresh-database baseline has no predecessor, and an
/// identity outside the graph has none either, so a caller cannot name a
/// predecessor of its own choosing.
pub(crate) fn required_predecessor_migration_id(migration_id: &str) -> Option<&'static str> {
    let predecessor_generation = required_predecessor_generation(migration_id)?;
    EMBEDDED_SCHEMA_BODIES
        .iter()
        .find(|candidate| {
            candidate.disposition == BodyDisposition::ExecutableGraph
                && candidate.generation == Some(predecessor_generation)
        })
        .and_then(|candidate| candidate.migration_id)
}

// -- Legacy schema mapping (issue #1221 work item W3, acceptance A4) --------
//
// Every legacy table, index and field of the two declared legacy migration
// roots is mapped to a current capability owner, an explicit transform, or an
// archive-only disposition with a deletion rationale. The expected set is
// *derived from the legacy bytes themselves* by [`census_legacy_schema_objects`]
// and compared against [`LEGACY_TABLE_MAPPINGS`] in both directions, so a
// legacy object with no row, and a row naming an object the legacy DDL no
// longer declares, both fail closed. Nothing here trusts a list a caller
// supplies and nothing here is a second inventory: this is the same current
// owner, reading the roots it already declares non-executable in
// [`NON_EXECUTABLE_MIGRATION_ROOTS`].

/// One legacy migration root whose schema the current owner censuses.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacySchemaRoot {
    /// Repository path of the root, matching its
    /// [`NON_EXECUTABLE_MIGRATION_ROOTS`] entry.
    pub(crate) path: &'static str,
    /// The exact legacy DDL bytes, read for censusing only. This owner never
    /// executes them and never admits them.
    pub(crate) ddl: &'static str,
}

/// The declared legacy roots whose DDL declares schema objects.
///
/// Every schema-defining legacy body is listed. The remaining files of the
/// named-operation root declare no `DEFINE` statement, so including them could
/// not change the census; a file that later gains one is added here and the
/// census then fails closed until its objects are mapped.
pub(crate) static LEGACY_SCHEMA_ROOTS: [LegacySchemaRoot; 12] = [
    LegacySchemaRoot {
        path: "crates/eliot-store/migrations/000_schema.surql",
        ddl: include_str!("../../../eliot-store/migrations/000_schema.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/000_schema.surql",
        ddl: include_str!("../../../eliot-store/src/surql/000_schema.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/001_observability.surql",
        ddl: include_str!("../../../eliot-store/src/surql/001_observability.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/002_ul_core.surql",
        ddl: include_str!("../../../eliot-store/src/surql/002_ul_core.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/003_ul_delivery.surql",
        ddl: include_str!("../../../eliot-store/src/surql/003_ul_delivery.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/004_ul_artifacts.surql",
        ddl: include_str!("../../../eliot-store/src/surql/004_ul_artifacts.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/005_ul_pyramid.surql",
        ddl: include_str!("../../../eliot-store/src/surql/005_ul_pyramid.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/006_ul_measurement.surql",
        ddl: include_str!("../../../eliot-store/src/surql/006_ul_measurement.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/007_ul_dependency_activation.surql",
        ddl: include_str!("../../../eliot-store/src/surql/007_ul_dependency_activation.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/008_ul_token_policy.surql",
        ddl: include_str!("../../../eliot-store/src/surql/008_ul_token_policy.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/009_memory_search.surql",
        ddl: include_str!("../../../eliot-store/src/surql/009_memory_search.surql"),
    },
    LegacySchemaRoot {
        path: "crates/eliot-store/src/surql/010_memory_search_fts.surql",
        ddl: include_str!("../../../eliot-store/src/surql/010_memory_search_fts.surql"),
    },
];

/// One schema object the legacy roots actually declare.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacySchemaObject {
    /// The `DEFINE` keyword that declared it: `TABLE`, `INDEX` or `FIELD`.
    pub(crate) keyword: &'static str,
    /// Lowercased declared object name.
    pub(crate) name: String,
    /// Lowercased owning table; equal to `name` for a `TABLE` object.
    pub(crate) table: String,
    /// Repository path of the legacy root that declared it, so an omission
    /// names the file an operator must map rather than only the object.
    pub(crate) root: &'static str,
}

/// The `DEFINE INDEX` census keyword.
///
/// An index carries a name independent of its table, so it is the one object
/// kind checked against the per-table index list rather than only against the
/// table's own existence.
const LEGACY_INDEX_KEYWORD: &str = "INDEX";

/// Reads every schema object the declared legacy roots declare.
///
/// The expected set for the coverage check is derived here from the legacy DDL
/// bytes, so it is independent of [`LEGACY_TABLE_MAPPINGS`]: a legacy object
/// nobody mapped is visible, and a mapped object the legacy DDL does not
/// declare is stale. Fields are censused the same way as tables and indexes;
/// the legacy roots declare no `DEFINE FIELD` because every legacy table is
/// `SCHEMALESS`, and the census proves that rather than assuming it.
#[must_use]
pub(crate) fn census_legacy_schema_objects() -> Vec<LegacySchemaObject> {
    let mut census: Vec<LegacySchemaObject> = Vec::new();
    for root in &LEGACY_SCHEMA_ROOTS {
        for statement in root.ddl.split(';') {
            let tokens: Vec<&str> = statement.split_whitespace().collect();
            if !tokens
                .first()
                .is_some_and(|token| token.eq_ignore_ascii_case("DEFINE"))
            {
                continue;
            }
            let Some(keyword) = tokens.get(1) else {
                continue;
            };
            let keyword: &'static str = match keyword.to_ascii_uppercase().as_str() {
                "TABLE" => "TABLE",
                "INDEX" => LEGACY_INDEX_KEYWORD,
                "FIELD" => "FIELD",
                _ => continue,
            };
            let Some(name) = declared_name(&tokens) else {
                continue;
            };
            let table = if keyword == "TABLE" {
                name.clone()
            } else {
                let Some(table) = table_after_on(&tokens) else {
                    continue;
                };
                table
            };
            push_census_object(&mut census, root.path, keyword, &name, &table);
        }
    }
    census
}

/// Appends one census object unless the same object is already censused.
///
/// The legacy roots declare the same table and index in more than one file;
/// the denominator is the set of distinct objects, not the number of
/// `DEFINE` statements. The first root that declares an object is the one
/// reported, so the message is stable.
fn push_census_object(
    census: &mut Vec<LegacySchemaObject>,
    root: &'static str,
    keyword: &'static str,
    name: &str,
    table: &str,
) {
    let object = LegacySchemaObject {
        keyword,
        name: name.to_owned(),
        table: table.to_owned(),
        root,
    };
    if !census.contains(&object) {
        census.push(object);
    }
}

/// Returns the declared object name, skipping the `IF NOT EXISTS` and
/// `OVERWRITE` modifiers the legacy roots use.
fn declared_name(tokens: &[&str]) -> Option<String> {
    let mut index = 2;
    if tokens
        .get(index)
        .is_some_and(|token| token.eq_ignore_ascii_case("IF"))
        && tokens
            .get(index + 1)
            .is_some_and(|token| token.eq_ignore_ascii_case("NOT"))
        && tokens
            .get(index + 2)
            .is_some_and(|token| token.eq_ignore_ascii_case("EXISTS"))
    {
        index += 3;
    } else if tokens
        .get(index)
        .is_some_and(|token| token.eq_ignore_ascii_case("OVERWRITE"))
    {
        index += 1;
    }
    tokens.get(index).map(|token| token.to_ascii_lowercase())
}

/// Returns the owning table named after the `ON` keyword, tolerating the
/// `ON TABLE` spelling the legacy roots use for indexes.
fn table_after_on(tokens: &[&str]) -> Option<String> {
    let on = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("ON"))?;
    let mut next = on + 1;
    if tokens
        .get(next)
        .is_some_and(|token| token.eq_ignore_ascii_case("TABLE"))
    {
        next += 1;
    }
    tokens.get(next).map(|token| token.to_ascii_lowercase())
}

/// What the current capability does with one legacy table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyTableDisposition {
    /// A current capability owner carries the capability and the named
    /// transform states exactly how a legacy row becomes a current row. The
    /// legacy indexes are not carried: the current table publishes its own.
    Transform {
        /// The current owner that carries the capability.
        capability_owner: &'static str,
        /// The current table the legacy table's capability now lives in.
        current_table: &'static str,
        /// The exact transform, stated so no step is implied.
        transform: &'static str,
    },
    /// No current capability owner writes this table. The rows are retained
    /// read-only so restore and import can still verify their provenance under
    /// `A13.7`/`ARCH-RES-03`. The condition that removes the table is the
    /// removal condition of the root in [`NON_EXECUTABLE_MIGRATION_ROOTS`],
    /// stated once per root rather than restated per row.
    ArchiveOnly {
        /// Why the rows are retained rather than carried forward.
        rationale: &'static str,
    },
}

/// One legacy table and every disposition the current owner states for it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacyTableMapping {
    /// Lowercased legacy table name.
    pub(crate) table: &'static str,
    /// Every legacy index the census finds on this table, compared by name in
    /// both directions. An index added to or removed from the legacy DDL
    /// without a row change fails the coverage check.
    pub(crate) indexes: &'static [&'static str],
    /// What the current capability does with the table.
    pub(crate) disposition: LegacyTableDisposition,
}

/// Rationale shared by every legacy table no current capability owner writes.
///
/// The legacy domain tables belong to the pre-split `eliot-store` core. The
/// canonical Store publishes no table for them, so the rows are archived rather
/// than silently dropped: `A13.7` restore verifies provenance and
/// `ARCH-RES-03` forbids resurrecting invalid state, which a drop would do.
/// Removal is not this issue's to perform; the legacy core retirement issue
/// `#1189` owns it and must first complete donor retirement P1–P5, which is the
/// removal condition stated on the roots in [`NON_EXECUTABLE_MIGRATION_ROOTS`].
const LEGACY_DOMAIN_ARCHIVE_RATIONALE: &str = "pre-split eliot-store domain table; the canonical Store publishes no current table for this capability, so the rows are retained read-only for restore/import provenance verification under A13.7 and ARCH-RES-03 rather than dropped or migrated under a guessed shape";

/// Every legacy table the declared roots define, with its current owner,
/// explicit transform, or archive-only rationale — and, for each, the complete
/// set of legacy indexes the census finds on it.
pub(crate) static LEGACY_TABLE_MAPPINGS: [LegacyTableMapping; 45] = [
    LegacyTableMapping {
        table: "activation_trace",
        indexes: &["idx_ul_activation_scope"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "belongs_to",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "canonical_record",
        indexes: &[
            "idx_canonical_memory_manifest",
            "idx_canonical_memory_parent_segment",
            "idx_canonical_project_kind",
            "idx_canonical_project_subject",
            "idx_canonical_project_task_candidate_action",
            "idx_canonical_project_task_kind",
            "idx_canonical_project_task_trace",
            "idx_canonical_write",
            "idx_ul_artifact_path",
            "idx_ul_build_target",
            "idx_ul_capsule_concept",
            "idx_ul_concept_name",
            "idx_ul_mining_identity",
        ],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "canonical_event",
            transform: "one legacy canonical_record row becomes one canonical_event row plus its projection_record publications; the legacy project-scoped (project_id, receipt_kind) lookup is replaced by the current event_id and publication_id identities, so no legacy index is carried",
        },
    },
    LegacyTableMapping {
        table: "capsule_covers",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "card_covers",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "claim_card",
        indexes: &["idx_claim_project", "idx_claim_status", "idx_claim_write"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "co_change",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "cognitive_projection_cutover",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "cognitive_projection_state",
        indexes: &["idx_cognitive_projection_state_project_family_v1"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "concept_depends_on",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "concept_implemented_by",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "context_packet_receipt",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "contradicts",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "cue_index",
        indexes: &["idx_cue_lookup", "idx_cue_record"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "evidence_atom",
        indexes: &["idx_evidence_project", "idx_evidence_write"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "exam_record",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "failure_fingerprint",
        indexes: &["idx_failure_project"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "injection_receipt",
        indexes: &["idx_injection_session", "idx_injection_write"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "invalidated_by",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "memory_grant_offer",
        indexes: &[
            "idx_memory_grant_offer_id",
            "idx_memory_grant_offer_scope",
            "idx_memory_grant_offer_write",
        ],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "memory_influence_trace",
        indexes: &["idx_influence_task", "idx_influence_write"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "memory_search_outbox",
        indexes: &[
            "idx_cognitive_projection_outbox_claim_v1",
            "idx_memory_search_outbox_project_status_revision",
            "idx_memory_search_outbox_write",
        ],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "memory_search_projection",
        indexes: &[
            "idx_memory_search_projection_fts_v1",
            "idx_memory_search_projection_handle",
            "idx_memory_search_projection_lifecycle_kind_revision",
            "idx_memory_search_projection_parent_segment",
        ],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "memory_search_state",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "memory_transition",
        indexes: &["idx_transition_project"],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "canonical_event",
            transform: "one legacy memory transition becomes one canonical_event row; the legacy project_id sequence becomes the current OrderingScopeId sequence and the legacy per-project sequence index is not carried",
        },
    },
    LegacyTableMapping {
        table: "mentions",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "observability_receipt",
        indexes: &[
            "idx_observability_receipt_kind",
            "idx_observability_receipt_write",
        ],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "prediction_record",
        indexes: &[
            "idx_prediction_write",
            "idx_ul_prediction_scope",
            "idx_ul_prediction_verifier",
        ],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "produces",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "scope_head",
        indexes: &["idx_scope_head_project"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "source_snapshot",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "supersedes",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "supports",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "task_contract",
        indexes: &["idx_task_contract_project", "idx_task_contract_status"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "tool_observation",
        indexes: &["idx_tool_observation_project_task_kind_pattern"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "trace_span",
        indexes: &[],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_ab_counter",
        indexes: &["idx_ul_ab_counter"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_artifact_dirty",
        indexes: &["idx_ul_dirty_state", "idx_ul_dirty_target"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_dep_reverse_index",
        indexes: &["idx_ul_dep_reverse", "idx_ul_dep_target"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_task_class_policy",
        indexes: &["idx_ul_policy_class"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_task_experiment",
        indexes: &["idx_ul_experiment_class", "idx_ul_experiment_task"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "ul_task_ledger",
        indexes: &["idx_ul_task_ledger_project_task"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "verification_run",
        indexes: &["idx_verification_project", "idx_verification_result"],
        disposition: LegacyTableDisposition::ArchiveOnly {
            rationale: LEGACY_DOMAIN_ARCHIVE_RATIONALE,
        },
    },
    LegacyTableMapping {
        table: "verified_by",
        indexes: &[],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "relation_record",
            transform: "one legacy relation edge becomes one relation_record row whose relation_id is derived from the legacy edge triple; the legacy per-relation table name is not carried",
        },
    },
    LegacyTableMapping {
        table: "write_receipt",
        indexes: &[
            "idx_receipt_project",
            "idx_receipt_sequence",
            "idx_receipt_write",
        ],
        disposition: LegacyTableDisposition::Transform {
            capability_owner: CURRENT_MIGRATION_OWNER,
            current_table: "write_receipt",
            transform: "one legacy write_receipt row becomes one current write_receipt row re-keyed from the legacy (project_id, write_id) pair onto the canonical operation identity and its idempotency key; the legacy unique write_id index and the project_sequence index are not carried",
        },
    },
];

/// Why the legacy mapping is incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LegacyMappingOmission {
    /// A legacy table/index/field exists in the declared roots and no row maps
    /// the table that owns it.
    LegacyObjectUnmapped {
        /// The `DEFINE` keyword that declared the object.
        keyword: &'static str,
        /// The declared object name.
        name: String,
        /// The table that owns it.
        table: String,
        /// The legacy root file that declares it.
        root: &'static str,
    },
    /// A mapped table declares an index the legacy roots do not, so the row no
    /// longer describes the legacy schema.
    StaleIndexDeclaration {
        /// The mapped table.
        table: &'static str,
        /// The index the row names.
        index: &'static str,
    },
    /// Two rows claim the same legacy table.
    DuplicateTableRow {
        /// The table claimed twice.
        table: &'static str,
    },
}

impl fmt::Display for LegacyMappingOmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LegacyObjectUnmapped {
                keyword,
                name,
                table,
                root,
            } => write!(
                formatter,
                "legacy {keyword} {name} on table {table}, declared by {root}, has no current owner, transform or archive disposition"
            ),
            Self::StaleIndexDeclaration { table, index } => write!(
                formatter,
                "the mapping for {table} declares legacy index {index}, which the legacy roots no longer define"
            ),
            Self::DuplicateTableRow { table } => {
                write!(
                    formatter,
                    "the legacy table {table} has more than one mapping row"
                )
            }
        }
    }
}

/// Fails closed unless every legacy table, index and field has a disposition.
///
/// The check compares [`census_legacy_schema_objects`] — derived from the
/// legacy DDL bytes — against [`LEGACY_TABLE_MAPPINGS`] in both directions, so
/// neither an unmapped legacy object nor a stale mapping row can pass. It is
/// the gate that lets the declared legacy roots leave the tree only after the
/// mapping closes, so it runs on the same admission path that admits a real
/// migration.
pub(crate) fn validate_legacy_table_mapping() -> Result<(), LegacyMappingOmission> {
    let census = census_legacy_schema_objects();
    for mapping in &LEGACY_TABLE_MAPPINGS {
        if LEGACY_TABLE_MAPPINGS
            .iter()
            .filter(|other| other.table == mapping.table)
            .count()
            > 1
        {
            return Err(LegacyMappingOmission::DuplicateTableRow {
                table: mapping.table,
            });
        }
    }
    for object in &census {
        let Some(mapping) = LEGACY_TABLE_MAPPINGS
            .iter()
            .find(|mapping| mapping.table == object.table)
        else {
            return Err(LegacyMappingOmission::LegacyObjectUnmapped {
                keyword: object.keyword,
                name: object.name.clone(),
                table: object.table.clone(),
                root: object.root,
            });
        };
        if object.keyword == LEGACY_INDEX_KEYWORD
            && !mapping.indexes.contains(&object.name.as_str())
        {
            return Err(LegacyMappingOmission::LegacyObjectUnmapped {
                keyword: object.keyword,
                name: object.name.clone(),
                table: object.table.clone(),
                root: object.root,
            });
        }
    }
    for mapping in &LEGACY_TABLE_MAPPINGS {
        for index in mapping.indexes {
            if !census.iter().any(|object| {
                object.keyword == LEGACY_INDEX_KEYWORD
                    && object.table == mapping.table
                    && object.name == *index
            }) {
                return Err(LegacyMappingOmission::StaleIndexDeclaration {
                    table: mapping.table,
                    index,
                });
            }
        }
    }
    Ok(())
}

/// Finds the declared non-executable root a presented identity names.
///
/// Three arms reach a root, and all three resolve to the same
/// [`ExecutableBodyRefusal::NonExecutableRoot`]: the recorded identity, the
/// exact repository path, and the `root.path` directory prefix with its `/`
/// separator. The third arm is what refuses a file inside
/// `crates/eliot-store/migrations/` or `crates/eliot-store/src/surql/`.
///
/// Every declared root is a directory, so the prefix arm reaches every file
/// beneath it. The orphan root `migrations/0001_bootstrap.surql` was deleted
/// under issue #1221 acceptance A3, so it names no declared root: it reaches
/// no arm here and is refused as [`ExecutableBodyRefusal::UnknownIdentity`],
/// because it is neither a published executable body nor a declared root.
fn non_executable_root_for(identity: &str) -> Option<&'static NonExecutableRoot> {
    NON_EXECUTABLE_MIGRATION_ROOTS.iter().find(|root| {
        root.identity == identity
            || root.path == identity
            || identity
                .strip_prefix(root.path)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Finds a recorded adjacent-class location a presented identity names.
///
/// The presented identity is matched against the exact recorded location of each
/// of the five classes, so a caller that presents an executor, a configuration
/// key, a packaging consumer or a restore module instead of a migration identity
/// is refused with that class's recorded disposition rather than falling through
/// to [`ExecutableBodyRefusal::UnknownIdentity`]. This is what makes the classes
/// reachable from the admission gate: they are not only validated, they answer.
fn adjacent_location_for(identity: &str) -> Option<ExecutableBodyRefusal> {
    let (location, class, disposition, note) = MIGRATION_CONSTRUCTORS
        .iter()
        .find(|row| row.location == identity)
        .map(|row| {
            (
                row.location,
                AdjacentClass::MigrationConstructor,
                row.disposition,
                row.note,
            )
        })
        .or_else(|| {
            MIGRATION_EXECUTORS
                .iter()
                .find(|row| row.location == identity)
                .map(|row| {
                    (
                        row.location,
                        AdjacentClass::MigrationExecutor,
                        row.disposition,
                        row.note,
                    )
                })
        })
        .or_else(|| {
            CONFIG_MIGRATION_PATHS
                .iter()
                .find(|row| row.key == identity)
                .map(|row| {
                    (
                        row.key,
                        AdjacentClass::ConfigMigrationPath,
                        AccessDisposition::LegacyNotAdmitted,
                        row.note,
                    )
                })
        })
        .or_else(|| {
            PACKAGE_RELEASE_CONSUMERS
                .iter()
                .find(|row| row.location == identity)
                .map(|row| {
                    (
                        row.location,
                        AdjacentClass::PackageReleaseConsumer,
                        AccessDisposition::LegacyNotAdmitted,
                        row.note,
                    )
                })
        })
        .or_else(|| {
            RESTORE_SCHEMA_DEPENDENCIES
                .iter()
                .find(|row| row.location == identity)
                .map(|row| {
                    (
                        row.location,
                        AdjacentClass::RestoreSchemaDependency,
                        AccessDisposition::OwnerAdmitted,
                        row.note,
                    )
                })
        })?;
    Some(ExecutableBodyRefusal::NotAnAdjacentBody {
        location,
        class,
        disposition,
        note,
    })
}

/// Fail-closed resolution: is the presented body executable by the current
/// owner?
///
/// Returns the published [`EmbeddedSchemaBody`] only when the identity is in
/// the executable graph and the presented statements, digest and target
/// generation are exactly the published ones. Every other outcome is a typed
/// [`ExecutableBodyRefusal`]; there is no default-allow path and no way for a
/// caller to name a different body, directory or DDL text.
///
/// The adjacent classes are consulted here, which is what makes them reachable
/// from the gate rather than merely recorded:
///
/// - [`validate_adjacent_classes`] runs first, so an incomplete record of
///   constructors, executors, configuration paths, packaging consumers and
///   restore dependencies refuses every plan as
///   [`ExecutableBodyRefusal::AdjacentClassRecordIncomplete`];
/// - an identity that names one of those recorded locations is refused as
///   [`ExecutableBodyRefusal::NotAnAdjacentBody`] with that class's recorded
///   disposition, instead of the anonymous
///   [`ExecutableBodyRefusal::UnknownIdentity`];
/// - a declared non-executable root is refused as
///   [`ExecutableBodyRefusal::NonExecutableRoot`] for the three spellings
///   [`non_executable_root_for`] matches;
/// - any other identity that names no published body is refused as
///   [`ExecutableBodyRefusal::UnknownIdentity`].
pub(crate) fn resolve_executable_body(
    identity: &str,
    statements: &str,
    generation: &str,
    checksum_sha256: &str,
) -> Result<&'static EmbeddedSchemaBody, ExecutableBodyRefusal> {
    validate_adjacent_classes()
        .map_err(|omission| ExecutableBodyRefusal::AdjacentClassRecordIncomplete { omission })?;
    if let Some(body) = embedded_body_by_migration_id(identity) {
        return admit_published_body(body, statements, generation, checksum_sha256);
    }
    if let Some(body) = EMBEDDED_SCHEMA_BODIES
        .iter()
        .find(|body| body.const_name == identity)
    {
        return Err(ExecutableBodyRefusal::DeclaredNotAdmitted {
            const_name: body.const_name,
            note: body.note,
        });
    }
    if let Some(table) = LEGACY_TABLE_MAPPINGS
        .iter()
        .find(|mapping| mapping.table == identity)
    {
        return Err(ExecutableBodyRefusal::LegacyTableNotExecutable {
            table: table.table,
            disposition: table.disposition,
        });
    }
    if let Some(root) = non_executable_root_for(identity) {
        return Err(ExecutableBodyRefusal::NonExecutableRoot {
            path: root.path,
            disposition: root.disposition,
            rationale: root.rationale,
            removal_condition: root.removal_condition,
        });
    }
    if let Some(refusal) = adjacent_location_for(identity) {
        return Err(refusal);
    }
    Err(ExecutableBodyRefusal::UnknownIdentity {
        identity: identity.to_owned(),
    })
}

/// Checks a presented body against its published entry.
fn admit_published_body(
    body: &'static EmbeddedSchemaBody,
    statements: &str,
    generation: &str,
    checksum_sha256: &str,
) -> Result<&'static EmbeddedSchemaBody, ExecutableBodyRefusal> {
    let Some(migration_id) = body.migration_id else {
        return Err(ExecutableBodyRefusal::DeclaredNotAdmitted {
            const_name: body.const_name,
            note: body.note,
        });
    };
    if body.disposition != BodyDisposition::ExecutableGraph {
        return Err(ExecutableBodyRefusal::DeclaredNotAdmitted {
            const_name: body.const_name,
            note: body.note,
        });
    }
    let body_sha256 = body.body_sha256();
    if let Some(pinned_sha256) = body.pinned_sha256
        && pinned_sha256 != body_sha256
    {
        return Err(ExecutableBodyRefusal::PinnedBodyDrift {
            migration_id,
            pinned_sha256,
        });
    }
    if statements.trim() != body.ddl.trim() {
        return Err(ExecutableBodyRefusal::BodyBytesDiffer { migration_id });
    }
    if checksum_sha256 != body_sha256 {
        return Err(ExecutableBodyRefusal::BodyDigestDiffer { migration_id });
    }
    match body.generation {
        Some(current) if current == generation => {}
        current_generation => {
            return Err(ExecutableBodyRefusal::GenerationDiffer {
                migration_id,
                current_generation,
            });
        }
    }
    Ok(body)
}
