//! Machine-readable inventory of every schema/migration body and every
//! migration root known to the current Store schema-generation owner
//! (issue #1221, wave A).
//!
//! This module is the single place that answers "is this `SurrealQL` DDL body
//! executable by the current owner?". It publishes three closed, ordered
//! denominators and one fail-closed resolution over all of them:
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
//!
//! A third denominator completes the work-item W1 object classes that decide
//! whether a path *outside* this module can select or execute one of those
//! roots: [`SELECTION_PATHS`] — every migration constructor or executor,
//! configuration path, package/release consumer and restore dependency that can
//! reach a migration statement, each recorded with the exact repository
//! `path::symbol` it names.
//! Without it the two denominators above answer "which body and which root does
//! the current owner hold?" while staying silent about the callers that could
//! reach past them.
//!
//! The first two are derived from the same [`crate::schema`] constants the
//! executor applies. The third names repository locations by design, because
//! "which file outside this crate can still reach a migration statement" has no
//! answer without naming them; naming one grants it nothing. None of the three
//! treats a filesystem location as authority: no caller can supply a migration
//! directory, and repository filename presence is not execution ownership.
//!
//! [`resolve_executable_body`] is the only admission entry point and refuses
//! everything outside the executable set with a typed reason — never a
//! default-allow. It refuses a presented identity naming a recorded
//! [`SelectionPath`] as [`ExecutableBodyRefusal::SelectionPathNotExecutable`]
//! rather than as an anonymous unknown identity, and it fails the whole gate
//! closed with [`ExecutableBodyRefusal::SelectionPathClosure`] when
//! [`validate_selection_path_closure`] finds the record not closed — a class
//! with no instance, a selection path naming a root this owner has not declared
//! non-executable, or two rows claiming one `path::symbol`.
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
    /// A retired body retained on disk only as an explicitly named,
    /// expiring, non-executable fixture with no discovered consumer.
    NonExecutableFixture,
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
pub(crate) static EMBEDDED_SCHEMA_BODIES: [EmbeddedSchemaBody; 10] = [
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
/// Recorded from
/// `workstreams/storage/assignments/1221-schema-migration-owner.toml`
/// `[disposition]`, plus the legacy roots the assignment lists under
/// `current_source`. The legacy bodies are still owned by the legacy core
/// and still selected by legacy config/app code, so this owner records their
/// disposition and removal condition rather than removing them.
pub(crate) static NON_EXECUTABLE_MIGRATION_ROOTS: [NonExecutableRoot; 3] = [
    NonExecutableRoot {
        path: "migrations/0001_bootstrap.surql.retired",
        identity: "eliot.surql.orphan-root.0001_bootstrap",
        disposition: RootDisposition::NonExecutableFixture,
        rationale: "orphan root bootstrap body (health_record, migration_record) with no discovered consumer; neutralized and renamed out of the .surql extension on 2026-09-13, recorded as fixture-not-executable with consumers_found = 0 in the #1221 assignment [disposition]",
        removal_condition: "fixture expires 2026-12-12, or earlier when issue #1221 waves B/C/D close the legacy mapping",
    },
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

// -- Selection paths (issue #1221 work item W1) ----------------------------
//
// The two denominators above record what the current owner *holds*: every
// embedded DDL body and every migration root that exists in the tree but that
// this owner never executes. Work item W1 also names the object classes that
// decide whether a path *outside* this crate can reach a migration statement at
// all — a migration executor, a configuration path, a package/release consumer
// and a restore dependency. Without those classes the inventory would answer
// "which body and which root?" while staying silent about the callers that can
// reach past them, which is the smaller world the work item refuses.
//
// Every entry names a repository `path::symbol` that exists in the tree today,
// and the two closure checks below keep the table honest: no entry may name a
// root this owner has not declared non-executable, no two entries may claim one
// `path::symbol`, and no class may be empty. A class that lost its last real
// instance fails the gate instead of publishing an empty denominator.

/// The class of object a [`SelectionPath`] names, one variant per object class
/// work item W1 assigns to this inventory.
///
/// The class is the stable refusal identity: [`resolve_executable_body`] names
/// it when a presented identity resolves to an entry, so the operator-visible
/// error says *which kind* of outside path was refused and not only that some
/// identity was unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SelectionPathClass {
    /// A migration constructor that builds the value an outside executor sends,
    /// or such an executor itself: either reaches a provider without passing
    /// this owner's admission gate.
    MigrationExecutor,
    /// A configuration field or key that can name a migration root directory.
    ConfigPath,
    /// A packaging, installation or release step that copies a root into an
    /// installed tree or writes a root path into an installed configuration.
    PackageReleaseConsumer,
    /// A restore, snapshot or export path whose correctness depends on the
    /// current schema generation and therefore on this owner's migration graph.
    RestoreDependency,
}

/// One recorded outside path that can reach a migration statement.
///
/// This is deliberately not a second ownership claim. The current owner still
/// holds every body in [`EMBEDDED_SCHEMA_BODIES`] and is still the only
/// executor of them; what this row records is that a specific
/// `path::symbol` elsewhere in the tree is a *reachable* path to migration
/// statements, so the owner can state what that path is and what removes it
/// instead of discovering it after the fact.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SelectionPath {
    /// Which work-item-W1 object class this entry is.
    pub(crate) class: SelectionPathClass,
    /// Repository path of the file that owns the reachable path.
    pub(crate) path: &'static str,
    /// The item inside that file that performs the reaching.
    pub(crate) symbol: &'static str,
    /// The migration root directory this entry can select or execute, matched
    /// against [`NON_EXECUTABLE_MIGRATION_ROOTS`] as an exact path or a `/`
    /// separated prefix. `None` when the entry reaches the current owner's own
    /// generation rather than a legacy root.
    pub(crate) selects: Option<&'static str>,
    /// Why the entry is recorded, with the disposition source it comes from.
    pub(crate) rationale: &'static str,
}

/// Rationale shared by every entry that resolves nothing outside this owner.
///
/// A restore dependency is not an alternative migration root: it reads the
/// generation and the table census the current owner already published and
/// applies no DDL of its own. It is recorded because `A13.7` restore verifies
/// schema and format compatibility, so the set of paths whose correctness rides
/// on the migration graph is part of the graph's contract.
const OWNER_GENERATION_DEPENDENCY: &str = "depends on the current owner's schema generation and table census rather than selecting a migration root; it applies no DDL of its own, and A13.7 restore verifies schema and format compatibility against exactly this generation, so it is recorded as a dependency of the one executable graph and never as a second root";

/// Every outside path that can reach a migration statement.
///
/// Ordered by class so the table reads as the four work-item-W1 denominators in
/// sequence: executors, then configuration paths, then package/release
/// consumers, then restore dependencies. Every `path`/`symbol` pair is verified
/// to exist in the tree; [`validate_selection_path_closure`] additionally
/// requires each `selects` root to be one this owner already declares
/// non-executable, so this table cannot name a root nobody has dispositioned.
pub(crate) static SELECTION_PATHS: [SelectionPath; 15] = [
    // -- Migration executors ------------------------------------------------
    //
    // The current owner's own executor is deliberately absent: it is
    // `crate::apply::admit_migration` -> [`resolve_executable_body`], the one
    // gate every body in [`EMBEDDED_SCHEMA_BODIES`] reaches a provider through,
    // and it is the module this file is. Every row here is a path that reaches
    // migration statements *without* passing it.
    SelectionPath {
        class: SelectionPathClass::MigrationExecutor,
        path: "crates/eliot-store/src/migration.rs",
        symbol: "MigrationRunner::run_all",
        selects: None,
        rationale: "a migration executor outside the current owner: run_all hands each caller-constructed CompiledMigration straight to SurrealStore::apply_migration as (migration_id, sql), so its statements are arbitrary caller text that never reaches this owner's gate and its only digest is the legacy blake3 checksum rather than the published SHA-256. No in-tree caller constructs a MigrationRunner, which is why the executor is recorded here with its owner rather than deleted from under it",
    },
    SelectionPath {
        class: SelectionPathClass::MigrationExecutor,
        path: "crates/eliot-store/src/migration.rs",
        symbol: "CompiledMigration::new",
        selects: None,
        rationale: "the constructor that makes the executor above reachable: it accepts any caller's sql as impl Into<String>, digests it with the legacy blake3 hash rather than the published SHA-256, and produces exactly the value MigrationRunner::run_all forwards to SurrealStore::apply_migration. A migration constructor is a distinct object class from a migration executor and it is named in work item W1, so recording only the executor would leave the class unfilled while the closure check still passed; this owner admits migrations through its own CompiledMigration in readiness.rs, which is deliberately absent from this table as the owner's own path",
    },
    SelectionPath {
        class: SelectionPathClass::MigrationExecutor,
        path: "crates/eliot-store/src/surreal_store.rs",
        symbol: "SurrealStore::apply_migration",
        selects: None,
        rationale: "the executor MigrationRunner::run_all reaches: it passes the caller-supplied sql argument straight to transport().query() with no admission, digest or generation check, which is the arbitrary raw SQL execution the #1221 assignment lists as forbidden and which this owner must therefore keep out of its own callers rather than route through resolve_executable_body",
    },
    SelectionPath {
        class: SelectionPathClass::MigrationExecutor,
        path: "crates/eliot-store/src/canonical_store.rs",
        symbol: "CanonicalStore::migrate_schema",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the legacy core's ordered schema executor: it runs eleven SchemaMigrate* named operations whose bodies are include_str! from the declared legacy src/surql root, and current eliot-app commands still call it directly, so the legacy root has a live named-operation consumer this owner refuses rather than one that merely sits on disk",
    },
    SelectionPath {
        class: SelectionPathClass::MigrationExecutor,
        path: "crates/eliot-store/src/surql/operation.rs",
        symbol: "NamedSurqlOp::SchemaMigrate",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the binding from a named operation to its exact legacy bytes: template() returns include_str!(\"000_schema.surql\") from the declared legacy root, so every legacy body has a compile-time consumer identity even where no configuration key selects the root; this owner refuses that identity and executes none of those bytes. Presenting the file path reaches the root refusal instead, which names the same root",
    },
    // -- Configuration paths -------------------------------------------------
    //
    // A config path names a root by *value*. The one current key that still
    // carries a root-named value is `store.surql_dir`; the front door scans for
    // it only to refuse it, and the refusal is recorded rather than the value.
    SelectionPath {
        class: SelectionPathClass::ConfigPath,
        path: "crates/eliot-types/src/config.rs",
        symbol: "StoreConfig::surql_dir",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the one surviving configuration key that names a migration-root directory; its default is crates/eliot-store/src/surql and require_non_empty refuses an empty value, so a current document selects the declared legacy root by default. The migrations_dir key that also named a root is deleted and deny_unknown_fields keeps a document that still carries it a refusal, which is why exactly one surviving key is recorded",
    },
    SelectionPath {
        class: SelectionPathClass::ConfigPath,
        path: "crates/eliot-types/src/config.rs",
        symbol: "StoreConfig",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the [store] table itself: deny_unknown_fields refuses an unknown member, so surql_dir is the only way a document can name a root through it and a second key would be a refusal rather than a silent default; recorded as the enclosing shape so a future field is a stated addition to this table and not an unnoticed new selection path",
    },
    SelectionPath {
        class: SelectionPathClass::ConfigPath,
        path: "bins/eliot/src/legacy_governor_config.rs",
        symbol: "detect_legacy_markers",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the front door's legacy-configuration scan: it matches the [store] table, surql_dir and migrations_dir by text and rejects the document, so the retired governor configuration is a current path that reads both legacy root names. The refusal, not the value, is what keeps it from selecting one, and recording it states where that refusal lives rather than leaving the mention undiscovered",
    },
    // -- Package/release consumers -------------------------------------------
    SelectionPath {
        class: SelectionPathClass::PackageReleaseConsumer,
        path: "crates/eliot-app/src/commands/operations.rs",
        symbol: "run_daemon_init_default",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "a real packaging consumer of a root this owner declares LegacyRoot: it reads config.store.surql_dir, copies the whole configured tree into the installed <eliot_home>/resources/surql, and writes the copied path back into the installed config, so a legacy root survives installation and stays selectable from the installed document",
    },
    SelectionPath {
        class: SelectionPathClass::PackageReleaseConsumer,
        path: "crates/eliot-app/src/commands/operations.rs",
        symbol: "copy_resource_tree",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "the copier run_daemon_init_default uses: it recursively reproduces whatever directory it is handed, so the installed legacy .surql tree is a byte copy of the declared root rather than a generated artifact, and its removal condition is the same as the root's",
    },
    SelectionPath {
        class: SelectionPathClass::PackageReleaseConsumer,
        path: "crates/eliot-app/src/dogfood.rs",
        symbol: "init",
        selects: Some("crates/eliot-store/src/surql"),
        rationale: "a second instance of the packaging shape, distinct from run_daemon_init_default because it writes the path rather than copying the tree: it sets config.store.surql_dir to the project surql directory in the generated dogfood config, so an installed dogfood document names a root-shaped directory and the operator-visible difference from the daemon path is copy-versus-reference",
    },
    // -- Restore dependencies ------------------------------------------------
    SelectionPath {
        class: SelectionPathClass::RestoreDependency,
        path: "crates/storage/eliot-store-surreal-adapter/src/backup_snapshot.rs",
        symbol: "admitted_generation_ddl",
        selects: None,
        rationale: OWNER_GENERATION_DEPENDENCY,
    },
    SelectionPath {
        class: SelectionPathClass::RestoreDependency,
        path: "crates/storage/eliot-store-surreal-adapter/src/client/backup_snapshot.rs",
        symbol: "fixed_snapshot_statement",
        selects: None,
        rationale: OWNER_GENERATION_DEPENDENCY,
    },
    SelectionPath {
        class: SelectionPathClass::RestoreDependency,
        path: "crates/storage/eliot-store-surreal-adapter/src/backup_restore.rs",
        symbol: "validate_restore_batch",
        selects: None,
        rationale: OWNER_GENERATION_DEPENDENCY,
    },
    SelectionPath {
        class: SelectionPathClass::RestoreDependency,
        path: "crates/storage/eliot-store-surreal-adapter/src/client/backup_restore.rs",
        symbol: "fixed_restore_statement",
        selects: None,
        rationale: "the closed registry binding each restore operation name to its fixed interned statement, the exact structural mirror of fixed_snapshot_statement in the sibling client/backup_snapshot.rs: it selects only from the module's own prepare, fence, purge-ledger, archive-member, carrier-publish, canonical-read, apply, validate and reconcile constants and refuses any other operation name. It applies no DDL of its own and takes no caller SQL, but its operations write the restore and purge tables of the generation this owner publishes, and A13.7 requires restore to verify schema and format compatibility against exactly that generation",
    },
];

/// Why the recorded selection paths are not closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SelectionPathClosure {
    /// A [`SelectionPathClass`] has no entry, so the inventory would answer
    /// for three classes of the four work item W1 names.
    EmptyClass {
        /// The class with no recorded instance.
        class: SelectionPathClass,
    },
    /// An entry names a migration root this owner does not declare in
    /// [`NON_EXECUTABLE_MIGRATION_ROOTS`], so the table would record a
    /// reachable root nobody has dispositioned.
    UndeclaredRoot {
        /// The class of the offending entry.
        class: SelectionPathClass,
        /// Repository path of the offending entry.
        path: &'static str,
        /// Symbol of the offending entry.
        symbol: &'static str,
        /// The root the entry claims to select.
        root: &'static str,
    },
    /// Two entries claim the same `path::symbol`.
    DuplicateEntry {
        /// The class of the duplicated entry.
        class: SelectionPathClass,
        /// Repository path claimed twice.
        path: &'static str,
        /// Symbol claimed twice.
        symbol: &'static str,
    },
}

impl fmt::Display for SelectionPathClosure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyClass { class } => {
                write!(
                    formatter,
                    "no selection path is recorded for class {class:?}"
                )
            }
            Self::UndeclaredRoot {
                class,
                path,
                symbol,
                root,
            } => write!(
                formatter,
                "{path}::{symbol} is recorded as a {class:?} selecting {root}, which the current schema owner does not declare as a non-executable migration root"
            ),
            Self::DuplicateEntry {
                class,
                path,
                symbol,
            } => write!(
                formatter,
                "the {class:?} selection path {path}::{symbol} is recorded more than once"
            ),
        }
    }
}

/// Fails closed unless every work-item-W1 class is populated and every entry
/// names a root this owner already declares non-executable.
///
/// Run on the same admission path that admits a real migration, for the same
/// reason [`validate_legacy_table_mapping`] runs there: an incomplete record is
/// an operator-visible refusal rather than a smaller published world. It reads
/// [`SELECTION_PATHS`] only — it never consults the filesystem — so a record
/// cannot claim an instance it has not verified; the verification is that every
/// `path::symbol` in the table was confirmed to exist in the tree before it was
/// written here, and this check keeps the table internally closed.
fn validate_selection_path_closure() -> Result<(), SelectionPathClosure> {
    for class in [
        SelectionPathClass::MigrationExecutor,
        SelectionPathClass::ConfigPath,
        SelectionPathClass::PackageReleaseConsumer,
        SelectionPathClass::RestoreDependency,
    ] {
        if !SELECTION_PATHS.iter().any(|entry| entry.class == class) {
            return Err(SelectionPathClosure::EmptyClass { class });
        }
    }
    for entry in &SELECTION_PATHS {
        if SELECTION_PATHS
            .iter()
            .filter(|other| other.path == entry.path && other.symbol == entry.symbol)
            .count()
            > 1
        {
            return Err(SelectionPathClosure::DuplicateEntry {
                class: entry.class,
                path: entry.path,
                symbol: entry.symbol,
            });
        }
        if let Some(root) = entry.selects
            && non_executable_root_for(root).is_none()
        {
            return Err(SelectionPathClosure::UndeclaredRoot {
                class: entry.class,
                path: entry.path,
                symbol: entry.symbol,
                root,
            });
        }
    }
    Ok(())
}

/// Returns the recorded selection path a presented identity names.
///
/// The arms mirror [`non_executable_root_for`]: the recorded `symbol`, the
/// repository `path` alone, and the `path` directory prefix with its `/`
/// separator. Matching on the path means a caller that presents the file
/// holding a legacy executor is refused as that executor rather than as an
/// anonymous unknown identity; where two entries share one file, the first in
/// table order answers and the message is stable.
///
/// One entry's `path` arm is deliberately shadowed, and the shadow is a refusal
/// rather than a gap. `crates/eliot-store/src/surql/operation.rs` sits inside a
/// declared legacy root, so [`resolve_executable_body`] refuses it first as
/// [`ExecutableBodyRefusal::NonExecutableRoot`], which names the root and its
/// removal condition and so is the more precise answer; the entry's `symbol`
/// arm still reaches this function for the bare operation name. A declared
/// root's own path reaches no entry here at all, which is correct: a root is
/// not an outside path to a migration statement.
fn selection_path_for(identity: &str) -> Option<&'static SelectionPath> {
    SELECTION_PATHS.iter().find(|entry| {
        entry.path == identity
            || entry.symbol == identity
            || identity
                .strip_prefix(entry.path)
                .is_some_and(|rest| rest.starts_with('/'))
    })
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
    /// [`non_executable_root_for`]). A root that is a single file rather than
    /// a directory matches only its identity and its exact path.
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
    /// The presented identity names a recorded outside path: a migration
    /// executor, a configuration path, a package/release consumer or a restore
    /// dependency. Naming one is not itself the refusal — the current owner
    /// simply does not execute through it — and the class makes the refusal
    /// answer "which kind of outside path" rather than "unknown identity".
    SelectionPathNotExecutable {
        /// The class of the recorded path.
        class: SelectionPathClass,
        /// Repository path of the recorded path.
        path: &'static str,
        /// Symbol of the recorded path.
        symbol: &'static str,
        /// Why the entry is recorded.
        rationale: &'static str,
    },
    /// The recorded selection paths are not closed, so the inventory cannot
    /// answer the question it exists to answer and no body is admitted at all.
    SelectionPathClosure {
        /// The closure failure, stated rather than collapsed into a string.
        omission: SelectionPathClosure,
    },
    /// The presented identity names a legacy table, which has a stated
    /// disposition but is never an executable migration body.
    LegacyTableNotExecutable {
        /// The legacy table that was presented.
        table: &'static str,
        /// What the current owner does with that table.
        disposition: LegacyTableDisposition,
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
            Self::SelectionPathNotExecutable {
                class,
                path,
                symbol,
                rationale,
            } => write!(
                formatter,
                "{path}::{symbol} is a recorded {class:?} outside the current schema owner and is not executable through it: {rationale}"
            ),
            Self::SelectionPathClosure { omission } => {
                write!(
                    formatter,
                    "the recorded selection paths are not closed: {omission}"
                )
            }
            Self::NonExecutableRoot {
                path,
                disposition,
                rationale,
                removal_condition,
            } => {
                let disposition = match disposition {
                    RootDisposition::NonExecutableFixture => "non-executable fixture",
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
/// The retired root `migrations/0001_bootstrap.surql.retired` is a single
/// file, so the directory arm is vacuous for it: only its recorded identity
/// and its exact path reach this variant. Any other spelling of it —
/// `migrations/0001_bootstrap.surql` in particular — reaches no arm here and
/// is refused as [`ExecutableBodyRefusal::UnknownIdentity`] instead, because
/// it is neither a published executable body nor a declared root. The refusal
/// is the same either way; only the typed reason differs.
fn non_executable_root_for(identity: &str) -> Option<&'static NonExecutableRoot> {
    NON_EXECUTABLE_MIGRATION_ROOTS.iter().find(|root| {
        root.identity == identity
            || root.path == identity
            || identity
                .strip_prefix(root.path)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Fail-closed resolution: is the presented body executable by the current
/// owner?
///
/// Returns the published [`EmbeddedSchemaBody`] only when the identity is in
/// the executable graph and the presented statements, digest and target
/// generation are exactly the published ones. Every other outcome is a typed
/// [`ExecutableBodyRefusal`]; there is no default-allow path and no way for a
/// caller to name a different body, directory or DDL text. A declared
/// non-executable root is refused as
/// [`ExecutableBodyRefusal::NonExecutableRoot`] for the three spellings
/// [`non_executable_root_for`] matches; an identity naming a recorded outside
/// path in [`SELECTION_PATHS`] is refused as
/// [`ExecutableBodyRefusal::SelectionPathNotExecutable`]; and any other identity
/// that names no published body is refused as
/// [`ExecutableBodyRefusal::UnknownIdentity`].
///
/// The recorded selection paths are checked closed before anything is resolved:
/// an inventory that lost a work-item-W1 class, duplicated a `path::symbol` or
/// named an undeclared root cannot answer "can a current config, launch,
/// packaging or restore path select or execute a legacy migration root?", so it
/// admits nothing rather than answering from a smaller world.
pub(crate) fn resolve_executable_body(
    identity: &str,
    statements: &str,
    generation: &str,
    checksum_sha256: &str,
) -> Result<&'static EmbeddedSchemaBody, ExecutableBodyRefusal> {
    if let Err(omission) = validate_selection_path_closure() {
        return Err(ExecutableBodyRefusal::SelectionPathClosure { omission });
    }
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
    if let Some(entry) = selection_path_for(identity) {
        return Err(ExecutableBodyRefusal::SelectionPathNotExecutable {
            class: entry.class,
            path: entry.path,
            symbol: entry.symbol,
            rationale: entry.rationale,
        });
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
