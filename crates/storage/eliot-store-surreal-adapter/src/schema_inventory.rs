//! Machine-readable inventory of every schema/migration body and every
//! migration root known to the current Store schema-generation owner
//! (issue #1221, wave A).
//!
//! This module is the single place that answers "is this `SurrealQL` DDL body
//! executable by the current owner?". It publishes two closed, ordered
//! denominators and one fail-closed resolution over both:
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
//! Both are derived from the same [`crate::schema`] constants the executor
//! applies. Neither restates DDL bytes, neither names a filesystem location
//! as authority, and no caller can supply a migration directory: repository
//! filename presence is not execution ownership. [`resolve_executable_body`]
//! is the only admission entry point and refuses everything outside the
//! executable set with a typed reason — never a default-allow.
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
    /// declares non-executable.
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
/// The refusal covers the whole root, not one filename: the recorded identity,
/// the exact repository path and every path under that root (the `root.path`
/// directory prefix with its `/` separator) all resolve to the same
/// [`ExecutableBodyRefusal::NonExecutableRoot`]. A file inside
/// `crates/eliot-store/migrations/` or `crates/eliot-store/src/surql/`, or the
/// retired root `migrations/0001_bootstrap.surql.retired` under any other
/// name, therefore cannot be selected by current configuration, launch,
/// packaging or restore: `I5.9` admits one executable migration graph, and
/// this array is that graph's closed non-executable complement.
fn non_executable_root_for(identity: &str) -> Option<&'static NonExecutableRoot> {
    NON_EXECUTABLE_MIGRATION_ROOTS.iter().find(|root| {
        root.identity == identity
            || root.path == identity
            || identity.strip_prefix(root.path).is_some_and(|rest| rest.starts_with('/'))
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
/// non-executable root refuses every identity it covers — its recorded
/// identity, its exact path and every path beneath it (see
/// [`non_executable_root_for`]).
pub(crate) fn resolve_executable_body(
    identity: &str,
    statements: &str,
    generation: &str,
    checksum_sha256: &str,
) -> Result<&'static EmbeddedSchemaBody, ExecutableBodyRefusal> {
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
