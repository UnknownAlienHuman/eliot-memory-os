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
        rationale: "pre-split canonical schema root still owned by the legacy core; selected by the legacy store.migrations_dir config default and by legacy app/engine code, and retired by the legacy core retirement issue #1189 — the current owner records the disposition and never executes it",
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

/// Fail-closed resolution: is the presented body executable by the current
/// owner?
///
/// Returns the published [`EmbeddedSchemaBody`] only when the identity is in
/// the executable graph and the presented statements, digest and target
/// generation are exactly the published ones. Every other outcome is a typed
/// [`ExecutableBodyRefusal`]; there is no default-allow path and no way for a
/// caller to name a different body, directory or DDL text.
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
    if let Some(root) = NON_EXECUTABLE_MIGRATION_ROOTS
        .iter()
        .find(|root| root.identity == identity || root.path == identity)
    {
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
