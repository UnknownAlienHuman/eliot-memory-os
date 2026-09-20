//! Private `SurrealDB` physical schema and closed named-operation `SurrealQL`.
//!
//! Table names, record shapes, query strings and schema-generation mechanics
//! never cross the crate boundary. Only [`eliot_store_api`] types and the
//! bounded [`crate::error::AdapterError`] are exposed. This module is the
//! single place that owns raw `SurrealQL` and physical names, so the "no SDK
//! types, credentials, table names or raw query strings outside the bridge"
//! boundary is enforced structurally.

/// Physical table names, private to this crate.
pub(crate) mod table {
    pub(crate) const SCHEMA_META: &str = "schema_meta";
    pub(crate) const WRITE_RECEIPT: &str = "write_receipt";
    pub(crate) const REVISION_HEAD: &str = "revision_head";
    pub(crate) const ORDERING_HEAD: &str = "ordering_head";
    pub(crate) const CANONICAL_EVENT: &str = "canonical_event";
    pub(crate) const PROJECTION_RECORD: &str = "projection_record";
    pub(crate) const RELATION_RECORD: &str = "relation_record";
    pub(crate) const OUTBOX_EVENT: &str = "outbox_event";
    pub(crate) const CANONICAL_FENCE: &str = "canonical_fence";
    pub(crate) const RECOVERY_OWNER: &str = "recovery_owner";
    /// Dreamer ledger lives inside this existing table (S1 #775); the
    /// versioned Dreamer namespace plus discriminated keys separate it from
    /// other recovery users without a new table or migration.
    pub(crate) const RECOVERY_JOB: &str = "recovery_job";
    /// Durable erasure-intent row per operation, recorded before any
    /// destructive dispatch (688-B). One row per `operation_id`; the intent
    /// upsert refuses when the same id already names a different intent.
    pub(crate) const ERASURE_INTENT: &str = "erasure_intent";
    /// Sealed per-surface erasure outcomes per operation. The single
    /// completion marker for the intent row above — never a second ledger.
    pub(crate) const ERASURE_OUTCOME: &str = "erasure_outcome";
}

/// Record key of the single canonical fence/sequence row.
pub(crate) const FENCE_KEY: &str = "current";
/// Record key of the single schema-meta row.
pub(crate) const SCHEMA_META_KEY: &str = "current";

pub(crate) const GENERATION_V1: &str = "1.0.0";
pub(crate) const GENERATION_V2: &str = "2.0.0";
pub(crate) const MIGRATION_ID_V1: &str = "eliot.store.surreal.schema.v1";
pub(crate) const MIGRATION_ID_V2: &str = "eliot.store.surreal.schema.v2";
pub(crate) const MIGRATION_ID_V1_TO_V2: &str = "eliot.store.surreal.schema.v1_to_v2";
/// Additive erasure-table migration: creates only `erasure_intent` and
/// `erasure_outcome` on top of a v2 baseline (688-B).
#[allow(dead_code)]
pub(crate) const MIGRATION_ID_V2_TO_V3: &str = "eliot.store.surreal.schema.v2_to_v3";
/// Schema generation reached by the erasure-table migration. The tables are
/// additive, so v3 contains every v2 table verbatim plus the two erasure
/// tables below.
#[allow(dead_code)]
pub(crate) const GENERATION_V3: &str = "3.0.0";
pub(crate) const SCHEMA_DDL_V1_SHA256: &str =
    "783d3207ab39fc0471e32f893302eedd579ae4980ee95f9f883f92a5f7ba705b";

/// First-generation schema DDL for the canonical control tables. This is
/// applied only through an explicit migration; it is never executed implicitly
/// by the adapter.
pub(crate) const SCHEMA_DDL: &str = r"
DEFINE TABLE schema_meta SCHEMALESS;
DEFINE FIELD generation ON schema_meta TYPE string;
DEFINE FIELD migrations ON schema_meta TYPE array;
DEFINE FIELD compatible_bridge_range ON schema_meta TYPE string;
DEFINE FIELD migration_state ON schema_meta TYPE string;
DEFINE FIELD migration_id ON schema_meta TYPE string;
DEFINE FIELD migration_checksum_sha256 ON schema_meta TYPE string;
DEFINE FIELD updated_at ON schema_meta TYPE string;

DEFINE TABLE write_receipt SCHEMALESS;
DEFINE FIELD operation_id ON write_receipt TYPE string;
DEFINE FIELD idempotency_key ON write_receipt TYPE string;
DEFINE INDEX wr_operation ON write_receipt FIELDS operation_id UNIQUE;
DEFINE INDEX wr_idempotency ON write_receipt FIELDS idempotency_key UNIQUE;

DEFINE TABLE revision_head SCHEMALESS;
DEFINE FIELD revision_key ON revision_head TYPE string;
DEFINE INDEX rh_key ON revision_head FIELDS revision_key UNIQUE;

DEFINE TABLE ordering_head SCHEMALESS;
DEFINE FIELD ordering_scope ON ordering_head TYPE string;
DEFINE INDEX oh_scope ON ordering_head FIELDS ordering_scope UNIQUE;

DEFINE TABLE canonical_event SCHEMALESS;
DEFINE FIELD event_id ON canonical_event TYPE string;
DEFINE INDEX ce_id ON canonical_event FIELDS event_id UNIQUE;

DEFINE TABLE projection_record SCHEMALESS;
DEFINE FIELD publication_id ON projection_record TYPE string;
DEFINE INDEX pr_id ON projection_record FIELDS publication_id UNIQUE;

DEFINE TABLE relation_record SCHEMALESS;
DEFINE FIELD relation_id ON relation_record TYPE string;
DEFINE INDEX rr_id ON relation_record FIELDS relation_id UNIQUE;

DEFINE TABLE outbox_event SCHEMALESS;
DEFINE FIELD outbox_id ON outbox_event TYPE string;
DEFINE INDEX oe_id ON outbox_event FIELDS outbox_id UNIQUE;

DEFINE TABLE canonical_fence SCHEMALESS;
DEFINE FIELD id ON canonical_fence TYPE string;
DEFINE INDEX fence_id ON canonical_fence FIELDS id UNIQUE;
";

pub(crate) const RECOVERY_TABLES_DDL: &str = r"
DEFINE TABLE recovery_owner SCHEMALESS;
DEFINE FIELD namespace ON recovery_owner TYPE string;
DEFINE FIELD key ON recovery_owner TYPE string;
DEFINE FIELD state_fence ON recovery_owner TYPE object;
DEFINE FIELD revision ON recovery_owner TYPE int;
DEFINE FIELD schema ON recovery_owner TYPE string;
DEFINE FIELD payload ON recovery_owner TYPE bytes;
DEFINE FIELD value_digest ON recovery_owner TYPE string;
DEFINE INDEX ro_namespace_key ON recovery_owner FIELDS namespace, key UNIQUE;

DEFINE TABLE recovery_job SCHEMALESS;
DEFINE FIELD namespace ON recovery_job TYPE string;
DEFINE FIELD key ON recovery_job TYPE string;
DEFINE FIELD state_fence ON recovery_job TYPE object;
DEFINE FIELD revision ON recovery_job TYPE int;
DEFINE FIELD schema ON recovery_job TYPE string;
DEFINE FIELD payload ON recovery_job TYPE bytes;
DEFINE FIELD value_digest ON recovery_job TYPE string;
DEFINE INDEX rj_namespace_key ON recovery_job FIELDS namespace, key UNIQUE;
";

pub(crate) const SCHEMA_MIGRATION_V1_TO_V2_DDL: &str = RECOVERY_TABLES_DDL;

/// Erasure intent/outcome tables (688-B). Additive delta applied on top of a
/// v2 baseline: `erasure_intent` carries the exact durable intent row bound by
/// `erasure_transaction_bindings` (`operation_id`, `subject`, `scope_id`,
/// `surfaces`, `state_fence`, `operation_count`), and `erasure_outcome`
/// carries the sealed per-surface outcomes (`operation_id`, `outcomes`).
/// `operation_id` is unique in each table; one intent row plus its single
/// outcome seal per operation — never a second ledger.
#[allow(dead_code)]
pub(crate) const ERASURE_TABLES_DDL: &str = r"
DEFINE TABLE erasure_intent SCHEMALESS;
DEFINE FIELD operation_id ON erasure_intent TYPE string;
DEFINE FIELD subject ON erasure_intent TYPE string;
DEFINE FIELD scope_id ON erasure_intent TYPE string;
DEFINE FIELD surfaces ON erasure_intent TYPE array;
DEFINE FIELD state_fence ON erasure_intent TYPE object;
DEFINE FIELD operation_count ON erasure_intent TYPE int;
DEFINE INDEX ei_operation ON erasure_intent FIELDS operation_id UNIQUE;

DEFINE TABLE erasure_outcome SCHEMALESS;
DEFINE FIELD operation_id ON erasure_outcome TYPE string;
DEFINE FIELD outcomes ON erasure_outcome TYPE array;
DEFINE INDEX eo_operation ON erasure_outcome FIELDS operation_id UNIQUE;
";

/// Forward-migration body for the v2-to-v3 erasure step. Like the v1-to-v2
/// body it is a delta: no `schema_meta` redefinition, no data statements.
#[allow(dead_code)]
pub(crate) const SCHEMA_MIGRATION_V2_TO_V3_DDL: &str = ERASURE_TABLES_DDL;

pub(crate) const SCHEMA_DDL_V2: &str = r"
DEFINE TABLE schema_meta SCHEMALESS;
DEFINE FIELD generation ON schema_meta TYPE string;
DEFINE FIELD migrations ON schema_meta TYPE array;
DEFINE FIELD compatible_bridge_range ON schema_meta TYPE string;
DEFINE FIELD migration_state ON schema_meta TYPE string;
DEFINE FIELD migration_id ON schema_meta TYPE string;
DEFINE FIELD migration_checksum_sha256 ON schema_meta TYPE string;
DEFINE FIELD updated_at ON schema_meta TYPE string;

DEFINE TABLE write_receipt SCHEMALESS;
DEFINE FIELD operation_id ON write_receipt TYPE string;
DEFINE FIELD idempotency_key ON write_receipt TYPE string;
DEFINE INDEX wr_operation ON write_receipt FIELDS operation_id UNIQUE;
DEFINE INDEX wr_idempotency ON write_receipt FIELDS idempotency_key UNIQUE;

DEFINE TABLE revision_head SCHEMALESS;
DEFINE FIELD revision_key ON revision_head TYPE string;
DEFINE INDEX rh_key ON revision_head FIELDS revision_key UNIQUE;

DEFINE TABLE ordering_head SCHEMALESS;
DEFINE FIELD ordering_scope ON ordering_head TYPE string;
DEFINE INDEX oh_scope ON ordering_head FIELDS ordering_scope UNIQUE;

DEFINE TABLE canonical_event SCHEMALESS;
DEFINE FIELD event_id ON canonical_event TYPE string;
DEFINE INDEX ce_id ON canonical_event FIELDS event_id UNIQUE;

DEFINE TABLE projection_record SCHEMALESS;
DEFINE FIELD publication_id ON projection_record TYPE string;
DEFINE INDEX pr_id ON projection_record FIELDS publication_id UNIQUE;

DEFINE TABLE relation_record SCHEMALESS;
DEFINE FIELD relation_id ON relation_record TYPE string;
DEFINE INDEX rr_id ON relation_record FIELDS relation_id UNIQUE;

DEFINE TABLE outbox_event SCHEMALESS;
DEFINE FIELD outbox_id ON outbox_event TYPE string;
DEFINE INDEX oe_id ON outbox_event FIELDS outbox_id UNIQUE;

DEFINE TABLE canonical_fence SCHEMALESS;
DEFINE FIELD id ON canonical_fence TYPE string;
DEFINE INDEX fence_id ON canonical_fence FIELDS id UNIQUE;

DEFINE TABLE recovery_owner SCHEMALESS;
DEFINE FIELD namespace ON recovery_owner TYPE string;
DEFINE FIELD key ON recovery_owner TYPE string;
DEFINE FIELD state_fence ON recovery_owner TYPE object;
DEFINE FIELD revision ON recovery_owner TYPE int;
DEFINE FIELD schema ON recovery_owner TYPE string;
DEFINE FIELD payload ON recovery_owner TYPE bytes;
DEFINE FIELD value_digest ON recovery_owner TYPE string;
DEFINE INDEX ro_namespace_key ON recovery_owner FIELDS namespace, key UNIQUE;

DEFINE TABLE recovery_job SCHEMALESS;
DEFINE FIELD namespace ON recovery_job TYPE string;
DEFINE FIELD key ON recovery_job TYPE string;
DEFINE FIELD state_fence ON recovery_job TYPE object;
DEFINE FIELD revision ON recovery_job TYPE int;
DEFINE FIELD schema ON recovery_job TYPE string;
DEFINE FIELD payload ON recovery_job TYPE bytes;
DEFINE FIELD value_digest ON recovery_job TYPE string;
DEFINE INDEX rj_namespace_key ON recovery_job FIELDS namespace, key UNIQUE;
";

/// Third-generation full schema: every v2 table verbatim plus the two
/// additive erasure tables (688-B). A fresh database reaches v3 by applying
/// v1, then the v1-to-v2 delta, then the v2-to-v3 delta below, in order; the
/// assembled body here is the checksum-level proof that the chain stays
/// exactly additive.
#[allow(dead_code)]
pub(crate) const SCHEMA_DDL_V3: &str = r"
DEFINE TABLE schema_meta SCHEMALESS;
DEFINE FIELD generation ON schema_meta TYPE string;
DEFINE FIELD migrations ON schema_meta TYPE array;
DEFINE FIELD compatible_bridge_range ON schema_meta TYPE string;
DEFINE FIELD migration_state ON schema_meta TYPE string;
DEFINE FIELD migration_id ON schema_meta TYPE string;
DEFINE FIELD migration_checksum_sha256 ON schema_meta TYPE string;
DEFINE FIELD updated_at ON schema_meta TYPE string;

DEFINE TABLE write_receipt SCHEMALESS;
DEFINE FIELD operation_id ON write_receipt TYPE string;
DEFINE FIELD idempotency_key ON write_receipt TYPE string;
DEFINE INDEX wr_operation ON write_receipt FIELDS operation_id UNIQUE;
DEFINE INDEX wr_idempotency ON write_receipt FIELDS idempotency_key UNIQUE;

DEFINE TABLE revision_head SCHEMALESS;
DEFINE FIELD revision_key ON revision_head TYPE string;
DEFINE INDEX rh_key ON revision_head FIELDS revision_key UNIQUE;

DEFINE TABLE ordering_head SCHEMALESS;
DEFINE FIELD ordering_scope ON ordering_head TYPE string;
DEFINE INDEX oh_scope ON ordering_head FIELDS ordering_scope UNIQUE;

DEFINE TABLE canonical_event SCHEMALESS;
DEFINE FIELD event_id ON canonical_event TYPE string;
DEFINE INDEX ce_id ON canonical_event FIELDS event_id UNIQUE;

DEFINE TABLE projection_record SCHEMALESS;
DEFINE FIELD publication_id ON projection_record TYPE string;
DEFINE INDEX pr_id ON projection_record FIELDS publication_id UNIQUE;

DEFINE TABLE relation_record SCHEMALESS;
DEFINE FIELD relation_id ON relation_record TYPE string;
DEFINE INDEX rr_id ON relation_record FIELDS relation_id UNIQUE;

DEFINE TABLE outbox_event SCHEMALESS;
DEFINE FIELD outbox_id ON outbox_event TYPE string;
DEFINE INDEX oe_id ON outbox_event FIELDS outbox_id UNIQUE;

DEFINE TABLE canonical_fence SCHEMALESS;
DEFINE FIELD id ON canonical_fence TYPE string;
DEFINE INDEX fence_id ON canonical_fence FIELDS id UNIQUE;

DEFINE TABLE recovery_owner SCHEMALESS;
DEFINE FIELD namespace ON recovery_owner TYPE string;
DEFINE FIELD key ON recovery_owner TYPE string;
DEFINE FIELD state_fence ON recovery_owner TYPE object;
DEFINE FIELD revision ON recovery_owner TYPE int;
DEFINE FIELD schema ON recovery_owner TYPE string;
DEFINE FIELD payload ON recovery_owner TYPE bytes;
DEFINE FIELD value_digest ON recovery_owner TYPE string;
DEFINE INDEX ro_namespace_key ON recovery_owner FIELDS namespace, key UNIQUE;

DEFINE TABLE recovery_job SCHEMALESS;
DEFINE FIELD namespace ON recovery_job TYPE string;
DEFINE FIELD key ON recovery_job TYPE string;
DEFINE FIELD state_fence ON recovery_job TYPE object;
DEFINE FIELD revision ON recovery_job TYPE int;
DEFINE FIELD schema ON recovery_job TYPE string;
DEFINE FIELD payload ON recovery_job TYPE bytes;
DEFINE FIELD value_digest ON recovery_job TYPE string;
DEFINE INDEX rj_namespace_key ON recovery_job FIELDS namespace, key UNIQUE;

DEFINE TABLE erasure_intent SCHEMALESS;
DEFINE FIELD operation_id ON erasure_intent TYPE string;
DEFINE FIELD subject ON erasure_intent TYPE string;
DEFINE FIELD scope_id ON erasure_intent TYPE string;
DEFINE FIELD surfaces ON erasure_intent TYPE array;
DEFINE FIELD state_fence ON erasure_intent TYPE object;
DEFINE FIELD operation_count ON erasure_intent TYPE int;
DEFINE INDEX ei_operation ON erasure_intent FIELDS operation_id UNIQUE;

DEFINE TABLE erasure_outcome SCHEMALESS;
DEFINE FIELD operation_id ON erasure_outcome TYPE string;
DEFINE FIELD outcomes ON erasure_outcome TYPE array;
DEFINE INDEX eo_operation ON erasure_outcome FIELDS operation_id UNIQUE;
";

/// Transaction delimiters for a single atomic apply.
pub(crate) const TX_BEGIN: &str = "BEGIN TRANSACTION;";
pub(crate) const TX_COMMIT: &str = "COMMIT TRANSACTION;";

/// Compare-and-set update of the canonical fence singleton.
pub(crate) const TX_UPSERT_FENCE: &str = "LET $fence_cas = (UPDATE type::record($fence_table, $fence_key) CONTENT $fence WHERE state_fence = $expected_state_fence AND next_commit_sequence = $expected_commit_sequence AND next_outbox_sequence = $expected_outbox_sequence RETURN AFTER); IF array::len($fence_cas ?? []) != 1 { THROW 'canonical_fence_cas_conflict'; };";
pub(crate) const TX_CREATE_FENCE: &str = "LET $fence_create = (CREATE type::record($fence_table, $fence_key) CONTENT $fence RETURN AFTER); IF array::len($fence_create ?? []) != 1 { THROW 'canonical_fence_create_conflict'; };";
/// Compare-and-set update of one revision head. Exactly one revision key exists per transition.
pub(crate) const TX_UPSERT_REVISION: &str = "LET $revision_cas = (UPDATE type::record($revision_table, $revision_key) CONTENT $revision_record WHERE body.revision = $expected_revision AND body.state_fence = $expected_state_fence RETURN AFTER); IF array::len($revision_cas ?? []) != 1 { THROW 'revision_head_cas_conflict'; };";
pub(crate) const TX_CREATE_REVISION: &str = "LET $revision_create = (CREATE type::record($revision_table, $revision_key) CONTENT $revision_record RETURN AFTER); IF array::len($revision_create ?? []) != 1 { THROW 'revision_head_create_conflict'; };";
/// Compare-and-set update of one ordering head. `{i}` selects the binding index.
pub(crate) const TX_UPSERT_ORDERING: &str = "LET $ordering_cas{i} = (UPDATE type::record($ordering_table{i}, $ordering_scope{i}) CONTENT $ordering_record{i} WHERE body.sequence = $expected_ordering_sequence{i} AND body.state_fence = $expected_state_fence RETURN AFTER); IF array::len($ordering_cas{i} ?? []) != 1 { THROW 'ordering_head_cas_conflict'; };";
pub(crate) const TX_CREATE_ORDERING: &str = "LET $ordering_create{i} = (CREATE type::record($ordering_table{i}, $ordering_scope{i}) CONTENT $ordering_record{i} RETURN AFTER); IF array::len($ordering_create{i} ?? []) != 1 { THROW 'ordering_head_create_conflict'; };";
/// Create of one canonical event (immutable). `{i}` selects the binding index.
pub(crate) const TX_CREATE_EVENT: &str =
    "CREATE type::record($event_table{i}, $event_id{i}) CONTENT $event{i};";
/// Create of one projection publication (immutable). `{i}` selects the index.
pub(crate) const TX_CREATE_PROJECTION: &str =
    "CREATE type::record($projection_table{i}, $publication_id{i}) CONTENT $projection{i};";
/// Create one typed relation intent. `{i}` selects the index.
pub(crate) const TX_CREATE_RELATION: &str =
    "CREATE type::record($relation_table{i}, $relation_id{i}) CONTENT $relation{i};";
/// Create of one outbox intent (immutable). `{i}` selects the binding index.
pub(crate) const TX_CREATE_OUTBOX: &str =
    "CREATE type::record($outbox_table{i}, $outbox_id{i}) CONTENT $outbox{i};";
/// Create of the write receipt, the durable linearization point.
pub(crate) const TX_CREATE_RECEIPT: &str =
    "CREATE type::record($receipt_table, $receipt_operation_id) CONTENT $receipt;";

/// Renders an indexed transaction template for the given binding index.
pub(crate) fn indexed(template: &str, index: usize) -> String {
    template.replace("{i}", &index.to_string())
}

/// Migration metadata is part of the same provider transaction as DDL.  A
/// first-write `CREATE` prevents a stale or racing writer from overwriting the
/// durable identity; exact replays are handled by the adapter preflight.
pub(crate) const TX_CREATE_SCHEMA_META: &str =
    "CREATE type::record($schema_meta_table, $schema_meta_key) CONTENT $schema_meta_record;";

pub(crate) const TX_GUARD_FENCE: &str = "LET $fence_guard = (SELECT * FROM ONLY canonical_fence:current); IF $fence_guard.state_fence != $expected_state_fence OR $fence_guard.next_commit_sequence != $expected_commit_sequence OR $fence_guard.next_outbox_sequence != $expected_outbox_sequence { THROW 'schema_fence_guard_mismatch'; };";

pub(crate) const TX_GUARD_SCHEMA_PREDECESSOR: &str = "LET $pre = (SELECT * FROM ONLY schema_meta:current); IF $pre.generation != $expected_generation OR $pre.migration_id != $expected_migration_id OR $pre.migration_checksum_sha256 != $expected_migration_checksum_sha256 OR $pre.compatible_bridge_range != $expected_bridge_range OR $pre.migration_state != $expected_migration_state OR array::len($pre.migrations) != $expected_migrations_len OR $pre.migrations[0].migration_id != $expected_migration_0_id OR $pre.migrations[0].migration_checksum_sha256 != $expected_migration_0_checksum OR $pre.migrations[0].generation != $expected_migration_0_generation OR $pre.updated_at != $expected_updated_at { THROW 'schema_predecessor_mismatch'; };";

pub(crate) const TX_UPDATE_SCHEMA_META_CAS: &str = "LET $schema_cas = (UPDATE type::record($schema_meta_table, $schema_meta_key) CONTENT $schema_meta_record WHERE generation = $expected_generation AND migration_id = $expected_migration_id AND migration_checksum_sha256 = $expected_migration_checksum_sha256 AND compatible_bridge_range = $expected_bridge_range AND migration_state = $expected_migration_state AND array::len(migrations) = $expected_migrations_len AND migrations[0].migration_id = $expected_migration_0_id AND migrations[0].migration_checksum_sha256 = $expected_migration_0_checksum AND migrations[0].generation = $expected_migration_0_generation AND updated_at = $expected_updated_at RETURN AFTER); IF array::len($schema_cas ?? []) != 1 { THROW 'schema_predecessor_mismatch'; };";

pub(crate) fn forward_migration_sql() -> String {
    format!(
        "{} {} {} {} {} {}",
        TX_BEGIN,
        TX_GUARD_FENCE,
        RECOVERY_TABLES_DDL.trim(),
        TX_GUARD_SCHEMA_PREDECESSOR,
        TX_UPDATE_SCHEMA_META_CAS,
        TX_COMMIT
    )
}

/// Forward migration from a v2 baseline to the v3 erasure schema: creates
/// only the `erasure_intent` and `erasure_outcome` tables under exactly the
/// same fence plus predecessor (`migrations[0]`) guards as the v1-to-v2
/// forward migration above. The caller supplies the v2 predecessor bindings
/// through the same `forward_migration_expected_bindings` shape.
#[allow(dead_code)]
pub(crate) fn erasure_forward_migration_sql() -> String {
    format!(
        "{} {} {} {} {} {}",
        TX_BEGIN,
        TX_GUARD_FENCE,
        ERASURE_TABLES_DDL.trim(),
        TX_GUARD_SCHEMA_PREDECESSOR,
        TX_UPDATE_SCHEMA_META_CAS,
        TX_COMMIT
    )
}

#[cfg(test)]
pub(crate) fn forward_migration_expected_bindings() -> Vec<&'static str> {
    vec![
        "expected_state_fence",
        "expected_commit_sequence",
        "expected_outbox_sequence",
        "expected_generation",
        "expected_migration_id",
        "expected_migration_checksum_sha256",
        "expected_bridge_range",
        "expected_migration_state",
        "expected_migrations_len",
        "expected_migration_0_id",
        "expected_migration_0_checksum",
        "expected_migration_0_generation",
        "expected_updated_at",
        "schema_meta_table",
        "schema_meta_key",
        "schema_meta_record",
    ]
}

/// Closed read templates. Results select `body` values so they deserialize
/// back into store-API types without a `SurrealDB` `id` field.
///
/// `READ_SCHEMA_META` projects the exact `SchemaMetaRecord` columns for the
/// same reason: `SELECT *` returns the provider `id` alongside the declared
/// fields, which fails the record's closed deserialization against a real
/// provider (S1 #775 real-provider proof). The projection carries every
/// validated column and drops only the undeclared provider identity.
pub(crate) const READ_SCHEMA_META: &str = "SELECT VALUE { generation: generation, migrations: migrations, compatible_bridge_range: compatible_bridge_range, migration_state: migration_state, migration_id: migration_id, migration_checksum_sha256: migration_checksum_sha256, updated_at: updated_at } FROM ONLY schema_meta:current;";

pub(crate) const READ_FENCE: &str = "SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current;";

pub(crate) const READ_RECEIPT_BY_OPERATION: &str =
    "SELECT VALUE body FROM ONLY type::record($table, $key);";

pub(crate) const READ_RECEIPT_IDEMPOTENCY: &str = r"
SELECT VALUE body FROM write_receipt WHERE operation_id = $operation_id LIMIT 1;
SELECT VALUE body FROM write_receipt WHERE idempotency_key = $idempotency_key LIMIT 1;
";

pub(crate) const READ_REVISION_HEADS_BY_KEYS: &str =
    "SELECT VALUE body FROM revision_head WHERE revision_key IN $keys;";

pub(crate) const READ_ORDERING_HEADS_BY_SCOPES: &str =
    "SELECT VALUE body FROM ordering_head WHERE ordering_scope IN $scopes;";

pub(crate) const READ_ALL_REVISION_HEADS: &str = "SELECT VALUE body FROM revision_head;";

pub(crate) const READ_ALL_ORDERING_HEADS: &str = "SELECT VALUE body FROM ordering_head;";

/// Closed evidence-pack read: one row per receipt with its durable capture
/// order and recoverable evidence array (T11.1, #19).
///
/// Pre-change receipts lack `commit_sequence` / `evidence_records` /
/// `named_operation_count` (they read as `NONE`); the Rust boundary treats a
/// missing array as empty, never as an error. Filtering by exact subject,
/// bound enforcement, and capture-index assignment all happen in Rust for
/// byte-exact parity with the reference handler — never as a substring match
/// in the query string.
pub(crate) const READ_EVIDENCE_RECORDS: &str = "SELECT VALUE { commit_sequence: commit_sequence, named_operation_count: named_operation_count, evidence_records: evidence_records } FROM write_receipt;";

pub(crate) const READ_RECOVERY_OWNER_BY_KEY: &str = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_owner WHERE namespace = $recovery_namespace{i} AND key = $recovery_key{i} LIMIT 1;";
pub(crate) const READ_ALL_RECOVERY_JOBS: &str = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job;";
pub(crate) const READ_ALL_RECEIPTS: &str = "SELECT VALUE body FROM write_receipt;";
pub(crate) const READ_GENESIS_SCHEMA_AND_STATE: &str = "BEGIN TRANSACTION; SELECT * FROM ONLY schema_meta:current; SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current; SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_owner; SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job; SELECT VALUE body FROM write_receipt; SELECT VALUE body FROM revision_head; SELECT VALUE body FROM ordering_head; SELECT VALUE body FROM canonical_event; SELECT VALUE body FROM projection_record; SELECT VALUE body FROM outbox_event; SELECT VALUE body FROM relation_record; COMMIT TRANSACTION;";

pub(crate) const TX_GENESIS_BEGIN: &str = "BEGIN TRANSACTION;";
pub(crate) const TX_GENESIS_SCHEMA_GUARD: &str = "LET $genesis_schema = (SELECT * FROM ONLY schema_meta:current); LET $genesis_fence = (SELECT VALUE { state_fence: state_fence, next_commit_sequence: next_commit_sequence, next_outbox_sequence: next_outbox_sequence } FROM ONLY canonical_fence:current); IF !type::is_object($genesis_schema) OR !type::is_object($genesis_fence) { THROW 'genesis_state_conflict'; }; IF $genesis_schema.generation != $expected_generation OR $genesis_fence.state_fence != $expected_state_fence OR $genesis_fence.next_commit_sequence != 1 OR $genesis_fence.next_outbox_sequence != 1 { THROW 'genesis_fence_conflict'; };";
pub(crate) const TX_GENESIS_EMPTY_GUARD: &str = "IF array::len((SELECT * FROM recovery_owner)) != 0 OR array::len((SELECT * FROM recovery_job)) != 0 OR array::len((SELECT * FROM write_receipt)) != 0 OR array::len((SELECT * FROM revision_head)) != 0 OR array::len((SELECT * FROM ordering_head)) != 0 OR array::len((SELECT * FROM canonical_event)) != 0 OR array::len((SELECT * FROM projection_record)) != 0 OR array::len((SELECT * FROM outbox_event)) != 0 OR array::len((SELECT * FROM relation_record)) != 0 { THROW 'genesis_state_conflict'; };";
pub(crate) const TX_GENESIS_FENCE_CAS: &str = "LET $genesis_fence_cas = (UPDATE type::record($fence_table, $fence_key) CONTENT $fence WHERE state_fence = $expected_state_fence AND next_commit_sequence = 1 AND next_outbox_sequence = 1 RETURN AFTER); IF array::len($genesis_fence_cas ?? []) != 1 { THROW 'genesis_fence_conflict'; };";
pub(crate) const TX_GENESIS_CREATE_OWNER: &str =
    "CREATE type::record($owner_table{i}, $owner_id{i}) CONTENT $owner{i};";
pub(crate) const TX_GENESIS_CREATE_RECEIPT: &str =
    "CREATE type::record($receipt_table, $receipt_operation_id) CONTENT $receipt;";
pub(crate) const TX_GENESIS_COMMIT: &str = "COMMIT TRANSACTION;";

/// Dreamer ledger physical layout (S1, owner #775).
///
/// One versioned namespace inside the existing `recovery_job` table carries
/// four discriminated key families; a single provider transaction commits one
/// job row plus its event, operation-idempotency and receipt rows atomically.
/// No new table, field, index or migration: the existing
/// `(namespace, key)` UNIQUE index plus deterministic record IDs provide the
/// insert-if-absent primitive, and the typed outer `revision`/`state_fence`
/// columns provide the compare-and-swap primitive over otherwise-opaque
/// canonical payload bytes.
pub(crate) mod dreamer {
    /// Versioned Dreamer namespace inside `recovery_job`.
    pub(crate) const NAMESPACE: &str = "dreamer-job-v1";
    /// Key discriminators inside the Dreamer namespace. Values avoid `:`:
    /// bound colon-bearing strings in the indexed `key` column mis-coerce to
    /// record IDs on the pinned provider (S1 #775 real-provider proof), while
    /// the opaque `schema` column is unaffected.
    pub(crate) const KEY_JOB_PREFIX: &str = "job_";
    pub(crate) const KEY_EVENT_PREFIX: &str = "event_";
    pub(crate) const KEY_OPERATION_PREFIX: &str = "op_";
    pub(crate) const KEY_RECEIPT_PREFIX: &str = "receipt_";
    /// Versioned payload schemas; keys already discriminate, schemas aid
    /// debugging and forward migration without a DDL change.
    pub(crate) const SCHEMA_LEDGER_RECORD: &str = "eliot.storage.dreamer-job.v1:ledger-record";
    pub(crate) const SCHEMA_LEDGER_EVENT: &str = "eliot.storage.dreamer-job.v1:ledger-event";
    pub(crate) const SCHEMA_MUTATION: &str = "eliot.storage.dreamer-job.v1:mutation";
    pub(crate) const SCHEMA_RECEIPT: &str = "eliot.storage.dreamer-job.v1:receipt";
    /// CAS conflict marker thrown when the expected outer revision/fence no
    /// longer matches (concurrent winner committed first).
    pub(crate) const CAS_CONFLICT: &str = "dreamer_job_cas_conflict";
}

/// Reads one Dreamer row by exact namespace/key. Returns zero or one
/// `RecoveryRecord` in canonical column shape.
pub(crate) const READ_DREAMER_BY_KEY: &str = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $dreamer_namespace AND key = $dreamer_key LIMIT 1;";

/// Creates one Dreamer row by deterministic record ID. `{i}` selects the
/// binding index for the four-row atomic commit.
///
/// The record is projected field-by-field (instead of `CONTENT $record`)
/// because the `payload` column is `TYPE bytes`: bound JSON byte arrays only
/// coerce through an explicit `<bytes>` cast on the pinned provider (S1 #775
/// real-provider proof), while reads return plain arrays.
pub(crate) const TX_DREAMER_CREATE: &str = "CREATE type::record($dreamer_table{i}, $dreamer_id{i}) CONTENT { namespace: $dreamer_record{i}.namespace, key: $dreamer_record{i}.key, state_fence: $dreamer_record{i}.state_fence, revision: $dreamer_record{i}.revision, schema: $dreamer_record{i}.schema, payload: <bytes>$dreamer_record{i}.payload, value_digest: $dreamer_record{i}.value_digest };";

/// Compare-and-swaps one Dreamer job row on outer revision plus fence.
/// `{i}` selects the binding index (always 0 for the single job row).
pub(crate) const TX_DREAMER_CAS_JOB: &str = "LET $dreamer_cas{i} = (UPDATE type::record($dreamer_table{i}, $dreamer_id{i}) CONTENT { namespace: $dreamer_record{i}.namespace, key: $dreamer_record{i}.key, state_fence: $dreamer_record{i}.state_fence, revision: $dreamer_record{i}.revision, schema: $dreamer_record{i}.schema, payload: <bytes>$dreamer_record{i}.payload, value_digest: $dreamer_record{i}.value_digest } WHERE namespace = $dreamer_namespace{i} AND key = $dreamer_key{i} AND revision = $dreamer_expected_revision{i} AND state_fence = $dreamer_expected_fence{i} RETURN AFTER); IF array::len($dreamer_cas{i} ?? []) != 1 { THROW 'dreamer_job_cas_conflict'; };";
