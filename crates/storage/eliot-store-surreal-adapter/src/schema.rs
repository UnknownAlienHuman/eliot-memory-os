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
    /// completion marker for the intent row above - never a second ledger.
    pub(crate) const ERASURE_OUTCOME: &str = "erasure_outcome";
    /// Canonical notification record row per dedup key (issue #1780). One
    /// row per `dedup_key` carrying the current record, the ordered admitted
    /// leg history used for deterministic rehydration replay, the owner
    /// revision, and the admission fence. Concurrent writers arbitrate
    /// through the in-transaction revision compare-and-set; retries
    /// recompute from fresh rows, never from stale reads.
    pub(crate) const NOTIFICATION_RECORD: &str = "notification_record";
    /// Durable reactive-session row per session (issue #1941 C4). One row
    /// per `session_id` carrying the verbatim bridge ledger snapshot, the
    /// owner revision, the admission fence, and task-binding provenance.
    /// Concurrent writers arbitrate through the in-transaction revision
    /// compare-and-set; retries recompute from fresh rows.
    pub(crate) const REACTIVE_SESSION: &str = "reactive_session";
    /// Immutable resource-snapshot row per canonical URI (issue #1941 C4).
    /// One row per `uri` carrying the content digest, the verbatim base64
    /// bytes, the owner revision, and the admission fence. Rewrites with
    /// different bytes fail closed; create races converge through retry.
    pub(crate) const RESOURCE_SNAPSHOT: &str = "resource_snapshot";
    /// Immutable automation revision row per automation + revision
    /// (issue #1779). One row per joined `(automation_id, revision)` key
    /// carrying the verbatim Kernel-owned revision document. Create-only;
    /// divergent rewrites fail closed.
    pub(crate) const AUTOMATION_REVISION: &str = "automation_revision";
    /// Current automation pointer per automation (issue #1779). One row
    /// per `automation_id` carrying the current revision plus the closed
    /// admission state. Compare-and-set on the observed revision.
    pub(crate) const AUTOMATION_CURRENT: &str = "automation_current";
    /// Automation invocation row per stable occurrence (issue #1779). One
    /// row per `occurrence_id` carrying the verbatim invocation document.
    /// Create-only; divergent rewrites fail closed.
    pub(crate) const AUTOMATION_INVOCATION: &str = "automation_invocation";
    /// Immutable automation failure row per automation + revision +
    /// fingerprint (issue #1779). One row per canonical failure key
    /// carrying the verbatim failure document with first-writer
    /// provenance. Create-or-converge; divergent rewrites fail closed.
    pub(crate) const AUTOMATION_FAILURE: &str = "automation_failure";
    /// Last automation failure pointer per automation (issue #1779). One
    /// row per `automation_id` naming the most recently committed
    /// failure key. Last write wins; no compare-and-set.
    pub(crate) const AUTOMATION_LAST_FAILURE: &str = "automation_last_failure";
    /// Bounded, owner-issued page continuations and their quota guard (issue #2859).
    /// Rows are schemaless and created only by the truncated-page issuance path;
    /// named reads never define this table as a side effect.
    pub(crate) const AUTOMATION_CONTINUATION: &str = "automation_continuation";
    /// Immutable experience-bank row per handle + owner revision
    /// (issue #223). One row per joined `(handle, revision)` key
    /// carrying the verbatim Governor-admitted bank-record document.
    /// Create-only; divergent rewrites fail closed.
    pub(crate) const EXPERIENCE_BANK: &str = "experience_bank";
    /// Immutable agent-feedback row per handle + owner revision
    /// (issue #223). Same create-only rule as the bank rows.
    pub(crate) const EXPERIENCE_FEEDBACK: &str = "experience_feedback";
    /// Immutable learning-record row per record kind + handle + record
    /// digest (issue #1868). One row per joined
    /// `(record_kind, handle, record_digest)` key carrying the verbatim
    /// learning-record document. Create-only; divergent rewrites fail
    /// closed. The digest IS the immutable revision identity: a new
    /// digest is a new row, never an in-place rewrite.
    pub(crate) const LEARNING_RECORD: &str = "learning_record";

    /// Singleton instrument-registry snapshot head (issue #1814 W1.2). One
    /// row under the fixed `head` key carrying the verbatim opaque
    /// snapshot bytes with a store-issued revision. Replaced verbatim
    /// with a bumped revision on each admitted apply under the same
    /// fence+revision compare-and-set contract as the reactive tables.
    pub(crate) const INSTRUMENT_REGISTRY: &str = "instrument_registry";

    /// Every physical table *name* this single owner declares, in declaration
    /// order.
    ///
    /// This is the closed denominator a consumer checks for exact 1:1
    /// coverage. It adds no name: every entry is the same const declared
    /// above, so physical-name ownership stays in this one place (A2.3 /
    /// ARCH-MOD-03) and a consumer can name the denominator instead of
    /// counting its own list.
    ///
    /// Maintenance invariant: this array MUST be updated in the same edit as
    /// any new const declared in this module. Rust cannot reflect over `const`s,
    /// so no compile-time or test-time link exists between the two lists.
    ///
    /// Exactly what a 1:1 census against this array does and does not prove:
    ///
    /// - It proves every name listed here has exactly one disposition, and that
    ///   no disposition names a table absent from here. Adding a const above
    ///   together with its disposition but forgetting this entry therefore
    ///   fails loudly.
    /// - It does not prove the converse. A const added above and left out of
    ///   both this array and every disposition is a silent omission no check
    ///   can see, so the invariant above is the only thing guarding it.
    /// - It does not prove a name listed here is a physical table. Nothing
    ///   machine-links these consts to this module's DDL strings, so a declared
    ///   name that no baseline DDL ever creates is dispositioned and passed
    ///   like any other. `automation_failure`, `automation_last_failure`, and
    ///   `automation_continuation` are declared without generation DDL;
    ///   continuations create their schemaless table only during explicit
    ///   truncated-page issuance.
    pub(crate) const ALL_TABLES: [&str; 26] = [
        SCHEMA_META,
        WRITE_RECEIPT,
        REVISION_HEAD,
        ORDERING_HEAD,
        CANONICAL_EVENT,
        PROJECTION_RECORD,
        RELATION_RECORD,
        OUTBOX_EVENT,
        CANONICAL_FENCE,
        RECOVERY_OWNER,
        RECOVERY_JOB,
        ERASURE_INTENT,
        ERASURE_OUTCOME,
        NOTIFICATION_RECORD,
        REACTIVE_SESSION,
        RESOURCE_SNAPSHOT,
        AUTOMATION_REVISION,
        AUTOMATION_CURRENT,
        AUTOMATION_INVOCATION,
        AUTOMATION_FAILURE,
        AUTOMATION_LAST_FAILURE,
        AUTOMATION_CONTINUATION,
        EXPERIENCE_BANK,
        EXPERIENCE_FEEDBACK,
        LEARNING_RECORD,
        INSTRUMENT_REGISTRY,
    ];
}

/// Record key of the single canonical fence/sequence row.
pub(crate) const FENCE_KEY: &str = "current";
/// Record key of the single schema-meta row.
pub(crate) const SCHEMA_META_KEY: &str = "current";

pub(crate) const GENERATION_V1: &str = "1.0.0";
pub(crate) const GENERATION_V2: &str = "2.0.0";

/// Durable `migration_state` of a committed schema metadata row. Only this
/// value means "this generation is applied and usable"; every other value
/// blocks writer readiness.
pub(crate) const MIGRATION_STATE_APPLIED: &str = "APPLIED";
/// Durable `migration_state` of the row a migration operation owns between
/// recording its intent and committing its DDL. The DDL and the `APPLIED`
/// write share one transaction, so this value is durable proof that the DDL
/// did not commit, and it names the exact plan that was in flight.
pub(crate) const MIGRATION_STATE_APPLYING: &str = "APPLYING";
pub(crate) const MIGRATION_ID_V1: &str = "eliot.store.surreal.schema.v1";
pub(crate) const MIGRATION_ID_V2: &str = "eliot.store.surreal.schema.v2";
pub(crate) const MIGRATION_ID_V1_TO_V2: &str = "eliot.store.surreal.schema.v1_to_v2";
/// Additive erasure-table migration: creates only `erasure_intent` and
/// `erasure_outcome` on top of a v2 baseline (688-B).
pub(crate) const MIGRATION_ID_V2_TO_V3: &str = "eliot.store.surreal.schema.v2_to_v3";
/// Schema generation reached by the erasure-table migration. The tables are
/// additive, so v3 contains every v2 table verbatim plus the two erasure
/// tables below.
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
/// `erasure_transaction_bindings` (`operation_id`, `subject`, `payload_ref`,
/// `encryption_key_ref`, `deadline_unix_ms`, `scope_id`, `surfaces`,
/// `state_fence`, `operation_count`), and `erasure_outcome`
/// carries the sealed per-surface outcomes (`operation_id`, `scope_id`,
/// `outcomes`). `operation_id` is unique in each table; one intent row plus its
/// single outcome seal per operation — never a second ledger.
///
/// `erasure_outcome.scope_id` is the *sealed* row's own copy of the single
/// admitted scope, copied verbatim from the frozen intent that opened the
/// transaction by `erasure_transaction_bindings` and never derived. A privacy
/// purge ledger is read per scope, so a seal carrying only `operation_id` could
/// not attribute its own outcomes to the scope whose data they purged. The
/// scope the seal's identity rests on is still the intent row's, which
/// `TX_ERASURE_INTENT` compares in the same transaction.
pub(crate) const ERASURE_TABLES_DDL: &str = r"
DEFINE TABLE erasure_intent SCHEMALESS;
DEFINE FIELD operation_id ON erasure_intent TYPE string;
DEFINE FIELD subject ON erasure_intent TYPE string;
DEFINE FIELD payload_ref ON erasure_intent TYPE string;
DEFINE FIELD encryption_key_ref ON erasure_intent TYPE string;
DEFINE FIELD deadline_unix_ms ON erasure_intent TYPE int;
DEFINE FIELD scope_id ON erasure_intent TYPE string;
DEFINE FIELD surfaces ON erasure_intent TYPE array;
DEFINE FIELD state_fence ON erasure_intent TYPE object;
DEFINE FIELD operation_count ON erasure_intent TYPE int;
DEFINE INDEX ei_operation ON erasure_intent FIELDS operation_id UNIQUE;

DEFINE TABLE erasure_outcome SCHEMALESS;
DEFINE FIELD operation_id ON erasure_outcome TYPE string;
DEFINE FIELD scope_id ON erasure_outcome TYPE string;
DEFINE FIELD outcomes ON erasure_outcome TYPE array;
DEFINE INDEX eo_operation ON erasure_outcome FIELDS operation_id UNIQUE;
";

/// Forward-migration body for the v2-to-v3 erasure step. Like the v1-to-v2
/// body it is a delta: no `schema_meta` redefinition, no data statements.
pub(crate) const SCHEMA_MIGRATION_V2_TO_V3_DDL: &str = ERASURE_TABLES_DDL;

/// Notification record table (issue #1780). Additive delta in the erasure
/// migration style: one row per dedup key with the current record, the
/// ordered admitted leg history, the owner revision, and the admission
/// fence. Applied explicitly where the owning slice proves it; never
/// executed implicitly by the adapter.
pub(crate) const NOTIFICATION_TABLES_DDL: &str = r"
DEFINE TABLE notification_record SCHEMALESS;
DEFINE FIELD dedup_key ON notification_record TYPE string;
DEFINE FIELD record ON notification_record TYPE object;
DEFINE FIELD history ON notification_record TYPE array;
DEFINE FIELD revision ON notification_record TYPE int;
DEFINE FIELD state_fence ON notification_record TYPE object;
DEFINE INDEX notify_dedup ON notification_record FIELDS dedup_key UNIQUE;
";

/// Reactive session + resource snapshot tables (issue #1941 C4). Additive
/// delta in the notification style: `reactive_session` carries one row
/// per session with the verbatim ledger snapshot, the owner revision,
/// the admission fence, and task-binding provenance; `resource_snapshot`
/// carries one row per canonical URI with the content digest, the
/// verbatim base64 bytes, the owner revision, and the admission fence.
/// Applied explicitly where the owning slice proves it; never executed
/// implicitly by the adapter.
pub(crate) const REACTIVE_TABLES_DDL: &str = r"
DEFINE TABLE reactive_session SCHEMALESS;
DEFINE FIELD session_id ON reactive_session TYPE string;
DEFINE FIELD ledger_json ON reactive_session TYPE string;
DEFINE FIELD revision ON reactive_session TYPE int;
DEFINE FIELD state_fence ON reactive_session TYPE object;
DEFINE FIELD scope_id ON reactive_session TYPE string;
DEFINE FIELD task_id ON reactive_session TYPE option<string>;
DEFINE INDEX reactive_session_id ON reactive_session FIELDS session_id UNIQUE;

DEFINE TABLE resource_snapshot SCHEMALESS;
DEFINE FIELD uri ON resource_snapshot TYPE string;
DEFINE FIELD content_sha256 ON resource_snapshot TYPE string;
DEFINE FIELD content_base64 ON resource_snapshot TYPE string;
DEFINE FIELD revision ON resource_snapshot TYPE int;
DEFINE FIELD state_fence ON resource_snapshot TYPE object;
DEFINE FIELD scope_id ON resource_snapshot TYPE string;
DEFINE FIELD task_id ON resource_snapshot TYPE option<string>;
DEFINE INDEX snapshot_uri ON resource_snapshot FIELDS uri UNIQUE;
";

/// Automation revision, pointer, and invocation tables (issue #1779).
/// Additive delta in the notification style: `automation_revision`
/// carries one immutable row per joined automation/revision key with the
/// verbatim revision document; `automation_current` carries one
/// compare-and-set pointer per automation with the current revision and
/// the closed admission state; `automation_invocation` carries one
/// create-only row per occurrence identity with the verbatim invocation
/// document. Applied explicitly where the owning slice proves it; never
/// executed implicitly by the adapter.
pub(crate) const AUTOMATION_TABLES_DDL: &str = r"
DEFINE TABLE automation_revision SCHEMALESS;
DEFINE FIELD automation_id ON automation_revision TYPE string;
DEFINE FIELD revision ON automation_revision TYPE string;
DEFINE FIELD revision_json ON automation_revision TYPE string;
DEFINE FIELD state_fence ON automation_revision TYPE object;
DEFINE FIELD scope_id ON automation_revision TYPE string;
DEFINE FIELD task_id ON automation_revision TYPE option<string>;

DEFINE TABLE automation_current SCHEMALESS;
DEFINE FIELD automation_id ON automation_current TYPE string;
DEFINE FIELD revision ON automation_current TYPE string;
DEFINE FIELD configuration_state ON automation_current TYPE string;
DEFINE FIELD state_fence ON automation_current TYPE object;
DEFINE FIELD scope_id ON automation_current TYPE string;
DEFINE FIELD task_id ON automation_current TYPE option<string>;
DEFINE INDEX automation_pointer ON automation_current FIELDS automation_id UNIQUE;

DEFINE TABLE automation_invocation SCHEMALESS;
DEFINE FIELD occurrence_id ON automation_invocation TYPE string;
DEFINE FIELD automation_id ON automation_invocation TYPE string;
DEFINE FIELD invocation_json ON automation_invocation TYPE string;
DEFINE FIELD state_fence ON automation_invocation TYPE object;
DEFINE FIELD scope_id ON automation_invocation TYPE string;
DEFINE FIELD task_id ON automation_invocation TYPE option<string>;
DEFINE INDEX invocation_occurrence ON automation_invocation FIELDS occurrence_id UNIQUE;
";

/// Experience bank/feedback tables (issue #223).
/// Additive delta in the automation style: `experience_bank` carries one
/// immutable row per joined handle/revision key with the verbatim
/// Governor-admitted bank-record document plus presented digests;
/// `experience_feedback` carries the same shape for feedback records.
/// Applied explicitly where the owning slice proves it; never executed
/// implicitly by the adapter.
pub(crate) const EXPERIENCE_TABLES_DDL: &str = r"
DEFINE TABLE experience_bank SCHEMALESS;
DEFINE FIELD handle ON experience_bank TYPE string;
DEFINE FIELD revision ON experience_bank TYPE int;
DEFINE FIELD record_json ON experience_bank TYPE string;
DEFINE FIELD record_digest ON experience_bank TYPE string;
DEFINE FIELD state_fence ON experience_bank TYPE object;
DEFINE FIELD scope_id ON experience_bank TYPE string;
DEFINE FIELD task_id ON experience_bank TYPE option<string>;

DEFINE TABLE experience_feedback SCHEMALESS;
DEFINE FIELD handle ON experience_feedback TYPE string;
DEFINE FIELD revision ON experience_feedback TYPE int;
DEFINE FIELD record_json ON experience_feedback TYPE string;
DEFINE FIELD record_digest ON experience_feedback TYPE string;
DEFINE FIELD state_fence ON experience_feedback TYPE object;
DEFINE FIELD scope_id ON experience_feedback TYPE string;
DEFINE FIELD task_id ON experience_feedback TYPE option<string>;
";

/// Learning-record table (issue #1868).
/// Additive delta in the experience style: `learning_record` carries one
/// immutable row per joined kind/handle/digest key with the verbatim
/// learning-record document plus presented digests. Applied explicitly
/// where the owning slice proves it; never executed implicitly by the
/// adapter.
pub(crate) const LEARNING_TABLES_DDL: &str = r"
DEFINE TABLE learning_record SCHEMALESS;
DEFINE FIELD record_kind ON learning_record TYPE string;
DEFINE FIELD handle ON learning_record TYPE string;
DEFINE FIELD record_json ON learning_record TYPE string;
DEFINE FIELD record_digest ON learning_record TYPE string;
DEFINE FIELD state_fence ON learning_record TYPE object;
DEFINE FIELD scope_id ON learning_record TYPE string;
DEFINE FIELD task_id ON learning_record TYPE option<string>;
";

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
DEFINE FIELD payload_ref ON erasure_intent TYPE string;
DEFINE FIELD encryption_key_ref ON erasure_intent TYPE string;
DEFINE FIELD deadline_unix_ms ON erasure_intent TYPE int;
DEFINE FIELD scope_id ON erasure_intent TYPE string;
DEFINE FIELD surfaces ON erasure_intent TYPE array;
DEFINE FIELD state_fence ON erasure_intent TYPE object;
DEFINE FIELD operation_count ON erasure_intent TYPE int;
DEFINE INDEX ei_operation ON erasure_intent FIELDS operation_id UNIQUE;

DEFINE TABLE erasure_outcome SCHEMALESS;
DEFINE FIELD operation_id ON erasure_outcome TYPE string;
DEFINE FIELD scope_id ON erasure_outcome TYPE string;
DEFINE FIELD outcomes ON erasure_outcome TYPE array;
DEFINE INDEX eo_operation ON erasure_outcome FIELDS operation_id UNIQUE;
";

/// Reports whether `ddl` declares a field whose *whole* name is `column`.
///
/// Both boundaries are identifier-byte boundaries, so this is a whole-name
/// match, never a substring one. `encryption` must not be satisfied by
/// `encryption_key_ref`, and `export_receipt` must not be satisfied by a longer
/// `export_receipt_digest`: an absence proven by a substring match is not an
/// absence, and an evidence column "found" inside a different field's name is a
/// fabricated observation rather than a measured one.
///
/// Const-evaluable so the negative inventory below is checked by `cargo check`
/// rather than by a test that can be skipped.
pub(crate) const fn declares_column_name(ddl: &str, column: &str) -> bool {
    let haystack = ddl.as_bytes();
    let needle = column.as_bytes();
    if needle.is_empty() {
        return false;
    }
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        let mut offset = 0;
        while offset < needle.len() {
            if haystack[start + offset] != needle[offset] {
                break;
            }
            offset += 1;
        }
        if offset == needle.len() {
            let end = start + needle.len();
            let left_clear = start == 0 || !is_identifier_byte(haystack[start - 1]);
            let right_clear = end == haystack.len() || !is_identifier_byte(haystack[end]);
            if left_clear && right_clear {
                return true;
            }
        }
        start += 1;
    }
    false
}

/// Whether `byte` may appear inside a `SurrealQL` field name.
///
/// Deliberately the *identifier* set, not the alphanumeric set: `encryption`
/// must not match `encryption_key_ref`, so `_` has to count as a name
/// character here or the boundary check would pass a longer field.
const fn is_identifier_byte(byte: u8) -> bool {
    byte == b'_'
        || (byte >= b'0' && byte <= b'9')
        || (byte >= b'a' && byte <= b'z')
        || (byte >= b'A' && byte <= b'Z')
}

/// The five ECXF capture-evidence column groups this owner does **not** define,
/// and the real owner of each value.
///
/// This is a *negative* inventory, and it is the schema owner's half of the
/// answer to "why does the ECXF capture report five evidence gaps". Each entry
/// is the exact field name `eliot_ecxf` already uses, so the vocabulary stays the
/// consumer's own and this file introduces no second set of names. For each,
/// this module was checked for a *differently named* column that carries the same
/// evidence; the const block below is the compiled proof that no such column
/// exists in any baseline this owner ships, and the per-entry notes record which
/// near-miss was examined and why it is a different quantity.
///
/// No entry is a `DEFINE FIELD`, deliberately. A declared column that no write
/// path populates is a certified no-op: it would make a reader believe an
/// evidence value exists when every real row reads back `NONE`, which is the
/// "claimed but unbacked" defect class rather than a fix for it. The adapter
/// crate contains no writer for any of these names today (`git grep` finds zero
/// occurrences of all seven identifiers under `crates/storage/eliot-store-surreal-adapter`),
/// so adding the field would back a claim with nothing. Each value below is
/// therefore owned by the component that actually mints it, and closing its gap
/// means that owner supplies the evidence, not that this file declares an empty
/// column.
pub(crate) const ECXF_UNDEFINED_CAPTURE_EVIDENCE: &[(&str, &str)] = &[
    (
        "architecture_source_digest",
        "minted by the Architecture/Kernel compatibility handshake \
         (crates/kernel/eliot-kernel-core/src/module/compatibility_handshake.rs); \
         sealed outside the store, so no baseline can define it",
    ),
    (
        "normative_pair_identity_receipt_digest",
        "the `NormativePair` identity receipt, sealed by the same handshake \
         owner; it is a receipt *about* this store, not a column of it",
    ),
    (
        "export_receipt",
        "a source-side ECXF export receipt; the exporter mints the package \
         receipt at emit time and no store row records that an export happened",
    ),
    (
        "store_generation",
        "the store's own generation. The two near-misses were examined and \
         rejected: `schema_meta.generation` is the SCHEMA generation, and \
         `StateFence::resource_generation` is the generation relevant to one \
         decision, not the store's aggregate",
    ),
    (
        "source_adapter",
        "this adapter's identity. `schema_meta.migration_id` names the \
         *migration*, not the adapter, and `crate::ADAPTER_NAME` is a build \
         constant of the running binary rather than an observation of the \
         source store",
    ),
    (
        "source_adapter_version",
        "same owner and same rejection as `source_adapter`; the adapter declares \
         no version column of its own",
    ),
    (
        "compression",
        "the codec profile of the EMITTED package. The only encryption-adjacent \
         field, `erasure_intent.encryption_key_ref`, is a key *reference* on a \
         table the admitted generation does not define, not a package profile",
    ),
];

/// Compile-time proof that no baseline this owner ships defines any name in
/// [`ECXF_UNDEFINED_CAPTURE_EVIDENCE`].
///
/// Both admitted baselines are covered (`SCHEMA_DDL_V2`, the generation a v2
/// pin admits, and `SCHEMA_DDL_V3`), plus the first-generation baseline and
/// every additive delta, so a gap cannot be closed by a table this owner already
/// declares in some other generation or migration body.
///
/// This asserts a *negative*, and a negative assertion is the one direction that
/// is safe to hard-wire: it can only ever fail if a real column is added, which
/// is precisely the moment the owner must revisit the corresponding gap entry
/// above. It can never make a gap report itself closed on its own, because it
/// proves absence and never presence.
const _: () = {
    // Every baseline body this module defines, in declaration order:
    // SCHEMA_DDL, SCHEMA_DDL_V2, SCHEMA_DDL_V3, RECOVERY_TABLES_DDL,
    // ERASURE_TABLES_DDL, NOTIFICATION_TABLES_DDL, REACTIVE_TABLES_DDL,
    // AUTOMATION_TABLES_DDL, EXPERIENCE_TABLES_DDL and LEARNING_TABLES_DDL.
    let baselines: [&str; 10] = [
        SCHEMA_DDL,
        SCHEMA_DDL_V2,
        SCHEMA_DDL_V3,
        RECOVERY_TABLES_DDL,
        ERASURE_TABLES_DDL,
        NOTIFICATION_TABLES_DDL,
        REACTIVE_TABLES_DDL,
        AUTOMATION_TABLES_DDL,
        EXPERIENCE_TABLES_DDL,
        LEARNING_TABLES_DDL,
    ];
    let mut baseline_index = 0;
    while baseline_index < baselines.len() {
        let ddl = baselines[baseline_index];
        let mut entry_index = 0;
        while entry_index < ECXF_UNDEFINED_CAPTURE_EVIDENCE.len() {
            let column = ECXF_UNDEFINED_CAPTURE_EVIDENCE[entry_index].0;
            assert!(
                !declares_column_name(ddl, column),
                "a schema baseline this owner ships now defines a column recorded \
                 here as absent; update ECXF_UNDEFINED_CAPTURE_EVIDENCE \
                 deliberately rather than letting the record and the DDL disagree"
            );
            entry_index += 1;
        }
        baseline_index += 1;
    }
};

/// Transaction delimiters for a single atomic apply.
pub(crate) const TX_BEGIN: &str = "BEGIN TRANSACTION;";
pub(crate) const TX_COMMIT: &str = "COMMIT TRANSACTION;";

/// Compare-and-set update of the canonical fence singleton.
pub(crate) const TX_UPSERT_FENCE: &str = "LET $fence_cas = (UPDATE type::record($fence_table, $fence_key) CONTENT $fence WHERE state_fence = $expected_state_fence AND next_commit_sequence = $expected_commit_sequence AND next_outbox_sequence = $expected_outbox_sequence RETURN AFTER); IF array::len($fence_cas ?? []) != 1 { THROW 'canonical_fence_cas_conflict'; };";
pub(crate) const TX_CREATE_FENCE: &str = "LET $fence_create = (CREATE type::record($fence_table, $fence_key) CONTENT $fence RETURN AFTER); IF array::len($fence_create ?? []) != 1 { THROW 'canonical_fence_create_conflict'; };";
/// Verify one independently declared revision dependency inside the canonical transaction.
pub(crate) const TX_VERIFY_EXPECTED_REVISION: &str = "LET $expected_revision_head{i} = (SELECT VALUE { revision: body.revision, state_fence: body.state_fence } FROM ONLY type::record($expected_revision_table{i}, $expected_revision_key{i})); IF type::is_object($expected_revision_head{i}) { IF $expected_revision_head{i}.revision != $expected_revision_value{i} OR $expected_revision_head{i}.state_fence != $expected_revision_fence{i} { THROW 'revision_head_cas_conflict'; }; } ELSE { IF $expected_revision_value{i} != 1 { THROW 'revision_head_cas_conflict'; }; };";
/// Verify one independently declared ordering dependency and its original chain tip.
pub(crate) const TX_VERIFY_EXPECTED_ORDERING: &str = "LET $expected_ordering_head{i} = (SELECT VALUE { sequence: body.sequence, state_fence: body.state_fence, event_hash: event_hash ?? $ordering_genesis_hash{i} } FROM ONLY type::record($expected_ordering_table{i}, $expected_ordering_scope{i})); IF type::is_object($expected_ordering_head{i}) { IF $expected_ordering_head{i}.sequence != $expected_ordering_sequence{i} OR $expected_ordering_head{i}.state_fence != $expected_ordering_fence{i} OR $expected_ordering_head{i}.event_hash != $expected_ordering_hash{i} { THROW 'ordering_head_cas_conflict'; }; } ELSE { IF $expected_ordering_sequence{i} != 1 OR $expected_ordering_hash{i} != $ordering_genesis_hash{i} { THROW 'ordering_head_cas_conflict'; }; };";
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

/// Terminal allocation proof of one canonical transaction (S-CONC-TX, #989).
///
/// Second-to-last statement of the assembled transaction, immediately before
/// [`TX_COMMIT`]: binds the exact operation identity plus the allocation this
/// attempt consumed (`commit_sequence`, `next_commit_sequence`,
/// `next_outbox_sequence`) into one typed result slot owned by the same
/// transaction. The writer validates this slot's operation binding and
/// allocation equality on every error-free RPC: a missing, duplicate,
/// malformed, or mismatched slot is a possible-commit outcome for
/// same-operation reconciliation, never a local success. Adds no `CREATE`,
/// so receipt/event/outbox row counts are unchanged.
pub(crate) const TX_ALLOC_PROOF: &str = "LET $alloc_proof = { operation_id: $alloc_operation_id, commit_sequence: $alloc_commit_sequence, next_commit_sequence: $alloc_next_commit_sequence, next_outbox_sequence: $alloc_next_outbox_sequence };";

/// Fenced upsert of the Governor finish-owner snapshot.  The outer recovery
/// record is the only storage-owned part of a finish decision: its payload is
/// opaque canonical receipt bytes, while the fixed `owner/finish` address,
/// state fence, and outer revision are arbitrated here.  Creation and update
/// use distinct markers so a stale create cannot be mistaken for a normal
/// revision conflict by the adapter.
pub(crate) const TX_FINISH_OWNER: &str = "LET $finish_existing = (SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision } FROM ONLY type::record($finish_owner_table, $finish_owner_id)); IF type::is_object($finish_existing) { LET $finish_owner_cas = (UPDATE type::record($finish_owner_table, $finish_owner_id) CONTENT $finish_owner_record WHERE state_fence = $finish_expected_state_fence AND revision = $finish_expected_revision RETURN AFTER); IF array::len($finish_owner_cas ?? []) != 1 { THROW 'finish_owner_cas_conflict'; }; } ELSE { IF $finish_expected_revision != 0 { THROW 'finish_owner_create_conflict'; }; LET $finish_owner_create = (CREATE type::record($finish_owner_table, $finish_owner_id) CONTENT $finish_owner_record RETURN AFTER); IF array::len($finish_owner_create ?? []) != 1 { THROW 'finish_owner_create_conflict'; }; };";

/// Fenced upsert of the Governor-produced canonical admission owner image.
/// The payload remains opaque to the adapter; only the fixed owner address,
/// fence, and outer revision are provider-arbitrated.
pub(crate) const TX_CANONICAL_OWNER: &str = "LET $canonical_existing = (SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision } FROM ONLY type::record($canonical_owner_table, $canonical_owner_id)); IF type::is_object($canonical_existing) { LET $canonical_owner_cas = (UPDATE type::record($canonical_owner_table, $canonical_owner_id) CONTENT $canonical_owner_record WHERE state_fence = $canonical_expected_state_fence AND revision = $canonical_expected_revision RETURN AFTER); IF array::len($canonical_owner_cas ?? []) != 1 { THROW 'canonical_owner_cas_conflict'; }; } ELSE { IF $canonical_expected_revision != 0 { THROW 'canonical_owner_create_conflict'; }; LET $canonical_owner_create = (CREATE type::record($canonical_owner_table, $canonical_owner_id) CONTENT $canonical_owner_record RETURN AFTER); IF array::len($canonical_owner_create ?? []) != 1 { THROW 'canonical_owner_create_conflict'; }; };";

/// Fenced update of the existing Governor-owned Module Catalog snapshot. The payload
/// remains opaque to the adapter; only the fixed `owner/module_registry`
/// address, fence, and outer revision are provider-arbitrated.
pub(crate) const TX_MODULE_REGISTRY_OWNER: &str = "LET $module_registry_existing = (SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema } FROM ONLY type::record($module_registry_owner_table, $module_registry_owner_id)); IF type::is_object($module_registry_existing) { LET $module_registry_owner_cas = (UPDATE type::record($module_registry_owner_table, $module_registry_owner_id) CONTENT $module_registry_owner_record WHERE namespace = 'owner' AND key = 'module_registry' AND schema = 'eliot.governor.owner.snapshot.v1' AND state_fence = $module_registry_expected_state_fence AND revision = $module_registry_expected_revision RETURN AFTER); IF array::len($module_registry_owner_cas ?? []) != 1 { THROW 'module_registry_owner_cas_conflict'; }; } ELSE { THROW 'module_registry_owner_cas_conflict'; };";

/// Fenced compare-and-set of one Governor-owned capability-evidence row
/// (issue #1773, I3.4).
///
/// Same shape as [`TX_CANONICAL_OWNER`], with the evidence row's own
/// addresses: a present row must be advanced from exactly the asserted
/// `revision` and fence, an absent row only from the `0` floor, and the issued
/// `revision` is always `expected + 1`. That issued revision is the
/// owner-issued immutable revision the Governor registry orders same-key
/// evidence by, so a delayed writer holding a stale predecessor is refused
/// inside the canonical transaction, before it can reach the registry. The
/// record document stays opaque bytes.
/// Fenced compare-and-set of the existing Governor-owned coordination owner
/// image. The payload remains opaque to the adapter; only the fixed
/// `owner/coordination` address, fence, and outer revision are
/// provider-arbitrated.
///
/// Same shape as [`TX_MODULE_REGISTRY_OWNER`], with the coordination row's own
/// address: the genesis owner record must already exist (a `RecoverySchema`
/// owner image is never created outside genesis), and a present row is advanced
/// only from exactly the asserted namespace, key, schema, state fence and
/// revision. The issued `revision` is always `expected + 1`. A delayed writer
/// holding a stale predecessor throws `coordination_owner_cas_conflict` inside
/// the canonical transaction, before the receipt commits, so it can never
/// overwrite a newer coordination image.
pub(crate) const TX_COORDINATION_OWNER: &str = "LET $coordination_existing = (SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema } FROM ONLY type::record($coordination_owner_table, $coordination_owner_id)); IF type::is_object($coordination_existing) { LET $coordination_owner_cas = (UPDATE type::record($coordination_owner_table, $coordination_owner_id) CONTENT $coordination_owner_record WHERE namespace = 'owner' AND key = 'coordination' AND schema = 'eliot.governor.owner.snapshot.v1' AND state_fence = $coordination_expected_state_fence AND revision = $coordination_expected_revision RETURN AFTER); IF array::len($coordination_owner_cas ?? []) != 1 { THROW 'coordination_owner_cas_conflict'; }; } ELSE { THROW 'coordination_owner_cas_conflict'; };";

pub(crate) const TX_CAPABILITY_EVIDENCE_OWNER: &str = "LET $capability_evidence_existing = (SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision } FROM ONLY type::record($capability_evidence_table, $capability_evidence_id)); IF type::is_object($capability_evidence_existing) { LET $capability_evidence_cas = (UPDATE type::record($capability_evidence_table, $capability_evidence_id) CONTENT $capability_evidence_record WHERE state_fence = $capability_evidence_expected_state_fence AND revision = $capability_evidence_expected_revision RETURN AFTER); IF array::len($capability_evidence_cas ?? []) != 1 { THROW 'capability_evidence_cas_conflict'; }; } ELSE { IF $capability_evidence_expected_revision != 0 { THROW 'capability_evidence_create_conflict'; }; LET $capability_evidence_create = (CREATE type::record($capability_evidence_table, $capability_evidence_id) CONTENT $capability_evidence_record RETURN AFTER); IF array::len($capability_evidence_create ?? []) != 1 { THROW 'capability_evidence_create_conflict'; }; };";

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

/// Durable state written over the `schema_meta` row by the operation that is
/// about to run provider DDL, in its own committed transaction.
///
/// The intent row carries the target generation, the target migration
/// identity, the complete migration history and the same `updated_at` stamp
/// the migration would commit, differing from the applied record only in the
/// state, so after a crash the row names exactly which plan was in flight.
/// Because the DDL and the `APPLIED` metadata write share one transaction (see
/// [`forward_migration_sql`]), an `APPLYING` row is proof that the DDL did
/// not commit. The compare-and-set is the same predecessor guard the forward
/// transaction uses, so the intent is owned by that one row and one state
/// fence, and re-recording it for the same plan is an exact replay.
pub(crate) const TX_MARK_SCHEMA_MIGRATION_INTENT: &str = "LET $schema_intent = (UPDATE type::record($schema_meta_table, $schema_meta_key) CONTENT $schema_meta_intent_record WHERE generation = $expected_generation AND migration_id = $expected_migration_id AND migration_checksum_sha256 = $expected_migration_checksum_sha256 AND compatible_bridge_range = $expected_bridge_range AND migration_state = $expected_migration_state AND array::len(migrations) = $expected_migrations_len AND migrations[0].migration_id = $expected_migration_0_id AND migrations[0].migration_checksum_sha256 = $expected_migration_0_checksum AND migrations[0].generation = $expected_migration_0_generation AND updated_at = $expected_updated_at RETURN AFTER); IF array::len($schema_intent ?? []) != 1 { THROW 'schema_predecessor_mismatch'; };";

/// The intent transaction: fence guard, then the owned intent write, then the
/// commit. It performs no DDL, so it neither creates nor removes a table and
/// cannot be mistaken for a schema generation.
pub(crate) fn migration_intent_sql() -> String {
    format!("{TX_BEGIN} {TX_GUARD_FENCE} {TX_MARK_SCHEMA_MIGRATION_INTENT} {TX_COMMIT}")
}

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

/// Strict post-commit effect readback (S-CONC-TX, #989).
///
/// Both rows carry the admitted `operation_id` verbatim in their committed
/// bindings (see the event/outbox bindings in `apply/atomic_write`), so these
/// closed reads resolve the exact durable effect set of one operation: every
/// missing, duplicate, or malformed row fails the success-path comparison in
/// `apply` with a possible-commit outcome, never a local success. Reads, not
/// DDL: no schema generation or migration change is involved.
pub(crate) const READ_OUTBOX_IDS_BY_OPERATION: &str =
    "SELECT VALUE outbox_id FROM outbox_event WHERE operation_id = $operation_id;";
pub(crate) const READ_EVENT_IDS_BY_OPERATION: &str =
    "SELECT VALUE event_id FROM canonical_event WHERE operation_id = $operation_id;";

pub(crate) const READ_RECEIPT_IDEMPOTENCY: &str = r"
SELECT VALUE body FROM write_receipt WHERE operation_id = $operation_id LIMIT 1;
SELECT VALUE body FROM write_receipt WHERE idempotency_key = $idempotency_key LIMIT 1;
";

pub(crate) const READ_REVISION_HEADS_BY_KEYS: &str =
    "SELECT VALUE body FROM revision_head WHERE revision_key IN $keys;";

pub(crate) const READ_ORDERING_HEADS_BY_SCOPES: &str =
    "SELECT VALUE body FROM ordering_head WHERE ordering_scope IN $scopes;";

/// Reads each Ordering Scope's own chain tip, the `previous_event_hash`/
/// `event_hash` siblings the closed `SELECT VALUE body` head read cannot see
/// (issue #1931). `event_hash` is null for a scope whose row predates per-scope
/// chain links, which the caller reads as the genesis prior.
pub(crate) const READ_ORDERING_CHAIN_TIPS_BY_SCOPES: &str = "SELECT VALUE { ordering_scope: ordering_scope, event_hash: event_hash } FROM ordering_head WHERE ordering_scope IN $scopes;";

/// Reads each declared projection kind's retained publication generations, the
/// `projection_generation`/`source_generation` the next publication of that
/// kind must advance from (issue #1931, `I5.8`).
///
/// The two generations live inside the record's `body`, so they are projected
/// out of it explicitly: a schemaless `SELECT *` would return the provider
/// `id` as well and fail closed deserialization against a real provider (see
/// [`READ_SCHEMA_META`]). A kind with no retained publication simply returns
/// no row, which the caller reads as the genesis cursor.
pub(crate) const READ_PROJECTION_GENERATIONS_BY_KINDS: &str = "SELECT VALUE { projection_kind: body.projection_kind, projection_generation: body.projection_generation, source_generation: body.source_generation } FROM projection_record WHERE body.projection_kind IN $kinds;";

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
